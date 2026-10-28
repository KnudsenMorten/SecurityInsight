#Requires -Version 5.1
<#
    CUSTOMER-MANAGED KEYS AS AN OPTION (#683). Microsoft-managed keys stay the DEFAULT; with this option the install's data
    is encrypted with a key in the customer's own Key Vault:
      * the Pro database server: Transparent Data Encryption with the customer's key (the server's TDE protector), automatic
        key rotation on -- every database on the server;
      * the storage account: encryption with the customer's key, the versionless key (a new key version is taken up by
        Azure itself);
      * Log Analytics: the workspace linked to a dedicated Log Analytics cluster that holds the customer's key -- an existing
        cluster of the customer's, or a new one (a cluster is a capacity commitment, so it is its own choice).
    ONE library for both ways it reaches an install: a NEW install (the guided install, only when it asks for it:
    customerManagedKeys = true) and an EXISTING install (setup\Set-SICustomerManagedKeys.ps1: PLAN by default, idempotent
    steps, read back after every change, one rollback record per run, through the Invardia Support app).

    The pieces, each idempotent and read back:
      1. the vault: soft delete and PURGE PROTECTION on (Azure requires both for a customer-managed key) -- ONE-WAY;
      2. the key: the one named (default: si-data in the install's own vault), created when it is not there -- RSA 3072,
         wrapKey / unwrapKey, with a ROTATION POLICY (a new version every year, expiry after two years, notice 30 days
         before); a key is NEVER removed by this code (data encrypted with it would be lost);
      3. the identity that uses the key: a user-assigned managed identity (id-si-keys) in the install's resource group;
      4. its access: "Key Vault Crypto Service Encryption User" on the KEY only (not the vault);
      5. storage, 6. the database server, 7. Log Analytics, as above.

    Every function that talks to Azure takes -Arm { param([string]$Method, [string]$Path, $Body) } (see
    SI-PrivateNetwork.ps1); setup passes Invoke-SIArm, the cut-over the Support session's recording seam, tests a fake.
    No module, no az, no native exe. PS 5.1 safe.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

$script:SICmkKvApi   = '2023-07-01'
$script:SICmkSqlApi  = '2021-11-01'
$script:SICmkStApi   = '2023-05-01'
$script:SICmkMiApi   = '2023-01-31'
$script:SICmkAuthApi = '2022-04-01'
$script:SICmkLawApi  = '2022-10-01'
$script:SICmkLinkApi = '2020-08-01'
# Key Vault Crypto Service Encryption User (built-in role; read by NAME from Azure when -Arm can, this id otherwise)
$script:SICmkCryptoUserRole = 'e147488a-f6f5-4113-8e2d-b22465e65bf6'
$script:SICmkClusterCapacityGb = 100

function Get-SICustomerKeyNames {
    <# PURE. The names this option gives what it creates. No ring or environment in them (framework 12.11c). #>
    [ordered]@{ Identity = 'id-si-keys'; Key = 'si-data'; Cluster = 'log-si-cluster' }
}

function Get-SICmkProp {
    param($Object, [string[]]$Names)
    $o = $Object
    foreach ($n in $Names) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o = $o[$n] } else { return $null }; continue }
        $p = $o.PSObject.Properties[$n]
        if (-not $p) { return $null }
        $o = $p.Value
    }
    $o
}

function Read-SICmkBack {
    <# Reads -Path back until -Test is true about it, at most -Tries reads, -PauseSeconds apart. Returns the last read. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][scriptblock]$Test,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$Tries = 12, [int]$PauseSeconds = 10)
    $o = $null
    for ($i = 1; $i -le $Tries; $i++) {
        $o = & $Arm 'GET' $Path $null
        if (& $Test $o) { return $o }
        if ($i -lt $Tries) { & $Sleep $PauseSeconds }
    }
    $o
}

function Test-SICmkAccessNotYet {
    <# PURE. Azure's answer means "the identity's new right to the key is not honoured yet" (a new role assignment takes
       minutes) -- a wait, not a failure. #>
    param([AllowEmptyString()][AllowNull()][string]$Message)
    [bool]("$Message" -match '(?i)AzureKeyVaultMissingPermissions|KeyVaultAccessForbidden|does not have (the )?(required )?permissions?|not authorized to perform key|Forbidden.*key|unwrapKey|wrapKey|AKV10032|is not authorized to access the key')
}

function Get-SICustomerKeyTarget {
    <# PURE. The key to use: -KeyVaultId (default: the install's own vault) and -KeyName (default si-data), with its
       vault URI. @{ VaultId; VaultName; KeyName; VaultUri; KeyId (the ARM id of the key) }. #>
    param([Parameter(Mandatory)][string]$KeyVaultId, [string]$KeyName = '')
    $vid = $KeyVaultId.Trim().TrimEnd('/')
    $kn = if ("$KeyName".Trim()) { "$KeyName".Trim() } else { (Get-SICustomerKeyNames).Key }
    $vn = ($vid -split '/')[-1]
    [ordered]@{ VaultId = $vid; VaultName = $vn; KeyName = $kn; VaultUri = ('https://{0}.vault.azure.net/' -f $vn); KeyId = ('{0}/keys/{1}' -f $vid, $kn) }
}

# ============================================================================================================== 1. THE VAULT

function Get-SICmkVaultDecision {
    <# PURE. A customer-managed key needs soft delete and purge protection on the vault. @{ Action = 'none' | 'protect'; Reason }. #>
    param($Vault)
    if (-not $Vault) { return @{ Action = 'fail'; Reason = 'the Key Vault was not found' } }
    $sd = Get-SICmkProp $Vault @('properties', 'enableSoftDelete'); $pp = [bool](Get-SICmkProp $Vault @('properties', 'enablePurgeProtection'))
    if ($pp -and $sd -ne $false) { return @{ Action = 'none'; Reason = 'the vault has soft delete and purge protection on' } }
    @{ Action = 'protect'; Reason = 'purge protection is turned on for the vault (Azure requires it for a customer-managed key) -- ONE-WAY: Azure never turns it off, and a deleted vault keeps its name for its retention days' }
}

function Set-SICmkVaultProtection {
    <# Soft delete + purge protection ON, READ BACK. ONE-WAY. Returns @{ Ok; Line }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$VaultId, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $path = '{0}?api-version={1}' -f $VaultId.TrimEnd('/'), $script:SICmkKvApi
    $null = & $Arm 'PATCH' $path ([ordered]@{ properties = [ordered]@{ enableSoftDelete = $true; enablePurgeProtection = $true } })
    $back = Read-SICmkBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) [bool](Get-SICmkProp $o @('properties', 'enablePurgeProtection')) }
    $ok = [bool](Get-SICmkProp $back @('properties', 'enablePurgeProtection'))
    @{ Ok = $ok; Line = ('Key Vault {0}: purge protection {1}' -f ($VaultId -split '/')[-1], $(if ($ok) { 'ON (read back; one-way)' } else { 'still reads off after the change' })) }
}

# ============================================================================================================== 2. THE KEY

function Get-SICustomerKeyBody {
    <# PURE. A new key: RSA 3072, wrapKey / unwrapKey, rotated every year by Key Vault itself, expiring after two years,
       with a notice 30 days before. #>
    [ordered]@{ properties = [ordered]@{
        kty = 'RSA'; keySize = 3072; keyOps = @('wrapKey', 'unwrapKey')
        rotationPolicy = [ordered]@{
            attributes = [ordered]@{ expiryTime = 'P2Y' }
            lifetimeActions = @(
                [ordered]@{ trigger = [ordered]@{ timeAfterCreate = 'P1Y' }; action = [ordered]@{ type = 'rotate' } }
                [ordered]@{ trigger = [ordered]@{ timeBeforeExpiry = 'P30D' }; action = [ordered]@{ type = 'notify' } }) } } }
}

function Set-SICustomerKey {
    <# The key -KeyName in the vault: there = used as it is (never changed); not there = created, READ BACK. NEVER removed.
       Returns @{ Ok; Line; Created; KeyUri; KeyUriWithVersion }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)]$Target, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $path = '{0}?api-version={1}' -f $Target.KeyId, $script:SICmkKvApi
    $have = & $Arm 'GET' $path $null
    $created = $false
    if (-not $have) {
        $null = & $Arm 'PUT' $path (Get-SICustomerKeyBody)
        $have = Read-SICmkBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) [string](Get-SICmkProp $o @('properties', 'keyUriWithVersion')) }
        $created = $true
    }
    $kv = [string](Get-SICmkProp $have @('properties', 'keyUriWithVersion')); $ku = [string](Get-SICmkProp $have @('properties', 'keyUri'))
    if (-not $ku -and $kv) { $ku = $kv -replace '/[0-9a-fA-F]{32}$', '' }
    $kty = [string](Get-SICmkProp $have @('properties', 'kty'))
    if (-not $kv) { return @{ Ok = $false; Created = $created; KeyUri = ''; KeyUriWithVersion = ''; Line = ('the key {0} in {1} does not read back' -f $Target.KeyName, $Target.VaultName) } }
    if ($kty -and $kty -notmatch '^RSA') { return @{ Ok = $false; Created = $false; KeyUri = $ku; KeyUriWithVersion = $kv; Line = ('the key {0} is {1}: a customer-managed key must be an RSA key' -f $Target.KeyName, $kty) } }
    @{ Ok = $true; Created = $created; KeyUri = $ku; KeyUriWithVersion = $kv
       Line = $(if ($created) { 'key {0} created in {1} (RSA 3072, rotated every year; read back)' -f $Target.KeyName, $Target.VaultName } else { 'key {0} in {1} is used as it is' -f $Target.KeyName, $Target.VaultName }) }
}

# ============================================================================================================== 3 + 4. THE IDENTITY AND ITS ACCESS

function Set-SICustomerKeyIdentity {
    <# The user-assigned identity that uses the key, in -ResourceGroupId, READ BACK. Returns @{ Ok; Line; Id; PrincipalId; Created }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ResourceGroupId, [Parameter(Mandatory)][string]$Location, [string]$Name = '', [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    if (-not $Name) { $Name = (Get-SICustomerKeyNames).Identity }
    $id = '{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{1}' -f $ResourceGroupId.TrimEnd('/'), $Name
    $path = '{0}?api-version={1}' -f $id, $script:SICmkMiApi
    $have = & $Arm 'GET' $path $null
    $created = $false
    if (-not $have) {
        $null = & $Arm 'PUT' $path ([ordered]@{ location = $Location })
        $have = Read-SICmkBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) [string](Get-SICmkProp $o @('properties', 'principalId')) }
        $created = $true
    }
    $prin = [string](Get-SICmkProp $have @('properties', 'principalId'))
    @{ Ok = [bool]$prin; Id = $id; PrincipalId = $prin; Created = $created
       Line = $(if ($prin) { 'identity {0}{1}' -f $Name, $(if ($created) { ' created (read back)' } else { ' is there' }) } else { 'identity {0} does not read back' -f $Name }) }
}

function Set-SICustomerKeyAccess {
    <# "Key Vault Crypto Service Encryption User" for -PrincipalId on the KEY, READ BACK. Returns @{ Ok; Line; AssignmentId; Created }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$KeyId, [Parameter(Mandatory)][string]$PrincipalId, [string]$SubscriptionId = '', [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $sub = if ($SubscriptionId) { $SubscriptionId } else { ($KeyId -split '/')[2] }
    $rd = '/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/{1}' -f $sub, $script:SICmkCryptoUserRole
    $list = @()
    $lp = '{0}/providers/Microsoft.Authorization/roleAssignments?$filter={1}&api-version={2}' -f $KeyId.TrimEnd('/'), [uri]::EscapeDataString(("principalId eq '{0}'" -f $PrincipalId)), $script:SICmkAuthApi
    $page = & $Arm 'GET' $lp $null
    $list = @(Get-SICmkProp $page @('value') | Where-Object { $_ })
    $have = @($list | Where-Object { ([string](Get-SICmkProp $_ @('properties', 'roleDefinitionId'))) -match ('(?i)/' + $script:SICmkCryptoUserRole + '$') })[0]
    if ($have) { return @{ Ok = $true; Created = $false; AssignmentId = [string](Get-SICmkProp $have @('id')); Line = 'the identity may use the key (Key Vault Crypto Service Encryption User on the key)' } }
    $aid = '{0}/providers/Microsoft.Authorization/roleAssignments/{1}' -f $KeyId.TrimEnd('/'), ([guid]::NewGuid().ToString())
    $ap = '{0}?api-version={1}' -f $aid, $script:SICmkAuthApi
    $null = & $Arm 'PUT' $ap ([ordered]@{ properties = [ordered]@{ roleDefinitionId = $rd; principalId = $PrincipalId; principalType = 'ServicePrincipal' } })
    $back = Read-SICmkBack -Arm $Arm -Path $ap -Sleep $Sleep -Tries 6 -PauseSeconds 5 -Test { param($o) $null -ne $o }
    @{ Ok = ($null -ne $back); Created = $true; AssignmentId = $aid
       Line = $(if ($back) { 'the identity may use the key: Key Vault Crypto Service Encryption User on the key only (read back)' } else { 'the right of the identity on the key does not read back' }) }
}

function Invoke-SICmkWhenAccessReady {
    <# Runs -Action; Azure's "the identity may not use the key yet" (a new role assignment takes minutes) is waited for:
       -Waits seconds between tries. Any other error is rethrown at once. #>
    param([Parameter(Mandatory)][scriptblock]$Action, [int[]]$Waits = @(30, 30, 30, 60, 60, 60, 60), [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $try = 0
    while ($true) {
        try { return (& $Action) }
        catch {
            if (-not (Test-SICmkAccessNotYet -Message ([string]$_.Exception.Message)) -or $try -ge $Waits.Count) { throw }
            & $Sleep ([int]$Waits[$try]); $try++
        }
    }
}

function Add-SICmkIdentityBody {
    <# PURE. The identity block of a resource with -IdentityId ADDED to what it has (a system-assigned identity stays). #>
    param($Resource, [Parameter(Mandatory)][string]$IdentityId)
    $type = [string](Get-SICmkProp $Resource @('identity', 'type'))
    $ua = [ordered]@{}
    $have = Get-SICmkProp $Resource @('identity', 'userAssignedIdentities')
    if ($have -is [System.Collections.IDictionary]) { foreach ($k in @($have.Keys)) { $ua[[string]$k] = [ordered]@{} } }
    elseif ($have) { foreach ($p in $have.PSObject.Properties) { $ua[$p.Name] = [ordered]@{} } }
    if (-not @($ua.Keys | Where-Object { [string]::Equals($_, $IdentityId, [System.StringComparison]::OrdinalIgnoreCase) }).Count) { $ua[$IdentityId] = [ordered]@{} }
    $newType = if ($type -match '(?i)SystemAssigned') { 'SystemAssigned,UserAssigned' } else { 'UserAssigned' }
    [ordered]@{ type = $newType; userAssignedIdentities = $ua }
}

# ============================================================================================================== 5. STORAGE

function Test-SIStorageCustomerKey {
    <# PURE. Is the storage account encrypted with -KeyName in -VaultUri? #>
    param($Account, [Parameter(Mandatory)][string]$VaultUri, [Parameter(Mandatory)][string]$KeyName)
    $e = Get-SICmkProp $Account @('properties', 'encryption')
    ([string](Get-SICmkProp $e @('keySource')) -eq 'Microsoft.Keyvault') -and
    ([string](Get-SICmkProp $e @('keyvaultproperties', 'keyname')) -eq $KeyName) -and
    (([string](Get-SICmkProp $e @('keyvaultproperties', 'keyvaulturi'))).TrimEnd('/') -eq $VaultUri.TrimEnd('/'))
}

function Get-SIStorageCustomerKeyBody {
    <# PURE. The PATCH body: the identity added, encryption with the VERSIONLESS key (Azure takes up a new version itself). #>
    param($Account, [Parameter(Mandatory)][string]$IdentityId, [Parameter(Mandatory)][string]$VaultUri, [Parameter(Mandatory)][string]$KeyName)
    [ordered]@{ identity = (Add-SICmkIdentityBody -Resource $Account -IdentityId $IdentityId)
                properties = [ordered]@{ encryption = [ordered]@{
                    keySource = 'Microsoft.Keyvault'
                    keyvaultproperties = [ordered]@{ keyname = $KeyName; keyvaulturi = $VaultUri }
                    identity = [ordered]@{ userAssignedIdentity = $IdentityId }
                    services = [ordered]@{ blob = [ordered]@{ enabled = $true; keyType = 'Account' }; file = [ordered]@{ enabled = $true; keyType = 'Account' } } } } }
}

function Set-SIStorageCustomerKey {
    <# The storage account encrypted with the customer's key, READ BACK (the identity's new right is waited for).
       -Restore: back to Microsoft-managed keys. Returns @{ Ok; Line; Action }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$StorageAccountId, [string]$IdentityId = '', [string]$VaultUri = '', [string]$KeyName = '',
          [switch]$Restore, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $path = '{0}?api-version={1}' -f $StorageAccountId.TrimEnd('/'), $script:SICmkStApi
    $name = ($StorageAccountId -split '/')[-1]
    $have = & $Arm 'GET' $path $null
    if (-not $have) { return @{ Ok = $false; Action = 'none'; Line = ('storage account {0} was not found' -f $name) } }
    if ($Restore) {
        $null = & $Arm 'PATCH' $path ([ordered]@{ properties = [ordered]@{ encryption = [ordered]@{ keySource = 'Microsoft.Storage'; services = [ordered]@{ blob = [ordered]@{ enabled = $true }; file = [ordered]@{ enabled = $true } } } } })
        $back = Read-SICmkBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) [string](Get-SICmkProp $o @('properties', 'encryption', 'keySource')) -eq 'Microsoft.Storage' }
        $ok = [string](Get-SICmkProp $back @('properties', 'encryption', 'keySource')) -eq 'Microsoft.Storage'
        return @{ Ok = $ok; Action = 'restore'; Line = ('storage account {0}: {1}' -f $name, $(if ($ok) { 'Microsoft-managed keys again (read back)' } else { 'still reads the customer''s key after the change' })) }
    }
    if (Test-SIStorageCustomerKey -Account $have -VaultUri $VaultUri -KeyName $KeyName) { return @{ Ok = $true; Action = 'none'; Line = ('storage account {0} is encrypted with the key {1}' -f $name, $KeyName) } }
    $body = Get-SIStorageCustomerKeyBody -Account $have -IdentityId $IdentityId -VaultUri $VaultUri -KeyName $KeyName
    $null = Invoke-SICmkWhenAccessReady -Sleep $Sleep -Action { & $Arm 'PATCH' $path $body }
    $back = Read-SICmkBack -Arm $Arm -Path $path -Sleep $Sleep -Test { param($o) Test-SIStorageCustomerKey -Account $o -VaultUri $VaultUri -KeyName $KeyName }
    $ok = Test-SIStorageCustomerKey -Account $back -VaultUri $VaultUri -KeyName $KeyName
    @{ Ok = [bool]$ok; Action = 'change'; Line = ('storage account {0}: {1}' -f $name, $(if ($ok) { 'encrypted with the key {0} (versionless: a new version is used automatically; read back)' -f $KeyName } else { 'does NOT read back with the customer''s key' })) }
}

# ============================================================================================================== 6. THE DATABASE SERVER

function Get-SISqlServerKeyName {
    <# PURE. The server key's name Azure expects for a Key Vault key: <vault>_<key>_<version>. #>
    param([Parameter(Mandatory)][string]$KeyUriWithVersion)
    $m = [regex]::Match($KeyUriWithVersion.Trim(), '(?i)^https://([^.]+)\.vault\.azure\.net/keys/([^/]+)/([^/]+)/?$')
    if (-not $m.Success) { throw ('Not a versioned Key Vault key URI: {0}' -f $KeyUriWithVersion) }
    '{0}_{1}_{2}' -f $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value
}

function Test-SISqlCustomerKey {
    <# PURE. Is the server's TDE protector a Key Vault key of -KeyName in -VaultName (any version), with automatic rotation? #>
    param($Protector, [Parameter(Mandatory)][string]$VaultName, [Parameter(Mandatory)][string]$KeyName)
    $kind = [string](Get-SICmkProp $Protector @('properties', 'serverKeyType'))
    $sk = [string](Get-SICmkProp $Protector @('properties', 'serverKeyName'))
    ($kind -eq 'AzureKeyVault') -and ($sk -like ('{0}_{1}_*' -f $VaultName, $KeyName)) -and [bool](Get-SICmkProp $Protector @('properties', 'autoRotationEnabled'))
}

function Set-SISqlCustomerKey {
    <#
        The database server's TDE protector = the customer's key, automatic rotation ON, READ BACK: the identity added to the
        server as its primary identity, the key added as a server key, then the protector set (the identity's new right is
        waited for). -Restore: the protector back to the service-managed key. Returns @{ Ok; Lines; Action }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$ServerId, [string]$IdentityId = '', [string]$KeyUriWithVersion = '',
          [string]$VaultName = '', [string]$KeyName = '', [switch]$Restore, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $sid = $ServerId.TrimEnd('/'); $name = ($sid -split '/')[-1]
    $pp = '{0}/encryptionProtector/current?api-version={1}' -f $sid, $script:SICmkSqlApi
    $lines = New-Object System.Collections.Generic.List[string]
    if ($Restore) {
        $null = & $Arm 'PUT' $pp ([ordered]@{ properties = [ordered]@{ serverKeyType = 'ServiceManaged'; serverKeyName = 'ServiceManaged' } })
        $back = Read-SICmkBack -Arm $Arm -Path $pp -Sleep $Sleep -Test { param($o) [string](Get-SICmkProp $o @('properties', 'serverKeyType')) -eq 'ServiceManaged' }
        $ok = [string](Get-SICmkProp $back @('properties', 'serverKeyType')) -eq 'ServiceManaged'
        return @{ Ok = $ok; Action = 'restore'; Lines = @(('database server {0}: {1}' -f $name, $(if ($ok) { 'the service-managed key again (read back)' } else { 'still reads the customer''s key after the change' }))) }
    }
    $prot = & $Arm 'GET' $pp $null
    if (Test-SISqlCustomerKey -Protector $prot -VaultName $VaultName -KeyName $KeyName) { return @{ Ok = $true; Action = 'none'; Lines = @(('database server {0}: TDE uses the key {1}, rotated automatically' -f $name, $KeyName)) } }
    $sp = '{0}?api-version={1}' -f $sid, $script:SICmkSqlApi
    $server = & $Arm 'GET' $sp $null
    if (-not $server) { return @{ Ok = $false; Action = 'none'; Lines = @(('database server {0} was not found' -f $name)) } }
    if (-not (Test-SIPnSameIdCmk ([string](Get-SICmkProp $server @('properties', 'primaryUserAssignedIdentityId'))) $IdentityId)) {
        $null = & $Arm 'PATCH' $sp ([ordered]@{ identity = (Add-SICmkIdentityBody -Resource $server -IdentityId $IdentityId); properties = [ordered]@{ primaryUserAssignedIdentityId = $IdentityId } })
        $b = Read-SICmkBack -Arm $Arm -Path $sp -Sleep $Sleep -Test { param($o) Test-SIPnSameIdCmk ([string](Get-SICmkProp $o @('properties', 'primaryUserAssignedIdentityId'))) $IdentityId }
        if (-not (Test-SIPnSameIdCmk ([string](Get-SICmkProp $b @('properties', 'primaryUserAssignedIdentityId'))) $IdentityId)) { return @{ Ok = $false; Action = 'change'; Lines = @(('database server {0}: its identity does not read back' -f $name)) } }
        $lines.Add(('database server {0}: signs in to the vault as {1} (read back)' -f $name, ($IdentityId -split '/')[-1]))
    }
    $skName = Get-SISqlServerKeyName -KeyUriWithVersion $KeyUriWithVersion
    $kp = '{0}/keys/{1}?api-version={2}' -f $sid, $skName, $script:SICmkSqlApi
    if (-not (& $Arm 'GET' $kp $null)) {
        $null = Invoke-SICmkWhenAccessReady -Sleep $Sleep -Action { & $Arm 'PUT' $kp ([ordered]@{ properties = [ordered]@{ serverKeyType = 'AzureKeyVault'; uri = $KeyUriWithVersion } }) }
        $kb = Read-SICmkBack -Arm $Arm -Path $kp -Sleep $Sleep -Test { param($o) $null -ne $o }
        if (-not $kb) { return @{ Ok = $false; Action = 'change'; Lines = @($lines + @(('database server {0}: the key {1} does not read back as a server key' -f $name, $KeyName))) } }
        $lines.Add(('database server {0}: the key {1} added (read back)' -f $name, $KeyName))
    }
    $null = Invoke-SICmkWhenAccessReady -Sleep $Sleep -Action { & $Arm 'PUT' $pp ([ordered]@{ properties = [ordered]@{ serverKeyType = 'AzureKeyVault'; serverKeyName = $skName; autoRotationEnabled = $true } }) }
    $back = Read-SICmkBack -Arm $Arm -Path $pp -Sleep $Sleep -Test { param($o) Test-SISqlCustomerKey -Protector $o -VaultName $VaultName -KeyName $KeyName }
    $ok = Test-SISqlCustomerKey -Protector $back -VaultName $VaultName -KeyName $KeyName
    $lines.Add(('database server {0}: {1}' -f $name, $(if ($ok) { 'TDE uses the key {0}, rotated automatically (read back; every database on the server)' -f $KeyName } else { 'TDE does NOT read back with the customer''s key' })))
    @{ Ok = [bool]$ok; Action = 'change'; Lines = $lines.ToArray() }
}

function Test-SIPnSameIdCmk {
    param([AllowNull()][string]$A, [AllowNull()][string]$B)
    $x = "$A".Trim().TrimEnd('/'); $y = "$B".Trim().TrimEnd('/')
    [bool]($x -and $y -and [string]::Equals($x, $y, [System.StringComparison]::OrdinalIgnoreCase))
}

# ============================================================================================================== 7. LOG ANALYTICS

function Get-SILogAnalyticsClusterBody {
    <# PURE. A dedicated Log Analytics cluster with the customer's key (versionless: Azure takes up a new version), as the
       key identity, at the smallest commitment tier. #>
    param([Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$IdentityId, [Parameter(Mandatory)][string]$VaultUri, [Parameter(Mandatory)][string]$KeyName)
    $ua = [ordered]@{}; $ua[$IdentityId] = [ordered]@{}
    [ordered]@{ location = $Location; identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $ua }
                sku = [ordered]@{ name = 'CapacityReservation'; capacity = $script:SICmkClusterCapacityGb }
                properties = [ordered]@{ keyVaultProperties = [ordered]@{ keyVaultUri = $VaultUri; keyName = $KeyName; keyVersion = '' } } }
}

function Test-SIClusterCustomerKey {
    <# PURE. Does the cluster hold a customer-managed key (any key of a vault -- an existing cluster of the customer's)? #>
    param($Cluster)
    [bool]([string](Get-SICmkProp $Cluster @('properties', 'keyVaultProperties', 'keyName')))
}

function Set-SILogAnalyticsCustomerKey {
    <#
        The install's workspace linked to a Log Analytics cluster that holds the customer's key, READ BACK.
          -ClusterId given   the customer's existing cluster (it must hold a customer-managed key already)
          -Create            the cluster -ClusterName made in -ResourceGroupId with the key (Azure takes up to two hours:
                             when it is not ready yet the step says so and is run again later -- nothing waits for hours)
        Data the workspace received before the link stays encrypted with Microsoft's keys. -Restore: the workspace
        unlinked (new data then uses Microsoft's keys). Returns @{ Ok; Lines; Action; Pending; ClusterId; Created }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$WorkspaceId, [string]$ClusterId = '', [switch]$Create,
          [string]$ResourceGroupId = '', [string]$ClusterName = '', [string]$Location = '', [string]$IdentityId = '', [string]$VaultUri = '', [string]$KeyName = '',
          [switch]$Restore, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $ws = $WorkspaceId.TrimEnd('/'); $wn = ($ws -split '/')[-1]
    $lp = '{0}/linkedServices/cluster?api-version={1}' -f $ws, $script:SICmkLinkApi
    $lines = New-Object System.Collections.Generic.List[string]
    $link = & $Arm 'GET' $lp $null
    if ($Restore) {
        if (-not $link) { return @{ Ok = $true; Action = 'none'; Pending = $false; ClusterId = ''; Created = $false; Lines = @(('workspace {0} is not linked to a cluster' -f $wn)) } }
        $null = & $Arm 'DELETE' $lp $null
        $gone = Read-SICmkBack -Arm $Arm -Path $lp -Sleep $Sleep -Tries 30 -PauseSeconds 20 -Test { param($o) $null -eq $o }
        return @{ Ok = ($null -eq $gone); Action = 'restore'; Pending = $false; ClusterId = ''; Created = $false; Lines = @(('workspace {0}: {1}' -f $wn, $(if ($null -eq $gone) { 'unlinked from the cluster -- new data uses Microsoft''s keys (read back)' } else { 'still reads linked after the unlink was asked for' }))) }
    }
    $created = $false
    if (-not $ClusterId) {
        if (-not $Create) { return @{ Ok = $false; Action = 'none'; Pending = $false; ClusterId = ''; Created = $false; Lines = @('no Log Analytics cluster was named and none is to be made') } }
        if (-not $ClusterName) { $ClusterName = (Get-SICustomerKeyNames).Cluster }
        $ClusterId = '{0}/providers/Microsoft.OperationalInsights/clusters/{1}' -f $ResourceGroupId.TrimEnd('/'), $ClusterName
    }
    $cp = '{0}?api-version={1}' -f $ClusterId.TrimEnd('/'), $script:SICmkLawApi
    $cluster = & $Arm 'GET' $cp $null
    if (-not $cluster) {
        if (-not $Create) { return @{ Ok = $false; Action = 'none'; Pending = $false; ClusterId = $ClusterId; Created = $false; Lines = @(('the Log Analytics cluster {0} was not found' -f ($ClusterId -split '/')[-1])) } }
        $null = Invoke-SICmkWhenAccessReady -Sleep $Sleep -Action { & $Arm 'PUT' $cp (Get-SILogAnalyticsClusterBody -Location $Location -IdentityId $IdentityId -VaultUri $VaultUri -KeyName $KeyName) }
        $cluster = & $Arm 'GET' $cp $null
        $created = $true
        $lines.Add(('Log Analytics cluster {0} asked for with the key {1} ({2} GB a day commitment)' -f ($ClusterId -split '/')[-1], $KeyName, $script:SICmkClusterCapacityGb))
    }
    $state = [string](Get-SICmkProp $cluster @('properties', 'provisioningState'))
    if ($state -ne 'Succeeded') {
        $lines.Add(('the cluster is still being made by Azure ({0}; this takes up to two hours) -- run the same step again later: it links the workspace then' -f $(if ($state) { $state } else { 'no state yet' })))
        return @{ Ok = $true; Action = 'change'; Pending = $true; ClusterId = $ClusterId; Created = $created; Lines = $lines.ToArray() }
    }
    if (-not (Test-SIClusterCustomerKey -Cluster $cluster)) { return @{ Ok = $false; Action = 'none'; Pending = $false; ClusterId = $ClusterId; Created = $created; Lines = @($lines + @(('the cluster {0} holds no customer-managed key -- the workspace is not linked to it' -f ($ClusterId -split '/')[-1]))) } }
    if ($link -and (Test-SIPnSameIdCmk ([string](Get-SICmkProp $link @('properties', 'writeAccessResourceId'))) $ClusterId)) {
        $lines.Add(('workspace {0} is linked to the cluster {1}' -f $wn, ($ClusterId -split '/')[-1]))
        return @{ Ok = $true; Action = 'none'; Pending = $false; ClusterId = $ClusterId; Created = $created; Lines = $lines.ToArray() }
    }
    $null = & $Arm 'PUT' $lp ([ordered]@{ properties = [ordered]@{ writeAccessResourceId = $ClusterId } })
    $back = Read-SICmkBack -Arm $Arm -Path $lp -Sleep $Sleep -Tries 30 -PauseSeconds 20 -Test { param($o) [string](Get-SICmkProp $o @('properties', 'provisioningState')) -in 'Succeeded', 'Failed' }
    $ok = [string](Get-SICmkProp $back @('properties', 'provisioningState')) -eq 'Succeeded'
    $lines.Add(('workspace {0}: {1}' -f $wn, $(if ($ok) { 'linked to the cluster {0}: new data is encrypted with the customer''s key (read back; data from before stays with Microsoft''s keys)' -f ($ClusterId -split '/')[-1] } else { 'the link to the cluster does not read back as done' })))
    @{ Ok = [bool]$ok; Action = 'change'; Pending = $false; ClusterId = $ClusterId; Created = $created; Lines = $lines.ToArray() }
}

# ============================================================================================================== SETUP'S CALL

function Invoke-SICustomerKeySetup {
    <#
        Setup's call (the guided install, after the database and the updater): the whole option over setup's own ARM
        sign-in (Invoke-SIArm unless -Arm is given), in order -- vault protection, key, identity, access, storage, database
        server (Pro), Log Analytics (-LogAnalytics 'off' | 'cluster-new' | 'cluster-existing'). A piece that fails stops the
        pieces after it that need it (no data is ever switched to a key the identity cannot use). Returns @{ Ok; Lines; Pending }.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroupId, [Parameter(Mandatory)][string]$Location, [Parameter(Mandatory)][string]$KeyVaultId, [string]$KeyName = '',
          [string]$StorageAccountId = '', [string]$SqlServerId = '', [string]$WorkspaceId = '',
          [ValidateSet('off', 'cluster-new', 'cluster-existing')][string]$LogAnalytics = 'off', [string]$ClusterId = '',
          [scriptblock]$Arm, [scriptblock]$Sleep, [string]$SubscriptionId)
    if (-not $Arm) { $Arm = { param([string]$Method, [string]$Path, $Body) if ($Method -eq 'GET') { Invoke-SIArm -Path $Path -AllowNotFound } else { Invoke-SIArm -Method $Method -Path $Path -Body $Body } } }
    if (-not $Sleep) { $Sleep = { param($s) Start-Sleep -Seconds $s } }
    $lines = New-Object System.Collections.Generic.List[string]
    $t = Get-SICustomerKeyTarget -KeyVaultId $KeyVaultId -KeyName $KeyName
    $vault = & $Arm 'GET' ('{0}?api-version={1}' -f $t.VaultId, $script:SICmkKvApi) $null
    $vd = Get-SICmkVaultDecision -Vault $vault
    if ($vd.Action -eq 'fail') { return @{ Ok = $false; Pending = $false; Lines = @(('Customer-managed keys: {0} ({1}). Nothing was changed.' -f $vd.Reason, $t.VaultName)) } }
    if ($vd.Action -eq 'protect') { $x = Set-SICmkVaultProtection -Arm $Arm -VaultId $t.VaultId -Sleep $Sleep; $lines.Add($x.Line); if (-not $x.Ok) { return @{ Ok = $false; Pending = $false; Lines = $lines.ToArray() } } }
    $k = Set-SICustomerKey -Arm $Arm -Target $t -Sleep $Sleep; $lines.Add($k.Line); if (-not $k.Ok) { return @{ Ok = $false; Pending = $false; Lines = $lines.ToArray() } }
    $i = Set-SICustomerKeyIdentity -Arm $Arm -ResourceGroupId $ResourceGroupId -Location $Location -Sleep $Sleep; $lines.Add($i.Line); if (-not $i.Ok) { return @{ Ok = $false; Pending = $false; Lines = $lines.ToArray() } }
    $a = Set-SICustomerKeyAccess -Arm $Arm -KeyId $t.KeyId -PrincipalId $i.PrincipalId -Sleep $Sleep; $lines.Add($a.Line); if (-not $a.Ok) { return @{ Ok = $false; Pending = $false; Lines = $lines.ToArray() } }
    $ok = $true; $pending = $false
    if ($StorageAccountId) { $s = Set-SIStorageCustomerKey -Arm $Arm -StorageAccountId $StorageAccountId -IdentityId $i.Id -VaultUri $t.VaultUri -KeyName $t.KeyName -Sleep $Sleep; $lines.Add($s.Line); if (-not $s.Ok) { $ok = $false } }
    if ($SqlServerId) { $q = Set-SISqlCustomerKey -Arm $Arm -ServerId $SqlServerId -IdentityId $i.Id -KeyUriWithVersion $k.KeyUriWithVersion -VaultName $t.VaultName -KeyName $t.KeyName -Sleep $Sleep; foreach ($l in $q.Lines) { $lines.Add($l) }; if (-not $q.Ok) { $ok = $false } }
    if ($LogAnalytics -ne 'off' -and $WorkspaceId) {
        $la = Set-SILogAnalyticsCustomerKey -Arm $Arm -WorkspaceId $WorkspaceId -ClusterId $ClusterId -Create:($LogAnalytics -eq 'cluster-new') -ResourceGroupId $ResourceGroupId -Location $Location -IdentityId $i.Id -VaultUri $t.VaultUri -KeyName $t.KeyName -Sleep $Sleep
        foreach ($l in $la.Lines) { $lines.Add($l) }; if (-not $la.Ok) { $ok = $false }; if ($la.Pending) { $pending = $true }
    }
    @{ Ok = $ok; Pending = $pending; Lines = $lines.ToArray() }
}
