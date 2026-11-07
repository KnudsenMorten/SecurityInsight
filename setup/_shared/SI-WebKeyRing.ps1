#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE WEB APP'S SIGN-IN KEYS, ENCRYPTED WITH A KEY VAULT KEY (pro-management/src/SI.Management.Web/
    Auth/KeyRingProtection.cs). One converge, run by setup (pro-management\deploy\Deploy-SIManagement.ps1) and by the updater
    on every run (container\updater\Start-SIUpdater.ps1), so a new install and an existing one reach the same state:

      1. THE KEY   'SI-Web-KeyRing' in the install's Key Vault: RSA 3072, wrapKey / unwrapKey only, never exportable.
                   Created when missing (keys/create), read otherwise.
      2. THE GRANT "Key Vault Crypto Service Encryption User" for the web app's identities, at the SCOPE OF THAT ONE KEY
                   (never the vault): the web app may wrap and unwrap with it, and nothing else. A deterministic assignment
                   name per (key, identity), so a re-run adds nothing (409 = already there). Only on a vault that uses
                   Azure RBAC (with access policies a role grants nothing: nothing is set, and it is said).
                   SETUP makes the grant (run by an Owner). THE UPDATER (-CheckGrantOnly) may not give roles: it only
                   checks the grant, and a missing one is the customer's action with the command -- never a failed update.
      3. THE SETTING DataProtection__KeyVaultKeyId on the web app -- ONLY after every grant is in place (the web app turns
                   the protection on when it sees it, and rotates the keys stored before without encryption).
    SETUP (#1098) reads both back before the setting: the key (a GET after it is made) and the grant (the list of the role
    assignments on the key shows the identity). When the vault's DATA PLANE cannot be used from the installing machine (a
    private vault answers only inside its network; or the installer's Key Vault right is not honoured yet) setup reads -- and
    when missing makes -- the key through Azure Resource Manager (the management plane: Microsoft.KeyVault/vaults/keys), so
    the grant (always ARM) is still made whenever the key exists. A refused role write (401 / 403) is NOT KNOWN: a customer
    task naming the role, the key and the identity -- never a stop.
    Any step that cannot be done is said in plain words and the later steps are not taken: the web app keeps working exactly
    as before. Seams (-Arm, -KeyVault, -SetEnv) carry every Azure call, so it runs offline in the tests. Never throws.
#>

$script:SIWebKeyRingKeyName = 'SI-Web-KeyRing'
$script:SIWebKeyRingRoleId = 'e147488a-f6f5-4113-8e2d-b22465e65bf6'   # Key Vault Crypto Service Encryption User
$script:SIWebKeyRingEnv = 'DataProtection__KeyVaultKeyId'

function Get-SIWebKeyRingKeyId {
    <# PURE. The versionless key id the web app is given. #>
    param([Parameter(Mandatory)][string]$VaultName)
    'https://{0}.vault.azure.net/keys/{1}' -f $VaultName.Trim().ToLowerInvariant(), $script:SIWebKeyRingKeyName
}

function Get-SIWebKeyRingAssignmentName {
    <# PURE. A stable role assignment name (a GUID) for one identity on the key, so a re-run never adds a second one. #>
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$PrincipalId)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try { $b = $md5.ComputeHash([Text.Encoding]::UTF8.GetBytes(('si-web-keyring|{0}|{1}|{2}' -f $Scope.ToLowerInvariant(), $PrincipalId.ToLowerInvariant(), $script:SIWebKeyRingRoleId))) } finally { $md5.Dispose() }
    ([guid]::new($b)).ToString()
}

function Get-SIWebKeyRingCreateBody {
    <# PURE. The key: RSA 3072, wrap / unwrap only, never exportable. #>
    [ordered]@{ kty = 'RSA'; key_size = 3072; key_ops = @('wrapKey', 'unwrapKey'); attributes = [ordered]@{ enabled = $true; exportable = $false }
                tags = [ordered]@{ purpose = 'SecurityInsight web app sign-in keys: only the web app wraps and unwraps with it' } }
}

function Get-SIWebKeyRingArmCreateBody {
    <# PURE. The same key as Get-SIWebKeyRingCreateBody, in Azure Resource Manager's shape (Microsoft.KeyVault/vaults/keys). #>
    [ordered]@{ tags = [ordered]@{ purpose = 'SecurityInsight web app sign-in keys: only the web app wraps and unwraps with it' }
                properties = [ordered]@{ kty = 'RSA'; keySize = 3072; keyOps = @('wrapKey', 'unwrapKey'); attributes = [ordered]@{ enabled = $true; exportable = $false } } }
}

function Get-SIWebKeyRingGrantTask {
    <# PURE. #1098: the customer task when setup may not give the web app its role on the key (a refused role write = not known). #>
    param([Parameter(Mandatory)][string]$Scope, [Parameter(Mandatory)][string]$PrincipalId, [AllowEmptyString()][string]$IdentityName = '', [int]$Status = 403)
    $who = if ("$IdentityName".Trim()) { 'the web app''s managed identity {0} (object id {1})' -f "$IdentityName".Trim(), $PrincipalId } else { 'the web app''s managed identity (object id {0})' -f $PrincipalId }
    ('CUSTOMER TASK (not known -- you may not give roles here, HTTP {0}): Azure role "Key Vault Crypto Service Encryption User" on the key SI-Web-KeyRing ({1}) for {2} -- Azure portal: the Key Vault > Keys > SI-Web-KeyRing > Access control (IAM) > Add role assignment. The updater then turns the protection on by itself.' -f $Status, $Scope, $who)
}

function Invoke-SIWebKeyRingConverge {
    <#
        The three steps. -Arm { param($Method, $Path, $ApiVersion, $Body) } -> @{ Status; Json }; -KeyVault { param($Method,
        $Uri, $Body) } -> @{ Status; Json }; -SetEnv { param($Name, $Value) } -> $true when it changed (throws on failure).
        -VaultId: the vault's ARM id; -PrincipalIds: the web app's identities; -CurrentEnv: the web app's value today.
        Returns @{ Ok; KeyId; Lines; Report (a failure); CustomerAction (texts); Actions (@{ Text; Class } per customer
        action: grant-missing = the web identity has no grant on the key, config-missing = the vault uses access policies);
        Warnings (@{ Text; Class }: grant-not-known = the updater cannot read the grants, a 401 / 403 on the read -- not
        known, never "missing" and never a failure) }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$KeyVault, [Parameter(Mandatory)][scriptblock]$SetEnv,
          [Parameter(Mandatory)][string]$VaultName, [AllowEmptyString()][string]$VaultId = '', [AllowEmptyCollection()][string[]]$PrincipalIds = @(),
          [AllowEmptyString()][string]$SubscriptionId = '', [AllowEmptyString()][string]$CurrentEnv = '',
          # THE UPDATER: it may not give roles (no roleAssignments/write) -- it only CHECKS the grant, and a missing one is
          # the customer's action (CustomerAction), never a failed update. Setup (run by an Owner) makes the grant.
          [switch]$CheckGrantOnly,
          # the words of the customer's action: the command that makes the grant
          [string]$GrantCommand = 'pro-management\deploy\Deploy-SIManagement.ps1 -SigninStoreKeyVaultName <your Key Vault> -Apply (as an Owner of the resource group)',
          # #1098: the web app's identity by name, for the customer task when the role may not be given
          [AllowEmptyString()][string]$IdentityName = '')
    $lines = New-Object System.Collections.Generic.List[string]; $report = New-Object System.Collections.Generic.List[string]; $action = New-Object System.Collections.Generic.List[string]
    $actions = New-Object System.Collections.Generic.List[object]; $warnings = New-Object System.Collections.Generic.List[object]
    $addAction = { param($t, $c) $action.Add($t); $actions.Add([pscustomobject]@{ Text = $t; Class = $c }) }
    $keyId = Get-SIWebKeyRingKeyId -VaultName $VaultName
    $done = { param($ok) [pscustomobject]@{ Ok = [bool]$ok; KeyId = $keyId; Lines = $lines.ToArray(); Report = $report.ToArray(); CustomerAction = $action.ToArray()
                                            Actions = $actions.ToArray(); Warnings = $warnings.ToArray() } }
    $keyMade = $false
    try {
        # 1. the key
        $g = & $KeyVault 'GET' ('{0}?api-version=7.4' -f $keyId) $null
        if ([int]$g.Status -eq 404) { $g = & $KeyVault 'POST' ('{0}/create?api-version=7.4' -f $keyId) (Get-SIWebKeyRingCreateBody); if ([int]$g.Status -ge 200 -and [int]$g.Status -lt 300) { $keyMade = $true; $lines.Add('web sign-in keys: the Key Vault key SI-Web-KeyRing was created') } }
        $keyOk = [int]$g.Status -ge 200 -and [int]$g.Status -lt 300 -and $g.Json -and $g.Json.key
        if ($keyOk -and $keyMade -and -not $CheckGrantOnly) {
            # #1098: setup reads the key it made back
            $rb = & $KeyVault 'GET' ('{0}?api-version=7.4' -f $keyId) $null
            $keyOk = [int]$rb.Status -ge 200 -and [int]$rb.Status -lt 300 -and $rb.Json -and $rb.Json.key
            if ($keyOk) { $lines.Add('web sign-in keys: the key SI-Web-KeyRing reads back') } else { $g = $rb }
        }
        if (-not $keyOk -and -not $CheckGrantOnly -and $VaultId) {
            # #1098: the vault's data plane cannot be used from here (a private vault answers only inside its network, or the
            # installer's Key Vault right is not honoured yet) -- the key is read, and made when missing, through Azure
            # Resource Manager, so the grant below (ARM) is still made whenever the key exists
            $dpStatus = [int]$g.Status
            $armKey = '{0}/keys/{1}' -f $VaultId.TrimEnd('/'), $script:SIWebKeyRingKeyName
            $ak = & $Arm 'GET' $armKey '2023-07-01' $null
            if ([int]$ak.Status -eq 404) {
                $null = & $Arm 'PUT' $armKey '2023-07-01' (Get-SIWebKeyRingArmCreateBody)
                $ak = & $Arm 'GET' $armKey '2023-07-01' $null
                if ([int]$ak.Status -ge 200 -and [int]$ak.Status -lt 300 -and $ak.Json) { $keyMade = $true; $lines.Add('web sign-in keys: the Key Vault key SI-Web-KeyRing was created through Azure Resource Manager and reads back') }
            }
            if ([int]$ak.Status -ge 200 -and [int]$ak.Status -lt 300 -and $ak.Json) {
                $keyOk = $true
                if (-not $keyMade) { $lines.Add(('web sign-in keys: the key SI-Web-KeyRing exists (read through Azure Resource Manager; the vault''s data plane answered HTTP {0} from here)' -f $dpStatus)) }
            } else {
                $report.Add(('the web app''s sign-in keys are not protected with Key Vault yet: the key SI-Web-KeyRing could not be made or read from this machine -- the Key Vault answered HTTP {0} (a private Key Vault answers only inside its network) and Azure Resource Manager HTTP {1} -- the updater, inside the network, makes the key on its next run' -f $dpStatus, [int]$ak.Status))
                return (& $done $false)
            }
        }
        if (-not $keyOk) {
            $report.Add(('the web app''s sign-in keys are not protected with Key Vault yet: the key could not be made or read in your Key Vault (HTTP {0}) -- the updater tries again on its next run' -f [int]$g.Status))
            return (& $done $false)
        }
        # 2. the grant, on the key only
        if (-not $VaultId -or -not $SubscriptionId) { $report.Add('the web app''s sign-in keys are not protected with Key Vault yet: the vault could not be found from here'); return (& $done $false) }
        $principals = @($PrincipalIds | Where-Object { $_ })
        if (-not $principals.Count) { $report.Add('the web app''s sign-in keys are not protected with Key Vault yet: the web app''s identity could not be read'); return (& $done $false) }
        # the vault must use Azure RBAC: on a vault with access policies a role on the key grants nothing, wrap / unwrap
        # would fail and sign-in would break the first time a new key is made -- so nothing is set, and it is said
        $v = & $Arm 'GET' $VaultId.TrimEnd('/') '2023-07-01' $null
        if ([int]$v.Status -lt 200 -or [int]$v.Status -ge 300 -or -not $v.Json) {
            $report.Add(('the web app''s sign-in keys are not protected with Key Vault yet: the vault could not be read (HTTP {0}) -- the updater tries again on its next run' -f [int]$v.Status))
            return (& $done $false)
        }
        $props = if ($v.Json.PSObject.Properties['properties']) { $v.Json.properties } else { $null }
        $rbac = $props -and $props.PSObject.Properties['enableRbacAuthorization'] -and [bool]$props.enableRbacAuthorization
        if (-not $rbac) {
            & $addAction ('the web app''s sign-in keys are not protected with Key Vault: the Key Vault {0} uses access policies, not Azure RBAC -- switch it to Azure RBAC, then run {1}' -f $VaultName, $GrantCommand) 'config-missing'
            return (& $done $false)
        }
        $scope = '{0}/keys/{1}' -f $VaultId.TrimEnd('/'), $script:SIWebKeyRingKeyName
        if ($CheckGrantOnly -and $keyMade) {
            # 3.0.30: a key made a moment ago has no grant on it yet (setup grants it) -- never a "missing grant" in its first run
            $lines.Add('web sign-in keys: the key was just made; the grant is checked on the next run')
            return (& $done $false)
        }
        if ($CheckGrantOnly) {
            # the roles that let the web app wrap / unwrap with the key: Crypto Service Encryption User, Crypto User, Crypto
            # Officer, Key Vault Administrator -- on the key or above it
            $wrapRoles = @($script:SIWebKeyRingRoleId, '12338af0-0e69-4776-bea7-57ae8d297424', '14b46e9e-c2b7-41b4-b07b-48a6ebf60603', '00482a5a-887f-4fb3-b363-3b7fe8e74483')
            $l = & $Arm 'GET' ('{0}/providers/Microsoft.Authorization/roleAssignments?$filter=atScope()' -f $scope) '2022-04-01' $null
            if ([int]$l.Status -in @(401, 403)) {
                # 3.0.30: the updater may not READ the grants (no Microsoft.Authorization/roleAssignments/read there): whether
                # the web app has its grant is NOT KNOWN -- a warning, never "missing" (a customer action) and never a failure
                $warnings.Add([pscustomobject]@{ Text = ('web sign-in keys: not known -- the updater cannot read the grants on the key SI-Web-KeyRing (HTTP {0}); nothing was changed, the check runs again on the next run' -f [int]$l.Status); Class = 'grant-not-known' })
                return (& $done $false)
            }
            if ([int]$l.Status -lt 200 -or [int]$l.Status -ge 300 -or -not $l.Json) {
                $report.Add(('the web app''s sign-in keys are not protected with Key Vault yet: the grants on its key could not be read (HTTP {0}) -- the updater tries again on its next run' -f [int]$l.Status))
                return (& $done $false)
            }
            $have = @(@($l.Json.value) | Where-Object { $_ -and $_.properties } | ForEach-Object { $_.properties } | Where-Object {
                    $rid = [string]$_.roleDefinitionId; @($wrapRoles | Where-Object { $rid.EndsWith('/' + $_, [StringComparison]::OrdinalIgnoreCase) }).Count })
            foreach ($p in $principals) {
                if (-not @($have | Where-Object { [string]$_.principalId -ieq $p }).Count) {
                    & $addAction ('the web app''s sign-in keys are not protected with Key Vault yet: the web app may not use its Key Vault key SI-Web-KeyRing -- run {0}' -f $GrantCommand) 'grant-missing'
                    return (& $done $false)
                }
            }
        }
        foreach ($p in $(if ($CheckGrantOnly) { @() } else { $principals })) {
            $path = '{0}/providers/Microsoft.Authorization/roleAssignments/{1}' -f $scope, (Get-SIWebKeyRingAssignmentName -Scope $scope -PrincipalId $p)
            $body = [ordered]@{ properties = [ordered]@{ roleDefinitionId = ('/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/{1}' -f $SubscriptionId, $script:SIWebKeyRingRoleId); principalId = $p; principalType = 'ServicePrincipal' } }
            $r = & $Arm 'PUT' $path '2022-04-01' $body
            $st = [int]$r.Status
            if ($st -eq 409 -or ($st -ge 200 -and $st -lt 300)) {
                # #1098: read back -- the list of the role assignments on the key shows the identity with the role
                $rb = & $Arm 'GET' ('{0}/providers/Microsoft.Authorization/roleAssignments?$filter=atScope()' -f $scope) '2022-04-01' $null
                $seen = ([int]$rb.Status -ge 200 -and [int]$rb.Status -lt 300 -and $rb.Json) -and @(@($rb.Json.value) | Where-Object { $_ -and $_.properties -and [string]$_.properties.principalId -ieq $p -and ([string]$_.properties.roleDefinitionId).EndsWith('/' + $script:SIWebKeyRingRoleId, [StringComparison]::OrdinalIgnoreCase) }).Count
                if (-not $seen) {
                    $report.Add(('the web app''s sign-in keys are not protected with Key Vault yet: the web app''s use of its key did not read back (HTTP {0}) -- the setting is not set; the updater checks it again on its next run' -f [int]$rb.Status))
                    return (& $done $false)
                }
                $lines.Add('web sign-in keys: the web app may use the key SI-Web-KeyRing (that key only; read back)')
                continue
            }
            if ($st -in @(401, 403)) {
                # #1098 (the 403-outside rule, #1088): the person may not give roles -- NOT KNOWN, a customer task naming the
                # role, the key and the identity; never a stop, and the setting is not set
                & $addAction (Get-SIWebKeyRingGrantTask -Scope $scope -PrincipalId $p -IdentityName $IdentityName -Status $st) 'grant-missing'
                return (& $done $false)
            }
            $report.Add(('the web app''s sign-in keys are not protected with Key Vault yet: the web app could not be given the use of its key (HTTP {0}) -- the updater tries again on its next run' -f $st))
            return (& $done $false)
        }
        # 3. the setting, only now
        if ([string]::Equals("$CurrentEnv".Trim().TrimEnd('/'), $keyId, [StringComparison]::OrdinalIgnoreCase)) { return (& $done $true) }
        $changed = & $SetEnv $script:SIWebKeyRingEnv $keyId
        if ($changed) { $lines.Add('web sign-in keys: the web app protects them with its Key Vault key from now on (its keys from before are retired once: everyone signs in again once)') }
        return (& $done $true)
    } catch {
        $report.Add(('the web app''s sign-in keys are not protected with Key Vault yet: {0}' -f $_.Exception.Message))
        return (& $done $false)
    }
}
