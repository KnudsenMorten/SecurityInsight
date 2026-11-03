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

function Invoke-SIWebKeyRingConverge {
    <#
        The three steps. -Arm { param($Method, $Path, $ApiVersion, $Body) } -> @{ Status; Json }; -KeyVault { param($Method,
        $Uri, $Body) } -> @{ Status; Json }; -SetEnv { param($Name, $Value) } -> $true when it changed (throws on failure).
        -VaultId: the vault's ARM id; -PrincipalIds: the web app's identities; -CurrentEnv: the web app's value today.
        Returns @{ Ok; KeyId; Lines; Report }. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][scriptblock]$KeyVault, [Parameter(Mandatory)][scriptblock]$SetEnv,
          [Parameter(Mandatory)][string]$VaultName, [AllowEmptyString()][string]$VaultId = '', [AllowEmptyCollection()][string[]]$PrincipalIds = @(),
          [AllowEmptyString()][string]$SubscriptionId = '', [AllowEmptyString()][string]$CurrentEnv = '',
          # THE UPDATER: it may not give roles (no roleAssignments/write) -- it only CHECKS the grant, and a missing one is
          # the customer's action (CustomerAction), never a failed update. Setup (run by an Owner) makes the grant.
          [switch]$CheckGrantOnly,
          # the words of the customer's action: the command that makes the grant
          [string]$GrantCommand = 'pro-management\deploy\Deploy-SIManagement.ps1 -SigninStoreKeyVaultName <your Key Vault> -Apply (as an Owner of the resource group)')
    $lines = New-Object System.Collections.Generic.List[string]; $report = New-Object System.Collections.Generic.List[string]; $action = New-Object System.Collections.Generic.List[string]
    $keyId = Get-SIWebKeyRingKeyId -VaultName $VaultName
    $done = { param($ok) [pscustomobject]@{ Ok = [bool]$ok; KeyId = $keyId; Lines = $lines.ToArray(); Report = $report.ToArray(); CustomerAction = $action.ToArray() } }
    try {
        # 1. the key
        $g = & $KeyVault 'GET' ('{0}?api-version=7.4' -f $keyId) $null
        if ([int]$g.Status -eq 404) { $g = & $KeyVault 'POST' ('{0}/create?api-version=7.4' -f $keyId) (Get-SIWebKeyRingCreateBody); if ([int]$g.Status -ge 200 -and [int]$g.Status -lt 300) { $lines.Add('web sign-in keys: the Key Vault key SI-Web-KeyRing was created') } }
        if ([int]$g.Status -lt 200 -or [int]$g.Status -ge 300 -or -not $g.Json -or -not $g.Json.key) {
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
            $action.Add(('the web app''s sign-in keys are not protected with Key Vault: the Key Vault {0} uses access policies, not Azure RBAC -- switch it to Azure RBAC, then run {1}' -f $VaultName, $GrantCommand))
            return (& $done $false)
        }
        $scope = '{0}/keys/{1}' -f $VaultId.TrimEnd('/'), $script:SIWebKeyRingKeyName
        if ($CheckGrantOnly) {
            # the roles that let the web app wrap / unwrap with the key: Crypto Service Encryption User, Crypto User, Crypto
            # Officer, Key Vault Administrator -- on the key or above it
            $wrapRoles = @($script:SIWebKeyRingRoleId, '12338af0-0e69-4776-bea7-57ae8d297424', '14b46e9e-c2b7-41b4-b07b-48a6ebf60603', '00482a5a-887f-4fb3-b363-3b7fe8e74483')
            $l = & $Arm 'GET' ('{0}/providers/Microsoft.Authorization/roleAssignments?$filter=atScope()' -f $scope) '2022-04-01' $null
            if ([int]$l.Status -lt 200 -or [int]$l.Status -ge 300 -or -not $l.Json) {
                $report.Add(('the web app''s sign-in keys are not protected with Key Vault yet: the grants on its key could not be read (HTTP {0}) -- the updater tries again on its next run' -f [int]$l.Status))
                return (& $done $false)
            }
            $have = @(@($l.Json.value) | Where-Object { $_ -and $_.properties } | ForEach-Object { $_.properties } | Where-Object {
                    $rid = [string]$_.roleDefinitionId; @($wrapRoles | Where-Object { $rid.EndsWith('/' + $_, [StringComparison]::OrdinalIgnoreCase) }).Count })
            foreach ($p in $principals) {
                if (-not @($have | Where-Object { [string]$_.principalId -ieq $p }).Count) {
                    $action.Add(('the web app''s sign-in keys are not protected with Key Vault yet: the web app may not use its Key Vault key SI-Web-KeyRing -- run {0}' -f $GrantCommand))
                    return (& $done $false)
                }
            }
        }
        foreach ($p in $(if ($CheckGrantOnly) { @() } else { $principals })) {
            $path = '{0}/providers/Microsoft.Authorization/roleAssignments/{1}' -f $scope, (Get-SIWebKeyRingAssignmentName -Scope $scope -PrincipalId $p)
            $body = [ordered]@{ properties = [ordered]@{ roleDefinitionId = ('/subscriptions/{0}/providers/Microsoft.Authorization/roleDefinitions/{1}' -f $SubscriptionId, $script:SIWebKeyRingRoleId); principalId = $p; principalType = 'ServicePrincipal' } }
            $r = & $Arm 'PUT' $path '2022-04-01' $body
            $st = [int]$r.Status
            if ($st -eq 409 -or ($st -ge 200 -and $st -lt 300)) { if ($st -ne 409) { $lines.Add('web sign-in keys: the web app may use the key SI-Web-KeyRing (that key only)') } ; continue }
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
