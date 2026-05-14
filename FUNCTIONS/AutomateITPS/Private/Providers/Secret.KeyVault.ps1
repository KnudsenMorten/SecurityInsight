function Get-PlatformSecretKeyVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Name,
        [switch]$AsPlainText
    )

    if (-not $Context.Tenant.KeyVaultName) {
        throw "Get-PlatformSecretKeyVault: Tenant.KeyVaultName not set. Pass -KeyVaultName to New-PlatformContext."
    }
    if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) {
        throw "Get-PlatformSecretKeyVault: module Az.KeyVault not available. Install-Module Az.KeyVault -Scope CurrentUser"
    }
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.KeyVault -ErrorAction Stop

    $existing = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $existing) {
        if ($Context.Host.Kind -in @('AzureFunction','LogicApp','HybridWorker')) {
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
        } else {
            throw "Get-PlatformSecretKeyVault: no active AzContext and host '$($Context.Host.Kind)' is not a managed-identity host. Run Connect-AzAccount (e.g. with the bootstrap SP cert) before invoking this script."
        }
    }

    $secret = Get-AzKeyVaultSecret -VaultName $Context.Tenant.KeyVaultName -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue
    if (-not $secret) {
        # v2.2.285 -- soft-fail when the secret simply doesn't exist in KV.
        # Previously this threw, which propagated through Layer 3 (customer
        # SecurityInsight.custom.ps1) and halted the launcher on a fresh
        # install where optional secrets (SI-StorageKey, OpenAI-ApiKey,
        # SI-Shodan-ApiKey) hadn't been seeded yet. Returning $null + warning
        # lets the caller's `if (-not $global:X)` fall-through pattern work
        # naturally; unwrapped strict callers get $null which propagates as
        # a more actionable downstream error than a KV stack trace.
        Write-Warning ("Get-PlatformSecretKeyVault: secret '{0}' not found in vault '{1}' (returning `$null)." -f $Name, $Context.Tenant.KeyVaultName)
        return $null
    }

    if ($AsPlainText) {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue)
        try   { return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    return $secret.SecretValue
}

function Get-AutomateITAzureToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [string]$ResourceUrl = 'https://management.azure.com/'
    )
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        throw "Get-AutomateITAzureToken: module Az.Accounts not available. Install-Module Az.Accounts -Scope CurrentUser"
    }
    Import-Module Az.Accounts -ErrorAction Stop

    if ($Context.Host.Kind -ne 'Dev') {
        $existing = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $existing) {
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
        }
    }
    (Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop).Token
}
