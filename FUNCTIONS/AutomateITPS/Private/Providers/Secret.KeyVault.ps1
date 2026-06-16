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
    # No explicit Import-Module -- Get-AzContext / Get-AzKeyVaultSecret
    # auto-load Az.Accounts / Az.KeyVault on first call.

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
        # Throw on a missing secret (restored 2026-06-14). The caller requested
        # it by name, so absence is an error it must see. OPTIONAL secrets
        # (SI-StorageKey on OAuth-default tenants, Shodan/OpenAI/SMTP keys when
        # those features are off) are handled at the call site: wrap in try/catch
        # with -ErrorAction Stop and Write-Verbose the skip -- that keeps normal
        # runs quiet WITHOUT silently returning $null (which masks config errors
        # and breaks the -IgnoreMissing contract that callers rely on).
        throw ("Get-PlatformSecretKeyVault: secret '{0}' not found in vault '{1}'. Seed it, or treat it as optional via -IgnoreMissing / try-catch (-ErrorAction Stop)." -f $Name, $Context.Tenant.KeyVaultName)
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
    # No explicit Import-Module Az.Accounts -- Get-AzContext / Connect-AzAccount
    # / Get-AzAccessToken auto-load it on first call.

    if ($Context.Host.Kind -ne 'Dev') {
        $existing = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $existing) {
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
        }
    }
    (Get-AzAccessToken -ResourceUrl $ResourceUrl -ErrorAction Stop).Token
}
