#Requires -Version 5.1
<#
    Get-SIKvSecret -- runtime KV secret fetch for SecurityInsight engines.

    Designed to be called from config/SecurityInsight.custom.ps1 at config-
    load time so high-value secrets (Storage account keys, Shodan API key,
    Azure OpenAI key) live ONLY in Key Vault and are pulled fresh into
    in-memory globals on every launcher run -- never persisted to disk.

    Auth strategy (in order):
      1. Existing Az context (if launcher already did Connect-AzAccount)
      2. System-assigned Managed Identity (typical internal VM scenario)
      3. User-assigned MI via $global:SI_KvMiClientId (if set)
      4. Throws -- caller must establish Az first

    Returns the secret as a plain string. Caller assigns it to a $global:
    variable that the engines read.

    Example use in config/SecurityInsight.custom.ps1:
        . "$PSScriptRoot\..\auth\Get-SIKvSecret.ps1"
        $kv = 'kv-2linkit-automation-p'
        $global:SI_Shodan_ApiKey = Get-SIKvSecret -VaultName $kv -SecretName 'SI-Shodan-ApiKey'
        $global:OpenAI_apiKey    = Get-SIKvSecret -VaultName $kv -SecretName 'OpenAI-ApiKey'

    NOTE: v2.2.314+ no longer supports SI_StorageKey. Storage auth is OAuth-only
    via the SPN/MSI's Storage Blob/Table/Queue Data Contributor RBAC -- there is
    no shared key to KV-pull anymore. Pre-v2.2.314 examples that pulled
    'SI-StorageKey' should be deleted from your custom.ps1.

    Notes
    -----
    * PS 5.1 safe (no -AsPlainText switch which is PS 7+).
    * Az.KeyVault module is required. Caller is responsible for `Install-Module Az.KeyVault`.
    * No fallback to plaintext globals -- this helper is opt-in. If the
      customer prefers plaintext, just don't call it.
    * Returns $null (NOT throws) when the secret doesn't exist OR the
      caller lacks Get-Secret RBAC -- engines will throw their own missing-
      value error which is more actionable than a KV stack trace.
#>

function Get-SIKvSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$SecretName
    )

    # ---- 1. Ensure an Az context exists ----
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        # Try managed identity first (system-assigned, then user-assigned via global)
        try {
            if ($global:SI_KvMiClientId) {
                Connect-AzAccount -Identity -AccountId $global:SI_KvMiClientId -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
            } else {
                Connect-AzAccount -Identity -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
            }
        } catch {
            throw "Get-SIKvSecret: no Az context and Managed Identity connect failed. Either run from an Azure VM with MI assigned, or call Connect-AzAccount before loading custom.ps1. Inner: $($_.Exception.Message)"
        }
    }

    # ---- 2. Pull the secret ----
    try {
        $sec = Get-AzKeyVaultSecret -VaultName $VaultName -Name $SecretName -ErrorAction Stop
    } catch {
        Write-Warning ("Get-SIKvSecret: failed to read '{0}' from KV '{1}': {2}" -f $SecretName, $VaultName, $_.Exception.Message)
        return $null
    }
    if (-not $sec) { return $null }

    # PS 5.1: convert SecureString -> plain text via NetworkCredential
    return [System.Net.NetworkCredential]::new('', $sec.SecretValue).Password
}
