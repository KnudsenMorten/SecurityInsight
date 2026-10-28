#Requires -Version 5.1
<#
    Get-SIKvSecret -- runtime KV secret fetch for SecurityInsight engines.

    Designed to be called from config/SecurityInsight.custom.ps1 at config-
    load time so high-value secrets (Storage account keys, Shodan API key,
    Azure OpenAI key) live ONLY in Key Vault and are pulled fresh into
    in-memory globals on every launcher run -- never persisted to disk.

    Auth strategy (in order) -- plain REST, no PowerShell module:
      1. The run's own sign-in (what the launcher recorded with Connect-SIAzAccount, else the configured
         SPN certificate / secret)
      2. Otherwise a Managed Identity: user-assigned via $global:SI_ManagedIdentityClientId /
         SI_KvMiClientId / SI_UAMI_ClientId when set, else the system-assigned one (typical internal VM)

    Returns the secret as a plain string. Caller assigns it to a $global:
    variable that the engines read.

    Example use in config/SecurityInsight.custom.ps1:
        . "$PSScriptRoot\..\auth\Get-SIKvSecret.ps1"
        $kv = '<your-key-vault-name>'
        $global:SI_Shodan_ApiKey = Get-SIKvSecret -VaultName $kv -SecretName 'SI-Shodan-ApiKey'
        $global:OpenAI_apiKey    = Get-SIKvSecret -VaultName $kv -SecretName 'OpenAI-ApiKey'

    Storage needs no secret: it is reached with the signed-in identity's Storage
    Blob/Table/Queue Data Contributor roles.

    Notes
    -----
    * PS 5.1 safe (no -AsPlainText switch which is PS 7+).
    * No PowerShell module needed: the secret is read over REST (engine/_shared/SI-AzRest.ps1).
    * No fallback to plaintext globals -- this helper is opt-in. If the
      customer prefers plaintext, just don't call it.
    * Returns $null (NOT throws) when the secret doesn't exist OR the
      caller lacks Get-Secret RBAC -- engines will throw their own missing-
      value error which is more actionable than a KV stack trace.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../engine/_shared/SI-AzRest.ps1') }

function Get-SIKvSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$VaultName,
        [Parameter(Mandatory)][string]$SecretName
    )

    # ---- 1. Make sure a sign-in is known (recorded; the token is minted over REST on the read) ----
    $ctx = Get-SIAzContext -ErrorAction SilentlyContinue
    if (-not $ctx) {
        # Try managed identity first (system-assigned, then user-assigned via global)
        try {
            # #222: the install's one managed-identity client id; SI_KvMiClientId is the older name.
            $kvMi = if ($global:SI_ManagedIdentityClientId) { [string]$global:SI_ManagedIdentityClientId }
                    elseif ($global:SI_KvMiClientId) { [string]$global:SI_KvMiClientId }
                    else { [string]$global:SI_UAMI_ClientId }
            if ($kvMi) {
                Connect-SIAzAccount -Identity -AccountId $kvMi -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
            } else {
                Connect-SIAzAccount -Identity -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
            }
        } catch {
            throw "Get-SIKvSecret: no sign-in is configured and the managed identity could not be used. Either run on an Azure VM with a managed identity assigned, or configure the SecurityInsight sign-in before loading custom.ps1. Inner: $($_.Exception.Message)"
        }
    }

    # ---- 2. Pull the secret ----
    try {
        $sec = Get-SIAzKeyVaultSecret -VaultName $VaultName -Name $SecretName -ErrorAction Stop
    } catch {
        Write-Warning ("Get-SIKvSecret: failed to read '{0}' from KV '{1}': {2}" -f $SecretName, $VaultName, $_.Exception.Message)
        return $null
    }
    if (-not $sec) { return $null }

    # PS 5.1: convert SecureString -> plain text via NetworkCredential
    return [System.Net.NetworkCredential]::new('', $sec.SecretValue).Password
}
