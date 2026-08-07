#Requires -Version 5.1
<#
    Connect-SIAzCli -- give the `az` CLI its OWN sign-in, for unattended deploys.

    WHY THIS EXISTS (audit #33)
    ---------------------------
    `analyzer-web/deploy/Deploy-SIAnalyzer.ps1` is entirely `az`-based, and it had no
    authentication step at all: it assumed somebody had already run `az login`. That is
    fine when a human runs it and fatal the moment the daily sync runs it unattended --
    it would die on the first `az` call on every customer.

    The trap to understand before changing any of this: **an Az PowerShell context is NOT
    an `az` CLI context.** `Connect-AzAccount` (and a VM's Managed Identity as consumed by
    Az PowerShell) does nothing for `az`. They keep separate token caches, so a session
    that can happily run Get-AzKeyVaultSecret can still fail every `az` command with
    "Please run 'az login'". Both halves must be established independently. Same lesson as
    CEH's az-based deploy, which needs its own credential rather than inheriting one.

    WHAT IT DOES
    ------------
    Establishes an `az` CLI context for the SI service principal, from what the customer's
    own config already declares -- no new configuration surface:

      1. Already signed in (`az account show` succeeds, right tenant) -> no-op.
      2. $global:SI_SPN_UseManagedIdentity          -> `az login --identity`
      3. SPN secret from the LOCAL AutomateIT Key Vault ($global:SpnKeyVaultName,
         secret $global:SI_SPN_KvSecretName, default 'SI-SPN-Secret') -> service-principal login
      4. $global:SI_SPN_Secret already in memory    -> service-principal login
      5. otherwise -> throw, naming exactly which global is missing

    Reading the secret from Key Vault uses Get-SIKvSecret, which needs an Az PowerShell
    context (MI on the VM). So on a customer VM the chain is: MI -> Az PowerShell -> read
    the SPN secret from that customer's Key Vault -> `az login` as the SPN. The secret is
    never written to disk and never echoed.

    IDEMPOTENT + UNATTENDED: safe to call before every `az` call and safe to run daily.

    Usage:
        . "$PSScriptRoot\..\auth\Connect-SIAzCli.ps1"
        Connect-SIAzCli -SubscriptionId $subId
#>

function Connect-SIAzCli {
    [CmdletBinding()]
    param(
        # Subscription to select once signed in. Optional -- omit to keep the SPN's default.
        [Parameter()][string]$SubscriptionId,

        # Tenant override. Defaults to $global:SI_SPN_TenantId.
        [Parameter()][string]$TenantId,

        # Re-authenticate even if a context already exists.
        [Parameter()][switch]$Force
    )

    if (-not (Get-Command az -CommandType Application -ErrorAction SilentlyContinue)) {
        throw "Connect-SIAzCli: the 'az' CLI is not on PATH. The SIA deploy is az-based; install the Azure CLI on this host."
    }

    if (-not $TenantId) { $TenantId = [string]$global:SI_SPN_TenantId }

    # ---- 1. Already signed in? ------------------------------------------------
    # `az account show` writes to stderr and returns non-zero when signed out, so the
    # exit code is the signal -- never the captured text (a failure string is truthy).
    if (-not $Force) {
        $null = & az account show 2>&1
        if ($LASTEXITCODE -eq 0) {
            if ($SubscriptionId) {
                $null = & az account set --subscription $SubscriptionId 2>&1
                if ($LASTEXITCODE -ne 0) { throw "Connect-SIAzCli: signed in, but could not select subscription '$SubscriptionId'." }
            }
            Write-Verbose 'Connect-SIAzCli: existing az context reused.'
            return
        }
    }

    $appId = [string]$global:SI_SPN_AppId

    # ---- 2. Managed identity --------------------------------------------------
    if ($global:SI_SPN_UseManagedIdentity) {
        $miArgs = @('login', '--identity')
        if ($global:SI_SPN_ManagedIdentityClientId) { $miArgs += @('--username', [string]$global:SI_SPN_ManagedIdentityClientId) }
        $null = & az @miArgs 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Connect-SIAzCli: 'az login --identity' failed on this host." }
    }
    else {
        if (-not $appId)    { throw "Connect-SIAzCli: `$global:SI_SPN_AppId is not set -- cannot sign the az CLI in. Set it in config/SecurityInsight.custom.ps1." }
        if (-not $TenantId) { throw "Connect-SIAzCli: `$global:SI_SPN_TenantId is not set -- cannot sign the az CLI in. Set it in config/SecurityInsight.custom.ps1." }

        # ---- 3. SPN secret from the local AutomateIT Key Vault ----------------
        $secret = $null
        $vault  = [string]$global:SpnKeyVaultName
        if ($vault) {
            $secretName = if ($global:SI_SPN_KvSecretName) { [string]$global:SI_SPN_KvSecretName } else { 'SI-SPN-Secret' }
            $helper = Join-Path $PSScriptRoot 'Get-SIKvSecret.ps1'
            if (Test-Path -LiteralPath $helper) {
                if (-not (Get-Command Get-SIKvSecret -ErrorAction SilentlyContinue)) { . $helper }
                try {
                    $secret = Get-SIKvSecret -VaultName $vault -SecretName $secretName
                } catch {
                    Write-Warning ("Connect-SIAzCli: Key Vault '{0}' lookup of '{1}' failed: {2}" -f $vault, $secretName, $_.Exception.Message)
                }
            }
        }

        # ---- 4. Fall back to an in-memory secret ------------------------------
        if (-not $secret -and $global:SI_SPN_Secret) { $secret = [string]$global:SI_SPN_Secret }

        if (-not $secret) {
            throw ("Connect-SIAzCli: no SPN credential. Set `$global:SpnKeyVaultName (secret '{0}') so it is read from the customer's Key Vault, or set `$global:SI_SPN_Secret, or set `$global:SI_SPN_UseManagedIdentity." -f `
                   $(if ($global:SI_SPN_KvSecretName) { [string]$global:SI_SPN_KvSecretName } else { 'SI-SPN-Secret' }))
        }

        try {
            # Output is discarded rather than shown: az echoes subscription details, and
            # on failure the message can contain the credential.
            $null = & az login --service-principal --username $appId --password $secret --tenant $TenantId --allow-no-subscriptions 2>&1
            $ok = ($LASTEXITCODE -eq 0)
        } finally {
            # Drop the plaintext as soon as the call returns.
            $secret = $null
            [System.GC]::Collect()
        }
        if (-not $ok) {
            throw "Connect-SIAzCli: 'az login --service-principal' failed for app '$appId' in tenant '$TenantId'. Check the SPN secret in Key Vault '$vault' has not expired."
        }
    }

    if ($SubscriptionId) {
        $null = & az account set --subscription $SubscriptionId 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Connect-SIAzCli: signed in, but could not select subscription '$SubscriptionId'." }
    }
    Write-Verbose 'Connect-SIAzCli: az CLI signed in.'
}
