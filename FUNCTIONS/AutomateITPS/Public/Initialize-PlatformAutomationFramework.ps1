function Initialize-PlatformAutomationFramework {
<#
.SYNOPSIS
    DEPRECATED in v2.3 -- thin alias for Connect-Platform. Kept for back-compat
    with launcher code (Initialize-LauncherConfig.ps1) and engine code paths
    that haven't yet been updated to call Connect-Platform directly.

.DESCRIPTION
    The v2.2 implementation did all of:
      - Resolve config from params / env vars / JSON file
      - Connect bootstrap SPN with cert
      - Initialize-PlatformIdentity to pull Modern-* from KV
      - Populate $global:HighPriv_* contract names
      - Reconnect as Modern SPN

    v2.3 splits this into two crisp tier functions (Connect-PlatformBootstrap
    + Connect-PlatformModern) and a single orchestrator (Connect-Platform).
    This wrapper delegates to Connect-Platform so existing callers keep
    working unchanged. New code should call Connect-Platform directly.

    Differences in behavior from v2.2:
      - v2.3 Modern SPN is SECRET-based, not cert (cert returns in v2.4+).
      - Config now ONLY comes from <repo>\bootstrap\platform-config.json.
        Env vars (PLATFORM_*) and inline params (-TenantId etc.) are no
        longer honored -- they made it impossible to reason about which
        identity a session was using. Migrate to platform-config.json or
        pass -ConfigPath to a non-default file location.
      - The v2.2 short-circuit (detect already-set v1 globals + skip) is
        GONE. Connect-Platform always re-acquires tokens; idempotent.
      - -SkipModernReconnect is ignored (v2.3 always connects Modern).
      - -IgnoreMissingSecrets is ignored (v2.3 needs Modern-AppId +
        Modern-Secret in KV; throws if absent -- there's no halfway state).

.PARAMETER ConfigPath
    Path to platform-config.json. Default: auto-resolve <repo>\bootstrap\platform-config.json.

.PARAMETER TenantId
    DEPRECATED -- ignored. Read from platform-config.json.

.PARAMETER SubscriptionId
    DEPRECATED -- ignored. Read from platform-config.json.

.PARAMETER KeyVaultName
    DEPRECATED -- ignored. Read from platform-config.json.

.PARAMETER BootstrapAppId
    DEPRECATED -- ignored. Read from platform-config.json.

.PARAMETER BootstrapThumbprint
    DEPRECATED -- ignored. Read from platform-config.json.

.PARAMETER SkipModernReconnect
    DEPRECATED -- ignored.

.PARAMETER IgnoreMissingSecrets
    DEPRECATED -- ignored.

.OUTPUTS
    PSCustomObject -- the PlatformContext (forwarded from Connect-Platform).

.EXAMPLE
    # Existing launcher code -- still works unchanged in v2.3:
    $global:Context = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets

.EXAMPLE
    # New code -- prefer this:
    $ctx = Connect-Platform

.NOTES
    Solution     : PlatformConfiguration / AutomateITPS
    Designed by  : Morten Knudsen, 2linkIT
    v2.3 status  : back-compat alias. Will be removed in a future major release.
    Replacement  : Connect-Platform
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [string]$ConfigPath,
        [Parameter()] [string]$TenantId,             # ignored
        [Parameter()] [string]$SubscriptionId,       # ignored
        [Parameter()] [string]$KeyVaultName,         # ignored
        [Parameter()] [string]$BootstrapAppId,       # ignored
        [Parameter()] [string]$BootstrapThumbprint,  # ignored
        [Parameter()] [switch]$SkipModernReconnect,  # ignored
        [Parameter()] [switch]$IgnoreMissingSecrets  # ignored
    )

    if ($TenantId -or $SubscriptionId -or $KeyVaultName -or $BootstrapAppId -or $BootstrapThumbprint) {
        Write-Verbose "Initialize-PlatformAutomationFramework: deprecated inline param(s) supplied; ignored. v2.3 reads platform-config.json only."
    }
    if ($SkipModernReconnect -or $IgnoreMissingSecrets) {
        Write-Verbose "Initialize-PlatformAutomationFramework: -SkipModernReconnect / -IgnoreMissingSecrets are no-ops in v2.3."
    }

    # Back-compat: when running on a v2.2 customer host that synced the v2.3
    # code but hasn't yet provisioned platform-config.json (via Initialize-PlatformVm
    # or Convert-V1ToPlatform), soft-fail and return $null. The caller is
    # presumed to be already auth'd via the v2.2 chain (Connect_Azure.ps1 +
    # platform-defaults.ps1 dot-source). Hard-throw would break engines like
    # Invoke-PublicIpScanner / AssetTagging / PrivilegeTierClassifier that call
    # this defensively at engine startup. Genuine v2.3 callers MUST have
    # platform-config.json -- they get the throw via Connect-Platform.
    $resolvedConfig = $ConfigPath
    if (-not $resolvedConfig) {
        $r = $PSScriptRoot
        while ($r -and -not (Test-Path (Join-Path $r 'bootstrap'))) {
            $parent = Split-Path -Parent $r
            if ($parent -eq $r) { break }
            $r = $parent
        }
        if ($r) { $resolvedConfig = Join-Path $r 'bootstrap\platform-config.json' }
    }
    if ($resolvedConfig -and -not (Test-Path -LiteralPath $resolvedConfig)) {
        Write-Verbose "Initialize-PlatformAutomationFramework: platform-config.json absent at $resolvedConfig -- assuming v2.2 chain already auth'd the caller. Returning null (back-compat)."
        return $null
    }

    return Connect-Platform -ConfigPath $ConfigPath -PassThru
}
