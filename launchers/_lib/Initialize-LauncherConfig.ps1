#Requires -Version 5.1
<#
.SYNOPSIS
    Layered config loader for AutomateIT launchers.

.DESCRIPTION
    Dot-sources the customer-tunable config layers in the right order so
    the launcher template makes one call:

        . (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')
        Initialize-LauncherConfig `
            -Solution 'SecurityInsight' `
            -Engine   'SecurityInsight_RiskAnalysis' `
            -LauncherDir $PSScriptRoot `
            -RepoRoot $InstallPath `
            -Mode 'community'

    Layer order (each layer's $global:* override the previous):

      0. <RepoRoot>/SOLUTIONS/<Solution>/LAUNCHERS/_lib/<Solution>.shared-defaults.ps1  (us, ships, solution-wide)
      1. <LauncherDir>/LauncherConfig.defaults.ps1                                  (us, ships, per-engine)
      2. <RepoRoot>/SOLUTIONS/PlatformConfiguration/CUSTOMDATA/platform-defaults.ps1 (customer, internal only)
      3. <RepoRoot>/SOLUTIONS/<Solution>/CUSTOMDATA/<Solution>.custom.ps1            (customer, solution-wide)
      4. <LauncherDir>/LauncherConfig.custom.ps1  OR  LauncherConfig.ps1 (legacy)    (customer, per-engine)
      5. CLI args                                                                    (applied later in the launcher)

    Layer 0 (new): ships solution-wide shared defaults that apply to every
    engine in the solution (e.g. canonical DCE / Workspace / DCR names).
    Optional -- launcher still works if the file is absent.

    Layer 1 must always exist (shipped). Layers 2-4 are optional unless
    -RequireCustom is passed -- which community-vm launchers do, because the
    customer's SPN/MI auth lives in layer 4 there. community-azure /
    internal-vm / internal-azure all source auth from elsewhere (App Settings
    + KV / Initialize-PlatformAutomationFramework), so layer 4 is optional.

.NOTES
    Function     : Initialize-LauncherConfig
    Solution     : All
    Developed by : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
#>

function Initialize-LauncherConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Solution,
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$LauncherDir,
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][ValidateSet('community','internal')][string]$Mode,
        [string]$CustomConfigPath,
        [switch]$RequireCustom
    )

    function _CfgStep ([string]$m) { Write-Host "[STEP]  $m" -ForegroundColor Cyan }
    function _CfgOk   ([string]$m) { Write-Host "[OK]    $m" -ForegroundColor Green }
    function _CfgInfo ([string]$m) { Write-Host "[INFO]  $m" -ForegroundColor Gray }

    # ---- Layer 0: <Solution>.shared-defaults.ps1 (solution-wide shared baseline, ours) ----
    # Optional. The file sits in _lib/, which is always a SIBLING of the launcher
    # folder in both layouts:
    #   monorepo:  SOLUTIONS/<Solution>/LAUNCHERS/_lib/<Solution>.shared-defaults.ps1
    #   community: launchers/_lib/<Solution>.shared-defaults.ps1
    # Resolve it relative to $LauncherDir so both layouts work.
    $sharedPath = Join-Path (Split-Path -Parent $LauncherDir) ("_lib\{0}.shared-defaults.ps1" -f $Solution)
    _CfgStep "Layer 0/4: $Solution.shared-defaults.ps1 (solution-wide shared baseline)"
    if (Test-Path -LiteralPath $sharedPath) {
        . $sharedPath
        _CfgOk "loaded ($sharedPath)"
    } else {
        _CfgInfo "absent ($sharedPath) -- skipping"
    }

    # ---- Layer 1: defaults.ps1 (engine baseline, ours, must exist) -----------
    $defaultsPath = Join-Path $LauncherDir 'LauncherConfig.defaults.ps1'
    _CfgStep "Layer 1/4: LauncherConfig.defaults.ps1 (engine baseline)"
    if (-not (Test-Path -LiteralPath $defaultsPath)) {
        throw "LauncherConfig.defaults.ps1 missing at $defaultsPath. This file ships with each release; reinstall the $Solution package to restore it."
    }
    . $defaultsPath
    _CfgOk "loaded"

    # ---- Layer 2: platform-defaults.ps1 (internal only) ----------------------
    if ($Mode -eq 'internal') {
        $platformPath = Join-Path $RepoRoot 'SOLUTIONS\PlatformConfiguration\CUSTOMDATA\platform-defaults.ps1'
        _CfgStep "Layer 2/4: platform-defaults.ps1 (shared platform vars)"
        if (Test-Path -LiteralPath $platformPath) {
            . $platformPath
            _CfgOk "loaded"
        } else {
            _CfgInfo "absent ($platformPath) -- skipping"
        }
    }

    # ---- Layer 3: <Solution>.custom.ps1 (solution-wide overrides) ------------
    $solutionCustomPath = Join-Path $RepoRoot ("SOLUTIONS\{0}\CUSTOMDATA\{0}.custom.ps1" -f $Solution)
    _CfgStep "Layer 3/4: $Solution.custom.ps1 (solution-wide overrides)"
    if (Test-Path -LiteralPath $solutionCustomPath) {
        . $solutionCustomPath
        _CfgOk "loaded"
    } else {
        _CfgInfo "absent ($solutionCustomPath) -- skipping"
    }

    # ---- Layer 4: per-engine custom (LauncherConfig.custom.ps1 preferred,
    #              LauncherConfig.ps1 legacy fallback) -----------------------
    $explicit = -not [string]::IsNullOrWhiteSpace($CustomConfigPath)
    if ($explicit) {
        $customPath = $CustomConfigPath
    } else {
        $customPath = Join-Path $LauncherDir 'LauncherConfig.custom.ps1'
        if (-not (Test-Path -LiteralPath $customPath)) {
            $legacy = Join-Path $LauncherDir 'LauncherConfig.ps1'
            if (Test-Path -LiteralPath $legacy) {
                $customPath = $legacy
                _CfgInfo "legacy filename 'LauncherConfig.ps1' detected -- consider renaming to 'LauncherConfig.custom.ps1' to match the layered model"
            }
        }
    }

    _CfgStep "Layer 4/4: per-engine customer overrides"
    if (Test-Path -LiteralPath $customPath) {
        . $customPath
        _CfgOk "loaded ($customPath)"
    } elseif ($RequireCustom) {
        $expected = Join-Path $LauncherDir 'LauncherConfig.custom.ps1'
        throw @"
Per-engine customer config not found. Looked for:
  $expected
  $(Join-Path $LauncherDir 'LauncherConfig.ps1')   (legacy)

Copy $(Join-Path $LauncherDir 'LauncherConfig.sample.ps1') to LauncherConfig.custom.ps1 in the same folder and fill in your auth values.
"@
    } else {
        _CfgInfo "absent ($customPath) -- skipping (auth comes from elsewhere on this flavour)"
    }

    # ---- Derived defaults: run AFTER all 4 layers so late-bound vars resolve ----
    # Platform-defaults (Layer 2, internal only) sets $global:MainLogAnalyticsWorkspaceSubId
    # but doesn't set $global:SubscriptionId. Derive it here so engines that read
    # $global:SubscriptionId don't have to duplicate the fallback logic.
    if ([string]::IsNullOrWhiteSpace([string]$global:SubscriptionId) -and
        -not [string]::IsNullOrWhiteSpace([string]$global:MainLogAnalyticsWorkspaceSubId)) {
        $global:SubscriptionId = [string]$global:MainLogAnalyticsWorkspaceSubId
        _CfgInfo "derived `$global:SubscriptionId from `$global:MainLogAnalyticsWorkspaceSubId"
    }
}
