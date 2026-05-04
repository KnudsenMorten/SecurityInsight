#Requires -Version 5.1
<#
.SYNOPSIS
    Internal VM (Automation Framework) launcher for SecurityInsight\SecurityInsight_RiskAnalysis.
.DESCRIPTION
    Runs the SecurityInsight_RiskAnalysis engine on a platform-managed Windows VM using the
    existing 2LINKIT Automation Framework (FUNCTIONS/ modules, internal KV,
    Connect_Azure helper). Sets $global:AutomationFramework = $true.

    Assumes Initialize-PlatformAutomationFramework has populated the v1-contract
    globals (HighPriv_*, etc.) before this launcher runs, OR the engine itself
    will bootstrap on first connect.

.NOTES
    Solution       : SecurityInsight
    File           : launcher.internal-vm.template.ps1
    Developed by   : Morten Knudsen, Microsoft MVP
    Blog           : https://mortenknudsen.net   (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.
#>
[CmdletBinding()]
param(
    # Generic launcher knobs
    [string]$InstallPath,
    [switch]$WhatIfMode,
    [switch]$SuppressErrors,
    [switch]$SuppressWarnings,

    # Engine-specific switches (override Defaults block + engine defaults)
    [string]$ReportTemplate,
    [switch]$Summary,
    [switch]$Detailed,
    [switch]$BuildSummaryByAI,

    # Adaptive bucketing
    [switch]$AutoBucketCount,
    [switch]$AutoBucketCache,
    [ValidateRange(1,2048)][int]$AutoBucketMax,
    [Alias('ResetCache')][switch]$ResetCacheSwitch,

    # Other engine knobs
    [switch]$ShowConfig,
    [switch]$DebugQueryHash
)
$ErrorActionPreference = 'Stop'

# ============================================================================
#  DEFAULTS (single source of truth) -- edit here to change baseline behaviour
#  for ALL invocations of this launcher. CLI switches override these per run.
#
#  Internal-VM defaults match v1 RunRiskAnalysis_Automation_Framework.ps1:
#    AutomationFramework=$true, BuildSummaryByAI=$true.
# ============================================================================

# Run-mode default. Allowed: 'Auto', 'Summary', 'Detailed'.
# 'Auto' falls back to AutomationFramework rule (AF=>Summary, else neither).
$RunMode_Default = 'Auto'

# Optional in-script overrides ($null = no override; $true = force).
# Set Detailed_Override=$true if this VM should always produce the detailed report.
$Summary_Override   = $null
$Detailed_Override  = $null
$ResetCache_Override = $null

# Hardcoded defaults. Single place to change baseline operational tuning.
$AutomationFramework_Default = $true
$OverwriteXlsx_Default       = $true
$BuildSummaryByAI_Default    = $true

# ReportTemplate defaults (per mode). Set $ReportTemplate_Default to force a
# specific template regardless of Summary/Detailed; leave $null to let the
# Summary/Detailed mode below pick.
$ReportTemplate_Default          = $null
$ReportTemplate_Default_Summary  = 'RiskAnalysis_Summary'
$ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed'

# Adaptive bucketing baseline (engine reads these globals).
$AutoBucketCount_Default = $true
$AutoBucketCache_Default = $true
$AutoBucketMax_Default   = 1024

# Cache + diagnostics
$ResetCache_Default      = $false
$DebugQueryHash_Default  = $false
$ShowConfig_Default      = $false

# ============================================================================

# Get-PublishedVersion: shared helper in _lib/. Dot-sourced before the banner
# so the version shows on the very first line. Falls back from VERSION.txt
# (community installs) to `git describe` (monorepo) to '(dev)' (neither).
. (Join-Path $PSScriptRoot '..\_lib\Get-PublishedVersion.ps1')
. (Join-Path $PSScriptRoot '..\_lib\Start-LauncherTranscript.ps1')

function Write-Banner {
    param(
        [Parameter(Mandatory)][string]$Solution,
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$Flavour,
        [string]$Description = '',
        [string]$Version = '(dev)'
    )
    $line = '=' * 88
    # Strip the redundant 'SecurityInsight_' prefix on the engine label so the
    # banner reads "SecurityInsight -- AssetProfiling_Identity" instead of the
    # noisy "SecurityInsight -- SecurityInsight_AssetProfiling_Identity". 2026-05-02.
    $engineLabel = $Engine -replace '^SecurityInsight[_-]', ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  {0} -- {1}    [{2}]   {3}" -f $Solution, $engineLabel, $Flavour, $Version) -ForegroundColor Cyan
    if ($Description) {
        foreach ($chunk in ($Description -split '(?<=.{1,86})\s+')) {
            Write-Host ("  {0}" -f $chunk) -ForegroundColor White
        }
    }
    Write-Host '' -ForegroundColor Cyan
    Write-Host '  Developed by Morten Knudsen -- Microsoft MVP' -ForegroundColor Cyan
    Write-Host '  Blog:    https://mortenknudsen.net   (aka.ms/morten)' -ForegroundColor Cyan
    Write-Host '  GitHub:  https://github.com/KnudsenMorten' -ForegroundColor Cyan
    Write-Host '  Support: GitHub Issues on the public repo, or mok@mortenknudsen.net (internal)' -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}
function Write-Step  { param([string]$m) Write-Host "[STEP]  $m" -ForegroundColor Cyan }
function Write-Info  { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor White }
function Write-Ok    { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err2  { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }



function Resolve-RepoRoot {
    param([string]$Start = $PSScriptRoot)
    $cur = $Start
    $devMatch = $null
    while ($cur) {
        if (Test-Path (Join-Path $cur 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1')) { return $cur }
        # v2.2 dev tree: engine/ + launcher/ siblings (preview pulled to a customer site).
        if (-not $devMatch) {
            $dirs = Get-ChildItem -LiteralPath $cur -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            if (($dirs -ccontains 'engine') -and ($dirs -ccontains 'launcher')) { $devMatch = $cur }
        }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    if ($devMatch) { return $devMatch }
    throw ("Launcher: cannot locate AutomateIT repo root walking up from '{0}'. Expected FUNCTIONS\AutomateITPS\AutomateITPS.psd1 (monorepo) or engine/+launcher/ siblings (preview dev tree)." -f $Start)
}
# Resolve repo root + version BEFORE the banner so the banner can show the version.
try {
    if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }
} catch {
    $resolveError = $_
}
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath -Solution 'SecurityInsight'

Write-Banner -Solution 'SecurityInsight' -Engine 'RiskAnalysis' -Flavour 'internal-vm' -Version $versionStamp
$global:SI_TranscriptPath = Start-SILauncherTranscript -Engine 'risk-analysis' -Flavour 'internal-vm' -RepoRoot $InstallPath

if ($resolveError) {
    Write-Err2 $resolveError.Exception.Message
    throw $resolveError
}
Write-Step "Resolving repo root"
Write-Ok "repo root: $InstallPath"

try {
    # Layered config (internal-vm: layer 2 = platform-defaults shared across
    # solutions, layer 3 = SI solution-wide custom; auth comes from
    # Initialize-PlatformAutomationFramework which runs separately).
    . (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')
    Initialize-LauncherConfig `
        -Solution    'SecurityInsight' `
        -Engine      'RiskAnalysis' `
        -LauncherDir $PSScriptRoot `
        -RepoRoot    $InstallPath `
        -Mode        'internal'
} catch {
    Write-Err2 "Failed to load layered config: $($_.Exception.Message)"
    throw
}

$overrideFile = Join-Path $PSScriptRoot 'launcher.override.ps1'
if (Test-Path -LiteralPath $overrideFile) { Write-Info "dot-sourcing launcher.override.ps1"; . $overrideFile }

Write-Step "Setting engine globals (AutomationFramework mode)"
$global:PathScripts = $InstallPath
# launcher lives at v2.2/launcher/risk-analysis/. SettingsPath
# (consolidated YAML + risk-index + riskscore_weighted) lives at
# v2.2/risk-analysis-detection/. 2-up from launcher = v2.2 root.
$v22Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$siRoot  = Split-Path -Parent $v22Root
$settingsResolved = $null
foreach ($candidate in @(
    (Join-Path $v22Root 'risk-analysis-detection'),
    (Join-Path $siRoot  'DATA'),
    (Join-Path $siRoot  'data')
)) {
    if (Test-Path -LiteralPath $candidate) { $settingsResolved = $candidate; break }
}
$global:SettingsPath     = if ($settingsResolved) { $settingsResolved } else { $PSScriptRoot }
$global:WhatIfMode       = [bool]$WhatIfMode
$global:SuppressErrors   = [bool]$SuppressErrors
$global:SuppressWarnings = [bool]$SuppressWarnings

# ----- Resolve runtime values: CLI bound > in-script Override > Default -----
# Inline (v1 pattern): $PSBoundParameters at script scope is the launcher's
# own bound params. We snapshot it here so helpers don't have to receive it
# (inside a function, $PSBoundParameters refers to the function's bound
# params, not the caller's -- which was the bug fixed in v2.1.27 for
# community-vm; same fix applied here).
$cliBound = @{}
foreach ($k in $PSBoundParameters.Keys) { $cliBound[$k] = $PSBoundParameters[$k] }

function Resolve-RunMode {
    param([hashtable]$Bound, [string]$DefaultMode, $SummaryOverride, $DetailedOverride, [bool]$AFFlag)
    $cliS = $Bound.ContainsKey('Summary')  -and [bool]$Bound['Summary']
    $cliD = $Bound.ContainsKey('Detailed') -and [bool]$Bound['Detailed']
    if ($cliS -and $cliD) { throw '-Summary and -Detailed are mutually exclusive.' }
    if ($cliS) { return @{ Summary=$true;  Detailed=$false } }
    if ($cliD) { return @{ Summary=$false; Detailed=$true  } }
    if ($SummaryOverride -eq $true -and $DetailedOverride -eq $true) {
        throw 'Summary_Override and Detailed_Override cannot both be true.'
    }
    if ($DetailedOverride -eq $true) { return @{ Summary=$false; Detailed=$true  } }
    if ($SummaryOverride  -eq $true) { return @{ Summary=$true;  Detailed=$false } }
    switch (([string]$DefaultMode).Trim().ToLowerInvariant()) {
        'detailed' { return @{ Summary=$false; Detailed=$true  } }
        'summary'  { return @{ Summary=$true;  Detailed=$false } }
    }
    if ($AFFlag) { return @{ Summary=$true; Detailed=$false } }
    return @{ Summary=$false; Detailed=$false }
}

$global:AutomationFramework = $AutomationFramework_Default
if (-not (Test-Path variable:global:OverwriteXlsx)) { $global:OverwriteXlsx = [bool]$OverwriteXlsx_Default }

# Honor customer's $global:RiskAnalysis_*_Override (set in Layer 3 / Layer 5).
# Without this step, the launcher's hardcoded local $Summary_Override / $Detailed_Override
# win regardless of what the customer put in SecurityInsight.custom.ps1 or
# LauncherConfig.custom.ps1 -- which defeats the whole layered-config model.
# If EITHER global override is set, reset both locals from the customer values
# (null where the customer didn't set anything) so we never end up with two
# hardcoded $true values that trip Resolve-RunMode's 'both true' throw.
if ($null -ne $global:RiskAnalysis_Summary_Override -or $null -ne $global:RiskAnalysis_Detailed_Override) {
    $Summary_Override  = if ($null -ne $global:RiskAnalysis_Summary_Override)  { [bool]$global:RiskAnalysis_Summary_Override }  else { $null }
    $Detailed_Override = if ($null -ne $global:RiskAnalysis_Detailed_Override) { [bool]$global:RiskAnalysis_Detailed_Override } else { $null }
}

$mode = Resolve-RunMode `
    -Bound $cliBound `
    -DefaultMode $RunMode_Default `
    -SummaryOverride $Summary_Override `
    -DetailedOverride $Detailed_Override `
    -AFFlag $global:AutomationFramework
$global:Summary  = [bool]$mode.Summary
$global:Detailed = [bool]$mode.Detailed

# Each switch (inline v1 pattern): CLI bound > Override > Default
if (-not (Test-Path variable:global:BuildSummaryByAI)) { $global:BuildSummaryByAI = $BuildSummaryByAI_Default }
if ($cliBound.ContainsKey('BuildSummaryByAI')) { $global:BuildSummaryByAI = [bool]$cliBound['BuildSummaryByAI'] }

if (-not (Test-Path variable:global:AutoBucketCount)) { $global:AutoBucketCount = $AutoBucketCount_Default }
if ($cliBound.ContainsKey('AutoBucketCount')) { $global:AutoBucketCount = [bool]$cliBound['AutoBucketCount'] }

if (-not (Test-Path variable:global:AutoBucketCache)) { $global:AutoBucketCache = $AutoBucketCache_Default }
if ($cliBound.ContainsKey('AutoBucketCache')) { $global:AutoBucketCache = [bool]$cliBound['AutoBucketCache'] }

if (-not (Test-Path variable:global:ShowConfig)) { if (-not (Test-Path variable:global:ShowConfig)) { $global:ShowConfig = $ShowConfig_Default } }
if ($cliBound.ContainsKey('ShowConfig')) { $global:ShowConfig = [bool]$cliBound['ShowConfig'] }

if (-not (Test-Path variable:global:DebugQueryHash)) { if (-not (Test-Path variable:global:DebugQueryHash)) { $global:DebugQueryHash = $DebugQueryHash_Default } }
if ($cliBound.ContainsKey('DebugQueryHash')) { $global:DebugQueryHash = [bool]$cliBound['DebugQueryHash'] }

# ResetCache: CLI bound > Override > Default
$global:ResetCache = $ResetCache_Default
if ($cliBound.ContainsKey('ResetCacheSwitch')) {
    $global:ResetCache = [bool]$cliBound['ResetCacheSwitch']
} elseif ($null -ne $ResetCache_Override) {
    $global:ResetCache = [bool]$ResetCache_Override
}

# Int -- layered: CLI > existing layered global (Layer 4 defaults / Layer 5 custom) > template fallback default.
# Bare `else $AutoBucketMax_Default` would stomp Layer 4/5 -- a customer who sets a higher value in
# LauncherConfig.custom.ps1 would have it overwritten back to the launcher's hardcoded default.
if (-not (Test-Path variable:global:AutoBucketMax) -or $null -eq $global:AutoBucketMax) {
    $global:AutoBucketMax = [int]$AutoBucketMax_Default
}
if ($cliBound.ContainsKey('AutoBucketMax')) {
    $global:AutoBucketMax = [int]$cliBound['AutoBucketMax']
}

# Honor customer's $global:ReportTemplate_Default* (set in LauncherConfig.custom.ps1
# layer 3 / SecurityInsight.custom.ps1 layer 5). Without this lift, the launcher's
# hardcoded local defaults below always win regardless of what the customer set --
# the same layered-config bug we already fixed for $RiskAnalysis_*_Override above.
if (Test-Path variable:global:ReportTemplate_Default)          { $ReportTemplate_Default          = $global:ReportTemplate_Default }
if (Test-Path variable:global:ReportTemplate_Default_Summary)  { $ReportTemplate_Default_Summary  = $global:ReportTemplate_Default_Summary }
if (Test-Path variable:global:ReportTemplate_Default_Detailed) { $ReportTemplate_Default_Detailed = $global:ReportTemplate_Default_Detailed }

# ReportTemplate: -ReportTemplate wins, then $ReportTemplate_Default, then per-mode default.
if ($cliBound.ContainsKey('ReportTemplate') -and -not [string]::IsNullOrWhiteSpace([string]$cliBound['ReportTemplate'])) {
    $global:ReportTemplate = [string]$cliBound['ReportTemplate']
} elseif (-not [string]::IsNullOrWhiteSpace($ReportTemplate_Default)) {
    $global:ReportTemplate = $ReportTemplate_Default
} elseif ($global:Detailed -and -not $global:Summary) {
    $global:ReportTemplate = $ReportTemplate_Default_Detailed
} else {
    $global:ReportTemplate = $ReportTemplate_Default_Summary
}

Write-Info ("[LAUNCHER] AutomationFramework={0} Summary={1} Detailed={2} BuildSummaryByAI={3}" -f `
    $global:AutomationFramework, $global:Summary, $global:Detailed, $global:BuildSummaryByAI)
Write-Info ("[LAUNCHER] AutoBucketCount={0} AutoBucketCache={1} AutoBucketMax={2} ResetCache={3}" -f `
    $global:AutoBucketCount, $global:AutoBucketCache, $global:AutoBucketMax, $global:ResetCache)
Write-Info ("[LAUNCHER] ReportTemplate={0}  ShowConfig={1}  DebugQueryHash={2}" -f `
    $global:ReportTemplate, $global:ShowConfig, $global:DebugQueryHash)

try {
    Write-Step "Invoking engine"
    # v2.2 layout splits launcher (v2.2/launcher/risk-analysis/)
    # from engine (v2.2/engine/risk-analysis/). Resolve via 2-up nav from
    # launcher dir. Fall back to legacy SCRIPTS/ for non-migrated installs.
    $launcherDir       = $PSScriptRoot
    $v22RootForEngine  = Split-Path -Parent (Split-Path -Parent $launcherDir)   # v2.2/
    $engine            = Join-Path $v22RootForEngine 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    if (-not (Test-Path -LiteralPath $engine)) {
        $engineOwner = Split-Path -Parent $v22RootForEngine                      # SOLUTIONS/SecurityInsight/
        foreach ($case in 'SCRIPTS','scripts') {
            $candidate = Join-Path $engineOwner (Join-Path $case 'Invoke-RiskAnalysis.ps1')
            if (Test-Path -LiteralPath $candidate) { $engine = $candidate; break }
        }
    }
    if (-not (Test-Path -LiteralPath $engine)) { throw "Launcher: engine 'Invoke-RiskAnalysis.ps1' not found at v2.2/engine/risk-analysis/ OR under <solroot>/SCRIPTS/." }
    Write-Info "engine: $engine"
    & $engine
    Write-Ok "Engine completed successfully"
} catch {
    Write-Err2 "Engine failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    throw
}

# flush + close the transcript started right after Write-Banner.
Stop-SILauncherTranscript
