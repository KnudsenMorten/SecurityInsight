#Requires -Version 5.1
<#
.SYNOPSIS
    Internal VM (Automation Framework) launcher for SecurityInsight asset-profiling
    identity engine. Invokes Invoke-SIEngineRun -Engine identity.

.DESCRIPTION
    Runs the SecurityInsight asset-profiling identity engine on a platform-managed
    Windows VM using the existing 2LINKIT Automation Framework (FUNCTIONS/ modules,
    internal KV, Connect_Azure helper).

    Assumes Initialize-PlatformAutomationFramework has populated the v1-contract
    globals (HighPriv_*, etc.) before this launcher runs, OR the engine itself
    will bootstrap on first connect.

    Asset-profiling engines do NOT use $global:SettingsPath. Storage-account
    context is resolved in this order:
      1. -StorageAccountName / -StorageAccountKey on the CLI
      2. -UseStorageOAuth switch
      3. $global:SI_StorageAccount + $global:SI_StorageKey from config

.NOTES
    Solution       : SecurityInsight
    File           : launcher.internal-vm.ps1
    Engine         : asset-profiling/identity (Invoke-SIEngineRun -Engine identity)
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

    # Asset-profiling engine knobs (passthrough to Invoke-SIEngineRun)
    [switch]$Mock,
    [int]$AssetLimit = 0,
    [string[]]$Sinks,
    [switch]$ForceFullRun,
    [switch]$UseStorageOAuth,
    [string]$StorageAccountName,
    [string]$StorageAccountKey
)
$ErrorActionPreference = 'Stop'

# Get-PublishedVersion: shared helper in _lib/.
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

Write-Banner -Solution 'SecurityInsight' -Engine 'AssetProfiling_Identity' -Flavour 'internal-vm' -Version $versionStamp
$global:SI_TranscriptPath = Start-SILauncherTranscript -Engine 'identity' -Flavour 'internal-vm' -RepoRoot $InstallPath

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
        -Engine      'AssetProfiling_Identity' `
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
$global:AutomationFramework = $true
$global:PathScripts         = $InstallPath
$global:WhatIfMode          = [bool]$WhatIfMode
$global:SuppressErrors      = [bool]$SuppressErrors
$global:SuppressWarnings    = [bool]$SuppressWarnings

# Snapshot CLI bound params.
$cliBound = @{}
foreach ($k in $PSBoundParameters.Keys) { $cliBound[$k] = $PSBoundParameters[$k] }

# Resolve Sinks: CLI > $global:SI_Sinks_Identity > engine default.
if ($cliBound.ContainsKey('Sinks') -and $Sinks) {
    $effectiveSinks = $Sinks
} elseif ($global:SI_Sinks_Identity) {
    $effectiveSinks = @($global:SI_Sinks_Identity)
} else {
    $effectiveSinks = @('LA','JSON','Excel')
}

# Resolve AssetLimit: CLI > $global:SI_AssetLimit_Identity > 0.
if ($cliBound.ContainsKey('AssetLimit')) {
    $effectiveAssetLimit = [int]$AssetLimit
} elseif ($null -ne $global:SI_AssetLimit_Identity) {
    $effectiveAssetLimit = [int]$global:SI_AssetLimit_Identity
} else {
    $effectiveAssetLimit = 0
}

# Resolve ForceFullRun: CLI > $global:SI_ForceFullRun_Identity > $global:SI_ForceFullRun.
$effectiveForceFullRun = $false
if ($cliBound.ContainsKey('ForceFullRun')) {
    $effectiveForceFullRun = [bool]$ForceFullRun
} elseif ($global:SI_ForceFullRun_Identity) {
    $effectiveForceFullRun = [bool]$global:SI_ForceFullRun_Identity
} elseif ($global:SI_ForceFullRun) {
    $effectiveForceFullRun = [bool]$global:SI_ForceFullRun
}

Write-Info ("[LAUNCHER] AutomationFramework={0} Sinks={1} AssetLimit={2} ForceFullRun={3} Mock={4} UseStorageOAuth={5}" -f `
    $global:AutomationFramework, ($effectiveSinks -join ','), $effectiveAssetLimit, $effectiveForceFullRun, [bool]$Mock, [bool]$UseStorageOAuth)

# Build the splat for Invoke-SIEngineRun.
$cliPassthrough = @{
    AssetLimit   = $effectiveAssetLimit
    ForceFullRun = $effectiveForceFullRun
}
if ($Mock)            { $cliPassthrough['Mock']               = $true }
if ($UseStorageOAuth) { $cliPassthrough['UseStorageOAuth']    = $true }
if ($StorageAccountName) { $cliPassthrough['StorageAccountName'] = $StorageAccountName }
if ($StorageAccountKey)  { $cliPassthrough['StorageAccountKey']  = $StorageAccountKey  }

try {
    Write-Step "Invoking engine"
    # Launcher lives at v2.2/launcher/identity/. Engine entry is at
    # v2.2/engine/asset-profiling/Invoke-SIEngineRun.ps1. 2-up from launcher = v2.2/.
    # Asset-profiling is v2.2-only -- no legacy fallback.
    $launcherDir = $PSScriptRoot
    $v22RootForEngine = Split-Path -Parent (Split-Path -Parent $launcherDir)
    $engine = Join-Path $v22RootForEngine 'engine\asset-profiling\Invoke-SIEngineRun.ps1'
    if (-not (Test-Path -LiteralPath $engine)) {
        throw "Launcher: engine 'Invoke-SIEngineRun.ps1' not found at $engine. Asset-profiling is v2.2-only; check the v2.2/engine/asset-profiling/ tree."
    }
    Write-Info "engine: $engine -Engine identity"
    & $engine -Engine 'identity' -Sinks $effectiveSinks @cliPassthrough
    Write-Ok "Engine completed successfully"
} catch {
    Write-Err2 "Engine failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    throw
}

# flush + close the transcript started right after Write-Banner.
Stop-SILauncherTranscript
