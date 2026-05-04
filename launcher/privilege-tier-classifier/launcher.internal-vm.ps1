#Requires -Version 5.1
<#
.SYNOPSIS
    Internal VM (Automation Framework) launcher for SecurityInsight privilege-tier-classifier
    engine. Invokes engine/privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1.

.DESCRIPTION
    Builds the SecurityInsight tier-definitions JSON (AD groups, Entra roles, API
    permissions, Azure RBAC) using AI-batched tiering. Output written to
    v2.2/privilege-tier-catalog/privilege-tier-catalog.custom.json.

    The engine bootstraps its own Initialize-PlatformAutomationFramework when
    $global:AutomationFramework = $true. This launcher just sets that flag, the
    repo root, and the engine's $global:SettingsPath, then delegates.

.NOTES
    Solution       : SecurityInsight
    File           : launcher.internal-vm.ps1
    Engine         : privilege-tier-classifier/Invoke-PrivilegeTierClassifier.ps1
    Developed by   : Morten Knudsen, Microsoft MVP
    Blog           : https://mortenknudsen.net   (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.
#>
[CmdletBinding()]
param(
    [string]$InstallPath,
    [switch]$WhatIfMode,
    [switch]$SuppressErrors,
    [switch]$SuppressWarnings
)
$ErrorActionPreference = 'Stop'

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

try {
    if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }
} catch {
    $resolveError = $_
}
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath -Solution 'SecurityInsight'

Write-Banner -Solution 'SecurityInsight' -Engine 'PrivilegeTierClassifier' -Flavour 'internal-vm' -Version $versionStamp
$global:SI_TranscriptPath = Start-SILauncherTranscript -Engine 'privilege-tier-classifier' -Flavour 'internal-vm' -RepoRoot $InstallPath

if ($resolveError) {
    Write-Err2 $resolveError.Exception.Message
    throw $resolveError
}
Write-Step "Resolving repo root"
Write-Ok "repo root: $InstallPath"

try {
    . (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')
    Initialize-LauncherConfig `
        -Solution    'SecurityInsight' `
        -Engine      'PrivilegeTierClassifier' `
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

# Tiering engine reads $global:SettingsPath only as a soft default ($PSScriptRoot
# of the engine script). Output goes to v2.2/data/. Setting SettingsPath here
# keeps any future YAML/JSON inputs co-located with this launcher's overrides.
$launcherDir       = $PSScriptRoot
$v22Root           = Split-Path -Parent (Split-Path -Parent $launcherDir)
$global:SettingsPath = Join-Path $v22Root 'privilege-tier-catalog'

Write-Info ("[LAUNCHER] AutomationFramework={0} SettingsPath={1}" -f $global:AutomationFramework, $global:SettingsPath)

try {
    Write-Step "Invoking engine"
    $engine = Join-Path $v22Root 'engine\privilege-tier-classifier\Invoke-PrivilegeTierClassifier.ps1'
    if (-not (Test-Path -LiteralPath $engine)) {
        throw "Launcher: engine 'Invoke-PrivilegeTierClassifier.ps1' not found at $engine."
    }
    Write-Info "engine: $engine"
    & $engine
    Write-Ok "Engine completed successfully"
} catch {
    Write-Err2 "Engine failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    throw
}

Stop-SILauncherTranscript
