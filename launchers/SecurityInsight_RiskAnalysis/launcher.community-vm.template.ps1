#Requires -Version 5.1
<#
.SYNOPSIS
    Community launcher for SecurityInsight\SecurityInsight_RiskAnalysis (user VM / box).
.DESCRIPTION
    Dot-sources LauncherConfig.ps1 (user copies from LauncherConfig.sample.ps1)
    to set SPN tenant + client id + secret. No internal-only modules.
#>
[CmdletBinding()]
param(
    [string]$InstallPath,
    [string]$LauncherConfigPath,
    [switch]$WhatIfMode,
    [switch]$SuppressErrors,
    [switch]$SuppressWarnings
)

$ErrorActionPreference = 'Stop'

function Resolve-AutomateITRepoRoot {
    param([string]$Start = $PSScriptRoot)
    $cur = $Start
    while ($cur) {
        if (Test-Path (Join-Path $cur 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1')) { return $cur }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    throw "Launcher: cannot locate AutomateIT repo root walking up from '$Start'."
}
if (-not $InstallPath) { $InstallPath = Resolve-AutomateITRepoRoot }

if (-not $LauncherConfigPath) { $LauncherConfigPath = Join-Path $PSScriptRoot 'LauncherConfig.ps1' }
if (-not (Test-Path -LiteralPath $LauncherConfigPath)) {
    throw "Community launcher: $LauncherConfigPath not found. Copy LauncherConfig.sample.ps1 to LauncherConfig.ps1 and fill in SPN values."
}
. $LauncherConfigPath

$global:AutomationFramework = $false
$global:SettingsPath        = Join-Path $InstallPath 'SOLUTIONS\SecurityInsight\DATA'
$global:WhatIfMode          = [bool]$WhatIfMode
$global:SuppressErrors      = [bool]$SuppressErrors
$global:SuppressWarnings    = [bool]$SuppressWarnings

$engine = Join-Path $InstallPath 'SOLUTIONS\SecurityInsight\SCRIPTS\SecurityInsight_RiskAnalysis.ps1'
if (-not (Test-Path -LiteralPath $engine)) { throw "Launcher: engine script not found at $engine." }
& $engine
