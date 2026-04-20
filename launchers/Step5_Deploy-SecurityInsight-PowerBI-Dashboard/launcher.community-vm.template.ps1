#Requires -Version 5.1
<#
.SYNOPSIS
    Community VM launcher for SecurityInsight\Step5_Deploy-SecurityInsight-PowerBI-Dashboard.
.DESCRIPTION
    Deploys the Risk Analysis management dashboard into the customer's
    Power BI tenant. Reads settings from LauncherConfig.custom.ps1 and
    forwards them to the engine. The engine itself handles OAuth2 against
    the Power BI REST API -- no Az.Accounts prep needed in the launcher.

.NOTES
    Solution : SecurityInsight
    Flavour  : community-vm
    File     : launcher.community-vm.template.ps1
#>
[CmdletBinding()]
param(
    [string]$InstallPath,
    [switch]$WhatIfMode
)
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot '..\_lib\Get-PublishedVersion.ps1')
. (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')

function Write-Banner {
    param([string]$Solution,[string]$Engine,[string]$Flavour,[string]$Version='(dev)')
    $line = '=' * 88
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  {0} -- {1}    [{2}]   {3}" -f $Solution,$Engine,$Flavour,$Version) -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Developed by Morten Knudsen -- Microsoft MVP' -ForegroundColor Cyan
    Write-Host '  Blog:    https://mortenknudsen.net   (aka.ms/morten)' -ForegroundColor Cyan
    Write-Host '  GitHub:  https://github.com/KnudsenMorten' -ForegroundColor Cyan
    Write-Host '  Support: GitHub Issues on the public repo, or mok@mortenknudsen.net (internal)' -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}
function Write-Step { param([string]$m) Write-Host "[STEP]  $m" -ForegroundColor Cyan }
function Write-Info { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor Gray  }
function Write-Ok   { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Err2 { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red   }

function Resolve-RepoRoot {
    param([string]$Start = $PSScriptRoot)
    $cur = $Start; $communityMatch = $null
    while ($cur) {
        if (Test-Path (Join-Path $cur 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1')) { return $cur }
        if (-not $communityMatch) {
            $dirs = Get-ChildItem -LiteralPath $cur -Directory -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
            if (($dirs -ccontains 'scripts') -and ($dirs -ccontains 'launchers')) { $communityMatch = $cur }
        }
        $parent = Split-Path -Parent $cur
        if (-not $parent -or $parent -eq $cur) { break }
        $cur = $parent
    }
    if ($communityMatch) { return $communityMatch }
    throw "Launcher: cannot locate repo root walking up from '$Start'."
}

try { if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot } } catch { $resolveError = $_ }
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath -Solution 'SecurityInsight'

Write-Banner -Solution 'SecurityInsight' -Engine 'Step5_Deploy-SecurityInsight-PowerBI-Dashboard' -Flavour 'community-vm' -Version $versionStamp

if ($resolveError) { Write-Err2 $resolveError.Exception.Message; throw $resolveError }
Write-Step "Resolving repo root"
Write-Ok   "repo root: $InstallPath"

Initialize-LauncherConfig -LauncherDir $PSScriptRoot -Solution 'SecurityInsight' -RepoRoot $InstallPath -Mode 'community'

# Flavour default: SpnSecret (customer paste creds into LauncherConfig.custom.ps1)
if (-not $global:Step5_AuthMethod) { $global:Step5_AuthMethod = 'SpnSecret' }

# Engine path (monorepo or community layout)
$launcherDir = $PSScriptRoot
$engineOwner = Split-Path -Parent (Split-Path -Parent $launcherDir)
$engine = $null
foreach ($case in 'SCRIPTS','scripts') {
    $candidate = Join-Path $engineOwner (Join-Path $case 'Step5_Deploy-SecurityInsight-PowerBI-Dashboard.ps1')
    if (Test-Path -LiteralPath $candidate) { $engine = $candidate; break }
}
if (-not $engine) { throw "Launcher: engine 'Step5_Deploy-SecurityInsight-PowerBI-Dashboard.ps1' not found at $engineOwner\SCRIPTS or $engineOwner\scripts." }

# Splat Step5_* globals to engine params (skip nulls / empties)
$splat = @{}
$paramMap = @{
    PbixPath                    = $global:Step5_PbixPath
    PowerBIWorkspaceName        = $global:Step5_PowerBIWorkspaceName
    ReportName                  = $global:Step5_ReportName
    LAWorkspaceId               = $global:Step5_LAWorkspaceId
    LATenantId                  = $global:Step5_LATenantId
    StalenessDays               = $global:Step5_StalenessDays
    TopNFindings                = $global:Step5_TopNFindings
    AccessGroupObjectId         = $global:Step5_AccessGroupObjectId
    AccessGroupRole             = $global:Step5_AccessGroupRole
    AuthMethod                  = $global:Step5_AuthMethod
    AuthTenantId                = $global:Step5_AuthTenantId
    AuthClientId                = $global:Step5_AuthClientId
    AuthClientSecret            = $global:Step5_AuthClientSecret
    AuthCertificateThumbprint   = $global:Step5_AuthCertificateThumbprint
}
foreach ($k in $paramMap.Keys) {
    $v = $paramMap[$k]
    if ($null -eq $v) { continue }
    if ($v -is [string] -and [string]::IsNullOrWhiteSpace($v)) { continue }
    $splat[$k] = $v
}

# Switches: per-run -WhatIfMode wins; else global; TriggerInitialRefresh default $true
if ($PSBoundParameters.ContainsKey('WhatIfMode')) {
    $splat['WhatIfMode'] = [bool]$WhatIfMode
} elseif ([bool]$global:Step5_WhatIfMode) {
    $splat['WhatIfMode'] = $true
}
if ($null -eq $global:Step5_TriggerInitialRefresh -or [bool]$global:Step5_TriggerInitialRefresh) {
    $splat['TriggerInitialRefresh'] = $true
}

Write-Step "Invoking Step 5 engine"
Write-Info ("forwarding: {0}" -f (($splat.GetEnumerator() | Sort-Object Key | Where-Object { $_.Key -ne 'AuthClientSecret' } | ForEach-Object { "{0}={1}" -f $_.Key, $_.Value }) -join '  '))
& $engine @splat
Write-Ok "Engine completed"
