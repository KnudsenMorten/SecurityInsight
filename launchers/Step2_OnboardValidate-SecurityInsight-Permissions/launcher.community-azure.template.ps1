#Requires -Version 5.1
<#
.SYNOPSIS
    Community Azure launcher for SecurityInsight\Step2_OnboardValidate-SecurityInsight-Permissions.
.DESCRIPTION
    Thin wrapper around the Step2_OnboardValidate-SecurityInsight-Permissions.ps1
    admin utility. Loads the layered config (defaults + customer overrides),
    then invokes the script with each non-null global splatted as a parameter.

    Default AuthMethod = Interactive (browser sign-in by an admin user).
    Override $global:OnboardValidate_AuthMethod in LauncherConfig.custom.ps1
    if you want unattended SPN/MI/cert auth on this host.

.NOTES
    Solution       : SecurityInsight
    Engine         : Step2_OnboardValidate-SecurityInsight-Permissions
    File           : launcher.community-azure.template.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
#>
[CmdletBinding()]
param(
    [string]$InstallPath,
    [string]$LauncherConfigPath,
    [switch]$WhatIfMode
)
$ErrorActionPreference = 'Stop'

# Get-PublishedVersion: shared helper in _lib/. Dot-sourced before the banner.
. (Join-Path $PSScriptRoot '..\_lib\Get-PublishedVersion.ps1')

function Write-Banner {
    param(
        [Parameter(Mandatory)][string]$Solution,
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$Flavour,
        [string]$Version = '(dev)'
    )
    $line = '=' * 88
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  {0} -- {1}    [{2}]   {3}" -f $Solution, $Engine, $Flavour, $Version) -ForegroundColor Cyan
    Write-Host '' -ForegroundColor Cyan
    Write-Host '  Developed by Morten Knudsen -- Microsoft MVP' -ForegroundColor Cyan
    Write-Host '  Blog:    https://mortenknudsen.net   (aka.ms/morten)' -ForegroundColor Cyan
    Write-Host '  GitHub:  https://github.com/KnudsenMorten' -ForegroundColor Cyan
    Write-Host '  Support: GitHub Issues on the public repo, or mok@mortenknudsen.net (internal)' -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}
function Write-Step  { param([string]$m) Write-Host "[STEP]  $m" -ForegroundColor Cyan }
function Write-Info  { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor Gray }
function Write-Ok    { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Err2  { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

function Resolve-RepoRoot {
    param([string]$Start = $PSScriptRoot)
    $cur = $Start
    $communityMatch = $null
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
    throw "Launcher: cannot locate solution repo root walking up from '$Start'."
}

# Resolve repo root + version BEFORE the banner so the banner can show the version.
try {
    if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }
} catch {
    $resolveError = $_
}
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath -Solution 'SecurityInsight'

Write-Banner -Solution 'SecurityInsight' -Engine 'Step2_OnboardValidate-SecurityInsight-Permissions' -Flavour 'community-azure' -Version $versionStamp

if ($resolveError) {
    Write-Err2 $resolveError.Exception.Message
    throw $resolveError
}
Write-Step "Resolving repo root"
Write-Ok "repo root: $InstallPath"

try {
    # Layered config (community-vm: customer overrides optional -- script does
    # its own auth via -AuthMethod, so layer 4 is not REQUIRED).
    . (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')
    Initialize-LauncherConfig `
        -Solution    'SecurityInsight' `
        -Engine      'Step2_OnboardValidate-SecurityInsight-Permissions' `
        -LauncherDir $PSScriptRoot `
        -RepoRoot    $InstallPath `
        -Mode        'community' `
        -CustomConfigPath $LauncherConfigPath
} catch {
    Write-Err2 "Failed to load layered config: $($_.Exception.Message)"
    throw
}

# Locate the engine script
$launcherDir = $PSScriptRoot
$engineOwner = Split-Path -Parent (Split-Path -Parent $launcherDir)
$engine = $null
foreach ($case in 'SCRIPTS','scripts') {
    $candidate = Join-Path $engineOwner (Join-Path $case 'Step2_OnboardValidate-SecurityInsight-Permissions.ps1')
    if (Test-Path -LiteralPath $candidate) { $engine = $candidate; break }
}
if (-not $engine) {
    throw "Launcher: engine 'Step2_OnboardValidate-SecurityInsight-Permissions.ps1' not found at $engineOwner\SCRIPTS or $engineOwner\scripts."
}

# Flavor-specific AuthMethod default if customer didn't set one
if (-not $global:OnboardValidate_AuthMethod) { $global:OnboardValidate_AuthMethod = 'ManagedIdentity' }

# Build splat from $global:OnboardValidate_* globals (skip nulls / empties)
$splat = @{}
$paramMap = @{
    SpnDisplayName             = $global:OnboardValidate_SpnDisplayName
    SpnAppId                   = $global:OnboardValidate_SpnAppId
    AzureSubscriptionIds       = $global:OnboardValidate_AzureSubscriptionIds
    DefenderWorkspaceResourceId = $global:OnboardValidate_DefenderWorkspaceResourceId
    DcrResourceId              = $global:OnboardValidate_DcrResourceId
    AuthMethod                 = $global:OnboardValidate_AuthMethod
    AuthTenantId               = $global:OnboardValidate_AuthTenantId
    AuthClientId               = $global:OnboardValidate_AuthClientId
    AuthClientSecret           = $global:OnboardValidate_AuthClientSecret
    AuthCertificateThumbprint  = $global:OnboardValidate_AuthCertificateThumbprint
}
foreach ($k in $paramMap.Keys) {
    $v = $paramMap[$k]
    if ($null -eq $v) { continue }
    if ($v -is [string] -and [string]::IsNullOrWhiteSpace($v)) { continue }
    if ($v -is [System.Array] -and $v.Count -eq 0) { continue }
    $splat[$k] = $v
}
# CLI -WhatIfMode wins over the global default
if ($PSBoundParameters.ContainsKey('WhatIfMode')) {
    $splat['WhatIfMode'] = [bool]$WhatIfMode
} elseif ([bool]$global:OnboardValidate_WhatIfMode) {
    $splat['WhatIfMode'] = $true
}

Write-Step "Invoking OnboardValidate engine"
Write-Info ("forwarding: {0}" -f (($splat.GetEnumerator() | Sort-Object Key | ForEach-Object {
    $val = if ($_.Key -match 'Secret|Thumbprint') { '<redacted>' } else { $_.Value }
    "{0}={1}" -f $_.Key, $val
}) -join ' '))

& $engine @splat
