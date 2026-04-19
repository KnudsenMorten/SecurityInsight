#Requires -Version 5.1
#Requires -Modules @{ ModuleName='Az.Accounts'; ModuleVersion='2.0.0' }
<#
.SYNOPSIS
    Community Azure (Function / Logic App / Hybrid Worker) launcher for SecurityInsight\Onboarding_IdentityAssets_LogAnalytics.
.DESCRIPTION
    Runs the Onboarding_IdentityAssets_LogAnalytics engine from an Azure host that has a system-assigned MI.
    MI -> Key Vault -> SPN secret -> SPN login. Requires App Settings:
    PLATFORM_TENANT_ID, PLATFORM_SUBSCRIPTION_ID, PLATFORM_KEYVAULT.

.NOTES
    Solution       : SecurityInsight
    File           : launcher.community-azure.template.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
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

# Get-PublishedVersion: shared helper in _lib/. Dot-sourced before the banner.
. (Join-Path $PSScriptRoot '..\_lib\Get-PublishedVersion.ps1')

function Write-Banner {
    param(
        [Parameter(Mandatory)][string]$Solution,
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$Flavour,
        [string]$Description = '',
        [string]$Version = '(dev)'
    )
    $line = '=' * 88
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  {0} -- {1}    [{2}]   {3}" -f $Solution, $Engine, $Flavour, $Version) -ForegroundColor Cyan
    if ($Description) {
        foreach ($chunk in ($Description -split '(?<=.{1,86})\s+')) {
            Write-Host ("  {0}" -f $chunk) -ForegroundColor Gray
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
function Write-Step   { param([string]$m) Write-Host "[STEP]  $m" -ForegroundColor Cyan }
function Write-Info   { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor Gray }
function Write-Ok     { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn2  { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err2   { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

function Test-LauncherModule {
    param(
        [Parameter(Mandatory)][string]$Name,
        [switch]$Required,
        [switch]$AutoInstall
    )
    $mod = Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($mod) { Write-Ok "module '$Name' v$($mod.Version) present"; return $true }
    if ($AutoInstall) {
        Write-Warn2 "module '$Name' missing -- attempting Install-Module -Scope CurrentUser"
        try {
            Install-Module $Name -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            Write-Ok "installed '$Name'"
            return $true
        } catch {
            if ($Required) { throw "Required module '$Name' could not be installed: $($_.Exception.Message)" }
            Write-Warn2 "optional module '$Name' install failed: $($_.Exception.Message) (continuing)"
            return $false
        }
    }
    if ($Required) { throw "Required module '$Name' is not installed. Run: Install-Module $Name -Scope CurrentUser" }
    Write-Warn2 "optional module '$Name' not installed (some features may be unavailable)"
    return $false
}

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
    throw ("Launcher: cannot locate solution repo root walking up from '{0}'. Expected FUNCTIONS\AutomateITPS\AutomateITPS.psd1 (monorepo) or a lowercase scripts/+launchers/ pair (community repo)." -f $Start)
}
# Resolve repo root + version BEFORE the banner so the banner can show the version.
try {
    if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }
} catch {
    $resolveError = $_
}
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath -Solution 'SecurityInsight'

Write-Banner -Solution 'SecurityInsight' -Engine 'Onboarding_IdentityAssets_LogAnalytics' -Flavour 'community-azure' -Version $versionStamp

if ($resolveError) {
    Write-Err2 $resolveError.Exception.Message
    throw $resolveError
}
Write-Step "Resolving repo root"
Write-Ok "repo root: $InstallPath"

try {
    Write-Step "Checking required modules (Az.Accounts, Az.KeyVault)"
    [void](Test-LauncherModule -Name 'Az.Accounts' -Required -AutoInstall)
    [void](Test-LauncherModule -Name 'Az.KeyVault' -Required -AutoInstall)
    Import-Module Az.Accounts -ErrorAction Stop -WarningAction SilentlyContinue
    Import-Module Az.KeyVault  -ErrorAction Stop -WarningAction SilentlyContinue
} catch {
    Write-Err2 "Module load failed: $($_.Exception.Message)"
    throw
}

try {
    Write-Step "Connecting Managed Identity -> Key Vault"
    foreach ($v in 'PLATFORM_TENANT_ID','PLATFORM_KEYVAULT') {
        if (-not (Get-Item "env:$v" -ErrorAction SilentlyContinue)) { throw "App Setting '$v' is not set on this Function / Logic App." }
    }
    Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
    Write-Info "Fetching SPN secret from Key Vault '$env:PLATFORM_KEYVAULT' (secret name 'Modern-Secret-Azure')"
    $appIdSecret  = (Get-AzKeyVaultSecret -VaultName $env:PLATFORM_KEYVAULT -Name 'Modern-ApplicationId-Azure' -ErrorAction Stop).SecretValue
    $appSecSecret = (Get-AzKeyVaultSecret -VaultName $env:PLATFORM_KEYVAULT -Name 'Modern-Secret-Azure'         -ErrorAction Stop).SecretValue
    $bstrId  = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($appIdSecret)
    try { $appId = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrId) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrId) }
    $global:SpnTenantId     = $env:PLATFORM_TENANT_ID
    $global:SpnClientId     = $appId
    $bstrSec = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($appSecSecret)
    try { $global:SpnClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrSec) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrSec) }
    Disconnect-AzAccount -WarningAction SilentlyContinue | Out-Null
    $cred = [pscredential]::new($global:SpnClientId, $appSecSecret)
    Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
    Write-Ok "Connected as SPN via KV-retrieved secret"
} catch {
    Write-Err2 "Cloud auth failed: $($_.Exception.Message)"
    throw
}

Write-Step "Setting engine globals"
$global:AutomationFramework = $false
$engineOwner  = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$settingsOwner = $engineOwner
$settingsResolved = $null
foreach ($case in 'DATA','data') {
    $candidate = Join-Path $settingsOwner $case
    if (Test-Path -LiteralPath $candidate) { $settingsResolved = $candidate; break }
}
$global:SettingsPath = if ($settingsResolved) { $settingsResolved } else { $PSScriptRoot }
$global:WhatIfMode          = [bool]$WhatIfMode
$global:SuppressErrors      = [bool]$SuppressErrors
$global:SuppressWarnings    = [bool]$SuppressWarnings

try {
    Write-Step "Invoking engine"
    # Resolve engine path portably -- works in the monorepo, in a published
# community repo, and inside a bundled dependency under dependencies/<dep>/.
$launcherDir = $PSScriptRoot
$engineOwner = Split-Path -Parent (Split-Path -Parent $launcherDir)
$engine = $null
foreach ($case in 'SCRIPTS','scripts') {
    $candidate = Join-Path $engineOwner (Join-Path $case 'Onboarding_IdentityAssets_LogAnalytics.ps1')
    if (Test-Path -LiteralPath $candidate) { $engine = $candidate; break }
}
if (-not $engine) { throw "Launcher: engine 'Onboarding_IdentityAssets_LogAnalytics.ps1' not found at $engineOwner\SCRIPTS or $engineOwner\scripts. Expected the launcher to live at <solroot>\LAUNCHERS\<engine>\ with a sibling SCRIPTS\ or scripts\ folder." }
    if (-not (Test-Path -LiteralPath $engine)) { throw "engine script not found at $engine" }
    Write-Info "engine: $engine"
    & $engine
    Write-Ok "Engine completed successfully"
} catch {
    Write-Err2 "Engine failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    throw
}
finally {
    $global:SpnClientSecret = $null
    [System.GC]::Collect()
}