#Requires -Version 5.1
#Requires -Modules @{ ModuleName='Az.Accounts'; ModuleVersion='2.0.0' }
<#
.SYNOPSIS
    Community Azure (Function / Logic App / Hybrid Worker) launcher for SecurityInsight\SecurityInsight_RiskAnalysis.
.DESCRIPTION
    Runs the SecurityInsight_RiskAnalysis engine from an Azure host that has a system-assigned MI.
    MI -> Key Vault -> SPN secret -> SPN login. Requires App Settings:
    PLATFORM_TENANT_ID, PLATFORM_SUBSCRIPTION_ID, PLATFORM_KEYVAULT.

.NOTES
    Solution       : SecurityInsight
    File           : launcher.community-azure.template.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
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
    [ValidateRange(1,512)][int]$AutoBucketMax,
    [Alias('ResetCache')][switch]$ResetCacheSwitch,

    # Other engine knobs
    [switch]$ShowConfig,
    [switch]$DebugQueryHash
)
$ErrorActionPreference = 'Stop'

# ============================================================================
#  DEFAULTS (single source of truth) -- edit here to change baseline behaviour
#  for ALL invocations of this launcher. CLI switches override these per run.
# ============================================================================

$RunMode_Default = 'Auto'

$Summary_Override   = $null
$Detailed_Override  = $null
$ResetCache_Override = $null

$AutomationFramework_Default = $false
$OverwriteXlsx_Default       = $true
$BuildSummaryByAI_Default    = $false

$ReportTemplate_Default          = $null
$ReportTemplate_Default_Summary  = 'RiskAnalysis_Summary_Bucket'
$ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed_Bucket'

$AutoBucketCount_Default = $true
$AutoBucketCache_Default = $true
$AutoBucketMax_Default   = 512

$ResetCache_Default      = $false
$DebugQueryHash_Default  = $false
$ShowConfig_Default      = $false

# ============================================================================

function Write-Banner {
    param(
        [Parameter(Mandatory)][string]$Solution,
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][string]$Flavour,
        [string]$Description = ''
    )
    $line = '=' * 88
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  {0} -- {1}    [{2}]" -f $Solution, $Engine, $Flavour) -ForegroundColor Cyan
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
function Write-Step  { param([string]$m) Write-Host "[STEP]  $m" -ForegroundColor Cyan }
function Write-Info  { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor Gray }
function Write-Ok    { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err2  { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

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

Write-Banner -Solution 'SecurityInsight' -Engine 'SecurityInsight_RiskAnalysis' -Flavour 'community-azure' -Description 'SecurityInsight_RiskAnalysis -- v2 ported engine under SecurityInsight.'

try {
    Write-Step "Resolving repo root"
    if (-not $InstallPath) { $InstallPath = Resolve-RepoRoot }
    Write-Ok "repo root: $InstallPath"
} catch {
    Write-Err2 $_.Exception.Message
    throw
}

try {
    # Layered config (community-azure has no per-engine custom file; engine
    # knobs not in defaults come from App Settings env vars downstream).
    . (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')
    Initialize-LauncherConfig `
        -Solution    'SecurityInsight' `
        -Engine      'SecurityInsight_RiskAnalysis' `
        -LauncherDir $PSScriptRoot `
        -RepoRoot    $InstallPath `
        -Mode        'community'
} catch {
    Write-Err2 "Failed to load layered config: $($_.Exception.Message)"
    throw
}

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
$engineOwner = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$settingsOwner = $engineOwner
$settingsResolved = $null
foreach ($case in 'DATA','data') {
    $candidate = Join-Path $settingsOwner $case
    if (Test-Path -LiteralPath $candidate) { $settingsResolved = $candidate; break }
}
$global:SettingsPath     = if ($settingsResolved) { $settingsResolved } else { $PSScriptRoot }
$global:WhatIfMode       = [bool]$WhatIfMode
$global:SuppressErrors   = [bool]$SuppressErrors
$global:SuppressWarnings = [bool]$SuppressWarnings

# ----- Resolve runtime values: CLI bound > in-script Override > Default -----
# Inline (v1 pattern). See SecurityInsight_RiskAnalysis community-vm v2.1.27.
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
$global:OverwriteXlsx       = [bool]$OverwriteXlsx_Default

$mode = Resolve-RunMode `
    -Bound $cliBound `
    -DefaultMode $RunMode_Default `
    -SummaryOverride $Summary_Override `
    -DetailedOverride $Detailed_Override `
    -AFFlag $global:AutomationFramework
$global:Summary  = [bool]$mode.Summary
$global:Detailed = [bool]$mode.Detailed

$global:BuildSummaryByAI = $BuildSummaryByAI_Default
if ($cliBound.ContainsKey('BuildSummaryByAI')) { $global:BuildSummaryByAI = [bool]$cliBound['BuildSummaryByAI'] }

$global:AutoBucketCount = $AutoBucketCount_Default
if ($cliBound.ContainsKey('AutoBucketCount')) { $global:AutoBucketCount = [bool]$cliBound['AutoBucketCount'] }

$global:AutoBucketCache = $AutoBucketCache_Default
if ($cliBound.ContainsKey('AutoBucketCache')) { $global:AutoBucketCache = [bool]$cliBound['AutoBucketCache'] }

$global:ShowConfig = $ShowConfig_Default
if ($cliBound.ContainsKey('ShowConfig')) { $global:ShowConfig = [bool]$cliBound['ShowConfig'] }

$global:DebugQueryHash = $DebugQueryHash_Default
if ($cliBound.ContainsKey('DebugQueryHash')) { $global:DebugQueryHash = [bool]$cliBound['DebugQueryHash'] }

$global:ResetCache = $ResetCache_Default
if ($cliBound.ContainsKey('ResetCacheSwitch')) {
    $global:ResetCache = [bool]$cliBound['ResetCacheSwitch']
} elseif ($null -ne $ResetCache_Override) {
    $global:ResetCache = [bool]$ResetCache_Override
}

if ($cliBound.ContainsKey('AutoBucketMax')) {
    $global:AutoBucketMax = [int]$cliBound['AutoBucketMax']
} else {
    $global:AutoBucketMax = [int]$AutoBucketMax_Default
}

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
    $launcherDir = $PSScriptRoot
    $engineOwner = Split-Path -Parent (Split-Path -Parent $launcherDir)
    $engine = $null
    foreach ($case in 'SCRIPTS','scripts') {
        $candidate = Join-Path $engineOwner (Join-Path $case 'SecurityInsight_RiskAnalysis.ps1')
        if (Test-Path -LiteralPath $candidate) { $engine = $candidate; break }
    }
    if (-not $engine) { throw "Launcher: engine 'SecurityInsight_RiskAnalysis.ps1' not found at $engineOwner\SCRIPTS or $engineOwner\scripts." }
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
