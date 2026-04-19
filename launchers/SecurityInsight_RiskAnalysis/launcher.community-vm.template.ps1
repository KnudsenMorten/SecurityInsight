#Requires -Version 5.1
<#
.SYNOPSIS
    Community VM launcher for SecurityInsight\SecurityInsight_RiskAnalysis.
.DESCRIPTION
    Runs the SecurityInsight_RiskAnalysis engine on a Windows box in the customer's own tenant.
    Reads credentials from LauncherConfig.ps1 (.gitignore'd). Supports 4 auth
    methods (MI, SPN+KV, SPN+cert, SPN+plaintext). See LauncherConfig.sample.ps1.

.NOTES
    Solution       : SecurityInsight
    File           : launcher.community-vm.template.ps1
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

#>
[CmdletBinding()]
param(
    # Generic launcher knobs
    [string]$InstallPath,
    [string]$LauncherConfigPath,
    [switch]$WhatIfMode,
    [switch]$SuppressErrors,
    [switch]$SuppressWarnings,

    # Engine-specific switches (override LauncherConfig.ps1 + engine defaults)
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

# Run-mode default. Allowed: 'Auto', 'Summary', 'Detailed'
# 'Auto' falls back to AutomationFramework rule (AF=>Summary, else neither).
$RunMode_Default = 'Auto'

# Optional in-script overrides ($null = no override; $true = force).
# Community-vm baseline = Summary mode (matches v1 RunSecurityInsight_Community_Sample.ps1).
# Set Detailed_Override=$true and Summary_Override=$null if this host should always
# produce the detailed report instead.
$Summary_Override   = $true
$Detailed_Override  = $null
$ResetCache_Override = $null

# Hardcoded defaults. Single place to change baseline operational tuning.
$AutomationFramework_Default = $false
$OverwriteXlsx_Default       = $true
$BuildSummaryByAI_Default    = $false

# ReportTemplate defaults (per mode). Set $ReportTemplate_Default to force a
# specific template regardless of Summary/Detailed; leave $null to let the
# Summary/Detailed mode below pick.
$ReportTemplate_Default          = $null
$ReportTemplate_Default_Summary  = 'RiskAnalysis_Summary_Bucket'
$ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed_Bucket'

# Adaptive bucketing baseline (engine reads these globals).
$AutoBucketCount_Default = $true
$AutoBucketCache_Default = $true
$AutoBucketMax_Default   = 512

# Cache + diagnostics
$ResetCache_Default      = $false
$DebugQueryHash_Default  = $false
$ShowConfig_Default      = $false

# ============================================================================

function Get-PublishedVersion {
    # Reads VERSION.txt at the resolved repo root. The publish workflow stamps
    # this file from the git tag (e.g. 'SecurityInsight-v2.1.16') so a customer
    # can see exactly which release they are running. In the monorepo there is
    # no VERSION.txt -> returns '(dev)'.
    param([string]$RepoRoot)
    if (-not $RepoRoot) { return '(dev)' }
    $verFile = Join-Path $RepoRoot 'VERSION.txt'
    if (-not (Test-Path -LiteralPath $verFile)) { return '(dev)' }
    $raw = (Get-Content -Raw -LiteralPath $verFile -ErrorAction SilentlyContinue)
    if (-not $raw) { return '(dev)' }
    return $raw.Trim()
}

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
    # Defer the error until after the banner so the user sees what they ran.
    $resolveError = $_
}
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath

Write-Banner -Solution 'SecurityInsight' -Engine 'SecurityInsight_RiskAnalysis' -Flavour 'community-vm' -Version $versionStamp

if ($resolveError) {
    Write-Err2 $resolveError.Exception.Message
    throw $resolveError
}
Write-Step "Resolving repo root"
Write-Ok "repo root: $InstallPath"

try {
    # Layer order: defaults.ps1 (ours, replaceable on update)
    #            -> LauncherConfig.ps1 (customer, gitignored, only the values they override)
    #            -> CLI args (last word, applied later in the launcher)
    Write-Step "Loading LauncherConfig.defaults.ps1 (baseline)"
    $defaultsPath = Join-Path $PSScriptRoot 'LauncherConfig.defaults.ps1'
    if (-not (Test-Path -LiteralPath $defaultsPath)) {
        throw "LauncherConfig.defaults.ps1 missing at $defaultsPath. This file ships with each release; reinstall the SecurityInsight package to restore it."
    }
    . $defaultsPath
    Write-Ok "defaults loaded"

    Write-Step "Loading LauncherConfig.ps1 (customer overrides)"
    if (-not $LauncherConfigPath) { $LauncherConfigPath = Join-Path $PSScriptRoot 'LauncherConfig.ps1' }
    if (-not (Test-Path -LiteralPath $LauncherConfigPath)) {
        throw "LauncherConfig.ps1 not found at $LauncherConfigPath. Copy LauncherConfig.sample.ps1 to LauncherConfig.ps1 and fill in your auth values + any other settings you need to override."
    }
    . $LauncherConfigPath
    Write-Ok "customer overrides loaded"
} catch {
    Write-Err2 "Failed to load LauncherConfig: $($_.Exception.Message)"
    throw
}

Write-Step "Resolving authentication"
if (-not $global:SpnTenantId -or [string]::IsNullOrWhiteSpace([string]$global:SpnTenantId)) {
    throw "Launcher: `$global:SpnTenantId is required (set it in LauncherConfig.ps1)."
}

try {
    [void](Test-LauncherModule -Name 'Az.Accounts' -Required -AutoInstall)
    Import-Module Az.Accounts -ErrorAction Stop -WarningAction SilentlyContinue
} catch {
    Write-Err2 "Failed to load Az.Accounts: $($_.Exception.Message)"
    throw
}

$haveKv = Test-LauncherModule -Name 'Az.KeyVault' -AutoInstall
$haveMg = Test-LauncherModule -Name 'Microsoft.Graph.Authentication' -AutoInstall

$authMethodUsed = $null
try {
    if ([bool]$global:UseManagedIdentity) {
        Write-Step "Auth method: Managed Identity"
        Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
        if ($haveMg) {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
            Connect-MgGraph -Identity -NoWelcome -WarningAction SilentlyContinue | Out-Null
        }
        $authMethodUsed = 'ManagedIdentity'
    }
    elseif ($global:SpnKeyVaultName -and $global:SpnSecretName) {
        Write-Step ("Auth method: SPN + Key Vault  (kv='{0}', secret='{1}')" -f $global:SpnKeyVaultName, $global:SpnSecretName)
        if (-not $haveKv)             { throw "Az.KeyVault is required for Key Vault auth." }
        if (-not $global:SpnClientId) { throw "`$global:SpnClientId is required for SPN + Key Vault auth." }
        Import-Module Az.KeyVault -ErrorAction Stop -WarningAction SilentlyContinue
        Connect-AzAccount -Identity -WarningAction SilentlyContinue | Out-Null
        $secretSecure = (Get-AzKeyVaultSecret -VaultName $global:SpnKeyVaultName -Name $global:SpnSecretName -ErrorAction Stop).SecretValue
        if (-not $secretSecure) { throw "Key Vault returned no value for secret '$($global:SpnSecretName)' in '$($global:SpnKeyVaultName)'." }
        Disconnect-AzAccount -WarningAction SilentlyContinue | Out-Null
        $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretSecure)
        try   { $global:SpnClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        if ($haveMg) {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
            $credForGraph = [pscredential]::new($global:SpnClientId, (ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force))
            Connect-MgGraph -TenantId $global:SpnTenantId -ClientSecretCredential $credForGraph -NoWelcome -WarningAction SilentlyContinue | Out-Null
        }
        $authMethodUsed = 'SPN-KeyVault'
    }
    elseif ($global:SpnCertificateThumbprint) {
        Write-Step ("Auth method: SPN + certificate (thumbprint='{0}')" -f $global:SpnCertificateThumbprint)
        if (-not $global:SpnClientId) { throw "`$global:SpnClientId is required for SPN + certificate auth." }
        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId `
            -ApplicationId $global:SpnClientId -CertificateThumbprint $global:SpnCertificateThumbprint `
            -WarningAction SilentlyContinue | Out-Null
        if ($haveMg) {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop -WarningAction SilentlyContinue
            Connect-MgGraph -TenantId $global:SpnTenantId -ClientId $global:SpnClientId `
                -CertificateThumbprint $global:SpnCertificateThumbprint -NoWelcome -WarningAction SilentlyContinue | Out-Null
        }
        $authMethodUsed = 'SPN-Certificate'
    }
    elseif ($global:SpnClientId -and $global:SpnClientSecret) {
        Write-Step "Auth method: SPN + plaintext secret  [TESTING ONLY]"
        Write-Warn2 "Plaintext SPN secret in LauncherConfig.ps1 is acceptable for labs but NOT recommended for production. Switch to Managed Identity, SPN + Key Vault, or SPN + certificate when you can (see LauncherConfig.sample.ps1)."
        $secretSecure = ConvertTo-SecureString $global:SpnClientSecret -AsPlainText -Force
        $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
        $authMethodUsed = 'SPN-PlaintextSecret'
    }
    else {
        throw @"
No authentication method configured in LauncherConfig.ps1.
Populate ONE of (see LauncherConfig.sample.ps1 for copy-pasteable blocks):
  1. `$global:UseManagedIdentity = `$true  (Managed Identity)
  2. `$global:SpnKeyVaultName + `$global:SpnSecretName + SpnClientId  (SPN + KV secret)
  3. `$global:SpnCertificateThumbprint + SpnClientId                  (SPN + cert)
  4. `$global:SpnClientSecret + SpnClientId                           (SPN + plaintext, testing only)
"@
    }
} catch {
    Write-Err2 "Authentication failed: $($_.Exception.Message)"
    throw
}

Write-Ok ("Authentication established ({0})" -f $authMethodUsed)

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

# ----- Resolve runtime values: CLI bound > in-script Override > Default -----
# A switch only counts as "set on the CLI" when explicitly bound. The defaults
# block at the top of this file is the single source of truth for baseline
# behaviour; the script-scope Override sentinels are the per-host knob;
# the CLI -Switch is the per-run knob.
#
# Inline (v1 pattern): $PSBoundParameters at script scope is the launcher's
# own bound params. Don't wrap in a function -- inside a function it would
# be the function's bound params instead.

# Snapshot caller-bound CLI params for use by helpers below.
$cliBound = @{}
foreach ($k in $PSBoundParameters.Keys) { $cliBound[$k] = $PSBoundParameters[$k] }

# Mode resolution (Summary / Detailed)
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

# Each switch (inline v1 pattern): CLI bound > Override > Default
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

# ResetCache: CLI bound > Override > Default
$global:ResetCache = $ResetCache_Default
if ($cliBound.ContainsKey('ResetCacheSwitch')) {
    $global:ResetCache = [bool]$cliBound['ResetCacheSwitch']
} elseif ($null -ne $ResetCache_Override) {
    $global:ResetCache = [bool]$ResetCache_Override
}

# Int (no Override slot exposed, just CLI > Default)
if ($cliBound.ContainsKey('AutoBucketMax')) {
    $global:AutoBucketMax = [int]$cliBound['AutoBucketMax']
} else {
    $global:AutoBucketMax = [int]$AutoBucketMax_Default
}

# ReportTemplate: -ReportTemplate wins, then $ReportTemplate_Default,
# then per-mode default by Summary/Detailed.
if ($cliBound.ContainsKey('ReportTemplate') -and -not [string]::IsNullOrWhiteSpace([string]$cliBound['ReportTemplate'])) {
    $global:ReportTemplate = [string]$cliBound['ReportTemplate']
} elseif (-not [string]::IsNullOrWhiteSpace($ReportTemplate_Default)) {
    $global:ReportTemplate = $ReportTemplate_Default
} elseif ($global:Detailed -and -not $global:Summary) {
    $global:ReportTemplate = $ReportTemplate_Default_Detailed
} else {
    # Default to Summary template (covers Summary=$true and the "neither set" fall-through)
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
    # Resolve engine path portably -- works in the monorepo, in a published
# community repo, and inside a bundled dependency under dependencies/<dep>/.
$launcherDir = $PSScriptRoot
$engineOwner = Split-Path -Parent (Split-Path -Parent $launcherDir)
$engine = $null
foreach ($case in 'SCRIPTS','scripts') {
    $candidate = Join-Path $engineOwner (Join-Path $case 'SecurityInsight_RiskAnalysis.ps1')
    if (Test-Path -LiteralPath $candidate) { $engine = $candidate; break }
}
if (-not $engine) { throw "Launcher: engine 'SecurityInsight_RiskAnalysis.ps1' not found at $engineOwner\SCRIPTS or $engineOwner\scripts. Expected the launcher to live at <solroot>\LAUNCHERS\<engine>\ with a sibling SCRIPTS\ or scripts\ folder." }
    if (-not (Test-Path -LiteralPath $engine)) { throw "engine script not found at $engine" }
    Write-Info "engine: $engine"
    & $engine
    Write-Ok "Engine completed successfully"
} catch {
    Write-Err2 "Engine failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    throw
}