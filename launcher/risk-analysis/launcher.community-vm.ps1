#Requires -Version 5.1
<#
.SYNOPSIS
    Community VM launcher for SecurityInsight\SecurityInsight_RiskAnalysis.
.DESCRIPTION
    Runs the SecurityInsight_RiskAnalysis engine on a Windows box in the customer's own tenant.
    Reads credentials from LauncherConfig.custom.ps1 (.gitignore'd). Supports 4 auth
    methods (MI, SPN+KV, SPN+cert, SPN+plaintext). See LauncherConfig.custom.sample.ps1.

.NOTES
    Solution       : SecurityInsight
    File           : launcher.community-vm.template.ps1
    Developed by   : Morten Knudsen, Microsoft MVP
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
    [ValidateRange(1,131072)][int]$AutoBucketMax,
    [Alias('ResetCache')][switch]$ResetCacheSwitch,

    # Other engine knobs
    [switch]$ShowConfig,
    [switch]$DebugQueryHash
)
$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------
# Windows PS 5.1 + PS 7 coexistence: scrub PS7 module paths from
# PSModulePath so Microsoft.PowerShell.Security loads cleanly. PS7's
# v7.x copy of that module otherwise wins on lookup but its TypeData
# clashes with the v5.1 host -> ConvertTo-SecureString refuses to load.
# ----------------------------------------------------------------------
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $env:PSModulePath = ($env:PSModulePath -split ';' |
                         Where-Object { $_ -and ($_ -notmatch '(?i)\\powershell\\7') }) -join ';'
}

# ----------------------------------------------------------------------
# ConvertTo-SecureStringSafe: SecureString built via constructor instead
# of ConvertTo-SecureString. Avoids autoload failures when Microsoft.
# PowerShell.Security's TypeData is left in a half-loaded state on this
# host (observed on Windows hosts with PS7 ETD pollution).
# ----------------------------------------------------------------------
function ConvertTo-SecureStringSafe {
    param([Parameter(Mandatory)][string]$Plain)
    $ss = New-Object System.Security.SecureString
    foreach ($c in $Plain.ToCharArray()) { $ss.AppendChar($c) }
    $ss.MakeReadOnly()
    return $ss
}

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
$ReportTemplate_Default_Summary  = 'RiskAnalysis_Summary'
$ReportTemplate_Default_Detailed = 'RiskAnalysis_Detailed'

# Adaptive bucketing baseline (engine reads these globals).
$AutoBucketCount_Default = $true
$AutoBucketCache_Default = $true
$AutoBucketMax_Default   = 131072

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
    # banner reads "SecurityInsight -- RiskAnalysis" instead of the noisy
    # "SecurityInsight -- SecurityInsight_RiskAnalysis". 2026-05-02.
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
function Write-Step   { param([string]$m) Write-Host "[STEP]  $m" -ForegroundColor Cyan }
function Write-Info   { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor White }
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
    if ($mod) { return $true }  # silent-on-success; engine's Ensure-SecurityInsightModules logs the canonical [MODULE] X v... present line
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
            # v2.2 dev tree: engine/ + launcher/ siblings (uncopied/unpublished). Lets customers run preview directly without going through the publish step (engine->scripts rename).
            elseif (($dirs -ccontains 'engine') -and ($dirs -ccontains 'launcher')) { $communityMatch = $cur }
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

Write-Banner -Solution 'SecurityInsight' -Engine 'RiskAnalysis' -Flavour 'community-vm' -Version $versionStamp
$global:SI_TranscriptPath = Start-SILauncherTranscript -Engine 'risk-analysis' -Flavour 'community-vm' -RepoRoot $InstallPath

if ($resolveError) {
    Write-Err2 $resolveError.Exception.Message
    throw $resolveError
}
Write-Step "Resolving repo root"
Write-Ok "repo root: $InstallPath"

try {
    # Layered config: defaults (ours) -> platform (internal only) ->
    # solution-wide custom -> per-engine custom -> CLI args.
    . (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')
    Initialize-LauncherConfig `
        -Solution    'SecurityInsight' `
        -Engine      'RiskAnalysis' `
        -LauncherDir $PSScriptRoot `
        -RepoRoot    $InstallPath `
        -Mode        'community' `
        -CustomConfigPath $LauncherConfigPath
} catch {
    Write-Err2 "Failed to load layered config: $($_.Exception.Message)"
    throw
}

Write-Step "Resolving authentication"
if (-not $global:SpnTenantId -or [string]::IsNullOrWhiteSpace([string]$global:SpnTenantId)) {
    throw @"
Launcher: `$global:SpnTenantId is required but not set.

Put your SPN / Managed Identity credentials in ONE of these files:
  * config\SecurityInsight.custom.ps1         (solution-wide -- recommended; covers every SI engine)
  * LAUNCHERS\<engine>\LauncherConfig.custom.ps1  (per-engine override; closest wins)

Copy the matching .sample.ps1 next to the target file and fill in your values.
See README section 3.5 for the layered-config model.
"@
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
            $credForGraph = [pscredential]::new($global:SpnClientId, (ConvertTo-SecureStringSafe -Plain $global:SpnClientSecret))
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
        Write-Warn2 "Plaintext SPN secret in LauncherConfig.ps1 is acceptable for labs but NOT recommended for production. Switch to Managed Identity, SPN + Key Vault, or SPN + certificate when you can (see LauncherConfig.custom.sample.ps1)."
        $secretSecure = ConvertTo-SecureStringSafe -Plain $global:SpnClientSecret
        $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
        Connect-AzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
        $authMethodUsed = 'SPN-PlaintextSecret'
    }
    else {
        throw @"
No authentication method configured in LauncherConfig.custom.ps1.
Populate ONE of (see LauncherConfig.custom.sample.ps1 for copy-pasteable blocks):
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
# launcher lives at <SI>/launcher/risk-analysis/. SettingsPath (consolidated
# YAML + risk-index + riskscore_weighted) lives at sibling <SI>/risk-analysis-detection/.
# 2-up from $PSScriptRoot = SI install root.
$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$settingsResolved = $null
foreach ($candidate in @(
    (Join-Path $siRoot 'risk-analysis-detection'),
    (Join-Path $siRoot  'DATA'),
    (Join-Path $siRoot  'data')
)) {
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

# Int (no Override slot exposed, just CLI > Default)
# Layered: CLI > existing layered global (Layer 4 / Layer 5) > template fallback default.
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
    # launcher lives at v2.2/launcher/risk-analysis/. Engine lives
    # at v2.2/engine/risk-analysis/Invoke-RiskAnalysis.ps1 (per # self-contained tree). 2-up from launcher = v2.2 root.
    # Legacy fallback walks up to SOLUTIONS/<solution>/SCRIPTS/ for unmigrated repos.
    $launcherDir = $PSScriptRoot
    $siRootForEngine = Split-Path -Parent (Split-Path -Parent $launcherDir)
    $engine = Join-Path $siRootForEngine 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    if (-not (Test-Path -LiteralPath $engine)) {
        $engineOwner = Split-Path -Parent $siRootForEngine   # SOLUTIONS/SecurityInsight/
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
