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
    [switch]$DebugQueryHash,

    # v2.2.338 -- asset-simulation runner (see internal-vm launcher for details).
    [ValidateSet('FullSummary','ComplexSummary','FullDetailed','ComplexDetailed')]
    [string]$RunAssetSimulation,
    [int]$AssetSimulationAmount
)

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../engine/_shared/SI-AzRest.ps1') }
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
    Write-Host '  Support: https://github.com/KnudsenMorten/SecurityInsight/issues   (Pro: https://portal.invardia.com/ > Support)' -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}
function Write-Step   { param([string]$m) Write-Host "[STEP]  $m" -ForegroundColor Cyan }
function Write-Info   { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor White }
function Write-Ok     { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn2  { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err2   { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

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
    # Community-vm always lives at <install>\launcher\<engine>\launcher.community-vm.ps1.
    # 2-up from $PSScriptRoot IS the install root by file-layout convention -- no walk-up,
    # no marker-file requirement. Resolve-RepoRoot's walk-up looked for `scripts+launchers`
    # or `engine+launcher` pairs and returned empty on flat community installs missing
    # both pairs, causing Layer 3 (custom.ps1) to look at `\SOLUTIONS\...\config\...` and
    # silently miss the customer's actual `<install>\config\<solution>.custom.ps1`.
    if (-not $InstallPath) { $InstallPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
} catch {
    # Defer the error until after the banner so the user sees what they ran.
    $resolveError = $_
}
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath

Write-Banner -Solution 'SecurityInsight' -Engine 'RiskAnalysis' -Flavour 'community-vm' -Version $versionStamp

# v2.2.341 -- compute Template + Simulation labels BEFORE transcript start so
# the log filename carries them. See launcher.internal-vm.ps1 for full notes.
$_logSim = ''; $_logTpl = ''
if ($PSBoundParameters.ContainsKey('RunAssetSimulation') -and -not [string]::IsNullOrWhiteSpace([string]$RunAssetSimulation)) {
    $_logSim = $RunAssetSimulation
    $_logTpl = switch ($RunAssetSimulation) {
        'FullSummary'     { 'RiskAnalysis_Summary' }
        'FullDetailed'    { 'RiskAnalysis_Detailed' }
        'ComplexSummary'  { 'AssetSimulationComplexSummary' }
        'ComplexDetailed' { 'AssetSimulationComplexDetailed' }
    }
} elseif ($PSBoundParameters.ContainsKey('ReportTemplate') -and -not [string]::IsNullOrWhiteSpace($ReportTemplate)) {
    $_logTpl = $ReportTemplate
} elseif (-not [string]::IsNullOrWhiteSpace($ReportTemplate_Default)) {
    $_logTpl = $ReportTemplate_Default
} elseif ($Detailed -and -not $Summary) {
    $_logTpl = $ReportTemplate_Default_Detailed
} else {
    $_logTpl = $ReportTemplate_Default_Summary
}
$global:SI_TranscriptPath = Start-SILauncherTranscript -Engine 'risk-analysis' -Flavour 'community-vm' -RepoRoot $InstallPath -Template $_logTpl -Simulation $_logSim

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
if (-not [bool]$global:UseManagedIdentity -and (-not $global:SpnTenantId -or [string]::IsNullOrWhiteSpace([string]$global:SpnTenantId))) {   # #222: a managed identity knows its tenant
    throw @"
Launcher: `$global:SpnTenantId is required but not set.

Put your SPN / Managed Identity credentials in ONE of these files:
  * config\SecurityInsight.custom.ps1         (solution-wide -- recommended; covers every SI engine)
  * LAUNCHERS\<engine>\LauncherConfig.custom.ps1  (per-engine override; closest wins)

Copy the matching .sample.ps1 next to the target file and fill in your values.
See README section 3.5 for the layered-config model.
"@
}

# SecurityInsight needs no PowerShell module: the engine reaches Azure over plain REST (engine/_shared/SI-AzRest.ps1),
# and the sign-in below only records the identity (each call mints its own token).
# The Microsoft.Graph.Authentication probe and its Connect-MgGraph calls were removed. They existed
# so the engine would inherit a Graph session from the launcher; no engine needs one any more, because
# every Graph call acquires its own token via auth/Get-SIGraphToken.ps1 and uses the REST API. The
# calls were already optional, so removing them cannot break a host that has the module -- it stops
# the launcher auto-installing a module the product no longer uses.

$authMethodUsed = $null
try {
    if ([bool]$global:UseManagedIdentity) {
        # #222: the host's managed identity (Azure VM or Azure Arc server). A client id selects a USER-assigned one;
        # without it, the system-assigned identity.
        $miArgs = @{ WarningAction = 'SilentlyContinue' }
        if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_UAMI_ClientId)) { $miArgs['AccountId'] = [string]$global:SI_UAMI_ClientId }
        Write-Step ("Auth method: Managed Identity ({0})" -f $(if ($miArgs.ContainsKey('AccountId')) { 'user-assigned ' + $miArgs['AccountId'] } else { 'system-assigned' }))
        Connect-SIAzAccount -Identity @miArgs | Out-Null
        if (-not $global:SpnTenantId) { $global:SpnTenantId = [string](Get-SIAzContext).Tenant.Id }
        $authMethodUsed = 'ManagedIdentity'
    }
    elseif ($global:SpnKeyVaultName -and $global:SpnSecretName) {
        Write-Step ("Auth method: SPN + Key Vault  (kv='{0}', secret='{1}')" -f $global:SpnKeyVaultName, $global:SpnSecretName)
        if (-not $global:SpnClientId) { throw "`$global:SpnClientId is required for SPN + Key Vault auth." }
        Connect-SIAzAccount -Identity -WarningAction SilentlyContinue | Out-Null
        $secretSecure = (Get-SIAzKeyVaultSecret -VaultName $global:SpnKeyVaultName -Name $global:SpnSecretName -ErrorAction Stop).SecretValue
        if (-not $secretSecure) { throw "Key Vault returned no value for secret '$($global:SpnSecretName)' in '$($global:SpnKeyVaultName)'." }
        Disconnect-SIAzAccount -WarningAction SilentlyContinue | Out-Null
        $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
        Connect-SIAzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretSecure)
        try   { $global:SpnClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $authMethodUsed = 'SPN-KeyVault'
    }
    elseif ($global:SpnCertificateThumbprint) {
        Write-Step ("Auth method: SPN + certificate (thumbprint='{0}')" -f $global:SpnCertificateThumbprint)
        if (-not $global:SpnClientId) { throw "`$global:SpnClientId is required for SPN + certificate auth." }
        Connect-SIAzAccount -ServicePrincipal -Tenant $global:SpnTenantId `
            -ApplicationId $global:SpnClientId -CertificateThumbprint $global:SpnCertificateThumbprint `
            -WarningAction SilentlyContinue | Out-Null
        $authMethodUsed = 'SPN-Certificate'
    }
    elseif ($global:SpnClientId -and $global:SpnClientSecret) {
        Write-Step "Auth method: SPN + plaintext secret  [TESTING ONLY]"
        Write-Warn2 "Plaintext SPN secret in LauncherConfig.ps1 is acceptable for labs but NOT recommended for production. Switch to Managed Identity, SPN + Key Vault, or SPN + certificate when you can (see LauncherConfig.custom.sample.ps1)."
        $secretSecure = ConvertTo-SecureStringSafe -Plain $global:SpnClientSecret
        $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
        Connect-SIAzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
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
if ($PSBoundParameters.ContainsKey('WhatIfMode')) { $global:WhatIfMode = [bool]$WhatIfMode } elseif ($null -eq $global:WhatIfMode) { $global:WhatIfMode = $false }   # a switch you pass wins; otherwise the config value stands
if ($PSBoundParameters.ContainsKey('SuppressErrors')) { $global:SuppressErrors = [bool]$SuppressErrors } elseif ($null -eq $global:SuppressErrors) { $global:SuppressErrors = $false }   # a switch you pass wins; otherwise the config value stands
if ($PSBoundParameters.ContainsKey('SuppressWarnings')) { $global:SuppressWarnings = [bool]$SuppressWarnings } elseif ($null -eq $global:SuppressWarnings) { $global:SuppressWarnings = $false }   # a switch you pass wins; otherwise the config value stands

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

# ResetCache: CLI bound > Override > config layers > Default
if (-not (Test-Path variable:global:ResetCache)) { $global:ResetCache = $ResetCache_Default }
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
# #187: the names the config reference DOCUMENTS (RiskAnalysis_ReportTemplate_Default_*) were never read -- honour them, and let them win.
if ($global:RiskAnalysis_ReportTemplate_Default_Summary)  { $ReportTemplate_Default_Summary  = [string]$global:RiskAnalysis_ReportTemplate_Default_Summary }
if ($global:RiskAnalysis_ReportTemplate_Default_Detailed) { $ReportTemplate_Default_Detailed = [string]$global:RiskAnalysis_ReportTemplate_Default_Detailed }

# v2.2.338 -- -RunAssetSimulation routing. See launcher.internal-vm.ps1 for full notes.
if ($cliBound.ContainsKey('RunAssetSimulation') -and -not [string]::IsNullOrWhiteSpace([string]$cliBound['RunAssetSimulation'])) {
    $simMode = [string]$cliBound['RunAssetSimulation']
    $simAmount = if ($cliBound.ContainsKey('AssetSimulationAmount')) { [int]$cliBound['AssetSimulationAmount'] } else { 15000 }
    if ($simAmount -lt 1) { throw "-AssetSimulationAmount must be > 0 (got $simAmount)" }
    $global:SI_SimulateCLRowCount = $simAmount
    $simTemplate = switch ($simMode) {
        'FullSummary'     { 'RiskAnalysis_Summary' }
        'FullDetailed'    { 'RiskAnalysis_Detailed' }
        'ComplexSummary'  { 'AssetSimulationComplexSummary' }
        'ComplexDetailed' { 'AssetSimulationComplexDetailed' }
    }
    $global:ReportTemplate = $simTemplate
    Write-Info ("[LAUNCHER] RunAssetSimulation={0} AssetSimulationAmount={1} -> template={2} (SI_SimulateCLRowCount set)" -f $simMode, $simAmount, $simTemplate)
}
# ReportTemplate: -ReportTemplate wins, then $ReportTemplate_Default,
# then per-mode default by Summary/Detailed.
elseif ($cliBound.ContainsKey('ReportTemplate') -and -not [string]::IsNullOrWhiteSpace([string]$cliBound['ReportTemplate'])) {
    $global:ReportTemplate = [string]$cliBound['ReportTemplate']
} elseif (-not [string]::IsNullOrWhiteSpace($ReportTemplate_Default)) {
    $global:ReportTemplate = $ReportTemplate_Default
} elseif ($global:Detailed -and -not $global:Summary) {
    $global:ReportTemplate = $ReportTemplate_Default_Detailed
} else {
    # Default to Summary template (covers Summary=$true and the "neither set" fall-through)
    $global:ReportTemplate = $ReportTemplate_Default_Summary
}

# --- Reconcile the run mode with the resolved template (finding #39) ----------
# $global:Summary / $global:Detailed are not labels. The engine reads them to
# pick the mail lane, and -- far more expensively -- the Log Analytics TABLE and
# the DCR (Invoke-RiskAnalysis.ps1, "Pick the DCR + table for this run").
# Resolve-RunMode runs ABOVE, before the template is known, and never saw
# -ReportTemplate, so `-ReportTemplate RiskAnalysis_Detailed` fell through to the
# default mode and ingested Detailed rows into the Summary table. Confirmed in a
# live workspace 2026-08-07 (64 mis-routed snapshots since 2026-06-06). The
# template is the more specific statement of intent, so it wins over every
# config-level mode source; a contradicting explicit CLI switch throws rather
# than silently choosing a table.
function Get-SIRunModeForTemplate {
    param([string]$Template)
    if ([string]::IsNullOrWhiteSpace($Template)) { return $null }
    if ($Template -match '(?i)detailed') { return 'Detailed' }
    if ($Template -match '(?i)summary')  { return 'Summary'  }
    return $null   # unrecognised/custom template -- leave the resolved mode alone
}

$__tplMode = Get-SIRunModeForTemplate -Template $global:ReportTemplate
if ($null -ne $__tplMode) {
    $__cliS   = $cliBound.ContainsKey('Summary')  -and [bool]$cliBound['Summary']
    $__cliD   = $cliBound.ContainsKey('Detailed') -and [bool]$cliBound['Detailed']
    $__cliTpl = ($cliBound.ContainsKey('ReportTemplate')     -and -not [string]::IsNullOrWhiteSpace([string]$cliBound['ReportTemplate'])) -or `
                ($cliBound.ContainsKey('RunAssetSimulation') -and -not [string]::IsNullOrWhiteSpace([string]$cliBound['RunAssetSimulation']))
    if ($__cliTpl -and (($__cliS -and $__tplMode -eq 'Detailed') -or ($__cliD -and $__tplMode -eq 'Summary'))) {
        throw ("Contradictory parameters: template '{0}' is a {1} template, but -{2} was passed. The run mode selects the Log Analytics table and DCR, so this would ingest {1} rows into the {2} table. Pass one or the other." -f `
            $global:ReportTemplate, $__tplMode, $(if ($__cliS) { 'Summary' } else { 'Detailed' }))
    }
    $__wantSummary  = ($__tplMode -eq 'Summary')
    $__wantDetailed = ($__tplMode -eq 'Detailed')
    if ($global:Summary -ne $__wantSummary -or $global:Detailed -ne $__wantDetailed) {
        Write-Info ("[LAUNCHER] run mode reconciled to template '{0}': Summary {1}->{2}, Detailed {3}->{4} (mode selects the LA table + DCR + mail lane)" -f `
            $global:ReportTemplate, $global:Summary, $__wantSummary, $global:Detailed, $__wantDetailed)
        $global:Summary  = $__wantSummary
        $global:Detailed = $__wantDetailed
    }
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
    if ($global:SI_LastRunExitReason -eq 'success-partial') { Write-Host "[WARN]  Engine completed -- PARTIAL: not everything was published (the reason is above)" -ForegroundColor Yellow } else { Write-Ok "Engine completed successfully" }
} catch {
    Write-Err2 "Engine failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    throw
}

# flush + close the transcript started right after Write-Banner.
Stop-SILauncherTranscript
