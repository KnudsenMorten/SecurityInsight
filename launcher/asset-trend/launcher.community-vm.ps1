#Requires -Version 5.1
<#
.SYNOPSIS
    Community VM launcher for the SecurityInsight asset-trend engine.
    Invokes engine/asset-trend/Invoke-SITrend.ps1.

.DESCRIPTION
    The daily trend rollup: reads the Risk Analysis results already in your Log Analytics workspace,
    aggregates them, and publishes SI_Trend_CL -- a long, narrow table small enough to keep for years
    while the wide profile tables keep only about 30 days.

    Run it every day from the start. A trend line's value is its continuity, and Log Analytics cannot
    backfill a day that was never written.

    Reads credentials from the layered config (config\SecurityInsight.custom.ps1 and/or
    LauncherConfig.custom.ps1 in this folder, both gitignored). Supports 4 auth methods
    (Managed Identity, SPN + Key Vault secret, SPN + certificate, SPN + plaintext secret).

.NOTES
    Solution       : SecurityInsight
    File           : launcher.community-vm.ps1
    Engine         : asset-trend (Invoke-SITrend.ps1)
    Developed by   : Morten Knudsen, Microsoft MVP
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.

    SCHEDULING -- LAST in the chain, once per day:
      endpoint / identity / azure / publicip -> risk-analysis -> asset-trend
    It rolls up what Risk Analysis published. Run it before Risk Analysis and it stamps yesterday's
    numbers with today's date. Run it twice a day and the day gets two points.
#>
[CmdletBinding()]
param(
    # Generic launcher knobs
    [string]$InstallPath,
    [string]$LauncherConfigPath,
    [switch]$WhatIfMode,
    [switch]$SuppressErrors,
    [switch]$SuppressWarnings,

    # Engine knobs (passthrough to Invoke-SITrend)
    [switch]$DryRun,
    [ValidateSet('Summary','Detailed')][string]$Grain,
    [switch]$ShowWeeklyRate,
    [int]$Weeks = 0
)

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../engine/_shared/SI-AzRest.ps1') }
$ErrorActionPreference = 'Stop'

# Windows PS 5.1 + PS 7 coexistence: scrub PS7 module paths so a PS 5.1 host
# doesn't pick up PS 7 module variants that cause TypeData clashes.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    $env:PSModulePath = ($env:PSModulePath -split ';' |
                         Where-Object { $_ -and ($_ -notmatch '(?i)\\powershell\\7') }) -join ';'
}

function ConvertTo-SecureStringSafe {
    param([Parameter(Mandatory)][string]$Plain)
    $ss = New-Object System.Security.SecureString
    foreach ($c in $Plain.ToCharArray()) { $ss.AppendChar($c) }
    $ss.MakeReadOnly()
    return $ss
}

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
    $engineLabel = $Engine -replace '^SecurityInsight[_-]', ''
    Write-Host $line -ForegroundColor Cyan
    Write-Host ("  {0} -- {1}    [{2}]   {3}" -f $Solution, $engineLabel, $Flavour, $Version) -ForegroundColor Cyan
    if ($Description) { foreach ($chunk in ($Description -split '(?<=.{1,86})\s+')) { Write-Host ("  {0}" -f $chunk) -ForegroundColor White } }
    Write-Host '' -ForegroundColor Cyan
    Write-Host '  Developed by Morten Knudsen -- Microsoft MVP' -ForegroundColor Cyan
    Write-Host '  Blog:    https://mortenknudsen.net   (aka.ms/morten)' -ForegroundColor Cyan
    Write-Host '  GitHub:  https://github.com/KnudsenMorten' -ForegroundColor Cyan
    Write-Host '  Support: GitHub Issues on the public repo' -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}
function Write-Step  { param([string]$m) Write-Host "[STEP]  $m" -ForegroundColor Cyan }
function Write-Info  { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor White }
function Write-Ok    { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err2  { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

# Community-vm always lives at <install>\launcher\<engine>\launcher.community-vm.ps1, so 2-up from
# $PSScriptRoot IS the install root (same convention as every other community launcher).
if (-not $InstallPath) { $InstallPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath

Write-Banner -Solution 'SecurityInsight' -Engine 'Trend' -Flavour 'community-vm' -Version $versionStamp
$global:SI_TranscriptPath = Start-SILauncherTranscript -Engine 'asset-trend' -Flavour 'community-vm' -RepoRoot $InstallPath

Write-Step "Resolving repo root"
Write-Ok "repo root: $InstallPath"

try {
    . (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')
    Initialize-LauncherConfig `
        -Solution    'SecurityInsight' `
        -Engine      'Trend' `
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
  * config\SecurityInsight.custom.ps1              (solution-wide -- recommended; covers every SI engine)
  * launcher\asset-trend\LauncherConfig.custom.ps1  (per-engine override; closest wins)

Copy the matching .sample.ps1 next to the target file and fill in your values.
"@
}

# SecurityInsight needs no PowerShell module: the engine reaches Azure over plain REST (engine/_shared/SI-AzRest.ps1),
# and the sign-in below only records the identity (each call mints its own token).

# The engine reads the Risk Analysis results with the run's sign-in (over REST), and publishes with
# the SI_SPN_* identity -- so every method below signs in AND leaves SI_SPN_* set.
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
        Write-Warn2 "A plaintext SPN secret in a config file is acceptable for labs but NOT recommended for production. Switch to Managed Identity or SPN + Key Vault when you can."
        $secretSecure = ConvertTo-SecureStringSafe -Plain $global:SpnClientSecret
        $cred = [pscredential]::new($global:SpnClientId, $secretSecure)
        Connect-SIAzAccount -ServicePrincipal -Tenant $global:SpnTenantId -Credential $cred -WarningAction SilentlyContinue | Out-Null
        $authMethodUsed = 'SPN-PlaintextSecret'
    }
    else {
        throw @"
No authentication method configured.
Populate ONE of (see LauncherConfig.custom.sample.ps1 for copy-pasteable blocks):
  1. `$global:UseManagedIdentity = `$true  (Managed Identity)
  2. `$global:SpnKeyVaultName + `$global:SpnSecretName + SpnClientId  (SPN + KV secret)
  3. `$global:SpnCertificateThumbprint + SpnClientId                  (SPN + certificate)
  4. `$global:SpnClientSecret + SpnClientId                           (SPN + plaintext, testing only)
"@
    }
} catch {
    Write-Err2 "Authentication failed: $($_.Exception.Message)"
    throw
}
Write-Ok ("Authentication established ({0})" -f $authMethodUsed)

# The engine publishes with SI_SPN_*; a community config carries Spn*. Bridge the names it does not
# already have -- the same bridge the profiling engines apply in Invoke-SIEngineRun.ps1.
if (-not $global:SI_SPN_TenantId       -and $global:SpnTenantId)              { $global:SI_SPN_TenantId       = [string]$global:SpnTenantId }
if (-not $global:SI_SPN_AppId          -and $global:SpnClientId)              { $global:SI_SPN_AppId          = [string]$global:SpnClientId }
if (-not $global:SI_SPN_Secret         -and $global:SpnClientSecret)          { $global:SI_SPN_Secret         = [string]$global:SpnClientSecret }
if (-not $global:SI_SPN_CertThumbprint -and $global:SpnCertificateThumbprint) { $global:SI_SPN_CertThumbprint = [string]$global:SpnCertificateThumbprint }
if (-not $global:SI_SPN_ObjectId       -and $global:SpnObjectId)              { $global:SI_SPN_ObjectId       = [string]$global:SpnObjectId }

Write-Step "Setting engine globals"
$global:AutomationFramework = $false
if ($PSBoundParameters.ContainsKey('WhatIfMode')) { $global:WhatIfMode = [bool]$WhatIfMode } elseif ($null -eq $global:WhatIfMode) { $global:WhatIfMode = $false }   # a switch you pass wins; otherwise the config value stands
if ($PSBoundParameters.ContainsKey('SuppressErrors')) { $global:SuppressErrors = [bool]$SuppressErrors } elseif ($null -eq $global:SuppressErrors) { $global:SuppressErrors = $false }   # a switch you pass wins; otherwise the config value stands
if ($PSBoundParameters.ContainsKey('SuppressWarnings')) { $global:SuppressWarnings = [bool]$SuppressWarnings } elseif ($null -eq $global:SuppressWarnings) { $global:SuppressWarnings = $false }   # a switch you pass wins; otherwise the config value stands

$effectiveDryRun = $false
if ($PSBoundParameters.ContainsKey('DryRun')) { $effectiveDryRun = [bool]$DryRun }
elseif ($null -ne $global:SI_Trend_DryRun) { $effectiveDryRun = [bool]$global:SI_Trend_DryRun }

$effectiveGrain = 'Summary'
if ($PSBoundParameters.ContainsKey('Grain')) { $effectiveGrain = $Grain }
elseif (-not [string]::IsNullOrWhiteSpace([string]$global:SI_Trend_Grain)) {
    $g = ([string]$global:SI_Trend_Grain).Trim()
    if ($g -in @('Summary','Detailed')) { $effectiveGrain = $g }
    else { Write-Warn2 ("`$global:SI_Trend_Grain = '{0}' is not Summary or Detailed -- using Summary." -f $global:SI_Trend_Grain) }
}

$effectiveWeeks = 12
if ($PSBoundParameters.ContainsKey('Weeks') -and $Weeks -gt 0) { $effectiveWeeks = [int]$Weeks }
elseif ($global:SI_Trend_Weeks -gt 0) { $effectiveWeeks = [int]$global:SI_Trend_Weeks }

Write-Info ("[LAUNCHER] AutomationFramework={0} Auth={1} DryRun={2} Grain={3} WeeklyRate={4} Weeks={5}" -f `
    $global:AutomationFramework, $authMethodUsed, $effectiveDryRun, $effectiveGrain, [bool]$ShowWeeklyRate, $effectiveWeeks)

$cliPassthrough = @{ Grain = $effectiveGrain }
if ($effectiveDryRun) { $cliPassthrough['DryRun']         = $true }
if ($ShowWeeklyRate)  { $cliPassthrough['ShowWeeklyRate'] = $true; $cliPassthrough['Weeks'] = $effectiveWeeks }

try {
    Write-Step "Invoking engine"
    $engine = Join-Path $InstallPath 'engine\asset-trend\Invoke-SITrend.ps1'
    if (-not (Test-Path -LiteralPath $engine)) {
        throw "Launcher: engine 'Invoke-SITrend.ps1' not found at $engine."
    }
    Write-Info "engine: $engine"
    & $engine @cliPassthrough
    Write-Ok "Engine completed successfully"
} catch {
    Write-Err2 "Engine failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    throw
}

Stop-SILauncherTranscript
