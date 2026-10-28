#Requires -Version 5.1
<#
.SYNOPSIS
    Community VM launcher for the SecurityInsight asset-tagging engine.
    Invokes engine/asset-tagging/AssetTagging.ps1.

.DESCRIPTION
    Writes a criticality tag onto Azure resources (and the matching Entra/Defender objects) according to
    the asset-tagging rules (AssetTagging.locked.yaml, plus your AssetTagging.custom.yaml).

    🔑 REPORT ONLY BY DEFAULT. This is the one SecurityInsight engine that CAN write; every other engine only reads.
    Without -Apply a run logs every tag the rules would set and changes nothing. It writes only when you ask:
      -Apply on the run, or $global:SI_AssetTagging_Apply = $true in config\SecurityInsight.custom.ps1 (every run).
    -WhatIfMode is kept for compatibility: it asks for report only (the default) and wins over -Apply. Writing needs the
    write grants (setup\Grant-SIIdentity.ps1 -Tagging, or the Tag Contributor role setup grants only when asked).
    Up to 3.0 a run without -WhatIfMode WROTE tags: an install that ran it before is told once, on its first run after the
    update, that it is now report only and how to switch writing back on.

    Reads credentials from the layered config (config\SecurityInsight.custom.ps1 and/or
    LauncherConfig.custom.ps1 in this folder, both gitignored). The engine signs in to Azure, Microsoft Graph and
    Defender for Endpoint itself: as the host's MANAGED IDENTITY when the sign-in decision chose it
    ($global:SI_AuthMethod = 'ManagedIdentity'; give tagging its own identity with setup\Grant-SIIdentity.ps1 -Tagging),
    otherwise as the SPN, by certificate or secret; an SPN secret held in Key Vault is resolved here.

.NOTES
    Solution       : SecurityInsight
    File           : launcher.community-vm.ps1
    Engine         : asset-tagging (engine/asset-tagging/AssetTagging.ps1)
    Developed by   : Morten Knudsen, Microsoft MVP
    Blog           : https://mortenknudsen.net  (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : For public repos, open a GitHub Issue on that solution's repo.
#>
[CmdletBinding()]
param(
    [string]$InstallPath,
    [string]$LauncherConfigPath,
    # Write the tags. Without it (and without SI_AssetTagging_Apply) the run only reports what it would write.
    [switch]$Apply,
    # Report only -- the default now; kept so existing scheduled tasks and scripts keep working. Wins over -Apply.
    [switch]$WhatIfMode,
    [switch]$SuppressErrors,
    [switch]$SuppressWarnings,
    [string[]]$Scope,
    [string]$SettingsPath
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

. (Join-Path $PSScriptRoot '..\_lib\Get-PublishedVersion.ps1')
. (Join-Path $PSScriptRoot '..\_lib\Start-LauncherTranscript.ps1')

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
    Write-Host '  Support: GitHub Issues on the public repo' -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ''
}
function Write-Step  { param([string]$m) Write-Host "[STEP]  $m" -ForegroundColor Cyan }
function Write-Info  { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor White }
function Write-Ok    { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn2 { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err2  { param([string]$m) Write-Host "[ERROR] $m" -ForegroundColor Red }

# Community-vm always lives at <install>\launcher\<engine>\launcher.community-vm.ps1.
if (-not $InstallPath) { $InstallPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
$versionStamp = Get-PublishedVersion -RepoRoot $InstallPath

Write-Banner -Solution 'SecurityInsight' -Engine 'AssetTagging' -Flavour 'community-vm' -Version $versionStamp
$global:SI_TranscriptPath = Start-SILauncherTranscript -Engine 'asset-tagging' -Flavour 'community-vm' -RepoRoot $InstallPath

try {
    . (Join-Path $PSScriptRoot '..\_lib\Initialize-LauncherConfig.ps1')
    Initialize-LauncherConfig -Solution 'SecurityInsight' -Engine 'AssetTagging' -LauncherDir $PSScriptRoot `
        -RepoRoot $InstallPath -Mode 'community' -CustomConfigPath $LauncherConfigPath
} catch {
    Write-Err2 "Failed to load layered config: $($_.Exception.Message)"
    throw
}

Write-Step "Resolving authentication"
# #236: the MANAGED IDENTITY (the sign-in decision of auth\SI-AuthMethod.ps1, applied by Initialize-LauncherConfig):
# the host's identity -- an Azure VM's or an Azure Arc server's, system-assigned, or the user-assigned one named by
# SI_ManagedIdentityClientId. The engine takes its Graph, Defender and Azure tokens from it. Give tagging its OWN
# identity (setup\Grant-SIIdentity.ps1 -Tagging) -- never the read-only collection identity.
# The switch is set ONLY by that one decision (Set-SIAuthMethodGlobals); this launcher reads it.
$useMi = [bool]$global:SI_UseManagedIdentity
if ($useMi) {
    if (-not (Get-Command -Name Get-SIManagedIdentityToken -ErrorAction SilentlyContinue)) { . (Join-Path $InstallPath 'auth\SI-ManagedIdentity.ps1') }
    Write-Ok ("managed identity ({0}) -- the engine signs in itself" -f $(if ($global:SI_UAMI_ClientId) { "client id $($global:SI_UAMI_ClientId)" } else { 'system-assigned' }))
}
# The SPN path -- certificate or secret, unchanged.
else {
if (-not $global:SpnTenantId -or -not $global:SpnClientId) {
    throw 'Launcher: $global:SpnTenantId and $global:SpnClientId are required (or sign in as a managed identity: $global:SI_AuthMethod = ''ManagedIdentity''). Put them in config\SecurityInsight.custom.ps1 (see the .sample.ps1 next to it).'
}
if ($global:SpnKeyVaultName -and $global:SpnSecretName -and -not $global:SpnClientSecret -and -not $global:SpnCertificateThumbprint) {
    Write-Step ("Auth: SPN secret from Key Vault (kv='{0}', secret='{1}')" -f $global:SpnKeyVaultName, $global:SpnSecretName)
    Connect-SIAzAccount -Identity -WarningAction SilentlyContinue | Out-Null
    $secretSecure = (Get-SIAzKeyVaultSecret -VaultName $global:SpnKeyVaultName -Name $global:SpnSecretName -ErrorAction Stop).SecretValue
    if (-not $secretSecure) { throw "Key Vault returned no value for '$($global:SpnSecretName)' in '$($global:SpnKeyVaultName)'." }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretSecure)
    try   { $global:SpnClientSecret = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    Disconnect-SIAzAccount -WarningAction SilentlyContinue | Out-Null
}
if (-not $global:SpnCertificateThumbprint -and -not $global:SpnClientSecret) {
    throw 'Launcher: no SPN credential -- set $global:SpnCertificateThumbprint (recommended) or an SPN secret (SpnKeyVaultName + SpnSecretName, or SpnClientSecret for testing).'
}
Write-Ok ("SPN {0} ({1}) -- the engine signs in itself" -f $global:SpnClientId, $(if ($global:SpnCertificateThumbprint) { 'certificate' } else { 'secret' }))
}

Write-Step "Setting engine globals"
$global:AutomationFramework = $false
# REPORT ONLY BY DEFAULT (operator 2026-10-07). The run writes tags only when asked: -Apply on this run, or
# $global:SI_AssetTagging_Apply = $true in the configuration. -WhatIfMode is kept (it is the default now, and it wins over
# -Apply); a WhatIfMode = $true in the configuration still means report only. One decision: Resolve-SIAssetTaggingRunMode.
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\asset-tagging\AssetTagging.Resolve.ps1')
if ($Apply -and $WhatIfMode) { Write-Warn2 '-Apply and -WhatIfMode were both given: -WhatIfMode wins, nothing is changed.' }
$tagMode = Resolve-SIAssetTaggingRunMode -ApplySwitch ($PSBoundParameters.ContainsKey('Apply') -and [bool]$Apply) `
    -WhatIfSwitch ($PSBoundParameters.ContainsKey('WhatIfMode') -and [bool]$WhatIfMode) `
    -ApplySetting $global:SI_AssetTagging_Apply -ConfigWhatIf $global:WhatIfMode -EnabledSetting $global:SI_AssetTagging_Enabled
$global:WhatIfMode = [bool]$tagMode.WhatIfMode
if ($PSBoundParameters.ContainsKey('SuppressErrors')) { $global:SuppressErrors = [bool]$SuppressErrors } elseif ($null -eq $global:SuppressErrors) { $global:SuppressErrors = $false }   # a switch you pass wins; otherwise the config value stands
if ($PSBoundParameters.ContainsKey('SuppressWarnings')) { $global:SuppressWarnings = [bool]$SuppressWarnings } elseif ($null -eq $global:SuppressWarnings) { $global:SuppressWarnings = $false }   # a switch you pass wins; otherwise the config value stands

# Scope: CLI > $global:Scope > 'PROD'
if ($Scope) { $global:Scope = $Scope } elseif (-not $global:Scope -or @($global:Scope).Count -eq 0) { $global:Scope = @('PROD') }

# Rules folder: CLI > $global:SettingsPath > the shipped rules next to the endpoint enrichment.
# (Shared with the engine and the Pro importer: engine\asset-tagging\AssetTagging.Resolve.ps1, loaded above.)
$global:SettingsPath = Resolve-SIAssetTaggingSettingsPath -Cli $SettingsPath -Configured ([string]$global:SettingsPath) -SIRoot $InstallPath -Flavour community
if (-not $global:CustomYamlFile) { $global:CustomYamlFile = 'AssetTagging.custom.yaml' }
if (-not $global:LockedYamlFile) { $global:LockedYamlFile = 'AssetTagging.locked.yaml' }

Write-Info ("[LAUNCHER] AutomationFramework={0} Scope={1} WhatIf={2}" -f $global:AutomationFramework, ($global:Scope -join ','), $global:WhatIfMode)
Write-Info ("[LAUNCHER] SettingsPath={0}  Locked={1}  Custom={2}" -f $global:SettingsPath, $global:LockedYamlFile, $global:CustomYamlFile)
if ($tagMode.Apply) { Write-Warn2 (Get-SIAssetTaggingRunModeLine -Mode $tagMode) } else { Write-Info (Get-SIAssetTaggingRunModeLine -Mode $tagMode) }
# An install that wrote tags before is told ONCE that tagging is now report only, and how to switch writing back on.
$tagLogDir = if ($global:SI_LauncherLogRoot) { [string]$global:SI_LauncherLogRoot } elseif ($global:SI_TranscriptPath) { Split-Path -Parent ([string]$global:SI_TranscriptPath) } else { '' }
if ($tagLogDir) {
    $tagRunStart = try { [System.Diagnostics.Process]::GetCurrentProcess().StartTime } catch { Get-Date }
    $null = Invoke-SIAssetTaggingReportOnlyNotice -Mode $tagMode -Store @{ Kind = 'file'; Path = (Join-Path $tagLogDir 'state\install-state.json') } `
        -RanBefore { Test-SIAssetTaggingRanBefore -LogDir $tagLogDir -Before $tagRunStart -ExcludePath ([string]$global:SI_TranscriptPath) }
}

try {
    Write-Step "Invoking engine"
    $engine = Join-Path $InstallPath 'engine\asset-tagging\AssetTagging.ps1'
    if (-not (Test-Path -LiteralPath $engine)) { throw "Launcher: engine 'AssetTagging.ps1' not found at $engine." }
    Write-Info "engine: $engine"
    & $engine -RunMode $(if ($tagMode.Apply) { 'write' } else { 'report' })   # the mode decided above; the engine does not re-decide it
    Write-Ok "Engine completed successfully"
} catch {
    Write-Err2 "Engine failed: $($_.Exception.Message)"
    Write-Err2 $_.ScriptStackTrace
    throw
}

Stop-SILauncherTranscript
