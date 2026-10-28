#Requires -Version 5.1
<#
.SYNOPSIS
    Unattended Setup for SecurityInsight v2.2 -- no browser, no GUI, no operator interaction.

.DESCRIPTION
    Standalone alternative to setup\ConfigWizard\Start-SetupWizard.ps1 (the
    HTML wizard). Reads setup-unattended.json + CLI overrides, picks a
    flavour (Community), then drives the same backend cmdlets
    the HTML wizard uses (New-SISpn / Initialize-SIInfra /
    Write-SICustomConfig / Set-SIEntraDiagnosticSetting /
    Initialize-SIContainerInfra) in sequence.

    One flavour (#524: the Internal flavour -- the AutomateIT platform module's
    sign-in and its platform globals -- is retired and refused):

      Community -- standalone install (no v1 platform layer). Signs in as a
                   MANAGED IDENTITY by default (Auth_Community.CredKind null):
                   the Container Apps jobs' identity; on an Azure VM a
                   user-assigned identity, created, attached to the VM and
                   granted; outside Azure (no managed identity possible) a new
                   SI SPN with a cert in LocalCertStore. CredKind Cert / Secret
                   still creates an SPN (cert or client secret). Renders
                   the INLINE custom.ps1 (resolved values written directly).
                   Signs the operator in (browser, or automatically in Azure
                   Cloud Shell) -- or, for CI, an app from SI_SPN_AppId +
                   SI_SPN_Secret / SI_SPN_CertThumbprint in the environment.
                   No PowerShell modules: Azure and Microsoft Graph over REST
                   with that one sign-in.

    Idempotent. Re-run whenever you want; backend cmdlets short-circuit on
    "already in place" / "already granted".

.PARAMETER ConfigPath
    Path to setup-unattended.json. Default: <repo>\config\setup-unattended.json,
    falling back to <repo>\config\setup-unattended.sample.json if the customer
    file doesn't exist.

.PARAMETER Flavour
    Override the JSON's Flavour: 'Community' (the default). 'Internal' is retired and refused (#524).

.PARAMETER TenantId
    Override Sub.TenantId.

.PARAMETER SubscriptionId
    Override Sub.SubscriptionId.

.PARAMETER Location
    Override Sub.Location.

.PARAMETER NamingSuffix
    Override Resources.NamingSuffix.

.PARAMETER Ring
    Override Naming.Ring: prod (default, one production install) or r0 / r1 / r2.

.PARAMETER Edition
    Override Naming.Edition: community or pro. Default: pro when Licence.Path is set, else community.

.PARAMETER Owner
    Override Naming.Owner: the 'owner' tag on the resource group setup creates. Default empty.

    DEFAULT NAMES. A resource name left null in the config gets <type>-si-<ring>-<edition>-<hosting>:
    rg-si-prod-community-vm, log-si-..., dce-si-..., stsiprodcommunityvm01 and, with Container.Enabled,
    hosting 'ca' plus acrsi...ca01, cae-si-...-ca and the jobs' identity id-si-...-ca. The app registration
    is 'SecurityInsight (prod-community-vm)'. Names you set in the config are used as they are.

.PARAMETER EntraDiag_Enabled
    Force EntraDiag.Enabled = $true (overrides JSON).

.PARAMETER Container_Enabled
    Force Container.Enabled = $true (overrides JSON).

.PARAMETER SkipPhase1
    Skip the SPN phase entirely (use when an admin pre-granted Graph perms
    out-of-band). Phase 2-5 still run.

.OUTPUTS
    Exit code: 0 = all enabled phases completed; non-zero on first failure.
    Per-phase status streams to Write-Host with [STEP]/[OK]/[WARN]/[ERR] markers.

.EXAMPLE
    # Reads setup-unattended.json and signs you in (browser, or Azure Cloud Shell).
    .\Setup-SecurityInsight-Unattended.ps1

.EXAMPLE
    # One-off override for a Sentinel customer who NOW wants Entra Diag too:
    .\Setup-SecurityInsight-Unattended.ps1 -EntraDiag_Enabled

.EXAMPLE
    # Community install with a custom config path:
    .\Setup-SecurityInsight-Unattended.ps1 -ConfigPath D:\customers\acme.json -Flavour Community

.EXAMPLE
    # Community install -- non-interactive variant. With an app in the environment
    # (any SPN with sufficient privilege), the Community block signs in as that app
    # instead of opening a browser; Microsoft Graph uses the same sign-in. Lets
    # unattended Community deploys run from a SYSTEM scheduled task or CI agent.
    $env:SI_SPN_AppId = '<app id>'; $env:SI_SPN_Secret = '<secret>'   # or SI_SPN_CertThumbprint
    .\Setup-SecurityInsight-Unattended.ps1 -Flavour Community -Container_Enabled

.NOTES
    Status: v2.2.151 -- new in this release.
    Developed by Morten Knudsen, Microsoft MVP | https://mortenknudsen.net
#>
[CmdletBinding()]
param(
    [Parameter()] [string]$ConfigPath,
    [Parameter()] [ValidateSet('Internal','Community')] [string]$Flavour,
    [Parameter()] [string]$TenantId,
    [Parameter()] [string]$SubscriptionId,
    [Parameter()] [string]$Location,
    [Parameter()] [string]$NamingSuffix,
    [Parameter()] [ValidateSet('r0','r1','r2','prod')] [string]$Ring,
    [Parameter()] [ValidateSet('community','pro')] [string]$Edition,
    [Parameter()] [string]$Owner,
    [Parameter()] [switch]$EntraDiag_Enabled,
    [Parameter()] [switch]$Container_Enabled,
    [Parameter()] [switch]$SkipPhase1,
    # Default = REFUSE to overwrite an existing config/SecurityInsight.custom.ps1.
    # Pre-v2.2.310 silently backed up + overwrote, which in practice wiped a live
    # internal-VM config when an operator ran a sicont/container-flavour bootstrap
    # from the same repo checkout. Pass -ForceConfigOverwrite to opt into the old
    # rewrite-with-backup behaviour (re-onboarding, tenant migration, etc.).
    [Parameter()] [switch]$ForceConfigOverwrite
)

# SI #547 / framework section 12.7: "<Script> version <v> - documentation: <link>" first, and a transcript of the run
. ([IO.Path]::Combine($PSScriptRoot, 'setup', '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Setup-SecurityInsight-Unattended'
try {
$ErrorActionPreference = 'Stop'

# ----------- Logging helpers (mirror the wizard's style) -----------
function _Banner([string]$msg) { Write-Host ""; Write-Host ("=== {0} ===" -f $msg) -ForegroundColor Cyan }
function _Step  ([string]$msg) { Write-Host ("  [STEP] {0}" -f $msg) -ForegroundColor Cyan }
function _Ok    ([string]$msg) { Write-Host ("  [OK]   {0}" -f $msg) -ForegroundColor Green }
function _Info  ([string]$msg) { Write-Host ("  [INFO] {0}" -f $msg) -ForegroundColor Gray }
function _Warn  ([string]$msg) { Write-Host ("  [WARN] {0}" -f $msg) -ForegroundColor Yellow }
function _Err   ([string]$msg) { Write-Host ("  [ERR]  {0}" -f $msg) -ForegroundColor Red }

# ----------- Defensive: New-Guid shim for constrained runspaces ------------
# In constrained PS 5.1 runspaces (-NoProfile, SYSTEM scheduled tasks, certain hosts) New-Guid may not be
# visible; a global shim against [System.Guid]::NewGuid() is harmless when the real one is loaded.
if (-not (Get-Command New-Guid -ErrorAction SilentlyContinue)) {
    function global:New-Guid { [System.Guid]::NewGuid() }
}

# ----------- Resolve repo root + paths -----------
$repoRoot   = $PSScriptRoot

# Azure and Microsoft Graph with NO PowerShell modules (#305): native REST, ARM and .NET. The backend scripts
# below share this process's one sign-in (Connect-SISetupAzure).
. (Join-Path $repoRoot 'setup\_shared\SI-SetupAzure.ps1')
. (Join-Path $repoRoot 'setup\_shared\SI-GraphRest.ps1')
$backendDir = Join-Path $repoRoot 'setup\ConfigWizard\backend'

$cmdletNewSISpn      = Join-Path $backendDir 'New-SISpn.ps1'
$cmdletInitInfra     = Join-Path $backendDir 'Initialize-SIInfra.ps1'
$cmdletWriteConfig   = Join-Path $backendDir 'Write-SICustomConfig.ps1'
$cmdletEntraDiag     = Join-Path $backendDir 'Set-SIEntraDiagnosticSetting.ps1'
$cmdletContainer     = Join-Path $backendDir 'Initialize-SIContainerInfra.ps1'
foreach ($c in $cmdletNewSISpn, $cmdletInitInfra, $cmdletWriteConfig, $cmdletEntraDiag, $cmdletContainer) {
    if (-not (Test-Path -LiteralPath $c)) { throw "backend cmdlet missing: $c" }
}

# Load VERSION for the banner
$siVersion = 'unknown'
$verFile   = Join-Path $repoRoot 'VERSION'
if (Test-Path -LiteralPath $verFile) { $siVersion = (Get-Content -LiteralPath $verFile -Raw).Trim() }

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " SecurityInsight Setup -- UNATTENDED MODE" -ForegroundColor Cyan
Write-Host (" v{0}" -f $siVersion) -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " Built by Morten Knudsen, Microsoft MVP"  -ForegroundColor Gray
Write-Host " Web    : https://mortenknudsen.net"     -ForegroundColor Gray
Write-Host " GitHub : https://github.com/KnudsenMorten/SecurityInsight" -ForegroundColor Gray
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

# ----------- Load setup-unattended.json -----------
if (-not $ConfigPath) {
    $cfgCustom = Join-Path $repoRoot 'config\setup-unattended.json'
    $cfgSample = Join-Path $repoRoot 'config\setup-unattended.sample.json'
    if     (Test-Path -LiteralPath $cfgCustom) { $ConfigPath = $cfgCustom }
    elseif (Test-Path -LiteralPath $cfgSample) { $ConfigPath = $cfgSample; _Warn "no setup-unattended.json found -- using sample defaults from $cfgSample" }
    else { throw "No setup-unattended.json found. Copy config\setup-unattended.sample.json -> config\setup-unattended.json and edit." }
}
_Info ("config path  : {0}" -f $ConfigPath)

try {
    $cfgRaw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
    $cfg    = $cfgRaw | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw ("Could not parse {0}: {1}" -f $ConfigPath, $_.Exception.Message)
}

# ----------- Apply CLI overrides on top of JSON -----------
if ($PSBoundParameters.ContainsKey('Flavour'))         { $cfg.Flavour                  = $Flavour }
if ($PSBoundParameters.ContainsKey('TenantId'))        { $cfg.Sub.TenantId             = $TenantId }
if ($PSBoundParameters.ContainsKey('SubscriptionId'))  { $cfg.Sub.SubscriptionId       = $SubscriptionId }
if ($PSBoundParameters.ContainsKey('Location'))        { $cfg.Sub.Location             = $Location }
if ($PSBoundParameters.ContainsKey('NamingSuffix'))    { $cfg.Resources.NamingSuffix   = $NamingSuffix }
if ($EntraDiag_Enabled)                                 { $cfg.EntraDiag.Enabled        = $true }
if ($Container_Enabled)                                 { $cfg.Container.Enabled        = $true }

# #524 (owner 2026-10-09: "we dont use that legacy code"; "modern single connect only"): the Internal flavour -- signing in
# through the AutomateIT platform framework module (Connect-Platform and its platform globals)
# -- is RETIRED. One sign-in for every install: SecurityInsight's own REST client (a person, a managed identity, or an app
# with a certificate or a client secret), in the block further down.
if (-not $cfg.Flavour) { $cfg | Add-Member -NotePropertyName Flavour -NotePropertyValue 'Community' -Force }
if ($cfg.Flavour -eq 'Internal') {
    throw "The Internal flavour (sign-in through the AutomateIT platform module) is retired. Run with -Flavour Community: SecurityInsight signs in itself -- in your browser or Azure Cloud Shell, or as an app (SI_SPN_AppId + SI_SPN_Secret or SI_SPN_CertThumbprint in the environment)."
}
_Info ("flavour      : {0}" -f $cfg.Flavour)

# Validate the resolved values
if (-not $cfg.Sub.TenantId)       { throw "Sub.TenantId not set. Pass -TenantId or set Sub.TenantId in setup-unattended.json." }
if (-not $cfg.Sub.SubscriptionId) { throw "Sub.SubscriptionId not set. Pass -SubscriptionId or set Sub.SubscriptionId in setup-unattended.json." }
if (-not $cfg.Sub.Location) {
    throw "Sub.Location not set. Pass -Location <azure-region> or set Sub.Location in setup-unattended.json. SecurityInsight is used worldwide -- there is no implicit regional default. Examples: westeurope, northeurope, eastus, eastus2, westus2, southcentralus, uksouth, swedencentral, francecentral, germanywestcentral, switzerlandnorth, norwayeast, australiaeast, southeastasia, japaneast, canadacentral, brazilsouth."
}

# ----------- Default names for a NEW install (<type>-si-<ring>-<edition>-<hosting>) -----------
# Only names the config leaves empty get a default; names the customer set are used as they are. The engines never
# read these defaults: setup writes every name it used into config\SecurityInsight.custom.ps1 (Phase 3) and the
# container hosting block (Phase 5).
. (Join-Path $repoRoot 'setup\_shared\SI-SetupNaming.ps1')
foreach ($sec in 'Naming', 'Resources', 'Auth_Community', 'Container', 'Licence') {
    if (-not $cfg.PSObject.Properties[$sec] -or $null -eq $cfg.$sec) { $cfg | Add-Member -NotePropertyName $sec -NotePropertyValue ([pscustomobject]@{}) -Force }
}
function _CfgValue($obj, [string]$name) { if ($obj -and $obj.PSObject.Properties[$name]) { return $obj.$name } else { return $null } }
function _CfgSet($obj, [string]$name, $value) { if ($obj.PSObject.Properties[$name]) { $obj.$name = $value } else { $obj | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force } }
$nRing    = if ($PSBoundParameters.ContainsKey('Ring')) { $Ring } elseif ("$(_CfgValue $cfg.Naming 'Ring')".Trim()) { "$(_CfgValue $cfg.Naming 'Ring')".Trim().ToLowerInvariant() } else { 'prod' }
if (@('r0','r1','r2','prod') -notcontains $nRing) { throw ("Naming.Ring '{0}' is not known: use prod, r0, r1 or r2." -f $nRing) }
$nEditionIn = if ($PSBoundParameters.ContainsKey('Edition')) { $Edition } else { [string](_CfgValue $cfg.Naming 'Edition') }
$nEdition = Resolve-SISetupEdition -Edition $nEditionIn -LicencePath ([string](_CfgValue $cfg.Licence 'Path'))
$nHosting = if ([bool](_CfgValue $cfg.Container 'Enabled')) { 'ca' } else { 'vm' }
$nOwner   = if ($PSBoundParameters.ContainsKey('Owner')) { $Owner } else { [string](_CfgValue $cfg.Naming 'Owner') }
$defaultNames = Get-SISetupResourceNames -Ring $nRing -Edition $nEdition -Hosting $nHosting
$rgDefaulted  = -not "$(_CfgValue $cfg.Resources 'ResourceGroupName')".Trim()
if ($rgDefaulted)                                                  { _CfgSet $cfg.Resources 'ResourceGroupName' $defaultNames.ResourceGroup }
if (-not "$(_CfgValue $cfg.Resources 'WorkspaceName')".Trim())     { _CfgSet $cfg.Resources 'WorkspaceName'     $defaultNames.Workspace }
if (-not "$(_CfgValue $cfg.Resources 'DceName')".Trim())           { _CfgSet $cfg.Resources 'DceName'           $defaultNames.Dce }
if (-not "$(_CfgValue $cfg.Auth_Community 'DisplayName')".Trim())  { _CfgSet $cfg.Auth_Community 'DisplayName' $defaultNames.SpnDisplayName }
_Info ("naming       : {0} (ring {1}, edition {2}, hosting {3})" -f $defaultNames.EnvLabel, $nRing, $nEdition, $nHosting)

# Apply NamingSuffix to resource names if set
$sfx = [string](_CfgValue $cfg.Resources 'NamingSuffix')
if ($sfx) {
    if ($cfg.Resources.ResourceGroupName  -notlike "*$sfx") { $cfg.Resources.ResourceGroupName  = "$($cfg.Resources.ResourceGroupName)$sfx" }
    if ($cfg.Resources.WorkspaceName      -notlike "*$sfx") { $cfg.Resources.WorkspaceName      = "$($cfg.Resources.WorkspaceName)$sfx" }
    if ($cfg.Resources.DceName            -notlike "*$sfx") { $cfg.Resources.DceName            = "$($cfg.Resources.DceName)$sfx" }
}
$sfxFlat = ($sfx -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
function _GlobalName([string]$name) {
    # A globally unique default (storage / registry): the suffix goes before the instance number; max 24 characters.
    if (-not $sfxFlat) { return $name }
    $n = ($name -replace '01$', '') + $sfxFlat
    if ($n.Length -gt 22) { $n = $n.Substring(0, 22) }
    $n + '01'
}
# Storage and registry names are unique across ALL of Azure: a default carries the subscription's suffix
# (Get-SISetupSubscriptionSuffix), so two customers' installs never want the same name. $siGlobalDefaults holds the
# names THIS run defaulted, each with the names older releases gave it; after sign-in (before Phase 2) the ones an
# existing install already has in its resource group win (Resolve-SISetupDefaultGlobalName) -- nothing is renamed.
$siSubSuffix = Get-SISetupSubscriptionSuffix -SubscriptionId ([string]$cfg.Sub.SubscriptionId)
$siGlobalDefaults = [ordered]@{}
function _NewGlobalName([string]$Kind, [string]$Label, [string]$Legacy) {
    if (-not $siSubSuffix) { return $Legacy }
    Get-SISetupGlobalName -Kind $Kind -Label $Label -Suffix $siSubSuffix
}
$siPatternLabel = $defaultNames.EnvLabel + $(if ($sfx) { $sfx } else { '' })
# StorageAccountName when null (lowercase alnum, max 24, no hyphens)
if (-not "$(_CfgValue $cfg.Resources 'StorageAccountName')".Trim()) {
    if ($rgDefaulted) {
        $saOld = _GlobalName $defaultNames.StorageAccount
        $saNew = _NewGlobalName 'StorageAccount' $siPatternLabel $saOld
    } else {
        # The customer's own resource group: earlier releases derived the name from it (st<group>si).
        $saOld = ('st' + (($cfg.Resources.ResourceGroupName -replace '[^a-z0-9]','') + 'si')).ToLowerInvariant()
        if ($saOld.Length -gt 24) { $saOld = $saOld.Substring(0, 24) }
        $saNew = _NewGlobalName 'StorageAccount' ([string]$cfg.Resources.ResourceGroupName) $saOld
    }
    _CfgSet $cfg.Resources 'StorageAccountName' $saNew
    $siGlobalDefaults['StorageAccount'] = @{ Wanted = $saNew; Legacy = @($saOld) }
}
# Container names: in a default-named resource group, the pattern names (explicit, so a NamingSuffix carries over).
# In the customer's own resource group they stay unset, and the container setup picks them itself.
$containerDefaults = @{}
if ($rgDefaulted) {
    $acrOld = _GlobalName $defaultNames.Acr
    $containerDefaults.AcrName             = _NewGlobalName 'Acr' $siPatternLabel $acrOld
    $containerDefaults.EnvName             = $defaultNames.ContainerEnv + $(if ($sfx) { $sfx } else { '' })
    $containerDefaults.ManagedIdentityName = $defaultNames.ManagedIdentity + $(if ($sfx) { $sfx } else { '' })
    if ($cfg.Container.Enabled -and -not "$(_CfgValue $cfg.Container 'AcrName')".Trim()) {
        $siGlobalDefaults['Acr'] = @{ Wanted = $containerDefaults.AcrName; Legacy = @($acrOld) }
    }
}

_Info ("tenant       : {0}" -f $cfg.Sub.TenantId)
_Info ("subscription : {0}" -f $cfg.Sub.SubscriptionId)
_Info ("location     : {0}" -f $cfg.Sub.Location)
_Info ("RG / WS / DCE / Storage : {0} / {1} / {2} / {3}" -f $cfg.Resources.ResourceGroupName, $cfg.Resources.WorkspaceName, $cfg.Resources.DceName, $cfg.Resources.StorageAccountName)
Write-Host ""

# ----------- Community flavour: auth (reuse existing context if present, else browser) -----------
if ($cfg.Flavour -eq 'Community') {
    # No PowerShell module: Azure and Microsoft Graph over plain REST, one sign-in.
    $envApp   = [string]$env:SI_SPN_AppId
    $envSec   = [string]$env:SI_SPN_Secret
    $envThumb = [string]$env:SI_SPN_CertThumbprint
    $azCtxExisting = Get-SISetupAzureContext
    $mgCtxExisting = if ($azCtxExisting) { Get-SIGraphContext } else { $null }

    if ($azCtxExisting -and $azCtxExisting.Subscription -and $azCtxExisting.Subscription.Id -eq $cfg.Sub.SubscriptionId -and $mgCtxExisting -and $mgCtxExisting.TenantId -eq $cfg.Sub.TenantId) {
        _Banner "Reusing the existing sign-in in this session (non-interactive Community deploy)"
        _Ok ("Azure  : {0} (sub {1})" -f $azCtxExisting.Account.Id, $azCtxExisting.Subscription.Id)
        _Ok ("Graph  : {0} (tenant {1})" -f $mgCtxExisting.Account, $mgCtxExisting.TenantId)
    } elseif ($envApp -and ($envSec -or $envThumb)) {
        # CI / SYSTEM scheduled task: sign in as the app named in the environment (secret or certificate) -- no browser.
        _Banner "App sign-in (non-interactive Community deploy)"
        if ($envThumb) {
            $null = Connect-SISetupAzure -TenantId $cfg.Sub.TenantId -SubscriptionId $cfg.Sub.SubscriptionId -ApplicationId $envApp -CertificateThumbprint $envThumb -Force
        } else {
            $null = Connect-SISetupAzure -TenantId $cfg.Sub.TenantId -SubscriptionId $cfg.Sub.SubscriptionId -ApplicationId $envApp -ClientSecret $envSec -Force
        }
        _Ok ("Azure signed in as app {0}" -f $envApp)
        $null = Get-SIGraphAccessToken -ForceRefresh
        _Ok "Microsoft Graph reachable with the same sign-in"
    } else {
        _Banner "Sign in to Azure (browser, or automatically in Azure Cloud Shell)"
        _Step ("Signing in to tenant {0}, subscription {1}" -f $cfg.Sub.TenantId, $cfg.Sub.SubscriptionId)
        $null = Connect-SISetupAzure -TenantId $cfg.Sub.TenantId -SubscriptionId $cfg.Sub.SubscriptionId -Force
        _Ok "Azure signed in"
        $null = Get-SIGraphAccessToken -ForceRefresh
        _Ok "Microsoft Graph reachable with the same sign-in"
    }

    if ($cfg.Container.Enabled) {
        # #521 (no az CLI, ONE connect path): the container phase (Bootstrap-ContainerAppJob.ps1) runs in this process and
        # reuses the sign-in made just above -- ARM REST for every resource and the image build. No `az login` fallback.
        _Ok ("the container phase uses this same sign-in (sub {0}) -- no Azure CLI" -f $cfg.Sub.SubscriptionId)
    }
}

# The sign-in made just above (person or app) serves Azure and Microsoft Graph over REST.
_Banner "Using this session's sign-in"
$azCtx = Get-SISetupAzureContext
if (-not $azCtx) { throw "Nobody is signed in to Azure. Run the same command again -- it signs you in in your browser, or automatically in Azure Cloud Shell." }
$mgCtx = Get-SIGraphContext
if (-not $mgCtx) { throw ("No Microsoft Graph token from the Azure sign-in. Run the same command again to sign in to tenant {0}." -f $cfg.Sub.TenantId) }
_Ok ("Azure  : {0} (sub {1})" -f $azCtx.Account.Id, $(if ($azCtx.Subscription) { $azCtx.Subscription.Id } else { '' }))
_Ok ("Graph  : {0} (tenant {1})" -f $mgCtx.Account, $mgCtx.TenantId)

# Result accumulators
$spnOut       = $null
$infraOut     = $null
$cfgOut       = $null
$diagOut      = $null
$containerOut = $null
$phaseStatus  = @{ spn='pending'; infra='pending'; config='pending'; entraDiag='pending'; container='pending' }

# The Community sign-in (operator 2026-10-07): Auth_Community.CredKind when the JSON names one; with no CredKind the same
# default as the wizard -- a MANAGED IDENTITY (the Container Apps jobs'
# identity; on an Azure VM a user-assigned identity, created, attached to the VM and granted; an Arc server's own), and
# outside Azure a service principal by CERTIFICATE (a managed identity cannot exist there). setup\_shared\SI-ServerSignIn.ps1
$commSignIn = $null
$commHost   = $null
if (-not $SkipPhase1) {
    . (Join-Path $repoRoot 'setup\_shared\SI-ServerSignIn.ps1')
    . (Join-Path $backendDir 'SI-WizardSignIn.ps1')
    $commKindIn = [string](_CfgValue $cfg.Auth_Community 'CredKind')
    $commHost = [pscustomobject]@{ Kind = 'Outside'; VmName = ''; ResourceGroupName = ''; SubscriptionId = ''; Location = '' }
    if (-not [bool]$cfg.Container.Enabled -and (-not $commKindIn.Trim() -or (ConvertTo-SIServerSignInMethod $commKindIn) -eq 'ManagedIdentity')) { $commHost = Get-SIServerAzureHost }
    $commSignIn = Resolve-SIUnattendedSignIn -CredKind $commKindIn -CredStorage ([string](_CfgValue $cfg.Auth_Community 'CredStorage')) `
                      -ContainerEnabled ([bool]$cfg.Container.Enabled) -HostKind ([string]$commHost.Kind)
    if ($commSignIn.DefaultUsed -and $commHost.Kind -eq 'Outside' -and -not [bool]$cfg.Container.Enabled) { _Warn (Get-SIServerNoManagedIdentityNote) }
    _Info ("sign-in      : {0} -- {1}" -f $commSignIn.CredKind, $commSignIn.Note)
}

# ----------------------------------------------------------------------------
# Phase 1 -- SPN
# ----------------------------------------------------------------------------
if ($SkipPhase1) {
    # Skipping Phase 1 used to leave $spnOut empty, and Phase 2 needs the SPN's ObjectId (mandatory),
    # so -SkipPhase1 could never succeed. The SPN is not created here -- it is RESOLVED from the
    # config (read-only), and the phases that follow get the same shape Phase 1 would have returned.
    $phaseStatus.spn = 'skipped'
    _Warn 'Phase 1 (SPN) skipped via -SkipPhase1 -- resolving the existing SPN from the config'
    $skipAuth  = $cfg.Auth_Community
    $skipAppId = if ($skipAuth -and $skipAuth.PSObject.Properties['AppId']) { [string]$skipAuth.AppId } else { '' }
    if ([string]::IsNullOrWhiteSpace($skipAppId)) {
        throw "-SkipPhase1 needs the existing SPN's AppId in the config (Auth_Community.AppId)."
    }
    $skipSp = Get-SIAzADServicePrincipal -ApplicationId $skipAppId -ErrorAction Stop
    if (-not $skipSp) { throw ("-SkipPhase1: no service principal for AppId {0} in tenant {1}." -f $skipAppId, $cfg.Sub.TenantId) }
    $skipThumb  = if ($skipAuth.PSObject.Properties['CertificateThumbprint']) { [string]$skipAuth.CertificateThumbprint } else { '' }
    $skipSecret = if ($skipAuth.PSObject.Properties['Secret']) { [string]$skipAuth.Secret } else { '' }
    $spnOut = [pscustomobject]@{
        AppId          = $skipAppId
        ObjectId       = [string]@($skipSp)[0].Id
        TenantId       = $cfg.Sub.TenantId
        DisplayName    = [string]@($skipSp)[0].DisplayName
        CredKind       = if ($skipThumb) { 'Cert' } else { 'Secret' }
        CertThumbprint = if ($skipThumb) { $skipThumb } else { $null }
        CredValue      = if (-not $skipThumb -and $skipSecret) { $skipSecret } else { $null }
        KvName         = $null
        ConsentStatus  = 'unknown'
    }
    _Ok ("existing SPN resolved: AppId {0}, ObjectId {1}" -f $spnOut.AppId, $spnOut.ObjectId)
} else {
    try {
        if ($commSignIn.CredKind -eq 'ManagedIdentity') {
            # Community flavour, MANAGED IDENTITY (the default) -- no app registration is created.
            if ($commSignIn.Identity -eq 'user-assigned') {
                # An Azure VM: the wizard's steps -- the identity in the install's resource group, attached to the VM, granted.
                $miName = Get-SIWizardIdentityName -Name ([string](_CfgValue $cfg.Auth_Community 'ManagedIdentityName')) -ResourceGroupName $cfg.Resources.ResourceGroupName
                $miVm   = [string](_CfgValue $cfg.Auth_Community 'VmName'); if (-not $miVm) { $miVm = [string]$commHost.VmName }
                $miVmRg = [string](_CfgValue $cfg.Auth_Community 'VmResourceGroup')
                if (-not $miVmRg) { $miVmRg = if ($miVm -and $miVm -eq [string]$commHost.VmName -and $commHost.ResourceGroupName) { [string]$commHost.ResourceGroupName } else { [string]$cfg.Resources.ResourceGroupName } }
                $miTag  = ConvertTo-SIAzTagHashtable -Tags (Get-SIResourceGroupTags -Ring $nRing -Edition $nEdition -Hosting $nHosting -Tenant (Resolve-SITenantTag) -Owner $nOwner)
                $mi = Invoke-SIServerManagedIdentitySetup -TenantId $cfg.Sub.TenantId -SubscriptionId $cfg.Sub.SubscriptionId -ResourceGroupName $cfg.Resources.ResourceGroupName `
                          -Location $cfg.Sub.Location -IdentityName $miName -VmName $miVm -VmResourceGroup $miVmRg -Tag $miTag -NewSISpnPath $cmdletNewSISpn
                $spnOut = New-SIWizardManagedIdentityResult -TenantId $cfg.Sub.TenantId -ClientId $mi.ClientId -PrincipalId $mi.PrincipalId -Name $mi.Name -ResourceId $mi.ResourceId
                if ($mi.GrantResult) { foreach ($p in 'GraphPermissionResults', 'PendingPermissions', 'ConsentStatus', 'ConsentUrl', 'AzureRbacScopes', 'AzureRbacResults') { if ($mi.GrantResult.PSObject.Properties[$p]) { $spnOut.$p = $mi.GrantResult.$p } } }
                _Ok ("managed identity {0} (client id {1})" -f $mi.Name, $mi.ClientId)
                if ($mi.Attached -eq 'no') { _Warn ("no VM named (Auth_Community.VmName): attach it to the server that runs SecurityInsight -- Azure portal > the VM > Identity > User assigned > Add > {0}" -f $mi.Name) }
                else { _Ok ("attached to VM {0}/{1}" -f $miVmRg, $miVm) }
                if ($mi.Grants -eq 'failed') { throw ("the managed identity's permissions could not be granted: {0}" -f $mi.GrantError) }
                if ($mi.Grants -eq 'consent-pending') { _Warn ('some permissions need an administrator''s consent: {0}' -f (@($mi.PendingPermissions) -join ', ')) }
            } else {
                # Container Apps jobs (granted by the container setup, Phase 5) or an Arc server's own identity.
                $spnOut = New-SIWizardManagedIdentityResult -TenantId $cfg.Sub.TenantId -Name $(if ($commSignIn.Identity -eq 'container-jobs') { [string]$containerDefaults.ManagedIdentityName } else { '' })
                if ($commSignIn.Identity -eq 'system-assigned') {
                    _Info (Get-SIServerArcGrantHint -MachineName $(if ([string](_CfgValue $cfg.Auth_Community 'VmName')) { [string](_CfgValue $cfg.Auth_Community 'VmName') } else { [string]$commHost.VmName }) -ResourceGroupName ([string](_CfgValue $cfg.Auth_Community 'VmResourceGroup')))
                } else { _Info 'the Container Apps jobs'' managed identity is created and granted by the container setup (Phase 5)' }
            }
        } else {
            # Community flavour, a service principal (a certificate or a client secret -- named in Auth_Community.CredKind,
            # or a certificate by default outside Azure)
            $spnArgs = @{
                DisplayName    = $cfg.Auth_Community.DisplayName
                TenantId       = $cfg.Sub.TenantId
                SubscriptionId = $cfg.Sub.SubscriptionId
                CredKind       = $commSignIn.CredKind
                CredStorage    = $commSignIn.CredStorage
            }
            if ($cfg.Auth_Community.KeyVaultName) { $spnArgs.KeyVaultName = $cfg.Auth_Community.KeyVaultName }
            # #175: opt-in Tag Contributor for the asset-tagging engine (the only role that writes).
            if ($cfg.Auth_Community.PSObject.Properties['IncludeTagContributor'] -and [bool]$cfg.Auth_Community.IncludeTagContributor) { $spnArgs.IncludeTagContributor = $true }
            $spnOut = & $cmdletNewSISpn @spnArgs
        }
        $phaseStatus.spn = 'ok'
    } catch {
        $phaseStatus.spn = 'failed'
        _Err "Phase 1 (SPN) failed: $($_.Exception.Message)"
        throw
    }
}

# ----------------------------------------------------------------------------
# Defaulted storage / registry names: an existing install keeps the ones it has
# ----------------------------------------------------------------------------
if ($siGlobalDefaults.Count) {
    $siInRg = @(); $siReadFailed = $false
    try {
        if (Get-SIAzResourceGroup -Name $cfg.Resources.ResourceGroupName -ErrorAction SilentlyContinue) {
            $siInRg = @(Get-SIArmResource -ResourceGroupName $cfg.Resources.ResourceGroupName -SubscriptionId $cfg.Sub.SubscriptionId -ErrorAction Stop | Where-Object { $_ })
        }
    } catch {
        $siReadFailed = $true
        _Warn ("Could not read the resource group {0} to find this install's storage account and registry, so the names earlier releases used are kept: {1}" -f $cfg.Resources.ResourceGroupName, $_.Exception.Message)
    }
    foreach ($k in @($siGlobalDefaults.Keys)) {
        $type = $script:SISetupGlobalNameTypes[$k]
        $have = @($siInRg | Where-Object { [string]$_.ResourceType -eq $type } | ForEach-Object { [string]$_.Name })
        $pick = Resolve-SISetupDefaultGlobalName -Kind $k -Wanted $siGlobalDefaults[$k].Wanted -Legacy $siGlobalDefaults[$k].Legacy -Existing $have -ReadFailed:$siReadFailed
        if ($pick -eq $siGlobalDefaults[$k].Wanted) { continue }
        if ($k -eq 'StorageAccount') { $cfg.Resources.StorageAccountName = $pick } else { $containerDefaults.AcrName = $pick }
        if (-not $siReadFailed) { _Info ("{0}: keeps the existing {1}" -f $(if ($k -eq 'Acr') { 'Container registry' } else { 'Storage account' }), $pick) }
    }
}

# ----------------------------------------------------------------------------
# Phase 2 -- Infrastructure (LA + DCE + Storage + RBAC)
# ----------------------------------------------------------------------------
try {
    $infraArgs = @{
        SpnObjectId        = [string]$spnOut.ObjectId   # empty for the Container Apps jobs' identity: the container setup grants it
        TenantId           = $cfg.Sub.TenantId
        SubscriptionId     = $cfg.Sub.SubscriptionId
        ResourceGroupName  = $cfg.Resources.ResourceGroupName
        Location           = $cfg.Sub.Location
        WorkspaceName      = $cfg.Resources.WorkspaceName
        DceName            = $cfg.Resources.DceName
        StorageAccountName = $cfg.Resources.StorageAccountName
        # the tags of a resource group setup creates (product, ring, edition, hosting, tenant, owner, purpose)
        Ring               = $nRing
        Edition            = $nEdition
        Hosting            = $nHosting
        Owner              = $nOwner
    }
    $infraOut = & $cmdletInitInfra @infraArgs
    $phaseStatus.infra = 'ok'
} catch {
    $phaseStatus.infra = 'failed'
    _Err "Phase 2 (Infrastructure) failed: $($_.Exception.Message)"
    throw
}

# ----------------------------------------------------------------------------
# Phase 2.5 -- SecurityInsight Pro licence (#173), when Licence.Path is set
# ----------------------------------------------------------------------------
# Installed through the one tool that VERIFIES it first (signature, dates, known features, tenant binding), writes it,
# and reads it back -- into the Key Vault this install names (Licence.VaultName, else Auth_Community.KeyVaultName).
# Without a licence file this install runs the Community edition, which is complete on its own.
# (#524: the v1 platform Key Vault seeding of the retired Internal flavour -- Shodan / OpenAI keys from
# the platform vault -- is gone with that flavour.)
$phaseStatus.kvSeed = 'skipped'
$licPath = $null
if ($cfg.PSObject.Properties['Licence'] -and $cfg.Licence -and $cfg.Licence.PSObject.Properties['Path']) { $licPath = [string]$cfg.Licence.Path }
if (-not [string]::IsNullOrWhiteSpace($licPath)) {
    $licTool = Join-Path $PSScriptRoot 'setup\Set-SILicense.ps1'
    $kv = [string](_CfgValue $cfg.Licence 'VaultName'); if (-not $kv) { $kv = [string](_CfgValue $cfg.Auth_Community 'KeyVaultName') }
    if (-not (Test-Path -LiteralPath $licTool)) {
        _Warn 'Licence.Path is set, but this copy has no licence tool (the Community edition) -- nothing installed.'
        $phaseStatus.kvSeedLicence = 'skipped-no-tool'
    } elseif (-not $kv) {
        _Warn 'Licence.Path is set, but no Key Vault is named (Licence.VaultName or Auth_Community.KeyVaultName) -- nothing installed.'
        $phaseStatus.kvSeedLicence = 'skipped-no-vault'
    } else {
        try {
            & $licTool -Path $licPath -VaultName $kv -TenantId $cfg.Sub.TenantId
            $phaseStatus.kvSeedLicence = 'ok'
            $phaseStatus.kvSeed = 'ok'
        } catch {
            _Warn ("SecurityInsight Pro licence NOT installed: {0}" -f $_.Exception.Message)
            $phaseStatus.kvSeedLicence = 'failed'
        }
    }
}

# ----------------------------------------------------------------------------
# Phase 3 -- Config file
# ----------------------------------------------------------------------------
try {
    # v2.3: Write-SICustomConfig is single-template (no -Mode). Section 1 always
    # emits resolved values; Section 11 KV pulls gate at runtime on $global:Context.
    $cfgArgs = @{
        Spn   = $spnOut
        Infra = $infraOut
    }
    # #176: an existing config is UPGRADED by default -- every value kept, only missing settings added -- instead
    # of stopping here (and, with -ForceConfigOverwrite, regenerating the whole file and dropping every setting
    # added by hand). -ForceConfigOverwrite keeps its old meaning: back up, then regenerate.
    if ($ForceConfigOverwrite) { $cfgArgs.Force = $true } else { $cfgArgs.Merge = $true }
    # v2.2.355 -- pass Smtp through to the custom.ps1 writer when the operator
    # populated it in setup-unattended.json.
    if ($cfg.PSObject.Properties['Smtp'] -and $cfg.Smtp -and $cfg.Smtp.Server) {
        $smtpHash = @{
            Server     = [string]$cfg.Smtp.Server
            Port       = if ($cfg.Smtp.Port)   { [int]$cfg.Smtp.Port }   else { 587 }
            User       = [string]$cfg.Smtp.User
            Password   = [string]$cfg.Smtp.Password
            From       = [string]$cfg.Smtp.From
            UseSsl     = if ($null -ne $cfg.Smtp.UseSsl) { [bool]$cfg.Smtp.UseSsl } else { $true }
            MailTo     = @($cfg.Smtp.MailTo     | Where-Object { $_ })
            DetailedTo = @($cfg.Smtp.DetailedTo | Where-Object { $_ })
            SummaryTo  = @($cfg.Smtp.SummaryTo  | Where-Object { $_ })
        }
        $cfgArgs.Smtp = $smtpHash
        _Info ("Smtp section: server={0}:{1} from={2} mailTo={3} (emitted into custom.ps1)" -f `
            $smtpHash.Server, $smtpHash.Port, $smtpHash.From, ((@($smtpHash.MailTo) + @($smtpHash.DetailedTo) + @($smtpHash.SummaryTo) | Sort-Object -Unique) -join ','))
    }
    $cfgOut = & $cmdletWriteConfig @cfgArgs
    $phaseStatus.config = 'ok'
} catch {
    $phaseStatus.config = 'failed'
    _Err "Phase 3 (Config file) failed: $($_.Exception.Message)"
    throw
}

# ----------------------------------------------------------------------------
# Phase 4 -- Entra ID Diagnostic Setting (toggle-gated)
# ----------------------------------------------------------------------------
if ($cfg.EntraDiag.Enabled) {
    try {
        $diagOut = & $cmdletEntraDiag -WorkspaceResourceId $infraOut.WorkspaceResourceId
        $phaseStatus.entraDiag = 'ok'
    } catch {
        $phaseStatus.entraDiag = 'failed'
        _Err "Phase 4 (Entra Diag) failed: $($_.Exception.Message)"
        throw
    }
} else {
    $phaseStatus.entraDiag = 'skipped'
    _Info 'Phase 4 (Entra Diag) skipped (EntraDiag.Enabled=false)'
}

# ----------------------------------------------------------------------------
# Phase 5 -- Container Apps Job runtime (toggle-gated)
# ----------------------------------------------------------------------------
if ($cfg.Container.Enabled) {
    try {
        $containerArgs = @{
            ResourceGroupName = $cfg.Resources.ResourceGroupName
            Location          = $cfg.Sub.Location
            SubscriptionId    = $cfg.Sub.SubscriptionId
        }
        foreach ($k in $containerDefaults.Keys) { $containerArgs[$k] = $containerDefaults[$k] }
        if ($cfg.Container.AcrName)         { $containerArgs.AcrName         = $cfg.Container.AcrName }
        if ($cfg.Container.EnvName)         { $containerArgs.EnvName         = $cfg.Container.EnvName }
        if ($null -ne $cfg.Container.UseKEDA) { $containerArgs.UseKEDA       = [bool]$cfg.Container.UseKEDA }
        if ($cfg.Container.KedaMaxReplicas) { $containerArgs.KedaMaxReplicas = [int]$cfg.Container.KedaMaxReplicas }
        if ($commSignIn -and $commSignIn.Identity -eq 'container-jobs') { $containerArgs.GrantIdentityRoles = $true }   # the jobs' identity is the sign-in: grant it
        $containerOut = & $cmdletContainer @containerArgs
        $phaseStatus.container = 'ok'
    } catch {
        $phaseStatus.container = 'failed'
        _Err "Phase 5 (Container) failed: $($_.Exception.Message)"
        throw
    }
} else {
    $phaseStatus.container = 'skipped'
    _Info 'Phase 5 (Container) skipped (Container.Enabled=false)'
}

# ----------------------------------------------------------------------------
# Summary
# ----------------------------------------------------------------------------
Write-Host ""
Write-Host "===================================================================" -ForegroundColor Magenta
Write-Host (" UNATTENDED SETUP DONE  (flavour={0})" -f $cfg.Flavour) -ForegroundColor Magenta
Write-Host "===================================================================" -ForegroundColor Magenta
Write-Host (" SPN       : {0}" -f $phaseStatus.spn)       -ForegroundColor Gray
Write-Host (" Infra     : {0}" -f $phaseStatus.infra)     -ForegroundColor Gray
Write-Host (" Config    : {0}" -f $phaseStatus.config)    -ForegroundColor Gray
Write-Host (" EntraDiag : {0}" -f $phaseStatus.entraDiag) -ForegroundColor Gray
Write-Host (" Container : {0}" -f $phaseStatus.container) -ForegroundColor Gray
Write-Host ""

exit 0
} finally { Stop-SIScriptRun -Run $siRun }
