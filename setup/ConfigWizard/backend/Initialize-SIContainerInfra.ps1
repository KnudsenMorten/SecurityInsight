<#
.SYNOPSIS
    Phase 5 of the Setup Wizard's /api/apply -- provisions the Azure Container
    Apps Job runtime (ACR + image + Container Apps Environment + per-engine
    Jobs + KEDA queue scalers).

.DESCRIPTION
    Thin wrapper around the canonical Bootstrap-ContainerAppJob.ps1 at the
    repo root. The wizard already wrote config\SecurityInsight.custom.ps1 in
    Phase 3, which Bootstrap-ContainerAppJob loads to get SPN credentials,
    workspace ResourceId, storage account, etc. This wrapper:

      1. Verifies setup's own REST sign-in (the one the wizard signed in with;
         no az CLI -- Bootstrap-ContainerAppJob builds the image over ARM REST).
      2. Sets $global:SI_Bootstrap_* from the wizard's structured params
         (Bootstrap-ContainerAppJob's layered-config resolver picks them up).
      3. Invokes Bootstrap-ContainerAppJob.ps1 with -UseKEDA enabled by
         default (queue-scaled workers, scale-to-zero between runs).
      4. Captures the resulting resource IDs + per-engine job names.

    Idempotent. Bootstrap-ContainerAppJob's per-resource existence checks
    short-circuit when the ACR / CAE / Jobs already exist, so re-running
    /api/apply after a partial failure resumes cleanly.

    Pre-requisites:
      * the wizard's Azure sign-in in this process (setup's own REST sign-in -- no az CLI, no PowerShell module)
      * config\SecurityInsight.custom.ps1 exists (Phase 3 just wrote it)
      * The operator running the wizard has Owner / RBAC Admin at the target sub
        (creating the Managed Identity + assigning roles needs roleAssignments/write)

.PARAMETER ResourceGroupName
    The RG the wizard's Phase 2 created. ACR + CAE + Jobs land in this RG.

.PARAMETER Location
    Azure region. Same one Phase 2 used.

.PARAMETER SubscriptionId
    Target subscription.

.PARAMETER AcrName
    Container Registry name (globally unique, lowercase alphanumeric, 5-50 chars).
    Default: the name already saved in config\SecurityInsight.custom.ps1; else, in a resource group named by the
    setup pattern (rg-si-<ring>-<edition>-<hosting>), acrsi<ring><edition><hosting>01; else derived from the RG
    name as before.

.PARAMETER EnvName
    Container Apps Environment name. Default: the saved name; else cae-si-<ring>-<edition>-<hosting> in a
    pattern resource group; else 'cae-securityinsight' (the name every earlier release created).

.PARAMETER ManagedIdentityName
    The engine jobs' user-assigned identity. Default: the saved name; else id-si-<ring>-<edition>-<hosting> in a
    pattern resource group; else 'uami-securityinsight' (the name every earlier release created). Saved in the
    config, so a later re-run of Bootstrap-ContainerAppJob.ps1 finds the same identity.

.PARAMETER UseKEDA
    Default $true. Provisions producer + worker job pairs per engine with
    KEDA queue-depth scaling. Set $false for the legacy single-job-per-engine
    cron model.

.PARAMETER KedaMaxReplicas
    Cap on concurrent worker replicas. Default 30 (Consumption profile soft-cap).

.OUTPUTS
    pscustomobject @{
      AcrName; AcrLoginServer; EnvName; EnvResourceId;
      Jobs = @( @{ Name; Engine; Cron } ... );
      UseKEDA; KedaMaxReplicas
    }

.NOTES
    Status: v2.2.141 -- new in /api/apply Phase 5 (gated on hostType='azureContainerMI').
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$ResourceGroupName,
    [Parameter(Mandatory)] [string]$Location,
    [Parameter(Mandatory)] [string]$SubscriptionId,
    [Parameter()]          [string]$AcrName,
    [Parameter()]          [string]$EnvName = '',
    [Parameter()]          [string]$ManagedIdentityName = '',
    [Parameter()]          [bool]$UseKEDA = $true,
    [Parameter()]          [int]$KedaMaxReplicas = 30,
    # The jobs' managed identity is the install's sign-in (the wizard's default): grant it its read-only plan here.
    [Parameter()]          [switch]$GrantIdentityRoles
)

$ErrorActionPreference = 'Stop'

function _Step([string]$msg) { Write-Host "  [STEP] $msg" -ForegroundColor Cyan }
function _Ok  ([string]$msg) { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function _Info([string]$msg) { Write-Host "  [INFO] $msg" -ForegroundColor Gray }
function _Warn([string]$msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "=== Initialize-SIContainerInfra ===" -ForegroundColor Cyan

# ---------- Resolve repo root ----------
# Walk up from this script's location to the SI repo root (marker = VERSION).
$cur = $PSScriptRoot
while ($cur -and -not (Test-Path -LiteralPath (Join-Path $cur 'VERSION'))) {
    $parent = Split-Path -Parent $cur
    if (-not $parent -or $parent -eq $cur) { $cur = $null; break }
    $cur = $parent
}
if (-not $cur) { throw 'Could not auto-resolve SI repo root from backend cmdlet location.' }
$repoRoot = $cur
$bootstrapScript = Join-Path $repoRoot 'Bootstrap-ContainerAppJob.ps1'
$customFile      = Join-Path $repoRoot 'config\SecurityInsight.custom.ps1'

_Info ("repo root      : {0}" -f $repoRoot)
_Info ("bootstrap      : {0}" -f $bootstrapScript)
_Info ("custom config  : {0}" -f $customFile)

if (-not (Test-Path -LiteralPath $bootstrapScript)) {
    throw "Bootstrap-ContainerAppJob.ps1 not found at $bootstrapScript -- cannot provision container infra."
}
if (-not (Test-Path -LiteralPath $customFile)) {
    throw "config\SecurityInsight.custom.ps1 not found -- Phase 3 should have written it before Phase 5 runs."
}

# ---------- Pre-flight: setup's own REST sign-in (#521: no az CLI) ----------
# The wizard signed in through setup's REST client (SI-SetupAzure.ps1); Bootstrap-ContainerAppJob reuses that sign-in and
# builds the image over ARM REST. Nothing to install, no `az login`.
_Step "verify the Azure sign-in (setup's REST client) is on the same subscription"
if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) { . (Join-Path $repoRoot 'setup\_shared\SI-SetupAzure.ps1') }
if (-not (Get-Command -Name Get-SIContainerAppJobList -ErrorAction SilentlyContinue)) { . (Join-Path $repoRoot 'setup\_shared\SI-SetupArm.ps1') }
$azCtx = Get-SISetupAzureContext
if (-not $azCtx) {
    throw "Not signed in to Azure in this process. Sign in from the wizard's Azure step (Azure Cloud Shell or the browser), then re-click Setup."
}
$ctxSub = if ($azCtx.Subscription) { [string]$azCtx.Subscription.Id } else { '' }
if ($ctxSub -ne $SubscriptionId) {
    _Warn ("the sign-in is on subscription {0} but Phase 2 used {1}. Switching." -f $ctxSub, $SubscriptionId)
    $null = Set-SIAzContext -Subscription $SubscriptionId
}
_Ok ("signed in as {0}; subscription {1}" -f [string]$azCtx.Account.Id, $SubscriptionId)

# ---------- Default names ----------
# Explicit value > the value this install already SAVED in its config (same resource group) > the setup pattern, when
# the resource group follows it (rg-si-<ring>-<edition>-<hosting>) > the names earlier releases created in any other
# resource group. A re-run against an existing install therefore always lands on the resources it already has.
. (Join-Path $repoRoot 'setup\_shared\SI-ContainerUpdate.ps1')
. (Join-Path $repoRoot 'setup\_shared\SI-SetupNaming.ps1')
$savedText    = [IO.File]::ReadAllText($customFile)
$savedRg      = Get-SIContainerHostingValue -Text $savedText -Name 'SI_Bootstrap_ResourceGroupName'
$sameRg       = (-not $savedRg) -or ($savedRg -eq $ResourceGroupName)
$patternNames = Get-SISetupNamesFromResourceGroup -ResourceGroupName $ResourceGroupName
function _PickName([string]$Explicit, [string]$SavedName, [string]$PatternKey, [string]$Legacy) {
    if ("$Explicit".Trim()) { return "$Explicit".Trim() }
    if ($sameRg) { $v = Get-SIContainerHostingValue -Text $savedText -Name $SavedName; if ($v) { return $v } }
    if ($patternNames) { return [string]$patternNames[$PatternKey] }
    $Legacy
}
# ACR names: lowercase alphanumeric, 5-50 chars, unique across ALL of Azure. A new default carries the subscription's
# suffix (pattern RG: acrsi<label><6hex>; any other RG: acrsi<group><6hex>). Without an explicit or saved name, the
# registry this install already has in the group wins (Resolve-SISetupDefaultGlobalName): the name older releases gave
# it (acrsi<label>01, or acr<group> outside a pattern RG) is never replaced by a second registry.
$legacyAcr = ('acr' + ($ResourceGroupName -replace '[^a-z0-9]','')).ToLowerInvariant()
if ($legacyAcr.Length -gt 50) { $legacyAcr = $legacyAcr.Substring(0, 50) }
if ($legacyAcr.Length -lt 5)  { $legacyAcr = $legacyAcr + 'si' }
$acrOld = if ($patternNames) { [string]$patternNames['Acr'] } else { $legacyAcr }
$acrSavedOrGiven = _PickName $AcrName 'SI_Bootstrap_AcrName' '' ''
if ($acrSavedOrGiven) { $AcrName = $acrSavedOrGiven }
else {
    $acrNew = $acrOld
    $acrSfx = Get-SISetupSubscriptionSuffix -SubscriptionId $SubscriptionId
    if ($acrSfx) {
        $acrNew = if ($patternNames) { [string](Get-SISetupNamesFromResourceGroup -ResourceGroupName $ResourceGroupName -SubscriptionId $SubscriptionId)['Acr'] }
                  else { Get-SISetupGlobalName -Kind Acr -Label $ResourceGroupName -Suffix $acrSfx }
    }
    $acrHave = @(); $acrReadFailed = $false
    try {
        if (Get-SIResourceGroupArm -Name $ResourceGroupName -SubscriptionId $SubscriptionId) {
            $acrHave = @(Get-SIArmResource -ResourceGroupName $ResourceGroupName -ResourceType 'Microsoft.ContainerRegistry/registries' -SubscriptionId $SubscriptionId |
                         ForEach-Object { "$($_.Name)".Trim() } | Where-Object { $_ })
        }
    } catch { $acrReadFailed = $true }
    if ($acrReadFailed) { _Warn ("Could not read the resource group {0} for an existing container registry, so the name earlier releases used is kept: {1}" -f $ResourceGroupName, $acrOld) }
    $AcrName = Resolve-SISetupDefaultGlobalName -Kind Acr -Wanted $acrNew -Legacy @($acrOld) -Existing $acrHave -ReadFailed:$acrReadFailed
}
$EnvName             = _PickName $EnvName 'SI_Bootstrap_EnvName' 'ContainerEnv' 'cae-securityinsight'
$ManagedIdentityName = _PickName $ManagedIdentityName 'SI_Bootstrap_ManagedIdentityName' 'ManagedIdentity' 'uami-securityinsight'

_Info ("RG             : {0}" -f $ResourceGroupName)
_Info ("Location       : {0}" -f $Location)
_Info ("ACR            : {0}" -f $AcrName)
_Info ("CAE            : {0}" -f $EnvName)
_Info ("Identity       : {0}" -f $ManagedIdentityName)
_Info ("KEDA           : {0} (max replicas {1})" -f $UseKEDA, $KedaMaxReplicas)

# ---------- Set $global:SI_Bootstrap_* so Bootstrap-ContainerAppJob's layered resolver picks them up ----------
$global:SI_Bootstrap_ResourceGroupName = $ResourceGroupName
$global:SI_Bootstrap_Location          = $Location
$global:SI_Bootstrap_AcrName           = $AcrName
$global:SI_Bootstrap_EnvName           = $EnvName
$global:SI_Bootstrap_ManagedIdentityName = $ManagedIdentityName

# ---------- Invoke Bootstrap-ContainerAppJob.ps1 ----------
_Step "invoke Bootstrap-ContainerAppJob.ps1"
$bootstrapArgs = @{
    ResourceGroupName  = $ResourceGroupName
    Location           = $Location
    AcrName            = $AcrName
    EnvName            = $EnvName
    UseManagedIdentity = $true
    ManagedIdentityName = $ManagedIdentityName
    KedaMaxReplicas    = $KedaMaxReplicas
}
# #475: queue scaling is Bootstrap's default (KEDA by design) -- the wizard's choice is passed BOTH ways, so its "off" is not lost
$bootstrapArgs.UseKEDA = [bool]$UseKEDA
if ($GrantIdentityRoles) { $bootstrapArgs.GrantIdentityRoles = $true }

# Dot-source the bootstrap so its functions + globals stay in our scope
# (and so $cliBound logic inside the script picks up our params correctly
# we instead invoke via & with splatting -- the script's own
# $PSBoundParameters captures only what we passed).
& $bootstrapScript @bootstrapArgs
$bootstrapExit = $LASTEXITCODE
if ($bootstrapExit -and $bootstrapExit -ne 0) {
    throw "Bootstrap-ContainerAppJob.ps1 exited with code $bootstrapExit"
}
_Ok "Bootstrap-ContainerAppJob completed"

# ---------- Save where the containers live (#166) ----------
# The update hook (setup\Invoke-SIContainerUpdate.ps1, run after every sync) finds the container hosting
# ONLY through these values in the config. They used to exist in memory for this run alone, so every
# later update said "no container hosting is configured" and left the jobs on the old image.
_Step "save the container hosting location in config\SecurityInsight.custom.ps1"
$saved = Save-SIContainerHostingConfig -ConfigPath $customFile -SubscriptionId $SubscriptionId `
    -ResourceGroupName $ResourceGroupName -AcrName $AcrName -EnvName $EnvName -Location $Location `
    -ManagedIdentityName $ManagedIdentityName
if ($saved.Changed) { _Ok ("saved (previous file kept as {0})" -f $(if ($saved.Backup) { Split-Path -Leaf $saved.Backup } else { 'n/a' })) }
else { _Ok 'already saved -- unchanged' }

# ---------- Capture resource IDs ----------
_Step "capture resource IDs for /api/apply response"
$acrLoginServer = $null
try {
    $acr = Get-SIContainerRegistry -ResourceGroupName $ResourceGroupName -Name $AcrName -SubscriptionId $SubscriptionId
    if (-not $acr) { throw ("the registry {0} was not found in {1}" -f $AcrName, $ResourceGroupName) }
    $acrLoginServer = $acr.loginServer
} catch {
    _Warn ("could not read ACR loginServer: {0}" -f $_.Exception.Message)
}

$envResourceId = $null
try {
    $env = Get-SIManagedEnvironment -ResourceGroupName $ResourceGroupName -Name $EnvName -SubscriptionId $SubscriptionId
    if (-not $env) { throw ("the environment {0} was not found in {1}" -f $EnvName, $ResourceGroupName) }
    $envResourceId = $env.id
} catch {
    _Warn ("could not read CAE ResourceId: {0}" -f $_.Exception.Message)
}

$jobs = @()
try {
    # assigned as it comes: the helper returns its array with a leading comma (@( ) around it would nest it)
    $jobList = Get-SIContainerAppJobList -ResourceGroupName $ResourceGroupName -SubscriptionId $SubscriptionId
    foreach ($j in $jobList) {
        if ($j.name -like 'caj-si-*') {
            $cron = $null
            if ($j.properties -and $j.properties.configuration -and $j.properties.configuration.scheduleTriggerConfig) {
                $cron = $j.properties.configuration.scheduleTriggerConfig.cronExpression
            }
            $engine = ($j.name -replace '^caj-si-','' -replace '-(producer|worker)$','')
            $jobs += [pscustomobject]@{
                Name   = $j.name
                Engine = $engine
                Cron   = $cron
            }
        }
    }
} catch {
    _Warn ("could not list Container Apps Jobs: {0}" -f $_.Exception.Message)
}

[pscustomobject]@{
    AcrName         = $AcrName
    AcrLoginServer  = $acrLoginServer
    EnvName         = $EnvName
    EnvResourceId   = $envResourceId
    ManagedIdentityName = $ManagedIdentityName
    Jobs            = $jobs
    UseKEDA         = $UseKEDA
    KedaMaxReplicas = $KedaMaxReplicas
}
