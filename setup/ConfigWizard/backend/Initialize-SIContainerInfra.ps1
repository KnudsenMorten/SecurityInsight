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

      1. Verifies the `az` CLI is on PATH (Bootstrap-ContainerAppJob shells
         out to `az acr build` for server-side image builds).
      2. Sets $global:SI_Bootstrap_* from the wizard's structured params
         (Bootstrap-ContainerAppJob's layered-config resolver picks them up).
      3. Invokes Bootstrap-ContainerAppJob.ps1 with -UseKEDA enabled by
         default (queue-scaled workers, scale-to-zero between runs).
      4. Captures the resulting resource IDs + per-engine job names.

    Idempotent. Bootstrap-ContainerAppJob's per-resource existence checks
    short-circuit when the ACR / CAE / Jobs already exist, so re-running
    /api/apply after a partial failure resumes cleanly.

    Pre-requisites:
      * `az` CLI installed + logged in (`az login` -- same account as Connect-AzAccount)
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
    Default: derived from RG name.

.PARAMETER EnvName
    Container Apps Environment name. Default: 'cae-securityinsight'.

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
    [Parameter()]          [string]$EnvName = 'cae-securityinsight',
    [Parameter()]          [bool]$UseKEDA = $true,
    [Parameter()]          [int]$KedaMaxReplicas = 30
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

# ---------- Pre-flight: az CLI ----------
_Step "verify az CLI available"
try {
    $azVer = & az version --output json 2>&1 | ConvertFrom-Json -ErrorAction Stop
    _Ok ("az CLI found: {0}" -f $azVer.'azure-cli')
} catch {
    throw ("az CLI not found on PATH. Bootstrap-ContainerAppJob shells out to 'az acr build' for server-side " +
           "image builds; install from https://learn.microsoft.com/cli/azure/install-azure-cli-windows and " +
           "run 'az login' in this shell, then re-click Setup. Original: {0}" -f $_.Exception.Message)
}

# ---------- Pre-flight: az login context matches Az PowerShell context ----------
_Step "verify az CLI is logged in to the same subscription"
try {
    $azAccount = & az account show --output json 2>&1 | ConvertFrom-Json -ErrorAction Stop
    if ($azAccount.id -ne $SubscriptionId) {
        _Warn ("az CLI is on subscription {0} but Phase 2 used {1}. Switching." -f $azAccount.id, $SubscriptionId)
        $null = & az account set --subscription $SubscriptionId 2>&1
    }
    _Ok ("az CLI sub: {0}" -f $SubscriptionId)
} catch {
    throw ("az CLI not logged in. Run 'az login --tenant <tenant-id>' in this shell, then re-click Setup. " +
           "Original: {0}" -f $_.Exception.Message)
}

# ---------- Default ACR name ----------
if (-not $AcrName) {
    # ACR names: lowercase alphanumeric, 5-50 chars, globally unique. Derive from RG.
    $AcrName = ('acr' + ($ResourceGroupName -replace '[^a-z0-9]','')).ToLowerInvariant()
    if ($AcrName.Length -gt 50) { $AcrName = $AcrName.Substring(0, 50) }
    if ($AcrName.Length -lt 5)  { $AcrName = $AcrName + 'si' }
    _Info ("AcrName auto-derived: {0}" -f $AcrName)
}

_Info ("RG             : {0}" -f $ResourceGroupName)
_Info ("Location       : {0}" -f $Location)
_Info ("ACR            : {0}" -f $AcrName)
_Info ("CAE            : {0}" -f $EnvName)
_Info ("KEDA           : {0} (max replicas {1})" -f $UseKEDA, $KedaMaxReplicas)

# ---------- Set $global:SI_Bootstrap_* so Bootstrap-ContainerAppJob's layered resolver picks them up ----------
$global:SI_Bootstrap_ResourceGroupName = $ResourceGroupName
$global:SI_Bootstrap_Location          = $Location
$global:SI_Bootstrap_AcrName           = $AcrName
$global:SI_Bootstrap_EnvName           = $EnvName

# ---------- Invoke Bootstrap-ContainerAppJob.ps1 ----------
_Step "invoke Bootstrap-ContainerAppJob.ps1"
$bootstrapArgs = @{
    ResourceGroupName  = $ResourceGroupName
    Location           = $Location
    AcrName            = $AcrName
    EnvName            = $EnvName
    UseManagedIdentity = $true
    KedaMaxReplicas    = $KedaMaxReplicas
}
if ($UseKEDA) { $bootstrapArgs.UseKEDA = $true }

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

# ---------- Capture resource IDs ----------
_Step "capture resource IDs for /api/apply response"
$acrLoginServer = $null
try {
    $acr = & az acr show --name $AcrName --resource-group $ResourceGroupName --output json 2>&1 | ConvertFrom-Json -ErrorAction Stop
    $acrLoginServer = $acr.loginServer
} catch {
    _Warn ("could not read ACR loginServer: {0}" -f $_.Exception.Message)
}

$envResourceId = $null
try {
    $env = & az containerapp env show --name $EnvName --resource-group $ResourceGroupName --output json 2>&1 | ConvertFrom-Json -ErrorAction Stop
    $envResourceId = $env.id
} catch {
    _Warn ("could not read CAE ResourceId: {0}" -f $_.Exception.Message)
}

$jobs = @()
try {
    $jobList = & az containerapp job list --resource-group $ResourceGroupName --output json 2>&1 | ConvertFrom-Json -ErrorAction Stop
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
    Jobs            = $jobs
    UseKEDA         = $UseKEDA
    KedaMaxReplicas = $KedaMaxReplicas
}
