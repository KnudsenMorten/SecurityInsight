#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- top-level orchestrator entry point.

    Runs one engine end-to-end through all 6 stages. The orchestrator does
    NOT itself parallelise across collector workers -- shards are enqueued
    on the worker queue in stages 1/2/3 and a separate worker process
    pulls them. In single-host mode (Mock or small fleets), the orchestrator
    drains its own queues inline.
#>

[CmdletBinding(DefaultParameterSetName = 'Real')]
param(
    [Parameter(Mandatory)]
    [ValidateSet('endpoint','identity','azure','publicip','schema-discovery')]
    [string]$Engine,

    # Storage account name + key. When NOT supplied, fall back to
    # $global:SI_StorageAccount + $global:SI_StorageKey (set by custom.ps1
    # / Bootstrap-Storage.ps1). Lets the typical call shrink to:
    #   .\Invoke-SIEngineRun.ps1 -Engine azure -Sinks LA -ForceFullRun
    [Parameter(ParameterSetName = 'Real')]
    [Parameter(ParameterSetName = 'OAuth')]
    [string]$StorageAccountName,

    [Parameter(ParameterSetName = 'Real')]
    [string]$StorageAccountKey,

    [Parameter(Mandatory, ParameterSetName = 'OAuth')]
    [switch]$UseStorageOAuth,

    [Parameter(Mandatory, ParameterSetName = 'Mock')]
    [switch]$Mock,

    [Parameter()]
    [int]$AssetLimit = 0,

    [Parameter()]
    [string[]]$Sinks = @('LA','JSON','Excel'),

    [Parameter()]
    [int]$ShardCount = 1,

    [Parameter()]
    [int]$ShardIndex = 0,

    # Run-level CollectionTime shared across ALL shards of one execution.
    # Naming follows the AzLogDcrIngestPS convention (column name 'CollectionTime',
    # ISO-8601 UTC). Every replica MUST stamp its rows with the SAME value so
    # KQL can recover the full set via `where CollectionTime == toscalar(... |
    # summarize max(CollectionTime))`. Producer (KEDA pattern) mints once and
    # passes via queue. Without an explicit value, falls back to $env:SI_COLLECTION_TIME
    # then to floor-to-minute of UTC-now (parallel replicas booting in the same
    # minute converge on the same value).
    [Parameter()]
    [datetime]$CollectionTime,

    # Skip both fingerprint short-circuits for THIS run. Every asset re-runs
    # Enrich + Classify regardless of cache state. Used after rule/prompt
    # changes invalidate prior verdicts. Resolution order (highest wins):
    #   1. -ForceFullRun switch on CLI
    #   2. $env:SI_FORCE_FULL_RUN = '1'
    #   3. $global:SI_ForceFullRun = $true (custom.ps1)
    [Parameter()]
    [switch]$ForceFullRun,

    [Parameter()]
    [string]$RootPath = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

# v2.2.233 -- SPN name bridge (defensive copy of Initialize-LauncherConfig).
# The v2.3 Setup Wizard writes $global:SI_SPN_* (unified names). Engines / shared
# auth helpers still read the legacy $global:Spn* names. Initialize-LauncherConfig
# does the mirror -- but if the engine is invoked outside the standard launcher
# path (AF bootstrap, custom orchestrator, direct call), the legacy names stay
# $null and SPN+cert auth in particular falls through every elseif branch.
if ($global:SI_SPN_TenantId        -and -not $global:SpnTenantId)              { $global:SpnTenantId              = [string]$global:SI_SPN_TenantId }
if ($global:SI_SPN_AppId           -and -not $global:SpnClientId)              { $global:SpnClientId              = [string]$global:SI_SPN_AppId }
if ($global:SI_SPN_Secret          -and -not $global:SpnClientSecret)          { $global:SpnClientSecret          = [string]$global:SI_SPN_Secret }
if ($global:SI_SPN_ObjectId        -and -not $global:SpnObjectId)              { $global:SpnObjectId              = [string]$global:SI_SPN_ObjectId }
if ($global:SI_SPN_CertThumbprint  -and -not $global:SpnCertificateThumbprint) { $global:SpnCertificateThumbprint = [string]$global:SI_SPN_CertThumbprint }

# auto-load customer-overlay file each engine launch.
# Lookup order (first hit wins; cycle stops at filesystem root):
#   1. $global:SI_CustomConfigPath  (explicit override set in $PROFILE / launcher)
#   2. SOLUTIONS/SecurityInsight/config/SecurityInsight.custom.ps1
#      (relative to this script's location -- standard internal-VM layout)
# Customers no longer have to manually re-source custom.ps1 after editing it;
# every `& '.\Invoke-SIEngineRun.ps1' ...' picks up the latest globals.
# Skipped silently when nothing is found (mock / CI / minimal layouts).
$customConfigPath = if ($global:SI_CustomConfigPath) {
    [string]$global:SI_CustomConfigPath
} else {
    # $PSScriptRoot = ...\SecurityInsight\engine\asset-profiling
    # one Split-Path -Parent   = ...\SecurityInsight\engine
    # two Split-Path -Parent   = ...\SecurityInsight\v2.2
    # three Split-Path -Parent = ...\SecurityInsight  <-- target parent of config
    # had THREE Split-Path calls (correct under earlier layout, wrong
    # mid-restructure); current asset-profiling/ depth needs THREE again.
    Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'config/SecurityInsight.custom.ps1'   # forward slash works on both Win + Linux
}
# ----------------------------------------------------------------------
# Visual style helpers (Write-SIBanner / -Phase / -Step / -Ok / -Err /
# -Warn / -Info / -Done + Invoke-SIQuietBlock for Az SDK noise).
# Dot-source BEFORE custom-config + module probes so first-line output
# is already styled.
# ----------------------------------------------------------------------
. (Join-Path $PSScriptRoot '_shared/Write-SIStyle.ps1')

# -Verbose switch: wires both PS-standard $VerbosePreference (so stage code
# that calls Write-Verbose surfaces) AND a script-scope $script:SIVerbose
# flag so we can decide on extras (full error stack traces, SDK HTTP
# traces, per-shard inventory dump, per-rule trace). When NOT passed, the
# AzLogDcrIngestPS / Az SDK VERBOSE storms are suppressed by Invoke-
# SIQuietBlock; only [STEP]/[OK]/[INFO]/[WARN]/[ERR] markers reach the
# console. Pass -Verbose to debug.
$script:SIVerbose = $PSBoundParameters.ContainsKey('Verbose') -and [bool]$PSBoundParameters['Verbose']
if ($script:SIVerbose) {
    $global:VerbosePreference = 'Continue'
    $ErrorView = 'NormalView'    # full PS error formatting (default)
} else {
    $global:VerbosePreference = 'SilentlyContinue'
}

if (Test-Path $customConfigPath) {
    Write-SIInfo ("loading customer config: {0}" -f $customConfigPath)
    . $customConfigPath
}

$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $siRoot 'engine\asset-profiling\storage\StorageContext.ps1')
. (Join-Path $siRoot 'engine\asset-profiling\storage\FingerprintCache.ps1')
. (Join-Path $siRoot 'engine\asset-profiling\storage\StagingBlob.ps1')
. (Join-Path $siRoot 'engine\asset-profiling\storage\WorkerQueue.ps1')
. (Join-Path $siRoot 'Get-FingerprintEngine.ps1')

$runId = '{0:yyyyMMddTHHmmssZ}-{1}-{2}' -f ([datetime]::UtcNow), $Engine, [guid]::NewGuid().ToString().Substring(0,8)

# ---- CollectionTime (shared across all shards of one execution) ----
# Resolution order documented above on parameter declaration.
if (-not $PSBoundParameters.ContainsKey('CollectionTime')) {
    $envCt = [Environment]::GetEnvironmentVariable('SI_COLLECTION_TIME')
    if ($envCt) {
        $CollectionTime = [datetime]::Parse($envCt, $null, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
    } else {
        # Floor to minute -- parallel replicas launched within the same minute
        # converge on the same value. KEDA producer should override explicitly.
        $now = [datetime]::UtcNow
        $CollectionTime = [datetime]::new($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0, [DateTimeKind]::Utc)
    }
}

# ============================================================================
# Prestage infra (greenfield-friendly)
# ============================================================================
# Runs BEFORE the storage validation below so the prestage can create the
# storage account + backfill $global:SI_StorageKey from key1, satisfying
# the StorageAccountKey check on the first run. Also creates workspace + DCE
# + DCR RGs + RBAC. Read-then-write idempotent. Skipped when:
#   - $global:SI_PrestageInfra = $false (operator opt-out)
#   - 'LA' is not in $Sinks (no LA ingest needed -> no infra needed)
#   - Mock mode (no Azure)
if ($PSCmdlet.ParameterSetName -ne 'Mock' -and $Sinks -contains 'LA' -and $global:SI_PrestageInfra -ne $false) {
    try {
        . (Join-Path $PSScriptRoot 'shared\Invoke-SIPrestageInfra.ps1')

        $_subId  = $global:SI_AzSubscriptionId
        $_wsRg   = if ($global:SI_WorkspaceResourceGroup) { $global:SI_WorkspaceResourceGroup } else { 'rg-securityinsight' }
        $_wsName = if ($global:SI_WorkspaceName)          { $global:SI_WorkspaceName }          else { 'log-platform-management-securityinsight' }
        # If WorkspaceResourceId is set, parse sub from it (canonical source)
        if ($global:SI_WorkspaceResourceId -match '/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/[^/]+/workspaces/([^/?]+)') {
            if (-not $_subId)  { $_subId  = $Matches[1] }
            if (-not $_wsRg -or $_wsRg -eq 'rg-securityinsight')                       { $_wsRg  = $Matches[2] }
            if (-not $_wsName -or $_wsName -eq 'log-platform-management-securityinsight') { $_wsName = $Matches[3] }
        }
        $_dceRg   = if ($global:SI_DceResourceGroup) { $global:SI_DceResourceGroup } else { 'rg-securityinsight' }
        $_dcrRg   = if ($global:SI_DcrResourceGroup) { $global:SI_DcrResourceGroup } else { 'rg-securityinsight' }
        $_dceName = if ($global:SI_DceName)          { $global:SI_DceName }          else { 'dce-si-securityinsight' }
        $_loc     = if ($global:SI_Location)         { $global:SI_Location }         else { 'westeurope' }
        $_wsId    = if ($global:SI_WorkspaceResourceId) { $global:SI_WorkspaceResourceId } else { "/subscriptions/$_subId/resourceGroups/$_wsRg/providers/Microsoft.OperationalInsights/workspaces/$_wsName" }
        $_stAcct  = if ($StorageAccountName)            { $StorageAccountName }            else { $global:SI_StorageAccount }
        $_stRg    = if ($global:SI_StorageResourceGroup) { $global:SI_StorageResourceGroup } else { '' }
        $_spnObj  = if ($global:SI_SPN_ObjectId)         { $global:SI_SPN_ObjectId }         else { $global:SI_LogIngest_ObjectId }

        if (-not $_subId) {
            Write-Warning 'Prestage SKIPPED: $global:SI_AzSubscriptionId not set and not parseable from $global:SI_WorkspaceResourceId.'
        } elseif (-not $_spnObj) {
            Write-Warning 'Prestage SKIPPED: $global:SI_SPN_ObjectId not set (RBAC grants need it).'
        } else {
            Invoke-SIPrestageInfra `
                -WorkspaceName            $_wsName `
                -WorkspaceResourceGroup   $_wsRg `
                -WorkspaceResourceId      $_wsId `
                -DcrResourceGroup         $_dcrRg `
                -DceResourceGroup         $_dceRg `
                -DceName                  $_dceName `
                -StorageAccountName       $_stAcct `
                -StorageResourceGroup     $_stRg `
                -Location                 $_loc `
                -SubscriptionId           $_subId `
                -SpnObjectId              $_spnObj

            # Backfill canonical globals so downstream stages see the resolved values
            if (-not $global:SI_WorkspaceResourceId) { $global:SI_WorkspaceResourceId = $_wsId }
            if (-not $global:SI_DceName)             { $global:SI_DceName             = $_dceName }
            if (-not $global:SI_DcrResourceGroup)    { $global:SI_DcrResourceGroup    = $_dcrRg }
            if (-not $global:SI_DceResourceGroup)    { $global:SI_DceResourceGroup    = $_dceRg }
            if (-not $global:SI_AzSubscriptionId)    { $global:SI_AzSubscriptionId    = $_subId }
        }
    } catch {
        Write-Warning ('Prestage at engine entry failed (continuing -- storage / LA may fail downstream): {0}' -f $_.Exception.Message)
    }
}

switch ($PSCmdlet.ParameterSetName) {
    'Mock'  {
        $ctx = New-SIStorageContext -Mock
    }
    'OAuth' {
        if (-not $StorageAccountName -and $global:SI_StorageAccount) { $StorageAccountName = [string]$global:SI_StorageAccount }
        if (-not $StorageAccountName) { throw 'StorageAccountName is required (pass -StorageAccountName or set $global:SI_StorageAccount in custom.ps1).' }
        $ctx = New-SIStorageContext -AccountName $StorageAccountName -UseOAuth
    }
    default {
        # Real (default): fall back to globals when CLI args omitted -- lets the
        # typical call simplify to '.\Invoke-SIEngineRun.ps1 -Engine azure -Sinks LA'.
        if (-not $StorageAccountName -and $global:SI_StorageAccount) { $StorageAccountName = [string]$global:SI_StorageAccount }
        if (-not $StorageAccountKey  -and $global:SI_StorageKey)     { $StorageAccountKey  = [string]$global:SI_StorageKey }
        if (-not $StorageAccountName) { throw 'StorageAccountName is required (pass -StorageAccountName or set $global:SI_StorageAccount in custom.ps1).' }

        # Auth resolution priority (v2.2.79+):
        #   1. $global:SI_UseStorageOAuth = $true  -> OAuth (explicit operator opt-in)
        #   2. No StorageAccountKey AND no $global:SI_StorageKey -> OAuth (sensible default;
        #      since v2.2.55 the prestage grants the SPN Storage Blob/Table/Queue Data
        #      Contributor on the SA, so OAuth Just Works for new installs).
        #   3. Otherwise -> SharedKey (back-compat for installs that already have a key).
        # To force SharedKey on a customer with both globals set, set
        # $global:SI_UseStorageOAuth = $false explicitly in custom.ps1.
        $useOAuth = $false
        if ($PSBoundParameters.ContainsKey('SI_UseStorageOAuth') -or ($null -ne $global:SI_UseStorageOAuth)) {
            $useOAuth = [bool]$global:SI_UseStorageOAuth
        } elseif ([string]::IsNullOrWhiteSpace($StorageAccountKey)) {
            $useOAuth = $true
        }
        if ($useOAuth) {
            $ctx = New-SIStorageContext -AccountName $StorageAccountName -UseOAuth
        } else {
            if (-not $StorageAccountKey) { throw 'StorageAccountKey is required (pass -StorageAccountKey or set $global:SI_StorageKey in custom.ps1; or use -UseStorageOAuth for AAD-based storage auth).' }
            $ctx = New-SIStorageContext -AccountName $StorageAccountName -AccountKey $StorageAccountKey
        }
    }
}

$tableName     = Initialize-SIFingerprintTable -Context $ctx
$containerName = Initialize-SIStagingContainer -Context $ctx
foreach ($q in @('discover','collect','enrich','classify')) {
    Initialize-SIQueue -Context $ctx -QueueName "si-$Engine-$q" | Out-Null
}

# ForceFullRun resolution: CLI switch > env var > custom-file global.
$forceFullRun = [bool]$ForceFullRun
if (-not $forceFullRun) {
    $envFf = [Environment]::GetEnvironmentVariable('SI_FORCE_FULL_RUN')
    if ($envFf -in '1','true','True','yes') { $forceFullRun = $true }
}
if (-not $forceFullRun -and $global:SI_ForceFullRun) { $forceFullRun = $true }

$runContext = [pscustomobject]@{
    RunId            = $runId
    CollectionTime   = $CollectionTime
    ForceFullRun     = $forceFullRun
    Engine           = $Engine
    StartedAt        = [datetime]::UtcNow
    AssetLimit       = $AssetLimit
    Sinks            = $Sinks
    ShardCount       = $ShardCount
    ShardIndex       = $ShardIndex
    StorageContext   = $ctx
    FingerprintTable = $tableName
    StagingContainer = $containerName
    StageResults     = @{}
}

$siVersion = 'unknown'
$verFile = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'VERSION'
if (Test-Path $verFile) { $siVersion = (Get-Content -Raw $verFile).Trim() }

# Pretty engine-name + service domain for the banner.
$engineLabel = switch ($Engine) {
    'identity'         { 'Asset Profiling - Identity (users + service principals)' }
    'endpoint'         { 'Asset Profiling - Endpoint (devices + servers)' }
    'azure'            { 'Asset Profiling - Azure (resources + management groups)' }
    'publicip'         { 'Asset Profiling - Public IP (Shodan + Azure publicIPAddresses)' }
    'schema-discovery' { 'Schema Discovery (meta-engine)' }
    default            { "Asset Profiling - $Engine" }
}

# Banner with engine + version + run details. Shown on every invocation.
$bannerExtra = [ordered]@{
    'CollectionTime' = ('{0:u}' -f $CollectionTime)
    'ForceFullRun'   = $forceFullRun
    'Sinks'          = ($Sinks -join ', ')
    'AssetLimit'     = $(if ($AssetLimit -le 0) { 'no limit' } else { $AssetLimit })
    'Verbose'        = $script:SIVerbose
}
if ($ShardCount -gt 1) { $bannerExtra['Sharding'] = ('replica {0} of {1}' -f ($ShardIndex+1), $ShardCount) }

Write-SIBanner -Engine $engineLabel `
               -Version ('v{0}' -f $siVersion) `
               -RunId   $runId `
               -Mode    $ctx.Mode `
               -Extra   $bannerExtra

# Per-shard heartbeat -> SI_RunHealth_CL. Start row goes out before any
# work begins; End row goes out in the finally block below (success OR
# failure). A Start row with no matching End row is the signal that this
# replica was killed (OOM, container crash) -- KQL detects via leftanti join.
. (Join-Path $PSScriptRoot 'shared\Send-SIRunHealthRow.ps1')
# RunHealth ingest emits a wall of `VERBOSE: GET https://...` from
# AzLogDcrIngestPS / Az SDK. Silence unless caller passed -Verbose.
Invoke-SIQuietBlock { Send-SIRunHealthRow -RunContext $runContext -Phase 'Start' }

$stagesRoot = Join-Path $PSScriptRoot 'stages'
# Stage list -- order is the contract. Names map to file Invoke-<Name>.ps1 +
# function Invoke-SI<Name> in stages/. Index for the log line is computed
# at runtime so renumbering doesn't touch identifiers.
# Stage list per engine. Asset-profiling engines (endpoint/identity/azure)
# share the 7-stage pipeline. The schema-discovery meta-engine runs a
# completely different set: enumerate EG/hunting schema -> diff against
# stored baseline -> AI-propose rules for new findings -> write drafts to
# posture-rules-pending/ + audit to SI_SchemaCatalog_CL.
$stages = if ($Engine -eq 'schema-discovery') {
    @('Schedule','SchemaDiscover','SchemaDiff','SchemaPropose','SchemaOutput')
} else {
    # Profile + Reconcile slot in between Classify and Output.
    # Profile evaluates AssetProfileBy* YAML rules and overlays SI_RuleMatches /
    # SI_RuleTier onto Verdict (final tier becomes MIN of existing + rule-derived).
    # Reconcile re-enabled. disabled it under the
    # impression it ran cross-engine lookups (those actually live in Enrich) --
    # in fact Reconcile is the CMDB-merge stage. Without it Properties.collect.
    # cmdb stays empty and CMDB columns (cmdbId/cmdbName/etc.) never populate.
    @('Schedule','Discover','Collect','Enrich','Classify','Profile','Reconcile','Output','Tagging')
}

$exitReason   = 'success'
$exitErrorMsg = ''
$assetCount   = -1
try {
    $stageIdx = 0
    foreach ($s in $stages) {
        $stageStart = [datetime]::UtcNow
        Write-SIPhase ($stageIdx+1) $stages.Count $s
        . (Join-Path $stagesRoot ('Invoke-{0}.ps1' -f $s))
        $result = & ('Invoke-SI{0}' -f $s) -RunContext $runContext
        $runContext.StageResults[$s] = $result
        Write-SIDone ('{0}  ({1:n1}s)' -f $result.Summary, ([datetime]::UtcNow - $stageStart).TotalSeconds)
        # Capture asset count from Discover stage for the End heartbeat.
        if ($s -eq 'Discover' -and $result.PSObject.Properties['AssetCount']) {
            $assetCount = [int]$result.AssetCount
        }
        $stageIdx++
    }

    Write-Host ''
    $line = '=' * 88
    Write-SIOk $line
    Write-SIOk (' RUN COMPLETE  *  {0}  *  {1:n1}s elapsed' -f $runId, ([datetime]::UtcNow - $runContext.StartedAt).TotalSeconds)
    Write-SIOk $line
    return $runContext
}
catch {
    $exitReason   = 'error'
    $exitErrorMsg = $_.Exception.Message
    Write-Host ''
    $line = '=' * 88
    Write-SIErr $line
    Write-SIErr (' RUN FAILED  *  {0}  *  {1:n1}s elapsed' -f $runId, ([datetime]::UtcNow - $runContext.StartedAt).TotalSeconds)
    Write-SIErr $line
    Write-SIErr  $exitErrorMsg
    if ($script:SIVerbose) {
        Write-Host ''
        Write-Host '  --- VERBOSE: full exception detail ---' -ForegroundColor White
        Write-Host ($_ | Format-List -Property * -Force | Out-String) -ForegroundColor White
        if ($_.ScriptStackTrace) {
            Write-Host '  --- VERBOSE: script stack trace ---' -ForegroundColor White
            Write-Host $_.ScriptStackTrace -ForegroundColor White
        }
    } else {
        Write-Host ''
        Write-Host '  Re-run with -Verbose for the full exception + stack trace.' -ForegroundColor White
    }
    throw
}
finally {
    Invoke-SIQuietBlock {
        Send-SIRunHealthRow -RunContext $runContext `
                            -Phase 'End' `
                            -AssetCount $assetCount `
                            -ExitReason $exitReason `
                            -ErrorMessage $exitErrorMsg
    }
}
