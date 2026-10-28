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

    # Storage account name. When NOT supplied, fall back to $global:SI_StorageAccount
    # (set by custom.ps1 / Bootstrap-Storage.ps1). The account is always reached with
    # the run's signed-in identity. Lets the typical call shrink to:
    #   .\Invoke-SIEngineRun.ps1 -Engine azure -Sinks LA -ForceFullRun
    [Parameter(ParameterSetName = 'Real')]
    [string]$StorageAccountName,

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

    # #475 -- the Collect stage in parts (KEDA): 'discover' = the PRODUCER (Schedule + Discover; discovery writes every
    # object into its part and decides the part count); 'parts' = a WORKER (Collect onward, on part -ShardIndex of the
    # producer's run -RunId); 'all' = the whole run in one process (as before).
    [Parameter()]
    [ValidateSet('all', 'discover', 'parts')]
    [string]$Phase = 'all',

    # the producer's run id ('parts' only): the worker reads what the producer wrote under it
    [Parameter()]
    [string]$RunId = '',

    [Parameter()]
    [string]$RootPath = $PSScriptRoot
)

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-AzRest.ps1') }

$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------
#  -WhatIfMode = a DRY RUN (#257). It used to REFUSE (#22: the switch had been inert, and a "dry run"
#  created infrastructure, wrote the fingerprint cache and ingested). Now the run collects, enriches and
#  classifies as normal and writes its result to local JSON / CSV files only. NOT written:
#    * Log Analytics (profile rows, tag activity, schema audit, Defender recommendations, run health)
#    * Azure resources: no run creates any or assigns a role (and a dry run does not check them either)
#    * the fingerprint cache (it would make the next REAL run skip the assets this run saw)
#    * the CMDB cache refresh, the schema-discovery rule drafts and its baseline
#  Still used: the run's own staging area in the SecurityInsight storage account (the stages hand their
#  work to each other through it) and the AI result caches -- working space, not results anyone reads.
#  Note -Mock is a different thing: it fakes the DATA source.
# ----------------------------------------------------------------------
$script:SIWhatIf = [bool]$global:WhatIfMode
if ($script:SIWhatIf) {
    $Sinks = @($Sinks | Where-Object { $_ -notin 'LA', 'Eventhouse' })
    if ($Sinks.Count -eq 0) { $Sinks = @('JSON') }
}

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
# v2.2.278 -- bridge from internal-AutomateIT framework's HighPriv_Modern_*_Azure
# globals (set by Connect-Platform). Without this bridge, internal SPN+cert installs
# saw Connect-* fall through to the secret branch on reconnect because $global:SpnCertificateThumbprint
# stayed empty. SI_SPN_* > HighPriv_* precedence (community customer overrides win).
if ($global:HighPriv_Modern_TenantID                       -and -not $global:SpnTenantId)              { $global:SpnTenantId              = [string]$global:HighPriv_Modern_TenantID }
if ($global:HighPriv_Modern_ApplicationID_Azure            -and -not $global:SpnClientId)              { $global:SpnClientId              = [string]$global:HighPriv_Modern_ApplicationID_Azure }
if ($global:HighPriv_Modern_ApplicationSecret_Azure        -and -not $global:SpnClientSecret)          { $global:SpnClientSecret          = [string]$global:HighPriv_Modern_ApplicationSecret_Azure }
if ($global:HighPriv_Modern_CertificateThumbprint_Azure    -and -not $global:SpnCertificateThumbprint) { $global:SpnCertificateThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }

# v2.2.349 -- REVERSE bridge: legacy $global:Spn* + HighPriv_* -> canonical
# $global:SI_SPN_*. Stages downstream (Invoke-Output.ps1, Send-SIRunHealthRow.ps1,
# Get-SIShodanKey.ps1) read the SI_SPN_* unified globals to decide cert-vs-secret
# auth + log the "auth : SPN+Cert" / "auth : SPN+Secret" line. Without this reverse
# bridge, internal-AutomateIT customers (who set HighPriv_Modern_CertificateThumbprint_Azure
# via Connect-Platform but never SI_SPN_CertThumbprint) showed up as "SPN+Secret"
# in the ingest log even though they were actually using certificate auth, and
# Invoke-Output's auth-resolver fell through to the secret branch (wrong).
if (-not $global:SI_SPN_TenantId       -and $global:SpnTenantId)              { $global:SI_SPN_TenantId       = [string]$global:SpnTenantId }
if (-not $global:SI_SPN_AppId          -and $global:SpnClientId)              { $global:SI_SPN_AppId          = [string]$global:SpnClientId }
if (-not $global:SI_SPN_Secret         -and $global:SpnClientSecret)          { $global:SI_SPN_Secret         = [string]$global:SpnClientSecret }
if (-not $global:SI_SPN_ObjectId       -and $global:SpnObjectId)              { $global:SI_SPN_ObjectId       = [string]$global:SpnObjectId }
if (-not $global:SI_SPN_CertThumbprint -and $global:SpnCertificateThumbprint) { $global:SI_SPN_CertThumbprint = [string]$global:SpnCertificateThumbprint }
# v2.2.349 -- when cert auth is in play, BLANK out SI_SPN_Secret so the downstream
# auth-resolvers ($useCert = -not $useMi -and -not IsNullOrWhiteSpace $spnCertThumb)
# unambiguously pick the cert branch. Internal-AutomateIT installs that have BOTH
# secret AND cert populated were silently being treated as secret-auth (cert branch
# preferred only when explicitly set + secret empty -- see Invoke-Output.ps1:367,
# which prioritises cert via $useCert variable but the auth-NOTE check ran the
# wrong way).
if ($global:SI_SPN_CertThumbprint -and $global:SI_SPN_Secret) {
    # Defensive: if BOTH are set the operator probably copy-pasted both into config
    # without realising. Cert wins (matches Connect-AzAccount precedence; cert is
    # the more secure option) -- and we surface the override in the log so the
    # operator can confirm intent.
    Write-Warning ("Auth conflict: both SI_SPN_CertThumbprint and SI_SPN_Secret are populated. Cert wins. Clear `$global:SI_SPN_Secret to silence this warning.")
    $global:SI_SPN_Secret = $null
}

# auto-load customer-overlay file each engine launch.
# Lookup order (first hit wins; cycle stops at filesystem root):
#   1. $global:SI_CustomConfigPath  (explicit override set in $PROFILE / launcher)
#   2. SOLUTIONS/SecurityInsight/config/SecurityInsight.custom.ps1
#      (relative to this script's location -- standard internal-VM layout)
# Customers no longer have to manually re-source custom.ps1 after editing it;
# every `& '.\Invoke-SIEngineRun.ps1' ...' picks up the latest globals.
# Skipped silently when nothing is found (mock / CI / minimal layouts).
# WHO LOADED THE CONFIG ALREADY? A launcher (and the container entrypoint) applies the config layers
# itself -- shared defaults, custom.ps1, LauncherConfig, THEN the CLI flags that must win over all of
# them. Re-sourcing custom.ps1 here would run it AFTER those flags and silently invert that precedence.
# So the auto-load is for a DIRECT run only; the call stack says which one this is (#130).
$__calledByLauncher = @(Get-PSCallStack | Where-Object {
    $_.ScriptName -and ([System.IO.Path]::GetFileName([string]$_.ScriptName) -match '^(launcher\..+|Start-.+InContainer)\.ps1$')
}).Count -gt 0
$customConfigPath = if ($global:SI_CustomConfigPath) {
    [string]$global:SI_CustomConfigPath
} elseif ($__calledByLauncher) {
    ''
} else {
    # $PSScriptRoot = ...\SecurityInsight\engine\asset-profiling
    # one Split-Path -Parent = ...\SecurityInsight\engine
    # two Split-Path -Parent = ...\SecurityInsight            <-- the solution root, which holds config\
    # It used THREE (#130) -- a leftover of the old v2.2\ layer -- and resolved to SOLUTIONS\config\,
    # which does not exist, so a direct run silently never loaded the customer's config. $siRoot below
    # already used two; both now agree.
    Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'config/SecurityInsight.custom.ps1'   # forward slash works on both Win + Linux
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

if ($customConfigPath -and (Test-Path -LiteralPath $customConfigPath)) {
    Write-SIInfo ("loading customer config: {0}" -f $customConfigPath)
    . $customConfigPath
}

$siRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $siRoot 'engine\asset-profiling\storage\StorageContext.ps1')
. (Join-Path $siRoot 'engine\asset-profiling\storage\FingerprintCache.ps1')
. (Join-Path $siRoot 'engine\asset-profiling\storage\StagingBlob.ps1')
. (Join-Path $siRoot 'engine\asset-profiling\storage\WorkerQueue.ps1')
. (Join-Path $siRoot 'Get-FingerprintEngine.ps1')

# ---- #61: OPERATOR DECISIONS -- load the file the rest of the feature was already waiting for ----
# AFTER the customer config, because that is what sets $global:SI_AssetDecisionsPath and
# $global:SI_EnrichmentDataRoot; BEFORE the stages, because Build-EndpointProfileRow reads
# $global:SI_AssetDecisions while building rows.
#
# 🔴 THIS WIRING IS THE WHOLE FIX. The resolver, the row-builder wiring, the two columns and 36 tests
# all existed and were green while nothing populated the global -- so an operator writing
# asset-decisions.custom.yaml got no effect AND no error. Both ends of the path were built and the
# middle was not.
#
# DEGRADE, DO NOT DIE. A broken or missing decisions file must never cost the customer their inventory
# run: the load reports loudly and the computed tiers stand. The one thing it must not do is fail
# silently, which is what "no decisions" looked like before.
#
# Assign ONLY when a file was actually read. A launcher or test that set the global by hand is then
# never silently emptied by a run that simply has no file on disk.
try {
    . (Join-Path $siRoot 'engine\asset-profiling\shared\Import-SIAssetDecisions.ps1')
    $_decReport = Import-SIAssetDecisions -SolutionRoot $siRoot
    Write-SIAssetDecisionLoadReport -Report $_decReport -Info { param($m) Write-SIInfo $m }
    if (@($_decReport.Sources).Count -gt 0) {
        $global:SI_AssetDecisions = $_decReport.Decisions
    }
} catch {
    Write-Warning ("operator decisions could not be loaded ({0}) -- overrides, exceptions and exemptions are NOT in force this run; computed tiers stand." -f $_.Exception.Message)
}

# ---- v3 Phase 5: PAYLOAD PROFILE -- reset the per-run accounting BEFORE any row is built ----
# The container job runs several engines in one session, so without this reset the payload summary would
# report the PREVIOUS engine's fattest asset as this one's -- a number that looks authoritative and is
# about the wrong run, which is worse than no number at all.
# 🔑 THIS IS THE WIRING HALF, and it is the half that keeps being missed in this codebase (#61's loader,
# the class catalog, ServerAppCatalogMatch). Without the reset here AND the summary call in Invoke-Output,
# the projection would run and nobody would ever be told what it dropped.
try {
    . (Join-Path $siRoot 'engine\asset-profiling\shared\Get-SIPayloadProfile.ps1')
    Reset-SIPayloadStats
    Write-SIInfo ("   [payload] profile '{0}' selected" -f (Get-SIPayloadProfileName))
} catch {
    Write-Warning ("payload profile unavailable ({0}) -- Properties emitted unprojected (all collected metadata, the pre-v3 behaviour)." -f $_.Exception.Message)
}

# ---- v3 DATA MODEL: record capture (V3-DATA-MODEL part 2, P1) ----
# Every provider object this run reads becomes an SI record (data-model/mappings) written to the database by the Output
# stage (SQL only; SI_LaExport = records adds a copy in SI_Record_CL). Loaded BEFORE discovery, so the discovery hooks find it. SI_DataModelRecords = off switches it off.
try {
    . (Join-Path $siRoot 'engine\data-model\SI-RecordCapture.ps1')
    $null = Reset-SIRecordCapture -Engine $Engine
} catch {
    Write-Warning ("records: the record capture could not be loaded ({0}) -- the profile run is unaffected." -f $_.Exception.Message)
}

# ---- #412 ONE PULL PER SOURCE: the asset-properties level, decided ONCE, before discovery ----
# 'security' (the default, and the Community edition's only level): the sources are read exactly as before and nothing
# else is collected. 'full' (SecurityInsight Pro, SI_AssetProperties = 'full', licensed): each source is read ONCE, wide,
# the security record is built from that object, and the whole object is published to SI_AssetProperties_CL by the
# Output stage with this run's CollectionTime. The Pro file is dot-sourced HERE, at the run's own scope, so its
# functions are there for the stages. Reset on every run: a container session runs several engines.
try {
    . (Join-Path $siRoot 'engine\asset-profiling\shared\SI-FullAssetProperties.ps1')
    $__apLog = { param($l, $m) if ($l -eq 'WARN') { Write-SIWarn $m } elseif ($l -eq 'OK') { Write-SIOk $m } else { Write-SIInfo $m } }
    $__apPro = Initialize-SIFullAssetProperties -Engine $Engine -SIRoot $siRoot -Log $__apLog
    if ($__apPro) {
        . $__apPro
        Enable-SIFullAssetProperties -Engine $Engine -Log $__apLog
    }
    if (Test-SIFullAssetPropertiesOn) {
        Write-SIInfo ("   [asset properties] full -- each source is read once and kept whole for the asset page ({0})" -f ((Get-SIFullAssetPropertiesEngineSources $Engine) -join ', '))
    }
} catch {
    Write-Warning ("asset properties: the level could not be decided ({0}) -- the security level runs; the source queries are unchanged." -f $_.Exception.Message)
    if (Get-Command -Name Reset-SIFullAssetProperties -ErrorAction SilentlyContinue) { $null = Reset-SIFullAssetProperties -Engine $Engine }
}

$runId = if ($Phase -eq 'parts' -and "$RunId".Trim()) { "$RunId".Trim() } else { '{0:yyyyMMddTHHmmssZ}-{1}-{2}' -f ([datetime]::UtcNow), $Engine, [guid]::NewGuid().ToString().Substring(0,8) }   # #475: a worker uses its producer's run

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
# What the run needs in Azure: CHECKED, never created and never granted
# ============================================================================
# A collection run assigns no role and creates no resource group, workspace, data collection endpoint or storage
# account -- setup does (setup\ConfigWizard\backend\Initialize-SIInfra.ps1 creates them, setup\Grant-SIIdentity.ps1
# grants the identity). The run resolves the names the later stages read and then only LOOKS, read-only and once per
# process (shared\SI-RunAccessCheck.ps1): do the workspace, the rules' resource group and the endpoint exist, and may
# its identity send? Something missing is ONE line naming it and the setup command that fixes it; the run goes on and
# the send fails with its own error, as before. An identity that may not read its role assignments gets no line.
# Skipped when:
#   - 'LA' is not in $Sinks (nothing is sent to Log Analytics -- a dry run included)
#   - Mock mode (no Azure)
#   - the check only: a worker (-Phase parts) does not repeat what its producer checked
if ($PSCmdlet.ParameterSetName -ne 'Mock' -and $Sinks -contains 'LA') {
    try {
        . (Join-Path $PSScriptRoot 'shared\SI-RunAccessCheck.ps1')
        $_acc = Resolve-SIRunAccessTarget -Values (Get-SIRunAccessValues -StorageAccountName $StorageAccountName)
        if (-not $_acc.SubscriptionId) {
            Write-Verbose 'access check skipped: no subscription is named ($global:SI_AzSubscriptionId is not set and $global:SI_WorkspaceResourceId does not name one).'
        } else {
            # Backfill canonical globals so downstream stages see the resolved values
            if (-not $global:SI_WorkspaceResourceId) { $global:SI_WorkspaceResourceId = $_acc.WorkspaceResourceId }
            if (-not $global:SI_DceName)             { $global:SI_DceName             = $_acc.DceName }
            if (-not $global:SI_DcrResourceGroup)    { $global:SI_DcrResourceGroup    = $_acc.DcrResourceGroup }
            if (-not $global:SI_DceResourceGroup)    { $global:SI_DceResourceGroup    = $_acc.DceResourceGroup }
            if (-not $global:SI_AzSubscriptionId)    { $global:SI_AzSubscriptionId    = $_acc.SubscriptionId }

            if ($Phase -ne 'parts') { Write-SIRunAccessNote -Target $_acc -Need Send -Resources }
        }
    } catch {
        Write-Verbose ('access check skipped: {0}' -f $_.Exception.Message)
    }
}

switch ($PSCmdlet.ParameterSetName) {
    'Mock'  {
        $ctx = New-SIStorageContext -Mock
    }
    default {
        # Real (default): fall back to globals when CLI args omitted -- lets the
        # typical call simplify to '.\Invoke-SIEngineRun.ps1 -Engine azure -Sinks LA'.
        if (-not $StorageAccountName -and $global:SI_StorageAccount) { $StorageAccountName = [string]$global:SI_StorageAccount }
        if (-not $StorageAccountName) { throw 'StorageAccountName is required (pass -StorageAccountName or set $global:SI_StorageAccount in custom.ps1).' }

        # The storage account is reached ONLY with the run's signed-in identity. It needs
        # Storage Blob / Queue / Table Data Contributor on the account (granted by setup,
        # and by the container bootstrap for a job's identity; a run never grants them itself).
        $ctx = New-SIStorageContext -AccountName $StorageAccountName
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
    WhatIf           = $script:SIWhatIf
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
    Phase            = $Phase
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
if ($script:SIWhatIf) { $bannerExtra['DRY RUN'] = 'results go to local files only -- nothing is sent to Log Analytics, Azure or the caches' }
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
# The run's outcome from what it published (Get-SIRunOutcome); ingest notes belong to this run only.
. (Join-Path $PSScriptRoot '../_shared/SI-RunOutcome.ps1')
if (Get-Command -Name Reset-SILogIngestNotes -ErrorAction SilentlyContinue) { Reset-SILogIngestNotes }
$global:SI_LastRunExitReason = $null
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
    $__st = @('Schedule','Discover','Collect','Enrich','Classify','Profile','Reconcile','Output','Tagging')
    # #147 -- the azure engine also publishes every Defender for Cloud recommendation, LAST, so a problem
    # there can never cost the profile rows above.
    if ($Engine -eq 'azure') { $__st += 'Recommendations' }
    # #475: the producer discovers; a worker runs the rest on its part of the producer's run
    if ($Phase -eq 'discover') { $__st = @('Schedule', 'Discover') }
    elseif ($Phase -eq 'parts') { $__st = @($__st | Where-Object { $_ -notin 'Schedule', 'Discover' }) }
    $__st
}
# what the container needs after this run (#475): the run id and, for the producer, the part count discovery decided
$global:SI_CollectRunInfo = [pscustomobject]@{ RunId = $runId; Phase = $Phase; Parts = 0; CollectionTime = $runContext.CollectionTime }

$exitReason   = 'success'
$exitErrorMsg = ''
$assetCount   = -1
$global:SI_LicenceLimitNote = $null
try {
    $stageIdx = 0
    foreach ($s in $stages) {
        $stageStart = [datetime]::UtcNow
        Write-SIPhase ($stageIdx+1) $stages.Count $s
        . (Join-Path $stagesRoot ('Invoke-{0}.ps1' -f $s))
        $result = & ('Invoke-SI{0}' -f $s) -RunContext $runContext
        $runContext.StageResults[$s] = $result
        Write-SIDone ('{0}  ({1:n1}s)' -f $result.Summary, ([datetime]::UtcNow - $stageStart).TotalSeconds)
        # #475: discovery has copied what it needed out of the Exposure Graph identity index into each object -- let it go
        # (customer H 2026-10-08: 73,409 graph rows held for the whole run; 3.6 GB in use after Discover, then Collect ran out)
        # (the cache is this script's: the discovery functions load the fetcher inside themselves, its $script: is ours)
        if ($s -eq 'Discover' -and (Get-Variable -Name _SICache -Scope Script -ErrorAction SilentlyContinue) -and $script:_SICache -is [hashtable] -and $script:_SICache.ContainsKey('EgIdentitiesMap')) {
            if (Get-Command -Name Remove-SIDiskLookup -ErrorAction SilentlyContinue) { Remove-SIDiskLookup $script:_SICache['EgIdentitiesMap'] }   # #726: its file goes too
            $script:_SICache.Remove('EgIdentitiesMap')
            Write-SIInfo '[perms] EG identity nodes: released after discovery'
        }
        # #475: memory after every stage -- what a large tenant's run needs is read from the run log, never guessed. A full
        # collection first, so "in use" is what the run still holds, not garbage not yet collected.
        try {
            [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()
            $__p = [System.Diagnostics.Process]::GetCurrentProcess()
            Write-SIInfo ('memory after {0}: {1:N0} MB in use, {2:N0} MB peak' -f $s, ($__p.WorkingSet64 / 1MB), ($__p.PeakWorkingSet64 / 1MB))
        } catch { }
        # Capture asset count from Discover stage for the End heartbeat.
        if ($s -eq 'Discover' -and $result.PSObject.Properties['AssetCount']) {
            $assetCount = [int]$result.AssetCount
            # #474: a Pro Business licence's device limit, counted where the devices are discovered. A warning, never a
            # stop: every device is collected (SI-LicenceLimit.ps1). The END record carries the message when the limit is reached.
            if ($Engine -eq 'endpoint') {
                if (-not (Get-Command -Name Invoke-SILicenceLimitCheck -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-LicenceLimit.ps1') }
                $__lic = Invoke-SILicenceLimitCheck -Engine $Engine -DeviceCount $assetCount
                if ($__lic -and $__lic.State -in 'near', 'over', 'alarm') { $global:SI_LicenceLimitNote = [string]$__lic.Message } else { $global:SI_LicenceLimitNote = $null }
            }
        }
        $stageIdx++
    }

    # What the run PUBLISHED, not only that no stage threw: a failed Log Analytics post, an incomplete publish or new
    # columns that were not stored make the run 'success-partial' (exit code 0, as a partial Risk Analysis run); a run
    # whose every output failed is an 'error' and throws (non-zero exit code). Absence is not remediation -- a monitor,
    # Risk Analysis and the vulnerability close-loop must be able to tell a partial publish from a whole one.
    $__notes = if (Get-Command -Name Get-SILogIngestNotes -ErrorAction SilentlyContinue) { @(Get-SILogIngestNotes) } else { @() }
    $__outcome = Get-SIRunOutcome -StageResults $runContext.StageResults -IngestNotes $__notes
    if ($__outcome.ExitReason -eq 'error') {
        # The records did not reach the database: a failed collection, whatever else was written. Said as what it is, so
        # the step's error, the run-health record and the pipeline's "goes on without this source" sentence all carry it.
        if ($__outcome.PSObject.Properties['DatabaseFailed'] -and $__outcome.DatabaseFailed) {
            throw ('The records could not be written to the database -- this collection is not complete and the source stays on its last good collection: {0}' -f $__outcome.Message)
        }
        throw ('Nothing was published: {0}' -f $__outcome.Message)
    }
    $exitReason   = $__outcome.ExitReason
    $exitErrorMsg = $__outcome.Message
    # #474: the licence's device limit reached -- said on the END record too (the run's outcome is unchanged)
    if ($Engine -eq 'endpoint' -and $global:SI_LicenceLimitNote) { $exitErrorMsg = (@(@($exitErrorMsg, [string]$global:SI_LicenceLimitNote) | Where-Object { $_ }) -join ' | ') }
    $runContext | Add-Member -NotePropertyName 'ExitReason' -NotePropertyValue $exitReason -Force
    # The launcher's closing line reads this, so it never prints "completed successfully" over a partial run.
    $global:SI_LastRunExitReason = $exitReason

    Write-Host ''
    $line = '=' * 88
    if ($exitReason -eq 'success-partial') {
        Write-SIWarn $line
        Write-SIWarn (' RUN COMPLETE -- PARTIAL  *  {0}  *  {1:n1}s elapsed' -f $runId, ([datetime]::UtcNow - $runContext.StartedAt).TotalSeconds)
        Write-SIWarn (' {0}' -f $exitErrorMsg)
        Write-SIWarn $line
    } else {
        Write-SIOk $line
        Write-SIOk (' RUN COMPLETE  *  {0}  *  {1:n1}s elapsed' -f $runId, ([datetime]::UtcNow - $runContext.StartedAt).TotalSeconds)
        Write-SIOk $line
    }
    return $runContext
}
catch {
    $exitReason   = 'error'
    $exitErrorMsg = $_.Exception.Message
    # #226 -- the stage the run stopped in, for the telemetry run report (FailedStep). $s is the stage that threw.
    try { if ($s) { $runContext | Add-Member -NotePropertyName 'FailedStep' -NotePropertyValue ([string]$s).ToLowerInvariant() -Force } } catch { }
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
    # #702: a failed run lets go of what it was holding BEFORE its end record and its report to Invardia are built -- the
    # run is over, and a run that failed for memory could not build either (customer B 2026-10-15: "Run-health record could
    # not be saved: OutOfMemoryException", "The status report to Invardia could not be prepared (OutOfMemoryException)", so
    # Invardia never heard of the failure). Only on a failed run; never throws.
    if ($exitReason -eq 'error') {
        try {
            if ((Get-Variable -Name _SICache -Scope Script -ErrorAction SilentlyContinue) -and $script:_SICache -is [hashtable]) { $script:_SICache.Clear() }
            if (Get-Command -Name Get-SIAzRestState -ErrorAction SilentlyContinue) { $__st = Get-SIAzRestState; if ($__st -and $__st.Cache -is [hashtable]) { $__st.Cache.Clear() }; $__st = $null }
            $global:SI_DiscoverStream = $null; $global:SI_DiscoverStreamCounts = $null; $result = $null
            [System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers(); [System.GC]::Collect()
        } catch { }
    }
    Invoke-SIQuietBlock {
        Send-SIRunHealthRow -RunContext $runContext `
                            -Phase 'End' `
                            -AssetCount $assetCount `
                            -ExitReason $exitReason `
                            -ErrorMessage $exitErrorMsg
    }
}
