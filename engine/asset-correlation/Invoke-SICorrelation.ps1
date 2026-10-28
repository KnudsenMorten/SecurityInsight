#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight_AssetCorrelation -- the fifth SI engine. Resolves the per-source profile rows into
    one object per real-world asset and publishes the identity map as SI_ObjectMap_CL.

.DESCRIPTION
    v2 answers "what is wrong". This is the layer that answers "on WHICH object", and nothing downstream
    -- the ServiceNow connector, the tier rework, cross-domain reporting -- can be correct without it.

    IT MUST BE A POST-PASS, and that is measured rather than assumed. The profilers run staggered: a
    real run went identity 15:00 -> azure 15:17 -> endpoint 15:26 -> publicip 15:30. When the azure
    engine runs, THIS cycle's endpoint rows do not exist yet, which is exactly why the one existing
    cross-engine cache reads PRIOR runs and degrades silently to nothing. Correlating inside a profiler
    can only ever join against yesterday.

    A MAP, NOT A MERGED ROW. The raw per-source rows are retained untouched: correlation is a hypothesis,
    and you can only un-merge while the originals still exist.

.NOTES
    Solution : SecurityInsight
    Engine   : asset-correlation
    Docs     : docs/V3-ARCHITECTURE.md 2.3 / 2.4  ·  docs/REQUIREMENTS.md 60.5.5

    STATE, 2026-08-12: LA is the store. The design says "SQL computes and holds, LA publishes", and the
    SQL half waits on SCHEMA-1 (needsSchema: true would run migrations unattended on ~30 customers).
    Correctness does not depend on it -- the seed is deterministic, so an object recomputes to the same
    SI_CorrelationId every run with no memory of the last one. SQL buys key-stability memory and an
    ambiguity queue, which are improvements on a property the core already holds, not prerequisites.
#>
[CmdletBinding()]
param(
    # Correlate and report, publish nothing. The honest first run: it shows what WOULD be written
    # without creating a table or a DCR.
    [switch]$DryRun,

    # Cap rows per engine. Diagnostics only -- a partial snapshot SPLITS objects whose other half was
    # not read, so never judge correlation quality from a limited run.
    [int]$RowLimit = 0,

    # Write the map rows to a JSON file as well. Useful before the ~45-minute ingest window has passed.
    [string]$JsonOutPath,

    # ⏱️ Require every engine's snapshot to be at least this new (UTC) before correlating, waiting for
    # Log Analytics ingest if it is not. An orchestrator that has just run the profilers should pass the
    # time it started them. Unset is the standalone case: correlate over the last data that was sent,
    # however old it is -- with a warning past 24h and a louder one past 7 days.
    [datetime]$ExpectFreshSince = [datetime]::MinValue
)

$ErrorActionPreference = 'Stop'
try { Set-StrictMode -Off } catch { }

function Write-CorrStep ($m) { Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Write-CorrInfo ($m) { Write-Host "[INFO] $m" -ForegroundColor Gray }
function Write-CorrOk   ($m) { Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-CorrWarn ($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }

. (Join-Path $PSScriptRoot '_shared/SI-CorrelationCore.ps1')
. (Join-Path $PSScriptRoot '_shared/SI-CorrelationIngest.ps1')
# #61.4 -- after the core, because the anchor parser folds id-type aliases through
# Get-SICanonicalIdType and must not fall back to raw types in a real run.
. (Join-Path $PSScriptRoot '_shared/SI-CorrelationDecisions.ps1')
# #639 the map at millions of assets: read in parts, staged and grouped in SQL, correlated a batch at a time
. (Join-Path $PSScriptRoot '_shared/SI-CorrelationPaged.ps1')

# ---- AUTH BRIDGE: HighPriv_Modern_* -> SI_SPN_* -----------------------------------------------------
# 🔴 WITHOUT THIS, CERTIFICATE AUTH SILENTLY BECOMES "NO AUTH" AND THE FIRST PUBLISH FAILS.
#
# Found 2026-08-12 on the first real (non-DryRun) run of this engine. On the internal-vm flavour the
# identity comes from Connect-Platform, which populates the platform contract --
# HighPriv_Modern_CertificateThumbprint_Azure, HighPriv_Modern_AuthMethod = 'Cert' -- and NEVER
# SI_SPN_CertThumbprint. Resolve-SICorrelationAuthParams reads only the SI_SPN_* names, so its
# $useCert test saw an empty thumbprint, fell through to the secret branch, and returned
# AzAppSecret = $null on a tenant that has no secret at all.
#
# 🪤 THE FAILURE IS SILENT AND LANDS SOMEWHERE ELSE. AzLogDcrIngestPS gates its whole
# create-table-and-DCR body on `($AzAppId) -and (($AzAppSecret) -or ($AzAppCertificateThumbprint))`.
# With neither, it returns having done nothing and says nothing -- and the engine's `4>$null` discards
# even that. The DCR is never created, and the error finally surfaces two calls later as
# "Cannot bind argument to parameter 'DcrImmutableId' because it is an empty string", which reads like
# a DCR-lookup bug and is nothing of the kind.
#
# 📌 This is the SAME root cause as five of v2.2.426-432, and the v2 handoff predicted exactly this:
# "if another engine only reads $global:Spn*Secret, assume the same bug is there". It was.
#
# 🔒 DUPLICATED FROM Invoke-SIEngineRun.ps1 (v2.2.278 + v2.2.349) ON PURPOSE. Refactoring both onto a
# shared helper would edit the profiler's entry path, which ships to ~30 customers and works today.
# Isolation beats DRY here -- the house rule, and this is precisely the case it is for.
# Precedence: SI_SPN_* (an explicit customer override) wins over the platform globals.
if (-not $global:SI_SPN_TenantId       -and $global:HighPriv_Modern_TenantID)                    { $global:SI_SPN_TenantId       = [string]$global:HighPriv_Modern_TenantID }
if (-not $global:SI_SPN_TenantId       -and $global:SpnTenantId)                                 { $global:SI_SPN_TenantId       = [string]$global:SpnTenantId }
if (-not $global:SI_SPN_AppId          -and $global:HighPriv_Modern_ApplicationID_Azure)         { $global:SI_SPN_AppId          = [string]$global:HighPriv_Modern_ApplicationID_Azure }
if (-not $global:SI_SPN_AppId          -and $global:SpnClientId)                                 { $global:SI_SPN_AppId          = [string]$global:SpnClientId }
if (-not $global:SI_SPN_ObjectId       -and $global:SpnObjectId)                                 { $global:SI_SPN_ObjectId       = [string]$global:SpnObjectId }
if (-not $global:SI_SPN_CertThumbprint -and $global:HighPriv_Modern_CertificateThumbprint_Azure) { $global:SI_SPN_CertThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }
if (-not $global:SI_SPN_CertThumbprint -and $global:SpnCertificateThumbprint)                    { $global:SI_SPN_CertThumbprint = [string]$global:SpnCertificateThumbprint }
if (-not $global:SI_SPN_Secret         -and $global:HighPriv_Modern_ApplicationSecret_Azure)     { $global:SI_SPN_Secret         = [string]$global:HighPriv_Modern_ApplicationSecret_Azure }
if (-not $global:SI_SPN_Secret         -and $global:SpnClientSecret)                             { $global:SI_SPN_Secret         = [string]$global:SpnClientSecret }
# Cert wins when both are present, matching Connect-AzAccount precedence and the profiler's v2.2.349
# behaviour. Blanked rather than merely deprioritised so every downstream $useCert test agrees.
if ($global:SI_SPN_CertThumbprint -and $global:SI_SPN_Secret) {
    Write-CorrWarn 'Auth conflict: both SI_SPN_CertThumbprint and SI_SPN_Secret are populated. Cert wins.'
    $global:SI_SPN_Secret = $null
}
# 🔒 FAIL LOUD RATHER THAN PUBLISH NOTHING. Reaching the ingest with no usable credential produced an
# error that named the wrong component and cost a diagnosis; say it here, where the answer is.
if ([string]::IsNullOrWhiteSpace([string]$global:SI_SPN_CertThumbprint) -and
    [string]::IsNullOrWhiteSpace([string]$global:SI_SPN_Secret) -and
    -not ($global:SI_PreferUami -and $global:SI_UAMI_ClientId)) {
    throw ('correlation: no usable credential. SI_SPN_AppId={0}; no certificate thumbprint, no secret, no managed identity. ' -f $global:SI_SPN_AppId) +
          'On the internal-vm flavour these come from Connect-Platform (HighPriv_Modern_*); on community installs from config\SecurityInsight.custom.ps1 (SI_SPN_*).'
}
Write-CorrInfo ("auth      : {0}" -f $(
    if ($global:SI_PreferUami -and $global:SI_UAMI_ClientId) { 'managed identity' }
    elseif ($global:SI_SPN_CertThumbprint) { 'SPN + certificate' }
    else { 'SPN + secret' }))

# The engines to correlate across, and the table each publishes. publicip is included because a public
# IP bound to an Azure resource carries the ARM id, so it joins -- it is not only an endpoint/azure story.
$engineTables = @{
    endpoint = 'SI_Endpoint_Profile_CL'
    identity = 'SI_Identity_Profile_CL'
    azure    = 'SI_Azure_Profile_CL'
    publicip = 'SI_PublicIP_Profile_CL'
}

if ([string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId)) {
    throw 'correlation: $global:SI_WorkspaceResourceId is empty. Run this through its launcher so the layered config is loaded, not directly.'
}

# One RunId and ONE CollectionTime for the whole execution. Identical across every row this run emits,
# so `where CollectionTime == max(CollectionTime)` selects a complete map rather than a ragged mix.
$runId          = [guid]::NewGuid().ToString()
$collectionTime = [datetime]::UtcNow
$startedAt      = $collectionTime

Write-CorrStep 'SecurityInsight -- AssetCorrelation'
# The Community edition and Pro alike (owner 2026-10-27, SI #750 (1) / #678): cross-engine correlation is not a paid feature,
# so this job has no licence gate (engine/SI-FeatureCatalog.ps1 no longer lists 'correlation').
Write-CorrInfo ("workspace : {0}" -f $global:SI_WorkspaceResourceId)
Write-CorrInfo ("RunId     : {0}" -f $runId)
if ($DryRun)      { Write-CorrWarn 'DRY RUN -- correlating and reporting only. Nothing is published, and the identity ledger is READ but never written.' }
if ($RowLimit -gt 0) { Write-CorrWarn ("RowLimit={0} -- a PARTIAL snapshot. Objects whose other half was not read will SPLIT. Diagnostics only." -f $RowLimit) }

Write-CorrStep 'Reading the current snapshot from every profile table'

# ⏱️ Freshness. Log Analytics serves a row minutes after accepting it, so running this stage straight
# after the profilers reads the PREVIOUS snapshot. The local launcher transcripts say when each engine
# last finished ON THIS HOST and cannot lag, so they are the reference; -ExpectFreshSince overrides them
# when an orchestrator knows better. Neither is required: with no expectation the stage simply uses the
# last data that was sent, which is the correct behaviour for a standalone run.
$logRoot = [string]$global:SI_LauncherLogRoot
if ([string]::IsNullOrWhiteSpace($logRoot)) {
    # Start-SILauncherTranscript publishes this. It has not run when the engine is invoked directly, or
    # when transcripts are disabled -- so fall back rather than losing the freshness check with them.
    $logRoot = Join-Path $PSScriptRoot '..\..\logs'
}
$localRunStart = Get-SILocalEngineRunStart -Engines @($engineTables.Keys) -LogRoot $logRoot
if ($localRunStart.Count -gt 0) {
    Write-CorrInfo ("  local run history: {0}" -f (($localRunStart.GetEnumerator() | Sort-Object Name | ForEach-Object { '{0} {1:HH:mm}Z' -f $_.Key, $_.Value }) -join ' · '))
}

# ---- #639 THE MAP AT MILLIONS OF ASSETS (_shared/SI-CorrelationPaged.ps1) -------------------------------------------
# With the install database (every v3 Pro install) the snapshot is read in parts and staged in SQL, grouped in SQL, and
# correlated, resolved against the identity ledger and posted a BATCH at a time -- memory is one part / one batch at any
# tenant size. Without a database, or with one the updater has not updated (no sidata.CorrInput), the whole-snapshot path
# below runs as before -- and says so, as a warning of the run.
$corrIssues = New-Object System.Collections.Generic.List[object]
$pagedSql = $null
if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ProSqlServer) -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_ProSqlDatabase)) {
    try {
        if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model\SI-RecordSql.ps1') }
        $pagedSql = New-SIRecordSqlInvoke
        $hs = @(& $pagedSql (Get-SICorrelationStageCheckSql) @{} 'rows') | Select-Object -First 1
        if (-not ($hs -and [int]$hs.HasStage -eq 1)) {
            $pagedSql = $null
            Write-CorrWarn 'the database is not updated yet (sidata.CorrInput is missing) -- this run reads and correlates the whole snapshot in memory as before; run the updater.'
            $corrIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = 'the database is not updated yet (sidata.CorrInput is missing) -- the correlation map was built from the whole snapshot in memory; run the updater' })
        }
    } catch {
        $pagedSql = $null
        Write-CorrWarn ("the database could not be reached for the correlation map ({0}) -- this run reads and correlates the whole snapshot in memory." -f $_.Exception.Message)
        $corrIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the database could not be reached for the correlation map ({0}) -- the map was built from the whole snapshot in memory' -f $_.Exception.Message) })
    }
}

if ($null -ne $pagedSql) {
    # the operator's decisions FIRST: a force-merge joins its anchors' rows into one component (one batch)
    $decisionReport = Import-SICorrelationDecisions
    $decisionPlan   = Get-SICorrelationDecisionPlan -Decisions $decisionReport.Decisions
    foreach ($m in @($decisionReport.Missing)) { Write-CorrWarn ("correlation decisions: configured at '{0}' ({1}) but NOT FOUND -- none of its decisions are in force." -f $m.Path, $m.Source) }
    foreach ($p in @($decisionReport.ParseFailed)) { Write-CorrWarn ("correlation decisions: '{0}' could not be read -- {1}. No decisions from that file are in force." -f $p.Path, $p.Error) }
    foreach ($r in @($decisionReport.Rejected)) { Write-CorrWarn ("correlation decisions: entry #{0} in '{1}' REFUSED -- {2}" -f $r.Index, $r.Path, $r.Problem) }
    foreach ($c in @($decisionPlan.Conflicts)) { Write-CorrWarn ("correlation decisions: {0}" -f $c.Problem) }
    $decisionCount = @($decisionReport.Decisions).Count

    # freshness: the same wait as before, on each engine's snapshot TIME only (one small answer per engine and poll)
    $null = Wait-SICorrelationFreshSnapshot -WorkspaceResourceId $global:SI_WorkspaceResourceId -EngineTables $engineTables -ExpectFreshSince $ExpectFreshSince -LocalRunStart $localRunStart

    # the identity ledger and the one-build-at-a-time lock, BEFORE anything is written (the ledger is written per batch)
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model/identity/SI-ObjectIdentity.ps1')
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model/identity/SI-ObjectLedgerStore.ps1')
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model/identity/SI-ObjectLedgerBlob.ps1')
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model/identity/SI-ObjectLedgerProvider.ps1')
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling/storage/StorageContext.ps1')
    $ciBuildLock = $null
    trap { if (Get-Command -Name Exit-SICiBuildLock -ErrorAction SilentlyContinue) { Exit-SICiBuildLock }; break }
    try {
        if (-not (Get-Command -Name Enter-SICiBuildLock -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model\SI-RecordSql.ps1') }
        $ciBuildLock = Enter-SICiBuildLock -RunId $runId -Engine 'asset-correlation' -Log { param($l, $m) if ($l -eq 'WARN') { Write-CorrWarn $m } else { Write-CorrInfo $m } }
    } catch {
        Write-CorrWarn ("the lock that keeps two CI builds apart could not be taken ({0}) -- the correlation map is still published; the CI build asks for it again." -f $_.Exception.Message)
        $ciBuildLock = $null
    }
    $ledgerProv = $null; $ledgerOpenFailed = $false
    try { $ledgerProv = Get-SIObjectLedgerProvider } catch {
        Write-CorrWarn ("identity ledger is configured but could not be opened: {0}" -f $_.Exception.Message)
        $corrIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the identity ledger is configured but could not be opened ({0}) -- the map was published with DERIVED, PROVISIONAL ids; a connector does not create CIs from them' -f $_.Exception.Message) })
        $ledgerProv = $null; $ledgerOpenFailed = $true
    }
    if ($null -eq $ledgerProv -and -not $ledgerOpenFailed) {
        Write-CorrWarn 'identity ledger NOT configured -- ids will be `derived-provisional`, and the CMDB connector will refuse to CREATE CIs from them (enrichment is unaffected). Set $global:SI_StorageAccount for the blob ledger (every SI install already has one), or SI_LedgerSqlServer + SI_LedgerDatabase for SQL.'
        $corrIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = 'no identity ledger is configured -- the map was published with DERIVED, PROVISIONAL ids; a connector does not create CIs from them' })
    }
    if ($null -ne $ledgerProv) { Write-CorrStep ("Correlating a batch at a time; durable ids from the identity ledger ({0})" -f $ledgerProv.Description) } else { Write-CorrStep 'Correlating a batch at a time' }
    if ($DryRun) { Write-CorrWarn '  DRY RUN -- the ledger is read and resolved, never written; nothing is published.' }

    $jsonWriter = $null
    if ($JsonOutPath) {
        $dir = Split-Path -Parent $JsonOutPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        $jsonWriter = [System.IO.StreamWriter]::new($JsonOutPath, $false, [System.Text.UTF8Encoding]::new($true))
        $jsonWriter.Write('['); $jsonFirst = @{ V = $true }
    }
    $onMap = $null
    if ($jsonWriter) { $onMap = { param($Rows) foreach ($x in $Rows) { if (-not $jsonFirst.V) { $jsonWriter.Write(',') }; $jsonFirst.V = $false; $jsonWriter.Write((ConvertTo-Json -InputObject $x -Compress -Depth 6)) } } }
    try {
        $pg = Invoke-SICorrelationPaged -Sql $pagedSql -Plan $decisionPlan -LedgerProvider $ledgerProv -RunId $runId -CollectionTime $collectionTime -DryRun:$DryRun -OnMapRows $onMap `
            -ReadParts { param($OnPart) Read-SICorrelationSnapshotParts -EngineTables $engineTables -WorkspaceResourceId $global:SI_WorkspaceResourceId -RowLimit $RowLimit -OnPart $OnPart } `
            -Log { param($l, $m) if ($l -eq 'WARN') { Write-CorrWarn $m } else { Write-CorrInfo $m } }
    } finally {
        if ($jsonWriter) { $jsonWriter.Write(']'); $jsonWriter.Dispose(); Write-CorrOk ("map written to {0}" -f $JsonOutPath) }
        if ($null -ne $ledgerProv) { Close-SIObjectLedgerProvider -Provider $ledgerProv }
    }
    foreach ($t in @($pg.Snapshot.Tables)) {
        $age = if ($t.AgeDays -lt 0) { '   n/a' } else { ('{0,4}d' -f $t.AgeDays) }
        $suffix = if ($t.Note) { " -- $($t.Note)" } elseif ($t.NoJoinableId -gt 0) { (" -- {0} row(s) carry NO joinable id" -f $t.NoJoinableId) } else { '' }
        Write-CorrInfo ("  {0,-9} {1,-26} {2,6} rows  age {3}  ({4} part(s)){5}" -f $t.Engine, $t.Table, $t.Rows, $age, $t.Parts, $suffix)
        $ageHours = if ($t.SnapshotTime) { [int]([datetime]::UtcNow - ([datetime]$t.SnapshotTime)).TotalHours } else { -1 }
        if ($t.AgeDays -ge 7) { Write-CorrWarn ("  STALE: {0} last collected {1} days ago ({2:u}). Its assets may no longer exist; the map will still claim they do." -f $t.Engine, $t.AgeDays, $t.SnapshotTime) }
        elseif ($ageHours -ge 24) { Write-CorrWarn ("  AGEING: {0} last collected {1}h ago ({2:u}) -- more than a day. Correlation is still correct over it, but check that engine's schedule." -f $t.Engine, $ageHours, $t.SnapshotTime) }
        # a part count that does not add up to what the count query said is a short read -- never correlated as if whole
        if (-not $t.Note -and [long]$t.Counted -ne [long]$t.Rows) { throw ("correlation: {0} read {1} row(s) in {2} part(s) but its snapshot holds {3} -- not correlated over part of an engine." -f $t.Engine, $t.Rows, $t.Parts, $t.Counted) }
    }
    $report = $pg.Report
    # #876: an empty (new) tenant -- every table ANSWERED with no row (a read that failed threw above). Said, nothing
    # published, the ledger untouched; the run goes on. Never "removed": absence is not remediation.
    if ([long]$pg.StagedRows -eq 0) {
        $noAssets = Get-SICorrelationNoAssetsText -Tables @($pg.Snapshot.Tables)
        Write-CorrWarn $noAssets
        $corrIssues.Add([pscustomobject]@{ Level = 'INFO'; Text = $noAssets })
        Write-CorrOk ("AssetCorrelation completed in {0:n1}s -- no assets yet, nothing published" -f ([datetime]::UtcNow - $startedAt).TotalSeconds)
    } else {
    if ([long]$report.Rows -ne [long]$pg.StagedRows) { throw ("correlation: LOST ROWS -- {0} in, {1} accounted for across groups. Every input row must land in exactly one object." -f $pg.StagedRows, $report.Rows) }
    if ([long]$report.Unexplained -gt 0) { throw ("correlation: {0} object(s) were linked by something the join basis cannot account for. That is a defect in the basis calculation, not a data problem." -f $report.Unexplained) }
    foreach ($rj in @($pg.Refused)) { Write-CorrWarn ("correlation: join REFUSED by an operator decision -- '{0}' and '{1}' kept apart (would have joined via {2})." -f $rj.AnchorA, $rj.AnchorB, $rj.Via) }
    if ($decisionCount -gt 0) { Write-CorrInfo ("  decisions applied  : {0} join(s) refused · {1} object(s) carrying a pinned id" -f @($pg.Refused).Count, $pg.PinnedApplied) }
    Write-CorrInfo ("  rows in            : {0}" -f $report.Rows)
    Write-CorrInfo ("  objects out        : {0}" -f $report.Objects)
    Write-CorrInfo ("  cross-engine       : {0}" -f $report.CrossEngine)
    Write-CorrInfo ("  largest group      : {0}" -f $report.LargestGroup)
    Write-CorrInfo ("  confidence         : deterministic {0} · graph-inferred {1} · single-source {2}" -f $report.Deterministic, $report.GraphInferred, $report.SingleSource)
    if ($pg.UnseededObjects -gt 0) {
        Write-CorrWarn ("EXCLUDED {0} object(s) / {1} row(s) from the map -- no joinable identifier and no SI_AssetId, so they cannot be keyed." -f $pg.UnseededObjects, $pg.UnseededRows)
        foreach ($k in @($pg.UnseededByEngine.Keys)) { Write-CorrWarn ("  {0,-9} {1} object(s)" -f $k, $pg.UnseededByEngine[$k]) }
    }
    $fuseThreshold = [math]::Max(10, [int]([math]::Ceiling([long]$pg.StagedRows * 0.05)))
    if ([int]$report.LargestGroup -ge $fuseThreshold -and $pg.Biggest) {
        Write-CorrWarn ("POSSIBLE FUSION -- largest object holds {0} of {1} rows (threshold {2})." -f $report.LargestGroup, $pg.StagedRows, $fuseThreshold)
        Write-CorrWarn ("  SI_CorrelationId : {0}" -f $pg.Biggest.SICorrelationId)
        Write-CorrWarn ("  joined on        : {0}" -f ((@($pg.Biggest.JoinBasis) -join ', ')))
        Write-CorrWarn ("  engines          : {0}" -f ((@($pg.Biggest.Engines) -join ', ')))
    }
    $tt = $pg.Totals
    if ($pg.LedgerUsed) {
        Write-CorrInfo ("  minted {0} · reused {1} · merged {2} · unkeyable {3}" -f $tt.Minted, $tt.Reused, $tt.Merged, $tt.Unkeyable)
        if ($tt.Split -gt 0) { Write-CorrWarn ("  {0} object(s) SPLIT off an existing id ({1} because the id held another object as well) -- a connector must treat these as NEW CIs, not renames (first: {2})" -f $tt.Split, $tt.WrongMergeSplit, ((@($pg.Splits) | Select-Object -First 5 | ForEach-Object { '{0} -> {1}' -f $_.CorrelationId, $_.NewId }) -join '; ')) }
        if (@($pg.Superseded).Count -gt 0) { Write-CorrWarn ("  id(s) SUPERSEDED by a merge -- a connector must map old->new rather than create (first: {0})" -f ((@($pg.Superseded) | Select-Object -First 5 | ForEach-Object { '{0} -> {1}' -f $_.OldId, $_.NewId }) -join '; ')) }
        if ($tt.Shrunk -gt 0) { Write-CorrWarn ("  {0} object(s) lost anchors since the last run -- reported, not acted on (see V3-ARCHITECTURE 2.3a)." -f $tt.Shrunk) }
        if ($DryRun) { Write-CorrWarn ("  DRY RUN -- ledger NOT written. Would have written {0} anchor(s)." -f $tt.WouldAnchors) }
        else { Write-CorrOk ("  ledger updated: {0} anchor(s), {1} supersession(s)" -f $tt.Anchors, $tt.Superseded) }
    }
    foreach ($i in @($pg.Issues)) { $corrIssues.Add($i) }
    Write-CorrInfo ("  {0} objects published ({1} row(s) behind them); {2} map rows in {3} batch(es), at most {4} input row(s) in one batch" -f $pg.Published.Objects, $pg.Published.Rows, $tt.MapRows, $tt.Batches, $tt.MaxBatchRows)
    if ($DryRun) { Write-CorrWarn 'DRY RUN -- not publishing. Re-run without -DryRun to write SI_ObjectMap_CL.' }
    else { Write-CorrOk ("posted {0} rows to SI_ObjectMap_CL" -f $tt.Posted) }
    Write-CorrOk ("AssetCorrelation completed in {0:n1}s -- {1} rows in -> {2} objects published{3}" -f ([datetime]::UtcNow - $startedAt).TotalSeconds, $report.Rows, $pg.Published.Objects,
        $(if ($pg.UnseededObjects -gt 0) { (", {0} object(s) excluded as unkeyable" -f $pg.UnseededObjects) } else { '' }))
    }   # (#876: assets were found)
} else {

$snapshot = Get-SICorrelationSnapshot `
    -WorkspaceResourceId $global:SI_WorkspaceResourceId `
    -EngineTables        $engineTables `
    -RowLimit            $RowLimit `
    -ExpectFreshSince    $ExpectFreshSince `
    -LocalRunStart         $localRunStart

foreach ($t in @($snapshot.Tables)) {
    $age = if ($t.AgeDays -lt 0) { '   n/a' } else { ('{0,4}d' -f $t.AgeDays) }
    $suffix = if ($t.Note) { " -- $($t.Note)" } elseif ($t.NoJoinableId -gt 0) { (" -- {0} row(s) carry NO joinable id" -f $t.NoJoinableId) } else { '' }
    Write-CorrInfo ("  {0,-9} {1,-26} {2,6} rows  age {3}{4}" -f $t.Engine, $t.Table, $t.Rows, $age, $suffix)
    # A stale engine is the failure with no symptom: its rows still correlate, still publish, and still
    # assert that long-gone assets exist. Say it out loud rather than leaving it in a column nobody reads.
    #
    # Two thresholds, because "old" is not one thing here. This stage is deliberately runnable on its
    # own against whatever was last collected -- a snapshot from this morning is normal and healthy, so
    # nothing warns below a day. Past 24h something has probably not run when it should have; past 7d
    # the estate itself is no longer credible.
    $ageHours = if ($t.SnapshotTime) { [int]([datetime]::UtcNow - ([datetime]$t.SnapshotTime)).TotalHours } else { -1 }
    if ($t.AgeDays -ge 7) {
        Write-CorrWarn ("  STALE: {0} last collected {1} days ago ({2:u}). Its assets may no longer exist; the map will still claim they do." -f $t.Engine, $t.AgeDays, $t.SnapshotTime)
    } elseif ($ageHours -ge 24) {
        Write-CorrWarn ("  AGEING: {0} last collected {1}h ago ({2:u}) -- more than a day. Correlation is still correct over it, but check that engine's schedule." -f $t.Engine, $ageHours, $t.SnapshotTime)
    }
}

$inputs = @($snapshot.Inputs)
# #876: an empty (new) tenant -- every table ANSWERED with no row (a read that failed threw in the reader). Said, nothing
# published, the ledger untouched; the run goes on. Never "removed": absence is not remediation.
if ($inputs.Count -eq 0) {
    $noAssets = Get-SICorrelationNoAssetsText -Tables @($snapshot.Tables)
    Write-CorrWarn $noAssets
    $corrIssues.Add([pscustomobject]@{ Level = 'INFO'; Text = $noAssets })
    Write-CorrOk ("AssetCorrelation completed in {0:n1}s -- no assets yet, nothing published" -f ([datetime]::UtcNow - $startedAt).TotalSeconds)
} else {

# How many rows carry NO joinable identifier at all. These can only ever be single-source objects, so a
# high number is the ceiling on how much correlation can possibly achieve here -- worth seeing before
# reading the object count as a result.
$noKeys = @($inputs | Where-Object { @($_.Identifiers).Count -eq 0 }).Count
Write-CorrInfo ("  total {0} rows; {1} carry no joinable identifier" -f $inputs.Count, $noKeys)

Write-CorrStep 'Correlating'

# ---- #61.4 -- the operator's correlation decisions. --------------------------------------------
# READ, REPORTED, THEN APPLIED, in that order. #61 has already shipped a feature that was built,
# tested and completely inert because nothing loaded the file, and every test still passed -- so
# everything that will NOT apply is named, and so is everything that did.
#
# SILENT ONLY WHEN THERE IS GENUINELY NOTHING TO SAY. No file and no entries prints nothing, because
# the overwhelming majority of installs will never write one and a line saying "0 decisions" on every
# run of every engine is noise that trains people to skim. The moment there is a file, an entry, a
# rejection or a missing configured path, it is reported. The distinction that matters -- "written and
# not read" -- cannot occur silently: a file that exists always produces either decisions or
# rejections, and both print.
$decisionReport = Import-SICorrelationDecisions
$decisionPlan   = Get-SICorrelationDecisionPlan -Decisions $decisionReport.Decisions

foreach ($m in @($decisionReport.Missing)) {
    Write-CorrWarn ("correlation decisions: configured at '{0}' ({1}) but NOT FOUND -- none of its decisions are in force." -f $m.Path, $m.Source)
}
foreach ($p in @($decisionReport.ParseFailed)) {
    Write-CorrWarn ("correlation decisions: '{0}' could not be read -- {1}. No decisions from that file are in force." -f $p.Path, $p.Error)
}
foreach ($r in @($decisionReport.Rejected)) {
    Write-CorrWarn ("correlation decisions: entry #{0} in '{1}' REFUSED -- {2}" -f $r.Index, $r.Path, $r.Problem)
}
foreach ($c in @($decisionPlan.Conflicts)) {
    Write-CorrWarn ("correlation decisions: {0}" -f $c.Problem)
}

$decisionCount = @($decisionReport.Decisions).Count
if ($decisionCount -gt 0 -or @($decisionReport.Rejected).Count -gt 0) {
    Write-CorrInfo ("  operator decisions : {0} in force ({1} never-merge · {2} force-merge · {3} pin-id); {4} refused" -f `
        $decisionCount,
        @(@($decisionReport.Decisions) | Where-Object { $_.Kind -eq 'never-merge' }).Count,
        @(@($decisionReport.Decisions) | Where-Object { $_.Kind -eq 'force-merge' }).Count,
        @(@($decisionReport.Decisions) | Where-Object { $_.Kind -eq 'pin-id'      }).Count,
        @($decisionReport.Rejected).Count)
}

$groups = Get-SICorrelationGroups -Inputs $inputs -Plan $decisionPlan
$report = Get-SICorrelationReport -Groups $groups

# What the decisions ACTUALLY DID, counted off the produced groups rather than from a counter at the
# decision point -- #61 has already produced an override that moved a variable and not the output.
$refused = @()
if (@($groups).Count -gt 0 -and $groups[0].PSObject.Properties['RefusedJoins']) { $refused = @($groups[0].RefusedJoins) }
foreach ($rj in $refused) {
    Write-CorrWarn ("correlation: join REFUSED by an operator decision -- '{0}' and '{1}' kept apart (would have joined via {2})." -f $rj.AnchorA, $rj.AnchorB, $rj.Via)
}
$pinnedApplied = @(@($groups) | Where-Object { $_.PinnedBy }).Count
if ($decisionCount -gt 0) {
    Write-CorrInfo ("  decisions applied  : {0} join(s) refused · {1} object(s) carrying a pinned id" -f @($refused).Count, $pinnedApplied)
    # An anchor nobody carries is not an error -- the asset may simply be absent from this snapshot --
    # but it is not a success either, and reading "3 in force" as "3 applied" is exactly the wrong
    # conclusion. Say so when nothing happened.
    if (@($refused).Count -eq 0 -and $pinnedApplied -eq 0) {
        Write-CorrInfo ('                       (none changed this run -- either the assets are absent from this snapshot, or the data already agreed with the decision)')
    }
}

Write-CorrInfo ("  rows in            : {0}" -f $report.Rows)
Write-CorrInfo ("  objects out        : {0}" -f $report.Objects)
Write-CorrInfo ("  cross-engine       : {0}" -f $report.CrossEngine)
Write-CorrInfo ("  largest group      : {0}" -f $report.LargestGroup)
Write-CorrInfo ("  confidence         : deterministic {0} · graph-inferred {1} · single-source {2}" -f `
                    $report.Deterministic, $report.GraphInferred, $report.SingleSource)

# ---- Guards. Each one is a failure that otherwise looks exactly like data. -------------------------

if ($report.Rows -ne $inputs.Count) {
    throw ("correlation: LOST ROWS -- {0} in, {1} accounted for across groups. Every input row must land in exactly one object." -f $inputs.Count, $report.Rows)
}
# UNSEEDED objects are EXCLUDED from the map and reported -- deliberately not fatal.
#
# First live run: 16 of 941 rows had no joinable identifier AND no SI_AssetId, all of them from a
# publicip snapshot 52 days stale, collected before SI_AssetId was wired at all. Throwing meant one
# long-abandoned engine blocked correlation for the entire estate, which is the wrong severity by a
# wide margin. It is also not a defect in correlation: a row with no identifier of any kind genuinely
# cannot be keyed, and the map is keyed on SI_CorrelationId, so there is no row to publish.
#
# Excluding them is honest. Doing it SILENTLY would not be -- that is the silent-loss class this
# codebase fights -- so they are counted, attributed per engine, and named.
$unseeded = @($groups | Where-Object { -not $_.SICorrelationId })
$groups   = @($groups | Where-Object { $_.SICorrelationId })
if ($unseeded.Count -gt 0) {
    $rowsDropped = (@($unseeded | ForEach-Object { @($_.Members).Count } | Measure-Object -Sum).Sum)
    Write-CorrWarn ("EXCLUDED {0} object(s) / {1} row(s) from the map -- no joinable identifier and no SI_AssetId, so they cannot be keyed." -f $unseeded.Count, $rowsDropped)
    foreach ($g in @($unseeded | Group-Object { @($_.Engines) -join ',' })) {
        Write-CorrWarn ("  {0,-9} {1} object(s)" -f $g.Name, $g.Count)
    }
    Write-CorrWarn '  Usual cause: a snapshot collected before SI_AssetId was wired. Re-run that engine and they will key normally.'
}

# EVERY object that survives must be identifiable -- that is what the map is keyed on.
if (@($groups | Where-Object { -not $_.SICorrelationId }).Count -gt 0) {
    throw 'correlation: an unseeded object survived the exclusion pass. That is a defect in the exclusion, not in the data.'
}
if ($report.Unexplained -gt 0) {
    throw ("correlation: {0} object(s) were linked by something the join basis cannot account for. That is a defect in the basis calculation, not a data problem." -f $report.Unexplained)
}

# A runaway fusion is the failure mode with no visible symptom: one group swallows the estate, the row
# count still balances, and one machine's vulnerabilities are silently attributed to another. Warn hard
# rather than throw -- a genuinely large group is possible, and a stopped run tells the operator less
# than a completed one that says exactly which object to look at.
if ($report.Objects -gt 0) {
    $fuseThreshold = [math]::Max(10, [int]([math]::Ceiling($inputs.Count * 0.05)))
    if ($report.LargestGroup -ge $fuseThreshold) {
        $biggest = @($groups | Sort-Object { @($_.Members).Count } -Descending | Select-Object -First 1)[0]
        Write-CorrWarn ("POSSIBLE FUSION -- largest object holds {0} of {1} rows (threshold {2})." -f $report.LargestGroup, $inputs.Count, $fuseThreshold)
        Write-CorrWarn ("  SI_CorrelationId : {0}" -f $biggest.SICorrelationId)
        Write-CorrWarn ("  joined on        : {0}" -f ((@($biggest.JoinBasis) -join ', ')))
        Write-CorrWarn ("  engines          : {0}" -f ((@($biggest.Engines) -join ', ')))
        Write-CorrWarn '  A single identifier value shared by many rows is the usual cause. Inspect before trusting this map downstream.'
    }
}

# ---- IDENTITY LEDGER: turn a derived seed into a DURABLE id -----------------------------------------
# The derived SI_CorrelationId is `same INPUT -> same id`, which is not what a connector needs. It moves
# when a member joins or leaves the group (measured: ...:aaa -> ...:000) and when an anchor rotates. The
# ledger makes it `same OBJECT -> same id` by minting once and remembering.
#
# 🔴 DEGRADE LOUDLY, NEVER DIE. If the ledger is unreachable the run still publishes -- the map is the
# customer's output, and losing it to protect an id would be the wrong trade. The rows simply go out
# marked derived-provisional, which is TRUE, and a connector is already forbidden from creating CIs from
# those. An outage costs a late CI; silently emitting a derived id that LOOKS durable would cost a
# duplicate one, and duplicates are permanent once incidents point at them.
$resolvedIds  = $null
$ledgerProv   = $null
$ledgerETag   = $null
$ledgerBefore = @{}

# 🔑 THE LEDGER NO LONGER REQUIRES SQL, AND THAT IS WHAT UNBLOCKS CMDB CREATION.
# It used to run only when $global:SI_LedgerSqlServer was set, which meant standing up an Azure SQL
# database -- i.e. SCHEMA-1, whose `needsSchema: true` would run migrations unattended on ~30
# customers. Nobody had taken that decision, so in practice the ledger was never reachable and EVERY
# correlation id in every estate stayed `derived-provisional` -- which the CMDB connector correctly
# refuses to create from. The gap was not cosmetic: it blocked scenario 2 entirely.
# ✅ The ledger is not relational -- it is one map, read whole and written whole, exactly as
# Get-SIObjectLedger's own docblock says. A blob satisfies the whole contract, and every SI install
# already has the storage account. SQL stays preferred when configured; see SI-ObjectLedgerProvider.
# the identity ledger lives with the data model (engine/data-model/identity) -- both editions build CIs on it
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model/identity/SI-ObjectIdentity.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model/identity/SI-ObjectLedgerStore.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model/identity/SI-ObjectLedgerBlob.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model/identity/SI-ObjectLedgerProvider.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling/storage/StorageContext.ps1')

# ---- ONE CI BUILD AT A TIME (engine/data-model/SI-RecordSql.ps1, Enter-SICiBuildLock) ---------------------------
# From here this job WRITES what a second run of it would write too: the identity ledger below, then the CIs. So it
# takes the database's CI build lock now and keeps it to its end -- the CI build further down finds it held by this
# process and builds under it. A run that finds another CI build running waits for it here, before it writes anything,
# and then goes on as an ordinary run. The server frees the lock when this process ends, however it ends; the trap
# releases it when the job fails in a process that lives on (a run by hand). No database: nothing to lock.
$ciBuildLock = $null
trap { if (Get-Command -Name Exit-SICiBuildLock -ErrorAction SilentlyContinue) { Exit-SICiBuildLock }; break }
if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_ProSqlServer) -and -not [string]::IsNullOrWhiteSpace([string]$global:SI_ProSqlDatabase)) {
    try {
        if (-not (Get-Command -Name Enter-SICiBuildLock -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model\SI-RecordSql.ps1') }
        $ciBuildLock = Enter-SICiBuildLock -RunId $runId -Engine 'asset-correlation' -Log { param($l, $m) if ($l -eq 'WARN') { Write-CorrWarn $m } else { Write-CorrInfo $m } }
    } catch {
        # the map is still published (it is this job's own output); the CI build asks for the lock again and says why it cannot build
        Write-CorrWarn ("the lock that keeps two CI builds apart could not be taken ({0}) -- the correlation map is still published; the CI build asks for it again." -f $_.Exception.Message)
        $ciBuildLock = $null
    }
}

try { $ledgerProv = Get-SIObjectLedgerProvider } catch {
    # A CONFIGURED store that cannot be opened is an error, not a fallback -- see the provider's
    # header. Splitting the ledger across two stores re-mints ids and orphans every CI bound to them.
    Write-CorrWarn ("identity ledger is configured but could not be opened: {0}" -f $_.Exception.Message)
    $corrIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the identity ledger is configured but could not be opened ({0}) -- the map was published with DERIVED, PROVISIONAL ids; a connector does not create CIs from them' -f $_.Exception.Message) })
    $ledgerProv = $null
}

if ($null -ne $ledgerProv) {
    Write-CorrStep ("Resolving durable ids against the identity ledger ({0})" -f $ledgerProv.Description)
    try {
        $read         = Read-SIObjectLedger -Provider $ledgerProv
        $ledger       = $read.Ledger
        $ledgerETag   = $read.ETag
        $ledgerBefore = $ledger
        Write-CorrInfo ("  ledger holds {0} anchor(s){1}" -f $ledger.Keys.Count,
            $(if (-not $read.Existed) { ' -- FIRST RUN, every id will be minted now' } else { '' }))

        # #61.4 -- the contested anchors, so the ledger cannot re-fuse what a never-merge separated.
        # $null when no decision fired, which makes this argument inert on every ordinary run.
        $ambig = $null
        if (@($groups).Count -gt 0 -and $groups[0].PSObject.Properties['AmbiguousIdKeys']) { $ambig = $groups[0].AmbiguousIdKeys }

        $idy = Resolve-SIObjectIdentity -Groups $groups -Ledger $ledger -Now $collectionTime -AmbiguousIdKeys $ambig
        Write-CorrInfo ("  minted {0} · reused {1} · merged {2} · unkeyable {3}" -f $idy.Minted, $idy.Reused, $idy.Merged, $idy.Unkeyable)
        if ($idy.Split -gt 0) {
            # #642 WrongMergeSplit of them: an id the ledger had given to another object as well (proven), not an operator decision
            Write-CorrWarn ("  {0} object(s) SPLIT off an existing id ({1} on an operator decision, {2} because the id held another object as well) -- a connector must treat these as NEW CIs, not renames:" -f $idy.Split, ($idy.Split - [int]$idy.WrongMergeSplit), [int]$idy.WrongMergeSplit)
        }
        foreach ($s in @($idy.Splits)) {
            if ($s.Resolved -and [string]$s.Kind -eq 'wrong-merge') {
                Write-CorrWarn ("    {0} -> {1} ({2})" -f $s.CorrelationId, $s.NewId, $s.Reason)
            } elseif ($s.Resolved) {
                Write-CorrWarn ("    {0} -> {1} (the other half keeps {0})" -f $s.CorrelationId, $s.NewId)
            } else {
                # The deferred case: visible now instead of two objects silently sharing one id.
                Write-CorrWarn ("    {0}: {1} object(s) resolve to this one id -- {2}" -f $s.CorrelationId, $s.Objects, $s.Reason)
            }
        }
        if (@($idy.Superseded).Count -gt 0) {
            Write-CorrWarn ("  {0} id(s) SUPERSEDED by a merge -- a connector must map old->new rather than create:" -f @($idy.Superseded).Count)
            foreach ($s in @($idy.Superseded)) { Write-CorrWarn ("    {0} -> {1}" -f $s.OldId, $s.NewId) }
        }
        if (@($idy.ShrunkObjects).Count -gt 0) {
            # Reported, never acted on: one run cannot tell a split from a source that failed, and
            # guessing wrong RETIRES A LIVE CI.
            Write-CorrWarn ("  {0} object(s) lost anchors since the last run -- reported, not acted on (see V3-ARCHITECTURE 2.3a)." -f @($idy.ShrunkObjects).Count)
        }

        $resolvedIds = @{}
        foreach ($d in @($idy.Decisions)) {
            if ($null -ne $d -and $d.Group -and -not [string]::IsNullOrWhiteSpace([string]$d.CorrelationId)) {
                $resolvedIds[[string]$d.Group.SICorrelationId] = [string]$d.CorrelationId
            }
        }
        # ---- F7 -- A DRY RUN MUST NOT WRITE THE LEDGER. ------------------------------------------
        # It used to. Save-SIObjectLedger ran here unconditionally and only the PUBLISH step was
        # gated, so `-DryRun` printed "Nothing will be published" and then minted, re-pointed and
        # superseded rows in the live identity database. The one store a preview must not touch was
        # the one it touched -- and `-DryRun` is precisely what an operator reaches for BEFORE
        # committing to a change they are unsure about. Found 2026-08-20.
        #
        # 🔑 THE RESOLVE STILL RUNS, and that is deliberate: mint / reuse / merge / split counts are
        # the most valuable thing a dry run can tell you. Skipping the whole block to be safe would
        # have removed the reason to run one.
        if ($DryRun) {
            $wouldAnchors = 0
            foreach ($d in @($idy.Decisions)) { $wouldAnchors += @($d.NewIdentifiers).Count }
            Write-CorrWarn ("  DRY RUN -- ledger NOT written. Would have written {0} anchor(s) and {1} supersession(s)." -f `
                                $wouldAnchors, @($idy.Superseded).Count)
        } else {
            $saved = Write-SIObjectLedger -Provider $ledgerProv -Decisions $idy.Decisions -Superseded $idy.Superseded `
                        -IfMatchETag $ledgerETag -CurrentLedger $ledgerBefore
            Write-CorrOk ("  ledger updated: {0} anchor(s), {1} supersession(s)" -f $saved.AnchorsWritten, $saved.SupersededWritten)
        }
    } catch {
        $resolvedIds = $null
        Write-CorrWarn ("identity ledger unavailable ({0}) -- publishing with DERIVED, PROVISIONAL ids. They are labelled as such in SI_IdSource, and a connector must not create CIs from them." -f $_.Exception.Message)
        # #639 never silently green: a WARNING of the run
        $corrIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the identity ledger was unavailable ({0}) -- the map was published with DERIVED, PROVISIONAL ids (SI_IdSource); a connector does not create CIs from them' -f $_.Exception.Message) })
    } finally {
        Close-SIObjectLedgerProvider -Provider $ledgerProv
    }
} else {
    # 🔴 NAME BOTH WAYS TO CONFIGURE IT. The old message named only SI_LedgerSqlServer, which read as
    # "you need SQL" -- and that belief is why no estate had a ledger at all.
    Write-CorrWarn 'identity ledger NOT configured -- ids will be `derived-provisional`, and the CMDB connector will refuse to CREATE CIs from them (enrichment is unaffected). Set $global:SI_StorageAccount for the blob ledger (every SI install already has one), or SI_LedgerSqlServer + SI_LedgerDatabase for SQL.'
    $corrIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = 'no identity ledger is configured -- the map was published with DERIVED, PROVISIONAL ids; a connector does not create CIs from them' })
}

Write-CorrStep 'Building the object map'
# Recomputed AFTER the exclusion pass, so the published figures describe what was actually published
# rather than what was considered. Reporting the pre-exclusion count here would overstate the map by
# exactly the rows we just decided we could not key.
$published = Get-SICorrelationReport -Groups $groups
$mapRows   = ConvertTo-SIObjectMapRows -Groups $groups -RunId $runId -CollectionTime $collectionTime -ResolvedIds $resolvedIds
Write-CorrInfo ("  {0} objects published ({1} row(s) behind them)" -f $published.Objects, $published.Rows)
Write-CorrInfo ("  {0} map rows (one per object x member x identifier)" -f @($mapRows).Count)

if ($JsonOutPath) {
    $dir = Split-Path -Parent $JsonOutPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    @($mapRows) | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $JsonOutPath -Encoding UTF8
    Write-CorrOk ("map written to {0}" -f $JsonOutPath)
}

if ($DryRun) {
    Write-CorrWarn 'DRY RUN -- not publishing. Re-run without -DryRun to write SI_ObjectMap_CL.'
} else {
    Write-CorrStep 'Publishing SI_ObjectMap_CL'
    $posted = Send-SIObjectMapRows -Rows $mapRows
    Write-CorrOk ("posted {0} rows to SI_ObjectMap_CL" -f $posted)
    if ([int]$posted -lt @($mapRows).Count) { $corrIssues.Add([pscustomobject]@{ Level = 'FAILED'; Text = ('{0} of {1} map row(s) reached SI_ObjectMap_CL -- the map in Log Analytics is short this run' -f [int]$posted, @($mapRows).Count) }) }
    # A newly declared column or table needs ~45+ MINUTES before Log Analytics starts ingesting it, and
    # this is the single most misread fact in the v3 work so far. It is elapsed time, not "two runs":
    # re-running the engine does not help and wastes an hour proving nothing.
    Write-CorrWarn 'A brand-new table/column reads back EMPTY for ~45+ minutes. That is the ingest window, not a defect.'
    Write-CorrWarn 'Verify with diagnostics/Test-SIv3ColumnIngest.ps1 (~5 s). Do NOT re-run this engine to check.'
}

Write-CorrOk ("AssetCorrelation completed in {0:n1}s -- {1} rows in -> {2} objects published{3}" -f `
    ([datetime]::UtcNow - $startedAt).TotalSeconds, $report.Rows, $published.Objects,
    $(if ($unseeded.Count -gt 0) { (", {0} object(s) excluded as unkeyable" -f $unseeded.Count) } else { '' }))
}   # (#876: assets were found)
}   # (the whole-snapshot path)

# ---- v3 DATA MODEL: CIs from the provider records (V3-DATA-MODEL part 2, P2) ----
# The provider records every profiler wrote to the DATABASE become CIs, IN SQL (#477: "we dont support la for
# correlation, sql only"), identified by THIS ledger; the CIs are then posted to SI_CI_CL for Risk Analysis's Kusto. It
# runs AFTER the map is published (the map above is the current consumers' input and is kept), and a build that failed
# FAILS THIS JOB (2026-10-09: customer H showed the job Succeeded with a warning, which hid the failure from the job list and
# the post-deploy check). No database = no CIs, said plainly -- a failure too. SI_DataModelCi = off switches it off.
$ciFailure = $null
try {
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model\SI-RecordCapture.ps1')
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'data-model\SI-CiBuildRun.ps1')
    Write-CorrStep 'Building CIs from the provider records in the database (-> sidata.Ci + SI_CI_CL)'
    $ci = Invoke-SICiBuild -RunId $runId -DryRun:$DryRun -Log { param($l, $m) if ($l -eq 'WARN') { Write-CorrWarn $m } elseif ($l -eq 'OK') { Write-CorrOk $m } else { Write-CorrInfo $m } }
    if ($ci -and $ci.PSObject.Properties['Failed'] -and $ci.Failed) { $ciFailure = [string]$ci.Reason }
    # #639 (working rule 4): what the build caught never ends this job green -- a FAILED issue (CI rows short in SI_CI_CL,
    # which Risk Analysis reads) fails the job; a WARNING is said as one, plainly
    elseif ($ci -and $ci.PSObject.Properties['Issues']) {
        $ciFailed = @(@($ci.Issues) | Where-Object { $_ -and [string]$_.Level -eq 'FAILED' })
        foreach ($wi in @(@($ci.Issues) | Where-Object { $_ -and [string]$_.Level -eq 'WARNING' })) { Write-CorrWarn ('WARNING: ' + [string]$wi.Text) }
        if ($ciFailed.Count) { $ciFailure = (@($ciFailed | ForEach-Object { [string]$_.Text }) -join ' | ') }
    }
} catch {
    $ciFailure = $_.Exception.Message
}
# this job's writing is done: the next CI build may start (Exit-SICiBuildLock does nothing when no lock is held)
if (Get-Command -Name Exit-SICiBuildLock -ErrorAction SilentlyContinue) { Exit-SICiBuildLock }
# #639 what the map caught and went on from: every WARNING said as one, a FAILED one fails the job (the map is short)
foreach ($wi in @($corrIssues | Where-Object { $_ -and [string]$_.Level -eq 'WARNING' })) { Write-CorrWarn ('WARNING: ' + [string]$wi.Text) }
$mapFailed = @($corrIssues | Where-Object { $_ -and [string]$_.Level -eq 'FAILED' } | ForEach-Object { [string]$_.Text })
if ($ciFailure) {
    throw ("correlation: CIs could not be built this run -- {0}. The correlation map was published.{1}" -f $ciFailure, $(if ($mapFailed.Count) { ' ' + ($mapFailed -join ' | ') } else { '' }))
}
if ($mapFailed.Count) { throw ('correlation: ' + ($mapFailed -join ' | ')) }