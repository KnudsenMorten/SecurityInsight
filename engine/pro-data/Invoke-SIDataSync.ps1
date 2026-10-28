#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Pro -- the data backend sync: copies every COMPLETE Risk Analysis Detailed collection from Log
    Analytics into the Pro SQL database, keeps the daily aggregates current, and removes collections past retention.
.DESCRIPTION
    The Pro web app reads the database this fills (schema sidata, sql\si-data-schema.sql): the latest collection, any
    older one by its collection time, the CI view, and the pre-computed daily aggregates for dashboards and trends.
    It also copies each complete Risk Analysis SUMMARY collection (the RiskAnalysis_Summary workbook's rows, with their
    impacted assets) for the Risk Analysis Summary rows (#583, _shared\SI-DataSummary.ps1).

    Only a collection whose Risk Analysis run recorded success is loaded, each collection once; a re-run loads nothing
    twice. A collection whose run is not shown complete is held and tried again on the next run. See
    _shared\SI-DataSync.ps1 for the algorithm.

    Settings (config, or the Pro settings database):
        SI_ProSqlServer / SI_ProSqlDatabase           the Pro database (SI_Pro_DataSqlServer / SI_Pro_DataSqlDatabase
                                                      override them when the data lives in another database)
        SI_Pro_DataRetentionDays                      90 -- collections older than this are removed
        SI_Pro_DataLookbackDays                       3  -- how far back collections not yet loaded are caught up
        SI_AssetProperties                            security (default) = the security profile only, nothing extra
                                                      stored; full = the full asset metadata (SI_AssetProperties_CL) is
                                                      stored generically in sidata.AssetMetadata for the asset page (#408)
        SI_AssetProperties_RetentionDays              3  -- the full asset metadata is removed after this many days
        SI_Pro_AuditRetentionMonths                   not set = the audit trail is kept forever; at least 13 -- older
                                                      audit rows are removed by this job's audited retention step
        SI_Pro_Responsibility_Sources / _TagNames / _DefaultDepartment   the asset responsibility policy (#254):
                                                      which department each finding belongs to (see
                                                      _shared\SI-DataResponsibility.ps1)
    Sign-in: the container job's managed identity, else the engine SPN by certificate. The identity needs
    db_datareader + db_datawriter in the Pro database (it also reads vuln.VulnerabilityEvent).
.PARAMETER DryRun
    Read and report what would be loaded; write nothing (no load, no aggregates, no retention).
.PARAMETER LookbackDays
    Override SI_Pro_DataLookbackDays for this run.
#>
[CmdletBinding()]
param(
    [switch]$DryRun,
    [int]$LookbackDays = 0
)

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../_shared/SI-AzRest.ps1') }
$ErrorActionPreference = 'Stop'
try { Set-StrictMode -Off } catch { }

function Write-DataStep ($m) { Write-Host "[STEP] $m" -ForegroundColor Cyan }
function Write-DataInfo ($m) { Write-Host "[INFO] $m" -ForegroundColor Gray }
function Write-DataOk   ($m) { Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-DataWarn ($m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }

$here = $PSScriptRoot
$siRoot = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $siRoot 'engine\_shared\SI-V3Snapshot.ps1')
. (Join-Path $siRoot 'engine\_shared\SI-KqlError.ps1')
# The completeness verdict is the close-loop's own (Get-SIVulnRunHealthKql, Test-SIVulnSnapshotComplete).
. (Join-Path $siRoot 'engine\asset-cmdb\_shared\SI-VulnDesired.ps1')
. (Join-Path $here '_shared\SI-DataKql.ps1')
. (Join-Path $here '..\_shared\data-sql\SI-DataModel.ps1')
. (Join-Path $here '..\_shared\data-sql\SI-DataSql.ps1')
. (Join-Path $here '_shared\SI-DataSync.ps1')
. (Join-Path $here '_shared\SI-DataResponsibility.ps1')
. (Join-Path $here '_shared\SI-DataRepair.ps1')
. (Join-Path $here '_shared\SI-DataAssetMerge.ps1')
# #299: the correlation evidence per CI and the per-collection correlation rows
. (Join-Path $here '_shared\SI-DataEvidence.ps1')
# #408: the full asset metadata, stored generically -- only when SI_AssetProperties = full
. (Join-Path $here '_shared\SI-DataAssetMetadata.ps1')
# v3 data model: CIs, linked objects, findings per CI and provider records -> the Pro database
. (Join-Path $here '_shared\SI-DataCi.ps1')
# what the data views show by default, prepared as columns (the finding / issue context per collection, the CI context)
. (Join-Path $here '_shared\SI-DataViewContext.ps1')
# #812: What changed per collection pair and the wall board's top tier-0 assets, stored per collection
. (Join-Path $here '_shared\SI-DataChanges.ps1')
# #812: the findings browser's order and pivot cells and the Weighted risk pivot's cube, stored per collection
. (Join-Path $here '_shared\SI-DataPivots.ps1')
# #636: the Summary groupings of the Detailed findings, stored per collection (THE engine function: engine\_shared\SI-SummaryGroupings.ps1)
. (Join-Path $here '_shared\SI-DataSummaryGroups.ps1')
# #636: the remediations (one fix, many assets) and the key figures of the Executive overview and report
. (Join-Path $here '_shared\SI-DataRemediation.ps1')
. (Join-Path $here '_shared\SI-DataFindingNarrow.ps1')
. (Join-Path $here '_shared\SI-DataKeyFigures.ps1')
# what two pages open with, written by the data sync: the column chooser's lists and the open vulnerabilities by severity and tier
. (Join-Path $here '_shared\SI-DataPageLists.ps1')

Write-DataStep 'SecurityInsight -- Pro data backend sync'
. (Join-Path $siRoot 'engine\SI-FeatureCatalog.ps1')
if (-not (Assert-SIFeatureOrSkip -Feature 'data-backend')) { return }

# Same auth bridge as the other Pro engines: platform names -> SI_SPN_*.
if (-not $global:SI_SPN_TenantId       -and $global:HighPriv_Modern_TenantID)                    { $global:SI_SPN_TenantId       = [string]$global:HighPriv_Modern_TenantID }
if (-not $global:SI_SPN_AppId          -and $global:HighPriv_Modern_ApplicationID_Azure)         { $global:SI_SPN_AppId          = [string]$global:HighPriv_Modern_ApplicationID_Azure }
if (-not $global:SI_SPN_CertThumbprint -and $global:HighPriv_Modern_CertificateThumbprint_Azure) { $global:SI_SPN_CertThumbprint = [string]$global:HighPriv_Modern_CertificateThumbprint_Azure }
if ([string]::IsNullOrWhiteSpace([string]$global:SI_WorkspaceResourceId)) {
    throw 'data sync: $global:SI_WorkspaceResourceId is empty. Run this through its container job or launcher so the configuration is loaded.'
}

$g = @{}
# #408: the asset-metadata level and its retention travel too (the retention was never passed here, so it was always 3)
foreach ($n in 'SI_ProSqlServer', 'SI_ProSqlDatabase', 'SI_Pro_DataSqlServer', 'SI_Pro_DataSqlDatabase', 'SI_Pro_DataRetentionDays', 'SI_Pro_DataLookbackDays', 'SI_AssetProperties', 'SI_AssetProperties_RetentionDays') {
    $g[$n] = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue
}
if ($LookbackDays -gt 0) { $g['SI_Pro_DataLookbackDays'] = $LookbackDays }
$settings = Resolve-SIDataSettings -Globals $g
if (@($settings.Problems).Count) { throw ('data sync: ' + (@($settings.Problems) -join '; ')) }
$edition = ((Get-Content -LiteralPath (Join-Path $siRoot 'VERSION') -Raw).Trim() -split '\.')[0]

Write-DataInfo ("database  : {0}/{1}" -f $settings.Server, $settings.Database)
Write-DataInfo ("retention : {0} day(s); look-back {1} day(s){2}" -f $settings.RetentionDays, $settings.LookbackDays, $(if ($DryRun) { '   (DRY RUN -- nothing is written)' } else { '' }))

$wsId = Resolve-SIV3WorkspaceId
# Every read of this job goes through here. -RowsOnly: the rows are read straight from the answer's bytes -- the answer is
# never also held as one text and as a second copy of its tables (that is what ran a large install out of memory).
$query = {
    param([string]$kql)
    $answer = Invoke-SILaQuery -WorkspaceId $wsId -Query $kql -Wait 600 -RowsOnly -ErrorAction Stop
    # An answer the service CUT because it was too large says so beside the rows it did send. That is a FAILED read, never a
    # shorter result (#639, working rule 4: what was not read is UNKNOWN, never absent -- a cut object map or profile table
    # would make assets look gone). A read taken in pages (its query keys the rows: _pk) is taken again in smaller pages by
    # its reader (_shared\SI-DataSync.ps1, Read-SIDataPages); any other read fails the step that made it, which says so.
    if ($answer.Error) {
        $cut = ''
        try { $cut = ConvertTo-Json -InputObject $answer.Error -Depth 8 -Compress } catch { $cut = [string]$answer.Error }
        if (Test-SIDataResponseTooLarge -Text $cut) { throw (Format-SIDataCutAnswer -Rows @($answer.Results).Count -ErrorText $cut) }
    }
    @($answer.Results)
}
# #745: the views' aggregates and their counted twins are single statements over a whole collection -- 300 s was too short
# for a large customer's (1,138,554 findings, 314 s on S6), and that failed the whole data sync
$invoke = New-SIDataSqlInvoke -Server $settings.Server -Database $settings.Database -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint -CommandTimeoutSec 0
$log = {
    param([string]$level, [string]$msg)
    switch ($level) { 'OK' { Write-DataOk $msg } 'WARN' { Write-DataWarn $msg } default { Write-DataInfo $msg } }
}

$rg = @{}
foreach ($n in 'SI_Pro_Responsibility_Sources', 'SI_Pro_Responsibility_TagNames', 'SI_Pro_Responsibility_DefaultDepartment') {
    # an EMPTY list is a value (the policy sources switched off), so presence is tested, not truthiness
    $var = Get-Variable -Name $n -Scope Global -ErrorAction SilentlyContinue
    if ($var -and -not [object]::ReferenceEquals($null, $var.Value)) { $rg[$n] = $var.Value }
}
$responsibility = Resolve-SIDataResponsibilitySettings -Globals $rg
Write-DataInfo ("departments: sources {0}; tags {1}; default {2}" -f $(if (@($responsibility.Sources).Count) { @($responsibility.Sources) -join ' > ' } else { '(none)' }), (@($responsibility.TagNames) -join ', '), $(if ($responsibility.DefaultDepartment) { $responsibility.DefaultDepartment } else { 'Unassigned' }))

# #277: a tripped guard mails and reports itself (never fails the run)
try { . (Join-Path $siRoot 'engine\_shared\SI-Guard.ps1'); . (Join-Path $siRoot 'engine\pro-settings\SI-Audit.ps1') } catch { Write-DataWarn ("guard events are not sent: {0}" -f $_.Exception.Message) }
$guardCommon = @{ Engine = 'datasync'; Invoke = $(if (Get-Command -Name Get-SIGuardProInvoke -ErrorAction SilentlyContinue) { Get-SIGuardProInvoke -Default $invoke -Server $settings.Server -Database $settings.Database } else { $null }) }
# #294: run health (SI_RunHealth_CL), as the CMDB connector records its own -- so a snapshot this sync REFUSED is said
# where the operator looks for a run's verdict, not only in the log. Never fails the sync.
$runContext = [pscustomobject]@{ RunId = [guid]::NewGuid().ToString(); Engine = 'asset-datasync'; ShardIndex = 0; ShardCount = 1; StartedAt = [datetime]::UtcNow; CollectionTime = [datetime]::UtcNow }
$healthFile = Join-Path $siRoot 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1'
if (-not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $healthFile)) { try { . $healthFile } catch { Write-DataWarn ("run health is not recorded: {0}" -f $_.Exception.Message) } }
$sendHealth = {
    param([string]$phase, [string]$exit, [string]$err)
    if ($DryRun -or -not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue)) { return }
    try { Send-SIRunHealthRow -RunContext $runContext -Phase $phase -ExitReason $exit -ErrorMessage $err -NoTelemetry } catch { }
}
# #317: the END record is sent from the finally at the very end of this script, ONCE, whatever happens after the START --
# success, a refused snapshot, a failure of the load, of the guard calls, of the exec view or of the audit step. It was
# sent from two places in the middle of the run: anything that failed between them (or after) left the run's START
# with no END, which run health shows as a run that never finished.
$rhEnd = @{ Exit = 'success'; Message = '' }
# #639 (working rule 4): every failure a step below CATCHES and goes on from is a run issue -- WARNING (the data is still
# whole elsewhere) or FAILED (data short or missing), one plain line each (SI-RunOutcome.ps1). They reach this run's END
# record; any FAILED one fails the job at the end, after every other step has run. Nothing ends green on a caught failure.
if (-not (Get-Command -Name Get-SIRunIssueOutcome -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\_shared\SI-RunOutcome.ps1') }
$runIssues = New-Object System.Collections.Generic.List[object]
& $sendHealth 'Start' '' ''
try {
# Everything after the START sits inside this try, so its finally sends the END whatever fails (#317).
# Held collections an Admin may release once (Operations > Guards (safety checks)): cfg.GuardRelease in the Pro settings database, the
# same store as the vulnerability connector's held closes. No store = holds stay holds (said once).
$releaseStore = $null
try {
    if (-not (Get-Command -Name New-SIVulnReleaseStore -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\asset-cmdb\_shared\SI-VulnRelease.ps1') }
    $relInvoke = if ($guardCommon.Invoke) { $guardCommon.Invoke } else { $invoke }
    $releaseStore = New-SIVulnReleaseStore -Invoke $relInvoke
} catch { Write-DataWarn ("release   : held collections cannot be offered for release -- {0}" -f $_.Exception.Message) }
try {
    # #834 -SettingsInvoke: the settings database, where the pipeline records its runs (the rows of the collections this
    # sync marks removed are then removed by the pipeline runner while no run is running)
    $res = Invoke-SIDataSyncCore -Query $query -Invoke $invoke -EditionMajor $edition -Settings $settings -DryRun:$DryRun -Log $log -Responsibility $responsibility -ReleaseStore $releaseStore -SettingsInvoke $(if ($guardCommon.Invoke) { $guardCommon.Invoke } else { $invoke })
} catch {
    # the run stopped: "a data sync is running" is taken away now, so the web app's pages move to what is stored at once
    # instead of when its limit passes (the error below is the one that is reported)
    if (-not $DryRun -and (Get-Command -Name Clear-SIDataSyncRunning -ErrorAction SilentlyContinue)) { $null = Clear-SIDataSyncRunning -Invoke $invoke -Log $log }
    if ("$($_.Exception.Message)" -match 'NOT loaded|a chunk of \d+ wrote \d+|could not be marked complete' -and (Get-Command -Name Send-SIGuardEvent -ErrorAction SilentlyContinue)) {
        $null = Send-SIGuardEvent @guardCommon -GuardId 'datasync.collection.short-read' -Outcome 'refused' -Detail $_.Exception.Message
    }
    throw
}
$guardResults = @()
# owner 2026-10-17: a sync that LOADED a newer complete collection, held none, and leaves NOTHING held for this check clears
# an earlier "collection held" by itself. A held collection is never loaded by that: while one is still held (until it
# ends, or an Admin releases it once) the check stays open and says so; one the newer collection superseded is named.
$syncLoadedOne = (-not $DryRun) -and $res.PSObject.Properties['Loaded'] -and @($res.Loaded | Where-Object { $_ }).Count -gt 0
$heldCheck = $null
if ($syncLoadedOne) {
    $newest = @($res.Loaded | Where-Object { $_ -and $_.PSObject.Properties['CollectionTime'] -and $_.CollectionTime } | ForEach-Object { [datetime]$_.CollectionTime } | Sort-Object -Descending) | Select-Object -First 1
    $newestText = if ($newest) { [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0:yyyy-MM-dd HH:mm} UTC', $newest) } else { 'this sync' }
    $stillHeld = 0; $openRead = $true
    if ($releaseStore) { try { $stillHeld = @(@($releaseStore.Open('datasync/detailed')) | Where-Object { $_ -and [string]$(if ($_ -is [System.Collections.IDictionary]) { $_['State'] } else { $_.State }) -eq 'held' }).Count } catch { $openRead = $false } }
    $superseded = 0; if ($res -is [System.Collections.IDictionary]) { if ($res.Contains('SupersededHolds')) { $superseded = [int]$res['SupersededHolds'] } } elseif ($res.PSObject.Properties['SupersededHolds']) { $superseded = [int]$res.SupersededHolds }
    if (-not $openRead) { Write-DataInfo 'guards    : the held collections could not be read -- "collection held" stays open' }
    elseif ($stillHeld -gt 0) { Write-DataInfo ("guards    : the collection of {0} is loaded; {1} older held collection(s) stay held until they end or an Admin releases one -- ""collection held"" stays open" -f $newestText, $stillHeld) }
    else {
        $heldCheck = @{ GuardId = 'datasync.collection.held'
                        Detail = $(if ($superseded -gt 0) { 'The collection of {0} was loaded complete; the {1} older held collection(s) were superseded by it (closed by the current rules, never loaded), so nothing is held any more.' -f $newestText, $superseded }
                                   else { 'The collection of {0} was loaded complete and nothing is held any more.' -f $newestText }) }
    }
}
if (Get-Command -Name Invoke-SIGuardCalls -ErrorAction SilentlyContinue) {
    $syncCalls = @(Get-SIGuardCallsForDataSync -Result $res)
    $guardResults = @(Invoke-SIGuardCalls -Calls $syncCalls -Common $guardCommon -Checked @($heldCheck | Where-Object { $_ }) -Complete ([bool]$heldCheck))
    # #733: the sync's other checks clear by themselves too -- a sync that read and wrote every collection in full clears
    # "not read in full"; one that refused nothing clears "rows without their key"; one that LOADED a collection whose
    # asset kinds all arrived clears "findings an asset kind filter cannot show". A check that tripped in this run stays open.
    if (-not $DryRun -and (Get-Command -Name Invoke-SIGuardHeal -ErrorAction SilentlyContinue)) {
        $syncChecks = @(@{ GuardId = 'datasync.collection.short-read'; Detail = 'Every collection was read and written in full.' },
                        @{ GuardId = 'datasync.collection.refused'; Detail = 'No Risk Analysis data arrived without its key columns.' })
        if ($syncLoadedOne) { $syncChecks += @{ GuardId = 'datasync.asset.kind-dropped'; Detail = 'Every asset kind of the loaded findings arrived with its assets.' } }
        $null = Invoke-SIGuardHeal -Checked $syncChecks -Calls $syncCalls -Complete $true -Common $guardCommon
    }
}
$refusedNote = Get-SIDataRefusedSummary -Result $res
if ($refusedNote) { $rhEnd.Exit = 'success-partial'; $rhEnd.Message = [string]$refusedNote }
# #426: a refusal whose every cause was reported before (the guard said 'already-reported') is not a new partial run --
# ring 1 marked EVERY sync partial for two days over the same 14,624 rows without a collection time. The rows are still
# not loaded and the END still says so; only the verdict is success. A new cause (or the guard switched off) stays partial.
if ($refusedNote -and (Get-Command -Name Test-SIDataRefusalReportedBefore -ErrorAction SilentlyContinue) -and (Test-SIDataRefusalReportedBefore -GuardResults $guardResults)) {
    $rhEnd.Exit = 'success'; $rhEnd.Message = 'reported before, still not loaded (no new alert): ' + [string]$refusedNote
    Write-DataInfo 'refused   : every refused cause was reported in an earlier run -- this run is not marked partial for it again'
}
# #428: an asset kind the findings imply that arrived as 0 CIs (or CIs with no kind) -- the count anomaly on run health
$kindNote = Get-SIDataKindCoverageSummary -Result $res
if ($kindNote) { $rhEnd.Exit = 'success-partial'; $rhEnd.Message = (@([string]$rhEnd.Message, ('asset kinds: ' + $kindNote)) | Where-Object { $_ }) -join ' | ' }
Write-DataOk ("done      : loaded {0} (released, marked partial: {4}) | already loaded {1} | held (run not complete) {2} | refused (key columns missing) {3}" -f @($res.Loaded).Count, @($res.Skipped).Count, @($res.Held).Count, (@($res.Refused).Count + @($res.Untimed).Count), @($res.Released).Count)
# every released collection this run loaded is on the audit trail (the Admin's approval is audited by the web app)
if (@($res.Released).Count -and (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue) -and $guardCommon.Invoke) {
    foreach ($rl in @($res.Released)) {
        [void](Write-SIAuditEvent -Invoke $guardCommon.Invoke -Action 'guard.release.apply' -Actor (Get-SIAuditActor -Job 'data sync') -ActorSource 'job' -Target ('collection/{0:yyyy-MM-ddTHH:mm:ss}' -f $rl.CollectionTime) `
            -Reason ('released by {0}: {1}' -f $rl.ReleasedBy, $rl.Reason) -WhatIfRun:$DryRun -Log $log `
            -After ([ordered]@{ collectionId = $rl.CollectionId; findings = [long]$rl.Findings; markedPartial = [bool]$rl.Marked }))
    }
}
# #725: every collection a stopped run left with all its reports Complete, completed by this run, is on the audit trail
$__finished = @(if ($res -and $res.PSObject.Properties['Finished']) { $res.Finished })
if ($__finished.Count -and (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue) -and $guardCommon.Invoke) {
    foreach ($fc in $__finished) {
        [void](Write-SIAuditEvent -Invoke $guardCommon.Invoke -Action 'datasync.collection.finish' -Actor (Get-SIAuditActor -Job 'data sync') -ActorSource 'job' -Target ('collection/{0:yyyy-MM-ddTHH:mm:ss}' -f $fc.CollectionTime) `
            -Reason 'its run stopped after its verdicts were final, before it marked the collection -- completed by the data sync' -WhatIfRun:$DryRun -Log $log `
            -After ([ordered]@{ collectionId = $fc.CollectionId; reports = [int]$fc.Reports; findings = [long]$fc.Rows; partial = [bool]$fc.Partial }))
    }
}
$global:SI_DataSyncResult = $res
# #639: what the core caught (the findings per CI, the lifecycle, the full asset metadata, the correlation evidence)
foreach ($ci in @(Get-SIDataSyncIssues -Result $res)) { if ($ci) { $runIssues.Add($ci) } }
# #904: a PART that failed (a full database, a timeout, ...) is a failure of THAT part -- named on this run's END record
# (FailedStep + its class, success-partial) and sent to Invardia through the failure uplink (a full database opens a ticket).
# The job completes: each part keeps its last complete result and the next run builds what is missing.
$global:SI_DataSyncPartFailures = @()
if (Get-Command -Name Get-SIDataSyncPartFailures -ErrorAction SilentlyContinue) {
    $partFails = @(Get-SIDataSyncPartFailures -Result $res)
    $global:SI_DataSyncPartFailures = $partFails
    if ($partFails.Count) {
        foreach ($pl in @(Get-SIDataSyncPartFailureText -Failures $partFails)) { Write-DataWarn $pl }
        $runContext | Add-Member -NotePropertyName FailedStep -NotePropertyValue ([string]$partFails[0].Step) -Force
        $runContext | Add-Member -NotePropertyName FailedStepError -NotePropertyValue ([string]$partFails[0].Error) -Force
        $runContext | Add-Member -NotePropertyName FailedStepErrorClass -NotePropertyValue ([string]$partFails[0].ErrorClass) -Force
        $rhEnd.Exit = Merge-SIExitReason $rhEnd.Exit 'success-partial'
        $rhEnd.Message = (@([string]$rhEnd.Message) + @(Get-SIDataSyncPartFailureText -Failures $partFails) | Where-Object { $_ }) -join ' | '
        if (-not $DryRun) {
            foreach ($sr in @(Send-SIDataSyncPartFailures -Failures $partFails -StartedAt $runContext.StartedAt)) {
                Write-DataInfo ("uplink    : the failure of {0} ({1}{2}) was reported to Invardia: {3}" -f $sr.Step, $sr.ErrorClass, $(if ($sr.Code) { ', ' + $sr.Code } else { '' }), $sr.Status)
            }
        }
    }
}

# ---- #583: THE SUMMARY REPORT ROWS (SI_RiskAnalysis_Summary_CL -> sidata.Summary*) (the Risk Analysis Summary rows) -------
# The same rows the RiskAnalysis_Summary workbook is built from, each complete Summary collection once, with its impacted
# assets as rows. #639: a Summary collection that is in Log Analytics and not in the database is MISSING data -- a FAILED
# issue of this run (the other steps still run; the next run tries again while it is inside the look-back window), and so
# is a plan that accounts for fewer collections than Log Analytics lists (_shared\SI-DataSummary.ps1).
# #636: the Summary step is optional and off by default -- while the stored pipeline has it off there is nothing to load and
# nothing to warn about (the views read the groupings of the Detailed findings, step 4d (4) of the core).
$__sumLib = Join-Path $here '..\_shared\SI-SummaryStep.ps1'
if (-not (Get-Command -Name Get-SISummaryStepState -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $__sumLib)) { . $__sumLib }
# not knowable (no reader) = as before: the Summary rows are loaded
$__sumStep = if (Get-Command -Name Get-SISummaryStepState -ErrorAction SilentlyContinue) { Get-SISummaryStepState -Invoke $invoke -StoredOnly } else { 'unknown' }
if ($__sumStep -eq 'off') {
    Write-DataInfo 'summary   : the Risk Analysis Summary step is off -- no Summary rows to load (Security recommendations > Summary shows the groupings of the detailed findings).'
} else {
try {
    . (Join-Path $here '..\_shared\data-sql\SI-DataSummary.ps1')
    $global:SI_DataSummaryResult = Invoke-SIDataSummarySync -Query $query -Invoke $invoke -EditionMajor $edition -Settings $settings -DryRun:$DryRun -Log $log
    # #881 a part that fails is a WARNING (it opens a fix request), never a failed step: the Summary collection stays out of the
    # database, so the run is not published (the publisher checks its summary) and the trusted run stays shown
    if ([string]$global:SI_DataSummaryResult.Problem) { Add-SIRunIssue -Issues $runIssues -Level WARNING -Text ('Risk Analysis Summary: ' + [string]$global:SI_DataSummaryResult.Problem + ' -- this part failed; the next run loads it') }
    foreach ($sf in @($global:SI_DataSummaryResult.Failed)) {
        if ($sf) { Add-SIRunIssue -Issues $runIssues -Level WARNING -Text ('the Summary rows of the collection of {0:yyyy-MM-dd HH:mm} UTC were not loaded ({1}) -- this part failed; they are not in the database and the next run tries again' -f $sf.CollectionTime, [string]$sf.Reason) }
    }
} catch {
    Write-DataWarn ("summary   : the Summary report rows were not loaded this run -- {0}. The findings load is not affected." -f $_.Exception.Message)
    Add-SIRunIssue -Issues $runIssues -Level WARNING -Text ('the Summary report rows were not loaded this run ({0}) -- this part failed; the newest Summary collections are not in the database' -f $_.Exception.Message)
}
}

# ---- DATA OUT (V3-DATA-MODEL 2.12, P5): the outputs, from the CIs, findings and records just stored, through each output
# map in force (the customer's column changes included). Every output is a listed connector (config\data-out.locked.json):
# its run and each item written, changed (column before / now) or no longer sent are on Configuration > Connectors > Runs. Runs
# after the findings and their lifecycle are stored. #639: an output that was not written, or not whole, is a FAILED issue
# of this run (the customer's file / hand-off is missing or short) -- the other steps still run.
# NO WRITER ACTS ON A RUN THAT IS NOT COMPLETE: when the pipeline started this data sync after a failed step (the CI build,
# Risk Analysis), the outputs are held -- nothing goes to the ServiceNow import set or an Excel output from such a run.
# They send only what changed, so the next complete run sends it. Held too when it cannot be told (_shared\SI-DataSync.ps1).
$onStored = Get-SIDataRunOnStored -Invoke $(if ($guardCommon.Invoke) { $guardCommon.Invoke } else { $invoke })
$holdOutputs = [bool]$onStored.OnStored -or -not [bool]$onStored.Known
# #881 the findings per CI are a PART that may fail without failing the step -- then sidata.CiFinding still holds the
# previous collection's set. No output is written from it this run (never a "resolved" or a removal from a set that is not
# the newest): the outputs send only what changed, so the next run that stores the newest set sends it.
$dmPart = $null; if ($res -and ($res -is [System.Collections.IDictionary] -or $res.PSObject.Properties['DataModel'])) { $dmPart = $res.DataModel }
if (Test-SIDataOutHoldForStaleFindings -DataModel $dmPart) {
    Write-DataWarn 'data out  : held this run -- the findings per CI of the newest collection were not stored (a part failed); nothing is sent from the previous set, and the next run sends what changed.'
    $holdOutputs = $true
}
if ($onStored.OnStored) {
    Write-DataWarn ("partial   : this data sync was started after a failed step of the pipeline ({0}). What is stored whole is shown in the web app; nothing was closed, and nothing is sent to an output from this run." -f $onStored.Why)
    $rhEnd.Exit = 'success-partial'
    $rhEnd.Message = (@([string]$rhEnd.Message, 'ran after a failed step of the pipeline, on what is stored: the outputs were held, nothing was closed') | Where-Object { $_ }) -join ' | '
} elseif (-not $onStored.Known) {
    Write-DataWarn ("data out  : held this run -- whether the pipeline's run is complete could not be read ({0}). The outputs send only what changed, so the next run sends it." -f $onStored.Why)
}
if (-not $DryRun -and -not $holdOutputs) {
    try {
        . (Join-Path $siRoot 'engine\data-out\SI-DataOut.ps1')
        $doStore = $null
        try { $doStore = New-SIConnectorRegistryStore } catch { Write-DataWarn ("data out  : the runs are not recorded -- {0}" -f $_.Exception.Message) }
        # per report: the reports the newest run could not complete -- what they found is kept as last sent
        $doFrozen = @(); if ($res -and $res.PSObject.Properties['DataModel'] -and $res.DataModel -and $res.DataModel.PSObject.Properties['FrozenReports']) { $doFrozen = @($res.DataModel.FrozenReports | Where-Object { $_ }) }
        # CR2 (#656): while SecurityInsight's data is Unhealthy each output is held unless a SuperAdmin let its connector through
        $doHold = $null
        try {
            . (Join-Path $siRoot 'engine\_shared\SI-DataHealthHold.ps1')
            $doHold = { param([string]$Connector) Resolve-SIDataHealthHold -Channel $Connector }
        } catch { Write-DataWarn ("data out  : the data health hold could not be checked ({0}) -- the outputs run as configured" -f $_.Exception.Message) }
        $global:SI_DataOutResult = Invoke-SIDataOut -Invoke $invoke -Store $doStore -Edition 'pro' -Log $log -FrozenReports $doFrozen -HoldCheck $doHold
        # #881 an output that was not written whole is a WARNING of this run (it opens a fix request): the outputs send only what
        # changed, so the next run sends it -- the data sync itself completes
        foreach ($dr in @(Get-SIDataOutIssues -Results @($global:SI_DataOutResult))) { if ($dr) { $runIssues.Add([pscustomobject]@{ Level = 'WARNING'; Text = ([string]$dr.Text + $(if ([string]$dr.Level -eq 'FAILED') { ' -- this output failed; the next run sends what changed' } else { '' })) }) } }
    } catch {
        Write-DataWarn ("data out  : not run this time -- {0}. The data sync is not affected." -f $_.Exception.Message)
        Add-SIRunIssue -Issues $runIssues -Level WARNING -Text ('the data-out outputs were not written this run ({0}) -- this part failed; the next run sends what changed' -f $_.Exception.Message)
    }
}

# ---- #288: the Risk Analysis executive view (what each report's mail showed) for the web app's Overview -----------
# Read from the blob each Risk Analysis run keeps beside the shared Top-50 snapshot; never fails the data sync.
try {
    . (Join-Path $siRoot 'engine\risk-analysis\_shared\RA-AISummaryMode.ps1')
    . (Join-Path $siRoot 'engine\risk-analysis\_shared\RA-ExecView.ps1')
    . (Join-Path $here '..\_shared\data-sql\SI-DataExecView.ps1')
    $evAcct = [string]$global:SI_StorageAccount
    $evContainer = if ($global:SI_RATop50_BlobContainer) { [string]$global:SI_RATop50_BlobContainer } else { 'sistaging' }
    if ([string]::IsNullOrWhiteSpace($evAcct)) {
        Write-DataInfo 'exec view : SI_StorageAccount is not set, so the Risk Analysis executive view is not carried into the web app.'
    } else {
        $evRead = {
            param([string]$blobName)
            $ctx = New-SIAzStorageContext -StorageAccountName $evAcct -UseConnectedAccount -ErrorAction Stop
            $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), [System.IO.Path]::GetRandomFileName() + '.json')
            try {
                $prev = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'
                try { Get-SIAzStorageBlobContent -Container $evContainer -Blob $blobName -Destination $tmp -Context $ctx -Force -ErrorAction Stop | Out-Null }
                catch { if ($_.Exception.Message -match 'BlobNotFound|ResourceNotFound|404') { return $null }; throw }
                finally { $ProgressPreference = $prev }
                if (Test-Path -LiteralPath $tmp) { [System.IO.File]::ReadAllText($tmp) } else { $null }
            } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
        $global:SI_ExecViewSyncResult = Invoke-SIDataExecViewSync -ReadView $evRead -Invoke $invoke -Top50BlobName ([string]$global:SI_RATop50_BlobName) -DryRun:$DryRun -Log $log
        # #639: a WARNING (the view stays whole in the blob Risk Analysis keeps; the Overview shows the one carried before)
        if ($global:SI_ExecViewSyncResult -and [string]$global:SI_ExecViewSyncResult.Problem) {
            Add-SIRunIssue -Issues $runIssues -Level WARNING -Text ('the Risk Analysis executive view was not carried into the web app ({0}) -- the Overview shows the one carried before' -f [string]$global:SI_ExecViewSyncResult.Problem)
        }
    }
} catch {
    Write-DataWarn ("exec view : not carried this run -- {0}. The findings load is not affected." -f $_.Exception.Message)
    Add-SIRunIssue -Issues $runIssues -Level WARNING -Text ('the Risk Analysis executive view was not carried into the web app ({0}) -- the Overview shows the one carried before' -f $_.Exception.Message)
}

# ---- THE DETAILED MAIL WITH ITS STORED PROTECTION SCORE (owner 2026-10-22: "protection score must be a %" / "one computation,
# never two that can differ") -- after the key figures (in the core) and after the executive view is carried: the kept Detailed
# view takes its collection's STORED score, then every Detailed mail waiting in sidata.RaMailOutbox is sent with it (or with
# the one line why), claimed so it is never sent twice, put back when the send fails (engine\_shared\data-sql\SI-RaMailOutbox.ps1).
try {
    . (Join-Path $siRoot 'engine\_shared\SI-ProtectionScore.ps1')
    . (Join-Path $siRoot 'engine\risk-analysis\_shared\RA-ReportMail.ps1')
    if (-not (Get-Command -Name Send-SIMail -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\_shared\SI-MailTransport.ps1') }
    . (Join-Path $siRoot 'engine\_shared\data-sql\SI-RaMailOutbox.ps1')
    if (-not $DryRun) { $global:SI_RaExecProtectionResult = Update-SIRaExecViewProtection -Invoke $invoke -Log $log }
    $rmKf = $null; if ($res -and ($res -is [System.Collections.IDictionary] -or $res.PSObject.Properties['KeyFigures'])) { $rmKf = $res.KeyFigures }
    # review B1: whether THIS job can send is recorded for the Detailed runs -- they keep a mail for the stored score only then
    if (-not $DryRun) { $global:SI_RaMailSenderState = Set-SIRaMailSender -Invoke $invoke -MailSettings (Get-SIMailSettings) -Log $log }
    $rmSend = { param($m) $s = Get-SIMailSettings; if ($m.From) { $s.From = $m.From }; $r = Send-SIMail -Settings $s -To @($m.To) -Subject $m.Subject -BodyHtml $m.BodyHtml -Attachments @($m.Attachments) -Priority $m.Priority; @{ Sent = [bool]$r.Sent; Error = [string]$r.Error } }
    $global:SI_RaMailOutboxResult = Invoke-SIRaMailOutbox -Invoke $invoke -Role datasync -Send $rmSend -RunStartedUtc $runContext.StartedAt -KeyFigures $rmKf -DryRun:$DryRun -Log $log
    if ($global:SI_RaMailOutboxResult -and [int]$global:SI_RaMailOutboxResult.Failed -gt 0) {
        Add-SIRunIssue -Issues $runIssues -Level WARNING -Text ('{0} Risk Analysis Detailed mail(s) could not be sent this run -- they wait, and the next run sends them' -f [int]$global:SI_RaMailOutboxResult.Failed)
    }
} catch {
    Write-DataWarn ("risk analysis mail: the waiting Detailed mails were not sent this run -- {0}. They wait; the next run sends them." -f $_.Exception.Message)
    Add-SIRunIssue -Issues $runIssues -Level WARNING -Text ('the waiting Risk Analysis Detailed mails were not sent this run ({0}) -- they wait, and the next run sends them' -f $_.Exception.Message)
}

# ---- #260: the audit trail (it lives in the Pro SETTINGS database, which the data may share or not) -------------
# The responsibility re-resolution is a job-driven state change: one event when collections were (or, in a dry run,
# would be) resolved. Then the audited retention step: trail rows older than SI_Pro_AuditRetentionMonths (not set =
# kept forever, at least 13). A failure here is said and recorded; it never fails the data sync.
. (Join-Path $siRoot 'engine\pro-settings\SI-Audit.ps1')
$auditInvoke = $invoke
$psrv = [string]$global:SI_ProSqlServer; $pdb = [string]$global:SI_ProSqlDatabase
if ($psrv -and $pdb -and ($psrv -ne [string]$settings.Server -or $pdb -ne [string]$settings.Database)) {
    $auditInvoke = New-SIDataSqlInvoke -Server $psrv -Database $pdb -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint
}
$auditActor = Get-SIAuditActor -Job 'data sync'
$auditLog = { param([string]$level, [string]$msg) switch ($level) { 'OK' { Write-DataOk $msg } 'WARN' { Write-DataWarn $msg } default { Write-DataInfo $msg } } }
$resp = $res.Responsibility
if ($resp -and [int]$resp.Pending -gt 0) {
    [void](Write-SIAuditEvent -Invoke $auditInvoke -Action 'datasync.responsibility.resolve' -Actor $auditActor -ActorSource 'job' -Target 'sidata.Finding (department)' `
        -Reason 'the responsibility policy changed or new collections arrived' -WhatIfRun:$DryRun -Log $auditLog `
        -After ([ordered]@{ collections = [int]$resp.Pending; findings = [long](@($resp.Resolved | ForEach-Object { $_.Findings }) | Measure-Object -Sum).Sum; fingerprint = [string]$resp.Fingerprint }))
}
# #301: the full asset metadata pruned from the Pro database to SI_AssetProperties_RetentionDays -- one audited event.
$apPrune = $null; if ($res -and ($res -is [System.Collections.IDictionary] -or $res.PSObject.Properties['AssetPropertiesPrune'])) { $apPrune = $res.AssetPropertiesPrune }
if ($apPrune) {
    [void](Write-SIAuditEvent -Invoke $auditInvoke -Action 'datasync.assetproperties.prune' -Actor $auditActor -ActorSource 'job' -Target 'sidata.AssetMetadata + sidata.Asset (full asset metadata)' `
        -Reason ('full asset metadata is kept {0} day(s) (SI_AssetProperties_RetentionDays)' -f $apPrune.RetentionDays) -WhatIfRun:$DryRun -Log $auditLog `
        -After ([ordered]@{ retentionDays = [int]$apPrune.RetentionDays; assets = [long]$apPrune.Assets; metadataRows = [long]$apPrune.MetadataRows; cutoffUtc = ([datetime]$apPrune.Cutoff).ToString('o', [Globalization.CultureInfo]::InvariantCulture) }))
}
# #717: the collections' own retention -- what was removed, per collection and per table, is on the trail (product data is
# removed only by product code, and audited). One event per run that removed anything.
$colRet = $null; if ($res -and ($res -is [System.Collections.IDictionary] -or $res.PSObject.Properties['CollectionRetention'])) { $colRet = $res.CollectionRetention }
if ($colRet -and @($colRet.Removed).Count -gt 0) {
    [void](Write-SIAuditEvent -Invoke $auditInvoke -Action 'datasync.collection.retention' -Actor $auditActor -ActorSource 'job' -Target 'sidata.Finding + sidata.Recommendation + sidata.IssueContext + sidata.Summary* (older and abandoned collections)' `
        -Reason 'per kind the newest complete collection and the one before it are kept; older collections, and collections a stopped run left loading, have their rows removed' -WhatIfRun:$DryRun -Log $auditLog `
        -After ([ordered]@{ rows = $colRet.Rows
                            collections = @(@($colRet.Removed) | ForEach-Object { [ordered]@{ kind = $_.Grain; collectionId = $_.CollectionId; collectionTimeUtc = ([datetime]$_.CollectionTime).ToString('o', [Globalization.CultureInfo]::InvariantCulture); why = $(if ($_.Why) { $_.Why } else { 'finished' }) } })
                            refused = @(@($colRet.Refused) | ForEach-Object { [ordered]@{ kind = $_.Grain; collectionId = $_.CollectionId } }) }))
}
# the run's END record says what the retention could not do and how full the database is above 70 % -- in plain words;
# the verdict is not changed by either (the data is whole; the next run tries the retention again)
if ($colRet -and [string]$colRet.Status -eq 'failed') { $rhEnd.Message = (@([string]$rhEnd.Message, ('retention: ' + [string]$colRet.Text)) | Where-Object { $_ }) -join ' | ' }
$dbFill = $null; if ($res -and ($res -is [System.Collections.IDictionary] -or $res.PSObject.Properties['DatabaseFill'])) { $dbFill = $res.DatabaseFill }
if ($dbFill -and $dbFill.Warn) { $rhEnd.Message = (@([string]$rhEnd.Message, ('database: ' + [string]$dbFill.Text)) | Where-Object { $_ }) -join ' | ' }
# #296 / #297-#298: every repair of stored data is on the trail (a dry run is recorded as one)
$rn = $res.ReportNames
if ($rn -and [long]$rn.Findings -gt 0) {
    [void](Write-SIAuditEvent -Invoke $auditInvoke -Action 'datasync.reportname.backfill' -Actor $auditActor -ActorSource 'job' -Target 'sidata.Finding (ReportName)' `
        -Reason 'findings stored without the report they came from; each one''s own data names it' -WhatIfRun:$DryRun -Log $auditLog `
        -After ([ordered]@{ findings = [long]$rn.Findings; collections = @(@($rn.Collections) | ForEach-Object { [ordered]@{ collectionId = $_.CollectionId; day = $_.Day; findings = $_.Findings } }) }))
}
$mg = $res.Merges
if ($mg -and (@($mg.Merged).Count -gt 0 -or @($mg.Skipped).Count -gt 0)) {
    [void](Write-SIAuditEvent -Invoke $auditInvoke -Action 'datasync.asset.merge' -Actor $auditActor -ActorSource 'job' -Target 'sidata.Asset (duplicates of one device)' `
        -Reason 'an asset whose id another asset carries (an Entra or Defender device id, an earlier asset id) is the same device' -WhatIfRun:$DryRun -Log $auditLog `
        -Outcome $(if (@($mg.Skipped).Count -gt 0) { 'held' } else { 'ok' }) -OutcomeText $(if (@($mg.Skipped).Count -gt 0) { ('{0} duplicate(s) not merged -- see the list' -f @($mg.Skipped).Count) } else { '' }) `
        -After ([ordered]@{ findingsMoved = [long]$mg.Findings
                            merged  = @(@($mg.Merged) | ForEach-Object { [ordered]@{ from = $_.From; fromName = $_.FromName; to = $_.To; toName = $_.ToName; via = $_.Via; findings = $_.Findings } })
                            skipped = @(@($mg.Skipped) | ForEach-Object { [ordered]@{ asset = $_.From; name = $_.FromName; why = $_.Reason } }) }))
}
try {
    $global:SI_AuditRetentionResult = Invoke-SIAuditRetention -Invoke $auditInvoke -Months (Get-Variable -Name SI_Pro_AuditRetentionMonths -Scope Global -ValueOnly -ErrorAction SilentlyContinue) `
        -DryRun:$DryRun -Actor $auditActor -Log $auditLog
} catch { Write-DataWarn ("audit     : the audit trail's retention step failed -- {0}. The trail is kept; it is tried again on the next run." -f $_.Exception.Message) }
if ($global:SI_AuditRetentionResult -and [string]$global:SI_AuditRetentionResult.Problem -and (Get-Command -Name Send-SIGuardEvent -ErrorAction SilentlyContinue)) {
    $null = Send-SIGuardEvent @guardCommon -GuardId 'audit.retention.refused' -Outcome 'refused' -Detail ([string]$global:SI_AuditRetentionResult.Problem) -Values @(@{ Name = 'retentionMonths'; Label = 'Retention set (months)'; Measured = (Get-Variable -Name SI_Pro_AuditRetentionMonths -Scope Global -ValueOnly -ErrorAction SilentlyContinue); Limit = 13 })
}

# ---- the tenant's own name for the web app's header (TENANT) -------------------------------------------------------
# Read from Entra ID (Graph GET /organization) as this engine's identity -- Directory.Read.All is in its grants -- and
# recorded in the Pro settings database (cfg.InstallState 'Tenant') only when it changed. So an install made before setup
# recorded it, or a renamed tenant, shows the right name the next day without anyone running a script. Read-only towards
# the tenant; never fails the data sync; a dry run reads nothing.
if (-not $DryRun) {
    try {
        $siTenantFile = Join-Path $siRoot 'engine\_shared\SI-InstallTenant.ps1'
        if (-not (Get-Command -Name Invoke-SIRecordInstallTenant -ErrorAction SilentlyContinue)) { . $siTenantFile }
        if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'auth\Get-SIGraphToken.ps1') }
        if (-not (Get-Command -Name Invoke-SIGraphRest -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine\_shared\SI-GraphRest.ps1') }
        $global:SI_TenantRefreshResult = Invoke-SIRecordInstallTenant -Store ([pscustomobject]@{ Invoke = $auditInvoke }) -TenantId ([string]$global:SI_SPN_TenantId) -SetBy 'data sync' -OnlyIfChanged `
            -GraphGet { Invoke-SIGraphRest -Uri '/organization?$select=id,displayName,verifiedDomains' -Token (Get-SIGraphToken -Resource Graph) -TimeoutSec 30 -MaxAttempts 2 }
        if ($global:SI_TenantRefreshResult.Written) { Write-DataOk ("tenant    : {0}" -f $global:SI_TenantRefreshResult.Reason) }
        else { Write-DataInfo ("tenant    : {0}" -f $global:SI_TenantRefreshResult.Reason) }
    } catch { Write-DataWarn ("tenant    : the tenant's name was not refreshed -- {0}. The header keeps what is recorded." -f $_.Exception.Message) }
}

# ---- #577 step 2: DATA-QUALITY WARNINGS from a three-run fingerprint -------------------------------------------------
# The ONE point that measures the run's key numbers (assets per source, rows per Risk Analysis report, fill of the key
# columns, CIs per tier, active / to-retire CIs, CI owner fill) -- here, because this is the last Deliver step after every
# engine that produces them, and it holds both Log Analytics and the Pro database. Each number against the median of the
# last 3 runs; the likely cause from cfg.ChangeLog (the settings database); one line per anomaly on this run's END record;
# a mail only when the warnings differ from the last mailed run (at most one a day). NEVER blocks: no guard event, the verdict is unchanged, and a
# failure here is said and ignored (_shared\SI-DataQuality.ps1).
try {
    . (Join-Path $here '_shared\SI-DataQuality.ps1')
    $dqSmtp = $null
    if ((Get-Command -Name Send-SIMail -ErrorAction SilentlyContinue) -and (Get-Command -Name Get-SIGuardSmtp -ErrorAction SilentlyContinue)) { $dqSmtp = Get-SIGuardSmtp }
    # a plain block (no closure): it sees this script's functions and $dqSmtp when Invoke-SIDataQuality calls it
    $dqSend = { param([string[]]$to, [string]$subject, [string]$html) if (-not $dqSmtp) { return $false }; $r = Send-SIMail -Settings $dqSmtp -To $to -Subject $subject -BodyHtml $html; [bool]$r.Sent }
    $global:SI_DataQualityResult = Invoke-SIDataQuality -Query $query -Invoke $invoke -SettingsInvoke $auditInvoke -Send $dqSend -RunId $runContext.RunId `
        -LookbackDays ([int]$settings.LookbackDays) -DryRun:$DryRun -Log $log
    $dqLines = @($global:SI_DataQualityResult.Lines)
    if ($dqLines.Count) { $rhEnd.Message = (@([string]$rhEnd.Message) + $dqLines | Where-Object { $_ }) -join ' | ' }
    # classification incomplete (owner 2026-10-19): a WARNING of the run -- counts only -- that the telemetry carries to Invardia
    $dqClass = [string]$global:SI_DataQualityResult.ClassificationIssue
    if ($dqClass) { Add-SIRunIssue -Issues $runIssues -Level WARNING -Text $dqClass }
} catch {
    Write-DataWarn ("data quality: not measured this run -- {0}. Nothing was blocked." -f $_.Exception.Message)
    # #639: a WARNING -- nothing is missing from the data; this run's numbers were not compared with the last runs'
    Add-SIRunIssue -Issues $runIssues -Level WARNING -Text ('data quality was not measured this run ({0}) -- the data itself is not affected' -f $_.Exception.Message)
}

# ---- #639: THE RUN'S VERDICT -- what every step above caught, on the END record; a FAILED issue fails the job ----------
$issueOut = Get-SIRunIssueOutcome -Issues $runIssues.ToArray()
if ($issueOut.ExitReason -ne 'success') {
    $rhEnd.Exit = Merge-SIExitReason $rhEnd.Exit $issueOut.ExitReason
    $rhEnd.Message = (@([string]$rhEnd.Message, [string]$issueOut.Message) | Where-Object { $_ }) -join ' | '
    foreach ($ri in $runIssues) { Write-DataWarn ('{0,-9} : {1}' -f $ri.Level, $ri.Text) }
}
$global:SI_DataSyncIssues = $runIssues.ToArray()
if ($issueOut.Failed) {
    # after every step ran: the job fails, and its END record names every issue (the catch below keeps this message)
    throw ('the data sync did not deliver everything this run -- ' + [string]$rhEnd.Message)
}
} catch {
    $rhEnd.Exit = 'error'; $rhEnd.Message = $_.Exception.Message
    throw
} finally {
    # #317: the run's END record -- once, success or failure
    & $sendHealth 'End' $rhEnd.Exit $rhEnd.Message
}
