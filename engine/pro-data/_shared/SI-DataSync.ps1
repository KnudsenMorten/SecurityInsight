#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE DATA SYNC (REQUIREMENTS §9.3.3 phase B): Log Analytics -> the Pro database.

    Invoke-SIDataSyncCore is the whole algorithm behind two seams, so it runs offline in the tests exactly as it runs
    in the container:
        -Query   scriptblock (kql) -> rows          Log Analytics (throws on failure)
        -Invoke  scriptblock (sql, params, mode)    the Pro database (SI-DataSql.ps1)

    THE ALGORITHM
      1. The database must carry the sidata schema (setup\Initialize-SIDataSql.ps1) -- otherwise the run stops. Additive
         columns added to the schema later (FindingDaily.ScoreMax) are added here when missing, guarded, never altered.
      2. Every Risk Analysis Detailed collection of this edition in the look-back window is listed with its row count
         and size; what SQL already holds is read; the run-health END records say which runs ended 'success'.
      3. Per collection (oldest first): already loaded -> skipped; producing run not shown complete -> HELD (never
         loaded: partial data is never stored as a collection); a load that died part way -> its rows are removed and
         it is loaded again; otherwise loaded.
      4. A load: the run row, a 'Loading' collection row, the findings A PAGE AT A TIME (Read-SIDataPages: the pages
         are planned from the collection's measured size, each answer well under the query limits; a page is written
         set-based in measured chunks BEFORE the next page is read, so the job holds one page whatever the size of
         the collection; a page that is still too large is cut in two, alone), then the CIs (assets + identifiers) and the
         Defender for Cloud recommendations in force at that time, then the CIs' correlation evidence (#299,
         SI-DataEvidence.ps1: the source records behind each CI, the rule and confidence that joined them, the id history
         and the conflicts, and the collection's per-CI correlation rows). The collection becomes 'Complete' only when the
         findings written equal the rows Log Analytics held. Then that day's FindingDaily is recomputed.
      4b. The collection views' data (#241): every complete collection without it gets its columns filled from
         DetailJson (in measured FindingId ranges) and its per-collection aggregates (sidata.FindingFacet). A database
         whose schema predates these columns is said once; the load itself is not affected.
      4c. Asset responsibility (#254, SI-DataResponsibility.ps1): the tags of the CIs just loaded are stored, every CI
         gets its department, and every collection resolved with another policy (or never) is resolved again -- each
         finding stamped with its department and the source of that answer, plus a per-department aggregate.
      5. VulnLifecycleDaily is recomputed from vuln.VulnerabilityEvent (when the close-loop is installed).
      4f. Full asset metadata (#408 / #412, SI-DataAssetMetadata.ps1): ONLY when SI_AssetProperties = 'full', every
         SI_AssetProperties_CL snapshot (one per profiler run) inside the retention window is stored generically in
         sidata.AssetMetadata (one row per CI, source system, record and item; the source object as JSON, arrays kept as
         arrays), once per snapshot -- older snapshots are KEPT, so the asset page shows the history.
      6. Retention: collections older than SI_Pro_DataRetentionDays are purged in batches (sidata only); the full asset
         metadata after SI_AssetProperties_RetentionDays (6b).
      6a. The collections' own retention (#717, SI-DataSql.ps1 Invoke-SIDataCollectionRetention): per grain the newest
         complete collection and the one before it are kept; the finding rows of older ones, and of collections a stopped
         run left 'Loading' once a newer one is complete, are removed (the collection row and its aggregates stay, marked).
      6c. How full the database is: above 70 % of its maximum size the run says so (SI-DataSql.ps1 Get-SIDataFill).

    A source table that does not exist yet (a fresh install) is skipped with one line; any other failure stops the run.
    PS 5.1 safe.
#>

# #904 (a large install 2026-10-26: "The database ... has reached its size quota"; the narrow findings, the groupings, the
# remediations and the key figures of a collection failed, each only a WARN line, and the run ended Success): EVERY part of
# the data sync that can fail on its own -- its key in Invoke-SIDataSyncCore's result, the words the run says, and the step id
# its failure is reported under (Job si-datasync, FailedStep). A part that fails keeps its last complete result and the job
# completes (owner: "a report fails alone, the job completes"); its failure is a WARNING of the run, on the run record and to
# Invardia (Get-SIDataSyncPartFailures / Send-SIDataSyncPartFailures).
$script:SIDataSyncParts = [ordered]@{
    DataModel           = @{ Name = 'the findings per CI'; Step = 'ci-findings' }
    Narrow              = @{ Name = 'the narrow findings'; Step = 'narrow-findings' }
    ExemptedTwins       = @{ Name = 'the counted aggregates without exempted findings'; Step = 'exempted-twins' }
    ViewsReady          = @{ Name = 'the collection views'' ready marks'; Step = 'views-ready' }
    ViewContext         = @{ Name = 'the prepared view columns'; Step = 'view-context' }
    Remediations        = @{ Name = 'the remediations'; Step = 'remediations' }
    KeyFigures          = @{ Name = 'the key figures'; Step = 'key-figures' }
    CveSummary          = @{ Name = 'the CVE summary'; Step = 'cve-summary' }
    AssetRiskSummary    = @{ Name = 'the asset risk summary'; Step = 'asset-risk-summary' }
    DomainCategory      = @{ Name = 'the domain and category totals'; Step = 'domain-category' }
    ReportPreview       = @{ Name = 'the report previews'; Step = 'report-preview' }
    CiFindingSummary    = @{ Name = 'the findings-per-CI summary'; Step = 'ci-finding-summary' }
    FindingPivots       = @{ Name = 'the finding pivots'; Step = 'finding-pivots' }
    Changes             = @{ Name = 'the changes since the previous collection'; Step = 'changes' }
    Tier0               = @{ Name = 'the top tier-0 assets'; Step = 'tier0' }
    SummaryGroups       = @{ Name = 'the Summary groupings'; Step = 'summary-groups' }
    VulnOpenCounts      = @{ Name = 'the open vulnerability counts'; Step = 'vuln-open-counts' }
    ColumnChoices       = @{ Name = 'the column choices'; Step = 'column-choices' }
    Holds               = @{ Name = 'the closing of older held collections'; Step = 'holds' }
    AssetMetadata       = @{ Name = 'the full asset metadata'; Step = 'asset-metadata' }
    CollectionRetention = @{ Name = 'the collections'' own retention'; Step = 'collection-retention' }
    ViewVersion         = @{ Name = 'the views'' data mark'; Step = 'views-mark' }
}

function Invoke-SIDataSyncCore {
    param(
        [Parameter(Mandatory)][scriptblock]$Query,
        [Parameter(Mandatory)][scriptblock]$Invoke,
        [Parameter(Mandatory)][string]$EditionMajor,
        [Parameter(Mandatory)]$Settings,                 # Resolve-SIDataSettings output
        [switch]$DryRun,
        [datetime]$Now = [datetime]::UtcNow,
        [scriptblock]$Log,
        $Responsibility,                                 # Resolve-SIDataResponsibilitySettings output; $null = the defaults
        $ReleaseStore,                                   # New-SIVulnReleaseStore over cfg.GuardRelease: held collections an Admin may release once; $null = none
        # #830 the copy of the report rows to Log Analytics (SendToLogAnalytics; not set = off): only while it is on is
        # SI_RiskAnalysis_Detailed_CL listed, as the fallback for a run whose result could not go to the database
        [AllowNull()]$ReportCopy = $global:SendToLogAnalytics,
        # #834 the settings database (cfg.FlowRun / FlowStepRun): when the pipeline started this data sync, the rows of the
        # collections it marks removed are left to the pipeline runner's wake-ups (they run while no run is running)
        [scriptblock]$SettingsInvoke
    )
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    if ($null -eq $Responsibility -and (Get-Command -Name Resolve-SIDataResponsibilitySettings -ErrorAction SilentlyContinue)) { $Responsibility = Resolve-SIDataResponsibilitySettings -Globals @{} }
    # closures: a plain block would find $Log in the scope it is called in -- inside a function with a -Log of its own
    # that is a different block, and one that calls back here recurses until the call depth overflows
    $info = { param($m) & $Log 'INFO' $m }.GetNewClosure()
    $ok   = { param($m) & $Log 'OK' $m }.GetNewClosure()
    $warn = { param($m) & $Log 'WARN' $m }.GetNewClosure()
    $lookback = [int]$Settings.LookbackDays
    # PER-PHASE TIMING (2026-10-25): every phase says its seconds in the log AND writes them to cfg.StepPhaseTime (Write-SIStepPhase,
    # readable through the Support app) -- measurement only, it never fails the data sync. A plain block: called only here.
    if (-not (Get-Command -Name Write-SIStepPhase -ErrorAction SilentlyContinue)) {
        $spf = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), '_shared', 'SI-StepPhase.ps1')
        if (Test-Path -LiteralPath $spf) { . $spf }
    }
    $phaseInvoke = $Invoke; if ($SettingsInvoke) { $phaseInvoke = $SettingsInvoke }
    $phaseClock = [Diagnostics.Stopwatch]::StartNew()
    # the SQL pacing's own waits (SI-SqlPacing.ps1: the job sleeps before a range while the database is saturated -- time that
    # is in no SQL statement): per phase, the seconds the pacer waited, as a row of its own ('<phase>: paused')
    $phasePaced = @{ S = 0.0 }
    $phase = {
        param([string]$Name, [long]$Rows = -1)
        $sec = $phaseClock.Elapsed.TotalSeconds; $phaseClock.Restart()
        & $Log 'INFO' ("timing      : {0} -- {1:N1} s{2}" -f $Name, $sec, $(if ($Rows -ge 0) { (', {0:N0} row(s)' -f $Rows) } else { '' }))
        if (-not $DryRun -and (Get-Command -Name Write-SIStepPhase -ErrorAction SilentlyContinue)) { $null = Write-SIStepPhase -Invoke $phaseInvoke -Job 'asset-datasync' -Phase $Name -Seconds $sec -Rows $Rows }
        $pz = 0.0; if (Get-Command -Name Get-SISqlPacingSummary -ErrorAction SilentlyContinue) { try { $pz = [double](Get-SISqlPacingSummary -Invoke $Invoke).PausedSeconds } catch { $pz = $phasePaced.S } }
        $pd = $pz - $phasePaced.S; $phasePaced.S = $pz
        if ($pd -gt 0) {
            & $Log 'INFO' ("timing      : {0} -- of it {1:N1} s waited by the SQL pacing (the database was saturated)" -f $Name, $pd)
            if (-not $DryRun -and (Get-Command -Name Write-SIStepPhase -ErrorAction SilentlyContinue)) { $null = Write-SIStepPhase -Invoke $phaseInvoke -Job 'asset-datasync' -Phase ($Name + ': paused') -Seconds $pd }
        }
    }

    # A table that does not exist yet reads as $null (said once); every other failure is rethrown.
    $readOrSkip = {
        param([string]$kql, [string]$table)
        try { , @(& $Query $kql) }
        catch {
            if (Test-SIKqlTableMissing -ErrorRecord $_ -TableName $table) { & $warn ("{0} does not exist in this workspace yet -- skipped." -f $table); return $null }
            throw
        }
    }

    $result = [ordered]@{ Plan = @(); Loaded = @(); Held = @(); Skipped = @(); Refused = @(); Untimed = @(); Released = @(); AssetDays = 0; ReportNames = $null; Merges = $null; Derived = @(); Exempted = @(); Cmdb = $null; Tags = $null; Responsibility = $null; Lifecycle = $null; Retention = $null; DryRun = [bool]$DryRun }

    # ---- 1. schema -----------------------------------------------------------------------------------------------
    if ([int](& $Invoke (Get-SIDataSchemaCheckSql) @{} 'scalar') -ne 1) {
        throw 'the Pro database does not have the data tables yet -- run setup\Initialize-SIDataSql.ps1 once, then run this again.'
    }
    # The highest finding score per daily group (#245) -- an ADDITIVE column a database set up earlier does not have yet.
    if (-not $DryRun) { [void](& $Invoke (Get-SIDataScoreMaxColumnSql) @{} 'scalar') }
    # The exemption MARK on every finding (#264) -- additive columns, so a finding exempted before this sync lands marked.
    if (-not $DryRun) { [void](& $Invoke (Get-SIDataExemptionColumnsSql) @{} 'scalar') }
    # The distinct assets at every grain (#295) -- additive tables a database set up earlier does not have yet.
    if (-not $DryRun) { [void](& $Invoke (Get-SIDataAssetDailyTablesSql) @{} 'scalar') }
    # #855 W10: the CI lifecycle on every finding and on the derived tables that carry it -- additive columns (the schema file's
    # own statements), so an install whose schema was applied before them stamps from this run on. Never fails the sync.
    if (-not $DryRun) { try { [void](& $Invoke (Get-SIDataCiLifecycleColumnsSql) @{} 'scalar') } catch { & $warn ("lifecycle   : the lifecycle columns could not be added ({0}) -- the findings count as active this run; the next update adds them" -f $_.Exception.Message) } }
    # #717: the retention mark (sidata.Collection.RetiredAt) -- additive; from here on every step leaves a collection whose
    # rows the retention removed out (Get-SIDataLiveFilter). A database without it reads as before.
    $retiredReady = $false
    try {
        $rr = if ($DryRun) { & $Invoke (Get-SIDataRetiredReadySql) @{} 'scalar' } else { & $Invoke (Get-SIDataRetiredColumnsSql) @{} 'scalar' }
        $retiredReady = ([string]$rr -eq '1')
    } catch { & $warn ("collections : the retention mark could not be added ({0}) -- old collections are not removed this run; the next run tries again" -f $_.Exception.Message) }
    Set-SIDataRetiredReady -Ready $retiredReady
    # "A data sync is running" (sidata.ViewState 'sync'), before the first row is stored: the web app keeps serving the
    # pages it has until this run's end mark (step 7), and says so in its header. Never fails the data sync.
    if (-not $DryRun -and (Get-Command -Name Set-SIDataSyncRunning -ErrorAction SilentlyContinue)) { $result['SyncRunning'] = Set-SIDataSyncRunning -Invoke $Invoke -Now $Now -Log $Log }

    # ---- 2a. held collections an Admin RELEASED (Operations > Guards (safety checks), "Release: load this collection anyway") ------
    # Read first: a released collection older than the look-back window widens the listing just enough to reach it.
    $released = Read-SIDataReleasedCollections -Store $ReleaseStore -Log $Log
    $listDays = $lookback
    foreach ($r in $released) { $age = [int][Math]::Ceiling(($Now - $r.CollectionTime).TotalDays) + 1; if ($age -gt $listDays) { $listDays = $age } }

    # ---- 2. what exists ------------------------------------------------------------------------------------------
    # #830 (owner 2026-10-20): Pro reads Risk Analysis Detailed from the DATABASE only -- Risk Analysis writes its result there
    # itself (#638) and its collections are completed below (Get-SIDataRaPendingSql). The report rows in Log Analytics
    # (SI_RiskAnalysis_Detailed_CL) are an optional output, OFF by default (SendToLogAnalytics, Test-SIRaReportCopyOn): only
    # while it is on are they listed here -- the fallback for a run whose result could not go to the database.
    $laCopy = $false
    try {
        if (-not (Get-Command -Name Test-SIRaReportCopyOn -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'risk-analysis', '_shared', 'RA-Findings.ps1')) }
        $laCopy = [bool](Test-SIRaReportCopyOn -Value $ReportCopy)
    } catch { $laCopy = $false }
    $collections = @(); $runs = @()
    if ($laCopy) {
        $collections = & $readOrSkip (Get-SIDataCollectionsKql -EditionMajor $EditionMajor -LookbackDays $listDays) 'SI_RiskAnalysis_Detailed_CL'
        if ($null -eq $collections) { $collections = @() }
    }
    # a reader answer is ONE array object (as in SI-VulnTarget.ps1): assigned first, then enumerated
    $loadedRaw = & $Invoke (Get-SIDataLoadedSql) @{ Kind = 'Detailed'; Since = (Format-SIDataSqlTime -Time $Now.AddDays(-($listDays + 1))) } 'reader'
    $loaded = @($loadedRaw)
    if ($laCopy) {
        # the run-health END records WITH their message (Get-SIDataRunHealthKql): a held collection says what was incomplete
        $runs = & $readOrSkip (Get-SIDataRunHealthKql -LookbackDays ($listDays + 1)) 'SI_RunHealth_CL'
        if ($null -eq $runs) { $runs = @() }
        & $info ("collections : {0} Risk Analysis Detailed collection(s) of edition {1} in Log Analytics in the last {2} day(s); {3} already in the database" -f @($collections).Count, $EditionMajor, $listDays, @($loaded | Where-Object { $_ -and [string]$_['Status'] -eq 'Complete' }).Count)
    } else {
        & $info ("collections : the Risk Analysis Detailed results are read from the database ({0} complete in the last {1} day(s)); the copy of the report rows to Log Analytics is off, so Log Analytics is not read for them" -f @($loaded | Where-Object { $_ -and [string]$_['Status'] -eq 'Complete' }).Count, $listDays)
    }
    $result['ReportCopy'] = $laCopy

    # ---- 3. the plan ---------------------------------------------------------------------------------------------
    $loadedRows = @($loaded | ForEach-Object { if ($_) { [pscustomobject]@{ CollectionId = $_['CollectionId']; CollectionTime = $_['CollectionTime']; Status = $_['Status']; Source = $(if ($_ -is [System.Collections.IDictionary] -and $_.Contains('Source') -and $_['Source'] -isnot [System.DBNull]) { [string]$_['Source'] } else { '' })
        Retired = ($_ -is [System.Collections.IDictionary] -and $_.Contains('Retired') -and $_['Retired'] -isnot [System.DBNull] -and [int]$_['Retired'] -eq 1) } } })
    $plan = Get-SIDataLoadPlan -Collections @($collections) -Loaded $loadedRows -Runs @($runs) -Now $Now -LookbackDays $lookback
    # a wider listing (for a released collection) never plans anything else outside the usual window
    if ($listDays -gt $lookback) {
        $edge = $Now.AddDays(-$lookback)
        $plan = @($plan | Where-Object { $_.CollectionTime -ge $edge -or (Find-SIDataReleasedCollection -Released $released -CollectionTime $_.CollectionTime) })
    }
    # #414: a held collection a newer complete one superseded is no longer held (no event, no mail, no release offered)
    $plan = @(Set-SIDataSupersededPlan -Plan @($plan) -Released $released)
    $superseded = @($plan | Where-Object { $_ -and [string]$_.Action -eq 'Superseded' })
    if ($superseded.Count) { & $info ("superseded  : {0} held collection(s) are superseded by a newer complete collection -- no longer held, not loaded" -f $superseded.Count) }
    # #448: a collection held only because its run was PARTIAL is loaded now, marked partial (a warning, never a block);
    # only a real failure (the run failed outright, is still running, or left no record) stays held
    $plan = @(Set-SIDataPartialRunPlan -Plan @($plan) -Loaded $loadedRows -Runs @($runs))
    foreach ($pp in @($plan | Where-Object { $_ -and $_.Partial -and [string]$_.ReleasedBy -like 'the current rules*' })) {
        & $warn ("partial     : the collection of {0:yyyy-MM-dd HH:mm} UTC is loaded and MARKED PARTIAL -- its Risk Analysis run did not finish every report; what it missed is unknown, not resolved" -f $pp.CollectionTime)
    }
    $plan = @(Set-SIDataReleasedPlan -Plan @($plan) -Released $released -Loaded $loadedRows -Runs @($runs) -Store $ReleaseStore -DryRun:$DryRun -Log $Log)
    # #414: the guard switched off (Settings > Guards) -- what is still held is loaded anyway, marked partial
    if (@($plan | Where-Object { $_ -and [string]$_.Action -eq 'Hold' }).Count -and (Get-Command -Name Test-SIGuardOn -ErrorAction SilentlyContinue) -and
        -not (Test-SIGuardOn -GuardId 'datasync.collection.held' -Log $Log)) {
        $plan = @(Set-SIDataGuardOffPlan -Plan @($plan) -Loaded $loadedRows -Runs @($runs))
    }
    $result.Plan = $plan
    $result.Superseded = $superseded
    foreach ($p in $plan) {
        $line = ("{0:yyyy-MM-dd HH:mm:ss} UTC  {1,8} row(s)  {2,-6} {3}" -f $p.CollectionTime, $p.Rows, $p.Action, $p.Reason)
        if ($p.Action -eq 'Hold') { & $warn ('  ' + $line + ' -- not loaded; it is tried again on the next run') } else { & $info ('  ' + $line) }
    }
    $result.Held = @($plan | Where-Object { $_.Action -eq 'Hold' })
    $result.Skipped = @($plan | Where-Object { $_.Action -eq 'Skip' })
    # #294: REFUSED -- collections whose rows lack their finding id, and rows that carry no CollectionTime at all (they
    # belong to no collection, so the listing above never shows them). Never loaded; said here and in run health.
    $result.Refused = @($plan | Where-Object { $_.Action -eq 'Refuse' })
    foreach ($p in $result.Refused) { & $warn ("  {0:yyyy-MM-dd HH:mm:ss} UTC  {1,8} row(s)  REFUSED -- {2}. It is not loaded as a day." -f $p.CollectionTime, $p.Rows, $p.Reason) }
    $untimed = @(); if ($laCopy) { $untimed = & $readOrSkip (Get-SIDataUntimedRowsKql -LookbackDays $lookback) 'SI_RiskAnalysis_Detailed_CL' }
    $result.Untimed = @(@($untimed) | Where-Object { $_ -and $_.PSObject.Properties["UntimedRows"] -and [long](ConvertTo-SIDataNumber $_.UntimedRows) -gt 0 } | ForEach-Object {
        [pscustomobject]@{ Hour = (ConvertTo-SIDataUtc $_.Hour); Rows = [long](ConvertTo-SIDataNumber $_.UntimedRows) } })
    foreach ($u in $result.Untimed) { & $warn ("  {0:yyyy-MM-dd HH:00} UTC  {1,8} row(s)  REFUSED -- they arrived without a CollectionTime, so they belong to no collection (a Risk Analysis run whose key columns were lost). They are not loaded." -f $u.Hour, $u.Rows) }
    $todo = @($plan | Where-Object { $_.Action -in 'Load', 'Reload' })
    # #725: a collection whose run stopped after ALL its reports were Complete (before it marked itself) is marked in first,
    # so the adoption below completes and delivers it -- never one with any report not Complete (Invoke-SIDataRaFinish)
    $result['Finished'] = @(Invoke-SIDataRaFinish -Invoke $Invoke -DryRun:$DryRun -Log $Log)
    # #638: the collections Risk Analysis wrote itself and marked in -- completed here (never loaded from Log Analytics)
    $adopt = @(@(& $Invoke (Get-SIDataRaPendingSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] -and $null -ne $_['CollectionId'] } | ForEach-Object {
        [pscustomobject]@{ CollectionId = [int]$_['CollectionId']; CollectionTime = (ConvertTo-SIDataUtc $_['CollectionTime']); RaPartialReason = $(if ($_['RaPartialReason'] -is [System.DBNull]) { '' } else { [string]$_['RaPartialReason'] })
                           SolutionVersion = $(if ($_['SolutionVersion'] -is [System.DBNull]) { '' } else { [string]$_['SolutionVersion'] }) } })
    if ($adopt.Count) { & $info ("risk analysis: {0} collection(s) Risk Analysis wrote itself are completed here (not read from Log Analytics)" -f $adopt.Count) }
    $result['Adopted'] = @()

    $index = $null   # the correlation index, read below when collections are loaded (step 4f reuses it)
    if ($todo.Count -gt 0 -or $adopt.Count -gt 0) {
        if ($DryRun) {
            & $info ("dry run     : {0} collection(s) would be loaded; nothing is written." -f $todo.Count)
        } else {
            # ---- identity sources, read once per run -------------------------------------------------------------
            $profiles = New-Object System.Collections.Generic.List[object]
            foreach ($pair in @(@('endpoint', 'SI_Endpoint_Profile_CL'), @('identity', 'SI_Identity_Profile_CL'), @('azure', 'SI_Azure_Profile_CL'), @('publicip', 'SI_PublicIP_Profile_CL'))) {
                $rows = & $readOrSkip (Get-SIDataProfileKql -TableName $pair[1]) $pair[1]
                foreach ($r in @($rows)) { if ($r) { $profiles.Add([pscustomobject]@{ Kind = $pair[0]; SI_AssetId = [string]$r.SI_AssetId; SI_AssetName = [string]$r.SI_AssetName; Tier = $r.Tier; CollectionTime = $r.CollectionTime
                    SI_TierSetBy = [string]$r.SI_TierSetBy; SI_TierReason = [string]$r.SI_TierReason; SI_TierClaims = [string]$r.SI_TierClaims }) } }
            }
            $mapRows = & $readOrSkip (Get-SIDataObjectMapKql) 'SI_ObjectMap_CL'
            $index = New-SIDataIdentityIndex -MapRows @($mapRows)
            # #297/#298: an asset id that is only an IDENTIFIER of one asset (an Entra or Defender device id) is that asset
            $owners = New-SIDataIdentifierOwners -Index $index -Profiles $profiles.ToArray()
            # #408: the full asset metadata (SI_AssetProperties_CL) is NOT folded into sidata.Asset.PropertiesJson any more --
            # it has its own generic store (sidata.AssetMetadata, step 4f, only when SI_AssetProperties = full). The CI's
            # PropertiesJson carries SecurityInsight's own tier attribution (#244); bags stored before are pruned by 6b.
            $props = @{}
            # identifier value -> SI_AssetId, so a Defender for Cloud resource id finds its CI
            $assetOfId = @{}
            foreach ($k in @($index.Keys)) { $assetOfId[$k] = $index[$k].SIAssetId; foreach ($i in $index[$k].Identifiers) { if (-not $assetOfId.ContainsKey($i.Value)) { $assetOfId[$i.Value] = $index[$k].SIAssetId } } }
            foreach ($p in $profiles) { $l = $p.SI_AssetId.ToLowerInvariant(); if ($l -and -not $assetOfId.ContainsKey($l)) { $assetOfId[$l] = $p.SI_AssetId } }
            & $info ("identity    : {0} profiled asset(s), {1} in the correlation map ({2} with a ledger id)" -f $profiles.Count, $index.Count, @($index.Values | Where-Object { $_.IdSource -eq 'ledger' -and $_.CorrelationId }).Count)

            # ---- the correlation evidence (#299): what each source record says about itself, read once per run -----
            # A database whose schema predates the evidence tables is told once; the loads are not affected.
            $evidenceReady = $false; $evidenceProfiles = @{}
            if (Get-Command -Name Get-SIDataEvidenceSchemaCheckSql -ErrorAction SilentlyContinue) {
                $evidenceReady = ([int](& $Invoke (Get-SIDataEvidenceSchemaCheckSql) @{} 'scalar')) -eq 1
                if ($evidenceReady) { $evidenceProfiles = Read-SIDataEvidenceProfiles -ReadOrSkip $readOrSkip }
                else { & $warn 'correlation : the database does not have the correlation evidence tables yet -- run setup\Initialize-SIDataSql.ps1 again to add them; the asset page''s evidence and the correlation quality report stay empty until then.' }
            }

            $chunk = [long]0; $batch = [long]0
            if (@($todo | Where-Object { $_.Partial }).Count) { [void](& $Invoke (Get-SIDataPartialTableSql) @{} 'scalar') }
            # One collection at a time, oldest first (the plan's order). Each one is complete in the database before the
            # next begins, so when a run stops part way the collections it finished STAY finished -- the next run has
            # fewer to load, never more -- and what one collection needed in memory is handed back before the next.
            $profileRows = $profiles.ToArray()
            foreach ($item in $todo) {
                $one = Invoke-SIDataLoadCollection -Item $item -Query $Query -Invoke $Invoke -EditionMajor $EditionMajor -LookbackDays $listDays `
                    -Profiles $profileRows -Index $index -Owners $owners -Properties $props -AssetOfId $assetOfId -ChunkChars ([ref]$chunk) -BatchSize ([ref]$batch) -Log $Log `
                    -EvidenceReady:$evidenceReady -EvidenceProfiles $evidenceProfiles
                $result.Loaded += $one
                # a RELEASED collection: loaded once, MARKED PARTIAL (the web app badges it wherever it is used), the release applied
                if ($item.Partial) { $result.Released += (Complete-SIDataReleasedLoad -Item $item -Loaded $one -Invoke $Invoke -Store $ReleaseStore -Log $Log) }
                Clear-SIDataMemory
            }
            foreach ($item in $adopt) {
                $one = Invoke-SIDataAdoptRaCollection -Item $item -Query $Query -Invoke $Invoke -Profiles $profileRows -Index $index -Owners $owners -Properties $props -AssetOfId $assetOfId `
                    -ChunkChars ([ref]$chunk) -Log $Log -EvidenceReady:$evidenceReady -EvidenceProfiles $evidenceProfiles
                $result.Loaded += $one
                $result['Adopted'] += $one
                Clear-SIDataMemory
            }
            # ---- 4c (a). the CIs' platform tags and groupings (current state), for the responsibility policy --------
            if (Get-Command -Name Read-SIDataAssetTagRows -ErrorAction SilentlyContinue) {
                $tagRows = Read-SIDataAssetTagRows -ReadOrSkip $readOrSkip
                $newest = (@(@($todo) + @($adopt) | Sort-Object CollectionTime) | Select-Object -Last 1).CollectionTime
                $tagItems = Get-SIDataAssetTagItems -Rows $tagRows -Index $index -SeenAt $newest
                $result.Tags = Write-SIDataAssetTags -Invoke $Invoke -Items $tagItems -ChunkChars ([ref]$chunk)
                if ($result.Tags -lt 0) { & $warn 'tags        : the database does not have the asset tag table yet -- run setup\Initialize-SIDataSql.ps1 again to add it.' }
                else { & $ok ("tags        : the platform tags of {0} CI(s) stored" -f $result.Tags) }
            }
        }
    } else {
        & $info 'load        : nothing new to load.'
    }

    & $phase 'collections loaded' ([long](@($result.Loaded | ForEach-Object { if ($_ -and $_.PSObject.Properties['Findings']) { [long]$_.Findings } else { 0L } }) | Measure-Object -Sum).Sum)
    # ---- 4 (z). #834 the collections the retention removes are MARKED now, right after the loads -- before any step below
    # derives, prepares or groups them (measured at internal 2026-10-20: the run prepared the context, the CVE rows, the
    # pivots ... of a collection its own retention removed at the end: one collection in three). The same plan and the
    # same guards as the removal (Invoke-SIDataCollectionRetention: the newest complete collection and the one before it,
    # the published run's and a result waiting for the data sync are never marked); only the rows wait. Never fails the run.
    if (-not $DryRun -and $retiredReady) { $result['CollectionMarks'] = Invoke-SIDataCollectionRetention -Invoke $Invoke -MarkOnly -RowsRemovedBy 'at the end of this data sync' -Log $Log }

    & $phase 'retention marks'
    # ---- 4e. what earlier loads stored wrong (#296, #297/#298): report names, duplicate and phantom assets ---------
    # Guarded and idempotent (SI-DataRepair.ps1); a dry run reports only. The days they touched are re-aggregated here;
    # the views, services, departments and counted twins of those collections are derived again by the steps below.
    $repairDays = New-Object System.Collections.Generic.List[string]
    if (Get-Command -Name Invoke-SIDataReportNameBackfill -ErrorAction SilentlyContinue) {
        $rb = [long]0
        $result.ReportNames = Invoke-SIDataReportNameBackfill -Invoke $Invoke -DryRun:$DryRun -BatchSize ([ref]$rb) -Log $Log
        if (-not $DryRun) { foreach ($d in @($result.ReportNames.Days)) { if ($d -and -not $repairDays.Contains([string]$d)) { $repairDays.Add([string]$d) } } }
    }
    if (Get-Command -Name Invoke-SIDataDuplicateAssetMerge -ErrorAction SilentlyContinue) {
        $result.Merges = Invoke-SIDataDuplicateAssetMerge -Invoke $Invoke -DryRun:$DryRun -Log $Log
        if (-not $DryRun) { foreach ($d in @($result.Merges.Days)) { if ($d -and -not $repairDays.Contains([string]$d)) { $repairDays.Add([string]$d) } } }
    }
    foreach ($d in $repairDays) { [void](& $Invoke (Get-SIDataFindingDailySql) @{ Day = $d } 'scalar') }

    & $phase 'repairs (report names, duplicate assets)'
    # ---- 4 (y). #855 W10: the newest and the published collection, stored before the lifecycle was stamped, are stamped ONCE
    # and marked to be derived again -- by this run's own steps below (the views' data, the departments, every per-collection
    # aggregate, the context, the summaries, the remediations, the key figures), so every view counts active CIs by default
    # from the first data sync after the update. Bounded to those two collections; never fails the data sync.
    if (Get-Command -Name Invoke-SIDataCiLifecycleRestamp -ErrorAction SilentlyContinue) { $result['LifecycleRestamp'] = Invoke-SIDataCiLifecycleRestamp -Invoke $Invoke -DryRun:$DryRun -Log $Log }
    & $phase 'lifecycle restamp'
    # ---- 4a. the distinct assets of every day loaded before sidata.AssetDaily existed (#295) -----------------------
    # Each such day is recomputed ONCE (its FindingDaily and AssetDaily, and the counted twins where the day has them):
    # until then its trend shows the assets as unknown, never as a sum of per-group counts. Idempotent.
    # the seam answers its rows as ONE array: unrolled here, so each pending day is one item (never the whole answer as one)
    $pendAd = @(@(& $Invoke (Get-SIDataAssetDailyPendingSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $_ })
    $result.AssetDays = $pendAd.Count
    if ($pendAd.Count -gt 0) {
        if ($DryRun) { & $info ("assets      : {0} day(s) would get their distinct asset counts; nothing is written." -f $pendAd.Count) }
        else {
            foreach ($p in $pendAd) {
                $counted = [bool]$p['Counted']
                if ($counted) { [void](& $Invoke (Get-SIDataFindingDailySql -Counted) @{ Day = [string]$p['Day'] } 'scalar') }
                else { [void](& $Invoke (Get-SIDataFindingDailySql) @{ Day = [string]$p['Day'] } 'scalar') }
            }
            & $ok ("assets      : {0} day(s) got their distinct asset counts (an asset counts once per group, never once per finding group added up)" -f $pendAd.Count)
        }
    }

    & $phase 'asset days'
    # ---- 4b. the collection views' data (#241): columns from DetailJson + per-collection aggregates ---------------
    # Every complete collection without it -- the ones just loaded and, once, every one loaded before the columns
    # existed. A database whose schema predates them is said once and the load is NOT affected.
    $viewsReady = [int](& $Invoke (Get-SIDataViewsSchemaCheckSql) @{} 'scalar')
    $servicesReady = $false
    if ($viewsReady -ne 1) {
        & $warn 'views       : the database does not have the collection views'' columns yet -- run setup\Initialize-SIDataSql.ps1 again to add them; the web app''s collection views stay empty until then.'
    } else {
        # the Services view (#255): only when the database also carries its columns and tables -- said once otherwise
        $servicesReady = ([int](& $Invoke (Get-SIDataServicesSchemaCheckSql) @{} 'scalar')) -eq 1
        if (-not $servicesReady) {
            & $warn 'services    : the database does not have the Services view''s tables yet -- run setup\Initialize-SIDataSql.ps1 again to add them; the Services view stays empty until then.'
        } else {
            # the Pro database's own CMDB (#256): when configured it is THE service source; else the CMDB.csv fallback
            $cmdb = Use-SIDataCmdbServiceSource -Invoke $Invoke
            $result.Cmdb = $cmdb
            if ($cmdb.Used) { & $info ("services    : the CMDB is authoritative ({0}, {1} service(s) in force) -- services come from it" -f $cmdb.ActiveSource, $cmdb.Services) }
            elseif ($cmdb.HasCmdb) { & $info 'services    : the SecurityInsight CMDB holds no service yet -- services come from the CMDB columns Risk Analysis carries' }
        }
        # #590 the finding's fix columns (how to fix, recommended update, affected software): derived only when the database
        # carries them -- an older database is said once and everything else is derived as before
        $fixReady = $false
        if (Get-Command -Name Get-SIDataFixSchemaCheckSql -ErrorAction SilentlyContinue) { $fixReady = ([int](& $Invoke (Get-SIDataFixSchemaCheckSql) @{} 'scalar')) -eq 1 }
        if (-not $fixReady) { & $warn 'fixes       : the database does not have the findings'' fix columns yet -- run setup\Initialize-SIDataSql.ps1 again (the updater does it); the fix of each finding stays in its stored row until then.' }
        $pendRaw = & $Invoke (Get-SIDataUnderivedSql -Services:$servicesReady) @{} 'reader'
        $pending = @(@($pendRaw) | Where-Object { $_ })
        if ($DryRun) {
            & $info ("views       : {0} collection(s) would get their views' data; nothing is written." -f $pending.Count)
        } elseif ($pending.Count -gt 0) {
            $deriveBatch = [long]0
            foreach ($p in $pending) {
                $result.Derived += (Invoke-SIDataDeriveCollection -Invoke $Invoke -CollectionId ([int]$p['CollectionId']) -BatchSize ([ref]$deriveBatch) -Services:$servicesReady -Fix:$fixReady -Log $Log)
            }
            & $ok ("views       : {0} collection(s) got their views' data ({1} finding row(s), {2} aggregate row(s))" -f @($result.Derived).Count,
                (@($result.Derived | ForEach-Object { $_.Findings }) | Measure-Object -Sum).Sum, (@($result.Derived | ForEach-Object { $_.Facets }) | Measure-Object -Sum).Sum)
            if ($servicesReady) {
                & $ok ("services    : {0} collection(s) got their service membership ({1} service row(s), sources: {2})" -f @($result.Derived).Count,
                    (@($result.Derived | ForEach-Object { $_.Services }) | Measure-Object -Sum).Sum, ((Get-SIDataServiceSources | ForEach-Object { $_.Name }) -join ', '))
            }
        }
    }

    & $phase 'views (derive)' ([long](@($result.Derived | ForEach-Object { if ($_) { [long]$_.Findings } else { 0L } }) | Measure-Object -Sum).Sum)
    # ---- 4c. asset responsibility (#254): each finding's department, pre-resolved ---------------------------------
    if ($Responsibility -and (Get-Command -Name Invoke-SIDataResponsibility -ErrorAction SilentlyContinue)) {
        if (@($Responsibility.Problems).Count) {
            & $warn ('departments : the responsibility settings are not valid -- nothing is resolved this run: ' + (@($Responsibility.Problems) -join '; '))
        } else {
            $result.Responsibility = Invoke-SIDataResponsibility -Invoke $Invoke -Settings $Responsibility -DryRun:$DryRun -Log $Log
        }
    }

    & $phase 'departments'
    # ---- 4d. exempted findings (#264): every aggregate's counted twin, per collection ------------------------------
    # After the views, the services and the departments: each twin is computed from the same collection as its base, over
    # the findings without an exemption mark. A database without the twins is said once; the rest is not affected.
    if ($viewsReady -eq 1) {
        $exReady = [int](& $Invoke (Get-SIDataExemptedSchemaCheckSql) @{} 'scalar')
        if ($exReady -ne 1) {
            & $warn 'exempted    : the database does not have the counted aggregates yet -- run setup\Initialize-SIDataSql.ps1 again to add them; until then the pages count exempted findings as before.'
        } else {
            $deptReady = $false
            if (Get-Command -Name Get-SIDataResponsibilitySchemaCheckSql -ErrorAction SilentlyContinue) { $deptReady = ([int](& $Invoke (Get-SIDataResponsibilitySchemaCheckSql) @{} 'scalar')) -eq 1 }
            $exPendRaw = & $Invoke (Get-SIDataUnexemptedSql) @{} 'reader'
            $exPending = @(@($exPendRaw) | Where-Object { $_ })
            $result.Exempted = @()
            if ($DryRun) {
                & $info ("exempted    : {0} collection(s) would get their counted aggregates; nothing is written." -f $exPending.Count)
            } elseif ($exPending.Count -gt 0) {
                # #745 (a large customer 2026-10-17, 1,138,554 findings): a counted twin that did not finish failed the whole
                # data sync, so the collection was never shown. The twins are counts the pages also work out themselves
                # (as before the twins existed) -- a collection whose twins fail is said and tried again on the next run.
                foreach ($p in $exPending) {
                    try {
                        $result.Exempted += (Invoke-SIDataExemptedVariants -Invoke $Invoke -Services:$servicesReady -Departments:$deptReady -Log $Log -Collection ([pscustomobject]@{
                            CollectionId = $p['CollectionId']; CollectionTime = $p['CollectionTime']; Derived = $p['Derived']; Resolved = $p['Resolved']; ServicesDerived = $p['ServicesDerived'] }))
                    } catch {
                        & $warn ("exempted    : the counted aggregates of the collection of {0} were not completed this run -- {1}. They are tried again on the next run; until then the pages count exempted findings as before." -f $p['CollectionTime'], $_.Exception.Message)
                        # #904: a part that failed is reported as that part's failure, never only this WARN line
                        $result['ExemptedTwins'] = [pscustomobject]@{ Status = 'failed'; Error = ('the collection of {0}: {1}' -f $p['CollectionTime'], $_.Exception.Message) }
                    }
                }
                & $ok ("exempted    : {0} collection(s) got their counted aggregates (exempted findings left out of the twins; kept in the data)" -f @($result.Exempted | Where-Object { $_.Stamped }).Count)
            }
        }
    }

    & $phase 'exempted (counted twins)'
    # ---- 4d (2). the collections whose view data is written are shown by the collection views from here on --------------
    # (sidata.Collection.ViewsReadyAt, SI-DataViewContext.ps1). After the views' aggregates, the departments and the counted
    # aggregates: until now a collection was listed as soon as its rows were loaded, minutes before any of them. Every
    # complete collection without the mark, so a run that died is finished by the next one.
    if (-not $DryRun -and (Get-Command -Name Set-SIDataViewsReady -ErrorAction SilentlyContinue)) {
        $result['ViewsReady'] = Set-SIDataViewsReady -Invoke $Invoke -Views:($viewsReady -eq 1) -Log $Log
    }

    & $phase 'views ready'
    # ---- 4d (2b). one row per CVE, per collection (sidata.CveSummary + its counted twin), SI-DataViewContext.ps1 -- what
    # Security recommendations > Summary > Vulnerabilities (CVE) pages over (a large customer 2026-10-19: grouping 1.1 million finding rows per
    # request ran past the 90 s limit). After the views' columns (the CVSS and the exploit flag come from the derive), newest
    # collection first, before the prepared context (the longest step). Never fails the data sync.
    if ($viewsReady -eq 1 -and (Get-Command -Name Invoke-SIDataCveSummary -ErrorAction SilentlyContinue)) {
        $result['CveSummary'] = Invoke-SIDataCveSummary -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }

    & $phase 'cve summary'
    # ---- 4d (2c). one row per CI, per collection (sidata.AssetRiskSummary + its counted twin), and the Domain -> Category
    # pairs (sidata.DomainCategory), SI-DataViewContext.ps1 -- what Assets & services > Risk scores / Assets (CIs) at risk page over and what
    # the Security owners page lists (2026-10-19, the same large customer: both read every finding of the collection per
    # request). After the views' columns (the weighted score and the rating come from the derive), newest collection first,
    # before the prepared context. Never fails the data sync.
    if ($viewsReady -eq 1 -and (Get-Command -Name Invoke-SIDataAssetRiskSummary -ErrorAction SilentlyContinue)) {
        $result['AssetRiskSummary'] = Invoke-SIDataAssetRiskSummary -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }
    & $phase 'asset risk summary'
    if ($viewsReady -eq 1 -and (Get-Command -Name Invoke-SIDataDomainCategory -ErrorAction SilentlyContinue)) {
        $result['DomainCategory'] = Invoke-SIDataDomainCategory -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }
    & $phase 'domain category'
    # #812: Reports > Outputs' preview counts per collection (sidata.ReportPreviewCount) -- never grouped per page open
    if ($viewsReady -eq 1 -and (Get-Command -Name Invoke-SIDataReportPreview -ErrorAction SilentlyContinue)) {
        $result['ReportPreview'] = Invoke-SIDataReportPreview -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }
    & $phase 'report preview'
    # ---- 4d (2d). What changed per collection pair (sidata.FindingChange / AssetChange / ChangeCount + counted twins +
    # ChangeState) and the wall board's top tier-0 assets (sidata.Tier0Asset + counted twin + state), SI-DataChanges.ps1 --
    # /Collection/Changes compared every finding of two collections per request, the wall board grouped every finding per
    # refresh (2026-10-19, #812). After the views' columns and the view-data mark (the pair is the listed previous
    # collection), newest collection first, before the prepared context. Never fails the data sync.
    if ($viewsReady -eq 1 -and (Get-Command -Name Invoke-SIDataChanges -ErrorAction SilentlyContinue)) {
        $result['Changes'] = Invoke-SIDataChanges -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }
    & $phase 'changes'
    if ($viewsReady -eq 1 -and (Get-Command -Name Invoke-SIDataTier0 -ErrorAction SilentlyContinue)) {
        $result['Tier0'] = Invoke-SIDataTier0 -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }

    & $phase 'tier 0'
    # ---- 4d (2e). the findings browser's default order (Finding.ImportanceRank) and pivot cells (sidata.FindingPivotCell + its
    # counted twin) and the Weighted risk pivot's cube (sidata.PivotCell), SI-DataPivots.ps1 -- #812: the browser counted and
    # sorted every finding per open, both pivots grouped every finding per request. After the views' columns (the weighted
    # score comes from the derive), newest collection first, before the prepared context. Never fails the data sync.
    if ($viewsReady -eq 1 -and (Get-Command -Name Invoke-SIDataFindingPivots -ErrorAction SilentlyContinue)) {
        $result['FindingPivots'] = Invoke-SIDataFindingPivots -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }

    & $phase 'pivots'
    # ---- 4d (3). what the views show by default, prepared: each finding's context as columns and one row per CVE / issue
    # (sidata.IssueContext) -- every complete collection without it, newest first (SI-DataViewContext.ps1). After the views'
    # columns (the derive writes the fix columns). Never fails the data sync. #745: AFTER the collection is shown -- the
    # prepared context is the longest part of a large collection's sync, and a collection without it is read by the web app
    # from the finding rows, so it never holds the collection back.
    if ($viewsReady -eq 1 -and (Get-Command -Name Invoke-SIDataViewContext -ErrorAction SilentlyContinue)) {
        $result['ViewContext'] = Invoke-SIDataViewContext -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }

    & $phase 'view context'
    # ---- 4d (4). #636 THE SUMMARY GROUPINGS of the Detailed findings, per collection (sidata.SummaryGroup + its counted twin,
    # SI-DataSummaryGroups.ps1 -- data-model\summary-groupings.locked.json through THE engine function Invoke-SISummaryGrouping):
    # per recommendation with its affected assets, per asset, tier, Domain > Category > Subcategory, risk rating, department,
    # severity and report -- what the grouped views, the management summary and the status report read instead of the
    # Summary step's rows. After the prepared context (the category and subcategory columns come from there). Never fails
    # the data sync.
    if ($viewsReady -eq 1 -and (Get-Command -Name Invoke-SIDataSummaryGroups -ErrorAction SilentlyContinue)) {
        $result['SummaryGroups'] = Invoke-SIDataSummaryGroups -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }

    & $phase 'summary groups'
    # ---- 4d (5). #636 the remediations (one fix applied to many assets: sidata.Remediation / RemediationAsset and each
    # finding's key) and the key figures of the Executive overview and report (sidata.KeyFigure) -- per collection, from
    # the prepared columns, so AFTER the context. Each never fails the data sync (SI-DataRemediation.ps1, SI-DataKeyFigures.ps1).
    if ($viewsReady -eq 1 -and (Get-Command -Name Invoke-SIDataRemediations -ErrorAction SilentlyContinue)) {
        $result['Remediations'] = Invoke-SIDataRemediations -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }
    & $phase 'remediations'
    if ($viewsReady -eq 1 -and (Get-Command -Name Invoke-SIDataKeyFigures -ErrorAction SilentlyContinue)) {
        $result['KeyFigures'] = Invoke-SIDataKeyFigures -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }

    & $phase 'key figures'
    # ---- 4e (b). #448 ONLY CURRENT HOLDS: every stored held collection at or before the newest collection that is in the
    # database now (loaded in this run or before) is closed -- it is loaded, or a newer one is (guard.release.supersede).
    if ($ReleaseStore -and -not $DryRun -and $ReleaseStore.PSObject.Methods['Supersede']) {
        $newestIn = @($plan | Where-Object { $_ -and [string]$_.Action -in @('Load', 'Reload', 'Skip') } | Sort-Object CollectionTime | Select-Object -Last 1)
        if ($newestIn.Count) {
            $supKey = Get-SIDataReleaseKey -CollectionTime $newestIn[0].CollectionTime
            $supText = [string]::Format([Globalization.CultureInfo]::InvariantCulture, 'closed by the current rules: the collection of {0:yyyy-MM-dd HH:mm} UTC (or a newer one) is loaded', $newestIn[0].CollectionTime)
            try {
                $sup = @($ReleaseStore.Supersede($script:SIDataReleaseConnector, 'datasync.collection.held', $supKey, $true, $supText, 'data sync'))
                $result['SupersededHolds'] = $sup.Count
                if ($sup.Count) { & $ok ("holds       : {0} older held collection(s) closed -- {1}" -f $sup.Count, $supText) }
            } catch {
                & $warn ("holds       : the older held collections could not be closed -- {0}. They are tried again on the next run." -f $_.Exception.Message)
                $result['Holds'] = [pscustomobject]@{ Status = 'failed'; Error = $_.Exception.Message }
            }
        }
    }

    & $phase 'holds'
    # ---- 4f. the full asset metadata (#301 / #408): SI_AssetProperties_CL -> sidata.AssetMetadata, ONLY when 'full' ---
    # Generic: one row per (CI, source system, record, item), the source object as JSON (arrays stay arrays). Never fails
    # the data sync: a failure here is said, and the findings load is not affected (SI-DataAssetMetadata.ps1).
    if (Get-Command -Name Invoke-SIDataAssetMetadataSync -ErrorAction SilentlyContinue) {
        $amMode = 'security'; if ($Settings.PSObject.Properties['AssetPropertiesMode'] -and [string]$Settings.AssetPropertiesMode) { $amMode = [string]$Settings.AssetPropertiesMode }
        $amDays = 3; if ($Settings.PSObject.Properties['AssetPropertiesRetentionDays'] -and [int]$Settings.AssetPropertiesRetentionDays -ge 1) { $amDays = [int]$Settings.AssetPropertiesRetentionDays }
        $amRead = { New-SIDataIdentityIndex -MapRows @(& $readOrSkip (Get-SIDataObjectMapKql) 'SI_ObjectMap_CL') }
        try {
            $result['AssetMetadata'] = Invoke-SIDataAssetMetadataSync -Query $Query -Invoke $Invoke -ReadOrSkip $readOrSkip -Mode $amMode -Index $index -ReadIndex $amRead `
                -LookbackDays ([Math]::Max($lookback, $amDays) + 1) -RetentionDays $amDays -Now $Now -DryRun:$DryRun -Log $Log
        } catch {
            & $warn ("metadata    : the full asset metadata was not stored this run -- {0}. It is tried again on the next run; the findings load is not affected." -f $_.Exception.Message)
            $result['AssetMetadata'] = [pscustomobject]@{ Mode = $amMode; Status = 'failed'; Error = $_.Exception.Message }
        }
    }

    & $phase 'asset metadata'
    # ---- 4g. the v3 data model (V3-DATA-MODEL part 2, M5): CIs, their linked objects, the findings per CI and the provider
    # records -> sidata.Ci / CiLink / CiFinding / CiDaily / CiRecord (SI-DataCi.ps1). Never fails the data sync.
    if (Get-Command -Name Invoke-SIDataCiSync -ErrorAction SilentlyContinue) {
        # -LaQuery: the raw reader for its pages (#639) -- $readOrSkip reads a variable named $Query, which inside the page reader
        # would be the page reader's own
        $result['DataModel'] = Invoke-SIDataCiSync -Invoke $Invoke -ReadOrSkip $readOrSkip -LaQuery $Query -LookbackDays ($lookback + 1) -DryRun:$DryRun -Log $Log -Phase $phase
    }
    & $phase 'findings per CI (v3 model)' ([long]$(if ($result['DataModel'] -and $result['DataModel'].PSObject.Properties['Findings']) { $result['DataModel'].Findings } else { -1 }))
    # ---- 4g (2). #812: the CI findings' summary (sidata.CiFindingSummary) under the collection sidata.CiFinding holds -- after
    # the CI build, what Assets (CIs) > Findings per finding key pages over (never a GROUP BY over every CI finding per request).
    # Never fails the data sync.
    if (Get-Command -Name Invoke-SIDataCiFindingSummary -ErrorAction SilentlyContinue) {
        $result['CiFindingSummary'] = Invoke-SIDataCiFindingSummary -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }
    & $phase 'CI findings summary'
    # 2026-10-25 this run's narrow findings (SI-DataFindingNarrow.ps1) are emptied once the last step that reads them is done
    # #904: a narrow fill that FAILED this run is a part that failed (taken before the run's state is emptied)
    if (Get-Command -Name Get-SIDataFindingNarrowState -ErrorAction SilentlyContinue) { $result['Narrow'] = Get-SIDataFindingNarrowState }
    if (-not $DryRun -and (Get-Command -Name Clear-SIDataFindingNarrow -ErrorAction SilentlyContinue)) { Clear-SIDataFindingNarrow -Invoke $Invoke -Log $Log; & $phase 'narrow findings emptied' }
    # ---- 4g (3). the column chooser's lists (sidata.ColumnChoice, SI-DataPageLists.ps1): the CI fields, identifier types,
    # source properties and finding fields the data views offer as extra columns -- after the CI build and the full asset
    # metadata (they are read from both); written again only when the data they are read from moved. The web app reads them
    # instead of sampling the data on a page open. Never fails the data sync.
    if (Get-Command -Name Invoke-SIDataColumnChoices -ErrorAction SilentlyContinue) {
        $result['ColumnChoices'] = Invoke-SIDataColumnChoices -Invoke $Invoke -DryRun:$DryRun -Log $Log
    }

    & $phase 'column choices'
    if (-not $DryRun) {
        # ---- 5. close-loop statistics ----------------------------------------------------------------------------
        $n = [int](& $Invoke (Get-SIDataVulnLifecycleSql) @{} 'scalar')
        $result.Lifecycle = $n
        if ($n -lt 0) { & $info 'lifecycle   : the vulnerability close-loop is not installed in this database -- no lifecycle statistics.' }
        else { & $ok ("lifecycle   : {0} day(s) of opened / closed / reopened statistics recomputed" -f $n) }
        # the open items by severity and asset tier, both variants (sidata.VulnOpenCount, SI-DataPageLists.ps1) -- what
        # Vulnerabilities over time shows as "open now"; never fails the data sync
        if ($n -ge 0 -and (Get-Command -Name Invoke-SIDataVulnOpenCounts -ErrorAction SilentlyContinue)) {
            $result['VulnOpenCounts'] = Invoke-SIDataVulnOpenCounts -Invoke $Invoke -Log $Log
        }

        & $phase 'close-loop statistics'
        # ---- 6. retention ----------------------------------------------------------------------------------------
        $ret = Invoke-SIDataRetention -Invoke $Invoke -RetentionDays ([int]$Settings.RetentionDays) -LookbackDays $lookback -Now $Now
        $result.Retention = $ret
        & $ok ("retention   : {0} day(s) -- removed {1} collection(s) ({2} finding row(s), {3} recommendation row(s)), {4} run(s), {5} asset(s) not seen since {6:yyyy-MM-dd}" -f `
            $Settings.RetentionDays, $ret.Collections, $ret.Findings, $ret.Recommendations, $ret.Runs, $ret.Assets, $ret.Cutoff)

        & $phase 'retention'
        # ---- 6a. #717 the collections' own retention: per grain the newest complete collection + the one before it are
        # kept; the rows of older ones, and of collections a stopped run left 'Loading', are removed. Never fails the run.
        # #834 (measured at internal 2026-10-20, a small database: 26.3 min, most of it the pacing waiting on the database
        # this very sync had saturated): started by the pipeline, the sync only marks; the pipeline runner's wake-ups remove
        # the rows once the run has ended, while no run is running (Invoke-SIDataStoppedRunCleanup). By hand or on its own
        # schedule: removed here, as before.
        if ($retiredReady) {
            $byPipeline = Test-SIDataRunByPipeline -Invoke $SettingsInvoke
            if ($byPipeline) { $result['CollectionRetention'] = Invoke-SIDataCollectionRetention -Invoke $Invoke -MarkOnly -RowsRemovedBy 'by the pipeline runner''s next wake-ups, in key ranges -- also while a run is going' -Log $Log }
            else { $result['CollectionRetention'] = Invoke-SIDataCollectionRetention -Invoke $Invoke -Log $Log }
        }
    }
    & $phase 'collection retention'
    if ($DryRun -and $retiredReady) { $result['CollectionRetention'] = Invoke-SIDataCollectionRetention -Invoke $Invoke -DryRun -Log $Log }
    # ---- 6c. #717 how full the database is (its used share of its maximum size); above 70 % the run says so. Never fails.
    $result['DatabaseFill'] = Get-SIDataFill -Invoke $Invoke -Log $Log
    if (-not $DryRun) {

        & $phase 'database fill'
        # ---- 6b. the full asset metadata's own retention (#301; SI_AssetProperties_RetentionDays, default 3) ------
        $apDays = 3
        if ($Settings.PSObject.Properties['AssetPropertiesRetentionDays'] -and [int]$Settings.AssetPropertiesRetentionDays -ge 1) { $apDays = [int]$Settings.AssetPropertiesRetentionDays }
        $apr = Invoke-SIDataAssetPropertiesPrune -Invoke $Invoke -RetentionDays $apDays -Now $Now
        $result['AssetPropertiesPrune'] = $apr
        & $ok ("asset data  : full asset metadata older than {0} day(s) removed -- {1} stored object(s), {2} older asset bag(s) (collected before {3:yyyy-MM-dd HH:mm} UTC)" -f $apr.RetentionDays, $apr.MetadataRows, $apr.Assets, $apr.Cutoff)

        & $phase 'asset metadata retention'
        # ---- 7. the views' data mark: what the web app's result caches of the data views are kept under -- last, so a
        # page read under the new mark sees everything this run stored (SI-DataViewContext.ps1). Never fails the data sync.
        if (Get-Command -Name Set-SIDataViewVersion -ErrorAction SilentlyContinue) { $result['ViewVersion'] = Set-SIDataViewVersion -Invoke $Invoke -Log $Log }
        # the mark takes "a data sync is running" away with it; when the mark could not be set, it is taken away here
        if ((Get-Command -Name Clear-SIDataSyncRunning -ErrorAction SilentlyContinue) -and -not ($result['ViewVersion'] -and [string]$result['ViewVersion'].Status -eq 'ok')) {
            $null = Clear-SIDataSyncRunning -Invoke $Invoke -Log $Log
        }
    }
    & $phase 'views mark'
    [pscustomobject]$result
}

# =====================================================================================================================
#  RELEASING A HELD COLLECTION ONCE (operator 2026-10-05: "how can i release these guards").
#  A collection is HELD when the Risk Analysis run that produced it is not shown complete (working rule 4: partial data is
#  never stored as a collection). Every held collection is stored as a RELEASE CANDIDATE in cfg.GuardRelease (connector
#  'datasync/detailed', kind 'collection', run id = the collection time) -- the same table and states as the vulnerability
#  connector's held closes: held -> released (an Admin, ONCE, with a reason, audited) -> applied | expired (7 days).
#  The next data sync LOADS a released collection once and MARKS IT PARTIAL (sidata.CollectionPartial: the reason, who,
#  when); the web app shows a "partial" badge wherever it is used. A collection whose rows lack their key columns
#  (Refuse) is never loaded, released or not -- data that cannot be placed in a day is not a day.
# =====================================================================================================================
$script:SIDataReleaseConnector = 'datasync/detailed'

# =====================================================================================================================
#  THE DATA SYNC OF A RUN THAT IS NOT COMPLETE (owner 2026-10-12 / 13: one failed step must not cost the customer the rest
#  of the run; and: the rules towards ServiceNow and a CMDB are never compromised by it).
#  When a step of the pipeline failed (the CI build, Risk Analysis), the pipeline still starts the data sync and says so
#  in the step's own record (cfg.FlowStepRun.RetryReason: "... on what is stored ..." -- engine\_shared\SI-Pipeline.ps1,
#  $script:SIPipelineStoredMark). The data sync then does what it always does with what is stored -- it loads only WHOLE
#  collections whose run is shown complete, keys every asset by the ledger's id or its own asset id (never a provisional
#  id) and closes no finding on a collection that is not complete -- and it SENDS NOTHING TO AN OUTPUT (data out: the
#  ServiceNow import set, the Excel files): no writer acts on a run that is not complete. When it cannot be told whether
#  the run is complete, the outputs are held too (they send only what changed, so the next complete run sends it).
# =====================================================================================================================
$script:SIDataStoredMark = 'on what is stored'

function Get-SIDataRunOnStoredSql {
    <# One guarded statement over the settings database: the reason the pipeline gave when it started this job after a
       failed step ('' = it did not: a complete run, a run on the job's own schedule, or a run started by hand). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.FlowStepRun') IS NULL OR OBJECT_ID(N'cfg.FlowRun') IS NULL OR COL_LENGTH(N'cfg.FlowStepRun', N'RetryReason') IS NULL SELECT CAST(N'' AS NVARCHAR(1000));
ELSE SELECT ISNULL((SELECT TOP (1) s.RetryReason FROM cfg.FlowStepRun AS s JOIN cfg.FlowRun AS r ON r.FlowRunId = s.FlowRunId
                     WHERE s.Job = @Job AND s.State IN (N'Starting', N'Running') AND r.State = N'Running' AND s.RetryReason LIKE @Mark
                     ORDER BY r.StartedUtc DESC), N'');
'@
}

function Get-SIDataRunOnStored {
    <# Did the pipeline start this job after a failed step, on what is stored? @{ OnStored; Known; Why }. Never throws:
       a database that cannot be read answers Known = $false (the caller then holds its outputs). No seam = a run outside
       the pipeline's database: Known, not on stored. #>
    param([scriptblock]$Invoke, [string]$Job = 'asset-datasync')
    if (-not $Invoke) { return [pscustomobject]@{ OnStored = $false; Known = $true; Why = '' } }
    try {
        $why = [string](& $Invoke (Get-SIDataRunOnStoredSql) @{ Job = $Job; Mark = ('%' + $script:SIDataStoredMark + '%') } 'scalar')
        [pscustomobject]@{ OnStored = [bool]$why.Trim(); Known = $true; Why = $why.Trim() }
    } catch {
        [pscustomobject]@{ OnStored = $false; Known = $false; Why = [string]$_.Exception.Message }
    }
}

function Get-SIDataReleaseKey {
    <# PURE. The release key of one collection (cfg.GuardRelease RunId): 'collection@<UTC time>'. Not a bare date, so no
       JSON reader turns it into a [datetime] on the way back. #>
    param([Parameter(Mandatory)][datetime]$CollectionTime)
    'collection@' + (Format-SIDataSqlTime -Time $CollectionTime)
}

function ConvertFrom-SIDataReleaseKey {
    <# PURE. 'collection@<UTC time>' -> the UTC [datetime]; $null for anything else. #>
    param([string]$Key)
    if ($Key -notmatch '^collection@(.+)$') { return $null }
    try { ConvertTo-SIDataUtc $Matches[1] } catch { $null }
}

function ConvertTo-SIDataHeldCollectionSet {
    <# PURE. One held plan item -> the release candidate cfg.GuardRelease stores (no item list: the whole collection is held). #>
    param([Parameter(Mandatory)]$Item)
    $key = Get-SIDataReleaseKey -CollectionTime $Item.CollectionTime
    $summary = [pscustomobject]@{ CollectionTime = ($Item.CollectionTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture))
                                  Rows = [long]$Item.Rows; Reason = [string]$Item.Reason; RunDetail = [string]$Item.RunDetail; ByAsset = @(); ByCve = @() }
    [pscustomobject]@{ GuardId = 'datasync.collection.held'; Connector = $script:SIDataReleaseConnector; ConnectorKind = 'collection'; RunId = $key
                       HeldCount = [int][Math]::Min([long]$Item.Rows, [long][int]::MaxValue); Items = @(); ItemsJson = '[]'
                       SummaryJson = (ConvertTo-Json -InputObject $summary -Compress -Depth 4) }
}

function Read-SIDataReleasedCollections {
    <# The RELEASED (not yet applied) collection candidates: @{ Release; CollectionTime; Key; By }. Never throws. #>
    param($Store, [scriptblock]$Log)
    if ($null -eq $Store) { return , @() }
    $out = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($r in @($Store.Open($script:SIDataReleaseConnector))) {
            if ($null -eq $r -or [string]$r.State -ne 'released') { continue }
            $t = ConvertFrom-SIDataReleaseKey -Key ([string]$r.RunId)
            if ($null -eq $t) { continue }
            $out.Add([pscustomobject]@{ Release = $r; CollectionTime = $t; Key = (Get-SIDataReleaseKey -CollectionTime $t); By = [string]$r.ReleasedBy
                                        ReleasedUtc = $(if ($r.PSObject.Properties['ReleasedUtc']) { $r.ReleasedUtc } else { $null }) })
        }
    } catch { if ($Log) { & $Log 'WARN' ("release     : the released collections could not be read -- {0}. Held collections stay held." -f $_.Exception.Message) } }
    , $out.ToArray()
}

function Find-SIDataReleasedCollection {
    <# PURE. The released candidate of one collection time, or $null. #>
    param([AllowEmptyCollection()][object[]]$Released = @(), [Parameter(Mandatory)]$CollectionTime)
    $t = ConvertTo-SIDataUtc $CollectionTime
    if ($null -eq $t) { return $null }
    $k = Get-SIDataReleaseKey -CollectionTime $t
    @($Released | Where-Object { $_ -and $_.Key -eq $k }) | Select-Object -First 1
}

function Set-SIDataReleasedPlan {
    <#
        The plan with the releases applied:
          Hold + released     -> Load (Reload when an unfinished load exists) ONCE, Partial = true, the reason kept
          Hold, not released  -> stays Hold; its release candidate is stored (once per collection)
          Skip + released     -> already loaded: the release is marked applied
          Refuse + released   -> never loaded (no key columns): the release is closed as expired, with the reason
        -DryRun stores and marks nothing.
    #>
    param([AllowEmptyCollection()][object[]]$Plan = @(), [AllowEmptyCollection()][object[]]$Released = @(), [AllowEmptyCollection()][object[]]$Loaded = @(),
          [AllowEmptyCollection()][object[]]$Runs = @(), $Store, [switch]$DryRun, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) } }
    $seen = @{}
    foreach ($p in @($Plan)) {
        if ($null -eq $p) { continue }
        $rel = Find-SIDataReleasedCollection -Released $Released -CollectionTime $p.CollectionTime
        if ($rel) { $seen[$rel.Key] = $true }
        if ($p.Action -eq 'Hold' -and $rel) {
            $was = [string]$p.Reason
            $existing = @($Loaded | Where-Object { $_ -and (ConvertTo-SIDataUtc $_.CollectionTime) -and (Get-SIDataReleaseKey -CollectionTime (ConvertTo-SIDataUtc $_.CollectionTime)) -eq $rel.Key }) | Select-Object -First 1
            $p.Partial = $true; $p.ReleasedBy = $rel.By; $p.Release = $rel.Release
            $p.PartialReason = (@($was, [string]$p.RunDetail) | Where-Object { "$_".Trim() }) -join ' -- '
            $p.Run = Select-SIDataCoveringRun -SnapshotTime $p.CollectionTime -Runs @($Runs)
            if ($existing) { $p.Action = 'Reload'; $p.ExistingId = $existing.CollectionId } else { $p.Action = 'Load' }
            $p.Reason = ('released once by {0}: loaded although {1} -- marked partial' -f $(if ($rel.By) { $rel.By } else { 'an Admin' }), $was)
            continue
        }
        if ($p.Action -eq 'Hold' -and $Store -and -not $DryRun) {
            try {
                $why = $Store.Save((ConvertTo-SIDataHeldCollectionSet -Item $p))
                if ($why) { & $Log 'WARN' ("release     : {0:yyyy-MM-dd HH:mm} UTC cannot be offered for release -- {1}" -f $p.CollectionTime, $why) }
            } catch { & $Log 'WARN' ("release     : {0:yyyy-MM-dd HH:mm} UTC could not be stored for release -- {1}" -f $p.CollectionTime, $_.Exception.Message) }
            continue
        }
        if ($rel -and $Store -and -not $DryRun) {
            try {
                if ($p.Action -eq 'Skip') { $Store.Finish($rel.Release, 'applied', '', 'already loaded as a complete collection -- nothing to release') }
                elseif ($p.Action -eq 'Refuse') { $Store.Finish($rel.Release, 'expired', '', ('not loaded: ' + [string]$p.Reason)) }
            } catch { & $Log 'WARN' ("release     : the release of {0:yyyy-MM-dd HH:mm} UTC could not be closed -- {1}" -f $p.CollectionTime, $_.Exception.Message) }
        }
    }
    foreach ($r in @($Released)) {
        if ($r -and -not $seen.ContainsKey($r.Key)) { & $Log 'WARN' ("release     : the released collection of {0:yyyy-MM-dd HH:mm} UTC is no longer in Log Analytics -- it cannot be loaded" -f $r.CollectionTime) }
    }
    # unrolled: the caller collects it with @() (a wrapped array would arrive as ONE element)
    foreach ($p in @($Plan)) { if ($null -ne $p) { $p } }
}

function Complete-SIDataReleasedLoad {
    <# A released collection just loaded: marked partial in sidata.CollectionPartial, its release applied. Never throws. #>
    param([Parameter(Mandatory)]$Item, [Parameter(Mandatory)]$Loaded, [Parameter(Mandatory)][scriptblock]$Invoke, $Store, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) } }
    $rel = $Item.Release
    $ru = ''
    if ($rel -and $rel.PSObject.Properties['ReleasedUtc'] -and $rel.ReleasedUtc) { $u = ConvertTo-SIDataUtc $rel.ReleasedUtc; if ($u) { $ru = Format-SIDataSqlTime -Time $u } }
    $marked = $false
    try {
        [void](& $Invoke (Get-SIDataMarkPartialSql) @{ CollectionId = [int]$Loaded.CollectionId; Reason = [string]$Item.PartialReason; By = [string]$Item.ReleasedBy; ReleasedUtc = $ru } 'scalar')
        $marked = $true
    } catch { & $Log 'WARN' ("release     : {0:yyyy-MM-dd HH:mm} UTC was loaded but could not be marked partial -- {1}" -f $Item.CollectionTime, $_.Exception.Message) }
    if ($rel -and $Store) {
        try { $Store.Finish($rel, 'applied', [string]$Loaded.CollectionId, ('loaded once as collection {0} ({1} finding(s)), marked partial' -f $Loaded.CollectionId, $Loaded.Findings)) }
        catch { & $Log 'WARN' ("release     : the release of {0:yyyy-MM-dd HH:mm} UTC could not be marked applied -- {1}" -f $Item.CollectionTime, $_.Exception.Message) }
    }
    & $Log 'OK' ("release     : {0:yyyy-MM-dd HH:mm} UTC loaded once as released by {1} -- {2} finding(s), MARKED PARTIAL in the web app" -f $Item.CollectionTime, $(if ($Item.ReleasedBy) { $Item.ReleasedBy } else { 'an Admin' }), $Loaded.Findings)
    [pscustomobject]@{ CollectionId = $Loaded.CollectionId; CollectionTime = $Item.CollectionTime; Findings = $Loaded.Findings; ReleasedBy = [string]$Item.ReleasedBy
                       Reason = [string]$Item.PartialReason; Marked = $marked }
}

function Get-SIDataRefusedSummary {
    <# PURE (#294). The run-health sentence for what this sync REFUSED to load (empty when nothing was refused). #>
    param($Result)
    if ($null -eq $Result) { return '' }
    $parts = New-Object System.Collections.Generic.List[string]
    $refused = @(); if ($Result.PSObject.Properties['Refused']) { $refused = @($Result.Refused | Where-Object { $_ }) }
    $untimed = @(); if ($Result.PSObject.Properties['Untimed']) { $untimed = @($Result.Untimed | Where-Object { $_ }) }
    foreach ($r in $refused) { $parts.Add(('the Risk Analysis collection of {0:yyyy-MM-dd HH:mm} UTC was NOT loaded as a day: {1}' -f $r.CollectionTime, [string]$r.Reason)) }
    if ($untimed.Count) {
        $n = 0L; foreach ($u in $untimed) { $n += [long]$u.Rows }
        $parts.Add(('{0} Risk Analysis row(s) arrived without a CollectionTime ({1}) and were NOT loaded -- they belong to no collection' -f $n, ((@($untimed | ForEach-Object { '{0:yyyy-MM-dd HH:00} UTC' -f $_.Hour })) -join ', ')))
    }
    ($parts -join ' | ')
}

function Test-SIDataRefusalReportedBefore {
    <#
        PURE (#426). $true when this sync's refused-data guard event came back 'already-reported' -- every cause it carried
        (each refused collection, each hour of rows without a collection time) was reported by an earlier run (#414). Such a
        refusal is no new partial run. $false when there was no such event, when any refused event was reported now, or when
        the guard is off / could not decide (then run health is the only signal and stays partial).
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$GuardResults)
    $ref = @(@($GuardResults) | Where-Object { $_ -and $_.PSObject.Properties['Event'] -and $_.Event -and [string]$_.Event.GuardId -eq 'datasync.collection.refused' })
    if (-not $ref.Count) { return $false }
    foreach ($r in $ref) { if ([string]$r.Status -ne 'already-reported') { return $false } }
    $true
}

function Format-SIDataCutAnswer {
    <# PURE. #639: the failure of a Log Analytics answer the service CUT (too large) -- a failed read, never a shorter result:
       what it did not return is unknown, not absent. The service's own words stay in it (Read-SIDataPages recognises a
       paged read's cut by them and reads that page again in halves). #>
    param([long]$Rows = 0, [string]$ErrorText = '')
    'Log Analytics returned only a part of the answer (it was too large; {0} row(s) arrived) -- the read is failed: what it did not return is unknown, not absent. {1}' -f $Rows, $ErrorText
}

function Test-SIDataOutOfMemory {
    <# PURE. Did this failure come from the job running out of memory (an answer larger than it can hold)? #>
    param([AllowNull()]$ErrorRecord)
    $ex = $ErrorRecord
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ex = $ErrorRecord.Exception }
    $depth = 0
    while ($ex -is [System.Exception] -and $depth -lt 8) {
        if ($ex -is [System.OutOfMemoryException]) { return $true }
        $ex = $ex.InnerException
        $depth++
    }
    $false
}

function Clear-SIDataMemory {
    <#
        Hands back the memory nothing refers to any more: one full collection that also closes the gaps large blocks
        leave behind (a Log Analytics answer and its rows are large blocks). After every collection, and after a read
        that ran out of memory -- not after every page. Never throws.
    #>
    try {
        [System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = [System.Runtime.GCLargeObjectHeapCompactionMode]::CompactOnce
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    } catch { }
}

function Read-SIDataPages {
    <#
        Reads ONE large result a PAGE at a time and hands each page's rows to -OnRows before the next page is read, so
        what is held is one page -- whatever the size of the whole (a collection of 70,000 rows read as a few large
        answers ran the job out of memory, every night, with one more collection to load each time).
        A page is a list of cuts (Get-SIDataPageFilter): -KqlOf builds the query of a page from its cuts -- its rows,
        or with $true how many rows it holds. The -Pages planned pages never overlap and together are every row.
          * An answer too large to return, or to hold: THAT page is cut in two and read again. Nothing of it was
            written, and no other page is read again. A page of one row (or of rows no key tells apart) cannot be cut:
            the read stops with what is wrong -- no row is ever left out.
          * -OnRows returns the measured size of the page it stored (characters). A page more than twice -TargetChars
            cuts every page still to read by the measured factor: the size of a page follows what was measured, not a
            fixed number (working rule 5).
        Returns @{ Pages; Rows; Cuts }. Any other failure throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Query, [Parameter(Mandatory)][scriptblock]$KqlOf, [long]$Pages = 1,
          [Parameter(Mandatory)][scriptblock]$OnRows, [long]$TargetChars = 16MB, [string]$What = 'rows', [scriptblock]$Log)
    if ($Pages -lt 1) { $Pages = 1 }
    $pageQueue = New-Object 'System.Collections.Generic.Queue[object]'
    for ($pageNo = [long]0; $pageNo -lt $Pages; $pageNo++) { $pageQueue.Enqueue([pscustomobject]@{ Cuts = @([pscustomobject]@{ Parts = $Pages; Part = $pageNo }) }) }
    $pagesRead = 0L; $rowsRead = 0L; $cutsMade = 0L
    while ($pageQueue.Count -gt 0) {
        $page = $pageQueue.Dequeue()
        $pageRows = $null; $tooLarge = ''
        try { $pageRows = @(& $Query (& $KqlOf $page.Cuts $false)) }
        catch {
            if (Test-SIDataOutOfMemory -ErrorRecord $_) { $tooLarge = 'too large for this job''s memory' }
            elseif (Test-SIDataResponseTooLarge -Text (Get-SIKqlErrorText -ErrorRecord $_)) { $tooLarge = 'too large to read in one answer' }
            else { throw }
        }
        if ($tooLarge) {
            $pageRows = $null
            Clear-SIDataMemory
            # how many rows the page holds, and whether their keys differ: one row cannot be made smaller
            $held = -1L; $oneKey = $false
            $countRow = @(& $Query (& $KqlOf $page.Cuts $true)) | Select-Object -First 1
            if ($countRow -and $countRow.PSObject.Properties['PageRows']) {
                $heldN = ConvertTo-SIDataNumber $countRow.PageRows
                if ($null -ne $heldN) { $held = [long]$heldN }
                $oneKey = ([string]$countRow.OneKey) -match '^(?i:true|1)$'
            }
            if ($held -eq 0) { continue }   # nothing in this page: nothing to read
            if ($held -eq 1 -or ($held -gt 1 -and $oneKey) -or @($page.Cuts).Count -gt 64) {
                throw ("{0}: one row is {1} -- it cannot be read, so nothing of this load is shown." -f $What, $tooLarge)
            }
            foreach ($half in 0, 1) { $pageQueue.Enqueue([pscustomobject]@{ Cuts = @($page.Cuts) + @([pscustomobject]@{ Parts = [long]2; Part = [long]$half }) }) }
            $cutsMade++
            if ($Log) { & $Log 'INFO' ("  {0}: a part was {1} -- it is read again in two smaller parts" -f $What, $tooLarge) }
            continue
        }
        $pageCount = $pageRows.Count
        $pageChars = 0L
        $stored = @(& $OnRows $pageRows)
        if ($stored.Count -gt 0) { $pageChars = [long]$stored[$stored.Count - 1] }
        $pageRows = $null
        $pagesRead++; $rowsRead += $pageCount
        # measured, not assumed: a page far larger than planned -> every page still to read is cut by that factor
        if ($TargetChars -gt 0 -and $pageChars -gt (2 * $TargetChars) -and $pageCount -gt 1 -and $pageQueue.Count -gt 0) {
            $factor = [long][Math]::Ceiling([double]$pageChars / [double]$TargetChars)
            $rest = $pageQueue.ToArray()
            $pageQueue.Clear()
            foreach ($restPage in $rest) {
                for ($piece = [long]0; $piece -lt $factor; $piece++) { $pageQueue.Enqueue([pscustomobject]@{ Cuts = @($restPage.Cuts) + @([pscustomobject]@{ Parts = $factor; Part = $piece }) }) }
            }
            $cutsMade++
            if ($Log) { & $Log 'INFO' ("  {0}: its rows are larger than measured beforehand -- the {1} part(s) still to read are read as {2}" -f $What, $rest.Count, $pageQueue.Count) }
        }
    }
    [pscustomobject]@{ Pages = $pagesRead; Rows = $rowsRead; Cuts = $cutsMade }
}

function Invoke-SIDataLoadRecommendations {
    <# The recommendations in force at one collection's time -> sidata.Recommendation, a page at a time. Returns the rows written. #>
    param([Parameter(Mandatory)]$Item, [Parameter(Mandatory)][scriptblock]$Query, [Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][int]$CollectionId,
          [Parameter(Mandatory)]$Set, [hashtable]$AssetOfId = @{}, [ref]$ChunkChars, [scriptblock]$Log)
    $cid = $CollectionId
    $tText = Format-SIDataSqlTime -Time $Item.CollectionTime
    $set = $Set
    # ---- recommendations in force at that time ------------------------------------------------------------------
    # A large tenant's snapshot is larger than one answer, so it is read in pages like the findings: the pages are
    # planned from its measured size, and each page is stored before the next is read.
    $recState = @{ Written = 0L }
    try {
        $recPlanned = 1; $recEmpty = $false
        $recSize = @(& $Query (Get-SIDataRecommendationsKql -AsOf $Item.CollectionTime -Measure)) | Select-Object -First 1
        if ($recSize -and $recSize.PSObject.Properties['PageRows']) {
            $recRowCount = [long](ConvertTo-SIDataNumber $recSize.PageRows)
            $recEmpty = ($recRowCount -le 0)
            $recPlanned = Get-SIDataPartitionCount -Rows $recRowCount -Bytes ([double](ConvertTo-SIDataNumber $recSize.PageBytes))
        }
        if (-not $recEmpty) {
            $recSql = Get-SIDataInsertRecommendationSql
            $recKql = {
                param($cuts, $countOnly)
                Get-SIDataRecommendationsKql -AsOf $Item.CollectionTime -PageFilter (Get-SIDataPageFilter -Cuts $cuts) -CountOnly:([bool]$countOnly)
            }
            $onRecRows = {
                param($rows)
                $items = New-Object System.Collections.Generic.List[string]
                $chars = 0L
                for ($ri = 0; $ri -lt $rows.Count; $ri++) {
                    $r = $rows[$ri]
                    $rows[$ri] = $null
                    if (-not $r) { continue }
                    $json = ConvertTo-SIDataRecommendationJson -Row $r -AssetOfId $AssetOfId -KeyOf $set.KeyOf -TierOf $set.TierOf
                    $items.Add($json)
                    $chars += $json.Length + 1
                }
                if ($items.Count -gt 0) {
                    $recState.Written += Write-SIDataJsonRows -Invoke $Invoke -Sql $recSql -Items $items.ToArray() -Params @{ CollectionId = $cid } -ChunkChars $ChunkChars -What 'recommendations'
                }
                $chars
            }
            [void](Read-SIDataPages -Query $Query -KqlOf $recKql -Pages $recPlanned -OnRows $onRecRows -What ('recommendations of ' + $tText) -Log $Log)
        }
    }
    catch {
        if (Test-SIKqlTableMissing -ErrorRecord $_ -TableName 'SI_AzureRecommendation_CL') { & $Log 'WARN' 'SI_AzureRecommendation_CL does not exist in this workspace yet -- no recommendations stored.' }
        else { throw }
    }
    $recState.Written
}
# =====================================================================================================================
#  ONE INCOMPLETE REPORT DOES NOT HOLD A WHOLE RUN -- PER-REPORT LOADING (owner 2026-10-14: "one missing report must not
#  block the whole flow"). A Risk Analysis run in which a report could not be completed (its verdict NotComplete in
#  sidata.RaReportStatus -- a short answer, a query that failed, a report not in the run) is loaded like any other: every
#  report that IS complete is current at once. For each report that is NOT complete:
#    * the rows this run did store for it are KEPT (never removed);
#    * the rows of its LAST COMPLETE collection that this run did not return are CARRIED into this collection, each marked
#      with the time of that collection (sidata.Finding.CarriedFrom) -- shown "from <date>", never as current, never
#      dropped: what is missing from a report that could not be completed is UNKNOWN, not resolved;
#    * no complete earlier result: this run's rows are shown, marked as not complete;
#    * per report, what was done is stored (sidata.CollectionReportCarry) and said on the collection (sidata.CollectionPartial,
#      by 'per report' when every cause of the run's incompleteness is a named report -- the run's own judgement,
#      sidata.Collection.RaPartialScope; anything else keeps the whole-collection partial mark as before).
#  The closes act per report too (Resolve-SIReportScopedComplete, asset-cmdb\_shared\SI-VulnDesired.ps1): a report that is
#  not complete closes nothing, the complete ones close as usual. A database the updater has not updated yet (no
#  CarriedFrom column / CollectionReportCarry table) is said once and gets the whole-collection mark as before.
# =====================================================================================================================
$script:SIDataPerReportBy = 'per report'

function Get-SIDataCarrySchemaCheckSql {
    "SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'CarriedFrom') IS NOT NULL AND OBJECT_ID('sidata.CollectionReportCarry') IS NOT NULL AND OBJECT_ID('sidata.RaReportStatus') IS NOT NULL AND OBJECT_ID('sidata.CollectionPartial') IS NOT NULL THEN 1 ELSE 0 END"
}

function Get-SIDataCarryColumnsSql {
    <# The columns of sidata.Finding a carried row takes from its source row (every stored column but its own id, its collection, the carry mark and Risk Analysis' per-run bookkeeping). #>
    "SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('sidata.Finding') AND is_identity = 0 AND is_computed = 0 AND name NOT IN ('FindingId', 'CollectionId', 'CarriedFrom', 'RaReport', 'RaBucket', 'RaSeq', 'RaDedup', 'RaSort', 'RaInView') ORDER BY column_id"
}

function Get-SIDataCarryMaxDays {
    <# PURE. How old a carried report result may be: NO LIMIT (owner 2026-10-22: "remove the 7 days"). A report that could
       not be completed always carries its last complete result, however old, shown with its date -- never dropped, never
       closed. 0 = no limit. -Value is accepted and ignored (the source-dropout setting no longer bounds the carry). #>
    param($Value)
    0
}

function Get-SIDataCarrySql {
    <#
        ONE statement per collection (see above): the incomplete reports of the collection's run, the last collection in which
        each was complete (its verdict there was not NotComplete; a collection from before the verdicts existed counts when it
        carries no verdict at all and no partial mark), the rows carried, the record per report. Idempotent: a row already
        in the collection (this run's, or carried by an earlier try) is never added twice. Answers one row per report.
        -Columns: Get-SIDataCarryColumnsSql's names (checked against sys.columns; nothing else reaches the statement).
        @MaxDays (owner 2026-10-14: a carried result is at most 7 days old): a last complete result OLDER than that many days
        before this collection is not carried -- the report shows as not complete (TooOldTime says from when); 0 = no limit.
    #>
    param([Parameter(Mandatory)][string[]]$Columns)
    $safe = @($Columns | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*$' })
    $list = ($safe | ForEach-Object { '[{0}]' -f $_ }) -join ', '
    $from = ($safe | ForEach-Object { 'f.[{0}]' -f $_ }) -join ', '
    @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @c INT = CONVERT(int, @CollectionId);
DECLARE @t DATETIME2(3) = (SELECT CollectionTime FROM sidata.Collection WHERE CollectionId = @c);
DECLARE @inc TABLE (ReportName NVARCHAR(256) NOT NULL PRIMARY KEY, Reason NVARCHAR(2000) NULL);
INSERT @inc SELECT ReportName, MAX(Reason) FROM sidata.RaReportStatus WHERE CollectionTime = @t AND Grain = N'Detailed' AND State = N'NotComplete' GROUP BY ReportName;
DECLARE @max INT = ISNULL(TRY_CONVERT(int, @MaxDays), 0);
DECLARE @src TABLE (ReportName NVARCHAR(256) NOT NULL PRIMARY KEY, FromId INT NULL, FromTime DATETIME2(3) NULL, Reason NVARCHAR(2000) NULL, TooOldTime DATETIME2(3) NULL);
INSERT @src SELECT i.ReportName,
       CASE WHEN @max > 0 AND g.CollectionTime < DATEADD(day, -@max, @t) THEN NULL ELSE g.CollectionId END,
       CASE WHEN @max > 0 AND g.CollectionTime < DATEADD(day, -@max, @t) THEN NULL ELSE g.CollectionTime END,
       i.Reason,
       CASE WHEN @max > 0 AND g.CollectionTime < DATEADD(day, -@max, @t) THEN g.CollectionTime END
FROM @inc i OUTER APPLY (
    SELECT TOP (1) p.CollectionId, p.CollectionTime FROM sidata.Collection p
    WHERE p.Kind = N'Detailed' AND p.Status = N'Complete' AND p.CollectionId <> @c AND p.CollectionTime < @t$(if (Get-Command -Name Get-SIDataLiveFilter -ErrorAction SilentlyContinue) { Get-SIDataLiveFilter -Alias p })
      AND (EXISTS (SELECT 1 FROM sidata.RaReportStatus s WHERE s.CollectionTime = p.CollectionTime AND s.Grain = N'Detailed' AND s.ReportName = i.ReportName AND s.State <> N'NotComplete')
           OR (NOT EXISTS (SELECT 1 FROM sidata.RaReportStatus s WHERE s.CollectionTime = p.CollectionTime AND s.Grain = N'Detailed')
               AND NOT EXISTS (SELECT 1 FROM sidata.CollectionPartial x WHERE x.CollectionId = p.CollectionId)))
    ORDER BY p.CollectionTime DESC) g;
DECLARE @added TABLE (ReportName NVARCHAR(256) NULL);
BEGIN TRANSACTION;
INSERT sidata.Finding (CollectionId, $list, CarriedFrom)
OUTPUT inserted.ReportName INTO @added (ReportName)
SELECT @c, $from, s.FromTime
FROM @src s JOIN sidata.Finding f ON f.CollectionId = s.FromId AND f.ReportName = s.ReportName
WHERE s.FromId IS NOT NULL
  AND NOT EXISTS (SELECT 1 FROM sidata.Finding k WHERE k.CollectionId = @c AND k.ReportName = f.ReportName
                  AND ISNULL(k.AssetKey, N'') = ISNULL(f.AssetKey, N'') AND ISNULL(k.ConfigurationId, N'') = ISNULL(f.ConfigurationId, N'')
                  AND (f.ConfigurationId IS NOT NULL OR ISNULL(k.Title, N'') = ISNULL(f.Title, N'')));
DELETE FROM sidata.CollectionReportCarry WHERE CollectionId = @c OR NOT EXISTS (SELECT 1 FROM sidata.Collection x WHERE x.CollectionId = sidata.CollectionReportCarry.CollectionId);
INSERT sidata.CollectionReportCarry (CollectionId, ReportName, FromCollectionId, FromTime, CarriedRows, ThisRunRows, Reason)
SELECT @c, s.ReportName, s.FromId, s.FromTime,
       (SELECT COUNT(*) FROM sidata.Finding f WHERE f.CollectionId = @c AND f.ReportName = s.ReportName AND f.CarriedFrom IS NOT NULL),
       (SELECT COUNT(*) FROM sidata.Finding f WHERE f.CollectionId = @c AND f.ReportName = s.ReportName AND f.CarriedFrom IS NULL),
       LEFT(s.Reason, 2000)
FROM @src s;
COMMIT TRANSACTION;
SELECT r.ReportName, r.FromCollectionId, r.FromTime, r.CarriedRows, r.ThisRunRows, r.Reason, (SELECT COUNT(*) FROM @added a WHERE a.ReportName = r.ReportName) AS AddedNow,
       (SELECT s.TooOldTime FROM @src s WHERE s.ReportName = r.ReportName) AS TooOldTime, @max AS MaxDays
FROM sidata.CollectionReportCarry r WHERE r.CollectionId = @c ORDER BY r.ReportName;
"@
}

function Get-SIDataScopeSql {
    <# What the run's incompleteness covers, as Risk Analysis judged it (sidata.Collection.RaPartialScope): 'reports' | 'run' | '' (not recorded). #>
    @'
IF COL_LENGTH('sidata.Collection', 'RaPartialScope') IS NULL SELECT CAST(N'' AS NVARCHAR(16));
ELSE EXEC sp_executesql N'SELECT ISNULL((SELECT RaPartialScope FROM sidata.Collection WHERE CollectionId = CONVERT(int, @c)), N'''')', N'@c nvarchar(20)', @c = @CollectionId;
'@
}

function Format-SIDataCarryText {
    <#
        PURE. The words of the per-report mark and log lines: per report "from <date> -- this run's report could not be
        completed", or that no complete earlier result exists. -Rows: Get-SIDataCarrySql's rows. Returns @{ Text; Lines }.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $g = { param($r, [string]$n) if ($r -is [System.Collections.IDictionary]) { $v = $r[$n] } elseif ($r.PSObject.Properties[$n]) { $v = $r.$n } else { $v = $null }; if ($v -is [System.DBNull]) { $null } else { $v } }
    $parts = New-Object System.Collections.Generic.List[string]
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $name = [string](& $g $r 'ReportName'); if (-not $name) { continue }
        $why = ([string](& $g $r 'Reason')).Trim()
        $why = ([regex]::Replace($why, '\s*\((?:audit\s*)?#\d+\)', '')).Trim()
        if ($why.Length -gt 200) { $why = $why.Substring(0, 197) + '...' }
        $from = & $g $r 'FromTime'
        $carried = [int](& $g $r 'CarriedRows'); $own = [int](& $g $r 'ThisRunRows')
        if ($null -ne $from -and "$from" -ne '') {
            $ft = ConvertTo-SIDataUtc $from
            $p = [string]::Format($inv, "{0}: from {1:yyyy-MM-dd HH:mm} UTC -- this run's report could not be completed", $name, $ft)
            $l = [string]::Format($inv, "{0}: this run's report could not be completed -- its last complete result (from {1:yyyy-MM-dd HH:mm} UTC) is shown: {2} row(s) carried, {3} row(s) this run did return kept; nothing of it is closed", $name, $ft, $carried, $own)
        } elseif ($null -ne (& $g $r 'TooOldTime') -and "$(& $g $r 'TooOldTime')" -ne '') {
            $ot = ConvertTo-SIDataUtc (& $g $r 'TooOldTime'); $md = [int](& $g $r 'MaxDays')
            $p = [string]::Format($inv, "{0}: this run's report could not be completed; its last complete result (from {1:yyyy-MM-dd HH:mm} UTC) is older than {2} day(s) and is not shown -- the {3} row(s) this run did return are shown, not complete", $name, $ot, $md, $own)
            $l = $p + '; nothing of it is closed'
        } else {
            $p = [string]::Format($inv, "{0}: this run's report could not be completed and no complete earlier result exists -- the {1} row(s) it did return are shown, not complete", $name, $own)
            $l = $p + '; nothing of it is closed'
        }
        if ($why) { $p += ' (' + $why + ')'; $l += ' (' + $why + ')' }
        $parts.Add($p); $lines.Add($l)
    }
    [pscustomobject]@{ Text = ($parts -join '; '); Lines = $lines.ToArray() }
}

function Invoke-SIDataCarryReports {
    <#
        One collection Risk Analysis wrote, before it is marked complete: its incomplete reports keep their last complete rows
        (see above). Returns @{ Ready; Reports (rows); Text; Scope }. Ready = $false: the database is not updated yet (said
        once) -- nothing is carried and the caller marks the whole collection as before. Throws on a database error (the
        caller's load fails and is tried again, as any load).
    #>
    param([Parameter(Mandatory)][int]$CollectionId, [Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $ready = ([int](& $Invoke (Get-SIDataCarrySchemaCheckSql) @{} 'scalar')) -eq 1
    if (-not $ready) {
        if (-not $script:SIDataCarryNotReadySaid) {
            & $Log 'WARN' '  per report  : the database does not have the per-report columns yet (the updater adds them) -- a run with a report that could not be completed is marked partial as a whole until then.'
            $script:SIDataCarryNotReadySaid = $true
        }
        return [pscustomobject]@{ Ready = $false; Reports = @(); Text = ''; Scope = '' }
    }
    $cols = @(@(& $Invoke (Get-SIDataCarryColumnsSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { [string]$_['name'] } | Where-Object { $_ })
    $rows = @(@(& $Invoke (Get-SIDataCarrySql -Columns $cols) @{ CollectionId = [string]$CollectionId; MaxDays = [string](Get-SIDataCarryMaxDays) } 'reader') | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] -and $_['ReportName'] })
    $scope = ''
    try { $scope = ([string](& $Invoke (Get-SIDataScopeSql) @{ CollectionId = [string]$CollectionId } 'scalar')).Trim().ToLowerInvariant() } catch { $scope = '' }
    $fmt = Format-SIDataCarryText -Rows $rows
    foreach ($l in $fmt.Lines) { & $Log 'WARN' ('  per report  : ' + $l) }
    [pscustomobject]@{ Ready = $true; Reports = $rows; Text = $fmt.Text; Scope = $scope }
}

# =====================================================================================================================
#  #638 COLLECTIONS RISK ANALYSIS WROTE ITSELF. Risk Analysis writes its Detailed result straight into sidata.Finding, a
#  query slice at a time, and marks the collection when every slice is in (RaCompletedAt). The data sync does NOT load such a
#  collection from Log Analytics (it would load it twice); it does the rest of a load -- each finding's CI key, the CIs and
#  their identifiers, the correlation evidence, the recommendations in force, the daily aggregates -- and marks it 'Complete'.
# =====================================================================================================================
function Get-SIDataRaFinishSql {
    <#
        A COLLECTION WHOSE RUN STOPPED AFTER ITS VERDICTS WERE FINAL (live 2026-10-16: a Detailed run stored all 65 reports,
        then ran out of memory building its workbook before it marked its collection; it was never delivered). Such a
        collection is marked in (RaCompletedAt) HERE, so the adoption below completes it like any other -- ONLY when:
          * Detailed, written by Risk Analysis, still 'Loading', never marked in, not retired;
          * Risk Analysis recorded its VERDICTS FINAL (RaVerdictsFinalAt, Set-RAStreamVerdictsFinal): the guards, the
            per-report verdicts and the Log Analytics post were settled and nothing held the run -- its partial reason / scope
            persisted at that moment, so the adoption delivers it as partial when it was partial. A collection WITHOUT the
            marker (a run that stopped earlier, a refused or undelivered post, every collection from before the marker
            existed) is NEVER finished here (the trust rule: per-report states alone are not the run's verdict);
          * its run has ENDED: a newer Detailed collection exists (one run at a time per install), or it is older than 8 days.
        -Apply '0' = only list them. Returns CollectionId, CollectionTime, Partial, Reports, Rows per collection finished.
    #>
    $body = @'
DECLARE @c TABLE (CollectionId int PRIMARY KEY, CollectionTime datetime2(3), Partial nvarchar(2000));
INSERT @c (CollectionId, CollectionTime, Partial)
SELECT c.CollectionId, c.CollectionTime, c.RaPartialReason
FROM sidata.Collection c
WHERE c.Kind = N''Detailed'' AND c.Source = N''risk-analysis'' AND c.Status = N''Loading'' AND c.RaCompletedAt IS NULL AND c.RaVerdictsFinalAt IS NOT NULL{RET}
  AND (EXISTS (SELECT 1 FROM sidata.Collection n WHERE n.Kind = N''Detailed'' AND n.CollectionTime > c.CollectionTime) OR c.CollectionTime < DATEADD(day, -8, SYSUTCDATETIME()));
IF @Apply = N''1''
    UPDATE x SET RaCompletedAt = SYSUTCDATETIME(), [Rows] = (SELECT COUNT_BIG(*) FROM sidata.Finding f WHERE f.CollectionId = x.CollectionId)
    FROM sidata.Collection x JOIN @c c ON c.CollectionId = x.CollectionId WHERE x.Status = N''Loading'' AND x.RaCompletedAt IS NULL AND x.RaVerdictsFinalAt IS NOT NULL;
SELECT c.CollectionId, c.CollectionTime, c.Partial,
       (SELECT COUNT(*) FROM sidata.RaReportStatus s WHERE s.CollectionTime = c.CollectionTime AND s.Grain = N''Detailed'') AS Reports,
       (SELECT COUNT_BIG(*) FROM sidata.Finding f WHERE f.CollectionId = c.CollectionId) AS [Rows]
FROM @c c ORDER BY c.CollectionTime;
'@
    $withRet = $body.Replace('{RET}', ' AND c.RetiredAt IS NULL')
    $noRet = $body.Replace('{RET}', '')
    @"
IF COL_LENGTH('sidata.Collection', 'RaVerdictsFinalAt') IS NULL OR OBJECT_ID(N'sidata.RaReportStatus') IS NULL
    SELECT TOP (0) CAST(0 AS int) AS CollectionId, CAST(NULL AS datetime2(3)) AS CollectionTime, CAST(NULL AS nvarchar(2000)) AS Partial, CAST(0 AS int) AS Reports, CAST(0 AS bigint) AS [Rows];
ELSE IF COL_LENGTH('sidata.Collection', 'RetiredAt') IS NULL EXEC sp_executesql N'$noRet', N'@Apply nvarchar(1)', @Apply = @Apply;
ELSE EXEC sp_executesql N'$withRet', N'@Apply nvarchar(1)', @Apply = @Apply;
"@
}

function Invoke-SIDataRaFinish {
    <#
        The data sync's step for the collections Get-SIDataRaFinishSql describes: marks them in and says ONE line per
        collection. A dry run sends nothing (a dry run of the data sync sends no statement that can write). Returns the
        collections @{ CollectionId; CollectionTime; Reports; Rows } (unrolled; wrap the call in @()). Never throws (a
        failure is one warning; the collection stays held, as before).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [switch]$DryRun, [scriptblock]$Log)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    if ($DryRun) { return }
    try {
        $raw = @(& $Invoke (Get-SIDataRaFinishSql) @{ Apply = '1' } 'reader')
        $out = @($raw | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] -and $null -ne $_['CollectionId'] -and $_['CollectionId'] -isnot [System.DBNull] } | ForEach-Object {
            [pscustomobject]@{ CollectionId = [int]$_['CollectionId']; CollectionTime = (ConvertTo-SIDataUtc $_['CollectionTime']); Reports = [int]$_['Reports']; Rows = [long]$_['Rows']
                               Partial = $(if ($null -eq $_['Partial'] -or $_['Partial'] -is [System.DBNull]) { '' } else { [string]$_['Partial'] }) } })
        foreach ($o in $out) {
            & $Log 'WARN' ("risk analysis: the collection of {0:yyyy-MM-dd HH:mm:ss} UTC ({1} report(s), {2:N0} row(s)) had its verdicts final but its run stopped before marking it -- it is completed here and delivered{3}" -f `
                $o.CollectionTime, $o.Reports, $o.Rows, $(if ($o.Partial) { ', marked partial as its run judged it' } else { '' }))
        }
        $out
    } catch {
        & $Log 'WARN' ("risk analysis: the collections a stopped run left with every report complete could not be checked ({0}) -- they stay held; the next data sync tries again" -f $_.Exception.Message)
    }
}

function Get-SIDataRaPendingSql {
    <# The Risk Analysis collections whose result is in and that the data sync has not completed yet, oldest first. #>
    @'
IF COL_LENGTH('sidata.Collection', 'RaCompletedAt') IS NULL SELECT TOP (0) CAST(0 AS int) AS CollectionId, CAST(NULL AS datetime2(3)) AS CollectionTime, CAST(NULL AS nvarchar(2000)) AS RaPartialReason, CAST(NULL AS nvarchar(64)) AS SolutionVersion;
ELSE IF COL_LENGTH('sidata.Collection', 'RetiredAt') IS NULL EXEC sp_executesql N'SELECT CollectionId, CollectionTime, RaPartialReason, SolutionVersion FROM sidata.Collection WHERE Kind = ''Detailed'' AND Source = ''risk-analysis'' AND Status = ''Loading'' AND RaCompletedAt IS NOT NULL ORDER BY CollectionTime';
ELSE EXEC sp_executesql N'SELECT CollectionId, CollectionTime, RaPartialReason, SolutionVersion FROM sidata.Collection WHERE Kind = ''Detailed'' AND Source = ''risk-analysis'' AND Status = ''Loading'' AND RaCompletedAt IS NOT NULL AND RetiredAt IS NULL ORDER BY CollectionTime';
'@
}

function Get-SIDataRaAssetsSql {
    <# The assets of one Risk Analysis collection's findings: the asset id Risk Analysis wrote, a name, the tier the rows tell about the ASSET. #>
    'SELECT RaAssetId, MIN(AssetName) AS AssetName, MIN(RaAssetTier) AS Tier, MIN(SecurityDomain) AS SecurityDomain FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaAssetId IS NOT NULL GROUP BY RaAssetId;'
}

function Get-SIDataRaSetAssetKeySql {
    <# Each finding keyed to its CI (the ledger's id), from the asset id Risk Analysis wrote. #>
    @'
UPDATE f SET AssetKey = j.K
FROM sidata.Finding f JOIN OPENJSON(@j) WITH (A nvarchar(400), K nvarchar(400)) j ON f.RaAssetId = j.A
WHERE f.CollectionId = CONVERT(int, @CollectionId);
SELECT @@ROWCOUNT;
'@
}

# =====================================================================================================================
#  #877 A REPORT RISK ANALYSIS HELD BACK (owner 2026-10-22: "Hold back that report"). A report whose rows of its run had to
#  go and could not be removed -- even in measured batches -- is held back by the run instead of failing it: its verdict
#  is NotComplete and sidata.RaReportStatus.HeldRaReport names the ordinal of those rows (RA-SqlStream.ps1). They are
#  removed HERE, FIRST, when the data sync takes the collection in -- before its CI keys, CIs, evidence, recommendations,
#  the per-report carry, the lifecycle stamp and the mark 'Complete' -- so nothing built from the collection, and nothing
#  that reads a complete collection (the groupings, the views, the key figures, the closes, the web app), ever reads a part
#  of that report as the report. The carry then shows the report's last complete result, marked; nothing of it is closed.
#  The removal is batched and measured (halved when a batch runs into the command timeout). When even that fails, the
#  collection is NOT taken in this time (said plainly; the earlier collection stays current) and the next data sync tries
#  again -- a partial report is never delivered as the report.
# =====================================================================================================================
function Get-SIDataHeldReportsSql {
    <# The reports Risk Analysis held back in one collection's run: ReportName, HeldRaReport (none on a database without the column). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.RaReportStatus') IS NULL OR COL_LENGTH('sidata.RaReportStatus', 'HeldRaReport') IS NULL
    SELECT TOP (0) CAST(N'' AS nvarchar(256)) AS ReportName, CAST(0 AS int) AS HeldRaReport;
ELSE
    EXEC sp_executesql N'SELECT s.ReportName, s.HeldRaReport FROM sidata.RaReportStatus s JOIN sidata.Collection c ON c.CollectionTime = s.CollectionTime
        WHERE c.CollectionId = CONVERT(int, @c) AND s.Grain = N''Detailed'' AND s.HeldRaReport IS NOT NULL ORDER BY s.HeldRaReport', N'@c nvarchar(20)', @c = @CollectionId;
'@
}

function Get-SIDataHeldRowsBatchSql {
    <# ONE batch of a held-back report's rows of its run (the rows Risk Analysis wrote: RaSeq set; a carried row has none). Answers the rows removed. #>
    'DELETE TOP (CONVERT(int, @Batch)) FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaReport = CONVERT(int, @Report) AND RaSeq IS NOT NULL; SELECT @@ROWCOUNT;'
}

function Remove-SIDataHeldReportRows {
    <#
        The rows of every report Risk Analysis held back in collection -CollectionId, removed in measured batches: the size
        grows (at most double) when a batch is fast, shrinks when slow, is HALVED when a batch runs into the command timeout;
        a batch of ONE that still times out three times, or any other error, THROWS with the report named (the caller's
        load of this collection fails and is tried again by the next data sync). Returns @{ Reports; Removed }.
    #>
    param([Parameter(Mandatory)][int]$CollectionId, [Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log, [string]$What = '', [long]$StartSize = 5000, [long]$TargetMs = 5000)
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $held = @(@(& $Invoke (Get-SIDataHeldReportsSql) @{ CollectionId = [string]$CollectionId } 'reader') | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] -and $null -ne $_['HeldRaReport'] -and -not ($_['HeldRaReport'] -is [System.DBNull]) })
    $total = 0L
    foreach ($h in $held) {
        $name = [string]$h['ReportName']; $ord = [int]$h['HeldRaReport']
        $size = [Math]::Max(1L, $StartSize); $floor = 0; $removed = 0L
        while ($true) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            try { $n = [long](@(& $Invoke (Get-SIDataHeldRowsBatchSql) @{ CollectionId = [string]$CollectionId; Report = [string]$ord; Batch = [string]$size } 'scalar')[-1]) }
            catch {
                $msg = [string]$_.Exception.Message
                if ($msg -match '(?i)timeout') {
                    if ($size -le 1) {
                        $floor++
                        if ($floor -lt 3) { continue }
                    } else { $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)); continue }
                }
                throw ("{0}: the rows report '{1}' left in this run (held back by Risk Analysis) could not be removed ({2}) -- the collection is not taken in this time, so no part of that report is ever shown as the report; the earlier collection stays current and the next data sync tries again" -f $What, $name, $msg)
            }
            $sw.Stop(); $floor = 0
            $removed += $n
            if ($n -lt $size) { break }
            $size = Get-SIDataNextSize -Current $size -ElapsedMs $sw.ElapsedMilliseconds -TargetMs $TargetMs -Minimum 1
        }
        $total += $removed
        & $Log 'WARN' ("  {0}: report '{1}' was held back by its Risk Analysis run -- {2} row(s) it left in this run are removed before the collection is taken in; it shows its last complete result, nothing of it is closed" -f $What, $name, $removed)
    }
    [pscustomobject]@{ Reports = @($held | ForEach-Object { [string]$_['ReportName'] }); Removed = $total }
}

function Invoke-SIDataAdoptRaCollection {
    <# One collection Risk Analysis wrote: the rest of its load (see above), then 'Complete'. Returns the shape Invoke-SIDataLoadCollection returns. #>
    param([Parameter(Mandatory)]$Item, [Parameter(Mandatory)][scriptblock]$Query, [Parameter(Mandatory)][scriptblock]$Invoke,
          [AllowEmptyCollection()][object[]]$Profiles = @(), [hashtable]$Index = @{}, $Owners, [hashtable]$Properties = @{}, [hashtable]$AssetOfId = @{},
          [ref]$ChunkChars, [scriptblock]$Log, [switch]$EvidenceReady, [hashtable]$EvidenceProfiles = @{})
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $cid = [int]$Item.CollectionId
    $tText = Format-SIDataSqlTime -Time $Item.CollectionTime
    # ---- #877 FIRST: the rows of a report the run HELD BACK go before anything reads the collection (see above) ---------
    $null = Remove-SIDataHeldReportRows -CollectionId $cid -Invoke $Invoke -Log $Log -What $tText
    # ---- each finding's CI key (#297/#298: an id that is only another asset's identifier belongs to that asset) ----------
    $raw = @(& $Invoke (Get-SIDataRaAssetsSql) @{ CollectionId = [string]$cid } 'reader')
    $byAsset = @{}; $map = New-Object System.Collections.Generic.List[string]; $resolved = 0
    foreach ($x in $raw) {
        foreach ($h in @($x)) {
            if (-not $h) { continue }
            $aid0 = ([string]$h['RaAssetId']).Trim(); if (-not $aid0) { continue }
            $aid = $aid0
            if ($null -ne $Owners) { $rs = Resolve-SIDataFindingAssetId -Id $aid0 -Owners $Owners; if ($rs.Resolved) { $aid = $rs.Id; $resolved++ } }
            $key = (Get-SIDataAssetKey -SIAssetId $aid -Index $Index).Key; if (-not $key) { $key = $aid }
            if ($key -cne $aid0) { $map.Add((ConvertTo-SIDataJsonObject -Values ([ordered]@{ A = $aid0; K = $key }))) }
            $tier = $null; if ($null -ne $h['Tier'] -and $h['Tier'] -isnot [System.DBNull]) { $tier = ConvertTo-SIDataTier $h['Tier'] }
            $l = $aid.ToLowerInvariant()
            $nm = $(if ($null -eq $h['AssetName'] -or $h['AssetName'] -is [System.DBNull]) { '' } else { [string]$h['AssetName'] })
            $sd = $(if ($null -eq $h['SecurityDomain'] -or $h['SecurityDomain'] -is [System.DBNull]) { '' } else { [string]$h['SecurityDomain'] })
            if (-not $byAsset.ContainsKey($l)) { $byAsset[$l] = [pscustomobject]@{ SI_AssetId = $aid; AssetName = $nm; Tier = $tier; SecurityDomain = $sd } }
            elseif ($null -ne $tier -and ($null -eq $byAsset[$l].Tier -or $tier -lt $byAsset[$l].Tier)) { $byAsset[$l].Tier = $tier }
        }
    }
    $raw = $null
    for ($i = 0; $i -lt $map.Count; $i += 2000) {
        $n = [Math]::Min(2000, $map.Count - $i)
        [void](& $Invoke (Get-SIDataRaSetAssetKeySql) @{ CollectionId = [string]$cid; j = ('[' + (($map.GetRange($i, $n).ToArray()) -join ',') + ']') } 'scalar')
    }
    if ($resolved -gt 0) { & $Log 'INFO' ("  {0} asset id(s) Risk Analysis wrote are another asset's identifier -- their findings are kept on that asset" -f $resolved) }
    # ---- the CIs ------------------------------------------------------------------------------------------------
    $set = Build-SIDataAssets -Profiles $Profiles -FindingAssets @($byAsset.Values) -Index $Index -Properties $Properties -SeenAt $Item.CollectionTime
    $kindCoverage = Get-SIDataKindCoverage -FindingAssets @($byAsset.Values) -Set $set
    foreach ($dk in @($kindCoverage.Dropped)) { & $Log 'WARN' ("  {0}: findings on {1} {2} asset(s), but 0 CIs of kind {2} were stored -- the web app's '{2}' filter shows none of them" -f $tText, $kindCoverage.Implied[$dk], $dk) }
    $assetItems = @($set.Assets | ForEach-Object { ConvertTo-SIDataJsonObject -Values ([ordered]@{ AssetKey = $_.AssetKey; AssetName = $_.AssetName; AssetKind = $_.AssetKind
        AssetKinds = $_.AssetKinds; Tier = $_.Tier; KeySource = $_.KeySource; LastSeen = $_.LastSeen; PropertiesJson = $_.PropertiesJson }) })
    $nAssets = Write-SIDataJsonRows -Invoke $Invoke -Sql (Get-SIDataUpsertAssetSql) -Items $assetItems -ChunkChars $ChunkChars -What 'assets'
    $idItems = @($set.Identifiers | ForEach-Object { ConvertTo-SIDataJsonObject -Values ([ordered]@{ AssetKey = $_.AssetKey; IdentifierType = $_.IdentifierType
        IdentifierValue = $_.IdentifierValue; SeenAt = $_.SeenAt }) })
    [void](Write-SIDataJsonRows -Invoke $Invoke -Sql (Get-SIDataUpsertIdentifierSql) -Items $idItems -ChunkChars $ChunkChars -What 'asset identifiers')
    $tierFilled = [int](& $Invoke (Get-SIDataFindingTierFromAssetSql) @{ CollectionId = $cid } 'scalar')
    if ($tierFilled -gt 0) { & $Log 'INFO' ("  {0} finding(s) without a tier took the tier of their asset" -f $tierFilled) }
    $evidence = $null
    if ($EvidenceReady) {
        try { $evidence = Invoke-SIDataEvidence -Invoke $Invoke -Set $set -CollectionId $cid -CollectionTime $Item.CollectionTime -Index $Index -EvidenceProfiles $EvidenceProfiles -ChunkChars $ChunkChars -Log $Log }
        catch { & $Log 'WARN' ("  {0}: the correlation evidence could not be written ({1}) -- the collection loads without it; the next collection's load computes it." -f $tText, $_.Exception.Message) }
    }
    $nRec = Invoke-SIDataLoadRecommendations -Item $Item -Query $Query -Invoke $Invoke -CollectionId $cid -Set $set -AssetOfId $AssetOfId -ChunkChars $ChunkChars -Log $Log
    # ---- per report: a report this run could not complete keeps its last complete rows, marked (see above) -----------
    $carry = $null
    if (Get-Command -Name Invoke-SIDataCarryReports -ErrorAction SilentlyContinue) { $carry = Invoke-SIDataCarryReports -CollectionId $cid -Invoke $Invoke -Log $Log }
    # ---- #855 W10: each finding's CI lifecycle, BEFORE the collection is marked complete and any aggregate is built from it.
    # A failure leaves the collection unstamped (its findings count as active, as before) and never stops the load.
    try { $null = Invoke-SIDataCiLifecycleStamp -Invoke $Invoke -CollectionId $cid }
    catch { & $Log 'WARN' ("  {0}: the CIs' lifecycle was not stamped on the findings ({1}) -- they count as active until the collection is stamped (the newest one is, on the next run)." -f $tText, $_.Exception.Message) }
    # ---- complete --------------------------------------------------------------------------------------------------
    $rows = [long](& $Invoke 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId);' @{ CollectionId = [string]$cid } 'scalar')
    $done = [int](& $Invoke (Get-SIDataCompleteCollectionSql) @{ CollectionId = $cid; Rows = [int]$rows } 'scalar')
    if ($done -ne 1) { throw ("{0}: the collection Risk Analysis wrote could not be marked complete ({1} row(s))" -f $tText, $rows) }
    $perReport = [bool]($carry -and $carry.Ready -and @($carry.Reports).Count -gt 0)
    if ($perReport -and [string]$carry.Scope -eq 'reports') {
        # every cause of the run's incompleteness is a named report: the collection is current, those reports are marked
        [void](& $Invoke (Get-SIDataMarkPartialSql) @{ CollectionId = $cid; Reason = [string]$carry.Text; By = $script:SIDataPerReportBy; ReleasedUtc = '' } 'scalar')
        & $Log 'WARN' ("  the collection of {0} UTC is loaded; {1} report(s) could not be completed in this run and show their last complete result, marked -- what they missed is unknown, not resolved" -f $tText, @($carry.Reports).Count)
    } elseif ([string]$Item.RaPartialReason -or $perReport) {
        [void](& $Invoke (Get-SIDataPartialTableSql) @{} 'scalar')
        $why = (@([string]$Item.RaPartialReason, $(if ($perReport) { [string]$carry.Text } else { '' })) | Where-Object { "$_".Trim() }) -join ' -- '
        [void](& $Invoke (Get-SIDataMarkPartialSql) @{ CollectionId = $cid; Reason = $why; By = 'the current rules (a partial run is loaded, marked partial)'; ReleasedUtc = '' } 'scalar')
        & $Log 'WARN' ("  the collection of {0} UTC is MARKED PARTIAL -- its Risk Analysis run did not finish every report; what it missed is unknown, not resolved" -f $tText)
    }
    $daily = [int](& $Invoke (Get-SIDataFindingDailySql) @{ Day = $Item.CollectionTime.ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } 'scalar')
    $clock.Stop()
    $seconds = [long][Math]::Round($clock.Elapsed.TotalSeconds)
    & $Log 'OK' ("  completed {0} (written by Risk Analysis): {1} row(s), {2} second(s) -- {3} asset(s), {4} recommendation(s); {5} daily aggregate row(s)" -f $tText, $rows, $seconds, $nAssets, $nRec, $daily)
    [pscustomobject]@{ CollectionId = $cid; CollectionTime = $Item.CollectionTime; Findings = $rows; Assets = $nAssets; Recommendations = $nRec; Pages = 0; Seconds = $seconds; Evidence = $evidence; KindCoverage = $kindCoverage; WrittenByRiskAnalysis = $true
                       IncompleteReports = $(if ($perReport) { @($carry.Reports | ForEach-Object { [string]$_['ReportName'] }) } else { @() }); IncompleteText = $(if ($perReport) { [string]$carry.Text } else { '' }) }
}

function Invoke-SIDataLoadCollection {
    <# Loads ONE collection (see the file header, step 4). Returns @{ CollectionId; CollectionTime; Findings; Assets; Recommendations; Pages; Seconds }.
       The collection row is 'Loading' from its first row to its last: it becomes 'Complete' only after every page is in the
       database, so a load that stops part way -- for any reason -- is found unfinished by the next run and loaded again. #>
    param(
        [Parameter(Mandatory)]$Item,
        [Parameter(Mandatory)][scriptblock]$Query,
        [Parameter(Mandatory)][scriptblock]$Invoke,
        [Parameter(Mandatory)][string]$EditionMajor,
        [int]$LookbackDays = 3,
        [AllowEmptyCollection()][object[]]$Profiles = @(),
        [hashtable]$Index = @{},
        $Owners,                                         # New-SIDataIdentifierOwners (#297/#298); $null = ids are used as they come
        [hashtable]$Properties = @{},
        [hashtable]$AssetOfId = @{},
        [ref]$ChunkChars,
        [ref]$BatchSize,
        [scriptblock]$Log,
        [switch]$EvidenceReady,                          # #299: the database carries the correlation evidence tables
        [hashtable]$EvidenceProfiles = @{}
    )
    if (-not $Log) { $Log = { param([string]$level, [string]$msg) Write-Host ('[{0}] {1}' -f $level, $msg) } }
    $tText = Format-SIDataSqlTime -Time $Item.CollectionTime
    $clock = [Diagnostics.Stopwatch]::StartNew()
    if ($Item.Action -eq 'Reload' -and $null -ne $Item.ExistingId) {
        $rm = Remove-SIDataCollection -Invoke $Invoke -CollectionId ([int]$Item.ExistingId) -BatchSize $BatchSize
        & $Log 'INFO' ("  removed the unfinished earlier load of {0} ({1} row(s))" -f $tText, $rm.Findings)
    }
    $runId = ''
    if ($Item.Run) {
        $runId = [string]$Item.Run.RunId
        $st = ConvertTo-SIDataUtc $Item.Run.StartedAt
        $dur = ConvertTo-SIDataNumber $Item.Run.DurationSec; if ($null -eq $dur) { $dur = 0 }
        if ($runId) {
            & $Invoke (Get-SIDataRunUpsertSql) @{ RunId = $runId; Engine = 'risk-analysis'; CollectionTime = $tText; Verdict = [string]$Item.Run.ExitReason
                StartedAt = $(if ($st) { Format-SIDataSqlTime -Time $st } else { '' }); EndedAt = $(if ($st) { Format-SIDataSqlTime -Time $st.AddSeconds($dur) } else { '' })
                SolutionVersion = [string]$Item.SolutionVersion } 'nonquery'
        }
    }
    $cid = [int](& $Invoke (Get-SIDataNewCollectionSql) @{ CollectionTime = $tText; Kind = 'Detailed'; RunId = $runId; SolutionVersion = [string]$Item.SolutionVersion } 'scalar')
    if ($cid -le 0) { throw ("the collection {0} could not be registered in the database" -f $tText) }

    # ---- findings, a page at a time -------------------------------------------------------------------------------
    # The number of pages comes from the collection's MEASURED size; each page is written to the database before the
    # next one is read (Read-SIDataPages), so the job holds one page -- not the collection, and never several.
    $planned = Get-SIDataPartitionCount -Rows $Item.Rows -Bytes $Item.Bytes
    $keyOf = @{}
    $findingAssets = @{}
    $state = @{ Written = 0L; Resolved = 0L }
    $findingSql = Get-SIDataInsertFindingSql
    $findingKql = {
        param($cuts, $countOnly)
        Get-SIDataFindingsKql -CollectionTime $Item.CollectionTime -EditionMajor $EditionMajor -LookbackDays $LookbackDays -PageFilter (Get-SIDataPageFilter -Cuts $cuts) -CountOnly:([bool]$countOnly)
    }
    $onRows = {
        param($rows)
        # One page. Each row becomes its insert text and is LET GO at once; the texts go to the database a chunk at a
        # time. So what is held is this page's rows not yet stored and one chunk -- never a second copy of the page.
        $items = New-Object System.Collections.Generic.List[string]
        $pending = 0L; $chars = 0L
        for ($ri = 0; $ri -lt $rows.Count; $ri++) {
            $r = $rows[$ri]
            $rows[$ri] = $null
            if ($null -eq $r) { continue }
            $aid = ([string]$r.SI_AssetId).Trim()
            # #297/#298: keyed to the asset that carries the id -- never a second asset for one device
            if ($aid -and $null -ne $Owners) {
                $rs = Resolve-SIDataFindingAssetId -Id $aid -Owners $Owners
                if ($rs.Resolved) { $r.SI_AssetId = $rs.Id; $aid = $rs.Id; $state.Resolved++ }
            }
            # #297: an attack-path row takes its SOURCE asset's tier; the path's TARGET tier never becomes the asset's
            $tiers = Get-SIDataRowTiers -Row $r
            if ($tiers.IsPath -and $r.PSObject.Properties['Tier']) { $r.Tier = $tiers.FindingTier }
            if ($aid) {
                $l = $aid.ToLowerInvariant()
                if (-not $keyOf.ContainsKey($l)) { $keyOf[$l] = (Get-SIDataAssetKey -SIAssetId $aid -Index $Index).Key }
                $t = $tiers.AssetTier
                if (-not $findingAssets.ContainsKey($l)) { $findingAssets[$l] = [pscustomobject]@{ SI_AssetId = $aid; AssetName = [string]$r.AssetName; Tier = $t; SecurityDomain = [string]$r.SecurityDomain } }
                elseif ($null -ne $t -and ($null -eq $findingAssets[$l].Tier -or $t -lt $findingAssets[$l].Tier)) { $findingAssets[$l].Tier = $t }
            }
            $json = ConvertTo-SIDataFindingJson -Row $r -KeyOf $keyOf
            $r = $null
            $items.Add($json)
            $pending += $json.Length + 1; $chars += $json.Length + 1
            # a chunk's worth is ready (the size the database last took in good time): store it and let it go
            $chunkAt = [long]2000000; if ($ChunkChars -and $ChunkChars.Value -gt 0) { $chunkAt = [long]$ChunkChars.Value }
            if ($pending -ge $chunkAt) {
                $state.Written += Write-SIDataJsonRows -Invoke $Invoke -Sql $findingSql -Items $items.ToArray() -Params @{ CollectionId = $cid } -ChunkChars $ChunkChars -What ('findings of ' + $tText)
                $items.Clear(); $pending = 0L
            }
        }
        if ($items.Count -gt 0) {
            $state.Written += Write-SIDataJsonRows -Invoke $Invoke -Sql $findingSql -Items $items.ToArray() -Params @{ CollectionId = $cid } -ChunkChars $ChunkChars -What ('findings of ' + $tText)
        }
        $chars
    }
    $read = Read-SIDataPages -Query $Query -KqlOf $findingKql -Pages $planned -OnRows $onRows -What $tText -Log $Log
    $written = $state.Written
    if ($state.Resolved -gt 0) { & $Log 'INFO' ("  {0} finding(s) named their asset by a device id another asset carries -- kept on that asset" -f $state.Resolved) }
    if ($written -ne $Item.Rows) {
        throw ("{0}: Log Analytics held {1} row(s) for this collection but {2} were read -- the collection is NOT loaded (an incomplete copy is never shown as a collection)." -f $tText, $Item.Rows, $written)
    }

    # ---- the CIs ------------------------------------------------------------------------------------------------
    $set = Build-SIDataAssets -Profiles $Profiles -FindingAssets @($findingAssets.Values) -Index $Index -Properties $Properties -SeenAt $Item.CollectionTime
    # #428: every asset kind the findings imply must arrive as CIs of that kind -- else the web app's kind filter shows 0
    $kindCoverage = Get-SIDataKindCoverage -FindingAssets @($findingAssets.Values) -Set $set
    foreach ($dk in @($kindCoverage.Dropped)) { & $Log 'WARN' ("  {0}: findings on {1} {2} asset(s), but 0 CIs of kind {2} were stored -- the web app's '{2}' filter shows none of them" -f $tText, $kindCoverage.Implied[$dk], $dk) }
    if ($kindCoverage.Kindless -gt 0) { & $Log 'WARN' ("  {0}: {1} CI(s) with findings have no asset kind -- no kind filter shows them" -f $tText, $kindCoverage.Kindless) }
    $assetItems = @($set.Assets | ForEach-Object { ConvertTo-SIDataJsonObject -Values ([ordered]@{ AssetKey = $_.AssetKey; AssetName = $_.AssetName; AssetKind = $_.AssetKind
        AssetKinds = $_.AssetKinds; Tier = $_.Tier; KeySource = $_.KeySource; LastSeen = $_.LastSeen; PropertiesJson = $_.PropertiesJson }) })
    $nAssets = Write-SIDataJsonRows -Invoke $Invoke -Sql (Get-SIDataUpsertAssetSql) -Items $assetItems -ChunkChars $ChunkChars -What 'assets'
    $idItems = @($set.Identifiers | ForEach-Object { ConvertTo-SIDataJsonObject -Values ([ordered]@{ AssetKey = $_.AssetKey; IdentifierType = $_.IdentifierType
        IdentifierValue = $_.IdentifierValue; SeenAt = $_.SeenAt }) })
    [void](Write-SIDataJsonRows -Invoke $Invoke -Sql (Get-SIDataUpsertIdentifierSql) -Items $idItems -ChunkChars $ChunkChars -What 'asset identifiers')
    if ($set.Skipped -gt 0) { & $Log 'WARN' ("  {0} identifier(s) are longer than 256 characters and were not stored" -f $set.Skipped) }
    # A finding without a tier on an asset that has one takes the asset's tier -- the pages never show a finding as
    # Unclassified while the Tier board shows its asset in a tier.
    $tierFilled = [int](& $Invoke (Get-SIDataFindingTierFromAssetSql) @{ CollectionId = $cid } 'scalar')
    if ($tierFilled -gt 0) { & $Log 'INFO' ("  {0} finding(s) without a tier took the tier of their asset" -f $tierFilled) }

    # ---- the correlation evidence of these CIs (#299) -------------------------------------------------------------
    # Reporting on the correlation, not the collection: a failure here is said loudly and the collection still loads --
    # its CorrelatedAt stays empty, so the pages say "not computed for this collection" instead of showing a part.
    $evidence = $null; $evidenceError = ''
    if ($EvidenceReady) {
        try {
            $evidence = Invoke-SIDataEvidence -Invoke $Invoke -Set $set -CollectionId $cid -CollectionTime $Item.CollectionTime -Index $Index -EvidenceProfiles $EvidenceProfiles -ChunkChars $ChunkChars -Log $Log
        } catch {
            # #639: said in the run record too (Get-SIDataSyncIssues), never only here
            $evidenceError = $_.Exception.Message
            & $Log 'WARN' ("  {0}: the correlation evidence could not be written ({1}) -- the collection loads without it; the next collection's load computes it." -f $tText, $_.Exception.Message)
        }
    }

    # ---- recommendations in force at that time (Invoke-SIDataLoadRecommendations) ----
    $nRec = Invoke-SIDataLoadRecommendations -Item $Item -Query $Query -Invoke $Invoke -CollectionId $cid -Set $set -AssetOfId $AssetOfId -ChunkChars $ChunkChars -Log $Log

    # ---- #855 W10: each finding's CI lifecycle, BEFORE the collection is marked complete and any aggregate is built from it.
    # A failure leaves the collection unstamped (its findings count as active, as before) and never stops the load.
    try { $null = Invoke-SIDataCiLifecycleStamp -Invoke $Invoke -CollectionId $cid }
    catch { & $Log 'WARN' ("  {0}: the CIs' lifecycle was not stamped on the findings ({1}) -- they count as active until the collection is stamped (the newest one is, on the next run)." -f $tText, $_.Exception.Message) }
    # ---- complete -----------------------------------------------------------------------------------------------
    $done = [int](& $Invoke (Get-SIDataCompleteCollectionSql) @{ CollectionId = $cid; Rows = [int]$written } 'scalar')
    if ($done -ne 1) { throw ("{0}: the collection could not be marked complete -- the database does not hold all {1} row(s)." -f $tText, $written) }
    $daily = [int](& $Invoke (Get-SIDataFindingDailySql) @{ Day = $Item.CollectionTime.ToUniversalTime().ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } 'scalar')
    $clock.Stop()
    $seconds = [long][Math]::Round($clock.Elapsed.TotalSeconds)
    # one plain line per collection: what was loaded, in how many pages, and how long it took
    & $Log 'OK' ("  loaded {0}: {1} row(s) in {2} page(s), {3} second(s) -- {4} asset(s), {5} recommendation(s); {6} daily aggregate row(s) for {7:yyyy-MM-dd}" -f $tText, $written, $read.Pages, $seconds, $nAssets, $nRec, $daily, $Item.CollectionTime)
    [pscustomobject]@{ CollectionId = $cid; CollectionTime = $Item.CollectionTime; Findings = $written; Assets = $nAssets; Recommendations = $nRec; Pages = $read.Pages; Seconds = $seconds; Evidence = $evidence; EvidenceError = $evidenceError; KindCoverage = $kindCoverage }
}

function Test-SIDataOutHoldForStaleFindings {
    <#
        PURE. #881 Must the outputs be held because the findings per CI of the newest collection were NOT stored (the part
        failed, or its read was short) and sidata.CiFinding still holds the previous collection's set? -DataModel: the core's
        DataModel result. $true = hold (nothing is sent from a set that is not the newest -- never a "resolved" or a removal).
        No result at all (the part did not run, e.g. no findings to store) = not held.
    #>
    param($DataModel)
    if ($null -eq $DataModel) { return $false }
    $st = if ($DataModel -is [System.Collections.IDictionary]) { [string]$DataModel['Status'] } elseif ($DataModel.PSObject.Properties['Status']) { [string]$DataModel.Status } else { '' }
    $st -eq 'failed'
}

function Get-SIDataSyncIssues {
    <#
        PURE. #639 (working rule 4): every failure the data sync's core CAUGHT and went on from, as run issues
        (@{ Level = WARNING | FAILED; Text }, SI-RunOutcome.ps1) -- so none of them ends a run 'success':
          WARNING  (#881: a PART that fails never fails the step -- it keeps its last complete result and opens a fix request)
                   the findings per CI of the newest collection were not stored (a failure, a short read, the database not
                   updated: the stored findings per CI are kept as they were, no finding is closed), every other part of the
                   core that failed (view columns, remediations, key figures, summaries, pivots, changes ...);
          WARNING  the v3 model's conveniences and the lifecycle (the findings are stored; nothing was closed), the full asset
                   metadata (each snapshot is kept in Log Analytics and stored by the next run), a collection's correlation
                   evidence (the collection loads; its pages say "not computed for this collection").
        -Result: Invoke-SIDataSyncCore's result.
    #>
    param($Result)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Result) { return }
    $get = { param($o, [string]$n) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { return $o[$n] }; $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } }
    $dm = & $get $Result 'DataModel'
    if ($dm) {
        # #881 A PART THAT FAILS NEVER FAILS THE STEP (owner 2026-10-22: "we cannot loose data (prio 1) but if a report fails,
        # then let it fail so job completes so we can fix issue"): the findings per CI keep what they stored before (the swap
        # never ran; no finding is closed on a short read), so it is a WARNING of the run -- the run's report opens the fix
        # request -- and the job completes. Only the core load still fails the step (a collection not loaded is not shown).
        $part = { param([string]$t) if ($t -match '^the findings per CI') { $t } else { 'the findings per CI: ' + $t } }
        $iss = & $get $dm 'Issues'
        if ($null -ne $iss) { foreach ($i in @($iss)) { if ($i) { $out.Add([pscustomobject]@{ Level = 'WARNING'; Text = $(if ([string]$i.Level -eq 'FAILED') { (& $part ([string]$i.Text)) + ' -- this part failed; the stored findings per CI are kept as they were' } else { [string]$i.Text }) }) } } }
        elseif ([string](& $get $dm 'Status') -eq 'failed') { $out.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the findings per CI of the newest collection were not stored -- {0} -- this part failed; the stored findings per CI are kept as they were, no finding was closed' -f [string](& $get $dm 'Error')) }) }
    }
    # #881 every other PART of the data sync that failed this run keeps its last complete result (each part replaces its set
    # in one step at its end, or keeps a mark the next run goes on from); its pages show that, and the run says it -- a
    # WARNING that opens a fix request. Never a stop: the other parts and the job complete.
    # #904: every part of the result that can fail (the same map Get-SIDataSyncPartFailures reports to Invardia)
    $parts = $script:SIDataSyncParts
    foreach ($k in $parts.Keys) {
        if ($k -in @('DataModel', 'AssetMetadata')) { continue }
        $p = & $get $Result $k
        if ($p -and [string](& $get $p 'Status') -eq 'failed') {
            $out.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('{0} were not built this run ({1}) -- this part failed; its pages show the last complete result and the next run builds it' -f $parts[$k].Name, [string](& $get $p 'Error')) })
        }
    }
    $am = & $get $Result 'AssetMetadata'
    if ($am -and [string](& $get $am 'Status') -eq 'failed') {
        $out.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the full asset metadata was not stored this run ({0}) -- its snapshots stay in Log Analytics and the next run stores them' -f [string](& $get $am 'Error')) })
    }
    foreach ($l in @(& $get $Result 'Loaded')) {
        if (-not $l) { continue }
        $ee = [string](& $get $l 'EvidenceError')
        if ($ee) {
            $t = & $get $l 'CollectionTime'
            $tt = if ($t -is [datetime]) { $t.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { [string]$t }
            $out.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the correlation evidence of the collection of {0} was not written ({1}) -- the collection is loaded; its evidence shows "not computed"' -f $tt, $ee) })
        }
        # per report: a report the run could not complete is a WARNING on that report, never a hold on the run
        $ir = [string](& $get $l 'IncompleteText')
        if ($ir) {
            $t = & $get $l 'CollectionTime'
            $tt = if ($t -is [datetime]) { $t.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { [string]$t }
            $out.Add([pscustomobject]@{ Level = 'WARNING'; Text = ('the collection of {0} is loaded; report(s) that could not be completed show their last complete result and close nothing: {1}' -f $tt, $ir) })
        }
    }
    # one issue per item: @(Get-SIDataSyncIssues ...) counts the issues
    $out.ToArray()
}

function Get-SIDataSyncPartFailures {
    <#
        PURE. #904: every PART of the data sync that failed this run (-Result: Invoke-SIDataSyncCore's result), most severe
        first: @(@{ Part; Step; Name; Error; ErrorClass }) -- Step = the part's id ($script:SIDataSyncParts), ErrorClass =
        'database-full' when Azure SQL refused it for the database's size quota (1105 / 40544 / "reached its size quota"), else
        the class of its own error (Get-SIErrorClass; 'unknown' when that is not loaded). A full database comes first: it is
        the cause of the others.
    #>
    param($Result)
    if ($null -eq $Result) { return @() }
    $get = { param($o, [string]$n) if ($null -eq $o) { return $null }; if ($o -is [System.Collections.IDictionary]) { return $o[$n] }; $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } }
    $full = New-Object System.Collections.Generic.List[object]; $rest = New-Object System.Collections.Generic.List[object]
    foreach ($k in $script:SIDataSyncParts.Keys) {
        $p = & $get $Result $k
        if (-not $p -or [string](& $get $p 'Status') -ne 'failed') { continue }
        $err = [string](& $get $p 'Error'); if (-not $err) { $err = [string](& $get $p 'Text') }
        $cls = if ((Get-Command -Name Test-SIDatabaseFullError -ErrorAction SilentlyContinue) -and (Test-SIDatabaseFullError $err)) { 'database-full' }
               elseif ("$err" -match '(?i)has reached its size quota|filegroup is full|\b(1105|40544)\b') { 'database-full' }
               elseif (Get-Command -Name Get-SIErrorClass -ErrorAction SilentlyContinue) { Get-SIErrorClass -Message $err -Service 'sql' }
               else { 'unknown' }
        $f = [pscustomobject]@{ Part = $k; Step = [string]$script:SIDataSyncParts[$k].Step; Name = [string]$script:SIDataSyncParts[$k].Name; Error = $err; ErrorClass = $cls }
        if ($cls -eq 'database-full') { $full.Add($f) } else { $rest.Add($f) }
    }
    @($full.ToArray()) + @($rest.ToArray())
}

function Get-SIDataSyncPartFailureText {
    <# PURE. #904: the run record's words for the failed parts: "PART FAILED <step> (<class>): <name> -- <error>", one per part. #>
    param([object[]]$Failures)
    @(@($Failures) | Where-Object { $_ } | ForEach-Object {
        $e = ([string]$_.Error -split "`n")[0].Trim(); if ($e.Length -gt 300) { $e = $e.Substring(0, 297) + '...' }
        'PART FAILED {0} ({1}): {2} -- {3}' -f $_.Step, $_.ErrorClass, $_.Name, $e })
}

function Send-SIDataSyncPartFailures {
    <#
        #904: each failed part (-Failures: Get-SIDataSyncPartFailures, at most -Max, the most severe first) to Invardia through
        the existing failure uplink (Send-SITelemetryFailure -Job datasync): FailedStep = the part, ErrorClass its class,
        Outcome warning (the job completed -- -Partial). A part that failed on a FULL database carries the catalogue code
        si-data-1404 (opensTicket: a ticket for support). -Send { param($Failure, $Code) } is the test seam (default:
        Send-SITelemetryFailure). Never throws; returns what was sent: @(@{ Step; ErrorClass; Code; Status }).
    #>
    param([object[]]$Failures, [int]$Max = 5, [scriptblock]$Send, $StartedAt)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(@($Failures) | Where-Object { $_ } | Select-Object -First $Max)) {
        $code = if ([string]$f.ErrorClass -eq 'database-full') { 'si-data-1404' } else { '' }
        $st = 'not-sent'
        try {
            if ($Send) { $r = & $Send $f $code; $st = if ($r -and $r.PSObject.Properties['Status']) { [string]$r.Status } else { 'sent' } }
            elseif (Get-Command -Name Send-SITelemetryFailure -ErrorAction SilentlyContinue) {
                $a = @{ Job = 'datasync'; Step = [string]$f.Step; ErrorMessage = ('{0} failed: {1}' -f $f.Name, $f.Error); ErrorClass = [string]$f.ErrorClass; Partial = $true }
                if ($code) { $a.Code = $code }
                if ($StartedAt) { $a.StartedAt = $StartedAt }
                $r = Send-SITelemetryFailure @a
                $st = if ($r -and $r.PSObject.Properties['Status']) { [string]$r.Status } else { 'unknown' }
            } else { $st = 'no-telemetry-client' }
        } catch { $st = 'error' }
        $out.Add([pscustomobject]@{ Step = [string]$f.Step; ErrorClass = [string]$f.ErrorClass; Code = $code; Status = $st })
    }
    $out.ToArray()
}
