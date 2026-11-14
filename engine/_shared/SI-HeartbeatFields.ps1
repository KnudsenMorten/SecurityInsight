#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE REMAINING TELEMETRY FIELDS ON THE HOURLY HEARTBEAT (#719; owner 2026-10-16 via Invardia: "i want
    data"). Eight optional fields of the identified heartbeat that caj-si-heartbeat sends every hour (SI-HeartbeatJob.ps1,
    Send-SIHeartbeatTick), each in EXACTLY the shape agreed with Invardia (validator live in Invardia 1.0.500, 2026-10-16):

      Pipeline  { runId, state, startedUtc, step, stepSinceUtc, lastEndedUtc, nextStartUtc }
                state running | idle | failed | succeeded -- the newest run record (cfg.FlowRun / cfg.FlowStepRun); nextStartUtc
                from the stored pipeline (cfg.JobFlow) by the runner's own rule (Get-SIJobFlowDue)
                + THE PROGRESS AND ESTIMATED END (owner 2026-10-17: "give completion estimate of all env from last pipeline and
                show est completion"), its own switch SI_Uplink_SendPipelineEta (default ON on every ring):
                { stepsDone, stepsTotal, runningSteps[<= 12] { step, sinceUtc, prevMin, endUtc, estimate [, lastProgressUtc]
                [, progress] -- #1180, Invardia 452cb22c: the step's own progress record, each key only when known }, remainingSteps[<= 30]
                { step, group, estimateMin }, estimatedEndUtc, estimateConfidence, queuedRuns } (Get-SIPipelineEta: each step's
                estimate = its job's duration in the newest succeeded run; the steps of one group run together, so a group
                takes as long as its longest step). Invardia refusing these keys (4xx) = the heartbeat is sent again once with
                Pipeline WITHOUT them (Send-SIHeartbeatTick), so they never cost the rest of the record.
                + housekeepingRowsLeft (the LAST key when known, agreed with Invardia 2026-10-24): the rows of retired
                collections still waiting to be removed, index reads only (Get-SIHeartbeatHousekeepingSql); unknown = absent.
      Jobs      [<= 30] { name, lastStartUtc, lastEndUtc, lastResult, durationMin, prevDurationMin, cpu, memoryGi, timeoutHours }
                lastResult succeeded | failed | stopped | running -- the pipeline's steps from the last 10 run records; the jobs
                that are never a step (updater, heartbeat, config backup) from their Container Apps executions; cpu / memory /
                run limit from ONE list of the install's jobs
      Sources   [<= 10] { source, lastGoodUtc, lastErrorCode, retries24h, throttled24h, lagMin }
                source defender | graph | azure | exposureGraph | logAnalytics -- from run health (SI_RunHealth_CL, ONE query);
                lastErrorCode = SecurityInsight's error class (the closed list of SI-ErrorClass.ps1); lagMin = the ingestion lag
                of SI's own run-health rows (logAnalytics only)
      Database  { tier, dtu, maxSizeMb, usedMb, peakLogWritePct1h, minutesAtLimit1h } -- the Pro database from ARM + ONE
                metrics read; #904 (owner 2026-10-27): maxSizeMb / usedMb = the same cheap read as Counts.sqlMaxMb / sqlUsedMb
                (sys.database_files FILEPROPERTY SpaceUsed + DATABASEPROPERTYEX MaxSizeInBytes), taken from the Counts when
                they carry it -- a full database is seen before a write fails (Warnings si-data-1403 at 85 %)
                + #1210 (Invardia SQL-STATS-PROOF, its check PERF-01) EXACTLY three keys after the six: statsAsync, statsStalePct,
                statsRefreshedUtc -- ONE catalog read of the data database (Get-SIHeartbeatDatabaseStatsSql) and cfg.InstallState
                'StatisticsRefresh' (written by the pipeline's statistics refresh); a failed read leaves the three out
      Update    { installed, available, lastUpdaterRunUtc, lastUpdaterResult, nextUpdateUtc }
                lastUpdaterResult succeeded | failed | nothing-to-do -- cfg.InstallState 'UpdateState' + the updater's timer
      Mail      { mailJob, lastSentUtc, lastFailedUtc, lastErrorCode, restriction, queued }
                mailJob present | missing; restriction verified | not-verified | failed -- the two mail outboxes
                (cfg.ExemptionMail, cfg.SignInMail), cfg.InstallState 'MailRestriction', the mail step's records, the job by name
      Warnings  [<= 20] { code, sinceUtc } -- code ONLY from data-model/errors.locked.json (si-<area>-<nnnn>): the customer
                actions SecurityInsight already detects (Get-SIHeartbeatWarnings)
      Security  { collectionUtc, domains[<= 4] { domain, reports, reportsComplete, findings, findingsCritical, findingsHigh,
                impactedAssets, detailedRows, cveDevicePairs, cveDevices, missingCves, recommendations, recommendationPairs } }
                domain endpoint | identity | azure | publicip -- the latest COMPLETE Risk Analysis collections
                (sidata.RaReportStatus + sidata.SummaryRow of ONE Summary collection) and the #719 Counts keys; never
                sidata.Finding; a domain without a complete report is left out; partial = reportsComplete < reports
      Published { collectionId, collectionUtc, publishedUtc, copiedUtc, newestCompleteUtc } (2026-10-26, Invardia 1.0.593): the
                collection customers SEE (sidata.PublishedRun 'current') next to the newest complete one; left out when nothing is
                published yet. Its own switch; auto = ring 0 first (ConfirmedRings).
      DataOut   [<= 10, unique by output] { output, phase, batchId, startedUtc, rowsPlanned, rowsSent, rowsHeld, rowsPerSec,
                lastProgressUtc, stalled, lastEndedUtc, lastResult, lastErrorCode, heldReason } (#1043, AGREED with Invardia
                2026-11-01): one entry per data-out output, running or last finished -- from cfg.DataOutBatch (the progress the
                writer records there, batched) and cfg.ConnectorRun (the newest run of each data-out connector), ONE read when
                the heartbeat is built; nothing is added to the send. output + phase (read | build | send | close | readback |
                idle | held | failed) required; every other value soft (null when not known). lastResult complete | partial |
                held | failed; lastErrorCode only a catalogue code (si-snow-1301 for a ServiceNow output held by its check), else
                null; heldReason column-too-long | mapping | connection | auth | other -- never free text. Read = ONE array, an
                empty one too (no outputs). Its own switch; auto = ring 0 first (ConfirmedRings).
                #1188 (3.1.2): rowsHeld is the REAL holds only -- a row sent with u_action held because its finding is not in
                this run is kept open, not held, and is counted in cfg.DataOutBatch.KeptOpenRows. Its own key (rowsKeptOpen) is
                sent as the LAST key of each entry, a whole number (null when not known), behind DataOutSendKeptOpen = $true
                (Invardia accepts it since its deploy b03e7e72, 2026-11-11).
                #1237 (Invardia's wire contract 2026-11-13, "a held install must never go quiet"): an output whose newest
                attempt was held because the collection is not trusted (the data sync's record cfg.InstallState
                'DataOutTrust') reads phase / lastResult 'held', heldReason 'untrusted', + the SOFT keys heldSinceUtc /
                newestTrustedUtc after the others, each only when known -- behind DataOutSendTrustHold = $true.
      BuildPool { tier, count, building, checkedUtc } (framework rule 11g, 2026-11-05): a PRIVATE install's image build pool --
                tier as Azure names it (S2), its agents now (0 between builds), building = a run of the registry is Queued /
                Started / Running. Only an install with an agent pool sends it. NOT YET CONFIRMED by Invardia (its wire contract
                is closed: an unknown key drops the heartbeat): CONFIRMED live by Invardia 2026-11-05 (1a3a21c3) -- every ring;
                its own switch SI_Uplink_SendBuildPool 'off' turns it off.
      UplinkBacklog { pending, oldestUtc, checkedUtc } (framework 8.4, agreed with Invardia 2026-11-05): the run reports kept
                unsent in the install's outbox (cfg.UplinkOutbox, SI-UplinkOutbox.ps1) -- pending = how many (whole number >= 0),
                oldestUtc = when the oldest was kept (null when none), checkedUtc = when this was read (ALWAYS set: Invardia drops
                the field without it). EXACTLY these three keys. Caught up = pending 0 / oldestUtc null -- a value, never left
                out as "empty". Invardia judges "more than one cycle behind" from oldestUtc. Only an install with the Pro
                database sends it. DEPLOYED by Invardia 2026-11-05 (f0f2403b; its wire contract is closed): ON on every
                ring; its own switch SI_Uplink_SendUplinkBacklog 'off' turns it off.

    THE RULES (the same as Collections, #718):
      * identified heartbeats only; each field behind ITS OWN switch (SI_Uplink_Send<Field>, job variable
        SI_UPLINK_SEND<FIELD>): on / off / a ring list / auto = the rings in ConfirmedRings (every ring, 0-3,
        since 2026-10-17). REMOVE-ME (#719): once every install sends them, drop the switches ('off' still turns a field off).
      * values: the closed lists EXACTLY as written; times ISO-8601 UTC or null; counts whole numbers >= 0 or null; NO free
        text in Pipeline..Warnings. Every value is checked against the agreed schema (Test-SIHeartbeatField) before it goes
        on the record -- a value that does not pass is left out, never sent half-right.
      * each field is read in its OWN try: a field that cannot be read is left out, never the heartbeat.
      * cheap: index reads on the two databases, ONE Container Apps job list (+ the executions of the at most three jobs that
        are never a step), ONE database GET + ONE metrics read, ONE Log Analytics query per tick.
      * the identified heartbeat stays under 48 KB: over it, fields are dropped in a fixed order (Get-SIHeartbeatFieldDropOrder)
        and that is said once.
      * a heartbeat Invardia refuses WITH them is sent again once WITHOUT them (Get-SITelemetryOptionalFields).

    PS 5.1 and 7. No PowerShell modules. A test session never reads a database, ARM or Log Analytics (every reader is a seam).
#>

if (-not (Get-Command -Name Get-SIErrorClass -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-ErrorClass.ps1')) }
if (-not (Get-Command -Name Get-SIErrorCatalogue -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-UplinkCauses.ps1')) }
if (-not (Get-Command -Name Get-SIJobFlowDue -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-JobFlow.ps1')) }
# framework 8.4: UplinkBacklog -- the run reports kept unsent in the outbox
if (-not (Get-Command -Name ConvertTo-SIUplinkBacklog -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-UplinkOutbox.ps1')) }

$script:SIHeartbeatFields = @{
    # the fields in the order they go on the record (Published: 2026-10-26, agreed with Invardia -- what customers see)
    Names            = @('Pipeline', 'Jobs', 'Sources', 'Database', 'Update', 'Mail', 'Warnings', 'Security', 'Published', 'DataOut', 'BuildPool', 'UplinkBacklog')
    # REMOVE-ME (#719): the rings whose heartbeat carries each field while its switch is 'auto' -- EVERY ring since 2026-10-17
    # (Invardia's validator has taken the eight fields since its migration 118; owner: "i want data" / "i need to see it in my
    # backend via telemetry"). SI_Uplink_Send<Field> 'off' still turns a field off per install; then drop the switches.
    ConfirmedRings   = @{ Pipeline = @(0, 1, 2, 3); Jobs = @(0, 1, 2, 3); Sources = @(0, 1, 2, 3); Database = @(0, 1, 2, 3); Update = @(0, 1, 2, 3); Mail = @(0, 1, 2, 3); Warnings = @(0, 1, 2, 3); Security = @(0, 1, 2, 3)
                         # REMOVE-ME (2026-10-26): Published -- Invardia's validator takes it since 1.0.593 (07f7aa4); RING 0 FIRST,
                         # the other rings once ring 0's first value is checked. SI_Uplink_SendPublished 'off' still turns it off.
                         Published = @(0)
                         # REMOVE-ME (#1043, 2026-11-01): DataOut -- agreed with Invardia, which deploys its side first; RING 0 FIRST;
                         # the other rings once ring 0's first value is checked.
                         # SI_Uplink_SendDataOut 'on' / a ring list sends it earlier, 'off' turns it off.
                         # 2026-11-02: ring 0's value checked by Invardia (an empty list -- no data-out output there); ring 1
                         # (the pilot, the first real entries) on Invardia's ask
                         DataOut = @(0, 1)
                         # REMOVE-ME (framework rule 11g, 2026-11-05): BuildPool { tier, count, building, checkedUtc } -- a private
                         # install's image build pool. Invardia's wire contract is CLOSED (an unknown key drops the heartbeat), so it
                         # Invardia confirmed it live 2026-11-05 (1a3a21c3): every ring. Only an install that HAS an agent pool sends it.
                         BuildPool = @(0, 1, 2, 3)
                         # REMOVE-ME (framework 8.4, 2026-11-05): UplinkBacklog { pending, oldestUtc, checkedUtc } -- the run reports kept
                         # unsent. Invardia's wire contract is CLOSED (an unknown key has dropped whole heartbeats); Invardia DEPLOYED
                         # the field 2026-11-05 (f0f2403b): every ring. SI_Uplink_SendUplinkBacklog 'off' still turns it off per install.
                         UplinkBacklog = @(0, 1, 2, 3) }
    # over the size limit the fields go in THIS order (the least needed first); Collections (#718) is in the list too
    DropOrder        = @('Jobs', 'BuildPool', 'Security', 'DataOut', 'Sources', 'Collections', 'Database', 'Mail', 'Update', 'Published', 'UplinkBacklog', 'Warnings', 'Pipeline')
    # framework rule 11g: the ACR tiers an agent pool can have; the registry and its runs are read with these api-versions
    BuildPoolTiers   = @('S1', 'S2', 'S3', 'I6')
    ArmAcrApi        = '2023-07-01'
    ArmAcrTasksApi   = '2019-06-01-preview'
    BuildPoolActiveRuns = @('Queued', 'Started', 'Running')
    MaxBytes         = 48 * 1024
    # framework 8.4: Invardia's cap on UplinkBacklog.pending (its heartbeat state contract)
    UplinkBacklogMax = 1000000
    # the closed lists and caps agreed with Invardia (2026-10-16)
    PipelineStates   = @('running', 'idle', 'failed', 'succeeded')
    # #1035 (2026-11-01): a run that was STOPPED or CANCELLED before its end reads 'stopped' -- NOT YET AGREED with Invardia,
    # so behind its own switch SI_Uplink_SendPipelineStopped, OFF on every ring (auto = PipelineStoppedRings, none). While
    # it is off such a run reads 'idle'; a heartbeat Invardia refuses with 'stopped' is sent again with 'idle'.
    # REMOVE-ME once Invardia takes it: move 'stopped' into PipelineStates and drop the switch.
    PipelineStoppedState = 'stopped'
    PipelineStoppedRings = @()
    # the run states a stopped run ends in (SI-JobFlow: RunFinished minus Succeeded / Failed)
    PipelineStoppedRunStates = @('Stopped', 'Cancelled')
    JobResults       = @('succeeded', 'failed', 'stopped', 'running')
    Sources          = @('defender', 'graph', 'azure', 'exposureGraph', 'logAnalytics')
    UpdateResults    = @('succeeded', 'failed', 'nothing-to-do')
    MailJobStates    = @('present', 'missing')
    MailRestrictions = @('verified', 'not-verified', 'failed')
    Domains          = @('endpoint', 'identity', 'azure', 'publicip')
    MaxJobs = 30; MaxSources = 10; MaxWarnings = 20; MaxDomains = 4
    # #1043 DataOut (agreed with Invardia 2026-11-01): the closed lists, the caps, the stall rule
    DataOutPhases      = @('read', 'build', 'send', 'close', 'readback', 'idle', 'held', 'failed')
    DataOutRunPhases   = @('readback', 'read', 'build', 'send', 'close')
    DataOutResults     = @('complete', 'partial', 'held', 'failed')
    # #1237 (Invardia's wire contract, 2026-11-13): 'untrusted' = the newest attempt was held because the collection is not trusted
    DataOutHeldReasons = @('column-too-long', 'mapping', 'connection', 'auth', 'other', 'untrusted')
    MaxDataOut = 10; DataOutStallMinutes = 10
    # #1237 (Invardia 2026-11-13: "a held install must never go quiet"): an output whose newest data-out attempt was HELD because
    # the collection is not trusted (the data sync's record, cfg.InstallState 'DataOutTrust') reads phase / lastResult 'held',
    # heldReason 'untrusted', + two SOFT keys after the others, each only when known (never null): heldSinceUtc = the first run
    # of the current row of held runs, newestTrustedUtc = the CollectionTime of the newest trusted collection. Invardia raises a
    # LASTING hold itself from the two. >>> THE SWITCH: DataOutSendTrustHold ($false = the entries as before 3.1.16).
    DataOutTrustHeldReason = 'untrusted'
    DataOutTrustFields     = @('heldSinceUtc', 'newestTrustedUtc')
    DataOutSendTrustHold   = $true
    # the catalogue code of a ServiceNow output held by its check (data-model/errors.locked.json); every other result: null
    DataOutSnowHeldCode = 'si-snow-1301'
    # #1188 (owner 2026-11-11; Invardia 2026-11-11 asked for it): rowsHeld counts ONLY the real holds since 3.1.2 -- the rows
    # sent with u_action 'held' because their finding is not in this run are KEPT OPEN (cfg.DataOutBatch.KeptOpenRows), not
    # held. Their own count -- rowsKeptOpen, an integer per DataOut entry (the name Invardia accepted 2026-11-11, beside
    # rowsPlanned / rowsSent / rowsHeld) -- is SENT: Invardia's wire contract is CLOSED (an unknown key can drop the whole
    # heartbeat), and its backend accepts rowsKeptOpen since its deploy b03e7e72 (live 2026-11-11).
    # >>> THE SWITCH (#1188): DataOutSendKeptOpen. $true = the agreed fourteen keys + rowsKeptOpen (the last key); $false = the
    # >>> fourteen only (a fallback should Invardia ever refuse the key). The ONLY place to change.
    DataOutKeptOpenField = 'rowsKeptOpen'
    DataOutSendKeptOpen  = $true
    # the pipeline's progress and estimated end -- extra keys of Pipeline, after its agreed seven, behind their own switch
    # (SI_Uplink_SendPipelineEta). ON by default on every ring (owner 2026-10-17); a refusal resends Pipeline without them.
    PipelineEtaFields   = @('stepsDone', 'stepsTotal', 'runningSteps', 'remainingSteps', 'estimatedEndUtc', 'estimateConfidence', 'queuedRuns')
    RunningStepFields   = @('step', 'sinceUtc', 'prevMin', 'endUtc', 'estimate')
    # #1180 (Invardia 452cb22c, 2026-11-11): two OPTIONAL keys of a running step, after the five, in this order, each only when
    # known (never null, never empty): lastProgressUtc = when the step's own progress record last moved (never in the
    # future); progress = what it has done, in words ("batch 161 of 266"), at most 80 characters of RunningStepProgressChars
    RunningStepOptionalFields = @('lastProgressUtc', 'progress')
    RunningStepProgressMax    = 80
    RunningStepProgressChars  = 'A-Za-z0-9 .,:%()/_-'
    RemainingStepFields = @('step', 'group', 'estimateMin')
    StepEstimates       = @('known', 'overdue', 'unknown')
    EtaConfidences      = @('known', 'partial', 'overdue')
    MaxRunningSteps = 12; MaxRemainingSteps = 30
    PipelineEtaRings    = @(0, 1, 2, 3)
    # the rows of retired collections still waiting to be removed (agreed with Invardia 2026-10-24: no database-load ticket
    # while it is > 0) -- the LAST key of Pipeline when known (Get-SIHeartbeatHousekeepingRowsLeft); absent = not known
    PipelineHousekeepingField = 'housekeepingRowsLeft'
    # 2026-10-29 (owner): the running steps far past their last run's time with no progress -- an optional key of Pipeline after
    # the progress keys and before housekeepingRowsLeft, present only when there is one; a refusal resends Pipeline without it
    PipelineStalledField = 'stalledSteps'
    StalledStepFields    = @('step', 'sinceUtc', 'lastProgressUtc')
    MaxStalledSteps      = 12
    Fields = @{
        Pipeline = @('runId', 'state', 'startedUtc', 'step', 'stepSinceUtc', 'lastEndedUtc', 'nextStartUtc')
        Jobs     = @('name', 'lastStartUtc', 'lastEndUtc', 'lastResult', 'durationMin', 'prevDurationMin', 'cpu', 'memoryGi', 'timeoutHours')
        Sources  = @('source', 'lastGoodUtc', 'lastErrorCode', 'retries24h', 'throttled24h', 'lagMin')
        Database = @('tier', 'dtu', 'maxSizeMb', 'usedMb', 'peakLogWritePct1h', 'minutesAtLimit1h')
        Update   = @('installed', 'available', 'lastUpdaterRunUtc', 'lastUpdaterResult', 'nextUpdateUtc')
        Mail     = @('mailJob', 'lastSentUtc', 'lastFailedUtc', 'lastErrorCode', 'restriction', 'queued')
        Warnings = @('code', 'sinceUtc')
        Security = @('collectionUtc', 'domains')
        Published = @('collectionId', 'collectionUtc', 'publishedUtc', 'copiedUtc', 'newestCompleteUtc')
        DataOut  = @('output', 'phase', 'batchId', 'startedUtc', 'rowsPlanned', 'rowsSent', 'rowsHeld', 'rowsPerSec', 'lastProgressUtc', 'stalled',
                     'lastEndedUtc', 'lastResult', 'lastErrorCode', 'heldReason')
        BuildPool = @('tier', 'count', 'building', 'checkedUtc')
        UplinkBacklog = @('pending', 'oldestUtc', 'checkedUtc')
        Domain   = @('domain', 'reports', 'reportsComplete', 'findings', 'findingsCritical', 'findingsHigh', 'impactedAssets', 'detailedRows',
                     'cveDevicePairs', 'cveDevices', 'missingCves', 'recommendations', 'recommendationPairs')
    }
    # the runs read for Jobs (the newest N run records and their steps -- by the FlowRun index and the step primary key)
    RunsRead         = 10
    ExecutionPages   = 3
    ArmJobsApi       = '2025-07-01'
    ArmSqlApi        = '2021-11-01'
    ArmMetricsApi    = '2023-10-01'
    MailJob          = 'caj-si-close-loop-mail'
    # a metric minute at or above this is "at the limit"
    LimitPct         = 99
    # which collection engine reads which source (run health names the engine, not the source)
    EngineSources    = @{ 'identity' = @('graph', 'exposureGraph', 'azure'); 'endpoint' = @('defender', 'graph', 'exposureGraph'); 'azure' = @('azure')
                          'publicip' = @('azure'); 'privilege-tier-classifier' = @('graph', 'azure'); 'risk-analysis' = @('logAnalytics', 'defender')
                          'asset-correlation' = @('logAnalytics'); 'correlation' = @('logAnalytics') }
    # the source an error text names (first match wins: the Exposure Graph and Defender are both reached through Graph)
    SourcePatterns   = [ordered]@{ exposureGraph = '(?i)exposure\s*graph|exposuregraph'
                                   defender      = '(?i)api\.security\.microsoft\.com|securitycenter|runhuntingquery|advanced hunting|\bdefender\b'
                                   graph         = '(?i)graph\.microsoft\.com|microsoft graph'
                                   azure         = '(?i)management\.azure\.com|resource\s*graph|azure resource manager'
                                   logAnalytics  = '(?i)api\.loganalytics|log analytics|ods\.opinsights|ingestion' }
    ClassSources     = @{ 'graph-401' = 'graph'; 'graph-403' = 'graph'; 'defender-403' = 'defender'; 'arm-403' = 'azure' }
    # the report families of each security domain (Attack_Paths_* reports cross domains -- they are Counts.attackPaths)
    DomainPrefixes   = [ordered]@{ endpoint = @('Device_', 'Endpoint_'); identity = @('Identity_'); azure = @('Azure_'); publicip = @('PublicIP_') }
    # the customer-action codes of data-model/errors.locked.json this file can raise
    WarningCodes     = @{ SecretHandover = 'si-upd-0801'; UpdaterDatabase = 'si-upd-0802'; GraphPermission = 'si-perm-1001'; DefenderPermission = 'si-perm-1002'
                          AzurePermission = 'si-perm-1003'; ScoresPermission = 'si-perm-1004'; MailUnrestricted = 'si-mail-1101'; MailNotGranted = 'si-mail-1102'; MailNotVerified = 'si-mail-1103'
                          # #732: the pipeline runner (caj-si-flow) has no timer -- the pipeline never starts by itself
                          FlowRunnerNotScheduled = 'si-flow-1201'
                          # a ServiceNow output's newest check failed (connection, table, columns or column mapping): its push is held
                          ServiceNowCheckFailed = 'si-snow-1301'
                          # the merged assets' pages show a copy older than the run the web app shows (sidata.PublishedRun CopiedAt < PublishedAt)
                          PublishedCopyStale = 'si-data-1401'
                          # #871: the newest complete Risk Analysis collection has no groupings yet -- the report figures go out
                          # from the newest collection that has them, with its date (Security.collectionUtc)
                          FiguresFromEarlierCollection = 'si-data-1402'
                          # 2026-10-23: an update has waited more than 24 hours for a pipeline run to end (warning only)
                          UpdateWaitsLong = 'si-upd-0806'
                          # 2026-10-25: a scheduled collection waited for or skipped a pipeline run (information only)
                          CollectionHeld = 'si-flow-1202'
                          # 2026-10-26: the run going on, or one of its steps, has run much longer than usual here (warning only)
                          RunMuchLonger = 'si-flow-1203'
                          # 2026-10-29: a running step far past its last run's time that shows no progress (warning only)
                          StepStalled = 'si-flow-1204'
                          # #1096: an execution of a pipeline step's job belonged to no pipeline run and to no person's start (warning only)
                          RanOutsidePipeline = 'si-flow-1205'
                          # #904: the database uses DatabaseNearFullPct % or more of its maximum size (Database usedMb / maxSizeMb)
                          DatabaseNearFull = 'si-data-1403'
                          # 2026-11-10: the clean-up of old data cannot finish before the next run at the pace the database's load
                          # allows (cfg.InstallState 'Housekeeping' behind) -- support is told (the ticket)
                          HousekeepingBehind = 'si-data-1405' }
    # #904: a database at or above this share of its maximum size is said (Warnings si-data-1403) before a write fails
    DatabaseNearFullPct = 85
    # #1210 (Invardia contract SQL-STATS-PROOF, framework §12.27 point 5; its check PERF-01): Database carries EXACTLY these
    # three keys after its agreed six, in this order -- statsAsync (bool: AUTO_UPDATE_STATISTICS_ASYNC on), statsStalePct
    # (0-100: the share of the user tables' statistics whose changes exceed DatabaseStatsStalePct % of the rows +
    # DatabaseStatsStaleRows), statsRefreshedUtc (the last statistics refresh SI ran after its writes, cfg.InstallState
    # 'StatisticsRefresh'; null = none recorded yet). ONE read of the database per heartbeat; a read that fails leaves the
    # three out (and adds no other key). Invardia's wire contract is CLOSED: never another key here.
    # >>> THE SWITCH: DatabaseSendStats. $false = the agreed six only (a fallback should Invardia ever refuse the keys).
    DatabaseStatsFields   = @('statsAsync', 'statsStalePct', 'statsRefreshedUtc')
    DatabaseSendStats     = $true
    DatabaseStatsStalePct = 20
    DatabaseStatsStaleRows = 500
    DatabaseStatsState    = 'StatisticsRefresh'
    # 2026-10-23: an update that waits for a pipeline run longer than this is a warning (it never cancels and never blocks)
    UpdateWaitsWarnHours = 24
    # 2026-10-25: a scheduled collection held back by a pipeline run is said for this long after it (cfg.InstallState 'CollectionHeld')
    CollectionHeldHours = 24
    # #1096: the verification job's pipeline check (cfg.InstallState 'OutsidePipeline') is said while it is at most this old
    OutsidePipelineHours = 30
    # 2026-11-10: the clean-up's progress (cfg.InstallState 'Housekeeping', written by every wake-up of the runner) is read while
    # it is at most this old -- a runner that no longer wakes has its own warning (si-flow-1201)
    HousekeepingRecordHours = 24
}

function Get-SIHeartbeatFieldsContract { $script:SIHeartbeatFields }
function Get-SIHeartbeatFieldDropOrder { @($script:SIHeartbeatFields.DropOrder) }

# =====================================================================================================================
#  The switches -- PURE (Resolve-SIUplinkFieldSwitch, SI-HeartbeatJob.ps1)
# =====================================================================================================================
function Resolve-SIUplinkHeartbeatFieldSwitch {
    <# PURE. Does the field -Field go out from this install? SI_Uplink_Send<Field> (setting) > SI_UPLINK_SEND<FIELD> (job
       variable) > auto (the field's ConfirmedRings). -Value / -EnvValue override the reads (tests). #>
    param([Parameter(Mandatory)][string]$Field, [AllowNull()]$Ring, $Value = '__read__', $EnvValue = '__read__', [int[]]$ConfirmedRings)
    if ($script:SIHeartbeatFields.Names -cnotcontains $Field) { throw "not a heartbeat field: $Field" }
    $setting = 'SI_Uplink_Send' + $Field
    if ("$Value" -eq '__read__') { $Value = Get-Variable -Name $setting -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
    if ("$EnvValue" -eq '__read__') { $EnvValue = [Environment]::GetEnvironmentVariable($setting.ToUpperInvariant()) }
    if (-not $PSBoundParameters.ContainsKey('ConfirmedRings')) { $ConfirmedRings = @($script:SIHeartbeatFields.ConfirmedRings[$Field]) }
    Resolve-SIUplinkFieldSwitch -Name $setting -Value $Value -EnvValue ([string]$EnvValue) -Ring $Ring -ConfirmedRings $ConfirmedRings
}

function Resolve-SIUplinkPipelineEtaSwitch {
    <# PURE. Does Pipeline carry the progress and estimated end? SI_Uplink_SendPipelineEta (setting) > SI_UPLINK_SENDPIPELINEETA
       (job variable) > auto = on for every ring (owner 2026-10-17: on by default). Only where Pipeline itself goes out. #>
    param([AllowNull()]$Ring, $Value = '__read__', $EnvValue = '__read__', [int[]]$ConfirmedRings = @($script:SIHeartbeatFields.PipelineEtaRings))
    if ("$Value" -eq '__read__') { $Value = Get-Variable -Name 'SI_Uplink_SendPipelineEta' -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
    if ("$EnvValue" -eq '__read__') { $EnvValue = [Environment]::GetEnvironmentVariable('SI_UPLINK_SENDPIPELINEETA') }
    Resolve-SIUplinkFieldSwitch -Name 'SI_Uplink_SendPipelineEta' -Value $Value -EnvValue ([string]$EnvValue) -Ring $Ring -ConfirmedRings $ConfirmedRings
}

function Resolve-SIUplinkPipelineStoppedSwitch {
    <# PURE. #1035: does Pipeline say 'stopped' for a run stopped or cancelled before its end? SI_Uplink_SendPipelineStopped
       (setting) > SI_UPLINK_SENDPIPELINESTOPPED (job variable) > auto = the rings in PipelineStoppedRings -- NONE until
       Invardia agrees the value (then 'idle' is said). #>
    param([AllowNull()]$Ring, $Value = '__read__', $EnvValue = '__read__', [int[]]$ConfirmedRings = @($script:SIHeartbeatFields.PipelineStoppedRings))
    if ("$Value" -eq '__read__') { $Value = Get-Variable -Name 'SI_Uplink_SendPipelineStopped' -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
    if ("$EnvValue" -eq '__read__') { $EnvValue = [Environment]::GetEnvironmentVariable('SI_UPLINK_SENDPIPELINESTOPPED') }
    Resolve-SIUplinkFieldSwitch -Name 'SI_Uplink_SendPipelineStopped' -Value $Value -EnvValue ([string]$EnvValue) -Ring $Ring -ConfirmedRings $ConfirmedRings
}

# =====================================================================================================================
#  Small helpers -- PURE
# =====================================================================================================================
function ConvertTo-SIHeartbeatInt {
    <# PURE. A whole number >= 0 ([long], rounded from a decimal), or $null. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [DBNull] -or "$Value".Trim() -eq '') { return $null }
    $d = 0.0
    if (-not [double]::TryParse("$Value".Trim(), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $null }
    if ([double]::IsNaN($d) -or [double]::IsInfinity($d) -or $d -lt 0) { return $null }
    [long][Math]::Round($d, [MidpointRounding]::AwayFromZero)
}

function ConvertTo-SIHeartbeatNumber {
    <# PURE. A number >= 0 with at most 2 decimals ([double]), or $null. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [DBNull] -or "$Value".Trim() -eq '') { return $null }
    $d = 0.0
    if (-not [double]::TryParse("$Value".Trim(), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $null }
    if ([double]::IsNaN($d) -or [double]::IsInfinity($d) -or $d -lt 0) { return $null }
    [double][Math]::Round($d, 2)
}

function ConvertTo-SIHeartbeatTime {
    <# PURE. A time as [datetime] UTC, or $null. #>
    param($Value)
    $s = ConvertTo-SIHeartbeatUtc $Value
    if (-not $s) { return $null }
    [datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
}

function ConvertTo-SIHeartbeatMinutes {
    <# PURE. Whole minutes between two times (>= 0), or $null when either is missing. #>
    param($From, $To)
    $a = ConvertTo-SIHeartbeatTime $From; $b = ConvertTo-SIHeartbeatTime $To
    if ($null -eq $a -or $null -eq $b -or $b -lt $a) { return $null }
    [long][Math]::Round(($b - $a).TotalMinutes, [MidpointRounding]::AwayFromZero)
}

function ConvertTo-SIHeartbeatJobName {
    <# PURE. A job as its short key (caj-si-identity -> identity): a-z, 0-9 and dashes, at most 60; $null otherwise. #>
    param($Job)
    $k = (("$Job").Trim().ToLowerInvariant()) -replace '^caj-si-', ''
    if ($k -cmatch '^[a-z0-9][a-z0-9-]{0,59}$') { $k } else { $null }
}

function ConvertTo-SIHeartbeatErrorCode {
    <# PURE. An error class of the closed list (SI-ErrorClass.ps1), or $null ('unknown' is not a code). #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $c = "$Value".Trim().ToLowerInvariant()
    if ($c -and $c -ne 'unknown' -and (Get-SIErrorClasses) -ccontains $c) { $c } else { $null }
}

function Get-SIHeartbeatRowsOf {
    param([object[]]$Rows, [string]$K)
    @(@($Rows) | Where-Object { $null -ne $_ -and [string](Get-SIHeartbeatRowValue $_ 'K') -eq $K })
}

function Get-SIHeartbeatSnowOutputsOn {
    <#
        PURE (#903). The ServiceNow outputs switched on, from the K 'dataout' row (cfg.Setting SI_DataOut_Outputs, its ValueJson:
        a JSON string or array of output ids, comma / semicolon separated). No row = none: both ServiceNow outputs are off by
        default -- the rule of SI-SnowVerify.ps1 Get-SISnowOutputsOn (a test keeps them equal).
    #>
    param([object[]]$Rows)
    $r = @(Get-SIHeartbeatRowsOf $Rows 'dataout')[0]
    $txt = if ($r) { [string](Get-SIHeartbeatRowValue $r 'Txt') } else { '' }
    $vals = @()
    if ($txt.Trim()) { try { $vals = @(ConvertFrom-Json -InputObject $txt -ErrorAction Stop) } catch { $vals = @($txt) } }
    $chosen = @($vals | ForEach-Object { ([string]$_) -split '[,;]' } | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    , [string[]]@(@('servicenow-ci', 'servicenow-vulnerable-item') | Where-Object { $chosen -contains $_ })
}

function New-SIHeartbeatOrdered {
    <# PURE. An object with exactly -Names in order, each from -Values (missing = null). #>
    param([string[]]$Names, [System.Collections.IDictionary]$Values)
    $o = [ordered]@{}
    foreach ($n in $Names) { $o[$n] = $(if ($Values.Contains($n)) { $Values[$n] } else { $null }) }
    [pscustomobject]$o
}

# =====================================================================================================================
#  The schema of every field -- PURE (what Invardia's validator accepts; nothing that fails it is put on the record)
# =====================================================================================================================
function Test-SIHeartbeatField {
    <# PURE. Is -Value EXACTLY the agreed shape of field -Name? '' = good, else what is wrong. #>
    param([Parameter(Mandatory)][string]$Name, $Value)
    $c = $script:SIHeartbeatFields
    $isTime = { param($v) $null -eq $v -or ($v -is [string] -and $v -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') }
    $isInt = { param($v) $null -eq $v -or (($v -is [int] -or $v -is [long]) -and $v -ge 0) }
    $isNum = { param($v) $null -eq $v -or (($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal]) -and $v -ge 0) }
    $inList = { param($v, $list, [bool]$nullOk) ($nullOk -and $null -eq $v) -or ($v -is [string] -and @($list) -ccontains $v) }
    $exact = { param($o, $names, $what)
        if ($null -eq $o -or $o -is [string] -or $o -is [array] -or $o -is [System.Collections.IDictionary]) { return "$what is not an object" }
        $have = @($o.PSObject.Properties | ForEach-Object { $_.Name })
        if (($have -join ',') -cne (@($names) -join ',')) { return ("{0} has the fields '{1}', agreed '{2}'" -f $what, ($have -join ','), (@($names) -join ',')) }
        '' }
    $array = { param($v, $max, $what) if ($null -eq $v -or -not ($v -is [array])) { return "$what is not an array" }; if (@($v).Count -gt $max) { return ('{0} has {1} entries (at most {2})' -f $what, @($v).Count, $max) }; '' }
    switch ($Name) {
        'Pipeline' {
            # the agreed seven -- or the agreed seven followed by EXACTLY the progress / estimated-end keys -- and, either way,
            # housekeepingRowsLeft as the LAST key when it is there
            $withEta = [bool]($Value -and -not ($Value -is [string]) -and $Value.PSObject.Properties['stepsDone'])
            $hkName = [string]$c.PipelineHousekeepingField
            $withHk = [bool]($Value -and -not ($Value -is [string]) -and $Value.PSObject.Properties[$hkName])
            $snName = [string]$c.PipelineStalledField
            $withSt = [bool]($Value -and -not ($Value -is [string]) -and $Value.PSObject.Properties[$snName])
            $names = @($c.Fields.Pipeline); if ($withEta) { $names += @($c.PipelineEtaFields) }; if ($withSt) { $names += $snName }; if ($withHk) { $names += $hkName }
            $w = & $exact $Value $names 'Pipeline'; if ($w) { return $w }
            if ($withHk) {
                $hk = $Value.$hkName
                if (-not (($hk -is [int] -or $hk -is [long]) -and $hk -ge 0)) { return "Pipeline.$hkName is not a whole number >= 0" }
            }
            if ($withSt) {
                $w = & $array $Value.$snName $c.MaxStalledSteps 'Pipeline.stalledSteps'; if ($w) { return $w }
                if (-not @($Value.$snName).Count) { return 'Pipeline.stalledSteps is empty (it is left out when there is none)' }
                foreach ($s in @($Value.$snName)) {
                    $w = & $exact $s $c.StalledStepFields 'a Pipeline.stalledSteps entry'; if ($w) { return $w }
                    if (-not ($s.step -is [string] -and $s.step -cmatch '^[a-z0-9][a-z0-9-]{0,59}$')) { return ("Pipeline.stalledSteps.step '{0}' is not a job key" -f $s.step) }
                    if ($null -eq $s.sinceUtc) { return 'Pipeline.stalledSteps.sinceUtc is missing' }
                    foreach ($t in 'sinceUtc', 'lastProgressUtc') { if (-not (& $isTime $s.$t)) { return "Pipeline.stalledSteps.$t is not ISO-8601 UTC" } }
                }
            }
            # #1035: 'stopped' is only ever built while its own switch is on (see PipelineStoppedState)
            if (-not (& $inList $Value.state (@($c.PipelineStates) + @($c.PipelineStoppedState)) $false)) { return ("Pipeline.state '{0}' is not in the list" -f $Value.state) }
            if ($null -ne $Value.runId -and -not ($Value.runId -is [string] -and $Value.runId -cmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$')) { return 'Pipeline.runId is not an id' }
            if ($null -ne $Value.step -and -not ($Value.step -is [string] -and $Value.step -cmatch '^[a-z0-9][a-z0-9-]{0,59}$')) { return 'Pipeline.step is not a job key' }
            foreach ($t in 'startedUtc', 'stepSinceUtc', 'lastEndedUtc', 'nextStartUtc') { if (-not (& $isTime $Value.$t)) { return "Pipeline.$t is not ISO-8601 UTC" } }
            if (-not $withEta) { return '' }
            foreach ($n in 'stepsDone', 'stepsTotal', 'queuedRuns') { if (-not (& $isInt $Value.$n)) { return "Pipeline.$n is not a whole number >= 0" } }
            if ($null -ne $Value.stepsDone -and $null -ne $Value.stepsTotal -and $Value.stepsDone -gt $Value.stepsTotal) { return 'Pipeline.stepsDone is more than stepsTotal' }
            if (-not (& $isTime $Value.estimatedEndUtc)) { return 'Pipeline.estimatedEndUtc is not ISO-8601 UTC' }
            if (-not (& $inList $Value.estimateConfidence $c.EtaConfidences $true)) { return ("Pipeline.estimateConfidence '{0}' is not in the list" -f $Value.estimateConfidence) }
            $w = & $array $Value.runningSteps $c.MaxRunningSteps 'Pipeline.runningSteps'; if ($w) { return $w }
            foreach ($s in @($Value.runningSteps)) {
                # #1180: the five, then lastProgressUtc / progress -- each only when it is there, in that order
                $rsNames = @($c.RunningStepFields)
                if ($s -and -not ($s -is [string]) -and -not ($s -is [System.Collections.IDictionary])) { foreach ($on in @($c.RunningStepOptionalFields)) { if ($s.PSObject.Properties[$on]) { $rsNames += $on } } }
                $w = & $exact $s $rsNames 'a Pipeline.runningSteps entry'; if ($w) { return $w }
                if ($s.PSObject.Properties['lastProgressUtc'] -and ($null -eq $s.lastProgressUtc -or -not (& $isTime $s.lastProgressUtc))) { return 'Pipeline.runningSteps.lastProgressUtc is not ISO-8601 UTC (left out when not known)' }
                if ($s.PSObject.Properties['progress'] -and -not ($s.progress -is [string] -and $s.progress -cmatch ('^[{0}]{{1,{1}}}$' -f $c.RunningStepProgressChars, [int]$c.RunningStepProgressMax))) { return ('Pipeline.runningSteps.progress is not 1-{0} of the agreed characters (left out when not known)' -f [int]$c.RunningStepProgressMax) }
                if (-not ($s.step -is [string] -and $s.step -cmatch '^[a-z0-9][a-z0-9-]{0,59}$')) { return ("Pipeline.runningSteps.step '{0}' is not a job key" -f $s.step) }
                foreach ($t in 'sinceUtc', 'endUtc') { if (-not (& $isTime $s.$t)) { return "Pipeline.runningSteps.$t is not ISO-8601 UTC" } }
                if (-not (& $isInt $s.prevMin)) { return 'Pipeline.runningSteps.prevMin is not a whole number >= 0' }
                if (-not (& $inList $s.estimate $c.StepEstimates $false)) { return ("Pipeline.runningSteps.estimate '{0}' is not in the list" -f $s.estimate) }
            }
            $w = & $array $Value.remainingSteps $c.MaxRemainingSteps 'Pipeline.remainingSteps'; if ($w) { return $w }
            foreach ($s in @($Value.remainingSteps)) {
                $w = & $exact $s $c.RemainingStepFields 'a Pipeline.remainingSteps entry'; if ($w) { return $w }
                if (-not ($s.step -is [string] -and $s.step -cmatch '^[a-z0-9][a-z0-9-]{0,59}$')) { return ("Pipeline.remainingSteps.step '{0}' is not a job key" -f $s.step) }
                foreach ($n in 'group', 'estimateMin') { if (-not (& $isInt $s.$n)) { return "Pipeline.remainingSteps.$n is not a whole number >= 0" } }
            }
            return ''
        }
        'Jobs' {
            $w = & $array $Value $c.MaxJobs 'Jobs'; if ($w) { return $w }
            $seen = @{}
            foreach ($j in @($Value)) {
                $w = & $exact $j $c.Fields.Jobs 'a Jobs entry'; if ($w) { return $w }
                if (-not ($j.name -is [string] -and $j.name -cmatch '^[a-z0-9][a-z0-9-]{0,59}$')) { return ("Jobs.name '{0}' is not a job key" -f $j.name) }
                if ($seen.ContainsKey($j.name)) { return ("job {0} appears more than once" -f $j.name) }; $seen[$j.name] = 1
                if (-not (& $inList $j.lastResult $c.JobResults $true)) { return ("Jobs.lastResult '{0}' is not in the list" -f $j.lastResult) }
                foreach ($t in 'lastStartUtc', 'lastEndUtc') { if (-not (& $isTime $j.$t)) { return "Jobs.$t is not ISO-8601 UTC" } }
                foreach ($n in 'durationMin', 'prevDurationMin') { if (-not (& $isInt $j.$n)) { return "Jobs.$n is not a whole number >= 0" } }
                foreach ($n in 'cpu', 'memoryGi', 'timeoutHours') { if (-not (& $isNum $j.$n)) { return "Jobs.$n is not a number >= 0" } }
            }
            return ''
        }
        'Sources' {
            $w = & $array $Value $c.MaxSources 'Sources'; if ($w) { return $w }
            $seen = @{}
            foreach ($s in @($Value)) {
                $w = & $exact $s $c.Fields.Sources 'a Sources entry'; if ($w) { return $w }
                if (-not (& $inList $s.source $c.Sources $false)) { return ("Sources.source '{0}' is not in the list" -f $s.source) }
                if ($seen.ContainsKey($s.source)) { return ("source {0} appears more than once" -f $s.source) }; $seen[$s.source] = 1
                if (-not (& $isTime $s.lastGoodUtc)) { return 'Sources.lastGoodUtc is not ISO-8601 UTC' }
                if ($null -ne $s.lastErrorCode -and -not (& $inList $s.lastErrorCode (Get-SIErrorClasses) $false)) { return ("Sources.lastErrorCode '{0}' is not an error class" -f $s.lastErrorCode) }
                foreach ($n in 'retries24h', 'throttled24h', 'lagMin') { if (-not (& $isInt $s.$n)) { return "Sources.$n is not a whole number >= 0" } }
            }
            return ''
        }
        'Database' {
            # the agreed six, then -- #1210 -- the statistics keys present, in their agreed order
            $dbNames = @($c.Fields.Database)
            if ($Value -and -not ($Value -is [string]) -and -not ($Value -is [System.Collections.IDictionary])) { foreach ($sn in @($c.DatabaseStatsFields)) { if ($Value.PSObject.Properties[$sn]) { $dbNames += $sn } } }
            $w = & $exact $Value $dbNames 'Database'; if ($w) { return $w }
            if ($Value.PSObject.Properties['statsAsync'] -and -not ($Value.statsAsync -is [bool])) { return 'Database.statsAsync is not true / false' }
            if ($Value.PSObject.Properties['statsStalePct'] -and -not ((& $isNum $Value.statsStalePct) -and $null -ne $Value.statsStalePct -and $Value.statsStalePct -le 100)) { return 'Database.statsStalePct is not a number 0-100' }
            if ($Value.PSObject.Properties['statsRefreshedUtc'] -and -not (& $isTime $Value.statsRefreshedUtc)) { return 'Database.statsRefreshedUtc is not ISO-8601 UTC' }
            if ($null -ne $Value.tier -and -not ($Value.tier -is [string] -and $Value.tier -cmatch '^[A-Za-z][A-Za-z0-9]{0,31}$')) { return 'Database.tier is not a tier name' }
            foreach ($n in 'dtu', 'maxSizeMb', 'usedMb', 'peakLogWritePct1h', 'minutesAtLimit1h') { if (-not (& $isInt $Value.$n)) { return "Database.$n is not a whole number >= 0" } }
            if ($null -ne $Value.peakLogWritePct1h -and $Value.peakLogWritePct1h -gt 100) { return 'Database.peakLogWritePct1h is over 100' }
            if ($null -ne $Value.minutesAtLimit1h -and $Value.minutesAtLimit1h -gt 60) { return 'Database.minutesAtLimit1h is over 60' }
            return ''
        }
        'Update' {
            $w = & $exact $Value $c.Fields.Update 'Update'; if ($w) { return $w }
            foreach ($n in 'installed', 'available') { if ($null -ne $Value.$n -and -not ($Value.$n -is [string] -and $Value.$n -cmatch '^[0-9][0-9A-Za-z.+-]{0,63}$')) { return "Update.$n is not a version" } }
            if (-not (& $inList $Value.lastUpdaterResult $c.UpdateResults $true)) { return ("Update.lastUpdaterResult '{0}' is not in the list" -f $Value.lastUpdaterResult) }
            foreach ($t in 'lastUpdaterRunUtc', 'nextUpdateUtc') { if (-not (& $isTime $Value.$t)) { return "Update.$t is not ISO-8601 UTC" } }
            return ''
        }
        'Mail' {
            $w = & $exact $Value $c.Fields.Mail 'Mail'; if ($w) { return $w }
            # mailJob and restriction are REQUIRED (Invardia drops the whole Mail field when either is null or missing)
            if (-not (& $inList $Value.mailJob $c.MailJobStates $false)) { return ("Mail.mailJob '{0}' is not in the list (required)" -f $Value.mailJob) }
            if (-not (& $inList $Value.restriction $c.MailRestrictions $false)) { return ("Mail.restriction '{0}' is not in the list (required)" -f $Value.restriction) }
            if ($null -ne $Value.lastErrorCode -and -not (& $inList $Value.lastErrorCode (Get-SIErrorClasses) $false)) { return 'Mail.lastErrorCode is not an error class' }
            foreach ($t in 'lastSentUtc', 'lastFailedUtc') { if (-not (& $isTime $Value.$t)) { return "Mail.$t is not ISO-8601 UTC" } }
            if (-not (& $isInt $Value.queued)) { return 'Mail.queued is not a whole number >= 0' }
            return ''
        }
        'Warnings' {
            $w = & $array $Value $c.MaxWarnings 'Warnings'; if ($w) { return $w }
            $codes = @(Get-SIErrorCatalogue | ForEach-Object { [string]$_.code })
            $seen = @{}
            foreach ($x in @($Value)) {
                $w = & $exact $x $c.Fields.Warnings 'a Warnings entry'; if ($w) { return $w }
                if (-not ($x.code -is [string] -and $x.code -cmatch '^si-[a-z]{2,8}-\d{4}$' -and $codes -ccontains $x.code)) { return ("Warnings.code '{0}' is not a published code" -f $x.code) }
                if ($seen.ContainsKey($x.code)) { return ("code {0} appears more than once" -f $x.code) }; $seen[$x.code] = 1
                if (-not (& $isTime $x.sinceUtc)) { return 'Warnings.sinceUtc is not ISO-8601 UTC' }
            }
            return ''
        }
        'Security' {
            $w = & $exact $Value $c.Fields.Security 'Security'; if ($w) { return $w }
            if (-not (& $isTime $Value.collectionUtc)) { return 'Security.collectionUtc is not ISO-8601 UTC' }
            $w = & $array $Value.domains $c.MaxDomains 'Security.domains'; if ($w) { return $w }
            if (@($Value.domains).Count -eq 0) { return 'Security.domains is empty (no field then)' }
            $seen = @{}
            foreach ($d in @($Value.domains)) {
                $w = & $exact $d $c.Fields.Domain 'a Security domain'; if ($w) { return $w }
                if (-not (& $inList $d.domain $c.Domains $false)) { return ("Security.domain '{0}' is not in the list" -f $d.domain) }
                if ($seen.ContainsKey($d.domain)) { return ("domain {0} appears more than once" -f $d.domain) }; $seen[$d.domain] = 1
                foreach ($n in @($c.Fields.Domain | Select-Object -Skip 1)) { if (-not (& $isInt $d.$n)) { return "Security.$($d.domain).$n is not a whole number >= 0" } }
                if ($null -eq $d.reportsComplete -or $d.reportsComplete -lt 1) { return "Security.$($d.domain) has no complete report (the domain is left out then)" }
                if ($null -ne $d.reports -and $d.reportsComplete -gt $d.reports) { return "Security.$($d.domain).reportsComplete is more than reports" }
            }
            return ''
        }
        'Published' {
            # nothing published = the field is LEFT OUT (Invardia 1.0.593): null is not a value of it
            if ($null -eq $Value) { return 'Published is null (leave the field out when nothing is published)' }
            $w = & $exact $Value $c.Fields.Published 'Published'; if ($w) { return $w }
            if ($null -eq $Value.collectionId -or -not (& $isInt $Value.collectionId)) { return 'Published.collectionId is not a whole number >= 0' }
            foreach ($n in 'collectionUtc', 'publishedUtc') { if ($null -eq $Value.$n -or -not (& $isTime $Value.$n)) { return "Published.$n is not ISO-8601 UTC" } }
            foreach ($n in 'copiedUtc', 'newestCompleteUtc') { if (-not (& $isTime $Value.$n)) { return "Published.$n is not ISO-8601 UTC or null" } }
            return ''
        }
        'DataOut' {
            # #1043: at most 10 entries, unique by output; output + phase required, every other value soft but of its type
            $w = & $array $Value $c.MaxDataOut 'DataOut'; if ($w) { return $w }
            $seen = @{}
            foreach ($x in @($Value)) {
                # #1237: heldSinceUtc / newestTrustedUtc after the others -- each only when it is there (soft, never null)
                # assigned first: the function answers ONE string[] (', [string[]]'), which @( ) would wrap as one element
                $doNames = Get-SIHeartbeatDataOutFieldNames; $doNames = [string[]]$doNames
                if ($x -and -not ($x -is [string]) -and -not ($x -is [System.Collections.IDictionary])) { foreach ($on in @($c.DataOutTrustFields)) { if ($x.PSObject.Properties[$on]) { $doNames += $on } } }
                $w = & $exact $x $doNames 'a DataOut entry'; if ($w) { return $w }
                foreach ($on in @($c.DataOutTrustFields)) { if ($x.PSObject.Properties[$on] -and ($null -eq $x.$on -or -not (& $isTime $x.$on))) { return ("DataOut.{0} is not ISO-8601 UTC (left out when not known)" -f $on) } }
                if ($c.DataOutSendKeptOpen -and -not (& $isInt $x.($c.DataOutKeptOpenField))) { return ("DataOut.{0} is not a whole number >= 0" -f $c.DataOutKeptOpenField) }
                if (-not ($x.output -is [string] -and $x.output -cmatch '^[a-z0-9-]{1,64}$')) { return ("DataOut.output '{0}' is not an output id" -f $x.output) }
                if ($seen.ContainsKey($x.output)) { return ("output {0} appears more than once" -f $x.output) }; $seen[$x.output] = 1
                if (-not (& $inList $x.phase $c.DataOutPhases $false)) { return ("DataOut.phase '{0}' is not in the list" -f $x.phase) }
                if ($null -ne $x.batchId -and -not ($x.batchId -is [string] -and $x.batchId -cmatch '^[A-Za-z0-9._:-]{1,64}$')) { return 'DataOut.batchId is not an id' }
                foreach ($t in 'startedUtc', 'lastProgressUtc', 'lastEndedUtc') { if (-not (& $isTime $x.$t)) { return "DataOut.$t is not ISO-8601 UTC" } }
                foreach ($n in 'rowsPlanned', 'rowsSent', 'rowsHeld') { if (-not (& $isInt $x.$n)) { return "DataOut.$n is not a whole number >= 0" } }
                if (-not (& $isNum $x.rowsPerSec)) { return 'DataOut.rowsPerSec is not a number >= 0' }
                if ($null -ne $x.stalled -and -not ($x.stalled -is [bool])) { return 'DataOut.stalled is not true / false' }
                if (-not (& $inList $x.lastResult $c.DataOutResults $true)) { return ("DataOut.lastResult '{0}' is not in the list" -f $x.lastResult) }
                if ($null -ne $x.lastErrorCode -and -not ($x.lastErrorCode -is [string] -and $x.lastErrorCode -cmatch '^si-[a-z]{2,8}-\d{4}$' -and @(Get-SIErrorCatalogue | ForEach-Object { [string]$_.code }) -ccontains $x.lastErrorCode)) { return ("DataOut.lastErrorCode '{0}' is not a published code" -f $x.lastErrorCode) }
                if (-not (& $inList $x.heldReason $c.DataOutHeldReasons $true)) { return ("DataOut.heldReason '{0}' is not in the list" -f $x.heldReason) }
            }
            return ''
        }
        'BuildPool' {
            # framework rule 11g: { tier (string), count (whole number), building (true / false), checkedUtc (ISO string) } -- all
            # four required; an install without an agent pool leaves the field out
            if ($null -eq $Value) { return 'BuildPool is null (leave the field out when the install has no agent pool)' }
            $w = & $exact $Value $c.Fields.BuildPool 'BuildPool'; if ($w) { return $w }
            if (-not (& $inList $Value.tier $c.BuildPoolTiers $false)) { return ("BuildPool.tier '{0}' is not an agent pool tier" -f $Value.tier) }
            if ($null -eq $Value.count -or -not (& $isInt $Value.count)) { return 'BuildPool.count is not a whole number >= 0' }
            if (-not ($Value.building -is [bool])) { return 'BuildPool.building is not true / false' }
            if ($null -eq $Value.checkedUtc -or -not (& $isTime $Value.checkedUtc)) { return 'BuildPool.checkedUtc is not ISO-8601 UTC' }
            return ''
        }
        'UplinkBacklog' {
            # framework 8.4: EXACTLY { pending, oldestUtc, checkedUtc } -- pending a whole number 0..1,000,000 (required),
            # oldestUtc ISO-8601 UTC or null (null exactly when nothing is pending), checkedUtc ISO-8601 UTC (required: Invardia
            # drops the field without it). No "required" or any other key. Not known = the field is left out, never null.
            if ($null -eq $Value) { return 'UplinkBacklog is null (leave the field out when the outbox cannot be read)' }
            $w = & $exact $Value $c.Fields.UplinkBacklog 'UplinkBacklog'; if ($w) { return $w }
            if ($null -eq $Value.pending -or -not (& $isInt $Value.pending) -or $Value.pending -gt $c.UplinkBacklogMax) { return 'UplinkBacklog.pending is not a whole number 0..1000000' }
            if (-not (& $isTime $Value.oldestUtc)) { return 'UplinkBacklog.oldestUtc is not ISO-8601 UTC or null' }
            if ($Value.pending -eq 0 -and $null -ne $Value.oldestUtc) { return 'UplinkBacklog.oldestUtc is set while nothing is pending' }
            if ($Value.pending -gt 0 -and $null -eq $Value.oldestUtc) { return 'UplinkBacklog.oldestUtc is missing while records are pending' }
            if ($null -eq $Value.checkedUtc -or -not (& $isTime $Value.checkedUtc)) { return 'UplinkBacklog.checkedUtc is not ISO-8601 UTC (required)' }
            return ''
        }
        default { return "not a heartbeat field: $Name" }
    }
}

# =====================================================================================================================
#  The reads behind the fields
# =====================================================================================================================
function Get-SIHeartbeatFieldsCfgSql {
    <#
        ONE read of the settings database (every table may be missing on an older schema -- then no rows of it). Rows:
        K (run | step | def | state | mail | queue), Name, S, T1, T2, T3, T4, N1, N2, Txt, Txt2. Index reads only: the newest run
        records by IX_FlowRun_Started, their steps by the primary key (N2 = the step's group: the steps of one group run
        together), cfg.InstallState by its key, the outboxes by IX_*Mail_Pending, the waiting pipeline requests by
        IX_PipelineQueue_State (a count; a database without the table or the right to read it gives no row).
    #>
    $n = [int]$script:SIHeartbeatFields.RunsRead
@"
SET NOCOUNT ON;
DECLARE @r TABLE (K NVARCHAR(16) NOT NULL, Name NVARCHAR(128) NULL, S NVARCHAR(32) NULL, T1 DATETIME2(3) NULL, T2 DATETIME2(3) NULL, T3 DATETIME2(3) NULL, T4 DATETIME2(3) NULL, N1 BIGINT NULL, N2 BIGINT NULL, Txt NVARCHAR(MAX) NULL, Txt2 NVARCHAR(128) NULL);
IF OBJECT_ID(N'cfg.FlowRun') IS NOT NULL
BEGIN
    INSERT @r (K, Name, S, T1, T2, T3, T4, Txt, Txt2)
    SELECT TOP ($n) N'run', FlowRunId, State, StartedUtc, EndedUtc, HeartbeatUtc, LastSlotUtc, FromStep, CONVERT(nvarchar(30), SlotUtc, 126) FROM cfg.FlowRun WHERE FlowId = N'daily' ORDER BY StartedUtc DESC;
    -- si-flow-1203: each run's scope (a column an older schema does not have yet -- then no row: every run counts as the pipeline)
    IF COL_LENGTH(N'cfg.FlowRun', N'Scope') IS NOT NULL
        INSERT @r (K, Name, S) EXEC (N'SELECT TOP ($n) N''runscope'', FlowRunId, LEFT(Scope, 32) FROM cfg.FlowRun WHERE FlowId = N''daily'' ORDER BY StartedUtc DESC;');
    IF OBJECT_ID(N'cfg.FlowStepRun') IS NOT NULL
        INSERT @r (K, Name, S, T1, T2, N1, N2, Txt, Txt2)
        SELECT N'step', s.Job, s.State, s.StartedUtc, s.EndedUtc, s.StepOrder, s.GroupNo, s.FlowRunId, s.ErrorClass
        FROM cfg.FlowStepRun s JOIN @r r ON r.K = N'run' AND r.Name = s.FlowRunId COLLATE DATABASE_DEFAULT;
    -- si-flow-1204: the running steps of the newest run, each with its newest sign of progress since it started (its own and
    -- its workers' marks in cfg.StepProgress, its phase rows in cfg.StepPhaseTime) and whether the runner found it silent
    IF OBJECT_ID(N'cfg.FlowStepRun') IS NOT NULL
    BEGIN
        DECLARE @topRun nvarchar(64) = (SELECT TOP (1) Name FROM @r WHERE K = N'run' ORDER BY T1 DESC);
        CREATE TABLE #prog (Job nvarchar(64) COLLATE DATABASE_DEFAULT NOT NULL, FlowRunId nvarchar(64) COLLATE DATABASE_DEFAULT NOT NULL, StepOrder int NOT NULL,
                            StartedUtc datetime2(3) NULL, Execution nvarchar(128) COLLATE DATABASE_DEFAULT NULL, Phase datetime2(3) NULL, Mark datetime2(3) NULL, Silent bit NOT NULL DEFAULT 0);
        INSERT #prog (Job, FlowRunId, StepOrder, StartedUtc, Execution)
        SELECT s.Job, s.FlowRunId, s.StepOrder, s.StartedUtc, s.Execution FROM cfg.FlowStepRun s WHERE s.FlowRunId = @topRun AND s.State IN (N'Running', N'Starting');
        IF OBJECT_ID(N'cfg.StepPhaseTime') IS NOT NULL
            UPDATE p SET Phase = (SELECT MAX(x.AtUtc) FROM cfg.StepPhaseTime x WHERE x.Execution = p.Execution AND x.AtUtc >= p.StartedUtc) FROM #prog p;
        IF OBJECT_ID(N'cfg.StepProgress') IS NOT NULL
            UPDATE p SET Mark = (SELECT MAX(x.LastUtc) FROM cfg.StepProgress x WHERE (x.Execution = p.Execution OR x.Job = N'caj-si-' + p.Job OR x.Job LIKE N'caj-si-' + p.Job + N'-%') AND x.LastUtc >= p.StartedUtc) FROM #prog p;
        IF COL_LENGTH(N'cfg.FlowStepRun', N'RetryReason') IS NOT NULL
            EXEC (N'UPDATE p SET Silent = 1 FROM #prog p JOIN cfg.FlowStepRun s ON s.FlowRunId = p.FlowRunId AND s.StepOrder = p.StepOrder WHERE s.RetryReason LIKE N''%has shown no sign of progress for%'';');
        INSERT @r (K, Name, T1, T2, N1, N2, Txt)
        SELECT N'prog', Job, StartedUtc, CASE WHEN Mark IS NULL THEN Phase WHEN Phase IS NULL OR Mark >= Phase THEN Mark ELSE Phase END, StepOrder, CONVERT(bigint, Silent), FlowRunId FROM #prog;
        -- #1180: each running step's OWN progress record (its execution's row of cfg.StepProgress: when it last moved, what
        -- it does, done / total) -- Pipeline.runningSteps[].lastProgressUtc / progress (Invardia 452cb22c)
        IF OBJECT_ID(N'cfg.StepProgress') IS NOT NULL
            INSERT @r (K, Name, T1, N1, N2, Txt)
            SELECT N'sprog', p.Job, x.LastUtc, x.Done, x.Total, LEFT(x.Phase, 200) FROM #prog p JOIN cfg.StepProgress x ON x.Execution = p.Execution WHERE x.LastUtc >= p.StartedUtc;
        DROP TABLE #prog;
    END
END
IF OBJECT_ID(N'cfg.PipelineQueue') IS NOT NULL
BEGIN
    BEGIN TRY
        INSERT @r (K, Name, N1) SELECT N'queue', N'Queued', COUNT_BIG(*) FROM cfg.PipelineQueue WHERE PipelineId = N'daily' AND State = N'Queued';
    END TRY
    BEGIN CATCH
        DECLARE @queueUnread INT = ERROR_NUMBER();
    END CATCH
END
IF OBJECT_ID(N'cfg.JobFlow') IS NOT NULL
    INSERT @r (K, Name, Txt) SELECT TOP (1) N'def', Mode, DefinitionJson FROM cfg.JobFlow WHERE FlowId = N'daily';
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
    INSERT @r (K, Name, T1, Txt) SELECT N'state', Name, UpdatedAt, Value FROM cfg.InstallState
    WHERE Name IN (N'UpdateState', N'SecretHandover', N'MailRestriction', N'MailRestrictionAttestation', N'MailLastSent', N'MailLastFailed', N'CollectionHeld', N'OutsidePipeline', N'Housekeeping', N'StatisticsRefresh');
IF OBJECT_ID(N'cfg.ServiceNowCheck') IS NOT NULL
    INSERT @r (K, Name, T1, Txt, T2)
    SELECT N'snow', c.[Output], c.CheckedAt, c.Outcome,
           (SELECT MIN(x.CheckedAt) FROM cfg.ServiceNowCheck AS x WHERE x.[Output] = c.[Output] AND x.Outcome <> N'ok'
              AND x.CheckId > ISNULL((SELECT MAX(o.CheckId) FROM cfg.ServiceNowCheck AS o WHERE o.[Output] = c.[Output] AND o.Outcome = N'ok'), 0))
    FROM cfg.ServiceNowCheck AS c WHERE c.CheckId = (SELECT MAX(m.CheckId) FROM cfg.ServiceNowCheck AS m WHERE m.[Output] = c.[Output]);
-- #903: which outputs are switched on (SI_DataOut_Outputs) -- a switched-off ServiceNow output never raises si-snow-1301
IF OBJECT_ID(N'cfg.Setting') IS NOT NULL
    INSERT @r (K, Name, Txt) SELECT N'dataout', Name, LEFT(ValueJson, 4000) FROM cfg.Setting WHERE Name = N'SI_DataOut_Outputs' AND Scope = N'solution';
IF OBJECT_ID(N'cfg.ExemptionMail') IS NOT NULL
    INSERT @r (K, Name, T1, N1, Txt, T2)
    SELECT N'mail', N'ExemptionMail', (SELECT MAX(SentAt) FROM cfg.ExemptionMail), (SELECT COUNT_BIG(*) FROM cfg.ExemptionMail WHERE SentAt IS NULL),
           (SELECT TOP (1) LEFT(LastError, 400) FROM cfg.ExemptionMail WHERE SentAt IS NULL AND LastError IS NOT NULL ORDER BY MailId DESC),
           (SELECT TOP (1) QueuedAt FROM cfg.ExemptionMail WHERE SentAt IS NULL AND LastError IS NOT NULL ORDER BY MailId DESC);
IF OBJECT_ID(N'cfg.SignInMail') IS NOT NULL
    INSERT @r (K, Name, T1, N1, Txt, T2)
    SELECT N'mail', N'SignInMail', (SELECT MAX(SentAt) FROM cfg.SignInMail),
           (SELECT COUNT_BIG(*) FROM cfg.SignInMail WHERE SentAt IS NULL AND QueuedAt > DATEADD(DAY, -1, SYSUTCDATETIME())),
           (SELECT TOP (1) LEFT(LastError, 400) FROM cfg.SignInMail WHERE SentAt IS NULL AND LastError IS NOT NULL ORDER BY MailId DESC),
           (SELECT TOP (1) QueuedAt FROM cfg.SignInMail WHERE SentAt IS NULL AND LastError IS NOT NULL ORDER BY MailId DESC);
SELECT K, Name, S, T1, T2, T3, T4, N1, N2, Txt, Txt2 FROM @r;
"@
}

function Get-SIHeartbeatHoldSql {
    <#
        #902: ONE read of the data database for the Warnings: the reports held ON PURPOSE in the newest collection of each
        grain (sidata.RaReportStatus NotComplete with a HoldKind) -- Grain, ReportName, HoldKind, HeldRuns and SinceUtc (the
        first run of the streak: the earliest row after the report's newest row that was NOT held for that kind). A database
        without the columns answers nothing.
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.RaReportStatus') IS NULL OR COL_LENGTH('sidata.RaReportStatus', 'HoldKind') IS NULL
BEGIN
    SELECT CAST(NULL AS NVARCHAR(16)) AS Grain, CAST(NULL AS NVARCHAR(256)) AS ReportName, CAST(NULL AS NVARCHAR(32)) AS HoldKind, CAST(NULL AS INT) AS HeldRuns, CAST(NULL AS DATETIME2(3)) AS SinceUtc WHERE 1 = 0;
    RETURN;
END
DECLARE @h nvarchar(100) = CASE WHEN COL_LENGTH('sidata.RaReportStatus', 'HeldRuns') IS NOT NULL THEN N's.HeldRuns' ELSE N'CAST(NULL AS INT)' END;
DECLARE @sql nvarchar(max) = N'
SELECT s.Grain, s.ReportName, s.HoldKind, ' + @h + N' AS HeldRuns,
       (SELECT MIN(x.CollectionTime) FROM sidata.RaReportStatus x
        WHERE x.Grain = s.Grain AND x.ReportName = s.ReportName
          AND x.CollectionTime > ISNULL((SELECT MAX(y.CollectionTime) FROM sidata.RaReportStatus y
                                         WHERE y.Grain = s.Grain AND y.ReportName = s.ReportName AND (y.HoldKind IS NULL OR y.HoldKind <> s.HoldKind)), ''19000101'')) AS SinceUtc
FROM sidata.RaReportStatus s
JOIN (SELECT Grain, MAX(CollectionTime) AS T FROM sidata.RaReportStatus GROUP BY Grain) n ON n.Grain = s.Grain AND n.T = s.CollectionTime
WHERE s.State = N''NotComplete'' AND NULLIF(s.HoldKind, N'''') IS NOT NULL;';
EXEC sp_executesql @sql;
'@
}

function Get-SIHeartbeatHoldWarnings {
    <# PURE. #902: the Warnings of the reports held on purpose (-HoldRows: Get-SIHeartbeatHoldSql) -- per row its kind's code
       (the escalation code once Test-SIHoldEscalated) and the first run of the streak, @(@{ Code; SinceUtc }); a kind that is
       not in the list says nothing. #>
    param([AllowNull()][object[]]$HoldRows)
    foreach ($r in @($HoldRows | Where-Object { $null -ne $_ })) {
        $k = [string](Get-SIHeartbeatRowValue $r 'HoldKind')
        if (-not (Test-SIHoldKind -Kind $k)) { continue }
        $esc = Test-SIHoldEscalated -HeldRuns (Get-SIHeartbeatRowValue $r 'HeldRuns') -Grain ([string](Get-SIHeartbeatRowValue $r 'Grain'))
        [pscustomobject]@{ Code = (Get-SIHoldKindCode -Kind $k -Escalated:$esc); SinceUtc = (Get-SIHeartbeatRowValue $r 'SinceUtc') }
    }
}

function Get-SIHeartbeatSecuritySql {
    <#
        ONE read of the data database for Security: the latest COMPLETE Detailed collection (as SI-TelemetryCounts reads it),
        each report's verdict there (sidata.RaReportStatus, by its primary key) and the DETAILED findings grouped by report --
        the stored 'report' grouping of that collection (sidata.SummaryGroup, #636: the Summary step is optional and off by
        default, so the per-domain counts come from the findings, never from Summary rows). Never sidata.Finding.
        Rows: K (time | status | sum), R, G, S, N1..N4, T -- sum: N1 findings, N2 / N3 rated Critical / High, N4 distinct assets.
        #871: the collection is the NEWEST complete one that HAS its groupings (a run that stopped before the data sync never
        drops the figures -- they go out with their own date, collectionUtc); when that is older than the newest complete
        collection, a row K 'time' G 'Newest' T = the newest one's time (Warnings: si-data-1402 since then).
    #>
@'
SET NOCOUNT ON;
DECLARE @o TABLE (K NVARCHAR(16) NOT NULL, R NVARCHAR(256) NULL, G NVARCHAR(16) NULL, S NVARCHAR(16) NULL, N1 BIGINT NULL, N2 BIGINT NULL, N3 BIGINT NULL, N4 BIGINT NULL, T DATETIME2(3) NULL);
DECLARE @dt DATETIME2(3), @dc INT, @gt DATETIME2(3), @gc INT;
IF OBJECT_ID(N'sidata.Collection') IS NOT NULL
    SELECT TOP (1) @dt = CollectionTime, @dc = CollectionId FROM sidata.Collection WHERE Kind = N'Detailed' AND Status = N'Complete' ORDER BY CollectionTime DESC;
IF @dc IS NOT NULL AND OBJECT_ID(N'sidata.SummaryGroup') IS NOT NULL AND OBJECT_ID(N'sidata.SummaryGroupState') IS NOT NULL
    EXEC sp_executesql N'SELECT TOP (1) @gt = c.CollectionTime, @gc = c.CollectionId FROM sidata.Collection AS c
WHERE c.Kind = N''Detailed'' AND c.Status = N''Complete'' AND EXISTS (SELECT 1 FROM sidata.SummaryGroupState AS s WHERE s.CollectionId = c.CollectionId)
ORDER BY c.CollectionTime DESC;', N'@gt DATETIME2(3) OUTPUT, @gc INT OUTPUT', @gt = @gt OUTPUT, @gc = @gc OUTPUT;
IF @gc IS NOT NULL AND @gc <> @dc
BEGIN
    INSERT @o (K, G, T) VALUES (N'time', N'Newest', @dt);
    SELECT @dt = @gt, @dc = @gc;
END
INSERT @o (K, G, T) VALUES (N'time', N'Detailed', @dt);
IF OBJECT_ID(N'sidata.RaReportStatus') IS NOT NULL AND @dt IS NOT NULL
    INSERT @o (K, R, G, S, N1)
    SELECT N'status', ReportName, Grain, State, StoredRows FROM sidata.RaReportStatus
    WHERE Grain = N'Detailed' AND CollectionTime = @dt;
IF @dc IS NOT NULL AND OBJECT_ID(N'sidata.SummaryGroup') IS NOT NULL AND OBJECT_ID(N'sidata.SummaryGroupState') IS NOT NULL
    INSERT @o (K, R, N1, N2, N3, N4)
    EXEC sp_executesql N'
IF EXISTS (SELECT 1 FROM sidata.SummaryGroupState WHERE CollectionId = @dc)
SELECT N''sum'', g.Key1, g.Findings, g.RatedCriticalFindings, g.RatedHighFindings, g.Assets
FROM sidata.SummaryGroup AS g WHERE g.CollectionId = @dc AND g.GroupingId = ''report'';', N'@dc int', @dc = @dc;
SELECT K, R, G, S, N1, N2, N3, N4, T FROM @o;
'@
}

function Get-SIHeartbeatPublishedCopySql {
    <#
        ONE key read of the DATA database: the run the web app shows (sidata.PublishedRun 'current') -- when it was published,
        when its copies of the merged assets were last refreshed, and whether they are older than it (Stale: CopiedAt NULL or
        before PublishedAt, the rule of sidata.PublishedCopyCatchUp). No row on an older schema or with nothing published.
        Refreshing (2026-10-24): 1 while a refresher writes the copies right now -- the session lock si-published-copy-refresh
        that Invoke-SIPublishedCopyRefresh (and the database's own catch-up) holds for the whole refresh is TESTED only
        (APPLOCK_TEST: nothing is taken, no right is needed); 0 when it is free; NULL when it cannot be tested.
    #>
@'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.PublishedRun') IS NOT NULL AND COL_LENGTH(N'sidata.PublishedRun', N'CopiedAt') IS NOT NULL AND OBJECT_ID(N'sidata.CiPub') IS NOT NULL
BEGIN
    DECLARE @lk int = NULL, @ms bigint = NULL;
    -- the time the last refresh of the copies took (each copy's own milliseconds, one after the other): si-data-1401 waits for it
    IF OBJECT_ID(N'sidata.PublishedCopy') IS NOT NULL
    BEGIN
        BEGIN TRY EXEC sp_executesql N'SELECT @m = SUM(CONVERT(bigint, Milliseconds)) FROM sidata.PublishedCopy;', N'@m bigint OUTPUT', @m = @ms OUTPUT; END TRY BEGIN CATCH SET @ms = NULL; END CATCH;
    END
    BEGIN TRY SET @lk = APPLOCK_TEST(N'public', N'si-published-copy-refresh', N'Exclusive', N'Session'); END TRY BEGIN CATCH SET @lk = NULL; END CATCH;
    SELECT PublishedAt, CopiedAt, CONVERT(bit, CASE WHEN CopiedAt IS NULL OR CopiedAt < PublishedAt THEN 1 ELSE 0 END) AS Stale,
           CONVERT(bit, CASE WHEN @lk = 0 THEN 1 WHEN @lk = 1 THEN 0 ELSE NULL END) AS Refreshing, @ms AS RefreshMs
    FROM sidata.PublishedRun WHERE Name = N'current' AND DetailedCollectionId IS NOT NULL;
END
'@
}

function Get-SIHeartbeatPublishedSql {
    <#
        ONE key read of the DATA database for Published (2026-10-26, agreed with Invardia): the collection customers SEE (sidata.
        PublishedRun 'current'), when it was published, when its copies were refreshed, and the newest COMPLETE Detailed
        collection -- so a gap between what was collected and what is shown is visible in one record (one install showed a
        16-day-old collection while every collection looked fresh). Always ONE row when read: CollectionId NULL = nothing is
        published yet. Older schema (no PublishedAt): no row.
    #>
@'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.PublishedRun') IS NOT NULL AND OBJECT_ID(N'sidata.Collection') IS NOT NULL AND COL_LENGTH(N'sidata.PublishedRun', N'PublishedAt') IS NOT NULL
BEGIN
    DECLARE @q nvarchar(max) = N'SELECT p.DetailedCollectionId AS CollectionId, COALESCE(c.CollectionTime, p.DetailedCollectionTime) AS CollectionTime,
       p.PublishedAt, ' + CASE WHEN COL_LENGTH(N'sidata.PublishedRun', N'CopiedAt') IS NOT NULL THEN N'p.CopiedAt' ELSE N'CAST(NULL AS datetime2(3))' END + N' AS CopiedAt,
       (SELECT TOP (1) n.CollectionTime FROM sidata.Collection AS n WHERE n.Kind = N''Detailed'' AND n.Status = N''Complete'' ORDER BY n.CollectionTime DESC) AS NewestComplete
FROM (SELECT 1 AS one) AS x
LEFT JOIN sidata.PublishedRun AS p ON p.Name = N''current'' AND p.DetailedCollectionId IS NOT NULL
LEFT JOIN sidata.Collection AS c ON c.CollectionId = p.DetailedCollectionId;';
    EXEC sp_executesql @q;
END
'@
}

function Get-SIHeartbeatPublished {
    <#
        PURE. Published from the rows of Get-SIHeartbeatPublishedSql: $null = not read (the field is left out: Invardia keeps
        what it had); 'none' = read, nothing is published yet (also left out -- Invardia 1.0.593); else the object { collectionId,
        collectionUtc, publishedUtc, copiedUtc, newestCompleteUtc }.
    #>
    param([AllowNull()][object[]]$Rows)
    if ($null -eq $Rows) { return $null }
    $r = @(@($Rows) | Where-Object { $null -ne $_ }) | Select-Object -First 1
    if ($null -eq $r) { return $null }
    $g = { param($n) $v = Get-SIHeartbeatRowValue $r $n; if ($v -is [System.DBNull]) { $null } else { $v } }
    $id = & $g 'CollectionId'; $pub = & $g 'PublishedAt'
    if ($null -eq $id -or $null -eq $pub) { return 'none' }
    New-SIHeartbeatOrdered -Names $script:SIHeartbeatFields.Fields.Published -Values @{
        collectionId = (ConvertTo-SIHeartbeatInt $id); collectionUtc = (ConvertTo-SIHeartbeatUtc (& $g 'CollectionTime')); publishedUtc = (ConvertTo-SIHeartbeatUtc $pub)
        copiedUtc = (ConvertTo-SIHeartbeatUtc (& $g 'CopiedAt')); newestCompleteUtc = (ConvertTo-SIHeartbeatUtc (& $g 'NewestComplete')) }
}

function Test-SIHeartbeatCopyStaleTooLong {
    <#
        PURE. si-data-1401 only for a copy that REALLY stays stale (owner 2026-10-29). Every publish leaves the copies of the
        merged assets to be refreshed range by range right after it (#881) -- 14 minutes on a ring 0 install, 2026-10-28, a healthy run
        that raised the warning for those minutes. -CopyRow: the row of Get-SIHeartbeatPublishedCopySql. True only when ALL hold:
          * the copies are older than the shown run (Stale = 1);
          * no refresher is writing them right now (Refreshing is not 1 -- NULL, not testable, counts as not refreshing);
          * the publish is older than twice the last refresh's own time (RefreshMs, sidata.PublishedCopy) plus 10 minutes (two
            wake-ups of the pipeline runner, which catches the copies up) -- without a measured time, 10 minutes.
        A publish time that is not known cannot be measured: the stale copy is said (as before).
    #>
    param($CopyRow, [Parameter(Mandatory)][datetime]$NowUtc)
    if ($null -eq $CopyRow) { return $false }
    $b = { param($x) ($x -eq $true) -or ([string]$x -in @('1', 'True', 'true')) }
    if (-not (& $b (Get-SIHeartbeatRowValue $CopyRow 'Stale'))) { return $false }
    if (& $b (Get-SIHeartbeatRowValue $CopyRow 'Refreshing')) { return $false }
    $pub = ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $CopyRow 'PublishedAt')
    if ($null -eq $pub) { return $true }
    $ms = 0.0; $raw = Get-SIHeartbeatRowValue $CopyRow 'RefreshMs'
    if ($null -ne $raw -and -not ($raw -is [System.DBNull])) { [void][double]::TryParse([string]$raw, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$ms) }
    $graceMin = 10.0 + [Math]::Max(0.0, 2.0 * $ms / 60000.0)
    return (($NowUtc.ToUniversalTime() - $pub).TotalMinutes -gt $graceMin)
}

function Get-SIHeartbeatHousekeepingSql {
    <#
        ONE read of the DATA database for Pipeline.housekeepingRowsLeft: the rows of retired collections still waiting to be
        removed -- the collections the removal still works on, by the retention plan's own rule (HasRows): a MARKED Detailed
        collection (sidata.Collection.RetiredAt) with sidata.Finding rows left, a MARKED Summary load (sidata.SummaryLoad)
        with sidata.SummaryRow rows left. One row: RowsLeft (NULL = the database has no retention mark yet: not known).
        THE COST -- index reads only, never a COUNT over sidata.Finding:
          * sidata.Collection and sidata.SummaryLoad are small (a row per collection);
          * per MARKED collection: the first and the last key of sidata.Finding (CollectionId, FindingId) and of
            sidata.Recommendation (CollectionId, RecommendationRowId) -- four single-row seeks on their clustered keys (an
            explicit TOP (1) ORDER BY each: MIN and MAX together can become a range scan);
          * per MARKED Summary load: one EXISTS seek on sidata.SummaryRow's clustered key (CollectionTime, ...).
        THE ACCURACY:
          * 0 is EXACT: 0 only when no marked collection has a Finding or SummaryRow row left;
          * Finding and Recommendation NEVER READ TOO LOW: the ids are unique, so the key span (last - first + 1) is at least
            the rows left; the removal goes from the lowest key up, so the span shrinks as it works. EXACT when a
            collection's ids are contiguous (one loader at a time -- the usual case), too HIGH with gaps (identity jumps
            after a failover, rolled-back inserts, two collections loading at once); Finding's span is held to the rows the
            collection loaded (sidata.Collection.Rows), which bounds that;
          * the Summary part is an UPPER BOUND: the load's Rows (what was loaded; at least 1 while rows are left), not what is
            left part way -- a Summary load is small and one wake-up usually removes it whole;
          * NOT in the size: IssueContext, RaStage, RaDefenderKey and SummaryAsset -- each collection's rows of those are
            removed BEFORE its Finding / SummaryRow rows, so while any of them are left the value is already > 0.
        Every reference to a column the retention adds is in dynamic SQL (an older schema compiles and answers NULL).
    #>
@'
SET NOCOUNT ON;
DECLARE @d bigint = NULL, @s bigint = NULL;
IF OBJECT_ID(N'sidata.Collection') IS NOT NULL AND OBJECT_ID(N'sidata.Finding') IS NOT NULL AND COL_LENGTH(N'sidata.Collection', N'RetiredAt') IS NOT NULL
BEGIN
    DECLARE @rec nvarchar(max) = CASE WHEN OBJECT_ID(N'sidata.Recommendation') IS NULL THEN N'CAST(NULL AS bigint)'
        ELSE N'(SELECT TOP (1) r.RecommendationRowId FROM sidata.Recommendation AS r WHERE r.CollectionId = c.CollectionId ORDER BY r.RecommendationRowId DESC) - (SELECT TOP (1) r.RecommendationRowId FROM sidata.Recommendation AS r WHERE r.CollectionId = c.CollectionId ORDER BY r.RecommendationRowId ASC) + 1' END;
    DECLARE @q nvarchar(max) = N'SELECT @d = ISNULL(SUM(CASE WHEN c.[Rows] > 0 AND CAST(c.[Rows] AS bigint) < x.F THEN CAST(c.[Rows] AS bigint) ELSE x.F END + ISNULL(x.R, 0)), 0)
FROM sidata.Collection AS c
CROSS APPLY (SELECT (SELECT TOP (1) f.FindingId FROM sidata.Finding AS f WHERE f.CollectionId = c.CollectionId ORDER BY f.FindingId DESC) - (SELECT TOP (1) f.FindingId FROM sidata.Finding AS f WHERE f.CollectionId = c.CollectionId ORDER BY f.FindingId ASC) + 1 AS F, ' + @rec + N' AS R) AS x
WHERE c.Kind = N''Detailed'' AND c.RetiredAt IS NOT NULL AND x.F IS NOT NULL;';
    EXEC sp_executesql @q, N'@d bigint OUTPUT', @d = @d OUTPUT;
END
IF OBJECT_ID(N'sidata.SummaryLoad') IS NOT NULL AND OBJECT_ID(N'sidata.SummaryRow') IS NOT NULL AND COL_LENGTH(N'sidata.SummaryLoad', N'RetiredAt') IS NOT NULL
    EXEC sp_executesql N'SELECT @s = ISNULL(SUM(CASE WHEN l.[Rows] > 0 THEN CAST(l.[Rows] AS bigint) ELSE CAST(1 AS bigint) END), 0)
FROM sidata.SummaryLoad AS l
WHERE l.RetiredAt IS NOT NULL AND EXISTS (SELECT 1 FROM sidata.SummaryRow AS r WHERE r.CollectionTime = l.CollectionTime);', N'@s bigint OUTPUT', @s = @s OUTPUT;
SELECT CASE WHEN @d IS NULL AND @s IS NULL THEN CAST(NULL AS bigint) ELSE ISNULL(@d, 0) + ISNULL(@s, 0) END AS RowsLeft;
'@
}

function Get-SIHeartbeatHousekeepingRowsLeft {
    <# Pipeline.housekeepingRowsLeft through -DataInvoke (Get-SIHeartbeatHousekeepingSql): a [long] >= 0, or $null when it is
       not known (no answer, an older schema, a value that is not a whole number >= 0). Throws when the read fails. #>
    param([Parameter(Mandatory)][scriptblock]$DataInvoke)
    $r = & $DataInvoke (Get-SIHeartbeatHousekeepingSql) @{} 'scalar'
    # a seam may answer rows instead of the scalar: the first row's RowsLeft
    $v = @(@($r) | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
    if ($v -is [System.Collections.IDictionary]) { $v = $v['RowsLeft'] } elseif ($null -ne $v -and $v.PSObject.Properties['RowsLeft']) { $v = $v.RowsLeft }
    if ($null -eq $v -or $v -is [System.DBNull]) { return $null }
    if (-not ($v -is [int] -or $v -is [long] -or $v -is [short] -or $v -is [byte] -or $v -is [decimal])) { return $null }
    if ($v -is [decimal] -and [decimal]::Truncate($v) -ne $v) { return $null }
    if ($v -lt 0 -or $v -gt [long]::MaxValue) { return $null }
    [long]$v
}

function Add-SIPipelineHousekeeping {
    <# PURE. -Pipeline with housekeepingRowsLeft = -RowsLeft as its LAST key (every other key and value as it was). #>
    param([Parameter(Mandatory)]$Pipeline, [Parameter(Mandatory)][long]$RowsLeft)
    $hkName = [string]$script:SIHeartbeatFields.PipelineHousekeepingField
    $o = [ordered]@{}
    foreach ($pr in $Pipeline.PSObject.Properties) { if ($pr.Name -ne $hkName) { $o[$pr.Name] = $pr.Value } }
    $o[$hkName] = $RowsLeft
    [pscustomobject]$o
}

function Get-SIHeartbeatSourcesKql {    <#
        ONE Log Analytics query: run health (SI_RunHealth_CL, the END records of the first shard) -- per engine its newest
        success in 8 days ('good'), every END that was not a success in 24 hours ('fail', at most 200, the first 600
        characters of the message), and the ingestion lag of SI's own run-health rows of the last 6 hours in seconds ('lag').
    #>
@'
let rh = SI_RunHealth_CL | where TimeGenerated > ago(8d) | where tostring(Phase) == 'End' and toint(ShardIndex) == 0
    | project T = TimeGenerated, E = tolower(tostring(Engine)), X = tolower(tostring(ExitReason)), M = substring(tostring(ErrorMessage), 0, 600);
let lagSec = toscalar(SI_RunHealth_CL | where TimeGenerated > ago(6h) | summarize avg(datetime_diff('second', ingestion_time(), TimeGenerated)));
union
 (rh | where X == 'success' | summarize T = max(T) by E | extend K = 'good', X = '', M = '', N = real(null)),
 (rh | where X != 'success' and T > ago(24h) | top 200 by T desc | extend K = 'fail', N = real(null)),
 (print K = 'lag', N = todouble(lagSec), T = now(), E = '', X = '', M = '')
| project K, T, E, X, M, N
'@
}

# =====================================================================================================================
#  The fields -- PURE over the rows
# =====================================================================================================================
function ConvertTo-SIHeartbeatJobResult {
    <# PURE. A run-record step state / a Container Apps execution status -> succeeded | failed | stopped | running, or $null. #>
    param([AllowNull()][AllowEmptyString()][string]$State)
    switch -Regex ("$State".Trim()) {
        '^(?i)(success|succeeded)$' { 'succeeded'; break }
        '^(?i)(failed|timedout|degraded)$' { 'failed'; break }
        '^(?i)(interrupted|stopped)$' { 'stopped'; break }
        '^(?i)(running|starting|processing)$' { 'running'; break }
        default { $null }
    }
}

function Get-SIHeartbeatPipeline {
    <#
        PURE. Pipeline from the cfg rows: state running (the newest run is Running), succeeded / failed (it ended so; a run
        stopped or cancelled before its end is idle -- or 'stopped' with -Stopped, #1035, its own switch, not yet agreed --
        with step / stepSinceUtc = the step it was stopped at), idle (no run recorded); the step running now (by order) and since when; the newest end
        among the runs read; nextStartUtc by the runner's own rule (Get-SIJobFlowDue) when the stored pipeline runs on its
        schedule (mode flow), and while a run is in progress the first scheduled start after now (Get-SIJobFlowNextSlot,
        #1175); null in schedules mode or when it cannot be made. $null when nothing is recorded at all.
        -Eta: the progress and estimated end follow the agreed seven (Get-SIPipelineEta over the newest run's steps, each
        job's duration in the newest succeeded run among those read, and the waiting pipeline requests).
        THE STATE FOLLOWS THE RUN RECORD, AND ONLY IT (live 2026-11-13: a run closed Succeeded at 05:44Z read "running" for
        the next hour, because an update that took the install right after was refreshing the published copies -- the
        refresher's lock, tested here since 2026-10-24, said "running" for a run that had ended, whoever held it). A run
        whose record is Succeeded / Failed / Stopped / Cancelled is never 'running': what holds the install after it (an
        update, the copies of the pages) is said by its own job (Jobs: the updater's newest execution, lastResult 'running').
    #>
    param([object[]]$Rows, [Parameter(Mandatory)][datetime]$NowUtc, [switch]$Eta, [switch]$Stopped)
    $runs = @(Get-SIHeartbeatRowsOf $Rows 'run' | Sort-Object { ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $_ 'T1') } -Descending)
    $def = @(Get-SIHeartbeatRowsOf $Rows 'def')[0]
    if (-not $runs.Count -and -not $def) { return $null }
    $v = @{ state = 'idle' }
    $top = if ($runs.Count) { $runs[0] } else { $null }
    if ($top) {
        $rid = [string](Get-SIHeartbeatRowValue $top 'Name'); if ($rid -cmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$') { $v.runId = $rid }
        $v.startedUtc = ConvertTo-SIHeartbeatUtc (Get-SIHeartbeatRowValue $top 'T1')
        $topState = [string](Get-SIHeartbeatRowValue $top 'S')
        $wasStopped = $topState -in @($script:SIHeartbeatFields.PipelineStoppedRunStates)
        switch ($topState) { 'Running' { $v.state = 'running' } 'Succeeded' { $v.state = 'succeeded' } 'Failed' { $v.state = 'failed' } default { $v.state = 'idle' } }
        # #1035: a run stopped or cancelled before its end -- 'stopped' only while its switch is on (not yet agreed), else idle
        if ($wasStopped -and $Stopped) { $v.state = [string]$script:SIHeartbeatFields.PipelineStoppedState }
        if ($v.state -eq 'running') {
            $steps = @(Get-SIHeartbeatRowsOf $Rows 'step' | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'Txt') -eq $rid -and [string](Get-SIHeartbeatRowValue $_ 'S') -in @('Running', 'Starting') } |
                       Sort-Object { [int](Get-SIHeartbeatRowValue $_ 'N1') })
            if ($steps.Count) { $v.step = ConvertTo-SIHeartbeatJobName (Get-SIHeartbeatRowValue $steps[0] 'Name'); $v.stepSinceUtc = ConvertTo-SIHeartbeatUtc (Get-SIHeartbeatRowValue $steps[0] 'T1') }
        } elseif ($wasStopped) {
            # #1035 (live 2026-11-01: a cancelled run read "idle, 12/12"): the step the run was stopped at -- the first one
            # closed Interrupted (stopped / cancelled while it ran), else the first one that ended without success
            $mine = @(Get-SIHeartbeatRowsOf $Rows 'step' | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'Txt') -eq $rid } | Sort-Object { [int](Get-SIHeartbeatRowValue $_ 'N1') })
            $at = @($mine | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'S') -eq 'Interrupted' }) + @($mine | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'S') -in @('Failed', 'TimedOut') })
            if ($at.Count) {
                $k = ConvertTo-SIHeartbeatJobName (Get-SIHeartbeatRowValue $at[0] 'Name')
                if ($k) { $v.step = $k; $v.stepSinceUtc = ConvertTo-SIHeartbeatUtc (Get-SIHeartbeatRowValue $at[0] 'T1') }
            }
        }
    }
    $ended = @($runs | Where-Object { $null -ne (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $_ 'T2')) } | Sort-Object { ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $_ 'T2') } -Descending)
    if ($ended.Count) { $v.lastEndedUtc = ConvertTo-SIHeartbeatUtc (Get-SIHeartbeatRowValue $ended[0] 'T2') }
    # #1175: the next SCHEDULED start, so Invardia judges a source against its schedule. While a run is going (its record
    # says Running) it is the first slot after now -- the schedule's own time, the same function the runner uses
    # (Get-SIJobFlowNextSlot); a run that has ended (its publish copy may still be written) takes the runner's own rule.
    # A pipeline on its own schedules (mode 'schedules') or a value that cannot be made (no definition, a definition that
    # does not read, an interval cadence while running, a runner that must resume a run that stopped) stays null.
    $topRunning = $top -and [string](Get-SIHeartbeatRowValue $top 'S') -in @('Running', 'Starting')
    if ($def -and [string](Get-SIHeartbeatRowValue $def 'Name') -ne 'schedules' -and $topRunning) {
        try {
            $d = ConvertFrom-SIJobFlowJson -Json ([string](Get-SIHeartbeatRowValue $def 'Txt'))
            $nx = Get-SIJobFlowNextSlot -Definition $d -AfterUtc $NowUtc
            if ($nx) { $v.nextStartUtc = ConvertTo-SIHeartbeatUtc $nx }
        } catch { }
    }
    elseif ($def -and [string](Get-SIHeartbeatRowValue $def 'Name') -ne 'schedules') {
        try {
            $d = ConvertFrom-SIJobFlowJson -Json ([string](Get-SIHeartbeatRowValue $def 'Txt'))
            $prev = $null
            if ($top) {
                $prev = [pscustomobject]@{ FlowRunId = [string](Get-SIHeartbeatRowValue $top 'Name'); State = [string](Get-SIHeartbeatRowValue $top 'S')
                    StartedUtc = (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $top 'T1')); EndedUtc = (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $top 'T2'))
                    HeartbeatUtc = (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $top 'T3')); LastSlotUtc = (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $top 'T4'))
                    # the run's own slot (a scheduled / catch-up run): the runner's rule of a covered slot reads it (Get-SIJobFlowCoveredSlot)
                    SlotUtc = (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $top 'Txt2')) }
            }
            $due = Get-SIJobFlowDue -Definition $d -Previous $prev -NowUtc $NowUtc
            if ($due.Action -eq 'Wait' -and $due.NextUtc) { $v.nextStartUtc = ConvertTo-SIHeartbeatUtc $due.NextUtc }
            elseif ($due.Action -eq 'Start') { $v.nextStartUtc = ConvertTo-SIHeartbeatUtc $NowUtc }
        } catch { }
    }
    if (-not $Eta) { return (New-SIHeartbeatOrdered -Names $script:SIHeartbeatFields.Fields.Pipeline -Values $v) }
    # the progress and estimated end -- over the same rows (the runs read, their steps, the queue count)
    $asStep = { param($r) [pscustomobject]@{ FlowRunId = [string](Get-SIHeartbeatRowValue $r 'Txt'); Order = (Get-SIHeartbeatRowValue $r 'N1'); Group = (Get-SIHeartbeatRowValue $r 'N2')
                                             Job = [string](Get-SIHeartbeatRowValue $r 'Name'); State = [string](Get-SIHeartbeatRowValue $r 'S')
                                             StartedUtc = (Get-SIHeartbeatRowValue $r 'T1'); EndedUtc = (Get-SIHeartbeatRowValue $r 'T2') } }
    $allSteps = @(Get-SIHeartbeatRowsOf $Rows 'step' | ForEach-Object { & $asStep $_ })
    $runList = @($runs | ForEach-Object { [pscustomobject]@{ FlowRunId = [string](Get-SIHeartbeatRowValue $_ 'Name'); State = [string](Get-SIHeartbeatRowValue $_ 'S'); StartedUtc = (Get-SIHeartbeatRowValue $_ 'T1') } })
    $topId = if ($top) { [string](Get-SIHeartbeatRowValue $top 'Name') } else { '' }
    $prev = Get-SIPipelinePreviousMinutes -Runs $runList -Steps $allSteps -ExcludeRunId $topId
    $q = @(Get-SIHeartbeatRowsOf $Rows 'queue')[0]
    $e = Get-SIPipelineEta -Steps @($allSteps | Where-Object { $topId -and $_.FlowRunId -eq $topId }) -PreviousMinutes $prev -NowUtc $NowUtc `
            -RunState $(if ($top) { [string](Get-SIHeartbeatRowValue $top 'S') } else { '' }) -Queued $(if ($q) { Get-SIHeartbeatRowValue $q 'N1' } else { $null }) `
            -StepProgress (Get-SIHeartbeatStepProgress -Rows $Rows)
    foreach ($k in $script:SIHeartbeatFields.PipelineEtaFields) { $v[$k] = $e.$k }
    $o = New-SIHeartbeatOrdered -Names (@($script:SIHeartbeatFields.Fields.Pipeline) + @($script:SIHeartbeatFields.PipelineEtaFields)) -Values $v
    # New-SIHeartbeatOrdered reads each value through $( ), which unrolls an array (one entry -> the entry, none -> null):
    # the two arrays are set again as arrays
    $o.runningSteps = [object[]]@($e.runningSteps | Where-Object { $null -ne $_ })
    $o.remainingSteps = [object[]]@($e.remainingSteps | Where-Object { $null -ne $_ })
    $o
}

# =====================================================================================================================
#  THE PIPELINE'S PROGRESS AND ESTIMATED END -- PURE (owner 2026-10-17: "give completion estimate of all env from last
#  pipeline and show est completion")
# =====================================================================================================================
function Get-SIPipelinePreviousMinutes {
    <#
        PURE. How long each job took the last time it ran well: job key -> whole minutes. -Runs { FlowRunId, State, StartedUtc },
        -Steps { FlowRunId, Job, State, StartedUtc, EndedUtc }; -ExcludeRunId = the run in progress (never its own steps).
        Per job: its successful step in the NEWEST run that succeeded; a job that did not succeed in any succeeded run read
        takes its successful step in the newest other run read (a measured time, from a run that failed elsewhere). A job
        that never succeeded in the runs read has no entry (its estimate is unknown).
    #>
    param([object[]]$Runs = @(), [object[]]$Steps = @(), [AllowEmptyString()][string]$ExcludeRunId = '')
    $out = @{}
    $order = @(@($Runs) | Where-Object { $_ -and [string]$_.FlowRunId -and [string]$_.FlowRunId -ne $ExcludeRunId } |
               Sort-Object @{ Expression = { $(if ([string]$_.State -eq 'Succeeded') { 0 } else { 1 }) } }, @{ Expression = { ConvertTo-SIHeartbeatTime $_.StartedUtc }; Descending = $true })
    foreach ($r in $order) {
        $rid = [string]$r.FlowRunId
        foreach ($s in @(@($Steps) | Where-Object { $_ -and [string]$_.FlowRunId -eq $rid -and [string]$_.State -eq 'Success' })) {
            $k = ConvertTo-SIHeartbeatJobName $s.Job
            if (-not $k -or $out.ContainsKey($k)) { continue }
            $m = ConvertTo-SIHeartbeatMinutes $s.StartedUtc $s.EndedUtc
            if ($null -ne $m) { $out[$k] = [long]$m }
        }
    }
    $out
}

function Get-SIPipelineEta {
    <#
        PURE. The progress and estimated end of ONE run: -Steps = its steps { Order, Group, Job, State, StartedUtc } (the run
        record's shape), -PreviousMinutes = job key -> minutes it took before (Get-SIPipelinePreviousMinutes), -NowUtc,
        -RunState (Running / Succeeded / Failed / ...), -Queued = the pipeline requests waiting after it.
        THE RULES:
          * stepsTotal = every step that is not switched off; stepsDone = those that ended (succeeded, failed, skipped) --
            for a run stopped or cancelled before its end (#1035) only those that ran to their end (succeeded, failed, timed out);
          * the steps of ONE GROUP run together (the runner starts a group's steps at once and waits for all of them before
            the next group: Get-SIJobFlowGroups), so a group takes as long as its LONGEST step; groups run one after another;
          * a running step: its earlier duration minus the time it has run so far -> its end (estimate 'known'); past its
            earlier duration -> 'overdue' and NO time (never a time in the past), counted as ending now; no earlier duration
            -> 'unknown';
          * a waiting step: its earlier duration (estimateMin), or null (unknown);
          * estimatedEndUtc = now + the groups still to run; null when nothing known lies ahead;
            estimateConfidence: 'overdue' (a step runs past its earlier duration -- the end is at least that), 'partial' (a
            step has no earlier duration -- the end is at least that), 'known' (every remaining step has one);
          * a run that is not Running: the counts only (no running / remaining steps, no estimate).
        Returns { stepsDone, stepsTotal, runningSteps[], remainingSteps[], estimatedEndUtc, estimateConfidence, queuedRuns }.
    #>
    # #1180 -StepProgress: job key -> @{ LastUtc; Phase; Done; Total } (each running step's own progress record, Get-SIHeartbeatStepProgress)
    param([object[]]$Steps = @(), [hashtable]$PreviousMinutes = @{}, [Parameter(Mandatory)][datetime]$NowUtc,
          [AllowEmptyString()][string]$RunState = 'Running', $Queued, [hashtable]$StepProgress = @{})
    $c = $script:SIHeartbeatFields
    $now = $NowUtc.ToUniversalTime()
    $now = $now.AddTicks(-($now.Ticks % [TimeSpan]::TicksPerSecond))
    $val = { param($o, $n) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o[$n] } } elseif ($o.PSObject.Properties[$n]) { $o.$n } }
    $norm = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($s in @($Steps)) {
        if ($null -eq $s) { continue }
        $i++
        $ord = ConvertTo-SIHeartbeatInt (& $val $s 'Order'); if ($null -eq $ord) { $ord = $i }
        $grp = ConvertTo-SIHeartbeatInt (& $val $s 'Group')
        $norm.Add([pscustomobject]@{ Order = [long]$ord; Group = $grp; Key = (ConvertTo-SIHeartbeatJobName (& $val $s 'Job')); State = ([string](& $val $s 'State')).Trim()
                                     Started = (ConvertTo-SIHeartbeatTime (& $val $s 'StartedUtc')) })
    }
    $active = @($norm | Where-Object { $_.State -ne 'Disabled' })
    $isRunning = { param($x) $x.State -in @('Running', 'Starting') }
    $isWaiting = { param($x) $x.State -eq 'Waiting' }
    $open = @($active | Where-Object { (& $isRunning $_) -or (& $isWaiting $_) })
    $done = [long]($active.Count - $open.Count)
    # #1035 (live 2026-11-01: a run cancelled at step 8 of 12 read 12/12): for a run STOPPED or CANCELLED before its end,
    # done = the steps that really ran to their end (succeeded, failed, timed out) -- never the step it was stopped in
    # (Interrupted) nor the steps it never started (Skipped)
    if ("$RunState".Trim() -in @($c.PipelineStoppedRunStates)) { $done = [long]@($active | Where-Object { $_.State -in @('Success', 'Failed', 'TimedOut') }).Count }
    $out = [ordered]@{ stepsDone = $done; stepsTotal = [long]$active.Count; runningSteps = @(); remainingSteps = @()
                       estimatedEndUtc = $null; estimateConfidence = $null; queuedRuns = (ConvertTo-SIHeartbeatInt $Queued) }
    if ("$RunState".Trim() -ne 'Running' -or -not $open.Count) { return [pscustomobject]$out }

    # the groups still to run, in order (a step without a group is a group of its own)
    $groups = @($open | Group-Object { if ($null -ne $_.Group -and $_.Group -gt 0) { 'g{0}' -f $_.Group } else { 's{0}' -f $_.Order } } |
                Sort-Object { ($_.Group | Measure-Object -Property Order -Minimum).Minimum })
    $running = New-Object System.Collections.Generic.List[object]
    $remaining = New-Object System.Collections.Generic.List[object]
    $cursor = $now; $unknown = $false; $overdue = $false
    foreach ($g in $groups) {
        $longest = 0.0
        foreach ($m in @($g.Group | Sort-Object Order)) {
            $prev = if ($m.Key -and $PreviousMinutes.ContainsKey($m.Key) -and $null -ne $PreviousMinutes[$m.Key]) { [double]$PreviousMinutes[$m.Key] } else { $null }
            if (& $isRunning $m) {
                $est = 'unknown'; $end = $null
                if ($null -eq $prev) { $unknown = $true }
                else {
                    $ran = if ($m.Started) { [Math]::Max(0.0, ($now - $m.Started).TotalMinutes) } else { 0.0 }
                    $left = $prev - $ran
                    if ($left -lt 0) { $overdue = $true; $est = 'overdue' }
                    else { $est = 'known'; $end = ConvertTo-SIHeartbeatUtc ($now.AddMinutes($left)); if ($left -gt $longest) { $longest = $left } }
                }
                if ($m.Key) {
                    $rs = [ordered]@{ step = $m.Key; sinceUtc = (ConvertTo-SIHeartbeatUtc $m.Started); prevMin = $(if ($null -ne $prev) { [long]$prev } else { $null }); endUtc = $end; estimate = $est }
                    # #1180: the step's own progress record -- each key only when known; never a time in the future
                    $sp = if ($StepProgress -and $StepProgress.ContainsKey($m.Key)) { $StepProgress[$m.Key] } else { $null }
                    # a record from before the step started belongs to an earlier run of it: not its own
                    $lp = if ($sp) { ConvertTo-SIHeartbeatTime $sp.LastUtc } else { $null }
                    if ($null -ne $lp -and $m.Started -and $lp.ToUniversalTime() -lt $m.Started.ToUniversalTime().AddSeconds(-1)) { $sp = $null }
                    if ($sp) {
                        # the tick is written by the step's own container and read here by another: a time a little AHEAD of this
                        # clock is that clock difference, not the future -- clamped to now (up to 5 min); further ahead is left out
                        # (2026-11-12: a tick written seconds before the heartbeat lost its time while its words were sent)
                        if ($null -ne $lp) {
                            $ahead = ($lp.ToUniversalTime() - $NowUtc.ToUniversalTime()).TotalMinutes
                            if ($ahead -le 0) { $rs['lastProgressUtc'] = ConvertTo-SIHeartbeatUtc $lp }
                            elseif ($ahead -le 5) { $rs['lastProgressUtc'] = ConvertTo-SIHeartbeatUtc $NowUtc }
                        }
                        $pt = ConvertTo-SIHeartbeatStepProgressText -Phase ([string]$sp.Phase) -Done $sp.Done -Total $sp.Total
                        if ($pt) { $rs['progress'] = $pt }
                    }
                    $running.Add([pscustomobject]$rs)
                }
            } else {
                if ($null -eq $prev) { $unknown = $true } elseif ($prev -gt $longest) { $longest = $prev }
                if ($m.Key) { $remaining.Add([pscustomobject][ordered]@{ step = $m.Key; group = $(if ($null -ne $m.Group) { [long]$m.Group } else { $null }); estimateMin = $(if ($null -ne $prev) { [long]$prev } else { $null }) }) }
            }
        }
        $cursor = $cursor.AddMinutes($longest)
    }
    $out.runningSteps = [object[]]@($running.ToArray() | Select-Object -First ([int]$c.MaxRunningSteps))
    $out.remainingSteps = [object[]]@($remaining.ToArray() | Select-Object -First ([int]$c.MaxRemainingSteps))
    if ($cursor -gt $now) { $out.estimatedEndUtc = ConvertTo-SIHeartbeatUtc $cursor }
    $out.estimateConfidence = $(if ($overdue) { 'overdue' } elseif ($unknown) { 'partial' } else { 'known' })
    [pscustomobject]$out
}

function ConvertTo-SIHeartbeatStepProgressText {
    <#
        PURE. #1180: a running step's progress in words for Pipeline.runningSteps[].progress (Invardia 452cb22c): from its
        progress record's phase -- the counted part after its last ': ' ("the CI build: batch 161 of 266" -> "batch 161 of
        266"); a phase without a count gets done / total added when the record has them; only the agreed characters
        (letters, digits, space and . , : % ( ) / _ -) -- every other one dropped --, spaces folded, at most 80 characters.
        $null when nothing is left (the key is then left out).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Phase, $Done = $null, $Total = $null)
    $c = $script:SIHeartbeatFields
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $num = { param($v) if ($null -eq $v -or $v -is [System.DBNull]) { -1L } else { try { [long]$v } catch { -1L } } }
    $d = & $num $Done; $t = & $num $Total
    $p = ([string]$Phase).Trim()
    $i = $p.LastIndexOf(': ')
    if ($i -ge 0 -and $p.Substring($i + 2) -match '\d') { $p = $p.Substring($i + 2) }
    elseif ($p -notmatch '\d' -and $d -ge 0) {
        $cnt = if ($t -ge 0) { '{0} of {1}' -f $d.ToString('N0', $inv), $t.ToString('N0', $inv) } else { $d.ToString('N0', $inv) }
        $p = ('{0} {1}' -f $p, $cnt).Trim()
    }
    $p = [regex]::Replace($p, ('[^{0}]' -f $c.RunningStepProgressChars), '')
    $p = [regex]::Replace($p, ' {2,}', ' ').Trim()
    if ($p.Length -gt [int]$c.RunningStepProgressMax) { $p = $p.Substring(0, [int]$c.RunningStepProgressMax).Trim() }
    if (-not $p) { return $null }
    $p
}

function Get-SIHeartbeatStepProgress {
    <# PURE. #1180: job key -> @{ LastUtc; Phase; Done; Total } from the cfg rows K 'sprog' (each running step's own progress
       record, Get-SIHeartbeatFieldsCfgSql); the newest one per job. #>
    param([object[]]$Rows)
    $out = @{}
    foreach ($r in @(Get-SIHeartbeatRowsOf $Rows 'sprog')) {
        $k = ConvertTo-SIHeartbeatJobName (Get-SIHeartbeatRowValue $r 'Name'); if (-not $k) { continue }
        $t = ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $r 'T1'); if ($null -eq $t) { continue }
        if ($out.ContainsKey($k) -and $out[$k].LastUtc -ge $t) { continue }
        $out[$k] = @{ LastUtc = $t; Phase = [string](Get-SIHeartbeatRowValue $r 'Txt'); Done = (Get-SIHeartbeatRowValue $r 'N1'); Total = (Get-SIHeartbeatRowValue $r 'N2') }
    }
    $out
}

function Test-SIPipelineHasEta {
    <# PURE. Does a Pipeline value carry the progress / estimated-end keys? #>
    param($Pipeline)
    [bool]($Pipeline -and -not ($Pipeline -is [string]) -and $Pipeline.PSObject.Properties['stepsDone'])
}

function Test-SIPipelineHasExtras {
    <# PURE. Does a Pipeline value carry any key beyond the agreed seven (the progress / estimated end, housekeepingRowsLeft)
       -- or a state not yet agreed (#1035 'stopped')? #>
    param($Pipeline)
    [bool]((Test-SIPipelineHasEta $Pipeline) -or ($Pipeline -and -not ($Pipeline -is [string]) -and ($Pipeline.PSObject.Properties[[string]$script:SIHeartbeatFields.PipelineHousekeepingField] -or $Pipeline.PSObject.Properties[[string]$script:SIHeartbeatFields.PipelineStalledField] -or ($Pipeline.PSObject.Properties['state'] -and [string]$Pipeline.state -ceq [string]$script:SIHeartbeatFields.PipelineStoppedState))))
}

function Remove-SIPipelineEta {
    <# PURE. The Pipeline value with only its agreed seven keys (what Invardia took before the estimate and
       housekeepingRowsLeft): a refusal of the newer keys resends Pipeline without ANY of them -- and with state 'idle' for
       a state not yet agreed (#1035 'stopped': the stopped run as it read before). #>
    param($Pipeline)
    if (-not (Test-SIPipelineHasExtras $Pipeline)) { return $Pipeline }
    $v = @{}; foreach ($n in $script:SIHeartbeatFields.Fields.Pipeline) { $v[$n] = $Pipeline.$n }
    if ([string]$v['state'] -ceq [string]$script:SIHeartbeatFields.PipelineStoppedState) { $v['state'] = 'idle' }
    New-SIHeartbeatOrdered -Names $script:SIHeartbeatFields.Fields.Pipeline -Values $v
}

function ConvertFrom-SIHeartbeatArmJob {
    <# PURE. One Container Apps job (ARM) -> @{ Name; Key; Cpu; MemoryGi; TimeoutHours; Cron; Trigger }. #>
    param($Job)
    $p = if ($Job -and $Job.PSObject.Properties['properties']) { $Job.properties } else { $null }
    $cfg = if ($p -and $p.PSObject.Properties['configuration']) { $p.configuration } else { $null }
    $res = $null
    try { $res = @($p.template.containers)[0].resources } catch { $res = $null }
    $mem = $null
    if ($res -and $res.PSObject.Properties['memory']) { $m = [regex]::Match([string]$res.memory, '^\s*([0-9]+(\.[0-9]+)?)\s*Gi\s*$'); if ($m.Success) { $mem = ConvertTo-SIHeartbeatNumber $m.Groups[1].Value } }
    $to = $null; if ($cfg -and $cfg.PSObject.Properties['replicaTimeout']) { $sec = ConvertTo-SIHeartbeatNumber $cfg.replicaTimeout; if ($null -ne $sec) { $to = [double][Math]::Round($sec / 3600, 2) } }
    $cron = ''; try { if ($cfg.scheduleTriggerConfig.cronExpression) { $cron = [string]$cfg.scheduleTriggerConfig.cronExpression } } catch { }
    # #732: when the job was last changed (ARM systemData) -- since when a trigger it has now holds
    $mod = $null; try { if ($Job.PSObject.Properties['systemData'] -and $Job.systemData -and $Job.systemData.PSObject.Properties['lastModifiedAt']) { $mod = $Job.systemData.lastModifiedAt } } catch { }
    [pscustomobject]@{ Name = [string]$Job.name; Key = (ConvertTo-SIHeartbeatJobName $Job.name); Modified = $mod
        Cpu = $(if ($res -and $res.PSObject.Properties['cpu']) { ConvertTo-SIHeartbeatNumber $res.cpu } else { $null }); MemoryGi = $mem; TimeoutHours = $to
        Cron = $cron; Trigger = $(if ($cfg -and $cfg.PSObject.Properties['triggerType']) { [string]$cfg.triggerType } else { '' }) }
}

function Get-SIHeartbeatExecutionSummary {
    <#
        PURE. A job's Container Apps executions -> @{ Start; End; Result; Duration; PrevDuration } of the newest one (by
        startTime) and the duration of the newest FINISHED one before it. A Failed execution without an endTime has no end
        and no duration (never guessed). $null when there is none.
    #>
    param([object[]]$Executions)
    $x = @(@($Executions) | Where-Object { $_ } | ForEach-Object {
        $p = if ($_.PSObject.Properties['properties']) { $_.properties } else { $_ }
        [pscustomobject]@{ Start = (ConvertTo-SIHeartbeatTime $p.startTime); End = $(if ($p.PSObject.Properties['endTime']) { ConvertTo-SIHeartbeatTime $p.endTime } else { $null }); Status = [string]$p.status }
    } | Where-Object { $null -ne $_.Start } | Sort-Object Start -Descending)
    if (-not $x.Count) { return $null }
    $n = $x[0]
    $prev = @($x | Select-Object -Skip 1 | Where-Object { $null -ne $_.End } | Select-Object -First 1)
    [pscustomobject]@{ Start = $n.Start; End = $n.End; Result = (ConvertTo-SIHeartbeatJobResult $n.Status)
        Duration = (ConvertTo-SIHeartbeatMinutes $n.Start $n.End); PrevDuration = $(if ($prev.Count) { ConvertTo-SIHeartbeatMinutes $prev[0].Start $prev[0].End } else { $null }) }
}

function Get-SIHeartbeatJobs {
    <#
        PURE. Jobs: every pipeline step of the runs read (its newest record that started; the duration of its newest finished
        record before that), in the newest run's order; then the jobs that are never a step (-Executions: key -> the
        executions of that job); cpu / memory / run limit from -ArmJobs (ConvertFrom-SIHeartbeatArmJob). At most 30.
    #>
    param([object[]]$Rows, [object[]]$ArmJobs = @(), [System.Collections.IDictionary]$Executions = @{})
    $arm = @{}; foreach ($a in @($ArmJobs)) { if ($a -and $a.Key) { $arm[$a.Key] = $a } }
    $steps = @(Get-SIHeartbeatRowsOf $Rows 'step' | Where-Object { $null -ne (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $_ 'T1')) })
    $runOrder = @{}; $i = 0
    foreach ($r in @(Get-SIHeartbeatRowsOf $Rows 'run' | Sort-Object { ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $_ 'T1') } -Descending)) { $runOrder[[string](Get-SIHeartbeatRowValue $r 'Name')] = $i++ }
    $byJob = [ordered]@{}
    foreach ($s in @($steps | Sort-Object @{ Expression = { $o = $runOrder[[string](Get-SIHeartbeatRowValue $_ 'Txt')]; if ($null -eq $o) { 999 } else { $o } } }, @{ Expression = { [int](Get-SIHeartbeatRowValue $_ 'N1') } })) {
        $k = ConvertTo-SIHeartbeatJobName (Get-SIHeartbeatRowValue $s 'Name'); if (-not $k) { continue }
        if (-not $byJob.Contains($k)) { $byJob[$k] = New-Object System.Collections.Generic.List[object] }
        $byJob[$k].Add($s)
    }
    $out = New-Object System.Collections.Generic.List[object]
    $mk = { param($k, $start, $end, $res, $dur, $prev)
        $a = $arm[$k]
        New-SIHeartbeatOrdered -Names $script:SIHeartbeatFields.Fields.Jobs -Values @{ name = $k; lastStartUtc = (ConvertTo-SIHeartbeatUtc $start); lastEndUtc = (ConvertTo-SIHeartbeatUtc $end)
            lastResult = $res; durationMin = $dur; prevDurationMin = $prev
            cpu = $(if ($a) { $a.Cpu } else { $null }); memoryGi = $(if ($a) { $a.MemoryGi } else { $null }); timeoutHours = $(if ($a) { $a.TimeoutHours } else { $null }) } }
    foreach ($k in @($byJob.Keys)) {
        # .ToArray(): @() around a List[object] throws "Argument types do not match"
        $recs = $byJob[$k].ToArray()
        $n = $recs[0]
        $res = ConvertTo-SIHeartbeatJobResult ([string](Get-SIHeartbeatRowValue $n 'S'))
        if ($null -eq $res -and [string](Get-SIHeartbeatRowValue $n 'S') -eq 'Skipped') { $res = 'stopped' }
        $end = $(if ($res -eq 'running') { $null } else { Get-SIHeartbeatRowValue $n 'T2' })
        $prev = @($recs | Select-Object -Skip 1 | Where-Object { $null -ne (ConvertTo-SIHeartbeatMinutes (Get-SIHeartbeatRowValue $_ 'T1') (Get-SIHeartbeatRowValue $_ 'T2')) } | Select-Object -First 1)
        $out.Add((& $mk $k (Get-SIHeartbeatRowValue $n 'T1') $end $res (ConvertTo-SIHeartbeatMinutes (Get-SIHeartbeatRowValue $n 'T1') $end) $(if ($prev.Count) { ConvertTo-SIHeartbeatMinutes (Get-SIHeartbeatRowValue $prev[0] 'T1') (Get-SIHeartbeatRowValue $prev[0] 'T2') } else { $null })))
    }
    foreach ($k in @($Executions.Keys)) {
        if ($byJob.Contains($k) -or -not (ConvertTo-SIHeartbeatJobName $k)) { continue }
        $e = Get-SIHeartbeatExecutionSummary -Executions @($Executions[$k])
        if ($e) { $out.Add((& $mk $k $e.Start $e.End $e.Result $e.Duration $e.PrevDuration)) }
        elseif ($arm.ContainsKey($k)) { $out.Add((& $mk $k $null $null $null $null $null)) }
    }
    # unrolled: callers take @( ... ) (a leading comma would hand them ONE nested array)
    if (-not $out.Count) { return }
    $out.ToArray() | Select-Object -First ([int]$script:SIHeartbeatFields.MaxJobs)
}

function Get-SIHeartbeatSourceOf {
    <# PURE. The source one failure names: by its class (graph-403 -> graph ...), else by its text; nothing when it names none. #>
    param([AllowEmptyString()][string]$Message, [AllowEmptyString()][string]$Class)
    $c = $script:SIHeartbeatFields
    if ($Class -and $c.ClassSources.ContainsKey($Class)) { return [string]$c.ClassSources[$Class] }
    foreach ($s in $c.SourcePatterns.Keys) { if ("$Message" -match $c.SourcePatterns[$s]) { return [string]$s } }
}

function Get-SIHeartbeatSources {
    <#
        PURE. Sources from the run-health rows (Get-SIHeartbeatSourcesKql) -- per source:
          lastGoodUtc    the newest successful run of an engine that reads it (logAnalytics: now, when the query answered)
          lastErrorCode  the error class of the newest failed run in 24 hours that named it (null when none)
          retries24h     the runs in 24 hours that ended without success on it (each is retried by the next run)
          throttled24h   of them, the runs that were throttled (class / exit reason 'throttled')
          lagMin         logAnalytics only: the ingestion lag of SI's own run-health rows (null when unreadable)
        -Failed: the query could not be read (its error text) -- then logAnalytics alone, with that error's class.
        A source with nothing known is left out. $null when nothing is left.
    #>
    param([object[]]$Rows, [Parameter(Mandatory)][datetime]$NowUtc, [AllowEmptyString()][string]$Failed)
    $c = $script:SIHeartbeatFields
    $acc = [ordered]@{}; foreach ($s in $c.Sources) { $acc[$s] = @{ good = $null; code = $null; codeAt = $null; retries = 0L; throttled = 0L; lag = $null; seen = $false } }
    if ("$Failed".Trim()) {
        $acc['logAnalytics'].code = ConvertTo-SIHeartbeatErrorCode (Get-SIErrorClass -Message $Failed); $acc['logAnalytics'].seen = $true
    } else {
        $acc['logAnalytics'].good = $NowUtc.ToUniversalTime(); $acc['logAnalytics'].seen = $true
        foreach ($r in @(Get-SIHeartbeatRowsOf $Rows 'good')) {
            $t = ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $r 'T'); if ($null -eq $t) { continue }
            $e = ([string](Get-SIHeartbeatRowValue $r 'E')).ToLowerInvariant()
            foreach ($s in @($c.EngineSources[$e])) { if (-not $s) { continue }; $a = $acc[$s]; $a.seen = $true; if ($s -ne 'logAnalytics' -and ($null -eq $a.good -or $t -gt $a.good)) { $a.good = $t } }
        }
        foreach ($r in @(Get-SIHeartbeatRowsOf $Rows 'fail')) {
            $t = ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $r 'T'); if ($null -eq $t -or ($NowUtc - $t).TotalHours -gt 24) { continue }
            $m = [string](Get-SIHeartbeatRowValue $r 'M'); $x = [string](Get-SIHeartbeatRowValue $r 'X')
            $cls = Get-SIErrorClass -Message $m -ExitReason $x
            foreach ($s in @(Get-SIHeartbeatSourceOf -Message $m -Class $cls)) {
                $a = $acc[$s]; $a['seen'] = $true; $a['retries'] = $a['retries'] + 1
                if ($cls -eq 'throttled' -or $x -eq 'throttled') { $a['throttled'] = $a['throttled'] + 1 }
                if ($null -eq $a.codeAt -or $t -gt $a.codeAt) { $a.codeAt = $t; $a.code = ConvertTo-SIHeartbeatErrorCode $cls }
            }
        }
        $lag = @(Get-SIHeartbeatRowsOf $Rows 'lag')[0]
        if ($lag) { $sec = ConvertTo-SIHeartbeatNumber (Get-SIHeartbeatRowValue $lag 'N'); if ($null -ne $sec) { $acc['logAnalytics'].lag = [long][Math]::Round($sec / 60, [MidpointRounding]::AwayFromZero) } }
    }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($s in $acc.Keys) {
        $a = $acc[$s]; if (-not $a.seen) { continue }
        $out.Add((New-SIHeartbeatOrdered -Names $c.Fields.Sources -Values @{ source = $s; lastGoodUtc = (ConvertTo-SIHeartbeatUtc $a.good); lastErrorCode = $a.code
            retries24h = $(if ("$Failed".Trim()) { $null } else { [long]$a.retries }); throttled24h = $(if ("$Failed".Trim()) { $null } else { [long]$a.throttled }); lagMin = $a.lag
            # the newest failure time rides along for Warnings (removed before the field goes on the record)
        }))
        $out[$out.Count - 1] | Add-Member -NotePropertyName '_failedAt' -NotePropertyValue $a.codeAt
    }
    if (-not $out.Count) { return }
    $out.ToArray() | Select-Object -First ([int]$c.MaxSources)
}

function ConvertTo-SIHeartbeatSourcesWire {
    <# PURE. Sources without the helper property (the agreed fields only), unrolled. #>
    param([object[]]$Sources)
    @($Sources) | Where-Object { $_ } | ForEach-Object { New-SIHeartbeatOrdered -Names $script:SIHeartbeatFields.Fields.Sources -Values @{ source = $_.source; lastGoodUtc = $_.lastGoodUtc; lastErrorCode = $_.lastErrorCode; retries24h = $_.retries24h; throttled24h = $_.throttled24h; lagMin = $_.lagMin } }
}

function Get-SIHeartbeatDatabase {
    <#
        PURE. Database from the ARM database (-Db: sku.tier, sku.capacity) and its metrics of the last hour (-Metrics: an ARM
        metrics answer, one value per minute, Maximum): tier; dtu (the capacity of a DTU tier -- Basic / Standard / Premium --
        null for vCore); the highest log write percent; the minutes at or above 99 % of any limit read.
        #904: -Space @{ sqlUsedMb; sqlMaxMb } (ConvertFrom-SISqlSpaceValue: the data files' used space, the maximum size) ->
        usedMb / maxSizeMb (null when not read). $null when neither -Db nor a size is known.
    #>
    param($Db, $Metrics, [System.Collections.IDictionary]$Space)
    $used = $null; $max = $null
    if ($Space) {
        if ($Space.Contains('sqlUsedMb')) { $used = ConvertTo-SIHeartbeatInt $Space['sqlUsedMb'] }
        if ($Space.Contains('sqlMaxMb')) { $max = ConvertTo-SIHeartbeatInt $Space['sqlMaxMb']; if ($null -ne $max -and $max -le 0) { $max = $null } }
    }
    if ($null -eq $Db -and $null -eq $used -and $null -eq $max) { return $null }
    $tier = $null; $cap = $null
    if ($null -ne $Db) { try { $tier = [string]$Db.sku.tier; $cap = $Db.sku.capacity } catch { } }
    if (-not ($tier -cmatch '^[A-Za-z][A-Za-z0-9]{0,31}$')) { $tier = $null }
    $dtu = if ($tier -in @('Basic', 'Standard', 'Premium')) { ConvertTo-SIHeartbeatInt $cap } else { $null }
    $peak = $null; $atLimit = $null
    if ($Metrics -and $Metrics.PSObject.Properties['value']) {
        $minutes = @{}
        foreach ($m in @($Metrics.value)) {
            $name = ''; try { $name = [string]$m.name.value } catch { }
            foreach ($ts in @($m.timeseries)) { foreach ($d in @($ts.data)) {
                $v = ConvertTo-SIHeartbeatNumber $d.maximum; if ($null -eq $v) { continue }
                if ($name -eq 'log_write_percent' -and ($null -eq $peak -or $v -gt $peak)) { $peak = $v }
                if ($v -ge $script:SIHeartbeatFields.LimitPct) { $minutes[[string]$d.timeStamp] = 1 }
            } }
        }
        $atLimit = [long][Math]::Min(60, $minutes.Count)
    }
    New-SIHeartbeatOrdered -Names $script:SIHeartbeatFields.Fields.Database -Values @{ tier = $tier; dtu = $dtu; maxSizeMb = $max; usedMb = $used
        peakLogWritePct1h = $(if ($null -ne $peak) { [long][Math]::Min(100, [Math]::Round($peak, [MidpointRounding]::AwayFromZero)) } else { $null }); minutesAtLimit1h = $atLimit }
}

function Get-SIHeartbeatDatabaseStatsSql {
    <#
        #1210 ONE read of the database (catalog views only, no table data): one row Async (bit: AUTO_UPDATE_STATISTICS_ASYNC),
        Total (the statistics counted), Stale (of them, the ones whose changes exceed DatabaseStatsStalePct % of their rows +
        DatabaseStatsStaleRows). WHAT IS COUNTED: every statistic of every user table (not shipped by Microsoft, not of a
        hypothetical index) that HAS been computed (sys.dm_db_stats_properties answers with a time) -- of the tables this
        identity may read (the function answers only for a table whose columns the caller may SELECT; the engine's role reads
        every schema SI writes in bulk). A lock that does not come within 5 seconds = the read fails (the keys are left out).
    #>
    $c = $script:SIHeartbeatFields
    $pct = [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{0:0.##}', [double]$c.DatabaseStatsStalePct / 100.0)
    $rows = [int]$c.DatabaseStatsStaleRows
@"
SET NOCOUNT ON;
SET LOCK_TIMEOUT 5000;
SELECT CONVERT(bit, (SELECT d.is_auto_update_stats_async_on FROM sys.databases AS d WHERE d.database_id = DB_ID())) AS Async,
       COUNT_BIG(*) AS Total,
       ISNULL(SUM(CASE WHEN ISNULL(sp.modification_counter, 0) > $pct * ISNULL(sp.rows, 0) + $rows THEN 1 ELSE 0 END), 0) AS Stale
FROM sys.stats AS s
JOIN sys.tables AS t ON t.object_id = s.object_id AND t.is_ms_shipped = 0
LEFT JOIN sys.indexes AS i ON i.object_id = s.object_id AND i.index_id = s.stats_id
CROSS APPLY sys.dm_db_stats_properties(s.object_id, s.stats_id) AS sp
WHERE ISNULL(i.is_hypothetical, 0) = 0 AND sp.last_updated IS NOT NULL;
"@
}

function Test-SIHeartbeatStatStale {
    <# PURE. #1210 the rule of statsStalePct for ONE statistic: its changes exceed DatabaseStatsStalePct % of its rows +
       DatabaseStatsStaleRows (20 % + 500) -- the same rule as Get-SIHeartbeatDatabaseStatsSql. #>
    param([double]$Rows, [double]$Changes)
    $c = $script:SIHeartbeatFields
    $Changes -gt (([double]$c.DatabaseStatsStalePct / 100.0) * $Rows + [double]$c.DatabaseStatsStaleRows)
}

function ConvertFrom-SIHeartbeatDatabaseStats {
    <# PURE. #1210 the row of Get-SIHeartbeatDatabaseStatsSql -> @{ statsAsync [bool]; statsStalePct [double] 0-100, one
       decimal }, or $null when it is not a whole answer (then the keys are left out). No statistic counted = 0 %. #>
    param([object[]]$Rows)
    $r = @(@($Rows) | Where-Object { $null -ne $_ })[0]
    if ($null -eq $r) { return $null }
    $async = Get-SIHeartbeatRowValue $r 'Async'
    if ($null -eq $async -or $async -is [DBNull]) { return $null }
    $a = $null
    if ($async -is [bool]) { $a = $async } elseif ("$async" -in @('1', 'True', 'true')) { $a = $true } elseif ("$async" -in @('0', 'False', 'false')) { $a = $false }
    if ($null -eq $a) { return $null }
    $total = ConvertTo-SIHeartbeatInt (Get-SIHeartbeatRowValue $r 'Total'); $stale = ConvertTo-SIHeartbeatInt (Get-SIHeartbeatRowValue $r 'Stale')
    if ($null -eq $total -or $null -eq $stale -or $stale -gt $total) { return $null }
    $p = if ($total -eq 0) { 0.0 } else { [double][Math]::Round(100.0 * $stale / $total, 1, [MidpointRounding]::AwayFromZero) }
    [ordered]@{ statsAsync = [bool]$a; statsStalePct = [double]$p }
}

function Get-SIHeartbeatStatsRefreshedUtc {
    <# PURE. #1210 the last statistics refresh SI recorded after its writes: the K 'state' row 'StatisticsRefresh' of the
       settings read (its UpdatedAt), ISO-8601 UTC; $null when none is recorded yet. #>
    param([object[]]$Rows)
    $r = @(Get-SIHeartbeatRowsOf $Rows 'state' | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'Name') -eq [string]$script:SIHeartbeatFields.DatabaseStatsState })[0]
    if ($null -eq $r) { return $null }
    $t = ConvertTo-SIHeartbeatUtc (Get-SIHeartbeatRowValue $r 'T1')
    if ($t) { $t } else { $null }
}

function Add-SIHeartbeatDatabaseStats {
    <# PURE. #1210 Database with the three statistics keys after its agreed six: -Stats (ConvertFrom-SIHeartbeatDatabaseStats)
       and -RefreshedUtc. -Stats $null = Database as it is (the read failed: no key added). #>
    param([Parameter(Mandatory)]$Database, [System.Collections.IDictionary]$Stats, [AllowNull()][AllowEmptyString()][string]$RefreshedUtc)
    if ($null -eq $Stats) { return $Database }
    $o = [ordered]@{}
    foreach ($n in @($script:SIHeartbeatFields.Fields.Database)) { $o[$n] = $Database.$n }
    $o['statsAsync'] = [bool]$Stats['statsAsync']
    $o['statsStalePct'] = [double]$Stats['statsStalePct']
    $o['statsRefreshedUtc'] = $(if ($RefreshedUtc) { $RefreshedUtc } else { $null })
    [pscustomobject]$o
}

function Get-SIHeartbeatCronNext {
    <#
        PURE. The next time a 5-field cron (UTC: minute hour day-of-month month day-of-week; * , - / supported) fires after
        -NowUtc, within 8 days; $null when it cannot be read.
    #>
    param([AllowEmptyString()][string]$Cron, [Parameter(Mandatory)][datetime]$NowUtc)
    try {
        $f = @("$Cron".Trim() -split '\s+')
        if ($f.Count -ne 5) { return $null }
        $expand = { param([string]$spec, [int]$lo, [int]$hi)
            $set = New-Object System.Collections.Generic.HashSet[int]
            foreach ($part in $spec.Split(',')) {
                $step = 1; $range = $part
                if ($part -match '^(.+)/(\d+)$') { $range = $Matches[1]; $step = [int]$Matches[2]; if ($step -lt 1) { throw 'step' } }
                if ($range -eq '*') { $a = $lo; $b = $hi } elseif ($range -match '^(\d+)-(\d+)$') { $a = [int]$Matches[1]; $b = [int]$Matches[2] } elseif ($range -match '^\d+$') { $a = [int]$range; $b = $(if ($part -match '/') { $hi } else { $a }) } else { throw 'field' }
                for ($v = $a; $v -le $b; $v += $step) { if ($v -ge $lo -and $v -le $hi) { [void]$set.Add($v) } }
            }
            , @($set | Sort-Object) }
        $min = & $expand $f[0] 0 59; $hr = & $expand $f[1] 0 23; $dom = & $expand $f[2] 1 31; $mon = & $expand $f[3] 1 12; $dow = @((& $expand $f[4] 0 7) | ForEach-Object { $_ % 7 } | Select-Object -Unique)
        $domAny = ($f[2] -eq '*'); $dowAny = ($f[4] -eq '*')
        $n = [datetime]::SpecifyKind($NowUtc.ToUniversalTime(), 'Utc')
        $start = $n.AddSeconds(-$n.Second).AddMilliseconds(-$n.Millisecond).AddMinutes(1)
        for ($d = 0; $d -le 8; $d++) {
            $day = $start.Date.AddDays($d)
            if ($mon -notcontains $day.Month) { continue }
            $domOk = $dom -contains $day.Day; $dowOk = $dow -contains [int]$day.DayOfWeek
            $ok = if ($domAny -and $dowAny) { $true } elseif ($domAny) { $dowOk } elseif ($dowAny) { $domOk } else { $domOk -or $dowOk }
            if (-not $ok) { continue }
            foreach ($h in $hr) { foreach ($m in $min) {
                $t = $day.AddHours($h).AddMinutes($m)
                if ($t -ge $start) { return [datetime]::SpecifyKind($t, 'Utc') }
            } }
        }
        $null
    } catch { $null }
}

function Get-SIHeartbeatUpdate {
    <#
        PURE. Update from the cfg rows (cfg.InstallState 'UpdateState', the compact state the updater writes) and what this
        job knows: installed = the release this job runs (-Installed); available = the version of the updater's last code
        manifest; lastUpdaterRunUtc = its last check; lastUpdaterResult: failed (an error, or the manifest was refused /
        not answered / the roll did not reach it), succeeded (the manifest's update is applied), nothing-to-do (current,
        held, deferred, off); nextUpdateUtc = the next tick of the updater's timer (-UpdaterCron).
    #>
    param([object[]]$Rows, [AllowEmptyString()][string]$Installed, [AllowEmptyString()][string]$UpdaterCron, [Parameter(Mandatory)][datetime]$NowUtc)
    $v = @{}
    $vre = '^[0-9][0-9A-Za-z.+-]{0,63}$'
    if ("$Installed".Trim() -cmatch $vre) { $v.installed = "$Installed".Trim() }
    $row = @(Get-SIHeartbeatRowsOf $Rows 'state' | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'Name') -eq 'UpdateState' })[0]
    if ($row) {
        $o = $null; try { $o = [string](Get-SIHeartbeatRowValue $row 'Txt') | ConvertFrom-Json -ErrorAction Stop } catch { $o = $null }
        if ($o) {
            if ($o.PSObject.Properties['lastCheckUtc']) { $v.lastUpdaterRunUtc = ConvertTo-SIHeartbeatUtc $o.lastCheckUtc }
            $code = if ($o.PSObject.Properties['code']) { $o.code } else { $null }
            $err = if ($o.PSObject.Properties['error']) { "$($o.error)".Trim() } else { '' }
            if ($code) {
                if ("$($code.version)".Trim() -cmatch $vre) { $v.available = "$($code.version)".Trim() }
                $act = "$($code.action)".Trim().ToLowerInvariant()
                $seq = ConvertTo-SIHeartbeatCount $code.sequence; $app = $code.applied
                $v.lastUpdaterResult = switch ($act) {
                    'update' { if ($null -ne $seq -and $null -ne $app -and [long]$app -ge [long]$seq) { 'succeeded' } else { 'failed' } }
                    { $_ -in @('current', 'none', 'off', 'hold', 'held', 'deferred', 'waiting') } { 'nothing-to-do' }
                    { $_ -in @('refused', 'error', 'unauthorized', 'forbidden', 'notfound', 'invalid', 'network') } { 'failed' }
                    default { $null }
                }
                if ($err -and $v.lastUpdaterResult -ne 'failed') { $v.lastUpdaterResult = 'failed' }
            } elseif ($err) { $v.lastUpdaterResult = 'failed' }
        }
    }
    if ("$UpdaterCron".Trim()) { $v.nextUpdateUtc = ConvertTo-SIHeartbeatUtc (Get-SIHeartbeatCronNext -Cron $UpdaterCron -NowUtc $NowUtc) }
    if (-not $v.Count) { return $null }
    New-SIHeartbeatOrdered -Names $script:SIHeartbeatFields.Fields.Update -Values $v
}

function ConvertTo-SIHeartbeatMailRestriction {
    <# PURE. cfg.InstallState 'MailRestriction' (state) / an attestation -> verified | not-verified | failed, or $null. #>
    param([AllowNull()][AllowEmptyString()][string]$Json, [AllowNull()][AllowEmptyString()][string]$Attestation)
    $st = ''
    if ("$Json".Trim()) { try { $st = [string]($Json | ConvertFrom-Json -ErrorAction Stop).state } catch { $st = '' } }
    switch ($st) {
        { $_ -in @('verified', 'legacy-policy') } { return 'verified' }
        'unverified' { if ("$Attestation".Trim()) { return 'verified' }; return 'not-verified' }
        { $_ -in @('unrestricted', 'not-granted', 'error') } { return 'failed' }
    }
    if ("$Attestation".Trim()) { return 'verified' }
    $null
}

function Get-SIHeartbeatMail {
    <#
        PURE. Mail from the cfg rows: mailJob present / missing (-ArmJobs: the job list; $null = not read -> null);
        lastSentUtc = the newest mail handed over by ANY SecurityInsight mail -- cfg.InstallState 'MailLastSent' (written by
        the one transport, Send-SIMail, for every mail: close-loop, Risk Analysis, guard, management summary, exemption,
        ...) or the newest sent mail of the two outboxes, whichever is newer; lastFailedUtc = the newest failed send --
        cfg.InstallState 'MailLastFailed' or the end of a FAILED mail step in the runs read, whichever is newer;
        lastErrorCode = the class of the newest failure (that failed send, or the newest unsent outbox mail's error);
        restriction from cfg.InstallState 'MailRestriction' (+ an Exchange administrator's attestation); queued = mails
        waiting to go out (sign-in mails only for a day -- older ones are never sent). $null when nothing is known.
    #>
    param([object[]]$Rows, [AllowNull()][object[]]$ArmJobs)
    $c = $script:SIHeartbeatFields
    $v = @{}
    if ($null -ne $ArmJobs) { $v.mailJob = $(if (@($ArmJobs | Where-Object { $_ -and $_.Name -eq $c.MailJob }).Count) { 'present' } else { 'missing' }) }
    $stateRow = { param($n) @(Get-SIHeartbeatRowsOf $Rows 'state' | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'Name') -eq $n })[0] }
    $state = { param($n) $r = & $stateRow $n; if ($r) { [string](Get-SIHeartbeatRowValue $r 'Txt') } else { '' } }
    # the send record of the one transport: { utc, mode[, error] }; its time = utc, else the row's UpdatedAt
    $record = {
        param($n)
        $r = & $stateRow $n; if (-not $r) { return $null }
        $o = $null; try { $o = [string](Get-SIHeartbeatRowValue $r 'Txt') | ConvertFrom-Json -ErrorAction Stop } catch { $o = $null }
        $t = $null; if ($o -and $o.PSObject.Properties['utc']) { $t = ConvertTo-SIHeartbeatTime $o.utc }
        if ($null -eq $t) { $t = ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $r 'T1') }
        if ($null -eq $t) { return $null }
        [pscustomobject]@{ Time = $t; Error = $(if ($o -and $o.PSObject.Properties['error']) { [string]$o.error } else { '' }) }
    }
    $sentTimes = New-Object System.Collections.Generic.List[datetime]
    # failures: @{ Time; Code; Failed (counts for lastFailedUtc -- an outbox row's time is when it was queued, so it only names the code) }
    $fails = New-Object System.Collections.Generic.List[object]
    $mail = @(Get-SIHeartbeatRowsOf $Rows 'mail')
    if ($mail.Count) {
        foreach ($m in $mail) { $t = ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $m 'T1'); if ($null -ne $t) { $sentTimes.Add($t) } }
        $q = 0L; foreach ($m in $mail) { $n = ConvertTo-SIHeartbeatCount (Get-SIHeartbeatRowValue $m 'N1'); if ($null -ne $n) { $q += $n } }; $v.queued = $q
        foreach ($m in @($mail | Where-Object { "$(Get-SIHeartbeatRowValue $_ 'Txt')".Trim() })) {
            $fails.Add([pscustomobject]@{ Time = (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $m 'T2')); Failed = $false
                                          Code = (ConvertTo-SIHeartbeatErrorCode (Get-SIErrorClass -Message ([string](Get-SIHeartbeatRowValue $m 'Txt')))) })
        }
    }
    $ls = & $record 'MailLastSent'; if ($ls) { $sentTimes.Add($ls.Time) }
    $lf = & $record 'MailLastFailed'
    if ($lf) { $fails.Add([pscustomobject]@{ Time = $lf.Time; Failed = $true; Code = $(if ($lf.Error.Trim()) { ConvertTo-SIHeartbeatErrorCode (Get-SIErrorClass -Message $lf.Error) } else { $null }) }) }
    foreach ($f in @(Get-SIHeartbeatRowsOf $Rows 'step' | Where-Object { (ConvertTo-SIHeartbeatJobName (Get-SIHeartbeatRowValue $_ 'Name')) -eq 'close-loop-mail' -and (ConvertTo-SIHeartbeatJobResult ([string](Get-SIHeartbeatRowValue $_ 'S'))) -eq 'failed' })) {
        $t = ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $f 'T2'); if ($null -eq $t) { $t = ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $f 'T1') }
        if ($null -ne $t) { $fails.Add([pscustomobject]@{ Time = $t; Failed = $true; Code = (ConvertTo-SIHeartbeatErrorCode ([string](Get-SIHeartbeatRowValue $f 'Txt2'))) }) }
    }
    if ($sentTimes.Count) { $v.lastSentUtc = ConvertTo-SIHeartbeatUtc (@($sentTimes | Sort-Object -Descending)[0]) }
    $failedOnes = @($fails | Where-Object { $_.Failed } | Sort-Object { $_.Time } -Descending)
    if ($failedOnes.Count) { $v.lastFailedUtc = ConvertTo-SIHeartbeatUtc $failedOnes[0].Time }
    # the newest failure that names a class (an outbox row without a time counts as the oldest)
    $coded = @($fails | Where-Object { $_.Code } | Sort-Object { if ($null -eq $_.Time) { [datetime]::MinValue } else { $_.Time } } -Descending)
    if ($coded.Count) { $v.lastErrorCode = $coded[0].Code }
    $rs = ConvertTo-SIHeartbeatMailRestriction -Json (& $state 'MailRestriction') -Attestation (& $state 'MailRestrictionAttestation')
    if ($rs) { $v.restriction = $rs }
    if (-not $v.Count) { return $null }
    # restriction is REQUIRED by Invardia's validator (verified | not-verified | failed): a null / missing one drops the whole
    # Mail field there (live 2026-10-17: Detail.Dropped = Mail.restriction). Unknown = not verified.
    if (-not $v.ContainsKey('restriction') -or -not "$($v.restriction)".Trim()) { $v.restriction = 'not-verified' }
    New-SIHeartbeatOrdered -Names $c.Fields.Mail -Values $v
}

function Get-SIHeartbeatLongRun {
    <#
        PURE. si-flow-1203 over the cfg rows the heartbeat already read (Get-SIHeartbeatFieldsCfgSql: K 'run' -- Txt = its
        FromStep --, 'runscope' -- S = its Scope, absent on an older schema --, 'step'): Get-SIPipelineLongRun for the
        NEWEST run against the usual lengths of the other runs read. Nothing when the newest run is not Running.
    #>
    param([object[]]$Rows, [Parameter(Mandatory)][datetime]$NowUtc)
    $scopeOf = @{}
    foreach ($x in @(Get-SIHeartbeatRowsOf $Rows 'runscope')) { $scopeOf[[string](Get-SIHeartbeatRowValue $x 'Name')] = [string](Get-SIHeartbeatRowValue $x 'S') }
    $runs = @(Get-SIHeartbeatRowsOf $Rows 'run' | ForEach-Object {
        $id = [string](Get-SIHeartbeatRowValue $_ 'Name')
        [pscustomobject]@{ FlowRunId = $id; State = [string](Get-SIHeartbeatRowValue $_ 'S'); FromStep = [string](Get-SIHeartbeatRowValue $_ 'Txt')
                           Scope = $(if ($scopeOf.ContainsKey($id)) { $scopeOf[$id] } else { '' })
                           StartedUtc = (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $_ 'T1')); EndedUtc = (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $_ 'T2')) } } |
              Sort-Object StartedUtc -Descending)
    if (-not $runs.Count -or $runs[0].State -ne 'Running') { return }
    $steps = @(Get-SIHeartbeatRowsOf $Rows 'step' | ForEach-Object {
        [pscustomobject]@{ FlowRunId = [string](Get-SIHeartbeatRowValue $_ 'Txt'); Job = [string](Get-SIHeartbeatRowValue $_ 'Name'); State = [string](Get-SIHeartbeatRowValue $_ 'S')
                           Order = (Get-SIHeartbeatRowValue $_ 'N1'); StartedUtc = (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $_ 'T1')); EndedUtc = (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $_ 'T2')) } })
    $top = $runs[0]
    $usual = Get-SIPipelineUsualMinutes -Runs $runs -Steps $steps -ExcludeRunId $top.FlowRunId
    Get-SIPipelineLongRun -Run $top -Steps @($steps | Where-Object { $_.FlowRunId -eq $top.FlowRunId }) -Usual $usual -NowUtc $NowUtc
}

function Get-SIHeartbeatStalledSteps {
    <#
        PURE. si-flow-1204 over the cfg rows the heartbeat already read: the running steps of the NEWEST run (K 'prog': Name =
        the job, T1 = its start, T2 = its newest sign of progress since then -- cfg.StepProgress / cfg.StepPhaseTime --, N1 = its
        order, N2 = 1 when the runner's log check found no sign of progress) against the last run's time of each job (K 'step'
        of the OTHER runs read). Get-SIPipelineStalledSteps (SI-JobFlow.ps1) decides. Nothing when the newest run is not Running.
    #>
    param([object[]]$Rows, [Parameter(Mandatory)][datetime]$NowUtc)
    $runs = @(Get-SIHeartbeatRowsOf $Rows 'run' | Sort-Object { ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $_ 'T1') } -Descending)
    if (-not $runs.Count -or [string](Get-SIHeartbeatRowValue $runs[0] 'S') -ne 'Running') { return }
    $top = [string](Get-SIHeartbeatRowValue $runs[0] 'Name')
    $other = @(Get-SIHeartbeatRowsOf $Rows 'step' | ForEach-Object {
        [pscustomobject]@{ FlowRunId = [string](Get-SIHeartbeatRowValue $_ 'Txt'); Job = [string](Get-SIHeartbeatRowValue $_ 'Name'); State = [string](Get-SIHeartbeatRowValue $_ 'S')
                           StartedUtc = (Get-SIHeartbeatRowValue $_ 'T1'); EndedUtc = (Get-SIHeartbeatRowValue $_ 'T2') } })
    $last = Get-SIPipelineLastStepMinutes -Steps $other -ExcludeRunId $top
    $mine = @(Get-SIHeartbeatRowsOf $Rows 'prog' | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'Txt') -eq $top } | ForEach-Object {
        $n2 = Get-SIHeartbeatRowValue $_ 'N2'
        [pscustomobject]@{ Job = [string](Get-SIHeartbeatRowValue $_ 'Name'); Order = (Get-SIHeartbeatRowValue $_ 'N1'); State = 'Running'
                           StartedUtc = (Get-SIHeartbeatRowValue $_ 'T1'); LastProgressUtc = (ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $_ 'T2'))
                           Silent = ($null -ne $n2 -and -not ($n2 -is [System.DBNull]) -and [long]$n2 -eq 1) } })
    Get-SIPipelineStalledSteps -Steps $mine -LastMinutes $last -NowUtc $NowUtc
}

function ConvertTo-SIHeartbeatStalledWire {
    <# PURE. Get-SIHeartbeatStalledSteps' entries as Pipeline.stalledSteps: { step, sinceUtc, lastProgressUtc }, at most 12. #>
    param([object[]]$Stalled)
    $c = $script:SIHeartbeatFields
    , [object[]]@(@($Stalled) | Where-Object { $_ } | Select-Object -First ([int]$c.MaxStalledSteps) | ForEach-Object {
        New-SIHeartbeatOrdered -Names $c.StalledStepFields -Values @{ step = (ConvertTo-SIHeartbeatJobName $_.Step); sinceUtc = (ConvertTo-SIHeartbeatUtc $_.SinceUtc); lastProgressUtc = (ConvertTo-SIHeartbeatUtc $_.LastProgressUtc) } })
}

function Add-SIPipelineStalled {
    <# PURE. -Pipeline with stalledSteps (-Steps, the wire entries) after its other keys and before housekeepingRowsLeft. #>
    param([Parameter(Mandatory)]$Pipeline, [Parameter(Mandatory)][object[]]$Steps)
    $c = $script:SIHeartbeatFields
    $hkName = [string]$c.PipelineHousekeepingField; $sn = [string]$c.PipelineStalledField
    $o = [ordered]@{}
    foreach ($pr in $Pipeline.PSObject.Properties) { if ($pr.Name -notin @($hkName, $sn)) { $o[$pr.Name] = $pr.Value } }
    $o[$sn] = [object[]]@($Steps)
    if ($Pipeline.PSObject.Properties[$hkName]) { $o[$hkName] = $Pipeline.$hkName }
    $r = [pscustomobject]$o
    $r.$sn = [object[]]@($Steps)
    $r
}

function Test-SIHeartbeatDatabaseNearFull {
    <# PURE. #904: does the database use -Pct (default DatabaseNearFullPct, 85) % or more of its maximum size? -Space
       @{ sqlUsedMb; sqlMaxMb }. $true / $false, or $null when either size is not known. #>
    param([AllowNull()][System.Collections.IDictionary]$Space, [double]$Pct = $script:SIHeartbeatFields.DatabaseNearFullPct)
    if (-not $Space -or -not $Space.Contains('sqlUsedMb') -or -not $Space.Contains('sqlMaxMb')) { return $null }
    $u = ConvertTo-SIHeartbeatInt $Space['sqlUsedMb']; $m = ConvertTo-SIHeartbeatInt $Space['sqlMaxMb']
    if ($null -eq $u -or $null -eq $m -or $m -le 0) { return $null }
    return ([double]$u -ge ([double]$m * $Pct / 100.0))
}

function Get-SIHeartbeatWarnings {
    <#
        PURE. The customer actions SecurityInsight already detects, each as its code from data-model/errors.locked.json and
        since when it holds:
          si-upd-0801   the updater may not use its Key Vault hand-over key (cfg.InstallState 'SecretHandover' missing,
                        checked within 3 days -- the kv-403 grant)
          si-upd-0802   the updater may not change the database (its last update failed on its database rights)
          si-upd-0806   2026-10-23: an update has waited more than 24 hours for a pipeline run to end (cfg.InstallState
                        'UpdateState' waits.since, the updater's run gate) -- a warning only; since = when it began to wait
          si-flow-1202  2026-10-25: a scheduled collection found a pipeline run going and skipped or waited (cfg.InstallState
                        'CollectionHeld' atUtc within 24 hours, engine/_shared/SI-CollectionRunGate.ps1) -- information only;
                        since = that collection's time
          si-flow-1203  2026-10-26: the newest run is Running and it, or one of its running steps, has run longer than
                        max(2 x usual, usual + 2 h) -- usual = the median of the install's own lengths among the runs read
                        (Get-SIPipelineUsualMinutes, at least 3 measured), else the floor 24 h (run) / 12 h (step)
                        (Get-SIPipelineLongRun, SI-JobFlow.ps1) -- a warning only; since = when the first of them crossed it.
                        The run and step are Pipeline.runId / step; the full words are in the run's log, note and step record
          si-flow-1204  2026-10-29: a running step of the newest run has run longer than max(2 x its last run's time, + 60 min)
                        (6 h when none is known) AND shows no progress for 60 minutes (Get-SIHeartbeatStalledSteps,
                        Get-SIPipelineStalledSteps) -- a warning only; the steps are named in Pipeline.stalledSteps
          si-flow-1205  #1096: the verification job's pipeline check (cfg.InstallState 'OutsidePipeline', checked within 30 h,
                        engine/_shared/SI-OutsidePipeline.ps1) found executions of pipeline step jobs (a collect producer
                        included) that belong to no pipeline run and to no person's start -- a warning only; since = the first
          si-perm-1001 / 1002 / 1003   SecurityInsight's identity is refused by Microsoft Graph / Defender / Azure (the newest
                        failed run in 24 hours on that source was a 401 / 403 and no run of that source succeeded since)
          si-perm-1004  SecurityInsight may not read the security scores (Microsoft Secure Score / Defender exposure score answered
                        401 / 403 in this process -- -ScoreState: Get-SISecurityScoreState, SI-TelemetryCounts.ps1)
          si-mail-1101  the mail send right is not restricted to the shared mailbox (sending is refused until it is)
          si-mail-1102  SecurityInsight may not send as the shared mailbox yet
          si-mail-1103  the restriction is not verified (no test mailbox, no attestation)
          si-flow-1201  #732: the pipeline runner (caj-si-flow) has no timer and no job of the pipeline runs on its own
                        (-ArmJobs: ConvertFrom-SIHeartbeatArmJob; Get-SIFlowRunnerScheduleState 'not-scheduled') -- the
                        pipeline never starts by itself and a queued run waits; since = when the job was last changed
          si-snow-1301  a ServiceNow output's newest check failed (cfg.ServiceNowCheck: the connection, the Import Set table,
                        its columns or its column mapping) -- its push is held; since = its first check that was not ok. Only an
                        output switched on (SI_DataOut_Outputs, K 'dataout'): a switched-off output never raises it (#903)
          si-data-1401  the merged assets' pages (CIs and assets) read a copy OLDER than the run the web app shows (the data
                        database's sidata.PublishedRun 'current': CopiedAt NULL or before PublishedAt -- -CopyRows:
                        Get-SIHeartbeatPublishedCopySql) and no refresher writing them, past twice the last refresh's time + 10
                        minutes (Test-SIHeartbeatCopyStaleTooLong); since = when that run was published. The pipeline runner and the
                        update catch the copies up by themselves; a warning that stays means they could not
          si-data-1402  #871: the newest complete Risk Analysis collection has no groupings yet (its run stopped before the
                        data sync, or the data sync is still running), so the report figures (Counts and Security) are those of
                        the newest collection that has them, dated by Security.collectionUtc -- -SecurityRows: the rows of
                        Get-SIHeartbeatSecuritySql, K 'time' G 'Newest'; since = that newest collection's time
          si-data-1403  #904: the Pro database uses 85 % (DatabaseNearFullPct) or more of its maximum size -- -DatabaseSpace:
                        @{ sqlUsedMb; sqlMaxMb } (the Counts' read, the same as Database usedMb / maxSizeMb); since = now
          si-data-1405  2026-11-10: the clean-up of old data cannot finish before the next scheduled run at the pace the
                        database's load allows (cfg.InstallState 'Housekeeping' behind, its record at most 24 h old --
                        Get-SIDataHousekeepingVerdict, SI-DataSql.ps1); since = when it fell behind. Support (the ticket)
        Only codes that are in the catalogue are returned (-Catalogue: the codes). At most 20.
    #>
    param([object[]]$Rows, [AllowNull()][object[]]$Sources, [Parameter(Mandatory)][datetime]$NowUtc, [string[]]$Catalogue, [AllowNull()][object[]]$ArmJobs,
          [AllowNull()]$ScoreState, [AllowNull()][object[]]$CopyRows, [AllowNull()][object[]]$SecurityRows,
          # #902: the reports held on purpose (Get-SIHeartbeatHoldSql) -- si-ra-0911 / 0912 (0913 / 0914 escalated), since = the
          # first held run; passed only when the hold contract is live for this install (Resolve-SIUplinkHoldFieldsSwitch)
          [AllowNull()][object[]]$HoldRows,
          # #904: the Pro database's used space and maximum size (@{ sqlUsedMb; sqlMaxMb }) -- si-data-1403 at 85 %
          [AllowNull()][System.Collections.IDictionary]$DatabaseSpace)
    $c = $script:SIHeartbeatFields
    if (-not $PSBoundParameters.ContainsKey('Catalogue')) { $Catalogue = @(Get-SIErrorCatalogue | ForEach-Object { [string]$_.code }) }
    $out = [ordered]@{}
    $add = { param($code, $since) if ($Catalogue -ccontains $code -and -not $out.Contains($code)) { $out[$code] = (ConvertTo-SIHeartbeatUtc $since) } }
    $stateRow = { param($n) @(Get-SIHeartbeatRowsOf $Rows 'state' | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'Name') -eq $n })[0] }
    $json = { param($r) if (-not $r) { return $null }; try { [string](Get-SIHeartbeatRowValue $r 'Txt') | ConvertFrom-Json -ErrorAction Stop } catch { $null } }
    # the secure hand-over (kv-403)
    $h = & $stateRow 'SecretHandover'; $ho = & $json $h
    if ($ho -and "$($ho.state)" -eq 'missing') {
        $at = ConvertTo-SIHeartbeatTime $(if ($ho.PSObject.Properties['checkedUtc']) { $ho.checkedUtc } else { $null })
        if ($at -and ($NowUtc - $at).TotalDays -le 3) { & $add $c.WarningCodes.SecretHandover $(if ($ho.PSObject.Properties['sinceUtc'] -and $ho.sinceUtc) { $ho.sinceUtc } else { $at }) }
    }
    # the updater's database rights
    $u = & $stateRow 'UpdateState'; $uo = & $json $u
    if ($uo -and $uo.PSObject.Properties['error'] -and "$($uo.error)" -match '(?i)db_ddladmin|db_securityadmin|permission was denied|permission denied in database|CREATE TABLE permission|ALTER permission|not have permission') {
        & $add $c.WarningCodes.UpdaterDatabase $(if ($uo.PSObject.Properties['lastCheckUtc']) { $uo.lastCheckUtc } else { Get-SIHeartbeatRowValue $u 'T1' })
    }
    # 2026-10-23: the update has waited more than 24 hours for a pipeline run to end (UpdateState waits.since) -- a warning only
    if ($uo -and $uo.PSObject.Properties['waits'] -and $uo.waits -and $uo.waits.PSObject.Properties['since']) {
        $ws = ConvertTo-SIHeartbeatTime $uo.waits.since
        if ($null -ne $ws -and ($NowUtc - $ws).TotalHours -gt [double]$c.UpdateWaitsWarnHours) { & $add $c.WarningCodes.UpdateWaitsLong $ws }
    }
    # 2026-10-25: a scheduled collection held back by a pipeline run (skipped / waiting / waited / limit) in the last 24 hours
    $ch = & $stateRow 'CollectionHeld'; $cho = & $json $ch
    if ($cho -and $cho.PSObject.Properties['atUtc'] -and "$($cho.action)" -in @('skipped', 'waiting', 'waited', 'limit')) {
        $cat = ConvertTo-SIHeartbeatTime $cho.atUtc
        if ($null -ne $cat -and ($NowUtc - $cat).TotalHours -le [double]$c.CollectionHeldHours -and ($NowUtc - $cat).TotalHours -ge -1) { & $add $c.WarningCodes.CollectionHeld $cat }
    }
    # #1096: the newest pipeline check (verification job, cfg.InstallState 'OutsidePipeline') found executions of pipeline
    # step jobs that belong to no run and to no person's start -- a warning only; since = the first of them
    $op = & $stateRow 'OutsidePipeline'; $opo = & $json $op
    if ($opo -and $opo.PSObject.Properties['count'] -and [int]$opo.count -gt 0 -and $opo.PSObject.Properties['checkedUtc']) {
        $opc = ConvertTo-SIHeartbeatTime $opo.checkedUtc
        if ($null -ne $opc -and ($NowUtc - $opc).TotalHours -le [double]$c.OutsidePipelineHours -and ($NowUtc - $opc).TotalHours -ge -1) { & $add $c.WarningCodes.RanOutsidePipeline $(if ($opo.PSObject.Properties['firstUtc'] -and $opo.firstUtc) { $opo.firstUtc } else { $opc }) }
    }
    # 2026-10-26: the run going on (or one of its steps) has run much longer than usual for this install -- a warning only
    try {
        $lr = @(Get-SIHeartbeatLongRun -Rows $Rows -NowUtc $NowUtc)
        if ($lr.Count) { & $add $c.WarningCodes.RunMuchLonger (@($lr | Sort-Object CrossedUtc)[0].CrossedUtc) }
    } catch { }
    # 2026-10-29: a running step far past its last run's time that shows no progress -- a warning only; the steps are named
    # in Pipeline.stalledSteps
    try {
        $ss = @(Get-SIHeartbeatStalledSteps -Rows $Rows -NowUtc $NowUtc)
        if ($ss.Count) { & $add $c.WarningCodes.StepStalled (@($ss | Sort-Object SinceUtc)[0].SinceUtc) }
    } catch { }
    # 2026-11-10: the clean-up of old data cannot keep up -- it falls short of the next run at the widest the load allows
    $hk = & $stateRow 'Housekeeping'; $hko = & $json $hk
    if ($hko -and $hko.PSObject.Properties['behind'] -and $hko.behind) {
        $hka = ConvertTo-SIHeartbeatTime (Get-SIHeartbeatRowValue $hk 'T1')
        if ($null -eq $hka -and $hko.PSObject.Properties['at']) { $hka = ConvertTo-SIHeartbeatTime $hko.at }
        $hkb = ConvertTo-SIHeartbeatTime $hko.behind
        if ($null -ne $hka -and $null -ne $hkb -and ($NowUtc - $hka).TotalHours -le [double]$c.HousekeepingRecordHours -and ($NowUtc - $hka).TotalHours -ge -1) { & $add $c.WarningCodes.HousekeepingBehind $hkb }
    }
    # a source that refuses SecurityInsight's identity
    foreach ($s in @($Sources)) {
        if (-not $s) { continue }
        $code = switch ("$($s.lastErrorCode)") { { $_ -in @('graph-401', 'graph-403') } { $c.WarningCodes.GraphPermission } 'defender-403' { $c.WarningCodes.DefenderPermission } 'arm-403' { $c.WarningCodes.AzurePermission } default { $null } }
        if (-not $code) { continue }
        $failedAt = if ($s.PSObject.Properties['_failedAt']) { $s._failedAt } else { $null }
        $good = ConvertTo-SIHeartbeatTime $s.lastGoodUtc
        if ($null -ne $good -and $null -ne $failedAt -and $good -gt $failedAt) { continue }
        & $add $code $failedAt
    }
    # the security scores (Secure Score / exposure score): a permission not granted yet
    if ($null -ne $ScoreState -and @($ScoreState.Refused | Where-Object { $_ }).Count) {
        & $add $c.WarningCodes.ScoresPermission $(if ($ScoreState.SinceUtc) { $ScoreState.SinceUtc } else { $NowUtc })
    }
    # the mail send right
    $mr = & $stateRow 'MailRestriction'; $mo = & $json $mr
    if ($mo) {
        $since = if ($mo.PSObject.Properties['checkedUtc'] -and $mo.checkedUtc) { $mo.checkedUtc } else { Get-SIHeartbeatRowValue $mr 'T1' }
        $att = & $stateRow 'MailRestrictionAttestation'
        switch ("$($mo.state)") {
            'unrestricted' { & $add $c.WarningCodes.MailUnrestricted $since }
            'not-granted' { & $add $c.WarningCodes.MailNotGranted $since }
            'unverified' { if (-not $att) { & $add $c.WarningCodes.MailNotVerified $since } }
        }
    }
    # a ServiceNow output whose newest check FAILED (cfg.ServiceNowCheck, K 'snow': Txt = the outcome, T2 = not ok since): the
    # push is held until the table, the key or the role is right. A warning outcome is said in the web app only.
    # #903: only an output that is SWITCHED ON (SI_DataOut_Outputs, K 'dataout'; both ServiceNow outputs are off by default) --
    # a switched-off output never raises it, whatever its newest stored check says (owner: no unnecessary alerts)
    $snowOn = Get-SIHeartbeatSnowOutputsOn -Rows $Rows
    foreach ($s in @(Get-SIHeartbeatRowsOf $Rows 'snow' | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'Txt') -eq 'failed' -and $snowOn -contains [string](Get-SIHeartbeatRowValue $_ 'Name') })) {
        $since = Get-SIHeartbeatRowValue $s 'T2'; if ($null -eq $since) { $since = Get-SIHeartbeatRowValue $s 'T1' }
        & $add $c.WarningCodes.ServiceNowCheckFailed $since
    }
    # #732: the pipeline runner without its timer (the jobs as ARM lists them; not read = nothing said)
    if ($null -ne $ArmJobs -and (Get-Command -Name Get-SIFlowRunnerScheduleState -ErrorAction SilentlyContinue)) {
        try {
            $trig = @(@($ArmJobs) | Where-Object { $_ -and $_.Name } | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; TriggerType = [string]$_.Trigger; Cron = [string]$_.Cron; RememberedCron = '' } })
            $fs = Get-SIFlowRunnerScheduleState -Jobs $trig
            if ($fs.State -eq 'not-scheduled') {
                $fj = @(@($ArmJobs) | Where-Object { $_ -and $_.Key -eq 'flow' })[0]
                $since = if ($fj -and $fj.PSObject.Properties['Modified'] -and $fj.Modified) { $fj.Modified } else { $NowUtc }
                & $add $c.WarningCodes.FlowRunnerNotScheduled $since
            }
        } catch { }
    }
    # the shown run's copies of the merged assets older than it (the data database; not read = nothing said)
    foreach ($cr in @(@($CopyRows) | Where-Object { $_ } | Select-Object -First 1)) {
        if (Test-SIHeartbeatCopyStaleTooLong -CopyRow $cr -NowUtc $NowUtc) { & $add $c.WarningCodes.PublishedCopyStale $(Get-SIHeartbeatRowValue $cr 'PublishedAt') }
    }
    # #871: the report figures are from an earlier collection than the newest complete one (not read = nothing said)
    foreach ($nr in @(Get-SIHeartbeatRowsOf $SecurityRows 'time' | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'G') -eq 'Newest' } | Select-Object -First 1)) {
        $t = Get-SIHeartbeatRowValue $nr 'T'
        if ($null -ne $t -and -not ($t -is [DBNull])) { & $add $c.WarningCodes.FiguresFromEarlierCollection $t }
    }
    # #902: a report held on purpose at its last complete result (information), or held too long (escalated) -- the earliest
    # streak of a code first, so its since is the first held run
    foreach ($hw in @(Get-SIHeartbeatHoldWarnings -HoldRows $HoldRows | Sort-Object -Property @{ Expression = { $(if ($null -eq $_.SinceUtc -or $_.SinceUtc -is [DBNull]) { [datetime]::MaxValue } else { [datetime]$_.SinceUtc }) } })) {
        & $add $hw.Code $(if ($null -eq $hw.SinceUtc -or $hw.SinceUtc -is [DBNull]) { $NowUtc } else { $hw.SinceUtc })
    }
    # #904: the database is almost full (not read = nothing said)
    if ((Test-SIHeartbeatDatabaseNearFull -Space $DatabaseSpace) -eq $true) { & $add $c.WarningCodes.DatabaseNearFull $NowUtc }
    if (-not $out.Count) { return }
    @($out.Keys) | Select-Object -First ([int]$c.MaxWarnings) | ForEach-Object { New-SIHeartbeatOrdered -Names $c.Fields.Warnings -Values @{ code = $_; sinceUtc = $out[$_] } }
}

function Get-SIHeartbeatDomainOf {
    <# PURE. The security domain of a report (by its family), or $null (Attack paths and anything else). #>
    param([AllowEmptyString()][string]$Report)
    foreach ($d in $script:SIHeartbeatFields.DomainPrefixes.Keys) { foreach ($p in $script:SIHeartbeatFields.DomainPrefixes[$d]) { if ("$Report".StartsWith($p, [StringComparison]::Ordinal)) { return $d } } }
    $null
}

function Get-SIHeartbeatSecurity {
    <#
        PURE. Security from the rows of Get-SIHeartbeatSecuritySql and the heartbeat's Counts (-Counts: the #719 keys of
        SI-TelemetryCounts -- already only from Complete reports). Per domain:
          reports / reportsComplete   the domain's Detailed reports in the latest complete collection / of them Complete
          findings                    the Detailed findings of the domain's reports (#636: one finding = one issue on one asset;
                                      the stored 'report' grouping of the collection)
          findingsCritical / High     of them with the risk rating Critical / High
          impactedAssets              the SUM of each report's distinct assets (an asset in two reports counts twice)
          detailedRows                the rows stored by the domain's Detailed reports
          endpoint: cveDevicePairs / cveDevices / missingCves / recommendations / recommendationPairs = Counts cveDevicePairs /
                    cveDevices (distinct devices) / cves (distinct CVE ids) / recommendations / recommendationDevicePairs
          azure:    recommendations = Counts azureRecommendations
          anything else: null
        A domain with no Complete report is left out. $null when no domain is left.
    #>
    param([object[]]$Rows, [System.Collections.IDictionary]$Counts = @{})
    $c = $script:SIHeartbeatFields
    $cnt = { param($k) if ($Counts -and $Counts.Contains($k)) { ConvertTo-SIHeartbeatInt $Counts[$k] } else { $null } }
    $times = @(Get-SIHeartbeatRowsOf $Rows 'time')
    $tOf = { param($g) $r = @($times | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'G') -eq $g })[0]; if ($r) { ConvertTo-SIHeartbeatUtc (Get-SIHeartbeatRowValue $r 'T') } else { $null } }
    # #636: the Detailed collection (the Summary step is optional and off by default)
    $collection = & $tOf 'Detailed'
    # #871: a 'Newest' time row = these rows are from an earlier (grouped) collection than the newest complete one
    $older = ($null -ne (& $tOf 'Newest'))
    # a Detailed report's stored rows in THIS collection, only when it is Complete here (the rule of Counts' pair keys)
    $pairOf = { param($rn) $r = @(Get-SIHeartbeatRowsOf $Rows 'status' | Where-Object { [string](Get-SIHeartbeatRowValue $_ 'R') -eq $rn -and [string](Get-SIHeartbeatRowValue $_ 'G') -eq 'Detailed' -and [string](Get-SIHeartbeatRowValue $_ 'S') -eq 'Complete' })[0]; if ($r) { ConvertTo-SIHeartbeatInt (Get-SIHeartbeatRowValue $r 'N1') } else { $null } }
    $acc = [ordered]@{}
    foreach ($d in $c.Domains) { $acc[$d] = @{ reports = 0L; complete = 0L; detailed = $null; findings = $null; crit = $null; high = $null; assets = $null } }
    foreach ($r in @(Get-SIHeartbeatRowsOf $Rows 'status')) {
        $d = Get-SIHeartbeatDomainOf ([string](Get-SIHeartbeatRowValue $r 'R')); if (-not $d) { continue }
        $a = $acc[$d]; $a['reports'] = $a['reports'] + 1
        if ([string](Get-SIHeartbeatRowValue $r 'S') -eq 'Complete') { $a['complete'] = $a['complete'] + 1 }
        if ([string](Get-SIHeartbeatRowValue $r 'G') -eq 'Detailed') { $n = ConvertTo-SIHeartbeatCount (Get-SIHeartbeatRowValue $r 'N1'); if ($null -ne $n) { $a.detailed = $(if ($null -eq $a.detailed) { 0L } else { $a.detailed }) + $n } }
    }
    foreach ($r in @(Get-SIHeartbeatRowsOf $Rows 'sum')) {
        $d = Get-SIHeartbeatDomainOf ([string](Get-SIHeartbeatRowValue $r 'R')); if (-not $d) { continue }
        $a = $acc[$d]
        foreach ($p in @(@('findings', 'N1'), @('crit', 'N2'), @('high', 'N3'), @('assets', 'N4'))) {
            $n = ConvertTo-SIHeartbeatCount (Get-SIHeartbeatRowValue $r $p[1]); if ($null -eq $n) { continue }
            $a[$p[0]] = $(if ($null -eq $a[$p[0]]) { 0L } else { $a[$p[0]] }) + $n
        }
    }
    $domains = New-Object System.Collections.Generic.List[object]
    foreach ($d in $acc.Keys) {
        $a = $acc[$d]
        if ($a.complete -lt 1) { continue }
        $v = @{ domain = $d; reports = [long]$a.reports; reportsComplete = [long]$a.complete; findings = $a.findings; findingsCritical = $a.crit; findingsHigh = $a.high
                impactedAssets = $a.assets; detailedRows = $a.detailed }
        if ($d -eq 'endpoint') {
            $v.cveDevicePairs = & $cnt 'cveDevicePairs'; $v.cveDevices = & $cnt 'cveDevices'; $v.missingCves = & $cnt 'cves'
            $v.recommendations = & $cnt 'recommendations'; $v.recommendationPairs = & $cnt 'recommendationDevicePairs'
            # #871: Counts' pair keys are the NEWEST collection's; when these figures are from an earlier one, the pairs are
            # that collection's own stored rows -- one domain never mixes two collections, and collectionUtc dates all of it
            if ($older) { $v.cveDevicePairs = & $pairOf 'Device_Missing_CVEs_Detailed'; $v.recommendationPairs = & $pairOf 'Device_Recommendations_Detailed' }
        } elseif ($d -eq 'azure') { $v.recommendations = & $cnt 'azureRecommendations' }
        $domains.Add((New-SIHeartbeatOrdered -Names $c.Fields.Domain -Values $v))
    }
    if (-not $domains.Count) { return $null }
    New-SIHeartbeatOrdered -Names $c.Fields.Security -Values @{ collectionUtc = $collection; domains = @($domains.ToArray() | Select-Object -First ([int]$c.MaxDomains)) }
}

# =====================================================================================================================
#  DataOut (#1043) -- the progress of every data-out output, as the writer records it (cfg.DataOutBatch) and its runs
#  (cfg.ConnectorRun). ONE read of the settings database per heartbeat, by the tables' own indexes.
# =====================================================================================================================
function Get-SIHeartbeatDataOutSql {
    <#
        Rows: K = batch (the newest live / resync batch of each output: its state, times, counts and the progress columns --
        NULL on a schema without them) | run (the newest run of each data-out connector: its outcome, times and why) |
        trust (#1237: the data sync's record cfg.InstallState 'DataOutTrust' -- Reason = its value, EndedAt = when written).
        A database without a table gives no rows of it.
    #>
    @'
SET NOCOUNT ON; SET LOCK_TIMEOUT 5000;
DECLARE @r TABLE (K NVARCHAR(8) NOT NULL, OutputId NVARCHAR(64) NULL, BatchId NVARCHAR(160) NULL, RunId NVARCHAR(64) NULL, State NVARCHAR(16) NULL,
                  StartedAt DATETIME2(3) NULL, EndedAt DATETIME2(3) NULL, Phase NVARCHAR(16) NULL, RowsPlanned BIGINT NULL, RowsSent BIGINT NULL,
                  RowsHeld BIGINT NULL, KeptOpenRows BIGINT NULL, LastProgressUtc DATETIME2(3) NULL, Reason NVARCHAR(1000) NULL);
-- #1188 the kept-open rows (not seen this run) apart from the held ones; NULL on a schema without the column
DECLARE @ko NVARCHAR(40) = CASE WHEN COL_LENGTH(N'cfg.DataOutBatch', N'KeptOpenRows') IS NULL THEN N'CAST(NULL AS bigint)' ELSE N'b.KeptOpenRows' END;
IF OBJECT_ID(N'cfg.DataOutBatch') IS NOT NULL
BEGIN
    IF COL_LENGTH(N'cfg.DataOutBatch', N'LastProgressUtc') IS NOT NULL
        INSERT @r (K, OutputId, BatchId, RunId, State, StartedAt, EndedAt, Phase, RowsPlanned, RowsSent, RowsHeld, KeptOpenRows, LastProgressUtc, Reason)
        EXEC (N'SELECT N''batch'', b.OutputId, b.BatchId, b.RunId, b.State, b.StartedAt, b.FinishedAt, b.Phase, COALESCE(b.PlannedRows, b.RowsPlanned),
                       COALESCE(b.SentRows, b.RowsSent), COALESCE(b.RowsHeld, b.HeldRows), ' + @ko + N', b.LastProgressUtc, b.Reason
                FROM (SELECT DISTINCT OutputId FROM cfg.DataOutBatch) o
                CROSS APPLY (SELECT TOP (1) * FROM cfg.DataOutBatch x WHERE x.OutputId = o.OutputId AND x.Mode IN (N''live'', N''resync'') ORDER BY x.StartedAt DESC) b;');
    ELSE
        INSERT @r (K, OutputId, BatchId, RunId, State, StartedAt, EndedAt, RowsPlanned, RowsSent, RowsHeld, Reason)
        SELECT N'batch', b.OutputId, b.BatchId, b.RunId, b.State, b.StartedAt, b.FinishedAt, b.PlannedRows, b.SentRows, b.HeldRows, b.Reason
        FROM (SELECT DISTINCT OutputId FROM cfg.DataOutBatch) o
        CROSS APPLY (SELECT TOP (1) * FROM cfg.DataOutBatch x WHERE x.OutputId = o.OutputId AND x.Mode IN (N'live', N'resync') ORDER BY x.StartedAt DESC) b;
END
IF OBJECT_ID(N'cfg.ConnectorRun') IS NOT NULL
    INSERT @r (K, OutputId, RunId, State, StartedAt, EndedAt, Reason)
    SELECT N'run', SUBSTRING(n.ConnectorName, 10, 64), x.RunId, x.Outcome, x.StartedAt, x.EndedAt, x.HaltReason
    FROM (SELECT DISTINCT ConnectorName FROM cfg.ConnectorRun WHERE ConnectorName LIKE N'data-out-%') n
    CROSS APPLY (SELECT TOP (1) r.RunId, r.Outcome, r.StartedAt, r.EndedAt, r.HaltReason FROM cfg.ConnectorRun r
                 WHERE r.ConnectorName = n.ConnectorName ORDER BY r.StartedAt DESC, r.ConnectorRunId DESC) x;
-- #1237 the data sync's record of its newest decision on the collection's trust (one row, its primary key)
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
    INSERT @r (K, EndedAt, Reason) SELECT N'trust', UpdatedAt, LEFT(Value, 1000) FROM cfg.InstallState WHERE Name = N'DataOutTrust';
SELECT K, OutputId, BatchId, RunId, State, StartedAt, EndedAt, Phase, RowsPlanned, RowsSent, RowsHeld, KeptOpenRows, LastProgressUtc, Reason FROM @r;
'@
}

function Get-SIHeartbeatDataOutFieldNames {
    <#
        PURE. #1188 The keys of one DataOut entry: the agreed ones; + the kept-open count (DataOutKeptOpenField) at the end ONLY
        while DataOutSendKeptOpen is on (ON since Invardia's backend accepts the key; off = the fourteen agreed keys only).
    #>
    $c = $script:SIHeartbeatFields
    if ($c.DataOutSendKeptOpen) { return , [string[]]@(@($c.Fields.DataOut) + @([string]$c.DataOutKeptOpenField)) }
    , [string[]]@($c.Fields.DataOut)
}

function Get-SIHeartbeatDataOutHeldReason {
    <# PURE. The closed-list reason of a hold, from its text (the check's summary, the run's why): never free text. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = "$Text"
    if ($t -match '(?i)would be cut|longer than the column') { return 'column-too-long' }
    if ($t -match '(?i)by label|column mappings?|\bmapping\b') { return 'mapping' }
    if ($t -match '(?i)\b40[13]\b|sign-in|refused the request|api key|credential|\brole\b|password') { return 'auth' }
    if ($t -match '(?i)could not be (reached|found)|not reachable|unreachable|\bDNS\b|\bTLS\b|connection|timed? ?out|no connection') { return 'connection' }
    'other'
}

function Get-SIHeartbeatDataOutTrust {
    <#
        PURE. #1237 The data sync's trust record (a K 'trust' row of Get-SIHeartbeatDataOutSql: Reason = 'held=1;since=..;
        collection=..;trusted=..;at=..', EndedAt = when written) -> @{ Held; HeldSinceUtc; NewestTrustedUtc; AtUtc } (times as
        ISO-8601 UTC texts or $null; AtUtc falls back to when the row was written), or $null (no row / not a record).
    #>
    param([AllowNull()]$Row)
    if ($null -eq $Row) { return $null }
    $txt = Get-SIHeartbeatRowValue $Row 'Reason'; if ($txt -is [DBNull]) { $txt = $null }
    $kv = @{}
    foreach ($p in ("$txt" -split ';')) { $i = $p.IndexOf('='); if ($i -gt 0) { $kv[$p.Substring(0, $i).Trim().ToLowerInvariant()] = $p.Substring($i + 1).Trim() } }
    if (-not $kv.ContainsKey('held')) { return $null }
    $at = ConvertTo-SIHeartbeatUtc $kv['at']
    if (-not $at) { $w = Get-SIHeartbeatRowValue $Row 'EndedAt'; if ($w -isnot [DBNull]) { $at = ConvertTo-SIHeartbeatUtc $w } }
    [pscustomobject]@{ Held = ($kv['held'] -eq '1'); HeldSinceUtc = (ConvertTo-SIHeartbeatUtc $kv['since']); NewestTrustedUtc = (ConvertTo-SIHeartbeatUtc $kv['trusted']); AtUtc = $at }
}

function Get-SIHeartbeatDataOut {
    <#
        PURE. The DataOut entries from -Rows (Get-SIHeartbeatDataOutSql) at -NowUtc: one per output, running first, then the
        newest; at most 10. A batch still 'writing' with no run row of its run that ended after it started is RUNNING (its
        phase, rows, rate; stalled = no progress for 10 minutes); otherwise the output's newest run: idle (complete / partial),
        held (+ heldReason, + si-snow-1301 for a ServiceNow output held by its check) or failed. A switched-off or what-if
        output is left out. Returns ONE array (possibly empty).
        #1237: when the data sync's newest decision HELD data out because the collection is not trusted (K 'trust', while
        DataOutSendTrustHold is on), that hold IS the newest attempt of every output whose last run started before it: phase /
        lastResult 'held', heldReason 'untrusted', started / ended = when it was held, no batch and no row counts (nothing was
        sent), + heldSinceUtc / newestTrustedUtc after the other keys, each only when known. A running send is never changed.
    #>
    param([AllowNull()][object[]]$Rows, [Parameter(Mandatory)][datetime]$NowUtc)
    $c = $script:SIHeartbeatFields
    $v = { param($r, $n) $x = Get-SIHeartbeatRowValue $r $n; if ($x -is [DBNull]) { $null } else { $x } }
    $byOut = [ordered]@{}
    $trust = $null
    foreach ($r in @($Rows | Where-Object { $null -ne $_ })) {
        if ([string](& $v $r 'K') -eq 'trust') { if ($null -eq $trust) { $trust = Get-SIHeartbeatDataOutTrust -Row $r }; continue }
        $o = ([string](& $v $r 'OutputId')).Trim().ToLowerInvariant()
        if (-not ($o -cmatch '^[a-z0-9-]{1,64}$')) { continue }
        if (-not $byOut.Contains($o)) { $byOut[$o] = @{ Batch = $null; Run = $null } }
        $k = [string](& $v $r 'K')
        if ($k -notin 'batch', 'run') { continue }
        $slot = $(if ($k -eq 'batch') { 'Batch' } else { 'Run' })
        # one per output and kind -- the newest (the read gives one; a second row never replaces a newer one)
        $have = $byOut[$o][$slot]
        if ($have) { $ta = ConvertTo-SIHeartbeatTime (& $v $have 'StartedAt'); $tb = ConvertTo-SIHeartbeatTime (& $v $r 'StartedAt'); if ($null -ne $ta -and ($null -eq $tb -or $tb -le $ta)) { continue } }
        $byOut[$o][$slot] = $r
    }
    $codes = @(); try { $codes = @(Get-SIErrorCatalogue | ForEach-Object { [string]$_.code }) } catch { $codes = @() }
    $int = { param($x) ConvertTo-SIHeartbeatInt $x }
    $rate = { param($rows, $from, $to) $a = ConvertTo-SIHeartbeatTime $from; $b = ConvertTo-SIHeartbeatTime $to; $n = ConvertTo-SIHeartbeatInt $rows
              if ($null -eq $a -or $null -eq $b -or $null -eq $n -or $b -le $a) { return $null }; ConvertTo-SIHeartbeatNumber ($n / ($b - $a).TotalSeconds) }
    $bid = { param($x) $s = [string]$x; if ($s -cmatch '^[A-Za-z0-9._:-]{1,64}$') { $s } else { $null } }
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($o in $byOut.Keys) {
        $b = $byOut[$o].Batch; $r = $byOut[$o].Run
        $bStart = $(if ($b) { ConvertTo-SIHeartbeatTime (& $v $b 'StartedAt') } else { $null })
        $rEnd = $(if ($r) { ConvertTo-SIHeartbeatTime (& $v $r 'EndedAt') } else { $null })
        $running = ($b -and [string](& $v $b 'State') -eq 'writing' -and -not ($null -ne $rEnd -and $null -ne $bStart -and $rEnd -ge $bStart))
        $e = [ordered]@{}
        if ($running) {
            $ph = [string](& $v $b 'Phase'); if ($c.DataOutRunPhases -cnotcontains $ph) { $ph = 'send' }
            $lp = & $v $b 'LastProgressUtc'
            $since = ConvertTo-SIHeartbeatTime $(if ($null -ne $lp) { $lp } else { & $v $b 'StartedAt' })
            $e = [ordered]@{ output = $o; phase = $ph; batchId = (& $bid (& $v $b 'BatchId')); startedUtc = (ConvertTo-SIHeartbeatUtc (& $v $b 'StartedAt'))
                             rowsPlanned = (& $int (& $v $b 'RowsPlanned')); rowsSent = (& $int (& $v $b 'RowsSent')); rowsHeld = (& $int (& $v $b 'RowsHeld'))
                             rowsPerSec = (& $rate (& $v $b 'RowsSent') (& $v $b 'StartedAt') $lp); lastProgressUtc = (ConvertTo-SIHeartbeatUtc $lp)
                             stalled = [bool]($null -ne $since -and ($NowUtc - $since).TotalMinutes -ge [int]$c.DataOutStallMinutes)
                             lastEndedUtc = $(if ($r) { ConvertTo-SIHeartbeatUtc (& $v $r 'EndedAt') } else { $null }); lastResult = $null; lastErrorCode = $null; heldReason = $null }
            if ($r) { $e.lastResult = switch ([string](& $v $r 'State')) { 'success' { 'complete' } 'partial' { 'partial' } 'held' { 'held' } 'source-empty' { 'held' } 'failed' { 'failed' } default { $null } } }
            # #1188 prepared: the kept-open rows (not seen this run) -- only sent while DataOutSendKeptOpen is on
            $e[[string]$c.DataOutKeptOpenField] = & $int (& $v $b 'KeptOpenRows')
            $sortAt = $(if ($null -ne $since) { $since } else { $NowUtc })
            $entries.Add([pscustomobject]@{ Running = $true; At = $sortAt; Entry = (New-SIHeartbeatOrdered -Names (Get-SIHeartbeatDataOutFieldNames) -Values $e) })
            continue
        }
        # the newest finished run of the output: its run row, else the batch's own end
        $outcome = $(if ($r) { [string](& $v $r 'State') } elseif ($b) { switch ([string](& $v $b 'State')) { 'complete' { 'success' } 'held' { 'held' } 'failed' { 'failed' } default { '' } } } else { '' })
        $res = switch ($outcome) { 'success' { 'complete' } 'partial' { 'partial' } 'held' { 'held' } 'source-empty' { 'held' } 'failed' { 'failed' } default { $null } }
        if ($null -eq $res) { continue }   # off, what-if, not known: no entry
        $ph = switch ($res) { 'held' { 'held' } 'failed' { 'failed' } default { 'idle' } }
        $same = ($b -and (-not $r -or [string](& $v $b 'RunId') -eq [string](& $v $r 'RunId')))
        $why = @($(if ($r) { [string](& $v $r 'Reason') }), $(if ($same) { [string](& $v $b 'Reason') })) -join ' '
        $hr = $(if ($res -eq 'held') { Get-SIHeartbeatDataOutHeldReason -Text $why } else { $null })
        $code = $null
        if ($res -eq 'held' -and $o -like 'servicenow-*' -and $outcome -eq 'held' -and $hr -ne 'other' -and $codes -ccontains [string]$c.DataOutSnowHeldCode) { $code = [string]$c.DataOutSnowHeldCode }
        $st = $(if ($r) { & $v $r 'StartedAt' } else { & $v $b 'StartedAt' }); $en = $(if ($r) { & $v $r 'EndedAt' } else { & $v $b 'EndedAt' })
        $e = [ordered]@{ output = $o; phase = $ph; batchId = $(if ($same) { & $bid (& $v $b 'BatchId') } else { $null }); startedUtc = (ConvertTo-SIHeartbeatUtc $st)
                         rowsPlanned = $(if ($same) { & $int (& $v $b 'RowsPlanned') } else { $null }); rowsSent = $(if ($same) { & $int (& $v $b 'RowsSent') } else { $null })
                         rowsHeld = $(if ($same) { & $int (& $v $b 'RowsHeld') } else { $null })
                         rowsPerSec = $(if ($same) { & $rate (& $v $b 'RowsSent') (& $v $b 'StartedAt') (& $v $b 'EndedAt') } else { $null })
                         lastProgressUtc = $(if ($same) { ConvertTo-SIHeartbeatUtc (& $v $b 'LastProgressUtc') } else { $null }); stalled = $false
                         lastEndedUtc = (ConvertTo-SIHeartbeatUtc $en); lastResult = $res; lastErrorCode = $code; heldReason = $hr }
        # #1188 prepared: the kept-open rows (not seen this run) -- only sent while DataOutSendKeptOpen is on
        $e[[string]$c.DataOutKeptOpenField] = $(if ($same) { & $int (& $v $b 'KeptOpenRows') } else { $null })
        $at = ConvertTo-SIHeartbeatTime $en; if ($null -eq $at) { $at = ConvertTo-SIHeartbeatTime $st }; if ($null -eq $at) { $at = [datetime]::MinValue }
        $names = Get-SIHeartbeatDataOutFieldNames
        # #1237: the data sync held data out AFTER this output's newest run started -- that hold is the output's newest attempt
        $holdAt = $(if ($c.DataOutSendTrustHold -and $trust -and $trust.Held -and $trust.AtUtc) { ConvertTo-SIHeartbeatTime $trust.AtUtc } else { $null })
        $lastStart = ConvertTo-SIHeartbeatTime $st; if ($null -eq $lastStart) { $lastStart = $at }
        if ($null -ne $holdAt -and $holdAt -ge $lastStart) {
            foreach ($k in 'batchId', 'rowsPlanned', 'rowsSent', 'rowsHeld', 'rowsPerSec', 'lastProgressUtc', 'lastErrorCode') { $e[$k] = $null }
            $e.phase = 'held'; $e.lastResult = 'held'; $e.heldReason = [string]$c.DataOutTrustHeldReason; $e.stalled = $false
            $e.startedUtc = [string]$trust.AtUtc; $e.lastEndedUtc = [string]$trust.AtUtc
            $e[[string]$c.DataOutKeptOpenField] = $null
            # the two SOFT keys, after the others, each only when known (never null)
            foreach ($k in @($c.DataOutTrustFields)) { if ($trust.$k) { $e[$k] = [string]$trust.$k; $names = @($names) + @([string]$k) } }
            $at = $holdAt
        }
        $entries.Add([pscustomobject]@{ Running = $false; At = $at; Entry = (New-SIHeartbeatOrdered -Names $names -Values $e) })
    }
    , [object[]]@($entries | Sort-Object -Property @{ Expression = { $_.Running }; Descending = $true }, @{ Expression = { $_.At }; Descending = $true } | Select-Object -First ([int]$c.MaxDataOut) | ForEach-Object { $_.Entry })
}

# =====================================================================================================================
#  The size limit -- PURE over the record
# =====================================================================================================================
#  BuildPool (framework rule 11g) -- PURE
# =====================================================================================================================
function Get-SIHeartbeatBuildPool {
    <#
        PURE. BuildPool from a private install's agent pool -Pool (as ARM returns it) and its registry's newest runs -Runs:
        { tier (string), count (int), building (any run Queued / Started / Running), checkedUtc (-NowUtc) }. $null = no pool
        (the field is left out: only an install that has an agent pool sends it), or a pool whose tier / count cannot be read.
    #>
    param($Pool, [object[]]$Runs = @(), [Parameter(Mandatory)][datetime]$NowUtc)
    if ($null -eq $Pool) { return $null }
    $c = $script:SIHeartbeatFields
    $props = if ($Pool.PSObject.Properties['properties']) { $Pool.properties } else { $null }
    if ($null -eq $props) { return $null }
    $tier = [string]$props.tier
    $cnt = ConvertTo-SIHeartbeatInt $props.count
    if (-not $tier -or $null -eq $cnt) { return $null }
    $building = $false
    foreach ($r in @($Runs)) {
        if ($null -eq $r) { continue }
        $st = ''
        if ($r.PSObject.Properties['properties'] -and $r.properties -and $r.properties.PSObject.Properties['status']) { $st = [string]$r.properties.status }
        elseif ($r.PSObject.Properties['status']) { $st = [string]$r.status }
        if (@($c.BuildPoolActiveRuns) -contains $st) { $building = $true; break }
    }
    New-SIHeartbeatOrdered -Names $c.Fields.BuildPool -Values ([ordered]@{ tier = $tier; count = [int]$cnt; building = [bool]$building; checkedUtc = (ConvertTo-SIHeartbeatUtc $NowUtc) })
}

# =====================================================================================================================
function Get-SIHeartbeatRecordBytes {
    param([Parameter(Mandatory)]$Record)
    [System.Text.Encoding]::UTF8.GetByteCount(($Record | ConvertTo-Json -Depth 10 -Compress))
}

function Limit-SIHeartbeatRecordSize {
    <#
        PURE (in place). An identified heartbeat at most -MaxBytes (48 KB, Invardia's limit for an identified heartbeat):
        while over it, the optional fields are dropped in the fixed order of Get-SIHeartbeatFieldDropOrder. Returns
        @{ Record; Dropped; Bytes }.
    #>
    param([Parameter(Mandatory)]$Record, [int]$MaxBytes = $script:SIHeartbeatFields.MaxBytes)
    $dropped = New-Object System.Collections.Generic.List[string]
    $bytes = Get-SIHeartbeatRecordBytes $Record
    foreach ($n in $script:SIHeartbeatFields.DropOrder) {
        if ($bytes -le $MaxBytes) { break }
        if ($Record.PSObject.Properties[$n]) { $Record.PSObject.Properties.Remove($n); $dropped.Add($n); $bytes = Get-SIHeartbeatRecordBytes $Record }
    }
    [pscustomobject]@{ Record = $Record; Dropped = $dropped.ToArray(); Bytes = $bytes }
}

# =====================================================================================================================
#  The readers (seams) and the one call the tick makes
# =====================================================================================================================
function Get-SIHeartbeatArmScope {
    <# The install's subscription and resource group (the jobs, the Pro database): SI_FLOW_* (the runner's), else the run's
       settings. @{ Sub; Rg } -- '' when not known. #>
    $sub = @([string]$env:SI_FLOW_SUBSCRIPTIONID, [string]$global:SI_AzSubscriptionId) | Where-Object { "$_".Trim() } | Select-Object -First 1
    $rg = @([string]$env:SI_FLOW_RESOURCEGROUP, [string]$global:SI_Bootstrap_ResourceGroupName) | Where-Object { "$_".Trim() } | Select-Object -First 1
    [pscustomobject]@{ Sub = "$sub".Trim(); Rg = "$rg".Trim() }
}

function Invoke-SIHeartbeatArmList {
    <# A list from ARM through -Arm { param($Path) } (GET), following nextLink up to -Pages pages. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path, [int]$Pages = 5)
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Path; $i = 0
    while ($next -and $i -lt $Pages) {
        $i++
        $page = & $Arm $next
        if ($null -eq $page) { break }
        foreach ($v in @($page.value)) { if ($null -ne $v) { $items.Add($v) } }
        $next = if ($page.PSObject.Properties['nextLink']) { [string]$page.nextLink } else { '' }
    }
    # unrolled: callers take @( ... )
    $items.ToArray()
}

function New-SIHeartbeatFields {
    <#
        THE ONE CALL of the tick: the eight fields of THIS heartbeat (an ordered dictionary name -> value, possibly empty) --
        only the fields whose switch is on for -Ring (-Switch: @{ <Field> = $true/$false } overrides it, tests), each read
        and built in its own try, each checked against the agreed schema (Test-SIHeartbeatField) and left out when it does
        not pass. NEVER throws. The seams (a test session reads nothing without them):
          -CfgRows / -CfgInvoke        the rows of Get-SIHeartbeatFieldsCfgSql / { param($Sql, $Params, $Mode) } (the Pro database)
          -SecurityRows / -DataInvoke  the rows of Get-SIHeartbeatSecuritySql / the data database
          -Arm                         { param($Path) } -> an ARM GET answer (default Invoke-SIArm as the job's identity)
          -SourceRows / -RunQuery      the rows of Get-SIHeartbeatSourcesKql / { param($Kql) } (default Invoke-SITelemetryLaQuery)
          -Counts                      the heartbeat's Counts (Security reuses the #719 keys)
          -Installed                   the release this job runs (default Get-SITelemetryReleaseVersion)
          -ScoreState                  the security scores' permission state (default Get-SISecurityScoreState, set by the Counts)
          -Log                         { param($Line) } for the one line per process about a field that could not be read
    #>
    param([AllowNull()]$Ring, [Parameter(Mandatory)][datetime]$NowUtc, [hashtable]$Switch = @{},
          [object[]]$CfgRows, [scriptblock]$CfgInvoke, [object[]]$SecurityRows, [scriptblock]$DataInvoke,
          [scriptblock]$Arm, [object[]]$SourceRows, [scriptblock]$RunQuery, [System.Collections.IDictionary]$Counts = @{},
          [AllowEmptyString()][string]$Installed, [scriptblock]$Log, [AllowNull()]$ScoreState, [object[]]$CopyRows,
          # #902: the held reports' rows (Get-SIHeartbeatHoldSql; the test seam -- default: read through -DataInvoke)
          [object[]]$HoldRows,
          # #904: the Pro database's used space / maximum size @{ sqlUsedMb; sqlMaxMb } (the test seam -- default: the Counts'
          # sqlUsedMb / sqlMaxMb, else ONE cheap read, Get-SISqlSpaceCounts; never in a test session)
          [System.Collections.IDictionary]$DatabaseSpace,
          # #1043: the rows of Get-SIHeartbeatDataOutSql (the test seam -- default: read through -CfgInvoke, once per tick)
          [object[]]$DataOutRows,
          # framework 8.4: the outbox's backlog row { Pending; OldestUtc } (Get-SIUplinkOutboxBacklogSql; the test seam --
          # default: read through -CfgInvoke, never in a test session)
          [object[]]$UplinkBacklogRows,
          # #1210: the row of Get-SIHeartbeatDatabaseStatsSql (the test seam -- default: ONE read through -DataInvoke, the
          # database SI writes its data to and refreshes the statistics of; never in a test session)
          [object[]]$DatabaseStatsRows)
    $out = [ordered]@{}
    $problems = New-Object System.Collections.Generic.List[string]
    try {
        $c = $script:SIHeartbeatFields
        $on = @{}
        foreach ($n in $c.Names) { $on[$n] = $(if ($Switch.ContainsKey($n)) { [bool]$Switch[$n] } else { (Resolve-SIUplinkHeartbeatFieldSwitch -Field $n -Ring $Ring).On }) }
        if (-not @($on.Values | Where-Object { $_ }).Count) { return $out }
        $testSession = [bool](Get-Module -Name Pester)
        $want = { param([string[]]$names) [bool](@($names | Where-Object { $on[$_] }).Count) }

        # the settings database: Pipeline, Jobs, Update, Mail, Warnings
        if ($null -eq $CfgRows -and $CfgInvoke -and (& $want @('Pipeline', 'Jobs', 'Update', 'Mail', 'Warnings'))) {
            try { $CfgRows = @(& $CfgInvoke (Get-SIHeartbeatFieldsCfgSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } }) }
            catch { $CfgRows = $null; $problems.Add(('the settings database could not be read ({0})' -f $_.Exception.Message)) }
        }
        # ARM: ONE list of the install's jobs (+ the executions of the jobs that are never a step), the database + its metrics
        $armJobs = $null; $execs = @{}
        if (-not $Arm -and -not $testSession -and (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { $Arm = { param($Path) Invoke-SIArm -Method GET -Path $Path } }
        $scope = Get-SIHeartbeatArmScope
        if ($Arm -and $scope.Sub -and $scope.Rg -and (& $want @('Jobs', 'Update', 'Mail', 'Warnings'))) {
            try {
                $base = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f $scope.Sub, $scope.Rg
                $armJobs = @(Invoke-SIHeartbeatArmList -Arm $Arm -Path ('{0}?api-version={1}' -f $base, $c.ArmJobsApi) | ForEach-Object { ConvertFrom-SIHeartbeatArmJob $_ } | Where-Object { $_.Key })
                if ($on['Jobs']) {
                    $map = $null; try { $map = Get-SIJobFlowMap } catch { $map = $null }
                    foreach ($j in @($armJobs)) {
                        # the runner itself (flow, every 5 minutes) is the Pipeline field -- its executions are never read
                        if ($j.Key -eq 'flow' -or -not $map -or -not $map.Jobs.Contains($j.Key) -or -not $map.Jobs[$j.Key].NeverInFlow) { continue }
                        try { $execs[$j.Key] = @(Invoke-SIHeartbeatArmList -Arm $Arm -Path ('{0}/{1}/executions?api-version={2}' -f $base, $j.Name, $c.ArmJobsApi) -Pages $c.ExecutionPages) } catch { $execs[$j.Key] = @() }
                    }
                }
            } catch { $armJobs = $null; $problems.Add(('the job list could not be read ({0})' -f $_.Exception.Message)) }
        }
        # run health: ONE Log Analytics query (Sources, and the source refusals among the Warnings)
        $srcFailed = ''
        if ($null -eq $SourceRows -and (& $want @('Sources', 'Warnings'))) {
            if (-not $RunQuery -and -not $testSession -and (Get-Command -Name Invoke-SITelemetryLaQuery -ErrorAction SilentlyContinue)) { $RunQuery = { param($Kql) Invoke-SITelemetryLaQuery -Query $Kql } }
            if ($RunQuery) {
                try { $SourceRows = & $RunQuery (Get-SIHeartbeatSourcesKql); if ($null -ne $SourceRows) { $SourceRows = @($SourceRows) } }
                catch { $SourceRows = @(); $srcFailed = [string]$_.Exception.Message; if (-not $srcFailed) { $srcFailed = 'the query failed' } }
            }
        }
        $sources = $null
        if ($null -ne $SourceRows -or $srcFailed) { try { $sources = @(Get-SIHeartbeatSources -Rows @($SourceRows) -NowUtc $NowUtc -Failed $srcFailed); if (-not $sources.Count) { $sources = $null } } catch { $sources = $null } }

        # #904: how full the Pro database is -- the Counts' read when they carry it (never read twice), else one cheap read
        $space = $null
        if ($PSBoundParameters.ContainsKey('DatabaseSpace')) { $space = $DatabaseSpace }
        elseif ($Counts -and ($Counts.Contains('sqlUsedMb') -or $Counts.Contains('sqlMaxMb'))) {
            $space = @{}; foreach ($k in 'sqlUsedMb', 'sqlMaxMb') { if ($Counts.Contains($k)) { $space[$k] = $Counts[$k] } }
        }
        elseif (-not $testSession -and (& $want @('Database', 'Warnings')) -and (Get-Command -Name Get-SISqlSpaceCounts -ErrorAction SilentlyContinue)) {
            try { $space = Get-SISqlSpaceCounts; if ($space -and -not $space.Count) { $space = $null } } catch { $space = $null }
        }
        $hasInstalled = $PSBoundParameters.ContainsKey('Installed')
        # the security scores' permission state, as the Counts read left it (si-perm-1004)
        if (-not $PSBoundParameters.ContainsKey('ScoreState') -and (Get-Command -Name Get-SISecurityScoreState -ErrorAction SilentlyContinue)) {
            try { $ScoreState = Get-SISecurityScoreState } catch { $ScoreState = $null }
        }
        # #871: the Security rows, read at most once per tick and shared by Warnings and Security (a child scope cannot set a local)
        $tick = @{ SecurityRows = $SecurityRows; CopyRows = $CopyRows; CopyRead = ($null -ne $CopyRows) }
        # the shown run's publish and its copies (the data database, one key read), read at most once per tick, for Warnings
        # (si-data-1401) only -- never Pipeline, whose state follows the run record alone; a read that fails says nothing
        $readCopy = {
            if (-not $tick.CopyRead) {
                $tick.CopyRead = $true
                if ($DataInvoke) { try { $tick.CopyRows = @(& $DataInvoke (Get-SIHeartbeatPublishedCopySql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } }) } catch { $tick.CopyRows = $null } }
            }
            # as ONE array (an empty read is still a read), or $null when there was none
            if ($null -eq $tick.CopyRows) { return $null }
            , @($tick.CopyRows)
        }
        # Database's agreed six: the database from ARM + its metrics, and the size (#904)
        $dbCore = {
                # #904: the size is sent also when ARM is not read (usedMb / maxSizeMb; the rest null)
                if (-not $Arm -or -not $scope.Sub -or -not $scope.Rg) { return (Get-SIHeartbeatDatabase -Db $null -Space $space) }
                $srv = ("$($global:SI_ProSqlServer)".Trim() -split '\.')[0]; $db = "$($global:SI_ProSqlDatabase)".Trim()
                if (-not $srv -or -not $db) { return (Get-SIHeartbeatDatabase -Db $null -Space $space) }
                $id = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Sql/servers/{2}/databases/{3}' -f $scope.Sub, $scope.Rg, $srv, $db
                $d = & $Arm ('{0}?api-version={1}' -f $id, $c.ArmSqlApi)
                if ($null -eq $d) { return (Get-SIHeartbeatDatabase -Db $null -Space $space) }
                $tier = ''; try { $tier = [string]$d.sku.tier } catch { }
                $names = if ($tier -in @('Basic', 'Standard', 'Premium')) { 'log_write_percent,dtu_consumption_percent' } else { 'log_write_percent,cpu_percent' }
                $m = $null
                try { $m = & $Arm ('{0}/providers/Microsoft.Insights/metrics?api-version={1}&metricnames={2}&timespan=PT1H&interval=PT1M&aggregation=Maximum' -f $id, $c.ArmMetricsApi, $names) } catch { $m = $null }
                Get-SIHeartbeatDatabase -Db $d -Metrics $m -Space $space }
        $build = [ordered]@{
            Pipeline = {
                if ($null -eq $CfgRows) { return $null }
                # the progress and estimated end ride along only where their own switch says so (default: every ring);
                # built in their own try -- a problem there never costs the agreed seven
                $etaOn = $(if ($Switch.ContainsKey('PipelineEta')) { [bool]$Switch['PipelineEta'] } else { (Resolve-SIUplinkPipelineEtaSwitch -Ring $Ring).On })
                # #1035: 'stopped' for a run stopped / cancelled before its end -- its own switch, off until Invardia agrees
                $stoppedOn = $false
                try { $stoppedOn = $(if ($Switch.ContainsKey('PipelineStopped')) { [bool]$Switch['PipelineStopped'] } else { [bool](Resolve-SIUplinkPipelineStoppedSwitch -Ring $Ring).On }) } catch { $stoppedOn = $false }
                $pv = $null
                if ($etaOn) {
                    try {
                        $pe = Get-SIHeartbeatPipeline -Rows $CfgRows -NowUtc $NowUtc -Eta -Stopped:$stoppedOn
                        $why = Test-SIHeartbeatField -Name 'Pipeline' -Value $pe
                        if (-not $why) { $pv = $pe }
                        else { $problems.Add(('the pipeline estimate was left out: {0}' -f $why)) }
                    } catch { $problems.Add(('the pipeline estimate could not be made ({0})' -f $_.Exception.Message)) }
                }
                if ($null -eq $pv) { $pv = Get-SIHeartbeatPipeline -Rows $CfgRows -NowUtc $NowUtc -Stopped:$stoppedOn }
                # the running steps far past their last run's time with no progress (si-flow-1204), named -- in their own try:
                # a problem there never costs the rest of Pipeline; none = the key is left out
                if ($null -ne $pv) {
                    try {
                        $stw = ConvertTo-SIHeartbeatStalledWire -Stalled @(Get-SIHeartbeatStalledSteps -Rows $CfgRows -NowUtc $NowUtc)
                        if (@($stw).Count) {
                            $px = Add-SIPipelineStalled -Pipeline $pv -Steps $stw
                            $why = Test-SIHeartbeatField -Name 'Pipeline' -Value $px
                            if (-not $why) { $pv = $px } else { $problems.Add(('the stalled steps were left out: {0}' -f $why)) }
                        }
                    } catch { $problems.Add(('the stalled steps could not be told ({0})' -f $_.Exception.Message)) }
                }
                # the rows of retired collections still waiting to be removed (the data database, index reads only), in its
                # own try: unknown or not right = the key is left out, never the rest of Pipeline
                if ($null -ne $pv -and $DataInvoke) {
                    try {
                        $hk = Get-SIHeartbeatHousekeepingRowsLeft -DataInvoke $DataInvoke
                        if ($null -ne $hk) {
                            $px = Add-SIPipelineHousekeeping -Pipeline $pv -RowsLeft $hk
                            $why = Test-SIHeartbeatField -Name 'Pipeline' -Value $px
                            if (-not $why) { $pv = $px } else { $problems.Add(('the housekeeping count was left out: {0}' -f $why)) }
                        }
                    } catch { $problems.Add(('the housekeeping count could not be read ({0})' -f $_.Exception.Message)) }
                }
                $pv }
            Jobs     = { if ($null -ne $CfgRows -or $null -ne $armJobs) { Get-SIHeartbeatJobs -Rows @($CfgRows) -ArmJobs @($armJobs) -Executions $execs } }
            Sources  = { if ($null -ne $sources) { ConvertTo-SIHeartbeatSourcesWire -Sources @($sources) } }
            Database = {
                $dbv = & $dbCore
                # #1210 (SQL-STATS-PROOF): the three statistics keys after the agreed six -- ONE read of the database; a read
                # that fails (or a value that does not pass) leaves the three out and is said once, never the rest of Database
                if ($null -eq $dbv -or -not $c.DatabaseSendStats) { return $dbv }
                try {
                    $sr = $DatabaseStatsRows
                    if ($null -eq $sr -and -not $testSession -and $DataInvoke) { $sr = @(& $DataInvoke (Get-SIHeartbeatDatabaseStatsSql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
                    if ($null -eq $sr) { return $dbv }
                    # the refresh time comes from the settings read: not read = not known -- the three are left out (a null
                    # statsRefreshedUtc would read as "never refreshed")
                    if ($null -eq $CfgRows) { $problems.Add('the settings database was not read -- Database goes without the statistics'); return $dbv }
                    $st = ConvertFrom-SIHeartbeatDatabaseStats -Rows @($sr)
                    if ($null -eq $st) { $problems.Add('the database''s statistics were not answered whole -- Database goes without them'); return $dbv }
                    $dx = Add-SIHeartbeatDatabaseStats -Database $dbv -Stats $st -RefreshedUtc (Get-SIHeartbeatStatsRefreshedUtc -Rows @($CfgRows))
                    $why = Test-SIHeartbeatField -Name 'Database' -Value $dx
                    if ($why) { $problems.Add(('the database''s statistics were left out: {0}' -f $why)); return $dbv }
                    return $dx
                } catch { $problems.Add(('the database''s statistics could not be read ({0}) -- Database goes without them' -f $_.Exception.Message)); return $dbv }
            }
            Update   = {
                $inst = if ($hasInstalled) { $Installed } elseif (Get-Command -Name Get-SITelemetryReleaseVersion -ErrorAction SilentlyContinue) { Get-SITelemetryReleaseVersion } else { '' }
                $cron = ''; if ($null -ne $armJobs) { $u = @($armJobs | Where-Object { $_.Key -eq 'updater' })[0]; if ($u) { $cron = $u.Cron } }
                Get-SIHeartbeatUpdate -Rows @($CfgRows) -Installed $inst -UpdaterCron $cron -NowUtc $NowUtc }
            Mail     = { if ($null -ne $CfgRows -or $null -ne $armJobs) { Get-SIHeartbeatMail -Rows @($CfgRows) -ArmJobs $armJobs } }
            Warnings = {
                # the shown run's copies (the data database, one key read); a read that fails says nothing
                $CopyRows = & $readCopy
                # #871: the Security read (made once per tick, shared with Security) says whether the figures are from an earlier collection
                if ($null -eq $tick.SecurityRows -and $DataInvoke) { try { $tick.SecurityRows = @(& $DataInvoke (Get-SIHeartbeatSecuritySql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } }) } catch { $tick.SecurityRows = $null } }
                $secRows = $tick.SecurityRows
                # #902: the reports held on purpose -- only once the hold contract is live for this install (REMOVE-ME switch:
                # Invardia takes a Warnings code only from the catalogue it has); a read that fails says nothing
                $holdRows = $null
                $holdOn = $(if ($Switch.ContainsKey('HoldFields')) { [bool]$Switch['HoldFields'] } else { try { [bool](Resolve-SIUplinkHoldFieldsSwitch -Ring $Ring).On } catch { $false } })
                if ($holdOn) {
                    if ($null -ne $HoldRows) { $holdRows = $HoldRows }
                    elseif ($DataInvoke) { try { $holdRows = @(& $DataInvoke (Get-SIHeartbeatHoldSql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } }) } catch { $holdRows = $null } }
                }
                # read = ONE array, also when it is empty: "Warnings: []" is how a cleared warning clears at Invardia (a field
                # not sent is KEPT there, the uplink contract) -- 2026-10-26, si-data-1401 stayed raised after its copy caught up
                if ($null -ne $CfgRows -or $null -ne $sources -or $null -ne $armJobs -or $null -ne $ScoreState -or $null -ne $CopyRows -or $null -ne $secRows -or $null -ne $holdRows -or $null -ne $space) { , [object[]]@(Get-SIHeartbeatWarnings -Rows @($CfgRows) -Sources $sources -NowUtc $NowUtc -ArmJobs $armJobs -ScoreState $ScoreState -CopyRows $CopyRows -SecurityRows $secRows -HoldRows $holdRows -DatabaseSpace $space) } }
            Security = {
                if ($null -eq $tick.SecurityRows -and $DataInvoke) { $tick.SecurityRows = @(& $DataInvoke (Get-SIHeartbeatSecuritySql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } }) }
                if ($null -ne $tick.SecurityRows) { Get-SIHeartbeatSecurity -Rows $tick.SecurityRows -Counts $Counts } }
            # 2026-10-26: what customers SEE (the published collection) next to the newest complete one; a read that fails says nothing
            Published = {
                if (-not $DataInvoke) { return }
                $pr = $null
                try { $pr = @(& $DataInvoke (Get-SIHeartbeatPublishedSql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } }) } catch { $pr = $null }
                Get-SIHeartbeatPublished -Rows $pr }
            # #1043: the data-out outputs' progress (cfg.DataOutBatch + cfg.ConnectorRun, ONE read); a read that fails says nothing
            DataOut = {
                $dr = $DataOutRows
                if ($null -eq $dr) {
                    # a test session reads them only from -DataOutRows (the other suites' database fakes never see this read)
                    if (-not $CfgInvoke -or $testSession) { return }
                    $dr = @(& $CfgInvoke (Get-SIHeartbeatDataOutSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { [pscustomobject]$_ } else { $_ } })
                }
                , [object[]]@(Get-SIHeartbeatDataOut -Rows @($dr) -NowUtc $NowUtc) }
            # framework rule 11g: the private install's image build pool -- the install's registry, its agent pool, its newest
            # runs (three ARM reads, only while the field's switch is on); no registry / no pool = the field is left out
            BuildPool = {
                if (-not $Arm -or -not $scope.Sub -or -not $scope.Rg) { return }
                $rgPath = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.ContainerRegistry/registries' -f $scope.Sub, $scope.Rg
                foreach ($reg in @(Invoke-SIHeartbeatArmList -Arm $Arm -Path ('{0}?api-version={1}' -f $rgPath, $c.ArmAcrApi) -Pages 1)) {
                    $rid = [string]$reg.id; if (-not $rid) { continue }
                    $pool = @(Invoke-SIHeartbeatArmList -Arm $Arm -Path ('{0}/agentPools?api-version={1}' -f $rid, $c.ArmAcrTasksApi) -Pages 1)[0]
                    if ($null -eq $pool) { continue }
                    # runs that cannot be read: "building" is not known -- the field is left out, never a guess
                    $runs = @(Invoke-SIHeartbeatArmList -Arm $Arm -Path ('{0}/runs?api-version={1}&$top=10' -f $rid, $c.ArmAcrTasksApi) -Pages 1)
                    return (Get-SIHeartbeatBuildPool -Pool $pool -Runs $runs -NowUtc $NowUtc)
                }
            }
            # framework 8.4: the run reports kept unsent (cfg.UplinkOutbox) -- ONE small read of the Pro database; no database /
            # no table yet / not readable = the field is left out. Caught up = pending 0, oldestUtc null (sent, never dropped).
            UplinkBacklog = {
                $br = $UplinkBacklogRows
                if ($null -eq $br) {
                    if (-not $CfgInvoke -or $testSession) { return }
                    $br = @(& $CfgInvoke (Get-SIUplinkOutboxBacklogSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
                }
                $b0 = @(@($br) | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
                if ($null -eq $b0) { return }
                ConvertTo-SIUplinkBacklog -Row $b0 -NowUtc $NowUtc
            }
        }
        foreach ($n in $c.Names) {
            if (-not $on[$n]) { continue }
            try {
                $v = & $build[$n]
                if ($null -eq $v) { continue }
                # Published read and nothing published yet: LEFT OUT (Invardia 1.0.593: "leave the field out when nothing is published")
                if ($n -eq 'Published' -and $v -is [string] -and $v -ceq 'none') { continue }
                # an array field comes back as ONE array (the builders return it with a leading comma)
                # an empty Jobs / Sources says nothing; an empty Warnings that WAS read is sent as [] (none now)
                # #1043: an empty DataOut that WAS read is sent as [] too (no outputs: Invardia replaces the list)
                if ($n -in @('Jobs', 'Sources', 'Warnings', 'DataOut')) { $v = @($v | ForEach-Object { $_ }) ; if (-not $v.Count -and $n -notin @('Warnings', 'DataOut')) { continue }; $v = [object[]]$v }
                $why = Test-SIHeartbeatField -Name $n -Value $v
                if ($why) { $problems.Add(('{0} was left out: {1}' -f $n, $why)); continue }
                $out[$n] = $v
            } catch { $problems.Add(('{0} could not be read ({1})' -f $n, $_.Exception.Message)) }
        }
    } catch { $problems.Add(('the fields could not be read ({0})' -f $_.Exception.Message)) }
    if ($problems.Count -and -not $global:SI_HeartbeatFieldProblemsSaid) {
        $global:SI_HeartbeatFieldProblemsSaid = $true
        $line = ' [INFO] The Invardia support link leaves out what could not be read: ' + (($problems | ForEach-Object { "$_" -replace '\s+', ' ' }) -join '; ')
        if ($line.Length -gt 600) { $line = $line.Substring(0, 597) + '...' }
        try { if ($Log) { & $Log $line } else { Write-Host $line } } catch { }
    }
    $out
}
