#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight -- the pipeline runner (#269, #306). One wake-up: the queued runs of the install's pipeline, one after
    the other, each stage when the stage before it has ended, each step when the step before it has ended.

.DESCRIPTION
    The Daily pipeline = Collect -> Correlate -> Deliver (config\job-flow.locked.json). A schedule belongs to the
    pipeline; "Run now" works on the pipeline, on one stage or on one step. Nothing ever runs over anything else: every
    run -- scheduled or Run now, from the web app or on the VM -- takes the install's ONE lock; a request that finds it
    busy waits in the queue (engine\_shared\SI-Pipeline.ps1).

    Container (caj-si-flow, -HostKind Container): the job's timer wakes this runner every 5 minutes. Each step's
    Container Apps job is started through Azure Resource Manager as the job's own identity (Container Apps Jobs
    Contributor on the jobs' resource group -- Bootstrap grants it), and polled until it ends.
    VM (-HostKind Vm, one scheduled task every 5 minutes -- setup\Install-SIFlowTask.ps1): each step's launcher in its
    own PowerShell process. Run now on a VM: .\engine\flow\Invoke-SIJobFlowRun.ps1 -HostKind Vm -Stage correlate
    (or -Step asset-datasync, or -Force for the whole pipeline) -- queued when a run is going, run when it is free.

    The definition: the Pro database (cfg.JobFlow, written by Operations > Jobs) when one is configured; else
    config\job-flow.custom.json (a VM's file; a container gets it from the install's storage with the other
    customisation files); else the default pipeline over the jobs that are installed. A schema-1 flow is read as a
    pipeline (migrated in memory, lossless). Mode 'schedules' = the jobs run on their own timers: the schedule does
    nothing here (a request made explicitly still runs).

    The run record: cfg.FlowRun + cfg.FlowStepRun (Pro), else <storage>/sistate/flow/flow-run.json (a container), else
    data\flow\flow-run.json (a VM). The lock + queue: cfg.PipelineLock + cfg.PipelineQueue (Pro), else
    sistate/flow/pipeline.lock + pipeline-queue.json (a container), else data\flow\ (a VM). Plus one run-health row per
    step and per run (SI_RunHealth_CL; Engine 'flow' / 'flow:<step>'), the audit trail (Pro: job.flow.run) and ONE
    telemetry run per run (#226).

    Environment (a container; the web app sets them on one execution): SI_FLOW_DRAIN=1 (run what waits in the queue
    now), SI_FLOW_FORCE=1 (Run the pipeline now), SI_FLOW_STAGE=<stage>, SI_FLOW_STEP=<job>, SI_FLOW_FROM_STEP=<job>
    (re-run from that step), SI_FLOW_TRIGGER (schedule | manual), SI_AUDIT_STARTED_BY (who asked).
    CANCEL THE RUNNING RUN (#700): SI_FLOW_CANCEL=1 with SI_FLOW_CANCEL_REASON=<why> (required) and SI_AUDIT_STARTED_BY
    (who), optionally SI_FLOW_CANCEL_RUN=<run id> -- the run is marked cancelled (never resumed), its running job
    executions are stopped, the lock is released at once and the cancel is on the audit trail; this execution then ends
    (the next queued request starts on the next wake-up). Web app: Operations > Jobs, "Cancel this run". Support: start
    caj-si-flow once with these values (VM: -Cancel -CancelReason '<why>').
    Exit 0: every run succeeded, or there was nothing to do (or it waits in the queue), or its only failures were steps
    Microsoft throttled (#532, THROTTLE-IS-NORMAL); 1: a run failed or stopped.
#>
[CmdletBinding()]
param(
    [ValidateSet('Container', 'Vm')][string]$HostKind = 'Container',
    [string]$FromStep = $env:SI_FLOW_FROM_STEP,
    [string]$Stage = $env:SI_FLOW_STAGE,
    [string]$Step = $env:SI_FLOW_STEP,
    [switch]$Force,
    [string]$Trigger = $(if ($env:SI_FLOW_TRIGGER) { $env:SI_FLOW_TRIGGER } else { 'schedule' }),
    # who asked for a Run now (the web app passes the person; on a VM the Windows account)
    [string]$RequestedBy = $(if ($env:SI_AUDIT_STARTED_BY) { $env:SI_AUDIT_STARTED_BY } else { '' }),
    # VM: which launcher flavour each step runs (community-vm | internal-vm)
    [string]$Flavour = 'community-vm',
    [int]$PollSeconds = 30,
    # #700: cancel the running pipeline run (and nothing else) -- who asks is -RequestedBy, why is -CancelReason (required)
    [switch]$Cancel,
    [string]$CancelReason = $env:SI_FLOW_CANCEL_REASON,
    [string]$CancelRun = $env:SI_FLOW_CANCEL_RUN
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$siRoot = Split-Path -Parent (Split-Path -Parent $here)
. (Join-Path $siRoot 'engine/_shared/SI-JobFlow.ps1')
if (-not $Force -and "$env:SI_FLOW_FORCE" -in @('1', 'true', 'yes')) { $Force = $true }
if (-not $Cancel -and "$env:SI_FLOW_CANCEL" -in @('1', 'true', 'yes')) { $Cancel = $true }
# #700: the version this runner runs -- recorded on every new run, so the updater can tell a run of another version
$siVersion = ''
try { $vf = Join-Path $siRoot 'VERSION'; if (Test-Path -LiteralPath $vf) { $siVersion = ([IO.File]::ReadAllText($vf)).Trim() } } catch { $siVersion = '' }
# VM: the install's config (workspace, endpoint, sign-in) -- for the run-health rows. The steps load it themselves.
if ($HostKind -eq 'Vm' -and -not $global:SI_WorkspaceResourceId) {
    $cfg = Join-Path $siRoot 'config/SecurityInsight.custom.ps1'
    if (Test-Path -LiteralPath $cfg) { try { . $cfg } catch { Write-Warning ('[pipeline] the config could not be loaded ({0}) -- run health is not recorded' -f $_.Exception.Message) } }
}
$say = { param($Level, $Message) $c = switch ($Level) { 'WARN' { 'Yellow' } 'ERROR' { 'Red' } default { 'Gray' } }; Write-Host ('[pipeline] {0}' -f $Message) -ForegroundColor $c }

# ---- the Pro database (definition + run records + lock + queue + audit), when this install has one ----
$proStore = $null
if ([string]$global:SI_ProSqlServer -and [string]$global:SI_ProSqlDatabase) {
    try {
        # The database store comes from the settings layer (engine/pro-settings/SI-ProSettings.ps1), which BOTH editions ship
        # (#750 (a)): the Community edition has the database and the web app, so its runs, lock, queue ("Run now") and
        # definition (Operations > Jobs) live there too. It used to come from the connector registry helper, which only the
        # Pro package carries -- the Community env 4 install (2026-10-28) ran its pipeline on the blob store while the web
        # app read an empty cfg.FlowRun / cfg.PipelineQueue. SI-CommunityPayload now refuses that dependency here.
        if (-not (Get-Command -Name New-SIProSettingsStore -ErrorAction SilentlyContinue)) {
            $ps = Join-Path $siRoot 'engine/pro-settings/SI-ProSettings.ps1'
            if (Test-Path -LiteralPath $ps) { . $ps }
        }
        if (Get-Command -Name New-SIProSettingsStore -ErrorAction SilentlyContinue) {
            $first = { param([object[]]$v) foreach ($x in $v) { if (-not [string]::IsNullOrWhiteSpace([string]$x)) { return [string]$x } }; '' }
            $proStore = New-SIProSettingsStore -Server ([string]$global:SI_ProSqlServer) -Database ([string]$global:SI_ProSqlDatabase) `
                -AppId (& $first @($global:SI_SPN_AppId, $global:HighPriv_Modern_ApplicationID_Azure)) `
                -TenantId (& $first @($global:SI_SPN_TenantId, $global:AzureTenantId)) `
                -CertThumbprint (& $first @($global:SI_SPN_CertThumbprint, $global:HighPriv_Modern_CertificateThumbprint_Azure))
        }
        $au = Join-Path $siRoot 'engine/pro-settings/SI-Audit.ps1'
        if ($proStore -and (Test-Path -LiteralPath $au) -and -not (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue)) { . $au }
    } catch { & $say 'WARN' ('the Pro database could not be opened ({0}) -- the pipeline runs from the file / default definition' -f $_.Exception.Message); $proStore = $null }
}

# ---- the seams: ARM (container) or local processes (VM) ----
if ($HostKind -eq 'Container') {
    $sub = if ($env:SI_FLOW_SUBSCRIPTIONID) { $env:SI_FLOW_SUBSCRIPTIONID } else { [string]$global:SI_AzSubscriptionId }
    $rg  = if ($env:SI_FLOW_RESOURCEGROUP) { $env:SI_FLOW_RESOURCEGROUP } else { [string]$global:SI_Bootstrap_ResourceGroupName }
    if (-not $sub -or -not $rg) { throw 'the pipeline does not know where its jobs are: SI_FLOW_SUBSCRIPTIONID / SI_FLOW_RESOURCEGROUP (Bootstrap sets them on caj-si-flow)' }
    if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-AzRest.ps1') }
    $seams = New-SIJobFlowArmSeams -SubscriptionId $sub -ResourceGroup $rg
    # the plain ARM seams, kept: collecting in parts wraps $seams below, and the wrapper has no Arm / Base of its own
    $armSeams = $seams
    # the runner's own health check, on a run somebody asked for (a scheduled wake-up proves the timer is on): "neither mode"
    # -- caj-si-flow without its timer and no job of the pipeline on its own -- means nothing runs by itself. Said plainly;
    # every update repairs it (Invoke-SIJobOrchestrationRepair).
    if (-not $Cancel -and ($Force -or $Stage -or $Step -or $FromStep -or "$env:SI_FLOW_DRAIN" -in @('1', 'true', 'yes'))) {
        try {
            # every page (Azure lists 20 jobs a page -- a job on page 2 counts too)
            $armJobs = New-Object System.Collections.Generic.List[object]; $p = $seams.Base; $pg = 0
            while ($p -and $pg -lt 50) { $r = & $seams.Arm 'GET' $p $null; $pg++; foreach ($v in @($r.value)) { if ($v) { $armJobs.Add($v) } }; $p = if ($r -and $r.PSObject.Properties['nextLink'] -and $r.nextLink) { [string]$r.nextLink } else { $null } }
            $nm = Test-SIJobOrchestrationNeitherMode -Jobs (ConvertTo-SIJobFlowTriggerList -ArmJobs $armJobs.ToArray())
            if ($nm.Neither) { & $say 'WARN' ('{0} -- this run was started by hand; the next update switches the install to the pipeline (now: setup\Switch-SIJobOrchestration.ps1 -Mode flow -Apply)' -f $nm.Why) }
        } catch { }
    }
    $installed = @()
    try { $installed = @($seams.List() | Where-Object { $_ -like 'caj-si-*' }) } catch { & $say 'WARN' ('the jobs could not be listed ({0})' -f $_.Exception.Message) }
    # #475: KEDA for the Collect stage -- an engine with a producer job runs as producer + workers, and its step follows the
    # run's parts (Add-SIJobFlowCollectParts); the engine counts as installed by its producer
    $producers = @($installed | Where-Object { $_ -match '^caj-si-.+-producer$' })
    if ($producers.Count -and [string]$global:SI_StorageAccount) {
        if (-not (Get-Command -Name New-SICollectBlobStore -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-CollectParts.ps1') }
        $seams = Add-SIJobFlowCollectParts -Seams $seams -Store (New-SICollectBlobStore -Account ([string]$global:SI_StorageAccount)) -ProducerJobs $producers
        foreach ($p in $producers) { $base = $p -replace '-producer$', ''; if ($installed -notcontains $base) { $installed += $base } }
        & $say 'INFO' ('collect in parts (producer + workers): {0}' -f ((@($producers | ForEach-Object { ($_ -replace '^caj-si-', '') -replace '-producer$', '' })) -join ', '))
    }
} else {
    $seams = New-SIJobFlowVmSeams -Root $siRoot -Flavour $Flavour
    $installed = @(Get-SIJobFlowVmInstalled -Root $siRoot -Flavour $Flavour)
}

# ---- CR8 (framework 12.11f item 1): the job trigger changes the web app ASKED for (it holds start-only rights on the jobs)
# -- applied first, as this job's own identity, the trigger and tags only, read back, each row recorded. Never stops the run.
if ($HostKind -eq 'Container' -and $proStore -and $armSeams) {
    try {
        $jtr = Join-Path $siRoot 'engine/_shared/SI-JobTriggerRequests.ps1'
        if (Test-Path -LiteralPath $jtr) {
            . $jtr
            $null = Invoke-SIJobTriggerRequests -Invoke $proStore.Invoke -Arm $armSeams.Arm -Base $armSeams.Base -Installed @($armSeams.List() | Where-Object { $_ -like 'caj-si-*' }) -Log $say
        }
    } catch { & $say 'WARN' ('job trigger requests: not applied in this wake-up ({0})' -f $_.Exception.Message) }
}
# ---- CR8 step 2, OBSERVE ONLY (framework 12.11f item 2): the people's changes verified against their signed Entra tokens
# (signature, issuer, audience, time, person) -- recorded and said; NOTHING is refused. Never stops the run.
if ($proStore) {
    try {
        $sgr = Join-Path $siRoot 'engine/_shared/SI-SignedRequests.ps1'
        if (Test-Path -LiteralPath $sgr) {
            . $sgr
            $sgTenant = @([string]$global:SI_SPN_TenantId, [string]$global:AzureTenantId, [string]$env:SI_TENANT_ID) | Where-Object { $_ } | Select-Object -First 1
            $null = Invoke-SISignedRequestCheck -Invoke $proStore.Invoke -TenantId ([string]$sgTenant) -Audience ([string]$global:SI_Web_SignInClientId) -Log $say
        }
    } catch { & $say 'WARN' ('signed requests: not checked in this wake-up ({0})' -f $_.Exception.Message) }
}

# ---- the definition ----
$pipeDefinition = $null; $source = ''
$sqlFlow = if ($proStore) { New-SIJobFlowSqlStore -Invoke $proStore.Invoke } else { $null }
if ($sqlFlow) {
    try { $row = $sqlFlow.ReadDefinition(); if ($row) { $pipeDefinition = ConvertFrom-SIJobFlowJson -Json $row.Json; if ($row.Mode) { $pipeDefinition.Mode = $row.Mode.ToLowerInvariant() }; $source = 'the Pro database (cfg.JobFlow)' } }
    catch { & $say 'WARN' ('cfg.JobFlow could not be read ({0}) -- apply the Pro database schema again (it only adds)' -f $_.Exception.Message) }
}
$file = Join-Path $siRoot 'config/job-flow.custom.json'
if (-not $pipeDefinition -and (Test-Path -LiteralPath $file)) { $pipeDefinition = ConvertFrom-SIJobFlowJson -Json ([IO.File]::ReadAllText($file)); $source = 'config/job-flow.custom.json' }
if (-not $pipeDefinition) { $pipeDefinition = New-SIDefaultJobFlow -Installed $installed; $source = 'the default pipeline' }
& $say 'INFO' ('{0}: {1} -- {2} stage(s), {3} step(s), runs {4}' -f $pipeDefinition.Name, $source, @(Get-SIPipelineStages -Definition $pipeDefinition).Count, @($pipeDefinition.Steps).Count, (Get-SIJobFlowCadenceText -Definition $pipeDefinition))
$tzCheck = Resolve-SIPipelineTimeZone (Get-SIPipelineTimeZoneId $pipeDefinition)
if ($tzCheck.Fallback) { & $say 'WARN' $tzCheck.Why }
if ($pipeDefinition.PSObject.Properties['Migrated'] -and $pipeDefinition.Migrated) {
    & $say 'INFO' ('the stored pipeline was brought up to date as it was read (saving it on Operations > Jobs, or as config/job-flow.custom.json, stores it so):')
    foreach ($n in @($pipeDefinition.MigrationNotes)) { & $say 'INFO' ('  ' + $n) }
}

# ---- what was asked (a Run now) ----
$pipeRequest = $null
$who = if ($RequestedBy) { $RequestedBy } elseif ($HostKind -eq 'Vm') { [Environment]::UserName } else { '' }
if ($Step) { $pipeRequest = New-SIPipelineRequest -Scope step -Target $Step -Trigger 'manual' -RequestedBy $who }
elseif ($Stage) { $pipeRequest = New-SIPipelineRequest -Scope stage -Target $Stage.ToLowerInvariant() -Trigger 'manual' -RequestedBy $who }
elseif ($FromStep) { $pipeRequest = New-SIPipelineRequest -Scope from-step -Target $FromStep -Trigger 'manual' -RequestedBy $who }
elseif ($Force) { $pipeRequest = New-SIPipelineRequest -Scope pipeline -Trigger $(if ($Trigger -eq 'schedule') { 'manual' } else { $Trigger }) -RequestedBy $who }
# ---- ONE TRUSTED RUN (owner 2026-10-19: "we need the views to use last know good run"): the web app shows ONE published
# run, and it moves only here -- at the end of a run of the whole pipeline that is trusted (every step succeeded, the data
# sync and the verification included; the database checks the run's own data: engine/_shared/data-sql/SI-DataPublishedRun.ps1).
# The seam is the database the web app reads (the data database when it is its own). Never stops the pipeline.
$publishSql = $null
if ([string]$global:SI_ProSqlServer -and [string]$global:SI_ProSqlDatabase) {
    try {
        . (Join-Path $siRoot 'engine/_shared/data-sql/SI-DataPublishedRun.ps1')
        if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/data-model/SI-RecordSql.ps1') }
        $pubSrv = if ([string]$global:SI_Pro_DataSqlServer) { [string]$global:SI_Pro_DataSqlServer } else { [string]$global:SI_ProSqlServer }
        $pubDb = if ([string]$global:SI_Pro_DataSqlDatabase) { [string]$global:SI_Pro_DataSqlDatabase } else { [string]$global:SI_ProSqlDatabase }
        $publishSql = New-SIRecordSqlInvoke -Server $pubSrv -Database $pubDb
    } catch { & $say 'WARN' ('the run the web app shows is not moved by this wake-up ({0}) -- it keeps the last trusted run' -f $_.Exception.Message) }
}
# the update that brings the published run (SUP-2026-00204): an install with complete data and NOTHING published yet is
# published once, here, by the first wake-up after it -- the newest complete collection, its CI and asset copies filled.
# Every later wake-up only reads that a run is published. (The schema apply cannot: it runs as the updater, without EXECUTE.)
if ($publishSql) { $null = Invoke-SIDataPublishRun -Invoke $publishSql -Source update -SolutionVersion $siVersion -Log $say }
# #816 (owner 2026-10-20): a run that failed or was cancelled leaves its Detailed collection 'Loading' with all its rows, and
# the collections' retention runs only at the end of a SUCCESSFUL data sync. So every wake-up while NO pipeline run is running
# removes stopped runs' collections (and the older ones retention would), inside a time budget -- the published run's
# collection and a result waiting for the data sync are never touched. Says only what it removed or what went wrong.
if ($proStore -and [string]$global:SI_ProSqlServer -and [string]$global:SI_ProSqlDatabase) {
    try {
        if (-not (Get-Command -Name Invoke-SIDataStoppedRunCleanup -ErrorAction SilentlyContinue)) {
            . (Join-Path $siRoot 'engine/_shared/data-sql/SI-DataModel.ps1')
            . (Join-Path $siRoot 'engine/_shared/data-sql/SI-DataSql.ps1')
        }
        $cleanSrv = if ([string]$global:SI_Pro_DataSqlServer) { [string]$global:SI_Pro_DataSqlServer } else { [string]$global:SI_ProSqlServer }
        $cleanDb = if ([string]$global:SI_Pro_DataSqlDatabase) { [string]$global:SI_Pro_DataSqlDatabase } else { [string]$global:SI_ProSqlDatabase }
        $cleanSql = New-SIDataSqlInvoke -Server $cleanSrv -Database $cleanDb -AppId $global:SI_SPN_AppId -TenantId $global:SI_SPN_TenantId -CertThumbprint $global:SI_SPN_CertThumbprint
        # the pacing's own line ('pacing: ...', one a minute at most) goes through: the log shows when the clean-up waits
        $cleanLog = { param([string]$level, [string]$msg) if ($level -ne 'INFO' -or $msg -match 'still loading' -or $msg -match '^pacing:') { & $say $(if ($level -eq 'OK') { 'INFO' } else { $level }) $msg } }.GetNewClosure()
        # on its own schedules a job runs without a pipeline run record, so "no run is running" proves nothing: the idle rule is off
        $idleHours = if ($pipeDefinition.Mode -eq 'schedules') { 0 } else { 24 }
        # #882: while a run is going, the 'Loading' collections no live run owns are marked at once -- which run owns which is
        # read from the run records and the Risk Analysis Detailed job's running execution (a container; elsewhere: as before)
        $cleanRa = $null
        if ($seams -and $seams.PSObject.Methods['Running']) { $cleanRa = { $seams.Running('risk-analysis-detailed') } }
        $null = Invoke-SIDataStoppedRunCleanup -Invoke $cleanSql -SettingsInvoke $proStore.Invoke -IdleStaleHours $idleHours -Log $cleanLog -RaRunning $cleanRa
    } catch { & $say 'WARN' ('stopped runs were not removed by this wake-up ({0}) -- the next one tries again' -f $_.Exception.Message) }
}
if ($pipeDefinition.Mode -eq 'schedules' -and -not $pipeRequest -and -not $Cancel) {
    & $say 'INFO' 'this install runs its jobs on their own schedules (Operations > Jobs: Schedules) -- the pipeline does nothing.'
    # no pipeline run judges the data here: the web app moves to the newest complete collection newer than the one it shows
    if ($publishSql) { $null = Invoke-SIDataPublishRun -Invoke $publishSql -Source schedules -SolutionVersion $siVersion -Log $say }
    exit 0
}

# ---- the run record, the lock and the queue ----
$runStore = $null; $control = $null
if ($sqlFlow) { $runStore = $sqlFlow; $control = New-SIPipelineSqlControl -Invoke $proStore.Invoke -LockLog { param($l, $m) & $say $l $m } }
elseif ($HostKind -eq 'Container' -and [string]$global:SI_StorageAccount) {
    if (-not (Get-Command -Name Get-SIBlobContent -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-AzRest.ps1') }
    $runStore = New-SIJobFlowBlobStore -Account ([string]$global:SI_StorageAccount)
    $control = New-SIPipelineDocControl -Docs (New-SIPipelineBlobDocs -Account ([string]$global:SI_StorageAccount)) -Kind 'blob'
} else {
    $runStore = New-SIJobFlowFileStore -Path (Join-Path $siRoot 'data/flow/flow-run.json')
    $control = New-SIPipelineDocControl -Docs (New-SIPipelineFileDocs -Folder (Join-Path $siRoot 'data/flow')) -Kind 'file'
}
$lockHolder = if ($env:CONTAINER_APP_JOB_EXECUTION_NAME) { [string]$env:CONTAINER_APP_JOB_EXECUTION_NAME } else { '{0}:{1}:{2}' -f $env:COMPUTERNAME, $PID, ([guid]::NewGuid().ToString('n').Substring(0, 8)) }

# ---- #700: CANCEL THE RUNNING RUN, and nothing else (the web app's "Cancel this run", or support starting this job once
# with SI_FLOW_CANCEL=1). No people's SQL: the product marks, stops, releases and audits.
# The stops a cancel makes:
# the workers of a step (#882, Get-SIJobFlowWorkerJobs): the workers of a collection in parts (<engine>-worker) and the Risk
# Analysis queue workers (raworker-<grain>). The step's scale-out runs are CLOSED in the state store first (a worker the queue
# scaler starts later then discards their messages and writes nothing for them), then every running execution of the
# worker job that started since the step did is stopped. Called when a step is cancelled, ends without success, or is closed
# Interrupted -- live 2026-10-22: a Detailed step closed Interrupted at 09:40Z kept its worker querying until 10:30.
$stopWorkers = $null
if ($HostKind -eq 'Container') {
        $stopWorkers = {
            param($Job, $SinceUtc, $Execution)
            $errs = New-Object System.Collections.Generic.List[string]
            foreach ($w in @(Get-SIJobFlowWorkerJobs -Job $Job -Installed @($installed))) {
                if ([string]$w.RunsFolder -and [string]$global:SI_StorageAccount) {
                    try {
                        if (-not (Get-Command -Name Close-SICollectRunsOf -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-CollectParts.ps1') }
                        $cr = Close-SICollectRunsOf -Store (New-SICollectBlobStore -Account ([string]$global:SI_StorageAccount)) -Engine ([string]$w.RunsFolder) -ProducerExecution ([string]$Execution) -SinceUtc $SinceUtc `
                                  -Why ('the pipeline ended step {0} -- this run is over; its workers write nothing more for it' -f (Get-SIJobFlowKey $Job))
                        if (@($cr.Closed).Count) { & $say 'WARN' ('{0}: {1} queue run(s) closed for its workers ({2})' -f (Get-SIJobFlowKey $Job), @($cr.Closed).Count, (@($cr.Closed) -join ', ')) }
                        if ([string]$cr.Why) { $errs.Add(('{0}: its queue runs could not be closed ({1})' -f $w.RunsFolder, $cr.Why)) }
                    } catch { $errs.Add(('{0}: its queue runs could not be closed ({1})' -f $w.RunsFolder, $_.Exception.Message)) }
                }
                $wk = [string]$w.Job
                if (-not $wk) { continue }
                $r = $null
                try { $r = & $armSeams.Arm 'GET' ('{0}/{1}/executions' -f $armSeams.Base, $wk) $null } catch { if ("$($_.Exception.Message)" -match '404|ResourceNotFound|not found') { continue } else { $errs.Add(('{0}: {1}' -f $wk, $_.Exception.Message)); continue } }
                foreach ($e in @($r.value | Where-Object { $_ -and $_.properties -and [string]$_.properties.status -in @('Running', 'Processing') })) {
                    if ($SinceUtc -and $e.properties.startTime -and ([datetime]$e.properties.startTime).ToUniversalTime() -lt ([datetime]$SinceUtc).ToUniversalTime().AddMinutes(-5)) { continue }
                    try { $null = & $armSeams.Arm 'POST' ('{0}/{1}/stop/{2}' -f $armSeams.Base, $wk, [string]$e.name) @{}; & $say 'WARN' ('{0}: its worker {1} was stopped' -f (Get-SIJobFlowKey $Job), [string]$e.name) }
                    catch {
                        # it ended between the list and the stop (400 "job execution ... not found"): already stopped, not a failure
                        if (Test-SIJobFlowStopAlreadyEnded -Message ([string]$_.Exception.Message)) { & $say 'INFO' ('{0}: its worker {1} had already ended' -f (Get-SIJobFlowKey $Job), [string]$e.name) }
                        else { $errs.Add(('{0} {1}: {2}' -f $wk, [string]$e.name, $_.Exception.Message)) }
                    }
                }
            }
            if ($errs.Count) { throw ($errs -join '; ') }
        }
}
# the runner that holds the lock for the run: another execution of this job (container), or a runner process on this
# machine (VM: holder <computer>:<pid>:<tag>) -- never this execution / process itself
$stopRunner = if ($HostKind -eq 'Container') {
    { param($Holder) if ([string]$Holder -match '^caj-si-flow-[a-z0-9\-]+$') { $null = & $armSeams.Arm 'POST' ('{0}/{1}/stop/{2}' -f $armSeams.Base, (Get-SIJobFlowJobName 'flow'), [string]$Holder) @{} } else { throw ("'{0}' is not an execution of the pipeline job" -f $Holder) } }
} else {
    { param($Holder) $hp = ([string]$Holder) -split ':'; if ($hp.Count -ge 2 -and $hp[0] -eq $env:COMPUTERNAME -and [int]$hp[1] -ne $PID) { Stop-Process -Id ([int]$hp[1]) -Force -ErrorAction SilentlyContinue } }
}
# one audit record per cancel: who, why ($cancelAuditBy / $cancelAuditWhy, set by the caller), what was stopped, whether the
# lock was released. No GetNewClosure: a closure cannot see the functions this script dot-sourced.
$cancelAuditBy = ''; $cancelAuditWhy = ''
$cancelAudit = $null
if ($proStore -and (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue)) {
    $cancelAudit = {
        param($Res)
        $null = Write-SIAuditEvent -Store $proStore -Action 'job.flowrun.stop' -Actor (Get-SIAuditActor -Job 'pipeline runner') -ActorSource 'job' -Target ('flow/{0}' -f $Res.FlowRunId) `
            -Reason ('cancelled by {0}: {1}' -f $cancelAuditBy, $cancelAuditWhy) -Outcome $(if (@($Res.StopFailed).Count) { 'error' } else { 'ok' }) -OutcomeText $Res.Text -CorrelationId $Res.FlowRunId -JobRun $Res.FlowRunId `
            -After ([ordered]@{ cancelledBy = $cancelAuditBy; reason = $cancelAuditWhy; version = $Res.Version; stopped = @($Res.Stopped | ForEach-Object { '{0} {1}' -f $_.Job, $_.Execution }); notStopped = @($Res.StopFailed); lockReleased = $Res.LockReleased })
    }
}
$cancelArgsFor = {
    param($CBy, $CWhy)
    @{ Store = $runStore; Control = $control; Stop = { param($j, $e) $seams.Stop($j, $e) }; StopWorkers = $stopWorkers; StopRunner = $stopRunner; Self = $lockHolder
       By = $CBy; Reason = $CWhy; Audit = $cancelAudit; Log = $say }
}
if ($Cancel) {
    if (-not "$CancelReason".Trim()) {
        & $say 'ERROR' 'cancelling the running pipeline run needs a reason (SI_FLOW_CANCEL_REASON, or -CancelReason) -- nothing was cancelled'
        exit 1
    }
    $cancelBy = if ($who) { $who } else { 'support' }
    $cancelAuditBy = $cancelBy; $cancelAuditWhy = $CancelReason.Trim()
    try {
        $cancelArgs = & $cancelArgsFor $cancelBy $CancelReason.Trim()
        $cancelArgs.RunnerHolder = "$env:SI_FLOW_CANCEL_RUNNER".Trim(); $cancelArgs.FlowRunId = [string]$CancelRun
        $cx = Invoke-SIPipelineCancelRun @cancelArgs
    } catch { & $say 'ERROR' ('the pipeline run could not be cancelled: {0}' -f $_.Exception.Message); exit 1 }
    & $say $(if ($cx.Outcome -eq 'Cancelled' -and -not @($cx.StopFailed).Count) { 'INFO' } else { 'WARN' }) $cx.Text
    exit $(if (@($cx.StopFailed).Count) { 1 } else { 0 })
}

# ---- run health (every edition): one row per step and one per run ----
$rh = Join-Path $siRoot 'engine/asset-profiling/shared/Send-SIRunHealthRow.ps1'
if (-not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $rh)) { try { . $rh } catch { & $say 'WARN' ('run health is not recorded: {0}' -f $_.Exception.Message) } }
$onStep = {
    param($State, $StepRec, $Phase)
    if (-not (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue)) { return }
    $ctx = [pscustomobject]@{ RunId = $State.FlowRunId; Engine = ('flow:{0}' -f $StepRec.Job); ShardIndex = [int]$StepRec.Order; ShardCount = @($State.Steps).Count
                              CollectionTime = $State.StartedUtc; StartedAt = $(if ($StepRec.StartedUtc) { $StepRec.StartedUtc } else { [datetime]::UtcNow }) }
    $msg = 'execution={0}; class={1}; {2}' -f $StepRec.Execution, $StepRec.ErrorClass, $StepRec.Error
    if ([int]$StepRec.Attempts -gt 1) { $msg = '{0}; attempts={1}; {2}' -f $msg, $StepRec.Attempts, $StepRec.RetryReason }
    if ($Phase -eq 'Start') { Send-SIRunHealthRow -RunContext $ctx -Phase Start -NoTelemetry }
    # self-healing: the step's job was stopped at its run limit, the limit was raised and the step is started again -- one
    # row per action, not an END (the step's own END row follows when it has ended)
    # no sign of progress for 2 hours: a WARNING, once per step per run -- the step keeps running, nothing is stopped
    elseif ($Phase -eq 'Silent') { Send-SIRunHealthRow -RunContext $ctx -Phase Guard -ExitReason 'warning' -ErrorMessage ('execution={0}; {1}' -f $StepRec.Execution, (@(([string]$StepRec.RetryReason) -split ' \| ' | Where-Object { $_ -match 'no sign of progress' })[-1])) -NoTelemetry }
    elseif ($Phase -eq 'Heal') { Send-SIRunHealthRow -RunContext $ctx -Phase Guard -ExitReason 'self-healed' -ErrorMessage ('execution={0}; {1}' -f $StepRec.Execution, $StepRec.Error) -NoTelemetry }
    else { Send-SIRunHealthRow -RunContext $ctx -Phase End -ExitReason (Get-SIJobFlowStepExitReason $StepRec) -ErrorMessage $msg -NoTelemetry }
}

# ---- working rule 4: a step whose container never ran the engine (an Azure platform failure) is started again ----
$retry = @{}
if ($HostKind -eq 'Container') {
    $retry.StartEvidence = New-SIJobFlowStartEvidence -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId) -StorageAccount ([string]$global:SI_StorageAccount)
    $nn = 0
    $cfgRetries = if ($env:SI_FLOW_START_RETRIES) { $env:SI_FLOW_START_RETRIES } else { [string]$global:SI_Flow_StartRetries }
    if ($cfgRetries -and [int]::TryParse($cfgRetries, [ref]$nn) -and $nn -ge 0 -and $nn -le 3) { $retry.StartRetries = $nn }
    $cfgBackoff = if ($env:SI_FLOW_START_RETRY_BACKOFF) { $env:SI_FLOW_START_RETRY_BACKOFF } else { [string]$global:SI_Flow_StartRetryBackoffSeconds }
    if ($cfgBackoff -and [int]::TryParse($cfgBackoff, [ref]$nn) -and $nn -ge 0 -and $nn -le 900) { $retry.StartRetryBackoffSeconds = $nn }
    # ---- a running step that shows no sign of progress for 2 hours is REPORTED once (log + run health), never stopped: the
    # probe reads when its job last wrote a console log line or a run-health record (Log Analytics, as the job's identity)
    $retry.Progress = New-SIJobFlowProgressProbe -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId) -PartsJobs @($producers)
    # ---- self-healing: a step whose job was stopped at its own run limit gets the limit raised by the update's sizing rule
    # (setup\_shared\SI-JobSizing.ps1 -- the same code the update runs) and is started again once in the same run. The
    # pipeline changes the job as its own identity (Container Apps Jobs Contributor on the jobs' resource group, the right
    # it already has to start them); a run limit the customer set (SI_Bootstrap_ReplicaTimeout_<Engine>) is kept.
    try {
        $sizingLib = Join-Path $siRoot 'setup/_shared/SI-JobSizing.ps1'
        if (Test-Path -LiteralPath $sizingLib) {
            . $sizingLib
            $healRest = New-SIUpdateRestSeam
            $healGlobals = @{}
            foreach ($gvar in @(Get-Variable -Scope Global -ErrorAction Ignore | Where-Object { $_.Name -match '^SI_Bootstrap_ReplicaTimeout_' })) { if ($null -ne $gvar.Value) { $healGlobals[$gvar.Name] = $gvar.Value } }
            $retry.RaiseLimit = { param($Hit) Invoke-SIJobRunLimitHeal -Rest $healRest -SubscriptionId $sub -ResourceGroup $rg -JobName ([string]$Hit.JobName) -HitLimitSeconds ([int]$Hit.LimitSeconds) -Globals $healGlobals }
        }
    } catch { & $say 'WARN' ('a step stopped at its run limit is not started again in this run: the job sizing could not be loaded ({0})' -f $_.Exception.Message) }
}
# #882: a step the pipeline ends without success, cancels or closes Interrupted leaves no worker running for it
if ($stopWorkers) { $retry.StopWorkers = $stopWorkers }

# ---- the run goes on without one source: the state of each source lives in the install's database (sidata.SourceState).
# A failed collection is recorded as "on its last good collection" and nothing it wrote counts as a complete collection;
# without a database the run still goes on, and its sentence names the source without the date (or the date of the run before).
if ([string]$global:SI_ProSqlServer -and [string]$global:SI_ProSqlDatabase) {
    try {
        . (Join-Path $siRoot 'engine/_shared/SI-SourceState.ps1')
        if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/data-model/SI-RecordSql.ps1') }
        $sourceSql = New-SIRecordSqlInvoke
        if ($sourceSql) {
            $retry.SourceState = New-SISourceStateStore -Invoke $sourceSql
            # a source without a good collection for SI_Pro_SourceDropout_HoldDeliveryDays days (default 7) or more: delivery
            # waits until it collects again -- the calculation goes on (asked once per run, when Deliver would start)
            $sourceStore = $retry.SourceState
            $retry.DeliverHold = { Get-SISourceDeliveryHold -Sources @($sourceStore.Read()) -NowUtc ([datetime]::UtcNow) -HoldDays (Get-SISourceHoldDays) }
        }
        # one failed step does not cost the rest of the run: when the data sync ran all the same, the run's sentence says
        # "first collection, not complete yet" on an install whose database holds no complete collection yet (there is no
        # last good run to fall back on) -- asked once, at the end of such a run only
        $firstSrv = if ([string]$global:SI_Pro_DataSqlServer) { [string]$global:SI_Pro_DataSqlServer } else { [string]$global:SI_ProSqlServer }
        $firstDb = if ([string]$global:SI_Pro_DataSqlDatabase) { [string]$global:SI_Pro_DataSqlDatabase } else { [string]$global:SI_ProSqlDatabase }
        $firstSql = New-SIRecordSqlInvoke -Server $firstSrv -Database $firstDb
        if ($firstSql) { $retry.FirstRun = { Test-SIPipelineFirstRun -Invoke $firstSql } }
    } catch { & $say 'WARN' ('the state of the sources is not recorded in this run ({0}) -- a failed collection still does not stop the run' -f $_.Exception.Message) }
}

# ---- the failed step's own run log (its class + first error lines go into the run's report) ----
$stepLogs = if ($HostKind -eq 'Container') { New-SIJobFlowStepLogReader -StorageAccount ([string]$global:SI_StorageAccount) }
            else { New-SIJobFlowStepLogReader -LogRoot $(if ($global:SI_LauncherLogRoot) { [string]$global:SI_LauncherLogRoot } else { Join-Path $siRoot 'logs' }) }

# ---- one run: the runner + what every run reports (guards, run health, telemetry, audit) ----
# NOTE: the names below are prefixed -- this block runs inside Invoke-SIPipelineDrain, whose own variables it would see first.
# ---- CR3 (#657): release mode -- after a release that changed engine code, a status report every 30 minutes for 12 hours.
# Asked at every wake-up and from the lock heartbeat of a long run (at most once every 4 minutes per process; the half hour
# is claimed in the Pro database, so it goes out once). Never stops or slows the pipeline: anything wrong = no report.
$releaseTick = { if ($proStore -and (Get-Command -Name Invoke-SIReleaseModeReportTick -ErrorAction SilentlyContinue)) { try { $null = Invoke-SIReleaseModeReportTick -Invoke $proStore.Invoke } catch { } } }
& $releaseTick

$pipeRunOne = {
    param($PipeReq, $PipePrev, $PipeRunId)
    # #700: the version this runner runs (kept on a new run), and "was this run cancelled meanwhile?" at every poll
    $pArgs = @{ Definition = $pipeDefinition; Seams = $seams; Store = $runStore; OnStep = $onStep; Log = $say; PollSeconds = $PollSeconds; Previous = $PipePrev; Version = $siVersion
                Cancelled = $(if ($runStore.PSObject.Methods['Cancelled']) { { param($id) $runStore.Cancelled($id) } } else { $null })
                # si-flow-1203: the newest runs read once the run goes on -- a run / step much longer than usual is said, never stopped
                History = $(if ($runStore.PSObject.Methods['Recent']) { { $runStore.Recent() } } else { $null })
                Heartbeat = { param($s) $null = $control.HeartbeatLock($lockHolder, [string]$s.FlowRunId, (Get-SIPipelineStatusText -State $s -Definition $pipeDefinition)); & $releaseTick } }
    foreach ($k in $retry.Keys) { $pArgs[$k] = $retry[$k] }
    if ($PipeReq) {
        $pArgs.FlowRunId = $PipeRunId; $pArgs.Trigger = [string]$PipeReq.Trigger; $pArgs.RequestedBy = [string]$PipeReq.RequestedBy; $pArgs.RequestId = [long]$PipeReq.Id; $pArgs.Note = [string]$PipeReq.Note
        switch ([string]$PipeReq.Scope) {
            'stage' { $pArgs.Scope = 'stage'; $pArgs.Target = [string]$PipeReq.Target }
            'step' { $pArgs.Scope = 'step'; $pArgs.Target = [string]$PipeReq.Target }
            'from-step' { $pArgs.FromStep = [string]$PipeReq.Target }
            default { $pArgs.Force = $true; if ($PipeReq.SlotUtc) { $pArgs.SlotUtc = $PipeReq.SlotUtc } }
        }
    }
    $pipeStart = [datetime]::UtcNow
    $pipeCtx = [pscustomobject]@{ RunId = ''; Engine = 'flow'; ShardIndex = 0; ShardCount = 1; CollectionTime = $pipeStart; StartedAt = $pipeStart; FailedStep = '' }
    $pipeResult = Invoke-SIJobFlow @pArgs
    if (-not $pipeResult -or $pipeResult.Outcome -in @('Busy', 'Wait', 'Done')) { return $pipeResult }
    # ONE TRUSTED RUN: the run has ended -- the web app moves to it only when it is trusted; otherwise it keeps the last
    # trusted run, and the reason is kept for the banner and Operations (the 'refused' row)
    # 2026-10-24: the run's publish copy can take 15-50 minutes -- its progress keeps THIS runner's lock alive (same holder,
    # the expiry moves), so the next wake-up never starts a run beside it; a copy that dies stops beating and the lock
    # lapses after its 15 minutes, as before
    $pipeBeat = { $null = $control.HeartbeatLock($lockHolder, [string]$pipeResult.FlowRunId, ('publishing run {0}' -f $pipeResult.FlowRunId)) }.GetNewClosure()
    if ($publishSql) { $null = Invoke-SIDataPublishRun -Invoke $publishSql -State $pipeResult -Map (Get-SIJobFlowMap) -Previous $PipePrev -SolutionVersion $siVersion -Log $say -Beat $pipeBeat }
    # #277: the run's guards (a missed scheduled start, skipped / interrupted steps) mail and report themselves. A start that
    # was late ONLY because the previous run was still going is not one of them: the run's note says it, no guard event
    if (Get-Command -Name Invoke-SIGuardCalls -ErrorAction SilentlyContinue) { $null = Invoke-SIGuardCalls -Calls @(Get-SIGuardCallsForFlow -Result $pipeResult) -Common @{ Engine = 'flow'; RunId = [string]$pipeResult.FlowRunId; Invoke = $(if ($proStore) { $proStore.Invoke } else { $null }) } }
    $pipeSummary = Get-SIJobFlowSummary -State $pipeResult
    $pipeText = Get-SIPipelineStatusText -State $pipeResult -Definition $pipeDefinition
    $pipeBad = @($pipeResult.Steps | Where-Object { $_.State -in @('Failed', 'TimedOut', 'Interrupted') } | Select-Object -First 1)
    # THE WARNING THAT OPENS A FIX REQUEST (owner 2026-10-13): a run that went on after a failed step names THAT step in
    # its report (not a source it went on without) -- Outcome warning + FailedStep + the step's own class, which Invardia
    # treats as a fix request. No new channel: the run's own run-health record and its report, as every run.
    $pipeWentAfter = @(Get-SIPipelineWentOnAfter -State $pipeResult -Definition $pipeDefinition | Select-Object -First 1)
    if ($pipeWentAfter.Count) { $pipeBad = $pipeWentAfter }
    $pipeCtx.RunId = $pipeResult.FlowRunId; $pipeCtx.StartedAt = $pipeResult.StartedUtc; $pipeCtx.CollectionTime = $pipeResult.StartedUtc
    $pipeStepLine = ''
    if ($pipeBad.Count) {
        $pipeCtx.FailedStep = Get-SIJobFlowKey ([string]$pipeBad[0].Job)
        # telemetry quality (owner 2026-10-10): the report names the failed step and carries THAT step's class + its first
        # error lines (its own run log), not the pipeline's summary line. Never fails the run.
        try {
            $pipeLog = $null
            try { $pipeLog = $stepLogs.Read([string]$pipeBad[0].Job, $pipeBad[0].StartedUtc, $pipeBad[0].EndedUtc) } catch { $pipeLog = $null }
            $pipeFail = Get-SIJobFlowStepFailure -Step $pipeBad[0] -LogLines $(if ($pipeLog) { @($pipeLog.Lines) } else { $null })
            $pipeCtx | Add-Member -NotePropertyName FailedStepError -NotePropertyValue ([string]$pipeFail.Text) -Force
            $pipeCtx | Add-Member -NotePropertyName FailedStepErrorClass -NotePropertyValue ([string]$pipeFail.ErrorClass) -Force
            $pipeStepLine = 'step {0} failed ({1}): {2}; ' -f $pipeFail.Step, $pipeFail.ErrorClass, (($pipeFail.Text -split "`n")[0])
            # #850: the step's own cause (an out-of-memory, a timeout ...) goes on the STEP's run record too, so run health and
            # Operations > Jobs say why -- not only "the execution ended failed". Never fails the run.
            if ($pipeLog -and [string]$pipeBad[0].Error -match '^the execution ended ') {
                $pipeCause = Get-SIJobFlowStepCauseText -Recorded ([string]$pipeBad[0].Error) -Cause ([string]$pipeFail.Text)
                if ($pipeCause -ne [string]$pipeBad[0].Error) {
                    $pipeBad[0].Error = $pipeCause
                    try { $runStore.Save($pipeResult) } catch { & $say 'WARN' ('the failed step''s cause could not be put on its run record ({0})' -f $_.Exception.Message) }
                }
            }
            & $say 'WARN' ('{0}{1}' -f $pipeStepLine, $(if ($pipeLog) { '(from its run log ' + $pipeLog.Name + ')' } else { '' }))
        } catch { & $say 'WARN' ('the failed step''s own error could not be read ({0})' -f $_.Exception.Message) }
    }
    # a run held back by a failed collection or correlation says so in plain words (the log and the run's record)
    $pipeHeld = Get-SIPipelineHeldBackText -State $pipeResult
    if ($pipeHeld) { & $say 'WARN' $pipeHeld }
    # one failed step did not cost the rest of the run: the runner said which step failed, what ran all the same and what
    # was held, and kept it first in the run's note. Here: who must act (from the failed step's own class), and the same
    # words in the run's own run-health record -- a WARNING, never a success and never silent.
    $pipePartial = ''
    if (Test-SIPipelinePartialRun -State $pipeResult) {
        $pipePartial = Get-SIPipelinePartialText -State $pipeResult -Definition $pipeDefinition -Short -FirstRun:([string]$pipeResult.Note -like 'first collection, not complete yet:*')
        $pipeWho = Get-SIPipelineWhoActsText -ErrorClass $(if ($pipeCtx.PSObject.Properties['FailedStepErrorClass']) { [string]$pipeCtx.FailedStepErrorClass } else { '' })
        & $say 'WARN' $pipeWho
        $pipePartial = '{0}{1} {2}' -f $(if ((Get-SIJobFlowRunExitReason -State $pipeResult) -eq 'success-partial') { 'warning, to be fixed: ' } else { '' }), $pipePartial, $pipeWho
    }
    # a run that went on without a source says which one and from when its data is (the runner logged it and kept it in
    # the run's note; here it goes into the run's own run-health record)
    $pipeWentOn = Get-SIPipelineWentOnText -State $pipeResult -Definition $pipeDefinition
    # every run that rests on an older collection of a source says how old it is; and why delivery waited, when it did
    $pipeAges = @()
    if ($retry.SourceState -and [string]$pipeResult.Scope -ne 'step') {
        try { $pipeAges = @(Get-SISourceAgeText -Sources @($retry.SourceState.Read()) -NowUtc ([datetime]::UtcNow)) } catch { $pipeAges = @() }
        foreach ($pipeAge in $pipeAges) { & $say 'WARN' $pipeAge }
    }
    $pipeWaited = @($pipeResult.Steps | Where-Object { [string]$_.ErrorClass -eq 'source-too-old' } | Select-Object -First 1)
    $pipeSources = (@(@($pipeWentOn) + @($pipeAges) + @($pipeWaited | ForEach-Object { [string]$_.Error })) | Where-Object { $_ }) -join '; '
    # the measured cadence (a full run takes longer than the schedule's interval) is kept in the run's record too
    $pipeCadence = if ([string]$pipeResult.Note -match '(At this size a full run takes about \d+ hours, so data is refreshed about every \d+ hours\.)') { $Matches[1] } else { '' }
    # steps that showed no sign of progress for 2 hours and were left running: named once in the run's own record -- a
    # warning, never a failure (the run's outcome is not changed by it)
    $pipeSilent = @($pipeResult.Steps | Where-Object { [string]$_.RetryReason -match 'no sign of progress' } | ForEach-Object { [string]$_.Job })
    if ($pipeSilent.Count) { $pipeCadence = (@($pipeCadence, ('warning: {0} showed no sign of progress for 2 hours or more while running and was left running' -f ($pipeSilent -join ', '))) | Where-Object { $_ }) -join '; ' }
    if (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue) {
        # #532: a run whose only failures were throttled steps is 'throttled' -- Outcome warning, no fix request
        Send-SIRunHealthRow -RunContext $pipeCtx -Phase End -AssetCount @($pipeResult.Steps).Count -ExitReason (Get-SIJobFlowRunExitReason -State $pipeResult) `
            -ErrorMessage ('{0}{1}; {2}{3}{4}{5}{6}{7}' -f $pipeStepLine, $pipeText, $pipeSummary, $(if ($pipeResult.StopReason) { '; ' + $pipeResult.StopReason } else { '' }), $(if ($pipeHeld) { '; ' + $pipeHeld } else { '' }), $(if ($pipeSources) { '; ' + $pipeSources } else { '' }), $(if ($pipeCadence) { '; ' + $pipeCadence } else { '' }), $(if ($pipePartial) { '; ' + $pipePartial } else { '' }))
    }
    if ($proStore -and (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue)) {
        # #302 (AUDIT-1.1) + #306: the run names what was run (pipeline / stage / step) and who asked for it; a scheduled
        # run keeps the job as the actor and names who last set the pipeline.
        $pipeAfter = [ordered]@{ pipeline = [string]$pipeDefinition.Name; scope = [string]$pipeResult.Scope; target = [string]$pipeResult.Target; requestedBy = [string]$pipeResult.RequestedBy
                                 trigger = $pipeResult.Trigger; fromStep = $pipeResult.FromStep; state = $pipeResult.State
                                 steps = @($pipeResult.Steps | ForEach-Object { [ordered]@{ stage = $_.Stage; job = $_.Job; state = $_.State; execution = $_.Execution } }) }
        if (-not $pipeResult.RequestedBy -and -not (Get-SIJobAttribution -Invoke $proStore.Invoke)) {
            $setBy = Get-SIChangeAttribution -Invoke $proStore.Invoke -TargetKey 'jobflow/daily' -Kind 'flow' -Days 3650 -Log { param($l, $m) & $say 'WARN' $m }
            if ($setBy) { $pipeAfter['flowSetBy'] = $setBy.Actor }
        }
        $null = Write-SIAuditEvent -Store $proStore -Action 'job.flow.run' -Actor (Get-SIAuditActor -Job 'pipeline runner') -ActorSource 'job' -Target ('flow/{0}' -f $pipeResult.FlowRunId) `
            -Reason $(if ($pipeResult.RequestedBy) { 'run now by ' + $pipeResult.RequestedBy } else { '' }) `
            -Outcome $(if ($pipeResult.State -eq 'Succeeded') { 'ok' } elseif ($pipeResult.State -eq 'Cancelled' -or (Test-SIJobFlowThrottledOnly -State $pipeResult)) { 'held' } else { 'error' }) -OutcomeText ('{0}: {1}' -f $pipeText, $pipeSummary) -CorrelationId $pipeResult.FlowRunId -JobRun $pipeResult.FlowRunId `
            -After $pipeAfter
    }
    $pipeResult
}

# ---- never under an update (framework UPDATE-1.6: the updater runs on its own daily schedule, never in the pipeline) ----
# The updater never installs while a pipeline run is going (owner 2026-10-23, its run gate; replaces the 2026-10-12 rule
# that it installed at once); the pipeline does not start while an update runs -- it ends this wake-up (what waits stays
# queued; a due slot stays due) and the next wake-up tries again.
$updateRunning = if ($HostKind -eq 'Container') {
    # CR5 step 1 (#655): the updater job's name from the install record (cfg.InstallState 'InstallNames'), else today's name
    . (Join-Path $siRoot 'engine/_shared/SI-InstallNames.ps1')
    $updaterJobName = Get-SIInstallName -Role updater -Record (Read-SIInstallNamesRecord -Store $proStore)
    {
        # $armSeams, never $seams: with a producer job $seams is the collect-in-parts wrapper, whose Arm is $null -- the check
        # then failed on every wake-up ("The expression after '&' ...") and the pipeline could start under an update
        try { $r = & $armSeams.Arm 'GET' ('{0}/{1}/executions' -f $armSeams.Base, $updaterJobName) $null }
        catch { if ("$($_.Exception.Message)" -match '404|ResourceNotFound|not found') { return '' } else { throw } }
        Get-SIPipelineUpdateRunning -Executions @($r.value)
    }
} else {
    { Get-SIPipelineUpdateRunning -Processes @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction Stop | ForEach-Object { [string]$_.CommandLine }) }
}

# ---- 2026-10-23: AN UPDATE WAITS FOR THE PIPELINE (a container): the updater found a run going and left its wait mark on
# its own job (tag si-update-waits). The runner then starts no NEW run: it starts the updater (once per mark, with
# SI_UPDATER_MODE = pending-update -- the same start body as the heartbeat's "update now") and what waits in the queue
# starts after it, on the new build. Reading the mark fails = nothing is held back. This identity starts the pipeline's
# jobs already ("Container Apps Jobs Contributor" on the jobs' resource group, Bootstrap-ContainerAppJob.ps1) -- no new right.
$updateWaits = $null; $startUpdate = $null
if ($HostKind -eq 'Container' -and $updaterJobName) {
    if (-not (Get-Command -Name New-SIUpdateNowStartTemplate -ErrorAction SilentlyContinue)) { . (Join-Path $siRoot 'engine/_shared/SI-UpdaterStart.ps1') }
    $updateWaits = {
        $j = $null
        try { $j = & $armSeams.Arm 'GET' ('{0}/{1}' -f $armSeams.Base, $updaterJobName) $null }
        catch { if ("$($_.Exception.Message)" -match '404|ResourceNotFound|not found') { return $null } else { throw } }
        if (-not $j -or -not $j.tags -or -not $j.tags.PSObject.Properties['si-update-waits']) { return $null }
        ConvertFrom-SIPipelineUpdateWaitsTag -Value ([string]$j.tags.'si-update-waits')
    }
    $startUpdate = {
        param($W)
        $ex = & $armSeams.Arm 'GET' ('{0}/{1}/executions' -f $armSeams.Base, $updaterJobName) $null
        $may = Get-SIPipelineUpdateStart -Waits $W -Executions @($ex.value)
        if ($may.Running) { return [pscustomobject]@{ Started = $true; Text = $may.Text } }
        if (-not $may.Start) { return [pscustomobject]@{ Started = $false; Text = $may.Text } }
        $job = & $armSeams.Arm 'GET' ('{0}/{1}' -f $armSeams.Base, $updaterJobName) $null
        $r = & $armSeams.Arm 'POST' ('{0}/{1}/start' -f $armSeams.Base, $updaterJobName) (New-SIUpdateNowStartTemplate -Job $job -Mode 'pending-update')
        [pscustomobject]@{ Started = $true; Text = ('{0} execution {1}' -f $updaterJobName, $(if ($r -and $r.PSObject.Properties['name']) { [string]$r.name } else { '(started)' })) }
    }
}

# ---- never a NEW run on replaced code (a container): the image this execution started with, read once, against the
# flow job's image now -- an update rolls a new image into the job; a runner that started before it finishes what it runs
# and leaves the queue to the next wake-up (a new execution, on the new image). Unreadable = current (never stops a run).
$codeCurrent = $null
if ($HostKind -eq 'Container' -and "$env:CONTAINER_APP_JOB_NAME".Trim()) {
    $flowJobName = "$env:CONTAINER_APP_JOB_NAME".Trim()
    $readFlowImage = {
        try { $j = & $armSeams.Arm 'GET' ('{0}/{1}' -f $armSeams.Base, $flowJobName) $null; [string](@($j.properties.template.containers)[0].image) } catch { '' }
    }
    $flowStartImage = & $readFlowImage
    if ($flowStartImage) { $codeCurrent = { Test-SIPipelineCodeCurrent -StartImage $flowStartImage -NowImage (& $readFlowImage) } }
}

# ---- a CANCELLED run is final (live 2026-10-19, ring 2): what a runner that never saw the cancel left running, or started
# again, is stopped by the runner that holds the lock now; a run written back to Running is ended Cancelled again
$closeCancelled = {
    param($CRun)
    Close-SIJobFlowCancelledRun -State $CRun -Stop $(if ($seams.PSObject.Methods['Stop']) { { param($j, $e) $seams.Stop($j, $e) } } else { $null }) `
        -Running $(if ($seams.PSObject.Methods['Running']) { { param($j) $seams.Running($j) } } else { $null }) -Save { param($s) $runStore.Save($s) } -NowUtc ([datetime]::UtcNow) -Log $say `
        -StopWorkers $stopWorkers
}

# ---- a step of a run that has ENDED is never left open (live 2026-10-21, ring 2: two step rows of runs cancelled two days
# earlier still said Running) -- every wake-up closes them with the reason, in one statement. Only ended runs' rows: never
# the run that is going on, never the lock. A failing close is said and never stops the wake-up.
if ($runStore -and $runStore.PSObject.Methods['CloseEndedRunSteps']) {
    # #882: what may still run for a started step row of an ended run is stopped FIRST -- its recorded execution and its
    # workers (their queue runs closed) -- never what the run going on now follows or runs (Get-SIJobFlowEndedStepStops).
    # A step closed here leaves nothing behind that writes for a run that is over. A failing stop is said, never fatal.
    if ($runStore.PSObject.Methods['EndedRunOpenSteps']) {
        try {
            $endedOpen = @($runStore.EndedRunOpenSteps())
            if ($endedOpen.Count) {
                $liveRun = $null
                try { $lr0 = $runStore.Load(); if ($lr0 -and [string]$lr0.State -notin $script:SIPipeline.RunFinished) { $liveRun = $lr0 } } catch { $liveRun = $null }
                foreach ($es in @(Get-SIJobFlowEndedStepStops -Rows $endedOpen -Live $liveRun)) {
                    if ([string]$es.Execution -and $seams.PSObject.Methods['Stop']) {
                        try { $seams.Stop([string]$es.Job, [string]$es.Execution); & $say 'WARN' ('{0}: execution {1} of a run that has ended was asked to stop' -f $es.Job, $es.Execution) }
                        catch { & $say 'WARN' ('{0}: execution {1} of a run that has ended could not be stopped ({2})' -f $es.Job, $es.Execution, $_.Exception.Message) }
                    }
                    if ($es.Workers -and $stopWorkers) {
                        try { $null = & $stopWorkers ([string]$es.Job) $es.SinceUtc ([string]$es.Execution) } catch { & $say 'WARN' ('{0}: the workers of a run that has ended could not be stopped ({1})' -f $es.Job, $_.Exception.Message) }
                    }
                    if ([string]$es.Why) { & $say 'INFO' ('{0}: {1}' -f $es.Job, $es.Why) }
                }
            }
        } catch { & $say 'WARN' ('what still runs for the open step rows of ended runs could not be read this time: {0}' -f $_.Exception.Message) }
    }
    try {
        $closedSteps = [int]$runStore.CloseEndedRunSteps()
        if ($closedSteps -gt 0) { & $say 'INFO' ('{0} step row(s) of runs that had already ended were still open -- closed (the run ended before they finished)' -f $closedSteps) }
    } catch { & $say 'WARN' ('the open step rows of ended runs could not be closed this time: {0}' -f $_.Exception.Message) }
}

$drain = $null
try {
    $drain = Invoke-SIPipelineDrain -Definition $pipeDefinition -Control $control -LoadLast { $runStore.Load() } -RunOne $pipeRunOne -Request $pipeRequest -Holder $lockHolder -Log $say -UpdateRunning $updateRunning -CodeCurrent $codeCurrent -CloseCancelled $closeCancelled -UpdateWaits $updateWaits -StartUpdate $startUpdate
} catch {
    # #913: the pipeline lock could not be reached because Azure SQL answered a transient error for about a minute (the lock
    # calls retried it -- Invoke-SIPipelineLockCall). Nothing was started under it, so no run was affected: one WARN, a
    # run-health row of class transient-sql (Outcome warning, no FixKind -- never a product defect, never a red alert), exit 0.
    # The next wake-up (5 minutes) runs as usual and starts what waits.
    $lockClass = if (Get-Command -Name Get-SIPipelineErrorClassTag -ErrorAction SilentlyContinue) { Get-SIPipelineErrorClassTag -ErrorRecord $_ } else { '' }
    if ($lockClass -eq 'transient-sql') {
        & $say 'WARN' ('this wake-up started nothing: {0}' -f $_.Exception.Message)
        if (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue) {
            $tsCtx = [pscustomobject]@{ RunId = [guid]::NewGuid().ToString(); Engine = 'flow'; ShardIndex = 0; ShardCount = 1; CollectionTime = [datetime]::UtcNow; StartedAt = [datetime]::UtcNow
                                         FailedStep = 'lock'; FailedStepError = [string]$_.Exception.Message; FailedStepErrorClass = 'transient-sql' }
            try { Send-SIRunHealthRow -RunContext $tsCtx -Phase End -ExitReason 'success-partial' -ErrorMessage $_.Exception.Message } catch { }
        }
        exit 0
    }
    & $say 'ERROR' ('the pipeline could not run: {0}' -f $_.Exception.Message)
    if (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue) {
        $failCtx = [pscustomobject]@{ RunId = [guid]::NewGuid().ToString(); Engine = 'flow'; ShardIndex = 0; ShardCount = 1; CollectionTime = [datetime]::UtcNow; StartedAt = [datetime]::UtcNow; FailedStep = '' }
        Send-SIRunHealthRow -RunContext $failCtx -Phase End -ExitReason 'error' -ErrorMessage $_.Exception.Message
    }
    exit 1
}
# #277: a busy wake-up is normal operation (every 5 minutes of a long run) -- one INFO line, no row, not a guard. A Run now
# that waits in the queue is recorded once ("queued") so it is visible.
if ($drain.Outcome -in @('Busy', 'Blocked')) {
    if ($pipeRequest -and (Get-Command -Name Send-SIRunHealthRow -ErrorAction SilentlyContinue)) {
        $qCtx = [pscustomobject]@{ RunId = [guid]::NewGuid().ToString(); Engine = 'flow'; ShardIndex = 0; ShardCount = 1; CollectionTime = [datetime]::UtcNow; StartedAt = [datetime]::UtcNow; FailedStep = '' }
        Send-SIRunHealthRow -RunContext $qCtx -Phase End -ExitReason 'skipped' -ErrorMessage ('queued: {0} waits for the run that holds the install ({1})' -f (Get-SIPipelineRequestText $pipeRequest), $drain.Lock.What) -NoTelemetry
    }
    exit 0
}
# #532 THROTTLE-IS-NORMAL: a run whose only failures were throttled steps is not a failure of this job -- it exits 0, so the
# flow job's own execution is not shown as failed (its steps' engines ran again on their next schedule; the one "stuck"
# alert is raised by the engine itself). Any other failure exits 1, as before.
$bad = @($drain.Runs | Where-Object { $_ -and $_.PSObject.Properties['State'] -and [string]$_.State -in @('Failed', 'Stopped') -and -not (Test-SIJobFlowThrottledOnly -State $_) })
if ($bad.Count) { exit 1 }
exit 0
