#Requires -Version 5.1
<#
    SecurityInsight -- A SCHEDULED COLLECTION NEVER RUNS BESIDE THE PIPELINE (2026-10-25, measured on two large installs on
    S3 / 100 DTU databases: a daily identity collection that started on its own timer while the pipeline held the install
    rewrote 2.39 M sidata.CiRecord rows row by row for 10-12 hours, beside the pipeline's correlation and data sync, on a
    database at 100 % of its disk-read limit -- more database time than the correlation itself).

    WHY IT HAPPENED. A collection in parts has a producer job (caj-si-<key>-producer) that is created on a TIMER in every
    mode (Get-SIKedaProducerCreateArgs), and the pipeline starts that same producer for its Collect step. So the producer's
    own daily timer is a SECOND collection, which fires whatever the pipeline is doing. (An install whose jobs run on their
    own timers has the same overlap with a pipeline run started by hand.)

    THE RULE (one read of the Pro database, read-only; Start-SIInContainer.ps1 asks it right after the execution guard, for
    the OWN execution of a Collect-stage job only -- never a queue worker, never a collect child):
      no pipeline run holds the install                      -> RUN, as today
        (cfg.PipelineLock 'install' has no holder, or no FlowRunId, or its heartbeat is older than 15 minutes -- a runner
        that died never holds a collection back -- or the run it names has ended)
      the run's step for this job is Starting (the runner saves that BEFORE it starts the job), or Running with THIS
      execution                                              -> RUN: the pipeline's own collection is never held
      the run includes this job's step (waiting, running another execution, or already ended)
                                                             -> SKIP: nothing is collected, nothing is queued, so no
                                                                worker starts -- the pipeline collects it itself
      the run does not include this job (a run of one step or one stage, or the step is switched off or skipped)
                                                             -> WAIT: asked again every minute, NO time cap of its own --
                                                                then it runs. The waiting counts against the job's own
                                                                run limit (said when the wait starts); when the limit
                                                                ends the wait, nothing is collected and the next slot
                                                                collects (said plainly).
      the state cannot be read / no Pro database             -> RUN, as today: the gate never blocks a collection on its
                                                                own failure
    SAID: one plain line in the job's log, a 'skipped' run-health row (no guard event -- this is normal operation, as a
    wake-up of the runner during a run is), and cfg.InstallState 'CollectionHeld' { job, exec, run, action, atUtc } that the
    heartbeat turns into the warning si-flow-1202 for 24 hours (P4, nobody acts, no ticket).
    PS 5.1 and 7. No PowerShell module.
#>

$script:SICollectionRunGate = @{
    # the same as SI-Pipeline.ps1 LockStaleMinutes: a lock whose heartbeat is older is a runner that stopped
    LockStaleMinutes = 15
    # how often a waiting collection asks again (a read of three index rows)
    PollSeconds      = 60
    # a waiting collection is said again at most this often
    SayEverySeconds  = 600
    # the step states of a run that are not the pipeline's own collection of this job: switched off / not run in this run
    NotCovered       = @('Disabled', 'Skipped')
    RunFinished      = @('Succeeded', 'Failed', 'Stopped', 'Cancelled')
    StateName        = 'CollectionHeld'
    ArmApi           = '2025-07-01'
    # #947 (owner 2026-10-29): A WAITING UPDATE GOES FIRST -- while an update of SecurityInsight waits for this install (the
    # updater's wait mark, tag si-update-waits, kind 'run') or is being installed (the updater holds the install's lock), a
    # scheduled collection collects nothing (SKIP; the next slot collects, on the new build). A mark older than this is not
    # obeyed: the updater cancels an old run after 6 hours, so a mark this old means the update is not coming -- the
    # collections are never held back by it for ever.
    UpdateHoldMaxHours = 12
    UpdaterHolder      = 'caj-si-updater:'
}

function ConvertFrom-SICollectionUpdateWaitsTag {
    <# PURE (#947). The updater's wait mark '<sinceUtc>|<setUtc>|<run|store>|<reason>' -> @{ SinceUtc; SetUtc; Kind; Reason },
       or $null. (The same shape SI-Pipeline.ps1 ConvertFrom-SIPipelineUpdateWaitsTag reads; this file stands alone.) #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if (-not "$Value".Trim()) { return $null }
    $p = "$Value".Split('|', 4)
    if ($p.Count -lt 3 -or $p[2] -notin @('run', 'store')) { return $null }
    $t = { param($s) $d = [datetime]::MinValue; if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { $d } else { $null } }
    $since = & $t $p[0]; $set = & $t $p[1]
    if (-not $since -or -not $set) { return $null }
    [pscustomobject]@{ SinceUtc = $since; SetUtc = $set; Kind = $p[2]; Reason = $(if ($p.Count -ge 4) { $p[3] } else { '' }) }
}

function Get-SICollectionUpdateHold {
    <#
        PURE (#947). Does a waiting update hold this scheduled collection? -Waits: the updater's wait mark (parsed; $null =
        none). Holds for a mark of kind 'run' set within -MaxHours. A 'store' mark (the updater could not read the state) holds
        nothing. Returns the plain reason, or '' (no hold).
    #>
    param($Waits, [Parameter(Mandatory)][datetime]$NowUtc, [int]$MaxHours = $script:SICollectionRunGate.UpdateHoldMaxHours)
    if (-not $Waits -or [string]$Waits.Kind -ne 'run' -or -not $Waits.SinceUtc) { return '' }
    $since = ([datetime]$Waits.SinceUtc).ToUniversalTime()
    if (($NowUtc.ToUniversalTime() - $since).TotalHours -ge $MaxHours) { return '' }
    'an update of SecurityInsight waits for this install (since {0:yyyy-MM-dd HH:mm}Z) and goes first -- this scheduled collection collected nothing; the next slot collects, on the new version' -f $since
}

function Get-SICollectionRunGateJobKey {
    <# PURE. 'caj-si-identity-producer' / 'caj-si-identity' -> 'identity' (the key the pipeline's step records use). #>
    param([AllowEmptyString()][AllowNull()][string]$JobName)
    $k = ([string]$JobName).Trim().ToLowerInvariant()
    if ($k.StartsWith('caj-si-')) { $k = $k.Substring(7) }
    if ($k.EndsWith('-producer')) { $k = $k.Substring(0, $k.Length - 9) }
    $k
}

function Get-SICollectionRunGateKeys {
    <# The keys of the Collect stage (config\job-flow.locked.json 'stage': 'collect'). Empty when the map cannot be read. #>
    param([string]$MapPath)
    if (-not $MapPath) { $MapPath = [System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'config', 'job-flow.locked.json') }
    try {
        $raw = [System.IO.File]::ReadAllText($MapPath) | ConvertFrom-Json
        @(@($raw.jobs) | Where-Object { $_ -and $_.PSObject.Properties['stage'] -and [string]$_.stage -eq 'collect' -and -not ($_.PSObject.Properties['retired'] -and [bool]$_.retired) } | ForEach-Object { ([string]$_.key).ToLowerInvariant() })
    } catch { @() }
}

function Test-SICollectionRunGateApplies {
    <#
        PURE. Is this execution one the gate asks about? Only the OWN execution of a Collect-stage job (a producer, or the one
        job of an engine collected without queue scaling): never a queue worker (-FromQueue: it works a part a producer
        already queued), never a collect child (-CollectPhase), never a job outside the Collect stage.
    #>
    param([AllowEmptyString()][string]$JobName, [AllowEmptyString()][string]$Execution, [bool]$FromQueue, [AllowEmptyString()][string]$CollectPhase, [string[]]$CollectKeys = @())
    if (-not "$JobName".Trim() -or -not "$Execution".Trim() -or $FromQueue -or "$CollectPhase".Trim()) { return $false }
    if ("$JobName".ToLowerInvariant().EndsWith('-worker')) { return $false }
    @($CollectKeys) -contains (Get-SICollectionRunGateJobKey $JobName)
}

function Get-SICollectionRunGateSql {
    <#
        PURE. ONE read-only statement: the install's lock, the run it names, and that run's step for @Job (key, or its job
        name). No lock hints: nothing is taken, the pipeline is never slowed by it. One row: HasStore, Holder, FlowRunId,
        LockAgeSeconds, RunState, RunStartedUtc, StepState, StepExecution, StepRows.
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.PipelineLock') IS NULL OR OBJECT_ID(N'cfg.FlowRun') IS NULL OR OBJECT_ID(N'cfg.FlowStepRun') IS NULL
BEGIN
    SELECT CONVERT(bit, 0) AS HasStore, CAST(NULL AS nvarchar(128)) AS Holder, CAST(NULL AS nvarchar(64)) AS FlowRunId, CAST(NULL AS int) AS LockAgeSeconds,
           CAST(NULL AS nvarchar(16)) AS RunState, CAST(NULL AS datetime2(0)) AS RunStartedUtc, CAST(NULL AS nvarchar(16)) AS StepState,
           CAST(NULL AS nvarchar(128)) AS StepExecution, 0 AS StepRows;
    RETURN;
END
DECLARE @holder nvarchar(128), @fr nvarchar(64), @hb datetime2(0);
SELECT @holder = Holder, @fr = FlowRunId, @hb = HeartbeatUtc FROM cfg.PipelineLock WHERE LockId = N'install';
DECLARE @rs nvarchar(16), @rst datetime2(0);
IF @fr IS NOT NULL SELECT @rs = State, @rst = StartedUtc FROM cfg.FlowRun WHERE FlowRunId = @fr;
DECLARE @ss nvarchar(16), @se nvarchar(128), @n int = 0;
IF @fr IS NOT NULL
BEGIN
    SELECT @n = COUNT(*) FROM cfg.FlowStepRun WHERE FlowRunId = @fr AND (Job = @Job OR Job = N'caj-si-' + @Job);
    -- the step that says most: one the runner is starting or running, else the latest of its records in this run
    SELECT TOP (1) @ss = State, @se = Execution FROM cfg.FlowStepRun
     WHERE FlowRunId = @fr AND (Job = @Job OR Job = N'caj-si-' + @Job)
     ORDER BY CASE State WHEN N'Starting' THEN 0 WHEN N'Running' THEN 1 ELSE 2 END, StepOrder DESC;
END
SELECT CONVERT(bit, 1) AS HasStore, @holder AS Holder, @fr AS FlowRunId,
       CASE WHEN @hb IS NULL THEN NULL ELSE DATEDIFF(second, @hb, SYSUTCDATETIME()) END AS LockAgeSeconds,
       @rs AS RunState, @rst AS RunStartedUtc, @ss AS StepState, @se AS StepExecution, @n AS StepRows;
'@
}

function Get-SICollectionRunGateDecision {
    <#
        PURE. THE RULE (see the top of this file) over one row of Get-SICollectionRunGateSql (a hashtable or an object; $null =
        nothing read). -Self: this execution's name; -Job: its key. Returns @{ Action = Run | Skip | Wait; Reason; RunId }.
    #>
    param($Row, [string]$Self = '', [string]$Job = '', [int]$StaleMinutes = $script:SICollectionRunGate.LockStaleMinutes)
    $v = { param($n)
        if ($null -eq $Row) { return $null }
        $x = if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { $Row[$n] } else { $null } } elseif ($Row.PSObject.Properties[$n]) { $Row.$n } else { $null }
        if ($x -is [System.DBNull]) { $null } else { $x } }
    # Own: this execution IS the pipeline's own collection step (never held, not even by a waiting update -- #947)
    $out = { param($a, $why, $run, [bool]$own = $false) [pscustomobject]@{ Action = $a; Reason = $why; RunId = [string]$run; Own = $own } }
    if ($null -eq $Row) { return (& $out 'Run' 'the pipeline''s state was not read -- the collection runs as before' '') }
    $has = & $v 'HasStore'
    if (-not (($has -eq $true) -or ([string]$has -in @('1', 'True', 'true')))) { return (& $out 'Run' 'this install keeps no pipeline state yet -- the collection runs as before' '') }
    $run = [string](& $v 'FlowRunId'); $holder = [string](& $v 'Holder')
    $age = & $v 'LockAgeSeconds'
    # #947: the UPDATER holds the install's lock (it is installing an update): a scheduled collection started now would run on
    # the version being replaced -- it collects nothing; the next slot collects, on the new version
    if ($holder -and $holder.StartsWith([string]$script:SICollectionRunGate.UpdaterHolder) -and $null -ne $age -and [int]$age -le ($StaleMinutes * 60)) {
        return (& $out 'Skip' 'an update of SecurityInsight is being installed -- this scheduled collection collected nothing; the next slot collects, on the new version' '')
    }
    if (-not $holder -or -not $run) { return (& $out 'Run' 'no pipeline run holds the install' '') }
    if ($null -eq $age -or [int]$age -gt ($StaleMinutes * 60)) { return (& $out 'Run' ('the pipeline lock of run {0} has not been renewed for more than {1} minutes (its runner stopped) -- the collection runs' -f $run, $StaleMinutes) $run) }
    $rs = [string](& $v 'RunState')
    if (-not $rs -or $rs -in $script:SICollectionRunGate.RunFinished) { return (& $out 'Run' ('pipeline run {0} has ended' -f $run) $run) }
    $ss = [string](& $v 'StepState'); $se = [string](& $v 'StepExecution')
    $rows = 0; $rv = & $v 'StepRows'; if ($null -ne $rv) { $rows = [int]$rv }
    if ($ss -eq 'Starting') { return (& $out 'Run' ('pipeline run {0} is starting its {1} step -- this is that collection' -f $run, $Job) $run $true) }
    if ($ss -eq 'Running' -and $se -and $Self -and $se -eq $Self) { return (& $out 'Run' ('this is the {0} step of pipeline run {1}' -f $Job, $run) $run $true) }
    if ($rows -gt 0 -and $ss -and $ss -notin $script:SICollectionRunGate.NotCovered) {
        $what = switch ($ss) {
            'Waiting' { 'its {0} step is still to come' -f $Job }
            'Running' { 'its {0} step is running ({1})' -f $Job, $(if ($se) { $se } else { 'another execution' }) }
            default   { 'its {0} step has already run ({1})' -f $Job, $ss.ToLowerInvariant() }
        }
        return (& $out 'Skip' ('pipeline run {0} is running and {1} -- the pipeline collects {2} itself, so this scheduled collection collected nothing (the next slot collects as usual)' -f $run, $what, $Job) $run)
    }
    $why = if ($rows -gt 0) { 'its {0} step is {1} in this run' -f $Job, $ss.ToLowerInvariant() } else { 'this run does not include {0}' -f $Job }
    & $out 'Wait' ('pipeline run {0} is running and {1} -- this scheduled collection waits for the run to end, then runs' -f $run, $why) $run
}

function ConvertTo-SICollectionRunGateState {
    <# PURE. The cfg.InstallState 'CollectionHeld' value (JSON, at most 400 characters). -Action: skipped | waiting | waited | limit. #>
    param([Parameter(Mandatory)][string]$Job, [string]$Execution = '', [string]$RunId = '', [Parameter(Mandatory)][ValidateSet('skipped', 'waiting', 'waited', 'limit')][string]$Action, [Parameter(Mandatory)][datetime]$AtUtc)
    $cut = { param($s, [int]$n) $t = [string]$s; if ($t.Length -gt $n) { $t.Substring(0, $n) } else { $t } }
    ([ordered]@{ job = (& $cut $Job 60); exec = (& $cut $Execution 120); run = (& $cut $RunId 64); action = $Action
                 atUtc = $AtUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } | ConvertTo-Json -Compress)
}

function Save-SICollectionRunGateState {
    <# cfg.InstallState 'CollectionHeld' (the heartbeat reads it). Never throws: $true when written. #>
    param([scriptblock]$Invoke, [Parameter(Mandatory)][string]$Value, [string]$By = 'collection')
    if (-not $Invoke) { return $false }
    $sql = @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NULL RETURN;
UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name;
IF @@ROWCOUNT = 0 INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (@Name, @Value, @By);
'@
    try { $null = & $Invoke $sql ([ordered]@{ Name = [string]$script:SICollectionRunGate.StateName; Value = $Value; By = $By }) 'nonquery'; $true } catch { $false }
}

function Get-SICollectionRunGateDeadline {
    <#
        PURE. When the job's own run limit ends this execution: its start (-StartedUtc) + the job's replica timeout
        (-LimitSeconds). $null when either is not known.
    #>
    param($StartedUtc, [int]$LimitSeconds = 0)
    if ($null -eq $StartedUtc -or $LimitSeconds -le 0) { return $null }
    ([datetime]$StartedUtc).ToUniversalTime().AddSeconds($LimitSeconds)
}

function Invoke-SICollectionRunGate {
    <#
        THE GATE. -Invoke: the Pro database's (sql, params, mode) seam ($null = none: Run). -Job: the key; -Self: this
        execution. -DeadlineUtc: when the job's run limit ends this execution ($null = not known). Seams: -Now, -Sleep, -Log
        { param($Level, $Message) }, -Record { param($Action, $RunId) } (cfg.InstallState; default Save-SICollectionRunGateState).
        Returns @{ Action = Run | Skip | Limit; Reason; RunId; WaitedSeconds }. Never throws.
    #>
    param([scriptblock]$Invoke, [Parameter(Mandatory)][string]$Job, [string]$Self = '', $DeadlineUtc,
          [scriptblock]$Now = { [datetime]::UtcNow }, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          [scriptblock]$Log = { param($l, $m) Write-Host $m }, [scriptblock]$Record,
          [int]$PollSeconds = $script:SICollectionRunGate.PollSeconds, [int]$SayEverySeconds = $script:SICollectionRunGate.SayEverySeconds,
          # #947: { } -> the updater's wait mark (parsed, ConvertFrom-SICollectionUpdateWaitsTag) or $null. Read once; a mark
          # that cannot be read holds nothing.
          [scriptblock]$UpdateWaits)
    $res = { param($a, $why, $run, $w) [pscustomobject]@{ Action = $a; Reason = $why; RunId = [string]$run; WaitedSeconds = [int]$w } }
    $updateHold = ''
    if ($UpdateWaits) {
        $uw = $null
        try { $uw = & $UpdateWaits } catch { & $Log 'WARN' ('[no-overlap] whether an update waits could not be read ({0}) -- nothing is held for it' -f $_.Exception.Message); $uw = $null }
        $updateHold = Get-SICollectionUpdateHold -Waits $uw -NowUtc ([datetime](& $Now))
    }
    if (-not $Record) {
        # (no closure: called only inside this function, it sees $Invoke / $Job / $Self / $Now here)
        $Record = { param($action, $run) $null = Save-SICollectionRunGateState -Invoke $Invoke -By ('caj-si-' + $Job) -Value (ConvertTo-SICollectionRunGateState -Job $Job -Execution $Self -RunId $run -Action $action -AtUtc ([datetime](& $Now))) }
    }
    if (-not $Invoke) { return (& $res 'Run' 'no Pro database is configured -- the collection runs as before' '' 0) }
    $sql = Get-SICollectionRunGateSql
    $t0 = ([datetime](& $Now)).ToUniversalTime(); $waiting = $false; $saidAt = $null
    while ($true) {
        $row = $null; $err = ''
        try { $row = @(& $Invoke $sql ([ordered]@{ Job = $Job }) 'reader' | ForEach-Object { $_ } | Where-Object { $_ })[0] } catch { $err = $_.Exception.Message }
        $tNow = ([datetime](& $Now)).ToUniversalTime()
        $waited = [int][Math]::Max(0, ($tNow - $t0).TotalSeconds)
        if ($err) {
            $why = 'the pipeline''s state could not be read ({0}) -- the collection runs as before' -f $err
            if ($waiting) { $why = 'the pipeline''s state could not be read any more ({0}) after waiting {1} min -- the collection runs now' -f $err, [int][Math]::Ceiling($waited / 60) }
            & $Log 'WARN' ('[no-overlap] ' + $why)
            return (& $res 'Run' $why '' $waited)
        }
        $d = Get-SICollectionRunGateDecision -Row $row -Self $Self -Job $Job
        # #947: a waiting update goes first -- every scheduled collection that is not the pipeline's own step holds (SKIP)
        if ($updateHold -and $d.Action -ne 'Skip' -and -not ($d.PSObject.Properties['Own'] -and $d.Own)) {
            & $Log 'INFO' ('[no-overlap] ' + $updateHold)
            try { & $Record 'skipped' $d.RunId } catch { }
            return (& $res 'Skip' $updateHold $d.RunId $waited)
        }
        if ($d.Action -eq 'Run') {
            if ($waiting) {
                $why = '{0} -- the scheduled collection waited {1} min and runs now' -f $d.Reason, [int][Math]::Ceiling($waited / 60)
                & $Log 'INFO' ('[no-overlap] ' + $why)
                try { & $Record 'waited' $d.RunId } catch { }
                return (& $res 'Run' $why $d.RunId $waited)
            }
            return (& $res 'Run' $d.Reason $d.RunId 0)
        }
        if ($d.Action -eq 'Skip') {
            $why = $d.Reason; if ($waiting) { $why = '{0} (after waiting {1} min)' -f $why, [int][Math]::Ceiling($waited / 60) }
            & $Log 'INFO' ('[no-overlap] ' + $why)
            try { & $Record 'skipped' $d.RunId } catch { }
            return (& $res 'Skip' $why $d.RunId $waited)
        }
        # Wait: said when it starts (the waiting counts against the job's own run limit), then about every ten minutes
        if (-not $waiting) {
            $waiting = $true; $saidAt = $tNow
            $lim = if ($null -ne $DeadlineUtc) { 'the job''s run limit ends this execution at {0:yyyy-MM-dd HH:mm}Z' -f ([datetime]$DeadlineUtc).ToUniversalTime() } else { 'the job''s run limit (not known here) still counts' }
            & $Log 'INFO' ('[no-overlap] {0}. The waiting counts against the job''s own run limit: {1}; if the limit ends the wait, nothing is collected and the next slot collects.' -f $d.Reason, $lim)
            try { & $Record 'waiting' $d.RunId } catch { }
        } elseif (($tNow - $saidAt).TotalSeconds -ge $SayEverySeconds) {
            $saidAt = $tNow
            & $Log 'INFO' ('[no-overlap] still waiting for pipeline run {0} to end ({1} min so far)' -f $d.RunId, [int][Math]::Ceiling($waited / 60))
        }
        # the job's own run limit, never one of the gate's: stop waiting while there is still time to say so
        if ($null -ne $DeadlineUtc -and $tNow.AddSeconds(2 * $PollSeconds) -ge ([datetime]$DeadlineUtc).ToUniversalTime()) {
            $why = 'the job''s run limit ended the wait for pipeline run {0} after {1} min -- nothing was collected; the next slot collects' -f $d.RunId, [int][Math]::Ceiling($waited / 60)
            & $Log 'WARN' ('[no-overlap] ' + $why)
            try { & $Record 'limit' $d.RunId } catch { }
            return (& $res 'Limit' $why $d.RunId $waited)
        }
        & $Sleep $PollSeconds
    }
}
