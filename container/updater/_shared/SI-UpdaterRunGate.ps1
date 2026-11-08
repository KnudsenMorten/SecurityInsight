#Requires -Version 5.1
<#
    caj-si-updater -- THE RUN GATE (owner 2026-10-23: "Should the rolls skip installs that are mid-run (large installs pick up
    the new build at their next run)?" -> "yes to both"). REPLACES the rule of 2026-10-12 ("an SI run in progress does not
    hold the update"): live 2026-10-24 an install's nightly update was installed at 16:34Z under a running pipeline run and
    the run's later steps started on the new build -- one run on two builds.

    THE RULE: the updater never changes the install while a pipeline run is going.
      * Before anything that changes the install (the database step, the code roll, the size step, the template publish)
        the updater reads the install's state store, in ONE transaction:
          - the newest pipeline run (cfg.FlowRun, as the runner reads it) is not ended (Succeeded / Failed / Stopped /
            Cancelled are ended -- no time limit, no age cap), or a step of it, or of a run that has ended, is Starting /
            Running (cfg.FlowStepRun)                                          -> WAIT ("update waits: run <id> is running")
          - otherwise it takes the install's ONE lock (cfg.PipelineLock 'install', the lock every pipeline run takes), so
            no run can start while it installs                                   -> GO (the lock is held to the end of the
            update run, beaten at every stage and released at its end)
          - the lock is held by a runner that is not running a run (a wake-up of caj-si-flow, seconds): tried again
            for a short while, then WAIT
      * The state store cannot be read                                          -> UNREADABLE: nothing is installed
        (said plainly; the pipeline runner starts the updater again at its next wake-up -- never a guess)
      * A brand-new install: no cfg.FlowRun table yet (the schema not applied yet), or no database at all (ARM: the
        database does not exist -- no run can exist without it)                  -> GO (FRESH)
      * WAIT / UNREADABLE are handed to the pipeline runner by a tag on the updater job (si-update-waits; a merge of one
        tag, no new job revision): caj-si-flow starts no NEW run while it is set (kind 'run'), and starts the updater
        once the run has ended -- so the install lands between two runs, and the queued run starts on the new build.
    It never cancels a run, never changes a grant or a security setting. REST / .NET only, no PowerShell module.
#>

$script:SIUpdaterRunGate = @{
    # the same as SI-Pipeline.ps1 LockStaleMinutes: a lock whose heartbeat is older is a runner that stopped
    LockStaleMinutes = 15
    # a lock held by a wake-up of the runner that runs nothing: asked again this often, this many times, then WAIT
    BusyRetries      = 6
    BusyRetrySeconds = 20
    Tag              = 'si-update-waits'
    RunFinished      = @('Succeeded', 'Failed', 'Stopped', 'Cancelled')
    SqlApi           = '2021-11-01'
    # #1111: the lock of the index build job is taken by an update at once (the update never waits for an index build)
    TakeFrom         = 'caj-si-index-build:%'
    # #1112: while the schema files' transactions run, the lock's What starts with this text -- the web app reads it (one row,
    # NOLOCK, a short timeout: SI.Management.Web UpdateWindow) and answers "SecurityInsight is being updated" meanwhile. The
    # web app's own copy of the text must stay equal (SIv3-WebDuringUpdate.Tests.ps1 checks both).
    WindowWhat       = 'an update of SecurityInsight: database schema'
}

function Get-SIUpdaterRunGateSql {
    <#
        PURE. The gate's T-SQL: ONE transaction -- the lock row first (UPDLOCK, so a runner cannot take it between the read
        and the claim), then the newest run and its open steps, then the claim. Returns one row: Verdict (Fresh | Wait |
        Busy | Go), RunId, RunState, RunStartedUtc, StepJob, StepState, LockHolder, LockWhat, LockHeartbeatUtc.
        #1111: @TakeFrom (a LIKE pattern, NULL = none): a lock whose holder matches it is TAKEN, never waited for -- the
        updater takes the lock of the index build job (caj-si-index-build:%) at once; that job sees it at its next check,
        pauses its build and ends. The update never waits for an index build.
    #>
    @'
SET NOCOUNT ON; SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.FlowRun') IS NULL
BEGIN
    SELECT N'Fresh' AS Verdict, CAST(NULL AS nvarchar(64)) AS RunId, CAST(NULL AS nvarchar(16)) AS RunState, CAST(NULL AS datetime2) AS RunStartedUtc,
           CAST(NULL AS nvarchar(64)) AS StepJob, CAST(NULL AS nvarchar(16)) AS StepState, CAST(NULL AS nvarchar(128)) AS LockHolder,
           CAST(NULL AS nvarchar(200)) AS LockWhat, CAST(NULL AS datetime2) AS LockHeartbeatUtc;
    RETURN;
END
DECLARE @hasLock bit = CASE WHEN OBJECT_ID(N'cfg.PipelineLock') IS NULL THEN 0 ELSE 1 END;
-- (T-SQL names are not case-sensitive: these never share a name with the parameters @Holder / @What2 / @StaleMinutes)
DECLARE @lockHolder nvarchar(128), @lockWhat nvarchar(200), @lockHb datetime2(0);
DECLARE @runId nvarchar(64), @runState nvarchar(16), @runStarted datetime2(0), @stepJob nvarchar(64), @stepState nvarchar(16);
DECLARE @verdict nvarchar(8);
BEGIN TRAN;
IF @hasLock = 1
BEGIN
    IF NOT EXISTS (SELECT 1 FROM cfg.PipelineLock WITH (UPDLOCK, HOLDLOCK) WHERE LockId = N'install') INSERT cfg.PipelineLock (LockId) VALUES (N'install');
    SELECT @lockHolder = Holder, @lockWhat = What, @lockHb = HeartbeatUtc FROM cfg.PipelineLock WITH (UPDLOCK, HOLDLOCK) WHERE LockId = N'install';
END
-- no lock hint on the run records: a NEW run needs the lock row this transaction holds, and a run that is going is seen as it is
SELECT TOP (1) @runId = FlowRunId, @runState = State, @runStarted = StartedUtc FROM cfg.FlowRun WHERE FlowId = N'daily' ORDER BY StartedUtc DESC;
SELECT TOP (1) @stepJob = s.Job, @stepState = s.State
  FROM cfg.FlowStepRun s JOIN cfg.FlowRun r ON r.FlowRunId = s.FlowRunId
 WHERE s.State IN (N'Starting', N'Running')
   AND (s.FlowRunId = @runId OR r.State IN (N'Succeeded', N'Failed', N'Stopped', N'Cancelled'))
 ORDER BY CASE WHEN s.FlowRunId = @runId THEN 0 ELSE 1 END, s.StepOrder;
IF @runId IS NOT NULL AND ISNULL(@runState, N'') NOT IN (N'Succeeded', N'Failed', N'Stopped', N'Cancelled') SET @verdict = N'Wait'
ELSE IF @stepJob IS NOT NULL SET @verdict = N'Wait'
ELSE IF @hasLock = 0 SET @verdict = N'Go'
ELSE
BEGIN
    UPDATE cfg.PipelineLock
       SET Holder = @Holder, What = @What2, FlowRunId = NULL,
           AcquiredUtc = CASE WHEN Holder = @Holder THEN AcquiredUtc ELSE SYSUTCDATETIME() END, HeartbeatUtc = SYSUTCDATETIME()
     WHERE LockId = N'install' AND (Holder IS NULL OR Holder = @Holder OR HeartbeatUtc IS NULL OR HeartbeatUtc < DATEADD(minute, -@StaleMinutes, SYSUTCDATETIME())
                                    OR (@TakeFrom IS NOT NULL AND Holder LIKE @TakeFrom));
    SET @verdict = CASE WHEN @@ROWCOUNT = 1 THEN N'Go' ELSE N'Busy' END;
END
COMMIT;
SELECT @verdict AS Verdict, @runId AS RunId, @runState AS RunState, @runStarted AS RunStartedUtc, @stepJob AS StepJob, @stepState AS StepState,
       @lockHolder AS LockHolder, @lockWhat AS LockWhat, @lockHb AS LockHeartbeatUtc;
'@
}

function Get-SIUpdaterRunGateHolder {
    <# The name this update run holds the install's lock under: caj-si-updater:<its execution> (unique per run). #>
    param([hashtable]$Env = @{})
    $x = if ($Env.ContainsKey('CONTAINER_APP_JOB_EXECUTION_NAME')) { "$($Env['CONTAINER_APP_JOB_EXECUTION_NAME'])" } else { "$([Environment]::GetEnvironmentVariable('CONTAINER_APP_JOB_EXECUTION_NAME'))" }
    if (-not "$x".Trim()) { $x = [guid]::NewGuid().ToString('n').Substring(0, 12) }
    ('caj-si-updater:{0}' -f "$x".Trim())
}

function ConvertTo-SIUpdaterRunGateText {
    <# PURE. The one plain line of a WAIT. #>
    param($Row)
    $v = { param($n) if ($Row -and $Row.ContainsKey($n) -and $null -ne $Row[$n] -and -not ($Row[$n] -is [DBNull])) { $Row[$n] } else { $null } }
    $run = & $v 'RunId'; $state = & $v 'RunState'; $started = & $v 'RunStartedUtc'; $job = & $v 'StepJob'; $stepState = & $v 'StepState'
    $since = if ($started) { (' since {0:yyyy-MM-dd HH:mm}Z' -f ([datetime]$started)) } else { '' }
    if ($run -and "$state" -notin $script:SIUpdaterRunGate.RunFinished) {
        return ('update waits: run {0} is running{1}{2} -- the update is installed when it has ended, before the next run starts' -f $run, $since, $(if ($job) { (', step {0}' -f $job) } else { '' }))
    }
    if ($job) { return ('update waits: step {0} is still {1} -- the update is installed when it has ended, before the next run starts' -f $job, "$stepState".ToLowerInvariant()) }
    $h = & $v 'LockHolder'; $w = & $v 'LockWhat'
    ('update waits: the pipeline runner holds the install ({0}{1}) -- the update is installed before the next run starts' -f $h, $(if ($w) { ", $w" } else { '' }))
}

function Test-SIUpdaterDatabaseMissing {
    <#
        Is the Pro database not there at all (a brand-new install before its database is made)? ARM: the SQL server whose
        fullyQualifiedDomainName is -Server, then its database -Database -> 404 = missing ($true). Anything that cannot be
        read is NOT missing ($false): only a database Azure says does not exist counts. -Arm { param($Method, $Path) }: the
        test seam (default Invoke-SIUpdaterArm).
    #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][string]$SubscriptionId, [scriptblock]$Arm)
    if (-not $Arm) {
        $Arm = { param($Method, $Path, [switch]$List, [switch]$AllowNotFound)
                 if ($List) { Invoke-SIUpdaterArm -Path $Path -ApiVersion $script:SIUpdaterRunGate.SqlApi -List } else { Invoke-SIUpdaterArm -Path $Path -ApiVersion $script:SIUpdaterRunGate.SqlApi -AllowNotFound } }
    }
    try {
        $servers = @(& $Arm 'GET' ('/subscriptions/{0}/providers/Microsoft.Sql/servers' -f $SubscriptionId) -List | Where-Object { $_ })
        $hit = @($servers | Where-Object { [string]$_.properties.fullyQualifiedDomainName -ieq $Server -or [string]$_.name -ieq (($Server -split '\.')[0]) })[0]
        if (-not $hit) { return $false }
        $db = & $Arm 'GET' ('{0}/databases/{1}' -f [string]$hit.id, $Database) -AllowNotFound
        return ($null -eq $db)
    } catch { return $false }
}

function Get-SIUpdaterStartingRun {
    <#
        PURE. #1150 (an install, 2026-11-07: a scheduled run's runner started 18:00:55, an "update now" a minute later found
        no run recorded yet, took the lock and rolled the jobs under the starting run -- it was cancelled): the executions of
        the pipeline runner (ARM shape) that run now and started within -Minutes -- a run that may be starting and is not in
        the run record yet. An execution started with SI_FLOW_CANCEL=1 is the caller's own cancel of a run (cancelled on
        purpose) and never counts. Returns "name (started HH:mm:ssZ)" strings.
    #>
    param([object[]]$Executions = @(), [Parameter(Mandatory)][datetime]$NowUtc, [int]$Minutes = 10)
    $styles = [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal'
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($e in @($Executions | Where-Object { $_ })) {
        $p = $e.properties
        if (-not $p -or "$($p.status)" -notin @('Running', 'Processing') -or "$($p.endTime)".Trim()) { continue }
        $d = [datetime]::MinValue
        if (-not [datetime]::TryParse("$($p.startTime)", [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { continue }
        if (($NowUtc.ToUniversalTime() - $d).TotalMinutes -gt $Minutes) { continue }
        $cancel = $false
        try { foreach ($c in @($p.template.containers)) { foreach ($v in @($c.env)) { if ($v -and "$($v.name)" -eq 'SI_FLOW_CANCEL' -and "$($v.value)" -match '^(?i)(1|true|yes)$') { $cancel = $true } } } } catch { }
        if ($cancel) { continue }
        $out.Add(('{0} (started {1:HH:mm:ss}Z)' -f [string]$e.name, $d))
    }
    $out.ToArray()   # (unrolled: the callers wrap it in @(); none = nothing)
}

function Invoke-SIUpdaterRunGate {
    <#
        THE GATE. Returns @{ Go; Verdict = Go | Fresh | Wait | Unreadable; Kind ('' | run | store); Reason; RunId; LockTaken;
        Holder }. -Store: the Pro database ($null = none configured: then the SI jobs' executions decide, -BusyJobs).
        -Sleep: the test seam for the short wait on a runner's wake-up. Never throws.
    #>
    param($Store, [Parameter(Mandatory)][string]$Holder, [string]$What = 'an update of SecurityInsight', [string]$SubscriptionId = '',
          [scriptblock]$BusyJobs, [scriptblock]$DatabaseMissing, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$BusyRetries = $script:SIUpdaterRunGate.BusyRetries,
          # #1111: the holders whose lock is TAKEN, never waited for (default: the index build job -- the update goes first);
          # '' = none (the index build job itself)
          [AllowEmptyString()][string]$TakeFrom = $script:SIUpdaterRunGate.TakeFrom,
          # #1150: { } -> the pipeline runner's executions that started minutes ago and still run (Get-SIUpdaterStartingRun);
          # given for an "update now" start: such a run may be starting and not be recorded yet -- asked again for a short
          # while (a wake-up that runs nothing ends in seconds), then WAIT. $null = not asked (every other start).
          [scriptblock]$StartingRun)
    $res = { param($v, $kind, $why, $row, [bool]$lock) [pscustomobject]@{ Go = ($v -in @('Go', 'Fresh')); Verdict = $v; Kind = $kind; Reason = $why
                                                                       RunId = $(if ($row -and $row.ContainsKey('RunId') -and -not ($row['RunId'] -is [DBNull])) { [string]$row['RunId'] } else { '' })
                                                                       LockTaken = $lock; Holder = $Holder } }
    if ($StartingRun) {
        $seen = @()
        for ($i = 0; $i -le $BusyRetries; $i++) {
            $seen = @(); try { $seen = @(& $StartingRun | Where-Object { $_ }) } catch { $seen = @() }
            if (-not $seen.Count) { break }
            if ($i -lt $BusyRetries) { & $Sleep ([int]$script:SIUpdaterRunGate.BusyRetrySeconds) }
        }
        if ($seen.Count) {
            return (& $res 'Wait' 'run' ('update waits: a pipeline run is starting (the pipeline runner {0} started minutes ago and still runs) -- the update is installed when it has ended, before the next run starts' -f ($seen -join ', ')) $null $false)
        }
    }
    if (-not $Store) {
        # no state store configured: the SI jobs' executions decide (an install without a Pro database)
        $busy = @(); $err = ''
        if ($BusyJobs) { try { $busy = @(& $BusyJobs | Where-Object { $_ }) } catch { $err = $_.Exception.Message } }
        if ($err) { return (& $res 'Unreadable' 'store' ("update waits: whether an SI job runs could not be read ({0}) -- nothing is installed now; it is tried again" -f $err) $null $false) }
        if ($busy.Count) { return (& $res 'Wait' 'run' ("update waits: {0} is running -- the update is installed when it has ended" -f ($busy -join ', ')) $null $false) }
        return (& $res 'Go' '' 'no SI job runs (this install has no state store; its jobs were read)' $null $false)
    }
    $sql = Get-SIUpdaterRunGateSql
    $attempt = 0
    while ($true) {
        $attempt++
        $row = $null
        try {
            $rows = @(& $Store.Invoke $sql ([ordered]@{ Holder = $Holder; What2 = $What; StaleMinutes = [int]$script:SIUpdaterRunGate.LockStaleMinutes; TakeFrom = $(if ("$TakeFrom".Trim()) { "$TakeFrom".Trim() } else { $null }) }) 'reader' | ForEach-Object { $_ } | Where-Object { $_ })
            $row = $rows[0]
            if (-not $row) { throw 'the state store answered no row' }
        } catch {
            $msg = $_.Exception.Message
            if ($DatabaseMissing) {
                $missing = $false; try { $missing = [bool](& $DatabaseMissing) } catch { $missing = $false }
                if ($missing) { return (& $res 'Fresh' '' 'a new install: its database is not made yet, so no pipeline run can be going' $null $false) }
            }
            return (& $res 'Unreadable' 'store' ("update waits: the state store could not be read ({0}) -- nothing is installed now; it is tried again at the pipeline runner's next wake-up" -f $msg) $null $false)
        }
        $verdict = [string]$row['Verdict']
        switch ($verdict) {
            'Fresh' { return (& $res 'Fresh' '' 'a new install: no pipeline run has been recorded yet (the state store has no run table yet)' $row $false) }
            'Go'    { return (& $res 'Go' '' ('no pipeline run is going -- the install''s lock is held by this update ({0})' -f $Holder) $row $true) }
            'Wait'  { return (& $res 'Wait' 'run' (ConvertTo-SIUpdaterRunGateText -Row $row) $row $false) }
            default {
                # Busy: a runner holds the lock and runs nothing (a wake-up, seconds) -- asked again for a short while
                if ($attempt -le $BusyRetries) { & $Sleep ([int]$script:SIUpdaterRunGate.BusyRetrySeconds); continue }
                return (& $res 'Wait' 'run' (ConvertTo-SIUpdaterRunGateText -Row $row) $row $false)
            }
        }
    }
}

function Update-SIUpdaterRunGateBeat {
    <# The lock's heartbeat, while this update holds it (a runner takes over a lock 15 minutes old). Never throws. #>
    param($Store, [string]$Holder, [string]$What = 'an update of SecurityInsight')
    if (-not $Store -or -not $Holder) { return $false }
    try { $null = & $Store.Invoke "IF OBJECT_ID(N'cfg.PipelineLock') IS NOT NULL UPDATE cfg.PipelineLock SET HeartbeatUtc = SYSUTCDATETIME(), What = @What WHERE LockId = N'install' AND Holder = @Holder;" ([ordered]@{ Holder = $Holder; What = $What }) 'nonquery'; $true } catch { $false }
}

function Exit-SIUpdaterRunGate {
    <# The lock is released at the end of the update run (only when this run holds it). Never throws. #>
    param($Store, [string]$Holder)
    if (-not $Store -or -not $Holder) { return $false }
    try { $null = & $Store.Invoke "IF OBJECT_ID(N'cfg.PipelineLock') IS NOT NULL UPDATE cfg.PipelineLock SET Holder = NULL, What = NULL, FlowRunId = NULL, HeartbeatUtc = NULL WHERE LockId = N'install' AND Holder = @Holder;" ([ordered]@{ Holder = $Holder }) 'nonquery'; $true } catch { $false }
}

# ---- the hand-over to the pipeline runner: the tag si-update-waits on the updater job ---------------------------------
function ConvertTo-SIUpdateWaitsTag {
    <# PURE. The tag value: <sinceUtc>|<setUtc>|<kind>|<reason> (at most 256 characters; '|' never in the reason). #>
    param([Parameter(Mandatory)][datetime]$SinceUtc, [Parameter(Mandatory)][datetime]$SetUtc, [Parameter(Mandatory)][ValidateSet('run', 'store')][string]$Kind, [string]$Reason = '')
    $f = 'yyyy-MM-ddTHH:mm:ssZ'
    $head = '{0}|{1}|{2}|' -f $SinceUtc.ToUniversalTime().ToString($f, [Globalization.CultureInfo]::InvariantCulture), $SetUtc.ToUniversalTime().ToString($f, [Globalization.CultureInfo]::InvariantCulture), $Kind
    $why = ("$Reason" -replace '\|', '/' -replace '[\r\n]+', ' ').Trim()
    $room = 256 - $head.Length
    if ($why.Length -gt $room) { $why = $why.Substring(0, [Math]::Max(0, $room - 3)) + '...' }
    $head + $why
}

function ConvertFrom-SIUpdateWaitsTag {
    <# PURE. The tag value -> @{ SinceUtc; SetUtc; Kind; Reason }, or $null (empty / not this shape). #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if (-not "$Value".Trim()) { return $null }
    $p = "$Value".Split('|', 4)
    if ($p.Count -lt 3 -or $p[2] -notin @('run', 'store')) { return $null }
    $t = { param($s) $d = [datetime]::MinValue; if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { $d } else { $null } }
    $since = & $t $p[0]; $set = & $t $p[1]
    if (-not $since -or -not $set) { return $null }
    [pscustomobject]@{ SinceUtc = $since; SetUtc = $set; Kind = $p[2]; Reason = $(if ($p.Count -ge 4) { $p[3] } else { '' }) }
}

function Read-SIUpdaterWaitsTag {
    <# The tag on the updater job now ('' = none). Throws when the job cannot be read. #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$JobName)
    $j = Invoke-SIUpdaterArm -Path (Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/jobs/' + $JobName)) -AllowNotFound
    if (-not $j) { return [pscustomobject]@{ Value = ''; JobId = '' } }
    $v = ''; if ($j.tags -and $j.tags.PSObject.Properties[$script:SIUpdaterRunGate.Tag]) { $v = [string]$j.tags.($script:SIUpdaterRunGate.Tag) }
    [pscustomobject]@{ Value = $v; JobId = [string]$j.id }
}

function Write-SIUpdaterWaitsTag {
    <# The tag set ('' = cleared) -- a merge of this one tag, no new job revision. Never throws. #>
    param([Parameter(Mandatory)][string]$JobId, [AllowEmptyString()][string]$Value, [string]$SubscriptionId = '')
    if (-not $JobId) { return $false }
    try { Update-SIUpdaterTags -ResourceId $JobId -Tags @{ $script:SIUpdaterRunGate.Tag = "$Value" }; $true }
    catch { Write-UpdLog ("WARNING: the update's wait could not be handed to the pipeline runner (tag {0}): {1}" -f $script:SIUpdaterRunGate.Tag, $_.Exception.Message); $false }
}

# ---- the second update (the update steps a release brings run on the update AFTER the one that installs it) ------------
function Start-SIUpdaterSecondPass {
    <#
        After an update that installed a release AND moved the updater onto that release's image: the updater's own job is
        started once more (SI_UPDATER_MODE = second-pass), so the release's own update steps run at once -- while the
        pipeline still starts nothing (an updater execution is running) -- instead of at the next nightly update, which on a
        busy install would find a run going. -Arm { param($Method, $Path, $Body) }: the test seam. Returns the line. Never throws.
    #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$JobName, [scriptblock]$Arm)
    try {
        if (-not (Get-Command -Name New-SIUpdateNowStartTemplate -ErrorAction SilentlyContinue)) { return 'second update: not started (this image has no start template) -- the next update runs the release''s update steps' }
        $path = Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider ('Microsoft.App/jobs/' + $JobName)
        $job = if ($Arm) { & $Arm 'GET' $path $null } else { Invoke-SIUpdaterArm -Path $path }
        $body = New-SIUpdateNowStartTemplate -Job $job -Mode 'second-pass'
        $r = if ($Arm) { & $Arm 'POST' ($path + '/start') $body } else { Invoke-SIUpdaterArm -Method POST -Path ($path + '/start') -Body $body }
        ('second update: started ({0}) -- it runs this release''s update steps before the next pipeline run' -f $(if ($r -and $r.PSObject.Properties['name']) { [string]$r.name } else { 'an execution' }))
    } catch { ('second update: could not be started ({0}) -- the next update runs the release''s update steps' -f $_.Exception.Message) }
}

function Wait-SIUpdaterPreviousEnded {
    <#
        The second update waits for the update that started it to end (its execution is still finishing). No time limit of
        its own: the job's run limit ends it. -Executions { } -> the updater job's executions (ARM shape); -Self: this
        execution's name. Returns the line.
    #>
    param([Parameter(Mandatory)][scriptblock]$Executions, [string]$Self = '', [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [int]$PollSeconds = 15)
    $n = 0
    while ($true) {
        $others = @()
        try { $others = @(& $Executions | Where-Object { $_ -and [string]$_.name -ne $Self }) } catch { return ('second update: the update before it could not be read ({0}) -- going on' -f $_.Exception.Message) }
        $running = if (Get-Command -Name Test-SIUpdateNowUpdaterRunning -ErrorAction SilentlyContinue) { Test-SIUpdateNowUpdaterRunning -Executions $others -NowUtc ([datetime]::UtcNow) }
                   else { @($others | Where-Object { "$($_.properties.status)" -in @('Running', 'Processing') } | ForEach-Object { [string]$_.name })[0] }
        if (-not $running) { return $(if ($n) { 'second update: the update before it has ended' } else { 'second update: no other update runs' }) }
        $n++
        & $Sleep $PollSeconds
    }
}

# ---- #911: two hourly updates never overlap ------------------------------------------------------------------------------
# Live 2026-10-27 (a large install): the 17:30Z execution started while the 16:30Z one still ran; its web-app roll got HTTP
# 409 ContainerAppOperationInProgress and the post-roll check said "the engine jobs run X, but the web app was NOT updated"
# (a customer ticket). An update execution now STEPS ASIDE at once when an EARLIER execution of its own job still runs.
function Select-SIUpdaterEarlierRunning {
    <#
        PURE. The EARLIER execution of the updater job that is still running, or $null. -Executions: the job's executions (ARM
        shape: name, properties.status / startTime / endTime); -Self: this execution's name. Running / Processing with no
        endTime, started within the job's run limit (an older Running one is a leftover -- Test-SIUpdateNowUpdaterRunning's
        rule), and started BEFORE this execution (same second: the lower name is the earlier -- of two at once, exactly one
        goes on). Without -Self (a hand run) every other running execution is earlier. @{ Name; StartedUtc }.
    #>
    param([object[]]$Executions = @(), [string]$Self = '', [Parameter(Mandatory)][datetime]$NowUtc, [int]$RunLimitSeconds = 0)
    $limit = if ($RunLimitSeconds -gt 0) { $RunLimitSeconds + 900 } else { 6 * 3600 }
    $start = { param($e) $p = if ($e.PSObject.Properties['properties']) { $e.properties } else { $e }
               try { if ($p.PSObject.Properties['startTime'] -and "$($p.startTime)".Trim()) { return [datetime]::Parse([string]$p.startTime, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal) } } catch { }
               $null }
    $mine = $null
    if ("$Self".Trim()) { $me = @($Executions | Where-Object { $_ -and [string]$_.name -eq $Self })[0]; if ($me) { $mine = & $start $me } }
    $best = $null
    foreach ($e in @($Executions)) {
        if ($null -eq $e -or ("$Self".Trim() -and [string]$e.name -eq $Self)) { continue }
        $p = if ($e.PSObject.Properties['properties']) { $e.properties } else { $e }
        if ([string]$p.status -notin @('Running', 'Processing')) { continue }
        if ($p.PSObject.Properties['endTime'] -and "$($p.endTime)".Trim()) { continue }
        $s = & $start $e
        if ($s -and ($NowUtc.ToUniversalTime() - $s).TotalSeconds -gt $limit) { continue }
        if ($mine -and $s) {
            if ($s -gt $mine) { continue }
            if ($s -eq $mine -and [string]::CompareOrdinal([string]$e.name, [string]$Self) -gt 0) { continue }
        }
        if (-not $best -or ($s -and $best.StartedUtc -and $s -lt $best.StartedUtc)) { $best = [pscustomobject]@{ Name = [string]$e.name; StartedUtc = $s } }
    }
    $best
}

function Select-SIUpdaterEarlierLiveness {
    <#
        PURE. NO FRESH BEAT = DEAD (engine/_shared/SI-ExecutionLiveness.ps1) for the step-aside: of the EARLIER running
        executions of the updater job (the same "earlier" as Select-SIUpdaterEarlierRunning: started before this one; the same
        second: the lower name), which are DEAD (no beat on the install lock or the update's own lock for 15 minutes; never a
        beat and started more than 30 minutes ago) and which LIVE one this update steps aside for (the earliest; a live one
        past the run limit -- 6 h without -RunLimitSeconds -- is a leftover, as before). -LocksKnown $false: the old rule
        (Select-SIUpdaterEarlierRunning; nothing is dead). Returns @{ Earlier = @{ Name; StartedUtc } or $null; Dead = @() }.
    #>
    param([object[]]$Executions = @(), [string]$Self = '', [Parameter(Mandatory)][datetime]$NowUtc, [int]$RunLimitSeconds = 0,
          [object[]]$Locks = @(), [bool]$LocksKnown = $false, [System.Collections.IDictionary]$Stopped)
    if (-not $LocksKnown -or -not (Get-Command -Name Select-SIExecutionLiveness -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Earlier = (Select-SIUpdaterEarlierRunning -Executions $Executions -Self $Self -NowUtc $NowUtc -RunLimitSeconds $RunLimitSeconds); Dead = @() }
    }
    $limit = if ($RunLimitSeconds -gt 0) { $RunLimitSeconds + 900 } else { 6 * 3600 }
    $mine = $null
    if ("$Self".Trim()) { $me = @($Executions | Where-Object { $_ -and [string]$_.name -eq $Self })[0]; if ($me) { $mine = Get-SIExecutionStartUtc $me } }
    $earlier = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Executions | Where-Object { $_ })) {
        if ("$Self".Trim() -and [string]$e.name -eq $Self) { continue }
        $s = Get-SIExecutionStartUtc $e
        if ($mine -and $s) {
            if ($s -gt $mine) { continue }
            if ($s -eq $mine -and [string]::CompareOrdinal([string]$e.name, [string]$Self) -gt 0) { continue }
        }
        $earlier.Add($e)
    }
    $sel = Select-SIExecutionLiveness -Executions $earlier.ToArray() -Self $Self -Kind updater -Locks $Locks -LocksKnown $true -NowUtc $NowUtc -Stopped $Stopped
    $best = $null
    foreach ($lv in @($sel.Live)) {
        if ($lv.StartedUtc -and ($NowUtc.ToUniversalTime() - $lv.StartedUtc).TotalSeconds -gt $limit) { continue }
        if (-not $best -or ($lv.StartedUtc -and $best.StartedUtc -and $lv.StartedUtc -lt $best.StartedUtc)) { $best = [pscustomobject]@{ Name = $lv.Name; StartedUtc = $lv.StartedUtc } }
    }
    [pscustomobject]@{ Earlier = $best; Dead = @($sel.Dead) }
}

function Get-SIUpdaterEarlierLiveness {
    <#
        The step-aside under the rule: reads the lock rows (-Store: the Pro database; -Locks / -LocksKnown: the test seam),
        STOPS every dead earlier execution (-Stop { param($Name) }, said with Write-UpdLog, raised to Invardia as the alert
        si.execution.stopped-dead -- -Alert { param($Event) } is the test seam) and answers the execution this update steps
        aside for: a live earlier one, or a dead one that could not be stopped (unless it started more than 6 hours ago --
        never two updates side by side). $null = go on. Lock rows that cannot be read: the old rule.
    #>
    param([object[]]$Executions = @(), [string]$Self = '', [Parameter(Mandatory)][datetime]$NowUtc, [int]$RunLimitSeconds = 0, $Store,
          [object[]]$Locks, $LocksKnown, [Parameter(Mandatory)][scriptblock]$Stop, [scriptblock]$Alert, [scriptblock]$Log)
    if (-not $Log) { $Log = { param($l, $m) Write-UpdLog $(if ($l -eq 'WARN') { 'WARNING: ' + $m } else { $m }) } }
    $known = $false; $rows = @()
    if ($null -ne $LocksKnown) { $known = [bool]$LocksKnown; $rows = @($Locks) }
    elseif ($Store -and $Store.Invoke -and (Get-Command -Name Read-SIExecutionLocks -ErrorAction SilentlyContinue)) {
        try { $lr = Read-SIExecutionLocks -Store (New-SIExecutionLockStore -Invoke $Store.Invoke); $known = [bool]$lr.Known; $rows = @($lr.Rows) }
        catch { & $Log 'INFO' ('whether an earlier update still works could not be read ({0}) -- a running one is waited for as before' -f $_.Exception.Message) }
    }
    if ($null -eq $global:SI_ExecutionStopped) { $global:SI_ExecutionStopped = @{} }
    $sel = Select-SIUpdaterEarlierLiveness -Executions $Executions -Self $Self -NowUtc $NowUtc -RunLimitSeconds $RunLimitSeconds -Locks $rows -LocksKnown $known -Stopped $global:SI_ExecutionStopped
    if (-not @($sel.Dead).Count) { return $sel.Earlier }
    if (-not $Alert) { $Alert = { param($ev) $null = Send-SIExecutionStoppedAlert -Event $ev } }
    $st = Invoke-SIExecutionDeadStop -Dead @($sel.Dead) -Stop $Stop -Log $Log -Alert $Alert -OthersLive ([bool]$sel.Earlier) -Stopped $global:SI_ExecutionStopped -NowUtc $NowUtc
    if ($sel.Earlier) { return $sel.Earlier }
    $b = @($st.Blocking)[0]
    if ($b) { return [pscustomobject]@{ Name = $b.Name; StartedUtc = $b.StartedUtc } }
    $null
}

function Get-SIUpdaterStepAsideText {
    <# PURE. #911: the one line of an update that steps aside for an earlier one. #>
    param([Parameter(Mandatory)]$Earlier)
    ('update steps aside: the earlier update {0}{1} is still running -- this one changes nothing and ends (the next hourly update goes on as usual)' -f $Earlier.Name, $(if ($Earlier.StartedUtc) { (' (started {0:yyyy-MM-dd HH:mm}Z)' -f ([datetime]$Earlier.StartedUtc)) } else { '' }))
}

# ---- #911 (d): the update beats the install's lock at every step -----------------------------------------------------------
# Live 2026-10-27: the later update held cfg.PipelineLock 'install' with a heartbeat never beaten after 17:33Z while a step ran
# silently for an hour. The gate registers the lock it took; every step of the update -- the updater's own and the release's
# setup\Invoke-SIContainerUpdate.ps1 (its Step function) -- beats it through Invoke-SIUpdaterLockBeat.
function Register-SIUpdaterLockBeat {
    <# The lock this update holds, for Invoke-SIUpdaterLockBeat. -Beat { param($Holder, $What) } is the test seam (default
       Update-SIUpdaterRunGateBeat on -Store). #>
    param($Store, [Parameter(Mandatory)][string]$Holder, [scriptblock]$Beat, [switch]$Real)
    $global:SI_UpdaterLockBeat = [pscustomobject]@{ Store = $Store; Holder = $Holder; Beat = $Beat; Real = [bool]$Real; LastUtc = [datetime]::MinValue; Beats = 0 }
}

function Unregister-SIUpdaterLockBeat { $global:SI_UpdaterLockBeat = $null; $global:SI_UpdaterDbWindow = $false }

function Register-SIUpdaterExecutionBeat {
    <#
        NO FRESH BEAT = DEAD (d): the update's OWN sign of life -- the 'updater' row of the lock table (Holder
        caj-si-updater:<execution>), taken at once (free, stale 15 minutes, or its own) and then beaten by
        Invoke-SIUpdaterLockBeat (every log line, at most once a minute). -Beat { param($Holder, $What) } is the test seam.
        Never throws; $true when taken.
    #>
    param($Store, [Parameter(Mandatory)][string]$Holder, [scriptblock]$Beat)
    if (-not $Beat -and -not (Get-Command -Name Enter-SIExecutionLock -ErrorAction SilentlyContinue)) { return $false }
    $lockStore = if ($Beat) { $null } elseif ($Store -and $Store.Invoke) { New-SIExecutionLockStore -Invoke $Store.Invoke } else { $null }
    if (-not $Beat -and -not $lockStore) { return $false }
    $global:SI_UpdaterExecBeat = [pscustomobject]@{ Store = $lockStore; Holder = $Holder; Beat = $Beat; LastUtc = [datetime]::MinValue; Beats = 0 }
    $ok = $false
    try { $ok = if ($Beat) { [bool](& $Beat $Holder 'start') } else { [bool](Enter-SIExecutionLock -Store $lockStore -Lock 'updater' -Holder $Holder -What 'an update of SecurityInsight: start') } } catch { $ok = $false }
    if ($ok) { $global:SI_UpdaterExecBeat.LastUtc = [datetime]::UtcNow; $global:SI_UpdaterExecBeat.Beats = 1 }
    $ok
}

function Unregister-SIUpdaterExecutionBeat {
    <# The update's own sign of life released at the end of the run (only when this run holds it). Never throws. #>
    $x = $global:SI_UpdaterExecBeat
    $global:SI_UpdaterExecBeat = $null
    if ($x -and $x.Store -and $x.Holder) { try { Exit-SIExecutionLock -Store $x.Store -Lock 'updater' -Holder $x.Holder } catch { } }
}

function Get-SIUpdaterLockWhat {
    <# PURE. The lock's What for a beat of the step -What (at most 200 characters). #1112: inside the database window
       ($global:SI_UpdaterDbWindow, Set-SIUpdaterDatabaseWindow) it starts with the window's text, whatever the step says --
       so a log line's beat during the schema files never ends the web app's notice early. #>
    param([string]$What = 'an update step')
    $w = if ($global:SI_UpdaterDbWindow) {
        $m = [string]$script:SIUpdaterRunGate.WindowWhat
        if ("$What".Trim() -and "$What".Trim() -ne 'database schema') { '{0} -- {1}' -f $m, "$What".Trim() } else { $m }
    } else { 'an update of SecurityInsight: {0}' -f $What }
    if ($w.Length -gt 200) { $w = $w.Substring(0, 200) }
    $w
}

function Set-SIUpdaterDatabaseWindow {
    <#
        #1112: the database window opened ($true) / closed ($false) -- called by the schema apply around the files'
        transactions (Invoke-SIProSchemaApply -Window). The install's lock is beaten at once (-Force) with the window's text,
        or, closed, with the step's own; the web app sees it at its next read (seconds). Never throws; $true when beaten.
    #>
    param([Parameter(Mandatory)][bool]$On, [string]$Step = 'database')
    $global:SI_UpdaterDbWindow = $On
    $what = if ($On) { 'database schema' } else { $Step }
    try { [bool](Invoke-SIUpdaterLockBeat -What $what -Force) } catch { $false }
}

function Invoke-SIUpdaterLockBeat {
    <#
        #911 (d): the install's lock beaten for the step -What, when this update holds it (Register-SIUpdaterLockBeat). At most
        once per -MinSeconds (60) unless -Force; a lock this update does not hold is never touched. Never throws; $true when
        it was beaten.
    #>
    param([string]$What = 'an update step', [int]$MinSeconds = 60, [switch]$Force, $NowUtc)
    $now = if ($NowUtc) { ([datetime]$NowUtc).ToUniversalTime() } else { [datetime]::UtcNow }
    # NO FRESH BEAT = DEAD: the update's own sign of life (its 'updater' lock row) is beaten too -- from its first moment,
    # also before (and without) the install lock
    $x = $global:SI_UpdaterExecBeat
    if ($x -and $x.Holder -and ($Force -or ($now - $x.LastUtc).TotalSeconds -ge $MinSeconds)) {
        $xok = $false
        try { $xok = if ($x.Beat) { [bool](& $x.Beat $x.Holder $What) } else { [bool](Update-SIExecutionLockBeat -Store $x.Store -Lock 'updater' -Holder $x.Holder -What (Get-SIUpdaterLockWhat -What $What)) } } catch { $xok = $false }
        if ($xok) { $x.LastUtc = $now; $x.Beats++ }
        # lost it (another update took a stale row): take it again when it is free
        elseif (-not $x.Beat -and $x.Store) { try { if (Enter-SIExecutionLock -Store $x.Store -Lock 'updater' -Holder $x.Holder -What (Get-SIUpdaterLockWhat -What $What)) { $x.LastUtc = $now; $x.Beats++ } } catch { } }
    }
    $b = $global:SI_UpdaterLockBeat
    if (-not $b -or -not $b.Holder) { return $false }
    if (-not $Force -and ($now - $b.LastUtc).TotalSeconds -lt $MinSeconds) { return $false }
    $ok = $false
    try {
        $w = Get-SIUpdaterLockWhat -What $What
        if ($b.Beat) { $null = & $b.Beat $b.Holder $w; $ok = $true }
        elseif ($b.Real -and $b.Store) { $ok = [bool](Update-SIUpdaterRunGateBeat -Store $b.Store -Holder $b.Holder -What $w) }
    } catch { $ok = $false }
    if ($ok) { $b.LastUtc = $now; $b.Beats++ }
    $ok
}
