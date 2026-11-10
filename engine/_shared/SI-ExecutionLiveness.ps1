#Requires -Version 5.1
<#
    SecurityInsight -- NO FRESH BEAT = DEAD (one rule for every execution kind; agreed with Invardia 2026-11-06).

    WHY. Live 2026-11-06: an updater execution that never started its container (ARM status Running, no log line) held an
    install's daily run back for 6 hours -- the pipeline treated ANY running updater execution younger than 6 h as an update.
    Live 2026-11-05/06: a hung flow execution held another install for 47 hours -- every later wake-up saw "the flow is still
    running" and only did the housekeeping. Azure's "Running" says nothing about whether the code still works.

    THE RULE. An execution counts as RUNNING only while it shows a fresh sign of life -- a BEAT on a lock row (Pro: a row of
    cfg.PipelineLock; Community without a database: a lock document in the install's storage) whose Holder names the
    execution:
      * updater      -- the install lock ('install', Holder caj-si-updater:<execution>, from its run gate on) or its own row
                        ('updater', from its first moment after the sign-in; every log line beats it);
      * flow         -- the install lock ('install', Holder = the execution name: the runner of a run);
      * housekeeping -- its own row ('housekeeping'), taken by the container entry as its first act, beaten by the clean-up;
                        the upkeep of a full wake-up (the copies the pages show, the clean-up -- after the queue and the
                        update hand-off) beats its own row ('wakeup'): judged as a clean-up, it never holds a wake-up back.
    A DEAD RUNNER's install lock is released in the same step as its stop (Exit-SIExecutionInstallLockOf: only while that
    execution is still its holder), so the next runner takes the queue at once.
    GRACE: an execution that beat before is DEAD 15 minutes after its last beat; one that has NEVER beaten is dead only 30
    minutes after it started (nothing runs before the image pull). An execution with neither a start time nor a beat is never
    judged dead. When the lock rows cannot be read the old rule holds (everything Running counts; nothing is stopped).
    A DEAD execution is STOPPED (ARM executions/<name>/stop), said in one plain WARNING line, and raised to Invardia as the
    alert si.execution.stopped-dead; the queued work goes on in the same wake-up. A stop that fails is a WARNING and the
    execution still holds the work back -- unless it started more than 6 hours ago (the outer fallback): never two runs side
    by side. PURE functions + small seams; PS 5.1 and 7; no PowerShell module.
#>

function Get-SIExecutionLivenessContract {
    <# PURE. The numbers and names of the rule (a function, so every scope that dot-sources this file reads the same). #>
    [pscustomobject]@{
        BeatStaleMinutes      = 15
        NeverBeatGraceMinutes = 30
        FallbackHours         = 6
        AlertId               = 'si.execution.stopped-dead'
        Kinds                 = @('updater', 'flow', 'housekeeping')
        InstallLock           = 'install'
        UpdaterLock           = 'updater'
        HousekeepingLock      = 'housekeeping'
        WakeupLock            = 'wakeup'
        StopApi               = '2024-03-01'
        UpdaterHolderPrefix   = 'caj-si-updater:'
        ActionTextMax         = 500
    }
}

function Get-SIExecLiveField {
    <# PURE. One field of a row (a hashtable, a DataRow-like dictionary or an object); DBNull = $null. #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = $null
    if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $v = $Row[$Name] } }
    elseif ($Row.PSObject.Properties[$Name]) { $v = $Row.$Name }
    if ($v -is [DBNull]) { return $null }
    $v
}

function ConvertTo-SIExecLiveUtc {
    <# PURE. A time (a [datetime] of any kind -- Unspecified is UTC, as SQL datetime2 and ARM give it -- or ISO text) -> UTC, or $null. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [DBNull]) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse($s, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d }
    $null
}

function Get-SIExecutionStartUtc {
    <# PURE. The start of an execution in the ARM shape (name, properties.startTime), or $null. #>
    param($Execution)
    if (-not $Execution) { return $null }
    $p = if ($Execution.PSObject.Properties['properties'] -and $Execution.properties) { $Execution.properties } else { $Execution }
    if (-not $p.PSObject.Properties['startTime']) { return $null }
    ConvertTo-SIExecLiveUtc $p.startTime
}

function Test-SIExecutionRunning {
    <# PURE. Azure says the execution runs: status Running / Processing and no end time. #>
    param($Execution)
    if (-not $Execution) { return $false }
    $p = if ($Execution.PSObject.Properties['properties'] -and $Execution.properties) { $Execution.properties } else { $Execution }
    $st = if ($p.PSObject.Properties['status']) { [string]$p.status } else { '' }
    if ($st -notin @('Running', 'Processing')) { return $false }
    if ($p.PSObject.Properties['endTime'] -and "$($p.endTime)".Trim()) { return $false }
    $true
}

function Test-SIExecutionHolder {
    <# PURE. Does the lock Holder name this execution? '<execution>', 'caj-si-updater:<execution>' or any '<prefix>:<execution>'. #>
    param([string]$Holder, [string]$Name)
    $h = "$Holder".Trim(); $n = "$Name".Trim()
    if (-not $h -or -not $n) { return $false }
    if ($h -ieq $n) { return $true }
    $i = $h.LastIndexOf(':')
    ($i -ge 0 -and $h.Substring($i + 1) -ieq $n)
}

function Get-SIExecutionBeat {
    <# PURE. The freshest beat of the execution -Name on the lock rows -Locks (LockName, Holder, HeartbeatUtc): @{ LastBeatUtc; LockName }, or $null. #>
    param([string]$Name, [object[]]$Locks = @())
    $best = $null
    foreach ($l in @($Locks | Where-Object { $_ })) {
        if (-not (Test-SIExecutionHolder -Holder ([string](Get-SIExecLiveField $l 'Holder')) -Name $Name)) { continue }
        $hb = ConvertTo-SIExecLiveUtc (Get-SIExecLiveField $l 'HeartbeatUtc')
        if (-not $hb) { continue }
        if (-not $best -or $hb -gt $best.LastBeatUtc) { $best = [pscustomobject]@{ LastBeatUtc = $hb; LockName = [string](Get-SIExecLiveField $l 'LockName') } }
    }
    $best
}

function Get-SIExecutionLiveness {
    <#
        PURE. THE RULE for one execution. -Kind: 'updater', or 'flow' (then 'housekeeping' when its beat is on the housekeeping
        lock). Returns @{ Name; Kind; StartedUtc; AgeMin; LastBeatUtc; MinutesSinceBeat; LockName; Alive; PastFallback; Execution }.
    #>
    param([Parameter(Mandatory)]$Execution, [ValidateSet('updater', 'flow', 'housekeeping')][string]$Kind = 'flow', [object[]]$Locks = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $c = Get-SIExecutionLivenessContract
    $now = (ConvertTo-SIExecLiveUtc $NowUtc)
    $name = [string]$Execution.name
    $start = Get-SIExecutionStartUtc $Execution
    $beat = Get-SIExecutionBeat -Name $name -Locks $Locks
    $age = if ($start) { [Math]::Max(0, ($now - $start).TotalMinutes) } else { $null }
    $since = if ($beat) { [Math]::Max(0, ($now - $beat.LastBeatUtc).TotalMinutes) } else { $null }
    $k = $Kind
    if ($k -eq 'flow' -and $beat -and $beat.LockName -in @($c.HousekeepingLock, $c.WakeupLock)) { $k = 'housekeeping' }
    $alive = if ($beat) { $since -lt $c.BeatStaleMinutes } elseif ($null -ne $age) { $age -lt $c.NeverBeatGraceMinutes } else { $true }
    [pscustomobject]@{
        Name = $name; Kind = $k; StartedUtc = $start
        AgeMin = $(if ($null -ne $age) { [int][Math]::Floor($age) } else { $null })
        LastBeatUtc = $(if ($beat) { $beat.LastBeatUtc } else { $null })
        MinutesSinceBeat = $(if ($null -ne $since) { [int][Math]::Floor($since) } else { $null })
        LockName = $(if ($beat) { $beat.LockName } else { '' })
        Alive = [bool]$alive
        PastFallback = [bool]($null -ne $age -and $age -gt ($c.FallbackHours * 60))
        Execution = $Execution
    }
}

function Select-SIExecutionLiveness {
    <#
        PURE. The OTHER running executions of one job, split: @{ Live = @(..); Dead = @(..); Known }. -Self is never judged.
        -LocksKnown $false (the lock rows could not be read): every running one is Live -- the old rule, nothing is stopped.
        -Stopped: names this process stopped already (a stopped execution may still read Running for a moment) -- left out.
    #>
    param([object[]]$Executions = @(), [string]$Self = '', [ValidateSet('updater', 'flow')][string]$Kind = 'flow', [object[]]$Locks = @(),
          [bool]$LocksKnown = $true, [datetime]$NowUtc = [datetime]::UtcNow, [System.Collections.IDictionary]$Stopped)
    $live = New-Object System.Collections.Generic.List[object]; $dead = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Executions | Where-Object { $_ })) {
        if ("$Self".Trim() -and [string]$e.name -eq $Self) { continue }
        if (-not (Test-SIExecutionRunning $e)) { continue }
        if ($Stopped -and $Stopped.Contains([string]$e.name)) { continue }
        $lv = Get-SIExecutionLiveness -Execution $e -Kind $Kind -Locks $(if ($LocksKnown) { $Locks } else { @() }) -NowUtc $NowUtc
        if (-not $LocksKnown) { $lv.Alive = $true }
        if ($lv.Alive) { $live.Add($lv) } else { $dead.Add($lv) }
    }
    [pscustomobject]@{ Live = $live.ToArray(); Dead = $dead.ToArray(); Known = [bool]$LocksKnown }
}

function Select-SIFlowGuardOther {
    <#
        PURE. The flow job's execution guard under the rule: of the OTHER flow executions that started before this one (-Self)
        and still read Running, which are DEAD, and which LIVE one holds this wake-up back. A live clean-up pass (its beat on
        the housekeeping lock) never holds a wake-up back: it gives way to a run by itself (it asks before every range). Without
        readable lock rows (-LocksKnown $false) every running one is live (the old rule). Returns @{ Other (the ARM execution
        that holds it back, the earliest, or $null); Dead = @(); Live = @() }.
    #>
    param([object[]]$Executions = @(), [Parameter(Mandatory)][string]$Self, [object[]]$Locks = @(), [bool]$LocksKnown = $true,
          [datetime]$NowUtc = [datetime]::UtcNow, [System.Collections.IDictionary]$Stopped)
    $mine = @($Executions | Where-Object { $_ -and [string]$_.name -eq $Self })[0]
    $myStart = Get-SIExecutionStartUtc $mine; if (-not $myStart) { $myStart = [datetime]::MaxValue }
    $earlier = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Executions | Where-Object { $_ -and [string]$_.name -ne $Self })) {
        $s = Get-SIExecutionStartUtc $e
        if ((-not $s) -or $s -le $myStart) { $earlier.Add($e) }
    }
    $earlier = $earlier.ToArray()
    $sel = Select-SIExecutionLiveness -Executions $earlier -Self $Self -Kind flow -Locks $Locks -LocksKnown $LocksKnown -NowUtc $NowUtc -Stopped $Stopped
    $hold = @($sel.Live | Where-Object { $_.Kind -ne 'housekeeping' } | Sort-Object { if ($_.StartedUtc) { $_.StartedUtc } else { [datetime]::MinValue } })
    [pscustomobject]@{ Other = $(if ($hold.Count) { $hold[0].Execution } else { $null }); Dead = @($sel.Dead); Live = @($sel.Live) }
}

function Get-SIExecutionKindText {
    <# PURE. What the execution is, in plain words. #>
    param([string]$Kind)
    switch ($Kind) { 'updater' { 'an update of SecurityInsight' } 'housekeeping' { 'a clean-up of old data' } default { 'a pipeline runner' } }
}

function Get-SIExecutionLifeText {
    <# PURE. Its last sign of life, in plain words. #>
    param([Parameter(Mandatory)]$Dead)
    $st = if ($Dead.StartedUtc) { (' (started {0:yyyy-MM-dd HH:mm}Z)' -f ([datetime]$Dead.StartedUtc)) } else { '' }
    $life = if ($Dead.LastBeatUtc) { ('last reported that it was working at {0:yyyy-MM-dd HH:mm}Z, {1} minutes ago' -f ([datetime]$Dead.LastBeatUtc), $Dead.MinutesSinceBeat) }
            else { ('never reported that it was working, {0} minutes after it started' -f $Dead.AgeMin) }
    ('{0}{1} {2}' -f $Dead.Name, $st, $life)
}

function Get-SIExecutionStoppedText {
    <# PURE. The one WARNING line of a stop -- customer language, no internal numbers. #>
    param([Parameter(Mandatory)]$Dead, [bool]$QueuedRunStarted = $true)
    ('{0} showed no sign of life and was stopped: {1} -- {2}' -f (Get-SIExecutionKindText $Dead.Kind), (Get-SIExecutionLifeText $Dead),
        $(if ($QueuedRunStarted) { 'the waiting work goes on now' } else { 'nothing else was held back by it' }))
}

function Get-SIExecutionStopFailedText {
    <# PURE. The WARNING line of a stop that failed. #>
    param([Parameter(Mandatory)]$Dead, [string]$Reason = '')
    ('{0} showed no sign of life but could not be stopped ({1}): {2} -- {3}' -f (Get-SIExecutionKindText $Dead.Kind), $(if ("$Reason".Trim()) { "$Reason".Trim() } else { 'no answer' }), (Get-SIExecutionLifeText $Dead),
        $(if ($Dead.PastFallback) { 'it started more than 6 hours ago, so it is no longer waited for' } else { 'nothing new starts beside it; the next wake-up tries again' }))
}

function New-SIExecutionStoppedEvent {
    <# PURE. The stop as an event: id, execution, kind, ageMin, lastBeatUtc ($null = never beat), lockName, stoppedUtc, queuedRunStarted. #>
    param([Parameter(Mandatory)]$Dead, [Parameter(Mandatory)][datetime]$StoppedUtc, [bool]$QueuedRunStarted)
    $c = Get-SIExecutionLivenessContract
    [pscustomobject]@{
        Id = $c.AlertId; Execution = [string]$Dead.Name; Kind = [string]$Dead.Kind; AgeMin = $Dead.AgeMin
        LastBeatUtc = $Dead.LastBeatUtc; MinutesSinceBeat = $Dead.MinutesSinceBeat; LockName = [string]$Dead.LockName
        StoppedUtc = (ConvertTo-SIExecLiveUtc $StoppedUtc); QueuedRunStarted = [bool]$QueuedRunStarted
    }
}

function ConvertTo-SIExecutionStoppedAlert {
    <#
        PURE. The uplink ALERT record (Invardia's closed shape, Kind 'alert', identified only -- $null for an anonymous
        context): the envelope (Schema 2, Kind, Product, Version, Ring, Edition, ClaimedTenantId, InstallId, LicenceId,
        EnvironmentName -- each only when known) and AlertId si.execution.stopped-dead, Severity warning, Measured { ageMin,
        minutesSinceBeat (left out when it never beat), queuedRunStarted 0 | 1 } (whole numbers), Area execution, Job = the
        kind, ActionText = the execution and the lock in plain words (at most 500), FirstSeenUtc = the stop time, Count 1.
        Nothing else: any other field refuses the whole record.
    #>
    param([Parameter(Mandatory)]$Event, [Parameter(Mandatory)]$Context)
    $c = Get-SIExecutionLivenessContract
    if ([string]$Context.Mode -ne 'identified') { return $null }
    if ($c.Kinds -notcontains [string]$Event.Kind) { return $null }
    $r = [ordered]@{ Schema = 2; Kind = 'alert'; Product = 'securityinsight' }
    $ctxv = { param($n) if ($Context.PSObject.Properties[$n] -and $null -ne $Context.$n -and "$($Context.$n)".Trim() -ne '') { $Context.$n } else { $null } }
    if (& $ctxv 'Version') { $r.Version = [string](& $ctxv 'Version') }
    if ($null -ne (& $ctxv 'Ring')) { $r.Ring = [int](& $ctxv 'Ring') }
    if (& $ctxv 'Edition') { $r.Edition = [string](& $ctxv 'Edition') }
    if (& $ctxv 'TenantId') { $r.ClaimedTenantId = [string](& $ctxv 'TenantId') }
    $lid = & $ctxv 'LastingInstallId'
    if ($lid -and (Get-Command -Name ConvertTo-SIInvardiaInstallId -ErrorAction SilentlyContinue)) { $lid = ConvertTo-SIInvardiaInstallId ([string]$lid) }
    if ($lid) { $r.InstallId = [string]$lid }
    if (& $ctxv 'LicenceId') { $r.LicenceId = [string](& $ctxv 'LicenceId') }
    if (& $ctxv 'EnvironmentName') { $r.EnvironmentName = [string](& $ctxv 'EnvironmentName') }
    $m = [ordered]@{ ageMin = [int]$(if ($null -ne $Event.AgeMin) { $Event.AgeMin } else { 0 }) }
    if ($Event.LastBeatUtc -and $null -ne $Event.MinutesSinceBeat) { $m.minutesSinceBeat = [int]$Event.MinutesSinceBeat }
    $m.queuedRunStarted = $(if ($Event.QueuedRunStarted) { 1 } else { 0 })
    $lockWords = switch ([string]$Event.LockName) {
        'install'      { 'its last beat was on the install lock' }
        'updater'      { 'its last beat was on the update''s own lock' }
        'housekeeping' { 'its last beat was on the clean-up''s own lock' }
        'wakeup'       { 'its last beat was on the wake-up''s own lock' }
        default        { 'it never beat a lock' }
    }
    $at = ('SecurityInsight stopped the {0} execution {1}: Azure still showed it running, but {2}{3} -- {4}.' -f [string]$Event.Kind, [string]$Event.Execution, $lockWords,
        $(if ($Event.LastBeatUtc) { (' ({0:yyyy-MM-dd HH:mm}Z)' -f ([datetime]$Event.LastBeatUtc)) } else { '' }),
        $(if ($Event.QueuedRunStarted) { 'the queued work started' } else { 'nothing else was waiting for it' }))
    $at = ($at -replace '[\x00-\x1F\x7F]', ' ')
    if ($at.Length -gt $c.ActionTextMax) { $at = $at.Substring(0, $c.ActionTextMax) }
    $r.AlertId = $c.AlertId
    $r.Severity = 'warning'
    $r.Measured = [pscustomobject]$m
    $r.FirstSeenUtc = ([datetime]$Event.StoppedUtc).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $r.Count = 1
    $r.Area = 'execution'
    $r.Job = [string]$Event.Kind
    $r.ActionText = $at
    [pscustomobject]$r
}

function Send-SIExecutionStoppedAlert {
    <#
        Raises the alert to Invardia (the uplink, as every SecurityInsight report). NEVER throws. Returns @{ State; Record }:
        sent | failed | off (telemetry switched off) | anonymous (alerts are identified only) | test-session | no-telemetry.
        -Context: a Get-SITelemetryContext result; -Transport { param($Record, $Endpoint, $AccessCode, $TimeoutSec) } (default
        Send-SITelemetryUplink, else Send-AitUplink).
    #>
    param([Parameter(Mandatory)]$Event, $Context, [scriptblock]$Transport, [scriptblock]$Log)
    $res = [ordered]@{ State = 'no-telemetry'; Record = $null }
    try {
        if (-not $Context) {
            if ((Get-Command -Name Test-SITelemetryEnabled -ErrorAction SilentlyContinue) -and -not (Test-SITelemetryEnabled)) { $res.State = 'off'; return [pscustomobject]$res }
            if (-not $Transport -and (Get-Module -Name Pester)) { $res.State = 'test-session'; return [pscustomobject]$res }
            if (-not (Get-Command -Name Get-SITelemetryContext -ErrorAction SilentlyContinue)) { return [pscustomobject]$res }
            $Context = Get-SITelemetryContext
        }
        $rec = ConvertTo-SIExecutionStoppedAlert -Event $Event -Context $Context
        if (-not $rec) { $res.State = 'anonymous'; return [pscustomobject]$res }
        $res.Record = $rec
        if (-not $Transport) {
            if (Get-Command -Name Send-SITelemetryUplink -ErrorAction SilentlyContinue) { $Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) Send-SITelemetryUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec } }
            elseif (Get-Command -Name Send-AitUplink -ErrorAction SilentlyContinue) { $Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) Send-AitUplink -Record $Record -Endpoint $Endpoint -AccessCode $AccessCode -TimeoutSec $TimeoutSec } }
            else { return [pscustomobject]$res }
        }
        $a = & $Transport $rec ([string]$Context.Endpoint) ([string]$Context.AccessCode) 5
        $res.State = if ($a -and [string]$a.Status -eq 'ok') { 'sent' } else { 'failed' }
    } catch { $res.State = 'failed'; if ($Log) { try { & $Log 'INFO' ('the stop could not be reported to Invardia ({0})' -f $_.Exception.Message) } catch { } } }
    [pscustomobject]$res
}

function Invoke-SIExecutionDeadStop {
    <#
        Stops every DEAD execution (-Dead: Select-SIExecutionLiveness .Dead). -Stop { param($Name) } (throws on failure; an
        execution that already ended is not a failure -- Test-SIJobFlowStopAlreadyEnded's words). Each stop: one WARNING line
        (-Log { param($Level, $Message) }), the alert (-Alert { param($Event) }), and the name kept in -Stopped (this process
        never stops or counts it again). -OthersLive: a live execution still holds the work back (then queuedRunStarted = 0).
        Returns @{ Stopped = @(); Failed = @(); Blocking = @() (failed and not past the 6 h fallback: wait); Events = @() }.
        Never throws.
    #>
    param([object[]]$Dead = @(), [Parameter(Mandatory)][scriptblock]$Stop, [scriptblock]$Log, [scriptblock]$Alert, [bool]$OthersLive = $false,
          [System.Collections.IDictionary]$Stopped, [datetime]$NowUtc = [datetime]::UtcNow)
    $ok = New-Object System.Collections.Generic.List[object]; $failed = New-Object System.Collections.Generic.List[object]
    $events = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($Dead | Where-Object { $_ })) {
        try { $null = & $Stop ([string]$d.Name); $ok.Add($d) }
        catch {
            $msg = [string]$_.Exception.Message
            if ($msg -match '(?is)\bexecution\b.{0,300}\bnot\s+found\b|ExecutionNotFound|JobExecutionNotFound') { $ok.Add($d) }
            else { $failed.Add([pscustomobject]@{ Dead = $d; Reason = $msg }) }
        }
    }
    $blocking = @($failed | Where-Object { -not $_.Dead.PastFallback } | ForEach-Object { $_.Dead })
    $goesOn = (-not $OthersLive) -and ($blocking.Count -eq 0)
    foreach ($d in $ok) {
        if ($Stopped) { $Stopped[[string]$d.Name] = $true }
        if ($Log) { try { & $Log 'WARN' (Get-SIExecutionStoppedText -Dead $d -QueuedRunStarted $goesOn) } catch { } }
        $ev = New-SIExecutionStoppedEvent -Dead $d -StoppedUtc $NowUtc -QueuedRunStarted $goesOn
        $events.Add($ev)
        if ($Alert) { try { $null = & $Alert $ev } catch { } }
    }
    foreach ($f in $failed) {
        if ($f.Dead.PastFallback -and $Stopped) { $Stopped[[string]$f.Dead.Name] = $true }
        if ($Log) { try { & $Log 'WARN' (Get-SIExecutionStopFailedText -Dead $f.Dead -Reason $f.Reason) } catch { } }
    }
    [pscustomobject]@{ Stopped = $ok.ToArray(); Failed = $failed.ToArray(); Blocking = $blocking; Events = $events.ToArray() }
}

function Get-SIExecutionStopPath {
    <# PURE. The ARM path that stops one execution of a job (-Base: .../providers/Microsoft.App/jobs). #>
    param([Parameter(Mandatory)][string]$Base, [Parameter(Mandatory)][string]$Job, [Parameter(Mandatory)][string]$Execution)
    ('{0}/{1}/executions/{2}/stop?api-version={3}' -f $Base.TrimEnd('/'), $Job, $Execution, (Get-SIExecutionLivenessContract).StopApi)
}

# =====================================================================================================================
#  THE LOCK ROWS -- read and beat (Pro: cfg.PipelineLock rows over the (sql, params, mode) seam; Community: documents)
# =====================================================================================================================
function Get-SIExecutionLockSql {
    <# PURE. The T-SQL of the lock rows. Read: every row (a row LockId '-' = no lock table). Take / Beat / Release: one NAMED row
       (never 'install' -- that one belongs to the run gate and the runner). #>
    param([Parameter(Mandatory)][ValidateSet('Read', 'Take', 'Beat', 'Release')][string]$Name)
    switch ($Name) {
        'Read' { "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.PipelineLock') IS NULL BEGIN SELECT CAST(N'-' AS nvarchar(32)) AS LockId, CAST(NULL AS nvarchar(128)) AS Holder, CAST(NULL AS datetime2) AS HeartbeatUtc; RETURN; END SELECT LockId, Holder, HeartbeatUtc FROM cfg.PipelineLock WHERE Holder IS NOT NULL;" }
        'Take' { @'
SET NOCOUNT ON; SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.PipelineLock') IS NULL OR @LockId = N'install' BEGIN SELECT CAST(-1 AS int) AS Mine; RETURN; END
BEGIN TRAN;
IF NOT EXISTS (SELECT 1 FROM cfg.PipelineLock WITH (UPDLOCK, HOLDLOCK) WHERE LockId = @LockId) INSERT cfg.PipelineLock (LockId) VALUES (@LockId);
UPDATE cfg.PipelineLock
   SET Holder = @Holder, What = @What, FlowRunId = NULL,
       AcquiredUtc = CASE WHEN Holder = @Holder THEN AcquiredUtc ELSE SYSUTCDATETIME() END, HeartbeatUtc = SYSUTCDATETIME()
 WHERE LockId = @LockId AND (Holder IS NULL OR Holder = @Holder OR HeartbeatUtc IS NULL OR HeartbeatUtc < DATEADD(minute, -@StaleMinutes, SYSUTCDATETIME()));
COMMIT;
SELECT CASE WHEN Holder = @Holder THEN 1 ELSE 0 END AS Mine FROM cfg.PipelineLock WHERE LockId = @LockId;
'@ }
        'Beat' { "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.PipelineLock') IS NULL OR @LockId = N'install' BEGIN SELECT 0 AS Held; RETURN; END UPDATE cfg.PipelineLock SET HeartbeatUtc = SYSUTCDATETIME(), What = @What WHERE LockId = @LockId AND Holder = @Holder; SELECT @@ROWCOUNT AS Held;" }
        'Release' { "IF OBJECT_ID(N'cfg.PipelineLock') IS NOT NULL AND @LockId <> N'install' UPDATE cfg.PipelineLock SET Holder = NULL, What = NULL, FlowRunId = NULL, HeartbeatUtc = NULL WHERE LockId = @LockId AND Holder = @Holder;" }
    }
}

function ConvertTo-SIExecLiveRows {
    <# PURE. The rows a seam answered (one array per reader, arrays of hashtables, DataRows, objects) flattened. #>
    param($Answer)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($x in @($Answer)) {
        if ($null -eq $x) { continue }
        if ($x -is [System.Collections.IDictionary] -or $x -is [System.Data.DataRow] -or $x -is [string] -or $x -is [System.Management.Automation.PSCustomObject]) { $out.Add($x); continue }
        if ($x -is [System.Collections.IEnumerable]) { foreach ($y in $x) { if ($null -ne $y) { $out.Add($y) } }; continue }
        $out.Add($x)
    }
    , $out.ToArray()
}

function New-SIExecutionLockStore {
    <# The lock rows' store: -Invoke (sql, params, mode) for Pro, or -Docs (Read / Write / Delete of a named document) for an
       install without a database -- the same documents the pipeline's lock uses ('pipeline.lock' = the install lock). #>
    param([scriptblock]$Invoke, $Docs, [scriptblock]$Now = { [datetime]::UtcNow })
    if ($Invoke) { return [pscustomobject]@{ Kind = 'sql'; Invoke = $Invoke; Docs = $null; Now = $Now } }
    if ($Docs) { return [pscustomobject]@{ Kind = 'docs'; Invoke = $null; Docs = $Docs; Now = $Now } }
    $null
}

function Get-SIExecLiveDocName {
    param([string]$Lock)
    if ($Lock -eq 'install') { 'pipeline.lock' } else { '{0}.lock' -f $Lock }
}

function Read-SIExecLiveDoc {
    param($Store, [string]$Lock)
    $t = $Store.Docs.Read((Get-SIExecLiveDocName $Lock))
    if (-not "$t".Trim()) { return $null }
    try { $o = ConvertFrom-Json -InputObject ([string]$t) } catch { return $null }
    [pscustomobject]@{ LockName = $Lock; Holder = [string]$o.Holder; HeartbeatUtc = (ConvertTo-SIExecLiveUtc $o.HeartbeatUtc) }
}

function Read-SIExecutionLocks {
    <# The lock rows now: @{ Known; Rows = @( @{ LockName; Holder; HeartbeatUtc } ) }. Known $false = no lock table (old schema). Throws when unreadable. #>
    param([Parameter(Mandatory)]$Store)
    if ($Store.Kind -eq 'sql') {
        $rows = ConvertTo-SIExecLiveRows (& $Store.Invoke (Get-SIExecutionLockSql 'Read') @{} 'reader')
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($r in $rows) {
            $id = [string](Get-SIExecLiveField $r 'LockId')
            if ($id -eq '-') { return [pscustomobject]@{ Known = $false; Rows = @() } }
            $out.Add([pscustomobject]@{ LockName = $id; Holder = [string](Get-SIExecLiveField $r 'Holder'); HeartbeatUtc = (ConvertTo-SIExecLiveUtc (Get-SIExecLiveField $r 'HeartbeatUtc')) })
        }
        return [pscustomobject]@{ Known = $true; Rows = $out.ToArray() }
    }
    $c = Get-SIExecutionLivenessContract
    $docs = @(foreach ($n in @($c.InstallLock, $c.UpdaterLock, $c.HousekeepingLock, $c.WakeupLock)) { Read-SIExecLiveDoc -Store $Store -Lock $n })
    [pscustomobject]@{ Known = $true; Rows = @($docs | Where-Object { $_ -and $_.Holder }) }
}

function Enter-SIExecutionLock {
    <# Takes the NAMED lock -Lock for -Holder (free, stale 15 min, or its own). $true = held. Never throws ($false). #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Lock, [Parameter(Mandatory)][string]$Holder, [string]$What = '')
    if ($Lock -eq 'install' -or -not $Store) { return $false }
    $stale = (Get-SIExecutionLivenessContract).BeatStaleMinutes
    try {
        if ($Store.Kind -eq 'sql') {
            $r = ConvertTo-SIExecLiveRows (& $Store.Invoke (Get-SIExecutionLockSql 'Take') @{ LockId = $Lock; Holder = $Holder; What = $What; StaleMinutes = [int]$stale } 'reader')
            return [bool]($r.Count -and [int](Get-SIExecLiveField $r[0] 'Mine') -eq 1)
        }
        $now = ([datetime](& $Store.Now)).ToUniversalTime()
        $cur = Read-SIExecLiveDoc -Store $Store -Lock $Lock
        $free = (-not $cur) -or (-not $cur.Holder) -or (-not $cur.HeartbeatUtc) -or (($now - $cur.HeartbeatUtc).TotalMinutes -ge $stale) -or ($cur.Holder -eq $Holder)
        if (-not $free) { return $false }
        $Store.Docs.Write((Get-SIExecLiveDocName $Lock), (ConvertTo-Json -Compress -InputObject ([ordered]@{ Holder = $Holder; What = $What; HeartbeatUtc = $now.ToString('o', [Globalization.CultureInfo]::InvariantCulture) })))
        $back = Read-SIExecLiveDoc -Store $Store -Lock $Lock
        return [bool]($back -and $back.Holder -eq $Holder)
    } catch { return $false }
}

function Update-SIExecutionLockBeat {
    <# Beats the NAMED lock while -Holder holds it. $true = beaten. Never throws. #>
    param([Parameter(Mandatory)]$Store, [Parameter(Mandatory)][string]$Lock, [Parameter(Mandatory)][string]$Holder, [string]$What = '')
    if ($Lock -eq 'install' -or -not $Store) { return $false }
    try {
        if ($Store.Kind -eq 'sql') {
            $r = ConvertTo-SIExecLiveRows (& $Store.Invoke (Get-SIExecutionLockSql 'Beat') @{ LockId = $Lock; Holder = $Holder; What = $What } 'reader')
            return [bool]($r.Count -and [int](Get-SIExecLiveField $r[0] 'Held') -gt 0)
        }
        $cur = Read-SIExecLiveDoc -Store $Store -Lock $Lock
        if (-not $cur -or $cur.Holder -ne $Holder) { return $false }
        $now = ([datetime](& $Store.Now)).ToUniversalTime()
        $Store.Docs.Write((Get-SIExecLiveDocName $Lock), (ConvertTo-Json -Compress -InputObject ([ordered]@{ Holder = $Holder; What = $What; HeartbeatUtc = $now.ToString('o', [Globalization.CultureInfo]::InvariantCulture) })))
        return $true
    } catch { return $false }
}

function Exit-SIExecutionLock {
    <# Releases the NAMED lock when -Holder holds it. Never throws. #>
    param($Store, [string]$Lock, [string]$Holder)
    if (-not $Store -or -not $Lock -or -not $Holder -or $Lock -eq 'install') { return }
    try {
        if ($Store.Kind -eq 'sql') { $null = & $Store.Invoke (Get-SIExecutionLockSql 'Release') @{ LockId = $Lock; Holder = $Holder } 'nonquery'; return }
        $cur = Read-SIExecLiveDoc -Store $Store -Lock $Lock
        if ($cur -and $cur.Holder -eq $Holder) { $Store.Docs.Delete((Get-SIExecLiveDocName $Lock)) }
    } catch { }
}

function Get-SIExecutionInstallReleaseSql {
    <# PURE. The T-SQL that frees the INSTALL lock of ONE holder (a dead runner just stopped) -- only while that holder still
       holds it; answers Released (rows). The run gate and the runner keep every other release. #>
    "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.PipelineLock') IS NULL BEGIN SELECT 0 AS Released; RETURN; END UPDATE cfg.PipelineLock SET Holder = NULL, What = NULL, FlowRunId = NULL, HeartbeatUtc = NULL WHERE LockId = N'install' AND Holder = @Holder; SELECT @@ROWCOUNT AS Released;"
}

function Exit-SIExecutionInstallLockOf {
    <#
        Live 2026-11-09/10: a dead runner was stopped, but its install lock stayed taken until its beat was 15 minutes old, and
        the queue row of its finished run stayed 'Running'. The watchdog frees the install lock of the execution it has just
        STOPPED, in the same step -- only while -Holder (that execution's name) still holds it; a lock another runner holds is
        never touched. The next runner then takes the lock at once: it resumes a run that never finished and closes the
        request of one that did (Invoke-SIPipelineDrain). $true = released. Never throws.
    #>
    param($Store, [string]$Holder)
    if (-not $Store -or -not "$Holder".Trim()) { return $false }
    try {
        if ($Store.Kind -eq 'sql') {
            $r = ConvertTo-SIExecLiveRows (& $Store.Invoke (Get-SIExecutionInstallReleaseSql) @{ Holder = [string]$Holder } 'reader')
            return [bool]($r.Count -and [int](Get-SIExecLiveField $r[0] 'Released') -gt 0)
        }
        $cur = Read-SIExecLiveDoc -Store $Store -Lock 'install'
        if ($cur -and (Test-SIExecutionHolder -Holder $cur.Holder -Name $Holder) -and $cur.Holder -eq $Holder) { $Store.Docs.Delete((Get-SIExecLiveDocName 'install')); return $true }
        $false
    } catch { $false }
}

function New-SIExecutionLockBlobDocs {
    <# The document seam over the install's storage (<account>/sistate/flow/<name>) -- the same place as the pipeline's lock. #>
    param([Parameter(Mandatory)][string]$Account, [string]$Container = 'sistate', [string]$Prefix = 'flow/')
    $o = [pscustomobject]@{ Account = $Account; Container = $Container; Prefix = $Prefix }
    $o | Add-Member -MemberType ScriptMethod -Name Read -Value { param($Name) $b = Get-SIBlobContent -Account $this.Account -Container $this.Container -Blob ($this.Prefix + $Name) -AllowMissing; if (-not $b -or $b.Length -eq 0) { $null } else { [Text.Encoding]::UTF8.GetString($b) } }
    $o | Add-Member -MemberType ScriptMethod -Name Write -Value { param($Name, $Text) $null = Set-SIBlobContent -Account $this.Account -Container $this.Container -Blob ($this.Prefix + $Name) -Bytes ([Text.Encoding]::UTF8.GetBytes([string]$Text)) -ContentType 'application/json' }
    $o | Add-Member -MemberType ScriptMethod -Name Delete -Value { param($Name) try { Remove-SIBlob -Account $this.Account -Container $this.Container -Blob ($this.Prefix + $Name) } catch { } }
    $o
}
