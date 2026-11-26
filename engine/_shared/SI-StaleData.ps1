#Requires -Version 5.1
<#
    SecurityInsight -- DATA GETTING OLD (#1396, owner 2026-11-26: "why have nobody found out" / "fix it"). One install had no
    complete pipeline run for eight days and others were 1.5 to 2.5 days behind, and nobody was told: every page showed
    the last complete run as it should, but nothing said that it was getting old.

    The heartbeat job (engine\heartbeat\Invoke-SIHeartbeat.ps1, every 15 minutes) asks Invoke-SIStaleDataCheck on every
    tick. It reads the collection the web app shows -- sidata.vPublishedCollection, the SAME view the pages read (the
    published collection; nothing published yet = the newest complete Detailed collection that is not retired and whose
    views are ready) -- and counts its age from when that collection became COMPLETE (its LoadedAt, which a later
    republish never resets; not its collection time, set near the run's start: a large install's healthy run can take
    more than 12 hours from start to publish). Older than SI_Pro_StaleDataWarnHours (default 36, 0 = off) = ONE guard
    event 'data.published.stale' per UTC day (cause key 'stale|<day>', outcome warning) -- OFF BY DEFAULT (the owner's
    guard rule: only the damage brakes are on by default; a warn-only check is not a guard; pipeline problems are
    telemetry): an install switches it on. Never a mail (the catalog says "mail": "never"). Its detail names the newest
    WHOLE-PIPELINE run (never one job a person ran on its own): its result and first failed step, with the catalogue
    code si-flow-1206 (data-model\errors.locked.json).

    The web app shows the same as a warning on Home (every reader and the wall board) and at the top of every page (Admins):
    pro-management\src\SI.Management.Web\Collection\StaleDataWarning.cs, the same setting, default and age rule -- on by
    itself, whatever this check's switch says. Invardia's fleet alert reads Published{} of the heartbeat -- no new wire key.

    NEVER blocks and never throws: anything it cannot read means no warning this tick, said in the job's log.
    PS 5.1 and 7.
#>

# The check's fixed names, through a function (#1392: a function reads $script: from the script that CALLS it, so state
# set by this file at load time is not there for a caller that loaded it elsewhere).
function Get-SIStaleDataNames {
    [pscustomobject]@{ GuardId = 'data.published.stale'; Setting = 'SI_Pro_StaleDataWarnHours'; DefaultHours = 36; Code = 'si-flow-1206' }
}

function Get-SIStaleDataWarnHours {
    <# PURE. SI_Pro_StaleDataWarnHours as whole hours: 0 = off; not set, not a whole number or below 0 = the default (36). #>
    param([AllowNull()]$Value)
    $d = [int](Get-SIStaleDataNames).DefaultHours
    if ($null -eq $Value) { return $d }
    $s = ([string]$Value).Trim().Trim("'").Trim('"').Trim()
    if (-not $s) { return $d }
    $n = 0
    if ([int]::TryParse($s, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n) -and $n -ge 0) { return $n }
    $d
}

function ConvertTo-SIStaleDataUtc {
    <# PURE. A value from a row (DateTime, ISO text, DBNull, $null) -> a UTC [datetime] or $null. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $null }
    if ($Value -is [datetime]) { return $(if ($Value.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) } else { $Value.ToUniversalTime() }) }
    $t = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$t)) { return $t }
    $null
}

function Get-SIStaleDataShownSql {
    <# The collection the pages show: sidata.vPublishedCollection (the web app's own view -- the same fallback before the
       first publish), its collection time and when it became Complete. A database without the view: no row. #>
@'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.vPublishedCollection') IS NOT NULL
    SELECT TOP (1) pc.CollectionTime, pc.LoadedAt FROM sidata.vPublishedCollection AS pc WHERE pc.Kind = N'Detailed';
'@
}

function Get-SIStaleDataLastRunSql {
    <# The newest WHOLE-PIPELINE run (Scope 'pipeline' or 'from-step' -- Re-run from here; a schema without Scope: every run) and its
       first failed step -- one read of the settings database. #>
@'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.FlowRun') IS NOT NULL AND OBJECT_ID(N'cfg.FlowStepRun') IS NOT NULL
BEGIN
    DECLARE @q nvarchar(max) = N'SELECT TOP (1) r.FlowRunId, r.State, r.StartedUtc, r.EndedUtc, r.HeartbeatUtc, r.StopReason,
       s.Job AS FailedJob, s.State AS FailedState, s.Error AS FailedError
FROM cfg.FlowRun AS r
OUTER APPLY (SELECT TOP (1) x.Job, x.State, x.Error FROM cfg.FlowStepRun AS x
             WHERE x.FlowRunId = r.FlowRunId AND x.State IN (N''Failed'', N''TimedOut'', N''Interrupted'')
               AND (x.ErrorClass IS NULL OR x.ErrorClass <> N''cancelled'') ORDER BY x.StepOrder) AS s
WHERE r.FlowId = N''daily'''
        + CASE WHEN COL_LENGTH(N'cfg.FlowRun', N'Scope') IS NOT NULL THEN N' AND (r.Scope IS NULL OR r.Scope IN (N''pipeline'', N''from-step''))' ELSE N'' END
        + N' ORDER BY r.StartedUtc DESC;';
    EXEC sp_executesql @q;
END
'@
}

function Get-SIStaleDataRowValue {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $v = if ($Row -is [System.Collections.IDictionary]) { $Row[$Name] } elseif ($Row.PSObject.Properties[$Name]) { $Row.$Name } else { $null }
    if ($v -is [System.DBNull]) { $null } else { $v }
}

function Get-SIStaleDataShown {
    <#
        PURE. The rows of Get-SIStaleDataShownSql -> { CollectionUtc; SinceUtc } or $null (nothing shown yet -- a new install
        before its first complete collection: nothing to warn about). SinceUtc = when the collection became Complete; not
        recorded = its collection time.
    #>
    param([AllowNull()][object[]]$Rows)
    $r = @(@($Rows) | Where-Object { $null -ne $_ }) | Select-Object -First 1
    $t = ConvertTo-SIStaleDataUtc (Get-SIStaleDataRowValue $r 'CollectionTime')
    if ($null -eq $t) { return $null }
    $done = ConvertTo-SIStaleDataUtc (Get-SIStaleDataRowValue $r 'LoadedAt')
    [pscustomobject]@{ CollectionUtc = $t; SinceUtc = $(if ($done) { $done } else { $t }) }
}

function ConvertTo-SIStaleDataLastRun {
    <# PURE. The row of Get-SIStaleDataLastRunSql -> { State; StartedUtc; EndedUtc; StopReason; Steps (the failed one) } or $null. #>
    param([AllowNull()][object[]]$Rows)
    $r = @(@($Rows) | Where-Object { $null -ne $_ }) | Select-Object -First 1
    if ($null -eq $r -or -not (Get-SIStaleDataRowValue $r 'FlowRunId')) { return $null }
    $job = [string](Get-SIStaleDataRowValue $r 'FailedJob')
    [pscustomobject]@{
        State = [string](Get-SIStaleDataRowValue $r 'State'); StartedUtc = (ConvertTo-SIStaleDataUtc (Get-SIStaleDataRowValue $r 'StartedUtc'))
        EndedUtc = (ConvertTo-SIStaleDataUtc (Get-SIStaleDataRowValue $r 'EndedUtc')); HeartbeatUtc = (ConvertTo-SIStaleDataUtc (Get-SIStaleDataRowValue $r 'HeartbeatUtc'))
        StopReason = [string](Get-SIStaleDataRowValue $r 'StopReason')
        Steps = @(if ($job) { [pscustomobject]@{ Order = 0; Job = $job; State = [string](Get-SIStaleDataRowValue $r 'FailedState'); Error = [string](Get-SIStaleDataRowValue $r 'FailedError'); ErrorClass = '' } })
    }
}

function Get-SIStaleDataRunText {
    <#
        PURE. The newest run in one plain sentence (the event's detail and the job's log), as the web app says it:
        "A run is in progress (started ...)." / "The last run failed on ... at step x: <its error>." / "The last run was
        stopped on ...: <why>." / "The last run completed on ..., but its data was not published." '' = no run record.
    #>
    param([AllowNull()]$LastRun)
    if ($null -eq $LastRun) { return '' }
    $f = { param($t) if ($t) { ([datetime]$t).ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC' } else { 'an unknown time' } }
    $cut = { param([string]$s) $x = ("$s" -replace '\s+', ' ').Trim(); if ($x.Length -gt 300) { $x = $x.Substring(0, 297) + '...' }; $x.TrimEnd('.') }
    $state = [string]$LastRun.State
    $endT = if ($LastRun.EndedUtc) { $LastRun.EndedUtc } elseif ($LastRun.PSObject.Properties['HeartbeatUtc'] -and $LastRun.HeartbeatUtc) { $LastRun.HeartbeatUtc } else { $LastRun.StartedUtc }
    $on = & $f $endT
    $why = if ("$($LastRun.StopReason)".Trim()) { ': ' + (& $cut $LastRun.StopReason) + '.' } else { '.' }
    if ($state -eq 'Running') { return 'A run is in progress (started {0}).' -f (& $f $LastRun.StartedUtc) }
    if ($state -in @('Cancelled', 'Stopped', 'Interrupted')) { return 'The last run was stopped on {0}{1}' -f $on, $why }
    if ($state -in @('Success', 'Succeeded')) { return 'The last run completed on {0}, but its data was not published.' -f $on }
    $bad = @(@($LastRun.Steps) | Where-Object { $_ -and [string]$_.State -in @('Failed', 'TimedOut', 'Interrupted') -and [string]$_.ErrorClass -ne 'cancelled' } | Sort-Object { [int]$_.Order }) | Select-Object -First 1
    if ($bad) { return 'The last run failed on {0} at step {1}{2}' -f $on, [string]$bad.Job, $(if ("$($bad.Error)".Trim()) { ': ' + (& $cut $bad.Error) + '.' } else { '.' }) }
    if ($state -in @('Failed', 'TimedOut')) { return 'The last run failed on {0}{1}' -f $on, $why }
    'The last run ended on {0}{1}' -f $on, $why
}

function Get-SIStaleDataDecision {
    <#
        PURE. Whether no new data has been published for longer than the limit.
        -ShownUtc: the shown collection's time (the date the warning names); -SinceUtc: when it became Complete (the age
        counts from here; $null = -ShownUtc); -WarnHours: Get-SIStaleDataWarnHours; -LastRun: the newest whole-pipeline run
        (ConvertTo-SIStaleDataLastRun) or $null. $null = no warning (off, nothing shown yet, or not older than the limit --
        exactly AT the limit does not warn yet). Otherwise { ShownUtc; SinceUtc; AgeHours; LimitHours; Day (UTC yyyy-MM-dd);
        CauseKey; RunText; Detail }.
    #>
    param([AllowNull()]$ShownUtc, [AllowNull()]$SinceUtc, [int]$WarnHours, [datetime]$NowUtc, [AllowNull()]$LastRun)
    if ($WarnHours -le 0 -or $null -eq $ShownUtc) { return $null }
    $shown = ConvertTo-SIStaleDataUtc $ShownUtc
    if ($null -eq $shown) { return $null }
    $since = ConvertTo-SIStaleDataUtc $SinceUtc
    if ($null -eq $since) { $since = $shown }
    $now = ConvertTo-SIStaleDataUtc $NowUtc
    $age = ($now - $since).TotalHours
    if ($age -le $WarnHours) { return $null }
    $day = $now.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    $ageText = if ($age -lt 48) { '{0} hours' -f [math]::Floor($age) } else { '{0} days' -f [math]::Floor($age / 24) }
    $runText = Get-SIStaleDataRunText -LastRun $LastRun
    $shownText = $shown.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) + ' UTC'
    $runPart = if ($runText) { ' ' + $runText } else { '' }
    $detail = 'The newest complete data is from {0}. No new data has been published since then ({1}; the limit is {2} hours) -- see Operations > Jobs.{3} ({4})' -f $shownText, $ageText, $WarnHours, $runPart, (Get-SIStaleDataNames).Code
    [pscustomobject]@{ ShownUtc = $shown; SinceUtc = $since; AgeHours = [math]::Round($age, 1); LimitHours = $WarnHours; Day = $day; CauseKey = ('stale|' + $day); RunText = $runText; Detail = $detail }
}

function Invoke-SIStaleDataCheck {
    <#
        The heartbeat's check, every tick. NEVER throws. Returns { Status; Line; Decision; Event }:
          off        SI_Pro_StaleDataWarnHours is 0
          no-data    the shown collection could not be read, or there is none yet
          fresh      not older than the limit
          raised     the day's warning was recorded (Send-SIGuardEvent: 'recorded')
          reported   the day's warning was already recorded earlier today ('already-reported' / 'duplicate')
          guard-off  the check's own switch is off -- the default (the pages still warn)
          error      something went wrong (said in Line)
        -DataInvoke: the data database (sql, params, mode). -RunInvoke: the settings database for the newest run (else
        -Invoke). -Invoke: the Pro database for the guard event (cfg.GuardEvent / cfg.GuardState). -Globals: settings instead
        of the live globals. -ShownRows / -RunRows: the reads' rows (tests). -GuardArgs: more parameters for Send-SIGuardEvent
        (the tests' seams). -Send: { param([hashtable]$Arguments) } instead of Send-SIGuardEvent.
    #>
    param([scriptblock]$DataInvoke, [scriptblock]$RunInvoke, [scriptblock]$Invoke, [System.Collections.IDictionary]$Globals, [datetime]$NowUtc = [datetime]::UtcNow,
          [hashtable]$GuardArgs = @{}, [scriptblock]$Send, [object[]]$ShownRows, [object[]]$RunRows)
    $res = [ordered]@{ Status = 'error'; Line = ''; Decision = $null; Event = $null }
    try {
        $names = Get-SIStaleDataNames
        $raw = if ($Globals -and $Globals.Contains($names.Setting)) { $Globals[$names.Setting] } else { (Get-Variable -Scope Global -Name $names.Setting -ValueOnly -ErrorAction Ignore) }
        $hours = Get-SIStaleDataWarnHours $raw
        if ($hours -le 0) { $res.Status = 'off'; return [pscustomobject]$res }
        $rows = $ShownRows
        if ($null -eq $rows -and $DataInvoke) { $rows = @(& $DataInvoke (Get-SIStaleDataShownSql) @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
        $shown = Get-SIStaleDataShown -Rows $rows
        if ($null -eq $shown) { $res.Status = 'no-data'; return [pscustomobject]$res }
        $d = Get-SIStaleDataDecision -ShownUtc $shown.CollectionUtc -SinceUtc $shown.SinceUtc -WarnHours $hours -NowUtc $NowUtc -LastRun $null
        if ($null -eq $d) { $res.Status = 'fresh'; return [pscustomobject]$res }
        # old: the newest whole-pipeline run is read only now; a read that fails still warns, without it
        $runR = $RunRows
        $ri = if ($RunInvoke) { $RunInvoke } else { $Invoke }
        if ($null -eq $runR -and $ri) { try { $runR = @(& $ri (Get-SIStaleDataLastRunSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) } catch { $runR = $null } }
        $d = Get-SIStaleDataDecision -ShownUtc $shown.CollectionUtc -SinceUtc $shown.SinceUtc -WarnHours $hours -NowUtc $NowUtc -LastRun (ConvertTo-SIStaleDataLastRun -Rows $runR)
        $res.Decision = $d
        $a = @{ GuardId = $names.GuardId; Outcome = 'warning'; Engine = 'heartbeat'; Detail = $d.Detail
                # ONE A DAY: the day is the cause (a cause reported before is not reported again) and the run of this check
                RunId = ('stale-data-' + $d.Day); CauseKeys = @($d.CauseKey); NoMail = $true
                Values = @(@{ Name = 'ageHours'; Label = 'Hours since new data was published'; Measured = $d.AgeHours; Limit = $d.LimitHours; Unit = 'hours' }) }
        if ($Invoke) { $a.Invoke = $Invoke }
        if ($Globals) { $a.Globals = $Globals }
        $a.Now = $NowUtc
        foreach ($k in $GuardArgs.Keys) { $a[$k] = $GuardArgs[$k] }
        if (-not $Send) {
            if (-not (Get-Command -Name Send-SIGuardEvent -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-Guard.ps1')) }
            $Send = { param([hashtable]$Arguments) Send-SIGuardEvent @Arguments }
        }
        $ev = & $Send $a
        $res.Event = $ev
        $st = if ($ev -and $ev.PSObject.Properties['Status']) { [string]$ev.Status } else { '' }
        $res.Status = switch ($st) { 'recorded' { 'raised' } 'already-reported' { 'reported' } 'duplicate' { 'reported' } 'off' { 'guard-off' } default { 'error' } }
        $res.Line = switch ($res.Status) {
            'raised'    { 'data getting old: {0}' -f $d.Detail }
            'reported'  { '' }
            # the switch says itself once (Test-SIGuardOn); a line on every tick would only repeat it
            'guard-off' { '' }
            default     { 'data getting old: the warning could not be recorded ({0})' -f $(if ($ev -and $ev.PSObject.Properties['Reason']) { $ev.Reason } else { 'no answer' }) }
        }
    } catch {
        $res.Status = 'error'; $res.Line = 'data getting old: not checked this time ({0})' -f $_.Exception.Message
    }
    [pscustomobject]$res
}
