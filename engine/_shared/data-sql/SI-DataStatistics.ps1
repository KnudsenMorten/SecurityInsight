#Requires -Version 5.1
<#
    SecurityInsight Pro -- THE DATABASE'S STATISTICS KEPT FRESH BY THE PIPELINE (2026-11-05; owner: "Fix code + refresh now";
    priority: data quality and stability first, speed second).

    WHY. Every pipeline run rewrites the product's tables, and nothing refreshed their statistics: the database updated a
    stale one SYNCHRONOUSLY on the first page read after a run (20+ s of reading for one statistic at the storage limit),
    a page that hit its time limit cancelled that update with it, and the planner planned on statistics weeks old -- the
    pages took one to two minutes.

    WHAT. The pipeline runner (engine\flow\Invoke-SIJobFlowRun.ps1) calls Invoke-SIDataStatisticsRefresh
      * ONCE when a run has ENDED, ONLY AFTER its publish (Invardia, framework owner, 2026-11-05: a refresh before the
        publish took 640 s live at an S2 database and held the pages back -- they move to a run only at the publish). By
        then every step that writes has finished and the published copies (sidata.<Table>Pub) were just refreshed from
        their sources, so the one refresh covers both; it steps aside when an update waits for the run (#1129);
      * -AsyncOnly on every wake-up: the database setting that a page never waits for a statistic -- set where the
        procedure runs as an identity that may change the database (made by setup's admin); already on = one read; where
        it may not (made by the updater) it is left as it is and said nowhere.
    The database's own procedure sidata.StatisticsRefresh (sql\si-data-schema.sql) does the work, ONE TABLE PER CALL, so the
    runner's lock is beaten between tables (-Beat) and the log says the time. A statistic is refreshed only when its changes
    passed the database's own threshold for a stale statistic; with the database's default sampling, never a full scan.
    It changes no row.

    NEVER FAILS THE RUN. Every failure -- the procedure not there yet (a database one schema version behind), a refused
    caller, a statistic that cannot be updated, a lost connection -- is one plain WARNING line and the run goes on: a stale
    statistic makes a page slower, never wrong. PS 5.1 safe; pure except -Invoke (the data database seam: sql, params, mode).
#>

Set-StrictMode -Off

function Get-SIDataStatisticsRefreshSql {
    <# One call of sidata.StatisticsRefresh -- parameters After ('' = the first table), AsyncOnly ('1' / '0'). One row: Ready
       (the procedure is there), TableName (NULL = no table left), Refreshed, Failed, Error, Async. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.StatisticsRefresh') IS NULL BEGIN SELECT CONVERT(bit, 0) AS Ready; RETURN; END
DECLARE @af nvarchar(300) = NULLIF(@After, N''), @ao bit = ISNULL(TRY_CONVERT(bit, @AsyncOnly), 0),
        @t nvarchar(300), @r int, @f int, @e nvarchar(2000), @a bit;
EXEC sidata.StatisticsRefresh @After = @af, @AsyncOnly = @ao, @Table = @t OUTPUT, @Refreshed = @r OUTPUT, @Failed = @f OUTPUT, @Error = @e OUTPUT, @Async = @a OUTPUT;
SELECT CONVERT(bit, 1) AS Ready, @t AS TableName, @r AS Refreshed, @f AS Failed, @e AS Error, @a AS Async;
'@
}

function Get-SIDataStatisticsRecordSql {
    <# #1210 (Invardia SQL-STATS-PROOF): the ONE statement that records a finished refresh pass in the settings database --
       cfg.InstallState 'StatisticsRefresh' (UpdatedAt = when it ended; the heartbeat sends it as Database.statsRefreshedUtc),
       @Value = a short JSON of the pass (<= 400). A database without the table yet: nothing. #>
@'
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'StatisticsRefresh')
        UPDATE cfg.InstallState SET Value = LEFT(@Value, 400), UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'StatisticsRefresh';
    ELSE
        INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'StatisticsRefresh', LEFT(@Value, 400), NULL, @By);
END
'@
}

function Test-SIDataStatisticsPassDone {
    <# PURE. #1210 is -Result a refresh pass that went through every table (not only the setting, not stopped part-way)? Only
       such a pass is recorded as the refresh after the writes; one statistic that failed does not undo the rest. #>
    param($Result)
    [bool]($Result -and $Result.Ready -and -not $Result.AsyncOnly -and -not $Result.Stopped)
}

function Save-SIDataStatisticsRefreshRecord {
    <# #1210 records a finished pass (Test-SIDataStatisticsPassDone) through -Invoke (the SETTINGS database seam: sql, params,
       mode 'nonquery'). NEVER throws: $true = recorded, $false = not a finished pass / no seam / the write failed. #>
    param([scriptblock]$Invoke, $Result, [string]$By = 'caj-si-flow')
    if (-not $Invoke -or -not (Test-SIDataStatisticsPassDone $Result)) { return $false }
    try {
        $v = [string]::Format([Globalization.CultureInfo]::InvariantCulture, '{{"tables":{0},"refreshed":{1},"failed":{2},"seconds":{3:0}}}', [int]$Result.Tables, [int]$Result.Refreshed, [int]$Result.Failed, [double]$Result.Seconds)
        $null = & $Invoke (Get-SIDataStatisticsRecordSql) ([ordered]@{ Value = $v; By = $By }) 'nonquery'
        $true
    } catch { $false }
}

function Get-SIDataStatisticsRefreshText {
    <# PURE. The plain line(s) a refresh says. -Result: Invoke-SIDataStatisticsRefresh's answer; -When: the words for when it
       ran ('at the end of the run, after the pages moved to it'). Rows @{ Level; Text }; none when nothing was stale and nothing went wrong.
       The database setting is never said: only an identity that may change the database sets it (setup's admin) -- an
       install updated by the updater keeps it as it is, and the refresh after every run keeps the statistics fresh there. #>
    param([Parameter(Mandatory)]$Result, [string]$When = '')
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $at = if ($When) { ' ' + $When } else { '' }
    $lines = New-Object System.Collections.Generic.List[object]
    $add = { param($l, $t) $lines.Add([pscustomobject]@{ Level = $l; Text = $t }) }
    if (-not $Result.Ready) {
        if ($Result.Error) { & $add 'WARN' ('the database''s statistics were not refreshed{0} ({1}) -- the pages may be slower until the next run; the data is not affected' -f $at, $Result.Error) }
        return $lines.ToArray()
    }
    if ($Result.Tables -gt 0) { & $add 'INFO' ([string]::Format($inv, 'the database''s statistics refreshed{0}: {1} statistic(s) of {2} table(s) in {3:0} s', $at, $Result.Refreshed, $Result.Tables, $Result.Seconds)) }
    if ($Result.Failed -gt 0) { & $add 'WARN' ('{0} statistic(s) could not be refreshed{1} ({2}) -- the pages may be slower on that table until the next run; the data is not affected' -f $Result.Failed, $at, $Result.FailedError) }
    if ($Result.Stopped) { & $add 'WARN' ('the database''s statistics were refreshed only in part{0} ({1}) -- the next run goes on; the data is not affected' -f $at, $Result.Error) }
    $lines.ToArray()
}

function Invoke-SIDataStatisticsRefresh {
    <#
        The stale statistics of the data database refreshed, table after table (or -AsyncOnly: only the setting). NEVER
        throws. -Invoke: the data database seam (sql, params, mode 'rows'); $null = no database, nothing done. -Beat: called
        between tables (the runner's lock). -When: the words the log line ends its time with.
        Returns @{ Ready; AsyncOnly; Tables; Refreshed; Failed; FailedError; Async; AsyncOff; AsyncError; Error; Stopped; Seconds;
        Lines }. AsyncOff = the database setting is (still) off after the call: kept for the caller, never said (only setup's
        admin may change the database; an install the updater keeps relies on the refresh after every run).
    #>
    param([scriptblock]$Invoke, [switch]$AsyncOnly, [string]$When = '', [scriptblock]$Log = { param($l, $m) }, [scriptblock]$Beat, [double]$ProgressSeconds = 60,
          # #1210: the SETTINGS database seam (sql, params, 'nonquery') -- a pass through every table is recorded there
          # (cfg.InstallState 'StatisticsRefresh', Save-SIDataStatisticsRefreshRecord); $null = not recorded
          [scriptblock]$RecordInvoke)
    $res = [pscustomobject]@{ Ready = $false; AsyncOnly = [bool]$AsyncOnly; Tables = 0; Names = @(); Refreshed = 0; Failed = 0; FailedError = ''; Async = $null; AsyncOff = $false; AsyncError = ''; Error = ''; Stopped = $false; Seconds = 0.0; Lines = @() }
    if (-not $Invoke) { return $res }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $after = ''
    $first = $true
    $saidAt = 0.0
    try {
        while ($true) {
            $rows = @(& $Invoke (Get-SIDataStatisticsRefreshSql) @{ After = $after; AsyncOnly = $(if ($AsyncOnly) { '1' } else { '0' }) } 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            if (-not $rows.Count) { throw 'the database answered no result' }
            $r = $rows[0]
            $val = { param($n) $v = $null; if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $v = $r[$n] } } elseif ($r.PSObject.Properties[$n]) { $v = $r.$n }; if ($v -is [System.DBNull]) { $null } else { $v } }
            $bit = { param($x) ($x -eq $true) -or ([string]$x -in @('1', 'True', 'true')) }
            if (-not (& $bit (& $val 'Ready'))) { break }    # a database one schema version behind: nothing to call yet, nothing said
            $res.Ready = $true
            $err = [string](& $val 'Error')
            if ($first) {
                $first = $false
                $res.Async = & $bit (& $val 'Async')
                if (-not $res.Async) { $res.AsyncOff = $true; $res.AsyncError = 'the setting did not change' }
            }
            if ($AsyncOnly) { break }
            $t = [string](& $val 'TableName')
            if (-not $t) { break }
            $res.Tables++
            $res.Names += $t
            $res.Refreshed += [int](& $val 'Refreshed')
            $f = [int](& $val 'Failed')
            if ($f -gt 0) { $res.Failed += $f; if (-not $res.FailedError) { $res.FailedError = $err } }
            $after = $t
            if ($Beat) { try { $null = & $Beat } catch { } }
            # #1129 (live 2026-11-05: 10.5 minutes of refresh at the end of a run without one line): at most one line a minute
            # while it goes on, so the log shows where the runner is
            if (($sw.Elapsed.TotalSeconds - $saidAt) -ge $ProgressSeconds) {
                $saidAt = $sw.Elapsed.TotalSeconds
                try { & $Log 'INFO' ([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'the database''s statistics{0}: {1} table(s) refreshed so far (the newest {2}), {3:0} s', $(if ($When) { ' ' + $When } else { '' }), $res.Tables, $t, $sw.Elapsed.TotalSeconds)) } catch { }
            }
        }
    } catch {
        $res.Stopped = $true
        $res.Error = [string]$_.Exception.Message
    }
    $sw.Stop()
    $res.Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
    if ($res.Stopped -and -not $res.Ready) {
        $res.Lines = @(Get-SIDataStatisticsRefreshText -Result ([pscustomobject]@{ Ready = $false; Error = $res.Error }) -When $When)
    } else {
        $res.Lines = @(Get-SIDataStatisticsRefreshText -Result $res -When $When)
    }
    # the wake-up's setting check says nothing of its own (every 5 minutes): the refresh at the end of a run says what is wrong
    if ($AsyncOnly) { $res.Lines = @() }
    foreach ($l in @($res.Lines | Where-Object { $null -ne $_ })) { try { & $Log $l.Level $l.Text } catch { } }
    # #1210: a pass through every table is recorded (the heartbeat's Database.statsRefreshedUtc); never fails the run
    if ($RecordInvoke) { $null = Save-SIDataStatisticsRefreshRecord -Invoke $RecordInvoke -Result $res }
    $res
}
