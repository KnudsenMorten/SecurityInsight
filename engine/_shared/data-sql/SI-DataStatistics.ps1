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

# =====================================================================================================================
#  #1372 THE TABLES THE DATA SYNC REWROTE, REFRESHED AT ITS END (owner 2026-11-25: "Refresh stats in the run"). Measured at
#  internal (3.1.47, Azure SQL S2, 12:13-12:20Z): right after the data sync rewrote its big tables, the first page reads
#  found their statistics stale and the database refreshed them itself (AUTO_UPDATE_STATISTICS_ASYNC: SummaryGroup 59 s,
#  SummaryGroupCounted 52 s, Finding 51 s, IssueContext 40 s, CiFindingSummary 28 s, ...) -- disk reads at 88-100 %, and the
#  first click on a Remediations page took ~20 s. The refresh after the run (above) comes only after the publish, a later
#  wake-up. So the data sync refreshes, as its LAST step before the views' mark moves the pages to the new rows:
#    * exactly the tables it rewrote -- read from the database's own change counter: every sidata table with a statistic past
#      the database's own threshold (the same rule as sidata.StatisticsRefreshTable), ONE catalog read, largest change first;
#    * each with the database's default sampling (sized by the database for the table: never a full scan) through the same
#      gated procedure, ONE table per call (@Only, procedure v2);
#    * inside a time budget MEASURED from this run: a tenth of the data sync's own time so far, at least a minute (an S2
#      install with a short sync and a 500k-device install with a long one get the same share) -- no new table after it; what
#      is left is refreshed by the refresh after the run, as before. Nothing is ever skipped for good.
#  One timing line. NEVER fails the data sync (a step fails alone): every problem is one WARN line.
# =====================================================================================================================

function Get-SIDataStatisticsRewrittenSql {
    <# ONE read of the catalog (no table data): the sidata tables with a statistic past the database's own stale threshold --
       TableName (quoted), Stats (how many), Changes (the largest change counter), Rows. Largest change first. A statistic of a
       hypothetical index is left out; one never computed counts once its table holds more than 500 rows. #>
@'
SET NOCOUNT ON;
SET LOCK_TIMEOUT 5000;
SELECT QUOTENAME(SCHEMA_NAME(t.schema_id)) + N'.' + QUOTENAME(t.name) AS TableName, COUNT(*) AS Stats,
       MAX(ISNULL(sp.modification_counter, 0)) AS Changes, MAX(ISNULL(sp.rows, tr.N)) AS [Rows]
FROM sys.stats AS s
JOIN sys.tables AS t ON t.object_id = s.object_id AND t.is_ms_shipped = 0 AND t.schema_id = SCHEMA_ID(N'sidata')
LEFT JOIN sys.indexes AS i ON i.object_id = s.object_id AND i.index_id = s.stats_id AND s.auto_created = 0 AND s.user_created = 0
OUTER APPLY sys.dm_db_stats_properties(s.object_id, s.stats_id) AS sp
OUTER APPLY (SELECT SUM(p.rows) AS N FROM sys.partitions AS p WHERE p.object_id = s.object_id AND p.index_id IN (0, 1)) AS tr
WHERE ISNULL(i.is_hypothetical, 0) = 0
  AND (   (sp.last_updated IS NULL AND s.has_filter = 0 AND ISNULL(tr.N, 0) > 500)
       OR (sp.last_updated IS NOT NULL AND ISNULL(sp.modification_counter, 0) >
              CASE WHEN ISNULL(sp.rows, 0) <= 500 THEN 500.0
                   WHEN 500.0 + 0.2 * sp.rows < SQRT(1000.0 * sp.rows) THEN 500.0 + 0.2 * sp.rows
                   ELSE SQRT(1000.0 * sp.rows) END))
GROUP BY t.schema_id, t.name
ORDER BY MAX(ISNULL(sp.modification_counter, 0)) DESC, TableName;
'@
}

function Get-SIDataStatisticsRefreshOneSql {
    <# One call of sidata.StatisticsRefresh for ONE table (@Only). Ready = 0: the procedure is not there, or not v2 yet (no
       @Only parameter) -- nothing done (the refresh after the run covers it). Same row as Get-SIDataStatisticsRefreshSql. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.StatisticsRefresh') IS NULL
   OR NOT EXISTS (SELECT 1 FROM sys.parameters WHERE object_id = OBJECT_ID(N'sidata.StatisticsRefresh') AND name = N'@Only')
BEGIN SELECT CONVERT(bit, 0) AS Ready; RETURN; END
DECLARE @t nvarchar(300), @r int, @f int, @e nvarchar(2000), @a bit;
EXEC sidata.StatisticsRefresh @After = NULL, @AsyncOnly = 0, @Table = @t OUTPUT, @Refreshed = @r OUTPUT, @Failed = @f OUTPUT, @Error = @e OUTPUT, @Async = @a OUTPUT, @Only = @Only;
SELECT CONVERT(bit, 1) AS Ready, @t AS TableName, @r AS Refreshed, @f AS Failed, @e AS Error, @a AS Async;
'@
}

function Get-SIDataStatisticsRewrittenBudget {
    <# PURE. The time budget of the refresh at the data sync's end: -Share of the data sync's own seconds so far (default a
       tenth), at least -FloorSeconds (60). A measurement of this run, never a cap on the work: what the budget does not
       reach is refreshed by the refresh after the run. #>
    param([double]$SyncSeconds = 0, [double]$Share = 0.1, [double]$FloorSeconds = 60)
    [Math]::Round([Math]::Max($FloorSeconds, [Math]::Max(0.0, $SyncSeconds) * $Share), 1)
}

function Invoke-SIDataStatisticsRefreshRewritten {
    <#
        #1372 the statistics of the tables this data sync rewrote, refreshed at its end (see above). NEVER throws. -Invoke:
        the data database seam (sql, params, mode 'rows'); -SyncSeconds: the data sync's own time so far (the budget's
        measure); -BudgetSeconds: the budget given (0 = worked out, Get-SIDataStatisticsRewrittenBudget); -Clock: seconds
        (the tests' clock). Returns @{ Ready; Tables; Names; Refreshed; Failed; FailedError; Left; LeftNames; Budget; Seconds;
        Error; Lines }.
    #>
    param([scriptblock]$Invoke, [double]$SyncSeconds = 0, [double]$BudgetSeconds = 0, [scriptblock]$Log = { param($l, $m) }, [scriptblock]$Clock)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $budget = if ($BudgetSeconds -gt 0) { $BudgetSeconds } else { Get-SIDataStatisticsRewrittenBudget -SyncSeconds $SyncSeconds }
    $res = [pscustomobject]@{ Ready = $false; Tables = 0; Names = @(); Refreshed = 0; Failed = 0; FailedError = ''; Left = 0; LeftNames = @(); Budget = $budget; Seconds = 0.0; Error = ''; Lines = @() }
    if (-not $Invoke) { return $res }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    if (-not $Clock) { $Clock = { $sw.Elapsed.TotalSeconds }.GetNewClosure() }
    $t0 = [double](& $Clock)
    $val = { param($r, $n) $v = $null; if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $v = $r[$n] } } elseif ($null -ne $r -and $r.PSObject.Properties[$n]) { $v = $r.$n }; if ($v -is [System.DBNull]) { $null } else { $v } }
    $bit = { param($x) ($x -eq $true) -or ([string]$x -in @('1', 'True', 'true')) }
    $lines = New-Object System.Collections.Generic.List[object]
    try {
        $todo = @(@(& $Invoke (Get-SIDataStatisticsRewrittenSql) @{} 'rows') | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { [string](& $val $_ 'TableName') } | Where-Object { $_ })
        $res.Ready = $true
        for ($i = 0; $i -lt $todo.Count; $i++) {
            # no new table once the budget is spent: the rest waits for the refresh after the run
            if (([double](& $Clock) - $t0) -ge $budget) { $res.LeftNames = @($todo[$i..($todo.Count - 1)]); break }
            $rows = @(& $Invoke (Get-SIDataStatisticsRefreshOneSql) @{ Only = $todo[$i] } 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            $r = if ($rows.Count) { $rows[0] } else { $null }
            if (-not (& $bit (& $val $r 'Ready'))) { $res.Ready = $false; $res.LeftNames = @($todo[$i..($todo.Count - 1)]); $res.Error = 'the database''s refresh procedure is not updated yet'; break }
            $res.Tables++; $res.Names += $todo[$i]
            $res.Refreshed += [int](& $val $r 'Refreshed')
            $f = [int](& $val $r 'Failed')
            if ($f -gt 0) { $res.Failed += $f; if (-not $res.FailedError) { $res.FailedError = [string](& $val $r 'Error') } }
        }
    } catch {
        $res.Error = [string]$_.Exception.Message
    }
    $res.Left = @($res.LeftNames).Count
    $sw.Stop()
    $res.Seconds = [Math]::Round([Math]::Max(0.0, [double](& $Clock) - $t0), 1)
    $add = { param($l, $t) $lines.Add([pscustomobject]@{ Level = $l; Text = $t }) }
    if ($res.Error -and $res.Tables -eq 0 -and $res.Left -eq 0) {
        & $add 'WARN' ('the statistics of the tables this data sync rewrote were not refreshed ({0}) -- the refresh after the run does it; the data is not affected' -f $res.Error)
    } elseif ($res.Tables -gt 0 -or $res.Left -gt 0) {
        # nothing stale and nothing wrong: nothing said (the step's own timing line says its time)
        $leftText = if ($res.Left -gt 0) { [string]::Format($inv, '; {0} table(s) left to the refresh after the run ({1})', $res.Left, $(if ($res.Error) { $res.Error } else { [string]::Format($inv, 'the {0:0} s budget, a tenth of the data sync, was spent', $budget) })) } else { '' }
        & $add 'INFO' ([string]::Format($inv, 'statistics   : {0} statistic(s) of {1} table(s) this data sync rewrote refreshed in {2:0.0} s (budget {3:0} s){4}', $res.Refreshed, $res.Tables, $res.Seconds, $budget, $leftText))
        if ($res.Failed -gt 0) { & $add 'WARN' ('{0} statistic(s) could not be refreshed ({1}) -- the refresh after the run tries again; the data is not affected' -f $res.Failed, $res.FailedError) }
        if ($res.Error -and $res.Left -eq 0) { & $add 'WARN' ('the statistics refresh stopped part-way ({0}) -- the refresh after the run goes on; the data is not affected' -f $res.Error) }
    }
    $res.Lines = $lines.ToArray()
    foreach ($l in $res.Lines) { try { & $Log $l.Level $l.Text } catch { } }
    $res
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
