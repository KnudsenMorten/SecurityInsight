#Requires -Version 5.1
<#
    SecurityInsight Pro -- ONE TRUSTED RUN (owner 2026-10-19: "it is a big problem that we have a mix of old and new data,
    so trust is broken to the solution. we need the views to use last know good run, where we can trust it apart all" /
    "and not show some parts from recent run and some from last known good run").

    Every view of the web app reads ONE run per install: the PUBLISHED run (sidata.PublishedRun 'current',
    sql/si-data-schema.sql "ONE TRUSTED RUN"). The pointer moves ONLY here, at the END of a pipeline run, and only when the
    run is trusted:
      * the run (Get-SIDataPublishEligibility, PURE): a run of the WHOLE pipeline (not one stage or one step) that ended
        Succeeded, in which every step that was not switched off succeeded -- the data sync and the verification service
        included. A re-run from a step counts as the whole run it finishes when every step it skipped succeeded in the run
        before it (owner 2026-10-23); its collection is then looked for from that run's start. A run that failed, was stopped, was cancelled, or went on after a failed step
        never publishes: the previous trusted run stays what every view shows.
      * the data (the database's own procedure sidata.PublishedRunSet, one transaction): the run's own Risk Analysis
        collection is complete and not empty, its view data and day totals are written, it is not partial, the run wrote
        the executive view of every Risk Analysis grain it ran, its summary is loaded whole, and it built the merged
        assets. What is not met is answered in plain words and kept as the 'refused' row.
    PARTIAL (a report of the run fell back to an earlier result -- sidata.CollectionPartial / CollectionReportCarry):
    SI_Pro_PublishPartialRun, OFF by default (the owner: no mixing) -- such a run does not publish.
    On an install whose jobs run on their own schedules (no pipeline runs), each wake-up of the pipeline runner publishes
    the newest complete collection newer than the published one (Source 'schedules').
    Never throws and never fails the run: a publish that cannot be made is said, and the views keep the trusted run.
    PS 5.1 safe.
#>

Set-StrictMode -Off

function Test-SIPublishPartialRun {
    <# PURE. The setting SI_Pro_PublishPartialRun: OFF unless it is set to true / 1 / yes / on (then a run in which a report
       fell back to an earlier result is published, marked partial). #>
    param($Value = $global:SI_Pro_PublishPartialRun)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return [bool]$Value }
    ([string]$Value).Trim().Trim('$') -match '^(?i)(true|1|yes|on)$'
}

function Test-SIDataPublishWholeRun {
    <# PURE. A run of the whole pipeline (not one stage, one step or a re-run from a step). #>
    param([Parameter(Mandatory)]$State)
    $scope = if ($State.PSObject.Properties['Scope'] -and $State.Scope) { [string]$State.Scope } else { 'pipeline' }
    ($scope -eq 'pipeline') -and -not ($State.PSObject.Properties['FromStep'] -and [string]$State.FromStep)
}

function Get-SIDataPublishContinuedSteps {
    <#
        PURE. A re-run from a step FINISHES the run before it (owner 2026-10-23: a re-run whose earlier run had every step
        before it succeed is one whole run -- live: the data sync re-run at the largest install succeeded, the web app stayed
        on a collection three days old). -State: the re-run's record; -Previous: the run record that was the last one when the
        re-run was asked for (the run it continues). The steps the re-run skipped ('before-rerun') are taken from that run;
        each must have succeeded there (or be switched off). Only one level: a re-run of a re-run is not continued.
        Returns @{ Ok; Why; Steps (the whole run's steps); StartedUtc (the earlier run's start); ContinuesRunId }.
    #>
    param([Parameter(Mandatory)]$State, $Previous)
    $no = { param($why) [pscustomobject]@{ Ok = $false; Why = ('a re-run from a step is not a whole run ({0})' -f $why); Steps = @(); StartedUtc = $null; ContinuesRunId = '' } }
    if (-not $Previous -or -not [string]$Previous.FlowRunId) { return (& $no 'the run it continues is not known') }
    if ([string]$Previous.FlowRunId -eq [string]$State.FlowRunId) { return (& $no 'the run it continues is not known') }
    $pScope = if ($Previous.PSObject.Properties['Scope'] -and $Previous.Scope) { [string]$Previous.Scope } else { 'pipeline' }
    if ($pScope -ne 'pipeline' -or ($Previous.PSObject.Properties['FromStep'] -and [string]$Previous.FromStep)) { return (& $no 'the run before it was not a run of the whole pipeline') }
    if (-not $Previous.StartedUtc -or -not $Previous.EndedUtc) { return (& $no 'the run before it did not end') }
    if ($State.StartedUtc -and ([datetime]$Previous.StartedUtc).ToUniversalTime() -ge ([datetime]$State.StartedUtc).ToUniversalTime()) { return (& $no 'the run before it started after it') }
    $prevSteps = @{}
    foreach ($p in @($Previous.Steps | Where-Object { $_ })) { $prevSteps[(Get-SIJobFlowKey ([string]$p.Job))] = $p }
    $steps = New-Object System.Collections.ArrayList
    foreach ($s in @($State.Steps | Where-Object { $_ })) {
        if ([string]$s.ErrorClass -ne 'before-rerun') { [void]$steps.Add($s); continue }
        $k = Get-SIJobFlowKey ([string]$s.Job)
        $p = $prevSteps[$k]
        if (-not $p) { return (& $no ('step {0} is not in the run before it' -f $k)) }
        if ([string]$p.State -notin @('Success', 'Disabled')) { return (& $no ('step {0} did not succeed in the run before it ({1})' -f $k, ([string]$p.State).ToLowerInvariant())) }
        [void]$steps.Add($p)
    }
    [pscustomobject]@{ Ok = $true; Why = ''; Steps = @($steps); StartedUtc = $Previous.StartedUtc; ContinuesRunId = [string]$Previous.FlowRunId }
}

function Get-SIDataPublishEligibility {
    <#
        PURE. May this ended pipeline run publish? -State: the run record Invoke-SIJobFlow answered. -Map: Get-SIJobFlowMap.
        -Previous: the last run record when this run was asked for (a re-run from a step continues it).
        Returns @{ Eligible; Why; Grains ('Detailed,Summary' -- the Risk Analysis grains whose step ran); NeedCiBuild;
        StartedUtc (a re-run that continues a run: that run's start -- the window of the run's own collection; else $null);
        ContinuesRunId }.
        Eligible only for a run of the whole pipeline -- or a re-run from a step that finishes the run before it
        (Get-SIDataPublishContinuedSteps) -- that ended Succeeded, with every step Success or switched off (Disabled), and with
        the data sync and the verification service among the steps that succeeded.
    #>
    param([Parameter(Mandatory)]$State, $Map, $Previous)
    $no = { param($why) [pscustomobject]@{ Eligible = $false; Why = $why; Grains = ''; NeedCiBuild = $false; StartedUtc = $null; ContinuesRunId = '' } }
    $scope = if ($State.PSObject.Properties['Scope'] -and $State.Scope) { [string]$State.Scope } else { 'pipeline' }
    if ($scope -ne 'pipeline') { return (& $no ('a run of one {0} is not a whole run' -f $(if ($scope -eq 'from-step') { 'part of the pipeline' } else { $scope }))) }
    if ([string]$State.State -ne 'Succeeded') { return (& $no ('the run ended {0}' -f ([string]$State.State).ToLowerInvariant())) }
    $steps = @($State.Steps | Where-Object { $_ })
    $from = $null; $contId = ''
    if ($State.PSObject.Properties['FromStep'] -and [string]$State.FromStep) {
        $cont = Get-SIDataPublishContinuedSteps -State $State -Previous $Previous
        if (-not $cont.Ok) { return (& $no $cont.Why) }
        $steps = @($cont.Steps); $from = $cont.StartedUtc; $contId = $cont.ContinuesRunId
    }
    $bad = @($steps | Where-Object { [string]$_.State -notin @('Success', 'Disabled') })
    if ($bad.Count) { return (& $no ('step {0} did not succeed ({1})' -f (Get-SIJobFlowKey ([string]$bad[0].Job)), ([string]$bad[0].State).ToLowerInvariant())) }
    $ok = @($steps | Where-Object { [string]$_.State -eq 'Success' } | ForEach-Object { Get-SIJobFlowKey ([string]$_.Job) })
    foreach ($must in 'risk-analysis-detailed', 'asset-datasync', 'verification') {
        if ($ok -notcontains $must) { return (& $no ('step {0} did not run in this run' -f $must)) }
    }
    $grains = @('Detailed')
    if ($ok -contains 'risk-analysis') { $grains += 'Summary' }
    $ci = $false
    # the build of the merged assets: the map's 'assetBuild' step, when it ran in this run (no map = not asked)
    if ($Map -and $Map.Jobs) { foreach ($k in $ok) { if ($Map.Jobs.Contains($k) -and [bool]$Map.Jobs[$k].AssetBuild) { $ci = $true } } }
    [pscustomobject]@{ Eligible = $true; Why = ''; Grains = ($grains -join ','); NeedCiBuild = $ci; StartedUtc = $from; ContinuesRunId = $contId }
}

function Get-SIDataPublishSql {
    <#
        The ONE batch: the database's publisher decides (sidata.PublishedRunSet, created by the schema apply). One code path for
        every publisher: the run, the schedules, the update and a hand publish all go through the procedure.
        #881 THE COPIES ARE NOT REFRESHED IN THIS BATCH any more (live 2026-10-22, the largest tenant: the refresh of every copy
        as one statement per table inside the publishing transaction ran 20+ minutes at the log-rate governor and held the
        pipeline's start). The publisher runs here inside INSERT ... EXEC, so it leaves the copies stale (CopiedAt older than
        the publish); Invoke-SIDataPublishRun then catches them up range by range, the ranges at once, with a progress line
        (Invoke-SIPublishedCopyCatchUp -> Invoke-SIPublishedCopyRefresh), and CopiedAt moves only when every range is done.
        Answers the publisher's row (or one row saying it is not there yet: the update adds it), plus CopiesCaughtUp /
        CopiesNote (always 0 / NULL now: kept for the readers of earlier releases).
    #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID(N'sidata.PublishedRunSet') IS NULL
BEGIN
    SELECT CONVERT(bit, 0) AS Published, N'the database does not have the publisher yet -- the update adds it; the views keep what they show' AS Reason,
           CAST(NULL AS int) AS CollectionId, CAST(NULL AS datetime2(3)) AS CollectionTime, CONVERT(bit, 0) AS [Partial],
           CONVERT(bit, 0) AS CopiesCaughtUp, CAST(NULL AS nvarchar(400)) AS CopiesNote;
    RETURN;
END
-- every value arrives as text ('' = none): typed here, once
DECLARE @rs datetime2(3) = TRY_CONVERT(datetime2(3), NULLIF(@RunStartedUtc, N''), 126),
        @re datetime2(3) = TRY_CONVERT(datetime2(3), NULLIF(@RunEndedUtc, N''), 126),
        @ci bit = CASE WHEN @NeedCiBuild = N'1' THEN 1 ELSE 0 END,
        @ap bit = CASE WHEN @AllowPartial = N'1' THEN 1 ELSE 0 END,
        @keep int = ISNULL(TRY_CONVERT(int, @SnapshotKeepDays), 90),
        @fr nvarchar(64) = NULLIF(@FlowRunId, N''), @sv nvarchar(64) = NULLIF(@SolutionVersion, N'');
DECLARE @res TABLE (Published bit, Reason nvarchar(400), CollectionId int, CollectionTime datetime2(3), [Partial] bit);
-- the decision and the pointer: one call, one transaction (the copies follow, range by range: Invoke-SIDataPublishRun)
INSERT @res EXEC sidata.PublishedRunSet @Source = @Source, @FlowRunId = @fr, @RunStartedUtc = @rs, @RunEndedUtc = @re,
     @SolutionVersion = @sv, @Grains = @Grains, @NeedCiBuild = @ci, @AllowPartial = @ap, @SnapshotKeepDays = @keep,
     @RefuseWhy = @RefuseWhy;
SELECT Published, Reason, CollectionId, CollectionTime, [Partial], CONVERT(bit, 0) AS CopiesCaughtUp, CAST(NULL AS nvarchar(400)) AS CopiesNote FROM @res;
'@
}

$script:SIPublishedCopyTables = @('Ci', 'CiLink', 'CiFinding', 'CiService', 'CiRecord', 'CiFindingState', 'CiRelation', 'Asset', 'AssetIdentifier', 'AssetTag')

function Get-SIPublishedCopyRangeSql {
    <# #881 One key range of one copy (sidata.PublishedCopyRefreshRange): parameters Table, HasFrom, From, Size, HasTo, To.
       One row: Rows (NULL = the copy or its source is not there), Next (the range's upper bound as text), Done. #>
    @'
SET NOCOUNT ON;
DECLARE @n nvarchar(max), @d bit, @r bigint;
EXEC sidata.PublishedCopyRefreshRange @Table = @Table, @HasFrom = @HasFrom, @From = @From, @Size = @Size, @HasTo = @HasTo, @To = @To,
     @Next = @n OUTPUT, @Done = @d OUTPUT, @Rows = @r OUTPUT;
SELECT @r AS [Rows], @n AS [Next], CONVERT(int, @d) AS Done;
'@
}

function Get-SIPublishedCopyBoundsSql {
    <# #881 The next @Count range bounds of one copy after @From, @Size values apart (a read): rows K, in order. #>
    'SET NOCOUNT ON; EXEC sidata.PublishedCopyRefreshRange @Table = @Table, @HasFrom = @HasFrom, @From = @From, @Size = @Size, @Count = @Count;'
}

function Get-SIPublishedCopyFigureSql {
    <# #881 One copy's figures after its refresh (sidata.PublishedCopy: rows written, milliseconds, when). #>
    @'
SET NOCOUNT ON;
MERGE sidata.PublishedCopy AS x
USING (SELECT CONVERT(nvarchar(64), @Table) AS TableName) AS s ON x.TableName = s.TableName
WHEN MATCHED THEN UPDATE SET [Rows] = CONVERT(bigint, @Rows), Milliseconds = CONVERT(int, @Ms), CopiedAt = SYSUTCDATETIME()
WHEN NOT MATCHED THEN INSERT (TableName, [Rows], Milliseconds) VALUES (s.TableName, CONVERT(bigint, @Rows), CONVERT(int, @Ms));
'@
}

function Get-SIPublishedCopyWorkers {
    <# How many ranges run at once: the database's own cores (Get-SIDataFillWorkers when the data sync's code is loaded),
       else the schedulers it sees, else 2 -- a measurement of the database, never a fixed count. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    if (Get-Command -Name Get-SIDataFillWorkers -ErrorAction SilentlyContinue) { return (Get-SIDataFillWorkers -Invoke $Invoke) }
    $n = 0
    foreach ($sql in @('SELECT MAX(cpu_limit) FROM sys.dm_user_db_resource_governance WHERE database_id = DB_ID();', "SELECT COUNT(*) FROM sys.dm_os_schedulers WHERE status = N'VISIBLE ONLINE';")) {
        try { $v = & $Invoke $sql @{} 'scalar'; if ($null -ne $v -and -not ($v -is [System.DBNull])) { $n = [int]$v } } catch { $n = 0 }
        if ($n -ge 1) { break }
    }
    if ($n -lt 1) { 2 } else { $n }
}

function Test-SIPublishedCopyTransientError {
    <# PURE. Is a failed range's error one of Microsoft's TRANSIENT SQL answers, so the same range may simply run again (review
       S4)? -Numbers: the SQL error numbers (SqlException.Errors); -Message: the error's text. Transient: a deadlock victim (1205),
       a client timeout (-2), the Azure SQL "not available / busy / failover / resource" errors (40613, 40501, 40197, 49918, 49919,
       49920), and a connection that was reset or closed under the command. Anything else is not: it fails the refresh. #>
    param([AllowNull()][int[]]$Numbers = @(), [AllowNull()][AllowEmptyString()][string]$Message = '')
    $codes = @(1205, -2, 40613, 40501, 40197, 49918, 49919, 49920, 10053, 10054, 233, 64)
    foreach ($n in @($Numbers)) { if ($codes -contains [int]$n) { return $true } }
    [bool]([string]$Message -match '(?i)deadlocked on lock|deadlock victim|Timeout expired|transport-level error|connection was forcibly closed|forcibly closed by the remote host|connection reset|Connection reset by peer|broken pipe|is not currently available|\b(40613|40501|40197|49918|49919|49920)\b')
}

function Invoke-SIPublishedCopyRangeWave {
    <# #881 One wave: every range of -Ranges AT ONCE, each on its own connection, no command time limit; waits for all. Answers,
       in the order of -Ranges, @{ Failed; Rows ($null = the copy is not there); Ms; Numbers; Message } -- an error is ANSWERED
       (with its SQL error numbers), never thrown, so the caller can tell a transient one from any other. #>
    param([Parameter(Mandatory)]$Info, [Parameter(Mandatory)][object[]]$Ranges)
    $sql = Get-SIPublishedCopyRangeSql
    $work = {
        param([string]$Cs, [string]$Token, [string]$Text, [hashtable]$R)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try {
            $cn = New-Object System.Data.SqlClient.SqlConnection($Cs)
            if ($Token) { $cn.AccessToken = $Token }
            try {
                $cn.Open()
                $c = $cn.CreateCommand(); $c.CommandText = $Text; $c.CommandTimeout = 0
                foreach ($k in 'Table', 'HasFrom', 'From', 'Size', 'HasTo', 'To') { $v = $R[$k]; if ($null -eq $v) { $v = [System.DBNull]::Value }; [void]$c.Parameters.AddWithValue('@' + $k, $v) }
                $rd = $c.ExecuteReader(); $rows = $null
                try { if ($rd.Read()) { $rows = $(if ($rd.IsDBNull(0)) { $null } else { [long]$rd.GetValue(0) }) } } finally { $rd.Close() }
                [pscustomobject]@{ Failed = $false; Rows = $rows; Ms = $sw.ElapsedMilliseconds; Numbers = @(); Message = '' }
            } finally { $cn.Dispose() }
        } catch {
            $nums = New-Object System.Collections.Generic.List[int]
            $e = $_.Exception
            while ($e) { if ($e -is [System.Data.SqlClient.SqlException]) { foreach ($x in $e.Errors) { $nums.Add([int]$x.Number) } }; $e = $e.InnerException }
            [pscustomobject]@{ Failed = $true; Rows = $null; Ms = $sw.ElapsedMilliseconds; Numbers = $nums.ToArray(); Message = [string]$_.Exception.Message }
        }
    }
    $pool = [runspacefactory]::CreateRunspacePool(1, [Math]::Max(1, $Ranges.Count))
    $pool.Open()
    $jobs = New-Object System.Collections.Generic.List[object]
    try {
        foreach ($r in $Ranges) {
            $ps = [powershell]::Create(); $ps.RunspacePool = $pool
            $null = $ps.AddScript($work.ToString()).AddArgument([string]$Info.ConnectionString).AddArgument([string]$Info.AccessToken).AddArgument($sql).AddArgument([hashtable]$r)
            $jobs.Add(@($ps, $ps.BeginInvoke()))
        }
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($j in $jobs) {
            $o = $null
            try {
                $res = @($j[0].EndInvoke($j[1]))
                if ($res.Count) { $o = $res[-1] }
                elseif ($j[0].Streams.Error.Count -gt 0) { $o = [pscustomobject]@{ Failed = $true; Rows = $null; Ms = 0L; Numbers = @(); Message = [string]$j[0].Streams.Error[0].Exception.Message } }
            } catch { $o = [pscustomobject]@{ Failed = $true; Rows = $null; Ms = 0L; Numbers = @(); Message = [string]$_.Exception.Message } }
            if ($null -eq $o) { $o = [pscustomobject]@{ Failed = $true; Rows = $null; Ms = 0L; Numbers = @(); Message = 'the range answered nothing' } }
            $out.Add($o)
        }
        , $out.ToArray()
    } finally {
        foreach ($j in $jobs) { try { $j[0].Dispose() } catch { } }
        $pool.Close(); $pool.Dispose()
    }
}

function Invoke-SIPublishedCopyRangesParallel {
    <#
        #881 Runs Get-SIPublishedCopyRangeSql for every range of -Ranges (@{ Table; HasFrom; From; Size; HasTo; To }) AT ONCE,
        each on its own connection (-ConnectionInfo: the seam's SIConnectionInfo), with no command time limit; waits for all.
        Answers @{ Rows ($null = the copy is not there); Ms } per range, in the order of -Ranges. The same shape as
        Invoke-SIDataParallelRanges (SI-DataViewContext.ps1), whose ranges are numbers -- these are key values as text.
        Review S4: a range that fails with one of Microsoft's TRANSIENT SQL answers (Test-SIPublishedCopyTransientError: a
        deadlock, a timeout, Azure SQL busy / failover, a reset connection) runs again, after a growing pause (2, 4, 8 ... s,
        at most a minute), up to -TransientRetries times -- a bound on Microsoft's errors, never on SI's own work. A range is
        IDEMPOTENT (sidata.PublishedCopyRefreshRange makes its rows equal to the source's, in its own transaction): a repeat
        writes the same rows. Any other error -- or a transient one past its retries -- is thrown after every range has ended,
        as before (the copies stay stale, the next refresh does it again). -Wave / -Sleep / -Log are seams.
    #>
    param([Parameter(Mandatory)][scriptblock]$ConnectionInfo, [Parameter(Mandatory)][object[]]$Ranges,
          [scriptblock]$Wave = { param($info, $ranges) Invoke-SIPublishedCopyRangeWave -Info $info -Ranges $ranges },
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Log = { param($l, $m) },
          [int]$TransientRetries = 5)
    if ($Ranges.Count -eq 0) { return , @() }
    $results = New-Object object[] $Ranges.Count
    $pending = @(0..($Ranges.Count - 1))
    $attempt = 0
    while ($pending.Count) {
        $info = & $ConnectionInfo   # asked again for every attempt: a fresh token after a long pause
        # assigned first, then @(): a wave answers `, $array` -- @(& $Wave ...) would wrap that array as ONE element
        $outs = & $Wave $info @($pending | ForEach-Object { $Ranges[$_] }); $outs = @($outs)
        $again = New-Object System.Collections.Generic.List[int]; $err = $null
        for ($i = 0; $i -lt $pending.Count; $i++) {
            $idx = $pending[$i]; $o = $(if ($i -lt $outs.Count) { $outs[$i] } else { $null })
            if ($null -eq $o) { $o = [pscustomobject]@{ Failed = $true; Rows = $null; Ms = 0L; Numbers = @(); Message = 'the range answered nothing' } }
            if (-not [bool]$o.Failed) { $results[$idx] = [pscustomobject]@{ Rows = $o.Rows; Ms = [long]$o.Ms }; continue }
            $transient = Test-SIPublishedCopyTransientError -Numbers @($o.Numbers) -Message ([string]$o.Message)
            if ($transient -and $attempt -lt $TransientRetries) { $again.Add($idx); continue }
            if ($null -eq $err) {
                $r = $Ranges[$idx]
                $err = ("published copies: {0}Pub, the range after '{1}': {2}{3}" -f $r.Table, $(if ([int]$r.HasFrom -eq 1) { [string]$r.From } else { '(the start)' }), [string]$o.Message,
                        $(if ($transient) { (' (a transient SQL error, still there after {0} retries)' -f $attempt) } else { '' }))
            }
        }
        if ($err) { throw $err }
        if ($again.Count) {
            $attempt++
            $pause = [int][Math]::Min(60, [Math]::Pow(2, $attempt))
            & $Log 'WARN' ("published copies: {0} range(s) of {1}Pub met a transient SQL error (a deadlock, a timeout or Azure SQL busy) -- run again in {2} s (retry {3} of {4})" -f $again.Count, $Ranges[$again[0]].Table, $pause, $attempt, $TransientRetries)
            & $Sleep $pause
        }
        $pending = $again.ToArray()
    }
    , $results
}

function Invoke-SIPublishedCopyRefresh {
    <#
        #881 THE PUBLISHED COPIES MADE EQUAL TO THEIR SOURCES, RANGE BY RANGE (the engine's driver: the pipeline runner and the
        update reach it through Invoke-SIPublishedCopyCatchUp). For each of the ten copies the key ranges of a wave run AT ONCE,
        each its own short transaction on its own connection -- as many as the database has cores (Get-SIPublishedCopyWorkers),
        one fewer each time the database is saturated (SI-SqlPacing.ps1) and one more again when it is not; the range size
        follows the measured time of the wave before (Get-SIDataNextSize; -FirstSize is only where it starts). A seam without
        a connection to hand out (a test's fake) runs the ranges one after another. ONE REFRESHER at a time: the session lock
        si-published-copy-refresh on a connection of its own for the whole refresh (another one running = Held, nothing
        done). A progress line every -ProgressSeconds and one line per copy that changed. No time limit.
        Returns @{ Ok (every copy refreshed); Held; Tables; Rows; Ranges; Seconds; Missing (copies not there) }. Throws on a
        failure (the caller says it): the copies stay stale, CopiedAt is not moved, the next catch-up refreshes.
        -Beat (2026-10-24): called while the refresh makes progress -- when it starts and then at most every -BeatSeconds,
        after a range or a wave has ended -- so the pipeline runner can keep ITS lock alive while the run's copy is written
        (a 15-50 minute copy outlived the lock's 15 minutes and the next wake-up could start a run beside it). Only progress
        beats: a refresh that hangs or dies stops beating, and the lock lapses as before. A beat that fails never stops it.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log = { param($l, $m) }, [int]$Workers = 0, [long]$FirstSize = 10000,
          [long]$TargetMs = 2000, [double]$ProgressSeconds = 60, [scriptblock]$Beat, [double]$BeatSeconds = 60)
    $res = [pscustomobject]@{ Ok = $false; Held = $false; Tables = 0; Rows = 0L; Ranges = 0L; Seconds = 0.0; Missing = @() }
    $ci = $null; if ($Invoke.PSObject.Properties['SIConnectionInfo'] -and $Invoke.SIConnectionInfo) { $ci = $Invoke.SIConnectionInfo }
    $maxWorkers = 1
    if ($ci -and $Workers -ne 1) { $maxWorkers = $(if ($Workers -gt 1) { $Workers } else { Get-SIPublishedCopyWorkers -Invoke $Invoke }) }
    $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue)
    $tgt = $TargetMs
    $nextSize = {
        param([long]$cur, [long]$ms)
        if (Get-Command -Name Get-SIDataNextSize -ErrorAction SilentlyContinue) { return (Get-SIDataNextSize -Current $cur -ElapsedMs $ms -TargetMs $tgt -Minimum 1) }
        $limit = [Math]::Min([double]([long]::MaxValue / 2), 2.0 * $cur)
        $w = if ($ms -le 0) { $limit } else { [Math]::Min($limit, [Math]::Floor([double]$cur * $tgt / $ms)) }
        [long][Math]::Max(1, $w)
    }
    $val = { param($row, $n) if ($null -eq $row) { $null } elseif ($row -is [System.Collections.IDictionary]) { $v = $row[$n]; if ($v -is [System.DBNull]) { $null } else { $v } } else { $v = $row.$n; if ($v -is [System.DBNull]) { $null } else { $v } } }
    $lockCn = $null
    $clock = [Diagnostics.Stopwatch]::StartNew(); $said = [double]0
    $beatState = @{ At = [double]::NegativeInfinity }
    $beatNow = { if ($Beat -and ($clock.Elapsed.TotalSeconds - $beatState.At) -ge $BeatSeconds) { $beatState.At = $clock.Elapsed.TotalSeconds; try { $null = & $Beat } catch { } } }
    try {
        if ($ci) {
            # one refresher at a time: the session lock, on a connection held for the whole refresh
            $info = & $ci
            $lockCn = New-Object System.Data.SqlClient.SqlConnection([string]$info.ConnectionString)
            if ($info.AccessToken) { $lockCn.AccessToken = [string]$info.AccessToken }
            $lockCn.Open()
            $lc = $lockCn.CreateCommand(); $lc.CommandTimeout = 0
            $lc.CommandText = "DECLARE @l int; EXEC @l = sp_getapplock @Resource = N'si-published-copy-refresh', @LockMode = N'Exclusive', @LockOwner = N'Session', @LockTimeout = 0; SELECT @l;"
            if ([int]$lc.ExecuteScalar() -lt 0) { $res.Held = $true; return $res }
        }
        & $beatNow
        if ($maxWorkers -gt 1) { & $Log 'INFO' ("published copies: the merged assets' copies are refreshed {0} range(s) at a time (the database's cores)" -f $maxWorkers) }
        $missing = New-Object System.Collections.Generic.List[string]
        foreach ($t in $script:SIPublishedCopyTables) {
            $tw = [Diagnostics.Stopwatch]::StartNew(); $rows = 0L; $ranges = 0L; $size = [Math]::Max(1L, $FirstSize); $workersNow = $maxWorkers; $lastMs = 0L
            $hasFrom = 0; $from = $null; $done = $false; $gone = $false
            while (-not $done) {
                if ($paced) {
                    $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs -Log $Log
                    if ($pace.Shrink) { $size = [Math]::Max(1L, [long][Math]::Floor($size / 2)); $workersNow = [Math]::Max(1, $workersNow - 1) }
                    elseif ($workersNow -lt $maxWorkers -and [string]$pace.State -eq 'normal') { $workersNow++ }
                }
                $sz = [int][Math]::Min([double][int]::MaxValue, [double]$size)
                $sw = [Diagnostics.Stopwatch]::StartNew(); $ms = 0L
                if ($workersNow -le 1) {
                    # one range: its upper bound worked out by the procedure (the @Size-th value after the last one)
                    $row = @(& $Invoke (Get-SIPublishedCopyRangeSql) @{ Table = $t; HasFrom = $hasFrom; From = $from; Size = $sz; HasTo = 0; To = $null } 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | Select-Object -First 1
                    $n = & $val $row 'Rows'
                    if ($null -eq $n) { $gone = $true; break }
                    $rows += [long]$n; $ranges++
                    $next = & $val $row 'Next'
                    $done = ([int](& $val $row 'Done')) -eq 1 -or $null -eq $next
                    $from = $next; $hasFrom = 1
                    $ms = $sw.ElapsedMilliseconds
                } else {
                    # a wave: the next bounds first (a read), then every range of the wave at once. Fewer bounds than ranges
                    # wanted = the column ends inside this wave: its last range is open upwards (worked out by the procedure)
                    $bounds = @(@(& $Invoke (Get-SIPublishedCopyBoundsSql) @{ Table = $t; HasFrom = $hasFrom; From = $from; Size = $sz; Count = $workersNow } 'rows') | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { [string](& $val $_ 'K') })
                    $wave = New-Object System.Collections.Generic.List[object]
                    $pf = $hasFrom; $pv = $from
                    foreach ($k in $bounds) { $wave.Add(@{ Table = $t; HasFrom = $pf; From = $pv; Size = $sz; HasTo = 1; To = $k }); $pf = 1; $pv = $k }
                    # (the open range is asked for every row that is left: its own TOP takes them all, so nothing past it is left out)
                    if ($bounds.Count -lt $workersNow) { $wave.Add(@{ Table = $t; HasFrom = $pf; From = $pv; Size = [int]::MaxValue; HasTo = 0; To = $null }); $done = $true }
                    foreach ($r in (Invoke-SIPublishedCopyRangesParallel -ConnectionInfo $ci -Ranges $wave.ToArray() -Log $Log)) {
                        if ($null -eq $r.Rows) { $gone = $true } else { $rows += [long]$r.Rows }
                        if ([long]$r.Ms -gt $ms) { $ms = [long]$r.Ms }
                    }
                    if ($gone) { break }
                    $ranges += $wave.Count; $hasFrom = $pf; $from = $pv
                }
                $lastMs = $ms
                # a range / a wave has ended: progress -- the caller's lock is kept alive
                & $beatNow
                $size = & $nextSize $size $ms
                $now = $clock.Elapsed.TotalSeconds
                if (-not $done -and ($now - $said) -ge $ProgressSeconds) {
                    $said = $now
                    & $Log 'INFO' ("published copies: {0}Pub -- {1:N0} range(s), {2:N0} row(s) written so far" -f $t, $ranges, $rows)
                }
            }
            if ($gone) { $missing.Add($t); continue }
            $null = & $Invoke (Get-SIPublishedCopyFigureSql) @{ Table = $t; Rows = [string]$rows; Ms = [string][Math]::Min([long][int]::MaxValue, $tw.ElapsedMilliseconds) } 'nonquery'
            $res.Tables++; $res.Rows += $rows; $res.Ranges += $ranges
            if ($rows -gt 0 -or $tw.Elapsed.TotalSeconds -ge $ProgressSeconds) {
                & $Log 'INFO' ("published copies: {0}Pub -- {1:N0} row(s) written in {2:N0} range(s), {3:N0} s" -f $t, $rows, $ranges, $tw.Elapsed.TotalSeconds)
            }
        }
        $res.Missing = $missing.ToArray()
        $res.Ok = ($res.Tables -eq $script:SIPublishedCopyTables.Count)
        $res.Seconds = [Math]::Round($clock.Elapsed.TotalSeconds, 1)
        $res
    } finally {
        if ($lockCn) {
            try { $lc = $lockCn.CreateCommand(); $lc.CommandText = "EXEC sp_releaseapplock @Resource = N'si-published-copy-refresh', @LockOwner = N'Session';"; [void]$lc.ExecuteNonQuery() } catch { }
            $lockCn.Dispose()
        }
    }
}

function Get-SIPublishedCopyCatchUpSql {
    <# The catch-up of the shown run's copies (sidata.PublishedCopyCatchUp), one row: Ready (the procedure is there), Stale,
       Refreshed, PublishedAt, CopiedAt, Ranged (#881: the copies can be refreshed range by range by the engine's driver --
       sidata.PublishedCopyRefreshRange is there), Now (the database's time, ISO text). @WhatIf = '1': only whether they are
       stale. @MarkFor (ISO text, '' = none): the engine refreshed the copies itself, range by range, for the publish of that
       PublishedAt -- only the claim (CopiedAt) is made, and only while that is still the publish shown. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.PublishedRun') IS NULL
   OR NOT EXISTS (SELECT 1 FROM sys.parameters WHERE object_id = OBJECT_ID(N'sidata.PublishedCopyCatchUp') AND name = N'@Refreshed')
BEGIN
    SELECT CONVERT(bit, 0) AS Ready, CONVERT(bit, 0) AS Stale, CONVERT(bit, 0) AS Refreshed, CAST(NULL AS datetime2(0)) AS PublishedAt, CAST(NULL AS datetime2(0)) AS CopiedAt,
           CONVERT(bit, 0) AS Ranged, CAST(NULL AS nvarchar(30)) AS Now;
    RETURN;
END
DECLARE @s bit, @r bit, @p datetime2(0), @c datetime2(0), @w bit = CASE WHEN @WhatIf = N'1' THEN 1 ELSE 0 END,
        @m datetime2(0) = TRY_CONVERT(datetime2(0), NULLIF(@MarkFor, N''), 126), @now nvarchar(30) = CONVERT(nvarchar(30), SYSUTCDATETIME(), 126),
        @ranged bit = CASE WHEN OBJECT_ID(N'sidata.PublishedCopyRefreshRange') IS NOT NULL
                            AND EXISTS (SELECT 1 FROM sys.parameters WHERE object_id = OBJECT_ID(N'sidata.PublishedCopyCatchUp') AND name = N'@MarkFor') THEN 1 ELSE 0 END;
IF @m IS NOT NULL AND @ranged = 1
    EXEC sidata.PublishedCopyCatchUp @Stale = @s OUTPUT, @Refreshed = @r OUTPUT, @PublishedAt = @p OUTPUT, @CopiedAt = @c OUTPUT, @MarkFor = @m;
ELSE
    EXEC sidata.PublishedCopyCatchUp @WhatIf = @w, @Stale = @s OUTPUT, @Refreshed = @r OUTPUT, @PublishedAt = @p OUTPUT, @CopiedAt = @c OUTPUT;
SELECT CONVERT(bit, 1) AS Ready, ISNULL(@s, 0) AS Stale, ISNULL(@r, 0) AS Refreshed, @p AS PublishedAt, @c AS CopiedAt, @ranged AS Ranged, @now AS Now;
'@
}

function Get-SIPublishedCopyCatchUpText {
    <# PURE. The one plain line about the shown run's copies, or '' when there is nothing to say. -Result: Invoke-SIPublishedCopyCatchUp's.
       -AfterPublish (#881: every publish leaves the copies to be caught up right after it): a refresh is the normal course,
       said as how much it wrote -- never as a warning. #>
    param([Parameter(Mandatory)]$Result, [switch]$AfterPublish)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $fmt = { param($d) if ($null -eq $d) { 'never' } else { [string]::Format($inv, '{0:yyyy-MM-dd HH:mm} UTC', ([datetime]$d)) } }
    $how = ''
    if ($Result.PSObject.Properties['Refresh'] -and $Result.Refresh) { $how = [string]::Format($inv, ' ({0:N0} row(s) written in {1:N0} range(s), {2:N0} s)', $Result.Refresh.Rows, $Result.Refresh.Ranges, $Result.Refresh.Seconds) }
    if ($AfterPublish) {
        switch ([string]$Result.Action) {
            'refreshed' { return ('the merged assets'' pages (CIs and assets) now show the published run{0}' -f $how) }
            'current'   { return '' }
        }
    }
    $what = 'the merged assets'' pages (CIs and assets) showed a copy older than the run the web app shows (run published {0}, copy {1})' -f (& $fmt $Result.PublishedAt), (& $fmt $Result.CopiedAt)
    switch ([string]$Result.Action) {
        'refreshed'     { return ('{0} -- refreshed now{1}; every page shows the same run again' -f $what, $how) }
        'would-refresh' { return ('{0} -- the update would refresh it now' -f $what) }
        'held'          { return ('{0} -- not refreshed this time ({1}); the next wake-up tries again' -f $what, $(if ($Result.Reason) { $Result.Reason } else { 'another publish or refresh was running, or a copy is missing' })) }
        'failed'        { return ('the copies of the merged assets could not be checked or refreshed ({0}) -- the next wake-up tries again' -f $Result.Reason) }
    }
    ''
}

function Invoke-SIPublishedCopyCatchUp {
    <#
        The shown run's copies caught up when they are older than it (CopiedAt NULL or older than the publish). NEVER throws.
        Used by the pipeline runner after every publish attempt and on every wake-up (Invoke-SIDataPublishRun) and by the update
        (setup\Invoke-SIContainerUpdate.ps1 step 9g). -Invoke: the data database seam (sql, params, mode 'rows'); -WhatIf: only
        whether they are stale.
        #881 RANGE BY RANGE: on a database that has sidata.PublishedCopyRefreshRange the engine refreshes the copies itself
        (Invoke-SIPublishedCopyRefresh: the ranges at once, each its own short transaction, a progress line), and only when
        every range of every copy is done does it claim them (CopiedAt, for the publish it was for). An older
        database: the procedure as before. -AfterPublish: this run just published -- the refresh is said as INFO, not as a
        stale copy.
        Returns @{ Action ('not-yet' | 'current' | 'refreshed' | 'would-refresh' | 'held' | 'failed'); Stale; PublishedAt;
        CopiedAt; Reason; Lines; Refresh }. Said: one line when they were stale or could not be checked (a data-health
        warning; warn only, never a block), nothing when they are current.
    #>
    param([scriptblock]$Invoke, [switch]$WhatIf, [switch]$AfterPublish, [scriptblock]$Log = { param($l, $m) }, [scriptblock]$Beat)
    $res = [pscustomobject]@{ Action = 'not-yet'; Stale = $false; PublishedAt = $null; CopiedAt = $null; Reason = ''; Lines = @(); Refresh = $null }
    $bit = { param($x) ($x -eq $true) -or ([string]$x -in @('1', 'True', 'true')) }
    $ask = {
        param([string]$w, [string]$mark)
        $rows = @(& $Invoke (Get-SIPublishedCopyCatchUpSql) @{ WhatIf = $w; MarkFor = $mark } 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        if (-not $rows.Count) { throw 'the database answered no result' }
        $r = $rows[0]
        $val = { param($n) $v = $null; if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $v = $r[$n] } } elseif ($r.PSObject.Properties[$n]) { $v = $r.$n }; if ($v -is [System.DBNull]) { $null } else { $v } }
        [pscustomobject]@{ Ready = (& $bit (& $val 'Ready')); Stale = (& $bit (& $val 'Stale')); Refreshed = (& $bit (& $val 'Refreshed'))
                           PublishedAt = (& $val 'PublishedAt'); CopiedAt = (& $val 'CopiedAt'); Ranged = (& $bit (& $val 'Ranged')); Now = [string](& $val 'Now') }
    }
    try {
        if (-not $Invoke) { return $res }
        # first only ask (a database that refreshes range by range is refreshed by the engine itself, below)
        $a = & $ask '1' ''
        if (-not $a.Ready) { return $res }
        $res.PublishedAt = $a.PublishedAt; $res.CopiedAt = $a.CopiedAt
        if (-not $a.Stale) { $res.Action = 'current' }
        elseif ($WhatIf) { $res.Stale = $true; $res.Action = 'would-refresh' }
        elseif ($a.Ranged -and $null -ne $a.PublishedAt -and $Invoke.PSObject.Properties['SIConnectionInfo'] -and $Invoke.SIConnectionInfo) {
            # review S3: the engine's range driver ONLY on a seam that can hand out connections -- it then takes the refresher
            # lock si-published-copy-refresh for the whole refresh. A seam without one (the update's) never refreshes unlocked:
            # it goes to the database's procedure below, which takes the same lock itself (another refresher = nothing done).
            $res.Refresh = Invoke-SIPublishedCopyRefresh -Invoke $Invoke -Log $Log -Beat $Beat
            if ($res.Refresh.Held) { $res.Stale = $true; $res.Action = 'held'; $res.Reason = 'another refresh of the copies was running' }
            elseif (-not $res.Refresh.Ok) { $res.Stale = $true; $res.Action = 'held'; $res.Reason = ('a copy is not there: {0}' -f (@($res.Refresh.Missing) -join ', ')) }
            else {
                # every range of every copy is done: claimed for the publish it was for (PublishedAt as asked before it began)
                $m = & $ask '0' ([datetime]$a.PublishedAt).ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
                if ($m.Refreshed) { $res.Action = 'refreshed' }
                else { $res.Stale = $true; $res.Action = 'held'; $res.Reason = 'a newer publish came while the copies were refreshed' }
            }
        } else {
            # an older database, or a seam without connections: the procedure refreshes (under the refresher lock) and claims them itself
            $o = & $ask '0' ''
            $res.Stale = $o.Stale -and -not $o.Refreshed
            $res.Action = if ($o.Refreshed) { 'refreshed' } elseif (-not $o.Stale) { 'current' } else { 'held' }
        }
    } catch {
        $res.Action = 'failed'; $res.Reason = $_.Exception.Message
    }
    $line = Get-SIPublishedCopyCatchUpText -Result $res -AfterPublish:$AfterPublish
    if ($line) { $res.Lines = @($line); & $Log $(if ($AfterPublish -and $res.Action -eq 'refreshed') { 'INFO' } else { 'WARN' }) $line }
    $res
}

function Get-SIDataPublishSnapshotPruneSql {
    <# The executive-view copies no pointer names any more, past the data retention (the schema file stays additive: this
       removal lives here). Answers how many were removed. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.RiskExecViewSnapshot') IS NULL OR OBJECT_ID(N'sidata.PublishedRun') IS NULL BEGIN SELECT 0; RETURN; END
DELETE s FROM sidata.RiskExecViewSnapshot AS s
WHERE s.SnapshotAt < DATEADD(DAY, -ISNULL(TRY_CONVERT(int, @KeepDays), 90), SYSUTCDATETIME())
  AND NOT EXISTS (SELECT 1 FROM sidata.PublishedRun AS p WHERE p.ExecViewDetailedId = s.SnapshotId OR p.ExecViewSummaryId = s.SnapshotId);
SELECT @@ROWCOUNT;
'@
}

function Format-SIDataPublishTime {
    <# PURE. A UTC time as the ISO text the statements convert (style 126), or $null. #>
    param($Time)
    if ($null -eq $Time -or [string]$Time -eq '') { return $null }
    $d = if ($Time -is [datetime]) { [datetime]$Time } else { [datetime]::Parse([string]$Time, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind) }
    $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-SIDataPublishText {
    <# PURE. The one plain line the run log says. -Result: Invoke-SIDataPublishRun's answer. #>
    param([Parameter(Mandatory)]$Result)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    if ($Result.Published) {
        $when = if ($Result.CollectionTime) { [string]::Format($inv, ' of {0:yyyy-MM-dd HH:mm} UTC', ([datetime]$Result.CollectionTime)) } else { '' }
        return ('the web app now shows this run: its collection{0} is published{1}' -f $when, $(if ($Result.Reason) { ' (' + ([string]$Result.Reason).TrimEnd(' ', ';') + ')' } else { '' }))
    }
    if ($Result.Skipped) { return ('the web app keeps showing the last complete run: {0}' -f $Result.Reason) }
    'the web app keeps showing the last complete run -- this run is not published: {0}' -f $Result.Reason
}

function Write-SIDataPublishCopiesLine {
    <# The publish batch's word on the shown run's copies (CopiesCaughtUp / CopiesNote), as one WARN line -- nothing when the
       copies were current. Never throws. #>
    param($Rows, [scriptblock]$Log = { param($l, $m) })
    try {
        $r = @(@($Rows) | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
        if ($null -eq $r) { return }
        $val = { param($n) $v = $null; if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $v = $r[$n] } } elseif ($r.PSObject.Properties[$n]) { $v = $r.$n }; if ($v -is [System.DBNull]) { $null } else { $v } }
        $caught = & $val 'CopiesCaughtUp'; $note = [string](& $val 'CopiesNote')
        if (($caught -eq $true) -or ([string]$caught -in @('1', 'True', 'true'))) { & $Log 'WARN' 'the merged assets'' pages (CIs and assets) showed a copy older than the run the web app shows -- refreshed now; every page shows the same run again' }
        elseif ($note) { & $Log 'WARN' ('the copies of the merged assets could not be checked or refreshed ({0}) -- the next wake-up tries again' -f $note) }
    } catch { }
}

function Invoke-SIDataPublishRun {    <#
        Publish (or not) one ended run. NEVER throws. -Invoke: the data database seam (sql, params, mode 'rows'), $null = no
        database (nothing to publish). -State + -Map: a pipeline run (Source 'run'); -Source 'schedules': no run, the
        newest complete collection; -Source 'update': an install that has data and NOTHING published yet (the update that
        brought the published run) is published once -- the newest complete collection, its copies filled -- and every later
        wake-up only reads that something is published and catches up the shown run's copies when they are older than it
        (Invoke-SIPublishedCopyCatchUp). Returns @{ Published; Skipped (the run was not eligible -- the
        database was not asked); Reason; CollectionId; CollectionTime; Partial; Text }.
    #>
    param([scriptblock]$Invoke, $State, $Map, $Previous, [ValidateSet('run', 'schedules', 'update')][string]$Source = 'run', [string]$SolutionVersion = '',
          [bool]$AllowPartial = (Test-SIPublishPartialRun), [int]$RetentionDays = 0, [scriptblock]$Log = { param($l, $m) }, [scriptblock]$Beat)
    $res = [pscustomobject]@{ Published = $false; Skipped = $false; Reason = ''; CollectionId = $null; CollectionTime = $null; Partial = $false; Text = '' }
    try {
        if (-not $Invoke) { $res.Skipped = $true; $res.Reason = 'this install has no database'; $res.Text = Get-SIDataPublishText -Result $res; return $res }
        if ($Source -eq 'update') {
            # one read on every wake-up; the publisher (its lock, its checks) only while nothing is published
            $n = @(& $Invoke "SELECT CASE WHEN OBJECT_ID(N'sidata.PublishedRun') IS NULL OR OBJECT_ID(N'sidata.PublishedRunSet') IS NULL THEN 1 ELSE (SELECT COUNT(*) FROM sidata.PublishedRun WHERE Name = N'current') END AS N" @{} 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
            $has = if ($n.Count) { $v = if ($n[0] -is [System.Collections.IDictionary]) { $n[0]['N'] } else { $n[0].N }; [int]$v -gt 0 } else { $true }
            # a run is published: its copies of the merged assets caught up when they are older than it (one cheap read when not)
            if ($has) { $null = Invoke-SIPublishedCopyCatchUp -Invoke $Invoke -Log $Log; $res.Skipped = $true; $res.Reason = 'a run is published'; return $res }
        }
        $prm = @{ Source = $Source; FlowRunId = ''; RunStartedUtc = ''; RunEndedUtc = ''; SolutionVersion = $SolutionVersion
                  Grains = 'Detailed,Summary'; NeedCiBuild = '0'; AllowPartial = $(if ($AllowPartial) { '1' } else { '0' }); RefuseWhy = ''
                  SnapshotKeepDays = $(if ($RetentionDays -gt 0) { $RetentionDays } elseif ([int]$global:SI_Pro_DataRetentionDays -gt 0) { [int]$global:SI_Pro_DataRetentionDays } else { 90 }) }
        if ($Source -eq 'run') {
            if (-not $State) { throw 'no run record' }
            $el = Get-SIDataPublishEligibility -State $State -Map $Map -Previous $Previous
            $prm.FlowRunId = [string]$State.FlowRunId
            # a re-run that finishes the run before it: the run's own collection is looked for from THAT run's start
            $prm.RunStartedUtc = Format-SIDataPublishTime $(if ($el.StartedUtc) { $el.StartedUtc } else { $State.StartedUtc })
            if ($el.Eligible -and $el.ContinuesRunId) { & $Log 'INFO' ('this re-run finishes run {0} (every step before the re-run succeeded there): the two are published as one run' -f $el.ContinuesRunId) }
            $prm.RunEndedUtc = Format-SIDataPublishTime $(if ($State.EndedUtc) { $State.EndedUtc } else { [datetime]::UtcNow })
            if (-not $el.Eligible) {
                $res.Skipped = $true; $res.Reason = $el.Why; $res.Text = Get-SIDataPublishText -Result $res
                & $Log 'INFO' $res.Text
                # a run of the WHOLE pipeline that did not end trusted is what the banner calls "the newest run did not
                # complete": its reason is kept (a stage or a step run on its own is not a run of the data, and is not kept)
                if (Test-SIDataPublishWholeRun -State $State) {
                    $prm.RefuseWhy = $el.Why
                    try { Write-SIDataPublishCopiesLine -Rows @(& $Invoke (Get-SIDataPublishSql) $prm 'rows') -Log $Log } catch { & $Log 'WARN' ('why this run is not shown could not be kept ({0})' -f $_.Exception.Message) }
                    # #881 the shown run's copies caught up when they are older than it (range by range)
                    $null = Invoke-SIPublishedCopyCatchUp -Invoke $Invoke -Log $Log -Beat $Beat
                }
                return $res
            }
            $prm.Grains = $el.Grains; $prm.NeedCiBuild = $(if ($el.NeedCiBuild) { '1' } else { '0' })
        }
        # the rows as one list, however the seam hands them back (one array, or one row after the other)
        $rows = @(& $Invoke (Get-SIDataPublishSql) $prm 'rows' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        if (-not $rows.Count) { throw 'the database answered no result' }
        $r = $rows[0]
        $val = { param($n) $v = $null; if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $v = $r[$n] } } elseif ($r.PSObject.Properties[$n]) { $v = $r.$n }; if ($v -is [System.DBNull]) { $null } else { $v } }
        $bit = { param($x) ($x -eq $true) -or ([string]$x -in @('1', 'True', 'true')) }
        $res.Published = & $bit (& $val 'Published')
        $res.Reason = [string](& $val 'Reason')
        $res.CollectionId = & $val 'CollectionId'
        $res.CollectionTime = & $val 'CollectionTime'
        $res.Partial = & $bit (& $val 'Partial')
        # an attempt that did not publish caught up the shown run's copies when they were older than it: said (a data-health warning)
        Write-SIDataPublishCopiesLine -Rows $rows -Log $Log
        # #881 the copies follow the pointer range by range, right after it moved (CopiedAt only when every range is done); an
        # attempt that did not publish catches up copies older than the shown run the same way
        $null = Invoke-SIPublishedCopyCatchUp -Invoke $Invoke -Log $Log -AfterPublish:$res.Published -Beat $Beat
        # 'schedules': nothing newer is the normal answer of most wake-ups -- not said ('update': nothing complete yet, the same)
        if (($Source -in @('schedules', 'update')) -and -not $res.Published) { $res.Skipped = $true; $res.Text = ''; return $res }
        $res.Text = Get-SIDataPublishText -Result $res
        # #901 published with reports held at their last complete result: said as a WARNING, by name (never a silent publish)
        & $Log $(if ($res.Published -and [string]$res.Reason -notmatch 'report\(s\) held at their last complete result') { 'INFO' } else { 'WARN' }) $res.Text
        if ($res.Published) {
            try { $null = & $Invoke (Get-SIDataPublishSnapshotPruneSql) @{ KeepDays = [string]$prm.SnapshotKeepDays } 'scalar' }
            catch { & $Log 'WARN' ('the older executive-view copies were not removed this time ({0}) -- the next publish tries again' -f $_.Exception.Message) }
        }
    } catch {
        $res.Published = $false
        $res.Reason = ('it could not be published ({0}) -- the next trusted run publishes' -f $_.Exception.Message)
        $res.Text = Get-SIDataPublishText -Result $res
        & $Log 'WARN' $res.Text
    }
    $res
}
