#Requires -Version 7.0
<#
    SecurityInsight Pro -- THE DATA SYNC'S FIELD FILL STARTS PER REPORT (#1337, SCALE-3 #1330 track D).

    Today the data sync's field fill (SI-DataViewContext.ps1: every finding's prepared context columns, from its whole row --
    10.2 h of a 97 h run at a large install) waits until the whole Risk Analysis has ended. Risk Analysis already stores each
    finding's view values as it writes it (#1318, the per-report part that existed); this extends that: AS EACH REPORT IS
    COMPLETE (its verdict 'Complete', Set-RAStreamReportStatus), the same field fill statement runs over that report's rows,
    while the rows are fresh -- hours of the two steps overlap.

    THE ONE TRUSTED RUN (#780) IS UNCHANGED. Nothing here publishes, marks a collection complete or moves the pointer: the
    collection stays 'Loading' until Risk Analysis has ended, and only the pipeline runner publishes at the run's end.

    WHAT THE DATA SYNC TAKES FROM IT. Per report a mark (sidata.ViewState 'ectx:<collection>:<report>:<list>' =
    'lo;hi;rows;idcheck;print'): the report's FindingId range, its rows, a checksum of their ids and the statement its view
    values were worked out with. When the data sync prepares the collection it takes a report as filled ONLY when, now:
      * the report holds exactly those rows (same range, count and id checksum -- a report that ran again, was held back or
        lost rows does not match),
      * nothing else lies in its range (the range is the report's alone),
      * every one of its rows carries the view values of the CURRENT statement (#1318) -- a row the data sync worked out
        again (another statement, the setting off) does not match,
      * the list of prepared columns is the same (the mark names it).
    A report that does not match, or has no mark, is filled by the data sync exactly as before (today's rule). A report that
    fails later in the run (its rows removed, its verdict NotComplete) has its mark removed at once.

    SETTING SI_Data_LoadPerReport: on (the default, owner 2026-11-23: new features ship on -- the data sync leaves out the ranges
    of the reports that still match; a report that does not match is filled as before and said in a WARNING line, the run's report
    opens a fix request, so nothing unverified is published) | shadow (for troubleshooting -- both: the early fill runs, the data sync still fills every row and
    first counts, per report, the rows whose early values differ from its own; a difference is a WARNING line, the run's report
    opens a fix request, and the data sync's values are what is stored) | off (no early fill; exactly as before). Every mode stores the values of the same field fill statement.
#>

if (-not (Get-Command -Name Get-SIDataFindingContextSql -ErrorAction SilentlyContinue)) {
    $__vc = Join-Path $PSScriptRoot 'SI-DataViewContext.ps1'
    if (Test-Path -LiteralPath $__vc) { . $__vc }
}

function Get-SIDataLoadPerReportMode {
    <# PURE. SI_Data_LoadPerReport: on (the default, and anything unknown) | shadow | off. #>
    param($Value = $global:SI_Data_LoadPerReport)
    if ($Value -is [bool]) { if ($Value) { return 'on' } else { return 'off' } }
    $v = ([string]$Value).Trim().ToLowerInvariant()
    if ($v -in 'off', 'false', '0', 'no') { return 'off' }
    if ($v -eq 'shadow') { return 'shadow' }
    'on'
}

function Get-SIDataEarlyMarkName {
    <# PURE. The mark of one report's early field fill (sidata.ViewState.Name, at most 64). #>
    param([Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)][int]$Report, [Parameter(Mandatory)][string]$SetId)
    ('ectx:{0}:{1}:{2}' -f $CollectionId, $Report, $SetId)
}

function Format-SIDataEarlyMark {
    <# PURE. 'lo;hi;rows;idcheck;print' (print = the first 8 hex of the statement's fingerprint). #>
    param([long]$Lo, [long]$Hi, [long]$Rows, [long]$IdCheck, [string]$Print)
    $p8 = ([string]$Print).ToUpperInvariant(); if ($p8.Length -gt 8) { $p8 = $p8.Substring(0, 8) }
    ('{0};{1};{2};{3};{4}' -f $Lo, $Hi, $Rows, $IdCheck, $p8)
}

function ConvertFrom-SIDataEarlyMark {
    <# PURE. The mark's text -> @{ Lo; Hi; Rows; IdCheck; Print8 }; $null when it is not that shape. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [System.DBNull]) { return $null }
    $m = [regex]::Match([string]$Value, '^\s*(\d+);(\d+);(\d+);(-?\d+);([0-9A-Fa-f]{8})\s*$')
    if (-not $m.Success) { return $null }
    [pscustomobject]@{ Lo = [long]$m.Groups[1].Value; Hi = [long]$m.Groups[2].Value; Rows = [long]$m.Groups[3].Value; IdCheck = [long]$m.Groups[4].Value; Print8 = $m.Groups[5].Value.ToUpperInvariant() }
}

function Get-SIDataEarlyReportSql {
    <# READS ONLY. One report's rows of a collection (Risk Analysis' own: RaSeq set): its FindingId range, count, id checksum
       and how many carry the view values of the statement @Print (hex, 32), plus how many rows of the collection lie in its range. #>
    @'
SET NOCOUNT ON;
DECLARE @lo bigint, @hi bigint, @n bigint, @chk int, @typed bigint;
SELECT @lo = MIN(FindingId), @hi = MAX(FindingId), @n = COUNT_BIG(*), @chk = CHECKSUM_AGG(CHECKSUM(FindingId)),
       @typed = SUM(CASE WHEN TypedStatement = CONVERT(binary(16), NULLIF(@Print, N''), 2) THEN 1 ELSE 0 END)
FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaReport = CONVERT(int, @Report) AND RaSeq IS NOT NULL;
SELECT @lo AS Lo, @hi AS Hi, ISNULL(@n, 0) AS N, ISNULL(@chk, 0) AS IdCheck, ISNULL(@typed, 0) AS Typed,
       (SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND FindingId >= @lo AND FindingId <= @hi) AS InRange;
'@
}

function Read-SIDataEarlyReport {
    <# The answer of Get-SIDataEarlyReportSql as an object (Lo / Hi $null when the report holds no row). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)][int]$Report, [string]$Print = '')
    $raw = & $Invoke (Get-SIDataEarlyReportSql) @{ CollectionId = [string]$CollectionId; Report = [string]$Report; Print = [string]$Print } 'reader'
    $h = @(@($raw) | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] }) | Select-Object -First 1
    if (-not $h) { return $null }
    $v = { param($k) $x = $h[$k]; if ($null -eq $x -or $x -is [System.DBNull]) { $null } else { [long]$x } }
    [pscustomobject]@{ Lo = (& $v 'Lo'); Hi = (& $v 'Hi'); Rows = [long](& $v 'N'); IdCheck = [long](& $v 'IdCheck'); Typed = [long](& $v 'Typed'); InRange = $(if ($null -eq (& $v 'InRange')) { 0L } else { [long](& $v 'InRange') }) }
}

function Get-SIDataEarlyMarkWriteSql {
    "IF OBJECT_ID('sidata.ViewState') IS NULL SELECT 0; ELSE BEGIN UPDATE sidata.ViewState SET Value = @Value, UpdatedAt = SYSUTCDATETIME() WHERE Name = @Name; IF @@ROWCOUNT = 0 INSERT sidata.ViewState (Name, Value) VALUES (@Name, @Value); SELECT 1; END"
}

function Remove-SIDataReportEarlyLoad {
    <# A report's early field fill no longer counts (it ran again, its rows went, its verdict is not Complete): its marks go.
       -Report 0 = every report of the collection. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [int]$Report = 0)
    try {
        $like = $(if ($Report -gt 0) { 'ectx:{0}:{1}:%' -f $CollectionId, $Report } else { 'ectx:{0}:%' -f $CollectionId })
        $null = & $Invoke "IF OBJECT_ID('sidata.ViewState') IS NOT NULL DELETE FROM sidata.ViewState WHERE Name LIKE @Like;" @{ Like = $like } 'nonquery'
    } catch { }
}

function Invoke-SIDataReportEarlyLoad {
    <#
        Risk Analysis, a Detailed report just Complete: the data sync's field fill (Get-SIDataFindingContextSql, unchanged)
        over that report's rows, in measured FindingId ranges, then its mark. Only when SI_Data_LoadPerReport is not off, the
        database has the prepared columns, the report's rows carry the view values of -Print (the run's #1318 statement) and
        its range is its own (rows of another report in between: not filled early -- the data sync fills it as before). NEVER
        THROWS and never changes what a step decides: a failure is one INFO line and the report is filled by the data sync.
        Returns @{ Filled; Rows; Why }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)][int]$Report,
          [string]$Print = '', [string]$ReportName = '', [scriptblock]$Log, $List, [string]$Mode = '', [long]$TargetMs = 5000,
          # asked before every range: $true = stop now (the run ends) -- the report is then left to the data sync, no mark
          [scriptblock]$ShouldStop)
    $out = [pscustomobject]@{ Filled = $false; Rows = 0L; Why = '' }
    try {
        if (-not $Mode) { $Mode = Get-SIDataLoadPerReportMode }
        if ($Mode -eq 'off') { $out.Why = 'off'; return $out }
        if (-not $Print) { $out.Why = 'the view values are not worked out as the findings are stored'; return $out }
        if (-not (Get-Command -Name Get-SIDataFindingContextSql -ErrorAction SilentlyContinue)) { $out.Why = 'the field fill is not installed'; return $out }
        if (-not $List) { $List = Get-SIViewStoredColumns }
        if (-not $List) { $out.Why = 'no list of prepared columns'; return $out }
        if (([int](& $Invoke (Get-SIDataFindingContextSchemaCheckSql -List $List) @{} 'scalar')) -ne 1) { $out.Why = 'the database does not have the prepared columns yet'; return $out }
        $setId = Get-SIViewFindingSetId -List $List
        Remove-SIDataReportEarlyLoad -Invoke $Invoke -CollectionId $CollectionId -Report $Report
        $r = Read-SIDataEarlyReport -Invoke $Invoke -CollectionId $CollectionId -Report $Report -Print $Print
        if ($null -eq $r -or $r.Rows -le 0 -or $null -eq $r.Lo) { $out.Why = 'no row'; return $out }
        if ($r.Typed -ne $r.Rows) { $out.Why = 'not every row carries the view values of this run''s statement'; return $out }
        if ($r.InRange -ne $r.Rows) { $out.Why = 'its rows share their range with another report'; return $out }
        $fill = Get-SIDataFindingContextSql -List $List
        $after = [long]$r.Lo - 1; $hi = [long]$r.Hi; $size = [long]5000
        $paced = [bool](Get-Command -Name Invoke-SISqlPacing -ErrorAction SilentlyContinue); $lastMs = 0L
        while ($after -lt $hi) {
            if ($ShouldStop -and (& $ShouldStop)) { $out.Why = 'the run ended first'; return $out }
            if ($paced) { $pace = Invoke-SISqlPacing -Invoke $Invoke -LastBatchMs $lastMs; if ($pace.Shrink) { $size = [Math]::Max(500L, [long][Math]::Floor($size / 2)) } }
            $upto = [Math]::Min($hi, $after + $size)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $null = & $Invoke $fill @{ CollectionId = [int]$CollectionId; After = $after; Upto = $upto } 'scalar'
            $lastMs = $sw.ElapsedMilliseconds; $after = $upto
            $size = Get-SIDataNextSize -Current $size -ElapsedMs $lastMs -TargetMs $TargetMs -Minimum 500
        }
        # the mark only after the last range, and only when the report is still exactly what was filled
        $r2 = Read-SIDataEarlyReport -Invoke $Invoke -CollectionId $CollectionId -Report $Report -Print $Print
        if ($null -eq $r2 -or $r2.Rows -ne $r.Rows -or $r2.Lo -ne $r.Lo -or $r2.Hi -ne $r.Hi -or $r2.IdCheck -ne $r.IdCheck) { $out.Why = 'its rows changed while they were filled'; return $out }
        $ok = [string](& $Invoke (Get-SIDataEarlyMarkWriteSql) @{ Name = (Get-SIDataEarlyMarkName -CollectionId $CollectionId -Report $Report -SetId $setId); Value = (Format-SIDataEarlyMark -Lo $r.Lo -Hi $r.Hi -Rows $r.Rows -IdCheck $r.IdCheck -Print $Print) } 'scalar')
        if ($ok -ne '1') { $out.Why = 'the database has no mark table'; return $out }
        $out.Filled = $true; $out.Rows = $r.Rows
        if ($Log) { & $Log 'INFO' ("the views' prepared context of report '{0}' ({1:N0} finding(s)) is filled as the report is complete -- the data sync takes it from here" -f $(if ($ReportName) { $ReportName } else { $Report }), $r.Rows) }
        $out
    } catch {
        $out.Why = $_.Exception.Message
        if ($Log) { & $Log 'INFO' ("the views' prepared context of report '{0}' is filled by the data sync ({1})" -f $(if ($ReportName) { $ReportName } else { $Report }), $_.Exception.Message) }
        try { Remove-SIDataReportEarlyLoad -Invoke $Invoke -CollectionId $CollectionId -Report $Report } catch { }
        $out
    }
}

function Get-SIDataReportEarlyIntervals {
    <#
        The data sync, before it fills collection -CollectionId: the reports filled early that STILL match (see the header),
        as FindingId intervals @{ Report; Lo; Hi; Rows }, sorted, plus the marks that did not match and why. -Print: the
        statement the data sync's own derive leaves alone (its #1318 plan); '' = none (then no report matches). Never throws.
        Returns @{ Intervals; Rejected }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)][string]$SetId, [string]$Print = '')
    $iv = New-Object System.Collections.Generic.List[object]; $rej = New-Object System.Collections.Generic.List[string]
    try {
        $raw = & $Invoke "IF OBJECT_ID('sidata.ViewState') IS NOT NULL SELECT Name, Value FROM sidata.ViewState WHERE Name LIKE @Like;" @{ Like = ('ectx:{0}:%' -f $CollectionId) } 'reader'
        foreach ($h in @(@($raw) | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] })) {
            $m = [regex]::Match([string]$h['Name'], '^ectx:(\d+):(\d+):(.+)$'); if (-not $m.Success) { continue }
            $rep = [int]$m.Groups[2].Value
            if ($m.Groups[3].Value -ne $SetId) { $rej.Add(('report {0}: filled for another list of columns' -f $rep)); continue }
            $mk = ConvertFrom-SIDataEarlyMark $h['Value']
            if (-not $mk) { $rej.Add(('report {0}: its mark is not readable' -f $rep)); continue }
            $p8 = ([string]$Print).ToUpperInvariant(); if ($p8.Length -gt 8) { $p8 = $p8.Substring(0, 8) }
            if (-not $Print -or $mk.Print8 -ne $p8) { $rej.Add(('report {0}: its view values are not those of the current statement' -f $rep)); continue }
            $now = Read-SIDataEarlyReport -Invoke $Invoke -CollectionId $CollectionId -Report $rep -Print $Print
            if ($null -eq $now -or $now.Rows -ne $mk.Rows -or $now.Lo -ne $mk.Lo -or $now.Hi -ne $mk.Hi -or $now.IdCheck -ne $mk.IdCheck) { $rej.Add(('report {0}: its rows changed after it was filled' -f $rep)); continue }
            if ($now.Typed -ne $now.Rows) { $rej.Add(('report {0}: rows were worked out again after it was filled' -f $rep)); continue }
            if ($now.InRange -ne $now.Rows) { $rej.Add(('report {0}: its range holds other rows' -f $rep)); continue }
            $iv.Add([pscustomobject]@{ Report = $rep; Lo = $mk.Lo; Hi = $mk.Hi; Rows = $mk.Rows })
        }
    } catch { $rej.Add(('the marks could not be read: {0}' -f $_.Exception.Message)); $iv.Clear() }
    [pscustomobject]@{ Intervals = @($iv | Sort-Object Lo); Rejected = $rej.ToArray() }
}

function Get-SIDataFindingContextDiffSql {
    <# PURE. READS ONLY. The field fill (-Fill, Get-SIDataFindingContextSql) as a count: the findings of the range (@After,
       @Upto] whose stored context differs from what the fill works out -- the same expressions, nothing written. #>
    param([Parameter(Mandatory)][string]$Fill)
    $a = $Fill.IndexOf('FROM sidata.Finding AS f'); $e = $Fill.IndexOf('SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = @CollectionId')
    if ($a -lt 0 -or $e -lt 0) { throw 'the field fill is not in the shape its count is cut from' }
    'SELECT COUNT_BIG(*) ' + $Fill.Substring($a, $e - $a).TrimEnd()
}

function Get-SIDataEarlyPrint {
    <# The statement the data sync's derive leaves alone (#1318 plan's fingerprint), '' when values are not worked out at insert. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    try {
        if (-not (Get-Command -Name Get-SIDataParseAtInsertPlan -ErrorAction SilentlyContinue)) { return '' }
        $p = Get-SIDataParseAtInsertPlan -Invoke $Invoke
        if ($p -and $p.Ready -and [string]$p.Mode -eq 'on') { return [string]$p.Print }
    } catch { }
    ''
}

# ---------------------------------------------------------------------------------------------------------------------
#  RISK ANALYSIS' SIDE: the early fill runs BESIDE the run, never in its way. One worker (its own runspace, plain .NET, its
#  own connection per report from the run's connection string and a current token handed over with each report) takes the
#  reports in the order they are complete; Risk Analysis goes on with its next report at once. At the run's end the worker
#  stops after the range in hand (the report in hand gets no mark: the data sync fills it), the reports that turned out not
#  complete lose their marks again, and the worker's lines go to the run's log.
# ---------------------------------------------------------------------------------------------------------------------

$script:SIDataEarlyWorkerBody = {
    param($State, $Files)
    foreach ($f in $Files) { . $f }
    # the shared open-with-retry (SI-SqlRetry.ps1, loaded by SI-DataViewContext.ps1), as a value for the closure below
    $openCs = ${function:Open-SISqlConnectionStringRetry}
    $item = $null
    while ($true) {
        # the run's end: nothing more is taken; what is left in the queue is let go (the data sync fills those reports)
        if ($State.Stop) { $x = $null; while ($State.Queue.TryDequeue([ref]$x)) { $State.Dropped = [int]$State.Dropped + 1 }; break }
        # busy BEFORE the queue is asked: an item taken is never between "queue empty" and "busy"
        $State.Busy = $true
        if (-not $State.Queue.TryDequeue([ref]$item)) {
            $State.Busy = $false
            if ($State.Stop) { break }
            Start-Sleep -Milliseconds 200; continue
        }
        $cs = [string]$item.ConnectionString; $tok = [string]$item.AccessToken; $cto = [int]$State.CommandTimeout
        $inv = {
            param([string]$sql, $p, [string]$mode)
            # a failover / a resume / a moment's network fault is waited out briefly (Open-SISqlConnectionStringRetry); a range
            # whose open still fails ends here, its report gets no mark and the data sync fills it
            $cn = & $openCs -ConnectionString $cs -AccessToken $tok
            try {
                # every command has a time limit: a range that hangs ends, its report gets no mark and the data sync fills it
                $c = $cn.CreateCommand(); $c.CommandTimeout = $cto; $c.CommandText = $sql
                if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                while ($r.Read()) { $h = @{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add($h) }
                $r.Close(); return , $rows.ToArray()
            } finally { $cn.Dispose() }
        }.GetNewClosure()
        $lg = { param($l, $m) $State.Lines.Enqueue(('{0}|{1}' -f $l, $m)) }.GetNewClosure()
        $stop = { [bool]$State.Stop }.GetNewClosure()
        try {
            $r = Invoke-SIDataReportEarlyLoad -Invoke $inv -CollectionId ([long]$item.CollectionId) -Report ([int]$item.Report) -Print ([string]$item.Print) -ReportName ([string]$item.ReportName) -Mode ([string]$item.Mode) -Log $lg -ShouldStop $stop
            if ($r.Filled) { $State.Filled = [int]$State.Filled + 1 }
        } catch { $State.Lines.Enqueue(("INFO|the views' prepared context of report '{0}' is filled by the data sync ({1})" -f $item.ReportName, $_.Exception.Message)) }
        finally { $State.Busy = $false }
    }
}

function Start-SIDataEarlyLoadWorker {
    <# The worker (see above). -Files: the engine files it loads (this file and what it needs). Returns its handle. #>
    # -CommandTimeoutSec: the limit of each of its commands (a range aims at a few seconds; one that hangs ends here)
    param([Parameter(Mandatory)][string[]]$Files, [int]$CommandTimeoutSec = 300)   # limit-ok: a helper BESIDE the run -- the data sync fills any report it does not finish; one hung command must never hold the run's end
    $st = [hashtable]::Synchronized(@{ Queue = (New-Object 'System.Collections.Concurrent.ConcurrentQueue[object]'); Lines = (New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'); Stop = $false; Busy = $false; Filled = 0; Dropped = 0
                                       CommandTimeout = [Math]::Max(1, $CommandTimeoutSec) })
    $rs = [runspacefactory]::CreateRunspace(); $rs.Open()
    $ps = [powershell]::Create(); $ps.Runspace = $rs
    [void]$ps.AddScript($script:SIDataEarlyWorkerBody.ToString()).AddArgument($st).AddArgument($Files)
    $h = $ps.BeginInvoke()
    [pscustomobject]@{ State = $st; PowerShell = $ps; Runspace = $rs; Handle = $h }
}

function Submit-SIDataEarlyLoad {
    <# One complete report handed to the worker (with the connection string and a current token). Never throws. #>
    param([Parameter(Mandatory)]$Worker, [Parameter(Mandatory)][long]$CollectionId, [Parameter(Mandatory)][int]$Report, [string]$Print = '', [string]$ReportName = '',
          [string]$Mode = '', [string]$ConnectionString = '', [string]$AccessToken = '')
    try { $Worker.State.Queue.Enqueue([pscustomobject]@{ CollectionId = $CollectionId; Report = $Report; Print = $Print; ReportName = $ReportName; Mode = $Mode; ConnectionString = $ConnectionString; AccessToken = $AccessToken }); $true } catch { $false }
}

function Read-SIDataEarlyLoadLines {
    <# The worker's lines so far, to -Log (level|text). Never throws. #>
    param($Worker, [scriptblock]$Log)
    try {
        if ($null -eq $Worker) { return }
        $x = $null
        while ($Worker.State.Lines.TryDequeue([ref]$x)) { $i = $x.IndexOf('|'); if ($Log -and $i -gt 0) { & $Log $x.Substring(0, $i) $x.Substring($i + 1) } }
    } catch { }
}

function Stop-SIDataEarlyLoadWorker {
    <# The run's end: the worker stops after the range in hand (reports still queued are let go); what it said goes to -Log;
       it is let go. Answers the reports it filled. -WaitSeconds: how long the stop is waited for (default: one command's
       limit + 30 s) -- a worker that has not stopped by then is LEFT BEHIND, said in one line, never waited on further (its
       report in hand gets no mark the data sync would take on trust: the data sync checks every mark). -Drain: it first
       finishes every report handed to it, within the same wait (tests). Never throws. #>
    param($Worker, [scriptblock]$Log, [switch]$Drain, [int]$WaitSeconds = -1)
    if ($null -eq $Worker) { return 0 }
    $left = $false
    try {
        if ($WaitSeconds -lt 0) { $WaitSeconds = [int]$Worker.State.CommandTimeout + 30 }
        $until = [datetime]::UtcNow.AddSeconds([Math]::Max(1, $WaitSeconds))
        if ($Drain) { while ((-not $Worker.State.Queue.IsEmpty -or $Worker.State.Busy) -and [datetime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 100 } }
        $Worker.State.Stop = $true
        $ms = [int][Math]::Max(0, ($until - [datetime]::UtcNow).TotalMilliseconds)
        if ($Worker.Handle.AsyncWaitHandle.WaitOne($ms)) { try { $null = $Worker.PowerShell.EndInvoke($Worker.Handle) } catch { } }
        else {
            $left = $true
            try { $null = $Worker.PowerShell.BeginStop($null, $null) } catch { }
            if ($Log) { & $Log 'WARN' ("the early fill of the views' prepared context did not stop within {0} s -- it is left behind; the data sync fills what it did not finish (it checks every report before it takes one)" -f $WaitSeconds) }
        }
        Read-SIDataEarlyLoadLines -Worker $Worker -Log $Log
        if ([int]$Worker.State.Dropped -gt 0 -and $Log) { & $Log 'INFO' ("{0} complete report(s) were still waiting for the early fill when the run ended -- the data sync fills them" -f [int]$Worker.State.Dropped) }
        [int]$Worker.State.Filled
    } catch { 0 } finally {
        # a worker left behind is not disposed under its feet (it ends with the process)
        if (-not $left) {
            try { $Worker.PowerShell.Dispose() } catch { }
            try { $Worker.Runspace.Dispose() } catch { }
        }
    }
}
