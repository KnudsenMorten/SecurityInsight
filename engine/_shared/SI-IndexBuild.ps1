#Requires -Version 5.1
<#
    SecurityInsight Pro -- INDEXES THAT DO NOT FIT AN UPDATE (#1050, owner 2026-11-01).

    Live 2026-11-01 (a ring 2 install, 3.0.9 -> 3.0.10): the update said "up to 10 min" for its indexes on large tables and
    then built a FILTERED index on the findings table (17.2 million rows) for more than two hours. A filtered index cannot be
    built resumably, so it cannot pause at the update's time; the install and the queued pipeline run waited behind it.

    THE RULE (no cap on size -- an estimate from this database's own measured rate):
      * the pages to read = the table's in-row pages (sys.partitions + sys.allocation_units: a build reads every page of
        the table whatever its filter); the rate = pages per second this database has built before (cfg.InstallState
        'IndexBuildRate', the median of the newest measured builds), else what a resumable build here has done so far,
        else a timed sample read of the table (TABLESAMPLE) taken as half the build rate (a build reads, sorts and writes);
      * estimate = pages / rate x a margin (the spread of the measured builds; 1.5 until three are measured);
      * an update builds a non-resumable index only when its estimate fits the update's minutes; otherwise the index WAITS
        (cfg.IndexBuild, one row per index, with the statement and why) and the release runs without it;
      * a waiting index is built when the install is idle long enough: the pipeline runner's wake-up starts THE INDEX BUILD
        JOB caj-si-index-build (#1111, owner 2026-11-05: "why not split this into 2 jobs" / "we cannot have env that doesnt
        upd suddently") when no run, step, data sync, data out or update is going and the estimate ends before the next
        scheduled run; the job takes the install's lock (a pipeline run waits for it) and beats it while the index builds;
      * THE UPDATE ALWAYS GOES FIRST (#1111): the job never starts while an update waits (the updater's wait mark) or runs;
        while it builds it checks both every CheckSeconds -- and whether it still holds the install's lock, which the
        updater may take from it at once. Either = a resumable build is PAUSED (ALTER INDEX ... PAUSE; the row 'paused',
        resumed in a later idle window), a filtered one (it cannot pause) is cancelled and waits again; the lock is freed
        and the job ends. The updater never waits for an index build and no longer has an index-build mode;
      * NO INDEX WAITS FOR EVER (owner 2026-11-01): one that has waited 7 days without an idle window long enough is
        built at the next idle moment, once, said in plain words -- the next run waits for it.
    Every build that ran long enough to measure records its rate, so the next estimate is this database's own.
    PowerShell 5.1 and 7. No PowerShell modules.
#>

$script:SIIndexBuild = @{
    Table           = 'cfg.IndexBuild'
    RateRow         = 'IndexBuildRate'
    RateKeep        = 7          # the newest measured builds the median is taken over (older ones age out; not a size limit)
    ReadFactor      = 2.0        # a sample READ rate / this = the build rate, until this database has measured a build
    MarginFew       = 1.5        # the estimate's margin while fewer than three builds are measured
    MarginLeast     = 1.2        # the least margin once they are (the measured spread decides above it)
    SamplePages     = 20000      # the timed sample read reads about this many pages (a few seconds on any tier)
    MeasureSeconds  = 60         # a build shorter than this is not recorded as a rate (too short to measure)
    BeatSeconds     = 30         # the install's lock is beaten this often while an index builds
    SayEveryMinutes = 5          # one line while it builds, this often
    WaitDays        = 7          # an index that has waited this long is built at the next idle moment (once)
    LeadMinutes     = 15         # a window build must end this long before the next run starts
    ResumeMinutes   = 10         # a resumable build (new or paused) starts when the window has at least this many minutes
    CheckSeconds    = 15         # while it builds, the job looks this often for an update (and beats the install's lock)
    # #1316 follow-up (coordinator 2026-11-23): an install whose runs go back to back has no idle window. An index that has
    # waited GapAfterHours is built in the GAP before a scheduled run starts (also the gap after an update): the run starts
    # late, at most GapLateMinutes (a resumable build pauses there; a non-resumable one starts only when its estimate fits --
    # or the once-after-WaitDays build), at most once per GapEveryHours per index, never again within GapRetryMinutes of an
    # index build job start (a start that did not take the lock never holds run after run).
    GapAfterHours   = 24
    GapLateMinutes   = 180
    GapEveryHours   = 24
    GapRetryMinutes = 60
    Job             = 'caj-si-index-build'   # #1111: the index build job (its own job; the updater only updates)
    Role            = 'index-build'          # its SI_ROLE (container\Start-SIInContainer.ps1 hands it to its entry)
    WaitTag         = 'si-update-waits'      # the updater's wait mark on its own job (the same tag the runner reads)
}

function Get-SIIndexBuildContract { $script:SIIndexBuild }

# =====================================================================================================================
#  The size of a table -- catalog views only (the updater's db_ddladmin sees them; no VIEW DATABASE STATE needed)
# =====================================================================================================================
function Get-SIIndexTablePagesSql {
    @'
SET NOCOUNT ON;
SELECT CONVERT(bigint, ISNULL(SUM(a.used_pages), 0)) AS Pages,
       CONVERT(bigint, ISNULL(SUM(CASE WHEN a.type = 1 THEN p.rows ELSE 0 END), 0)) AS RowCnt
  FROM sys.partitions AS p
  JOIN sys.allocation_units AS a ON a.container_id = p.hobt_id AND a.type IN (1, 3)
 WHERE p.object_id = OBJECT_ID(@T) AND p.index_id IN (0, 1);
'@
}

function Get-SIIndexRowValue {
    <# PURE. One column of a row from any reader seam (hashtable, dictionary, object, DataRow). #>
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) { return $Row[$Name] }
    if ($Row -is [System.Data.DataRow]) { return $Row[$Name] }
    $p = $Row.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    $null
}

function Get-SIIndexReaderRows {
    <# The rows of a reader call, flattened (a seam may answer one array of rows, or the rows one by one). #>
    param($Answer)
    @($Answer | ForEach-Object { $_ } | Where-Object { $null -ne $_ -and -not ($_ -is [DBNull]) })
}

function Get-SIIndexTablePages {
    <# @{ Pages; Rows } of -Table ('schema.table'), or $null when it cannot be read. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Table)
    try {
        $r = @(Get-SIIndexReaderRows (& $Invoke (Get-SIIndexTablePagesSql) ([ordered]@{ T = $Table }) 'reader'))
        if (-not $r.Count) { return $null }
        $p = Get-SIIndexRowValue $r[0] 'Pages'; $n = Get-SIIndexRowValue $r[0] 'RowCnt'
        if ($null -eq $p -or $p -is [DBNull]) { return $null }
        $pages = [long]0; if (-not [long]::TryParse("$p", [ref]$pages)) { return $null }
        $rows = [long]0; [void][long]::TryParse("$n", [ref]$rows)
        [pscustomobject]@{ Pages = $pages; Rows = $rows }
    } catch { $null }
}

# =====================================================================================================================
#  The rate -- this database's own
# =====================================================================================================================
function ConvertFrom-SIIndexRateValue {
    <# PURE. cfg.InstallState 'IndexBuildRate' value -> the samples @( @{ Pps; Pages; Seconds } ), newest first. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if (-not "$Value".Trim()) { return @() }
    try {
        $o = $Value | ConvertFrom-Json -ErrorAction Stop
        @(@($o.s) | Where-Object { $null -ne $_ } | ForEach-Object {
            $a = @($_)
            if ($a.Count -ge 3 -and [double]$a[0] -gt 0) { [pscustomobject]@{ Pps = [double]$a[0]; Pages = [long]$a[1]; Seconds = [long]$a[2] } }
        })
    } catch { @() }
}

function ConvertTo-SIIndexRateValue {
    <# PURE. The samples (newest first) -> the stored value: {"s":[[pps,pages,seconds],...]} -- the newest RateKeep, within
       the 400 characters cfg.InstallState holds (the oldest dropped first). #>
    param([object[]]$Samples = @())
    $keep = @($Samples | Where-Object { $null -ne $_ } | Select-Object -First $script:SIIndexBuild.RateKeep)
    for ($n = $keep.Count; $n -ge 0; $n--) {
        $arr = @($keep | Select-Object -First $n | ForEach-Object { , @([Math]::Round([double]$_.Pps, 1), [long]$_.Pages, [long]$_.Seconds) })
        $v = ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{ s = @($arr) })
        if ($v.Length -le 400) { return $v }
    }
    '{"s":[]}'
}

function Read-SIIndexBuildRate {
    <# The measured samples of this database (newest first); none when the row or the table is not there. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    try {
        $r = @(Get-SIIndexReaderRows (& $Invoke "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = @N;" ([ordered]@{ N = $script:SIIndexBuild.RateRow }) 'reader'))
        if (-not $r.Count) { return @() }
        $v = Get-SIIndexRowValue $r[0] 'Value'
        @(ConvertFrom-SIIndexRateValue -Value $(if ($null -eq $v -or $v -is [DBNull]) { '' } else { [string]$v }))
    } catch { @() }
}

function Add-SIIndexBuildRateSample {
    <# One measured build (pages read, seconds) added to this database's rate. A build shorter than MeasureSeconds is not a
       measurement. Returns $true when recorded. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [long]$Pages, [double]$Seconds, [string]$By = 'caj-si-updater')
    if ($Pages -le 0 -or $Seconds -lt $script:SIIndexBuild.MeasureSeconds) { return $false }
    try {
        $now = @(Read-SIIndexBuildRate -Invoke $Invoke)
        $s = @([pscustomobject]@{ Pps = ($Pages / $Seconds); Pages = $Pages; Seconds = [long][Math]::Round($Seconds) }) + $now
        $sql = @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = @N)
        UPDATE cfg.InstallState SET Value = @V, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @N;
    ELSE INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (@N, @V, NULL, @By);
END
'@
        $null = & $Invoke $sql ([ordered]@{ N = $script:SIIndexBuild.RateRow; V = (ConvertTo-SIIndexRateValue -Samples $s); By = $By }) 'nonquery'
        $true
    } catch { $false }
}

function Get-SIIndexResumableRateSql {
    @'
SET NOCOUNT ON;
DECLARE @b TABLE (P bigint NOT NULL, Pct float NOT NULL, M float NOT NULL);
IF OBJECT_ID(N'sys.index_resumable_operations') IS NOT NULL
  INSERT @b (P, Pct, M) EXEC (N'SELECT CONVERT(bigint, ISNULL(page_count, 0)), CONVERT(float, ISNULL(percent_complete, 0)), CONVERT(float, ISNULL(total_execution_time, 0)) FROM sys.index_resumable_operations');
SELECT P, Pct, M FROM @b;
'@
}

function Get-SIIndexResumableRate {
    <# Pages per second a resumable build on this database has done so far (its pages x its percent / its minutes), the
       highest-volume one; $null when there is none to read. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    try {
        $best = $null; $bestPages = 0.0
        foreach ($r in @(Get-SIIndexReaderRows (& $Invoke (Get-SIIndexResumableRateSql) @{} 'reader'))) {
            $p = [double](Get-SIIndexRowValue $r 'P'); $pct = [double](Get-SIIndexRowValue $r 'Pct'); $m = [double](Get-SIIndexRowValue $r 'M')
            $done = $p * $pct / 100.0
            if ($done -gt 0 -and $m -gt 0 -and $done -gt $bestPages) { $bestPages = $done; $best = $done / ($m * 60.0) }
        }
        $best
    } catch { $null }
}

function Get-SIIndexSamplePercent {
    <# PURE. The TABLESAMPLE percent that reads about SamplePages of -Pages (the whole table when it is smaller). #>
    param([long]$Pages)
    if ($Pages -le $script:SIIndexBuild.SamplePages) { return 100.0 }
    [Math]::Max(0.001, [Math]::Round(100.0 * $script:SIIndexBuild.SamplePages / $Pages, 4))
}

function Measure-SIIndexReadRate {
    <# A timed sample read of -Table (TABLESAMPLE SYSTEM -- random pages, as a build reads them from storage): pages per
       second READ, or $null. -Clock (tests): { } -> seconds elapsed since the previous call. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Table, [long]$Pages, [scriptblock]$Clock)
    try {
        if ($Pages -le 0 -or $Table -notmatch '^\w+\.\w+$') { return $null }
        $pct = Get-SIIndexSamplePercent -Pages $Pages
        $sch, $tab = $Table -split '\.', 2
        $sql = 'SET NOCOUNT ON; SELECT COUNT_BIG(*) AS N FROM {0}.{1} TABLESAMPLE SYSTEM ({2} PERCENT) WITH (NOLOCK);' -f (Get-SIIndexQuotedName $sch), (Get-SIIndexQuotedName $tab), $pct.ToString('0.####', [Globalization.CultureInfo]::InvariantCulture)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $null = & $Invoke $sql @{} 'reader'
        $sw.Stop()
        $sec = if ($Clock) { [double](& $Clock) } else { $sw.Elapsed.TotalSeconds }
        $read = $Pages * $pct / 100.0
        if ($sec -le 0) { $sec = 0.001 }
        $read / $sec
    } catch { $null }
}

function Get-SIIndexBuildRate {
    <#
        PURE. The build rate to estimate with: -Samples (this database's measured builds, newest first) > -ResumableRate (a
        resumable build here, pages per second) > -ReadRate (a timed sample read, pages per second, / ReadFactor). Returns
        @{ Known; PagesPerSecond; Margin; Source }.
    #>
    param([object[]]$Samples = @(), $ResumableRate, $ReadRate)
    $S = $script:SIIndexBuild
    # (not $s: PowerShell names are case-insensitive, $S is the contract)
    $smp = @($Samples | Where-Object { $null -ne $_ -and [double]$_.Pps -gt 0 })
    if ($smp.Count) {
        $sorted = @($smp | ForEach-Object { [double]$_.Pps } | Sort-Object)
        $mid = [int][Math]::Floor($sorted.Count / 2)
        $median = if ($sorted.Count % 2) { $sorted[$mid] } else { ($sorted[$mid - 1] + $sorted[$mid]) / 2.0 }
        $margin = if ($smp.Count -lt 3) { [double]$S.MarginFew } else { [Math]::Max([double]$S.MarginLeast, $median / $sorted[0]) }
        return [pscustomobject]@{ Known = $true; PagesPerSecond = $median; Margin = [Math]::Round([double]$margin, 2); Source = ('measured on this database ({0} build(s))' -f $smp.Count) }
    }
    if ($null -ne $ResumableRate -and [double]$ResumableRate -gt 0) {
        return [pscustomobject]@{ Known = $true; PagesPerSecond = [double]$ResumableRate; Margin = $S.MarginFew; Source = 'a resumable build on this database' }
    }
    if ($null -ne $ReadRate -and [double]$ReadRate -gt 0) {
        return [pscustomobject]@{ Known = $true; PagesPerSecond = ([double]$ReadRate / $S.ReadFactor); Margin = $S.MarginFew; Source = 'a timed sample read of the table' }
    }
    [pscustomobject]@{ Known = $false; PagesPerSecond = 0.0; Margin = $S.MarginFew; Source = 'no rate could be measured' }
}

function Get-SIIndexBuildEstimate {
    <# PURE. -Pages at -Rate (Get-SIIndexBuildRate) -> @{ Known; Minutes (whole, at least 1); Pages; PagesPerSecond; Source }. #>
    param([long]$Pages, [Parameter(Mandatory)]$Rate)
    if (-not $Rate.Known -or $Pages -lt 0) { return [pscustomobject]@{ Known = $false; Minutes = 0; Pages = $Pages; PagesPerSecond = 0.0; Source = [string]$Rate.Source } }
    $min = $Pages / [double]$Rate.PagesPerSecond / 60.0 * [double]$Rate.Margin
    [pscustomobject]@{ Known = $true; Minutes = [int][Math]::Max(1, [Math]::Ceiling($min)); Pages = $Pages; PagesPerSecond = [double]$Rate.PagesPerSecond; Source = [string]$Rate.Source }
}

function New-SIIndexBuildEstimator {
    <#
        The estimator one schema apply uses: { param($Index) } -> Get-SIIndexBuildEstimate's answer. The rate is read ONCE
        (the stored samples, else a resumable build), a table's pages and sample read once per table. Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $cache = @{ Samples = $null; Resumable = $null; Read = @{}; Pages = @{} }
    $inv = $Invoke
    # the functions, captured: a closure's own scope does not see functions dot-sourced into a function (the updater loads
    # this file inside its database step) -- a captured function runs where it was defined
    $fPages = ${function:Get-SIIndexTablePages}; $fSamples = ${function:Read-SIIndexBuildRate}; $fResumable = ${function:Get-SIIndexResumableRate}
    $fRead = ${function:Measure-SIIndexReadRate}; $fRate = ${function:Get-SIIndexBuildRate}; $fEst = ${function:Get-SIIndexBuildEstimate}
    {
        param($Index)
        try {
            $t = [string]$Index.Table
            if (-not $cache.Pages.ContainsKey($t)) { $cache.Pages[$t] = & $fPages -Invoke $inv -Table $t }
            $pg = $cache.Pages[$t]
            if (-not $pg) { return [pscustomobject]@{ Known = $false; Minutes = 0; Pages = 0; PagesPerSecond = 0.0; Source = 'the size of the table could not be read' } }
            if ($null -eq $cache.Samples) { $cache.Samples = @(& $fSamples -Invoke $inv); $cache.Resumable = & $fResumable -Invoke $inv }
            $read = $null
            if (-not @($cache.Samples).Count -and -not $cache.Resumable) {
                if (-not $cache.Read.ContainsKey($t)) { $cache.Read[$t] = & $fRead -Invoke $inv -Table $t -Pages $pg.Pages }
                $read = $cache.Read[$t]
            }
            & $fEst -Pages $pg.Pages -Rate (& $fRate -Samples @($cache.Samples) -ResumableRate $cache.Resumable -ReadRate $read)
        } catch { [pscustomobject]@{ Known = $false; Minutes = 0; Pages = 0; PagesPerSecond = 0.0; Source = ('the estimate failed: {0}' -f $_.Exception.Message) } }
    }.GetNewClosure()
}

# =====================================================================================================================
#  The words -- PURE
# =====================================================================================================================
function Format-SIIndexDuration {
    <# PURE. Minutes as '45 min' / '2 h 10 min'. #>
    param([int]$Minutes)
    if ($Minutes -lt 60) { return ('{0} min' -f [Math]::Max(1, $Minutes)) }
    $h = [int][Math]::Floor($Minutes / 60); $m = $Minutes - 60 * $h
    if ($m) { '{0} h {1} min' -f $h, $m } else { '{0} h' -f $h }
}

function Format-SIIndexPages {
    <# PURE. 11500000 -> '11.5 M', 85000 -> '85,000'. #>
    param([long]$Pages)
    if ($Pages -ge 1000000) { return ('{0} M' -f ([Math]::Round($Pages / 1000000.0, 1)).ToString('0.#', [Globalization.CultureInfo]::InvariantCulture)) }
    $Pages.ToString('N0', [Globalization.CultureInfo]::InvariantCulture)
}

function Get-SIIndexWaitText {
    <# PURE. Why an index is not built in this update -- ONE plain line (the update's log, the index's row, the status). #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)]$Estimate, [int]$BudgetMinutes)
    $why = if ($Estimate.Known) {
        'a filtered index cannot pause, and at this database''s measured rate its {0} pages take about {1}, more than the {2} this update has' -f (Format-SIIndexPages $Estimate.Pages), (Format-SIIndexDuration $Estimate.Minutes), (Format-SIIndexDuration $BudgetMinutes)
    } else {
        'a filtered index cannot pause, and how long it takes is not known here ({0})' -f $Estimate.Source
    }
    'index {0} on {1}: not built in this update -- {2}. It is built when the install is idle long enough before the next run; the release works without it.' -f $Name, $Table, $why
}

# =====================================================================================================================
#  The waiting indexes -- cfg.IndexBuild (one row per index)
# =====================================================================================================================
function Get-SIIndexBuildSaveSql {
    <# ONE upsert of an index's row. SinceUtc is the FIRST time it waited -- kept across updates and failed window builds
       (the 7 days count from it), new only when a built index waits again; ForcedUtc (the one-time build after 7 days) is
       kept the same way. No table = nothing (an older schema). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.IndexBuild') IS NOT NULL
BEGIN
    SET XACT_ABORT ON;
    BEGIN TRAN;
    IF EXISTS (SELECT 1 FROM cfg.IndexBuild WITH (UPDLOCK, HOLDLOCK) WHERE TableName = @T AND IndexName = @I)
        UPDATE cfg.IndexBuild
           SET Statement = ISNULL(@Stmt, Statement), State = @State, Pages = ISNULL(@Pages, Pages), EstMinutes = ISNULL(@Est, EstMinutes),
               RateSource = ISNULL(@Src, RateSource), Why = @Why,
               SinceUtc = CASE WHEN @State = N'waiting' AND State = N'built' THEN SYSUTCDATETIME() ELSE SinceUtc END,
               LastStartUtc = CASE WHEN @State = N'building' THEN SYSUTCDATETIME() ELSE LastStartUtc END,
               LastEndUtc = CASE WHEN @State IN (N'built', N'failed', N'paused') OR (@State = N'waiting' AND State = N'building') THEN SYSUTCDATETIME() ELSE LastEndUtc END,
               ForcedUtc = CASE WHEN @Forced = 1 THEN SYSUTCDATETIME() WHEN @State = N'waiting' AND State = N'built' THEN NULL ELSE ForcedUtc END,
               UpdatedUtc = SYSUTCDATETIME(), UpdatedBy = @By
         WHERE TableName = @T AND IndexName = @I;
    ELSE
        INSERT cfg.IndexBuild (TableName, IndexName, Statement, State, Pages, EstMinutes, RateSource, Why, SinceUtc, LastStartUtc, ForcedUtc, UpdatedUtc, UpdatedBy)
        VALUES (@T, @I, ISNULL(@Stmt, N''), @State, @Pages, @Est, @Src, @Why, SYSUTCDATETIME(),
                CASE WHEN @State = N'building' THEN SYSUTCDATETIME() END, CASE WHEN @Forced = 1 THEN SYSUTCDATETIME() END, SYSUTCDATETIME(), @By);
    COMMIT;
END
'@
}

function Save-SIIndexBuildRow {
    <# Records one index's state (waiting | building | paused | built | failed). 'paused': a resumable build paused (an
       update went first, or its window ended) -- resumed in a later idle window. Never throws; $true when written. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$Index,
          [Parameter(Mandatory)][ValidateSet('waiting', 'building', 'paused', 'built', 'failed')][string]$State, [string]$Statement, $Pages, $EstMinutes,
          [string]$Source, [string]$Why = '', [switch]$Forced, [string]$By = 'caj-si-updater')
    $nz = { param($v) if ($null -eq $v -or "$v" -eq '') { [DBNull]::Value } else { $v } }
    $w = "$Why"; if ($w.Length -gt 1000) { $w = $w.Substring(0, 1000) }
    $src = "$Source"; if ($src.Length -gt 200) { $src = $src.Substring(0, 200) }
    try {
        $null = & $Invoke (Get-SIIndexBuildSaveSql) ([ordered]@{ T = $Table; I = $Index; Stmt = (& $nz $Statement); State = $State; Pages = (& $nz $Pages); Est = (& $nz $EstMinutes)
                                                      Src = (& $nz $src); Why = $w; Forced = [int][bool]$Forced; By = $By }) 'nonquery'
        $true
    } catch { $false }
}

function Read-SIIndexBuildRows {
    <# Every row of cfg.IndexBuild (none when the table is not there). Throws on a read error -- the caller decides. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $sql = "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.IndexBuild') IS NOT NULL SELECT TableName, IndexName, Statement, State, Pages, EstMinutes, RateSource, Why, SinceUtc, LastStartUtc, LastEndUtc, ForcedUtc FROM cfg.IndexBuild;"
    @(Get-SIIndexReaderRows (& $Invoke $sql @{} 'reader') | ForEach-Object {
        $r = $_
        $d = { param($n) $v = Get-SIIndexRowValue $r $n; if ($null -eq $v -or $v -is [DBNull]) { $null } else { ([datetime]$v) } }
        $i = { param($n) $v = Get-SIIndexRowValue $r $n; if ($null -eq $v -or $v -is [DBNull]) { $null } else { [long]$v } }
        [pscustomobject]@{ Table = [string](Get-SIIndexRowValue $r 'TableName'); Name = [string](Get-SIIndexRowValue $r 'IndexName'); Statement = [string](Get-SIIndexRowValue $r 'Statement')
                           State = [string](Get-SIIndexRowValue $r 'State'); Pages = (& $i 'Pages'); EstMinutes = (& $i 'EstMinutes'); Source = [string](Get-SIIndexRowValue $r 'RateSource')
                           Why = [string](Get-SIIndexRowValue $r 'Why'); SinceUtc = (& $d 'SinceUtc'); LastStartUtc = (& $d 'LastStartUtc'); LastEndUtc = (& $d 'LastEndUtc'); ForcedUtc = (& $d 'ForcedUtc') }
    })
}

function Get-SIIndexBuildStatusLines {
    <# PURE. What the status says about the indexes that wait or build (none = no line). #>
    param([object[]]$Rows = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    @($Rows | Where-Object { $_ -and $_.State -in @('waiting', 'building', 'paused', 'failed') } | Sort-Object SinceUtc | ForEach-Object {
        $r = $_   # (inside switch, $_ is the switch's own value)
        $est = if ($r.EstMinutes) { 'about {0}' -f (Format-SIIndexDuration ([int]$r.EstMinutes)) } else { 'time not known' }
        switch ([string]$r.State) {
            'building' { 'index {0} on {1}: being built now ({2}, started {3:yyyy-MM-dd HH:mm}Z)' -f $r.Name, $r.Table, $est, $r.LastStartUtc }
            'paused'   { 'index {0} on {1}: paused ({2}) -- it resumes in the next idle window; the release works without it' -f $r.Name, $r.Table, $(if ("$($r.Why)".Trim()) { $r.Why } else { 'an update went first' }) }
            'failed'   { 'index {0} on {1}: the build failed ({2}) -- the next update tries again' -f $r.Name, $r.Table, $r.Why }
            default    { 'index {0} on {1}: waits for an idle window of {2} (waiting since {3:yyyy-MM-dd HH:mm}Z); the release works without it' -f $r.Name, $r.Table, $est, $r.SinceUtc }
        }
    })
}

# =====================================================================================================================
#  The window -- PURE
# =====================================================================================================================
function Test-SIIndexBuildFiltered {
    <# PURE. Is -Statement (a stored CREATE INDEX) a FILTERED index -- a WHERE after its column list? A filtered index cannot
       be built resumably (SQL Server refuses RESUMABLE for it), so it cannot pause. The same rule as SI-ProSchema.ps1's
       Test-SIProSchemaIndexFiltered, on the statement text alone. #>
    param([AllowNull()][AllowEmptyString()][string]$Statement)
    [bool]("$Statement" -match '(?is)^\s*CREATE\b.*?\bON\b.*?\)\s*(INCLUDE\s*\([^)]*\)\s*)?WHERE\b')
}

function Test-SIIndexBuildColumnstore {
    <# PURE. #1316 Is -Statement a CREATE [NONCLUSTERED] COLUMNSTORE INDEX? SQL Server builds a columnstore index online but
       never resumably, so -- like a filtered one -- it cannot pause: it starts only when its estimate fits the window. #>
    param([AllowNull()][AllowEmptyString()][string]$Statement)
    [bool]("$Statement" -match '(?is)^\s*CREATE\s+(?:NONCLUSTERED\s+)?COLUMNSTORE\s+INDEX\b')
}

function Test-SIIndexBuildJobStartedRecently {
    <# PURE. Did an execution of the index build job START within GapRetryMinutes (ARM executions: properties.startTime)? A
       start that cannot be read counts as recent -- a scheduled run is then never held on a guess. #>
    param([object[]]$Executions = @(), [Parameter(Mandatory)][datetime]$NowUtc, [int]$Minutes = $script:SIIndexBuild.GapRetryMinutes)
    $now = $NowUtc.ToUniversalTime()
    foreach ($e in @($Executions)) {
        if (-not $e) { continue }
        $p = $e.PSObject.Properties['properties']; if (-not $p -or -not $p.Value) { return $true }
        $st = $p.Value.PSObject.Properties['startTime']
        if (-not $st -or -not "$($st.Value)".Trim()) { return $true }
        $t = [datetime]::MinValue
        if ($st.Value -is [datetime]) { $t = ([datetime]$st.Value).ToUniversalTime() }
        elseif (-not [datetime]::TryParse("$($st.Value)", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$t)) { return $true }
        if (($now - $t).TotalMinutes -lt $Minutes) { return $true }
    }
    $false
}

function Read-SIIndexBuildGapHold {
    <# Review item 6: when this install's last scheduled run was held for an index (cfg.InstallState 'IndexGapHold', ISO UTC
       text), or $null. Unreadable = now (a run is never held on a guess). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        $v = [string](& $Invoke "SET NOCOUNT ON; SELECT CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN NULL ELSE (SELECT TOP (1) Value FROM cfg.InstallState WHERE Name = N'IndexGapHold') END;" @{} 'scalar')
        if (-not "$v".Trim()) { return $null }
        $t = [datetime]::MinValue
        if ([datetime]::TryParse($v, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$t)) { return $t }
        $NowUtc.ToUniversalTime()
    } catch { $NowUtc.ToUniversalTime() }
}

function Save-SIIndexBuildGapHold {
    <# Records that this install's scheduled run is held for an index now (cfg.InstallState 'IndexGapHold'). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [datetime]$NowUtc = [datetime]::UtcNow)
    try {
        $null = & $Invoke "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.InstallState') IS NULL RETURN; UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'caj-si-flow' WHERE Name = N'IndexGapHold'; IF @@ROWCOUNT = 0 INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'IndexGapHold', @Value, N'caj-si-flow');" @{ Value = $NowUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } 'nonquery'
        $true
    } catch { $false }
}

function Get-SIIndexBuildWindowDecision {
    <#
        PURE. Does this wake-up start the index build job (caj-si-index-build) for a waiting or paused index? -Rows
        (cfg.IndexBuild), -NowUtc, -NextRunUtc (the next scheduled pipeline run; $null = none scheduled), -Busy
        (Get-SIDataHousekeepingBusy: Busy, Why), -UpdaterRunning (an updater execution runs; '' = none), -UpdateWaits (the
        updater's wait mark is set: an update waits to install; '' = none), -IndexJobRunning (an execution of the index build
        job runs; '' = none), -RunDue (a run starts / runs / resumes at this wake-up).
        THE UPDATE GOES FIRST: never while an update waits or runs.
        A resumable index (a paused build, or a statement without a filter) starts when the window has at least ResumeMinutes:
        it builds for the window's minutes (MAX_DURATION) and pauses at its end. A filtered one starts only when its estimate
        fits the window -- or, after WaitDays of waiting, ONCE whatever the window (the next run waits for it).
        A row still 'building' while no index build job runs is a build that ended without an outcome: it is a candidate again.
        THE GAP BEFORE A RUN (#1316 follow-up, for installs whose runs go back to back): -StartDue = a SCHEDULED run would
        start at this wake-up (no run runs or resumes, no Run now asked; also the first run after an update). An index that
        has waited GapAfterHours, was not started in the last GapEveryHours (its LastStartUtc) and whose job did not start in
        the last GapRetryMinutes (-IndexJobStartedRecently) is built FIRST and the run starts late (HoldsRun = $true: this
        wake-up starts no run; the job takes the install's lock, the run waits for it, never cancelled): a resumable one for
        GapLateMinutes (it pauses there), a non-resumable one (filtered, columnstore) only when its estimate fits GapLateMinutes,
        or ONCE after WaitDays whatever its estimate. Never while an update waits or runs, never during a data sync / data out
        / an open step (-Busy).
        Returns @{ Start; Force; Index (the row); Why; Minutes (the window, 0 = no run scheduled); Resumable; HoldsRun }. One
        index per window: the one that has waited longest.
    #>
    param([object[]]$Rows = @(), [Parameter(Mandatory)][datetime]$NowUtc, $NextRunUtc, $Busy, [AllowEmptyString()][string]$UpdaterRunning = '',
          [AllowEmptyString()][string]$UpdateWaits = '', [AllowEmptyString()][string]$IndexJobRunning = '', [bool]$RunDue = $false,
          [bool]$StartDue = $false, [bool]$IndexJobStartedRecently = $false, $LastGapHoldUtc = $null)
    $S = $script:SIIndexBuild
    $no = { param($why, $row) [pscustomobject]@{ Start = $false; Force = $false; Index = $row; Why = $why; Minutes = 0; Resumable = $false; HoldsRun = $false } }
    $now = $NowUtc.ToUniversalTime()
    $jobRuns = [bool]"$IndexJobRunning".Trim()
    $states = @('waiting', 'paused'); if (-not $jobRuns) { $states += 'building' }
    $cand = @($Rows | Where-Object { $_ -and $_.State -in $states -and "$($_.Statement)".Trim() } | Sort-Object { if ($_.SinceUtc) { ([datetime]$_.SinceUtc).ToUniversalTime() } else { [datetime]::MaxValue } })
    if (-not $cand.Count) { return (& $no '' $null) }
    $row = $cand[0]
    if ($RunDue) { return (& $no 'a pipeline run starts or runs now' $row) }
    if ("$UpdateWaits".Trim()) { return (& $no ('an update waits ({0}) -- the update goes first' -f $UpdateWaits) $row) }
    if ("$UpdaterRunning".Trim()) { return (& $no ('the updater runs ({0}) -- the update goes first' -f $UpdaterRunning) $row) }
    if ($jobRuns) { return (& $no ('the index build job runs ({0})' -f $IndexJobRunning) $row) }
    if ($Busy -and $Busy.Busy) { return (& $no ('{0}' -f $Busy.Why) $row) }
    $since = if ($row.SinceUtc) { ([datetime]$row.SinceUtc).ToUniversalTime() } else { $now }
    $waitedDays = ($now - $since).TotalDays
    $est = if ($row.EstMinutes) { [int]$row.EstMinutes } else { 0 }
    $next = if ($NextRunUtc) { ([datetime]$NextRunUtc).ToUniversalTime() } else { $null }
    $room = if ($next) { ($next - $now).TotalMinutes - $S.LeadMinutes } else { [double]::MaxValue }
    $win = if ($next) { [int][Math]::Max(0, [Math]::Floor($room)) } else { 0 }
    $after = if ($row.State -eq 'building') { ' (its last build ended without an outcome)' } else { '' }
    # #1316: a columnstore index cannot be built resumably either -- it is taken like a filtered one (its estimate must fit)
    $resumable = ($row.State -eq 'paused') -or -not ((Test-SIIndexBuildFiltered -Statement $row.Statement) -or (Test-SIIndexBuildColumnstore -Statement $row.Statement))
    if ($StartDue) {
        # THE GAP BEFORE A SCHEDULED RUN (see above): the index goes first, the run starts late -- bounded and at most once a day
        $lastStart = if ($row.LastStartUtc) { ([datetime]$row.LastStartUtc).ToUniversalTime() } else { $null }
        # STABILITY (review item 6): at most ONE late run a day for the INSTALL (not per index) -- -LastGapHoldUtc: when this
        # install's last run was held for an index (cfg.InstallState 'IndexGapHold')
        if ($null -ne $LastGapHoldUtc -and ($now - ([datetime]$LastGapHoldUtc).ToUniversalTime()).TotalHours -lt $S.GapEveryHours) { return (& $no ('a scheduled run starts now; a run of this install was already held for an index at {0:yyyy-MM-dd HH:mm}Z -- at most one late run a day' -f ([datetime]$LastGapHoldUtc).ToUniversalTime()) $row) }
        if (($now - $since).TotalHours -lt $S.GapAfterHours) { return (& $no ('a scheduled run starts now; the index has waited less than {0} h -- it waits for an idle window' -f $S.GapAfterHours) $row) }
        if ($lastStart -and ($now - $lastStart).TotalHours -lt $S.GapEveryHours) { return (& $no ('a scheduled run starts now; the index was last started {0:yyyy-MM-dd HH:mm}Z -- at most one late run a day for it' -f $lastStart) $row) }
        if ($IndexJobStartedRecently) { return (& $no ('a scheduled run starts now; the index build job started less than {0} min ago -- the run is not held again' -f $S.GapRetryMinutes) $row) }
        $gm = [int]$S.GapLateMinutes
        $late = 'the next run starts late, after it (at most {0})' -f (Format-SIIndexDuration $gm)
        if ($resumable) {
            $how = if ($row.State -eq 'paused') { 'resumed' } else { 'built resumably' }
            return [pscustomobject]@{ Start = $true; Force = $false; Index = $row; Resumable = $true; HoldsRun = $true; Minutes = $gm; Cap = $true
                                      Why = ('{0} in the gap before the scheduled run -- the runs go back to back, no idle window came in {1} h; {2}; it pauses there{3}' -f $how, [int][Math]::Floor(($now - $since).TotalHours), $late, $after) }
        }
        if ($est -gt 0 -and $est -le $gm) {
            return [pscustomobject]@{ Start = $true; Force = $false; Index = $row; Resumable = $false; HoldsRun = $true; Minutes = $gm; Cap = $true
                                      Why = ('about {0}, built in the gap before the scheduled run -- the runs go back to back, no idle window came in {1} h; the next run starts late, after it{2}' -f (Format-SIIndexDuration $est), [int][Math]::Floor(($now - $since).TotalHours), $after) }
        }
        if ($waitedDays -ge $S.WaitDays -and -not $row.ForcedUtc) {
            return [pscustomobject]@{ Start = $true; Force = $true; Index = $row; Resumable = $false; HoldsRun = $true; Minutes = $gm; Cap = $true
                                      Why = ('it has waited {0} days without an idle window long enough ({1}); it is built now, once, in the gap before the scheduled run -- the next run starts late, after it, at most {2} (a build not done by then is stopped and tried again in an idle window, where it may take as long as it needs)' -f [int][Math]::Floor($waitedDays), $(if ($est) { 'about ' + (Format-SIIndexDuration $est) } else { 'its time is not known' }), (Format-SIIndexDuration $gm)) }
        }
        return (& $no ('a scheduled run starts now; the index needs {0}, more than the {1} a run may start late -- it waits (built once after {2} days)' -f $(if ($est) { 'about ' + (Format-SIIndexDuration $est) } else { 'a time that is not known' }), (Format-SIIndexDuration $gm), $S.WaitDays) $row)
    }
    if ($resumable) {
        if ($room -ge $S.ResumeMinutes) {
            $how = if ($row.State -eq 'paused') { 'resumed' } else { 'built resumably' }
            $why = if ($next) { '{0} for up to {1} (it pauses at the end of the window; the next run starts {2:yyyy-MM-dd HH:mm}Z){3}' -f $how, (Format-SIIndexDuration $win), $next, $after }
                   else { '{0}, and no run is scheduled{1}' -f $how, $after }
            return [pscustomobject]@{ Start = $true; Force = $false; Index = $row; Why = $why; Minutes = $win; Resumable = $true; HoldsRun = $false }
        }
        return (& $no ('the window before the next run is shorter than {0} min' -f $S.ResumeMinutes) $row)
    }
    if ($est -gt 0 -and $est -le $room) {
        $why = if ($next) { 'about {0}, and the next run starts {1:yyyy-MM-dd HH:mm}Z{2}' -f (Format-SIIndexDuration $est), $next, $after } else { 'about {0}, and no run is scheduled{1}' -f (Format-SIIndexDuration $est), $after }
        return [pscustomobject]@{ Start = $true; Force = $false; Index = $row; Why = $why; Minutes = $win; Resumable = $false; HoldsRun = $false }
    }
    if ($waitedDays -ge $S.WaitDays -and -not $row.ForcedUtc) {
        $why = 'it has waited {0} days without an idle window long enough ({1}); it is built now, once, and the next run waits for it' -f [int][Math]::Floor($waitedDays), $(if ($est) { 'about ' + (Format-SIIndexDuration $est) } else { 'its time is not known' })
        return [pscustomobject]@{ Start = $true; Force = $true; Index = $row; Why = $why; Minutes = $win; Resumable = $false; HoldsRun = $false }
    }
    $left = if ($next) { 'the next run starts in {0}' -f (Format-SIIndexDuration ([int][Math]::Max(0, ($next - $now).TotalMinutes))) } else { 'no run is scheduled' }
    & $no ('it needs {0}; {1}' -f $(if ($est) { 'about ' + (Format-SIIndexDuration $est) } else { 'a time that is not known' }), $left) $row
}

# =====================================================================================================================
#  #1317 THE COLLECTION PARTITIONS in the same idle window (SI_Data_RetireByPartition, ON by default -- owner 2026-11-23;
#  off = today's paced removal only). The pipeline runner's
#  wake-up reads -- with the engine's own read rights, data only -- whether partition work waits, and starts the index
#  build job for it (SI_INDEXBUILD_PARTITIONS=1) by the same window rule as a resumable index. Set off = nothing here runs.
# =====================================================================================================================
function Test-SIIndexBuildPartitionSwitch {
    <# PURE. SI_Data_RetireByPartition: ON by default -- not set or empty = on; off only for $false / 0 / 'false' / 'off' /
       'no'. The same rule as engine\pro-settings\SI-ProPartitionMove.ps1 Test-SIPartitionSwitchOn (that file runs as the
       updater's identity and is not loaded by the runner). #>
    param($Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [bool]) { return $Value }
    -not (("$Value".Trim().ToLowerInvariant()) -in @('0', 'false', 'off', 'no', '$false'))
}

function Get-SIPartitionWorkSql {
    <#
        Does partition work wait? ONE value, 1 or 0 (data only; the runner's identity reads it): a large table whose move is
        not recorded done (and not blocked), fewer than @Low empty boundaries left above the newest collection id, or a
        retired Detailed collection still holding finding rows that the job has not already left to the paced removal
        (sidata.PartitionMove '(removal)'). A database without the tables = 0.
    #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.PartitionMove', N'U') IS NULL OR COL_LENGTH('sidata.Collection', 'RetiredAt') IS NULL BEGIN SELECT 0; RETURN; END
DECLARE @lw int = TRY_CONVERT(int, @Low); IF @lw IS NULL OR @lw < 1 SET @lw = 4;
DECLARE @skip nvarchar(1000) = ISNULL((SELECT TOP (1) Note FROM sidata.PartitionMove WHERE TableName = N'(removal)'), N'');
SELECT CASE
    WHEN (SELECT COUNT(*) FROM sidata.PartitionMove WHERE TableName IN (N'Finding', N'Recommendation', N'IssueContext') AND State = N'done') < 3
         AND NOT EXISTS (SELECT 1 FROM sidata.PartitionMove WHERE TableName IN (N'Finding', N'Recommendation', N'IssueContext') AND State IN (N'blocked', N'gave-up', N'check-differs', N'waiting-space')) THEN 1
    WHEN ISNULL((SELECT TOP (1) ScopeRows FROM sidata.PartitionMove WHERE TableName = N'(boundaries)'), 0) < ISNULL((SELECT MAX(CollectionId) FROM sidata.Collection), 0) + @lw THEN 1
    WHEN EXISTS (SELECT 1 FROM sidata.Collection AS m WHERE m.Kind = N'Detailed' AND m.RetiredAt IS NOT NULL
                 AND CHARINDEX(CONCAT(N',', m.CollectionId, N','), @skip) = 0
                 AND EXISTS (SELECT 1 FROM sidata.Finding AS f WHERE f.CollectionId = m.CollectionId)) THEN 1
    ELSE 0 END;
'@
}

function Get-SIPartitionWorkRow {
    <# PURE. The partition work as one waiting, resumable row for Get-SIIndexBuildWindowDecision (the same window rule as a
       resumable index: at least ResumeMinutes before the next run; never during a run, an updater run or the job). #>
    param([Parameter(Mandatory)][datetime]$NowUtc)
    [pscustomobject]@{ Table = 'sidata.Finding'; Name = 'collection-partitions'; State = 'waiting'; Statement = 'the collection partitions'
                       SinceUtc = $NowUtc.ToUniversalTime(); EstMinutes = 0; ForcedUtc = $null; Why = '' }
}

# =====================================================================================================================
#  #1111 THE INDEX BUILD JOB's statements -- PURE
# =====================================================================================================================
function Test-SIIndexBuildName {
    <# PURE. -Table 'schema.table' and -Index a plain name (what Get-SIProSchemaIndexStatements ever records): $true when both
       are safe to put into a statement. #>
    param([string]$Table, [string]$Index)
    ("$Table" -match '^[A-Za-z_]\w{0,127}\.[A-Za-z_]\w{0,127}$') -and ("$Index" -match '^[A-Za-z_]\w{0,127}$')
}

function Get-SIIndexQuotedName {
    <# PURE. One identifier bracket-quoted: 'a]b' -> '[a]]b]' (every name this file puts into a statement, constants too). #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Name)
    '[' + $Name.Replace(']', ']]') + ']'
}

function Get-SIIndexSqlText {
    <# PURE. A value inside an N'...' literal: "'" -> "''". #>
    param([AllowEmptyString()][string]$Text)
    "$Text".Replace("'", "''")
}

function Get-SIIndexBuildQuotedTable {
    <# PURE. 'sidata.Finding' -> '[sidata].[Finding]' (callers check Test-SIIndexBuildName first; ']' escaped all the same). #>
    param([Parameter(Mandatory)][string]$Table)
    $p = $Table -split '\.', 2
    '{0}.{1}' -f (Get-SIIndexQuotedName $p[0]), (Get-SIIndexQuotedName $p[1])
}

function Get-SIIndexBuildRunSql {
    <#
        PURE. What the index build job runs for one row: -ResumableState = the index's resumable operation now ('PAUSED',
        'RUNNING' or ''), -Minutes = the window (MAX_DURATION; at least 1).
          PAUSED                      -> ALTER INDEX [i] ON [s].[t] RESUME WITH (MAX_DURATION = n MINUTES)
          a filtered index            -> its CREATE ... WITH (ONLINE = ON)   (it cannot pause: no RESUMABLE, no MAX_DURATION)
          any other                   -> its CREATE ... WITH (ONLINE = ON, RESUMABLE = ON, MAX_DURATION = n MINUTES)
        The stored statement's own trailing WITH (...) is replaced. Returns @{ Sql; Resumable; How }; Sql '' when the names
        are not safe or the statement is not a CREATE INDEX of this index.
    #>
    # -OnPartitionScheme (#1316 x #1317): a columnstore index of the list on a table that is on PS_SICollection is created
    # ALIGNED -- ... WITH (ONLINE = ON) ON PS_SICollection ([CollectionId]) -- so TRUNCATE ... WITH (PARTITIONS) keeps working
    param([Parameter(Mandatory)]$Row, [AllowEmptyString()][string]$ResumableState = '', [int]$Minutes = 60, [switch]$OnPartitionScheme)
    $m = [Math]::Max(1, $Minutes)
    $none = [pscustomobject]@{ Sql = ''; Resumable = $false; How = '' }
    if (-not (Test-SIIndexBuildName -Table ([string]$Row.Table) -Index ([string]$Row.Name))) { return $none }
    $qt = Get-SIIndexBuildQuotedTable -Table ([string]$Row.Table)
    if ($ResumableState -eq 'PAUSED') {
        return [pscustomobject]@{ Sql = ('ALTER INDEX {0} ON {1} RESUME WITH (MAX_DURATION = {2} MINUTES)' -f (Get-SIIndexQuotedName ([string]$Row.Name)), $qt, $m); Resumable = $true; How = 'resumed (resumable: it pauses at the end of its window)' }
    }
    $base = ([string]$Row.Statement).Trim().TrimEnd(';').TrimEnd()
    $base = ($base -replace '(?is)\s+WITH\s*\([^()]*\)\s*$', '').TrimEnd()
    $head = '(?is)^CREATE\s+(?:UNIQUE\s+)?(?:NONCLUSTERED\s+)?(?:COLUMNSTORE\s+)?INDEX\s+\[?' + [regex]::Escape([string]$Row.Name) + '\]?\s+ON\s+'
    if ($base -notmatch $head -or $base -match ';') { return $none }
    if (Test-SIIndexBuildFiltered -Statement $base) { return [pscustomobject]@{ Sql = ('{0} WITH (ONLINE = ON)' -f $base); Resumable = $false; How = 'built online (a filtered index cannot pause)' } }
    # #1316: a nonclustered COLUMNSTORE index (only SI's own, SI_Data_ColumnstoreIndexes) -- online, never resumable
    if (Test-SIIndexBuildColumnstore -Statement $base) {
        if ($OnPartitionScheme -and (Test-SIColumnstoreIndexName -Table ([string]$Row.Table) -Index ([string]$Row.Name)) -and $base -notmatch '(?is)\)\s*ON\s+\[?\w+\]?\s*\(') {
            $S = $script:SIColumnstore
            return [pscustomobject]@{ Sql = ('{0} WITH (ONLINE = ON) ON {1} ({2})' -f $base, (Get-SIIndexQuotedName $S.Scheme), (Get-SIIndexQuotedName $S.SchemeColumn)); Resumable = $false; How = ('built online, aligned on the collection partitions ({0}; a columnstore index cannot pause)' -f $S.Scheme) }
        }
        return [pscustomobject]@{ Sql = ('{0} WITH (ONLINE = ON)' -f $base); Resumable = $false; How = 'built online (a columnstore index cannot pause)' }
    }
    [pscustomobject]@{ Sql = ('{0} WITH (ONLINE = ON, RESUMABLE = ON, MAX_DURATION = {1} MINUTES)' -f $base, $m); Resumable = $true; How = 'built online, resumable (it pauses at the end of its window)' }
}

function Get-SIIndexBuildPauseSql {
    <# PURE. The pause of a running resumable build (sent on a second connection while the build runs). '' = unsafe names. #>
    param([Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$Index)
    if (-not (Test-SIIndexBuildName -Table $Table -Index $Index)) { return '' }
    'ALTER INDEX {0} ON {1} PAUSE' -f (Get-SIIndexQuotedName $Index), (Get-SIIndexBuildQuotedTable -Table $Table)
}

function Get-SIIndexResumableOpSql {
    <# PURE. The one index's resumable operation (state, percent), where the view exists (one result set). #>
    @'
SET NOCOUNT ON;
DECLARE @b TABLE (S nvarchar(60) NOT NULL, P float NOT NULL);
IF OBJECT_ID(N'sys.index_resumable_operations') IS NOT NULL
  INSERT @b (S, P) EXEC sp_executesql N'SELECT CONVERT(nvarchar(60), state_desc), CONVERT(float, ISNULL(percent_complete, 0)) FROM sys.index_resumable_operations WHERE object_id = OBJECT_ID(@T) AND name = @I', N'@T nvarchar(300), @I nvarchar(128)', @T = @T, @I = @I;
SELECT S, P FROM @b;
'@
}

function Read-SIIndexResumableOp {
    <# The index's resumable operation: @{ State = PAUSED | RUNNING; Percent } or $null (none, or it cannot be read). Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$Index)
    try {
        $r = @(Get-SIIndexReaderRows (& $Invoke (Get-SIIndexResumableOpSql) ([ordered]@{ T = $Table; I = $Index }) 'reader'))
        if (-not $r.Count) { return $null }
        $s = [string](Get-SIIndexRowValue $r[0] 'S'); if (-not $s.Trim()) { return $null }
        [pscustomobject]@{ State = $s.Trim().ToUpperInvariant(); Percent = [int][Math]::Floor([double](Get-SIIndexRowValue $r[0] 'P')) }
    } catch { $null }
}

function Test-SIIndexExists {
    <# Is the index there now? $true / $false; $null when it cannot be read. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$Index)
    try {
        $n = @(Get-SIIndexReaderRows (& $Invoke "SET NOCOUNT ON; SELECT COUNT(*) AS N FROM sys.indexes WHERE name = @I AND object_id = OBJECT_ID(@T);" ([ordered]@{ I = $Index; T = $Table }) 'reader'))
        if (-not $n.Count) { return $false }
        [int](Get-SIIndexRowValue $n[0] 'N') -gt 0
    } catch { $null }
}

# =====================================================================================================================
#  One build -- its own connection, the lock beaten while it runs
# =====================================================================================================================
function Invoke-SIIndexBuildCommand {
    <#
        Runs ONE index statement on the open -Connection, outside any transaction, with no statement time limit (a build runs
        to its end or to its own MAX_DURATION), and calls -Beat { param($Minutes) } every BeatSeconds while it runs -- the
        install's lock and the progress line (a long build never leaves the lock looking abandoned). Throws the statement's
        own error. Returns the seconds it took.
        #1111: -Interrupt { param($Minutes) } -> '' or a reason, asked at every beat (the index build job: an update waits or
        runs, or the install's lock was taken). A reason = -OnInterrupt { param($Command, $Reason) } (a resumable build:
        ALTER INDEX ... PAUSE on a second connection; a filtered one: the command cancelled), then the statement is waited for
        (up to -DrainSeconds) and an OperationCanceledException is thrown whose Data['SIInterrupted'] is the reason.
    #>
    param([Parameter(Mandatory)]$Connection, [Parameter(Mandatory)][string]$Sql, [scriptblock]$Beat, [int]$BeatSeconds = $script:SIIndexBuild.BeatSeconds,
          [scriptblock]$Interrupt, [scriptblock]$OnInterrupt, [int]$DrainSeconds = 300)
    $cmd = $Connection.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $task = $cmd.ExecuteNonQueryAsync()
    try {
        while (-not $task.Wait([Math]::Max(1, $BeatSeconds) * 1000)) {
            if ($Beat) { try { $null = & $Beat ([int][Math]::Floor($sw.Elapsed.TotalMinutes)) } catch { } }
            $why = ''
            if ($Interrupt) { try { $why = [string](& $Interrupt ([int][Math]::Floor($sw.Elapsed.TotalMinutes))) } catch { $why = '' } }
            if ("$why".Trim()) {
                if ($OnInterrupt) { try { $null = & $OnInterrupt $cmd $why } catch { } } else { try { $cmd.Cancel() } catch { } }
                try { $null = $task.Wait([Math]::Max(1, $DrainSeconds) * 1000) } catch { }
                $x = New-Object System.OperationCanceledException ('the index build was interrupted: {0}' -f $why)
                $x.Data['SIInterrupted'] = "$why"
                throw $x
            }
        }
    } catch [System.OperationCanceledException] {
        if ($_.Exception.Data.Contains('SIInterrupted')) { throw $_.Exception }
        $e = $_.Exception
        while (($e -is [System.Management.Automation.MethodInvocationException] -or $e -is [System.AggregateException]) -and $e.InnerException) { $e = $e.InnerException }
        throw $e
    } catch {
        # PowerShell hands the task's failure as a MethodInvocationException around an AggregateException: the SQL error inside
        $e = $_.Exception
        while (($e -is [System.Management.Automation.MethodInvocationException] -or $e -is [System.AggregateException]) -and $e.InnerException) { $e = $e.InnerException }
        throw $e
    }
    $sw.Stop()
    $sw.Elapsed.TotalSeconds
}

# =====================================================================================================================
#  #1316 COLUMNSTORE ON THE READ-HEAVY TABLES (SCALE-2, REQUIREMENTS #1314 / #1316) -- behind ONE setting, ON by default
# =====================================================================================================================
#  The data sync's summary groups, key figures and changes phases SCAN and AGGREGATE a whole collection of sidata.Finding
#  (GROUP BY asset / issue / report, SUM / MIN / MAX / COUNT DISTINCT) and the key figures scan sidata.CiFindingState (opened /
#  fixed / time to fix). A large install's database sat at its limit 40 % of a 97 h run, bound by PHYSICAL READS. A
#  NONCLUSTERED COLUMNSTORE index on the columns those statements read lets SQL Server read compressed column segments in
#  batch mode instead of every row's pages. It is an INDEX: no statement is changed and no result can change (prio 1); SQL
#  Server picks it only where it is cheaper. Rollback = the setting off: the next update drops the index.
#  THE SETTING SI_Data_ColumnstoreIndexes, solution setting, default ON (owner 2026-11-23: new features ship on). Not set =
#  on; false / off = the rollback below.
#  WHO: the UPDATER on every run (Invoke-SIColumnstoreIndexStep, from Invoke-SIUpdaterIndexBuildJob) records a missing index
#  as 'waiting' in cfg.IndexBuild with its statement and its estimate; the INDEX BUILD JOB caj-si-index-build builds it in an
#  idle window (ONLINE; a columnstore index cannot pause, so it is taken like a filtered one). The updater never builds one
#  itself; nothing else creates them. Off: the updater removes a waiting row and drops a built index of THIS list only; the
#  job refuses a waiting row of this list while the setting is off. Azure SQL Database: only from Standard S3 (and every
#  Premium / vCore size) -- a smaller size records nothing and says why.
#  RISK (#1314 (6e)): a later schema change that ALTERs or DROPs a column inside one of these indexes is refused by SQL Server
#  while the index is there -- the columns are SI's stable key columns; such a change drops the index first.
$script:SIColumnstore = @{
    Setting = 'SI_Data_ColumnstoreIndexes'
    Indexes = @(
        # every column the three phases' statements read from a collection's findings (no MAX column: a nonclustered
        # columnstore index takes none)
        # Partitioned: the table is one of #1317's (PS_SICollection) -- its index waits while the table's move is pending and is
        # then built ALIGNED on the scheme (see "COLUMNSTORE x PARTITIONS" below)
        [pscustomobject]@{ Table = 'sidata.Finding'; Name = 'NCCI_Finding_Load'; Partitioned = $true
                           Columns = @('CollectionId', 'FindingId', 'AssetKey', 'AssetName', 'ReportName', 'SecurityDomain', 'ConfigurationId', 'Cve', 'Title', 'Severity',
                                       'Tier', 'RiskScore', 'RiskRating', 'ExemptionId', 'HasExploit', 'DepartmentId', 'Category', 'Subcategory', 'CiLifecycle', 'EosStatus',
                                       'FixDueDate', 'SourceFirstDetected') }
        # the finding lifecycle the key figures count (opened / fixed in N days, the mean time to fix)
        # (not partitioned: CiFindingState is one row per finding on a CI, never per collection -- never held, never aligned)
        [pscustomobject]@{ Table = 'sidata.CiFindingState'; Name = 'NCCI_CiFindingState_Load'; Partitioned = $false
                           Columns = @('OwnerKey', 'FindingKey', 'CiId', 'State', 'FirstDetected', 'ClosedAt', 'CloseReason', 'Severity') }
    )
    # Azure SQL Database service objectives without columnstore (Basic, S0-S2); every other size and every other engine has it
    NoColumnstore = @('Basic', 'S0', 'S1', 'S2', 'System', 'System0', 'System1', 'System2')
    DropLockMs = 10000
    # #1317's partition scheme and its column (an index of a Partitioned table is built ON it once the table is there)
    Scheme = 'PS_SICollection'; SchemeColumn = 'CollectionId'
}

function Get-SIColumnstoreContract { $script:SIColumnstore }

function Test-SIColumnstoreSettingOn {
    <# PURE. The setting's stored value (cfg.Setting ValueJson, or a plain value) -> on? false / "off" / 0 / no = OFF; anything
       else -- empty, not set, true, a typo -- is ON (the default, owner 2026-11-23). #>
    param($Value)
    if ($null -eq $Value -or $Value -is [DBNull]) { return $true }
    if ($Value -is [bool]) { return $Value }
    $v = ("$Value".Trim() -replace '^"|"$', '').Trim().ToLowerInvariant()
    -not ($v -in @('false', 'off', '0', 'no'))
}

function Read-SIColumnstoreSetting {
    <# The install's setting (cfg.Setting, solution scope): @{ Known; On }. Known = $false when it cannot be read -- then
       NOTHING is queued, removed or dropped on a guess. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    try {
        $r = @(Get-SIIndexReaderRows (& $Invoke "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.Setting') IS NOT NULL SELECT ValueJson FROM cfg.Setting WHERE Name = @N AND Scope = N'solution';" ([ordered]@{ N = $script:SIColumnstore.Setting }) 'reader'))
        $v = if ($r.Count) { Get-SIIndexRowValue $r[0] 'ValueJson' } else { $null }
        [pscustomobject]@{ Known = $true; On = (Test-SIColumnstoreSettingOn -Value $v) }
    } catch { [pscustomobject]@{ Known = $false; On = $false } }
}

function Test-SIColumnstoreIndexName {
    <# PURE. Is -Table / -Index one of THIS list's columnstore indexes (the only ones the updater may remove or drop)? #>
    param([string]$Table, [string]$Index)
    [bool](@($script:SIColumnstore.Indexes | Where-Object { $_.Table -ieq $Table -and $_.Name -ieq $Index }).Count)
}

function Get-SIColumnstoreStatement {
    <# PURE. The CREATE statement of one index of the list (no WITH: the index build job adds ONLINE = ON). #>
    param([Parameter(Mandatory)]$Index)
    'CREATE NONCLUSTERED COLUMNSTORE INDEX {0} ON {1} ({2})' -f (Get-SIIndexQuotedName ([string]$Index.Name)), (Get-SIIndexBuildQuotedTable -Table ([string]$Index.Table)),
        (@($Index.Columns | ForEach-Object { Get-SIIndexQuotedName ([string]$_) }) -join ', ')
}

function Test-SIColumnstoreSupported {
    <# PURE. Does this database take a columnstore index? -EngineEdition (SERVERPROPERTY: 5 = Azure SQL Database, 8 = Managed
       Instance, 2/3/4 = SQL Server Standard / Enterprise / Express), -Objective (DATABASEPROPERTYEX ServiceObjective, Azure SQL
       Database only). @{ Ok; Why }. #>
    param([AllowEmptyString()][string]$EngineEdition, [AllowEmptyString()][string]$Objective)
    $e = "$EngineEdition".Trim(); $o = "$Objective".Trim()
    if ($e -eq '5') {
        if (-not $o) { return [pscustomobject]@{ Ok = $false; Why = 'the database''s size could not be read' } }
        if (@($script:SIColumnstore.NoColumnstore) -contains $o) { return [pscustomobject]@{ Ok = $false; Why = ('the database''s size {0} does not support columnstore indexes (Standard S3 or above does)' -f $o) } }
        return [pscustomobject]@{ Ok = $true; Why = ('size {0}' -f $o) }
    }
    if ($e -in @('2', '3', '4', '8')) { return [pscustomobject]@{ Ok = $true; Why = ('engine edition {0}' -f $e) } }
    [pscustomobject]@{ Ok = $false; Why = ('the engine edition ({0}) is not known to support columnstore indexes' -f $(if ($e) { $e } else { 'not read' })) }
}

function Get-SIColumnstoreStateSql {
    <# ONE read: the engine edition and size (K 'db'), and per index of the list whether it is there (K 'ix', A = 'table|name',
       N = 1 / 0) and whether every one of its columns is there yet (K 'cols', N = the columns missing). Catalog only. #>
    $parts = New-Object System.Collections.Generic.List[string]
    $parts.Add("SELECT N'db' AS K, CONVERT(nvarchar(300), SERVERPROPERTY('EngineEdition')) AS A, CONVERT(nvarchar(300), DATABASEPROPERTYEX(DB_NAME(), 'ServiceObjective')) AS B, CONVERT(int, 0) AS N")
    foreach ($ix in @($script:SIColumnstore.Indexes)) {
        $key = '{0}|{1}' -f $ix.Table, $ix.Name
        $qtab = Get-SIIndexSqlText (Get-SIIndexBuildQuotedTable -Table ([string]$ix.Table))
        $parts.Add(("SELECT N'ix', N'{0}', N'', CASE WHEN EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'{1}' AND object_id = OBJECT_ID(N'{2}')) THEN 1 ELSE 0 END" -f (Get-SIIndexSqlText $key), (Get-SIIndexSqlText ([string]$ix.Name)), $qtab))
        $miss = @($ix.Columns | ForEach-Object { "CASE WHEN COL_LENGTH(N'{0}', N'{1}') IS NULL THEN 1 ELSE 0 END" -f $qtab, (Get-SIIndexSqlText ([string]$_)) }) -join ' + '
        $parts.Add(("SELECT N'cols', N'{0}', N'', {1}" -f (Get-SIIndexSqlText $key), $miss))
    }
    "SET NOCOUNT ON;`n" + ($parts -join "`nUNION ALL`n") + ';'
}

function Read-SIColumnstoreState {
    <# @{ Supported (@{ Ok; Why }); Exists (hashtable 'table|name' -> bool); Missing ('table|name' -> columns missing) }, or
       $null when it cannot be read. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    try {
        $st = [pscustomobject]@{ Supported = $null; Exists = @{}; Missing = @{} }
        $ed = ''; $ob = ''
        foreach ($r in @(Get-SIIndexReaderRows (& $Invoke (Get-SIColumnstoreStateSql) @{} 'reader'))) {
            $k = [string](Get-SIIndexRowValue $r 'K'); $a = [string](Get-SIIndexRowValue $r 'A'); $n = Get-SIIndexRowValue $r 'N'
            switch ($k) {
                'db'   { $ed = $a; $b = Get-SIIndexRowValue $r 'B'; $ob = if ($null -eq $b -or $b -is [DBNull]) { '' } else { [string]$b } }
                'ix'   { $st.Exists[$a.ToLowerInvariant()] = ([int]$n -gt 0) }
                'cols' { $st.Missing[$a.ToLowerInvariant()] = [int]$n }
            }
        }
        $st.Supported = Test-SIColumnstoreSupported -EngineEdition $ed -Objective $ob
        $st
    } catch { $null }
}

function Get-SIColumnstorePlan {
    <#
        PURE. What the updater does for each index of the list. -Setting @{ Known; On }; -State (Read-SIColumnstoreState);
        -Rows (cfg.IndexBuild). Returns one @{ Index; Action; Why } per index:
          queue       setting on, supported, not there, its columns there, no row waiting / paused / building -> 'waiting'
          remove-row  setting off (or the size does not take it): its waiting / failed / built row goes (never one that builds
                      or is paused -- the job owns that; the next update looks again)
          drop        setting off and the index is there -> DROP INDEX (the rollback)
          none        nothing to do (said why)
        The setting not readable (Known $false) or the state not readable = 'none' for every index: nothing on a guess.
    #>
    param([Parameter(Mandatory)]$Setting, $State, [object[]]$Rows = @())
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($ix in @($script:SIColumnstore.Indexes)) {
        $key = ('{0}|{1}' -f $ix.Table, $ix.Name).ToLowerInvariant()
        $row = @($Rows | Where-Object { $_ -and [string]$_.Table -ieq $ix.Table -and [string]$_.Name -ieq $ix.Name })[0]
        $one = { param($a, $w) $out.Add([pscustomobject]@{ Index = $ix; Action = $a; Why = $w }) }
        if (-not $Setting.Known) { & $one 'none' 'the setting could not be read -- nothing changed'; continue }
        if ($null -eq $State) { & $one 'none' 'the database could not be read -- nothing changed'; continue }
        $there = [bool]$State.Exists[$key]
        $rowState = if ($row) { [string]$row.State } else { '' }
        $owned = $rowState -in @('building', 'paused')
        if (-not $Setting.On -or -not $State.Supported.Ok) {
            $why = if (-not $Setting.On) { 'the setting is off' } else { $State.Supported.Why }
            if ($there -and -not $Setting.On) { & $one 'drop' ('{0}: the index is dropped (the rollback)' -f $why); continue }
            if ($row -and -not $owned) { & $one 'remove-row' ('{0}: its waiting row is removed' -f $why); continue }
            & $one 'none' $(if ($owned) { '{0}: it is being built -- the next update looks again' -f $why } else { $why }); continue
        }
        if ($there) { & $one 'none' 'there'; continue }
        if ([int]$State.Missing[$key] -gt 0) { & $one 'none' ('{0} of its columns are not there yet -- the next update records it' -f [int]$State.Missing[$key]); continue }
        if ($rowState -in @('waiting', 'paused', 'building')) { & $one 'none' ('it {0} for the index build job' -f $(if ($rowState -eq 'waiting') { 'waits' } else { 'is ' + $rowState })); continue }
        & $one 'queue' 'the setting is on -- recorded for the index build job (an idle window)'
    }
    $out.ToArray()
}

function Get-SIColumnstoreRemoveRowSql {
    <# One cfg.IndexBuild row of the list removed (never one that is building or paused). #>
    "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.IndexBuild') IS NOT NULL DELETE FROM cfg.IndexBuild WHERE TableName = @T AND IndexName = @I AND State NOT IN (N'building', N'paused');"
}

function Get-SIColumnstoreDropSql {
    <# PURE. The rollback of one index of the list; '' for any other name. A lock that does not come within DropLockMs = not now. #>
    param([Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$Index)
    if (-not (Test-SIColumnstoreIndexName -Table $Table -Index $Index) -or -not (Test-SIIndexBuildName -Table $Table -Index $Index)) { return '' }
    $qt = Get-SIIndexBuildQuotedTable -Table $Table
    "SET LOCK_TIMEOUT {0}; IF EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'{1}' AND object_id = OBJECT_ID(N'{2}') AND type = 6) DROP INDEX {3} ON {4};" -f [int]$script:SIColumnstore.DropLockMs, (Get-SIIndexSqlText $Index), (Get-SIIndexSqlText $qt), (Get-SIIndexQuotedName $Index), $qt
}

# =====================================================================================================================
#  #1316 x #1317 COLUMNSTORE x PARTITIONS -- ONE rule (2026-11-23, both features ON by default)
# =====================================================================================================================
#  sidata.Finding carries NCCI_Finding_Load (#1316) AND is moved onto PS_SICollection (#1317, SI_Data_RetireByPartition).
#  TRUNCATE ... WITH (PARTITIONS) needs every index of the table ALIGNED on the scheme, and the move copies only row-store
#  indexes. So:
#    1. ORDER: while sidata.Finding's move is PENDING (the switch on, the move's state table there, the table not on the
#       scheme yet, its move not 'blocked') the index waits -- the runner does not start the job for it, the job does not
#       build it, the update says it in one line. Once the table is on the scheme (or the switch is off, or the move is
#       blocked for another reason) it is built as usual -- ALIGNED (ON PS_SICollection ([CollectionId])) when the table is on
#       the scheme.
#    2. AN INDEX BUILT BEFORE (on the old table): the move drops it right before its copy starts (it is only an index: no
#       result changes; the row-store indexes stay) and sets its row back to 'waiting'; rule 1 then builds it aligned on the
#       new table after the swap. Never blocked, never a run held.
#  On the scheme = the catalog says so (the clustered index on PS_SICollection), or -- for a reader that may not see the
#  scheme in the catalog -- sidata.PartitionMove says the table was swapped / checked / done.
function Get-SIColumnstorePartitionSql {
    <# ONE row about a #1317 table (@T = 'Finding'): Live, OnScheme (catalog), Scheme (seen), MoveTable, MoveState. Catalog +
       sidata.PartitionMove only; readable by the engine's identity (data only) and the updater's. #>
    @'
SET NOCOUNT ON;
DECLARE @f int = OBJECT_ID(N'sidata.' + @T, N'U');
DECLARE @ps int = (SELECT data_space_id FROM sys.data_spaces WHERE name = N'PS_SICollection' AND type = 'PS');
DECLARE @mt int = CASE WHEN OBJECT_ID(N'sidata.PartitionMove', N'U') IS NULL THEN 0 ELSE 1 END;
DECLARE @mv nvarchar(32) = NULL;
IF @mt = 1 EXEC sp_executesql N'SELECT TOP (1) @s = State FROM sidata.PartitionMove WHERE TableName = @n', N'@s nvarchar(32) OUTPUT, @n nvarchar(128)', @s = @mv OUTPUT, @n = @T;
SELECT CASE WHEN @f IS NULL THEN 0 ELSE 1 END AS Live,
       CASE WHEN @f IS NOT NULL AND @ps IS NOT NULL AND EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = @f AND index_id IN (0, 1) AND data_space_id = @ps) THEN 1 ELSE 0 END AS OnScheme,
       CASE WHEN @ps IS NULL THEN 0 ELSE 1 END AS Scheme, @mt AS MoveTable, @mv AS MoveState;
'@
}

function Read-SIColumnstorePartitionState {
    <# The partition state of one table of the list (-Table 'sidata.Finding'): @{ Live; OnScheme; Scheme; MoveTable;
       MoveState }, or $null when it cannot be read. Never throws. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [string]$Table = 'sidata.Finding')
    try {
        $r = @(Get-SIIndexReaderRows (& $Invoke (Get-SIColumnstorePartitionSql) ([ordered]@{ T = ($Table -replace '^sidata\.', '') }) 'reader'))
        if (-not $r.Count) { return $null }
        $ms = Get-SIIndexRowValue $r[0] 'MoveState'
        [pscustomobject]@{ Live = ([int](Get-SIIndexRowValue $r[0] 'Live') -eq 1); OnScheme = ([int](Get-SIIndexRowValue $r[0] 'OnScheme') -eq 1)
                           Scheme = ([int](Get-SIIndexRowValue $r[0] 'Scheme') -eq 1); MoveTable = ([int](Get-SIIndexRowValue $r[0] 'MoveTable') -eq 1)
                           MoveState = $(if ($null -eq $ms -or $ms -is [DBNull]) { '' } else { ([string]$ms).Trim().ToLowerInvariant() }) }
    } catch { $null }
}

function Get-SIColumnstorePartitionHold {
    <#
        PURE. Rule 1 above for ONE index of the list (-Index: an entry of Get-SIColumnstoreContract).Indexes, or a row with
        Table / Name). -SwitchOn: SI_Data_RetireByPartition. -State: Read-SIColumnstorePartitionState ($null = not read).
        Returns @{ Hold; Aligned; Why }: Hold = the index waits now; Aligned = build it ON the scheme (the catalog shows the
        table on it). An index of a table that is not partitioned is never held (CiFindingState).
    #>
    param([Parameter(Mandatory)]$Index, [bool]$SwitchOn = $true, $State)
    $ok = { param($a, $w) [pscustomobject]@{ Hold = $false; Aligned = [bool]$a; Why = $w } }
    $entry = @($script:SIColumnstore.Indexes | Where-Object { $_.Table -ieq [string]$Index.Table -and $_.Name -ieq [string]$Index.Name })[0]
    if (-not $entry -or -not $entry.Partitioned) { return (& $ok $false 'the table is not partitioned') }
    if ($null -eq $State) {
        return [pscustomobject]@{ Hold = $true; Aligned = $false; Why = ('whether {0} is on the collection partitions could not be read -- it waits; the next wake-up looks again' -f $entry.Table) }
    }
    $moved = $State.OnScheme -or ($State.MoveState -in @('swapped', 'checked', 'done'))
    if ($moved) { return (& $ok $State.OnScheme ('{0} is on the collection partitions -- built aligned on them' -f $entry.Table)) }
    if (-not $SwitchOn) { return (& $ok $false 'SI_Data_RetireByPartition is off -- built on the table as it is') }
    if (-not $State.MoveTable) { return (& $ok $false 'the database does not carry the collection partitions yet -- built on the table as it is (the move takes it along later)') }
    if ($State.MoveState -in 'blocked', 'gave-up', 'waiting-space') { return (& $ok $false ('the move of {0} onto the collection partitions is blocked for another reason -- built on the table as it is' -f $entry.Table)) }
    [pscustomobject]@{ Hold = $true; Aligned = $false
                       Why = ('waits until {0} is on the collection partitions (SI_Data_RetireByPartition: the move goes first) -- it is then built aligned on them' -f $entry.Table) }
}

function Select-SIColumnstoreRowsNotHeld {
    <#
        THE RUNNER's side of rule 1: -Rows (cfg.IndexBuild) without the rows of an index that waits for its table's move, so
        the idle wake-up never starts the job for it (and picks the next index instead). Reads the partition state ONCE, only
        when such a row waits. -State: a seam (tests). Returns @{ Rows; Held (the held rows, each with its Why) }. Never throws:
        a state that cannot be read holds the index (nothing on a guess).
    #>
    param([object[]]$Rows = @(), [scriptblock]$Invoke, [bool]$SwitchOn = $true, $State = 'read')
    $keep = New-Object System.Collections.Generic.List[object]; $held = New-Object System.Collections.Generic.List[object]
    $read = $false; $st = $null
    foreach ($r in @($Rows)) {
        if (-not $r) { continue }
        $e = @($script:SIColumnstore.Indexes | Where-Object { $_.Partitioned -and $_.Table -ieq [string]$r.Table -and $_.Name -ieq [string]$r.Name })[0]
        if (-not $e -or [string]$r.State -notin @('waiting', 'paused', 'building')) { $keep.Add($r); continue }
        if (-not $read) { $read = $true; $st = if ($State -is [string] -and $State -eq 'read') { if ($Invoke) { Read-SIColumnstorePartitionState -Invoke $Invoke -Table $e.Table } else { $null } } else { $State } }
        $h = Get-SIColumnstorePartitionHold -Index $e -SwitchOn $SwitchOn -State $st
        if ($h.Hold) { $held.Add([pscustomobject]@{ Row = $r; Why = $h.Why }) } else { $keep.Add($r) }
    }
    [pscustomobject]@{ Rows = $keep.ToArray(); Held = $held.ToArray() }
}

function Get-SIColumnstorePartitionSwitch {
    <# SI_Data_RetireByPartition where the caller has no value of its own: $global:, else SI_CFG_SI_Data_RetireByPartition / the
       job's SI_INDEXBUILD_PARTITIONSWITCH; not set = ON (Test-SIIndexBuildPartitionSwitch's rule). #>
    $g = $null; try { $g = Get-Variable -Name 'SI_Data_RetireByPartition' -Scope Global -ValueOnly -ErrorAction Stop } catch { $g = $null }
    if ($null -eq $g -or ($g -isnot [bool] -and "$g".Trim() -eq '')) { $g = [Environment]::GetEnvironmentVariable('SI_CFG_SI_Data_RetireByPartition') }
    if ($null -eq $g -or ($g -isnot [bool] -and "$g".Trim() -eq '')) { $g = [Environment]::GetEnvironmentVariable('SI_INDEXBUILD_PARTITIONSWITCH') }
    if ($null -eq $g -or ($g -isnot [bool] -and "$g".Trim() -eq '')) { return $true }
    Test-SIIndexBuildPartitionSwitch -Value $g
}

# =====================================================================================================================
#  #1332 THE FINDING HISTORY'S PAGE INDEXES (the readers on the history; docs\DESIGN.md "Finding history model")
# =====================================================================================================================
#  The readers read a collection served from the history off the member's page keys (sidata.FindingStateMember: CollectionId +
#  the copies of AssetKey, Severity, Tier, the scores, ExemptionId, Cve, ConfigurationId) exactly as they read sidata.Finding off
#  its (CollectionId, ...) indexes: the same seeks, the same sorts. They are built ONLY by the index build job in an idle window
#  (the updater records them 'waiting'; it never builds one) and a collection is SERVED from its history only once every one of
#  them is there (SI-DataHistoryServe.ps1: until then the stored rows serve and the run says why). Additive: an index only
#  makes a read faster; dropping one = the stored rows serve again.
function Get-SIHistoryIndexDefinitions {
    <# PURE. The history's page indexes -- built ONLY by the index build job (the updater's identity), never by the engine. #>
    @(
    [pscustomobject]@{ Table = 'sidata.FindingStateMember'; Name = 'IX_FindingStateMember_RiskPage';      Statement = 'CREATE INDEX IX_FindingStateMember_RiskPage ON sidata.FindingStateMember (CollectionId, RiskScore DESC) INCLUDE (ExemptionId, StateId)' }
    [pscustomobject]@{ Table = 'sidata.FindingStateMember'; Name = 'IX_FindingStateMember_CvssPage';      Statement = 'CREATE INDEX IX_FindingStateMember_CvssPage ON sidata.FindingStateMember (CollectionId, Cvss DESC) INCLUDE (ExemptionId, StateId)' }
    [pscustomobject]@{ Table = 'sidata.FindingStateMember'; Name = 'IX_FindingStateMember_WeightedPage';  Statement = 'CREATE INDEX IX_FindingStateMember_WeightedPage ON sidata.FindingStateMember (CollectionId, RiskScoreWeighted DESC) INCLUDE (ExemptionId, StateId)' }
    [pscustomobject]@{ Table = 'sidata.FindingStateMember'; Name = 'IX_FindingStateMember_AssetSidePage'; Statement = 'CREATE INDEX IX_FindingStateMember_AssetSidePage ON sidata.FindingStateMember (CollectionId, RiskAssetSide DESC) INCLUDE (ExemptionId, StateId)' }
    [pscustomobject]@{ Table = 'sidata.FindingStateMember'; Name = 'IX_FindingStateMember_VulnSidePage';  Statement = 'CREATE INDEX IX_FindingStateMember_VulnSidePage ON sidata.FindingStateMember (CollectionId, RiskVulnSide DESC) INCLUDE (ExemptionId, StateId)' }
    [pscustomobject]@{ Table = 'sidata.FindingStateMember'; Name = 'IX_FindingStateMember_Asset';         Statement = 'CREATE INDEX IX_FindingStateMember_Asset ON sidata.FindingStateMember (CollectionId, AssetKey) INCLUDE (StateId, AssetName, Title, Severity, Tier, RiskScore, Cve, ConfigurationId, ExemptionId, CiLifecycle, ReportName)' }
    [pscustomobject]@{ Table = 'sidata.FindingStateMember'; Name = 'IX_FindingStateMember_Cve';           Statement = 'CREATE INDEX IX_FindingStateMember_Cve ON sidata.FindingStateMember (CollectionId, Cve) INCLUDE (StateId, AssetKey, Severity, Tier, RiskScore)' }
    [pscustomobject]@{ Table = 'sidata.FindingStateMember'; Name = 'IX_FindingStateMember_Config';        Statement = 'CREATE INDEX IX_FindingStateMember_Config ON sidata.FindingStateMember (CollectionId, ConfigurationId) INCLUDE (StateId, AssetKey, Severity, Tier, RiskScore)' }
    [pscustomobject]@{ Table = 'sidata.FindingStateMember'; Name = 'IX_FindingStateMember_Counts';        Statement = 'CREATE INDEX IX_FindingStateMember_Counts ON sidata.FindingStateMember (CollectionId, Severity, Tier) INCLUDE (ExemptionId, RiskScore, AssetKey)' }
    [pscustomobject]@{ Table = 'sidata.FindingStateMember'; Name = 'IX_FindingStateMember_Importance';    Statement = 'CREATE INDEX IX_FindingStateMember_Importance ON sidata.FindingStateMember (CollectionId, ImportanceRank) INCLUDE (StateId, Tier, Severity, ExemptionId)' }
)
}
$script:SIHistoryIndexes = Get-SIHistoryIndexDefinitions

function Get-SIHistoryIndexContract { $script:SIHistoryIndexes }

function Get-SIHistoryIndexStateSql {
    <# Per index of the list: is it there (X), are its columns there (C = how many are missing), the member table there. #>
    $rows = foreach ($ix in $script:SIHistoryIndexes) {
        $cols = @([regex]::Matches(($ix.Statement -replace '^.*?\((.*)$', '$1'), '[A-Za-z_][A-Za-z0-9_]*') | ForEach-Object { $_.Value } | Where-Object { $_ -notin 'DESC', 'ASC', 'INCLUDE' } | Select-Object -Unique)
        $miss = (@($cols | ForEach-Object { "CASE WHEN COL_LENGTH(N'$($ix.Table)', N'$_') IS NULL THEN 1 ELSE 0 END" })) -join ' + '
        "SELECT N'$($ix.Name)' AS Name, CASE WHEN EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'$($ix.Name)' AND object_id = OBJECT_ID(N'$($ix.Table)')) THEN 1 ELSE 0 END AS X, $miss AS C"
    }
    "SET NOCOUNT ON; IF OBJECT_ID(N'sidata.FindingStateMember') IS NULL SELECT CAST(NULL AS nvarchar(128)) AS Name, 0 AS X, 0 AS C WHERE 1 = 0; ELSE " + ($rows -join ' UNION ALL ') + ';'
}

function Read-SIHistoryIndexState {
    <# @{ Known; There = [names]; Missing = [names]; ColumnsMissing = [names] } of the list. Known $false = not readable. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    try {
        $r = @(Get-SIIndexReaderRows (& $Invoke (Get-SIHistoryIndexStateSql) @{} 'reader'))
        $there = @($r | Where-Object { [int](Get-SIIndexRowValue $_ 'X') -eq 1 } | ForEach-Object { [string](Get-SIIndexRowValue $_ 'Name') })
        $cm = @($r | Where-Object { [int](Get-SIIndexRowValue $_ 'X') -ne 1 -and [int](Get-SIIndexRowValue $_ 'C') -gt 0 } | ForEach-Object { [string](Get-SIIndexRowValue $_ 'Name') })
        $miss = @($script:SIHistoryIndexes | Where-Object { $there -notcontains $_.Name } | ForEach-Object { $_.Name })
        [pscustomobject]@{ Known = ($r.Count -gt 0); There = $there; Missing = $miss; ColumnsMissing = $cm }
    } catch { [pscustomobject]@{ Known = $false; There = @(); Missing = @($script:SIHistoryIndexes | ForEach-Object { $_.Name }); ColumnsMissing = @() } }
}

function Invoke-SIHistoryIndexStep {
    <#
        #1332 THE UPDATER'S STEP (every run, beside the columnstore step): each page index of the finding history that is not
        there, whose columns are there, and has no row waiting / paused / building is recorded 'waiting' in cfg.IndexBuild with
        its statement and estimate; the index build job builds it in an idle window. NEVER builds one itself, never throws,
        never holds the update. Seams: -State (Read-SIHistoryIndexState), -Rows (cfg.IndexBuild), -Estimate. Returns @{ Queued; Lines }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log = { param($m) }, $State, [object[]]$Rows, [scriptblock]$Estimate, [string]$By = 'caj-si-updater')
    $lines = New-Object System.Collections.Generic.List[string]
    $say = { param($m) $lines.Add($m); try { $null = & $Log $m } catch { } }
    $queued = New-Object System.Collections.Generic.List[string]
    try {
        if ($null -eq $State) { $State = Read-SIHistoryIndexState -Invoke $Invoke }
        if (-not $State.Known) { return [pscustomobject]@{ Queued = @(); Lines = $lines.ToArray() } }
        if ($null -eq $Rows) { try { $Rows = @(Read-SIIndexBuildRows -Invoke $Invoke) } catch { $Rows = $null } }
        if ($null -eq $Rows) { & $say 'finding history indexes: the waiting indexes could not be read -- nothing changed; the next update looks again'; return [pscustomobject]@{ Queued = @(); Lines = $lines.ToArray() } }
        foreach ($ix in $script:SIHistoryIndexes) {
            if (@($State.There) -contains $ix.Name -or @($State.ColumnsMissing) -contains $ix.Name) { continue }
            $row = @($Rows | Where-Object { $_ -and [string]$_.Table -ieq $ix.Table -and [string]$_.Name -ieq $ix.Name })[0]
            if ($row -and [string]$row.State -in @('waiting', 'paused', 'building')) { continue }
            if (-not $Estimate) { $Estimate = New-SIIndexBuildEstimator -Invoke $Invoke }
            $est = $null; try { $est = & $Estimate ([pscustomobject]@{ Table = $ix.Table; Name = $ix.Name }) } catch { $est = $null }
            $ok = Save-SIIndexBuildRow -Invoke $Invoke -Table $ix.Table -Index $ix.Name -State 'waiting' -Statement $ix.Statement `
                    -Pages $(if ($est -and $est.Pages) { [long]$est.Pages } else { $null }) -EstMinutes $(if ($est -and $est.Known) { [int]$est.Minutes } else { $null }) `
                    -Source $(if ($est) { [string]$est.Source } else { '' }) -Why 'a page index of the finding history: built by the index build job in an idle window; until every one is there the stored rows serve the pages' -By $By
            if ($ok) { $queued.Add($ix.Name); & $say ('finding history indexes: {0} recorded for the index build job' -f $ix.Name) }
            else { & $say ('WARNING: finding history indexes: {0} could not be recorded -- the next update tries again' -f $ix.Name) }
        }
        # #1385 READ BACK, one line every run (the 3.1.50 gap stayed invisible because a run that recorded nothing said nothing):
        # how many of the list are there, and how many wait / build for the index build job -- read from cfg.IndexBuild again
        $all = @($script:SIHistoryIndexes); $there = @($all | Where-Object { @($State.There) -contains $_.Name }).Count
        $back = $null; try { $back = @(Read-SIIndexBuildRows -Invoke $Invoke) } catch { $back = $null }
        if ($null -eq $back) { & $say ('finding history indexes: {0} of {1} there; the waiting indexes could not be read back -- the next update looks again' -f $there, $all.Count) }
        else {
            $wait = @($all | Where-Object { $n = $_.Name; @($State.There) -notcontains $n -and @($back | Where-Object { $_ -and [string]$_.Name -ieq $n -and [string]$_.State -in @('waiting', 'paused', 'building') }).Count })
            $lost = @($queued | Where-Object { $n = $_; -not @($wait | Where-Object { $_.Name -ieq $n }).Count })
            $cm = @($State.ColumnsMissing).Count
            & $say ('finding history indexes: {0} of {1} there, {2} waiting for the index build job (read back){3}{4}' -f $there, $all.Count, $wait.Count,
                     $(if ($cm) { ('; {0} wait(s) for their columns' -f $cm) } else { '' }),
                     $(if ($lost.Count) { ('; WARNING: {0} recorded but not read back ({1}) -- the next update records it again' -f $lost.Count, ($lost -join ', ')) } else { '' }))
        }
    } catch { & $say ('WARNING: finding history indexes: not checked ({0}) -- the next update looks again' -f $_.Exception.Message) }
    [pscustomobject]@{ Queued = $queued.ToArray(); Lines = $lines.ToArray() }
}

function Invoke-SIColumnstoreIndexStep {
    <#
        #1316 THE UPDATER'S STEP (every run, from Invoke-SIUpdaterIndexBuildJob): reads the setting and the database once,
        then per index of the list does what Get-SIColumnstorePlan says -- 'queue' records the row 'waiting' with its
        statement and its estimate (this database's rate, New-SIIndexBuildEstimator); the index build job builds it.
        Seams: -Setting @{ Known; On }, -State, -Rows, -Estimate { param($Index) }. Returns @{ Plan; Lines }. NEVER throws,
        never fails or holds the update; it never builds an index itself.
    #>
    # -PartitionSwitch (SI_Data_RetireByPartition; $null = Get-SIColumnstorePartitionSwitch) and -PartitionState (seam):
    # #1316 x #1317 -- an index of a partitioned table is still recorded, and its line says it waits for the table's move
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log = { param($m) }, $Setting, $State, [object[]]$Rows, [scriptblock]$Estimate,
          [string]$By = 'caj-si-updater', $PartitionSwitch = $null, $PartitionState = 'read')
    $lines = New-Object System.Collections.Generic.List[string]
    $say = { param($m) $lines.Add($m); try { $null = & $Log $m } catch { } }
    $plan = @()
    $holdOf = {
        param($ix)
        if (-not $ix.Partitioned) { return $null }
        $sw = if ($null -ne $PartitionSwitch) { Test-SIIndexBuildPartitionSwitch -Value $PartitionSwitch } else { Get-SIColumnstorePartitionSwitch }
        $st = if ($PartitionState -is [string] -and $PartitionState -eq 'read') { Read-SIColumnstorePartitionState -Invoke $Invoke -Table $ix.Table } else { $PartitionState }
        $h = Get-SIColumnstorePartitionHold -Index $ix -SwitchOn $sw -State $st
        if ($h.Hold) { $h } else { $null }
    }
    try {
        if ($null -eq $Setting) { $Setting = Read-SIColumnstoreSetting -Invoke $Invoke }
        # one catalog read (also while off: a row or an index left from an earlier "on" is undone)
        if (-not $Setting.Known) { & $say 'columnstore indexes: the setting could not be read -- nothing changed; the next update looks again'; return [pscustomobject]@{ Plan = @(); Lines = $lines.ToArray() } }
        if ($null -eq $State) { $State = Read-SIColumnstoreState -Invoke $Invoke }
        if ($null -eq $Rows) { try { $Rows = @(Read-SIIndexBuildRows -Invoke $Invoke) } catch { $Rows = $null } }
        if ($null -eq $Rows) { & $say 'columnstore indexes: the waiting indexes could not be read -- nothing changed; the next update looks again'; return [pscustomobject]@{ Plan = @(); Lines = $lines.ToArray() } }
        $plan = @(Get-SIColumnstorePlan -Setting $Setting -State $State -Rows @($Rows))
        if (-not $Estimate -and @($plan | Where-Object { $_.Action -eq 'queue' }).Count) { $Estimate = New-SIIndexBuildEstimator -Invoke $Invoke }
        foreach ($p in $plan) {
            $ix = $p.Index
            switch ($p.Action) {
                'queue' {
                    $est = $null; if ($Estimate) { try { $est = & $Estimate ([pscustomobject]@{ Table = $ix.Table; Name = $ix.Name }) } catch { $est = $null } }
                    $ok = Save-SIIndexBuildRow -Invoke $Invoke -Table $ix.Table -Index $ix.Name -State 'waiting' -Statement (Get-SIColumnstoreStatement -Index $ix) `
                            -Pages $(if ($est -and $est.Pages) { [long]$est.Pages } else { $null }) -EstMinutes $(if ($est -and $est.Known) { [int]$est.Minutes } else { $null }) `
                            -Source $(if ($est) { [string]$est.Source } else { '' }) -Why 'columnstore index (SI_Data_ColumnstoreIndexes on): built by the index build job in an idle window' -By $By
                    $hold = if ($ok) { & $holdOf $ix } else { $null }
                    & $say $(if ($ok) { 'columnstore indexes: {0} on {1} recorded for the index build job ({2}){3}' -f $ix.Name, $ix.Table, $(if ($est -and $est.Known) { 'about ' + (Format-SIIndexDuration ([int]$est.Minutes)) } else { 'its time is not known yet' }), $(if ($hold) { '; it ' + $hold.Why } else { '' }) }
                             else { 'WARNING: columnstore indexes: {0} on {1} could not be recorded -- the next update tries again' -f $ix.Name, $ix.Table })
                }
                'remove-row' {
                    try { $null = & $Invoke (Get-SIColumnstoreRemoveRowSql) ([ordered]@{ T = $ix.Table; I = $ix.Name }) 'nonquery'; & $say ('columnstore indexes: {0} on {1} -- {2}' -f $ix.Name, $ix.Table, $p.Why) }
                    catch { & $say ('WARNING: columnstore indexes: the row of {0} could not be removed ({1}) -- the next update tries again' -f $ix.Name, $_.Exception.Message) }
                }
                'drop' {
                    $sql = Get-SIColumnstoreDropSql -Table $ix.Table -Index $ix.Name
                    if (-not $sql) { continue }
                    try {
                        $null = & $Invoke $sql @{} 'nonquery'
                        $null = & $Invoke (Get-SIColumnstoreRemoveRowSql) ([ordered]@{ T = $ix.Table; I = $ix.Name }) 'nonquery'
                        & $say ('columnstore indexes: {0} on {1} -- {2}' -f $ix.Name, $ix.Table, $p.Why)
                    } catch { & $say ('WARNING: columnstore indexes: {0} on {1} could not be dropped now ({2}) -- the next update tries again; results are the same with or without it' -f $ix.Name, $ix.Table, $_.Exception.Message) }
                }
                default {
                    if ($Setting.On) {
                        $hold = if ($p.Why -match '^it waits for the index build job') { & $holdOf $ix } else { $null }
                        & $say ('columnstore indexes: {0} on {1} -- {2}' -f $ix.Name, $ix.Table, $(if ($hold) { 'it ' + $hold.Why } else { $p.Why }))
                    }
                }
            }
        }
    } catch { & $say ('WARNING: columnstore indexes: not checked ({0}) -- the next update looks again' -f $_.Exception.Message) }
    [pscustomobject]@{ Plan = @($plan); Lines = $lines.ToArray() }
}
