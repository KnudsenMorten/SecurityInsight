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
      * a waiting index is built when the install is idle long enough: the pipeline runner's wake-up starts the updater
        (SI_UPDATER_MODE = index-build) when no run, step, data sync or data out is going and the estimate ends before the
        next scheduled run; the updater takes the install's lock, as an update does, and beats it while the index builds;
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
    Mode            = 'index-build'
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
        $sql = 'SET NOCOUNT ON; SELECT COUNT_BIG(*) AS N FROM [{0}].[{1}] TABLESAMPLE SYSTEM ({2} PERCENT) WITH (NOLOCK);' -f $sch, $tab, $pct.ToString('0.####', [Globalization.CultureInfo]::InvariantCulture)
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
               LastEndUtc = CASE WHEN @State IN (N'built', N'failed') OR (@State = N'waiting' AND State = N'building') THEN SYSUTCDATETIME() ELSE LastEndUtc END,
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
    <# Records one index's state (waiting | building | built | failed). Never throws; $true when written. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Table, [Parameter(Mandatory)][string]$Index,
          [Parameter(Mandatory)][ValidateSet('waiting', 'building', 'built', 'failed')][string]$State, [string]$Statement, $Pages, $EstMinutes,
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
    @($Rows | Where-Object { $_ -and $_.State -in @('waiting', 'building', 'failed') } | Sort-Object SinceUtc | ForEach-Object {
        $r = $_   # (inside switch, $_ is the switch's own value)
        $est = if ($r.EstMinutes) { 'about {0}' -f (Format-SIIndexDuration ([int]$r.EstMinutes)) } else { 'time not known' }
        switch ([string]$r.State) {
            'building' { 'index {0} on {1}: being built now ({2}, started {3:yyyy-MM-dd HH:mm}Z)' -f $r.Name, $r.Table, $est, $r.LastStartUtc }
            'failed'   { 'index {0} on {1}: the build failed ({2}) -- the next update tries again' -f $r.Name, $r.Table, $r.Why }
            default    { 'index {0} on {1}: waits for an idle window of {2} (waiting since {3:yyyy-MM-dd HH:mm}Z); the release works without it' -f $r.Name, $r.Table, $est, $r.SinceUtc }
        }
    })
}

# =====================================================================================================================
#  The window -- PURE
# =====================================================================================================================
function Get-SIIndexBuildWindowDecision {
    <#
        PURE. Does this wake-up start the updater to build a waiting index? -Rows (cfg.IndexBuild), -NowUtc, -NextRunUtc (the
        next scheduled pipeline run; $null = none scheduled), -Busy (Get-SIDataHousekeepingBusy: Busy, Why), -UpdaterRunning
        (text: an updater execution runs; '' = none), -RunDue (a run starts / runs / resumes at this wake-up).
        Returns @{ Start; Force; Index (the row); Why }. One index per window: the one that has waited longest.
    #>
    param([object[]]$Rows = @(), [Parameter(Mandatory)][datetime]$NowUtc, $NextRunUtc, $Busy, [AllowEmptyString()][string]$UpdaterRunning = '', [bool]$RunDue = $false)
    $S = $script:SIIndexBuild
    $no = { param($why, $row) [pscustomobject]@{ Start = $false; Force = $false; Index = $row; Why = $why } }
    $now = $NowUtc.ToUniversalTime()
    $building = @($Rows | Where-Object { $_ -and $_.State -eq 'building' })
    $wait = @($Rows | Where-Object { $_ -and $_.State -eq 'waiting' } | Sort-Object { if ($_.SinceUtc) { ([datetime]$_.SinceUtc).ToUniversalTime() } else { [datetime]::MaxValue } })
    if (-not $wait.Count) { return (& $no '' $null) }
    $row = $wait[0]
    if ($RunDue) { return (& $no 'a pipeline run starts or runs now' $row) }
    if ("$UpdaterRunning".Trim()) { return (& $no ('the updater runs ({0})' -f $UpdaterRunning) $row) }
    if ($building.Count) { return (& $no ('index {0} is being built' -f $building[0].Name) $row) }
    if ($Busy -and $Busy.Busy) { return (& $no ('{0}' -f $Busy.Why) $row) }
    $since = if ($row.SinceUtc) { ([datetime]$row.SinceUtc).ToUniversalTime() } else { $now }
    $waitedDays = ($now - $since).TotalDays
    $est = if ($row.EstMinutes) { [int]$row.EstMinutes } else { 0 }
    $next = if ($NextRunUtc) { ([datetime]$NextRunUtc).ToUniversalTime() } else { $null }
    $room = if ($next) { ($next - $now).TotalMinutes - $S.LeadMinutes } else { [double]::MaxValue }
    if ($est -gt 0 -and $est -le $room) {
        $why = if ($next) { 'about {0}, and the next run starts {1:yyyy-MM-dd HH:mm}Z' -f (Format-SIIndexDuration $est), $next } else { 'about {0}, and no run is scheduled' -f (Format-SIIndexDuration $est) }
        return [pscustomobject]@{ Start = $true; Force = $false; Index = $row; Why = $why }
    }
    if ($waitedDays -ge $S.WaitDays -and -not $row.ForcedUtc) {
        $why = 'it has waited {0} days without an idle window long enough ({1}); it is built now, once, and the next run waits for it' -f [int][Math]::Floor($waitedDays), $(if ($est) { 'about ' + (Format-SIIndexDuration $est) } else { 'its time is not known' })
        return [pscustomobject]@{ Start = $true; Force = $true; Index = $row; Why = $why }
    }
    $left = if ($next) { 'the next run starts in {0}' -f (Format-SIIndexDuration ([int][Math]::Max(0, ($next - $now).TotalMinutes))) } else { 'no run is scheduled' }
    & $no ('it needs {0}; {1}' -f $(if ($est) { 'about ' + (Format-SIIndexDuration $est) } else { 'a time that is not known' }), $left) $row
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
    #>
    param([Parameter(Mandatory)]$Connection, [Parameter(Mandatory)][string]$Sql, [scriptblock]$Beat, [int]$BeatSeconds = $script:SIIndexBuild.BeatSeconds)
    $cmd = $Connection.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $task = $cmd.ExecuteNonQueryAsync()
    try {
        while (-not $task.Wait([Math]::Max(1, $BeatSeconds) * 1000)) {
            if ($Beat) { try { $null = & $Beat ([int][Math]::Floor($sw.Elapsed.TotalMinutes)) } catch { } }
        }
    } catch {
        # PowerShell hands the task's failure as a MethodInvocationException around an AggregateException: the SQL error inside
        $e = $_.Exception
        while (($e -is [System.Management.Automation.MethodInvocationException] -or $e -is [System.AggregateException]) -and $e.InnerException) { $e = $e.InnerException }
        throw $e
    }
    $sw.Stop()
    $sw.Elapsed.TotalSeconds
}
