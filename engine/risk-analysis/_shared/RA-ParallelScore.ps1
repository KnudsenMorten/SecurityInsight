#Requires -Version 7.0
<#
    Risk Analysis -- ONE QUERY SLICE'S ROWS ON SEVERAL PROCESSOR CORES (the risk scores and the rows' stored form).

    Owner 2026-10-14: "go ahead, fix the performance". A slice of a Detailed report is tens of thousands of rows, and the
    per-row work ran on ONE core of a 4-core container (measured live: 42,894 rows scored in 1,908 s, written in 16.5
    minutes). Two steps are split over the cores:

      * THE SCORES (Calculate-RiskScore, RA-RiskScore.ps1). For a report that is not a Summary report every row's scored
        output depends only on that row (the report-wide parts -- the impacted-asset lists, the group maps -- are filled
        for Summary reports only), so the rows, already de-duplicated over the whole slice, are split into contiguous
        parts, each part is scored by the SAME function in its own runspace, and the parts are put back together in their
        order before the one final sort;
      * THE STORED FORM (ConvertTo-RAStreamRowItems, RA-SqlStream.ps1): each row's JSON for sidata.Finding depends only on
        that row and its place in the write order, so contiguous parts are made at once, each with its own place in the
        order, and put back in order before the one write.
    Either way the result is the result of one pass over all the rows: the same rows, the same values, the same order
    (tests\pester\SIv3-RaRowPerformance.Tests.ps1 compares them).

    A worker runspace is the engine's environment, made the way the engine makes its own: the same engine files
    dot-sourced (so their load-time state is the same), then before every part the run's global variables (settings,
    the risk index, the catalogs already read) handed over. The caches a worker fills are its own; the risk index is
    handed over with an empty memo of its own (the memo is written while scoring). The workers are made once per process
    and kept for the run.

    SI_RA_ScoringThreads   how many cores: unset = ON, the cores this process has (a 4-CPU job: 4); 1 / 0 / off = one core;
                           a number = that many, never more than the cores. Also read from the environment variable
                           SI_RA_SCORINGTHREADS when the setting is not set (a job can be switched to one core without a
                           configuration change).
    SI_RA_ParallelMinRows  the smallest slice worth splitting (default 2,000 rows)
    Anything that goes wrong with the workers is said in plain words and the step is done on one core instead -- the
    result is the same either way. Every slice says how many cores scored it and how long it took.

    ON BY DEFAULT AGAIN (2026-10-16, REQUIREMENTS #716). It was switched off on 2026-10-14 after the first live Detailed run with it on
    was reported hung. The run log showed later that day (REQUIREMENTS #666) that the silence was the once-per-run read of
    Defender's whole vulnerability catalogue (26 minutes, no line, no time limit) BEFORE "calculating risk scores", the
    same as in the run before this step existed -- not the workers. The off-switch's own suspicion (a script block among
    the globals handed to a worker, bound to the MAIN runspace) was measured on the test VM (pwsh 7.6): called in a worker
    it does NOT wait -- it runs at once, but against the MAIN runspace's variables, from the worker's thread, while the
    main thread runs too (a race, not a hang). Script blocks and delegates are therefore no longer handed over at all
    (nothing on the scoring / stored-form path calls one). A part is stopped only when it makes no progress
    (RAParallelNoProgressMinutes without CPU use -- never a clock) and a part still running is never disposed. A worker also runs in the main thread's culture (a number is never formatted or
    read in another culture than the one-core path would use). Proof: tests\pester\SIv3-RaParallelScoring.Tests.ps1.
#>

$script:RAParallelEngineRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
# the engine files the two steps and every function they call are defined in (engine-relative; '/' works on every host)
$script:RAParallelFiles = @(
    '_shared/SI-AssetIdentity.ps1',
    'data-model/SI-DataModelTemplates.ps1', 'data-model/SI-Conditions.ps1', 'data-model/SI-Classification.ps1', 'data-model/SI-FindingTexts.ps1',
    'data-model/SI-RecommendationEquivalence.ps1',
    'risk-analysis/_shared/RA-RiskIndexOrder.ps1', 'risk-analysis/_shared/RA-RiskIndexSi.ps1', 'risk-analysis/_shared/RA-FactorKeys.ps1',
    'risk-analysis/_shared/RA-CiContext.ps1', 'risk-analysis/_shared/RA-AssetIdentityMap.ps1', 'risk-analysis/_shared/RA-RiskScore.ps1',
    'risk-analysis/_shared/RA-RowShaping.ps1', '_shared/data-sql/SI-DataModel.ps1', 'risk-analysis/_shared/RA-Findings.ps1',
    'risk-analysis/_shared/RA-SqlStream.ps1',
    # #744: the Log Analytics preparation (ConvertTo-RALaPostRows' steps) on the cores -- the ingest client's row shaping and
    # the type alignment
    '_shared/SI-LogIngest.ps1', 'risk-analysis/_shared/RA-ColumnTypeAlign.ps1')
# global variables never handed to a worker: PowerShell's own, and $Error (a list each runspace writes)
$script:RAParallelSkipVars = @('$', '^', '_', '?', 'args', 'input', 'PSItem', 'this', 'foreach', 'switch', 'Matches', 'MyInvocation', 'PSBoundParameters',
    'PSCmdlet', 'PSScriptRoot', 'PSCommandPath', 'ExecutionContext', 'Host', 'PID', 'PWD', 'HOME', 'ShellId', 'PSHOME', 'PSVersionTable', 'PSEdition',
    'IsWindows', 'IsLinux', 'IsMacOS', 'IsCoreCLR', 'Error', 'StackTrace', 'LASTEXITCODE', 'NestedPromptLevel', 'ConsoleFileName', 'EnabledExperimentalFeatures',
    'PSCulture', 'PSUICulture', 'true', 'false', 'null', 'PROFILE', 'ProgressPreference', 'RA_ParallelWorker', 'RA_ParallelCulture')
$script:RAParallelWorkers = $null

# ON by default: 0 = the cores this process has ([Environment]::ProcessorCount -- in a container job, its CPU limit).
# See the header for why it was off for two days and what closed the two ways a worker could hang.
$script:RAScoringThreadsDefault = 0

function Get-RAScoringThreads {
    <# PURE over the setting. How many cores: SI_RA_ScoringThreads (else the environment variable SI_RA_SCORINGTHREADS):
       1 / 0 / off / false / no = one core; a number = that many; unset = the built-in default (0 = the cores). Never more
       than the machine has (more workers than cores only compete for them). #>
    param($Setting = $global:SI_RA_ScoringThreads, [int]$Cores = [Environment]::ProcessorCount, [int]$Default = $script:RAScoringThreadsDefault,
          [AllowNull()][AllowEmptyString()][string]$EnvValue = $env:SI_RA_SCORINGTHREADS)
    $cores = [Math]::Max(1, $Cores)
    $s = if ($null -ne $Setting -and ([string]$Setting).Trim() -ne '') { ([string]$Setting).Trim() } elseif ($null -ne $EnvValue -and $EnvValue.Trim() -ne '') { $EnvValue.Trim() } else { '' }
    if ($s -match '^(?i)(off|false|no|disabled?)$') { return 1 }
    $n = 0
    if ($s -ne '' -and [int]::TryParse($s, [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n)) {
        if ($n -le 1) { return 1 }
        return [Math]::Min($n, $cores)
    }
    if ($Default -le 0) { return $cores }
    [Math]::Max(1, [Math]::Min($cores, $Default))
}

function Test-RAParallelHandOver {
    <# PURE. Whether a global variable's value is handed to a worker: never a script block or a delegate (bound to the
       MAIN runspace: called in a worker it reads and writes the main runspace's variables from the worker's thread). #>
    param($Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [System.Management.Automation.PSObject]) { $Value = $Value.PSObject.BaseObject }
    -not ($Value -is [scriptblock] -or $Value -is [System.Delegate])
}

# HANG DETECTION BY LACK OF PROGRESS, NEVER A CLOCK (owner 2026-10-22: "i accept no limits" / "remove those stupid breaks"):
# a scoring part is pure CPU work (no SQL, no HTTP), so a part that is working burns CPU. A part is stopped (and the step
# redone on one core) only when the process used under 1 CPU-second in this many minutes while a part was still running --
# a stuck worker never hangs a run, and a large tenant's long part is never cut off.
$script:RAParallelNoProgressMinutes = 10

function Get-RAParallelMinRows {
    <# PURE over the setting. The smallest slice split over the cores: SI_RA_ParallelMinRows, else 2,000 rows. #>
    param($Setting = $global:SI_RA_ParallelMinRows)
    $n = 0
    if ($null -ne $Setting -and ([string]$Setting).Trim() -ne '' -and [int]::TryParse(([string]$Setting).Trim(), [ref]$n) -and $n -ge 0) { return $n }
    2000
}

function Split-RAParallelParts {
    <# PURE. 0..Count-1 split into at most -Parts contiguous ranges of near-equal size, in order: @(@(start, length), ...). #>
    param([int]$Count, [int]$Parts)
    $out = [System.Collections.Generic.List[object]]::new()
    if ($Count -le 0 -or $Parts -le 0) { return , $out.ToArray() }
    $p = [Math]::Min($Parts, $Count)
    $base = [Math]::Floor($Count / $p); $extra = $Count % $p; $start = 0
    for ($i = 0; $i -lt $p; $i++) { $len = [int]$base + $(if ($i -lt $extra) { 1 } else { 0 }); $out.Add(@($start, $len)); $start += $len }
    , $out.ToArray()
}

function Get-RAParallelSplit {
    <# $null when the rows are handled on one core (one core set, or fewer rows than the minimum), else the parts. #>
    param([int]$Count)
    $threads = Get-RAScoringThreads
    if ($threads -le 1 -or $Count -lt [Math]::Max(2, (Get-RAParallelMinRows))) { return $null }
    $parts = Split-RAParallelParts -Count $Count -Parts $threads
    if ($parts.Count -le 1) { return $null }
    , $parts
}

function Format-RAScoringLine {
    <# PURE. The line a slice's scoring says: how many rows, on how many cores, in how long (and why one core, when one). #>
    param([int]$Rows, [int]$Cores, [double]$Seconds, [string]$Why = '')
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $core = if ($Cores -le 1) { 'one processor core' } else { [string]::Format($inv, '{0} processor cores', $Cores) }
    $line = [string]::Format($inv, 'risk scores of {0:N0} row(s) worked out on {1} in {2:N1} s', $Rows, $core, $Seconds)
    if ($Cores -le 1 -and $Why) { $line += ' (' + $Why + ')' }
    $line
}

function Get-RAOneCoreReason {
    <# PURE over the settings. Why a slice of -Count rows is scored on one core ('' when it is not). #>
    param([int]$Count, [bool]$Summary)
    if ($Summary) { return 'a Summary report is scored on one core: its impacted-asset lists are report-wide' }
    $t = Get-RAScoringThreads
    if ($t -le 1) { if ([Environment]::ProcessorCount -le 1) { return 'this machine has one core' } else { return 'SI_RA_ScoringThreads = 1' } }
    $min = [Math]::Max(2, (Get-RAParallelMinRows))
    if ($Count -lt $min) { return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, 'fewer than {0:N0} rows', $min) }
    ''
}

function Get-RAParallelPart {
    <# PURE. The rows of one range (Split-RAParallelParts), as their own array. #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [Parameter(Mandatory)]$Range)
    $part = New-Object 'object[]' ([int]$Range[1])
    [System.Array]::Copy($Rows, [int]$Range[0], $part, 0, [int]$Range[1])
    , $part
}

function Get-RAParallelWorkers {
    <# The worker runspaces (made once per process, at least -Count of them): each has the engine files dot-sourced. #>
    param([Parameter(Mandatory)][int]$Count)
    if ($null -ne $script:RAParallelWorkers -and $script:RAParallelWorkers.Count -ge $Count) { return , $script:RAParallelWorkers }
    $files = @(foreach ($f in $script:RAParallelFiles) { [System.IO.Path]::Combine($script:RAParallelEngineRoot, $f) })
    foreach ($f in $files) { if (-not (Test-Path -LiteralPath $f)) { throw "an engine file the workers need is missing: $f" } }
    $init = @'
param($Files)
$ErrorActionPreference = 'Stop'
foreach ($__f in $Files) { . $__f }
# the console lines are said by the main run (the workers' own are not shown)
function global:Write-Info { param($m) }
function global:Write-Warn2 { param($m) }
function global:Write-Ok { param($m) }
function global:Write-Diag { param($m) }
function global:Write-Err2 { param($m) }
'@
    $list = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $script:RAParallelWorkers) { foreach ($w in $script:RAParallelWorkers) { $list.Add($w) } }
    while ($list.Count -lt $Count) {
        $rs = [runspacefactory]::CreateRunspace([initialsessionstate]::CreateDefault2())
        $rs.Open()
        $ps = [powershell]::Create()
        $ps.Runspace = $rs
        try {
            $null = $ps.AddScript($init, $false).AddArgument($files).Invoke()
            if ($ps.HadErrors) { throw ('the engine files could not be loaded: ' + (@($ps.Streams.Error | ForEach-Object { $_.ToString() }) -join '; ')) }
        } catch { $ps.Dispose(); $rs.Dispose(); throw }
        $ps.Dispose()
        $list.Add($rs)
    }
    $script:RAParallelWorkers = $list.ToArray()
    , $script:RAParallelWorkers
}

function Invoke-RAParallelParts {
    <#
        Runs -Script (text: a script whose param block takes one part's arguments) once per part, each part in its own worker
        runspace, all at once, and returns each part's LAST output object in the parts' order. Before the parts start, the
        run's global variables are handed to the workers. Throws on the first part that fails (the caller then does the work
        on one core). A worker's warnings are said here.
    #>
    # -NoGlobals (#744): the run's global variables are NOT handed over -- for a part script that reads only its arguments
    # (the delivery steps: the stored rows decoded, the JSON text of rows, the Log Analytics preparation)
    param([Parameter(Mandatory)][string]$Script, [Parameter(Mandatory)][object[]]$PartArgs, [switch]$NoGlobals)
    $workers = Get-RAParallelWorkers -Count $PartArgs.Count
    $ro = [System.Management.Automation.ScopedItemOptions]::ReadOnly -bor [System.Management.Automation.ScopedItemOptions]::Constant
    # never a script block / delegate (Test-RAParallelHandOver): it would run on the main runspace, which is waiting here
    $globals = @()
    if (-not $NoGlobals) { $globals = @(Get-Variable -Scope Global | Where-Object { $_.Name -notin $script:RAParallelSkipVars -and -not ($_.Options -band $ro) -and (Test-RAParallelHandOver $_.Value) }) }
    # the worker works in the main thread's culture (a number formatted / read the same way as on one core)
    $culture = @([System.Globalization.CultureInfo]::CurrentCulture.Name, [System.Globalization.CultureInfo]::CurrentUICulture.Name)
    $pending = [System.Collections.Generic.List[object]]::new()
    try {
        for ($i = 0; $i -lt $PartArgs.Count; $i++) {
            $rs = $workers[$i]
            foreach ($g in $globals) { try { $rs.SessionStateProxy.SetVariable($g.Name, $g.Value) } catch { } }
            $rs.SessionStateProxy.SetVariable('RA_ParallelWorker', $true)
            $rs.SessionStateProxy.SetVariable('RA_ParallelCulture', $culture)
            $ps = [powershell]::Create()
            $ps.Runspace = $rs
            $null = $ps.AddScript($Script, $false)
            foreach ($a in $PartArgs[$i]) { $null = $ps.AddArgument($a) }
            $pending.Add(@($ps, $ps.BeginInvoke()))
        }
        $results = [System.Collections.Generic.List[object]]::new()
        $failed = $null
        $me = [System.Diagnostics.Process]::GetCurrentProcess()
        $quiet = [TimeSpan]::FromMinutes([Math]::Max(1, [double]$script:RAParallelNoProgressMinutes))
        foreach ($pw in $pending) {
            try {
                # wait while the workers make progress (CPU used); a part with no progress for the window is stopped and the
                # step is redone on one core
                $me.Refresh(); $cpu = $me.TotalProcessorTime; $since = [DateTime]::UtcNow
                while (-not $pw[1].AsyncWaitHandle.WaitOne(30000)) {
                    $me.Refresh(); $cpuNow = $me.TotalProcessorTime
                    if (($cpuNow - $cpu).TotalSeconds -ge 1) { $cpu = $cpuNow; $since = [DateTime]::UtcNow; continue }
                    if (([DateTime]::UtcNow - $since) -lt $quiet) { continue }
                    foreach ($q in $pending) { try { $null = $q[0].BeginStop($null, $null) } catch { } }
                    # a worker that was stopped is not reused (its state is unknown)
                    $script:RAParallelWorkers = $null
                    throw ('a part made no progress for {0} minutes (no CPU used)' -f [int]$quiet.TotalMinutes)
                }
                $r = @($pw[0].EndInvoke($pw[1]))
                if ($r.Count -eq 0) { if ($pw[0].Streams.Error.Count -gt 0) { throw $pw[0].Streams.Error[0].Exception }; throw 'a part returned nothing' }
                foreach ($w in $pw[0].Streams.Warning) { Write-Warning $w.Message }
                $results.Add($r[-1])
            } catch { if ($null -eq $failed) { $failed = $_.Exception.Message } }
        }
        if ($null -ne $failed) { throw $failed }
        , $results.ToArray()
    } finally {
        # only a part that ended is disposed: disposing one still running waits for it, which is the hang this avoids
        foreach ($pw in $pending) { if ($pw[1].IsCompleted) { try { $pw[0].Dispose() } catch { } } }
    }
}

# what a worker runs for one part of the scores: Calculate-RiskScore over its rows (no sort: the caller sorts once)
$script:RAParallelScoreScript = @'
param($Rows, $P)
$ProgressPreference = 'SilentlyContinue'
$global:RA_ParallelWorker = $true
if ($global:RA_ParallelCulture) {
    [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[0])
    [System.Globalization.CultureInfo]::CurrentUICulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[1])
}
$script:_mdOversizeSkipped = 0
$res = @(Calculate-RiskScore -Rows $Rows @P)
[pscustomobject]@{ Rows = $res; Oversize = [int]$script:_mdOversizeSkipped }
'@

# what a worker runs for one part of the stored form: ConvertTo-RAStreamRowItems over its rows, from its place in the order
$script:RAParallelItemsScript = @'
param($Rows, $FirstSeq, $InView, $Context)
$ProgressPreference = 'SilentlyContinue'
if ($global:RA_ParallelCulture) {
    [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[0])
    [System.Globalization.CultureInfo]::CurrentUICulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[1])
}
$dc = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$b = ConvertTo-RAStreamRowItems -Rows $Rows -FirstSeq $FirstSeq -InView $InView -Context $Context -DateCols $dc
[pscustomobject]@{ Items = $b.Items; AssetItems = $b.AssetItems; Illegal = $b.Illegal; DateCols = [string[]]@($dc) }
'@

function Invoke-RAParallelScoring {
    <#
        Scores the (already de-duplicated) rows of one non-Summary slice on several cores. -Bound: Calculate-RiskScore's
        bound parameters (forwarded, without -Rows / -SortBy / -Descending / -Trace). Returns @{ Rows (in the rows' order,
        not yet sorted); Oversize (fields MoreDetails skipped) } -- or $null when the slice is scored on one core (one core
        set, a slice under the minimum, or the workers failed: said in plain words).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [Parameter(Mandatory)][hashtable]$Bound, [Parameter(Mandatory)]$RiskIndex)
    if ($global:RA_ParallelWorker) { return $null }
    $parts = Get-RAParallelSplit -Count $Rows.Count
    if ($null -eq $parts) { return $null }
    try {
        # the run's catalogs are read HERE first (they are read once per process and kept in globals): every worker then
        # starts from exactly what this run has read, never a fresh read of its own
        foreach ($warm in 'Get-RAFactorCatalogFactors', 'Get-RAFactorAliasMap', 'Get-RAFactorImpactMap', 'Get-RAFactorCatalog', 'Get-RARiskRatingBands') {
            if (Get-Command -Name $warm -ErrorAction SilentlyContinue) { $null = & $warm }
        }
        $partArgs = [System.Collections.Generic.List[object]]::new()
        foreach ($range in $parts) {
            $p = @{}
            foreach ($k in $Bound.Keys) { if ($k -notin 'Rows', 'SortBy', 'Descending', 'Trace', 'RiskIndex') { $p[$k] = $Bound[$k] } }
            # the risk index with a memo of its own (the memo is written while scoring)
            $ix = $RiskIndex
            if ($null -ne $RiskIndex.PSObject.Properties['Memo']) {
                $ix = $RiskIndex.PSObject.Copy()
                $ix.Memo = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::Ordinal)
            }
            $p['RiskIndex'] = $ix
            $partArgs.Add(@((Get-RAParallelPart -Rows $Rows -Range $range), $p))
        }
        $results = Invoke-RAParallelParts -Script $script:RAParallelScoreScript -PartArgs $partArgs.ToArray()
        $out = [System.Collections.Generic.List[object]]::new([int]($Rows.Count))
        $over = 0
        foreach ($res in $results) { foreach ($x in $res.Rows) { $out.Add($x) }; $over += [int]$res.Oversize }
        if ($out.Count -ne $Rows.Count) { throw ('the parts returned {0} row(s) for {1}' -f $out.Count, $Rows.Count) }
        return [pscustomobject]@{ Rows = $out.ToArray(); Oversize = $over; Cores = $parts.Count }
    } catch {
        $msg = 'The risk scores of this query slice are worked out on one processor core instead of several (the result is the same): {0}' -f $_.Exception.Message
        if (Get-Command -Name Write-Warn2 -ErrorAction SilentlyContinue) { Write-Warn2 $msg } else { Write-Warning $msg }
        return $null
    }
}

function Invoke-RAParallelStreamItems {
    <#
        The stored form of one Detailed slice's rows (ConvertTo-RAStreamRowItems, RA-SqlStream.ps1) made on several cores:
        contiguous parts, each from its own place in the write order, put back in order; the date columns the parts found
        are added to -DateCols. Returns what ConvertTo-RAStreamRowItems returns -- or $null to make it in one pass (one
        core set, a slice under the minimum, or the workers failed: said in plain words).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [long]$FirstSeq, [bool[]]$InView, [Parameter(Mandatory)][hashtable]$Context,
          [System.Collections.Generic.HashSet[string]]$DateCols)
    if ($global:RA_ParallelWorker) { return $null }
    $parts = Get-RAParallelSplit -Count $Rows.Count
    if ($null -eq $parts) { return $null }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $partArgs = [System.Collections.Generic.List[object]]::new()
        foreach ($range in $parts) {
            $iv =New-Object 'bool[]' ([int]$range[1])
            if ($null -ne $InView) { [System.Array]::Copy($InView, [int]$range[0], $iv, 0, [int]$range[1]) }
            $partArgs.Add(@((Get-RAParallelPart -Rows $Rows -Range $range), ([long]$FirstSeq + [long]$range[0]), $iv, $Context))
        }
        $results = Invoke-RAParallelParts -Script $script:RAParallelItemsScript -PartArgs $partArgs.ToArray()
        $items = [System.Collections.Generic.List[string]]::new()
        $assets = [System.Collections.Generic.List[string]]::new()
        $illegal = 0L
        foreach ($res in $results) {
            foreach ($x in $res.Items) { $items.Add([string]$x) }
            foreach ($x in $res.AssetItems) { $assets.Add([string]$x) }
            $illegal += [long]$res.Illegal
            if ($null -ne $DateCols) { foreach ($c in $res.DateCols) { if ($c) { [void]$DateCols.Add([string]$c) } } }
        }
        if ($items.Count -ne $Rows.Count) { throw ('the parts returned {0} item(s) for {1} row(s)' -f $items.Count, $Rows.Count) }
        if (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) {
            Write-Info ([string]::Format([System.Globalization.CultureInfo]::InvariantCulture, 'rows of this query slice prepared for the database: {0:N0} row(s) on {1} processor cores in {2:N1} s', $Rows.Count, $parts.Count, $sw.Elapsed.TotalSeconds))
        }
        return [pscustomobject]@{ Items = $items.ToArray(); AssetItems = $assets.ToArray(); Illegal = $illegal }
    } catch {
        $msg = 'The rows of this query slice are prepared for the database on one processor core instead of several (the result is the same): {0}' -f $_.Exception.Message
        if (Get-Command -Name Write-Warn2 -ErrorAction SilentlyContinue) { Write-Warn2 $msg } else { Write-Warning $msg }
        return $null
    }
}

# =====================================================================================================================
#  #744 THE DELIVERY STEPS ON THE CORES (the run's result read back from the database, the JSON file, Log Analytics).
#
#  Live (a large customer, 1,138,554 Detailed rows, 2026-10-17): after the reports, the result is read back a page at a
#  time and every row was decoded, prepared for Log Analytics and written to the JSON file on the ONE main thread
#  (measured per row: decode 0.6 ms, the Log Analytics preparation 1.4 ms). Each step below is the SAME function per row,
#  on contiguous parts of the page / chunk, put back in order -- the rows, their values and their order are those of one
#  pass. None of these parts needs the run's globals: they read only their arguments (-NoGlobals), and every function
#  they call is in the engine files every worker loads ($script:RAParallelFiles; tests\pester\SIv3-RaFinishSpeed pins it).
#  Anything that goes wrong is said in plain words and the step is done on one core (the result is the same).
# =====================================================================================================================

# a part of the stored rows decoded (ConvertFrom-RAStreamJson, RA-SqlStream.ps1), each with its report's columns
$script:RAParallelDecodeScript = @'
param($Texts, $Ords, $Cols, $Dates)
$ProgressPreference = 'SilentlyContinue'
if ($global:RA_ParallelCulture) {
    [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[0])
    [System.Globalization.CultureInfo]::CurrentUICulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[1])
}
$out = New-Object 'object[]' ($Texts.Count)
for ($i = 0; $i -lt $Texts.Count; $i++) {
    $o = [int]$Ords[$i]
    $out[$i] = ConvertFrom-RAStreamJson -Json ([string]$Texts[$i]) -Columns $Cols[$o] -DateCols $Dates[$o]
}
[pscustomobject]@{ Rows = $out }
'@

# a part of the rows as the JSON file writes them (ConvertTo-Json -Depth, one text per row)
$script:RAParallelJsonTextScript = @'
param($Rows, $Depth)
$ProgressPreference = 'SilentlyContinue'
if ($global:RA_ParallelCulture) {
    [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[0])
    [System.Globalization.CultureInfo]::CurrentUICulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[1])
}
$t = New-Object 'string[]' ($Rows.Count)
for ($i = 0; $i -lt $Rows.Count; $i++) { $t[$i] = ConvertTo-Json -Depth $Depth -InputObject $Rows[$i] }
[pscustomobject]@{ Texts = $t }
'@

# the Log Analytics preparation, round 1 (every step that depends only on the row): copies, the run's collection time,
# the host columns, legal column names
$script:RAParallelLaShapeScript = @'
param($Rows, $HostName, $Fqdn, $User, $CollectionTime)
$ProgressPreference = 'SilentlyContinue'
if ($global:RA_ParallelCulture) {
    [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[0])
    [System.Globalization.CultureInfo]::CurrentUICulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[1])
}
# the run's ONE collection time (minted by the main run before the parts start): a row without one gets exactly it
$global:SI_LogIngestRunCollectionTime = $CollectionTime
$copies = New-Object 'System.Collections.Generic.List[object]' ($Rows.Count)
foreach ($r in $Rows) { if ($null -ne $r) { [void]$copies.Add($r.PSObject.Copy()) } }
$data = $copies.ToArray(); $copies = $null
$data = @(Add-SICollectionTime -Data $data -Verbose:$false 4>$null)
$data = @(Add-SIColumnData -Data $data -Column1Name Computer -Column1Data $HostName -Column2Name ComputerFqdn -Column2Data $Fqdn `
                            -Column3Name UserLoggedOn -Column3Data $User -Verbose:$false 4>$null)
$data = @(Repair-SILogColumnName -Data $data -Verbose:$false 4>$null)
[pscustomobject]@{ Rows = $data }
'@

# round 2 (after the main run read the chunk's columns over ALL its rows, as one pass does): every column of the chunk on
# every row in schema order, then every value to its column's type
$script:RAParallelLaAlignScript = @'
param($Rows, $Names, $Types, $Dec, $Txt, $Num)
$ProgressPreference = 'SilentlyContinue'
if ($global:RA_ParallelCulture) {
    [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[0])
    [System.Globalization.CultureInfo]::CurrentUICulture = [System.Globalization.CultureInfo]::GetCultureInfo([string]$global:RA_ParallelCulture[1])
}
$data = @(Format-SILogRowsToNames -Data $Rows -Names $Names)
$align = $null
if ($Types -and $Types.Count -gt 0) {
    $align = Set-RALaColumnTypes -Rows $data -Types $Types -DecimalCompanions $Dec -TextCompanions $Txt -NumberCompanions $Num
}
[pscustomobject]@{ Rows = $data; Align = $align }
'@

function Write-RAParallelFallback {
    <# The step is done on one core instead (the result is the same): said once per step and run, in plain words. #>
    param([Parameter(Mandatory)][string]$Step, [string]$Why)
    if (-not $script:RAParallelFallbackSaid) { $script:RAParallelFallbackSaid = @{} }
    if ($script:RAParallelFallbackSaid.ContainsKey($Step)) { return }
    $script:RAParallelFallbackSaid[$Step] = $true
    $msg = '{0} on one processor core instead of several (the result is the same): {1}' -f $Step, $Why
    if (Get-Command -Name Write-Warn2 -ErrorAction SilentlyContinue) { Write-Warn2 $msg } else { Write-Warning $msg }
}

function Invoke-RAParallelDecode {
    <#
        A page of stored rows (New-RARowPager: hashtables with Json + RaReport) decoded on several cores: the same
        ConvertFrom-RAStreamJson per row with its report's columns, in the page's order. -ByOrd: the report per ordinal
        (Columns, DateCols). Returns the rows, or $null to decode them in one pass (one core set, a page under the minimum,
        or the workers failed: said once).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Stored, $ByOrd)
    if ($global:RA_ParallelWorker) { return $null }
    $parts = Get-RAParallelSplit -Count $Stored.Count
    if ($null -eq $parts) { return $null }
    try {
        $cols = @{}; $dates = @{}
        if ($ByOrd) { foreach ($k in @($ByOrd.Keys)) { $rep = $ByOrd[$k]; if ($rep) { $cols[[int]$k] = $rep.Columns.ToArray(); $dates[[int]$k] = $rep.DateCols } } }
        $texts = New-Object 'string[]' ($Stored.Count); $ords = New-Object 'int[]' ($Stored.Count)
        for ($i = 0; $i -lt $Stored.Count; $i++) { $texts[$i] = [string]$Stored[$i]['Json']; $ords[$i] = [int]$Stored[$i]['RaReport'] }
        $partArgs = [System.Collections.Generic.List[object]]::new()
        foreach ($range in $parts) {
            $t = New-Object 'string[]' ([int]$range[1]); [System.Array]::Copy($texts, [int]$range[0], $t, 0, [int]$range[1])
            $o = New-Object 'int[]' ([int]$range[1]); [System.Array]::Copy($ords, [int]$range[0], $o, 0, [int]$range[1])
            $partArgs.Add(@($t, $o, $cols, $dates))
        }
        $results = Invoke-RAParallelParts -Script $script:RAParallelDecodeScript -PartArgs $partArgs.ToArray() -NoGlobals
        $out = New-Object 'object[]' ($Stored.Count); $at = 0
        foreach ($res in $results) { foreach ($x in $res.Rows) { $out[$at] = $x; $at++ } }
        if ($at -ne $Stored.Count) { throw ('the parts returned {0} row(s) for {1}' -f $at, $Stored.Count) }
        , $out
    } catch {
        Write-RAParallelFallback -Step 'The result is read back from the database' -Why $_.Exception.Message
        return $null
    }
}

function Invoke-RAParallelJsonText {
    <# The JSON text of each row (ConvertTo-Json -Depth -InputObject), made on several cores, in the rows' order -- or $null
       to make them in one pass (said once). #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [int]$Depth = 20)
    if ($global:RA_ParallelWorker) { return $null }
    $parts = Get-RAParallelSplit -Count $Rows.Count
    if ($null -eq $parts) { return $null }
    try {
        $partArgs = [System.Collections.Generic.List[object]]::new()
        foreach ($range in $parts) { $partArgs.Add(@((Get-RAParallelPart -Rows $Rows -Range $range), $Depth)) }
        $results = Invoke-RAParallelParts -Script $script:RAParallelJsonTextScript -PartArgs $partArgs.ToArray() -NoGlobals
        $out = New-Object 'string[]' ($Rows.Count); $at = 0
        foreach ($res in $results) { foreach ($x in $res.Texts) { $out[$at] = [string]$x; $at++ } }
        if ($at -ne $Rows.Count) { throw ('the parts returned {0} text(s) for {1} row(s)' -f $at, $Rows.Count) }
        , $out
    } catch {
        Write-RAParallelFallback -Step 'The JSON file is written' -Why $_.Exception.Message
        return $null
    }
}

function Invoke-RAParallelLaPrepare {
    <#
        ConvertTo-RALaPostRows (RA-Delivery.ps1) of ONE chunk on several cores, exactly as one pass makes it:
          round 1 (the parts): copies, the run's collection time, the host columns, legal names -- each only the row's own;
          the main run: the chunk's columns over ALL its rows (Get-SILogSchemaRest, the one pass's schema, in its order);
          round 2 (the parts): those columns on every row in that order, every value to its column's type (the counts added).
        Returns @{ Rows; Align } as ConvertTo-RALaPostRows does -- or $null to prepare the chunk in one pass (one core set,
        a chunk under the minimum, or the workers failed: said once).
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
          [AllowEmptyString()][string]$HostName = '', [AllowEmptyString()][string]$Fqdn = '', [AllowEmptyString()][string]$User = '',
          [hashtable]$Types, [string[]]$DecimalCompanions = @(), [string[]]$TextCompanions = @(), [string[]]$NumberCompanions = @())
    if ($global:RA_ParallelWorker) { return $null }
    $nn = [System.Collections.Generic.List[object]]::new($Rows.Count)
    foreach ($r in $Rows) { if ($null -ne $r) { $nn.Add($r) } }
    if ($nn.Count -eq 0) { return $null }
    $parts = Get-RAParallelSplit -Count $nn.Count
    if ($null -eq $parts) { return $null }
    try {
        foreach ($fn in 'Add-SICollectionTime', 'Get-SILogSchemaRest', 'Format-SILogRowsToNames') {
            if (-not (Get-Command -Name $fn -ErrorAction SilentlyContinue)) { throw "$fn is not loaded" }
        }
        # the run's collection time, minted HERE first (a row without one gets exactly this value in every part)
        $null = Add-SICollectionTime -Data @([pscustomobject]@{ CollectionTime = 'set' }) -Verbose:$false 4>$null
        $ct = $global:SI_LogIngestRunCollectionTime
        $all = $nn.ToArray(); $nn = $null
        $a1 = [System.Collections.Generic.List[object]]::new()
        foreach ($range in $parts) { $a1.Add(@((Get-RAParallelPart -Rows $all -Range $range), $HostName, $Fqdn, $User, $ct)) }
        $r1 = Invoke-RAParallelParts -Script $script:RAParallelLaShapeScript -PartArgs $a1.ToArray() -NoGlobals
        $shaped = New-Object 'object[]' ($all.Count); $at = 0
        foreach ($res in $r1) { foreach ($x in $res.Rows) { $shaped[$at] = $x; $at++ } }
        if ($at -ne $all.Count) { throw ('the parts returned {0} row(s) for {1}' -f $at, $all.Count) }
        $r1 = $null; $a1 = $null
        # the chunk's columns, over all its rows, in the one pass's order
        $schema = @(Get-SILogSchemaRest -Data $shaped -As Array)
        $names = [string[]]@(foreach ($c in $schema) { [string]$c.name })
        $a2 = [System.Collections.Generic.List[object]]::new()
        foreach ($range in $parts) { $a2.Add(@((Get-RAParallelPart -Rows $shaped -Range $range), $names, $Types, [string[]]@($DecimalCompanions), [string[]]@($TextCompanions), [string[]]@($NumberCompanions))) }
        $r2 = Invoke-RAParallelParts -Script $script:RAParallelLaAlignScript -PartArgs $a2.ToArray() -NoGlobals
        $out = New-Object 'object[]' ($all.Count); $at = 0
        $align = $null
        if ($Types -and $Types.Count -gt 0) { $align = New-RALaAlignReport }
        foreach ($res in $r2) {
            foreach ($x in $res.Rows) { $out[$at] = $x; $at++ }
            if ($null -ne $align) { Merge-RALaAlignReport -Into $align -Align $res.Align }
        }
        if ($at -ne $all.Count) { throw ('the parts returned {0} prepared row(s) for {1}' -f $at, $all.Count) }
        @{ Rows = $out; Align = $align }
    } catch {
        Write-RAParallelFallback -Step 'The rows are prepared for Log Analytics' -Why $_.Exception.Message
        return $null
    }
}
