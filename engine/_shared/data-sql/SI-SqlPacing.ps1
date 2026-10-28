#Requires -Version 5.1
<#
    SecurityInsight -- THE DATABASE'S OWN LOAD PACES THE LARGE WRITERS (owner 2026-10-18: a product fix, never "buy a bigger
    database"; three school installs and a large customer saw "the database is at its limit" for whole hours of a full run).

    WHAT IT IS. One shared helper every large batched writer calls BEFORE each batch:
      * Risk Analysis Detailed streaming its findings (Write-SIDataJsonRows, the chunked JSON insert it uses),
      * the data sync's prepared-context field fill (SI-DataViewContext.ps1 Invoke-SIDataViewContext) and the views' derive,
      * collection retention's batched deletes (Invoke-SIDataBatchedDelete).
    The removal of RETIRED collections (key ranges and batches) uses its own rule instead -- it waits until the database is
    calm (Invoke-SISqlPacingHousekeeping, -Housekeeping).
    It reads the database's own load -- log write, data IO and CPU, in percent of what its tier allows -- and:
      above the HIGH mark (SI_SqlPacing_HighPercent, default 85)  waits before the batch -- a measured pause that grows
                                                                   while the database stays above it -- and asks for a
                                                                   smaller next batch;
      between the marks                                            keeps the pause it has (no growth, no shrink);
      below the LOW mark (SI_SqlPacing_LowPercent, default 70)     back to today's pace: no pause.
    No row is ever left out, no batch is cut short and nothing is capped: the writer only goes slower while the database is
    saturated, so the web app and the other jobs keep a share. Equal output is the contract (the tests prove it).

    WHERE THE LOAD COMES FROM (cheapest first; "unknown" = today's behaviour, it never fails a writer):
      1. sys.dm_db_resource_stats through the writer's own SQL seam (Azure SQL: one row per 15 s; the newest ~30 s are
         used). Needs VIEW DATABASE (PERFORMANCE) STATE: an identity without it gets "denied" once and the next source is used.
      2. The database's Azure Monitor metrics through ARM (log_write_percent, physical_data_read_percent, cpu_percent;
         one-minute values; the same read the heartbeat makes with the engine identity), at most once a minute.
      3. Neither -> the writer's OWN MEASURED STATEMENT TIME (#881; a data sync failed at one install on "VIEW DATABASE
         PERFORMANCE STATE permission denied"): the writers size their batches for a steady time each (Get-SIDataNextSize),
         so a batch that takes far longer than the batches before it is the database slowing down -- 1.7 x their median is
         read as the HIGH mark, 1.4 x as the LOW mark (Get-SISqlPacingMeasuredLoad). Needs no right and no statement.
      4. Nothing measured yet -> unknown: no pause, said once in plain words.
    Only a REAL connection (New-SIDataSqlInvoke marks its seam with SISqlTarget) or a source registered explicitly
    (Register-SISqlPacingSource -- the tests) is read: any other seam behaves exactly as before, with no extra statement.

    THE LOG says it in ONE plain line per minute at most: "pacing: the database is at 97 % log write -- slower batches (8 s
    pause before each)" / "pacing: the database is back at 42 % -- the usual pace". No internal numbers.

    PS 5.1 safe: no ?. / ??, no ternary. No module.
#>

# the pacer of each SQL seam, for the life of the process (a seam that is gone takes its pacer with it)
$script:SISqlPacers = New-Object 'System.Runtime.CompilerServices.ConditionalWeakTable[object,object]'

$script:SISqlPacingDmvSql = 'SELECT TOP (2) end_time, avg_cpu_percent, avg_data_io_percent, avg_log_write_percent FROM sys.dm_db_resource_stats ORDER BY end_time DESC'
$script:SISqlPacingArmApi = '2023-10-01'

function Get-SISqlPacingSettings {
    <#
        PURE over the globals (or -Globals). @{ Enabled; High; Low }:
          SI_SqlPacing_Enabled      on unless 'false' / '0' / 'no' / 'off' / $false (default ON: it only slows a saturated database)
          SI_SqlPacing_HighPercent  1..100, default 85
          SI_SqlPacing_LowPercent   0..High-1, default 70 (a value at or above High becomes High - 15, at least 0)
        A value that is not a number keeps its default.
    #>
    param([System.Collections.IDictionary]$Globals)
    $g = {
        param($n)
        if ($Globals) { if ($Globals.Contains($n)) { return $Globals[$n] } else { return $null } }
        Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue
    }
    $on = $true
    $e = & $g 'SI_SqlPacing_Enabled'
    if ($null -ne $e) {
        if ($e -is [bool]) { $on = [bool]$e }
        elseif ("$e".Trim() -match '^(?i)(false|0|no|off|\$false)$') { $on = $false }
    }
    $num = { param($v, [double]$d) $x = 0.0; if ($null -ne $v -and [double]::TryParse("$v".Trim(), [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$x)) { return $x }; $d }
    $high = & $num (& $g 'SI_SqlPacing_HighPercent') 85
    if ($high -lt 1 -or $high -gt 100) { $high = 85 }
    $low = & $num (& $g 'SI_SqlPacing_LowPercent') 70
    if ($low -lt 0) { $low = 0 }
    if ($low -ge $high) { $low = [Math]::Max(0, $high - 15) }
    [pscustomobject]@{ Enabled = $on; High = [double]$high; Low = [double]$low }
}

function ConvertFrom-SISqlPacingDmvRows {
    <#
        PURE. Rows of sys.dm_db_resource_stats (newest first) -> @{ Log; Data; Cpu; Max; Source = 'database' } over the newest
        rows given (their average per component), or $null when there is none. Max = the highest of the three: the share of
        its tier the database uses (what DTU percent is).
    #>
    param([object[]]$Rows = @())
    $get = { param($r, $k) if ($r -is [System.Collections.IDictionary]) { $r[$k] } else { $r.$k } }
    $n = 0; $lw = 0.0; $io = 0.0; $cpu = 0.0
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $a = & $get $r 'avg_log_write_percent'; $b = & $get $r 'avg_data_io_percent'; $c = & $get $r 'avg_cpu_percent'
        if (($null -eq $a -or $a -is [System.DBNull]) -and ($null -eq $b -or $b -is [System.DBNull]) -and ($null -eq $c -or $c -is [System.DBNull])) { continue }
        $n++
        if ($null -ne $a -and -not ($a -is [System.DBNull])) { $lw += [double]$a }
        if ($null -ne $b -and -not ($b -is [System.DBNull])) { $io += [double]$b }
        if ($null -ne $c -and -not ($c -is [System.DBNull])) { $cpu += [double]$c }
    }
    if ($n -eq 0) { return $null }
    New-SISqlPacingLoad -Log ($lw / $n) -Data ($io / $n) -Cpu ($cpu / $n) -Source 'database'
}

function ConvertFrom-SISqlPacingMetrics {
    <#
        PURE. An ARM metrics answer (log_write_percent / physical_data_read_percent / cpu_percent, one value per minute) ->
        the load of the NEWEST minute that carries a value per metric, or $null when none carries one.
    #>
    param($Metrics)
    if ($null -eq $Metrics -or -not $Metrics.PSObject.Properties['value']) { return $null }
    $v = @{}
    foreach ($m in @($Metrics.value)) {
        if ($null -eq $m) { continue }
        $name = ''; try { $name = [string]$m.name.value } catch { $name = '' }
        $last = $null
        foreach ($ts in @($m.timeseries)) {
            foreach ($d in @($ts.data)) {
                if ($null -eq $d) { continue }
                $x = $null
                foreach ($k in 'average', 'maximum') { if ($d.PSObject.Properties[$k] -and $null -ne $d.$k) { $x = [double]$d.$k; break } }
                if ($null -ne $x) { $last = $x }
            }
        }
        if ($null -ne $last) { $v[$name] = $last }
    }
    if ($v.Count -eq 0) { return $null }
    $pick = { param($k) if ($v.ContainsKey($k)) { [double]$v[$k] } else { 0.0 } }
    New-SISqlPacingLoad -Log (& $pick 'log_write_percent') -Data (& $pick 'physical_data_read_percent') -Cpu (& $pick 'cpu_percent') -Source 'metrics'
}

function Get-SISqlPacingMeasuredLoad {
    <#
        PURE. #881 The load as the writer's own statements measure it, when the database's figures cannot be read: -LastBatchMs
        against the MEDIAN of the batches before it (-Times, oldest first). Max = 50 x last / median, so a batch 1.7 x the
        median reads as 85 (the default HIGH mark) and 1.4 x as 70 (LOW). $null until three batches are measured, or when
        -LastBatchMs is not a measurement. Source 'measured'.
    #>
    param([long[]]$Times = @(), [long]$LastBatchMs = 0)
    $t = @(@($Times) | Where-Object { $_ -gt 0 })
    if ($LastBatchMs -le 0 -or $t.Count -lt 3) { return $null }
    $s = @($t | Sort-Object)
    $mid = [int][Math]::Floor($s.Count / 2)
    $median = if ($s.Count % 2) { [double]$s[$mid] } else { ([double]$s[$mid - 1] + [double]$s[$mid]) / 2.0 }
    if ($median -le 0) { return $null }
    $x = 50.0 * [double]$LastBatchMs / $median
    $l = New-SISqlPacingLoad -Log $x -Source 'measured'
    $l.What = 'statement time'
    $l
}

function New-SISqlPacingLoad {
    <# PURE. One load reading: the three components, the highest of them and the name of the highest (for the log line). #>
    param([double]$Log = 0, [double]$Data = 0, [double]$Cpu = 0, [string]$Source = 'test')
    $max = $Log; $what = 'log write'
    if ($Data -gt $max) { $max = $Data; $what = 'data reads' }
    if ($Cpu -gt $max) { $max = $Cpu; $what = 'CPU' }
    [pscustomobject]@{ Log = [Math]::Round($Log, 1); Data = [Math]::Round($Data, 1); Cpu = [Math]::Round($Cpu, 1); Max = [Math]::Round($max, 1); What = $what; Source = $Source }
}

function Get-SISqlPacingDecision {
    <#
        PURE. THE RULE. From the reading (-Load: $null = unknown), the pause in force (-PauseMs) and the last batch's measured
        time (-LastBatchMs), with -High / -Low:
          unknown         no pause (today's behaviour); the pacing state ends
          >= High         pause: the first one = the last batch's own time (at least 1 s), each next one double the last --
                          never longer than 4 x the last batch's time or 60 s, so the writer always keeps at least a fifth of
                          its pace; the next batch is asked to be smaller (Shrink)
          between         the pause in force is kept, nothing shrinks
          < Low           no pause: today's pace
        Returns @{ PauseMs; Shrink; State = unknown | saturated | holding | normal }.
    #>
    param($Load, [long]$PauseMs = 0, [long]$LastBatchMs = 0, [double]$High = 85, [double]$Low = 70)
    if ($null -eq $Load) { return [pscustomobject]@{ PauseMs = 0L; Shrink = $false; State = 'unknown' } }
    $m = [double]$Load.Max
    if ($m -ge $High) {
        $first = [Math]::Max(1000L, $LastBatchMs)
        $want = if ($PauseMs -le 0) { $first } else { 2L * $PauseMs }
        $ceil = [Math]::Min(60000L, [Math]::Max(4000L, 4L * $LastBatchMs))
        return [pscustomobject]@{ PauseMs = [long][Math]::Min($want, $ceil); Shrink = $true; State = 'saturated' }
    }
    if ($m -ge $Low -and $PauseMs -gt 0) { return [pscustomobject]@{ PauseMs = [long]$PauseMs; Shrink = $false; State = 'holding' } }
    [pscustomobject]@{ PauseMs = 0L; Shrink = $false; State = 'normal' }
}

function Format-SISqlPacingLine {
    <# PURE. The one plain line: what the database is at, and what the writer does about it. -State from the decision. #>
    param([Parameter(Mandatory)][string]$State, $Load, [long]$PauseMs = 0)
    $pct = { param($x) ('{0:0}' -f [double]$x) + ' %' }
    # #881 measured on the writer's own statements (the database's figures cannot be read): said as how much slower it answers
    if ($Load -and $Load.PSObject.Properties['Source'] -and [string]$Load.Source -eq 'measured') {
        $times = [double]$Load.Max / 50.0
        switch ($State) {
            'saturated' { return ('pacing: the database answers {0:0.0} x slower than the batches before -- slower batches ({1:0} s pause before each)' -f $times, ($PauseMs / 1000.0)) }
            'holding'   { return ('pacing: the database answers {0:0.0} x slower than the batches before -- still slower batches ({1:0} s pause before each)' -f $times, ($PauseMs / 1000.0)) }
            'normal'    { return 'pacing: the database answers at its usual pace again -- the usual pace' }
        }
    }
    switch ($State) {
        'saturated' { return ('pacing: the database is at {0} {1} -- slower batches ({2:0} s pause before each)' -f (& $pct $Load.Max), $Load.What, ($PauseMs / 1000.0)) }
        'holding'   { return ('pacing: the database is at {0} {1} -- still slower batches ({2:0} s pause before each)' -f (& $pct $Load.Max), $Load.What, ($PauseMs / 1000.0)) }
        'normal'    { return ('pacing: the database is back at {0} -- the usual pace' -f (& $pct $Load.Max)) }
        default     { return 'pacing: the database''s load cannot be read -- writing at the usual pace' }
    }
}

function Register-SISqlPacingSource {
    <#
        A load source of its own for -Invoke (the tests; a measurement): -Read returns a load (New-SISqlPacingLoad) or $null.
        -Sleep replaces the wait (param($ms)); -Clock replaces the time in seconds (a scriptblock). -Globals: the settings to use.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Read, [scriptblock]$Sleep, [scriptblock]$Clock, [System.Collections.IDictionary]$Globals, [scriptblock]$Log)
    $p = Get-SISqlPacer -Invoke $Invoke -Log $Log -Globals $Globals -Force
    if ($Read) { $p.Read = $Read }
    if ($Sleep) { $p.Sleep = $Sleep }
    if ($Clock) { $p.Clock = $Clock }
    $p
}

function Get-SISqlPacer {
    <#
        The pacer of one SQL seam (kept per seam for the life of the process): its settings, its load source, its state.
        -Force makes a new one. -Log: where its line goes (the first writer that gives one; default the console).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log, [System.Collections.IDictionary]$Globals, [switch]$Force)
    $p = $null
    if (-not $Force) {
        $o = $null
        if ($script:SISqlPacers.TryGetValue($Invoke, [ref]$o)) { $p = $o }
    }
    if ($null -eq $p) {
        $s = Get-SISqlPacingSettings -Globals $Globals
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $p = @{ Enabled = $s.Enabled; High = $s.High; Low = $s.Low; Read = $null; Sleep = $null; Log = $Log
                Clock = { $sw.Elapsed.TotalSeconds }.GetNewClosure()
                Load = $null; ReadAt = [double]::NegativeInfinity; ReadEvery = 15.0
                PauseMs = 0L; State = 'normal'; SaidAt = [double]::NegativeInfinity; SaidState = 'normal'
                PausedMs = 0L; Pauses = 0L; UnknownSaid = $false
                HkRan = $false; HkWaiting = $false; HkPauseMs = 0L
                DmvOff = $false; ArmOff = $false; ArmFails = 0; ArmAt = [double]::NegativeInfinity
                Times = (New-Object 'System.Collections.Generic.List[long]') }
        $t = $null
        if ($Invoke.PSObject.Properties['SISqlTarget']) { $t = $Invoke.SISqlTarget }
        if ($t) { $p.Read = (New-SISqlPacingReader -Invoke $Invoke -Target $t -Pacer $p) }
        [void]$script:SISqlPacers.Remove($Invoke)
        $script:SISqlPacers.Add($Invoke, $p)
    }
    if ($Log -and -not $p.Log) { $p.Log = $Log }
    $p
}

function New-SISqlPacingReader {
    <#
        The load source of a REAL connection: sys.dm_db_resource_stats through the seam, else the database's metrics through
        ARM (at most once a minute), else $null. A source that answers "not there" / "denied" is not asked again in this process.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)]$Target, [Parameter(Mandatory)][hashtable]$Pacer)
    $dmv = $script:SISqlPacingDmvSql; $api = $script:SISqlPacingArmApi
    $fromRows = ${function:ConvertFrom-SISqlPacingDmvRows}; $fromMetrics = ${function:ConvertFrom-SISqlPacingMetrics}
    # a GetNewClosure() block cannot see functions the caller dot-sourced: ARM travels in as a value (none = no second source)
    $armFn = ${function:Invoke-SIArm}
    $srv = ([string]$Target.Server).Trim(); $db = ([string]$Target.Database).Trim()
    {
        if (-not $Pacer.DmvOff) {
            try {
                $rows = @(& $Invoke $dmv @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
                $l = & $fromRows -Rows $rows
                if ($null -ne $l) { return $l }
            } catch {
                $m = [string]$_.Exception.Message
                if ($m -match '(?i)invalid object name|permission|denied|VIEW DATABASE|VIEW SERVER') { $Pacer.DmvOff = $true }
            }
        }
        if ($Pacer.ArmOff) { return $null }
        $now = & $Pacer.Clock
        if (($now - $Pacer.ArmAt) -lt 60) { return $Pacer.Load }
        $Pacer.ArmAt = $now
        if (-not $armFn -or (Get-Module -Name Pester)) { $Pacer.ArmOff = $true; return $null }
        $sub = @([string]$env:SI_FLOW_SUBSCRIPTIONID, [string]$global:SI_AzSubscriptionId) | Where-Object { "$_".Trim() } | Select-Object -First 1
        $rg = @([string]$env:SI_FLOW_RESOURCEGROUP, [string]$global:SI_Bootstrap_ResourceGroupName) | Where-Object { "$_".Trim() } | Select-Object -First 1
        $short = ($srv -split '\.')[0]
        if (-not "$sub".Trim() -or -not "$rg".Trim() -or -not $short -or -not $db) { $Pacer.ArmOff = $true; return $null }
        $path = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Sql/servers/{2}/databases/{3}/providers/Microsoft.Insights/metrics?api-version={4}&metricnames=log_write_percent,physical_data_read_percent,cpu_percent&timespan=PT5M&interval=PT1M&aggregation=Average' -f "$sub".Trim(), "$rg".Trim(), $short, $db, $api
        try {
            $l = & $fromMetrics -Metrics (& $armFn -Method GET -Path $path)
            $Pacer.ArmFails = 0
            return $l
        } catch {
            $Pacer.ArmFails++
            if ($Pacer.ArmFails -ge 3) { $Pacer.ArmOff = $true }
            return $null
        }
    }.GetNewClosure()
}

function Invoke-SISqlPacingHousekeeping {
    <#
        THE HOUSEKEEPING RULE -- the removal of retired collections ONLY (a support ticket "database at its limit", 2026-10-24:
        the writers' rule below keeps at least a fifth of the pace, and a delete's IO -- ghost cleanup, checkpoint, version
        store -- comes after the statement, so a fifth was still enough to hold data IO at 92-100 %). Housekeeping is
        background work: it GIVES WAY to the database instead of slowing a little.
          * the FIRST statement of the process (one wake-up) is never held back -- the removal always moves on, even on a
            database that is never calm (a floor on progress, never a limit on the work);
          * the load (the highest of data IO, CPU and log write) at or above HIGH: the next statement is asked to be smaller
            and the removal WAITS, re-reading the load every 15 s (the DMV's own step), until it is below LOW -- no ceiling
            tied to the statement's time; between the marks a wait in progress goes on (hysteresis), else the usual pace;
          * only the writer's own measured statement time is known: the pause doubles from the statement's own time while
            statements stay slow (no 4 x / 60 s ceiling), none once one is back at its usual time;
          * unknown load: no wait (today's behaviour);
          * every wait ends at -DeadlineUtc (the wake-up's time budget, counted on the pacer's clock): the caller then
            starts no new statement and the next wake-up goes on from what is left.
        Waits happen BETWEEN statements: no lock and no transaction is held while waiting. -P: the seam's pacer.
    #>
    param([Parameter(Mandatory)][hashtable]$P, [long]$LastBatchMs = 0, [datetime]$DeadlineUtc = [datetime]::MaxValue)
    $now = [double](& $P.Clock)
    $leftMs = if ($DeadlineUtc -eq [datetime]::MaxValue) { [double]::PositiveInfinity } else { [Math]::Max(0.0, ($DeadlineUtc - [datetime]::UtcNow).TotalMilliseconds) }
    $start = $now
    $read = {
        $t = [double](& $P.Clock)
        if (($t - $P.ReadAt) -ge $P.ReadEvery) {
            $P.ReadAt = $t
            $l = $null
            try { $l = & $P.Read } catch { $l = $null }
            $P.Load = $l
        }
        $P.Load
    }
    $say = {
        param([string]$Line)
        $P.SaidAt = [double](& $P.Clock)
        if ($P.Log) { try { & $P.Log 'INFO' $Line } catch { } } else { Write-Host ('[INFO] ' + $Line) }
    }
    $sleep = { param([long]$Ms) if ($Ms -le 0) { return }; if ($P.Sleep) { & $P.Sleep $Ms } else { Start-Sleep -Milliseconds ([int][Math]::Min([long][int]::MaxValue, $Ms)) }; $P.PausedMs += $Ms }
    # Deadline = the wait reached -DeadlineUtc on the pacer's own clock: the caller starts no new statement
    $result = { param([long]$W, [bool]$S, [string]$St, $L, [bool]$D = $false) [pscustomobject]@{ WaitedMs = $W; Shrink = $S; State = $St; Load = $L; Deadline = $D } }
    # the first statement of this wake-up always runs
    if (-not $P.HkRan) {
        $P.HkRan = $true
        if ($LastBatchMs -gt 0) { $P.Times.Add($LastBatchMs) }
        return (& $result 0L $false 'first' $null)
    }
    $load = & $read
    if ($null -eq $load) { $load = Get-SISqlPacingMeasuredLoad -Times $P.Times.ToArray() -LastBatchMs $LastBatchMs }
    if ($LastBatchMs -gt 0) { $P.Times.Add($LastBatchMs); while ($P.Times.Count -gt 20) { $P.Times.RemoveAt(0) } }
    if ($null -eq $load) {
        $P.HkWaiting = $false; $P.HkPauseMs = 0L
        if (-not $P.UnknownSaid -and ($now - $P.SaidAt) -ge 60) { $P.UnknownSaid = $true; & $say (Format-SISqlPacingLine -State 'unknown') }
        return (& $result 0L $false 'unknown' $null)
    }
    $since = $now - $P.SaidAt
    # the writer's own measured time: no statement can see the database calm down while waiting -- a growing pause
    if ([string]$load.Source -eq 'measured') {
        $m = [double]$load.Max
        $want = 0L; $shrink = $false
        if ($m -ge $P.High) { $want = if ($P.HkPauseMs -le 0) { [Math]::Max(1000L, $LastBatchMs) } else { 2L * $P.HkPauseMs }; $shrink = $true }
        elseif ($m -ge $P.Low -and $P.HkPauseMs -gt 0) { $want = $P.HkPauseMs }
        $P.HkPauseMs = [long]$want
        $ms = [long][Math]::Min([double]$want, $leftMs)
        if ($want -gt 0 -and (($P.SaidState -ne 'pacing' -and $since -ge 60) -or $since -ge 300)) { & $say (Format-SISqlPacingLine -State 'saturated' -Load $load -PauseMs $ms); $P.SaidState = 'pacing' }
        elseif ($want -le 0 -and $P.SaidState -eq 'pacing' -and $since -ge 60) { & $say (Format-SISqlPacingLine -State 'normal' -Load $load); $P.SaidState = 'normal' }
        if ($ms -gt 0) { & $sleep $ms; $P.Pauses++ }
        return (& $result $ms $shrink $(if ($want -gt 0) { 'waited' } else { 'normal' }) $load ($want -gt 0 -and [double]$want -ge $leftMs))
    }
    $shrink = $false
    if ([double]$load.Max -ge $P.High) { $P.HkWaiting = $true; $shrink = $true }
    if (-not $P.HkWaiting) {
        if ($P.SaidState -eq 'pacing' -and $since -ge 60) { & $say (Format-SISqlPacingLine -State 'normal' -Load $load); $P.SaidState = 'normal' }
        return (& $result 0L $false 'normal' $load)
    }
    if (($P.SaidState -ne 'pacing' -and $since -ge 60) -or $since -ge 300) {
        & $say ([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'pacing: the database is at {0:0} % {1} -- the clean-up of older collections waits until it is below {2:0} %', [double]$load.Max, $load.What, $P.Low))
        $P.SaidState = 'pacing'
    }
    $waited = 0L; $P.Pauses++; $hit = $false
    while ($P.HkWaiting) {
        $rest = $leftMs - (([double](& $P.Clock) - $start) * 1000.0)
        if ($rest -le 0) { $hit = $true; break }
        $step = [long][Math]::Max(1.0, [Math]::Min($P.ReadEvery * 1000.0, $rest))
        & $sleep $step; $waited += $step
        $load = & $read
        # the source is lost while waiting: unknown -- today's behaviour
        if ($null -eq $load) { $P.HkWaiting = $false; break }
        if ([double]$load.Max -lt $P.Low) { $P.HkWaiting = $false; break }
        if (([double](& $P.Clock) - $P.SaidAt) -ge 300) {
            & $say ([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'pacing: the database is still at {0:0} % {1} -- the clean-up of older collections waits until it is below {2:0} %', [double]$load.Max, $load.What, $P.Low))
        }
    }
    if (-not $P.HkWaiting -and $null -ne $load -and $P.SaidState -eq 'pacing' -and ([double](& $P.Clock) - $P.SaidAt) -ge 60) {
        & $say ([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'pacing: the database is back at {0:0} % -- the clean-up of older collections goes on', [double]$load.Max)); $P.SaidState = 'normal'
    }
    & $result $waited $shrink 'waited' $load $hit
}

function Invoke-SISqlPacing {
    <#
        BEFORE A BATCH. Reads the load of -Invoke's database (at most every 15 s), applies the rule (Get-SISqlPacingDecision)
        and waits the pause. -LastBatchMs: the measured time of the batch just written. NEVER THROWS: anything that goes wrong
        is "unknown" -- today's behaviour. Returns @{ WaitedMs; Shrink; State; Load }.
        -Housekeeping (the removal of retired collections ONLY): the housekeeping rule (Invoke-SISqlPacingHousekeeping) --
        wait until the database is calm, never past -DeadlineUtc. Every other writer keeps the rule above.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [long]$LastBatchMs = 0, [scriptblock]$Log, [switch]$Housekeeping, [datetime]$DeadlineUtc = [datetime]::MaxValue)
    $none = [pscustomobject]@{ WaitedMs = 0L; Shrink = $false; State = 'off'; Load = $null }
    try {
        $p = Get-SISqlPacer -Invoke $Invoke -Log $Log
        if (-not $p.Enabled -or -not $p.Read) { return $none }
        if ($Housekeeping) { return (Invoke-SISqlPacingHousekeeping -P $p -LastBatchMs $LastBatchMs -DeadlineUtc $DeadlineUtc) }
        $now = [double](& $p.Clock)
        if (($now - $p.ReadAt) -ge $p.ReadEvery) {
            $p.ReadAt = $now
            $l = $null
            try { $l = & $p.Read } catch { $l = $null }
            $p.Load = $l
        }
        $load = $p.Load
        # #881 the database's figures cannot be read (no right, no metrics): the writer's own measured statement time, against
        # the batches before it (the window is a measurement, never a limit on the work)
        if ($null -eq $load) { $load = Get-SISqlPacingMeasuredLoad -Times $p.Times.ToArray() -LastBatchMs $LastBatchMs }
        if ($LastBatchMs -gt 0) { $p.Times.Add($LastBatchMs); while ($p.Times.Count -gt 20) { $p.Times.RemoveAt(0) } }
        $d = Get-SISqlPacingDecision -Load $load -PauseMs $p.PauseMs -LastBatchMs $LastBatchMs -High $p.High -Low $p.Low
        $p.PauseMs = $d.PauseMs
        $p.State = $d.State
        # ONE line per minute at most: when the pace changes (said once the minute since the last line is over, so a change
        # inside it is said then -- unless it went back), and while it stays slower a reminder every 5 minutes
        $since = $now - $p.SaidAt
        $say = $null
        if ($d.State -eq 'unknown') {
            if (-not $p.UnknownSaid -and $since -ge 60) { $p.UnknownSaid = $true; $say = Format-SISqlPacingLine -State 'unknown' }
        } elseif ($d.State -in 'saturated', 'holding') {
            if (($p.SaidState -ne 'pacing' -and $since -ge 60) -or $since -ge 300) { $say = Format-SISqlPacingLine -State $d.State -Load $load -PauseMs $d.PauseMs; $p.SaidState = 'pacing' }
        } elseif ($p.SaidState -eq 'pacing' -and $since -ge 60) {
            $say = Format-SISqlPacingLine -State 'normal' -Load $load; $p.SaidState = 'normal'
        }
        if ($say) {
            $p.SaidAt = $now
            if ($p.Log) { try { & $p.Log 'INFO' $say } catch { } } else { Write-Host ('[INFO] ' + $say) }
        }
        $waited = 0L
        if ($d.PauseMs -gt 0) {
            if ($p.Sleep) { & $p.Sleep $d.PauseMs } else { Start-Sleep -Milliseconds ([int][Math]::Min([long][int]::MaxValue, $d.PauseMs)) }
            $waited = $d.PauseMs
            $p.PausedMs += $waited; $p.Pauses++
        }
        [pscustomobject]@{ WaitedMs = $waited; Shrink = [bool]$d.Shrink; State = $d.State; Load = $load }
    } catch { $none }
}

function Get-SISqlPacingSummary {
    <# What the pacer of -Invoke did in this process: @{ Pauses; PausedSeconds; State }. Nothing paced = zeros. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $o = $null
    if (-not $script:SISqlPacers.TryGetValue($Invoke, [ref]$o)) { return [pscustomobject]@{ Pauses = 0L; PausedSeconds = 0.0; State = 'normal' } }
    [pscustomobject]@{ Pauses = [long]$o.Pauses; PausedSeconds = [Math]::Round($o.PausedMs / 1000.0, 1); State = [string]$o.State }
}
