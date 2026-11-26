#Requires -Version 5.1
<#
    SecurityInsight -- THE DATABASE TIER SIZED PER INSTALL FROM ITS OWN LOAD (#1335, SCALE-3 #1330 track D).

    A MEASURED RECOMMENDATION, NEVER A CHANGE. From the database's own load of the last 24 hours (Azure Monitor, one value per
    minute, Maximum: the data IO, log write, CPU and -- on a DTU tier -- DTU percent) and the heartbeat's load telemetry (#1306:
    the largest tables), the tier that keeps the run's read-bound phases below the limit. SecurityInsight never changes a
    database's tier itself: the recommendation goes to Invardia in the heartbeat (numbers only), and a change is the owner's
    cost decision, made through Invardia (rights and cost).

    THE RULE (Get-SIDatabaseTierAdvice, pure):
      * busy minutes = the minutes whose load (the highest of data IO, log write, CPU, DTU) is at or above BusyPct -- the run's
        phases, not the idle hours;
      * at the limit = a busy minute at or above LimitPct (the heartbeat's own "at the limit", 99 %);
      * the load of the busy time = its 95th percentile; bound by = the dimension (data IO / log / CPU) with the highest 95th
        percentile;
      * a minute at the limit hides how much more the run asked for, so the demand is the 95th percentile grown by the share of
        busy minutes at the limit: demand = p95 x (1 + atLimit / busy);
      * the capacity needed = the capacity now x demand / TargetPct (the busy phases at TargetPct, 80 %, of the new tier);
      * the tier = the smallest step of the ladder (Azure's own steps, Standard -> vCore General Purpose -> Hyperscale for the
        largest; 100 DTU = 1 vCore, Microsoft's guidance) whose capacity covers it -- never below the floor (#1133's approved
        S4 at a large install: one whose largest table holds LargeRows rows or more), never a step down while any minute was
        at the limit;
      * no busy minute = keep the tier (nothing to measure).
    Nothing here is a cap: the ladder is Azure's, the result grows with the measured load.

    THE WIRE: Database.tierAdvice { recommended, capacityNow, capacityNeeded, p95LoadPct, minutesAtLimit24h, busyMinutes24h,
    boundBy, change } -- recommended a tier name, the counts whole numbers (p95LoadPct 0-100, the minutes 0-1440), boundBy
    data-io | log | cpu, change up | down | keep; every key always set. ACCEPTED by Invardia (ee2e9fab, 2026-11-23): behind
    DatabaseSendTierAdvice, ON (SI-HeartbeatFields.ps1), computed every TierAdviceEveryHours hours with ONE metrics read;
    nothing measured (no minute, or only DTU percent) = the key is left out.

    PS 5.1 and 7. No module; a test never reads ARM (every reader is a seam).
#>

$script:SIDbTierAdvice = @{
    BusyPct = 20; LimitPct = 99; TargetPct = 80
    # a large install (the floor): its largest table holds this many rows or more (#1133: the approved S4 step-up)
    LargeRows = 1000000; LargeFloor = 'S4'
    # Azure's steps, smallest first: name, edition, capacity in DTU (a vCore = 100 DTU, Microsoft's guidance)
    Ladder = @(
        @{ Name = 'S0'; Edition = 'Standard'; Capacity = 10 }, @{ Name = 'S1'; Edition = 'Standard'; Capacity = 20 }, @{ Name = 'S2'; Edition = 'Standard'; Capacity = 50 },
        @{ Name = 'S3'; Edition = 'Standard'; Capacity = 100 }, @{ Name = 'S4'; Edition = 'Standard'; Capacity = 200 }, @{ Name = 'S6'; Edition = 'Standard'; Capacity = 400 },
        @{ Name = 'S7'; Edition = 'Standard'; Capacity = 800 }, @{ Name = 'S9'; Edition = 'Standard'; Capacity = 1600 }, @{ Name = 'S12'; Edition = 'Standard'; Capacity = 3000 },
        @{ Name = 'GP_Gen5_32'; Edition = 'GeneralPurpose'; Capacity = 3200 }, @{ Name = 'GP_Gen5_40'; Edition = 'GeneralPurpose'; Capacity = 4000 },
        @{ Name = 'GP_Gen5_80'; Edition = 'GeneralPurpose'; Capacity = 8000 }, @{ Name = 'HS_Gen5_128'; Edition = 'Hyperscale'; Capacity = 12800 })
    Metrics = 'physical_data_read_percent,log_write_percent,cpu_percent,dtu_consumption_percent'
    Fields = @('recommended', 'capacityNow', 'capacityNeeded', 'p95LoadPct', 'minutesAtLimit24h', 'busyMinutes24h', 'boundBy', 'change')
    BoundBy = @('data-io', 'log', 'cpu'); Changes = @('up', 'down', 'keep')
}

function Get-SIDbTierAdviceContract { $script:SIDbTierAdvice }

function Get-SIDbTierCapacity {
    <# PURE. A database's capacity in DTU: a DTU tier's capacity as it is; a vCore one (GP_ / BC_ / HS_<gen>_<n>, or -VCores)
       its vCores x 100 (Premium / Business Critical: x 125). $null when it cannot be told. #>
    param([string]$ServiceObjective = '', [string]$Edition = '', $Capacity = $null)
    $so = "$ServiceObjective".Trim(); $ed = "$Edition".Trim()
    $cap = $null; if ($null -ne $Capacity -and "$Capacity" -match '^\d+$') { $cap = [long]$Capacity }
    if ($ed -in 'Basic', 'Standard', 'Premium' -or $so -match '^(?i)(Basic|S\d+|P\d+)$') {
        if ($null -ne $cap -and $cap -gt 0) { return $cap }
        $l = @($script:SIDbTierAdvice.Ladder | Where-Object { $_.Name -eq $so })[0]; if ($l) { return [long]$l.Capacity }
        return $null
    }
    $m = [regex]::Match($so, '^(?i)(GP|BC|HS)_[A-Za-z0-9]+_(\d+)$')
    $v = if ($m.Success) { [long]$m.Groups[2].Value } elseif ($null -ne $cap -and $cap -gt 0) { $cap } else { $null }
    if ($null -eq $v) { return $null }
    $per = if ($ed -eq 'BusinessCritical' -or ($m.Success -and $m.Groups[1].Value -ieq 'BC')) { 125 } else { 100 }
    [long]($v * $per)
}

function ConvertFrom-SIDbTierMetrics {
    <# PURE. An Azure Monitor answer (one value per minute, Maximum) -> one entry per minute @{ DataIo; Log; Cpu; Dtu } (a
       metric not answered = $null). Minutes without any value are left out. #>
    param($Metrics)
    $by = @{}
    if ($null -eq $Metrics -or -not $Metrics.PSObject.Properties['value']) { return , @() }
    $map = @{ physical_data_read_percent = 'DataIo'; log_write_percent = 'Log'; cpu_percent = 'Cpu'; dtu_consumption_percent = 'Dtu' }
    foreach ($m in @($Metrics.value)) {
        $name = ''; try { $name = [string]$m.name.value } catch { }
        if (-not $map.ContainsKey($name)) { continue }
        foreach ($ts in @($m.timeseries)) { foreach ($d in @($ts.data)) {
            $v = $null; try { if ($null -ne $d.maximum) { $v = [double]$d.maximum } } catch { $v = $null }
            if ($null -eq $v) { continue }
            $k = [string]$d.timeStamp
            if (-not $by.ContainsKey($k)) { $by[$k] = @{ DataIo = $null; Log = $null; Cpu = $null; Dtu = $null } }
            $by[$k][$map[$name]] = $v
        } }
    }
    , @($by.Keys | Sort-Object | ForEach-Object { [pscustomobject]$by[$_] })
}

function Get-SIDbTierPercentile {
    <# PURE. The -P percentile (nearest rank) of -Values; $null when none. #>
    param([double[]]$Values, [double]$P = 95)
    $v = @($Values | Where-Object { $null -ne $_ } | Sort-Object)
    if ($v.Count -eq 0) { return $null }
    $rank = [int][Math]::Ceiling(($P / 100.0) * $v.Count); if ($rank -lt 1) { $rank = 1 }
    [double]$v[$rank - 1]
}

function Get-SIDatabaseTierAdvice {
    <#
        PURE. THE RULE (see the header). -Minutes: ConvertFrom-SIDbTierMetrics' entries; -ServiceObjective / -Edition /
        -Capacity: the database now (ARM sku.name / sku.tier / sku.capacity); -LargestTableRows: the heartbeat's largest table
        (#1306), for the floor; -Floor: a floor given by name (else the large-install floor when it applies). Returns the
        wire object (the fields of the contract, in order), or $null when the capacity now cannot be told.
    #>
    param([AllowEmptyCollection()][object[]]$Minutes = @(), [string]$ServiceObjective = '', [string]$Edition = '', $Capacity = $null,
          $LargestTableRows = $null, [string]$Floor = '')
    $c = $script:SIDbTierAdvice
    $now = Get-SIDbTierCapacity -ServiceObjective $ServiceObjective -Edition $Edition -Capacity $Capacity
    if ($null -eq $now -or $now -le 0) { return $null }
    $load = New-Object System.Collections.Generic.List[double]
    $dims = @{ 'data-io' = (New-Object System.Collections.Generic.List[double]); 'log' = (New-Object System.Collections.Generic.List[double]); 'cpu' = (New-Object System.Collections.Generic.List[double]) }
    $atLimit = 0
    # a day is 1,440 minutes: a 24-hour read can answer one more (both ends) -- the newest 1,440 are taken (Invardia's range 0-1440)
    $mins = @(@($Minutes) | Where-Object { $null -ne $_ -and $null -ne (@($_.DataIo, $_.Log, $_.Cpu, $_.Dtu) | Where-Object { $null -ne $_ } | Select-Object -First 1) })
    if ($mins.Count -gt 1440) { $mins = @($mins | Select-Object -Last 1440) }
    # nothing measured: no recommendation is sent (never a made-up one)
    if ($mins.Count -eq 0) { return $null }
    $allLoad = New-Object System.Collections.Generic.List[double]
    $allDims = @{ 'data-io' = (New-Object System.Collections.Generic.List[double]); 'log' = (New-Object System.Collections.Generic.List[double]); 'cpu' = (New-Object System.Collections.Generic.List[double]) }
    foreach ($m in $mins) {
        $vals = @($m.DataIo, $m.Log, $m.Cpu, $m.Dtu) | Where-Object { $null -ne $_ }
        $mx = [double](@($vals) | Measure-Object -Maximum).Maximum
        $allLoad.Add($mx)
        if ($null -ne $m.DataIo) { $allDims['data-io'].Add([double]$m.DataIo) }
        if ($null -ne $m.Log) { $allDims['log'].Add([double]$m.Log) }
        if ($null -ne $m.Cpu) { $allDims['cpu'].Add([double]$m.Cpu) }
        if ($mx -lt $c.BusyPct) { continue }
        $load.Add($mx)
        if ($mx -ge $c.LimitPct) { $atLimit++ }
        if ($null -ne $m.DataIo) { $dims['data-io'].Add([double]$m.DataIo) }
        if ($null -ne $m.Log) { $dims['log'].Add([double]$m.Log) }
        if ($null -ne $m.Cpu) { $dims['cpu'].Add([double]$m.Cpu) }
    }
    $busy = $load.Count
    # the floor: by name, else a large install's (its largest table)
    $floorName = "$Floor".Trim()
    if (-not $floorName -and $null -ne $LargestTableRows -and "$LargestTableRows" -match '^\d+$' -and [long]$LargestTableRows -ge [long]$c.LargeRows) { $floorName = [string]$c.LargeFloor }
    $floorCap = 0L; if ($floorName) { $fc = Get-SIDbTierCapacity -ServiceObjective $floorName; if ($null -ne $fc) { $floorCap = [long]$fc } }
    $p95 = $null; $bound = $null; $needed = $now
    # the load and the dimension it is bound by: of the busy time; with no busy minute, of the whole day (both always sent)
    # (plain statements: a $( ) would unroll the lists)
    $useLoad = $allLoad; $useDims = $allDims
    if ($busy -gt 0) { $useLoad = $load; $useDims = $dims }
    $p95 = Get-SIDbTierPercentile -Values $useLoad.ToArray()
    $best = -1.0
    foreach ($d in $c.BoundBy) { if ($useDims[$d].Count) { $q = Get-SIDbTierPercentile -Values $useDims[$d].ToArray(); if ($q -gt $best) { $best = $q; $bound = $d } } }
    # a database that answered only its DTU percent: what it is bound by is not known -- no recommendation is sent
    if ($null -eq $bound) { return $null }
    if ($busy -gt 0) {
        $demand = ($p95 / 100.0) * (1.0 + ([double]$atLimit / [double]$busy))
        $needed = [long][Math]::Ceiling([double]$now * $demand / ([double]$c.TargetPct / 100.0))
    }
    if ($needed -lt $floorCap) { $needed = $floorCap }
    # no step down while the database touched its limit; no busy minute = keep
    if ($busy -eq 0 -or ($atLimit -gt 0 -and $needed -lt $now)) { $needed = [Math]::Max($now, $floorCap) }
    $rec = $null
    foreach ($l in $c.Ladder) { if ([long]$l.Capacity -ge $needed) { $rec = $l; break } }
    if ($null -eq $rec) { $rec = $c.Ladder[-1] }
    $cur = "$ServiceObjective".Trim()
    # up only when the measured need is above today's capacity; down only to a step below it; otherwise keep the tier as it
    # is (a tier off the ladder -- a P1 -- is never 'moved' to the next ladder step for the rounding alone)
    $change = if ($needed -gt $now) { 'up' } elseif ([long]$rec.Capacity -lt $now) { 'down' } else { 'keep' }
    $recName = if ($change -eq 'keep' -and $cur) { $cur } else { [string]$rec.Name }
    $o = [ordered]@{}
    $o['recommended'] = $recName
    $o['capacityNow'] = [long]$now
    $o['capacityNeeded'] = [long]$needed
    $o['p95LoadPct'] = [long][Math]::Max(0, [Math]::Min(100, [Math]::Round([double]$p95, [MidpointRounding]::AwayFromZero)))
    $o['minutesAtLimit24h'] = [long]$atLimit
    $o['busyMinutes24h'] = [long]$busy
    $o['boundBy'] = $bound
    $o['change'] = $change
    [pscustomobject]$o
}

function Test-SIDbTierAdvice {
    <# PURE. '' when -Value is exactly the wire object (the fields in order, tier names, whole numbers, the closed lists), else why. #>
    param($Value)
    $c = $script:SIDbTierAdvice
    if ($null -eq $Value -or $Value -is [string]) { return 'tierAdvice is not an object' }
    $names = @($Value.PSObject.Properties | ForEach-Object { $_.Name })
    if (($names -join ',') -cne (@($c.Fields) -join ',')) { return ('tierAdvice has the keys {0}' -f ($names -join ', ')) }
    if (-not ($Value.recommended -is [string] -and $Value.recommended -cmatch '^[A-Za-z][A-Za-z0-9_]{0,31}$')) { return 'tierAdvice.recommended is not a tier name' }
    foreach ($n in 'capacityNow', 'capacityNeeded', 'minutesAtLimit24h', 'busyMinutes24h') { $v = $Value.$n; if (-not ($v -is [long] -or $v -is [int]) -or $v -lt 0) { return "tierAdvice.$n is not a whole number >= 0" } }
    if ($null -eq $Value.p95LoadPct -or (-not ($Value.p95LoadPct -is [long] -or $Value.p95LoadPct -is [int]) -or $Value.p95LoadPct -lt 0 -or $Value.p95LoadPct -gt 100)) { return 'tierAdvice.p95LoadPct is not 0-100' }
    if ($Value.minutesAtLimit24h -gt 1440 -or $Value.busyMinutes24h -gt 1440 -or $Value.minutesAtLimit24h -gt $Value.busyMinutes24h) { return 'tierAdvice minutes are not minutes of a day' }
    if ($null -eq $Value.boundBy -or $c.BoundBy -cnotcontains [string]$Value.boundBy) { return 'tierAdvice.boundBy is not in the list' }
    if ($c.Changes -cnotcontains [string]$Value.change) { return 'tierAdvice.change is not in the list' }
    ''
}

function Get-SIDbTierAdviceMetricsPath {
    <# PURE. The ONE metrics read of the last 24 hours, a value per minute (Maximum), for database -Id (its ARM id). #>
    param([Parameter(Mandatory)][string]$Id, [string]$Api = '2023-10-01')
    '{0}/providers/Microsoft.Insights/metrics?api-version={1}&metricnames={2}&timespan=P1D&interval=PT1M&aggregation=Maximum' -f $Id, $Api, $script:SIDbTierAdvice.Metrics
}
