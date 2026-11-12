#Requires -Version 5.1
<#
    SecurityInsight -- THE PERFORMANCE PAGE'S HOURLY SAMPLES (#757; owner 2026-10-18: "add performance and stats in si gui so
    customer can see it. new page" / "so they can choose to scale up down" / "you have data").

    WHY HERE. The web app holds NO Azure right (CR8: no Monitoring Reader, no VIEW DATABASE STATE). The only facts the
    Performance page needs that SecurityInsight does not keep yet are the LOAD over the last days -- the databases' DTU /
    CPU / data IO / log write and the web app's CPU and memory -- and the sizes the install runs. The heartbeat job already
    reads these kinds of facts with the engine identity every half hour (the Database field: the database GET + its metrics;
    the Jobs field: the job list; the write pacing reads the same database metrics). This file stores what it reads in the
    Pro database (cfg.PerfSample, one row per hour per metric), so the page reads SQL only.

    ONCE AN HOUR (Invoke-SIPerfSample, called by engine\heartbeat\Invoke-SIHeartbeat.ps1 after the status report):
      * ONE read of the table first: nothing more when this hour was read already (the job runs every 15 minutes);
      * per database (the Pro database, the data database when it is another one, the identity database when configured):
        ONE GET (its size: service objective, DTU / vCores, max size) + ONE metrics read of the hours not stored yet
        (interval 1 hour, average and maximum; the first time: the last 7 days, so the page has a week at once);
      * the web app: ONE GET (its CPU / memory) + ONE metrics read (UsageNanoCores, WorkingSetBytes);
      * the jobs: ONE list (each job's CPU / memory);
      * ONE call of cfg.PerfSampleSave (it adds or replaces the hours, and removes rows older than 30 days -- a size after
        2 days). A metric or a resource that cannot be read is left out, said once; the page says "not available".
    Only COMPLETE hours are stored (an hour that is still running is read the next hour).

    NEVER THROWS where the job calls it. PowerShell 5.1 and 7. No PowerShell modules. A test session reads nothing without
    its seams (-Invoke, -Arm).
#>

$script:SIPerfSample = @{
    BackfillDays   = 7
    ArmSqlApi      = '2021-11-01'
    ArmAppApi      = '2025-07-01'
    ArmMetricsApi  = '2023-10-01'
    # the metrics read, as Azure names them -- exactly what is stored
    DtuMetrics     = @('dtu_consumption_percent', 'cpu_percent', 'physical_data_read_percent', 'log_write_percent', 'storage')
    VcoreMetrics   = @('cpu_percent', 'physical_data_read_percent', 'log_write_percent', 'storage')
    WebMetrics     = @('UsageNanoCores', 'WorkingSetBytes')
    Kinds          = @('database', 'webapp', 'job')
}

function Get-SIPerfSampleContract { $script:SIPerfSample }

function ConvertTo-SIPerfHour {
    <# PURE. A time (DateTime, or ISO text as PS 5.1 leaves it) -> that hour's start, UTC; $null when it is not a time. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    $d = $null
    if ($Value -is [datetime]) { $d = $Value.ToUniversalTime() }
    elseif ($Value -is [datetimeoffset]) { $d = $Value.UtcDateTime }
    else {
        $p = [datetimeoffset]::MinValue
        if (-not [datetimeoffset]::TryParse("$Value", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$p)) { return $null }
        $d = $p.UtcDateTime
    }
    [datetime]::new($d.Year, $d.Month, $d.Day, $d.Hour, 0, 0, [DateTimeKind]::Utc)
}

function New-SIPerfRow {
    <# PURE. One row in the shape cfg.PerfSampleSave takes: { t, kind, name, metric, avg, max, text }. #>
    param([Parameter(Mandatory)][datetime]$Hour, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Metric,
          $Avg, $Max, [AllowNull()][AllowEmptyString()][string]$Text)
    $num = { param($v) if ($null -eq $v -or "$v".Trim() -eq '') { return $null }; $x = 0.0; if ([double]::TryParse("$v", [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$x) -and -not [double]::IsNaN($x) -and -not [double]::IsInfinity($x)) { $x } else { $null } }
    [ordered]@{
        t = $Hour.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
        kind = $Kind; name = $(if ($Name.Length -gt 128) { $Name.Substring(0, 128) } else { $Name }); metric = $Metric
        avg = (& $num $Avg); max = (& $num $Max); text = $(if ("$Text".Trim()) { "$Text".Trim().Substring(0, [Math]::Min(64, "$Text".Trim().Length)) } else { $null })
    }
}

function ConvertFrom-SIPerfMetrics {
    <#
        PURE. An Azure Monitor metrics answer (interval one hour, aggregation Average + Maximum) -> rows, one per metric per
        COMPLETE hour (an hour at or after -NowUtc's hour is still running: left out). A data point with neither value is
        left out. -Kind / -Name: what the rows are of.
    #>
    param($Metrics, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][datetime]$NowUtc)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Metrics -or -not $Metrics.PSObject.Properties['value']) { return @() }
    $current = ConvertTo-SIPerfHour $NowUtc
    foreach ($m in @($Metrics.value)) {
        if ($null -eq $m) { continue }
        $metric = ''; try { $metric = [string]$m.name.value } catch { $metric = '' }
        if (-not $metric) { continue }
        foreach ($ts in @($m.timeseries)) {
            foreach ($d in @($ts.data)) {
                if ($null -eq $d) { continue }
                $h = ConvertTo-SIPerfHour $d.timeStamp
                if ($null -eq $h -or $h -ge $current) { continue }
                $avg = if ($d.PSObject.Properties['average']) { $d.average } else { $null }
                $max = if ($d.PSObject.Properties['maximum']) { $d.maximum } else { $null }
                if ($null -eq $avg -and $null -eq $max) { continue }
                $out.Add((New-SIPerfRow -Hour $h -Kind $Kind -Name $Name -Metric $metric -Avg $avg -Max $max))
            }
        }
    }
    # unrolled: callers take @( ... )
    $out.ToArray()
}

function ConvertTo-SIPerfGiB {
    <# PURE. A Container Apps memory value ('2Gi', '0.5Gi', '4096Mi') -> GiB as a number, or $null. #>
    param($Memory)
    $m = [regex]::Match("$Memory", '^\s*([0-9]+(\.[0-9]+)?)\s*(Gi|Mi)?\s*$')
    if (-not $m.Success) { return $null }
    $v = [double]::Parse($m.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture)
    if ($m.Groups[3].Value -eq 'Mi') { $v = $v / 1024.0 }
    $v
}

function ConvertFrom-SIPerfDatabase {
    <#
        PURE. An ARM database (GET) -> its size rows for -Hour: size.sku (Text = the service objective, Avg = its DTU or
        vCores) and size.maxBytes. Returns @{ Rows; Vcore } (Vcore: a vCore database -- it has no DTU metric).
    #>
    param($Resource, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][datetime]$Hour)
    $rows = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Resource) { return [pscustomobject]@{ Rows = @(); Vcore = $false } }
    $so = ''; $tier = ''; $cap = $null; $max = $null
    try { $so = [string]$Resource.properties.currentServiceObjectiveName } catch { }
    try { if (-not $so) { $so = [string]$Resource.sku.name } } catch { }
    try { $tier = [string]$Resource.sku.tier } catch { }
    try { $cap = $Resource.sku.capacity } catch { }
    try { $max = $Resource.properties.maxSizeBytes } catch { }
    $vcore = -not ($tier -in @('Basic', 'Standard', 'Premium'))
    if ($so) { $rows.Add((New-SIPerfRow -Hour $Hour -Kind 'database' -Name $Name -Metric 'size.sku' -Avg $cap -Max $cap -Text $so)) }
    if ($null -ne $max) { $rows.Add((New-SIPerfRow -Hour $Hour -Kind 'database' -Name $Name -Metric 'size.maxBytes' -Avg $max -Max $max)) }
    [pscustomobject]@{ Rows = $rows.ToArray(); Vcore = [bool]($tier -and $vcore) }
}

function ConvertFrom-SIPerfContainer {
    <# PURE. A container app or job (ARM) -> its size rows for -Hour (size.cpu, size.memoryGi of its first container). #>
    param($Resource, [Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][datetime]$Hour)
    if ($null -eq $Resource) { return @() }
    $res = $null
    try { $res = (@($Resource.properties.template.containers) | Where-Object { $_ } | Select-Object -First 1).resources } catch { $res = $null }
    if ($null -eq $res) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    if ($res.PSObject.Properties['cpu'] -and $null -ne $res.cpu) { $out.Add((New-SIPerfRow -Hour $Hour -Kind $Kind -Name $Name -Metric 'size.cpu' -Avg $res.cpu -Max $res.cpu)) }
    if ($res.PSObject.Properties['memory']) { $g = ConvertTo-SIPerfGiB $res.memory; if ($null -ne $g) { $out.Add((New-SIPerfRow -Hour $Hour -Kind $Kind -Name $Name -Metric 'size.memoryGi' -Avg $g -Max $g)) } }
    $out.ToArray()
}

function Get-SIPerfSampleTargets {
    <#
        What this install samples: @{ Sub; Rg; Databases = @(@{ Name = pro | data | identity; Server; Database }); WebApp }.
        From the job's settings (the same the heartbeat reads); -Globals replaces them (tests). '' / empty = not known.
    #>
    param([System.Collections.IDictionary]$Globals)
    $g = {
        param($n)
        if ($Globals) { if ($Globals.Contains($n)) { return "$($Globals[$n])".Trim() } else { return '' } }
        "$(Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue)".Trim()
    }
    $envOr = { param($e, $n) $v = if ($Globals) { '' } else { "$([Environment]::GetEnvironmentVariable($e))".Trim() }; if ($v) { $v } else { & $g $n } }
    $sub = & $envOr 'SI_FLOW_SUBSCRIPTIONID' 'SI_AzSubscriptionId'
    $rg = & $envOr 'SI_FLOW_RESOURCEGROUP' 'SI_Bootstrap_ResourceGroupName'
    $short = { param($s) ("$s".Trim() -split '\.')[0] }
    $dbs = New-Object System.Collections.Generic.List[object]
    $pS = & $short (& $g 'SI_ProSqlServer'); $pD = & $g 'SI_ProSqlDatabase'
    if ($pS -and $pD) { $dbs.Add([pscustomobject]@{ Name = 'pro'; Server = $pS; Database = $pD }) }
    $dS = & $short (& $g 'SI_Pro_DataSqlServer'); $dD = & $g 'SI_Pro_DataSqlDatabase'
    if ($dS -and $dD -and -not ($dS -eq $pS -and $dD -eq $pD)) { $dbs.Add([pscustomobject]@{ Name = 'data'; Server = $dS; Database = $dD }) }
    $lS = & $short (& $g 'SI_LedgerSqlServer'); $lD = & $g 'SI_LedgerDatabase'
    if ($lS -and $lD -and -not ($lS -eq $pS -and $lD -eq $pD)) { $dbs.Add([pscustomobject]@{ Name = 'identity'; Server = $lS; Database = $lD }) }
    $web = ''
    if ($Globals) { $web = & $g 'SI_WebAppName' }
    elseif (Get-Command -Name Get-SIInstallName -ErrorAction SilentlyContinue) { try { $web = Get-SIInstallName -Role web } catch { $web = '' } }
    if (-not $web) { $web = 'ca-si-management' }
    [pscustomobject]@{ Sub = $sub; Rg = $rg; Databases = $dbs.ToArray(); WebApp = $web }
}

function Get-SIPerfSampleStateSql {
    <# The ONE read before anything else: is the table there, the newest hour of any row, the newest hour of a metric row. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'cfg.PerfSample') IS NULL
    SELECT 0 AS HasTable, CAST(NULL AS datetime2(0)) AS LastAny, CAST(NULL AS datetime2(0)) AS LastMetric;
ELSE
    SELECT 1 AS HasTable, (SELECT MAX(TimeUtc) FROM cfg.PerfSample) AS LastAny,
           (SELECT MAX(TimeUtc) FROM cfg.PerfSample WHERE Metric NOT LIKE N'size.%') AS LastMetric;
'@
}

function Get-SIPerfSampleSaveSql { 'EXEC cfg.PerfSampleSave @Rows = @Rows;' }

function Get-SIPerfSampleWindow {
    <#
        PURE. Which hours to read: @{ Due; From; To } -- To = the start of the hour now (only complete hours are read), From =
        the hour after the newest stored metric hour, at most -BackfillDays back. Not due when this hour was read already
        (-LastAny at or after the hour now).
    #>
    param($LastAny, $LastMetric, [Parameter(Mandatory)][datetime]$NowUtc, [int]$BackfillDays = $script:SIPerfSample.BackfillDays)
    $to = ConvertTo-SIPerfHour $NowUtc
    $any = ConvertTo-SIPerfHour $LastAny
    if ($null -ne $any -and $any -ge $to) { return [pscustomobject]@{ Due = $false; From = $null; To = $to } }
    $floor = $to.AddDays(-[Math]::Max(1, $BackfillDays))
    $last = ConvertTo-SIPerfHour $LastMetric
    $from = if ($null -ne $last -and $last.AddHours(1) -gt $floor) { $last.AddHours(1) } else { $floor }
    if ($from -gt $to) { $from = $to }
    [pscustomobject]@{ Due = $true; From = $from; To = $to }
}

function Invoke-SIPerfSample {
    <#
        ONE hourly sample (see the header). NEVER throws; returns @{ Status = no-database | no-table | not-due | saved |
        nothing | error; Rows; Line; Problems }. Seams:
          -Invoke   { param($Sql, $Params, $Mode) } -- the Pro database (the heartbeat's own connection)
          -Arm      { param($Path) } -> an ARM GET answer (default Invoke-SIArm as the job's identity; never in a test session)
          -Targets  Get-SIPerfSampleTargets' answer
    #>
    param([scriptblock]$Invoke, [scriptblock]$Arm, $Targets, $Now)
    $problems = New-Object System.Collections.Generic.List[string]
    $res = { param($s, $line, $n) [pscustomobject]@{ Status = $s; Rows = [int]$n; Line = $line; Problems = $problems.ToArray() } }
    try {
        if (-not $Invoke) { return (& $res 'no-database' 'performance samples: no Pro database -- nothing recorded' 0) }
        $nowUtc = if ($Now) { ([datetime]$Now).ToUniversalTime() } else { [datetime]::UtcNow }
        $c = $script:SIPerfSample
        $st = @(& $Invoke (Get-SIPerfSampleStateSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
        $val = { param($r, $n) if ($null -eq $r) { $null } elseif ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { $v = $r[$n]; if ($v -is [DBNull]) { $null } else { $v } } } elseif ($r.PSObject.Properties[$n]) { $v = $r.$n; if ($v -is [DBNull]) { $null } else { $v } } }
        if ("$(& $val $st 'HasTable')" -ne '1') { return (& $res 'no-table' 'performance samples: the database has no table for them yet -- the next update adds it' 0) }
        $w = Get-SIPerfSampleWindow -LastAny (& $val $st 'LastAny') -LastMetric (& $val $st 'LastMetric') -NowUtc $nowUtc
        if (-not $w.Due) { return (& $res 'not-due' 'performance samples: this hour is recorded already' 0) }

        if (-not $Targets) { $Targets = Get-SIPerfSampleTargets }
        if (-not $Arm -and -not (Get-Module -Name Pester) -and (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { $Arm = { param($Path) Invoke-SIArm -Method GET -Path $Path } }
        if (-not $Arm -or -not $Targets.Sub -or -not $Targets.Rg) { return (& $res 'nothing' 'performance samples: Azure cannot be read from here (no subscription / resource group known) -- the page says not available' 0) }

        $rows = New-Object System.Collections.Generic.List[object]
        $hourNow = $w.To
        $span = '{0}/{1}' -f $w.From.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture), $w.To.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
        $readMetrics = $w.From -lt $w.To
        $rgBase = '/subscriptions/{0}/resourceGroups/{1}/providers' -f $Targets.Sub, $Targets.Rg
        $metricsOf = { param($id, [string[]]$names) & $Arm ('{0}/providers/Microsoft.Insights/metrics?api-version={1}&metricnames={2}&timespan={3}&interval=PT1H&aggregation=Average,Maximum' -f $id, $c.ArmMetricsApi, ($names -join ','), $span) }

        foreach ($db in @($Targets.Databases)) {
            if (-not $db) { continue }
            $id = '{0}/Microsoft.Sql/servers/{1}/databases/{2}' -f $rgBase, $db.Server, $db.Database
            $vcore = $false
            try {
                $s = ConvertFrom-SIPerfDatabase -Resource (& $Arm ('{0}?api-version={1}' -f $id, $c.ArmSqlApi)) -Name $db.Name -Hour $hourNow
                foreach ($r in @($s.Rows)) { $rows.Add($r) }
                $vcore = $s.Vcore
            } catch { $problems.Add(('the {0} database''s size ({1})' -f $db.Name, $_.Exception.Message)) }
            if ($readMetrics) {
                try { foreach ($r in @(ConvertFrom-SIPerfMetrics -Metrics (& $metricsOf $id $(if ($vcore) { $c.VcoreMetrics } else { $c.DtuMetrics })) -Kind 'database' -Name $db.Name -NowUtc $nowUtc)) { $rows.Add($r) } }
                catch { $problems.Add(('the {0} database''s load ({1})' -f $db.Name, $_.Exception.Message)) }
            }
        }
        if ($Targets.WebApp) {
            $id = '{0}/Microsoft.App/containerApps/{1}' -f $rgBase, $Targets.WebApp
            try { foreach ($r in @(ConvertFrom-SIPerfContainer -Resource (& $Arm ('{0}?api-version={1}' -f $id, $c.ArmAppApi)) -Kind 'webapp' -Name $Targets.WebApp -Hour $hourNow)) { $rows.Add($r) } }
            catch { $problems.Add(('the web app''s size ({0})' -f $_.Exception.Message)) }
            if ($readMetrics) {
                try { foreach ($r in @(ConvertFrom-SIPerfMetrics -Metrics (& $metricsOf $id $c.WebMetrics) -Kind 'webapp' -Name $Targets.WebApp -NowUtc $nowUtc)) { $rows.Add($r) } }
                catch { $problems.Add(('the web app''s load ({0})' -f $_.Exception.Message)) }
            }
        }
        try {
            $next = '{0}/Microsoft.App/jobs?api-version={1}' -f $rgBase, $c.ArmAppApi; $pages = 0
            while ($next -and $pages -lt 5) {
                $pages++
                $page = & $Arm $next
                if ($null -eq $page) { break }
                foreach ($j in @($page.value)) { if ($j -and [string]$j.name) { foreach ($r in @(ConvertFrom-SIPerfContainer -Resource $j -Kind 'job' -Name ([string]$j.name) -Hour $hourNow)) { $rows.Add($r) } } }
                $next = if ($page.PSObject.Properties['nextLink']) { [string]$page.nextLink } else { '' }
            }
        } catch { $problems.Add(('the jobs'' sizes ({0})' -f $_.Exception.Message)) }

        if (-not $rows.Count) {
            return (& $res 'nothing' ('performance samples: nothing could be read this hour{0} -- the page says not available' -f $(if ($problems.Count) { ' (' + ($problems -join '; ') + ')' } else { '' })) 0)
        }
        $json = ConvertTo-Json -InputObject @($rows.ToArray()) -Compress -Depth 4
        $saved = @(& $Invoke (Get-SIPerfSampleSaveSql) ([ordered]@{ Rows = $json }) 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })[0]
        $added = & $val $saved 'Added'; $pruned = & $val $saved 'Pruned'
        $line = 'performance samples: {0} recorded ({1} new{2}){3}' -f $rows.Count, $(if ($null -ne $added) { $added } else { '?' }), $(if ($pruned) { ", $pruned older than 30 days removed" } else { '' }),
            $(if ($problems.Count) { ' -- not read: ' + ($problems -join '; ') } else { '' })
        if ($line.Length -gt 600) { $line = $line.Substring(0, 597) + '...' }
        & $res 'saved' $line $rows.Count
    } catch {
        & $res 'error' ('performance samples: not recorded this hour ({0}) -- the next tick tries again' -f $_.Exception.Message) 0
    }
}
