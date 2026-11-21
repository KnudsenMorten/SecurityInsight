#Requires -Version 5.1
<#
    caj-si-updater -- ROLL-HUNG-1 (framework, Invardia 2026-11-20, all products): A HUNG STEP NO LONGER HOLDS THE ROLL.
    Found by PIM at an install: an execution sat "Running" 333 min with ZERO log lines, the wait for the run held the roll
    twice and the ring missed its window. SecurityInsight's roll waits for the pipeline run (SI-UpdaterRunGate.ps1), so a
    step of that run that hangs held the roll the same way.

    THE RULE. A running step of the run the update waits for is HUNG only when ALL hold:
      * it is Running longer than Factor (10) x its usual length -- the median of its job's last (at most 10) SUCCESSFUL
        steps in other runs -- AND at least FloorMinutes (120). A job with no measured success here is never called hung;
      * it has written NO log line since it started: its execution has no console log line and no run-health record in the
        install's Log Analytics workspace, while OTHER executions' console lines DO reach the workspace in the same window
        (so the silence is proven, not a workspace that receives nothing), AND no sign of progress (cfg.StepProgress /
        cfg.StepPhaseTime) since it started.
    Anything that cannot be read (the workspace, the progress record, the run's steps, the history) = NOT hung: the update
    waits, as before. A run that writes log lines is NEVER stopped, however long it takes (the owner's long-run rule for the
    large installs stands: a run is stopped only when it DIED, and no log line since its start is the definition of died).

    THEN the updater stops THAT ONE execution (ARM executions/<name>/stop), reads back that it ended (Stopped), says it in
    one WARNING line, raises the alert si.pipeline.step-hung to Invardia (the pipeline is stuck: one fix request, never a
    mail to the owner), and asks the run gate again. The roll goes on the way it always does: the pipeline runner closes the
    stopped step at its next poll and the run goes on to its end; the wait mark then starts this updater between two runs --
    never one run on two builds. PURE functions + small seams; PS 5.1 and 7; no PowerShell module.
#>

function Get-SIUpdaterHungRule {
    <# PURE. The numbers of ROLL-HUNG-1. #>
    @{ Factor = 10.0; FloorMinutes = 120; History = 10; StopReadSeconds = 120; StopPollSeconds = 10; AlertId = 'si.pipeline.step-hung' }
}

function ConvertTo-SIUpdaterHungUtc {
    <# PURE. A time ([datetime]: Unspecified = UTC, as SQL and ARM give it; or ISO text) -> UTC [datetime], or $null. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [DBNull]) { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }; return $Value.ToUniversalTime() }
    $d = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { return $d }
    $null
}

function Get-SIUpdaterHungKey {
    <# PURE. A step's job key: 'caj-si-asset-datasync' / 'asset-datasync' -> 'asset-datasync'. #>
    param([string]$Job)
    $k = ([string]$Job).Trim().ToLowerInvariant()
    if ($k.StartsWith('caj-si-')) { $k = $k.Substring(7) }
    $k
}

function Get-SIUpdaterUsualStepMinutes {
    <# PURE. Job key -> the MEDIAN minutes of its newest (at most -History) SUCCESSFUL steps among -Steps { FlowRunId, Job,
       State, StartedUtc, EndedUtc } of the runs other than -ExcludeRunId. A job with none has no entry. #>
    param([object[]]$Steps = @(), [AllowEmptyString()][string]$ExcludeRunId = '', [int]$History = (Get-SIUpdaterHungRule).History)
    $by = @{}
    foreach ($s in @(@($Steps) | Where-Object { $_ -and [string]$_.State -eq 'Success' -and [string]$_.FlowRunId -ne $ExcludeRunId })) {
        $k = Get-SIUpdaterHungKey ([string]$s.Job); if (-not $k) { continue }
        $a = ConvertTo-SIUpdaterHungUtc $s.StartedUtc; $b = ConvertTo-SIUpdaterHungUtc $s.EndedUtc
        if ($null -eq $a -or $null -eq $b -or $b -lt $a) { continue }
        if (-not $by.ContainsKey($k)) { $by[$k] = New-Object System.Collections.Generic.List[object] }
        $by[$k].Add([pscustomobject]@{ At = $a; Minutes = ($b - $a).TotalMinutes })
    }
    $out = @{}
    foreach ($k in @($by.Keys)) {
        $m = @($by[$k] | Sort-Object At -Descending | Select-Object -First $History | ForEach-Object { [double]$_.Minutes } | Sort-Object)
        if (-not $m.Count) { continue }
        $out[$k] = if ($m.Count % 2) { $m[[int][Math]::Floor($m.Count / 2)] } else { ($m[$m.Count / 2 - 1] + $m[$m.Count / 2]) / 2 }
    }
    $out
}

function Get-SIUpdaterHungLogQuery {
    <#
        PURE. The KQL: since -StartedUtc, how many log lines THIS execution wrote (Mine: its console lines -- the replica's
        name starts with the execution, or with -WorkerJob for a collection in parts -- and its run-health records) and how many
        console lines OTHER SecurityInsight executions wrote (Others: proof that console logs reach the workspace). One row.
        $null for a name that is not an execution / job name (never put into a query).
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Execution, [Parameter(Mandatory)][datetime]$StartedUtc, [AllowEmptyString()][string]$WorkerJob = '')
    if ($Execution -notmatch '^[a-z0-9][a-z0-9\-]{0,126}$') { return $null }
    if ($WorkerJob -and $WorkerJob -notmatch '^[a-z0-9][a-z0-9\-]{0,63}$') { return $null }
    $from = $StartedUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    $mine = if ($WorkerJob) { "(N startswith '{0}' or N startswith '{1}')" -f $Execution, $WorkerJob } else { "N startswith '{0}'" -f $Execution }
    ("union isfuzzy=true " +
     "(ContainerAppConsoleLogs | where TimeGenerated >= datetime({0}) | extend N = tostring(column_ifexists('ContainerGroupName', '')) | project N, K = 'log'), " +
     "(ContainerAppConsoleLogs_CL | where TimeGenerated >= datetime({0}) | extend N = tostring(column_ifexists('ContainerGroupName_s', '')) | project N, K = 'log'), " +
     "(SI_RunHealth_CL | where TimeGenerated >= datetime({0}) | extend N = tostring(column_ifexists('Execution', '')) | project N, K = 'health') " +
     "| extend M = {1} | summarize Mine = countif(M), Others = countif(not(M) and K == 'log' and N startswith 'caj-si-')") -f $from, $mine
}

function Select-SIUpdaterHungSteps {
    <#
        PURE. Of -Steps (the running steps of the run the update waits for: { Job, Execution, State, StartedUtc }), the HUNG
        ones and why each other one is not. -Usual: Get-SIUpdaterUsualStepMinutes. -Probe: execution -> @{ Known (the
        workspace was read); Mine; Others; ProgressKnown (the progress record was read); LastProgressUtc }. Returns
        @{ Hung = @({ Job; Key; Execution; StartedUtc; AgeMin; UsualMin; BoundMin }); Kept = @({ Key; Execution; Why }) }.
    #>
    param([object[]]$Steps = @(), [hashtable]$Usual = @{}, [hashtable]$Probe = @{}, [Parameter(Mandatory)][datetime]$NowUtc)
    $r = Get-SIUpdaterHungRule
    $now = $NowUtc.ToUniversalTime()
    $hung = New-Object System.Collections.Generic.List[object]; $kept = New-Object System.Collections.Generic.List[object]
    foreach ($s in @(@($Steps) | Where-Object { $_ -and [string]$_.State -in @('Running', 'Starting') })) {
        $k = Get-SIUpdaterHungKey ([string]$s.Job); $x = [string]$s.Execution
        $keep = { param($why) $kept.Add([pscustomobject]@{ Key = $k; Execution = $x; Why = $why }) }
        $start = ConvertTo-SIUpdaterHungUtc $s.StartedUtc
        if (-not $k -or -not $x.Trim() -or $null -eq $start) { & $keep 'its execution or start time is not recorded'; continue }
        $age = ($now - $start).TotalMinutes
        if (-not $Usual.ContainsKey($k)) { & $keep 'its usual length is not known here (no measured success)'; continue }
        $bound = [Math]::Max([double]$Usual[$k] * [double]$r.Factor, [double]$r.FloorMinutes)
        if ($age -le $bound) { & $keep ('inside its bound ({0:0} of {1:0} min)' -f $age, $bound); continue }
        $p = if ($Probe.ContainsKey($x)) { $Probe[$x] } else { $null }
        if (-not $p -or -not $p.Known) { & $keep 'its log lines could not be read'; continue }
        if ([long]$p.Mine -gt 0) { & $keep ('it writes log lines ({0} since its start) -- a run that logs is never stopped' -f [long]$p.Mine); continue }
        if ([long]$p.Others -le 0) { & $keep 'no console line of any execution reaches the workspace in that time, so its silence proves nothing'; continue }
        if (-not $p.ProgressKnown) { & $keep 'its progress record could not be read'; continue }
        $lp = ConvertTo-SIUpdaterHungUtc $p.LastProgressUtc
        if ($null -ne $lp -and $lp -ge $start) { & $keep ('it recorded progress at {0:yyyy-MM-dd HH:mm}Z' -f $lp); continue }
        $hung.Add([pscustomobject]@{ Job = [string]$s.Job; Key = $k; Execution = $x; StartedUtc = $start; AgeMin = [long][Math]::Floor($age)
                                     UsualMin = [long][Math]::Round([double]$Usual[$k]); BoundMin = [long][Math]::Ceiling($bound) })
    }
    [pscustomobject]@{ Hung = $hung.ToArray(); Kept = $kept.ToArray() }
}

function Get-SIUpdaterHungStepText {
    <# PURE. The one WARNING line of a stop. #>
    param([Parameter(Mandatory)]$Hung, [string]$RunId = '', [bool]$Ended = $true)
    ('the update stopped step {0} (execution {1}) of run {2}: it ran {3} min -- more than 10 times its usual {4} min and at least 120 min -- and wrote no log line since it started{5}. The pipeline is reported as stuck to Invardia; the run goes on to its end and the update is installed between two runs.' -f
        $Hung.Key, $Hung.Execution, $(if ($RunId) { $RunId } else { '(unknown)' }), $Hung.AgeMin, $Hung.UsualMin, $(if ($Ended) { '' } else { ' (Azure did not read back Stopped yet)' }))
}

function Get-SIUpdaterHungStepSql {
    <# PURE. The running steps of run @RunId, and the newest successful steps of the other runs (for the usual lengths). #>
    @'
SET NOCOUNT ON;
SELECT N'run' AS K, FlowRunId, Job, State, Execution, StartedUtc, EndedUtc FROM cfg.FlowStepRun WITH (NOLOCK)
 WHERE FlowRunId = @RunId AND State IN (N'Starting', N'Running')
UNION ALL
SELECT N'hist', FlowRunId, Job, State, Execution, StartedUtc, EndedUtc FROM (
  SELECT s.FlowRunId, s.Job, s.State, s.Execution, s.StartedUtc, s.EndedUtc, ROW_NUMBER() OVER (PARTITION BY s.Job ORDER BY s.StartedUtc DESC) AS rn
    FROM cfg.FlowStepRun s WITH (NOLOCK)
   WHERE s.State = N'Success' AND s.FlowRunId <> @RunId AND s.StartedUtc IS NOT NULL AND s.EndedUtc IS NOT NULL
     AND s.Job IN (SELECT Job FROM cfg.FlowStepRun WITH (NOLOCK) WHERE FlowRunId = @RunId AND State IN (N'Starting', N'Running'))) h
 WHERE rn <= @History;
'@
}

function Invoke-SIUpdaterHungStepCheck {
    <#
        ROLL-HUNG-1 for one WAIT of the run gate (-RunId: the run it waits for). Reads the run's running steps and their usual
        lengths (-Sql { param($Query, $Params, $Mode) } -- the Pro database), each candidate's log lines (-LogQuery
        { param($Kql) } -> rows Mine / Others) and progress (-Progress { param($Key, $Execution, $SinceUtc) } -> UTC or $null;
        throws = not readable), stops each HUNG execution (-Stop { param($Key, $Execution) }), reads back that it ended
        (-ReadStatus { param($Key, $Execution) } -> ARM status), says it (-Log { param($Level, $Message) }) and raises it
        (-Alert { param($Event) }). Returns @{ Stopped = @(); Kept = @(); Why }. Never throws.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RunId, [Parameter(Mandatory)][scriptblock]$Sql, [scriptblock]$LogQuery, [scriptblock]$Progress,
          [Parameter(Mandatory)][scriptblock]$Stop, [scriptblock]$ReadStatus, [scriptblock]$Log, [scriptblock]$Alert,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [scriptblock]$Now = { [datetime]::UtcNow }, [string[]]$PartsJobs = @())
    $r = Get-SIUpdaterHungRule
    $res = [ordered]@{ Stopped = @(); Kept = @(); Why = '' }
    if (-not $Log) { $Log = { param($l, $m) } }
    try {
        if (-not "$RunId".Trim()) { $res.Why = 'no run id'; return [pscustomobject]$res }
        $rows = @(& $Sql (Get-SIUpdaterHungStepSql) ([ordered]@{ RunId = $RunId; History = [int]$r.History }) 'reader' | ForEach-Object { $_ } | Where-Object { $_ })
        $field = { param($row, $n) if ($row -is [System.Collections.IDictionary]) { $v = $row[$n] } else { $v = $row.$n }; if ($v -is [DBNull]) { $null } else { $v } }
        $obj = { param($row) [pscustomobject]@{ K = [string](& $field $row 'K'); FlowRunId = [string](& $field $row 'FlowRunId'); Job = [string](& $field $row 'Job'); State = [string](& $field $row 'State')
                                                Execution = [string](& $field $row 'Execution'); StartedUtc = (& $field $row 'StartedUtc'); EndedUtc = (& $field $row 'EndedUtc') } }
        $all = @($rows | ForEach-Object { & $obj $_ })
        $running = @($all | Where-Object { $_.K -eq 'run' }); $hist = @($all | Where-Object { $_.K -eq 'hist' })
        if (-not $running.Count) { $res.Why = 'no step of the run is running'; return [pscustomobject]$res }
        $usual = Get-SIUpdaterUsualStepMinutes -Steps $hist -ExcludeRunId $RunId
        $nowUtc = ([datetime](& $Now)).ToUniversalTime()   # (never $now: names ignore case, and -Now is the clock seam)
        $parts = @{}; foreach ($p in @($PartsJobs)) { if ($p) { $parts[(Get-SIUpdaterHungKey (([string]$p) -replace '-(producer|worker)$', ''))] = $true } }
        # read the log lines and the progress ONLY of a step past its bound (a step inside it is never asked about)
        $probe = @{}
        foreach ($s in $running) {
            $k = Get-SIUpdaterHungKey $s.Job
            if (-not $usual.ContainsKey($k)) { continue }
            $st = ConvertTo-SIUpdaterHungUtc $s.StartedUtc; if ($null -eq $st) { continue }
            if (($nowUtc - $st).TotalMinutes -le [Math]::Max([double]$usual[$k] * [double]$r.Factor, [double]$r.FloorMinutes)) { continue }
            $p = [ordered]@{ Known = $false; Mine = 0L; Others = 0L; ProgressKnown = $false; LastProgressUtc = $null }
            if ($LogQuery) {
                try {
                    $kql = Get-SIUpdaterHungLogQuery -Execution $s.Execution -StartedUtc $st -WorkerJob $(if ($parts.ContainsKey($k)) { 'caj-si-{0}-worker' -f $k } else { '' })
                    if ($kql) {
                        $lr = @(& $LogQuery $kql | Where-Object { $_ })
                        if ($lr.Count) { $p.Mine = [long](& $field $lr[0] 'Mine'); $p.Others = [long](& $field $lr[0] 'Others'); $p.Known = $true }
                    }
                } catch { $p.Known = $false }
            }
            if ($Progress) { try { $p.LastProgressUtc = & $Progress $k $s.Execution $st; $p.ProgressKnown = $true } catch { $p.ProgressKnown = $false } }
            $probe[$s.Execution] = [pscustomobject]$p
        }
        $sel = Select-SIUpdaterHungSteps -Steps $running -Usual $usual -Probe $probe -NowUtc $nowUtc
        $res.Kept = @($sel.Kept)
        $stopped = New-Object System.Collections.Generic.List[object]
        foreach ($h in @($sel.Hung)) {
            try { $null = & $Stop $h.Key $h.Execution }
            catch {
                if ([string]$_.Exception.Message -notmatch '(?is)not\s+found|ExecutionNotFound') { & $Log 'WARN' ('the hung step {0} (execution {1}) could not be stopped: {2} -- the update waits, as before' -f $h.Key, $h.Execution, $_.Exception.Message); continue }
            }
            # read back: the execution ended
            $ended = $false
            if ($ReadStatus) {
                $waited = 0
                while ($true) {
                    $stt = ''; try { $stt = [string](& $ReadStatus $h.Key $h.Execution) } catch { $stt = '' }
                    if ($stt -and $stt -notin @('Running', 'Processing')) { $ended = $true; break }
                    if ($waited -ge [int]$r.StopReadSeconds) { break }
                    & $Sleep ([int]$r.StopPollSeconds); $waited += [int]$r.StopPollSeconds
                }
            } else { $ended = $true }
            & $Log 'WARN' (Get-SIUpdaterHungStepText -Hung $h -RunId $RunId -Ended $ended)
            $ev = [pscustomobject]@{ Id = $r.AlertId; Name = $h.Execution; Execution = $h.Execution; Kind = 'step'; Step = $h.Key; RunId = $RunId; AgeMin = $h.AgeMin; UsualMin = $h.UsualMin
                                     LastBeatUtc = $null; MinutesSinceBeat = $null; LockName = ''; StoppedUtc = $nowUtc; QueuedRunStarted = $false; Ended = $ended }
            if ($Alert) { try { $null = & $Alert $ev } catch { } }
            $stopped.Add($ev)
        }
        $res.Stopped = $stopped.ToArray()
        $res.Why = if ($stopped.Count) { 'stopped {0} hung step(s)' -f $stopped.Count } else { 'no hung step' }
    } catch { $res.Why = ('the run''s steps could not be read ({0}) -- nothing is stopped' -f $_.Exception.Message) }
    [pscustomobject]$res
}

# ---- the real seams (the updater's own REST sign-in; nothing here runs in a test that passes its own) ----------------------
function Get-SIUpdaterWorkspaceResourceId {
    <# The install's Log Analytics workspace: SI_WORKSPACE_RESOURCEID of the pipeline runner's job (the updater job does not
       carry it). '' when it cannot be read. -Arm { param($Path) } is the test seam. Never throws. #>
    param([Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId, [scriptblock]$Arm)
    try {
        $path = Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider 'Microsoft.App/jobs/caj-si-flow'
        $job = if ($Arm) { & $Arm $path } else { Invoke-SIUpdaterArm -Path $path }
        foreach ($c in @($job.properties.template.containers)) { foreach ($v in @($c.env)) { if ($v -and [string]$v.name -eq 'SI_WORKSPACE_RESOURCEID' -and "$($v.value)".Trim()) { return "$($v.value)".Trim() } } }
    } catch { }
    ''
}

function Invoke-SIUpdaterLaQuery {
    <# One Log Analytics query as the updater's identity: the workspace's customer id through ARM, then the query API. The
       first table's rows as objects. THROWS on any failure (the caller then counts the log lines as not read). #>
    param([Parameter(Mandatory)][string]$WorkspaceResourceId, [Parameter(Mandatory)][string]$Query)
    $ws = Invoke-SIUpdaterArm -Path $WorkspaceResourceId -ApiVersion '2022-10-01'
    $cid = if ($ws -and $ws.properties) { [string]$ws.properties.customerId } else { '' }
    if (-not $cid) { throw 'the Log Analytics workspace id could not be read' }
    $j = Invoke-SIRestJson -Rest (Get-SIUpdaterRest) -Method POST -Uri ('https://api.loganalytics.io/v1/workspaces/{0}/query' -f $cid) -Body (@{ query = $Query } | ConvertTo-Json -Compress) `
             -Resource 'https://api.loganalytics.io/' -Headers @{ 'Content-Type' = 'application/json' } -What 'Log Analytics query'
    $tbl = @($j.tables)[0]
    if (-not $tbl) { return @() }
    $names = @(@($tbl.columns) | ForEach-Object { [string]$_.name })
    foreach ($row in @($tbl.rows)) { $o = [ordered]@{}; for ($i = 0; $i -lt $names.Count; $i++) { $o[$names[$i]] = @($row)[$i] }; [pscustomobject]$o }
}

function Invoke-SIUpdaterHungStepGate {
    <#
        The run gate's ROLL-HUNG-1 pass with the real seams: -Store (the Pro database), -RunId (the run the update waits for).
        Returns Invoke-SIUpdaterHungStepCheck's result, or $null when it cannot be asked (no store, no run id). Never throws.
    #>
    param($Store, [AllowEmptyString()][string]$RunId, [Parameter(Mandatory)][string]$ResourceGroup, [Parameter(Mandatory)][string]$SubscriptionId)
    if (-not $Store -or -not $Store.Invoke -or -not "$RunId".Trim()) { return $null }
    try {
        $hgInvoke = $Store.Invoke
        $hgWs = Get-SIUpdaterWorkspaceResourceId -ResourceGroup $ResourceGroup -SubscriptionId $SubscriptionId
        $hgJobs = Get-SIUpdaterRgPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -Provider 'Microsoft.App/jobs'
        $hgProgSql = if (Get-Command -Name Get-SIStepProgressLastSql -ErrorAction SilentlyContinue) { Get-SIStepProgressLastSql } else { $null }
        Invoke-SIUpdaterHungStepCheck -RunId $RunId -Sql $hgInvoke `
            -LogQuery $(if ($hgWs) { { param($kql) Invoke-SIUpdaterLaQuery -WorkspaceResourceId $hgWs -Query $kql } } else { $null }) `
            -Progress $(if ($hgProgSql) { { param($k, $x, $since)
                        # throws when it cannot be read (Get-SIStepProgressLast would answer $null = "no progress" -- never used here)
                        $rows = @(& $hgInvoke $hgProgSql @{ Job = $k; Execution = [string]$x; SinceUtc = ([datetime]$since).ToString('yyyy-MM-ddTHH:mm:ss.fff', [Globalization.CultureInfo]::InvariantCulture) } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
                        if (-not $rows.Count) { return $null }
                        $v = if ($rows[0] -is [System.Collections.IDictionary]) { $rows[0]['LastUtc'] } else { $rows[0].LastUtc }
                        if ($v -is [DBNull]) { $null } else { $v } } } else { $null }) `
            -Stop { param($k, $x) Invoke-SIUpdaterArm -Method POST -Path ('{0}/caj-si-{1}/executions/{2}/stop' -f $hgJobs, $k, $x) -ApiVersion '2024-03-01' } `
            -ReadStatus { param($k, $x) $e = Invoke-SIUpdaterArm -Path ('{0}/caj-si-{1}/executions/{2}' -f $hgJobs, $k, $x) -ApiVersion '2024-03-01' -AllowNotFound; if ($e) { [string]$e.properties.status } else { 'Gone' } } `
            -Log { param($l, $m) Write-UpdLog $(if ($l -eq 'WARN') { 'WARNING: ' + $m } else { $m }) } `
            -Alert { param($ev) if (Get-Command -Name Send-SIExecutionStoppedAlert -ErrorAction SilentlyContinue) { $null = Send-SIExecutionStoppedAlert -Event $ev } }
    } catch { Write-UpdLog ('whether a step of the run is hung could not be read ({0}) -- the update waits, as before' -f $_.Exception.Message); $null }
}
