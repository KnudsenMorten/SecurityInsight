#Requires -Version 5.1
<#
    SecurityInsight -- STOP THE RUNNING PIPELINE RUN, THEN UPDATE (#1101; owner 2026-11-04: "i am tired of this happening
    where we are not in control"). The engine of setup\Stop-SIRunAndUpdate.ps1.

    LIVE 2026-11-04 (a support session at an install): the running run was cancelled and the updater started at the SAME
    moment. A cancel takes minutes to stop the run's executions, so the updater saw the run still going and stepped aside;
    the order was then improvised by hand. This file does it in ONE deterministic order, a READ-BACK before every next step:

      0. PLAN    what runs now (the running pipeline run -- id, trigger, step, age -- and every running execution of the
                 install's jobs), the installed version against the one the install's ring serves (the updater's own last
                 manifest check, read only), and what will happen. Without -Apply this is all.
      1. CANCEL  the product's way (#700): caj-si-flow started ONCE with SI_FLOW_CANCEL=1, SI_FLOW_CANCEL_REASON,
                 SI_AUDIT_STARTED_BY (and SI_FLOW_CANCEL_RUN when the run is known) -- the runner's own
                 Invoke-SIPipelineCancelRun marks, stops, releases and audits (job.flowrun.stop). Read back: the execution.
      2. WAIT    until the stop is CONFIRMED: the cancel execution has ended, the run record reads Cancelled (when this
                 machine can read it), and NO execution of any pipeline job runs -- steps, producers, workers, the data
                 sync, the runner (a wake-up of the runner younger than 5 minutes that started nothing is not counted).
                 Polled up to -TimeoutMinutes. On the limit: STOP, say exactly what still runs, and never start the updater.
      3. START   the run state READ AGAIN first (#1150: a scheduled run may have started since the plan -- then the updater is
                 NOT started; a young wake-up of the runner is waited for), then the updater once (New-SIUpdateNowStartTemplate,
                 mode update-now -- the start the heartbeat's "update now" makes), bound to its execution. Read back: the
                 execution. The plan warns when the install's next scheduled run is within 10 minutes.
      4. WAIT    for that execution to end, then READ BACK the installed version (the updater job's tag si-installed) and
                 the updater's own outcome (its update state, its wait mark).
      5. ONE summary line.
    It never starts a pipeline run or a step, never touches a run that is not running, and starts at most these two
    executions. Audit rows: job.flowrun.cancel (the cancel asked for) and job.execution.start (the updater started) on the
    install's trail when its database can be reached from here (never by opening it -- a private install's database stays
    closed and the line says so); the cancel execution writes job.flowrun.stop itself, from inside the install.

    Seams (tests pass fakes; the script passes the real ones):
      -Arm   { param([string]$Method, [string]$Path, $Body) }  parsed answer; $null for a GET that finds nothing
      -Sql   { param([string]$Query, $Params, [string]$Mode) } the Pro database ($null = cannot be read from here, -SqlWhy)
      -ReadUpdateState { } -> the updater's state JSON (SI-Update-State); throws when it cannot be read
      -Sleep { param($Seconds) }, -Now { } -> [datetime] UTC, -Say { param([string]$Line, [string]$Color) }
    PS 5.1 safe; no module.
#>

if (-not (Get-Command -Name New-SIJobStartTemplate -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', '_shared', 'SI-UpdaterStart.ps1'))
}
if (-not (Get-Command -Name New-SIJobFlowSqlStore -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', '_shared', 'SI-JobFlow.ps1'))
}
if (-not (Get-Command -Name Write-SIAuditEvent -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', 'pro-settings', 'SI-Audit.ps1'))
}

$script:SIStopRun = [ordered]@{
    ArmApi       = '2025-07-01'
    FlowJob      = 'caj-si-flow'
    UpdaterJob   = 'caj-si-updater'
    # a wake-up of the runner younger than this that started nothing is not a run
    WakeMinutes  = 5
    # jobs that are never a step of a pipeline run: the updater, the heartbeat, support's one-time jobs, the probes, and
    # (#1111) the index build job -- it gives way to the update by itself (it pauses its build and frees the lock), so the
    # stop never waits for it and never mistakes it for the updater
    NotStepRx    = '(?i)(-updater$|heartbeat|support|insidecheck|sizing-probe|index-build)'
    RunningState = @('Running', 'Processing')
    RunLive      = @('Starting', 'Running')
}

function Get-SIStopRunProp {
    <# PURE. A nested property (PSCustomObject or dictionary), $null when any step is missing. #>
    param($Object, [string[]]$Names)
    $o = $Object
    foreach ($n in $Names) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { $o = $(if ($o.Contains($n)) { $o[$n] } else { $null }); continue }
        $p = $o.PSObject.Properties[$n]
        $o = $(if ($p) { $p.Value } else { $null })
    }
    $o
}

function ConvertTo-SIStopRunUtc {
    <# PURE. A time (text or [datetime]) as UTC, $null when it is not one. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [DBNull]) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $s = "$Value".Trim(); if (-not $s) { return $null }
    $styles = [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal'
    try { return [datetime]::Parse($s, [Globalization.CultureInfo]::InvariantCulture, $styles) } catch { return $null }
}

function Format-SIStopRunAge {
    <# PURE. "3 h 12 min" / "7 min" / "40 s". #>
    param($Since, [Parameter(Mandatory)][datetime]$NowUtc)
    if (-not $Since) { return 'age unknown' }
    $s = ($NowUtc.ToUniversalTime() - ([datetime]$Since).ToUniversalTime()).TotalSeconds
    if ($s -lt 0) { $s = 0 }
    if ($s -lt 60) { return ('{0:N0} s' -f $s) }
    $m = [Math]::Floor($s / 60)
    if ($m -lt 60) { return ('{0} min' -f $m) }
    ('{0} h {1} min' -f [Math]::Floor($m / 60), ($m % 60))
}

function Get-SIStopRunArmList {
    <# Every item of an ARM list, following nextLink (at most 50 pages). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path)
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Path
    for ($i = 0; $next -and $i -lt 50; $i++) {
        $page = & $Arm 'GET' $next $null
        if (-not $page) { break }
        foreach ($v in @(Get-SIStopRunProp $page @('value'))) { if ($null -ne $v) { $items.Add($v) } }
        $next = [string](Get-SIStopRunProp $page @('nextLink'))
    }
    $items.ToArray()
}

function Get-SIStopRunJobsPath {
    <# PURE. The install's jobs: /subscriptions/<s>/resourceGroups/<rg>/providers/Microsoft.App/jobs #>
    param([Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.App/jobs' -f $SubscriptionId, $ResourceGroup
}

function Read-SIStopRunInstall {
    <# The install's jobs (ARM): @{ Base; Jobs; Flow; Updater; StepJobs (names: every job of a run, the runner excluded) }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup)
    $c = $script:SIStopRun
    $base = Get-SIStopRunJobsPath -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    $jobs = @(Get-SIStopRunArmList -Arm $Arm -Path ('{0}?api-version={1}' -f $base, $c.ArmApi) | Where-Object { $_ -and [string]$_.name })
    $flow = @($jobs | Where-Object { [string]$_.name -eq $c.FlowJob })[0]
    $upd = @($jobs | Where-Object { [string]$_.name -eq $c.UpdaterJob })[0]
    if (-not $upd) { $cand = @($jobs | Where-Object { [string]$_.name -match '-updater$' }); if ($cand.Count -eq 1) { $upd = $cand[0] } }
    $steps = @($jobs | ForEach-Object { [string]$_.name } | Where-Object { $_ -ne $c.FlowJob -and $_ -notmatch $c.NotStepRx -and (-not $upd -or $_ -ne [string]$upd.name) })
    [pscustomobject]@{ Base = $base; Jobs = $jobs; Flow = $flow; Updater = $upd; StepJobs = $steps }
}

function ConvertTo-SIStopRunExecution {
    <# PURE. One ARM execution -> @{ Name; Status; Running; StartUtc; EndUtc }. Running = Running / Processing without an end. #>
    param($Execution)
    $st = [string](Get-SIStopRunProp $Execution @('properties', 'status'))
    $end = ConvertTo-SIStopRunUtc (Get-SIStopRunProp $Execution @('properties', 'endTime'))
    [pscustomobject]@{ Name = [string](Get-SIStopRunProp $Execution @('name')); Status = $st
                       Running = ($st -in $script:SIStopRun.RunningState -and -not $end)
                       StartUtc = (ConvertTo-SIStopRunUtc (Get-SIStopRunProp $Execution @('properties', 'startTime'))); EndUtc = $end }
}

function Read-SIStopRunExecutions {
    <# The executions of -JobNames: @{ Map (job -> executions); Unreadable (job: why) }. A job that cannot be read is NOT
       read as idle -- the caller counts it as "not confirmed". #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Base, [string[]]$JobNames = @())
    # a plain hashtable: on pwsh 7 an [ordered] dictionary's indexer set from a [string[]] item failed ("Argument types do not match")
    $map = @{}; $bad = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($JobNames | Where-Object { $_ })) {
        try { $map[[string]$n] = @(Get-SIStopRunArmList -Arm $Arm -Path ('{0}/{1}/executions?api-version={2}' -f $Base, $n, $script:SIStopRun.ArmApi) | ForEach-Object { ConvertTo-SIStopRunExecution $_ }) }
        catch { $bad.Add(('{0}: {1}' -f $n, $_.Exception.Message)) }
    }
    [pscustomobject]@{ Map = $map; Unreadable = $bad.ToArray() }
}

function Get-SIStopRunActivity {
    <#
        PURE. What runs, from the executions: Steps (a job of the run with a running execution, as "job execution (age)"),
        Runner (an execution of the runner older than the wake-up window, or one the caller names as the run's), Wakes
        (a runner execution younger than the window -- a wake-up; it counts only when a step runs too, because then it may
        have started that step), Unreadable. -Ignore: executions this script started (the cancel), never counted here.
    #>
    param([Parameter(Mandatory)]$Executions, [Parameter(Mandatory)][string]$FlowJob, [Parameter(Mandatory)][datetime]$NowUtc,
          [string[]]$Ignore = @(), [int]$WakeMinutes = $script:SIStopRun.WakeMinutes)
    $steps = New-Object System.Collections.Generic.List[string]; $runner = New-Object System.Collections.Generic.List[string]; $wakes = New-Object System.Collections.Generic.List[string]
    foreach ($job in @($Executions.Map.Keys)) {
        foreach ($e in @($Executions.Map[$job] | Where-Object { $_ -and $_.Running -and $Ignore -notcontains $_.Name })) {
            $txt = '{0} {1} ({2})' -f $job, $e.Name, (Format-SIStopRunAge -Since $e.StartUtc -NowUtc $NowUtc)
            if ($job -ne $FlowJob) { $steps.Add($txt); continue }
            $young = $e.StartUtc -and (($NowUtc.ToUniversalTime() - $e.StartUtc).TotalMinutes -lt $WakeMinutes)
            if ($young) { $wakes.Add($txt) } else { $runner.Add($txt) }
        }
    }
    $busy = ($steps.Count -gt 0) -or ($runner.Count -gt 0) -or (($wakes.Count -gt 0) -and ($steps.Count -gt 0))
    [pscustomobject]@{ Steps = $steps.ToArray(); Runner = $runner.ToArray(); Wakes = $wakes.ToArray(); Unreadable = @($Executions.Unreadable); Busy = $busy }
}

function Get-SIStopRunRunView {
    <# PURE. The last pipeline run as the plan shows it: @{ Known; Running; Id; State; Trigger; Step; StartedUtc; RequestedBy }. #>
    param($Run)
    if (-not $Run) { return [pscustomobject]@{ Known = $true; Running = $false; Id = ''; State = ''; Trigger = ''; Step = ''; StartedUtc = $null; RequestedBy = '' } }
    $live = @(@($Run.Steps) | Where-Object { $_ -and [string]$_.State -in $script:SIStopRun.RunLive } | ForEach-Object { [string]$_.Job })
    [pscustomobject]@{ Known = $true; Running = ([string]$Run.State -in $script:SIStopRun.RunLive); Id = [string]$Run.FlowRunId; State = [string]$Run.State
                       Trigger = [string](Get-SIStopRunProp $Run @('Trigger')); Step = ($live -join ', '); StartedUtc = (ConvertTo-SIStopRunUtc $Run.StartedUtc)
                       RequestedBy = [string](Get-SIStopRunProp $Run @('RequestedBy')) }
}

function Read-SIStopRunRun {
    <# The last pipeline run from the Pro database (the runner's own reader, New-SIJobFlowSqlStore Load -- reads only).
       @{ View; Why } -- View $null when it cannot be read here (Why says why). #>
    param([scriptblock]$Sql, [string]$SqlWhy = '')
    if (-not $Sql) { return [pscustomobject]@{ View = $null; Why = $(if ($SqlWhy) { $SqlWhy } else { 'the install''s database is not reachable from here' }) } }
    try { [pscustomobject]@{ View = (Get-SIStopRunRunView -Run ((New-SIJobFlowSqlStore -Invoke $Sql).Load())); Why = '' } }
    catch { [pscustomobject]@{ View = $null; Why = ('the run record could not be read ({0})' -f $_.Exception.Message) } }
}

function Get-SIStopRunVersions {
    <#
        PURE apart from -UpdateState. The installed version (the updater job's tag si-installed, written after every roll)
        against the version the install's ring serves as the updater last read it (its update state SI-Update-State: the
        code manifest's version, sequence and ring, and when). @{ Installed; InstalledUtc; Ring; Served; ServedLine; Action;
        CheckedUtc; Hold; LastError; Why }.
    #>
    param($Updater, [AllowNull()][AllowEmptyString()][string]$UpdateStateJson, [string]$UpdateStateWhy = '')
    $tags = Get-SIStopRunProp $Updater @('tags')
    $installed = [string](Get-SIStopRunProp $tags @('si-installed')); $installedUtc = [string](Get-SIStopRunProp $tags @('si-installed-utc'))
    $ring = ''
    foreach ($e in @(Get-SIStopRunProp (@(Get-SIStopRunProp $Updater @('properties', 'template', 'containers'))[0]) @('env'))) { if ($e -and [string]$e.name -eq 'SI_UPDATER_RING') { $ring = [string]$e.value } }
    $out = [ordered]@{ Installed = $installed.Trim(); InstalledUtc = $installedUtc.Trim(); Ring = $ring.Trim(); Served = ''; ServedLine = ''; Action = ''; CheckedUtc = $null; Hold = ''; LastError = ''; Why = '' }
    if (-not "$UpdateStateJson".Trim()) {
        $out.Why = $(if ($UpdateStateWhy) { $UpdateStateWhy } else { 'the updater has recorded no manifest check' })
    } elseif (-not (Get-Command -Name Get-SIInvardiaUpdateStatus -ErrorAction SilentlyContinue)) {
        $out.Why = 'this copy carries no Invardia update client (Community edition: its ring is read by its own updater)'
    } else {
        try {
            $st = Get-SIInvardiaUpdateStatus -Json $UpdateStateJson
            $code = $st.Code
            $out.Served = [string](Get-SIStopRunProp $code @('lastVersion'))
            $out.Action = [string](Get-SIStopRunProp $code @('lastAction'))
            $out.CheckedUtc = ConvertTo-SIStopRunUtc $st.LastCheckUtc
            if (-not $out.Ring) { $out.Ring = [string](Get-SIStopRunProp $code @('lastRing')) }
            $out.Hold = [string](Get-SIStopRunProp $code @('hold'))
            $out.LastError = [string]$st.LastError
            $out.ServedLine = $(if ($out.Served) { '{0} (sequence {1}, ring {2}; the updater''s last check {3})' -f $out.Served, [string](Get-SIStopRunProp $code @('lastSequence')), [string](Get-SIStopRunProp $code @('lastRing')), $(if ($out.CheckedUtc) { $out.CheckedUtc.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + 'Z' } else { 'never' }) } else { '' })
            if (-not $out.Served) { $out.Why = [string]$st.Summary }
        } catch { $out.Why = ('the update state could not be read ({0})' -f $_.Exception.Message) }
    }
    [pscustomobject]$out
}

function ConvertFrom-SIStopRunWaitsTag {
    <# PURE. The updater's wait mark (tag si-update-waits: <sinceUtc>|<setUtc>|<kind>|<reason>) -> @{ SetUtc; Kind; Reason } or $null. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    if (-not "$Value".Trim()) { return $null }
    $p = "$Value".Split('|', 4)
    if ($p.Count -lt 3) { return $null }
    $set = ConvertTo-SIStopRunUtc $p[1]
    if (-not $set) { return $null }
    [pscustomobject]@{ SetUtc = $set; Kind = $p[2]; Reason = $(if ($p.Count -ge 4) { $p[3] } else { '' }) }
}

function Get-SIStopRunUpdateOutcome {
    <#
        PURE. What the updater did, read back: @{ Updated; Line }. -Before / -After: Get-SIStopRunVersions before the start
        and after the execution ended; -Status: the execution's end status; -WaitsTag: the updater job's si-update-waits
        after; -StartedUtc: when this script started it.
    #>
    param([Parameter(Mandatory)]$Before, [Parameter(Mandatory)]$After, [string]$Status = '', [string]$WaitsTag = '', [Parameter(Mandatory)][datetime]$StartedUtc, [string]$Execution = '')
    $a = if ($Before.Installed) { $Before.Installed } else { '(not recorded)' }
    $b = if ($After.Installed) { $After.Installed } else { '(not recorded)' }
    if ($After.Installed -and $After.Installed -ne $Before.Installed) { return [pscustomobject]@{ Updated = $true; Line = ('updated {0} -> {1} (read back: the updater job''s si-installed)' -f $a, $b) } }
    $why = New-Object System.Collections.Generic.List[string]
    if ($Status -and $Status -ne 'Succeeded') { $why.Add(('the updater execution {0} ended {1} -- its log names why' -f $Execution, $Status)) }
    $w = ConvertFrom-SIStopRunWaitsTag -Value $WaitsTag
    if ($w -and $w.SetUtc -ge $StartedUtc.ToUniversalTime().AddMinutes(-1)) { $why.Add(('it stepped aside: {0} (it handed the update to the pipeline -- si-update-waits)' -f $(if ($w.Reason) { $w.Reason } else { 'a pipeline run was going' }))) }
    if ($After.CheckedUtc -and $After.CheckedUtc -ge $StartedUtc.ToUniversalTime().AddMinutes(-1)) {
        $why.Add(('its check of ring {0}: {1}{2}' -f $(if ($After.Ring) { $After.Ring } else { '?' }), $(if ($After.Action) { $After.Action } else { 'no action recorded' }), $(if ($After.Served) { ' ' + $After.Served } else { '' })))
        if ($After.Hold) { $why.Add(('HOLD: {0}' -f $After.Hold)) }
        if ($After.LastError) { $why.Add(('last error: {0}' -f $After.LastError)) }
    }
    if (-not $why.Count) { $why.Add('the updater ended without installing a release and recorded no check this run -- its log has its own line') }
    [pscustomobject]@{ Updated = $false; Line = ('not updated -- still {0}: {1}' -f $a, ($why -join '; ')) }
}

function ConvertTo-SIStopRunInlineSql {
    <# PURE. The statement with its parameters DECLAREd in front (Invardia's audited SQL path takes no parameters): text as
       N'...' (quotes doubled), numbers, bit, datetime2, NULL. #>
    param([Parameter(Mandatory)][string]$Query, [System.Collections.IDictionary]$Params)
    if (-not $Params -or -not $Params.Count) { return $Query }
    $d = New-Object System.Collections.Generic.List[string]
    foreach ($k in @($Params.Keys)) {
        if ("$k" -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw ("'{0}' is not a parameter name" -f $k) }
        $v = $Params[$k]
        if ($null -eq $v -or $v -is [DBNull]) { $d.Add(('DECLARE @{0} nvarchar(max) = NULL;' -f $k)) }
        elseif ($v -is [bool]) { $d.Add(('DECLARE @{0} bit = {1};' -f $k, [int]$v)) }
        elseif ($v -is [int] -or $v -is [long] -or $v -is [int16] -or $v -is [byte]) { $d.Add(('DECLARE @{0} bigint = {1};' -f $k, [long]$v)) }
        elseif ($v -is [datetime]) { $d.Add(("DECLARE @{0} datetime2(7) = '{1}';" -f $k, $v.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffff', [Globalization.CultureInfo]::InvariantCulture))) }
        else { $d.Add(("DECLARE @{0} nvarchar(max) = N'{1}';" -f $k, ([string]$v).Replace("'", "''"))) }
    }
    ($d -join "`n") + "`n" + $Query
}

function ConvertTo-SIStopRunRows {
    <# PURE. Rows as hashtables (a DataRow's columns, a PSCustomObject's properties, a hashtable as it is). #>
    param([object[]]$Rows = @())
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        if ($r -is [System.Collections.IDictionary]) { $r; continue }
        $h = [ordered]@{}
        if ($r -is [System.Data.DataRow]) { foreach ($c in $r.Table.Columns) { $h[$c.ColumnName] = $(if ($r[$c] -is [DBNull]) { $null } else { $r[$c] }) } }
        else { foreach ($p in $r.PSObject.Properties) { $h[$p.Name] = $p.Value } }
        $h
    }
}

function New-SIStopRunSupportSql {
    <# The (sql, params, mode) seam over Invardia's audited SQL path (Invoke-InvardiaSupportSql): reads read-only, every
       statement with -Reason in the customer's audit log. -Invoke replaces Invoke-InvardiaSupportSql (tests). #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][string]$Reason, [scriptblock]$Invoke)
    if (-not $Invoke) { $Invoke = { param($Server, $Database, $Query, $Reason, [bool]$ReadOnly) Invoke-InvardiaSupportSql -Server $Server -Database $Database -Query $Query -Reason $Reason -ReadOnly:$ReadOnly } }
    $inline = ${function:ConvertTo-SIStopRunInlineSql}; $rowsOf = ${function:ConvertTo-SIStopRunRows}
    {
        param([string]$Query, $Params, [string]$Mode)
        $r = & $Invoke $Server $Database (& $inline -Query $Query -Params $Params) $Reason ($Mode -eq 'reader')
        $rows = @(& $rowsOf -Rows @($(if ($r -and $r.PSObject.Properties['Rows']) { $r.Rows } else { $r })))
        if ($Mode -eq 'scalar') { if ($rows.Count) { return @($rows[0].Values)[0] } else { return $null } }
        if ($Mode -eq 'nonquery') { return 0 }
        , $rows
    }.GetNewClosure()
}

function New-SIStopRunTokenSql {
    <# The (sql, params, mode) seam as the person signed in here (an Entra token for the database; -Token { } -> the token).
       One connection per statement; the open is retried only for Azure's transient answers (Open-SISqlConnectionRetry). #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][scriptblock]$Token)
    if (-not (Get-Command -Name Open-SISqlConnectionRetry -ErrorAction SilentlyContinue)) {
        . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', '_shared', 'SI-SqlRetry.ps1'))
    }
    $open = ${function:Open-SISqlConnectionRetry}
    {
        param([string]$Query, $Params, [string]$Mode)
        $cn = & $open -Server $Server -Database $Database -Token $Token -Waits @(5, 10)
        try {
            $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
            if ($Params) { foreach ($k in @($Params.Keys)) { $null = $cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $Params[$k]) { [DBNull]::Value } else { $Params[$k] })) } }
            if ($Mode -eq 'scalar') { return $cmd.ExecuteScalar() }
            if ($Mode -eq 'nonquery') { return $cmd.ExecuteNonQuery() }
            $t = New-Object System.Data.DataTable
            $rd = $cmd.ExecuteReader(); try { $t.Load($rd) } finally { $rd.Dispose() }
            $rows = New-Object System.Collections.Generic.List[object]
            foreach ($row in $t.Rows) { $h = [ordered]@{}; foreach ($c in $t.Columns) { $h[$c.ColumnName] = $(if ($row[$c] -is [DBNull]) { $null } else { $row[$c] }) }; $rows.Add($h) }
            , $rows.ToArray()
        } finally { $cn.Dispose() }
    }.GetNewClosure()
}

function Get-SIStopRunDatabase {
    <# PURE. The install's Pro database as its runner names it (SI_ProSqlServer / SI_ProSqlDatabase on caj-si-flow, else
       any job): @{ Server (an FQDN); Database } -- empty when the install keeps its runs in storage. #>
    param([object[]]$Jobs = @(), $Flow)
    $read = {
        param($job, $name)
        foreach ($c in @(Get-SIStopRunProp $job @('properties', 'template', 'containers'))) { foreach ($e in @(Get-SIStopRunProp $c @('env'))) { if ($e -and [string]$e.name -eq $name -and "$($e.value)".Trim()) { return "$($e.value)".Trim() } } }
        ''
    }
    $srv = ''; $db = ''
    # the jobs carry the settings as SI_CFG_<name> (the container's config hand-over; found live 2026-11-04), older ones
    # by the plain name -- both are read
    foreach ($j in @(@($Flow) + @($Jobs) | Where-Object { $_ })) {
        foreach ($pre in 'SI_CFG_', '') {
            if (-not $srv) { $srv = & $read $j ($pre + 'SI_ProSqlServer') }
            if (-not $db) { $db = & $read $j ($pre + 'SI_ProSqlDatabase') }
        }
        if ($srv -and $db) { break }
    }
    if ($srv -and $srv -notmatch '\.') { $srv += '.database.windows.net' }
    [pscustomobject]@{ Server = $srv; Database = $db }
}

function Get-SIStopRunExecName {
    <# PURE. The execution a /start answered (its name, else the last part of its id); '' = none. #>
    param($Answer)
    $n = [string](Get-SIStopRunProp $Answer @('name'))
    if (-not $n) { $id = [string](Get-SIStopRunProp $Answer @('id')); if ($id) { $n = ($id -split '/')[-1] } }
    $n
}

function Get-SIStopRunSlotWarning {
    <# PURE. #1150: the plan's warning when the install's next scheduled run is near: -Due (Get-SIJobFlowDue: Action Start = a
       run is due at the runner's next wake-up; Wait + NextUtc = the next slot) within -WithinMinutes of -NowUtc. '' = none. #>
    param($Due, [Parameter(Mandatory)][datetime]$NowUtc, [int]$WithinMinutes = 10)
    if (-not $Due) { return '' }
    $a = [string](Get-SIStopRunProp $Due @('Action'))
    if ($a -eq 'Start') { return ('a scheduled run is DUE now -- the pipeline runner starts it at its next wake-up (minutes); -Apply reads the run state again right before it starts the updater and stops if a run has started') }
    $next = ConvertTo-SIStopRunUtc (Get-SIStopRunProp $Due @('NextUtc'))
    if ($a -ne 'Wait' -or -not $next) { return '' }
    $mins = ($next - $NowUtc.ToUniversalTime()).TotalMinutes
    if ($mins -lt 0 -or $mins -gt $WithinMinutes) { return '' }
    ('the next scheduled run starts at {0} (in {1:N0} min) -- an update now may meet it; better after that run, or -Apply reads the run state again right before it starts the updater and stops if a run has started' -f ($next.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + 'Z'), [Math]::Max(0, $mins))
}

function Read-SIStopRunDue {
    <# #1150: the install's schedule as the pipeline runner reads it (cfg.JobFlow + the last run: Get-SIJobFlowDue), read only.
       $null when it cannot be read here, or the jobs run on their own timers. Never throws. #>
    param([scriptblock]$Sql, [Parameter(Mandatory)][datetime]$NowUtc)
    if (-not $Sql -or -not (Get-Command -Name Get-SIJobFlowDue -ErrorAction SilentlyContinue)) { return $null }
    try {
        $store = New-SIJobFlowSqlStore -Invoke $Sql
        $row = $store.ReadDefinition()
        if (-not $row -or -not "$($row.Json)".Trim()) { return $null }
        $def = ConvertFrom-SIJobFlowJson -Json ([string]$row.Json)
        if ("$($row.Mode)".Trim()) { $def.Mode = ([string]$row.Mode).ToLowerInvariant() }
        if ([string]$def.Mode -eq 'schedules') { return $null }
        Get-SIJobFlowDue -Definition $def -Previous ($store.Load()) -NowUtc $NowUtc
    } catch { $null }
}

function Get-SIStopRunStartCheck {
    <#
        PURE. #1150 (an install, 2026-11-07: the plan read no run at 17:59, the scheduled run started 18:00:55, -Apply started
        the updater a minute later and the roll cancelled the starting run): RIGHT BEFORE the updater is started, from a fresh
        read -- -Run (the run record's view, $null = not read here), -Activity (Get-SIStopRunActivity, this script's own cancel
        execution ignored), -CancelledRunId (the run this script cancelled). Returns @{ Verdict = go | wait | refuse; Why }:
          refuse  a run is running that this script did not cancel, or a step / the runner executes
          wait    only a young wake-up of the runner executes (it may be starting a run that is not recorded yet)
          go      nothing runs.
    #>
    param($Run, [Parameter(Mandatory)]$Activity, [string]$CancelledRunId = '')
    $o = { param($v, $w) [pscustomobject]@{ Verdict = $v; Why = $w } }
    if ($Run -and $Run.Running -and (-not $CancelledRunId -or [string]$Run.Id -ne $CancelledRunId)) {
        return (& $o 'refuse' ('pipeline run {0} is running now (started {1}{2}) -- it started after the plan' -f $Run.Id, $(if ($Run.StartedUtc) { ([datetime]$Run.StartedUtc).ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) + 'Z' } else { '?' }), $(if ($Run.Trigger) { ', trigger ' + $Run.Trigger } else { '' })))
    }
    $busy = @(@($Activity.Runner) + @($Activity.Steps) | Where-Object { $_ })
    if ($busy.Count) { return (& $o 'refuse' ('executing now: {0}' -f ($busy -join ', '))) }
    if (@($Activity.Wakes | Where-Object { $_ }).Count) { return (& $o 'wait' ('a wake-up of the pipeline runner executes ({0}) -- it may be starting a run' -f ((@($Activity.Wakes)) -join ', '))) }
    & $o 'go' 'no pipeline run is running and no job of a run executes (read again right before the start)'
}

function Format-SIStopRunPlan {
    <# PURE. The plan's lines (step 0): what runs, the versions, what will happen. #>
    param([Parameter(Mandatory)]$Plan)
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add(('install        : {0} (subscription {1})' -f $Plan.ResourceGroup, $Plan.SubscriptionId))
    $rv = $Plan.Run
    if ($rv) {
        if ($rv.Running) { $l.Add(('running run    : {0} -- trigger {1}, step {2}, started {3} ({4} ago){5}' -f $rv.Id, $(if ($rv.Trigger) { $rv.Trigger } else { '?' }), $(if ($rv.Step) { $rv.Step } else { '(between steps)' }), $(if ($rv.StartedUtc) { $rv.StartedUtc.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) + 'Z' } else { '?' }), (Format-SIStopRunAge -Since $rv.StartedUtc -NowUtc $Plan.NowUtc), $(if ($rv.RequestedBy) { ', asked by ' + $rv.RequestedBy } else { '' }))) }
        elseif ($rv.Id) { $l.Add(('running run    : none -- the last run {0} is {1}' -f $rv.Id, $rv.State.ToLowerInvariant())) }
        else { $l.Add('running run    : none -- no pipeline run recorded') }
    } else {
        $l.Add(('running run    : the run record is not read here ({0}) -- what runs is read from Azure: {1}' -f $Plan.RunWhy, $(if ($Plan.Running) { 'a run is going' } else { 'no run is going' })))
    }
    foreach ($x in @($Plan.Activity.Runner)) { $l.Add(('executing      : {0}  [the pipeline runner]' -f $x)) }
    foreach ($x in @($Plan.Activity.Steps)) { $l.Add(('executing      : {0}' -f $x)) }
    foreach ($x in @($Plan.Activity.Wakes)) { $l.Add(('executing      : {0}  [a wake-up of the runner]' -f $x)) }
    foreach ($x in @($Plan.UpdaterRunning)) { $l.Add(('executing      : {0}  [the updater]' -f $x)) }
    if (-not (@($Plan.Activity.Runner) + @($Plan.Activity.Steps) + @($Plan.Activity.Wakes) + @($Plan.UpdaterRunning) | Where-Object { $_ }).Count) { $l.Add('executing      : nothing') }
    foreach ($x in @($Plan.Activity.Unreadable)) { $l.Add(('NOT READ       : {0}' -f $x)) }
    $v = $Plan.Versions
    $l.Add(('installed      : {0}{1}' -f $(if ($v.Installed) { $v.Installed } else { '(not recorded on the updater job)' }), $(if ($v.InstalledUtc) { ' (since ' + $v.InstalledUtc + ')' } else { '' })))
    $l.Add(('ring serves    : {0}' -f $(if ($v.ServedLine) { $v.ServedLine } elseif ($v.Ring) { 'ring ' + $v.Ring + ' -- not known here (' + $v.Why + ')' } else { 'not known here (' + $v.Why + ')' })))
    foreach ($w in @($Plan.Will)) { $l.Add(('will           : {0}' -f $w)) }
    $l.ToArray()
}

function Invoke-SIStopRunAndUpdate {
    <#
        The whole run (steps 0-5, see the file header). Returns @{ Mode (plan | applied | refused); Outcome (plan |
        nothing-to-stop | stopped | timeout | refused | updated | not-updated | update-running | start-failed | run-started); Plan;
        Lines; Summary; Started (what this run started: job + execution); ExitCode }.
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Arm,
        [Parameter(Mandatory)][string]$SubscriptionId,
        [Parameter(Mandatory)][string]$ResourceGroup,
        [Parameter(Mandatory)][string]$Reason,
        [string]$RunId = '',
        [switch]$SkipUpdate,
        [switch]$Apply,
        [ValidateRange(1, 720)][int]$TimeoutMinutes = 30,
        [ValidateRange(1, 600)][int]$PollSeconds = 30,
        [string]$By = 'support',
        [scriptblock]$Sql,
        [string]$SqlWhy = '',
        [scriptblock]$ReadUpdateState,
        [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
        [scriptblock]$Now = { [datetime]::UtcNow },
        [scriptblock]$Say = { param([string]$Line, [string]$Color) if ($Color) { Write-Host $Line -ForegroundColor $Color } else { Write-Host $Line } },
        # #1150: how near the next scheduled run makes the plan warn, and how long the start waits for a wake-up of the runner
        [int]$SlotWarnMinutes = 10,
        [int]$WakeWaitMinutes = 5
    )
    $c = $script:SIStopRun
    $why = "$Reason".Trim()
    if ($why.Length -lt 5) { throw 'say why (-Reason, a plain sentence): it is kept with the cancelled run and on the audit trail' }
    if ($why.Length -gt 400) { $why = $why.Substring(0, 400) }
    $by = "$By".Trim(); if (-not $by) { $by = 'support' }; if ($by.Length -gt 256) { $by = $by.Substring(0, 256) }
    $lines = New-Object System.Collections.Generic.List[string]
    $started = New-Object System.Collections.Generic.List[object]
    $emit = { param([string]$t, [string]$col = '') $lines.Add($t); & $Say $t $col }
    $nowU = { ([datetime](& $Now)).ToUniversalTime() }
    $readState = {
        if (-not $ReadUpdateState) { return [pscustomobject]@{ Json = ''; Why = 'the update state is not read in this run' } }
        try { [pscustomobject]@{ Json = [string](& $ReadUpdateState); Why = '' } } catch { [pscustomobject]@{ Json = ''; Why = ('the update state could not be read ({0})' -f $_.Exception.Message) } }
    }
    $result = { param($mode, $outcome, $summary, [int]$exit, $plan)
        [pscustomobject]@{ Mode = $mode; Outcome = $outcome; Plan = $plan; Lines = $lines.ToArray(); Summary = $summary; Started = $started.ToArray(); ExitCode = $exit } }

    # ---- 0. PLAN ----
    $inst = Read-SIStopRunInstall -Arm $Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    if (-not @($inst.Jobs).Count) { throw ('No Container Apps job was found in {0} (subscription {1}) -- is this the install''s resource group? Nothing was started.' -f $ResourceGroup, $SubscriptionId) }
    $watch = @(@($inst.StepJobs) + @($(if ($inst.Flow) { $c.FlowJob })) | Where-Object { $_ })
    $ex = Read-SIStopRunExecutions -Arm $Arm -Base $inst.Base -JobNames $watch
    $t0 = & $nowU
    $act = Get-SIStopRunActivity -Executions $ex -FlowJob $c.FlowJob -NowUtc $t0
    $runRead = Read-SIStopRunRun -Sql $Sql -SqlWhy $SqlWhy
    $rv = $runRead.View
    $updName = if ($inst.Updater) { [string]$inst.Updater.name } else { '' }
    $updRunning = @()
    if ($updName) {
        $ue = Read-SIStopRunExecutions -Arm $Arm -Base $inst.Base -JobNames @($updName)
        $updRunning = @(@($ue.Map[$updName]) | Where-Object { $_ -and $_.Running } | ForEach-Object { '{0} {1} ({2})' -f $updName, $_.Name, (Format-SIStopRunAge -Since $_.StartUtc -NowUtc $t0) })
    }
    $st0 = & $readState
    $ver0 = Get-SIStopRunVersions -Updater $inst.Updater -UpdateStateJson $st0.Json -UpdateStateWhy $st0.Why
    # #1150: the next scheduled run, when it is near (the plan warns; -Apply reads the run state again before the start)
    $slotWarn = Get-SIStopRunSlotWarning -Due (Read-SIStopRunDue -Sql $Sql -NowUtc $t0) -NowUtc $t0 -WithinMinutes $SlotWarnMinutes
    # is a run going? The run record when it can be read here; else what runs in Azure (the runner or a step)
    $running = if ($rv) { [bool]$rv.Running } else { (@($act.Runner).Count + @($act.Steps).Count) -gt 0 }
    $targetId = if ($rv -and $rv.Running) { $rv.Id } else { "$RunId".Trim() }
    $refuse = ''
    if ("$RunId".Trim() -and $rv) {
        if ($rv.Running -and $rv.Id -ne "$RunId".Trim()) { $refuse = ('run {0} is not the running run ({1} is) -- nothing was cancelled and the updater was not started (it would only step aside for {1})' -f "$RunId".Trim(), $rv.Id) }
        elseif (-not $rv.Running) { $running = $false }
    }
    if (-not $inst.Flow -and $running) { $refuse = ('the install has no {0} job, so the run cannot be cancelled the product''s way -- nothing was started' -f $c.FlowJob) }
    $will = New-Object System.Collections.Generic.List[string]
    if ($refuse) { $will.Add('nothing: ' + $refuse) }
    else {
        if ($running) {
            $will.Add(('1. cancel: start {0} once with SI_FLOW_CANCEL=1{1} (reason: {2}; by: {3})' -f $c.FlowJob, $(if ($targetId) { ', SI_FLOW_CANCEL_RUN=' + $targetId } else { '' }), $why, $by))
            $will.Add(('2. wait up to {0} min for the stop to be confirmed (the cancel ended, the run Cancelled, no job of the run executing); not confirmed = stop here, the updater is NOT started' -f $TimeoutMinutes))
        } else {
            $will.Add(('1-2. skipped: no pipeline run is running{0} -- nothing is cancelled' -f $(if ("$RunId".Trim()) { ' (run ' + "$RunId".Trim() + ' is not running)' } else { '' })))
        }
        if ($SkipUpdate) { $will.Add('3-4. skipped (-SkipUpdate): the updater is not started') }
        elseif (-not $updName) { $will.Add('3-4. the install has no updater job -- nothing is updated') }
        elseif (@($updRunning).Count) { $will.Add(('3. the updater runs already ({0}) -- not started again; 4. its end is waited for and the version read back' -f (@($updRunning) -join ', '))) }
        else { $will.Add(('3. read the run state AGAIN, then start {0} once (update now) -- not started when a run has started since this plan; 4. wait for it to end and read back the installed version' -f $updName)) }
    }
    $plan = [pscustomobject]@{ SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; NowUtc = $t0; Run = $rv; RunWhy = $runRead.Why; Running = $running
                               Activity = $act; UpdaterRunning = $updRunning; Versions = $ver0; Will = $will.ToArray(); TargetRunId = $targetId; Refused = $refuse; SlotWarning = $slotWarn }
    & $emit '== 0. PLAN -- stop the running run, then update' 'Cyan'
    foreach ($x in (Format-SIStopRunPlan -Plan $plan)) { & $emit ('   ' + $x) '' }
    & $emit ('   limit          : {0} min to confirm the stop (-TimeoutMinutes), polled every {1} s' -f $TimeoutMinutes, $PollSeconds) ''
    if ($slotWarn) { & $emit ('   WARNING        : ' + $slotWarn) 'Yellow' }
    if ($refuse) {
        & $emit ('REFUSED: ' + $refuse) 'Red'
        return (& $result 'refused' 'refused' ('nothing was started: ' + $refuse) 1 $plan)
    }
    if (-not $Apply) {
        & $emit 'PLAN ONLY -- nothing was started. Run again with -Apply to do it.' 'Yellow'
        return (& $result 'plan' 'plan' 'plan only: nothing was started' 0 $plan)
    }

    # ---- 1. CANCEL ----
    $cancelExec = ''; $stopLine = 'no run was running'
    if ($running) {
        $flowJob = & $Arm 'GET' ('{0}/{1}?api-version={2}' -f $inst.Base, $c.FlowJob, $c.ArmApi) $null
        if (-not $flowJob) { throw ('{0} could not be read -- nothing was started' -f $c.FlowJob) }
        $envC = [ordered]@{ SI_FLOW_CANCEL = '1'; SI_FLOW_CANCEL_REASON = $why; SI_AUDIT_STARTED_BY = $by; SI_FLOW_TRIGGER = 'manual' }
        if ($targetId) { $envC['SI_FLOW_CANCEL_RUN'] = $targetId }
        $ans = & $Arm 'POST' ('{0}/{1}/start?api-version={2}' -f $inst.Base, $c.FlowJob, $c.ArmApi) (New-SIJobStartTemplate -Job $flowJob -Env $envC -What $c.FlowJob)
        $cancelExec = Get-SIStopRunExecName $ans
        if (-not $cancelExec) { throw ('{0} was asked to start but named no execution -- check Operations > Jobs; the updater was NOT started' -f $c.FlowJob) }
        $started.Add([pscustomobject]@{ Job = $c.FlowJob; Execution = $cancelExec; What = 'cancel' })
        $seen = @(@((Read-SIStopRunExecutions -Arm $Arm -Base $inst.Base -JobNames @($c.FlowJob)).Map[$c.FlowJob]) | Where-Object { $_ -and $_.Name -eq $cancelExec })[0]
        $ok = Write-SIStopRunAudit -Sql $Sql -SqlWhy $SqlWhy -Action 'job.flowrun.cancel' -By $by -Target ('flow/{0}' -f $(if ($targetId) { $targetId } else { 'running' })) -Reason $why `
                 -OutcomeText ('Stop-SIRunAndUpdate: {0} started once with SI_FLOW_CANCEL=1 (execution {1})' -f $c.FlowJob, $cancelExec) -After ([ordered]@{ flowRunId = $targetId; execution = $cancelExec; by = $by; reason = $why })
        & $emit ('1. CANCEL: {0} started once with SI_FLOW_CANCEL=1{1} -- execution {2} (read back: {3}); audit: {4}' -f $c.FlowJob, $(if ($targetId) { ' for run ' + $targetId } else { '' }), $cancelExec, $(if ($seen) { $seen.Status } else { 'not listed yet' }), $ok) 'Green'

        # ---- 2. WAIT until the stop is confirmed ----
        $deadline = (& $nowU).AddMinutes($TimeoutMinutes)
        $confirmed = $false; $last = $null
        while ($true) {
            $tn = & $nowU
            $exN = Read-SIStopRunExecutions -Arm $Arm -Base $inst.Base -JobNames $watch
            $cx = @(@($exN.Map[$c.FlowJob]) | Where-Object { $_ -and $_.Name -eq $cancelExec })[0]
            $cancelEnded = [bool]($cx -and -not $cx.Running -and $cx.Status)
            $actN = Get-SIStopRunActivity -Executions $exN -FlowJob $c.FlowJob -NowUtc $tn -Ignore @($cancelExec)
            $rr = Read-SIStopRunRun -Sql $Sql -SqlWhy $SqlWhy
            $runOk = $true; $runTxt = 'the run record is not read here'
            if ($rr.View) {
                $runOk = ($targetId -and $rr.View.Id -eq $targetId -and $rr.View.State -eq 'Cancelled') -or (-not $targetId -and -not $rr.View.Running)
                $runTxt = $(if ($rr.View.Id) { 'run {0} reads {1}' -f $rr.View.Id, $rr.View.State } else { 'no run recorded' })
            }
            $still = @(@($actN.Runner) + @($actN.Steps) + @($(if (@($actN.Steps).Count) { $actN.Wakes })) + @($actN.Unreadable | ForEach-Object { 'NOT READ ' + $_ }) | Where-Object { $_ })
            $last = [pscustomobject]@{ CancelEnded = $cancelEnded; CancelStatus = $(if ($cx) { $cx.Status } else { 'not listed' }); RunOk = $runOk; RunText = $runTxt; Still = $still }
            if ($cancelEnded -and $runOk -and -not $still.Count) { $confirmed = $true; break }
            if ($tn -ge $deadline) { break }
            & $emit ('   waiting ({0} of {1} min): cancel execution {2}; {3}; still executing: {4}' -f [Math]::Floor(($tn - $t0).TotalMinutes), $TimeoutMinutes, $last.CancelStatus, $runTxt, $(if ($still.Count) { $still -join ', ' } else { 'nothing' })) 'DarkGray'
            & $Sleep $PollSeconds
        }
        $stopLine = 'stopped run {0}{1}' -f $(if ($targetId) { $targetId } else { '(id not read)' }), $(if ($rv -and $rv.Step) { ' at step ' + $rv.Step } else { '' })
        if (-not $confirmed) {
            $what = @(); if (-not $last.CancelEnded) { $what += ('the cancel execution {0} ({1})' -f $cancelExec, $last.CancelStatus) }; if (-not $last.RunOk) { $what += $last.RunText }; $what += @($last.Still)
            & $emit ('2. WAIT: NOT confirmed stopped after {0} min -- still: {1}. STOPPED HERE: the updater was NOT started.' -f $TimeoutMinutes, ($what -join '; ')) 'Red'
            $sum = 'run {0} NOT confirmed stopped after {1} min ({2}); the updater was not started; nothing else was started besides the cancel execution {3}' -f $(if ($targetId) { $targetId } else { '(id not read)' }), $TimeoutMinutes, ($what -join '; '), $cancelExec
            & $emit ('5. SUMMARY: ' + $sum) 'Red'
            return (& $result 'applied' 'timeout' $sum 1 $plan)
        }
        & $emit ('2. WAIT: confirmed stopped -- the cancel execution {0} ended {1}; {2}; no job of the run executing (read back){3}' -f $cancelExec, $last.CancelStatus, $last.RunText, $(if ($last.CancelStatus -ne 'Succeeded') { ' -- NOTE: the cancel execution did not succeed; its log names what it could not stop' } else { '' })) 'Green'
    } else {
        & $emit ('1-2. skipped: no pipeline run is running{0} -- nothing was cancelled' -f $(if ("$RunId".Trim()) { ' (run ' + "$RunId".Trim() + ' is not running)' } else { '' })) 'Gray'
    }

    if ($SkipUpdate) {
        $sum = '{0}; update not started (-SkipUpdate); nothing else was started' -f $stopLine
        & $emit ('5. SUMMARY: ' + $sum) 'Green'
        return (& $result 'applied' $(if ($running) { 'stopped' } else { 'nothing-to-stop' }) $sum 0 $plan)
    }
    if (-not $updName) {
        $sum = '{0}; not updated: the install has no updater job; nothing else was started' -f $stopLine
        & $emit ('5. SUMMARY: ' + $sum) 'Yellow'
        return (& $result 'applied' 'not-updated' $sum 1 $plan)
    }

    # ---- 3. START the updater once ----
    $updJob = & $Arm 'GET' ('{0}/{1}?api-version={2}' -f $inst.Base, $updName, $c.ArmApi) $null
    if (-not $updJob) { throw ('{0} could not be read -- the updater was not started' -f $updName) }
    $limitS = 0; try { $limitS = [int](Get-SIStopRunProp $updJob @('properties', 'configuration', 'replicaTimeout')) } catch { $limitS = 0 }
    $updLimitMin = if ($limitS -gt 0) { [int][Math]::Ceiling($limitS / 60) + 15 } else { 6 * 60 }
    $tStart = & $nowU
    $ueNow = Read-SIStopRunExecutions -Arm $Arm -Base $inst.Base -JobNames @($updName)
    $already = @(@($ueNow.Map[$updName]) | Where-Object { $_ -and $_.Running })[0]
    $updExec = ''
    if ($already) {
        $updExec = $already.Name
        & $emit ('3. START: the updater runs already ({0} {1}) -- not started again; its end is waited for' -f $updName, $updExec) 'Yellow'
    } else {
        # ---- 3a. #1150: the run state READ AGAIN right before the start -- the plan may be minutes old, and a scheduled run
        # may have started since (an update now does not wait for a run that is only starting). A run that started since:
        # NOT started (the update lands after that run by itself). A wake-up of the runner: waited for, up to -WakeWaitMinutes.
        $wDeadline = (& $nowU).AddMinutes($WakeWaitMinutes)
        while ($true) {
            $tn = & $nowU
            $rr = Read-SIStopRunRun -Sql $Sql -SqlWhy $SqlWhy
            $actR = Get-SIStopRunActivity -Executions (Read-SIStopRunExecutions -Arm $Arm -Base $inst.Base -JobNames $watch) -FlowJob $c.FlowJob -NowUtc $tn -Ignore @($(if ($cancelExec) { $cancelExec }))
            $chk = Get-SIStopRunStartCheck -Run $rr.View -Activity $actR -CancelledRunId $(if ($running) { $targetId } else { '' })
            if ($chk.Verdict -eq 'go') { & $emit ('3. READ AGAIN: {0}' -f $chk.Why) 'Gray'; break }
            if ($chk.Verdict -eq 'wait' -and $tn -lt $wDeadline) {
                & $emit ('   waiting before the start: {0}' -f $chk.Why) 'DarkGray'
                & $Sleep $PollSeconds
                continue
            }
            $why2 = if ($chk.Verdict -eq 'wait') { '{0}, still after {1} min' -f $chk.Why, $WakeWaitMinutes } else { $chk.Why }
            $sum = '{0}; the updater was NOT started: {1} -- the update is installed after that run by itself (the run gate), or run this again to stop that run first; nothing else was started' -f $stopLine, $why2
            & $emit ('3. READ AGAIN: a run started since the plan -- ' + $why2 + '. The updater was NOT started.') 'Red'
            & $emit ('5. SUMMARY: ' + $sum) 'Yellow'
            return (& $result 'applied' 'run-started' $sum 1 $plan)
        }
        try { $ans = & $Arm 'POST' ('{0}/{1}/start?api-version={2}' -f $inst.Base, $updName, $c.ArmApi) (New-SIUpdateNowStartTemplate -Job $updJob) }
        catch {
            $sum = '{0}; the updater could NOT be started ({1}); nothing else was started' -f $stopLine, $_.Exception.Message
            & $emit ('3. START: FAILED -- ' + $_.Exception.Message) 'Red'; & $emit ('5. SUMMARY: ' + $sum) 'Red'
            return (& $result 'applied' 'start-failed' $sum 1 $plan)
        }
        $updExec = Get-SIStopRunExecName $ans
        if (-not $updExec) { $updExec = '(not named)' }
        $started.Add([pscustomobject]@{ Job = $updName; Execution = $updExec; What = 'update' })
        $seenU = @(@((Read-SIStopRunExecutions -Arm $Arm -Base $inst.Base -JobNames @($updName)).Map[$updName]) | Where-Object { $_ -and $_.Name -eq $updExec })[0]
        $okU = Write-SIStopRunAudit -Sql $Sql -SqlWhy $SqlWhy -Action 'job.execution.start' -By $by -Target ('job/{0}' -f $updName) -Reason $why `
                 -OutcomeText ('Stop-SIRunAndUpdate: {0} started once (update now, execution {1}) after the stop was confirmed' -f $updName, $updExec) -After ([ordered]@{ job = $updName; execution = $updExec; mode = 'update-now'; by = $by })
        & $emit ('3. START: {0} started once (update now) -- execution {1} (read back: {2}); audit: {3}' -f $updName, $updExec, $(if ($seenU) { $seenU.Status } else { 'not listed yet' }), $okU) 'Green'
    }

    # ---- 4. WAIT for the updater, READ BACK the version ----
    $uDeadline = (& $nowU).AddMinutes($updLimitMin)
    $endStatus = ''
    while ($true) {
        $tn = & $nowU
        $mine = @(@((Read-SIStopRunExecutions -Arm $Arm -Base $inst.Base -JobNames @($updName)).Map[$updName]) | Where-Object { $_ -and $_.Name -eq $updExec })[0]
        if ($mine -and -not $mine.Running -and $mine.Status) { $endStatus = $mine.Status; break }
        if ($tn -ge $uDeadline) { break }
        & $emit ('   updating ({0} min, its limit {1} min): {2} {3}' -f [Math]::Floor(($tn - $tStart).TotalMinutes), $updLimitMin, $updExec, $(if ($mine) { $mine.Status } else { 'not listed yet' })) 'DarkGray'
        & $Sleep $PollSeconds
    }
    if (-not $endStatus) {
        $sum = '{0}; the update is still running after {1} min ({2} {3}) -- read the version back later; nothing else was started' -f $stopLine, $updLimitMin, $updName, $updExec
        & $emit ('4. WAIT: ' + $sum) 'Yellow'; & $emit ('5. SUMMARY: ' + $sum) 'Yellow'
        return (& $result 'applied' 'update-running' $sum 1 $plan)
    }
    $updAfter = & $Arm 'GET' ('{0}/{1}?api-version={2}' -f $inst.Base, $updName, $c.ArmApi) $null
    $st1 = & $readState
    $ver1 = Get-SIStopRunVersions -Updater $updAfter -UpdateStateJson $st1.Json -UpdateStateWhy $st1.Why
    $oc = Get-SIStopRunUpdateOutcome -Before $ver0 -After $ver1 -Status $endStatus -WaitsTag ([string](Get-SIStopRunProp (Get-SIStopRunProp $updAfter @('tags')) @('si-update-waits'))) -StartedUtc $tStart -Execution $updExec
    & $emit ('4. WAIT: {0} {1} ended {2}; {3}' -f $updName, $updExec, $endStatus, $oc.Line) $(if ($oc.Updated) { 'Green' } else { 'Yellow' })
    $sum = '{0}; {1}; nothing else was started' -f $stopLine, $oc.Line
    & $emit ('5. SUMMARY: ' + $sum) $(if ($oc.Updated) { 'Green' } else { 'Yellow' })
    & $result 'applied' $(if ($oc.Updated) { 'updated' } else { 'not-updated' }) $sum $(if ($oc.Updated) { 0 } else { 1 }) $plan
}

function Write-SIStopRunAudit {
    <# One row on the install's audit trail (Write-SIAuditEvent, actor source setup). Returns the line to say: 'written',
       or why not -- never throws, never stops the run. #>
    param([scriptblock]$Sql, [string]$SqlWhy, [Parameter(Mandatory)][string]$Action, [string]$By, [string]$Target, [string]$Reason, [string]$OutcomeText, $After)
    if (-not $Sql) { return ('not written from here ({0}){1}' -f $(if ($SqlWhy) { $SqlWhy } else { 'the install''s database is not reachable' }), $(if ($Action -eq 'job.flowrun.cancel') { ' -- the cancel execution writes job.flowrun.stop itself' } else { '' })) }
    $warn = New-Object System.Collections.Generic.List[string]
    $ok = Write-SIAuditEvent -Invoke $Sql -Action $Action -Actor $By -ActorSource 'setup' -Target $Target -Reason $Reason -OutcomeText $OutcomeText -After $After -Log { param($l, $m) $warn.Add($m) }.GetNewClosure()
    if ($ok) { return ('{0} written' -f $Action) }
    ('{0} NOT written ({1})' -f $Action, ($warn -join '; '))
}
