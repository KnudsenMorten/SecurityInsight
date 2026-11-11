#Requires -Version 5.1
<#
    SecurityInsight -- DATA HEALTH NEVER DEPENDS ON A FINISHED RUN (#1201).

    The daily data health check runs inside the verification job (engine\verification\Invoke-SIVerification.ps1), the last
    step of the pipeline. An install whose runs never get there -- they fail earlier, or are stopped for an update -- never
    reported (one large install: 21 days without a report while the check was on and never failed).

    THE RULE (asked by the pipeline runner at the end of every full wake-up, engine\flow\Invoke-SIJobFlowRun.ps1): when the
    newest data health report is older than 24 hours (or there is none), the runner starts the verification job ONCE with
    SI_DATAHEALTH_ON_OWN=1 -- that execution runs ONLY the data health check, on the data already stored -- and only when
      * the check is on (SI_DataHealth_Enabled) and the Pro database has its tables;
      * the install is IDLE: no pipeline run going, no open step, no data sync and no data out (Get-SIDataHousekeepingBusy,
        the same idle rule the clean-up and the index build use) -- so it never competes with a step that works the database;
      * no update runs or waits (the update goes first);
      * the verification job is not running now and did not start in the last 6 hours (the pipeline's own verification, or
        an earlier start of this rule that has not reported yet -- never a start every 5 minutes).
    A run that reaches verification reports there, so this rule then finds a fresh report and starts nothing.
    NEVER throws, never fails or holds the wake-up: anything that cannot be read = nothing started, one line.
    The execution carries SI_DATAHEALTH_ON_OWN=1 in its template, so the pipeline check (engine\_shared\SI-OutsidePipeline.ps1)
    does not report it as "ran outside the pipeline".
    PS 5.1 and 7. No PowerShell module. Every reader is a seam.
#>

$script:SIDataHealthOnOwn = @{
    MaxAgeHours  = 24
    RetryHours   = 6
    EnvName      = 'SI_DATAHEALTH_ON_OWN'
    EnvWhy       = 'SI_DATAHEALTH_ON_OWN_WHY'
    Job          = 'verification'
}

function Get-SIDataHealthLastReportSql {
    <# The newest finished data health cycle (the last report); no tables = HasTables 0. One row. #>
    "IF OBJECT_ID('cfg.DataHealthCycle') IS NULL SELECT CAST(0 AS int) AS HasTables, CAST(NULL AS datetime2(3)) AS LastReport ELSE SELECT CAST(1 AS int) AS HasTables, MAX(FinishedAt) AS LastReport FROM cfg.DataHealthCycle WHERE FinishedAt IS NOT NULL;"
}

function Get-SIDataHealthJudgedCollectionSql {
    <# The collection the check judges: the newest complete Detailed collection (the vulnerability part reads it; each source
       part reads its source's newest good collection). One row: CollectionId, CollectionTime; none = no row. #>
    "IF OBJECT_ID('sidata.Collection') IS NOT NULL SELECT TOP (1) CollectionId, CollectionTime FROM sidata.Collection WHERE Kind = N'Detailed' AND Status = N'Complete' ORDER BY CollectionTime DESC;"
}

function Get-SIDataHealthJudged {
    <#
        PURE. What the check says it judged, and why it runs now: @{ Trigger (verification | on-its-own); Why; CollectionId;
        CollectionTime; Line }. -Row: the row of Get-SIDataHealthJudgedCollectionSql ($null = none / not read); -ReadError:
        why it could not be read.
    #>
    param([AllowNull()]$Row, [bool]$OnOwn = $false, [string]$Why = '', [string]$ReadError = '')
    $v = { param($n) if ($null -eq $Row) { return $null }; $x = if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { $Row[$n] } else { $null } } elseif ($Row.PSObject.Properties[$n]) { $Row.$n } else { $null }; if ($x -is [System.DBNull]) { $null } else { $x } }
    $id = & $v 'CollectionId'; $t = & $v 'CollectionTime'
    $tu = $null; if ($null -ne $t) { try { $tu = ([datetime]$t).ToUniversalTime() } catch { $tu = $null } }
    $trigger = if ($OnOwn) { 'on-its-own' } else { 'verification' }
    $how = if ($OnOwn) { 'on its own' + $(if ("$Why".Trim()) { ' (' + "$Why".Trim() + ')' } else { '' }) } else { 'after the run''s verification' }
    $what = if ($null -ne $id -and $tu) { 'the newest complete collection {0} of {1:yyyy-MM-dd HH:mm} UTC' -f $id, $tu }
            elseif ("$ReadError".Trim()) { 'the newest complete collection (which one could not be read: {0})' -f "$ReadError".Trim() }
            else { 'no complete collection (the vulnerability part has nothing to compare)' }
    [pscustomobject]@{ Trigger = $trigger; Why = "$Why".Trim(); CollectionId = $id; CollectionTime = $tu
                       Line = ('data health judges {0}; each source against its newest good collection -- run {1}' -f $what, $how) }
}

function Test-SIDataHealthOnOwnRequested {
    <# PURE. Was this execution started to run the data health check on its own? (-Value: SI_DATAHEALTH_ON_OWN) #>
    param([AllowNull()][AllowEmptyString()][string]$Value = [Environment]::GetEnvironmentVariable('SI_DATAHEALTH_ON_OWN'))
    ("$Value".Trim().ToLowerInvariant()) -in @('1', 'true', 'yes')
}

function Get-SIDataHealthOnOwnDecision {
    <#
        PURE. Start the data health check on its own now? Returns @{ Start; Quiet; Why }. Quiet = nothing worth a line
        (a fresh report, the check off).
          -LastReportUtc  the newest finished cycle ($null = none)       -HasTables  the Pro database has the tables
          -Busy           Get-SIDataHousekeepingBusy's answer (@{ Busy; Why })
          -UpdaterRunning / -UpdateWaits  non-empty = an update runs / waits (its text)
          -JobExecutions  the verification job's executions (ARM shape) -- $null = they could not be read
    #>
    param([bool]$Enabled = $true, [bool]$HasTables = $true, [AllowNull()]$LastReportUtc, [Parameter(Mandatory)][datetime]$NowUtc,
          [AllowNull()]$Busy, [string]$UpdaterRunning = '', [string]$UpdateWaits = '',
          [AllowNull()][object[]]$JobExecutions, [bool]$JobThere = $true,
          [int]$MaxAgeHours = $script:SIDataHealthOnOwn.MaxAgeHours, [int]$RetryHours = $script:SIDataHealthOnOwn.RetryHours)
    $res = { param([bool]$s, [bool]$q, [string]$w) [pscustomobject]@{ Start = $s; Quiet = $q; Why = $w } }
    $now = $NowUtc.ToUniversalTime()
    if (-not $Enabled) { return (& $res $false $true 'the data health check is switched off (SI_DataHealth_Enabled)') }
    if (-not $HasTables) { return (& $res $false $true 'the Pro database has no data health tables yet (the update adds them)') }
    $last = $null; if ($null -ne $LastReportUtc -and "$LastReportUtc".Trim()) { try { $last = ([datetime]$LastReportUtc).ToUniversalTime() } catch { $last = $null } }
    $age = if ($last) { ($now - $last).TotalHours } else { $null }
    if ($null -ne $age -and $age -lt $MaxAgeHours) { return (& $res $false $true ('the last data health report is {0:N1} h old' -f $age)) }
    $stale = if ($null -eq $age) { 'there is no data health report yet' } else { 'the last data health report is {0:N0} h old ({1:yyyy-MM-dd HH:mm} UTC)' -f $age, $last }
    if (-not $JobThere) { return (& $res $false $false ('{0}, but the verification job is not there -- the next update makes it' -f $stale)) }
    if ($null -ne $Busy -and [bool]$Busy.Busy) { return (& $res $false $false ('{0}; it runs on its own once nothing works the database ({1})' -f $stale, [string]$Busy.Why)) }
    if ("$UpdaterRunning".Trim()) { return (& $res $false $false ('{0}; it runs on its own after the update ({1})' -f $stale, "$UpdaterRunning".Trim())) }
    if ("$UpdateWaits".Trim()) { return (& $res $false $false ('{0}; an update waits and goes first ({1})' -f $stale, "$UpdateWaits".Trim())) }
    if ($null -eq $JobExecutions) { return (& $res $false $false ('{0}; whether the verification job runs could not be read -- the next wake-up looks again' -f $stale)) }
    foreach ($x in @($JobExecutions | Where-Object { $_ })) {
        $p = if ($x.PSObject.Properties['properties']) { $x.properties } else { $x }
        $st = [string]$p.status
        if ($st -in @('Running', 'Processing')) { return (& $res $false $false ('{0}; the verification job runs now ({1}) and makes the report' -f $stale, [string]$x.name)) }
        $t = $null; if ($p.startTime) { try { $t = ([datetime]$p.startTime).ToUniversalTime() } catch { $t = $null } }
        if ($t -and ($now - $t).TotalHours -lt $RetryHours) { return (& $res $false $false ('{0}; the verification job started {1:yyyy-MM-dd HH:mm} UTC ({2}) -- started again at the earliest {3} h after that' -f $stale, $t, [string]$x.name, $RetryHours)) }
    }
    & $res $true $false $stale
}

function Invoke-SIDataHealthOnOwnCheck {
    <#
        THE WAKE-UP'S ASK (never throws). Seams:
          -Invoke     the Pro settings database (sql, params, mode)
          -Busy       { } -> Get-SIDataHousekeepingBusy's answer
          -UpdaterRunning / -UpdateWaits  { } -> text (empty = none), as the runner has them ($null = not asked)
          -Executions { } -> the verification job's executions (ARM shape); a 404 / not found = the job is not there
          -Start      { param($Env) } -> the started execution's name (the runner: POST .../start with New-SIJobStartTemplate)
          -Log        { param($Level, $Message) }
        Returns @{ Started; Execution; Why }.
    #>
    param([scriptblock]$Invoke, [scriptblock]$Busy, [scriptblock]$UpdaterRunning, [scriptblock]$UpdateWaits, [scriptblock]$Executions,
          [Parameter(Mandatory)][scriptblock]$Start, [scriptblock]$Log = { param($l, $m) Write-Host $m }, [AllowNull()]$Enabled = $global:SI_DataHealth_Enabled,
          [scriptblock]$Now = { [datetime]::UtcNow })
    $say = { param($l, $m) try { & $Log $l $m } catch { } }
    $out = { param([bool]$s, [string]$e, [string]$w) [pscustomobject]@{ Started = $s; Execution = $e; Why = $w } }
    try {
        $on = $true
        if ($null -ne $Enabled) { $s = "$Enabled".Trim().Trim('$').ToLowerInvariant(); if ($Enabled -is [bool]) { $on = [bool]$Enabled } elseif ($s -in @('false', '0', 'off', 'no', 'disabled')) { $on = $false } }
        if (-not $on) { return (& $out $false '' 'the data health check is switched off (SI_DataHealth_Enabled)') }
        if (-not $Invoke) { return (& $out $false '' 'no Pro database') }
        $nowUtc = ([datetime](& $Now)).ToUniversalTime()
        $row = @(& $Invoke (Get-SIDataHealthLastReportSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ }) | Select-Object -First 1
        $get = { param($n) if ($null -eq $row) { return $null }; $v = if ($row -is [System.Collections.IDictionary]) { $row[$n] } elseif ($row.PSObject.Properties[$n]) { $row.$n } else { $null }; if ($v -is [System.DBNull]) { $null } else { $v } }
        $hasTables = ([int](& $get 'HasTables') -eq 1)
        $last = & $get 'LastReport'
        # the cheap answer first: a fresh report (or the tables missing) needs nothing else read
        $pre = Get-SIDataHealthOnOwnDecision -Enabled $true -HasTables $hasTables -LastReportUtc $last -NowUtc $nowUtc -JobExecutions @()
        if ($pre.Quiet) { return (& $out $false '' $pre.Why) }
        $busyAns = $null; if ($Busy) { $busyAns = & $Busy } else { $busyAns = [pscustomobject]@{ Busy = $true; Why = 'whether a run is going could not be asked' } }
        $upd = ''; if ($UpdaterRunning) { try { $upd = [string](& $UpdaterRunning) } catch { $upd = 'whether the updater runs could not be read' } }
        $wait = ''; if ($UpdateWaits) { try { $w = & $UpdateWaits; if ($w) { $wait = $(if ($w.PSObject -and $w.PSObject.Properties['Reason'] -and [string]$w.Reason) { [string]$w.Reason } else { 'the updater''s wait mark is set' }) } } catch { $wait = 'whether an update waits could not be read' } }
        $ex = $null; $there = $true
        if ($Executions) { try { $ex = @(& $Executions) } catch { if ("$($_.Exception.Message)" -match '404|ResourceNotFound|not found') { $there = $false; $ex = @() } else { $ex = $null } } }
        $dec = Get-SIDataHealthOnOwnDecision -Enabled $true -HasTables $hasTables -LastReportUtc $last -NowUtc $nowUtc -Busy $busyAns -UpdaterRunning $upd -UpdateWaits $wait -JobExecutions $ex -JobThere $there
        if (-not $dec.Start) { & $say 'INFO' ('data health: {0}' -f $dec.Why); return (& $out $false '' $dec.Why) }
        $envs = [ordered]@{}; $envs[$script:SIDataHealthOnOwn.EnvName] = '1'; $envs[$script:SIDataHealthOnOwn.EnvWhy] = $dec.Why
        $name = [string](& $Start $envs)
        & $say 'INFO' ('data health: {0} -- the check runs now on its own on the stored data (verification job execution {1}); the pipeline is not touched' -f $dec.Why, $(if ($name) { $name } else { '(started)' }))
        & $out $true $name $dec.Why
    } catch {
        & $say 'WARN' ('data health: whether it must run on its own could not be decided ({0}) -- nothing started; the next wake-up looks again' -f $_.Exception.Message)
        & $out $false '' $_.Exception.Message
    }
}
