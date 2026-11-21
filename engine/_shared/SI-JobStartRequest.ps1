#Requires -Version 5.1
<#
    SecurityInsight -- a job start's own values WITHOUT a start override (#931).

    Azure Container Apps: a job start that carries containers / initContainers (empty arrays included) needs
    Microsoft.App/jobs/write besides jobs/start/action. The web app must not hold jobs/write (it would let it change a job's
    image, command and identity), so it never sends a template. Instead:
      1. the web app writes a cfg.JobTriggerRequest row, Action 'start-env', the values as a JSON object (EnvJson);
      2. it starts the job with NO body;
      3. it binds the row to the execution the start returned (ExecutionName) -- or, when the start failed, closes it as
         failed, so no later execution ever runs a start the person was told did not happen.
    This file is the job's side, run by the container entrypoint before the execution guard:
      * Invoke-SIJobStartRequestClaim claims the row bound to THIS execution (one UPDATE ... OUTPUT). A scheduled execution
        never takes a person's request. When the web app has written a row for this job but not yet bound it (the few
        seconds between the start and the bind), the claim waits for the bind, at most $script:SIJobStartRequestBindWaitSeconds;
      * only the names allowed for this job are set (Get-SIJobStartRequestAllowed) -- anything else is said and dropped,
        so a row can never change a sign-in, a target or a secret reference;
      * Invoke-SIJobStartRequestRelease hands a claimed row back when the execution guard skips the run (outcome
        'handed-back', unbound); the next execution of the job takes it within $script:SIJobStartRequestMaxAgeMinutes.
    The pipeline runner's trigger-request pass (SI-JobTriggerRequests.ps1) never applies start-env rows; it closes the ones
    nobody took as expired.
    #1292 THE STARTS THE PIPELINE RUNNER MAKES FOR A PERSON (SECURE-WEB-1: the internet-facing web app holds no job right, so
    its own start is refused with 403 jobs/start/action). A row the web app wrote with Outcome 'runner-start' (unbound) is
    started by the pipeline runner (caj-si-flow, its own identity) on its next wake-up -- a wake-up during a run too -- with a
    plain start (no override), then bound to that execution, so the job claims it exactly as above
    (Invoke-SIJobRunnerStarts). Only the jobs and values in $script:SIJobRunnerStartAllowed: today the connector page's
    ServiceNow check (the mail job with SI_SNOW_VERIFY). Never while that job runs (the row waits for the next wake-up);
    one nobody started within $script:SIJobRunnerStartMaxAgeMinutes is closed as expired.
    NEVER THROWS: no database, an older schema or a read that fails = the run goes on as configured. PS 5.1 safe.
#>

$script:SIJobStartRequestMaxAgeMinutes = 30
$script:SIJobStartRequestBindWaitSeconds = 20

# The names a start request may set, per job (the job name without caj-si-). Every job: who started it.
$script:SIJobStartRequestAllowed = @{
    '*'               = @('SI_AUDIT_CID', 'SI_AUDIT_STARTED_BY')
    'flow'            = @('SI_FLOW_DRAIN', 'SI_FLOW_TRIGGER', 'SI_FLOW_FORCE', 'SI_FLOW_STAGE', 'SI_FLOW_STEP', 'SI_FLOW_FROM_STEP')
    'close-loop-mail' = @('SI_EXEMPTION_MAIL_ONLY', 'SI_SNOW_VERIFY', 'SI_SNOW_VERIFY_BY')
    'templates'       = @('SI_TEMPLATES_MODE', 'SI_TEMPLATES_PACK', 'SI_TEMPLATES_METHODS', 'SI_TEMPLATES_ACCEPT_FINGERPRINT', 'SI_TEMPLATES_REQUESTED_BY', 'SI_TEMPLATES_CLASS')
    # a one-off report certification run (ops\report-certification\Start-SICertRun.ps1): one template, no Log Analytics / mail
    'risk-analysis'          = @('SI_RA_REPORT_TEMPLATE', 'SI_RA_MODE', 'SI_RA_SEND_TO_LOG_ANALYTICS', 'SI_RA_SEND_MAIL')
    'risk-analysis-detailed' = @('SI_RA_REPORT_TEMPLATE', 'SI_RA_MODE', 'SI_RA_SEND_TO_LOG_ANALYTICS', 'SI_RA_SEND_MAIL')
}

# Names applied ONLY from a request bound to THIS execution (the start that ran with it). A request handed back by a
# skipped execution is taken by whichever execution of the job comes next -- a scheduled one too -- so it never carries
# these: a scheduled run is never switched off Log Analytics or mail, or moved to another report, by a row in the table.
# #1292: the ServiceNow check's values too -- a check handed back must never turn the pipeline's own mail step into an
# outbox-only check (the day's mail would not go out); a handed-back check is simply not run, the next one is asked again.
$script:SIJobStartRequestBoundOnly = @('SI_RA_REPORT_TEMPLATE', 'SI_RA_MODE', 'SI_RA_SEND_TO_LOG_ANALYTICS', 'SI_RA_SEND_MAIL',
    'SI_SNOW_VERIFY', 'SI_SNOW_VERIFY_BY', 'SI_EXEMPTION_MAIL_ONLY')

# #1292: the jobs the pipeline runner starts for a person, and the value such a request MUST carry (anything else is refused)
$script:SIJobRunnerStartAllowed = @{ 'caj-si-close-loop-mail' = 'SI_SNOW_VERIFY' }
$script:SIJobRunnerStartMaxAgeMinutes = 30

function Get-SIJobStartRequestAllowed {
    <# PURE. The names a start request may set on job -Job (caj-si-<x> or <x>). #>
    param([string]$Job)
    $key = ([string]$Job) -replace '^caj-si-', ''
    $names = @($script:SIJobStartRequestAllowed['*'])
    if ($script:SIJobStartRequestAllowed.ContainsKey($key)) { $names += @($script:SIJobStartRequestAllowed[$key]) }
    $names
}

function Get-SIJobStartRequestClaimSql {
    # the row bound to this execution, else (oldest first) one handed back by a skipped execution of the same job
    @"
UPDATE r SET AppliedUtc = SYSUTCDATETIME(), Outcome = N'applied', ExecutionName = @Exec, Detail = N'taken by execution ' + @Exec
OUTPUT inserted.RequestId, inserted.EnvJson, inserted.RequestedBy, deleted.ExecutionName AS BoundTo
FROM cfg.JobTriggerRequest r
WHERE r.RequestId = (SELECT TOP (1) q.RequestId FROM cfg.JobTriggerRequest q WITH (UPDLOCK, READPAST)
                     WHERE q.JobName = @Job AND q.Action = N'start-env' AND q.AppliedUtc IS NULL
                       AND q.RequestedUtc >= DATEADD(MINUTE, -@MaxAge, SYSUTCDATETIME())
                       AND (q.ExecutionName = @Exec OR (q.ExecutionName IS NULL AND q.Outcome = N'handed-back'))
                     ORDER BY CASE WHEN q.ExecutionName = @Exec THEN 0 ELSE 1 END, q.RequestId)
  AND r.AppliedUtc IS NULL
"@
}

function Get-SIJobStartRequestUnboundSql {
    # a row the web app wrote for this job in the last minutes and has not bound yet (its start is in flight)
    # #1292: or one the pipeline runner is starting right now ('runner-starting': taken, started, not yet bound)
    'SELECT COUNT(*) FROM cfg.JobTriggerRequest WHERE JobName = @Job AND Action = N''start-env'' AND AppliedUtc IS NULL AND ExecutionName IS NULL AND (Outcome IS NULL OR Outcome = N''runner-starting'') AND RequestedUtc >= DATEADD(MINUTE, -2, SYSUTCDATETIME())'
}

function Get-SIJobRunnerStartPendingSql {
    # #1292: one the runner took but never bound (it died between) or nobody started in time is closed; then the waiting ones
    "UPDATE cfg.JobTriggerRequest SET AppliedUtc = SYSUTCDATETIME(), Outcome = N'expired', Detail = N'the pipeline job did not start it within ' + CAST(@MaxAge AS nvarchar(10)) + N' minutes -- ask again' " +
    "WHERE Action = N'start-env' AND AppliedUtc IS NULL AND ExecutionName IS NULL AND Outcome IN (N'runner-start', N'runner-starting') AND RequestedUtc < DATEADD(MINUTE, -@MaxAge, SYSUTCDATETIME()); " +
    "SELECT TOP (5) RequestId, JobName, EnvJson, RequestedBy FROM cfg.JobTriggerRequest WHERE Action = N'start-env' AND AppliedUtc IS NULL AND ExecutionName IS NULL AND Outcome = N'runner-start' ORDER BY RequestId"
}

function Get-SIJobRunnerStartTakeSql {
    # one wake-up only: the row is taken before the start, so two wake-ups never start it twice
    "UPDATE cfg.JobTriggerRequest SET Outcome = N'runner-starting' OUTPUT inserted.RequestId WHERE RequestId = @Id AND Outcome = N'runner-start' AND AppliedUtc IS NULL AND ExecutionName IS NULL"
}

function Get-SIJobRunnerStartBindSql {
    # bound like the web app's own start: the job's claim (Get-SIJobStartRequestClaimSql) takes it by its execution name
    "UPDATE cfg.JobTriggerRequest SET ExecutionName = @Exec, Outcome = NULL, Detail = N'started by the pipeline job: ' + @Exec WHERE RequestId = @Id AND AppliedUtc IS NULL AND ExecutionName IS NULL"
}

function Get-SIJobRunnerStartCloseSql {
    "UPDATE cfg.JobTriggerRequest SET AppliedUtc = SYSUTCDATETIME(), Outcome = @Outcome, Detail = @Detail WHERE RequestId = @Id AND AppliedUtc IS NULL"
}

function Get-SIJobRunnerStartDecision {
    <#
        PURE. #1292: may the pipeline runner start request -Request (JobName, EnvJson) for a person? -Installed: the install's
        job names. Only a job in $script:SIJobRunnerStartAllowed, installed here, whose values are a JSON object carrying that
        job's required value. @{ Ok; Why }.
    #>
    param([Parameter(Mandatory)]$Request, [AllowEmptyCollection()][string[]]$Installed = @())
    $job = [string]$Request.JobName
    if (-not $script:SIJobRunnerStartAllowed.ContainsKey($job)) { return @{ Ok = $false; Why = ('{0} is not a job the pipeline starts for a person' -f $job) } }
    if (@($Installed) -notcontains $job) { return @{ Ok = $false; Why = ('{0} is not one of this install''s jobs' -f $job) } }
    $need = [string]$script:SIJobRunnerStartAllowed[$job]
    $o = $null; try { $o = ([string]$Request.EnvJson) | ConvertFrom-Json -ErrorAction Stop } catch { $o = $null }
    if ($null -eq $o -or $o -isnot [System.Management.Automation.PSCustomObject]) { return @{ Ok = $false; Why = 'the request''s values are not a JSON object' } }
    if (-not $o.PSObject.Properties[$need] -or -not ([string]$o.$need).Trim()) { return @{ Ok = $false; Why = ('the request does not carry {0}' -f $need) } }
    @{ Ok = $true; Why = '' }
}

function Invoke-SIJobRunnerStarts {
    <#
        #1292: starts the waiting person's requests the web app cannot start itself (SECURE-WEB-1). -Invoke: the Pro database
        seam (sql, params, mode). -Start { param($Job) } -> the execution name (a plain start, the runner's own identity).
        -Running { param($Job) } -> $true while an execution of that job runs (the request then waits for the next wake-up).
        -Installed: the install's job names. -Log { param($Level, $Message) }. NEVER THROWS; returns
        @{ RequestId; Job; Outcome = started | waiting | refused | failed | taken-elsewhere; Detail } per row.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][scriptblock]$Start, [scriptblock]$Running,
          [AllowEmptyCollection()][string[]]$Installed = @(), [scriptblock]$Log, [int]$MaxAgeMinutes = $script:SIJobRunnerStartMaxAgeMinutes)
    if (-not $Log) { $Log = { param($l, $m) } }
    $out = New-Object System.Collections.Generic.List[object]
    $rows = @()
    try { $rows = @(& $Invoke (Get-SIJobRunnerStartPendingSql) @{ MaxAge = $MaxAgeMinutes } 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
    catch { return @() }   # an older schema / no right: nothing waits here
    $close = { param($id, $outcome, $detail) try { $null = & $Invoke (Get-SIJobRunnerStartCloseSql) @{ Id = $id; Outcome = $outcome; Detail = $(if ($detail.Length -gt 1000) { $detail.Substring(0, 1000) } else { $detail }) } 'nonquery' } catch { & $Log 'WARN' ('start request {0}: the outcome could not be recorded ({1})' -f $id, $_.Exception.Message) } }
    foreach ($r in $rows) {
        $get = { param($n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } else { $r.$n } }
        $req = [pscustomobject]@{ RequestId = & $get 'RequestId'; JobName = [string](& $get 'JobName'); EnvJson = [string](& $get 'EnvJson'); RequestedBy = [string](& $get 'RequestedBy') }
        $d = Get-SIJobRunnerStartDecision -Request $req -Installed $Installed
        if (-not $d.Ok) {
            & $close $req.RequestId 'refused' $d.Why
            & $Log 'WARN' ('start request {0} by {1}: refused -- {2}' -f $req.RequestId, $req.RequestedBy, $d.Why)
            $out.Add([pscustomobject]@{ RequestId = $req.RequestId; Job = $req.JobName; Outcome = 'refused'; Detail = $d.Why }); continue
        }
        $busy = $false
        if ($Running) { try { $busy = [bool](& $Running $req.JobName) } catch { $busy = $true } }
        if ($busy) {
            & $Log 'INFO' ('start request {0} by {1}: {2} is running now -- it starts on a later wake-up' -f $req.RequestId, $req.RequestedBy, $req.JobName)
            $out.Add([pscustomobject]@{ RequestId = $req.RequestId; Job = $req.JobName; Outcome = 'waiting'; Detail = 'the job runs now' }); continue
        }
        $taken = @()
        try { $taken = @(& $Invoke (Get-SIJobRunnerStartTakeSql) @{ Id = $req.RequestId } 'reader' | Where-Object { $null -ne $_ }) } catch { $taken = @() }
        if (-not $taken.Count) { $out.Add([pscustomobject]@{ RequestId = $req.RequestId; Job = $req.JobName; Outcome = 'taken-elsewhere'; Detail = '' }); continue }
        $exec = ''
        try { $exec = [string](& $Start $req.JobName) } catch {
            $why = ('{0} could not be started: {1}' -f $req.JobName, (([string]$_.Exception.Message) -split "`n")[0])
            & $close $req.RequestId 'failed' $why
            & $Log 'WARN' ('start request {0} by {1}: failed -- {2}' -f $req.RequestId, $req.RequestedBy, $why)
            $out.Add([pscustomobject]@{ RequestId = $req.RequestId; Job = $req.JobName; Outcome = 'failed'; Detail = $why }); continue
        }
        # the job is starting: a bind that fails leaves the row 'runner-starting', which the job's claim never takes as its
        # values -- it runs as configured (outbox-only stays a bound-only value) and the row expires
        try { $null = & $Invoke (Get-SIJobRunnerStartBindSql) @{ Id = $req.RequestId; Exec = $exec } 'nonquery' }
        catch { & $Log 'WARN' ('start request {0}: started as {1}, but not bound ({2})' -f $req.RequestId, $exec, $_.Exception.Message) }
        & $Log 'INFO' ('start request {0} by {1}: {2} started for them (execution {3})' -f $req.RequestId, $req.RequestedBy, $req.JobName, $exec)
        $out.Add([pscustomobject]@{ RequestId = $req.RequestId; Job = $req.JobName; Outcome = 'started'; Detail = $exec })
    }
    $out.ToArray()
}

function Get-SIJobStartRequestReleaseSql {
    'UPDATE cfg.JobTriggerRequest SET AppliedUtc = NULL, Outcome = N''handed-back'', ExecutionName = NULL, Detail = N''handed back by execution '' + @Exec + N'' (it was skipped)'' WHERE RequestId = @Id AND ExecutionName = @Exec'
}

function ConvertFrom-SIJobStartRequestEnv {
    <#
        PURE. The values of a start request (-EnvJson, a JSON object of name -> value) that job -Job may set.
        -HandedBack: the request was handed back by a skipped execution (not bound to this one) -- the bound-only names
        ($script:SIJobStartRequestBoundOnly) are refused too.
        @{ Env = ordered name -> value; Dropped = names refused }.
    #>
    param([string]$EnvJson, [string]$Job, [switch]$HandedBack)
    $r = @{ Env = [ordered]@{}; Dropped = @() }
    if (-not ([string]$EnvJson).Trim()) { return $r }
    try { $o = $EnvJson | ConvertFrom-Json -ErrorAction Stop } catch { $r.Dropped = @('(the values are not valid JSON)'); return $r }
    if ($null -eq $o -or $o -isnot [System.Management.Automation.PSCustomObject]) { $r.Dropped = @('(the values are not a JSON object)'); return $r }
    $allowed = @(Get-SIJobStartRequestAllowed -Job $Job)
    if ($HandedBack) { $allowed = @($allowed | Where-Object { $script:SIJobStartRequestBoundOnly -cnotcontains $_ }) }
    foreach ($p in $o.PSObject.Properties) {
        $n = [string]$p.Name; $v = [string]$p.Value
        if ($allowed -ccontains $n -and $v.Length -le 1000) { $r.Env[$n] = $v } else { $r.Dropped += $n }
    }
    $r
}

function Invoke-SIJobStartRequestClaim {
    <#
        Claims this execution's start request and sets its allowed values in the process environment. -Invoke: the Pro
        database seam (sql, params, mode). @{ Claimed; RequestId; Names; Line }. Never throws.
    #>
    param([scriptblock]$Invoke, [string]$Job, [string]$Execution, [int]$MaxAgeMinutes = $script:SIJobStartRequestMaxAgeMinutes,
          [int]$BindWaitSeconds = $script:SIJobStartRequestBindWaitSeconds, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    $none = @{ Claimed = $false; RequestId = $null; Names = @(); Line = '' }
    if (-not $Invoke -or -not $Job -or -not $Execution) { return $none }
    $p = @{ Job = $Job; Exec = $Execution; MaxAge = $MaxAgeMinutes }
    $rows = @(); $waited = 0
    try {
        while ($true) {
            $rows = @(& $Invoke (Get-SIJobStartRequestClaimSql) $p 'reader' | Where-Object { $null -ne $_ })
            if ($rows.Count -or $waited -ge $BindWaitSeconds) { break }
            # nothing bound to this execution: wait only while a start of this job is in flight (written, not yet bound)
            $inFlight = 0; [void][int]::TryParse([string](& $Invoke (Get-SIJobStartRequestUnboundSql) @{ Job = $Job } 'scalar'), [ref]$inFlight)
            if ($inFlight -le 0) { break }
            & $Sleep 3; $waited += 3
        }
    } catch {
        # an older schema (no start-env yet) or no read right: the run goes on as configured
        $none.Line = ('[start-request] the start request could not be read ({0}) -- the run goes on as configured' -f (([string]$_.Exception.Message) -split "`n")[0])
        return $none
    }
    if (-not $rows.Count) { return $none }
    $row = $rows[0]
    $get = { param($n) if ($row -is [System.Collections.IDictionary]) { $row[$n] } else { $row.$n } }
    # bound to THIS execution (the web app bound it to the start it made) or handed back by a skipped one
    $handedBack = -not [string]::Equals([string](& $get 'BoundTo'), $Execution, [StringComparison]::Ordinal)
    $c = ConvertFrom-SIJobStartRequestEnv -EnvJson ([string](& $get 'EnvJson')) -Job $Job -HandedBack:$handedBack
    foreach ($k in $c.Env.Keys) { [Environment]::SetEnvironmentVariable($k, [string]$c.Env[$k]) }
    $line = '[start-request] started by {0}: {1}' -f [string](& $get 'RequestedBy'), $(if ($c.Env.Count) { (@($c.Env.Keys) -join ', ') } else { 'no values' })
    if (@($c.Dropped).Count) { $line += (' (not allowed for this job, not set: {0})' -f (@($c.Dropped) -join ', ')) }
    if ($handedBack -and @($c.Dropped | Where-Object { $script:SIJobStartRequestBoundOnly -ccontains $_ }).Count) {
        $line += ' -- the request was handed back by another execution: it never changes this run''s report, Log Analytics or mail'
    }
    @{ Claimed = $true; RequestId = (& $get 'RequestId'); Names = @($c.Env.Keys); Line = $line }
}

function Invoke-SIJobStartRequestRelease {
    <# Hands a claimed request back (the execution guard skipped the run), so the next execution takes it. Never throws. #>
    param([scriptblock]$Invoke, $RequestId, [string]$Execution)
    if (-not $Invoke -or $null -eq $RequestId -or -not $Execution) { return $false }
    try { $null = & $Invoke (Get-SIJobStartRequestReleaseSql) @{ Id = $RequestId; Exec = $Execution } 'nonquery'; $true } catch { $false }
}

function Invoke-SIJobStartRequestIsolated {
    <#
        What a container entrypoint calls, BEFORE its engine: the claim (-RequestId absent) or the hand-back (-RequestId) with
        the Pro database seam of SI-Guard.ps1 (-GuardPath), loaded INSIDE this call only. Live 3.0.5 (internal, 2026-10-28): the
        guard file, dot-sourced in the entrypoint's own scope, brought the telemetry code with it; the engine started after it
        then found those functions defined and did not load them, and they read their lists from the engine's scope, where they
        were never set -- the half-hourly status report stopped ("'pro' is not a valid Edition ()", no endpoint). Here
        nothing the guard file defines outlives the call, and the process-wide database seam it remembers is put back as it
        was, so the engine starts exactly as before. -Invoke: the database seam itself (tests); no guard file is loaded then.
        Claim: @{ Claimed; RequestId; Names; Line }. Hand-back: $true / $false. Never throws.
    #>
    param([string]$GuardPath, [string]$Job, [string]$Execution, $RequestId, [scriptblock]$Invoke, [scriptblock]$Sleep)
    $keep = @{}; foreach ($n in 'SI_GuardProInvoke', 'SI_GuardInvoke') { $keep[$n] = Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
    try {
        if (-not $Invoke) {
            if (-not (Get-Command -Name Get-SIGuardProInvoke -ErrorAction SilentlyContinue)) { . $GuardPath }
            $Invoke = Get-SIGuardProInvoke
        }
        if ($PSBoundParameters.ContainsKey('RequestId')) { return (Invoke-SIJobStartRequestRelease -Invoke $Invoke -RequestId $RequestId -Execution $Execution) }
        $a = @{ Invoke = $Invoke; Job = $Job; Execution = $Execution }; if ($Sleep) { $a.Sleep = $Sleep }
        return (Invoke-SIJobStartRequestClaim @a)
    } catch {
        if ($PSBoundParameters.ContainsKey('RequestId')) { return $false }
        return @{ Claimed = $false; RequestId = $null; Names = @(); Line = ('[start-request] the start request could not be read ({0}) -- the run goes on as configured' -f (([string]$_.Exception.Message) -split "`n")[0]) }
    } finally {
        foreach ($n in $keep.Keys) { Set-Variable -Name $n -Scope Global -Value $keep[$n] }
    }
}
