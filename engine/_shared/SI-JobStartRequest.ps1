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
OUTPUT inserted.RequestId, inserted.EnvJson, inserted.RequestedBy
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
    'SELECT COUNT(*) FROM cfg.JobTriggerRequest WHERE JobName = @Job AND Action = N''start-env'' AND AppliedUtc IS NULL AND ExecutionName IS NULL AND Outcome IS NULL AND RequestedUtc >= DATEADD(MINUTE, -2, SYSUTCDATETIME())'
}

function Get-SIJobStartRequestReleaseSql {
    'UPDATE cfg.JobTriggerRequest SET AppliedUtc = NULL, Outcome = N''handed-back'', ExecutionName = NULL, Detail = N''handed back by execution '' + @Exec + N'' (it was skipped)'' WHERE RequestId = @Id AND ExecutionName = @Exec'
}

function ConvertFrom-SIJobStartRequestEnv {
    <#
        PURE. The values of a start request (-EnvJson, a JSON object of name -> value) that job -Job may set.
        @{ Env = ordered name -> value; Dropped = names refused }.
    #>
    param([string]$EnvJson, [string]$Job)
    $r = @{ Env = [ordered]@{}; Dropped = @() }
    if (-not ([string]$EnvJson).Trim()) { return $r }
    try { $o = $EnvJson | ConvertFrom-Json -ErrorAction Stop } catch { $r.Dropped = @('(the values are not valid JSON)'); return $r }
    if ($null -eq $o -or $o -isnot [System.Management.Automation.PSCustomObject]) { $r.Dropped = @('(the values are not a JSON object)'); return $r }
    $allowed = @(Get-SIJobStartRequestAllowed -Job $Job)
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
    $c = ConvertFrom-SIJobStartRequestEnv -EnvJson ([string](& $get 'EnvJson')) -Job $Job
    foreach ($k in $c.Env.Keys) { [Environment]::SetEnvironmentVariable($k, [string]$c.Env[$k]) }
    $line = '[start-request] started by {0}: {1}' -f [string](& $get 'RequestedBy'), $(if ($c.Env.Count) { (@($c.Env.Keys) -join ', ') } else { 'no values' })
    if (@($c.Dropped).Count) { $line += (' (not allowed for this job, not set: {0})' -f (@($c.Dropped) -join ', ')) }
    @{ Claimed = $true; RequestId = (& $get 'RequestId'); Names = @($c.Env.Keys); Line = $line }
}

function Invoke-SIJobStartRequestRelease {
    <# Hands a claimed request back (the execution guard skipped the run), so the next execution takes it. Never throws. #>
    param([scriptblock]$Invoke, $RequestId, [string]$Execution)
    if (-not $Invoke -or $null -eq $RequestId -or -not $Execution) { return $false }
    try { $null = & $Invoke (Get-SIJobStartRequestReleaseSql) @{ Id = $RequestId; Exec = $Execution } 'nonquery'; $true } catch { $false }
}
