#Requires -Version 5.1
<#
    SecurityInsight -- the job trigger requests (CR8, framework DOCS/REQUIREMENTS.md 12.11f item 1; SI #659).

    The web app with START-ONLY rights on the jobs (Jobs:ChangeMode = request) never changes a job: Disable / Enable /
    Change schedule and the pipeline's include / remove / switch write a row in cfg.JobTriggerRequest. The pipeline runner
    (caj-si-flow, as its own identity -- which already changes jobs: it starts them and raises a run limit) applies the
    waiting rows at the start of every wake-up, oldest first:
      * only a job of THIS install (in the runner's own resource group, named caj-si-*) -- anything else is REFUSED;
      * only the trigger and the tags (ConvertTo-SIArmJobTrigger: the same PATCH body as the web app's direct change --
        never the image, the command, the environment or the secrets);
      * READ BACK: the job's trigger after the change must be what was asked, else the row says failed;
      * a row older than a day is EXPIRED, never applied late;
      * every row gets AppliedUtc + Outcome (applied | failed | refused | expired) + Detail -- one line in the run's log each.
      * a start-env row (#931, a job start's own values) is not a trigger change: the job itself takes it
        (SI-JobStartRequest.ps1), so this pass never reads it.
    NEVER THROWS: a request that fails is recorded and the pipeline runs on. PS 5.1 safe.
#>

$script:SIJobTriggerMaxAgeHours = 24

function Get-SIJobTriggerPendingSql {
    # #931: a start request (start-env) is never applied here; one no execution took within the day is closed as expired
    'UPDATE cfg.JobTriggerRequest SET AppliedUtc = SYSUTCDATETIME(), Outcome = N''expired'', Detail = N''no execution of the job took it'' WHERE Action = N''start-env'' AND AppliedUtc IS NULL AND RequestedUtc < DATEADD(HOUR, -24, SYSUTCDATETIME()); ' +
    'SELECT TOP (50) RequestId, JobName, Action, Cron, RequestedBy, RequestedUtc, DATEDIFF(MINUTE, RequestedUtc, SYSUTCDATETIME()) AS AgeMinutes FROM cfg.JobTriggerRequest WHERE AppliedUtc IS NULL AND Action <> N''start-env'' ORDER BY RequestId'
}

function Get-SIJobTriggerRecordSql {
    'UPDATE cfg.JobTriggerRequest SET AppliedUtc = SYSUTCDATETIME(), Outcome = @Outcome, Detail = @Detail WHERE RequestId = @Id AND AppliedUtc IS NULL'
}

function Get-SIJobTriggerDecision {
    <#
        PURE. Is request -Request (RequestId, JobName, Action, Cron, AgeMinutes) one this runner may apply? -Installed: the
        install's job names (ARM, the runner's resource group). @{ Ok; Outcome = '' | refused | expired; Why }.
    #>
    param([Parameter(Mandatory)]$Request, [AllowEmptyCollection()][string[]]$Installed = @(), [int]$MaxAgeHours = $script:SIJobTriggerMaxAgeHours)
    $job = [string]$Request.JobName; $act = [string]$Request.Action; $cron = [string]$Request.Cron
    $age = 0; [void][int]::TryParse([string]$Request.AgeMinutes, [ref]$age)
    if ($age -gt ($MaxAgeHours * 60)) { return @{ Ok = $false; Outcome = 'expired'; Why = ('asked {0} h ago -- older than {1} h, not applied late; ask again on Operations > Jobs' -f [Math]::Floor($age / 60), $MaxAgeHours) } }
    if ($job -notmatch '^caj-si-[a-z0-9\-]{1,56}$') { return @{ Ok = $false; Outcome = 'refused'; Why = ('{0} is not a SecurityInsight job name' -f $job) } }
    if (@($Installed) -notcontains $job) { return @{ Ok = $false; Outcome = 'refused'; Why = ('{0} is not one of this install''s jobs' -f $job) } }
    if ($act -notin 'to-manual', 'to-schedule') { return @{ Ok = $false; Outcome = 'refused'; Why = ('{0} is not a trigger change' -f $act) } }
    if ($cron -and $cron -notmatch '^[0-9*/,\-]{1,40}( [0-9*/,\-]{1,40}){4}$') { return @{ Ok = $false; Outcome = 'refused'; Why = ('''{0}'' is not a 5-field cron expression' -f $cron) } }
    @{ Ok = $true; Outcome = ''; Why = '' }
}

function Test-SIJobTriggerReadBack {
    <# PURE. Does the job (ARM, after the change) carry the trigger -Action asked for (and -Cron when given)? #>
    param($Job, [Parameter(Mandatory)][string]$Action, [string]$Cron)
    $cfg = if ($Job -and $Job.PSObject.Properties['properties'] -and $Job.properties -and $Job.properties.PSObject.Properties['configuration']) { $Job.properties.configuration } else { $null }
    if (-not $cfg) { return $false }
    if ($Action -eq 'to-manual') { return ([string]$cfg.triggerType -eq 'Manual') }
    if ([string]$cfg.triggerType -ne 'Schedule') { return $false }
    if (-not $Cron) { return $true }
    $now = if ($cfg.PSObject.Properties['scheduleTriggerConfig'] -and $cfg.scheduleTriggerConfig) { [string]$cfg.scheduleTriggerConfig.cronExpression } else { '' }
    ($now -replace '\s+', ' ').Trim() -eq ($Cron -replace '\s+', ' ').Trim()
}

function Invoke-SIJobTriggerRequests {
    <#
        Applies the waiting trigger requests. -Invoke: the Pro database seam (sql, params, mode). -Arm: { param($Method, $Path,
        $Body) } -> the parsed answer ($Path relative to -Base). -Base: '/subscriptions/<sub>/resourceGroups/<rg>/providers/
        Microsoft.App/jobs'. -Installed: the install's job names. -Log { param($Level, $Message) }. NEVER THROWS; returns the
        results (@{ RequestId; Job; Outcome; Detail }).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Base,
          [AllowEmptyCollection()][string[]]$Installed = @(), [scriptblock]$Log, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    if (-not $Log) { $Log = { param($l, $m) } }
    $out = New-Object System.Collections.Generic.List[object]
    $rows = @()
    try { $rows = @(& $Invoke (Get-SIJobTriggerPendingSql) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) }
    catch {
        # a database without the table (the schema not yet applied) or without the right: nothing to do, said once
        & $Log 'INFO' ('job trigger requests: not read ({0})' -f (([string]$_.Exception.Message) -split "`n")[0])
        return @()
    }
    foreach ($r in $rows) {
        $get = { param($n) if ($r -is [System.Collections.IDictionary]) { $r[$n] } else { $r.$n } }
        $req = [pscustomobject]@{ RequestId = & $get 'RequestId'; JobName = [string](& $get 'JobName'); Action = [string](& $get 'Action'); Cron = [string](& $get 'Cron')
                                  RequestedBy = [string](& $get 'RequestedBy'); AgeMinutes = & $get 'AgeMinutes' }
        $d = Get-SIJobTriggerDecision -Request $req -Installed $Installed
        $outcome = $d.Outcome; $detail = $d.Why
        if ($d.Ok) {
            try {
                $path = '{0}/{1}' -f $Base.TrimEnd('/'), $req.JobName
                $job = & $Arm 'GET' $path $null
                if (-not $job) { throw ('{0} was not found' -f $req.JobName) }
                $body = ConvertTo-SIArmJobTrigger -Job $job -Action $req.Action -Cron $req.Cron
                $null = & $Arm 'PATCH' $path $body
                $ok = $false; $back = $null
                for ($i = 1; $i -le 6 -and -not $ok; $i++) {
                    $back = & $Arm 'GET' $path $null
                    $ok = Test-SIJobTriggerReadBack -Job $back -Action $req.Action -Cron $req.Cron
                    if (-not $ok -and $i -lt 6) { & $Sleep 5 }
                }
                $trig = if ($back -and $back.properties -and $back.properties.configuration) { [string]$back.properties.configuration.triggerType } else { '?' }
                if ($ok) { $outcome = 'applied'; $detail = ('{0} {1}{2} (read back: {3})' -f $req.JobName, $req.Action, $(if ($req.Cron) { ' ' + $req.Cron } else { '' }), $trig) }
                else { $outcome = 'failed'; $detail = ('{0}: the change did not read back (trigger {1})' -f $req.JobName, $trig) }
            } catch { $outcome = 'failed'; $detail = ('{0}: {1}' -f $req.JobName, (([string]$_.Exception.Message) -split "`n")[0]) }
        }
        if ($detail.Length -gt 1000) { $detail = $detail.Substring(0, 1000) }
        try { $null = & $Invoke (Get-SIJobTriggerRecordSql) @{ Outcome = $outcome; Detail = $detail; Id = $req.RequestId } 'nonquery' }
        catch { & $Log 'WARN' ('job trigger request {0}: the outcome could not be recorded ({1})' -f $req.RequestId, $_.Exception.Message) }
        & $Log $(if ($outcome -eq 'applied') { 'INFO' } else { 'WARN' }) ('job trigger request {0} by {1}: {2} -- {3}' -f $req.RequestId, $req.RequestedBy, $outcome, $detail)
        $out.Add([pscustomobject]@{ RequestId = $req.RequestId; Job = $req.JobName; Outcome = $outcome; Detail = $detail })
    }
    $out.ToArray()
}
