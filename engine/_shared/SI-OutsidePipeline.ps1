#Requires -Version 5.1
<#
    SecurityInsight -- RAN OUTSIDE THE PIPELINE (#1096, owner 2026-11-04). Found live: a collect producer kept its own daily
    timer beside the pipeline, so every install collected twice a day and the extra collection belonged to no run. The fix
    takes the producers off their timers; THIS check proves it stays that way, on every install, every day.

    THE RULE (read-only; warn-only, never blocking). While the jobs run as one pipeline, every execution of a pipeline step's
    job in the last -Hours (48) -- the step's own job caj-si-<key>, or the PRODUCER of a collection in parts (its workers
    count through their producer's run and are not read) -- must belong to
      * a pipeline run: its execution name is a step record of a run (cfg.FlowStepRun.Execution), or it started inside the
        window of that step's record in a run (an earlier attempt the runner started again, working rule 4); or
      * a person's start: cfg.JobTriggerRequest.ExecutionName (the web app's start with its own values, claimed by the job).
    Any other execution "ran outside the pipeline: <job> <execution> <start>". In schedules mode (every job on its own
    timer) nothing is checked. ARM or the database not read = said in one line, nothing concluded.

    SAID: one line per execution in the verification job's log, and cfg.InstallState 'OutsidePipeline' (at most 400
    characters: { checkedUtc, count, firstUtc, sample }) that the heartbeat turns into the warning si-flow-1205 (Warnings,
    an existing key of the heartbeat -- no new key on the wire).
    PS 5.1 and 7. No PowerShell module. Every reader is a seam.
#>

$script:SIOutsidePipeline = @{
    Hours          = 48
    # step records are read a day further back than the executions, so a run that began before the window still counts
    RecordHours    = 72
    # an attempt the runner started again starts at most this long before the step's record says it started
    AttemptSlackMinutes = 5
    StateName      = 'OutsidePipeline'
    ArmApi         = '2025-07-01'
    # the warning is said while the newest check found something and is at most this old
    WarnHours      = 30
}

function Get-SIOutsidePipelineSql {
    <# PURE. ONE read-only statement: how the jobs run (cfg.JobFlow), the step records of the runs started in the last
       @Hours, and the executions people started (cfg.JobTriggerRequest.ExecutionName). Rows: K (def | step | person), Job,
       Execution, StartedUtc, EndedUtc, Txt. Every table may be missing on an older schema -- then no rows of it. #>
@'
SET NOCOUNT ON;
DECLARE @r TABLE (K nvarchar(8) NOT NULL, Job nvarchar(128) NULL, Execution nvarchar(128) NULL, StartedUtc datetime2(0) NULL, EndedUtc datetime2(0) NULL, Txt nvarchar(max) NULL);
DECLARE @since datetime2(0) = DATEADD(HOUR, -@Hours, SYSUTCDATETIME());
IF OBJECT_ID(N'cfg.JobFlow') IS NOT NULL
    INSERT @r (K, Job, Txt) SELECT TOP (1) N'def', Mode, DefinitionJson FROM cfg.JobFlow WHERE FlowId = N'daily';
IF OBJECT_ID(N'cfg.FlowRun') IS NOT NULL AND OBJECT_ID(N'cfg.FlowStepRun') IS NOT NULL
    INSERT @r (K, Job, Execution, StartedUtc, EndedUtc)
    SELECT N'step', s.Job, s.Execution, s.StartedUtc, s.EndedUtc
    FROM cfg.FlowStepRun s JOIN cfg.FlowRun r ON r.FlowRunId = s.FlowRunId
    WHERE r.StartedUtc >= @since;
IF OBJECT_ID(N'cfg.JobTriggerRequest') IS NOT NULL AND COL_LENGTH(N'cfg.JobTriggerRequest', N'ExecutionName') IS NOT NULL
    EXEC sp_executesql N'SELECT N''person'' AS K, JobName AS Job, ExecutionName AS Execution, RequestedUtc AS StartedUtc, CAST(NULL AS datetime2(0)) AS EndedUtc, CAST(NULL AS nvarchar(max)) AS Txt
                         FROM cfg.JobTriggerRequest WHERE ExecutionName IS NOT NULL AND RequestedUtc >= @s;', N'@s datetime2(0)', @s = @since;
SELECT K, Job, Execution, StartedUtc, EndedUtc, Txt FROM @r;
'@
}

function Get-SIOutsidePipelineValue {
    param($Row, [string]$Name)
    if ($null -eq $Row) { return $null }
    $x = if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($Name)) { $Row[$Name] } else { $null } } elseif ($Row.PSObject.Properties[$Name]) { $Row.$Name } else { $null }
    if ($x -is [System.DBNull]) { $null } else { $x }
}

function Get-SIOutsidePipelineStepJobs {
    <#
        PURE. The jobs whose executions are a pipeline step's runs: for each step key, caj-si-<key> when it is installed, else
        the producer caj-si-<key>-producer (a collection in parts; its workers are not read). -Steps: step keys; -Installed:
        the install's job names. Returns @(@{ Key; Job }).
    #>
    param([AllowEmptyCollection()][string[]]$Steps = @(), [AllowEmptyCollection()][string[]]$Installed = @())
    $have = @($Installed | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
    @(foreach ($k in @($Steps | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() -replace '^caj-si-', '' } | Select-Object -Unique)) {
        $plain = 'caj-si-' + $k
        if ($have -contains $plain) { [pscustomobject]@{ Key = $k; Job = $plain } }
        elseif ($have -contains ($plain + '-producer')) { [pscustomobject]@{ Key = $k; Job = $plain + '-producer' } }
    })
}

function Get-SIOutsidePipelineExecutions {
    <#
        PURE. THE RULE (see the top of this file). -StepJobs: Get-SIOutsidePipelineStepJobs; -Executions: job name -> its
        executions (ARM shape: name, properties.startTime, properties.status); -StepRecords: @(@{ Job (key or name);
        Execution; StartedUtc; EndedUtc }); -PersonExecutions: execution names people started. Returns the executions that
        belong to neither, oldest first: @(@{ Job; Execution; StartUtc; Status; Line }).
    #>
    param([AllowEmptyCollection()][object[]]$StepJobs = @(), [System.Collections.IDictionary]$Executions = @{},
          [AllowEmptyCollection()][object[]]$StepRecords = @(), [AllowEmptyCollection()][string[]]$PersonExecutions = @(),
          [Parameter(Mandatory)][datetime]$NowUtc, [int]$Hours = $script:SIOutsidePipeline.Hours, [int]$SlackMinutes = $script:SIOutsidePipeline.AttemptSlackMinutes)
    $since = $NowUtc.ToUniversalTime().AddHours(-$Hours)
    $known = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @($StepRecords)) { $e = [string](Get-SIOutsidePipelineValue $r 'Execution'); if ($e) { [void]$known.Add($e) } }
    foreach ($p in @($PersonExecutions)) { if ("$p".Trim()) { [void]$known.Add("$p".Trim()) } }
    $keyOf = { param($j) $k = ([string]$j).Trim().ToLowerInvariant() -replace '^caj-si-', ''; if ($k -match '^(.+)-producer$') { $Matches[1] } else { $k } }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($sj in @($StepJobs | Where-Object { $_ })) {
        $windows = @(@($StepRecords) | Where-Object { (& $keyOf (Get-SIOutsidePipelineValue $_ 'Job')) -eq [string]$sj.Key -and $null -ne (Get-SIOutsidePipelineValue $_ 'StartedUtc') } | ForEach-Object {
            $a = ([datetime](Get-SIOutsidePipelineValue $_ 'StartedUtc')).ToUniversalTime().AddMinutes(-$SlackMinutes)
            $b = Get-SIOutsidePipelineValue $_ 'EndedUtc'; $b = if ($null -ne $b) { ([datetime]$b).ToUniversalTime() } else { $NowUtc.ToUniversalTime() }
            [pscustomobject]@{ From = $a; To = $b } })
        foreach ($x in @($Executions[[string]$sj.Job])) {
            if (-not $x) { continue }
            $name = [string]$x.name
            $p = if ($x.PSObject.Properties['properties']) { $x.properties } else { $x }
            if (-not $name -or -not $p.startTime) { continue }
            $st = ([datetime]$p.startTime).ToUniversalTime()
            if ($st -lt $since) { continue }
            if ($known.Contains($name)) { continue }
            if (@($windows | Where-Object { $st -ge $_.From -and $st -le $_.To }).Count) { continue }
            $out.Add([pscustomobject]@{ Job = [string]$sj.Job; Execution = $name; StartUtc = $st; Status = [string]$p.status
                                        Line = ('ran outside the pipeline: {0} {1} {2:yyyy-MM-ddTHH:mm:ssZ}' -f $sj.Job, $name, $st) })
        }
    }
    @($out.ToArray() | Sort-Object StartUtc)
}

function ConvertTo-SIOutsidePipelineState {
    <# PURE. The cfg.InstallState 'OutsidePipeline' value (JSON, at most 400 characters): checkedUtc, count, firstUtc and a
       sample of the first execution(s) ('<job> <execution> <start>', cut to fit). #>
    param([AllowEmptyCollection()][object[]]$Items = @(), [Parameter(Mandatory)][datetime]$CheckedUtc)
    $fmt = { param($d) ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    $list = @($Items | Where-Object { $_ })
    $o = [ordered]@{ checkedUtc = (& $fmt $CheckedUtc); count = $list.Count; firstUtc = $(if ($list.Count) { & $fmt $list[0].StartUtc } else { $null }); sample = '' }
    $sample = ''
    foreach ($i in $list) {
        $s = '{0} {1} {2}' -f ([string]$i.Job -replace '^caj-si-', ''), $i.Execution, (& $fmt $i.StartUtc)
        $try = if ($sample) { $sample + '; ' + $s } else { $s }
        $o.sample = $try
        if ((ConvertTo-Json -Compress -InputObject $o).Length -gt 400) { break }
        $sample = $try
    }
    $o.sample = $sample
    $j = ConvertTo-Json -Compress -InputObject $o
    while ($j.Length -gt 400 -and $o.sample.Length -gt 0) { $o.sample = $o.sample.Substring(0, [Math]::Max(0, $o.sample.Length - 20)); $j = ConvertTo-Json -Compress -InputObject $o }
    $j
}

function Invoke-SIOutsidePipelineCheck {
    <#
        THE CHECK (warn-only, never blocking, NEVER THROWS). -Invoke: the Pro settings database's (sql, params, mode) seam;
        -Arm { param($Method, $Path, $Body) } -> the parsed answer (GET a list of jobs / a job's executions); -Base: the jobs'
        ARM path '/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.App/jobs'; -Log { param($Level, $Message) };
        -Now; -Save { param($Value) } (default: cfg.InstallState 'OutsidePipeline' through -Invoke); -DryRun: nothing stored.
        Returns @{ State = ok | found | schedules-mode | not-checked; Items; Lines; Mode }.
    #>
    param([scriptblock]$Invoke, [scriptblock]$Arm, [string]$Base = '', [scriptblock]$Log = { param($l, $m) Write-Host $m },
          [scriptblock]$Now = { [datetime]::UtcNow }, [scriptblock]$Save, [switch]$DryRun, $Map, [int]$Hours = $script:SIOutsidePipeline.Hours)
    $lines = New-Object System.Collections.Generic.List[string]
    $say = { param($l, $m) $lines.Add($m); try { & $Log $l $m } catch { } }
    $res = { param($s, $items, $mode) [pscustomobject]@{ State = $s; Items = @($items); Lines = $lines.ToArray(); Mode = [string]$mode } }
    try {
        if (-not $Invoke) { & $say 'INFO' 'pipeline check: no Pro database -- not checked'; return (& $res 'not-checked' @() '') }
        if (-not $Arm -or -not $Base) { & $say 'WARN' 'pipeline check: where the jobs are is not known (SI_JOBS_SUBSCRIPTIONID / SI_JOBS_RESOURCEGROUP) -- not checked'; return (& $res 'not-checked' @() '') }
        $nowUtc = ([datetime](& $Now)).ToUniversalTime()
        # the install's jobs (every page)
        $jobs = New-Object System.Collections.Generic.List[object]
        try {
            $p = $Base; $pg = 0
            while ($p -and $pg -lt 50) { $r = & $Arm 'GET' $p $null; $pg++; foreach ($v in @($r.value)) { if ($v) { $jobs.Add($v) } }; $p = if ($r -and $r.PSObject.Properties['nextLink'] -and $r.nextLink) { [string]$r.nextLink } else { $null } }
        } catch { & $say 'WARN' ('pipeline check: the jobs could not be read from Azure ({0}) -- not checked; the next check tries again' -f $_.Exception.Message); return (& $res 'not-checked' @() '') }
        $names = @($jobs | ForEach-Object { [string]$_.name } | Where-Object { $_ -like 'caj-si-*' })
        # the database: how the jobs run, the step records, the people's starts
        $rows = @()
        try { $rows = @(& $Invoke (Get-SIOutsidePipelineSql) ([ordered]@{ Hours = [int]$script:SIOutsidePipeline.RecordHours }) 'reader' | ForEach-Object { $_ } | Where-Object { $_ }) }
        catch { & $say 'WARN' ('pipeline check: the pipeline''s records could not be read ({0}) -- not checked; the next check tries again' -f $_.Exception.Message); return (& $res 'not-checked' @() '') }
        $def = @($rows | Where-Object { [string](Get-SIOutsidePipelineValue $_ 'K') -eq 'def' })[0]
        $flowJob = @($jobs | Where-Object { [string]$_.name -eq 'caj-si-flow' })[0]
        $mode = ([string](Get-SIOutsidePipelineValue $def 'Job')).ToLowerInvariant()
        if ($mode -notin @('flow', 'schedules')) { $mode = if ($flowJob -and [string]$flowJob.properties.configuration.triggerType -eq 'Schedule') { 'flow' } else { 'schedules' } }
        if ($mode -ne 'flow') { & $say 'INFO' 'pipeline check: the jobs run on their own timers -- nothing to check'; return (& $res 'schedules-mode' @() $mode) }
        # the steps: the stored pipeline, else the default over the installed jobs (a collection in parts is its engine's step)
        $steps = @()
        $json = [string](Get-SIOutsidePipelineValue $def 'Txt')
        if ($json.Trim()) { $d = $json | ConvertFrom-Json; $steps = @(@(@($d.steps) + @(@($d.stages) | ForEach-Object { @($_.steps) })) | Where-Object { $_ } | ForEach-Object { [string]$_.job }) }
        else {
            if (-not (Get-Command -Name New-SIDefaultJobFlow -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine($PSScriptRoot, 'SI-JobFlow.ps1')) }
            $installedKeys = @($names | ForEach-Object { Get-SIJobFlowStepKey $_ } | Select-Object -Unique)
            $steps = @(@((New-SIDefaultJobFlow -Installed $installedKeys -Map $Map).Steps) | ForEach-Object { [string]$_.Job })
        }
        $stepJobs = @(Get-SIOutsidePipelineStepJobs -Steps $steps -Installed $names)
        $execs = @{}; $unread = New-Object System.Collections.Generic.List[string]
        foreach ($sj in $stepJobs) {
            try { $r = & $Arm 'GET' ('{0}/{1}/executions' -f $Base, $sj.Job) $null; $execs[[string]$sj.Job] = @($r.value) }
            catch { $unread.Add(('{0} ({1})' -f $sj.Job, $_.Exception.Message)) }
        }
        if ($unread.Count) { & $say 'WARN' ('pipeline check: the executions of {0} could not be read -- those jobs are not checked' -f ($unread -join ', ')) }
        $records = @($rows | Where-Object { [string](Get-SIOutsidePipelineValue $_ 'K') -eq 'step' })
        $people = @($rows | Where-Object { [string](Get-SIOutsidePipelineValue $_ 'K') -eq 'person' } | ForEach-Object { [string](Get-SIOutsidePipelineValue $_ 'Execution') })
        $found = @(Get-SIOutsidePipelineExecutions -StepJobs $stepJobs -Executions $execs -StepRecords $records -PersonExecutions $people -NowUtc $nowUtc -Hours $Hours)
        foreach ($f in $found) { & $say 'WARN' $f.Line }
        if (-not $found.Count) { & $say 'INFO' ('pipeline check: every execution of the {0} pipeline step job(s) in the last {1} h belongs to a pipeline run or to a person''s start' -f ($stepJobs.Count - $unread.Count), $Hours) }
        if (-not $DryRun -and $unread.Count -lt [Math]::Max(1, $stepJobs.Count)) {
            $value = ConvertTo-SIOutsidePipelineState -Items $found -CheckedUtc $nowUtc
            try {
                if ($Save) { & $Save $value }
                else {
                    $sql = "SET NOCOUNT ON; IF OBJECT_ID(N'cfg.InstallState') IS NULL RETURN; UPDATE cfg.InstallState SET Value = @Value, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = @Name; IF @@ROWCOUNT = 0 INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (@Name, @Value, @By);"
                    $null = & $Invoke $sql ([ordered]@{ Name = [string]$script:SIOutsidePipeline.StateName; Value = $value; By = 'verification' }) 'nonquery'
                }
            } catch { & $say 'WARN' ('pipeline check: the result could not be stored ({0}) -- the heartbeat does not show it this time' -f $_.Exception.Message) }
        }
        & $res $(if ($found.Count) { 'found' } else { 'ok' }) $found $mode
    } catch {
        & $say 'WARN' ('pipeline check: not checked ({0}) -- the next check tries again' -f $_.Exception.Message)
        & $res 'not-checked' @() ''
    }
}
