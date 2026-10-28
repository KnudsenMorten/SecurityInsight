#Requires -Version 5.1
<#
    #882 (C1) A STEP THE PIPELINE ENDS LEAVES NOTHING RUNNING FOR IT (live 2026-10-22, internal: the Detailed Risk Analysis
    step was closed Interrupted at 09:40Z and its queue worker went on querying until 10:30, writing state the next run used).
    What these tests keep true (engine/_shared/SI-JobFlow.ps1, SI-Pipeline.ps1, SI-CollectParts.ps1,
    engine/flow/Invoke-SIJobFlowRun.ps1):
      * which worker jobs work for a step (Get-SIJobFlowWorkerJobs);
      * the step's queue run is closed by the PRODUCER'S OWN execution, never every run (Close-SICollectRunsOf);
      * every path that ends a step without success, cancels it, or closes it Interrupted stops its workers;
      * a success stops nothing; and THE LIVE RUN'S WORK IS NEVER STOPPED (Get-SIJobFlowEndedStepStops).
    Offline; PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-JobFlow.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-CollectParts.ps1'))
    $script:Map = Get-SIJobFlowMap
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-10-22T08:00:00', 'Utc')
    $script:LogSb = { param($l, $m) }
    function script:New-MemStore {
        $d = @{}
        [pscustomobject]@{
            Data  = $d
            Read  = { param($Path) if ($d.ContainsKey($Path)) { $d[$Path] } else { $null } }.GetNewClosure()
            Write = { param($Path, $Text) $d[$Path] = [string]$Text }.GetNewClosure()
            List  = { param($Prefix) @($d.Keys | Where-Object { ([string]$_).StartsWith($Prefix) }) }.GetNewClosure()
        }
    }
    function script:Add-Manifest($Store, [string]$Engine, [string]$RunId, [string]$Exec, [datetime]$Written) {
        & $Store.Write ('collect/{0}/{1}/manifest.json' -f $Engine, $RunId) (ConvertTo-Json -Compress -InputObject ([ordered]@{ Engine = $Engine; RunId = $RunId; ProducerExecution = $Exec; WrittenUtc = $Written.ToString('o') }))
    }
    function script:New-Fake {
        param([hashtable]$Outcome = @{}, [int]$Polls = 1)
        $script:Arm = @{ Outcome = $Outcome; Starts = (New-Object System.Collections.Generic.List[string]); Stops = (New-Object System.Collections.Generic.List[string]); Exec = @{}; Polls = $Polls }
        return {
            param($Method, $Path, $Body)
            if ($Method -eq 'POST' -and $Path -match '/jobs/caj-si-([a-z0-9\-]+)/start$') {
                $k = $Matches[1]; $name = '{0}-x{1}' -f $k, ($script:Arm.Starts.Count + 1); $script:Arm.Starts.Add($k)
                $script:Arm.Exec[$name] = @{ Left = $script:Arm.Polls; End = $(if ($script:Arm.Outcome.ContainsKey($k)) { $script:Arm.Outcome[$k] } else { 'Succeeded' }) }
                return [pscustomobject]@{ name = $name }
            }
            if ($Method -eq 'GET' -and $Path -match '/executions/([a-z0-9\-]+)$') {
                $e = $script:Arm.Exec[$Matches[1]]
                if ($e.Left -gt 0) { $e.Left--; return [pscustomobject]@{ properties = [pscustomobject]@{ status = 'Running' } } }
                return [pscustomobject]@{ properties = [pscustomobject]@{ status = $e.End } }
            }
            if ($Method -eq 'POST' -and $Path -match '/jobs/(caj-si-[a-z0-9\-]+)/stop/([a-z0-9\-]+)$') { $script:Arm.Stops.Add(('{0} {1}' -f $Matches[1], $Matches[2])); return $null }
            if ($Method -eq 'GET' -and $Path -match '/jobs/caj-si-[a-z0-9\-]+$') { return [pscustomobject]@{ properties = [pscustomobject]@{ configuration = [pscustomobject]@{ replicaTimeout = 0 } } } }
            if ($Method -eq 'GET' -and $Path -match '/executions$') { return [pscustomobject]@{ value = @() } }
            throw "unexpected ARM call $Method $Path"
        }
    }
    function script:Step([string]$Job, [string]$State, [string]$Exec, $Started) {
        [pscustomobject]@{ Order = 1; Group = 1; Job = $Job; Stage = 'correlate'; State = $State; Execution = $Exec; StartedUtc = $Started; EndedUtc = $null; ErrorClass = ''; Error = ''; Attempts = 1; RetryReason = '' }
    }
}

Describe 'the worker jobs of a step (Get-SIJobFlowWorkerJobs)' {
    It 'Detailed Risk Analysis: its queue worker job and its runs folder; Summary: its own; a collection in parts: its worker' {
        $w = @(Get-SIJobFlowWorkerJobs -Job 'risk-analysis-detailed' -Installed @('caj-si-risk-analysis-detailed', 'caj-si-raworker-detailed'))
        @($w | Where-Object { $_.Job -eq 'caj-si-raworker-detailed' -and $_.RunsFolder -eq 'ra-detailed' }).Count | Should -Be 1
        @($w | Where-Object { $_.Job -eq 'caj-si-risk-analysis-detailed-worker' }).Count | Should -Be 0 -Because 'a worker job that is not installed is not returned'
        @(Get-SIJobFlowWorkerJobs -Job 'caj-si-risk-analysis' -Installed @('caj-si-raworker-summary'))[0].RunsFolder | Should -Be 'ra-summary'
        @(Get-SIJobFlowWorkerJobs -Job 'endpoint' -Installed @('caj-si-endpoint-producer', 'caj-si-endpoint-worker')).Job | Should -Be @('caj-si-endpoint-worker')
    }
    It 'the queue runs are closed even when no worker job exists (a worker inside the producer reads the same mark)' {
        $w = @(Get-SIJobFlowWorkerJobs -Job 'risk-analysis-detailed' -Installed @('caj-si-risk-analysis-detailed'))
        $w.Count | Should -Be 1
        $w[0].Job | Should -Be ''
        $w[0].RunsFolder | Should -Be 'ra-detailed'
    }
}

Describe 'the step''s queue run is closed -- only the step''s own (Close-SICollectRunsOf)' {
    It 'by the producer''s execution: exactly that run; another producer''s run and an already-closed run are left' {
        $s = New-MemStore
        Add-Manifest $s 'ra-detailed' 'ct-1' 'caj-si-risk-analysis-detailed-aaa' $script:T0
        Add-Manifest $s 'ra-detailed' 'ct-2' 'caj-si-risk-analysis-detailed-bbb' $script:T0.AddHours(1)   # the LIVE run
        Add-Manifest $s 'ra-detailed' 'ct-3' 'caj-si-risk-analysis-detailed-aaa' $script:T0
        & $s.Write 'collect/ra-detailed/ct-3/closed.json' '{"Why":"earlier"}'
        $r = Close-SICollectRunsOf -Store $s -Engine 'ra-detailed' -ProducerExecution 'caj-si-risk-analysis-detailed-aaa'
        @($r.Closed) | Should -Be @('ct-1')
        $s.Data.ContainsKey('collect/ra-detailed/ct-2/closed.json') | Should -BeFalse -Because 'the live run''s queue run is never closed'
        $s.Data['collect/ra-detailed/ct-3/closed.json'] | Should -Be '{"Why":"earlier"}'
        $r.Why | Should -Be ''
    }
    It 'without the execution: the runs written since the step started (5 minutes slack) -- an older run is left' {
        $s = New-MemStore
        Add-Manifest $s 'ra-detailed' 'ct-old' 'x' $script:T0.AddHours(-3)
        Add-Manifest $s 'ra-detailed' 'ct-new' '' $script:T0.AddMinutes(-2)
        @((Close-SICollectRunsOf -Store $s -Engine 'ra-detailed' -SinceUtc $script:T0).Closed) | Should -Be @('ct-new')
    }
    It 'with neither: nothing is closed (never every run), and a store that fails is said, never thrown' {
        $s = New-MemStore
        Add-Manifest $s 'ra-detailed' 'ct-1' 'x' $script:T0
        $r = Close-SICollectRunsOf -Store $s -Engine 'ra-detailed'
        @($r.Closed).Count | Should -Be 0
        $r.Why | Should -Match 'no run is closed'
        $bad = [pscustomobject]@{ List = { param($p) throw 'storage down' }; Read = { param($p) $null }; Write = { param($p, $t) } }
        (Close-SICollectRunsOf -Store $bad -Engine 'ra-detailed' -ProducerExecution 'x').Why | Should -Match 'storage down'
    }
}

Describe 'every path that ends a step stops its workers' {
    It 'a step that ends FAILED: its workers are stopped, with its start and its execution' {
        $def = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map -StartTime '01:00' -TimeZone 'UTC'
        $script:Clock = $script:T0
        $seams = New-SIJobFlowArmSeams -SubscriptionId 's' -ResourceGroup 'r' -Arm (New-Fake -Outcome @{ identity = 'Failed' })
        $script:W = New-Object System.Collections.Generic.List[string]
        $sw = { param($j, $s, $e) $script:W.Add(('{0}|{1}|{2:o}' -f $j, $e, $s)) }
        $r = Invoke-SIJobFlow -Definition $def -Seams $seams -Save { param($s) } -Now { $script:Clock } -Sleep { param($s) $script:Clock = $script:Clock.AddSeconds($s) } -Log $script:LogSb -Map $script:Map -PollSeconds 30 -Previous $null -Force -StopWorkers $sw
        @($r.Steps | Where-Object { $_.Job -eq 'identity' })[0].State | Should -Be 'Failed'
        @($script:W | Where-Object { $_ -like 'identity|identity-x*' }).Count | Should -Be 1
        @($script:W | Where-Object { $_ -like 'ptc|*' }).Count | Should -Be 0 -Because 'a step that succeeded stops nothing'
    }
    It 'a run cancelled while a step runs: the step''s execution AND its workers are stopped (Set-SIPipelineRunCancelled)' {
        $st = [pscustomobject]@{ FlowRunId = 'r1'; State = 'Running'; StopReason = ''; EndedUtc = $null; CancelledBy = ''; Steps = @((Step 'risk-analysis-detailed' 'Running' 'ra-x1' $script:T0), (Step 'asset-datasync' 'Waiting' '' $null)) }
        $script:S = New-Object System.Collections.Generic.List[string]; $script:W = New-Object System.Collections.Generic.List[string]
        $res = Set-SIPipelineRunCancelled -State $st -By 'ann' -Reason 'hang' -NowUtc $script:T0.AddHours(2) -Stop { param($j, $e) $script:S.Add($e) } -StopWorkers { param($j, $s, $e) $script:W.Add(('{0}|{1}' -f $j, $e)) }
        @($script:S) | Should -Be @('ra-x1')
        @($script:W) | Should -Be @('risk-analysis-detailed|ra-x1')
        @($res.StopFailed).Count | Should -Be 0
    }
    It 'a worker stop that fails is said on the cancel, never stops it' {
        $st = [pscustomobject]@{ FlowRunId = 'r1'; State = 'Running'; StopReason = ''; EndedUtc = $null; CancelledBy = ''; Steps = @((Step 'risk-analysis-detailed' 'Running' 'ra-x1' $script:T0)) }
        $res = Set-SIPipelineRunCancelled -State $st -By 'ann' -Reason 'hang' -Stop { param($j, $e) } -StopWorkers { param($j, $s, $e) throw 'arm refused' }
        $st.State | Should -Be 'Cancelled'
        @($res.StopFailed) -join ' ' | Should -Match 'its workers.*arm refused'
    }
    It 'the cancel command (Invoke-SIPipelineCancelRun) hands the step''s execution to the worker stop' {
        $src = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-Pipeline.ps1'))
        $src | Should -Match ([regex]::Escape('& $StopWorkers ([string]$st.Job) $sinceOf[[string]$st.Job] ([string]$st.Execution)'))
    }
    It 'the close of a cancelled run (Close-SIJobFlowCancelledRun) stops the open step''s workers once' {
        $st = [pscustomobject]@{ FlowRunId = 'r1'; State = 'Cancelled'; CancelledBy = 'ann'; StartedUtc = $script:T0; EndedUtc = $script:T0.AddHours(1); StopReason = ''
                                 Steps = @((Step 'risk-analysis-detailed' 'Running' 'ra-x1' $script:T0)) }
        $script:W = New-Object System.Collections.Generic.List[string]
        $null = Close-SIJobFlowCancelledRun -State $st -Stop { param($j, $e) } -StopWorkers { param($j, $s, $e) $script:W.Add(('{0}|{1}' -f $j, $e)) } -NowUtc $script:T0.AddHours(2)
        @($script:W) | Should -Be @('risk-analysis-detailed|ra-x1')
        $null = Close-SIJobFlowCancelledRun -State $st -Stop { param($j, $e) } -StopWorkers { param($j, $s, $e) $script:W.Add('again') } -NowUtc $script:T0.AddHours(3)
        @($script:W).Count | Should -Be 1 -Because 'a step closed already is not stopped again'
    }
    It 'a resumed run that closes a Starting step Interrupted: the job''s running execution since the step and its workers are stopped' {
        $def = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map -StartTime '01:00' -TimeZone 'UTC'
        $prev = [pscustomobject]@{ FlowRunId = 'run-r'; Day = '2026-10-22'; Trigger = 'schedule'; FromStep = ''; State = 'Running'; StartedUtc = $script:T0; EndedUtc = $null
            HeartbeatUtc = $script:T0; StopReason = ''; SlotUtc = $null; LastSlotUtc = $null; Note = ''; Scope = 'pipeline'; Target = ''; RequestedBy = ''; RequestId = 0; Version = ''; CancelledBy = ''
            Steps = @([pscustomobject]@{ Order = 1; Group = 1; Job = 'ptc'; Stage = 'collect'; State = 'Success'; Execution = 'ptc-x1'; StartedUtc = $script:T0; EndedUtc = $script:T0; ErrorClass = ''; Error = ''; Attempts = 1; RetryReason = '' }
                      [pscustomobject]@{ Order = 2; Group = 2; Job = 'identity'; Stage = 'collect'; State = 'Starting'; Execution = ''; StartedUtc = $script:T0.AddMinutes(10); EndedUtc = $null; ErrorClass = ''; Error = ''; Attempts = 1; RetryReason = '' }) }
        $script:S = New-Object System.Collections.Generic.List[string]; $script:W = New-Object System.Collections.Generic.List[string]
        $script:Clock = $script:T0.AddHours(1)
        $r = Invoke-SIJobFlow -Definition $def -Start { param($j) throw 'nothing starts' } -Poll { param($j, $e) 'Succeeded' } -Stop { param($j, $e) $script:S.Add($e) } `
                -Running { param($j) if ($j -eq 'identity') { [pscustomobject]@{ Execution = 'identity-late'; StartedUtc = $script:T0.AddMinutes(11) } } } `
                -StopWorkers { param($j, $s, $e) $script:W.Add($j) } -Save { param($s) } -Now { $script:Clock } -Sleep { param($s) } -Log $script:LogSb -Map $script:Map -Previous $prev
        $r.Outcome | Should -Be 'Resume'
        @($r.Steps | Where-Object { $_.Job -eq 'identity' })[0].State | Should -Be 'Interrupted'
        @($script:S) | Should -Contain 'identity-late'
        @($script:W) | Should -Contain 'identity'
    }
    It 'an execution that started BEFORE the Starting step (a different run) is not stopped by the resume' {
        $def = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map -StartTime '01:00' -TimeZone 'UTC'
        $prev = [pscustomobject]@{ FlowRunId = 'run-r'; Day = '2026-10-22'; Trigger = 'schedule'; FromStep = ''; State = 'Running'; StartedUtc = $script:T0; EndedUtc = $null
            HeartbeatUtc = $script:T0; StopReason = ''; SlotUtc = $null; LastSlotUtc = $null; Note = ''; Scope = 'pipeline'; Target = ''; RequestedBy = ''; RequestId = 0; Version = ''; CancelledBy = ''
            Steps = @([pscustomobject]@{ Order = 2; Group = 2; Job = 'identity'; Stage = 'collect'; State = 'Starting'; Execution = ''; StartedUtc = $script:T0.AddHours(1); EndedUtc = $null; ErrorClass = ''; Error = ''; Attempts = 1; RetryReason = '' }) }
        $script:S = New-Object System.Collections.Generic.List[string]
        $script:Clock = $script:T0.AddHours(2)
        $null = Invoke-SIJobFlow -Definition $def -Start { param($j) throw 'nothing starts' } -Poll { param($j, $e) 'Succeeded' } -Stop { param($j, $e) $script:S.Add($e) } `
                -Running { param($j) [pscustomobject]@{ Execution = 'identity-older'; StartedUtc = $script:T0 } } -Save { param($s) } -Now { $script:Clock } -Sleep { param($s) } -Log $script:LogSb -Map $script:Map -Previous $prev
        @($script:S) | Should -Not -Contain 'identity-older'
    }
}

Describe 'THE LIVE RUN''S WORK IS NEVER STOPPED (Get-SIJobFlowEndedStepStops)' {
    BeforeAll {
        $script:Rows = @(
            [pscustomobject]@{ Job = 'risk-analysis-detailed'; Execution = 'ra-old'; StartedUtc = $script:T0 },
            [pscustomobject]@{ Job = 'identity'; Execution = 'id-shared'; StartedUtc = $script:T0 },
            [pscustomobject]@{ Job = 'endpoint'; Execution = 'ep-old'; StartedUtc = $script:T0 })
    }
    It 'no live run: every recorded execution and every step''s workers are stopped' {
        $s = @(Get-SIJobFlowEndedStepStops -Rows $script:Rows -Live $null)
        @($s | ForEach-Object { $_.Execution }) | Should -Be @('ra-old', 'id-shared', 'ep-old')
        @($s | Where-Object { -not $_.Workers }).Count | Should -Be 0
    }
    It 'an execution the live run FOLLOWS is not stopped; the workers of a job the live run RUNS are left to it' {
        $live = [pscustomobject]@{ FlowRunId = 'now'; State = 'Running'; Steps = @((Step 'identity' 'Running' 'id-shared' $script:T0), (Step 'risk-analysis-detailed' 'Starting' '' $script:T0.AddHours(5))) }
        $s = @(Get-SIJobFlowEndedStepStops -Rows $script:Rows -Live $live)
        $ra = $s | Where-Object { $_.Job -eq 'risk-analysis-detailed' }
        $ra.Execution | Should -Be 'ra-old' -Because 'the old run''s own execution is not the live run''s'
        $ra.Workers | Should -BeFalse -Because 'the live run runs that job now -- its workers are the live run''s'
        $id = $s | Where-Object { $_.Job -eq 'identity' }
        $id.Execution | Should -Be '' -Because 'the live run follows that very execution'
        $id.Workers | Should -BeFalse
        ($s | Where-Object { $_.Job -eq 'endpoint' }).Workers | Should -BeTrue
    }
}

Describe 'the Pro store and the runner''s wiring' {
    It 'EndedRunOpenSteps reads only STARTED step rows of ENDED runs, read-only; the store answers plain rows' {
        $t = Get-SIJobFlowSqlText 'EndedRunOpenSteps'
        $t | Should -Match "r\.State IN \(N'Succeeded', N'Failed', N'Stopped', N'Cancelled'\) AND s\.State IN \(N'Starting', N'Running'\)"
        $t | Should -Not -Match 'UPDATE|DELETE|INSERT'
        $inv = { param($Sql, $Params, $Mode) , @(@{ FlowRunId = 'r'; StepOrder = 1; Job = 'risk-analysis-detailed'; Execution = [DBNull]::Value; State = 'Running'; StartedUtc = [datetime]'2026-10-22T08:00:00' }) }
        $rows = @((New-SIJobFlowSqlStore -Invoke $inv).EndedRunOpenSteps())
        $rows.Count | Should -Be 1
        $rows[0].Execution | Should -Be ''
        $rows[0].Job | Should -Be 'risk-analysis-detailed'
    }
    It 'the runner stops what runs for them BEFORE it closes the rows, with the live run excluded, and hands the worker stop to every path' {
        $r = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'engine', 'flow', 'Invoke-SIJobFlowRun.ps1'))
        $r.IndexOf('$runStore.EndedRunOpenSteps()') | Should -BeLessThan $r.IndexOf('$runStore.CloseEndedRunSteps()')
        $r | Should -Match 'Get-SIJobFlowEndedStepStops -Rows \$endedOpen -Live \$liveRun'
        $r | Should -Match ([regex]::Escape('$retry.StopWorkers = $stopWorkers'))
        $r | Should -Match '(?s)Close-SIJobFlowCancelledRun.{0,600}-StopWorkers \$stopWorkers'
        $r | Should -Match 'StopWorkers = \$stopWorkers; StopRunner'
        $r | Should -Match 'Close-SICollectRunsOf -Store'
        $r | Should -Match 'Get-SIJobFlowWorkerJobs -Job \$Job -Installed'
    }
}
