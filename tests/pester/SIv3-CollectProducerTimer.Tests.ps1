#Requires -Version 5.1
<#
    #1096 -- A COLLECT ENGINE THAT IS A PIPELINE STEP RUNS ONLY WHEN THE PIPELINE STARTS IT (found live: caj-si-<engine>-producer
    kept its own cron beside the pipeline; its timer fired outside any run and collected everything again -- every install
    collected twice a day).
      1. the install creates a producer Manual (its cron remembered) in pipeline mode and with its cron in schedules mode;
      2. the update converges an existing Schedule producer to Manual, reads it back, and is idempotent;
      3. the collection gate skips a SCHEDULED execution of a pipeline step's job in pipeline mode (defence in depth);
      4. INVARIANT (owner 2026-11-04): in pipeline mode NO job that is a pipeline step -- a producer included -- has its own
         trigger, across every job the install creates and across the update's converged set; schedules mode: the opposite;
      5. the daily pipeline check flags an execution that belongs to no run and to no person, and the heartbeat says it
         (si-flow-1205) -- an ARM read that fails is said, never blocking.
    Offline; every reader is a seam; stubs live in SCRIPT scope. PS 5.1 + 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    . (Join-Path $script:SIRoot 'setup\_shared\SI-KedaConvert.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectionRunGate.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-OutsidePipeline.ps1')
    $script:Map = Get-SIJobFlowMap
    function script:Get-Code([string]$Rel) { ((Get-Content -LiteralPath (Join-Path $script:SIRoot $Rel)) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n" }

    # Bootstrap's job definition for one engine, exactly as Bootstrap builds it: the producer through
    # Get-SIKedaProducerCreateArgs + Get-SIBootstrapProducerTriggerPlan, every other job through its Schedule create
    # arguments turned Manual by its trigger plan (ConvertTo-SIManualCreateArgs) -- then the ARM body (ConvertFrom-SIJobCreateArgs)
    function script:Get-InstallBodies([string]$Mode) {
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($k in @($script:Map.Jobs.Keys)) {
            $j = $script:Map.Jobs[$k]
            $engine = if ($j.Engine) { [string]$j.Engine } else { [string]$k }
            if ($engine -eq 'updater') { continue }
            $cron = if ($j.DefaultCron) { [string]$j.DefaultCron } else { '0 4 * * *' }
            $plan = Get-SIBootstrapTriggerPlan -Engine $engine -Mode $Mode -Cron $cron -Map $script:Map
            if (Test-SIKedaPartsEngine $engine) {
                $name = (Get-SIBootstrapJobName -Engine $engine) + '-producer'
                $a = @(Get-SIKedaProducerCreateArgs -Name $name -ResourceGroup 'rg' -Environment '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/cae' -Cron $cron -Image 'img' -LoginServer 'acr.azurecr.io')
                $pp = Get-SIBootstrapProducerTriggerPlan -TriggerPlan $plan -Cron $cron
                if ($pp.Trigger -eq 'Manual') { $a = ConvertTo-SIManualCreateArgs -CreateArgs $a -RememberCron $pp.RememberCron }
            } else {
                $name = Get-SIBootstrapJobName -Engine $engine
                $a = @('containerapp', 'job', 'create', '--name', $name, '--resource-group', 'rg', '--environment', '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/cae',
                       '--trigger-type', 'Schedule', '--replica-timeout', '3600', '--replica-retry-limit', '0', '--replica-completion-count', '1', '--parallelism', '1',
                       '--cron-expression', $cron, '--image', 'img', '--registry-server', 'acr.azurecr.io', '--cpu', '2.0', '--memory', '4.0Gi', '--output', 'none')
                if ($plan.Trigger -eq 'Manual' -and -not ($j.PSObject.Properties['ManualOnly'] -and $j.ManualOnly)) { $a = ConvertTo-SIManualCreateArgs -CreateArgs $a -RememberCron $plan.RememberCron }
                elseif ($plan.Trigger -eq 'Manual') { $a = ConvertTo-SIManualCreateArgs -CreateArgs $a -RememberCron '' }
            }
            $out.Add([pscustomobject]@{ Key = [string]$k; Name = $name; Body = (ConvertFrom-SIJobCreateArgs -CreateArgs $a -Location 'westeurope').Body })
        }
        $out.ToArray()
    }
    function script:TriggerOf($body) { [string]$body.properties.configuration.triggerType }
    function script:CronOf($body) { $c = $body.properties.configuration; if ($c.Contains('scheduleTriggerConfig')) { [string]$c.scheduleTriggerConfig.cronExpression } else { '' } }
    function script:TagsOf($body) { if ($body.Contains('tags') -and $body.tags) { $body.tags } else { @{} } }

    # an ARM job as Azure lists it
    function script:ArmJob([string]$Name, [string]$Trigger, [string]$Cron = '', [hashtable]$Tags = @{}) {
        $cfg = [ordered]@{ triggerType = $Trigger; replicaTimeout = 3600 }
        if ($Trigger -eq 'Schedule') { $cfg.scheduleTriggerConfig = [ordered]@{ cronExpression = $Cron; parallelism = 1; replicaCompletionCount = 1 } }
        elseif ($Trigger -eq 'Manual') { $cfg.manualTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 } }
        else { $cfg.eventTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 } }
        ([ordered]@{ id = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/jobs/$Name"; name = $Name; tags = $Tags; properties = [ordered]@{ configuration = $cfg; template = @{ containers = @(@{ name = 'c'; image = 'i' }) } } } | ConvertTo-Json -Depth 10) | ConvertFrom-Json
    }
    # an in-memory ARM: GET returns the job, PATCH applies the trigger body (as ARM would), every call recorded
    function script:New-FakeArm([object[]]$Jobs, [switch]$PatchIgnored) {
        $st = [pscustomobject]@{ Jobs = @{}; Calls = New-Object System.Collections.Generic.List[string]; Ignore = [bool]$PatchIgnored }
        foreach ($j in $Jobs) { $st.Jobs[[string]$j.id] = $j }
        $arm = {
            param($Method, $Path, $Body)
            $st.Calls.Add(('{0} {1}' -f $Method, ($Path -split '/')[-1]))
            $j = $st.Jobs[[string]$Path]
            if ($Method -eq 'PATCH' -and -not $st.Ignore) {
                $b = ($Body | ConvertTo-Json -Depth 10) | ConvertFrom-Json
                $j.properties.configuration = $b.properties.configuration
                $j.tags = $b.tags
            }
            ($j | ConvertTo-Json -Depth 10) | ConvertFrom-Json
        }.GetNewClosure()
        [pscustomobject]@{ State = $st; Arm = $arm }
    }
    function script:Installed([string]$ProducerTrigger = 'Schedule') {
        @((ArmJob 'caj-si-flow' Schedule '*/5 * * * *'), (ArmJob 'caj-si-ptc' Manual '' @{ 'si-disabled-cron' = '0 1 * * *' }),
          (ArmJob 'caj-si-endpoint-producer' $ProducerTrigger '0 4 * * *'), (ArmJob 'caj-si-endpoint-worker' Event),
          (ArmJob 'caj-si-identity-producer' $ProducerTrigger '30 4 * * *'), (ArmJob 'caj-si-identity-worker' Event),
          (ArmJob 'caj-si-azure-producer' $ProducerTrigger '0 5 * * *'), (ArmJob 'caj-si-azure-worker' Event),
          (ArmJob 'caj-si-asset-correlation' Manual '' @{ 'si-disabled-cron' = '0 7 * * *' }), (ArmJob 'caj-si-verification' Manual '' @{ 'si-disabled-cron' = '0 11 * * *' }),
          (ArmJob 'caj-si-updater' Schedule '30 16 * * *'))
    }
}

Describe '#1096 the install: a producer of a pipeline step is created Manual' {
    It 'pipeline mode: the producer is Manual, its cron remembered in si-disabled-cron; schedules mode: its cron' {
        $flowPlan = Get-SIBootstrapTriggerPlan -Engine 'endpoint' -Mode flow -Cron '0 4 * * *' -Map $script:Map
        $p = Get-SIBootstrapProducerTriggerPlan -TriggerPlan $flowPlan -Cron '0 4 * * *'
        $p.Trigger | Should -Be 'Manual'; $p.RememberCron | Should -Be '0 4 * * *'
        $schedPlan = Get-SIBootstrapTriggerPlan -Engine 'endpoint' -Mode schedules -Cron '0 4 * * *' -Map $script:Map
        (Get-SIBootstrapProducerTriggerPlan -TriggerPlan $schedPlan -Cron '0 4 * * *').Trigger | Should -Be 'Schedule'
        $b = @(Get-InstallBodies -Mode flow | Where-Object { $_.Name -eq 'caj-si-identity-producer' })[0].Body
        TriggerOf $b | Should -Be 'Manual'
        (TagsOf $b)['si-disabled-cron'] | Should -Be '30 4 * * *'
        $s = @(Get-InstallBodies -Mode schedules | Where-Object { $_.Name -eq 'caj-si-identity-producer' })[0].Body
        TriggerOf $s | Should -Be 'Schedule'; CronOf $s | Should -Be '30 4 * * *'
    }
    It 'Bootstrap builds the producer from that plan and never gives a Manual producer its timer back' {
        $b = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        $b | Should -Match '\$producerPlan = Get-SIBootstrapProducerTriggerPlan -TriggerPlan \$trigPlan -Cron \$schedule'
        $b | Should -Match "if \(\`$producerPlan\.Trigger -eq 'Manual'\) \{ \`$producerCreateArgs = ConvertTo-SIManualCreateArgs -CreateArgs \`$producerCreateArgs -RememberCron \`$producerPlan\.RememberCron \}"
        $b | Should -Match "if \(-not \`$producerManual\) \{ \`$pupd\['Cron'\] = \`$schedule \}"
        $b | Should -Not -Match 'Image = \$image; Cron = \$schedule; Env = @\(\$producerEnvArgs\)'
    }
}

Describe '#1096 INVARIANT: in pipeline mode no pipeline step has its own trigger' {
    It 'every job the install creates: a pipeline step (a producer included) is Manual in pipeline mode, on its timer in schedules mode' {
        $steps = @($script:Map.DefaultFlow)
        $flow = @(Get-InstallBodies -Mode flow)
        $sched = @(Get-InstallBodies -Mode schedules)
        $flow.Count | Should -BeGreaterThan 10
        @($flow | Where-Object { $_.Name -like '*-producer' }).Count | Should -Be 3 -Because 'endpoint, identity and azure collect in parts'
        $timed = @($flow | Where-Object { $steps -contains (Get-SIJobFlowStepKey $_.Name) -and (TriggerOf $_.Body) -ne 'Manual' } | ForEach-Object { $_.Name })
        $timed | Should -BeNullOrEmpty -Because 'a step with its own timer runs beside the pipeline and belongs to no run'
        foreach ($x in @($flow | Where-Object { $steps -contains (Get-SIJobFlowStepKey $_.Name) })) { $x.Body.properties.configuration.Contains('scheduleTriggerConfig') | Should -BeFalse -Because $x.Name }
        $untimed = @($sched | Where-Object { $steps -contains (Get-SIJobFlowStepKey $_.Name) -and (TriggerOf $_.Body) -ne 'Schedule' } | ForEach-Object { $_.Name })
        $untimed | Should -BeNullOrEmpty -Because 'in schedules mode every step runs on its own timer'
    }
    It 'the update''s converged set: a flow install whose producers have timers ends with no step on a timer; schedules mode is left on its timers' {
        $fake = New-FakeArm -Jobs (Installed 'Schedule')
        $r = Invoke-SICollectProducerTrigger -Jobs (Installed 'Schedule') -Arm $fake.Arm -Mode flow -Map $script:Map -PollSeconds 0
        $r.State | Should -Be 'converged'
        $after = @($fake.State.Jobs.Values)
        $list = ConvertTo-SIJobFlowTriggerList -ArmJobs $after
        $def = New-SIDefaultJobFlow -Installed @($list | ForEach-Object { Get-SIJobFlowStepKey $_.Name }) -Map $script:Map
        $steps = @($def.Steps | ForEach-Object { [string]$_.Job })
        @($list | Where-Object { $_.TriggerType -eq 'Schedule' -and $steps -contains (Get-SIJobFlowStepKey $_.Name) -and $_.Name -notlike '*-worker' } | ForEach-Object { $_.Name }) | Should -BeNullOrEmpty
        @($list | Where-Object { $_.Name -eq 'caj-si-updater' })[0].TriggerType | Should -Be 'Schedule' -Because 'the updater keeps its own timer'
        # the switch to the pipeline (the migration of a schedules install) takes EVERY step off its timer, the producers too
        $schedJobs = ConvertTo-SIJobFlowTriggerList -ArmJobs @((ArmJob 'caj-si-flow' Manual '' @{ 'si-disabled-cron' = '*/5 * * * *' }), (ArmJob 'caj-si-ptc' Schedule '0 1 * * *'),
                         (ArmJob 'caj-si-endpoint-producer' Schedule '0 4 * * *'), (ArmJob 'caj-si-endpoint-worker' Event), (ArmJob 'caj-si-asset-correlation' Schedule '0 7 * * *'))
        $plan = Get-SIJobOrchestrationSwitchPlan -Jobs $schedJobs -Mode flow -Map $script:Map
        @($plan | Where-Object { $_.Action -eq 'to-manual' } | ForEach-Object { $_.Job }) | Should -Be @('caj-si-ptc', 'caj-si-endpoint-producer', 'caj-si-asset-correlation')
        # and back: schedules mode gives the producer its remembered timer
        $back = Get-SIJobOrchestrationSwitchPlan -Jobs (ConvertTo-SIJobFlowTriggerList -ArmJobs @((ArmJob 'caj-si-endpoint-producer' Manual '' @{ 'si-disabled-cron' = '0 4 * * *' }), (ArmJob 'caj-si-endpoint-worker' Event))) -Mode schedules -Map $script:Map
        @($back | Where-Object { $_.Job -eq 'caj-si-endpoint-producer' })[0].Action | Should -Be 'to-schedule'
        @($back | Where-Object { $_.Job -eq 'caj-si-endpoint-producer' })[0].Cron | Should -Be '0 4 * * *'
    }
}

Describe '#1096 the update converges existing installs' {
    It 'a Schedule producer goes Manual (cron remembered), read back; a second update changes nothing' {
        $fake = New-FakeArm -Jobs (Installed 'Schedule')
        $r = Invoke-SICollectProducerTrigger -Jobs (Installed 'Schedule') -Arm $fake.Arm -Mode flow -Map $script:Map -PollSeconds 0
        $r.State | Should -Be 'converged'
        @($r.Changed) | Should -Be @('caj-si-endpoint-producer', 'caj-si-identity-producer', 'caj-si-azure-producer')
        $j = $fake.State.Jobs['/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-identity-producer']
        $j.properties.configuration.triggerType | Should -Be 'Manual'
        $j.tags.'si-disabled-cron' | Should -Be '30 4 * * *'
        @($fake.State.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 3
        ($r.Lines -join "`n") | Should -Match 'read back'
        # idempotent: the converged state is left as it is
        $again = New-FakeArm -Jobs @($fake.State.Jobs.Values)
        $r2 = Invoke-SICollectProducerTrigger -Jobs @($fake.State.Jobs.Values) -Arm $again.Arm -Mode flow -Map $script:Map -PollSeconds 0
        $r2.State | Should -Be 'ok'
        @($again.State.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
    }
    It 'schedules mode: nothing changes; -WhatIf: the plan only' {
        $fake = New-FakeArm -Jobs (Installed 'Schedule')
        (Invoke-SICollectProducerTrigger -Jobs (Installed 'Schedule') -Arm $fake.Arm -Mode schedules -Map $script:Map -PollSeconds 0).State | Should -Be 'ok'
        (Invoke-SICollectProducerTrigger -Jobs (Installed 'Schedule') -Arm $fake.Arm -Mode flow -Map $script:Map -WhatIf).State | Should -Be 'would-converge'
        @($fake.State.Calls).Count | Should -Be 0
    }
    It 'a producer whose engine is not a step of the STORED pipeline keeps its timer (its only collection), said' {
        $def = New-SIDefaultJobFlow -Installed @('ptc', 'endpoint', 'identity', 'asset-correlation', 'verification') -Map $script:Map
        $fake = New-FakeArm -Jobs (Installed 'Schedule')
        $r = Invoke-SICollectProducerTrigger -Jobs (Installed 'Schedule') -Arm $fake.Arm -Mode flow -Definition $def -Map $script:Map -PollSeconds 0
        @($r.Changed) | Should -Not -Contain 'caj-si-azure-producer'
        $fake.State.Jobs['/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-azure-producer'].properties.configuration.triggerType | Should -Be 'Schedule'
        ($r.Lines -join "`n") | Should -Match 'caj-si-azure-producer -- azure is not a step of the stored pipeline'
    }
    It 'a PATCH that does not read back is said and the update goes on (failed, never thrown)' {
        $fake = New-FakeArm -Jobs (Installed 'Schedule') -PatchIgnored
        $r = Invoke-SICollectProducerTrigger -Jobs (Installed 'Schedule') -Arm $fake.Arm -Mode flow -Map $script:Map -PollSeconds 0 -PollMax 2
        $r.State | Should -Be 'failed'
        ($r.Lines -join "`n") | Should -Match 'was NOT taken off its own timer \(read back: trigger Schedule\)'
    }
    It 'every update runs it after the pipeline schedule, with the stored pipeline and mode' {
        $u = Get-Code 'setup\Invoke-SIContainerUpdate.ps1'
        $u | Should -Match 'try \{ Invoke-SIUpdateCollectProducers -Arm \$arm \}'
        $u | Should -Match 'Get-SIJobFlowSqlText -Name ReadDefinition'
        $u | Should -Match '\$cp = Invoke-SICollectProducerTrigger -Jobs \$all -Arm \$Arm -Mode \$mode -Definition \$def'
    }
}

Describe '#1096 the producer guard: a scheduled execution in pipeline mode skips' {
    BeforeAll {
        $script:NoRun = @{ HasStore = $true; Holder = $null; FlowRunId = $null; LockAgeSeconds = $null; RunState = $null; StepState = $null; StepExecution = $null; StepRows = 0; FlowMode = 'flow'; FlowJson = $null }
        function script:Gate([hashtable]$Row, [string]$Trigger, [string]$Mode = '') {
            $rec = New-Object System.Collections.Generic.List[string]
            $row = $Row
            $g = Invoke-SICollectionRunGate -Invoke { param($q, $p, $m) [pscustomobject]$row }.GetNewClosure() -Job 'azure' -Self 'caj-si-azure-producer-x1' -JobTrigger $Trigger -PipelineMode $Mode `
                    -Log { param($l, $m) } -Record { param($a, $r) $rec.Add($a) }.GetNewClosure() -Sleep { param($s) } -PollSeconds 0
            [pscustomobject]@{ Action = $g.Action; Reason = $g.Reason; Records = $rec.ToArray() }
        }
    }
    It 'pipeline mode, the producer on its own timer, no run starting it: SKIP with one line, exit 0 path' {
        $g = Gate $script:NoRun 'Schedule'
        $g.Action | Should -Be 'Skip'
        $g.Reason | Should -Match 'only the pipeline starts its collection -- this execution came from the job''s own timer'
        $g.Records | Should -Be @('skipped')
    }
    It 'a Manual producer (started by the pipeline or a person), schedules mode, or an engine that is no step of the stored pipeline: RUN' {
        (Gate $script:NoRun 'Manual').Action | Should -Be 'Run'
        $s = $script:NoRun.Clone(); $s.FlowMode = 'schedules'
        (Gate $s 'Schedule').Action | Should -Be 'Run'
        $noStored = $script:NoRun.Clone(); $noStored.FlowMode = $null
        (Gate $noStored 'Schedule' 'schedules').Action | Should -Be 'Run'
        (Gate $noStored 'Schedule' 'flow').Action | Should -Be 'Skip' -Because 'no pipeline stored: caj-si-flow on its timer = pipeline mode, the default pipeline has every collect engine'
        $lacks = $script:NoRun.Clone(); $lacks.FlowJson = '{"schema":2,"steps":[{"job":"ptc"},{"job":"identity"},{"job":"endpoint"}]}'
        (Gate $lacks 'Schedule').Action | Should -Be 'Run' -Because 'its timer is then the engine''s only collection'
    }
    It 'the pipeline''s own start of the step is never skipped, even while the producer still has its timer' {
        $own = $script:NoRun.Clone(); $own.Holder = 'caj-si-flow:x'; $own.FlowRunId = 'r1'; $own.LockAgeSeconds = 10; $own.RunState = 'Running'; $own.StepState = 'Starting'; $own.StepRows = 1
        (Gate $own 'Schedule').Action | Should -Be 'Run'
    }
    It 'nothing read = the collection runs as before (the gate never blocks on its own failure)' {
        Get-SICollectionRunGateTimerSkip -Row $null -Job 'azure' -JobTrigger 'Schedule' -PipelineMode 'flow' | Should -Be ''
    }
    It 'the container passes the job''s trigger and the pipeline mode to the gate' {
        $c = Get-Code 'container\Start-SIInContainer.ps1'
        $c | Should -Match '-JobTrigger \$gateJobTrigger -PipelineMode \$gatePipelineMode'
        $c | Should -Match '\$gateJobTrigger = \[string\]\$gateJobArm\.properties\.configuration\.triggerType'
        (Get-SICollectionRunGateSql) | Should -Match '@fm AS FlowMode, @fj AS FlowJson'
    }
}

Describe '#1096 the pipeline check: ran outside the pipeline' {
    BeforeAll {
        $script:Now = [datetime]'2026-11-04T12:00:00Z'
        function script:Exec([string]$Name, [string]$Start) { [pscustomobject]@{ name = $Name; properties = [pscustomobject]@{ startTime = $Start; status = 'Succeeded' } } }
        $script:Base = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/jobs'
        $script:Execs = @{
            'caj-si-azure-producer'    = @((Exec 'azp-run' '2026-11-03T19:05:00Z'), (Exec 'azp-timer' '2026-11-04T05:00:00Z'), (Exec 'azp-person' '2026-11-04T09:00:00Z'), (Exec 'azp-old' '2026-11-01T05:00:00Z'))
            'caj-si-identity-producer' = @((Exec 'idp-run' '2026-11-03T19:00:00Z'), (Exec 'idp-retry' '2026-11-03T19:01:00Z'))
            'caj-si-ptc'               = @((Exec 'ptc-run' '2026-11-03T19:00:00Z'))
        }
        $script:Rows = @(
            [pscustomobject]@{ K = 'def'; Job = 'flow'; Execution = $null; StartedUtc = $null; EndedUtc = $null; Txt = $null },
            [pscustomobject]@{ K = 'step'; Job = 'azure'; Execution = 'azp-run'; StartedUtc = [datetime]'2026-11-03T19:05:00Z'; EndedUtc = [datetime]'2026-11-03T20:00:00Z'; Txt = $null },
            [pscustomobject]@{ K = 'step'; Job = 'identity'; Execution = 'idp-run2'; StartedUtc = [datetime]'2026-11-03T19:00:30Z'; EndedUtc = [datetime]'2026-11-03T19:40:00Z'; Txt = $null },
            [pscustomobject]@{ K = 'step'; Job = 'ptc'; Execution = 'ptc-run'; StartedUtc = [datetime]'2026-11-03T19:00:00Z'; EndedUtc = [datetime]'2026-11-03T19:10:00Z'; Txt = $null },
            [pscustomobject]@{ K = 'person'; Job = 'caj-si-azure-producer'; Execution = 'azp-person'; StartedUtc = [datetime]'2026-11-04T09:00:00Z'; EndedUtc = $null; Txt = $null })
        function script:New-CheckArm([switch]$FailList, [switch]$FailExec) {
            $jobs = @((ArmJob 'caj-si-flow' Schedule '*/5 * * * *'), (ArmJob 'caj-si-ptc' Manual), (ArmJob 'caj-si-azure-producer' Manual), (ArmJob 'caj-si-azure-worker' Event),
                      (ArmJob 'caj-si-identity-producer' Manual), (ArmJob 'caj-si-identity-worker' Event))
            $execs = $script:Execs; $base = $script:Base; $fl = [bool]$FailList; $fe = [bool]$FailExec
            {
                param($Method, $Path, $Body)
                if ($Path -eq $base) { if ($fl) { throw 'AuthorizationFailed' }; return [pscustomobject]@{ value = $jobs } }
                if ($Path -match '/jobs/([^/]+)/executions$') { if ($fe) { throw 'ResourceNotFound' }; return [pscustomobject]@{ value = @($execs[$Matches[1]]) } }
                throw "unexpected $Path"
            }.GetNewClosure()
        }
    }
    It 'an execution of a step job that belongs to no run and to no person is flagged -- a run''s, a retried attempt''s and a person''s are not' {
        $saved = New-Object System.Collections.Generic.List[string]
        $rows = $script:Rows
        $r = Invoke-SIOutsidePipelineCheck -Invoke { param($q, $p, $m) $rows }.GetNewClosure() -Arm (New-CheckArm) -Base $script:Base -Log { param($l, $m) } -Now { $script:Now } -Save { param($v) $saved.Add($v) }.GetNewClosure() -Map $script:Map
        $r.State | Should -Be 'found'
        @($r.Items | ForEach-Object { $_.Execution }) | Should -Be @('azp-timer')
        $r.Lines -join "`n" | Should -Match 'ran outside the pipeline: caj-si-azure-producer azp-timer 2026-11-04T05:00:00Z'
        $saved.Count | Should -Be 1
        $o = $saved[0] | ConvertFrom-Json
        $o.count | Should -Be 1; $saved[0] | Should -Match '"firstUtc":"2026-11-04T05:00:00Z"'
        $saved[0].Length | Should -BeLessOrEqual 400
    }
    It 'the SQL returns ONE result set: every inner EXEC goes into @r (the reader keeps only the first result set -- a bare EXEC hid the step records and flagged every run, 2026-11-08)' {
        $sql = Get-SIOutsidePipelineSql
        $lines = @($sql -split "`r?`n")
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\s*EXEC\s+sp_executesql') { $lines[$i - 1] | Should -Match '^\s*INSERT @r \(K, Job, Execution, StartedUtc, EndedUtc, Txt\)\s*$' }
        }
        # only the final statement selects to the client: every other SELECT feeds an INSERT @r or sits inside an EXEC's string
        $bare = @($lines | Where-Object { $_ -match '^\s*SELECT\s' -and $_ -notmatch '^\s*SELECT K, Job, Execution, StartedUtc, EndedUtc, Txt FROM @r;' })
        foreach ($b in $bare) { $idx = [array]::IndexOf($lines, $b); $lines[$idx - 1] | Should -Match 'INSERT @r' }
        # the first-result-set reader sees the step records -> a run's execution is never flagged
        $first = { param($q, $p, $m) if ($q -match '(?m)^\s*EXEC\s+sp_executesql' -and $q -notmatch 'INSERT @r \(K, Job, Execution, StartedUtc, EndedUtc, Txt\)\s+EXEC') { @($script:Rows | Where-Object K -eq 'person') } else { $script:Rows } }
        $r = Invoke-SIOutsidePipelineCheck -Invoke $first -Arm (New-CheckArm) -Base $script:Base -Log { param($l, $m) } -Now { $script:Now } -Save { param($v) } -Map $script:Map
        @($r.Items | ForEach-Object { $_.Execution }) | Should -Be @('azp-timer')
    }
    It 'schedules mode: nothing is checked' {
        $rows = @([pscustomobject]@{ K = 'def'; Job = 'schedules'; Execution = $null; StartedUtc = $null; EndedUtc = $null; Txt = $null })
        (Invoke-SIOutsidePipelineCheck -Invoke { param($q, $p, $m) $rows }.GetNewClosure() -Arm (New-CheckArm) -Base $script:Base -Log { param($l, $m) } -Now { $script:Now } -Save { param($v) } -Map $script:Map).State | Should -Be 'schedules-mode'
    }
    It 'an ARM read that fails is said and nothing is concluded -- never thrown, never blocking' {
        $rows = $script:Rows; $warn = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIOutsidePipelineCheck -Invoke { param($q, $p, $m) $rows }.GetNewClosure() -Arm (New-CheckArm -FailList) -Base $script:Base -Log { param($l, $m) if ($l -eq 'WARN') { $warn.Add($m) } }.GetNewClosure() -Now { $script:Now } -Save { param($v) throw 'must not store' } -Map $script:Map
        $r.State | Should -Be 'not-checked'
        $warn -join "`n" | Should -Match 'the jobs could not be read from Azure \(AuthorizationFailed\) -- not checked'
        $r2 = Invoke-SIOutsidePipelineCheck -Invoke { param($q, $p, $m) $rows }.GetNewClosure() -Arm (New-CheckArm -FailExec) -Base $script:Base -Log { param($l, $m) } -Now { $script:Now } -Save { param($v) throw 'must not store' } -Map $script:Map
        $r2.State | Should -Be 'ok'
        $r2.Lines -join "`n" | Should -Match 'could not be read -- those jobs are not checked'
        (Invoke-SIOutsidePipelineCheck -Invoke { throw 'db down' } -Arm (New-CheckArm) -Base $script:Base -Log { param($l, $m) } -Now { $script:Now } -Map $script:Map).State | Should -Be 'not-checked'
    }
    It 'the verification job runs the check, read-only, and the catalogue carries its code si-flow-1205' {
        (Get-Code 'engine\verification\Invoke-SIVerification.ps1') | Should -Match 'Invoke-SIOutsidePipelineCheck -Invoke \$opInvoke -Arm \$opArm'
        $cat = Get-Content -Raw (Join-Path $script:SIRoot 'data-model\errors.locked.json') | ConvertFrom-Json
        @($cat | Where-Object { $_.code -eq 'si-flow-1205' }).Count | Should -Be 1
    }}
