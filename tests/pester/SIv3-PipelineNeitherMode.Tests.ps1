#Requires -Version 5.1
<#
    SecurityInsight -- "NEITHER MODE" NEVER STAYS (found live on a ring 2 install 2026-10-10: caj-si-flow had no timer AND no
    job of the pipeline had its own -- no daily pipeline ran, telemetry showed nothing for 14 h).

    What must hold:
      - DETECT   caj-si-flow Manual + no job of the pipeline on a timer = neither; the pipeline scheduled, or the jobs on their
                 own timers, is not; the updater's own timer, a queue worker, a producer, the template job do not count;
      - REPAIR   every update puts it back to the pipeline by the switch's own plan and PATCH (caj-si-flow gets its timer),
                 one plain warning line; -DetectOnly = the plan only; any other state is not touched; a failed PATCH is said;
      - REPORT   the update records the check; the heartbeat's setup report says job-layout = wrong while it is not repaired;
      - ROOT CAUSE  (a) an install that stopped half-way (its pipeline jobs created Manual, caj-si-flow -- created last -- not
                 yet) re-run as an EXISTING install chose 'schedules' and created caj-si-flow Manual: the existing jobs'
                 triggers now decide (flow); (b) a switch turned timers off before it turned caj-si-flow on and failed in
                 between: timers are now turned on FIRST (script, web app, repair).
    Offline; every ARM call is a stub. PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-SetupUplink.ps1')
    $script:Map = Get-SIJobFlowMap
    $script:Rg = '/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/jobs'
    function script:Job([string]$Name, [string]$Trigger, [string]$Cron = '', [string]$Remembered = '') {
        $cfg = [ordered]@{ triggerType = $Trigger; replicaTimeout = 7200 }
        if ($Trigger -eq 'Schedule') { $cfg.scheduleTriggerConfig = [pscustomobject]@{ cronExpression = $Cron; parallelism = 1; replicaCompletionCount = 1 } }
        elseif ($Trigger -eq 'Manual') { $cfg.manualTriggerConfig = [pscustomobject]@{ parallelism = 1; replicaCompletionCount = 1 } }
        $tags = [ordered]@{}; if ($Remembered) { $tags['si-disabled-cron'] = $Remembered }
        [pscustomobject]@{ name = $Name; id = "$script:Rg/$Name"; tags = [pscustomobject]$tags; properties = [pscustomobject]@{ configuration = [pscustomobject]$cfg } }
    }
    # the ring 2 install as found: every pipeline job Manual, caj-si-flow Manual; tagging, backup and the updater on timers
    function script:Neither {
        @((Job 'caj-si-ptc' Manual '' '0 1 * * *'), (Job 'caj-si-identity' Manual '' '30 4 * * *'), (Job 'caj-si-identity-producer' Manual),
          (Job 'caj-si-identity-worker' Event), (Job 'caj-si-endpoint' Manual), (Job 'caj-si-azure' Manual), (Job 'caj-si-risk-analysis' Manual),
          (Job 'caj-si-asset-tagging' Schedule '50 5 * * *'), (Job 'caj-si-config-backup' Schedule '0 18 * * *'), (Job 'caj-si-updater' Schedule '0 3 * * *'),
          (Job 'caj-si-templates' Manual), (Job 'caj-si-flow' Manual '' '*/5 * * * *'))
    }
    # one function out of a script file, by its AST (the script itself is not run)
    function script:Import-Fn([string]$File, [string[]]$Names) {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($File, [ref]$null, [ref]$null)
        foreach ($n in $Names) {
            $fn = @($ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true))[0]
            . ([scriptblock]::Create(($fn.Extent.Text -replace '^function ', 'function script:')))
        }
    }
    Import-Fn (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1') @('Get-SIBootstrapJobName', 'Get-SIBootstrapTriggerPlan')
    Import-Fn (Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1') @('ConvertTo-SIUpdaterPipelineScheduleValue')
    function script:New-Arm {
        $calls = New-Object System.Collections.Generic.List[object]
        $all = @(Neither)
        $arm = { param($Method, $Path, $Body) $calls.Add([pscustomobject]@{ Method = $Method; Path = $Path; Body = $Body }); if ($Method -eq 'GET') { @($all | Where-Object { $_.id -eq $Path })[0] } }.GetNewClosure()
        [pscustomobject]@{ Calls = $calls; Arm = $arm }
    }
}

Describe 'detect' {
    It 'caj-si-flow Manual and no job of the pipeline on a timer = neither (the updater, a worker, a producer and the template job do not count)' {
        $r = Test-SIJobOrchestrationNeitherMode -Jobs (ConvertTo-SIJobFlowTriggerList -ArmJobs @(Neither)) -Map $script:Map
        $r.Neither | Should -BeTrue
        $r.Timed | Should -Be 0
        $r.Steps | Should -BeGreaterThan 3
        $r.Why | Should -Match 'NOTHING RUNS'
    }
    It 'the pipeline scheduled, the jobs on their own timers, or no caj-si-flow at all is NOT neither' {
        $flowOn = @(Neither | Where-Object { $_.name -ne 'caj-si-flow' }) + @(Job 'caj-si-flow' Schedule '*/5 * * * *')
        (Test-SIJobOrchestrationNeitherMode -Jobs (ConvertTo-SIJobFlowTriggerList -ArmJobs $flowOn) -Map $script:Map).Neither | Should -BeFalse
        $sched = @(Neither | Where-Object { $_.name -ne 'caj-si-identity' }) + @(Job 'caj-si-identity' Schedule '30 4 * * *')
        (Test-SIJobOrchestrationNeitherMode -Jobs (ConvertTo-SIJobFlowTriggerList -ArmJobs $sched) -Map $script:Map).Neither | Should -BeFalse
        $old = @(Neither | Where-Object { $_.name -ne 'caj-si-flow' })
        (Test-SIJobOrchestrationNeitherMode -Jobs (ConvertTo-SIJobFlowTriggerList -ArmJobs $old) -Map $script:Map).Why | Should -Match 'no caj-si-flow'
    }
}

Describe 'repair (every update)' {
    It 'puts it back to the pipeline: caj-si-flow gets its timer by the switch''s own PATCH, nothing else is changed, one warning line' {
        $a = New-Arm
        # a closure over its own list: inside the function an unbound $log would be its -Log parameter
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIJobOrchestrationRepair -Jobs @(Neither) -Arm $a.Arm -Map $script:Map -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r.State | Should -Be 'repaired'
        @($r.Changed) | Should -Be @('caj-si-flow')
        $patch = @($a.Calls | Where-Object { $_.Method -eq 'PATCH' })
        $patch.Count | Should -Be 1
        $patch[0].Path | Should -Be "$script:Rg/caj-si-flow"
        $patch[0].Body.properties.configuration.triggerType | Should -Be 'Schedule'
        $patch[0].Body.properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '*/5 * * * *'
        @($lines | Where-Object { $_ -like 'WARN *' }).Count | Should -Be 1
        ($lines -join ' ') | Should -Match 'switched to the pipeline'
    }
    It '-WhatIf (the update''s -DetectOnly): the plan only, no PATCH; a healthy install: nothing at all' {
        $a = New-Arm
        (Invoke-SIJobOrchestrationRepair -Jobs @(Neither) -Arm $a.Arm -Map $script:Map -WhatIf).State | Should -Be 'would-repair'
        @($a.Calls | Where-Object { $_.Method -eq 'PATCH' }).Count | Should -Be 0
        $ok = @(Neither | Where-Object { $_.name -ne 'caj-si-flow' }) + @(Job 'caj-si-flow' Schedule '*/5 * * * *')
        $b = New-Arm
        (Invoke-SIJobOrchestrationRepair -Jobs $ok -Arm $b.Arm -Map $script:Map).State | Should -Be 'ok'
        $b.Calls.Count | Should -Be 0
    }
    It 'a PATCH Azure refuses is said and the state is failed (never thrown at the update)' {
        $bad = { param($Method, $Path, $Body) if ($Method -eq 'PATCH') { throw 'AuthorizationFailed' }; @(Neither | Where-Object { $_.id -eq $Path })[0] }
        $r = Invoke-SIJobOrchestrationRepair -Jobs @(Neither) -Arm $bad -Map $script:Map
        $r.State | Should -Be 'failed'
    }
    It 'the update runs it on every update (Complete-SIUpdate), and the updater records it' {
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $u | Should -Match ([regex]::Escape('$null = Invoke-SIUpdateOrchestration;'))
        $u | Should -Match ([regex]::Escape('Invoke-SIJobOrchestrationRepair -Jobs $all -Arm $arm -WhatIf:(-not $Apply -or $DetectOnly)'))
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\updater\Start-SIUpdater.ps1'))
        $s | Should -Match ([regex]::Escape('Save-SIUpdaterPipelineScheduleRow -Store $Store -Result $global:SI_UpdateOrchestration'))
    }
}

Describe 'report (the heartbeat''s setup report)' {
    It 'job-layout is wrong while it is not repaired, ok once it is; an old check says nothing' {
        $ctx = [pscustomobject]@{ Mode = 'identified'; Ring = 2; LicenceState = 'valid'; Edition = 'pro' }
        $now = [datetime]'2026-10-10T20:00:00Z'
        $w = Get-SISetupControlStates -Context $ctx -NowUtc $now -PipelineScheduleJson '{"state":"would-repair","why":"NOTHING RUNS","checkedUtc":"2026-10-10T03:00:00Z"}'
        $w['job-layout'].State | Should -Be 'wrong'
        (Get-SISetupControlStates -Context $ctx -NowUtc $now -PipelineScheduleJson '{"state":"failed","why":"x","checkedUtc":"2026-10-10T03:00:00Z"}')['job-layout'].State | Should -Be 'wrong'
        (Get-SISetupControlStates -Context $ctx -NowUtc $now -PipelineScheduleJson '{"state":"repaired","why":"x","checkedUtc":"2026-10-10T03:00:00Z"}')['job-layout'].State | Should -Be 'ok'
        (Get-SISetupControlStates -Context $ctx -NowUtc $now -PipelineScheduleJson '{"state":"would-repair","why":"x","checkedUtc":"2026-10-01T03:00:00Z"}').ContainsKey('job-layout') | Should -BeFalse
        (Get-SISetupControlStates -Context $ctx -NowUtc $now -PipelineScheduleJson '{"state":"unchecked","why":"x","checkedUtc":"2026-10-10T03:00:00Z"}').ContainsKey('job-layout') | Should -BeFalse
    }
    It 'the updater''s value is the compact JSON the report reads' {
        $v = ConvertTo-SIUpdaterPipelineScheduleValue -Result ([pscustomobject]@{ State = 'repaired'; Why = 'NOTHING RUNS' }) -NowUtc ([datetime]'2026-10-10T03:00:00Z')
        ($v | ConvertFrom-Json).state | Should -Be 'repaired'
        $v | Should -Match '"checkedUtc":"2026-10-10T03:00:00Z"'
        ConvertTo-SIUpdaterPipelineScheduleValue -Result $null | Should -Be ''
    }
}

Describe 'root cause' {
    It '(a) an install that stopped half-way is completed as the pipeline, not as per-job schedules' {
        # first run: the pipeline jobs made Manual, then it stopped -- caj-si-flow (created last) does not exist yet
        $half = ConvertTo-SIJobFlowTriggerList -ArmJobs @(Neither | Where-Object { $_.name -ne 'caj-si-flow' })
        $m = Get-SIJobOrchestrationMode -Explicit '' -ExistingInstall $true -ExistingJobs $half -Map $script:Map
        $m.Mode | Should -Be 'flow'
        $m.Why | Should -Match 'half-way'
        # so the re-run creates caj-si-flow ON its timer
        (Get-SIBootstrapTriggerPlan -Engine 'flow' -Mode $m.Mode -Cron '*/5 * * * *' -Map $script:Map).Trigger | Should -Be 'Schedule'
        # an existing install whose jobs run on their own timers keeps them; one whose caj-si-flow is on stays the pipeline
        $timed = ConvertTo-SIJobFlowTriggerList -ArmJobs @((Job 'caj-si-ptc' Schedule '0 1 * * *'), (Job 'caj-si-identity' Schedule '30 4 * * *'), (Job 'caj-si-flow' Manual))
        (Get-SIJobOrchestrationMode -Explicit '' -ExistingInstall $true -ExistingJobs $timed -Map $script:Map).Mode | Should -Be 'schedules'
        $on = ConvertTo-SIJobFlowTriggerList -ArmJobs @((Job 'caj-si-ptc' Schedule '0 1 * * *'), (Job 'caj-si-flow' Schedule '*/5 * * * *'))
        (Get-SIJobOrchestrationMode -Explicit '' -ExistingInstall $true -ExistingJobs $on -Map $script:Map).Mode | Should -Be 'flow'
        # Bootstrap passes the existing jobs' triggers
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')) | Should -Match ([regex]::Escape('-ExistingJobs @(ConvertTo-SIJobFlowTriggerList -ArmJobs $existingJobObjects)'))
    }
    It '(b) a switch turns timers ON before it turns any off (script, web app, repair) -- stopped half-way it never leaves nothing scheduled' {
        $s = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Switch-SIJobOrchestration.ps1'))
        $s | Should -Match ([regex]::Escape("foreach (`$p in @(@(`$plan | Where-Object { `$_.Action -eq 'to-schedule' }) + @(`$plan | Where-Object { `$_.Action -eq 'to-manual' })))"))
        # the web app's switch (Pro only: the Community copy has no web app -- checked where it exists)
        $web = Join-Path $script:SIRoot 'pro-management\src\SI.Management.Web\Pages\Admin\Jobs.cshtml.cs'
        if (Test-Path -LiteralPath $web) { [IO.File]::ReadAllText($web) | Should -Match ([regex]::Escape('.OrderBy(p => p.Action == "to-manual" ? 1 : 0)')) }
        # the repair's own order, measured: the first PATCH is the one that turns a timer on
        $jobs = @((Job 'caj-si-ptc' Schedule '0 1 * * *'), (Job 'caj-si-flow' Manual '' '*/5 * * * *'))
        $all = Get-SIJobOrchestrationSwitchPlan -Jobs (ConvertTo-SIJobFlowTriggerList -ArmJobs $jobs) -Mode flow -Map $script:Map
        $plan = @($all | Where-Object { $_.Action -ne 'keep' })
        @($plan | ForEach-Object Action) | Should -Contain 'to-manual'
        @($plan | ForEach-Object Action) | Should -Contain 'to-schedule'
    }
}

Describe '#732: every update puts the pipeline runner on its schedule (over the update''s REST seam)' {
    BeforeAll {
        # the runner as found live 2026-10-17: Manual since its install, its 7-day run limit, a secret, a template
        function script:Runner([string]$Trigger = 'Manual', [string]$Cron = '') {
            $cfg = [ordered]@{ triggerType = $Trigger; replicaTimeout = 604800; replicaRetryLimit = 1
                               secrets = @([pscustomobject]@{ name = 'si-license' }); registries = @([pscustomobject]@{ server = 'acr.io'; identity = '/uami' }) }
            if ($Trigger -eq 'Schedule') { $cfg.scheduleTriggerConfig = [pscustomobject]@{ cronExpression = $Cron; parallelism = 1; replicaCompletionCount = 1 } }
            else { $cfg.manualTriggerConfig = [pscustomobject]@{ parallelism = 1; replicaCompletionCount = 1 } }
            [pscustomobject]@{ name = 'caj-si-flow'; id = "$script:Rg/caj-si-flow"; tags = [pscustomobject]@{ 'si-build' = 'b1'; 'si-disabled-cron' = '*/5 * * * *' }
                               properties = [pscustomobject]@{ provisioningState = 'Succeeded'; configuration = [pscustomobject]$cfg
                                   template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'flow'; image = 'acr.io/si:v1'; imageType = 'ContainerImage'; env = @([pscustomobject]@{ name = 'SI_ENGINE'; value = 'flow' }); resources = [pscustomobject]@{ cpu = 0.5; memory = '1Gi'; ephemeralStorage = '2Gi' } }) } } }
        }
        # the update's REST seam: { param($Method, $Uri, $Body, $Resource, $Headers) } -> @{ Status; Body }
        function script:New-Rest([switch]$RefusePatch, [switch]$IgnorePatch) {
            $w = [pscustomobject]@{ Job = (Runner); Calls = (New-Object System.Collections.Generic.List[string]); Bodies = (New-Object System.Collections.Generic.List[string]) }
            $refuse = [bool]$RefusePatch; $ignore = [bool]$IgnorePatch
            $rest = {
                param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
                $w.Calls.Add(('{0} {1}' -f $Method, $Uri))
                if ($Method -eq 'GET') { return [pscustomobject]@{ Status = 200; Body = (ConvertTo-Json -InputObject $w.Job -Depth 20 -Compress) } }
                if ($Method -eq 'PATCH') {
                    $w.Bodies.Add([string]$Body)
                    if ($refuse) { return [pscustomobject]@{ Status = 403; Body = '{"error":{"code":"AuthorizationFailed","message":"no write"}}' } }
                    if (-not $ignore) {
                        $c = ([string]$Body | ConvertFrom-Json).properties.configuration
                        $w.Job.properties.configuration = [pscustomobject]@{ triggerType = $c.triggerType; replicaTimeout = $c.replicaTimeout; replicaRetryLimit = $c.replicaRetryLimit; scheduleTriggerConfig = $c.scheduleTriggerConfig }
                    }
                    return [pscustomobject]@{ Status = 202; Body = '' }
                }
                [pscustomobject]@{ Status = 405; Body = 'unexpected' }
            }.GetNewClosure()
            [pscustomobject]@{ W = $w; Rest = $rest }
        }
        $script:Others = @(Neither | Where-Object { $_.name -ne 'caj-si-flow' })
    }
    It 'Manual -> ONE read-modify-write PATCH to Schedule "*/5 * * * *": the whole template, the run limit kept, no secret sent back; read back; one line' {
        $f = New-Rest
        $r = Invoke-SIFlowRunnerSchedule -Rest $f.Rest -SubscriptionId 's' -ResourceGroup 'rg' -Jobs (@($script:Others) + @(Runner)) -PollSeconds 0 -Map $script:Map
        $r.State | Should -Be 'patched'
        $r.Line | Should -Match 'caj-si-flow had no timer -- put on its schedule "\*/5 \* \* \* \*" and read back'
        @($r.Line).Count | Should -Be 1
        $f.W.Bodies.Count | Should -Be 1
        @($f.W.Calls | Where-Object { $_ -like 'PATCH *caj-si-flow?api-version=2025-07-01' }).Count | Should -Be 1
        @($f.W.Calls | Where-Object { $_ -like 'GET *' }).Count | Should -BeGreaterOrEqual 2 -Because 'read before and read back after'
        $b = $f.W.Bodies[0] | ConvertFrom-Json
        $b.properties.configuration.triggerType | Should -Be 'Schedule'
        $b.properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '*/5 * * * *'
        $b.properties.configuration.replicaTimeout | Should -Be 604800 -Because 'the runner keeps its 7-day run limit'
        $b.properties.configuration.replicaRetryLimit | Should -Be 1
        $b.properties.configuration.PSObject.Properties['secrets'] | Should -BeNullOrEmpty -Because 'ARM returns secrets without values -- never sent back'
        $b.properties.configuration.PSObject.Properties['registries'] | Should -BeNullOrEmpty
        $b.properties.configuration.PSObject.Properties['manualTriggerConfig'] | Should -BeNullOrEmpty
        $b.properties.template.containers[0].image | Should -Be 'acr.io/si:v1'
        $b.properties.template.containers[0].env[0].value | Should -Be 'flow'
        $b.properties.template.containers[0].PSObject.Properties['imageType'] | Should -BeNullOrEmpty
        $b.properties.template.containers[0].resources.PSObject.Properties['ephemeralStorage'] | Should -BeNullOrEmpty
        $b.tags.'si-build' | Should -Be 'b1'
        $b.tags.PSObject.Properties['si-disabled-cron'] | Should -BeNullOrEmpty
        $f.W.Job.properties.configuration.triggerType | Should -Be 'Schedule'
    }
    It 'already Schedule -> no PATCH (and no call at all); whatever cron it has is kept' {
        $f = New-Rest
        $r = Invoke-SIFlowRunnerSchedule -Rest $f.Rest -SubscriptionId 's' -ResourceGroup 'rg' -Jobs (@($script:Others) + @(Runner Schedule '*/10 * * * *')) -PollSeconds 0 -Map $script:Map
        $r.State | Should -Be 'ok'
        $r.Line | Should -Match 'on its schedule'
        $f.W.Calls.Count | Should -Be 0
    }
    It 'PATCH fails -> one line, state failed, never thrown at the update; a change Azure did not keep is failed too' {
        $f = New-Rest -RefusePatch
        { $script:R = Invoke-SIFlowRunnerSchedule -Rest $f.Rest -SubscriptionId 's' -ResourceGroup 'rg' -Jobs (@($script:Others) + @(Runner)) -PollSeconds 0 -Map $script:Map } | Should -Not -Throw
        $script:R.State | Should -Be 'failed'
        @($script:R.Line).Count | Should -Be 1
        $script:R.Line | Should -Match 'was NOT put on its schedule .*HTTP 403.*the update goes on; the next update tries again'
        $g = New-Rest -IgnorePatch
        $r2 = Invoke-SIFlowRunnerSchedule -Rest $g.Rest -SubscriptionId 's' -ResourceGroup 'rg' -Jobs (@($script:Others) + @(Runner)) -PollSeconds 0 -PollMax 2 -Map $script:Map
        $r2.State | Should -Be 'failed'
        $r2.Line | Should -Match 'read back: trigger Manual'
        $boom = { param($Method, $Uri, $Body, $Resource, $Headers) throw 'network down' }
        (Invoke-SIFlowRunnerSchedule -Rest $boom -SubscriptionId 's' -ResourceGroup 'rg' -Jobs (@($script:Others) + @(Runner)) -PollSeconds 0 -Map $script:Map).State | Should -Be 'failed'
    }
    It '-WhatIf (the update''s -DetectOnly): the plan only, no call; no runner: nothing; per-job schedules: left as they are' {
        $f = New-Rest
        (Invoke-SIFlowRunnerSchedule -Rest $f.Rest -SubscriptionId 's' -ResourceGroup 'rg' -Jobs (@($script:Others) + @(Runner)) -WhatIf -Map $script:Map).State | Should -Be 'would-patch'
        (Invoke-SIFlowRunnerSchedule -Rest $f.Rest -SubscriptionId 's' -ResourceGroup 'rg' -Jobs $script:Others -Map $script:Map).State | Should -Be 'no-runner'
        $perJob = @($script:Others | Where-Object { $_.name -ne 'caj-si-identity' }) + @((Job 'caj-si-identity' Schedule '30 4 * * *'), (Runner))
        $s = Invoke-SIFlowRunnerSchedule -Rest $f.Rest -SubscriptionId 's' -ResourceGroup 'rg' -Jobs $perJob -Map $script:Map
        $s.State | Should -Be 'schedules-mode' -Because 'a runner on its timer would run the default pipeline there too -- every job twice'
        $f.W.Calls.Count | Should -Be 0
    }
    It 'the update runs it in step 9b, before the neither-mode repair, and never fails on it' {
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $call = 'Invoke-SIFlowRunnerSchedule -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Jobs $all -WhatIf:(-not $Apply -or $DetectOnly)'
        $u | Should -Match ([regex]::Escape($call))
        $u.IndexOf($call) | Should -BeLessThan $u.IndexOf('Invoke-SIJobOrchestrationRepair -Jobs $all -Arm $arm')
        $u | Should -Match ([regex]::Escape('pipeline runner: not checked ({0}) -- the update goes on; the next update tries again.'))
    }
    It 'the install (setup) runs the SAME step on a pipeline install -- after every job is ensured, never fatal, never with -WhatIf' {
        $b = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1'))
        $call = 'Invoke-SIFlowRunnerSchedule -Rest $frRest -SubscriptionId $subId -ResourceGroup $ResourceGroupName -Jobs $frJobs -Map $flowMap'
        $b | Should -Match ([regex]::Escape($call))
        $b | Should -Match ([regex]::Escape("if (`$orch.Mode -eq 'flow' -and @(`$Engines) -contains 'flow') {"))
        $b.IndexOf($call) | Should -BeGreaterThan $b.IndexOf('foreach ($engine in $Engines) {') -Because 'after the jobs exist'
        $b.IndexOf($call) | Should -BeLessThan $b.IndexOf("Write-Host '[5/5] Done.'")
        $b | Should -Match ([regex]::Escape("the pipeline runner''s schedule was not checked ({0}) -- setup goes on; the next update checks it."))
        # the seam it hands over speaks the step's contract: status + body, never a throw
        $seam = [regex]::Match($b, '(?s)\$frRest = \{.*?\n        \}').Value
        $seam | Should -Match 'Status = \[int\]\$r\.StatusCode; Body = \[string\]\$r\.Content'
        $seam | Should -Match 'catch \{ \[pscustomobject\]@\{ Status = 0; Body = \$_\.Exception\.Message \} \}'
    }
    It 'nothing but this step sets caj-si-flow''s trigger in setup, and only to its schedule' {
        $b = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1'))
        $b | Should -Not -Match 'caj-si-flow.*triggerType\s*=\s*[''"]Manual'
        (New-SIFlowRunnerSchedulePatchBody -Job (Runner) -Cron '*/5 * * * *').properties.configuration.triggerType | Should -Be 'Schedule'
    }
}
Describe '#732: every update moves a per-job-timer install to the pipeline (REST and SQL seams)' {
    BeforeAll {
        # the school install as found 2026-10-17: identity, endpoint, azure (and the rest of the pipeline) on their own
        # timers, caj-si-flow Manual; tagging, backup and the updater on timers outside the pipeline
        function script:PerJob {
            @((Job 'caj-si-ptc' Schedule '0 1 * * *'), (Job 'caj-si-identity' Schedule '30 4 * * *'), (Job 'caj-si-identity-producer' Manual),
              (Job 'caj-si-identity-worker' Event), (Job 'caj-si-endpoint' Schedule '0 5 * * *'), (Job 'caj-si-azure' Schedule '30 5 * * *'),
              (Job 'caj-si-risk-analysis' Schedule '0 7 * * *'), (Job 'caj-si-asset-tagging' Schedule '50 5 * * *'), (Job 'caj-si-config-backup' Schedule '0 18 * * *'),
              (Job 'caj-si-updater' Schedule '0 21 * * *'), (Job 'caj-si-templates' Manual), (Job 'caj-si-flow' Manual '' '*/5 * * * *'))
        }
        $script:Now = [datetime]'2026-10-17T21:00:00Z'   # an update in the evening; the steps ran at 17:30Z, after the day's 19:00 Danish-time slot (17:00Z)
        # the update's REST seam over a little ARM: jobs, their executions, PATCH of the trigger + tags
        function script:New-World([string]$Started = '2026-10-17T17:30:00Z', [string]$Status = 'Succeeded', [string[]]$FailPatch = @(), [string]$RunningJob = '') {
            $w = [pscustomobject]@{ Jobs = @{}; Calls = (New-Object System.Collections.Generic.List[string]); FailPatch = $FailPatch; Execs = @{} }
            foreach ($j in @(PerJob)) {
                $w.Jobs[[string]$j.name] = $j
                $st = if ($RunningJob -eq [string]$j.name) { 'Running' } else { $Status }
                $w.Execs[[string]$j.name] = @([pscustomobject]@{ name = "$($j.name)-x1"; properties = [pscustomobject]@{ status = $st; startTime = $Started; endTime = $Started } })
            }
            $rest = {
                param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
                $w.Calls.Add(('{0} {1}' -f $Method, $Uri))
                $m = [regex]::Match($Uri, '/jobs/(?<n>[^/?]+)(?<x>/executions)?\?')
                $n = $m.Groups['n'].Value
                if ($Method -eq 'GET' -and $m.Groups['x'].Success) { return [pscustomobject]@{ Status = 200; Body = (ConvertTo-Json -InputObject ([pscustomobject]@{ value = @($w.Execs[$n]) }) -Depth 10 -Compress) } }
                if ($Method -eq 'GET') { return [pscustomobject]@{ Status = 200; Body = (ConvertTo-Json -InputObject $w.Jobs[$n] -Depth 20 -Compress) } }
                if ($Method -eq 'PATCH') {
                    $b = [string]$Body | ConvertFrom-Json
                    if ($w.FailPatch -contains ('{0}:{1}' -f $n, $b.properties.configuration.triggerType)) { return [pscustomobject]@{ Status = 409; Body = '{"error":{"code":"Conflict","message":"busy"}}' } }
                    $w.Jobs[$n].properties.configuration = $b.properties.configuration
                    $w.Jobs[$n].tags = $b.tags
                    return [pscustomobject]@{ Status = 200; Body = '' }
                }
                [pscustomobject]@{ Status = 405; Body = '' }
            }.GetNewClosure()
            $w | Add-Member -NotePropertyName Rest -NotePropertyValue $rest
            $w
        }
        # the Pro database: cfg.JobFlow (optional), the last cfg.FlowRun, cfg.PipelineQueue
        function script:New-Db([string]$Mode = '', [string]$RunState = '', $RunHeartbeat = $null) {
            $d = [pscustomobject]@{ Mode = $Mode; Json = $(if ($Mode) { $df = New-SIDefaultJobFlow -Installed @(PerJob | ForEach-Object { [string]$_.name }) -Map $script:Map; $df.Mode = $Mode; ConvertTo-SIJobFlowJson -Definition $df } else { '' }); Queue = (New-Object System.Collections.Generic.List[object]); Sql = (New-Object System.Collections.Generic.List[string]); RunState = $RunState; RunHeartbeat = $RunHeartbeat; FailUpdate = $false; SetBy = '' }
            $sql = {
                param([string]$Query, $Params, [string]$Mode)
                $d.Sql.Add($Query)
                if ($Query -like '*FROM cfg.JobFlow WHERE FlowId*' -and $Query -like 'IF OBJECT_ID*') {
                    if (-not $d.Mode) { return , @(@{ DefinitionJson = [DBNull]::Value; Mode = [DBNull]::Value }) }
                    return , @(@{ DefinitionJson = $d.Json; Mode = $d.Mode })
                }
                if ($Query -like 'UPDATE cfg.JobFlow*' -or $Query -like 'INSERT cfg.JobFlow*' -or $Query -like 'MERGE cfg.JobFlow*') { throw 'the engine role has no write right on cfg.JobFlow' }
                if ($Query -like 'EXEC cfg.JobFlowSetMode*') {
                    if ($d.FailUpdate) { throw 'the database refused it' }
                    $d.Mode = [string]$Params.Mode; $d.SetBy = [string]$Params.By; return , @(@{ Updated = 1 })
                }
                if ($Query -like '*FROM cfg.FlowRun*') {
                    if (-not $d.RunState) { return , @() }
                    return , @(@{ FlowRunId = 'run-9'; Day = '2026-10-17'; Trg = 'manual'; FromStep = ''; State = $d.RunState; StartedUtc = [datetime]'2026-10-17T20:00:00Z'; EndedUtc = [DBNull]::Value; HeartbeatUtc = $d.RunHeartbeat; StopReason = ''; SlotUtc = [DBNull]::Value; LastSlotUtc = [DBNull]::Value; Note = '' })
                }
                if ($Query -like '*FROM cfg.FlowStepRun*') { return , @() }
                if ($Query -like '*INSERT cfg.PipelineQueue*') { $d.Queue.Add($Params); return , @(@{ Id = [long]($d.Queue.Count); Outcome = 'Queued' }) }
                throw "unexpected SQL: $Query"
            }.GetNewClosure()
            $d | Add-Member -NotePropertyName Invoke -NotePropertyValue $sql
            $d
        }
        function script:Trig($w, [string]$n) { [string]$w.Jobs[$n].properties.configuration.triggerType }
        function script:Mig($w, $d, [switch]$WhatIf) { Invoke-SIJobFlowMigration -Rest $w.Rest -SubscriptionId 's' -ResourceGroup 'rg' -Jobs @($w.Jobs.Values) -Sql $(if ($d) { $d.Invoke } else { $null }) -NowUtc $script:Now -PollSeconds 0 -PollMax 2 -Map $script:Map -WhatIf:$WhatIf }
        $script:Steps = @('caj-si-ptc', 'caj-si-identity', 'caj-si-endpoint', 'caj-si-azure', 'caj-si-risk-analysis')
    }
    It 'per-job timers -> the pipeline: the steps Manual (timers remembered, the rest of the job kept), caj-si-flow on "*/5", read back, one line per change; a day already run is not run again' {
        $w = New-World; $d = New-Db
        $r = Mig $w $d
        $r.State | Should -Be 'migrated'
        foreach ($n in $script:Steps) { Trig $w $n | Should -Be 'Manual' -Because $n; [string]$w.Jobs[$n].tags.'si-disabled-cron' | Should -Not -BeNullOrEmpty -Because $n }
        [string]$w.Jobs['caj-si-identity'].tags.'si-disabled-cron' | Should -Be '30 4 * * *'
        $w.Jobs['caj-si-identity'].properties.configuration.replicaTimeout | Should -Be 7200 -Because 'everything else on the job is kept'
        Trig $w 'caj-si-flow' | Should -Be 'Schedule'
        [string]$w.Jobs['caj-si-flow'].properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '*/5 * * * *'
        foreach ($n in 'caj-si-updater', 'caj-si-config-backup') { Trig $w $n | Should -Be 'Schedule' -Because "$n is not a step of the pipeline" }
        (Get-SIFlowRunnerScheduleState -Jobs (ConvertTo-SIJobFlowTriggerList -ArmJobs @($w.Jobs.Values)) -Map $script:Map).State | Should -Be 'scheduled'
        @($r.Changed).Count | Should -BeGreaterOrEqual 6
        foreach ($c in $r.Changed) { @($r.Lines | Where-Object { $_ -match [regex]::Escape($c) }).Count | Should -BeGreaterOrEqual 1 -Because $c }
        ($r.Lines -join "`n") | Should -Match 'done and read back'
        $d.Queue.Count | Should -Be 0 -Because 'every step ran after the pipeline''s start time'
        $r.Queued | Should -BeFalse
        # PATCH only after every job was seen idle; never a PUT
        @($w.Calls | Where-Object { $_ -like 'PUT *' }).Count | Should -Be 0
        $firstPatch = [array]::IndexOf(@($w.Calls), @($w.Calls | Where-Object { $_ -like 'PATCH *' })[0])
        $lastExec = [array]::LastIndexOf(@($w.Calls), @($w.Calls | Where-Object { $_ -like 'GET */executions*' })[-1])
        $firstPatch | Should -BeGreaterThan $lastExec
    }
    It 'never a day skipped: the last complete run is older than the pipeline''s start -> ONE run queued, as Run now' {
        $w = New-World -Started '2026-10-15T06:00:00Z'; $d = New-Db
        $r = Mig $w $d
        $r.State | Should -Be 'migrated'
        $r.Queued | Should -BeTrue
        $d.Queue.Count | Should -Be 1
        $d.Queue[0].Scope | Should -Be 'pipeline'; $d.Queue[0].Trg | Should -Be 'manual'; $d.Queue[0].RequestedBy | Should -Be 'update'
        ($r.Lines -join "`n") | Should -Match 'one pipeline run queued'
        # a step that never succeeded counts as not run
        $w2 = New-World -Status 'Failed'; $d2 = New-Db
        (Mig $w2 $d2).Queued | Should -BeTrue
    }
    It 'the stored pipeline that says schedules is set to run as the pipeline (read back); none stored = the default, nothing written' {
        $w = New-World; $d = New-Db -Mode 'schedules'
        (Mig $w $d).State | Should -Be 'migrated'
        $d.Mode | Should -Be 'flow'
        $d.SetBy | Should -Be 'update'
        @($d.Sql | Where-Object { $_ -like 'EXEC cfg.JobFlowSetMode*' }).Count | Should -Be 1 -Because 'the mode is set only through cfg.JobFlowSetMode -- never a table write'
        $w2 = New-World; $d2 = New-Db
        $null = Mig $w2 $d2
        @($d2.Sql | Where-Object { $_ -like '*cfg.JobFlowSetMode*' -or $_ -like 'UPDATE cfg.JobFlow*' -or $_ -like '*INSERT cfg.JobFlow*' -or $_ -like 'MERGE cfg.JobFlow*' }).Count | Should -Be 0
    }
    It 'something running -> deferred: a job execution Running, or a pipeline run with a fresh heartbeat; nothing changed, one line' {
        $w = New-World -RunningJob 'caj-si-endpoint'; $d = New-Db
        $r = Mig $w $d
        $r.State | Should -Be 'deferred'
        @($r.Lines).Count | Should -Be 1
        $r.Lines[0] | Should -Match 'not now -- running: caj-si-endpoint; nothing was changed .*next update tries again'
        @($w.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
        $w2 = New-World; $d2 = New-Db -RunState 'Running' -RunHeartbeat ([datetime]'2026-10-17T20:55:00Z')
        $r2 = Mig $w2 $d2
        $r2.State | Should -Be 'deferred'
        $r2.Lines[0] | Should -Match 'the pipeline run run-9'
        @($w2.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
        # a run record whose runner died long ago does not hold the switch (the pipeline resumes it)
        $w3 = New-World; $d3 = New-Db -RunState 'Running' -RunHeartbeat ([datetime]'2026-10-16T01:00:00Z')
        (Mig $w3 $d3).State | Should -Be 'migrated'
    }
    It 'partial failure -> put back: caj-si-flow refused, every timer back, caj-si-flow Manual, the stored mode as it was -- still one working mode' {
        $w = New-World -FailPatch @('caj-si-flow:Schedule'); $d = New-Db -Mode 'schedules'
        $r = Mig $w $d
        $r.State | Should -Be 'reverted'
        foreach ($n in $script:Steps) { Trig $w $n | Should -Be 'Schedule' -Because $n }
        [string]$w.Jobs['caj-si-identity'].properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '30 4 * * *'
        Trig $w 'caj-si-flow' | Should -Be 'Manual'
        $d.Mode | Should -Be 'schedules'
        $d.Queue.Count | Should -Be 0
        ($r.Lines -join "`n") | Should -Match 'NOT done .*put back: the install runs on its own timers as before'
        $list = ConvertTo-SIJobFlowTriggerList -ArmJobs @($w.Jobs.Values)
        (Test-SIJobOrchestrationNeitherMode -Jobs $list -Map $script:Map).Neither | Should -BeFalse
        (Get-SIFlowRunnerScheduleState -Jobs $list -Map $script:Map).State | Should -Be 'schedules-mode'
        # a step refused half-way through the timers: the ones already Manual go back
        $w2 = New-World -FailPatch @('caj-si-azure:Manual'); $d2 = New-Db
        (Mig $w2 $d2).State | Should -Be 'reverted'
        foreach ($n in $script:Steps) { Trig $w2 $n | Should -Be 'Schedule' -Because $n }
        Trig $w2 'caj-si-flow' | Should -Be 'Manual'
    }
    It 'a put-back that fails too ends in neither at worst -- and the neither-mode repair that runs next puts caj-si-flow on its timer' {
        $w = New-World -FailPatch @('caj-si-flow:Schedule', 'caj-si-ptc:Schedule'); $d = New-Db
        $r = Mig $w $d
        $r.State | Should -Be 'failed'
        ($r.Lines -join "`n") | Should -Match 'NOT fully put back .*neither-mode repair'
        # caj-si-ptc stays Manual, the others are back on their timers: per-job schedules, never neither
        (Test-SIJobOrchestrationNeitherMode -Jobs (ConvertTo-SIJobFlowTriggerList -ArmJobs @($w.Jobs.Values)) -Map $script:Map).Neither | Should -BeFalse
        # every timer stuck off: the repair gives caj-si-flow its timer
        $w.FailPatch = @()
        foreach ($n in $script:Steps) { $w.Jobs[$n] = Job $n Manual '' '0 1 * * *' }
        $arm = { param($Method, $Path, $Body) $n = ($Path -split '/')[-1]; if ($Method -eq 'GET') { return $w.Jobs[$n] }; $w.Jobs[$n].properties.configuration = $Body.properties.configuration }.GetNewClosure()
        (Invoke-SIJobOrchestrationRepair -Jobs @($w.Jobs.Values) -Arm $arm -Map $script:Map).State | Should -Be 'repaired'
        Trig $w 'caj-si-flow' | Should -Be 'Schedule'
    }
    It 'an install already on the pipeline is untouched (no call at all); -DetectOnly gives the plan only' {
        $w = New-World; $d = New-Db
        $w.Jobs['caj-si-flow'] = Job 'caj-si-flow' Schedule '*/5 * * * *'
        foreach ($n in $script:Steps) { $w.Jobs[$n] = Job $n Manual '' '0 1 * * *' }
        $r = Mig $w $d
        $r.State | Should -Be 'not-needed'
        @($r.Lines).Count | Should -Be 0
        $w.Calls.Count | Should -Be 0
        $d.Sql.Count | Should -Be 0
        $w2 = New-World -Started '2026-10-15T06:00:00Z'; $d2 = New-Db -Mode 'schedules'
        $p = Mig $w2 $d2 -WhatIf
        $p.State | Should -Be 'would-migrate'
        @($w2.Calls | Where-Object { $_ -like 'PATCH *' }).Count | Should -Be 0
        $d2.Queue.Count | Should -Be 0; $d2.Mode | Should -Be 'schedules'
        ($p.Lines -join "`n") | Should -Match 'caj-si-flow would go on its schedule'
        ($p.Lines -join "`n") | Should -Match 'one pipeline run would be queued'
    }
    It 'the stored mode is written ONLY through cfg.JobFlowSetMode: no table write in the engine code, the procedure gated and granted like the others' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1'))
        $src | Should -Not -Match '(?i)(UPDATE|INSERT|MERGE)\s+cfg\.JobFlow\b'
        (Get-SIJobFlowSetModeSql) | Should -Be 'EXEC cfg.JobFlowSetMode @Mode = @Mode, @By = @By;'
        # the procedure lives in the Pro settings schema: checked only where Test-Path finds it (the Community copy has none)
        $proSql = Join-Path $script:SIRoot 'sql\si-pro-settings.sql'
        if (Test-Path -LiteralPath $proSql) {
            $sql = [IO.File]::ReadAllText($proSql)
            $sql | Should -Match ([regex]::Escape("CREATE OR ALTER PROCEDURE cfg.JobFlowSetMode @Mode NVARCHAR(16), @By NVARCHAR(256)"))
            $sql | Should -Match ([regex]::Escape("GRANT EXECUTE ON OBJECT::cfg.JobFlowSetMode TO public;"))
        }
    }
    It 'the update runs it in step 9b for a per-job-timer install, after the runner check and before the neither-mode repair, on a fresh job list' {
        $u = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'setup\Invoke-SIContainerUpdate.ps1'))
        $call = 'Invoke-SIJobFlowMigration -Rest $rest -SubscriptionId $sub -ResourceGroup $target.ResourceGroupName -Jobs $all -Sql $migSql -WhatIf:(-not $Apply -or $DetectOnly)'
        $u | Should -Match ([regex]::Escape($call))
        $u.IndexOf("if (`$fr -and `$fr.State -eq 'schedules-mode')") | Should -BeGreaterThan $u.IndexOf('Invoke-SIFlowRunnerSchedule -Rest $rest')
        $u.IndexOf($call) | Should -BeLessThan $u.IndexOf('Invoke-SIJobOrchestrationRepair -Jobs $all -Arm $arm')
        $u | Should -Match ([regex]::Escape('if (@($mig.Changed).Count) { try { $v = @(Get-SIArmJobList'))
    }
}