#Requires -Version 5.1
<#
    #393 -- the updater is NEVER a step of the pipeline (framework UPDATE-1.6 (a): one updater per environment, daily at
    03:00 UTC on its OWN schedule, plus started on a release -- never inside the product's daily pipeline).

    Found live on ring 1 (2026-10-06): the default Daily pipeline had caj-si-updater as step 1 of Collect, and the switch to
    pipeline mode turned its own timer to manual. It also deadlocked: the updater waits while any SI job runs (60 min, then
    defers) and the running pipeline IS an SI job -- as a step it waited for itself and never updated.

    Proven here: the default pipeline has no updater; a stored pipeline (schema 1 and 2) that has it loses the step (said);
    the validator refuses it; the mode switch keeps the updater's timer in both modes and gives back one an earlier switch
    took away; Bootstrap / Install-SIUpdaterJob keep 03:00 UTC; the VM flow task never disables the updater's task; and the
    pipeline does not start while an update runs (what waits stays queued) -- neither waits on the other. Offline; PS 5.1 + 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    $script:Map = Get-SIJobFlowMap
    $script:Installed = @('updater', 'ptc', 'identity', 'azure', 'endpoint', 'publicip', 'risk-analysis', 'risk-analysis-detailed', 'asset-datasync')
    function script:J([string]$Name, [string]$Trigger, [string]$Cron = '', [string]$Remembered = '') { [pscustomobject]@{ Name = $Name; TriggerType = $Trigger; Cron = $Cron; RememberedCron = $Remembered } }
    function script:Get-Code([string]$Rel) { ((Get-Content -LiteralPath (Join-Path $script:SIRoot $Rel)) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n" }
    function script:New-TempDir { $d = Join-Path ([IO.Path]::GetTempPath()) ('si393-{0}' -f ([guid]::NewGuid().ToString('N').Substring(0, 10))); New-Item -ItemType Directory -Path $d -Force | Out-Null; $d }
}

Describe 'the map and the default pipeline' {
    It 'the updater is never in the default pipeline, even when it is installed' {
        $d = New-SIDefaultJobFlow -Installed $script:Installed -Map $script:Map -StartTime '22:00' -TimeZone 'UTC'
        @($d.Steps | ForEach-Object Job) | Should -Not -Contain 'updater'
        $script:Map.DefaultFlow | Should -Not -Contain 'updater'
        foreach ($st in $script:Map.DefaultPipeline.Stages) { @($st.Steps) | Should -Not -Contain 'updater' }
    }
    It 'the map marks it: own schedule, never in the flow, daily 23:00 Danish time (two UTC ticks), no stage' {
        $u = $script:Map.Jobs['updater']
        $u.OwnSchedule | Should -BeTrue
        $u.NeverInFlow | Should -BeTrue
        $u.DefaultCron | Should -Be '30 16,17 * * *'
        $u.Stage | Should -BeNullOrEmpty
        Test-SIJobFlowOwnSchedule -Job 'caj-si-updater' -Map $script:Map | Should -BeTrue
        Test-SIJobFlowOwnSchedule -Job 'updater' | Should -BeTrue -Because 'the updater is one whatever the map says'
        Test-SIJobFlowOwnSchedule -Job 'ptc' -Map $script:Map | Should -BeFalse
    }
}

Describe 'a stored pipeline that has the updater as a step loses it (logged)' {
    It 'schema 2: the step is dropped, said in the notes, and the step that started together with it starts on its own' {
        $json = '{"schema":2,"id":"daily","name":"Daily pipeline","mode":"flow","startTime":"22:00","timeZone":"Europe/Copenhagen","cadence":"daily","weekday":1,"intervalMinutes":1440,' +
                '"stages":[{"id":"collect","name":"Collect","steps":[{"job":"updater","timeoutMinutes":60},{"job":"ptc","withPrevious":true,"timeoutMinutes":180},{"job":"endpoint"}]},' +
                '{"id":"correlate","name":"Correlate","steps":[]},{"id":"deliver","name":"Deliver","steps":[]}]}'
        $d = ConvertFrom-SIJobFlowJson -Json $json -Map $script:Map
        @($d.Steps | ForEach-Object Job) | Should -Be @('ptc', 'endpoint')
        @($d.Steps)[0].WithPrevious | Should -BeFalse
        $d.Migrated | Should -BeTrue
        ($d.MigrationNotes -join "`n") | Should -Match 'updater was a step of the stored pipeline and is taken out: the updater runs on its own daily schedule'
        $d.StartTime | Should -Be '22:00'; $d.TimeZone | Should -Be 'Europe/Copenhagen'
        (Test-SIJobFlowDefinition -Definition $d -Map $script:Map).Problems | Should -BeNullOrEmpty
        (ConvertTo-SIJobFlowJson -Definition $d) | Should -Not -Match '"job":"updater"' -Because 'saving it stores it without the step'
    }
    It 'schema 1: migrated to stages AND the updater step dropped; the other notes are kept' {
        $d = ConvertFrom-SIJobFlowJson -Json '{"startTime":"01:00","steps":[{"job":"updater"},{"job":"ptc"},{"job":"asset-trend"},{"job":"asset-datasync"}]}' -Map $script:Map
        @($d.Steps | ForEach-Object Job) | Should -Be @('ptc', 'asset-trend', 'asset-datasync')
        $d.Migrated | Should -BeTrue
        ($d.MigrationNotes -join "`n") | Should -Match 'updater was a step'
        ($d.MigrationNotes -join "`n") | Should -Match 'asset-trend is kept but switched off'
    }
    It 'a pipeline without the updater is read as it is (nothing migrated)' {
        $d = New-SIDefaultJobFlow -Installed $script:Installed -Map $script:Map -StartTime '22:00' -TimeZone 'UTC'
        $back = ConvertFrom-SIJobFlowJson -Json (ConvertTo-SIJobFlowJson -Definition $d) -Map $script:Map
        $back.Migrated | Should -BeFalse
        @($back.MigrationNotes).Count | Should -Be 0
    }
    It 'the runner logs the notes, and its log line does not claim the older form' {
        $s = Get-Code 'engine\flow\Invoke-SIJobFlowRun.ps1'
        $s | Should -Match 'foreach \(\$n in @\(\$pipeDefinition\.MigrationNotes\)\)'
        $s | Should -Not -Match 'older one-list form'
    }
}

Describe 'the validator refuses the updater as a step' {
    It 'says why: the updater runs on its own daily schedule' {
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'endpoint') -Map $script:Map -StartTime '22:00' -TimeZone 'UTC'
        $d.Steps = @((New-SIJobFlowStep -Job 'updater' -Stage 'collect' -TimeoutMinutes 60)) + @($d.Steps)
        $r = Test-SIJobFlowDefinition -Definition $d -Map $script:Map
        ($r.Problems -join "`n") | Should -Match 'step 1: updater is never part of the pipeline -- the updater runs on its own daily schedule'
    }
}

Describe 'the mode switch keeps (and gives back) the updater''s own timer' {
    It 'to the pipeline: an updater on its timer keeps it -- never to-manual' {
        $p = Get-SIJobOrchestrationSwitchPlan -Jobs @((J 'caj-si-updater' 'Schedule' '0 3 * * *'), (J 'caj-si-ptc' 'Schedule' '0 1 * * *'), (J 'caj-si-flow' 'Manual' '' '*/5 * * * *')) -Mode flow -Map $script:Map
        $u = @($p | Where-Object Job -eq 'caj-si-updater')[0]
        $u.Action | Should -Be 'keep'; $u.Cron | Should -Be '0 3 * * *'
        $u.Why | Should -Match 'own daily schedule'
        @($p | Where-Object Job -eq 'caj-si-ptc')[0].Action | Should -Be 'to-manual' -Because 'a real step still loses its timer'
    }
    It 'to the pipeline: an updater an earlier switch turned to manual gets its remembered timer back (ring 1, 2026-10-06)' {
        $p = Get-SIJobOrchestrationSwitchPlan -Jobs @((J 'caj-si-updater' 'Manual' '' '0 3 * * *'), (J 'caj-si-flow' 'Schedule' '*/5 * * * *')) -Mode flow -Map $script:Map
        $u = @($p | Where-Object Job -eq 'caj-si-updater')[0]
        $u.Action | Should -Be 'to-schedule'; $u.Cron | Should -Be '0 3 * * *'
    }
    It 'to schedules: the same -- kept on its timer, or its remembered timer back' {
        $p = Get-SIJobOrchestrationSwitchPlan -Jobs @((J 'caj-si-updater' 'Schedule' '0 3 * * *')) -Mode schedules -Map $script:Map
        @($p)[0].Action | Should -Be 'keep'
        $p = Get-SIJobOrchestrationSwitchPlan -Jobs @((J 'caj-si-updater' 'Manual' '' '0 2 * * *')) -Mode schedules -Map $script:Map
        @($p)[0].Action | Should -Be 'to-schedule'; @($p)[0].Cron | Should -Be '0 2 * * *' -Because 'the remembered timer is the one it had'
    }
    It 'an updater with no timer and none remembered is kept and the plan says how to give it one' {
        $p = Get-SIJobOrchestrationSwitchPlan -Jobs @((J 'caj-si-updater' 'Manual')) -Mode flow -Map $script:Map
        @($p)[0].Action | Should -Be 'keep'
        @($p)[0].Why | Should -Match 'Install-SIUpdaterJob\.ps1'
        @($p)[0].Why | Should -Match '30 16,17 \* \* \*'
    }
    It 'a stored definition that still lists the updater does not make it a step of the switch' {
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map -StartTime '22:00' -TimeZone 'UTC'
        $d.Steps = @((New-SIJobFlowStep -Job 'updater' -Stage 'collect')) + @($d.Steps)
        $p = Get-SIJobOrchestrationSwitchPlan -Jobs @((J 'caj-si-updater' 'Schedule' '0 3 * * *'), (J 'caj-si-ptc' 'Schedule' '0 1 * * *')) -Mode flow -Definition $d -Map $script:Map
        @($p | Where-Object Job -eq 'caj-si-updater')[0].Action | Should -Be 'keep'
        @($p | Where-Object Job -eq 'caj-si-ptc')[0].Why | Should -Match 'step 1 of the flow'
    }
    It 'the ARM body restores the remembered timer and removes the tag (what -Apply sends for to-schedule)' {
        $job = ([ordered]@{ name = 'caj-si-updater'; tags = @{ 'si-disabled-cron' = '0 3 * * *'; 'si-installed' = '3.0.0-rc.343' }
                            properties = [ordered]@{ configuration = [ordered]@{ triggerType = 'Manual'; replicaTimeout = 3600; manualTriggerConfig = @{ parallelism = 1; replicaCompletionCount = 1 } } } } | ConvertTo-Json -Depth 8) | ConvertFrom-Json
        $b = ConvertTo-SIArmJobTrigger -Job $job -Action 'to-schedule'
        $b.properties.configuration.triggerType | Should -Be 'Schedule'
        $b.properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '0 3 * * *'
        $b.tags.PSObject.Properties['si-disabled-cron'] | Should -BeNullOrEmpty
        $b.tags.'si-installed' | Should -Be '3.0.0-rc.343' -Because 'what runs (the updater''s record) is kept'
    }
}

Describe 'Bootstrap, Install-SIUpdaterJob and the VM keep the updater on its own timer (23:00 Danish time)' {
    It 'Bootstrap: an updater it creates is on a timer in both modes' {
        (Get-SIBootstrapTriggerPlan -Engine 'updater' -Mode flow -Cron '0 3 * * *' -Map $script:Map).Trigger | Should -Be 'Schedule'
        (Get-SIBootstrapTriggerPlan -Engine 'updater' -Mode schedules -Cron '0 3 * * *' -Map $script:Map).Trigger | Should -Be 'Schedule'
    }
    It 'Install-SIUpdaterJob: the region zone''s nightly ticks by default, and an updater found without a timer is put back on it (PATCH of the trigger only)' {
        $s = Get-Code 'setup\Install-SIUpdaterJob.ps1'
        # owner 2026-10-15: 23:00 in the local time of the install's Azure region -- computed, not a fixed cron (SIv3-NightlySchedule)
        $s | Should -Match "\[string\]\`$Schedule\s+= '',"
        $s | Should -Match '\$Schedule = \$nightly\.UpdaterCron'
        $s | Should -Match "triggerType -eq 'Manual'"
        $s | Should -Match "ConvertTo-SIArmJobTrigger -Job \`$existing -Action 'to-schedule' -Cron \`$Schedule"
        # #521: over ARM REST, never `az rest`
        $s | Should -Match "Invoke-SIArm -Method PATCH -Path \(\[string\]\`$existing\.id\) -ApiVersion '2025-07-01' -Body \`$body"
        $s | Should -Not -Match "'rest', '--method'"
        # the PATCH comes BEFORE the update (the read-modify-write sets a cron only on a Schedule job)
        $s.IndexOf("ConvertTo-SIArmJobTrigger -Job `$existing") | Should -BeLessThan $s.IndexOf("-Cron `$Schedule -Image `$image")
    }
    It 'VM: the flow task never disables the updater''s task, and gives back one an earlier setup disabled' {
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map -StartTime '22:00' -TimeZone 'UTC'
        $d.Steps = @((New-SIJobFlowStep -Job 'updater' -Stage 'collect')) + @($d.Steps)   # a stale custom definition
        $tasks = @([pscustomobject]@{ TaskPath = '\SecurityInsight\'; TaskName = '1. Update'; State = 'Ready'; Execute = 'powershell.exe'; Arguments = '-File C:\SecurityInsight\Update-SecurityInsight.ps1 -Apply' })
        $r = Get-SIFlowTaskReplacePlan -Tasks $tasks -Definition $d -Map $script:Map   # returns its array as one object
        $r.Count | Should -Be 0
        $s = Get-Code 'setup\Install-SIFlowTask.ps1'
        $s | Should -Match 'Test-SIJobFlowOwnSchedule -Job \(\[string\]\$_\.Job\)'
        $s | Should -Match 'Enable-ScheduledTask -TaskPath \$t\.TaskPath'
    }
}

Describe 'the pipeline never starts while an update runs (and the updater never starts under the pipeline)' {
    BeforeEach {
        $script:Dir = New-TempDir
        $script:QClock = [datetime]::SpecifyKind([datetime]'2026-10-06T03:02:00', 'Utc')
        $script:Ctl = New-SIPipelineDocControl -Docs (New-SIPipelineFileDocs -Folder $script:Dir) -Now { $script:QClock }
        $script:Def = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map -StartTime '22:00' -TimeZone 'UTC'
        $script:RunLog = New-Object System.Collections.Generic.List[string]
        $script:Logs = New-Object System.Collections.Generic.List[string]
        $script:LogSb = { param($l, $m) $script:Logs.Add(('{0} {1}' -f $l, $m)) }
        $script:RunOne = { param($Req, $Prev, $Fid) $script:RunLog.Add($(if ($Req) { Get-SIPipelineRequestKey $Req } else { 'resume' })); [pscustomobject]@{ FlowRunId = $Fid; State = 'Succeeded'; Outcome = 'New'; Steps = @() } }
    }
    AfterEach { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }
    It 'an update runs: nothing starts, the Run now stays queued; when it has finished the next wake-up runs it' {
        $script:Update = 'caj-si-updater execution caj-si-updater-x1'
        $out = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $null } -RunOne $script:RunOne -Request (New-SIPipelineRequest -Scope stage -Target collect -RequestedBy 'ann@example.test') `
                   -Holder 'w1' -Now { $script:QClock } -Log $script:LogSb -UpdateRunning { $script:Update }
        $out.Outcome | Should -Be 'Busy'
        $out.Lock.What | Should -Match 'an update of SecurityInsight'
        $script:RunLog.Count | Should -Be 0
        @($script:Ctl.List() | Where-Object State -eq 'Queued').Count | Should -Be 1
        $script:Ctl.ReadLock() | Should -BeNullOrEmpty -Because 'the pipeline took no lock while it waited'
        ($script:Logs -join "`n") | Should -Match 'an update of SecurityInsight is running .* nothing starts until it has finished; 1 request\(s\) wait in the queue'
        # the update ends; the next wake-up runs what waited
        $script:Update = ''; $script:QClock = $script:QClock.AddMinutes(5)
        $out = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $null } -RunOne $script:RunOne -Holder 'w2' -Now { $script:QClock } -Log $script:LogSb -UpdateRunning { $script:Update }
        $out.Outcome | Should -Be 'Ran'
        @($script:RunLog) | Should -Be @('stage|collect')
    }
    It 'a check that fails never stops the pipeline (the updater waits for the pipeline anyway)' {
        $out = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $null } -RunOne $script:RunOne -Request (New-SIPipelineRequest -Scope step -Target ptc) `
                   -Holder 'w' -Now { $script:QClock } -Log $script:LogSb -UpdateRunning { throw 'ARM GET returned 503' }
        $out.Outcome | Should -Be 'Ran'
        ($script:Logs -join "`n") | Should -Match 'WARN whether an update is running could not be checked \(ARM GET returned 503\)'
    }
    It 'the check asks ARM through the plain ARM seams, also when the install collects in parts (ring 1, 2026-10-12)' {
        # with a producer job the runner's $seams is the collect-in-parts wrapper: it has no Arm / Base, so the check
        # failed on every wake-up and the pipeline could start under an update
        $parts = Add-SIJobFlowCollectParts -Seams (New-SIJobFlowArmSeams -SubscriptionId 's' -ResourceGroup 'r' -Arm { }) -Store ([pscustomobject]@{}) -ProducerJobs @('caj-si-identity-producer')
        $parts.PSObject.Properties['Arm'] | Should -BeNullOrEmpty -Because 'this is why the runner keeps the plain seams'
        $code = Get-Code 'engine\flow\Invoke-SIJobFlowRun.ps1'
        $code | Should -Match '\$armSeams = \$seams'
        # CR5 step 1 (#655): the updater job is named by the install record (Get-SIInstallName -Role updater), never a literal
        $code | Should -Match '& \$armSeams\.Arm ''GET'' \(''\{0\}/\{1\}/executions'' -f \$armSeams\.Base, \$updaterJobName\)'
        $code | Should -Match '\$updaterJobName = Get-SIInstallName -Role updater -Record \(Read-SIInstallNamesRecord -Store \$proStore\)'
        $code.IndexOf('$armSeams = $seams') | Should -BeLessThan $code.IndexOf('Add-SIJobFlowCollectParts') -Because 'kept before the wrapper replaces $seams'
    }
    It 'what counts as a running update: a Running / Processing execution of the updater, or Update-SecurityInsight.ps1 on a VM' {
        $now = [datetime]::SpecifyKind([datetime]'2026-10-06T03:10:00', 'Utc')
        $ex = { param($n, $s, $t) [pscustomobject]@{ name = $n; properties = [pscustomobject]@{ status = $s; startTime = $t } } }
        Get-SIPipelineUpdateRunning -Executions @((& $ex 'u-1' 'Succeeded' '2026-10-05T03:00:00Z')) -NowUtc $now | Should -BeNullOrEmpty
        Get-SIPipelineUpdateRunning -Executions @((& $ex 'u-2' 'Running' '2026-10-06T03:00:00Z')) -NowUtc $now | Should -Match 'caj-si-updater execution u-2'
        Get-SIPipelineUpdateRunning -Executions @((& $ex 'u-3' 'Processing' '2026-10-06T03:00:00Z')) -NowUtc $now | Should -Match 'u-3'
        Get-SIPipelineUpdateRunning -Executions @((& $ex 'u-4' 'Running' '2026-10-05T03:00:00Z')) -NowUtc $now | Should -BeNullOrEmpty -Because 'older than the updater can run: Azure''s stale record'
        Get-SIPipelineUpdateRunning -Processes @('powershell.exe -File C:\SI\engine\flow\Invoke-SIJobFlowRun.ps1', 'powershell.exe -File "C:\SI\Update-SecurityInsight.ps1" -Apply') | Should -Match 'Update-SecurityInsight\.ps1 is running'
        Get-SIPipelineUpdateRunning | Should -BeNullOrEmpty
    }
    It 'the runner asks before it starts anything: the updater''s executions (container), its script (VM)' {
        $s = Get-Code 'engine\flow\Invoke-SIJobFlowRun.ps1'
        $s | Should -Match '/\{1\}/executions'' -f \$armSeams\.Base, \$updaterJobName'
        $s | Should -Match 'Get-SIPipelineUpdateRunning -Executions'
        $s | Should -Match 'Get-SIPipelineUpdateRunning -Processes'
        $s | Should -Match 'Invoke-SIPipelineDrain .*-UpdateRunning \$updateRunning'
    }
    It 'a running pipeline run HOLDS the update (owner 2026-10-23, replaces the 2026-10-12 rule): the run gate decides, before the roll' -Tag 'PrivateRepo' {
        # the pre-roll lives in SI-UpdaterRollSteps.ps1 since 2026-10-27 (#750 (b): shared with the Community updater)
        $s = (Get-Code 'container\updater\_shared\SI-UpdaterInvardia.ps1') + "`n" + (Get-Code 'container\updater\_shared\SI-UpdaterRollSteps.ps1')
        # the ARM wait for no SI job at all is still reached only inside the branch of a release that says it needs quiet
        $s | Should -Match '(?s)\$quiet = Get-SIUpdaterNeedsQuiet -SIRoot \$SIRoot\s+if \(\$quiet\) \{.{0,400}Wait-SIUpdaterPipelineIdle -JobNames'
        [regex]::Matches($s, 'Wait-SIUpdaterPipelineIdle -JobNames').Count | Should -Be 1
        $s | Should -Not -Match 'the update is installed now: a job already running finishes on the version it started with'
        $s | Should -Match 'owner 2026-10-23'
        $s | Should -Match 'REPLACES the rule of\s+(#\s+)?2026-10-12'
        $s | Should -Match 'Invoke-SIUpdaterInvardiaPreRoll .*-WaitMinutes \$waitMin -SIRoot \$si'
        $s | Should -Match "SI_UPDATER_WAIT_MINUTES"
        # the gate comes before the roll, the size step and the template publish
        $s.IndexOf('$gr = & $passGate') | Should -BeLessThan $s.IndexOf('$roll = Invoke-SIUpdaterRoll')
        $s.IndexOf('$grS = & $passGate') | Should -BeLessThan $s.IndexOf('$null = Invoke-SIUpdaterSizingPass')
        $s | Should -Match "-eq 'update' -and \(& \`$templatesGo\)"
    }
    It 'a release needs quiet only when it carries UPDATE-NEEDS-QUIET.txt; the first line is the reason' -Tag 'PrivateRepo' {
        $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        . (Join-Path $root 'container\updater\_shared\SI-UpdaterInvardia.ps1')
        $d = Join-Path ([IO.Path]::GetTempPath()) ('si-quiet-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $d -Force
        try {
            Get-SIUpdaterNeedsQuiet -SIRoot $d | Should -Be ''
            Get-SIUpdaterNeedsQuiet -SIRoot '' | Should -Be ''
            [IO.File]::WriteAllText((Join-Path $d 'UPDATE-NEEDS-QUIET.txt'), "the findings table is rebuilt`r`nmore text")
            Get-SIUpdaterNeedsQuiet -SIRoot $d | Should -Be 'the findings table is rebuilt'
            [IO.File]::WriteAllText((Join-Path $d 'UPDATE-NEEDS-QUIET.txt'), '')
            Get-SIUpdaterNeedsQuiet -SIRoot $d | Should -Be 'the release asks for it'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'this release carries UPDATE-NEEDS-QUIET.txt only with its REMOVE-ME (#897/#898: the release that brings the run gate)' -Tag 'PrivateRepo' {
        # REMOVE-ME (#898): in the release after the run gate, the file goes and this test is "carries no UPDATE-NEEDS-QUIET.txt" again
        $f = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'UPDATE-NEEDS-QUIET.txt'
        if (Test-Path -LiteralPath $f) {
            $t = [IO.File]::ReadAllText($f)
            $t | Should -Match 'REMOVE-ME' -Because 'the file is for ONE release: the one whose older updater has no run gate'
            $t | Should -Match 'run gate'
        }
    }
}
