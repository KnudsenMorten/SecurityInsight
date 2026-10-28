#Requires -Version 5.1
<#
    #269 -- how the daily job flow is SET UP: Bootstrap's mode decision and job triggers (a new install = the flow, an
    existing install keeps its timers), the previewed + reversible switch between flow and schedules (container), the
    ARM job body that moves a job into / out of the flow (the same transformation as the web app's Disable / Enable),
    and the VM setup step that replaces the per-engine scheduled tasks with one flow task. Offline; PS 5.1 + 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    $script:Map = Get-SIJobFlowMap
    function script:Get-Code([string]$Rel) { ((Get-Content -LiteralPath (Join-Path $script:SIRoot $Rel)) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n" }
    function script:J([string]$Name, [string]$Trigger, [string]$Cron = '', [string]$Remembered = '') { [pscustomobject]@{ Name = $Name; TriggerType = $Trigger; Cron = $Cron; RememberedCron = $Remembered } }
    function script:ArmJob([string]$Trigger, [string]$Cron, [hashtable]$Tags = @{}) {
        # As ARM's GET returns a Pro job: its secrets WITHOUT values (si-license), env, registries.
        $cfg = [ordered]@{ triggerType = $Trigger; replicaTimeout = 3600; secrets = @(@{ name = 'si-license' }); registries = @(@{ server = 'acr.azurecr.io'; identity = 'system' }) }
        if ($Trigger -eq 'Schedule') { $cfg.scheduleTriggerConfig = [ordered]@{ cronExpression = $Cron; parallelism = 2; replicaCompletionCount = 2 } } else { $cfg.manualTriggerConfig = [ordered]@{ parallelism = 2; replicaCompletionCount = 2 } }
        ([ordered]@{ name = 'caj-si-endpoint'; location = 'westeurope'; tags = $Tags; systemData = @{ createdBy = 'x' }; properties = [ordered]@{ provisioningState = 'Succeeded'; configuration = $cfg; template = @{ containers = @(@{ name = 'c'; image = 'i'; env = @(@{ name = 'SI_LICENSE'; secretRef = 'si-license' }) }) } } } | ConvertTo-Json -Depth 10) | ConvertFrom-Json
    }
    function script:BodyKeys($o) { @($o.PSObject.Properties | ForEach-Object { $_.Name }) -join ',' }
}

Describe 'Bootstrap: the trigger a NEW job gets' {
    It 'flow mode: a job of the flow is Manual with its timer remembered; caj-si-flow is the one timer' {
        $t = Get-SIBootstrapTriggerPlan -Engine 'endpoint' -Mode flow -Cron '0 4 * * *' -Map $script:Map
        $t.Trigger | Should -Be 'Manual'; $t.RememberCron | Should -Be '0 4 * * *'
        (Get-SIBootstrapTriggerPlan -Engine 'flow' -Mode flow -Cron '0 1 * * *' -Map $script:Map).Trigger | Should -Be 'Schedule'
        (Get-SIBootstrapTriggerPlan -Engine 'privilege-tier-classifier' -Mode flow -Cron '0 1 * * *' -Map $script:Map).Trigger | Should -Be 'Manual'
        (Get-SIBootstrapTriggerPlan -Engine 'asset-vulnerabilities-servicenow' -Mode flow -Cron '15 10 * * *' -Map $script:Map).Trigger | Should -Be 'Manual'
    }
    It 'flow mode: a job never in the flow keeps its timer (asset tagging, schema discovery)' {
        (Get-SIBootstrapTriggerPlan -Engine 'asset-tagging' -Mode flow -Cron '50 5 * * *' -Map $script:Map).Trigger | Should -Be 'Schedule'
        (Get-SIBootstrapTriggerPlan -Engine 'schema-discovery' -Mode flow -Cron '0 3 * * 0' -Map $script:Map).Trigger | Should -Be 'Schedule'
    }
    It 'schedules mode: every job on its timer; caj-si-flow waits with its time remembered' {
        (Get-SIBootstrapTriggerPlan -Engine 'endpoint' -Mode schedules -Cron '0 4 * * *' -Map $script:Map).Trigger | Should -Be 'Schedule'
        $f = Get-SIBootstrapTriggerPlan -Engine 'flow' -Mode schedules -Cron '0 1 * * *' -Map $script:Map
        $f.Trigger | Should -Be 'Manual'; $f.RememberCron | Should -Be '0 1 * * *'
    }
    It 'the create arguments become Manual + the remembered-timer tag, nothing else changes' {
        $a = @('containerapp', 'job', 'create', '--name', 'caj-si-endpoint', '--trigger-type', 'Schedule', '--replica-timeout', '3600', '--cron-expression', '0 4 * * *', '--image', 'img')
        $m = ConvertTo-SIManualCreateArgs -CreateArgs $a -RememberCron '0 4 * * *'
        ($m -join '|') | Should -Be 'containerapp|job|create|--name|caj-si-endpoint|--trigger-type|Manual|--replica-timeout|3600|--image|img|--tags|si-disabled-cron=0 4 * * *'
    }
    It 'Bootstrap: new install = flow, existing = timers, an existing job''s trigger is never changed, the flow job gets 7 days and its grant' {
        $b = Get-Code 'Bootstrap-ContainerAppJob.ps1'
        $b | Should -Match 'Get-SIJobOrchestrationMode -Explicit \$JobOrchestration -ExistingInstall'
        $b | Should -Match "if \(@\(\`$Engines\) -notcontains 'flow'\) \{ \`$Engines = @\(\`$Engines\) \+ @\('flow'\) \}"
        $b | Should -Match 'ConvertTo-SIManualCreateArgs -CreateArgs \$createArgs -RememberCron \$trigPlan\.RememberCron'
        $b | Should -Match "if \(-not \`$isManualOnly -and -not \`$existingManual\) \{ \`$upd\['Cron'\] = \`$schedule \}"
        $b | Should -Match '\$jobRes\.ReplicaTimeout = Get-SIFlowJobReplicaTimeout'
        $b | Should -Match "Role = 'Container Apps Jobs Contributor'"
        $b | Should -Match "ScheduleFlow                = '\*/5 \* \* \* \*'"
        $b | Should -Match '-not \$isFlow\)'
    }
}

Describe 'switching between the flow and schedules (preview, reversible)' {
    BeforeAll {
        $script:Jobs = @((J 'caj-si-ptc' 'Schedule' '0 1 * * *'), (J 'caj-si-endpoint' 'Schedule' '0 4 * * *'), (J 'caj-si-identity' 'Schedule' '30 4 * * *'),
                         (J 'caj-si-asset-tagging' 'Schedule' '50 5 * * *'), (J 'caj-si-templates' 'Manual'), (J 'caj-si-endpoint-worker' 'Event'),
                         (J 'caj-si-flow' 'Manual' '' '0 1 * * *'))
    }
    It 'to the flow: the flow''s jobs lose their timer (remembered), the flow gets its start time, the rest is kept' {
        $p = Get-SIJobOrchestrationSwitchPlan -Jobs $script:Jobs -Mode flow -Map $script:Map
        $by = @{}; foreach ($x in $p) { $by[$x.Job] = $x }
        $by['caj-si-ptc'].Action | Should -Be 'to-manual'
        $by['caj-si-endpoint'].Why | Should -Match 'remembered'
        $by['caj-si-flow'].Action | Should -Be 'to-schedule'; $by['caj-si-flow'].Cron | Should -Be '*/5 * * * *' -Because 'the cron only wakes the runner (SCHED-1.1)'
        $by['caj-si-asset-tagging'].Action | Should -Be 'keep'
        $by['caj-si-templates'].Action | Should -Be 'keep'
        $by['caj-si-endpoint-worker'].Action | Should -Be 'keep'
    }
    It 'back to schedules: the remembered timers return; a job without one gets the default in dependency order' {
        $jobs = @((J 'caj-si-ptc' 'Manual' '' '0 1 * * *'), (J 'caj-si-endpoint' 'Manual' '' '15 3 * * *'), (J 'caj-si-asset-datasync' 'Manual'), (J 'caj-si-flow' 'Schedule' '0 1 * * *'))
        $p = Get-SIJobOrchestrationSwitchPlan -Jobs $jobs -Mode schedules -Map $script:Map
        $by = @{}; foreach ($x in $p) { $by[$x.Job] = $x }
        $by['caj-si-endpoint'].Cron | Should -Be '15 3 * * *'
        $by['caj-si-asset-datasync'].Cron | Should -Be '30 10 * * *'
        $by['caj-si-asset-datasync'].Why | Should -Match 'default'
        $by['caj-si-flow'].Action | Should -Be 'to-manual'
    }
    It 'the ARM body: to-manual remembers the timer in the tag (as Disable); to-schedule restores it (as Enable)' {
        $m = ConvertTo-SIArmJobTrigger -Job (ArmJob 'Schedule' '0 4 * * *' @{ owner = 'si' }) -Action to-manual
        $m.properties.configuration.triggerType | Should -Be 'Manual'
        $m.tags.'si-disabled-cron' | Should -Be '0 4 * * *'
        $m.tags.owner | Should -Be 'si' -Because 'the PATCH replaces the tag set, so every existing tag is carried'
        $m.properties.configuration.PSObject.Properties['scheduleTriggerConfig'] | Should -BeNullOrEmpty
        $m.properties.configuration.manualTriggerConfig.parallelism | Should -Be 2
        $m.properties.configuration.manualTriggerConfig.replicaCompletionCount | Should -Be 2
        $m.properties.configuration.replicaTimeout | Should -Be 3600
        $back = ConvertTo-SIArmJobTrigger -Job (ArmJob 'Manual' '' @{ owner = 'si'; 'si-disabled-cron' = '0 4 * * *' }) -Action to-schedule
        $back.properties.configuration.triggerType | Should -Be 'Schedule'
        $back.properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '0 4 * * *'
        $back.properties.configuration.scheduleTriggerConfig.parallelism | Should -Be 2
        $back.properties.configuration.PSObject.Properties['manualTriggerConfig'] | Should -BeNullOrEmpty
        $back.tags.PSObject.Properties['si-disabled-cron'] | Should -BeNullOrEmpty
        $back.tags.owner | Should -Be 'si'
        (ConvertTo-SIArmJobTrigger -Job $m -Action to-schedule).properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '0 4 * * *' -Because 'a PATCH body round-trips'
        (ConvertTo-SIArmJobTrigger -Job (ArmJob 'Manual' '') -Action to-schedule -Cron '30 10 * * *').properties.configuration.scheduleTriggerConfig.cronExpression | Should -Be '30 10 * * *'
        { ConvertTo-SIArmJobTrigger -Job (ArmJob 'Manual' '') -Action to-schedule } | Should -Throw '*not a 5-field cron*'
        { ConvertTo-SIArmJobTrigger -Job (ArmJob 'Manual' '') -Action to-manual } | Should -Throw '*only a scheduled job*'
    }
    It 'the ARM body is a PATCH of ONLY tags + the trigger: never the secrets (ARM returns them without values), the template or anything else' {
        foreach ($b in @((ConvertTo-SIArmJobTrigger -Job (ArmJob 'Schedule' '0 4 * * *') -Action to-manual),
                         (ConvertTo-SIArmJobTrigger -Job (ArmJob 'Manual' '' @{ 'si-disabled-cron' = '0 4 * * *' }) -Action to-schedule))) {
            BodyKeys $b | Should -Be 'tags,properties'
            BodyKeys $b.properties | Should -Be 'configuration'
            (BodyKeys $b.properties.configuration) | Should -Match '^triggerType,replicaTimeout,(manualTriggerConfig|scheduleTriggerConfig)$'
            $json = $b | ConvertTo-Json -Depth 20
            $json | Should -Not -Match 'secrets|si-license|template|registries|systemData|provisioningState|location'
        }
        $j = ArmJob 'Schedule' '0 4 * * *' @{ owner = 'si' }
        $before = $j | ConvertTo-Json -Depth 20
        $null = ConvertTo-SIArmJobTrigger -Job $j -Action to-manual
        ($j | ConvertTo-Json -Depth 20) | Should -Be $before -Because 'the input is not changed'
        (ConvertTo-SIArmJobTrigger -Job (ArmJob 'Schedule' '0 4 * * *') -Action to-manual | ConvertTo-Json -Depth 20 -Compress) | Should -Match '"tags":\{"si-disabled-cron":"0 4 \* \* \*"\}'
        (ConvertTo-SIArmJobTrigger -Job (ArmJob 'Manual' '' @{ 'si-disabled-cron' = '0 4 * * *' }) -Action to-schedule | ConvertTo-Json -Depth 20 -Compress) | Should -Match '"tags":\{\}' -Because 'the remembered timer is removed from the tags'
    }
    It 'Azure''s refusal text survives: the az error becomes the ARM code and message' {
        $line = 'ERROR: Bad Request({"error":{"code":"ContainerAppSecretInvalid","message":"Container app secret(s) with name(s) ''si-license'' are invalid: value or keyVaultUrl and identity should be provided"}})'
        $m = Get-SIAzErrorMessage -Lines @($line)
        $m | Should -BeLike 'ContainerAppSecretInvalid: Container app secret(s) with name(s) ''si-license'' are invalid*'
        Get-SIAzErrorMessage -Lines @('ERROR: (AuthorizationFailed) The client does not have authorization') | Should -BeLike 'AuthorizationFailed*'
        Get-SIAzErrorMessage -Lines @() | Should -Be '(az printed no error text)'
    }
}

Describe 'the switch script against a fake ARM (REST, no az CLI -- PATCH, and a failure is never silent)' {
    BeforeAll {
        $script:Switch = Join-Path $script:SIRoot 'setup\Switch-SIJobOrchestration.ps1'
        # #521: the script reaches ARM through setup's REST layer -- loaded here, so the script reuses it and the ONE HTTP
        # seam (Invoke-SIAzRestHttp) is this test's fake. Signed in as an app; every token from the hook.
        . (Join-Path $script:SIRoot 'setup\_shared\SI-SetupAzure.ps1')
        $global:SI_TokenProvider = { param($Resource) (@('e30', [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"tid":"t"}')).TrimEnd('='), 'c2ln') -join '.') }   # a fake token, built here
        $global:SISwitchTestCalls = New-Object System.Collections.Generic.List[object]
        $global:SISwitchTestFail = @()
        Mock Invoke-SIAzRestHttp {
            $global:SISwitchTestCalls.Add([pscustomobject]@{ Method = $Method; Url = $Uri; Body = $(if ($null -ne $Body) { [string]$Body } else { $null }) })
            $path = ($Uri -split '\?')[0]
            $job = { param($n, $t, $c) $cfg = [ordered]@{ triggerType = $t; replicaTimeout = 3600; secrets = @(@{ name = 'si-license' }) }
                     if ($t -eq 'Schedule') { $cfg.scheduleTriggerConfig = @{ cronExpression = $c; parallelism = 1; replicaCompletionCount = 1 } } else { $cfg.manualTriggerConfig = @{ parallelism = 1; replicaCompletionCount = 1 } }
                     [ordered]@{ name = $n; tags = @{ owner = 'si' }; properties = [ordered]@{ configuration = $cfg; template = @{ containers = @(@{ name = 'c'; image = 'i' }) } } } }
            $all = @((& $job 'caj-si-endpoint' 'Schedule' '0 4 * * *'), (& $job 'caj-si-asset-correlation' 'Schedule' '0 6 * * *'), (& $job 'caj-si-flow' 'Manual' ''))
            $ok = { param($c) [pscustomobject]@{ StatusCode = 200; Content = $c; Bytes = $null; Headers = @{}; RetryAfter = $null } }
            if ($Method -eq 'GET' -and $path -match '/jobs$') { return (& $ok (@{ value = $all } | ConvertTo-Json -Depth 20)) }
            $name = ($path -split '/')[-1]
            if ($Method -eq 'GET' -and $path -match '/jobs/') { return (& $ok ($all | Where-Object { $_.name -eq $name } | ConvertTo-Json -Depth 20)) }
            if ($Method -eq 'PATCH' -and $global:SISwitchTestFail -contains $name) {
                return [pscustomobject]@{ StatusCode = 400; Headers = @{}; RetryAfter = $null; Bytes = $null
                    Content = '{"error":{"code":"ContainerAppSecretInvalid","message":"Container app secret(s) with name(s) ''si-license'' are invalid: value or keyVaultUrl and identity should be provided"}}' }
            }
            & $ok '{}'
        }
    }
    BeforeEach {
        $global:SISwitchTestCalls.Clear(); $global:SISwitchTestFail = @()
        $st = Get-SIAzRestState; $st.Connection = @{ Mode = 'Secret'; AppId = 'app'; TenantId = 't'; Secret = 'x' }; $st.TenantId = 't'; $st.SubscriptionId = '00000000-0000-0000-0000-000000000000'; $st.Cache = @{}
    }
    AfterAll { Remove-Variable -Scope Global -Name SI_TokenProvider -ErrorAction SilentlyContinue; Remove-Variable -Scope Global -Name SI_AzRestState -ErrorAction SilentlyContinue }

    It 'calls no az CLI: ARM through the REST layer only' {
        $s = Get-Code 'setup\Switch-SIJobOrchestration.ps1'
        $s | Should -Not -Match '(?m)&\s*az\b|\baz\s+rest\b'
        $s | Should -Match 'Invoke-SIArm -Method \$Method -Path \$Path -ApiVersion \$ApiVersion'
    }

    It 'moves the jobs with PATCH and a body without secrets or template -- never a PUT' {
        $null = & $script:Switch -Mode flow -ResourceGroupName rg-x -SubscriptionId 00000000-0000-0000-0000-000000000000 -Apply 6>$null
        $writes = @($global:SISwitchTestCalls | Where-Object { $_.Method -ne 'GET' })
        $writes.Count | Should -BeGreaterThan 0
        @($writes | Where-Object { $_.Method -ne 'PATCH' }).Count | Should -Be 0
        foreach ($w in $writes) { $w.Body | Should -Not -Match 'secrets|si-license|template' }
        ($writes | Where-Object { $_.Url -match 'caj-si-endpoint\?' }).Body | Should -Match 'si-disabled-cron'
    }
    It 'a job Azure refuses fails the run with Azure''s reason, even with warnings silenced by the caller' {
        $global:SISwitchTestFail = @('caj-si-endpoint')
        $WarningPreference = 'SilentlyContinue'
        $err = $null
        try { $null = & $script:Switch -Mode flow -ResourceGroupName rg-x -SubscriptionId 00000000-0000-0000-0000-000000000000 -Apply 6>$null } catch { $err = $_.Exception.Message }
        $err | Should -Not -BeNullOrEmpty -Because 'a job that was not switched must end the run in an error'
        $err | Should -Match 'caj-si-endpoint'
        $err | Should -Match 'ContainerAppSecretInvalid'
        $err | Should -Match '1 of \d+ job\(s\) were not switched'
        @($global:SISwitchTestCalls | Where-Object { $_.Method -eq 'PATCH' -and $_.Url -match 'caj-si-flow\?' }).Count | Should -Be 1 -Because 'the other jobs are still attempted'
    }
    It 'prints the failure list with Write-Host (red), not only as a warning' {
        $s = Get-Code 'setup\Switch-SIJobOrchestration.ps1'
        $s | Should -Match "job\(s\) were NOT switched:' -f \`$failed\.Count\) -ForegroundColor Red"
        $s | Should -Not -Match '2>\$null'
        $s | Should -Not -Match "'PUT'"
    }
    It 'the switch script previews without -Apply and is the documented way for a container install' {
        $s = Get-Code 'setup\Switch-SIJobOrchestration.ps1'
        $s | Should -Match 'if \(-not \$Apply\) \{ return \$plan \}'
        $s | Should -Match 'ConvertTo-SIArmJobTrigger -Job \$job -Action \$p\.Action'
    }
}

Describe 'the VM setup step (one flow task instead of one task per engine)' {
    It 'finds the per-engine tasks that run a step of the flow -- Risk Analysis Summary and Detailed told apart; never the updater''s task' {
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'endpoint', 'risk-analysis', 'risk-analysis-detailed', 'updater') -Map $script:Map
        $tasks = @(
            [pscustomobject]@{ TaskPath = '\SecurityInsight\'; TaskName = '1. Update'; State = 'Ready'; Execute = 'powershell.exe'; Arguments = '-File C:\SecurityInsight\Update-SecurityInsight.ps1 -Apply' },
            [pscustomobject]@{ TaskPath = '\SecurityInsight\'; TaskName = '3. Identity'; State = 'Ready'; Execute = 'powershell.exe'; Arguments = '-File C:\SecurityInsight\launcher\identity\launcher.community-vm.ps1' },
            [pscustomobject]@{ TaskPath = '\SecurityInsight\'; TaskName = '7. RA Summary'; State = 'Ready'; Execute = 'powershell.exe'; Arguments = '-File C:\SecurityInsight\launcher\risk-analysis\launcher.community-vm.ps1 -Summary' },
            [pscustomobject]@{ TaskPath = '\SecurityInsight\'; TaskName = '8. RA Detailed'; State = 'Disabled'; Execute = 'powershell.exe'; Arguments = '-File C:\SecurityInsight\launcher\risk-analysis\launcher.community-vm.ps1 -Detailed' },
            [pscustomobject]@{ TaskPath = '\SecurityInsight\'; TaskName = 'Tagging'; State = 'Ready'; Execute = 'powershell.exe'; Arguments = '-File C:\SecurityInsight\launcher\asset-tagging\launcher.community-vm.ps1' },
            [pscustomobject]@{ TaskPath = '\SecurityInsight\'; TaskName = 'SecurityInsight (flow)'; State = 'Ready'; Execute = 'powershell.exe'; Arguments = '-File C:\SecurityInsight\engine\flow\Invoke-SIJobFlowRun.ps1 -HostKind Vm' },
            [pscustomobject]@{ TaskPath = '\Other\'; TaskName = 'Backup'; State = 'Ready'; Execute = 'backup.exe'; Arguments = '' })
        $r = Get-SIFlowTaskReplacePlan -Tasks $tasks -Definition $d
        @($r | ForEach-Object { '{0}={1}' -f $_.TaskName, $_.Job }) | Should -Be @('3. Identity=identity', '7. RA Summary=risk-analysis', '8. RA Detailed=risk-analysis-detailed')
    }
    It 'the setup step previews by default, disables (never deletes), records what it disabled and -Remove enables exactly those' {
        $s = Get-Code 'setup\Install-SIFlowTask.ps1'
        $s | Should -Match 'if \(-not \$Apply\) \{ Write-Host .Preview only'
        $s | Should -Match 'Disable-ScheduledTask'
        $s | Should -Not -Match 'Unregister-ScheduledTask -TaskPath \$t\.TaskPath'
        $s | Should -Match 'Enable-ScheduledTask -TaskPath \$t\.TaskPath'
        $s | Should -Match 'replaced-tasks\.json'
        $s | Should -Match "-HostKind Vm"
        $s | Should -Match 'MultipleInstances IgnoreNew'
    }
}

Describe 'telemetry: the flow is one run' {
    It 'si-flow is a job id, and the step rows carry no telemetry' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-Telemetry.ps1')
        . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
        (Get-SITelemetryContract).Jobs | Should -Contain 'si-flow'
        Resolve-SITelemetryJob -Engine 'flow' | Should -Be 'si-flow'
        Resolve-SITelemetryJob -Engine 'flow:endpoint' | Should -BeNullOrEmpty
        $rh = Get-Code 'engine\asset-profiling\shared\Send-SIRunHealthRow.ps1'
        $rh | Should -Match "if \(\`$Phase -eq 'End' -and -not \`$NoTelemetry\)"
        $run = Get-Code 'engine\flow\Invoke-SIJobFlowRun.ps1'
        # #532: the step's ExitReason is 'throttled' for a step Microsoft only throttled (Get-SIJobFlowStepExitReason)
        $run | Should -Match "Phase End -ExitReason \(Get-SIJobFlowStepExitReason \`$StepRec\) -ErrorMessage \`$msg -NoTelemetry"
        $run | Should -Match "Action 'job\.flow\.run'"
    }
}
