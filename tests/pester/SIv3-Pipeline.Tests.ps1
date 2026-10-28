#Requires -Version 5.1
<#
    #306 PIPELINES AND STAGES (engine/_shared/SI-Pipeline.ps1 + SI-JobFlow.ps1): the Daily pipeline Collect -> Correlate ->
    Deliver, schema 2 and the lossless migration of a schema-1 flow, the stage gate (nothing delivered after a failed
    Collect; Deliver targets independent), Run now per pipeline / stage / step, the install's ONE lock and the persisted
    queue (file store, and the Pro SQL store over a seam that returns rows the way New-SIProSettingsStore does), the time
    zone of the start time (22:00 local, daylight saving), and the daily trend row written at the end of Risk Analysis.
    Offline; PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-JobFlow.ps1'))
    # #636: a new pipeline has the Risk Analysis Summary step switched OFF (SIv3-SummaryGroupings.Tests.ps1). The runner's
    # mechanics here use it as an ordinary step -- an install that switched it on -- so the default flow has every step on.
    $script:SINewDefaultFlowShipped = ${function:New-SIDefaultJobFlow}
    function New-SIDefaultJobFlow { $d = & $script:SINewDefaultFlowShipped @args; foreach ($s in @($d.Steps)) { $s.Enabled = $true }; $d }
    $script:Map = Get-SIJobFlowMap
    $script:SavedStart = $global:SI_Pipeline_StartTime; $script:SavedTz = $global:SI_Pipeline_TimeZone
    $global:SI_Pipeline_StartTime = $null; $global:SI_Pipeline_TimeZone = $null
    $script:All = @($script:Map.DefaultFlow)

    # a fake ARM: every execution runs one poll, then ends with the scripted status
    function New-FakeArm {
        param([hashtable]$Outcome = @{})
        $script:Arm = @{ Outcome = $Outcome; Starts = (New-Object System.Collections.Generic.List[string]); Exec = @{} }
        return {
            param($Method, $Path, $Body)
            if ($Method -eq 'POST' -and $Path -match '/jobs/caj-si-([a-z0-9\-]+)/start$') {
                $k = $Matches[1]; $name = '{0}-x{1}' -f $k, ($script:Arm.Starts.Count + 1); $script:Arm.Starts.Add($k)
                $script:Arm.Exec[$name] = @{ Left = 1; End = $(if ($script:Arm.Outcome.ContainsKey($k)) { $script:Arm.Outcome[$k] } else { 'Succeeded' }) }
                return [pscustomobject]@{ name = $name }
            }
            if ($Method -eq 'GET' -and $Path -match '/executions/([a-z0-9\-]+)$') {
                $e = $script:Arm.Exec[$Matches[1]]
                if ($e.Left -gt 0) { $e.Left--; return [pscustomobject]@{ properties = [pscustomobject]@{ status = 'Running' } } }
                return [pscustomobject]@{ properties = [pscustomobject]@{ status = $e.End } }
            }
            if ($Method -eq 'POST' -and $Path -match '/stop/') { return $null }
            throw "unexpected ARM call $Method $Path"
        }
    }
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-10-05T01:00:00', 'Utc')
    $script:NowSb = { $script:Clock }
    $script:SleepSb = { param($s) $script:Clock = $script:Clock.AddSeconds($s) }
    $script:Logs = New-Object System.Collections.Generic.List[string]
    $script:LogSb = { param($l, $m) $script:Logs.Add(('{0} {1}' -f $l, $m)) }
    function Invoke-Pipe {
        param($Definition, [hashtable]$Outcome = @{}, [hashtable]$Extra = @{})
        $script:Clock = $script:T0; $script:Logs.Clear()
        $p = @{ Definition = $Definition; Seams = (New-SIJobFlowArmSeams -SubscriptionId 's' -ResourceGroup 'r' -Arm (New-FakeArm -Outcome $Outcome)); Save = { param($s) }
                Now = $script:NowSb; Sleep = $script:SleepSb; Log = $script:LogSb; Map = $script:Map; PollSeconds = 30; Previous = $null; Force = $true }
        foreach ($k in $Extra.Keys) { $p[$k] = $Extra[$k] }
        Invoke-SIJobFlow @p
    }
    function Get-Step { param($State, [string]$Job) @($State.Steps | Where-Object { $_.Job -eq $Job })[0] }
    function New-TempDir { $d = Join-Path ([IO.Path]::GetTempPath()) ('si306-{0}' -f ([guid]::NewGuid().ToString('N').Substring(0, 10))); New-Item -ItemType Directory -Path $d -Force | Out-Null; $d }
}
AfterAll { $global:SI_Pipeline_StartTime = $script:SavedStart; $global:SI_Pipeline_TimeZone = $script:SavedTz }

Describe 'the Daily pipeline (the default)' {
    It 'is Collect -> Correlate -> Deliver, in the dependency order, each stage one step after the other (azure + endpoint together)' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        $d.Schema | Should -Be 2; $d.Name | Should -Be 'Daily pipeline'
        @($d.Stages | ForEach-Object Id) | Should -Be @('collect', 'correlate', 'deliver')
        @($d.Stages | ForEach-Object Name) | Should -Be @('Collect', 'Correlate', 'Deliver')   # the short names: what a pipeline stores, and what a sentence about one step says
        @($d.Stages | ForEach-Object { Get-SIPipelineStageTitle -Id $_.Id -Name $_.Name }) | Should -Be @('Collect (data-in)', 'Correlate (data structure)', 'Deliver (data-out)')
        @($d.Steps | Where-Object Stage -eq 'collect' | ForEach-Object Job) | Should -Be @('ptc', 'identity', 'azure', 'endpoint', 'publicip')
        @($d.Steps | Where-Object Stage -eq 'correlate' | ForEach-Object Job) | Should -Be @('asset-correlation', 'risk-analysis', 'risk-analysis-detailed')   # v3: Risk Analysis reads the CIs; #412: asset-properties is retired
        @($d.Steps | Where-Object Stage -eq 'deliver' | ForEach-Object Job) | Should -Be @('asset-cmdb-sql', 'asset-cmdb', 'asset-vulnerabilities', 'asset-vulns-servicenow', 'asset-datasync', 'close-loop-mail', 'verification')
        @($d.Steps | Where-Object WithPrevious | ForEach-Object Job) | Should -Be @('endpoint', 'risk-analysis-detailed')
        $r = Test-SIJobFlowDefinition -Definition $d -Map $script:Map
        $r.Problems | Should -BeNullOrEmpty
        $r.Warnings | Should -BeNullOrEmpty -Because 'no step runs before a job it needs'
    }
    It 'Risk Analysis reads the CIs (so it needs asset-correlation, which builds them); the SQL CMDB connector does too; asset-properties is retired (#412)' {
        foreach ($k in 'risk-analysis', 'risk-analysis-detailed') { $script:Map.Jobs[$k].Needs | Should -Contain 'asset-correlation' -Because 'v3: Risk Analysis takes each finding''s CI context' }
        $script:Map.Jobs['asset-properties'].Retired | Should -BeTrue
        @($script:Map.Jobs['asset-properties'].Needs).Count | Should -Be 0
        foreach ($k in 'asset-cmdb-sql', 'asset-cmdb', 'asset-datasync') { $script:Map.Jobs[$k].Needs | Should -Not -Contain 'asset-properties' -Because 'the full asset metadata comes from the profilers' }
        $script:Map.Jobs['asset-cmdb-sql'].Needs | Should -Contain 'asset-correlation'
        $ra = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'engine', 'risk-analysis', 'Invoke-RiskAnalysis.ps1'))
        $ra | Should -Not -Match 'SI_ObjectMap_CL|SI_AssetProperties_CL'
        $q = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'risk-analysis-detection', 'RiskAnalysis_Queries_Locked.yaml'))
        $q | Should -Not -Match 'SI_ObjectMap_CL|SI_AssetProperties_CL'
    }
    It 'inside Deliver a failure carries on (the targets are independent); Collect and Correlate skip what needs it' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        @($d.Steps | Where-Object Stage -eq 'deliver' | ForEach-Object OnFailure | Select-Object -Unique) | Should -Be @('continue')
        @($d.Steps | Where-Object Stage -ne 'deliver' | ForEach-Object OnFailure | Select-Object -Unique) | Should -Be @('skip-dependents')
    }
    It 'the risk trend is no step: the job waits in pipeline mode, runnable by hand' {
        $script:Map.DefaultFlow | Should -Not -Contain 'asset-trend'
        $script:Map.Jobs['asset-trend'].ManualInFlowMode | Should -BeTrue
        $plan = Get-SIJobOrchestrationSwitchPlan -Jobs @([pscustomobject]@{ Name = 'caj-si-asset-trend'; TriggerType = 'Schedule'; Cron = '0 9 * * *' }) -Mode flow -Map $script:Map
        $plan[0].Action | Should -Be 'to-manual'
        $back = Get-SIJobOrchestrationSwitchPlan -Jobs @([pscustomobject]@{ Name = 'caj-si-asset-trend'; TriggerType = 'Manual'; RememberedCron = '0 9 * * *' }) -Mode schedules -Map $script:Map
        $back[0].Action | Should -Be 'to-schedule'; $back[0].Cron | Should -Be '0 9 * * *'
        . ([IO.Path]::Combine($script:SIRoot, 'container', '_shared', 'SI-ContainerConfig.ps1'))
        (Get-SIBootstrapTriggerPlan -Engine 'asset-trend' -Mode flow -Cron '0 9 * * *' -Map $script:Map).Trigger | Should -Be 'Manual'
        (Get-SIBootstrapTriggerPlan -Engine 'asset-trend' -Mode schedules -Cron '0 9 * * *' -Map $script:Map).Trigger | Should -Be 'Schedule'
        $vmPlan = Get-SIFlowTaskReplacePlan -Tasks @([pscustomobject]@{ TaskPath = '\SI\'; TaskName = 'trend'; State = 'Ready'; Execute = 'powershell.exe'; Arguments = '-File C:\SI\launcher\asset-trend\launcher.community-vm.ps1' }) -Definition (New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map) -Map $script:Map
        @($vmPlan).Count | Should -Be 1 -Because 'the VM flow task replaces the risk trend''s own task too'
    }
}

Describe 'schema 2 and the migration of a schema-1 flow' {
    It 'the JSON round-trips, and carries the flat steps a schema-1 reader reads' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        $d.Stages[2].RunIfPreviousFailed = $true
        $j = ConvertTo-SIJobFlowJson -Definition $d
        (ConvertTo-SIJobFlowJson -Definition (ConvertFrom-SIJobFlowJson -Json $j -Map $script:Map)) | Should -Be $j
        $o = $j | ConvertFrom-Json
        $o.schema | Should -Be 2
        @($o.steps).Count | Should -Be @($d.Steps).Count -Because 'an older reader of steps[] still sees the whole pipeline, in order'
        @($o.steps | ForEach-Object job) | Should -Be @($d.Steps | ForEach-Object Job)
        @($o.stages)[2].runIfPreviousFailed | Should -BeTrue
        $o.timeZone | Should -Be 'Europe/Copenhagen'
        $one = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        @((ConvertFrom-SIJobFlowJson -Json (ConvertTo-SIJobFlowJson -Definition $one) -Map $script:Map).Steps).Count | Should -Be 1
    }
    It 'a stored schema-1 flow with a custom step migrates losslessly' {
        $v1 = '{"schema":1,"mode":"flow","startTime":"02:30","cadence":"weekdays","weekday":1,"intervalMinutes":1440,"steps":[' +
              '{"job":"ptc","enabled":true,"withPrevious":false,"onFailure":"stop","timeoutMinutes":90},' +
              '{"job":"endpoint","enabled":false,"withPrevious":false,"onFailure":"skip-dependents","timeoutMinutes":200},' +
              '{"job":"asset-correlation","enabled":true,"withPrevious":false,"onFailure":"skip-dependents","timeoutMinutes":120},' +
              '{"job":"my-export","enabled":true,"withPrevious":true,"onFailure":"continue","timeoutMinutes":30},' +
              '{"job":"risk-analysis","enabled":true,"withPrevious":true,"onFailure":"skip-dependents","timeoutMinutes":240},' +
              '{"job":"asset-trend","enabled":true,"withPrevious":false,"onFailure":"skip-dependents","timeoutMinutes":60},' +
              '{"job":"asset-vulnerabilities","enabled":true,"withPrevious":false,"onFailure":"skip-dependents","timeoutMinutes":240},' +
              '{"job":"asset-datasync","enabled":true,"withPrevious":false,"onFailure":"stop","timeoutMinutes":240}]}'
        $d = ConvertFrom-SIJobFlowJson -Json $v1 -Map $script:Map
        $d.Schema | Should -Be 2; $d.Migrated | Should -BeTrue
        @($d.Steps).Count | Should -Be 8 -Because 'every step is kept'
        ($d.StartTime, $d.Cadence, $d.TimeZone) | Should -Be @('02:30', 'weekdays', 'UTC') -Because 'a stored schedule keeps its time (UTC, as before time zones)'
        @($d.Steps | ForEach-Object { '{0}:{1}' -f $_.Stage, $_.Job }) | Should -Be @('collect:ptc', 'collect:endpoint', 'correlate:asset-correlation', 'correlate:my-export', 'correlate:risk-analysis', 'correlate:asset-trend', 'deliver:asset-vulnerabilities', 'deliver:asset-datasync')
        (Get-Step $d 'ptc').OnFailure | Should -Be 'stop'; (Get-Step $d 'ptc').TimeoutMinutes | Should -Be 90
        (Get-Step $d 'endpoint').Enabled | Should -BeFalse; (Get-Step $d 'endpoint').TimeoutMinutes | Should -Be 200
        (Get-Step $d 'my-export').WithPrevious | Should -BeTrue -Because 'the custom step stays with the step above it (asset-correlation), in its stage'
        (Get-Step $d 'my-export').OnFailure | Should -Be 'continue'
        (Get-Step $d 'risk-analysis').WithPrevious | Should -BeTrue -Because 'the step above it (my-export) is in the same stage (Correlate) now'
        (Get-Step $d 'asset-trend').Enabled | Should -BeFalse -Because 'Risk Analysis writes the trend row now'
        (Get-Step $d 'asset-vulnerabilities').OnFailure | Should -Be 'continue' -Because 'the Deliver default'
        (Get-Step $d 'asset-datasync').OnFailure | Should -Be 'stop' -Because 'an explicit choice is kept'
        ($d.MigrationNotes -join "`n") | Should -Match 'my-export is not a job SecurityInsight ships'
        (Test-SIJobFlowDefinition -Definition $d -Map $script:Map).Problems | Should -BeNullOrEmpty
    }
    It 'an unknown first step goes to the first stage; the old config/job-flow.custom.sample migrates too' {
        $d = ConvertFrom-SIJobFlowJson -Json '{"steps":[{"job":"pre-check"},{"job":"ptc"}]}' -Map $script:Map
        (Get-Step $d 'pre-check').Stage | Should -Be 'collect'
        $s = ConvertFrom-SIJobFlowJson -Json ([IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'config', 'job-flow.custom.sample.json'))) -Map $script:Map
        (Test-SIJobFlowDefinition -Definition $s -Map $script:Map).Problems | Should -BeNullOrEmpty
    }
    It 'refuses stages that cannot run' {
        $bad = '{"schema":2,"stages":[{"id":"deliver","steps":[{"job":"asset-datasync"}]},{"id":"collect","steps":[{"job":"ptc"}]},{"id":"Data In","steps":[]},{"id":"collect","steps":[]}]}'
        $r = Test-SIJobFlowDefinition -Definition (ConvertFrom-SIJobFlowJson -Json $bad -Map $script:Map) -Map $script:Map
        ($r.Problems -join "`n") | Should -Match 'Deliver runs before Collect'
        ($r.Problems -join "`n") | Should -Match "'data in' is not a stage"
        ($r.Problems -join "`n") | Should -Match 'collect is already stage 2'
        $custom = '{"schema":2,"stages":[{"id":"collect","steps":[{"job":"ptc"}]},{"id":"custom-export","name":"Export","steps":[{"job":"my-export"}]}]}'
        (Test-SIJobFlowDefinition -Definition (ConvertFrom-SIJobFlowJson -Json $custom -Map $script:Map) -Map $script:Map).Problems | Should -BeNullOrEmpty
    }
}

Describe 'the stage gate' {
    It 'Collect failed (the tier classifier, so no collection ran): Correlate and Deliver do not start (nothing delivered from a partial collection)' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        $r = Invoke-Pipe -Definition $d -Outcome @{ 'ptc' = 'Failed' }
        foreach ($k in 'asset-correlation', 'asset-cmdb-sql', 'asset-datasync', 'close-loop-mail') {
            (Get-Step $r $k).State | Should -Be 'Skipped'; (Get-Step $r $k).ErrorClass | Should -Be 'stage-blocked'
        }
        @($script:Arm.Starts) | Should -Not -Contain 'asset-correlation'
        @($script:Arm.Starts) | Should -Not -Contain 'asset-datasync'
        $r.State | Should -Be 'Failed'
        (Get-Step $r 'asset-datasync').Error | Should -Match 'Collect did not succeed'
    }
    It 'Correlate failed: Deliver is skipped and said -- unless it is set to run anyway' {
        # the stage gate itself, with the go-on of the data sync after a failed step switched off (its own suite is
        # SIv3-RunGoesOnAfterFailedStep: with it on, the data sync runs on what is stored)
        $global:SI_Pro_Pipeline_GoOnAfterFailedStep = $false
        try {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        $r = Invoke-Pipe -Definition $d -Outcome @{ 'asset-correlation' = 'Failed' }
        (Get-Step $r 'asset-datasync').ErrorClass | Should -Be 'stage-blocked'
        (Get-Step $r 'asset-datasync').Error | Should -Match 'Correlate did not succeed'
        $d.Stages[2].RunIfPreviousFailed = $true
        $r2 = Invoke-Pipe -Definition $d -Outcome @{ 'asset-correlation' = 'Failed' }
        # v3: every Deliver step needs the CIs or the Risk Analysis that reads them, so with the CI build failed each is skipped
        # by its own NEED -- not by the stage gate -- and the run says Deliver was set to run anyway
        (Get-Step $r2 'asset-vulnerabilities').State | Should -Be 'Skipped'
        (Get-Step $r2 'asset-vulnerabilities').ErrorClass | Should -Not -Be 'stage-blocked'
        (Get-Step $r2 'asset-cmdb-sql').State | Should -Be 'Skipped' -Because 'it needs the failed asset correlation (skip-dependents is still per step)'
        ($script:Logs -join "`n") | Should -Match 'Deliver is set to run anyway'
        } finally { $global:SI_Pro_Pipeline_GoOnAfterFailedStep = $null }
    }
    It 'Deliver set to run anyway still never runs after a failed Collect' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        $d.Stages[1].RunIfPreviousFailed = $true; $d.Stages[2].RunIfPreviousFailed = $true
        $r = Invoke-Pipe -Definition $d -Outcome @{ 'ptc' = 'Failed' }
        @($script:Arm.Starts | Where-Object { $_ -in @('asset-cmdb-sql', 'asset-cmdb', 'asset-vulnerabilities', 'asset-vulns-servicenow', 'asset-datasync', 'close-loop-mail') }).Count | Should -Be 0
    }
    It 'one collection failed while the others succeeded: the run goes on -- Correlate and Deliver start, the step stays failed' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        $r = Invoke-Pipe -Definition $d -Outcome @{ 'publicip' = 'Failed' }
        (Get-Step $r 'publicip').State | Should -Be 'Failed'
        foreach ($k in 'asset-correlation', 'risk-analysis', 'asset-cmdb-sql', 'asset-datasync', 'close-loop-mail') { (Get-Step $r $k).State | Should -Be 'Success' }
        $r.State | Should -Be 'Failed' -Because 'a run with a failed step is never shown as succeeded'
        ($script:Logs -join "`n") | Should -Match 'Collect: publicip did not succeed -- Correlate starts all the same'
    }
    It 'inside Deliver a failed vulnerability connector does not skip the data sync or the mail' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        $r = Invoke-Pipe -Definition $d -Outcome @{ 'asset-vulnerabilities' = 'Failed' }
        (Get-Step $r 'asset-vulnerabilities').State | Should -Be 'Failed'
        foreach ($k in 'asset-vulns-servicenow', 'asset-datasync', 'close-loop-mail') { (Get-Step $r $k).State | Should -Be 'Success' }
    }
    It 'a stage starts only when the stage before it ENDED' {
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'azure', 'endpoint', 'asset-correlation') -Map $script:Map
        $d.Steps[4].WithPrevious = $true   # the first step of Correlate cannot join Collect's last group
        $groups = Get-SIJobFlowGroups -Definition $d
        @($groups | Where-Object Stage -eq 'correlate').Count | Should -Be 1
        $r = Invoke-Pipe -Definition $d
        (Get-Step $r 'asset-correlation').StartedUtc | Should -BeGreaterOrEqual (Get-Step $r 'endpoint').EndedUtc
        (Test-SIJobFlowDefinition -Definition $d -Map $script:Map).Warnings -join ' ' | Should -Match 'first of Correlate'
    }
    It 'the status says where the pipeline is' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        $st = New-SIJobFlowRunState -Definition $d -NowUtc $script:T0
        foreach ($s in $st.Steps) { if ($s.Stage -eq 'collect') { $s.State = 'Success' } }
        (Get-Step $st 'asset-correlation').State = 'Running'
        Get-SIPipelineStatusText -State $st -Definition $d | Should -Be ('Daily pipeline {0} Stage 2 of 3: Correlate (data structure)' -f [char]0x00B7)
        $st.State = 'Succeeded'
        Get-SIPipelineStatusText -State $st -Definition $d | Should -Be ('Daily pipeline {0} succeeded' -f [char]0x00B7)
    }
}

Describe 'a stage says what it is for (data-in, data structure, data-out)' {
    BeforeAll {
        # what an install stored BEFORE the stages said what they are for: the three stages by their old names, plus a
        # stage of the customer's own and a stage a person renamed
        $script:StoredBefore = '{"schema":2,"id":"daily","name":"Daily pipeline","mode":"flow","startTime":"01:00","timeZone":"UTC","cadence":"daily","weekday":1,"intervalMinutes":1440,"defaults":2,' +
            '"stages":[{"id":"collect","name":"Collect","runIfPreviousFailed":false,"steps":[{"job":"ptc"},{"job":"identity"}]},{"id":"correlate","name":"Correlate","runIfPreviousFailed":false,"steps":[{"job":"asset-correlation"}]},' +
            '{"id":"custom-export","name":"Nightly export","runIfPreviousFailed":false,"steps":[]},{"id":"deliver","name":"Hand-over","runIfPreviousFailed":false,"steps":[{"job":"asset-datasync"}]}]}'
    }
    It 'the three titles are the owner''s words, the same as in the shipped map' {
        Get-SIPipelineStageTitle -Id 'collect' | Should -BeExactly 'Collect (data-in)'
        Get-SIPipelineStageTitle -Id 'correlate' | Should -BeExactly 'Correlate (data structure)'
        Get-SIPipelineStageTitle -Id 'deliver' | Should -BeExactly 'Deliver (data-out)'
        $raw = [IO.File]::ReadAllText(([IO.Path]::Combine($script:SIRoot, 'config', 'job-flow.locked.json'))) | ConvertFrom-Json
        foreach ($st in @($raw.defaultPipeline.stages)) {
            [string]$st.title | Should -BeExactly (Get-SIPipelineStageTitle -Id $st.id) -Because ('the map''s title of {0}' -f $st.id)
            [string]$st.name | Should -BeExactly (Get-SIPipelineStageName $st.id) -Because 'the short name did not change'
        }
        # the web app's half is compared with the same map by its own tests (JobFlowTests: the map check)
    }
    It 'a stored pipeline with the names from before shows the new words -- nothing is rewritten; a custom stage and a renamed stage keep their own name' {
        $d = ConvertFrom-SIJobFlowJson -Json $script:StoredBefore -Map $script:Map
        $d.Migrated | Should -BeFalse -Because 'the new words come from the stage id when it is shown, not from a rewrite'
        @($d.Stages | ForEach-Object Name) | Should -Be @('Collect', 'Correlate', 'Nightly export', 'Hand-over')
        @($d.Stages | ForEach-Object { Get-SIPipelineStageTitle -Id $_.Id -Name $_.Name }) | Should -Be @('Collect (data-in)', 'Correlate (data structure)', 'Nightly export', 'Hand-over')
        $json = ConvertTo-SIJobFlowJson -Definition $d
        $json | Should -Match '"name":"Collect"' -Because 'a save stores the names as they were'
        $json | Should -Match '"name":"Hand-over"'
        # the run's status names the stage as the heading does
        $st = New-SIJobFlowRunState -Definition $d -NowUtc $script:T0
        foreach ($s in $st.Steps) { if ($s.Stage -eq 'collect') { $s.State = 'Success' } }
        (Get-Step $st 'asset-correlation').State = 'Running'
        Get-SIPipelineStatusText -State $st -Definition $d | Should -Be ('Daily pipeline {0} Stage 2 of 4: Correlate (data structure)' -f [char]0x00B7)
        (Get-Step $st 'asset-correlation').State = 'Success'
        (Get-Step $st 'asset-datasync').State = 'Running'
        Get-SIPipelineStatusText -State $st -Definition $d | Should -Be ('Daily pipeline {0} Stage 4 of 4: Hand-over' -f [char]0x00B7)
    }
    It 'a stored name that is empty, the id or already the title reads as the title; a custom stage without a name shows its id' {
        Get-SIPipelineStageTitle -Id 'deliver' -Name '' | Should -Be 'Deliver (data-out)'
        Get-SIPipelineStageTitle -Id 'deliver' -Name 'deliver' | Should -Be 'Deliver (data-out)'
        Get-SIPipelineStageTitle -Id 'deliver' -Name 'Deliver (data-out)' | Should -Be 'Deliver (data-out)'
        Get-SIPipelineStageTitle -Id 'custom-export' | Should -Be 'custom-export'
    }
    It 'a sentence about one step keeps the short name: the reason a stage does not start, the held-back sentence, a request' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        # the held-back sentence is the one of a run that went on after nothing (the go-on switched off); the sentence of a
        # run that did go on keeps the short name too
        $global:SI_Pro_Pipeline_GoOnAfterFailedStep = $false
        try { $r = Invoke-Pipe -Definition $d -Outcome @{ 'asset-correlation' = 'Failed' } } finally { $global:SI_Pro_Pipeline_GoOnAfterFailedStep = $null }
        (Get-SIPipelineHeldBackText -State $r) | Should -Match 'asset-correlation \(Correlate\) did not succeed'
        (Get-SIPipelineHeldBackText -State $r) | Should -Not -Match 'data structure'
        $r = Invoke-Pipe -Definition $d -Outcome @{ 'asset-correlation' = 'Failed' }
        (Get-SIPipelinePartialText -State $r) | Should -Match 'asset-correlation \(Correlate\) did not succeed'
        (Get-SIPipelinePartialText -State $r) | Should -Not -Match 'data structure'
        (Get-SIPipelineRequestText (New-SIPipelineRequest -Scope stage -Target deliver)) | Should -Be 'stage Deliver'
    }
}

Describe 'Run now per pipeline, stage and step' {
    It 'a stage runs only its own steps, records what was run and who asked' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        $r = Invoke-Pipe -Definition $d -Extra @{ Force = $false; Scope = 'stage'; Target = 'correlate'; RequestedBy = 'ann@example.test'; RequestId = 7 }
        @($script:Arm.Starts) | Should -Be @('asset-correlation', 'risk-analysis', 'risk-analysis-detailed')
        ($r.Scope, $r.Target, $r.RequestedBy, $r.RequestId) | Should -Be @('stage', 'correlate', 'ann@example.test', 7)
        $r.State | Should -Be 'Succeeded'
        $back = ConvertFrom-SIJobFlowRunJson -Json (ConvertTo-SIJobFlowRunJson -State $r)
        ($back.Scope, $back.Target, $back.RequestedBy) | Should -Be @('stage', 'correlate', 'ann@example.test')
        @($back.Steps | ForEach-Object Stage | Select-Object -Unique) | Should -Be @('correlate')
    }
    It 'a stage run of Deliver is not held back by a Collect that is not part of it' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        $r = Invoke-Pipe -Definition $d -Extra @{ Force = $false; Scope = 'stage'; Target = 'deliver' }
        @($script:Arm.Starts).Count | Should -Be 7   # the Deliver stage: six jobs + the verification service
    }
    It 'a step runs alone (even when switched off in the pipeline); an unknown step or stage is refused' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        (Get-Step $d 'asset-datasync').Enabled = $false
        $r = Invoke-Pipe -Definition $d -Extra @{ Force = $false; Scope = 'step'; Target = 'caj-si-asset-datasync' }
        @($script:Arm.Starts) | Should -Be @('asset-datasync')
        @($r.Steps).Count | Should -Be 1
        { Invoke-Pipe -Definition $d -Extra @{ Force = $false; Scope = 'step'; Target = 'nope' } } | Should -Throw '*not a step*'
        { Invoke-Pipe -Definition $d -Extra @{ Force = $false; Scope = 'stage'; Target = 'custom-x' } } | Should -Throw '*not a stage*'
        Test-SIPipelineRequest -Request (New-SIPipelineRequest -Scope stage -Target 'custom-x') -Definition $d | Should -Match 'not a stage'
    }
    It 'the request names what it runs, and the same request is the same key' {
        (Get-SIPipelineRequestText (New-SIPipelineRequest -Scope stage -Target correlate)) | Should -Be 'stage Correlate'
        (Get-SIPipelineRequestText (New-SIPipelineRequest -Scope step -Target 'caj-si-asset-datasync')) | Should -Be 'step asset-datasync'
        (Get-SIPipelineRequestKey (New-SIPipelineRequest -Scope pipeline -Target 'ignored')) | Should -Be 'pipeline|'
        { New-SIPipelineRequest -Scope stage } | Should -Throw
    }
}

Describe 'one lock per install and the queue (VM file store)' {
    BeforeEach {
        $script:Dir = New-TempDir
        $script:QClock = $script:T0
        $script:Ctl = New-SIPipelineDocControl -Docs (New-SIPipelineFileDocs -Folder $script:Dir) -Now { $script:QClock }
        $script:Def = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'asset-correlation', 'asset-datasync') -Map $script:Map -StartTime '01:00' -TimeZone 'UTC'
        $script:RunLog = New-Object System.Collections.Generic.List[string]
        $script:LastRun = $null
        $script:RunOne = {
            param($Req, $Prev, $Fid)
            $what = if ($Req) { Get-SIPipelineRequestKey $Req } else { 'resume' }
            $script:RunLog.Add($what)
            $s = [pscustomobject]@{ FlowRunId = $Fid; State = 'Succeeded'; Outcome = 'New'; Scope = $(if ($Req) { $Req.Scope } else { 'pipeline' }); StartedUtc = $script:QClock; EndedUtc = $script:QClock; HeartbeatUtc = $script:QClock
                                    LastSlotUtc = $(if ($Req -and $Req.SlotUtc) { $Req.SlotUtc } elseif ($script:LastRun) { $script:LastRun.LastSlotUtc } else { $null }); Steps = @() }
            $script:LastRun = $s; $s
        }
    }
    AfterEach { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue }
    It 'a Run now while the scheduled pipeline holds the install waits in the queue, then runs when it is free' {
        $script:QClock = $script:T0.AddHours(5)   # away from the 01:00 slot: only the Run now is queued
        $other = $script:Ctl.AcquireLock('scheduled-runner', 'the Daily pipeline', 15)
        $other.Acquired | Should -BeTrue
        $req = New-SIPipelineRequest -Scope stage -Target correlate -RequestedBy 'ann@example.test' -RequestedUtc $script:QClock
        $out = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Request $req -Holder 'manual-runner' -Now { $script:QClock } -Log $script:LogSb
        $out.Outcome | Should -Be 'Busy'
        $script:RunLog.Count | Should -Be 0 -Because 'nothing overlaps'
        @($script:Ctl.List()).Count | Should -Be 1
        @($script:Ctl.List())[0].RequestedBy | Should -Be 'ann@example.test'
        # the same request again is kept once
        $null = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Request (New-SIPipelineRequest -Scope stage -Target correlate) -Holder 'manual-runner-2' -Now { $script:QClock } -Log $script:LogSb
        @($script:Ctl.List()).Count | Should -Be 1
        # the scheduled run ends; the next wake-up runs the queue
        $script:Ctl.ReleaseLock('scheduled-runner')
        $script:QClock = $script:QClock.AddMinutes(5)
        $out = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Holder 'wake-up' -Now { $script:QClock } -Log $script:LogSb
        $out.Outcome | Should -Be 'Ran'
        @($script:RunLog) | Should -Be @('stage|correlate')
        @($script:Ctl.List()).Count | Should -Be 0
        $script:Ctl.ReadLock() | Should -BeNullOrEmpty -Because 'the lock is released'
    }
    It 'a FORCED start of the whole pipeline (Run the pipeline now) while a run is going starts no second pipeline: it waits in the queue and runs once, afterwards' {
        # what "Run the pipeline now" (SI_FLOW_FORCE=1) hands the runner: a request for the whole pipeline, asked by a person
        $script:QClock = $script:T0.AddHours(5)
        ($script:Ctl.AcquireLock('scheduled-runner', 'the Daily pipeline', 15)).Acquired | Should -BeTrue
        $forced = New-SIPipelineRequest -Scope pipeline -Trigger 'manual' -RequestedBy 'ann@example.test' -RequestedUtc $script:QClock
        $out = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Request $forced -Holder 'forced-runner' -Now { $script:QClock } -Log $script:LogSb
        $out.Outcome | Should -Be 'Busy' -Because 'a forced start never runs beside the run that holds the install'
        $script:RunLog.Count | Should -Be 0
        @($script:Ctl.List() | Where-Object { $_.Scope -eq 'pipeline' -and $_.State -eq 'Queued' }).Count | Should -Be 1
        # forced again while it still waits: kept once, still nothing runs
        $out = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Request (New-SIPipelineRequest -Scope pipeline -Trigger 'manual') -Holder 'forced-runner-2' -Now { $script:QClock } -Log $script:LogSb
        $out.Outcome | Should -Be 'Busy'
        $script:RunLog.Count | Should -Be 0
        @($script:Ctl.List()).Count | Should -Be 1
        # the run that held the install ends: the forced request runs ONCE
        $script:Ctl.ReleaseLock('scheduled-runner')
        $script:QClock = $script:QClock.AddMinutes(5)
        $out = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Holder 'wake-up' -Now { $script:QClock } -Log $script:LogSb
        $out.Outcome | Should -Be 'Ran'
        $script:RunLog.Count | Should -Be 1
        @($script:Ctl.List()).Count | Should -Be 0
    }
    It 'the queue runs oldest first, and a cancelled request never runs' {
        $null = $script:Ctl.AcquireLock('busy', 'x', 15)
        $a = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope step -Target ptc))
        $b = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope stage -Target deliver))
        $c = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope pipeline))
        $script:Ctl.Cancel($b.Id, 'ann') | Should -BeTrue
        $script:Ctl.Cancel($b.Id, 'ann') | Should -BeFalse
        $script:Ctl.ReleaseLock('busy')
        $null = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Holder 'w' -Now { $script:QClock } -Log $script:LogSb
        @($script:RunLog) | Should -Be @('step|ptc', 'pipeline|')
    }
    It 'a scheduled slot that passes while a manual run holds the install is queued once, and runs once' {
        $script:QClock = [datetime]::SpecifyKind([datetime]'2026-10-05T00:50:00', 'Utc')
        # a manual run started 00:50 and still beats at 01:05
        $script:LastRun = [pscustomobject]@{ FlowRunId = 'manual-1'; State = 'Running'; StartedUtc = $script:QClock; EndedUtc = $null; HeartbeatUtc = $null; LastSlotUtc = [datetime]::SpecifyKind([datetime]'2026-10-04T01:00:00', 'Utc'); Steps = @() }
        $null = $script:Ctl.AcquireLock('manual', 'stage Correlate', 15)
        foreach ($min in 15, 20, 25) {
            $script:QClock = [datetime]::SpecifyKind([datetime]'2026-10-05T01:00:00', 'Utc').AddMinutes($min - 15)
            $script:LastRun.HeartbeatUtc = $script:QClock
            $script:Ctl.HeartbeatLock('manual', 'manual-1', 'stage Correlate') | Should -BeTrue
            $o = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Holder ('wake-{0}' -f $min) -Now { $script:QClock } -Log $script:LogSb
            $o.Outcome | Should -Be 'Busy'
        }
        @($script:Ctl.List()).Count | Should -Be 1 -Because 'the slot is queued once, never per wake-up'
        @($script:Ctl.List())[0].Trigger | Should -Be 'catch-up'
        # the manual run ends FAILED (2026-10-24: one that succeeded as a whole run is that day's run -- the next test)
        $script:LastRun.State = 'Failed'; $script:LastRun.EndedUtc = $script:QClock; $script:Ctl.ReleaseLock('manual')
        $script:QClock = $script:QClock.AddMinutes(5)
        $null = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Holder 'wake-30' -Now { $script:QClock } -Log $script:LogSb
        @($script:RunLog) | Should -Be @('pipeline|')
        $script:LastRun.LastSlotUtc | Should -Be ([datetime]::SpecifyKind([datetime]'2026-10-05T01:00:00', 'Utc'))
        # the next wake-up: the slot has run -- nothing again
        $script:QClock = $script:QClock.AddMinutes(5)
        $null = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Holder 'wake-35' -Now { $script:QClock } -Log $script:LogSb
        @($script:RunLog).Count | Should -Be 1
    }
    It '2026-10-24: a manual WHOLE run that was running at the slot and SUCCEEDED is that day''s run -- the queued catch-up closes Covered, nothing starts; a stage run does not count' {
        foreach ($case in @(@{ Scope = 'pipeline'; Runs = 0 }, @{ Scope = 'stage'; Runs = 1 })) {
            $script:Ctl = New-SIPipelineDocControl -Docs (New-SIPipelineFileDocs -Folder (New-TempDir)) -Now { $script:QClock }
            $script:RunLog.Clear(); $script:Logs.Clear()
            $script:QClock = [datetime]::SpecifyKind([datetime]'2026-10-05T00:50:00', 'Utc')
            $script:LastRun = [pscustomobject]@{ FlowRunId = 'manual-1'; State = 'Running'; Scope = $case.Scope; StartedUtc = $script:QClock; EndedUtc = $null; HeartbeatUtc = $null; SlotUtc = $null; LastSlotUtc = [datetime]::SpecifyKind([datetime]'2026-10-04T01:00:00', 'Utc'); Steps = @() }
            $null = $script:Ctl.AcquireLock('manual', 'the pipeline', 15)
            $script:QClock = [datetime]::SpecifyKind([datetime]'2026-10-05T01:05:00', 'Utc'); $script:LastRun.HeartbeatUtc = $script:QClock
            $null = $script:Ctl.HeartbeatLock('manual', 'manual-1', 'the pipeline')
            (Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Holder 'wake-5' -Now { $script:QClock } -Log $script:LogSb).Outcome | Should -Be 'Busy'
            @($script:Ctl.List()).Count | Should -Be 1 -Because 'queued while the manual run goes, as before'
            $script:LastRun.State = 'Succeeded'; $script:LastRun.EndedUtc = [datetime]::SpecifyKind([datetime]'2026-10-05T02:10:00', 'Utc'); $script:Ctl.ReleaseLock('manual')
            $script:QClock = [datetime]::SpecifyKind([datetime]'2026-10-05T02:15:00', 'Utc')
            $null = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Holder 'wake-75' -Now { $script:QClock } -Log $script:LogSb
            @($script:RunLog).Count | Should -Be $case.Runs -Because "a $($case.Scope) run"
            @($script:Ctl.List()).Count | Should -Be 0
            if ($case.Runs -eq 0) {
                @($script:Logs | Where-Object { $_ -match 'the queued 2026-10-05 01:00:00Z start is not run: the run before it was running at that time and succeeded' }).Count | Should -Be 1
                # the next wake-ups: nothing (the slot has run); tomorrow's slot starts on time
                $script:QClock = $script:QClock.AddMinutes(5)
                $null = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Holder 'wake-80' -Now { $script:QClock } -Log $script:LogSb
                @($script:RunLog).Count | Should -Be 0
                $script:QClock = [datetime]::SpecifyKind([datetime]'2026-10-06T01:02:00', 'Utc')
                $null = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Holder 'wake-next' -Now { $script:QClock } -Log $script:LogSb
                @($script:RunLog) | Should -Be @('pipeline|')
            }
        }
    }
    It 'a lock whose runner stopped (no heartbeat for 15 minutes) is taken over and said' {
        $null = $script:Ctl.AcquireLock('dead-runner', 'the Daily pipeline', 15)
        $script:QClock = $script:QClock.AddMinutes(10)
        ($script:Ctl.AcquireLock('new', 'x', 15)).Acquired | Should -BeFalse
        $script:QClock = $script:QClock.AddMinutes(6)
        $l = $script:Ctl.AcquireLock('new', 'x', 15)
        $l.Acquired | Should -BeTrue; $l.TookOver | Should -Be 'dead-runner'
        $script:Ctl.HeartbeatLock('dead-runner', 'r', 'x') | Should -BeFalse -Because 'the old runner no longer holds it'
        $script:Ctl.HeartbeatLock('new', 'r', 'x') | Should -BeTrue
    }
    It 'a runner never starts a NEW run on replaced code: after a run, an update that replaced its code leaves the queue to the next wake-up (live 2026-10-19: a runner of 10-15 ran the run queued after the rc11 roll-out)' {
        $script:QClock = $script:T0.AddHours(5)
        # today's slot has run: only the two requests below are in the queue
        $script:LastRun = [pscustomobject]@{ FlowRunId = 'done'; State = 'Succeeded'; Outcome = 'New'; Scope = 'pipeline'; StartedUtc = $script:T0; EndedUtc = $script:T0.AddHours(1); HeartbeatUtc = $script:T0.AddHours(1); LastSlotUtc = $script:T0; Steps = @() }
        $null = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope step -Target ptc))
        $null = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope stage -Target deliver))
        $script:Image = 'acr.example/si:old'
        $script:Asked = 0
        $cc = { $script:Asked++; Test-SIPipelineCodeCurrent -StartImage 'acr.example/si:old' -NowImage $script:Image }
        # the update rolls a new image into the flow job while the first run runs
        $one = { param($r, $p, $f) $x = & $script:RunOne $r $p $f; $script:Image = 'acr.example/si:new'; $x }
        $out = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $one -Holder 'old-runner' -Now { $script:QClock } -Log $script:LogSb -CodeCurrent $cc
        $out.Outcome | Should -Be 'Ran'
        @($script:RunLog) | Should -Be @('step|ptc') -Because 'the second request is not run by the replaced code'
        $script:Asked | Should -Be 1 -Because 'the first request of an execution is never held back'
        @($script:Ctl.List() | Where-Object { $_.State -eq 'Queued' }).Count | Should -Be 1
        ($script:Logs -join "`n") | Should -Match 'SecurityInsight was updated while this runner worked -- what waits in the queue starts on the next wake-up, on the new version'
        $script:Ctl.ReadLock() | Should -BeNullOrEmpty -Because 'the lock is released for the next wake-up'
        # the next wake-up (a new execution, on the new image) takes it
        $script:QClock = $script:QClock.AddMinutes(5)
        $null = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $one -Holder 'new-runner' -Now { $script:QClock } -Log $script:LogSb -CodeCurrent { Test-SIPipelineCodeCurrent -StartImage 'acr.example/si:new' -NowImage $script:Image }
        @($script:RunLog) | Should -Be @('step|ptc', 'stage|deliver')
    }
    It 'the code check: same image = current; a replaced image = not; unreadable = current, and a check that throws never stops the queue' {
        Test-SIPipelineCodeCurrent -StartImage 'a/si:1' -NowImage 'A/SI:1' | Should -BeTrue
        Test-SIPipelineCodeCurrent -StartImage 'a/si:1' -NowImage 'a/si:2' | Should -BeFalse
        Test-SIPipelineCodeCurrent -StartImage 'a/si:1' -NowImage '' | Should -BeTrue
        Test-SIPipelineCodeCurrent -StartImage '' -NowImage 'a/si:2' | Should -BeTrue
        $script:QClock = $script:T0.AddHours(5)
        $script:LastRun = [pscustomobject]@{ FlowRunId = 'done'; State = 'Succeeded'; Outcome = 'New'; Scope = 'pipeline'; StartedUtc = $script:T0; EndedUtc = $script:T0.AddHours(1); HeartbeatUtc = $script:T0.AddHours(1); LastSlotUtc = $script:T0; Steps = @() }
        $null = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope step -Target ptc))
        $null = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope stage -Target deliver))
        $null = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Holder 'w' -Now { $script:QClock } -Log $script:LogSb -CodeCurrent { throw 'ARM 503' }
        @($script:RunLog) | Should -Be @('step|ptc', 'stage|deliver')
    }
    It 'the runner wires the check: the flow job''s image at the start against its image before each further run' {
        $s = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine/flow/Invoke-SIJobFlowRun.ps1')
        $s | Should -Match ([regex]::Escape('$flowStartImage = & $readFlowImage'))
        $s | Should -Match ([regex]::Escape('Test-SIPipelineCodeCurrent -StartImage $flowStartImage -NowImage (& $readFlowImage)'))
        $s | Should -Match 'Invoke-SIPipelineDrain .*-CodeCurrent \$codeCurrent'
        $s | Should -Match ([regex]::Escape('properties.template.containers)[0].image'))
    }
    It 'an unfinished run of a stopped runner is resumed before anything in the queue' {
        $script:LastRun = [pscustomobject]@{ FlowRunId = 'old'; State = 'Running'; StartedUtc = $script:QClock.AddHours(-2); EndedUtc = $null; HeartbeatUtc = $script:QClock.AddMinutes(-40); LastSlotUtc = $script:QClock; Steps = @() }
        $null = $script:Ctl.Enqueue((New-SIPipelineRequest -Scope step -Target ptc))
        $null = Invoke-SIPipelineDrain -Definition $script:Def -Control $script:Ctl -LoadLast { $script:LastRun } -RunOne $script:RunOne -Holder 'w' -Now { $script:QClock } -Log $script:LogSb
        @($script:RunLog) | Should -Be @('resume', 'step|ptc')
    }
}

Describe 'the Pro lock and queue (SQL) over the store seam' {
    It 'reads every answer the way New-SIProSettingsStore returns it (ONE array of hashtables)' {
        $script:Sql = New-Object System.Collections.Generic.List[object]
        $inv = {
            param($sql, $p, $mode)
            $script:Sql.Add([pscustomobject]@{ Sql = $sql; P = $p; Mode = $mode })
            if ($sql -match 'cfg\.PipelineLock WITH \(UPDLOCK') { return , @(@{ Holder = 'me'; What = 'x'; AcquiredUtc = [datetime]::UtcNow; HeartbeatUtc = [datetime]::UtcNow; PreviousHolder = 'dead'; Mine = 1 }) }
            if ($sql -match "N'Deduplicated'") { return , @(@{ Id = [long]41; Outcome = 'Deduplicated' }) }
            if ($sql -match 'SELECT TOP \(1\) Id, Scope') { return , @(@{ Id = [long]42; Scope = 'stage'; Target = 'correlate'; Trg = 'manual'; RequestedBy = 'ann'; RequestedUtc = [datetime]::UtcNow; SlotUtc = [DBNull]::Value; Note = [DBNull]::Value; State = 'Queued'; FlowRunId = [DBNull]::Value; Outcome = [DBNull]::Value }) }
            if ($sql -match "State IN \(N'Queued', N'Running'\) ORDER BY Id") { return , @(@{ Id = [long]42; Scope = 'stage'; Target = 'correlate'; Trg = 'manual'; State = 'Queued' }, @{ Id = [long]43; Scope = 'pipeline'; Target = ''; Trg = 'schedule'; State = 'Queued' }) }
            if ($sql -match 'AS Taken|AS Held|AS Cancelled') { return , @(@{ Taken = 1; Held = 1; Cancelled = 1 }) }
            , @()
        }
        $c = New-SIPipelineSqlControl -Invoke $inv
        $l = $c.AcquireLock('me', 'x', 15)
        ($l.Available, $l.Acquired, $l.TookOver) | Should -Be @($true, $true, 'dead')
        $q = $c.Enqueue((New-SIPipelineRequest -Scope stage -Target correlate -RequestedBy 'ann'))
        ($q.Id, $q.Outcome) | Should -Be @(41, 'Deduplicated')
        $n = $c.NextQueued()
        ($n.Id, $n.Scope, $n.Target, $n.Trigger, $n.RequestedBy, $n.SlotUtc) | Should -Be @(42, 'stage', 'correlate', 'manual', 'ann', $null)
        @($c.List()).Count | Should -Be 2
        $c.MarkRunning(42, 'run-1') | Should -BeTrue
        $c.Cancel(43, 'ann') | Should -BeTrue
        $c.HeartbeatLock('me', 'run-1', 'x') | Should -BeTrue
        @($script:Sql | Where-Object { $_.Sql -match 'INSERT cfg.PipelineQueue' })[0].P.Scope | Should -Be 'stage'
    }
    It 'an older database without the tables: no lock (the run record''s heartbeat guards), and a Run now still runs' {
        $c = New-SIPipelineSqlControl -Invoke { param($sql, $p, $mode) if ($sql -match 'PipelineLock\) IS NULL') { return , @(@{ Holder = [DBNull]::Value; Mine = -1 }) }; if ($sql -match "N'Missing'") { return , @(@{ Id = [long]0; Outcome = 'Missing' }) }; , @() }
        $l = $c.AcquireLock('me', 'x', 15); ($l.Available, $l.Acquired) | Should -Be @($false, $true)
        $script:Ran = $null
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        # a fixed clock, away from the default 22:00 start: on the real clock, from 22:00 Copenhagen the scheduled run is
        # due too and runs after the Run now (release gate 2026-10-06, run at 21:58-22:13)
        $o = Invoke-SIPipelineDrain -Definition $d -Control $c -LoadLast { $null } -RunOne { param($r, $p, $f) $script:Ran = $r; [pscustomobject]@{ State = 'Succeeded'; Outcome = 'New' } } -Request (New-SIPipelineRequest -Scope step -Target ptc) -Log { param($l, $m) } -Now { [datetime]::SpecifyKind([datetime]'2026-10-05T10:00:00', 'Utc') }
        $o.Outcome | Should -Be 'Ran'; $script:Ran.Target | Should -Be 'ptc'
    }
    It 'the run store keeps what was run, by whom, and each step''s stage' {
        $script:Calls = New-Object System.Collections.Generic.List[object]
        $store = New-SIJobFlowSqlStore -Invoke { param($sql, $p, $mode) $script:Calls.Add([pscustomobject]@{ Sql = $sql; P = $p }); , @() }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'asset-correlation') -Map $script:Map
        $st = New-SIJobFlowRunState -Definition $d -NowUtc $script:T0 -Scope stage -Target correlate -RequestedBy 'ann' -RequestId 9
        $store.Save($st)
        $run = @($script:Calls | Where-Object { $_.Sql -match 'MERGE cfg.FlowRun' })[0]
        ($run.P.Scope, $run.P.Target, $run.P.RequestedBy, $run.P.RequestId) | Should -Be @('stage', 'correlate', 'ann', 9)
        $run.Sql | Should -Match "COL_LENGTH\(N'cfg.FlowRun', N'Scope'\)"
        @($script:Calls | Where-Object { $_.Sql -match 'MERGE cfg.FlowStepRun' })[0].P.Stage | Should -Be 'correlate'
        # read back as the real reader returns it
        $load = New-SIJobFlowSqlStore -Invoke {
            param($sql, $p, $mode)
            if ($sql -match 'FROM cfg.FlowRun') { return , @(@{ FlowRunId = 'r1'; Day = '2026-10-05'; Trg = 'manual'; FromStep = ''; State = 'Succeeded'; StartedUtc = $script:T0; EndedUtc = $script:T0; HeartbeatUtc = $script:T0; StopReason = ''; SlotUtc = [DBNull]::Value; LastSlotUtc = [DBNull]::Value; Note = ''; Scope = 'stage'; Target = 'correlate'; RequestedBy = 'ann'; RequestId = [long]9 }) }
            if ($sql -match 'FROM cfg.FlowStepRun') { return , @(@{ StepOrder = 1; GroupNo = 2; Job = 'asset-correlation'; Stage = 'correlate'; State = 'Success'; Execution = 'e'; StartedUtc = $script:T0; EndedUtc = $script:T0; ErrorClass = ''; Error = '' }, @{ StepOrder = 2; GroupNo = 3; Job = 'asset-properties'; Stage = 'correlate'; State = 'Success'; Execution = 'f'; StartedUtc = $script:T0; EndedUtc = $script:T0; ErrorClass = ''; Error = '' }) }
            , @()
        }
        $back = $load.Load()
        ($back.Scope, $back.Target, $back.RequestedBy, $back.RequestId) | Should -Be @('stage', 'correlate', 'ann', 9)
        @($back.Steps | ForEach-Object Stage) | Should -Be @('correlate', 'correlate')
    }
}

Describe 'the start time in the install''s time zone' {
    It 'a new install starts at 19:00 Danish time (owner 2026-10-21) when no region is known, whatever its own zone; a start time that is set is read in its zone' {
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        ($d.StartTime, $d.TimeZone) | Should -Be @('19:00', 'Europe/Copenhagen')
        $global:SI_Pipeline_TimeZone = 'America/Nuuk'
        try { $n = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map; ($n.StartTime, $n.TimeZone) | Should -Be @('19:00', 'Europe/Copenhagen') -Because 'Greenland time: the default is still Danish time' }
        finally { $global:SI_Pipeline_TimeZone = $null }
        $global:SI_Pipeline_TimeZone = 'America/New_York'; $global:SI_Pipeline_StartTime = '21:15'
        try { $d2 = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map; ($d2.StartTime, $d2.TimeZone) | Should -Be @('21:15', 'America/New_York') }
        finally { $global:SI_Pipeline_TimeZone = $null; $global:SI_Pipeline_StartTime = $null }
        $global:SI_Pipeline_StartTime = '25:00'
        try { (New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map).StartTime | Should -Be '19:00' -Because 'a malformed time is ignored' } finally { $global:SI_Pipeline_StartTime = $null }
        # 19:00 Danish time = 17:00 UTC in summer, 18:00 UTC in winter: after the 18:30 update in both
        $u = { param($s) [datetime]::SpecifyKind([datetime]$s, 'Utc') }
        Get-SIJobFlowLatestSlot -Definition $d -NowUtc (& $u '2026-07-01T23:00:00') | Should -Be (& $u '2026-07-01T17:00:00')
        Get-SIJobFlowLatestSlot -Definition $d -NowUtc (& $u '2026-01-10T23:00:00') | Should -Be (& $u '2026-01-10T18:00:00')
    }
    It 'daylight saving: 22:00 Copenhagen is 21:00 UTC in winter and 20:00 UTC in summer (the last Sundays of March and October)' {
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map -StartTime '22:00' -TimeZone 'Europe/Copenhagen'
        $u = { param($s) [datetime]::SpecifyKind([datetime]$s, 'Utc') }
        Get-SIJobFlowLatestSlot -Definition $d -NowUtc (& $u '2026-03-28T23:00:00') | Should -Be (& $u '2026-03-28T21:00:00')
        Get-SIJobFlowLatestSlot -Definition $d -NowUtc (& $u '2026-03-29T23:00:00') | Should -Be (& $u '2026-03-29T20:00:00')
        Get-SIJobFlowLatestSlot -Definition $d -NowUtc (& $u '2026-10-24T23:00:00') | Should -Be (& $u '2026-10-24T20:00:00')
        Get-SIJobFlowLatestSlot -Definition $d -NowUtc (& $u '2026-10-25T23:00:00') | Should -Be (& $u '2026-10-25T21:00:00')
        # 20:30 UTC on the summer day: the slot was 20:00 -- due; on the winter day 20:30 is before 21:00 -- yesterday's
        Get-SIJobFlowLatestSlot -Definition $d -NowUtc (& $u '2026-10-25T20:30:00') | Should -Be (& $u '2026-10-24T20:00:00')
        $due = Get-SIJobFlowDue -Definition $d -Previous ([pscustomobject]@{ FlowRunId = 'y'; State = 'Succeeded'; StartedUtc = (& $u '2026-03-28T21:00:00'); EndedUtc = (& $u '2026-03-28T23:00:00'); LastSlotUtc = (& $u '2026-03-28T21:00:00') }) -NowUtc (& $u '2026-03-29T20:05:00')
        ($due.Action, $due.SlotUtc) | Should -Be @('Start', (& $u '2026-03-29T20:00:00'))
        Get-SIJobFlowCron -Definition $d -NowUtc (& $u '2026-07-01T12:00:00') | Should -Be '0 20 * * *'
        Get-SIPipelineScheduleText -Definition $d -NowUtc (& $u '2026-01-10T12:00:00') | Should -Be '22:00 Europe/Copenhagen (21:00 UTC today)'
    }
    It 'a time that does not exist (spring forward) runs when the clock reaches it; the weekday is the local one' {
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map -StartTime '02:30' -TimeZone 'Europe/Copenhagen'
        $u = { param($s) [datetime]::SpecifyKind([datetime]$s, 'Utc') }
        Get-SIJobFlowLatestSlot -Definition $d -NowUtc (& $u '2026-03-29T05:00:00') | Should -Be (& $u '2026-03-29T01:30:00')
        $w = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map -StartTime '00:30' -TimeZone 'Europe/Copenhagen'
        $w.Cadence = 'weekly'; $w.Weekday = 1   # Monday 00:30 Copenhagen = Sunday 22:30 UTC in summer
        Get-SIJobFlowLatestSlot -Definition $w -NowUtc (& $u '2026-10-05T12:00:00') | Should -Be (& $u '2026-10-04T22:30:00')
    }
    It 'a Windows id works as well as an IANA id; an unknown zone is UTC with a warning' {
        (Resolve-SIPipelineTimeZone 'Romance Standard Time').Fallback | Should -BeFalse
        (Resolve-SIPipelineTimeZone 'Europe/Copenhagen').Fallback | Should -BeFalse
        $x = Resolve-SIPipelineTimeZone 'Mars/Olympus_Mons'
        $x.Fallback | Should -BeTrue; $x.Zone.Id | Should -Be ([TimeZoneInfo]::Utc.Id); $x.Why | Should -Match 'read as UTC'
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map -StartTime '22:00' -TimeZone 'Mars/Olympus_Mons'
        (Test-SIJobFlowDefinition -Definition $d -Map $script:Map).Warnings -join ' ' | Should -Match 'not known'
        Get-SIJobFlowLatestSlot -Definition $d -NowUtc ([datetime]::SpecifyKind([datetime]'2026-10-05T23:00:00', 'Utc')) | Should -Be ([datetime]::SpecifyKind([datetime]'2026-10-05T22:00:00', 'Utc'))
    }
    It 'the guided install writes the start time and the time zone: the answer, else this machine''s zone, else the setting''s default on a UTC machine' {
        . ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-GuidedInstall.ps1'))
        Get-SIInstallPipelineTimeZone -Answer 'Europe/Oslo' | Should -Be 'Europe/Oslo'
        $cph = (Resolve-SIPipelineTimeZone 'Europe/Copenhagen').Zone
        # pre-filled from the machine; a Windows id is written as its IANA id where .NET can convert it (pwsh 7), because
        # the jobs run on Linux (live 2026-10-06, Community rehearsal); Windows PowerShell 5.1 keeps the id (SI-Pipeline maps it)
        $canConvert = [bool][TimeZoneInfo].GetMethod('TryConvertWindowsIdToIanaId', [Type[]]@([string], [string].MakeByRefType()))
        $expected = if ($canConvert) { 'Europe/Copenhagen' } else { $cph.Id }
        Get-SIInstallPipelineTimeZone -Answer '' -Local $cph | Should -Be $expected -Because 'pre-filled from the machine'
        Get-SIInstallPipelineTimeZone -Answer '' -Local ([TimeZoneInfo]::Utc) | Should -Be 'Europe/Copenhagen' -Because 'Azure Cloud Shell runs on UTC'
        (Resolve-SIPipelineTimeZone (Get-SIInstallPipelineTimeZone -Answer '' -Local $cph)).Fallback | Should -BeFalse
        $p = (Get-Content -Raw ([IO.Path]::Combine($script:SIRoot, 'setup', 'install-parameters.json')) | ConvertFrom-Json).parameters
        @($p | Where-Object key -eq 'pipelineStartTime')[0].default | Should -Be '19:00'
        # owner 2026-10-21: the default start (19:00) is Danish time whatever zone was answered (no region known here); a time of one's own is read in that zone
        $ps = Get-SIInstallPipelineSchedule -StartAnswer '' -ZoneAnswer 'America/Nuuk'; ($ps.StartTime, $ps.TimeZone) | Should -Be @('19:00', 'Europe/Copenhagen')
        $ps = Get-SIInstallPipelineSchedule -StartAnswer '19:00' -ZoneAnswer ''; ($ps.StartTime, $ps.TimeZone) | Should -Be @('19:00', 'Europe/Copenhagen')
        $ps = Get-SIInstallPipelineSchedule -StartAnswer '21:00' -ZoneAnswer 'America/Nuuk'; ($ps.StartTime, $ps.TimeZone) | Should -Be @('21:00', 'America/Nuuk')
        (Get-Content -Raw ([IO.Path]::Combine($script:SIRoot, 'setup', '_shared', 'SI-GuidedInstall.ps1'))) | Should -Match "Get-SIInstallPipelineSchedule -StartAnswer \(\[string\]\`$v\['pipelineStartTime'\]\)"
        @($p | Where-Object key -eq 'pipelineTimeZone').Count | Should -Be 1
    }
    It 'the migration keeps an existing schedule''s time as UTC; a schema-2 definition keeps its zone' {
        $old = ConvertFrom-SIJobFlowJson -Json '{"schema":1,"startTime":"01:00","cadence":"daily","steps":[{"job":"ptc"}]}' -Map $script:Map
        $old.TimeZone | Should -Be 'UTC'
        Get-SIJobFlowLatestSlot -Definition $old -NowUtc ([datetime]::SpecifyKind([datetime]'2026-07-01T02:00:00', 'Utc')) | Should -Be ([datetime]::SpecifyKind([datetime]'2026-07-01T01:00:00', 'Utc'))
        (ConvertFrom-SIJobFlowJson -Json (ConvertTo-SIJobFlowJson (New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map -StartTime '01:00' -TimeZone 'Asia/Tokyo')) -Map $script:Map).TimeZone | Should -Be 'Asia/Tokyo'
    }
}

Describe 'the daily trend row at the end of Risk Analysis' {
    It 'is written by a Detailed run that published its rows (#636: the trend counts findings) -- never a dry run, a partial run, or when switched off' {
        (Test-SIRaTrendAtEnd -Detailed $true -Published $true -WhatIfRun $false -RowCount 10).Run | Should -BeTrue
        (Test-SIRaTrendAtEnd -Detailed $false -Published $true -WhatIfRun $false -RowCount 10).Run | Should -BeFalse
        (Test-SIRaTrendAtEnd -Detailed $true -Published $false -WhatIfRun $false -RowCount 10).Run | Should -BeFalse
        (Test-SIRaTrendAtEnd -Detailed $true -Published $true -WhatIfRun $true -RowCount 10).Run | Should -BeFalse
        (Test-SIRaTrendAtEnd -Detailed $true -Published $true -WhatIfRun $false -RowCount 0).Run | Should -BeFalse
        (Test-SIRaTrendAtEnd -Detailed $true -Published $true -WhatIfRun $false -RowCount 10 -LostBuckets 2).Why | Should -Match 'gap'
        (Test-SIRaTrendAtEnd -Detailed $true -Published $true -WhatIfRun $false -RowCount 10 -UpstreamExit 'success-partial').Run | Should -BeFalse
        (Test-SIRaTrendAtEnd -Detailed $true -Published $true -WhatIfRun $false -RowCount 10 -Setting $false).Run | Should -BeFalse
        (Test-SIRaTrendAtEnd -Detailed $true -Published $true -WhatIfRun $false -RowCount 10 -Setting 'off').Run | Should -BeFalse
        (Test-SIRaTrendAtEnd -Detailed $true -Published $true -WhatIfRun $false -RowCount 10 -Setting $true).Run | Should -BeTrue
    }
    BeforeAll { . ([IO.Path]::Combine($script:SIRoot, 'engine', 'risk-analysis', '_shared', 'RA-TrendAtEnd.ps1')) }
    It 'runs the trend engine with the rows this run published; a failure never fails Risk Analysis' {
        $eng = Join-Path (New-TempDir) 'fake-trend.ps1'
        Set-Content -LiteralPath $eng -Value 'param($Grain, [object[]]$PublishedRows) $global:SI306TrendCall = @{ Grain = $Grain; Count = @($PublishedRows).Count }'
        $r = Invoke-SIRaTrendAtEnd -Rows @(1, 2, 3) -Detailed $true -Published $true -WhatIfRun $false -Engine $eng -Log { param($l, $m) }
        $r.Ran | Should -BeTrue; $global:SI306TrendCall.Grain | Should -Be 'Detailed'; $global:SI306TrendCall.Count | Should -Be 3
        Set-Content -LiteralPath $eng -Value 'throw "ingest refused"'
        $w = New-Object System.Collections.Generic.List[string]
        (Invoke-SIRaTrendAtEnd -Rows @(1) -Detailed $true -Published $true -WhatIfRun $false -Engine $eng -Log { param($l, $m) $w.Add("$l $m") }.GetNewClosure()).Ran | Should -BeFalse
        ($w -join ' ') | Should -Match 'WARN .*gap'
        Remove-Variable -Name SI306TrendCall -Scope Global -ErrorAction SilentlyContinue
    }
    It 'is wired: Risk Analysis calls it after a successful run, and the trend engine rolls up the rows it is given' {
        $ra = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'engine', 'risk-analysis', 'Invoke-RiskAnalysis.ps1'))
        $ok = $ra.LastIndexOf("Send-RARunHealthEnd -ExitReason 'success'")
        $call = $ra.IndexOf('Invoke-SIRaTrendAtEnd -Rows @($script:_RAPublishedRows)')
        $ok | Should -BeGreaterThan 0
        $call | Should -BeGreaterThan $ok -Because 'the trend row is written only after the run recorded success'
        $ra.Substring($ok, $call - $ok) | Should -Match "_shared/RA-TrendAtEnd.ps1"
        $tr = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'engine', 'asset-trend', 'Invoke-SITrend.ps1'))
        $tr | Should -Match "\`$PSBoundParameters.ContainsKey\('PublishedRows'\)"
    }
}
