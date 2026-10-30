#Requires -Version 5.1
<#
    THE DAILY JOB FLOW (#269): engine/_shared/SI-JobFlow.ps1 -- the definition, the default flow from the ONE dependency
    map (config/job-flow.locked.json), and the RUNNER over a fake Azure Resource Manager and a fake clock: the order,
    parallel groups ("start together with the step above"), stop / continue / skip-dependents, timeouts, and a crash
    mid-run (the restart resumes the record or reports it -- a step is NEVER started twice). Offline; PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-JobFlow.ps1'))
    # #636: a new pipeline has the Risk Analysis Summary step switched OFF (SIv3-SummaryGroupings.Tests.ps1). The runner's
    # mechanics here use it as an ordinary step -- an install that switched it on -- so the default flow has every step on.
    $script:SINewDefaultFlowShipped = ${function:New-SIDefaultJobFlow}
    function New-SIDefaultJobFlow { $d = & $script:SINewDefaultFlowShipped @args; foreach ($s in @($d.Steps)) { $s.Enabled = $true }; $d }
    $script:Map = Get-SIJobFlowMap
    # #306: the shipped default is 22:00 in the install's time zone; the clock tests below are written for a 01:00 UTC
    # pipeline, set through the two settings (the default itself is proven in SIv3-Pipeline.Tests.ps1)
    $script:SavedStart = $global:SI_Pipeline_StartTime; $script:SavedTz = $global:SI_Pipeline_TimeZone
    $global:SI_Pipeline_StartTime = '01:00'; $global:SI_Pipeline_TimeZone = 'UTC'
    # #306: the Daily pipeline -- Collect (the profilers), Correlate (asset-correlation, then Risk Analysis on the CIs), Deliver (#412: asset-properties is retired)
    # the updater is installed but never a step (UPDATE-1.6: it runs on its own daily schedule)
    $script:All = @('ptc', 'identity', 'azure', 'endpoint', 'publicip',
                    'asset-correlation', 'risk-analysis', 'risk-analysis-detailed',
                    'asset-cmdb-sql', 'asset-cmdb', 'asset-vulnerabilities', 'asset-vulns-servicenow', 'asset-datasync', 'close-loop-mail')

    # ---- a fake ARM: each job's executions run for N polls, then end with the scripted status ----
    function New-FakeArm {
        # -Running: job key -> the name of an execution of it that SOMEBODY ELSE started and that is running now (it runs for
        # the job's -Polls and ends with its -Outcome, like an execution the pipeline started); -ListFails: the jobs whose
        # executions cannot be listed
        param([hashtable]$Outcome = @{}, [hashtable]$Polls = @{}, [string[]]$StartFails = @(), [hashtable]$Running = @{}, [string[]]$ListFails = @())
        $script:Arm = @{ Outcome = $Outcome; Polls = $Polls; StartFails = $StartFails; Starts = (New-Object System.Collections.Generic.List[string]); Exec = @{}; Stops = (New-Object System.Collections.Generic.List[string]); Calls = (New-Object System.Collections.Generic.List[string]); Running = $Running; ListFails = $ListFails }
        foreach ($rk in @($Running.Keys)) {
            $n = 1; if ($Polls.ContainsKey($rk)) { $n = [int]$Polls[$rk] }
            $script:Arm.Exec[[string]$Running[$rk]] = @{ Left = $n; End = $(if ($Outcome.ContainsKey($rk)) { $Outcome[$rk] } else { 'Succeeded' }) }
        }
        return {
            param($Method, $Path, $Body)
            $script:Arm.Calls.Add(('{0} {1}' -f $Method, $Path))
            # a job's executions (the pipeline asks before it starts a step): only what somebody else has running
            if ($Method -eq 'GET' -and $Path -match '/jobs/caj-si-([a-z0-9\-]+)/executions$') {
                $k = $Matches[1]
                if ($script:Arm.ListFails -contains $k) { throw 'ARM GET returned 503' }
                $v = @()
                if ($script:Arm.Running.ContainsKey($k) -and $script:Arm.Exec[[string]$script:Arm.Running[$k]].Left -gt 0) {
                    $v = @([pscustomobject]@{ name = [string]$script:Arm.Running[$k]; properties = [pscustomobject]@{ status = 'Running'; startTime = '2026-10-05T00:40:00Z' } })
                }
                return [pscustomobject]@{ value = $v }
            }
            if ($Method -eq 'POST' -and $Path -match '/jobs/caj-si-([a-z0-9\-]+)/start$') {
                $k = $Matches[1]
                if ($script:Arm.StartFails -contains $k) { throw "ARM POST returned 403" }
                $name = '{0}-x{1}' -f $k, ($script:Arm.Starts.Count + 1)
                $script:Arm.Starts.Add($k)
                $n = 1; if ($script:Arm.Polls.ContainsKey($k)) { $n = [int]$script:Arm.Polls[$k] }
                $script:Arm.Exec[$name] = @{ Left = $n; End = $(if ($script:Arm.Outcome.ContainsKey($k)) { $script:Arm.Outcome[$k] } else { 'Succeeded' }) }
                return [pscustomobject]@{ name = $name; id = "/x/executions/$name" }
            }
            if ($Method -eq 'GET' -and $Path -match '/executions/([a-z0-9\-]+)$') {
                $e = $script:Arm.Exec[$Matches[1]]
                if ($e.Left -gt 0) { $e.Left--; return [pscustomobject]@{ properties = [pscustomobject]@{ status = 'Running' } } }
                return [pscustomobject]@{ properties = [pscustomobject]@{ status = $e.End } }
            }
            if ($Method -eq 'POST' -and $Path -match '/stop/([a-z0-9\-]+)$') { $script:Arm.Stops.Add($Matches[1]); return $null }
            if ($Method -eq 'GET' -and $Path -match '/jobs$') { return [pscustomobject]@{ value = @($script:All | ForEach-Object { [pscustomobject]@{ name = "caj-si-$_" } }) } }
            throw "unexpected ARM call $Method $Path"
        }
    }
    function New-Seams { param($Arm) New-SIJobFlowArmSeams -SubscriptionId 'sub' -ResourceGroup 'rg' -Arm $Arm }
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-10-05T01:00:00', 'Utc')
    function Reset-Clock { $script:Clock = $script:T0 }
    $script:NowSb = { $script:Clock }
    $script:SleepSb = { param($s) $script:Clock = $script:Clock.AddSeconds($s) }
    $script:Quiet = { param($l, $m) }
    function Invoke-Flow {
        param($Definition, $Arm, $Previous, [string]$FromStep, [switch]$Force, [scriptblock]$Save)
        if (-not $Save) { $Save = { param($s) $script:Saved = (ConvertTo-SIJobFlowRunJson -State $s) } }
        $p = @{ Definition = $Definition; Seams = (New-Seams $Arm); Save = $Save; Now = $script:NowSb; Sleep = $script:SleepSb; Log = $script:Quiet; Map = $script:Map; PollSeconds = 60; Previous = $Previous }
        if ($FromStep) { $p.FromStep = $FromStep }
        if ($Force) { $p.Force = $true }
        Invoke-SIJobFlow @p
    }
    function Get-StepState { param($State, [string]$Job) @($State.Steps | Where-Object { $_.Job -eq $Job })[0].State }
}
AfterAll { $global:SI_Pipeline_StartTime = $script:SavedStart; $global:SI_Pipeline_TimeZone = $script:SavedTz }

Describe 'the dependency map and the default flow' {
    It 'every need names a job of the map, and the default flow lists only flow jobs' {
        foreach ($j in $script:Map.Jobs.Values) { foreach ($n in $j.Needs) { $script:Map.Jobs.Contains($n) | Should -BeTrue -Because "$($j.Key) needs $n" } }
        foreach ($k in $script:Map.DefaultFlow) { $script:Map.Jobs[$k].NeverInFlow | Should -BeFalse }
    }
    It 'the default flow is the operator''s order, one step after the other except azure + endpoint and the two Risk Analysis reports together, starting 01:00 UTC daily' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        @($d.Steps.Job) | Should -Be $script:All
        @((New-SIDefaultJobFlow -Installed (@('updater') + $script:All) -Map $script:Map).Steps.Job) | Should -Be $script:All -Because 'the updater is installed but never a step'
        @($d.Steps | Where-Object WithPrevious | ForEach-Object Job) | Should -Be @('endpoint', 'risk-analysis-detailed') -Because 'endpoint starts together with azure, Risk Analysis Detailed with Summary (#754) -- neither reads the other''s output of the same day'
        $d.StartTime | Should -Be '01:00'; $d.Cadence | Should -Be 'daily'; $d.Mode | Should -Be 'flow'
        (Get-SIJobFlowCron -Definition $d) | Should -Be '0 1 * * *'
        (Test-SIJobFlowDefinition -Definition $d -Map $script:Map).Problems | Should -BeNullOrEmpty
        (Test-SIJobFlowDefinition -Definition $d -Map $script:Map).Warnings | Should -BeNullOrEmpty -Because 'the default order never runs a job before one it needs'
    }
    It 'a job that is not installed is left out (no ServiceNow, no updater, Community)' {
        $d = New-SIDefaultJobFlow -Installed @('caj-si-ptc', 'caj-si-endpoint', 'caj-si-identity', 'caj-si-azure', 'caj-si-risk-analysis', 'caj-si-risk-analysis-detailed', 'caj-si-asset-trend') -Map $script:Map
        @($d.Steps.Job) | Should -Be @('ptc', 'identity', 'azure', 'endpoint', 'risk-analysis', 'risk-analysis-detailed') -Because 'the risk trend is no step of the default pipeline (#306)'
    }
    It 'the ServiceNow vulnerability connector runs after the CMDB connector and the SQL connector; mails after both' {
        $script:Map.Jobs['asset-vulns-servicenow'].Needs | Should -Contain 'asset-cmdb'
        $script:Map.Jobs['close-loop-mail'].Needs | Should -Contain 'asset-vulns-servicenow'
        $script:Map.Jobs['asset-datasync'].Needs | Should -Contain 'asset-vulnerabilities'
        $script:Map.Jobs['asset-datasync'].Needs | Should -Not -Contain 'asset-vulns-servicenow'
        $i = [array]::IndexOf($script:Map.DefaultFlow, 'asset-vulns-servicenow')
        $i | Should -BeGreaterThan ([array]::IndexOf($script:Map.DefaultFlow, 'asset-cmdb'))
        $i | Should -BeGreaterThan ([array]::IndexOf($script:Map.DefaultFlow, 'asset-vulnerabilities'))
        $i | Should -BeLessThan ([array]::IndexOf($script:Map.DefaultFlow, 'asset-datasync'))
    }
    It 'the JSON round-trips (one step too -- PS 5.1 must not collapse the list)' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        $d.Steps[3].WithPrevious = $true; $d.Steps[2].OnFailure = 'stop'; $d.Steps[1].TimeoutMinutes = 45
        $back = ConvertFrom-SIJobFlowJson -Json (ConvertTo-SIJobFlowJson -Definition $d)
        (ConvertTo-SIJobFlowJson -Definition $back) | Should -Be (ConvertTo-SIJobFlowJson -Definition $d)
        $one = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        @((ConvertFrom-SIJobFlowJson -Json (ConvertTo-SIJobFlowJson -Definition $one)).Steps).Count | Should -Be 1
        (ConvertTo-SIJobFlowJson -Definition $one) | Should -Match '"steps":\s*\['
    }
    It 'refuses what cannot run, and warns about a step before a job it needs' {
        $d = ConvertFrom-SIJobFlowJson -Json '{"startTime":"25:00","cadence":"hourly","steps":[{"job":"publicip"},{"job":"endpoint","onFailure":"retry"},{"job":"endpoint"},{"job":"templates"},{"job":"ptc","timeoutMinutes":2}]}'
        $r = Test-SIJobFlowDefinition -Definition $d -Map $script:Map
        ($r.Problems -join "`n") | Should -Match 'start time'
        ($r.Problems -join "`n") | Should -Match 'cadence'
        ($r.Problems -join "`n") | Should -Match "on failure 'retry'"
        ($r.Problems -join "`n") | Should -Match 'already step \d'
        ($r.Problems -join "`n") | Should -Match 'templates is never part of the flow'
        ($r.Problems -join "`n") | Should -Match 'timeout must be 5-4320'
        ($r.Warnings -join "`n") | Should -Match 'publicip runs before endpoint'   # both in Collect: warned, never moved
    }
    It 'the cron follows the cadence' {
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        $d.StartTime = '23:05'; $d.Cadence = 'weekdays'; (Get-SIJobFlowCron $d) | Should -Be '5 23 * * 1-5'
        $d.Cadence = 'weekly'; $d.Weekday = 0; (Get-SIJobFlowCron $d) | Should -Be '5 23 * * 0'
    }
    It 'new installs default to the flow; existing installs keep their timers until switched' {
        (Get-SIJobOrchestrationMode -Explicit '' -ExistingInstall $false).Mode | Should -Be 'flow'
        (Get-SIJobOrchestrationMode -Explicit '' -ExistingInstall $true).Mode | Should -Be 'schedules'
        (Get-SIJobOrchestrationMode -Explicit 'Flow' -ExistingInstall $true).Mode | Should -Be 'flow'
        (Get-SIJobOrchestrationMode -Explicit 'nonsense' -ExistingInstall $false).Why | Should -Match 'ignored'
    }
}

Describe 'the runner: order and parallel groups' {
    BeforeEach { Reset-Clock }
    It 'runs the steps one after the other: a step starts only when the one above has ended' {
        $arm = New-FakeArm -Polls @{ ptc = 3; identity = 2 }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'azure') -Map $script:Map
        $r = Invoke-Flow -Definition $d -Arm $arm
        $r.State | Should -Be 'Succeeded'
        @($script:Arm.Starts) | Should -Be @('ptc', 'identity', 'azure')
        # identity was started only after ptc's 3 running polls + its end
        $ptc = @($r.Steps)[0]; $id = @($r.Steps)[1]
        $id.StartedUtc | Should -BeGreaterOrEqual $ptc.EndedUtc
        @($r.Steps.State) | Should -Be @('Success', 'Success', 'Success')
    }
    It '"start together with the step above" starts a group at once and waits for all of it' {
        $arm = New-FakeArm -Polls @{ identity = 5; azure = 1; endpoint = 2 }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'azure', 'endpoint', 'publicip') -Map $script:Map
        foreach ($s in $d.Steps) { if ($s.Job -in 'azure', 'endpoint') { $s.WithPrevious = $true } }
        $r = Invoke-Flow -Definition $d -Arm $arm
        @($r.Steps | ForEach-Object Group) | Should -Be @(1, 2, 2, 2, 3)
        $g = @($r.Steps | Where-Object Group -eq 2)
        @($g.StartedUtc | Select-Object -Unique).Count | Should -Be 1 -Because 'the group starts together'
        $pub = @($r.Steps | Where-Object Job -eq 'publicip')[0]
        $pub.StartedUtc | Should -BeGreaterOrEqual (@($g.EndedUtc | Sort-Object)[-1]) -Because 'the next group waits for the slowest member'
    }
    It 'a disabled step is not run, and its dependents still run' {
        $arm = New-FakeArm
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map
        $d.Steps[0].Enabled = $false
        $r = Invoke-Flow -Definition $d -Arm $arm
        @($script:Arm.Starts) | Should -Be @('identity')
        (Get-StepState $r 'ptc') | Should -Be 'Disabled'
        $r.State | Should -Be 'Succeeded'
    }
}

Describe 'the runner: failures' {
    BeforeEach { Reset-Clock }
    It 'skip-dependents (default): only the steps that NEED the failed one are skipped, transitively' {
        # the CI build fails: Risk Analysis needs it (directly) -- skipped; the collections before it are untouched
        $arm = New-FakeArm -Outcome @{ 'asset-correlation' = 'Failed' }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'azure', 'endpoint', 'publicip', 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed') -Map $script:Map
        $r = Invoke-Flow -Definition $d -Arm $arm
        (Get-StepState $r 'asset-correlation') | Should -Be 'Failed'
        foreach ($k in 'risk-analysis', 'risk-analysis-detailed') { (Get-StepState $r $k) | Should -Be 'Skipped' -Because "$k needs the CI build" }
        foreach ($k in 'ptc', 'identity', 'azure', 'endpoint', 'publicip') { (Get-StepState $r $k) | Should -Be 'Success' }
        @($script:Arm.Starts) | Should -Not -Contain 'risk-analysis'
        @($r.Steps | Where-Object Job -eq 'risk-analysis')[0].Error | Should -Match 'needs'
        $r.State | Should -Be 'Failed'
    }
    It 'the tier classifier fails: every collection needs it, so nothing is collected and Correlate does not start' {
        $arm = New-FakeArm -Outcome @{ ptc = 'Failed' }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'azure', 'endpoint', 'publicip', 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed') -Map $script:Map
        $r = Invoke-Flow -Definition $d -Arm $arm
        foreach ($k in 'identity', 'azure', 'endpoint', 'publicip') { (Get-StepState $r $k) | Should -Be 'Skipped' -Because "$k needs the tier classifier (directly or through another step)" }
        @($r.Steps | Where-Object Job -eq 'publicip')[0].Error | Should -Match 'needs'
        # #306: Correlate does not start after a Collect that did not succeed
        @($r.Steps | Where-Object Job -eq 'asset-correlation')[0].ErrorClass | Should -Be 'stage-blocked'
        $r.State | Should -Be 'Failed'
    }
    It 'one collection fails, the others succeed: the run goes on -- nothing that needs the failed source is skipped' {
        $arm = New-FakeArm -Outcome @{ azure = 'Failed' }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'azure', 'endpoint', 'publicip', 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed') -Map $script:Map
        $r = Invoke-Flow -Definition $d -Arm $arm
        (Get-StepState $r 'azure') | Should -Be 'Failed'
        foreach ($k in 'ptc', 'identity', 'endpoint', 'publicip', 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed') { (Get-StepState $r $k) | Should -Be 'Success' -Because "$k runs on the last good collection of azure" }
        $r.State | Should -Be 'Failed'
    }
    It 'stop: nothing after the failed step runs' {
        $arm = New-FakeArm -Outcome @{ identity = 'Failed' }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'azure', 'endpoint') -Map $script:Map
        $d.Steps[1].OnFailure = 'stop'
        $r = Invoke-Flow -Definition $d -Arm $arm
        @($script:Arm.Starts) | Should -Be @('ptc', 'identity')
        (Get-StepState $r 'azure') | Should -Be 'Skipped'
        @($r.Steps | Where-Object Job -eq 'endpoint')[0].ErrorClass | Should -Be 'flow-stopped'
        $r.State | Should -Be 'Stopped'
        $r.StopReason | Should -Match 'identity failed'
    }
    It 'continue: the dependents run anyway' {
        $arm = New-FakeArm -Outcome @{ ptc = 'Failed' }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'azure') -Map $script:Map
        $d.Steps[0].OnFailure = 'continue'
        $r = Invoke-Flow -Definition $d -Arm $arm
        @($script:Arm.Starts) | Should -Be @('ptc', 'identity', 'azure')
        $r.State | Should -Be 'Failed'
    }
    It 'a step that cannot start (403) fails with start-failed, and skips its dependents' {
        $arm = New-FakeArm -StartFails @('ptc')
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map
        $r = Invoke-Flow -Definition $d -Arm $arm
        @($r.Steps)[0].ErrorClass | Should -Be 'start-failed'
        (Get-StepState $r 'identity') | Should -Be 'Skipped'
    }
    It 'NO GIVE-UP ON ELAPSED TIME (owner 2026-10-13): a step over its step timeout is REPORTED once and keeps running -- it is not stopped and does not count as failed' {
        $arm = New-FakeArm -Polls @{ identity = 1000 }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'asset-correlation', 'azure') -Map $script:Map
        $d.Steps[1].TimeoutMinutes = 30
        $r = Invoke-Flow -Definition $d -Arm $arm
        (Get-StepState $r 'identity') | Should -Be 'Success' -Because 'the step ran on until it ended by itself'
        @($script:Arm.Stops) | Should -BeNullOrEmpty -Because 'the pipeline stops no step for the time it takes'
        @($r.Steps | Where-Object { $_.State -eq 'TimedOut' }) | Should -BeNullOrEmpty
        (Get-StepState $r 'azure') | Should -Be 'Success'
        (Get-StepState $r 'asset-correlation') | Should -Be 'Success'
        $id = @($r.Steps | Where-Object Job -eq 'identity')[0]
        ($id.EndedUtc - $id.StartedUtc).TotalMinutes | Should -BeGreaterThan 500 -Because 'far past its 30 minutes'
        $id.RetryReason | Should -Match '^identity has run for \d+ minutes, longer than its step timeout of 30 minutes\. It keeps running: the pipeline stops no step for the time it takes\.'
        $r.State | Should -Be 'Succeeded'
        Get-SIJobFlowOverdueText -Job 'identity' -RunMinutes 31 -TimeoutMinutes 30 | Should -Be 'identity has run for 31 minutes, longer than its step timeout of 30 minutes. It keeps running: the pipeline stops no step for the time it takes. A step that stands still is reported when it shows no sign of progress.'
    }
    It 'a step''s timeout may be 5 minutes to 72 hours (4320 minutes); NEGATIVE: 4321 is refused' {
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map
        $d.Steps[0].TimeoutMinutes = 4320
        @((Test-SIJobFlowDefinition -Definition $d -Map $script:Map).Problems) -join "`n" | Should -Not -Match 'timeout must be'
        $d.Steps[0].TimeoutMinutes = 4321
        @((Test-SIJobFlowDefinition -Definition $d -Map $script:Map).Problems) -join "`n" | Should -Match 'step 1 \(ptc\): the timeout must be 5-4320 minutes'
    }
    It 'THE STEP TIMEOUT IS A REPORT, NOT A STOP: with or without a known run limit of the job the step runs on; the log says once what applies and once that the step is taking long' {
        $run = {
            param([hashtable]$Polls, [hashtable]$Outcome = @{}, [scriptblock]$JobLimit)
            Reset-Clock; $script:LimitLogs = New-Object System.Collections.Generic.List[string]
            $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map
            $d.Steps[1].TimeoutMinutes = 30
            Invoke-SIJobFlow -Definition $d -Seams (New-Seams (New-FakeArm -Polls $Polls -Outcome $Outcome)) -Save { param($s) } -Now $script:NowSb -Sleep $script:SleepSb `
                -Log { param($l, $m) $script:LimitLogs.Add([string]$m) } -Map $script:Map -PollSeconds 60 -Previous $null -Force -JobLimit $JobLimit
        }
        # the job's own run limit (120 min) is longer than the step timeout (30 min): the step runs on, past both
        $r = & $run @{ identity = 1000 } @{} { param($j) if ($j -eq 'identity') { 120 } else { 0 } }
        $id = @($r.Steps | Where-Object Job -eq 'identity')[0]
        $id.State | Should -Be 'Success'
        ($id.EndedUtc - $id.StartedUtc).TotalMinutes | Should -BeGreaterThan 500
        @($script:LimitLogs) -join "`n" | Should -Match 'identity: the pipeline stops no step for the time it takes -- its job''s own run limit is 120 minutes; after 30 minutes \(the step timeout\) the pipeline says it is taking long'
        @($script:LimitLogs | Where-Object { $_ -match 'identity: the pipeline stops no step' }).Count | Should -Be 1 -Because 'said once per step'
        @($script:LimitLogs | Where-Object { $_ -match 'identity: identity has run for \d+ minutes, longer than its step timeout of 30 minutes' }).Count | Should -Be 1 -Because 'reported once, however long it runs'
        # the job ended by itself at its limit (Azure stopped it): the step failed, and the error says what it ran into
        $r = & $run @{ identity = 121 } @{ identity = 'Failed' } { param($j) 120 }
        $id = @($r.Steps | Where-Object Job -eq 'identity')[0]
        $id.State | Should -Be 'Failed'
        $id.Error | Should -Match 'the execution ended failed after \d+ minutes -- it ran until its job''s own run limit \(120 minutes\)'
        # the job's limit is shorter than the step timeout: nothing is stopped either (Azure ends the job, not the pipeline)
        $r = & $run @{ identity = 1000 } @{} { param($j) 20 }
        $id = @($r.Steps | Where-Object Job -eq 'identity')[0]
        $id.State | Should -Be 'Success'; $id.Error | Should -BeNullOrEmpty
        @($script:LimitLogs) -join "`n" | Should -Match 'identity: the pipeline stops no step for the time it takes -- its job''s own run limit is 20 minutes; after 30 minutes'
        # NEGATIVE: the job's limit cannot be read -> nothing is said about a limit, the step is still reported and still runs on
        $r = & $run @{ identity = 1000 } @{} { param($j) throw 'ARM GET returned 503' }
        (@($r.Steps | Where-Object Job -eq 'identity')[0]).State | Should -Be 'Success'
        @($script:LimitLogs | Where-Object { $_ -match 'the pipeline says it is taking long' }) | Should -BeNullOrEmpty
        @($script:LimitLogs | Where-Object { $_ -match 'longer than its step timeout of 30 minutes' }).Count | Should -Be 1
    }
    It 'A STEP THAT SHOWS NO PROGRESS IS REPORTED, NEVER STOPPED: silent for 2 hours -> ONE warning for that step in that run, and it keeps running' {
        $run = {
            param([scriptblock]$Progress, $Previous, [scriptblock]$Save = { param($s) })
            $script:SilentLogs = New-Object System.Collections.Generic.List[string]; $script:SilentPhases = New-Object System.Collections.Generic.List[string]
            $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map
            $p = @{ Definition = $d; Seams = (New-Seams $script:SilentArm); Save = $Save; Now = $script:NowSb; Sleep = $script:SleepSb; Map = $script:Map; PollSeconds = 60; Previous = $Previous
                    Log = { param($l, $m) $script:SilentLogs.Add(('{0} {1}' -f $l, $m)) }; OnStep = { param($s, $st, $ph) $script:SilentPhases.Add(('{0} {1}' -f $ph, $st.Job)) }; Progress = $Progress }
            if (-not $Previous) { $p.Force = $true }
            Invoke-SIJobFlow @p
        }
        # identity runs for 200 minutes; its job's last log line stays at 5 minutes after it started
        Reset-Clock; $script:SilentArm = New-FakeArm -Polls @{ identity = 200 }; $script:Asked = 0; $script:Snap = $null
        $stuck = { param($Job, $Execution, $StartedUtc) $script:Asked++; [pscustomobject]@{ LastSeenUtc = ([datetime]$StartedUtc).AddMinutes(5) } }
        $keep = { param($s) if (-not $script:Snap -and @($s.Steps | Where-Object { [string]$_.RetryReason -match 'no sign of progress' }).Count) { $script:Snap = ConvertTo-SIJobFlowRunJson -State $s; $script:SnapAt = $script:Clock } }
        $r = & $run $stuck $null $keep
        $id = @($r.Steps | Where-Object Job -eq 'identity')[0]
        $id.State | Should -Be 'Success' -Because 'it was left running and finished by itself'
        @($script:Arm.Stops) | Should -BeNullOrEmpty -Because 'nothing is ever stopped for it'
        $warn = @($script:SilentLogs | Where-Object { $_ -match 'no sign of progress' })
        $warn.Count | Should -Be 1 -Because 'one warning per step per run'
        $warn[0] | Should -Match ('^WARN step {0} identity: identity has shown no sign of progress for 2\.4 hours \(noticed 2026-10-05 03:\d\d UTC; its last log line or record was at 2026-10-05 01:06 UTC\)\. It is still running and nothing is stopped -- if it does not move on, look at the job''s log$' -f $id.Order)
        @($script:SilentPhases | Where-Object { $_ -eq 'Silent identity' }).Count | Should -Be 1 -Because 'one run-health record for it'
        $id.RetryReason | Should -Match 'identity has shown no sign of progress for 2\.4 hours'
        # THE PIPELINE PAGE reads the warning from the step's record while the step runs: the hours and when it was noticed.
        # The saved record (taken while identity was still running) carries both, in the form the web app reads.
        $snapStep = @((ConvertFrom-SIJobFlowRunJson -Json $script:Snap).Steps | Where-Object Job -eq 'identity')[0]
        $snapStep.State | Should -Be 'Running'
        $snapStep.RetryReason | Should -Match 'no sign of progress for 2\.4 hours \(noticed 2026-10-05 03:\d\d UTC; '
        Get-SIJobFlowSilentText -Job 'identity' -SilentMinutes 125 -LastSeenUtc ([datetime]::SpecifyKind([datetime]'2026-10-05T01:06:00', 'Utc')) -NoticedUtc ([datetime]::SpecifyKind([datetime]'2026-10-05T03:11:40', 'Utc')) |
            Should -Be 'identity has shown no sign of progress for 2.1 hours (noticed 2026-10-05 03:11 UTC; its last log line or record was at 2026-10-05 01:06 UTC). It is still running and nothing is stopped -- if it does not move on, look at the job''s log'
        Get-SIJobFlowSilentText -Job 'identity' -SilentMinutes 120 -NoticedUtc ([datetime]::SpecifyKind([datetime]'2026-10-05T03:11:00', 'Utc')) | Should -Match '^identity has shown no sign of progress for 2 hours \(noticed 2026-10-05 03:11 UTC\)\. '
        # the web app reads exactly these two things: its pattern is in JobFlow.cs (SecurityInsight Pro; not in a Community payload)
        $webFlow = Join-Path $script:SIRoot 'pro-management\src\SI.Management.Web\Jobs\JobFlow.cs'
        if (Test-Path -LiteralPath $webFlow) {
            $webPattern = 'no sign of progress for (?<h>\d+(?:\.\d+)?) hours(?: \(noticed (?<t>\d{4}-\d{2}-\d{2} \d{2}:\d{2}) UTC)?'
            [IO.File]::ReadAllText($webFlow) | Should -Match ([regex]::Escape($webPattern))
            $snapStep.RetryReason -match $webPattern | Should -BeTrue
            $Matches['h'] | Should -Be '2.4'; $Matches['t'] | Should -Match '^2026-10-05 03:\d\d$'
        }
        $script:Asked | Should -Be 2 -Because 'asked only once the step has run 2 hours, then every 30 minutes, and not again after the warning'
        $r.State | Should -Be 'Succeeded' -Because 'a warning never changes the run''s outcome'
        # A SECOND WAKE-UP (the runner stopped and the run is resumed): the step is still silent -> NO second warning
        $script:Arm.Exec['identity-x2'].Left = 60
        $script:Clock = $script:SnapAt.AddMinutes(20); $script:Asked = 0
        $r2 = & $run $stuck (ConvertFrom-SIJobFlowRunJson -Json $script:Snap)
        $r2.Outcome | Should -Be 'Resume'
        @($script:SilentLogs | Where-Object { $_ -match 'no sign of progress' }) | Should -BeNullOrEmpty
        $script:SilentPhases | Should -Not -Contain 'Silent identity'
        $script:Asked | Should -Be 0
        # NEGATIVE: the job keeps writing (its last line is always 10 minutes old) -> nothing is said, however long it runs
        Reset-Clock; $script:SilentArm = New-FakeArm -Polls @{ identity = 200 }; $script:Asked = 0
        $r = & $run { param($Job, $Execution, $StartedUtc) $script:Asked++; [pscustomobject]@{ LastSeenUtc = $script:Clock.AddMinutes(-10) } }
        @($script:SilentLogs | Where-Object { $_ -match 'no sign of progress' }) | Should -BeNullOrEmpty
        $script:Asked | Should -Be 3 -Because 'at 120, 150 and 180 minutes'
        # NEGATIVE: it cannot be told (no log line of this job is in the workspace) -> nothing is said: never a false warning
        Reset-Clock; $script:SilentArm = New-FakeArm -Polls @{ identity = 200 }
        $r = & $run { param($Job, $Execution, $StartedUtc) [pscustomobject]@{ LastSeenUtc = $null } }
        @($script:SilentLogs | Where-Object { $_ -match 'no sign of progress' }) | Should -BeNullOrEmpty
        # NEGATIVE: the probe fails -> nothing is said and the run goes on
        Reset-Clock; $script:SilentArm = New-FakeArm -Polls @{ identity = 200 }
        $r = & $run { param($Job, $Execution, $StartedUtc) throw 'the workspace could not be read' }
        (@($r.Steps | Where-Object Job -eq 'identity')[0]).State | Should -Be 'Success'
        @($script:SilentLogs | Where-Object { $_ -match 'no sign of progress' }) | Should -BeNullOrEmpty
    }
    It 'the progress probe reads the job''s console log lines and run-health records; silence is only reported for a job that was heard before' {
        $t = [datetime]::SpecifyKind([datetime]'2026-10-05T01:01:00', 'Utc')
        $q = Get-SIJobFlowProgressQuery -Execution 'caj-si-identity-abc12' -StartedUtc $t
        $q | Should -Match ([regex]::Escape("ContainerAppConsoleLogs | where TimeGenerated > datetime(2026-10-05T00:51:00Z)"))
        $q | Should -Match ([regex]::Escape("where N startswith 'caj-si-identity-abc12' | project TimeGenerated, K = 'log'"))
        $q | Should -Match 'ContainerAppConsoleLogs_CL .*ContainerGroupName_s'
        $q | Should -Match "SI_RunHealth_CL .*not\(Engine startswith 'flow'\)"
        $q | Should -Match "summarize Last = max\(TimeGenerated\), Console = countif\(K == 'log'\)$"
        Get-SIJobFlowProgressQuery -Execution "x' or 1==1" -StartedUtc $t | Should -BeNullOrEmpty -Because 'a name that is not an execution name is never put into a query'
        # a collection in parts: the workers' lines count for the step
        $script:Kql = ''
        $probe = New-SIJobFlowProgressProbe -PartsJobs @('caj-si-identity-producer') -Query { param($Kql) $script:Kql = $Kql; [pscustomobject]@{ Last = '2026-10-05T03:00:00Z'; Console = 42 } }
        $a = $probe.Probe('identity', 'caj-si-identity-producer-abc12', $t)
        $a.LastSeenUtc | Should -Be ([datetime]::SpecifyKind([datetime]'2026-10-05T03:00:00', 'Utc'))
        $script:Kql | Should -Match ([regex]::Escape("(N startswith 'caj-si-identity-producer-abc12' or N startswith 'caj-si-identity-worker')"))
        # NEGATIVE: no console log line of this job in the workspace (only its start record) -> cannot be told
        (New-SIJobFlowProgressProbe -Query { param($Kql) [pscustomobject]@{ Last = '2026-10-05T01:02:00Z'; Console = 0 } }).Probe('ptc', 'caj-si-ptc-abc12', $t).LastSeenUtc | Should -BeNullOrEmpty
        (New-SIJobFlowProgressProbe -Query { param($Kql) throw 'Forbidden' }).Probe('ptc', 'caj-si-ptc-abc12', $t).LastSeenUtc | Should -BeNullOrEmpty
        (New-SIJobFlowProgressProbe).Probe('ptc', 'caj-si-ptc-abc12', $t).LastSeenUtc | Should -BeNullOrEmpty -Because 'no workspace, no signal'
        # WIRING: the runner gives the pipeline the probe and writes the warning to run health as a warning, not an end
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $src | Should -Match ([regex]::Escape('$retry.Progress = New-SIJobFlowProgressProbe -WorkspaceResourceId ([string]$global:SI_WorkspaceResourceId) -PartsJobs @($producers)'))
        $src | Should -Match "elseif \(\`$Phase -eq 'Silent'\) \{ Send-SIRunHealthRow -RunContext \`$ctx -Phase Guard -ExitReason 'warning'"
    }
    It 'the installed jobs are listed from EVERY page (Azure lists 20 a page) -- a job on page 2 is in the default pipeline' {
        # internal 2026-10-20: 26 jobs, caj-si-verification on page 2; the runner read page 1 only -> no verification step,
        # every run refused at publish, the data health check never ran
        $script:ListPaths = New-Object System.Collections.Generic.List[string]
        $page1 = @('ptc', 'identity', 'azure', 'endpoint', 'publicip', 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed', 'asset-cmdb-sql',
                   'asset-vulnerabilities', 'asset-datasync', 'close-loop-mail', 'flow', 'updater', 'heartbeat', 'templates', 'asset-trend', 'asset-properties',
                   'identity-worker', 'identity-producer') | ForEach-Object { [pscustomobject]@{ name = "caj-si-$_" } }
        $arm = { param($Method, $Path, $Body) $script:ListPaths.Add($Path)
                 if ($Path -like 'https://*skiptoken*') { [pscustomobject]@{ value = @([pscustomobject]@{ name = 'caj-si-verification' }, [pscustomobject]@{ name = 'caj-si-raworker-detailed' }) } }
                 else { [pscustomobject]@{ value = $page1; nextLink = 'https://management.azure.com/subscriptions/s/resourceGroups/r/providers/Microsoft.App/jobs?api-version=2024-03-01&$skiptoken=abc' } } }
        $names = @((New-SIJobFlowArmSeams -SubscriptionId 's' -ResourceGroup 'r' -Arm $arm).List())
        $names.Count | Should -Be 22
        $names | Should -Contain 'caj-si-verification'
        $script:ListPaths.Count | Should -Be 2 -Because 'the nextLink is followed, once'
        $def = New-SIDefaultJobFlow -Installed $names
        @($def.Steps | ForEach-Object { [string]$_.Job }) | Should -Contain 'verification' -Because 'the required verification step is in the default pipeline'
        # a page without nextLink ends the list
        @((New-SIJobFlowArmSeams -SubscriptionId 's' -ResourceGroup 'r' -Arm { param($Method, $Path, $Body) [pscustomobject]@{ value = @([pscustomobject]@{ name = 'caj-si-ptc' }) } }).List()) | Should -Be @('caj-si-ptc')
    }
    It 'the job''s own run limit is read from the job (its replica timeout, in minutes); a step that collects in parts gets the producer''s limit plus the wait for its parts' {
        $script:LimitPaths = New-Object System.Collections.Generic.List[string]
        $arm = { param($Method, $Path, $Body) $script:LimitPaths.Add(('{0} {1}' -f $Method, $Path))
                 $sec = if ($Path -like '*-producer') { 7200 } elseif ($Path -like '*-worker') { 86400 } else { 32400 }
                 [pscustomobject]@{ properties = [pscustomobject]@{ configuration = [pscustomobject]@{ replicaTimeout = $sec } } } }
        $seams = New-SIJobFlowArmSeams -SubscriptionId 's' -ResourceGroup 'r' -Arm $arm
        $seams.Limit('asset-correlation') | Should -Be 540
        $script:LimitPaths[0] | Should -Be 'GET /subscriptions/s/resourceGroups/r/providers/Microsoft.App/jobs/caj-si-asset-correlation'
        (New-SIJobFlowArmSeams -SubscriptionId 's' -ResourceGroup 'r' -Arm { param($Method, $Path, $Body) [pscustomobject]@{ name = 'x' } }).Limit('ptc') | Should -Be 0 -Because 'a job that does not say'
        # in parts: the parts are waited for 180 minutes PLUS the worker's own run limit (24 h here), after the producer (2 h)
        $parts = Add-SIJobFlowCollectParts -Seams $seams -Store ([pscustomobject]@{}) -ProducerJobs @('caj-si-identity-producer')
        $parts.PartsWait('identity') | Should -Be 1620 -Because 'a part whose worker is still running is never called incomplete'
        $parts.Limit('identity') | Should -Be 1740
        $parts.Limit('asset-correlation') | Should -Be 540 -Because 'every other job is unchanged'
        # a wrapper over seams that cannot read a job's limit keeps the 180 minutes
        $plain = New-SIJobFlowSeams -Fields @{ Kind = 'plain' } -Methods @{ Start = { param($j) 'e' }; Poll = { param($j, $e) 'Running' }; List = { @() } }
        (Add-SIJobFlowCollectParts -Seams $plain -Store ([pscustomobject]@{}) -ProducerJobs @('caj-si-identity-producer')).PartsWait('identity') | Should -Be 180
    }
    It 'a status that cannot be read is retried, not taken as failure' {
        $arm = New-FakeArm
        $n = 0
        $seams = New-Seams $arm
        $flaky = { param($j, $e) $script:Flaky++; if ($script:Flaky -le 2) { throw 'ARM GET returned 503' }; 'Succeeded' }
        $script:Flaky = 0
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        $r = Invoke-SIJobFlow -Definition $d -Seams $seams -Poll $flaky -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map -PollSeconds 60
        $r.State | Should -Be 'Succeeded'
    }
}

Describe 'the runner: re-run from a step, and a crash mid-run' {
    BeforeEach { Reset-Clock }
    It 're-run from a step: the steps above it are not run' {
        $arm = New-FakeArm
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'azure', 'risk-analysis') -Map $script:Map
        $r = Invoke-Flow -Definition $d -Arm $arm -FromStep 'caj-si-azure'
        @($script:Arm.Starts) | Should -Be @('azure', 'risk-analysis')
        $r.Trigger | Should -Be 'rerun'
        @($r.Steps)[0].ErrorClass | Should -Be 'before-rerun'
        { Invoke-Flow -Definition $d -Arm $arm -FromStep 'templates' } | Should -Throw "*not a step of the flow*"
    }
    It 'a crash mid-run: the restart RESUMES -- the running step is followed, not started again; finished steps are kept' {
        $arm = New-FakeArm -Polls @{ identity = 3 }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'azure') -Map $script:Map
        # run until identity is Running, then "crash" (the save seam throws)
        $script:Crash = { param($s) $script:Saved = (ConvertTo-SIJobFlowRunJson -State $s); if (@($s.Steps | Where-Object { $_.Job -eq 'identity' -and $_.State -eq 'Running' }).Count) { throw 'container killed' } }
        { Invoke-Flow -Definition $d -Arm $arm -Save $script:Crash } | Should -Throw '*container killed*'
        $prev = ConvertFrom-SIJobFlowRunJson -Json $script:Saved
        (Get-StepState $prev 'identity') | Should -Be 'Running'
        $script:Clock = $script:Clock.AddMinutes(30)   # the heartbeat is now stale
        $r = Invoke-Flow -Definition $d -Arm $arm -Previous $prev
        $r.Outcome | Should -Be 'Resume'
        $r.FlowRunId | Should -Be $prev.FlowRunId
        @($script:Arm.Starts) | Should -Be @('ptc', 'identity', 'azure') -Because 'identity was started ONCE, before the crash'
        $r.State | Should -Be 'Succeeded'
    }
    It 'a crash between "starting" and the recorded execution: reported Interrupted, never started again' {
        $arm = New-FakeArm
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'asset-correlation', 'azure') -Map $script:Map
        $prev = New-SIJobFlowRunState -Definition $d -NowUtc $script:Clock
        $prev.Steps[0].State = 'Success'; $prev.Steps[1].State = 'Starting'; $prev.Steps[1].StartedUtc = $script:Clock
        $script:Clock = $script:Clock.AddMinutes(20)
        $r = Invoke-Flow -Definition $d -Arm $arm -Previous $prev
        (Get-StepState $r 'identity') | Should -Be 'Interrupted'
        @($script:Arm.Starts) | Should -Not -Contain 'identity'
        @($script:Arm.Starts) | Should -Not -Contain 'ptc'
        (Get-StepState $r 'azure') | Should -Be 'Success'
        (Get-StepState $r 'asset-correlation') | Should -Be 'Success' -Because 'another collection succeeded: the run goes on with the last good identity collection'
    }
    It 'a second runner while the first is alive (fresh heartbeat) does nothing' {
        $arm = New-FakeArm
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        $prev = New-SIJobFlowRunState -Definition $d -NowUtc $script:Clock
        $script:Clock = $script:Clock.AddMinutes(2)
        $r = Invoke-Flow -Definition $d -Arm $arm -Previous $prev
        $r.Outcome | Should -Be 'Busy'
        $script:Arm.Starts.Count | Should -Be 0
    }
    It 'today''s finished run is not run again by a second scheduled start; a forced run (Run flow now) is' {
        $arm = New-FakeArm
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        $first = Invoke-Flow -Definition $d -Arm $arm
        $again = Invoke-Flow -Definition $d -Arm $arm -Previous $first
        $again.Outcome | Should -Be 'Wait' -Because 'the 01:00 slot has run (SCHED-1.1: the next wake-up waits for the next slot)'
        $script:Arm.Starts.Count | Should -Be 1
        $forced = Invoke-Flow -Definition $d -Arm $arm -Previous $first -Force
        $forced.Outcome | Should -Be 'New'
        $script:Arm.Starts.Count | Should -Be 2
        $script:Clock = $script:Clock.AddDays(1)
        (Invoke-Flow -Definition $d -Arm $arm -Previous $forced).Outcome | Should -Be 'New' -Because 'the next day is a new run'
    }
    It 'refuses an invalid definition before anything starts' {
        $arm = New-FakeArm
        $d = ConvertFrom-SIJobFlowJson -Json '{"steps":[{"job":"ptc","onFailure":"retry"}]}'
        { Invoke-Flow -Definition $d -Arm $arm } | Should -Throw '*not valid*'
        $script:Arm.Starts.Count | Should -Be 0
    }
}

Describe 'the runner: a job that is already running is not started again (owner 2026-10-12)' {
    BeforeEach { Reset-Clock; $script:FollowLogs = New-Object System.Collections.Generic.List[string]; $script:FollowLog = { param($l, $m) $script:FollowLogs.Add(($l + ' ' + $m)) } }
    It 'which execution counts as running: Running / Processing, the one that started first; ended ones never' {
        $ex = @(
            [pscustomobject]@{ name = 'j-done'; properties = [pscustomobject]@{ status = 'Succeeded'; startTime = '2026-10-05T00:10:00Z' } },
            [pscustomobject]@{ name = 'j-late'; properties = [pscustomobject]@{ status = 'Running'; startTime = '2026-10-05T00:50:00Z' } },
            [pscustomobject]@{ name = 'j-first'; properties = [pscustomobject]@{ status = 'Processing'; startTime = '2026-10-05T00:40:00Z' } },
            [pscustomobject]@{ name = 'j-failed'; properties = [pscustomobject]@{ status = 'Failed'; startTime = '2026-10-05T00:45:00Z' } })
        $r = Select-SIJobFlowRunningExecution -Executions $ex
        $r.Execution | Should -Be 'j-first'
        $r.StartedUtc.ToUniversalTime().ToString('u') | Should -Be '2026-10-05 00:40:00Z'
        Select-SIJobFlowRunningExecution -Executions @($ex[0], $ex[3]) | Should -BeNullOrEmpty
        Select-SIJobFlowRunningExecution -Executions @() | Should -BeNullOrEmpty
        Select-SIJobFlowRunningExecution -Executions $null | Should -BeNullOrEmpty
        (Select-SIJobFlowRunningExecution -Executions @([pscustomobject]@{ name = 'j-x'; properties = [pscustomobject]@{ status = 'Running' } })).StartedUtc | Should -BeNullOrEmpty -Because 'Azure does not always say when it started'
    }
    It 'a step whose job is already running starts NO second execution: the pipeline follows the running one, and its result is the step''s' {
        $arm = New-FakeArm -Running @{ 'asset-correlation' = 'asset-correlation-hand1' } -Polls @{ 'asset-correlation' = 3 }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'asset-correlation', 'risk-analysis') -Map $script:Map
        $r = Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Save { param($s) } -Now $script:NowSb -Sleep $script:SleepSb -Log $script:FollowLog -Map $script:Map -PollSeconds 60
        $r.State | Should -Be 'Succeeded'
        @($script:Arm.Starts) | Should -Be @('ptc', 'identity', 'risk-analysis') -Because 'the CI build that was already running is not started a second time'
        $st = @($r.Steps | Where-Object { $_.Job -eq 'asset-correlation' })[0]
        ($st.State, $st.Execution, $st.Attempts) | Should -Be @('Success', 'asset-correlation-hand1', 1)
        @($script:FollowLogs | Where-Object { $_ -match '^INFO step \d+ asset-correlation: already running \(asset-correlation-hand1, started 2026-10-05 00:40:00Z\) -- the pipeline follows it instead of starting another$' }).Count | Should -Be 1
        @($script:FollowLogs | Where-Object { $_ -match 'asset-correlation: started \(' }).Count | Should -Be 0
        $r.Note | Should -Match 'asset-correlation was already running \(asset-correlation-hand1, started 2026-10-05 00:40:00Z\) -- the pipeline followed that run instead of starting another\.'
        # the step after it started only when the followed run had ended
        $script:Arm.Calls.IndexOf('POST /subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-risk-analysis/start') | Should -BeGreaterThan $script:Arm.Calls.LastIndexOf('GET /subscriptions/sub/resourceGroups/rg/providers/Microsoft.App/jobs/caj-si-asset-correlation/executions/asset-correlation-hand1')
        # nothing went wrong: no guard event for a step that was simply followed
        . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-Guard.ps1'))
        @(Get-SIGuardCallsForFlow -Result $r).Count | Should -Be 0
    }
    It 'the followed execution fails: the step fails with it, and what needs it does not run' {
        $arm = New-FakeArm -Running @{ 'asset-correlation' = 'asset-correlation-hand2' } -Outcome @{ 'asset-correlation' = 'Failed' }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'asset-correlation', 'risk-analysis') -Map $script:Map
        $r = Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Save { param($s) } -Now $script:NowSb -Sleep $script:SleepSb -Log $script:FollowLog -Map $script:Map -PollSeconds 60
        (Get-StepState $r 'asset-correlation') | Should -Be 'Failed'
        (Get-StepState $r 'risk-analysis') | Should -Be 'Skipped'
        @($script:Arm.Starts) | Should -Not -Contain 'asset-correlation'
        @($script:Arm.Starts) | Should -Not -Contain 'risk-analysis'
    }
    It 'NEGATIVE: nothing is running -> the step is started as always; a check that cannot be made is said and the step is started' {
        $arm = New-FakeArm
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map
        $r = Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Save { param($s) } -Now $script:NowSb -Sleep $script:SleepSb -Log $script:FollowLog -Map $script:Map -PollSeconds 60
        @($script:Arm.Starts) | Should -Be @('ptc', 'identity')
        @($script:FollowLogs | Where-Object { $_ -match 'already running|could not be checked' }).Count | Should -Be 0
        [string]$r.Note | Should -Not -Match 'already running'
        Reset-Clock; $script:FollowLogs.Clear()
        $arm = New-FakeArm -ListFails @('identity')
        $r = Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Save { param($s) } -Now $script:NowSb -Sleep $script:SleepSb -Log $script:FollowLog -Map $script:Map -PollSeconds 60 -Force
        $r.State | Should -Be 'Succeeded'
        @($script:Arm.Starts) | Should -Be @('ptc', 'identity')
        @($script:FollowLogs | Where-Object { $_ -match '^INFO step \d+ identity: whether its job is already running could not be checked \(.*503.*\) -- it is started$' }).Count | Should -Be 1
    }
    It 'a collection in parts follows its PRODUCER the same way; the workers are never asked about' {
        $inner = New-SIJobFlowSeams -Fields @{ Asked = (New-Object System.Collections.Generic.List[string]); Started = (New-Object System.Collections.Generic.List[string]) } -Methods @{
            Running = { param($Job) $this.Asked.Add([string]$Job); if ($Job -eq 'endpoint-producer') { [pscustomobject]@{ Execution = 'endpoint-producer-hand1'; StartedUtc = $null } } else { $null } }
            Start = { param($Job) $this.Started.Add([string]$Job); 'x1' }
            Poll = { param($Job, $Execution) 'Running' }
            List = { @('caj-si-endpoint-producer', 'caj-si-endpoint-worker', 'caj-si-identity') }
        }
        $parts = Add-SIJobFlowCollectParts -Seams $inner -Store ([pscustomobject]@{}) -ProducerJobs @('caj-si-endpoint-producer')
        $parts.Running('endpoint').Execution | Should -Be 'endpoint-producer-hand1'
        $parts.Running('identity') | Should -BeNullOrEmpty
        @($inner.Asked) | Should -Be @('endpoint-producer', 'identity') -Because 'never the worker job: several workers at once is normal'
        $inner.Started.Count | Should -Be 0
        # seams that cannot list executions (the VM flow): nothing is checked
        $plain = New-SIJobFlowSeams -Fields @{} -Methods @{ Start = { param($Job) 'x1' }; Poll = { param($Job, $Execution) 'Succeeded' }; List = { @() } }
        (Add-SIJobFlowCollectParts -Seams $plain -Store ([pscustomobject]@{}) -ProducerJobs @()).Running('identity') | Should -BeNullOrEmpty
        (New-SIJobFlowVmSeams -Root $script:SIRoot -Flavour 'community-vm').PSObject.Methods['Running'] | Should -BeNullOrEmpty
    }
    It 'a FORCED start while a pipeline run is going (fresh heartbeat) starts nothing and says so' {
        $arm = New-FakeArm
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map
        $prev = New-SIJobFlowRunState -Definition $d -NowUtc $script:Clock
        $script:Clock = $script:Clock.AddMinutes(2)
        $r = Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Save { param($s) } -Now $script:NowSb -Sleep $script:SleepSb -Log $script:FollowLog -Map $script:Map -Previous $prev -Force
        $r.Outcome | Should -Be 'Busy'
        $r.FlowRunId | Should -Be $prev.FlowRunId -Because 'no second run record'
        $script:Arm.Starts.Count | Should -Be 0
        @($script:FollowLogs | Where-Object { $_ -match '^WARN skipped: the previous flow run .* is still running -- nothing starts twice$' }).Count | Should -Be 1
    }
}

Describe 'the run-record stores' {
    BeforeEach { Reset-Clock }
    It 'the file store keeps the record across a restart (and the runner reads it from the store)' {
        $path = Join-Path ([IO.Path]::GetTempPath()) ('siflow-{0}\flow-run.json' -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
        try {
            $store = New-SIJobFlowFileStore -Path $path
            $store.Load() | Should -BeNullOrEmpty
            $arm = New-FakeArm
            $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map
            $r = Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Store $store -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map
            $back = $store.Load()
            $back.FlowRunId | Should -Be $r.FlowRunId
            @($back.Steps.State) | Should -Be @('Success', 'Success')
            # a second start the same day reads the store and does nothing
            (Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Store $store -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map).Outcome | Should -Be 'Wait'
        } finally { Remove-Item -LiteralPath (Split-Path -Parent $path) -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'the SQL store writes the run row on every save and a step row only when it changed' {
        $script:Sql = New-Object System.Collections.Generic.List[object]
        $inv = { param($sql, $p, $mode) $script:Sql.Add([pscustomobject]@{ Sql = $sql; P = $p }); @() }
        $store = New-SIJobFlowSqlStore -Invoke $inv
        $arm = New-FakeArm -Polls @{ ptc = 3 }
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map
        $null = Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Store $store -Previous $null -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map
        $runs = @($script:Sql | Where-Object { $_.Sql -match 'MERGE cfg.FlowRun ' })
        $steps = @($script:Sql | Where-Object { $_.Sql -match 'MERGE cfg.FlowStepRun' })
        $runs.Count | Should -BeGreaterThan $steps.Count -Because 'the heartbeat does not rewrite unchanged steps'
        @($steps | ForEach-Object { '{0}:{1}' -f $_.P.Job, $_.P.State }) | Should -Contain 'ptc:Running'
        @($steps | ForEach-Object { '{0}:{1}' -f $_.P.Job, $_.P.State }) | Should -Contain 'identity:Success'
        @($runs)[-1].P.State | Should -Be 'Succeeded'
    }
    It 'the SQL store reads a stored run of many steps the way the real Pro reader returns it (one array of hashtables)' {
        # found live 2026-10-05: New-SIProSettingsStore returns a result set as ONE array (, $rows); the loader cast
        # [int]$_.StepOrder on the whole array and every flow wake-up failed after a run with 14 steps was stored
        $run = @{ FlowRunId = 'r1'; FlowId = 'daily'; Day = '2026-10-05'; Trg = 'schedule'; FromStep = ''; State = 'Failed'
                  StartedUtc = [datetime]'2026-10-05T10:40:00Z'; EndedUtc = [datetime]'2026-10-05T11:35:00Z'; HeartbeatUtc = [datetime]'2026-10-05T11:35:00Z'
                  StopReason = $null; SlotUtc = $null; LastSlotUtc = $null; Note = '' }
        $stepRows = @(1..14 | ForEach-Object { @{ FlowRunId = 'r1'; StepOrder = $_; GroupNo = $_; Job = ('job{0}' -f $_); State = 'Success'; Execution = ('job{0}-x' -f $_)
                                                    StartedUtc = [datetime]'2026-10-05T10:40:00Z'; EndedUtc = [datetime]'2026-10-05T10:50:00Z'; ErrorClass = $null; Error = $null
                                                    Attempts = $(if ($_ -eq 3) { 2 } else { 1 }); RetryReason = $(if ($_ -eq 3) { 'did not start' } else { $null }) } })
        $inv = { param($sql, $p, $mode)
            if ($sql -match 'FROM cfg\.FlowRun ') { , @($run) } elseif ($sql -match 'FROM cfg\.FlowStepRun') { , $stepRows } else { , @() } }.GetNewClosure()
        $back = (New-SIJobFlowSqlStore -Invoke $inv).Load()
        $back.FlowRunId | Should -Be 'r1'
        @($back.Steps).Count | Should -Be 14
        @($back.Steps)[0].Order | Should -Be 1
        @($back.Steps)[13].Job | Should -Be 'job14'
        @($back.Steps)[2].Attempts | Should -Be 2 -Because 'the columns are seen as properties, not lost in a hashtable'
        @($back.Steps)[2].RetryReason | Should -Be 'did not start'
        @($back.Steps)[0].Attempts | Should -Be 1
    }
    It 'the SQL store reads nothing as no previous run (the real reader returns an empty array)' {
        $inv = { param($sql, $p, $mode) , @() }
        (New-SIJobFlowSqlStore -Invoke $inv).Load() | Should -BeNullOrEmpty
        (New-SIJobFlowSqlStore -Invoke $inv).ReadDefinition() | Should -BeNullOrEmpty
    }
}

Describe 'the VM adapter' {
    It 'maps each step to its launcher (Risk Analysis -Summary / -Detailed, the updater -Apply), and a Pro job to none' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('sivm-{0}' -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
        try {
            foreach ($f in 'privilege-tier-classifier', 'risk-analysis', 'endpoint') { New-Item -ItemType Directory -Path (Join-Path $root "launcher\$f") -Force | Out-Null; Set-Content (Join-Path $root "launcher\$f\launcher.community-vm.ps1") '#' }
            New-Item -ItemType Directory -Path (Join-Path $root 'launcher\asset-correlation') -Force | Out-Null; Set-Content (Join-Path $root 'launcher\asset-correlation\launcher.internal-vm.ps1') '#'
            Set-Content (Join-Path $root 'Update-SecurityInsight.ps1') '#'
            (Get-SIJobFlowVmCommand -Job 'ptc' -Root $root).File | Should -BeLike '*privilege-tier-classifier*launcher.community-vm.ps1'
            (Get-SIJobFlowVmCommand -Job 'risk-analysis-detailed' -Root $root).Arguments | Should -Be @('-Detailed')
            (Get-SIJobFlowVmCommand -Job 'risk-analysis' -Root $root).Arguments | Should -Be @('-Summary')
            (Get-SIJobFlowVmCommand -Job 'updater' -Root $root).Arguments | Should -Be @('-Apply')
            (Get-SIJobFlowVmCommand -Job 'asset-correlation' -Root $root).File | Should -BeLike '*launcher.internal-vm.ps1'
            Get-SIJobFlowVmCommand -Job 'asset-datasync' -Root $root | Should -BeNullOrEmpty
            @(Get-SIJobFlowVmInstalled -Root $root -Map $script:Map) | Should -Be @('ptc', 'endpoint', 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed')
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'runs real processes in order and reads their exit codes' {
        $root = Join-Path ([IO.Path]::GetTempPath()) ('sivm-{0}' -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
        try {
            New-Item -ItemType Directory -Path (Join-Path $root 'launcher\privilege-tier-classifier') -Force | Out-Null
            New-Item -ItemType Directory -Path (Join-Path $root 'launcher\endpoint') -Force | Out-Null
            Set-Content (Join-Path $root 'launcher\privilege-tier-classifier\launcher.community-vm.ps1') 'exit 0'
            Set-Content (Join-Path $root 'launcher\endpoint\launcher.community-vm.ps1') 'exit 3'
            $exe = (Get-Process -Id $PID).Path
            $d = New-SIDefaultJobFlow -Installed @('ptc', 'endpoint') -Map $script:Map
            $r = Invoke-SIJobFlow -Definition $d -Seams (New-SIJobFlowVmSeams -Root $root -Exe $exe) -Log $script:Quiet -Map $script:Map -PollSeconds 1 -Previous $null -Force -Trigger manual
            @($r.Steps.State) | Should -Be @('Success', 'Failed')
            @($r.Steps)[0].Execution | Should -Match '^\d+@'
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'SCHED-1.1: the cadence starts when the previous run FINISHES' {
    BeforeAll {
        $script:T = [datetime]::SpecifyKind([datetime]'2026-10-05T10:00:00', 'Utc')
        function script:Iv([int]$Minutes) { $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map; $d.Cadence = 'interval'; $d.IntervalMinutes = $Minutes; $d }
        function script:Done([datetime]$Started, [datetime]$Ended) { [pscustomobject]@{ FlowRunId = 'r1'; State = 'Succeeded'; StartedUtc = $Started; EndedUtc = $Ended; HeartbeatUtc = $Ended; LastSlotUtc = $null; Steps = @() } }
    }
    It 'the sample: an 8-minute run on a 5-minute cadence, started T, finished T+8 -> next due T+13 (not T+5, not T+8)' {
        $prev = Done $script:T $script:T.AddMinutes(8)
        $running = [pscustomobject]@{ FlowRunId = 'r1'; State = 'Running'; StartedUtc = $script:T; EndedUtc = $null; HeartbeatUtc = $script:T.AddMinutes(5); Steps = @() }
        (Get-SIJobFlowDue -Definition (Iv 5) -Previous $running -NowUtc $script:T.AddMinutes(5)).Action | Should -Be 'Busy' -Because 'T+5: still running'
        $d8 = Get-SIJobFlowDue -Definition (Iv 5) -Previous $prev -NowUtc $script:T.AddMinutes(8)
        $d8.Action | Should -Be 'Wait'; $d8.NextUtc | Should -Be $script:T.AddMinutes(13)
        (Get-SIJobFlowDue -Definition (Iv 5) -Previous $prev -NowUtc $script:T.AddMinutes(12)).Action | Should -Be 'Wait'
        (Get-SIJobFlowDue -Definition (Iv 5) -Previous $prev -NowUtc $script:T.AddMinutes(13)).Action | Should -Be 'Start'
    }
    It 'a cadence change after a long run re-derives from the finish (5 -> 10 min after an 8-min run = T+18)' {
        $prev = Done $script:T $script:T.AddMinutes(8)
        (Get-SIJobFlowDue -Definition (Iv 10) -Previous $prev -NowUtc $script:T.AddMinutes(13)).Action | Should -Be 'Wait'
        (Get-SIJobFlowDue -Definition (Iv 10) -Previous $prev -NowUtc $script:T.AddMinutes(13)).NextUtc | Should -Be $script:T.AddMinutes(18)
        (Get-SIJobFlowDue -Definition (Iv 10) -Previous $prev -NowUtc $script:T.AddMinutes(18)).Action | Should -Be 'Start'
    }
    It 'a FAILED run counts as finished: the next attempt waits one interval (no tight retry loop)' {
        $prev = Done $script:T $script:T.AddMinutes(2); $prev.State = 'Failed'
        (Get-SIJobFlowDue -Definition (Iv 60) -Previous $prev -NowUtc $script:T.AddMinutes(30)).Action | Should -Be 'Wait'
        (Get-SIJobFlowDue -Definition (Iv 60) -Previous $prev -NowUtc $script:T.AddMinutes(62)).Action | Should -Be 'Start'
    }
    It 'the runner stamps the finish (EndedUtc) on the run it ran, and the next wake-up derives from it' {
        Reset-Clock
        $arm = New-FakeArm -Polls @{ ptc = 8 }
        $d = Iv 5
        $r1 = Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Previous $null -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map -PollSeconds 60
        $r1.EndedUtc | Should -Be $script:T0.AddMinutes(8)
        $r1.Trigger | Should -Be 'interval'
        $script:Clock = $script:T0.AddMinutes(10)
        (Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Previous $r1 -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map).Outcome | Should -Be 'Wait'
        $script:Clock = $script:T0.AddMinutes(13)
        (Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Previous $r1 -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map -PollSeconds 60).Outcome | Should -Be 'New'
    }
    It 'a time of day keeps its clock time; a start blocked by a run still running runs ONCE when that run finishes (recorded)' {
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map     # daily 01:00 UTC
        $slot1 = [datetime]::SpecifyKind([datetime]'2026-10-05T01:00:00', 'Utc'); $slot2 = $slot1.AddDays(1)
        # yesterday's run started 01:00 (slot1) and is still running at 01:00 the next day
        $long = [pscustomobject]@{ FlowRunId = 'long'; State = 'Running'; StartedUtc = $slot1; EndedUtc = $null; HeartbeatUtc = $slot2; SlotUtc = $slot1; LastSlotUtc = $slot1; Steps = @() }
        (Get-SIJobFlowDue -Definition $d -Previous $long -NowUtc $slot2).Action | Should -Be 'Busy'
        (Get-SIJobFlowDue -Definition $d -Previous $long -NowUtc $slot2).Reason | Should -Match 'skipped: the previous flow run \(long\) is still running'
        # it finishes at 03:20 -> the blocked 01:00 start runs once, as a catch-up, saying what blocked it
        $long.State = 'Succeeded'; $long.EndedUtc = $slot2.AddMinutes(140)
        $c = Get-SIJobFlowDue -Definition $d -Previous $long -NowUtc $slot2.AddMinutes(145)
        $c.Action | Should -Be 'Start'; $c.Trigger | Should -Be 'catch-up'; $c.SlotUtc | Should -Be $slot2
        $c.Note | Should -Match 'blocked: flow run long was still running'
        # and once that catch-up has run, the slot is not run again (not queued twice)
        $after = [pscustomobject]@{ FlowRunId = 'cu'; State = 'Succeeded'; StartedUtc = $slot2.AddMinutes(145); EndedUtc = $slot2.AddMinutes(150); HeartbeatUtc = $slot2.AddMinutes(150); SlotUtc = $slot2; LastSlotUtc = $slot2; Steps = @() }
        $w = Get-SIJobFlowDue -Definition $d -Previous $after -NowUtc $slot2.AddHours(5)
        $w.Action | Should -Be 'Wait'; $w.NextUtc | Should -Be $slot2.AddDays(1)
    }
    It 'START WHEN THE LAST ONE ENDS: a scheduled time during a run starts no second run; however many scheduled times passed, exactly ONE start is owed, at the first wake-up after the run ended' {
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map     # daily 01:00 UTC
        $s0 = [datetime]::SpecifyKind([datetime]'2026-10-05T01:00:00', 'Utc')
        $long = [pscustomobject]@{ FlowRunId = 'long'; State = 'Running'; StartedUtc = $s0; EndedUtc = $null; HeartbeatUtc = $s0; SlotUtc = $s0; LastSlotUtc = $s0; Steps = @() }
        # the run goes on for 60 hours: the scheduled times at +24 h and +48 h pass, and every wake-up finds it busy
        foreach ($h in 24, 30, 48, 55) {
            $long.HeartbeatUtc = $s0.AddHours($h)
            (Get-SIJobFlowDue -Definition $d -Previous $long -NowUtc $s0.AddHours($h)).Action | Should -Be 'Busy' -Because "never two runs at once (+$h h)"
        }
        # it ends: the first wake-up after it starts ONE run -- for the latest scheduled time only, not one per missed time
        $long.State = 'Succeeded'; $long.EndedUtc = $s0.AddHours(60)
        $c = Get-SIJobFlowDue -Definition $d -Previous $long -NowUtc $s0.AddHours(60).AddMinutes(4)
        $c.Action | Should -Be 'Start'; $c.Trigger | Should -Be 'catch-up'; $c.SlotUtc | Should -Be $s0.AddDays(2)
        # that run is going: nothing else starts; it ends after 2 hours and NOTHING more is owed -- the next start is the next scheduled time
        $cu = [pscustomobject]@{ FlowRunId = 'cu'; State = 'Running'; StartedUtc = $s0.AddHours(60).AddMinutes(4); EndedUtc = $null; HeartbeatUtc = $s0.AddHours(61); SlotUtc = $s0.AddDays(2); LastSlotUtc = $s0.AddDays(2); Steps = @() }
        (Get-SIJobFlowDue -Definition $d -Previous $cu -NowUtc $s0.AddHours(61)).Action | Should -Be 'Busy'
        $cu.State = 'Succeeded'; $cu.EndedUtc = $s0.AddHours(62)
        $w = Get-SIJobFlowDue -Definition $d -Previous $cu -NowUtc $s0.AddHours(62).AddMinutes(5)
        $w.Action | Should -Be 'Wait' -Because 'one owed start, not two'
        $w.NextUtc | Should -Be $s0.AddDays(3)
        # a run that again takes longer than a day: its end starts the next one at once -- the pipeline runs back to back
        $cu.EndedUtc = $s0.AddHours(92)
        $n = Get-SIJobFlowDue -Definition $d -Previous $cu -NowUtc $s0.AddHours(92).AddMinutes(3)
        $n.Action | Should -Be 'Start'; $n.Trigger | Should -Be 'catch-up'; $n.SlotUtc | Should -Be $s0.AddDays(3)
    }
    It 'NEGATIVE: an install whose run finishes before the next scheduled time is unchanged -- it waits for the schedule and starts on time' {
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        $s0 = [datetime]::SpecifyKind([datetime]'2026-10-05T01:00:00', 'Utc')
        $short = [pscustomobject]@{ FlowRunId = 'short'; State = 'Succeeded'; StartedUtc = $s0; EndedUtc = $s0.AddHours(3); HeartbeatUtc = $s0.AddHours(3); SlotUtc = $s0; LastSlotUtc = $s0; Steps = @() }
        $w = Get-SIJobFlowDue -Definition $d -Previous $short -NowUtc $s0.AddHours(5)
        $w.Action | Should -Be 'Wait'; $w.NextUtc | Should -Be $s0.AddDays(1)
        $on = Get-SIJobFlowDue -Definition $d -Previous $short -NowUtc $s0.AddDays(1).AddMinutes(2)
        $on.Action | Should -Be 'Start'; $on.Trigger | Should -Be 'schedule'; $on.Note | Should -Be ''
        Get-SIPipelineMeasuredCadence -Definition $d -Previous $short -NowUtc $s0.AddDays(1).AddMinutes(2) -SlotUtc $s0.AddDays(1) | Should -BeNullOrEmpty -Because 'the run fitted inside the day: nothing to say'
    }
    It 'THE MEASURED CADENCE: when a full run takes longer than the schedule''s interval, the next run''s note says in plain words how often the data is refreshed' {
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        # yesterday's run started on time (01:00) and took 31 hours: it ended 7 hours after today's scheduled time
        $now = $script:T0.AddHours(7).AddMinutes(5)
        $prev = [pscustomobject]@{ FlowRunId = 'long'; State = 'Succeeded'; StartedUtc = $script:T0.AddDays(-1); EndedUtc = $script:T0.AddHours(7); HeartbeatUtc = $script:T0.AddHours(7)
                                   SlotUtc = $script:T0.AddDays(-1); LastSlotUtc = $script:T0.AddDays(-1); Steps = @() }
        $m = Get-SIPipelineMeasuredCadence -Definition $d -Previous $prev -NowUtc $now -SlotUtc $script:T0
        $m.Text | Should -Be 'At this size a full run takes about 31 hours, so data is refreshed about every 31 hours.'
        $m.IntervalHours | Should -Be 24; $m.RunHours | Should -Be 31; $m.StartToStartHours | Should -Be 31.1
        # NEGATIVE: a run of one step or stage, and an "every N hours after the finish" schedule, say nothing
        $step = $prev.PSObject.Copy(); $step | Add-Member -NotePropertyName Scope -NotePropertyValue 'step'
        Get-SIPipelineMeasuredCadence -Definition $d -Previous $step -NowUtc $now -SlotUtc $script:T0 | Should -BeNullOrEmpty
        $iv = $d.PSObject.Copy(); $iv.Cadence = 'interval'; $iv.IntervalMinutes = 60
        Get-SIPipelineMeasuredCadence -Definition $iv -Previous $prev -NowUtc $now | Should -BeNullOrEmpty
        # the runner: the owed start is made, and its note (shown on the pipeline page, kept in the run's record) carries the sentence
        $script:Clock = $now
        $run = Invoke-SIJobFlow -Definition $d -Seams (New-Seams (New-FakeArm)) -Previous $prev -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map
        $run.Trigger | Should -Be 'catch-up'
        $run.Note | Should -Match '^At this size a full run takes about 31 hours, so data is refreshed about every 31 hours\. This run started late because the previous run \(long\) was still going at its scheduled time'
        $run.Note.Length | Should -BeLessOrEqual 400
        # and the runner writes it to the run's own record
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1')) | Should -Match ([regex]::Escape('$pipeCadence = if ([string]$pipeResult.Note -match'))
    }
    It 'the runner records the catch-up with its note, and a manual run never makes the slot run twice' {
        Reset-Clock
        $arm = New-FakeArm
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        $prev = [pscustomobject]@{ FlowRunId = 'long'; State = 'Succeeded'; StartedUtc = $script:T0.AddDays(-1); EndedUtc = $script:T0.AddMinutes(30); HeartbeatUtc = $script:T0.AddMinutes(30); SlotUtc = $script:T0.AddDays(-1); LastSlotUtc = $script:T0.AddDays(-1); Steps = @() }
        $script:Clock = $script:T0.AddMinutes(35)
        $cu = Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Previous $prev -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map
        $cu.Trigger | Should -Be 'catch-up'; $cu.Note | Should -Match 'started late because the previous run \(long\) was still going'; $cu.LastSlotUtc | Should -Be $script:T0
        $m = Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Previous $cu -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map -Force -Trigger manual
        $m.Trigger | Should -Be 'manual'; $m.LastSlotUtc | Should -Be $script:T0 -Because 'the slot is carried forward'
        (Invoke-SIJobFlow -Definition $d -Seams (New-Seams $arm) -Previous $m -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map).Outcome | Should -Be 'Wait'
        $script:Arm.Starts.Count | Should -Be 2
    }
    It 'QUIET WHEN RUNS ARE JUST LONG: back-to-back long runs raise no guard event and the run''s note says why' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-Guard.ps1')
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map     # daily 01:00 UTC
        $catchUp = { param($r) @(@(Get-SIGuardCallsForFlow -Result $r) | Where-Object { $_.GuardId -eq 'flow.run.catch-up' }) }
        # the run before started on time yesterday and took 31 hours: it was still going at today's scheduled time
        $prev = [pscustomobject]@{ FlowRunId = 'long'; State = 'Succeeded'; StartedUtc = $script:T0.AddDays(-1); EndedUtc = $script:T0.AddHours(7); HeartbeatUtc = $script:T0.AddHours(7)
                                   SlotUtc = $script:T0.AddDays(-1); LastSlotUtc = $script:T0.AddDays(-1); Steps = @() }
        $l = Get-SIJobFlowLateStart -Trigger 'catch-up' -SlotUtc $script:T0 -Previous $prev -NowUtc $script:T0.AddHours(7).AddMinutes(4)
        $l.Kind | Should -Be 'previous-run'; $l.LateMinutes | Should -Be 424
        $l.Note | Should -Be 'This run started late because the previous run (long) was still going at its scheduled time (2026-10-05 01:00:00Z); it started as soon as that run ended (2026-10-05 08:00:00Z).'
        # the runner: the owed start is made at the first wake-up after that run ended -- its note says why, and NO guard event
        $script:Clock = $script:T0.AddHours(7).AddMinutes(4)
        $run = Invoke-SIJobFlow -Definition $d -Seams (New-Seams (New-FakeArm)) -Previous $prev -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map
        $run.Trigger | Should -Be 'catch-up'; $run.State | Should -Be 'Succeeded'
        $run.Note | Should -Match 'This run started late because the previous run \(long\) was still going at its scheduled time'
        @(& $catchUp $run).Count | Should -Be 0 -Because 'a start owed only to a long previous run is normal operation'
        # ... and the next one, back to back again (this run takes 25 hours): still no guard event
        $prev2 = [pscustomobject]@{ FlowRunId = 'long2'; State = 'Succeeded'; StartedUtc = $run.StartedUtc; EndedUtc = $script:T0.AddDays(1).AddHours(9); HeartbeatUtc = $script:T0.AddDays(1).AddHours(9)
                                    SlotUtc = $script:T0; LastSlotUtc = $script:T0; Steps = @() }
        $script:Clock = $script:T0.AddDays(1).AddHours(9).AddMinutes(3)
        $run2 = Invoke-SIJobFlow -Definition $d -Seams (New-Seams (New-FakeArm)) -Previous $prev2 -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map
        $run2.Trigger | Should -Be 'catch-up'; $run2.Note | Should -Match 'started late because the previous run \(long2\) was still going'
        @(& $catchUp $run2).Count | Should -Be 0
        # a start that waited in the QUEUE while that run held the install (the pipeline's own path) is the same: quiet, and said
        $script:Clock = $script:T0.AddHours(7).AddMinutes(1)
        $q = Invoke-SIJobFlow -Definition $d -Seams (New-Seams (New-FakeArm)) -Previous $prev -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map `
            -Force -Trigger 'catch-up' -SlotUtc $script:T0 -Note 'the 2026-10-05 01:00:00Z start waited in the queue: run long was still running'
        $q.Trigger | Should -Be 'catch-up'; $q.Note | Should -Match 'started late because the previous run \(long\) was still going'
        @(& $catchUp $q).Count | Should -Be 0
        # the record keeps it: a run that is read back (a resumed run, the web app) is still quiet
        @(& $catchUp (ConvertFrom-SIJobFlowRunJson -Json (ConvertTo-SIJobFlowRunJson -State $run))).Count | Should -Be 0
    }
    It 'A START MISSED FOR ANY OTHER REASON IS STILL REPORTED: no run was going, or the run did not start when the previous one ended' {
        . (Join-Path $script:SIRoot 'engine\_shared\SI-Guard.ps1')
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        $catchUp = { param($r) @(@(Get-SIGuardCallsForFlow -Result $r) | Where-Object { $_.GuardId -eq 'flow.run.catch-up' }) }
        # yesterday's run took 3 hours: nothing was going at today's scheduled time, and the pipeline was not woken for 5 hours
        $short = [pscustomobject]@{ FlowRunId = 'short'; State = 'Succeeded'; StartedUtc = $script:T0.AddDays(-1); EndedUtc = $script:T0.AddDays(-1).AddHours(3); HeartbeatUtc = $script:T0.AddDays(-1).AddHours(3)
                                    SlotUtc = $script:T0.AddDays(-1); LastSlotUtc = $script:T0.AddDays(-1); Steps = @() }
        $script:Clock = $script:T0.AddHours(5)
        $late = Invoke-SIJobFlow -Definition $d -Seams (New-Seams (New-FakeArm)) -Previous $short -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map
        $late.Note | Should -Be 'This scheduled start was missed: its time was 2026-10-05 01:00:00Z and no run was going then, but it started 300 minutes late.'
        $c = @(& $catchUp $late)
        $c.Count | Should -Be 1; $c[0].Outcome | Should -Be 'held'; $c[0].Detail | Should -Match 'scheduled start was missed'
        # the previous run WAS going at the scheduled time, but this run started 3 hours after it ended: not "just long"
        $long = [pscustomobject]@{ FlowRunId = 'long'; State = 'Succeeded'; StartedUtc = $script:T0.AddDays(-1); EndedUtc = $script:T0.AddHours(7); HeartbeatUtc = $script:T0.AddHours(7)
                                   SlotUtc = $script:T0.AddDays(-1); LastSlotUtc = $script:T0.AddDays(-1); Steps = @() }
        $script:Clock = $script:T0.AddHours(10)
        $gap = Invoke-SIJobFlow -Definition $d -Seams (New-Seams (New-FakeArm)) -Previous $long -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map
        $gap.Trigger | Should -Be 'catch-up'; $gap.Note | Should -Match 'This scheduled start was missed: the previous run \(long\) was still going at its time .* but this run started 180 minutes after that\.'
        @(& $catchUp $gap).Count | Should -Be 1
        # NEGATIVE: a run that starts at its time says nothing and raises nothing; a run somebody asked for is never "late"
        $script:Clock = $script:T0.AddMinutes(2)
        $on = Invoke-SIJobFlow -Definition $d -Seams (New-Seams (New-FakeArm)) -Previous $short -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map
        $on.Trigger | Should -Be 'schedule'; $on.Note | Should -Be ''; @(& $catchUp $on).Count | Should -Be 0
        (Get-SIJobFlowLateStart -Trigger 'manual' -SlotUtc $script:T0 -Previous $short -NowUtc $script:T0.AddHours(5)).Kind | Should -Be 'on-time'
        (Get-SIJobFlowLateStart -Trigger 'schedule' -SlotUtc $null -Previous $short -NowUtc $script:T0.AddHours(5)).Kind | Should -Be 'on-time'
        (Get-SIJobFlowLateStart -Trigger 'schedule' -SlotUtc $script:T0 -Previous $null -NowUtc $script:T0.AddMinutes(40)).Kind | Should -Be 'missed' -Because 'a start that waited 40 minutes with no run going (an update held it) is missed'
    }
    It 'a new install does not start hours late: the first slot starts only within 15 minutes of its time' {
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        $slot = [datetime]::SpecifyKind([datetime]'2026-10-05T01:00:00', 'Utc')
        (Get-SIJobFlowDue -Definition $d -Previous $null -NowUtc $slot.AddMinutes(5)).Action | Should -Be 'Start'
        $w = Get-SIJobFlowDue -Definition $d -Previous $null -NowUtc $slot.AddHours(13)
        $w.Action | Should -Be 'Wait'; $w.NextUtc | Should -Be $slot.AddDays(1)
    }
    It 'weekdays / weekly slots' {
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map; $d.Cadence = 'weekdays'
        $sat = [datetime]::SpecifyKind([datetime]'2026-10-10T12:00:00', 'Utc')   # a Saturday
        (Get-SIJobFlowLatestSlot -Definition $d -NowUtc $sat).DayOfWeek | Should -Be 'Friday'
        $d.Cadence = 'weekly'; $d.Weekday = 1
        (Get-SIJobFlowLatestSlot -Definition $d -NowUtc $sat).DayOfWeek | Should -Be 'Monday'
        (Get-SIJobFlowCadenceText -Definition (Iv 360)) | Should -Be 'every 6 h after the previous run finished'
    }
    It 'interval cadence is validated (5 min - 7 days)' {
        ((Test-SIJobFlowDefinition -Definition (Iv 2) -Map $script:Map).Problems -join ' ') | Should -Match 'interval must be 5 minutes'
        (Test-SIJobFlowDefinition -Definition (Iv 360) -Map $script:Map).Problems | Should -BeNullOrEmpty
    }
}

Describe 'SCHED-1.1: the execution guard (a job''s own cron never runs it twice at once)' {
    BeforeAll { . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1') }
    It 'a second execution while an earlier one of the same job runs is skipped; a finished earlier one is not in the way' {
        $ex = @([pscustomobject]@{ name = 'caj-si-endpoint-a1'; properties = [pscustomobject]@{ status = 'Running'; startTime = '2026-10-05T04:00:00Z' } },
                [pscustomobject]@{ name = 'caj-si-endpoint-b2'; properties = [pscustomobject]@{ status = 'Running'; startTime = '2026-10-05T05:00:00Z' } },
                [pscustomobject]@{ name = 'caj-si-endpoint-z0'; properties = [pscustomobject]@{ status = 'Succeeded'; startTime = '2026-10-04T04:00:00Z' } })
        (Get-SIJobExecutionOverlap -Executions $ex -Self 'caj-si-endpoint-b2').name | Should -Be 'caj-si-endpoint-a1'
        Get-SIJobExecutionOverlap -Executions $ex -Self 'caj-si-endpoint-a1' | Should -BeNullOrEmpty -Because 'the FIRST one runs; only the later one steps aside'
        Get-SIJobExecutionOverlap -Executions @($ex[2]) -Self 'caj-si-endpoint-new' | Should -BeNullOrEmpty
    }
    It 'is wired into the container entry before any engine work, records "skipped", and every job knows where its executions are' {
        $c = ((Get-Content -LiteralPath (Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1')) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $c | Should -Match 'Get-SIJobExecutionOverlap -Executions \$guardList -Self \$guardExec'
        $c | Should -Match "-ExitReason 'skipped' -ErrorMessage \('skipped: previous still running"
        $c.IndexOf('Get-SIJobExecutionOverlap') | Should -BeLessThan $c.IndexOf('dispatchClassifier) {')
        $b = ((Get-Content -LiteralPath (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $b | Should -Match 'Get-SIBootstrapJobGuardEnvArgs -SubscriptionId \$subId -ResourceGroup \$ResourceGroupName'
    }
}

Describe '#277 live (ring 1 2026-10-05): a flow wake-up during a flow run is NOT a guard' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
        # the container entry's execution guard, run as it is (exit -> return), over stubs
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $a = $src.IndexOf('$guardJob = [Environment]::GetEnvironmentVariable(''CONTAINER_APP_JOB_NAME'')'); $b = $src.IndexOf('# #211 (2)')
        $a | Should -BeGreaterThan 0; $b | Should -BeGreaterThan $a
        $script:GuardBlock = $src.Substring($a, $b - $a) -replace '\bexit 0\b', 'return ''exited-0'''
        $script:Running = @([pscustomobject]@{ name = 'caj-si-flow-29852960'; properties = [pscustomobject]@{ status = 'Running'; startTime = '2026-10-05T01:00:00Z' } },
                            [pscustomobject]@{ name = 'caj-si-flow-29853040'; properties = [pscustomobject]@{ status = 'Running'; startTime = '2026-10-05T01:05:00Z' } })
        function script:Invoke-GuardBlock {
            param([string]$Engine, [string]$Job, [string]$Self, $Executions, [hashtable]$Env = @{})
            $script:GuardEvents = New-Object System.Collections.Generic.List[object]; $script:Rows = New-Object System.Collections.Generic.List[object]
            $saved = @{}; foreach ($n in 'CONTAINER_APP_JOB_NAME', 'CONTAINER_APP_JOB_EXECUTION_NAME', 'SI_JOBS_SUBSCRIPTIONID', 'SI_JOBS_RESOURCEGROUP', 'SI_TRIGGER_FROM_QUEUE', 'SI_FLOW_FORCE', 'SI_FLOW_STAGE', 'SI_FLOW_STEP', 'SI_FLOW_FROM_STEP', 'SI_FLOW_CANCEL') { $saved[$n] = [Environment]::GetEnvironmentVariable($n) }
            try {
                [Environment]::SetEnvironmentVariable('CONTAINER_APP_JOB_NAME', $Job); [Environment]::SetEnvironmentVariable('CONTAINER_APP_JOB_EXECUTION_NAME', $Self)
                [Environment]::SetEnvironmentVariable('SI_JOBS_SUBSCRIPTIONID', 'sub'); [Environment]::SetEnvironmentVariable('SI_JOBS_RESOURCEGROUP', 'rg'); [Environment]::SetEnvironmentVariable('SI_TRIGGER_FROM_QUEUE', $null)
                foreach ($n in 'SI_FLOW_FORCE', 'SI_FLOW_STAGE', 'SI_FLOW_STEP', 'SI_FLOW_FROM_STEP', 'SI_FLOW_CANCEL') { [Environment]::SetEnvironmentVariable($n, $null) }; foreach ($k in $Env.Keys) { [Environment]::SetEnvironmentVariable($k, [string]$Env[$k]) }
                $engine = $Engine; $exs = $Executions
                function Get-OptionalEnv { param([string]$Name, $Default = $null) $v = [Environment]::GetEnvironmentVariable($Name); if ([string]::IsNullOrWhiteSpace($v)) { $Default } else { $v } }
                function Invoke-SIArm { param($Path, $ApiVersion, [switch]$List) $exs }
                function Send-SIRunHealthRow { param($Phase, $ExitReason, $ErrorMessage, [switch]$NoTelemetry, $RunContext) $script:Rows.Add([pscustomobject]@{ Phase = $Phase; Exit = $ExitReason }) }
                function Send-SIGuardEvent { param($GuardId, $Outcome, $Engine, $Subject, $RunId, $Detail) $script:GuardEvents.Add($GuardId); [pscustomobject]@{ Status = 'recorded' } }
                $out = @(. ([scriptblock]::Create($script:GuardBlock)) 3>&1 6>&1)
                [pscustomobject]@{ Out = $out; Lines = @($out | ForEach-Object { "$_" } | Where-Object { $_ -and $_ -ne 'exited-0' }); Warnings = @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }); Exited = ($out -contains 'exited-0') }
            } finally { foreach ($n in $saved.Keys) { [Environment]::SetEnvironmentVariable($n, $saved[$n]) } }
        }
    }
    It 'the decision: the flow runner is FlowBusy (an INFO line); any other job started twice is still Skip; nothing running is Run' {
        $d = Get-SIExecutionGuardDecision -Engine 'flow' -Job 'caj-si-flow' -Other $script:Running[0] -Self 'caj-si-flow-29853040'
        $d.Action | Should -Be 'FlowBusy'
        $d.Message | Should -Be '[flow] the flow is still running (execution caj-si-flow-29852960, started 2026-10-05T01:00:00Z); this wake-up does nothing.'
        (Get-SIExecutionGuardDecision -Engine 'endpoint' -Job 'caj-si-endpoint' -Other $script:Running[0] -Self 'x').Action | Should -Be 'Skip'
        (Get-SIExecutionGuardDecision -Engine 'flow' -Job 'caj-si-flow' -Other $null -Self 'x').Action | Should -Be 'Run'
    }
    It 'a flow-runner wake-up during a live flow run: ONE INFO line, no guard event, no Guard (or any) row, no WARNING, exit 0' {
        $r = Invoke-GuardBlock -Engine 'flow' -Job 'caj-si-flow' -Self 'caj-si-flow-29853040' -Executions $script:Running
        $r.Exited | Should -BeTrue
        $script:GuardEvents.Count | Should -Be 0
        $script:Rows.Count | Should -Be 0
        $r.Warnings.Count | Should -Be 0
        $r.Lines.Count | Should -Be 1
        $r.Lines[0] | Should -Match '^\[flow\] the flow is still running \(execution caj-si-flow-29852960, started .+\); this wake-up does nothing\.$'
    }
    It 'a normal job started twice still trips the guard (skipped row + job.execution.previous-running)' {
        $ex = @($script:Running | ForEach-Object { [pscustomobject]@{ name = ($_.name -replace 'flow', 'endpoint'); properties = $_.properties } })
        $r = Invoke-GuardBlock -Engine 'endpoint' -Job 'caj-si-endpoint' -Self 'caj-si-endpoint-29853040' -Executions $ex
        $r.Exited | Should -BeTrue
        $script:GuardEvents.Count | Should -Be 1
        $script:GuardEvents[0] | Should -Be 'job.execution.previous-running'
        $script:Rows.Count | Should -Be 1; $script:Rows[0].Exit | Should -Be 'skipped'
        $r.Lines[0] | Should -Match '^\[guard\] skipped: previous still running'
    }
    It 'Community rehearsal 2026-10-06: a flow execution that CARRIES a request (Run the pipeline now) is never dropped -- it goes on, saying so, and the runner''s lock queues it; a plain wake-up still does nothing' {
        $d = Get-SIExecutionGuardDecision -Engine 'flow' -Job 'caj-si-flow' -Other $script:Running[0] -Self 'caj-si-flow-29853040' -FlowRequest
        $d.Action | Should -Be 'Run'
        $d.Message | Should -Match '^\[flow\] another flow execution is running \(caj-si-flow-29852960, .+\); this one carries a request, so it goes on'
        (Get-SIExecutionGuardDecision -Engine 'endpoint' -Job 'caj-si-endpoint' -Other $script:Running[0] -Self 'x' -FlowRequest).Action | Should -Be 'Skip' -Because 'only the flow runner has a queue'
        foreach ($req in @(@{ SI_FLOW_FORCE = '1' }, @{ SI_FLOW_STAGE = 'collect' }, @{ SI_FLOW_STEP = 'endpoint' }, @{ SI_FLOW_FROM_STEP = 'identity' })) {
            $r = Invoke-GuardBlock -Engine 'flow' -Job 'caj-si-flow' -Self 'caj-si-flow-29853040' -Executions $script:Running -Env $req
            $r.Exited | Should -BeFalse -Because (($req.Keys -join '') + ' is a request')
            $script:GuardEvents.Count | Should -Be 0; $script:Rows.Count | Should -Be 0
            $r.Lines[0] | Should -Match 'carries a request'
        }
        (Invoke-GuardBlock -Engine 'flow' -Job 'caj-si-flow' -Self 'caj-si-flow-29853040' -Executions $script:Running -Env @{ SI_FLOW_FORCE = '0' }).Exited | Should -BeTrue -Because 'SI_FLOW_FORCE=0 is no request'
    }
    It '#946 (live 2026-10-29, three installs): a CANCEL execution beside a live runner is not FlowBusy -- it goes on to the cancel' {
        $getEnv = { param($n) if ($script:EnvOf.ContainsKey($n)) { [string]$script:EnvOf[$n] } else { '' } }
        $script:EnvOf = @{ SI_FLOW_CANCEL = '1' }
        $ask = Test-SIFlowGuardRequest -Get $getEnv
        $ask.Request | Should -BeTrue; $ask.Cancel | Should -BeTrue
        foreach ($off in '0', 'false', 'no', '') {
            $script:EnvOf = @{ SI_FLOW_CANCEL = $off }
            (Test-SIFlowGuardRequest -Get $getEnv).Request | Should -BeFalse -Because ("SI_FLOW_CANCEL='{0}' is no cancel" -f $off)
        }
        foreach ($k in 'SI_FLOW_FORCE', 'SI_FLOW_STAGE', 'SI_FLOW_STEP', 'SI_FLOW_FROM_STEP') {
            $script:EnvOf = @{ $k = '1' }
            $a = Test-SIFlowGuardRequest -Get $getEnv
            $a.Request | Should -BeTrue; $a.Cancel | Should -BeFalse
        }
        $d = Get-SIExecutionGuardDecision -Engine 'flow' -Job 'caj-si-flow' -Other $script:Running[0] -Self 'caj-si-flow-29853040' -FlowRequest -FlowCancel
        $d.Action | Should -Be 'Run'
        $d.Message | Should -Match 'carries a cancel of the running run, so it goes on'
        (Get-SIExecutionGuardDecision -Engine 'endpoint' -Job 'caj-si-endpoint' -Other $script:Running[0] -Self 'x' -FlowCancel).Action | Should -Be 'Skip' -Because 'only the flow runner takes a cancel'
        # the entry's guard as it runs: the cancel execution is not ended as FlowBusy, no guard event, no row
        $r = Invoke-GuardBlock -Engine 'flow' -Job 'caj-si-flow' -Self 'caj-si-flow-29853040' -Executions $script:Running -Env @{ SI_FLOW_CANCEL = '1'; SI_FLOW_CANCEL_REASON = 'support: the run is stuck' }
        $r.Exited | Should -BeFalse
        $script:GuardEvents.Count | Should -Be 0; $script:Rows.Count | Should -Be 0
        $r.Lines[0] | Should -Match 'carries a cancel'
        [Environment]::SetEnvironmentVariable('SI_FLOW_CANCEL_REASON', $null)
        # a plain wake-up is still FlowBusy
        (Invoke-GuardBlock -Engine 'flow' -Job 'caj-si-flow' -Self 'caj-si-flow-29853040' -Executions $script:Running).Exited | Should -BeTrue
        # wiring: the entry asks the one function, and passes the cancel on
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $src | Should -Match '\$guardFlowAsk = Test-SIFlowGuardRequest'
        $src | Should -Match '-FlowCancel:\(\[bool\]\$guardFlowAsk\.Cancel\)'
    }
    It 'the first execution (nothing earlier running) goes on' {
        $r = Invoke-GuardBlock -Engine 'flow' -Job 'caj-si-flow' -Self 'caj-si-flow-29852960' -Executions $script:Running
        $r.Exited | Should -BeFalse; $script:GuardEvents.Count | Should -Be 0; $script:Rows.Count | Should -Be 0
    }
    It 'the runner''s own Busy: a schedule wake-up logs INFO only (no WARN) and raises no guard call; a refused manual start warns' {
        $script:Clock = $script:T0
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        $prev = New-SIJobFlowRunState -Definition $d -NowUtc $script:Clock
        $script:Clock = $script:Clock.AddMinutes(5)
        $logs = New-Object System.Collections.Generic.List[object]
        $p = @{ Definition = $d; Seams = (New-Seams (New-FakeArm)); Save = { param($s) }; Now = $script:NowSb; Sleep = $script:SleepSb; Map = $script:Map; PollSeconds = 60; Previous = $prev
                Log = { param($l, $m) $logs.Add([pscustomobject]@{ L = $l; M = $m }) }.GetNewClosure() }
        $r = Invoke-SIJobFlow @p
        $r.Outcome | Should -Be 'Busy'
        @($logs | Where-Object L -eq 'WARN').Count | Should -Be 0
        @($logs | Where-Object { $_.L -eq 'INFO' -and $_.M -match 'the flow is still running .*this wake-up does nothing' }).Count | Should -Be 1
        . (Join-Path $script:SIRoot 'engine\_shared\SI-Guard.ps1')
        @(Get-SIGuardCallsForFlow -Result $r).Count | Should -Be 0
        $logs.Clear(); $p.Force = $true
        $null = Invoke-SIJobFlow @p
        @($logs | Where-Object { $_.L -eq 'WARN' -and $_.M -match 'nothing starts twice' }).Count | Should -Be 1
        $c = ((Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1')) | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        # #306: a busy wake-up is silent; only a Run now that waits in the queue is recorded once
        $c | Should -Match "if \(\`$pipeRequest -and \(Get-Command -Name Send-SIRunHealthRow"
    }
}

# #412 (operator 2026-10-06, "we dont pull in the same data twice"): asset-properties is RETIRED -- the endpoint, identity and
# azure profilers publish the full asset metadata themselves. An install that still has the job, or a stored pipeline with
# its step, keeps working: the step is dropped when the pipeline is read (said), the validator refuses it, and the mode
# switch turns its timer off in both modes.
Describe 'the retired asset-properties job (#412)' {
    It 'the map marks it retired and never in the flow; nothing needs it; the default pipeline leaves it out even when installed' {
        $j = $script:Map.Jobs['asset-properties']
        $j.Retired | Should -BeTrue
        $j.NeverInFlow | Should -BeTrue
        @($j.Needs).Count | Should -Be 0
        foreach ($k in @($script:Map.Jobs.Keys)) { @($script:Map.Jobs[$k].Needs) | Should -Not -Contain 'asset-properties' -Because "$k reads the profilers' output now" }
        Test-SIJobFlowRetired -Job 'caj-si-asset-properties' -Map $script:Map | Should -BeTrue
        Test-SIJobFlowRetired -Job 'asset-properties' | Should -BeTrue -Because 'it is retired whatever an older map says'
        Test-SIJobFlowRetired -Job 'asset-correlation' -Map $script:Map | Should -BeFalse
        $d = New-SIDefaultJobFlow -Installed (@($script:All) + @('asset-properties')) -Map $script:Map
        @($d.Steps | ForEach-Object Job) | Should -Not -Contain 'asset-properties'
        $script:Map.DefaultFlow | Should -Not -Contain 'asset-properties'
    }
    It 'a stored pipeline that has it as a step loses the step, says why, and saves without it' {
        $json = '{"schema":2,"id":"daily","name":"Daily pipeline","mode":"flow","startTime":"22:00","timeZone":"UTC","cadence":"daily","weekday":1,"intervalMinutes":1440,' +
                '"stages":[{"id":"collect","name":"Collect","steps":[{"job":"endpoint"}]},{"id":"correlate","name":"Correlate","steps":[{"job":"asset-correlation"},{"job":"asset-properties"}]},' +
                '{"id":"deliver","name":"Deliver","steps":[{"job":"asset-datasync"}]}]}'
        $d = ConvertFrom-SIJobFlowJson -Json $json -Map $script:Map
        @($d.Steps | ForEach-Object Job) | Should -Be @('endpoint', 'asset-correlation', 'asset-datasync')
        $d.Migrated | Should -BeTrue
        ($d.MigrationNotes -join "`n") | Should -Match 'asset-properties was a step of the stored pipeline and is taken out: it is retired'
        (ConvertTo-SIJobFlowJson -Definition $d) | Should -Not -Match '"job":"asset-properties"'
        (Test-SIJobFlowDefinition -Definition $d -Map $script:Map).Problems | Should -BeNullOrEmpty
    }
    It 'the validator refuses it as a step, and the mode switch turns its timer off in both modes (never back on)' {
        $bad = New-SIDefaultJobFlow -Installed @('endpoint', 'asset-correlation') -Map $script:Map
        $bad.Steps = @($bad.Steps) + @([pscustomobject]@{ Job = 'asset-properties'; Enabled = $true; WithPrevious = $false; OnFailure = 'skip-dependents'; TimeoutMinutes = 240; Stage = 'correlate' })
        ((Test-SIJobFlowDefinition -Definition $bad -Map $script:Map).Problems -join ' ') | Should -Match 'asset-properties is retired'
        foreach ($mode in 'flow', 'schedules') {
            $p = Get-SIJobOrchestrationSwitchPlan -Jobs @([pscustomobject]@{ Name = 'caj-si-asset-properties'; TriggerType = 'Schedule'; Cron = '45 5 * * *'; RememberedCron = '' }) -Mode $mode -Map $script:Map
            $p[0].Action | Should -Be 'to-manual'
            $p[0].Why | Should -Match 'retired'
        }
        $off = Get-SIJobOrchestrationSwitchPlan -Jobs @([pscustomobject]@{ Name = 'caj-si-asset-properties'; TriggerType = 'Manual'; Cron = ''; RememberedCron = '45 5 * * *' }) -Mode schedules -Map $script:Map
        $off[0].Action | Should -Be 'keep' -Because 'a retired job never gets its timer back'
    }
    It 'Bootstrap no longer creates the job, and the guided install does not ask for it' {
        $b = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'Bootstrap-ContainerAppJob.ps1')
        $b | Should -Match "foreach \(\`$pro in 'asset-correlation', 'asset-cmdb'\)"
        $b | Should -Match "\`$Engines = @\(\`$Engines \| Where-Object \{ \`$_ -ne 'asset-properties' \}\)"
        # the guided install's Pro jobs, where the Pro copy carries them (Test-Path; the Community copy has no Pro jobs)
        $gp = Join-Path $script:SIRoot 'setup\_shared\SI-GuidedInstallPro.ps1'
        if (Test-Path -LiteralPath $gp) { ([regex]::Match((Get-Content -Raw -LiteralPath $gp), "\`$e = @\([^)]*\)").Value) | Should -Not -Match 'asset-properties' }
    }
}
