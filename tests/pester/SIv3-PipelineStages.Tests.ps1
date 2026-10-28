#Requires -Version 5.1
<#
    THE DAILY PIPELINE RUNS INDEPENDENT STEPS SIDE BY SIDE -- and only those (engine/_shared/SI-JobFlow.ps1).

    Measured on internal 2026-10-09: all 12 steps strictly one after the other (~1 h 30). The default layout is now level 2:
    ptc -> identity -> [azure || endpoint] -> publicip -> the rest as before. Verified in the code before grouping:
      * azure reads identity's tiers of the SAME day (Get-SIIdentityTierMap -> XENG_AccessedBy*), endpoint too
        (MostFrequentUser tier) -- so neither may start together with identity (the map's 'reads');
      * azure and endpoint read nothing of each other from the same day (azure's VM correlation uses PRIOR endpoint runs);
      * publicip needs both. Level 3 (#754): Risk Analysis Summary and Detailed start together -- neither reads the other's
        output (the AI summary's leader snapshot is read just before the follower's mail, order-independent by design, #108).
    The runner already starts every step of a group at once and waits for all of them; this suite proves it for the
    default layout over a fake Azure Resource Manager and a fake clock: start together, wait for the slowest, failure
    semantics inside a group, a crash mid-group (a running step is followed, never started twice), and CONVERGE-DEFAULTS:
    a stored pipeline still on the old one-after-the-other layout gets the new one as it is read; one a person changed is
    never re-laid. Offline.
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
    $global:SI_Pipeline_StartTime = '01:00'; $global:SI_Pipeline_TimeZone = 'UTC'
    $script:Collect = @('ptc', 'identity', 'azure', 'endpoint', 'publicip')
    $script:All = @('ptc', 'identity', 'azure', 'endpoint', 'publicip',
                    'asset-correlation', 'risk-analysis', 'risk-analysis-detailed',
                    'asset-cmdb-sql', 'asset-cmdb', 'asset-vulnerabilities', 'asset-vulns-servicenow', 'asset-datasync', 'close-loop-mail')

    # a fake ARM: each execution runs for N polls, then ends with the scripted status; every start and poll is logged in order
    function New-FakeArm {
        param([hashtable]$Outcome = @{}, [hashtable]$Polls = @{})
        $script:Arm = @{ Outcome = $Outcome; Polls = $Polls; Starts = (New-Object System.Collections.Generic.List[string]); Exec = @{}
                         Events = (New-Object System.Collections.Generic.List[string]); Stops = (New-Object System.Collections.Generic.List[string]) }
        return {
            param($Method, $Path, $Body)
            if ($Method -eq 'POST' -and $Path -match '/jobs/caj-si-([a-z0-9\-]+)/start$') {
                $k = $Matches[1]
                $name = '{0}-x{1}' -f $k, ($script:Arm.Starts.Count + 1)
                $script:Arm.Starts.Add($k); $script:Arm.Events.Add("start:$k")
                $n = 1; if ($script:Arm.Polls.ContainsKey($k)) { $n = [int]$script:Arm.Polls[$k] }
                $script:Arm.Exec[$name] = @{ Job = $k; Left = $n; End = $(if ($script:Arm.Outcome.ContainsKey($k)) { $script:Arm.Outcome[$k] } else { 'Succeeded' }) }
                return [pscustomobject]@{ name = $name; id = "/x/executions/$name" }
            }
            if ($Method -eq 'GET' -and $Path -match '/executions/([a-z0-9\-]+)$') {
                $e = $script:Arm.Exec[$Matches[1]]
                $script:Arm.Events.Add("poll:$($e.Job)")
                if ($e.Left -gt 0) { $e.Left--; return [pscustomobject]@{ properties = [pscustomobject]@{ status = 'Running' } } }
                return [pscustomobject]@{ properties = [pscustomobject]@{ status = $e.End } }
            }
            if ($Method -eq 'POST' -and $Path -match '/stop/([a-z0-9\-]+)$') { $script:Arm.Stops.Add($Matches[1]); return $null }
            throw "unexpected ARM call $Method $Path"
        }
    }
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-10-05T01:00:00', 'Utc')
    $script:NowSb = { $script:Clock }
    $script:SleepSb = { param($s) $script:Clock = $script:Clock.AddSeconds($s) }
    $script:Quiet = { param($l, $m) }
    function Invoke-Flow {
        param($Definition, $Arm, $Previous, [scriptblock]$Save)
        if (-not $Save) { $Save = { param($s) $script:Saved = (ConvertTo-SIJobFlowRunJson -State $s) } }
        Invoke-SIJobFlow -Definition $Definition -Seams (New-SIJobFlowArmSeams -SubscriptionId 'sub' -ResourceGroup 'rg' -Arm $Arm) -Save $Save `
            -Now $script:NowSb -Sleep $script:SleepSb -Log $script:Quiet -Map $script:Map -PollSeconds 60 -Previous $Previous
    }
    function Get-Step { param($State, [string]$Job) @($State.Steps | Where-Object { $_.Job -eq $Job })[0] }
    # what a stored pipeline looked like before layout levels: the shipped order, every step one after the other, no 'defaults'
    function Get-OldDefaultJson {
        param([string[]]$Jobs = $script:All, [hashtable]$Timeouts = @{})
        $d = New-SIDefaultJobFlow -Installed $Jobs -Map $script:Map
        foreach ($s in $d.Steps) { $s.WithPrevious = $false; if ($Timeouts.ContainsKey([string]$s.Job)) { $s.TimeoutMinutes = $Timeouts[[string]$s.Job] } }
        $d.DefaultsLevel = 1
        (ConvertTo-SIJobFlowJson -Definition $d) -replace ',"defaults":1', ''
    }
}
AfterAll { $global:SI_Pipeline_StartTime = $script:SavedStart; $global:SI_Pipeline_TimeZone = $script:SavedTz }

Describe 'the default layout (level 3)' {
    It 'Collect is ptc -> identity -> azure + endpoint together -> publicip; Risk Analysis Summary + Detailed together; nothing else is grouped' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        $d.DefaultsLevel | Should -Be 4   # #636: level 4 = the Summary step off by default
        $groups = Get-SIJobFlowGroups -Definition $d   # returns ONE array (unary comma): enumerate it, never pipe the call
        $g = @(@($groups) | Where-Object Stage -eq 'collect' | ForEach-Object { (@($_.Steps | ForEach-Object Job)) -join '+' })
        $g | Should -Be @('ptc', 'identity', 'azure+endpoint', 'publicip')
        @(@($groups) | Where-Object Stage -eq 'correlate' | ForEach-Object { (@($_.Steps | ForEach-Object Job)) -join '+' }) | Should -Be @('asset-correlation', 'risk-analysis+risk-analysis-detailed')
        @($d.Steps | Where-Object WithPrevious | ForEach-Object Job) | Should -Be @('endpoint', 'risk-analysis-detailed')
        $r = Test-SIJobFlowDefinition -Definition $d -Map $script:Map
        $r.Problems | Should -BeNullOrEmpty
        $r.Warnings | Should -BeNullOrEmpty -Because 'no step runs before or together with a job it needs or reads'
        (ConvertTo-SIJobFlowJson -Definition $d) | Should -Match '"defaults":4'
    }
    It 'the same-day reads found in the code are in the map: azure and endpoint read identity; neither reads the other' {
        $script:Map.Jobs['azure'].Reads | Should -Contain 'identity'
        $script:Map.Jobs['endpoint'].Reads | Should -Contain 'identity'
        $script:Map.Jobs['azure'].Reads | Should -Not -Contain 'endpoint'
        $script:Map.Jobs['endpoint'].Reads | Should -Not -Contain 'azure'
        foreach ($k in 'endpoint', 'azure') { $script:Map.Jobs['publicip'].Needs | Should -Contain $k }
        # the code the reads stand for (a read removed from the code should take the map entry with it)
        $enrich = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'engine', 'asset-profiling', 'stages', 'Invoke-Enrich.ps1'))
        $enrich | Should -Match "Engine -eq 'azure'\)\s*\{[\s\S]{0,1500}Get-SIIdentityTierMap"
        $enrich | Should -Match 'SI_Identity_Profile_CL'
    }
    It 'azure not installed: endpoint starts on its own -- it never joins identity, whose tiers it reads' {
        $d = New-SIDefaultJobFlow -Installed @('ptc', 'identity', 'endpoint', 'publicip') -Map $script:Map
        @($d.Steps | Where-Object WithPrevious).Count | Should -Be 0
        (Test-SIJobFlowDefinition -Definition $d -Map $script:Map).Warnings | Should -BeNullOrEmpty
    }
    It 'a person who starts azure together with identity is warned: azure then uses identity''s previous run' {
        $d = New-SIDefaultJobFlow -Installed $script:Collect -Map $script:Map
        (@($d.Steps | Where-Object Job -eq 'azure')[0]).WithPrevious = $true
        ((Test-SIJobFlowDefinition -Definition $d -Map $script:Map).Warnings -join "`n") | Should -Match 'azure runs together with identity, whose output of the same day it reads'
    }
}

Describe 'the runner over the default layout' {
    BeforeEach { $script:Clock = $script:T0 }
    It 'azure and endpoint are both started before either is polled, and publicip waits for the slower one' {
        $arm = New-FakeArm -Polls @{ azure = 4; endpoint = 1 }
        $r = Invoke-Flow -Definition (New-SIDefaultJobFlow -Installed $script:Collect -Map $script:Map) -Arm $arm
        $r.State | Should -Be 'Succeeded'
        $ev = @($script:Arm.Events)
        $ev.IndexOf('start:endpoint') | Should -BeLessThan $ev.IndexOf('poll:azure') -Because 'the group starts together'
        $ev.IndexOf('start:azure') | Should -BeLessThan $ev.IndexOf('start:endpoint')
        (Get-Step $r 'azure').StartedUtc | Should -Be (Get-Step $r 'endpoint').StartedUtc
        (Get-Step $r 'azure').Group | Should -Be (Get-Step $r 'endpoint').Group
        (Get-Step $r 'publicip').StartedUtc | Should -BeGreaterOrEqual (Get-Step $r 'azure').EndedUtc -Because 'the next group waits for the slowest member'
        (Get-Step $r 'endpoint').EndedUtc | Should -BeLessThan (Get-Step $r 'azure').EndedUtc
        (Get-Step $r 'azure').StartedUtc | Should -BeGreaterOrEqual (Get-Step $r 'identity').EndedUtc -Because 'azure reads identity''s tiers of the same day'
        @($script:Arm.Starts) | Should -Be $script:Collect -Because 'every step started exactly once'
    }
    It 'saving: a group''s steps both reach Running before the first poll, each with its own execution' {
        $arm = New-FakeArm -Polls @{ azure = 2; endpoint = 2 }
        $script:Snaps = New-Object System.Collections.Generic.List[string]
        $save = { param($s) $script:Saved = (ConvertTo-SIJobFlowRunJson -State $s); $script:Snaps.Add(('{0}/{1}' -f (Get-Step $s 'azure').State, (Get-Step $s 'endpoint').State)) }
        $r = Invoke-Flow -Definition (New-SIDefaultJobFlow -Installed $script:Collect -Map $script:Map) -Arm $arm -Save $save
        @($script:Snaps) | Should -Contain 'Running/Running'
        (Get-Step $r 'azure').Execution | Should -Not -Be (Get-Step $r 'endpoint').Execution
    }
    It 'azure fails: endpoint (already running) finishes; the run goes on without azure -- publicip and Correlate start; Collect is still not shown as whole' {
        $arm = New-FakeArm -Outcome @{ azure = 'Failed' } -Polls @{ endpoint = 3 }
        $r = Invoke-Flow -Definition (New-SIDefaultJobFlow -Installed $script:All -Map $script:Map) -Arm $arm
        (Get-Step $r 'azure').State | Should -Be 'Failed'
        (Get-Step $r 'endpoint').State | Should -Be 'Success'
        (Get-Step $r 'publicip').State | Should -Be 'Success' -Because 'it reads the last good collection of azure'
        (Get-Step $r 'asset-correlation').State | Should -Be 'Success'
        (Get-SIPipelineStageOutcome -State $r -Stage 'collect') | Should -Not -Be 'Succeeded' -Because 'rule 4: a Collect with a failed step is never shown as whole'
        $r.State | Should -Be 'Failed'
    }
    It 'endpoint fails while azure still runs: azure is followed to its end; the collection after them runs without endpoint' {
        $arm = New-FakeArm -Outcome @{ endpoint = 'Failed' } -Polls @{ azure = 5 }
        $r = Invoke-Flow -Definition (New-SIDefaultJobFlow -Installed $script:Collect -Map $script:Map) -Arm $arm
        (Get-Step $r 'azure').State | Should -Be 'Success'
        (Get-Step $r 'endpoint').State | Should -Be 'Failed'
        @($script:Arm.Stops).Count | Should -Be 0 -Because 'a failed step never stops the other step of its group'
        (Get-Step $r 'publicip').State | Should -Be 'Success' -Because 'another collection succeeded: the run goes on with the last good endpoint collection'
    }
    It 'azure set to stop the pipeline: endpoint (already started) is followed to its end; nothing after the group starts' {
        $arm = New-FakeArm -Outcome @{ azure = 'Failed' } -Polls @{ endpoint = 3 }
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        (@($d.Steps | Where-Object Job -eq 'azure')[0]).OnFailure = 'stop'
        $r = Invoke-Flow -Definition $d -Arm $arm
        (Get-Step $r 'endpoint').State | Should -Be 'Success'
        (Get-Step $r 'publicip').ErrorClass | Should -Be 'flow-stopped'
        @($script:Arm.Starts) | Should -Be @('ptc', 'identity', 'azure', 'endpoint')
        $r.State | Should -Be 'Stopped'
    }
    It 'a crash while the group runs: the restart follows both running steps -- neither is started again' {
        $arm = New-FakeArm -Polls @{ azure = 4; endpoint = 4 }
        $d = New-SIDefaultJobFlow -Installed $script:Collect -Map $script:Map
        $script:Crash = { param($s) $script:Saved = (ConvertTo-SIJobFlowRunJson -State $s); if ((Get-Step $s 'azure').State -eq 'Running' -and (Get-Step $s 'endpoint').State -eq 'Running') { throw 'container killed' } }
        { Invoke-Flow -Definition $d -Arm $arm -Save $script:Crash } | Should -Throw '*container killed*'
        $prev = ConvertFrom-SIJobFlowRunJson -Json $script:Saved
        (Get-Step $prev 'azure').State | Should -Be 'Running'; (Get-Step $prev 'endpoint').State | Should -Be 'Running'
        $script:Clock = $script:Clock.AddMinutes(30)
        $r = Invoke-Flow -Definition $d -Arm $arm -Previous $prev
        $r.Outcome | Should -Be 'Resume'
        @($script:Arm.Starts) | Should -Be $script:Collect -Because 'azure and endpoint were started ONCE, before the crash'
        $r.State | Should -Be 'Succeeded'
    }
    It 'a crash between starting the two: the started one is followed, the one in "Starting" is Interrupted and never started again' {
        $arm = New-FakeArm
        $d = New-SIDefaultJobFlow -Installed $script:Collect -Map $script:Map
        $prev = New-SIJobFlowRunState -Definition $d -NowUtc $script:Clock
        foreach ($k in 'ptc', 'identity') { (Get-Step $prev $k).State = 'Success' }
        $az = Get-Step $prev 'azure'; $az.State = 'Running'; $az.Execution = 'azure-x0'; $az.StartedUtc = $script:Clock; $az.Attempts = 1
        $script:Arm.Exec['azure-x0'] = @{ Job = 'azure'; Left = 0; End = 'Succeeded' }
        $ep = Get-Step $prev 'endpoint'; $ep.State = 'Starting'; $ep.StartedUtc = $script:Clock
        $script:Clock = $script:Clock.AddMinutes(20)
        $r = Invoke-Flow -Definition $d -Arm $arm -Previous $prev
        (Get-Step $r 'azure').State | Should -Be 'Success'
        (Get-Step $r 'endpoint').State | Should -Be 'Interrupted'
        @($script:Arm.Starts) | Should -Not -Contain 'endpoint'
        @($script:Arm.Starts) | Should -Not -Contain 'azure'
        (Get-Step $r 'publicip').State | Should -Be 'Success' -Because 'the other collections succeeded: it runs on the last good endpoint collection'
    }
}

Describe 'CONVERGE-DEFAULTS: a stored pipeline gets the new layout only while it still has the old default' {
    It 'the old default (every step one after the other, no level) gets azure + endpoint together; nothing else of a step changes' {
        $json = Get-OldDefaultJson -Timeouts @{ endpoint = 75; azure = 300 }
        $json | Should -Not -Match '"defaults"'
        $d = ConvertFrom-SIJobFlowJson -Json $json -Map $script:Map
        $d.DefaultsLevel | Should -Be 4   # #636: level 4 = the Summary step off by default
        @($d.Steps | Where-Object WithPrevious | ForEach-Object Job) | Should -Be @('endpoint', 'risk-analysis-detailed')
        (@($d.Steps | Where-Object Job -eq 'endpoint')[0]).TimeoutMinutes | Should -Be 75 -Because 'a timeout the person set is kept'
        (@($d.Steps | Where-Object Job -eq 'azure')[0]).TimeoutMinutes | Should -Be 300
        @($d.Steps.Job) | Should -Be $script:All
        $d.Migrated | Should -BeTrue
        (@($d.MigrationNotes) -join "`n") | Should -Match 'endpoint now starts together with azure'
        # saved, it is read back as it is: no second change, no note
        $again = ConvertFrom-SIJobFlowJson -Json (ConvertTo-SIJobFlowJson -Definition $d) -Map $script:Map
        $again.Migrated | Should -BeFalse
        (ConvertTo-SIJobFlowJson -Definition $again) | Should -Be (ConvertTo-SIJobFlowJson -Definition $d)
    }
    It 'a step switched off or set to continue does not make it a changed layout -- the grouping still converges' {
        $old = ConvertFrom-Json (Get-OldDefaultJson)
        foreach ($st in @($old.stages)) { foreach ($s in @($st.steps)) { if ($s.job -eq 'publicip') { $s.enabled = $false } } }
        $d = ConvertFrom-SIJobFlowJson -Json ($old | ConvertTo-Json -Depth 8 -Compress) -Map $script:Map
        @($d.Steps | Where-Object WithPrevious | ForEach-Object Job) | Should -Be @('endpoint', 'risk-analysis-detailed')
        (@($d.Steps | Where-Object Job -eq 'publicip')[0]).Enabled | Should -BeFalse
    }
    It 'a pipeline a person grouped themselves is NOT re-laid (only marked)' {
        $old = ConvertFrom-Json (Get-OldDefaultJson)
        foreach ($st in @($old.stages)) { foreach ($s in @($st.steps)) { if ($s.job -eq 'risk-analysis-detailed') { $s.withPrevious = $true } } }
        $d = ConvertFrom-SIJobFlowJson -Json ($old | ConvertTo-Json -Depth 8 -Compress) -Map $script:Map
        @($d.Steps | Where-Object WithPrevious | ForEach-Object Job) | Should -Be @('risk-analysis-detailed')
        $d.DefaultsLevel | Should -Be 4   # #636: level 4 = the Summary step off by default
        [bool]$d.Migrated | Should -BeFalse
    }
    It 'a pipeline a person re-ordered (endpoint above azure) is NOT re-laid' {
        $old = ConvertFrom-Json (Get-OldDefaultJson -Jobs $script:Collect)
        $c = @($old.stages)[0]; $steps = @($c.steps)
        $c.steps = @($steps[0], $steps[1], $steps[3], $steps[2], $steps[4])
        $d = ConvertFrom-SIJobFlowJson -Json ($old | ConvertTo-Json -Depth 8 -Compress) -Map $script:Map
        @($d.Steps.Job) | Should -Be @('ptc', 'identity', 'endpoint', 'azure', 'publicip')
        @($d.Steps | Where-Object WithPrevious).Count | Should -Be 0
    }
    It 'a pipeline with a custom step is NOT re-laid' {
        $old = ConvertFrom-Json (Get-OldDefaultJson -Jobs $script:Collect)
        $c = @($old.stages)[0]
        $c.steps = @($c.steps) + @([pscustomobject]@{ job = 'my-export'; stage = 'collect'; enabled = $true; withPrevious = $false; onFailure = 'continue'; timeoutMinutes = 30 })
        $d = ConvertFrom-SIJobFlowJson -Json ($old | ConvertTo-Json -Depth 8 -Compress) -Map $script:Map
        @($d.Steps | Where-Object WithPrevious).Count | Should -Be 0
    }
    It 'a person who ran azure and endpoint one after the other AFTER the change keeps that (the current level is never re-laid)' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        (@($d.Steps | Where-Object Job -eq 'endpoint')[0]).WithPrevious = $false
        $back = ConvertFrom-SIJobFlowJson -Json (ConvertTo-SIJobFlowJson -Definition $d) -Map $script:Map
        @($back.Steps | Where-Object WithPrevious | ForEach-Object Job) | Should -Be @('risk-analysis-detailed') -Because 'endpoint stays on its own; nothing is re-laid'
        [bool]$back.Migrated | Should -BeFalse
    }
    It 'the old default without azure installed: endpoint stays on its own' {
        $d = ConvertFrom-SIJobFlowJson -Json (Get-OldDefaultJson -Jobs @('ptc', 'identity', 'endpoint', 'publicip', 'asset-correlation')) -Map $script:Map
        @($d.Steps | Where-Object WithPrevious).Count | Should -Be 0
        [bool]$d.Migrated | Should -BeFalse
        $d.DefaultsLevel | Should -Be 4   # #636: level 4 = the Summary step off by default
    }
    It 'a schema-1 flow in the old order converges too (after its lossless migration)' {
        $v1 = '{"schema":1,"mode":"flow","startTime":"01:00","cadence":"daily","steps":[' + ((@($script:Collect | ForEach-Object { '{{"job":"{0}"}}' -f $_ })) -join ',') + ']}'
        $d = ConvertFrom-SIJobFlowJson -Json $v1 -Map $script:Map
        @($d.Steps | Where-Object WithPrevious | ForEach-Object Job) | Should -Be @('endpoint')
    }
    It 'the C# web app carries the same rule and the same default (JobFlow.cs DefaultTogether / ConvergeDefaultLayout)' {
        $cs = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'pro-management', 'src', 'SI.Management.Web', 'Jobs', 'JobFlow.cs'))
        $cs | Should -Match '\["collect"\] = \["endpoint"\]'
        $cs | Should -Match '\["correlate"\] = \["risk-analysis-detailed"\]'
        $cs | Should -Match ('CurrentDefaultsLevel = {0};' -f $script:SIJobFlow.DefaultsLevel)
        $cs | Should -Match 'ConvergeDefaultLayout\(MoveAfterNeeds'
    }
}
