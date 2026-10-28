#Requires -Version 5.1
<#
    SELF-HEALING IN THE SAME RUN (owner 2026-10-12: "si must self heal with limits" / "so it starts again with new limits,
    same we ci correlation, failed collection or failed ci correlation blocks data out").

    A step whose job was stopped AT ITS OWN RUN LIMIT is not left for the next update and the next day's run: the pipeline
    gives that job the run limit every engine job gets -- the longest Azure takes (7 days; owner 2026-10-13:
    SecurityInsight chooses none) -- by the update's own write (setup/_shared/SI-JobSizing.ps1,
    Invoke-SIJobRunLimitHeal), starts the step again ONCE in the same run and carries on with the steps after it. Any
    kind of step: a collection (also in parts -- the producer or a worker), the CI build, a delivery.
    And BLOCKING: when a collection step or the CI build has failed for good, nothing that needs its result runs in that
    run -- no Risk Analysis, no vulnerability / CMDB step, no mail. (Since 2026-10-13 the data sync and the verification
    still run after a failed CI build, on what is stored: tests\pester\SIv3-RunGoesOnAfterFailedStep.Tests.ps1.)

    Offline: engine/_shared/SI-JobFlow.ps1 over a fake Azure Resource Manager (jobs with a run limit, executions with a
    start and an end) and the sizing's REST seam over the same fake jobs. Stubs in script scope.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-JobFlow.ps1')
    # #636: a new pipeline has the Risk Analysis Summary step switched OFF (SIv3-SummaryGroupings.Tests.ps1). The runner's
    # mechanics here use it as an ordinary step -- an install that switched it on -- so the default flow has every step on.
    $script:SINewDefaultFlowShipped = ${function:New-SIDefaultJobFlow}
    function New-SIDefaultJobFlow { $d = & $script:SINewDefaultFlowShipped @args; foreach ($s in @($d.Steps)) { $s.Enabled = $true }; $d }
    . (Join-Path $script:SIRoot 'setup\_shared\SI-JobSizing.ps1')
    $script:Map = Get-SIJobFlowMap
    $script:SavedStart = $global:SI_Pipeline_StartTime; $script:SavedTz = $global:SI_Pipeline_TimeZone
    $global:SI_Pipeline_StartTime = '01:00'; $global:SI_Pipeline_TimeZone = 'UTC'
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-10-12T01:00:00', 'Utc')
    $script:AllJobs = @('ptc', 'identity', 'azure', 'endpoint', 'publicip', 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed',
                        'asset-cmdb-sql', 'asset-vulnerabilities', 'asset-datasync', 'close-loop-mail', 'verification')

    # ---- a fake Azure: every job has a run limit (default 2 h); an execution ends at once with the scripted status. A
    # 'Failed' execution ran for the job's whole run limit (Azure stopped it) unless -Durations says how long it ran. ----
    function script:New-HealArm {
        param([hashtable]$Outcomes = @{}, [hashtable]$Limits = @{}, [hashtable]$Durations = @{}, [int]$RefuseAbove = 700000, [int]$PatchStatus = 0)
        $script:Arm = @{ Outcomes = $Outcomes; Limits = $Limits; Durations = $Durations; RefuseAbove = $RefuseAbove; PatchStatus = $PatchStatus; N = @{}; Exec = @{}
                         Starts = (New-Object System.Collections.Generic.List[string]); Asked = (New-Object System.Collections.Generic.List[string]); Patched = @{} }
        return {
            param($Method, $Path, $Body)
            $limitOf = { param($k) if ($script:Arm.Limits.ContainsKey($k)) { [int]$script:Arm.Limits[$k] } else { 7200 } }
            $shape = { param($n) $e = $script:Arm.Exec[$n]
                       [pscustomobject]@{ name = $n; properties = [pscustomobject]@{ status = $e.Status; startTime = $e.Start.ToString('o'); endTime = $e.Start.AddSeconds($e.Seconds).ToString('o') } } }
            if ($Method -eq 'POST' -and $Path -match '/jobs/caj-si-([a-z0-9\-]+)/start$') {
                $k = $Matches[1]; $i = 0; if ($script:Arm.N.ContainsKey($k)) { $i = $script:Arm.N[$k] }; $script:Arm.N[$k] = $i + 1
                $name = 'caj-si-{0}-e{1}' -f $k, ($i + 1)
                $status = 'Succeeded'; if ($script:Arm.Outcomes.ContainsKey($k) -and $i -lt @($script:Arm.Outcomes[$k]).Count) { $status = [string]@($script:Arm.Outcomes[$k])[$i] }
                $secs = 600; if ($status -ne 'Succeeded') { $secs = & $limitOf $k }
                if ($script:Arm.Durations.ContainsKey($k) -and $i -lt @($script:Arm.Durations[$k]).Count) { $secs = [int]@($script:Arm.Durations[$k])[$i] }
                $script:Arm.Exec[$name] = @{ Job = $k; Status = $status; Start = $script:Clock; Seconds = $secs }
                $script:Arm.Starts.Add($k)
                return [pscustomobject]@{ name = $name }
            }
            if ($Method -eq 'GET' -and $Path -match '/executions/([a-z0-9\-]+)$') { return (& $shape $Matches[1]) }
            if ($Method -eq 'GET' -and $Path -match '/jobs/caj-si-([a-z0-9\-]+)/executions$') {
                $k = $Matches[1]
                return [pscustomobject]@{ value = @($script:Arm.Exec.Keys | Where-Object { $script:Arm.Exec[$_].Job -eq $k } | Sort-Object | ForEach-Object { & $shape $_ }) }
            }
            if ($Method -eq 'GET' -and $Path -match '/jobs/caj-si-([a-z0-9\-]+)$') {
                return [pscustomobject]@{ name = ('caj-si-' + $Matches[1]); properties = [pscustomobject]@{ configuration = [pscustomobject]@{ replicaTimeout = (& $limitOf $Matches[1]) } } }
            }
            if ($Method -eq 'POST' -and $Path -match '/stop/') { return $null }
            throw "unexpected ARM call $Method $Path"
        }
    }
    # the sizing's REST seam over the same fake jobs: GET = the job, PATCH = its new run limit (refused above RefuseAbove, or
    # with PatchStatus when the identity may not change a job)
    $script:HealRest = {
        param([string]$Method, [string]$Uri, $Body, [string]$Resource, [hashtable]$Headers)
        if ($Uri -notmatch '/Microsoft\.App/jobs/caj-si-([a-z0-9\-]+)\?api-version=') { return [pscustomobject]@{ Status = 400; Body = "unexpected call: $Method $Uri" } }
        $k = $Matches[1]
        $limit = if ($script:Arm.Limits.ContainsKey($k)) { [int]$script:Arm.Limits[$k] } else { 7200 }
        if ($Method -eq 'GET') {
            $job = [pscustomobject]@{ name = "caj-si-$k"; properties = [pscustomobject]@{
                configuration = [pscustomobject]@{ triggerType = 'Manual'; replicaTimeout = $limit; replicaRetryLimit = 0; manualTriggerConfig = [pscustomobject]@{ parallelism = 1; replicaCompletionCount = 1 } }
                template = [pscustomobject]@{ containers = @([pscustomobject]@{ name = 'si'; image = 'acr.io/si-orchestrator:v3'
                    env = @([pscustomobject]@{ name = 'SI_ENGINE'; value = $k }); resources = [pscustomobject]@{ cpu = 4.0; memory = '8.0Gi' } }) } } }
            return [pscustomobject]@{ Status = 200; Body = (ConvertTo-Json -InputObject $job -Depth 12 -Compress) }
        }
        if ($Method -eq 'PATCH') {
            if ($script:Arm.PatchStatus) { return [pscustomobject]@{ Status = $script:Arm.PatchStatus; Body = '{"error":{"code":"AuthorizationFailed","message":"the client does not have authorization to perform action Microsoft.App/jobs/write"}}' } }
            $cfg = ([string]$Body | ConvertFrom-Json).properties.PSObject.Properties['configuration']
            $to = if ($cfg) { [int]$cfg.Value.replicaTimeout } else { 0 }
            $script:Arm.Asked.Add(('{0}={1}' -f $k, $to))
            if ($to -gt [int]$script:Arm.RefuseAbove) { return [pscustomobject]@{ Status = 400; Body = '{"error":{"code":"InvalidRequestParameterWithDetails","message":"ReplicaTimeout must be between 1 and 86400"}}' } }
            if ($to -gt 0) { $script:Arm.Limits[$k] = $to }
            $script:Arm.Patched[$k] = [string]$Body
            return [pscustomobject]@{ Status = 202; Body = '' }
        }
        [pscustomobject]@{ Status = 400; Body = "unexpected call: $Method $Uri" }
    }
    $script:HealGlobals = @{}
    $script:StepKeys = @(Get-SIJobSizingStepKeys)
    # the runner's own wiring (engine\flow\Invoke-SIJobFlowRun.ps1): the update's sizing code raises the limit
    $script:RealRaise = { param($Hit) $script:Raises.Add([string]$Hit.JobName)
        Invoke-SIJobRunLimitHeal -Rest $script:HealRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -JobName ([string]$Hit.JobName) -HitLimitSeconds ([int]$Hit.LimitSeconds) -Globals $script:HealGlobals -Steps $script:StepKeys }
    function script:Invoke-HealFlow {
        param([string[]]$Jobs = $script:AllJobs, $Arm, [switch]$NoHeal, [scriptblock]$Change, [hashtable]$Extra = @{})
        $script:Clock = $script:T0
        $script:Logs = New-Object System.Collections.Generic.List[string]; $script:Phases = New-Object System.Collections.Generic.List[string]; $script:Raises = New-Object System.Collections.Generic.List[string]
        $d = New-SIDefaultJobFlow -Installed $Jobs -Map $script:Map
        if ($Change) { & $Change $d }
        $p = @{ Definition = $d; Seams = (New-SIJobFlowArmSeams -SubscriptionId 's1' -ResourceGroup 'rg-si' -Arm $Arm); Save = { param($s) }
                Now = { $script:Clock }; Sleep = { param($s) $script:Clock = $script:Clock.AddSeconds($s) }; Log = { param($l, $m) $script:Logs.Add(('{0} {1}' -f $l, $m)) }
                Map = $script:Map; PollSeconds = 30; Previous = $null; Force = $true
                OnStep = { param($s, $st, $ph) $script:Phases.Add(('{0} {1}' -f $ph, $st.Job)) } }
        if (-not $NoHeal) { $p.RaiseLimit = $script:RealRaise }
        foreach ($k in $Extra.Keys) { $p[$k] = $Extra[$k] }
        Invoke-SIJobFlow @p
    }
    function script:Get-Step { param($State, [string]$Job) @($State.Steps | Where-Object { $_.Job -eq $Job })[0] }
}

AfterAll {
    $global:SI_Pipeline_StartTime = $script:SavedStart; $global:SI_Pipeline_TimeZone = $script:SavedTz
    Set-SIRunLimitRefused -Value $false
}

Describe 'a step stopped at its job''s own run limit: the limit is raised and the step is started again, once, in the same run' {
    BeforeEach { Set-SIRunLimitRefused -Value $false; $script:HealGlobals = @{} }

    It 'the CI build stopped at 4 h (a job no update has raised yet): ONE raise to the longest run limit Azure takes (7 days), ONE restart, and every step after it runs' {
        $arm = New-HealArm -Outcomes @{ 'asset-correlation' = @('Failed', 'Succeeded') } -Limits @{ 'asset-correlation' = 14400 }
        $r = Invoke-HealFlow -Arm $arm
        $r.State | Should -Be 'Succeeded'
        $ci = Get-Step $r 'asset-correlation'
        $ci.State | Should -Be 'Success'; $ci.Attempts | Should -Be 2
        $ci.RetryReason | Should -Be 'caj-si-asset-correlation was stopped at its run limit of 4 h; the limit is now 168 h and the step is started again'
        @($script:Arm.Starts | Where-Object { $_ -eq 'asset-correlation' }).Count | Should -Be 2
        @($script:Arm.Asked) | Should -Be @('asset-correlation=604800') -Because 'one write, the same value the update''s floor step gives'
        @($script:Raises) | Should -Be @('caj-si-asset-correlation')
        foreach ($k in 'risk-analysis', 'risk-analysis-detailed', 'asset-cmdb-sql', 'asset-vulnerabilities', 'asset-datasync', 'close-loop-mail', 'verification') { (Get-Step $r $k).State | Should -Be 'Success' -Because "$k runs after the healed step" }
        @($script:Logs | Where-Object { $_ -match 'was stopped at its run limit of 4 h; the limit is now 168 h and the step is started again' }).Count | Should -Be 1 -Because 'one plain line'
        @($script:Phases | Where-Object { $_ -eq 'Heal asset-correlation' }).Count | Should -Be 1 -Because 'one run-health row for the action'
        # only the run limit is written: CPU and memory go back as they are
        $c = ($script:Arm.Patched['asset-correlation'] | ConvertFrom-Json).properties.template.containers[0]
        [double]$c.resources.cpu | Should -Be 4.0; $c.resources.memory | Should -Be '8.0Gi'
    }
    It 'EVERY kind of step: a collection (identity) and a delivery (the data sync) are healed the same way' {
        foreach ($k in 'identity', 'asset-datasync') {
            $arm = New-HealArm -Outcomes @{ $k = @('Stopped', 'Succeeded') }
            $r = Invoke-HealFlow -Arm $arm
            (Get-Step $r $k).State | Should -Be 'Success' -Because "$k is started again"
            (Get-Step $r $k).RetryReason | Should -Match ('caj-si-{0} was stopped at its run limit of 2 h; the limit is now 168 h' -f $k)
            @($script:Arm.Asked) | Should -Be @(('{0}=604800' -f $k))
            $r.State | Should -Be 'Succeeded'
        }
    }
    It 'NEGATIVE: stopped at its limit a second time -> the step fails with a plain reason and is NOT started a third time; nothing after it runs' {
        $arm = New-HealArm -Outcomes @{ 'asset-correlation' = @('Failed', 'Failed', 'Succeeded') } -Limits @{ 'asset-correlation' = 14400 }
        $r = Invoke-HealFlow -Arm $arm
        $ci = Get-Step $r 'asset-correlation'
        $ci.State | Should -Be 'Failed'; $ci.Attempts | Should -Be 2
        @($script:Arm.Starts | Where-Object { $_ -eq 'asset-correlation' }).Count | Should -Be 2 -Because 'never more than one retry per step per run'
        @($script:Arm.Asked).Count | Should -Be 1 -Because 'the limit is raised once'
        $ci.Error | Should -Match 'was stopped at its run limit again \(168 h\).*it is not started a third time$'
        (Get-Step $r 'risk-analysis').State | Should -Be 'Skipped'
        (Get-Step $r 'asset-datasync').State | Should -Be 'Skipped'
        $r.State | Should -Be 'Failed'
    }
    It 'NEGATIVE: the customer''s own run limit wins -> no raise, no restart, and the reason says so' {
        $script:HealGlobals = @{ SI_Bootstrap_ReplicaTimeout_AssetCorrelation = '14400' }
        $arm = New-HealArm -Outcomes @{ 'asset-correlation' = @('Failed', 'Succeeded') } -Limits @{ 'asset-correlation' = 14400 }
        $r = Invoke-HealFlow -Arm $arm
        @($script:Arm.Starts | Where-Object { $_ -eq 'asset-correlation' }).Count | Should -Be 1
        @($script:Arm.Asked) | Should -BeNullOrEmpty
        $ci = Get-Step $r 'asset-correlation'
        $ci.State | Should -Be 'Failed'
        $ci.Error | Should -Match 'was stopped at its run limit of 4 h and is not started again: .*SI_Bootstrap_ReplicaTimeout_AssetCorrelation is set'
    }
    It 'Azure refuses the longer limit -> 24 hours is written (the fallback) and the step is started again with it' {
        $arm = New-HealArm -Outcomes @{ 'asset-correlation' = @('Failed', 'Succeeded') } -Limits @{ 'asset-correlation' = 43200 } -RefuseAbove 86400
        $r = Invoke-HealFlow -Arm $arm
        @($script:Arm.Asked) | Should -Be @('asset-correlation=604800', 'asset-correlation=86400') -Because '7 days is refused, 24 h is taken'
        $ci = Get-Step $r 'asset-correlation'
        $ci.State | Should -Be 'Success'; $ci.Attempts | Should -Be 2
        $ci.RetryReason | Should -Match 'run limit of 12 h; the limit is now 24 h and the step is started again'
        $r.State | Should -Be 'Succeeded'
    }
    It 'NEGATIVE: Azure takes no longer limit than the job has (24 h already) -> no restart, with the reason' {
        $arm = New-HealArm -Outcomes @{ 'asset-correlation' = @('Failed', 'Succeeded') } -Limits @{ 'asset-correlation' = 86400 } -RefuseAbove 86400
        $r = Invoke-HealFlow -Arm $arm
        @($script:Arm.Starts | Where-Object { $_ -eq 'asset-correlation' }).Count | Should -Be 1
        (Get-Step $r 'asset-correlation').Error | Should -Match 'is not started again: Azure did not accept a run limit longer than 24 h'
    }
    It 'NEGATIVE: the pipeline may not change the job (403) -> no restart; the reason names the right it needs' {
        $arm = New-HealArm -Outcomes @{ 'asset-correlation' = @('Failed', 'Succeeded') } -Limits @{ 'asset-correlation' = 14400 } -PatchStatus 403
        $r = Invoke-HealFlow -Arm $arm
        @($script:Arm.Starts | Where-Object { $_ -eq 'asset-correlation' }).Count | Should -Be 1
        $ci = Get-Step $r 'asset-correlation'
        $ci.State | Should -Be 'Failed'
        $ci.Error | Should -Match 'is not started again: the pipeline could not change the job \(HTTP 403.*Container Apps Jobs Contributor'
        # ... but a limit that is ALREADY longer than the one that stopped the run (an update raised it) lets the step start again, with nothing written
        $h = Invoke-SIJobRunLimitHeal -Rest $script:HealRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -JobName 'caj-si-asset-correlation' -HitLimitSeconds 7200 -Steps $script:StepKeys
        $h.Restart | Should -BeTrue; $h.Raised | Should -BeFalse; $h.NewSeconds | Should -Be 14400
    }
    It 'NEGATIVE: a run that failed BEFORE its limit (out of memory, its own error) is not healed by a limit: no raise, no restart' {
        $arm = New-HealArm -Outcomes @{ 'asset-correlation' = @('Failed', 'Succeeded') } -Limits @{ 'asset-correlation' = 14400 } -Durations @{ 'asset-correlation' = @(1800) }
        $r = Invoke-HealFlow -Arm $arm
        @($script:Raises) | Should -BeNullOrEmpty
        @($script:Arm.Starts | Where-Object { $_ -eq 'asset-correlation' }).Count | Should -Be 1
        (Get-Step $r 'asset-correlation').Error | Should -Be 'the execution ended failed' -Because 'the existing reason stands'
        Test-SIJobFlowExecutionAtLimit -LimitSeconds 14400 -Execution ([pscustomobject]@{ properties = [pscustomobject]@{ status = 'Failed'; startTime = '2026-10-12T01:00:00Z'; endTime = '2026-10-12T04:58:30Z' } }) | Should -BeTrue
        Test-SIJobFlowExecutionAtLimit -LimitSeconds 14400 -Execution ([pscustomobject]@{ properties = [pscustomobject]@{ status = 'Succeeded'; startTime = '2026-10-12T01:00:00Z'; endTime = '2026-10-12T05:00:00Z' } }) | Should -BeFalse
        Test-SIJobFlowExecutionAtLimit -LimitSeconds 14400 -Execution ([pscustomobject]@{ properties = [pscustomobject]@{ status = 'Running'; startTime = '2026-10-12T01:00:00Z' } }) | Should -BeFalse
    }
    It 'without the self-healing seam (a VM, or the sizing not loaded) nothing changes: the step fails as before' {
        $arm = New-HealArm -Outcomes @{ 'asset-correlation' = @('Failed', 'Succeeded') } -Limits @{ 'asset-correlation' = 14400 }
        $r = Invoke-HealFlow -Arm $arm -NoHeal
        @($script:Arm.Starts | Where-Object { $_ -eq 'asset-correlation' }).Count | Should -Be 1
        (Get-Step $r 'asset-correlation').State | Should -Be 'Failed'
    }
    It 'a collection in parts: the job that was stopped is found -- the producer, else a worker that started since the step did -- and a worker''s queue lease follows its new limit' {
        $arm = New-HealArm -Limits @{ 'identity-producer' = 7200; 'identity-worker' = 14400 }
        $script:Clock = $script:T0
        $parts = Add-SIJobFlowCollectParts -Seams (New-SIJobFlowArmSeams -SubscriptionId 's1' -ResourceGroup 'rg-si' -Arm $arm) -Store ([pscustomobject]@{}) -ProducerJobs @('caj-si-identity-producer')
        # the producer succeeded; a worker of this run ran for its whole 4 h and was stopped; an older worker run does not count
        $script:Arm.Exec['caj-si-identity-producer-e1'] = @{ Job = 'identity-producer'; Status = 'Succeeded'; Start = $script:T0; Seconds = 900 }
        $script:Arm.Exec['caj-si-identity-worker-old'] = @{ Job = 'identity-worker'; Status = 'Failed'; Start = $script:T0.AddDays(-1); Seconds = 14400 }
        $parts.LimitHit('identity', 'caj-si-identity-producer-e1', $script:T0) | Should -BeNullOrEmpty
        $script:Arm.Exec['caj-si-identity-worker-w1'] = @{ Job = 'identity-worker'; Status = 'Failed'; Start = $script:T0.AddMinutes(16); Seconds = 14400 }
        $hit = $parts.LimitHit('identity', 'caj-si-identity-producer-e1', $script:T0)
        $hit.JobName | Should -Be 'caj-si-identity-worker'; $hit.LimitSeconds | Should -Be 14400; $hit.Execution | Should -Be 'caj-si-identity-worker-w1'
        # the producer itself stopped at its limit
        $script:Arm.Exec['caj-si-identity-producer-e2'] = @{ Job = 'identity-producer'; Status = 'Failed'; Start = $script:T0; Seconds = 7200 }
        $parts.LimitHit('identity', 'caj-si-identity-producer-e2', $script:T0).JobName | Should -Be 'caj-si-identity-producer'
        # the worker's limit is raised by the same code, and its queue lease with it
        $h = Invoke-SIJobRunLimitHeal -Rest $script:HealRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -JobName 'caj-si-identity-worker' -HitLimitSeconds 14400 -Steps $script:StepKeys
        $h.Restart | Should -BeTrue; $h.NewSeconds | Should -Be 604800
        $env = @((($script:Arm.Patched['identity-worker'] | ConvertFrom-Json).properties.template.containers[0]).env)
        @($env | Where-Object { $_.name -eq 'SI_QUEUE_LEASE_SECONDS' })[0].value | Should -Be '604800' -Because '7 days is the longest lease a storage queue gives'
        # NEGATIVE: a job that has the longest limit already cannot be given more time -- no write, no restart, the reason says so
        $script:Arm.Asked.Clear()
        $top = Invoke-SIJobRunLimitHeal -Rest $script:HealRest -SubscriptionId 's1' -ResourceGroup 'rg-si' -JobName 'caj-si-identity-worker' -HitLimitSeconds 604800 -Steps $script:StepKeys
        $top.Restart | Should -BeFalse; $top.Why | Should -Match '^7 days is the longest run limit Azure takes for a job'
        @($script:Arm.Asked) | Should -BeNullOrEmpty
    }
    It 'WIRING: the pipeline runner loads the update''s sizing code, keeps the customer''s own run limits and writes one run-health row per action' {
        $run = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $run | Should -Match ([regex]::Escape("Join-Path `$siRoot 'setup/_shared/SI-JobSizing.ps1'"))
        $run | Should -Match ([regex]::Escape('$retry.RaiseLimit = { param($Hit) Invoke-SIJobRunLimitHeal -Rest $healRest -SubscriptionId $sub -ResourceGroup $rg'))
        $run | Should -Match ([regex]::Escape("'^SI_Bootstrap_ReplicaTimeout_'"))
        $run | Should -Match "elseif \(\`$Phase -eq 'Heal'\) \{ Send-SIRunHealthRow -RunContext \`$ctx -Phase Guard -ExitReason 'self-healed'"
    }
}

Describe 'THE RUN GOES ON WITHOUT ONE SOURCE: a failed collection does not stop the CI build, Risk Analysis or delivery' {
    BeforeAll {
        # the source state store's seam (engine\_shared\SI-SourceState.ps1), faked: what the runner told it, and the date it answers
        function script:New-FakeSourceState {
            param($LastGood)
            $script:SrcCalls = New-Object System.Collections.Generic.List[string]
            $o = [pscustomobject]@{ LastGood = $LastGood }
            $o | Add-Member -MemberType ScriptMethod -Name Good -Value { param($j, $since, $now) $script:SrcCalls.Add("good $j"); $now }
            $o | Add-Member -MemberType ScriptMethod -Name Dropped -Value { param($j, $since, $now, $why) $script:SrcCalls.Add("dropped $j"); $this.LastGood }
            $o
        }
    }
    It 'the endpoint collection failed for good, the others succeeded -> the CI build, Risk Analysis and every delivery step START; the step stays failed' {
        $arm = New-HealArm -Outcomes @{ 'endpoint' = @('Failed') } -Durations @{ 'endpoint' = @(900) }
        $r = Invoke-HealFlow -Arm $arm
        (Get-Step $r 'endpoint').State | Should -Be 'Failed' -Because 'a failed step is never shown as succeeded'
        foreach ($k in 'publicip', 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed', 'asset-cmdb-sql', 'asset-vulnerabilities', 'asset-datasync', 'close-loop-mail', 'verification') {
            (Get-Step $r $k).State | Should -Be 'Success' -Because "$k runs on the last good endpoint collection"
            @($script:Arm.Starts) | Should -Contain $k
        }
        $r.State | Should -Be 'Failed' -Because 'the run had a failed step'
        Get-SIPipelineHeldBackText -State $r | Should -Be ''
        Get-SIPipelineWentOnText -State $r | Should -Be 'this run went on without endpoint: its data is from its last good collection, because its last collection did not complete'
        ($script:Logs -join "`n") | Should -Match 'WARN Collect: endpoint did not succeed -- Correlate starts all the same, with the last good collection of that source'
        ($script:Logs -join "`n") | Should -Match 'WARN this run went on without endpoint'
        [string]$r.Note | Should -Match 'this run went on without endpoint' -Because 'the run''s own record keeps the sentence'
    }
    It 'the run''s record names the source AND the date of its last good collection; every collection''s end is told to the source state' {
        $arm = New-HealArm -Outcomes @{ 'endpoint' = @('Failed') } -Durations @{ 'endpoint' = @(900) }
        $good = [datetime]::SpecifyKind([datetime]'2026-10-10T14:05:00', 'Utc')
        $r = Invoke-HealFlow -Arm $arm -Extra @{ SourceState = (New-FakeSourceState -LastGood $good) }
        (Get-Step $r 'endpoint').LastGoodUtc | Should -Be $good
        $sentence = 'this run went on without endpoint: its data is from 2026-10-10 14:05 UTC, because its last collection did not complete'
        Get-SIPipelineWentOnText -State $r | Should -Be $sentence
        [string]$r.Note | Should -Be $sentence
        @($script:SrcCalls | Sort-Object) | Should -Be @('dropped endpoint', 'good azure', 'good identity', 'good publicip')
        @($script:SrcCalls) | Should -Not -Contain 'good ptc' -Because 'the tier classifier is a prerequisite, not a source'
    }
    It 'without a source state the date is the run before''s, when that collection succeeded in it' {
        $prev = [pscustomobject]@{ FlowRunId = 'prev'; State = 'Succeeded'; StartedUtc = $script:T0.AddDays(-1); EndedUtc = $script:T0.AddDays(-1).AddHours(3); HeartbeatUtc = $script:T0.AddDays(-1).AddHours(3); LastSlotUtc = $null
                                   Steps = @([pscustomobject]@{ Job = 'endpoint'; State = 'Success'; StartedUtc = [datetime]::SpecifyKind([datetime]'2026-10-11T01:20:00', 'Utc') }) }
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'endpoint' = @('Failed') } -Durations @{ 'endpoint' = @(900) }) -Extra @{ Previous = $prev }
        Get-SIPipelineWentOnText -State $r | Should -Match 'its data is from 2026-10-11 01:20 UTC'
    }
    It 'a source state that cannot be written never stops the run: said, and the run goes on' {
        $bad = [pscustomobject]@{}
        $bad | Add-Member -MemberType ScriptMethod -Name Good -Value { param($j, $since, $now) throw 'the database did not answer' }
        $bad | Add-Member -MemberType ScriptMethod -Name Dropped -Value { param($j, $since, $now, $why) throw 'the database did not answer' }
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'endpoint' = @('Failed') } -Durations @{ 'endpoint' = @(900) }) -Extra @{ SourceState = $bad }
        (Get-Step $r 'asset-datasync').State | Should -Be 'Success'
        ($script:Logs -join "`n") | Should -Match 'the state of this source could not be recorded \(.*the database did not answer'
    }
    It 'a collection stopped at its run limit is healed FIRST (limit raised, started again once); only when that fails too does the run go on without it' {
        $arm = New-HealArm -Outcomes @{ 'endpoint' = @('Failed', 'Failed') } -Limits @{ 'endpoint' = 14400 }
        $r = Invoke-HealFlow -Arm $arm
        @($script:Arm.Starts | Where-Object { $_ -eq 'endpoint' }).Count | Should -Be 2 -Because 'self-healing ran before the dropout'
        (Get-Step $r 'endpoint').State | Should -BeIn @('Failed', 'TimedOut')
        (Get-Step $r 'asset-correlation').State | Should -Be 'Success'
        Get-SIPipelineWentOnText -State $r | Should -Match '^this run went on without endpoint'
    }
    It 'two sources dropped, one collected -> the run goes on and names both' {
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'endpoint' = @('Failed'); 'azure' = @('Failed') } -Durations @{ 'endpoint' = @(900); 'azure' = @(900) })
        (Get-Step $r 'risk-analysis').State | Should -Be 'Success'
        Get-SIPipelineWentOnText -State $r | Should -Match '^this run went on without azure, endpoint: azure data is from its last good collection; endpoint data is from its last good collection -- their last collections did not complete$'
    }
    It 'EVERY collection failed -> held back as before: nothing new to calculate, nothing runs after Collect' {
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'identity' = @('Failed'); 'azure' = @('Failed'); 'endpoint' = @('Failed') } -Durations @{ 'identity' = @(900); 'azure' = @(900); 'endpoint' = @(900) })
        (Get-Step $r 'publicip').State | Should -Be 'Skipped' -Because 'no collection succeeded, so the collection that needs them is skipped as before'
        foreach ($k in 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed', 'asset-cmdb-sql', 'asset-vulnerabilities', 'asset-datasync', 'close-loop-mail', 'verification') {
            (Get-Step $r $k).State | Should -Be 'Skipped' -Because "$k must not run when no collection succeeded"
            @($script:Arm.Starts) | Should -Not -Contain $k
        }
        (Get-Step $r 'asset-datasync').Error | Should -Match 'Collect did not succeed in this run -- nothing is delivered from a partial collection'
        Get-SIPipelineWentOnText -State $r | Should -Be ''
        Get-SIPipelineHeldBackText -State $r | Should -Match '^this run was held back: identity \(Collect\) did not succeed, so 9 step\(s\) after it did not run and nothing was delivered from this run'
    }
    It 'the tier classifier failed (a prerequisite, not a source) -> held back as before' {
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'ptc' = @('Failed') } -Durations @{ 'ptc' = @(900) })
        foreach ($k in 'identity', 'azure', 'endpoint', 'publicip', 'asset-correlation', 'risk-analysis', 'asset-datasync', 'close-loop-mail') { (Get-Step $r $k).State | Should -Be 'Skipped' }
        Get-SIPipelineWentOnText -State $r | Should -Be ''
        Get-SIPipelineHeldBackText -State $r | Should -Match '^this run was held back: ptc \(Collect\) did not succeed'
    }
    It 'a source dropped AND the CI build failed -> everything that needs the CI build is held at it as before, and the sentence names the CI build (not the source)' {
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'endpoint' = @('Failed'); 'asset-correlation' = @('Failed') } -Durations @{ 'endpoint' = @(900); 'asset-correlation' = @(900) })
        # (no run before this one = a first collection: the data sync waits for the asset build too; the verification runs)
        foreach ($k in 'risk-analysis', 'risk-analysis-detailed', 'asset-cmdb-sql', 'asset-vulnerabilities', 'asset-datasync', 'close-loop-mail') { (Get-Step $r $k).State | Should -Be 'Skipped' }
        (Get-Step $r 'verification').State | Should -Be 'Success' -Because 'it does not rest on the CI build'
        Get-SIPipelinePartialText -State $r -FirstRun | Should -Match '^first collection, not complete yet: asset-correlation \(Correlate\) did not succeed\.'
        Get-SIPipelinePartialText -State $r | Should -Not -Match 'endpoint \('
        # the setting off: held back whole, exactly as before
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'endpoint' = @('Failed'); 'asset-correlation' = @('Failed') } -Durations @{ 'endpoint' = @(900); 'asset-correlation' = @(900) }) -Extra @{ GoOnAfterFailedStep = $false }
        foreach ($k in 'risk-analysis', 'risk-analysis-detailed', 'asset-cmdb-sql', 'asset-vulnerabilities', 'asset-datasync', 'close-loop-mail', 'verification') { (Get-Step $r $k).State | Should -Be 'Skipped' }
        Get-SIPipelineHeldBackText -State $r | Should -Match '^this run was held back: asset-correlation \(Correlate\) did not succeed, so 7 step\(s\)'
    }
    It 'the customer''s saved choices keep working: "stop" on a collection still stops the pipeline; "carry on" goes on like the default' {
        $stop = { param($d) (@($d.Steps | Where-Object { $_.Job -eq 'endpoint' })[0]).OnFailure = 'stop' }
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'endpoint' = @('Failed') } -Durations @{ 'endpoint' = @(900) }) -Change $stop
        $r.State | Should -Be 'Stopped'
        foreach ($k in 'publicip', 'asset-correlation', 'asset-datasync') { (Get-Step $r $k).State | Should -Be 'Skipped'; (Get-Step $r $k).ErrorClass | Should -Be 'flow-stopped' }
        Get-SIPipelineWentOnText -State $r -Definition (New-SIDefaultJobFlow -Installed $script:AllJobs -Map $script:Map | ForEach-Object { & $stop $_; $_ }) | Should -Be ''
        $carry = { param($d) (@($d.Steps | Where-Object { $_.Job -eq 'endpoint' })[0]).OnFailure = 'continue' }
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'endpoint' = @('Failed') } -Durations @{ 'endpoint' = @(900) }) -Change $carry
        foreach ($k in 'publicip', 'asset-correlation', 'risk-analysis', 'asset-datasync', 'close-loop-mail') { (Get-Step $r $k).State | Should -Be 'Success' }
    }
    It 'a source without a good collection for 7 days or more: the calculation runs, DELIVERY WAITS -- no delivery step starts, said once, no skipped-step guard' {
        $why = 'delivery waits: endpoint had no good collection for 7 days or more (endpoint: 8 days) -- nothing is mailed and no ticket is changed until that source collects again; the calculation goes on'
        $script:HoldAsked = 0; $script:HoldWhy = $why
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'endpoint' = @('Failed') } -Durations @{ 'endpoint' = @(900) }) -Extra @{ DeliverHold = { $script:HoldAsked++; $script:HoldWhy } }
        foreach ($k in 'asset-correlation', 'risk-analysis', 'risk-analysis-detailed') { (Get-Step $r $k).State | Should -Be 'Success' -Because 'the calculation goes on' }
        foreach ($k in 'asset-cmdb-sql', 'asset-vulnerabilities', 'asset-datasync', 'close-loop-mail', 'verification') {
            (Get-Step $r $k).State | Should -Be 'Skipped'; (Get-Step $r $k).ErrorClass | Should -Be 'source-too-old'; (Get-Step $r $k).Error | Should -Be $why
            @($script:Arm.Starts) | Should -Not -Contain $k
        }
        $script:HoldAsked | Should -Be 1 -Because 'asked once per run'
        @($script:Logs | Where-Object { $_ -eq ('WARN ' + $why) }).Count | Should -Be 1
        [string]$r.Note | Should -Match 'this run went on without endpoint'
        [string]$r.Note | Should -Match 'delivery waits: endpoint'
        Get-SIPipelineHeldBackText -State $r | Should -Be '' -Because 'nothing failed that held it back -- delivery waits for a source'
        # a waiting delivery is said in the run, never mailed every run: its class is not one the skipped-step guard counts
        [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-Guard.ps1')) | Should -Match ([regex]::Escape("[string]`$_.ErrorClass -in @('needs-failed', 'flow-stopped', 'stage-blocked') -and -not (`$stoppedOnPurpose -and [string]`$_.ErrorClass -eq 'flow-stopped') })"))
    }
    It 'NEGATIVE: no reason -> Deliver runs; a check that throws never holds delivery; a step run now on its own is never held' {
        $r = Invoke-HealFlow -Arm (New-HealArm) -Extra @{ DeliverHold = { '' } }
        (Get-Step $r 'asset-datasync').State | Should -Be 'Success'
        $r = Invoke-HealFlow -Arm (New-HealArm) -Extra @{ DeliverHold = { throw 'the database did not answer' } }
        (Get-Step $r 'close-loop-mail').State | Should -Be 'Success'
        ($script:Logs -join "`n") | Should -Match 'whether delivery must wait for a source could not be checked'
        $r = Invoke-HealFlow -Arm (New-HealArm) -Extra @{ DeliverHold = { 'delivery waits: x' }; Scope = 'step'; Target = 'asset-datasync' }
        (Get-Step $r 'asset-datasync').State | Should -Be 'Success' -Because 'a person asked for this step'
    }
    It 'the verdict is pure: it goes on only with a failed collection, a succeeded one, and nothing else wrong in Collect' {
        $st = { param([hashtable]$s) [pscustomobject]@{ Steps = @($s.Keys | ForEach-Object { [pscustomobject]@{ Job = $_; Stage = $(if ($_ -in 'ptc', 'identity', 'azure', 'endpoint', 'publicip', 'my-step') { 'collect' } else { 'correlate' }); State = $s[$_]; ErrorClass = '' } }) } }
        (Get-SIPipelineCollectVerdict -State (& $st @{ ptc = 'Success'; identity = 'Success'; endpoint = 'Failed' })).GoesOn | Should -BeTrue
        (Get-SIPipelineCollectVerdict -State (& $st @{ ptc = 'Success'; identity = 'Success'; endpoint = 'TimedOut' })).GoesOn | Should -BeTrue
        (Get-SIPipelineCollectVerdict -State (& $st @{ ptc = 'Success'; identity = 'Failed'; endpoint = 'Failed' })).GoesOn | Should -BeFalse -Because 'no collection succeeded'
        (Get-SIPipelineCollectVerdict -State (& $st @{ ptc = 'Failed'; identity = 'Success'; endpoint = 'Failed' })).GoesOn | Should -BeFalse -Because 'the tier classifier is not a source'
        (Get-SIPipelineCollectVerdict -State (& $st @{ identity = 'Success'; endpoint = 'Failed'; 'my-step' = 'Failed' })).GoesOn | Should -BeFalse -Because 'a custom step is not a source'
        (Get-SIPipelineCollectVerdict -State (& $st @{ identity = 'Success'; endpoint = 'Success' })).GoesOn | Should -BeFalse -Because 'nothing dropped'
        (Get-SIPipelineCollectVerdict -State (& $st @{ identity = 'Success'; endpoint = 'Disabled'; azure = 'Failed' })).Dropouts.Job | Should -Be 'azure'
        Test-SIPipelineSourceJob 'caj-si-endpoint' | Should -BeTrue
        Test-SIPipelineSourceJob 'ptc' | Should -BeFalse
        Test-SIPipelineSourceJob 'asset-correlation' | Should -BeFalse
    }
    It 'WIRING: the pipeline runner gives the source state to every run and puts the sentence in the run''s own run-health record; the run record''s note is saved again at the end' {
        $run = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $run | Should -Match ([regex]::Escape('$retry.SourceState = New-SISourceStateStore -Invoke $sourceSql'))
        $run | Should -Match ([regex]::Escape('$pipeWentOn = Get-SIPipelineWentOnText -State $pipeResult -Definition $pipeDefinition'))
        $run | Should -Match ([regex]::Escape("`$(if (`$pipeSources) { '; ' + `$pipeSources } else { '' })"))
        $run | Should -Match ([regex]::Escape('$retry.DeliverHold = { Get-SISourceDeliveryHold -Sources @($sourceStore.Read()) -NowUtc ([datetime]::UtcNow) -HoldDays (Get-SISourceHoldDays) }'))
        $run | Should -Match ([regex]::Escape('$pipeAges = @(Get-SISourceAgeText -Sources @($retry.SourceState.Read()) -NowUtc ([datetime]::UtcNow))'))
        # the run record's note is saved again at the end (since 2026-10-15 a Cancelled run keeps its State / EndedUtc / StopReason;
        # since 2026-10-19 every ended run keeps its state, and its heartbeat + note unless the save is that same final state)
        (Get-SIJobFlowSqlText 'SaveRun') | Should -Match "(?s)WHEN MATCHED THEN UPDATE SET State = CASE WHEN t\.State IN \(N'Succeeded', N'Failed', N'Stopped', N'Cancelled'\) THEN t\.State ELSE @State END,.*?EndedUtc = .*?@EndedUtc END,\s+HeartbeatUtc = .*?@HeartbeatUtc END,\s+StopReason = .*?@StopReason END,\s+Note = CASE WHEN t\.State IN \(N'Succeeded', N'Failed', N'Stopped', N'Cancelled'\) AND t\.State <> @State THEN t\.Note ELSE @Note END\s"
    }
}

Describe 'BLOCKING: a failed CI build, or a Collect with nothing collected, lets no data out of that run' {
    It 'the CI build failed for good -> Risk Analysis and every step that writes, changes a ticket or mails do not run' {
        $arm = New-HealArm -Outcomes @{ 'asset-correlation' = @('Failed') } -Durations @{ 'asset-correlation' = @(900) }
        $r = Invoke-HealFlow -Arm $arm
        foreach ($k in 'risk-analysis', 'risk-analysis-detailed', 'asset-cmdb-sql', 'asset-vulnerabilities', 'close-loop-mail') {
            (Get-Step $r $k).State | Should -Be 'Skipped' -Because "$k must not run after a failed CI build"
            @($script:Arm.Starts) | Should -Not -Contain $k
        }
    }
    It 'the CI build failed for good, the setting off -> nothing after it runs and nothing is delivered (as before 2026-10-13)' {
        $arm = New-HealArm -Outcomes @{ 'asset-correlation' = @('Failed') } -Durations @{ 'asset-correlation' = @(900) }
        $r = Invoke-HealFlow -Arm $arm -Extra @{ GoOnAfterFailedStep = $false }
        foreach ($k in 'risk-analysis', 'risk-analysis-detailed', 'asset-cmdb-sql', 'asset-vulnerabilities', 'asset-datasync', 'close-loop-mail', 'verification') {
            (Get-Step $r $k).State | Should -Be 'Skipped' -Because "$k must not run after a failed CI build"
            @($script:Arm.Starts) | Should -Not -Contain $k
        }
        Get-SIPipelineHeldBackText -State $r | Should -Match '^this run was held back: asset-correlation \(Correlate\) did not succeed, so 7 step\(s\) after it did not run and nothing was delivered from this run'
    }
    It 'a step of Collect that is not a collection (the tier classifier) set to "carry on" when it fails still blocks the stages after it (the stage did not succeed)' {
        $arm = New-HealArm -Outcomes @{ 'ptc' = @('Failed') } -Durations @{ 'ptc' = @(900) }
        $r = Invoke-HealFlow -Arm $arm -Change { param($d) (@($d.Steps | Where-Object { $_.Job -eq 'ptc' })[0]).OnFailure = 'continue' }
        (Get-Step $r 'endpoint').State | Should -Be 'Success' -Because 'inside Collect the collections still run'
        foreach ($k in 'asset-correlation', 'risk-analysis', 'asset-datasync', 'close-loop-mail') { (Get-Step $r $k).State | Should -Be 'Skipped' }
    }
    It 'a choice the customer saved stays theirs, and still lets no data out by itself: Deliver set to "run anyway" starts after a failed CI build, but every step that needs the CI build is skipped -- and it NEVER starts after a Collect in which nothing was collected' {
        $anyway = { param($d) (@(Get-SIPipelineStages -Definition $d | Where-Object { [string]$_.Id -eq 'deliver' })[0]).RunIfPreviousFailed = $true }
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'asset-correlation' = @('Failed') } -Durations @{ 'asset-correlation' = @(900) }) -Change $anyway
        (Get-Step $r 'verification').State | Should -Be 'Success' -Because 'the stage runs anyway; verification needs no CI build'
        foreach ($k in 'asset-cmdb-sql', 'asset-vulnerabilities', 'asset-datasync', 'close-loop-mail') { (Get-Step $r $k).State | Should -Be 'Skipped' -Because "$k needs the CI build, directly or through another step" }
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'ptc' = @('Failed') } -Durations @{ 'ptc' = @(900) }) -Change $anyway
        foreach ($k in 'verification', 'asset-cmdb-sql', 'asset-datasync') { (Get-Step $r $k).State | Should -Be 'Skipped' -Because 'nothing is delivered from a partial collection, whatever the stage is set to' }
        # the one saved choice that DOES let a later step run on the previous CI build: the CI build step itself set to "carry on"
        $carry = { param($d) (@($d.Steps | Where-Object { $_.Job -eq 'asset-correlation' })[0]).OnFailure = 'continue' }
        $r = Invoke-HealFlow -Arm (New-HealArm -Outcomes @{ 'asset-correlation' = @('Failed') } -Durations @{ 'asset-correlation' = @(900) }) -Change $carry
        (Get-Step $r 'risk-analysis').State | Should -Be 'Success' -Because 'inside Correlate, "carry on" is the customer''s explicit choice'
        (Get-Step $r 'asset-datasync').State | Should -Be 'Skipped' -Because 'Deliver still does not start: Correlate did not succeed'
    }
    It 'a collection stopped at its limit, raised, started again and succeeding -> everything after it runs and nothing is held back' {
        $arm = New-HealArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') } -Limits @{ 'endpoint' = 14400 }
        $r = Invoke-HealFlow -Arm $arm
        $r.State | Should -Be 'Succeeded'
        foreach ($k in $script:AllJobs) { (Get-Step $r $k).State | Should -Be 'Success' }
        Get-SIPipelineHeldBackText -State $r | Should -Be ''
    }
}
