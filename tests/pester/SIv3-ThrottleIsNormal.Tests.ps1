#Requires -Version 5.1
<#
    SecurityInsight -- THROTTLE-IS-NORMAL (#532; the contract is framework DOCS/REQUIREMENTS.md §12.18).

    Owner 2026-10-10, after a customer-visible "job FAILED" mail whose only cause was Microsoft Graph HTTP 429: "maybe even
    have a throttle category or similar, but it is not to alert me about, except if you cannot handle it, but this is
    normal".

    What must hold:
      - a run whose failures are ALL real throttling (429) and that wrote nothing ends 'throttled' (run health), telemetry
        Outcome 'warning' + ErrorClass 'throttled' (never 'failed', so never a fix request), and NO mail;
      - a 403 is a real failure ('error' / 'failed'); 429 + 403 together is a real failure, also when both are in one line;
      - a failure in a stage that writes, a partial run, or a run of an engine that APPLIES changes (unless it says it
        wrote nothing) is never turned into 'throttled' -- a partial result is never shipped as whole;
      - the flow: a step whose engine recorded END 'throttled' is a throttled step (amber, not failed); a run whose only
        failures are throttled steps is 'throttled', exits 0 and mails no "skipped" guard; a real failure next to it still does;
      - ONE "stuck" alert: only when the job has been throttled on every run for SI_Throttle_StuckHours (6) or
        SI_Throttle_StuckRuns (12) runs -- whichever first, never on one run -- once per episode; a success clears it.
    Offline; every network call is a seam; nothing is sent or mailed. PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-TelemetrySend.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-RunOutcome.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-JobFlow.ps1'))
    # #636: a new pipeline has the Risk Analysis Summary step switched OFF (SIv3-SummaryGroupings.Tests.ps1). The runner's
    # mechanics here use it as an ordinary step -- an install that switched it on -- so the default flow has every step on.
    $script:SINewDefaultFlowShipped = ${function:New-SIDefaultJobFlow}
    function New-SIDefaultJobFlow { $d = & $script:SINewDefaultFlowShipped @args; foreach ($s in @($d.Steps)) { $s.Enabled = $true }; $d }
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-Guard.ps1'))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', 'asset-profiling', 'shared', 'Send-SIRunHealthRow.ps1'))

    $script:M429  = 'Response status code does not indicate success: 429 (Too Many Requests). graph.microsoft.com Retry-After: 30'
    $script:M403  = 'Response status code does not indicate success: 403 (Forbidden). graph.microsoft.com Authorization_RequestDenied'
    $script:M503  = 'Response status code does not indicate success: 503 (Service Unavailable). graph.microsoft.com'
    $script:MTime = 'The request was canceled due to the configured HttpClient.Timeout of 100 seconds elapsing. A task was canceled.'
    $script:Anon = [pscustomobject]@{ Mode = 'anonymous'; Endpoint = 'https://uplink.test'; AccessCode = 'community'; Edition = 'community'; LicenceState = 'none'
                                      Version = '3.0.0'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; InstallId = '0f0e0d0c-0b0a-4908-8706-050403020100'; TenantId = ''; StateDirectory = $TestDrive }
    function script:New-Capture { $l = New-Object System.Collections.Generic.List[object]; [pscustomobject]@{ List = $l; Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $l.Add($Record); [pscustomobject]@{ Status = 'ok' } }.GetNewClosure() } }
    function script:Get-RunWire($c) { @($c.List | Where-Object { $_.Kind -eq 'run' })[0] }
}

Describe 'which runs are throttled (pure)' {
    It 'a 429-only run that wrote nothing is throttled' {
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage $script:M429 | Should -Be 'throttled'
    }
    It '2026-10-22: a 5xx or a timeout is NOT throttling -- a real failure with its own text (alone or next to a 429)' {
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage $script:M503 | Should -Be 'error'
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage $script:MTime | Should -Be 'error'
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage ('{0} | {1}' -f $script:M429, $script:M503) | Should -Be 'error'
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage 'Connection timed out (acct.table.core.windows.net:443)' | Should -Be 'error'
    }
    It 'a 403 is a real failure' {
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage $script:M403 | Should -Be 'error'
    }
    It 'mixed 429 + 403 is a real failure -- as two failures, and in ONE line too' {
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage ('{0} | {1}' -f $script:M429, $script:M403) | Should -Be 'error'
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage 'Graph answered 429 Too Many Requests, then 403 Forbidden (Authorization_RequestDenied)' | Should -Be 'error'
        @(Get-SIRunFailureClasses -Message 'Graph answered 429 Too Many Requests, then 403 Forbidden') | Should -Contain 'access-refused'
    }
    It 'an unknown failure next to the throttling is a real failure (a bug is never hidden)' {
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage ('{0} | You cannot call a method on a null-valued expression.' -f $script:M429) | Should -Be 'error'
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage '' | Should -Be 'error' -Because 'no message proves nothing'
    }
    It 'NEGATIVE: a partial run, a failure while writing, or a run that says it wrote part is never throttled' {
        Resolve-SIThrottledExitReason -ExitReason 'success-partial' -ErrorMessage $script:M429 | Should -Be 'success-partial'
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage $script:M429 -FailedStep 'output' | Should -Be 'error'
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage $script:M429 -FailedStep 'tagging' | Should -Be 'error'
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage $script:M429 -FailedStep 'collect' | Should -Be 'throttled'
        Resolve-SIThrottledExitReason -ExitReason 'error' -ErrorMessage $script:M429 -WrotePartial | Should -Be 'error'
        Resolve-SIThrottledExitReason -ExitReason 'settings-error' -ErrorMessage $script:M429 | Should -Be 'settings-error'
        Resolve-SIThrottledExitReason -ExitReason 'success' -ErrorMessage $script:M429 | Should -Be 'success'
    }
    It 'a real failure next to a throttled one is a real failure when outcomes are merged' {
        Merge-SIExitReason 'throttled' 'error' | Should -Be 'error'
        Merge-SIExitReason 'error' 'throttled' | Should -Be 'error'
        Merge-SIExitReason 'success' 'throttled' | Should -Be 'throttled'
    }
}

Describe 'telemetry: throttled = warning, ErrorClass throttled, never failed' {
    BeforeEach { $global:SI_TelemetryHalted = $false; $global:SI_Telemetry_Enabled = $null }
    It 'the outcome map' {
        Get-SITelemetryOutcome -ExitReason 'throttled' | Should -Be 'warning'
        Get-SITelemetryOutcome -ExitReason 'error' | Should -Be 'failed'
        ConvertTo-SITelemetryExitReason 'throttled' | Should -Be 'throttled'
    }
    It 'a 503-only throttled run reports ErrorClass throttled (platform-5xx maps the same way)' {
        $r = New-SITelemetryRunRecord -Job 'si-identity' -ExitReason 'throttled' -Edition 'community' -Version '3.0.0' -Hosting 'container' -RuntimeIdentity 'mi-container' `
                -LicenceState 'none' -ErrorMessage $script:M503 -Anonymous -InstallId '0f0e0d0c-0b0a-4908-8706-050403020100'
        $r.Outcome | Should -Be 'warning'
        $r.ErrorClass | Should -Be 'throttled'
        $r.Ok | Should -BeFalse
    }
    It 'the wire record of a throttled run: Outcome warning, ErrorClass throttled' {
        $c = New-Capture
        $rc = [pscustomobject]@{ Engine = 'identity'; ShardIndex = 0; StartedAt = [datetime]::UtcNow }
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'throttled' -ErrorMessage $script:M429 -Context $script:Anon -Transport $c.Transport -NoHeartbeat
        $w = Get-RunWire $c
        $w.Outcome | Should -Be 'warning'
        $w.ErrorClass | Should -Be 'throttled'
    }
    It 'NEGATIVE: a 403 run is still failed' {
        $c = New-Capture
        $rc = [pscustomobject]@{ Engine = 'identity'; ShardIndex = 0; StartedAt = [datetime]::UtcNow }
        $null = Send-SITelemetryRunEnd -RunContext $rc -ExitReason 'error' -ErrorMessage $script:M403 -Context $script:Anon -Transport $c.Transport -NoHeartbeat
        (Get-RunWire $c).Outcome | Should -Be 'failed'
    }
}

Describe 'the run-health END record decides throttled (every engine, one place)' {
    BeforeAll {
        function script:Save-G { @{ W = $global:SI_WorkspaceResourceId; D = $global:SI_DceName; R = $global:SI_DcrResourceGroup; Wi = $global:WhatIfMode } }
        function script:Restore-G($s) { $global:SI_WorkspaceResourceId = $s.W; $global:SI_DceName = $s.D; $global:SI_DcrResourceGroup = $s.R; $global:WhatIfMode = $s.Wi }
        function script:New-Rc([string]$Engine, [string]$Step) {
            $o = [pscustomobject]@{ RunId = 'r1'; Engine = $Engine; ShardIndex = 0; ShardCount = 1; CollectionTime = [datetime]::UtcNow; StartedAt = [datetime]::UtcNow }
            if ($Step) { $o | Add-Member -NotePropertyName FailedStep -NotePropertyValue $Step }
            $o
        }
    }
    BeforeEach {
        $script:g = Save-G
        # no workspace: the record itself is not posted; the END moment (telemetry + the stuck check) still runs
        $global:SI_WorkspaceResourceId = $null; $global:SI_DceName = $null; $global:SI_DcrResourceGroup = $null; $global:WhatIfMode = $false
        $script:Tel = New-Object System.Collections.Generic.List[object]
        $script:Stuck = New-Object System.Collections.Generic.List[object]
        Mock Send-SITelemetryRunEnd { $script:Tel.Add([pscustomobject]@{ ExitReason = $ExitReason; ErrorMessage = $ErrorMessage }) }
        Mock Invoke-SIThrottleStuckCheck { $script:Stuck.Add($Engine) }
        Mock Send-SIGuardEvent { throw 'no guard event may be raised here' }
        Mock Send-SIMail { throw 'no mail may be sent here' }
    }
    AfterEach { Restore-G $script:g }

    It 'a 429-only profiler run: throttled to telemetry, the customer words in the record, the stuck CHECK runs, no mail' {
        Send-SIRunHealthRow -RunContext (New-Rc 'identity' 'collect') -Phase End -ExitReason 'error' -ErrorMessage $script:M429
        $script:Tel.Count | Should -Be 1
        $script:Tel[0].ExitReason | Should -Be 'throttled'
        $script:Tel[0].ErrorMessage | Should -Match 'Microsoft throttled this run; it runs again automatically'
        $script:Stuck.Count | Should -Be 1
        Should -Invoke Send-SIGuardEvent -Times 0
        Should -Invoke Send-SIMail -Times 0
    }
    It 'a 403 run stays error (no stuck check)' {
        Send-SIRunHealthRow -RunContext (New-Rc 'identity' 'collect') -Phase End -ExitReason 'error' -ErrorMessage $script:M403
        $script:Tel[0].ExitReason | Should -Be 'error'
        $script:Stuck.Count | Should -Be 0
    }
    It 'a mixed 429 + 403 run stays error' {
        Send-SIRunHealthRow -RunContext (New-Rc 'identity' 'collect') -Phase End -ExitReason 'error' -ErrorMessage ('{0} | {1}' -f $script:M429, $script:M403)
        $script:Tel[0].ExitReason | Should -Be 'error'
    }
    It 'NEGATIVE: an engine that APPLIES changes stays error, unless it says it wrote nothing' {
        Send-SIRunHealthRow -RunContext (New-Rc 'an-applying-job') -Phase End -ExitReason 'error' -ErrorMessage $script:M429
        $script:Tel[0].ExitReason | Should -Be 'error'
        $rc = New-Rc 'an-applying-job'; $rc | Add-Member -NotePropertyName WroteNothing -NotePropertyValue $true
        Send-SIRunHealthRow -RunContext $rc -Phase End -ExitReason 'error' -ErrorMessage $script:M429
        $script:Tel[1].ExitReason | Should -Be 'throttled'
    }
    It 'NEGATIVE: a profiler that failed while writing its output stays error' {
        Send-SIRunHealthRow -RunContext (New-Rc 'endpoint' 'output') -Phase End -ExitReason 'error' -ErrorMessage $script:M429
        $script:Tel[0].ExitReason | Should -Be 'error'
    }
}

Describe 'the ONE stuck alert' {
    BeforeAll { $script:N = [datetime]::SpecifyKind([datetime]'2026-10-10T12:00:00', 'Utc') }
    It 'one throttled run is never stuck' {
        $v = Get-SIThrottleStuckVerdict -History @([pscustomobject]@{ EndedUtc = $script:N; ExitReason = 'throttled' }) -NowUtc $script:N
        $v.Stuck | Should -BeFalse; $v.AlertDue | Should -BeFalse
    }
    It 'a daily job throttled twice in a row (24 h): stuck, alert due once; the third run does not alert again' {
        $h2 = @([pscustomobject]@{ EndedUtc = $script:N; ExitReason = 'throttled' }, [pscustomobject]@{ EndedUtc = $script:N.AddHours(-24); ExitReason = 'throttled' }, [pscustomobject]@{ EndedUtc = $script:N.AddHours(-48); ExitReason = 'success' })
        $v = Get-SIThrottleStuckVerdict -History $h2 -NowUtc $script:N
        $v.Stuck | Should -BeTrue; $v.AlertDue | Should -BeTrue; $v.Runs | Should -Be 2
        $h3 = @([pscustomobject]@{ EndedUtc = $script:N.AddHours(24); ExitReason = 'throttled' }) + $h2
        $v3 = Get-SIThrottleStuckVerdict -History $h3 -NowUtc $script:N.AddHours(24)
        $v3.Stuck | Should -BeTrue; $v3.AlertDue | Should -BeFalse
    }
    It 'under the threshold: two throttled runs 2 hours apart are not stuck' {
        $h = @([pscustomobject]@{ EndedUtc = $script:N; ExitReason = 'throttled' }, [pscustomobject]@{ EndedUtc = $script:N.AddHours(-2); ExitReason = 'throttled' })
        (Get-SIThrottleStuckVerdict -History $h -NowUtc $script:N).Stuck | Should -BeFalse
    }
    It 'a frequent job: stuck at the 12th throttled run in a row, not at the 11th' {
        $h = @(0..11 | ForEach-Object { [pscustomobject]@{ EndedUtc = $script:N.AddMinutes(-5 * $_); ExitReason = 'throttled' } })
        $v12 = Get-SIThrottleStuckVerdict -History $h -NowUtc $script:N
        $v12.Stuck | Should -BeTrue; $v12.AlertDue | Should -BeTrue
        (Get-SIThrottleStuckVerdict -History @($h | Select-Object -Skip 1) -NowUtc $script:N.AddMinutes(-5)).Stuck | Should -BeFalse
    }
    It 'the alert is not missed when TIME crosses the threshold between two runs (judged at the previous run''s own time)' {
        $h = @([pscustomobject]@{ EndedUtc = $script:N; ExitReason = 'throttled' }, [pscustomobject]@{ EndedUtc = $script:N.AddHours(-5); ExitReason = 'throttled' },
               [pscustomobject]@{ EndedUtc = $script:N.AddHours(-5.5); ExitReason = 'throttled' })
        (Get-SIThrottleStuckVerdict -History $h -NowUtc $script:N).Stuck | Should -BeFalse -Because '5.5 h < 6 h and 3 runs < 12'
        $h1 = @([pscustomobject]@{ EndedUtc = $script:N.AddHours(1); ExitReason = 'throttled' }) + $h
        $v = Get-SIThrottleStuckVerdict -History $h1 -NowUtc $script:N.AddHours(1)
        $v.Stuck | Should -BeTrue; $v.AlertDue | Should -BeTrue
    }
    It 'a success ends the episode; a real failure breaks the streak too' {
        $h = @([pscustomobject]@{ EndedUtc = $script:N; ExitReason = 'throttled' }, [pscustomobject]@{ EndedUtc = $script:N.AddHours(-1); ExitReason = 'success' }, [pscustomobject]@{ EndedUtc = $script:N.AddHours(-30); ExitReason = 'throttled' })
        (Get-SIThrottleStuckVerdict -History $h -NowUtc $script:N).Stuck | Should -BeFalse
        $h[1].ExitReason = 'error'
        (Get-SIThrottleStuckVerdict -History $h -NowUtc $script:N).Stuck | Should -BeFalse
    }
    It 'the thresholds can be set (SI_Throttle_StuckHours / SI_Throttle_StuckRuns); a bad value keeps the default' {
        Get-SIThrottleSetting -Name 'SI_Throttle_StuckHours' -Default 6 -Globals @{ SI_Throttle_StuckHours = '48' } | Should -Be 48
        Get-SIThrottleSetting -Name 'SI_Throttle_StuckHours' -Default 6 -Globals @{ SI_Throttle_StuckHours = 'soon' } | Should -Be 6
        Get-SIThrottleSetting -Name 'SI_Throttle_StuckRuns' -Default 12 -Globals @{ SI_Throttle_StuckRuns = 0 } | Should -Be 12
        $h = @([pscustomobject]@{ EndedUtc = $script:N; ExitReason = 'throttled' }, [pscustomobject]@{ EndedUtc = $script:N.AddHours(-24); ExitReason = 'throttled' })
        (Get-SIThrottleStuckVerdict -History $h -NowUtc $script:N -Hours 48).Stuck | Should -BeFalse
    }
    It 'a run-by-run sequence of a daily job raises exactly ONE alert, and a new one only after a success' {
        $store = New-Object System.Collections.Generic.List[object]
        $alerts = New-Object System.Collections.Generic.List[object]
        $q = { param($k) @($store.ToArray()) }.GetNewClosure()
        $raise = { param($v, $e, $r) $alerts.Add($e) }.GetNewClosure()
        $seq = @('throttled', 'throttled', 'throttled', 'throttled', 'success', 'throttled', 'throttled')
        for ($i = 0; $i -lt $seq.Count; $i++) {
            $t = $script:N.AddDays($i)
            if ($seq[$i] -eq 'throttled') { $null = Invoke-SIThrottleStuckCheck -Engine 'identity' -RunId "r$i" -NowUtc $t -Query $q -Raise $raise -Globals @{} }
            $store.Add([pscustomobject]@{ EndedUtc = $t; ExitReason = $seq[$i] })
        }
        $alerts.Count | Should -Be 2 -Because 'one per episode: runs 1-4 (alert at run 2) and runs 6-7 (alert at run 7)'
    }
    It 'the stuck alert is the catalogued guard, and it can be turned off like every guard' {
        $g = Get-SIGuardDefinition -Id 'job.run.throttled-stuck'
        $g | Should -Not -BeNullOrEmpty
        $g.kind | Should -Be 'next-run'
        (Get-SIGuardSwitchNames -GuardId 'job.run.throttled-stuck').Enabled | Should -Be 'SI_Guard_JobRunThrottledStuck_Enabled'
        $ref = Get-Content -LiteralPath ([IO.Path]::Combine($script:SIRoot, 'config', 'SecurityInsight.custom.reference.ps1')) -Raw
        $ref | Should -Match '\$global:SI_Throttle_StuckHours = 6'
        $ref | Should -Match '\$global:SI_Throttle_StuckRuns = 12'
    }
}

Describe 'the flow: a throttled step is amber, not failed, and mails nothing' {
    BeforeAll {
        $script:Map = Get-SIJobFlowMap
        function script:New-ThrottleArm([hashtable]$Outcomes) {
            $script:Arm = @{ Outcomes = $Outcomes; Exec = @{}; N = @{} }
            {
                param($Method, $Path, $Body)
                if ($Method -eq 'POST' -and $Path -match '/jobs/caj-si-([a-z0-9\-]+)/start$') {
                    $k = $Matches[1]; $i = 0; if ($script:Arm.N.ContainsKey($k)) { $i = $script:Arm.N[$k] }; $script:Arm.N[$k] = $i + 1
                    $name = 'caj-si-{0}-e{1}' -f $k, ($i + 1)
                    $script:Arm.Exec[$name] = $(if ($script:Arm.Outcomes.ContainsKey($k)) { $script:Arm.Outcomes[$k] } else { 'Succeeded' })
                    return [pscustomobject]@{ name = $name }
                }
                if ($Method -eq 'GET' -and $Path -match '/executions/([a-z0-9\-]+)$') { return [pscustomobject]@{ properties = [pscustomobject]@{ status = $script:Arm.Exec[$Matches[1]] } } }
                throw "unexpected ARM call $Method $Path"
            }
        }
        function script:Invoke-ThrottleFlow([string[]]$Jobs, $Arm, $Evidence) {
            $script:Clock = [datetime]::SpecifyKind([datetime]'2026-10-10T05:00:00', 'Utc')
            $d = New-SIDefaultJobFlow -Installed $Jobs -Map $script:Map
            Invoke-SIJobFlow -Definition $d -Seams (New-SIJobFlowArmSeams -SubscriptionId 'sub' -ResourceGroup 'rg' -Arm $Arm) -Save { param($s) } `
                -Now { $script:Clock } -Sleep { param($s) $script:Clock = $script:Clock.AddSeconds($s) } -Log { param($l, $m) } -Map $script:Map -PollSeconds 30 -Previous $null -Force `
                -StartEvidence $Evidence -StartRetryBackoffSeconds 0
        }
    }
    It 'the engine of the step recorded END throttled: the step is throttled, the run is throttled, no skipped-step mail' {
        $arm = New-ThrottleArm @{ 'ptc' = 'Failed' }
        $ev = { param($Job, $Execution, $StartedUtc, $EndedUtc) [pscustomobject]@{ HasStartRecord = $true; HasTranscript = $true; EndReason = $(if ($Job -eq 'ptc') { 'throttled' } else { $null }) } }
        $r = Invoke-ThrottleFlow -Jobs @('ptc', 'identity') -Arm $arm -Evidence $ev
        $s = @($r.Steps | Where-Object { $_.Job -eq 'ptc' })[0]
        $s.State | Should -Be 'Failed'
        $s.ErrorClass | Should -Be 'throttled'
        $s.Error | Should -Not -BeNullOrEmpty -Because 'the step keeps its own error text (filled with the throttle words only when it had none)'
        Get-SIJobFlowStepExitReason $s | Should -Be 'throttled'
        Test-SIJobFlowThrottledOnly -State $r | Should -BeTrue
        Get-SIJobFlowRunExitReason -State $r | Should -Be 'throttled'
        Get-SIPipelineStatusText -State $r -Definition (New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map) | Should -Match 'throttled$'
        # the step that needs it was skipped (never built on a result that did not land) -- and that is not mailed
        @($r.Steps | Where-Object { $_.Job -eq 'identity' })[0].State | Should -Be 'Skipped'
        @(Get-SIGuardCallsForFlow -Result $r | Where-Object { $_.GuardId -eq 'flow.step.skipped' }).Count | Should -Be 0
    }
    It 'NEGATIVE: the engine recorded another failure (or no END record at all): the step fails as before and the skip is mailed' {
        foreach ($why in @('failed', $null)) {
            $arm = New-ThrottleArm @{ 'ptc' = 'Failed' }
            $ev = { param($Job, $Execution, $StartedUtc, $EndedUtc) [pscustomobject]@{ HasStartRecord = $true; HasTranscript = $true; EndReason = $why } }.GetNewClosure()
            $r = Invoke-ThrottleFlow -Jobs @('ptc', 'identity') -Arm $arm -Evidence $ev
            @($r.Steps | Where-Object { $_.Job -eq 'ptc' })[0].ErrorClass | Should -Be 'job-failed'
            Test-SIJobFlowThrottledOnly -State $r | Should -BeFalse
            Get-SIJobFlowRunExitReason -State $r | Should -Be 'error'
            @(Get-SIGuardCallsForFlow -Result $r | Where-Object { $_.GuardId -eq 'flow.step.skipped' }).Count | Should -Be 1
        }
    }
    It 'mixed: a throttled step AND a real failure -- the run is failed, the real failure''s skips are still mailed' {
        $r = [pscustomobject]@{ State = 'Failed'; Trigger = 'schedule'; Outcome = 'Run'; Steps = @(
            [pscustomobject]@{ Job = 'ptc'; State = 'Failed'; ErrorClass = 'throttled'; Error = 'x' }
            [pscustomobject]@{ Job = 'endpoint'; State = 'Failed'; ErrorClass = 'job-failed'; Error = 'the execution ended failed' }
            [pscustomobject]@{ Job = 'identity'; State = 'Skipped'; ErrorClass = 'needs-failed'; Error = 'needs ptc, which did not succeed' }
            [pscustomobject]@{ Job = 'publicip'; State = 'Skipped'; ErrorClass = 'needs-failed'; Error = 'needs endpoint, which did not succeed' }) }
        Test-SIJobFlowThrottledOnly -State $r | Should -BeFalse
        Get-SIJobFlowRunExitReason -State $r | Should -Be 'error'
        $calls = @(Get-SIGuardCallsForFlow -Result $r | Where-Object { $_.GuardId -eq 'flow.step.skipped' })
        $calls.Count | Should -Be 1
        $calls[0].Detail | Should -Match 'publicip'
        $calls[0].Detail | Should -Not -Match 'identity'
    }
    It 'the flow job exits 0 for a throttled-only run, 1 for a real failure (the runner''s exit rule)' {
        $src = Get-Content -LiteralPath ([IO.Path]::Combine($script:SIRoot, 'engine', 'flow', 'Invoke-SIJobFlowRun.ps1')) -Raw
        $src | Should -Match '-not \(Test-SIJobFlowThrottledOnly -State \$_\)'
        $src | Should -Match 'Get-SIJobFlowRunExitReason -State \$pipeResult'
        $src | Should -Match 'Get-SIJobFlowStepExitReason \$StepRec'
    }
    It 'the probe reads how the engine of THIS execution ended' {
        $kql = Get-SIJobFlowStartRecordQuery -Execution 'caj-si-ptc-e1' -StartedUtc ([datetime]::SpecifyKind([datetime]'2026-10-10T05:00:00', 'Utc')) -Engine 'privilege-tier-classifier'
        $kql | Should -Match "Throttled = countif\(.*Phase == 'End' and Execution == 'caj-si-ptc-e1'.*ExitReason\) == 'throttled'\)"
        $kql | Should -Match 'EndOther = countif'
        $p = New-SIJobFlowStartEvidence -Query { param($k) [pscustomobject]@{ Mine = 1; Stamped = 3; Throttled = 1; EndOther = 0 } }
        $p.Probe('ptc', 'caj-si-ptc-e1', [datetime]::UtcNow, [datetime]::UtcNow).EndReason | Should -Be 'throttled'
        $p = New-SIJobFlowStartEvidence -Query { param($k) [pscustomobject]@{ Mine = 1; Stamped = 3; Throttled = 1; EndOther = 1 } }
        $p.Probe('ptc', 'caj-si-ptc-e1', [datetime]::UtcNow, [datetime]::UtcNow).EndReason | Should -Be 'failed'
    }
}
