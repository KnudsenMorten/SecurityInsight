#Requires -Version 5.1
<#
    THE DAILY JOB FLOW -- ONLY THE PLATFORM GETS RE-RUN (#269, working rule 4). Found live 2026-10-05 (ring 1): step 11
    (asset-trend) ended Failed 31 s after it was started, with no console line, no run transcript and no run-health
    record -- its container died before PowerShell ran. The runner marked the step failed and the flow ended Failed.
    Now: a failed step is CLASSIFIED (Get-SIJobFlowFailureClass) from the engine's START run-health record of that
    execution (the Execution column every engine stamps), else the run transcript + the duration. A container that never
    ran the engine is started again once (after a pause); a real engine failure never is; a step that does not start the
    second time either fails as before and trips the guard flow.step.start-failed. Offline; fake ARM, fake clock, fake
    evidence. PS 5.1 and 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-JobFlow.ps1'))
    # #636: a new pipeline has the Risk Analysis Summary step switched OFF (SIv3-SummaryGroupings.Tests.ps1). The runner's
    # mechanics here use it as an ordinary step -- an install that switched it on -- so the default flow has every step on.
    $script:SINewDefaultFlowShipped = ${function:New-SIDefaultJobFlow}
    function New-SIDefaultJobFlow { $d = & $script:SINewDefaultFlowShipped @args; foreach ($s in @($d.Steps)) { $s.Enabled = $true }; $d }
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-Guard.ps1'))
    # the guard relief (owner 2026-10-11) turned the job-flow guards off by default; this suite proves the event they raise
    # when on, so it runs with every guard on as before -- SIv3-GuardSwitches proves the defaults
    function Test-SIGuardDefaultOn { param([string]$GuardId) $true }
    $script:Map = Get-SIJobFlowMap

    # ---- a fake ARM: each START of a job takes the next scripted outcome of that job (default Succeeded) ----
    function New-RetryArm {
        param([hashtable]$Outcomes = @{})
        $script:Arm = @{ Outcomes = $Outcomes; Starts = (New-Object System.Collections.Generic.List[string]); Exec = @{}; N = @{} }
        return {
            param($Method, $Path, $Body)
            if ($Method -eq 'POST' -and $Path -match '/jobs/caj-si-([a-z0-9\-]+)/start$') {
                $k = $Matches[1]
                $i = 0; if ($script:Arm.N.ContainsKey($k)) { $i = $script:Arm.N[$k] }; $script:Arm.N[$k] = $i + 1
                $name = 'caj-si-{0}-e{1}' -f $k, ($i + 1)
                $script:Arm.Starts.Add($k)
                $list = @(); if ($script:Arm.Outcomes.ContainsKey($k)) { $list = @($script:Arm.Outcomes[$k]) }
                $script:Arm.Exec[$name] = $(if ($i -lt $list.Count) { $list[$i] } else { 'Succeeded' })
                return [pscustomobject]@{ name = $name }
            }
            if ($Method -eq 'GET' -and $Path -match '/executions/([a-z0-9\-]+)$') { return [pscustomobject]@{ properties = [pscustomobject]@{ status = $script:Arm.Exec[$Matches[1]] } } }
            throw "unexpected ARM call $Method $Path"
        }
    }
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-10-05T05:00:00', 'Utc')
    $script:NowSb = { $script:Clock }
    $script:SleepSb = { param($s) $script:Sleeps.Add([int]$s); $script:Clock = $script:Clock.AddSeconds($s) }
    $script:Logs = New-Object System.Collections.Generic.List[string]
    $script:LogSb = { param($l, $m) $script:Logs.Add(('{0} {1}' -f $l, $m)) }
    # the evidence seam: per execution name, what the store and the run logs say; every probe is recorded with its clock
    function New-Evidence {
        param([hashtable]$Rows = @{}, [hashtable]$Logs = @{}, [switch]$Throw)
        $script:Ev = @{ Rows = $Rows; Logs = $Logs; Throw = [bool]$Throw; Probes = (New-Object System.Collections.Generic.List[object]) }
        return {
            param($Job, $Execution, $StartedUtc, $EndedUtc)
            $script:Ev.Probes.Add([pscustomobject]@{ Job = $Job; Execution = $Execution; At = $script:Clock })
            if ($script:Ev.Throw) { throw 'the workspace could not be read' }
            $r = $null; if ($script:Ev.Rows.ContainsKey($Execution)) { $r = $script:Ev.Rows[$Execution] }
            $t = $null; if ($script:Ev.Logs.ContainsKey($Execution)) { $t = $script:Ev.Logs[$Execution] }
            [pscustomobject]@{ HasStartRecord = $r; HasTranscript = $t }
        }
    }
    function Invoke-RetryFlow {
        param([string[]]$Jobs, $Arm, $Evidence, [int]$Retries = 1)
        $script:Clock = $script:T0; $script:Sleeps = New-Object System.Collections.Generic.List[int]; $script:Logs.Clear()
        $d = New-SIDefaultJobFlow -Installed $Jobs -Map $script:Map
        # #306: the risk trend left the default pipeline -- a test that uses it adds it as a step of its stage (Collect, last)
        foreach ($j in @($Jobs | Where-Object { @($d.Steps.Job) -notcontains $_ })) { $d.Steps = @($d.Steps) + @(New-SIJobFlowStep -Job $j -Stage (Get-SIPipelineStageOf -Job $j -Map $script:Map)) }
        $p = @{ Definition = $d; Seams = (New-SIJobFlowArmSeams -SubscriptionId 'sub' -ResourceGroup 'rg' -Arm $Arm); Save = { param($s) $script:Saved = (ConvertTo-SIJobFlowRunJson -State $s) }
                Now = $script:NowSb; Sleep = $script:SleepSb; Log = $script:LogSb; Map = $script:Map; PollSeconds = 30; Previous = $null; Force = $true; StartRetries = $Retries }
        if ($Evidence) { $p.StartEvidence = $Evidence }
        Invoke-SIJobFlow @p
    }
    function Get-Step { param($State, [string]$Job) @($State.Steps | Where-Object { $_.Job -eq $Job })[0] }
}

Describe 'classifying a failed step (pure)' {
    It 'no START record of the execution, a short run: never started -- retried once' {
        $c = Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $false -HasTranscript $false -DurationSeconds 31 -Attempts 1 -Retries 1
        $c.Class | Should -Be 'never-started'; $c.Retry | Should -BeTrue; $c.Signal | Should -Be 'transcript+duration+run-health'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $false -HasTranscript $false -DurationSeconds 31 -Attempts 2 -Retries 1).Retry | Should -BeFalse -Because 'the retry count is spent'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $false -HasTranscript $false -DurationSeconds 31 -Attempts 1 -Retries 0).Retry | Should -BeFalse -Because 'retries can be turned off'
    }
    It 'any evidence that the engine ran is a real failure -- never retried' {
        foreach ($e in @(@{ R = $true; T = $null }, @{ R = $true; T = $false }, @{ R = $false; T = $true }, @{ R = $null; T = $true })) {
            $c = Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $e.R -HasTranscript $e.T -DurationSeconds 20
            $c.Class | Should -Be 'engine-failed'; $c.Retry | Should -BeFalse
        }
    }
    It 'the store cannot tell: the fallback is no run transcript AND a short run' {
        $c = Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $false -DurationSeconds 31
        $c.Class | Should -Be 'never-started'; $c.Signal | Should -Be 'transcript+duration'; $c.Retry | Should -BeTrue
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $false -DurationSeconds 600).Class | Should -Be 'unknown' -Because 'a long run is not a start failure'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $null -DurationSeconds 31).Class | Should -Be 'unknown' -Because 'nothing could be read: unsure is never retried'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $false -DurationSeconds 121).Retry | Should -BeFalse -Because 'the default bound is 120 s when the store cannot tell'
    }
    It 'no run log AND no START row is never-started whatever the duration (live 2026-10-23: pods held unstarted 314 s / 377 s)' {
        $c = Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $false -HasTranscript $false -DurationSeconds 377 -Attempts 1 -Retries 1
        $c.Class | Should -Be 'never-started'; $c.Retry | Should -BeTrue
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $false -HasTranscript $false -DurationSeconds 314 -Attempts 1 -Retries 1).Retry | Should -BeTrue
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $false -HasTranscript $false -DurationSeconds 377 -Attempts 2 -Retries 1).Retry | Should -BeFalse -Because 'the retry count still holds'
        $s = Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $true -HasTranscript $false -DurationSeconds 377 -Attempts 1 -Retries 1
        $s.Class | Should -Be 'engine-failed'; $s.Retry | Should -BeFalse -Because 'a step that recorded its start is never started again'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $false -HasTranscript $true -DurationSeconds 377).Retry | Should -BeFalse -Because 'a run log means it ran'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $false -HasTranscript $null -DurationSeconds 377).Retry | Should -BeFalse -Because 'unreadable run logs stay unsure'
    }
    It 'the run-health store alone is NEVER enough (ring 1 2026-10-05: container runs were not saving run health at all)' {
        # "no START row" with the run logs unknown: not retried -- an empty store would otherwise retry every real failure
        $c = Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $false -HasTranscript $null -DurationSeconds 31
        $c.Class | Should -Be 'unknown'; $c.Retry | Should -BeFalse
        # the store cannot be read / holds no row of this engine, the run logs cannot be read: unknown
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $null -DurationSeconds 31).Retry | Should -BeFalse
    }
    It 'THE PLATFORM SAYS THE CONTAINER NEVER STARTED (live 2026-11-13, internal: correlation 158 s / 187 s, store cannot tell) -> never-started, retried, any duration' {
        $c = Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $false -DurationSeconds 158 -Attempts 1 -Retries 1 -HasContainerStarted $false
        $c.Class | Should -Be 'never-started'; $c.Retry | Should -BeTrue; $c.Signal | Should -Be 'platform-events'
        $c.Why | Should -Match 'Azure scheduled the step''s container but never started it'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $null -DurationSeconds 187 -HasContainerStarted $false).Class | Should -Be 'never-started' -Because 'the platform''s own word needs no run-log read'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $false -DurationSeconds 158 -Attempts 2 -Retries 1 -HasContainerStarted $false).Retry | Should -BeFalse -Because 'the retry count still holds'
    }
    It 'the engine''s own evidence still wins over the platform events; a started container (or no events) keeps the old rule' {
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $true -HasTranscript $false -DurationSeconds 158 -HasContainerStarted $false).Class | Should -Be 'engine-failed'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $true -DurationSeconds 158 -HasContainerStarted $false).Class | Should -Be 'engine-failed'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $false -DurationSeconds 158 -HasContainerStarted $true).Class | Should -Be 'unknown' -Because 'the container started: the 120 s rule as before'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $false -DurationSeconds 158).Class | Should -Be 'unknown' -Because 'no platform events: as before'
        (Get-SIJobFlowFailureClass -ErrorClass 'timeout' -HasStartRecord $null -HasTranscript $false -DurationSeconds 5 -HasContainerStarted $false).Class | Should -Be 'not-applicable'
    }
    It 'the platform-event query: this execution''s replicas, the step''s window; a name that is not an execution never reaches a query' {
        $q = Get-SIJobFlowContainerStartQuery -Execution 'caj-si-asset-correlation-uxf5u22' -StartedUtc ([datetime]::SpecifyKind([datetime]'2026-11-13T02:20:57', 'Utc')) -EndedUtc ([datetime]::SpecifyKind([datetime]'2026-11-13T02:23:35', 'Utc'))
        $q | Should -Match "^ContainerAppSystemLogs \|"
        $q | Should -Match "ReplicaName startswith 'caj-si-asset-correlation-uxf5u22-'"
        $q | Should -Match 'datetime\(2026-11-13T02:18:57Z\) \.\. datetime\(2026-11-13T02:28:35Z\)'
        $q | Should -Match "Started = countif\(Reason == 'ContainerStarted' and ReplicaName startswith 'caj-si-asset-correlation-uxf5u22-'\)"
        # reviews 2026-11-13: the end is THIS execution's -- its own pod's end, or a backoff event of the job that NAMES this
        # execution; when that end happened (EndAt) decides whether the answer is settled
        $q | Should -Match "OwnEnd = countif\(Reason == 'PodDeletion' and ReplicaName startswith 'caj-si-asset-correlation-uxf5u22-'\)"
        $q | Should -Match "JobEnd = countif\(Reason == 'BackoffLimitExceeded' and JobName == 'caj-si-asset-correlation' and Ex == 'caj-si-asset-correlation-uxf5u22'\)"
        $q | Should -Match ([regex]::Escape("EndAt = maxif(TimeGenerated, (Reason == 'PodDeletion' and ReplicaName startswith 'caj-si-asset-correlation-uxf5u22-') or (Reason == 'BackoffLimitExceeded' and JobName == 'caj-si-asset-correlation' and Ex == 'caj-si-asset-correlation-uxf5u22'))"))
        $q | Should -Match ([regex]::Escape('Ended = iff(OwnEnd > 0 or JobEnd > 0, 1, 0)'))
        $q | Should -Not -Match 'Others' -Because 'a backoff event that names no execution is never this execution''s end (an earlier one''s inside the window ended it)'
        Get-SIJobFlowContainerStartQuery -Execution "x' or 1==1 //" -StartedUtc $script:T0 -EndedUtc $script:T0 | Should -BeNullOrEmpty
    }
    It 'reading the answer: scheduled and never started -> $false; started -> $true; nothing (not readable / not delivered yet) -> $null, never "never started"' {
        $now = [datetime]::SpecifyKind([datetime]'2026-11-13T03:00:00', 'Utc')
        ConvertFrom-SIJobFlowContainerStartRows -NowUtc $now -Rows @([pscustomobject]@{ Scheduled = 1; Started = 0; Ended = 1; EndAt = '2026-11-13T02:40:00Z' }) | Should -BeFalse -Because 'scheduled, never started, and this execution''s end arrived 20 minutes ago: settled'
        ConvertFrom-SIJobFlowContainerStartRows -NowUtc $now -Rows @([pscustomobject]@{ Scheduled = 1; Started = 0; Ended = 1; EndAt = '2026-11-13T02:58:00Z' }) | Should -BeNullOrEmpty -Because 'the end is 2 minutes old: a ContainerStarted may still be on its way'
        ConvertFrom-SIJobFlowContainerStartRows -NowUtc $now -Rows @([pscustomobject]@{ Scheduled = 1; Started = 0; Ended = 1 }) | Should -BeNullOrEmpty -Because 'an end with no time is never settled'
        ConvertFrom-SIJobFlowContainerStartRows -Rows @([pscustomobject]@{ Scheduled = 1; Started = 0; Ended = 0 }) | Should -BeNullOrEmpty -Because 'review 2026-11-13: the end not delivered yet -- a ContainerStarted may still be on its way'
        ConvertFrom-SIJobFlowContainerStartRows -Rows @([pscustomobject]@{ Scheduled = 1; Started = 1 }) | Should -BeTrue
        ConvertFrom-SIJobFlowContainerStartRows -Rows @([pscustomobject]@{ Scheduled = 0; Started = 0 }) | Should -BeNullOrEmpty
        ConvertFrom-SIJobFlowContainerStartRows -Rows @() | Should -BeNullOrEmpty
        ConvertFrom-SIJobFlowContainerStartRows -Rows @([pscustomobject]@{ Mine = 0; Stamped = 3 }) | Should -BeNullOrEmpty -Because 'another query''s row is no answer'
    }
    It 'a timeout, a start ARM refused, an interruption are not start failures of the container' {
        foreach ($k in 'timeout', 'start-failed', 'interrupted', '') {
            $c = Get-SIJobFlowFailureClass -ErrorClass $k -HasStartRecord $false -HasTranscript $false -DurationSeconds 5
            $c.Class | Should -Be 'not-applicable'; $c.Retry | Should -BeFalse
        }
    }
}

Describe 'the runner: a step whose container never started' {
    It 'is started again once after the pause; it then succeeds and the flow ends Succeeded with 2 attempts' {
        $arm = New-RetryArm -Outcomes @{ 'asset-trend' = @('Failed', 'Succeeded') }
        $ev = New-Evidence -Rows @{ 'caj-si-asset-trend-e1' = $false } -Logs @{ 'caj-si-asset-trend-e1' = $false }
        $r = Invoke-RetryFlow -Jobs @('ptc', 'risk-analysis', 'asset-trend') -Arm $arm -Evidence $ev
        $r.State | Should -Be 'Succeeded'
        $s = Get-Step $r 'asset-trend'
        $s.State | Should -Be 'Success'
        $s.Attempts | Should -Be 2
        $s.Execution | Should -Be 'caj-si-asset-trend-e2'
        $s.RetryReason | Should -Match "the step's container did not start \(an Azure platform problem\); it was started again"
        $s.RetryReason | Should -Match 'caj-si-asset-trend-e1'
        @($script:Arm.Starts | Where-Object { $_ -eq 'asset-trend' }).Count | Should -Be 2
        (Get-Step $r 'ptc').Attempts | Should -Be 1
        # the probe ran AFTER the pause (the engine's records have time to arrive), once
        $script:Ev.Probes.Count | Should -Be 1
        $script:Sleeps | Should -Contain 60
        ($script:Logs -join "`n") | Should -Match 'it was started again'
        # the record keeps it (the file / blob store)
        $back = ConvertFrom-SIJobFlowRunJson -Json $script:Saved
        (Get-Step $back 'asset-trend').Attempts | Should -Be 2
        (Get-Step $back 'asset-trend').RetryReason | Should -Match 'started again'
        @(Get-SIGuardCallsForFlow -Result $r).Count | Should -Be 0 -Because 'a retry that worked trips no guard'
    }
    It 'the fallback (the store cannot tell, no run log, a short run) retries too' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $ev = New-Evidence -Rows @{ 'caj-si-endpoint-e1' = $null } -Logs @{ 'caj-si-endpoint-e1' = $false }
        $r = Invoke-RetryFlow -Jobs @('endpoint') -Arm $arm -Evidence $ev
        $r.State | Should -Be 'Succeeded'; (Get-Step $r 'endpoint').Attempts | Should -Be 2
    }
    It 'does not start the second time either: the step fails as before, dependents are skipped, the guard fires (halted)' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Failed') }
        $ev = New-Evidence -Rows @{ 'caj-si-endpoint-e1' = $false; 'caj-si-endpoint-e2' = $false } -Logs @{ 'caj-si-endpoint-e1' = $false; 'caj-si-endpoint-e2' = $false }
        $r = Invoke-RetryFlow -Jobs @('endpoint', 'publicip') -Arm $arm -Evidence $ev
        $r.State | Should -Be 'Failed'
        $s = Get-Step $r 'endpoint'
        $s.State | Should -Be 'Failed'; $s.ErrorClass | Should -Be 'never-started'; $s.Attempts | Should -Be 2
        $s.Error | Should -Match 'also not when it was started again \(2 attempts\)'
        @($script:Arm.Starts | Where-Object { $_ -eq 'endpoint' }).Count | Should -Be 2 -Because 'once retried, never a third time'
        (Get-Step $r 'publicip').State | Should -Be 'Skipped'
        $calls = @(Get-SIGuardCallsForFlow -Result $r)
        $g = @($calls | Where-Object { $_.GuardId -eq 'flow.step.start-failed' })
        $g.Count | Should -Be 1
        $g[0].Outcome | Should -Be 'halted'
        $g[0].Subject | Should -Be 'endpoint'
        $g[0].Detail | Should -Match 'endpoint \(2 attempts\)'
        $g[0].Detail | Should -Match '1 job\(s\) after it were skipped'
        @($calls.GuardId) | Should -Contain 'flow.step.skipped'
        # the guard id is in the closed catalog: the event is recorded (mail / telemetry / ticket go through it)
        $call = $g[0]
        $ev2 = Send-SIGuardEvent @call -RunId 'flow-1' -Engine 'flow' -Globals @{ MailTo = 'ops@x.test'; SI_Telemetry_Enabled = $false } -RunHealth { } `
                   -MailTransport { param($to, $s, $h, $p) $script:Mail = $s; $true } -StateStore (New-SIGuardMemoryStateStore) -Log { param($l, $m) }
        $ev2.Status | Should -Be 'recorded'
        $ev2.Event.Severity | Should -Be 'critical'
        $ev2.Mail.State | Should -Be 'sent'
    }
    It 'does not start twice and nothing needs it: the guard says skipped (a warning)' {
        $arm = New-RetryArm -Outcomes @{ 'asset-trend' = @('Failed', 'Failed') }
        $ev = New-Evidence -Rows @{ 'caj-si-asset-trend-e1' = $false; 'caj-si-asset-trend-e2' = $false } -Logs @{ 'caj-si-asset-trend-e1' = $false; 'caj-si-asset-trend-e2' = $false }
        $r = Invoke-RetryFlow -Jobs @('ptc', 'risk-analysis', 'asset-trend') -Arm $arm -Evidence $ev
        $g = @(Get-SIGuardCallsForFlow -Result $r | Where-Object { $_.GuardId -eq 'flow.step.start-failed' })
        $g[0].Outcome | Should -Be 'skipped'
        (Get-SIGuardSeverity -Outcome $g[0].Outcome) | Should -Be 'warning'
    }
}

Describe 'the runner: everything else is a real failure and is never retried' {
    It 'an engine failure (its START record exists) is NOT started again' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $ev = New-Evidence -Rows @{ 'caj-si-endpoint-e1' = $true }
        $r = Invoke-RetryFlow -Jobs @('endpoint', 'publicip') -Arm $arm -Evidence $ev
        $r.State | Should -Be 'Failed'
        $s = Get-Step $r 'endpoint'
        $s.State | Should -Be 'Failed'; $s.ErrorClass | Should -Be 'job-failed'; $s.Attempts | Should -Be 1; $s.RetryReason | Should -BeNullOrEmpty
        @($script:Arm.Starts | Where-Object { $_ -eq 'endpoint' }).Count | Should -Be 1
        (Get-Step $r 'publicip').State | Should -Be 'Skipped' -Because 'dependents are handled as before'
        @(Get-SIGuardCallsForFlow -Result $r | Where-Object { $_.GuardId -eq 'flow.step.start-failed' }).Count | Should -Be 0
    }
    It '3.0.30: an engine failure with its own run log is named by the LAST ERROR line of that log, classified (never a bare job-failed)' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $p = @{ Definition = (New-SIDefaultJobFlow -Installed @('endpoint') -Map $script:Map); Seams = (New-SIJobFlowArmSeams -SubscriptionId 'sub' -ResourceGroup 'rg' -Arm $arm)
                Save = { param($s) }; Now = $script:NowSb; Sleep = $script:SleepSb; Log = $script:LogSb; Map = $script:Map; PollSeconds = 30; Previous = $null; Force = $true; StartRetries = 1
                StartEvidence = (New-Evidence -Rows @{ 'caj-si-endpoint-e1' = $true } -Logs @{ 'caj-si-endpoint-e1' = $true }) }
        $script:Clock = $script:T0; $script:Sleeps = New-Object System.Collections.Generic.List[int]; $script:Logs.Clear()
        $script:LogReads = New-Object System.Collections.Generic.List[string]
        $p.StepLogs = { param($Job, $StartedUtc, $EndedUtc)
            $script:LogReads.Add([string]$Job)
            [pscustomobject]@{ Name = 'run-logs/endpoint/endpoint_container_20261005T050000Z.log'; Lines = @(
                '[INFO] endpoint: reading',
                '[ERROR] endpoint: page 2 failed once: 429 Too Many Requests -- retried',
                '[ERROR] endpoint: the step failed: SQL error 40544 (line 1): The database ''sqldb-si'' has reached its size quota.') } }
        $r = Invoke-SIJobFlow @p
        $s = Get-Step $r 'endpoint'
        $s.State | Should -Be 'Failed'
        $s.ErrorClass | Should -Be 'database-full' -Because 'the LAST ERROR line names the error, not the first'
        $s.Error | Should -Match '^the execution ended failed: \[ERROR\] endpoint: the step failed: SQL error 40544'
        $s.Attempts | Should -Be 1 -Because 'an engine failure is still never started again'
        @($script:LogReads).Count | Should -Be 1
        (Get-SIJobFlowStepFailure -Step $s -LogLines $null).ErrorClass | Should -Be 'database-full' -Because 'the pipeline''s report carries the step''s class'
    }
    It '3.0.30: a log with nothing the classifier knows, or no log, leaves the step as it was' {
        (Get-SIJobFlowLogErrorClass -Lines @('[INFO] all fine', '[ERROR] something odd happened')).ErrorClass | Should -Be ''
        (Get-SIJobFlowLogErrorClass -Lines @()).ErrorClass | Should -Be ''
        $x = Get-SIJobFlowLogErrorClass -Lines @('[ERROR] identity: Graph refused /users: Response status code does not indicate success: 403 (Forbidden). Authorization_RequestDenied graph.microsoft.com', '[INFO] done')
        $x.ErrorClass | Should -Be 'graph-403'; $x.Line | Should -Match '^\[ERROR\] identity: Graph refused'
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $p = @{ Definition = (New-SIDefaultJobFlow -Installed @('endpoint') -Map $script:Map); Seams = (New-SIJobFlowArmSeams -SubscriptionId 'sub' -ResourceGroup 'rg' -Arm $arm)
                Save = { param($s) }; Now = $script:NowSb; Sleep = $script:SleepSb; Log = $script:LogSb; Map = $script:Map; PollSeconds = 30; Previous = $null; Force = $true; StartRetries = 1
                StartEvidence = (New-Evidence -Rows @{ 'caj-si-endpoint-e1' = $true }); StepLogs = { param($Job, $StartedUtc, $EndedUtc) $null } }
        $script:Clock = $script:T0; $script:Sleeps = New-Object System.Collections.Generic.List[int]; $script:Logs.Clear()
        $s = Get-Step (Invoke-SIJobFlow @p) 'endpoint'
        $s.ErrorClass | Should -Be 'job-failed'; $s.Error | Should -Be 'the execution ended failed'
    }
    It 'the tier classifier SKIPPED its run (no catalog at all) and ended successfully: its run log says so, the step is skipped, everything after it runs, the run succeeds (owner 2026-11-11)' {
        foreach ($case in @(@{ Says = $true }, @{ Says = $false })) {
            $arm = New-RetryArm
            $says = [bool]$case.Says
            $p = @{ Definition = (New-SIDefaultJobFlow -Installed @('ptc', 'identity') -Map $script:Map); Seams = (New-SIJobFlowArmSeams -SubscriptionId 'sub' -ResourceGroup 'rg' -Arm $arm)
                    Save = { param($s) }; Now = $script:NowSb; Sleep = $script:SleepSb; Log = $script:LogSb; Map = $script:Map; PollSeconds = 30; Previous = $null; Force = $true; StartRetries = 1
                    StartEvidence = (New-Evidence) }
            $script:Clock = $script:T0; $script:Sleeps = New-Object System.Collections.Generic.List[int]; $script:Logs.Clear()
            $script:LogReads = New-Object System.Collections.Generic.List[string]
            $script:Says = $says
            $p.StepLogs = { param($Job, $StartedUtc, $EndedUtc)
                $script:LogReads.Add([string]$Job)
                $l = @('[INFO] reading the role definitions')
                if ($script:Says) { $l += '[WARN] The daily classified tier catalog could not be downloaded, and this install has no tier catalog of its own yet: the step is skipped -- the collections use the catalog shipped with SecurityInsight, and the next run tries again.' }
                [pscustomobject]@{ Name = 'run-logs/privilege-tier-classifier/x.log'; Lines = $l } }
            $r = Invoke-SIJobFlow @p
            $s = Get-Step $r 'ptc'
            if ($says) {
                $s.State | Should -Be 'Skipped'; $s.ErrorClass | Should -Be 'classifier-skipped'
                $s.Error | Should -Match '^the tier classifier skipped this run'
            } else { $s.State | Should -Be 'Success' }
            (Get-Step $r 'identity').State | Should -Be 'Success'
            $r.State | Should -Be 'Succeeded'
            @($script:LogReads) | Should -Be @('ptc') -Because 'only the classifier''s successful step log is read, once'
            $script:Ev.Probes.Count | Should -Be 0 -Because 'a run that succeeds is never probed'
        }
    }
    It '3.0.30 WIRING: the container runner hands its step log reader to the step close' {
        $src = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'engine', 'flow', 'Invoke-SIJobFlowRun.ps1'))
        $src | Should -Match ([regex]::Escape('$retry.StepLogs = $stepLogs'))
    }
    It 'a run log in the window is a real failure too' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $r = Invoke-RetryFlow -Jobs @('endpoint') -Arm $arm -Evidence (New-Evidence -Rows @{ 'caj-si-endpoint-e1' = $null } -Logs @{ 'caj-si-endpoint-e1' = $true })
        (Get-Step $r 'endpoint').Attempts | Should -Be 1; $r.State | Should -Be 'Failed'
    }
    It 'an EMPTY run-health store (no row of the engine) with the run logs unreadable is UNKNOWN: not retried' {
        $arm = New-RetryArm -Outcomes @{ 'asset-trend' = @('Failed', 'Succeeded') }
        # the probe over a store with no rows at all (Mine 0, Stamped 0) and a storage listing that fails
        $p = New-SIJobFlowStartEvidence -Query { param($k) [pscustomobject]@{ Mine = 0; Stamped = 0 } } -ListBlobs { param($pre) throw 'AuthorizationPermissionMismatch' }
        $script:EmptyProbe = $p
        $r = Invoke-RetryFlow -Jobs @('ptc', 'risk-analysis', 'asset-trend') -Arm $arm -Evidence { param($j, $e, $s, $t) $script:EmptyProbe.Probe($j, $e, $s, $t) }
        $s = Get-Step $r 'asset-trend'
        $s.State | Should -Be 'Failed'; $s.ErrorClass | Should -Be 'job-failed'; $s.Attempts | Should -Be 1
        @($script:Arm.Starts | Where-Object { $_ -eq 'asset-trend' }).Count | Should -Be 1
        $r.State | Should -Be 'Failed'
    }
    It 'a store that says "no START row" while the run logs are unknown is not enough either' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $r = Invoke-RetryFlow -Jobs @('endpoint') -Arm $arm -Evidence (New-Evidence -Rows @{ 'caj-si-endpoint-e1' = $false })
        (Get-Step $r 'endpoint').Attempts | Should -Be 1; $r.State | Should -Be 'Failed'
    }
    It 'WIRING (live 2026-11-13): the same unsure case, but the PLATFORM says the container never started -> started again, the run succeeds' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $r = Invoke-RetryFlow -Jobs @('endpoint') -Arm $arm -Evidence { param($j, $e, $s, $t) [pscustomobject]@{ HasStartRecord = $false; HasTranscript = $null; HasContainerStarted = $false } }
        $st = Get-Step $r 'endpoint'
        $st.Attempts | Should -Be 2; $st.State | Should -Be 'Success'; $r.State | Should -Be 'Succeeded'
        ($script:Logs -join "`n") | Should -Match 'Azure scheduled the step''s container but never started it'
    }
    It 'a probe that cannot read anything is unsure: not retried, said' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $r = Invoke-RetryFlow -Jobs @('endpoint') -Arm $arm -Evidence (New-Evidence -Throw)
        (Get-Step $r 'endpoint').Attempts | Should -Be 1; $r.State | Should -Be 'Failed'
        ($script:Logs -join "`n") | Should -Match 'whether it started could not be checked'
    }
    It 'without a probe (the VM flow) nothing is retried and nothing waits' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $r = Invoke-RetryFlow -Jobs @('endpoint') -Arm $arm -Evidence $null
        (Get-Step $r 'endpoint').Attempts | Should -Be 1; $r.State | Should -Be 'Failed'
        $script:Sleeps | Should -Not -Contain 60
    }
    It 'a run that succeeds is never probed' {
        $arm = New-RetryArm
        $null = Invoke-RetryFlow -Jobs @('endpoint', 'publicip') -Arm $arm -Evidence (New-Evidence)
        $script:Ev.Probes.Count | Should -Be 0
    }
}

Describe 'the platform''s word must be SETTLED: Azure''s events arrive late (review 2026-11-13)' {
    BeforeAll {
        # the real probe over a scripted workspace: the run-health store cannot tell (no stamped row), no run-log listing
        # (unknown), and the container events of the execution answer, call by call, the next scripted row (the last repeats).
        # A row's EndAt is minutes relative to the run's start (T0); $null = no end event delivered.
        function New-PlatformProbe {
            param([object[]]$Answers)
            $script:Plat = @{ Answers = @($Answers); Calls = (New-Object System.Collections.Generic.List[object]) }
            $p = New-SIJobFlowStartEvidence -Query {
                param($k)
                if ($k -notmatch '^ContainerAppSystemLogs') { return [pscustomobject]@{ Mine = 0; Stamped = 0 } }
                $i = [Math]::Min($script:Plat.Calls.Count, $script:Plat.Answers.Count - 1)
                $script:Plat.Calls.Add($script:Clock)
                $a = $script:Plat.Answers[$i]
                $row = [ordered]@{ Scheduled = 1; Started = [int]$a.Started; OwnEnd = 0; JobEnd = 0; Ended = 0; EndAt = $null }
                if ($null -ne $a.EndMin) { $row.OwnEnd = 1; $row.Ended = 1; $row.EndAt = $script:T0.AddMinutes([double]$a.EndMin).ToString('yyyy-MM-ddTHH:mm:ssZ') }
                [pscustomobject]$row
            }
            $script:PlatProbe = $p
            { param($j, $e, $s, $t, $n) $script:PlatProbe.Probe($j, $e, $s, $t, $n) }
        }
        function Invoke-PlatFlow {
            param($Arm, $Evidence, [scriptblock]$Running, [scriptblock]$StopWorkers)
            $script:Clock = $script:T0; $script:Sleeps = New-Object System.Collections.Generic.List[int]; $script:Logs.Clear()
            $script:SavedStates = New-Object System.Collections.Generic.List[string]
            $p = @{ Definition = (New-SIDefaultJobFlow -Installed @('endpoint') -Map $script:Map); Seams = (New-SIJobFlowArmSeams -SubscriptionId 'sub' -ResourceGroup 'rg' -Arm $Arm)
                    Save = { param($s) $script:SavedStates.Add([string](@($s.Steps | Where-Object { $_.Job -eq 'endpoint' })[0].State)) }
                    Now = $script:NowSb; Sleep = $script:SleepSb; Log = $script:LogSb; Map = $script:Map; PollSeconds = 30; Previous = $null; Force = $true; StartRetries = 1; StartEvidence = $Evidence }
            if ($Running) { $p.Running = $Running }
            if ($StopWorkers) { $p.StopWorkers = $StopWorkers }
            Invoke-SIJobFlow @p
        }
    }
    It 'the contract values are named: 15 minutes of delivery lag, 30 minutes at most, the wake-up check waits longer than that' {
        $script:SIJobFlow.ContainerEventsLagMinutes | Should -Be 15
        $script:SIJobFlow.StartDecideMaxMinutes | Should -Be 30
        $script:SIJobFlow.EndedGraceMinutes | Should -BeGreaterThan $script:SIJobFlow.StartDecideMaxMinutes
    }
    It 'reading the events (pure): started / settled never-started / not known yet / nothing to wait for' {
        $now = [datetime]::SpecifyKind([datetime]'2026-11-13T03:00:00', 'Utc')
        $r = Read-SIJobFlowContainerStartRows -NowUtc $now -Rows @([pscustomobject]@{ Scheduled = 1; Started = 0; Ended = 1; EndAt = '2026-11-13T02:58:00Z' })
        $r.Started | Should -BeNullOrEmpty; $r.Pending | Should -BeTrue -Because 'PodDeletion 2 minutes old and no ContainerStarted: not known yet'
        $r = Read-SIJobFlowContainerStartRows -NowUtc $now -Rows @([pscustomobject]@{ Scheduled = 1; Started = 0; Ended = 1; EndAt = ([datetime]::SpecifyKind([datetime]'2026-11-13T02:40:00', 'Utc')) })
        $r.Started | Should -BeFalse; $r.Pending | Should -BeFalse -Because 'PodDeletion 20 minutes old and still no ContainerStarted: settled'
        (Read-SIJobFlowContainerStartRows -NowUtc $now -Rows @([pscustomobject]@{ Scheduled = 1; Started = 0; Ended = 1; EndAt = '2026-11-13T02:45:00Z' })).Started | Should -BeFalse -Because 'exactly 15 minutes'
        (Read-SIJobFlowContainerStartRows -NowUtc $now -Rows @([pscustomobject]@{ Scheduled = 1; Started = 0; Ended = 1; EndAt = 'not a time' })).Pending | Should -BeTrue -Because 'an end time that cannot be read is never settled'
        $r = Read-SIJobFlowContainerStartRows -NowUtc $now -Rows @([pscustomobject]@{ Scheduled = 1; Started = 1; Ended = 1; EndAt = '2026-11-13T02:58:00Z' })
        $r.Started | Should -BeTrue; $r.Pending | Should -BeFalse
        $r = Read-SIJobFlowContainerStartRows -NowUtc $now -Rows @([pscustomobject]@{ Scheduled = 0; Started = 0; Ended = 0 })
        $r.Started | Should -BeNullOrEmpty; $r.Pending | Should -BeFalse -Because 'no event of the execution: nothing to wait for (as before)'
    }
    It 'an EARLIER execution''s BackoffLimitExceeded that does not name this execution is not this execution''s end' {
        # the query counts a backoff only by this execution's name; what it then answers for this execution: no end -> not
        # settled -> never "never started"
        $q = Get-SIJobFlowContainerStartQuery -Execution 'caj-si-endpoint-e2' -StartedUtc $script:T0 -EndedUtc $script:T0.AddMinutes(3)
        $q | Should -Match ([regex]::Escape("JobEnd = countif(Reason == 'BackoffLimitExceeded' and JobName == 'caj-si-endpoint' and Ex == 'caj-si-endpoint-e2')"))
        $q | Should -Not -Match ([regex]::Escape("countif(Reason == 'BackoffLimitExceeded' and JobName == 'caj-si-endpoint')"))
        $r = Read-SIJobFlowContainerStartRows -NowUtc $script:T0.AddHours(1) -Rows @([pscustomobject]@{ Scheduled = 1; Started = 0; OwnEnd = 0; JobEnd = 0; Ended = 0; EndAt = $null })
        $r.Started | Should -BeNullOrEmpty; $r.Pending | Should -BeTrue
    }
    It 'the class (pure): not settled is "deciding" only where the platform''s answer would decide; past the bound it is as before' {
        $c = Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $null -DurationSeconds 158 -ContainerStartPending $true
        $c.Class | Should -Be 'deciding'; $c.Retry | Should -BeFalse; $c.Why | Should -Match 'not known yet'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $false -DurationSeconds 600 -ContainerStartPending $true).Class | Should -Be 'deciding'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $true -HasTranscript $null -DurationSeconds 158 -ContainerStartPending $true).Class | Should -Be 'engine-failed' -Because 'the engine''s own record decides at once'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $false -HasTranscript $false -DurationSeconds 600 -ContainerStartPending $true).Class | Should -Be 'never-started' -Because 'both signals known absent decide as before'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $false -DurationSeconds 30 -ContainerStartPending $true).Class | Should -Be 'never-started' -Because 'a short run with no run log decides as before'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $null -HasTranscript $null -DurationSeconds 158 -ContainerStartPending $false).Class | Should -Be 'unknown'
    }
    It 'ContainerStarted ARRIVES LATE: the first read (scheduled, PodDeletion 2 min old, no ContainerStarted) is "not known yet" -- no restart; the next read says started -- no restart' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $ev = New-PlatformProbe -Answers @(@{ Started = 0; EndMin = -1 }, @{ Started = 1; EndMin = -1 })
        $r = Invoke-PlatFlow -Arm $arm -Evidence $ev
        $s = Get-Step $r 'endpoint'
        @($script:Arm.Starts | Where-Object { $_ -eq 'endpoint' }).Count | Should -Be 1 -Because 'it really ran: never a second run (the close-loop mail would go out twice)'
        $s.Attempts | Should -Be 1
        $s.State | Should -Be 'Failed'; $s.ErrorClass | Should -Be 'job-failed'
        $script:Plat.Calls.Count | Should -Be 2
        ($script:Plat.Calls[1] - $script:Plat.Calls[0]).TotalSeconds | Should -BeGreaterOrEqual $script:SIJobFlow.StartDecideRecheckSeconds -Because 'asked again at most every 2 minutes'
        ($script:Logs -join "`n") | Should -Match 'is not known yet'
        # while it was not known, the step was never recorded failed
        $saved = @($script:SavedStates)
        $firstFailed = [array]::IndexOf($saved, 'Failed')
        $firstFailed | Should -BeGreaterThan 3 -Because 'held Running through the passes that waited'
        @($saved[$firstFailed..($saved.Count - 1)] | Where-Object { $_ -ne 'Failed' }).Count | Should -Be 0 -Because 'recorded failed only at the decision, and from then on'
        @($saved[0..($firstFailed - 1)] | Where-Object { $_ -notin @('Waiting', 'Starting', 'Running') }).Count | Should -Be 0
    }
    It 'PodDeletion 20 min old and no ContainerStarted: never-started -- started again ONCE, the run succeeds' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $ev = New-PlatformProbe -Answers @(@{ Started = 0; EndMin = -19 })
        $r = Invoke-PlatFlow -Arm $arm -Evidence $ev
        $s = Get-Step $r 'endpoint'
        $s.State | Should -Be 'Success'; $s.Attempts | Should -Be 2; $r.State | Should -Be 'Succeeded'
        @($script:Arm.Starts | Where-Object { $_ -eq 'endpoint' }).Count | Should -Be 2
        $script:Plat.Calls.Count | Should -Be 1 -Because 'settled on the first read: decided at once'
        ($script:Logs -join "`n") | Should -Match 'Azure scheduled the step''s container but never started it'
    }
    It 'an end 1 min old that stays without ContainerStarted is waited for, then -- once 15 min old -- decided never-started and started again once' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $ev = New-PlatformProbe -Answers @(@{ Started = 0; EndMin = -1 })
        $r = Invoke-PlatFlow -Arm $arm -Evidence $ev
        $s = Get-Step $r 'endpoint'
        $s.State | Should -Be 'Success'; $s.Attempts | Should -Be 2
        @($script:Arm.Starts | Where-Object { $_ -eq 'endpoint' }).Count | Should -Be 2
        $script:Plat.Calls.Count | Should -BeGreaterThan 1
        ($script:Plat.Calls[-1] - $script:T0.AddMinutes(-1)).TotalMinutes | Should -BeGreaterOrEqual 15 -Because 'decided only once the end was 15 minutes old'
    }
    It 'PAST THE BOUND: events that never settle -> after 30 minutes "unknown" as before 3.1.16, never started again' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $ev = New-PlatformProbe -Answers @(@{ Started = 0; EndMin = $null })
        $r = Invoke-PlatFlow -Arm $arm -Evidence $ev
        $s = Get-Step $r 'endpoint'
        $s.State | Should -Be 'Failed'; $s.ErrorClass | Should -Be 'job-failed'; $s.Attempts | Should -Be 1
        @($script:Arm.Starts | Where-Object { $_ -eq 'endpoint' }).Count | Should -Be 1
        ($script:Plat.Calls[-1] - $script:Plat.Calls[0]).TotalMinutes | Should -BeGreaterOrEqual 28
        ($script:Clock - $script:T0).TotalMinutes | Should -BeLessThan 40 -Because 'bounded: the runner never waits on for ever'
        ($script:Logs -join "`n") | Should -Match 'could still not be told 30 minutes after its execution ended'
        $r.State | Should -Be 'Failed'
    }
    It 'RESTART SAFETY: a restart that finds the job already running follows that execution and starts none' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed') }
        $script:Arm.Exec['caj-si-endpoint-x9'] = 'Succeeded'
        $script:RunningAsked = 0
        $running = { param($j) $script:RunningAsked++; if ($script:RunningAsked -ge 2) { [pscustomobject]@{ Execution = 'caj-si-endpoint-x9'; StartedUtc = $script:Clock.AddSeconds(-20) } } else { $null } }
        $r = Invoke-PlatFlow -Arm $arm -Evidence { param($j, $e, $s, $t, $n) [pscustomobject]@{ HasStartRecord = $false; HasTranscript = $null; HasContainerStarted = $false; ContainerStartPending = $false } } -Running $running
        $s = Get-Step $r 'endpoint'
        @($script:Arm.Starts | Where-Object { $_ -eq 'endpoint' }).Count | Should -Be 1 -Because 'the restart started no second execution'
        $script:RunningAsked | Should -Be 2 -Because 'the first start and the restart both ask'
        $s.Execution | Should -Be 'caj-si-endpoint-x9'; $s.State | Should -Be 'Success'; $s.Attempts | Should -Be 2
        ($script:Logs -join "`n") | Should -Match 'already running \(caj-si-endpoint-x9.*follows that run instead of starting it again'
        $r.Note | Should -Match 'was already running \(caj-si-endpoint-x9'
    }
    It 'RESTART SAFETY: before the new start, the earlier execution''s step work (its workers) is stopped' {
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $script:Stops = New-Object System.Collections.Generic.List[object]
        $sw = { param($j, $since, $e) $script:Stops.Add([pscustomobject]@{ Job = $j; Since = $since; Execution = $e; StartsBefore = $script:Arm.Starts.Count }) }
        $r = Invoke-PlatFlow -Arm $arm -Evidence { param($j, $e, $s, $t, $n) [pscustomobject]@{ HasStartRecord = $false; HasTranscript = $null; HasContainerStarted = $false } } -StopWorkers $sw
        (Get-Step $r 'endpoint').State | Should -Be 'Success'
        $script:Stops.Count | Should -Be 1
        $script:Stops[0].Execution | Should -Be 'caj-si-endpoint-e1' -Because 'the EARLIER execution''s work'
        $script:Stops[0].Since | Should -Be $script:T0 -Because 'since the earlier execution started'
        $script:Stops[0].StartsBefore | Should -Be 1 -Because 'stopped before the second start'
    }
    It 'RESTART SAFETY WIRING: no restart path calls the start seam directly any more' {
        $src = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-JobFlow.ps1'))
        @([regex]::Matches($src, [regex]::Escape('. $startAgain $st'))).Count | Should -Be 3 -Because 'never-started, run limit, first collection'
        @([regex]::Matches($src, [regex]::Escape('$st.Execution = [string](& $Start $st.Job)'))).Count | Should -Be 1 -Because 'only inside the restart helper'
    }
}

Describe 'the evidence probe (container) and the record' {
    It 'reads the START record of the execution; no stamped row of THIS engine (an empty store) means "cannot tell"' {
        $kql = Get-SIJobFlowStartRecordQuery -Execution 'caj-si-asset-trend-tdkx9w2' -StartedUtc ([datetime]::SpecifyKind([datetime]'2026-10-05T05:01:07', 'Utc')) -Engine 'asset-trend'
        $kql | Should -Match "Execution == 'caj-si-asset-trend-tdkx9w2'"
        $kql | Should -Match "column_ifexists\('Execution', ''\)"
        $kql | Should -Match "Phase == 'Start'"
        $kql | Should -Match "not\(Engine startswith 'flow'\)"
        $kql | Should -Match "Stamped = countif\(Engine == 'asset-trend' and isnotempty\(Execution\)\)"
        $kql | Should -Match 'datetime\(2026-10-05T04:51:07Z\)'
        Get-SIJobFlowStartRecordQuery -Execution "x' or 1==1 //" -StartedUtc $script:T0 -Engine 'x' | Should -BeNullOrEmpty -Because 'a name that is not an execution never reaches a query'
        Get-SIJobFlowStartRecordQuery -Execution 'caj-si-x-e1' -StartedUtc $script:T0 -Engine "x' or 1==1" | Should -BeNullOrEmpty
        # the probe asks for the map's engine of the job (ptc -> privilege-tier-classifier)
        $script:Kqls = New-Object System.Collections.Generic.List[string]
        $null = (New-SIJobFlowStartEvidence -Query { param($k) $script:Kqls.Add($k); [pscustomobject]@{ Mine = 0; Stamped = 3 } }).Probe('ptc', 'caj-si-ptc-e1', $script:T0, $script:T0.AddSeconds(31))
        @($script:Kqls | Where-Object { $_ -match "Engine == 'privilege-tier-classifier'" }).Count | Should -Be 1 -Because 'the START record query (the platform-event query is asked too)'
        $t0 = $script:T0; $t1 = $script:T0.AddSeconds(31)
        # the platform's events of the execution: scheduled, never started -> HasContainerStarted $false; the store's row is no answer to it
        $pp = New-SIJobFlowStartEvidence -Query { param($k) if ($k -match '^ContainerAppSystemLogs') { [pscustomobject]@{ Scheduled = 1; Started = 0; Ended = 1; EndAt = $t1 } } else { [pscustomobject]@{ Mine = 0; Stamped = 0 } } }.GetNewClosure()
        $pe = $pp.Probe('asset-correlation', 'caj-si-asset-correlation-uxf5u22', $t0, $t1, $t1.AddMinutes(16))
        $pe.HasContainerStarted | Should -BeFalse; $pe.ContainerStartPending | Should -BeFalse
        $py = $pp.Probe('asset-correlation', 'caj-si-asset-correlation-uxf5u22', $t0, $t1, $t1.AddMinutes(2))
        $py.HasContainerStarted | Should -BeNullOrEmpty -Because 'the end is 2 minutes old: not settled'
        $py.ContainerStartPending | Should -BeTrue
        (New-SIJobFlowStartEvidence -Query { param($k) [pscustomobject]@{ Mine = 0; Stamped = 12 } }).Probe('x', 'caj-si-x-e1', $t0, $t1).HasContainerStarted | Should -BeNullOrEmpty
        (New-SIJobFlowStartEvidence -Query { param($k) if ($k -match '^ContainerAppSystemLogs') { throw 'forbidden' } else { [pscustomobject]@{ Mine = 0; Stamped = 12 } } }).Probe('x', 'caj-si-x-e1', $t0, $t1).HasContainerStarted | Should -BeNullOrEmpty -Because 'a read that fails tells nothing'
        $p = New-SIJobFlowStartEvidence -Query { param($k) [pscustomobject]@{ Mine = 0; Stamped = 12 } } -ListBlobs { param($pre) @('run-logs/ptc/ptc_container_20261004T010000Z.log', 'run-logs/asset-trend/asset-trend_container_20261004T050000Z.log') }
        $e = $p.Probe('asset-trend', 'caj-si-asset-trend-e1', $t0, $t1)
        $e.HasStartRecord | Should -BeFalse; $e.HasTranscript | Should -BeFalse
        (New-SIJobFlowStartEvidence -Query { param($k) [pscustomobject]@{ Mine = 1; Stamped = 12 } }).Probe('x', 'caj-si-x-e1', $t0, $t1).HasStartRecord | Should -BeTrue
        (New-SIJobFlowStartEvidence -Query { param($k) [pscustomobject]@{ Mine = 0; Stamped = 0 } }).Probe('x', 'caj-si-x-e1', $t0, $t1).HasStartRecord | Should -BeNullOrEmpty
        (New-SIJobFlowStartEvidence -Query { param($k) throw 'forbidden' }).Probe('x', 'caj-si-x-e1', $t0, $t1).HasStartRecord | Should -BeNullOrEmpty
        (New-SIJobFlowStartEvidence).Probe('x', 'caj-si-x-e1', $t0, $t1).HasStartRecord | Should -BeNullOrEmpty -Because 'no workspace: cannot tell'
        (New-SIJobFlowStartEvidence -ListBlobs { param($pre) @('run-logs/asset-trend/asset-trend_container_20261005T050012Z.log') }).Probe('asset-trend', 'e', $t0, $t1).HasTranscript | Should -BeTrue
        (New-SIJobFlowStartEvidence -ListBlobs { param($pre) @() }).Probe('x', 'e', $t0, $t1).HasTranscript | Should -BeNullOrEmpty -Because 'no run logs at all: the install keeps none'
        # #966 (live 2026-10-30): ANOTHER step's run log inside the window is not this step's -- the step before and the
        # heartbeat publish theirs there. The verification step whose container died: the close-loop mail's log 4 s before
        $t30 = [datetime]::new(2026, 10, 30, 18, 23, 9, [DateTimeKind]::Utc); $e30 = $t30.AddSeconds(96)
        $logs = @('run-logs/close-loop-mail/close-loop-mail_container_20261030T182208Z.log', 'run-logs/heartbeat/heartbeat_container_20261030T182218Z.log',
                  'run-logs/verification/verification_container_20261029T182416Z.log')
        $v = (New-SIJobFlowStartEvidence -ListBlobs { param($pre) $logs }.GetNewClosure()).Probe('verification', 'caj-si-verification-efr9zu5', $t30, $e30)
        $v.HasTranscript | Should -BeFalse -Because 'no run log of the verification engine in the window: its container never ran it'
        (Get-SIJobFlowFailureClass -ErrorClass 'job-failed' -HasStartRecord $false -HasTranscript $v.HasTranscript -DurationSeconds 96 -Attempts 1 -Retries 1).Retry | Should -BeTrue -Because 'a platform start failure is started again (working rule 4)'
        # its own run log in the window: it ran
        $own = @($logs) + 'run-logs/verification/verification_container_20261030T182405Z.log'
        (New-SIJobFlowStartEvidence -ListBlobs { param($pre) $own }.GetNewClosure()).Probe('caj-si-verification', 'x', $t30, $e30).HasTranscript | Should -BeTrue
        # run logs, but never one of this engine (named otherwise): the signal does not exist -- never a retry on it
        (New-SIJobFlowStartEvidence -ListBlobs { param($pre) @('run-logs/heartbeat/heartbeat_container_20261030T182218Z.log') }).Probe('verification', 'x', $t30, $e30).HasTranscript | Should -BeNullOrEmpty
    }
    It 'the transcript window is the execution +/- 60 s' {
        $a = $script:T0; $b = $script:T0.AddSeconds(31)
        Test-SIJobFlowTranscriptInWindow -Names @('run-logs/x/x_container_20261005T045859Z.log') -StartedUtc $a -EndedUtc $b | Should -BeFalse
        Test-SIJobFlowTranscriptInWindow -Names @('run-logs/x/x_container_20261005T045930Z.log') -StartedUtc $a -EndedUtc $b | Should -BeTrue
        Test-SIJobFlowTranscriptInWindow -Names @('run-logs/x/x_container_20261005T050131Z.log') -StartedUtc $a -EndedUtc $b | Should -BeTrue
        Test-SIJobFlowTranscriptInWindow -Names @('run-logs/x/x_container_20261005T050132Z.log', 'not-a-log.txt') -StartedUtc $a -EndedUtc $b | Should -BeFalse
    }
    It 'every run-health record carries the job execution (a container) and nothing on a VM' {
        . ([IO.Path]::Combine($script:SIRoot, 'engine', 'asset-profiling', 'shared', 'Send-SIRunHealthRow.ps1'))
        Get-SIRunHealthExecution -RunContext ([pscustomobject]@{ RunId = 'r' }) -Environment @{ CONTAINER_APP_JOB_EXECUTION_NAME = 'caj-si-asset-trend-tdkx9w2' } | Should -Be 'caj-si-asset-trend-tdkx9w2'
        Get-SIRunHealthExecution -RunContext ([pscustomobject]@{ RunId = 'r'; Execution = 'given' }) -Environment @{ CONTAINER_APP_JOB_EXECUTION_NAME = 'env' } | Should -Be 'given'
        Get-SIRunHealthExecution -RunContext ([pscustomobject]@{ RunId = 'r' }) -Environment @{} | Should -Be ''
        [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'engine', 'asset-profiling', 'shared', 'Send-SIRunHealthRow.ps1')) | Should -Match 'Execution\s+=\s+\[string\]\(Get-SIRunHealthExecution'
    }
    It 'the Pro store writes attempts and the reason (guarded: a database without the columns still works) and reads them back' {
        $sql = New-Object System.Collections.Generic.List[object]
        $inv = { param($q, $p, $mode) $sql.Add([pscustomobject]@{ Sql = $q; P = $p }); @() }.GetNewClosure()
        $store = New-SIJobFlowSqlStore -Invoke $inv
        $arm = New-RetryArm -Outcomes @{ 'endpoint' = @('Failed', 'Succeeded') }
        $script:Clock = $script:T0; $script:Sleeps = New-Object System.Collections.Generic.List[int]
        $d = New-SIDefaultJobFlow -Installed @('endpoint') -Map $script:Map
        $null = Invoke-SIJobFlow -Definition $d -Seams (New-SIJobFlowArmSeams -SubscriptionId 's' -ResourceGroup 'r' -Arm $arm) -Store $store -Previous $null -Force `
                    -Now $script:NowSb -Sleep $script:SleepSb -Log $script:LogSb -Map $script:Map -StartEvidence (New-Evidence -Rows @{ 'caj-si-endpoint-e1' = $false } -Logs @{ 'caj-si-endpoint-e1' = $false })
        $last = @($sql | Where-Object { $_.Sql -match 'MERGE cfg.FlowStepRun' })[-1]
        $last.P.Attempts | Should -Be 2
        $last.P.RetryReason | Should -Match 'started again'
        $last.Sql | Should -Match "IF COL_LENGTH\(N'cfg.FlowStepRun', N'Attempts'\) IS NOT NULL"
        (Get-SIJobFlowSqlText 'LastRunSteps') | Should -Match 'SELECT \* FROM cfg.FlowStepRun'
        # (the two columns in the Pro schema are proven by xunit FlowLocalSqlTests on a real SQL Server -- this free suite
        #  does not read Pro files: the Community edition does not contain them)
        # a record from before attempts were kept reads as 1 start (it has an execution) or 0
        Get-SIJobFlowAttempts ([pscustomobject]@{ Execution = 'caj-si-endpoint-a1' }) | Should -Be 1
        Get-SIJobFlowAttempts ([pscustomobject]@{ Execution = '' }) | Should -Be 0
        Get-SIJobFlowAttempts ([pscustomobject]@{ Execution = 'x'; Attempts = [DBNull]::Value }) | Should -Be 1
    }
    It 'the runner script gives the probe to the container flow only, with the configurable count' {
        $src = [IO.File]::ReadAllText([IO.Path]::Combine($script:SIRoot, 'engine', 'flow', 'Invoke-SIJobFlowRun.ps1'))
        $src | Should -Match "if \(\`$HostKind -eq 'Container'\) \{\s+\`$retry.StartEvidence = New-SIJobFlowStartEvidence"
        $src | Should -Match 'SI_FLOW_START_RETRIES'
        $src | Should -Match 'foreach \(\$k in \$retry\.Keys\) \{ \$pArgs\[\$k\] = \$retry\[\$k\] \}'
    }
}
