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
        $arm = New-RetryArm -Outcomes @{ 'ptc' = @('Failed', 'Succeeded') }
        $ev = New-Evidence -Rows @{ 'caj-si-ptc-e1' = $null } -Logs @{ 'caj-si-ptc-e1' = $false }
        $r = Invoke-RetryFlow -Jobs @('ptc') -Arm $arm -Evidence $ev
        $r.State | Should -Be 'Succeeded'; (Get-Step $r 'ptc').Attempts | Should -Be 2
    }
    It 'does not start the second time either: the step fails as before, dependents are skipped, the guard fires (halted)' {
        $arm = New-RetryArm -Outcomes @{ 'ptc' = @('Failed', 'Failed') }
        $ev = New-Evidence -Rows @{ 'caj-si-ptc-e1' = $false; 'caj-si-ptc-e2' = $false } -Logs @{ 'caj-si-ptc-e1' = $false; 'caj-si-ptc-e2' = $false }
        $r = Invoke-RetryFlow -Jobs @('ptc', 'identity', 'azure') -Arm $arm -Evidence $ev
        $r.State | Should -Be 'Failed'
        $s = Get-Step $r 'ptc'
        $s.State | Should -Be 'Failed'; $s.ErrorClass | Should -Be 'never-started'; $s.Attempts | Should -Be 2
        $s.Error | Should -Match 'also not when it was started again \(2 attempts\)'
        @($script:Arm.Starts | Where-Object { $_ -eq 'ptc' }).Count | Should -Be 2 -Because 'once retried, never a third time'
        (Get-Step $r 'identity').State | Should -Be 'Skipped'; (Get-Step $r 'azure').State | Should -Be 'Skipped'
        $calls = @(Get-SIGuardCallsForFlow -Result $r)
        $g = @($calls | Where-Object { $_.GuardId -eq 'flow.step.start-failed' })
        $g.Count | Should -Be 1
        $g[0].Outcome | Should -Be 'halted'
        $g[0].Subject | Should -Be 'ptc'
        $g[0].Detail | Should -Match 'ptc \(2 attempts\)'
        $g[0].Detail | Should -Match '2 job\(s\) after it were skipped'
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
        $arm = New-RetryArm -Outcomes @{ 'ptc' = @('Failed', 'Succeeded') }
        $ev = New-Evidence -Rows @{ 'caj-si-ptc-e1' = $true }
        $r = Invoke-RetryFlow -Jobs @('ptc', 'identity') -Arm $arm -Evidence $ev
        $r.State | Should -Be 'Failed'
        $s = Get-Step $r 'ptc'
        $s.State | Should -Be 'Failed'; $s.ErrorClass | Should -Be 'job-failed'; $s.Attempts | Should -Be 1; $s.RetryReason | Should -BeNullOrEmpty
        @($script:Arm.Starts | Where-Object { $_ -eq 'ptc' }).Count | Should -Be 1
        (Get-Step $r 'identity').State | Should -Be 'Skipped' -Because 'dependents are handled as before'
        @(Get-SIGuardCallsForFlow -Result $r | Where-Object { $_.GuardId -eq 'flow.step.start-failed' }).Count | Should -Be 0
    }
    It 'a run log in the window is a real failure too' {
        $arm = New-RetryArm -Outcomes @{ 'ptc' = @('Failed', 'Succeeded') }
        $r = Invoke-RetryFlow -Jobs @('ptc') -Arm $arm -Evidence (New-Evidence -Rows @{ 'caj-si-ptc-e1' = $null } -Logs @{ 'caj-si-ptc-e1' = $true })
        (Get-Step $r 'ptc').Attempts | Should -Be 1; $r.State | Should -Be 'Failed'
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
        $arm = New-RetryArm -Outcomes @{ 'ptc' = @('Failed', 'Succeeded') }
        $r = Invoke-RetryFlow -Jobs @('ptc') -Arm $arm -Evidence (New-Evidence -Rows @{ 'caj-si-ptc-e1' = $false })
        (Get-Step $r 'ptc').Attempts | Should -Be 1; $r.State | Should -Be 'Failed'
    }
    It 'a probe that cannot read anything is unsure: not retried, said' {
        $arm = New-RetryArm -Outcomes @{ 'ptc' = @('Failed', 'Succeeded') }
        $r = Invoke-RetryFlow -Jobs @('ptc') -Arm $arm -Evidence (New-Evidence -Throw)
        (Get-Step $r 'ptc').Attempts | Should -Be 1; $r.State | Should -Be 'Failed'
        ($script:Logs -join "`n") | Should -Match 'whether it started could not be checked'
    }
    It 'without a probe (the VM flow) nothing is retried and nothing waits' {
        $arm = New-RetryArm -Outcomes @{ 'ptc' = @('Failed', 'Succeeded') }
        $r = Invoke-RetryFlow -Jobs @('ptc') -Arm $arm -Evidence $null
        (Get-Step $r 'ptc').Attempts | Should -Be 1; $r.State | Should -Be 'Failed'
        $script:Sleeps | Should -Not -Contain 60
    }
    It 'a run that succeeds is never probed' {
        $arm = New-RetryArm
        $null = Invoke-RetryFlow -Jobs @('ptc', 'identity') -Arm $arm -Evidence (New-Evidence)
        $script:Ev.Probes.Count | Should -Be 0
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
        $script:Kql = ''
        $null = (New-SIJobFlowStartEvidence -Query { param($k) $script:Kql = $k; [pscustomobject]@{ Mine = 0; Stamped = 3 } }).Probe('ptc', 'caj-si-ptc-e1', $script:T0, $script:T0.AddSeconds(31))
        $script:Kql | Should -Match "Engine == 'privilege-tier-classifier'"
        $t0 = $script:T0; $t1 = $script:T0.AddSeconds(31)
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
        $arm = New-RetryArm -Outcomes @{ 'ptc' = @('Failed', 'Succeeded') }
        $script:Clock = $script:T0; $script:Sleeps = New-Object System.Collections.Generic.List[int]
        $d = New-SIDefaultJobFlow -Installed @('ptc') -Map $script:Map
        $null = Invoke-SIJobFlow -Definition $d -Seams (New-SIJobFlowArmSeams -SubscriptionId 's' -ResourceGroup 'r' -Arm $arm) -Store $store -Previous $null -Force `
                    -Now $script:NowSb -Sleep $script:SleepSb -Log $script:LogSb -Map $script:Map -StartEvidence (New-Evidence -Rows @{ 'caj-si-ptc-e1' = $false } -Logs @{ 'caj-si-ptc-e1' = $false })
        $last = @($sql | Where-Object { $_.Sql -match 'MERGE cfg.FlowStepRun' })[-1]
        $last.P.Attempts | Should -Be 2
        $last.P.RetryReason | Should -Match 'started again'
        $last.Sql | Should -Match "IF COL_LENGTH\(N'cfg.FlowStepRun', N'Attempts'\) IS NOT NULL"
        (Get-SIJobFlowSqlText 'LastRunSteps') | Should -Match 'SELECT \* FROM cfg.FlowStepRun'
        # (the two columns in the Pro schema are proven by xunit FlowLocalSqlTests on a real SQL Server -- this free suite
        #  does not read Pro files: the Community edition does not contain them)
        # a record from before attempts were kept reads as 1 start (it has an execution) or 0
        Get-SIJobFlowAttempts ([pscustomobject]@{ Execution = 'caj-si-ptc-a1' }) | Should -Be 1
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
