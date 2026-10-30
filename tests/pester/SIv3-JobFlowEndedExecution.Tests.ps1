#Requires -Version 5.1
<#
    THE PIPELINE NOTICES THAT ITS STEP'S EXECUTION HAS ENDED (REQUIREMENTS #945, owner 2026-10-29; live, a customer install: the
    correlation step's execution ended Failed on 28 Oct 03:09Z and the run still showed the step running on 29 Oct).
      1. the wake-up check (Get-SIJobFlowEndedExecutionCloses): an execution that ENDED at least 20 minutes ago while its step
         still says Running closes the step with that result; running / unknown / too recent / unreadable = nothing;
      2. the poll falls back to the job's execution LIST when the read of the one execution fails;
      3. the stores close one step only while it is Running with that execution, in a run that has not ended;
      4. the runner that holds the run takes the close over at its next poll; the run goes on by the normal rules (a failed
         step's dependants are skipped, the run ends);
      5. the runner script asks it on every wake-up, before the drain, and never stops anything there.
    Offline; PS 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . ([IO.Path]::Combine($script:SIRoot, 'engine', '_shared', 'SI-JobFlow.ps1'))
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-29T05:10:00', 'Utc')
    function script:New-Exec([string]$Name, [string]$Status, $EndUtc) {
        $p = [ordered]@{ status = $Status; startTime = '2026-10-26T19:52:00Z' }
        if ($EndUtc) { $p.endTime = ([datetime]$EndUtc).ToString('yyyy-MM-ddTHH:mm:ssZ') }
        [pscustomobject]@{ name = $Name; properties = [pscustomobject]$p }
    }
    function script:New-Run([string]$State = 'Running') {
        [pscustomobject]@{ FlowRunId = 'b64fbc83'; Day = '2026-10-26'; Trigger = 'schedule'; FromStep = ''; State = $State; StartedUtc = $script:Now.AddDays(-3); EndedUtc = $null
            HeartbeatUtc = $script:Now.AddMinutes(-1); StopReason = ''; SlotUtc = $null; LastSlotUtc = $null; Note = ''; Scope = 'pipeline'; Target = ''; RequestedBy = ''; RequestId = 0; Version = '3.0.0.202610251703'; CancelledBy = ''
            Steps = @(
                [pscustomobject]@{ Order = 1; Group = 1; Job = 'identity'; Stage = 'collect'; State = 'Success'; Execution = 'caj-si-identity-a1'; StartedUtc = $script:Now.AddDays(-3); EndedUtc = $script:Now.AddDays(-3).AddHours(1); ErrorClass = ''; Error = ''; Attempts = 1; RetryReason = '' }
                [pscustomobject]@{ Order = 2; Group = 2; Job = 'asset-correlation'; Stage = 'correlate'; State = 'Running'; Execution = 'caj-si-asset-correlation-ihcbirb'; StartedUtc = $script:Now.AddDays(-2.4); EndedUtc = $null; ErrorClass = ''; Error = ''; Attempts = 1; RetryReason = '' }
                [pscustomobject]@{ Order = 3; Group = 3; Job = 'risk-analysis-detailed'; Stage = 'correlate'; State = 'Waiting'; Execution = ''; StartedUtc = $null; EndedUtc = $null; ErrorClass = ''; Error = ''; Attempts = 0; RetryReason = '' }
            ) }
    }
}

Describe '#945 the wake-up check: an ENDED execution closes its open step' {
    It 'the live case: Failed at 03:09Z, the step still Running at 05:10Z the next day -> closed Failed, with the end time and the words' {
        $ended = [datetime]::SpecifyKind([datetime]'2026-10-28T03:09:00', 'Utc')
        $c = @(Get-SIJobFlowEndedExecutionCloses -State (New-Run) -NowUtc $script:Now -ExecutionsByJob @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Failed' $ended)) })
        $c.Count | Should -Be 1
        $c[0].Order | Should -Be 2
        $c[0].State | Should -Be 'Failed'
        $c[0].ErrorClass | Should -Be 'job-failed'
        $c[0].EndedUtc | Should -Be $ended
        $c[0].Error | Should -Match '^the execution ended failed at 2026-10-28 03:09Z; noticed by the pipeline''s wake-up at 2026-10-29 05:10Z'
    }
    It 'Stopped -> Interrupted (class stopped); Succeeded -> Success; Degraded -> Failed' {
        $e = $script:Now.AddHours(-1)
        (Get-SIJobFlowEndedExecutionCloses -State (New-Run) -NowUtc $script:Now -ExecutionsByJob @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Stopped' $e)) })[0].State | Should -Be 'Interrupted'
        (Get-SIJobFlowEndedExecutionCloses -State (New-Run) -NowUtc $script:Now -ExecutionsByJob @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Stopped' $e)) })[0].ErrorClass | Should -Be 'stopped'
        (Get-SIJobFlowEndedExecutionCloses -State (New-Run) -NowUtc $script:Now -ExecutionsByJob @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Succeeded' $e)) })[0].State | Should -Be 'Success'
        (Get-SIJobFlowEndedExecutionCloses -State (New-Run) -NowUtc $script:Now -ExecutionsByJob @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Degraded' $e)) })[0].State | Should -Be 'Failed'
    }
    It 'NEVER closes a step whose execution still runs, is too recent, is not in the list, has no end, or whose list was not read' {
        $run = New-Run
        foreach ($case in @(
                @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Running' $null)) },
                @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Processing' $null)) },
                @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Failed' $script:Now.AddMinutes(-19))) },
                @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-other' 'Failed' $script:Now.AddHours(-3))) },
                @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Failed' $null)) },
                @{ 'asset-correlation' = $null },
                @{})) {
            @(Get-SIJobFlowEndedExecutionCloses -State $run -NowUtc $script:Now -ExecutionsByJob $case).Count | Should -Be 0
        }
        # exactly at the grace it closes (20 minutes)
        @(Get-SIJobFlowEndedExecutionCloses -State $run -NowUtc $script:Now -ExecutionsByJob @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Failed' $script:Now.AddMinutes(-20))) }).Count | Should -Be 1
    }
    It 'a run that has ended, a VM process (pid@...) and a step that is not Running are left alone' {
        $old = $script:Now.AddHours(-3)
        $list = @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Failed' $old)) }
        foreach ($rs in 'Succeeded', 'Failed', 'Stopped', 'Cancelled') { @(Get-SIJobFlowEndedExecutionCloses -State (New-Run $rs) -NowUtc $script:Now -ExecutionsByJob $list).Count | Should -Be 0 }
        $vm = New-Run; $vm.Steps[1].Execution = '4412@2026-10-26T19:52:00Z'
        @(Get-SIJobFlowEndedExecutionCloses -State $vm -NowUtc $script:Now -ExecutionsByJob @{ 'asset-correlation' = @((New-Exec '4412@2026-10-26T19:52:00Z' 'Failed' $old)) }).Count | Should -Be 0
        $st = New-Run; $st.Steps[1].State = 'Starting'
        @(Get-SIJobFlowEndedExecutionCloses -State $st -NowUtc $script:Now -ExecutionsByJob $list).Count | Should -Be 0
    }
    It 'a collection in parts: a producer that SUCCEEDED does not end the step (its parts do); a producer that failed or was stopped does' {
        $run = New-Run; $run.Steps[1].Job = 'identity2'; $run.Steps[1].Execution = 'caj-si-identity2-producer-p1'
        $old = $script:Now.AddHours(-3)
        @(Get-SIJobFlowEndedExecutionCloses -State $run -NowUtc $script:Now -PartsJobs @{ identity2 = $true } -ExecutionsByJob @{ identity2 = @((New-Exec 'caj-si-identity2-producer-p1' 'Succeeded' $old)) }).Count | Should -Be 0
        (Get-SIJobFlowEndedExecutionCloses -State $run -NowUtc $script:Now -PartsJobs @{ identity2 = $true } -ExecutionsByJob @{ identity2 = @((New-Exec 'caj-si-identity2-producer-p1' 'Failed' $old)) })[0].State | Should -Be 'Failed'
    }
}

Describe '#945 the poll reads the execution LIST when the read of the one execution fails' {
    It 'single read throws -> the list says Failed -> Failed; both fail -> the first error is thrown (the runner tries again)' {
        $script:ListFails = $false
        $arm = { param($Method, $Path, $Body)
            if ($Path -match '/executions/[^/]+$') { throw 'HTTP 404: job execution caj-si-asset-correlation-ihcbirb not found' }
            if ($Path -match '/executions$') { if ($script:ListFails) { throw 'HTTP 503' }; return [pscustomobject]@{ value = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Failed' $script:Now.AddHours(-2))) } }
            throw "unexpected $Method $Path" }
        $seams = New-SIJobFlowArmSeams -SubscriptionId 'sub' -ResourceGroup 'rg' -Arm $arm
        $seams.Poll('asset-correlation', 'caj-si-asset-correlation-ihcbirb') | Should -Be 'Failed'
        $script:ListFails = $true
        { $seams.Poll('asset-correlation', 'caj-si-asset-correlation-ihcbirb') } | Should -Throw '*not found*'
    }
    It 'a single read that answers keeps answering as before (the list is not read)' {
        $script:Calls = New-Object System.Collections.Generic.List[string]
        $arm = { param($Method, $Path, $Body) $script:Calls.Add($Path); [pscustomobject]@{ properties = [pscustomobject]@{ status = 'Running' } } }
        (New-SIJobFlowArmSeams -SubscriptionId 'sub' -ResourceGroup 'rg' -Arm $arm).Poll('ptc', 'caj-si-ptc-1') | Should -Be 'Running'
        @($script:Calls).Count | Should -Be 1
    }
    It 'Get-SIJobFlowExecutionStatusOf: by name only' {
        Get-SIJobFlowExecutionStatusOf -Executions @((New-Exec 'a' 'Failed' $null), (New-Exec 'b' 'Running' $null)) -Execution 'b' | Should -Be 'Running'
        Get-SIJobFlowExecutionStatusOf -Executions @((New-Exec 'a' 'Failed' $null)) -Execution 'c' | Should -Be ''
    }
}

Describe '#945 the stores close one step only while it is Running with that execution' {
    It 'the SQL text: guarded by State = Running AND the execution AND a run that has not ended; the row read is read-only' {
        $s = Get-SIJobFlowSqlText 'CloseOpenStep'
        $s | Should -Match "s\.State = N'Running' AND s\.Execution = @Execution"
        $s | Should -Match "r\.State NOT IN \(N'Succeeded', N'Failed', N'Stopped', N'Cancelled'\)"
        $s | Should -Match 'SELECT @@ROWCOUNT AS Closed'
        (Get-SIJobFlowSqlText 'StepRow') | Should -Match '^SELECT State, Execution, EndedUtc, ErrorClass, Error FROM cfg\.FlowStepRun WHERE FlowRunId = @FlowRunId AND StepOrder = @StepOrder;$'
    }
    It 'a runner that never saw the close does not reopen it: SaveStep and the file / blob save keep an ended step with the same execution' {
        (Get-SIJobFlowSqlText 'SaveStep') | Should -Match "AND NOT \(@State = N'Running' AND t\.Execution = @Execution AND t\.State IN \(N'Success', N'Failed', N'Interrupted', N'TimedOut'\)\)"
        $stored = New-Run; $stored.Steps[1].State = 'Failed'; $stored.Steps[1].ErrorClass = 'job-failed'; $stored.Steps[1].Error = 'closed'; $stored.Steps[1].EndedUtc = $script:Now.AddDays(-1)
        $mem = New-Run
        $j = ConvertFrom-SIJobFlowRunJson -Json (Get-SIJobFlowSaveJson -State $mem -Stored $stored)
        $j.Steps[1].State | Should -Be 'Failed'
        $mem.Steps[1].State | Should -Be 'Running' -Because 'the runner''s own record is never changed by the save'
        # started again (a new execution): written as it is
        $mem.Steps[1].Execution = 'caj-si-asset-correlation-again'
        (ConvertFrom-SIJobFlowRunJson -Json (Get-SIJobFlowSaveJson -State $mem -Stored $stored)).Steps[1].State | Should -Be 'Running'
    }
    It 'the SQL store passes the close and reads the answer' {
        $script:Sent = $null
        $inv = { param($sql, $p, $mode) $script:Sent = $p; , @(@{ Closed = 1 }) }
        $store = New-SIJobFlowSqlStore -Invoke $inv
        $c = [pscustomobject]@{ Order = 2; Execution = 'caj-si-asset-correlation-ihcbirb'; State = 'Failed'; ErrorClass = 'job-failed'; Error = 'x'; EndedUtc = $script:Now }
        $store.CloseOpenStep('b64fbc83', $c) | Should -Be 1
        $script:Sent.StepOrder | Should -Be 2
        $script:Sent.Execution | Should -Be 'caj-si-asset-correlation-ihcbirb'
        $script:Sent.State | Should -Be 'Failed'
    }
    It 'the file store: closes it once; a step the runner moved on (another execution) is never overwritten' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('si945-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Path $dir | Out-Null
        try {
            $store = New-SIJobFlowFileStore -Path (Join-Path $dir 'flow-run.json')
            $store.Save((New-Run))
            $c = [pscustomobject]@{ Order = 2; Execution = 'caj-si-asset-correlation-ihcbirb'; State = 'Failed'; ErrorClass = 'job-failed'; Error = 'the execution ended failed'; EndedUtc = $script:Now.AddDays(-1) }
            $store.CloseOpenStep('b64fbc83', $c) | Should -Be 1
            $store.StepRow('b64fbc83', 2).State | Should -Be 'Failed'
            $store.CloseOpenStep('b64fbc83', $c) | Should -Be 0 -Because 'it is not Running any more'
            $r = New-Run; $r.Steps[1].Execution = 'caj-si-asset-correlation-again'; $store.Save($r)
            $store.CloseOpenStep('b64fbc83', $c) | Should -Be 0 -Because 'the runner started the step again: another execution'
            $store.StepRow('b64fbc83', 2).State | Should -Be 'Running'
            $store.CloseOpenStep('another-run', $c) | Should -Be 0
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe '#945 the run goes on by the normal rules' {
    It 'the live runner cannot read its execution; the wake-up closed the step -> the runner takes it over, the dependants are skipped, the run ends Failed' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('si945r-' + [guid]::NewGuid().ToString('N').Substring(0, 8)); New-Item -ItemType Directory -Path $dir | Out-Null
        try {
            $store = New-SIJobFlowFileStore -Path (Join-Path $dir 'flow-run.json')
            $def = New-SIDefaultJobFlow -Installed @('identity', 'asset-correlation', 'risk-analysis-detailed') -Map (Get-SIJobFlowMap)
            $mkRun = {
                $r = New-SIJobFlowRunState -Definition $def -NowUtc $script:Now.AddDays(-3) -FlowRunId 'b64fbc83'
                foreach ($x in @($r.Steps)) {
                    if ($x.Job -eq 'asset-correlation') { $x.State = 'Running'; $x.Execution = 'caj-si-asset-correlation-ihcbirb'; $x.StartedUtc = $script:Now.AddDays(-2.4); $x.Attempts = 1 }
                    elseif ($x.Job -eq 'risk-analysis-detailed') { }
                    elseif ($x.State -eq 'Waiting') { $x.State = 'Success'; $x.Execution = ('caj-si-{0}-a1' -f $x.Job); $x.StartedUtc = $script:Now.AddDays(-3); $x.EndedUtc = $script:Now.AddDays(-3).AddHours(1); $x.Attempts = 1 }
                }
                $r.HeartbeatUtc = $script:Now.AddHours(-1)   # its runner stopped: this wake-up resumes it
                $r
            }
            $store.Save((& $mkRun))
            # the wake-up check (as the runner script does it) closes the step
            $c = @(Get-SIJobFlowEndedExecutionCloses -State $store.Load() -NowUtc $script:Now -ExecutionsByJob @{ 'asset-correlation' = @((New-Exec 'caj-si-asset-correlation-ihcbirb' 'Failed' ([datetime]::SpecifyKind([datetime]'2026-10-28T03:09:00', 'Utc')))) })
            $c.Count | Should -Be 1
            $store.CloseOpenStep('b64fbc83', $c[0]) | Should -Be 1
            # a runner that still had the step open in memory: its poll keeps failing -> it takes the stored close over
            $mem = & $mkRun
            $script:Started = New-Object System.Collections.Generic.List[string]
            $res = Invoke-SIJobFlow -Definition $def -Map (Get-SIJobFlowMap) -Previous $mem -Store $store -Now { $script:Now } -Sleep { param($s) } -PollSeconds 0 -Log { param($l, $m) } `
                -Start { param($j) $script:Started.Add($j); "caj-si-$j-new" } -Poll { param($j, $e) if ($j -eq 'asset-correlation') { throw 'HTTP 404: job execution not found' }; 'Succeeded' }
            ($res.Steps | Where-Object { $_.Job -eq 'asset-correlation' }).State | Should -Be 'Failed'
            ($res.Steps | Where-Object { $_.Job -eq 'asset-correlation' }).EndedUtc | Should -Be ([datetime]::SpecifyKind([datetime]'2026-10-28T03:09:00', 'Utc'))
            ($res.Steps | Where-Object { $_.Job -eq 'risk-analysis-detailed' }).State | Should -Be 'Skipped'
            $res.State | Should -BeIn @('Failed', 'Stopped')
            @($script:Started) | Should -Not -Contain 'asset-correlation' -Because 'a failed step is never started again by the close'
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe '#945 wiring: the runner asks on every wake-up, before the drain, and stops nothing there' {
    It 'Invoke-SIJobFlowRun.ps1' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
        $a = $src.IndexOf('Get-SIJobFlowEndedExecutionCloses'); $b = $src.IndexOf('$drain = Invoke-SIPipelineDrain')
        $a | Should -BeGreaterThan 0; $a | Should -BeLessThan $b
        $from = $src.LastIndexOf('# ---- #945', $a); $to = $src.IndexOf('# ---- #947', $a)
        $to | Should -BeGreaterThan $from
        $block = $src.Substring($from, $to - $from)
        $block | Should -Match '\$runStore\.CloseOpenStep'
        $block | Should -Match '\$armSeams\.Executions\('
        ($block -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n" | Should -Not -Match "/stop/|\.Stop\(|'POST'"
        $src.IndexOf('Get-SIJobFlowEndedExecutionCloses') | Should -BeLessThan $src.IndexOf('Get-SIPipelineUpdateOverdueStart')
    }
}
