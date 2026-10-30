#Requires -Version 5.1
<#
    SecurityInsight -- RUN REPORTS CARRY StepsOk, AND ONLY THE EXECUTION THAT KNOWS THE WHOLE RESULT SENDS THE JOB'S OK
    (Invardia 2026-10-28: a step ticket closes only when a later ok report of the same job lists that step in StepsOk; SI
    never sent it, 61 tickets stayed open. And each execution of a collection reported its own ok -- the producer before its
    hand-over -- so a failed hand-over's ticket was once closed by an ok that proved nothing).

    What must hold (offline; every post is a stub):
      - StepsOk: ids in the FailedStep shape, each once, at most 50; ok = the listed steps + 'run'; warning = the steps before
        the failed one (or all when it is not listed), never 'run'; failed = none; on identified AND anonymous reports;
      - a FailedStep ticket opened by one report is closed by the next ok report's StepsOk (the same id);
      - a part of a run in parts (SuppressJobOk) does not send the job's ok; its failure is still sent;
      - the execution that published a collection's records sends ok with every step, or failed with FailedStep 'records';
        a run with a failed part sends nothing more;
      - the wiring: the engine run, the container, Risk Analysis, the pipeline and the data sync fill it.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-TelemetrySend.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-CollectParts.ps1')
    $script:Now = [datetime]'2026-10-29T10:00:00Z'
    function script:New-Ctx([string]$Mode = 'identified') {
        if ($Mode -eq 'anonymous') {
            return [pscustomobject]@{ Mode = 'anonymous'; Endpoint = 'https://uplink.test'; AccessCode = 'community-code'; Edition = 'community'; LicenceState = 'none'; Version = '3.0.0'; Hosting = 'container'
                                      RuntimeIdentity = 'mi-container'; InstallId = '0f3c9a2e-5b7d-4c1a-9e8f-1a2b3c4d5e6f'; TenantId = ''; StateDirectory = $TestDrive }
        }
        [pscustomobject]@{ Mode = 'identified'; Endpoint = 'https://uplink.test'; AccessCode = 'inv-TESTKEY-0123456789'; Edition = 'pro'; LicenceState = 'valid'; Version = '3.0.0'; Hosting = 'container'
                           RuntimeIdentity = 'mi-container'; InstallId = ''; TenantId = '11111111-2222-3333-4444-555555555555'; StateDirectory = $TestDrive; Endpoints = @() }
    }
    function script:New-Capture { $l = New-Object System.Collections.Generic.List[object]; [pscustomobject]@{ List = $l; Transport = { param($Record, $Endpoint, $AccessCode, $TimeoutSec) $l.Add($Record); [pscustomobject]@{ Status = 'ok' } }.GetNewClosure() } }
    function script:Send([object]$Rc, [string]$Exit, [string]$Mode = 'identified', [string]$Msg = 'x') {
        $c = New-Capture
        $r = Send-SITelemetryRunEnd -RunContext $Rc -ExitReason $Exit -ErrorMessage $Msg -Context (New-Ctx $Mode) -Transport $c.Transport -Now $script:Now -NoHeartbeat
        [pscustomobject]@{ Result = $r; Run = @($c.List | Where-Object { $_.Kind -eq 'run' })[0] }
    }
}

AfterAll { $global:SI_TelemetryHalted = $null; $global:SI_TelemetryWarned = $null; $global:SI_Telemetry_Enabled = $null }

Describe 'SIv3-TelemetryStepsOk: which steps a report lists (Get-SITelemetryStepsOk)' {
    It 'ok: the listed steps and run; warning: the steps before the failed one, never run; failed: none' {
        $rc = [pscustomobject]@{ StepsOk = @('Collect', 'enrich', 'classify', 'enrich') }
        @(Get-SITelemetryStepsOk -RunContext $rc -ExitReason 'success') | Should -Be @('collect', 'enrich', 'classify', 'run')
        @(Get-SITelemetryStepsOk -RunContext $rc -ExitReason 'success-partial' -FailedStep 'classify') | Should -Be @('collect', 'enrich')
        @(Get-SITelemetryStepsOk -RunContext $rc -ExitReason 'success-partial' -FailedStep 'output') | Should -Be @('collect', 'enrich', 'classify') -Because 'the failed step is not one of those: every listed one finished'
        @(Get-SITelemetryStepsOk -RunContext $rc -ExitReason 'error' -FailedStep 'classify').Count | Should -Be 0
        @(Get-SITelemetryStepsOk -RunContext $null -ExitReason 'success') | Should -Be @('run')
        @(Get-SITelemetryStepsOk -RunContext ([pscustomobject]@{ StepsOk = @('run') }) -ExitReason 'success-partial' -FailedStep 'ra-query').Count | Should -Be 0
    }
    It 'ids in the FailedStep shape, each once, at most 50' {
        $rc = [pscustomobject]@{ StepsOk = @(1..70 | ForEach-Object { "step-$_" }) + @('Bad Step!', '9lives', '') }
        $s = @(Get-SITelemetryStepsOk -RunContext $rc -ExitReason 'success')
        $s.Count | Should -Be 50
        foreach ($x in $s) { $x | Should -MatchExactly '^[a-z][a-z0-9\-]{0,31}$' }
    }
    It 'the run record carries them only for ok and warning, cleaned' {
        $base = @{ Job = 'si-flow'; Edition = 'pro'; Version = '3.0.0'; Hosting = 'container'; RuntimeIdentity = 'mi-container'; LicenceState = 'valid'; TenantId = 't' }
        (New-SITelemetryRunRecord @base -ExitReason 'success' -StepsOk @('identity', 'Bad Id', 'identity')).StepsOk | Should -Be @('identity')
        (New-SITelemetryRunRecord @base -ExitReason 'error' -StepsOk @('identity') -ErrorMessage 'x').PSObject.Properties['StepsOk'] | Should -BeNullOrEmpty
        (New-SITelemetryRunRecord @base -ExitReason 'success').PSObject.Properties['StepsOk'] | Should -BeNullOrEmpty
    }
}

Describe 'SIv3-TelemetryStepsOk: on the wire, and a ticket closes on the next ok' {
    BeforeEach { $global:SI_TelemetryHalted = $false; $global:SI_TelemetryWarned = $false; $global:SI_Telemetry_Enabled = $null }
    It 'a FailedStep ticket opened by one report is closed by the next ok report''s StepsOk (the same id), identified and anonymous' {
        foreach ($m in 'identified', 'anonymous') {
            $f = Send ([pscustomobject]@{ Engine = 'flow'; ShardIndex = 0; StartedAt = $script:Now.AddHours(-2); FailedStep = 'identity'; StepsOk = @('ptc') }) 'error' $m
            $f.Run.Outcome | Should -Be 'failed'
            $f.Run.FailedStep | Should -Be 'identity'
            $f.Run.PSObject.Properties['StepsOk'] | Should -BeNullOrEmpty -Because 'a failed report lists nothing'
            $ok = Send ([pscustomobject]@{ Engine = 'flow'; ShardIndex = 0; StartedAt = $script:Now.AddHours(-1); StepsOk = @('ptc', 'identity', 'risk-analysis-detailed') }) 'success' $m
            $ok.Run.Outcome | Should -Be 'ok'
            $ok.Run.Job | Should -Be $f.Run.Job
            @($ok.Run.StepsOk) | Should -Contain $f.Run.FailedStep -Because "$m : the ok report names the step whose ticket it closes"
            @($ok.Run.StepsOk) | Should -Contain 'run'
        }
    }
    It 'a warning lists the steps that finished, not the failed one' {
        $w = Send ([pscustomobject]@{ Engine = 'flow'; ShardIndex = 0; StartedAt = $script:Now.AddHours(-1); FailedStep = 'identity'; StepsOk = @('ptc', 'endpoint') }) 'success-partial'
        $w.Run.Outcome | Should -Be 'warning'
        @($w.Run.StepsOk) | Should -Be @('ptc', 'endpoint')
    }
    It 'Risk Analysis: ra-report only when every report is complete' {
        $ctx = [pscustomobject]@{ Engine = 'risk-analysis'; ShardIndex = 0; StartedAt = $script:Now.AddHours(-1); StepsOk = @('ra-query', 'ra-report'); ReportsExpected = 10; ReportsStored = 9; ReportsIncomplete = 1 }
        $global:ReportTemplate = 'RiskAnalysis_Detailed'
        try {
            $w = Send $ctx 'success-partial'
            $w.Run.FailedStep | Should -Be 'ra-report'
            @($w.Run.StepsOk) | Should -Be @('ra-query')
            $ok = Send ([pscustomobject]@{ Engine = 'risk-analysis'; ShardIndex = 0; StartedAt = $script:Now.AddHours(-1); StepsOk = @('ra-query', 'ra-report') }) 'success'
            @($ok.Run.StepsOk) | Should -Be @('ra-query', 'ra-report', 'run')
        } finally { $global:ReportTemplate = $null }
    }
    It 'a part of a run in parts does not send the job''s ok; its failure and its warning still go' {
        $ok = Send ([pscustomobject]@{ Engine = 'identity'; ShardIndex = 0; StartedAt = $script:Now.AddHours(-1); SuppressJobOk = $true; StepsOk = @('collect') }) 'success'
        $ok.Result.Status | Should -Be 'skipped'
        $ok.Result.Reason | Should -Match 'publishes the whole result'
        $ok.Run | Should -BeNullOrEmpty
        $bad = Send ([pscustomobject]@{ Engine = 'identity'; ShardIndex = 0; StartedAt = $script:Now.AddHours(-1); SuppressJobOk = $true; FailedStep = 'collect' }) 'error'
        $bad.Run.Outcome | Should -Be 'failed'
        $warn = Send ([pscustomobject]@{ Engine = 'identity'; ShardIndex = 0; StartedAt = $script:Now.AddHours(-1); SuppressJobOk = $true }) 'success-partial'
        $warn.Run.Outcome | Should -Be 'warning'
    }
}

Describe 'SIv3-TelemetryStepsOk: the execution that published a collection''s records reports the job' {
    It 'whole: ok with every step of the run, in order; azure adds recommendations' {
        $r = Get-SICollectRunReport -Engine 'identity' -RecordsState 'published' -FailedParts 0 -RunId 'run-1' -StartedAt $script:Now.AddHours(-3)
        $r.ExitReason | Should -Be 'success'
        @($r.RunContext.StepsOk) | Should -Be @('schedule', 'discover', 'collect', 'enrich', 'classify', 'profile', 'reconcile', 'output', 'tagging', 'handover', 'records')
        $r.RunContext.Engine | Should -Be 'identity'
        $r.RunContext.StartedAt | Should -Be $script:Now.AddHours(-3).ToUniversalTime()
        @((Get-SICollectRunReport -Engine 'azure' -RecordsState 'published').RunContext.StepsOk) | Should -Contain 'recommendations'
        $s = Send $r.RunContext $r.ExitReason
        $s.Run.Job | Should -Be 'si-identity'; $s.Run.Outcome | Should -Be 'ok'
        @($s.Run.StepsOk) | Should -Contain 'handover'
        @($s.Run.StepsOk) | Should -Contain 'run'
    }
    It 'records not all published: failed, step records; a failed part: nothing more (that part reported itself)' {
        $f = Get-SICollectRunReport -Engine 'endpoint' -RecordsState 'failed'
        $f.ExitReason | Should -Be 'error'
        $f.RunContext.FailedStep | Should -Be 'records'
        $f.Message | Should -Not -Match '#\d{3}'
        (Send $f.RunContext $f.ExitReason 'identified' $f.Message).Run.FailedStep | Should -Be 'records'
        Get-SICollectRunReport -Engine 'endpoint' -RecordsState 'published' -FailedParts 1 | Should -BeNullOrEmpty
        Get-SICollectRunReport -Engine 'endpoint' -RecordsState 'not-last' | Should -BeNullOrEmpty
    }
    It 'the steps are the engine run''s own stage list' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1'))
        $t -match "\`$__st = @\(([^)]*)\)" | Should -BeTrue
        $stages = @([regex]::Matches($Matches[1], "'([A-Za-z]+)'") | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() })
        $stages.Count | Should -BeGreaterThan 5
        @(Get-SICollectRunStepsOk -Engine 'identity')[0..($stages.Count - 1)] | Should -Be $stages
    }
}

Describe 'SIv3-TelemetryStepsOk: the wiring' {
    It 'the engine run: a producer or a part does not send the job''s ok; the stages it finished are its StepsOk' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\asset-profiling\Invoke-SIEngineRun.ps1'))
        $t | Should -Match ([regex]::Escape("SuppressJobOk    = (`$Phase -in @('discover', 'parts'))"))
        $t | Should -Match ([regex]::Escape("-NotePropertyName 'StepsOk' -NotePropertyValue ([string[]]@(`$stages | Where-Object { `$runContext.StageResults.ContainsKey(`$_) }"))
    }
    It 'the container: the execution that published the records sends the one report' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1'))
        $t | Should -Match 'Get-SICollectRunReport -Engine \$recEngineName -RecordsState \$recState -FailedParts \$recFailedParts'
        $t | Should -Match 'Send-SITelemetryRunEnd -RunContext \$recReport\.RunContext'
    }
    It 'Risk Analysis, the pipeline and the data sync fill StepsOk' {
        ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))) | Should -Match "@\('ra-query', 'ra-report'\)"
        ([IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))) | Should -Match "\`$pipeCtx \| Add-Member -NotePropertyName StepsOk"
        $ds = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\pro-data\Invoke-SIDataSync.ps1'))
        $ds | Should -Match '\$failedSteps -notcontains \$_'
        $ds | Should -Match "\[string\]\`$rhEnd\.Exit -eq 'success'.{0,120}Send-SITelemetryRunEnd"
    }
}
