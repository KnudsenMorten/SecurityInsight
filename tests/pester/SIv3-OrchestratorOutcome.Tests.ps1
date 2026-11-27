#Requires -Version 5.1
<#
    #1427 HOW AN ENGINE RUN ENDED IS THE RUN'S OWN WORD (fix request 1d044cd3, 3.1.53). The container entry point took
    $LASTEXITCODE after the orchestrator -- a PowerShell script -- as the run's outcome. It is only the exit code of the last
    native program the run happened to start (or none at all), so a recommendations phase that published 949 rows with its
    completion marker said 'error', and every Azure run in parts reported "recommendations not refreshed this run: the
    publishing process ended error" -- a false warning at every install with Defender for Cloud.
    Offline: the orchestrators are small fake scripts; the "native program" is this test's own pwsh started with `exit 3`.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'container\_shared\SI-ContainerConfig.ps1')
    $script:Pwsh = (Get-Process -Id $PID).Path
    function script:New-FakeOrchestrator([string]$Name, [string]$Body) {
        $p = Join-Path $TestDrive ($Name + '.ps1')
        Set-Content -LiteralPath $p -Value $Body -Encoding UTF8
        $p
    }
    # the parent reads the child's result file exactly as Start-SIInContainer.ps1 does (JSON on disk, ConvertFrom-Json)
    function script:Get-ParentReading($Outcome, $ProcessExit) {
        $f = Join-Path $TestDrive ('res-{0}.json' -f [guid]::NewGuid().ToString('N'))
        [IO.File]::WriteAllText($f, (ConvertTo-Json -Compress -InputObject (Get-SIRecommendationsPhaseResult -Outcome $Outcome)))
        $said = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
        Resolve-SIRecommendationsRefresh -ProcessExit $ProcessExit -Said $said
    }
    $script:Native = "& '$((Get-Process -Id $PID).Path)' -NoProfile -NonInteractive -Command 'exit 3'"
}

Describe '#1427 the run''s outcome -- not the exit code a native program left behind' {
    AfterEach { $global:SI_LastRunExitReason = $null }

    It 'THE BUG: an orchestrator that ends success after a native command returned non-zero -- success, Exit 0, refreshed' {
        $o = New-FakeOrchestrator 'native-then-success' ($script:Native + "`n" + '$global:SI_LastRunExitReason = ''success''' + "`n" + '[pscustomobject]@{ Run = ''ok'' }')
        $r = Invoke-SIContainerOrchestrator -OrchestratorScript $o -OrchestratorArgs @{} 3>$null
        $r.ExitCode | Should -Be 3 -Because 'the native program really did return 3 -- kept as information'
        $r.ExitReason | Should -BeExactly 'success'
        $r.Exit | Should -Be 0
        $res = Get-SIRecommendationsPhaseResult -Outcome $r
        $res.ExitReason | Should -BeExactly 'success'
        $res.Exit | Should -Be 0
        $p = Get-ParentReading $r $r.Exit
        $p.Refreshed | Should -BeTrue
        $p.Reason | Should -BeExactly ''
    }
    It 'the code before the fix gave ''error'' for that same run (the shape that was reported live)' {
        # 3.1.52: ExitReason = if ($orchExit -ne 0) { 'error' } ... with $orchExit = $LASTEXITCODE (3 here; $null in a process that ran no native program)
        foreach ($stale in 3, $null) { $(if ($stale -ne 0) { 'error' } else { 'success' }) | Should -BeExactly 'error' }
    }
    It 'an exit code left in the caller BEFORE the run is never the run''s (it is set to 0 right before)' {
        $o = New-FakeOrchestrator 'plain-success' '$global:SI_LastRunExitReason = ''success'''
        $global:LASTEXITCODE = 7
        $r = Invoke-SIContainerOrchestrator -OrchestratorScript $o 3>$null
        $r.ExitCode | Should -Be 0
        $r.Exit | Should -Be 0
        $r.ExitReason | Should -BeExactly 'success'
    }
    It 'a reason left by an EARLIER run in the process is cleared -- a run that says nothing and exits 0 is not success' {
        $global:SI_LastRunExitReason = 'success'
        $o = New-FakeOrchestrator 'silent' '$null = 1'
        $r = Invoke-SIContainerOrchestrator -OrchestratorScript $o 3>$null
        $r.ExitReason | Should -BeExactly ''
        $r.Exit | Should -Be 0
        $p = Get-ParentReading $r 0
        $p.Refreshed | Should -BeFalse
        $p.Reason | Should -Match '^the publishing process did not say how it ended'
    }
    It 'an orchestrator that throws -- error, Exit 1; the parent: not refreshed, exit code 1' {
        $o = New-FakeOrchestrator 'throws' ('$global:SI_LastRunExitReason = ''success''' + "`n" + 'throw ''Nothing was published: boom''')
        $r = Invoke-SIContainerOrchestrator -OrchestratorScript $o 3>$null
        $r.ExitReason | Should -BeExactly 'error'
        $r.Exit | Should -Be 1
        (Get-SIRecommendationsPhaseResult -Outcome $r).ExitReason | Should -BeExactly 'error'
        $p = Get-ParentReading $r $r.Exit
        $p.Refreshed | Should -BeFalse
        $p.Reason | Should -BeExactly 'the publishing process ended with exit code 1 (its run-health record azure-recommendations says why)'
        # the result file alone (a process that still ended 0) says it as well
        (Get-ParentReading $r 0).Reason | Should -BeExactly 'the publishing process ended error (its run-health record azure-recommendations says why)'
    }
    It 'a thrown run says so in the log (message, position, stack) -- as before' {
        $o = New-FakeOrchestrator 'throws2' 'throw ''boom-1427'''
        $w = @(Invoke-SIContainerOrchestrator -OrchestratorScript $o 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })
        ($w | ForEach-Object Message) -join "`n" | Should -Match 'orchestrator threw: boom-1427'
    }
    It 'an orchestrator that does `exit 2` with no reason -- error, Exit 2 (a deliberate exit is kept); the parent: exit code 2' {
        $o = New-FakeOrchestrator 'exit2' 'exit 2'
        $r = Invoke-SIContainerOrchestrator -OrchestratorScript $o 3>$null
        $r.ExitReason | Should -BeExactly 'error'
        $r.Exit | Should -Be 2
        $r.ExitCode | Should -Be 2
        (Get-SIRecommendationsPhaseResult -Outcome $r).Exit | Should -Be 2
        $p = Get-ParentReading $r $r.Exit
        $p.Refreshed | Should -BeFalse
        $p.Reason | Should -BeExactly 'the publishing process ended with exit code 2 (its run-health record azure-recommendations says why)'
    }
    It 'a partial publish stays partial: Exit 0 (as before), not refreshed -- "ended success-partial"' {
        $o = New-FakeOrchestrator 'partial' ($script:Native + "`n" + '$global:SI_LastRunExitReason = ''success-partial''')
        $r = Invoke-SIContainerOrchestrator -OrchestratorScript $o 3>$null
        $r.Exit | Should -Be 0
        $r.ExitReason | Should -BeExactly 'success-partial'
        $p = Get-ParentReading $r 0
        $p.Refreshed | Should -BeFalse
        $p.Reason | Should -BeExactly 'the publishing process ended success-partial (its run-health record azure-recommendations says why)'
    }
    It 'the arguments reach the orchestrator' {
        $o = New-FakeOrchestrator 'args' ('param([string]$Engine, [int]$ShardIndex)' + "`n" + '$global:SI_Test1427 = ''{0}|{1}'' -f $Engine, $ShardIndex; $global:SI_LastRunExitReason = ''success''')
        $r = Invoke-SIContainerOrchestrator -OrchestratorScript $o -OrchestratorArgs @{ Engine = 'azure'; ShardIndex = 2 } 3>$null
        $global:SI_Test1427 | Should -BeExactly 'azure|2'
        $r.Exit | Should -Be 0
        Remove-Variable -Name SI_Test1427 -Scope Global -ErrorAction SilentlyContinue
    }
    It 'the decision table (pure)' {
        (Resolve-SIOrchestratorOutcome -ExitCode 3 -Reason 'success').Exit | Should -Be 0
        (Resolve-SIOrchestratorOutcome -ExitCode $null -Reason 'success').ExitReason | Should -BeExactly 'success'
        (Resolve-SIOrchestratorOutcome -ExitCode 0 -Threw -Reason 'success').ExitReason | Should -BeExactly 'error'
        (Resolve-SIOrchestratorOutcome -ExitCode $null).Exit | Should -Be 0
        (Resolve-SIOrchestratorOutcome -ExitCode $null).ExitReason | Should -BeExactly ''
        (Resolve-SIOrchestratorOutcome -ExitCode 4).ExitReason | Should -BeExactly 'error'
        (Resolve-SIOrchestratorOutcome -ExitCode 0 -Reason 'something-else').Exit | Should -Be 1
    }
}

Describe '#1427 wiring: every phase reads the run''s own outcome' {
    BeforeAll { $script:Src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'container\Start-SIInContainer.ps1')) }
    It 'the entry point runs the orchestrator through the outcome and takes Exit from it -- no $LASTEXITCODE after the run' {
        $script:Src | Should -Match ([regex]::Escape('$orchOutcome = Invoke-SIContainerOrchestrator -OrchestratorScript $orchestrator -OrchestratorArgs $orchArgs'))
        $script:Src | Should -Match ([regex]::Escape('$orchExit = $orchOutcome.Exit'))
        $script:Src | Should -Not -Match ([regex]::Escape('$orchExit = $LASTEXITCODE'))
        $at = $script:Src.IndexOf('$orchExit = $orchOutcome.Exit')
        # the recommendations result, the part's queue delete, the producer's queueing, the discover hand-over and the final exit follow it
        foreach ($after in '(Get-SIRecommendationsPhaseResult -Outcome $orchOutcome)',
                           'if ($useQueue -and $queueMessageId -and ($orchExit -eq 0 -or $null -eq $orchExit)) {',
                           'if ($producerDiscovers -and ($orchExit -eq 0 -or $null -eq $orchExit)) {',
                           "if (`$collectChild -eq 'discover' -and (`$orchExit -eq 0 -or `$null -eq `$orchExit)) {",
                           'if ($orchExit -gt 0) { exit $orchExit }') {
            $script:Src.IndexOf($after) | Should -BeGreaterThan $at -Because $after
        }
    }
    It 'the parent reads the phase through the same decision' {
        $script:Src | Should -Match ([regex]::Escape('$out = Resolve-SIRecommendationsRefresh -ProcessExit $code -Said $said'))
        $script:Src | Should -Match ([regex]::Escape('if (-not $out.Refreshed) { Write-Warning ('))
    }
}
