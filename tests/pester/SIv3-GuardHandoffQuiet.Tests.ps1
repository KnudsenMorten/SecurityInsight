#Requires -Version 5.1
<#
    A RECOMMENDATION THAT MOVED TO THE DEFENDER REPORT IS NOT A LOSS -- AND A WARNING SAYS "WARNING" ONCE.

    Measured in the live 2.2.460 -> 3.0 upgrade test (2026-10-05, #261 round 1), Risk Analysis -Detailed, the first
    3.0 night of an upgraded install:
        [INFO] [RowCountGuard] Azure_Recommendations_Detailed: 720 -> 106. The other recommendations are now
               reported in Azure_DefenderRecommendations_Detailed (1681 row(s)) -- moved, not lost.
        WARNING: WARNING: the completeness of your Risk Analysis reports -- 1 report(s) produced far fewer
               findings than the previous run: Azure_Recommendations_Detailed: 720 -> 106 (handed-off) ...
    The row-count guard recognised the hand-off (informational), and the guard event raised a warning about it
    anyway -- every upgraded install would see it on its first night (and a mail, where mail is set up). The
    guard event now leaves HANDED-OFF out (HANDOFF-LOST, a real loss, still raises), and a guard warning no longer
    repeats "WARNING:" in front of the console's own "WARNING:".
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Guard.ps1')
    $script:HandedOff = @{ Report = 'Azure_Recommendations_Detailed'; Kind = 'HANDED-OFF'; Previous = 720; Current = 106; Successor = 'Azure_DefenderRecommendations_Detailed'; SuccessorCurrent = 1681 }
}

Describe 'the row-count guard event' {
    It 'a hand-off alone raises no event' {
        @(Get-SIGuardCallsForRowCount -Template 'Detailed' -Findings @($script:HandedOff)).Count | Should -Be 0
    }

    It 'with a real drop beside it, the event lists only the real drop' {
        $c = @(Get-SIGuardCallsForRowCount -Template 'Detailed' -Findings @($script:HandedOff, @{ Report = 'Attack paths'; Kind = 'LARGE-DROP'; Previous = 75; Current = 3 }))
        $c.Count | Should -Be 1
        $c[0].Detail | Should -Match 'Attack paths: 75 -> 3'
        $c[0].Detail | Should -Not -Match 'Azure_Recommendations_Detailed'
        (@($c[0].Values | Where-Object { $_.Name -eq 'reports' })[0]).Measured | Should -Be 1
    }

    It 'a hand-off whose receiving report produced nothing (HANDOFF-LOST) still raises, in plain words' {
        $c = @(Get-SIGuardCallsForRowCount -Template 'Detailed' -Findings @(@{ Report = 'Azure_Recommendations_Detailed'; Kind = 'HANDOFF-LOST'; Previous = $null; Current = 106; Successor = 'Azure_DefenderRecommendations_Detailed' }))
        $c.Count | Should -Be 1
        $c[0].Detail | Should -Not -Match 'handoff-lost'
    }
}

Describe 'the console line of a guard event' {
    BeforeEach { $script:Lines = New-Object System.Collections.Generic.List[string] }

    It 'a warning does not start with "WARNING:" (the console adds that itself)' {
        # row-drop is off by default (the "is off by default" line is INFO since the guard relief) -- switched on here, because
        # this test is about the console line of the event itself
        $null = Send-SIGuardEvent -GuardId 'ra.output.row-drop' -Outcome warning -Detail 'x' -RunId 'quiet-1' -StateStore (New-SIGuardMemoryStateStore) `
                    -Globals @{ SI_Telemetry_Enabled = $false; SI_Guard_RaOutputRowDrop_Enabled = $true } -NoMail -NoTelemetry -RunHealth { } -Log { param($l, $m) $script:Lines.Add("$l|$m") }
        $first = @($script:Lines | Where-Object { $_ -like 'WARN|*' })[0]
        $first | Should -Not -BeNullOrEmpty
        $first | Should -Not -Match '^WARN\|WARNING:'
    }

    It 'other outcomes still name the outcome' {
        # #448: row-drop is off by default -- switched on here, because this test is about its console line
        $null = Send-SIGuardEvent -GuardId 'ra.output.row-drop' -Outcome held -Detail 'x' -RunId 'quiet-2' -StateStore (New-SIGuardMemoryStateStore) `
                    -Globals @{ SI_Telemetry_Enabled = $false; SI_Guard_RaOutputRowDrop_Enabled = $true } -NoMail -NoTelemetry -RunHealth { } -Log { param($l, $m) $script:Lines.Add("$l|$m") }
        @($script:Lines | Where-Object { $_ -like 'WARN|HELD:*' }).Count | Should -Be 1
    }
}
