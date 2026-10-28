#Requires -Version 5.1
<#
    THE ROW-COUNT GUARD MUST SEE A REPORT THAT FAILED OUTRIGHT (#119).

    The guard compared only the reports that PRODUCED a count. A report that threw never reaches the
    line that records its count, so it was never compared -- and the history write REPLACED the
    template's baseline with this run's counts, erasing the failed report's last value. A report that
    failed every night therefore printed "no report lost its findings" forever. And when EVERY report
    failed there were no counts at all, so the guard did not run.

    Now: the engine records every report it ATTEMPTS; attempted + no count + findings last time =
    MISSING (a WARNING -- its findings are UNKNOWN, not remediated); history is MERGED, so the baseline
    survives until the report produces a count again; a report merely removed from the template is
    never flagged.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RowCountGuard.ps1')
    $script:Warned = New-Object System.Collections.Generic.List[string]
    # SCRIPT scope, never global: a global stub outlives this file in the gate's single process and
    # once silenced the Trend suite's output. The functions under test are dot-sourced into this same
    # scope, so they still resolve it.
    function script:Write-Warn2 { param([string]$m) [void]$script:Warned.Add($m) }
    function script:Write-Info  { param([string]$m) }

    $raw = [regex]::Replace((Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1') -Raw), '(?s)<#.*?#>', '')
    $script:CodeNC = (($raw -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
}

Describe 'Get-RARowCountRegressions -- attempted but no result' {

    It 'flags MISSING when an attempted report produced no count and had findings last run' {
        $f = @(Get-RARowCountRegressions -Previous @{ A = 40; B = 7 } -Current @{ A = 40 } -Attempted @('A','B'))
        $f.Count       | Should -Be 1
        $f[0].Report   | Should -Be 'B'
        $f[0].Kind     | Should -Be 'MISSING'
        $f[0].Previous | Should -Be 7
    }

    It 'stays silent for a report REMOVED from the template (not attempted)' {
        @(Get-RARowCountRegressions -Previous @{ Gone = 12 } -Current @{} -Attempted @()).Count | Should -Be 0
    }

    It 'stays silent for a brand-new report that failed on its first ever run (no baseline to lose)' {
        @(Get-RARowCountRegressions -Previous @{} -Current @{} -Attempted @('New')).Count | Should -Be 0
    }

    It 'stays silent when the missing report legitimately had zero findings last time' {
        @(Get-RARowCountRegressions -Previous @{ Z = 0 } -Current @{} -Attempted @('Z')).Count | Should -Be 0
    }

    It 'still reports WENT-TO-ZERO alongside MISSING' {
        $f = @(Get-RARowCountRegressions -Previous @{ A = 40; B = 7 } -Current @{ A = 0 } -Attempted @('A','B'))
        @($f | ForEach-Object { $_.Kind } | Sort-Object) | Should -Be @('MISSING','WENT-TO-ZERO')
    }
}

Describe 'Invoke-RARowCountGuard -- the baseline survives a failed report' {

    BeforeEach {
        $script:Warned.Clear()
        $script:Settings = Join-Path ([IO.Path]::GetTempPath()) ('si-rcg-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Settings -Force | Out-Null
    }
    AfterEach {
        if ($script:Settings -and $script:Settings.StartsWith([IO.Path]::GetTempPath())) {
            Remove-Item -LiteralPath $script:Settings -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'a report failing TWO nights running is flagged BOTH nights (history merged, not replaced)' {
        $null = Invoke-RARowCountGuard -SettingsPath $script:Settings -TemplateName 'T' -Counts @{ A = 10; B = 5 } -Attempted @('A','B')
        $n1 = @(Invoke-RARowCountGuard -SettingsPath $script:Settings -TemplateName 'T' -Counts @{ A = 10 } -Attempted @('A','B'))
        $n2 = @(Invoke-RARowCountGuard -SettingsPath $script:Settings -TemplateName 'T' -Counts @{ A = 10 } -Attempted @('A','B'))
        $n1.Count | Should -Be 1
        $n2.Count | Should -Be 1 -Because 'replacing the history erased the baseline, so the second failure was invisible'
        $n2[0].Kind | Should -Be 'MISSING'
    }

    It 'the MISSING line says the findings are UNKNOWN, not remediated' {
        $null = Invoke-RARowCountGuard -SettingsPath $script:Settings -TemplateName 'T' -Counts @{ B = 5 } -Attempted @('B')
        $null = Invoke-RARowCountGuard -SettingsPath $script:Settings -TemplateName 'T' -Counts @{} -Attempted @('B')
        ($script:Warned -join "`n") | Should -Match 'MISSING\s+B: 5 finding\(s\) last run, NO RESULT'
        ($script:Warned -join "`n") | Should -Match 'UNKNOWN, not remediated'
    }

    It 'a report that recovers updates its baseline normally' {
        $null = Invoke-RARowCountGuard -SettingsPath $script:Settings -TemplateName 'T' -Counts @{ B = 5 } -Attempted @('B')
        $null = Invoke-RARowCountGuard -SettingsPath $script:Settings -TemplateName 'T' -Counts @{ B = 9 } -Attempted @('B')
        (Read-RARowCountHistory -Path (Get-RARowCountHistoryPath -SettingsPath $script:Settings) -TemplateName 'T')['B'] | Should -Be 9
    }
}

Describe 'WIRING -- the engine records attempts and hands them to the guard' {
    It 'every report is recorded as attempted right after its name is resolved' {
        $script:CodeNC | Should -Match '\$ReportName\s+= \$Entry\.ReportName\s*\n\s*if \(\$null -ne \$global:RA_ReportsAttemptedThisRun\) \{ \[void\]\$global:RA_ReportsAttemptedThisRun\.Add'
    }
    It 'the guard receives the attempted list' {
        $script:CodeNC | Should -Match '-Attempted \$__attempted'
    }
    It 'the guard runs even when NO report produced a count (every report failed)' {
        $script:CodeNC | Should -Match '-or \$__attempted\.Count -gt 0\)'
    }
}
