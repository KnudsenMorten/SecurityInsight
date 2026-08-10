#Requires -Version 5.1
<#
    AUDIT #57.1(a) -- unit tests for the run-over-run row-count regression guard.

    The guard exists because SI has had THREE silent-loss defects (#48, v2.2.415, #57) in which a
    run reported success while producing less data than the day before, and a human -- never the
    engine -- noticed. These tests pin the two behaviours that make it useful and the two that
    stop it becoming noise.
#>

BeforeAll {
    $shared = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\_shared'
    . (Join-Path $shared 'RA-RowCountGuard.ps1')
}

Describe 'row-count guard -- audit #57.1(a)' {

    It 'flags a report that produced findings yesterday and none today (the #57 signature)' {
        # Azure_Recommendations_Summary went 75 -> 0 overnight and nothing noticed.
        $prev = @{ 'Azure_Recommendations_Summary' = 75 }
        $curr = @{ 'Azure_Recommendations_Summary' = 0  }
        $f = @(Get-RARowCountRegressions -Previous $prev -Current $curr)
        $f.Count | Should -Be 1
        $f[0].Kind     | Should -Be 'WENT-TO-ZERO'
        $f[0].Previous | Should -Be 75
    }

    It 'flags a large drop that is not all the way to zero' {
        $f = @(Get-RARowCountRegressions -Previous @{ R = 100 } -Current @{ R = 5 } -DropFraction 0.8)
        $f.Count   | Should -Be 1
        $f[0].Kind | Should -Be 'LARGE-DROP'
    }

    It 'stays SILENT on a clean tenant that legitimately has nothing (0 -> 0)' {
        # Three of six cross-domain reports return 0 on the reference tenant every run. If the
        # guard shouted about those it would be muted within a week, and then it protects nothing.
        @(Get-RARowCountRegressions -Previous @{ R = 0 } -Current @{ R = 0 }).Count | Should -Be 0
    }

    It 'stays SILENT when findings are remediated down to zero from a SMALL baseline' {
        # A customer fixing their last finding is success, not a defect. It is still reported as
        # WENT-TO-ZERO (the transition is what matters) -- but never as a failure. This test pins
        # that the guard RETURNS it rather than throwing.
        { Get-RARowCountRegressions -Previous @{ R = 1 } -Current @{ R = 0 } } | Should -Not -Throw
    }

    It 'stays SILENT when a report GROWS -- #57 legitimately took one report 75 -> 334' {
        @(Get-RARowCountRegressions -Previous @{ 'Azure_Recommendations_Summary' = 75 } `
                                    -Current  @{ 'Azure_Recommendations_Summary' = 334 }).Count | Should -Be 0
    }

    It 'ignores a report with no prior history rather than inventing a baseline' {
        @(Get-RARowCountRegressions -Previous @{} -Current @{ BrandNewReport = 0 }).Count | Should -Be 0
    }

    It 'ignores a small dip that is ordinary data movement' {
        # 4 -> 3 on an attack-path report was real drift. The guard must not cry about that.
        @(Get-RARowCountRegressions -Previous @{ R = 4 } -Current @{ R = 3 } -DropFraction 0.8).Count | Should -Be 0
    }

    It 'reports every affected report, not just the first' {
        $f = @(Get-RARowCountRegressions `
                -Previous @{ A = 75; B = 304; C = 10 } `
                -Current  @{ A = 0;  B = 0;   C = 10 })
        $f.Count | Should -Be 2
        (@($f | ForEach-Object { $_.Report }) -join ',') | Should -Be 'A,B'
    }

    It 'survives a corrupt history file instead of breaking the run' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("si-rcg-{0}.json" -f ([guid]::NewGuid().ToString('N')))
        Set-Content -LiteralPath $tmp -Value '{ this is not json' -Encoding UTF8
        try {
            $h = Read-RARowCountHistory -Path $tmp -TemplateName 'RiskAnalysis_Summary'
            $h.Count | Should -Be 0
        } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }

    It 'the ENGINE records a count on the zero-row path too, not only after filters' {
        # 🪤 REGRESSION GUARD. The first cut captured only at "rows after filters". A report that
        # returns nothing hits `continue` at the "No rows returned from query" early exit and never
        # reaches that line -- so the one case this guard exists to catch (a report going to zero,
        # the #57 signature) was the one case it silently could not see. Found by smoke-running the
        # engine, NOT by the unit tests above, which all passed while the feature was inert.
        $engine = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
        $src    = [System.IO.File]::ReadAllText($engine)

        # both capture sites must exist
        ([regex]::Matches($src, '\$global:RA_RowCountsThisRun\[\[string\]\$ReportName\]')).Count |
            Should -BeGreaterOrEqual 2 -Because 'the post-filter path AND the zero-row early-exit must both record'

        # and the zero-row one must sit BEFORE its `continue`, or it never runs
        $idxNoRows = $src.IndexOf('No rows returned from query')
        $idxNoRows | Should -BeGreaterThan 0
        $window = $src.Substring($idxNoRows, [Math]::Min(900, $src.Length - $idxNoRows))
        $posRecord = $window.IndexOf('RA_RowCountsThisRun')
        # Match the STATEMENT (a line that is just `continue`), not the word. A first cut used
        # IndexOf('continue') and matched the word inside this very fix's own comment.
        $mCont = [regex]::Match($window, '(?m)^\s*continue\s*$')
        $mCont.Success | Should -BeTrue -Because 'the early exit must still continue'
        $posRecord     | Should -BeGreaterThan 0 -Because 'the zero must be recorded at the early exit'
        $posRecord     | Should -BeLessThan $mCont.Index -Because 'recording after `continue` would never execute'
    }

    It 'round-trips history per TEMPLATE, so Summary and Detailed cannot overwrite each other' {
        # The same report name yields different counts under Summary vs Detailed
        # (Azure_Recommendations: 334 vs 507). Keying by report alone would corrupt both.
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("si-rcg-{0}.json" -f ([guid]::NewGuid().ToString('N')))
        try {
            Write-RARowCountHistory -Path $tmp -TemplateName 'RiskAnalysis_Summary'  -Counts @{ R = 334 }
            Write-RARowCountHistory -Path $tmp -TemplateName 'RiskAnalysis_Detailed' -Counts @{ R = 507 }
            (Read-RARowCountHistory -Path $tmp -TemplateName 'RiskAnalysis_Summary')['R']  | Should -Be 334
            (Read-RARowCountHistory -Path $tmp -TemplateName 'RiskAnalysis_Detailed')['R'] | Should -Be 507
        } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}
