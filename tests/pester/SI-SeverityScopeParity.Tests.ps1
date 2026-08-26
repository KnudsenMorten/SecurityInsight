#Requires -Version 5.1
<#
    THE DETAILED REPORT SILENTLY OMITTED SEVERITIES ITS OWN SUMMARY COUNTED.

    Found 2026-08-26 by running the filter audit after an operator asked why a report showed
    "474 rows -> 200 rows after filters". The engine's post-query scope filter
    (Invoke-RiskAnalysis.ps1, $filterSpecs) keeps a row only if its SecuritySeverity value appears in
    that report's SecuritySeverityScope. Blanks are kept; a non-blank out-of-scope value is dropped.

    THREE reports declared a NARROWER scope than their own Summary twin:

        report                            Detailed scope                  Summary scope
        Device_Missing_CVEs               ... Medium                      ... Medium, Low
        Device_Recommendations            ... Medium-High                 ... Medium, Low
        Azure_Recommendations             ... Medium-High                 ... Medium, Low

    Measured impact, from the filter audit on a live estate:

        Device_Missing_CVEs_Detailed        191 dropped   (Low)
        Device_Recommendations_Detailed     274 dropped   (Medium 249, Low 25)   =  58% of the report
        Azure_Recommendations_Detailed      541 dropped   (Low 408, Medium 133)  =  92% of the report

    ...and on a production estate the same three reports lost 1,742 / 59,225 / 19,714 rows -- the
    Azure one shipping 1,474 of 21,188 rows, again 93%.

    🔑 WHY THIS IS A DEFECT AND NOT A SETTING. The Summary says "N findings" counting Low and Medium;
    the paired Detailed -- the sheet an operator opens to see WHICH assets -- silently omitted them.
    The count and the list disagreed by construction, which is exactly audit #25's shape
    (ImpactedAssetCount != ImpactedAssetsList).

    Operator ruling 2026-08-26: *"all reports must default to Very High / High / Medium-High /
    Medium / Low"* and *"detailed must match summary"*.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Yaml   = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'

    Import-Module powershell-yaml -ErrorAction Stop
    $parsed = ConvertFrom-Yaml (Get-Content $script:Yaml -Raw)
    $script:Reports = @($parsed.Values | ForEach-Object { $_ } | Where-Object { $_.ReportName })

    # The full severity ladder. This is the DEFAULT every report ships with.
    $script:FullSeverity = @('Very High', 'High', 'Medium-High', 'Medium', 'Low')
    # Tier has always been complete; asserted so it cannot quietly regress the same way.
    $script:FullTier     = @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3')
}

Describe 'every shipped report scopes the FULL severity ladder' {

    It 'the catalog parses and carries the expected number of reports' {
        $script:Reports.Count | Should -BeGreaterThan 100
    }

    It '🔴 no report declares a NARROWER SecuritySeverityScope than the full five' {
        # A narrow scope does not produce an empty report -- it produces a PARTIAL one, which is the
        # dangerous shape: it looks populated and can't be told apart from an estate that genuinely
        # has no Low/Medium findings.
        $bad = @($script:Reports | Where-Object {
            $_.SecuritySeverityScope -and
            (@(Compare-Object $script:FullSeverity @($_.SecuritySeverityScope)).Count -ne 0)
        })
        $names = ($bad | ForEach-Object { "$($_.ReportName) => $($_.SecuritySeverityScope -join '|')" }) -join "; "
        $bad.Count | Should -Be 0 -Because "these narrow the severity ladder: $names"
    }

    It 'no report declares a narrower CriticalityTierLevelScope than all four tiers' {
        $bad = @($script:Reports | Where-Object {
            $_.CriticalityTierLevelScope -and
            (@(Compare-Object $script:FullTier @($_.CriticalityTierLevelScope)).Count -ne 0)
        })
        $names = ($bad | ForEach-Object { $_.ReportName }) -join ', '
        $bad.Count | Should -Be 0 -Because "these narrow the tier ladder: $names"
    }

    It 'only the TEMPLATE entries may omit a severity scope' {
        # A report with no scope skips the filter entirely (the engine `continue`s on an empty scope),
        # which is fine -- but a REPORT reaching that state by accident would look identical to one
        # that was deliberately unfiltered. Only the template list-entries are allowed here.
        $noScope = @($script:Reports | Where-Object { -not $_.SecuritySeverityScope } |
                     ForEach-Object { $_.ReportName })
        foreach ($n in $noScope) {
            $n | Should -Match '^(RiskAnalysis_(Summary|Detailed)|AssetSimulationComplex(Summary|Detailed))$' `
                -Because "'$n' has no SecuritySeverityScope but is not a template entry"
        }
    }
}

Describe '🔴 SUMMARY AND DETAILED MUST AGREE -- the count and the list cannot disagree by design' {

    It 'every Summary/Detailed pair declares the SAME SecuritySeverityScope' {
        # This is the invariant that actually failed. The Summary counted Low and Medium findings and
        # the Detailed omitted them, so the number and the asset list described different populations
        # -- audit #25's shape, in a different column.
        $byName = @{}
        foreach ($r in $script:Reports) { $byName[[string]$r.ReportName] = $r }

        $mismatched = New-Object System.Collections.Generic.List[string]
        foreach ($r in $script:Reports) {
            $n = [string]$r.ReportName
            if ($n -notmatch '_Detailed$') { continue }
            $twin = $byName[($n -replace '_Detailed$', '_Summary')]
            if (-not $twin) { continue }
            $a = @($r.SecuritySeverityScope    | Where-Object { $_ }) | Sort-Object
            $b = @($twin.SecuritySeverityScope | Where-Object { $_ }) | Sort-Object
            # Template entries carry no scope on EITHER side -- not a pair to compare.
            if (@($a).Count -eq 0 -and @($b).Count -eq 0) { continue }
            if (@($a).Count -eq 0 -or  @($b).Count -eq 0) { [void]$mismatched.Add("$n one side has NO scope"); continue }
            if (@(Compare-Object $a $b).Count -ne 0) {
                [void]$mismatched.Add("$n [$($a -join '|')] vs twin [$($b -join '|')]")
            }
        }
        $mismatched.Count | Should -Be 0 -Because ($mismatched -join '; ')
    }

    It 'every Summary/Detailed pair declares the SAME CriticalityTierLevelScope' {
        $byName = @{}
        foreach ($r in $script:Reports) { $byName[[string]$r.ReportName] = $r }

        $mismatched = New-Object System.Collections.Generic.List[string]
        foreach ($r in $script:Reports) {
            $n = [string]$r.ReportName
            if ($n -notmatch '_Detailed$') { continue }
            $twin = $byName[($n -replace '_Detailed$', '_Summary')]
            if (-not $twin) { continue }
            $a = @($r.CriticalityTierLevelScope    | Where-Object { $_ }) | Sort-Object
            $b = @($twin.CriticalityTierLevelScope | Where-Object { $_ }) | Sort-Object
            # Template entries carry no scope on EITHER side -- not a pair to compare.
            if (@($a).Count -eq 0 -and @($b).Count -eq 0) { continue }
            if (@($a).Count -eq 0 -or  @($b).Count -eq 0) { [void]$mismatched.Add("$n one side has NO scope"); continue }
            if (@(Compare-Object $a $b).Count -ne 0) {
                [void]$mismatched.Add("$n [$($a -join '|')] vs twin [$($b -join '|')]")
            }
        }
        $mismatched.Count | Should -Be 0 -Because ($mismatched -join '; ')
    }

    It 'the three reports that caused this are specifically covered' {
        # Named explicitly so the regression is recognisable in a failure message years from now.
        foreach ($n in @('Device_Missing_CVEs_Detailed',
                         'Device_Recommendations_Detailed',
                         'Azure_Recommendations_Detailed')) {
            $r = $script:Reports | Where-Object { $_.ReportName -eq $n }
            $r | Should -Not -BeNullOrEmpty -Because "$n must exist in the catalog"
            @(Compare-Object $script:FullSeverity @($r.SecuritySeverityScope)).Count |
                Should -Be 0 -Because "$n dropped up to 92% of its rows before this was fixed"
        }
    }
}
