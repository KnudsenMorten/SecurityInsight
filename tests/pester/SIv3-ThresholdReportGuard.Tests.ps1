#Requires -Version 5.1
<#
    #407 -- A ONE-ROW THRESHOLD REPORT GOING 1 -> 0 IS A RESOLVED FINDING, NOT A LOST RESULT.

    Ring 1, 2026-10-05/06: an admin self-activated Global Administrator through PIM for 8 hours. The 23:13 identity
    collection counted 6 permanent Global Administrators, the 08:38 one 5 again. Identity_TooManyGlobalAdmins_Summary
    (`summarize GACount = dcount(...)` then `where GACount > 5`) went 0 -> 1 -> 0, and the row-count guard read the
    second transition as WENT-TO-ZERO: the Risk Analysis run was recorded partial and the data sync held the collection.

    Now:
      * the threshold reports are listed explicitly (Get-RAThresholdReportNames) and the list is held in step with the
        shipped catalog by the shape detector (Test-RAThresholdShapedQuery) -- a new report of that shape fails here;
      * for them 1 -> 0 is BELOW-THRESHOLD: a logged warning, never an incomplete report, not in the row-drop event;
      * every other report keeps the #347 protection: WENT-TO-ZERO still makes the run partial (negative tests), and a
        threshold report that FAILED (MISSING) is still incomplete.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    if ($env:SI_TEST_ROOT) { $script:SIRoot = $env:SI_TEST_ROOT }
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RowCountGuard.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Guard.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $script:Warned = New-Object System.Collections.Generic.List[string]
    function script:Write-Warn2 { param([string]$m) [void]$script:Warned.Add($m) }
    function script:Write-Info  { param([string]$m) }
    $script:Catalog = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml') | ConvertFrom-SIYaml
    $script:Ga = 'Identity_TooManyGlobalAdmins_Summary'
}

Describe 'which reports are threshold reports' {
    It 'the explicit list is exactly the reports of that shape in the shipped catalog' {
        $found = @($script:Catalog.Reports | Where-Object { Test-RAThresholdShapedQuery -Query ([string]$_.ReportQuery) } | ForEach-Object { [string]$_.ReportName } | Sort-Object)
        $found | Should -Be @(Get-RAThresholdReportNames | Sort-Object)
        $found | Should -Contain $script:Ga
    }
    It 'every listed report exists in the catalog' {
        foreach ($n in @(Get-RAThresholdReportNames)) { @($script:Catalog.Reports | Where-Object { $_.ReportName -eq $n }).Count | Should -Be 1 }
    }
    It 'the detail view of the same finding IS one since #690 (23) -- it lists the Global Administrators only while there are more than 5' {
        @(Get-RAThresholdReportNames) | Should -Contain 'Identity_TooManyGlobalAdmins_Detailed'
        $d = @($script:Catalog.Reports | Where-Object { $_.ReportName -eq 'Identity_TooManyGlobalAdmins_Detailed' })[0]
        Test-RAThresholdShapedQuery -Query ([string]$d.ReportQuery) | Should -BeTrue
    }
    It 'shape: a tenant-wide aggregate filtered against a number' {
        Test-RAThresholdShapedQuery -Query "T | summarize N = dcount(Id), L = make_set(Name) | where N > 5 | extend X = 1" | Should -BeTrue
        Test-RAThresholdShapedQuery -Query "T | summarize N = count() | where N >= 10" | Should -BeTrue
    }
    It 'NEGATIVE shape: per-group aggregates, a per-asset filter, a filter in a comment or string' {
        Test-RAThresholdShapedQuery -Query "T | summarize N = dcount(Id) by Tier | where N > 5" | Should -BeFalse
        Test-RAThresholdShapedQuery -Query "T | where LastSignInDays > 180 | summarize N = dcount(Id)" | Should -BeFalse
        Test-RAThresholdShapedQuery -Query "T | summarize N = dcount(Id) // | where N > 5" | Should -BeFalse
        Test-RAThresholdShapedQuery -Query 'T | summarize N = dcount(Id) | extend S = "| where N > 5"' | Should -BeFalse
        Test-RAThresholdShapedQuery -Query '' | Should -BeFalse
    }
}

Describe 'a threshold report going 1 -> 0 is a warning, never an incomplete report' {
    It 'BELOW-THRESHOLD, not WENT-TO-ZERO' {
        $f = @(Get-RARowCountRegressions -Previous @{ $script:Ga = 1 } -Current @{ $script:Ga = 0 } -Attempted @($script:Ga))
        $f.Count | Should -Be 1
        $f[0].Kind | Should -Be 'BELOW-THRESHOLD'
        $f[0].Previous | Should -Be 1
    }
    It 'the run stays complete: no incomplete report' {
        $f = @(Get-RARowCountRegressions -Previous @{ $script:Ga = 1 } -Current @{ $script:Ga = 0 } -Attempted @($script:Ga))
        @(Get-RAIncompleteReports -Findings $f -Attempted @($script:Ga) -Counts @{ $script:Ga = 0 }).Count | Should -Be 0
    }
    It 'it is not in the row-drop guard event' {
        @(Get-SIGuardCallsForRowCount -Template 'Summary' -Findings @(@{ Report = $script:Ga; Kind = 'BELOW-THRESHOLD'; Previous = 1; Current = 0 })).Count | Should -Be 0
    }
    It 'Invoke-RARowCountGuard logs it as a warning, says no report lost findings, and keeps the history' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ('si-thr-' + [guid]::NewGuid().ToString('N'))
        try {
            $null = Invoke-RARowCountGuard -SettingsPath $dir -TemplateName 'RiskAnalysis_Summary' -Counts @{ $script:Ga = 1; Other = 4 } -Attempted @($script:Ga, 'Other')
            $script:Warned.Clear()
            $f = @(Invoke-RARowCountGuard -SettingsPath $dir -TemplateName 'RiskAnalysis_Summary' -Counts @{ $script:Ga = 0; Other = 4 } -Attempted @($script:Ga, 'Other'))
            @($f | ForEach-Object { $_.Kind }) | Should -Be @('BELOW-THRESHOLD')
            @($script:Warned | Where-Object { $_ -match 'BELOW-THRESHOLD' -and $_ -match [regex]::Escape($script:Ga) }).Count | Should -Be 1
            @($script:Warned | Where-Object { $_ -match 'FEWER findings' }).Count | Should -Be 0
            (Read-RARowCountHistory -Path (Get-RARowCountHistoryPath -SettingsPath $dir) -TemplateName 'RiskAnalysis_Summary')[$script:Ga] | Should -Be 0
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
    It 'back over the threshold (0 -> 1) is no finding at all' {
        @(Get-RARowCountRegressions -Previous @{ $script:Ga = 0 } -Current @{ $script:Ga = 1 }).Count | Should -Be 0
    }
}

Describe 'NEGATIVE -- the incomplete-run protection (#347) is unchanged for everything else' {
    It 'a normal report going to zero is still WENT-TO-ZERO and still makes the run partial' {
        $f = @(Get-RARowCountRegressions -Previous @{ Identity_NoMFA_Detailed = 6; $script:Ga = 1 } -Current @{ Identity_NoMFA_Detailed = 0; $script:Ga = 0 } -Attempted @('Identity_NoMFA_Detailed', $script:Ga))
        ($f | Where-Object { $_.Report -eq 'Identity_NoMFA_Detailed' }).Kind | Should -Be 'WENT-TO-ZERO'
        $r = @(Get-RAIncompleteReports -Findings $f -Attempted @('Identity_NoMFA_Detailed', $script:Ga) -Counts @{ Identity_NoMFA_Detailed = 0; $script:Ga = 0 })
        @($r | ForEach-Object { $_.Report }) | Should -Be @('Identity_NoMFA_Detailed')
        $r[0].Why | Should -Be 'it went from 6 finding(s) last run to none'
    }
    It 'a threshold report that produced NO result (failed) is still MISSING and still incomplete' {
        $f = @(Get-RARowCountRegressions -Previous @{ $script:Ga = 1 } -Current @{} -Attempted @($script:Ga))
        $f[0].Kind | Should -Be 'MISSING'
        @(Get-RAIncompleteReports -Findings $f -Attempted @($script:Ga) -Counts @{}).Count | Should -Be 1
    }
    It 'the exemption is the list, nothing else: an empty list gives WENT-TO-ZERO again' {
        (@(Get-RARowCountRegressions -Previous @{ $script:Ga = 1 } -Current @{ $script:Ga = 0 } -ThresholdReports @()))[0].Kind | Should -Be 'WENT-TO-ZERO'
    }
    It 'a normal WENT-TO-ZERO is still in the row-drop guard event' {
        @(Get-SIGuardCallsForRowCount -Template 'Summary' -Findings @(@{ Report = 'R'; Kind = 'WENT-TO-ZERO'; Previous = 3; Current = 0 })).Count | Should -Be 1
    }
}
