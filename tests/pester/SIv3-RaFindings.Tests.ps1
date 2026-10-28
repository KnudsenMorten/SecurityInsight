#Requires -Version 5.1
<#
    SI FINDINGS (engine/risk-analysis/_shared/RA-Findings.ps1) -- V3-DATA-MODEL part 2, P4 / 2.8.2: the Detailed rows a
    run published, de-duplicated per CI and finding key -> SI_Finding_CL.

      * ONE FINDING PER (CI, KEY): the same CVE from two reports on one CI is one finding -- every report in
        si_detected_by, the highest severity and scores, every risk-factor token once, the lowest tier; two CIs stay two.
      * NOTHING DROPPED: a row without a CI is keyed on its asset id (si_asset_id); a row without a key is the only one left out.
      * VOCABULARY: severity words -> critical/high/medium/low/info, the rating bands of the risk score, a CVE id typed
        'cve', CVSS as text (a decimal), the run's collection time.
      * SWITCHES (#829): the copy is an optional output, OFF BY DEFAULT -- not set, off / false / 0 / $false post nothing; only
        an explicit on / true / 1 / yes / $true posts; a dry run posts nothing.
      * WIRING: only a Detailed run that published its rows publishes findings, and (#829) before the run's END record.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-Findings.ps1')
    function script:Row([string]$ci, [string]$key, [string]$report, [string]$sev, $score, $weighted, [string]$prob = '', $tier = 1) {
        [pscustomobject]@{ si_ci_id = $ci; AssetId = "id-$ci"; AssetName = "asset-$ci"; ConfigurationId = $key; ConfigurationName = "title $key"; ReportName = $report
            SecuritySeverity = $sev; RiskScoreTotal = $score; RiskScoreTotal_Weighted = $weighted; RiskFactor_Probability_Detailed = $prob; RiskFactor_Consequence_Detailed = ''
            CriticalityTier = $tier; SecurityDomain = 'Endpoint'; MaxCvssScore = '9.8' }
    }
}

Describe 'De-duplicating findings per CI' {
    It 'makes one finding of the same CVE on one CI from two reports' {
        $rows = @(
            (Row 'ci-1' 'CVE-2024-1111' 'Device_Missing_CVEs_Detailed' 'High' 16 16 'ExploitSignals' 1)
            (Row 'ci-1' 'cve-2024-1111' 'PublicIP_Vulnerabilities_Detailed' 'Very High' 24 30 'Internet-Exposed;ExploitSignals' 0)
            (Row 'ci-2' 'CVE-2024-1111' 'Device_Missing_CVEs_Detailed' 'Medium' 8 8 '' 3)
        )
        $f = @(ConvertTo-SIFindingRows -Rows $rows -CollectionTime ([datetime]'2026-10-08T05:00:00Z') -RunId 'r1')
        $f.Count | Should -Be 2
        $one = @($f | Where-Object si_ci_id -eq 'ci-1')[0]
        @($one.si_detected_by) | Should -Be @('Device_Missing_CVEs_Detailed', 'PublicIP_Vulnerabilities_Detailed')
        $one.si_severity | Should -Be 'critical'
        $one.si_risk_score | Should -Be 24
        $one.si_weighted_risk_score | Should -Be 30
        $one.si_risk_rating | Should -Be 'moderate'   # bands 50 / 30 / 15 (owner 2026-10-11): 24 is moderate
        @($one.si_finding_risk_factors) | Should -Be @('ExploitSignals', 'Internet-Exposed')
        $one.si_tier | Should -Be 0
        $one.si_finding_rows | Should -Be 2
        $one.si_finding_type | Should -Be 'cve'
        $one.si_cve | Should -Be 'CVE-2024-1111'
        $one.si_cvss | Should -Be '9.8'
        $one.si_cvss | Should -BeOfType [string]
        $one.si_run_id | Should -Be 'r1'
    }
    It 'keys a row without a CI on its asset id and leaves out only a row without a finding key' {
        $rows = @((Row '' 'scid-2000' 'Endpoint_Av_Detailed' 'Low' 4 4), (Row 'ci-9' '' 'x' 'Low' 1 1))
        $f = @(ConvertTo-SIFindingRows -Rows $rows)
        $f.Count | Should -Be 1
        $f[0].si_ci_id | Should -BeNullOrEmpty
        $f[0].si_asset_id | Should -Be 'id-'
        $f[0].si_finding_type | Should -Be 'recommendation'
        $f[0].si_severity | Should -Be 'low'
    }
    It 'maps the severity words and bands the rating' {
        ConvertTo-SIFindingSeverity 'Medium-High' | Should -Be 'medium'
        ConvertTo-SIFindingSeverity '' | Should -Be 'info'
        @(ConvertTo-SIFindingRows -Rows @((Row 'c' 'k' 'r' 'Low' 50 50)))[0].si_risk_rating | Should -Be 'critical'
        @(ConvertTo-SIFindingRows -Rows @((Row 'c' 'k' 'r' 'Low' 49 49)))[0].si_risk_rating | Should -Be 'high'
        @(ConvertTo-SIFindingRows -Rows @((Row 'c' 'k' 'r' 'Low' 30 30)))[0].si_risk_rating | Should -Be 'high'
        @(ConvertTo-SIFindingRows -Rows @((Row 'c' 'k' 'r' 'Low' 15 15)))[0].si_risk_rating | Should -Be 'moderate'
        @(ConvertTo-SIFindingRows -Rows @((Row 'c' 'k' 'r' 'Low' 14 14)))[0].si_risk_rating | Should -Be 'low'
    }
}

Describe 'Switches and wiring' {
    BeforeEach { $script:KeepCopy = $global:SI_RA_Findings }
    AfterEach { $global:SI_RA_Findings = $script:KeepCopy }
    It '#829 the copy is OFF unless clearly on: not set, $false, off, false, 0 and a typo are off' {
        $global:SI_RA_Findings = $null
        Test-SIFindingsCopyOn | Should -BeFalse -Because 'not set = off, in every install'
        foreach ($v in @($false, 'off', 'OFF', 'false', '0', '', 'ture', 0)) { Test-SIFindingsCopyOn -Value $v | Should -BeFalse -Because "'$v' is off" }
        foreach ($v in @($true, 'on', 'On', 'true', '1', 'yes', ' on ')) { Test-SIFindingsCopyOn -Value $v | Should -BeTrue -Because "'$v' is on" }
    }
    It 'posts nothing by default, when switched off or in a dry run' {
        function Send-SIObjectMapRows { throw 'must not post' }   # a post would throw -- the switches return before it
        $global:SI_RA_Findings = $null
        Publish-SIFindings -Rows @((Row 'c' 'k' 'r' 'Low' 1 1)) | Should -Be 0 -Because '#829 not set = off'
        foreach ($v in @('off', 'false', '0', $false)) {
            $global:SI_RA_Findings = $v
            Publish-SIFindings -Rows @((Row 'c' 'k' 'r' 'Low' 1 1)) | Should -Be 0
        }
        $global:SI_RA_Findings = 'on'
        Publish-SIFindings -Rows @((Row 'c' 'k' 'r' 'Low' 1 1)) -WhatIfRun | Should -Be 0
    }
    It 'posts the de-duplicated findings when the copy is switched on' {
        $script:Posted = New-Object System.Collections.Generic.List[object]
        function Send-SIObjectMapRows { param($Rows, $TableName, $DcrName) foreach ($r in @($Rows)) { $script:Posted.Add($r) }; $script:PostedTable = $TableName; @($Rows).Count }
        $global:SI_RA_Findings = $true
        Publish-SIFindings -Rows @((Row 'c1' 'CVE-2024-1' 'r1' 'High' 10 10), (Row 'c1' 'CVE-2024-1' 'r2' 'Low' 5 5), (Row 'c2' 'k2' 'r1' 'Low' 1 1)) | Should -Be 2
        $script:Posted.Count | Should -Be 2
        $script:PostedTable | Should -Be 'SI_Finding'
    }
    It 'is published at the end of a Detailed run that published its rows -- #829 only when on, BEFORE the run''s END record' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $t | Should -Match 'if \(\[bool\]\$global:Detailed -and \$null -ne \$script:_RAPublishedRows\)'
        $iEnd = [regex]::Match($t, "(?m)^Send-RARunHealthEnd -ExitReason 'success'\r?$").Index
        $t.IndexOf('Publish-SIFindings -Rows') | Should -BeLessThan $iEnd -Because 'a run that has ended is a copy that has ended -- the data sync checks it'
        $t.IndexOf('Publish-SIFindings -Rows') | Should -BeGreaterThan $t.IndexOf('$script:RAFindingsRunNote = [string](Get-SIFindingsSkipNote')
        $t | Should -Match ([regex]::Escape('if (-not (Test-SIFindingsCopyOn)) {'))
        $t | Should -Not -Match 'SI_RA_Findings\)\.Trim\(\)' -Because 'the setting has ONE rule (Test-SIFindingsCopyOn)'
    }
}

Describe '#774: a Detailed run published from SQL publishes its findings -- and a skipped publish is never silent (a customer install, 2026-10-19)' {
    BeforeAll { $script:Ra = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) }
    It 'THE CAUSE: in PowerShell an `if` that yields @() assigns $null -- the published-rows marker is assigned in each branch' {
        $stream = $true
        $viaIf = if ($stream) { @() } else { 'rows' }
        $null -eq $viaIf | Should -BeTrue -Because 'this is what silently skipped the findings on every SQL-published Detailed run'
        if ($stream) { $direct = @() } else { $direct = 'rows' }
        $null -ne $direct | Should -BeTrue
        $script:Ra | Should -Match ([regex]::Escape('if ($script:RAStreamOn) { $script:_RAPublishedRows = @() } else { $script:_RAPublishedRows = $global:final }'))
        $script:Ra | Should -Not -Match '\$script:_RAPublishedRows = if \('
    }
    It 'the skip note: only a Detailed run that will not publish, not a dry run, not switched off, not a run that already failed' {
        $keep = $global:SI_RA_Findings
        $global:SI_RA_Findings = 'on'
        try {
        Get-SIFindingsSkipNote -Detailed $true -Published $false -WhatIfRun $false -SentToLogAnalytics $true -EndFailed $false | Should -Match '^the findings of this Detailed run were not published to SI_Finding_CL \(the run''s rows did not reach Log Analytics in full\)'
        Get-SIFindingsSkipNote -Detailed $true -Published $false -WhatIfRun $false -SentToLogAnalytics $false -EndFailed $false | Should -Match 'the run does not send to Log Analytics'
        Get-SIFindingsSkipNote -Detailed $true -Published $true -WhatIfRun $false -SentToLogAnalytics $true -EndFailed $false | Should -BeNullOrEmpty
        Get-SIFindingsSkipNote -Detailed $false -Published $false -WhatIfRun $false -SentToLogAnalytics $true -EndFailed $false | Should -BeNullOrEmpty
        Get-SIFindingsSkipNote -Detailed $true -Published $false -WhatIfRun $true -SentToLogAnalytics $true -EndFailed $false | Should -BeNullOrEmpty
        Get-SIFindingsSkipNote -Detailed $true -Published $false -WhatIfRun $false -SentToLogAnalytics $true -EndFailed $true | Should -BeNullOrEmpty
        $global:SI_RA_Findings = 'off'
        Get-SIFindingsSkipNote -Detailed $true -Published $false -WhatIfRun $false -SentToLogAnalytics $true -EndFailed $false | Should -BeNullOrEmpty
        $global:SI_RA_Findings = $null
        Get-SIFindingsSkipNote -Detailed $true -Published $false -WhatIfRun $false -SentToLogAnalytics $true -EndFailed $false | Should -BeNullOrEmpty -Because '#829 off by default: nothing is skipped'
        } finally { $global:SI_RA_Findings = $keep }
    }
    It 'WIRING: judged before the run record''s END, said as WARN, carried on the END row without changing the exit' {
        $iNote = $script:Ra.IndexOf('$script:RAFindingsRunNote = [string](Get-SIFindingsSkipNote')
        $iNote | Should -BeGreaterThan 0
        $iNote | Should -BeLessThan ([regex]::Match($script:Ra, "(?m)^Send-RARunHealthEnd -ExitReason 'success'\r?$").Index) -Because 'the END row carries it'
        $script:Ra | Should -Match ([regex]::Escape('if ($script:RAFindingsRunNote) { Write-Warn2 $script:RAFindingsRunNote }'))
        $script:Ra | Should -Match ([regex]::Escape('$ErrorMessage + '' | '' + [string]$script:RAFindingsRunNote'))
        $fn = [regex]::Match($script:Ra, '(?s)function Send-RARunHealthEnd \{.*?\r?\n\}').Value
        $fn | Should -Match 'RAFindingsRunNote'
        ([regex]::Match($fn, '(?s)# #774.*?\r?\n    \}').Value) | Should -Not -Match 'success-partial|ExitReason =' -Because 'a warning, never a partial or failed run'
        # rows went out but no finding was posted: loud too
        $script:Ra | Should -Match 'no findings were posted to SI_Finding_CL from \{0\} Detailed row\(s\)'
        $script:Ra | Should -Match ([regex]::Escape('$__nFind = Publish-SIFindings -Pager (New-RARowPager -Stream $script:RAStream -Source FindingKey)'))
    }
}
