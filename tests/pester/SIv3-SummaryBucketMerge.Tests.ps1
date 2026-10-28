#Requires -Version 5.1
<#
    A SUMMARY GROUP SPLIT ACROSS BUCKETS IS ONE ROW, WITH EVERY ASSET OF EVERY BUCKET (#152).

    A bucketed Summary query returns a group once per bucket, each row aggregated over that bucket's
    assets only. The engine concatenated them and the risk-score de-duplication (whose key has no asset
    list and no cmdbId / cmdbName) kept the first and dropped the rest. Measured on the internal tenant
    2026-09-28: 74 Summary rows lost across 5 reports in one run; the two devices with the most CVEs
    (3,603 and 2,979) were in no Device_Missing_CVEs_Summary row at all.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SummaryBucketMerge.ps1')
    . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\_shared\SI-Yaml.ps1')   # SecurityInsight's own YAML reader
    $script:Catalog = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml') | ConvertFrom-SIYaml
    $script:CveQ = [string]($script:Catalog.Reports | Where-Object ReportName -eq 'Device_Missing_CVEs_Summary').ReportQuery
    $script:RecQ = [string]($script:Catalog.Reports | Where-Object ReportName -eq 'Device_Recommendations_Summary').ReportQuery

    function script:New-CveGroupRow($tier, $cmdb, $assets, $issues, $impact, $prob, $probDet, $assetId) {
        [pscustomobject][ordered]@{
            SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs (Missing Updates)'
            ConfigurationName = 'Update vulnerable software'; ConfigurationId = 'CVE'
            Impact = $impact; SecuritySeverity = 'High'; CriticalityTier = $tier; CriticalityTierLevel = "t$tier"
            cmdbId = ''; cmdbName = $cmdb; cmdbCriticality = ''; cmdbDataSensitivity = ''
            RiskFactor_Consequence = 0; RiskFactor_Probability = $prob; RiskFactor_Probability_Detailed = $probDet
            RiskScore_Weight_Detailed = ''; RiskScore_Weight_Factor = 100; RiskFactor_Weight = 100
            ImpactedAssetCount = @($assets).Count; ImpactedAssetsList = [object[]]@($assets)
            ImpactedAssetPairs = [object[]]@($assets | ForEach-Object { "$_|id-$_" })
            UniqueIssues = @($issues).Count; IssueList = [object[]]@($issues)
            MoreDetails = (@($issues | ForEach-Object { "$_ => https://nvd/$_" }) -join '; ')
            AssetId = $assetId
        }
    }
}

Describe 'the merge plan is read from the report''s own summarize' {
    It 'Device_Missing_CVEs_Summary: every by-column is a key (cmdbId / cmdbName included) and each aggregate has its rule' {
        $p = Get-RASummaryMergePlan -Query $script:CveQ
        $p | Should -Not -BeNullOrEmpty
        foreach ($k in 'SecurityDomain','ConfigurationId','CriticalityTier','SecuritySeverity','cmdbId','cmdbName','cmdbCriticality','cmdbDataSensitivity') { $p.Keys | Should -Contain $k }
        $p.Agg['ImpactedAssetsList'].Kind | Should -Be 'union'
        $p.Agg['ImpactedAssetPairs'].Kind | Should -Be 'union'
        $p.Agg['MoreDetails'].Kind        | Should -Be 'tokens'
        $p.Agg['MoreDetails'].Delim       | Should -Be '; '
        $p.Agg['Impact'].Kind             | Should -Be 'max'
        $p.Agg['AssetId'].Kind            | Should -Be 'min'
        $p.Agg['RiskFactor_Probability_Detailed'].Kind    | Should -Be 'argmax'
        $p.Agg['RiskFactor_Probability_Detailed'].Measure | Should -Be 'RiskFactor_Probability'
        $p.Agg['UniqueIssues'].Kind | Should -Be 'dcount'
        $p.Agg['UniqueIssues'].Arg  | Should -Be 'FindingName'
        $p.Derived['ImpactedAssetCount'].Kind | Should -Be 'count'
        $p.Derived['ImpactedAssetCount'].Src  | Should -Be 'ImpactedAssetsList'
    }
    It 'every Summary report in the catalog has a plan, except the one-row constant report' {
        $none = @($script:Catalog.Reports | Where-Object { $_.ReportName -like '*_Summary*' } | Where-Object { $null -eq (Get-RASummaryMergePlan -Query ([string]$_.ReportQuery)) } | ForEach-Object ReportName)
        $none | Should -Be @('Identity_TooManyGlobalAdmins_Summary')
    }
}

Describe 'two bucket halves of one group become ONE row with every asset' {
    BeforeAll {
        $a = New-CveGroupRow 2 '' @('dons-ekn-dt-01','strv-acw-dt-03') @('CVE-1','CVE-2') 7.5 2 'ExploitSignals' 'id-b'
        $b = New-CveGroupRow 2 '' @('tomsdesktop')                       @('CVE-2','CVE-3') 9.8 3 'ExploitSignals;Internet-Exposed' 'id-a'
        $script:R = Merge-RASummaryBucketRows -Rows @($a, $b) -Query $script:CveQ
        $script:M = $script:R.Rows
    }
    It 'folds the two into one' {
        $script:R.Applied | Should -BeTrue
        $script:R.Merged  | Should -Be 1
        @($script:M).Count | Should -Be 1
    }
    It 'lists every asset from both buckets, and the count describes that list' {
        @($script:M[0].ImpactedAssetsList) | Should -Be @('dons-ekn-dt-01','strv-acw-dt-03','tomsdesktop')
        @($script:M[0].ImpactedAssetPairs).Count | Should -Be 3
        $script:M[0].ImpactedAssetCount | Should -Be 3
    }
    It 'distinct findings are counted once, not per bucket (CVE-2 is in both)' {
        @($script:M[0].IssueList) | Should -Be @('CVE-1','CVE-2','CVE-3')
        $script:M[0].UniqueIssues | Should -Be 3
        (($script:M[0].MoreDetails -split '; ') | Sort-Object) | Should -Be @('CVE-1 => https://nvd/CVE-1','CVE-2 => https://nvd/CVE-2','CVE-3 => https://nvd/CVE-3')
    }
    It 'max / min / arg_max follow the summarize' {
        $script:M[0].Impact | Should -Be 9.8
        $script:M[0].RiskFactor_Probability | Should -Be 3
        $script:M[0].RiskFactor_Probability_Detailed | Should -Be 'ExploitSignals;Internet-Exposed'
        $script:M[0].AssetId | Should -Be 'id-a'
    }
}

Describe 'the exploited CVE ids of a CVE Summary row (owner 2026-10-16: "Yes, change the report")' {
    It 'the report lists, per row, the CVE ids with a known exploit -- the Detailed report''s HasExploit -- and how many' {
        $script:CveQ | Should -Match ([regex]::Escape('si_exploited_cves         = make_set_if(tostring(FindingName), HasExploit == true)'))
        $script:CveQ | Should -Match ([regex]::Escape('| extend si_exploited_cve_count = array_length(si_exploited_cves)'))
        $script:CveQ | Should -Match ([regex]::Escape('IssueList, si_exploited_cves, si_exploited_cve_count, MoreDetails,'))
        # HasExploit is the finding's own flag (graph hasExploit, else vulnerability management IsExploitAvailable) -- the same
        # column the Detailed report outputs and the finding stores
        $script:CveQ | Should -Match ([regex]::Escape('| extend HasExploit        = FindingHasExploit'))
        $opo = @(($script:Catalog.Reports | Where-Object ReportName -eq 'Device_Missing_CVEs_Summary').OutputPropertyOrder)
        $opo | Should -Contain 'IssueList' -Because 'the CVE ids leave the engine only as a declared column (an undeclared IssueList is dropped at shaping)'
    }
    It 'the merge plan: the exploited list is a union, its count is recounted, UniqueIssues is still recounted from IssueList' {
        $p = Get-RASummaryMergePlan -Query $script:CveQ
        $p.Agg['si_exploited_cves'].Kind | Should -Be 'union'
        $p.Agg['si_exploited_cves'].Arg | Should -Be '' -Because 'tostring() keeps it from competing with IssueList as the set UniqueIssues is recounted from'
        $p.Derived['si_exploited_cve_count'].Kind | Should -Be 'count'
        $p.Derived['si_exploited_cve_count'].Src | Should -Be 'si_exploited_cves'
        @($p.Agg.Keys | Where-Object { $p.Agg[$_].Kind -eq 'union' -and $p.Agg[$_].Arg -eq 'FindingName' }) | Should -Be @('IssueList')
    }
    It 'two bucket halves of one group: the exploited ids are the union, the count follows, UniqueIssues counts every CVE' {
        $a = New-CveGroupRow 2 '' @('pc1') @('CVE-1','CVE-2') 7.5 2 'ExploitSignals' 'id-a'
        $b = New-CveGroupRow 2 '' @('pc2') @('CVE-2','CVE-3') 9.8 3 'ExploitSignals' 'id-b'
        $a | Add-Member -NotePropertyName si_exploited_cves -NotePropertyValue ([object[]]@('CVE-2')); $a | Add-Member -NotePropertyName si_exploited_cve_count -NotePropertyValue 1
        $b | Add-Member -NotePropertyName si_exploited_cves -NotePropertyValue ([object[]]@('CVE-2','CVE-3')); $b | Add-Member -NotePropertyName si_exploited_cve_count -NotePropertyValue 2
        $m = @((Merge-RASummaryBucketRows -Rows @($a, $b) -Query $script:CveQ).Rows)
        $m.Count | Should -Be 1
        @($m[0].si_exploited_cves | Sort-Object) | Should -Be @('CVE-2','CVE-3')
        $m[0].si_exploited_cve_count | Should -Be 2
        $m[0].UniqueIssues | Should -Be 3
    }
}

Describe 'columns derived AFTER the summarize (attack-path Summary shape)' {
    BeforeAll {
        $script:ApQ = [string]($script:Catalog.Reports | Where-Object ReportName -eq 'Attack_Paths_Summary_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure').ReportQuery
        function script:New-ApRow($asset, $impact, $sev, $prob) {
            [pscustomobject][ordered]@{
                SecurityDomain = 'Azure'; Category = 'c'; Subcategory = 's'; ConfigurationName = 'n'; ConfigurationId = 'i'
                AssetName = $asset; AssetId = "id-$asset"; AssetType = 's'; Impact = $impact; SecuritySeverity = $sev
                CriticalityTier = 0; CriticalityTierLevel = 'Critical - tier 0'
                RiskFactor_Consequence = 0; RiskFactor_Probability = $prob; RiskFactor_Probability_Detailed = "P$prob"
                RiskScore_Weight_Detailed = ''; RiskScore_Weight_Factor = 100; RiskFactor_Weight = 100
                cmdbId = ''; cmdbName = ''; cmdbCriticality = ''; cmdbDataSensitivity = ''
                ImpactedAssetCount = 1; UniqueIssues = 1
                ImpactedAssetsList = [object[]]@($asset); ImpactedAssetPairs = [object[]]@("$asset|id-$asset"); IssueList = [object[]]@('kv1')
            }
        }
    }
    It 'plans the derived columns: AssetName joined from the list, severity from the Impact winner' {
        $p = Get-RASummaryMergePlan -Query $script:ApQ
        $p.Derived['AssetName'].Kind  | Should -Be 'join'
        $p.Derived['AssetName'].Src   | Should -Be 'ImpactedAssetsList'
        $p.Derived['SecuritySeverity'].Kind    | Should -Be 'argmax'
        $p.Derived['SecuritySeverity'].Measure | Should -Be 'Impact'
        $p.Derived['RiskScore_Weight_Factor'].Kind | Should -Be 'key'
    }
    It 'the measured case: one group, two devices from two buckets -> one row naming BOTH devices' {
        $a = New-ApRow 'strv-mok-lt-06' 9 'Very High' 2
        $b = New-ApRow 'strv-mok-dt-04' 7 'High' 3
        $r = Merge-RASummaryBucketRows -Rows @($a, $b) -Query $script:ApQ
        @($r.Rows).Count | Should -Be 1
        $r.Rows[0].AssetName | Should -Be 'strv-mok-lt-06; strv-mok-dt-04'
        $r.Rows[0].ImpactedAssetCount | Should -Be 2
        $r.Rows[0].Impact | Should -Be 9
        $r.Rows[0].SecuritySeverity | Should -Be 'Very High'
        $r.Rows[0].RiskFactor_Probability | Should -Be 3
    }
    It 'REFUSES a group it cannot reproduce: an unexplained column that differs keeps both rows' {
        $a = New-ApRow 'x' 9 'Very High' 2; $a | Add-Member -NotePropertyName Mystery -NotePropertyValue 'one'
        $b = New-ApRow 'y' 9 'Very High' 2; $b | Add-Member -NotePropertyName Mystery -NotePropertyValue 'two'
        $r = Merge-RASummaryBucketRows -Rows @($a, $b) -Query $script:ApQ
        @($r.Rows).Count | Should -Be 2
        $r.Refused | Should -Be 1
        $r.Merged  | Should -Be 0
    }
}

Describe '#402 a sentence the report builds from the count is rebuilt after the merge' {
    BeforeAll {
        $script:ExQ = [string]($script:Catalog.Reports | Where-Object ReportName -eq 'Endpoint_ExcludedAssets_Summary').ReportQuery
        function script:New-ExRow([int]$tier, [string[]]$assets, [string[]]$reasons) {
            $list = [object[]]@($assets | Sort-Object)
            $reasonText = (@($reasons | Sort-Object -Unique) -join ' | ')
            [pscustomobject][ordered]@{
                SecurityDomain = 'Endpoint'; Category = 'Governance'; Subcategory = 'Suppressed Assets'
                ConfigurationName = 'Assets excluded from Risk Analysis by an operator tag'; ConfigurationId = 'ENDPOINT-EXCLUDED-BY-TAG-001'
                CriticalityTier = $tier; CriticalityTierLevel = 'Low - tier 3'; SecuritySeverity = 'Low'
                cmdbId = ''; cmdbName = ''; cmdbCriticality = ''; cmdbDataSensitivity = ''
                ImpactedAssetsList = $list; ImpactedAssetPairs = [object[]]@($assets | ForEach-Object { "$_|id-$_" })
                ExcludedReasons = $reasonText; AssetId = ('id-' + @($list)[0])
                ImpactedAssetCount = $list.Count
                Impact = ('{0} asset(s) at tier {1} are suppressed from every Risk Analysis report.' -f $list.Count, $tier)
                MoreDetails = ('Excluded by -> ' + $reasonText)
                RiskScore_Weight_Detailed = ''; RiskScore_Weight_Factor = 100; RiskFactor_Weight = 100
            }
        }
    }
    It 'plans Impact and MoreDetails as sentences over the merged count and the merged reasons' {
        $p = Get-RASummaryMergePlan -Query $script:ExQ
        $p.Derived['Impact'].Kind | Should -Be 'strcat'
        @($p.Derived['Impact'].Parts | Where-Object { $_.Col } | ForEach-Object { $_.Col }) | Should -Be @('ImpactedAssetCount', 'CriticalityTier')
        $p.Derived['MoreDetails'].Kind | Should -Be 'strcat'
    }
    It 'the measured case: one tier-3 group in two buckets (55 + 60 assets) -> ONE row with 115 assets and its sentence' {
        $a = New-ExRow 3 @(1..55 | ForEach-Object { 'pc-a{0:d3}' -f $_ }) @('NoScan')
        $b = New-ExRow 3 @(1..60 | ForEach-Object { 'pc-b{0:d3}' -f $_ }) @('NoScan', 'Lab')
        $r = Merge-RASummaryBucketRows -Rows @($a, $b) -Query $script:ExQ
        @($r.Rows).Count | Should -Be 1
        $r.Refused | Should -Be 0
        $r.Rows[0].ImpactedAssetCount | Should -Be 115
        @($r.Rows[0].ImpactedAssetsList).Count | Should -Be 115
        $r.Rows[0].Impact | Should -Be '115 asset(s) at tier 3 are suppressed from every Risk Analysis report.'
        $r.Rows[0].MoreDetails | Should -Be 'Excluded by -> Lab | NoScan'
    }
    It 'a real tier-2 group beside it stays its own row' {
        $a = New-ExRow 3 @('a1', 'a2') @('NoScan')
        $b = New-ExRow 3 @('b1') @('NoScan')
        $c = New-ExRow 2 @('c1') @('NoScan'); $c.CriticalityTierLevel = 'Medium - tier 2'; $c.SecuritySeverity = 'Medium'
        $r = Merge-RASummaryBucketRows -Rows @($a, $c, $b) -Query $script:ExQ
        @($r.Rows).Count | Should -Be 2
        @($r.Rows | Where-Object CriticalityTier -eq 3)[0].Impact | Should -Be '3 asset(s) at tier 3 are suppressed from every Risk Analysis report.'
        @($r.Rows | Where-Object CriticalityTier -eq 2)[0].Impact | Should -Be '1 asset(s) at tier 2 are suppressed from every Risk Analysis report.'
    }
    It 'a sentence over a column the rows do not carry is still REFUSED when it differs (never rebuilt from a guess)' {
        $q = "T | summarize L = make_set(A), Hidden = max(H) by K | extend S = strcat(`"n=`", tostring(Hidden)) | project-away Hidden"
        $a = [pscustomobject]@{ K = 'k'; L = [object[]]@('a'); S = 'n=1' }
        $b = [pscustomobject]@{ K = 'k'; L = [object[]]@('b'); S = 'n=2' }
        $r = Merge-RASummaryBucketRows -Rows @($a, $b) -Query $q
        @($r.Rows).Count | Should -Be 2
        $r.Refused | Should -Be 1
    }
}

Describe 'rows that are genuinely different groups are never merged' {
    It 'same tier and severity, different CMDB service -> two rows' {
        $a = New-CveGroupRow 2 'Payroll' @('a') @('CVE-1') 5 1 'x' 'id-a'
        $b = New-CveGroupRow 2 'Web'     @('b') @('CVE-1') 5 1 'x' 'id-b'
        $r = Merge-RASummaryBucketRows -Rows @($a, $b) -Query $script:CveQ
        @($r.Rows).Count | Should -Be 2
        $r.Merged | Should -Be 0
    }
}

Describe 'shapes and guards' {
    It 'lists arriving as JSON text (Log Analytics direct) merge and stay JSON text' {
        $a = New-CveGroupRow 1 '' @('x') @('CVE-9') 5 1 'x' 'i1'; $a.ImpactedAssetsList = '["x"]'
        $b = New-CveGroupRow 1 '' @('y') @('CVE-9') 5 1 'x' 'i2'; $b.ImpactedAssetsList = '["y"]'
        $m = (Merge-RASummaryBucketRows -Rows @($a, $b) -Query $script:CveQ).Rows[0]
        $m.ImpactedAssetsList | Should -BeOfType [string]
        @((ConvertFrom-Json $m.ImpactedAssetsList) | ForEach-Object { $_ }) | Should -Be @('x','y')
        $m.ImpactedAssetCount | Should -Be 2
    }
    It 'a one-asset merged list stays a list (not unrolled to a scalar)' {
        $a = New-CveGroupRow 1 '' @('solo') @('CVE-9') 5 1 'x' 'i1'
        $b = New-CveGroupRow 1 '' @('solo') @('CVE-9') 5 1 'x' 'i1'
        $m = (Merge-RASummaryBucketRows -Rows @($a, $b) -Query $script:CveQ).Rows[0]
        , $m.ImpactedAssetsList | Should -BeOfType [object[]]
        $m.ImpactedAssetCount | Should -Be 1
    }
    It 'dcount of an asset identity adds up; dcount of anything else never inflates' {
        $q = "T`n| summarize AssetCount = dcount(PrimaryEntityId), UniqueIssues = dcount(ConfigurationId), TotalIssues = count() by ConfigurationId, CriticalityTier"
        $a = [pscustomobject]@{ ConfigurationId = 'r1'; CriticalityTier = 2; AssetCount = 3; UniqueIssues = 1; TotalIssues = 3 }
        $b = [pscustomobject]@{ ConfigurationId = 'r1'; CriticalityTier = 2; AssetCount = 2; UniqueIssues = 1; TotalIssues = 2 }
        $m = (Merge-RASummaryBucketRows -Rows @($a, $b) -Query $q).Rows[0]
        $m.AssetCount   | Should -Be 5
        $m.UniqueIssues | Should -Be 1
        $m.TotalIssues  | Should -Be 5
    }
    It 'an unreadable by clause, or a key the rows lack, leaves the rows UNCHANGED' {
        $a = [pscustomobject]@{ K = 1; N = 1 }; $b = [pscustomobject]@{ K = 1; N = 2 }
        $r1 = Merge-RASummaryBucketRows -Rows @($a, $b) -Query "T | summarize N = count() by bin(TimeGenerated, 1d)"
        $r1.Applied | Should -BeFalse; @($r1.Rows).Count | Should -Be 2
        $r2 = Merge-RASummaryBucketRows -Rows @($a, $b) -Query "T | summarize N = count() by Missing"
        $r2.Applied | Should -BeFalse; @($r2.Rows).Count | Should -Be 2
    }
}

Describe 'WIRING' {
    BeforeAll {
        $script:Eng = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $script:Score = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1')
    }
    It 'the engine loads the merge and runs it on bucketed Summary results before they are counted' {
        $script:Eng | Should -Match "_shared/RA-SummaryBucketMerge\.ps1"
        # merged BEFORE the total is printed, so the total and the loss verdict under it describe the merged rows
        $at    = $script:Eng.IndexOf('Merge-RASummaryBucketRows -Rows $ResultAll -Query $Query')
        $total = $script:Eng.IndexOf('Write-Info ("total rows across all buckets')
        $at | Should -BeGreaterThan 0
        $at | Should -BeLessThan $total
        $total | Should -BeLessThan $script:Eng.IndexOf('Write-RABucketLossVerdict -ReportName $ReportName')
        $script:Eng.Substring($at - 200, 200) | Should -Match "ReportName -like '\*_Summary\*'"
    }
    It 'the risk-score de-duplication drops only EXACT copies of a Summary row' {
        $script:Score | Should -Match "\`$isSummaryReport = \(\[string\]\`$ReportName -like '\*_Summary\*'\)"
        $script:Score | Should -Match 'if \(\$isSummaryReport\) \{'
    }
}
