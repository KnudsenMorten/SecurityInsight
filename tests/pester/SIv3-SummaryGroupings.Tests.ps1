#Requires -Version 5.1
<#
    #636 -- SUMMARY = GROUPINGS OF THE DETAILED FINDINGS, THE SUMMARY STEP OFF BY DEFAULT (owner 2026-10-19: "i prefer to
    switch so detailed becomes the engine default and summary is optional" / "technically i feel that summary could be build
    as views with the detailed data instead" / "community must switch" / "same core functionality").

    What these tests keep true (both editions -- the Pro side is SIv3-SummaryGroupsPro.Tests.ps1):
      * ONE declarative definition (data-model\summary-groupings.locked.json) compiles into ONE plan; every grouping and
        measure names a known field; the normalisation is the same rule in PowerShell and in the SQL it writes;
      * THE engine function (engine\_shared\SI-SummaryGroupings.ps1 Invoke-SISummaryGrouping) groups Detailed rows exactly:
        distinct assets (never an empty one), distinct recommendations, the counted variant without the exempted rows, the
        attack path's source tier, the severity words, the tier words; a pager gives the same result as the rows;
      * -AsSql is one pass over the collection's narrow finding columns -- never DetailJson, no cap -- and writes both
        variants and the state in ONE transaction;
      * Community: the Detailed run computes them (no SQL) for its management mail and next to its workbook; the mail section;
      * the Summary step is off by default (the map, a new pipeline, a stored default pipeline as it is read -- one a person
        changed keeps it, said once) and the Summary mail settings move to the management mail while it is off;
      * the daily trend row comes from the Detailed run; the AI-summary leader defaults to Detailed.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-SummaryGroupings.ps1')
    . (Join-Path $script:Root 'engine\_shared\SI-SummaryStep.ps1')
    $script:Plan = Get-SISummaryGroupingPlan
    function script:Row([hashtable]$h) { [pscustomobject]$h }
    # six Detailed rows: two assets on one CVE, an exempted CVE finding, an identity finding with a "Tier2" tier and a lower-
    # case severity, an attack path keyed to its source asset (target tier 0, source tier 2) and a row without an asset
    function script:Fixture {
        @(
            (Row @{ SI_AssetId = 'a1'; AssetName = 'host1'; ConfigurationId = 'CVE-1'; ConfigurationName = 'Vuln one'; CriticalityTier = 0; SecuritySeverity = 'Critical'; SecurityDomain = 'Endpoint'; Category = 'Vulnerability'; Subcategory = 'OS'; RiskRating = 'Critical'; RiskScoreTotal = 90; HasExploit = $true; AssetDetectedInReportName = 'Device_Missing_CVEs_Detailed' })
            (Row @{ SI_AssetId = 'a2'; AssetName = 'host2'; ConfigurationId = 'CVE-1'; ConfigurationName = 'Vuln one'; CriticalityTier = 1; SecuritySeverity = 'High'; SecurityDomain = 'Endpoint'; Category = 'Vulnerability'; Subcategory = 'OS'; RiskRating = 'High'; RiskScoreTotal = 50; HasExploit = $false; AssetDetectedInReportName = 'Device_Missing_CVEs_Detailed' })
            (Row @{ SI_AssetId = 'a1'; AssetName = 'host1'; ConfigurationId = 'CVE-2'; ConfigurationName = 'Vuln two'; CriticalityTier = '0'; SecuritySeverity = 'Very High'; SecurityDomain = 'Endpoint'; Category = 'Vulnerability'; Subcategory = 'App'; RiskRating = 'Critical'; RiskScoreTotal = '80'; SI_ExemptionId = '77'; AssetDetectedInReportName = 'Device_Missing_CVEs_Detailed' })
            (Row @{ SI_AssetId = 'u1'; AssetName = 'user1'; ConfigurationId = 'cfg-mfa'; ConfigurationName = 'No MFA'; CriticalityTier = 'Tier2'; SecuritySeverity = 'medium'; SecurityDomain = 'Identity'; Category = 'Identity'; Subcategory = 'MFA'; RiskRating = 'Moderate'; RiskScoreTotal = 20; AssetDetectedInReportName = 'Identity_NoMFA_Detailed' })
            (Row @{ SI_AssetId = 'a3'; AssetName = 'vm3'; ConfigurationId = 'path-1'; ConfigurationName = 'Path to DC'; CriticalityTier = 0; SourceCriticalityTier = 2; SecuritySeverity = 'high'; SecurityDomain = 'Azure'; Category = 'AttackPath'; Subcategory = 'Lateral'; RiskRating = 'High'; RiskScoreTotal = 60; AssetDetectedInReportName = 'Attack_Paths_Detailed_X' })
            (Row @{ AssetId = ''; ConfigurationId = 'cfg-x'; ConfigurationName = 'Loose'; SecuritySeverity = ''; RiskScoreTotal = $null; AssetDetectedInReportName = 'Azure_DefenderRecommendations_Detailed' })
        )
    }
    function script:Pick($res, [string]$g, [string]$k1, [bool]$counted = $false, [string]$k2 = '', [string]$k3 = '') {
        @($res | Where-Object { $_.GroupingId -eq $g -and [bool]$_.Counted -eq $counted -and $_.Key1 -eq $k1 -and $_.Key2 -eq $k2 -and $_.Key3 -eq $k3 })
    }
}

Describe 'the definition' {
    It 'compiles into one plan: known fields and kinds, 1-3 keys, a measure per column, a hash' {
        $script:Plan.Groupings.Count | Should -BeGreaterOrEqual 10
        @($script:Plan.Groupings | ForEach-Object Id) | Should -Contain 'recommendation'
        foreach ($id in 'asset', 'tier', 'domain', 'domain-category', 'domain-category-subcategory', 'risk-rating', 'department', 'severity', 'report') {
            @($script:Plan.Groupings | ForEach-Object Id) | Should -Contain $id
        }
        @($script:Plan.Groupings | ForEach-Object Id | Select-Object -Unique).Count | Should -Be $script:Plan.Groupings.Count
        @($script:Plan.MeasureIds) | Should -Be @('Findings', 'Assets', 'Recommendations', 'MaxRisk', 'TotalRisk', 'BestTier', 'Tier0Findings', 'CriticalFindings', 'HighFindings', 'RatedCriticalFindings', 'RatedHighFindings', 'CriticalRecommendations', 'HighRecommendations', 'ExploitedRecommendations')
        (Get-SISummaryGroupingDefinition).Hash | Should -Match '^[0-9a-f]{32}$'
        $script:Plan.Exempted | Should -Be 'exempted'
    }
    It 'refuses a grouping that names an unknown field' {
        $d = Get-Content -Raw (Join-Path $script:Root 'data-model\summary-groupings.locked.json') | ConvertFrom-Json
        $d.groupings[0].keys = @('nope')
        { Get-SISummaryGroupingPlan -Definition $d } | Should -Throw '*unknown field*'
    }
}

Describe 'the normalisation (the same rule as the SQL)' {
    It 'tier, severity, id, flag, text' {
        $f = $script:Plan.Fields
        ConvertTo-SISummaryGroupingValue -Field $f['tier'] -Value 'Tier2' -Plan $script:Plan | Should -Be '2'
        ConvertTo-SISummaryGroupingValue -Field $f['tier'] -Value $null -Plan $script:Plan | Should -Be 'Unclassified'
        ConvertTo-SISummaryGroupingValue -Field $f['tier'] -Value 7 -Plan $script:Plan | Should -Be 'Unclassified'
        ConvertTo-SISummaryGroupingValue -Field $f['tierNumber'] -Value '1' -Plan $script:Plan | Should -Be 1
        ConvertTo-SISummaryGroupingValue -Field $f['severity'] -Value 'medium-high' -Plan $script:Plan | Should -Be 'Medium-High'
        ConvertTo-SISummaryGroupingValue -Field $f['severity'] -Value 'Critical' -Plan $script:Plan | Should -Be 'Very High'
        ConvertTo-SISummaryGroupingValue -Field $f['severity'] -Value '' -Plan $script:Plan | Should -Be 'None'
        ConvertTo-SISummaryGroupingValue -Field $f['severity'] -Value 'weird' -Plan $script:Plan | Should -Be 'Other'
        ConvertTo-SISummaryGroupingValue -Field $f['department'] -Value $null -Plan $script:Plan | Should -Be '0'
        ConvertTo-SISummaryGroupingValue -Field $f['exploit'] -Value $true -Plan $script:Plan | Should -Be '1'
        ConvertTo-SISummaryGroupingValue -Field $f['domain'] -Value '  Endpoint ' -Plan $script:Plan | Should -Be 'Endpoint'
        ConvertTo-SISummaryGroupingValue -Field $f['domain'] -Value '{}' -Plan $script:Plan | Should -Be ''
    }
    It 'the SQL twin words the tier and the severity alike' {
        $s = Get-SISummaryGroupingSqlValue -Field $script:Plan.Fields['severity'] -Plan $script:Plan
        $s | Should -Match "WHEN N'' THEN N'None'"
        $s | Should -Match "WHEN N'critical' THEN N'Very High'"
        $s | Should -Match "ELSE N'Other' END$"
        Get-SISummaryGroupingSqlValue -Field $script:Plan.Fields['tier'] -Plan $script:Plan | Should -Be "CASE WHEN f.Tier BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), f.Tier) ELSE N'Unclassified' END"
    }
}

Describe '#812 tokens and bands: the named views Risk rating / MITRE ATT&CK / Compliance / CVSS are groupings of the ONE definition' {
    BeforeAll {
        # MITRE lists as a text (comma or ';'), as an array, as a JSON array text; compliance tags keep their commas; CVSS on
        # every band edge, none and a text
        $script:TokRows = @(
            (Row @{ SI_AssetId = 'a1'; ConfigurationId = 'c1'; MITRE_Tactics = 'Initial Access, Persistence'; MITRE_Techniques = 'T1190;T1078'; ComplianceTags = 'CIS 1.1; NIST AC-2'; MaxCvssScore = 9.8; RiskScoreTotal = 10 })
            (Row @{ SI_AssetId = 'a2'; ConfigurationId = 'c1'; MITRE_Tactics = @('Persistence', 'persistence', ' Initial Access '); MITRE_Techniques = '["T1190"]'; ComplianceTags = 'CIS 1.1, extended'; MaxCvssScore = '7'; RiskScoreTotal = 5; SI_ExemptionId = '9' })
            (Row @{ SI_AssetId = 'a3'; ConfigurationId = 'c2'; MITRE_Tactics = ''; ComplianceTags = $null; MaxCvssScore = 4.0 })
            (Row @{ SI_AssetId = 'a4'; ConfigurationId = 'c3'; MaxCvssScore = 0.1 })
            (Row @{ SI_AssetId = 'a5'; ConfigurationId = 'c4'; MaxCvssScore = 0 })
            (Row @{ SI_AssetId = 'a6'; ConfigurationId = 'c5' })
        )
        $script:TokRes = @(Invoke-SISummaryGrouping -Rows $script:TokRows)
    }
    It 'the definition declares the four groupings over a tokens / band field; a tokens field is a key only' {
        foreach ($id in 'mitre-tactic', 'mitre-technique', 'compliance-control', 'cvss-band') { @($script:Plan.Groupings | ForEach-Object Id) | Should -Contain $id }
        $script:Plan.Fields['mitreTactic'].Kind | Should -Be 'tokens'
        @($script:Plan.Fields['mitreTactic'].Split) | Should -Be @(',')
        @($script:Plan.Fields['complianceTag'].Split).Count | Should -Be 0
        $script:Plan.Fields['cvssBand'].Kind | Should -Be 'band'
        $d = Get-Content -Raw (Join-Path $script:Root 'data-model\summary-groupings.locked.json') | ConvertFrom-Json
        $d.measures[1].field = 'mitreTactic'
        { Get-SISummaryGroupingPlan -Definition $d } | Should -Throw '*grouping key only*'
        $d = Get-Content -Raw (Join-Path $script:Root 'data-model\summary-groupings.locked.json') | ConvertFrom-Json
        $d.groupings[0].keys = @('mitreTactic', 'mitreTechnique')
        { Get-SISummaryGroupingPlan -Definition $d } | Should -Throw '*more than one tokens key*'
    }
    It 'the bands are sidata.FindingFacet''s CVSS words on every edge; no score = no band' {
        $f = $script:Plan.Fields['cvssBand']
        foreach ($p in @(@(10, 'Critical (9.0-10)'), @(9, 'Critical (9.0-10)'), @(8.99, 'High (7.0-8.9)'), @('7', 'High (7.0-8.9)'), @(6.9, 'Medium (4.0-6.9)'), @(4, 'Medium (4.0-6.9)'), @(3.9, 'Low (0.1-3.9)'), @(0.1, 'Low (0.1-3.9)'), @(0, 'None (0)'), @(-1, 'None (0)'))) {
            ConvertTo-SISummaryGroupingValue -Field $f -Value $p[0] -Plan $script:Plan | Should -Be $p[1]
        }
        ConvertTo-SISummaryGroupingValue -Field $f -Value $null -Plan $script:Plan | Should -Be ''
        ConvertTo-SISummaryGroupingValue -Field $f -Value 'n/a' -Plan $script:Plan | Should -Be ''
        # the SQL twin: the same edges as the derive's facet ('>= 9', '>= 7', '>= 4', '> 0', else)
        $s = Get-SISummaryGroupingSqlValue -Field $f -Plan $script:Plan
        $s | Should -Be "CASE WHEN f.Cvss IS NULL THEN N'' WHEN CONVERT(float, f.Cvss) >= 9 THEN N'Critical (9.0-10)' WHEN CONVERT(float, f.Cvss) >= 7 THEN N'High (7.0-8.9)' WHEN CONVERT(float, f.Cvss) >= 4 THEN N'Medium (4.0-6.9)' WHEN CONVERT(float, f.Cvss) > 0 THEN N'Low (0.1-3.9)' ELSE N'None (0)' END"
        $derive = Get-Content -Raw (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
        foreach ($w in "Cvss >= 9 THEN N'Critical (9.0-10)'", "Cvss >= 7 THEN N'High (7.0-8.9)'", "Cvss >= 4 THEN N'Medium (4.0-6.9)'", "Cvss > 0 THEN N'Low (0.1-3.9)' ELSE N'None (0)'") { $derive | Should -Match ([regex]::Escape($w)) }
    }
    It 'tokens: split on the field''s separators and ";", trimmed, distinct ignoring case, every list shape' {
        $t = $script:Plan.Fields['mitreTactic']
        @(ConvertTo-SISummaryGroupingTokens -Field $t -Value 'Initial Access, Persistence') | Should -Be @('Initial Access', 'Persistence')
        @(ConvertTo-SISummaryGroupingTokens -Field $t -Value @('Persistence', 'persistence', ' Initial Access ')) | Should -Be @('Persistence', 'Initial Access')
        @(ConvertTo-SISummaryGroupingTokens -Field $t -Value '["T1", "T2"]') | Should -Be @('T1', 'T2')
        @(ConvertTo-SISummaryGroupingTokens -Field $t -Value '').Count | Should -Be 0
        @(ConvertTo-SISummaryGroupingTokens -Field $t -Value $null).Count | Should -Be 0
        @(ConvertTo-SISummaryGroupingTokens -Field $script:Plan.Fields['complianceTag'] -Value 'CIS 1.1, extended; NIST') | Should -Be @('CIS 1.1, extended', 'NIST')
    }
    It 'a finding counts once under each of its tokens; no token = not in the grouping; the counted variant leaves the exempted out' {
        $ia = Pick $script:TokRes 'mitre-tactic' 'Initial Access'
        $ia[0].Findings | Should -Be 2
        $ia[0].Assets | Should -Be 2
        (Pick $script:TokRes 'mitre-tactic' 'Persistence')[0].Findings | Should -Be 2 -Because 'persistence twice on one finding counts once'
        (Pick $script:TokRes 'mitre-tactic' 'Persistence' $true)[0].Findings | Should -Be 1
        @($script:TokRes | Where-Object { $_.GroupingId -eq 'mitre-tactic' -and -not $_.Counted }).Count | Should -Be 2 -Because 'findings without a tactic stand in no group'
        (Pick $script:TokRes 'mitre-technique' 'T1190')[0].Findings | Should -Be 2
        (Pick $script:TokRes 'mitre-technique' 'T1078')[0].Findings | Should -Be 1
        (Pick $script:TokRes 'compliance-control' 'CIS 1.1')[0].Findings | Should -Be 1
        (Pick $script:TokRes 'compliance-control' 'CIS 1.1, extended')[0].Findings | Should -Be 1
        (Pick $script:TokRes 'compliance-control' 'NIST AC-2')[0].TotalRisk | Should -Be 10
    }
    It 'every finding stands in one CVSS band (none = an empty key)' {
        foreach ($p in @(@('Critical (9.0-10)', 1), @('High (7.0-8.9)', 1), @('Medium (4.0-6.9)', 1), @('Low (0.1-3.9)', 1), @('None (0)', 1), @('', 1))) {
            (Pick $script:TokRes 'cvss-band' $p[0])[0].Findings | Should -Be $p[1]
        }
        (Pick $script:TokRes 'cvss-band' 'High (7.0-8.9)' $true).Count | Should -Be 0
    }
    It 'the SQL: the token key through ONE CROSS APPLY in its own grouping, the state names the groupings it holds' {
        $sql = Invoke-SISummaryGrouping -AsSql
        $sql | Should -Match ([regex]::Escape("REPLACE(ISNULL(CONVERT(nvarchar(4000), f.MitreTactics), N''), N',', N';')"))
        $sql | Should -Match ([regex]::Escape("ISNULL(CONVERT(nvarchar(4000), f.ComplianceTags), N'')"))
        @([regex]::Matches($sql, 'CROSS APPLY \(SELECT DISTINCT LEFT\(LTRIM\(RTRIM\(ts\.\[value\]\)\), 400\) AS V FROM STRING_SPLIT\(f\.x_')).Count | Should -Be 3
        $sql | Should -Match "SELECT N'mitre-tactic', v\.Counted, tk\.V, N'', N''"
        $sql | Should -Match 'GROUP BY v\.Counted, tk\.V;'
        $sql | Should -Match "x_mitreTactic nvarchar\(4000\) COLLATE DATABASE_DEFAULT NOT NULL"
        $sql | Should -Match "N';recommendation-tier;recommendation;asset;.*;mitre-tactic;mitre-technique;compliance-control;cvss-band;'"
    }
}
Describe 'THE engine function over Detailed rows (Community: in the run, no SQL)' {
    BeforeAll { $script:Res = @(Invoke-SISummaryGrouping -Rows (Fixture)) }
    It 'per recommendation: findings, distinct assets, risk, tier, severity and exploit measures' {
        $r = Pick $script:Res 'recommendation' 'CVE-1'
        $r.Count | Should -Be 1
        $r[0].Label | Should -Be 'Vuln one'
        $r[0].Findings | Should -Be 2
        $r[0].Assets | Should -Be 2
        $r[0].MaxRisk | Should -Be 90
        $r[0].TotalRisk | Should -Be 140
        $r[0].BestTier | Should -Be 0
        $r[0].Tier0Findings | Should -Be 1
        $r[0].CriticalFindings | Should -Be 1
        $r[0].HighFindings | Should -Be 1
        $r[0].RatedCriticalFindings | Should -Be 1
        $r[0].ExploitedRecommendations | Should -Be 1
    }
    It 'the counted variant leaves the exempted finding out' {
        (Pick $script:Res 'recommendation' 'CVE-2').Count | Should -Be 1
        (Pick $script:Res 'recommendation' 'CVE-2' $true).Count | Should -Be 0
        (Pick $script:Res 'tier' '0')[0].Findings | Should -Be 2
        (Pick $script:Res 'tier' '0' $true)[0].Findings | Should -Be 1
        (Pick $script:Res 'tier' '0')[0].Assets | Should -Be 1 -Because 'a1 twice is one asset'
    }
    It 'an attack path takes its source tier; "Tier2" is tier 2; no tier is Unclassified; an empty asset is never an asset' {
        (Pick $script:Res 'tier' '2')[0].Findings | Should -Be 2
        (Pick $script:Res 'tier' '2')[0].Assets | Should -Be 2
        $u = Pick $script:Res 'tier' 'Unclassified'
        $u[0].Findings | Should -Be 1
        $u[0].Assets | Should -Be 0
        (Pick $script:Res 'asset' '')[0].Assets | Should -Be 0
        (Pick $script:Res 'tier' '0')[0].Findings | Should -Be 2 -Because 'the path row (target tier 0) is not on tier 0'
    }
    It 'severity words, the Domain > Category > Subcategory levels, departments, reports' {
        (Pick $script:Res 'severity' 'Very High')[0].Findings | Should -Be 2
        (Pick $script:Res 'severity' 'High')[0].Findings | Should -Be 2
        (Pick $script:Res 'severity' 'Medium')[0].Findings | Should -Be 1
        (Pick $script:Res 'severity' 'None')[0].Findings | Should -Be 1
        (Pick $script:Res 'domain-category-subcategory' 'Endpoint' $false 'Vulnerability' 'OS')[0].Findings | Should -Be 2
        (Pick $script:Res 'domain-category' 'Endpoint' $false 'Vulnerability')[0].Recommendations | Should -Be 2
        (Pick $script:Res 'domain' 'Endpoint')[0].Assets | Should -Be 2
        (Pick $script:Res 'department' '0')[0].Findings | Should -Be 6
        (Pick $script:Res 'report' 'Device_Missing_CVEs_Detailed')[0].Recommendations | Should -Be 2
        (Pick $script:Res 'report' 'Device_Missing_CVEs_Detailed')[0].CriticalRecommendations | Should -Be 2
        (Pick $script:Res 'report' 'Device_Missing_CVEs_Detailed' $true)[0].Recommendations | Should -Be 1
    }
    It 'a pager gives the same result as the rows; no rows = no groups' {
        $pages = [System.Collections.Generic.Queue[object]]::new()
        $all = @(Fixture); $pages.Enqueue(@($all[0..2])); $pages.Enqueue(@($all[3..5]))
        $pager = [pscustomobject]@{ Q = $pages }
        $pager | Add-Member -MemberType ScriptMethod -Name Next -Value { if ($this.Q.Count) { , $this.Q.Dequeue() } else { $null } }
        $p = @(Invoke-SISummaryGrouping -Pager $pager)
        $text = { param($x) @($x | ForEach-Object { ($_.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join '|' } | Sort-Object) -join "`n" }
        (& $text $p) | Should -Be (& $text $script:Res)
        @(Invoke-SISummaryGrouping -Rows @()).Count | Should -Be 0
    }
    It 'Select-SISummaryGroupingRows: one grouping and variant, most findings first' {
        $t = @(Select-SISummaryGroupingRows -Result $script:Res -GroupingId 'tier')
        $t[0].Findings | Should -BeGreaterOrEqual $t[-1].Findings
        @($t | ForEach-Object { [bool]$_.Counted } | Select-Object -Unique) | Should -Be @($false)
    }
}

Describe 'the statement of one stored collection (Pro, -AsSql)' {
    BeforeAll { $script:Sql = Invoke-SISummaryGrouping -AsSql }
    It 'reads the collection once, narrow columns only, every finding -- no DetailJson, no cap' {
        @([regex]::Matches($script:Sql, 'FROM sidata\.Finding AS f')).Count | Should -Be 1
        $script:Sql | Should -Match 'WHERE f\.CollectionId = @CollectionId AND \(f\.CiLifecycle IS NULL OR f\.CiLifecycle = N''active''\);'   # #855: the stored groupings count active CIs
        $script:Sql | Should -Not -Match 'DetailJson'
        # the one TOP is a list attribute's own length (the first ten asset names shown on a row), never a cap on the findings
        ([regex]::Replace($script:Sql, '(?i)SELECT DISTINCT TOP \(\d+\) f2\.x_\w+ AS V FROM #f AS f2', '')) | Should -Not -Match '(?i)\bTOP\s*\('
        $script:Sql | Should -Not -Match '(?i)TABLESAMPLE'
    }
    It 'one aggregate per grouping, both variants, and the state in ONE transaction' {
        foreach ($g in $script:Plan.Groupings) { $script:Sql | Should -Match ("SELECT N'{0}', v\.Counted" -f [regex]::Escape($g.Id)) }
        $script:Sql | Should -Match "WHERE v\.Counted = 0 OR f\.x_exempted = N'0'"
        $tran = $script:Sql.Substring($script:Sql.IndexOf('BEGIN TRAN;'))
        foreach ($t in 'SummaryGroup', 'SummaryGroupCounted', 'SummaryGroupState') { $tran | Should -Match ("DELETE FROM sidata\.{0} WHERE CollectionId = @CollectionId;" -f $t) }
        $tran.IndexOf('COMMIT;') | Should -BeGreaterThan $tran.IndexOf('INSERT sidata.SummaryGroupState')
        $script:Sql | Should -Match 'SET XACT_ABORT ON;'
        foreach ($m in $script:Plan.MeasureIds) { $script:Sql | Should -Match ("\b{0}\b" -f $m) }
        $script:Sql | Should -Match "COUNT\(DISTINCT NULLIF\(f\.x_asset, N''\)\)"
    }
}

Describe 'the Summary report''s shape: per recommendation AND tier with the report''s columns (owner 2026-10-20)' {
    # "the summary view must be grouped data based on detailed data, but with output similar to what we had for the old summary
    # report where the same vulnerability existed in the report but with different tier so we had quick overview"
    BeforeAll {
        $rows = @(Fixture) + @(
            (Row @{ SI_AssetId = 'a4'; AssetName = 'host4'; ConfigurationId = 'CVE-1'; ConfigurationName = 'Vuln one'; CriticalityTier = 0; SecuritySeverity = 'Medium'; SecurityDomain = 'Endpoint'; Category = 'Vulnerability'; Subcategory = 'OS'; RiskRating = 'Moderate'; RiskScoreTotal = 10; si_fix_remediation = 'Install KB1'; si_source_first_seen = '2026-09-03T10:00:00Z'; AssetDetectedInReportName = 'Device_Missing_CVEs_Detailed' })
            (Row @{ SI_AssetId = 'a1'; AssetName = 'host1'; ConfigurationId = 'CVE-1'; ConfigurationName = 'Vuln one'; CriticalityTier = 0; SecuritySeverity = 'Critical'; SecurityDomain = 'Endpoint'; Category = 'Vulnerability'; Subcategory = 'OS'; RiskRating = 'Critical'; RiskScoreTotal = 5; si_source_first_seen = '2026-08-20'; AssetDetectedInReportName = 'Device_Missing_CVEs_Detailed' })
        )
        $script:R2 = @(Invoke-SISummaryGrouping -Rows $rows)
        function script:Attr($r) { if ($r.AttributesJson) { $r.AttributesJson | ConvertFrom-Json } }
    }
    It 'is the definition''s first grouping: keys recommendation and tier, its attributes in order' {
        $g = $script:Plan.Groupings[0]
        $g.Id | Should -Be 'recommendation-tier'
        @($g.Keys | Where-Object { $_ }) | Should -Be @('recommendation', 'tier')
        @($g.Attributes | ForEach-Object Id) | Should -Be @('Domain', 'Category', 'Subcategory', 'Severity', 'RiskRating', 'AssetNames', 'FirstSeen', 'Remediation')
        @($script:Plan.Groupings | Where-Object { $_.Id -ne 'recommendation-tier' } | Where-Object { @($_.Attributes).Count }) | Should -BeNullOrEmpty
    }
    It 'the same vulnerability once per tier it is on; every finding in exactly one row' {
        (Pick $script:R2 'recommendation-tier' 'CVE-1' $false '0').Count | Should -Be 1
        (Pick $script:R2 'recommendation-tier' 'CVE-1' $false '1').Count | Should -Be 1
        $t0 = (Pick $script:R2 'recommendation-tier' 'CVE-1' $false '0')[0]
        $t0.Findings | Should -Be 3
        $t0.Assets | Should -Be 2 -Because 'host1 twice is one asset'
        $t0.Label | Should -Be 'Vuln one'
        $n = 0; foreach ($r in @($script:R2 | Where-Object { $_.GroupingId -eq 'recommendation-tier' -and -not $_.Counted })) { $n += $r.Findings }
        $n | Should -Be 8
    }
    It 'the attributes: domain / category, the MOST severe severity and rating (never the alphabetical one), the names, first seen, remediation' {
        $a = Attr (Pick $script:R2 'recommendation-tier' 'CVE-1' $false '0')[0]
        $a.Domain | Should -Be 'Endpoint'
        $a.Category | Should -Be 'Vulnerability'
        $a.Subcategory | Should -Be 'OS'
        $a.Severity | Should -Be 'Very High' -Because 'Critical normalises to Very High; Medium on the same row group does not win'
        $a.RiskRating | Should -Be 'Critical'
        $a.AssetNames | Should -Be 'host1; host4' -Because 'distinct, in order'
        $a.FirstSeen | Should -Be '2026-08-20' -Because 'the earliest day'
        $a.Remediation | Should -Be 'Install KB1' -Because 'the empty remediation never wins'
        $b = Attr (Pick $script:R2 'recommendation-tier' 'CVE-1' $false '1')[0]
        $b.Severity | Should -Be 'High'
        $b.PSObject.Properties['FirstSeen'] | Should -BeNullOrEmpty -Because 'no first seen = left out, as the SQL''s FOR JSON leaves a NULL out'
        $b.PSObject.Properties['Remediation'] | Should -BeNullOrEmpty
        # the other groupings carry no attributes
        (Pick $script:R2 'recommendation' 'CVE-1')[0].AttributesJson | Should -BeNullOrEmpty
    }
    It 'a list attribute shows at most its "max" names; the counted variant leaves the exempted out of the names too' {
        $g = $script:Plan.Groupings[0]
        $many = @(1..14 | ForEach-Object { Row @{ SI_AssetId = "m$_"; AssetName = ('srv{0:D2}' -f $_); ConfigurationId = 'CVE-9'; ConfigurationName = 'Nine'; CriticalityTier = 1; SecuritySeverity = 'Low'; SI_ExemptionId = $(if ($_ -eq 1) { '5' }) } })
        $r = @(Invoke-SISummaryGrouping -Rows $many -Grouping 'recommendation-tier')
        $all = Attr (Pick $r 'recommendation-tier' 'CVE-9' $false '1')[0]
        @($all.AssetNames -split '; ').Count | Should -Be ($g.Attributes | Where-Object Id -eq 'AssetNames').Max
        ($all.AssetNames -split '; ')[0] | Should -Be 'srv01'
        (Attr (Pick $r 'recommendation-tier' 'CVE-9' $true '1')[0]).AssetNames.Split('; ')[0] | Should -Be 'srv02' -Because 'the exempted srv01 is not in the counted row'
    }
    It 'the SQL: per grouping with attributes ONE update from the findings of its keys, as one JSON object -- the same rules' {
        $sql = Invoke-SISummaryGrouping -AsSql
        $sql | Should -Match 'AttributesJson NVARCHAR\(MAX\) NULL\);'
        $sql | Should -Match 'CREATE INDEX IX_f_recommendation_tier ON #f \(x_recommendation, x_tier\)'
        $sql | Should -Match "UPDATE s SET AttributesJson = \(SELECT MAX\(NULLIF\(f\.x_domain, N''\)\) AS \[Domain\]"
        $sql | Should -Match "WHEN f\.x_severity = N'Very High' THEN 1"
        $sql | Should -Match 'FOR JSON PATH, WITHOUT_ARRAY_WRAPPER\)'
        $sql | Should -Match "FROM #s AS s WHERE s\.GroupingId = N'recommendation-tier';"
        $sql | Should -Match "\(s\.Counted = 0 OR f\.x_exempted = N'0'\)"
        $sql | Should -Match 'CONVERT\(nvarchar\(10\), CONVERT\(date, f\.SourceFirstDetected\), 23\)'
        $sql.IndexOf('UPDATE s SET AttributesJson') | Should -BeLessThan $sql.IndexOf('BEGIN TRAN;')
        $sql | Should -Match 'INSERT sidata\.SummaryGroup \(CollectionId, GroupingId, Key1, Key2, Key3, Label, .*, AttributesJson\)'
    }
    It 'refuses an attribute it cannot keep: an unknown op, a tokens field, a list without its length, a ''first'' without its order' {
        $base = Get-Content -Raw (Join-Path $script:Root 'data-model\summary-groupings.locked.json')
        foreach ($case in @(
                @{ Op = 'sum'; Field = 'domain'; Extra = ''; Msg = '*unknown op*' },
                @{ Op = 'max'; Field = 'mitreTactic'; Extra = ''; Msg = '*tokens field*' },
                @{ Op = 'list'; Field = 'assetName'; Extra = ''; Msg = "*needs 'max'*" },
                @{ Op = 'first'; Field = 'severity'; Extra = ''; Msg = "*needs 'order'*" })) {
            $d = $base | ConvertFrom-Json
            $d.groupings[0].attributes = @([pscustomobject]@{ id = 'X'; op = $case.Op; field = $case.Field })
            { Get-SISummaryGroupingPlan -Definition $d } | Should -Throw $case.Msg
        }
    }
}

Describe 'Community: the Detailed run computes them for its management mail and outputs' {
    BeforeAll {
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-ReportMail.ps1')
        $script:Ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
    }
    It 'the mail section lists the tiers, the domains, the top recommendations by affected assets and the risk ratings' {
        $h = ConvertTo-RAReportMailGroupingsHtml -Result @(Invoke-SISummaryGrouping -Rows (Fixture))
        $h | Should -Match 'Management summary'
        $h | Should -Match 'Tier 0'
        $h | Should -Match 'Unclassified'
        $h | Should -Match 'Findings per domain'
        $h | Should -Match 'Top \d+ recommendations by affected assets'
        $h | Should -Match 'Vuln one'
        $h | Should -Match 'Per risk rating'
        ConvertTo-RAReportMailGroupingsHtml -Result @() | Should -Be ''
        $c = ConvertTo-RAReportMailGroupingsHtml -Result @(Invoke-SISummaryGrouping -Rows (Fixture)) -Counted $true
        $c | Should -Not -Match 'Vuln two' -Because 'its only finding is exempted'
    }
    It 'is wired: a Detailed run without the Pro database computes them with THE function, writes them next to the workbook and mails them' {
        $script:Ra | Should -Match ([regex]::Escape("if ([bool]`$global:Detailed -and -not `$script:RAStreamOn -and -not `$script:SIWhatIf) {"))
        $script:Ra | Should -Match ([regex]::Escape('$script:RASummaryGroupings = @(Invoke-SISummaryGrouping -Rows'))
        $script:Ra | Should -Match ([regex]::Escape("'.groupings.json'"))
        $script:Ra | Should -Match ([regex]::Escape('-GroupingsHtml $__sgHtml'))
        $script:Ra.IndexOf('$script:RASummaryGroupings = @(Invoke-SISummaryGrouping') | Should -BeGreaterThan $script:Ra.IndexOf('$global:RA_KPI = $null')
        $script:Ra | Should -Not -Match 'Invoke-SISummaryGrouping -AsSql' -Because 'the engine never writes the stored groupings itself'
    }
    It 'the RA mail body carries the section after the risk by domain' {
        $kpi = [pscustomobject]@{ GlobalScore = 80; Band = 'Good'; DomainScore = @{ Endpoint = 80 }; SevCount = @{ Critical = 1; High = 2; Medium = 0; Low = 0 }; SevByDomain = @{}; TotalRows = 6 }
        $b = ConvertTo-RAReportMailHtml -Kpi $kpi -ReportLabel 'Detailed' -GroupingsHtml '<p data-x>GROUPINGS</p>'
        $b.IndexOf('GROUPINGS') | Should -BeGreaterThan $b.IndexOf('Risk by domain')
    }
}

Describe 'the Summary step: off by default, its mail settings move to the management mail' {
    It 'reads the state of a stored pipeline (schema 2 or 1, a caj-si- name, schedules mode = unknown)' {
        Get-SISummaryStepStateFromJson -Json '{"schema":2,"mode":"flow","stages":[{"id":"correlate","steps":[{"job":"risk-analysis","enabled":false},{"job":"risk-analysis-detailed"}]}]}' | Should -Be 'off'
        Get-SISummaryStepStateFromJson -Json '{"schema":2,"mode":"flow","stages":[{"id":"correlate","steps":[{"job":"caj-si-risk-analysis","enabled":true}]}]}' | Should -Be 'on'
        Get-SISummaryStepStateFromJson -Json '{"schema":1,"steps":[{"job":"risk-analysis"}]}' | Should -Be 'on'
        Get-SISummaryStepStateFromJson -Json '{"schema":2,"mode":"flow","stages":[{"id":"correlate","steps":[{"job":"risk-analysis-detailed"}]}]}' | Should -Be 'off'
        Get-SISummaryStepStateFromJson -Json '{"schema":2,"mode":"schedules","stages":[]}' | Should -Be 'unknown'
        Get-SISummaryStepStateFromJson -Json 'not json' | Should -Be 'unknown'
        Get-SISummaryStepDefaultState | Should -Be 'off'
    }
    It 'reads the Pro database first, else the file, else the default; -StoredOnly never guesses' {
        $db = { param($q, $p, $m) if ($q -match 'cfg\.JobFlow') { , @(@{ DefinitionJson = '{"mode":"flow","steps":[{"job":"risk-analysis","enabled":true}]}' }) } }
        Get-SISummaryStepState -Invoke $db -FlowFile 'C:\nope.json' | Should -Be 'on'
        Get-SISummaryStepState -Invoke { param($q, $p, $m) , @() } -FlowFile 'C:\nope.json' | Should -Be 'off'
        Get-SISummaryStepState -Invoke { param($q, $p, $m) , @() } -FlowFile 'C:\nope.json' -StoredOnly | Should -Be 'unknown'
        Get-SISummaryStepState -Invoke { param($q, $p, $m) throw 'down' } | Should -Be 'unknown'
    }
    It 'the management mail gets the Summary recipients while the step is off -- never twice, nothing moves otherwise' {
        $m = Resolve-SIManagementMailRouting -DetailedSend $true -DetailedTo @('a@x.dk', 'B@x.dk') -SummarySend $true -SummaryTo @('b@x.dk', 'c@x.dk') -SummaryStep off
        $m.Send | Should -BeTrue; $m.To | Should -Be @('a@x.dk', 'B@x.dk', 'c@x.dk'); $m.Moved | Should -Be @('c@x.dk')
        $m = Resolve-SIManagementMailRouting -DetailedSend $false -DetailedTo @('a@x.dk') -SummarySend $true -SummaryTo @('c@x.dk') -SummaryStep off
        $m.Send | Should -BeTrue; $m.To | Should -Be @('c@x.dk') -Because 'the Detailed recipients did not ask for the mail'
        $m = Resolve-SIManagementMailRouting -DetailedSend $false -DetailedTo @('a@x.dk') -SummarySend $true -SummaryTo @('c@x.dk') -SummaryStep on
        $m.Send | Should -BeFalse; $m.To | Should -Be @('a@x.dk')
        $m = Resolve-SIManagementMailRouting -DetailedSend $true -DetailedTo @('a@x.dk') -SummarySend $true -SummaryTo @('c@x.dk') -SummaryStep unknown
        $m.To | Should -Be @('a@x.dk')
        (Resolve-SIManagementMailRouting -DetailedSend $true -DetailedTo @('a@x.dk') -SummarySend $false -SummaryTo @('c@x.dk') -SummaryStep off).To | Should -Be @('a@x.dk')
    }
    It 'is wired into both mail routings of Risk Analysis and narrowed once more before the send with the stored pipeline' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        @([regex]::Matches($ra, [regex]::Escape('$__mm = Resolve-SIManagementMailRouting @script:RAMgmtMail -SummaryStep $script:RAMgmtMailEarly'))).Count | Should -Be 2
        $ra | Should -Match ([regex]::Escape('$__mmState = Get-SISummaryStepState -Invoke $script:RAStream.Invoke'))
        $ra.IndexOf('$__mmState = Get-SISummaryStepState') | Should -BeLessThan $ra.IndexOf('$__toRaw     = @($global:Report_To)')
    }
}

Describe 'the pipeline: the Summary step off by default (layout level 4)' {
    BeforeAll {
        . (Join-Path $script:Root 'engine\_shared\SI-JobFlow.ps1')
        . (Join-Path $script:Root 'setup\_shared\SI-PipelineLayout.ps1')
        $script:Map = Get-SIJobFlowMap
        # every job of the shipped default pipeline (from the map: job names only, never a load of a folder)
        $script:All = @($script:Map.DefaultPipeline.Stages | ForEach-Object { @($_.Steps) })
        # the default pipeline of level 3 as an install stored it (every step on)
        function script:Level3Json([scriptblock]$Change) {
            $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map -StartTime '23:30' -TimeZone 'Europe/Copenhagen'
            foreach ($s in $d.Steps) { $s.Enabled = $true }
            $d.DefaultsLevel = 3
            if ($Change) { & $Change $d }
            ConvertTo-SIJobFlowJson -Definition $d
        }
    }
    It 'the map ships risk-analysis switched off; the trend and the data sync need only Detailed' {
        $script:Map.Jobs['risk-analysis'].DefaultEnabled | Should -BeFalse
        $script:Map.Jobs['risk-analysis-detailed'].DefaultEnabled | Should -BeTrue
        $script:Map.Jobs['asset-trend'].Needs | Should -Be @('risk-analysis-detailed')
        $script:Map.Jobs['asset-datasync'].Reads | Should -Not -Contain 'risk-analysis'
        $script:SIJobFlow.DefaultsLevel | Should -Be 4
    }
    It 'a new pipeline has the step, switched off' {
        $d = New-SIDefaultJobFlow -Installed $script:All -Map $script:Map
        @($d.Steps | Where-Object Job -eq 'risk-analysis')[0].Enabled | Should -BeFalse
        @($d.Steps | Where-Object Job -eq 'risk-analysis-detailed')[0].Enabled | Should -BeTrue
        @($d.Steps | Where-Object { -not $_.Enabled }).Count | Should -Be 1
    }
    It 'a stored default pipeline with every step on gets it switched off as it is read -- once, said in one line' {
        $d = ConvertFrom-SIJobFlowJson -Json (Level3Json) -Map $script:Map
        @($d.Steps | Where-Object Job -eq 'risk-analysis')[0].Enabled | Should -BeFalse
        $d.DefaultsLevel | Should -Be 4
        $d.Migrated | Should -BeTrue
        (@($d.MigrationNotes) -join ' ') | Should -Match 'risk-analysis is now switched off'
        $again = ConvertFrom-SIJobFlowJson -Json (ConvertTo-SIJobFlowJson -Definition $d) -Map $script:Map
        @($again.Steps | Where-Object Job -eq 'risk-analysis')[0].Enabled | Should -BeFalse
        [bool]($again.PSObject.Properties['Migrated'] -and $again.Migrated) | Should -BeFalse -Because 'stored at level 4 the decision is never made again'
    }
    It 'a person who switches it on again keeps it on (level 4)' {
        $d = ConvertFrom-SIJobFlowJson -Json (Level3Json) -Map $script:Map
        @($d.Steps | Where-Object Job -eq 'risk-analysis')[0].Enabled = $true
        $back = ConvertFrom-SIJobFlowJson -Json (ConvertTo-SIJobFlowJson -Definition $d) -Map $script:Map
        @($back.Steps | Where-Object Job -eq 'risk-analysis')[0].Enabled | Should -BeTrue
    }
    It 'a pipeline a person changed keeps the step on, and one line says so' {
        $json = Level3Json { param($d) @($d.Steps | Where-Object Job -eq 'close-loop-mail')[0].Enabled = $false }
        $d = ConvertFrom-SIJobFlowJson -Json $json -Map $script:Map
        @($d.Steps | Where-Object Job -eq 'risk-analysis')[0].Enabled | Should -BeTrue
        (@($d.MigrationNotes) -join ' ') | Should -Match 'risk-analysis stays switched on: the pipeline was changed by a person'
        $plan = Get-SIPipelineLayoutPlan -FlowJson $json -Installed $script:All -Map $script:Map
        $plan.Changed | Should -BeTrue
        (@($plan.Lines) -join ' ') | Should -Match 'stays switched on'
    }
    It 'the update stores it (the layout plan) with its line' {
        $plan = Get-SIPipelineLayoutPlan -FlowJson (Level3Json) -Installed $script:All -Map $script:Map
        $plan.Changed | Should -BeTrue
        (@($plan.Lines) -join ' ') | Should -Match 'risk-analysis is now switched off'
        (Get-SISummaryStepStateFromJson -Json $plan.FlowJson) | Should -Be 'off'
        (Get-SIPipelineLayoutPlan -FlowJson $plan.FlowJson -Installed $script:All -Map $script:Map).Changed | Should -BeFalse
    }
    It 'the update moves the scheduled Summary management reports to Detailed only while the step is off' {
        $calls = [System.Collections.Generic.List[string]]::new()
        $off = '{"schema":2,"mode":"flow","stages":[{"id":"correlate","steps":[{"job":"risk-analysis","enabled":false}]}]}'
        $sql = { param($q, $p, $m) $calls.Add($q); if ($q -match 'cfg\.JobFlow') { return [pscustomobject]@{ DefinitionJson = $off } }; if ($q -match 'SELECT ReportId') { return [pscustomobject]@{ ReportId = 5; Name = 'Board' } }; if ($m -eq 'nonquery') { return 1 } }.GetNewClosure()
        $r = Invoke-SIMgmtReportsDetailed -Sql $sql
        $r.Action | Should -Be 'changed'
        (@($r.Lines) -join ' ') | Should -Match "'Board' now shows the Detailed report's data"
        @($calls | Where-Object { $_ -match "SET Grain = N'Detailed'" }).Count | Should -Be 1
        $on = '{"schema":2,"mode":"flow","stages":[{"id":"correlate","steps":[{"job":"risk-analysis","enabled":true}]}]}'
        $sql2 = { param($q, $p, $m) if ($q -match 'cfg\.JobFlow') { return [pscustomobject]@{ DefinitionJson = $on } }; throw 'must not read the reports' }.GetNewClosure()
        (Invoke-SIMgmtReportsDetailed -Sql $sql2).Action | Should -Be 'kept'
        (Invoke-SIMgmtReportsDetailed -Sql $sql -WhatIf).Action | Should -Be 'plan'
    }
    It 'is wired into the update next to the pipeline layout' {
        $u = [IO.File]::ReadAllText((Join-Path $script:Root 'setup\Invoke-SIContainerUpdate.ps1'))
        $u | Should -Match ([regex]::Escape('$m = Invoke-SIMgmtReportsDetailed -Sql $sql -WhatIf:(-not $Apply -or $DetectOnly)'))
        $u.IndexOf('Invoke-SIMgmtReportsDetailed -Sql $sql') | Should -BeGreaterThan $u.IndexOf('$r = Invoke-SIPipelineLayout -Sql $sql')
    }
}

Describe 'what hung on the Summary report' {
    It 'the daily trend row is written by the Detailed run (it counts findings)' {
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-TrendAtEnd.ps1')
        (Test-SIRaTrendAtEnd -Detailed $true -Published $true -WhatIfRun $false -RowCount 3).Run | Should -BeTrue
        (Test-SIRaTrendAtEnd -Detailed $false -Published $true -WhatIfRun $false -RowCount 3).Why | Should -Match 'not a detailed run'
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $ra | Should -Match ([regex]::Escape('-Detailed ([bool]$global:Detailed) -Published'))
        $ra | Should -Match ([regex]::Escape('if ($script:RAStreamOn -and [bool]$global:Detailed -and $null -ne $script:_RAPublishedRows) { $__trRollup = @(Get-RAStreamTrendRollup'))
        [IO.File]::ReadAllText((Join-Path $script:Root 'engine\asset-trend\Invoke-SITrend.ps1')) | Should -Match ([regex]::Escape("[ValidateSet('Summary','Detailed')][string]`$Grain = 'Detailed'"))
    }
    It 'the trend rollup of a Detailed run in SQL: the findings of the collection, distinct assets, the counted twin' {
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-SqlStream.ps1')
        $s = Get-RAStreamTrendSql -Grain Detailed
        $s | Should -Match 'FROM sidata\.Finding WHERE CollectionId = CONVERT\(int, @CollectionId\) AND RaSeq IS NOT NULL'
        $s | Should -Match 'COUNT\(DISTINCT d\.A\) AS Assets'
        $s | Should -Match "x\.Dim \+ '-counted'"
        $s | Should -Not -Match 'DetailJson'
        Get-RAStreamTrendSql | Should -Match 'FROM sidata\.SummaryRow' -Because 'the Summary grain stays for an install that switched the step on'
    }
    It 'the AI-summary leader defaults to Detailed (an unknown value too)' {
        . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-AISummaryMode.ps1')
        (Resolve-RAAISummaryLeader -Value '').Leader | Should -Be 'Detailed'
        (Resolve-RAAISummaryLeader -Value 'banana').Leader | Should -Be 'Detailed'
        (Resolve-RAAISummaryLeader -Value 'summary').Leader | Should -Be 'Summary'
    }
}
