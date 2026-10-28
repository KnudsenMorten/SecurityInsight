#Requires -Version 5.1
<#
    M4 -- RISK ANALYSIS ON CIs (V3-DATA-MODEL 2.21; engine/risk-analysis/_shared/RA-CiContext.ps1, RA-RiskScore.ps1,
    RA-ModelCompare.ps1). What these tests keep true:
      * the data model is 'legacy' unless SI_DataModel = ci; the stale days are SI_ActiveStaleDays (default 30);
      * the 'ci' index query takes the CI SET from the latest build (seen or full rows) and each CI's PROPERTIES from its
        latest FULL row within the stale days, marks stale CIs, and reads a table without si_row_kind as all full; the
        'legacy' query is unchanged;
      * the factor catalog: every ASSET factor the catalog evaluates is keyed by its id, short name, description and legacy
        tokens; finding and report-scoped factors are not; a factor is shown by its short name (#558 / #559);
      * 'ci': the CI's production factors REPLACE the report's asset-catalog tokens (never twice; testing factors not
        counted), the CI's criticality factor is the weight over the report's, the CI's CMDB values win; the scorer drops
        asset tokens it derived from provider columns that the CI did not set; finding / report-scoped tokens stay;
      * 'legacy' is unchanged: the CI context on top, the report's weighting kept;
      * THE COMPARISON (M4's proof): the fixture scored legacy vs ci -- every moved row explained, none unexplained, and
        rows without a CI identical.
    Offline. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    function script:Write-Info { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Ok { param($m) }
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-FactorKeys.ps1')        # #559: the scorer's factor impacts (Measure-RARowFactors)
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiContext.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ModelCompare.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexOrder.ps1')      # New-RiskIndex reads the index in precedence order
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexSi.ps1')         # #559: the index keyed by the SI fields
    $global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ExcelReport.ps1'), [ref]$null, [ref]$null)
    $fn = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'New-RiskIndex' }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1')
    $shipped = @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
    $script:Idx = New-RiskIndex -CsvRows $shipped
    $factors = @((Get-Content -LiteralPath (Join-Path $script:SIRoot 'data-model\risk-factors.locked.json') -Raw | ConvertFrom-Json).factors)
    $script:Cat = New-RAFactorCatalog -Factors $factors
    $fx = Get-Content -LiteralPath (Join-Path $script:SIRoot 'tests\fixtures\ra-m4\compare-fixture.json') -Raw | ConvertFrom-Json
    $script:FxCis = @($fx.cis)
    $script:FxFindings = @($fx.findings)
    $script:Index = New-RACiIndex -Cis $script:FxCis
    $script:Score = {
        param($Rows)
        $ProgressPreference = 'SilentlyContinue'
        @(Calculate-RiskScore -Rows @($Rows) -RiskIndex $script:Idx -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
            -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -ReportName 'M4_Fixture')
    }
    function script:Clone($rows) { @($rows | ForEach-Object { $_.PSObject.Copy() }) }
}

AfterAll { $global:RA_FactorCatalog = $null; $global:SI_DataModel = $null }

Describe 'the data model and the stale days' {
    It 'is legacy unless SI_DataModel = ci' {
        Get-RADataModelMode -Setting $null | Should -Be 'legacy'
        Get-RADataModelMode -Setting 'legacy' | Should -Be 'legacy'
        Get-RADataModelMode -Setting ' CI ' | Should -Be 'ci'
    }
    It 'takes SI_ActiveStaleDays, default 30' {
        Get-RAStaleDays -Setting $null | Should -Be 30
        Get-RAStaleDays -Setting 'x' | Should -Be 30
        Get-RAStaleDays -Setting 45 | Should -Be 45
    }
}

Describe 'the CI index query' {
    It 'ci: the CI set from the latest build, properties from the latest full row within the stale days, stale marked' {
        $q = Get-RACiIndexKql -Mode ci -StaleDays 30
        $q | Should -Match 'ago\(30d\)'
        $q | Should -Match ([regex]::Escape("tostring(column_ifexists('si_row_kind', ''))"))
        $q | Should -Match ([regex]::Escape('let build_ = toscalar(ci_ | summarize max(si_t_));'))
        $q | Should -Match ([regex]::Escape("| where si_kind_ in ('full', '')"))
        $q | Should -Match ([regex]::Escape('| join kind=inner set_ on si_k_'))
        # #855 W10: stale = the CI's lifecycle says not seen; the day count only for a row without a lifecycle
        $q | Should -Match ([regex]::Escape("si_lc_ = tostring(column_ifexists('si_lifecycle', ''))"))
        $q | Should -Match ([regex]::Escape("si_stale_ = iff(isnotempty(si_lc_), si_lc_ == 'not_seen', isnotnull(si_seen_) and si_seen_ < ago(30d))"))
        $q | Should -Not -Match '//'
    }
    It 'legacy reads the same CI set (one query for both data models; the model changes what a finding takes)' {
        (Get-RACiIndexKql -Mode legacy -StaleDays 30) | Should -Be (Get-RACiIndexKql -Mode ci -StaleDays 30)
    }
    It 'the run reads the index for its data model and stale days' {
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiContext.ps1')) | Should -Match ([regex]::Escape('Get-RACiIndexKql -Mode (Get-RADataModelMode) -StaleDays (Get-RAStaleDays)'))   # (#639 adapted: the index is counted, then read per slice / per page -- each from this query)
    }
}

Describe 'the factor catalog' {
    It 'keys every asset factor by id and legacy tokens; finding and report-scoped factors are not asset keys' {
        $script:Cat.AssetKeys[(ConvertTo-RATokenKey 'InternetExposureSignal')] | Should -Be 'internet_exposed'
        $script:Cat.AssetKeys[(ConvertTo-RATokenKey 'RF_P_InternetExposed')] | Should -Be 'internet_exposed'
        # tier is never a factor (owner 2026-10-10): the retired tier factors are no asset keys
        $script:Cat.AssetKeys.ContainsKey((ConvertTo-RATokenKey 'Tier0BlastRadius')) | Should -BeFalse
        $script:Cat.AssetKeys.ContainsKey((ConvertTo-RATokenKey 'RF_P_Tier0')) | Should -BeFalse
        $script:Cat.AssetKeys.ContainsKey((ConvertTo-RATokenKey 'RF_P_ExploitSignals')) | Should -BeFalse
        $script:Cat.AssetKeys.ContainsKey((ConvertTo-RATokenKey 'RF_P_Frequent')) | Should -BeFalse
        # #558 / #559: a report shows the catalog's SHORT name; the short name and the description are asset keys too
        $script:Cat.Display['internet_exposed'] | Should -Be 'InternetExposed'
        $script:Cat.AssetKeys[(ConvertTo-RATokenKey 'InternetExposed')] | Should -Be 'internet_exposed'
        $script:Cat.AssetKeys[(ConvertTo-RATokenKey 'The asset can be reached from the internet')] | Should -Be 'internet_exposed'
        $script:Cat.Axis['ms_criticality_high'] | Should -Be 'consequence'
    }
    It 'keeps finding / report tokens and the CI''s own, drops other asset tokens' {
        @(Select-RACiModeTokens -Tokens @('RF_P_InternetExposed', 'InternetExposureSignal', 'RF_P_ExploitSignals', 'RF_P_Frequent') -Catalog $script:Cat -CiTokens @('RF_P_InternetExposed')) |
            Should -Be @('RF_P_InternetExposed', 'RF_P_ExploitSignals', 'RF_P_Frequent')
        @(Select-RACiModeTokens -Tokens @('RF_P_InternetExposed') -Catalog $script:Cat -CiTokens @()).Count | Should -Be 0
    }
}

Describe 'a finding''s CI context in each data model' {
    It 'ci: the CI''s factors replace the asset tokens, its weight and CMDB values win, testing factors do not count' {
        $rows = Clone $script:FxFindings
        $null = Add-RACiContext -Rows $rows -Index $script:Index -Mode ci -Catalog $script:Cat
        $dup = $rows | Where-Object case -EQ 'double-count'
        $dup.RiskFactor_Probability_Detailed | Should -Be 'InternetExposed'   # the catalog's short name (#558 / #559)
        $dup.si_data_model | Should -Be 'ci'
        $dup.si_ci_factor_tokens | Should -Be 'InternetExposed'
        ($rows | Where-Object case -EQ 'provider-token-not-on-ci').RiskFactor_Probability_Detailed | Should -Be ''
        ($rows | Where-Object case -EQ 'ci-factor-added').RiskFactor_Probability_Detailed | Should -Be 'NoOwner'
        ($rows | Where-Object case -EQ 'finding-factor-stays').RiskFactor_Probability_Detailed | Should -Be 'RF_P_ExploitSignals;RF_P_Frequent'
        $w = $rows | Where-Object case -EQ 'weight-from-ci'
        $w.RiskFactor_Weight | Should -Be 150
        $w.cmdbCriticality | Should -Be 'Business Critical'
        $w.cmdbId | Should -Be 'SVC-1'
        ($rows | Where-Object case -EQ 'testing-factor-not-counted').RiskFactor_Probability_Detailed | Should -Be ''
        $none = $rows | Where-Object case -EQ 'no-ci'
        $none.PSObject.Properties['si_data_model'] | Should -BeNullOrEmpty
        $none.RiskFactor_Probability_Detailed | Should -Be 'RF_P_InternetExposed'
    }
    It 'legacy: unchanged -- the CI context on top, the report''s own weighting and CMDB values kept' {
        $rows = Clone $script:FxFindings
        $null = Add-RACiContext -Rows $rows -Index $script:Index -Mode legacy -Catalog $script:Cat
        ($rows | Where-Object case -EQ 'double-count').RiskFactor_Probability_Detailed | Should -Be 'RF_P_InternetExposed;InternetExposureSignal'
        ($rows | Where-Object case -EQ 'provider-token-not-on-ci').RiskFactor_Probability_Detailed | Should -Be 'RF_P_InternetExposed'
        $w = $rows | Where-Object case -EQ 'weight-from-ci'
        $w.RiskFactor_Weight | Should -Be 125
        $w.cmdbCriticality | Should -Be 'High'
        ($rows | Where-Object case -EQ 'double-count').PSObject.Properties['si_data_model'] | Should -BeNullOrEmpty
    }
    It 'the scorer drops an asset token it derived from provider columns when the CI did not set the factor' {
        $global:RA_FactorCatalog = $script:Cat
        try {
            $row = [pscustomobject]@{ SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs'; ConfigurationId = 'CVE'; SecuritySeverity = 'High'
                CriticalityTierLevel = 'Medium - tier 2'; AssetName = 'srv-closed'; MdeDeviceId = 'm-closed'; HasInternetExposureSignal = $true
                RiskFactor_Probability_Detailed = 'RF_P_ExploitSignals'; RiskFactor_Consequence_Detailed = 'RemoteCodeExecutionRisk' }
            $legacy = @(& $script:Score (Add-RACiContext -Rows @($row.PSObject.Copy()) -Index $script:Index -Mode legacy -Catalog $script:Cat))[0]
            $ci = @(& $script:Score (Add-RACiContext -Rows @($row.PSObject.Copy()) -Index $script:Index -Mode ci -Catalog $script:Cat))[0]
            # #559: the asset factor sits on the ASSET side (RiskFactor_Consequence*, its short name and impact); the finding
            # factors (ExploitAvailable, RCE) on the vulnerability side in both models
            $ie = [int](@((Get-Content -LiteralPath (Join-Path $script:SIRoot 'data-model\risk-factors.locked.json') -Raw | ConvertFrom-Json).factors | Where-Object { $_.id -eq 'internet_exposed' })[0].impact)
            $legacy.RiskFactor_Consequence_Detailed | Should -Be 'InternetExposed'
            [int]$legacy.RiskFactor_Consequence | Should -Be $ie
            $ci.RiskFactor_Consequence_Detailed | Should -Be ''
            [int]$ci.RiskFactor_Consequence | Should -Be 0
            $ci.RiskFactor_Probability_Detailed | Should -Be 'ExploitAvailable;RCE'
            $legacy.RiskFactor_Probability_Detailed | Should -Be 'ExploitAvailable;RCE'
            [int]$ci.RiskFactor_Probability | Should -Be ([int]$legacy.RiskFactor_Probability)
        } finally { $global:RA_FactorCatalog = $null }
    }
}

Describe 'M4''s proof: the fixture scored legacy vs ci, every difference explained' {
    BeforeAll {
        $global:RA_FactorCatalog = $script:Cat
        $script:Res = @(Compare-RADataModelScores -Rows (Clone $script:FxFindings) -Index $script:Index -Catalog $script:Cat -Score $script:Score)
        $script:ByCase = @{}
        for ($i = 0; $i -lt $script:FxFindings.Count; $i++) { $script:ByCase[[string]$script:FxFindings[$i].case] = $script:Res[$i] }
    }
    AfterAll { $global:RA_FactorCatalog = $null }
    It 'compares every finding and leaves nothing unexplained' {
        $script:Res.Count | Should -Be $script:FxFindings.Count
        @($script:Res | Where-Object Unexplained).Count | Should -Be 0
    }
    It 'moves exactly the rows the fixture expects to move, each for its reason' {
        foreach ($f in $script:FxFindings) {
            $r = $script:ByCase[[string]$f.case]
            if ($f.expect -eq 'moved') {
                $r.Moved | Should -BeTrue -Because $f.case
                (@($r.Reasons) -join '; ') | Should -Match ([regex]::Escape([string]$f.why)) -Because $f.case
            } else {
                $r.Moved | Should -BeFalse -Because $f.case
            }
        }
    }
    It '#559: the factor a report names twice counts once in BOTH models -- the two scores are equal' {
        $r = $script:ByCase['double-count']
        $r.CiScore | Should -Be $r.LegacyScore
        $r.Moved | Should -BeFalse
    }
    It 'the weight: the CI''s criticality factor 1.5 instead of the report''s 1.25' {
        $r = $script:ByCase['weight-from-ci']
        $r.CiScore | Should -Be $r.LegacyScore
        $r.CiWeighted | Should -BeGreaterThan $r.LegacyWeighted
        (@($r.Reasons) -join ';') | Should -Match 'weight: 125 -> 150'
    }
    It 'writes the comparison as a report' {
        $md = ConvertTo-RAModelCompareMarkdown -Results $script:Res
        $md | Should -Match ('{0} row\(s\) compared; [1-9]\d* moved; 0 unexplained\.' -f $script:FxFindings.Count)
        $md | Should -Match '\| row \| asset \| CI \|'
    }
}
