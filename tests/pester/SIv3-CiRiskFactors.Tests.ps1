#Requires -Version 5.1
<#
    THE CATALOG'S RISK FACTORS PER CI, DE-DUPLICATED, WITH THEIR EVIDENCE (#464).

    The CI build (P3, Invoke-SICiRiskFactors) evaluates every catalog asset factor once per CI over its resolved SI fields;
    Add-SICiRiskFactorEvidence (engine/data-model/SI-RiskFactorCatalog.ps1) then records, per factor, WHICH providers and
    fields prove it, and gives Risk Analysis plain columns: si_rf_<id> (the catalog's ciColumn factors) and si_rf_count.

    What these tests keep true:
      * a risk boolean resolved any-true names EVERY provider that said true (si_field_sources.<field>.providers)
      * ONE factor entry however many providers prove it; its evidence lists each provider with the provider fields of its
        mapping and the record; a network range and a computed tier are named as such; no observed_at (it moves every build
        and would make every CI "changed")
      * si_rf_<id> true / false for every ciColumn factor, si_rf_count = the factors that count (#559: a disabled factor is
        not evaluated; an enabled one carries its catalog impact 1..5)
      * SI_CI_CL: the full row carries si_rf_* + si_rf_count and each factor's providers ('by'); a CI without them keeps the
        old contract
      * the KQL helper _SiCiFactors() (marker //__SI_CI_FACTORS__): no marker = the query unchanged; the marker = one row per
        CI with the si_rf_ columns of the catalog; wired after the weighted block; no shipped report uses it yet
      * before / after for InternetExposed + NoMFA through the CI (the CI context): a report flag and the CI factor count
        once; a CI factor the report did not flag adds its impact to the ASSET side (#559)
    Offline; PS 7 (v3 gate).
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuild.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildSql.ps1')
    $script:Model = Get-SIDataModel
    $script:Lists = Merge-SIRiskFactorRanges -Lists (Get-SIDataModelListContext $script:Model) -Setting '10.50.0.0/16'
    $script:Now = [datetime]::SpecifyKind([datetime]'2026-10-10T03:00:00', [DateTimeKind]::Utc)
    function script:New-Ci([hashtable]$Fields, [hashtable]$Sources) {
        $c = [ordered]@{ si_ci_id = 'ci-1'; si_class = 'device'; si_asset_name = 'srv01' }
        foreach ($k in $Fields.Keys) { $c[$k] = $Fields[$k] }
        $src = [ordered]@{}; foreach ($k in $Sources.Keys) { $src[$k] = $Sources[$k] }
        $c['si_field_sources'] = $src
        $c
    }
    function script:Evaluate($Ci) {
        $null = Invoke-SICiRiskFactors -Ci $Ci -Factors $script:Model['risk-factors'] -Checks $script:Model['coverage-checks'] -Context @{ Lists = $script:Lists; Now = $script:Now }
        $Ci
    }
    function script:Factor($Ci, [string]$Id) { @($Ci['si_risk_factors'] | Where-Object { $_.id -eq $Id })[0] }
}

Describe 'the CI build names every provider behind an any-true risk boolean' {
    It 'Resolve-SICiField returns all providers that said true, and the winner' {
        $field = @($script:Model['field-catalog'].fields | Where-Object { $_.name -eq 'si_internet_exposed' })[0]
        $seen = $script:Now.AddHours(-2)
        $c = @(
            [pscustomobject]@{ Record = [pscustomobject]@{ si_internet_exposed = $true; si_source_last_seen = $seen }; Provider = 'mde'; Key = 'mde:1'; State = 'active' }
            [pscustomobject]@{ Record = [pscustomobject]@{ si_internet_exposed = $true; si_source_last_seen = $seen.AddHours(-1) }; Provider = 'eg'; Key = 'eg:1'; State = 'active' }
            [pscustomobject]@{ Record = [pscustomobject]@{ si_internet_exposed = $false; si_source_last_seen = $seen }; Provider = 'azure'; Key = 'az:1'; State = 'active' })
        $r = Resolve-SICiField -Field $field -Candidates $c -Now $script:Now
        $r.Value | Should -BeTrue
        @($r.Providers | Sort-Object) | Should -Be @('eg', 'mde')
        $r.Provider | Should -Be 'mde'
    }
    It 'New-SICiDocument keeps them in si_field_sources (only when more than one)' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuild.ps1'))
        $t | Should -Match "if \(\`$res\.Providers -and @\(\`$res\.Providers\)\.Count -gt 1\) \{ \`$resolvedSources\[\[string\]\`$f\.name\]\['providers'\] = @\(\`$res\.Providers\) \}"
    }
}

Describe 'factors per CI with their evidence' {
    BeforeAll {
        $script:Ci = Evaluate (New-Ci @{ si_internet_exposed = $true; si_ip_addresses = @('10.50.1.2'); si_privilege_tier_permanent = 0 } @{
                si_internet_exposed = [ordered]@{ provider = 'mde'; record = 'mde:dev-1'; observed_at = $script:Now; stale = $false; providers = @('mde', 'eg') }
                si_ip_addresses     = [ordered]@{ provider = 'mde'; record = 'mde:dev-1'; observed_at = $script:Now; stale = $false } })
    }
    It 'one internet_exposed entry, proven by Defender for Endpoint, Exposure Graph and the network range' {
        @($script:Ci['si_risk_factors'] | Where-Object { $_.id -eq 'internet_exposed' }).Count | Should -Be 1
        $e = Factor $script:Ci 'internet_exposed'
        @($e.by) | Should -Contain 'mde'; @($e.by) | Should -Contain 'eg'; @($e.by) | Should -Contain 'network'
        $mde = @($e.evidence | Where-Object { $_.provider -eq 'mde' -and $_.field -eq 'si_internet_exposed' })[0]
        @($mde.providerFields) | Should -Be @('deviceInfo.IsInternetFacing')
        $mde.record | Should -Be 'mde:dev-1'
        $eg = @($e.evidence | Where-Object { $_.provider -eq 'eg' })[0]
        @($eg.providerFields) | Should -Contain 'node.NodeProperties.rawData.hasInternetExposureSignal'
        @($e.evidence | Where-Object { $_.provider -eq 'network' })[0].list | Should -Be 'internet_exposed_ranges'
    }
    It 'a field SecurityInsight computes (standing privileged role) is named as computed' {
        $e = Factor $script:Ci 'permanent_privileged_role'
        $c = @($e.evidence | Where-Object { $_.provider -eq 'computed' })[0]
        $c.field | Should -Be 'si_privilege_tier_permanent'
    }
    It 'no evidence item carries observed_at (the CI''s content stays the same build to build)' {
        foreach ($f in @($script:Ci['si_risk_factors'])) { foreach ($x in @($f.evidence)) { $x.Contains('observed_at') | Should -BeFalse } }
    }
    It 'si_rf_<id> for every ciColumn factor, si_rf_count = the factors that count' {
        $script:Ci['si_rf_internet_exposed'] | Should -BeTrue
        $script:Ci.Contains('si_rf_tier0_or_1') | Should -BeFalse -Because 'tier is never a factor (#527 (5)); si_tier is on the CI already'
        $script:Ci['si_rf_has_secret'] | Should -BeFalse
        $script:Ci['si_rf_no_mfa'] | Should -BeFalse
        foreach ($id in (Get-SIRiskFactorCiColumns -Factors $script:Model['risk-factors'])) { $script:Ci.Contains("si_rf_$id") | Should -BeTrue -Because "si_rf_$id is on every CI" }
        $script:Ci['si_rf_count'] | Should -Be @($script:Ci['si_risk_factors'] | Where-Object { $_.impact -gt 0 }).Count
    }
    It '#559: an enabled factor carries its catalog impact, short name and side; a disabled optional factor is not evaluated' {
        $ci = Evaluate (New-Ci @{ si_has_leaked_credentials = $true } @{ si_has_leaked_credentials = [ordered]@{ provider = 'eg'; record = 'eg:1'; stale = $false } })
        $e = Factor $ci 'leaked_credentials'
        $e.impact | Should -Be 5
        $e.shortName | Should -Be 'LeakedCreds'
        $e.side | Should -Be 'asset'; $e.state | Should -Be 'enabled'; $e.stage | Should -Be 'production'
        $ci['si_rf_count'] | Should -Be 1
        # a copy of the catalog with the optional 'unmanaged' factor switched off: it is not on the CI
        $cat = $script:Model['risk-factors'] | ConvertTo-Json -Depth 30 | ConvertFrom-Json
        @($cat.factors | Where-Object { $_.id -eq 'unmanaged' })[0].state = 'disabled'
        $c2 = New-Ci @{ si_managed_by = 'unmanaged' } @{ si_managed_by = [ordered]@{ provider = 'mde'; record = 'mde:1'; stale = $false } }
        $null = Invoke-SICiRiskFactors -Ci $c2 -Factors $cat -Checks $script:Model['coverage-checks'] -Context @{ Lists = $script:Lists; Now = $script:Now }
        Factor $c2 'unmanaged' | Should -BeNullOrEmpty
        # a built-in factor stays on even when an override says disabled
        @($cat.factors | Where-Object { $_.id -eq 'leaked_credentials' })[0].state = 'disabled'
        $c3 = New-Ci @{ si_has_leaked_credentials = $true } @{ si_has_leaked_credentials = [ordered]@{ provider = 'eg'; record = 'eg:1'; stale = $false } }
        $null = Invoke-SICiRiskFactors -Ci $c3 -Factors $cat -Checks $script:Model['coverage-checks'] -Context @{ Lists = $script:Lists; Now = $script:Now }
        (Factor $c3 'leaked_credentials').impact | Should -Be 5
    }
    It 'no MFA on a user: the provider that won (Entra) with its registration field' {
        $ci = Evaluate (New-Ci @{ si_class = 'identity'; si_identity_type = 'user'; si_mfa_registered = $false } @{ si_mfa_registered = [ordered]@{ provider = 'entra'; record = 'entra:u1'; stale = $false } })
        $e = Factor $ci 'no_mfa'
        @($e.by) | Should -Be @('entra')
        @($e.evidence[0].providerFields) | Should -Be @('registration.isMfaRegistered')
        $ci['si_rf_no_mfa'] | Should -BeTrue
    }
    It 'is wired: Invoke-SICiRiskFactors adds the evidence for every CI (both the loop and the parallel path call it)' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiEnrich.ps1'))
        $t | Should -Match '\$null = Add-SICiRiskFactorEvidence -Ci \$Ci -Factors \$Factors -Lists \$lists'
    }
}

Describe 'SI_CI_CL carries the per-CI factors' {
    It 'the full row has si_rf_* + si_rf_count and each factor''s providers' {
        $ci = Evaluate (New-Ci @{ si_internet_exposed = $true; si_tier = 2 } @{ si_internet_exposed = [ordered]@{ provider = 'mde'; record = 'mde:1'; stale = $false } })
        $ci['si_collection_time'] = $script:Now; $ci['si_last_seen'] = $script:Now
        $row = ConvertTo-SICiPostRow -Ci $ci
        $row.si_rf_internet_exposed | Should -BeTrue
        $row.si_rf_no_mfa | Should -BeFalse
        $row.si_rf_count | Should -Be 1
        $f = @($row.si_risk_factors | Where-Object { $_.id -eq 'internet_exposed' })[0]
        @($f.by) | Should -Be @('mde')
        $f.Contains('evidence') | Should -BeFalse -Because 'the full evidence stays in the database document (sidata.Ci), not the Log Analytics row'
    }
    It 'a CI without them keeps the old column contract' {
        $row = ConvertTo-SICiPostRow -Ci ([ordered]@{ si_ci_id = 'x'; si_class = 'device'; si_risk_factors = @([ordered]@{ id = 'a'; axis = 'probability'; impact = 1; stage = 'production' }); si_collection_time = $script:Now; si_last_seen = $script:Now })
        @($row.PSObject.Properties.Name | Where-Object { $_ -like 'si_rf_*' }) | Should -BeNullOrEmpty
        @(@($row.si_risk_factors)[0].Keys) | Should -Be @('id', 'shortName', 'side', 'axis', 'impact', 'state', 'stage')
    }
}

Describe 'the KQL helper Risk Analysis reports can use' {
    BeforeAll { . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-FactorKeys.ps1') }
    It 'no marker: the query is unchanged' {
        $q = "SI_CI_CL`n| take 1"
        Resolve-RACiFactorsBlock -Query $q | Should -BeExactly $q
    }
    It 'the marker becomes _SiCiFactors() with the catalog''s si_rf_ columns and the provider links' {
        $r = Resolve-RACiFactorsBlock -Query "  //__SI_CI_FACTORS__`nDeviceInfo | take 1"
        $r | Should -Match '(?m)^let _SiCiFactors = \(\) \{'
        $r | Should -Not -Match '//__SI_CI_FACTORS__'
        foreach ($id in (Get-SIRiskFactorCiColumns -Factors $script:Model['risk-factors'])) { $r | Should -Match ("si_rf_$id = tobool\(column_ifexists\('si_rf_$id', bool\(null\)\)\)") }
        foreach ($c in 'si_rf_count', 'si_link_mde', 'si_link_entra', 'si_link_azure', 'si_link_eg') { $r | Should -Match "\b$c = " }
        $r | Should -Match "where tostring\(column_ifexists\('si_row_kind', ''\)\) in \('full', ''\)"
        $r | Should -Match '(?m)^DeviceInfo \| take 1$'
    }
    It 'is wired after the weighted block; no shipped report uses the marker yet' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $t.IndexOf('$Query = Resolve-RACiFactorsBlock -Query $Query') | Should -BeGreaterThan $t.IndexOf('$Query = Resolve-WeightedFactorsBlock')
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')) | Should -Not -Match '//__SI_CI_FACTORS__'
    }
}

Describe 'InternetExposed + NoMFA through the CI: before / after' {
    BeforeAll {
        function script:Write-Info { param($m) }
        function script:Write-Warn2 { param($m) }
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ExcelReport.ps1'), [ref]$null, [ref]$null)
        $fn = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'New-RiskIndex' }, $true)
        . ([scriptblock]::Create($fn.Extent.Text))
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexOrder.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexSi.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-FactorKeys.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiContext.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1')
        $global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null; $global:RA_FactorCatalog = $null
        $rows = @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
        $script:Idx = New-RiskIndex -CsvRows $rows
        $script:ImpIe = [int](@($script:Model['risk-factors'].factors | Where-Object { $_.id -eq 'internet_exposed' })[0].impact)
        $script:ImpMfa = [int](@($script:Model['risk-factors'].factors | Where-Object { $_.id -eq 'no_mfa' })[0].impact)
        function script:Run([hashtable]$Row, [string]$Factors) {
            $ci = [pscustomobject]@{ si_ci_id = 'c'; si_asset_name = 'a1'; si_tier = '2'; si_link_mde = 'dev-1'; si_link_entra = 'u-1'; si_risk_factors = $Factors }
            $r = Add-RACiContext -Rows @([pscustomobject]$Row) -Index (New-RACiIndex -Cis @($ci))   # returns , @(rows): assigned, not wrapped
            $ProgressPreference = 'SilentlyContinue'
            @(Calculate-RiskScore -Rows $r -RiskIndex $script:Idx -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
                -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -ReportName 'T_Detailed')[0]
        }
        $script:Cve = @{ SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs (Missing Updates)'; ConfigurationName = 'x'; ConfigurationId = 'CVE-1'; SecuritySeverity = 'High'
            CriticalityTier = 2; CriticalityTierLevel = 'Medium - tier 2'; AssetName = 'a1'; MdeDeviceId = 'dev-1'; RiskFactor_Consequence_Detailed = '' }
        $script:Idn = @{ SecurityDomain = 'Identity'; Category = 'Identity'; Subcategory = 'MFA'; ConfigurationName = 'x'; ConfigurationId = 'IDENTITY-MFA-001'; SecuritySeverity = 'High'
            CriticalityTier = 2; CriticalityTierLevel = 'Medium - tier 2'; AssetName = 'a1'; EntraObjectId = 'u-1'; RiskFactor_Consequence_Detailed = '' }
    }
    It 'CVE: the report''s Internet-Exposed and the CI''s internet_exposed count once (before = after)' {
        $before = $script:Cve.Clone(); $before['RiskFactor_Probability_Detailed'] = 'Internet-Exposed'
        $a = Run $before '[]'
        $b = Run $before '[{"id":"internet_exposed","axis":"probability","impact":4,"stage":"production"}]'
        # #559: an asset factor counts on the ASSET side (RiskFactor_Consequence), once, with its catalog impact
        [int]$b.RiskFactor_Consequence | Should -Be ([int]$a.RiskFactor_Consequence)
        [int]$a.RiskFactor_Consequence | Should -Be $script:ImpIe
        [double]$b.RiskScoreTotal | Should -Be ([double]$a.RiskScoreTotal)
    }
    It 'CVE: the CI says internet exposed and the report did not -> + its impact on the asset side' {
        $row = $script:Cve.Clone(); $row['RiskFactor_Probability_Detailed'] = ''
        $a = Run $row '[]'
        $b = Run $row '[{"id":"internet_exposed","axis":"probability","impact":4,"stage":"production"}]'
        [int]$b.RiskFactor_Consequence | Should -Be ([int]$a.RiskFactor_Consequence + $script:ImpIe)
        $b.RiskFactor_Consequence_Detailed | Should -Match '\bInternetExposed\b'
    }
    It 'identity: the report''s NoMfaIsRegistered and the CI''s no_mfa count once; the CI alone adds its impact' {
        $r1 = $script:Idn.Clone(); $r1['RiskFactor_Probability_Detailed'] = 'NoMfaIsRegistered'
        [int](Run $r1 '[{"id":"no_mfa","axis":"probability","impact":3,"stage":"production"}]').RiskFactor_Consequence | Should -Be $script:ImpMfa
        $r2 = $script:Idn.Clone(); $r2['RiskFactor_Probability_Detailed'] = ''
        [int](Run $r2 '[{"id":"no_mfa","axis":"probability","impact":3,"stage":"production"}]').RiskFactor_Consequence | Should -Be $script:ImpMfa
    }
}
