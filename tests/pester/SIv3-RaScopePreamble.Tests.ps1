#Requires -Version 5.1
<#
    RISK ANALYSIS KQL IS GENERIC: THE SCOPE PREAMBLE (REQUIREMENTS #541, #550..#553; DESIGN.md "Risk Analysis -- the scope
    preamble"). What these tests keep true:
      * every report carries the scope block first and is listed in data-model/report-scope.locked.json; the template is
        valid; the YAML copy is the canonical shipped one (tools/ra-ci/Update-RaCiBlocks.ps1 regenerates it byte for byte);
      * PER SCOPE PART, every report that declares it CHANGES when the setting / exclusion changes, and a report that does
        not declare it does not (disabled, stale, tier, excluded assets, asset tags, configuration ids, CVEs, address ranges);
      * PER SETTING (the inventory in DESIGN.md), a query changes when the setting changes: SI_DisabledAssets_RiskAnalysis,
        SI_InternetExposedRanges (through the CI's internet_exposed factor), the SI_CVE_* filters, the Exclusions lists,
        the weights, the tier scope, SI_ActiveStaleDays; SI_Exempted_CountInManagement changes the counted view;
      * the factor set is DERIVED from the catalog and the report's subjects -- an identity report never gets a network or
        device factor; a customer factor reaches every report whose subject fits with no query edit; a report naming a
        factor outside its set is refused;
      * the lint: no query re-implements a factor or hard-codes a value a list owns (OS lists, permission names, the
        exclusion tag), no query emits a removed tier factor, no query filters on the enabled state the scope owns;
      * criteria reach Kusto through the typed builders only (escaped), an invalid criterion is refused.
    Offline: reads files and calls pure functions only. PS 5.1 and pwsh 7.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-DataModelTemplates.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-DisabledAssets.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiKql.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiContext.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-FactorKeys.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ScopePreamble.ps1')
    $script:YamlPath = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Reports = @((ConvertFrom-SIYaml -Path $script:YamlPath).Reports)
    $script:ByName = @{}; foreach ($r in $script:Reports) { $script:ByName[[string]$r.ReportName] = $r }
    $script:Dm = Join-Path $script:SIRoot 'data-model'
    $script:Model = Get-SIDataModel -Root $script:Dm
    $script:Template = (Get-SIDataModelTemplate -Name 'report-scope' -Root $script:Dm).Document
    $script:Subjects = Get-RASubjectDefinitions -Template $script:Template
    $script:FieldClasses = @{}; foreach ($f in @($script:Model['field-catalog'].fields)) { $script:FieldClasses[[string]$f.name] = @($f.classes) }
    $script:Factors = @($script:Model['risk-factors'].factors)
    $script:FactorById = @{}; foreach ($f in $script:Factors) { $script:FactorById[[string]$f.id] = $f }
    $script:Lists = @{}; foreach ($l in @($script:Model['lists'].lists)) { $script:Lists[[string]$l.id] = $l }
    $script:Scoped = @(@($script:Template.reports) | ForEach-Object { [string]$_.id })

    function script:QueryOf([string]$Name) { [string](@($script:ByName[$Name].ReportQuery) -join "`n") }
    function script:LabelsOf([string]$Name) { @($script:ByName[$Name].CriticalityTierLevelScope) }
    function script:SpecOf([string]$Name) { Get-RAReportScope -ReportName $Name -Template $script:Template }
    function script:FactorSetOf([string]$Name) { @(Get-RAReportFactorSet -Spec (script:SpecOf $Name) -Factors $script:Factors -Subjects $script:Subjects -FieldClasses $script:FieldClasses) }
    function script:Values([string]$Name, [hashtable]$Change = @{}) {
        $v = Get-RAScopeDefaults -Spec (script:SpecOf $Name) -TierLabels (script:LabelsOf $Name) -FactorSet (script:FactorSetOf $Name)
        $v.Lists = $script:Lists; $v.Factors = $script:FactorById
        $v.FactorNames = Get-RAFactorNameMap -Factors $script:Factors -FactorSet (script:FactorSetOf $Name)
        foreach ($k in $Change.Keys) { $v[$k] = $Change[$k] }
        $v
    }
    # the query the engine runs for one report, from explicit values (Resolve-RAScopePreamble, the engine's one call)
    function script:Run([string]$Name, [hashtable]$Change = @{}) {
        (Resolve-RAScopePreamble -Query (script:QueryOf $Name) -ReportName $Name -TierLabels (script:LabelsOf $Name) -Template $script:Template -Values (script:Values $Name $Change)).Query
    }
    function script:Declaring([string]$Part, $Value = $true) { @(@($script:Template.reports) | Where-Object { $_.scope.$Part -eq $Value } | ForEach-Object { [string]$_.id }) }
    function script:NotDeclaring([string]$Part) { @(@($script:Template.reports) | Where-Object { $_.scope.$Part -ne $true } | ForEach-Object { [string]$_.id }) }
}

Describe 'Every report carries the scope block and is described by data-model/report-scope.locked.json (#541)' {

    It 'the report-scope template is valid (subjects, parts, disabled modes, factor ids)' {
        @(Test-RAReportScopeTemplate -Template $script:Template -Factors $script:Factors) | Should -BeNullOrEmpty
    }

    It 'every report with a CI block is listed, and every listed report exists' {
        foreach ($r in $script:Reports) {
            $q = script:QueryOf ([string]$r.ReportName)
            if ($q -match '__SI_CI_(ASSET|LINK|PEER)_BEGIN__') { $script:Scoped | Should -Contain ([string]$r.ReportName) }
        }
        foreach ($n in $script:Scoped) { $script:ByName.ContainsKey($n) | Should -BeTrue -Because "$n is in report-scope.locked.json" }
    }

    It 'every listed report starts with ONE scope block' {
        foreach ($n in $script:Scoped) {
            $q = script:QueryOf $n
            $q | Should -Match '^\s*//__SI_SCOPE_BEGIN__' -Because $n
            ([regex]::Matches($q, '//__SI_SCOPE_BEGIN__')).Count | Should -Be 1 -Because $n
        }
    }

    It 'the YAML copy is the canonical shipped one (the generator rewrites nothing)' {
        $copy = Join-Path $TestDrive 'q.yaml'
        Copy-Item -LiteralPath $script:YamlPath -Destination $copy
        $null = & (Join-Path $script:SIRoot 'tools\ra-ci\Update-RaCiBlocks.ps1') -YamlPath $copy
        [IO.File]::ReadAllText($copy) | Should -Be ([IO.File]::ReadAllText($script:YamlPath))
    }

    It 'the scope block holds no colon in a comment and no semicolon inside a let' {
        foreach ($n in $script:Scoped) {
            $b = [regex]::Match((script:QueryOf $n), '(?s)//__SI_SCOPE_BEGIN__.*?//__SI_SCOPE_END__').Value
            foreach ($l in ($b -split "`n")) {
                $t = $l.Trim()
                if ($t.StartsWith('//')) { $t.Substring(2) | Should -Not -Match ':' -Because "$n -- $t" }
                elseif ($t.StartsWith('let ')) { ([regex]::Matches(($t -replace '"(?:[^"\\]|\\.)*"', '""'), ';')).Count | Should -Be 1 -Because "$n -- one statement per let" }
            }
        }
    }

    It 'the engine resolves every report through Resolve-RAScopePreamble before the install filter and bucketing' {
        $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $at = $t.IndexOf('Resolve-RAScopePreamble -Query $Query')
        $at | Should -BeGreaterThan 0
        $at | Should -BeLessThan $t.IndexOf('$Query = Add-SIInstallRowsFilter')
        $t | Should -Match "_shared/RA-ScopePreamble\.ps1"
        $t | Should -Match 'Add-RACiContext -Rows @\(\$ResultFiltered\) -FactorSet \$raFs'
    }
}

Describe 'Per scope part: every report that declares it changes with the setting, the others do not' {

    It 'disabled -- "setting" reports follow SI_DisabledAssets_RiskAnalysis; "exclude" / "include" reports never change' {
        foreach ($n in (script:Declaring 'disabled' 'setting')) {
            $off = script:Run $n @{ IncludeDisabled = $false }; $on = script:Run $n @{ IncludeDisabled = $true }
            $off | Should -Match ([regex]::Escape('coalesce(tobool(column_ifexists("si_account_enabled", bool(null))), true)')) -Because "$n keeps enabled assets by default"
            $on | Should -Not -Be $off -Because "$n follows the setting"
        }
        foreach ($mode in 'exclude', 'include') {
            foreach ($n in (script:Declaring 'disabled' $mode)) { (script:Run $n @{ IncludeDisabled = $true }) | Should -Be (script:Run $n @{ IncludeDisabled = $false }) -Because "$n is '$mode' whatever the setting" }
        }
    }

    It 'the two hygiene reports and the disabled-is-the-finding reports are "include"; the seven #533 reports are "setting"' {
        foreach ($b in 'Identity_GuestWithPrivilegedRole', 'Identity_SPN_OwnsResourcePublicAccess', 'Identity_DisabledAccount_ActivePIMAssignment', 'Identity_DisabledPrivilegedUser', 'Identity_DisabledUser_StillInCriticalGroup') {
            foreach ($k in 'Summary', 'Detailed') { (script:SpecOf "${b}_$k").Scope.disabled | Should -Be 'include' -Because "${b}_$k" }
        }
        foreach ($b in 'Identity_SPN_ExpiringCredentials', 'Identity_SPN_Orphan_NoOwner', 'Identity_SPN_OverCredentialed', 'Identity_MultiTenant_HighPermission_SPN', 'Identity_SPN_MailboxImpersonation', 'Identity_BreakGlass_Anomaly', 'Identity_HighRiskFactorComposite4Plus') {
            foreach ($k in 'Summary', 'Detailed') { (script:SpecOf "${b}_$k").Scope.disabled | Should -Be 'setting' -Because "${b}_$k" }
        }
    }

    It 'device reports follow the same setting (an Entra device carries accountEnabled)' {
        foreach ($n in 'Device_Missing_CVEs_Summary', 'Device_Recommendations_Summary', 'Endpoint_ActiveCompromise_Detected_Summary') {
            (script:SpecOf $n).Scope.disabled | Should -Be 'setting'
            (script:Run $n @{ IncludeDisabled = $true }) | Should -Not -Be (script:Run $n @{ IncludeDisabled = $false }) -Because $n
        }
    }

    It 'excluded assets -- every declaring report drops the listed CI ids / names' {
        foreach ($n in (script:Declaring 'excludedAssets')) {
            $q = script:Run $n @{ ExcludedAssets = @('ci-excluded-1') }
            $q | Should -Match 'tolower\(_ciId\) in \(dynamic\(\["ci-excluded-1"\]\)\)' -Because $n
        }
    }

    It 'asset tags -- every declaring report drops the CIs carrying an exclusion tag; the shipped tag is the data-model list' {
        @($script:Lists['excluded_asset_tags'].values) | Should -Contain '--Excluded--SI'
        foreach ($n in (script:Declaring 'assetTags')) {
            (script:Run $n @{ ExcludedAssetTags = @('Lab-Only') }) | Should -Match 'si_tags_ has_any \(dynamic\(\["--excluded--si", "lab-only"\]\)\)' -Because $n
        }
        foreach ($n in (script:NotDeclaring 'assetTags')) {
            (script:Run $n @{ ExcludedAssetTags = @('Lab-Only') }) | Should -Not -Match 'not\(si_tags_ has_any' -Because "$n lists the excluded assets themselves"
        }
    }

    It 'configuration ids -- every declaring report ends with the exclusion filter' {
        foreach ($n in (script:Declaring 'configurationIds')) {
            (script:Run $n @{ ExcludedConfigurationIds = @('scid-2000') }) | Should -Match ([regex]::Escape('| where not(tostring(column_ifexists("ConfigurationId", "")) in (dynamic(["scid-2000"])))') + '\s*$') -Because $n
        }
    }

    It 'the appended configuration-id filter leaves the Summary bucket-merge plan unchanged (it reads only extends after the final summarize)' {
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SummaryBucketMerge.ps1')
        foreach ($n in @($script:Scoped | Where-Object { $_ -like '*_Summary' })) {
            $p0 = Get-RASummaryMergePlan -Query (script:Run $n)
            $p1 = Get-RASummaryMergePlan -Query (script:Run $n @{ ExcludedConfigurationIds = @('scid-2000') })
            ($p1 | ConvertTo-Json -Depth 8 -Compress) | Should -Be ($p0 | ConvertTo-Json -Depth 8 -Compress) -Because $n
        }
    }

    It 'CVEs -- the vulnerability reports name SI_ExcludedCves / SI_CveMinAgeDays / SI_InScopeCve and change with them' {
        $cveReports = script:Declaring 'cves'
        $cveReports | Should -Contain 'Device_Missing_CVEs_Summary'
        foreach ($n in $cveReports) {
            $q0 = script:Run $n; $q1 = script:Run $n @{ ExcludedCves = @('CVE-2024-0001'); CveMinAgeDays = 40 }
            $q1 | Should -Match 'let SI_ExcludedCves = dynamic\(\["CVE-2024-0001"\]\);' -Because $n
            $q1 | Should -Match 'let SI_CveMinAgeDays = 40;' -Because $n
            $q1 | Should -Not -Be $q0
        }
        foreach ($n in 'Device_Missing_CVEs_Summary', 'Device_Missing_CVEs_Detailed') { (script:QueryOf $n) | Should -Match 'FindingName in \(SI_ExcludedCves\)' }
        foreach ($n in 'Attack_Paths_Summary_Public_IP_to_VM_with_CVE_Exploitation', 'Attack_Paths_Detailed_Public_IP_to_VM_with_CVE_Exploitation') {
            (script:QueryOf $n) | Should -Match 'SI_InScopeCve\(NodeName'
            (script:QueryOf $n) | Should -Match 'in \(_ScopedCveNodeIds\)'
        }
        foreach ($n in 'PublicIP_Vulnerabilities_Summary', 'PublicIP_Vulnerabilities_Detailed') { (script:QueryOf $n) | Should -Match ([regex]::Escape('| where SI_InScopeCve(Cve, datetime(null))')) }
        foreach ($n in (script:NotDeclaring 'cves')) { (script:Run $n @{ ExcludedCves = @('CVE-2024-0001') }) | Should -Match 'let SI_ExcludedCves = dynamic\(\[\]\);' -Because $n }
    }

    It 'address ranges -- only the public IP reports drop an excluded range' {
        foreach ($n in (script:Declaring 'ipRanges')) {
            $n | Should -Match '^PublicIP_'
            (script:Run $n @{ ExcludedIpRanges = @('203.0.113.0/24') }) | Should -Match 'ipv4_is_in_any_range\(tostring\(column_ifexists\("si_ip_address", ""\)\), dynamic\(\["203\.0\.113\.0/24"\]\)\)' -Because $n
        }
        foreach ($n in (script:NotDeclaring 'ipRanges')) { (script:Run $n @{ ExcludedIpRanges = @('203.0.113.0/24') }) | Should -Not -Match 'si_ip_address", ""\)\), dynamic' -Because $n }
    }

    It 'tier -- a report with a narrower tier scope cuts the CIs early; the tier part follows CriticalityTierLevelScope' {
        # #690 (19): the three privileged-account pairs (tier 0 / 1 scope) no longer cut on the ASSET tier in the CI block -- the
        # identity's ROLE tier decides in their own query -- so the tier part is shown on a report that declares it, narrowed
        $n = 'Identity_NoMFA_Summary'
        (script:SpecOf $n).Scope.tier | Should -BeTrue
        $narrow = (Resolve-RAScopePreamble -Query (script:QueryOf $n) -ReportName $n -TierLabels @('Critical - tier 0', 'High - tier 1') -Template $script:Template -Values (script:Values $n @{ Tiers = @(0, 1) })).Query
        $narrow | Should -Match 'toint\(column_ifexists\("si_tier", int\(null\)\)\) in \(0, 1\)'
        foreach ($p in 'Identity_PrivilegedUser_StalePassword_Summary', 'Identity_AdminAccount_OnPremSynced_Detailed', 'Identity_AdminAccount_NeverUsed_Summary') {
            (script:SpecOf $p).Scope.tier | Should -BeFalse -Because "$p selects on the role tier in its own query"
            (script:Run $p) | Should -Not -Match 'si_tier", int\(null\)\)\) in \(' -Because "$p must not lose a Tier 0 role holder whose asset tier is 2 or 3"
        }
        $wide = (Resolve-RAScopePreamble -Query (script:QueryOf $n) -ReportName $n -TierLabels @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2') -Template $script:Template -Values (script:Values $n @{ Tiers = @(0, 1, 2) })).Query
        $wide | Should -Match 'in \(0, 1, 2\)'
        foreach ($m in (script:NotDeclaring 'tier')) { (script:Run $m @{ Tiers = @(0) }) | Should -Not -Match 'si_tier", int\(null\)\)\) in \(' -Because "$m derives its tier itself" }
    }

    It 'stale -- every declaring report keeps the CIs a source saw within SI_ActiveStaleDays, and the days change the window' {
        foreach ($n in (script:Declaring 'stale')) {
            $q = script:Run $n @{ StaleDays = 45 }
            $q | Should -Match 'not\(si_stale_\)' -Because $n
            $q | Should -Match 'ago\(45d\)' -Because $n
            # the stale window lives in the CI blocks; a report's own provider look-back (a 30-day sign-in window) is not it
            $ciBlocks = @([regex]::Matches($q, '(?s)//__SI_CI_(LINK|ASSET|PEER)_BEGIN__.*?//__SI_CI_(LINK|ASSET|PEER)_END__') | ForEach-Object { $_.Value })
            $ciBlocks.Count | Should -BeGreaterThan 0 -Because $n
            foreach ($b in $ciBlocks) { $b | Should -Not -Match 'ago\(30d\)' -Because "$n reads the install's stale days" }
        }
    }
}

Describe 'Per setting: the setting changes the query (or the counted view)' {

    It 'SI_DisabledAssets_RiskAnalysis -- through Get-SIDisabledAssetPolicy and Resolve-SIDisabledAssetsRaFilter (the one decision)' {
        $n = 'Identity_SPN_ExpiringCredentials_Summary'
        $off = Get-SIDisabledAssetPolicy -Values @{ SI_DisabledAssets_RiskAnalysis = $false }
        $on = Get-SIDisabledAssetPolicy -Values @{ SI_DisabledAssets_RiskAnalysis = $true }
        $q = script:QueryOf $n
        $r0 = Resolve-RAScopePreamble -Query $q -ReportName $n -TierLabels (script:LabelsOf $n) -Template $script:Template -Values (script:Values $n @{ IncludeDisabled = [bool]$off.Effective.RiskAnalysis }) -Policy $off
        $r1 = Resolve-RAScopePreamble -Query $q -ReportName $n -TierLabels (script:LabelsOf $n) -Template $script:Template -Values (script:Values $n @{ IncludeDisabled = [bool]$on.Effective.RiskAnalysis }) -Policy $on
        $r0.Active.IncludeDisabled | Should -BeFalse; $r1.Active.IncludeDisabled | Should -BeTrue
        $r1.Query | Should -Not -Be $r0.Query
        (Resolve-SIDisabledAssetsRaFilter -Mode setting -Policy $off).Predicate | Should -Match 'si_account_enabled'
        (Resolve-SIDisabledAssetsRaFilter -Mode setting -Policy $on).Predicate | Should -Be 'true'
        (Resolve-SIDisabledAssetsRaFilter -Mode exclude -Policy $on).Include | Should -BeFalse
        (Resolve-SIDisabledAssetsRaFilter -Mode include -Policy $off).Include | Should -BeTrue
    }

    It 'a legacy marked line (a customer query written for #533) is still rewritten from the same decision' {
        $q = "T`n| where AccountEnabled == true //__SI_DISABLED_ASSETS_RA__`n| take 1"
        (Resolve-SIDisabledAssetsRaFilter -Query $q -Include $true).Query | Should -Match ([regex]::Escape('| where 1 == 1 //__SI_DISABLED_ASSETS_RA__'))
        (Resolve-SIDisabledAssetsRaFilter -Query $q -Include $false).Marked | Should -Be 1
    }

    It 'SI_InternetExposedRanges -- reaches the internet_exposed factor the CI carries; the reports read that factor, never ranges' {
        $l0 = Merge-SIRiskFactorRanges -Lists @{ internet_exposed_ranges = $script:Lists['internet_exposed_ranges'] } -Setting $null
        $l1 = Merge-SIRiskFactorRanges -Lists @{ internet_exposed_ranges = $script:Lists['internet_exposed_ranges'] } -Setting '198.51.100.0/24'
        (@(Get-RAValues (Get-SIItemValue $l1['internet_exposed_ranges'] 'values')) -join ',') | Should -Not -Be (@(Get-RAValues (Get-SIItemValue $l0['internet_exposed_ranges'] 'values')) -join ',')
        foreach ($n in $script:Scoped) { (script:QueryOf $n) | Should -Not -Match 'internet_exposed_ranges|SI_InternetExposedRanges' -Because "$n reads internet_exposed from the CI (si_rf_p)" }
    }

    It 'the SI_CVE_* filters -- substituted into every report that carries the CVE block' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'), [ref]$null, [ref]$null)
        foreach ($fn in 'Resolve-CveFilterBlock') { . ([scriptblock]::Create($ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $fn }, $true).Extent.Text)) }
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1')
        $script:_CveFilterBeginMark = '//__CVE_FILTER_BEGIN__'; $script:_CveFilterEndMark = '//__CVE_FILTER_END__'
        function script:Write-Info { param($m) }
        $withBlock = @($script:Scoped | Where-Object { (script:QueryOf $_) -match '//__CVE_FILTER_BEGIN__' })
        $withBlock | Should -Contain 'Device_Missing_CVEs_Summary'
        $withBlock | Should -Contain 'Attack_Paths_Summary_Public_IP_to_VM_with_CVE_Exploitation'
        try {
            foreach ($n in $withBlock) {
                $global:SI_CVE_MinSeverity = $null; $global:SI_CVE_MinCvssScore = $null; $global:SI_CVE_RequireExploit = $false; $global:SI_CVE_MaxPublishedAgeDays = $null
                $q0 = Resolve-CveFilterBlock -Query (script:QueryOf $n) -ReportName $n
                $global:SI_CVE_MinSeverity = 'High'; $global:SI_CVE_MinCvssScore = 7.5; $global:SI_CVE_RequireExploit = $true; $global:SI_CVE_MaxPublishedAgeDays = 365
                $q1 = Resolve-CveFilterBlock -Query (script:QueryOf $n) -ReportName $n
                $q1 | Should -Not -Be $q0 -Because $n
                $q1 | Should -Match 'cvssScore\) >= 7\.5' -Because $n
            }
        } finally { $global:SI_CVE_MinSeverity = $null; $global:SI_CVE_MinCvssScore = $null; $global:SI_CVE_RequireExploit = $null; $global:SI_CVE_MaxPublishedAgeDays = $null }
    }

    It 'the Exclusions page -- the ONE reader (Get-RAScopeInputs) takes the lists and the minimum age from the exclusion documents' {
        function script:Get-ExcludedListForReport { param($ReportName, $PropertyNames, $Token) switch ($PropertyNames[0]) { 'ExcludedAssets' { @('srv-1') } 'ExcludedAssetTags' { @('Lab') } 'ExcludedConfigurationIds' { @('scid-1') } 'ExcludedCves' { @('CVE-2020-1111') } 'ExcludedIpRanges' { @('10.0.0.0/8', 'not-a-range') } default { @() } } }
        function script:Get-ScalarValueForReport { param($ReportName, $PropertyNames, $Default) 30 }
        $n = 'Device_Missing_CVEs_Summary'
        $v = Get-RAScopeInputs -ReportName $n -Spec (script:SpecOf $n) -TierLabels (script:LabelsOf $n) -Policy (Get-SIDisabledAssetPolicy -Values @{})
        @($v.ExcludedAssets) | Should -Be @('srv-1'); @($v.ExcludedAssetTags) | Should -Be @('Lab'); @($v.ExcludedConfigurationIds) | Should -Be @('scid-1')
        @($v.ExcludedCves) | Should -Be @('CVE-2020-1111'); @($v.ExcludedIpRanges) | Should -Be @('10.0.0.0/8') -Because 'a value that is not a range never reaches Kusto'
        $v.CveMinAgeDays | Should -Be 30
        @($v.FactorSet) | Should -Contain 'exploit_available'
    }

    It 'the weights -- every report carries the weighted-factor block the engine substitutes' {
        foreach ($n in $script:Scoped) { (script:QueryOf $n) | Should -Match '//__WEIGHTED_FACTORS_BEGIN__' -Because $n }
    }

    It 'SI_Exempted_CountInManagement -- decides whether exempted rows are counted (the view, not the query)' {
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-Exemptions.ps1')
        $rows = @([pscustomobject]@{ A = 1; SI_Exempted = $true }, [pscustomobject]@{ A = 2 })
        $a = Select-RAReportRows -Rows $rows; $b = Select-RAReportRows -Rows $rows -IncludeExempted
        @($b.Rows).Count | Should -BeGreaterOrEqual @($a.Rows).Count
    }
}

Describe 'The factor set is derived from the catalog and the report''s subjects (#541 (6))' {

    It 'every listed report declares at least one subject' {
        foreach ($r in @($script:Template.reports)) { @($r.subjects).Count | Should -BeGreaterThan 0 -Because $r.id }
    }

    It 'an identity report never gets a network or device factor; a device report never gets an identity factor' {
        $id = script:FactorSetOf 'Identity_NoMFA_Summary'
        foreach ($x in 'internet_exposed', 'unsupported_os', 'antivirus_disabled', 'high_risk_port_open', 'not_onboarded') { $id | Should -Not -Contain $x }
        $id | Should -Contain 'no_mfa'
        $dev = script:FactorSetOf 'Device_Missing_CVEs_Summary'
        foreach ($x in 'no_mfa', 'stale_sign_in', 'old_account', 'has_secret') { $dev | Should -Not -Contain $x }
        # CVSS9Plus (high_cvss_public_ip) applies to every vulnerability finding, on any asset (owner-approved widening)
        foreach ($x in 'unsupported_os', 'exploit_available', 'remote_code_execution', 'high_cvss_public_ip') { $dev | Should -Contain $x }
        (script:FactorSetOf 'Identity_SPN_ExpiringCredentials_Summary') | Should -Contain 'has_secret'
        (script:FactorSetOf 'PublicIP_Vulnerabilities_Summary') | Should -Contain 'high_cvss_public_ip'
    }

    It 'a customer factor added to the catalog reaches every report whose subject fits -- with no query edit' {
        $own = [pscustomobject]@{ id = 'customer_sp_flag'; shortName = 'CustomerSpFlag'; name = 'Customer SP flag'; appliesTo = 'asset'; group = 'Apps'; class = 'optional'; axis = 'probability'; impact = 1; state = 'enabled'; evaluatedBy = 'catalog'
            providers = [pscustomobject]@{ entra = @([pscustomobject]@{ siField = 'si_publisher_verified'; recordTypes = @('service_principal') }) }
            when = [pscustomobject]@{ all = @([pscustomobject]@{ field = 'si_publisher_verified'; op = 'is_false' }) } }
        $all = @($script:Factors) + $own
        foreach ($n in $script:Scoped) {
            $set = @(Get-RAReportFactorSet -Spec (script:SpecOf $n) -Factors $all -Subjects $script:Subjects -FieldClasses $script:FieldClasses)
            $fits = @((script:SpecOf $n).Subjects | Where-Object { $_ -in 'service-principal', 'managed-identity' }).Count -gt 0
            if ($fits) { $set | Should -Contain 'customer_sp_flag' -Because $n } else { $set | Should -Not -Contain 'customer_sp_flag' -Because $n }
        }
        # and the CI block feeds it: the factor set reaches si_rf_p / si_rf_c
        $n = 'Identity_SPN_ExpiringCredentials_Summary'
        $v = script:Values $n @{ FactorSet = @(Get-RAReportFactorSet -Spec (script:SpecOf $n) -Factors $all -Subjects $script:Subjects -FieldClasses $script:FieldClasses) }
        (Resolve-RAScopePreamble -Query (script:QueryOf $n) -ReportName $n -Template $script:Template -Values $v).Query | Should -Match 'set_intersect\(si_rf_p, dynamic\(\[[^\]]*"customer_sp_flag"'
    }

    It 'an explicit include / exclude is an exception on top of the derived set' {
        $spec = @{ Report = 'x'; Subjects = @('device'); Scope = @{}; Include = @('no_mfa'); Exclude = @('unsupported_os'); Known = $true }
        $set = @(Get-RAReportFactorSet -Spec $spec -Factors $script:Factors -Subjects $script:Subjects -FieldClasses $script:FieldClasses)
        $set | Should -Contain 'no_mfa'; $set | Should -Not -Contain 'unsupported_os'
    }

    It 'a report that names a factor outside its set is refused (lint)' {
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($n in $script:Scoped) {
            $set = @(script:FactorSetOf $n)
            foreach ($m in [regex]::Matches((script:QueryOf $n), 'set_has_element\(si_rf_[pc], "([a-z0-9_]+)"\)')) { if ($set -notcontains $m.Groups[1].Value) { $bad.Add(('{0}: {1}' -f $n, $m.Groups[1].Value)) } }
        }
        @($bad) | Should -BeNullOrEmpty
    }

    It 'a report consumes the fed factor set generically (RF_P_CiFactors) instead of naming factors one by one' {
        $generic = 0
        foreach ($n in $script:Scoped) {
            $q = script:QueryOf $n
            # no report names a CI factor as a flag of its own -- the subject's, a joined device's or a path end's alike
            $q | Should -Not -Match 'iff\(set_has_element\((si_rf_[pc]|Source_si_rf_p), "[a-z0-9_]+"\), [01], [01]\)' -Because "$n reads the fed set"
            if ($q -match '\| extend RF_P_CiFactors = coalesce\(si_rf_p, dynamic\(\[\]\)\)') {
                $generic++
                $q | Should -Match 'array_length\(RF_P_CiFactors\)' -Because "$n counts the fed set"
            }
        }
        $generic | Should -BeGreaterThan 65
    }

    It 'a joined object''s factors are its own fed set too: the device an admin logs on to, an attack path''s end and source' {
        foreach ($n in @($script:Scoped | Where-Object { $_ -match '^Identity_Admin_LogonTo_(VulnerableDevice|InternetExposedDevice|LowTierDevice)_' })) {
            $q = script:QueryOf $n
            $q | Should -Match 'DeviceFactorIds = set_difference\(coalesce\((?:si|peer)_rf_p, dynamic\(\[\]\)\), dynamic\(\[[^\]]*\]\)\), DeviceFactorNames = set_difference\(coalesce\((?:si_rf_names_|peer_rf_names)' -Because $n
            $q | Should -Match 'array_length\(DeviceFactorIds\)' -Because "$n counts the device's set"
            $q | Should -Match 'RiskFactorIds = strcat_array\(DeviceFactorIds, ";"\)' -Because $n
            if ($q -match 'where set_has_element\((?:si|peer)_rf_p, "internet_exposed"\)') { $q | Should -Match ([regex]::Escape('pack_array(tostring(SI_FactorNames["internet_exposed"]))')) -Because "$n leaves its question out of the list, by the catalog name it is fed" }
        }
        foreach ($n in @($script:Scoped | Where-Object { $_ -match '^Attack_Paths_' -and $_ -notmatch 'Device_with_high_severity' })) {
            $q = script:QueryOf $n
            $q | Should -Match ([regex]::Escape('| extend TargetFactorIds = coalesce(si_rf_p, dynamic([])), TargetFactorNames = coalesce(si_rf_names_, dynamic([]))')) -Because $n
            $q | Should -Match ([regex]::Escape('| extend _tgtRf = array_concat(TargetRiskFactorSet, TargetFactorNames)')) -Because $n
            if ($q -match 'Source_si_rf_p') { $q | Should -Match ([regex]::Escape('| extend _srcRf = array_concat(SourceRiskFactorSet, _srcNames)')) -Because $n }
        }
    }

    It 'the CI context adds only the report''s factors to a row' {
        $ci = [pscustomobject]@{ si_ci_id = 'ci-1'; si_asset_name = 'a'; si_tier = 2; si_risk_factors = @([pscustomobject]@{ id = 'no_mfa'; axis = 'probability'; impact = 1; stage = 'production' }, [pscustomobject]@{ id = 'internet_exposed'; axis = 'probability'; impact = 1; stage = 'production' }) }
        $idx = New-RACiIndex -Cis @($ci)
        $row = [pscustomobject]@{ si_ci_id = 'ci-1'; RiskFactor_Probability_Detailed = '' }
        $null = Add-RACiContext -Rows @($row) -Index $idx -Mode legacy -FactorSet @('no_mfa') -Catalog (New-RAFactorCatalog -Factors $script:Factors)
        # the row shows the catalog's SHORT names (#558 / #559); the ids stay in RiskFactorIds
        $row.RiskFactor_Probability_Detailed | Should -Match ([regex]::Escape([string]$script:FactorById['no_mfa'].shortName))
        $row.RiskFactor_Probability_Detailed | Should -Not -Match ([regex]::Escape([string]$script:FactorById['internet_exposed'].shortName))
        $row.RiskFactor_Probability_Detailed | Should -Not -Match 'internet_exposed'
    }
}

Describe 'Reports show the catalog''s SHORT names (#558 / #559); the ids stay in RiskFactorIds' {

    It 'the scope block and the CI blocks are fed the name map of the report''s factor set, from the catalog' {
        foreach ($n in $script:Scoped) {
            $q = script:QueryOf $n
            $q | Should -Match 'let SI_FactorNames = dynamic\(\{' -Because $n
            foreach ($id in (script:FactorSetOf $n)) {
                $name = [string]$script:FactorById[$id].shortName
                if ($name -and $id -ne 'report_scoped') { $q | Should -Match ([regex]::Escape('"' + $id + '": ' + (ConvertTo-RAKqlString $name))) -Because "$n feeds the short name of $id" }
            }
            if ($q -match '__SI_CI_(ASSET|LINK|PEER)_BEGIN__') { $q | Should -Match 'si_rf_names_' -Because "$n's CI block carries the names" }
        }
    }

    It 'every report that lists the fed set lists the NAMES and carries the ids in RiskFactorIds' {
        foreach ($n in $script:Scoped) {
            $q = script:QueryOf $n
            if ($q -notmatch '\| extend RF_P_CiFactors = ') { continue }
            $q | Should -Match ([regex]::Escape('RF_P_CiFactorNames = coalesce(si_rf_names_, dynamic([])), RiskFactorIds = strcat_array(coalesce(si_rf_p, dynamic([])), ";")')) -Because $n
            foreach ($m in [regex]::Matches($q, '(?s)\| extend (Source_)?RiskFactor_Probability_Detailed\s*=.*?(?=\n\s*\|)')) { $m.Value | Should -Not -Match '\bRF_P_CiFactors\b' -Because "$n shows names, not ids" }
            @($script:ByName[$n].OutputPropertyOrder) | Should -Contain 'RiskFactorIds' -Because "$n publishes the ids for machines and exports"
            if ($n -like '*_Summary') { $q | Should -Match 'arg_max\(RiskFactor_Probability, RiskFactor_Probability_Detailed, RiskFactorIds\)|RiskFactorIds = strcat_array\(array_sort_asc\(make_set_if\(RiskFactorIds' -Because "$n keeps the ids of the row it shows" }
        }
    }

    It 'a factor the customer renames in the catalog reaches every report that fits it, with no query edit' {
        $n = 'Identity_SPN_ExpiringCredentials_Summary'
        $names = Get-RAFactorNameMap -Factors $script:Factors -FactorSet (script:FactorSetOf $n)
        $names['has_secret'] = 'Uses a client secret (ours)'
        $q = script:Run $n @{ FactorNames = $names }
        $q | Should -Match ([regex]::Escape('"has_secret": "Uses a client secret (ours)"'))
        ([regex]::Matches($q, [regex]::Escape('Uses a client secret (ours)'))).Count | Should -BeGreaterOrEqual 2 -Because 'the scope block and the CI block'
    }

    It 'no query hard-codes a catalog description (names come only from the name map)' {
        $bad = New-Object System.Collections.Generic.List[string]
        $names = @($script:Factors | Where-Object { $_.name -and [string]$_.id -ne 'report_scoped' } | ForEach-Object { [string]$_.name })
        foreach ($n in $script:Scoped) {
            $q = [regex]::Replace((script:QueryOf $n), '(?s)//__SI_SCOPE_BEGIN__.*?//__SI_SCOPE_END__', '')
            $q = [regex]::Replace($q, '(?m)^[ \t]*\| extend _ciRfNames = [^\r\n]*$', '')
            foreach ($nm in $names) { if ($q.Contains('"' + $nm + '"')) { $bad.Add("$n hard-codes ""$nm""") } }
        }
        @($bad) | Should -BeNullOrEmpty
    }

    It 'a short name and a description are tokens of their factor: the score counts "ClientSecret" and has_secret once' {
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-CiContext.ps1')
        $map = New-RAFactorAliasMap -Catalog ([pscustomobject]@{ factors = $script:Factors })
        ConvertTo-RAFactorKey -Token 'ClientSecret' -Map $map | Should -Be (ConvertTo-RAFactorKey -Token 'has_secret' -Map $map)
        ConvertTo-RAFactorKey -Token ([string]$script:FactorById['has_secret'].name) -Map $map | Should -Be (ConvertTo-RAFactorKey -Token 'has_secret' -Map $map)
        ConvertTo-RAFactorKey -Token 'NoOwner' -Map $map | Should -Be (ConvertTo-RAFactorKey -Token 'RF_P_NoOwner' -Map $map)
        $cat = New-RAFactorCatalog -Factors $script:Factors
        $cat.Display['no_owner'] | Should -Be 'NoOwner'
    }
}

Describe 'The lint: no query re-implements a factor or hard-codes what a list, a setting or the scope owns' {

    It 'no query emits a removed tier factor (tier counts through the multiplier and the risk index only)' {
        $ret = Get-RARetiredTierFactors
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($r in $script:Reports) {
            $q = script:QueryOf ([string]$r.ReportName)
            foreach ($id in $ret.Ids) { if ($q -match ('set_has_element\(si_rf_[pc], "' + [regex]::Escape($id) + '"\)') -or $q -match ('dynamic\(\["(?:[^"]*", ")*' + [regex]::Escape($id) + '"')) { $bad.Add("$($r.ReportName): $id") } }
            foreach ($t in $ret.Tokens) { if ($q -match ('\b' + [regex]::Escape($t) + '\b')) { $bad.Add("$($r.ReportName): $t") } }
        }
        @($bad) | Should -BeNullOrEmpty
    }

    It 'has_secret is its own factor; old_account / stale_sign_in never reach a device report' {
        foreach ($n in $script:Scoped) {
            (script:QueryOf $n) | Should -Not -Match 'RF_P_HasSecret\s*=\s*iff\(set_has_element\(si_rf_p, "expiring_credentials"\)' -Because $n
            if ((script:SpecOf $n).Subjects -notcontains 'identity-user' -and (script:SpecOf $n).Subjects -notcontains 'service-principal') {
                (script:FactorSetOf $n) | Should -Not -Contain 'old_account' -Because $n
                (script:FactorSetOf $n) | Should -Not -Contain 'stale_sign_in' -Because $n
            }
        }
    }

    It 'no query hard-codes a value a data-model values list owns, or the shipped exclusion tag' {
        $owned = New-Object System.Collections.Generic.List[string]
        foreach ($l in @($script:Model['lists'].lists)) { if ([string]$l.type -eq 'values') { foreach ($v in @($l.values)) { if ($v -is [string] -and $v.Length -ge 6) { $owned.Add($v) } } } }
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($n in $script:Scoped) {
            $q = [regex]::Replace((script:QueryOf $n), '(?s)//__SI_SCOPE_BEGIN__.*?//__SI_SCOPE_END__', '')
            # the CI blocks are engine-generated too (Resolve-RACiBlocks regenerates them byte for byte -- SIv3-RaReadsCi):
            # their factor-stage filter ("production" = the factor lifecycle stage) is not the service-environment list
            $q = [regex]::Replace($q, '(?s)//__SI_CI_(LINK|ASSET|PEER)_BEGIN__.*?//__SI_CI_(LINK|ASSET|PEER)_END__', '')
            $q = ($q -split "`n" | Where-Object { $_.Trim() -notmatch '^//' }) -join "`n"
            # reviewed exception (#690 (5)): the owner side of si_owners (`of` = service principal / application / both, set by the
            # collection) is not the tag-key list that happens to own "application" -- that one expression is left out
            $q = $q.Replace('_ow.of) == "application"', '_ow.of) == "<owner side>"').Replace('_ow["of"]) == "application"', '_ow["of"]) == "<owner side>"')
            foreach ($v in $owned) { if ($q.Contains('"' + $v + '"')) { $bad.Add("$n hard-codes ""$v""") } }
        }
        @($bad) | Should -BeNullOrEmpty
    }

    It 'customer text (ReportPurpose, Impact, MoreDetails) carries no internal numbers' {
        foreach ($r in $script:Reports) {
            [string]$r.ReportPurpose | Should -Not -Match '#\d{2,4}|REQUIREMENTS|v2\.2\.\d+' -Because "$($r.ReportName)'s purpose is customer text"
            $q = script:QueryOf ([string]$r.ReportName)
            foreach ($m in [regex]::Matches($q, '(?m)\b(MoreDetails|Impact)\s*=\s*[^\r\n]*')) { $m.Value | Should -Not -Match '"[^"]*(#\d{2,4}|REQUIREMENTS)[^"]*"' -Because $r.ReportName }
        }
    }

    It 'no static unsupported-OS list: the attack paths use the catalog''s unsupported_os criteria (SI_InList_unsupported_os)' {
        foreach ($r in $script:Reports) {
            $q = script:QueryOf ([string]$r.ReportName)
            $q | Should -Not -Match 'LegacyWindowsOSPlatforms|LegacyMacOSMajorVersions|LegacyLinuxMatchers|IsLegacyWindows' -Because $r.ReportName
            $q | Should -Not -Match '"WindowsServer2008|"Windows7"|"CentOS 7"' -Because $r.ReportName
            if ($q -match 'LegacyEndOfSupport = iff\(') {
                $q | Should -Match 'SI_InList_unsupported_os\(' -Because $r.ReportName
                $q | Should -Match 'let SI_InList_unsupported_os = \(' -Because "$($r.ReportName) gets the compiled criteria in its scope block"
            }
        }
    }

    It 'no query filters on the enabled state or staleness itself unless the disabled state IS its question' {
        foreach ($n in $script:Scoped) {
            $q = script:QueryOf $n
            $q | Should -Not -Match '\| where si_stale_ == false' -Because $n
            if ((script:SpecOf $n).Scope.disabled -ne 'include') { $q | Should -Not -Match 'si_account_enabled == (true|false)' -Because $n }
        }
    }

    It 'every link join keeps the CIs in scope, and no tier comes from Exposure Graph criticality' {
        foreach ($n in $script:Scoped) {
            $q = script:QueryOf $n
            foreach ($m in [regex]::Matches($q, '(?m)^[ \t]*\| join kind=leftouter \(_ciLink\) on [^\r\n]*\r?\n([^\r\n]*)')) { $m.Groups[1].Value.Trim() | Should -Be '| where coalesce(si_in_scope_, true)' -Because $n }
            $q | Should -Not -Match 'CriticalityTier = toint\(coalesce\(EgCriticalityLevel' -Because $n
        }
    }
}

Describe 'Criteria reach Kusto through the typed builders only (#541 (7))' {

    It 'strings are escaped, control characters refused, numbers invariant' {
        ConvertTo-RAKqlString 'a"b\c' | Should -Be '"a\"b\\c"'
        { ConvertTo-RAKqlString "a`nb" } | Should -Throw
        ConvertTo-RAKqlNumber '7.5' | Should -Be '7.5'
        { ConvertTo-RAKqlNumber '7,5;drop' } | Should -Throw
        ConvertTo-RAKqlDynamic -Values @('x"y', 'X"Y') -Lower | Should -Be 'dynamic(["x\"y"])'
    }

    It 'a list entry reaches the compiled function escaped; a pattern becomes an RE2-safe verbatim regex' {
        $l = [pscustomobject]@{ id = 'unsupported_os'; type = 'conditions'; entries = @([pscustomobject]@{ name = 'x'; when = [pscustomobject]@{ all = @([pscustomobject]@{ field = 'si_os_name'; op = 'eq'; value = 'Win"dows\7' }) } }, [pscustomobject]@{ name = 'y'; when = [pscustomobject]@{ all = @([pscustomobject]@{ field = 'si_os_name'; op = 'matches'; value = '(?i)^CentOS\ 7(\b|$)' }) } }) }
        $k = Get-RAListKqlFunction -List $l -Lists @{ unsupported_os = $l }
        $k | Should -Match ([regex]::Escape('=~ "Win\"dows\\7"'))
        $k | Should -Match ([regex]::Escape('matches regex @"(?i)^CentOS 7(\b|$)"'))
        $k | Should -Match '^let SI_InList_unsupported_os = \(si_os_name:string\) \{'
    }

    It 'the shipped unsupported_os factor compiles and validates (criteria + Kusto shape)' {
        $r = Test-SIRiskFactorCriteriaKql -Factor $script:FactorById['unsupported_os'] -Lists $script:Lists -NoRun
        $r.Ok | Should -BeTrue
        $r.Kql | Should -Match 'print si_os_name = "", si_os_platform = "", si_os_version = "" \| where SI_Factor_unsupported_os\('
        foreach ($id in 'stale_sign_in', 'old_account', 'old_password', 'high_cvss_public_ip') { (Test-SIRiskFactorCriteriaKql -Factor $script:FactorById[$id] -Lists $script:Lists -NoRun).Ok | Should -BeTrue -Because $id }
    }

    It 'an invalid criterion is refused before it can make a report fail' {
        Test-RAKqlCondition -Criterion ([pscustomobject]@{ field = 'si_os_name'; op = 'matches'; value = '(?<=x)y' }) | Should -Match 'look-ahead'
        Test-RAKqlCondition -Criterion ([pscustomobject]@{ field = 'si_os_name'; op = 'matches'; value = 'a"b' }) | Should -Match 'double quote'
        Test-RAKqlCondition -Criterion ([pscustomobject]@{ field = 'si_last_sign_in'; op = 'older_than_days'; value = 'abc' }) | Should -Match 'number of days'
        Test-RAKqlCondition -Criterion ([pscustomobject]@{ field = 'si_os_name; drop'; op = 'eq'; value = 'x' }) | Should -Match 'not a field name'
        Test-RAKqlCondition -Criterion ([pscustomobject]@{ field = 'si_os_name'; op = 'exec'; value = 'x' }) | Should -Match 'not an operation'
        Test-RAKqlCondition -Criterion ([pscustomobject]@{ field = 'si_ip_address'; op = 'in_ranges'; value = @('10.0.0.0/8', 'x') }) | Should -Match 'not an IPv4'
        $badThreshold = $script:FactorById['stale_sign_in'] | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        # unknown is never a finding (owner 2026-10-10): the sign-in condition is the threshold alone (no "or empty" branch)
        @($badThreshold.when.all | Where-Object { $_.field -eq 'si_last_sign_in' })[0].value = 99999   # by field: the factor also requires an enabled account (#559)
        (Test-SIRiskFactorCriteriaKql -Factor $badThreshold -Lists $script:Lists -NoRun).Ok | Should -BeFalse
    }

    It 'a criterion a customer changes reaches the query: the factor function follows the threshold' {
        $f = $script:FactorById['high_cvss_public_ip'] | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $f.when.all[0].value = 7
        (Get-RAFactorKqlFunction -Factor $f -Lists $script:Lists) | Should -Match '>= 7\)'
        $n = 'PublicIP_Vulnerabilities_Summary'
        $byId = @{}; foreach ($k in $script:FactorById.Keys) { $byId[$k] = $script:FactorById[$k] }; $byId['high_cvss_public_ip'] = $f
        (Resolve-RAScopePreamble -Query (script:QueryOf $n) -ReportName $n -Template $script:Template -Values (script:Values $n @{ Factors = $byId })).Query | Should -Match 'let SI_Factor_high_cvss_public_ip = \(si_cvss:string\) \{ \(todouble\([^)]*\)[^}]*>= 7\) \};'
    }

    It 'a customer list entry reaches the query: the unsupported OS criteria follow the list' {
        $l = $script:Lists['unsupported_os'] | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $l.entries = @($l.entries) + [pscustomobject]@{ name = 'Customer OS'; when = [pscustomobject]@{ all = @([pscustomobject]@{ field = 'si_os_name'; op = 'matches'; value = '(?i)^LegacyBox' }) } }
        $lists = @{}; foreach ($k in $script:Lists.Keys) { $lists[$k] = $script:Lists[$k] }; $lists['unsupported_os'] = $l
        $n = 'Attack_Paths_Summary_Public_IP_to_VM_with_CVE_Exploitation'
        (Resolve-RAScopePreamble -Query (script:QueryOf $n) -ReportName $n -Template $script:Template -Values (script:Values $n @{ Lists = $lists })).Query | Should -Match ([regex]::Escape('@"(?i)^LegacyBox"'))
    }
}
