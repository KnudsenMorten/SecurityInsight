#Requires -Version 5.1
<#
    #690 (3) -- THE FINDING'S TARGET IS PART OF ITS IDENTITY (report certification #688, owner 2026-10-15: "better give me
    too much rows in si than leaving customer in the dark").

    Measured on internal 2026-10-15: Identity_SPN_OwnsResourcePublicAccess_Detailed stored 3 of 20 retrieved rows -- the
    scoring's de-duplication key (RA-RiskScore.ps1, and the same key in RA-SqlStream.ps1 across buckets) had no resource
    column, so every exposed resource of one service principal collapsed into ONE finding.

    What this file pins:
      * distinct targets of one asset stay distinct findings (the identity-on-resource report, an attack path's target);
      * a TRUE duplicate (an exact copy, the same target too) is still kept once -- in the scoring and in the SQL key;
      * a row WITHOUT a target column keeps exactly the key text it had before the change, so no other report changes
        which rows collapse (and the SQL de-duplication hash of every such row is unchanged);
      * the scoring and the SQL writer use the same key (same base columns, same target columns);
      * the Detailed reports whose rows carry a target column are a reviewed list -- a new one is reviewed here.
    Offline; nothing runs a query.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ra = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    function script:Write-Info { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Ok { param($m) }
    function script:Write-Diag { param($m) }
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ra 'RA-ExcelReport.ps1'), [ref]$null, [ref]$null)
    . ([scriptblock]::Create(($ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'New-RiskIndex' }, $true)).Extent.Text))
    foreach ($f in 'RA-RiskIndexOrder.ps1', 'RA-RiskIndexSi.ps1', 'RA-FactorKeys.ps1', 'RA-CiContext.ps1', 'RA-RiskScore.ps1', 'RA-RowShaping.ps1', 'RA-SummaryBucketMerge.ps1',
                   'RA-Findings.ps1', 'RA-ColumnFillGuard.ps1', 'RA-SqlStream.ps1') { . (Join-Path $ra $f) }
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null; $global:RA_FactorCatalog = $null
    $ProgressPreference = 'SilentlyContinue'
    $script:Index = New-RiskIndex -CsvRows @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
    $yaml = Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
    $script:Catalog = ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText($yaml)) -SourceName $yaml

    function script:Score([object[]]$Rows, [string]$Report = 'Identity_SPN_OwnsResourcePublicAccess_Detailed') {
        @(Calculate-RiskScore -Rows @($Rows) -RiskIndex $script:Index -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
            -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -ReportName $Report)
    }
    # one service principal, one role on each of N exposed resources (the shape of the report's rows)
    function script:New-SpRows([int]$N, [string]$Sp = 'ci-sp-1') {
        @(for ($i = 0; $i -lt $N; $i++) {
            [pscustomobject][ordered]@{ SecurityDomain = 'Identity'; Category = ''; Subcategory = ''; ConfigurationName = 'AutomateIT-App'; ConfigurationId = 'app-1111'
                AssetName = 'AutomateIT-App'; AssetId = $Sp; AssetType = 'Service principal'; SecuritySeverity = 'Low'; CriticalityTier = 0; CriticalityTierLevel = 'Critical - tier 0'
                LinkedAzureResourceId = "/subscriptions/s1/resourcegroups/rg1/providers/microsoft.storage/storageaccounts/sa$i"; Impact = "role on sa$i"
                RiskFactor_Probability = 0; RiskFactor_Probability_Detailed = ''; RiskFactor_Consequence_Detailed = '' }
        })
    }
    # the key exactly as it was built before #690 (3): the base columns, lower-cased, '|'-joined
    function script:Get-OldKey($Row) {
        $cols = @('SecurityDomain','Category','Subcategory','ConfigurationName','ConfigurationId','CriticalityTier','SecuritySeverity','cmdbCriticality','cmdbDataSensitivity','AssetName','SI_AssetId','AssetId','AadDeviceId')
        $cn = [string]$Row.ConfigurationName; $cv = [string]$Row.ConfigurationId
        if ([string]::IsNullOrWhiteSpace($cn) -and [string]::IsNullOrWhiteSpace($cv)) { return '' }
        ((@(foreach ($c in $cols) { $p = $Row.PSObject.Properties[$c]; if ($p) { [string]$p.Value } else { '' } })) -join '|').ToLowerInvariant()
    }
}

Describe 'distinct targets stay distinct findings; true duplicates are still kept once' {
    It 'one service principal with a role on 19 exposed resources is 19 findings, not 1 (the 3-of-20 defect)' {
        $rows = New-SpRows -N 19
        (Score -Rows $rows).Count | Should -Be 19
        @($rows | ForEach-Object { Get-RARowDedupKey -Row $_ } | Select-Object -Unique).Count | Should -Be 19 -Because 'the SQL writer keeps a finding once per key across buckets'
    }
    It 'CONTROL: the same rows sent twice (a true duplicate -- an exact copy, the same resource) are kept once' {
        $rows = New-SpRows -N 5
        $copies = @($rows | ForEach-Object { $_.PSObject.Copy() })
        (Score -Rows (@($rows) + @($copies))).Count | Should -Be 5
        foreach ($i in 0..4) { (Get-RARowDedupKey -Row $copies[$i]) | Should -Be (Get-RARowDedupKey -Row $rows[$i]) }
    }
    It 'CONTROL: a mv-expand copy that differs only outside the key (Impact text) is still one finding' {
        $rows = New-SpRows -N 1
        $dup = $rows[0].PSObject.Copy(); $dup.Impact = 'another text'
        (Score -Rows @($rows[0], $dup)).Count | Should -Be 1
    }
    It 'an attack path from one source to two targets with the same NAME but different ids is two findings' {
        $mk = { param($t) [pscustomobject][ordered]@{ SecurityDomain = 'Azure'; Category = 'Attack Paths'; Subcategory = 'x'; ConfigurationName = 'vm1 -> sa'; ConfigurationId = 'vm1->sa'
            AssetName = 'vm1'; AssetId = 'ci-vm1'; SecuritySeverity = 'High'; CriticalityTier = 1; CriticalityTierLevel = 'High - tier 1'; TargetAssetId = $t; TargetNodeId = "node-$t"
            RiskFactor_Probability = 0; RiskFactor_Probability_Detailed = ''; RiskFactor_Consequence_Detailed = '' } }
        $a = & $mk '/subscriptions/s1/resourcegroups/a/providers/microsoft.storage/storageaccounts/sa'
        $b = & $mk '/subscriptions/s2/resourcegroups/b/providers/microsoft.storage/storageaccounts/sa'
        (Score -Rows @($a, $b) -Report 'Attack_Paths_Detailed_Github_to_Azure_Resources').Count | Should -Be 2
        (Score -Rows @($a, $a.PSObject.Copy()) -Report 'Attack_Paths_Detailed_Github_to_Azure_Resources').Count | Should -Be 1
    }
}

Describe 'a row without a target keeps the key it had -- no other report changes' {
    It 'the SQL key text of a row without a target column is byte-identical to the key before the change' {
        $rows = @(
            [pscustomobject]@{ SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs'; ConfigurationName = 'CVE-2026-1'; ConfigurationId = 'CVE-2026-1'; CriticalityTier = 2; SecuritySeverity = 'High'; AssetName = 'h1'; SI_AssetId = 'a1' }
            [pscustomobject]@{ SecurityDomain = 'Identity'; Category = ''; Subcategory = ''; ConfigurationName = 'n'; ConfigurationId = 'id'; AssetName = 'u1'; AssetId = 'ci-u1'; TargetAssetId = ''; LinkedAzureResourceId = $null }
            [pscustomobject]@{ SecurityDomain = 'Azure'; ConfigurationName = ''; ConfigurationId = ''; AssetName = 'x' }
        )
        foreach ($r in $rows) { (Get-RARowDedupKey -Row $r) | Should -BeExactly (Get-OldKey $r) }
    }
    It 'over a mixed set without target columns the scoring keeps exactly the rows the old key kept' {
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($a in 0..9) { foreach ($c in 0..2) { $rows.Add([pscustomobject][ordered]@{ SecurityDomain = 'Endpoint'; Category = 'V'; Subcategory = 'C'; ConfigurationName = "CVE-$c"; ConfigurationId = "CVE-$c"
            SecuritySeverity = 'High'; CriticalityTier = 1; CriticalityTierLevel = 'High - tier 1'; AssetName = "h$($a % 7)"; SI_AssetId = "a$a"; RiskFactor_Probability = 0; RiskFactor_Probability_Detailed = ''; RiskFactor_Consequence_Detailed = '' }) } }
        $rows.Add($rows[4].PSObject.Copy()); $rows.Add($rows[17].PSObject.Copy())
        $expected = @($rows | ForEach-Object { Get-OldKey $_ } | Select-Object -Unique).Count
        (Score -Rows $rows.ToArray() -Report 'Device_Missing_CVEs_Detailed').Count | Should -Be $expected
        $expected | Should -Be 30
    }
    It 'the scoring and the SQL writer key on the same columns' {
        $rs = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1'))
        $m = [regex]::Match($rs, '\$targetKeyCols\s*=\s*@\(([^)]*)\)')
        $m.Success | Should -BeTrue
        $fromScore = @([regex]::Matches($m.Groups[1].Value, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
        $fromScore | Should -Be @($script:RAStreamDedupTargetCols)
        $k = [regex]::Match($rs, "\`$keyCols\s*=\s*@\(([^)]*)\)").Groups[1].Value
        $base = @([regex]::Matches($k, "'([^']+)'|\`$cnInName") | ForEach-Object { if ($_.Value -eq '$cnInName') { '<cfg>' } else { $_.Groups[1].Value } })
        $base | Should -Be @($script:RAStreamDedupCols)
    }
}

Describe 'the Detailed reports whose rows carry a target column are reviewed' {
    It 'exactly these Detailed reports project a target column (their row counts can rise -- each distinct target is a finding)' {
        $found = New-Object System.Collections.Generic.List[string]
        foreach ($r in @($script:Catalog.Reports)) {
            if ([string]$r.ReportName -like '*_Summary*') { continue }
            $q = (@($r.ReportQuery) | ForEach-Object { [string]$_ }) -join "`n"
            $i = $q.LastIndexOf('| project ')
            if ($i -lt 0) { continue }
            if ($q.Substring($i) -match '\b(TargetAssetId|LinkedAzureResourceId)\b') { $found.Add([string]$r.ReportName) }
        }
        @($found | Sort-Object) | Should -Be @(
            'Attack_Paths_Detailed_Credential_Based_Lateral_Movement'
            'Attack_Paths_Detailed_Data_Sensitivity_to_Exposed_Credentials'
            'Attack_Paths_Detailed_Github_to_Azure_Resources'
            'Attack_Paths_Detailed_Identity_Group_Membership_to_Privileged_Resources'
            'Attack_Paths_Detailed_Public_IP_to_VM_with_CVE_Exploitation'
            # #690 (17b): one row per account x machine -- the machine is the target (second review 2026-10-15)
            'Identity_Admin_LogonTo_InternetExposedDevice_Detailed'
            'Identity_Admin_LogonTo_LowTierDevice_Detailed'
            'Identity_Admin_LogonTo_VulnerableDevice_Detailed'
            'Identity_EligibleAdmin_LogonTo_ExploitableDevice_Detailed'
            'Identity_SPN_OwnsResourcePublicAccess_Detailed'
        ) -Because 'a new report with a target column is reviewed here: its distinct targets become distinct findings'
    }
}
