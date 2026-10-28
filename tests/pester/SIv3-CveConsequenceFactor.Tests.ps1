#Requires -Version 5.1
<#
    THE CVE REPORTS' REMOTE-CODE-EXECUTION CONSEQUENCE FACTOR REACHES THE SCORE (#469).

    The scoring contract (engine/risk-analysis/_shared/RA-RiskScore.ps1, #559 risk factor model v2): every catalog factor
    counts its impact (1..5) ONCE on its side -- an asset factor (RestrictedData, Production) on the asset side
    (RiskFactor_Consequence), a finding factor (RCE) on the vulnerability side (RiskFactor_Probability) -- whatever column
    the report put its token in; a numeric RiskFactor_* a report sets is scaffolding the engine overrides. Device_Missing_CVEs_Summary / _Detailed computed RF_C_RemoteCodeExec and its token
    "RemoteCodeExecutionRisk" -- and then never projected RiskFactor_Consequence_Detailed, so the token never reached the
    engine and the factor was silently dropped.

    What these tests keep true:
      * every CVE report (a report that reads the per-CVE exploit signals) computes the token, carries it through its
        summarize and projects RiskFactor_Consequence_Detailed; none hard-sets RiskFactor_Consequence = 0
      * the engine counts the token: an RCE CVE scores the RCE factor's impact above the same CVE without one (vulnerability side)
      * the asset baseline (data sensitivity; no tier, no CMDB criticality -- #527 (5)) is ADDED to a report's tokens, never
        replaced by them -- the token used to switch the baseline off, so an exploitable CVE scored LOWER than a
        non-exploitable one
      * one factor is counted once: a baseline token is not added again when the CI context already put the same catalog
        factor on the row (restricted_data == RestrictedDataAccess)
    Offline; PS 5.1 and 7.
#>

BeforeDiscovery {
    $root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $y = [IO.File]::ReadAllText((Join-Path $root 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    $script:CveReports = @([regex]::Matches($y, '(?s)    - ReportName: (\S+)\r?\n(.*?)(?=\r?\n    - ReportName: |\z)') |
        Where-Object { $_.Groups[2].Value -match 'FindingHasExploit' } | ForEach-Object { @{ Name = $_.Groups[1].Value } })
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Yaml = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'))
    function script:Get-ReportBlock([string]$Name) {
        [regex]::Match($script:Yaml, '(?s)- ReportName: ' + [regex]::Escape($Name) + '\r?\n(.*?)(?=\r?\n    - ReportName: |\z)').Groups[1].Value
    }
    function script:Get-FinalProject([string]$Block) {
        $q = [regex]::Match($Block, '(?s)ReportQuery:(.*)$').Groups[1].Value
        $m = [regex]::Matches($q, '(?s)\|\s*project\s+(.*?)(?=\r?\n\s*\||\z)')
        if ($m.Count -eq 0) { return '' }
        $m[$m.Count - 1].Groups[1].Value
    }

    function script:Write-Info { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Ok { param($m) }
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-ExcelReport.ps1'), [ref]$null, [ref]$null)
    $fn = $ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'New-RiskIndex' }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexOrder.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskIndexSi.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-FactorKeys.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RiskScore.ps1')
    $global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null
    $rows = @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
    $script:Index = New-RiskIndex -CsvRows $rows
    $cat = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model\risk-factors.locked.json')) | ConvertFrom-Json
    function script:Imp([string]$Id) { [int](@($cat.factors | Where-Object { $_.id -eq $Id })[0].impact) }
    $script:ImpRce = Imp 'remote_code_execution'; $script:ImpRestricted = Imp 'restricted_data'; $script:ImpProd = Imp 'production_environment'
    function script:Score([hashtable]$Extra) {
        $h = [ordered]@{ SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs (Missing Updates)'; ConfigurationName = 'Update vulnerable software'
            ConfigurationId = 'CVE-2026-0001'; SecuritySeverity = 'High'; CriticalityTier = 0; CriticalityTierLevel = 'Critical - tier 0'; AssetName = 'srv01'
            cmdbCriticality = 'Critical'; cmdbDataSensitivity = 'Restricted'; RiskFactor_Probability = 0; RiskFactor_Probability_Detailed = '' }
        foreach ($k in $Extra.Keys) { $h[$k] = $Extra[$k] }
        $ProgressPreference = 'SilentlyContinue'
        @(Calculate-RiskScore -Rows @([pscustomobject]$h) -RiskIndex $script:Index -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
            -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -ReportName 'T_Detailed')[0]
    }
}

Describe 'the catalog has CVE reports to check' {
    It 'finds the CVE reports by their exploit signals' {
        $names = @([regex]::Matches($script:Yaml, '(?s)    - ReportName: (\S+)\r?\n(.*?)(?=\r?\n    - ReportName: |\z)') | Where-Object { $_.Groups[2].Value -match 'FindingHasExploit' } | ForEach-Object { $_.Groups[1].Value })
        $names | Should -Contain 'Device_Missing_CVEs_Summary'
        $names | Should -Contain 'Device_Missing_CVEs_Detailed'
    }
}

Describe 'CVE report <Name>' -ForEach $script:CveReports {
    BeforeAll { $script:B = Get-ReportBlock $Name }
    It 'computes the remote-code-execution consequence token' {
        $script:B | Should -Match 'RF_C_RemoteCodeExec\s+= iff\('
        $script:B | Should -Match 'extend RiskFactor_Consequence_Detailed = strcat_array\(array_concat\(\s*iff\(RF_C_RemoteCodeExec == 1, dynamic\(\["RemoteCodeExecutionRisk"\]\)'
    }
    It 'projects RiskFactor_Consequence_Detailed in its final projection' {
        (Get-FinalProject $script:B) | Should -Match '\bRiskFactor_Consequence_Detailed\b'
    }
    It 'carries the token through its summarize (a Summary groups many findings)' {
        if ($Name -notlike '*_Summary*') { Set-ItResult -Skipped -Because 'a Detailed report has no summarize over findings'; return }
        $script:B | Should -Match 'RiskFactor_Consequence_Detailed = strcat_array\(make_set_if\(RiskFactor_Consequence_Detailed, isnotempty\(RiskFactor_Consequence_Detailed\)\), ";"\)'
    }
    It 'never hard-sets RiskFactor_Consequence = 0' {
        $script:B | Should -Not -Match 'RiskFactor_Consequence\s*=\s*0\b'
    }
    It 'lists RiskFactor_Consequence_Detailed in its output columns' {
        $script:B | Should -Match '(?m)^\s+- RiskFactor_Consequence_Detailed\s*$'
    }
}

Describe 'the engine counts the token and keeps the asset baseline' {
    It 'an RCE CVE scores the RCE impact above the same CVE without one, on the vulnerability side (#559)' {
        $no = Score @{ RiskFactor_Consequence_Detailed = '' }
        $rce = Score @{ RiskFactor_Consequence_Detailed = 'RemoteCodeExecutionRisk' }
        [int]$rce.RiskFactor_Probability | Should -Be ([int]$no.RiskFactor_Probability + $script:ImpRce)
        [double]$rce.RiskProbabilityScore | Should -Be ([double]$no.RiskProbabilityScore + $script:ImpRce)
        [double]$rce.RiskScoreTotal | Should -BeGreaterThan ([double]$no.RiskScoreTotal)
        @($rce.RiskFactor_Probability_Detailed -split ';') | Should -Contain 'RCE'
    }
    It 'keeps the data-sensitivity baseline (asset side) next to the report token; tier and CMDB criticality are never factors (#527 (5))' {
        $rce = Score @{ RiskFactor_Consequence_Detailed = 'RemoteCodeExecutionRisk' }
        @($rce.RiskFactor_Consequence_Detailed -split ';') | Should -Contain 'RestrictedData'
        @($rce.RiskFactor_Probability_Detailed -split ';') | Should -Contain 'RCE'
        foreach ($t in 'Tier0BlastRadius', 'BusinessCriticalAsset') { @(($rce.RiskFactor_Consequence_Detailed + ';' + $rce.RiskFactor_Probability_Detailed) -split ';') | Should -Not -Contain $t }
        [int]$rce.RiskFactor_Consequence | Should -Be $script:ImpRestricted
        [int]$rce.RiskFactor_Probability | Should -Be $script:ImpRce
    }
    It 'with no report token the baseline alone counts' {
        $no = Score @{ RiskFactor_Consequence_Detailed = '' }
        [int]$no.RiskFactor_Consequence | Should -Be $script:ImpRestricted
        [int]$no.RiskFactor_Probability | Should -Be 0
    }
    It 'does not add a baseline factor the CI context already put on the row under its catalog id' {
        $ci = Score @{ RiskFactor_Consequence_Detailed = 'RemoteCodeExecutionRisk;restricted_data' }
        [int]$ci.RiskFactor_Consequence | Should -Be $script:ImpRestricted
        @($ci.RiskFactor_Consequence_Detailed -split ';') | Should -Be @('RestrictedData')
    }
    It 'an engine signal does not lower the score either (Tier 0 + production environment)' {
        $base = Score @{ RiskFactor_Consequence_Detailed = '' }
        $prod = Score @{ RiskFactor_Consequence_Detailed = ''; IsProductionEnvironment = $true }
        [int]$prod.RiskFactor_Consequence | Should -Be ([int]$base.RiskFactor_Consequence + $script:ImpProd)
    }
}
