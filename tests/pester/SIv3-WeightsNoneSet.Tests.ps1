#Requires -Version 5.1
<#
    AN ENGINE WITH NO RISK WEIGHTS SHOWS "NOTHING WEIGHTED", NOT A WEIGHT EXPLANATION THAT WAS NEVER APPLIED.

    Risk weights are the customer's (riskscore_weighted.schema.custom.json, or the Pro settings database); none ship.
    When an engine has none, the catalog's default block stood: factor 100 (no lift, correct) but
    RiskScore_Weight_Detailed = "cmdbCriticality=<value>" on every row -- it read as a weight that had been applied.
    On top, every report warned "no riskscore_weighted.schema.custom.json found ... YAML stub will ship" (the
    publicip engine, which no sample covers, warned on every run).

    Now: no weights -> the zero-field chain the engine builds itself (factor 100, detail EMPTY -- what a configured
    engine shows on a row no field lifted), and one plain line per engine per run.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:_WeightedFactorsBeginMark = '//__WEIGHTED_FACTORS_BEGIN__'
    $script:_WeightedFactorsEndMark   = '//__WEIGHTED_FACTORS_END__'
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-WeightedFactors.ps1')
    $engineSrc = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    # the marks the engine really uses
    $src = [System.IO.File]::ReadAllText($engineSrc)
    $src | Should -Match ([regex]::Escape("`$script:_WeightedFactorsBeginMark = '//__WEIGHTED_FACTORS_BEGIN__'"))
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($engineSrc, [ref]$null, [ref]$null)
    $script:GetCfgText = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-WeightedFactorsConfig' }, $true).Extent.Text

    $script:Query = @'
T
| extend cmdbCriticality = "High"
//__WEIGHTED_FACTORS_BEGIN__
| extend RiskScore_Weight_Detailed = iff(isnotempty(cmdbCriticality), strcat("cmdbCriticality=", tostring(cmdbCriticality)), "")
| extend RiskScore_Weight_Factor   = 100   // basis-100, 100 = 1.0x = no lift
| extend RiskFactor_Weight         = 100
//__WEIGHTED_FACTORS_END__
| project RiskScore_Weight_Detailed, RiskScore_Weight_Factor, RiskFactor_Weight
'@
}

Describe 'no weights for an engine' {
    It 'the block becomes factor 100 with an EMPTY detail -- the catalog default''s cmdbCriticality string is gone' {
        function Get-WeightedFactorsConfig { param($ReportName, $Engine) $null }
        $q = Resolve-WeightedFactorsBlock -Query $script:Query -ReportName 'PublicIP_OpenPorts_Detailed' -Engine 'publicip'
        $block = [regex]::Match($q, '(?s)//__WEIGHTED_FACTORS_BEGIN__(.*?)//__WEIGHTED_FACTORS_END__').Groups[1].Value
        $block | Should -Match '\| extend RiskScore_Weight_Factor = 100'
        $block | Should -Match '\| extend RiskFactor_Weight = RiskScore_Weight_Factor'
        $block | Should -Match '\| extend RiskScore_Weight_Detailed = ""'
        $block | Should -Not -Match 'cmdbCriticality='
        $q | Should -Match '\| project RiskScore_Weight_Detailed, RiskScore_Weight_Factor, RiskFactor_Weight' -Because 'the rest of the query is untouched'
    }

    It 'a config with fields is substituted as before (the field''s chain, its detail string)' {
        function Get-WeightedFactorsConfig { param($ReportName, $Engine)
            [pscustomobject]@{ Path = 'x\riskscore_weighted.schema.custom.json'; Engine = 'endpoint'; Combine = 'product'; MaxMultiplier = 500.0
                Fields = @([pscustomobject]@{ field = 'cmdbCriticality'; valueMap = [pscustomobject]@{ Critical = 150 }; default = 100 }) } }
        $q = Resolve-WeightedFactorsBlock -Query $script:Query -ReportName 'R' -Engine 'endpoint'
        $q | Should -Match 'RF_W_cmdbCriticality = case\('
        $q | Should -Match 'min_of\(500, RF_W_cmdbCriticality\)'
        $q | Should -Match 'iff\(RF_W_cmdbCriticality != 100, pack_array\(strcat\("cmdbCriticality="'
    }

    It 'a query without the block is returned unchanged' {
        function Get-WeightedFactorsConfig { param($ReportName, $Engine) $null }
        Resolve-WeightedFactorsBlock -Query 'T | take 1' -ReportName 'R' -Engine 'endpoint' | Should -BeExactly 'T | take 1'
    }

    It 'the loader says it ONCE per engine, as information, never as a warning' {
        . ([scriptblock]::Create($script:GetCfgText))
        $script:Said = New-Object System.Collections.Generic.List[string]
        $script:Warned = New-Object System.Collections.Generic.List[string]
        function Write-Info { param($m) $script:Said.Add([string]$m) }
        function Write-Warn2 { param($m) $script:Warned.Add([string]$m) }
        $savedSp = $global:SettingsPath; $savedPro = $global:SI_ProRaSettingsPath
        try {
            $global:SettingsPath = (New-Item -ItemType Directory -Force (Join-Path $TestDrive 'empty-settings')).FullName
            $global:SI_ProRaSettingsPath = $null
            $script:_WeightedFactorsCache = $null; $script:_WeightedFactorsNoneSaid = $null
            foreach ($r in 'PublicIP_OpenPorts_Detailed', 'PublicIP_Vulnerabilities_Detailed', 'PublicIP_OpenPorts_Summary') {
                Get-WeightedFactorsConfig -ReportName $r -Engine 'publicip' | Should -BeNullOrEmpty
            }
            @($script:Said | Where-Object { $_ -like '*publicip*' }).Count | Should -Be 1
            ($script:Said | Where-Object { $_ -like '*publicip*' }) | Should -Match 'equals the base score'
            $script:Warned.Count | Should -Be 0
        } finally { $global:SettingsPath = $savedSp; $global:SI_ProRaSettingsPath = $savedPro }
    }
}
