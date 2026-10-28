#Requires -Version 5.1
<#
    NUMBERS FED TO THE AI SUMMARY ARE CULTURE-INVARIANT, WITH NO GROUP SEPARATOR (#155).

    Measured 2026-09-29 on the internal tenant (da-DK host): the prompt formatted scores with '{0:N0}' in the
    host's culture, so 4366 reached the model as "4.366". The model read it as a decimal below 289 and moved
    three workstations (289 / 281 / 224) above dc1 (4366), mgmt1 (3754) and dc3 (2189) in the Top-50 list it
    was told to copy in the engine's order. The engine's own ranking was correct.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
    $a = $script:Src.IndexOf('$script:_RAFmtInv = {')
    $b = $script:Src.IndexOf('$assetsTextForAI = $assetLines -join')
    $script:PromptBlock = $script:Src.Substring($a, $b - $a)
    $script:HelperLine = [regex]::Match($script:Src, '(?m)^\s*\$script:_RAFmtInv = \{.*\}\s*$').Value
}

Describe 'the numbers in the AI prompt' {
    It 'the prompt rollup uses no culture-dependent number format' {
        $a | Should -BeGreaterThan 0
        $script:PromptBlock | Should -Not -Match '\{\d+:N\d\}'
        $script:PromptBlock | Should -Not -Match '"\s*-f\s'
    }
    It 'the finding line, the asset line and the per-finding asset scores all go through the invariant formatter' {
        ([regex]::Matches($script:PromptBlock, '\$script:_RAFmtInv\.Invoke\(')).Count | Should -Be 3
    }
    It 'on a da-DK host, 4366 reaches the prompt as "4366" and a line still joins as one string' {
        $script:HelperLine | Should -Not -BeNullOrEmpty
        $saved = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('da-DK')
            Invoke-Expression $script:HelperLine
            ('{0:N0}' -f 4366.0) | Should -Be '4.366'   # the trap this guards against
            $lines = @()
            $lines += $script:_RAFmtInv.Invoke('{0}. TotalRiskScore={1:0}; WeightedRiskScore={2:0}', @(1, 4366.0, 4366.4))
            $lines += $script:_RAFmtInv.Invoke('{0}. TotalRiskScore={1:0}; WeightedRiskScore={2:0}', @(2, 289.0, 288.6))
            $lines.Count | Should -Be 2
            ($lines -join "`n") | Should -Be "1. TotalRiskScore=4366; WeightedRiskScore=4366`n2. TotalRiskScore=289; WeightedRiskScore=289"
        } finally {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = $saved
        }
    }
}
