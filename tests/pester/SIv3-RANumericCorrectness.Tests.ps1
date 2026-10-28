#Requires -Version 5.1
<#
    RISK ANALYSIS NUMERIC CORRECTNESS (#121) -- on the host SI actually runs on, which is da-DK.

    Every defect here produced a WRONG NUMBER with no error:
      * an UNKNOWN tier became Tier 0 -- [int]::TryParse writes 0 into its out-variable on failure,
        so `$tier = -1; TryParse(blank, [ref]$tier)` weighted an unclassified asset 4x in the KPI;
        and _toDouble($null) = 0 stamped Tier0BlastRadius on every blank-tier row
      * `'>= {1}' -f 7.5` renders `>= 7,5` on da-DK -- a KQL syntax error in the CVE filter
      * culture-default [double]::TryParse reads "12.5" as 125 on da-DK (and a preceding
        -replace ',', '.' made a Danish "12,5" hit the same trap)
      * $rfWeight never existed ($rfWeightPct does): RiskFactor_Weight published 0 instead of 100
      * the JSON sibling was an empty file for 0 rows and a bare object for 1 row
      * the challenger "median" used [int]() rounding (half-to-even): n=3 picked the MAXIMUM

    The culture-sensitive tests run with the thread culture set to da-DK explicitly, so they fail on
    ANY host -- not only on the one whose locale happens to expose the bug.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:RaDir  = Join-Path $script:SIRoot 'engine\risk-analysis'
    . (Join-Path $script:RaDir '_shared\RA-RiskScore.ps1')
    . (Join-Path $script:RaDir '_shared\RA-AutoBucketing.ps1')
    # SCRIPT scope, never global: a global stub outlives this file in the gate's single process and
    # once silenced the Trend suite's output. The functions under test are dot-sourced into this same
    # scope, so they still resolve it.
    function script:Write-Info { param([string]$m) }

    $script:Engine = Join-Path $script:RaDir 'Invoke-RiskAnalysis.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Engine, [ref]$null, [ref]$null)
    $fn  = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Resolve-CveFilterBlock' }, $true) | Select-Object -First 1
    . ([scriptblock]::Create($fn.Extent.Text))
    $script:_CveFilterBeginMark = '//__CVE_FILTER_BEGIN__'
    $script:_CveFilterEndMark   = '//__CVE_FILTER_END__'

    $raw = [regex]::Replace((Get-Content -LiteralPath $script:Engine -Raw), '(?s)<#.*?#>', '')
    $script:CodeNC = (($raw -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    $rsRaw = [regex]::Replace((Get-Content -LiteralPath (Join-Path $script:RaDir '_shared\RA-RiskScore.ps1') -Raw), '(?s)<#.*?#>', '')
    $script:ScoreNC = (($rsRaw -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

    function script:Invoke-InDanish([scriptblock]$Body) {
        $prev = [System.Threading.Thread]::CurrentThread.CurrentCulture
        try {
            [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('da-DK')
            & $Body
        } finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $prev }
    }
}

Describe 'ConvertTo-RADouble -- invariant on a da-DK host' {
    It 'reads "12.5" as 12.5, not 125' {
        Invoke-InDanish { ConvertTo-RADouble -Value '12.5' } | Should -Be 12.5
    }
    It 'accepts a hand-typed decimal comma "7,5" as 7.5' {
        Invoke-InDanish { ConvertTo-RADouble -Value '7,5' } | Should -Be 7.5
    }
    It 'passes real numbers through and defaults blank/garbage' {
        ConvertTo-RADouble -Value 3 | Should -Be 3
        ConvertTo-RADouble -Value '' -Default 100 | Should -Be 100
        ConvertTo-RADouble -Value 'n/a' -Default 7 | Should -Be 7
        ConvertTo-RADouble -Value $null -Default 1 | Should -Be 1
    }
}

Describe 'ConvertTo-RATierOrNull -- unknown stays unknown' {
    It 'blank, null and garbage are $null -- never Tier 0' {
        ConvertTo-RATierOrNull ''    | Should -BeNullOrEmpty
        ConvertTo-RATierOrNull $null | Should -BeNullOrEmpty
        ConvertTo-RATierOrNull 'abc' | Should -BeNullOrEmpty
    }
    It 'real tiers survive, including 0' {
        ConvertTo-RATierOrNull '0'   | Should -Be 0
        ConvertTo-RATierOrNull 2     | Should -Be 2
        ConvertTo-RATierOrNull '1.0' | Should -Be 1
    }
    It 'a $null tier takes a switch''s DEFAULT branch, not the 0 branch (the assumption the KPI relies on)' {
        $t = ConvertTo-RATierOrNull ''
        $w = switch ($t) { 0 { 4.0 } 1 { 2.0 } default { 1.0 } }
        $w | Should -Be 1.0
    }
}

Describe 'the CVE filter emits valid KQL on a da-DK host' {
    BeforeEach {
        $global:SI_CVE_MinSeverity = $null; $global:SI_CVE_RequireExploit = $false; $global:SI_CVE_MaxPublishedAgeDays = $null
    }
    AfterEach { $global:SI_CVE_MinCvssScore = $null }

    It 'a 7.5 threshold renders ">= 7.5", never ">= 7,5"' {
        $global:SI_CVE_MinCvssScore = 7.5
        $q = "x`n//__CVE_FILTER_BEGIN__`n//__CVE_FILTER_END__`ny"
        $out = Invoke-InDanish { Resolve-CveFilterBlock -Query $q -ReportName 'r' }
        $out | Should -Match 'toreal\(NodeProperties\.rawData\.cvssScore\) >= 7\.5'
        $out | Should -Not -Match '7,5'
    }
    It 'a config value typed with a decimal comma still works' {
        $global:SI_CVE_MinCvssScore = '7,5'
        $q = "x`n//__CVE_FILTER_BEGIN__`n//__CVE_FILTER_END__`ny"
        (Invoke-InDanish { Resolve-CveFilterBlock -Query $q -ReportName 'r' }) | Should -Match '>= 7\.5'
    }
}

Describe 'the challenger median is the real median' {
    It 'with 11 other entries 1..11 the median is 6, so a cached 65 at 10x IS flagged' {
        $cache = @{}
        for ($i = 1; $i -le 11; $i++) { $cache["q$i"] = $i }
        $global:AutoBucketChallenger_MedianMultiplier = 10
        $global:AutoBucketChallenger_MinEntries = 10
        try {
            Test-AutoBucketChallenger -Cache $cache -QueryKey 'target' -CachedValue 65 | Should -BeTrue -Because 'banker''s rounding picked index 6 (value 7) and 65 < 70 slipped through'
        } finally {
            $global:AutoBucketChallenger_MedianMultiplier = $null; $global:AutoBucketChallenger_MinEntries = $null
        }
    }
}

Describe 'WIRING -- the fixed call sites' {
    It 'no culture-default double parse is left in the engine' {
        $script:CodeNC | Should -Not -Match '\[double\]::TryParse\([^,]+,\s*\[ref\]'
    }
    It 'the KPI tier is read through ConvertTo-RATierOrNull, not TryParse into the -1 sentinel' {
        $script:CodeNC | Should -Not -Match 'TryParse\(\[string\]\$r\.CriticalityTier'
        $script:CodeNC | Should -Match 'ConvertTo-RATierOrNull \$r\.CriticalityTier'
    }
    It 'RA-RiskScore reads the tier through ConvertTo-RATierOrNull (no tier-derived risk factor any more)' {
        $script:ScoreNC | Should -Not -Match 'TryParse\(\[string\]\$tmp2\[''CriticalityTier''\]'
        $script:ScoreNC | Should -Match 'ConvertTo-RATierOrNull \$tmp2\[''CriticalityTier''\]'
        $script:ScoreNC | Should -Not -Match '''Tier0BlastRadius''\)'
    }
    It 'RiskFactor_Weight defaults from $rfWeightPct, and $rfWeight is gone' {
        $script:ScoreNC | Should -Match "\`$tmp\['RiskFactor_Weight'\]\s*= \[double\]\`$rfWeightPct"
        $script:ScoreNC | Should -Not -Match '\$rfWeight\b'
    }
    It 'the JSON sibling is written with -InputObject, so 0 rows is [] and 1 row is a one-element array' {
        # #264: the JSON sibling is Risk Analysis's read-time view (exempted rows left out unless counted)
        # 2026-10-13: written row by row (Write-RAJsonArrayFile, RA-Delivery.ps1) -- always an array; SIv3-RaDeliveryMemory proves 0 / 1 / many
        $script:CodeNC | Should -Match 'Write-RAJsonArrayFile -Rows \$global:RA_ReportRows'
        (ConvertTo-Json -InputObject @() -Compress) | Should -Be '[]'
        (ConvertTo-Json -InputObject @([pscustomobject]@{ a = 1 }) -Compress) | Should -Be '[{"a":1}]'
    }
}
