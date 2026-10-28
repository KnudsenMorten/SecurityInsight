#Requires -Version 5.1
<#
    A REPORT THAT DECLARES THE WEIGHT COLUMNS MUST NOT PROJECT THEM AWAY (#156).

    Measured 2026-09-29 on the internal tenant: 13 Detailed rows (Identity_PrivilegedRole_PermanentNotEligible,
    Identity_SPN_MailboxImpersonation) shipped an EMPTY RiskScore_Weight_Factor / RiskScore_Weight_Detailed.
    The weighted-factors block sets both, and the report's LAST `| project` -- after that block -- listed only
    RiskFactor_Weight, so the declared columns were dropped. Eleven Identity *_Detailed reports carried the same
    shape; only two had findings that day. The weighted score itself was right (it reads RiskFactor_Weight).
#>

BeforeAll {
    $script:SIRoot  = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')   # SecurityInsight's own YAML reader
    $script:Catalog = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml') | ConvertFrom-SIYaml

    # Report names whose final plain `| project` after the weighted-factors block omits a weight column
    # the report declares in OutputPropertyOrder.
    function Get-DroppedWeightColumns {
        param([object[]]$Reports)
        $hits = New-Object System.Collections.Generic.List[string]
        foreach ($r in $Reports) {
            $q = [string]$r.ReportQuery
            if (-not $q) { continue }
            $declared = @($r.OutputPropertyOrder | Where-Object { $_ -in 'RiskScore_Weight_Factor', 'RiskScore_Weight_Detailed' })
            if ($declared.Count -eq 0) { continue }
            $e = $q.IndexOf('//__WEIGHTED_FACTORS_END__')
            if ($e -lt 0) { continue }
            $after = (($q.Substring($e) -split "`n") | ForEach-Object { $_ -replace '//.*$', '' }) -join "`n"
            $projs = [regex]::Matches($after, '(?s)\|\s*project\s+(?!-)(.*?)(?=\n\s*\||$)')
            if ($projs.Count -eq 0) { continue }
            $last = $projs[$projs.Count - 1].Groups[1].Value
            foreach ($c in $declared) {
                if ($last -notmatch "\b$c\b") { $hits.Add(('{0}: {1}' -f $r.ReportName, $c)) }
            }
        }
        $hits.ToArray()   # no unary comma: @(...) at the caller must count 0 on no hits
    }
}

Describe 'the weight columns in the shipped catalog' {
    It 'every report that declares them still carries them after its final project' {
        $hits = @(Get-DroppedWeightColumns -Reports @($script:Catalog.Reports))
        $hits.Count | Should -Be 0 -Because ($hits -join '; ')
    }
    It 'the scan sees the defect it guards against (a project that drops them)' {
        $bad = @{
            ReportName          = 'Probe_Detailed'
            OutputPropertyOrder = @('RiskScoreTotal', 'RiskScore_Weight_Factor', 'RiskScore_Weight_Detailed')
            ReportQuery         = "T`n//__WEIGHTED_FACTORS_BEGIN__`n| extend RiskScore_Weight_Factor = 100`n//__WEIGHTED_FACTORS_END__`n| project A, B, RiskFactor_Weight`n| sort by RiskFactor_Weight desc"
        }
        $good = $bad.Clone()
        $good.ReportQuery = $bad.ReportQuery.Replace('B, RiskFactor_Weight', 'B, RiskFactor_Weight, RiskScore_Weight_Detailed, RiskScore_Weight_Factor')
        @(Get-DroppedWeightColumns -Reports @($bad)).Count  | Should -Be 2
        @(Get-DroppedWeightColumns -Reports @($good)).Count | Should -Be 0
    }
}
