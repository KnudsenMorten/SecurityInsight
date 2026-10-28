#Requires -Version 5.1
<#
    A SUMMARY ROW MUST NOT NAME ONE ARBITRARY ASSET, AND MUST NOT NAME A DIFFERENT ONE NEXT RUN.

    A Summary report groups many assets into one row (the `by` clause carries no asset). KQL's any() returns an
    ARBITRARY value from the group, with no determinism guarantee, so every column filled by any() at that grain
    was one random member of the group -- and a different one on the next run. AssetId was moved to min() on
    2026-09-01; the same any() still filled cmdbId / cmdbName (48 sites each) and MdeDeviceId /
    EntraAccountObjectId / AzureResourceId / MITRE_Tactics / MITRE_Techniques / ComplianceTags (84 each). The
    portal link in MoreDetails is built from MdeDeviceId / EntraAccountObjectId / AzureResourceId, so a Summary
    row pointed at one random machine or identity of the group, changing every run.

    min() is deterministic by VALUE and ignores empty strings (measured against Log Analytics 2026-09-01:
    min over "", "bbb", "aaa" is "aaa"), so it is a line-for-line replacement. At the Detailed grain the group
    holds one asset and the two agree.
#>

BeforeAll {
    $script:SIRoot  = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Lines   = @(Get-Content -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml') -Encoding UTF8)
    # the asset-identifying / attributing columns a Summary row publishes or builds links from
    $script:Cols    = @('AssetId', 'FirstSourceAssetId', 'cmdbId', 'cmdbName', 'MdeDeviceId', 'EntraAccountObjectId', 'AzureResourceId',
                        'MITRE_Tactics', 'MITRE_Techniques', 'ComplianceTags')
    $script:AnyRx   = '\b(' + ($script:Cols -join '|') + ')\s*=\s*any\('
    function Get-AnyAggregateLines([string[]]$Lines) {
        $hits = New-Object System.Collections.Generic.List[string]
        for ($i = 0; $i -lt $Lines.Count; $i++) {
            $code = $Lines[$i] -replace '//.*$', ''
            if ($code -match $script:AnyRx) { $hits.Add(('line {0}: {1}' -f ($i + 1), $Lines[$i].Trim())) }
        }
        $hits.ToArray()
    }
}

Describe 'the catalog fills asset columns deterministically' {
    It 'no report fills an asset-identifying column with any()' {
        $bad = @(Get-AnyAggregateLines $script:Lines)
        $bad.Count | Should -Be 0 -Because ("any() picks an arbitrary member of a Summary group, a different one each run -- use min():`n" + ($bad -join "`n"))
    }

    It 'the guard inspects the real aggregations (min() is present at scale)' {
        $min = @($script:Lines | Where-Object { $_ -match ('\b(' + ($script:Cols -join '|') + ')\s*=\s*min\(') })
        $min.Count | Should -BeGreaterThan 500
    }

    It 'the guard can fail: an any() line is caught, a commented one is not' {
        @(Get-AnyAggregateLines @('            MdeDeviceId = any(tostring(column_ifexists("MdeDeviceId",""))),')).Count | Should -Be 1
        @(Get-AnyAggregateLines @('            cmdbName = any(cmdbName),')).Count | Should -Be 1
        @(Get-AnyAggregateLines @('            // was: AssetId = any(x)')).Count | Should -Be 0
        @(Get-AnyAggregateLines @('            AssetLabel = any(AssetLabel),')).Count | Should -Be 0
    }

    It 'the bare-column forms are wrapped in tostring() so min() always sees a string' {
        @($script:Lines | Where-Object { $_ -match '\bcmdb(Id|Name)\s*=\s*min\(cmdb(Id|Name)\)' }).Count | Should -Be 0
    }
}
