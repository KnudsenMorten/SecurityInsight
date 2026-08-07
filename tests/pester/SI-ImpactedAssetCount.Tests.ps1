#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- audit #25: ImpactedAssetCount must be the length of ImpactedAssetsList.

.DESCRIPTION
    The defect an operator noticed before any suite did: a count sitting next to a list it does
    not describe. Neither number is wrong on its own -- they measure different things -- so
    nothing looks broken, and the report quietly lies about how many assets are impacted.

    There are TWO places that produce these columns, and audit #25 named only the first:

      1. KQL, in the catalog. 5 Summary reports compute ImpactedAssetCount inside a summarize,
         e.g. `dcount(DeviceKey)` beside `ImpactedAssetsList = make_set(AssetName)`. Different
         columns, and dcount is approximate besides.

      2. THE ENGINE -- RA-RiskScore.ps1. For every Summary report whose KQL does NOT emit these
         columns (55 of them), the engine fills them itself, and it used distinct
         ConfigurationId for the count while building the list from distinct AssetName. Same
         defect, far wider blast radius, and not mentioned in the finding at all.

    The engine deliberately PRESERVES a YAML-computed value and only injects its own when the
    query did not provide one, so the two paths are complementary rather than competing --
    which is why both halves need fixing.
#>

BeforeAll {
    $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    if (-not (Get-Module -Name powershell-yaml)) { Import-Module powershell-yaml -Force }
    $script:Catalog = Get-Content -Raw -LiteralPath (Join-Path $si 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml') | ConvertFrom-Yaml
    $script:RiskScoreText = Get-Content -Raw -LiteralPath (Join-Path $si 'engine\risk-analysis\_shared\RA-RiskScore.ps1')
}

# ============================================================================
Describe 'audit #25 -- the KQL half: the count is derived from the list' {
# ============================================================================

    It 'no report computes ImpactedAssetCount with dcount while it also builds a list' {
        # The exact shape of the defect: a count aggregate beside a set aggregate.
        $bad = @()
        foreach ($r in $script:Catalog.Reports) {
            $q = [string]$r.ReportQuery
            if ($q -notmatch 'ImpactedAssetsList\s*=\s*make_set') { continue }
            if ($q -match 'ImpactedAssetCount\s*=\s*dcount\(') { $bad += $r.ReportName }
        }
        $bad | Should -BeNullOrEmpty -Because "these report a count over a different column than the list they display: $($bad -join ', ')"
    }

    It 'every report that builds a list derives the count from THAT list' {
        $missing = @()
        foreach ($r in $script:Catalog.Reports) {
            $q = [string]$r.ReportQuery
            if ($q -notmatch 'ImpactedAssetsList\s*=\s*make_set') { continue }
            if ($q -notmatch 'ImpactedAssetCount\s*=\s*array_length\(\s*ImpactedAssetsList\s*\)') { $missing += $r.ReportName }
        }
        $missing | Should -BeNullOrEmpty -Because "missing array_length derivation: $($missing -join ', ')"
    }

    It 'covers the four reports the fix was applied to' {
        # Pins the blast radius so a report cannot quietly drop out of the invariant.
        $derived = @($script:Catalog.Reports | Where-Object {
            ([string]$_.ReportQuery) -match 'ImpactedAssetCount\s*=\s*array_length\(\s*ImpactedAssetsList\s*\)'
        } | ForEach-Object { $_.ReportName })
        $derived.Count | Should -Be 4
        foreach ($n in @('Device_Missing_CVEs_Summary','Device_Recommendations_Summary','Azure_Recommendations_Summary')) {
            $derived | Should -Contain $n
        }
    }

    It 'the one report with NO list is left alone, deliberately' {
        # Endpoint_ActiveCompromise_Detected_Summary emits no ImpactedAssetsList at all, so
        # array_length has nothing to derive from -- the audit's prescription is impossible
        # there. Its KQL count stays, and the ENGINE supplies the list (see the engine half),
        # which is what makes the pair consistent for this report.
        $r = $script:Catalog.Reports | Where-Object { $_.ReportName -eq 'Endpoint_ActiveCompromise_Detected_Summary' }
        ([string]$r.ReportQuery) | Should -Not -Match 'ImpactedAssetsList\s*=\s*make_set'
    }
}

# ============================================================================
Describe 'audit #25 -- the ENGINE half (55 reports, unmentioned by the finding)' {
# ============================================================================

    It 'no longer counts distinct ConfigurationId as an asset count' {
        # ConfigurationId identifies the finding / configuration item, not the asset, so the
        # old value was closer to an issue count than an asset count despite its name.
        $script:RiskScoreText | Should -Not -Match "\`$tmp2\['ImpactedAssetCount'\]\s*=\s*\[int\]\`$assetIds\.Count"
        $script:RiskScoreText | Should -Match '\$configIdCount\s*=\s*\$assetIds\.Count'
    }

    It 'derives the injected count from the same set it puts in the list' {
        $script:RiskScoreText | Should -Match '\$assetCount\s*=\s*if\s*\(\s*\$impactedAssets\.Count\s*-gt\s*0\s*\)\s*\{\s*\$impactedAssets\.Count\s*\}'
    }

    It 'falls back rather than reporting zero impacted assets' {
        # If no row carried a resolvable AssetName the list is empty; reporting 0 for a report
        # that clearly has findings would be a new lie in place of the old one.
        $script:RiskScoreText | Should -Match 'else\s*\{\s*\$configIdCount\s*\}'
    }

    It 'still only injects when the query did not supply the value' {
        # The two halves must stay complementary: a KQL-computed count wins, so the catalog
        # fix above is not silently overwritten by the engine. The condition now reads through
        # $yamlSuppliedCount, which is captured BEFORE the injection for exactly this reason.
        $script:RiskScoreText | Should -Match "if \(-not \`$yamlSuppliedCount\) \{"
        $script:RiskScoreText | Should -Match "\`$yamlSuppliedCount\s*=\s*\(\`$tmp2\.Contains\('ImpactedAssetCount'\) -and -not \[string\]::IsNullOrWhiteSpace"
    }

    It 'still restricts these aggregates to Summary reports' {
        # Whole-report scalars are meaningless per-asset in Detailed reports.
        $script:RiskScoreText | Should -Match '\$isSummaryReport\s*=\s*\$ReportName\s+-and'
    }

    It 'corrects the count when the LIST came from the report but the count did not' {
        # The third shape of #25, found by measuring a completed run rather than by reading code:
        # the list is per-summarize-group (this row's assets) while the injected count is a
        # whole-report aggregate, so they describe different things. Live example --
        # Identity_SPN_RoleManagementWrite_Summary showed ImpactedAssetCount = 1 beside a list of
        # 5 SPNs; 14 of 99 rows across the run disagreed this way.
        $script:RiskScoreText | Should -Match "if \(\`$hasYamlImpacted -and -not \`$yamlSuppliedCount\) \{"
        $script:RiskScoreText | Should -Match "\`$tmp2\['ImpactedAssetCount'\] = \[int\]@\(\`$existingImpacted\)\.Count"
    }

    It 'a count the REPORT computed still wins over the engine' {
        # Same precedence rule as the injection above: only a count this engine supplied may be
        # corrected. A report that deliberately computes its own count keeps it.
        $script:RiskScoreText | Should -Match '\$yamlSuppliedCount\s*=\s*\(\$tmp2\.Contains\(''ImpactedAssetCount''\)'
    }
}
