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

    It 'covers the six reports the fix was applied to' {
        # Pins the blast radius so a report cannot quietly drop out of the invariant.
        # 4 -> 6 on 2026-08-13: Endpoint_ExcludedAssets_Summary and
        # Endpoint_ActiveCompromise_Detected_Summary both joined when their regressions were fixed.
        $derived = @($script:Catalog.Reports | Where-Object {
            ([string]$_.ReportQuery) -match 'ImpactedAssetCount\s*=\s*array_length\(\s*ImpactedAssetsList\s*\)'
        } | ForEach-Object { $_.ReportName })
        $derived.Count | Should -Be 6
        foreach ($n in @('Device_Missing_CVEs_Summary','Device_Recommendations_Summary','Azure_Recommendations_Summary',
                         'Endpoint_ExcludedAssets_Summary','Endpoint_ActiveCompromise_Detected_Summary')) {
            $derived | Should -Contain $n
        }
    }

    # ------------------------------------------------------------------------
    # RE-KEYED 2026-08-13, and this is the important part of the file.
    #
    # Every check above opens with `if ($q -notmatch 'ImpactedAssetsList\s*=\s*make_set') { continue }`
    # -- it selects on the LIST. Endpoint_ExcludedAssets_Summary (v2.2.431) built
    # `ImpactedAssets = strcat_array(array_sort_asc(make_set(AssetName)), ";")` beside
    # `ImpactedAssetCount = dcount(PrimaryEntityId)`: a different column name AND a different shape,
    # so it failed the selector on both counts and was skipped in SILENCE. This suite reported PASS
    # while walking past the one report that violated it, for six days, and only SI-OutputIntegrity
    # against a real export (count=19, listLen=17) caught it.
    #
    # A guard whose selector is narrower than its invariant reports success for what it never
    # inspected. So the checks below select on the COUNT -- the thing being defended -- and make the
    # inspected set itself assertable.
    # ------------------------------------------------------------------------

    # The selector is "does this report project an impacted-ASSET list at all", under either name and
    # in either shape. Deliberately NOT a bare `make_set(` -- several reports build sets for unrelated
    # columns (ExcludedReasons, MITRE tags), and a guard that fires on those would be noise, which is
    # its own way of going unread.
    It 'no report counts with dcount/count while ALSO projecting an asset list -- under either name' {
        # The regression shape, stated without pinning the list column's name or its wrapper. This is
        # the assertion that would have failed on 2026-08-12 instead of silently passing.
        $bad = @()
        foreach ($r in $script:Catalog.Reports) {
            $q = [string]$r.ReportQuery
            if ($q -notmatch 'ImpactedAssetCount\s*=\s*(dcount|count)\s*\(') { continue }
            if ($q -match 'ImpactedAssets(List)?\s*=\s*\w+\s*\(')            { $bad += $r.ReportName }
        }
        $bad | Should -BeNullOrEmpty -Because ("these count one column while listing another, which is audit #25 " +
                                               "regardless of what the list column is named: $($bad -join ', ')")
    }

    It 'every report computing ImpactedAssetCount is accounted for -- none is silently skipped' {
        # Turns "0 violations" into "N inspected, and here is why each is acceptable". A new report
        # computing a count in some third shape lands in $unexplained and FAILS, instead of slipping
        # past a selector that never matched it.
        $derivesFromList = @()   # count = array_length(<its own list>)
        $noListAtAll     = @()   # projects no asset list; the engine supplies one (see the engine half)
        $unexplained     = @()
        foreach ($r in $script:Catalog.Reports) {
            $q = [string]$r.ReportQuery
            if ($q -notmatch 'ImpactedAssetCount\s*=') { continue }
            if ($q -match 'ImpactedAssetCount\s*=\s*array_length\(')  { $derivesFromList += $r.ReportName; continue }
            if ($q -notmatch 'ImpactedAssets(List)?\s*=\s*\w+\s*\(')  { $noListAtAll     += $r.ReportName; continue }
            $unexplained += $r.ReportName
        }
        $unexplained | Should -BeNullOrEmpty -Because ("each of these computes ImpactedAssetCount in a shape this " +
                                                       "suite does not recognise, so it is neither proven correct nor " +
                                                       "reported as unchecked: $($unexplained -join ', ')")
        # The count-carrying population is small and known; if it grows, that is a deliberate act.
        (@($derivesFromList).Count + @($noListAtAll).Count) | Should -BeGreaterThan 0
        # Every KQL-computed count now derives from that report's own list. There is no longer a
        # report claiming a count with no list to justify it -- the last such claim turned out to be
        # a misreading rather than an exception.
        $noListAtAll | Should -BeNullOrEmpty -Because ("a count with no list beside it cannot be checked by " +
                                                       "anything: $($noListAtAll -join ', ')")
    }

    It 'the "report with NO list" was a misreading, and it is fixed' {
        # SUPERSEDED 2026-08-13. This assertion used to say Endpoint_ActiveCompromise_Detected_Summary
        # emits no list, so array_length had nothing to derive from and the audit's prescription was
        # "impossible" there. That was true only of the NAME: the report always projected the same
        # set as `ImpactedAssets = strcat_array(array_sort_asc(make_set(AssetName)), ";")`, beside
        # `dcount(PrimaryEntityId)` -- audit #25 verbatim, sitting behind an exemption this suite
        # granted it. It returns 0 rows on this estate, so the export-based test could never catch it
        # either: the invariant is vacuous on an empty report, and it would first have misstated its
        # numbers on the day a real compromise was detected.
        #
        # The lesson is about exemptions, not this report: an exemption justified by a claim nobody
        # re-checked is indistinguishable from a gap.
        $r = $script:Catalog.Reports | Where-Object { $_.ReportName -eq 'Endpoint_ActiveCompromise_Detected_Summary' }
        ([string]$r.ReportQuery) | Should -Match 'ImpactedAssetsList\s*=\s*make_set'
        ([string]$r.ReportQuery) | Should -Match 'ImpactedAssetCount\s*=\s*array_length\(\s*ImpactedAssetsList\s*\)'
        ([string]$r.ReportQuery) | Should -Not -Match 'ImpactedAssetCount\s*=\s*dcount\('
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

# ============================================================================
Describe 'audit #25 -- the FOURTH shape: a make_set list arrives in two different shapes' {
# ============================================================================
<#
    Found by measuring run 20260813T204314Z, after the KQL half of #25 was fixed.

    `ImpactedAssetsList = make_set(AssetName)` does not produce one shape at the engine. It
    depends on which ROUTE the query took:

      * XDR Advanced Hunting  -> the dynamic column is materialized as an object[]
      * LA-direct (any report reading a *_CL table) -> it comes back as JSON TEXT

    The normalizer only understood "semicolon-joined string" and "already an array", so the JSON
    text was split on ';', found no separator, and became a SINGLE element holding the whole
    document. Endpoint_ExcludedAssets_Summary published [["a","b",... 17 items ...]] -- a list
    whose length reads 1 -- beside a KQL-computed count of 17.

    These tests execute the REAL normalizer block, extracted from the shipped file by AST. A copy
    would drift; the self-check below fails the suite if the extraction stops matching, so this
    can never pass by inspecting nothing.
#>

    BeforeAll {
        $si  = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
        $src = Join-Path $si 'engine\risk-analysis\_shared\RA-RiskScore.ps1'

        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($src, [ref]$tokens, [ref]$errors)
        if ($errors.Count) { throw "RA-RiskScore.ps1 has parse errors: $($errors[0].Message)" }

        # The two sibling `if` statements that normalize $existingImpacted, in source order.
        $script:NormalizerAsts = @($ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.IfStatementAst] -and
            $n.Clauses[0].Item1.Extent.Text -match '\$existingImpacted -is \[string\]'
        }, $true))

        $script:NormalizerText = ($script:NormalizerAsts | ForEach-Object { $_.Extent.Text }) -join "`n"

        function script:Invoke-Normalizer {
            param($Value)
            $existingImpacted = $Value
            . ([scriptblock]::Create($script:NormalizerText))
            return $existingImpacted
        }
    }

    It 'the extraction found the normalizer (self-check -- absence must not read as success)' {
        $script:NormalizerAsts.Count | Should -BeGreaterOrEqual 2
        $script:NormalizerText | Should -Match 'ConvertFrom-Json'
    }

    It 'LA-direct shape: a JSON array in TEXT becomes a real array of that many items' {
        $json = (1..17 | ForEach-Object { "asset$_" }) | ConvertTo-Json -Compress
        $out  = script:Invoke-Normalizer -Value $json
        @($out).Count | Should -Be 17
        @($out)[0]    | Should -Be 'asset1'
    }

    It 'the parsed list is EXACTLY what array_length counted -- order and duplicates preserved' {
        # Not re-sorted and not blank-filtered on this path: KQL already counted this array, so
        # any tidying here would recreate the mismatch from the other direction.
        $json = '["zebra","alpha","","alpha"]'
        $out  = script:Invoke-Normalizer -Value $json
        @($out).Count | Should -Be 4
        @($out)[0]    | Should -Be 'zebra'
    }

    It 'XDR shape: an array is passed through untouched' {
        $arr = @('b','a','c')
        $out = script:Invoke-Normalizer -Value $arr
        @($out).Count | Should -Be 3
        @($out)[0]    | Should -Be 'b'
    }

    It 'strcat_array shape: a semicolon-joined string still splits, dedupes and sorts' {
        $out = script:Invoke-Normalizer -Value 'charlie; alpha ;bravo;;alpha'
        @($out).Count | Should -Be 3
        @($out)[0]    | Should -Be 'alpha'
    }

    It 'a single plain name is still one item, not one character' {
        $out = script:Invoke-Normalizer -Value 'SRV-01'
        @($out).Count | Should -Be 1
        @($out)[0]    | Should -Be 'SRV-01'
    }

    It 'text that only LOOKS like JSON falls back to the semicolon split instead of throwing' {
        # A hostname list is not a document. If ConvertFrom-Json fails the row must still ship.
        $out = script:Invoke-Normalizer -Value '[not json; really'
        @($out).Count | Should -BeGreaterThan 0
    }

    It 'an empty JSON array yields an empty list, not a one-element list holding "[]"' {
        $out = script:Invoke-Normalizer -Value '[]'
        @($out).Count | Should -Be 0
    }
}
