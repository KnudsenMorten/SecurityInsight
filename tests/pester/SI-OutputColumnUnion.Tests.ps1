#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- audit #26: export columns must be the UNION of all rows, not row 1's.

.DESCRIPTION
    The defect the operator found before any suite did: "vital columns are gone in the
    reporting in ra excel like remediation data".

    Advanced-Hunting rows are rebuilt from the Graph additional-properties bag
    (RA-GraphHunting.ps1:448) and that bag OMITS null-valued columns. So rows of the SAME
    report genuinely carry different property sets. The engine discovered its export columns
    from `$firstObj | Get-Member` and then applied `Select-Object -Property $DesiredColumns`,
    so a column that merely happened to be empty on row 1 vanished from the xlsx, the JSON
    sibling AND the Log Analytics ingest for that whole report.

    A column named in the YAML OutputPropertyOrder was safe. RemediationOptions /
    RecommendedAction / Recommendation are declared nowhere, so they rode on first-row luck.

    TESTS.md section 8 asked for exactly this shape of test: "shape a fake $RiskScoreArray
    whose first row is missing a property, run it through the column-shaping logic, and
    assert the property survives".
#>

BeforeAll {
    $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $si 'engine\risk-analysis\_shared\RA-ExcelReport.ps1')

    # An AH-shaped row: only the keys the additional-properties bag actually carried.
    # Null-valued columns are simply absent, which is the whole point.
    # NOTE the param type. Typing this [hashtable] silently COERCES an [ordered] dictionary
    # into an unordered one, so any order-sensitive assertion becomes a coin flip -- it
    # passed standalone and failed in the gate run. IDictionary keeps [ordered] ordered.
    function New-AhRow {
        param([System.Collections.IDictionary]$Props)
        return [pscustomobject]$Props
    }
}

# ============================================================================
Describe 'audit #26 -- the export column list is the union across all rows' {
# ============================================================================

    It 'keeps a column that is missing from the FIRST row' {
        # The exact production shape: remediation data is null on row 1, present on row 2.
        $rows = @(
            (New-AhRow @{ AssetName = 'srv1'; RiskScoreTotal = 10 }),
            (New-AhRow @{ AssetName = 'srv2'; RiskScoreTotal = 20; RemediationOptions = 'Patch KB123' })
        )
        $cols = Get-RAColumnUnion -Rows $rows
        $cols | Should -Contain 'RemediationOptions'
    }

    It 'keeps a column that appears only on the LAST row of a long report' {
        # Guards against any "sample the first N rows" shortcut creeping back in.
        $rows = @(1..500 | ForEach-Object { New-AhRow @{ AssetName = "srv$_"; RiskScoreTotal = $_ } })
        $rows += (New-AhRow @{ AssetName = 'srv-last'; RiskScoreTotal = 1; RecommendedAction = 'Rotate the key' })
        $cols = Get-RAColumnUnion -Rows $rows
        $cols | Should -Contain 'RecommendedAction'
    }

    It 'recovers all three undeclared remediation columns at once' {
        # These three are in no OutputPropertyOrder anywhere, so they have no other protection.
        $rows = @(
            (New-AhRow @{ AssetName = 'a' }),
            (New-AhRow @{ AssetName = 'b'; RemediationOptions = 'x' }),
            (New-AhRow @{ AssetName = 'c'; RecommendedAction  = 'y' }),
            (New-AhRow @{ AssetName = 'd'; Recommendation     = 'z' })
        )
        $cols = Get-RAColumnUnion -Rows $rows
        foreach ($c in @('RemediationOptions','RecommendedAction','Recommendation')) {
            $cols | Should -Contain $c
        }
    }

    It 'is FIRST-SEEN ordered, so the sheet shape stays stable and readable' {
        $rows = @(
            (New-AhRow ([ordered]@{ Zebra = 1; Alpha = 2 })),
            (New-AhRow ([ordered]@{ Zebra = 3; Middle = 4 }))
        )
        # Not sorted alphabetically -- Zebra was seen first and stays first.
        (Get-RAColumnUnion -Rows $rows) | Should -Be @('Zebra','Alpha','Middle')
    }

    It 'lists each column exactly once however many rows carry it' {
        $rows = @(1..50 | ForEach-Object { New-AhRow @{ AssetName = "s$_"; RiskScoreTotal = $_ } })
        $cols = Get-RAColumnUnion -Rows $rows
        @($cols | Where-Object { $_ -eq 'AssetName' }).Count | Should -Be 1
        $cols.Count | Should -Be 2
    }

    It 'reproduces the loss measured in the last real run' {
        # OUTPUT/RiskAnalysis_Summary.json: 108 rows, 46 properties on row 1, 48 across the
        # pool -- AssetName and AssetType were absent from row 1 and were therefore dropped
        # from the delivered workbook. This pins the delta the fix recovers.
        # [ordered] on row 2 so the two recovered columns come back in a defined order.
        $rows = @(
            (New-AhRow ([ordered]@{ RiskScoreTotal = 1; MoreDetails = 'd' })),
            (New-AhRow ([ordered]@{ RiskScoreTotal = 2; MoreDetails = 'd'; AssetName = 'srv1'; AssetType = 'Server' }))
        )
        $cols = Get-RAColumnUnion -Rows $rows
        $firstRowOnly = @(($rows[0] | Get-Member -MemberType NoteProperty).Name)
        @($cols | Where-Object { $_ -notin $firstRowOnly }) | Should -Be @('AssetName','AssetType')
    }

    It 'survives null rows without losing the surrounding columns' {
        # The per-report array can carry nulls after a partial/failed source.
        $rows = @(
            (New-AhRow @{ AssetName = 'a' }),
            $null,
            (New-AhRow @{ AssetName = 'b'; RemediationOptions = 'x' })
        )
        { Get-RAColumnUnion -Rows $rows } | Should -Not -Throw
        (Get-RAColumnUnion -Rows $rows) | Should -Contain 'RemediationOptions'
    }

    It 'returns empty for no rows at all rather than throwing' {
        (Get-RAColumnUnion -Rows @()).Count | Should -Be 0
        (Get-RAColumnUnion -Rows $null).Count | Should -Be 0
    }

    It 'ignores non-NoteProperty members so array internals never become columns' {
        # A wrapped-array row (the v2.1.199 bug) could otherwise surface Count/Length/Rank
        # as if they were report columns.
        $rows = @( (New-AhRow @{ AssetName = 'a' }) )
        $cols = Get-RAColumnUnion -Rows $rows
        foreach ($junk in @('Count','Length','Rank','SyncRoot','IsReadOnly')) {
            $cols | Should -Not -Contain $junk
        }
    }
}

# ============================================================================
Describe 'audit #26 -- the engine actually uses the union at every discovery site' {
# ============================================================================
    # The finding named ONE site. There were three, and the second is the one that decides
    # what the operator opens: every report's rows go into a single 'Details' sheet whose
    # shape is filtered by Export-Worksheet with a strict Select-Object.

    BeforeAll {
        $script:EnginePath = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))) `
                                       'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
        $script:EngineText = Get-Content -LiteralPath $script:EnginePath -Raw
    }

    It 'no longer discovers per-report columns from row 1 alone' {
        # The exact old line. If it ever comes back, this fails.
        $script:EngineText | Should -Not -Match '\$allProps\s*=\s*\(\$firstObj\s*\|\s*Get-Member'
    }

    It 'no longer seeds the merged-sheet shape from AllShapedRows[0]' {
        $script:EngineText | Should -Not -Match '\$global:AllShapedRows\[0\]\s*\|\s*Get-Member'
    }

    It 'routes every discovery site through Get-RAColumnUnion' {
        # Two call sites: the per-report list and the final-export fallback.
        @([regex]::Matches($script:EngineText, 'Get-RAColumnUnion')).Count | Should -BeGreaterOrEqual 2
    }

    It 'unions the merged-sheet columns ACROSS reports instead of keeping the first report' {
        # Instance 2. Row-1 correctness is not enough: the workbook is filtered again by
        # $global:FinalDesiredColumns, which used to be whichever report ran first.
        $script:EngineText | Should -Match 'mergedCols'
    }

    It 'still pins the trace columns last after the cross-report union' {
        # $TraceCols are appended per report ("always the LAST four columns"); a plain union
        # would strand report 1's copies mid-sheet.
        $script:EngineText | Should -Match 'foreach \(\$t in \$TraceCols\) \{ \[void\]\$mergedCols\.Add\(\$t\) \}'
    }
}

# ============================================================================
Describe 'audit #26 part 2 -- a column worth showing is worth DECLARING' {
# ============================================================================
    # The engine fix protects undeclared columns, but a declared column is protected
    # unconditionally -- it enters $DesiredColumns whether or not any row carries it. These
    # three were declared NOWHERE, which is why remediation data went missing intermittently.
    #
    # NOTE they are declared in the SHIPPED catalog, not _source/. See audit #28: _source/ +
    # Build-RiskAnalysis.ps1 are frozen at commit 536e1405 while the catalog has been
    # hand-edited ever since, so editing _source/ changes nothing that ships.

    BeforeAll {
        $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
        if (-not (Get-Module -Name powershell-yaml)) { Import-Module powershell-yaml -Force }
        $script:CatalogPath = Join-Path $si 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
        $script:Catalog = Get-Content -Raw -LiteralPath $script:CatalogPath | ConvertFrom-Yaml
    }

    It 'every report that EMITS a remediation column also DECLARES it' {
        $cols = 'RemediationOptions','RecommendedAction','Recommendation'
        $gaps = @()
        foreach ($c in $cols) {
            foreach ($r in $script:Catalog.Reports) {
                $q = [string]$r.ReportQuery
                $emits = ($q -match ("(?m)^\s*(\|\s*)?(project|extend|project-rename|summarize)[^\r\n]*\b" + $c + "\b")) -or ($q -match ("\b$c\s*="))
                if ($emits -and ($c -notin @($r.OutputPropertyOrder))) { $gaps += "$($r.ReportName) emits '$c' without declaring it" }
            }
        }
        $gaps | Should -BeNullOrEmpty -Because ($gaps -join '; ')
    }
}

# ============================================================================
Describe 'audit #28 -- the shipped catalog must stay the shipped catalog' {
# ============================================================================
    # tests/Test-Restructure.ps1 section 7 runs Build-RiskAnalysis.ps1, which REPLACES this
    # catalog with output regenerated from the frozen _source/ tree: 264 reports instead of
    # 118, and templates renamed to *_Bucket. The launcher asks for 'RiskAnalysis_Summary'
    # and the engine THROWS on a missing template, so that swap takes every RA run down for
    # all ~30 customers. Nothing detected it before -- these are the tripwire.

    BeforeAll {
        $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
        if (-not (Get-Module -Name powershell-yaml)) { Import-Module powershell-yaml -Force }
        $script:Cat28 = Get-Content -Raw -LiteralPath (Join-Path $si 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml') | ConvertFrom-Yaml
        $script:LauncherText = Get-Content -Raw -LiteralPath (Join-Path $si 'launcher\risk-analysis\launcher.community-vm.ps1')
    }

    It 'defines every template the launcher can ask for' {
        # The actual failure mode, asserted directly rather than via a report count.
        $wanted = [regex]::Matches($script:LauncherText, "ReportTemplate_Default_\w+\s*=\s*'([^']+)'") |
                    ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
        $defined = @($script:Cat28.ReportTemplates | ForEach-Object { $_.ReportName })
        $missing = @($wanted | Where-Object { $_ -notin $defined })
        $missing | Should -BeNullOrEmpty -Because "the engine throws on a missing template; launcher wants: $($wanted -join ', '); catalog defines: $($defined -join ', ')"
    }

    It 'still carries the hand-curated template set, not the regenerated pair' {
        $defined = @($script:Cat28.ReportTemplates | ForEach-Object { $_.ReportName })
        $defined | Should -Not -Contain 'RiskAnalysis_Summary_Bucket'
        $defined | Should -Not -Contain 'RiskAnalysis_Detailed_Bucket'
    }

    It 'has not been swapped for the 264-report regenerated catalog' {
        # A blunt but effective tripwire: the regenerated catalog is 264 reports. Any large
        # jump means the consolidator ran against the tree.
        @($script:Cat28.Reports).Count | Should -BeLessThan 200
    }

    It 'keeps the Detailed reports the regenerator would delete' {
        # These are among the 57 that regeneration drops -- and two of them carry the
        # remediation columns from #26.
        $names = @($script:Cat28.Reports | ForEach-Object { $_.ReportName })
        foreach ($n in @('Device_Missing_CVEs_Detailed','Device_Recommendations_Detailed')) {
            $names | Should -Contain $n
        }
    }

    It 'no test script regenerates the catalog as a side effect' {
        # The actual mechanism of the damage: Test-Restructure.ps1 section 7 INVOKED the
        # consolidator, so merely running the "static test battery" rewrote the product's
        # report catalog. Retired 2026-08-06 on the operator's decision.
        $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
        # Matches a call-operator invocation of the retired consolidator. A COMMENT naming it
        # is fine -- that is how the history stays readable -- so this looks for the call
        # form only. This file is skipped because it necessarily contains the pattern itself.
        foreach ($t in (Get-ChildItem (Join-Path $si 'tests') -Filter '*.ps1' -File -Recurse)) {
            if ($t.FullName -eq $PSCommandPath) { continue }
            $body = Get-Content -Raw -LiteralPath $t.FullName
            $body | Should -Not -Match '&\s*\([^)]*Build-RiskAnalysis' -Because "$($t.Name) would rewrite the shipped catalog"
        }
    }

    It 'the retired consolidator and its _source tree are gone' {
        $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
        (Test-Path (Join-Path $si 'engine\risk-analysis\tools\Build-RiskAnalysis.ps1')) | Should -BeFalse
        (Test-Path (Join-Path $si 'engine\risk-analysis\_source')) | Should -BeFalse
    }
}
