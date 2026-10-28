#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- AUDIT #48. The DCR schema sample must cover EVERY column the run produces.

.DESCRIPTION
    CheckCreateUpdate-TableDcr-Structure declares the Log Analytics table + DCR columns from the
    UNION of the property names across whatever `-Data` it is handed. Anything absent from that
    sample is never declared, and Build-DataArrayToAlignWithSchema then drops it at ingest --
    silently. The rows post, the run logs SUCCESS, and the column simply does not exist in the
    table. There is no error anywhere in that path, which is why it survived undetected.

    Measured on the 2026-08-08 Detailed export before the fix:
      2,216 rows / 151 columns produced, but the sample was `Select-Object -First 100`
      -> 69 columns, and the live DCR declared exactly those 69. 82 columns dropped.
      57 of them held REAL data -- RecommendedAction / RemediationOptions first appear on
      row 596, the whole attack-path block on row 2215 of 2216.

    Same defect family as #26, which fixed positional column discovery in the EXPORT and left the
    INGEST path untouched. #26 has its own test (SI-OutputColumnUnion.Tests.ps1); this is the
    ingest-side twin, and the pair should be kept together.

    Two layers here, deliberately:
      1. UNIT -- the sampler's contract, including the return-shape trap that a first version of
         this fix actually hit (see "return shape" context below).
      2. REAL EXPORT -- run the sampler over the JSON sidecar an actual run produced and assert
         100% column coverage. Skips when no sidecar exists, exactly like SI-OutputIntegrity, so a
         fresh checkout that has never run the engine is never blocked.
#>

BeforeAll {
    $script:V22Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:V22Root 'engine\risk-analysis\_shared\RA-RowShaping.ps1')

    function New-Row {
        param([hashtable]$Props)
        [pscustomobject]$Props
    }

    # Union of property names across a row set -- the same thing the module computes internally.
    function Get-UnionColumns {
        param($Rows)
        @(@($Rows) | ForEach-Object { $_.PSObject.Properties.Name } | Sort-Object -Unique)
    }

    function Get-SidecarRows {
        param([string]$Name)
        foreach ($dir in @('OUTPUT','output')) {
            $p = Join-Path $script:V22Root (Join-Path $dir $Name)
            if (Test-Path -LiteralPath $p) {
                # PS 5.1 TRAP -- see the same note in SI-OutputIntegrity.Tests.ps1. ConvertFrom-Json
                # emits the array as ONE pipeline object on 5.1 (7 unrolls), so @(pipeline) yields a
                # single element whose properties are object[]'s own members. Assign, then wrap.
                try {
                    $parsed = Get-Content -Raw -LiteralPath $p | ConvertFrom-Json
                    return ,@($parsed)
                } catch { return ,@() }
            }
        }
        return $null
    }
}

Describe 'AUDIT #48 -- Get-RASchemaCoverageSample contract' {

    It 'covers a column that appears ONLY on the last row -- the exact shape of the bug' {
        # AttackPath first appeared on row 2215 of 2216 in the real export.
        $rows = @(1..250 | ForEach-Object { New-Row @{ A = 1; B = 2 } })
        $rows += New-Row @{ A = 1; B = 2; RareLateColumn = 'x' }

        $old = @($rows | Select-Object -First 100)
        (Get-UnionColumns $old) | Should -Not -Contain 'RareLateColumn'   # the old behaviour

        $new = @(Get-RASchemaCoverageSample -Rows $rows -BaseCount 100)
        (Get-UnionColumns $new) | Should -Contain 'RareLateColumn'
    }

    It 'is a strict SUPERSET of the old first-N sample -- it can never declare FEWER columns' {
        $rows = @(1..40 | ForEach-Object { New-Row @{ A = 1; B = 2 } })
        $rows += New-Row @{ C = 3 }
        $old = Get-UnionColumns (@($rows | Select-Object -First 100))
        $new = Get-UnionColumns (@(Get-RASchemaCoverageSample -Rows $rows -BaseCount 100))
        foreach ($c in $old) { $new | Should -Contain $c }
    }

    It 'keeps only rows that INTRODUCE a column -- it does not return the whole set' {
        # 5,000 identical rows plus one wide row must not produce a 5,001-row sample.
        $rows = @(1..5000 | ForEach-Object { New-Row @{ A = 1 } })
        $rows += New-Row @{ A = 1; Z = 9 }
        $s = @(Get-RASchemaCoverageSample -Rows $rows -BaseCount 100)
        $s.Count | Should -Be 101
        (Get-UnionColumns $s) | Should -Contain 'Z'
    }

    It 'respects MaxRows so a pathological row set cannot make the sample unbounded' {
        # Every row introduces a new column; without the cap this would return all 400.
        $rows = @(1..400 | ForEach-Object { New-Row @{ ('Col{0}' -f $_) = 1 } })
        $s = @(Get-RASchemaCoverageSample -Rows $rows -BaseCount 10 -MaxRows 50)
        $s.Count | Should -BeLessOrEqual 50
    }

    # RETURN SHAPE. The first version of this fix returned `,($sample.ToArray())`, which emitted the
    # array as ONE pipeline object; the caller's @() then yielded a single element whose "columns"
    # were object[]'s own members -- 1 row, 8 columns, and a DCR that would have been declared from
    # Count/Length/Rank. The offline test caught it before it ran anywhere. These assertions exist so
    # it cannot come back.
    It 'unrolls so the caller''s @() re-collects the rows (return-shape regression)' {
        $rows = @(1..5 | ForEach-Object { New-Row @{ A = $_ } })
        $s = @(Get-RASchemaCoverageSample -Rows $rows -BaseCount 100)
        $s.Count | Should -Be 5
        $s[0].PSObject.Properties.Name | Should -Contain 'A'
        (Get-UnionColumns $s) | Should -Not -Contain 'Length'
    }

    It 'returns an empty set for empty input, and one row for a single row' {
        (@(Get-RASchemaCoverageSample -Rows @())).Count | Should -Be 0
        (@(Get-RASchemaCoverageSample -Rows @((New-Row @{ A = 1 })))).Count | Should -Be 1
    }

    It 'skips nulls without losing the real rows' {
        $s = @(Get-RASchemaCoverageSample -Rows @($null, (New-Row @{ A = 1 }), $null))
        $s.Count | Should -Be 1
    }

    It 'picks REAL rows, never a synthesised wide row of empty strings (type inference depends on it)' {
        # The module infers column TYPES from the sampled values. A synthetic row of ''s would
        # declare numeric columns as string.
        $rows = @((New-Row @{ A = 'text' }), (New-Row @{ A = 'text'; Score = 42 }))
        $s = @(Get-RASchemaCoverageSample -Rows $rows -BaseCount 1)
        $withScore = $s | Where-Object { $_.PSObject.Properties['Score'] } | Select-Object -First 1
        $withScore | Should -Not -BeNullOrEmpty
        $withScore.Score | Should -BeOfType [int]
    }
}

Describe 'AUDIT #48 -- schema coverage on a REAL export' {

    It 'covers 100% of the columns in the Detailed sidecar (skips when no run has happened)' {
        $rows = Get-SidecarRows 'RiskAnalysis_Detailed.json'
        if ($null -eq $rows -or $rows.Count -eq 0) {
            Set-ItResult -Skipped -Because 'no RiskAnalysis_Detailed.json sidecar -- engine has not run in this checkout'
            return
        }
        $union  = Get-UnionColumns $rows
        $sample = @(Get-RASchemaCoverageSample -Rows $rows -BaseCount 100)
        $missing = @($union | Where-Object { $_ -notin (Get-UnionColumns $sample) })
        $missing | Should -BeNullOrEmpty -Because ("every produced column must be declarable; missing: {0}" -f ($missing -join ', '))
    }

    It 'covers 100% of the columns in the Summary sidecar (skips when no run has happened)' {
        $rows = Get-SidecarRows 'RiskAnalysis_Summary.json'
        if ($null -eq $rows -or $rows.Count -eq 0) {
            Set-ItResult -Skipped -Because 'no RiskAnalysis_Summary.json sidecar -- engine has not run in this checkout'
            return
        }
        $union  = Get-UnionColumns $rows
        $sample = @(Get-RASchemaCoverageSample -Rows $rows -BaseCount 100)
        $missing = @($union | Where-Object { $_ -notin (Get-UnionColumns $sample) })
        $missing | Should -BeNullOrEmpty -Because ("every produced column must be declarable; missing: {0}" -f ($missing -join ', '))
    }

    It 'NEGATIVE -- the old first-100 sample would still FAIL on the real Detailed export' {
        # Guards the test itself: if this ever passes, the export shrank and the test above stopped
        # proving anything.
        $rows = Get-SidecarRows 'RiskAnalysis_Detailed.json'
        if ($null -eq $rows -or $rows.Count -lt 200) {
            Set-ItResult -Skipped -Because 'need a real multi-hundred-row Detailed export to prove the old sample was insufficient'
            return
        }
        $union = Get-UnionColumns $rows
        $old   = Get-UnionColumns (@($rows | Select-Object -First 100))
        @($union | Where-Object { $_ -notin $old }).Count |
            Should -BeGreaterThan 0 -Because 'the positional sample must be demonstrably lossy on this data, or this suite proves nothing'
    }
}
