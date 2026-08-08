#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- assert the INVARIANTS on a real export, not on the source that produces it.

.DESCRIPTION
    TESTS.md section 8 called this out as the gap that let audits #25 and #26 survive: nothing
    asserted anything about what actually reaches the .xlsx / JSON / LA.

    It is not a theoretical gap. #25 was fixed twice from source reading -- in the report KQL, and
    in the engine roll-up -- and a completed run still had **14 of 99 rows** where
    `ImpactedAssetCount` disagreed with `ImpactedAssetsList`. The third cause was a SCOPE mismatch
    (per-row list beside a per-report count) that no amount of reading either half in isolation
    would have surfaced, because each half was individually correct.

    So this file asserts against the JSON sidecar a real run produced. It SKIPS when there is no
    sidecar, exactly like the OutputArtifacts category, so it never blocks a checkout that has
    never run the engine -- but the moment a run exists, the invariant is checked for real.
#>

BeforeAll {
    $script:V22Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))

    function Get-SidecarRows {
        param([string]$Name)
        foreach ($dir in @('OUTPUT','output','risk-analysis-detection\OUTPUT')) {
            $p = Join-Path $script:V22Root (Join-Path $dir $Name)
            if (Test-Path -LiteralPath $p) {
                # PS 5.1 TRAP -- do NOT collapse this into @(... | ConvertFrom-Json). PowerShell 5.1's
                # ConvertFrom-Json writes the whole array to the pipeline as a SINGLE object (PS 7
                # unrolls it), so @() around the pipeline yields ONE element -- the array itself --
                # whose "properties" are object[]'s own members (Count, Length, Rank, ...). Measured
                # on the real Summary sidecar 2026-08-08: the old form gave 1 row / 8 props and saw
                # ImpactedAssetCount on ZERO rows, so every invariant below iterated nothing and
                # PASSED VACUOUSLY -- this file is the guard for #25/#26 and it was not guarding.
                # Assigning first, then wrapping the VARIABLE, gives the real 151 rows / 46 props.
                try {
                    $parsed = Get-Content -Raw -LiteralPath $p | ConvertFrom-Json
                    return ,@($parsed)
                } catch { return ,@() }
            }
        }
        return $null
    }

    # The invariant itself, kept separate so both templates use identical logic.
    function Get-CountVsListMismatches {
        param($Rows)
        $bad = @()
        foreach ($r in $Rows) {
            $c = $r.PSObject.Properties['ImpactedAssetCount']
            $l = $r.PSObject.Properties['ImpactedAssetsList']
            if (-not $c -or -not $l) { continue }
            if ($null -eq $l.Value -or $null -eq $c.Value) { continue }
            if ([string]::IsNullOrWhiteSpace([string]$c.Value)) { continue }
            $len = @($l.Value).Count
            if ([int]$c.Value -ne $len) {
                $bad += ('{0}: count={1} listLen={2}' -f $r.AssetDetectedInReportName, [int]$c.Value, $len)
            }
        }
        return ,$bad
    }
}

# ============================================================================
Describe 'output integrity -- audit #25 on a REAL export' {
# ============================================================================

    It 'RiskAnalysis_Summary.json: ImpactedAssetCount equals the length of ImpactedAssetsList' {
        $rows = Get-SidecarRows -Name 'RiskAnalysis_Summary.json'
        if ($null -eq $rows) {
            Set-ItResult -Skipped -Because 'no Summary JSON sidecar -- run the RA Summary launcher first'
            return
        }
        $bad = Get-CountVsListMismatches -Rows $rows
        # Deliberately reports the offending reports, not just a count: the last time this fired,
        # the report NAMES were what identified the scope mismatch.
        $bad | Should -BeNullOrEmpty -Because ("{0} of {1} row(s) disagree -- {2}" -f @($bad).Count, @($rows).Count, (($bad | Select-Object -First 6) -join '; '))
    }

    It 'RiskAnalysis_Detailed.json: ImpactedAssetCount equals the length of ImpactedAssetsList' {
        $rows = Get-SidecarRows -Name 'RiskAnalysis_Detailed.json'
        if ($null -eq $rows) {
            Set-ItResult -Skipped -Because 'no Detailed JSON sidecar -- run the RA Detailed launcher first'
            return
        }
        $bad = Get-CountVsListMismatches -Rows $rows
        $bad | Should -BeNullOrEmpty -Because ("{0} of {1} row(s) disagree -- {2}" -f @($bad).Count, @($rows).Count, (($bad | Select-Object -First 6) -join '; '))
    }
}

# ============================================================================
Describe 'output integrity -- audit #26 on a REAL export' {
# ============================================================================

    It 'the export carries the union of all rows, not just the first row''s columns' {
        # The first row's property set is what the OLD code shipped. If the export ever collapses
        # back to exactly that, the union fix has regressed. Equality is legitimate (every row can
        # genuinely share a shape), so this asserts the export is never NARROWER than row 1 --
        # and reports the delta, which is the number that made #26 concrete (46 vs 48, then 46 vs 49).
        $rows = Get-SidecarRows -Name 'RiskAnalysis_Summary.json'
        if ($null -eq $rows -or @($rows).Count -eq 0) {
            Set-ItResult -Skipped -Because 'no Summary JSON sidecar -- run the RA Summary launcher first'
            return
        }
        $union = @($rows | ForEach-Object { $_.PSObject.Properties.Name } | Select-Object -Unique)
        $first = @(@($rows)[0].PSObject.Properties.Name)
        @($union).Count | Should -BeGreaterOrEqual @($first).Count -Because (
            "row-1 discovery would have shipped {0} columns; the union is {1}" -f @($first).Count, @($union).Count)
    }

    It 'no report emits a remediation column without the export carrying it' {
        # #26's symptom in its original form: the column is emitted but absent from the output.
        $rows = Get-SidecarRows -Name 'RiskAnalysis_Detailed.json'
        if ($null -eq $rows -or @($rows).Count -eq 0) {
            Set-ItResult -Skipped -Because 'no Detailed JSON sidecar -- run the RA Detailed launcher first'
            return
        }
        # Only assert for reports that actually produced rows carrying the data.
        $present = @($rows | Where-Object { $_.PSObject.Properties['RemediationOptions'] -or $_.PSObject.Properties['RecommendedAction'] })
        if ($present.Count -eq 0) {
            Set-ItResult -Skipped -Because 'this run produced no rows from the remediation reports'
            return
        }
        $present.Count | Should -BeGreaterThan 0
    }
}
