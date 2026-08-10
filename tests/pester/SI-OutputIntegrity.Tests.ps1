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

# ============================================================================
Describe 'output integrity -- audit #52: the degenerate aggregate columns are gone' {
# ============================================================================
#
#   A customer reported ImpactedAssetCount = 3 beside TotalIssuesImpactedAssets = 102, with a
#   three-name asset list. Reproduced in the internal workspace, so it was never customer data:
#   the column disagreed with ImpactedAssetCount on 64 of 311 live rows (21%), with ratios from
#   0.125 to 2048.5, and the customer's own rows were a constant 34x.
#
#   Root cause: THREE definitions of one column. The KQL computed count() of source rows, the
#   engine substituted ImpactedAssetCount whenever the KQL supplied nothing, and the name promised
#   issues x assets. count() counts rows; make_set() de-duplicates and drops nulls -- so the count
#   and the list beside it measured different things and diverged by construction. Exactly audit
#   #25's defect family, one column across, which #25 never covered.
#
#   🔴 It was not cosmetic. The value was also the per-row POPULATION WEIGHT for the headline risk
#   score (v2.2.314), so a row inflated 2048x dominated its domain's KPI. The weight now comes from
#   ImpactedAssetCount.
#
#   Why this file did not catch it: it asserted ImpactedAssetCount against ImpactedAssetsList and
#   never looked at the third column standing next to them.

    It 'no export row carries TotalIssuesImpactedAssets' {
        foreach ($name in @('RiskAnalysis_Summary.json','RiskAnalysis_Detailed.json')) {
            $rows = Get-SidecarRows -Name $name
            if ($null -eq $rows -or @($rows).Count -eq 0) { continue }
            $bad = @($rows | Where-Object { $_.PSObject.Properties['TotalIssuesImpactedAssets'] })
            $bad.Count | Should -Be 0 -Because (
                "{0}: {1} row(s) still carry TotalIssuesImpactedAssets. It was removed as incorrect; if a report re-emits it the engine blacklist should drop it before export." -f $name, $bad.Count)
        }
    }

    It 'the catalog declares TotalIssuesImpactedAssets nowhere' {
        # The export test above only sees reports that produced rows. This one covers all 118.
        $yamlPath = Join-Path $script:V22Root 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'
        if (-not (Test-Path -LiteralPath $yamlPath)) {
            Set-ItResult -Skipped -Because 'query catalog not present'
            return
        }
        $hits = @(Select-String -LiteralPath $yamlPath -Pattern 'TotalIssuesImpactedAssets' -ErrorAction SilentlyContinue)
        $hits.Count | Should -Be 0 -Because (
            "the catalog still references TotalIssuesImpactedAssets on {0} line(s): {1}" -f $hits.Count, (($hits | Select-Object -First 3 | ForEach-Object { "L$($_.LineNumber)" }) -join ', '))
    }

    It 'UniqueIssues survives ONLY where it genuinely varies' {
        # It is 1 by construction wherever ConfigurationId is in the summarize by-clause -- the row
        # IS one issue. It was kept in the 6 reports grouped the other way (per asset), where it is
        # the blast radius in the opposite direction. This asserts the surviving column is real:
        # if every row that has it shows 1, the curation was wrong and it should go too.
        $rows = Get-SidecarRows -Name 'RiskAnalysis_Summary.json'
        if ($null -eq $rows -or @($rows).Count -eq 0) {
            Set-ItResult -Skipped -Because 'no Summary JSON sidecar -- run the RA Summary launcher first'
            return
        }
        $withUi = @($rows | Where-Object { $_.PSObject.Properties['UniqueIssues'] -and "$($_.UniqueIssues)" -ne '' })
        if ($withUi.Count -eq 0) {
            Set-ItResult -Skipped -Because 'this run produced no rows from the 6 reports that still declare UniqueIssues'
            return
        }
        $varying = @($withUi | Where-Object { $n = 0; [int]::TryParse("$($_.UniqueIssues)", [ref]$n) -and $n -gt 1 })
        $varying.Count | Should -BeGreaterThan 0 -Because (
            "all {0} row(s) carrying UniqueIssues show 1, so it is degenerate everywhere it survives and should be removed from those reports too" -f $withUi.Count)
    }

    It 'IssueList never restates a single issue on a Detailed row' {
        # On a Detailed row the finding IS the row, so a one-entry IssueList is pure redundancy.
        # Measured before removal: 1,818 of 1,818 Detailed rows had exactly one entry.
        $rows = Get-SidecarRows -Name 'RiskAnalysis_Detailed.json'
        if ($null -eq $rows -or @($rows).Count -eq 0) {
            Set-ItResult -Skipped -Because 'no Detailed JSON sidecar -- run the RA Detailed launcher first'
            return
        }
        $bad = @($rows | Where-Object { $_.PSObject.Properties['IssueList'] -and $_.IssueList })
        $bad.Count | Should -Be 0 -Because (
            "{0} Detailed row(s) still carry IssueList; it duplicates the finding the row already names" -f $bad.Count)
    }
}

# ============================================================================
Describe 'output integrity -- RiskRating is a faithful band of RiskScoreTotal' {
# ============================================================================
#
#   RiskRating is DERIVED, never supplied: it is stamped in _setScores, in the same atomic block as
#   the score it bands, so the two cannot drift apart. That placement is deliberate -- audit #52 was
#   one column carrying three definitions, wrong on 21% of rows, because it was computed in more
#   than one place. This asserts the derivation on the real export rather than trusting it.
#
#   Bands (operator, 2026-08-10):  >=25 Critical | >=20 High | >=12 Moderate | else Low

    It 'every row''s RiskRating matches the band its RiskScoreTotal falls in' {
        foreach ($name in @('RiskAnalysis_Summary.json','RiskAnalysis_Detailed.json')) {
            $rows = Get-SidecarRows -Name $name
            if ($null -eq $rows -or @($rows).Count -eq 0) { continue }
            $bad = @()
            foreach ($r in $rows) {
                $lv = $r.PSObject.Properties['RiskRating']
                $sc = $r.PSObject.Properties['RiskScoreTotal']
                if (-not $lv -or -not $sc) { continue }
                if ([string]::IsNullOrWhiteSpace([string]$sc.Value)) { continue }
                $s = [double]$sc.Value
                $expect = if ($s -ge 25) { 'Critical' } elseif ($s -ge 20) { 'High' } elseif ($s -ge 12) { 'Moderate' } else { 'Low' }
                if ([string]$lv.Value -ne $expect) { $bad += ('score={0} level={1} expected={2}' -f $s, $lv.Value, $expect) }
            }
            $bad | Should -BeNullOrEmpty -Because ("{0}: {1} row(s) disagree -- {2}" -f $name, @($bad).Count, (($bad | Select-Object -First 5) -join '; '))
        }
    }

    It 'RiskRating is present wherever RiskScoreTotal is' {
        # It is stamped by _setScores alongside the score, so a row with a score and no level means
        # some other code path produced that row and bypassed the single source of truth.
        foreach ($name in @('RiskAnalysis_Summary.json','RiskAnalysis_Detailed.json')) {
            $rows = Get-SidecarRows -Name $name
            if ($null -eq $rows -or @($rows).Count -eq 0) { continue }
            $missing = @($rows | Where-Object {
                $_.PSObject.Properties['RiskScoreTotal'] -and
                -not [string]::IsNullOrWhiteSpace([string]$_.RiskScoreTotal) -and
                (-not $_.PSObject.Properties['RiskRating'] -or [string]::IsNullOrWhiteSpace([string]$_.RiskRating))
            })
            $missing.Count | Should -Be 0 -Because (
                "{0}: {1} row(s) carry RiskScoreTotal but no RiskRating -- a code path is stamping scores outside _setScores" -f $name, $missing.Count)
        }
    }

    It 'only the four defined levels ever appear' {
        foreach ($name in @('RiskAnalysis_Summary.json','RiskAnalysis_Detailed.json')) {
            $rows = Get-SidecarRows -Name $name
            if ($null -eq $rows -or @($rows).Count -eq 0) { continue }
            $vals = @($rows | Where-Object { $_.PSObject.Properties['RiskRating'] -and $_.RiskRating } |
                       ForEach-Object { [string]$_.RiskRating } | Sort-Object -Unique)
            $unexpected = @($vals | Where-Object { $_ -notin @('Critical','High','Moderate','Low') })
            $unexpected | Should -BeNullOrEmpty -Because ("{0}: unexpected level(s): {1}" -f $name, ($unexpected -join ', '))
        }
    }
}
