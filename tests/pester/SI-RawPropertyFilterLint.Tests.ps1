#Requires -Version 5.1
<#
    AUDIT #57.1(b) -- static lint: a filter must not depend on an UNHEDGED raw graph property.

    WHY. On 2026-08-10 both Azure recommendation reports silently returned zero because they
    filtered on `tostring(NodeProperties.rawData.environmentName) contains "Azure"` and Microsoft
    reshaped that property -- it is now empty on ~1.0M nodes and the literal 0 on 208, with the
    string "Azure" nowhere. Valid KQL, ~130s, exit 0, no findings. 75 -> 0 and 304 -> 0 overnight.

    🔑 THE PROOF THAT THIS RULE WORKS IS IN THE BROKEN QUERY ITSELF. The two lines directly BELOW
    the dead predicate read isCustomerFacing and isExcluded, and both hedge across paths with
    coalesce(rawData.X, raw.X). Those survived the change untouched. environmentName did not hedge,
    and it is the one that broke.

    WHAT IT ENFORCES. Any `where` predicate reading NodeProperties.rawData.* / NodeProperties.raw.*
    must either coalesce across the alternative paths, or be listed in the baseline below with a
    reason. The baseline exists so this lands as a RATCHET rather than a wall of pre-existing noise
    -- same approach as the #21 baseline in SI-PublishPayloadSanitization.Tests.ps1. NEW unhedged
    filters fail; the known ones are recorded and can be burnt down separately.
#>

BeforeAll {
    $script:SolutionRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $script:LockedYaml   = Join-Path $script:SolutionRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml'

    # Known unhedged raw-property filters as of v2.2.419, by the property they read.
    # Each is a live silent-zero risk of exactly the #57 shape. Burn this list DOWN, never up.
    # 🎯 BASELINE IS ZERO as of v2.2.420 -- all 8 were hedged with coalesce across
    # rawData.X / raw.X / X. The ratchet is now fully closed: ANY unhedged raw-property filter
    # fails this test.
    #
    # History, kept because it is the argument for the rule. The list was first counted BY HAND at
    # 6 and was wrong in both directions -- it counted a ReportPurpose SENTENCE as a filter, and
    # missed the two graph-match `and Device...` continuation lines, which gate rows exactly as
    # `| where` does. The lint said 8. Count with the detector, never by eye.
    #   deviceCategory                                  x4  (Device_Missing_CVEs + Device_Recommendations, Summary+Detailed)
    #   highRiskVulnerabilityInsights.hasHighOrCritical x4  (device attack-path pair: 2x `| where` + 2x graph-match `and`)
    #
    # ⚠️ Do not re-add entries here to make a red run green. The correct fix is a coalesce hedge,
    # or better, a structural identifier (NodeLabel / NodeId) that is schema rather than payload.
    $script:BaselineUnhedged = @{}

    function Get-UnhedgedRawFilters {
        param([Parameter(Mandatory=$true)][string]$Path)
        $found = New-Object System.Collections.Generic.List[object]
        $lines = [System.IO.File]::ReadAllLines($Path)
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            # Must LOOK like a KQL predicate line, not YAML prose. A first cut keyed only on the
            # word "where" flagged a ReportPurpose sentence ("...endpoints where Microsoft Exposure
            # Mgmt has flagged...NodeProperties.rawData.isCompromisedRecently"), which is
            # documentation, not a filter. Require the line to OPEN with a pipe or a boolean
            # continuation -- that is what a real predicate looks like, in both `| where` form and
            # the `and`/`or` continuation lines of a graph-match where-clause.
            if ($line -notmatch '^\s*(\||and\b|or\b|where\b)')     { continue }
            if ($line -match '^\s*//')                             { continue }   # commented-out KQL
            if ($line -notmatch '\b(where|and|or)\b')              { continue }
            if ($line -notmatch 'NodeProperties\.(rawData|raw)\.') { continue }
            if ($line -match 'coalesce\s*\(')                      { continue }   # hedged -> fine
            # extend/project/summarize SURFACE a property; they do not gate rows, so they cannot
            # silently zero a report on their own.
            if ($line -match '^\s*\|\s*(extend|project|summarize|mv-expand)\b') { continue }
            $m = [regex]::Match($line, 'NodeProperties\.(?:rawData|raw)\.([A-Za-z0-9_.]+)')
            $prop = if ($m.Success) { $m.Groups[1].Value.TrimEnd('.') } else { '<unparsed>' }
            [void]$found.Add(@{ Line = $i + 1; Property = $prop; Text = $line.Trim() })
        }
        return @($found.ToArray())
    }
}

Describe 'raw graph-property filters must be hedged -- audit #57.1(b)' {

    It 'the locked catalog is present and non-empty (control -- green must not mean "scanned nothing")' {
        Test-Path -LiteralPath $script:LockedYaml | Should -BeTrue
        (Get-Item -LiteralPath $script:LockedYaml).Length | Should -BeGreaterThan 100000
    }

    It 'the detector actually fires on the #57 pattern (control -- a rule that matches nothing protects nothing)' {
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("si-lint-{0}.yaml" -f ([guid]::NewGuid().ToString('N')))
        @(
            '        | where tostring(NodeProperties.rawData.environmentName) contains "Azure"',
            '        | where isnull(coalesce(NodeProperties.rawData.isExcluded, NodeProperties.raw.isExcluded))'
        ) | Set-Content -LiteralPath $tmp -Encoding UTF8
        try {
            $hits = @(Get-UnhedgedRawFilters -Path $tmp)
            $hits.Count            | Should -Be 1 -Because 'the hedged line must NOT be flagged'
            $hits[0].Property      | Should -Be 'environmentName'
        } finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }

    It 'introduces NO new unhedged raw-property filter beyond the recorded baseline' {
        $hits = @(Get-UnhedgedRawFilters -Path $script:LockedYaml)
        $byProp = @{}
        foreach ($h in $hits) {
            if (-not $byProp.ContainsKey($h.Property)) { $byProp[$h.Property] = 0 }
            $byProp[$h.Property]++
        }

        $new = @()
        foreach ($p in $byProp.Keys) {
            $allowed = 0
            if ($script:BaselineUnhedged.ContainsKey($p)) { $allowed = [int]$script:BaselineUnhedged[$p] }
            if ($byProp[$p] -gt $allowed) {
                $new += ("{0} (found {1}, baseline {2})" -f $p, $byProp[$p], $allowed)
            }
        }

        $new.Count | Should -Be 0 -Because (
            "these filters depend on a raw graph property with no fallback, which is exactly how #57 " +
            "silently zeroed both Azure recommendation reports: " + ($new -join '; ') +
            ". Hedge with coalesce(rawData.X, raw.X, X), or prefer a structural identifier such as " +
            "NodeLabel, or add it to BaselineUnhedged with a reason.")
    }

    It 'reports the outstanding baseline so it stays visible rather than forgotten (informational)' {
        $hits  = @(Get-UnhedgedRawFilters -Path $script:LockedYaml)
        $total = ($script:BaselineUnhedged.Values | Measure-Object -Sum).Sum
        Write-Host ("  #57.1(b) baseline: {0} unhedged raw-property filter(s) still outstanding across {1} propert(ies)." -f $total, $script:BaselineUnhedged.Count)
        foreach ($h in $hits) { Write-Host ("    line {0}: {1}" -f $h.Line, $h.Property) }
        $hits.Count | Should -BeLessOrEqual $total -Because 'the baseline must shrink, never grow'
    }
}
