#Requires -Version 5.1
<#
    A WEEK WITH ONE SNAPSHOT CANNOT SHOW CHANGE -- AND MUST NOT BE PUBLISHED AS A QUIET WEEK (#135).

    With a single run in a week, its first and last snapshot are the same run: the set difference is
    trivially empty. The KQL already returns null opened/closed for that (Comparable needs Snapshots > 1),
    but Invoke-SITrend turned the null into 0 and New-SITrendWeeklyRows gated only on ComparedAssets > 0,
    so "0 opened, 0 closed" was stored as a MEASURED week -- and history keeps it for a year. Separately,
    `[datetime]$r.Week` converted the UTC week start to local time, shifting the week key a day on any host
    west of UTC.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\asset-trend\_shared\SI-TrendRollup.ps1')
    function script:Dims($rows) { @($rows | ForEach-Object { $_.Dimension }) }
}

Describe 'opened/closed need two snapshots' {
    It 'ONE snapshot: the denominators are written, the counts are NOT (they used to be a measured 0/0)' {
        $rows = @(New-SITrendWeeklyRows -CollectionTime ([datetime]'2026-09-28') -RunId 'r' `
                    -Week ([datetime]'2026-09-21') -HasData $true -Snapshots 1 `
                    -Opened 0 -Closed 0 -ComparedAssets 40 -ObservedAssets 40)
        $d = Dims $rows
        $d | Should -Contain 'weekly-compared-assets'
        $d | Should -Not -Contain 'weekly-opened'
        $d | Should -Not -Contain 'weekly-closed'
    }
    It 'TWO snapshots: the counts are written' {
        $rows = @(New-SITrendWeeklyRows -CollectionTime ([datetime]'2026-09-28') -RunId 'r' `
                    -Week ([datetime]'2026-09-21') -HasData $true -Snapshots 2 `
                    -Opened 3 -Closed 1 -ComparedAssets 40 -ObservedAssets 41)
        $d = Dims $rows
        $d | Should -Contain 'weekly-opened'
        $d | Should -Contain 'weekly-closed'
    }
}

Describe 'the week key is the UTC week start' {
    It 'a UTC week start keeps its date in the key' {
        $wk = [datetime]::new(2026, 9, 21, 0, 0, 0, [DateTimeKind]::Utc)
        $rows = @(New-SITrendWeeklyRows -CollectionTime ([datetime]'2026-09-28') -RunId 'r' -Week $wk -HasData $false -Snapshots 0)
        $rows[0].DimensionValue | Should -Be '2026-09-21'
    }
    It 'Invoke-SITrend parses the week as UTC, not local' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\asset-trend\Invoke-SITrend.ps1') -Raw
        $src | Should -Match '-Week \$weekUtc'
        $src | Should -Match 'AdjustToUniversal'
        $src | Should -Not -Match '-Week \(\[datetime\]\$r\.Week\)'
    }
}
