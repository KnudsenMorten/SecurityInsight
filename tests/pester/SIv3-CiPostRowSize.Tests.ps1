#Requires -Version 5.1
<#
    ONE CI LARGER THAN THE LOG INGESTION LIMIT NEVER FAILS ITS BATCH (#760, support 2026-10-18: "A single record (2001077
    bytes) is larger than the 1048576-byte limit", batch 13 of 34, the asset-correlation step failed on every build).

    What these tests keep true (engine\data-model\SI-CiBuildSql.ps1 Limit-SICiPostRowSize, SI-CiBuildRun.ps1):
      * a row that fits is returned untouched;
      * a 2 MB row is cut where it is largest -- measured, not a fixed cap -- until it fits one post: the CI's id, class,
        name, tier, keys and row bookkeeping are never cut, si_truncated names each field cut and how much was kept;
      * measured as the post measures it (compressed when the post compresses: a large row that compresses under the
        limit is NOT cut);
      * the CI build trims each full row before the post and never sends the whole batch to "posted again next build" for
        one row (wiring).
    Offline: no Log Analytics.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\data-model\SI-RecordCapture.ps1')
    . (Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildSql.ps1')
    function script:New-BigRow([int]$Links = 12000) {
        $rnd = [Random]::new(7)
        $linked = New-Object object[] $Links
        for ($i = 0; $i -lt $Links; $i++) { $linked[$i] = [ordered]@{ provider = 'azure'; id = ('/subscriptions/{0}/resourceGroups/rg-{1}/providers/Microsoft.Network/networkInterfaces/nic-{2}-{3}' -f ('{0:x8}-0000-0000-0000-000000000000' -f $rnd.Next()), $i, $i, $rnd.Next()) } }
        [pscustomobject][ordered]@{ si_ci_id = 'ci-big-1'; si_class = 'azure-resource'; si_asset_name = 'vnet-hub'; si_tier = 0; si_tier_set_by = 'rule'
                                    si_linked_objects = $linked; si_tier_explanation = ('x' * 200); si_row_kind = 'full'
                                    si_content_hash = 'ABC'; si_collection_time = [datetime]'2026-10-18T19:00:00Z'; si_last_seen = [datetime]'2026-10-18T19:00:00Z' }
    }
}

Describe 'Limit-SICiPostRowSize' {
    It 'a row that fits is returned as it is' {
        $row = [pscustomobject][ordered]@{ si_ci_id = 'ci-1'; si_class = 'device'; si_linked_objects = @([ordered]@{ provider = 'mde'; id = 'm1' }) }
        $r = Limit-SICiPostRowSize -Row $row
        $r.Trimmed | Should -BeFalse
        [object]::ReferenceEquals($r.Row, $row) | Should -BeTrue
    }
    It 'a 2 MB row is cut to fit one post; identity, tier and keys are kept whole; si_truncated says what was cut' {
        $row = New-BigRow
        $before = Measure-SICiPostRowBytes -Row $row
        $before | Should -BeGreaterThan 1MB
        $r = Limit-SICiPostRowSize -Row $row
        $r.Trimmed | Should -BeTrue
        $r.Fits | Should -BeTrue
        (Measure-SICiPostRowBytes -Row $r.Row) | Should -BeLessOrEqual ([long][Math]::Floor(1MB * 0.95))
        $r.OriginalBytes | Should -Be $before
        foreach ($k in 'si_ci_id', 'si_class', 'si_asset_name', 'si_tier', 'si_tier_set_by', 'si_row_kind', 'si_content_hash', 'si_collection_time', 'si_last_seen') {
            $r.Row.$k | Should -Be $row.$k
        }
        @($r.Row.si_linked_objects).Count | Should -BeGreaterThan 0
        @($r.Row.si_linked_objects).Count | Should -BeLessThan 12000
        $r.Row.si_truncated | Should -Match 'si_linked_objects \(\d+ of 12000 items kept\)'
        $r.Row.si_truncated | Should -Match ('\({0} bytes before\)' -f $before)
        # the input row is not changed (the SQL copy keeps the whole CI)
        @($row.si_linked_objects).Count | Should -Be 12000
        $row.PSObject.Properties['si_truncated'] | Should -BeNullOrEmpty
    }
    It 'measured as the post measures it: compressed, a large row that compresses under the limit is not cut' {
        $row = [pscustomobject][ordered]@{ si_ci_id = 'ci-2'; si_class = 'device'; si_tier_explanation = ('a' * 1500000) }
        (Limit-SICiPostRowSize -Row $row -Compressed $true).Trimmed | Should -BeFalse
        (Limit-SICiPostRowSize -Row $row -Compressed $false).Trimmed | Should -BeTrue
    }
    It 'a long text is cut too, and a one-item list stays a list' {
        $row = [pscustomobject][ordered]@{ si_ci_id = 'ci-3'; si_class = 'identity'; si_unknown_fields = @('a'); si_tier_explanation = ('y' * 1200000) }
        $r = Limit-SICiPostRowSize -Row $row
        $r.Fits | Should -BeTrue
        $r.Row.si_tier_explanation.Length | Should -BeLessThan 1200000
        $r.Row.si_truncated | Should -Match 'si_tier_explanation \(\d+ of 1200000 characters kept\)'
        , $r.Row.si_unknown_fields | Should -BeOfType [System.Array]
    }
}

Describe 'the CI build trims before the post (wiring)' {
    It 'SI-CiBuildRun.ps1 measures each full row with Limit-SICiPostRowSize before posting SI_CI_CL' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\data-model\SI-CiBuildRun.ps1'))
        $iTrim = $src.IndexOf('Limit-SICiPostRowSize -Row $rw')
        $iPost = $src.IndexOf("Send-SIObjectMapRows -Rows `$rows.ToArray() -TableName 'SI_CI'")
        $iTrim | Should -BeGreaterThan 0
        $iPost | Should -BeGreaterThan $iTrim
        $src | Should -Match "si_row_kind -eq 'seen'\) \{ continue \}"
    }
}
