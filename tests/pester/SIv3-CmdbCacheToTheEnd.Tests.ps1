#Requires -Version 5.1
<#
    #891 part 3 (sweep A-3, owner 2026-10-22): THE CMDB CACHE IS READ TO THE END, OR IT IS INCOMPLETE.

    What these tests keep true:
      * Read-SICmdbTablePages follows the continuation to the LAST page -- no 100-page (100,000-row) stop; at 500,000 CIs
        the old reader dropped about 80 % of the cache without a word;
      * every page goes through the shared storage helper (Invoke-SIStorageRequest, its retry), with the continuation
        tokens on the next request;
      * a page that still fails is a NAMED error (table, page, rows read) -- never a shorter list;
      * Get-SICmdbCIs / Get-SICmdbServices mark the cache INCOMPLETE on a failed read (a named warning), and the
        dependents (the profilers' reconcile, the CI build) treat it as incomplete, never as complete with fewer rows.
    Offline: the storage service is a fake.
#>

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-AzRest.ps1')
    . (Join-Path $script:Root 'engine\asset-profiling\storage\CmdbCache.ps1')
    $script:Ctx = [pscustomobject]@{ AccountName = 'stsi'; Mode = 'OAuth' }
    # a fake table service: -Pages pages of -PerPage entities, continuation tokens between them; -FailOn = the page that fails
    function script:New-FakeTable([int]$Pages, [int]$PerPage = 10, [int]$FailOn = 0) {
        $seen = New-Object System.Collections.ArrayList
        $sb = {
            param([string]$Uri)
            [void]$seen.Add($Uri)
            $i = 1; if ($Uri -match 'NextPartitionKey=p(\d+)') { $i = [int]$Matches[1] }
            if ($FailOn -and $i -eq $FailOn) { throw 'The operation has timed out.' }
            $rows = @(1..$PerPage | ForEach-Object { [ordered]@{ PartitionKey = ('p{0}' -f $i); RowKey = ('r{0}-{1}' -f $i, $_); name = ('ci-{0}-{1}' -f $i, $_) } })
            $h = New-Object 'System.Collections.Hashtable' ([System.StringComparer]::OrdinalIgnoreCase)
            if ($i -lt $Pages) { $h['x-ms-continuation-NextPartitionKey'] = ('p{0}' -f ($i + 1)); $h['x-ms-continuation-NextRowKey'] = ('r{0}-1' -f ($i + 1)) }
            [pscustomobject]@{ Content = (ConvertTo-Json -InputObject @{ value = $rows } -Depth 4 -Compress); Headers = $h }
        }.GetNewClosure()
        [pscustomobject]@{ Request = $sb; Seen = $seen }
    }
}

Describe 'READ TO THE END -- no page limit' {
    It '250 pages (well past the old 100-page stop) are all read, in order, each with the previous page''s continuation' {
        $t = New-FakeTable -Pages 250 -PerPage 10
        $got = New-Object System.Collections.Generic.List[object]
        $n = Read-SICmdbTablePages -Context $script:Ctx -Table 'sicmdbcis' -OnPage { param($p) foreach ($e in $p) { $got.Add($e) } } -Request $t.Request
        $n | Should -Be 2500
        $got.Count | Should -Be 2500
        $t.Seen.Count | Should -Be 250
        $t.Seen[0] | Should -Be 'https://stsi.table.core.windows.net/sicmdbcis()'
        $t.Seen[249] | Should -Match 'NextPartitionKey=p250&NextRowKey=r250-1$'
        $got[2499].name | Should -Be 'ci-250-10'
    }
    It 'Get-SICmdbTableEntities returns every row, not the first 100 pages' {
        $t = New-FakeTable -Pages 120 -PerPage 5
        @(Get-SICmdbTableEntities -Context $script:Ctx -Table 'sicmdbcis' -Request $t.Request).Count | Should -Be 600
    }
    It 'the partition filter is on every page' {
        $t = New-FakeTable -Pages 3
        $null = Read-SICmdbTablePages -Context $script:Ctx -Table 'sicmdbservices' -PartitionKey 'service' -OnPage { param($p) } -Request $t.Request
        @($t.Seen | Where-Object { $_ -match '\$filter=PartitionKey%20eq%20''service''' }).Count | Should -Be 3
    }
    It 'a missing table (404 on the first page) is an empty one' {
        Read-SICmdbTablePages -Context $script:Ctx -Table 'sicmdbcis' -OnPage { param($p) throw 'no page expected' } -Request { param($u) $null } | Should -Be 0
    }
    It 'the source has no page cap left' {
        $src = Get-Content -Raw (Join-Path $script:Root 'engine\asset-profiling\storage\CmdbCache.ps1')
        $src | Should -Not -Match '\$pages -lt 100'
        $src | Should -Not -Match 'Invoke-WebRequest -Method GET'
    }
}

Describe 'THE SHARED STORAGE HELPER -- its retry' {
    It 'the default request goes through Invoke-SIStorageRequest (table service, 404 allowed, JSON without metadata)' {
        $script:Calls = 0
        Mock Invoke-SIStorageRequest {
            $script:Calls++
            $h = @{}; if ($script:Calls -lt 3) { $h['x-ms-continuation-NextPartitionKey'] = ('p{0}' -f ($script:Calls + 1)) }
            [pscustomobject]@{ Content = '{"value":[{"RowKey":"x"}]}'; Headers = $h }
        }
        Read-SICmdbTablePages -Context $script:Ctx -Table 'sicmdbcis' -OnPage { param($p) } | Should -Be 3
        Should -Invoke Invoke-SIStorageRequest -Times 3 -Exactly -ParameterFilter { $Method -eq 'GET' -and $AllowNotFound -and $Uri -like 'https://stsi.table.core.windows.net/sicmdbcis()*' -and $Headers['Accept'] -eq 'application/json;odata=nometadata' }
    }
    It 'a page that still fails after the helper''s retries is a NAMED error -- table, page and rows read -- never a short list' {
        $t = New-FakeTable -Pages 5 -FailOn 4
        { Read-SICmdbTablePages -Context $script:Ctx -Table 'sicmdbcis' -OnPage { param($p) } -Request $t.Request } |
            Should -Throw "*the CMDB cache table 'sicmdbcis' could not be read to the end (page 4, 30 entities read)*timed out*"
        { Get-SICmdbTableEntities -Context $script:Ctx -Table 'sicmdbcis' -Request $t.Request } | Should -Throw '*could not be read to the end*'
    }
}

Describe 'A FAILED READ IS AN INCOMPLETE CACHE, NEVER A SHORTER ONE' {
    It 'Get-SICmdbCIs: a named warning, the cache marked incomplete; the next good read clears it by itself' {
        Mock Get-SICmdbTableEntities { throw "the CMDB cache table 'sicmdbcis' could not be read to the end (page 101, 100000 entities read): timed out" }
        $w = $null
        $r = @(Get-SICmdbCIs -Context $script:Ctx -WarningVariable w -WarningAction SilentlyContinue)
        $r.Count | Should -Be 0
        Test-SICmdbCacheReadComplete | Should -BeFalse
        (Get-SICmdbCacheReadIssues) -join ' ' | Should -Match 'sicmdbcis: .*page 101'
        ($w | Out-String) | Should -Match 'CMDB cache INCOMPLETE'
        Mock Get-SICmdbTableEntities { @([pscustomobject]@{ RowKey = 'a' }) }
        @(Get-SICmdbCIs -Context $script:Ctx).Count | Should -Be 1
        Test-SICmdbCacheReadComplete | Should -BeTrue
    }
    It 'Get-SICmdbServices: the same' {
        Mock Get-SICmdbTableEntities { throw 'x' }
        $null = Get-SICmdbServices -Context $script:Ctx -WarningAction SilentlyContinue
        Test-SICmdbCacheReadComplete | Should -BeFalse
        Mock Get-SICmdbTableEntities { @() }
        $null = Get-SICmdbServices -Context $script:Ctx
        Test-SICmdbCacheReadComplete | Should -BeTrue
    }
    It 'the dependents treat an incomplete cache as incomplete: the reconcile tags stale-cache (no orphan, no gap report); the CI build does not use a short CMDB' {
        $rec = Get-Content -Raw (Join-Path $script:Root 'engine\asset-profiling\stages\Invoke-Reconcile.ps1')
        $rec | Should -Match "(?s)-not \(Test-SICmdbCacheReadComplete\)\) \{.*?State = 'critical'"
        $ci = Get-Content -Raw (Join-Path $script:Root 'engine\data-model\SI-CiBuildRun.ps1')
        $ci | Should -Match "-not \(Test-SICmdbCacheReadComplete\)\) \{ throw \('the cache is incomplete: '"
        $ci | Should -Match 'Read-SICmdbTablePages -Context \$Context -Table \$Table -PartitionKey \$PartitionKey -OnPage \$OnPage'
    }
}
