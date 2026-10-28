#Requires -Version 5.1
<#
    THE SHODAN MONTHLY CREDIT CAP FAILS CLOSED (#127), AND ITS LEDGER IS ACTUALLY READ AND WRITTEN (#157).

    Get-SIShodanCreditsUsedThisMonth returned 0 on ANY failure -- including the AzTable module being
    absent, which nothing in the solution installs. The /scan gate is `$used -lt $creditCap`, so an
    unreadable ledger read as "nothing spent" and -ForceShodanRescan spent PAID scan credits with no cap.
    Now an unreadable ledger is $null (UNKNOWN), the caller refuses paid scans on it and says so once,
    a month with no row is still a genuine 0, and the writer never overwrites the month's count with a
    guessed "0 + delta".
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\asset-profiling\storage\ShodanCache.ps1')
}

Describe 'Get-SIShodanCreditsUsedThisMonth -- unknown is not zero' {
    It 'store flagged unreachable at Initialize -> $null, not 0' {
        $ctx = [pscustomobject]@{ Mode = 'OAuth'; AccountName = 'x'; _ShodanStoreUnavailable = $true }
        $r = Get-SIShodanCreditsUsedThisMonth -Context $ctx
        $null -eq $r | Should -BeTrue
    }
    It 'a storage read error (missing table, auth, network) -> $null' {
        Mock _SIShodanTableCall { throw 'HTTP 404 TableNotFound' }
        $ctx = [pscustomobject]@{ Mode = 'OAuth'; AccountName = 'x' }
        $r = Get-SIShodanCreditsUsedThisMonth -Context $ctx
        $null -eq $r | Should -BeTrue
    }
    It 'a month with no row yet is a genuine 0 (query answered, empty)' {
        Mock _SIShodanTableCall { [pscustomobject]@{ Content = '{"value":[]}' } }
        $ctx = [pscustomobject]@{ Mode = 'OAuth'; AccountName = 'x' }
        Get-SIShodanCreditsUsedThisMonth -Context $ctx | Should -Be 0
    }
    It 'a month with a row returns its count' {
        Mock _SIShodanTableCall { [pscustomobject]@{ Content = '{"value":[{"PartitionKey":"shodan","RowKey":"2026-09","ScanCreditsUsed":7}]}' } }
        $ctx = [pscustomobject]@{ Mode = 'OAuth'; AccountName = 'x' }
        Get-SIShodanCreditsUsedThisMonth -Context $ctx | Should -Be 7
    }
    It 'the Mock path is unchanged' {
        $ctx = [pscustomobject]@{ Mode = 'Mock'; MockState = @{ Tables = @{ sishodanbudget = @{} } } }
        Get-SIShodanCreditsUsedThisMonth -Context $ctx | Should -Be 0
    }
}

Describe 'Add-SIShodanCreditsUsed never writes a guessed total' {
    It 'with an unreadable ledger it does not write' {
        $script:wrote = $false
        Mock _SIShodanPutEntity { $script:wrote = $true }
        $ctx = [pscustomobject]@{ Mode = 'OAuth'; AccountName = 'x'; _ShodanStoreUnavailable = $true }
        Add-SIShodanCreditsUsed -Context $ctx -Delta 1
        $script:wrote | Should -BeFalse
    }
    It 'with a readable ledger it writes current + delta' {
        $script:put = $null
        Mock _SIShodanTableCall { [pscustomobject]@{ Content = '{"value":[{"ScanCreditsUsed":3}]}' } }
        Mock _SIShodanPutEntity { $script:put = $Properties }
        $ctx = [pscustomobject]@{ Mode = 'OAuth'; AccountName = 'x' }
        Add-SIShodanCreditsUsed -Context $ctx -Delta 2
        $script:put.ScanCreditsUsed | Should -Be 5
    }
}

Describe 'the store is REST, not AzTable (#157)' {
    It 'ShodanCache.ps1 calls no AzTable or Az.Storage table cmdlet' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\asset-profiling\storage\ShodanCache.ps1')
        $code = ($src -split "`n" | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Not -Match 'Add-AzTableRow|Get-AzTableRow|Get-AzStorageTable|New-AzStorageTable|Import-Module AzTable'
    }
    It 'a cached row written as UTC "...Z" one second ago reads back 0 days old, whatever the host time zone' {
        $stamp = [datetime]::UtcNow.AddSeconds(-1).ToString('o')
        Mock _SIShodanTableCall { [pscustomobject]@{ Content = ('{"value":[{"JsonResponse":"{}","CachedAtUtc":"' + $stamp + '"}]}') } }
        $ctx = [pscustomobject]@{ Mode = 'OAuth'; AccountName = 'x' }
        $h = Get-SIShodanHostFromCache -Context $ctx -Ip '192.0.2.1'
        $h.AgeDays | Should -Be 0
        $h.CachedAtUtc.Kind | Should -Be ([System.DateTimeKind]::Utc)
    }
}
Describe 'WIRING -- the /scan gate refuses on unknown' {
    It 'the caller checks for $null BEFORE comparing against the cap, and warns once per pass' {
        $src = Get-Content -LiteralPath (Join-Path $script:SIRoot 'engine\asset-profiling\discovery\Get-DiscoveryFromShodan.ps1') -Raw
        $src | Should -Match '(?s)\$used = Get-SIShodanCreditsUsedThisMonth -Context \$cacheCtx\s*\n\s*if \(\$null -eq \$used\) \{.{0,600}\} elseif \(\$used -lt \$creditCap\)'
        $src | Should -Match '\$script:_SIShodanLedgerWarned = \$false'
    }
}
