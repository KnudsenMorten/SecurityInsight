#Requires -Version 5.1
<#
    SILENT UNDER-COLLECTION -- a failure or a limit must never look like a small estate (#125).

    Operator, 2026-09-28: "it is very important that we dont loose data in this solution, so retries,
    selfhealing, buckets are weapons to solve this" / "it must take into account that api can throttle
    or have issues".

      * Resource Graph: Shodan's public-IP query took the first 1000 rows and never followed the
        SkipToken; AzureResources returned @() on ANY page failure (throwing away the pages it had);
        ARG discovery had no error handling; none retried a throttle. One shared pager now:
        Invoke-SIArgPaged -- paged to the end, throttle retried, collected pages KEPT, partial said aloud.
      * Graph per-principal permission lookups (one call per service principal, thousands of them):
        3 attempts at 1s/2s ignoring Retry-After, then `catch { return @() }` -- the SP was published
        with NO permissions and nothing said so. Now 5 attempts honouring Retry-After, and every
        exhausted failure is counted and reported once per run.
      * EG identity fetch: the "probe failed -> use buckets" catch was unreachable (the DefenderGraph
        route warns, it does not throw), so a failed probe read as count 0 and the label was fetched in
        one query. Now: probe failure -> buckets; a failed single fetch -> retried as buckets; failed
        buckets -> reported INCOMPLETE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Disc   = Join-Path $script:SIRoot 'engine\asset-profiling\discovery'
    $script:Shared = Join-Path $script:SIRoot 'engine\asset-profiling\shared'
    . (Join-Path $script:Disc 'Invoke-SIArgPaged.ps1')
    function script:Write-SIInfo { param($m) }
    function script:Write-SIWarn { param($m) $script:Warned += ,$m }
    function script:Get-CodeNoComments([string]$Path) {
        $t = [regex]::Replace((Get-Content -LiteralPath $Path -Raw), '(?s)<#.*?#>', '')
        (($t -split "`r?`n") | ForEach-Object { $_ -replace '(^|\s)#.*$', '' }) -join "`n"
    }
    # A Resource Graph page in the shape Search-AzGraph returns: .Data (the rows) and .SkipToken.
    function script:New-ArgPage([object[]]$Rows, [string]$SkipToken) {
        [pscustomobject]@{ Data = @($Rows); SkipToken = $SkipToken }
    }
}

Describe 'Invoke-SIArgPaged -- paged to the end, throttle survived, pages kept' {
    It 'follows the SkipToken across every page (Shodan stopped at the first 1000)' {
        $script:n = 0
        $fetch = { param($p) $script:n++; switch ($script:n) {
            1 { (New-ArgPage -Rows @(1,2) -SkipToken 't2') }
            2 { (New-ArgPage -Rows @(3,4) -SkipToken 't3') }
            default { (New-ArgPage -Rows @(5) -SkipToken $null) } } }
        $r = Invoke-SIArgPaged -Query 'q' -SourceLabel 'test' -PageFetcher $fetch -BackoffBaseSeconds 0
        $r.Complete    | Should -BeTrue
        $r.Pages       | Should -Be 3
        @($r.Rows).Count | Should -Be 5
    }
    It 'retries a throttle and completes' {
        $script:n = 0
        $fetch = { param($p) $script:n++; if ($script:n -eq 1) { throw 'Response status code does not indicate success: 429 (Too Many Requests).' }; (New-ArgPage -Rows @('a') -SkipToken $null) }
        $r = Invoke-SIArgPaged -Query 'q' -SourceLabel 'test' -PageFetcher $fetch -BackoffBaseSeconds 0
        $r.Complete | Should -BeTrue
        $r.Retries  | Should -Be 1
    }
    It 'a page that finally fails KEEPS the pages already collected, and says it is partial' {
        $script:n = 0
        $fetch = { param($p) $script:n++; switch ($script:n) {
            1 { (New-ArgPage -Rows @('p1a','p1b') -SkipToken 't2') }
            default { throw 'Forbidden: the client does not have authorization' } } }
        $w = $null
        $r = Invoke-SIArgPaged -Query 'q' -SourceLabel 'test' -PageFetcher $fetch -BackoffBaseSeconds 0 -WarningVariable w -WarningAction SilentlyContinue
        $r.Complete      | Should -BeFalse
        @($r.Rows).Count | Should -Be 2 -Because 'AzureResources used to return @() here, discarding page 1'
        ($w -join ' ')   | Should -Match 'INCOMPLETE'
    }
    It 'a permanent error is not retried' {
        $script:n = 0
        $fetch = { param($p) $script:n++; throw 'InvalidQuery: syntax error' }
        $null = Invoke-SIArgPaged -Query 'q' -SourceLabel 'test' -PageFetcher $fetch -BackoffBaseSeconds 0 -WarningAction SilentlyContinue
        $script:n | Should -Be 1
    }
}

Describe 'Graph per-principal lookups survive throttling, and a real failure is counted' {
    BeforeAll {
        . (Join-Path $script:Shared 'IdentityRoleFetcher.ps1')
    }
    It 'Invoke-SIGraphPaged survives FOUR throttles in a row (it used to give up after two retries)' {
        $script:calls = 0
        Mock Start-Sleep { }
        Mock Invoke-RestMethod {
            $script:calls++
            if ($script:calls -le 4) { throw (New-Object System.Exception 'The remote server returned an error: (429) Too Many Requests.') }
            [pscustomobject]@{ value = @([pscustomobject]@{ id = 'x' }) }
        }
        $rows = Invoke-SIGraphPaged -RelativeUrl '/servicePrincipals/1/appRoleAssignments' -Token 't'
        @($rows).Count | Should -Be 1
        $script:calls  | Should -Be 5
    }
    It 'an exhausted permission lookup is COUNTED and reported once, not silently published as "no permissions"' {
        Reset-SIPermissionFetchFailures
        Mock Invoke-SIGraphPaged { throw 'The remote server returned an error: (503) Server Unavailable.' }
        (Get-SISPOauth2Grants -Token 't' -ObjectId 'sp-1') | Should -BeNullOrEmpty
        $null = Get-SISPAppRoleAssignments -Token 't' -ObjectId 'sp-1' -AppRoleResolver @{}
        @($global:SI_PermissionFetchFailures).Count | Should -Be 2
        $script:Warned = @()
        Write-SIPermissionFetchSummary -Label 'service principal'
        ($script:Warned -join ' ') | Should -Match '1 service principal\(s\).*UNKNOWN.*too LOW'
    }
    It 'nothing failed -> the summary is silent' {
        Reset-SIPermissionFetchFailures
        $script:Warned = @()
        Write-SIPermissionFetchSummary
        @($script:Warned).Count | Should -Be 0
    }
}

Describe 'EG identity fetch -- a failed probe or fetch falls back to buckets, never to "count 0"' {
    BeforeAll {
        . (Join-Path $script:Shared 'IdentityRoleFetcher.ps1')
        . (Join-Path $script:Shared 'HuntingQuery.ps1')
    }
    It 'Invoke-SIEgIdentityQuery reads a WARNING as a failure and retries' {
        $script:calls = 0
        Mock Start-Sleep { }
        Mock Invoke-SIHuntingQuery { $script:calls++; Write-Warning 'hunting query failed: 429'; @() }
        $r = Invoke-SIEgIdentityQuery -Query 'x'
        $r.Ok         | Should -BeFalse
        $r.Error      | Should -Match '429'
        $script:calls | Should -Be 3
    }
    It 'a failed count probe sends the label down the BUCKETED path' {
        $script:_SICache = @{}
        $script:queries = New-Object System.Collections.ArrayList
        Mock Start-Sleep { }
        Mock Invoke-SIHuntingQuery {
            [void]$script:queries.Add($Query)
            if ($Query -match '\| count') { Write-Warning 'probe failed'; return @() }
            @()
        }
        # #882 (C6): the buckets go out in parallel waves through Invoke-SIEgIdentityQueriesParallel's -SendMany seam (a
        # runHuntingQuery request each) -- here each bucket query is answered through the same mocked hunting query
        $script:SIEgIdentitySendMany = { param([string[]]$qs) , @(foreach ($q in $qs) { $r = Invoke-SIEgIdentityQuery -Query $q; [pscustomobject]@{ Ok = [bool]$r.Ok; Rows = $r.Rows; Status = 200; RetryAfter = $null; Error = [string]$r.Error } }) }
        $script:SIEgIdentitySleep = { param($s) }
        try { $null = Get-SIExposureGraphIdentities -WarningAction SilentlyContinue 6>$null }
        finally { $script:SIEgIdentitySendMany = $null; $script:SIEgIdentitySleep = $null }
        $bucketed = @($script:queries | Where-Object { $_ -match '_bucket == ' })
        $bucketed.Count | Should -BeGreaterThan 0 -Because 'a failed probe used to read as count 0 and run ONE unbounded query'
        # and never the unbucketed single fetch after a failed probe
        @($script:queries | Where-Object { $_ -notmatch '\| count' -and $_ -notmatch '_bucket == ' }).Count | Should -Be 0
    }
}

Describe 'WIRING -- every Resource Graph pager uses the shared contract' {
    It 'Shodan no longer takes -First 1000 without paging' {
        $c = Get-CodeNoComments (Join-Path $script:Disc 'Get-DiscoveryFromShodan.ps1')
        $c | Should -Not -Match 'Search-AzGraph -Query \$argQuery -First 1000'
        $c | Should -Match 'Invoke-SIArgPaged -Query \$argQuery'
    }
    It 'AzureResources no longer returns @() on a page failure' {
        $c = Get-CodeNoComments (Join-Path $script:Disc 'Get-DiscoveryFromAzureResources.ps1')
        $c | Should -Not -Match '(?s)Search-AzGraph failed.{0,120}return @\(\)'
        $c | Should -Match 'Test-SIArgTransientError'
    }
    It 'ARG discovery and the security type-queries use Invoke-SIArgPaged' {
        (Get-CodeNoComments (Join-Path $script:Disc 'Get-DiscoveryFromARG.ps1'))      | Should -Match 'Invoke-SIArgPaged -Query \$kql'
        (Get-CodeNoComments (Join-Path $script:Disc 'AzureResourceTypeQueries.ps1')) | Should -Match 'Invoke-SIArgPaged -Query \$entry\.Kql'
    }
    It 'the SP discovery resets the failure counter before the loop and reports after it' {
        $c = Get-CodeNoComments (Join-Path $script:Disc 'Get-DiscoveryFromEntraServicePrincipals.ps1')
        $c | Should -Match '(?s)Reset-SIPermissionFetchFailures\s*\n\s*foreach \(\$sp in \$rows\)'
        $c | Should -Match 'Write-SIPermissionFetchSummary'
    }
}
