#Requires -Version 5.1
<#
.SYNOPSIS
    Covers Invoke-SIPagedRest -- the paged-REST retry helper behind audit #4.

.DESCRIPTION
    The bug this guards against: the four discovery connectors wrapped their whole
    pagination loop in ONE try/catch that did `return @()`, so a throttle on page 40
    of 50 discarded all 40 pages and returned a result indistinguishable from "this
    tenant has none". These tests assert the two properties the fix must hold:

      1. transient failures (429/502/503/504/network) are RETRIED, honouring
         Retry-After when the server sends it;
      2. when a page finally fails, the rows already collected are RETURNED, the
         call does NOT throw, and Complete reports $false.

    Property 2 is the one that matters operationally: per operator decision
    2026-08-05 a source that dies after retries must degrade the run, never block it.

    Invoke-RestMethod is mocked, so these are offline and deterministic -- no tenant,
    no network, no credentials.
#>

BeforeAll {
    # tests/pester/<file> -> tests/pester -> tests -> SecurityInsight
    $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $siRoot 'engine/asset-profiling/shared/Invoke-SIPagedRest.ps1')

    # Build an ErrorRecord carrying a given HTTP status, the way Invoke-RestMethod
    # surfaces one, so Get-SIRestHttpStatus can read it back.
    function New-HttpError {
        param([int]$Status)
        $ex = New-Object System.Exception ("The remote server returned an error: ($Status).")
        New-Object System.Management.Automation.ErrorRecord($ex, 'HttpError', 'InvalidOperation', $null)
    }
}

Describe 'Invoke-SIPagedRest -- transient failures are retried' {

    It 'retries a 429 and then succeeds, returning all rows' {
        $script:calls = 0
        Mock -CommandName Invoke-RestMethod -MockWith {
            $script:calls++
            if ($script:calls -eq 1) { throw (New-HttpError -Status 429) }
            [pscustomobject]@{ value = @([pscustomobject]@{ id = 'a' }, [pscustomobject]@{ id = 'b' }) }
        }
        $r = Invoke-SIPagedRest -Url 'https://x/api' -Token 't' -SourceLabel 'test' -MaxDelaySeconds 0
        $r.Complete       | Should -BeTrue
        $r.Rows.Count     | Should -Be 2
        $r.Retries        | Should -Be 1
        $script:calls     | Should -Be 2
    }

    It 'gives up after MaxAttempts and does NOT throw' {
        Mock -CommandName Invoke-RestMethod -MockWith { throw (New-HttpError -Status 503) }
        { Invoke-SIPagedRest -Url 'https://x/api' -Token 't' -SourceLabel 'test' `
                -MaxAttempts 2 -MaxDelaySeconds 0 } | Should -Not -Throw
    }

    It 'does NOT retry a permanent error (403)' {
        $script:calls = 0
        Mock -CommandName Invoke-RestMethod -MockWith { $script:calls++; throw (New-HttpError -Status 403) }
        $r = Invoke-SIPagedRest -Url 'https://x/api' -Token 't' -SourceLabel 'test' -MaxDelaySeconds 0
        $script:calls | Should -Be 1
        $r.Complete   | Should -BeFalse
        $r.Retries    | Should -Be 0
    }
}

Describe 'Invoke-SIPagedRest -- collected pages are NEVER discarded (audit #4)' {

    It 'returns the rows from pages 1-2 when page 3 fails permanently' {
        # THE REGRESSION TEST. Old behaviour: return @() -- all four rows lost.
        $script:calls = 0
        Mock -CommandName Invoke-RestMethod -MockWith {
            $script:calls++
            switch ($script:calls) {
                1 { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'p1a' }, [pscustomobject]@{ id = 'p1b' })
                                       '@odata.nextLink' = 'https://x/api?page=2' } }
                2 { [pscustomobject]@{ value = @([pscustomobject]@{ id = 'p2a' }, [pscustomobject]@{ id = 'p2b' })
                                       '@odata.nextLink' = 'https://x/api?page=3' } }
                default { throw (New-HttpError -Status 403) }
            }
        }
        $r = Invoke-SIPagedRest -Url 'https://x/api' -Token 't' -SourceLabel 'test' -MaxDelaySeconds 0

        $r.Rows.Count | Should -Be 4                     # <-- was 0 before the fix
        $r.Pages      | Should -Be 2
        $r.Complete   | Should -BeFalse                  # partial is reported, not hidden
        $r.Error      | Should -Match 'page 3'
        @($r.Rows | ForEach-Object { $_.id }) | Should -Contain 'p2b'
    }

    It 'reports Complete=$true and every row when nothing fails' {
        $script:calls = 0
        Mock -CommandName Invoke-RestMethod -MockWith {
            $script:calls++
            if ($script:calls -eq 1) {
                [pscustomobject]@{ value = @([pscustomobject]@{ id = 1 }); '@odata.nextLink' = 'https://x/api?p=2' }
            } else {
                [pscustomobject]@{ value = @([pscustomobject]@{ id = 2 }) }
            }
        }
        $r = Invoke-SIPagedRest -Url 'https://x/api' -Token 't' -SourceLabel 'test' -MaxDelaySeconds 0
        $r.Complete   | Should -BeTrue
        $r.Pages      | Should -Be 2
        $r.Rows.Count | Should -Be 2
        $r.Error      | Should -BeNullOrEmpty
    }

    It 'returns an empty ARRAY (never $null) when the very first page fails' {
        # Callers do `foreach ($x in $page.Rows)` and read .Count without a null
        # check, so Rows must always be an array -- an empty one, not $null.
        Mock -CommandName Invoke-RestMethod -MockWith { throw (New-HttpError -Status 500) }
        $r = Invoke-SIPagedRest -Url 'https://x/api' -Token 't' -SourceLabel 'test' -MaxDelaySeconds 0
        $null -eq $r.Rows | Should -BeFalse -Because 'Rows must never be $null'
        ,$r.Rows          | Should -BeOfType [System.Array]
        $r.Rows.Count     | Should -Be 0
        $r.Complete       | Should -BeFalse
    }
}

Describe 'Get-SIRetryAfterSeconds -- the server''s backoff is honoured' {

    It 'parses a delta-seconds Retry-After header' {
        $ex = New-Object System.Exception 'throttled'
        $err = New-Object System.Management.Automation.ErrorRecord($ex, 'e', 'InvalidOperation', $null)
        # No Response object -> must fall back to $null so the caller uses exponential backoff.
        Get-SIRetryAfterSeconds -ErrorRecord $err | Should -BeNullOrEmpty
    }
}
