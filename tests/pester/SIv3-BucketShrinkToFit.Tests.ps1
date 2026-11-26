#Requires -Version 5.1
<#
    #1378 SHRINK TO FIT (owner 2026-11-25, approved option "Shrink to fit", after the report bucket page of a small tenant
    showed Azure_Recommendations_Summary at "Buckets now 8, Last run started 16 / ended 8, Run before 16, Usual 12" -- "this
    looks wrong for my little env"): "After each run, size the next run's buckets from what this run actually returned (rows
    per bucket vs. the API limit) -- so a small tenant drops back to 1-2 at once, and a big one keeps what it needs; a
    throttled answer no longer raises the count permanently."

    What these tests keep true (offline, pure functions; the engine wiring is checked on its source text):
      * a small result shrinks to 1 in ONE run (not one halving per run), never below the learn floor;
      * a once-inflated count (16) on small data drops to fit in one run -- also with a raise in its history once this run
        measured every slice far below every limit, or the report's rows have since fallen to half;
      * a result near the limit keeps its count; the fit never raises (raising stays with a slice that hit a limit);
      * a big tenant keeps what its rows and its slice time need (the time against HALF the back end's documented limit
        when the run cannot tell the fixed part of a slice);
      * a throttled (429) answer never raises a count: it is retried at the same size, a busy-only split adds nothing, and
        the run after it is sized to fit like any other;
      * the request part no slice count shrinks is not counted once per slice; an unknown request shape stays conservative;
      * the history row of a count sized to fit is 'fit' (the page: "Last run: sized to fit (N rows -> M buckets)").
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-BucketStore.ps1')
    function Write-Info { param($msg) }
    function Write-Warn2 { param($msg) }

    # one run's measure in the shape Get-AutoBucketFitMeasure hands over
    function script:New-FitMeasure {
        param([long]$Rows, [long]$MaxRows, [int]$Slices, [double]$Seconds = 0, [long]$MaxBytes = 0, [long]$MaxRequest = 0,
              [long]$RequestRows = 0, [int]$RequestBpr = 0, [int]$Overhead = 0, [double]$Fixed = 0, [string]$Backend = 'hunting')
        [pscustomobject]@{ ResultRows = $Rows; MaxBucketRows = $MaxRows; MaxBucketBytes = $(if ($MaxBytes) { $MaxBytes } else { $MaxRows * 400 })
                           MaxRequestBytes = $MaxRequest; RequestRows = $RequestRows; RequestBytesPerRow = $RequestBpr; RequestOverheadBytes = $Overhead
                           MaxBucketSeconds = $Seconds; FixedSeconds = $Fixed; Backend = $Backend; Slices = $Slices }
    }
    function script:New-HistRow {
        param([int]$Start, [int]$Count, [string]$Decided, [long]$Rows = 0, [string]$Fp = 'abc')
        [pscustomobject]@{ StartCount = $Start; BucketCount = $Count; Decided = $Decided; ResultRows = $Rows; Fingerprint = $Fp; MaxBucketRows = 0; MaxBucketBytes = 0; MaxRequestBytes = 0 }
    }
}

Describe 'a small result is sized to fit at once (#1378)' {
    It 'a small result at 16 buckets shrinks to 1 in one run' {
        $m = New-FitMeasure -Rows 12 -MaxRows 3 -Slices 16 -Seconds 4
        $r = Get-SIRaBucketFitCount -Measure $m -RanCount 16 -Floor 1
        $r.Down | Should -BeTrue
        $r.Count | Should -Be 1 -Because 'one halving per run took 16 -> 8 -> 4 -> 2 -> 1, four runs; the fit is measured, so it is taken at once'
        $r.Fit | Should -Be 1
        $r.Why | Should -Match 'sized to fit: this run returned 12 row\(s\) in 16 bucket\(s\)'
    }

    It 'a report that returns nothing comes down to 1 as well, never below the floor its template sets' {
        (Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 0 -MaxRows 0 -Slices 8 -Seconds 2) -RanCount 8 -Floor 1).Count | Should -Be 1
        (Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 0 -MaxRows 0 -Slices 8 -Seconds 2) -RanCount 8 -Floor 4).Count | Should -Be 4
        (Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 0 -MaxRows 0 -Slices 4 -Seconds 2) -RanCount 4 -Floor 4).Down | Should -BeFalse
    }

    It 'a small tenant with ~21,000 rows drops to 2, not to 1 (rows against half the 30,000 planning target)' {
        $r = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 21400 -MaxRows 1500 -Slices 16 -Seconds 6) -RanCount 16 -Floor 1
        $r.Count | Should -Be 2
    }

    It 'the OWNER CASE: a once-inflated 16 on small data drops to fit in one run, even with a raise in its history' {
        $h = @((New-HistRow -Start 16 -Count 16 -Decided 'cache' -Rows 30), (New-HistRow -Start 8 -Count 16 -Decided 'raised' -Rows 30), (New-HistRow -Start 8 -Count 8 -Decided 'cache' -Rows 30))
        $m = New-FitMeasure -Rows 30 -MaxRows 5 -Slices 16 -Seconds 5
        # this run measured every slice far below every limit: the raise no longer binds
        $r = Get-SIRaBucketFitCount -Measure $m -RanCount 16 -Floor 1 -History $h -Fingerprint 'abc' -FarBelow
        $r.Down | Should -BeTrue
        $r.Count | Should -Be 1
        # the next run measures at 1: it fits, nothing changes -- the count stays down
        (Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 30 -MaxRows 30 -Slices 1 -Seconds 8) -RanCount 1 -Floor 1).Down | Should -BeFalse
    }

    It 'a raise whose data has since shrunk to half or less no longer holds the count up' {
        $h = @((New-HistRow -Start 4 -Count 16 -Decided 'raised' -Rows 100000))
        $r = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 40 -MaxRows 8 -Slices 16 -Seconds 4) -RanCount 16 -Floor 1 -History $h -Fingerprint 'abc'
        $r.Count | Should -BeLessThan 16
    }

    It 'a raise of the SAME query on the same data still holds while this run was not far below every limit' {
        $h = @((New-HistRow -Start 8 -Count 16 -Decided 'raised' -Rows 40))
        $r = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 40 -MaxRows 8 -Slices 16 -Seconds 4) -RanCount 16 -Floor 1 -History $h -Fingerprint 'abc'
        $r.Down | Should -BeFalse
        $r.Count | Should -Be 16
        $r.Why | Should -Match 'a failed query of this report needed 16'
        # ... but a raise of an EARLIER query proves nothing for this one
        $r2 = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 40 -MaxRows 8 -Slices 16 -Seconds 4) -RanCount 16 -Floor 1 -History $h -Fingerprint 'other'
        $r2.Count | Should -Be 1
    }
}

Describe 'near the limit and a big tenant keep what they need (#1378)' {
    It 'a result near the limit keeps its count -- the fit never raises' {
        $r = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 56000 -MaxRows 14500 -Slices 4 -Seconds 40) -RanCount 4 -Floor 1
        $r.Down | Should -BeFalse
        $r.Count | Should -Be 4
        $r.Fit | Should -Be 4
        # more than the count needs: still kept (a slice that really hits a limit raises it in the run, Get-RACountAfterSplit)
        $r2 = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 110000 -MaxRows 29000 -Slices 4 -Seconds 60) -RanCount 4 -Floor 1
        $r2.Count | Should -Be 4
        $r2.Down | Should -BeFalse
        $r2.Fit | Should -BeGreaterThan 4
    }

    It 'a slice that really hit a limit raises the count as today' {
        Get-RACountAfterSplit -BucketCount 4 -Slices @([pscustomobject]@{ Rows = 60000; Bytes = 0; Seconds = 20; TooLarge = $true; Lost = $false }) -FanOut 4 | Should -BeGreaterThan 4
    }

    It 'BIG TENANT fixture: 64 buckets of ~12,000 rows keep 64' {
        $r = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 768000 -MaxRows 12500 -Slices 64 -Seconds 60) -RanCount 64 -Floor 1
        $r.Down | Should -BeFalse
        $r.Count | Should -Be 64
    }

    It 'a big tenant whose count is set by TIME keeps it: few rows, slices of 80 s, fixed part unknown -> half the 180 s hunting limit' {
        $r = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 900 -MaxRows 40 -Slices 32 -Seconds 80) -RanCount 32 -Floor 1
        $r.Count | Should -Be 32 -Because '32 x 80 s of work at 90 s a slice still needs 32; coming down would send slices into the gateway time limit'
        $r.Down | Should -BeFalse
    }

    It 'with the fixed part of a slice known, only the divisible time counts' {
        # 16 slices of 60 s, of which 55 s is fixed (the same whatever a slice holds): fewer slices are barely longer
        $r = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 300 -MaxRows 30 -Slices 16 -Seconds 60 -Fixed 55) -RanCount 16 -Floor 1
        $r.Down | Should -BeTrue
        $r.Count | Should -BeLessThan 16
    }
}

Describe 'a throttled answer never raises the count (#1378)' {
    It 'a 429 is retried at the same size -- never split, never an overflow, never "too large"' {
        Get-RABucketFailureAction -Err 'Response status code does not indicate success: 429 (Too Many Requests).' | Should -Be 'Retry'
        Test-IsBucketOverflowError -Err '429 Too Many Requests' | Should -BeFalse
        Test-IsDeterministicTooLargeError -Err '429 Too Many Requests -- a task was canceled' | Should -BeFalse
        Get-RABucketFailureAction -Err 'Query execution has exceeded the allowed limits. The query execution was preempted due to high CPU and/or memory' | Should -Be 'Retry'
    }

    It 'a busy-only split adds nothing to the count' {
        $busy = [pscustomobject]@{ Rows = 30; Bytes = 3000; Seconds = 200; TooLarge = $false; Lost = $false; Busy = 2; SizeFails = 0 }
        Get-RACountAfterSplit -BucketCount 2 -Slices @($busy) -FanOut 4 | Should -Be 2
    }

    It 'the run after a throttled run is sized to fit like any other: a throttle leaves no proof behind' {
        # the throttled run ran complete at 16 after its retries; it recorded no 'raised' row (nothing was split)
        $h = @((New-HistRow -Start 16 -Count 16 -Decided 'cache' -Rows 25))
        $r = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 25 -MaxRows 4 -Slices 16 -Seconds 5) -RanCount 16 -Floor 1 -History $h -Fingerprint 'abc'
        $r.Count | Should -Be 1
    }
}

Describe 'the request is sized from its shape (#1378)' {
    It 'the query text and lookups sent whole are not counted once per slice' {
        # 300 KB every slice carries whatever the count, nothing split per slice: no count makes it smaller
        $r = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 12 -MaxRows 3 -Slices 16 -Seconds 4 -MaxRequest 300KB -Overhead 300KB) -RanCount 16 -Floor 1
        $r.Count | Should -Be 1
    }

    It 'the split lookup rows are sized against the request room' {
        # 40,000 inlined rows of 50 bytes split across the slices, 100 KB fixed: 2,000,000 x 1.15 / (512 KB - 100 KB) -> 6 -> 8
        $r = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 12 -MaxRows 3 -Slices 16 -Seconds 4 -MaxRequest 225KB -RequestRows 40000 -RequestBpr 50 -Overhead 100KB) -RanCount 16 -Floor 1
        $r.Count | Should -Be 8
    }

    It 'an unknown request shape stays conservative (the largest request x the count it was sent at)' {
        $r = Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 12 -MaxRows 3 -Slices 16 -Seconds 4 -MaxRequest 300KB) -RanCount 16 -Floor 1
        $r.Count | Should -Be 16
        $r.Down | Should -BeFalse
    }

    It 'nothing measured keeps the count' {
        (Get-SIRaBucketFitCount -Measure $null -RanCount 8).Down | Should -BeFalse
        (Get-SIRaBucketFitCount -Measure (New-FitMeasure -Rows 0 -MaxRows 0 -Slices 0) -RanCount 8).Count | Should -Be 8
    }
}

Describe 'the measure handed over and the history row (#1378)' {
    It 'Get-AutoBucketFitMeasure carries the run''s answer, request shape and time' {
        Reset-AutoBucketMeasure
        foreach ($i in 1..4) { Add-AutoBucketMeasure -Rows 3 -Sample @([pscustomobject]@{ a = 'x' }) -Seconds 5 -Backend 'hunting' }
        $m = Get-AutoBucketFitMeasure -Measure $script:AutoBucketMeasure
        $m.ResultRows | Should -Be 12
        $m.MaxBucketRows | Should -Be 3
        $m.Slices | Should -Be 4
        $m.MaxBucketSeconds | Should -Be 5
        $m.Backend | Should -Be 'hunting'
        (Get-SIRaBucketFitCount -Measure $m -RanCount 4 -Floor 1).Count | Should -Be 1
        Get-AutoBucketFitMeasure -Measure $null | Should -BeNullOrEmpty
    }

    It 'a count sized to fit is recorded as ''fit''; kept lower any other way stays ''down''' {
        $script:Added = @()
        $script:AutoBucketSql = [pscustomobject]@{ Invoke = { param($s, $p, $mode) if ($s -match 'INSERT cfg\.RaBucketHistory') { $script:Added += , $p } }
                                                   Template = 'RiskAnalysis_Summary'; RunId = 'r1'; State = @{}; Saved = @{}; History = @{}; Offline = $false }
        Reset-AutoBucketMeasure
        foreach ($i in 1..16) { Add-AutoBucketMeasure -Rows 1 -Sample @([pscustomobject]@{ a = 'x' }) -Seconds 3 }
        $null = Complete-AutoBucketReport -ReportName 'Azure_Recommendations_Summary' -QueryKey 'Azure_Recommendations_Summary|abc' -StartCount 16 -FinalCount 1 -Source 'cache' -RanCount 16 -SizedToFit
        $null = Complete-AutoBucketReport -ReportName 'Other' -QueryKey 'Other|abc' -StartCount 16 -FinalCount 8 -Source 'cache' -RanCount 16
        $script:Added.Count | Should -Be 2
        $script:Added[0].Decided | Should -Be 'fit'
        $script:Added[0].BucketCount | Should -Be 1
        $script:Added[0].ResultRows | Should -Be 16
        $script:Added[1].Decided | Should -Be 'down'
        $script:AutoBucketSql = $null
    }

    It 'step 3 (half after 3 runs far below) never halves straight after a fit' {
        $row = { param($d) [pscustomobject]@{ StartCount = 2; BucketCount = 2; Decided = $d; ResultRows = 10; MaxBucketRows = 5; MaxBucketBytes = 100; MaxRequestBytes = 0 } }
        # three far-below runs of 'cache' halve (as before) ...
        (Get-SIRaBucketDownCount -Count 2 -Floor 1 -History @((& $row 'cache'), (& $row 'cache'), (& $row 'cache'))).Down | Should -BeTrue
        # ... a 'fit' among them sized itself from its own answer: no halving on top of it
        (Get-SIRaBucketDownCount -Count 2 -Floor 1 -History @((& $row 'fit'), (& $row 'cache'), (& $row 'cache'))).Down | Should -BeFalse
    }
}

Describe 'the engine wiring (#1378)' {
    BeforeAll { $script:Txt = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) }

    It 'after a complete run without a split, the next count is sized to fit before the halving rules' {
        $i = $script:Txt.IndexOf('$__abFit = Get-SIRaBucketFitCount')
        $i | Should -BeGreaterThan 0
        $script:Txt | Should -Match '\$__abFit = Get-SIRaBucketFitCount -Measure \(Get-AutoBucketFitMeasure -Measure \$script:AutoBucketMeasure\) -RanCount \(\[int\]\$bucketCountToUse\) -Floor \(\[int\]\$__abLearnFloor\)'
        $script:Txt | Should -Match '-FarBelow:\$__abFar'
        $j = $script:Txt.IndexOf('$__abHalf = Get-RACountAfterSmallRun')
        $i | Should -BeLessThan $j
        # the fit is taken only in the no-split, complete branch (the split branch raises as before)
        $g = $script:Txt.LastIndexOf('-not $__abSplitUsed -and -not $__abIncomplete -and -not $completeBucketDone', $i)
        $g | Should -BeGreaterThan 0
        ($i - $g) | Should -BeLessThan 2500
        $script:Txt | Should -Match '\$__abRemember = \[int\]\$__abFit\.Count'
    }

    It 'the history row says how it was decided (-SizedToFit)' {
        $script:Txt | Should -Match '-Incomplete:\$__abIncomplete -SizedToFit:\$__abSizedToFit'
        $script:Txt | Should -Match '\$__abSizedToFit = \$false'
    }
}
