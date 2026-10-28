#Requires -Version 7.0
<#
    #737 -- A SPLIT IS SIZED TO THE ANSWER; A BUSY BACKEND NEVER MULTIPLIES THE BUCKETS; THE COUNT COMES DOWN AGAIN.

    Live 2026-10-17 (build 2138, a large customer): Risk Analysis Detailed ran 8+ hours where the same work took 6 h 12 m.
    The guard ra.bucket.count-jump warned "3 reports needed far more buckets than usual (largest 232)": 232 vs a usual 58,
    8 vs 2 (and 32 vs 8, 8 vs 2 at internal). #722 started the next run at the finest count a split slice worked at whenever
    half or more of a report's buckets were split -- 4 x the count -- and a 2-bucket report reaches "half" with ONE split
    slice. A busy backend (900 s timeouts, 502s, preemptions) splits many slices at once, so a backend hiccup became 4 x the
    requests for every later run, and the remembered count never came down.

    What these tests keep true (offline, no tenant):
      * a transient 504 / throttle / timeout is retried, never split and never escalated; a preempted (busy) answer is
        retried at the same size and never split (#880);
      * a split whose own answer was small (busy backend) leaves the next count where it was: 58 stays 58, 2 stays 2;
      * a 502 / too-large answer splits only THAT slice, of THAT report, and the next count grows by what that slice needed;
      * a run whose every slice came back far below every limit (rows, bytes, request AND time) halves the next count, one
        step per run, never below the configured count; a slow slice keeps it;
      * one report's count never affects another's (early save, previous-count hint, the per-report evidence);
      * the engine wiring.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $shared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    . (Join-Path $shared 'RA-AutoBucketing.ps1')
    . (Join-Path $shared 'RA-BucketStore.ps1')
    $script:AutoBucketConfirmedKey = '__confirmed'
    function Write-Info { param($msg) }
    function Write-Warn2 { param($msg) }
    function Slice { param([long]$Rows = 0, [double]$Seconds = 0, [switch]$TooLarge, [switch]$Lost)
        [pscustomobject]@{ Rows = $Rows; Bytes = 0L; Seconds = $Seconds; TooLarge = [bool]$TooLarge; Lost = [bool]$Lost } }
    function New-Measure { param([long]$MaxRows = 0, [long]$MaxBytes = 0, [double]$MaxSeconds = 0, [int]$Slices = 1, [long]$MaxRequest = 0, [long]$Fixed = 0)
        [pscustomobject]@{ ResultRows = $MaxRows; MaxBucketRows = $MaxRows; MaxBucketBytes = $MaxBytes; MaxRequestBytes = $MaxRequest; SplitRows = 0L; SplitBytes = 0L
                           MaxFixedBytes = $Fixed; Slices = $Slices; MaxBucketSeconds = $MaxSeconds } }
}

Describe 'a transient answer is retried, not escalated' {
    It 'a 504 / 503 / throttle / timeout / token expiry is a retry at the same size, never a split' {
        foreach ($m in '504 Gateway Timeout -- {"error":{"code":"UnknownError","message":"<html><head><title>504 Gateway Time-out</title></head></html>"}}',
                       '504 Gateway Timeout', '503 Service Unavailable', '429 Too Many Requests', 'The operation timed out',
                       'InvalidAuthenticationToken: Access token has expired') {
            Get-RABucketFailureAction -Err $m | Should -Be 'Retry' -Because $m
            Test-RABucketExplicitTooLarge -Err $m | Should -BeFalse -Because $m
        }
    }

    It 'a preempted (busy backend) answer is RETRIED at the same size, never split (#880)' {
        # #880 (live 2026-10-22): splitting a busy slice multiplied the fixed reads of every slice -- 263 requests instead of 3
        $m = 'Query execution has exceeded the allowed limits. The query was preempted due to high CPU and/or memory resource consumption'
        Test-RABucketBusyAnswer -Err $m | Should -BeTrue
        Test-RABucketExplicitTooLarge -Err $m | Should -BeFalse
        Get-RABucketFailureAction -Err $m | Should -Be 'Retry'
        Get-RABucketFailureAction -Err $m -AllTimedOut $true | Should -Be 'Retry' -Because 'the busy answer is recognised before every size signal'
    }

    It 'the 900 s ceiling and a 502 still split the slice at once in the run (lossless), but do not say WHY' {
        Get-RABucketFailureAction -Err 'TaskCanceledException: the request was canceled due to the configured timeout of 900 seconds elapsing.' | Should -Be 'Split'
        Get-RABucketFailureAction -Err '502 Bad Gateway -- <html>nginx</html>' | Should -Be 'Split'
        Test-RABucketExplicitTooLarge -Err 'TaskCanceledException: the request was canceled due to the configured timeout of 900 seconds elapsing.' | Should -BeFalse
        Test-RABucketExplicitTooLarge -Err '502 Bad Gateway -- <html>nginx</html>' | Should -BeFalse
    }

    It 'the live case: half of 58 buckets timed out on a busy backend, their sub-slices came back small and quick -> the next run starts at 58, not 232' {
        $s = @(1..30 | ForEach-Object { Slice -Rows 40 -Seconds 120 })
        Get-RACountAfterSplit -BucketCount 58 -Slices $s -WorkingCount 232 -FanOut 4 -Cap 4096 | Should -Be 58
    }

    It 'the live case: one of 2 buckets hit a one-off 502 -> the next run starts at 2, not 8' {
        Get-RACountAfterSplit -BucketCount 2 -Slices @(Slice -Rows 300 -Seconds 30) -WorkingCount 8 -FanOut 4 -Cap 4096 | Should -Be 2
    }

    It 'a split whose sub-slices were themselves slow is real compute evidence and adds what it needed' {
        # 4 sub-slices of 300 s each = 1,200 s of work for one slice: ceil(1200 / 450) = 3 slices
        Get-RACountAfterSplit -BucketCount 58 -Slices @(Slice -Rows 40 -Seconds 1200) -WorkingCount 232 -FanOut 4 -Cap 4096 | Should -Be 60
    }
}

Describe 'a 502 / too-large answer splits only that slice, of that report' {
    It 'only the slice the service refused is split in the run; the others keep their rows at the same count' {
        # a fake report of 8 slices; slice 5 answers too large, the others fit
        $failed = New-Object System.Collections.Generic.List[int]
        foreach ($b in 0..7) {
            $err = if ($b -eq 5) { '502 Bad Gateway -- <html>nginx</html>' } else { $null }
            if ($err) { if ((Get-RABucketFailureAction -Err $err) -eq 'Split') { $failed.Add($b) } }
        }
        @($failed) | Should -Be @(5)
    }

    It 'the next count grows by what THAT slice needed -- not 2 x, not 4 x the report' {
        # the refused slice really was large: its 4 sub-slices returned 40,000 rows together -> it needed 3 slices
        Get-RACountAfterSplit -BucketCount 8 -Slices @(Slice -Rows 40000) -WorkingCount 32 -FanOut 4 -Cap 4096 | Should -Be 10
        # the service SAID too large (result size), even with a small measured answer: at least the split it needed
        Get-RACountAfterSplit -BucketCount 8 -Slices @(Slice -Rows 10 -TooLarge) -WorkingCount 32 -FanOut 4 -Cap 4096 | Should -Be 9
        # a slice still too large at the deepest split: at least 2
        Get-RACountAfterSplit -BucketCount 8 -Slices @(Slice -Lost) -WorkingCount 0 -FanOut 4 -Cap 4096 | Should -Be 9
    }

    It 'one method for every size: the same rule from 2 to 4,096 buckets, bounded only by what worked and the configured maximum' {
        foreach ($n in 2, 8, 58, 64, 512, 4096) {
            Get-RACountAfterSplit -BucketCount $n -Slices @(Slice -Rows 20 -Seconds 10) -WorkingCount ($n * 4) | Should -Be $n -Because "a small answer at $n"
            Get-RACountAfterSplit -BucketCount $n -Slices @(Slice -Rows 1000000 -TooLarge) -WorkingCount ($n * 4) | Should -Be ($n + 3) -Because "a huge slice at $n needs at most the 4-way split that worked"
        }
    }
}

Describe 'the remembered count comes down after small runs' {
    It 'every slice far below every limit (rows, bytes, request, time) -> far below' {
        Test-RABucketRunFarBelow -Measure (New-Measure -MaxRows 300 -MaxBytes 200KB -MaxSeconds 40 -Slices 58) | Should -BeTrue
    }
    It 'one slice near a limit -- rows, bytes, request or TIME -- is not far below' {
        Test-RABucketRunFarBelow -Measure (New-Measure -MaxRows 9000 -MaxSeconds 40) | Should -BeFalse
        Test-RABucketRunFarBelow -Measure (New-Measure -MaxRows 10 -MaxBytes 20MB -MaxSeconds 40) | Should -BeFalse
        Test-RABucketRunFarBelow -Measure (New-Measure -MaxRows 10 -MaxSeconds 300) | Should -BeFalse -Because 'a slow slice is compute evidence, invisible in its rows'
        Test-RABucketRunFarBelow -Measure (New-Measure -MaxRows 10 -MaxSeconds 10 -MaxRequest 600KB -Fixed 100KB) | Should -BeFalse
        Test-RABucketRunFarBelow -Measure (New-Measure -Slices 0) | Should -BeFalse -Because 'nothing measured is not far below'
        Test-RABucketRunFarBelow -Measure $null | Should -BeFalse
    }
    It 'a report sized to 232 by a busy night comes back down, half per run, to where its slices stop being far below' {
        $c = 232; $seen = @()
        # the report's real work: ~7,000 s of compute over ~11,600 rows, spread evenly over its slices
        foreach ($i in 1..10) {
            $m = New-Measure -MaxRows ([long][Math]::Ceiling(11600 / $c)) -MaxBytes 0 -MaxSeconds (7000.0 / $c) -Slices $c
            if (-not (Test-RABucketRunFarBelow -Measure $m)) { break }
            $c = Get-RACountAfterSmallRun -BucketCount $c -Floor 2; $seen += $c
        }
        $seen | Should -Be @(116, 58, 29)
        $c | Should -Be 29 -Because '7,000 s over 29 slices is 241 s each -- no longer far below the 900 s ceiling'
    }
    It 'never below the configured count, never below 1' {
        Get-RACountAfterSmallRun -BucketCount 8 -Floor 8 | Should -Be 8
        Get-RACountAfterSmallRun -BucketCount 9 -Floor 8 | Should -Be 8
        Get-RACountAfterSmallRun -BucketCount 2 -Floor 1 | Should -Be 1
        Get-RACountAfterSmallRun -BucketCount 3 -Floor 1 | Should -Be 2
    }
    It 'a measured slice keeps its time (Add-AutoBucketMeasure -Seconds)' {
        Reset-AutoBucketMeasure
        Add-AutoBucketMeasure -Rows 5 -Seconds 12.5
        Add-AutoBucketMeasure -Rows 7 -Seconds 80
        Add-AutoBucketMeasure -Rows 1 -Seconds 3
        $script:AutoBucketMeasure.Slices | Should -Be 3
        $script:AutoBucketMeasure.MaxBucketSeconds | Should -Be 80
        $script:AutoBucketMeasure.MaxBucketRows | Should -Be 7
    }
}

Describe 'one report''s count never affects another''s' {
    BeforeEach {
        $script:AutoBucketMemo = @{}; $script:AutoBucketSql = $null
        $global:AutoBucketCache = $true
        $global:SettingsPath = Join-Path ([IO.Path]::GetTempPath()) ('si-split-right-size-' + [guid]::NewGuid().ToString('N'))
    }
    AfterEach {
        if (Test-Path $global:SettingsPath) { Remove-Item -LiteralPath $global:SettingsPath -Recurse -Force }
        $global:SettingsPath = $null
    }

    It 'a raised count kept early for one report leaves every other report''s count as it was' {
        $a = 'Attack_Paths_Summary_Identity_Group_Membership_to_Privileged_Resources|111'
        $b = 'Identity_PrivilegedUser_SignIn_NonTrustedLocation_Summary|222'
        Save-AutoBucketCountEarly -QueryKey $a -Count 58 | Should -BeTrue
        Save-AutoBucketCountEarly -QueryKey $b -Count 2 | Should -BeTrue
        Save-AutoBucketCountEarly -QueryKey $a -Count 60 | Should -BeTrue
        $cache = Read-AutoBucketCache -Path (Get-AutoBucketCachePath -SettingsPath $global:SettingsPath)
        [int]$cache[$a] | Should -Be 60
        [int]$cache[$b] | Should -Be 2
        $n = Get-OptimalBucketCount -QueryKey $b -MaxBucketCount 4096 -MinBucketCount 2 -ProbeScript { param([int]$BucketCount) throw 'no probe expected' }
        $n | Should -Be 2
    }

    It 'a changed query takes ITS OWN report''s earlier count -- never one of a report whose name starts the same' {
        Save-AutoBucketCountEarly -QueryKey 'Identity_Summary|1' -Count 4 | Should -BeTrue
        Save-AutoBucketCountEarly -QueryKey 'Identity_Summary_Extended|2' -Count 232 | Should -BeTrue
        Get-AutoBucketPreviousCount -QueryKey 'Identity_Summary|9' -Floor 2 -Cap 4096 | Should -Be 4
    }

    It 'the split evidence is per report: another report''s slices are not in the sum' {
        # the engine keeps $__abSplitSlices per report run; two reports' sizing never share it
        $x = Get-RACountAfterSplit -BucketCount 8 -Slices @(Slice -Rows 40000) -WorkingCount 32
        $y = Get-RACountAfterSplit -BucketCount 2 -Slices @() -WorkingCount 0
        $x | Should -Be 10
        $y | Should -Be 2
    }
}

Describe 'the engine wiring (#737)' {
    BeforeAll { $script:Txt = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) }

    It 'the split evidence and the busy count are reset with every report run, beside the #722 counters' {
        $i = $script:Txt.IndexOf('$__abSplitWorking = 0     # #722')
        $seg = $script:Txt.Substring($i, 900)
        $seg | Should -Match '\$__abSplitCause = @\{\}'
        $seg | Should -Match '\$__abSplitSlices = @\{\}'
        $seg | Should -Match '\$__abBusySlices = 0'
    }

    It 'a preempted answer is sent once more (-Busy), and the cause of every split is recorded' {
        $script:Txt | Should -Match '\$__ovStep = Get-RABucketOverflowStep -OverflowAttempt \$bucketOverflowAttempt -ProbeAttempts \$bucketOverflowRetries -Busy:\$__ovBusy'
        $script:Txt | Should -Match '\$__abSplitCause\[\[int\]\$b\] = \(Test-RABucketExplicitTooLarge -Err \$_\)'
        $script:Txt | Should -Match '\$__abSplitCause\[\[int\]\$db\] = \(Test-RABucketExplicitTooLarge -Err \$_\)'
    }

    It 'each slice''s time is measured, and every sub-slice''s answer is summed under the bucket it came from' {
        $script:Txt | Should -Match '-Seconds \(\[double\]\$__abSliceSw\.Elapsed\.TotalSeconds\)'
        # (#848: every queued slice also carries how it is split -- by key or by row -- and its row split)
        $script:Txt | Should -Match 'R = \[int\]\$idx; How = '
        $script:Txt | Should -Match 'PK = \$thisParentKey; R = \$root; How = '
        $script:Txt | Should -Match '\$__abEv\.Rows \+= \[long\]@\(\$subConv\.Rows\)\.Count'
    }

    It 'the early save and the end of the report size from the same evidence; a far-below run halves the next count' {
        $script:Txt | Should -Match '\$__abSplitNext = Get-RACountAfterSplit -BucketCount \(\[int\]\$bucketCountToUse\) -Slices @\(\$__abSplitSlices\.Values\)'
        $script:Txt | Should -Match '\$__abNext = Get-RACountAfterSplit -BucketCount \(\[int\]\$bucketCountToUse\) -Slices @\(\$__abSplitSlices\.Values\)'
        $i = $script:Txt.IndexOf('$__abHalf = Get-RACountAfterSmallRun')
        $i | Should -BeGreaterThan 0
        $guard = $script:Txt.Substring($i - 2600, 2600)
        # #880: a busy answer that was retried and answered at its own size no longer keeps the count up; a NOT COMPLETE
        # report (a slice lost) never changes it
        $guard | Should -Match '-not \$__abSplitUsed -and -not \$__abIncomplete -and -not \$completeBucketDone'
        $guard | Should -Not -Match '\$__abBusySlices -eq 0'
        $guard | Should -Match '\$__abFar = Test-RABucketRunFarBelow -Measure \$script:AutoBucketMeasure'
        # #833: never below the report's learn floor (1 with the Pro database unless its template sets a count)
        $script:Txt | Should -Match '\$__abHalfFloor = if \(\$__abFar\) \{ \[int\]\$__abLearnFloor \}'
        $script:Txt | Should -Match '\$__abHalf = Get-RACountAfterSmallRun -BucketCount \(\[int\]\$bucketCountToUse\) -Floor \$__abHalfFloor'
    }
}
