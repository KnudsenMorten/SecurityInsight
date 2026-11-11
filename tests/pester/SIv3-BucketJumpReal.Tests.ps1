#Requires -Version 7.0
<#
    #1202 -- THE RISK-ANALYSIS "BUCKET COUNT JUMP" WARNING ONLY TRIPS ON A REAL JUMP.

    Live 2026-11-11 (two installs, read-only): the warning 'ra.bucket.count-jump' tripped on every run while the reports'
    result rows stayed flat. The "usual" count was the median over the report NAME, so it spanned a query change and the
    growth of an embedded lookup; the sizing after the changed query and the size-down rule ("ran complete at N" from when
    the lookup was small) then produced 16s and a 4 <-> 8 swing that tripped the 4 x rule.

    What these tests keep true (offline, no tenant; the database is a fake behind the ONE -Invoke seam):
      * rule 1: the usual count is over runs of the SAME query version only; fewer than 3 such runs = no jump judgement;
      * rule 2: a count sized from a measurement after a changed query does not warn when neither the result rows nor the
        request grew at least 2 x against the previous measured run;
      * rule 3: the size-down rule ignores "ran complete at N" runs whose request was more than 15 % smaller than now;
      * rule 4: a real jump (rows or request 4 x, same query version) still warns exactly as before;
      * the two live cases replayed: install A (identity report, embedded lookup 0.25 MB -> 4.2 MB, 4 <-> 8, then 16 after
        a query change) -- no warning and no swing; install B (stable 4-5, then 16 after a query change) -- no warning.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $shared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    . (Join-Path $shared 'RA-AutoBucketing.ps1')
    . (Join-Path $shared 'RA-BucketStore.ps1')
    $script:AutoBucketConfirmedKey = '__confirmed'
    function Write-Info { param($msg) }
    function Write-Warn2 { param($msg) }

    # a history row as Read-SIRaBucketHistory returns it (newest first in a list)
    function New-HRow {
        param([int]$Count, [int]$Start = -1, [string]$Decided = 'cache', [string]$Fp = '', [long]$Rows = 10,
              [long]$ReqRows = 0, [int]$ReqBpr = 0, [int]$ReqOver = 4000, [double]$Seconds = 30, [int]$Ran = -1)
        if ($Start -lt 0) { $Start = $Count }
        if ($Ran -lt 0) { $Ran = $Start }
        [pscustomobject]@{ BucketCount = $Count; StartCount = $Start; Decided = $Decided; ResultRows = $Rows; MaxBucketRows = $Rows
                           MaxBucketBytes = 2000L; MaxRequestBytes = $(if ($ReqRows -gt 0) { [long](($ReqRows * $ReqBpr) / [Math]::Max(1, $Ran) + $ReqOver) } else { $null })
                           RequestRows = $(if ($ReqRows -gt 0) { $ReqRows } else { $null }); RequestBytesPerRow = $(if ($ReqRows -gt 0) { $ReqBpr } else { $null })
                           RequestOverheadBytes = $(if ($ReqRows -gt 0) { $ReqOver } else { $null })
                           Fingerprint = $Fp; MaxBucketSeconds = $Seconds; RanCount = $Ran }
    }
    # the Pro database behind its ONE seam (the history row's parameters are captured) with the report's earlier runs
    function Set-BucketRun {
        param([string]$Report, [object[]]$History, [long]$Rows, [long]$ReqRows = 0, [int]$ReqBpr = 0, [int]$ReqOver = 4000, [int]$RanAt = 1)
        $captured = New-Object System.Collections.Generic.List[object]
        $script:Captured = $captured
        $script:AutoBucketSql = [pscustomobject]@{ Invoke = { param($s, $p, $m) $captured.Add($p) }.GetNewClosure(); Template = 'T'; RunId = 'r-now'
                                                   State = @{}; Saved = @{}; History = @{ $Report = @($History) }; Offline = $false }
        $script:AutoBucketJumps = $null
        $script:AutoBucketMeasure = [pscustomobject]@{ ResultRows = $Rows; MaxBucketRows = $Rows; MaxBucketBytes = 2000L
            MaxRequestBytes = $(if ($ReqRows -gt 0) { [long](($ReqRows * $ReqBpr) / [Math]::Max(1, $RanAt) + $ReqOver) } else { 0L })
            SplitRows = $ReqRows; SplitBytes = [long]($ReqRows * $ReqBpr); MaxFixedBytes = $ReqOver; Slices = $RanAt; MaxBucketSeconds = 40.0 }
    }
    function Complete-Run {
        param([string]$Report, [string]$Fp, [int]$Start, [int]$Final, [string]$Source, [long]$ReqRows = 0, [int]$ReqBpr = 0, [int]$ReqOver = 4000)
        Complete-AutoBucketReport -ReportName $Report -QueryKey ('{0}|{1}' -f $Report, $Fp) -StartCount $Start -FinalCount $Final -Source $Source `
            -RequestRows $ReqRows -RequestBytesPerRow $ReqBpr -RequestOverheadBytes $ReqOver -RanCount $Start
    }

    # THE LIVE CASE OF INSTALL A (an identity report): the embedded CI-link lookup grew 719 rows / ~0.25 MB (day 1) ->
    # 13,107 / 2.77 MB (day 2) -> 19,739 / 4.22 MB (day 9) while the result stayed at 8-11 rows; days 5-8 swung 4 <-> 8 on
    # query version 4017900102; day 9 the query changed (2857676019) and was sized from its last measurement to 16.
    $script:A = 'Identity_PrivilegedUser_NoConditionalAccess_Detailed'
    $script:AOld = '4017900102'; $script:ANew = '2857676019'
    $script:AHistory = @(   # newest first, as of the run after the query change
        (New-HRow -Count 4  -Start 8 -Decided 'down'       -Fp $script:AOld -Rows 11 -ReqRows 19300 -ReqBpr 214 -Ran 8),
        (New-HRow -Count 8  -Start 4 -Decided 'raised'     -Fp $script:AOld -Rows 11 -ReqRows 18700 -ReqBpr 214 -Ran 4),
        (New-HRow -Count 4  -Start 8 -Decided 'down'       -Fp $script:AOld -Rows 10 -ReqRows 17800 -ReqBpr 214 -Ran 8),
        (New-HRow -Count 8  -Start 4 -Decided 'raised'     -Fp $script:AOld -Rows 10 -ReqRows 16900 -ReqBpr 214 -Ran 4),
        (New-HRow -Count 4                                 -Fp $script:AOld -Rows 10 -ReqRows 13900 -ReqBpr 214),
        (New-HRow -Count 4                                 -Fp $script:AOld -Rows 10 -ReqRows 13500 -ReqBpr 214),
        (New-HRow -Count 4  -Start 1 -Decided 'raised'     -Fp $script:AOld -Rows 10 -ReqRows 13107 -ReqBpr 211 -Ran 1),
        (New-HRow -Count 1  -Decided 'configured'          -Fp $script:AOld -Rows 8  -ReqRows 719   -ReqBpr 365)
    )
    # THE LIVE CASE OF INSTALL B: stable at 4-5 buckets for eight days (rows 122 -> 84, the lookup flat at ~1.9 MB), then the
    # query changed (2896214918) and was sized from its last measurement to 16 with 80 rows and the same lookup.
    $script:B = 'Identity_EligibleAdmin_LogonTo_ExploitableDevice_Detailed'
    $script:BOld = '1188812301'; $script:BNew = '2896214918'
    $script:BHistory = @(foreach ($d in 0..7) {
        $c = if ($d % 2) { 5 } else { 4 }
        New-HRow -Count $c -Fp $script:BOld -Rows (84 + 5 * $d) -ReqRows 9000 -ReqBpr 211 -ReqOver 6000   # ~1,905,000 bytes
    })
}

Describe 'rule 1: the usual count is over the runs of the same query version' {
    It 'only rows of the current fingerprint (and rows without one) count' {
        $h = @((New-HRow -Count 16 -Fp 'new'), (New-HRow -Count 1 -Fp 'old'), (New-HRow -Count 1 -Fp 'old'), (New-HRow -Count 1 -Fp 'old'), (New-HRow -Count 16 -Fp ''))
        @(Get-SIRaBucketSameQueryCounts -History $h -Fingerprint 'new') | Should -Be @(16, 16)
        @(Get-SIRaBucketSameQueryCounts -History $h -Fingerprint '').Count | Should -Be 5 -Because 'without a fingerprint every row counts, as before'
    }
    It 'fewer than 3 runs of the current version: no usual, no 4 x warning' {
        Set-BucketRun -Report 'R' -History @((New-HRow -Count 1 -Fp 'old'), (New-HRow -Count 1 -Fp 'old'), (New-HRow -Count 1 -Fp 'old'), (New-HRow -Count 4 -Fp 'new')) -Rows 10
        $why = Complete-Run -Report 'R' -Fp 'new' -Start 4 -Final 4 -Source 'cache'
        $why | Should -Be ''
        $script:Captured[0].UsualCount | Should -BeNullOrEmpty
        $script:Captured[0].Jump | Should -BeFalse
    }
    It 'the usual of the current version is used once it has 3 runs' {
        Set-BucketRun -Report 'R' -History @((New-HRow -Count 4 -Fp 'new'), (New-HRow -Count 4 -Fp 'new'), (New-HRow -Count 4 -Fp 'new'), (New-HRow -Count 1 -Fp 'old')) -Rows 10
        $null = Complete-Run -Report 'R' -Fp 'new' -Start 4 -Final 4 -Source 'cache'
        $script:Captured[0].UsualCount | Should -Be 4
    }
}

Describe 'rule 2: a count sized after a changed query warns only when the input grew' {
    BeforeAll {
        # rows WITHOUT a fingerprint (written before it was recorded) still make a usual of 4 for any query
        $script:Legacy = @(foreach ($i in 1..4) { New-HRow -Count 4 -Fp '' -Rows 100 -ReqRows 9000 -ReqBpr 211 })
    }
    It 'sized from a measurement, rows and request flat: no warning' {
        Set-BucketRun -Report 'R' -History $script:Legacy -Rows 110 -ReqRows 9100 -ReqBpr 211 -RanAt 16
        Complete-Run -Report 'R' -Fp 'q2' -Start 16 -Final 16 -Source 'measured' -ReqRows 9100 -ReqBpr 211 | Should -Be ''
        $script:Captured[0].Jump | Should -BeFalse
    }
    It 'the same count NOT from the sizing still warns (the rule is only for the measured sizing)' {
        Set-BucketRun -Report 'R' -History $script:Legacy -Rows 110 -ReqRows 9100 -ReqBpr 211 -RanAt 16
        Complete-Run -Report 'R' -Fp 'q2' -Start 16 -Final 16 -Source 'cache' -ReqRows 9100 -ReqBpr 211 | Should -Match '4 x'
    }
    It 'sized from a measurement but raised in the run: judged as before' {
        Set-BucketRun -Report 'R' -History $script:Legacy -Rows 110 -ReqRows 9100 -ReqBpr 211 -RanAt 8
        Complete-Run -Report 'R' -Fp 'q2' -Start 8 -Final 16 -Source 'measured' -ReqRows 9100 -ReqBpr 211 | Should -Match '4 x'
    }
    It 'materially = at least 2 x: rows or request at 2 x warn, just under does not' {
        $prev = New-HRow -Count 4 -Rows 100 -ReqRows 9000 -ReqBpr 200 -ReqOver 0
        Test-SIRaBucketInputGrew -Previous $prev -Current ([pscustomobject]@{ ResultRows = 199; RequestRows = 9000; RequestBytesPerRow = 200; RequestOverheadBytes = 0 }) | Should -BeFalse
        Test-SIRaBucketInputGrew -Previous $prev -Current ([pscustomobject]@{ ResultRows = 200; RequestRows = 9000; RequestBytesPerRow = 200; RequestOverheadBytes = 0 }) | Should -BeTrue
        Test-SIRaBucketInputGrew -Previous $prev -Current ([pscustomobject]@{ ResultRows = 100; RequestRows = 18000; RequestBytesPerRow = 200; RequestOverheadBytes = 0 }) | Should -BeTrue
        Test-SIRaBucketInputGrew -Previous $null -Current ([pscustomobject]@{ ResultRows = 100 }) | Should -BeTrue -Because 'nothing to compare: judged as before'
    }
    It 'the jump test itself: sized + not grown = no warning; sized + grown = as before' {
        Test-SIRaBucketJump -Count 16 -Usual 4 -SizedFromMeasure -InputGrew $false | Should -Be ''
        Test-SIRaBucketJump -Count 16 -Usual 4 -SizedFromMeasure -InputGrew $true | Should -Match '4 x'
        Test-SIRaBucketJump -Count 16 -Usual 4 | Should -Match '4 x' -Because 'the default is unchanged'
    }
}

Describe 'rule 3: a lower count is proved only by a run that carried as large a request' {
    It 'a complete run at fewer slices from before the lookup grew is ignored' {
        $h = @((New-HRow -Count 2 -Fp 'f' -ReqRows 1000 -ReqBpr 200), (New-HRow -Count 4 -Fp 'f' -ReqRows 9000 -ReqBpr 200))
        $now = [pscustomobject]@{ RequestRows = 9500; RequestBytesPerRow = 200; RequestOverheadBytes = 4000 }
        Get-SIRaBucketCompleteLowerCount -Count 8 -History $h -Fingerprint 'f' | Should -Be 2 -Because 'without -Current: as before'
        Get-SIRaBucketCompleteLowerCount -Count 8 -History $h -Fingerprint 'f' -Current $now | Should -Be 4 -Because 'the 2-slice run carried a ninth of the request'
    }
    It 'within 15 % the run still proves its count; a run without request numbers is used as before' {
        $h = @((New-HRow -Count 2 -Fp 'f' -ReqRows 9000 -ReqBpr 200))
        Get-SIRaBucketCompleteLowerCount -Count 8 -History $h -Fingerprint 'f' -Current ([pscustomobject]@{ RequestRows = 10000; RequestBytesPerRow = 200; RequestOverheadBytes = 4000 }) | Should -Be 2
        Get-SIRaBucketCompleteLowerCount -Count 8 -History $h -Fingerprint 'f' -Current ([pscustomobject]@{ RequestRows = 11000; RequestBytesPerRow = 200; RequestOverheadBytes = 4000 }) | Should -Be 0
        Get-SIRaBucketCompleteLowerCount -Count 8 -History @((New-HRow -Count 2 -Fp 'f')) -Fingerprint 'f' -Current ([pscustomobject]@{ RequestRows = 11000; RequestBytesPerRow = 200 }) | Should -Be 2
    }
    It 'without split numbers the request total is the largest request times the count it was sent at' {
        Get-SIRaBucketRequestTotal -Run ([pscustomobject]@{ MaxRequestBytes = 100000; RanCount = 4 }) | Should -Be 400000
        Get-SIRaBucketRequestTotal -Run ([pscustomobject]@{ MaxRequestBytes = 100000; RanCount = 4 }) -SentAt 8 | Should -Be 800000
        Get-SIRaBucketRequestTotal -Run ([pscustomobject]@{ RequestRows = 10; RequestBytesPerRow = 100; RequestOverheadBytes = 50; MaxRequestBytes = 999999 }) | Should -Be 1050
        Get-SIRaBucketRequestTotal -Run ([pscustomobject]@{ ResultRows = 5 }) | Should -Be 0
    }
    It 'the engine passes this run''s request to the size-down rule' {
        $eng = Get-Content -Raw (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
        $eng | Should -Match 'Get-SIRaBucketCompleteLowerCount -Count \(\[int\]\$bucketCountToUse\) -History [^\r\n]*-Current \$__abNow -CurrentSentAt \(\[int\]\$bucketCountToUse\)'
        $eng | Should -Match '\$__abReqNow = Get-AutoBucketRequestMeasure -Measure \$script:AutoBucketMeasure'
    }
}

Describe 'rule 4: a real jump still warns exactly as before' {
    It 'same query version, rows 4 x, count raised 2 -> 8: warns' {
        Set-BucketRun -Report 'R' -History @((New-HRow -Count 2 -Fp 'f' -Rows 20000), (New-HRow -Count 2 -Fp 'f' -Rows 20000), (New-HRow -Count 2 -Fp 'f' -Rows 20000)) -Rows 80000
        Complete-Run -Report 'R' -Fp 'f' -Start 2 -Final 8 -Source 'cache' | Should -Match '8 buckets is 4 x or more its usual 2'
        $script:Captured[0].Jump | Should -BeTrue
        $script:AutoBucketJumps.Count | Should -Be 1
    }
    It 'sized from a measurement with the request grown 4 x: warns' {
        $h = @(foreach ($i in 1..3) { New-HRow -Count 4 -Fp '' -Rows 50 -ReqRows 5000 -ReqBpr 200 })
        Set-BucketRun -Report 'R' -History $h -Rows 50 -ReqRows 20000 -ReqBpr 200 -RanAt 16
        Complete-Run -Report 'R' -Fp 'q2' -Start 16 -Final 16 -Source 'measured' -ReqRows 20000 -ReqBpr 200 | Should -Match '4 x'
    }
    It 'above 256 still warns without any history' {
        Set-BucketRun -Report 'R' -History @() -Rows 10
        Complete-Run -Report 'R' -Fp 'f' -Start 300 -Final 300 -Source 'cache' | Should -Match 'above 256'
    }
}

Describe 'the live cases replayed' {
    It 'install A, the run after the query change (16, sized from its measurement): no warning' {
        Set-BucketRun -Report $script:A -History $script:AHistory -Rows 11 -ReqRows 19739 -ReqBpr 214 -RanAt 16
        Complete-Run -Report $script:A -Fp $script:ANew -Start 16 -Final 16 -Source 'measured' -ReqRows 19739 -ReqBpr 214 | Should -Be ''
        $script:Captured[0].UsualCount | Should -BeNullOrEmpty -Because 'no earlier run of the new query version'
        # before #1202 the usual over the report NAME was 4 here and 16 warned (live: "16 buckets is 4 x or more its usual")
        Get-SIRaBucketUsual -Counts @($script:AHistory | ForEach-Object { [int]$_.BucketCount }) | Should -Be 4
    }
    It 'install A, the next runs on the new query at 16: no warning, and the count is judged against 16 once known' {
        $h = @($script:AHistory)
        foreach ($i in 1..4) {
            Set-BucketRun -Report $script:A -History $h -Rows 11 -ReqRows 19800 -ReqBpr 214 -RanAt 16
            Complete-Run -Report $script:A -Fp $script:ANew -Start 16 -Final 16 -Source 'cache' -ReqRows 19800 -ReqBpr 214 | Should -Be ''
            $h = @((New-HRow -Count 16 -Fp $script:ANew -Rows 11 -ReqRows 19800 -ReqBpr 214)) + $h
        }
        Get-SIRaBucketUsual -Counts (Get-SIRaBucketSameQueryCounts -History $h -Fingerprint $script:ANew) | Should -Be 16
    }
    It 'install A, the old query at 8 with the lookup at 4.1 MB: no step down to 4 (no more swing between 4 and 8)' {
        $h = @($script:AHistory | Select-Object -Skip 1)   # as of the day-8 run, which ran at 8
        $now = [pscustomobject]@{ RequestRows = 19300; RequestBytesPerRow = 214; RequestOverheadBytes = 4000 }
        # before #1202: the complete run at 1 slice from day 1 (0.25 MB) proved "1", so 8 came down to 4 and was raised again
        Get-SIRaBucketCompleteLowerCount -Count 8 -History $h -Fingerprint $script:AOld | Should -BeGreaterThan 0
        Get-SIRaBucketCompleteLowerCount -Count 8 -History $h -Fingerprint $script:AOld -Current $now -CurrentSentAt 8 | Should -Be 0
        # and on the new query version at 16 nothing of the old query proves a lower count
        Get-SIRaBucketCompleteLowerCount -Count 16 -History $script:AHistory -Fingerprint $script:ANew -Current $now -CurrentSentAt 16 | Should -Be 0
    }
    It 'install A, the old query: the 4 and 8 counts were not a jump against the same version' {
        $h = @($script:AHistory | Select-Object -Skip 2)   # as of the day-7 run, raised 4 -> 8
        Set-BucketRun -Report $script:A -History $h -Rows 11 -ReqRows 18700 -ReqBpr 214 -RanAt 4
        Complete-Run -Report $script:A -Fp $script:AOld -Start 4 -Final 8 -Source 'cache' -ReqRows 18700 -ReqBpr 214 | Should -Be ''
    }
    It 'install B, the run after the query change (16, rows 80, lookup flat): no warning' {
        Set-BucketRun -Report $script:B -History $script:BHistory -Rows 80 -ReqRows 9000 -ReqBpr 211 -ReqOver 6000 -RanAt 16
        Complete-Run -Report $script:B -Fp $script:BNew -Start 16 -Final 16 -Source 'measured' -ReqRows 9000 -ReqBpr 211 -ReqOver 6000 | Should -Be ''
        $script:Captured[0].Jump | Should -BeFalse
        # and even with the usual of 4 (rows without a version) the flat input keeps the sized count quiet (rule 2)
        $legacy = @($script:BHistory | ForEach-Object { $x = $_.PSObject.Copy(); $x.Fingerprint = ''; $x })
        Set-BucketRun -Report $script:B -History $legacy -Rows 80 -ReqRows 9000 -ReqBpr 211 -ReqOver 6000 -RanAt 16
        Complete-Run -Report $script:B -Fp $script:BNew -Start 16 -Final 16 -Source 'measured' -ReqRows 9000 -ReqBpr 211 -ReqOver 6000 | Should -Be ''
    }
}
