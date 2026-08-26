#Requires -Version 5.1
<#
    AUDIT #62 -- A FAILED BUCKET SILENTLY SHRANK A REPORT, AND THE RUN LOOKED CLEAN.

    Found in a customer run 2026-08-26. `Device_Recommendations_Detailed` lost buckets 10 and 11 of 26
    to HTTP 500 after all four retries. The engine printed two `[ERR] query failed for bucket N/26`
    lines and ran to completion normally: no report-level total, no run-level total, nothing in
    SI_RunHealth_CL, and the email went out looking healthy.

    Measured against the previous night on the same estate:
        raw rows      162,495 -> 150,148
        after dedup    15,220 ->  14,084     (~1,100 findings simply absent)

    ⚠️ `RowCountGuard` CANNOT catch this and printed "no report lost its findings". It asks whether a
    report lost ALL of its findings; this one still produced 14,084 rows, so it passed. Same shape as
    #58.5 (every row present, the columns blank): THE RUN LOOKS CLEAN AND THE DATA IS PARTIAL.

    🔑 THE WIRING BLOCK IS THE POINT OF THIS FILE. Accounting helpers that nothing calls would be the
    eleventh "declared but never wired" case in this codebase. There are SIX paths that drop a
    bucket's rows and a fix covering only the one in the customer's log would have left five silent,
    so each is asserted individually.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:Engine = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    $script:Code   = Get-Content $script:Engine -Raw

    # Comment-stripped copy: the block comments in the engine QUOTE the call names they describe, so a
    # naive match counts prose as code. (Learned the hard way in SI-ExcelBulkExport.Tests.ps1.)
    $script:CodeNC = (($script:Code -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

    # The engine is a single large script that cannot be dot-sourced standalone, so the three
    # accounting functions are lifted out by AST and defined here verbatim -- the same technique the
    # rest of this suite uses. That way the behaviour tests exercise the SHIPPING source text, not a
    # copy that can drift away from it.
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Engine, [ref]$null, [ref]$null)
    $wanted = @('Reset-RABucketLoss', 'Add-RABucketLoss', 'Write-RABucketLossVerdict')
    $fns = $ast.FindAll({
        param($n)
        $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $wanted -contains $n.Name
    }, $true)
    foreach ($f in $fns) { . ([scriptblock]::Create($f.Extent.Text)) }

    # Capture what the verdict prints instead of writing to the host.
    $script:Emitted = New-Object System.Collections.Generic.List[string]
    function global:Write-Err2 { param([string]$m) [void]$script:Emitted.Add($m) }
}

Describe 'the accounting helpers' {

    BeforeEach {
        $script:Emitted = New-Object System.Collections.Generic.List[string]
        $script:_RABucketLossRun = New-Object System.Collections.Generic.List[string]
        Reset-RABucketLoss
    }

    It 'a clean report prints NOTHING -- silence must stay the normal case' {
        # If a healthy report emitted a verdict line, operators would learn to ignore it, and the one
        # run that mattered would scroll past unnoticed.
        Write-RABucketLossVerdict -ReportName 'X' -BucketCount 26 -RowsKept 14084
        $script:Emitted.Count | Should -Be 0
    }

    It 'a lost bucket produces a verdict naming the report, the counts and the rows kept' {
        Add-RABucketLoss 'bucket 10/26: query failed -- 500'
        Write-RABucketLossVerdict -ReportName 'Device_Recommendations_Detailed' -BucketCount 26 -RowsKept 14084
        $joined = $script:Emitted -join "`n"
        $joined | Should -Match 'INCOMPLETE REPORT'
        $joined | Should -Match 'Device_Recommendations_Detailed'
        $joined | Should -Match '1 of 26'
        $joined | Should -Match '14084'
    }

    It 'the verdict says the rows are PARTIAL, not merely fewer' {
        # "fewer rows" reads as a real-world change; "partial" is the fact that matters.
        Add-RABucketLoss 'bucket 11/26: query failed -- 500'
        Write-RABucketLossVerdict -ReportName 'R' -BucketCount 26 -RowsKept 100
        ($script:Emitted -join "`n") | Should -Match 'PARTIAL'
    }

    It 'the verdict explicitly disclaims the row-count guard' {
        # The guard is what an operator trusts to mean "nothing went missing", and it passed green on
        # the run that lost 1,100 findings. Saying so at the point of loss is the whole fix.
        Add-RABucketLoss 'bucket 10/26: query failed -- 500'
        Write-RABucketLossVerdict -ReportName 'R' -BucketCount 26 -RowsKept 100
        ($script:Emitted -join "`n") | Should -Match 'row-count regression the guard can see'
    }

    It 'the verdict tells the operator to re-run -- these losses are transient, not a data condition' {
        Add-RABucketLoss 'bucket 10/26: query failed -- 500'
        Write-RABucketLossVerdict -ReportName 'R' -BucketCount 26 -RowsKept 100
        ($script:Emitted -join "`n") | Should -Match 'RE-RUN'
    }

    It 'each lost bucket is listed individually, not just counted' {
        Add-RABucketLoss 'bucket 10/26: query failed -- 500'
        Add-RABucketLoss 'bucket 11/26: query failed -- 500'
        Write-RABucketLossVerdict -ReportName 'R' -BucketCount 26 -RowsKept 100
        @($script:Emitted | Where-Object { $_ -match 'lost bucket --' }).Count | Should -Be 2
    }

    It 'losses roll up to the RUN list, tagged with the report they came from' {
        Add-RABucketLoss 'bucket 10/26: query failed -- 500'
        Write-RABucketLossVerdict -ReportName 'Device_Recommendations_Detailed' -BucketCount 26 -RowsKept 1
        $script:_RABucketLossRun.Count | Should -Be 1
        $script:_RABucketLossRun[0]    | Should -Match '^Device_Recommendations_Detailed :: '
    }

    It '🔑 Reset clears the PER-REPORT list but never the RUN list' {
        # Get this backwards and either one report inherits the previous report's losses, or the
        # run-level roll-up is empty at the end -- the exact silence #62 is about.
        Add-RABucketLoss 'bucket 1/2: query failed -- x'
        Write-RABucketLossVerdict -ReportName 'A' -BucketCount 2 -RowsKept 1
        Reset-RABucketLoss
        Write-RABucketLossVerdict -ReportName 'B' -BucketCount 2 -RowsKept 1   # B is clean
        $script:_RABucketLossRun.Count | Should -Be 1
        ($script:_RABucketLossRun -join '') | Should -Match '^A :: '
    }
}

Describe '🔑 WIRING -- all SIX loss paths must actually report' {

    It 'the engine defines the accounting surface' {
        $script:CodeNC | Should -Match 'function Reset-RABucketLoss'
        $script:CodeNC | Should -Match 'function Add-RABucketLoss'
        $script:CodeNC | Should -Match 'function Write-RABucketLossVerdict'
    }

    It 'the per-report list is RESET where the bucket loop begins' {
        $script:CodeNC | Should -Match 'Reset-RABucketLoss'
    }

    It 'there are exactly SIX Add-RABucketLoss call sites' {
        # One per known loss path. If a seventh path is introduced this fails and forces the author to
        # account for it rather than add another silent drop.
        $calls = [regex]::Matches($script:CodeNC, '(?m)^\s*Add-RABucketLoss ')
        $calls.Count | Should -Be 6
    }

    It 'LOSS PATH 2 -- transient retries exhausted' {
        $script:CodeNC | Should -Match 'transient platform error survived all'
    }

    It 'LOSS PATH 3 -- any other query failure' {
        $script:CodeNC | Should -Match 'Add-RABucketLoss \("bucket \{0\}/\{1\}: query failed'
    }

    It 'LOSS PATH 4 -- the query SUCCEEDED but conversion threw' {
        # The most deceptive of the six: nothing upstream reports a failure at all.
        $script:CodeNC | Should -Match 'query succeeded but result conversion threw'
    }

    It 'LOSS PATHS 5 and 6 -- sub-bucket max-depth and non-timeout failures' {
        $script:CodeNC | Should -Match 'still timing out at MAX DEPTH'
        $script:CodeNC | Should -Match 'failed \(non-timeout\)'
    }

    It '🔴 the verdict is emitted immediately after the row total it qualifies' {
        # Printed anywhere else, an operator reads the total as complete.
        $iTotal   = $script:Code.IndexOf('total rows across all buckets')
        $iVerdict = $script:Code.IndexOf('Write-RABucketLossVerdict -ReportName')
        $iTotal   | Should -BeGreaterThan 0
        $iVerdict | Should -BeGreaterThan $iTotal
        ($iVerdict - $iTotal) | Should -BeLessThan 700
    }

    It '🔴 a bucket RECOVERED by sub-bucketing is NOT counted as lost' {
        # The 900s path queues the bucket for splitting and is expected to succeed; only paths 5/6
        # record a loss. Counting the queue-for-split would fire INCOMPLETE on healthy runs, and a
        # false alarm here is worse than none -- it retrains the operator to ignore the line.
        $queueIdx = $script:Code.IndexOf('queueing for sub-bucket pass')
        $queueIdx | Should -BeGreaterThan 0
        $window = $script:Code.Substring($queueIdx, [Math]::Min(400, $script:Code.Length - $queueIdx))
        $window | Should -Not -Match 'Add-RABucketLoss'
    }
}

Describe '🔑 WIRING -- the run-level roll-up and SI_RunHealth_CL' {

    It 'a run-level roll-up exists' {
        $script:CodeNC | Should -Match '_RABucketLossRun'
        $script:Code   | Should -Match 'INCOMPLETE DATA -- buckets lost this run'
    }

    It '🔴 the roll-up is printed ABOVE the row-count guard' {
        # The guard is the line an operator trusts to mean "nothing went missing", and it printed
        # green on the run that lost ~1,100 findings. The contradiction has to be read first.
        $iRoll  = $script:Code.IndexOf('INCOMPLETE DATA -- buckets lost this run')
        $iGuard = $script:Code.IndexOf('Write-Section "row-count guard"')
        $iRoll  | Should -BeGreaterThan 0
        $iGuard | Should -BeGreaterThan 0
        $iRoll  | Should -BeLessThan $iGuard
    }

    It 'the roll-up states that the row-count guard cannot detect this class' {
        $script:Code | Should -Match 'row-count guard below CANNOT detect this'
    }

    It 'a CLEAN run says so explicitly rather than printing nothing' {
        # Absence of a warning is not evidence the check ran -- #27's lesson. One positive line means
        # an operator can tell "no losses" from "the accounting silently broke".
        $script:Code | Should -Match '\[BucketLoss\] every bucket in every report contributed'
    }

    It '🔴 a run that lost buckets no longer reports a bare success to SI_RunHealth_CL' {
        $script:CodeNC | Should -Match "success-partial"
    }

    It 'the degrade happens inside Send-RARunHealthEnd, so every call site is covered' {
        # Doing it at the one known call site would leave any future/error path reporting clean.
        $iFn   = $script:Code.IndexOf('function Send-RARunHealthEnd')
        $iDeg  = $script:Code.IndexOf("success-partial")
        $iSend = $script:Code.IndexOf('Send-SIRunHealthRow -RunContext $script:_RunHealthCtx -Phase ''End''')
        $iFn   | Should -BeGreaterThan 0
        $iDeg  | Should -BeGreaterThan $iFn
        $iSend | Should -BeGreaterThan $iDeg
    }

    It 'the run-health degrade is guarded so it can never break the heartbeat' {
        # The heartbeat is the crash-detection signal. Accounting must never be able to suppress it.
        $iDeg = $script:Code.IndexOf("success-partial")
        $pre  = $script:Code.Substring([Math]::Max(0, $iDeg - 400), [Math]::Min(400, $iDeg))
        $pre  | Should -Match 'try \{'
    }
}

Describe '🔴 EXECUTION -- the six recording lines are RUN from the shipped source, not just present' {
    # Everything above proves the six Add-RABucketLoss lines EXIST in the right branches. That is
    # textual evidence, and this codebase has shipped textually-correct-but-unreachable code before.
    # This block lifts each line VERBATIM out of the engine and EXECUTES it with the variables its
    # branch would have in scope, then asserts a loss was actually recorded. If a line were ever
    # edited into something that cannot run -- a renamed variable, a broken format string, a wrong
    # argument count -- these fail, and the textual assertions above would not.

    BeforeAll {
        $script:LossLines = @(
            Select-String -Path $script:Engine -Pattern '^\s*Add-RABucketLoss \(' |
                ForEach-Object { $_.Line.Trim() }
        )
        # Every variable each branch would legitimately have in scope at that point.
        $script:b                      = 9
        $script:bucketNo               = 10
        $script:bucketCountToUse       = 26
        $script:errMsg                 = 'Internal Server Error'
        $script:bucketTransientRetries = 4
        $script:depth                  = 6
        $script:pN                     = 1
        $script:pT                     = 2
        $script:j                      = 3
        $script:subFanOut              = 4
        $script:subErr                 = 'timed out'
    }

    It 'six recording lines were lifted out of the engine' {
        $script:LossLines.Count | Should -Be 6
    }

    It '🔴 EVERY one of them, executed verbatim, records exactly one loss' {
        foreach ($line in $script:LossLines) {
            Reset-RABucketLoss
            $b = $script:b; $bucketNo = $script:bucketNo; $bucketCountToUse = $script:bucketCountToUse
            $errMsg = $script:errMsg; $bucketTransientRetries = $script:bucketTransientRetries
            $depth = $script:depth; $pN = $script:pN; $pT = $script:pT
            $j = $script:j; $subFanOut = $script:subFanOut; $subErr = $script:subErr

            { & ([scriptblock]::Create($line)) } | Should -Not -Throw -Because "this line ships in the engine: $line"
            $script:_RABucketLoss.Count | Should -Be 1 -Because "executing it must record a loss: $line"

            # And the recorded text must be usable -- a format string that silently produced
            # "{0}/{1}" instead of "10/26" would satisfy a count check while telling an operator
            # nothing about WHICH bucket was lost.
            $script:_RABucketLoss[0] | Should -Not -Match '\{\d\}' -Because "unformatted placeholder left in: $line"
            $script:_RABucketLoss[0] | Should -Not -BeNullOrEmpty
        }
    }

    It 'the recorded text identifies the bucket or sub-bucket concretely' {
        foreach ($line in $script:LossLines) {
            Reset-RABucketLoss
            $b = $script:b; $bucketNo = $script:bucketNo; $bucketCountToUse = $script:bucketCountToUse
            $errMsg = $script:errMsg; $bucketTransientRetries = $script:bucketTransientRetries
            $depth = $script:depth; $pN = $script:pN; $pT = $script:pT
            $j = $script:j; $subFanOut = $script:subFanOut; $subErr = $script:subErr
            $null = & ([scriptblock]::Create($line))
            $script:_RABucketLoss[0] | Should -Match '(bucket \d+/\d+|sub-bucket depth=\d+)'
        }
    }
}
