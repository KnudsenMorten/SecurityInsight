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

Describe '🔑 WIRING -- every loss path must actually report' {

    It 'the engine defines the accounting surface' {
        $script:CodeNC | Should -Match 'function Reset-RABucketLoss'
        $script:CodeNC | Should -Match 'function Add-RABucketLoss'
        $script:CodeNC | Should -Match 'function Write-RABucketLossVerdict'
    }

    It 'the per-report list is RESET where the bucket loop begins' {
        $script:CodeNC | Should -Match 'Reset-RABucketLoss'
    }

    It 'there are exactly THIRTEEN Add-RABucketLoss call sites' {
        # One per known loss path. If another path is introduced this fails and forces the author to
        # account for it rather than add another silent drop.
        # Was SIX. #118 (2026-09-28) made every recovery reachable before a loss is recorded, and
        # counted the places rows were still being dropped UNCOUNTED: the futile skip, the futile prune,
        # a sub-bucket conversion failure, the escalation-cap safety net, and the late-retry pass (which
        # has its own conversion + exhausted-retry paths). ELEVEN -> TEN 2026-10-10: loss path 1 (skip the
        # remaining buckets after a 900s ceiling) keyed on a flag nothing ever set, so it could never run;
        # the branch was removed with its recording line (SIv3-NoUnwiredRiskAnalysisCode).
        $calls = [regex]::Matches($script:CodeNC, '(?m)^\s*Add-RABucketLoss ')
        $calls.Count | Should -Be 14   # (merged 2026-10-22: - the futile-prune, one mechanism) #882 (2026-10-22): the late retry's slices still refused when a pass recovers nothing are named apart from its defect / unrecognised failure; #880 (2026-10-22): a sub-slice not split further because splitting did not reduce its bucket's failure; #641 (2026-10-13): a slice that stays SHORT against the source's count of it -- main loop and sub-buckets; #803 (2026-10-19): a sub-slice too large for memory even at the deepest split
    }

    It 'LOSS PATH 2 -- a throttled/unavailable API survived BOTH the in-loop and the late retries' {
        # A throttled bucket is no longer written off when its in-loop retries run out -- it is deferred
        # to a late retry after the other buckets. Only that exhausting too is a loss.
        $script:CodeNC | Should -Match 'the in-loop AND late retries'
        $script:CodeNC | Should -Match 'API throttling/unavailable survived'   # #880: or "Defender kept refusing it as busy"
    }

    It 'LOSS PATH 3 -- a query defect or an unrecognised failure' {
        $script:CodeNC | Should -Match 'Add-RABucketLoss \("bucket \{0\}/\{1\}: \{2\} -- \{3\}" -f \$bucketNo, \$bucketCountToUse, \$whyLost, \$errMsg\)'
    }

    It 'the paths #118 found dropping rows UNCOUNTED now record them' {
        $script:CodeNC | Should -Match 'sub-bucket pass skipped as futile'
        # (2026-10-22, one mechanism) the futile-prune is gone; its slices are now the #880 stop's named loss
        $script:CodeNC | Should -Match 'not split further -- splitting did not reduce the failure'
        $script:CodeNC | Should -Match 'never run -- escalation cap'
        $script:CodeNC | Should -Match 'late retry succeeded but result conversion threw'
    }

    It 'LOSS PATH 4 -- the query SUCCEEDED but conversion threw' {
        # The most deceptive of the six: nothing upstream reports a failure at all.
        $script:CodeNC | Should -Match 'query succeeded but result conversion threw'
    }

    It 'LOSS PATHS 5 and 6 -- sub-bucket max-depth and non-timeout failures' {
        $script:CodeNC | Should -Match 'the key partition cannot be split finer'   # (2026-10-22) no depth cap: only the partition's end
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
        $queueIdx = $script:Code.IndexOf('queueing for the sub-bucket pass')
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

Describe '🔴 EXECUTION -- every recording line is RUN from the shipped source, not just present' {
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
        # Variables the #118 recording lines use.
        $script:whyLost                = 'query failed'
        $script:lb                     = 11
        $script:capBucket              = 64
        $script:dbNo                   = 12
        $script:conv                   = @{ Ok = $false; Rows = @(); Error = 'conversion boom' }
        $script:dbErr                  = '429 Too Many Requests'
        $script:skippedIdx             = 4
        $script:subConv                = @{ Ok = $false; Rows = @(); Error = 'conversion boom' }
        $script:subWhy                 = 'failed (non-timeout)'
        $script:q                      = @{ N = 9; T = 32; D = 3; PK = '1/8/2' }
        $script:thisParentKey          = '1/8/2'
        # #848: a slice too large for the worker's memory at the finest split (the row split at the hash's range)
        $script:__mk                   = @{ N = 5; T = 4096; RC = 4294967296L; RI = 3L; Why = 'its answer is too large for this worker''s memory' }
        # #882: the late retry's passes -- a slice still refused when a pass recovered nothing
        $script:db                     = 11
        $script:__lpErr                = @{ 11 = '504 Gateway Timeout' }
        $script:__lateWhy              = 'API throttling/unavailable survived'
        $script:__lp                   = [pscustomobject]@{ Pass = 3 }
    }

    It 'every recording line was lifted out of the engine' {
        $script:LossLines.Count | Should -Be 14   # (merged 2026-10-22: - the futile-prune, one mechanism) #882: + the late retry's slices still refused after a pass that recovered nothing; #880: + a sub-slice not split further (splitting did not reduce the failure); #803: + a sub-slice too large for memory at the deepest split; #641: + the two short-slice paths; loss path 1 was unreachable and is removed (see the call-site count)
    }

    It '🔴 EVERY one of them, executed verbatim, records exactly one loss' {
        foreach ($line in $script:LossLines) {
            Reset-RABucketLoss
            $b = $script:b; $bucketNo = $script:bucketNo; $bucketCountToUse = $script:bucketCountToUse
            $errMsg = $script:errMsg; $bucketTransientRetries = $script:bucketTransientRetries
            $depth = $script:depth; $pN = $script:pN; $pT = $script:pT
            $j = $script:j; $subFanOut = $script:subFanOut; $subErr = $script:subErr
            $whyLost = $script:whyLost; $lb = $script:lb; $capBucket = $script:capBucket
            $dbNo = $script:dbNo; $conv = $script:conv; $dbErr = $script:dbErr; $skippedIdx = $script:skippedIdx
            $subConv = $script:subConv; $subWhy = $script:subWhy; $q = $script:q; $thisParentKey = $script:thisParentKey
            $db = $script:db; $__lpErr = $script:__lpErr; $__lateWhy = $script:__lateWhy; $__lp = $script:__lp
            $__mk = $script:__mk

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
            $whyLost = $script:whyLost; $lb = $script:lb; $capBucket = $script:capBucket
            $dbNo = $script:dbNo; $conv = $script:conv; $dbErr = $script:dbErr; $skippedIdx = $script:skippedIdx
            $subConv = $script:subConv; $subWhy = $script:subWhy; $q = $script:q; $thisParentKey = $script:thisParentKey
            $db = $script:db; $__lpErr = $script:__lpErr; $__lateWhy = $script:__lateWhy; $__lp = $script:__lp
            $null = & ([scriptblock]::Create($line))
            $script:_RABucketLoss[0] | Should -Match '(bucket \d+/\d+|sub-bucket depth=\d+|sub-bucket index \d+/\d+)'
        }
    }
}
