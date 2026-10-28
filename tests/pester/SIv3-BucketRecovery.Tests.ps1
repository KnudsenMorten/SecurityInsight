#Requires -Version 5.1
<#
    A BUCKET IS NEVER WRITTEN OFF WHILE A RECOVERY IS LEFT (#118).

    Operator, 2026-09-28: "it is very important that we dont loose data in this solution, so retries,
    selfhealing, buckets are weapons to solve this" and "it must take into account that api can throttle
    or have issues".

    So every failed bucket is routed by CAUSE through ONE classifier, Get-RABucketFailureAction:
      Split  -- too large / too slow (900s ceiling, 502, overflow, the #99/#106 platform cancellations):
                a SMALLER slice is the fix -> sub-bucket pass
      Retry  -- the API is throttling or had an issue (429/503/504/401/token expiry): same size, backoff
                + re-auth, then a LATE retry after the other buckets. NEVER split -- splitting multiplies
                calls against a throttling API
      Defect -- the query is wrong: fail on attempt 1 (working rule 4)
      Fail   -- unrecognised: lost, loudly

    What this file pins, and what was broken before it:
      * the #99/#106 cancellations fell through every classifier in the main loop ("cancelled" is not
        "canceled"; 400 is not transient) and were recorded LOST without ever being resized;
      * a throttled bucket that exhausted its retries was written off -- now deferred to a late retry;
      * an overflow AT the escalation cap `break`-ed and silently never ran the remaining buckets;
      * the futile skip, the futile prune and a sub-bucket conversion failure dropped rows uncounted;
      * the hunting layer's "all timed out" flag leaked from one call to the next.
    The engine is one large script that cannot be dot-sourced, so the wiring half is asserted on the
    comment-stripped source -- the same technique SI-BucketLossAccounting uses.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $hunting = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'
    $bucket  = Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1'
    . $hunting
    . $bucket

    $script:Engine = Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
    $raw = Get-Content -LiteralPath $script:Engine -Raw
    $raw = [regex]::Replace($raw, '(?s)<#.*?#>', '')
    $script:CodeNC = (($raw -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
    $hraw = [regex]::Replace((Get-Content -LiteralPath $hunting -Raw), '(?s)<#.*?#>', '')
    $script:HuntNC = (($hraw -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

    # Verbatim service messages (from the #99 and #106 transcripts), and a genuine defect as control.
    $script:Msg99     = '400 Bad Request -- [BadRequest] : ScalarEvaluator.Evaluate failed: Query cancelled on creation:. Fix semantic errors in your query.'
    $script:Msg106    = "400 Bad Request -- [BadRequest] : Errors occurred while resolving remote entities. Failed to resolve name or pattern 'TvmSCASnapshotCooked' in one or more scopes: (`$Cluster='', Database=''). Fix semantic errors in your query."
    $script:MsgDefect = "400 Bad Request -- [BadRequest] : Fix semantic errors in your query. 'case' operator: the return types are not compatible"
}

Describe 'Get-RABucketFailureAction routes a failure to the recovery that matches its cause' {

    It 'the #99 platform cancellation is SPLIT, not lost and not called a defect' {
        Get-RABucketFailureAction -Err $script:Msg99 | Should -Be 'Split'
    }
    It 'the #106 remote-entity failure is SPLIT' {
        Get-RABucketFailureAction -Err $script:Msg106 | Should -Be 'Split'
    }
    It 'a genuine semantic error is a DEFECT (fail on attempt 1, rule 4)' {
        Get-RABucketFailureAction -Err $script:MsgDefect | Should -Be 'Defect'
    }
    It 'a syntax error is a DEFECT' {
        Get-RABucketFailureAction -Err '400 Bad Request -- Fix syntax errors in your query. Expected: )' | Should -Be 'Defect'
    }
    It 'the 900s client ceiling is SPLIT' {
        Get-RABucketFailureAction -Err 'TaskCanceledException: the request was canceled due to the configured timeout of 900 seconds elapsing.' | Should -Be 'Split'
    }
    It 'a 502 from the proxy is SPLIT' {
        Get-RABucketFailureAction -Err '502 Bad Gateway -- <html>upstream</html>' | Should -Be 'Split'
    }
    It 'a result-size overflow is SPLIT' {
        Get-RABucketFailureAction -Err 'Query execution has exceeded the allowed result size' | Should -Be 'Split'
        Get-RABucketFailureAction -Err 'Query execution has exceeded the allowed limits' | Should -Be 'Split'
    }
    It 'a preempted (busy backend) answer is RETRIED at the same size, never split (#880)' {
        Get-RABucketFailureAction -Err 'Query execution has exceeded the allowed limits ... preempted' | Should -Be 'Retry'
    }
    It 'the hunting layer''s own "every attempt hit the ceiling" verdict is SPLIT' {
        Get-RABucketFailureAction -Err 'something the text classifiers do not know' -AllTimedOut $true | Should -Be 'Split'
    }

    Context 'the API throttling or having an issue is RETRIED, never split' {
        It '<Name> -> Retry' -ForEach @(
            @{ Name = '429';                 Msg = '429 Too Many Requests -- throttled' }
            @{ Name = '503';                 Msg = '503 Service Unavailable -- ' }
            @{ Name = '504';                 Msg = '504 Gateway Timeout -- ' }
            @{ Name = 'expired token';       Msg = '401 HTTP error -- InvalidAuthenticationToken: Access token has expired' }
            @{ Name = 'connection timeout';  Msg = 'The operation has timed out.' }
        ) {
            Get-RABucketFailureAction -Err $Msg | Should -Be 'Retry'
        }
        It 'a 429 stays RETRY even when the hunting layer flagged a timeout (throttle wins -- never multiply calls)' {
            Get-RABucketFailureAction -Err '429 Too Many Requests' -AllTimedOut $true | Should -Be 'Retry'
        }
        It '#882: a 504 Gateway Timeout is a busy platform -- RETRY at the same size even when every attempt timed out (never split)' {
            Get-RABucketFailureAction -Err '504 Gateway Timeout -- ' -AllTimedOut $true | Should -Be 'Retry'
            Get-RABucketFailureAction -Err 'Response status code does not indicate success: 504 (Gateway Time-out).' -AllTimedOut $true | Should -Be 'Retry'
        }
    }

    It 'an unrecognised failure is FAIL (recorded lost, loudly) -- not silently retried forever' {
        Get-RABucketFailureAction -Err 'something entirely unexpected' | Should -Be 'Fail'
    }

    It 'the PROBE classifier learns the platform cancellations too, so it can pick a higher bucket count' {
        Test-IsDeterministicTooLargeError -Err $script:Msg99  | Should -BeTrue
        Test-IsDeterministicTooLargeError -Err $script:Msg106 | Should -BeTrue
        Test-IsDeterministicTooLargeError -Err '429 Too Many Requests' | Should -BeFalse
    }
}

Describe 'Test-IsBucketOverflowError never mistakes a throttle for an overflow' {
    It '429 Too Many Requests is NOT an overflow (it used to match "too many" and escalate into more calls)' {
        Test-IsBucketOverflowError -Err '429 Too Many Requests -- throttled' | Should -BeFalse
    }
    It 'a genuine overflow still is' {
        Test-IsBucketOverflowError -Err 'Query execution has exceeded the allowed result size' | Should -BeTrue
        Test-IsBucketOverflowError -Err 'too many rows returned' | Should -BeTrue
    }
}

Describe 'Get-RABucketRetryDelaySeconds backs off a throttling API' {
    It 'grows exponentially' {
        (Get-RABucketRetryDelaySeconds -Attempt 1 -BaseSeconds 30 -MaxSeconds 300) | Should -Be 30
        (Get-RABucketRetryDelaySeconds -Attempt 2 -BaseSeconds 30 -MaxSeconds 300) | Should -Be 60
        (Get-RABucketRetryDelaySeconds -Attempt 3 -BaseSeconds 30 -MaxSeconds 300) | Should -Be 120
    }
    It 'is capped' {
        (Get-RABucketRetryDelaySeconds -Attempt 10 -BaseSeconds 30 -MaxSeconds 300) | Should -Be 300
    }
    It 'never waits LESS than a server-sent Retry-After' {
        (Get-RABucketRetryDelaySeconds -Attempt 1 -BaseSeconds 30 -MaxSeconds 300 -Err '429 Too Many Requests -- Retry-After: 90') | Should -Be 90
    }
}

Describe 'WIRING -- every recovery is reachable from the production loop' {

    It 'the main-loop catch routes through the shared classifier' {
        $script:CodeNC | Should -Match 'Get-RABucketFailureAction\s+-Err\s+\$_'
    }
    It 'a throttled bucket that exhausts its retries is DEFERRED, not written off' {
        $script:CodeNC | Should -Match '\$deferredBucketIndices\.Add\(\$b\)'
    }
    It 'the late-retry pass exists, re-runs the query, and can hand a too-large bucket to the sub-bucket pass' {
        $script:CodeNC | Should -Match '\$__lp = New-RALatePasses -Pending @\(\$deferredBucketIndices\.ToArray\(\)\)'
        $script:CodeNC | Should -Match '\$dbResp = Invoke-GraphHuntingQuery'
        $script:CodeNC | Should -Match '\$failedBucketIndices\.Add\(\$db\)'
    }
    It 'the late-retry pass runs BEFORE the sub-bucket pass (so a bucket it moves there is still split)' {
        $late = $script:CodeNC.IndexOf('$__lp = New-RALatePasses -Pending @($deferredBucketIndices.ToArray())')
        $sub  = $script:CodeNC.IndexOf('$subQueue = New-Object')
        $late | Should -BeGreaterThan 0
        $late | Should -BeLessThan $sub
    }
    It 'an overflow AT the escalation cap is split instead of escalated into the break' {
        $script:CodeNC | Should -Match '(?s)elseif \(\$bucketCountToUse -ge \$capBucket\) \{.{0,900}?\$failedBucketIndices\.Add\(\$b\)'
    }
    It 'the cap break, if ever reached, records every bucket it never ran' {
        $script:CodeNC | Should -Match '(?s)bucket escalation reached cap.{0,400}Add-RABucketLoss.{0,200}break'
    }
    It 'the futile SKIP records a loss for every bucket before clearing the queue' {
        $script:CodeNC | Should -Match '(?s)foreach \(\$skippedIdx in \$failedBucketIndices\)\s*\{\s*Add-RABucketLoss.{0,300}\$failedBucketIndices\.Clear\(\)'
    }
    It 'the split that does not reduce the failure records a loss for every slice it stops (it replaced the futile prune, #887)' {
        # owner 2026-10-22, one mechanism: the v2.2.357 futile-prune is gone; #880's measured stop is the only one
        $script:CodeNC | Should -Not -Match '\$purgedCount\+\+'
        $script:CodeNC | Should -Match '(?s)-not \(Test-RASplitReducesFailure .{0,400}\$prunedSubtreeCount\+\+.{0,600}Add-RABucketLoss .{0,200}not split further.{0,200}\s+continue'
    }
    It 'a sub-bucket whose rows fail to convert is counted as lost' {
        $script:CodeNC | Should -Match '(?s)if \(-not \$subConv\.Ok\).{0,400}Add-RABucketLoss'
    }
    It 'a sub-bucket failure is classified by the shared classifier, and a throttled one is retried at the same size' {
        $script:CodeNC | Should -Match '\$subAction = Get-RABucketFailureAction'
        $script:CodeNC | Should -Match "(?s)if \(\`$subAction -eq 'Retry' -and \`$subAttempt -lt \`$subTransientRetries\).{0,1000}Invoke-RABucketReauth"   # #880: + the busy wording of the retry line
    }
    It 'the sub-bucket loop no longer PRESETS the timeout flag to $true (that made every error look like a timeout)' {
        $script:CodeNC | Should -Not -Match '_LastGraphHuntingAllTimedOut\s*=\s*\$true\s*$'
    }
    It 'Invoke-GraphHuntingQuery clears the timeout flag on entry, before any path can fail' {
        $fnStart = $script:HuntNC.IndexOf('function Invoke-GraphHuntingQuery')
        $clear   = $script:HuntNC.IndexOf('$script:_LastGraphHuntingAllTimedOut = $false', $fnStart)
        $firstLa = $script:HuntNC.IndexOf('LA-direct', $fnStart)
        $clear | Should -BeGreaterThan $fnStart
        $clear | Should -BeLessThan $firstLa
    }
}

Describe 'Get-RABucketRows -- a successful query whose rows cannot be converted is reported, not dropped' {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Engine, [ref]$null, [ref]$null)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-RABucketRows' }, $true) | Select-Object -First 1
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    It 'direct rows pass through' {
        $r = Get-RABucketRows -Resp ([pscustomobject]@{ _SIDirectRows = @(1,2,3) })
        $r.Ok | Should -BeTrue
        @($r.Rows).Count | Should -Be 3
    }
    It 'a conversion that throws returns Ok=$false with the error' {
        function script:ConvertTo-PSObjectDeep { throw 'boom' }
        $resp = [pscustomobject]@{ Results = [pscustomobject]@{ AdditionalProperties = @(@{ a = 1 }) } }
        $r = Get-RABucketRows -Resp $resp
        $r.Ok    | Should -BeFalse
        $r.Error | Should -Match 'boom'
    }
}
Describe 'no Microsoft Defender XDR in the tenant: advanced hunting "Account is not provisioned" (live 2026-10-06, Community rehearsal)' {
    BeforeAll {
        # verbatim from the rehearsal's Risk Analysis console log (tenant with Entra ID P2 only)
        $script:MsgNoXdr = '403 HTTP error -- {"error":{"code":"Unauthorized","message":"Unauthorized request - Account is not provisioned.","innerError":{"date":"2026-10-06T21:53:05"}}}'
    }
    It 'is ABSENT -- not Retry, although the answer says Unauthorized: nothing exists to retrieve, so nothing is lost and nothing is retried' {
        Get-RABucketFailureAction -Err $script:MsgNoXdr | Should -Be 'Absent'
        Get-RABucketFailureAction -Err (Get-RAHuntingNotProvisionedMessage) | Should -Be 'Absent'
    }
    It 'a real token problem is still Retry' {
        Get-RABucketFailureAction -Err '401 Unauthorized -- InvalidAuthenticationToken: Access token has expired' | Should -Be 'Retry'
    }
    It 'Test-RAHuntingNotProvisioned recognises the service answer and SI''s own message, nothing else' {
        Test-RAHuntingNotProvisioned -Message $script:MsgNoXdr | Should -BeTrue
        Test-RAHuntingNotProvisioned -Message (Get-RAHuntingNotProvisionedMessage) | Should -BeTrue
        Test-RAHuntingNotProvisioned -Message '429 Too Many Requests' | Should -BeFalse
        Test-RAHuntingNotProvisioned -Message '' | Should -BeFalse
    }
    It 'the hunting layer stops at once: no retry, no reconnect, and no further query once it has said so in this run' {
        $script:HuntNC | Should -Match 'if \(\$script:_RAHuntingNotProvisioned\) \{ throw \(Get-RAHuntingNotProvisionedMessage\) \}\s*\n\s*for \(\$attempt = 1'
        $iNp = $script:HuntNC.IndexOf('if (Test-RAHuntingNotProvisioned -Message $msg)')
        $iAuth = $script:HuntNC.IndexOf('if ($looksAuth)')
        $iNp | Should -BeGreaterThan 0
        $iNp | Should -BeLessThan $iAuth -Because 'checked before the auth branch, which would reconnect and retry'
    }
    It 'an SI profile table that does not exist yet (no row ever -- e.g. no devices without Defender for Endpoint) is ABSENT, not a query defect; any other missing name is still a defect' {
        $m = "Operation returned an invalid status code 'BadRequest' -- SemanticError/SEM0100: 'where' operator: Failed to resolve table or column expression named 'SI_Endpoint_Profile_CL'"
        Get-RABucketFailureAction -Err $m | Should -Be 'Absent'
        Test-RANoDataSource -Message $m | Should -BeTrue
        $other = "Operation returned an invalid status code 'BadRequest' -- SemanticError/SEM0100: 'where' operator: Failed to resolve table or column expression named 'DeviceInfoo'"
        Get-RABucketFailureAction -Err $other | Should -Be 'Defect'
        Test-RANoDataSource -Message $other | Should -BeFalse
        Test-RANoDataSource -Message $script:MsgNoXdr | Should -BeTrue
        $tvm = "400 Bad Request -- 'extend' operator: Failed to resolve table or column expression named 'DeviceTvmSoftwareVulnerabilities'. Fix semantic errors"
        Get-RABucketFailureAction -Err $tvm | Should -Be 'Absent' -Because 'no Defender vulnerability management in the tenant (customer A 2026-10-15)'
        Test-RANoDataSource -Message $tvm | Should -BeTrue
    }
    It 'the main bucket loop and the sub-bucket pass record an Absent bucket as not applicable, never as a lost bucket' {
        $script:CodeNC | Should -Match "elseif \(\`$bucketAction -eq 'Absent'\) \{\s*\n\s*Write-Info"
        $script:CodeNC | Should -Match "elseif \(\`$subAction -eq 'Absent'\) \{\s*\n\s*Write-Info"
    }
    It 'an unbucketed report whose query has no source here records zero rows, not a failed report' {
        $script:CodeNC | Should -Match 'Test-RANoDataSource -Message \$_\.Exception\.Message\)\) \{\s*\n\s*Write-Info \("not applicable in this tenant'
    }
}
Describe '#882 THE LATE RETRY GOES ON WHILE THE RUN MAKES PROGRESS -- no clock, no count of passes' {
    BeforeAll {
        # the engine's pass loop, driven the way Invoke-RiskAnalysis.ps1 drives it: -Outcome { param($Index, $Pass) } answers
        # ok | retry | gone for one slice in one pass (one ladder of attempts); every ask is recorded
        function script:Invoke-SimLatePasses([int[]]$Pending, [scriptblock]$Outcome) {
            $s = New-RALatePasses -Pending $Pending
            $asked = New-Object System.Collections.Generic.List[string]
            while (Step-RALatePasses -State $s) {
                foreach ($i in @($s.Current)) {
                    $asked.Add(('{0}@{1}' -f $i, $s.Pass))
                    Set-RALatePassResult -State $s -Index $i -Result ([string](& $Outcome $i $s.Pass))
                }
            }
            [pscustomobject]@{ State = $s; Asked = $asked.ToArray() }
        }
    }
    It 'an outage that clears one slice per pass recovers EVERY slice (N passes, no loss)' {
        # slice i answers from pass i+1 on -- each pass recovers exactly one, so each pass makes progress
        $r = Invoke-SimLatePasses -Pending @(0, 1, 2, 3, 4) -Outcome { param($i, $p) if ($p -ge $i + 1) { 'ok' } else { 'retry' } }
        $r.State.Recovered | Should -Be 5
        @($r.State.Left).Count | Should -Be 0
        $r.State.Stopped | Should -BeFalse
        $r.State.Pass | Should -Be 5
    }
    It 'an outage that clears after N passes for the rest, while a few slices answer on the way, recovers everything' {
        # slices 0 and 1 answer in passes 1 and 2; the outage of the other six clears in pass 3
        $r = Invoke-SimLatePasses -Pending @(0..7) -Outcome { param($i, $p) if ($i -lt 2 -and $p -ge $i + 1) { 'ok' } elseif ($p -ge 3) { 'ok' } else { 'retry' } }
        $r.State.Recovered | Should -Be 8
        @($r.State.Left).Count | Should -Be 0
        $r.State.Pass | Should -Be 3
    }
    It 'a permanent outage stops after ONE pass with no progress: every slice asked once, every slice named' {
        $r = Invoke-SimLatePasses -Pending @(3, 7, 9) -Outcome { param($i, $p) 'retry' }
        $r.State.Pass | Should -Be 1
        $r.State.Stopped | Should -BeTrue
        @($r.State.Left) | Should -Be @(3, 7, 9)
        $r.Asked | Should -Be @('3@1', '7@1', '9@1')
    }
    It 'a run that makes progress and then none stops after the first pass that recovers nothing' {
        # slice 0 moves to the smaller slices (gone), slice 1 recovers in pass 1, slice 2 never answers
        $r = Invoke-SimLatePasses -Pending @(0, 1, 2) -Outcome { param($i, $p) switch ($i) { 0 { 'gone' } 1 { 'ok' } default { 'retry' } } }
        $r.State.Pass | Should -Be 2
        $r.State.Stopped | Should -BeTrue
        @($r.State.Left) | Should -Be @(2)
        $r.Asked | Should -Be @('0@1', '1@1', '2@1', '2@2') -Because 'a slice that left the late retry is never asked again'
    }
    It 'a pass whose slices only leave (split / lost) is no progress' {
        $r = Invoke-SimLatePasses -Pending @(0, 1) -Outcome { param($i, $p) if ($i -eq 0) { 'gone' } else { 'retry' } }
        $r.State.Pass | Should -Be 1
        @($r.State.Left) | Should -Be @(1)
    }
    It 'nothing deferred: no pass at all' {
        $r = Invoke-SimLatePasses -Pending @() -Outcome { param($i, $p) throw 'never asked' }
        $r.State.Pass | Should -Be 0
        @($r.State.Left).Count | Should -Be 0
    }
    It 'a smaller slice is asked again for its first rounds as before, after them only while the pass recovered a slice since it was queued' {
        Test-RASubSliceAskAgain -Rounds 0 -LateRounds 3 -RecoveredNow 0 -RecoveredAtAsk -1 | Should -BeTrue
        Test-RASubSliceAskAgain -Rounds 2 -LateRounds 3 -RecoveredNow 5 -RecoveredAtAsk 5 | Should -BeTrue
        Test-RASubSliceAskAgain -Rounds 3 -LateRounds 3 -RecoveredNow 6 -RecoveredAtAsk 5 | Should -BeTrue
        Test-RASubSliceAskAgain -Rounds 3 -LateRounds 3 -RecoveredNow 5 -RecoveredAtAsk 5 | Should -BeFalse
        Test-RASubSliceAskAgain -Rounds 40 -LateRounds 3 -RecoveredNow 90 -RecoveredAtAsk 89 | Should -BeTrue -Because 'no count of rounds'
    }
    It 'WIRING: the engine runs its late retry in these passes, and loses a slice only when a pass recovered nothing' {
        $script:CodeNC | Should -Match 'while \(Step-RALatePasses -State \$__lp\) \{'
        $script:CodeNC | Should -Match 'foreach \(\$db in @\(\$__lp\.Current\)\) \{'
        $script:CodeNC | Should -Match 'Set-RALatePassResult -State \$__lp -Index \(\[int\]\$db\) -Result \$dbResult'
        $script:CodeNC | Should -Match "(?s)\} elseif \(\`$dbAction -eq 'Retry'\) \{.{0,700}?\`$dbResult = 'retry'"
        $script:CodeNC | Should -Match '(?s)foreach \(\$db in @\(\$__lp\.Left\)\) \{.{0,700}?Add-RABucketLoss'
        # a recovered slice is progress only when its rows were kept
        $script:CodeNC | Should -Match "\} else \{ \`$dbResult = 'ok' \}"
        $script:CodeNC | Should -Match "else \{ \`$ResultAll = @\(\`$ResultAll\) \+ @\(\`$conv\.Rows\); \`$dbResult = 'ok' \}"
    }
    It 'WIRING: the smaller slices count what they recover and ask again by the same rule' {
        $script:CodeNC | Should -Match 'if \(\$__subIn\) \{ \$__subOk\+\+ \}'
        $script:CodeNC | Should -Match 'Test-RASubSliceAskAgain -Rounds \$pRounds -LateRounds \$__subLateRounds -RecoveredNow \$__subOk -RecoveredAtAsk \$__subAtAsk'
        $script:CodeNC | Should -Match "How = 'again'; RC = \`$subRC; RI = \`$subRI; M = \`$false; A = \(\`$pRounds \+ 1\); S = \`$__subOk \}"
    }
}
