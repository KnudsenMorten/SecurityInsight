#Requires -Version 5.1
<#
.SYNOPSIS
    Pester v5 -- audit #24: the AutoBucket probe must ESCALATE on a 900s ceiling timeout.

.DESCRIPTION
    The defect: the run path and the probe path classified the same failure differently.

      run   (Invoke-RiskAnalysis.ps1:1235)  TaskCanceled / 502 = "query too big" -> escalate
      probe (Get-OptimalBucketCount)        used Test-IsBucketOverflowError ALONE, which
                                            deliberately excludes TaskCanceled -> threw ->
                                            "Falling back to configured BucketCount=2"

    So for exactly the reports that need a higher bucket count, the exponential ramp and
    binary search were unreachable. Measured live: a complete RiskAnalysis_Summary run
    cascaded through TEN 900s timeouts, finished successfully, and left all 59 cache
    entries at 2 -- it had learned nothing and would re-pay every timeout the next night.

    These tests drive the REAL Get-OptimalBucketCount with a fake probe script, so they
    assert the escalation actually happens rather than just that a predicate returns true.
#>

BeforeAll {
    $si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $si 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')

    # Shims for the engine helpers the bucketing module logs through.
    function Write-Info { param($msg) $script:Logged += ,[string]$msg }
    function Write-Warn2 { param($msg) $script:Logged += ,[string]$msg }

    # Module state the functions expect.
    $script:AutoBucketConfirmedKey = '__confirmed'

    function Reset-BucketState {
        $script:Logged = @()
        # Global, not $script:, deliberately -- the probes below are built with
        # .GetNewClosure(), which rebinds their scope, so a $script: write inside one never
        # reaches the It block that asserts on it.
        $global:BucketProbeAttempts = @()
        $script:AutoBucketMemo = @{}
        $global:AutoBucketCache = $false      # no disk cache in these tests
        $global:SettingsPath = ''
        $global:AutoBucketMaxRampDoublings = $null
    }

    # A probe that behaves like Advanced Hunting: anything below $SucceedAt blows the
    # 900s HttpClient ceiling (TaskCanceled); at or above it, the query fits.
    # Every attempt is recorded so a test can assert the ramp actually STOPPED rather
    # than merely that the returned number looks right.
    function New-CeilingProbe {
        param([int]$SucceedAt)
        return {
            param([int]$BucketCount)
            $global:BucketProbeAttempts += ,[int]$BucketCount
            if ($BucketCount -lt $SucceedAt) {
                throw [System.Threading.Tasks.TaskCanceledException]::new('A task was canceled.')
            }
            return @( [pscustomobject]@{ ok = $true } )
        }.GetNewClosure()
    }

    # Rows/payload overflow (413 / result-limit), NOT the query-time ceiling. Bucketing
    # DOES fix this even when the EG-side filter is suppressed, because the CL inline
    # payload still shrinks ~1/N per bucket.
    function New-OverflowProbe {
        param([int]$SucceedAt)
        return {
            param([int]$BucketCount)
            $global:BucketProbeAttempts += ,[int]$BucketCount
            if ($BucketCount -lt $SucceedAt) { throw 'Request Entity Too Large' }
            return @( [pscustomobject]@{ ok = $true } )
        }.GetNewClosure()
    }
}

# ============================================================================
Describe 'audit #24 -- classification of a 900s ceiling timeout' {
# ============================================================================

    It 'a TaskCanceledException is "too large" (the HttpClient ceiling)' {
        $err = try { throw [System.Threading.Tasks.TaskCanceledException]::new('A task was canceled.') } catch { $_ }
        Test-IsDeterministicTooLargeError $err | Should -BeTrue
    }

    It 'the "A task was canceled" message form is "too large" too' {
        Test-IsDeterministicTooLargeError 'A task was canceled.' | Should -BeTrue
    }

    It '502 from the nginx in front of runHuntingQuery is "too large"' {
        Test-IsDeterministicTooLargeError 'Response status code 502 Bad Gateway' | Should -BeTrue
    }

    # The exclusion that Test-IsBucketOverflowError was protecting must survive: escalating
    # on a genuine transient amplifies it (more buckets = more calls = more throttle).
    It 'throttle is NOT escalated' -ForEach @(
        'Too Many Requests',
        'HTTP 429 returned',
        'request was throttled, retry later',
        'Service Unavailable (503)'
    ) {
        Test-IsDeterministicTooLargeError $_ | Should -BeFalse
    }

    It 'auth failures are NOT escalated' -ForEach @(
        'InvalidAuthenticationToken',
        'Access token has expired',
        '401 Unauthorized'
    ) {
        Test-IsDeterministicTooLargeError $_ | Should -BeFalse
    }

    It 'throttle WINS even when the message also mentions a timeout' {
        # Ordering matters: a 429 that also says "timed out" must stay transient.
        Test-IsDeterministicTooLargeError 'A task was canceled. 429 Too Many Requests' | Should -BeFalse
    }
}

# ============================================================================
Describe 'audit #24 -- the probe now escalates instead of aborting' {
# ============================================================================

    It 'ramps past the floor to the count that actually fits' {
        Reset-BucketState
        # Needs 16; the old code aborted at 2 and fell back to the configured count.
        $optimal = Get-OptimalBucketCount -QueryKey 'R|1' -MaxBucketCount 1024 -MinBucketCount 2 `
                                          -ProbeScript (New-CeilingProbe -SucceedAt 16)
        $optimal | Should -BeGreaterOrEqual 16
        $optimal | Should -BeLessOrEqual 16
    }

    It 'the escalation is visible in the log, not silent' {
        Reset-BucketState
        [void](Get-OptimalBucketCount -QueryKey 'R|2' -MaxBucketCount 1024 -MinBucketCount 2 `
                                      -ProbeScript (New-CeilingProbe -SucceedAt 8))
        ($script:Logged -join "`n") | Should -Match 'probing .* with bucketCount=2'
        ($script:Logged -join "`n") | Should -Match 'probing .* with bucketCount=(4|8)'
        ($script:Logged -join "`n") | Should -Match 'chosen'
    }

    It 'converges on the MINIMUM workable count, not merely a workable one' {
        # The binary search matters: overshooting to 64 when 5 would do multiplies every
        # subsequent run's API calls.
        Reset-BucketState
        Get-OptimalBucketCount -QueryKey 'R|3' -MaxBucketCount 1024 -MinBucketCount 1 `
                               -ProbeScript (New-CeilingProbe -SucceedAt 5) | Should -Be 5
    }

    It 'a report that already fits at the floor still returns the floor' {
        # Guards the inverse mistake: this fix must not inflate the 6-of-7 reports that
        # genuinely are optimal at 2.
        Reset-BucketState
        Get-OptimalBucketCount -QueryKey 'R|4' -MaxBucketCount 1024 -MinBucketCount 2 `
                               -ProbeScript (New-CeilingProbe -SucceedAt 1) | Should -Be 2
    }

    It 'a NON-escalatable failure still aborts the probe' {
        # Auth/throttle must not be turned into an escalation loop by this change.
        Reset-BucketState
        $probe = { param([int]$BucketCount) throw 'InvalidAuthenticationToken: token expired' }
        { Get-OptimalBucketCount -QueryKey 'R|5' -MaxBucketCount 64 -MinBucketCount 2 -ProbeScript $probe } |
            Should -Throw
    }

    It 'gives up cleanly when even MaxBucketCount cannot fit' {
        Reset-BucketState
        { Get-OptimalBucketCount -QueryKey 'R|6' -MaxBucketCount 8 -MinBucketCount 2 `
                                 -ProbeScript (New-CeilingProbe -SucceedAt 4096) } |
            Should -Throw '*did not succeed up to MaxBucketCount*'
    }
}

# ============================================================================
Describe 'audit #24 -- the escalation must STOP when splitting cannot help' {
# ============================================================================
    # The #24 fix without this guard made one report class WORSE: an EG-suppressed
    # cross-domain report ramped 2 -> 65536 (16 rungs, 13 x 900s, 242 min) and never
    # converged, because the EG-side bucket filter is deliberately suppressed to keep the
    # join lossless -- so every sub-query still does the FULL Exposure-Graph work.

    It 'stops after ONE ceiling failure when the report cannot be distributed' {
        Reset-BucketState
        # Nothing ever succeeds -- exactly the live case.
        $optimal = Get-OptimalBucketCount -QueryKey 'EG|1' -MaxBucketCount 131072 -MinBucketCount 2 `
                                          -ProbeScript (New-CeilingProbe -SucceedAt 999999) `
                                          -FutilityCheck { $true }
        $optimal | Should -Be 2                      # the configured count, as before #24
        $global:BucketProbeAttempts.Count | Should -Be 1        # NOT 16 rungs
        $global:BucketProbeAttempts | Should -Be @(2)
    }

    It 'says so loudly rather than failing silently' {
        Reset-BucketState
        [void](Get-OptimalBucketCount -QueryKey 'EG|2' -MaxBucketCount 131072 -MinBucketCount 2 `
                                      -ProbeScript (New-CeilingProbe -SucceedAt 999999) `
                                      -FutilityCheck { $true })
        ($script:Logged -join "`n") | Should -Match 'FUTILE-STOP'
    }

    It 'reports the REASON the check gave, not a hardcoded one' {
        # The first live run of this guard stopped the right report for the right reason but
        # logged the WRONG cause: the message hardcoded "EG-side bucket filter suppressed"
        # while the run log showed that filter was ACTIVE and the payload-bound branch had
        # fired. A wrong explanation in a log is how #24 acquired a wrong root cause to begin
        # with, so the check now returns its reason and the message quotes it.
        Reset-BucketState
        [void](Get-OptimalBucketCount -QueryKey 'EG|7' -MaxBucketCount 131072 -MinBucketCount 2 `
                                      -ProbeScript (New-CeilingProbe -SucceedAt 999999) `
                                      -FutilityCheck { 'the inline payload was only 25909 bytes, so this query is EG-BOUND' })
        $log = ($script:Logged -join "`n")
        $log | Should -Match 'FUTILE-STOP'
        $log | Should -Match 'EG-BOUND'
        $log | Should -Not -Match 'bucket filter suppressed'
    }

    It 'still falls back to a generic reason when the check just returns $true' {
        Reset-BucketState
        [void](Get-OptimalBucketCount -QueryKey 'EG|8' -MaxBucketCount 131072 -MinBucketCount 2 `
                                      -ProbeScript (New-CeilingProbe -SucceedAt 999999) `
                                      -FutilityCheck { $true })
        ($script:Logged -join "`n") | Should -Match 'splitting cannot distribute'
    }

    It 'an empty string is NOT futile (it is falsey, and a reasonless stop is a bug)' {
        Reset-BucketState
        Get-OptimalBucketCount -QueryKey 'EG|9' -MaxBucketCount 1024 -MinBucketCount 2 `
                               -ProbeScript (New-CeilingProbe -SucceedAt 16) `
                               -FutilityCheck { '' } | Should -Be 16
    }

    It 'does NOT fire for a report that is merely slow but splittable' {
        # The regression that matters most: the guard must not undo the #24 fix for the
        # reports it exists to help.
        Reset-BucketState
        Get-OptimalBucketCount -QueryKey 'EG|3' -MaxBucketCount 1024 -MinBucketCount 2 `
                               -ProbeScript (New-CeilingProbe -SucceedAt 16) `
                               -FutilityCheck { $false } | Should -Be 16
    }

    It 'keeps escalating on a rows/payload OVERFLOW even when futility is signalled' {
        # The distinction that keeps the guard safe. A 413 shrinks with bucketing (the CL
        # inline payload is ~1/N per bucket) whether or not the EG filter is suppressed --
        # only the query-time ceiling is futile. Stopping here would reintroduce the 1MB
        # body-cap failures that CL bucketing was built to solve.
        Reset-BucketState
        Get-OptimalBucketCount -QueryKey 'EG|4' -MaxBucketCount 1024 -MinBucketCount 2 `
                               -ProbeScript (New-OverflowProbe -SucceedAt 8) `
                               -FutilityCheck { $true } | Should -Be 8
    }

    It 'treats a FutilityCheck that throws as "not futile" (fails open, keeps escalating)' {
        Reset-BucketState
        Get-OptimalBucketCount -QueryKey 'EG|5' -MaxBucketCount 1024 -MinBucketCount 2 `
                               -ProbeScript (New-CeilingProbe -SucceedAt 16) `
                               -FutilityCheck { throw 'flag unavailable' } | Should -Be 16
    }

    It 'behaves exactly as before when no FutilityCheck is supplied' {
        Reset-BucketState
        Get-OptimalBucketCount -QueryKey 'EG|6' -MaxBucketCount 1024 -MinBucketCount 2 `
                               -ProbeScript (New-CeilingProbe -SucceedAt 16) | Should -Be 16
    }
}

# ============================================================================
Describe 'audit #24 -- PAYLOAD-BOUND vs EG-BOUND (the real runaway mechanism)' {
# ============================================================================
    # #24 recorded the 242-minute report as EG-suppressed. The live log
    # (risk-analysis_internal-vm_RiskAnalysisSummary_20260806T050241Z.log) says the
    # opposite -- "EG-side bucket filter stays ACTIVE (bounded EG work)" -- so a check on
    # $script:_SkipEGBucketForCrossDomain alone would never have fired for it. What the log
    # does show is the inline CL body falling 25,996 -> 868 bytes while every rung still
    # died at exactly 900s: the body was never the constraint.

    BeforeAll {
        # The engine's real predicate, as wired in Invoke-RiskAnalysis.ps1.
        function New-PayloadFutilityCheck {
            param([int]$FloorBytes = 65536)
            return { ($global:LastInlineBytes -gt 0) -and ($global:LastInlineBytes -lt $FloorBytes) }.GetNewClosure()
        }

        # Replays the logged byte sequence: the inline body halves each rung, and the query
        # times out at the ceiling regardless -- because the cost is EG-side.
        function New-EgBoundProbe {
            return {
                param([int]$BucketCount)
                $global:BucketProbeAttempts += ,[int]$BucketCount
                $global:LastInlineBytes = [int](51992 / $BucketCount)   # 25,996 at BucketCount=2
                throw [System.Threading.Tasks.TaskCanceledException]::new('A task was canceled.')
            }.GetNewClosure()
        }
    }

    It 'stops after ONE rung on the report that actually ran away' {
        Reset-BucketState
        $optimal = Get-OptimalBucketCount -QueryKey 'AP|1' -MaxBucketCount 131072 -MinBucketCount 2 `
                                          -ProbeScript (New-EgBoundProbe) `
                                          -FutilityCheck (New-PayloadFutilityCheck)
        $optimal | Should -Be 2
        # 25,996 bytes is already only ~2.5% of the 1MB cap, so the very first rung is
        # enough to know. 1 attempt instead of the 16 the live run burned.
        $global:BucketProbeAttempts | Should -Be @(2)
        ($script:Logged -join "`n") | Should -Match 'FUTILE-STOP'
    }

    It 'keeps escalating while the report is genuinely PAYLOAD-bound' {
        # Body starts near the 1MB cap and only fits once split 16 ways. Splitting IS the
        # right answer here and the guard must not interrupt it -- this is the case CL
        # bucketing exists for.
        Reset-BucketState
        $probe = {
            param([int]$BucketCount)
            $global:BucketProbeAttempts += ,[int]$BucketCount
            $global:LastInlineBytes = [int](16000000 / $BucketCount)   # 1MB at 16 buckets
            if ($BucketCount -lt 16) {
                throw [System.Threading.Tasks.TaskCanceledException]::new('A task was canceled.')
            }
            return @( [pscustomobject]@{ ok = $true } )
        }
        Get-OptimalBucketCount -QueryKey 'AP|2' -MaxBucketCount 131072 -MinBucketCount 2 `
                               -ProbeScript $probe -FutilityCheck (New-PayloadFutilityCheck) |
            Should -Be 16
    }

    It 'stays out of the way when there is no inline payload at all (2-phase path)' {
        # $script:_LastHybridInlineBytes is 0 when the 2-phase augment path runs and nothing
        # is inlined. Absent signal must mean "keep escalating", not "futile".
        Reset-BucketState
        $global:LastInlineBytes = 0
        Get-OptimalBucketCount -QueryKey 'AP|3' -MaxBucketCount 1024 -MinBucketCount 2 `
                               -ProbeScript (New-CeilingProbe -SucceedAt 16) `
                               -FutilityCheck (New-PayloadFutilityCheck) | Should -Be 16
    }
}

# ============================================================================
Describe 'audit #24 -- the ramp cap backstop' {
# ============================================================================
    # A bound for an unknown report class that cannot converge for some reason the
    # futility check does not recognise. Without it the worst case is MaxBucketCount
    # (131072 = 16 rungs x 900s).

    It 'bounds a report that never converges and no futility signal exists' {
        Reset-BucketState
        $optimal = Get-OptimalBucketCount -QueryKey 'CAP|1' -MaxBucketCount 131072 -MinBucketCount 2 `
                                          -ProbeScript (New-CeilingProbe -SucceedAt 999999) `
                                          -MaxRampDoublings 3
        $optimal | Should -Be 2
        $global:BucketProbeAttempts | Should -Be @(2, 4, 8, 16)   # floor + 3 doublings, then stop
        ($script:Logged -join "`n") | Should -Match 'RAMP-CAP'
    }

    It 'the DEFAULT cap does not suppress the values this cache has really learned' {
        # The historical cache held 62, 125, 127, 232, 248, 256, 496. 496 is 8 doublings
        # from a floor of 2, so a cap that cannot reach it would silently re-break #24.
        Reset-BucketState
        Get-OptimalBucketCount -QueryKey 'CAP|2' -MaxBucketCount 131072 -MinBucketCount 2 `
                               -ProbeScript (New-CeilingProbe -SucceedAt 496) | Should -Be 496
    }

    It 'is operator-overridable via $global:AutoBucketMaxRampDoublings' {
        Reset-BucketState
        $global:AutoBucketMaxRampDoublings = 2
        try {
            Get-OptimalBucketCount -QueryKey 'CAP|3' -MaxBucketCount 131072 -MinBucketCount 2 `
                                   -ProbeScript (New-CeilingProbe -SucceedAt 999999) | Should -Be 2
            $global:BucketProbeAttempts | Should -Be @(2, 4, 8)
        } finally { $global:AutoBucketMaxRampDoublings = $null }
    }
}
