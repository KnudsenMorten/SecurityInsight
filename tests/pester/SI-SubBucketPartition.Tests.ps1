#Requires -Version 5.1
<#
    AUDIT #56.3 -- pin the sub-bucket partition property.

    BACKGROUND. On 2026-08-10 an attack-path report returned 4 rows on a clean run, 3 rows on a
    run where one bucket timed out and was rescued by the sub-bucket pass, and 4 again once a
    BucketCount floor kept it out of the recovery path. That was written up as "the sub-bucket
    pass silently dropped a row" -- and then reading New-SubBucketFilterKql showed the mapping is
    provably lossless, so the accusation was withdrawn (see #56.3 CORRECTION).

    These tests exist so the question never has to be re-litigated from a log again. They assert
    the property directly:

        parent bucket N of T, split into K children, uses modulus T*K and indices N + j*T.
        A row lands in parent N  <=>  hash % T == N
                                <=>  hash % (T*K) in { N, N+T, ..., N+(K-1)T }

    i.e. the K children EXACTLY partition the parent -- every parent row lands in exactly one
    child, and no child claims a row from another parent. If a future change breaks that, THIS
    fails instead of a customer quietly losing an attack path.
#>

BeforeAll {
    $shared = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\_shared'
    . (Join-Path $shared 'RA-BucketFilters.ps1')
    # The engine sets this per report; a unit test must not depend on that having happened.
    $script:_CrossDomainBucketCoalesce = @()
}

Describe 'sub-bucket partitioning is lossless -- audit #56.3' {

    It 'derives modulus T*K and index N + j*T (the documented mapping)' {
        # Parent 1 of 2, child 3 of 4 -> modulus 8, index 1 + 2*2 = 5.
        $kql = New-SubBucketFilterKql -ParentBucketCount 2 -ParentBucketIndex 1 -SubBucketCount 4 -SubBucketIndex 2
        $kql | Should -Match '%\s*8'
        $kql | Should -Match '==\s*5'
    }

    It 'covers every parent row exactly once, for every parent/child combination' {
        # Exhaustive over the shapes the engine actually uses, simulating the KQL modulo
        # arithmetic over a wide hash space. This is the property the whole recovery path rests on.
        foreach ($T in 2, 4, 8) {
            foreach ($K in 2, 4) {
                foreach ($N in 0..($T - 1)) {
                    $childIndices = @(0..($K - 1) | ForEach-Object { $N + ($_ * $T) })
                    foreach ($h in 0..(($T * $K * 7) - 1)) {
                        $inParent = (($h % $T) -eq $N)
                        $hits     = @($childIndices | Where-Object { ($h % ($T * $K)) -eq $_ }).Count
                        if ($inParent) {
                            $hits | Should -Be 1 -Because "hash $h is in parent $N of $T so exactly one of $K children must claim it"
                        } else {
                            $hits | Should -Be 0 -Because "hash $h is NOT in parent $N of $T so no child may claim it"
                        }
                    }
                }
            }
        }
    }

    It 'never lets two different parents claim the same child index' {
        # Cross-parent collision would double-count rather than lose -- the other failure direction.
        $T = 4; $K = 4
        $seen = @{}
        foreach ($N in 0..($T - 1)) {
            foreach ($j in 0..($K - 1)) {
                $idx = $N + ($j * $T)
                $seen.ContainsKey($idx) | Should -BeFalse -Because "index $idx already claimed by parent $($seen[$idx])"
                $seen[$idx] = $N
            }
        }
        $seen.Count | Should -Be ($T * $K)
    }

    It 'emits the same key-selection shape as the top-level filter, so EG and CL stay aligned' {
        # If the sub-bucket filter hashed a different column than the parent, partitions would
        # diverge and rows really could be lost. Both must build __bucket_key the same way.
        $parent = New-BucketFilterKql -BucketCount 8 -BucketIndex 5
        $child  = New-SubBucketFilterKql -ParentBucketCount 2 -ParentBucketIndex 1 -SubBucketCount 4 -SubBucketIndex 2
        foreach ($token in '__bucket_key', 'hash_sha256', 'isnotempty') {
            $child | Should -Match ([regex]::Escape($token))
        }
        # identical modulus + index => identical predicate
        $child | Should -Be $parent
    }
}

Describe 'the CL side gets the SAME partition as the EG filter -- v2.2.428' {
    <#
        The other half of the alignment, and the half that was missing. Every test above pins the
        EG-side filter. But a hybrid query has TWO sides: the EG predicate, and the CL snapshot inlined
        as a datatable() literal. RA-GraphHunting.ps1 (~:149) picks the CL rows from
        $script:_CurrentBucketCount/_Index, which the MAIN bucket loop sets before each call -- and
        which the SUB-bucket pass did not set at all until v2.2.428.

        The customer symptom: all 8 children of a 2-bucket report logged the identical
        "'_ep' bucket 2/2: 426/845 row(s) inlined", including the four under parent 0/2. The CL side
        stayed frozen on whatever the main loop finished on, so sub-bucketing narrowed the EG side
        while every child still carried the full CL payload.
    #>

    It 'pairs (newT, subN) with exactly the modulus and index the EG filter encodes' {
        # This is the invariant the fix depends on. If the loop's arithmetic and the filter's ever
        # diverge, the CL rows inlined would be the counterparts of a DIFFERENT EG partition -- and
        # the join would silently drop real matches. That is worse than the payload waste being fixed,
        # which is why it is pinned rather than assumed.
        foreach ($pT in 1,2,3,4,8) {
            foreach ($K in 2,4) {
                foreach ($pN in 0..($pT - 1)) {
                    foreach ($j in 0..($K - 1)) {
                        # verbatim from the sub-bucket loop in Invoke-RiskAnalysis.ps1
                        $subN = $pN + ($j * $pT)
                        $newT = $pT * $K
                        $kql  = New-SubBucketFilterKql -ParentBucketCount $pT -ParentBucketIndex $pN -SubBucketCount $K -SubBucketIndex $j
                        $kql | Should -Be (New-BucketFilterKql -BucketCount $newT -BucketIndex $subN) `
                            -Because "parent $pN/$pT child $j/$K must hand the CL side ($newT, $subN)"
                    }
                }
            }
        }
    }

    It '🔴 the sub-bucket pass actually ASSIGNS those coordinates to the CL-side state' {
        # The regression itself. The arithmetic above was always correct; the bug was that nobody
        # handed the result to the CL side. Asserting the source is blunt, but this defect is
        # invisible in every offline behavioural test -- it only shows up as a repeated log line in a
        # customer transcript, which is how it survived from v2.2.277 to v2.2.428.
        $engine = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'
        $src    = Get-Content -LiteralPath $engine -Raw

        # Isolate the sub-bucket loop so a match in the MAIN bucket loop cannot satisfy this.
        $start = $src.IndexOf('$subFilter  = New-SubBucketFilterKql')
        $start | Should -BeGreaterThan 0 -Because 'the sub-bucket loop must still exist'
        # Window must comfortably span the loop body INCLUDING its comments -- a too-small window
        # fails on a correct engine, which is a false alarm on the highest-blast-radius file we ship.
        $len    = [Math]::Min(6000, $src.Length - [Math]::Max(0, $start - 400))
        $window = $src.Substring([Math]::Max(0, $start - 400), $len)

        $window | Should -Match '_CurrentBucketCount\s*=\s*\$newT'
        $window | Should -Match '_CurrentBucketIndex\s*=\s*\$subN'
    }
}
