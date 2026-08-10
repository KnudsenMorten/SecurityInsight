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
