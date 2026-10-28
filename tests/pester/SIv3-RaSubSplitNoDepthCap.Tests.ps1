#Requires -Version 5.1
<#
    NO DEPTH CAP ON THE SUB-SPLIT (owner 2026-10-22: no fixed limits; coordinator: "one mechanism, not two"). Internal's
    Device_Missing_CVEs_Detailed ended NOT COMPLETE on 3.0.0.202610220919: 21 slices "still timing out at MAX DEPTH 6". The
    sub-bucket pass now splits a slice deeper while the split REDUCES the failure (#880, Test-RASplitReducesFailure) and stops
    on that measurement -- never at a fixed depth. The only other end is a slice count past what the hash partition can address
    (Test-RASubSplitAddressable). A slice that is not split further is a NAMED loss (Add-RABucketLoss): the report ends NOT
    COMPLETE and says why, never complete with rows missing.

    The engine is one large script: the decisions are pure functions (RA-AutoBucketing.ps1), driven here by a small model of the
    pass's own order (a slice's children are asked and counted at its depth; the next depth is judged before it is asked), and
    the pass's wiring is read from the shipping text. Offline. NO EMOJI IN THIS FILE.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ra = Join-Path $script:SIRoot 'engine\risk-analysis'
    . (Join-Path $ra '_shared\RA-AutoBucketing.ps1')
    $script:Engine = Get-Content -Raw -LiteralPath (Join-Path $ra 'Invoke-RiskAnalysis.ps1')
    $script:EngineNC = (($script:Engine -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"

    # The pass, modelled: ONE bucket, fan-out 4. -FailedAt: per depth, how many of the slices asked there are refused for
    # their size or time (the first ones of each failing parent). Returns @{ Deepest; Lost (named losses); Asked }.
    function script:Invoke-SubSplitModel([hashtable]$FailedAt, [int]$StartCount = 64) {
        $tried = @{}; $failed = @{}; $lost = New-Object System.Collections.Generic.List[string]
        $q = New-Object System.Collections.Generic.Queue[object]
        $q.Enqueue(@{ D = 1; T = [long]$StartCount })
        $deepest = 0; $asked = 0; $failedSoFar = @{}
        while ($q.Count -gt 0) {
            $it = $q.Dequeue(); $d = [int]$it.D
            if ($d -ge 2 -and -not (Test-RASplitReducesFailure -Tried $tried -Failed $failed -Depth $d)) { $lost.Add("depth $d`: not split further -- splitting did not reduce the failure"); continue }
            $newT = [long]$it.T * 4
            for ($j = 0; $j -lt 4; $j++) {
                $asked++; if ($d -gt $deepest) { $deepest = $d }
                $tried[$d] = [int]('0' + [string]$tried[$d]) + 1
                $want = [int]('0' + [string]$FailedAt[$d]); $have = [int]('0' + [string]$failedSoFar[$d])
                if ($have -lt $want) {
                    $failedSoFar[$d] = $have + 1
                    $failed[$d] = [int]('0' + [string]$failed[$d]) + 1
                    if (Test-RASubSplitAddressable -SliceCount $newT -FanOut 4) { $q.Enqueue(@{ D = $d + 1; T = $newT }) }
                    else { $lost.Add("depth $d`: the key partition cannot be split finer") }
                }
            }
        }
        @{ Deepest = $deepest; Lost = $lost.ToArray(); Asked = $asked }
    }
}

Describe 'the sub-split has no depth cap; it stops only when splitting does not reduce the failure' {
    It 'a deep split whose failure share keeps falling goes PAST the old cap of 6 and ends with nothing lost' {
        # refused share per depth: 3/4, 6/12, 8/24, 8/32, 6/32, 3/24, 1/12, 0/4 -- falling at every level
        $plan = @{ 1 = 3; 2 = 6; 3 = 8; 4 = 8; 5 = 6; 6 = 3; 7 = 1; 8 = 0 }
        $r = Invoke-SubSplitModel -FailedAt $plan
        $r.Deepest | Should -Be 8 -Because 'the split was still reducing the failure at depth 7, so depth 8 was asked'
        $r.Deepest | Should -BeGreaterThan 6
        @($r.Lost).Count | Should -Be 0 -Because 'every slice was read in the end: nothing is lost'
    }
    It 'a split that does NOT reduce the failure stops at once, and every slice it leaves is a NAMED loss (the report is NOT COMPLETE)' {
        $r = Invoke-SubSplitModel -FailedAt @{ 1 = 4; 2 = 16; 3 = 64 }
        $r.Deepest | Should -Be 1 -Because 'all four smaller slices were refused as often as the bucket: no deeper split is asked'
        @($r.Lost).Count | Should -Be 4
        @($r.Lost) | ForEach-Object { $_ | Should -Match 'not split further -- splitting did not reduce the failure' }
    }
    It 'a split that helped once and then stopped helping stops there -- named, never silently' {
        $r = Invoke-SubSplitModel -FailedAt @{ 1 = 2; 2 = 4; 3 = 8 }    # 2/4 = 0.5, then 4/8 = 0.5: no longer falling
        $r.Deepest | Should -Be 2
        @($r.Lost).Count | Should -Be 4
    }
    It 'the only other end is the finest key partition (2^31 - 1 slices) -- not a depth' {
        Test-RASubSplitAddressable -SliceCount 64 -FanOut 4 | Should -BeTrue
        Test-RASubSplitAddressable -SliceCount (64L * [long][Math]::Pow(4, 6)) -FanOut 4 | Should -BeTrue -Because 'depth 7 from 64 slices is far inside the partition'
        Test-RASubSplitAddressable -SliceCount 536870911 -FanOut 4 | Should -BeTrue
        Test-RASubSplitAddressable -SliceCount 536870912 -FanOut 4 | Should -BeFalse -Because '2^29 x 4 = 2^31 is past [int]::MaxValue'
        Test-RASubSplitAddressable -SliceCount 0 -FanOut 4 | Should -BeFalse
    }
}

Describe 'WIRING: the pass in Invoke-RiskAnalysis.ps1' {
    It 'no depth cap is left: no $subDepthMax in the code, the split asks Test-RASubSplitAddressable instead' {
        $script:EngineNC | Should -Not -Match '\$subDepthMax'
        $script:EngineNC | Should -Not -Match 'MAX DEPTH'
        $script:EngineNC | Should -Match ([regex]::Escape('$__subFiner = Test-RASubSplitAddressable -SliceCount $newT -FanOut $subFanOut'))
        $script:EngineNC | Should -Match ([regex]::Escape("if (`$subAction -eq 'Split' -and `$__subFiner) {"))
    }
    It 'ONE mechanism: the v2.2.357 futile-prune is gone; a parent whose children ALL fail is stopped by #880 as a named loss, row splits included' {
        $script:EngineNC | Should -Not -Match 'FUTILE-PRUNE'
        $script:EngineNC | Should -Not -Match '\$parentTimeoutCount'
        $script:EngineNC | Should -Not -Match 'pruned as futile'
        $script:EngineNC | Should -Match ([regex]::Escape("if (-not `$pAgain -and `$pHow -in @('key', 'row') -and -not [bool]`$item.M"))
        # the same outcome as before for "all four children refused": that parent's children are stopped at their dequeue,
        # each a named loss
        $r = Invoke-SubSplitModel -FailedAt @{ 1 = 4 }
        @($r.Lost).Count | Should -Be 4
        @($r.Lost) | ForEach-Object { $_ | Should -Match 'not split further' }
    }
    It 'the measured stop and both ends are counted losses (Add-RABucketLoss), so the report can never read as complete' {
        $script:EngineNC | Should -Match ([regex]::Escape('Test-RASplitReducesFailure -Tried $('))
        $script:EngineNC | Should -Match ([regex]::Escape('not split further -- splitting did not reduce the failure of bucket {3}'))
        $script:EngineNC | Should -Match ([regex]::Escape('the key partition cannot be split finer'))
    }
}
