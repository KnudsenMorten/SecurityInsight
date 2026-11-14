#Requires -Version 7.0
<#
    #1216 -- A QUERY SLICE ADVANCED HUNTING ANSWERS 504 TWICE IS SPLIT IN HALVES, NEVER ASKED AGAIN AS THE SAME QUERY.

    Live 2026-11-12 (a large install, Risk Analysis Detailed on a scale-out worker): an attack-path report over SI_CI_CL + the
    exposure graph ran in 42 slices; 15 of them answered 504 Gateway Timeout after ~200 s on EVERY attempt (4 attempts a round),
    the late-retry rounds asked the SAME query again, and the report's recovery budget ended with 15 slices "not read".

    What these tests keep true (offline, no tenant; the engine's loops in miniature over the SAME helpers, a fake advanced
    hunting that honours the stop exactly as Invoke-GraphHuntingQuery does):
      * EQUIVALENCE: a fake source that answers 504 above N rows and answers below -- the halves (and their halves) return
        exactly the rows of the unsplit query, none twice, nothing lost; a heavy slice is asked twice at its size, never more;
      * the floor is measured: a slice that times out at every size is halved twice and then stops as a named loss (no
        endless split, no fixed depth);
      * NEGATIVE: a 429, a busy answer and a one-off 504 still ask the SAME query again (never split);
      * NEGATIVE: a query defect (400 / Fix syntax / Fix semantic errors) fails on attempt 1 (working rule 4) -- one call;
      * the helpers: the stop, the count, the action, the -Step of the measured stop, the run-log line;
      * the _ciPeer finding: cut per slice by the slice's hash it loses rows (its key is the path's TARGET, not the slice key)
        -- so it is never bucketed with the slice; whole or cut to the slice's needed keys it gives the same rows;
      * the engine wiring: the hunting layer counts 504s and stops at the caller's stop; the main pass, the late retry and the
        smaller slices set the stop before each call and route a slice answered 504 twice to halves; the run log line.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $shared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    . (Join-Path $shared 'RA-AutoBucketing.ps1')
    function Write-Info { param($msg) }
    function Write-Warn2 { param($msg) }
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $shared 'RA-ProfileAugment.ps1'), [ref]$null, [ref]$null)
    . ([scriptblock]::Create(($ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Get-SISha256Bucket' }, $true)).Extent.Text))
    $script:Engine  = Get-Content -Raw (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
    $script:Hunting = Get-Content -Raw (Join-Path $shared 'RA-GraphHunting.ps1')

    # THE SOURCE: 1,200 device keys; a key's slice at count C is the engine's own hash (Get-SISha256Bucket: first 4 bytes of
    # SHA256 as uint32, mod C) -- precomputed once, and checked against the engine function below.
    $script:Keys = @(1..1200 | ForEach-Object { 'dev-{0:d5}' -f $_ })
    $script:U = @{}
    foreach ($k in $script:Keys) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($k)) } finally { $sha.Dispose() }
        $b = [byte[]]($h[0..3]); [Array]::Reverse($b)
        $script:U[$k] = [System.BitConverter]::ToUInt32($b, 0)
    }
    $script:Slice = { param([long]$C, [long]$I) @($script:Keys | Where-Object { ([long]$script:U[$_] % $C) -eq $I }) }

    # THE FAKE ADVANCED HUNTING, as Invoke-GraphHuntingQuery: takes the caller's stop once and clears it, up to 4 attempts, a query
    # defect thrown at once, every 504 counted ($script:_LastGraphHuntingGatewayTimeouts) and, at the stop, thrown without asking
    # again. -Answer { param($C, $I, $Attempt) } returns the rows or throws. Every attempt is logged in $script:Asked.
    $script:Hunt = {
        param([long]$C, [long]$I, [scriptblock]$Answer)
        $stop = [int]$script:RAGatewayTimeoutStopAt; $script:RAGatewayTimeoutStopAt = 0
        $gw = 0; $script:_LastGraphHuntingGatewayTimeouts = 0
        for ($a = 1; $a -le 4; $a++) {
            $script:Asked.Add(('{0}/{1}' -f $I, $C))
            $script:AttemptNo[('{0}/{1}' -f $I, $C)] = 1 + [int]$script:AttemptNo[('{0}/{1}' -f $I, $C)]
            # the rows go out one by one (the caller collects them with @()): never wrapped as one array
            try { return @(& $Answer $C $I ([int]$script:AttemptNo[('{0}/{1}' -f $I, $C)])) }
            catch {
                $m = $_.Exception.Message
                if ((Get-RABucketFailureAction -Err $m) -eq 'Defect') { throw }
                if (Test-RABucketGatewayTimeout -Err $m) {
                    $gw++; $script:_LastGraphHuntingGatewayTimeouts = $gw
                    if ($stop -gt 0 -and $gw -ge $stop) { throw }
                }
                if ($a -eq 4) { throw }
            }
        }
    }

    # THE ENGINE'S LOOPS IN MINIATURE (Invoke-RiskAnalysis.ps1: the main pass, then the smaller slices), over the real helpers:
    # before each call the stop (Get-RAGatewayTimeoutStopAt), after a failure the count (Add-RASliceGatewayTimeouts) and the
    # route (Get-RABucketFailureAction, then Get-RAGatewayTimeoutAction): a slice answered 504 twice goes to halves; a Retry asks
    # the same query again (3 rounds); anything else is a named loss. The halves: two per slice (the same hash, 2x the count),
    # judged by the measured stop over two halvings (Test-RASplitReducesFailure -Step 2).
    $script:RunReport = {
        param([int]$Count, [scriptblock]$Answer, [int]$Outer = 3)
        $script:Asked = New-Object System.Collections.Generic.List[string]; $script:AttemptNo = @{}
        $rows = New-Object System.Collections.Generic.List[string]; $loss = New-Object System.Collections.Generic.List[string]
        $seen = @{}; $roots = New-Object System.Collections.Generic.List[int]; $finest = [long]$Count
        $canSplit = { param([long]$T) Test-RASubSplitAddressable -SliceCount $T -FanOut 2 }
        $ask = {
            param([long]$C, [long]$I)
            for ($att = 1; $att -le $Outer; $att++) {
                $key = ('{0}/{1}' -f $I, $C)
                $script:RAGatewayTimeoutStopAt = Get-RAGatewayTimeoutStopAt -Seen ([int]('0' + [string]$seen[$key])) -Off:(-not (& $canSplit $C))
                $script:_LastGraphHuntingGatewayTimeouts = -1
                try { return @{ Do = 'ok'; Rows = @(& $script:Hunt $C $I $Answer) } }
                catch {
                    $act = Get-RABucketFailureAction -Err $_
                    $n = Add-RASliceGatewayTimeouts -Seen $seen -Slice $key -Err $_ -Reported ([int]$script:_LastGraphHuntingGatewayTimeouts)
                    if ($act -eq 'Retry' -and (Get-RAGatewayTimeoutAction -Err $_ -Count $n -SplitAt $script:RAGatewaySplitAt -CanSplit (& $canSplit $C)) -eq 'Split') { return @{ Do = 'split' } }
                    if ($act -eq 'Retry' -and $att -lt $Outer) { continue }
                    return @{ Do = 'lost'; Why = $act; Err = $_.Exception.Message }
                }
            }
        }
        $q = New-Object System.Collections.Generic.Queue[object]
        for ($b = 0; $b -lt $Count; $b++) {
            $r = & $ask $Count $b
            if ($r.Do -eq 'ok') { foreach ($x in $r.Rows) { $rows.Add([string]$x) } }
            elseif ($r.Do -eq 'split') { $roots.Add($b); $q.Enqueue(@{ N = [long]$b; T = [long]$Count; D = 1; R = $b }) }
            else { $loss.Add(('bucket {0}/{1}: {2} -- {3}' -f ($b + 1), $Count, $r.Why, $r.Err)) }
        }
        $tried = @{}; $failed = @{}
        $bump = { param([hashtable]$S, [int]$R, [int]$D) if (-not $S.ContainsKey($R)) { $S[$R] = @{} }; $S[$R][$D] = [int]('0' + [string]$S[$R][$D]) + 1 }
        while ($q.Count -gt 0) {
            $it = $q.Dequeue()
            if ($it.D -ge 2 -and -not (Test-RASplitReducesFailure -Tried $(if ($tried.ContainsKey($it.R)) { $tried[$it.R] } else { @{} }) -Failed $(if ($failed.ContainsKey($it.R)) { $failed[$it.R] } else { @{} }) -Depth $it.D -Step 2)) {
                $loss.Add(('slice {0}/{1} of bucket {2}: not split further' -f ($it.N + 1), $it.T, ($it.R + 1))); continue
            }
            $newT = $it.T * 2
            if ($newT -gt $finest) { $finest = $newT }
            for ($j = 0; $j -lt 2; $j++) {
                $subN = $it.N + $j * $it.T
                $r = & $ask $newT $subN
                & $bump $tried $it.R $it.D
                if ($r.Do -eq 'ok') { foreach ($x in $r.Rows) { $rows.Add([string]$x) } }
                elseif ($r.Do -eq 'split') { & $bump $failed $it.R $it.D; $q.Enqueue(@{ N = $subN; T = $newT; D = $it.D + 1; R = $it.R }) }
                else { $loss.Add(('slice {0}/{1}: {2}' -f ($subN + 1), $newT, $r.Why)) }
            }
        }
        [pscustomobject]@{ Rows = @($rows); Loss = @($loss); Roots = @($roots); Finest = $finest; Asked = @($script:Asked) }
    }
    # the gateway's time limit as a row count: a slice of more than $script:HeavyN rows answers 504, a smaller one answers
    $script:HeavyN = 100
    $script:Heavy = { param($C, $I, $A) $r = & $script:Slice $C $I; if ($r.Count -gt $script:HeavyN) { throw 'Response status code does not indicate success: 504 (Gateway Timeout).' }; $r }
}

Describe '#1216 the fake source is the engine''s own partition' {
    It 'the precomputed slice of a key is Get-SISha256Bucket, and halves are exactly their parent' {
        foreach ($k in $script:Keys[0..39]) {
            foreach ($c in 8, 16, 42, 84) { [int]([long]$script:U[$k] % $c) | Should -Be ([int](Get-SISha256Bucket -Key $k -BucketCount $c)) }
        }
        foreach ($i in 0..7) {
            $parent = & $script:Slice 8 $i
            $halves = @(& $script:Slice 16 $i) + @(& $script:Slice 16 ($i + 8))
            (Compare-Object $parent $halves) | Should -BeNullOrEmpty
        }
    }
}

Describe '#1216 EQUIVALENCE: a fake advanced hunting that answers 504 above N rows and answers below' {
    It 'the slices over 100 rows answer 504 at 8 slices: the halves give exactly the unsplit rows, none twice' {
        $script:HeavyN = 100
        $want = @(0..7 | Where-Object { @(& $script:Slice 8 $_).Count -gt 100 })
        $want.Count | Should -BeGreaterThan 0 -Because 'the fixture has slices over the limit (1,200 rows in 8 slices: ~150 each)'
        $r = & $script:RunReport -Count 8 -Answer $script:Heavy
        $r.Loss | Should -BeNullOrEmpty
        $r.Roots | Should -Be $want
        $r.Rows.Count | Should -Be 1200 -Because 'no row twice'
        (Compare-Object ($r.Rows | Sort-Object) ($script:Keys | Sort-Object)) | Should -BeNullOrEmpty
        $r.Finest | Should -BeGreaterOrEqual 16
        # each heavy slice was asked exactly twice at its own size -- the second 504 ends it, never 4 attempts x 3 rounds
        foreach ($b in $want) { @($r.Asked | Where-Object { $_ -eq ('{0}/8' -f $b) }).Count | Should -Be 2 }
    }
    It 'heavier: halves of halves (and deeper where needed) until each answers -- still exactly the unsplit rows' {
        $script:HeavyN = 50
        $r = & $script:RunReport -Count 8 -Answer $script:Heavy
        $script:HeavyN = 100
        $r.Loss | Should -BeNullOrEmpty
        $r.Rows.Count | Should -Be 1200
        (Compare-Object ($r.Rows | Sort-Object) ($script:Keys | Sort-Object)) | Should -BeNullOrEmpty
        $r.Finest | Should -BeGreaterOrEqual 32 -Because 'a slice of ~150 rows needs at least two halvings to come under 50'
        # nothing is asked again at a size that already answered 504 twice
        $byKey = $r.Asked | Group-Object
        foreach ($g in $byKey) { $g.Count | Should -BeLessOrEqual 2 }
    }
    It 'only the heavy slices are split; a light slice is asked once' {
        # a mixed source: slices 2 and 5 are heavy (all their rows), the others answer
        $ans = { param($C, $I, $A) if ($C -eq 8 -and $I -in 2, 5) { throw '504 (Gateway Timeout)' }; & $script:Slice $C $I }
        $r = & $script:RunReport -Count 8 -Answer $ans
        $r.Roots | Should -Be @(2, 5)
        $r.Loss | Should -BeNullOrEmpty
        (Compare-Object ($r.Rows | Sort-Object) ($script:Keys | Sort-Object)) | Should -BeNullOrEmpty
        @($r.Asked | Where-Object { $_ -eq '0/8' }).Count | Should -Be 1
        @($r.Asked | Where-Object { $_ -in '2/16', '10/16', '5/16', '13/16' }).Count | Should -Be 4
    }
}

Describe '#1216 the floor is measured, never a fixed depth' {
    It 'a slice that times out at EVERY size is halved twice (one 4-way step), then stops as a named loss' {
        $ans = { param($C, $I, $A) if ($I % 8 -eq 3) { throw '504 (Gateway Timeout)' }; & $script:Slice $C $I }
        $r = & $script:RunReport -Count 8 -Answer $ans
        $r.Roots | Should -Be @(3)
        $r.Finest | Should -Be 32 -Because '1/8 -> 1/16 -> 1/32; the halves of the halves refused as often as the slice: no further split'
        $r.Loss.Count | Should -Be 4
        $r.Loss | ForEach-Object { $_ | Should -Match 'of bucket 4: not split further' }
        @($r.Asked | Where-Object { $_ -like '*/64' }).Count | Should -Be 0
        # the other slices are all there, nothing of the refused one is claimed
        $want = @($script:Keys | Where-Object { ([long]$script:U[$_] % 8) -ne 3 })
        (Compare-Object ($r.Rows | Sort-Object) ($want | Sort-Object)) | Should -BeNullOrEmpty
    }
    It 'Test-RASplitReducesFailure -Step 2: the first two halvings always run; then the share is compared two halvings back' {
        Test-RASplitReducesFailure -Tried @{ 1 = 2 } -Failed @{ 1 = 2 } -Depth 2 -Step 2 | Should -BeTrue -Because 'one halving is half a 4-way step'
        Test-RASplitReducesFailure -Tried @{ 1 = 2; 2 = 4 } -Failed @{ 1 = 2; 2 = 4 } -Depth 3 -Step 2 | Should -BeFalse
        Test-RASplitReducesFailure -Tried @{ 1 = 2; 2 = 4 } -Failed @{ 1 = 2; 2 = 1 } -Depth 3 -Step 2 | Should -BeTrue
        Test-RASplitReducesFailure -Tried @{ 1 = 2; 2 = 4; 3 = 2 } -Failed @{ 1 = 2; 2 = 1; 3 = 2 } -Depth 4 -Step 2 | Should -BeFalse -Because '2 of 2 is not below 2 of 2 two halvings back'
    }
    It '-Step 1 (the default) is the 4-way rule unchanged' {
        Test-RASplitReducesFailure -Tried @{ 1 = 4 } -Failed @{ 1 = 4 } -Depth 2 | Should -BeFalse
        Test-RASplitReducesFailure -Tried @{ 1 = 4 } -Failed @{ 1 = 3 } -Depth 2 | Should -BeTrue
        Test-RASplitReducesFailure -Tried @{ 1 = 4; 2 = 12 } -Failed @{ 1 = 3; 2 = 9 } -Depth 3 | Should -BeFalse
    }
    It 'no finer slice the hash partition can address: the slice is asked with every retry as before (no stop, no split)' {
        Get-RAGatewayTimeoutStopAt -Seen 0 -Off | Should -Be 0
        Get-RAGatewayTimeoutAction -Err '504 (Gateway Timeout)' -Count 5 -CanSplit $false | Should -Be 'Retry'
        Test-RASubSplitAddressable -SliceCount ([int]::MaxValue) -FanOut 2 | Should -BeFalse
    }
}

Describe '#1216 NEGATIVE: a throttle, a busy answer and a one-off 504 still ask the SAME query' {
    It 'a 429 on five attempts in a row: retried at the same size, never split, every row' {
        $ans = { param($C, $I, $A) if ($C -eq 8 -and $I -eq 3 -and $A -le 5) { throw '429 Too Many Requests' }; & $script:Slice $C $I }
        $r = & $script:RunReport -Count 8 -Answer $ans
        $r.Roots | Should -BeNullOrEmpty
        $r.Finest | Should -Be 8
        @($r.Asked | Where-Object { $_ -eq '3/8' }).Count | Should -Be 6 -Because 'the same query, asked again until it answered'
        (Compare-Object ($r.Rows | Sort-Object) ($script:Keys | Sort-Object)) | Should -BeNullOrEmpty
        Get-RAGatewayTimeoutAction -Err '429 Too Many Requests' -Count 9 | Should -Be 'Retry'
    }
    It 'a 503 and a busy answer (preempted) are never counted as 504s and never split' {
        $ans = { param($C, $I, $A) if ($C -eq 8 -and $I -eq 1 -and $A -le 3) { throw '504 Query execution was preempted due to high CPU and/or memory resource consumption' }; if ($C -eq 8 -and $I -eq 6 -and $A -le 3) { throw '503 Service Unavailable' }; & $script:Slice $C $I }
        $r = & $script:RunReport -Count 8 -Answer $ans
        $r.Roots | Should -BeNullOrEmpty
        (Compare-Object ($r.Rows | Sort-Object) ($script:Keys | Sort-Object)) | Should -BeNullOrEmpty
        $s = @{}
        Add-RASliceGatewayTimeouts -Seen $s -Slice 'x' -Err '504 query preempted due to high CPU' | Should -Be 0
        Add-RASliceGatewayTimeouts -Seen $s -Slice 'x' -Err '503 Service Unavailable' | Should -Be 0
    }
    It 'a one-off 504 is retried by the same query and answers: no split' {
        $ans = { param($C, $I, $A) if ($C -eq 8 -and $I -eq 2 -and $A -eq 1) { throw '504 (Gateway Timeout)' }; & $script:Slice $C $I }
        $r = & $script:RunReport -Count 8 -Answer $ans
        $r.Roots | Should -BeNullOrEmpty
        @($r.Asked | Where-Object { $_ -eq '2/8' }).Count | Should -Be 2
        (Compare-Object ($r.Rows | Sort-Object) ($script:Keys | Sort-Object)) | Should -BeNullOrEmpty
        Get-RABucketFailureAction -Err '504 (Gateway Timeout)' | Should -Be 'Retry' -Because 'one 504 alone is still a platform answer'
        Get-RAGatewayTimeoutAction -Err '504 (Gateway Timeout)' -Count 1 | Should -Be 'Retry'
    }
}

Describe '#1216 NEGATIVE: a query defect still fails on attempt 1 (working rule 4)' {
    It '<Msg>: one call, a named loss as a defect, never retried, never split' -ForEach @(
        @{ Msg = '400 Bad Request: Query could not be parsed. Fix syntax errors in your query.' }
        @{ Msg = 'BadRequest: Fix semantic errors in your query. return types are not compatible' }
    ) {
        $script:DefectMsg = $Msg
        $ans = { param($C, $I, $A) if ($C -eq 8 -and $I -eq 5) { throw $script:DefectMsg }; & $script:Slice $C $I }
        $r = & $script:RunReport -Count 8 -Answer $ans
        @($r.Asked | Where-Object { $_ -eq '5/8' }).Count | Should -Be 1
        $r.Roots | Should -BeNullOrEmpty
        $r.Loss.Count | Should -Be 1
        $r.Loss[0] | Should -Match '^bucket 6/8: Defect'
        Get-RABucketFailureAction -Err $Msg | Should -Be 'Defect'
    }
}

Describe '#1216 the helpers' {
    It 'the stop: two 504s a slice, less the ones it already had, at least 1' {
        Get-RAGatewayTimeoutStopAt -Seen 0 | Should -Be 2
        Get-RAGatewayTimeoutStopAt -Seen 1 | Should -Be 1
        Get-RAGatewayTimeoutStopAt -Seen 5 | Should -Be 1
        $script:RAGatewaySplitAt | Should -Be 2
    }
    It 'the count: the hunting call''s own count when it reports one, else 1 for a 504' {
        $s = @{}
        Add-RASliceGatewayTimeouts -Seen $s -Slice '0/42' -Err '429 Too Many Requests' -Reported 1 | Should -Be 1
        Add-RASliceGatewayTimeouts -Seen $s -Slice '0/42' -Err '504 (Gateway Timeout)' | Should -Be 2
        Add-RASliceGatewayTimeouts -Seen $s -Slice '1/42' -Err '504 (Gateway Timeout)' -Reported 2 | Should -Be 2
        $s['0/42'] | Should -Be 2
    }
    It 'the action: a 504 counted twice with a finer slice -> Split; the last answer must be the 504 itself' {
        Get-RAGatewayTimeoutAction -Err 'Response status code does not indicate success: 504 (Gateway Timeout).' -Count 2 | Should -Be 'Split'
        Get-RAGatewayTimeoutAction -Err '{"error":{"code":"GatewayTimeout"}}' -Count 3 | Should -Be 'Split'
        Get-RAGatewayTimeoutAction -Err '429 Too Many Requests' -Count 2 | Should -Be 'Retry' -Because 'the API is throttling now: the same query, after a pause'
    }
    It 'the run log line: how many slices, how deep, recovered or not' {
        $l = Format-RAGatewaySplitSummary -ReportName 'R' -Slices 15 -Finest 168 -BucketCount 42
        $l | Should -Be "[gateway split] 'R': 15 of 42 query slice(s) answered 504 Gateway Timeout twice and were split in halves instead of being asked again -- 2 halving(s) deep at most (finest slice 1/168); every one recovered"
        Format-RAGatewaySplitSummary -ReportName 'R' -Slices 1 -Finest 84 -BucketCount 42 -Lost 1 | Should -Match '1 halving\(s\) deep at most \(finest slice 1/84\); 1 of them still have rows unknown'
    }
}

Describe '#1216 the _ciPeer finding: it is never cut by the slice''s hash' {
    BeforeAll {
        # paths from an entry device (the slice key) to an Azure target; _ciPeer has one row per target key (its _peerKey).
        $script:Targets = @(1..60 | ForEach-Object { 'az-{0:d3}' -f $_ })
        $script:Paths = @(for ($p = 0; $p -lt 400; $p++) { [pscustomobject]@{ DeviceKey = $script:Keys[$p]; TargetKey = $script:Targets[($p * 7) % 60] } })
        $script:Peer = @{}; foreach ($t in $script:Targets) { $script:Peer[$t] = "tier-of-$t" }
        $script:Enriched = {
            param([int]$C, [string]$How)
            $out = New-Object System.Collections.Generic.List[string]
            for ($i = 0; $i -lt $C; $i++) {
                $slice = @($script:Paths | Where-Object { (Get-SISha256Bucket -Key $_.DeviceKey -BucketCount $C) -eq $i })
                $peer = switch ($How) {
                    'whole'  { $script:Peer }
                    'needed' { $h = @{}; foreach ($p in $slice) { $h[$p.TargetKey] = $script:Peer[$p.TargetKey] }; $h }
                    'hash'   { $h = @{}; foreach ($t in $script:Targets) { if ((Get-SISha256Bucket -Key $t -BucketCount $C) -eq $i) { $h[$t] = $script:Peer[$t] } }; $h }
                }
                foreach ($p in $slice) { $out.Add(('{0}>{1}:{2}' -f $p.DeviceKey, $p.TargetKey, [string]$peer[$p.TargetKey])) }
            }
            @($out | Sort-Object)
        }
    }
    It 'whole in every slice, or cut to the slice''s needed keys (LookupNeededKeys): the same rows as unsliced' {
        $unsliced = & $script:Enriched 1 'whole'
        (Compare-Object (& $script:Enriched 8 'whole') $unsliced) | Should -BeNullOrEmpty
        (Compare-Object (& $script:Enriched 8 'needed') $unsliced) | Should -BeNullOrEmpty
        (Compare-Object (& $script:Enriched 16 'needed') $unsliced) | Should -BeNullOrEmpty
    }
    It 'cut by the slice''s own hash (as _ciLink is) the targets lose their CI -- NOT the same rows, so it is not done' {
        $unsliced = & $script:Enriched 1 'whole'
        $hashed = & $script:Enriched 8 'hash'
        $lostCi = @($hashed | Where-Object { $_ -match ':$' }).Count
        $lostCi | Should -BeGreaterThan 0
        (Compare-Object $hashed $unsliced) | Should -Not -BeNullOrEmpty
    }
    It 'the report declares _ciPeer for the needed-key cut, and the catalog does not slice it' {
        $y = Get-Content -Raw (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')
        $i = $y.IndexOf('- ReportName: Attack_Paths_Detailed_Device_with_high_severity_vulnerabilities_allows_lateral_movement_Azure')
        $i | Should -BeGreaterThan 0
        $y.Substring($i, 1500) | Should -Match '(?s)LookupNeededKeys:\s+- Lookup: _ciPeer\s+Column: _peerKey'
    }
}

Describe '#1216 the engine wiring' {
    It 'the hunting layer takes the caller''s stop once, clears it, counts each 504 and stops at it -- before its own retry' {
        $script:Hunting | Should -Match ([regex]::Escape('$__gwStopAt = [int]$script:RAGatewayTimeoutStopAt'))
        $script:Hunting | Should -Match '(?s)\$__gwStopAt = \[int\]\$script:RAGatewayTimeoutStopAt\s+\$script:RAGatewayTimeoutStopAt = 0'
        $i = $script:Hunting.IndexOf('(Test-RABucketGatewayTimeout -Err $_)')
        $i | Should -BeGreaterThan 0
        $i | Should -BeLessThan $script:Hunting.IndexOf('if ($attempt -lt $MaxRetries) {')
        $script:Hunting.Substring($i, 500) | Should -Match '(?s)\$__gwHere\+\+.{0,120}\$script:_LastGraphHuntingGatewayTimeouts = \$__gwHere.{0,120}if \(\$__gwStopAt -gt 0 -and \$__gwHere -ge \$__gwStopAt\)'
        # a query defect is still thrown before (attempt 1, working rule 4)
        $script:Hunting.IndexOf('if ($looksQueryDefect) {') | Should -BeLessThan $i
        $script:Hunting | Should -Match ([regex]::Escape('$script:_LastGraphHuntingGatewayTimeouts = $__gwHere   # #1216'))
    }
    It 'the main pass, the late retry and the smaller slices set the stop right before their call' {
        ([regex]::Matches($script:Engine, '\$script:RAGatewayTimeoutStopAt = Get-RAGatewayTimeoutStopAt -Seen ')).Count | Should -Be 3
        ([regex]::Matches($script:Engine, '\$__gwN = Add-RASliceGatewayTimeouts -Seen \$__gwSeen -Slice \$__gwKey -Err \$_ -Reported \(\[int\]\$script:_LastGraphHuntingGatewayTimeouts\)')).Count | Should -Be 3
        ([regex]::Matches($script:Engine, 'Get-RAGatewayTimeoutAction -Err \$_ -Count \$__gwN -SplitAt \$script:RAGatewaySplitAt')).Count | Should -Be 3
    }
    It 'the main pass sends a slice answered 504 twice to the halves (the sub-bucket pass), never to the late retry' {
        $i = $script:Engine.IndexOf("if (`$bucketAction -eq 'GatewaySplit') {")
        $i | Should -BeGreaterThan 0
        $blk = $script:Engine.Substring($i, 900)
        $blk | Should -Match '\$__gwRoots\[\[int\]\$b\] = \$true'
        $blk | Should -Match '\[void\]\$failedBucketIndices\.Add\(\$b\)'
        $blk | Should -Not -Match 'deferredBucketIndices'
    }
    It 'the late retry routes it to the halves before its own Split / Retry branches' {
        $i = $script:Engine.IndexOf('$dbAction = Get-RABucketFailureAction -Err $_')
        $blk = $script:Engine.Substring($i, 2000)
        $blk | Should -Match '(?s)Get-RAGatewayTimeoutAction.{0,1000}\[void\]\$failedBucketIndices\.Add\(\$db\).{0,120}\} elseif \(\$dbAction -eq ''Split''\) \{'
    }
    It 'the sub-bucket pass splits a slice in HALVES (K = 2) and judges them over two halvings' {
        $script:Engine | Should -Match ([regex]::Escape("K = `$(if (`$__gwR) { 2 } else { `$subFanOut }); G = `$__gwR })"))
        $script:Engine | Should -Match ([regex]::Escape("K = `$(if (`$__subGw) { 2 } else { `$subFanOut }); G = [bool]`$__subGw })"))
        $script:Engine | Should -Match ([regex]::Escape('$newT    = if ($pHow -eq ''row'' -or $pAgain) { $pT } else { $pT * $pFan }'))
        $script:Engine | Should -Match ([regex]::Escape('-SubBucketCount $pFan -SubBucketIndex $j'))
        $script:Engine | Should -Match ([regex]::Escape('-Depth $depth -Step $(if ($pGw) { 2 } else { 1 })'))
        # a smaller slice answered 504 twice is a size split there: no retry round, no recovery clock
        $i = $script:Engine.IndexOf('$__subGw = ($subAction -eq ''Retry''')
        $i | Should -BeGreaterThan 0
        $i | Should -BeLessThan $script:Engine.IndexOf("if (`$subAction -eq 'Retry') { & `$__rbStart }")
    }
    It 'the run log says per report how many slices were split and how deep' {
        $script:Engine | Should -Match 'Write-Info \(Format-RAGatewaySplitSummary -ReportName \$ReportName -Slices \$__gwRoots\.Count -Finest \$__gwFin'
        $script:Engine.IndexOf('Format-RAGatewaySplitSummary') | Should -BeLessThan $script:Engine.IndexOf('$bucketRunSucceeded = $true')
    }
}
