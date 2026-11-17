#Requires -Version 7.0
<#
    #1275 STAGE 1 (owner 2026-11-17: "go with stage 1"; "no data loss"; "remember it can be millions of rows") -- the slow
    detailed Risk Analysis step. Every test proves ZERO rows lost or changed against today's code on the same input.

      (1) a 504 on a slice's KEY query counts towards the split exactly like a 504 on its row query (it reset to 0 and the
          slice was asked again until the recovery budget was spent: "not read"). The union of the halves IS the slice.
      (2) the slices are sized at half the DOCUMENTED time limit per request of the back end that answers them (advanced
          hunting 180 s, Log Analytics 600 s with "Prefer: wait=600", the data lake 240 s) instead of half the 900 s client
          ceiling; the planning row target (30,000) and the cut limit (100,000 advanced hunting) read ONE table. Only the
          slice COUNTS change: the same rows, the same Expected / Retrieved / Stored.
      (3) after review F1: the count just after the read is ALWAYS asked (the independent check); only when BOTH counts
          failed and no slice was lost do the slices stand for the count, and the report says "count taken from the slices".
      (5) the JSON file is written after the result is completed in the database, with EXACTLY the rows it had before
          (the held set taken where it was written; a report the end guards judge NOT COMPLETE is still in it) -- byte
          for byte (SQL Server).
    (4), the set-based Top 50 lists over a column in another case, is in SIv3-RaTop50SetBased.Tests.ps1.
    Scale (on demand): (2) over 1.5 M generated keys. NO EMOJI IN THIS FILE.
#>

BeforeDiscovery {
    $script:SqlUp = $false
    if ($env:SI_TEST_LOCALSQL) {
        for ($try = 0; $try -lt 6 -and -not $script:SqlUp; $try++) {
            try { $p = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=60"; $p.Open(); $p.Dispose(); $script:SqlUp = $true } catch { Start-Sleep -Seconds 5 }
        }
    }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $shared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    function script:Write-Info { param($m) $script:Said += , [string]$m }
    function script:Write-Warn2 { param($m) }
    . (Join-Path $shared 'RA-AutoBucketing.ps1')
    . (Join-Path $shared 'RA-BucketStore.ps1')
    . (Join-Path $shared 'RA-SqlStream.ps1')
    . (Join-Path $shared 'RA-ScaleOut.ps1')
    $script:HuntingText = [IO.File]::ReadAllText((Join-Path $shared 'RA-GraphHunting.ps1'))
    $script:Engine = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
    $hAst = [System.Management.Automation.Language.Parser]::ParseInput($script:HuntingText, [ref]$null, [ref]$null)
    foreach ($fn in 'Invoke-RAKeyQueryCounted', 'Get-RAQueryBackend', 'Test-RAQueryNeedsAdvancedHunting') {
        . ([scriptblock]::Create(($hAst.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $fn }, $true)).Extent.Text))
    }
    $pAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $shared 'RA-ProfileAugment.ps1'), [ref]$null, [ref]$null)
    . ([scriptblock]::Create(($pAst.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Get-SISha256Bucket' }, $true)).Extent.Text))
    function script:Get-EngineFunction([string]$Name) {
        $body = [regex]::Match($script:Engine, ('(?s)function {0} \{{.*?\n\}}' -f [regex]::Escape($Name))).Value
        if (-not $body) { throw "function $Name not found in the engine" }
        $body
    }

    # THE SOURCE: device keys; a key's slice at count C is the engine's own hash (first 4 bytes of SHA256 as uint32, mod C)
    function script:New-KeySource([int]$N) {
        $u = [uint32[]]::new($N); $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            for ($i = 0; $i -lt $N; $i++) {
                $h = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(('dev-{0:d7}' -f $i)))
                $u[$i] = ([uint32]$h[0] -shl 24) -bor ([uint32]$h[1] -shl 16) -bor ([uint32]$h[2] -shl 8) -bor [uint32]$h[3]
            }
        } finally { $sha.Dispose() }
        , $u
    }
    $script:U = New-KeySource -N 1200
    # (the loop variable is $k: PowerShell names ignore case, a loop $i would overwrite the slice index $I)
    $script:Slice = { param([long]$C, [long]$I) @(for ($k = 0; $k -lt $script:U.Length; $k++) { if (([long]$script:U[$k] % $C) -eq $I) { $k } }) }

    # THE FAKE ADVANCED HUNTING, as Invoke-GraphHuntingQuery is ordered: the caller's stop taken once and cleared, its 504
    # count reset to 0, THEN the slice's key query (one attempt, before the retry loop -- Invoke-RALookupKeyDiscovery), then
    # up to 4 attempts of the rows with every 504 counted and, at the stop, thrown. -Key: the key query's answer (throws or
    # not); -Counted: the key query goes through Invoke-RAKeyQueryCounted (the fix), else it is called as before the fix.
    $script:Hunt = {
        param([long]$C, [long]$I, [scriptblock]$Key, [bool]$Counted)
        $stop = [int]$script:RAGatewayTimeoutStopAt; $script:RAGatewayTimeoutStopAt = 0
        $gw = 0; $script:_LastGraphHuntingGatewayTimeouts = 0
        $script:Asked.Add(('{0}/{1}' -f $I, $C))
        $script:AttemptNo[('{0}/{1}' -f $I, $C)] = 1 + [int]$script:AttemptNo[('{0}/{1}' -f $I, $C)]
        if ($Counted) { Invoke-RAKeyQueryCounted -Counted $gw -Ask { & $Key $C $I } }
        else { & $Key $C $I }
        for ($a = 1; $a -le 4; $a++) {
            try { return @(& $script:Slice $C $I) }
            catch {
                if (Test-RABucketGatewayTimeout -Err $_) { $gw++; $script:_LastGraphHuntingGatewayTimeouts = $gw; if ($stop -gt 0 -and $gw -ge $stop) { throw } }
                if ($a -eq 4) { throw }
            }
        }
    }
    # THE ENGINE'S LOOPS IN MINIATURE (as SIv3-RaBucketSplit): the stop before each call, the count after a failure, the route.
    $script:RunReport = {
        param([int]$Count, [scriptblock]$Key, [bool]$Counted, [int]$Outer = 3)
        $script:Asked = New-Object System.Collections.Generic.List[string]; $script:AttemptNo = @{}
        $rows = New-Object System.Collections.Generic.List[int]; $loss = New-Object System.Collections.Generic.List[string]
        $seen = @{}; $roots = New-Object System.Collections.Generic.List[int]
        $canSplit = { param([long]$T) Test-RASubSplitAddressable -SliceCount $T -FanOut 2 }
        $ask = {
            param([long]$C, [long]$I)
            for ($att = 1; $att -le $Outer; $att++) {
                $k = ('{0}/{1}' -f $I, $C)
                $script:RAGatewayTimeoutStopAt = Get-RAGatewayTimeoutStopAt -Seen ([int]('0' + [string]$seen[$k])) -Off:(-not (& $canSplit $C))
                $script:_LastGraphHuntingGatewayTimeouts = -1
                try { return @{ Do = 'ok'; Rows = @(& $script:Hunt $C $I $Key $Counted) } }
                catch {
                    $act = Get-RABucketFailureAction -Err $_
                    $n = Add-RASliceGatewayTimeouts -Seen $seen -Slice $k -Err $_ -Reported ([int]$script:_LastGraphHuntingGatewayTimeouts)
                    if ($act -eq 'Retry' -and (Get-RAGatewayTimeoutAction -Err $_ -Count $n -SplitAt $script:RAGatewaySplitAt -CanSplit (& $canSplit $C)) -eq 'Split') { return @{ Do = 'split' } }
                    if ($act -eq 'Retry' -and $att -lt $Outer) { continue }
                    return @{ Do = 'lost'; Why = $act }
                }
            }
        }
        $q = New-Object System.Collections.Generic.Queue[object]
        for ($b = 0; $b -lt $Count; $b++) {
            $r = & $ask $Count $b
            if ($r.Do -eq 'ok') { foreach ($x in $r.Rows) { $rows.Add([int]$x) } }
            elseif ($r.Do -eq 'split') { $roots.Add($b); $q.Enqueue(@{ N = [long]$b; T = [long]$Count }) }
            else { $loss.Add(('bucket {0}/{1}: {2}' -f ($b + 1), $Count, $r.Why)) }
        }
        while ($q.Count -gt 0) {
            $it = $q.Dequeue(); $newT = $it.T * 2
            for ($j = 0; $j -lt 2; $j++) {
                $subN = $it.N + $j * $it.T
                $r = & $ask $newT $subN
                if ($r.Do -eq 'ok') { foreach ($x in $r.Rows) { $rows.Add([int]$x) } }
                elseif ($r.Do -eq 'split') { $q.Enqueue(@{ N = $subN; T = $newT }) }
                else { $loss.Add(('slice {0}/{1}: {2}' -f ($subN + 1), $newT, $r.Why)) }
            }
        }
        [pscustomobject]@{ Rows = @($rows); Loss = @($loss); Roots = @($roots); Asked = @($script:Asked) }
    }
    # the key query of a heavy slice (over 100 rows) is too slow for the gateway: 504
    $script:HeavyKey = { param($C, $I) if (@(& $script:Slice $C $I).Count -gt 100) { throw 'Response status code does not indicate success: 504 (Gateway Timeout).' } }
}

Describe '#1275 (1) a 504 on the slice''s KEY query counts towards the split' {
    It 'Invoke-RAKeyQueryCounted: a 504 is counted (the call''s 504s so far + 1) and thrown unchanged; anything else is not counted' {
        $script:_LastGraphHuntingGatewayTimeouts = 0
        { Invoke-RAKeyQueryCounted -Counted 0 -Ask { throw '504 (Gateway Timeout)' } } | Should -Throw '504 (Gateway Timeout)'
        $script:_LastGraphHuntingGatewayTimeouts | Should -Be 1
        { Invoke-RAKeyQueryCounted -Counted 1 -Ask { throw '{"error":{"code":"GatewayTimeout"}}' } } | Should -Throw
        $script:_LastGraphHuntingGatewayTimeouts | Should -Be 2
        $script:_LastGraphHuntingGatewayTimeouts = 0
        { Invoke-RAKeyQueryCounted -Ask { throw '429 Too Many Requests' } } | Should -Throw '429 Too Many Requests'
        { Invoke-RAKeyQueryCounted -Ask { throw '504 Query execution was preempted due to high CPU and/or memory resource consumption' } } | Should -Throw
        $script:_LastGraphHuntingGatewayTimeouts | Should -Be 0 -Because 'a throttle and a busy answer are never counted as the gateway''s time limit'
        Invoke-RAKeyQueryCounted -Ask { 'answer' } | Should -Be 'answer'
    }
    It 'the key query answers 504 twice -> GatewaySplit: the slice is split in halves and the union of the halves IS the slice -- every row, none twice' {
        $r = & $script:RunReport -Count 8 -Key $script:HeavyKey -Counted $true
        $want = @(0..7 | Where-Object { @(& $script:Slice 8 $_).Count -gt 100 })
        $want.Count | Should -BeGreaterThan 0 -Because 'the fixture has slices whose key query is too slow (1,200 keys in 8 slices: ~150 each)'
        $r.Roots | Should -Be $want
        $r.Loss | Should -BeNullOrEmpty
        $r.Rows.Count | Should -Be 1200 -Because 'no row twice'
        (Compare-Object ($r.Rows | Sort-Object) (0..1199)) | Should -BeNullOrEmpty -Because 'no row lost'
        foreach ($b in $want) {
            @($r.Asked | Where-Object { $_ -eq ('{0}/8' -f $b) }).Count | Should -Be 2 -Because 'the second 504 ends it -- never 3 rounds of the same query'
            # the halves are exactly the slice (the same hash at twice the count)
            (Compare-Object @(& $script:Slice 8 $b) (@(& $script:Slice 16 $b) + @(& $script:Slice 16 ($b + 8)))) | Should -BeNullOrEmpty
        }
    }
    It 'NEGATIVE CONTROL (today''s code): the key query''s 504 never counted -- the heavy slices are asked round after round and never split' {
        $r = & $script:RunReport -Count 8 -Key $script:HeavyKey -Counted $false
        $r.Roots | Should -BeNullOrEmpty
        @($r.Loss).Count | Should -BeGreaterThan 0 -Because 'they end lost (in the engine: "not read" when the recovery budget is spent)'
    }
    It 'the engine: both key queries of a slice go through the counter, with the call''s own 504 count; none is called bare' {
        ([regex]::Matches($script:HuntingText, [regex]::Escape('Invoke-RAKeyQueryCounted -Counted $__gwHere -Ask { Invoke-RALookupKeyDiscovery '))).Count | Should -Be 2
        ([regex]::Matches($script:HuntingText, '(?m)^\s+Invoke-RALookupKeyDiscovery ')).Count | Should -Be 0
        # the count is reset at the call's entry and the key query runs after that, before the retry loop
        $script:HuntingText.IndexOf('$script:_LastGraphHuntingGatewayTimeouts = 0', $script:HuntingText.IndexOf('function Invoke-GraphHuntingQuery')) |
            Should -BeLessThan $script:HuntingText.IndexOf('Invoke-RAKeyQueryCounted -Counted $__gwHere')
    }
}

Describe '#1275 (2) the slices are sized at half the back end''s documented time limit; the row numbers read one table' {
    BeforeEach { $script:SIRaSliceBackend = 'hunting' }
    It 'the documented limits per request: 180 s advanced hunting, 600 s Log Analytics (Prefer: wait=600), 240 s the data lake; unknown = the tightest' {
        Get-SIRaSliceSecondsLimit -Backend 'hunting' | Should -Be 180
        Get-SIRaSliceSecondsLimit -Backend 'loganalytics' | Should -Be 600
        Get-SIRaSliceSecondsLimit -Backend 'lake' | Should -Be 240
        Get-SIRaSliceSecondsLimit -Backend 'something' | Should -Be 180
        Get-SIRaSliceSecondsLimit -Measure ([pscustomobject]@{ Backend = 'lake' }) | Should -Be 240
        $script:SIRaSliceBackend = 'loganalytics'; Get-SIRaSliceSecondsLimit | Should -Be 600
        # the engine asks Log Analytics for up to 10 minutes
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-LogAnalyticsQuery.ps1')) | Should -Match '\[int\]\$TimeoutSec = 600'
    }
    It 'rows: the planning target (30,000, unchanged) is never above any back end''s cut limit; the cut check reads the same table' {
        foreach ($b in 'hunting', 'loganalytics', 'lake') {
            Get-SIRaPlanningRowLimit -Backend $b | Should -Be 30000
            Get-SIRaPlanningRowLimit -Backend $b | Should -BeLessOrEqual (Get-SIRaRowCutLimit -Backend $b)
        }
        Get-SIRaRowCutLimit -Backend 'hunting' | Should -Be 100000
        Get-SIRaRowCutLimit -Backend 'lake' | Should -Be 500000
        $script:HuntingText | Should -Match ([regex]::Escape("[int](Get-SIRaRowCutLimit -Backend 'hunting')"))
    }
    It 'a HISTORY row (no fixed part stored): exactly today''s count on every back end -- never more slices from a row that cannot say what slicing removes' {
        foreach ($b in '', 'hunting', 'loganalytics', 'lake') {
            $m = [pscustomobject]@{ ResultRows = 100; MaxBucketRows = 20; MaxBucketBytes = 4000; MaxBucketSeconds = 120; RanCount = 8; BucketCount = 8; Backend = $b }
            Get-SIRaBucketCountFromMeasure -Measure $m | Should -Be 4 -Because 'today: 120 x 8 / 450 -> 3 -> 4'
        }
        # the live identity report (customer A, 2026-11-17): 117 slices x 227 s for 172 rows -- today's rule from history: 64
        Get-SIRaBucketCountFromMeasure -Measure ([pscustomobject]@{ ResultRows = 172; MaxBucketRows = 3; MaxBucketBytes = 900; MaxBucketSeconds = 227; RanCount = 117; BucketCount = 117 }) | Should -Be 64
    }
    It 'the run''s OWN fixed part (as its slices show it): the divisible time against half the back end''s documented limit' {
        $mk = { param($b, $fixed) [pscustomobject]@{ ResultRows = 100; MaxBucketRows = 20; MaxBucketBytes = 4000; MaxBucketSeconds = 120; FixedSeconds = $fixed; RanCount = 8; BucketCount = 8; Backend = $b } }
        Get-SIRaBucketCountFromMeasure -Measure (& $mk 'hunting' 10) | Should -Be 16 -Because '(120 - 10) x 8 / (90 - 10) = 11 -> 16: a slice aims at 90 s of the API''s 180 s'
        Get-SIRaBucketCountFromMeasure -Measure (& $mk 'loganalytics' 10) | Should -Be 4 -Because '880 / 290 -> 4'
        Get-SIRaBucketCountFromMeasure -Measure (& $mk 'lake' 10) | Should -Be 8 -Because '880 / 110 -> 8'
        # A SLICE THAT IS MOSTLY ITS FIXED PART (the live over-slicing: ~170 rows, 117 slices of 227 s): more slices only repeat it
        $fx = { param($b) [pscustomobject]@{ ResultRows = 172; MaxBucketRows = 3; MaxBucketBytes = 900; MaxBucketSeconds = 227; FixedSeconds = 220; RanCount = 117; BucketCount = 117; Backend = $b } }
        Get-SIRaBucketCountFromMeasure -Measure (& $fx 'loganalytics') | Should -Be 16 -Because '(227 - 220) x 117 / (300 - 220) = 10.2 -> 16 (today 64)'
        Get-SIRaBucketCountFromMeasure -Measure (& $fx 'hunting') | Should -Be 1 -Because 'a fixed part over the whole 180 s limit: no count helps -- the time says nothing, the 172 rows decide'
        # review F3: a fixed part just under half the limit never makes the room ~1 s (at least a quarter of half the limit)
        Get-SIRaSliceTimeNeed -Seconds 100 -Count 8 -Measure ([pscustomobject]@{ FixedSeconds = 89; Backend = 'hunting' }) | Should -BeLessThan 4 -Because '(100 - 89) x 8 / max(1, 22.5) = 3.9, not 88'
        # a report sized by its ROWS only: the very same count on every back end and as before (the row target is not raised)
        foreach ($b in 'hunting', 'loganalytics', 'lake') {
            $r = [pscustomobject]@{ ResultRows = 100000; MaxBucketRows = 13000; MaxBucketBytes = 13000000; Backend = $b }
            Get-SIRaBucketCountFromMeasure -Measure $r | Should -Be 8 -Because '100,000 / 15,000 -> 7 -> 8, unchanged'
        }
    }
    It 'review F2: the fixed part is told ONLY from slices whose rows spread widely; evenly hashed slices keep today''s rule' {
        $run = { param([object[]]$S, $b) Reset-AutoBucketMeasure; foreach ($x in $S) { Add-AutoBucketMeasure -Rows $x[0] -Seconds $x[1] -Backend $b }; $script:AutoBucketMeasure }
        # THE REVIEW'S CASE: Log Analytics, 8 evenly hashed slices of 450-500 s -- min ~ max whatever the divisible work
        $even = & $run @(@(980, 450), @(1010, 470), @(990, 455), @(1020, 500), @(1000, 480), @(995, 462), @(1005, 490), @(1015, 475)) 'loganalytics'
        $even.FixedSeconds | Should -Be 0 -Because 'the rows do not spread: a fixed cost cannot be told from divisible work'
        Test-RABucketRunFarBelow -Measure $even | Should -BeFalse -Because 'today''s rule: 500 s is not far below -- the next run is NOT halved into slices past the 600 s limit'
        Get-RASliceNeed -Slice ([pscustomobject]@{ Rows = 1000; Bytes = 0; Seconds = 500; TooLarge = $false; Lost = $false }) -Bound 8 | Should -Be 2 -Because 'today''s rule: 500 / 450'
        # a time that grows with the rows: the line meets 0 rows at the fixed part (10 s)
        $lin = & $run @(@(1000, 20), @(2000, 30), @(4000, 50), @(8000, 90)) 'hunting'
        [Math]::Round($lin.FixedSeconds, 6) | Should -Be 10
        # SECOND REVIEW: a flat line over a FEW rows (0-5) cannot tell a fixed scan from scan work that divides -> not known
        $few = & $run @(@(0, 168), @(5, 160), @(2, 175), @(1, 171), @(4, 163), @(3, 166)) 'hunting'
        $few.FixedSeconds | Should -Be 0 -Because '160-175 s over 0-5 rows: the fixed part is not told'
        $today = [bool]([double]$few.MaxBucketSeconds -lt (0.25 * 900))
        Test-RABucketRunFarBelow -Measure $few | Should -Be $today -Because 'today''s rule decides (a quarter of the 900 s ceiling)'
        $few2 = & $run @(@(0, 222), @(1, 220), @(3, 225), @(2, 227), @(0, 224), @(1, 221)) 'loganalytics'
        $few2.FixedSeconds | Should -Be 0 -Because 'the live identity case (0-3 rows) keeps its count for now -- fixed later with measured data'
        Test-RABucketRunFarBelow -Measure $few2 | Should -BeFalse -Because 'today''s rule: 227 s is not far below'
        # a flat line over a WIDE row spread (at least 1,000 rows apart): the time does not follow the rows -> all fixed
        $flat = & $run @(@(0, 222), @(800, 220), @(3000, 225), @(1500, 227), @(5, 224), @(2400, 221)) 'loganalytics'
        $flat.FixedSeconds | Should -Be 220 -Because 'the shortest slice, never above it'
        $script:SIRaFixedFlatMinRowSpread | Should -Be 1000
        # too few slices to tell
        (& $run @(@(10, 50), @(1000, 90), @(5, 40)) 'hunting').FixedSeconds | Should -Be 0
        $script:AutoBucketMeasure = $null
    }
    It 'a split slice''s need and "far below every limit" read the same rule (Get-RASliceNeed, Test-RABucketRunFarBelow)' {
        $script:AutoBucketMeasure = $null
        Get-RASliceNeed -Slice ([pscustomobject]@{ Rows = 40; Bytes = 0; Seconds = 200; TooLarge = $false; Lost = $false }) -Bound 8 | Should -Be 1 -Because 'no fixed part known: 200 / 450, as before'
        Get-RASliceNeed -Slice ([pscustomobject]@{ Rows = 40; Bytes = 0; Seconds = 200; TooLarge = $false; Lost = $false; FixedSeconds = 20 }) -Bound 8 | Should -Be 3 -Because '(200 - 20) / (90 - 20)'
        Get-RASliceNeed -Slice ([pscustomobject]@{ Rows = 40; Bytes = 0; Seconds = 200; TooLarge = $false; Lost = $false; FixedSeconds = 20; Backend = 'loganalytics' }) -Bound 8 | Should -Be 1 -Because '180 / 280'
        # the running report's measure gives the fixed part and the back end when the slice has none
        $script:AutoBucketMeasure = [pscustomobject]@{ FixedSeconds = 20; Backend = 'hunting' }
        Get-RASliceNeed -Slice ([pscustomobject]@{ Rows = 40; Bytes = 0; Seconds = 200; TooLarge = $false; Lost = $false }) -Bound 8 | Should -Be 3
        $script:AutoBucketMeasure = $null
        $fb = { param($max, $fixed) Test-RABucketRunFarBelow -Measure ([pscustomobject]@{ Slices = 4; MaxBucketRows = 10; MaxBucketBytes = 10; MaxRequestBytes = 0; MaxBucketSeconds = $max; FixedSeconds = $fixed; Backend = 'hunting' }) }
        & $fb 50 10 | Should -BeFalse -Because 'halved: 10 + 2 x 40 = 90 s, not within half of 180 s'
        & $fb 40 10 | Should -BeTrue -Because '10 + 60 = 70 s'
        & $fb 227 220 | Should -BeTrue -Because 'a slice that is its fixed part'
        & $fb 200 0 | Should -BeTrue -Because 'no fixed part known: 200 < 225 (a quarter of 900), as before'
        & $fb 230 0 | Should -BeFalse
    }
    It 'the measure keeps the back end of its slices -- the tightest when more than one answered -- and the parts'' fit sums' {
        Reset-AutoBucketMeasure
        Add-AutoBucketMeasure -Rows 5 -Seconds 10 -Backend 'loganalytics'
        $script:AutoBucketMeasure.Backend | Should -Be 'loganalytics'
        Add-AutoBucketMeasure -Rows 5 -Seconds 10 -Backend 'lake'
        $script:AutoBucketMeasure.Backend | Should -Be 'lake'
        Add-AutoBucketMeasure -Rows 5 -Seconds 4 -Backend 'loganalytics'
        $script:AutoBucketMeasure.Backend | Should -Be 'lake'
        $script:AutoBucketMeasure.MinBucketSeconds | Should -Be 4
        $script:AutoBucketMeasure.MaxBucketSeconds | Should -Be 10
        $script:AutoBucketMeasure.FitN | Should -Be 3
        $script:AutoBucketMeasure.ResultRows | Should -Be 15 -Because 'the rows are counted exactly as before'
        $p1 = [pscustomobject]@{ Slices = 2; ResultRows = 3000; Backend = 'loganalytics'; MinBucketSeconds = 20; FitN = 2; FitSx = 3000; FitSy = 50; FitSxx = 5000000; FitSxy = 80000; MinRows = 1000; MaxRows = 2000 }
        $p2 = [pscustomobject]@{ Slices = 2; ResultRows = 12000; Backend = 'hunting'; MinBucketSeconds = 50; FitN = 2; FitSx = 12000; FitSy = 140; FitSxx = 80000000; FitSxy = 920000; MinRows = 4000; MaxRows = 8000 }
        $m = Merge-RAScaleOutMeasure -Measures @($p1, $p2)
        $m.Backend | Should -Be 'hunting'; $m.ResultRows | Should -Be 15000; $m.MinBucketSeconds | Should -Be 20
        $m.FitN | Should -Be 4; $m.MinRows | Should -Be 1000; $m.MaxRows | Should -Be 8000
        [Math]::Round($m.FixedSeconds, 6) | Should -Be 10 -Because 'the four slices (1000, 20) (2000, 30) (4000, 50) (8000, 90) over both parts'
        $script:AutoBucketMeasure = $null
    }
    It 'the back end a report''s query is known to go to, before it is sent (no request is made; unknown = advanced hunting)' {
        $script:_TableInAdvHunting = @{ SI_CI_CL = $false; SI_Mirrored_CL = $true }; $script:_SentinelLakeUnavailable = $false; $script:RALakeAnswered = $false
        Get-RAQueryBackend -Query 'DeviceInfo | take 1' | Should -Be 'hunting'
        Get-RAQueryBackend -Query 'SI_CI_CL | take 1' | Should -Be 'loganalytics'
        Get-RAQueryBackend -Query 'SI_Mirrored_CL | take 1' | Should -Be 'hunting'
        Get-RAQueryBackend -Query 'SI_Unknown_CL | take 1' | Should -Be 'hunting'
        Get-RAQueryBackend -Query "let c = SI_CI_CL;`nExposureGraphNodes | take 1" | Should -Be 'hunting'
        $script:RALakeAnswered = $true
        Get-RAQueryBackend -Query "let c = SI_CI_CL;`nExposureGraphNodes | take 1" | Should -Be 'lake'
        $script:_SentinelLakeUnavailable = $true
        Get-RAQueryBackend -Query "let c = SI_CI_CL;`nExposureGraphNodes | take 1" | Should -Be 'hunting'
        $script:RALakeAnswered = $false; $script:_SentinelLakeUnavailable = $false; $script:_TableInAdvHunting = $null
        $script:Engine | Should -Match ([regex]::Escape('try { $script:SIRaSliceBackend = Get-RAQueryBackend -Query $Query } catch { $script:SIRaSliceBackend = ''hunting'' }'))
    }
    It 'ONLY THE SLICE COUNT CHANGES: at the old count (4) and the new count (16) the slices hold exactly the same rows -- Expected / Retrieved / Stored and the verdict identical' {
        $all = 0..($script:U.Length - 1)
        $res = foreach ($c in 4, 16) {
            $got = New-Object System.Collections.Generic.List[int]
            for ($i = 0; $i -lt $c; $i++) { foreach ($x in @(& $script:Slice $c $i)) { $got.Add([int]$x) } }
            $retrieved = [long]$got.Count; $stored = [long]@($got | Sort-Object -Unique).Count
            $v = Get-RAReadCountVerdict -Before ([long]$all.Count) -After ([long]$all.Count) -Retrieved $retrieved
            [pscustomobject]@{ C = $c; Expected = [long]$all.Count; Retrieved = $retrieved; Stored = $stored; State = $v.State; Rows = (@($got | Sort-Object) -join ',') }
        }
        $res[0].Rows | Should -Be $res[1].Rows
        foreach ($r in $res) { $r.Expected | Should -Be 1200; $r.Retrieved | Should -Be 1200; $r.Stored | Should -Be 1200; $r.State | Should -Be 'Complete' }
    }
    It 'SCALE (on demand): 1.5 M keys -- every key in exactly one slice at the old and the new count, each new slice inside one old slice' -Tag 'Scale' {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $u = New-KeySource -N 1500000
        $gen = $sw.Elapsed.TotalSeconds
        $proc = [Diagnostics.Process]::GetCurrentProcess()
        foreach ($pair in @(@(4, 16), @(32, 128), @(136, 544))) {
            $old = [long]$pair[0]; $new = [long]$pair[1]
            $cOld = [long[]]::new($old); $cNew = [long[]]::new($new)
            for ($i = 0; $i -lt $u.Length; $i++) { $x = [long]$u[$i]; $cOld[$x % $old]++; $cNew[$x % $new]++ }
            ($cOld | Measure-Object -Sum).Sum | Should -Be 1500000
            ($cNew | Measure-Object -Sum).Sum | Should -Be 1500000
            # each old slice is exactly the sum of the new slices that carry its index (new = 4 x old: the same hash, finer)
            for ($j = 0; $j -lt $old; $j++) { $s = 0L; for ($t = $j; $t -lt $new; $t += $old) { $s += $cNew[$t] }; $s | Should -Be $cOld[$j] }
        }
        $proc.Refresh()
        Write-Host ([string]::Format([Globalization.CultureInfo]::InvariantCulture, '[#1275 (2) scale] 1,500,000 keys hashed in {0:N1} s, partitions checked in {1:N1} s; peak working set {2:N0} MB', $gen, $sw.Elapsed.TotalSeconds - $gen, $proc.PeakWorkingSet64 / 1MB))
    }
}

Describe '#1275 (3) after review F1: the count just after the read is ALWAYS asked; the slices stand for the count only when both counts failed and no slice was lost' {
    BeforeAll {
        foreach ($fn in 'Reset-RAReadCounts', 'Invoke-RAReadCount', 'Get-RAReportExpectedRows') { . ([scriptblock]::Create((Get-EngineFunction $fn))) }
        function script:Test-QueryHasBucketFilterBlock { param($Query) $true }
        function script:Replace-BucketFilterBlock { param($Query, $BucketFilterKql) $Query }
        function script:New-BucketFilterKql { param($BucketCount, $BucketIndex, $ReportName) '' }
        function script:Get-RASummaryMergePlan { param($Query) $null }
        function script:Get-RABucketRows { param($Resp) $Resp }
        function script:Invoke-GraphHuntingQuery { param($Query, $ReconnectMaxAgeMinutes, $MaxRetries)
            $script:Hunted++
            $a = $script:Answers[[Math]::Min($script:Hunted, $script:Answers.Count) - 1]
            if ($a -is [string]) { throw $a }
            @{ Ok = $true; Rows = @([pscustomobject]@{ Count = [long]$a }) } }
    }
    BeforeEach { $script:Said = @(); $script:Hunted = 0; $script:RAStreamOn = $false; $script:RALakeAnswered = $false; $global:SI_RA_CompletenessCheck = $null; Reset-RAReadCounts }
    It 'THE REVIEW''S CASE: the count before the read answers 504, the one after answers 20,878, the slices returned 16,943 -> NOT COMPLETE' {
        $script:Answers = @('Response status code does not indicate success: 504 (Gateway Timeout).', 20878)
        Invoke-RAReadCount -When Before -Query 'T' -ReportName 'R_Detailed'
        Invoke-RAReadCount -When After -Query 'T' -ReportName 'R_Detailed'
        $script:Hunted | Should -Be 2 -Because 'the independent check is asked after the read, whatever the count before it answered'
        $script:RAReadCounts['Before'].Count | Should -BeNullOrEmpty
        $script:RAReadCounts['After'].Count | Should -Be 20878
        $v = Get-RAReadCountVerdict -Before $script:RAReadCounts['Before'].Count -After $script:RAReadCounts['After'].Count -Retrieved 16943
        $v.State | Should -Be 'NotComplete' -Because 'a slice that answered but returned fewer rows than the whole query is never taken as complete'
        $script:Engine | Should -Not -Match 'Test-RAReadCountTimedOut' -Because 'nothing skips the count after the read any more'
    }
    It 'BOTH counts failed and no slice was lost: the slices'' rows stand for the count (as before stage 1) and the report SAYS "count taken from the slices"' {
        $w = @{ Count = $null; Error = 'Response status code does not indicate success: 504 (Gateway Timeout).'; How = 'whole' }
        $script:Answers = @('504 (Gateway Timeout)')
        $r = Get-RAReportExpectedRows -Query 'T' -ReportName 'R_Detailed' -BucketCount 4 -Retrieved 1505 -LostSlices 0 -Whole $w
        $script:Hunted | Should -Be 0 -Because 'the count after the read was already asked; it is not asked a third time'
        $r.Count | Should -Be 1505
        $r.How | Should -Match 'count taken from the slices$'
        $r.How | Should -Match '^every one of the report''s 4 slices answered below the row limit'
        $lost = Get-RAReportExpectedRows -Query 'T' -ReportName 'R_Detailed' -BucketCount 1 -Retrieved 1505 -LostSlices 1 -Whole $w
        $lost.Count | Should -BeNullOrEmpty -Because 'a slice that did not answer is not "below the row limit": the rows are never taken as the count'
        $script:RALakeAnswered = $true
        (Get-RAReportExpectedRows -Query 'T' -ReportName 'R_Detailed' -BucketCount 1 -Retrieved 1505 -LostSlices 0 -Whole $w).Count | Should -BeNullOrEmpty -Because 'a lake answer is never taken from its slices (as before)'
        $script:Engine | Should -Match ([regex]::Escape('$__lostV = Get-RALostSliceVerdict -Lost @($script:_RABucketLoss)'))
    }
}
Describe '#1275 (5) the JSON file after the completion: the same rows, byte for byte (SQL Server)' -Skip:(-not $script:SqlUp) {
    BeforeAll {
        $eq = Join-Path $PSScriptRoot 'SIv3-RaScaleOutEquivalence.Tests.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($eq, [ref]$null, [ref]$null)
        $lib = ($ast.Find({ param($x) $x -is [System.Management.Automation.Language.AssignmentStatementAst] -and $x.Left.Extent.Text -eq '$script:LibText' }, $true)).Right.Expression.Value
        . ([scriptblock]::Create($lib)) -SIRoot $script:SIRoot
        function script:Write-Info { param($m) }
        $script:Db = 'si_test_stage1_{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 6)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$($script:Db)]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$($script:Db);$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
        $cn.Open(); try { foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') { $p = Join-Path $script:SIRoot $f; if (Test-Path -LiteralPath $p) { $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText($p); [void]$c.ExecuteNonQuery() } } } finally { $cn.Dispose() }
        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('si-stage1-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
    }
    AfterAll {
        try {
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$($script:Db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:Db)];"; $c.CommandTimeout = 120; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        } catch { }
        try { Remove-Item -LiteralPath $script:Tmp -Recurse -Force } catch { }
    }
    It 'the file written where it was (before the end guards) and after Complete-RAStream are identical -- a held report left out of both, a NOT COMPLETE report in both' {
        $s = New-RAStream -Invoke (New-Seam -Db $script:Db) -Grain Detailed -CollectionTime $script:CT -RunId 'stage1' -Log { param($l, $t) }
        foreach ($r in 1..3) {
            $name = 'Stage1Gen{0}_Detailed' -f $r
            $null = Start-RAStreamReport -Stream $s -ReportName $name -Staged $false
            $rows = @(New-TenantRows -Report $r -Assets 60 -Findings 3)
            foreach ($x in $rows) { Add-Member -InputObject $x -NotePropertyName CollectionTime -NotePropertyValue $script:CT -Force }
            Set-RATraceIdentity -Rows $rows -IsDetailed $true
            $cols = New-Object 'System.Collections.Generic.List[string]'; $seen = @{}
            foreach ($x in $rows) { foreach ($pn in $x.PSObject.Properties.Name) { if (-not $seen.ContainsKey($pn)) { $seen[$pn] = 1; $cols.Add($pn) } } }
            Add-RAStreamColumns -Stream $s -Columns $cols.ToArray()
            $view = New-Object 'System.Collections.Generic.HashSet[object]'; foreach ($x in $rows) { [void]$view.Add($x) }
            $null = Write-RAStreamRows -Stream $s -Rows $rows -Bucket '1/1' -InView $view -IsDetailedShape $true
            $null = Complete-RAStreamReport -Stream $s
        }
        # report 3 is held back DURING the run (its rows could not be removed) -- it was never in the JSON file and is not now
        $null = Add-RAStreamHeldReport -Stream $s -ReportName 'Stage1Gen3_Detailed' -Ordinal ([int]$s.Reports['Stage1Gen3_Detailed'].Ordinal) -Cause 'test: held back'
        $total = [long](Get-RAStreamCount -Stream $s -Source View)
        # WHERE IT WAS: the pager with the stream's held set as it is then
        $a = Join-Path $script:Tmp 'before.json'
        Write-RAJsonArrayFile -Pager (New-RARowPager -Stream $s -Source View) -Path $a -Depth 20 -Total $total
        # the snapshot the engine takes at that point
        [int[]]$snap = @(Get-RAStreamHeldOrdinals -Stream $s)
        # THE END: report 2 judged NOT COMPLETE by an end guard, the verdicts final, the collection completed
        Set-RAStreamReportNotComplete -Stream $s -ReportName 'Stage1Gen2_Detailed' -Reason 'test: the row-count guard'
        Set-RAStreamVerdictsFinal -Stream $s -Partial 'test' -Scope 'reports'
        $null = Complete-RAStream -Stream $s -Partial 'test' -Scope 'reports'
        $b = Join-Path $script:Tmp 'after.json'
        Write-RAJsonArrayFile -Pager (New-RARowPager -Stream $s -Source View -Held $snap) -Path $b -Depth 20 -Total $total
        $ha = (Get-FileHash -LiteralPath $a -Algorithm SHA256).Hash; $hb = (Get-FileHash -LiteralPath $b -Algorithm SHA256).Hash
        $hb | Should -Be $ha -Because 'byte for byte the same file'
        $j = Get-Content -Raw -LiteralPath $b | ConvertFrom-Json
        @($j).Count | Should -Be $total
        @($j | Where-Object { [string]$_.ConfigurationId -like 'CVE-2026-2*' }).Count | Should -BeGreaterThan 0 -Because 'the report judged NOT COMPLETE at the end is in the file, as before'
        @($j | Where-Object { [string]$_.ConfigurationId -like 'CVE-2026-3*' }).Count | Should -Be 0 -Because 'the report held back during the run was never in it'
        # the snapshot is what keeps it so: a report held only AFTER that point would otherwise drop out of the file
        $null = Add-RAStreamHeldReport -Stream $s -ReportName 'Stage1Gen1_Detailed' -Ordinal ([int]$s.Reports['Stage1Gen1_Detailed'].Ordinal) -Cause 'test: held later'
        $c2 = Join-Path $script:Tmp 'after2.json'
        Write-RAJsonArrayFile -Pager (New-RARowPager -Stream $s -Source View -Held $snap) -Path $c2 -Depth 20 -Total $total
        (Get-FileHash -LiteralPath $c2 -Algorithm SHA256).Hash | Should -Be $ha
        $d = Join-Path $script:Tmp 'nosnap.json'
        Write-RAJsonArrayFile -Pager (New-RARowPager -Stream $s -Source View) -Path $d -Depth 20 -Total $total
        (Get-FileHash -LiteralPath $d -Algorithm SHA256).Hash | Should -Not -Be $ha -Because 'without the snapshot the later hold would leave rows out -- what the snapshot prevents'
        # an EMPTY snapshot means "nothing held", never "the current set"
        [int[]]$none = @()
        $e = Join-Path $script:Tmp 'empty.json'
        Write-RAJsonArrayFile -Pager (New-RARowPager -Stream $s -Source View -Held $none) -Path $e -Depth 20
        $ej = @(Get-Content -Raw -LiteralPath $e | ConvertFrom-Json)
        $ej.Count | Should -BeGreaterThan $total -Because 'nothing held: every report, the held ones included'
        @($ej | Where-Object { [string]$_.ConfigurationId -like 'CVE-2026-3*' }).Count | Should -BeGreaterThan 0
    }
    It 'the engine: the file step is taken where it was, the held set kept there, and run after the completion' {
        $i0 = $script:Engine.IndexOf('$script:RAJsonStep = {')
        $i0 | Should -BeGreaterThan 0
        $iSnap = $script:Engine.IndexOf('[int[]]$script:RAJsonHeld = @(Get-RAStreamHeldOrdinals -Stream $script:RAStream)')
        $iSnap | Should -BeGreaterThan 0; $iSnap | Should -BeLessThan $i0
        $script:Engine | Should -Match ([regex]::Escape('New-RARowPager -Stream $script:RAStream -Source View -ReadAhead -Held $script:RAJsonHeld'))
        $iComplete = $script:Engine.IndexOf('$__raRows = Complete-RAStream -Stream $script:RAStream')
        $iRun = $script:Engine.IndexOf('if ($script:RAStreamOn) { . $script:RAJsonStep }')
        $iRun | Should -BeGreaterThan $iComplete
        $iRun | Should -BeLessThan $script:Engine.IndexOf('foreach ($localPath in @($global:OutputXlsx, $global:OutputJson))') -Because 'before the upload step'
        $script:Engine | Should -Match ([regex]::Escape('if (-not $script:RAStreamOn) { . $script:RAJsonStep }'))
    }
}

Describe '#1275 measurement only: the phase rows (cfg.StepPhaseTime)' {
    It 'the Log Analytics schema pass, its post and the Top 50 decline reason are timed; nothing else changes' {
        $script:Engine | Should -Match ([regex]::Escape("-Phase 'after the reports: the Log Analytics schema pass'"))
        $script:Engine | Should -Match ([regex]::Escape("-Phase 'after the reports: the Log Analytics post'"))
        $script:Engine | Should -Match ([regex]::Escape("('after the reports: the Top 50 lists declined: ' + [string]`$__sb.Why)"))
        $script:Engine | Should -Match ([regex]::Escape('if ($__sbWhy.Length -gt 128) { $__sbWhy = $__sbWhy.Substring(0, 128) }'))
    }
}
