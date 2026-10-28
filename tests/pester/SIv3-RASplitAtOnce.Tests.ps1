#Requires -Version 7.0
<#
    #722 -- A TOO-LARGE RISK ANALYSIS SLICE IS SPLIT AT ONCE, NOT RE-PROBED.

    Live 2026-10-16 (a large customer, build 0725, two Detailed reports of the Defender for Cloud recommendation family):
    each of 8 buckets logged "re-probing with current shard size (attempt 1/3, pausing 30s)" -> "(attempt 2/3, pausing 60s)"
    -> "shard too large after 3 probes", and then the sub-bucket pass split each into 4 and every sub-slice succeeded.
    About 12 minutes per report went on pauses and re-sends of a request that cannot succeed (same request, same size).

    What these tests keep true (offline, no tenant):
      * Get-RABucketOverflowStep: a too-large answer -> 'Split' with NO pause on the first answer by default; re-probes only
        when SI_BucketOverflowRetries asks for them;
      * the PLATFORM still gets its retries (working rule 4): 429 / 503 / timeout / token expiry are 'Retry', never an
        overflow; 502 nginx upstream-too-large stays 'Split';
      * EQUIVALENCE: a simulated report over a fake source (same hash partition as the engine, sub-slices built by the
        engine's own index math) writes the SAME rows through the immediate split as through the old 3-probe path -- and
        every row of the source -- with zero pauses on the new path and 90 s per too-large bucket on the old one; a
        throttled bucket is still retried with a pause on both;
      * Get-RACountAfterSplit (#737: sized to the answer): every bucket truly too large and needing the 4-way split -> 32 in
        the live case; one hot slice adds only the slices it needed; within the configured maximum
        (the busy-backend cases are in SIv3-RASplitRightSize.Tests.ps1);
      * the count is kept EARLY from the sub-bucket pass (Save-AutoBucketCountEarly), so the next run takes it from the
        store without probing even when the run is stopped part-way;
      * the engine wiring: the loop asks Get-RABucketOverflowStep with the setting (default 1), sleeps only on 'Probe',
        keeps the count from the sub-bucket pass, and the end-of-report count comes from Get-RACountAfterSplit.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $shared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    . (Join-Path $shared 'RA-AutoBucketing.ps1')
    . (Join-Path $shared 'RA-BucketStore.ps1')
    . (Join-Path $shared 'RA-BucketFilters.ps1')
    $script:_CrossDomainBucketCoalesce = @()
    $script:AutoBucketConfirmedKey = '__confirmed'
    function Write-Info { param($msg) }
    function Write-Warn2 { param($msg) }

    # The engine's own hash (identical math on the KQL and PowerShell sides), taken from its file without loading the rest.
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $shared 'RA-ProfileAugment.ps1'), [ref]$null, [ref]$null)
    $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-SISha256Bucket' }, $true)
    . ([scriptblock]::Create($fn.Extent.Text))

    # A source of findings: 400 devices x 3 findings. The fake service answers a slice (count T, index i) with the rows whose
    # device hashes to i mod T -- the partition New-BucketFilterKql asks for -- and refuses an answer over Limit rows as too
    # large, in the service's own words. A throttle can be injected on the first call of a slice.
    function New-FakeSource {
        $rows = foreach ($d in 1..400) { foreach ($f in 1..3) { [pscustomobject]@{ DeviceKey = "dev-$d"; Finding = "rec-$f" } } }
        $hash = @{}; foreach ($r in $rows) { if (-not $hash.ContainsKey($r.DeviceKey)) { $hash[$r.DeviceKey] = @{} } }
        [pscustomobject]@{ Rows = @($rows); HashCache = $hash; Limit = 90; Calls = 0; ThrottleOnce = @{} }
    }
    function Invoke-FakeSlice {
        param($Src, [int]$Count, [int]$Index)
        $Src.Calls++
        $tk = "$Count/$Index"
        if ($Src.ThrottleOnce.ContainsKey($tk) -and $Src.ThrottleOnce[$tk]) { $Src.ThrottleOnce[$tk] = $false; throw '429 Too Many Requests -- the request was throttled. Retry-After: 5' }
        $out = @($Src.Rows | Where-Object {
            $h = $Src.HashCache[$_.DeviceKey]
            if (-not $h.ContainsKey($Count)) { $h[$Count] = Get-SISha256Bucket -Key $_.DeviceKey -BucketCount $Count }
            $h[$Count] -eq $Index })
        if ($out.Count -gt $Src.Limit) { throw 'Query execution has exceeded the allowed result size. Reduce the result set.' }
        return $out
    }

    # The report's slice loop and sub-bucket pass, in the engine's order and with its decisions: the main loop asks
    # Get-RABucketOverflowStep for a too-large answer and Get-RABucketFailureAction for everything else; the sub-bucket pass
    # splits a too-large slice deeper with the engine's index math (count T*K, index N + j*T). Pauses are counted, not slept.
    function Invoke-SimulatedReport {
        param($Src, [int]$BucketCount, [int]$ProbeAttempts, [int]$FanOut = 4, [int]$DepthMax = 6)
        $res = [pscustomobject]@{ Rows = New-Object System.Collections.Generic.List[object]; PauseSeconds = 0; ProbePauses = 0; Failed = New-Object System.Collections.Generic.List[int]; Working = 0 }
        for ($b = 0; $b -lt $BucketCount; $b++) {
            $ov = 0; $att = 0; $done = $false
            while (-not $done) {
                $att++
                try { foreach ($r in (Invoke-FakeSlice -Src $Src -Count $BucketCount -Index $b)) { $res.Rows.Add($r) }; $done = $true }
                catch {
                    if (Test-IsBucketOverflowError $_) {
                        $ov++
                        $step = Get-RABucketOverflowStep -OverflowAttempt $ov -ProbeAttempts $ProbeAttempts
                        if ($step.Action -eq 'Probe') { $res.PauseSeconds += $step.PauseSeconds; $res.ProbePauses++ }
                        else { $res.Failed.Add($b); $done = $true }
                    } else {
                        $a = Get-RABucketFailureAction -Err $_
                        if ($a -eq 'Retry' -and $att -lt 3) { $res.PauseSeconds += (Get-RABucketRetryDelaySeconds -Attempt $att -Err $_) }
                        elseif ($a -eq 'Split') { $res.Failed.Add($b); $done = $true }
                        else { throw "lost bucket $b : $_" }
                    }
                }
            }
        }
        $q = New-Object System.Collections.Generic.Queue[object]
        foreach ($i in $res.Failed) { $q.Enqueue(@{ N = $i; T = $BucketCount; D = 1 }) }
        while ($q.Count -gt 0) {
            $it = $q.Dequeue(); $newT = $it.T * $FanOut
            for ($j = 0; $j -lt $FanOut; $j++) {
                $subN = $it.N + ($j * $it.T)
                try {
                    foreach ($r in (Invoke-FakeSlice -Src $Src -Count $newT -Index $subN)) { $res.Rows.Add($r) }
                    if ($newT -gt $res.Working) { $res.Working = $newT }
                } catch {
                    if ((Get-RABucketFailureAction -Err $_) -eq 'Split' -and $it.D -lt $DepthMax) { $q.Enqueue(@{ N = $subN; T = $newT; D = $it.D + 1 }) }
                    else { throw "lost sub-slice $subN/$newT : $_" }
                }
            }
        }
        $res
    }
    function Get-RowSet { param($Rows) @($Rows | ForEach-Object { '{0}|{1}' -f $_.DeviceKey, $_.Finding } | Sort-Object) }
}

Describe 'a too-large answer splits at once' {
    It 'the first too-large answer is a split with no pause (default)' {
        $s = Get-RABucketOverflowStep -OverflowAttempt 1
        $s.Action | Should -Be 'Split'
        $s.PauseSeconds | Should -Be 0
        (Get-RABucketOverflowStep -OverflowAttempt 1 -ProbeAttempts 1).Action | Should -Be 'Split'
        (Get-RABucketOverflowStep -OverflowAttempt 1 -ProbeAttempts 0).Action | Should -Be 'Split'
    }

    It 're-probes only when SI_BucketOverflowRetries asks for it (30 s, 60 s, then the split)' {
        $a = Get-RABucketOverflowStep -OverflowAttempt 1 -ProbeAttempts 3
        $a.Action | Should -Be 'Probe'; $a.PauseSeconds | Should -Be 30
        $b = Get-RABucketOverflowStep -OverflowAttempt 2 -ProbeAttempts 3
        $b.Action | Should -Be 'Probe'; $b.PauseSeconds | Should -Be 60
        (Get-RABucketOverflowStep -OverflowAttempt 3 -ProbeAttempts 3).Action | Should -Be 'Split'
    }

    It 'every too-large wording the main loop sees is an overflow (split), never a platform retry' {
        foreach ($m in 'Query execution has exceeded the allowed result size', 'Response too large', 'Payload too large for the response',
                       'too many rows returned', 'The result exceeds the rows limit') {
            Test-IsBucketOverflowError -Err $m | Should -BeTrue -Because $m
            Get-RABucketFailureAction -Err $m | Should -Be 'Split' -Because $m
        }
        # #880: the busy answer carries the overflow wording but is retried at the same size, never split
        $busy = 'Query execution has exceeded the allowed limits. The query was preempted due to high CPU and/or memory resource consumption'
        Get-RABucketFailureAction -Err $busy | Should -Be 'Retry'
        Get-RABucketFailureAction -Err '502 Bad Gateway <html>nginx</html>' | Should -Be 'Split'
    }

    It 'a genuine platform error keeps its retries (working rule 4): throttle, unavailable, timeout, token' {
        foreach ($m in '429 Too Many Requests', 'Request was throttled', '503 Service Unavailable', '504 Gateway Timeout', 'The operation timed out', 'InvalidAuthenticationToken: Access token has expired') {
            Test-IsBucketOverflowError -Err $m | Should -BeFalse -Because $m
            Get-RABucketFailureAction -Err $m | Should -Be 'Retry' -Because $m
        }
    }
}

Describe 'equivalence: the immediate split writes the same rows as the old 3-probe path' {
    It 'same rows, every row of the source, no pause for too-large -- and fewer requests' {
        $srcOld = New-FakeSource; $srcNew = New-FakeSource
        $old = Invoke-SimulatedReport -Src $srcOld -BucketCount 8 -ProbeAttempts 3
        $new = Invoke-SimulatedReport -Src $srcNew -BucketCount 8 -ProbeAttempts 1

        $expected = Get-RowSet $srcNew.Rows
        $newSet = Get-RowSet $new.Rows
        $oldSet = Get-RowSet $old.Rows
        $newSet.Count | Should -Be 1200
        ($newSet -join "`n") | Should -Be ($oldSet -join "`n") -Because 'the immediate split must write exactly the rows the old path wrote'
        ($newSet -join "`n") | Should -Be ($expected -join "`n") -Because 'and every row of the source arrives (trust: no silent data loss)'
        @($newSet | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0 -Because 'no row is written twice'

        # the live shape: every bucket at 8 is too large
        $new.Failed.Count | Should -Be 8
        $old.Failed.Count | Should -Be 8
        $new.PauseSeconds | Should -Be 0 -Because 'a too-large answer triggers no pause'
        $new.ProbePauses | Should -Be 0
        $old.PauseSeconds | Should -Be (8 * 90) -Because 'the old path paused 30 s + 60 s per too-large bucket (the ~12 minutes measured live)'
        ($srcOld.Calls - $srcNew.Calls) | Should -Be 16 -Because 'two re-sends of each of 8 too-large buckets are no longer made'
        $new.Working | Should -Be 32
    }

    It 'a throttled slice still gets its pause and retry on the new path, and still arrives' {
        $src = New-FakeSource
        $src.Limit = 1000   # nothing too large: only the throttle
        $src.ThrottleOnce['8/3'] = $true
        $r = Invoke-SimulatedReport -Src $src -BucketCount 8 -ProbeAttempts 1
        $r.PauseSeconds | Should -BeGreaterThan 0 -Because 'a throttle is a platform error: retried after a pause'
        $r.Failed.Count | Should -Be 0 -Because 'a throttled slice is never split'
        ((Get-RowSet $r.Rows) -join "`n") | Should -Be ((Get-RowSet $src.Rows) -join "`n")
    }

    It 'the sub-slices the engine builds are the slice: count T*K, index N + j*T' {
        foreach ($j in 0..3) {
            New-SubBucketFilterKql -ParentBucketCount 8 -ParentBucketIndex 5 -SubBucketCount 4 -SubBucketIndex $j |
                Should -Be (New-BucketFilterKql -BucketCount 32 -BucketIndex (5 + $j * 8))
        }
    }
}

Describe 'the next run starts at the size that worked (#737: sized to the answer)' {
    BeforeAll {
        # one split bucket's own answer: the rows / seconds its sub-slices took together, and whether the service SAID too large
        function Slice { param([long]$Rows = 0, [double]$Seconds = 0, [switch]$TooLarge, [switch]$Lost)
            [pscustomobject]@{ Rows = $Rows; Bytes = 0L; Seconds = $Seconds; TooLarge = [bool]$TooLarge; Lost = [bool]$Lost } }
    }
    It 'every bucket truly too large and needing the 4-way split -> 32 (the #722 live case)' {
        $s = @(1..8 | ForEach-Object { Slice -Rows 60000 -TooLarge })
        Get-RACountAfterSplit -BucketCount 8 -Slices $s -WorkingCount 32 -Cap 4096 | Should -Be 32
    }
    It 'one hot slice of 64 adds only the slices IT needed -- never doubles or quadruples the report' {
        Get-RACountAfterSplit -BucketCount 64 -Slices @(Slice -Rows 40000 -TooLarge) -WorkingCount 256 -Cap 4096 | Should -Be 66
        Get-RACountAfterSplit -BucketCount 8 -Slices @(Slice -Rows 100 -TooLarge) -WorkingCount 32 -Cap 4096 | Should -Be 9
    }
    It 'never above the configured maximum, never below the count used, never more than the finest count that worked' {
        $s = @(1..8 | ForEach-Object { Slice -Rows 500000 -TooLarge })
        Get-RACountAfterSplit -BucketCount 8 -Slices $s -WorkingCount 128 -Cap 64 | Should -Be 64
        Get-RACountAfterSplit -BucketCount 8 -Slices $s -WorkingCount 32 -Cap 4096 | Should -Be 32
        Get-RACountAfterSplit -BucketCount 8 -Slices @() -WorkingCount 0 -Cap 4096 | Should -Be 8
    }

    It 'the count kept from the sub-bucket pass is what the next run starts from, without probing (a run stopped part-way included)' {
        $script:AutoBucketMemo = @{}; $script:AutoBucketSql = $null
        $global:AutoBucketCache = $true
        $global:SettingsPath = Join-Path ([IO.Path]::GetTempPath()) ('si-split-at-once-' + [guid]::NewGuid().ToString('N'))
        try {
            $key = 'Azure_Recommendations_Detailed|42'
            $next = Get-RACountAfterSplit -BucketCount 8 -Slices @(1..8 | ForEach-Object { Slice -Rows 60000 -TooLarge }) -WorkingCount 32 -Cap 4096
            Save-AutoBucketCountEarly -QueryKey $key -Count $next | Should -BeTrue
            # ... stopped here: no end-of-report write
            $script:AutoBucketMemo = @{}
            $global:Probed = @()
            $n = Get-OptimalBucketCount -QueryKey $key -MaxBucketCount 4096 -MinBucketCount 8 -ProbeScript { param([int]$BucketCount) $global:Probed += $BucketCount }
            $n | Should -Be 32
            @($global:Probed).Count | Should -Be 0
        } finally {
            if (Test-Path $global:SettingsPath) { Remove-Item -LiteralPath $global:SettingsPath -Recurse -Force }
            $global:SettingsPath = $null
        }
    }
}

Describe 'the engine wiring' {
    BeforeAll { $script:Txt = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')) }

    It 'the slice loop asks Get-RABucketOverflowStep with the setting, whose default is 1 (split at once)' {
        $script:Txt | Should -Match '\$__ovStep = Get-RABucketOverflowStep -OverflowAttempt \$bucketOverflowAttempt -ProbeAttempts \$bucketOverflowRetries'
        $script:Txt | Should -Match '(?s)\[int\]\$global:SI_BucketOverflowRetries\s*\}\s*else\s*\{\s*1\s*\}'
    }

    It 'pauses only on a re-probe the setting asked for' {
        $i = $script:Txt.IndexOf('$__ovStep = Get-RABucketOverflowStep')
        $seg = $script:Txt.Substring($i, $script:Txt.IndexOf('# 2) Everything else is routed by CAUSE', $i) - $i)
        @([regex]::Matches($seg, 'Start-Sleep')).Count | Should -Be 1
        $seg | Should -Match "if \(\`$__ovStep\.Action -eq 'Probe'\) \{"
        $seg | Should -Match 'Start-Sleep -Seconds \$__ovStep\.PauseSeconds'
        $seg | Should -Not -Match 'Math\]::Pow'
    }

    It 'keeps the count from the sub-bucket pass early, after a sub-slice''s rows are handed on' {
        $i1 = $script:Txt.IndexOf('Add-RAStreamBucketGuarded -Rows @($subConv.Rows) -Bucket $subLabel')
        $i2 = $script:Txt.IndexOf('Save-AutoBucketCountEarly -QueryKey $queryKey -Count $__abSplitNext')
        $i1 | Should -BeGreaterThan 0
        $i2 | Should -BeGreaterThan $i1
        $script:Txt | Should -Match '\$__abSplitBuckets = \[int\]\$failedBucketIndices\.Count'
    }

    It 'the end-of-report count comes from Get-RACountAfterSplit over THIS report''s own split slices (#737)' {
        $script:Txt | Should -Match '\$__abNext = Get-RACountAfterSplit -BucketCount \(\[int\]\$bucketCountToUse\) -Slices @\(\$__abSplitSlices\.Values\) -WorkingCount \$__abSplitWorking -FanOut \$subFanOut -Cap \(\[int\]\$capBucket\)'
        $script:Txt | Should -Not -Match '\$__abNext = \[int\]\[Math\]::Min\(\[int\]\$capBucket, \[int\]\$bucketCountToUse \* 2\)'
    }
}
