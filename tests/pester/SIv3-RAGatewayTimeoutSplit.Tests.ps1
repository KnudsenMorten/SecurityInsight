#Requires -Version 7.0
<#
    #1155 -- A SLICE THE HUNTING GATEWAY TIMES OUT ON EVERY ATTEMPT IS SPLIT, NOT WRITTEN OFF; A REPORT NOT COMPLETE ON SEVERAL
    RUNS IN A ROW IS SAID AS SUCH.

    Live 2026-11-08 (a large install): one Detailed attack-path report lost 4 of its 9 slices to "504 Gateway Timeout" after
    the in-loop AND late retries, on every run for 13 days, at the same 9 slices -- the bucket history held 7 runs in a row
    'incomplete' with 0 rows. A 504 is a platform answer, so it was retried at the same size; a failure that repeats on the
    same slice every time is DETERMINISTIC, and only a smaller slice can change it.

    What these tests keep true (offline, no tenant):
      * Test-RABucketGatewayTimeout: 504 / Gateway Timeout / GatewayTimeout are the gateway's time limit; a busy answer
        (preempted) and a 429 / 503 are not;
      * Get-RALateLeftAction: a slice still refused by the gateway's time limit after every retry -> 'Split'; still busy or
        throttled -> 'Lost' (as before);
      * a 504 is still RETRIED first (Get-RABucketFailureAction says 'Retry'): only a slice that never recovers is split;
      * EQUIVALENCE over a fake source: slices that time out at their size and answer when split -> every row of the source,
        and the report is complete; under the old rule the same report lost those slices;
      * Get-RAIncompleteStreak: this run + the leading 'incomplete' runs of the history, and the oldest run of the streak;
      * the engine wiring: the late passes' left-overs ask Get-RALateLeftAction before a loss, the sub-bucket pass splits a
        gateway timeout deeper, and the end of the run says the runs-in-a-row line and puts it in the uplink's cause from 3.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $shared = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    . (Join-Path $shared 'RA-AutoBucketing.ps1')
    function Write-Info { param($msg) }
    function Write-Warn2 { param($msg) }
    $script:Engine = Get-Content -Raw (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')
}

Describe '#1155 the gateway time limit is recognised' {
    It '504 / Gateway Timeout / GatewayTimeout are the gateway''s time limit' {
        Test-RABucketGatewayTimeout -Err 'Response status code does not indicate success: 504 (Gateway Timeout).' | Should -BeTrue
        Test-RABucketGatewayTimeout -Err 'The remote server returned an error: (504) Gateway Time-out.' | Should -BeTrue
        Test-RABucketGatewayTimeout -Err '{"error":{"code":"GatewayTimeout","message":"The gateway did not receive a response"}}' | Should -BeTrue
    }
    It 'a busy answer, a throttle and an unavailable service are not' {
        Test-RABucketGatewayTimeout -Err '504 query preempted due to high CPU and/or memory resource consumption' | Should -BeFalse
        Test-RABucketGatewayTimeout -Err '429 Too Many Requests' | Should -BeFalse
        Test-RABucketGatewayTimeout -Err '503 Service Unavailable' | Should -BeFalse
        Test-RABucketGatewayTimeout -Err '' | Should -BeFalse
        Test-RABucketGatewayTimeout -Err $null | Should -BeFalse
    }
    It 'a 504 is still retried first -- only a slice that never recovers is split' {
        Get-RABucketFailureAction -Err '504 (Gateway Timeout)' | Should -Be 'Retry'
    }
}

Describe '#1155 what happens to a slice the late passes could not recover' {
    It 'refused by the gateway''s time limit every time -> Split' {
        Get-RALateLeftAction -LastError '504 (Gateway Timeout)' -Busy $false | Should -Be 'Split'
    }
    It 'still busy, throttled, unavailable or unknown -> Lost, as before' {
        Get-RALateLeftAction -LastError '504 (Gateway Timeout)' -Busy $true | Should -Be 'Lost'
        Get-RALateLeftAction -LastError '429 Too Many Requests' | Should -Be 'Lost'
        Get-RALateLeftAction -LastError '503 Service Unavailable' | Should -Be 'Lost'
        Get-RALateLeftAction -LastError '' | Should -Be 'Lost'
    }
}

Describe '#1155 EQUIVALENCE: the split recovers every row the timed-out slices held' {
    BeforeAll {
        # a fake source of 900 rows over 9 slices; slices 1-4 time out at the gateway at their size on EVERY attempt, and
        # answer when asked as 4 sub-slices (each a quarter of the rows). The slice of a row: id % 9; a sub-slice: id % 36.
        $script:Source = 1..900
        $script:Ask = {
            param([int]$Count, [int]$Index)
            if ($Count -eq 9 -and $Index -in 1..4) { throw '504 (Gateway Timeout)' }
            @($script:Source | Where-Object { ($_ % $Count) -eq $Index })
        }
        # the engine's rule, in miniature: retries at the same size, then the late-left decision, then the 4-way split
        $script:RunReport = {
            param([scriptblock]$LeftAction)
            $rows = New-Object System.Collections.Generic.List[int]; $lost = 0; $split = New-Object System.Collections.Generic.List[int]
            foreach ($b in 0..8) {
                $got = $false; $err = ''
                foreach ($try in 1..3) { try { foreach ($r in (& $script:Ask 9 $b)) { $rows.Add($r) }; $got = $true; break } catch { $err = $_.Exception.Message } }
                if ($got) { continue }
                if ((& $LeftAction $err) -eq 'Split') { $split.Add($b) } else { $lost++ }
            }
            foreach ($b in $split) { foreach ($k in 0..3) { foreach ($r in (& $script:Ask 36 ($b + 9 * $k))) { $rows.Add($r) } } }
            [pscustomobject]@{ Rows = @($rows | Sort-Object -Unique); Lost = $lost; Split = $split.Count }
        }
    }
    It 'the new rule: every row of the source, nothing lost, the four slices split' {
        $r = & $script:RunReport { param($e) Get-RALateLeftAction -LastError $e -Busy $false }
        $r.Lost | Should -Be 0
        $r.Split | Should -Be 4
        $r.Rows.Count | Should -Be 900
        (Compare-Object $r.Rows $script:Source) | Should -BeNullOrEmpty
    }
    It 'the old rule lost the same four slices on every run (the live case)' {
        $r = & $script:RunReport { param($e) 'Lost' }
        $r.Lost | Should -Be 4
        $r.Rows.Count | Should -Be 500
    }
}

Describe '#1155 a report not complete on several runs in a row' {
    It 'this run + the leading incomplete runs, since the oldest of them' {
        $h = @(
            [pscustomobject]@{ Decided = 'incomplete'; RunUtc = [datetime]'2026-11-07T05:15:00Z' },
            [pscustomobject]@{ Decided = 'incomplete'; RunUtc = [datetime]'2026-11-05T22:51:00Z' },
            [pscustomobject]@{ Decided = 'cache';      RunUtc = [datetime]'2026-10-22T23:44:00Z' },
            [pscustomobject]@{ Decided = 'incomplete'; RunUtc = [datetime]'2026-10-20T10:00:00Z' })
        $s = Get-RAIncompleteStreak -History $h -NowUtc ([datetime]'2026-11-08T06:05:00Z')
        $s.Runs | Should -Be 3
        $s.Since.ToString('yyyy-MM-dd') | Should -Be '2026-11-05'
    }
    It 'runs before a data reset are not counted (owner: incomplete reports can be legacy before the reset)' {
        # the live case: 6 incomplete runs before the reset of 2026-11-07 ~18:00Z, then the fresh run's report is incomplete too
        $h = @(1..6 | ForEach-Object { [pscustomobject]@{ Decided = 'incomplete'; RunUtc = ([datetime]'2026-11-07T05:15:00Z').AddDays(-2 * ($_ - 1)) } })
        $s = Get-RAIncompleteStreak -History $h -NowUtc ([datetime]'2026-11-08T06:05:00Z') -NotBefore ([datetime]'2026-11-07T18:25:44Z')
        $s.Runs | Should -Be 1 -Because 'only this run is over the fresh data'
        $s.Since.ToString('yyyy-MM-dd') | Should -Be '2026-11-08'
        (Get-RAIncompleteStreak -History $h -NowUtc ([datetime]'2026-11-08T06:05:00Z')).Runs | Should -Be 7 -Because 'without a boundary every kept run counts'
        $script:Engine | Should -Match 'SELECT MIN\(StartedUtc\) FROM cfg\.FlowRun'
        $script:Engine | Should -Match '-NotBefore \$__notBefore'
    }
    It 'no history, or a complete run last: this run only' {
        (Get-RAIncompleteStreak -History @() -NowUtc ([datetime]'2026-11-08')).Runs | Should -Be 1
        (Get-RAIncompleteStreak -History @([pscustomobject]@{ Decided = 'measured'; RunUtc = [datetime]'2026-11-07' })).Runs | Should -Be 1
        (Get-RAIncompleteStreak -History $null).Runs | Should -Be 1
    }
}

Describe '#1155 the engine wiring' {
    It 'the late passes'' left-overs ask Get-RALateLeftAction BEFORE recording a loss, and a split goes to the sub-bucket pass' {
        $i = $script:Engine.IndexOf('foreach ($db in @($__lp.Left))')
        $i | Should -BeGreaterThan 0
        $block = $script:Engine.Substring($i, 1400)
        $block | Should -Match 'Get-RALateLeftAction -LastError \(\[string\]\$__lpErr\[\[int\]\$db\]\) -Busy'
        $block.IndexOf('Get-RALateLeftAction') | Should -BeLessThan $block.IndexOf('Add-RABucketLoss')
        $block | Should -Match '\[void\]\$failedBucketIndices\.Add\(\$db\)'
        $block | Should -Match '\$__abSplitCause\[\[int\]\$db\] = \$true'
        # the sub-bucket pass comes AFTER, so the slice is really split in this run
        $script:Engine.IndexOf('if ($failedBucketIndices.Count -gt 0) {', $i) | Should -BeGreaterThan $i
    }
    It 'the sub-bucket pass splits a smaller slice that still times out at the gateway' {
        $script:Engine | Should -Match "if \(\`$subAction -eq 'Retry' -and \(Get-RALateLeftAction -LastError \`$subErr -Busy \`$__subBusy\) -eq 'Split'\) \{"
    }
    It 'the end of the run says the runs-in-a-row line, and from 3 runs the uplink''s cause carries it' {
        $script:Engine | Should -Match 'Get-RAIncompleteStreak -History'
        $script:Engine | Should -Match 'has NOT been complete on \{1\} runs in a row'
        $script:Engine | Should -Match 'if \(\$__st\.Runs -ge 3\)'
        $script:Engine | Should -Match 'not complete on \{1\} runs in a row \(since'
    }
}
