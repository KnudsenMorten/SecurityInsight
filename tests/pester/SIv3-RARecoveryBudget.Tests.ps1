#Requires -Version 7.0
<#
    #1200 -- ONE REPORT'S RETRIES NEVER HOLD THE WHOLE RUN: A TIME BUDGET PER REPORT FOR ITS RECOVERY.

    Live 2026-11-11 (two large installs): 71 of 72 Detailed reports done, the last one (an attack-path report over the exposure
    graph) answered 504 Gateway Timeout on every call (~3.3 min each, with its own 4 attempts). Its late passes went on, the
    refused slices were split (depth 1, then depth 2 = 512 slices) and retried there -- hours later still no loss and no end,
    and every later step, the next update and the identity move waited.

    What these tests keep true (offline, no tenant; the engine's loops in miniature over the SAME helpers, a fake clock):
      * 504s that outlast the budget: exactly the refused slices close as named losses, the report is partial, the loop ends;
      * a report that recovers inside the budget is whole, with no loss;
      * the budget is per report: a second report gets its own clock;
      * a call in flight when the budget runs out is never cut -- its rows are kept;
      * a split only for size (no retry) never starts the clock;
      * the setting: default 90, an override, 0 = no limit, junk = the default;
      * the engine wiring: one budget per report, checked before every new recovery call (late retry, smaller slice, retry
        pause), the plain line at the end, the losses through Add-RABucketLoss (the report's INCOMPLETE verdict and the run's
        partial roll-up), the progress ticker, and the setting in the reference and the catalog.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')
    function Write-Info { param($msg) }
    function Write-Warn2 { param($msg) }
    $script:Engine = Get-Content -Raw (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')

    # a fake clock: every call moves it by its own duration
    $script:Clock = [datetime]'2026-11-11T02:00:00Z'
    $script:Now = { $script:Clock }

    # THE ENGINE'S RECOVERY IN MINIATURE (Invoke-RiskAnalysis.ps1, the late-retry passes and the sub-bucket pass), over the real
    # helpers: the late passes (New-RALatePasses / Step / Set) with the budget asked before every attempt, the late left-overs
    # (Get-RALateLeftAction: a slice that timed out at the gateway every time is split), then the smaller slices (a queue, 4
    # per split; the budget asked at every dequeue and before every call). -Ask { param($Count, $Index) } moves the clock and
    # returns rows or throws. Returns the rows, the named losses, the calls made and the budget.
    $script:RunRecovery = {
        param([int]$Count, [int[]]$Refused, [scriptblock]$Ask, $Budget, [int]$LateRetries = 3, [int]$SubRetries = 3)
        $rows = New-Object System.Collections.Generic.List[int]
        $loss = New-Object System.Collections.Generic.List[string]
        $split = New-Object System.Collections.Generic.List[int]
        $calls = 0
        # the first normal pass: every slice not refused answered there (not part of the recovery)
        foreach ($b0 in 0..($Count - 1)) { if ($b0 -notin $Refused) { foreach ($r in (& $script:Rows $Count $b0)) { $rows.Add($r) } } }
        $null = Start-RARecoveryBudget -Budget $Budget
        $lp = New-RALatePasses -Pending $Refused
        $err = @{}; $notRead = @{}
        while (-not (Test-RARecoveryBudgetSpent -Budget $Budget) -and (Step-RALatePasses -State $lp)) {
            foreach ($db in @($lp.Current)) {
                $res = 'gone'; $last = [string]$err[$db]
                for ($la = 1; $la -le $LateRetries; $la++) {
                    if (Test-RARecoveryBudgetSpent -Budget $Budget) { $notRead[$db] = $last; break }
                    Step-RARecoveryBudgetCall -Budget $Budget; $calls++
                    try { foreach ($r in (& $Ask $Count $db)) { $rows.Add($r) }; $res = 'ok'; break }
                    catch { $last = $_.Exception.Message; if ($la -eq $LateRetries) { $err[$db] = $last; $res = 'retry' } }
                }
                Set-RALatePassResult -State $lp -Index $db -Result $res
            }
        }
        if (Test-RARecoveryBudgetSpent -Budget $Budget) {
            foreach ($db in @($lp.Next.ToArray()) + @($lp.Left)) { if (-not $notRead.ContainsKey($db)) { $notRead[$db] = [string]$err[$db] } }
            $lp.Left = [int[]]@()
            foreach ($db in @($notRead.Keys | Sort-Object)) { $loss.Add((Format-RARecoveryBudgetLoss -Slice ('bucket {0}/{1}' -f ($db + 1), $Count) -Minutes $Budget.Minutes -LastError $notRead[$db])); $Budget.Lost++ }
        }
        foreach ($db in @($lp.Left)) {
            if ((Get-RALateLeftAction -LastError ([string]$err[$db]) -Busy $false) -eq 'Split') { $split.Add($db) } else { $loss.Add(('bucket {0}/{1}: lost' -f ($db + 1), $Count)) }
        }
        $q = New-Object System.Collections.Generic.Queue[object]
        foreach ($db in $split) { $q.Enqueue(@{ N = $db; T = $Count }) }
        while ($q.Count -gt 0) {
            $it = $q.Dequeue()
            if (Test-RARecoveryBudgetSpent -Budget $Budget) { $loss.Add((Format-RARecoveryBudgetLoss -Slice ('sub-bucket {0}/{1}' -f $it.N, $it.T) -Minutes $Budget.Minutes)); $Budget.Lost++; continue }
            $newT = $it.T * 4
            for ($j = 0; $j -lt 4; $j++) {
                $subN = $it.N + $j * $it.T; $done = $false; $att = 0; $lastErr = ''
                while (-not $done) {
                    if (Test-RARecoveryBudgetSpent -Budget $Budget) { $loss.Add((Format-RARecoveryBudgetLoss -Slice ('sub-bucket {0}/{1}' -f $subN, $newT) -Minutes $Budget.Minutes -LastError $lastErr)); $Budget.Lost++; $done = $true; continue }
                    $att++; Step-RARecoveryBudgetCall -Budget $Budget; $calls++
                    try { foreach ($r in (& $Ask $newT $subN)) { $rows.Add($r) }; $done = $true }
                    catch {
                        $lastErr = $_.Exception.Message
                        if ($att -lt $SubRetries) { continue }
                        $done = $true
                        if ((Get-RALateLeftAction -LastError $lastErr -Busy $false) -eq 'Split') { $q.Enqueue(@{ N = $subN; T = $newT }) }
                        else { $loss.Add(('sub-bucket {0}/{1}: lost' -f $subN, $newT)) }
                    }
                }
            }
        }
        $line = if ($Budget.Spent -and $Budget.Lost -gt 0) { Format-RARecoveryBudgetLine -ReportName 'R' -ElapsedMinutes (Get-RARecoveryBudgetElapsedMinutes -Budget $Budget) -NotRead $Budget.Lost } else { '' }
        [pscustomobject]@{ Rows = @($rows | Sort-Object -Unique); Loss = @($loss); Calls = $calls; Budget = $Budget; Line = $line }
    }
    # a source of 3200 rows over 32 slices: a row's slice at count C is id % C
    $script:Source = 1..3200
    $script:Rows = { param([int]$C, [int]$I) @($script:Source | Where-Object { ($_ % $C) -eq $I }) }
}

Describe '#1200 504s that outlast the budget' {
    BeforeEach { $script:Clock = [datetime]'2026-11-11T02:00:00Z' }
    It 'exactly the refused slices close as named losses, the report is partial, and the recovery ends' {
        # slices 9 and 10 of 32 answer 504 on EVERY call at EVERY size (the live case); each call takes 3.3 minutes
        $ask = { param($C, $I) $script:Clock = $script:Clock.AddMinutes(3.3); if (($I % 32) -in 9, 10) { throw 'Response status code does not indicate success: 504 (Gateway Timeout).' }; & $script:Rows $C $I }
        $b = New-RARecoveryBudget -Minutes 90 -Now $script:Now
        $r = & $script:RunRecovery -Count 32 -Refused @(9, 10) -Ask $ask -Budget $b
        $r.Budget.Spent | Should -BeTrue
        $r.Loss.Count | Should -BeGreaterThan 0
        $r.Loss | ForEach-Object { $_ | Should -Match 'not read -- the recovery time budget of this report \(90 min\) was spent; its rows are unknown, not resolved' }
        # every loss is a slice of the two refused buckets -- never a bucket that answered
        foreach ($l in $r.Loss) {
            $m = [regex]::Match($l, '^(?:sub-)?bucket (\d+)/(\d+)')
            $n = [int]$m.Groups[1].Value; $t = [int]$m.Groups[2].Value
            $idx = if ($l -like 'bucket *') { $n - 1 } else { $n }
            ($idx % 32) | Should -BeIn @(9, 10)
            $t | Should -BeGreaterOrEqual 32
        }
        # the rows of every other bucket are all there; nothing of the refused ones is claimed
        $want = @($script:Source | Where-Object { ($_ % 32) -notin 9, 10 })
        (Compare-Object $r.Rows $want) | Should -BeNullOrEmpty
        # the recovery ended: no call started after the budget (the last one began before 90 min and ran its 3.3)
        (($script:Clock - [datetime]'2026-11-11T02:00:00Z').TotalMinutes) | Should -BeLessThan (90 + 3.3 + 0.01)
        $r.Line | Should -Match "^recovery for 'R' stopped after \d+ min \(budget\): $($r.Loss.Count) bucket\(s\) not read -- their findings are unknown, the next run reads this report again$"
    }
    It 'without the budget (0) the same source is still being retried far past 90 minutes -- the live hang' {
        $script:Calls0 = 0
        $ask = { param($C, $I) $script:Clock = $script:Clock.AddMinutes(3.3); $script:Calls0++; if ($script:Calls0 -gt 120) { throw 'STOP' }; if (($I % 32) -in 9, 10) { throw '504 (Gateway Timeout)' }; & $script:Rows $C $I }
        $b = New-RARecoveryBudget -Minutes 0 -Now $script:Now
        $null = & $script:RunRecovery -Count 32 -Refused @(9, 10) -Ask $ask -Budget $b
        (($script:Clock - [datetime]'2026-11-11T02:00:00Z').TotalMinutes) | Should -BeGreaterThan 180
        $b.Spent | Should -BeFalse
    }
}

Describe '#1200 a report that recovers inside the budget is whole' {
    BeforeEach { $script:Clock = [datetime]'2026-11-11T02:00:00Z' }
    It 'a slice that answers on its second late attempt and a slice that answers when split: every row, no loss, no line' {
        $script:Seen = @{}
        $ask = {
            param($C, $I)
            $script:Clock = $script:Clock.AddMinutes(3.3)
            $k = "$C/$I"; $script:Seen[$k] = 1 + [int]$script:Seen[$k]
            if ($C -eq 32 -and $I -eq 4 -and $script:Seen[$k] -lt 2) { throw '429 Too Many Requests' }
            if ($C -eq 32 -and $I -eq 7) { throw '504 (Gateway Timeout)' }
            & $script:Rows $C $I
        }
        $b = New-RARecoveryBudget -Minutes 90 -Now $script:Now
        $r = & $script:RunRecovery -Count 32 -Refused @(4, 7) -Ask $ask -Budget $b
        $r.Loss | Should -BeNullOrEmpty
        $b.Spent | Should -BeFalse
        $r.Line | Should -Be ''
        (Compare-Object $r.Rows $script:Source) | Should -BeNullOrEmpty
    }
}

Describe '#1200 the budget is per report' {
    It 'a second report gets its own clock' {
        $script:Clock = [datetime]'2026-11-11T02:00:00Z'
        $a = New-RARecoveryBudget -Minutes 90 -Now $script:Now
        $null = Start-RARecoveryBudget -Budget $a
        $script:Clock = $script:Clock.AddMinutes(95)
        Test-RARecoveryBudgetSpent -Budget $a | Should -BeTrue
        $b = New-RARecoveryBudget -Minutes 90 -Now $script:Now
        Test-RARecoveryBudgetSpent -Budget $b | Should -BeFalse -Because 'its clock has not started'
        Start-RARecoveryBudget -Budget $b | Should -BeTrue
        $script:Clock = $script:Clock.AddMinutes(60)
        Test-RARecoveryBudgetSpent -Budget $b | Should -BeFalse
        Test-RARecoveryBudgetSpent -Budget $a | Should -BeTrue -Because 'once spent it stays spent for that report'
    }
    It 'the clock starts once -- a later start does not move it' {
        $script:Clock = [datetime]'2026-11-11T02:00:00Z'
        $a = New-RARecoveryBudget -Minutes 90 -Now $script:Now
        Start-RARecoveryBudget -Budget $a | Should -BeTrue
        $script:Clock = $script:Clock.AddMinutes(80)
        Start-RARecoveryBudget -Budget $a | Should -BeFalse
        $script:Clock = $script:Clock.AddMinutes(11)
        Test-RARecoveryBudgetSpent -Budget $a | Should -BeTrue
    }
    It 'the engine makes the budget where each report resets its own losses' {
        $i = $script:Engine.IndexOf('Reset-RABucketLoss   # audit #62 -- per-report')
        $i | Should -BeGreaterThan 0
        $script:Engine.Substring($i, 400) | Should -Match '\$__rb = New-RARecoveryBudget -Minutes \(Get-RARecoveryBudgetMinutes -Value \$global:SI_RA_RecoveryBudgetMinutes\)'
    }
}

Describe '#1200 a call in flight is never cut' {
    It 'a call that starts before the budget ends and answers after it keeps its rows; the next call does not start' {
        $script:Clock = [datetime]'2026-11-11T02:00:00Z'
        $script:N = 0
        # bucket 3: refused for 88 minutes, then a 10-minute call that answers (it ends at minute 98, past the budget)
        $ask = {
            param($C, $I)
            $script:N++
            if ($I -eq 3) {
                if ($script:Clock -lt [datetime]'2026-11-11T03:28:00Z') { $script:Clock = $script:Clock.AddMinutes(4); throw '503 Service Unavailable' }
                $script:Clock = $script:Clock.AddMinutes(10); return (& $script:Rows $C $I)
            }
            $script:Clock = $script:Clock.AddMinutes(4); throw '503 Service Unavailable'
        }
        $b = New-RARecoveryBudget -Minutes 90 -Now $script:Now
        $r = & $script:RunRecovery -Count 32 -Refused @(3, 5) -Ask $ask -Budget $b -LateRetries 30
        @($r.Rows) | Should -Contain 3 -Because 'the call in flight finished and its rows are kept'
        ($r.Loss -join "`n") | Should -Not -Match 'bucket 4/32'
        ($r.Loss -join "`n") | Should -Match 'bucket 6/32: not read'
        $b.Spent | Should -BeTrue
        $script:Clock | Should -Be ([datetime]'2026-11-11T03:38:00Z') -Because 'no call started after the budget was seen spent'
    }
    It 'the engine asks the budget only BEFORE a call (never inside the hunting call): its own attempts are not shortened' {
        $script:Engine | Should -Not -Match 'Invoke-GraphHuntingQuery[^\r\n]*RecoveryBudget'
        $script:Engine | Should -Match 'Invoke-GraphHuntingQuery -Query \$dbQuery -ReconnectMaxAgeMinutes \$global:GraphReconnectMaxAgeMinutes -MaxRetries \$global:GraphQueryMaxRetries'
        $script:Engine | Should -Match 'Invoke-GraphHuntingQuery -Query \$subQuery -ReconnectMaxAgeMinutes \$global:GraphReconnectMaxAgeMinutes -MaxRetries \$global:GraphQueryMaxRetries'
    }
}

Describe '#1200 a split only for size never starts the clock' {
    It 'no retry-class answer = no clock = never spent, however long the smaller slices take' {
        $script:Clock = [datetime]'2026-11-11T02:00:00Z'
        $b = New-RARecoveryBudget -Minutes 90 -Now $script:Now
        $script:Clock = $script:Clock.AddMinutes(300)
        Test-RARecoveryBudgetSpent -Budget $b | Should -BeFalse
        Get-RARecoveryBudgetElapsedMinutes -Budget $b | Should -Be 0
    }
    It 'the engine starts the clock at the late retry and at a smaller slice refused as Retry -- not at a size split' {
        $script:Engine | Should -Match '(?s)\$__lpErr = @\{\}; \$__lpBusy = @\{\}\s+# #1200[^\n]*\n\s+& \$__rbStart'
        $script:Engine | Should -Match 'if \(\$subAction -eq ''Retry''\) \{ & \$__rbStart \}'
    }
}

Describe '#1200 the setting' {
    It 'default 90' {
        Get-RARecoveryBudgetMinutes -Value $null | Should -Be 90
        Get-RARecoveryBudgetMinutes -Value '' | Should -Be 90
        (New-RARecoveryBudget).Minutes | Should -Be 90
    }
    It 'an override is used; 0 = no time limit; junk or a negative number = the default' {
        Get-RARecoveryBudgetMinutes -Value 30 | Should -Be 30
        Get-RARecoveryBudgetMinutes -Value '240' | Should -Be 240
        Get-RARecoveryBudgetMinutes -Value 0 | Should -Be 0
        Get-RARecoveryBudgetMinutes -Value -5 | Should -Be 90
        Get-RARecoveryBudgetMinutes -Value 'soon' | Should -Be 90
        $script:Clock = [datetime]'2026-11-11T02:00:00Z'
        $b = New-RARecoveryBudget -Minutes (Get-RARecoveryBudgetMinutes -Value 30) -Now $script:Now
        $null = Start-RARecoveryBudget -Budget $b
        $script:Clock = $script:Clock.AddMinutes(29); Test-RARecoveryBudgetSpent -Budget $b | Should -BeFalse
        $script:Clock = $script:Clock.AddMinutes(1); Test-RARecoveryBudgetSpent -Budget $b | Should -BeTrue
        $z = New-RARecoveryBudget -Minutes 0 -Now $script:Now; $null = Start-RARecoveryBudget -Budget $z
        $script:Clock = $script:Clock.AddDays(2); Test-RARecoveryBudgetSpent -Budget $z | Should -BeFalse
    }
    It 'the reference documents it and the catalog carries it (minutes, at least 0)' {
        $ref = Get-Content -Raw (Join-Path $script:SIRoot 'config\SecurityInsight.custom.reference.ps1')
        $ref | Should -Match '\$global:SI_RA_RecoveryBudgetMinutes = 90'
        $cat = Get-Content -Raw (Join-Path $script:SIRoot 'config\settings.catalog.locked.json') | ConvertFrom-Json
        $s = @($cat.settings | Where-Object { $_.name -eq 'SI_RA_RecoveryBudgetMinutes' })
        $s.Count | Should -Be 1
        $s[0].type | Should -Be 'int'
        $s[0].min | Should -Be 0
        $s[0].defaultText | Should -Match '^90 minutes'
    }
}

Describe '#1200 the engine wiring' {
    It 'every new recovery call asks the budget first: the late passes, each late attempt (before and after its pause), each queued smaller slice, each smaller-slice call, each retry pause' {
        $script:Engine | Should -Match 'while \(-not \(Test-RARecoveryBudgetSpent -Budget \$__rb\) -and \(Step-RALatePasses -State \$__lp\)\) \{'
        ([regex]::Matches($script:Engine, 'if \(Test-RARecoveryBudgetSpent -Budget \$__rb\) \{ \$__rbNotRead\[\[int\]\$db\] = \[string\]\$dbErr; \$dbDone = \$true; break \}')).Count | Should -Be 2
        $i = $script:Engine.IndexOf('$pRounds = if ($item.ContainsKey(''A''))')
        $script:Engine.Substring($i, 600) | Should -Match 'if \(Test-RARecoveryBudgetSpent -Budget \$__rb\) \{'
        $w = $script:Engine.IndexOf('while (-not $subDone) {')
        $script:Engine.Substring($w, 300) | Should -Match 'if \(Test-RARecoveryBudgetSpent -Budget \$__rb\) \{'
        $script:Engine | Should -Match 'if \(Test-RARecoveryBudgetSpent -Budget \$__rb\) \{ continue \}\s+\$subSleep = Get-RABucketRetryDelaySeconds'
    }
    It 'the losses go through Add-RABucketLoss (the INCOMPLETE verdict, the run''s partial roll-up) and the plain line is said once' {
        ([regex]::Matches($script:Engine, 'Add-RABucketLoss \(Format-RARecoveryBudgetLoss ')).Count | Should -Be 3
        $script:Engine | Should -Match 'if \(\[bool\]\$__rb\.Spent -and \[int\]\$__rb\.Lost -gt 0\) \{\s+Write-Warn2 \(Format-RARecoveryBudgetLine '
        $script:Engine.IndexOf('Format-RARecoveryBudgetLine') | Should -BeLessThan $script:Engine.IndexOf('$bucketRunSucceeded = $true')
    }
    It 'a spent budget sends no late left-over to the smaller slices (it is a loss instead)' {
        $i = $script:Engine.IndexOf('# #1200: the budget was spent -- every slice still refused')
        $j = $script:Engine.IndexOf('foreach ($db in @($__lp.Left))', $i)
        $i | Should -BeGreaterThan 0
        $script:Engine.Substring($i, $j - $i) | Should -Match '\$__lp\.Left = \[int\[\]\]@\(\)'
    }
    It 'the recovery ticks progress (PROGRESS-TICK-1) through the step ticker' {
        $script:Engine | Should -Match "New-RAProgressTicker -Stream .* -Unit 'query slices asked again'"
        ([regex]::Matches($script:Engine, 'Step-RARecoveryBudgetCall -Budget \$__rb')).Count | Should -Be 2
    }
    It 'a call is counted and the ticker told; no ticker or no helper never fails' {
        $b = New-RARecoveryBudget -Minutes 90
        { Step-RARecoveryBudgetCall -Budget $b } | Should -Not -Throw
        $b.Calls | Should -Be 1
        { Step-RARecoveryBudgetCall -Budget $null } | Should -Not -Throw
        $script:Told = 0
        function script:Step-SIStepProgressTicker { param($Ticker, [long]$Done) $script:Told = $Done; $true }
        $t = New-RARecoveryBudget -Minutes 90 -Ticker @{ x = 1 }
        Step-RARecoveryBudgetCall -Budget $t; Step-RARecoveryBudgetCall -Budget $t
        $script:Told | Should -Be 2
    }
}
