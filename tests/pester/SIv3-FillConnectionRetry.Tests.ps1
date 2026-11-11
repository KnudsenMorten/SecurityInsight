#Requires -Version 7.0
<#
    #1181 A RANGE WHOSE CONNECTION FAILS TO OPEN IS TRIED AGAIN, NOT THE WHOLE FIELD FILL GIVEN UP (a large install 2026-11-11:
    a range of the parallel field fill lost its session, its new connection then failed with "A network-related or
    instance-specific error ... (provider: TCP Provider, error: 0 - No such host is known.)" -- a name look-up that failed for
    a moment -- and the whole prepared-view-columns step gave up; the next step ran an hour longer).
    Rule 4: a PLATFORM failure (network / name look-up / a reset / Azure SQL's platform answers) is retried in the run; a query
    defect is not.
      * Invoke-SIDataParallelRanges: a range that meets a brief network failure starts again on a new connection after a pause
        (-RetryWaits), the log says so in one plain line, the other ranges run on, and the call answers every range;
      * a query defect (a syntax error, SQL 102) is never tried again;
      * a network failure every time ends the call after the bounded attempts, with the real error, exactly as before;
      * the shared open (Open-SISqlConnectionRetry: the data seam's every statement, the updater, setup) opens again after a
        network-level failure too.
    No database: the ranges run a fake runner (-RangeRunner, tests only) that fails as the driver does.
#>

BeforeAll {
    $script:SIRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    . (Join-Path $script:SIRoot 'engine/pro-data/_shared/SI-DataViewContext.ps1')
    $script:NoHost = 'A network-related or instance-specific error occurred while establishing a connection to SQL Server. The server was not found or was not accessible. Verify that the instance name is correct and that SQL Server is configured to allow remote connections. (provider: TCP Provider, error: 0 - No such host is known.)'
    # a server nobody answers on: the watch's own read of the request views fails at once and is said (never reached here
    # in the normal case -- the ranges end within the first wait)
    $script:Ci = { @{ ConnectionString = 'Server=tcp:127.0.0.1,1;Database=x;Connect Timeout=1;Pooling=false'; AccessToken = '' } }
    # the fake range: answers its row count (@Upto - @After); the range named by -FailWhen (a regex on the range's program
    # name '<tag>-<range index>-<stall attempt>-<network retries>') throws -Message instead
    function script:New-Runner([string]$FailWhen, [string]$Message) {
        $e = $Message.Replace("'", "''")
        @"
param([string]`$Cs, [string]`$Token, [string]`$Text, [long]`$Cid, [long]`$After, [long]`$Upto, [hashtable]`$More, [string]`$UpName, [string]`$App, [hashtable]`$Live, [long]`$LockMs)
if (`$App -match '$FailWhen') { throw '$e' }
[pscustomobject]@{ N = (`$Upto - `$After); Ms = 1L }
"@
    }
}

Describe 'the decision: which failure of a range is tried again (rule 4)' {
    It 'a name look-up / network-level failure of the open is tried again, with the pause of its attempt' {
        Get-SIDataRangeRetryWait -ErrorRecord $script:NoHost -Attempt 1 -Waits @(5, 10, 20, 45) | Should -Be 5
        Get-SIDataRangeRetryWait -ErrorRecord ([Exception]::new('Exception calling "Open" with "0" argument(s)', [Exception]::new($script:NoHost))) -Attempt 3 -Waits @(5, 10, 20, 45) | Should -Be 20
    }
    It 'a session lost under the statement (a reset connection, SQL 10054) is tried again' {
        $e = [Exception]::new('A transport-level error has occurred when receiving results from the server.')
        $e.Data['SISqlNumbers'] = @(10054)
        Get-SIDataRangeRetryWait -ErrorRecord $e -Attempt 1 -Waits @(5) | Should -Be 5
    }
    It 'a query defect (SQL 102, a syntax error) or a full database is never tried again' {
        $e = [Exception]::new("Incorrect syntax near 'FROM'.")
        $e.Data['SISqlNumbers'] = @(102)
        Get-SIDataRangeRetryWait -ErrorRecord $e -Attempt 1 -Waits @(5, 10) | Should -BeNullOrEmpty
        Get-SIDataRangeRetryWait -ErrorRecord "The database 'x' has reached its size quota." -Attempt 1 -Waits @(5, 10) | Should -BeNullOrEmpty
    }
    It 'bounded: past the last pause, or with nothing, it is not tried again' {
        Get-SIDataRangeRetryWait -ErrorRecord $script:NoHost -Attempt 5 -Waits @(5, 10, 20, 45) | Should -BeNullOrEmpty
        Get-SIDataRangeRetryWait -ErrorRecord $script:NoHost -Attempt 1 -Waits @() | Should -BeNullOrEmpty
        Get-SIDataRangeRetryWait -ErrorRecord $null -Attempt 1 -Waits @(5) | Should -BeNullOrEmpty
    }
    It 'the log line keeps the driver''s cause: a long message keeps its start and its end; PowerShell''s call wrapper is dropped' {
        $l = Get-SIDataRangeErrorLine ([Exception]::new('Exception calling "Open" with "0" argument(s): "x"', [Exception]::new($script:NoHost)))
        $l | Should -Match '^A network-related or instance-specific error'
        $l | Should -Match 'No such host is known\.\)$'
        $l.Length | Should -BeLessOrEqual 240
        Get-SIDataRangeErrorLine ('Exception calling "Open" with "0" argument(s): "{0}"' -f 'short cause') | Should -Be 'short cause'
    }
    It 'the default pauses are the shared ones: a few attempts over about a minute and a half' {
        $w = @(Get-SISqlConnectRetryWaits)
        $w.Count | Should -BeGreaterThan 1
        ($w | Measure-Object -Sum).Sum | Should -BeLessOrEqual 120
    }
}

Describe 'the parallel field fill: a brief network failure is tried again, the fill completes' {
    It 'range 2''s connection fails once with "No such host is known", then works: every range answers, in order, and the retry is said in plain words' {
        $lines = New-Object System.Collections.Generic.List[string]
        $runner = New-Runner -FailWhen '-1-1-0$' -Message $script:NoHost
        $res = Invoke-SIDataParallelRanges -ConnectionInfo $script:Ci -Sql 'x' -CollectionId 1 -Ranges @(@(0, 10), @(10, 20), @(20, 40)) -Log { param($l, $t) $lines.Add("$l $t") } -WatchSeconds 1 -RetryWaits @(1, 1, 1) -RangeRunner $runner
        @($res | ForEach-Object { [long]$_.N }) | Should -Be @(10, 10, 20)
        $all = $lines -join "`n"
        $warn = @($lines | Where-Object { $_ -match 'brief network failure' })
        $warn.Count | Should -Be 1
        # (asserted on the line itself, so a failure shows that line)
        $warn[0] | Should -Match '^WARN fill watch  : range 2 of the field fill met a brief network failure reaching the database \(A network-related or instance-specific error.*No such host is known\.\)\) -- tried again in 1 s \(attempt 1 of 3\)$'
        $warn[0] | Should -Not -Match 'Exception calling' -Because 'the driver''s own words, not PowerShell''s wrapper'
        $all | Should -Not -Match 'given up'
    }
    It 'the clean-up of old data says it under its own name' {
        $lines = New-Object System.Collections.Generic.List[string]
        $runner = New-Runner -FailWhen '-0-1-0$' -Message $script:NoHost
        $res = Invoke-SIDataParallelRanges -ConnectionInfo $script:Ci -Sql 'x' -CollectionId 1 -Ranges @(@(0, 5), @(5, 9)) -Log { param($l, $t) $lines.Add("$l $t") } -WatchSeconds 1 -RetryWaits @(1) -RangeRunner $runner -What 'the clean-up of old data' -Watch 'clean-up watch'
        @($res | ForEach-Object { [long]$_.N }) | Should -Be @(5, 4)
        ($lines -join "`n") | Should -Match 'WARN clean-up watch: range 1 of the clean-up of old data met a brief network failure reaching the database'
    }
    It 'a query defect (a syntax error) is NOT tried again: the call ends with it at once' {
        $lines = New-Object System.Collections.Generic.List[string]
        $runner = New-Runner -FailWhen '-1-\d+-\d+$' -Message "Incorrect syntax near 'FROM'."
        $thrown = ''
        try { $null = Invoke-SIDataParallelRanges -ConnectionInfo $script:Ci -Sql 'x' -CollectionId 1 -Ranges @(@(0, 10), @(10, 20)) -Log { param($l, $t) $lines.Add("$l $t") } -WatchSeconds 1 -RetryWaits @(1, 1, 1) -RangeRunner $runner }
        catch { $thrown = $_.Exception.Message }
        $thrown | Should -Match 'Incorrect syntax near'
        ($lines -join "`n") | Should -Not -Match 'brief network failure'
    }
    It 'a network failure every time: tried the bounded number of times, then the call fails with the real error, as before' {
        $lines = New-Object System.Collections.Generic.List[string]
        $runner = New-Runner -FailWhen '-1-\d+-\d+$' -Message $script:NoHost
        $thrown = ''
        $sw = [Diagnostics.Stopwatch]::StartNew()
        try { $null = Invoke-SIDataParallelRanges -ConnectionInfo $script:Ci -Sql 'x' -CollectionId 1 -Ranges @(@(0, 10), @(10, 20)) -Log { param($l, $t) $lines.Add("$l $t") } -WatchSeconds 1 -RetryWaits @(1, 1, 1) -RangeRunner $runner }
        catch { $thrown = $_.Exception.Message }
        $sw.Stop()
        $thrown | Should -Match 'No such host is known'
        @($lines | Where-Object { $_ -match 'range 2 of the field fill met a brief network failure' }).Count | Should -Be 3
        $all = $lines -join "`n"
        $all | Should -Match 'attempt 3 of 3'
        $all | Should -Match 'range 2 of the field fill still could not reach the database after 4 attempt\(s\) -- given up for this run'
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 60 -Because 'bounded: three pauses of one second'
    }
    It 'WIRING: the decision is the shared classification; the watchdog is kept; the field fill hands its log on' {
        $d = (Get-Command Invoke-SIDataParallelRanges).Definition
        $d | Should -Match 'Get-SIDataRangeRetryWait -ErrorRecord \$rangeErr'
        $d | Should -Match 'Get-SISqlConnectRetryWaits'
        $d | Should -Match 'WaitAny\('
        $d | Should -Match '\$c\.CommandTimeout = 0'
        $w = (Get-Command Get-SIDataRangeRetryWait).Definition
        $w | Should -Match 'Test-SISqlConnectTransient'
        $w | Should -Match 'Test-SISqlStatementTransient'
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine/pro-data/_shared/SI-DataViewContext.ps1'))
        $src | Should -Not -Match 'Invoke-SIDataParallelRanges [^\r\n]*-RangeRunner' -Because 'the fake runner is for tests only'
    }
}

Describe 'the shared open (every statement of the data seam): a network-level failure is opened again' {
    It '"No such host is known" once, then open: two opens, one pause' {
        $st = @{ Opens = 0; Waits = (New-Object System.Collections.Generic.List[int]) }
        $noHost = $script:NoHost
        $connect = { param($Server, $Database, $Token) $st.Opens++; if ($st.Opens -eq 1) { throw ('Exception calling "Open" with "0" argument(s): "{0}"' -f $noHost) }; 'open' }.GetNewClosure()
        $cn = Open-SISqlConnectionRetry -Server 's' -Database 'd' -Sleep { param($s) $st.Waits.Add($s) }.GetNewClosure() -Token { param([bool]$Fresh) 'tok' } -Connect $connect -Waits @(3, 3) 6>$null
        $cn | Should -Be 'open'
        $st.Opens | Should -Be 2
        $st.Waits.ToArray() | Should -Be @(3)
    }
    It 'a syntax error or a refused permission is still thrown at once' {
        $st = @{ Opens = 0 }
        $bad = { param($Server, $Database, $Token) $st.Opens++; throw "Incorrect syntax near 'FROM'." }.GetNewClosure()
        { Open-SISqlConnectionRetry -Server 's' -Database 'd' -Sleep { param($s) } -Token { param([bool]$Fresh) 'tok' } -Connect $bad -Waits @(1, 1) 6>$null } | Should -Throw
        $st.Opens | Should -Be 1
    }
    It 'bounded: a network failure every time ends after its pauses with the real error' {
        $st = @{ Opens = 0 }
        $noHost = $script:NoHost
        $always = { param($Server, $Database, $Token) $st.Opens++; throw $noHost }.GetNewClosure()
        { Open-SISqlConnectionRetry -Server 's' -Database 'd' -Sleep { param($s) } -Token { param([bool]$Fresh) 'tok' } -Connect $always -Waits @(1, 1) 6>$null } | Should -Throw -ExpectedMessage '*No such host is known*'
        $st.Opens | Should -Be 3
    }
}
