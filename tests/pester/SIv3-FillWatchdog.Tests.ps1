#Requires -Version 5.1
<#
    THE FIELD FILL NEVER WAITS IN SILENCE (owner 2026-11-10, the most critical install: the data sync waited 4 hours on ONE
    range of a field fill -- the database idle, no line written, nobody told -- "why have we not detected that ... has been
    hunging" / "how can we learn from this"). Invoke-SIDataParallelRanges still puts no time limit on a statement that works
    (no fixed limits), but it watches the wait:
      * about once a minute, while ranges are out, ONE line says what each range waits on (its wait type, how long, and the
        session blocking it -- program, host, its statement), read from the database's own request views;
      * a range that makes no progress (blocked / on a lock, or its session gone) for the stall time is CANCELLED and filled
        again on a fresh connection (a range is idempotent);
      * a range stalled a SECOND time ends the call with an error that names what it waited on -- the step says so and goes
        on: never a silent hang;
      * without a blocker the call answers every range, in range order, as before.
    REAL SQL: a second connection holds a lock on a row one range must write; the stall time is seconds here.
    And the heartbeat's "a step far past its usual time with no progress" (si-flow-1204) opens the support ticket (Invardia
    2026-11-10: support acts; the owner is not mailed for a stall).
#>

BeforeDiscovery {
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL)
}

BeforeAll {
    $script:SIRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
    . (Join-Path $script:SIRoot 'engine/pro-data/_shared/SI-DataViewContext.ps1')
}

Describe 'the watchdog is wired (no fixed limit, the wait is watched)' {
    It 'a statement still has no time limit; the wait is a watched WaitAny, never a bare EndInvoke on an open range' {
        $d = (Get-Command Invoke-SIDataParallelRanges).Definition
        $d | Should -Match '\$c\.CommandTimeout = 0'
        $d | Should -Match 'WaitAny\('
        $d | Should -Match 'sys\.dm_exec_requests'
        $d | Should -Match '\.Cancel\(\)'
        $d | Should -Match 'SET LOCK_TIMEOUT' -Because 'a lock wait is ended by the database, never by a client cancel on the watch''s thread'
        $d | Should -Match 'StallSeconds'
    }
    It 'every caller hands the step''s log to the watchdog' {
        foreach ($f in 'engine/pro-data/_shared/SI-DataViewContext.ps1', 'engine/pro-data/_shared/SI-DataCi.ps1') {
            $t = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f))
            foreach ($m in [regex]::Matches($t, 'Invoke-SIDataParallelRanges -ConnectionInfo[^\r\n]*')) { $m.Value | Should -Match '-Log \$Log' -Because $f }
        }
    }
    It 'si-flow-1204 opens the support ticket (support acts; the owner is not mailed)' {
        $e = @(([IO.File]::ReadAllText((Join-Path $script:SIRoot 'data-model/errors.locked.json')) | ConvertFrom-Json) | ForEach-Object { $_ }) | Where-Object code -eq 'si-flow-1204'
        $e.opensTicket | Should -BeTrue
        $e.whoActs | Should -Be 'support'
    }
}

Describe 'REAL SQL: a blocked range is said, cancelled, filled again -- and a second stall ends the call loudly' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:DbName = 'si_test_fillwatch_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$script:DbName]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$script:DbName;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false"
        $cn = New-Object System.Data.SqlClient.SqlConnection $script:Cs; $cn.Open()
        try { $c = $cn.CreateCommand(); $c.CommandText = 'CREATE TABLE dbo.R (Id bigint NOT NULL PRIMARY KEY, V int NOT NULL); INSERT dbo.R (Id, V) SELECT TOP (40) ROW_NUMBER() OVER (ORDER BY (SELECT 1)), 0 FROM sys.all_objects;'; [void]$c.ExecuteNonQuery() } finally { $cn.Dispose() }
        # the range statement: answers the rows it wrote (the fill's shape: @After < Id <= @Upto)
        $script:Fill = 'UPDATE dbo.R WITH (ROWLOCK) SET V = V + 1 WHERE Id > @After AND Id <= @Upto AND @CollectionId = @CollectionId; SELECT @@ROWCOUNT;'
        $script:Ci = { @{ ConnectionString = $script:Cs; AccessToken = '' } }
    }
    AfterAll {
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$script:DbName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:DbName]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    It 'no blocker: every range answers, in range order, and nothing is cancelled' {
        $lines = New-Object System.Collections.Generic.List[string]
        $res = Invoke-SIDataParallelRanges -ConnectionInfo $script:Ci -Sql $script:Fill -CollectionId 1 -Ranges @(@(0, 10), @(10, 20), @(20, 40)) -Log { param($l, $t) $lines.Add("$l $t") } -StallSeconds 5 -WatchSeconds 1
        @($res | ForEach-Object { [long]$_.N }) | Should -Be @(10, 10, 20)
        ($lines -join "`n") | Should -Not -Match 'cancelled'
    }
    It 'a range blocked by another session''s lock: said with its blocker, cancelled, filled again, and a second stall throws naming the wait' {
        # the holder: an open transaction with an exclusive lock on row 15 (range 2 must write it)
        $hold = New-Object System.Data.SqlClient.SqlConnection ($script:Cs + ';Application Name=si-test-lock-holder'); $hold.Open()
        $tx = $hold.BeginTransaction()
        try {
            $c = $hold.CreateCommand(); $c.Transaction = $tx; $c.CommandText = 'UPDATE dbo.R SET V = V + 100 WHERE Id = 15'; [void]$c.ExecuteNonQuery()
            $lines = New-Object System.Collections.Generic.List[string]
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $thrown = $null
            try { $null = Invoke-SIDataParallelRanges -ConnectionInfo $script:Ci -Sql $script:Fill -CollectionId 1 -Ranges @(@(0, 10), @(10, 20), @(20, 30)) -Log { param($l, $t) $lines.Add("$l $t") } -StallSeconds 4 -WatchSeconds 1 }
            catch { $thrown = $_.Exception.Message }
            $sw.Stop()
            $all = $lines -join "`n"
            $thrown | Should -Match 'range 2 of the field fill made no progress' -Because 'a second stall ends the call with an error, never a silent hang'
            $all | Should -Match 'fill watch  : 1 range\(s\) still out -- range 2:'
            # the database ends the lock wait itself (SET LOCK_TIMEOUT -- a client cancel does not interrupt a lock wait on
            # Linux, measured 2026-11-10); the watch steps in only when that does not happen
            $all | Should -Match 'range 2 (waited .* for a lock and was stopped by the database|made no progress for .* -- stopped)'
            $all | Should -Match 'range 2 is filled again on a fresh connection'
            # where the database lets the test read its request views, the line names the blocker and its program
            if ($all -notmatch 'could not be read') { $all | Should -Match 'blocked by session \d+ \(si-test-lock-holder' }
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 120 -Because 'the watch ends the wait; nothing waits forever'
        } finally { try { $tx.Rollback() } catch { }; $hold.Dispose() }
        # the lock is gone: the same ranges fill again (idempotent), every range answers
        $res = Invoke-SIDataParallelRanges -ConnectionInfo $script:Ci -Sql $script:Fill -CollectionId 1 -Ranges @(@(0, 10), @(10, 20), @(20, 30)) -StallSeconds 4 -WatchSeconds 1
        @($res | ForEach-Object { [long]$_.N }) | Should -Be @(10, 10, 10)
    }
}
