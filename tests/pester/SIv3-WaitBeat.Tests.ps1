#Requires -Version 7.0
<#
    THE NAMED WAIT BEAT (#1310, framework 8.18 "a named wait beat during one external call is allowed", Invardia 2026-11-23;
    found in SUP-2026-00674: one long call wrote nothing for 2 h and the run monitor took a working step for dead).
    engine\_shared\SI-WaitBeat.ps1, wired into the SQL seam (engine\_shared\data-sql\SI-DataSql.ps1):
      * while ONE call runs it beats -- the line names what it waits on and since when (never a generic "alive");
      * at most every 5 minutes in production (300 s floor; the tests use milliseconds);
      * it stops when the call returns AND when it throws: the timer is disposed, nothing beats after (no orphan);
      * the mark moves this execution's cfg.StepProgress time and leaves its phase / done / total as they are (real SQL);
      * no sys.dm_exec_requests, no new right; a beat that cannot be built leaves the call as it was.
    The real-SQL part needs SI_TEST_LOCALSQL (the Azure runner). NO EMOJI IN THIS FILE.
#>

BeforeDiscovery {
    $script:HasSql = $false
    try { $script:HasSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:HasSql = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\SI-StepPhase.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-WaitBeat.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataSql.ps1')
    # a connection whose one command takes -Ms milliseconds, then answers or throws
    function script:New-FakeConnection([int]$Ms, [switch]$Throw) {
        $cmd = [pscustomobject]@{ CommandText = ''; CommandTimeout = 0; Ms = $Ms; Throw = [bool]$Throw; Parameters = [pscustomobject]@{} }
        $cmd.Parameters | Add-Member -MemberType ScriptMethod -Name AddWithValue -Value { param($n, $v) }
        $cmd | Add-Member -MemberType ScriptMethod -Name ExecuteNonQuery -Value { Start-Sleep -Milliseconds $this.Ms; if ($this.Throw) { throw 'Invalid object name ''dbo.Nope''.' }; 1 }
        $cn = [pscustomobject]@{ Cmd = $cmd }
        $cn | Add-Member -MemberType ScriptMethod -Name CreateCommand -Value { $this.Cmd }
        $cn | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
        $cn
    }
}

Describe 'the beat itself (Start-SIWaitBeat / Stop-SIWaitBeat)' {
    AfterEach { $global:SI_WaitBeatOff = $null }
    It 'beats while the call runs, and each line names what it waits on and since when' {
        $b = Start-SIWaitBeat -What 'the database sqldb-si-pro (nonquery): UPDATE sidata.Finding SET' -FirstMs 100 -EveryMs 100 -Quiet
        $b | Should -Not -BeNullOrEmpty
        Start-Sleep -Milliseconds 650
        $r = Stop-SIWaitBeat -Beat $b
        $r.Beats | Should -BeGreaterOrEqual 3
        foreach ($l in $r.Lines) {
            $l | Should -Match '^\[wait\] waiting on the database sqldb-si-pro \(nonquery\): UPDATE sidata\.Finding SET since \d\d:\d\d:\d\dZ \(\d+ min so far\) -- one call, still running$'
            $l | Should -Not -Match '(?i)\balive\b'
        }
    }
    It 'stops when it is ended: the timer is gone and nothing beats after (no orphan)' {
        $b = Start-SIWaitBeat -What 'x' -FirstMs 80 -EveryMs 80 -Quiet
        Start-Sleep -Milliseconds 300
        $r = Stop-SIWaitBeat -Beat $b
        $r.Stopped | Should -BeTrue
        $n = [int]$b.Beats
        Start-Sleep -Milliseconds 400
        [int]$b.Beats | Should -Be $n -Because 'a stopped beat never beats again'
    }
    It 'a call shorter than the first beat says nothing' {
        $b = Start-SIWaitBeat -What 'x' -FirstMs 2000 -EveryMs 2000 -Quiet
        $r = Stop-SIWaitBeat -Beat $b
        $r.Beats | Should -Be 0; $r.Lines.Count | Should -Be 0; $r.Stopped | Should -BeTrue
    }
    It 'in production it beats at most every 5 minutes (a smaller number of seconds is raised to 300)' {
        $src = (Get-Command Start-SIWaitBeat).Definition
        $src | Should -Match ([regex]::Escape('$FirstMs = [Math]::Max(300, $FirstSeconds) * 1000'))
        $src | Should -Match ([regex]::Escape('$EveryMs = [Math]::Max(300, $EverySeconds) * 1000'))
        # the SQL seam passes milliseconds only when a test set them (never in a run)
        [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataSql.ps1')) | Should -Match ([regex]::Escape('if ($global:SI_WaitBeatEveryMs -is [int] -and [int]$global:SI_WaitBeatEveryMs -gt 0)'))
    }
    It 'a beat that cannot be built leaves the call as it was: no beat, no throw, said once' {
        $global:SI_WaitBeatOff = 'test: no compiler'
        { Start-SIWaitBeat -What 'x' -Quiet } | Should -Not -Throw
        Start-SIWaitBeat -What 'x' -Quiet | Should -BeNullOrEmpty
        Stop-SIWaitBeat -Beat $null | Should -BeNullOrEmpty
    }
    It 'reads no server view and asks for no right' {
        # the code only (the C# the timer runs, and what the functions send) -- the file's header names what it does NOT do
        $code = (Get-SIWaitBeatSource) + (Get-Command Start-SIWaitBeat).Definition + (Get-Command Stop-SIWaitBeat).Definition + (Get-SIStepProgressMarkSql)
        $code | Should -Not -Match '(?i)dm_exec_requests|VIEW (DATABASE|SERVER) STATE'
        $code | Should -Match 'UPDATE cfg\.StepProgress SET LastUtc = SYSUTCDATETIME\(\)'
    }
}

Describe 'what a call waits on, in words (Get-SIWaitBeatWhat, PURE)' {
    It 'the database, the mode and the start of the statement -- folded, at most 120 characters, no comment lines' {
        Get-SIWaitBeatWhat -Database 'sqldb-si-pro' -Mode 'scalar' -Sql "SET NOCOUNT ON;`n-- a note`nSELECT   COUNT_BIG(*)`n FROM sidata.Finding" | Should -Be 'the database sqldb-si-pro (scalar): SELECT COUNT_BIG(*) FROM sidata.Finding'
        (Get-SIWaitBeatWhat -Database 'd' -Mode 'nonquery' -Sql ('UPDATE t SET a = 1 WHERE ' + ('x' * 300))).Length | Should -BeLessOrEqual 150
        Get-SIWaitBeatWhat -Database 'd' -Mode 'session' -Sql '' | Should -Be 'the database d (a session of several statements)'
    }
}

Describe 'the SQL seam beats for the one call it runs, and stops when the call returns or throws' {
    BeforeEach { $global:SI_WaitBeatEveryMs = 120; $global:SI_WaitBeatLast = $null }
    AfterEach { $global:SI_WaitBeatEveryMs = $null; $global:SI_WaitBeatLast = $null }
    It 'a long statement that returns: it beat, named the statement, and stopped with the call' {
        $fake = New-FakeConnection -Ms 700
        $inv = New-SIDataSqlInvoke -Server 'srv' -Database 'sqldb-si-pro' -TokenSeam { 't' } -Connect { param($s, $d, $t) $fake }.GetNewClosure() -StatementWaits @()
        & $inv 'UPDATE sidata.Finding SET State = 1 WHERE FindingId > @After' @{ After = 1 } 'nonquery'
        $r = $global:SI_WaitBeatLast
        $r | Should -Not -BeNullOrEmpty
        $r.Stopped | Should -BeTrue
        $r.Beats | Should -BeGreaterOrEqual 2
        $r.Lines[0] | Should -Match '^\[wait\] waiting on the database sqldb-si-pro \(nonquery\): UPDATE sidata\.Finding SET State = 1 WHERE FindingId > @After since '
        $r.Marks | Should -Be 0 -Because 'a test connection gives the beat nothing to mark with'
    }
    It 'a long statement that throws: the error is the call''s own, and the beat stopped with it' {
        $fake = New-FakeConnection -Ms 500 -Throw
        $inv = New-SIDataSqlInvoke -Server 'srv' -Database 'sqldb-si-pro' -TokenSeam { 't' } -Connect { param($s, $d, $t) $fake }.GetNewClosure() -StatementWaits @()
        { & $inv 'DELETE sidata.Nope' @{} 'nonquery' } | Should -Throw '*Invalid object name*'
        $r = $global:SI_WaitBeatLast
        $r.Stopped | Should -BeTrue
        $r.Beats | Should -BeGreaterOrEqual 1
    }
    It 'the wiring: the beat is made inside the call and ended in its finally' {
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataSql.ps1'))
        $at = $src.IndexOf('$__wb = & $beatStart @__wbArgs')
        $loop = $src.IndexOf('try { & $attemptOnce; break }')
        $fin = $src.IndexOf('} finally { if ($null -ne $__wb) { $global:SI_WaitBeatLast = & $beatStop $__wb } }')
        $at | Should -BeGreaterThan 0; $at | Should -BeLessThan $loop; $fin | Should -BeGreaterThan $loop
    }
}

Describe 'the mark in real SQL: this execution''s progress time moves, its words stay' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Db = 'si_test_wb_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $script:Cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$($script:Db);$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false"
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Q = {
            param([string]$Sql)
            $cn = New-Object System.Data.SqlClient.SqlConnection $script:Cs; $cn.Open()
            try { $c = $cn.CreateCommand(); $c.CommandText = $Sql; $v = $c.ExecuteScalar(); if ($v -is [DBNull]) { $null } else { $v } } finally { $cn.Dispose() }
        }
        $null = & $script:Q 'CREATE SCHEMA cfg'
        $null = & $script:Q (Get-SIStepProgressTableSql)
        $null = & $script:Q "INSERT cfg.StepProgress (Execution, Job, Phase, Done, Total, LastUtc, Beats) VALUES (N'caj-si-raworker-detailed-abc12', N'caj-si-raworker-detailed', N'report R_Detailed', 20, 21, DATEADD(HOUR, -2, SYSUTCDATETIME()), 1)"
    }
    AfterAll {
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$($script:Db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    It 'the beat moves LastUtc of THIS execution and leaves its phase, done and total as they are' {
        $b = Start-SIWaitBeat -What 'the database x (nonquery): UPDATE y' -FirstMs 100 -EveryMs 150 -Quiet -ConnectionString $script:Cs -Execution 'caj-si-raworker-detailed-abc12' -Job 'caj-si-raworker-detailed'
        Start-Sleep -Milliseconds 900
        $r = Stop-SIWaitBeat -Beat $b
        $r.LastError | Should -BeNullOrEmpty
        $r.Marks | Should -BeGreaterOrEqual 2
        [int](& $script:Q "SELECT DATEDIFF(SECOND, LastUtc, SYSUTCDATETIME()) FROM cfg.StepProgress WHERE Execution = N'caj-si-raworker-detailed-abc12'") | Should -BeLessThan 30
        & $script:Q "SELECT CONCAT(Phase, N'|', Done, N'|', Total) FROM cfg.StepProgress WHERE Execution = N'caj-si-raworker-detailed-abc12'" | Should -Be 'report R_Detailed|20|21'
        [int](& $script:Q 'SELECT COUNT(*) FROM cfg.StepProgress') | Should -Be 1
    }
    It 'through the real seam: a statement that waits beats, then the beat stops with it' {
        $global:SI_WaitBeatEveryMs = 150
        try {
            $real = { param($s, $d, $t) $c = New-Object System.Data.SqlClient.SqlConnection $script:Cs; $c.Open(); $c }
            $inv = New-SIDataSqlInvoke -Server 'srv' -Database $script:Db -TokenSeam { 't' } -Connect $real -StatementWaits @()
            & $inv "WAITFOR DELAY '00:00:01'" @{} 'nonquery'
            $global:SI_WaitBeatLast.Stopped | Should -BeTrue
            $global:SI_WaitBeatLast.Beats | Should -BeGreaterOrEqual 3
            $global:SI_WaitBeatLast.Lines[0] | Should -Match ("waiting on the database {0} \(nonquery\): WAITFOR DELAY '00:00:01' since " -f [regex]::Escape($script:Db))
        } finally { $global:SI_WaitBeatEveryMs = $null }
    }
    It 'SUP-2026-00676: a SESSION of several statements (the findings-per-CI replace) beats for the whole session, a short call of the seam inside it included, and stops with it' {
        $global:SI_WaitBeatEveryMs = 150
        try {
            $real = { param($s, $d, $t) $c = New-Object System.Data.SqlClient.SqlConnection $script:Cs; $c.Open(); $c }
            $inv = New-SIDataSqlInvoke -Server 'srv' -Database $script:Db -TokenSeam { 't' } -Connect $real -StatementWaits @()
            $seam = $inv
            $out = & $inv $null $null 'session' {
                param($Run)
                & $Run "WAITFOR DELAY '00:00:00.6'" 'none'
                # the step's progress ticker writes through the step's seam while the session runs (its own short call)
                $null = & $seam 'SELECT 1' @{} 'scalar'
                & $Run "WAITFOR DELAY '00:00:00.6'" 'none'
                [int](& $Run 'SELECT 7' 'scalar')
            }
            [int]@($out)[-1] | Should -Be 7
            $r = $global:SI_WaitBeatLast
            $r.Stopped | Should -BeTrue
            $r.Beats | Should -BeGreaterOrEqual 4 -Because 'the beat runs for the whole session, not only its first statement'
            $r.Lines[0] | Should -Match ('^\[wait\] waiting on the database {0} \(a session of several statements\) since ' -f [regex]::Escape($script:Db))
        } finally { $global:SI_WaitBeatEveryMs = $null }
    }
    It 'SUP-2026-00676: a session that throws: the error is the session''s own, and its beat stopped with it' {
        $global:SI_WaitBeatEveryMs = 150
        try {
            $real = { param($s, $d, $t) $c = New-Object System.Data.SqlClient.SqlConnection $script:Cs; $c.Open(); $c }
            $inv = New-SIDataSqlInvoke -Server 'srv' -Database $script:Db -TokenSeam { 't' } -Connect $real -StatementWaits @()
            { & $inv $null $null 'session' { param($Run) & $Run "WAITFOR DELAY '00:00:00.5'" 'none'; & $Run 'SELECT * FROM sidata.Nope' 'scalar' } } | Should -Throw '*Invalid object name*'
            $global:SI_WaitBeatLast.Stopped | Should -BeTrue
            $global:SI_WaitBeatLast.Beats | Should -BeGreaterOrEqual 2
        } finally { $global:SI_WaitBeatEveryMs = $null }
    }
}
