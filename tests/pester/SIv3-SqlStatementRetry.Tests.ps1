#Requires -Version 5.1
<#
    SecurityInsight -- A TEMPORARY AZURE SQL ANSWER IS RETRIED IN THE RUN, A QUERY DEFECT FAILS AT ONCE (live 2026-10-28: one
    statement of the data sync got 9001 + 3314 + "A severe error occurred on the current command" after minutes of a
    saturated log, the step was classified "unknown" and a 52-hour run failed).

    What must hold (offline: the data database seam New-SIDataSqlInvoke with a fake connection, no sign-in, no network):
      - the platform answers (9001, 3314, 40613, "a severe error", a reset connection, a broken pooled connection) are
        transient; a full database, a syntax error, a type clash and a permission are not;
      - a transient statement is run again on a NEW connection after the configured pauses (6 over about 9 minutes by
        default), and the log says so; a query defect fails on the first attempt with no pause;
      - past the last attempt the error is thrown tagged transient-sql;
      - a stream that has handed a row on is never read again (no row twice); one that failed before its first row is;
      - a session is run again whole (its steps rebuild their work on the new connection);
      - an open that failed is not retried again by the statement loop (the open has its own retry);
      - the data sync puts the tag on its run report, the settings database retries a broken open, and the pipeline
        runner says a wake-up that started nothing and met a temporary answer as a warning.
#>

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $script:SIRoot 'engine\_shared\SI-ErrorClass.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-SqlRetry.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataSql.ps1')

    function script:New-SqlError([string]$Message, [int[]]$Numbers = @()) {
        $e = [System.Exception]::new($Message)
        if ($Numbers.Count) { $e.Data['SISqlNumbers'] = $Numbers }
        $e
    }

    # a fake connection: -Plan is a list, one item per ATTEMPT (each connection takes the next): an exception is thrown by
    # the statement, anything else is its answer. -Rows: the reader's rows for 'stream' / 'reader' (with -ThrowAfter rows the read fails).
    function script:New-FakeDb {
        param([object[]]$Plan, [object[]]$Rows = @(), [int]$ThrowAfter = -1, $ReadError)
        $global:SIFakeDb = $st = @{ Connects = 0; Disposed = 0; Plan = $Plan; Rows = $Rows; ThrowAfter = $ThrowAfter; ReadError = $ReadError; Sql = New-Object System.Collections.Generic.List[string] }
        $connect = {
            param($Server, $Database, $Token)
            $global:SIFakeDb['Connects'] = [int]$global:SIFakeDb['Connects'] + 1
            $step = $global:SIFakeDb.Plan[[Math]::Min($global:SIFakeDb.Connects, $global:SIFakeDb.Plan.Count) - 1]; $do = { if ($step -is [System.Exception]) { throw $step }; $step }.GetNewClosure()
            $cmd = [pscustomobject]@{ CommandText = ''; CommandTimeout = 0; Parameters = ([pscustomobject]@{}) }
            $cmd.Parameters | Add-Member -MemberType ScriptMethod -Name AddWithValue -Value { param($n, $v) $null }
            $cmd | Add-Member -MemberType ScriptMethod -Name ExecuteScalar -Value { $global:SIFakeDb.Sql.Add($this.CommandText); & $do }.GetNewClosure()
            $cmd | Add-Member -MemberType ScriptMethod -Name ExecuteNonQuery -Value { $global:SIFakeDb.Sql.Add($this.CommandText); $null = & $do; 1 }.GetNewClosure()
            $cmd | Add-Member -MemberType ScriptMethod -Name ExecuteReader -Value {
                $global:SIFakeDb.Sql.Add($this.CommandText); $null = & $do
                $rd = [pscustomobject]@{ I = -1; FieldCount = 1 }
                $rd | Add-Member -MemberType ScriptMethod -Name Read -Value { $this.I++; if ($global:SIFakeDb.ThrowAfter -ge 0 -and $this.I -ge $global:SIFakeDb.ThrowAfter -and $global:SIFakeDb.Connects -eq 1) { throw $global:SIFakeDb.ReadError }; $this.I -lt $global:SIFakeDb.Rows.Count }.GetNewClosure()
                $rd | Add-Member -MemberType ScriptMethod -Name GetName -Value { param($i) 'V' }
                $rd | Add-Member -MemberType ScriptMethod -Name GetValue -Value { param($i) $global:SIFakeDb.Rows[$this.I] }.GetNewClosure()
                $rd | Add-Member -MemberType ScriptMethod -Name IsDBNull -Value { param($i) $false }
                $rd | Add-Member -MemberType ScriptMethod -Name Close -Value { }
                $rd
            }.GetNewClosure()
            $cn = [pscustomobject]@{}
            $cn | Add-Member -MemberType ScriptMethod -Name CreateCommand -Value { $cmd }.GetNewClosure()
            $cn | Add-Member -MemberType ScriptMethod -Name Dispose -Value { $global:SIFakeDb['Disposed'] = [int]$global:SIFakeDb['Disposed'] + 1 }.GetNewClosure()
            $cn
        }.GetNewClosure()
        $sleeps = New-Object System.Collections.Generic.List[int]
        $inv = New-SIDataSqlInvoke -Server 'srv.example.test' -Database 'sqldb-test' -TokenSeam { 'tok' } -Connect $connect -Sleep { param($s) $sleeps.Add([int]$s) }.GetNewClosure() -StatementWaits @(1, 2, 3)
        [pscustomobject]@{ Invoke = $inv; State = $st; Sleeps = $sleeps }
    }
}

Describe 'SIv3-SqlStatementRetry: which SQL failures are Azure SQL''s temporary answers' {
    It 'the platform answers are transient' {
        foreach ($n in 9001, 3314, 40613, 40501, 40197, 49918, 49919, 49920, 4060, 10928, 10929, 1205, 10054, 233) {
            Test-SISqlStatementTransient -ErrorRecord (New-SqlError 'x' @($n)) | Should -BeTrue -Because "SQL $n"
        }
        Test-SISqlStatementTransient -ErrorRecord (New-SqlError 'A severe error occurred on the current command.  The results, if any, should be discarded.') | Should -BeTrue
        Test-SISqlStatementTransient -ErrorRecord (New-SqlError 'The transaction log for database ''x'' is not available.' @(9001)) | Should -BeTrue
        Test-SISqlStatementTransient -ErrorRecord (New-SqlError 'Internal .NET Framework Data Provider error 6.') | Should -BeTrue
        Test-SISqlStatementTransient -ErrorRecord ([System.Exception]::new('outer', (New-SqlError 'inner' @(40613)))) | Should -BeTrue -Because 'an inner exception is read'
    }
    It 'a full database, a query defect and a permission are not' {
        Test-SISqlStatementTransient -ErrorRecord (New-SqlError 'Could not allocate space for object' @(1105)) | Should -BeFalse
        Test-SISqlStatementTransient -ErrorRecord (New-SqlError 'A severe error occurred on the current command.' @(40544)) | Should -BeFalse -Because 'a full database is never retried'
        Test-SISqlStatementTransient -ErrorRecord (New-SqlError 'Incorrect syntax near ''FROM''.' @(102)) | Should -BeFalse
        Test-SISqlStatementTransient -ErrorRecord (New-SqlError 'Operand type clash: int is incompatible with date' @(206)) | Should -BeFalse
        Test-SISqlStatementTransient -ErrorRecord (New-SqlError 'The SELECT permission was denied on the object' @(229)) | Should -BeFalse
        Test-SISqlStatementTransient -ErrorRecord $null | Should -BeFalse
    }
    It 'the default pauses are 6 attempts over about 9 minutes' {
        $w = @(Get-SISqlStatementRetryWaits)
        $w.Count | Should -Be 6
        ($w | Measure-Object -Sum).Sum | Should -Be 530
    }
}

Describe 'SIv3-SqlStatementRetry: the data database seam runs a statement again on a new connection' {
    It 'a transient statement is run again after the pauses and answers; one connection per attempt' {
        $db = New-FakeDb -Plan @((New-SqlError 'The transaction log for database is not available.' @(9001)), (New-SqlError 'A severe error occurred on the current command.' @(3314)), 42)
        & $db.Invoke 'SELECT 42' @{} 'scalar' | Should -Be 42
        $db.State.Connects | Should -Be 3
        $db.State.Disposed | Should -Be 3
        @($db.Sleeps) | Should -Be @(1, 2)
    }
    It 'a query defect fails on the first attempt, with no pause' {
        $db = New-FakeDb -Plan @((New-SqlError 'Incorrect syntax near ''FROM''.' @(102)), 1)
        { & $db.Invoke 'SELEC 1' @{} 'scalar' } | Should -Throw '*Incorrect syntax*'
        $db.State.Connects | Should -Be 1
        $db.Sleeps.Count | Should -Be 0
    }
    It 'past the last attempt the error is thrown tagged transient-sql' {
        $db = New-FakeDb -Plan @((New-SqlError 'A transport-level error has occurred.' @(10054)))
        $err = $null
        try { & $db.Invoke 'UPDATE x SET y = 1' @{} 'nonquery' } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Data['SIErrorClass'] | Should -Be 'transient-sql'
        $err.Exception.Message | Should -Match 'temporary Azure SQL error.*transient-sql'
        $db.State.Connects | Should -Be 4 -Because 'the first attempt and the 3 configured retries'
        @($db.Sleeps) | Should -Be @(1, 2, 3)
    }
    It 'a reader answers its rows as ONE array after a retry, as before' {
        $db = New-FakeDb -Plan @((New-SqlError 'x' @(40613)), $null) -Rows @('a', 'b')
        $got = & $db.Invoke 'SELECT V' @{} 'reader'
        @($got).Count | Should -Be 2
        @($got | ForEach-Object { $_['V'] }) | Should -Be @('a', 'b')
    }
    It 'a stream that failed before its first row is read again; every row reaches the callback once' {
        $db = New-FakeDb -Plan @((New-SqlError 'x' @(40613)), $null) -Rows @('a', 'b', 'c')
        $seen = New-Object System.Collections.Generic.List[string]
        $n = & $db.Invoke 'SELECT V' @{} 'stream' { param($Row) $seen.Add([string]$Row['V']) }.GetNewClosure()
        $n | Should -Be 3
        @($seen) | Should -Be @('a', 'b', 'c')
    }
    It 'a stream that has handed a row on is NOT read again (no row twice): thrown tagged transient-sql' {
        $db = New-FakeDb -Plan @($null) -Rows @('a', 'b', 'c') -ThrowAfter 2 -ReadError (New-SqlError 'A transport-level error has occurred.' @(10054))
        $seen = New-Object System.Collections.Generic.List[string]
        $err = $null
        try { $null = & $db.Invoke 'SELECT V' @{} 'stream' { param($Row) $seen.Add([string]$Row['V']) }.GetNewClosure() } catch { $err = $_ }
        $err.Exception.Data['SIErrorClass'] | Should -Be 'transient-sql'
        @($seen) | Should -Be @('a', 'b')
        $db.State.Connects | Should -Be 1
        $db.Sleeps.Count | Should -Be 0
    }
    It 'a session is run again whole on the new connection' {
        $db = New-FakeDb -Plan @((New-SqlError 'x' @(9001)), 7)
        $runs = New-Object System.Collections.Generic.List[int]
        $r = & $db.Invoke $null $null 'session' { param($Run) $runs.Add(1); & $Run 'SELECT 7' 'scalar' }.GetNewClosure()
        $r | Should -Be 7
        $runs.Count | Should -Be 2
    }
    It 'an open that failed is not run again by the statement loop (the open has its own retry)' {
        $tries = @{ N = 0 }
        $denied = New-SqlError 'The SELECT permission was denied' @(229)
        $connect = { param($Server, $Database, $Token) $tries['N'] = [int]$tries['N'] + 1; throw $denied }.GetNewClosure()
        $inv = New-SIDataSqlInvoke -Server 's' -Database 'd' -TokenSeam { 'tok' } -Connect $connect -Sleep { } -StatementWaits @(1, 2)
        { & $inv 'SELECT 1' @{} 'scalar' } | Should -Throw
        $tries.N | Should -Be 1
    }
}

Describe 'SIv3-SqlStatementRetry: the callers say it as the platform''s, not as a defect' {
    It 'the data sync puts the tag of the error on its run report (FailedStepErrorClass)' {
        $t = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\pro-data\Invoke-SIDataSync.ps1')
        $t | Should -Match "Data\.Contains\('SIErrorClass'\)"
        $t | Should -Match 'FailedStepErrorClass -NotePropertyValue \$tagClass'
        'transient-sql' | Should -BeIn @(Get-SIErrorClasses)
    }
    It 'the step''s log line carries the tag: the pipeline''s report of the step is class transient-sql, never unknown' {
        Get-SIErrorClass -Message 'the database sqldb-si-pro answered a temporary Azure SQL error (A severe error occurred on the current command.); it was tried 7 time(s) -- transient-sql' | Should -Be 'transient-sql'
        Get-SIErrorClass -Message 'the pipeline lock (acquire) could not be reached: Azure SQL answered a transient error 6 time(s) in about a minute (x) -- transient-sql; the next wake-up tries again' | Should -Be 'transient-sql'
        Get-SIErrorClass -Message 'Incorrect syntax near FROM' | Should -Not -Be 'transient-sql'
        Get-SIErrorFixKind -ErrorClass 'transient-sql' | Should -BeNullOrEmpty -Because 'nobody''s fix: never a product defect'
    }
    It 'the settings database retries a broken open on a new connection, its pool cleared' {
        $t = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\pro-settings\SI-ProSettings.ps1')
        $t | Should -Match '\$openTransient = \$\{function:Test-SISqlStatementTransient\}'
        $t | Should -Match 'ClearPool\(\$cn\)'
        $t | Should -Match '\$openWaits = @\(2, 5, 10, 20, 30\)'
    }
    It 'the pipeline runner says a wake-up that started nothing and met a temporary answer as a warning, exit 0' {
        $t = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1')
        $t | Should -Match '\$wake\.RunStarted = \$true'
        $t | Should -Match "if \(-not \`$wake\.RunStarted\)"
        $t | Should -Match "FailedStepErrorClass = 'transient-sql'"
    }
}
