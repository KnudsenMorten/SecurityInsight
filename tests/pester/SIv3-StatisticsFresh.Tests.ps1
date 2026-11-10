#Requires -Version 5.1
<#
    THE DATABASE'S STATISTICS KEPT FRESH BY THE PIPELINE, AND PAGES THAT NEVER WAIT FOR ONE (2026-11-05; owner: "Fix code +
    refresh now"; data quality and stability first, speed second).

    Found live (a ring-0 install, Azure SQL S2): the pages took one to two minutes. SI never refreshed statistics; a quarter of
    all statistics had more changes than rows; AUTO_UPDATE_STATISTICS_ASYNC was off, so the first page read after a run waited
    for a SYNCHRONOUS statistics update (20+ s for one statistic) and a page that hit its time limit cancelled it with it. Every
    scale measurement hid this: each one refreshes the statistics itself before it measures.

    STATIC: the schema makes sidata.StatisticsRefresh (gated, EXECUTE to public in the product's pattern) and the work procedure
    sidata.StatisticsRefreshTable (WITH EXECUTE AS SELF -- the identity that applied the schema; the updater may not make an
    EXECUTE AS OWNER module -- no grant, default sampling); the engine's grant list carries it; the
    pipeline runner calls the setting on every wake-up and the refresh at the end of a run, ONCE, only after the publish.
    THE DRIVER (fakes): never throws -- a failing database, a refused caller, a database one schema version behind, a statistic
    that cannot be updated are each said in plain words (no internal numbers) or not at all; table by table with the lock beaten.
    REAL SQL (the test VM's SQL Server Express): the setting off -> on, from the engine's own user; a stale statistic refreshed and
    not one row changed; a second pass finds nothing; a caller that is not a job identity is refused (nothing changed, nothing
    thrown); the procedures made by the UPDATER's least-privilege user (db_ddladmin) apply and refresh for the engine with the
    updater's rights (the database setting is then left as it is, said nowhere).
#>

BeforeDiscovery {
    try { $script:HasSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:HasSql = $false }
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataStatistics.ps1')
    . (Join-Path $script:SIRoot 'engine\_shared\SI-SchemaGate.ps1')
    $script:Schema = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql'))
    $script:Flow = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\flow\Invoke-SIJobFlowRun.ps1'))
    # a fake data database: -Answers is a list of rows handed out one per call (a scriptblock answers by itself)
    function script:New-StatsFake {
        param([object[]]$Answers)
        $st = [pscustomobject]@{ Calls = (New-Object System.Collections.Generic.List[object]); Answers = $Answers; Beats = 0 }
        $st | Add-Member -MemberType ScriptMethod -Name Invoke -Value {
            param($Sql, $Params, $Mode)
            $this.Calls.Add([pscustomobject]@{ Sql = $Sql; Params = $Params })
            $a = $this.Answers[[Math]::Min($this.Calls.Count, $this.Answers.Count) - 1]
            if ($a -is [scriptblock]) { return (& $a) }
            , @($a)
        }
        $st
    }
}

Describe 'STATIC: the schema, the grant and the runner' {
    It 'the schema stays additive and makes the gated refresh, granted to public in the product''s pattern' {
        (Test-SISchemaIsAdditive -Sql $script:Schema).IsAdditive | Should -BeTrue
        $script:Schema | Should -Match "EXEC \(N'CREATE OR ALTER PROCEDURE sidata\.StatisticsRefresh @After"
        $script:Schema | Should -Match "THROW 51793, N''only a job identity may refresh the statistics -- nothing was changed''"
        $script:Schema | Should -Match "IF IS_ROLEMEMBER\(N'db_owner'\) = 1 OR IS_ROLEMEMBER\(N'db_securityadmin'\) = 1\s+GRANT EXECUTE ON OBJECT::sidata\.StatisticsRefresh TO public;"
        . (Join-Path $script:SIRoot 'engine\pro-settings\SI-GrantProcedure.ps1')
        @(Get-SISchemaSecurityRows -SIRoot $script:SIRoot | Where-Object { $_.on -eq 'sidata.StatisticsRefresh' -and $_.permission -eq 'EXECUTE' -and $_.to -eq 'public' }).Count | Should -Be 1 -Because 'the signed grant procedure applies it on the signed path'
    }
    It 'the work procedure runs as its owner, has NO grant of its own, builds every name from the catalog and never reads a whole large table' {
        $m = [regex]::Match($script:Schema, "(?s)DECLARE @SIStatsProc nvarchar\(max\) = N'CREATE OR ALTER PROCEDURE sidata\.StatisticsRefreshTable .*?END';")
        $m.Success | Should -BeTrue
        $body = $m.Value
        # SELF = the identity that applied the schema (setup's admin, or the updater: db_ddladmin may not impersonate the owner,
        # live finding of this suite's first run -- "Cannot execute as the user 'dbo'"), never OWNER
        $body | Should -Match '(?m)^WITH EXECUTE AS SELF\r?$'
        $script:Schema | Should -Not -Match 'EXECUTE AS OWNER\r?\n'
        $body | Should -Match 'si-statistics-refresh v1'
        # made again when missing, older, or when the identity it runs as is gone -- the module guard never sees it (a variable)
        $script:Schema | Should -Match "(?s)IF OBJECT_ID\(N'sidata\.StatisticsRefreshTable'\) IS NULL\s+OR CHARINDEX\(N'si-statistics-refresh v1'.*?execute_as_principal_id.*?EXEC \(@SIStatsProc\);"
        $body | Should -Match ([regex]::Escape("SET @sql = N''UPDATE STATISTICS '' + @Table + N'' ('' + QUOTENAME(@name) + N'');'';")) -Because 'the table name is QUOTENAME''d from sys.tables, the statistic''s too'
        $body | Should -Match 'QUOTENAME\(SCHEMA_NAME\(t\.schema_id\)\) \+ N''''\.'''' \+ QUOTENAME\(t\.name\)'
        $body | Should -Not -Match '(?i)FULLSCAN|RESAMPLE|\bSAMPLE\b' -Because 'the database''s default sampling -- never a full scan of a large table'
        $body | Should -Match 'ALTER DATABASE CURRENT SET AUTO_UPDATE_STATISTICS_ASYNC ON'
        $body | Should -Match 'IF @@TRANCOUNT > 0' -Because 'a database setting cannot change inside a transaction, and no statistic is updated under a caller''s locks'
        $body | Should -Not -Match '(?i)\b(INSERT|DELETE|MERGE|TRUNCATE)\s+(?!@)\w*\.' -Because 'it changes no row (only its own table variables)'
        $script:Schema | Should -Not -Match '(?i)GRANT\s+\w+\s+ON\s+OBJECT::sidata\.StatisticsRefreshTable'
        # the threshold is the database's own for a stale statistic: 500 changes up to 500 rows, else the lower of 500 + 20 % and sqrt(1000 x rows)
        $body | Should -Match ([regex]::Escape('CASE WHEN ISNULL(sp.rows, 0) <= 500 THEN 500.0'))
        $body | Should -Match ([regex]::Escape('WHEN 500.0 + 0.2 * sp.rows < SQRT(1000.0 * sp.rows) THEN 500.0 + 0.2 * sp.rows'))
    }
    It 'the engine''s grant list carries EXECUTE on the refresh (and nothing on the work procedure)' {
        . (Join-Path $script:SIRoot 'engine\pro-settings\SI-EngineGrants.ps1')
        @($script:SIEngineObjectGrants | Where-Object { $_.Object -eq 'sidata.StatisticsRefresh' -and $_.Verbs -eq 'EXECUTE' }).Count | Should -Be 1
        @($script:SIEngineObjectGrants | Where-Object { $_.Object -eq 'sidata.StatisticsRefreshTable' }).Count | Should -Be 0
    }
    It 'the runner: the setting on every wake-up; the refresh ONCE after a run, in the wake-up''s upkeep after the publish and its copies, beaten; on schedules only after a publish' {
        $f = $script:Flow
        $f | Should -Match ([regex]::Escape(". (Join-Path `$siRoot 'engine/_shared/data-sql/SI-DataStatistics.ps1')"))
        $f | Should -Match ([regex]::Escape('if ($publishSql -and $statsOn) { $null = Invoke-SIDataStatisticsRefresh -Invoke $publishSql -AsyncOnly -Log $say }'))
        $flowEnd = $f.IndexOf('$pipeResult = Invoke-SIJobFlow @pArgs')
        $pub = $f.IndexOf('Invoke-SIDataPublishRun -Invoke $publishSql -State $pipeResult')
        $flowEnd | Should -BeGreaterThan 0
        $pub | Should -BeGreaterThan $flowEnd
        # live 2026-11-09/10: the run's end no longer refreshes anything (it held the report, the lock and the waiting update back)
        $endOfRun = $f.Substring($flowEnd)
        $endOfRun = $endOfRun.Substring(0, $endOfRun.IndexOf('Get-SIJobFlowSummary -State $pipeResult'))
        @([regex]::Matches($endOfRun, 'Invoke-SIDataStatisticsRefresh ')).Count | Should -Be 0 -Because 'the refresh is in the upkeep now'
        # Invardia 2026-11-05: ONE refresh after a run, only after the publish -- the upkeep runs it after the copies, beaten
        $f | Should -Match ([regex]::Escape("`$upkeepStats = { param(`$Beat) if (`$publishSql -and `$statsOn) { `$null = Invoke-SIDataStatisticsRefresh -Invoke `$publishSql -When 'after the run, once the pages moved to it' -Log `$say -Beat `$Beat } }"))
        $f | Should -Match ([regex]::Escape('-Stats ([bool]($publishSql -and $statsOn -and $schedPub -and $schedPub.Published))'))
    }
}

Describe 'THE DRIVER: table by table, never throws, plain words' {
    It 'every table with stale statistics, one call each (after the one before), the lock beaten between them, one INFO line' {
        $fake = New-StatsFake -Answers @(
            @{ Ready = $true; TableName = '[sidata].[Ci]'; Refreshed = 3; Failed = 0; Error = $null; Async = $true }
            @{ Ready = $true; TableName = '[sidata].[Finding]'; Refreshed = 9; Failed = 0; Error = $null; Async = $true }
            @{ Ready = $true; TableName = $null; Refreshed = 0; Failed = 0; Error = $null; Async = $true })
        $lines = New-Object System.Collections.Generic.List[string]; $beats = @{ N = 0 }
        $r = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) $fake.Invoke($s, $p, $m) }.GetNewClosure() -When 'at the end of the run' -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure() -Beat { $beats.N++ }.GetNewClosure()
        $r.Ready | Should -BeTrue; $r.Tables | Should -Be 2; $r.Refreshed | Should -Be 12; $r.Failed | Should -Be 0; $r.Stopped | Should -BeFalse
        $fake.Calls.Count | Should -Be 3
        $fake.Calls[0].Params.After | Should -Be ''
        $fake.Calls[1].Params.After | Should -Be '[sidata].[Ci]'
        $fake.Calls[2].Params.After | Should -Be '[sidata].[Finding]'
        @($fake.Calls | ForEach-Object { $_.Params.AsyncOnly }) | Should -Be @('0', '0', '0')
        $beats.N | Should -Be 2
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match "^INFO the database's statistics refreshed at the end of the run: 12 statistic\(s\) of 2 table\(s\) in \d+ s$"
    }
    It '#1129 a long refresh says where it is: at most one line a minute while it goes on (live: 10.5 minutes without a line)' {
        $fake = New-StatsFake -Answers @(
            @{ Ready = $true; TableName = '[sidata].[Ci]'; Refreshed = 3; Failed = 0; Error = $null; Async = $true }
            @{ Ready = $true; TableName = '[sidata].[Finding]'; Refreshed = 9; Failed = 0; Error = $null; Async = $true }
            @{ Ready = $true; TableName = $null; Refreshed = 0; Failed = 0; Error = $null; Async = $true })
        $lines = New-Object System.Collections.Generic.List[string]
        $null = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) $fake.Invoke($s, $p, $m) }.GetNewClosure() -When 'at the end of the run' -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure() -ProgressSeconds 0
        $lines.Count | Should -Be 3
        $lines[0] | Should -Match "^INFO the database's statistics at the end of the run: 1 table\(s\) refreshed so far \(the newest \[sidata\]\.\[Ci\]\), \d+ s$"
        $lines[1] | Should -Match 'so far \(the newest \[sidata\]\.\[Finding\]\)'
        $lines[2] | Should -Match '^INFO the database''s statistics refreshed at the end of the run: 12 statistic'
    }
    It 'nothing stale: nothing said' {
        $fake = New-StatsFake -Answers @(@{ Ready = $true; TableName = $null; Refreshed = 0; Failed = 0; Error = $null; Async = $true })
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) $fake.Invoke($s, $p, $m) }.GetNewClosure() -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r.Tables | Should -Be 0; $lines.Count | Should -Be 0
    }
    It 'a database one schema version behind (no procedure yet): nothing done, nothing said' {
        $fake = New-StatsFake -Answers @(@{ Ready = $false })
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) $fake.Invoke($s, $p, $m) }.GetNewClosure() -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r.Ready | Should -BeFalse; $r.Stopped | Should -BeFalse; $lines.Count | Should -Be 0; $fake.Calls.Count | Should -Be 1
    }
    It 'a REFRESH ERROR NEVER FAILS THE STEP OR THE RUN: a database that throws is one plain warning, no exception' {
        $lines = New-Object System.Collections.Generic.List[string]
        # called directly (no Should -Not -Throw block): an exception fails this test by itself
        $log = { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $script:R = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) throw 'Login failed for user ''<token-identified principal>''.' } -When 'at the end of the run' -Log $log
        $script:R.Stopped | Should -BeTrue; $script:R.Ready | Should -BeFalse
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match "^WARN the database's statistics were not refreshed at the end of the run \(Login failed.*\) -- the pages may be slower until the next run; the data is not affected$"
        $lines[0] | Should -Not -Match '#\d' -Because 'no internal numbers in what a customer reads'
    }
    It 'a connection lost half way: what was done is kept, one warning says the rest waits for the next run' {
        $fake = New-StatsFake -Answers @(@{ Ready = $true; TableName = '[sidata].[Ci]'; Refreshed = 2; Failed = 0; Error = $null; Async = $true }, { throw 'A transport-level error has occurred' })
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) $fake.Invoke($s, $p, $m) }.GetNewClosure() -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r.Stopped | Should -BeTrue; $r.Tables | Should -Be 1; $r.Refreshed | Should -Be 2
        @($lines | Where-Object { $_ -like 'WARN *refreshed only in part*transport-level*the data is not affected' }).Count | Should -Be 1
    }
    It 'a statistic that cannot be updated is counted and named; the others go on' {
        $fake = New-StatsFake -Answers @(
            @{ Ready = $true; TableName = '[sidata].[Ci]'; Refreshed = 1; Failed = 1; Error = '[sidata].[Ci] [IX_Ci_X]: Lock request time out period exceeded.'; Async = $true }
            @{ Ready = $true; TableName = '[sidata].[Finding]'; Refreshed = 4; Failed = 0; Error = $null; Async = $true }
            @{ Ready = $true; TableName = $null; Refreshed = 0; Failed = 0; Error = $null; Async = $true })
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) $fake.Invoke($s, $p, $m) }.GetNewClosure() -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r.Tables | Should -Be 2; $r.Refreshed | Should -Be 5; $r.Failed | Should -Be 1
        @($lines | Where-Object { $_ -like 'WARN 1 statistic(s) could not be refreshed*IX_Ci_X*the data is not affected' }).Count | Should -Be 1
    }
    It 'the setting that cannot be changed (a procedure made by the updater): kept in the answer, said nowhere; the wake-up''s check (-AsyncOnly) is one call' {
        $off = @{ Ready = $true; TableName = $null; Refreshed = 0; Failed = 0; Error = $null; Async = $false }
        $lines = New-Object System.Collections.Generic.List[string]
        $fake = New-StatsFake -Answers @($off)
        $r = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) $fake.Invoke($s, $p, $m) }.GetNewClosure() -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r.AsyncOff | Should -BeTrue
        $lines.Count | Should -Be 0
        # a statistic's own failure on the same call is named by ITS error
        $fake3 = New-StatsFake -Answers @(@{ Ready = $true; TableName = '[sidata].[Ci]'; Refreshed = 0; Failed = 1; Error = '[sidata].[Ci] [IX_Ci_X]: boom'; Async = $false }, $off)
        $r3 = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) $fake3.Invoke($s, $p, $m) }.GetNewClosure() -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r3.FailedError | Should -Be '[sidata].[Ci] [IX_Ci_X]: boom'
        $lines.Clear()
        $fake2 = New-StatsFake -Answers @($off)
        $r2 = Invoke-SIDataStatisticsRefresh -Invoke { param($s, $p, $m) $fake2.Invoke($s, $p, $m) }.GetNewClosure() -AsyncOnly -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $fake2.Calls.Count | Should -Be 1
        $fake2.Calls[0].Params.AsyncOnly | Should -Be '1'
        $r2.AsyncOff | Should -BeTrue
        $lines.Count | Should -Be 0
        { Invoke-SIDataStatisticsRefresh -Invoke { throw 'x' } -AsyncOnly -Log { param($l, $m) throw 'the log must not be reached' } } | Should -Not -Throw
    }
    It 'no database: nothing done' {
        (Invoke-SIDataStatisticsRefresh -Invoke $null).Ready | Should -BeFalse
    }
}

Describe 'REAL SQL: the setting, a stale statistic, no row changed, the gate, the updater''s procedures (local SQL Server Express)' -Skip:(-not $script:HasSql) {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\pro-settings\SI-ProSchema.ps1')
        $script:DbName = 'si_test_stats_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$script:DbName]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$script:DbName;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
        $script:Cn.Open()
        $script:Admin = {
            param($Sql, $Params, $Mode)
            $c = $script:Cn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 600
            if ($Params) { foreach ($k in $Params.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $Params[$k]) { [System.DBNull]::Value } else { $Params[$k] })) } }
            switch ($Mode) {
                { $_ -in 'reader', 'rows' } {
                    $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                    try { do { if ($rd.FieldCount -gt 0) { $out = New-Object System.Collections.Generic.List[object]; while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $out.Add($h) } } } while ($rd.NextResult()) } finally { $rd.Close() }
                    , $out.ToArray()
                }
                'scalar' { $c.ExecuteScalar() }
                default { [void]$c.ExecuteNonQuery() }
            }
        }
        $script:AsUser = {
            param([string]$User, $Sql, $Params, $Mode)
            & $script:Admin ("EXECUTE AS USER = N'{0}';" -f $User) @{} 'nonquery'
            try { & $script:Admin $Sql $Params $Mode } finally { & $script:Admin 'REVERT;' @{} 'nonquery' }
        }
        $a = Invoke-SIProSchemaApply -SIRoot $script:SIRoot -Invoke $script:Admin -Log { }
        if ($a.Action -ne 'applied') { throw "the schema was not applied: $($a.Reason)" }
        # nothing refreshes a statistic behind the test's back
        & $script:Admin "ALTER DATABASE [$script:DbName] SET AUTO_UPDATE_STATISTICS OFF;" @{} 'nonquery'
        # the ENGINE's user before its cut-over (db_datareader + db_datawriter: no ALTER on any table, none on the database),
        # and a READER (not a job identity)
        & $script:Admin 'CREATE USER si_eng WITHOUT LOGIN; CREATE USER si_rd WITHOUT LOGIN;' @{} 'nonquery'
        foreach ($r in 'db_datareader', 'db_datawriter') { & $script:Admin "ALTER ROLE [$r] ADD MEMBER [si_eng];" @{} 'nonquery' }
        & $script:Admin 'ALTER ROLE [db_datareader] ADD MEMBER [si_rd];' @{} 'nonquery'
        $script:AsEngine = { param($Sql, $Params, $Mode) & $script:AsUser 'si_eng' $Sql $Params $Mode }
        $script:AsReader = { param($Sql, $Params, $Mode) & $script:AsUser 'si_rd' $Sql $Params $Mode }
        # a collection and its findings; the statistics of the findings table computed on the first 1,000 rows, then 5,000 more
        & $script:Admin "INSERT sidata.Collection (CollectionTime, Kind, RunId, [Rows], Status, LoadedAt) VALUES (SYSUTCDATETIME(), N'Detailed', N'run-stats', 0, N'Complete', SYSUTCDATETIME());" @{} 'nonquery'
        $script:Rows = {
            param([int]$N)
            & $script:Admin @"
INSERT sidata.Finding (CollectionId, AssetKey, ConfigurationId, Title, RiskScore)
SELECT (SELECT MAX(CollectionId) FROM sidata.Collection), N'dev-' + CONVERT(nvarchar(10), v.n % 300), N'CVE-2026-' + CONVERT(nvarchar(10), v.n % 900), N'title ' + CONVERT(nvarchar(10), v.n), v.n % 10
FROM (SELECT TOP ($N) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS n FROM sys.all_columns AS a CROSS JOIN sys.all_columns AS b) AS v;
"@ @{} 'nonquery'
        }
        & $script:Rows 1000
        & $script:Admin 'UPDATE STATISTICS sidata.Finding WITH FULLSCAN;' @{} 'nonquery'
        & $script:Rows 5000
        $script:StaleSql = @"
SELECT s.name AS Name, sp.rows AS [Rows], sp.modification_counter AS Mods, sp.last_updated AS Updated
FROM sys.stats AS s CROSS APPLY sys.dm_db_stats_properties(s.object_id, s.stats_id) AS sp
WHERE s.object_id = OBJECT_ID(N'sidata.Finding') AND s.name = N'PK_Finding'
"@
        $script:Digest = "SELECT CONVERT(nvarchar(40), COUNT_BIG(*)) + N'/' + CONVERT(nvarchar(20), CHECKSUM_AGG(BINARY_CHECKSUM(*))) FROM sidata.Finding"
    }
    AfterAll {
        if ($script:Cn) { try { $script:Cn.Dispose() } catch { } }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$script:DbName] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:DbName]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    It 'the engine''s user holds no ALTER on the findings table and none on the database (the refresh needs no right it does not have)' {
        [int](& $script:AsEngine "SELECT HAS_PERMS_BY_NAME(N'sidata.Finding', N'OBJECT', N'ALTER')" @{} 'scalar') | Should -Be 0
        [int](& $script:AsEngine "SELECT HAS_PERMS_BY_NAME(DB_NAME(), N'DATABASE', N'ALTER')" @{} 'scalar') | Should -Be 0
        [int](& $script:AsEngine "SELECT HAS_PERMS_BY_NAME(N'sidata.StatisticsRefreshTable', N'OBJECT', N'EXECUTE')" @{} 'scalar') | Should -Be 0 -Because 'the work procedure is reached only through the gated one'
    }
    It 'THE SETTING: off -> the wake-up''s check, as the engine''s own user, turns it on; already on = nothing to do' {
        & $script:Admin "ALTER DATABASE [$script:DbName] SET AUTO_UPDATE_STATISTICS_ASYNC OFF;" @{} 'nonquery'
        [int](& $script:Admin 'SELECT CONVERT(int, is_auto_update_stats_async_on) FROM sys.databases WHERE database_id = DB_ID()' @{} 'scalar') | Should -Be 0
        $r = Invoke-SIDataStatisticsRefresh -Invoke $script:AsEngine -AsyncOnly
        $r.Stopped | Should -BeFalse -Because $r.Error
        $r.Ready | Should -BeTrue
        $r.AsyncOff | Should -BeFalse -Because $r.AsyncError
        [int](& $script:Admin 'SELECT CONVERT(int, is_auto_update_stats_async_on) FROM sys.databases WHERE database_id = DB_ID()' @{} 'scalar') | Should -Be 1
        (Invoke-SIDataStatisticsRefresh -Invoke $script:AsEngine -AsyncOnly).AsyncOff | Should -BeFalse
        # the wake-up's check refreshes no statistic
        $s = @(& $script:Admin $script:StaleSql @{} 'rows' | ForEach-Object { $_ })[0]
        [long]$s['Mods'] | Should -BeGreaterThan 700 -Because 'still stale: 5,000 changes on 1,000 rows'
    }
    It 'A STALE STATISTIC is refreshed by the engine''s own user (sampled by default) -- and NOT ONE ROW changes' {
        $before = @(& $script:Admin $script:StaleSql @{} 'rows' | ForEach-Object { $_ })[0]
        [long]$before['Rows'] | Should -Be 1000
        [long]$before['Mods'] | Should -BeGreaterThan 700
        $digest = [string](& $script:Admin $script:Digest @{} 'scalar')
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataStatisticsRefresh -Invoke $script:AsEngine -When 'at the end of the run' -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r.Stopped | Should -BeFalse -Because $r.Error
        $r.Failed | Should -Be 0 -Because $r.FailedError
        $r.Tables | Should -BeGreaterOrEqual 1
        $r.Refreshed | Should -BeGreaterOrEqual 1
        @($lines | Where-Object { $_ -like "INFO the database's statistics refreshed at the end of the run: *" }).Count | Should -Be 1
        $after = @(& $script:Admin $script:StaleSql @{} 'rows' | ForEach-Object { $_ })[0]
        [long]$after['Rows'] | Should -Be 6000
        [long]$after['Mods'] | Should -Be 0
        ([datetime]$after['Updated']) | Should -BeGreaterOrEqual ([datetime]$before['Updated'])
        [string](& $script:Admin $script:Digest @{} 'scalar') | Should -Be $digest -Because 'a statistics refresh changes no row'
        [int](& $script:Admin 'SELECT COUNT(*) FROM sidata.Collection' @{} 'scalar') | Should -Be 1
    }
    It 'a second pass finds nothing stale on that table (the database''s own threshold): nothing refreshed there, nothing said about it' {
        $r = Invoke-SIDataStatisticsRefresh -Invoke $script:AsEngine
        $r.Stopped | Should -BeFalse -Because $r.Error
        $s = @(& $script:Admin $script:StaleSql @{} 'rows' | ForEach-Object { $_ })[0]
        [long]$s['Mods'] | Should -Be 0
        $again = Invoke-SIDataStatisticsRefresh -Invoke $script:AsEngine
        $again.Tables | Should -Be 0 -Because ('every statistic is fresh now; still stale by the procedure: {0}' -f (@($again.Names) -join ', '))
    }
    It 'a caller that is NOT a job identity is refused: nothing changed, one warning, nothing thrown' {
        & $script:Rows 8000
        $lines = New-Object System.Collections.Generic.List[string]
        $log = { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $script:Rd = Invoke-SIDataStatisticsRefresh -Invoke $script:AsReader -When 'at the end of the run' -Log $log
        $script:Rd.Ready | Should -BeFalse
        @($lines | Where-Object { $_ -like 'WARN *only a job identity may refresh the statistics*' }).Count | Should -Be 1
        $s = @(& $script:Admin $script:StaleSql @{} 'rows' | ForEach-Object { $_ })[0]
        [long]$s['Mods'] | Should -BeGreaterThan 0 -Because 'the refused call refreshed nothing'
    }
    It 'THE UPDATER makes the procedures (db_ddladmin, no ALTER on the database): its schema applies, and the engine''s refresh runs with the updater''s rights -- the setting is left as it is, said nowhere' {
        & $script:Admin 'CREATE USER si_upd WITHOUT LOGIN;' @{} 'nonquery'
        foreach ($r in 'db_datareader', 'db_datawriter', 'db_ddladmin') { & $script:Admin "ALTER ROLE [$r] ADD MEMBER [si_upd];" @{} 'nonquery' }
        & $script:Admin 'DROP PROCEDURE sidata.StatisticsRefresh; DROP PROCEDURE sidata.StatisticsRefreshTable;' @{} 'nonquery'
        $asUpd = { param($Sql, $Params, $Mode) & $script:AsUser 'si_upd' $Sql $Params $Mode }
        $a = Invoke-SIProSchemaApply -SIRoot $script:SIRoot -Invoke $asUpd -Names data -Log { }
        $a.Action | Should -Be 'applied' -Because $a.Reason
        [int](& $script:Admin "SELECT CASE WHEN OBJECT_ID(N'sidata.StatisticsRefreshTable') IS NULL THEN 0 ELSE 1 END" @{} 'scalar') | Should -Be 1
        & $script:Admin 'GRANT EXECUTE ON OBJECT::sidata.StatisticsRefresh TO public;' @{} 'nonquery'   # the admin's grant (the updater's grant step / signed procedure in a real update)
        & $script:Admin "ALTER DATABASE [$script:DbName] SET AUTO_UPDATE_STATISTICS_ASYNC OFF;" @{} 'nonquery'
        [string](& $script:Admin "SELECT p.name FROM sys.sql_modules AS m JOIN sys.database_principals AS p ON p.principal_id = m.execute_as_principal_id WHERE m.object_id = OBJECT_ID(N'sidata.StatisticsRefreshTable')" @{} 'scalar') | Should -Be 'si_upd'
        # a second apply as the updater leaves it as it is (current marker, its identity there)
        (Invoke-SIProSchemaApply -SIRoot $script:SIRoot -Invoke $asUpd -Names data -Log { }).Action | Should -Be 'applied'
        $digest = [string](& $script:Admin $script:Digest @{} 'scalar')
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataStatisticsRefresh -Invoke $script:AsEngine -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r.Stopped | Should -BeFalse -Because $r.Error
        $r.Failed | Should -Be 0 -Because $r.FailedError
        $r.AsyncOff | Should -BeTrue -Because 'the updater may not change the database'
        @($lines | Where-Object { $_ -like 'WARN*' }).Count | Should -Be 0
        $s = @(& $script:Admin $script:StaleSql @{} 'rows' | ForEach-Object { $_ })[0]
        [long]$s['Mods'] | Should -Be 0
        [string](& $script:Admin $script:Digest @{} 'scalar') | Should -Be $digest
    }
    It '#1164 THE IDENTITY MOVE: the procedure is made again as the NEW updater user (read back), and only then the old user drops' {
        . (Join-Path $script:SIRoot 'setup\_shared\SI-IdentityMoveSql.ps1')
        & $script:Admin 'CREATE USER si_upd_new WITHOUT LOGIN;' @{} 'nonquery'
        foreach ($r in 'db_datareader', 'db_datawriter', 'db_ddladmin') { & $script:Admin "ALTER ROLE [$r] ADD MEMBER [si_upd_new];" @{} 'nonquery' }
        & $script:Admin 'GRANT VIEW DEFINITION ON OBJECT::sidata.StatisticsRefreshTable TO si_rd;' @{} 'nonquery'   # a permission that must survive
        { & $script:Admin 'DROP USER si_upd;' @{} 'nonquery' } | Should -Throw '*execution context*' -Because 'the live defect, reproduced'
        $sid = { param($u) [string](& $script:Admin "SELECT CONVERT(varchar(200), sid, 1) FROM sys.database_principals WHERE name = N'$u'" @{} 'scalar') }
        $rows = @(& $script:Admin (Get-SIIdentityMoveSqlModuleSql -OldSid (& $sid 'si_upd') -NewSid (& $sid 'si_upd_new')) @{} 'rows' | ForEach-Object { $_ })
        $m = Resolve-SIIdentityMoveSqlModules -Rows $rows
        $m.Clear | Should -BeTrue -Because (@($m.Kept) -join ' | ')
        ($m.Moved -join ' ') | Should -Match 'StatisticsRefreshTable\]: it now runs as si_upd_new'
        [string](& $script:Admin "SELECT p.name FROM sys.sql_modules AS m JOIN sys.database_principals AS p ON p.principal_id = m.execute_as_principal_id WHERE m.object_id = OBJECT_ID(N'sidata.StatisticsRefreshTable')" @{} 'scalar') | Should -Be 'si_upd_new'
        [int](& $script:Admin "SELECT COUNT(*) FROM sys.database_permissions WHERE major_id = OBJECT_ID(N'sidata.StatisticsRefreshTable') AND grantee_principal_id = USER_ID(N'si_rd') AND permission_name = N'VIEW DEFINITION'" @{} 'scalar') | Should -Be 1
        [int](& $script:Admin "SELECT CHARINDEX(N'si-statistics-refresh v1', OBJECT_DEFINITION(OBJECT_ID(N'sidata.StatisticsRefreshTable')))" @{} 'scalar') | Should -BeGreaterThan 0
        & $script:Admin 'DROP USER si_upd;' @{} 'nonquery'
        [int](& $script:Admin "SELECT COUNT(*) FROM sys.database_principals WHERE name = N'si_upd'" @{} 'scalar') | Should -Be 0
        # the refresh still runs, with the new user's rights
        $r = Invoke-SIDataStatisticsRefresh -Invoke $script:AsEngine
        $r.Stopped | Should -BeFalse -Because $r.Error
    }
}
