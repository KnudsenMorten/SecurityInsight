#Requires -Version 5.1
<#
    COLUMNSTORE x PARTITIONS (REQUIREMENTS #1316 x #1317, SCALE-2 #1314; 2026-11-23). Both features are ON by default and meet on
    sidata.Finding: #1316 builds NCCI_Finding_Load, #1317 moves the table onto PS_SICollection and empties a retired
    collection's partition by TRUNCATE ... WITH (PARTITIONS), which needs every index ALIGNED. ONE rule
    (engine\_shared\SI-IndexBuild.ps1 "COLUMNSTORE x PARTITIONS"):
      1. ORDER: while sidata.Finding's move is pending (switch on, not on the scheme yet, not blocked) NCCI_Finding_Load waits --
         the runner never starts the job for it, the job does not build it, the update says so in one line; once the table
         is on the scheme it is built ALIGNED (ON PS_SICollection ([CollectionId])). NCCI_CiFindingState_Load is never held.
      2. AN INDEX BUILT BEFORE on the old table: the move drops it right before its copy (only an index -- no result changes,
         the row-store indexes stay), sets its row back to 'waiting', and the job builds it aligned after the swap. Never
         blocked, never a run held.
      3. TRUNCATE ... WITH (PARTITIONS) works with the aligned columnstore index present; reads through it answer the same rows.
    Offline (pure functions + fakes) plus runs against the test SQL Server (tests\pester\_SITestSql.ps1). Pro path.
#>

BeforeDiscovery {
    $script:LocalSql = $false
    try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
}

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-KqlError.ps1')
    . (Join-Path $script:Root 'engine\_shared\SI-SchemaGate.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataModel.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
    . (Join-Path $script:Root 'engine\_shared\SI-IndexBuild.ps1')
    . (Join-Path $script:Root 'engine\index-build\SI-IndexBuildJob.ps1')
    . (Join-Path $script:Root 'engine\pro-settings\SI-ProPartitionMove.ps1')
    $script:Schema = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'sql\si-data-schema.sql')
    $script:Runner = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'engine\flow\Invoke-SIJobFlowRun.ps1')
    $script:Cs = Get-SIColumnstoreContract
    $script:Fi = @($script:Cs.Indexes | Where-Object { $_.Name -eq 'NCCI_Finding_Load' })[0]
    $script:Ci = @($script:Cs.Indexes | Where-Object { $_.Name -eq 'NCCI_CiFindingState_Load' })[0]
    $script:Now = [datetime]'2026-11-23T12:00:00Z'
    $script:Quiet = { param($l, $m) }
    function script:St([bool]$OnScheme = $false, [string]$Move = '', [bool]$MoveTable = $true, [bool]$Scheme = $true) {
        [pscustomobject]@{ Live = $true; OnScheme = $OnScheme; Scheme = $Scheme; MoveTable = $MoveTable; MoveState = $Move }
    }

    # ---- the real SQL Server (the same helpers as SIv3-CollectionPartitions) ----
    function script:New-LocalInvoke([string]$Db, [string]$AsUser = '') {
        $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True" + $(if ($AsUser) { ';Pooling=False' } else { '' })
        $pre = if ($AsUser) { "EXECUTE AS USER = N'$AsUser';`n" } else { '' }
        {
            param([string]$sql, $p, [string]$mode)
            $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
            try {
                $c = $cn.CreateCommand(); $c.CommandTimeout = 600; $c.CommandText = $pre + $sql
                if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                while ($r.Read()) { $h = @{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add($h) }
                $r.Close(); return , $rows.ToArray()
            } finally { $cn.Close() }
        }.GetNewClosure()
    }
    # the release's schema (-Unpartitioned: the large tables as an install made before the partitions has them), cfg.IndexBuild
    # exactly as the settings schema makes it, the UPDATER's roles (what the index build job runs as) and a reader with the
    # engine's data rights (what the pipeline runner's wake-up reads with)
    function script:New-TestDb([string]$Prefix, [switch]$Unpartitioned) {
        $db = $Prefix + [guid]::NewGuid().ToString('N').Substring(0, 8)
        [void](& (New-LocalInvoke 'master') "CREATE DATABASE [$db]" @{} 'nonquery')
        $inv = New-LocalInvoke $db
        $sql = $script:Schema
        if ($Unpartitioned) { $sql = $sql.Replace(') ON PS_SICollection (CollectionId);', ');') }
        [void](& $inv $sql @{} 'nonquery')
        [void](& $inv "IF SCHEMA_ID(N'cfg') IS NULL EXEC (N'CREATE SCHEMA cfg');" @{} 'nonquery')
        $pro = Get-Content -Raw (Join-Path $script:Root 'sql\si-pro-settings.sql')
        $mx = [regex]::Match($pro, "(?s)IF OBJECT_ID\('cfg\.IndexBuild'\) IS NULL\s*CREATE TABLE cfg\.IndexBuild \(.*?\n\);")
        if (-not $mx.Success) { throw 'cfg.IndexBuild not found in si-pro-settings.sql' }
        [void](& $inv $mx.Value @{} 'nonquery')
        [void](& $inv "CREATE USER si_test_updater WITHOUT LOGIN; ALTER ROLE db_ddladmin ADD MEMBER si_test_updater; ALTER ROLE db_datareader ADD MEMBER si_test_updater; ALTER ROLE db_datawriter ADD MEMBER si_test_updater;" @{} 'nonquery')
        [void](& $inv "CREATE USER si_test_engine WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER si_test_engine;" @{} 'nonquery')
        $ed = [string](& $inv "SELECT CONVERT(nvarchar(10), SERVERPROPERTY('EngineEdition'))" @{} 'scalar')
        [pscustomobject]@{ Name = $db; Invoke = $inv; Updater = (New-LocalInvoke $db 'si_test_updater'); Engine = (New-LocalInvoke $db 'si_test_engine'); Online = ($ed -in @('3', '5', '8')) }
    }
    function script:Remove-TestDb([string]$Db) { [System.Data.SqlClient.SqlConnection]::ClearAllPools(); try { [void](& (New-LocalInvoke 'master') "ALTER DATABASE [$Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$Db]" @{} 'nonquery') } catch { } }
    function script:Add-Collection($Inv, [string]$Time, [int]$Rows) {
        $cid = [int](@(& $Inv (Get-SIDataNewCollectionSql) @{ CollectionTime = $Time; Kind = 'Detailed'; RunId = ''; SolutionVersion = '3.0.test' } 'scalar') | Select-Object -Last 1)
        & $Inv @"
SET NOCOUNT ON;
DECLARE @c int = $cid;
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, Severity, Tier, RiskScore, Cve, Title, DetailJson)
SELECT TOP ($Rows) @c, CONCAT(N'a', n.i % 17), CONCAT(N'srv-', n.i % 17), N'R', CASE n.i % 3 WHEN 0 THEN N'High' WHEN 1 THEN N'Medium' ELSE N'Low' END, n.i % 3, n.i * 1.5,
       CONCAT(N'CVE-2026-', n.i % 11), CONCAT(N'T', n.i % 7), CONCAT(N'{"i":', n.i, N'}')
FROM (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS i FROM sys.all_objects AS a CROSS JOIN sys.all_objects AS b) AS n;
INSERT sidata.Recommendation (CollectionId, AssetKey, RecommendationId, Name, Severity, Tier)
SELECT TOP ($Rows) @c, CONCAT(N'a', n.i), CONCAT(N'rec', n.i), N'n', N'High', 1
FROM (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS i FROM sys.all_objects AS a CROSS JOIN sys.all_objects AS b) AS n;
INSERT sidata.IssueContext (CollectionId, IssueKey, Findings, Assets, AssetNamesShown)
SELECT TOP ($Rows) @c, CONCAT(N'CVE-', n.i), 1, 1, 1
FROM (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS i FROM sys.all_objects AS a CROSS JOIN sys.all_objects AS b) AS n;
UPDATE sidata.Collection SET Status = N'Complete', [Rows] = $Rows WHERE CollectionId = @c;
"@ @{} 'nonquery' | Out-Null
        $cid
    }
    function script:Count($Inv, [string]$Sql) { [long](& $Inv $Sql @{} 'scalar') }
    function script:Rows3($Inv, [int]$C) { '{0}/{1}/{2}' -f (Count $Inv "SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = $C"), (Count $Inv "SELECT COUNT(*) FROM sidata.Recommendation WHERE CollectionId = $C"), (Count $Inv "SELECT COUNT(*) FROM sidata.IssueContext WHERE CollectionId = $C") }
    function script:Mark($Inv, [int]$C) { [void](& $Inv ("UPDATE sidata.Collection SET RetiredAt = DATEADD(minute, -5, SYSUTCDATETIME()), RetiredWhy = N'superseded' WHERE CollectionId = {0}" -f $C) @{} 'nonquery') }
    function script:Partitioned($Inv, [string]$Table) { (Count $Inv ("SELECT COUNT(*) FROM sys.indexes AS i JOIN sys.partition_schemes AS s ON s.data_space_id = i.data_space_id WHERE s.name = N'PS_SICollection' AND i.object_id = OBJECT_ID(N'sidata.{0}') AND i.index_id IN (0, 1)" -f $Table)) -eq 1 }
    # where NCCI_Finding_Load is: 'none' | 'aligned' (on PS_SICollection) | 'unaligned'
    function script:NcciAt($Inv, [string]$Table = 'Finding', [string]$Name = 'NCCI_Finding_Load') {
        [string](& $Inv ("SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM sys.indexes WHERE object_id = OBJECT_ID(N'sidata.{0}') AND name = N'{1}' AND type = 6) THEN N'none' WHEN EXISTS (SELECT 1 FROM sys.indexes AS i JOIN sys.partition_schemes AS s ON s.data_space_id = i.data_space_id WHERE s.name = N'PS_SICollection' AND i.object_id = OBJECT_ID(N'sidata.{0}') AND i.name = N'{1}') THEN N'aligned' ELSE N'unaligned' END" -f $Table, $Name) @{} 'scalar')
    }
    function script:RowStore($Inv) { @(& $Inv "SELECT name FROM sys.indexes WHERE object_id = OBJECT_ID(N'sidata.Finding') AND type IN (1, 2) ORDER BY name" @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { [string]$_['name'] }) -join ',' }
    # ONE run of the index build job against the database, as the UPDATER's identity: real rows, saves, read-backs and partition
    # state; the lock / update seams answer "go"; the build runs its statement (ONLINE dropped where the edition has none)
    function script:Invoke-RealJob($D, [string]$Index, [bool]$Switch = $true) {
        $lg = New-Object System.Collections.Generic.List[string]
        $built = New-Object System.Collections.Generic.List[string]
        $upd = $D.Updater; $online = $D.Online
        $seams = @{
            UpdateFirst = { '' }; OtherRunning = { '' }
            Gate = { param($h) [pscustomobject]@{ Go = $true; Reason = 'ok'; LockTaken = $false } }
            Beat = { param($h, $what) $true }; ExitGate = { param($h) }
            Build = { param($sql, $interrupt, $onInterrupt) $built.Add($sql); $s = if ($online) { $sql } else { $sql.Replace(' WITH (ONLINE = ON)', '') }; [void](& $upd $s @{} 'nonquery'); 1.0 }.GetNewClosure()
            Rate = { param($t, $secs) }
            ColumnstoreSetting = { [pscustomobject]@{ Known = $true; On = $true } }
        }
        $tbl = if ($Index -eq 'NCCI_Finding_Load') { 'sidata.Finding' } else { 'sidata.CiFindingState' }
        $r = Invoke-SIIndexBuildJob -Store ([pscustomobject]@{ Invoke = $upd }) -Holder 'caj-si-index-build:test' -Seams $seams -Log { param($m) $lg.Add($m) }.GetNewClosure() -NowUtc ([datetime]::UtcNow) `
                 -Request ([pscustomobject]@{ Table = $tbl; Index = $Index; Minutes = 0; Force = $false; Partitions = $false; Keep = 2; PartitionSwitch = $Switch })
        [pscustomobject]@{ Outcome = $r.Outcome; Line = $r.Line; Log = ($lg -join ' / '); Sql = ($built -join ' / ') }
    }
    $script:ReadThrough = 'SELECT f.CollectionId, f.AssetKey, COUNT_BIG(*) AS N, SUM(f.RiskScore) AS Risk, MIN(f.Tier) AS Tier, COUNT(DISTINCT f.Cve) AS Cves, MAX(f.Title) AS Title FROM sidata.Finding AS f WITH (INDEX({0})) GROUP BY f.CollectionId, f.AssetKey ORDER BY f.CollectionId, f.AssetKey'
    function script:Read-Through($Inv, [string]$Ix) { @(& $Inv ($script:ReadThrough -f $Ix) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $_['CollectionId'], $_['AssetKey'], $_['N'], $_['Risk'], $_['Tier'], $_['Cves'], $_['Title'] }) -join ';' }
}

Describe 'the rule, pure: an index of sidata.Finding waits while the move is pending, then it is built aligned' {
    It 'the contract: NCCI_Finding_Load is on a partitioned table, NCCI_CiFindingState_Load is not; the scheme and its column' {
        $script:Fi.Partitioned | Should -BeTrue
        $script:Ci.Partitioned | Should -BeFalse
        $script:Cs.Scheme | Should -Be 'PS_SICollection'; $script:Cs.SchemeColumn | Should -Be 'CollectionId'
    }
    It 'PENDING (switch on, the move table there, not on the scheme, not blocked): it waits and says why' {
        foreach ($m in '', 'copying', 'ready') {
            $h = Get-SIColumnstorePartitionHold -Index $script:Fi -SwitchOn $true -State (St -Move $m)
            $h.Hold | Should -BeTrue -Because "move state '$m'"
            $h.Why | Should -Match 'waits until sidata\.Finding is on the collection partitions'
        }
    }
    It 'MOVED: on the scheme by the catalog = built ALIGNED; moved by sidata.PartitionMove only (a reader that cannot see the scheme) = not held' {
        $h = Get-SIColumnstorePartitionHold -Index $script:Fi -SwitchOn $true -State (St -OnScheme $true -Move 'done')
        $h.Hold | Should -BeFalse; $h.Aligned | Should -BeTrue
        foreach ($m in 'swapped', 'checked', 'done') { (Get-SIColumnstorePartitionHold -Index $script:Fi -SwitchOn $true -State (St -Move $m -Scheme $false)).Hold | Should -BeFalse -Because $m }
        # the switch OFF on a new install (the table made on the scheme): still aligned
        (Get-SIColumnstorePartitionHold -Index $script:Fi -SwitchOn $false -State (St -OnScheme $true)).Aligned | Should -BeTrue
    }
    It 'NOT held, built as today: the switch off; the move blocked for another reason; a database without the partition tables' {
        foreach ($c in @(@{ Sw = $false; S = (St) }, @{ Sw = $true; S = (St -Move 'blocked') }, @{ Sw = $true; S = (St -MoveTable $false -Scheme $false) })) {
            $h = Get-SIColumnstorePartitionHold -Index $script:Fi -SwitchOn $c.Sw -State $c.S
            $h.Hold | Should -BeFalse; $h.Aligned | Should -BeFalse
        }
    }
    It 'the state not readable = it waits (nothing on a guess); CiFindingState is never held, whatever the state' {
        (Get-SIColumnstorePartitionHold -Index $script:Fi -SwitchOn $true -State $null).Hold | Should -BeTrue
        foreach ($s in @($null, (St), (St -Move 'copying'))) {
            $h = Get-SIColumnstorePartitionHold -Index $script:Ci -SwitchOn $true -State $s
            $h.Hold | Should -BeFalse; $h.Aligned | Should -BeFalse
        }
    }
    It 'the statement: aligned = ... WITH (ONLINE = ON) ON PS_SICollection ([CollectionId]); not aligned = as today; never for another index' {
        $row = [pscustomobject]@{ Table = 'sidata.Finding'; Name = 'NCCI_Finding_Load'; Statement = (Get-SIColumnstoreStatement -Index $script:Fi) }
        (Get-SIIndexBuildRunSql -Row $row -OnPartitionScheme).Sql | Should -Be ('{0} WITH (ONLINE = ON) ON [PS_SICollection] ([CollectionId])' -f $row.Statement)
        (Get-SIIndexBuildRunSql -Row $row -OnPartitionScheme).Resumable | Should -BeFalse
        (Get-SIIndexBuildRunSql -Row $row).Sql | Should -Be ('{0} WITH (ONLINE = ON)' -f $row.Statement)
        $plain = [pscustomobject]@{ Table = 'sidata.Finding'; Name = 'IX_Finding_X'; Statement = 'CREATE INDEX IX_Finding_X ON sidata.Finding (CollectionId, AssetKey)' }
        (Get-SIIndexBuildRunSql -Row $plain -OnPartitionScheme -Minutes 30).Sql | Should -Not -Match 'PS_SICollection'
    }
    It 'THE RUNNER: a held row is left out (the next index goes); the state is read once and only when such a row waits' {
        $rows = @(
            [pscustomobject]@{ Table = 'sidata.Finding'; Name = 'NCCI_Finding_Load'; State = 'waiting'; Statement = 'x' }
            [pscustomobject]@{ Table = 'sidata.CiFindingState'; Name = 'NCCI_CiFindingState_Load'; State = 'waiting'; Statement = 'x' }
            [pscustomobject]@{ Table = 'sidata.Finding'; Name = 'IX_Finding_X'; State = 'waiting'; Statement = 'x' })
        $s = Select-SIColumnstoreRowsNotHeld -Rows $rows -SwitchOn $true -State (St -Move 'copying')
        @($s.Rows | ForEach-Object { $_.Name }) | Should -Be @('NCCI_CiFindingState_Load', 'IX_Finding_X')
        @($s.Held).Count | Should -Be 1
        (Select-SIColumnstoreRowsNotHeld -Rows $rows -SwitchOn $true -State (St -OnScheme $true -Move 'done')).Rows.Count | Should -Be 3
        (Select-SIColumnstoreRowsNotHeld -Rows $rows -SwitchOn $false -State (St)).Rows.Count | Should -Be 3
        $script:Reads = 0
        $null = Select-SIColumnstoreRowsNotHeld -Rows @($rows[1], $rows[2]) -Invoke { $script:Reads++; throw 'not read' } -SwitchOn $true
        $script:Reads | Should -Be 0 -Because 'no Finding columnstore row waits: nothing read'
        (Select-SIColumnstoreRowsNotHeld -Rows $rows -Invoke { throw 'denied' } -SwitchOn $true).Rows.Count | Should -Be 2 -Because 'not readable = held'
    }
    It 'THE RUNNER''s source: the held rows are left out right after cfg.IndexBuild is read; the switch rides to the job' {
        $a = $script:Runner.IndexOf('$ixRows = @(Read-SIIndexBuildRows')
        $b = $script:Runner.IndexOf('Select-SIColumnstoreRowsNotHeld -Rows $ixRows')
        $c = $script:Runner.IndexOf('Get-SIIndexBuildWindowDecision -Rows $ixRows')
        $a | Should -BeGreaterThan 0; $b | Should -BeGreaterThan $a; $c | Should -BeGreaterThan $b
        $script:Runner | Should -Match "SI_INDEXBUILD_PARTITIONSWITCH = \`$\(if \(\`$ptSwitch\) \{ '1' \} else \{ '0' \}\)"
        (Read-SIIndexBuildJobInput -Env @{ SI_INDEXBUILD_SERVER = 'server.database.windows.net'; SI_INDEXBUILD_DATABASE = 'd' }).Request.PartitionSwitch | Should -BeTrue -Because 'not set = on'
        (Read-SIIndexBuildJobInput -Env @{ SI_INDEXBUILD_SERVER = 'server.database.windows.net'; SI_INDEXBUILD_DATABASE = 'd'; SI_INDEXBUILD_PARTITIONSWITCH = '0' }).Request.PartitionSwitch | Should -BeFalse
    }
    It 'THE JOB: pending = nothing built, outcome waiting, ONE plain line; on the scheme = built aligned; CiFindingState built as today' {
        $mk = {
            param($Name, $State)
            $w = [pscustomobject]@{ Built = $null; Saves = (New-Object System.Collections.Generic.List[string]); Log = (New-Object System.Collections.Generic.List[string]) }
            $ix = @($script:Cs.Indexes | Where-Object { $_.Name -eq $Name })[0]
            $row = [pscustomobject]@{ Table = $ix.Table; Name = $Name; Statement = (Get-SIColumnstoreStatement -Index $ix); State = 'waiting'; Pages = 1; EstMinutes = 30; Source = 'x'; Why = ''
                                      SinceUtc = $script:Now.AddDays(-1); LastStartUtc = $null; LastEndUtc = $null; ForcedUtc = $null }
            $seams = @{ Rows = { , @($row) }.GetNewClosure(); Save = { param($t, $i, $st, $why, $f) $w.Saves.Add($st); $true }.GetNewClosure(); UpdateFirst = { '' }; OtherRunning = { '' }
                        Gate = { param($h) [pscustomobject]@{ Go = $true; Reason = 'ok'; LockTaken = $true } }; Beat = { param($h, $what) $true }; ExitGate = { param($h) }
                        Exists = { param($t, $i) [bool]$w.Built }.GetNewClosure(); ResumableOp = { param($t, $i) $null }
                        Build = { param($sql, $a, $b) $w.Built = $sql; 60.0 }.GetNewClosure(); Rate = { param($t, $s) }
                        ColumnstoreSetting = { [pscustomobject]@{ Known = $true; On = $true } }; PartitionState = { $State }.GetNewClosure() }
            $lg = $w.Log
            $r = Invoke-SIIndexBuildJob -Store ([pscustomobject]@{ Invoke = { throw 'no database in this test' } }) -Holder 'caj-si-index-build:e1' -Seams $seams -Log { param($m) $lg.Add($m) }.GetNewClosure() -NowUtc $script:Now `
                     -Request ([pscustomobject]@{ Table = $ix.Table; Index = $Name; Minutes = 0; Force = $false; PartitionSwitch = $true })
            $w | Add-Member -NotePropertyName R -NotePropertyValue $r; $w
        }
        $p = & $mk 'NCCI_Finding_Load' (St -Move 'copying')
        $p.R.Outcome | Should -Be 'waiting'; $p.R.ExitCode | Should -Be 0
        $p.Built | Should -BeNullOrEmpty
        @($p.Log | Where-Object { $_ -match 'waits until sidata\.Finding is on the collection partitions' }).Count | Should -Be 1
        @($p.Saves) | Should -Not -Contain 'building'
        $a = & $mk 'NCCI_Finding_Load' (St -OnScheme $true -Move 'done')
        $a.R.Outcome | Should -Be 'built'
        $a.Built | Should -Match 'WITH \(ONLINE = ON\) ON \[PS_SICollection\] \(\[CollectionId\]\)$'
        $c = & $mk 'NCCI_CiFindingState_Load' (St -Move 'copying')
        $c.R.Outcome | Should -Be 'built' -Because 'CiFindingState is not partitioned: never held'
        $c.Built | Should -Match 'ON \[sidata\]\.\[CiFindingState\] \(.*\) WITH \(ONLINE = ON\)$'
    }
    It 'THE UPDATE: the index is still recorded, and its line says it waits for the move' {
        $lines = New-Object System.Collections.Generic.List[string]
        $st = [pscustomobject]@{ Supported = [pscustomobject]@{ Ok = $true; Why = 'x' }; Exists = @{}; Missing = @{} }
        $r = Invoke-SIColumnstoreIndexStep -Invoke { param($s, $p, $m) $null } -Log { param($m) $lines.Add($m) }.GetNewClosure() -Setting ([pscustomobject]@{ Known = $true; On = $true }) -State $st -Rows @() `
                 -Estimate { param($i) $null } -PartitionSwitch $true -PartitionState (St -Move 'copying')
        @($r.Plan | Where-Object { $_.Action -eq 'queue' }).Count | Should -Be 2
        @($lines | Where-Object { $_ -match 'NCCI_Finding_Load .*recorded.*waits until sidata\.Finding is on the collection partitions' }).Count | Should -Be 1
        @($lines | Where-Object { $_ -match 'NCCI_CiFindingState_Load' -and $_ -match 'waits until' }).Count | Should -Be 0
    }
    It 'THE MOVE: SI''s own columnstore index never blocks it; any other non-row-store index still does; only Finding has one' {
        Get-SIPartitionMovePreflightSql | Should -Match 'NOT \(i\.type = 6 AND i\.name = ISNULL\(@Ncci'
        Get-SIPartitionMoveColumnstoreName -Table 'Finding' | Should -Be 'NCCI_Finding_Load'
        Get-SIPartitionMoveColumnstoreName -Table 'IssueContext' | Should -Be ''
        Get-SIPartitionMoveColumnstoreDropSql -Names (Get-SIPartitionMoveNames -Table 'Recommendation') | Should -Be ''
        $d = Get-SIPartitionMoveColumnstoreDropSql -Names (Get-SIPartitionMoveNames -Table 'Finding')
        $d | Should -Match 'DROP INDEX \[NCCI_Finding_Load\] ON sidata\.\[Finding\]'
        $d | Should -Match "type = 6"
        $d | Should -Match 'SET LOCK_TIMEOUT 30000'
        $d | Should -Match "UPDATE cfg\.IndexBuild SET State = N'waiting'"
        $d | Should -Not -Match '(?i)CREATE\s+(NONCLUSTERED\s+)?COLUMNSTORE' -Because 'only the index build job creates one'
    }
}

Describe 'on a real SQL Server: columnstore x partitions' {
    It '(a) + (b) + (d) + (e): PENDING = no NCCI on Finding and the line said (CiFindingState built); after the move it is built ALIGNED; a retired collection''s partition is truncated with it there; reads through it answer the same rows' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'sicsp_' -Unpartitioned
        try {
            $inv = $d.Invoke; $upd = $d.Updater
            $ids = @(); foreach ($day in 1..4) { $ids += Add-Collection $inv ('2026-10-0{0}T08:00:00' -f $day) 300 }
            # the update records both indexes; the partition tables are there, the move has not begun = PENDING
            $lines = New-Object System.Collections.Generic.List[string]
            $null = Invoke-SIColumnstoreIndexStep -Invoke $upd -Log { param($m) $lines.Add($m) }.GetNewClosure() -Estimate { param($i) $null } -PartitionSwitch $true
            @(Read-SIIndexBuildRows -Invoke $upd | ForEach-Object { $_.Name } | Sort-Object) | Should -Be @('NCCI_CiFindingState_Load', 'NCCI_Finding_Load')
            @($lines | Where-Object { $_ -match 'NCCI_Finding_Load.*waits until sidata\.Finding is on the collection partitions' }).Count | Should -Be 1 -Because ($lines -join ' / ')
            # the runner's own read (the engine's data rights): the Finding row is held, the other goes
            $sel = Select-SIColumnstoreRowsNotHeld -Rows @(Read-SIIndexBuildRows -Invoke $d.Engine) -Invoke $d.Engine -SwitchOn $true
            @($sel.Rows | ForEach-Object { $_.Name }) | Should -Be @('NCCI_CiFindingState_Load')
            # (a) the job, asked for it anyway: nothing built, the line said
            $j = Invoke-RealJob $d 'NCCI_Finding_Load'
            $j.Outcome | Should -Be 'waiting' -Because $j.Log
            $j.Log | Should -Match 'NCCI_Finding_Load on sidata\.Finding waits until sidata\.Finding is on the collection partitions'
            NcciAt $inv | Should -Be 'none'
            # CiFindingState is unaffected: built now, as today (not partitioned)
            $jc = Invoke-RealJob $d 'NCCI_CiFindingState_Load'
            $jc.Outcome | Should -Be 'built' -Because $jc.Log
            NcciAt $inv 'CiFindingState' 'NCCI_CiFindingState_Load' | Should -Be 'unaligned' -Because 'CiFindingState is not on the scheme'

            # the move (the job's idle windows) -- nothing blocks it
            Mark $inv $ids[0]
            $h = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 2 -BatchSize 200 -Sleep { param($ms) }
            @($h.Move.Tables | Where-Object { $_.Table -eq 'Finding' })[0].State | Should -BeIn @('swapped', 'checked') -Because ($h.Lines -join ' / ')
            Partitioned $inv 'Finding' | Should -BeTrue
            # the engine's reader: no longer held once the move is recorded
            @((Select-SIColumnstoreRowsNotHeld -Rows @(Read-SIIndexBuildRows -Invoke $d.Engine) -Invoke $d.Engine -SwitchOn $true).Rows | ForEach-Object { $_.Name }) | Should -Contain 'NCCI_Finding_Load'
            $byCluster = Read-Through $inv '1'

            # (b) after the move: built ALIGNED on the scheme
            $j2 = Invoke-RealJob $d 'NCCI_Finding_Load'
            $j2.Outcome | Should -Be 'built' -Because $j2.Log
            $j2.Sql | Should -Match 'ON \[PS_SICollection\] \(\[CollectionId\]\)$'
            NcciAt $inv | Should -Be 'aligned'
            Count $inv "SELECT COUNT(*) FROM sys.indexes WHERE object_id = OBJECT_ID(N'sidata.Finding') AND is_hypothetical = 0 AND data_space_id <> (SELECT data_space_id FROM sys.partition_schemes WHERE name = N'PS_SICollection')" | Should -Be 0 -Because 'every index of Finding is aligned'
            # (e) reads through it answer the same rows
            Read-Through $inv 'NCCI_Finding_Load' | Should -Be $byCluster

            # (d) a retired collection's partition truncated WITH the aligned NCCI there; counts read back
            Mark $inv $ids[1]
            $total = Count $inv 'SELECT COUNT(*) FROM sidata.Finding'
            $h2 = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 2 -Sleep { param($ms) }
            @($h2.Removed | ForEach-Object { [int]$_.CollectionId }) | Should -Contain $ids[1] -Because ($h2.Lines -join ' / ')
            @($h2.Removed | Where-Object { [int]$_.CollectionId -eq $ids[1] })[0].Findings | Should -Be 300
            Rows3 $inv $ids[1] | Should -Be '0/0/0'
            foreach ($c in $ids[2], $ids[3]) { Rows3 $inv $c | Should -Be '300/300/300' }
            Count $inv 'SELECT COUNT(*) FROM sidata.Finding' | Should -Be ($total - 300)
            NcciAt $inv | Should -Be 'aligned' -Because 'the index stays'
            # (e) again after the truncate: through the NCCI = through the clustered index
            Read-Through $inv 'NCCI_Finding_Load' | Should -Be (Read-Through $inv '1')
            Count $inv ("SELECT COUNT(*) FROM sidata.Finding WITH (INDEX(NCCI_Finding_Load)) WHERE CollectionId = {0}" -f $ids[1]) | Should -Be 0
        } finally { Remove-TestDb $d.Name }
    }
    It '(c) an NCCI built BEFORE on the unpartitioned table: the move completes (never blocked), its row-store indexes stay, and the NCCI is built aligned afterwards' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'sicspre_' -Unpartitioned
        try {
            $inv = $d.Invoke; $upd = $d.Updater
            $ids = @(); foreach ($day in 1..3) { $ids += Add-Collection $inv ('2026-10-0{0}T08:00:00' -f $day) 250 }
            $null = Invoke-SIColumnstoreIndexStep -Invoke $upd -Estimate { param($i) $null } -PartitionSwitch $false
            # built before this fix / with the switch off: on the old table, not aligned
            (Invoke-RealJob $d 'NCCI_Finding_Load' -Switch $false).Outcome | Should -Be 'built'
            NcciAt $inv | Should -Be 'unaligned'
            $rowStore = RowStore $inv
            $before = Read-Through $inv '1'
            # the move (switch on again): not blocked, the NCCI dropped right before the copy and said, its row waits
            $h = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 3 -BatchSize 200 -Sleep { param($ms) }
            ($h.Lines -join ' / ') | Should -Match 'Finding: its columnstore index NCCI_Finding_Load was dropped for the move'
            ($h.Lines -join ' / ') | Should -Not -Match 'not a row-store index'
            @($h.Move.Tables | Where-Object { $_.Table -eq 'Finding' })[0].State | Should -BeIn @('swapped', 'checked') -Because ($h.Lines -join ' / ')
            Partitioned $inv 'Finding' | Should -BeTrue
            RowStore $inv | Should -Be $rowStore -Because 'every row-store index of Finding is there after the swap'
            Read-Through $inv '1' | Should -Be $before -Because 'the move changes no row'
            (@(Read-SIIndexBuildRows -Invoke $upd | Where-Object { $_.Name -eq 'NCCI_Finding_Load' })[0]).State | Should -Be 'waiting'
            # the next idle window's index build: aligned now
            $j = Invoke-RealJob $d 'NCCI_Finding_Load'
            $j.Outcome | Should -Be 'built' -Because $j.Log
            NcciAt $inv | Should -Be 'aligned'
            Read-Through $inv 'NCCI_Finding_Load' | Should -Be $before
            # and a retired collection still leaves by its partition
            Mark $inv $ids[0]
            $h2 = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 2 -Sleep { param($ms) }
            @($h2.Removed | ForEach-Object { [int]$_.CollectionId }) | Should -Contain $ids[0] -Because ($h2.Lines -join ' / ')
            Rows3 $inv $ids[0] | Should -Be '0/0/0'
        } finally { Remove-TestDb $d.Name }
    }
    It 'a NEW install (Finding made on the scheme): the NCCI is never held and is built aligned at once' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'sicsnew_'
        try {
            $null = Add-Collection $d.Invoke '2026-10-01T08:00:00' 50
            $null = Invoke-SIColumnstoreIndexStep -Invoke $d.Updater -Estimate { param($i) $null } -PartitionSwitch $true
            $j = Invoke-RealJob $d 'NCCI_Finding_Load'
            $j.Outcome | Should -Be 'built' -Because $j.Log
            NcciAt $d.Invoke | Should -Be 'aligned'
        } finally { Remove-TestDb $d.Name }
    }
}
