#Requires -Version 7.0
<#
    THE FINDING HISTORY'S STORAGE (REQUIREMENTS #1332, SCALE-3 #1330 track B, storage lane; owner 2026-11-23 "Yes, all": 30 days
    of history, a collection no longer stored in full is FROZEN as it was published, prio 1 never fewer rows, a failed move =
    rolled back + warning, never partial). sql\si-data-schema.sql (the history on PS_SICollection),
    engine\pro-settings\SI-ProPartitionMove.ps1 (Invoke-SIHistoryPartitionRetention, Invoke-SIHistoryMigrationStep, the cut
    by each table's own partitioning column) and engine\pro-data\_shared\SI-DataHistory.ps1 (the resumable compare + checksum,
    the migration outside a run, the frozen rule, the 30-day default).

    What these tests keep true, on a REAL SQL Server (the Azure test runner, _SITestSql.ps1):
      * a new install's history tables are on the collection partitions, every index aligned; the schema stays additive;
      * A FOLD WITH HISTORY PRESENT KEEPS EVERY STATE: #1317 empties a retired collection's partition of the three large
        tables but never folds the range while the history holds rows there; the collection is frozen -- its history gives
        it back with the checksum it had when it was stored in full; an UNVERIFIED history is not kept frozen;
      * RETENTION AT 30 DAYS REMOVES ONLY UNREFERENCED STATES: collections older than 30 days leave by partition, the
        published one stays, the states a newer collection holds are moved forward with the same checksum, only states no
        collection holds go, every member keeps its state, the ranges fold once empty; a held lock = rolled back + warning,
        every row kept;
      * MIGRATION INTERRUPTED + RESUMED = IDENTICAL CHECKSUM: stopped every few ranges (writing and comparing), it resumes
        each time and ends with every collection verified, its checksum equal to the stored rows' and to an uninterrupted
        migration's;
      * A LOCK HELD BY A RUN BLOCKS THE MIGRATION STEP (before it starts and in the middle); the job's / an update's own
        lock and a stale run lock do not.
#>

BeforeDiscovery {
    $script:LocalSql = $false
    try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
}

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-KqlError.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataKql.ps1')
    . (Join-Path $script:Root 'engine\_shared\SI-SchemaGate.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataModel.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataViewContext.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataChanges.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataChangedSet.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataHistory.ps1')
    . (Join-Path $script:Root 'engine\_shared\SI-IndexBuild.ps1')
    . (Join-Path $script:Root 'engine\pro-settings\SI-ProPartitionMove.ps1')
    $script:Schema = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'sql\si-data-schema.sql')
    $script:Quiet = { param($l, $m) }
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
    # a new install's database (the release's schema) and a user with exactly the UPDATER's roles (the index build job)
    function script:New-TestDb([string]$Prefix) {
        $db = $Prefix + [guid]::NewGuid().ToString('N').Substring(0, 8)
        [void](& (New-LocalInvoke 'master') "CREATE DATABASE [$db]" @{} 'nonquery')
        $inv = New-LocalInvoke $db
        [void](& $inv $script:Schema @{} 'nonquery')
        [void](& $inv "CREATE USER si_test_updater WITHOUT LOGIN; ALTER ROLE db_ddladmin ADD MEMBER si_test_updater; ALTER ROLE db_datareader ADD MEMBER si_test_updater; ALTER ROLE db_datawriter ADD MEMBER si_test_updater;" @{} 'nonquery')
        [pscustomobject]@{ Name = $db; Invoke = $inv; Updater = (New-LocalInvoke $db 'si_test_updater') }
    }
    function script:Remove-TestDb([string]$Db) { try { [System.Data.SqlClient.SqlConnection]::ClearAllPools(); [void](& (New-LocalInvoke 'master') "ALTER DATABASE [$Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$Db]" @{} 'nonquery') } catch { } }
    function script:Step([string]$m) { Write-Host ('  [{0:HH:mm:ss}] {1}' -f [datetime]::UtcNow, $m) }
    function script:HasBoundary($Inv, [long]$V) { (Count $Inv "SELECT COUNT(*) FROM sys.partition_range_values AS v JOIN sys.partition_functions AS f ON f.function_id = v.function_id WHERE f.name = N'PF_SICollection' AND CONVERT(int, v.value) = $V") -eq 1 }
    function script:Count($Inv, [string]$Sql) { [long](& $Inv $Sql @{} 'scalar') }
    function script:Boundaries($Inv) { Count $Inv "SELECT COUNT(*) FROM sys.partition_range_values AS v JOIN sys.partition_functions AS f ON f.function_id = v.function_id WHERE f.name = N'PF_SICollection'" }
    function script:Mark($Inv, [long]$C) { [void](& $Inv ("UPDATE sidata.Collection SET RetiredAt = DATEADD(minute, -5, SYSUTCDATETIME()), RetiredWhy = N'superseded' WHERE CollectionId = {0}" -f $C) @{} 'nonquery') }
    # one Detailed collection with -Rows findings: rows i < $Shared have the same content in every collection (ONE state),
    # rows i < $Pair the same in the collections of one -PairKey only, the rest only this one's; the run's own time in every document
    function script:Add-Collection($Inv, [datetime]$When, [int]$Rows, [int]$K, [int]$Shared = 10, [int]$Pair = 0, [string]$PairKey = '') {
        $t = $When.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture)
        $cid = [long](@(& $Inv (Get-SIDataNewCollectionSql) @{ CollectionTime = $t; Kind = 'Detailed'; RunId = ''; SolutionVersion = '3.0.test' } 'scalar') | Select-Object -Last 1)
        [void](& $Inv @"
SET NOCOUNT ON;
DECLARE @c int = $cid;
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, Severity, Tier, RiskScore, Title, DetailJson, ImportanceRank)
SELECT TOP ($Rows) @c, CONCAT(N'a', n.i), CONCAT(N'srv-', n.i), N'R', N'High', 1, n.i * 1.5,
       CASE WHEN n.i < $Shared THEN CONCAT(N'same ', n.i) WHEN n.i < $Shared + $Pair THEN CONCAT(N'pair $PairKey ', n.i) ELSE CONCAT(N'only $K ', n.i) END,
       CONCAT(N'{"CollectionTime":"$t","i":', n.i, N',"note":"x"}'), 1000 - n.i
FROM (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS i FROM sys.all_objects AS a CROSS JOIN sys.all_objects AS b) AS n;
UPDATE sidata.Collection SET Status = N'Complete', [Rows] = $Rows WHERE CollectionId = @c;
"@ @{} 'nonquery')
        $cid
    }
    function script:Sum($Inv, [long]$C, [string]$From) {
        $cols = Read-SIDataHistoryColumns -Invoke $Inv
        [string](& $Inv (Get-SIDataHistoryCollectionSumSql -Columns $cols.All -From $From) @{ CollectionId = [string]$C } 'scalar')
    }
    # this test's own compare (independent of the product's hash): every column of every row as JSON, sorted
    function script:Get-Rows($Inv, [string]$From) {
        $rows = @(& $Inv ("SELECT (SELECT x.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J FROM ({0}) AS x" -f $From) @{} 'reader' | ForEach-Object { $_ } | ForEach-Object { [string]$_['J'] })
        [Array]::Sort($rows, [StringComparer]::Ordinal); , $rows
    }
    function script:Assert-Same($Inv, [long]$Cid, [string]$Why) {
        $a = Get-Rows $Inv "SELECT * FROM sidata.Finding WHERE CollectionId = $Cid"
        $b = Get-Rows $Inv "SELECT * FROM sidata.FindingAt($Cid)"
        $b.Count | Should -Be $a.Count -Because "$Why (rows)"
        for ($i = 0; $i -lt $a.Count; $i++) { if ($a[$i] -cne $b[$i]) { "row $i differs: $($a[$i]) / $($b[$i])" | Should -BeNullOrEmpty -Because $Why } }
    }
    function script:Orphans($Inv) { Count $Inv 'SELECT COUNT_BIG(*) FROM sidata.FindingStateMember AS m WHERE NOT EXISTS (SELECT 1 FROM sidata.FindingState AS s WHERE s.StateId = m.StateId)' }
    function script:Unheld($Inv) { Count $Inv 'SELECT COUNT_BIG(*) FROM sidata.FindingState AS s WHERE NOT EXISTS (SELECT 1 FROM sidata.FindingStateMember AS m WHERE m.StateId = s.StateId)' }
    # the boundaries ahead first (the job's first idle window), so every collection lands alone in its own partition
    function script:Initialize-Estate($D) { $h = Invoke-SIPartitionHousekeeping -Invoke $D.Updater -Keep 2 -Migrate $false -Sleep { param($ms) }; $h.Status | Should -BeIn @('done', 'nothing') -Because ($h.Lines -join ' / ') }
}

Describe 'the schema and the wiring' {
    It 'a new install''s members and states are made on the collection partitions (by CollectionId / HomeCollectionId); additive' {
        $script:Schema | Should -Match ([regex]::Escape("CONSTRAINT PK_FindingStateMember PRIMARY KEY CLUSTERED (CollectionId, FindingId)`r`n) ON PS_SICollection (CollectionId);").Replace('\r\n', '\r?\n'))
        $script:Schema | Should -Match ([regex]::Escape("CONSTRAINT PK_FindingState PRIMARY KEY CLUSTERED (StateId, HomeCollectionId)) ON PS_SICollection (HomeCollectionId);"))
        (Test-SISchemaIsAdditive -Sql $script:Schema).IsAdditive | Should -BeTrue
        $script:Schema | Should -Not -Match 'TRUNCATE TABLE sidata\.FindingState'
    }
    It 'the cut reads each table''s own partitioning column; the job and the update''s step run the history''s partition step and its migration' {
        (Get-SIPartitionAheadSql) | Should -Match 'ic\.partition_ordinal = 1'
        (Get-SIPartitionAheadSql) | Should -Match ([regex]::Escape("N'SELECT @m = MAX(' + @pc + N') FROM ' + @t"))
        $hk = (Get-Command Invoke-SIPartitionHousekeeping).Definition
        $hk | Should -Match 'Invoke-SIHistoryPartitionRetention -Invoke \$Invoke -DeadlineUtc \$DeadlineUtc -ShouldStop \$ShouldStop'
        $hk | Should -Match 'Invoke-SIHistoryMigrationStep -Invoke \$Invoke -DeadlineUtc \$DeadlineUtc -ShouldStop \$ShouldStop'
        $hk.IndexOf('Invoke-SIHistoryPartitionRetention -Invoke') | Should -BeGreaterThan $hk.IndexOf('Invoke-SIPartitionRemove -Invoke')
        (Get-Command Invoke-SIHistoryMigrationStep).Definition | Should -Match "'pro-data', '_shared', 'SI-DataHistory\.ps1'"
    }
    It 'the history leaves by TRUNCATE ... WITH (PARTITIONS) only -- no statement of the partition step deletes a member or a state' {
        foreach ($s in (Get-SIHistoryMemberRemoveSql), (Get-SIHistoryStateForwardSql), (Get-SIHistoryStateRemoveSql)) {
            $s | Should -Not -Match 'DELETE\s+(TOP\s*\(\d+\)\s*)?\w*\s*FROM\s+sidata\.FindingState(Member)?\b'
            $s | Should -Not -Match 'DELETE\s+\w+\s+FROM\s+sidata\.FindingState(Member)?\s'
        }
        (Get-SIHistoryMemberRemoveSql) | Should -Match ([regex]::Escape("TRUNCATE TABLE sidata.FindingStateMember WITH (PARTITIONS ("))
        (Get-SIHistoryStateRemoveSql) | Should -Match ([regex]::Escape("TRUNCATE TABLE sidata.FindingState WITH (PARTITIONS ("))
        (Get-SIHistoryMemberRemoveSql) | Should -Match "sp_getapplock @Resource = N'sidata\.PublishedRun'"
    }
    It 'the history window: 30 days by default (owner decision, the engine''s own fallback), 0 = the kept collections; the catalog says 30 days' {
        $old = Get-Variable -Name SI_Data_HistoryDays -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        try {
            Remove-Variable -Name SI_Data_HistoryDays -Scope Global -ErrorAction SilentlyContinue
            $none = { param($s, $p, $m) if ($m -eq 'scalar') { return $null }; , @() }
            Read-SIDataHistoryDays -Invoke $none | Should -Be 30
            Read-SIHistoryPartitionDays -Invoke $none | Should -Be 30
            Read-SIDataHistoryDays -Invoke $none -Value '0' | Should -Be 0
            Read-SIHistoryPartitionDays -Invoke { param($s, $p, $m) '"45"' } | Should -Be 45
        } finally { if ($null -ne $old) { $global:SI_Data_HistoryDays = $old } }
        $cat = Get-Content -Raw (Join-Path $script:Root 'config\settings.catalog.locked.json') | ConvertFrom-Json
        $e = @($cat.settings | Where-Object { $_.name -eq 'SI_Data_HistoryDays' })[0]
        # the catalog is the generator's output (SIv3-SettingsCatalogGenerated): a commented-out example has no default value, only
        # its default TEXT -- the 30 days that apply are the engine's own fallback, checked above (Read-SIDataHistoryDays unset = 30)
        $e.default | Should -BeNullOrEmpty
        [string]$e.defaultText | Should -Be '30 days'
    }
    It 'the checksum adds exactly, whatever the ranges were' {
        Add-SIDataHistorySum -A '2|10|20|30|40' -B '3|1|2|3|4' | Should -Be '5|11|22|33|44'
        Add-SIDataHistorySum -A '0|0|0|0|0' -B '1|72057594037927935|72057594037927935|1|1' | Should -Be '1|72057594037927935|72057594037927935|1|1'
        Add-SIDataHistorySum -A '1|72057594037927935|0|0|0' -B '1|72057594037927935|0|0|0' | Should -Be '2|144115188075855870|0|0|0'
    }
}

Describe 'REAL SQL: the history on the collection partitions' -Skip:(-not $script:LocalSql) {
    BeforeEach { Step ('start: ' + $____Pester.CurrentTest.Name) }
    It 'a new install: both history tables on PS_SICollection, every index aligned; once a boundary is cut the history leaves by partition' {
        $d = New-TestDb 'sihs_schema_'
        try {
            $inv = $d.Invoke
            foreach ($t in 'FindingStateMember', 'FindingState') {
                Count $inv "SELECT COUNT(*) FROM sys.indexes AS x LEFT JOIN sys.partition_schemes AS s ON s.data_space_id = x.data_space_id WHERE x.object_id = OBJECT_ID(N'sidata.$t') AND (s.name IS NULL OR s.name <> N'PS_SICollection')" | Should -Be 0 -Because "every index of $t is aligned"
            }
            Count $inv (Get-SIDataHistoryOnPartitionsSql) | Should -Be 0 -Because 'no boundary yet: one partition, the paced removal serves'
            Initialize-Estate $d
            Count $inv (Get-SIDataHistoryOnPartitionsSql) | Should -Be 1
            (Boundaries $inv) | Should -BeGreaterOrEqual 16
        } finally { Remove-TestDb $d.Name }
    }

    It 'A FOLD WITH HISTORY PRESENT KEEPS EVERY STATE: the retired collection''s rows leave, its range is not folded, its history is frozen with the checksum it had; an unverified one is not kept' {
        $d = New-TestDb 'sihs_fold_'
        try {
            $inv = $d.Invoke; $upd = $d.Updater
            Initialize-Estate $d
            $now = [datetime]::UtcNow
            $ids = @(); foreach ($k in 1..4) { $ids += Add-Collection $inv $now.AddDays(-5 + $k) 60 $k }
            $r = Invoke-SIDataHistory -Invoke $inv -Mode 'on' -Log $script:Quiet -FirstSize 17 -Days 30
            $r.Status | Should -Be 'ok'; $r.Verified | Should -Be 4
            $sum1 = Sum $inv $ids[0] 'stored'
            (Sum $inv $ids[0] 'history') | Should -Be $sum1
            [string](& $inv "SELECT SumHistory FROM sidata.HistoryRun WHERE CollectionId = $($ids[0])" @{} 'scalar') | Should -Be $sum1 -Because 'the compare''s own checksum is the collection''s'
            $states = Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingState'
            $members = Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingStateMember'
            $b0 = Boundaries $inv
            Mark $inv $ids[0]
            $h = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 2 -Migrate $false -Sleep { param($ms) }
            @($h.Removed | ForEach-Object { [long]$_.CollectionId }) | Should -Be @($ids[0]) -Because ($h.Lines -join ' / ')
            @($h.Removed)[0].Merged | Should -Be 0 -Because 'the history still holds rows in the range: it is never folded'
            HasBoundary $inv $ids[0] | Should -BeTrue -Because 'the range of the retired collection is not folded while the history holds it'
            Count $inv "SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = $($ids[0])" | Should -Be 0
            Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingState' | Should -Be $states -Because 'every state is kept'
            Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingStateMember' | Should -Be $members
            (Sum $inv $ids[0] 'history') | Should -Be $sum1 -Because 'FROZEN: the history gives the collection back exactly as it was stored in full'
            # the data sync's next run: never writes a frozen collection again, and leaves its retention to the partition step
            $r2 = Invoke-SIDataHistory -Invoke $inv -Mode 'on' -Log $script:Quiet -FirstSize 17
            $r2.Status | Should -Be 'ok'; $r2.Written | Should -Be 0
            (Sum $inv $ids[0] 'history') | Should -Be $sum1
            Orphans $inv | Should -Be 0
            # the same collection with an UNVERIFIED history is not kept frozen: its members leave by their partition
            [void](& $inv "UPDATE sidata.HistoryRun SET State = N'differs' WHERE CollectionId = $($ids[0])" @{} 'nonquery')
            $h2 = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 2 -Migrate $false -Sleep { param($ms) }
            Count $inv "SELECT COUNT_BIG(*) FROM sidata.FindingStateMember WHERE CollectionId = $($ids[0])" | Should -Be 0 -Because ($h2.Lines -join ' / ')
            Orphans $inv | Should -Be 0
            foreach ($c in $ids[1..3]) { Assert-Same $inv $c "kept collection $c after the fold and the frozen one left" }
        } finally { Remove-TestDb $d.Name }
    }

    It 'RETENTION AT 30 DAYS REMOVES ONLY UNREFERENCED STATES: older collections leave by partition, the published one stays, held states move forward with the same checksum; a held lock = rolled back + warning' {
        $d = New-TestDb 'sihs_ret_'
        try {
            $inv = $d.Invoke; $upd = $d.Updater
            Initialize-Estate $d
            $now = [datetime]::UtcNow
            # c1, c2 older than 30 days (c1 and c2 share 8 states only they hold); c3 older too but PUBLISHED; c4, c5 kept
            $ids = @()
            $ids += Add-Collection $inv $now.AddDays(-40) 50 1 -Shared 10 -Pair 8 -PairKey 'old'
            $ids += Add-Collection $inv $now.AddDays(-36) 50 2 -Shared 10 -Pair 8 -PairKey 'old'
            $ids += Add-Collection $inv $now.AddDays(-33) 50 3
            $ids += Add-Collection $inv $now.AddDays(-2) 50 4
            $ids += Add-Collection $inv $now.AddDays(-1) 50 5
            $r = Invoke-SIDataHistory -Invoke $inv -Mode 'on' -Log $script:Quiet -FirstSize 23 -Days 30
            $r.Verified | Should -Be 5
            [void](& $inv ("INSERT sidata.PublishedRun (Name, DetailedCollectionId, Source, PublishedAt) VALUES (N'current', {0}, N'run', SYSUTCDATETIME())" -f $ids[2]) @{} 'nonquery')
            $keep = @{}; foreach ($c in $ids[2..4]) { $keep[$c] = Sum $inv $c 'history' }
            $held = Count $inv ("SELECT COUNT(DISTINCT StateId) FROM sidata.FindingStateMember WHERE CollectionId IN ({0})" -f ($ids[2..4] -join ','))
            $only12 = Count $inv ("SELECT COUNT_BIG(*) FROM sidata.FindingState AS s WHERE NOT EXISTS (SELECT 1 FROM sidata.FindingStateMember AS m WHERE m.StateId = s.StateId AND m.CollectionId NOT IN ({0}, {1}))" -f $ids[0], $ids[1])
            $only12 | Should -Be 72 -Because 'c1 and c2 hold 72 states nobody else holds (32 + 32 of their own, the 8 of the pair)'
            Count $inv ("SELECT COUNT_BIG(*) FROM sidata.FindingState WHERE HomeCollectionId = {0} AND StateId IN (SELECT StateId FROM sidata.FindingStateMember WHERE CollectionId = {1})" -f $ids[0], $ids[4]) | Should -Be 10 -Because 'the shared states were made with the oldest collection'
            foreach ($c in $ids[0..2]) { Mark $inv $c }
            $b0 = Boundaries $inv
            $states0 = Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingState'; $members0 = Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingStateMember'

            Step 'retention: a held lock'
            # 1. A HELD LOCK: the members' step cannot get its lock -> rolled back, a warning, every row kept
            $blk = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=$($d.Name);$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True;Pooling=False"
            $blk.Open()
            try {
                $c0 = $blk.CreateCommand(); $c0.CommandText = 'BEGIN TRAN; SELECT TOP (1) StateId FROM sidata.FindingStateMember WITH (TABLOCKX, HOLDLOCK); SELECT TOP (1) StateId FROM sidata.FindingState WITH (TABLOCKX, HOLDLOCK);'; [void]$c0.ExecuteNonQuery()
                $x = Invoke-SIHistoryPartitionRetention -Invoke $upd -Days 30
                @($x.Problems).Count | Should -BeGreaterThan 0 -Because ($x.Lines -join ' / ')
                @($x.Problems | ForEach-Object { $_.Outcome } | Sort-Object -Unique) | Should -Be @('busy')
                ($x.Lines -join ' / ') | Should -Match 'WARNING .* rolled back, every (row|state) kept'
                $c1 = $blk.CreateCommand(); $c1.CommandText = 'ROLLBACK;'; [void]$c1.ExecuteNonQuery()
            } finally { $blk.Dispose() }
            Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingState' | Should -Be $states0
            Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingStateMember' | Should -Be $members0

            Step 'retention: the window'
            # 2. the idle window: #1317 empties c1 / c2 (c3 is published), then the history leaves by partition
            $h = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 2 -Migrate $false -BatchSize 3 -Sleep { param($ms) }
            $txt = ($h.Lines -join ' / ')
            $h.Status | Should -Not -Be 'failed' -Because $txt
            @($h.History.Collections | ForEach-Object { [long]$_ } | Sort-Object) | Should -Be @($ids[0], $ids[1]) -Because $txt
            foreach ($c in $ids[0], $ids[1]) {
                Count $inv "SELECT COUNT_BIG(*) FROM sidata.FindingStateMember WHERE CollectionId = $c" | Should -Be 0
                Count $inv "SELECT COUNT_BIG(*) FROM sidata.HistoryRun WHERE CollectionId = $c" | Should -Be 0
            }
            Count $inv "SELECT COUNT_BIG(*) FROM sidata.FindingStateMember WHERE CollectionId = $($ids[2])" | Should -Be 50 -Because 'the published collection''s history is never removed'
            # ONLY the unreferenced states went: every state a member holds is there, no state without a member is left
            Orphans $inv | Should -Be 0
            Unheld $inv | Should -Be 0 -Because $txt
            Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingState' | Should -Be $held
            Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingState' | Should -Be ($states0 - $only12)
            $h.History.Moved | Should -Be 10 -Because 'the shared states were still held: moved forward'
            Count $inv ("SELECT COUNT_BIG(*) FROM sidata.FindingState WHERE HomeCollectionId < {0}" -f $ids[2]) | Should -Be 0
            $txt | Should -Match 'moved forward first \(checksum the same'
            foreach ($c in $ids[2..4]) { (Sum $inv $c 'history') | Should -Be $keep[$c] -Because "collection $c is given back exactly as before" }
            foreach ($c in $ids[3..4]) { Assert-Same $inv $c "kept collection $c" }
            foreach ($c in $ids[0], $ids[1]) { HasBoundary $inv $c | Should -BeFalse -Because 'a range the history left is folded once every table is empty there' }
            HasBoundary $inv $ids[2] | Should -BeTrue
            # nothing more to do: a second window changes nothing
            $h2 = Invoke-SIHistoryPartitionRetention -Invoke $upd -Days 30
            $h2.Status | Should -Be 'nothing' -Because ($h2.Lines -join ' / ')
            Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingState' | Should -Be $held
        } finally { Remove-TestDb $d.Name }
    }

    It 'MIGRATION INTERRUPTED + RESUMED = IDENTICAL CHECKSUM: stopped every few ranges (writing and comparing), resumed each window, the same as the stored rows and as an uninterrupted migration' {
        $a = New-TestDb 'sihs_migA_'; $b = New-TestDb 'sihs_migB_'
        try {
            $now = [datetime]::UtcNow
            foreach ($d in $a, $b) { Initialize-Estate $d; foreach ($k in 1..3) { $null = Add-Collection $d.Invoke $now.AddDays(-4 + $k) 240 $k -Shared 90 } }
            $ids = @(& $a.Invoke "SELECT CollectionId FROM sidata.Collection ORDER BY CollectionId" @{} 'reader' | ForEach-Object { $_ } | ForEach-Object { [long]$_['CollectionId'] })
            # A: the update's / the job's bounded step (a pooled connection: many windows; B runs as the updater's identity), stopped by "an update wants to go" every 5th question
            $q = [pscustomobject]@{ N = 0 }
            $stop = { $q.N++; if ($q.N % 5 -eq 0) { 'an update wants to go' } else { '' } }.GetNewClosure()
            $lines = New-Object System.Collections.Generic.List[string]
            $n = 0; $last = $null
            do {
                $n++
                $last = Invoke-SIHistoryMigrationStep -Invoke $a.Invoke -DeadlineUtc ([datetime]::UtcNow.AddMinutes(10)) -ShouldStop $stop -Log { param($m) $lines.Add($m) }.GetNewClosure() -FirstSize 29
                if ($n % 10 -eq 0) { Step ("migration: window {0}, {1}" -f $n, $last.Status) }
            } while ($last.Status -ne 'ok' -and $n -lt 150)
            $last.Status | Should -Be 'ok' -Because (($lines | Select-Object -Last 8) -join "`n")
            $n | Should -BeGreaterThan 10 -Because 'it was interrupted many times'
            $all = $lines -join "`n"
            $all | Should -Match 'finding\(s\) written \(\d+ %\), stopped \(an update wants to go\); the next window goes on from there'
            $all | Should -Match 'written, [\d,]+ of [\d,]+ finding\(s\) compared \(\d+ %\), stopped \(an update wants to go\)'
            $all | Should -Match '3 of 3 kept collection\(s\) verified by checksum'
            Step ("migration: interrupted run done after {0} window(s)" -f $n)
            # B: the same estate, one window, never stopped
            $rb = Invoke-SIHistoryMigrationStep -Invoke $b.Updater -DeadlineUtc ([datetime]::UtcNow.AddMinutes(10)) -FirstSize 29
            $rb.Status | Should -Be 'ok'
            foreach ($c in $ids) {
                [string](& $a.Invoke "SELECT State FROM sidata.HistoryRun WHERE CollectionId = $c" @{} 'scalar') | Should -Be 'verified'
                $stored = Sum $a.Invoke $c 'stored'
                (Sum $a.Invoke $c 'history') | Should -Be $stored -Because "collection ${c}: the history is the stored rows"
                [string](& $a.Invoke "SELECT SumHistory FROM sidata.HistoryRun WHERE CollectionId = $c" @{} 'scalar') | Should -Be $stored -Because 'the checksum the resumed compare added up is the whole collection''s'
                [string](& $a.Invoke "SELECT SumStored FROM sidata.HistoryRun WHERE CollectionId = $c" @{} 'scalar') | Should -Be $stored
                (Sum $b.Invoke $c 'history') | Should -Be $stored -Because 'interrupted + resumed = uninterrupted'
                Count $a.Invoke "SELECT COUNT_BIG(*) FROM sidata.FindingStateMember WHERE CollectionId = $c" | Should -Be 240
                Assert-Same $a.Invoke $c "migrated collection $c"
            }
            Count $a.Invoke 'SELECT COUNT_BIG(*) FROM sidata.FindingState' | Should -Be (Count $b.Invoke 'SELECT COUNT_BIG(*) FROM sidata.FindingState') -Because 'no state was made twice by a resume'
        } finally { Remove-TestDb $a.Name; Remove-TestDb $b.Name }
    }

    It 'A LOCK HELD BY A RUN BLOCKS THE MIGRATION STEP -- before it starts and in the middle; the job''s own lock and a stale run lock do not' {
        $d = New-TestDb 'sihs_lock_'
        $contract = Get-SIDataHistoryContract; $every = $contract.StopEverySeconds
        try {
            $inv = $d.Invoke; $upd = $d.Updater
            Initialize-Estate $d
            $now = [datetime]::UtcNow
            $ids = @(); foreach ($k in 1..2) { $ids += Add-Collection $inv $now.AddDays(-3 + $k) 300 $k }
            [void](& $inv "IF SCHEMA_ID(N'cfg') IS NULL EXEC (N'CREATE SCHEMA cfg'); IF OBJECT_ID(N'cfg.PipelineLock') IS NULL CREATE TABLE cfg.PipelineLock (LockId NVARCHAR(32) NOT NULL PRIMARY KEY, Holder NVARCHAR(128) NULL, What NVARCHAR(200) NULL, FlowRunId NVARCHAR(64) NULL, AcquiredUtc DATETIME2(0) NULL, HeartbeatUtc DATETIME2(0) NULL); IF NOT EXISTS (SELECT 1 FROM cfg.PipelineLock WHERE LockId = N'install') INSERT cfg.PipelineLock (LockId) VALUES (N'install');" @{} 'nonquery')
            $runLock = "UPDATE cfg.PipelineLock SET Holder = N'flow:daily:run-1', What = N'the daily run', FlowRunId = N'run-1', HeartbeatUtc = SYSUTCDATETIME() WHERE LockId = N'install';"
            # 1. a run holds the lock: nothing is written, said in one line -- also through the job's partition step
            [void](& $inv $runLock @{} 'nonquery')
            $lines = New-Object System.Collections.Generic.List[string]
            $r = Invoke-SIHistoryMigrationStep -Invoke $upd -Log { param($m) $lines.Add($m) }.GetNewClosure()
            $r.Status | Should -Be 'waiting'
            ($lines -join ' ') | Should -Match 'the migration of the finding history waits -- a pipeline run holds the install''s lock; nothing was written'
            Count $inv 'SELECT COUNT_BIG(*) FROM sidata.HistoryRun' | Should -Be 0
            Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingStateMember' | Should -Be 0
            $h = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 2 -Sleep { param($ms) }
            ($h.Lines -join ' / ') | Should -Match 'a pipeline run holds the install''s lock'
            $h.Status | Should -Be 'progress'
            Count $inv 'SELECT COUNT_BIG(*) FROM sidata.FindingStateMember' | Should -Be 0
            # 2. the job's (or an update's) own lock -- no run id -- and a STALE run lock do not block
            [void](& $inv "UPDATE cfg.PipelineLock SET Holder = N'caj-si-index-build:x', FlowRunId = NULL, HeartbeatUtc = SYSUTCDATETIME() WHERE LockId = N'install';" @{} 'nonquery')
            Test-SIDataHistoryRunHoldsLock -Invoke $upd | Should -BeFalse
            [void](& $inv "UPDATE cfg.PipelineLock SET Holder = N'flow:daily:run-0', FlowRunId = N'run-0', HeartbeatUtc = DATEADD(minute, -20, SYSUTCDATETIME()) WHERE LockId = N'install';" @{} 'nonquery')
            Test-SIDataHistoryRunHoldsLock -Invoke $upd | Should -BeFalse
            Step 'lock: mid-migration'
            # 3. a run takes the lock IN THE MIDDLE of the migration: it stops at the next range, at its mark
            $contract.StopEverySeconds = 0
            $st = [pscustomobject]@{ N = 0 }; $inner = $upd; $own = $inv; $take = $runLock
            $taking = { param($s, $p, $m) if ([string]$s -match 'INSERT sidata\.FindingStateMember') { $st.N++; if ($st.N -eq 3) { [void](& $own $take @{} 'nonquery') } }; & $inner $s $p $m }.GetNewClosure()
            $lines.Clear()
            $r2 = Invoke-SIHistoryMigrationStep -Invoke $taking -Log { param($m) $lines.Add($m) }.GetNewClosure() -FirstSize 40
            $r2.Status | Should -Be 'progress' -Because ($lines -join "`n")
            ($lines -join ' ') | Should -Match 'stopped \(a pipeline run holds the install''s lock\); the next window goes on from there'
            $mark = [long](& $inv "SELECT UptoFindingId FROM sidata.HistoryRun WHERE CollectionId = $($ids[0]) AND State = N'writing'" @{} 'scalar')
            $mark | Should -BeGreaterThan 0
            $m0 = Count $inv "SELECT COUNT_BIG(*) FROM sidata.FindingStateMember WHERE CollectionId = $($ids[0])"
            $m0 | Should -BeLessThan 300
            $m0 | Should -Be (Count $inv "SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = $($ids[0]) AND FindingId <= $mark") -Because 'every finding up to the mark is a member, none after it (each range whole)'
            # the run ends (its lock released): the next window goes on from the mark and ends verified
            [void](& $inv "UPDATE cfg.PipelineLock SET Holder = NULL, FlowRunId = NULL, HeartbeatUtc = NULL WHERE LockId = N'install';" @{} 'nonquery')
            $r3 = Invoke-SIHistoryMigrationStep -Invoke $upd -FirstSize 40
            $r3.Status | Should -Be 'ok'
            foreach ($c in $ids) { [string](& $inv "SELECT State FROM sidata.HistoryRun WHERE CollectionId = $c" @{} 'scalar') | Should -Be 'verified'; Assert-Same $inv $c "collection $c" }
            # an expired window says so and writes nothing
            $r4 = Invoke-SIDataHistory -Invoke $upd -Mode 'on' -Log $script:Quiet -OutsideRun -DeadlineUtc ([datetime]::UtcNow.AddSeconds(-1))
            $r4.Status | Should -Be 'waiting'
        } finally { $contract.StopEverySeconds = $every; Remove-TestDb $d.Name }
    }
}
