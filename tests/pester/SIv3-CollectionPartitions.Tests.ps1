#Requires -Version 5.1
<#
    RETENTION BY PARTITION PER COLLECTION (REQUIREMENTS #1317, SCALE-2 #1314 (6f); first built offline 2026-11-01 as #1038 part 2
    on the branch si-v3-design/finding-partitions, brought forward 2026-11-23). The clean-up removes ~7,000 rows per 5-minute
    wake-up in paced key ranges; at the large installs millions wait. With SI_Data_RetireByPartition on (the DEFAULT -- owner 2026-11-23), a
    retired collection leaves by its own partition in seconds.

    What these tests keep true:
      * the schema: the partition function / scheme (empty, guarded) BEFORE the large tables; a new install's sidata.Finding,
        sidata.Recommendation and sidata.IssueContext ON the scheme; additive; NO procedure that runs as the owner and NO grant
        (the engine identity's rights are unchanged);
      * THE SWITCH: ON by default (not set = on), read only by the pipeline runner; set off = nothing partition-related runs and
        the paced removal (#1063 / #1315) removes rows exactly as before -- also on a partitioned new install;
      * THE GUARD (the index build job, the UPDATER's identity -- db_ddladmin + reader + writer, no VIEW DATABASE STATE): a
        collection leaves by its partition only when marked, never the published one, the newest, the one before it or a kept
        one (also when someone marked them); counts read before and after; a collection sharing its partition is left to the
        paced removal (the fallback), which still removes it;
      * THE CONVERSION of an existing install: copies the kept collections only, resumes after a lost connection and after
        a stop (an update wants to go), copies again what a run changed, swaps only on equal counts, checks later, drops later;
      * the job and the runner: an update goes first, one outcome line, the same idle-window rule as a resumable index.
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
    $script:Quiet = { param($l, $m) }
    function script:New-LocalInvoke([string]$Db, [string]$AsUser = '') {
        # an impersonating connection is never pooled: a pooled session that still carries EXECUTE AS cannot be reset
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
    # a database with the release's schema (-Unpartitioned: the large tables as an install made before the partitions has
    # them), and a user with exactly the UPDATER's database roles -- what the index build job runs as
    function script:New-TestDb([string]$Prefix, [switch]$Unpartitioned) {
        $db = $Prefix + [guid]::NewGuid().ToString('N').Substring(0, 8)
        [void](& (New-LocalInvoke 'master') "CREATE DATABASE [$db]" @{} 'nonquery')
        $inv = New-LocalInvoke $db
        $sql = $script:Schema
        if ($Unpartitioned) { $sql = $sql.Replace(') ON PS_SICollection (CollectionId);', ');') }
        [void](& $inv $sql @{} 'nonquery')
        [void](& $inv "CREATE USER si_test_updater WITHOUT LOGIN; ALTER ROLE db_ddladmin ADD MEMBER si_test_updater; ALTER ROLE db_datareader ADD MEMBER si_test_updater; ALTER ROLE db_datawriter ADD MEMBER si_test_updater;" @{} 'nonquery')
        [pscustomobject]@{ Name = $db; Invoke = $inv; Updater = (New-LocalInvoke $db 'si_test_updater') }
    }
    function script:Remove-TestDb([string]$Db) { try { [void](& (New-LocalInvoke 'master') "ALTER DATABASE [$Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$Db]" @{} 'nonquery') } catch { } }
    # one Detailed collection the way the data sync makes it, with -Rows findings, recommendations and issue rows
    function script:Add-Collection($Inv, [string]$Time, [int]$Rows, [string]$Status = 'Complete') {
        $cid = [int](@(& $Inv (Get-SIDataNewCollectionSql) @{ CollectionTime = $Time; Kind = 'Detailed'; RunId = ''; SolutionVersion = '3.0.test' } 'scalar') | Select-Object -Last 1)
        & $Inv @"
SET NOCOUNT ON;
DECLARE @c int = $cid;
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, Severity, Tier, RiskScore, DetailJson)
SELECT TOP ($Rows) @c, CONCAT(N'a', n.i), CONCAT(N'srv-', n.i), N'R', N'High', 1, n.i, CONCAT(N'{"i":', n.i, N'}')
FROM (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS i FROM sys.all_objects AS a CROSS JOIN sys.all_objects AS b) AS n;
INSERT sidata.Recommendation (CollectionId, AssetKey, RecommendationId, Name, Severity, Tier)
SELECT TOP ($Rows) @c, CONCAT(N'a', n.i), CONCAT(N'rec', n.i), N'n', N'High', 1
FROM (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS i FROM sys.all_objects AS a CROSS JOIN sys.all_objects AS b) AS n;
INSERT sidata.IssueContext (CollectionId, IssueKey, Findings, Assets, AssetNamesShown)
SELECT TOP ($Rows) @c, CONCAT(N'CVE-', n.i), 1, 1, 1
FROM (SELECT ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) - 1 AS i FROM sys.all_objects AS a CROSS JOIN sys.all_objects AS b) AS n;
UPDATE sidata.Collection SET Status = N'$Status', [Rows] = $Rows WHERE CollectionId = @c;
"@ @{} 'nonquery' | Out-Null
        $cid
    }
    function script:Count($Inv, [string]$Sql) { [long](& $Inv $Sql @{} 'scalar') }
    # the rows of a move's own copy table (0 when it is not there) -- what the stop seams read; they run INSIDE the move's
    # functions (whose $inv is a culture), so they read the test database from $script:SiTestDb, never from $inv
    function script:CopyRows([string]$Table) { [long](& $script:SiTestDb ("SELECT CASE WHEN OBJECT_ID(N'sidata.{0}') IS NULL THEN 0 ELSE (SELECT COUNT(*) FROM sidata.{0}) END" -f $Table) @{} 'scalar') }
    function script:Rows3($Inv, [int]$C) { '{0}/{1}/{2}' -f (Count $Inv "SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = $C"), (Count $Inv "SELECT COUNT(*) FROM sidata.Recommendation WHERE CollectionId = $C"), (Count $Inv "SELECT COUNT(*) FROM sidata.IssueContext WHERE CollectionId = $C") }
    function script:Boundaries($Inv) { @(& $Inv "SELECT CONVERT(int, v.value) AS V FROM sys.partition_range_values AS v JOIN sys.partition_functions AS f ON f.function_id = v.function_id WHERE f.name = N'PF_SICollection' ORDER BY v.boundary_id" @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { [int]$_['V'] }) }
    function script:Partitioned($Inv, [string]$Table) { (Count $Inv ("SELECT COUNT(*) FROM sys.indexes AS i JOIN sys.partition_schemes AS s ON s.data_space_id = i.data_space_id WHERE s.name = N'PS_SICollection' AND i.object_id = OBJECT_ID(N'sidata.{0}') AND i.index_id IN (0, 1)" -f $Table)) -eq 1 }
    function script:Mark($Inv, [int]$C, [string]$Why = 'superseded') { [void](& $Inv ("UPDATE sidata.Collection SET RetiredAt = DATEADD(minute, -5, SYSUTCDATETIME()), RetiredWhy = N'{1}' WHERE CollectionId = {0}" -f $C, $Why) @{} 'nonquery') }
}

Describe 'the schema: the partition scheme, additive, no procedure and no grant' {
    It 'creates the empty partition function and scheme BEFORE the large tables, guarded, and the tables of a new install on it' {
        $pf = $script:Schema.IndexOf("CREATE PARTITION FUNCTION PF_SICollection (INT) AS RANGE RIGHT FOR VALUES ()")
        $pf | Should -BeGreaterThan 0
        $script:Schema | Should -Match "IF \(SELECT COUNT\(\*\) FROM sys\.partition_functions WHERE name = N'PF_SICollection'\) = 0"
        $script:Schema | Should -Match "IF \(SELECT COUNT\(\*\) FROM sys\.partition_schemes WHERE name = N'PS_SICollection'\) = 0"
        $pf | Should -BeLessThan $script:Schema.IndexOf('CREATE TABLE sidata.Finding (')
        foreach ($t in 'Finding', 'Recommendation', 'IssueContext') {
            $body = [regex]::Match($script:Schema, "(?s)CREATE TABLE sidata\.$t \((.*?)\r?\n\)( ON PS_SICollection \(CollectionId\))?;")
            $body.Groups[2].Success | Should -BeTrue -Because "a new install's $t is created on the scheme"
        }
        $script:Schema | Should -Match "CREATE TABLE sidata\.PartitionMove \("
        $script:Schema | Should -Match "CREATE TABLE sidata\.PartitionMoveTouched \("
    }
    It 'stays additive, makes no procedure that runs as the owner and grants nothing -- the engine identity''s rights are unchanged' {
        (Test-SISchemaIsAdditive -Sql $script:Schema).IsAdditive | Should -BeTrue
        $script:Schema | Should -Not -Match 'CollectionPartition(Ensure|Remove)'
        $script:Schema | Should -Not -Match 'TRUNCATE TABLE sidata\.(Finding|Recommendation|IssueContext)'
        . (Join-Path $script:Root 'engine\pro-settings\SI-EngineGrants.ps1')
        $gl = Get-SIEngineGrantList   # one array (the function writes it whole): piped from a variable, row by row
        @($gl | Where-Object { [string]$_.Target -match 'Partition' -and $_.Kind -ne 'deny' }).Count | Should -Be 0 -Because 'no new right for the engine'
        # defense in depth: the engine may never write the move's record or its touched collections (it only reads them)
        @($gl | Where-Object { [string]$_.Target -match 'Partition' } | ForEach-Object { '{0} {1}' -f $_.Target, $_.Permission } | Sort-Object) |
            Should -Be @('sidata.PartitionMove DELETE', 'sidata.PartitionMove INSERT', 'sidata.PartitionMove UPDATE', 'sidata.PartitionMoveTouched DELETE', 'sidata.PartitionMoveTouched INSERT', 'sidata.PartitionMoveTouched UPDATE')
        Get-SIEngineGrantSql | Should -Match ([regex]::Escape("IF OBJECT_ID(N'sidata.PartitionMove') IS NOT NULL EXEC (N'DENY INSERT, UPDATE, DELETE ON OBJECT::sidata.PartitionMove TO [si_engine]');"))
        Get-SIEngineGrantSql | Should -Match ([regex]::Escape("IF OBJECT_ID(N'sidata.PartitionMoveTouched') IS NOT NULL EXEC (N'DENY INSERT, UPDATE, DELETE ON OBJECT::sidata.PartitionMoveTouched TO [si_engine]');"))
        Test-SIEngineNotEngineCode -File 'engine/pro-settings/SI-ProPartitionMove.ps1' -Function 'Invoke-SIPartitionHousekeeping' | Should -BeTrue
    }
}

Describe 'the switch SI_Data_RetireByPartition: ON by default, and off is today''s behaviour' {
    It 'is in the catalog: a bool, ON by default, community, in "How long data is kept" -- no off-by-default / REMOVE-ME note' {
        $c = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'config\settings.catalog.locked.json') | ConvertFrom-Json
        $s = @($c.settings | Where-Object { $_.name -eq 'SI_Data_RetireByPartition' })
        $s.Count | Should -Be 1
        $s[0].type | Should -Be 'bool'
        $s[0].defaultText | Should -Match '^On:'
        $s[0].info.default | Should -Match '^On:'
        $s[0].edition | Should -Be 'community'
        ($s[0].description + $s[0].purpose + $s[0].info.what) | Should -Not -Match 'REMOVE-ME'
        $s[0].description | Should -Match 'On \(the default\)'
        $s[0].card | Should -Be 'How long data is kept'
        [IO.File]::ReadAllText((Join-Path $script:Root 'config\SecurityInsight.custom.reference.ps1')) | Should -Match '(?m)^# \$global:SI_Data_RetireByPartition = \$true'
    }
    It 'DEFAULT ON: not set = on; off only for a real no (both copies of the rule)' {
        foreach ($f in @({ param($v) Test-SIPartitionSwitchOn -Value $v }, { param($v) Test-SIIndexBuildPartitionSwitch -Value $v })) {
            foreach ($v in @($null, '', $true, 1, '1', 'true', 'On', 'yes')) { & $f $v | Should -BeTrue -Because "'$v'" }
            foreach ($v in @($false, 0, '0', 'false', 'OFF', 'no', '$false')) { & $f $v | Should -BeFalse -Because "'$v'" }
        }
    }
    It 'DEFAULT ON in the runner: with the setting not set the runner asks for partition work; set off it does not' {
        $sb = [scriptblock]::Create('param($g) $ptWork = $false; $asked = $false; if (Test-SIIndexBuildPartitionSwitch -Value $g) { $asked = $true }; $asked')
        & $sb $null | Should -BeTrue
        & $sb $false | Should -BeFalse
        & $sb 'off' | Should -BeFalse
    }
    It 'set off = today''s behaviour: the runner reads partition work ONLY behind the switch, the paced removal and the new-collection statements carry no partition code' {
        $script:Runner | Should -Match '(?s)if \(Test-SIIndexBuildPartitionSwitch -Value \$global:SI_Data_RetireByPartition\) \{\s+try \{ \$ptWork = \[int\]\(& \$proStore\.Invoke \(Get-SIPartitionWorkSql\)'
        $script:Runner | Should -Match '\$ptWork = \$false'
        $script:Runner | Should -Match 'if \(-not \$ixDec\.Start -and \$ptWork\)'
        $script:Runner | Should -Match "SI_INDEXBUILD_PARTITIONS = '1'"
        (Get-Command Invoke-SIDataCollectionRetention).Definition | Should -Not -Match 'TRUNCATE TABLE|WITH \(PARTITIONS|PF_SICollection|SIPartition|PartitionMove|CollectionPartition(Ensure|Remove)'
        (Get-Command Invoke-SIDataRetireRangeDelete).Definition | Should -Not -Match '(?i)TRUNCATE'
        Get-SIDataNewCollectionSql | Should -Not -Match 'PF_SICollection|CollectionPartition|SPLIT RANGE'
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\_shared\RA-SqlStream.ps1'))
        $ra | Should -Not -Match 'CollectionPartition'

    }
}

Describe 'the statements and the pure parts' {
    It 'every name the move puts into a statement is bracket-quoted with '']'' doubled -- the foreign keys'' names from the catalog too' {
        $def = (Get-Command Invoke-SIProPartitionMoveTable).Definition
        $def | Should -Not -Match '\[\{\d\}\]\.\[\{\d\}\]' -Because 'never a raw [{n}].[{n}] around a catalog name'
        $def | Should -Not -Match 'REFERENCES \[\{' -Because 'the referenced schema / table are quoted by the helper'
        $def | Should -Match "\`$qn = \{ param\(\`$s\) '\[' \+ \(\[string\]\`$s\)\.Replace\('\]', '\]\]'\) \+ '\]' \}"
        $def | Should -Match 'REFERENCES \{4\}\.\{5\} \(\{6\}\)'
        foreach ($fn in 'Get-SIPartitionMoveResetSql', 'Get-SIPartitionMoveColumnstoreDropSql') { (Get-Command $fn).Definition | Should -Match "Replace\(''\]'', ''\]\]''\)|Replace\('\]', '\]\]'\)" -Because "$fn quotes its names" }
        $names = [pscustomobject]@{ Table = 'Finding'; Copy = 'Fin]ding_Partitioned'; Live = 'sidata.Finding' }
        Get-SIPartitionMoveResetSql -Names $names | Should -Match ([regex]::Escape('FROM sidata.[Fin]]ding_Partitioned] WHERE'))
    }
    It 'the removal: the guard inside one transaction under the publisher''s lock, counts before and after, roll back on any difference' {
        $s = Get-SIPartitionRemoveSql
        $s | Should -Match "sp_getapplock @Resource = N'sidata\.PublishedRun', @LockMode = N'Shared'"
        $s | Should -Match 'm\.RetiredAt IS NOT NULL'
        $s | Should -Match 'x\.DetailedCollectionId = @c'
        $s | Should -Match 'sidata\.vPublishedCollection'
        $s | Should -Match "y\.Status = N'Complete' AND y\.RetiredAt IS NULL AND y\.CollectionTime > @ct\) < 2"
        $s | Should -Match "Name = N'keep-collections'"
        $s | Should -Match 'CollectionReportCarry'
        $s.IndexOf('BEGIN TRANSACTION') | Should -BeLessThan $s.IndexOf('TRUNCATE TABLE')
        $s.IndexOf('IF @fp <> @fc') | Should -BeLessThan $s.IndexOf('TRUNCATE TABLE')
        $s | Should -Match "IF @fa <> 0 OR @ra <> 0 OR @ia <> 0 OR @fo2 <> @fo OR @ro2 <> @ro OR @io2 <> @io"
        $s | Should -Match "IF @outcome = N'truncated' COMMIT TRANSACTION; ELSE IF XACT_STATE\(\) <> 0 ROLLBACK TRANSACTION;"
        $s | Should -Not -Match 'dm_db_partition_stats' -Because 'the job''s identity has no VIEW DATABASE STATE'
        (Get-SIPartitionAheadSql) | Should -Match '@v > @top' -Because 'a boundary is cut only above every row (no row moves)'
        (Get-SIPartitionMoveSplitSql) | Should -Not -Match 'dm_db_partition_stats'
    }
    It 'Invoke-SIPartitionRemove never throws, and counts rows only when the partition WAS emptied' {
        (Invoke-SIPartitionRemove -Invoke { throw 'down' } -CollectionId '5').Outcome | Should -Be 'failed'
        $r = Invoke-SIPartitionRemove -Invoke { , @(@{ Outcome = 'not-alone'; Findings = 99; Recommendations = 9; IssueRows = 9; Merged = 0 }) } -CollectionId '5'
        $r.Findings | Should -Be 0
        $r = Invoke-SIPartitionRemove -Invoke { , @(@{ Outcome = 'truncated'; Findings = 99; Recommendations = 9; IssueRows = 3; Merged = 1 }) } -CollectionId '5'
        $r.Findings | Should -Be 99; $r.Merged | Should -Be 1
    }
    It 'the move''s plan: retired collections are never copied; a changed one or one with too many rows starts over; ready only when every kept one is exact' {
        $rows = @(
            @{ CollectionId = 1; Old = 100; Copied = 0;  Kept = 0; Touched = 0 },
            @{ CollectionId = 2; Old = 50;  Copied = 50; Kept = 1; Touched = 0 },
            @{ CollectionId = 3; Old = 50;  Copied = 50; Kept = 1; Touched = 1 },
            @{ CollectionId = 4; Old = 50;  Copied = 20; Kept = 1; Touched = 0 },
            @{ CollectionId = 5; Old = 10;  Copied = 12; Kept = 1; Touched = 0 })
        $p = Get-SIPartitionMovePlan -Rows $rows
        @($p.Done) | Should -Be @(2)
        @($p.Copy) | Should -Be @(3, 4, 5)
        @($p.Reset) | Should -Be @(3, 5)
        $p.ScopeRows | Should -Be 160
        $p.Ready | Should -BeFalse
    }
    It 'the move''s key, aligned indexes, copy (with the documents out of the row) and swap' {
        $cols = @(@{ Name = 'CollectionId'; TypeName = 'int'; MaxLength = 4; Prec = 10; Scale = 0 }, @{ Name = 'FindingId'; TypeName = 'bigint'; MaxLength = 8; Prec = 19; Scale = 0 }, @{ Name = 'IssueKey'; TypeName = 'nvarchar'; MaxLength = 512; Prec = 0; Scale = 0 })
        $ix = ConvertTo-SIPartitionMoveIndexes -Rows @(@{ Name = 'PK_Finding'; Type = 1; Uq = 1; Pk = 1; HasFilter = 0; Filter = $null; Col = 'CollectionId'; KeyOrd = 1; Incl = 0; Descending = 0 }, @{ Name = 'PK_Finding'; Type = 1; Uq = 1; Pk = 1; HasFilter = 0; Filter = $null; Col = 'FindingId'; KeyOrd = 2; Incl = 0; Descending = 0 })
        $k = Get-SIPartitionMoveKey -Indexes $ix -Columns $cols
        $k.Ok | Should -BeTrue; $k.Column | Should -Be 'FindingId'
        (Format-SIPartitionMoveColumnType -Column @{ TypeName = 'xml'; MaxLength = -1 }) | Should -BeNullOrEmpty
        $f = ConvertTo-SIPartitionMoveIndexes -Rows @(
            @{ Name = 'IX_Finding_RaOrder'; Type = 2; Uq = 0; Pk = 0; HasFilter = 1; Filter = '([RaSeq] IS NOT NULL)'; Col = 'CollectionId'; KeyOrd = 1; Incl = 0; Descending = 0 },
            @{ Name = 'IX_Finding_RaOrder'; Type = 2; Uq = 0; Pk = 0; HasFilter = 1; Filter = '([RaSeq] IS NOT NULL)'; Col = 'RaSort'; KeyOrd = 2; Incl = 0; Descending = 1 },
            @{ Name = 'IX_Finding_RaOrder'; Type = 2; Uq = 0; Pk = 0; HasFilter = 1; Filter = '([RaSeq] IS NOT NULL)'; Col = 'RaReport'; KeyOrd = 0; Incl = 1; Descending = 0 })
        Get-SIPartitionMoveIndexSql -Index $f[0] -Copy 'Finding_Partitioned' | Should -Be 'CREATE NONCLUSTERED INDEX [IX_Finding_RaOrder] ON sidata.[Finding_Partitioned] ([CollectionId], [RaSort] DESC) INCLUDE ([RaReport]) WHERE ([RaSeq] IS NOT NULL) ON PS_SICollection ([CollectionId]);'
        $n = Get-SIPartitionMoveNames -Table Finding
        (Get-SIPartitionMoveLobSql -Names $n) | Should -Match "sp_tableoption @TableNamePattern = N'sidata\.Finding_Partitioned', @OptionName = N'large value types out of row'"
        $s = Get-SIPartitionMoveSwapSql -Names $n -Key $k -Identity $true
        $s.IndexOf('WITH (TABLOCKX, HOLDLOCK)') | Should -BeLessThan $s.IndexOf('sp_rename')
        $s.IndexOf('IF @chg > 0') | Should -BeLessThan $s.IndexOf('sp_rename')
        $s | Should -Not -Match 'COUNT_BIG' -Because 'under the exclusive lock only the trigger''s notes are read (the rows were compared before it)'
        (Get-SIPartitionMovePreflightSql) | Should -Match 'is_schema_bound_reference = 1'
    }
}

Describe 'the index build job''s partition run and the runner''s window' {
    BeforeAll {
        function script:New-Seams([string]$Update = '', [string]$Status = 'done', [ref]$Called) {
            $calls = $Called
            @{
                UpdateFirst  = { $Update }.GetNewClosure()
                OtherRunning = { '' }
                Gate         = { param($h) [pscustomobject]@{ Go = $true; Reason = ''; LockTaken = $true } }
                Beat         = { param($h, $w) $true }
                ExitGate     = { param($h) $true }
                Partitions   = { param($d, $s, $k) if ($calls) { $calls.Value++ }; [pscustomobject]@{ Status = $Status; Removed = @(1, 2); Left = @(3); Lines = @() } }.GetNewClosure()
            }
        }
        $script:Req = [pscustomobject]@{ Table = ''; Index = ''; Minutes = 30; Force = $false; Partitions = $true; Keep = 3 }
        $script:Store = [pscustomobject]@{ Invoke = { param($s, $p, $m) }; Open = { } }
    }
    It 'a start for the partitions runs them, holds the lock, and ends with ONE outcome line (done -> built, progress -> paused)' {
        $n = 0; $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIIndexBuildJob -Store $script:Store -Holder 'h' -Request $script:Req -Seams (New-Seams -Called ([ref]$n)) -Log { param($m) $lines.Add($m) }
        $n | Should -Be 1
        $r.Outcome | Should -Be 'built'
        $r.ExitCode | Should -Be 0
        @($lines | Where-Object { $_ -match '^INDEX-BUILD outcome=built index=collection-partitions$' }).Count | Should -Be 1
        ($lines -join "`n") | Should -Match '2 retired collection\(s\) left by their partition, 1 left to the paced removal'
        (Invoke-SIIndexBuildJob -Store $script:Store -Holder 'h' -Request $script:Req -Seams (New-Seams -Status 'progress') -Log { param($m) }).Outcome | Should -Be 'paused'
        (Invoke-SIIndexBuildJob -Store $script:Store -Holder 'h' -Request $script:Req -Seams (New-Seams -Status 'failed') -Log { param($m) }).ExitCode | Should -Be 1
    }
    It 'THE UPDATE GOES FIRST: an update waiting = nothing done, not now' {
        $n = 0
        $r = Invoke-SIIndexBuildJob -Store $script:Store -Holder 'h' -Request $script:Req -Seams (New-Seams -Update 'an update waits' -Called ([ref]$n)) -Log { param($m) }
        $r.Outcome | Should -Be 'not-now'
        $n | Should -Be 0
    }
    It 'the stop seam the work gets says why once an update wants to go' {
        $u = [pscustomobject]@{ Why = '' }
        $seams = New-Seams; $seams.UpdateFirst = { $u.Why }.GetNewClosure(); $seams.AskSeconds = 1
        $seen = [pscustomobject]@{ Before = 'x'; After = '' }
        $seams.Partitions = { param($d, $s, $k) $seen.Before = [string](& $s); $u.Why = 'an update waits'; Start-Sleep -Seconds 2; $seen.After = [string](& $s); [pscustomobject]@{ Status = 'progress'; Removed = @(); Left = @(); Lines = @() } }.GetNewClosure()
        $null = Invoke-SIIndexBuildJob -Store $script:Store -Holder 'h' -Request $script:Req -Seams $seams -Log { param($m) }
        $seen.Before | Should -Be ''
        $seen.After | Should -Match 'an update waits'
    }
    It 'the job''s input: SI_INDEXBUILD_PARTITIONS and the keep count (at least 2)' {
        $base = @{ SI_INDEXBUILD_SERVER = 'server.database.windows.net'; SI_INDEXBUILD_DATABASE = 'sqldb-si-pro' }
        $i = Read-SIIndexBuildJobInput -Env ($base + @{ SI_INDEXBUILD_PARTITIONS = '1'; SI_INDEXBUILD_KEEP = '5' })
        $i.Request.Partitions | Should -BeTrue; $i.Request.Keep | Should -Be 5
        $i = Read-SIIndexBuildJobInput -Env ($base + @{ SI_INDEXBUILD_KEEP = '1' })
        $i.Request.Partitions | Should -BeFalse; $i.Request.Keep | Should -Be 2
    }
    It 'the runner''s window for the partitions: the same rule as a resumable index -- never while a run is due or an update waits' {
        $now = [datetime]'2026-11-23T10:00:00Z'
        $row = Get-SIPartitionWorkRow -NowUtc $now
        $d = Get-SIIndexBuildWindowDecision -Rows @($row) -NowUtc $now -NextRunUtc $now.AddHours(3) -Busy ([pscustomobject]@{ Busy = $false; Why = '' })
        $d.Start | Should -BeTrue; $d.Resumable | Should -BeTrue; $d.Minutes | Should -BeGreaterThan 0
        (Get-SIIndexBuildWindowDecision -Rows @($row) -NowUtc $now -NextRunUtc $now.AddHours(3) -RunDue $true).Start | Should -BeFalse
        (Get-SIIndexBuildWindowDecision -Rows @($row) -NowUtc $now -NextRunUtc $now.AddHours(3) -UpdateWaits 'waits').Start | Should -BeFalse
        (Get-SIIndexBuildWindowDecision -Rows @($row) -NowUtc $now -NextRunUtc $now.AddHours(3) -Busy ([pscustomobject]@{ Busy = $true; Why = 'a data sync runs' })).Start | Should -BeFalse
        [IO.File]::ReadAllText((Join-Path $script:Root 'engine\index-build\Invoke-SIIndexBuildJob.ps1')) | Should -Match "'pro-settings', 'SI-ProPartitionMove\.ps1'"
    }
}

Describe 'the update''s bounded step: a busy install (a run always going) still converts' {
    BeforeAll {
        . (Join-Path $script:Root 'container\updater\_shared\SI-UpdaterDatabase.ps1')
        $script:Upd = [IO.File]::ReadAllText((Join-Path $script:Root 'container\updater\_shared\SI-UpdaterDatabase.ps1'))
    }
    It 'the update runs it after the schema and the grants, on an update with new schema AND on one without, bounded (5 / 15 min), and says the next run may start later' {
        $script:Upd | Should -Match "'noop' \{(?s).*?Invoke-SIUpdaterPartitionStep -SIRoot \`$SIRoot -Store \`$Store -SchemaCurrent \`$true(?s).*?return \(& \`$res \`$true 'noop'"
        $script:Upd.IndexOf('Invoke-SIUpdaterPartitionStep -SIRoot $SIRoot -Store $Store -SchemaCurrent $false') | Should -BeGreaterThan $script:Upd.LastIndexOf('$null = Invoke-SIUpdaterEngineAccessCheck -SIRoot $SIRoot -Store $Store -Exclude $principals.ToArray()')
        $script:SIUpdaterPartitionMinutes.Applied | Should -Be 4
        $script:SIUpdaterPartitionMinutes.Current | Should -Be 8
        $script:Upd | Should -Match 'the next pipeline run may start up to \{0\} min later'
    }
    It 'DEFAULT ON for the updater; set off = nothing done; never fails the update' {
        $old = Get-Variable -Name SI_Data_RetireByPartition -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        try {
            Remove-Variable -Name SI_Data_RetireByPartition -Scope Global -ErrorAction SilentlyContinue
            Get-SIUpdaterPartitionSwitch -Get { param($n) '' } | Should -BeTrue
            Get-SIUpdaterPartitionSwitch -Get { param($n) 'false' } | Should -BeFalse
            $global:SI_Data_RetireByPartition = $false
            $lines = New-Object System.Collections.Generic.List[string]
            Invoke-SIUpdaterPartitionStep -SIRoot $script:Root -Store ([pscustomobject]@{ Invoke = { throw 'never called' } }) -Log { param($m) $lines.Add($m) } | Should -BeNullOrEmpty
            ($lines -join ' ') | Should -Match 'is off -- nothing done'
            $global:SI_Data_RetireByPartition = $true
            { Invoke-SIUpdaterPartitionStep -SIRoot $script:Root -Store ([pscustomobject]@{ Invoke = { throw 'down' } }) -Log { param($m) } } | Should -Not -Throw
        } finally { if ($null -ne $old) { $global:SI_Data_RetireByPartition = $old } else { Remove-Variable -Name SI_Data_RetireByPartition -Scope Global -ErrorAction SilentlyContinue } }
    }
    It 'A BUSY INSTALL: no idle window ever comes, yet update after update the bounded step moves the old tables onto the partitions, resumably, counts equal' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'sipbusy_' -Unpartitioned
        try {
            $inv = $d.Invoke
            $ids = @(); foreach ($day in 1..4) { $ids += Add-Collection $inv ('2026-10-0{0}T08:00:00' -f $day) 2000 }
            $oldCounts = @(& $inv 'SELECT CollectionId, COUNT_BIG(*) AS N FROM sidata.Finding GROUP BY CollectionId ORDER BY CollectionId' @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { '{0}:{1}' -f $_['CollectionId'], $_['N'] }) -join ','
            $store = [pscustomobject]@{ Invoke = $d.Updater }
            $lines = New-Object System.Collections.Generic.List[string]
            # update 1: a 2-second bound -- a part only
            $r1 = Invoke-SIUpdaterPartitionStep -SIRoot $script:Root -Store $store -DeadlineUtc ([datetime]::UtcNow.AddSeconds(2)) -BatchSize 50 -Log { param($m) $lines.Add($m) }
            $r1.Status | Should -Be 'progress' -Because ($lines -join ' / ')
            Count $inv "SELECT COUNT(*) FROM sidata.PartitionMove WHERE TableName IN (N'IssueContext', N'Recommendation', N'Finding')" | Should -BeGreaterThan 0 -Because 'the first update already started the move (its copy and state are in the database)'
            Partitioned $inv 'Finding' | Should -BeFalse
            ($lines -join ' / ') | Should -Match 'may start up to'
            # the next updates go on from where it stopped, until every table is on the partitions
            $n = 0
            while (-not (Partitioned $inv 'Finding') -and $n -lt 8) { $n++; $null = Invoke-SIUpdaterPartitionStep -SIRoot $script:Root -Store $store -DeadlineUtc ([datetime]::UtcNow.AddSeconds(20)) -BatchSize 500 -Log { param($m) $lines.Add($m) } }
            foreach ($t in 'Finding', 'Recommendation', 'IssueContext') { Partitioned $inv $t | Should -BeTrue -Because ($lines -join ' / ') }
            $newCounts = @(& $inv 'SELECT CollectionId, COUNT_BIG(*) AS N FROM sidata.Finding GROUP BY CollectionId ORDER BY CollectionId' @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { '{0}:{1}' -f $_['CollectionId'], $_['N'] }) -join ','
            $newCounts | Should -Be $oldCounts
        } finally { Remove-TestDb $d.Name }
    }
}

Describe 'on a real SQL Server: a new install (the tables made on the partitions)' {
    It 'THE GUARD: retired collections leave by their partition in all three tables; the published, the newest, the one before it and the kept ones never -- also when marked; counts read back' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'sipart_'
        try {
            $inv = $d.Invoke; $upd = $d.Updater; $siStopDb = $d.Invoke
            foreach ($t in 'Finding', 'Recommendation', 'IssueContext') { Partitioned $inv $t | Should -BeTrue -Because "a new install's $t is on the scheme" }
            (Boundaries $inv).Count | Should -Be 0 -Because 'created empty: nothing is cut while the switch is off'
            # the job's first idle window: the boundaries ahead (as the UPDATER's identity)
            $h0 = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 3 -Sleep { param($ms) }
            $h0.Status | Should -BeIn @('done', 'nothing') -Because ($h0.Lines -join ' / ')
            (Boundaries $inv).Count | Should -BeGreaterOrEqual 16
            $ids = @(); foreach ($day in 1..7) { $ids += Add-Collection $inv ('2026-10-0{0}T08:00:00' -f $day) 40 }
            # the published run is the SECOND oldest: kept whatever its age
            [void](& $inv ("INSERT sidata.PublishedRun (Name, DetailedCollectionId, Source, PublishedAt) VALUES (N'current', {0}, N'run', '2026-10-02T12:00:00')" -f $ids[1]) @{} 'nonquery')
            # the product's own marking (keep 3): 1, 3 and 4 are marked; 2 (published), 5, 6, 7 are kept
            $m = Invoke-SIDataCollectionRetention -Invoke $inv -Log $script:Quiet -NowUtc ([datetime]'2026-10-08T00:00:00Z') -StaleDays 0 -MarkOnly -KeepCollections 3
            $m.Status | Should -Be 'ok'
            Count $inv 'SELECT COUNT(*) FROM sidata.Collection WHERE RetiredAt IS NOT NULL' | Should -Be 3
            $reader = 'SELECT FindingId, CollectionId, AssetKey, RiskScore FROM sidata.Finding WHERE CollectionId IN (SELECT CollectionId FROM sidata.Collection WHERE RetiredAt IS NULL) ORDER BY FindingId'
            $line = { param($r) @($r | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { '{0}|{1}|{2}|{3}' -f $_['FindingId'], $_['CollectionId'], $_['AssetKey'], $_['RiskScore'] }) -join ';' }
            $before = & $line (& $inv $reader @{} 'reader')
            $total = Count $inv 'SELECT COUNT(*) FROM sidata.Finding'
            $h = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 3 -Sleep { param($ms) }
            @($h.Removed | ForEach-Object { [int]$_.CollectionId } | Sort-Object) | Should -Be @($ids[0], $ids[2], $ids[3]) -Because ($h.Lines -join ' / ')
            foreach ($r in $h.Removed) { $r.Findings | Should -Be 40; $r.Recommendations | Should -Be 40; $r.IssueRows | Should -Be 40 }
            foreach ($c in $ids[0], $ids[2], $ids[3]) { Rows3 $inv $c | Should -Be '0/0/0' }
            foreach ($c in $ids[1], $ids[4], $ids[5], $ids[6]) { Rows3 $inv $c | Should -Be '40/40/40' }
            Count $inv 'SELECT COUNT(*) FROM sidata.Finding' | Should -Be ($total - 120) -Because 'exactly the three collections'' rows went'
            (& $line (& $inv $reader @{} 'reader')) | Should -Be $before -Because 'a reader''s query returns the same rows'
            Count $inv 'SELECT COUNT(*) FROM sidata.Collection WHERE RetiredAt IS NOT NULL' | Should -Be 3 -Because 'the collection rows stay marked; the paced removal finishes them'
            # SOMEONE MARKS the published, the newest, the one before it and a kept one: the guard still refuses every one
            foreach ($c in $ids[1], $ids[4], $ids[5], $ids[6]) { Mark $inv $c }
            $h2 = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 3 -Sleep { param($ms) }
            @($h2.Removed).Count | Should -Be 0 -Because ($h2.Lines -join ' / ')
            @($h2.Left | Where-Object { $_.Outcome -ne 'refused' }).Count | Should -Be 0
            ($h2.Lines -join ' / ') | Should -Match 'published'
            foreach ($c in $ids[1], $ids[4], $ids[5], $ids[6]) { Rows3 $inv $c | Should -Be '40/40/40' }
            # the statement itself, asked directly for the newest one
            (Invoke-SIPartitionRemove -Invoke $upd -CollectionId ([string]$ids[6]) -Keep 3).Outcome | Should -Be 'refused'
        } finally { Remove-TestDb $d.Name }
    }
    It 'THE FALLBACK and SWITCH OFF: collections made before their partition share one -- left to the paced removal, which still removes them; with no boundary cut (switch off) the paced removal works exactly as before' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'sipfb_'
        try {
            $inv = $d.Invoke
            # switch off: no boundary is ever cut -- one partition, exactly as an unpartitioned table
            $ids = @(); foreach ($day in 1..5) { $ids += Add-Collection $inv ('2026-10-0{0}T08:00:00' -f $day) 25 }
            Mark $inv $ids[0]; Mark $inv $ids[1]
            $h = Invoke-SIPartitionHousekeeping -Invoke $d.Updater -Keep 2 -Sleep { param($ms) }
            @($h.Removed).Count | Should -Be 0 -Because 'the collections share the one partition made before the boundaries'
            @($h.Left | ForEach-Object { $_.Outcome } | Sort-Object -Unique) | Should -Be @('not-alone')
            Rows3 $inv $ids[0] | Should -Be '25/25/25'
            # the paced removal (the runner's wake-up, off or on) removes them, and only them
            $r = Invoke-SIDataCollectionRetention -Invoke $inv -Log $script:Quiet -NowUtc ([datetime]'2026-10-06T00:00:00Z') -StaleDays 0 -KeepCollections 2
            @($r.Removed | ForEach-Object { [int]$_.CollectionId } | Sort-Object) | Should -Be @($ids[0], $ids[1], $ids[2])
            foreach ($c in $ids[0], $ids[1], $ids[2]) { Rows3 $inv $c | Should -Be '0/0/0' }
            foreach ($c in $ids[3], $ids[4]) { Rows3 $inv $c | Should -Be '25/25/25' }
        } finally { Remove-TestDb $d.Name }
    }
}

Describe 'on a real SQL Server: converting an existing install (the old tables)' {
    It 'THE CONVERSION: kept collections only, resumes after a lost connection and after a stop, copies again what changed, swaps on equal counts, then retired collections leave by partition; checked and dropped in later windows' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'sipmove_' -Unpartitioned
        try {
            $inv = $d.Invoke; $upd = $d.Updater; $siStopDb = $d.Invoke
            Partitioned $inv 'Finding' | Should -BeFalse
            $ids = @(); foreach ($day in 1..4) { $ids += Add-Collection $inv ('2026-10-0{0}T08:00:00' -f $day) 250 }
            Mark $inv $ids[0]
            $reader = 'SELECT FindingId, CollectionId, AssetKey, AssetName, RiskScore, DetailJson FROM sidata.vCurrentFinding ORDER BY FindingId'
            $line = { param($rows) @($rows | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { '{0}|{1}|{2}|{3}|{4}|{5}' -f $_['FindingId'], $_['CollectionId'], $_['AssetKey'], $_['AssetName'], $_['RiskScore'], $_['DetailJson'] }) -join ';' }
            $maxId = Count $inv 'SELECT MAX(FindingId) FROM sidata.Finding'

            # 1. a LOST CONNECTION part way through Finding (as the updater's identity)
            $script:CopyCalls = 0
            $flaky = { param([string]$sql, $p, [string]$mode) if ($sql -match 'INSERT sidata\.\[Finding_Partitioned\]') { $script:CopyCalls++; if ($script:CopyCalls -gt 3) { throw 'the connection was lost' } }; & $upd $sql $p $mode }.GetNewClosure()
            $r1 = Invoke-SIProPartitionMove -Invoke $flaky -BudgetMinutes 30 -BatchSize 100 -Sleep { param($ms) }
            @($r1.Tables | Where-Object { $_.Table -eq 'IssueContext' })[0].State | Should -BeIn @('swapped', 'checked') -Because ($r1.Lines -join ' / ')
            @($r1.Tables | Where-Object { $_.Table -eq 'Recommendation' })[0].State | Should -BeIn @('swapped', 'checked')
            @($r1.Tables | Where-Object { $_.Table -eq 'Finding' })[0].State | Should -Be 'failed'
            Partitioned $inv 'Finding' | Should -BeFalse -Because 'the install keeps working on the old table'
            $part1 = Count $inv 'SELECT COUNT(*) FROM sidata.Finding_Partitioned'; $siP1 = $part1
            $part1 | Should -BeGreaterThan 0

            # 2. a STOP (an update wants to go) after two more ranges: resumable, said, nothing swapped
            # the stop comes once the copy has grown by a few ranges (the counts ask the seam too)
            $stop = { if ([long](& $siStopDb "IF OBJECT_ID(N'sidata.Finding_Partitioned') IS NULL SELECT 0; ELSE EXEC (N'SELECT COUNT(*) FROM sidata.Finding_Partitioned');" @{} 'scalar') -gt ($siP1 + 150)) { 'an update waits' } else { '' } }.GetNewClosure()
            $r2 = Invoke-SIProPartitionMove -Invoke $upd -BudgetMinutes 30 -BatchSize 100 -Sleep { param($ms) } -ShouldStop $stop
            $f2 = @($r2.Tables | Where-Object { $_.Table -eq 'Finding' })[0]
            $f2.State | Should -Be 'copying' -Because ($r2.Lines -join ' / ')
            $f2.StopWhy | Should -Be 'an update waits' -Because $f2.Text
            $f2.Text | Should -Match 'stopped: an update waits'
            Count $inv 'SELECT COUNT(*) FROM sidata.Finding_Partitioned' | Should -BeGreaterThan $part1 -Because 'it went on from where the copy stood'
            Partitioned $inv 'Finding' | Should -BeFalse

            # 3. a run changes a collection that was copied already (the trigger notes it) and adds a new one
            [void](& $inv ("UPDATE sidata.Finding SET RiskScore = 999 WHERE CollectionId = {0} AND AssetKey = N'a0'" -f $ids[1]) @{} 'nonquery')
            Count $inv ("SELECT COUNT(*) FROM sidata.PartitionMoveTouched WHERE TableName = N'Finding' AND CollectionId = {0}" -f $ids[1]) | Should -Be 1
            $ids += Add-Collection $inv '2026-10-05T08:00:00' 40
            $before = & $line (& $inv $reader @{} 'reader')
            $oldCounts = @(& $inv ("SELECT CollectionId, COUNT_BIG(*) AS N FROM sidata.Finding WHERE CollectionId <> {0} GROUP BY CollectionId ORDER BY CollectionId" -f $ids[0]) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { '{0}:{1}' -f $_['CollectionId'], $_['N'] }) -join ','

            # 4. the next idle window (the job's step) finishes the move and swaps
            $h = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 2 -BatchSize 100 -Sleep { param($ms) }
            @($h.Move.Tables | Where-Object { $_.Table -eq 'Finding' })[0].State | Should -BeIn @('swapped', 'checked') -Because ($h.Lines -join ' / ')
            foreach ($t in 'Finding', 'Recommendation', 'IssueContext') { Partitioned $inv $t | Should -BeTrue -Because "$t is on the scheme now" }
            $newCounts = @(& $inv ("SELECT CollectionId, COUNT_BIG(*) AS N FROM sidata.Finding WHERE CollectionId <> {0} GROUP BY CollectionId ORDER BY CollectionId" -f $ids[0]) @{} 'reader' | ForEach-Object { $_ } | Where-Object { $_ } | ForEach-Object { '{0}:{1}' -f $_['CollectionId'], $_['N'] }) -join ','
            $newCounts | Should -Be $oldCounts -Because 'every kept collection has exactly its rows'
            Count $inv ("SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = {0}" -f $ids[0]) | Should -Be 0 -Because 'the retired collection was not copied'
            Count $inv ("SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = {0} AND AssetKey = N'a0' AND RiskScore = 999" -f $ids[1]) | Should -Be 1 -Because 'the collection changed after it was copied was copied again'
            (& $line (& $inv $reader @{} 'reader')) | Should -Be $before -Because 'a reader''s query returns the same rows'
            Count $inv "SELECT COUNT(*) FROM sys.triggers WHERE name LIKE N'TR[_]%[_]PartitionMove'" | Should -Be 0
            Count $inv "SELECT COUNT(*) FROM sys.foreign_keys WHERE name = N'FK_Finding_Collection' AND parent_object_id = OBJECT_ID(N'sidata.Finding')" | Should -Be 1
            Count $inv "SELECT COUNT(*) FROM sys.tables WHERE object_id = OBJECT_ID(N'sidata.Finding') AND large_value_types_out_of_row = 1" | Should -Be 1 -Because 'the documents stay out of the row'
            $newId = Count $inv ("INSERT sidata.Finding (CollectionId, AssetKey) OUTPUT inserted.FindingId VALUES ({0}, N'new')" -f $ids[4])
            $newId | Should -BeGreaterThan $maxId -Because 'the identity goes on above every id the old table gave'
            [void](& $inv ("DELETE FROM sidata.Finding WHERE FindingId = {0}" -f $newId) @{} 'nonquery')

            # 5. retired collections now leave by their partition (the newest two and the kept ones stay)
            Mark $inv $ids[1]
            $h2 = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 2 -Sleep { param($ms) }
            @($h2.Removed | ForEach-Object { [int]$_.CollectionId }) | Should -Contain $ids[1] -Because ($h2.Lines -join ' / ')
            Rows3 $inv $ids[1] | Should -Be '0/0/0'
            foreach ($c in $ids[2], $ids[3]) { Rows3 $inv $c | Should -Be '250/250/250' }
            Rows3 $inv $ids[4] | Should -Be '40/40/40'

            # 6. a LATER window checks, the one after drops the old table
            $r3 = Invoke-SIProPartitionMove -Invoke $upd -BudgetMinutes 5 -StartedUtc ([datetime]::UtcNow.AddMinutes(2)) -Sleep { param($ms) }
            @($r3.Tables | Where-Object { $_.Table -eq 'Finding' })[0].State | Should -BeIn @('checked', 'done') -Because ('the window of step 5 may have checked it already: ' + ($r3.Lines -join ' / '))
            $r4 = Invoke-SIProPartitionMove -Invoke $upd -BudgetMinutes 5 -StartedUtc ([datetime]::UtcNow.AddMinutes(4)) -Sleep { param($ms) }
            @($r4.Tables | Where-Object { $_.Table -eq 'Finding' })[0].State | Should -Be 'done'
            Count $inv "SELECT CASE WHEN OBJECT_ID(N'sidata.Finding_Unpartitioned') IS NULL THEN 0 ELSE 1 END" | Should -Be 0
            $r4.Status | Should -Be 'done'
            # the runner's own read (the engine's identity, data only): nothing waits once every table is done and nothing is retired with rows
            Count $inv "SELECT COUNT(*) FROM sidata.PartitionMove WHERE TableName IN (N'Finding', N'Recommendation', N'IssueContext') AND State = N'done'" | Should -Be 3
        } finally { Remove-TestDb $d.Name }
    }
    It 'the ENGINE (role si_engine, its shipped grants): its write to Finding is still noted by the move''s trigger, but a direct write to the move''s record or its touched rows is refused' -Skip:(-not $script:LocalSql) {
        . (Join-Path $script:Root 'engine\pro-settings\SI-EngineGrants.ps1')
        $d = New-TestDb 'sipdeny_' -Unpartitioned
        try {
            $inv = $d.Invoke; $upd = $d.Updater
            $ids = @(); foreach ($day in 1..2) { $ids += Add-Collection $inv ('2026-10-0{0}T08:00:00' -f $day) 50 }
            # the engine's user exactly as an install has it: the role si_engine with the shipped grants and DENYs, nothing else
            [void](& $inv ("CREATE USER si_test_engine WITHOUT LOGIN;`n" + (Get-SIEngineGrantSql -UserName 'si_test_engine')) @{} 'nonquery')
            Count $inv "SELECT IS_ROLEMEMBER(N'si_engine', N'si_test_engine')" | Should -Be 1
            Count $inv "SELECT COUNT(*) FROM sys.database_permissions WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID(N'si_engine') AND state = 'D' AND major_id IN (OBJECT_ID(N'sidata.PartitionMove'), OBJECT_ID(N'sidata.PartitionMoveTouched'))" | Should -Be 6
            $eng = New-LocalInvoke $d.Name 'si_test_engine'
            # the move starts (as the index build job, the updater's identity) and stops in Finding's copy: its trigger is on the old table
            $script:DenyCopyCalls = 0
            $flaky = { param([string]$sql, $p, [string]$mode) if ($sql -match 'INSERT sidata\.\[Finding_Partitioned\]') { $script:DenyCopyCalls++; if ($script:DenyCopyCalls -gt 1) { throw 'the connection was lost' } }; & $upd $sql $p $mode }.GetNewClosure()
            $r = Invoke-SIProPartitionMove -Invoke $flaky -BudgetMinutes 30 -BatchSize 20 -Sleep { param($ms) }
            @($r.Tables | Where-Object { $_.Table -eq 'Finding' })[0].State | Should -Be 'failed' -Because ($r.Lines -join ' / ')
            Count $inv "SELECT COUNT(*) FROM sys.triggers WHERE parent_id = OBJECT_ID(N'sidata.Finding')" | Should -Be 1
            [void](& $inv "DELETE FROM sidata.PartitionMoveTouched" @{} 'nonquery')
            # 1. the engine's own write to Finding: allowed, and the trigger records the touched collection (ownership chain)
            [void](& $eng ("UPDATE sidata.Finding SET RiskScore = 777 WHERE CollectionId = {0} AND AssetKey = N'a0'" -f $ids[0]) @{} 'nonquery')
            Count $inv ("SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = {0} AND RiskScore = 777" -f $ids[0]) | Should -Be 1
            Count $inv ("SELECT COUNT(*) FROM sidata.PartitionMoveTouched WHERE TableName = N'Finding' AND CollectionId = {0}" -f $ids[0]) | Should -Be 1 -Because 'the trigger reaches the touched table through the ownership chain'
            [void](& $eng ("INSERT sidata.Finding (CollectionId, AssetKey) VALUES ({0}, N'engine-new')" -f $ids[1]) @{} 'nonquery')
            Count $inv ("SELECT COUNT(*) FROM sidata.PartitionMoveTouched WHERE TableName = N'Finding' AND CollectionId = {0}" -f $ids[1]) | Should -Be 1
            # 2. the engine may READ the record (the runner's wake-up does)
            Count $eng "SELECT COUNT(*) FROM sidata.PartitionMove WHERE TableName = N'Finding'" | Should -Be 1
            # 3. a direct write as the engine: refused, nothing changed
            $state = [string](& $inv "SELECT State FROM sidata.PartitionMove WHERE TableName = N'Finding'" @{} 'scalar')
            { & $eng "UPDATE sidata.PartitionMove SET State = N'checked' WHERE TableName = N'Finding'" @{} 'nonquery' } | Should -Throw '*denied*'
            { & $eng "INSERT sidata.PartitionMove (TableName, State) VALUES (N'Other', N'checked')" @{} 'nonquery' } | Should -Throw '*denied*'
            { & $eng "DELETE FROM sidata.PartitionMove" @{} 'nonquery' } | Should -Throw '*denied*'
            { & $eng "DELETE FROM sidata.PartitionMoveTouched" @{} 'nonquery' } | Should -Throw '*denied*'
            { & $eng "UPDATE sidata.PartitionMoveTouched SET CollectionId = 0" @{} 'nonquery' } | Should -Throw '*denied*'
            { & $eng "INSERT sidata.PartitionMoveTouched (TableName, CollectionId) VALUES (N'Finding', 0)" @{} 'nonquery' } | Should -Throw '*denied*'
            [string](& $inv "SELECT State FROM sidata.PartitionMove WHERE TableName = N'Finding'" @{} 'scalar') | Should -Be $state
            Count $inv "SELECT COUNT(*) FROM sidata.PartitionMove WHERE TableName = N'Other'" | Should -Be 0
            Count $inv "SELECT COUNT(*) FROM sidata.PartitionMoveTouched WHERE TableName = N'Finding'" | Should -Be 2
            # 4. the job (the updater's identity) still writes them: the move goes on and swaps
            $h = Invoke-SIPartitionHousekeeping -Invoke $upd -Keep 2 -BatchSize 100 -Sleep { param($ms) }
            @($h.Move.Tables | Where-Object { $_.Table -eq 'Finding' })[0].State | Should -BeIn @('swapped', 'checked') -Because ($h.Lines -join ' / ')
        } finally { Remove-TestDb $d.Name }
    }
    It 'a table that cannot be moved without changing what readers see (a grant on the table itself) is left alone and says why' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'sipblk_' -Unpartitioned
        try {
            $inv = $d.Invoke
            [void](& $inv 'GRANT SELECT ON OBJECT::sidata.IssueContext TO public;' @{} 'nonquery')
            $r = Invoke-SIProPartitionMoveTable -Invoke $d.Updater -Table IssueContext
            $r.State | Should -Be 'blocked' -Because $r.Text
            $r.Text | Should -Match 'a right is granted on the table itself'
            Count $inv "SELECT CASE WHEN OBJECT_ID(N'sidata.IssueContext_Partitioned') IS NULL THEN 0 ELSE 1 END" | Should -Be 0
        } finally { Remove-TestDb $d.Name }
    }
}

Describe 'stability and data quality of the move (review 2026-11-23)' {
    BeforeAll {
        . (Join-Path $script:Root 'container\updater\_shared\SI-UpdaterDatabase.ps1')
        $script:Upd2 = [IO.File]::ReadAllText((Join-Path $script:Root 'container\updater\_shared\SI-UpdaterDatabase.ps1'))
    }
    It 'ITEM 1: the update''s step beats the install''s lock before every range and its budget stays near 10 min with the longest overrun' {
        $script:Upd2 | Should -Match 'Invoke-SIUpdaterLockBeat -What ''the collection partitions'' -Force'
        $script:Upd2 | Should -Match 'Invoke-SIPartitionHousekeeping -Invoke \$Store\.Invoke -DeadlineUtc \$dl -Keep \$kp -Log \$Log -BatchSize \$BatchSize -ShouldStop \$beat -Holder'
        ($script:SIUpdaterPartitionMinutes.Current + [Math]::Ceiling($script:SIPartitionStatementSeconds / 60.0)) | Should -BeLessOrEqual 10
        $script:SIUpdaterPartitionMinutes.Applied | Should -BeLessThan $script:SIUpdaterPartitionMinutes.Current
        [IO.File]::ReadAllText((Join-Path $script:Root 'container\updater\_shared\SI-UpdaterRunGate.ps1')) | Should -Match 'LockStaleMinutes = 15'
    }
    It 'ITEM 1: the stop seam the step hands over beats the lock (a fake beat counts every call)' {
        $script:Beats = 0
        function global:Invoke-SIUpdaterLockBeat { param([string]$What, [switch]$Force) $script:Beats++; $true }
        try {
            # the seam exactly as the step builds it (read from the source), called twice

            ($script:Upd2 -match '\$beat = \{ if \(Get-Command -Name Invoke-SIUpdaterLockBeat -ErrorAction SilentlyContinue\) \{ \$null = Invoke-SIUpdaterLockBeat -What ''the collection partitions'' -Force \}; '''' \}') | Should -BeTrue
            $beat = { if (Get-Command -Name Invoke-SIUpdaterLockBeat -ErrorAction SilentlyContinue) { $null = Invoke-SIUpdaterLockBeat -What 'the collection partitions' -Force }; '' }
            & $beat | Should -Be ''
            & $beat | Out-Null
            $script:Beats | Should -Be 2
        } finally { Remove-Item function:global:Invoke-SIUpdaterLockBeat -ErrorAction SilentlyContinue }
    }
    It 'ITEM 3: every statement of the step carries a time limit (the store''s 4th argument); both stores honour it' {
        $got = [pscustomobject]@{ T = $null }
        $b = New-SIPartitionBoundedInvoke -Invoke { param($s, $p, $m, $t) $got.T = $t; 1 }.GetNewClosure() -Seconds 77
        $null = & $b 'SELECT 1' @{} 'scalar'
        $got.T | Should -Be 77
        $null = & (New-SIPartitionBoundedInvoke -Invoke { param($s, $p, $m) 1 }) 'SELECT 1' @{} 'scalar'   # a 3-argument seam still works
        [IO.File]::ReadAllText((Join-Path $script:Root 'container\updater\Start-SIUpdater.ps1')) | Should -Match '\$cmd\.CommandTimeout = \[Math\]::Max\(0, \$TimeoutSeconds\)'
        [IO.File]::ReadAllText((Join-Path $script:Root 'engine\index-build\Invoke-SIIndexBuildJob.ps1')) | Should -Match '\$cmd\.CommandTimeout = \[Math\]::Max\(0, \$TimeoutSeconds\)'
        (Get-Command Invoke-SIPartitionHousekeeping).Definition | Should -Match 'New-SIPartitionBoundedInvoke -Invoke \$Invoke -Seconds \$StatementSeconds'
    }
    It 'ITEM 3: counts per kept collection only (seeks), never one grouped scan of the whole table; every loop asks the stop seam' {
        $n = Get-SIPartitionMoveNames -Table Finding
        $ids = Get-SIPartitionMoveIdsSql -Names $n
        $ids | Should -Match 'WHILE @nx IS NOT NULL'
        $ids | Should -Not -Match 'GROUP BY'
        Get-SIPartitionMoveCountOneSql -Names $n | Should -Match 'WHERE CollectionId = @c'
        $d = (Get-Command Invoke-SIProPartitionMoveTable).Definition
        $d | Should -Match "Get-SIPartitionMoveResetSql -Names \`$n\) @\{ CollectionId = \[string\]\`$c \} 'scalar'\) -gt 0\) \{ \`$swr = & \`$stopNow"
        $d | Should -Match 'SELECT @@ROWCOUNT;" -f \$cpq, \$rs, \$rt, \$rc, \$col\) @\{\} ''scalar''\) -gt 0\) \{\s+\$swf = & \$stopNow'
        (Get-Command -Name Get-SIPartitionMoveCountsSql -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty -Because 'the whole-table count is gone'
    }
    It 'ITEM 4: the swap compares BEFORE the lock -- under it only the trigger''s notes; the plan is ready only when every kept collection is verified' {
        $n = Get-SIPartitionMoveNames -Table Finding
        $key = [pscustomobject]@{ Ok = $true; Column = 'FindingId'; Type = 'bigint'; PkName = 'PK_Finding'; Why = '' }
        $s = Get-SIPartitionMoveSwapSql -Names $n -Key $key -Identity $true -ScopeRows 10
        $s | Should -Not -Match 'COUNT_BIG|GROUP BY'
        $s.IndexOf('PartitionMoveTouched WHERE TableName') | Should -BeLessThan $s.IndexOf('sp_rename')
        $p = Get-SIPartitionMovePlan -Rows @(@{ CollectionId = 2; Old = 5; Copied = 5; Kept = 1; Touched = 0; Verified = 0 })
        $p.Ready | Should -BeFalse; @($p.Verify) | Should -Be @(2)
        (Get-SIPartitionMovePlan -Rows @(@{ CollectionId = 2; Old = 5; Copied = 5; Kept = 1; Touched = 0; Verified = 1 })).Ready | Should -BeTrue
        (Get-SIPartitionMovePlan -Rows @(@{ CollectionId = 2; Old = 5; Copied = 5; Kept = 1; Touched = 0; Verified = 1 }) -Incomplete).Ready | Should -BeFalse
    }
    It 'ITEM 5: room for the copy is checked first (refused with one line); the columnstore index goes INSIDE the swap; switched off = cleaned up' {
        $space = @{ TableBytes = 100GB; TableRows = 10000000; MaxBytes = 250GB; UsedBytes = 200GB }
        $r = Test-SIPartitionMoveRoom -Space $space -KeptRows 5000000
        $r.Fits | Should -BeFalse -Because '62.5 GB needed, 25 GB free after the margin'
        $r.Text | Should -Match 'the copy needs about'
        (Test-SIPartitionMoveRoom -Space @{ TableBytes = 10GB; TableRows = 1000; MaxBytes = 250GB; UsedBytes = 50GB } -KeptRows 500).Fits | Should -BeTrue
        (Test-SIPartitionMoveRoom -Space @{ TableBytes = 10GB; TableRows = 1000; MaxBytes = $null; UsedBytes = 50GB } -KeptRows 500).Fits | Should -BeTrue
        $n = Get-SIPartitionMoveNames -Table Finding
        $key = [pscustomobject]@{ Ok = $true; Column = 'FindingId'; Type = 'bigint'; PkName = 'PK_Finding'; Why = '' }
        $s = Get-SIPartitionMoveSwapSql -Names $n -Key $key
        $s | Should -Match 'DROP INDEX \[NCCI_Finding_Load\] ON sidata\.\[Finding\]'
        $s.IndexOf('BEGIN TRANSACTION') | Should -BeLessThan $s.IndexOf('DROP INDEX [NCCI_Finding_Load]')
        (Get-Command Invoke-SIProPartitionMoveTable).Definition | Should -Not -Match 'Get-SIPartitionMoveColumnstoreDropSql' -Because 'never dropped before the copy'
        $script:Upd2 | Should -Match 'Invoke-SIPartitionMoveStop -Invoke'
        $script:SIPartitionGiveUpWindows | Should -BeGreaterThan 0
    }
    It 'ITEM 7: a failed check is TERMINAL -- the runner''s work query skips it (no restart every wake-up)' {
        Get-SIPartitionWorkSql | Should -Match "State IN \(N'blocked', N'gave-up', N'check-differs', N'waiting-space'\)"
        $script:SIPartitionTerminalStates | Should -Contain 'check-differs'
        (Get-Command Invoke-SIProPartitionMoveTable).Definition | Should -Match "-State 'check-differs'"
    }
    It 'NIT: one lock order -- the partition truncate empties IssueContext, Recommendation, Finding, the order the paced removal uses' {
        $s = Get-SIPartitionRemoveSql
        $s.IndexOf('TRUNCATE TABLE sidata.IssueContext') | Should -BeLessThan $s.IndexOf('TRUNCATE TABLE sidata.Recommendation')
        $s.IndexOf('TRUNCATE TABLE sidata.Recommendation') | Should -BeLessThan $s.IndexOf('TRUNCATE TABLE sidata.Finding')
        $o = @($script:SIDataRetireTables['Detailed'] | Where-Object { $_ -in 'IssueContext', 'Recommendation', 'Finding' })
        ($o -join ',') | Should -Be 'IssueContext,Recommendation,Finding'
        (Get-SIPartitionMoveNextSize -Current 4000 -ElapsedMs 10 -MaxRows 5000) | Should -Be 5000 -Because 'a range never carries more than the bytes cap'
    }

    It 'ITEM 2: ONE mover at a time (the lease); a stale lease is taken over; a second mover does nothing' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'siplease_'
        try {
            $upd = $d.Updater
            Enter-SIPartitionLease -Invoke $upd -Holder 'job' | Should -BeTrue
            Enter-SIPartitionLease -Invoke $upd -Holder 'job' | Should -BeTrue -Because 'its own holder beats it'
            Enter-SIPartitionLease -Invoke $upd -Holder 'updater' | Should -BeFalse
            $h = Invoke-SIPartitionHousekeeping -Invoke $upd -Holder 'updater' -Sleep { param($ms) }
            ($h.Lines -join ' ') | Should -Match 'another mover works on the collection partitions'
            (Boundaries $d.Invoke).Count | Should -Be 0 -Because 'the second mover did nothing'
            [void](& $d.Invoke "UPDATE sidata.PartitionMove SET UpdatedAt = DATEADD(minute, -10, SYSUTCDATETIME()) WHERE TableName = N'(mover)'" @{} 'nonquery')
            Enter-SIPartitionLease -Invoke $upd -Holder 'updater' | Should -BeTrue -Because 'a lease not beaten for longer than the limit is free'
            Exit-SIPartitionLease -Invoke $upd -Holder 'updater'
            Enter-SIPartitionLease -Invoke $upd -Holder 'job' | Should -BeTrue
        } finally { Remove-TestDb $d.Name }
    }
    It 'ITEM 2 SELF-HEAL + DATA QUALITY: a copy that lost its low keys is copied again; a value written behind the trigger''s back stops the swap; a column added WITH VALUES restarts the copy; equal data swaps' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'sipdq_' -Unpartitioned
        try {
            $inv = $d.Invoke; $upd = $d.Updater; $siStopDb = $d.Invoke
            $ids = @(); foreach ($day in 1..3) { $ids += Add-Collection $inv ('2026-10-0{0}T08:00:00' -f $day) 300 }
            # the two smaller tables first, then Finding copied but not swapped (a stop right before the swap)
            $r0 = Invoke-SIProPartitionMove -Invoke $upd -BudgetMinutes 30 -BatchSize 100 -Sleep { param($ms) } -ShouldStop { if ([long](& $siStopDb "IF OBJECT_ID(N'sidata.Finding_Partitioned') IS NULL SELECT 0; ELSE EXEC (N'SELECT COUNT(*) FROM sidata.Finding_Partitioned');" @{} 'scalar') -ge 900) { 'an update waits' } else { '' } }.GetNewClosure()
            Partitioned $inv 'Finding' | Should -BeFalse -Because ($r0.Lines -join ' / ')
            Count $inv "SELECT CASE WHEN OBJECT_ID(N'sidata.Finding_Partitioned') IS NULL THEN 0 ELSE 1 END" | Should -Be 1 -Because ($r0.Lines -join ' / ')
            # (a) SELF-HEAL: the copy's low keys of one collection are lost (the race the review found) -- the copy cannot go on
            [void](& $inv ("DELETE TOP (50) FROM sidata.Finding_Partitioned WHERE CollectionId = {0} AND FindingId IN (SELECT TOP (50) FindingId FROM sidata.Finding_Partitioned WHERE CollectionId = {0} ORDER BY FindingId)" -f $ids[0]) @{} 'nonquery')
            # (b) a value changed with the trigger switched off (what a schema change's backfill looks like to the move)
            [void](& $inv ("DISABLE TRIGGER sidata.TR_Finding_PartitionMove ON sidata.Finding; UPDATE sidata.Finding SET DetailJson = N'{{""changed"":1}}' WHERE CollectionId = {0} AND AssetKey = N'a7'; ENABLE TRIGGER sidata.TR_Finding_PartitionMove ON sidata.Finding;" -f $ids[1]) @{} 'nonquery')
            $r1 = Invoke-SIProPartitionMove -Invoke $upd -BudgetMinutes 30 -BatchSize 100 -Sleep { param($ms) }
            Partitioned $inv 'Finding' | Should -BeFalse -Because ('no swap while a copy is short or holds other values: ' + ($r1.Lines -join ' / '))
            Count $inv ("SELECT COUNT(*) FROM sidata.PartitionMoveTouched WHERE TableName = N'Finding' AND CollectionId IN ({0}, {1})" -f $ids[0], $ids[1]) | Should -Be 2 -Because 'both are copied again next time'
            # (c) a column added WITH VALUES mid-move
            [void](& $inv "ALTER TABLE sidata.Finding ADD SiTestFlag INT NOT NULL CONSTRAINT DF_Finding_SiTestFlag DEFAULT 7 WITH VALUES;" @{} 'nonquery')
            $r2 = Invoke-SIProPartitionMove -Invoke $upd -BudgetMinutes 30 -BatchSize 100 -Sleep { param($ms) }
            $n = 0; while (-not (Partitioned $inv 'Finding') -and $n -lt 5) { $n++; $r2 = Invoke-SIProPartitionMove -Invoke $upd -BudgetMinutes 30 -BatchSize 500 -Sleep { param($ms) } }
            Partitioned $inv 'Finding' | Should -BeTrue -Because ('equal data swaps once the copy is redone: ' + ($r2.Lines -join ' / '))
            Count $inv 'SELECT COUNT(*) FROM sidata.Finding WHERE SiTestFlag = 7' | Should -Be 900 -Because 'the copy was made again with the column''s values'
            Count $inv ("SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = {0} AND AssetKey = N'a7' AND DetailJson = N'{{""changed"":1}}'" -f $ids[1]) | Should -Be 1
            foreach ($c in $ids) { Rows3 $inv $c | Should -Be '300/300/300' }
        } finally { Remove-TestDb $d.Name }
    }
    It 'ITEM 5: a move that cannot converge gives up and cleans up (no copy, no trigger); switched off mid-move = cleaned up too' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'sipgive_' -Unpartitioned
        try {
            $inv = $d.Invoke; $upd = $d.Updater; $siStopDb = $d.Invoke
            $ids = @(); foreach ($day in 1..3) { $ids += Add-Collection $inv ('2026-10-0{0}T08:00:00' -f $day) 200 }
            $null = Invoke-SIProPartitionMove -Invoke $upd -BudgetMinutes 30 -BatchSize 100 -Sleep { param($ms) } -ShouldStop { if ([long](& $siStopDb "IF OBJECT_ID(N'sidata.Finding_Partitioned') IS NULL SELECT 0; ELSE EXEC (N'SELECT COUNT(*) FROM sidata.Finding_Partitioned');" @{} 'scalar') -ge 300) { 'an update waits' } else { '' } }.GetNewClosure()
            Count $inv "SELECT CASE WHEN OBJECT_ID(N'sidata.Finding_Partitioned') IS NULL THEN 0 ELSE 1 END" | Should -Be 1
            # the windows before: runs kept changing what was copied
            [void](& $inv "UPDATE sidata.PartitionMove SET Attempts = $($script:SIPartitionGiveUpWindows - 1) WHERE TableName = N'Finding'" @{} 'nonquery')
            [void](& $inv ("UPDATE sidata.Finding SET RiskScore = 1 WHERE CollectionId = {0} AND AssetKey = N'a1'" -f $ids[0]) @{} 'nonquery')
            $siLim = (Count $inv 'SELECT COUNT(*) FROM sidata.Finding_Partitioned') + 50
            $r = Invoke-SIProPartitionMoveTable -Invoke $upd -Table Finding -BatchSize 50 -Sleep { param($ms) } -ShouldStop { if ([long](& $siStopDb "IF OBJECT_ID(N'sidata.Finding_Partitioned') IS NULL SELECT 0; ELSE EXEC (N'SELECT COUNT(*) FROM sidata.Finding_Partitioned');" @{} 'scalar') -ge $siLim) { 'a run is due' } else { '' } }.GetNewClosure()
            $r.State | Should -Be 'gave-up' -Because $r.Text
            $r.Text | Should -Match 'gave up after'
            Count $inv "SELECT CASE WHEN OBJECT_ID(N'sidata.Finding_Partitioned') IS NULL AND OBJECT_ID(N'sidata.TR_Finding_PartitionMove', N'TR') IS NULL THEN 1 ELSE 0 END" | Should -Be 1 -Because 'no copy and no trigger are left behind'
            Count $inv "SELECT COUNT(*) FROM sidata.Finding" | Should -Be 600 -Because 'nothing current changed'
            (Invoke-SIProPartitionMoveTable -Invoke $upd -Table Finding).State | Should -Be 'gave-up' -Because 'terminal: nothing starts again on its own'
            [void](& $inv "IF NOT EXISTS (SELECT 1 FROM sidata.PartitionMove WHERE TableName = N'(boundaries)') INSERT sidata.PartitionMove (TableName, State, ScopeRows) VALUES (N'(boundaries)', N'ready', 1000);" @{} 'nonquery')
            Count $inv (Get-SIPartitionWorkSql).Replace('@Low', '4') | Should -Be 0 -Because 'the runner does not start the job for it'
        } finally { Remove-TestDb $d.Name }
    }
    It 'ITEM 5: switched off while a table is being copied -- the update''s step removes its copy and trigger and says so' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'sipoff_' -Unpartitioned
        try {
            $inv = $d.Invoke; $upd = $d.Updater; $siStopDb = $d.Invoke
            $null = Add-Collection $inv '2026-10-01T08:00:00' 300
            $rOff = Invoke-SIProPartitionMoveTable -Invoke $upd -Table IssueContext -BatchSize 100 -Sleep { param($ms) } -ShouldStop { if ([long](& $siStopDb "IF OBJECT_ID(N'sidata.IssueContext_Partitioned') IS NULL SELECT 0; ELSE EXEC (N'SELECT COUNT(*) FROM sidata.IssueContext_Partitioned');" @{} 'scalar') -ge 100) { 'stop' } else { '' } }.GetNewClosure()
            Count $inv "SELECT CASE WHEN OBJECT_ID(N'sidata.IssueContext_Partitioned') IS NULL THEN 0 ELSE 1 END" | Should -Be 1
            $old = Get-Variable -Name SI_Data_RetireByPartition -Scope Global -ValueOnly -ErrorAction SilentlyContinue
            try {
                $global:SI_Data_RetireByPartition = $false
                $lines = New-Object System.Collections.Generic.List[string]
                $null = Invoke-SIUpdaterPartitionStep -SIRoot $script:Root -Store ([pscustomobject]@{ Invoke = $upd }) -Log { param($m) $lines.Add($m) }
                ($lines -join ' / ') | Should -Match 'IssueContext: the move stopped -- SI_Data_RetireByPartition is off'
            } finally { if ($null -ne $old) { $global:SI_Data_RetireByPartition = $old } else { Remove-Variable -Name SI_Data_RetireByPartition -Scope Global -ErrorAction SilentlyContinue } }
            Count $inv "SELECT CASE WHEN OBJECT_ID(N'sidata.IssueContext_Partitioned') IS NULL AND OBJECT_ID(N'sidata.TR_IssueContext_PartitionMove', N'TR') IS NULL THEN 1 ELSE 0 END" | Should -Be 1
            Count $inv 'SELECT COUNT(*) FROM sidata.IssueContext' | Should -Be 300
        } finally { Remove-TestDb $d.Name }
    }
    It 'ITEM 5: no room for the copy -- refused before it is made, one line, nothing created' -Skip:(-not $script:LocalSql) {
        $d = New-TestDb 'sipspace_' -Unpartitioned
        try {
            $inv = $d.Invoke
            $null = Add-Collection $inv '2026-10-01T08:00:00' 200
            # the database's answer about its room, as a full one would give it (every other statement as it is)
            $full = { param($s, $p, $m) if ($s -match 'MaxSizeInBytes') { return , @(@{ TableBytes = 900MB; TableRows = 200; MaxBytes = 1GB; UsedBytes = 950MB }) }; & $d.Updater $s $p $m }.GetNewClosure()
            $r = Invoke-SIProPartitionMoveTable -Invoke $full -Table IssueContext -Sleep { param($ms) }
            $r.State | Should -Be 'waiting-space' -Because $r.Text
            $r.Text | Should -Match 'the copy is not made'
            Count $inv "SELECT CASE WHEN OBJECT_ID(N'sidata.IssueContext_Partitioned') IS NULL AND OBJECT_ID(N'sidata.TR_IssueContext_PartitionMove', N'TR') IS NULL THEN 1 ELSE 0 END" | Should -Be 1
            (Get-SIPartitionMoveValue ((ConvertTo-SIPartitionMoveRows (& $inv (Get-SIPartitionMoveSpaceSql) @{ Live = 'sidata.IssueContext' } 'reader')) | Select-Object -First 1) 'TableRows') | Should -Be 200 -Because 'the real room read works on the test server'
        } finally { Remove-TestDb $d.Name }
    }
}
