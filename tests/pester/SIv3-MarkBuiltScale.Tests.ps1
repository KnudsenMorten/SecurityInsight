#Requires -Version 7.0
<#
    MARK-BUILT-COST -- THE CI BUILD'S "MARK EVERY RECORD AS BUILT" PASS AT A LARGE INSTALL'S SIZE (live 2026-11-11: a large
    install's correlation step sat 9 h+ in this pass after all its batches were done -- one session, one core, no I/O).

    Tag Scale: ON DEMAND ONLY (owner 2026-10-11) -- no gate runs it, not the quick gate, not a release, not a full run. It runs
    only when the owner asks for it by name, on the test runner's SQL Server (never on the development machine):
        Invoke-Pester -Path tests\pester\SIv3-MarkBuiltScale.Tests.ps1 -TagFilter Scale -Output Detailed
    with SI_TEST_LOCALSQL (and SI_TEST_SQL_AUTH) set as for every real-SQL suite. SI_MARKBUILT_SCALE_N sets the record count
    (default 100,000).

    What it measures, each time BEFORE (the key ranges as PROGRESS-TICK-1 ran them -- kept verbatim below) against AFTER (the
    code in this tree), on the same seeded records (documents of about 2 KB in-row, two date fields, four day thresholds):
      1. the usual full build: every batch was kept as it finished (Get-SICiMarkBatchBuiltSql), then the end-of-build pass;
      2. a full build whose batches were not kept (the build after SI_CI_CL gained columns): the end-of-build pass alone;
      3. an incremental build (a third of the groups dirty), no batch kept.
    Each: the time of the end-of-build pass, before and after, and the SAME row of every record and the same Marked / Cleared.
    NO EMOJI IN THIS FILE.
#>

BeforeDiscovery {
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL)
}

Describe 'MARK-BUILT-COST: the end-of-build marks at a large install''s size, before and after (on demand only)' -Tag 'Scale' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        . (Join-Path $script:Root 'engine\data-model\SI-RecordCapture.ps1')
        . (Join-Path $script:Root 'engine\data-model\SI-CiBuildRun.ps1')
        $script:N = 100000; if ($env:SI_MARKBUILT_SCALE_N) { $script:N = [int]$env:SI_MARKBUILT_SCALE_N }
        $script:Th = @(
            [pscustomobject]@{ Field = ''; Seconds = 2592000L }, [pscustomobject]@{ Field = ''; Seconds = 7776000L },
            [pscustomobject]@{ Field = 'si_created'; Seconds = 31536000L }, [pscustomobject]@{ Field = 'si_last_sign_in'; Seconds = 7776000L })
        # BEFORE: one range of the marks and one of the clean-up, as PROGRESS-TICK-1 ran them (SI-CiBuildSql.ps1 at 9a18c512f)
        $ts = Get-SICiThresholdSql -Thresholds $script:Th
        $vals = @(foreach ($i in $ts.Items) { "(CASE WHEN {0} IS NOT NULL AND DATEADD(second, {1}, {0}) > @now THEN DATEADD(second, {1}, {0}) END)" -f $i.Src, $i.Seconds })
        $due = 'CROSS APPLY (SELECT MIN(v.x) AS Due FROM (VALUES ' + ($vals -join ', ') + ') v(x)) d'
        $script:MarkBefore = @"
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @now DATETIME2(3) = CONVERT(DATETIME2(3), @nowAt, 126);
DECLARE @lo NVARCHAR(450) = @after, @hi NVARCHAR(450) = NULL, @first BIT = CONVERT(BIT, @isFirst), @n BIGINT = CONVERT(BIGINT, @take), @walked BIGINT = 0, @t0 DATETIME2(3), @ms BIGINT, @marked INT = 0;
SELECT @hi = MAX(k.RecordKey), @walked = COUNT_BIG(*) FROM (SELECT TOP (@n) g.RecordKey FROM sidata.CiGroupMember g WHERE (@first = 1 OR g.RecordKey > @lo) ORDER BY g.RecordKey) k;
IF @hi IS NULL
BEGIN
    SELECT CAST(NULL AS NVARCHAR(450)) AS Hi, 0 AS Marked, CAST(0 AS BIGINT) AS Ms, CAST(0 AS BIGINT) AS Walked;
    RETURN;
END
DECLARE @held TABLE (RecordKey NVARCHAR(450) COLLATE DATABASE_DEFAULT NOT NULL PRIMARY KEY);
IF @h IS NOT NULL AND @h <> N'' AND @h <> N'[]'
    INSERT @held (RecordKey) SELECT DISTINCT x.RecordKey FROM OPENJSON(@h) WITH (RecordKey NVARCHAR(450) '$') x WHERE x.RecordKey IS NOT NULL;
SET @t0 = SYSUTCDATETIME();
BEGIN TRANSACTION;
UPDATE r SET BuiltHash = m.CurHash, BuiltGroupKey = m.GroupKey, BuiltState = m.CurState, BuiltTimeSig = m.CurTimeSig, BuiltAt = @now, NextDueAt = d.Due
FROM sidata.CiRecord r JOIN sidata.CiGroupMember m ON m.RecordKey = r.RecordKey
$($ts.Apply)
$due
WHERE (m.Dirty = 1 OR @all = N'1') AND r.CiId IS NOT NULL AND (@first = 1 OR m.RecordKey > @lo) AND m.RecordKey <= @hi
  AND NOT EXISTS (SELECT 1 FROM @held hk WHERE hk.RecordKey = r.RecordKey);
SET @marked = @@ROWCOUNT;
COMMIT TRANSACTION;
SET @ms = DATEDIFF_BIG(MILLISECOND, @t0, SYSUTCDATETIME());
SELECT @hi AS Hi, @marked AS Marked, @ms AS Ms, @walked AS Walked;
"@
        $script:ClearBefore = @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @lo NVARCHAR(450) = @after, @hi NVARCHAR(450) = NULL, @first BIT = CONVERT(BIT, @isFirst), @n BIGINT = CONVERT(BIGINT, @take), @walked BIGINT = 0, @t0 DATETIME2(3), @ms BIGINT, @cleared INT = 0;
SELECT @hi = MAX(k.RecordKey), @walked = COUNT_BIG(*) FROM (SELECT TOP (@n) r.RecordKey FROM sidata.CiRecord r WHERE (@first = 1 OR r.RecordKey > @lo) ORDER BY r.RecordKey) k;
IF @hi IS NULL
BEGIN
    SELECT CAST(NULL AS NVARCHAR(450)) AS Hi, 0 AS Cleared, CAST(0 AS BIGINT) AS Ms, CAST(0 AS BIGINT) AS Walked;
    RETURN;
END
SET @t0 = SYSUTCDATETIME();
UPDATE r SET BuiltHash = NULL, BuiltGroupKey = NULL, BuiltState = NULL, BuiltTimeSig = NULL, NextDueAt = NULL
FROM sidata.CiRecord r
WHERE (@first = 1 OR r.RecordKey > @lo) AND r.RecordKey <= @hi
  AND r.BuiltGroupKey IS NOT NULL AND NOT EXISTS (SELECT 1 FROM sidata.CiGroupMember m WHERE m.RecordKey = r.RecordKey);
SET @cleared = @@ROWCOUNT;
SET @ms = DATEDIFF_BIG(MILLISECOND, @t0, SYSUTCDATETIME());
SELECT @hi AS Hi, @cleared AS Cleared, @ms AS Ms, @walked AS Walked;
'@
        $script:Db = $null; $script:DbError = $null
        try {
            $script:DbName = 'si_test_markscale_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open()
            try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$($script:DbName)]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
            $script:Conn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$($script:DbName);$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
            $script:Conn.Open()
            $c = $script:Conn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-data-schema.sql')); [void]$c.ExecuteNonQuery()
            $script:Db = $script:DbName
        } catch { $script:DbError = $_.Exception.Message }
        # the engine's seam (every value a text parameter; no command time limit: a measurement)
        $script:Seam = {
            param($Sql, $Params, $Mode)
            $c = $script:Conn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 0
            if ($Params) { foreach ($k in $Params.Keys) { $pp = $c.Parameters.Add('@' + $k, [System.Data.SqlDbType]::NVarChar, -1); $pp.Value = [string]$Params[$k] } }
            if ($Mode -eq 'scalar') { return $c.ExecuteScalar() }
            if ($Mode -eq 'rows') { return @(Read-SISqlRows -Command $c) }
            $c.ExecuteNonQuery()
        }
        # the same driver (Invoke-SICiMarkBuilt), with the BEFORE statements in place of this tree's
        $newMark = Get-SICiMarkBuiltSql -Thresholds $script:Th; $newClear = Get-SICiMarkBuiltClearSql
        $mb = $script:MarkBefore; $cb = $script:ClearBefore; $inner = $script:Seam
        $script:SeamBefore = { param($Sql, $Params, $Mode) $s = [string]$Sql; if ($s -eq $newMark) { $s = $mb } elseif ($s -eq $newClear) { $s = $cb }; & $inner $s $Params $Mode }.GetNewClosure()
        # N records (every 9th no member any more, every 2nd of those with a built mark; every 11th without a CI), documents of
        # about 2 KB with two date fields; 100 batches; every 3rd member dirty
        $script:Seed = @"
SET NOCOUNT ON;
TRUNCATE TABLE sidata.CiGroupMember; TRUNCATE TABLE sidata.CiRecord;
;WITH n AS (SELECT TOP ($($script:N)) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b CROSS JOIN sys.all_objects c)
INSERT sidata.CiRecord (RecordKey, CiId, Provider, CollectionTime, SourceLastSeen, DocJson, BuiltGroupKey, BuiltHash, BuiltAt)
SELECT CONCAT(CASE WHEN i % 2 = 0 THEN N'mde|device|' ELSE N'entra|user|' END, RIGHT(CONCAT(N'0000000', i), 7)),
       CASE WHEN i % 11 = 0 THEN NULL ELSE CONCAT(N'ci-', i % 40000) END, N'mde', '2026-11-10T00:00:00',
       DATEADD(day, -(i % 120), '2026-11-10T00:00:00'),
       CONCAT(N'{"si_name":"device-', i, N'","si_created":"20', 20 + i % 6, N'-0', 1 + i % 9, N'-15T00:00:00Z","si_last_sign_in":"2026-', RIGHT(CONCAT(N'0', 1 + i % 11), 2), N'-', RIGHT(CONCAT(N'0', 1 + i % 28), 2), N'T06:00:00Z","si_installed_software":["', REPLICATE(N'a', 900), N'","', REPLICATE(N'b', 900), N'"]}'),
       CASE WHEN i % 9 = 0 AND i % 2 = 0 THEN N'old-group' END,
       CASE WHEN i % 9 = 0 AND i % 2 = 0 THEN HASHBYTES('SHA2_256', N'old') END,
       CASE WHEN i % 9 = 0 AND i % 2 = 0 THEN '2026-11-01T00:00:00' END
FROM n;
;WITH n AS (SELECT TOP ($($script:N)) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b CROSS JOIN sys.all_objects c)
INSERT sidata.CiGroupMember (RecordKey, GroupKey, BatchNo, Dirty, CurHash, CurState, CurTimeSig)
SELECT CONCAT(CASE WHEN i % 2 = 0 THEN N'mde|device|' ELSE N'entra|user|' END, RIGHT(CONCAT(N'0000000', i), 7)), CONCAT(N'g-', i % 40000), 1 + i % 100,
       CASE WHEN i % 3 = 0 THEN 1 ELSE 0 END, HASHBYTES('SHA2_256', CONCAT(N'h', i)), CASE WHEN i % 2 = 0 THEN 'a' ELSE 'n' END, HASHBYTES('SHA2_256', CONCAT(N't', i))
FROM n WHERE i % 9 <> 0;
"@
        $script:State = @'
SELECT COUNT_BIG(*) AS N, CONVERT(varchar(64), HASHBYTES('SHA2_256', CAST((SELECT RecordKey, CONVERT(varchar(64), BuiltHash, 2) AS H, BuiltGroupKey, BuiltState, CONVERT(varchar(64), BuiltTimeSig, 2) AS T, BuiltAt, NextDueAt
    FROM sidata.CiRecord ORDER BY RecordKey FOR JSON PATH, INCLUDE_NULL_VALUES) AS NVARCHAR(MAX))), 2) AS H FROM sidata.CiRecord;
'@
        $script:NowText = '2026-11-11T01:00:00.0000000Z'
        function script:Measure-Pass([scriptblock]$Sql, [string]$All, [switch]$KeepBatches) {
            $null = & $script:Seam $script:Seed @{} 'nonquery'
            if ($KeepBatches) { foreach ($b in 1..100) { $null = & $script:Seam (Get-SICiMarkBatchBuiltSql -Thresholds $script:Th) @{ nowText = $script:NowText; all = $All; b = [string]$b; p = '[]'; h = '[]' } 'rows' } }
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $r = @(Invoke-SICiMarkBuilt -Sql $Sql -Thresholds $script:Th -Params @{ nowText = $script:NowText; all = $All; h = '[]' })
            $sw.Stop()
            $s = @(& $script:Seam $script:State @{} 'rows')
            [pscustomobject]@{ Ms = $sw.ElapsedMilliseconds; Marked = [int]$r[0].Marked; Cleared = [int]$r[0].Cleared; Ranges = $r[0].MarkRanges; State = [string]$s[0].H; Rows = [long]$s[0].N }
        }
        function script:Assert-BeforeAfter([string]$Name, $Before, $After) {
            Write-Host ('MARK-BUILT-COST {0}, {1:N0} records: before {2:N0} ms ({3} ranges), after {4:N0} ms ({5} ranges); marked {6:N0}, cleared {7:N0}' -f $Name, $Before.Rows, $Before.Ms, $Before.Ranges, $After.Ms, $After.Ranges, $After.Marked, $After.Cleared)
            $After.Marked | Should -Be $Before.Marked
            $After.Cleared | Should -Be $Before.Cleared
            $After.State | Should -Be $Before.State -Because 'the same row of every record'
            $After.Marked | Should -BeGreaterThan 0
        }
    }
    AfterAll {
        if ($script:Conn) { try { $script:Conn.Dispose() } catch { } }
        if ($script:Db) {
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open()
            try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$($script:Db)] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$($script:Db)]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        }
    }
    BeforeEach { if (-not $script:Db -or $script:DbError) { throw ('the SQL Server did not answer: ' + $script:DbError) } }
    It '1. the usual full build (every batch kept as it finished), then the end-of-build pass' {
        $b = Measure-Pass -Sql $script:SeamBefore -All '1' -KeepBatches
        $a = Measure-Pass -Sql $script:Seam -All '1' -KeepBatches
        Assert-BeforeAfter 'full build, batches kept' $b $a
    }
    It '2. a full build whose batches were not kept: the end-of-build pass alone' {
        $b = Measure-Pass -Sql $script:SeamBefore -All '1'
        $a = Measure-Pass -Sql $script:Seam -All '1'
        Assert-BeforeAfter 'full build, no batch kept' $b $a
    }
    It '3. an incremental build (a third of the groups dirty), no batch kept' {
        $b = Measure-Pass -Sql $script:SeamBefore -All '0'
        $a = Measure-Pass -Sql $script:Seam -All '0'
        Assert-BeforeAfter 'incremental build' $b $a
    }
}
