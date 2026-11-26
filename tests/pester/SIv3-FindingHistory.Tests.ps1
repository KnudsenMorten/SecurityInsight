#Requires -Version 7.0
<#
    THE FINDING HISTORY MODEL (REQUIREMENTS #1332, with #1334; design note SCALE-3 #1330) -- engine\pro-data\_shared\SI-DataHistory.ps1,
    the schema's history objects (sql\si-data-schema.sql) and the data sync's step (SI-DataSync.ps1).

    What these tests keep true (prio 1: HOW findings are stored changes, never WHAT is shown or sent):
      * SI_Data_HistoryModel is ON by default (owner 2026-11-23); only off / shadow switch it; off writes nothing;
      * REAL SQL, three collections with changed fields, closes, a REOPEN, new findings, duplicate rows, the run's own fields
        moving in every document (strings and a number), a document that names a key twice, a non-JSON document, a NULL one,
        exemptions and a per-run importance rank: sidata.FindingAt gives EVERY collection back exactly as sidata.Finding holds
        it (the product's own byte compare AND this test's own compare of every column), the states are shared across runs
        (fewer states than rows; a reopened finding gets its old state back), the change set is exact, and What changed built
        from the change set equals the stored full build -- both variants, every listed row, the counts;
      * a FULL build (the collection's marks moved) writes the history again and verifies every key;
      * a forced difference is found, said as a WARNING (the fix request) with ids and column names only, never a value;
      * a migration interrupted mid-way is resumed from its mark next run and ends verified, every finding a member once;
      * retention: a collection whose rows are gone leaves the history; states only it held go, shared ones stay.
    Runs on the Azure test runner (TEST_SQL_*: _SITestSql.ps1); without SQL only the offline part runs.
#>

BeforeDiscovery {
    $script:HasSql = [bool]($env:SI_TEST_LOCALSQL)
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
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataSummaryGroups.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataHistory.ps1')
    $script:Schema = [IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-data-schema.sql'))
    $script:Quiet = { param($l, $m) }
}

Describe 'the setting: on by default, off and shadow only when said' {
    It 'reads <V> as <Want>' -ForEach @(
        @{ V = $null; Want = 'on' }, @{ V = ''; Want = 'on' }, @{ V = '"on"'; Want = 'on' }, @{ V = 'typo'; Want = 'on' }
        @{ V = 'off'; Want = 'off' }, @{ V = '"off"'; Want = 'off' }, @{ V = 'false'; Want = 'off' }, @{ V = 'shadow'; Want = 'shadow' }
    ) {
        ConvertTo-SIDataHistoryMode $V | Should -Be $Want
    }
    It 'a database without the objects of this build = off, said; off writes and reads nothing of it' {
        $calls = New-Object System.Collections.Generic.List[string]
        $inv = { param($s, $p, $m) $calls.Add([string]$s); if ($s -match 'cfg\.Setting') { return , @() }; if ($m -eq 'scalar') { return '0' }; , @() }.GetNewClosure()
        $r = Read-SIDataHistoryMode -Invoke $inv -Value $null
        $r.Mode | Should -Be 'off'; $r.Source | Should -Match 'does not have its tables yet'
        $calls.Clear()
        $o = Invoke-SIDataHistory -Invoke $inv -Mode 'off' -Log $script:Quiet
        $o.Status | Should -Be 'off'; $calls.Count | Should -Be 0
    }
    It 'the catalog carries both settings, the model on by default with its three values' {
        $cat = Get-Content -Raw (Join-Path $script:Root 'config\settings.catalog.locked.json') | ConvertFrom-Json
        $e = @($cat.settings | Where-Object { $_.name -eq 'SI_Data_HistoryModel' })
        $e.Count | Should -Be 1
        @($e[0].values) | Should -Be @('on', 'shadow', 'off')
        [string]$e[0].defaultText | Should -Match '^On'
        @($cat.settings | Where-Object { $_.name -eq 'SI_Data_HistoryDays' }).Count | Should -Be 1
    }
    It 'the data sync runs the step after the last writer of the rows, and says its differences as a warning' {
        $sync = Get-Content -Raw (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataSync.ps1')
        $sync.IndexOf("& `$phase 'finding history'") | Should -BeGreaterThan $sync.IndexOf("& `$phase 'remediation tasks'")
        $sync | Should -Match 'Get-SIDataHistoryWarningText'
        (Get-Content -Raw (Join-Path $script:Root 'engine\pro-data\Invoke-SIDataSync.ps1')) | Should -Match ([regex]::Escape("_shared\SI-DataHistory.ps1"))
        $w = Get-SIDataHistoryWarningText -Result ([pscustomobject]@{ Status = 'ok'; Differing = @([pscustomobject]@{ When = 'x'; Reader = 'the collection'; Differences = 2; Detail = 'finding 5: Title;' }) })
        @($w).Count | Should -Be 1
        (@($w) -join ' ') | Should -Match 'nothing different was published'
    }
}

Describe 'the statements' {
    It 'the state hash leaves out the identity and the per-run columns; the key hash is What changed''s K' {
        $c = Get-SIDataHistoryContract
        foreach ($m in 'ImportanceRank', 'RaSeq', 'RaSort') { $c.Member | Should -Contain $m }
        $sql = Get-SIDataHistoryWriteRangeSql -StateColumns @('AssetKey', 'DetailJson', 'Title')
        $sql | Should -Match 'f\.FindingId > @A AND f\.FindingId <= @U'
        $sql | Should -Match 'JSON_MODIFY\(d0\.D'
        $sql | Should -Not -Match 'TRUNCATE'
        (Get-SIDataHistoryKeyHashExpr -Alias 'f') | Should -Match ([regex]::Escape("COALESCE(f.AssetKey, N'name:' + LOWER(COALESCE(f.AssetName, N'')))"))
    }
    It 'What changed''s check is built from the stored statement (its anchors are found) and never writes the stored tables' {
        $sql = Get-SIDataHistoryChangesCheckSql
        $sql | Should -Match 'JOIN #dk AS dk ON dk\.K = hm\.KeyHash'
        $sql | Should -Not -Match 'BEGIN TRAN'
        $sql | Should -Not -Match 'INSERT sidata\.FindingChange'
        $sql | Should -Not -Match 'DELETE FROM sidata\.'
    }
}

Describe 'REAL SQL: the history equals the stored rows, every reader, row for row' -Skip:(-not $script:HasSql) {
    BeforeAll {
        $script:Dbs = New-Object System.Collections.Generic.List[string]
        function script:New-TestDb {
            $name = 'si_test_hist_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
            $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
            $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$name]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
            $script:Dbs.Add($name)
            $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=$($env:SI_TEST_LOCALSQL);Database=$name;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false")
            $cn.Open()
            $seam = {
                param($Sql, $Params, $Mode)
                $c = $cn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 600
                if ($Params) { foreach ($k in $Params.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $Params[$k]) { [System.DBNull]::Value } else { $Params[$k] })) } }
                switch ($Mode) {
                    { $_ -in 'reader', 'rows' } { $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]; while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) }; $rd.Close(); , $out.ToArray() }
                    'scalar' { $c.ExecuteScalar() }
                    default { [void]$c.ExecuteNonQuery() }
                }
            }.GetNewClosure()
            [pscustomobject]@{ Name = $name; Cn = $cn; Seam = $seam }
        }
        # three collections of the same estate: c1 -> c2 (changed fields, gone, new, exemption moved) -> c3 (a finding gone in
        # c2 comes BACK, unchanged = a reopen); every document carries the run's own time (strings) and _BilledSize (a number);
        # some rows are exact duplicates, one document names a key twice, one is not JSON, one is NULL; the importance rank
        # differs per run
        $script:Seed = @'
DECLARE @t DATETIME2(3) = CONVERT(datetime2(3), @When);
INSERT sidata.Collection (CollectionTime, Kind, Status, DerivedAt, ViewsReadyAt, ExemptedDerivedAt, ContextAt) VALUES (@t, 'Detailed', 'Complete', DATEADD(minute, -30, SYSUTCDATETIME()), DATEADD(minute, -30, SYSUTCDATETIME()), DATEADD(minute, -30, SYSUTCDATETIME()), DATEADD(minute, -30, SYSUTCDATETIME()));
DECLARE @cid INT = SCOPE_IDENTITY(), @s INT = CONVERT(int, @Side);
;WITH n AS (SELECT TOP (420) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b)
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, RiskRating, ExemptionId, DetailJson, RaSeq, ImportanceRank)
SELECT @cid,
       CASE WHEN i % 53 = 0 THEN NULL ELSE CONCAT(N'ci-', i % 41) END, CONCAT(N'host', i % 41), CONCAT(N'Report_', i % 3), N'Endpoint',
       CONCAT(N'cfg.', i % 150), CASE WHEN i % 2 = 0 THEN CONCAT(N'CVE-2026-', 1000 + (i % 150)) END, CONCAT(N'Title ', i % 150),
       CHOOSE(((i + CASE WHEN @s >= 1 AND i % 11 = 0 THEN 1 ELSE 0 END) % 4) + 1, N'Very High', N'High', N'Medium', N'Low'),
       CASE WHEN i % 17 = 0 THEN NULL ELSE i % 4 END,
       (i % 60) * 1.25 + CASE WHEN @s >= 1 AND i % 7 = 1 THEN 0.5 ELSE 0 END, (i % 60) * 1.5,
       CHOOSE((i % 4) + 1, N'Critical', N'High', N'Moderate', N'Low'),
       CASE WHEN i % 9 = 4 OR (@s >= 1 AND i % 13 = 6) THEN 100 + i % 3 END,
       CASE WHEN i % 61 = 0 THEN NULL
            WHEN i % 67 = 0 THEN N'not a json document'
            WHEN i % 71 = 0 THEN CONCAT(N'{"CollectionTime":"', CONVERT(nvarchar(30), @t, 126), N'","dup":1,"dup":2}')
            ELSE CONCAT(N'{"CollectionTime":"', CONVERT(nvarchar(30), @t, 126), N'","TimeGenerated":"', CONVERT(nvarchar(30), DATEADD(second, i, @t), 126), N'Z",',
                        N'"_BilledSize":', 300 + i + @s, N',"si_component":"Comp', i % 5, N'","si_note":"', CASE WHEN @s >= 1 AND i % 10 = 0 THEN N'moved' ELSE N'same' END, N' \/ text"}') END,
       i, 1000 - i + @s * 7
FROM n
WHERE NOT (@s = 1 AND i % 19 = 0)          -- gone in c2 ...
  AND NOT (@s = 2 AND i % 19 = 0 AND i % 38 = 0)   -- ... half of them back in c3 (a reopen), half stay gone
  AND NOT (@s >= 1 AND i % 23 = 0);         -- gone for good
-- exact duplicates (same content, two rows) and new findings in c2 / c3
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, RiskRating, ExemptionId, DetailJson, RaSeq, ImportanceRank)
SELECT @cid, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, RiskRating, ExemptionId, DetailJson, RaSeq, ImportanceRank
FROM sidata.Finding WHERE CollectionId = @cid AND RaSeq % 29 = 3;
-- CIs whose findings never change (their What changed rows come from the members): the same rows in every collection
;WITH n AS (SELECT TOP (30) ROW_NUMBER() OVER (ORDER BY (SELECT 1)) AS i FROM sys.all_objects)
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, RiskRating, DetailJson, RaSeq, ImportanceRank)
SELECT @cid, CONCAT(N'stable-', i % 6), CONCAT(N'steady', i % 6), N'Report_1', N'Endpoint', CONCAT(N'cfg.s', i), NULL, CONCAT(N'Steady ', i), N'Low', 2, i * 0.3, i * 0.4, N'Low',
       CONCAT(N'{"CollectionTime":"', CONVERT(nvarchar(30), @t, 126), N'","si_component":"Steady"}'), 9000 + i, 9000 + i
FROM n;
IF @s >= 1
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, RiskScoreWeighted, RiskRating, DetailJson, RaSeq)
SELECT TOP (15 * @s) @cid, CONCAT(N'ci-', o.object_id % 41), CONCAT(N'host', o.object_id % 41), N'Report_0', N'Endpoint', CONCAT(N'new.', ROW_NUMBER() OVER (ORDER BY o.object_id)), NULL, N'A new one', N'High', 1, 40, 41, N'High',
       CONCAT(N'{"CollectionTime":"', CONVERT(nvarchar(30), @t, 126), N'","si_component":"New"}'), 5000 + ROW_NUMBER() OVER (ORDER BY o.object_id)
FROM sys.all_objects AS o;
SELECT @cid;
'@
        function script:New-Estate([switch]$Changes) {
            $db = New-TestDb
            & $db.Seam $script:Schema @{} 'nonquery'
            & $db.Seam $script:Schema @{} 'nonquery'      # applied twice: the second apply is a no-op (FindingAt made again)
            $c = @()
            foreach ($k in 0, 1, 2) { $c += [long](& $db.Seam $script:Seed @{ When = ('2026-11-{0:00}T03:00:00' -f (20 + $k)); Side = [string]$k } 'scalar') }
            if ($Changes) { $null = Invoke-SIDataChanges -Invoke $db.Seam -Log $script:Quiet -BudgetSeconds 100000; $null = Invoke-SIDataSummaryGroups -Invoke $db.Seam -Log $script:Quiet -BudgetSeconds 100000 -Keep 5 }
            [pscustomobject]@{ Db = $db; C = $c }
        }
        # this test's OWN compare (independent of the product's hash): every column of every row as JSON, sorted
        function script:Get-Rows($Db, [string]$From) {
            $rows = @(& $Db.Seam ("SELECT (SELECT x.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J FROM ({0}) AS x" -f $From) @{} 'reader' | ForEach-Object { $_ } | ForEach-Object { [string]$_['J'] })
            [Array]::Sort($rows, [StringComparer]::Ordinal); , $rows
        }
        function script:Assert-Same($Db, [long]$Cid, [string]$Why) {
            $a = Get-Rows $Db "SELECT * FROM sidata.Finding WHERE CollectionId = $Cid"
            $b = Get-Rows $Db "SELECT * FROM sidata.FindingAt($Cid)"
            $b.Count | Should -Be $a.Count -Because "$Why (rows)"
            $first = $null; for ($i = 0; $i -lt $a.Count; $i++) { if ($a[$i] -cne $b[$i]) { $first = "row $i`n stored : $($a[$i])`n history: $($b[$i])"; break } }
            $first | Should -BeNullOrEmpty -Because $Why
        }
        $script:Lines = New-Object System.Collections.Generic.List[string]
        $script:Log = { param($l, $m) $script:Lines.Add("$l $m") }
        $script:E = New-Estate -Changes
        $script:R1 = Invoke-SIDataHistory -Invoke $script:E.Db.Seam -Mode 'on' -Log $script:Log -FirstSize 37 -Days 0
    }
    AfterAll {
        foreach ($s in @($script:E, $script:M, $script:K, $script:O)) { if ($s) { try { $s.Db.Cn.Dispose() } catch { } } }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        foreach ($name in $script:Dbs) {
            try {
                $m = New-Object System.Data.SqlClient.SqlConnection "Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"
                $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$name] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$name]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
            } catch { }
        }
    }
    It 'writes and verifies every kept collection (oldest first), no difference' {
        $raw = if ($script:SIDataHistoryLastError) { ([string]$script:SIDataHistoryLastError.Exception.ToString()) + ' AT ' + [string]$script:SIDataHistoryLastError.ScriptStackTrace } else { '' }
        $script:R1.Status | Should -Be 'ok' -Because (($script:Lines -join "`n") + "`n" + $raw)
        $script:R1.Written | Should -Be 3
        $script:R1.Verified | Should -Be 3
        $script:R1.Differences | Should -Be 0 -Because ($script:Lines -join "`n")
        @(& $script:E.Db.Seam "SELECT State FROM sidata.HistoryRun ORDER BY CollectionId" @{} 'reader' | ForEach-Object { $_ } | ForEach-Object { [string]$_['State'] }) | Should -Be @('verified', 'verified', 'verified')
    }
    It 'FindingAt gives every collection back exactly as sidata.Finding holds it (this test''s own compare)' {
        foreach ($c in $script:E.C) { Assert-Same $script:E.Db $c "collection $c" }
    }
    It 'the states are shared across runs; the run fields live on the member; a reopen gets its old state back' {
        $db = $script:E.Db
        $rows = [long](& $db.Seam 'SELECT COUNT_BIG(*) FROM sidata.Finding' @{} 'scalar')
        $states = [long](& $db.Seam 'SELECT COUNT_BIG(*) FROM sidata.FindingState' @{} 'scalar')
        $why = ''
        if ($states -ge [long]($rows / 2)) {
            $pair = @(& $db.Seam "SELECT (SELECT s.* FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) AS J, (SELECT m.RunValues) AS RV FROM sidata.FindingStateMember AS m JOIN sidata.Finding AS f ON f.CollectionId = m.CollectionId AND f.FindingId = m.FindingId JOIN sidata.FindingState AS s ON s.StateId = m.StateId WHERE f.RaSeq = 2 AND m.CollectionId IN ($($script:E.C[0]), $($script:E.C[1])) ORDER BY m.CollectionId" @{} 'reader' | ForEach-Object { $_ })
            $why = ($pair | ForEach-Object { [string]$_['J'] + ' RV=' + [string]$_['RV'] }) -join "`n"
        }
        $states | Should -BeLessThan ([long]($rows / 2)) -Because ("unchanged findings share one state over the runs`n" + $why)
        [long](& $db.Seam "SELECT COUNT_BIG(*) FROM sidata.FindingStateMember WHERE RunValues LIKE N'%_BilledSize%'" @{} 'scalar') | Should -BeGreaterThan 0
        [long](& $db.Seam "SELECT COUNT_BIG(*) FROM sidata.FindingState WHERE DetailJson LIKE N'%""CollectionTime"":""2026%'" @{} 'scalar') | Should -BeGreaterThan 0 -Because 'a document naming a key twice keeps its fields as they are'
        # the reopened findings (gone in c2, back in c3): their state in c3 is the one they had in c1
        $reopen = [long](& $db.Seam @"
SELECT COUNT_BIG(*) FROM sidata.FindingStateMember AS m3
JOIN sidata.Finding AS f ON f.CollectionId = m3.CollectionId AND f.FindingId = m3.FindingId
WHERE m3.CollectionId = $($script:E.C[2]) AND f.RaSeq % 38 = 19
  AND EXISTS (SELECT 1 FROM sidata.FindingStateMember AS m1 WHERE m1.CollectionId = $($script:E.C[0]) AND m1.StateId = m3.StateId)
  AND NOT EXISTS (SELECT 1 FROM sidata.FindingStateMember AS m2 WHERE m2.CollectionId = $($script:E.C[1]) AND m2.StateId = m3.StateId)
"@ @{} 'scalar')
        $reopen | Should -BeGreaterThan 0
    }
    It 'the change set is exact: per state, the counts of the two memberships' {
        $db = $script:E.Db; $c2 = $script:E.C[1]; $c1 = $script:E.C[0]
        $bad = [long](& $db.Seam @"
SELECT COUNT_BIG(*) FROM (
  SELECT COALESCE(a.StateId, b.StateId) AS StateId, ISNULL(a.N, 0) AS NPrev, ISNULL(b.N, 0) AS NNow
  FROM (SELECT StateId, COUNT(*) AS N FROM sidata.FindingStateMember WHERE CollectionId = $c1 GROUP BY StateId) AS a
  FULL JOIN (SELECT StateId, COUNT(*) AS N FROM sidata.FindingStateMember WHERE CollectionId = $c2 GROUP BY StateId) AS b ON b.StateId = a.StateId
  WHERE ISNULL(a.N, 0) <> ISNULL(b.N, 0)) AS w
FULL JOIN (SELECT * FROM sidata.FindingStateDelta WHERE CollectionId = $c2) AS d ON d.StateId = w.StateId AND d.NPrev = w.NPrev AND d.NNow = w.NNow
WHERE w.StateId IS NULL OR d.StateId IS NULL
"@ @{} 'scalar')
        $bad | Should -Be 0
        $hr = @(& $db.Seam "SELECT PrevCollectionId, Opened, Closed FROM sidata.HistoryRun WHERE CollectionId = $c2" @{} 'reader' | ForEach-Object { $_ })[0]
        [long]$hr['PrevCollectionId'] | Should -Be $c1
        [long]$hr['Opened'] | Should -BeGreaterThan 0; [long]$hr['Closed'] | Should -BeGreaterThan 0
    }
    It 'What changed from the change set equals the stored full build, both variants and the counts (c2 and c3)' {
        foreach ($c in $script:E.C[1], $script:E.C[2]) {
            $x = @(& $script:E.Db.Seam "SELECT Outcome, Differences FROM sidata.HistoryCompare WHERE CollectionId = $c AND Reader = N'changes'" @{} 'reader' | ForEach-Object { $_ })
            $x.Count | Should -Be 1
            [string]$x[0]['Outcome'] | Should -Be 'same' -Because ($script:Lines -join "`n")
        }
        [string](@(& $script:E.Db.Seam "SELECT Outcome FROM sidata.HistoryCompare WHERE CollectionId = $($script:E.C[0]) AND Reader = N'changes'" @{} 'reader' | ForEach-Object { $_ })[0]['Outcome']) | Should -Be 'not-ready' -Because 'the oldest collection has no pair'
        [long](& $script:E.Db.Seam "SELECT COUNT_BIG(*) FROM sidata.AssetChange WHERE CollectionId = $($script:E.C[1]) AND Change = N'unchanged'" @{} 'scalar') | Should -BeGreaterThan 0 -Because 'unchanged CIs were compared from the members, changed ones from the rows'
    }
    It 'the summary groups from the change set (changed groups computed again, the rest carried) equal the stored full build (c2 and c3)' {
        foreach ($c in $script:E.C[1], $script:E.C[2]) {
            $x = @(& $script:E.Db.Seam "SELECT Outcome, [Rows] FROM sidata.HistoryCompare WHERE CollectionId = $c AND Reader = N'summary-groups'" @{} 'reader' | ForEach-Object { $_ })
            $x.Count | Should -Be 1
            [string]$x[0]['Outcome'] | Should -Be 'same' -Because ($script:Lines -join "`n")
            [long]$x[0]['Rows'] | Should -BeGreaterThan 0
        }
        ($script:Lines -join "`n") | Should -Match 'group row\(s\) computed again, the rest carried'
    }
    It 'a stored summary group that is wrong is found by the build from the changes (a WARNING); the stored rows are never written by it' {
        $db = $script:E.Db; $c3 = $script:E.C[2]
        $null = & $db.Seam "UPDATE TOP (1) sidata.SummaryGroup SET Findings = Findings + 1 WHERE CollectionId = $c3; UPDATE sidata.HistoryRun SET State = N'written' WHERE CollectionId = $c3;" @{} 'nonquery'
        $before = [long](& $db.Seam "SELECT SUM(CONVERT(bigint, Findings)) FROM sidata.SummaryGroup WHERE CollectionId = $c3" @{} 'scalar')
        $r = Invoke-SIDataHistory -Invoke $db.Seam -Mode 'on' -Log $script:Quiet -FirstSize 50 -Days 0
        $r.Differences | Should -BeGreaterThan 0
        (@(Get-SIDataHistoryWarningText -Result $r) -join ' ') | Should -Match 'summary groups'
        [long](& $db.Seam "SELECT SUM(CONVERT(bigint, Findings)) FROM sidata.SummaryGroup WHERE CollectionId = $c3" @{} 'scalar') | Should -Be $before
        # put right by the full build (as the data sync does: the next build of the collection), then the same again
        $null = & $db.Seam "UPDATE sidata.Collection SET ContextAt = SYSUTCDATETIME() WHERE CollectionId = $c3" @{} 'nonquery'
        $null = Invoke-SIDataSummaryGroups -Invoke $db.Seam -Log $script:Quiet -BudgetSeconds 100000 -Keep 5
        $r2 = Invoke-SIDataHistory -Invoke $db.Seam -Mode 'on' -Log $script:Quiet -FirstSize 50 -Days 0
        $r2.Differences | Should -Be 0
    }
    It 'a second run with nothing moved writes nothing again' {
        $before = [long](& $script:E.Db.Seam 'SELECT COUNT_BIG(*) FROM sidata.HistoryCompare' @{} 'scalar')
        $r = Invoke-SIDataHistory -Invoke $script:E.Db.Seam -Mode 'on' -Log $script:Quiet -FirstSize 37 -Days 0
        $r.Written | Should -Be 0; $r.Differences | Should -Be 0
        [long](& $script:E.Db.Seam 'SELECT COUNT_BIG(*) FROM sidata.HistoryCompare' @{} 'scalar') | Should -Be $before
    }
    It 'a FULL build: the collection rewritten after its history (its marks moved) is written again and verified' {
        $db = $script:E.Db; $c3 = $script:E.C[2]
        $null = & $db.Seam "UPDATE sidata.Finding SET Title = Title + N' (fixed text)' WHERE CollectionId = $c3 AND RaSeq % 5 = 0; UPDATE sidata.Collection SET DerivedAt = SYSUTCDATETIME() WHERE CollectionId = $c3;" @{} 'nonquery'
        # the data sync's What changed and summary groups build the collection again first (its derive moved), as in a run
        $null = Invoke-SIDataChanges -Invoke $db.Seam -Log $script:Quiet -BudgetSeconds 100000
        $null = Invoke-SIDataSummaryGroups -Invoke $db.Seam -Log $script:Quiet -BudgetSeconds 100000 -Keep 5
        $r = Invoke-SIDataHistory -Invoke $db.Seam -Mode 'on' -Log $script:Quiet -FirstSize 50 -Days 0
        $r.Written | Should -Be 1; $r.Verified | Should -Be 1; $r.Differences | Should -Be 0
        Assert-Same $db $c3 'after the full build'
    }
    It 'a forced difference is found and said (ids and column names, never a value); the stored rows stay what is served' {
        $db = $script:E.Db; $c2 = $script:E.C[1]
        $sid = [long](& $db.Seam "SELECT TOP (1) m.StateId FROM sidata.FindingStateMember AS m WHERE m.CollectionId = $c2 AND NOT EXISTS (SELECT 1 FROM sidata.FindingStateMember AS o WHERE o.StateId = m.StateId AND o.CollectionId <> m.CollectionId) ORDER BY m.FindingId" @{} 'scalar')
        $null = & $db.Seam "UPDATE sidata.FindingState SET Title = N'secret value' WHERE StateId = $sid; UPDATE sidata.HistoryRun SET State = N'written' WHERE CollectionId = $c2;" @{} 'nonquery'
        $r = Invoke-SIDataHistory -Invoke $db.Seam -Mode 'on' -Log $script:Quiet -FirstSize 50 -Days 0
        $r.Differences | Should -BeGreaterThan 0
        [string](& $db.Seam "SELECT State FROM sidata.HistoryRun WHERE CollectionId = $c2" @{} 'scalar') | Should -Be 'differs'
        $w = @(Get-SIDataHistoryWarningText -Result $r)
        $w.Count | Should -BeGreaterThan 0
        ($w -join ' ') | Should -Match 'Title'
        ($w -join ' ') | Should -Not -Match 'secret value'
        [long](& $db.Seam "SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = $c2 AND Title = N'secret value'" @{} 'scalar') | Should -Be 0 -Because 'the stored rows are untouched'
        # the next run writes it again (a differing collection is never a base) and it is the same again
        $r2 = Invoke-SIDataHistory -Invoke $db.Seam -Mode 'on' -Log $script:Quiet -FirstSize 50 -Days 0
        $r2.Differences | Should -Be 0
        [string](& $db.Seam "SELECT State FROM sidata.HistoryRun WHERE CollectionId = $c2" @{} 'scalar') | Should -Be 'verified'
    }
    It 'retention: a collection whose rows are gone leaves the history; the states only it held go, shared ones stay' {
        $db = $script:E.Db; $c1 = $script:E.C[0]
        $only = [long](& $db.Seam "SELECT COUNT_BIG(*) FROM sidata.FindingState AS s WHERE NOT EXISTS (SELECT 1 FROM sidata.FindingStateMember AS m WHERE m.StateId = s.StateId AND m.CollectionId <> $c1)" @{} 'scalar')
        $only | Should -BeGreaterThan 0
        $total = [long](& $db.Seam 'SELECT COUNT_BIG(*) FROM sidata.FindingState' @{} 'scalar')
        $null = & $db.Seam "DELETE FROM sidata.Finding WHERE CollectionId = $c1; UPDATE sidata.Collection SET RetiredAt = SYSUTCDATETIME() WHERE CollectionId = $c1;" @{} 'nonquery'
        $r = Invoke-SIDataHistory -Invoke $db.Seam -Mode 'on' -Log $script:Quiet -FirstSize 50 -Days 0
        $r.Status | Should -Be 'ok'
        [long](& $db.Seam "SELECT COUNT_BIG(*) FROM sidata.FindingStateMember WHERE CollectionId = $c1" @{} 'scalar') | Should -Be 0
        [long](& $db.Seam "SELECT COUNT_BIG(*) FROM sidata.HistoryRun WHERE CollectionId = $c1" @{} 'scalar') | Should -Be 0
        [long](& $db.Seam 'SELECT COUNT_BIG(*) FROM sidata.FindingState' @{} 'scalar') | Should -Be ($total - $only)
        foreach ($c in $script:E.C[1], $script:E.C[2]) { Assert-Same $db $c "collection $c after the retention" }
    }
    It 'a migration interrupted mid-way resumes from its mark and ends verified, every finding a member once' {
        $script:M = New-Estate
        $db = $script:M.Db; $inner = $db.Seam
        $state = @{ N = 0 }
        $breaking = { param($Sql, $Params, $Mode) if ([string]$Sql -match 'INSERT sidata\.FindingStateMember') { $state.N++; if ($state.N -eq 6) { throw 'the connection was lost (test)' } }; & $inner $Sql $Params $Mode }.GetNewClosure()
        $r1 = Invoke-SIDataHistory -Invoke $breaking -Mode 'on' -Log $script:Quiet -FirstSize 29 -Days 0
        $r1.Status | Should -Be 'failed'
        $hr = @(& $inner "SELECT CollectionId, State, UptoFindingId FROM sidata.HistoryRun WHERE State = N'writing'" @{} 'reader' | ForEach-Object { $_ })
        $hr.Count | Should -Be 1
        [long]$hr[0]['UptoFindingId'] | Should -BeGreaterThan 0
        $lines = New-Object System.Collections.Generic.List[string]
        $r2 = Invoke-SIDataHistory -Invoke $inner -Mode 'on' -Log { param($l, $m) $lines.Add($m) }.GetNewClosure() -FirstSize 29 -Days 0
        $r2.Status | Should -Be 'ok'; $r2.Differences | Should -Be 0
        ($lines -join "`n") | Should -Match '\(resumed\)'
        @(& $inner "SELECT State FROM sidata.HistoryRun ORDER BY CollectionId" @{} 'reader' | ForEach-Object { $_ } | ForEach-Object { [string]$_['State'] }) | Should -Be @('verified', 'verified', 'verified')
        [long](& $inner 'SELECT COUNT_BIG(*) FROM sidata.FindingStateMember' @{} 'scalar') | Should -Be ([long](& $inner 'SELECT COUNT_BIG(*) FROM sidata.Finding' @{} 'scalar'))
        foreach ($c in $script:M.C) { Assert-Same $db $c "migrated collection $c" }
    }
    It '#1359 a check from the change set that cannot finish (a statement timeout) is recorded failed, the collection STAYS VERIFIED (the next change set''s base), and the next run makes only the checks' {
        $script:K = New-Estate -Changes
        $db = $script:K.Db; $inner = $db.Seam
        $timingOut = { param($Sql, $Params, $Mode) if ([string]$Sql -match 'CREATE TABLE #ak') { throw 'Timeout expired.  The timeout period elapsed prior to completion of the operation (test)' }; & $inner $Sql $Params $Mode }.GetNewClosure()
        $lines = New-Object System.Collections.Generic.List[string]
        $r1 = Invoke-SIDataHistory -Invoke $timingOut -Mode 'on' -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure() -FirstSize 50 -Days 0
        $r1.Status | Should -Be 'ok' -Because ($lines -join "`n")
        $r1.Verified | Should -Be 3
        @(& $inner "SELECT State FROM sidata.HistoryRun ORDER BY CollectionId" @{} 'reader' | ForEach-Object { $_ } | ForEach-Object { [string]$_['State'] }) | Should -Be @('verified', 'verified', 'verified') -Because 'a check that did not finish is not a difference and not a failed history'
        foreach ($c in $script:K.C[1], $script:K.C[2]) {
            [string](& $inner "SELECT TOP (1) Outcome FROM sidata.HistoryCompare WHERE CollectionId = $c AND Reader = N'summary-groups' ORDER BY HistoryCompareId DESC" @{} 'scalar') | Should -Be 'failed'
            [string](& $inner "SELECT TOP (1) Outcome FROM sidata.HistoryCompare WHERE CollectionId = $c AND Reader = N'key-figures' ORDER BY HistoryCompareId DESC" @{} 'scalar') | Should -Not -Be 'failed' -Because 'each check on its own'
        }
        ($lines -join "`n") | Should -Match 'the summary groups \(0 group row\(s\) computed again, the rest carried\): not finished'
        # the base holds: the newest collection's change set is against the one before it
        [long](& $inner "SELECT PrevCollectionId FROM sidata.HistoryRun WHERE CollectionId = $($script:K.C[2])" @{} 'scalar') | Should -Be $script:K.C[1]
        # the next run: nothing written again, only the checks that are missing -- and they are the same
        $r2 = Invoke-SIDataHistory -Invoke $inner -Mode 'on' -Log $script:Quiet -FirstSize 50 -Days 0
        $r2.Status | Should -Be 'ok'; $r2.Written | Should -Be 0; $r2.Verified | Should -Be 0; $r2.Differences | Should -Be 0
        foreach ($c in $script:K.C[1], $script:K.C[2]) {
            [string](& $inner "SELECT TOP (1) Outcome FROM sidata.HistoryCompare WHERE CollectionId = $c AND Reader = N'summary-groups' ORDER BY HistoryCompareId DESC" @{} 'scalar') | Should -Be 'same'
        }
        $before = [long](& $inner 'SELECT COUNT_BIG(*) FROM sidata.HistoryCompare' @{} 'scalar')
        $null = Invoke-SIDataHistory -Invoke $inner -Mode 'on' -Log $script:Quiet -FirstSize 50 -Days 0
        [long](& $inner 'SELECT COUNT_BIG(*) FROM sidata.HistoryCompare' @{} 'scalar') | Should -Be $before -Because 'every check is recorded: nothing runs again'
    }
    It '#1359 outside a run (the update''s / the index build job''s bounded window) the history is written and compared row for row only; the checks follow in the data sync' {
        $script:O = New-Estate -Changes
        $db = $script:O.Db; $inner = $db.Seam
        $seen = @{ N = 0 }
        $watch = { param($Sql, $Params, $Mode, $Timeout) if ([string]$Sql -match 'CREATE TABLE #ak|INSERT sidata\.HistoryCompare \(CollectionId, Reader, \[Rows\], Differences, Outcome, Detail\) VALUES \(CONVERT\(int, @C\), N''(changes|key-figures)''') { $seen.N++ }; & $inner $Sql $Params $Mode }.GetNewClosure()
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataHistory -Invoke $watch -Mode 'on' -Log { param($l, $m) $lines.Add($m) }.GetNewClosure() -OutsideRun -DeadlineUtc ([datetime]::UtcNow.AddMinutes(30)) -FirstSize 50
        $r.Verified | Should -Be 3 -Because ($lines -join "`n")
        $seen.N | Should -Be 0 -Because 'no whole-collection check is started under a window''s statement limit'
        ($lines -join "`n") | Should -Match 'the checks from the change set follow in the next data sync'
        $r2 = Invoke-SIDataHistory -Invoke $inner -Mode 'on' -Log $script:Quiet -FirstSize 50 -Days 0
        $r2.Written | Should -Be 0; $r2.Differences | Should -Be 0
        foreach ($c in $script:O.C[1], $script:O.C[2]) {
            [string](& $inner "SELECT TOP (1) Outcome FROM sidata.HistoryCompare WHERE CollectionId = $c AND Reader = N'summary-groups' ORDER BY HistoryCompareId DESC" @{} 'scalar') | Should -Be 'same'
            [string](& $inner "SELECT TOP (1) Outcome FROM sidata.HistoryCompare WHERE CollectionId = $c AND Reader = N'changes' ORDER BY HistoryCompareId DESC" @{} 'scalar') | Should -Be 'same'
        }
    }
}
