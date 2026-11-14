#Requires -Version 7.0
<#
    A COLLECTION'S OWN TRUST VERDICT IS REMOVED WITH ITS COLLECTION (REQUIREMENTS #1228). sidata.CollectionTrust (one row per
    CollectionTime + Grain, written by Risk Analysis) was never removed -- about two rows a day, without end. The retention
    READS it to decide what to keep (only trusted collections count, #1226) and the data sync reads a collection's verdict by
    its time, so a verdict may go only once nothing can ask for it.

    What these tests keep true (engine\_shared\data-sql\SI-DataSql.ps1: Get-SIDataCollectionTrustRemoveSql,
    Get-SIDataCollectionTrustOrphanSql, Invoke-SIDataCollectionRetention):
      * a collection whose removal FINISHED loses its verdict in the same step, AFTER its rows;
      * a removal that stops part way keeps the verdict (it explains the mark);
      * NEGATIVE: never the verdict of a collection still present (not marked, or marked with rows left), of the published
        run, or of a collection a kept one carries rows from;
      * a verdict whose collection is gone and that is older than the oldest kept collection of its grain is removed once,
        bounded per call, said in one line; a younger one is not;
      * the retention's trust rule still sees the right verdicts afterwards, and a second pass removes nothing more;
      * a dry run, a mark-only and a finish-only call never sweep; the retire range / batch / mark statements are unchanged
        (their SHA pins stay in SIv3-RetireGentle).
    Offline (fakes) plus a run against a local SQL Server when SI_TEST_LOCALSQL is set (the test runner). Pro path.
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
    $script:Schema = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'sql\si-data-schema.sql')
    $script:Quiet = { param($l, $m) }
    function script:T([int]$Day, [int]$Hour = 8) { [datetime]::SpecifyKind((Get-Date -Year 2026 -Month 11 -Day $Day -Hour $Hour -Minute 0 -Second 0 -Millisecond 0), 'Utc') }
    function script:Row([string]$Grain, $Id, [datetime]$Time, [string]$Status) {
        @{ Grain = $Grain; CollectionId = $Id; CollectionTime = $Time; Status = $Status; RetiredAt = [System.DBNull]::Value; HasRows = 0; Published = 0; Untrusted = 0 }
    }
    # a fake data database: the state, the mark (1), each range / batch answers nothing left; records every statement
    function script:New-Fake([object[]]$State) {
        $sent = New-Object System.Collections.ArrayList
        $inv = { param([string]$sql, $p, [string]$mode)
            [void]$sent.Add([pscustomobject]@{ Sql = $sql; P = $(if ($p) { $p.Clone() } else { @{} }); Mode = $mode })
            if ($sql -match 'AS HasRows') { return , @($State) }
            if ($sql -match 'SET RetiredAt = SYSUTCDATETIME\(\)') { return 1 }
            # the verdict's two statements (each answers one verdict removed)
            if ($sql -match 'DELETE FROM sidata\.CollectionTrust|CREATE TABLE #gone') { return 1 }
            if ($sql -match 'CollectionReportCarry') { return , @() }
            if ($sql -match 'AS Refused') { return , @(@{ N = 0; Hi = $null; Refused = 0; Cap = 100 }) }
            if ($mode -eq 'scalar') { return 0 }
            , @() }.GetNewClosure()
        [pscustomobject]@{ Invoke = $inv; Sent = $sent }
    }
    function script:IndexOfSql($Sent, [string]$Pattern) { $i = 0; foreach ($s in $Sent) { if ($s.Sql -match $Pattern) { return $i }; $i++ }; -1 }
    function script:LastIndexOfSql($Sent, [string]$Pattern) { $r = -1; $i = 0; foreach ($s in $Sent) { if ($s.Sql -match $Pattern) { $r = $i }; $i++ }; $r }
    function script:New-LocalInvoke([string]$Db) {
        $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True;Connection Timeout=90"
        {
            param([string]$sql, $p, [string]$mode)
            $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
            try {
                $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = $sql
                if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                while ($r.Read()) { $h = @{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add($h) }
                $r.Close(); return , $rows.ToArray()
            } finally { $cn.Close() }
        }.GetNewClosure()
    }
    # a fresh database with the shipped schema; -Body gets the invoke; dropped afterwards
    function script:Use-Db([scriptblock]$Body) {
        $db = 'sitrrow_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalInvoke $db
            [void](& $inv $script:Schema @{} 'nonquery')
            [void](& $inv (Get-SIDataRetiredColumnsSql) @{} 'scalar')
            & $Body $inv
        } finally {
            try { [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery') } catch { }
        }
    }
    function script:Add-Coll($Inv, [int]$Id, [string]$Time, [int]$Findings = 2, [string]$Status = 'Complete') {
        [void](& $Inv ("SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status, ViewsReadyAt, DerivedAt, ContextAt) VALUES ({0}, '{1}', 'Detailed', N'{2}', SYSUTCDATETIME(), SYSUTCDATETIME(), SYSUTCDATETIME()); SET IDENTITY_INSERT sidata.Collection OFF;" -f $Id, $Time, $Status) @{} 'nonquery')
        for ($i = 1; $i -le $Findings; $i++) { [void](& $Inv ("INSERT sidata.Finding (CollectionId, AssetKey, ReportName, Severity, Tier, RiskScore) VALUES ({0}, N'a{1}', N'R', N'High', 1, 5)" -f $Id, $i) @{} 'nonquery') }
    }
    function script:Add-Trust($Inv, [string]$Time, [int]$Trusted = 1, [string]$Grain = 'Detailed') {
        [void](& $Inv ("INSERT sidata.CollectionTrust (CollectionTime, Grain, Trusted, Why) VALUES ('{0}', N'{1}', {2}, {3})" -f $Time, $Grain, $Trusted, $(if ($Trusted) { 'NULL' } else { "N'a source collection failed'" })) @{} 'nonquery')
    }
    function script:TrustTimes($Inv, [string]$Grain = 'Detailed') {
        @(@(& $Inv ("SELECT CONVERT(nvarchar(19), CollectionTime, 126) AS T FROM sidata.CollectionTrust WHERE Grain = N'{0}' ORDER BY CollectionTime" -f $Grain) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_['T'] })
    }
}

AfterAll { Set-SIDataRetiredReady -Ready $false }

Describe 'the statements (offline)' {
    It 'the verdict of one collection is removed only after the checks: marked, no rows left, no other present one, not published, not carried from' {
        $d = Get-SIDataCollectionTrustRemoveSql -Grain Detailed
        $del = $d.IndexOf('DELETE FROM sidata.CollectionTrust')
        $del | Should -BeGreaterThan 0
        foreach ($k in 'RetiredAt IS NOT NULL', 'FROM sidata.Finding WHERE CollectionId = @c', 'FROM sidata.Recommendation WHERE CollectionId = @c', 'o.RetiredAt IS NULL', 'sidata.PublishedRun', 'sidata.CollectionReportCarry') {
            $d.IndexOf($k) | Should -BeGreaterThan -1 -Because $k
            $d.IndexOf($k) | Should -BeLessThan $del -Because "$k is checked before anything is removed"
        }
        $d | Should -Match "WHERE CollectionTime = @t AND Grain = N'Detailed';"
        $s = Get-SIDataCollectionTrustRemoveSql -Grain Summary
        foreach ($k in 'RetiredAt IS NOT NULL', 'sidata.SummaryRow', 'sidata.SummaryAsset', 'SummaryCollectionTime = @t') { $s.IndexOf($k) | Should -BeLessThan $s.IndexOf('DELETE FROM sidata.CollectionTrust') -Because $k }
        $s | Should -Match "Grain = N'Summary';"
    }
    It 'the orphan statement is bounded per grain and never touches a time at or after the oldest kept collection' {
        $o = Get-SIDataCollectionTrustOrphanSql
        ([regex]::Matches($o, 'SELECT TOP \(@b\)')).Count | Should -Be 2
        $o | Should -Match 't\.CollectionTime < @oldD'
        $o | Should -Match 't\.CollectionTime < @oldS'
        $o | Should -Match 'sidata\.CollectionReportCarry'
        $o | Should -Not -Match 'DELETE TOP' -Because 'no statement of the collections'' removal looks like it'
        # a marked Summary load still holds its verdict while it has rows OR assets left (as the per-collection removal checks)
        $o | Should -Match ([regex]::Escape('EXISTS (SELECT 1 FROM sidata.SummaryAsset AS a WHERE a.CollectionTime = l.CollectionTime)'))
        $o | Should -Match ([regex]::Escape("OBJECT_ID('sidata.SummaryRow') IS NOT NULL AND OBJECT_ID('sidata.SummaryAsset') IS NOT NULL"))
    }
    It 'the three pinned retire statements carry nothing of the verdict (the SHA pins in SIv3-RetireGentle stay as they are)' {
        foreach ($fn in 'Get-SIDataRetireRangeSql', 'Get-SIDataRetireBatchSql') { (Get-Command $fn).Definition | Should -Not -Match 'CollectionTrust' }
        (Get-Command Get-SIDataRetireMarkSql).Definition | Should -Not -Match 'DELETE FROM sidata\.CollectionTrust'
    }
}

Describe 'the step (offline)' {
    It 'a finished removal sends the verdict''s removal AFTER its rows, then the orphan sweep once' {
        $f = New-Fake -State @((Row Detailed 1 (T 1) Complete), (Row Detailed 2 (T 2) Complete), (Row Detailed 3 (T 3) Complete))
        $lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataCollectionRetention -Invoke $f.Invoke -Log { param($l, $m) $lines.Add([string]$m) }.GetNewClosure()
        @($r.Removed).Count | Should -Be 1
        $iTrust = IndexOfSql $f.Sent 'DELETE FROM sidata\.CollectionTrust WHERE CollectionTime = @t'
        $iTrust | Should -BeGreaterThan (LastIndexOfSql $f.Sent 'AS Refused|DELETE TOP') -Because 'the verdict goes after every row'
        $f.Sent[$iTrust].P['CollectionId'] | Should -Be '1'
        $r.TrustRemoved | Should -Be 1
        @($f.Sent | Where-Object { $_.Sql -match 'CREATE TABLE #gone' }).Count | Should -Be 1
        (IndexOfSql $f.Sent 'CREATE TABLE #gone') | Should -BeGreaterThan $iTrust
        @($lines | Where-Object { $_ -match '^collections : collection 1 \(Detailed, .*\): its findings are removed \(0 row\(s\)\), with its saved verdict on the source data; its totals for the trends stay$' }).Count | Should -Be 1 -Because ($lines -join ' | ')
        @($lines | Where-Object { $_ -match '^collections : removed 1 saved verdict\(s\) on the source data of collections that are no longer stored$' }).Count | Should -Be 1
    }
    It 'a removal that stops part way keeps the verdict -- and no sweep' {
        $f = New-Fake -State @((Row Detailed 1 (T 1) Complete), (Row Detailed 2 (T 2) Complete), (Row Detailed 3 (T 3) Complete))
        Mock Remove-SIDataCollectionRows { [pscustomobject]@{ Rows = [ordered]@{ Finding = 2L }; Done = $false; Refused = $false; Stopped = $true; Paused = $false; StopWhy = '' } }
        $r = Invoke-SIDataCollectionRetention -Invoke $f.Invoke -Log $script:Quiet
        @($r.Removed).Count | Should -Be 0
        @($f.Sent | Where-Object { $_.Sql -match 'sidata\.CollectionTrust' -and $_.Sql -match 'DELETE' }).Count | Should -Be 0
    }
    It 'a refused removal keeps the verdict' {
        $f = New-Fake -State @((Row Detailed 1 (T 1) Complete), (Row Detailed 2 (T 2) Complete), (Row Detailed 3 (T 3) Complete))
        Mock Remove-SIDataCollectionRows { [pscustomobject]@{ Rows = [ordered]@{ Finding = 0L }; Done = $false; Refused = $true; Stopped = $false; Paused = $false; StopWhy = '' } }
        $null = Invoke-SIDataCollectionRetention -Invoke $f.Invoke -Log $script:Quiet
        @($f.Sent | Where-Object { $_.Sql -match 'DELETE FROM sidata\.CollectionTrust WHERE CollectionTime = @t' }).Count | Should -Be 0
    }
    It 'a dry run, a mark-only and a finish-only call never sweep' {
        $st = @((Row Detailed 1 (T 1) Complete), (Row Detailed 2 (T 2) Complete), (Row Detailed 3 (T 3) Complete))
        $a = New-Fake -State $st; $null = Invoke-SIDataCollectionRetention -Invoke $a.Invoke -DryRun -Log $script:Quiet
        $b = New-Fake -State $st; $null = Invoke-SIDataCollectionRetention -Invoke $b.Invoke -MarkOnly -Log $script:Quiet
        $c = New-Fake -State $st; $null = Invoke-SIDataCollectionRetention -Invoke $c.Invoke -FinishOnly -FinishFloorUtc (T 3) -FinishMarkedBeforeUtc (T 4) -TimeBudgetSeconds 60 -Log $script:Quiet
        foreach ($x in $a, $b, $c) { @($x.Sent | Where-Object { $_.Sql -match 'sidata\.CollectionTrust' -and $_.Sql -match 'DELETE' }).Count | Should -Be 0 }
    }
    It 'a failing verdict statement never fails the step' {
        $st = @((Row Detailed 1 (T 1) Complete), (Row Detailed 2 (T 2) Complete), (Row Detailed 3 (T 3) Complete))
        $base = New-Fake -State $st
        $inv = { param([string]$sql, $p, [string]$mode) if ($sql -match 'DELETE FROM sidata\.CollectionTrust|#gone') { throw 'the database is busy' }; & $base.Invoke $sql $p $mode }.GetNewClosure()
        $r = Invoke-SIDataCollectionRetention -Invoke $inv -Log $script:Quiet
        $r.Status | Should -Be 'ok'
        @($r.Removed).Count | Should -Be 1
        $r.TrustRemoved | Should -Be 0
    }
}

Describe 'on a real SQL Server' {
    It 'a fully removed collection loses its verdict; kept ones keep theirs; the trust rule still holds; a second pass removes nothing more' -Skip:(-not $script:LocalSql) {
        Use-Db {
            param($inv)
            # 1..6 complete; 2 and 6 untrusted, the rest trusted -- every one with its verdict
            foreach ($d in 1..6) { Add-Coll $inv $d ('2026-11-{0:00}T08:00:00' -f $d); Add-Trust $inv ('2026-11-{0:00}T08:00:00' -f $d) $(if ($d -in 2, 6) { 0 } else { 1 }) }
            $r = Invoke-SIDataCollectionRetention -Invoke $inv -KeepCollections 3 -BatchSize 2 -Log $script:Quiet
            @($r.Removed | ForEach-Object { [int]$_.CollectionId } | Sort-Object) | Should -Be @(1, 2)
            $r.TrustRemoved | Should -Be 2
            TrustTimes $inv | Should -Be @('2026-11-03T08:00:00', '2026-11-04T08:00:00', '2026-11-05T08:00:00', '2026-11-06T08:00:00')
            # the trust rule still sees the right verdicts: of the collections still kept, only 6 is untrusted
            $state = @(@(& $inv (Get-SIDataRetentionStateSql) @{} 'reader') | ForEach-Object { $_ } | Where-Object { $null -eq $_['RetiredAt'] })
            @($state | Where-Object { [int]$_['Untrusted'] -eq 1 } | ForEach-Object { [int]$_['CollectionId'] }) | Should -Be @(6)
            # a second pass removes nothing more -- no collection, no verdict
            $again = Invoke-SIDataCollectionRetention -Invoke $inv -KeepCollections 3 -Log $script:Quiet
            @($again.Removed).Count | Should -Be 0
            $again.TrustRemoved | Should -Be 0
            $again.TrustOrphansRemoved | Should -Be 0
            @(TrustTimes $inv).Count | Should -Be 4
            [int](& $inv 'SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId IN (3, 4, 5, 6)' @{} 'scalar') | Should -Be 8
        }
    }
    It 'a removal that stops part way keeps the verdict; finishing it removes the verdict' -Skip:(-not $script:LocalSql) {
        Use-Db {
            param($inv)
            foreach ($d in 1..3) { Add-Coll $inv $d ('2026-11-{0:00}T08:00:00' -f $d); Add-Trust $inv ('2026-11-{0:00}T08:00:00' -f $d) }
            # the mark only: collection 1 is marked with its rows left (a removal that stopped part way looks the same)
            $m = Invoke-SIDataCollectionRetention -Invoke $inv -MarkOnly -Log $script:Quiet
            @($m.Marked | ForEach-Object { [int]$_.CollectionId }) | Should -Be @(1)
            [int](& $inv (Get-SIDataCollectionTrustRemoveSql -Grain Detailed) @{ CollectionId = '1'; CollectionTime = '' } 'scalar') | Should -Be 0 -Because 'its rows are still there'
            # part of its rows gone, the rest still there
            [void](& $inv "DELETE TOP (1) FROM sidata.Finding WHERE CollectionId = 1" @{} 'nonquery')
            [int](& $inv (Get-SIDataCollectionTrustRemoveSql -Grain Detailed) @{ CollectionId = '1'; CollectionTime = '' } 'scalar') | Should -Be 0
            TrustTimes $inv | Should -Contain '2026-11-01T08:00:00'
            # the next call finishes it -- and its verdict goes with it
            $fin = Invoke-SIDataCollectionRetention -Invoke $inv -Log $script:Quiet
            @($fin.Removed | ForEach-Object { [int]$_.CollectionId }) | Should -Be @(1)
            TrustTimes $inv | Should -Be @('2026-11-02T08:00:00', '2026-11-03T08:00:00')
        }
    }
    It 'NEGATIVE: never the verdict of a kept, a published or a carried-from collection' -Skip:(-not $script:LocalSql) {
        Use-Db {
            param($inv)
            foreach ($d in 1..5) { Add-Coll $inv $d ('2026-11-{0:00}T08:00:00' -f $d); Add-Trust $inv ('2026-11-{0:00}T08:00:00' -f $d) }
            $rm = { param($id) [int](& $inv (Get-SIDataCollectionTrustRemoveSql -Grain Detailed) @{ CollectionId = [string]$id; CollectionTime = '' } 'scalar') }
            # kept (not marked), even with no rows
            [void](& $inv 'DELETE FROM sidata.Finding WHERE CollectionId = 4' @{} 'nonquery')
            & $rm 4 | Should -Be 0 -Because 'a collection that is not marked is still present'
            # published: marked by hand, no rows left -- still refused
            [void](& $inv "DELETE FROM sidata.Finding WHERE CollectionId = 1; UPDATE sidata.Collection SET RetiredAt = SYSUTCDATETIME(), RetiredWhy = N'test' WHERE CollectionId = 1; INSERT sidata.PublishedRun (Name, DetailedCollectionId, DetailedCollectionTime, Source) VALUES (N'current', 1, '2026-11-01T08:00:00', N'run');" @{} 'nonquery')
            & $rm 1 | Should -Be 0 -Because 'the published run'
            # carried from: 2 is marked with no rows, the kept 5 carries rows from it
            [void](& $inv "DELETE FROM sidata.Finding WHERE CollectionId = 2; UPDATE sidata.Collection SET RetiredAt = SYSUTCDATETIME(), RetiredWhy = N'test' WHERE CollectionId = 2; INSERT sidata.CollectionReportCarry (CollectionId, ReportName, FromCollectionId, FromTime, CarriedRows, ThisRunRows) VALUES (5, N'R', 2, '2026-11-02T08:00:00', 1, 0);" @{} 'nonquery')
            & $rm 2 | Should -Be 0 -Because 'a kept collection carries rows from it'
            # the control: 3 marked with no rows, nothing else holds it -- removed
            [void](& $inv "DELETE FROM sidata.Finding WHERE CollectionId = 3; UPDATE sidata.Collection SET RetiredAt = SYSUTCDATETIME(), RetiredWhy = N'test' WHERE CollectionId = 3;" @{} 'nonquery')
            & $rm 3 | Should -Be 1
            TrustTimes $inv | Should -Be @('2026-11-01T08:00:00', '2026-11-02T08:00:00', '2026-11-04T08:00:00', '2026-11-05T08:00:00')
            # the sweep leaves the published and the carried-from ones too
            [int](& $inv (Get-SIDataCollectionTrustOrphanSql) @{ Batch = '100' } 'scalar') | Should -Be 0
        }
    }
    It 'verdicts whose collection is gone: older than the oldest kept are removed (bounded), younger ones are not' -Skip:(-not $script:LocalSql) {
        Use-Db {
            param($inv)
            foreach ($d in 10..12) { Add-Coll $inv $d ('2026-11-{0:00}T08:00:00' -f $d); Add-Trust $inv ('2026-11-{0:00}T08:00:00' -f $d) }
            # three orphans from before (no collection), one at the time of a marked collection that still holds rows, one younger
            foreach ($t in '2026-10-01T08:00:00', '2026-10-02T08:00:00', '2026-10-03T08:00:00') { Add-Trust $inv $t 0 }
            Add-Coll $inv 5 '2026-11-05T08:00:00' 1
            [void](& $inv "UPDATE sidata.Collection SET RetiredAt = SYSUTCDATETIME(), RetiredWhy = N'superseded' WHERE CollectionId = 5" @{} 'nonquery')
            Add-Trust $inv '2026-11-05T08:00:00'
            Add-Trust $inv '2026-11-20T08:00:00'
            # Summary: a kept load, an orphan older than it
            [void](& $inv "INSERT sidata.SummaryLoad (CollectionTime, Status) VALUES ('2026-11-12T09:00:00', N'Complete')" @{} 'nonquery')
            Add-Trust $inv '2026-10-01T09:00:00' 1 'Summary'
            Add-Trust $inv '2026-11-12T09:00:00' 1 'Summary'
            # bounded: two per grain per call
            [int](& $inv (Get-SIDataCollectionTrustOrphanSql) @{ Batch = '2' } 'scalar') | Should -Be 3
            TrustTimes $inv | Should -Be @('2026-10-03T08:00:00', '2026-11-05T08:00:00', '2026-11-10T08:00:00', '2026-11-11T08:00:00', '2026-11-12T08:00:00', '2026-11-20T08:00:00')
            TrustTimes $inv 'Summary' | Should -Be @('2026-11-12T09:00:00')
            # the step sweeps the rest, says it once, and a second pass removes nothing more
            $lines = New-Object System.Collections.Generic.List[string]
            $r = Invoke-SIDataCollectionRetention -Invoke $inv -KeepCollections 3 -Log { param($l, $m) $lines.Add([string]$m) }.GetNewClosure()
            $r.TrustOrphansRemoved | Should -BeGreaterOrEqual 1
            TrustTimes $inv | Should -Not -Contain '2026-10-03T08:00:00'
            TrustTimes $inv | Should -Contain '2026-11-20T08:00:00' -Because 'younger than the oldest kept collection: Risk Analysis may have written it before the collection is stored'
            TrustTimes $inv | Should -Contain '2026-11-10T08:00:00'
            @($lines | Where-Object { $_ -match '^collections : removed \d+ saved verdict\(s\) on the source data of collections that are no longer stored$' }).Count | Should -Be 1 -Because ($lines -join ' | ')
            $again = Invoke-SIDataCollectionRetention -Invoke $inv -KeepCollections 3 -Log $script:Quiet
            $again.TrustOrphansRemoved | Should -Be 0
            $again.TrustRemoved | Should -Be 0
        }
    }
    It 'NEGATIVE (Summary): a marked load with only ASSET rows left keeps its verdict in the sweep; once they are gone it is removed' -Skip:(-not $script:LocalSql) {
        Use-Db {
            param($inv)
            # a kept load (the bound) and an older MARKED load with no Summary rows, but its assets still there
            [void](& $inv "INSERT sidata.SummaryLoad (CollectionTime, Status) VALUES ('2026-11-12T09:00:00', N'Complete'), ('2026-10-01T09:00:00', N'Complete')" @{} 'nonquery')
            [void](& $inv "UPDATE sidata.SummaryLoad SET RetiredAt = SYSUTCDATETIME() WHERE CollectionTime = '2026-10-01T09:00:00'" @{} 'nonquery')
            [void](& $inv "INSERT sidata.SummaryAsset (CollectionTime, RowNo, Ordinal, AssetName, AssetId) VALUES ('2026-10-01T09:00:00', 1, 1, N'host-1', N'a1')" @{} 'nonquery')
            Add-Trust $inv '2026-10-01T09:00:00' 1 'Summary'
            Add-Trust $inv '2026-11-12T09:00:00' 1 'Summary'
            [int](& $inv (Get-SIDataCollectionTrustOrphanSql) @{ Batch = '100' } 'scalar') | Should -Be 0 -Because 'its assets are still stored'
            TrustTimes $inv 'Summary' | Should -Be @('2026-10-01T09:00:00', '2026-11-12T09:00:00')
            # the control: the assets gone -> the verdict goes in the sweep
            [void](& $inv "DELETE FROM sidata.SummaryAsset WHERE CollectionTime = '2026-10-01T09:00:00'" @{} 'nonquery')
            [int](& $inv (Get-SIDataCollectionTrustOrphanSql) @{ Batch = '100' } 'scalar') | Should -Be 1
            TrustTimes $inv 'Summary' | Should -Be @('2026-11-12T09:00:00')
        }
    }
}
