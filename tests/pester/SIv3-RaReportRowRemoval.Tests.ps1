#Requires -Version 7.0
<#
    #1397 -- A DETAILED REPORT OF 7 M+ ROWS AT THE LARGE INSTALL (live 2026-11-24 .. 11-25, run ct-20261124160149000).

      (1) THE REMOVAL OF AN UNDELIVERED REPORT'S ROWS CRAWLED: "removing the rows the report stored: 7,160,452 row(s) so far
          in 11,371 batch(es), 58,590 s -- next batch 601". A forward walk on IX_Finding_RaSeq was built and MEASURED slower
          than the 3.1.51 batching (1 M rows, accelerated database recovery on: 1,016 vs 1,158 rows/s), so the 3.1.51
          statements and batching are kept (DELETE TOP, 5,000 first, aimed at 5 s). ADDED (two-agent check): "done" only
          when PROVEN -- after a pass the statement is asked again until a pass removes nothing (both removers).
      (2) THE WORKER THAT PUT THE REPORT TOGETHER RAN OUT OF MEMORY (GetValue OutOfMemoryException): the end-of-report
          trace-name check read EVERY candidate row with its whole JSON in one list. FIXED: in pages of shared trace hashes
          (Get-RAStreamTracePageSql), each page read, named and written before the next; the page sized by the rows it held.

    Offline (a fake database in memory) plus real SQL Server parts (SI_TEST_LOCALSQL: the test VM / the Linux runner's SQL
    sidecar). The 2 M-row measurement is tagged Scale (on demand: Invoke-FastGate.ps1 -Scale). NO EMOJI IN THIS FILE.
#>

BeforeDiscovery {
    $script:LocalSql = $false
    try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
    $script:HasSchema = Test-Path -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'sql', 'si-data-schema.sql'))
    $script:LocalSql = $script:LocalSql -and $script:HasSchema
}

AfterAll {
    foreach ($k in @($script:RunnerJobVars.Keys)) { [Environment]::SetEnvironmentVariable([string]$k, [string]$script:RunnerJobVars[$k]) }
}

BeforeAll {
    # the runner's CONTAINER_APP_* variables would make the pacing write a progress mark through the fake seam (see
    # SIv3-RaBatchedFinish.Tests.ps1)
    $script:RunnerJobVars = @{}
    foreach ($v in @([Environment]::GetEnvironmentVariables().Keys | Where-Object { "$_" -like 'CONTAINER_APP_*' })) {
        $script:RunnerJobVars[[string]$v] = [Environment]::GetEnvironmentVariable([string]$v); [Environment]::SetEnvironmentVariable([string]$v, $null)
    }
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataModel.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SqlStream.ps1')
    function script:Write-Info  { param($m) }
    function script:Write-Diag  { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Err2  { param($m) }
    $script:StreamText = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SqlStream.ps1'))
    $script:SyncText = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-DataSync.ps1'))
    $__schemaPath = Join-Path $script:SIRoot 'sql\si-data-schema.sql'
    $script:Schema = $(if (Test-Path -LiteralPath $__schemaPath) { [IO.File]::ReadAllText($__schemaPath) } else { '' })
    $script:TimeoutText = 'Exception calling "ExecuteReader" with "0" argument(s): "Timeout expired.  The timeout period elapsed prior to completion of the operation or the server is not responding."'

    # ---- a fake database of Finding rows: Coll, Report, Seq; the forward-walking removal evaluated as the SQL does it ----
    # the rows per collection + report as a sorted list of write numbers (a batch takes from where @After falls: no scan)
    function script:New-RemovalDb([object[]]$Rows, [long]$TimeoutAbove = 0) {
        $by = @{}
        foreach ($r in $Rows) { $k = '{0}|{1}' -f $r.Coll, $r.Report; if (-not $by.ContainsKey($k)) { $by[$k] = [System.Collections.Generic.List[long]]::new() }; $by[$k].Add([long]$r.Seq) }
        foreach ($k in @($by.Keys)) { $by[$k].Sort() }
        @{ By = $by; Calls = (New-Object System.Collections.Generic.List[object]); TimeoutAbove = $TimeoutAbove; Timeouts = 0 }
    }
    function script:Get-RemovalLeft($Db, [int]$Coll, [int]$Report) { $k = '{0}|{1}' -f $Coll, $Report; if ($Db.By.ContainsKey($k)) { $Db.By[$k].Count } else { 0 } }
    function script:New-SeqRows([int]$Coll, [int]$Report, [long]$From, [long]$Count, [long]$Step = 1) {
        $l = [System.Collections.Generic.List[object]]::new()
        for ($i = 0L; $i -lt $Count; $i++) { $l.Add([pscustomobject]@{ Coll = $Coll; Report = $Report; Seq = $From + $i * $Step }) }
        $l.ToArray()   # enumerated: @(New-SeqRows ...) + @(...) is one flat list of rows
    }
    function script:New-RemovalStream($Db) {
        $timeoutText = $script:TimeoutText   # a closure (GetNewClosure) has its own script scope: the text goes in as a local
        $s = @{ Grain = 'Detailed'; TimeText = '2026-11-24T16:01:49.000'; CollectionId = 2; RunKey = 'Detailed|x'; Log = $null
                Current = @{ Ordinal = 1; Name = 'Device_Missing_CVEs_Detailed'; Retrieved = 0L; Staged = $false; Account = @{}; Times = @{} } }
        $s.Invoke = {
            param($Sql, $P, $Mode)
            $Db.Calls.Add([pscustomobject]@{ Sql = $Sql; P = $P; Mode = $Mode })
            if ($Sql -notmatch 'DELETE TOP') { return 0 }
            if ($Db.TimeoutAbove -gt 0 -and [long]$P['Batch'] -gt $Db.TimeoutAbove) { $Db.Timeouts++; throw $timeoutText }
            if ($Sql -match 'FROM sidata\.RaStage') { return 0L }
            $k = '{0}|{1}' -f [int]$P['CollectionId'], [int]$P['Report']
            $l = $Db.By[$k]
            if ($null -eq $l -or $l.Count -eq 0) { return 0L }
            $n = [int][Math]::Min([long]$P['Batch'], [long]$l.Count)
            $l.RemoveRange(0, $n)
            if ($null -ne $Db['Inject']) { $l.Insert(0, [long]$Db['Inject']); $Db['Inject'] = $null }
            [long]$n
        }.GetNewClosure()
        $s
    }

    # ---- a fake database for the trace-name check: rows with a trace hash (hex), a key, the flag, the JSON ----------------
    function script:New-TraceDb([object[]]$Rows) {
        $l = New-Object System.Collections.Generic.List[object]; foreach ($r in $Rows) { $l.Add($r) }
        @{ Rows = $l; Calls = (New-Object System.Collections.Generic.List[object]); CandidateRows = (New-Object System.Collections.Generic.List[int]); Written = (New-Object System.Collections.Generic.List[long])
           NamePages = (New-Object System.Collections.Generic.List[int]); OneName = (New-Object System.Collections.Generic.List[string]) }
    }
    function script:Get-SharedHashes($Db) {
        # the names two different keys share do not change while the check runs (it only sets the flag): worked out once
        if ($null -eq $Db['Shared']) {
            $keys = @{}
            foreach ($r in $Db.Rows) { if (-not $keys.ContainsKey($r.Hash)) { $keys[$r.Hash] = [System.Collections.Generic.HashSet[string]]::new() }; [void]$keys[$r.Hash].Add([string]$r.Key) }
            $l = [System.Collections.Generic.List[string]]::new(); foreach ($k in $keys.Keys) { if ($keys[$k].Count -gt 1) { $l.Add([string]$k) } }
            $a = $l.ToArray(); [Array]::Sort($a, [StringComparer]::Ordinal); $Db['Shared'] = $a
        }
        $Db['Shared']   # enumerated: @(...) around the call is the list of names
    }
    function script:New-TraceStream($Db) {
        $s = @{ Grain = 'Detailed'; TimeText = '2026-11-24T16:01:49.000'; CollectionId = 2; RunKey = 'Detailed|x'; Chunk = 1MB; Typed = $null
                Current = @{ Ordinal = 1; Name = 'Device_Missing_CVEs_Detailed'; Retrieved = 0L; Staged = $false; Account = @{}; Times = @{} } }
        $s.Log = { param($l, $m) }
        $sharedOf = ${function:Get-SharedHashes}   # (a closure does not see the test's script functions)
        $s.Invoke = {
            param($Sql, $P, $Mode)
            $Db.Calls.Add([pscustomobject]@{ Sql = $Sql; P = $P; Mode = $Mode })
            if ($Sql -match 'RANK\(\) OVER') { return , @(@{ Removed = 0; Seen = 0L; LastKey = '' }) }
            $shared = @(& $sharedOf $Db)
            $after = [string]$P['After']
            # the names page: names after @After with the rows each holds
            if ($Sql -match 'AS H, COUNT_BIG\(\*\) AS N') {
                if ($null -eq $Db['Count']) { $c = @{}; foreach ($r in $Db.Rows) { $c[[string]$r.Hash] = [long]$c[[string]$r.Hash] + 1 }; $Db['Count'] = $c }
                $pg = @($shared | Where-Object { -not $after -or [string]::CompareOrdinal($_, $after) -gt 0 } | Select-Object -First ([int]$P['Page']))
                $Db.NamePages.Add($pg.Count)
                return , @(foreach ($h in $pg) { @{ H = [string]$h; N = [long]$Db['Count'][$h] } })
            }
            # one name by itself, a page of rows by row id
            if ($Sql -match 'RaTraceHash = @h') {
                $h = [string]$P['Hash']; $ai = $(if ([string]$P['AfterId']) { [long]$P['AfterId'] } else { [long]::MinValue })
                $out = @(@(foreach ($r in $Db.Rows) { if ([string]$r.Hash -eq $h -and -not $r.Suffixed -and [long]$r.Id -gt $ai) { $r } }) | Sort-Object Id | Select-Object -First ([int]$P['Rows']) | ForEach-Object { @{ Id = [long]$_.Id; Json = [string]$_.Json } })
                $Db.CandidateRows.Add($out.Count); $Db.OneName.Add($h)
                return , $out
            }
            if ($Sql -match 'f\.RaTraceSuffixed = 0') {
                $upTo = [string]$P['UpTo']
                $hs = [System.Collections.Generic.HashSet[string]]::new([string[]]@($shared | Where-Object { (-not $after -or [string]::CompareOrdinal($_, $after) -gt 0) -and [string]::CompareOrdinal($_, $upTo) -le 0 }), [StringComparer]::Ordinal)
                $out = @(foreach ($r in $Db.Rows) { if ($hs.Contains([string]$r.Hash) -and -not $r.Suffixed) { @{ Id = [long]$r.Id; Json = [string]$r.Json } } })
                $Db.CandidateRows.Add($out.Count)
                return , $out
            }
            return 0
        }.GetNewClosure()
        $s
    }
    # the helpers the check calls, in script scope (the shaping and the writer are tested in their own suites)
    function script:Get-RATraceBase { param($Row, $IsDetailed) @{ AssetKey = [string]$Row.AssetKey; Parts = @('dev') } }
    function script:Get-RATraceId { param($TraceName) ('id-' + $TraceName) }
    function script:Write-SIDataJsonRows { param($Invoke, $Sql, $Items, $Params, $ChunkChars, $What)
        if ($null -eq $script:TraceDb['ById']) { $m = @{}; foreach ($r in $script:TraceDb.Rows) { $m[[long]$r.Id] = $r }; $script:TraceDb['ById'] = $m }
        foreach ($i in @($Items)) { $o = $i | ConvertFrom-Json; $script:TraceDb.Written.Add([long]$o.Id); $hit = $script:TraceDb['ById'][[long]$o.Id]; if ($hit) { $hit.Suffixed = $true } }
        [long]@($Items).Count
    }
    function script:New-LocalInvoke([string]$Db) {
        $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True"
        {
            param([string]$sql, $p, [string]$mode)
            $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
            try {
                $c = $cn.CreateCommand(); $c.CommandTimeout = 600; $c.CommandText = $sql
                if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                while ($r.Read()) { $h = @{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { [DBNull]::Value } else { $r.GetValue($i) }) }; $rows.Add($h) }
                $r.Close(); return , $rows.ToArray()
            } finally { $cn.Close() }
        }.GetNewClosure()
    }
    function script:Get-PlanXml([string]$Db, [string]$Declare, [string]$Sql) {
        $cn = New-Object System.Data.SqlClient.SqlConnection("Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True"); $cn.Open()
        try {
            $c = $cn.CreateCommand(); $c.CommandText = 'SET SHOWPLAN_XML ON'; [void]$c.ExecuteNonQuery()
            $c = $cn.CreateCommand(); $c.CommandText = $Declare + "`n" + $Sql
            $r = $c.ExecuteReader(); $sb = New-Object System.Text.StringBuilder
            do { while ($r.Read()) { [void]$sb.Append([string]$r.GetValue(0)) } } while ($r.NextResult())
            $r.Close()
            $c = $cn.CreateCommand(); $c.CommandText = 'SET SHOWPLAN_XML OFF'; [void]$c.ExecuteNonQuery()
            $sb.ToString()
        } finally { $cn.Close() }
    }
    # rows of one report of one collection: @N rows from write number @S on, JSON of @J characters
    $script:Fill = @'
;WITH n AS (SELECT TOP (CONVERT(int, @N)) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b CROSS JOIN sys.all_objects c)
INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, DetailJson, RaReport, RaBucket, RaSeq, RaTraceHash, RaTraceKey, RaTraceSuffixed)
SELECT CONVERT(int, @C), CONCAT(N'dev-', i % 50000), CONCAT(N'host-', i % 50000), N'Device_Missing_CVEs_Detailed', CONCAT(N'CVE-2026-', i % 9000), CONCAT(N'CVE-2026-', i % 9000),
       N'A vulnerability', N'High', 1 + (i % 4), 5, CONCAT(N'{"AssetKey":"dev-', i % 50000, N'","pad":"', REPLICATE(N'x', CONVERT(int, @J)), N'"}'),
       CONVERT(int, @R), CONCAT(N'', i % 1024, N'/1024'), CONVERT(bigint, @S) + i, HASHBYTES('MD5', CONCAT(N'h', i % 50000)), CONCAT(N'dev-', i % 50000), 0
FROM n;
'@
}

Describe '#1397 (1) the removal: the 3.1.51 batching, done only when proven -- only that report of that collection' {
    BeforeEach { $script:RAStreamBatchSize = @{} }

    It 'removes exactly the report''s rows of the collection; another report, another collection untouched' {
        $rows = @(New-SeqRows 2 1 3 2500 3) + @(New-SeqRows 2 1 777 40 0) + @(New-SeqRows 2 2 100001 300) + @(New-SeqRows 1 1 1 500)
        $db = New-RemovalDb $rows
        $n = Remove-RAStreamRowsBatched -Stream (New-RemovalStream $db) -Sql (Get-RAStreamDeleteReportBatchSql -Grain Detailed) -Params @{ CollectionId = '2'; Report = '1'; Bucket = '*' } -What 'w' -Kind 'remove|Detailed'
        $n | Should -Be 2540
        Get-RemovalLeft $db 2 1 | Should -Be 0
        Get-RemovalLeft $db 2 2 | Should -Be 300
        Get-RemovalLeft $db 1 1 | Should -Be 500
        @($db.Calls | ForEach-Object { $_.Mode } | Sort-Object -Unique) | Should -Be @('scalar')
    }

    It 'the size starts at 5,000 and grows while batches are fast (at most double); a timeout halves it and asks again' {
        Mock Start-Sleep { }
        $db = New-RemovalDb (New-SeqRows 2 1 1 400000)
        $n = Remove-RAStreamRowsBatched -Stream (New-RemovalStream $db) -Sql (Get-RAStreamDeleteReportBatchSql -Grain Detailed) -Params @{ CollectionId = '2'; Report = '1'; Bucket = '*' } -What 'w' -Kind 'remove|Detailed'
        $n | Should -Be 400000
        $sizes = @($db.Calls | ForEach-Object { [long]$_.P['Batch'] })
        $sizes[0] | Should -Be 5000
        $sizes[1] | Should -BeGreaterThan 5000 -Because 'a fast batch grows the next'
        $sizes[1] | Should -BeLessOrEqual 10000
        $script:RAStreamBatchSize = @{}
        $db2 = New-RemovalDb (New-SeqRows 2 1 1 30000) -TimeoutAbove 3000
        (Remove-RAStreamRowsBatched -Stream (New-RemovalStream $db2) -Sql (Get-RAStreamDeleteReportBatchSql -Grain Detailed) -Params @{ CollectionId = '2'; Report = '1'; Bucket = '*' } -What 'w' -Kind 'remove|Detailed') | Should -Be 30000
        $db2.Timeouts | Should -BeGreaterThan 0
        Get-RemovalLeft $db2 2 1 | Should -Be 0
    }

    It 'done only when proven: a row that appears after a pass is found by the next pass and removed; the last pass removes nothing' {
        $db = New-RemovalDb (New-SeqRows 2 1 1000 3000)
        $db['Inject'] = 5L
        $script:RAStreamBatchSize['remove|Detailed'] = 500
        $n = Remove-RAStreamRowsBatched -Stream (New-RemovalStream $db) -Sql (Get-RAStreamDeleteReportBatchSql -Grain Detailed) -Params @{ CollectionId = '2'; Report = '1'; Bucket = '*' } -What 'w' -Kind 'remove|Detailed'
        $n | Should -Be 3001
        Get-RemovalLeft $db 2 1 | Should -Be 0
        $last = $db.Calls[$db.Calls.Count - 1]
        $last.Sql | Should -Match 'DELETE TOP' -Because 'the last statement is the pass that found nothing'
    }

    It 'a retry is idempotent: what is gone stays gone, the next run finds nothing and removes nothing else' {
        $db = New-RemovalDb (@(New-SeqRows 2 1 1 1000) + @(New-SeqRows 2 3 5001 10))
        $p = @{ CollectionId = '2'; Report = '1'; Bucket = '*' }
        (Remove-RAStreamRowsBatched -Stream (New-RemovalStream $db) -Sql (Get-RAStreamDeleteReportBatchSql -Grain Detailed) -Params $p -What 'w') | Should -Be 1000
        (Remove-RAStreamRowsBatched -Stream (New-RemovalStream $db) -Sql (Get-RAStreamDeleteReportBatchSql -Grain Detailed) -Params $p -What 'w') | Should -Be 0
        Get-RemovalLeft $db 2 3 | Should -Be 10
    }

    It 'the statements are the 3.1.51 ones; the remover and the data sync''s held removal keep its batching and prove the end' {
        (Get-RAStreamDeleteReportBatchSql -Grain Detailed) | Should -Match ([regex]::Escape("DELETE TOP (CONVERT(int, @Batch)) FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaReport = CONVERT(int, @Report) AND RaSeq IS NOT NULL AND (@Bucket = '*' OR RaBucket = @Bucket)"))
        (Get-RAStreamDeleteReportBatchSql -Grain Seq) | Should -Match 'DELETE TOP \(CONVERT\(int, @Batch\)\) FROM sidata\.Finding WHERE CollectionId = CONVERT\(int, @CollectionId\) AND RaReport = CONVERT\(int, @Report\) AND RaSeq >= CONVERT\(bigint, @From\) AND RaSeq < CONVERT\(bigint, @To\)'
        (Get-RAStreamDeleteReportBatchSql -Grain Stage) | Should -Match 'DELETE TOP \(CONVERT\(int, @Batch\)\) FROM sidata\.RaStage WHERE RunKey = @RunKey'
        (Get-Command Remove-RAStreamRowsBatched).Definition | Should -Match '-StartSize 5000 -TargetMs 5000'
        . (Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-DataSync.ps1')
        Get-SIDataHeldRowsBatchSql | Should -Match 'DELETE TOP \(CONVERT\(int, @Batch\)\) FROM sidata\.Finding WHERE CollectionId = CONVERT\(int, @CollectionId\) AND RaReport = CONVERT\(int, @Report\) AND RaSeq IS NOT NULL'
        $script:SyncText | Should -Match ([regex]::Escape('[long]$StartSize = 5000, [long]$TargetMs = 5000'))
        $script:SyncText | Should -Match ([regex]::Escape('if ($walk -eq 0) { break }'))
    }

    It '#1411 (a) BEHAVIOUR: the data sync''s held removal is done only when a pass removes NOTHING -- rows a short batch did not reach are removed too' {
        . (Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-DataSync.ps1')
        # a seam: report 3 held back; its rows come in waves the statement only reaches on a later ask (rows another
        # session still held, a page the index had not shown yet) -- 3 now, 2 on the next ask, then none
        $st = @{ Waves = [System.Collections.Generic.Queue[long]]::new(); Asks = (New-Object System.Collections.Generic.List[long]); Batches = (New-Object System.Collections.Generic.List[long]) }
        foreach ($w in 3L, 2L) { $st.Waves.Enqueue($w) }
        $batchSql = Get-SIDataHeldRowsBatchSql   # read here: the closure below does not see functions dot-sourced in this It
        $inv = {
            param([string]$Sql, $P, [string]$Mode)
            if ($Mode -eq 'reader') { return , @(@{ ReportName = 'Device_Missing_CVEs_Detailed'; HeldRaReport = 3 }) }
            if ($Sql -eq $batchSql) {
                $st.Batches.Add([long]$P['Batch'])
                $n = if ($st.Waves.Count) { [Math]::Min([long]$P['Batch'], $st.Waves.Dequeue()) } else { 0L }
                $st.Asks.Add($n); return $n
            }
            throw "unexpected SQL: $Sql"
        }.GetNewClosure()
        $r = Remove-SIDataHeldReportRows -CollectionId 2 -Invoke $inv -Log { param($l, $m) } -What 't'
        $r.Removed | Should -Be 5 -Because 'the rows of both waves are removed -- a first short batch is no proof of the end'
        @($st.Asks) | Should -Be @(3, 2, 0) -Because 'asked again after every pass that removed rows, until one removes nothing'
        @($st.Batches | Select-Object -Unique) | Should -Be @(5000) -Because 'the 3.1.51 batching (5,000 first) is kept'
        # nothing held: one read of the list, no statement
        $st2 = @{ N = 0 }
        $none = { param([string]$Sql, $P, [string]$Mode) if ($Mode -eq 'reader') { return , @() }; $st2.N++; 0L }.GetNewClosure()
        (Remove-SIDataHeldReportRows -CollectionId 2 -Invoke $none -Log { param($l, $m) } -What 't').Removed | Should -Be 0
        $st2.N | Should -Be 0
    }
}
Describe '#1397 (2) the trace-name check reads one page of shared names at a time -- never every candidate row' {
    BeforeEach { $script:RAStreamBatchSize = @{} }

    It 'the same rows get their names as the one statement gave them, page by page, each page bounded by the rows it holds' {
        # 1,500 assets; every 3rd name is shared by two assets; 20 findings per asset; every 97th row already named
        $rows = New-Object System.Collections.Generic.List[object]
        $id = 0
        foreach ($a in 1..1500) {
            $nameNo = $(if ($a % 3 -eq 0) { $a - 1 } else { $a })
            $hash = ('{0:X32}' -f ($nameNo * 7919))
            foreach ($f in 1..20) { $id++; $rows.Add([pscustomobject]@{ Id = [long]$id; Hash = $hash; Key = "dev-$a"; Suffixed = ($id % 97 -eq 0); Json = ('{"AssetKey":"dev-' + $a + '"}') }) }
        }
        $script:TraceDb = New-TraceDb $rows.ToArray()
        $sh = [System.Collections.Generic.HashSet[string]]::new([string[]](Get-SharedHashes $script:TraceDb), [StringComparer]::Ordinal)
        $expected = @(foreach ($r in $script:TraceDb.Rows) { if ($sh.Contains([string]$r.Hash) -and -not $r.Suffixed) { [long]$r.Id } }) | Sort-Object
        $expected.Count | Should -BeGreaterThan 10000
        $s = New-TraceStream $script:TraceDb
        $null = Complete-RAStreamReport -Stream $s
        @($script:TraceDb.Written | Sort-Object) | Should -Be $expected -Because 'every candidate row named once, none twice, none missing'
        $script:TraceDb.CandidateRows.Count | Should -BeGreaterThan 1 -Because 'read in pages'
        ($script:TraceDb.CandidateRows | Measure-Object -Maximum).Maximum | Should -BeLessOrEqual 5000 -Because 'a read holds at most ~5,000 rows: names are read together only while their rows fit'
        # every names page after the name the page before it ended on
        $pages = @($script:TraceDb.Calls | Where-Object { $_.Sql -match 'AS H, COUNT_BIG' })
        [string]$pages[0].P['After'] | Should -BeNullOrEmpty
        for ($i = 1; $i -lt $pages.Count; $i++) { [string]::CompareOrdinal([string]$pages[$i].P['After'], [string]$pages[$i - 1].P['After']) | Should -BeGreaterThan 0 }
    }

    It 'ONE name that holds 12,000 rows (a name that fell back to the finding''s own fields) is read by itself in pages of rows, never whole' {
        $rows = New-Object System.Collections.Generic.List[object]
        $big = ('{0:X32}' -f 7)
        for ($i = 1; $i -le 12000; $i++) { $rows.Add([pscustomobject]@{ Id = [long]$i; Hash = $big; Key = ('dev-' + ($i % 2)); Suffixed = $false; Json = ('{"AssetKey":"dev-' + ($i % 2) + '"}') }) }
        # small shared names before and after it in name order
        foreach ($k in 1..30) { foreach ($j in 0..1) { $rows.Add([pscustomobject]@{ Id = [long](20000 + 2 * $k + $j); Hash = ('{0:X32}' -f [long]$(if ($k -le 6) { $k } else { 100 + $k })); Key = "k$j"; Suffixed = $false; Json = '{"AssetKey":"x"}' }) } }
        $script:TraceDb = New-TraceDb $rows.ToArray()
        $sh = [System.Collections.Generic.HashSet[string]]::new([string[]](Get-SharedHashes $script:TraceDb), [StringComparer]::Ordinal)
        $expected = @(foreach ($r in $script:TraceDb.Rows) { if ($sh.Contains([string]$r.Hash)) { [long]$r.Id } }) | Sort-Object
        $null = Complete-RAStreamReport -Stream (New-TraceStream $script:TraceDb)
        @($script:TraceDb.Written | Sort-Object) | Should -Be $expected
        ($script:TraceDb.CandidateRows | Measure-Object -Maximum).Maximum | Should -BeLessOrEqual 5000
        @($script:TraceDb.OneName | Where-Object { $_ -eq $big }).Count | Should -BeGreaterOrEqual 3 -Because '12,000 rows in reads of 5,000 (and one more that finds the end)'
    }

    It 'nothing shared: one page statement, no row read, nothing written' {
        $script:TraceDb = New-TraceDb @(foreach ($i in 1..50) { [pscustomobject]@{ Id = [long]$i; Hash = ('{0:X32}' -f $i); Key = "dev-$i"; Suffixed = $false; Json = '{"AssetKey":"x"}' } })
        $null = Complete-RAStreamReport -Stream (New-TraceStream $script:TraceDb)
        $script:TraceDb.CandidateRows.Count | Should -Be 0
        $script:TraceDb.Written.Count | Should -Be 0
    }


    It 'the statements: the page through the trace index alone, the rows of the page only; WIRING: no whole-report read is left' {
        $pg = Get-RAStreamTracePageSql -Grain Detailed
        $pg | Should -Match 'SELECT TOP \(CONVERT\(bigint, @Page\)\) CONVERT\(varchar\(32\), RaTraceHash, 2\) AS H, COUNT_BIG\(\*\) AS N FROM sidata\.Finding'
        $pg | Should -Match 'RaTraceHash IS NOT NULL AND \(@a IS NULL OR RaTraceHash > @a\)\s+GROUP BY RaTraceHash HAVING MIN\(RaTraceKey\) <> MAX\(RaTraceKey\)\s+ORDER BY RaTraceHash'
        $one = Get-RAStreamTraceNameRowsSql -Grain Detailed
        $one | Should -Match 'RaTraceHash = @h AND RaTraceSuffixed = 0 AND RaTraceKey IS NOT NULL AND \(@i IS NULL OR FindingId > @i\)\s+ORDER BY FindingId'
        (Get-RAStreamTraceNameRowsSql -Grain Summary) | Should -Match 'ORDER BY RowNo'
        $c = Get-RAStreamTraceCandidatesSql -Grain Detailed -Paged
        $c | Should -Match 'AND \(@a IS NULL OR RaTraceHash > @a\) AND RaTraceHash <= @u'
        $c | Should -Match 'AND \(@a IS NULL OR f\.RaTraceHash > @a\) AND f\.RaTraceHash <= @u'
        (Get-RAStreamTracePageSql -Grain Summary) | Should -Match 'FROM sidata\.SummaryRow'
        $fn = [regex]::Match($script:StreamText, '(?s)function Complete-RAStreamReport \{.*?\n\}').Value
        $fn | Should -Match ([regex]::Escape('Get-RAStreamTraceCandidatesSql -Grain $Stream.Grain -Paged'))
        $fn | Should -Match ([regex]::Escape('Get-RAStreamTracePageSql -Grain $Stream.Grain'))
        $fn | Should -Not -Match ([regex]::Escape('(Get-RAStreamTraceCandidatesSql -Grain $Stream.Grain) -Params'))
    }
}

Describe '#1397 (3) Defender''s first sightings: a compact index -- the same dates, ~40 bytes a device-CVE pair' {
    BeforeAll { . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SourceFirstSeen.ps1') }
    It 'the earliest sighting per device + CVE, in whole seconds, the same as the string index gave the rows' {
        $lines = @(
            '{"deviceId":"ABC123","cveId":"cve-2026-1","firstSeenTimestamp":"2026-09-01 10:13:34.8476880"}'
            '{"deviceId":"abc123","cveId":"CVE-2026-1","firstSeenTimestamp":"2026-09-03 08:00:00"}'
            '{"deviceId":"d2","cveId":"CVE-2026-7","firstSeenTimestamp":"2026-08-01T00:00:00Z"}'
            '{"deviceId":"d2","cveId":null,"firstSeenTimestamp":"2026-08-01T00:00:00Z"}'
        )
        $c = New-RASourceFirstSeenIndex
        $o = New-Object 'System.Collections.Generic.Dictionary[string,datetime]' ([StringComparer]::Ordinal)
        (Add-RASourceFirstSeenLines -Index $c -Lines $lines) | Should -Be 3
        (Add-RASourceFirstSeenLines -Index $o -Lines $lines) | Should -Be 3
        $c.Count | Should -Be 2
        foreach ($k in 'abc123|CVE-2026-1', 'd2|CVE-2026-7') {
            (Find-RASourceFirstSeen -Index $c -Key $k).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) | Should -Be ((Find-RASourceFirstSeen -Index $o -Key $k).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture))
        }
        (Find-RASourceFirstSeen -Index $c -Key 'abc123|CVE-2026-1').ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) | Should -Be '2026-09-01T10:13:34Z'
        Find-RASourceFirstSeen -Index $c -Key 'nope|CVE-2026-1' | Should -BeNullOrEmpty
        # whole seconds by integer arithmetic: the last tick of a second stays in that second (a double division rounded it up)
        $c2 = New-RASourceFirstSeenIndex
        $null = Add-RASourceFirstSeenLines -Index $c2 -Lines @('{"deviceId":"d9","cveId":"CVE-2026-9","firstSeenTimestamp":"2026-09-02T23:59:59.9999999Z"}')
        (Find-RASourceFirstSeen -Index $c2 -Key 'd9|CVE-2026-9').ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) | Should -Be '2026-09-02T23:59:59Z'
        # WIRING: the run's index is the compact one
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SourceFirstSeen.ps1'))
        $src | Should -Match ([regex]::Escape('$state = @{ Index = (New-RASourceFirstSeenIndex)'))
    }
    It 'Add-RASourceFirstSeen puts the date on the row through the compact index' {
        $global:RA_SourceFirstSeenIndex = $null; $global:RA_SourceFirstSeenSaid = $false
        $rows = @([pscustomobject]@{ MdeDeviceId = 'ABC123'; si_cve = 'CVE-2026-1' }, [pscustomobject]@{ MdeDeviceId = 'zz'; si_cve = 'CVE-2026-1' })
        $out = Add-RASourceFirstSeen -Rows $rows -Fetch { param($u) @{ Files = @('f1') } } -Download { param($u) @('{"deviceId":"abc123","cveId":"CVE-2026-1","firstSeenTimestamp":"2026-09-01T10:13:34.9Z"}') }
        $out[0].si_source_first_seen | Should -Be '2026-09-01T10:13:34Z'
        $out[1].PSObject.Properties['si_source_first_seen'] | Should -BeNullOrEmpty
        $global:RA_SourceFirstSeenIndex.Index.GetType().FullName | Should -Match 'Dictionary`2\[\[System.Guid'
        $global:RA_SourceFirstSeenIndex = $null
    }
}

Describe '#1397 GUARD: every database read of Risk Analysis is bounded -- a new one fails here until its bound is named' {
    # Owner 2026-11-25: "why are we still not streaming all reports consistent" / 2026-10-21: "memory issues must not be a
    # problem in any step". The SQL seam's 'reader' mode collects EVERY row a statement answers (SI-DataSql.ps1), so each
    # read below is safe only because its statement is bounded: a page, a TOP, a key part, one row, or a grouping that does
    # not grow with the report's rows. The list is exact: a read added (or moved) anywhere in engine\risk-analysis fails
    # this test by name, and passes only when it is added here WITH what bounds it -- never a read of a whole report.
    BeforeAll {
        $script:AllowedReaders = [ordered]@{
            'Invoke-RiskAnalysis.ps1|Send-RARunHealthEnd'        = 'one reason per report of the run'
            'Invoke-RiskAnalysis.ps1|<top>#1'                    = 'the active source acceptances (settings)'
            'Invoke-RiskAnalysis.ps1|<top>#2'                    = 'one flow step outcome (settings)'
            'Invoke-RiskAnalysis.ps1|<top>#3'                    = 'one value: the flow run start'
            'RA-BucketStore.ps1|Get-SIRaBucketRows'              = 'the slice-count memory of one template (one row per report)'
            'RA-CiContext.ps1|Read-RACiIndexPage'                = 'one page of the CI index (Get-RACiPageSize)'
            'RA-CiContext.ps1|Use-RACiIndexSlice'                = 'the CIs of ONE slice''s keys'
            'RA-CiContext.ps1|Get-RACiIndex'                     = 'one row: a count'
            'RA-DefenderFilter.ps1|Get-RADefenderKeyMatches'     = 'the matches of one part of keys (200,000 / 20,000)'
            'RA-GraphPathStage.ps1|Invoke-RAGpsLoad'             = 'the walk is done in SQL; it answers its totals'
            'RA-GraphPathStage.ps1|Get-RAGpsSliceData#1'         = 'the paths of ONE slice'
            'RA-GraphPathStage.ps1|Get-RAGpsSliceData#2'         = 'the nodes of ONE slice'
            'RA-GraphPathStage.ps1|Get-RAGpsSliceData#3'         = 'the enrichment of ONE slice'
            'RA-SilentSource.ps1|Invoke-RASilentSourceCheck'     = 'one count per source table'
            'RA-SqlStream.ps1|Get-RAStreamCiIndex'               = 'the CIs of one part of ONE slice''s keys (5,000, halved on out of memory)'
            'RA-SqlStream.ps1|Invoke-RAStreamDedup'              = 'one row per page'
            'RA-SqlStream.ps1|Get-RAStreamReportCounts'          = 'one row per report'
            'RA-SqlStream.ps1|Invoke-RAStreamStagePages#1'       = 'Summary: one start + size per group (no rows)'
            'RA-SqlStream.ps1|Invoke-RAStreamStagePages#2'       = 'Summary: one page of staged groups (64 MB of text)'
            'RA-SqlStream.ps1|Complete-RAStreamReport#1'         = 'the rows of one read of shared trace names: at most ~5,000 (names together while they fit; one large name by row id)'
            'RA-SqlStream.ps1|Complete-RAStreamReport#2'         = 'one page of shared trace names with their row counts (1,000 names, no rows)'
            'RA-SqlStream.ps1|Read-RAStreamLastGood'             = 'one row per report'
            'RA-SqlStream.ps1|Read-RAStreamHoldStreak'           = 'one row per report'
            'RA-SqlStream.ps1|New-RARowPager'                    = 'one page (32 MB / 8 MB of text)'
            'RA-SqlStream.ps1|Get-RAStreamTrendRollup'           = 'grouped: one row per dimension value'
            'RA-TopListsSql.ps1|Invoke-RATopListsInSql'          = 'the top lists (TOP n each)'
        }
        $script:FoundReaders = [System.Collections.Generic.List[string]]::new()
        $seen = @{}
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis') -Recurse -Filter '*.ps1' | Sort-Object FullName)) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            $calls = $ast.FindAll({ param($x) $x -is [System.Management.Automation.Language.CommandAst] -and (
                        ($x.GetCommandName() -eq 'Invoke-RAStreamSql' -and $x.Extent.Text -match "-Mode\s+'reader'") -or
                        ($x.InvocationOperator -ne 'Unknown' -and $x.Extent.Text -match "'reader'")) }, $true)
            foreach ($c in @($calls | Sort-Object { $_.Extent.StartOffset })) {
                $p = $c.Parent; while ($p -and -not ($p -is [System.Management.Automation.Language.FunctionDefinitionAst])) { $p = $p.Parent }
                $k = '{0}|{1}' -f $f.Name, $(if ($p) { $p.Name } else { '<top>' })
                $seen[$k] = [int]$seen[$k] + 1
                $script:FoundReaders.Add(('{0}#{1}' -f $k, $seen[$k]))
            }
        }
        # a function with one read is named without its number
        $script:FoundReaders = [System.Collections.Generic.List[string]]@($script:FoundReaders | ForEach-Object { $b = $_ -replace '#\d+$', ''; if ($seen[$b] -eq 1) { $b } else { $_ } })
    }
    It 'every read is on the list with its bound, and the list has no read that is gone' {
        $new = @($script:FoundReaders | Where-Object { -not $script:AllowedReaders.Contains($_) })
        $new | Should -BeNullOrEmpty -Because ('a database read nobody named the bound of: ' + ($new -join ', ') + ' -- page it (a TOP, a key part, one row) and add it here with its bound')
        $gone = @($script:AllowedReaders.Keys | Where-Object { $script:FoundReaders -notcontains $_ })
        $gone | Should -BeNullOrEmpty -Because ('on the list but no longer read: ' + ($gone -join ', '))
    }
    It 'no statement of the stream reads every candidate row of a report: the whole-report trace statement is only used paged' {
        $script:StreamText | Should -Not -Match ([regex]::Escape('(Get-RAStreamTraceCandidatesSql -Grain $Stream.Grain) -Params'))
    }
}

Describe '#1397 on a real SQL Server: the removal and the trace pages' {
    It 'the removal takes exactly that report of that collection; the trace pages find the same rows as the one statement' -Skip:(-not $script:LocalSql) {
        $db = 'sirm_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalInvoke $db
            [void](& $inv $script:Schema @{} 'nonquery'); [void](& $inv $script:Schema @{} 'nonquery')
            [void](& $inv "SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status, Source) VALUES (1, '2026-11-23T16:01:49', 'Detailed', 'Complete', 'risk-analysis'), (2, '2026-11-24T16:01:49', 'Detailed', 'Loading', 'risk-analysis'); SET IDENTITY_INSERT sidata.Collection OFF;" @{} 'nonquery')
            [void](& $inv $script:Fill @{ N = '3000'; C = '1'; R = '1'; S = '0'; J = '200' } 'nonquery')      # the published collection
            [void](& $inv $script:Fill @{ N = '20000'; C = '2'; R = '1'; S = '0'; J = '200' } 'nonquery')     # the undelivered report
            [void](& $inv $script:Fill @{ N = '700'; C = '2'; R = '2'; S = '900000'; J = '200' } 'nonquery')  # another report of the run
            # trace names two keys share: 6,001 names over the report's 20,000 rows, the key alternating (6,001 is odd)
            [void](& $inv "UPDATE sidata.Finding SET RaTraceHash = HASHBYTES('MD5', CONCAT(N's', RaSeq % 6001)), RaTraceKey = CONCAT(N'k', RaSeq % 2) WHERE CollectionId = 2 AND RaReport = 1;" @{} 'nonquery')
            # write numbers two rows share
            [void](& $inv "UPDATE sidata.Finding SET RaSeq = 4242 WHERE CollectionId = 2 AND RaReport = 1 AND RaSeq BETWEEN 4242 AND 4300;" @{} 'nonquery')
            # rows the data sync wrote (no RaSeq) in the same collection
            [void](& $inv "INSERT sidata.Finding (CollectionId, AssetKey, ReportName, Severity, Tier, RiskScore, DetailJson, RaReport) SELECT TOP (100) 2, CONCAT(N'z', ROW_NUMBER() OVER (ORDER BY (SELECT NULL))), N'R', N'Low', 3, 1, N'{}', 1 FROM sys.all_objects" @{} 'nonquery')
            # the trace pages against the one statement (before anything is removed)
            $p = @{ CollectionId = '2'; Report = '1'; CollectionTime = '2026-11-24T16:01:49.000' }
            $whole = @(@(& $inv (Get-RAStreamTraceCandidatesSql -Grain Detailed) $p 'reader') | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] } | ForEach-Object { [long]$_['Id'] } | Sort-Object)
            $paged = New-Object System.Collections.Generic.List[long]; $after = ''; $size = 37; $pages = 0
            $rd = { param($sql, $q) @(@(& $inv $sql $q 'reader') | ForEach-Object { $_ } | Where-Object { $_ -is [System.Collections.IDictionary] }) }
            $oneName = 0
            while ($true) {
                $names = @(& $rd (Get-RAStreamTracePageSql -Grain Detailed) ($p + @{ Page = [string]$size; After = $after }))
                if (-not $names.Count) { break }
                $pages++
                $last = [string]$names[-1]['H']
                if ($pages -gt 1) {
                    # every page after the first: the range of names together
                    foreach ($x in (& $rd (Get-RAStreamTraceCandidatesSql -Grain Detailed -Paged) ($p + @{ After = $after; UpTo = $last }))) { $paged.Add([long]$x['Id']) }
                } else {
                    # the first page: each name by itself, 2 rows a read by row id (the path of a name too large for one read)
                    foreach ($nm in $names) {
                        $ai = ''
                        while ($true) {
                            $rr = @(& $rd (Get-RAStreamTraceNameRowsSql -Grain Detailed) ($p + @{ Hash = [string]$nm['H']; AfterId = $ai; Rows = '2' }))
                            foreach ($x in $rr) { $paged.Add([long]$x['Id']) }
                            $oneName++
                            if ($rr.Count -lt 2) { break }
                            $ai = [string]$rr[-1]['Id']
                        }
                    }
                }
                $after = $last
                if ($names.Count -lt $size) { break }
            }
            $oneName | Should -BeGreaterThan 0
            $whole.Count | Should -BeGreaterThan 0
            $pages | Should -BeGreaterThan 1
            @($paged | Sort-Object) | Should -Be $whole
            $decl = "DECLARE @CollectionId nvarchar(20) = N'2', @Report nvarchar(20) = N'1', @Page nvarchar(20) = N'500', @After nvarchar(40) = N'', @Batch nvarchar(20) = N'50000', @Bucket nvarchar(20) = N'*';"
            (Get-PlanXml $db $decl (Get-RAStreamTracePageSql -Grain Detailed)) | Should -Match 'Index="\[IX_Finding_RaTrace\]"'
            (Get-PlanXml $db ($decl + " DECLARE @Hash nvarchar(40) = N'00000000000000000000000000000001', @AfterId nvarchar(20) = N'', @Rows nvarchar(20) = N'5000';") (Get-RAStreamTraceNameRowsSql -Grain Detailed)) | Should -Match 'Index="\[IX_Finding_RaTrace\]"'
            (Get-PlanXml $db $decl (Get-RAStreamDeleteReportBatchSql -Grain Detailed)) | Should -Match 'Index="\[IX_Finding_Ra(Bucket|Seq)\]"' -Because 'the report''s rows are a seek on (CollectionId, RaReport)'
            # the removal: small batches so it walks many of them
            $script:RAStreamBatchSize = @{ 'remove|Detailed' = 333 }
            $st = @{ Invoke = $inv; Grain = 'Detailed'; Log = $null; CollectionId = 2 }
            (Remove-RAStreamRowsBatched -Stream $st -Sql (Get-RAStreamDeleteReportBatchSql -Grain Detailed) -Params @{ CollectionId = '2'; Report = '1'; Bucket = '*' } -What 'w' -Kind 'remove|Detailed') | Should -Be 20000
            [long](& $inv 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = 2 AND RaReport = 1 AND RaSeq IS NOT NULL' @{} 'scalar') | Should -Be 0
            [long](& $inv 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = 2 AND RaReport = 1 AND RaSeq IS NULL' @{} 'scalar') | Should -Be 100 -Because 'rows Risk Analysis did not write are never its to remove'
            [long](& $inv 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = 2 AND RaReport = 2' @{} 'scalar') | Should -Be 700
            [long](& $inv 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = 1' @{} 'scalar') | Should -Be 3000 -Because 'the published collection is never touched'
            # retry: nothing left, nothing else removed
            (Remove-RAStreamRowsBatched -Stream $st -Sql (Get-RAStreamDeleteReportBatchSql -Grain Detailed) -Params @{ CollectionId = '2'; Report = '1'; Bucket = '*' } -What 'w' -Kind 'remove|Detailed') | Should -Be 0
            [long](& $inv 'SELECT COUNT_BIG(*) FROM sidata.Finding' @{} 'scalar') | Should -Be (3000 + 700 + 100)
            # a part's range and the staged rows on the real schema
            [void](& $inv $script:Fill @{ N = '900'; C = '2'; R = '3'; S = '0'; J = '10' } 'nonquery')
            (Remove-RAStreamSeqRanges -Stream $st -Ordinal 3 -Ranges @(@{ From = 101; To = 401 })) | Should -Be 300
            [long](& $inv 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = 2 AND RaReport = 3' @{} 'scalar') | Should -Be 600
            (Remove-RAStreamRowsBatched -Stream $st -Sql (Get-RAStreamDeleteReportBatchSql -Grain Stage) -Params @{ RunKey = 'x'; Report = '3'; Bucket = '*' } -What 'w') | Should -Be 0
            # the data sync's held removal
            . (Join-Path $script:SIRoot 'engine\pro-data\_shared\SI-DataSync.ps1')
            $ans = [long](@(& $inv (Get-SIDataHeldRowsBatchSql) @{ CollectionId = '2'; Report = '3'; Batch = '250' } 'scalar')[-1])
            $ans | Should -Be 250
            [long](& $inv 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = 2 AND RaReport = 3' @{} 'scalar') | Should -Be 350
        } finally {
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            try { [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery') } catch { }
        }
    }
}

Describe '#1397 MEASURED on a real SQL Server: 2 M rows of one report removed, before and after; the trace check''s memory' -Tag 'Scale' {
    It 'the old DELETE TOP batches vs the forward walk over 2,000,000 rows; the trace check at bounded memory' -Skip:(-not $script:LocalSql) {
        $rows = 2000000; if ($env:SI_RA_RM_ROWS) { $rows = [int]$env:SI_RA_RM_ROWS }
        $db = 'sirmx_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $master = New-LocalInvoke 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = New-LocalInvoke $db
            [void](& $inv $script:Schema @{} 'nonquery'); [void](& $inv $script:Schema @{} 'nonquery')
            [void](& $inv "SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status, Source) VALUES (1, '2026-11-23T16:01:49', 'Detailed', 'Complete', 'risk-analysis'), (2, '2026-11-24T16:01:49', 'Detailed', 'Loading', 'risk-analysis'), (3, '2026-11-25T16:01:49', 'Detailed', 'Loading', 'risk-analysis'); SET IDENTITY_INSERT sidata.Collection OFF;" @{} 'nonquery')
            # the rows in parts of 200,000, a line each (the gate ends a suite that prints nothing for 5 minutes)
            $fill = $script:Fill   # (a closure has its own script scope)
            $fillBig = {
                param([int]$C, [int]$R, [long]$N, [long]$S0)
                for ($o = 0L; $o -lt $N; $o += 200000) {
                    $k = [Math]::Min(200000L, $N - $o)
                    [void](& $inv $fill @{ N = [string]$k; C = [string]$C; R = [string]$R; S = [string]($S0 + $o); J = '100' } 'nonquery')   # (the runner's SQL holds ~10 GB: a short JSON, every index as it is)
                    Write-Host ("[#1397 measure] collection {0} report {1}: {2:N0} of {3:N0} rows written" -f $C, $R, ($o + $k), $N)
                }
            }.GetNewClosure()
            & $fillBig 1 1 100000 0
            $old = "DELETE TOP (CONVERT(int, @Batch)) FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaReport = CONVERT(int, @Report) AND RaSeq IS NOT NULL AND (@Bucket = '*' OR RaBucket = @Bucket); SELECT @@ROWCOUNT;"
            $result = [ordered]@{}
            foreach ($mode in 'before', 'after') {
                $c = $(if ($mode -eq 'before') { 2 } else { 3 })
                $sw = [Diagnostics.Stopwatch]::StartNew()
                & $fillBig $c 1 $rows 0
                & $fillBig $c 2 50000 (10 * $rows)
                $fillS = $sw.Elapsed.TotalSeconds
                $script:RAStreamBatchSize = @{}
                $st = @{ Invoke = $inv; Grain = 'Detailed'; Log = { param($l, $m) Write-Host ('[#1397 measure] ' + $m) } }
                $p = @{ CollectionId = [string]$c; Report = '1'; Bucket = '*' }
                $sw.Restart()
                if ($mode -eq 'before') {
                    # 3.1.51 exactly: DELETE TOP from the start of the report, first batch 5,000, aimed at 5 s
                    $step = { param($Size) $q = @{}; foreach ($k in $p.Keys) { $q[$k] = $p[$k] }; $q['Batch'] = [string][long]$Size; $n = [long](@(Invoke-RAStreamSql -Stream $st -Sql $old -Params $q -Attempts 1)[-1]); @{ Removed = $n; Done = ($n -lt [long]$Size) } }   # no closure: it calls the stream's functions (script scope)
                    $r = Invoke-RAStreamBatched -Stream $st -Batch $step -What 'before' -StartSize 5000 -TargetMs 5000
                    $n = [long]$r.Removed; $last = [long]$r.Size
                } else {
                    $n = Remove-RAStreamRowsBatched -Stream $st -Sql (Get-RAStreamDeleteReportBatchSql -Grain Detailed) -Params $p -What 'after' -Kind 'remove|Detailed'
                    $last = [long]$script:RAStreamBatchSize['remove|Detailed']
                }
                try { [IO.File]::WriteAllText((Join-Path $script:SIRoot 'tests\_measure-1397.json'), ($result | ConvertTo-Json -Depth 4)) } catch { }
                $secs = $sw.Elapsed.TotalSeconds
                $n | Should -Be $rows
                [long](& $inv 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = CONVERT(int, @C) AND RaReport = 2' @{ C = [string]$c } 'scalar') | Should -Be 50000
                $result[$mode] = [ordered]@{ Rows = $n; Seconds = [Math]::Round($secs, 1); RowsPerSecond = [Math]::Round($n / [Math]::Max(0.001, $secs)); LastBatch = $last; FillSeconds = [Math]::Round($fillS, 1) }
                Write-Host ("[#1397 measure] removal {0}: {1:N0} rows in {2:N1} s = {3:N0} rows/s; batch size at the end {4:N0} (fill {5:N1} s)" -f $mode, $n, $secs, ($n / [Math]::Max(0.001, $secs)), $last, $fillS)
            }
            [long](& $inv 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = 1' @{} 'scalar') | Should -Be 100000
            # the trace check over 2 M rows of which every row's name is shared (50,000 names, two keys each) -- the old one
            # statement would hold every row with its JSON; the pages hold one page. Peak working set during the check.
            & $fillBig 3 5 $rows 0
            for ($lo = 0L; $lo -lt $rows; $lo += 200000) {
                [void](& $inv "UPDATE sidata.Finding SET RaTraceKey = CONCAT(RaTraceKey, N'-', RaSeq % 3) WHERE CollectionId = 3 AND RaReport = 5 AND RaSeq > CONVERT(bigint, @Lo) AND RaSeq <= CONVERT(bigint, @Lo) + 200000;" @{ Lo = [string]$lo } 'nonquery')
                Write-Host ("[#1397 measure] trace names shared: {0:N0} rows" -f [Math]::Min($rows, $lo + 200000))
            }
            $script:RAStreamBatchSize = @{}
            $written = @{ N = 0L }
            function script:Get-RATraceBase { param($Row, $IsDetailed) @{ AssetKey = [string]$Row.AssetKey; Parts = @('dev') } }
            function script:Get-RATraceId { param($TraceName) 'x' }
            function script:Write-SIDataJsonRows { param($Invoke, $Sql, $Items, $Params, $ChunkChars, $What) $written.N += @($Items).Count; [long]@($Items).Count }
            $ts = @{ Invoke = $inv; Grain = 'Detailed'; TimeText = '2026-11-25T16:01:49.000'; CollectionId = 3; Chunk = 1MB; Typed = $null; Log = { param($l, $m) Write-Host ('[#1397 measure] ' + $m) }
                     Current = @{ Ordinal = 5; Name = 'R5'; Retrieved = 0L; Staged = $false; Account = @{}; Times = @{} } }
            [GC]::Collect(); [GC]::WaitForPendingFinalizers()
            # the process's own high-water mark (Linux: VmHWM): everything before this point (the fills run in the SQL
            # sidecar, this process only sends text) stays far below what one statement over 2 M rows with JSON holds
            $proc = [Diagnostics.Process]::GetCurrentProcess(); $proc.Refresh(); $base = $proc.WorkingSet64; $peakBefore = $proc.PeakWorkingSet64
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $null = Complete-RAStreamReport -Stream $ts
            $proc.Refresh(); $peak = [Math]::Max($proc.PeakWorkingSet64, $proc.WorkingSet64)
            $growMb = [Math]::Round(([Math]::Max($peak, $peakBefore) - $base) / 1MB)
            $line = ("[#1397 measure] trace check over {0:N0} shared rows: {1:N0} named in {2:N1} s; working set {3:N0} MB at the start, peak {4:N0} MB (peak before the check {5:N0} MB) = at most +{6:N0} MB" -f $rows, $written.N, $sw.Elapsed.TotalSeconds, ($base / 1MB), ($peak / 1MB), ($peakBefore / 1MB), $growMb)
            Write-Host $line
            $result['trace'] = [ordered]@{ Rows = $rows; Named = $written.N; Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 1); StartMB = [Math]::Round($base / 1MB); PeakMB = [Math]::Round($peak / 1MB); PeakBeforeMB = [Math]::Round($peakBefore / 1MB) }
            try { [IO.File]::WriteAllText((Join-Path $script:SIRoot 'tests\_measure-1397.json'), ($result | ConvertTo-Json -Depth 4)) } catch { }
            $written.N | Should -Be $rows
            $growMb | Should -BeLessThan 1024 -Because 'one page of rows at a time: the old one statement held every row with its JSON (2 M x ~0.9 KB = GBs)'
        } finally {
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            try { [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery') } catch { }
        }
    }
}
