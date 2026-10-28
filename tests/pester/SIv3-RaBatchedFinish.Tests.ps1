#Requires -Version 5.1
<#
    THE LARGEST TENANT'S DETAILED RUN DID NOT FINISH (ring 1, live 2026-10-21, collection of 01:21Z: 67 of 69 reports stored,
    then the run failed and the collection stayed 'Loading' -- the data sync never built the groupings of the other 67).

      (a) Device_Missing_CVEs_Detailed (964,276 rows stored): "keeping once the findings two query slices both returned" was
          ONE DELETE over the whole report; it timed out three times at the database's command timeout. FIXED: the report is
          walked in pages through its key index, each page its own short statement (Get-RAStreamDedupPageSql,
          Invoke-RAStreamDedup); the page size is measured -- halved on a timeout, grown when fast, no fixed size, no time
          limit for the whole. The first written row is kept, exactly as before. Detailed and Summary.
      (b) Attack_Paths_Detailed_SignIn_Entitlement_to_Tier0_Servers: "the source could not count the report's rows in one
          query (413 Request Entity Too Large)" -- Unverified. FIXED: a count refused for its SIZE is asked in parts, the way
          the read is split, in twice as many parts while a finer split still makes the request smaller; the parts add up.
          When no count can be had it stays Unverified -- said, never a failure.
      (c) why the RUN failed: the report that failed had its rows taken back with ONE DELETE over 964,276 rows -- it timed out
          too, the stream was marked broken (a deliberate guard: a part of a report never goes out as the report) and the run
          ended failed. FIXED without touching the guard: every removal of a whole report (a report that failed or runs again,
          a part of a split report, an item that did not deliver) runs in measured batches. The failed report is NotComplete
          with its reason; the others load (the per-report scope), and nothing of the failed one is closed.

    Offline (a fake database in memory) plus a real SQL Server part when .\SQLEXPRESS runs (the test VM). NO EMOJI IN THIS FILE.
#>

BeforeDiscovery {
    $script:LocalSql = $false
    try { $script:LocalSql = (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction Stop).Status -eq 'Running' -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
    # the Pro data schema is read only after Test-Path finds it (the Community copy has no Pro database): skipped without it
    $script:HasSchema = Test-Path -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'sql', 'si-data-schema.sql'))
    $script:LocalSql = $script:LocalSql -and $script:HasSchema
}

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:SIRoot 'engine\_shared\data-sql\SI-DataModel.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SqlStream.ps1')
    . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-RowCountGuard.ps1')
    function script:Write-Info  { param($m) }
    function script:Write-Diag  { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Err2  { param($m) }
    $script:EngineText = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
    $script:StreamText = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-SqlStream.ps1'))
    $__schemaPath = Join-Path $script:SIRoot 'sql\si-data-schema.sql'
    $script:Schema = $(if (Test-Path -LiteralPath $__schemaPath) { [IO.File]::ReadAllText($__schemaPath) } else { '' })
    $script:TimeoutText = 'Exception calling "ExecuteScalar" with "0" argument(s): "Timeout expired.  The timeout period elapsed prior to completion of the operation or the server is not responding."'

    # ---- a fake database: one report's rows (Id, Key = the dedup key as hex, Seq = the write order) ---------------------
    function script:New-FakeRows([int]$N, [int]$Keys) {
        $l = New-Object System.Collections.Generic.List[object]
        for ($i = 1; $i -le $N; $i++) {
            $k = ('{0:X32}' -f ((($i * 7919) % $Keys)))
            $l.Add([pscustomobject]@{ Id = $i; Key = $k; Seq = [long]$i })
        }
        $l
    }
    # what "kept once, the first written" leaves: per key the row with the lowest write number
    function script:Get-Expected([object[]]$Rows) {
        @($Rows | Group-Object Key | ForEach-Object { ($_.Group | Sort-Object Seq | Select-Object -First 1).Id } | Sort-Object)
    }
    # the page statement, evaluated as the SQL does it: TOP(@Page) keys after @After in key order, every row of the last
    # key, remove a row when a row of the same key has a lower write number
    function script:Invoke-FakeDedupPage($Db, [hashtable]$P) {
        $page = [long]$P['Page']; $after = [string]$P['After']
        $cand = @($Db.Rows | Where-Object { -not $after -or [string]::CompareOrdinal($_.Key, $after) -gt 0 } | Sort-Object { $_.Key } -Culture ([Globalization.CultureInfo]::InvariantCulture))
        $top = @($cand | Select-Object -First $page)
        if ($top.Count -eq 0) { return , @(@{ Removed = 0; Seen = 0L; LastKey = '' }) }
        $k = ($top | ForEach-Object { $_.Key } | Sort-Object -Culture ([Globalization.CultureInfo]::InvariantCulture) | Select-Object -Last 1)
        $inPage = @($cand | Where-Object { [string]::CompareOrdinal($_.Key, $k) -le 0 })
        $gone = New-Object System.Collections.Generic.List[object]
        foreach ($g in ($inPage | Group-Object Key)) { $first = ($g.Group | Measure-Object Seq -Minimum).Minimum; foreach ($r in $g.Group) { if ($r.Seq -gt $first) { $gone.Add($r) } } }
        foreach ($r in $gone) { [void]$Db.Rows.Remove($r) }
        , @(@{ Removed = $gone.Count; Seen = [long]$top.Count; LastKey = $k })
    }
    function script:New-FakeStream($Db, [string]$Grain = 'Detailed') {
        $s = @{ Grain = $Grain; TimeText = '2026-10-21T01:21:01.000'; CollectionId = 24; RunKey = "$Grain|x"; Db = $Db; Log = $null
                Current = @{ Ordinal = 1; Name = 'Device_Missing_CVEs_Detailed'; Retrieved = 0L; Staged = $false; Account = @{} } }
        $s.Log = { param($l, $m) [void]$Db.Said.Add(('{0} {1}' -f $l, $m)) }.GetNewClosure()
        $s.Invoke = {
            param($Sql, $P, $Mode)
            $Db.Calls.Add([pscustomobject]@{ Sql = $Sql; P = $P; Mode = $Mode })
            if ($Db.TimeoutAbove -gt 0) {
                $sz = 0L; if ($P.ContainsKey('Page')) { $sz = [long]$P['Page'] } elseif ($P.ContainsKey('Batch')) { $sz = [long]$P['Batch'] }
                if ($sz -gt $Db.TimeoutAbove) { $Db.Timeouts++; throw $Db.TimeoutText }
            }
            if ($Sql -match 'RANK\(\) OVER') { return (& $Db.Page $Db $P) }
            if ($Sql -match 'DELETE TOP') {
                $take = [Math]::Min([long]$P['Batch'], [long]$Db.ReportRows); $Db.ReportRows -= $take; return $take
            }
            return 0
        }.GetNewClosure()
        $s
    }
    function script:New-FakeDb([object[]]$Rows = @(), [long]$ReportRows = 0, [long]$TimeoutAbove = 0) {
        $l = New-Object System.Collections.Generic.List[object]; foreach ($r in $Rows) { $l.Add($r) }
        @{ Rows = $l; Page = ${function:Invoke-FakeDedupPage}; ReportRows = $ReportRows; TimeoutAbove = $TimeoutAbove; Timeouts = 0; TimeoutText = $script:TimeoutText
           Calls = (New-Object System.Collections.Generic.List[object]); Said = (New-Object System.Collections.Generic.List[string]) }
    }
}

Describe '(a) keeping once the findings two query slices both returned -- in pages, never one statement' {
    BeforeEach { $script:RAStreamBatchSize = @{} }

    It 'the first written row of every key is kept, every later one removed -- the same rows as the one statement' {
        $rows = New-FakeRows -N 3000 -Keys 700
        $exp = Get-Expected $rows; $db = New-FakeDb -Rows $rows; $s = New-FakeStream $db
        $script:RAStreamBatchSize['dedup|Detailed'] = 128
        $n = Invoke-RAStreamDedup -Stream $s -Params @{ CollectionTime = $s.TimeText; CollectionId = '24'; Report = '1' }
        [long]$n | Should -Be 2300
        $kept = [long[]]@($db.Rows | ForEach-Object { [long]$_.Id } | Sort-Object)
        ($kept -join ',') | Should -Be ((@($exp | ForEach-Object { [long]$_ }) -join ','))
        $db.Calls.Count | Should -BeGreaterThan 1 -Because 'a report is walked in pages'
        # every page asks after the key the page before it ended on: the first from the start, none asked twice, in key order
        $after = [string[]]@(foreach ($c in $db.Calls) { [string]$c.P['After'] })
        $after[0] | Should -BeNullOrEmpty
        $sorted = [string[]]$after.Clone(); [Array]::Sort($sorted, [StringComparer]::Ordinal)
        ($after -join ',') | Should -Be ($sorted -join ',')
        @($after | Select-Object -Unique).Count | Should -Be $after.Count
    }

    It 'a key whose rows span a page boundary keeps its first row (every row of the last key is in the page)' {
        # 50 rows of ONE key, then others: the first page of 10 keys ends inside that key's rows
        $rows = New-Object System.Collections.Generic.List[object]
        for ($i = 1; $i -le 50; $i++) { $rows.Add([pscustomobject]@{ Id = $i; Key = ('{0:X32}' -f 5); Seq = [long](100 - $i) }) }
        for ($i = 51; $i -le 80; $i++) { $rows.Add([pscustomobject]@{ Id = $i; Key = ('{0:X32}' -f ($i % 7)); Seq = [long]$i }) }
        $exp = Get-Expected $rows.ToArray()
        $db = New-FakeDb -Rows $rows.ToArray()
        $s = New-FakeStream $db
        $script:RAStreamBatchSize['dedup|Detailed'] = 10
        $null = Invoke-RAStreamDedup -Stream $s -Params @{ CollectionId = '24'; Report = '1' }
        @($db.Rows | ForEach-Object { $_.Id } | Sort-Object) | Should -Be $exp
        @($db.Rows | Where-Object { $_.Key -eq ('{0:X32}' -f 5) }).Id | Should -Be 50 -Because 'the lowest write number of that key (seq 50) is the first written'
    }

    It 'a page that runs into the command timeout is asked again at half the size -- nothing lost, nothing doubled' {
        Mock Start-Sleep { }
        $rows = New-FakeRows -N 2000 -Keys 300
        $exp = Get-Expected $rows
        $db = New-FakeDb -Rows $rows -TimeoutAbove 200
        $s = New-FakeStream $db
        $script:RAStreamBatchSize['dedup|Detailed'] = 1000
        $n = Invoke-RAStreamDedup -Stream $s -Params @{ CollectionId = '24'; Report = '1' }
        $n | Should -Be 1700
        @($db.Rows | ForEach-Object { $_.Id } | Sort-Object) | Should -Be $exp
        $db.Timeouts | Should -BeGreaterThan 0
        $pages = @($db.Calls | ForEach-Object { [long]$_.P['Page'] })
        $pages[0] | Should -Be 1000
        $pages[1] | Should -Be 500 -Because 'halved on the timeout'
        $pages[2] | Should -Be 250
        $pages[3] | Should -Be 125
        ($db.Said -join "`n") | Should -Match 'keeping once the findings two query slices both returned: one batch took longer than the database allows for one statement -- it is asked again in batches of 500'
        Should -Invoke Start-Sleep -Exactly -Times 0 -Because 'a timeout is answered by a smaller batch, not by waiting'
    }

    It 'a batch of ONE that still times out three times fails the step with what it was doing -- the report is NotComplete' {
        $db = New-FakeDb -Rows (New-FakeRows -N 10 -Keys 3) -TimeoutAbove 0
        $s = New-FakeStream $db
        $s.Invoke = { param($Sql, $P, $Mode) throw $script:TimeoutText }
        $script:RAStreamBatchSize['dedup|Detailed'] = 4
        $err = $null
        try { $null = Invoke-RAStreamDedup -Stream $s -Params @{ CollectionId = '24'; Report = '1' } } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Message | Should -Match '^the database did not answer in time while keeping once the findings two query slices both returned \(3 attempt\(s\)\)'
        $err.Exception.Data['SIRAStreamTimeout'] | Should -BeTrue
    }

    It 'the size is measured: a fast batch grows it (at most double), a slow one shrinks it, and the next report starts where it ended' {
        Get-RAStreamNextBatchSize -Current 1000 -ElapsedMs 100 -TargetMs 10000 | Should -Be 2000
        Get-RAStreamNextBatchSize -Current 1000 -ElapsedMs 20000 -TargetMs 10000 | Should -Be 500
        Get-RAStreamNextBatchSize -Current 1 -ElapsedMs 999999 -TargetMs 10000 | Should -Be 1
        $script:RAStreamBatchSize = @{}
        $db = New-FakeDb -Rows (New-FakeRows -N 400 -Keys 100)
        $s = New-FakeStream $db
        $null = Invoke-RAStreamDedup -Stream $s -Params @{ CollectionId = '24'; Report = '1' }
        [long]$db.Calls[0].P['Page'] | Should -Be 50000 -Because 'the first page of a run'
        $script:RAStreamBatchSize['dedup|Detailed'] | Should -BeGreaterThan 0
        $script:RAStreamBatchSize['dedup|Detailed'] = 77
        $db2 = New-FakeDb -Rows (New-FakeRows -N 400 -Keys 100)
        $null = Invoke-RAStreamDedup -Stream (New-FakeStream $db2) -Params @{ CollectionId = '24'; Report = '2' }
        [long]$db2.Calls[0].P['Page'] | Should -Be 77 -Because 'the next report of the run starts at the size the last one ended with'
    }

    It 'a passing failure (a dropped connection) asks the same batch again; any other error fails at once' {
        Mock Start-Sleep { }
        $state = @{ N = 0 }
        $st = @{ Grain = 'Detailed'; Log = $null; Invoke = { param($Sql, $P, $Mode) $state.N++; if ($state.N -eq 1) { throw 'A transport-level error has occurred when receiving results from the server.' }; 3 }.GetNewClosure() }
        (Remove-RAStreamRowsBatched -Stream $st -Sql 'DELETE TOP (CONVERT(int, @Batch)) x' -What 'w') | Should -Be 3
        $state.N | Should -Be 2
        $bad = @{ Grain = 'Detailed'; Log = $null; Invoke = { param($Sql, $P, $Mode) throw 'Invalid column name x' } }
        { Remove-RAStreamRowsBatched -Stream $bad -Sql 'DELETE TOP (CONVERT(int, @Batch)) x' -What 'w' } | Should -Throw 'Invalid column name x'
    }

    It 'the page statements: the index''s condition, the cursor, the rank by the write order (both grains); the Summary index exists' {
        $d = Get-RAStreamDedupPageSql -Grain Detailed
        $d | Should -Match 'SELECT TOP \(CONVERT\(bigint, @Page\)\) RaDedup FROM sidata\.Finding\s+WHERE CollectionId = @c AND RaReport = @r AND RaDedup IS NOT NULL AND \(@a IS NULL OR RaDedup > @a\)\s+ORDER BY RaDedup'
        $d | Should -Match 'RANK\(\) OVER \(PARTITION BY RaDedup ORDER BY RaSeq\) AS Rk'
        $d | Should -Match 'RaSeq IS NOT NULL AND \(@a IS NULL OR RaDedup > @a\) AND RaDedup <= @k'
        $d | Should -Match 'x\.Rk > 1'
        $d | Should -Match 'SELECT @n AS Removed, ISNULL\(@seen, 0\) AS Seen, ISNULL\(CONVERT\(varchar\(32\), @k, 2\), ''''\) AS LastKey'
        $sm = Get-RAStreamDedupPageSql -Grain Summary
        $sm | Should -Match 'RANK\(\) OVER \(PARTITION BY RaDedup ORDER BY RowNo\)'
        $sm | Should -Match 'DELETE a FROM sidata\.SummaryAsset a JOIN @d d'
        $sm | Should -Match 'BEGIN TRAN;'
        if (-not $script:Schema) { return }   # the Community copy has no Pro data schema
        $script:Schema | Should -Match ([regex]::Escape('CREATE INDEX IX_SummaryRow_RaDedup ON sidata.SummaryRow (CollectionTime, RaReport, RaDedup, RowNo) WHERE RaDedup IS NOT NULL'))
        $script:Schema | Should -Match ([regex]::Escape('CREATE INDEX IX_Finding_RaDedup ON sidata.Finding (CollectionId, RaReport, RaDedup, RaSeq) WHERE RaDedup IS NOT NULL'))
    }

    It 'WIRING: the end of a report keeps once in pages, and names its step' {
        $fn = [regex]::Match($script:StreamText, '(?s)function Complete-RAStreamReport \{.*?\n\}').Value
        $fn | Should -Match ([regex]::Escape("Invoke-RAStreamDedup -Stream `$Stream -Params `$p -What 'keeping once the findings two query slices both returned'"))
        $fn | Should -Not -Match 'Get-RAStreamDedupSql'
    }
}

Describe '(c) a report that failed is taken back in batches -- one unfinished report never stops the rest' {
    BeforeEach { $script:RAStreamBatchSize = @{} }

    It 'the live case: 964,276 rows of a failed report are removed in batches although a large batch times out' {
        Mock Start-Sleep { }
        $db = New-FakeDb -ReportRows 964276 -TimeoutAbove 40000
        $s = New-FakeStream $db
        Clear-RAStreamReport -Stream $s -Why 'the report failed'
        $db.ReportRows | Should -Be 0 -Because 'every row of the report is removed'
        $del = @($db.Calls | Where-Object { $_.Sql -match 'DELETE TOP' })
        $del.Count | Should -BeGreaterThan 10
        @($del | Where-Object { $_.Sql -match 'FROM sidata\.Finding' }).Count | Should -BeGreaterThan 0
        @($del | Where-Object { $_.Sql -match 'FROM sidata\.RaStage' }).Count | Should -Be 1 -Because 'nothing staged: one batch finds none'
        $db.Timeouts | Should -BeGreaterThan 0 -Because 'the batch grew past what the database answers in time, and was halved'
        @($db.Said | Where-Object { $_ -match '^INFO 964276 row\(s\) this report already stored are removed -- the report failed$' }).Count | Should -Be 1
        $s.Current.Retrieved | Should -Be 0
    }

    It 'the batch statements remove the same rows as the one statement (same condition, same index), Summary with its assets' {
        $d = Get-RAStreamDeleteReportBatchSql -Grain Detailed
        $d | Should -Match ([regex]::Escape("DELETE TOP (CONVERT(int, @Batch)) FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaReport = CONVERT(int, @Report) AND RaSeq IS NOT NULL AND (@Bucket = '*' OR RaBucket = @Bucket)"))
        (Get-RAStreamDeleteBucketSql -Grain Detailed) | Should -Match ([regex]::Escape("WHERE CollectionId = CONVERT(int, @CollectionId) AND RaReport = CONVERT(int, @Report) AND RaSeq IS NOT NULL AND (@Bucket = '*' OR RaBucket = @Bucket)"))
        $sm = Get-RAStreamDeleteReportBatchSql -Grain Summary
        $sm | Should -Match 'SELECT TOP \(CONVERT\(int, @Batch\)\) RowNo FROM sidata\.SummaryRow WHERE CollectionTime = @t AND RaReport = @r'
        $sm | Should -Match 'DELETE a FROM sidata\.SummaryAsset a JOIN @d d'
        (Get-RAStreamDeleteReportBatchSql -Grain Stage) | Should -Match 'DELETE TOP \(CONVERT\(int, @Batch\)\) FROM sidata\.RaStage WHERE RunKey = @RunKey'
        (Get-RAStreamDeleteReportBatchSql -Grain Seq) | Should -Match 'RaSeq >= CONVERT\(bigint, @From\) AND RaSeq < CONVERT\(bigint, @To\)'
    }

    It 'WIRING: every removal of a whole report is batched; a report that still cannot be taken back is held back (#877), not the run failed' {
        $clear = [regex]::Match($script:StreamText, '(?s)function Clear-RAStreamReport \{.*?\n\}').Value
        $clear | Should -Match 'Remove-RAStreamRowsBatched -Stream \$Stream -Sql \(Get-RAStreamDeleteReportBatchSql -Grain \$Stream\.Grain\)'
        $clear | Should -Match 'Remove-RAStreamRowsBatched -Stream \$Stream -Sql \(Get-RAStreamDeleteReportBatchSql -Grain Stage\)'
        $seq = [regex]::Match($script:StreamText, '(?s)function Remove-RAStreamSeqRanges \{.*?\n\}').Value
        $seq | Should -Match 'Remove-RAStreamRowsBatched -Stream \$Stream -Sql \(Get-RAStreamDeleteReportBatchSql -Grain Seq\)'
        $item = [regex]::Match($script:EngineText, '(?s)function Clear-RAScaleOutReportRows \{.*?\n\}').Value
        $item | Should -Match 'Remove-RAStreamRowsBatched -Stream \$script:RAStream -Sql \(Get-RAStreamDeleteReportBatchSql -Grain \$script:RAStream\.Grain\)'
        # #877 (owner 2026-10-22, "Hold back that report"): a report whose rows could NOT be taken back is held back -- only
        # that report; its rows are never read as the report (SIv3-ReportHeldBack.Tests.ps1)
        $script:EngineText | Should -Match ([regex]::Escape("try { Clear-RAStreamReport -Stream `$script:RAStream -Why 'the report failed' } catch { Set-RAReportRowsHeld -Cause `$_.Exception.Message }"))
    }

    It 'the run goes on: the failed report is recorded NotComplete with its reason, and only it is held (per-report scope)' {
        $why = 'it failed: the database did not answer in time while keeping once the findings two query slices both returned (3 attempt(s)) -- the report''s stored result is not complete: Timeout expired'
        $inc = @(Get-RAIncompleteReports -Failures @(@{ Report = 'Device_Missing_CVEs_Detailed'; Why = $why }) -Attempted @('Device_Missing_CVEs_Detailed', 'Device_Recommendations_Detailed') -Counts @{ Device_Missing_CVEs_Detailed = 0; Device_Recommendations_Detailed = 5 })
        $inc.Count | Should -Be 1
        $inc[0].Report | Should -Be 'Device_Missing_CVEs_Detailed'
        $inc[0].Why | Should -Match '^it failed: the database did not answer in time while keeping once'
        Get-RAPartialScope -Reports @('Device_Missing_CVEs_Detailed') -RunCauses @() | Should -Be 'reports' -Because 'every cause is a named report: the others load, that one keeps its last complete result and closes nothing'
        Get-RAPartialScope -Reports @('Device_Missing_CVEs_Detailed') -RunCauses @('a Log Analytics post failed') | Should -Be 'run'
        # a report failure makes the run partial, never failed: the engine fails the run only on a broken stream or an undelivered result
        $script:EngineText | Should -Match ([regex]::Escape("Add-RAReportFailure -ReportName ([string]`$ReportName) -Reason (""it failed: {0}"" -f `$_.Exception.Message)"))
        $script:EngineText | Should -Match ([regex]::Escape('if ($script:RAStream.Broken) {'))
    }
}

Describe '(b) a count refused for its size is asked in parts, the way the read is split' {
    It 'two parts refused, four answered: the parts add up' {
        $asked = New-Object System.Collections.Generic.List[string]
        $run = { param($i, $parts) $asked.Add(('{0}/{1}' -f $i, $parts)); if ($parts -lt 4) { throw 'Response status code does not indicate success: 413 (Request Entity Too Large).' }; @{ Ok = $true; Rows = @([pscustomobject]@{ Count = [long](10 + $i) }) } }.GetNewClosure()
        $r = Measure-RAReportExpectedRowsInParts -Start 1 -RunSlice $run -CanSplitFiner { param($e, $p) $true }
        $r.Count | Should -Be (10 + 11 + 12 + 13)
        $r.Parts | Should -Be 4
        $asked[0] | Should -Be '0/2' -Because 'a report read in one slice is counted in two parts first'
    }
    It 'a finer split that no longer helps stops it: no count, the refusal said -- never a failure' {
        $run = { param($i, $parts) throw 'Response status code does not indicate success: 413 (Request Entity Too Large).' }
        $r = Measure-RAReportExpectedRowsInParts -Start 2 -RunSlice $run -CanSplitFiner { param($e, $p) $p -le 8 }
        $r.Count | Should -BeNullOrEmpty
        $r.Parts | Should -Be 8 -Because 'doubled while the split still helped (2 -> 4 -> 8; 16 refused by the rule)'
        $r.Error | Should -Match 'slice 1/8: .*413'
        # another refusal (not the size) is not split further
        $calls = @{ N = 0 }
        $run2 = { param($i, $parts) $calls.N++; throw 'Bad request: Fix syntax' }.GetNewClosure()
        $r2 = Measure-RAReportExpectedRowsInParts -Start 2 -RunSlice $run2 -CanSplitFiner { param($e, $p) $true }
        $r2.Parts | Should -Be 2
        $calls.N | Should -Be 1
    }
    It 'a Summary report counts its distinct groups over the parts (a group in two parts is one)' {
        $run = { param($i, $parts) @{ Ok = $true; Rows = @([pscustomobject]@{ SIGroupHash = 'g1' }, [pscustomobject]@{ SIGroupHash = ('g' + (2 + $i)) }) } }
        (Measure-RAReportExpectedRowsInParts -Start 2 -RunSlice $run -GroupKeys @('Tier')).Count | Should -Be 3
    }
    It 'the size refusal is recognised in the forms the service sends it' {
        Test-RACountRefusedForSize -Message '413 Request Entity Too Large -- {"error":{"code":"UnknownError","message":"<html>...nginx' | Should -BeTrue
        Test-RACountRefusedForSize -Message 'Response status code does not indicate success: 413 (Request Entity Too Large).' | Should -BeTrue
        Test-RACountRefusedForSize -Message 'Timeout expired' | Should -BeFalse
    }

    Context 'the engine''s count (Get-RAReportExpectedRows, lifted from the engine)' {
        BeforeAll {
            . ([scriptblock]::Create([regex]::Match($script:EngineText, '(?s)function Get-RAReportExpectedRows \{.*?\n\}').Value))
            function script:Test-QueryHasBucketFilterBlock { param($Query) $true }
            function script:Replace-BucketFilterBlock { param($Query, $BucketFilterKql) $Query }
            function script:New-BucketFilterKql { param($BucketCount, $BucketIndex, $ReportName) '' }
            function script:Get-RASummaryMergePlan { param($Query) $null }
            function script:Get-RABucketRows { param($Resp) $Resp }
            function script:Get-RAReportCountKql { param($Query, $GroupKeys) $Query }
            # the read's own rule (RA-AutoBucketing.ps1 Test-RASplitCanStillFit), lifted
            $ab = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1'), [ref]$null, [ref]$null)
            . ([scriptblock]::Create(($ab.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Test-RASplitCanStillFit' }, $true)).Extent.Text))
            # the hunting endpoint: a request carries 1.6 MB of inlined rows cut by the slice; over 1 MB it is refused (413)
            function script:Invoke-GraphHuntingQuery { param($Query, $ReconnectMaxAgeMinutes, $MaxRetries)
                $script:__asked++
                $n = [Math]::Max(1, [int]$script:_CurrentBucketCount)
                $script:_LastHybridInlineBytes = [long](1600000 / $n); $script:_LastHybridQueryBodyOverheadBytes = 50000
                if (($script:_LastHybridInlineBytes + 50000) -gt 1048576) { throw '413 Request Entity Too Large -- {"error":{"code":"UnknownError","message":"<html><head><title>413 Request Entity Too Large</title></head><body><center>nginx</center></body></html>"}}' }
                @{ Ok = $true; Rows = @([pscustomobject]@{ Count = [long](2 + [int]$script:_CurrentBucketIndex) }) } }
        }
        It 'the live report: the whole count refused, the slices'' rows cannot stand for it -> counted in 2 parts, Complete' {
            # the lake answered the read, so the rows are not taken as the count (the shortcut of a one-slice read does not apply)
            $script:__asked = 0; $script:RALakeAnswered = $true
            $r = Get-RAReportExpectedRows -Query 'T' -ReportName 'Attack_Paths_Detailed_SignIn_Entitlement_to_Tier0_Servers' -BucketCount 1 -Retrieved 5
            $script:RALakeAnswered = $false
            $r.Count | Should -Be 5 -Because 'parts 0 and 1 count 2 + 3'
            $r.Error | Should -BeNullOrEmpty
            $r.How | Should -Match '^counted in 2 parts, the way the report''s read is split \(the whole count could not be sent: 413 Request Entity Too Large'
            $script:__asked | Should -Be 3 -Because 'the whole count, then two parts'
            (Get-RACompletenessVerdict -Expected $r.Count -Retrieved 5 -CountError $r.Error).State | Should -Be 'Complete'
        }
        It 'nothing a finer split can cut (no inlined rows): no count -- Unverified, never NotComplete, never a failure' {
            function script:Invoke-GraphHuntingQuery { param($Query, $ReconnectMaxAgeMinutes, $MaxRetries)
                $script:_LastHybridInlineBytes = 0; $script:_LastHybridQueryBodyOverheadBytes = 2000000
                throw '413 Request Entity Too Large -- nginx' }
            $script:RALakeAnswered = $true
            $r = Get-RAReportExpectedRows -Query 'T' -ReportName 'R_Detailed' -BucketCount 1 -Retrieved 5
            $script:RALakeAnswered = $false
            $r.Count | Should -BeNullOrEmpty
            $r.Error | Should -Match '^count not available \(413 Request Entity Too Large -- nginx\); counted in 2 parts: slice 1/2: 413'
            $v = Get-RACompletenessVerdict -Expected $null -Retrieved 5 -CountError $r.Error
            $v.State | Should -Be 'Unverified'
        }
    }
}

Describe '(a) on a real SQL Server: the pages remove exactly what the one statement removed, through the index' {
    It 'Detailed: the same rows kept (the first written per key), IX_Finding_RaDedup in the plan; Summary runs with its index' -Skip:(-not $script:LocalSql) {
        $db = 'sidedup_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $mk = {
            param([string]$Name)
            $cs = "Server=.\SQLEXPRESS;Database=$Name;Integrated Security=True;TrustServerCertificate=True"
            {
                param([string]$sql, $p, [string]$mode)
                $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
                try {
                    $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = $sql
                    if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                    if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                    if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                    $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                    while ($r.Read()) { $h = @{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { [DBNull]::Value } else { $r.GetValue($i) }) }; $rows.Add($h) }
                    $r.Close(); return , $rows.ToArray()
                } finally { $cn.Close() }
            }.GetNewClosure()
        }
        $master = & $mk 'master'
        [void](& $master "CREATE DATABASE [$db]" @{} 'nonquery')
        try {
            $inv = & $mk $db
            [void](& $inv $script:Schema @{} 'nonquery'); [void](& $inv $script:Schema @{} 'nonquery')
            [void](& $inv "SET IDENTITY_INSERT sidata.Collection ON; INSERT sidata.Collection (CollectionId, CollectionTime, Kind, Status, Source) VALUES (2, '2026-10-21T01:21:00', 'Detailed', 'Loading', 'risk-analysis'), (3, '2026-10-21T01:22:00', 'Detailed', 'Loading', 'risk-analysis'); SET IDENTITY_INSERT sidata.Collection OFF;" @{} 'nonquery')
            # 3,000 rows of report 1 over 700 keys (write order NOT the key order), 200 rows of report 2, 50 rows without a key
            $fill = @'
;WITH n AS (SELECT TOP (3000) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b)
INSERT sidata.Finding (CollectionId, AssetKey, ReportName, Severity, Tier, RiskScore, DetailJson, RaReport, RaBucket, RaSeq, RaDedup)
SELECT CONVERT(int, @C), CONCAT(N'a', i), N'R', N'High', 1, 5, N'{}', 1, CONCAT(N'', i % 7, N'/7'), (i * 7919) % 100003, HASHBYTES('MD5', CONCAT(N'd', i % 700)) FROM n;
;WITH n AS (SELECT TOP (200) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects)
INSERT sidata.Finding (CollectionId, AssetKey, ReportName, Severity, Tier, RiskScore, DetailJson, RaReport, RaBucket, RaSeq, RaDedup)
SELECT CONVERT(int, @C), CONCAT(N'b', i), N'R2', N'High', 1, 5, N'{}', 2, N'1/1', 200000 + i, HASHBYTES('MD5', CONCAT(N'd', i % 50)) FROM n;
;WITH n AS (SELECT TOP (50) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects)
INSERT sidata.Finding (CollectionId, AssetKey, ReportName, Severity, Tier, RiskScore, DetailJson, RaReport, RaBucket, RaSeq)
SELECT CONVERT(int, @C), CONCAT(N'c', i), N'R', N'High', 1, 5, N'{}', 1, N'1/1', 300000 + i FROM n;
'@
            [void](& $inv $fill @{ C = '2' } 'nonquery')
            [void](& $inv $fill @{ C = '3' } 'nonquery')
            # collection 2: the one statement (as before); collection 3: the pages, from a small first page
            [void](& $inv (Get-RAStreamDedupSql -Grain Detailed) @{ CollectionId = '2'; Report = '1'; CollectionTime = '2026-10-21T01:21:00.000' } 'scalar')
            $script:RAStreamBatchSize = @{ 'dedup|Detailed' = 37 }
            $st = @{ Invoke = $inv; Grain = 'Detailed'; Log = $null }
            $n = Invoke-RAStreamDedup -Stream $st -Params @{ CollectionId = '3'; Report = '1'; CollectionTime = '2026-10-21T01:22:00.000' }
            $n | Should -Be 2300
            $q = 'SELECT RaSeq FROM sidata.Finding WHERE CollectionId = CONVERT(int, @C) ORDER BY RaSeq'
            $a = @(@(& $inv $q @{ C = '2' } 'reader') | ForEach-Object { $_ } | ForEach-Object { [long]$_['RaSeq'] })
            $b = @(@(& $inv $q @{ C = '3' } 'reader') | ForEach-Object { $_ } | ForEach-Object { [long]$_['RaSeq'] })
            $a.Count | Should -Be (700 + 200 + 50)
            $b | Should -Be $a -Because 'the same rows kept: the first written of every key, report 2 and the rows without a key untouched'
            # the page reads the index made for it
            $cn = New-Object System.Data.SqlClient.SqlConnection("Server=.\SQLEXPRESS;Database=$db;Integrated Security=True;TrustServerCertificate=True"); $cn.Open()
            try {
                $c = $cn.CreateCommand(); $c.CommandText = 'SET SHOWPLAN_XML ON'; [void]$c.ExecuteNonQuery()
                $c = $cn.CreateCommand(); $c.CommandText = "DECLARE @CollectionId nvarchar(20) = N'3', @Report nvarchar(20) = N'1', @Page nvarchar(20) = N'50000', @After nvarchar(40) = N'';`n" + (Get-RAStreamDedupPageSql -Grain Detailed)
                $r = $c.ExecuteReader(); $sb = New-Object System.Text.StringBuilder
                do { while ($r.Read()) { [void]$sb.Append([string]$r.GetValue(0)) } } while ($r.NextResult())
                $r.Close()
            } finally { $cn.Close() }
            $sb.ToString() | Should -Match 'Index="\[IX_Finding_RaDedup\]"'
            # Summary: the page statement runs against the real schema (no rows, nothing removed) and the removal batch too
            $sp = @{ CollectionTime = '2026-10-21T01:21:00.000'; Report = '1' }
            $sst = @{ Invoke = $inv; Grain = 'Summary'; Log = $null }
            (Invoke-RAStreamDedup -Stream $sst -Params $sp) | Should -Be 0
            (Remove-RAStreamRowsBatched -Stream $sst -Sql (Get-RAStreamDeleteReportBatchSql -Grain Summary) -Params ($sp + @{ Bucket = '*' }) -What 'w') | Should -Be 0
            # a whole report removed in batches on the real schema
            $script:RAStreamBatchSize = @{ 'remove|Detailed' = 333 }
            (Remove-RAStreamRowsBatched -Stream $st -Sql (Get-RAStreamDeleteReportBatchSql -Grain Detailed) -Params @{ CollectionId = '3'; Report = '1'; Bucket = '*' } -What 'w' -Kind 'remove|Detailed') | Should -Be 750
            [long](& $inv 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = 3 AND RaReport = 1' @{} 'scalar') | Should -Be 0
        } finally {
            [System.Data.SqlClient.SqlConnection]::ClearAllPools()
            try { [void](& $master "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]" @{} 'nonquery') } catch { }
        }
    }
}
