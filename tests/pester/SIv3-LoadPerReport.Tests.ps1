#Requires -Version 7.0
<#
    #1337 THE DATA SYNC'S FIELD FILL STARTS PER REPORT (SCALE-3 #1330 track D) -- the same rows as filling after the whole
    Risk Analysis; nothing publishes before the run ends.

    What these tests keep true:
      * the setting SI_Data_LoadPerReport: on (the default, anything unknown; owner 2026-11-23) | shadow | off; the mark's text;
      * the wiring: a Detailed report's verdict Complete starts its early fill, any other verdict, a report cleared to run
        again and one judged not complete at the end remove its mark, the run's end stops the worker BEFORE the collection is
        marked, the data sync's field fill takes the marks and removes them once the collection is prepared; the early fill
        never touches the published-run pointer or a collection's state;
      * ON A REAL SQL SERVER (the runner's, _SITestSql): three reports written as Risk Analysis writes them (view values at
        insert), each filled as it is complete, then the data sync's field fill (on) leaves their ranges out -- EVERY column
        of EVERY finding equals a collection filled only by the data sync after the whole run; a report that ran again (its
        rows gone, new rows, a stale mark) is filled by the data sync and still equals it; a failed report leaves no row and
        no mark; shadow fills every row, compares first and names a difference while the data sync's values are kept; the
        worker beside the run (its own runspace and connection) writes the same mark; the collection stays 'Loading' and the
        pointer does not move.
    PS 7. Never a customer database. Not a scale test.
#>

BeforeDiscovery {
    $script:LocalSql = $false
    try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
}

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-SchemaGate.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataModel.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
    . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-SqlStream.ps1')
    $script:Schema = [IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-data-schema.sql'))
    $script:EarlySrc = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-DataReportEarly.ps1'))
    $script:StreamSrc = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\_shared\RA-SqlStream.ps1'))
    $script:VcSrc = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-DataViewContext.ps1'))
    function script:Body([string]$Src, [string]$Name) { [regex]::Match($Src, '(?s)function ' + [regex]::Escape($Name) + ' \{.*?\r?\n\}').Value }
}

Describe 'the setting, the mark, the wiring' {
    It 'the setting: ON by default and for anything unknown; shadow / off' {
        Get-SIDataLoadPerReportMode -Value $null | Should -Be 'on'
        Get-SIDataLoadPerReportMode -Value 'whatever' | Should -Be 'on'
        Get-SIDataLoadPerReportMode -Value ' Shadow ' | Should -Be 'shadow'
        Remove-Variable -Name SI_Data_LoadPerReport -Scope Global -ErrorAction SilentlyContinue
        Get-SIDataLoadPerReportMode | Should -Be 'on'
        Get-SIDataLoadPerReportMode -Value ' ON ' | Should -Be 'on'
        Get-SIDataLoadPerReportMode -Value 'off' | Should -Be 'off'
        Get-SIDataLoadPerReportMode -Value $false | Should -Be 'off'
        $cat = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'config\settings.catalog.locked.json') | ConvertFrom-Json
        $s = @($cat.settings | Where-Object { $_.name -eq 'SI_Data_LoadPerReport' })[0]
        $s | Should -Not -BeNullOrEmpty
        @($s.values) | Should -Be @('off', 'shadow', 'on')
        $s.defaultText | Should -Match '^on'
    }
    It 'the mark: written and read back; anything else is no mark; its name fits the mark table' {
        $m = Format-SIDataEarlyMark -Lo 100 -Hi 250 -Rows 151 -IdCheck -12345 -Print ('ab' * 16)
        $m | Should -Be '100;250;151;-12345;ABABABAB'
        $r = ConvertFrom-SIDataEarlyMark $m
        $r.Lo | Should -Be 100; $r.Hi | Should -Be 250; $r.Rows | Should -Be 151; $r.IdCheck | Should -Be -12345; $r.Print8 | Should -Be 'ABABABAB'
        ConvertFrom-SIDataEarlyMark 'x;1' | Should -BeNullOrEmpty
        ConvertFrom-SIDataEarlyMark $null | Should -BeNullOrEmpty
        (Get-SIDataEarlyMarkName -CollectionId 2147483647 -Report 999 -SetId ('f' * 16)).Length | Should -BeLessOrEqual 64
        (Format-SIDataEarlyMark -Lo 9999999999 -Hi 9999999999 -Rows 99999999 -IdCheck -2147483648 -Print ('a' * 32)).Length | Should -BeLessOrEqual 64
    }
    It 'Risk Analysis: Complete starts the early fill; any other verdict, a cleared report and a late NotComplete remove its mark; the end stops the worker first' {
        (Body $script:StreamSrc 'Set-RAStreamReportStatus') | Should -Match 'Update-RAStreamEarlyLoad -Stream \$Stream -ReportName \$ReportName -State \$State'
        (Body $script:StreamSrc 'Clear-RAStreamReport') | Should -Match "Update-RAStreamEarlyLoad -Stream \`$Stream -State 'Cleared'"
        (Body $script:StreamSrc 'Set-RAStreamReportNotComplete') | Should -Match "Update-RAStreamEarlyLoad -Stream \`$Stream -ReportName \`$ReportName -State 'NotComplete'"
        $c = Body $script:StreamSrc 'Complete-RAStream'
        $c.IndexOf('Stop-RAStreamEarlyLoad') | Should -BeGreaterThan 0
        $c.IndexOf('Stop-RAStreamEarlyLoad') | Should -BeLessThan $c.LastIndexOf('Get-RAStreamCompleteSql')
        $u = Body $script:StreamSrc 'Update-RAStreamEarlyLoad'
        $u | Should -Match "if \(\`$State -ne 'Complete'\)"
        $u | Should -Match "\[string\]\`$Stream\.Typed\.Mode -eq 'on'"
        $u | Should -Match 'Start-SIDataEarlyLoadWorker'
    }
    It 'the early fill never publishes, never marks a collection, and reuses the data sync''s own field fill statement' {
        $script:EarlySrc | Should -Not -Match 'PublishedRun'
        $script:EarlySrc | Should -Not -Match '(?i)UPDATE sidata\.Collection'
        $script:EarlySrc | Should -Not -Match "(?i)Status\s*=\s*N?'Complete'"
        (Body $script:EarlySrc 'Invoke-SIDataReportEarlyLoad') | Should -Match '\$fill = Get-SIDataFindingContextSql -List \$List'
        # the data sync's side: the marks are read with the fill, its ranges skipped only in 'on', the marks removed after
        $script:VcSrc | Should -Match 'Get-SIDataReportEarlyIntervals -Invoke \$Invoke -CollectionId \$cid'
        $script:VcSrc | Should -Match "if \(\`$early\.Mode -eq 'shadow'\)"
        $script:VcSrc | Should -Match 'Remove-SIDataReportEarlyLoad -Invoke \$Invoke -CollectionId \$cid'
    }
    It 'the worker stops without hanging: reports still queued at the run''s end are let go; a worker that does not stop in time is left behind with a warning' {
        # a stand-in for the fill: -Seconds of work per report, deaf to the stop (the worst case: one command that hangs)
        $slow = Join-Path $TestDrive 'slow-fill.ps1'
        Set-Content -LiteralPath $slow -Encoding utf8 -Value 'function Invoke-SIDataReportEarlyLoad { param($Invoke, $CollectionId, $Report, $Print, $ReportName, $Mode, $Log, $ShouldStop) Start-Sleep -Seconds ([int]$Report); [pscustomobject]@{ Filled = $true; Rows = 1; Why = "" } }'
        $files = @(Get-RAStreamEarlyFiles) + @($slow)
        $wk = Start-SIDataEarlyLoadWorker -Files $files -CommandTimeoutSec 5
        foreach ($r in 3, 3, 3) { $null = Submit-SIDataEarlyLoad -Worker $wk -CollectionId 1 -Report $r -Print ('ab' * 16) -ConnectionString 'Server=none' }
        $deadline = [datetime]::UtcNow.AddSeconds(20); while (-not $wk.State.Busy -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
        $lines = New-Object System.Collections.Generic.List[string]
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $n = Stop-SIDataEarlyLoadWorker -Worker $wk -WaitSeconds 15 -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 12 -Because 'the report in hand finishes, the two still queued are let go'
        $n | Should -Be 1
        [int]$wk.State.Dropped | Should -Be 2
        @($lines | Where-Object { $_ -match '^INFO 2 complete report\(s\) were still waiting' }).Count | Should -Be 1
        # a worker that does not stop in time (one report of 60 s) is left behind -- the stop waits only as long as it is told
        $wk2 = Start-SIDataEarlyLoadWorker -Files $files -CommandTimeoutSec 5
        $null = Submit-SIDataEarlyLoad -Worker $wk2 -CollectionId 1 -Report 60 -Print ('ab' * 16) -ConnectionString 'Server=none'
        $deadline = [datetime]::UtcNow.AddSeconds(20); while (-not $wk2.State.Busy -and [datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
        $lines2 = New-Object System.Collections.Generic.List[string]
        $sw2 = [Diagnostics.Stopwatch]::StartNew()
        $null = Stop-SIDataEarlyLoadWorker -Worker $wk2 -WaitSeconds 2 -Log { param($l, $m) $lines2.Add("$l $m") }.GetNewClosure()
        $sw2.Elapsed.TotalSeconds | Should -BeLessThan 10
        @($lines2 | Where-Object { $_ -match '^WARN .*did not stop within 2 s' }).Count | Should -Be 1
        # the default wait is one command's limit + 30 s; every command of the worker has the limit
        [int]$wk2.State.CommandTimeout | Should -Be 5
        $script:EarlySrc | Should -Match '\$c\.CommandTimeout = \$cto'
        $script:EarlySrc | Should -Not -Match 'CommandTimeout = 0'
        $script:EarlySrc | Should -Match 'AsyncWaitHandle\.WaitOne\(\$ms\)'
    }
    It 'the check reads its own index (additive: IX_Finding_RaSeq left as it is), after the column it carries, built outside the file on a large table' {
        $s = $script:Schema
        $s | Should -Match ([regex]::Escape("CREATE INDEX IX_Finding_RaReportTyped ON sidata.Finding (CollectionId, RaReport) INCLUDE (TypedStatement) WHERE RaSeq IS NOT NULL"))
        $s | Should -Match ([regex]::Escape("CREATE INDEX IX_Finding_RaSeq ON sidata.Finding (CollectionId, RaReport, RaSeq) WHERE RaSeq IS NOT NULL"))
        $s.IndexOf('IX_Finding_RaReportTyped ON') | Should -BeGreaterThan $s.IndexOf("ALTER TABLE sidata.Finding ADD TypedStatement")
        . (Join-Path $script:Root 'engine\pro-settings\SI-ProSchema.ps1')
        @(Get-SIProSchemaIndexStatements -Sql $s | Where-Object { $_.Name -eq 'IX_Finding_RaReportTyped' }).Count | Should -Be 1 -Because 'a large install builds it on its own (estimate in the update, else the index-build window)'
    }
    It 'the shadow count is the field fill''s own expressions, reading only' {
        . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataViewContext.ps1')
        $list = Get-SIViewStoredColumns
        $fill = Get-SIDataFindingContextSql -List $list
        $d = Get-SIDataFindingContextDiffSql -Fill $fill
        $d | Should -Match '^SELECT COUNT_BIG\(\*\) FROM sidata\.Finding AS f'
        $d | Should -Not -Match 'UPDATE f SET'
        $d | Should -Match 'EXCEPT SELECT'
        $fill | Should -Match ([regex]::Escape($d.Substring('SELECT COUNT_BIG(*) '.Length)))
    }
}

Describe 'on a real SQL Server: per report = after the whole run, row for row' {
    BeforeAll {
        $script:LocalSql = $false
        try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
        if (-not $script:LocalSql) { return }
        $script:Db = 'siearly_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $script:CsFor = { param($Db) "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH)" }
        function script:New-LocalInvoke([string]$Db) {
            $cs = & $script:CsFor $Db
            {
                param([string]$sql, $p, [string]$mode)
                $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
                try {
                    $c = $cn.CreateCommand(); $c.CommandTimeout = 600; $c.CommandText = $sql
                    if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                    if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                    if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                    $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                    while ($r.Read()) { $h = [ordered]@{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add($h) }
                    $r.Close(); return , $rows.ToArray()
                } finally { $cn.Close() }
            }.GetNewClosure()
        }
        $script:Master = New-LocalInvoke 'master'
        [void](& $script:Master "CREATE DATABASE [$script:Db]" @{} 'nonquery')
        $script:Inv = New-LocalInvoke $script:Db
        function script:Get-Rows([string]$Sql, $P) { $x = & $script:Inv $Sql $P 'reader'; , @($x) }
        $cfg = [System.IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-pro-settings.sql'))
        foreach ($pass in 1, 2) {
            foreach ($b in ([regex]::Split($cfg, '(?m)^\s*$'))) { if (([regex]::Replace($b, '(?m)^\s*--.*$', '')).Trim()) { [void](& $script:Inv $b @{} 'nonquery') } }
            [void](& $script:Inv $script:Schema @{} 'nonquery')
        }
        $script:Quiet = { param($l, $m) }
        $global:SI_Data_ParseAtInsert = 'on'
        $script:Plan = Get-SIDataParseAtInsertPlan -Invoke $script:Inv -Mode on
        $script:List = Get-SIViewStoredColumns

        # ---- the rows of three reports: every field the field fill reads, in many shapes --------------------------------
        $flds = New-Object System.Collections.Generic.List[string]
        foreach ($e in @($script:List.finding)) { foreach ($f in @($e.fields)) { if ($f -and -not $flds.Contains([string]$f)) { $flds.Add([string]$f) } }; foreach ($g in @($e.flags)) { if ($g -and -not $flds.Contains([string]$g.field)) { $flds.Add([string]$g.field) } } }
        $vals = @('"High"', '""', '"  x  "', 'null', '["a","b",""]', '[]', '7.5', '"2026-01-02T03:04:05Z"', 'true', '"false"', '"Ünïcødé ☃"', ('"' + ('y' * 600) + '"'), '{"o":1}', '0', '"a;b"')
        $script:Items = @{}
        $seq = 0
        foreach ($rep in 1, 2, 3) {
            $list = New-Object System.Collections.Generic.List[string]
            for ($i = 1; $i -le 120; $i++) {
                $seq++
                $parts = New-Object System.Collections.Generic.List[string]; $k = 0
                foreach ($f in $flds) { $k++; if ((($seq + $k) % 4) -eq 0) { continue }; $v = $vals[($seq * 3 + $k * 7) % $vals.Count]; $parts.Add(('"{0}":{1}' -f $f, $v)) }
                $dj = '{' + ($parts -join ',') + '}'
                if ($seq % 41 -eq 0) { $dj = 'not json' }
                $list.Add((ConvertTo-Json -Compress -Depth 3 -InputObject ([ordered]@{
                    AssetKey = 'asset-' + ($seq % 37); AssetName = 'host-' + ($seq % 37); ReportName = 'Report_' + $rep; SecurityDomain = 'Endpoint'; ConfigurationId = 'CVE-2025-' + $seq
                    Cve = 'CVE-2025-' + $seq; Title = 't' + $seq; Severity = @('High', 'Low', 'Medium')[$seq % 3]; Tier = ($seq % 4); RiskScore = ($seq % 50) / 3.0; DetailJson = $dj
                    RaReport = $rep; RaBucket = '1/1'; RaSeq = $seq; RaSort = 1.0; RaInView = $true; RaTraceSuffixed = $false; RaTraceKey = 'k' + $seq; RaFindingKey = 'aid|cve-2025-' + $seq; RaAssetId = 'aid-' + ($seq % 37); RaAssetTier = 1
                })))
            }
            $script:Items[$rep] = $list.ToArray()
        }
        $script:Hour = 0
        function script:New-Collection([string]$Status = 'Complete') {
            $script:Hour++
            [int](& $script:Inv "INSERT sidata.Collection (CollectionTime, Kind, Status, [Rows]) VALUES (@t, N'Detailed', @s, 360); SELECT CONVERT(int, SCOPE_IDENTITY());" @{ t = ('2026-11-23T{0:00}:00:00' -f $script:Hour); s = $Status } 'scalar')
        }
        function script:Add-Report([int]$Cid, [int]$Rep) {
            $n = Write-SIDataJsonRows -Invoke $script:Inv -Sql (Get-RAStreamInsertFindingSql -Typed $script:Plan) -Items $script:Items[$Rep] -Params @{ CollectionId = [string]$Cid } -What 'test'
            $n | Should -Be 120
        }
        function script:Early([int]$Cid, [int]$Rep, [string]$Mode = 'on') { Invoke-SIDataReportEarlyLoad -Invoke $script:Inv -CollectionId $Cid -Report $Rep -Print $script:Plan.Print -List $script:List -Mode $Mode -Log $script:Quiet }
        function script:Context([string]$Mode) { $global:SI_Data_ParseAtInsert = 'on'; Invoke-SIDataViewContext -Invoke $script:Inv -List $script:List -Workers 1 -LoadPerReport $Mode -Log $script:Quiet }
        function script:Read-Findings([int]$Cid) { Get-Rows 'SELECT * FROM sidata.Finding WHERE CollectionId = @c ORDER BY RaSeq' @{ c = $Cid } }
        function script:Compare-Findings($A, $B) {
            $skip = @('FindingId', 'CollectionId')
            $diff = New-Object System.Collections.Generic.List[string]
            if ($A.Count -ne $B.Count) { $diff.Add(('row count {0} vs {1}' -f $A.Count, $B.Count)); return , $diff.ToArray() }
            $cols = @($A[0].Keys | Where-Object { $_ -notin $skip })
            for ($i = 0; $i -lt $A.Count; $i++) {
                foreach ($c in $cols) {
                    $x = $A[$i][$c]; $y = $B[$i][$c]
                    $same = if ($null -eq $x -or $null -eq $y) { $null -eq $x -and $null -eq $y }
                            elseif ($x -is [string]) { [string]::Equals($x, [string]$y, [StringComparison]::Ordinal) }
                            elseif ($x -is [double]) { [BitConverter]::DoubleToInt64Bits([double]$x) -eq [BitConverter]::DoubleToInt64Bits([double]$y) }
                            elseif ($x -is [array]) { (@($x) -join ',') -ceq (@($y) -join ',') }
                            else { $x -eq $y }
                    if (-not $same) { $diff.Add(('row {0} column {1}: [{2}] / [{3}]' -f $i, $c, $x, $y)) }
                }
            }
            , $diff.ToArray()
        }
        function script:Show-Diff($d) { if ($d.Count) { Write-Host ("DIFFERENCES ({0}):`n{1}" -f $d.Count, (($d | Select-Object -First 20) -join "`n")) } }
        function script:Marks([int]$Cid) { @(Get-Rows "SELECT Name, Value FROM sidata.ViewState WHERE Name LIKE @l" @{ l = ('ectx:{0}:%' -f $Cid) }) }

        # THE REFERENCE: filled only by the data sync after the whole run
        $script:Ref = New-Collection
        foreach ($rep in 1, 2, 3) { Add-Report $script:Ref $rep }
        $null = Context 'off'
        $script:RefRows = Read-Findings $script:Ref
    }
    AfterAll {
        Remove-Variable -Name SI_Data_ParseAtInsert -Scope Global -ErrorAction SilentlyContinue
        if (-not $script:LocalSql -or -not $script:Master) { return }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        [void](& $script:Master "ALTER DATABASE [$script:Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:Db]" @{} 'nonquery')
    }

    It 'the reference is filled (the comparison is not blind)' -Skip:(-not $script:LocalSql) {
        $script:Plan.Ready | Should -BeTrue
        @($script:RefRows | Where-Object { $null -ne $_['AffectedProduct'] }).Count | Should -BeGreaterThan 50
        @($script:RefRows | Where-Object { $null -ne $_['DescriptionFull'] }).Count | Should -BeGreaterThan 50
    }
    It 'on: each report filled as it is complete; the data sync leaves their ranges out; every column of every finding is the reference''s' -Skip:(-not $script:LocalSql) {
        $pub0 = [long](& $script:Inv 'SELECT COUNT_BIG(*) FROM sidata.PublishedRun' @{} 'scalar')
        $a = New-Collection
        foreach ($rep in 1, 2, 3) { Add-Report $a $rep; (Early $a $rep).Filled | Should -BeTrue -Because "report $rep" }
        (Marks $a).Count | Should -Be 3
        [long](& $script:Inv 'SELECT COUNT_BIG(*) FROM sidata.PublishedRun' @{} 'scalar') | Should -Be $pub0 -Because 'the early fill never moves the pointer'
        $r = Context 'on'
        $r.Early.Mode | Should -Be 'on'
        $r.Early.Reports | Should -Be 3
        $r.Early.Rows | Should -Be 360
        $d = Compare-Findings $script:RefRows (Read-Findings $a); Show-Diff $d
        $d.Count | Should -Be 0
        Write-Host ('PER-REPORT-SAME (on): 360 findings, 3 reports filled as each was complete, 0 differences')
        (Marks $a).Count | Should -Be 0 -Because 'the marks go once the collection is prepared'
    }
    It 'a report that ran again (rows gone, new rows, a stale mark) and one not filled early are filled by the data sync -- still the reference''s rows; a failed report leaves no row and no mark' -Skip:(-not $script:LocalSql) {
        $c = New-Collection
        Add-Report $c 1; $null = Early $c 1
        Add-Report $c 2; $null = Early $c 2
        # report 2 fails and is cleared: its rows and its mark go (as Clear-RAStreamReport does)
        Remove-SIDataReportEarlyLoad -Invoke $script:Inv -CollectionId $c -Report 2
        [void](& $script:Inv 'DELETE FROM sidata.Finding WHERE CollectionId = @c AND RaReport = 2' @{ c = $c } 'nonquery')
        [long](& $script:Inv 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = @c AND RaReport = 2' @{ c = $c } 'scalar') | Should -Be 0
        @(Marks $c | Where-Object { $_['Name'] -like ('ectx:{0}:2:*' -f $c) }).Count | Should -Be 0
        # report 3 is filled early, then runs again with its old mark left behind (a mark written after its verdict changed)
        Add-Report $c 3; $null = Early $c 3
        [void](& $script:Inv 'DELETE FROM sidata.Finding WHERE CollectionId = @c AND RaReport = 3' @{ c = $c } 'nonquery')
        # report 2 runs again (not filled early), then report 3 again
        Add-Report $c 2; Add-Report $c 3
        $lines = New-Object System.Collections.Generic.List[string]
        $global:SI_Data_ParseAtInsert = 'on'
        $r = Invoke-SIDataViewContext -Invoke $script:Inv -List $script:List -Workers 1 -LoadPerReport on -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r.Early.Reports | Should -Be 1 -Because 'only report 1 still matches'
        $r.Early.Rows | Should -Be 120
        $r.Early.Rejected | Should -BeGreaterOrEqual 1
        @($lines | Where-Object { $_ -match '^WARN .*report 3: its rows changed after it was filled' }).Count | Should -Be 1 -Because 'a report not taken is a warning (fix request)'
        $d = Compare-Findings $script:RefRows (Read-Findings $c); Show-Diff $d
        $d.Count | Should -Be 0
    }
    It 'shadow: every row filled by the data sync, the early reports compared first; a difference is named and the data sync''s values are kept' -Skip:(-not $script:LocalSql) {
        $s = New-Collection
        foreach ($rep in 1, 2, 3) { Add-Report $s $rep; $null = Early $s $rep 'shadow' }
        # one early value spoiled: the comparison must find it, the data sync's fill puts it right
        [void](& $script:Inv "UPDATE sidata.Finding SET AffectedProduct = N'SPOILED' WHERE CollectionId = @c AND RaSeq = 5" @{ c = $s } 'nonquery')
        $lines = New-Object System.Collections.Generic.List[string]
        $global:SI_Data_ParseAtInsert = 'on'
        $r = Invoke-SIDataViewContext -Invoke $script:Inv -List $script:List -Workers 1 -LoadPerReport shadow -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        $r.Early.Mode | Should -Be 'shadow'
        $r.Early.Compared | Should -Be 360
        $r.Early.Differences | Should -Be 1
        $r.Early.Rows | Should -Be 0 -Because 'shadow leaves nothing out'
        @($lines | Where-Object { $_ -match '^WARN .*differ from the data sync' }).Count | Should -Be 1
        $d = Compare-Findings $script:RefRows (Read-Findings $s); Show-Diff $d
        $d.Count | Should -Be 0
    }
    It 'off: no early fill, no mark' -Skip:(-not $script:LocalSql) {
        $o = New-Collection
        Add-Report $o 1
        (Early $o 1 'off').Filled | Should -BeFalse
        (Marks $o).Count | Should -Be 0
    }
    It 'the worker beside the run (its own runspace and connection) fills a report and writes its mark; the collection stays Loading' -Skip:(-not $script:LocalSql) {
        $pub0 = [long](& $script:Inv 'SELECT COUNT_BIG(*) FROM sidata.PublishedRun' @{} 'scalar')
        $w = New-Collection -Status 'Loading'
        Add-Report $w 1
        $wk = Start-SIDataEarlyLoadWorker -Files (Get-RAStreamEarlyFiles)
        Submit-SIDataEarlyLoad -Worker $wk -CollectionId $w -Report 1 -Print $script:Plan.Print -ReportName 'Report_1' -Mode on -ConnectionString (& $script:CsFor $script:Db) | Should -BeTrue
        $lines = New-Object System.Collections.Generic.List[string]
        $n = Stop-SIDataEarlyLoadWorker -Worker $wk -Drain -Log { param($l, $m) $lines.Add("$l $m") }.GetNewClosure()
        if ($n -ne 1) { Write-Host ($lines -join "`n") }
        $n | Should -Be 1
        @(Marks $w).Count | Should -Be 1
        [string](& $script:Inv 'SELECT Status FROM sidata.Collection WHERE CollectionId = @c' @{ c = $w } 'scalar') | Should -Be 'Loading'
        [long](& $script:Inv 'SELECT COUNT_BIG(*) FROM sidata.PublishedRun' @{} 'scalar') | Should -Be $pub0
        # the rows it filled are the reference's (report 1)
        $mine = Read-Findings $w; $ref1 = @($script:RefRows | Where-Object { $_['RaReport'] -eq 1 })
        $d = Compare-Findings $ref1 $mine; Show-Diff $d
        $d.Count | Should -Be 0
    }
}
