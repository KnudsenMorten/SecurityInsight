#Requires -Version 7.0
<#
    #1336 BULK LOAD (SCALE-3 #1330 track D) -- THE LARGE WRITES THROUGH SqlBulkCopy, THE SAME ROWS AS THE JSON PATH.

    What these tests keep true:
      * the setting SI_Data_BulkLoad: on (the default, anything unknown) | shadow | off;
      * ONE MAPPING: the statement of every bulk writer is the JSON path's own statement with "FROM OPENJSON(@j) WITH"
        read from the session table (#SIBulkRows) and an INSERT in the items' order; a statement in another shape is not
        converted (it is written the JSON way); every caller goes through Write-SIDataLoadRows / Write-RAStreamLoadRows;
      * the content hash: the compiled helper and its PowerShell twin agree on every kind of text;
      * a seam that cannot copy in bulk (a test's fake) is written the JSON way, exactly as before;
      * ON A REAL SQL SERVER (the runner's, _SITestSql): the same items written the JSON way and in bulk (many small
        batches) give byte-identical rows in EVERY column -- Risk Analysis' findings (plain and typed at insert), Summary
        rows, their impacted assets, the Summary stage, the findings per CI staged for the swap, the data out summary stage;
        a batch whose read-back differs once is redone (same rows); a batch that differs every time FAILS the load and keeps
        nothing of itself; shadow checks and rolls back, the JSON way serves; the batch size follows the measured time.
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
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSummary.ps1')
    . (Join-Path $script:Root 'engine\risk-analysis\_shared\RA-SqlStream.ps1')
    . (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataCi.ps1')
    $script:Schema = [IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-data-schema.sql'))
    $script:AllOn = [pscustomobject]@{ Mode = 'on'; Ready = $true; Why = ''; Services = $true; Fix = $true; Category = $true; RowColumns = $true; RiskParts = $true; Mask = 63; Print = (Get-SIDataTypedFingerprint -Services -Fix -Category -RowColumns -RiskParts) }
    $script:DataOutAdd = @'
INSERT sidata.DataOutSummaryStage (StageId, Seq, GroupKey, CiKey, Name, Score, WScore, AttrJson)
SELECT CONVERT(uniqueidentifier, @StageId), j.q, j.g, j.c, NULLIF(j.n, N''), j.s, j.w, j.a
FROM OPENJSON(@rows) WITH (q bigint, g nvarchar(380), c nvarchar(380), n nvarchar(400), s float, w float, a nvarchar(max) AS JSON) AS j;
'@
}

Describe 'the setting, the statements, the wiring' {
    It 'the setting: ON by default and for anything unknown; off / shadow' {
        Get-SIDataBulkLoadMode -Value $null | Should -Be 'on'
        Get-SIDataBulkLoadMode -Value '' | Should -Be 'on'
        Get-SIDataBulkLoadMode -Value ' Shadow ' | Should -Be 'shadow'
        Get-SIDataBulkLoadMode -Value 'OFF' | Should -Be 'off'
        Get-SIDataBulkLoadMode -Value $false | Should -Be 'off'
        Get-SIDataBulkLoadMode -Value 'yes' | Should -Be 'on'
        $cat = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'config\settings.catalog.locked.json') | ConvertFrom-Json
        $s = @($cat.settings | Where-Object { $_.name -eq 'SI_Data_BulkLoad' })[0]
        $s | Should -Not -BeNullOrEmpty
        @($s.values) | Should -Be @('off', 'shadow', 'on')
        $s.defaultText | Should -Match '^on'
    }
    It 'every writer''s statement converts: read from the session table, an INSERT in the items'' order, @j gone' {
        $sqls = [ordered]@{
            finding = (Get-RAStreamInsertFindingSql); typed = (Get-RAStreamInsertFindingSql -Typed $script:AllOn); summary = (Get-RAStreamInsertSummaryRowSql)
            asset = (Get-SIDataSummaryInsertAssetSql); stage = (Get-RAStreamInsertStageSql); cistage = (Get-SIDataWriteCiFindingSql -Stage -SubCi -Category)
        }
        foreach ($k in $sqls.Keys) {
            $b = ConvertTo-SIDataBulkSql -Sql $sqls[$k]
            $b | Should -Not -BeNullOrEmpty -Because $k
            $b | Should -Match ([regex]::Escape('FROM #SIBulkRows AS sib CROSS APPLY OPENJSON(sib.J) WITH (')) -Because $k
            # an INSERT keeps the items' order; a statement that first reads them into its own #temp table (the findings per CI) has none to keep
            if ($b -notmatch 'INTO #x FROM #SIBulkRows') { $b | Should -Match 'ORDER BY sib\.Seq;' -Because $k }
            $b | Should -Not -Match '@j\b' -Because $k
            # the mapping is untouched: the statement with the source put back is the statement of before
            $b.Replace('FROM #SIBulkRows AS sib CROSS APPLY OPENJSON(sib.J) WITH (', 'FROM OPENJSON(@j) WITH (').Replace(' ORDER BY sib.Seq;', ';') | Should -Be $sqls[$k] -Because $k
        }
        $d = ConvertTo-SIDataBulkSql -Sql $script:DataOutAdd -JsonParam rows
        $d | Should -Match 'AS JSON\) AS j ORDER BY sib\.Seq;'
        # not in the shape: written the JSON way
        ConvertTo-SIDataBulkSql -Sql (Get-RAStreamTraceUpdateSql -Grain Detailed) | Should -BeNullOrEmpty
        ConvertTo-SIDataBulkSql -Sql 'INSERT x SELECT a FROM OPENJSON(@j) WITH (a int) j; SELECT LEN(@j);' | Should -BeNullOrEmpty
        ConvertTo-SIDataBulkSql -Sql 'UPDATE t SET a = 1;' | Should -BeNullOrEmpty
        # an UPDATE keeps no order (none is needed); a comment with a quote or a ';' never ends the statement
        (ConvertTo-SIDataBulkSql -Sql "UPDATE t SET a = j.a FROM OPENJSON(@j) WITH (a int) j`n-- it's a note; really`nWHERE t.a = 0;") | Should -Not -Match 'ORDER BY'
        (ConvertTo-SIDataBulkSql -Sql "INSERT t (a) SELECT j.a FROM OPENJSON(@j) WITH (a int) j`n-- it's a note; really`nWHERE j.a > 0;") | Should -Match "WHERE j\.a > 0 ORDER BY sib\.Seq;$"
    }
    It 'the hash: the compiled helper and its PowerShell twin agree' {
        Get-SIDataBulkEngine | Should -Be 'compiled'
        $items = [string[]]@('{}', '{"a":"Ünïcødé ☃ 漢字 😀"}', '{"q":"a\"b"}', ('{"l":"' + ('x' * 5000) + '"}'), '{"n":null,"x":[1,2,{"y":true}]}', "{`"t`":`"line`nbreak`"}")
        $c = Get-SIDataBulkHashSum -Items $items -Engine compiled
        $p = Get-SIDataBulkHashSum -Items $items -Engine powershell
        $p | Should -Be $c
        Get-SIDataBulkHashSum -Items $items -Offset 2 -Count 3 -Engine compiled | Should -Be (Get-SIDataBulkHashSum -Items $items -Offset 2 -Count 3 -Engine powershell)
        # the order is part of it
        Get-SIDataBulkHashSum -Items ([string[]]@($items[1], $items[0])) | Should -Not -Be (Get-SIDataBulkHashSum -Items ([string[]]@($items[0], $items[1])))
        $t = ConvertTo-SIDataBulkTable -Items $items -Offset 1 -Count 2
        $t.Rows.Count | Should -Be 2; $t.Rows[0]['Seq'] | Should -Be 1; $t.Rows[1]['J'] | Should -Be $items[2]
    }
    It 'a seam that cannot copy in bulk is written the JSON way, as before' {
        $calls = New-Object System.Collections.Generic.List[string]
        $fake = { param($sql, $p, $mode) $calls.Add([string]$sql); ([regex]::Matches([string]$p['j'], '\{')).Count }.GetNewClosure()
        Test-SIDataBulkSeam $fake | Should -BeFalse
        $n = Write-SIDataLoadRows -Invoke $fake -Sql (Get-SIDataSummaryInsertAssetSql) -Items @('{"RowNo":1}', '{"RowNo":2}') -Params @{ CollectionTime = 'x' } -Mode on
        $n | Should -Be 2
        $calls[-1] | Should -Match 'FROM OPENJSON\(@j\)'
    }
    It 'every large writer goes through the one call' {
        $ra = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\risk-analysis\_shared\RA-SqlStream.ps1'))
        ([regex]::Matches($ra, 'Write-RAStreamLoadRows -Stream \$Stream')).Count | Should -Be 4
        $ra | Should -Match 'Write-SIDataLoadRows -Invoke \$Stream\.Invoke'
        $ci = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-DataCi.ps1'))
        $ci | Should -Match 'Write-SIDataLoadRows -Invoke \$Invoke -Sql \(Get-SIDataWriteCiFindingSql -Stage'
        $do = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\data-out\SI-DataOut.ps1'))
        $do | Should -Match "Write-SIDataLoadRows -Invoke \`$c\.Stage -Sql \(\(Get-SIDataOutSummaryAddSql\) \+ `"SELECT @@ROWCOUNT;"
        $sql = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1'))
        $sql | Should -Match 'Add-Member -NotePropertyName SIBulkOpen'
    }
}

Describe 'on a real SQL Server: bulk = the JSON way, row for row' {
    BeforeAll {
        $script:LocalSql = $false
        try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
        if (-not $script:LocalSql) { return }
        $script:Db = 'sibulk_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        function script:New-LocalInvoke([string]$Db, [switch]$Bulk) {
            $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH)"
            $inv = {
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
            if ($Bulk) { $inv | Add-Member -NotePropertyName SIBulkOpen -NotePropertyValue ({ $x = New-Object System.Data.SqlClient.SqlConnection($cs); $x.Open(); $x }.GetNewClosure()) }
            $inv
        }
        $script:Master = New-LocalInvoke 'master'
        [void](& $script:Master "CREATE DATABASE [$script:Db]" @{} 'nonquery')
        $script:Inv = New-LocalInvoke $script:Db
        $script:Bulk = New-LocalInvoke $script:Db -Bulk
        function script:Get-Rows([string]$Sql, $P) { $x = & $script:Inv $Sql $P 'reader'; , @($x) }
        $cfg = [System.IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-pro-settings.sql'))
        foreach ($pass in 1, 2) {
            foreach ($b in ([regex]::Split($cfg, '(?m)^\s*$'))) { if (([regex]::Replace($b, '(?m)^\s*--.*$', '')).Trim()) { [void](& $script:Inv $b @{} 'nonquery') } }
            [void](& $script:Inv $script:Schema @{} 'nonquery')
        }
        # the data out's staging tables (its own statement)
        [void](& $script:Inv @'
IF OBJECT_ID(N'sidata.DataOutSummaryStage') IS NULL
CREATE TABLE sidata.DataOutSummaryStage (StageId UNIQUEIDENTIFIER NOT NULL, Seq BIGINT NOT NULL, GroupKey NVARCHAR(380) NOT NULL, CiKey NVARCHAR(380) NULL,
    Name NVARCHAR(400) NULL, Score FLOAT NULL, WScore FLOAT NULL, AttrJson NVARCHAR(MAX) NULL, CONSTRAINT PK_DataOutSummaryStageT PRIMARY KEY (StageId, Seq));
'@ @{} 'nonquery')
        $script:Quiet = { param($l, $m) }

        # ---- items of every shape ------------------------------------------------------------------------------------
        $script:N = 700
        $str = @('High', '', '   ', $null, 'Ünïcødé ☃ 漢字 😀', 'a"quote', "line`nbreak", 'it''s', ('x' * 4500), 'Very High', ' padded ')
        $det = New-Object System.Collections.Generic.List[string]
        for ($i = 1; $i -le $script:N; $i++) {
            $inner = [ordered]@{ RiskRating = $str[$i % $str.Count]; RiskScoreTotal_Weighted = ($i % 97) / 7.0; MITRE_Tactics = @('TA0001', 'TA0002')[0..($i % 2)]; HasExploit = ($i % 3 -eq 0); cmdbId = 'svc-' + ($i % 13) }
            $det.Add((ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{
                AssetKey = $(if ($i % 37 -eq 0) { $null } else { 'asset-' + ($i % 211) }); AssetName = 'host-' + ($i % 211) + $str[$i % $str.Count]; ReportName = 'Report_' + ($i % 7)
                SecurityDomain = @('Endpoint', 'Identity', $null)[$i % 3]; ConfigurationId = 'CVE-2025-' + $i; Cve = $(if ($i % 3 -eq 0) { 'CVE-2025-' + $i } else { $null })
                Title = 'title ' + $str[($i + 3) % $str.Count]; Severity = @('High', 'Low', 'Very High', 'Medium', $null)[$i % 5]; Tier = $(if ($i % 9 -eq 0) { $null } else { $i % 4 })
                RiskScore = $(if ($i % 41 -eq 0) { $null } else { ($i % 97) / 7.0 }); DetailJson = $(if ($i % 53 -eq 0) { 'not json {' } else { ConvertTo-Json -Compress -InputObject $inner })
                ExemptionId = $(if ($i % 5 -eq 0) { 100 + $i % 3 } else { $null }); ExemptedUntil = $(if ($i % 10 -eq 0) { '2027-01-0' + (1 + $i % 9) + 'T00:00:00' } else { '' })
                RaReport = 1 + ($i % 3); RaBucket = '1/1'; RaSeq = $i; RaDedup = ('{0:X32}' -f $i); RaSort = ($i % 97) / 7.0; RaInView = ($i % 4 -ne 0); RaTraceSuffixed = ($i % 6 -eq 0)
                RaTraceHash = ('{0:X32}' -f ($i * 7)); RaTraceKey = 'k' + $i; RaFindingKey = 'fk' + $i; RaAssetId = 'aid-' + ($i % 211); RaAssetTier = ($i % 4)
            })))
        }
        $script:Det = $det.ToArray()
        $sum = New-Object System.Collections.Generic.List[string]; $ast = New-Object System.Collections.Generic.List[string]; $stg = New-Object System.Collections.Generic.List[string]
        for ($i = 1; $i -le 400; $i++) {
            $sum.Add((ConvertTo-Json -Compress -InputObject ([ordered]@{ RowNo = $i; SecurityDomain = 'Endpoint'; Category = $str[$i % $str.Count]; ConfigurationName = 'cfg ' + $i; ConfigurationId = 'CVE-2024-' + $i
                SecuritySeverity = 'High'; CriticalityTier = ($i % 4); RiskScoreTotal = ($i / 3.0); RatingRank = $(if ($i % 7 -eq 0) { $null } else { $i % 5 }); ImpactedAssetCount = ($i % 9); ImpactedAssetsList = ('a' * ($i % 300))
                RaReport = 2; RaBucket = '1/1'; RaDedup = ''; RaSort = ($i / 3.0); RaInView = $true; RaTraceHash = ('{0:X32}' -f $i); RaTraceKey = ''; RaTraceSuffixed = $false
                RaTrendSeverity = 'High'; RaTrendTier = '1'; RaTrendDomain = 'Endpoint'; RaTrendScore = ($i / 3.0); RaExempt = ($i % 8 -eq 0); RaTrendAssetIds = '["x","y"]'; RowJson = ('{"r":' + $i + '}') })))
            $ast.Add((ConvertTo-Json -Compress -InputObject ([ordered]@{ RowNo = $i; Ordinal = 1; AssetName = 'host ' + $str[$i % $str.Count]; AssetId = 'id-' + $i })))
            $stg.Add((ConvertTo-Json -Compress -InputObject ([ordered]@{ RaReport = 3; RaBucket = ('{0}/4' -f (1 + $i % 4)); RaSeq = $i; GroupHash = ('{0:X32}' -f ($i % 50)); RowJson = ('{"g":"' + $str[$i % $str.Count] + '"}') })))
        }
        $script:Sum = $sum.ToArray(); $script:Ast = $ast.ToArray(); $script:Stg = $stg.ToArray()
        $cif = New-Object System.Collections.Generic.List[string]
        for ($i = 1; $i -le 500; $i++) {
            $cif.Add((ConvertTo-Json -Compress -Depth 14 -InputObject ([ordered]@{ CiId = $(if ($i % 3 -eq 0) { 'ci-' + $i } else { '' }); AssetId = 'aid-' + $i; FindingKey = 'CVE-2025-' + $i; FindingType = 'cve'; Title = $str[$i % $str.Count]
                Severity = 'high'; Tier = ($i % 4); RiskScore = ($i / 7.0); WeightedRiskScore = ($i / 9.0); RiskRating = 'high'; SecurityDomain = 'Endpoint'; DetectedBy = 'r1; r2'; RiskFactors = 'f1;f2'; ExemptionId = $null
                CollectionTime = '2026-11-23T03:00:00.000Z'; DocJson = ('{"si_category":"' + @('OS', 'SQL', '')[$i % 3] + '","i":' + $i + '}'); Component = @('OS', '', $null)[$i % 3]; SubCi = 'sub'; PatchCycle = 'monthly'; CvePublished = '2025-01-02T00:00:00Z' })))
        }
        $script:Cif = $cif.ToArray()

        function script:New-Collection([string]$At) {
            [int](& $script:Inv "INSERT sidata.Collection (CollectionTime, Kind, Status, [Rows]) VALUES (@t, N'Detailed', N'Complete', @n); SELECT CONVERT(int, SCOPE_IDENTITY());" @{ t = $At; n = $script:N } 'scalar')
        }
        function script:Compare-Rows($A, $B, [string[]]$Skip) {
            $diff = New-Object System.Collections.Generic.List[string]
            if ($A.Count -ne $B.Count) { $diff.Add(('row count {0} vs {1}' -f $A.Count, $B.Count)); return , $diff.ToArray() }
            if ($A.Count -eq 0) { return , $diff.ToArray() }
            $cols = @($A[0].Keys | Where-Object { $_ -notin $Skip })
            for ($i = 0; $i -lt $A.Count; $i++) {
                foreach ($c in $cols) {
                    $x = $A[$i][$c]; $y = $B[$i][$c]
                    $same = if ($null -eq $x -or $null -eq $y) { $null -eq $x -and $null -eq $y }
                            elseif ($x -is [string]) { [string]::Equals($x, [string]$y, [StringComparison]::Ordinal) }
                            elseif ($x -is [double]) { [BitConverter]::DoubleToInt64Bits([double]$x) -eq [BitConverter]::DoubleToInt64Bits([double]$y) }
                            elseif ($x -is [byte[]]) { [Convert]::ToBase64String($x) -eq [Convert]::ToBase64String($y) }
                            # a binary value read through $( ) arrives as its bytes (Object[]): compared byte by byte
                            elseif ($x -is [array]) { (@($x) -join ',') -ceq (@($y) -join ',') }
                            else { $x -eq $y }
                    if (-not $same) { $sx = if ($x -is [byte[]]) { 'bytes ' + [BitConverter]::ToString($x) } else { '[' + [string]$x + '] ' + $(if ($null -ne $x) { $x.GetType().Name }) }; $sy = if ($y -is [byte[]]) { 'bytes ' + [BitConverter]::ToString($y) } else { '[' + [string]$y + '] ' + $(if ($null -ne $y) { $y.GetType().Name }) }; $diff.Add(('row {0} column {1}: {2} / {3}' -f $i, $c, $sx, $sy)) }
                }
            }
            , $diff.ToArray()
        }
        function script:Show-Diff($d) { if ($d.Count) { Write-Host ("DIFFERENCES ({0}):`n{1}" -f $d.Count, (($d | Select-Object -First 30) -join "`n")) } }
    }
    AfterAll {
        if (-not $script:LocalSql -or -not $script:Master) { return }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        [void](& $script:Master "ALTER DATABASE [$script:Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:Db]" @{} 'nonquery')
    }

    It 'Risk Analysis findings, plain and typed at insert: every column of every row the same, in many measured batches' -Skip:(-not $script:LocalSql) {
        foreach ($typed in @($null, $script:AllOn)) {
            $a = New-Collection ('2026-11-23T0{0}:00:00' -f $(if ($typed) { 3 } else { 1 })); $b = New-Collection ('2026-11-23T0{0}:00:00' -f $(if ($typed) { 4 } else { 2 }))
            $sql = Get-RAStreamInsertFindingSql -Typed $typed
            $ca = [ref][long]60000; $cb = [ref][long]60000
            Write-SIDataJsonRows -Invoke $script:Inv -Sql $sql -Items $script:Det -Params @{ CollectionId = [string]$a } -ChunkChars $ca -What 'json' | Should -Be $script:N
            Write-SIDataLoadRows -Invoke $script:Bulk -Sql $sql -Items $script:Det -Params @{ CollectionId = [string]$b } -ChunkChars $cb -What 'bulk' -Mode on | Should -Be $script:N
            $q = 'SELECT * FROM sidata.Finding WHERE CollectionId = @c ORDER BY FindingId'
            $fa = Get-Rows $q @{ c = $a }; $fb = Get-Rows $q @{ c = $b }
            $d = Compare-Rows $fa $fb @('FindingId', 'CollectionId'); Show-Diff $d
            $d.Count | Should -Be 0
            Write-Host ('BULK-SAME findings (typed {0}): {1} rows x {2} columns, 0 differences' -f [bool]$typed, $fa.Count, (@($fa[0].Keys).Count - 2))
            # not blind: filled values, a forced difference is found
            @($fb | Where-Object { $null -ne $_['ExemptedUntil'] }).Count | Should -BeGreaterThan 10
            if ($typed) { @($fb | Where-Object { $_['TypedOnInsert'] -eq 63 }).Count | Should -Be $script:N }
            $fb[5]['AssetName'] = 'changed'; (Compare-Rows $fa $fb @('FindingId', 'CollectionId')).Count | Should -Be 1
        }
    }
    It 'Summary rows, their impacted assets and the Summary stage: the same rows' -Skip:(-not $script:LocalSql) {
        foreach ($case in @(
                @{ Sql = (Get-RAStreamInsertSummaryRowSql); Items = $script:Sum; Read = 'SELECT * FROM sidata.SummaryRow WHERE CollectionTime = @t ORDER BY RowNo'; Skip = @('CollectionTime') },
                @{ Sql = (Get-SIDataSummaryInsertAssetSql); Items = $script:Ast; Read = 'SELECT * FROM sidata.SummaryAsset WHERE CollectionTime = @t ORDER BY RowNo, Ordinal'; Skip = @('CollectionTime') })) {
            $p1 = @{ CollectionTime = '2026-11-23T05:00:00.000' }; $p2 = @{ CollectionTime = '2026-11-23T06:00:00.000' }
            $ca = [ref][long]50000; $cb = [ref][long]50000
            Write-SIDataJsonRows -Invoke $script:Inv -Sql $case.Sql -Items $case.Items -Params $p1 -ChunkChars $ca | Should -Be $case.Items.Count
            Write-SIDataLoadRows -Invoke $script:Bulk -Sql $case.Sql -Items $case.Items -Params $p2 -ChunkChars $cb -Mode on | Should -Be $case.Items.Count
            $d = Compare-Rows (Get-Rows $case.Read @{ t = $p1.CollectionTime }) (Get-Rows $case.Read @{ t = $p2.CollectionTime }) $case.Skip; Show-Diff $d
            $d.Count | Should -Be 0
        }
        $sq = Get-RAStreamInsertStageSql
        Write-SIDataJsonRows -Invoke $script:Inv -Sql $sq -Items $script:Stg -Params @{ RunKey = 'json' } | Should -Be $script:Stg.Count
        Write-SIDataLoadRows -Invoke $script:Bulk -Sql $sq -Items $script:Stg -Params @{ RunKey = 'bulk' } -Mode on | Should -Be $script:Stg.Count
        $rq = 'SELECT RaReport, RaBucket, RaSeq, GroupHash, RowJson FROM sidata.RaStage WHERE RunKey = @k ORDER BY RaSeq'
        $d = Compare-Rows (Get-Rows $rq @{ k = 'json' }) (Get-Rows $rq @{ k = 'bulk' }) @(); Show-Diff $d
        $d.Count | Should -Be 0
    }
    It 'the findings per CI staged for the swap and the data out summary stage: the same rows' -Skip:(-not $script:LocalSql) {
        $cs = Get-SIDataWriteCiFindingSql -Stage -SubCi -Category
        [void](& $script:Inv 'DELETE FROM sidata.CiFindingStage;' @{} 'nonquery')
        Write-SIDataJsonRows -Invoke $script:Inv -Sql $cs -Items $script:Cif | Should -Be $script:Cif.Count
        # the stage's own order is not part of what it holds (its writer reads the chunk into #x first, in no order): compared by key
        $q = 'SELECT * FROM sidata.CiFindingStage ORDER BY FindingKey, AssetId'
        $ja = Get-Rows $q @{}
        [void](& $script:Inv 'DELETE FROM sidata.CiFindingStage;' @{} 'nonquery')
        Write-SIDataLoadRows -Invoke $script:Bulk -Sql $cs -Items $script:Cif -Mode on | Should -Be $script:Cif.Count
        $jb = Get-Rows $q @{}
        $d = Compare-Rows $ja $jb @('StageId'); Show-Diff $d
        $d.Count | Should -Be 0
        @($jb | Where-Object { $null -ne $_['Category'] }).Count | Should -BeGreaterThan 100
        # data out: its own statement, parameter @rows
        $rows = @(for ($i = 1; $i -le 300; $i++) { ConvertTo-Json -Compress -Depth 6 -InputObject ([ordered]@{ q = $i; g = 'g' + ($i % 20); c = 'ci-' + $i; n = $(if ($i % 9 -eq 0) { '' } else { 'name ' + $i }); s = ($i / 3.0); w = $null; a = $(if ($i % 4 -eq 0) { [ordered]@{ si_title = 'T ' + $i; si_tier = 1 } } else { $null }) }) })
        $s1 = [guid]::NewGuid().ToString(); $s2 = [guid]::NewGuid().ToString()
        [void](& $script:Inv $script:DataOutAdd @{ StageId = $s1; rows = ('[' + ($rows -join ',') + ']') } 'nonquery')
        Write-SIDataLoadRows -Invoke $script:Bulk -Sql ($script:DataOutAdd + "SELECT @@ROWCOUNT;`n") -Items ([string[]]$rows) -Params @{ StageId = $s2 } -JsonParam rows -Mode on -Fallback { throw 'not the bulk way' } | Should -Be 300
        $dq = 'SELECT Seq, GroupKey, CiKey, Name, Score, WScore, AttrJson FROM sidata.DataOutSummaryStage WHERE StageId = @s ORDER BY Seq'
        $d = Compare-Rows (Get-Rows $dq @{ s = $s1 }) (Get-Rows $dq @{ s = $s2 }) @(); Show-Diff $d
        $d.Count | Should -Be 0
    }
    It 'a batch read back different once is redone (same rows); different every time fails the load and keeps nothing of itself' -Skip:(-not $script:LocalSql) {
        $sql = Get-RAStreamInsertFindingSql
        $q = 'SELECT * FROM sidata.Finding WHERE CollectionId = @c ORDER BY FindingId'
        $ref = New-Collection '2026-11-23T12:00:00'
        $null = Write-SIDataJsonRows -Invoke $script:Inv -Sql $sql -Items $script:Det -Params @{ CollectionId = [string]$ref }
        $spoil = { param($cn, $tx, $batch, $attempt) if ($batch -eq 2 -and $attempt -eq 0) { $c = $cn.CreateCommand(); $c.Transaction = $tx; $c.CommandText = "UPDATE #SIBulkRows SET J = REPLACE(J, N'host', N'HOST') WHERE Seq = 1;"; [void]$c.ExecuteNonQuery() } }
        $one = New-Collection '2026-11-23T13:00:00'
        $ch = [ref][long]50000
        Write-SIDataBulkRows -Invoke $script:Bulk -Sql $sql -Items $script:Det -Params @{ CollectionId = [string]$one } -ChunkChars $ch -TestHook $spoil | Should -Be $script:N
        $d = Compare-Rows (Get-Rows $q @{ c = $ref }) (Get-Rows $q @{ c = $one }) @('FindingId', 'CollectionId'); Show-Diff $d
        $d.Count | Should -Be 0
        # every attempt of batch 2 differs: the load throws; batch 1 is in whole, nothing of batch 2 or later
        $always = { param($cn, $tx, $batch, $attempt) if ($batch -eq 2) { $c = $cn.CreateCommand(); $c.Transaction = $tx; $c.CommandText = 'DELETE FROM #SIBulkRows WHERE Seq = 1;'; [void]$c.ExecuteNonQuery() } }
        $two = New-Collection '2026-11-23T14:00:00'
        $ch2 = [ref][long]50000
        { Write-SIDataBulkRows -Invoke $script:Bulk -Sql $sql -Items $script:Det -Params @{ CollectionId = [string]$two } -ChunkChars $ch2 -TestHook $always } | Should -Throw '*did not load as sent twice*'
        $kept = [long](& $script:Inv 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = @c' @{ c = $two } 'scalar')
        $kept | Should -BeGreaterThan 0
        $kept | Should -BeLessThan $script:N
        # what is kept is the first batch, whole and in order: exactly the first rows sent
        [long](& $script:Inv 'SELECT MAX(RaSeq) FROM sidata.Finding WHERE CollectionId = @c' @{ c = $two } 'scalar') | Should -Be $kept
    }
    It 'a commit that did not answer but was stored (the connection dropped after it) is never loaded again: exactly one copy' -Skip:(-not $script:LocalSql) {
        $sql = Get-RAStreamInsertFindingSql
        $q = 'SELECT * FROM sidata.Finding WHERE CollectionId = @c ORDER BY FindingId'
        $ref = New-Collection '2026-11-23T16:00:00'
        $null = Write-SIDataJsonRows -Invoke $script:Inv -Sql $sql -Items $script:Det -Params @{ CollectionId = [string]$ref }
        $c = New-Collection '2026-11-23T17:00:00'
        # batch 2's commit goes through, then the connection "drops" (a transport-level error, as 10054)
        $drop = { param($batch, $attempt) if ($batch -eq 2 -and $attempt -eq 0) { throw 'A transport-level error has occurred when receiving results from the server. (provider: TCP Provider, error: 0 - An existing connection was forcibly closed by the remote host.)' } }
        $ch = [ref][long]50000
        Write-SIDataBulkRows -Invoke $script:Bulk -Sql $sql -Items $script:Det -Params @{ CollectionId = [string]$c } -ChunkChars $ch -CommitHook $drop -Waits @(0, 0, 0) | Should -Be $script:N
        [long](& $script:Inv 'SELECT COUNT_BIG(*) FROM sidata.Finding WHERE CollectionId = @c' @{ c = $c } 'scalar') | Should -Be $script:N -Because 'batch 2 is stored once, not twice'
        [long](& $script:Inv 'SELECT COUNT_BIG(*) - COUNT_BIG(DISTINCT RaSeq) FROM sidata.Finding WHERE CollectionId = @c' @{ c = $c } 'scalar') | Should -Be 0
        $d = Compare-Rows (Get-Rows $q @{ c = $ref }) (Get-Rows $q @{ c = $c }) @('FindingId', 'CollectionId'); Show-Diff $d
        $d.Count | Should -Be 0
        # the batch keys are taken away after use
        [long](& $script:Inv "SELECT COUNT_BIG(*) FROM sidata.ViewState WHERE Name LIKE N'bulk:%'" @{} 'scalar') | Should -Be 0
    }
    It 'each command of a batch takes the time limit it is given; the seam''s own when none is given' -Skip:(-not $script:LocalSql) {
        $b = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\_shared\data-sql\SI-DataBulkLoad.ps1'))
        $b | Should -Match 'Invoke-SIDataBulkBatch -Connection \$cn [^\r\n]*-TimeoutSec \$TimeoutSec'
        $b | Should -Match '\$TimeoutSec = \[int\]\$ci\.CommandTimeout'
    }
    It 'shadow: every batch checked through the bulk copy and rolled back; the JSON way serves' -Skip:(-not $script:LocalSql) {
        $sql = Get-SIDataSummaryInsertAssetSql
        $p = @{ CollectionTime = '2026-11-23T09:00:00.000' }
        $log = New-Object System.Collections.Generic.List[string]
        $n = Write-SIDataLoadRows -Invoke $script:Bulk -Sql $sql -Items $script:Ast -Params $p -Mode shadow -Log { param($l, $m) $log.Add("$l $m") }.GetNewClosure()
        $n | Should -Be $script:Ast.Count
        [long](& $script:Inv 'SELECT COUNT_BIG(*) FROM sidata.SummaryAsset WHERE CollectionTime = @t' @{ t = $p.CollectionTime } 'scalar') | Should -Be $script:Ast.Count -Because 'written once (the JSON way), never twice'
        @($log | Where-Object { $_ -match '^WARN' }).Count | Should -Be 0
        # off: never the bulk copy
        $p3 = @{ CollectionTime = '2026-11-23T10:00:00.000' }
        Write-SIDataLoadRows -Invoke $script:Bulk -Sql $sql -Items $script:Ast -Params $p3 -Mode off -Fallback { 'earlier' } | Should -Be 'earlier'
    }
    It 'the batch size follows the measured time (a slow target shrinks it, never below the floor)' -Skip:(-not $script:LocalSql) {
        $ch = [ref][long]4000000
        $c = New-Collection '2026-11-23T15:00:00'
        $null = Write-SIDataBulkRows -Invoke $script:Bulk -Sql (Get-RAStreamInsertFindingSql) -Items $script:Det -Params @{ CollectionId = [string]$c } -ChunkChars $ch -TargetMs 1
        $ch.Value | Should -BeLessThan 4000000
        $ch.Value | Should -BeGreaterOrEqual 50000
    }
}
