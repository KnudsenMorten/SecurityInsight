#Requires -Version 7.0
<#
    THE RISK SCORE'S PARTS AS COLUMNS (owner 2026-10-28: "it should be possible to see the Risk Score calculations as columns"
    / "people ask about the risk score calculation"). Risk Analysis writes every part of a finding's score on its row; the
    data sync copies them into typed columns of sidata.Finding (engine\_shared\data-sql\SI-DataSql.ps1: Get-SIDataRiskPartsSql,
    the derive, Invoke-SIDataRiskPartsBackfill) and of sidata.SummaryRow (Get-SIDataSummaryRiskPartsSql), so the Detailed and
    Summary rows show, sort and filter them without reading the row's JSON.

    What these tests keep true:
      * the fill reads each row's JSON ONCE (one OPENJSON per row), never JSON_VALUE per field, through the clustered key;
      * the stored values are EXACTLY what the explained score read from the row before (the JSON_VALUE texts of the
        explain grid, worked out with the web app's own rule -- RiskExplanation.SideOf: a number is the text trimmed and read
        invariant, a recorded base lists the factors with their points, an older row's base is its side minus its points),
        on rows of every shape (local SQL Server on the test VM);
      * earlier collections are filled NEWEST FIRST within a time budget, go on where a stopped fill stopped, and are
        stamped only after their last range; the fill never throws; a database without the columns writes nothing;
      * a new collection gets the parts with its derive and is stamped;
      * the Summary rows get them from the whole row, else worked out from their own columns.
    Offline (a fake database) plus a block on the local SQL Server when .\SQLEXPRESS is running (the test VM).
#>

BeforeDiscovery {
    try { $LocalSqlD = (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction Stop).Status -eq 'Running' -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $LocalSqlD = $false }
}

BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    . (Join-Path $script:Root 'engine\_shared\SI-SchemaGate.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataModel.ps1')
    . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
    $script:Schema = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'sql\si-data-schema.sql')
    $script:Fill = Get-SIDataRiskPartsSql
    try { $script:LocalSql = (Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction Stop).Status -eq 'Running' -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }

    # a fake database: -Answers maps a regex of the statement to its answer (a value or a block over the parameters)
    function script:New-FakeDb {
        param([System.Collections.Specialized.OrderedDictionary]$Answers = ([ordered]@{}))
        $calls = New-Object System.Collections.Generic.List[object]
        $invoke = {
            param($sql, $p, $mode)
            $calls.Add([pscustomobject]@{ Sql = [string]$sql; P = $p; Mode = $mode })
            foreach ($k in $Answers.Keys) { if ([string]$sql -match $k) { $a = $Answers[$k]; if ($a -is [scriptblock]) { return (& $a $p) }; return $a } }
            if ($mode -eq 'reader') { return @() }
            return 0
        }.GetNewClosure()
        [pscustomobject]@{ Calls = $calls; Invoke = $invoke }
    }

    # THE WEB APP'S RULE (Pages\Collection\RiskExplain.cs, RiskExplanation.SideOf / Num), as the reference the stored values
    # must equal: a number = the text trimmed, read invariant with NumberStyles.Float, finite; empty = none
    function script:Num([object]$v) {
        if ($null -eq $v -or $v -is [DBNull]) { return $null }
        $s = ([string]$v).Trim()
        $d = 0.0
        if ([double]::TryParse($s, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d) -and [double]::IsFinite($d)) { return $d }
        $null
    }
    function script:Text([object]$v) { if ($null -eq $v -or $v -is [DBNull] -or ([string]$v).Length -eq 0) { return $null }; [string]$v }
    # one side as the explained score worked it out from the row's texts: @{ Base; Derived; Factors (the list it reads); Points; Side }
    function script:Expect-Side($baseText, $impacts, $names, $sum, $side) {
        $sc = Num $side; $b = Num $baseText
        if ($null -ne $b) { return @{ Base = $b; Derived = $false; Factors = (Text $impacts); Points = (Num $sum); Side = $sc } }
        $pts = Num $sum
        $base = if ($null -ne $sc) { $sc - $(if ($null -ne $pts) { $pts } else { 0.0 }) } else { $null }
        @{ Base = $base; Derived = $true; Factors = (Text $names); Points = $pts; Side = $sc }
    }
}

Describe 'the fill reads each finding once' {
    It 'parses the row once (OPENJSON ... WITH), never one JSON_VALUE per field, and reads every part Risk Analysis writes' {
        ([regex]::Matches($script:Fill, 'OPENJSON\(CASE WHEN ISJSON\(f\.DetailJson\) = 1 THEN f\.DetailJson END\) WITH')).Count | Should -Be 1
        $script:Fill | Should -Not -Match 'JSON_VALUE'
        foreach ($f in 'RiskConsequenceBase', 'RiskConsequenceScore', 'RiskFactor_Consequence', 'RiskFactor_Consequence_Impacts', 'RiskFactor_Consequence_Detailed',
                       'RiskProbabilityBase', 'RiskProbabilityScore', 'RiskFactor_Probability', 'RiskFactor_Probability_Impacts', 'RiskFactor_Probability_Detailed',
                       'RiskScore_Weight_Factor', 'RiskScore_Weight_Detailed') {
            $script:Fill | Should -Match ("N'\`$\.{0}'" -f [regex]::Escape($f))
        }
        foreach ($c in 'RiskAssetBase', 'RiskAssetSide', 'RiskAssetPoints', 'RiskAssetFactors', 'RiskAssetDerived', 'RiskVulnBase', 'RiskVulnSide', 'RiskVulnPoints',
                       'RiskVulnFactors', 'RiskVulnDerived', 'RiskWeightPct', 'RiskWeightBy') {
            $script:Fill | Should -Match ("\b{0}\s+=" -f $c)
            $script:Schema | Should -Match ("COL_LENGTH\('sidata\.Finding', '{0}'\) IS NULL ALTER TABLE sidata\.Finding ADD {0} " -f $c)
        }
    }
    It 'reads a range through the clustered key, and only the backfill''s statement records how far it came' {
        $script:Fill | Should -Match 'WHERE f\.CollectionId = CONVERT\(int, @CollectionId\) AND f\.FindingId > CONVERT\(bigint, @After\) AND f\.FindingId <= CONVERT\(bigint, @Upto\);'
        $script:Fill | Should -Not -Match 'RiskPartsUpto'
        Get-SIDataRiskPartsSql -Progress | Should -Match 'UPDATE sidata\.Collection SET RiskPartsUpto = @Upto WHERE CollectionId = @CollectionId;'
    }
    It 'indexes the two sides only (the views sort on them), additively' {
        $script:Schema | Should -Match 'CREATE INDEX IX_Finding_AssetSidePage ON sidata\.Finding \(CollectionId, RiskAssetSide DESC\)'
        $script:Schema | Should -Match 'CREATE INDEX IX_Finding_VulnSidePage ON sidata\.Finding \(CollectionId, RiskVulnSide DESC\)'
        $script:Schema | Should -Not -Match 'ON sidata\.Finding \(CollectionId, RiskAssetBase'
        $script:Schema | Should -Not -Match 'ON sidata\.Finding \(CollectionId, RiskVulnBase'
        $script:Schema | Should -Match "COL_LENGTH\('sidata\.Collection', 'RiskPartsAt'\) IS NULL ALTER TABLE sidata\.Collection ADD RiskPartsAt DATETIME2\(0\) NULL;"
        $script:Schema | Should -Match "COL_LENGTH\('sidata\.Collection', 'RiskPartsUpto'\) IS NULL ALTER TABLE sidata\.Collection ADD RiskPartsUpto BIGINT NULL;"
    }
}

Describe 'earlier collections: newest first, within the budget, stamped after the last range' {
    It 'writes nothing on a database without the columns, and says so in plain words' {
        $db = New-FakeDb ([ordered]@{ "COL_LENGTH\('sidata\.Finding', 'RiskAssetDerived'\)" = 0 })
        $script:Lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataRiskPartsBackfill -Invoke $db.Invoke -Log { param($l, $m) $script:Lines.Add("$l $m") }
        $r.Ready | Should -BeFalse
        @($db.Calls | Where-Object { $_.Sql -match 'UPDATE' }).Count | Should -Be 0
        ($script:Lines -join "`n") | Should -Match 'the next update adds them'
        ($script:Lines -join "`n") | Should -Not -Match '#\d{3}'
    }
    It 'fills the newest collection first, goes on from where a stopped fill stopped, and stamps each after its last range' {
        $pending = @(
            [ordered]@{ CollectionId = 9; Upto = 150L; Lo = 101L; Hi = 300L },   # the newest: a fill stopped at 150
            [ordered]@{ CollectionId = 4; Upto = [DBNull]::Value; Lo = 1L; Hi = 40L }
        )
        $db = New-FakeDb ([ordered]@{
            "COL_LENGTH\('sidata\.Finding', 'RiskAssetDerived'\)" = 1
            'FROM sidata\.Collection AS c\s+WHERE c\.Status' = $pending
            'UPDATE f SET' = { param($p) [long]$p.Upto - [long]$p.After }
            'SET RiskPartsAt' = 1
        })
        $r = Invoke-SIDataRiskPartsBackfill -Invoke $db.Invoke -Log { param($l, $m) }
        $r.Ready | Should -BeTrue
        $r.Collections | Should -Be 2
        $r.Pending | Should -Be 0
        $r.Rows | Should -Be (150 + 40)
        $seq = @($db.Calls | Where-Object { $_.Sql -match 'UPDATE f SET|SET RiskPartsAt' } | ForEach-Object { '{0}:{1}' -f $(if ($_.Sql -match 'RiskPartsAt') { 'stamp' } else { 'fill' }), $_.P.CollectionId })
        $seq[0] | Should -Be 'fill:9'
        $seq.IndexOf('stamp:9') | Should -BeGreaterThan 0
        $seq.IndexOf('stamp:9') | Should -BeLessThan $seq.IndexOf('fill:4')
        $seq[-1] | Should -Be 'stamp:4'
        # collection 9 went on from 150, never from its first row
        $first = @($db.Calls | Where-Object { $_.Sql -match 'UPDATE f SET' -and $_.P.CollectionId -eq 9 })[0]
        [long]$first.P.After | Should -Be 150
        # every range records how far it came
        @($db.Calls | Where-Object { $_.Sql -match 'UPDATE f SET' } | Where-Object { $_.Sql -notmatch 'RiskPartsUpto = @Upto' }).Count | Should -Be 0
        @($db.Calls | Where-Object { $_.Sql -match 'SET RiskPartsAt' -and $_.P.CollectionId -eq 9 })[0].P.Upto | Should -Be 300
    }
    It 'stops at its budget: what it did not finish is not stamped and is said to follow' {
        $pending = @([ordered]@{ CollectionId = 9; Upto = [DBNull]::Value; Lo = 1L; Hi = 1000000L })
        $db = New-FakeDb ([ordered]@{
            "COL_LENGTH\('sidata\.Finding', 'RiskAssetDerived'\)" = 1
            'FROM sidata\.Collection AS c\s+WHERE c\.Status' = $pending
            'UPDATE f SET' = { param($p) Start-Sleep -Milliseconds 600; [long]$p.Upto - [long]$p.After }
        })
        $script:Lines = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataRiskPartsBackfill -Invoke $db.Invoke -BudgetSeconds 1 -Log { param($l, $m) $script:Lines.Add($m) }
        $r.Collections | Should -Be 0
        $r.Pending | Should -Be 1
        @($db.Calls | Where-Object { $_.Sql -match 'SET RiskPartsAt' }).Count | Should -Be 0
        ($script:Lines -join "`n") | Should -Match 'follow on the next run'
    }
    It 'never throws: a failing statement is said and the run goes on' {
        $db = New-FakeDb ([ordered]@{
            "COL_LENGTH\('sidata\.Finding', 'RiskAssetDerived'\)" = 1
            'FROM sidata\.Collection AS c\s+WHERE c\.Status' = { throw 'the database is full' }
        })
        $script:Lines = New-Object System.Collections.Generic.List[string]
        { $script:R = Invoke-SIDataRiskPartsBackfill -Invoke $db.Invoke -Log { param($l, $m) $script:Lines.Add("$l $m") } } | Should -Not -Throw
        $script:R.Error | Should -Match 'the database is full'
        ($script:Lines -join "`n") | Should -Match '^WARN score parts'
    }
    It 'a dry run writes nothing' {
        $db = New-FakeDb ([ordered]@{
            "COL_LENGTH\('sidata\.Finding', 'RiskAssetDerived'\)" = 1
            'FROM sidata\.Collection AS c\s+WHERE c\.Status' = @([ordered]@{ CollectionId = 1; Upto = [DBNull]::Value; Lo = 1L; Hi = 5L })
        })
        $null = Invoke-SIDataRiskPartsBackfill -Invoke $db.Invoke -DryRun -Log { param($l, $m) }
        @($db.Calls | Where-Object { $_.Sql -match 'UPDATE' }).Count | Should -Be 0
    }
    It 'the data sync runs it after the derive, within 20 minutes a run' {
        $src = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'engine\pro-data\_shared\SI-DataSync.ps1')
        $src | Should -Match 'Invoke-SIDataRiskPartsBackfill -Invoke \$Invoke -DryRun:\$DryRun -BudgetSeconds 1200'
        $src.IndexOf('Invoke-SIDataRiskPartsBackfill') | Should -BeGreaterThan $src.IndexOf("& `$phase 'views (derive)'")
    }
}

Describe 'a new collection gets the parts with its derive' {
    It 'fills every range of the collection and then stamps it' {
        $db = New-FakeDb ([ordered]@{
            'MIN\(FindingId\) AS Lo' = @([ordered]@{ Lo = 1L; Hi = 10L })
            "COL_LENGTH\('sidata\.Finding', 'RiskAssetDerived'\)" = 1
            'UPDATE f SET\s+RiskAssetSide' = { param($p) [long]$p.Upto - [long]$p.After }
            'SET RiskPartsAt' = 1
        })
        $null = Invoke-SIDataDeriveCollection -Invoke $db.Invoke -CollectionId 3 -Log { param($l, $m) }
        $fills = @($db.Calls | Where-Object { $_.Sql -match 'UPDATE f SET\s+RiskAssetSide' })
        $fills.Count | Should -BeGreaterThan 0
        ($fills | ForEach-Object { [long]$_.P.Upto - [long]$_.P.After } | Measure-Object -Sum).Sum | Should -Be 10
        $stamp = @($db.Calls | Where-Object { $_.Sql -match 'SET RiskPartsAt' })
        $stamp.Count | Should -Be 1
        $stamp[0].P.Upto | Should -Be 10
        $db.Calls.IndexOf($stamp[0]) | Should -BeGreaterThan $db.Calls.IndexOf($fills[-1])
    }
    It 'a database without the columns derives as before' {
        $db = New-FakeDb ([ordered]@{ 'MIN\(FindingId\) AS Lo' = @([ordered]@{ Lo = 1L; Hi = 10L }) })
        $null = Invoke-SIDataDeriveCollection -Invoke $db.Invoke -CollectionId 3 -Log { param($l, $m) }
        @($db.Calls | Where-Object { $_.Sql -match 'UPDATE f SET\s+RiskAssetSide|SET RiskPartsAt' }).Count | Should -Be 0
    }
}

Describe 'on a local SQL Server: exactly what the explained score read from each row' {
    BeforeAll {
        if (-not $script:LocalSql) { return }
        $script:Db = 'si_parts_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = [System.Data.SqlClient.SqlConnection]::new('Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30')
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$script:Db]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $script:Cn = [System.Data.SqlClient.SqlConnection]::new("Server=.\SQLEXPRESS;Database=$script:Db;Integrated Security=SSPI;Connection Timeout=30;Pooling=false")
        $script:Cn.Open()
        function script:Sql([string]$Text, [hashtable]$P = @{}, [string]$Mode = 'nonquery') {
            $c = $script:Cn.CreateCommand(); $c.CommandText = $Text; $c.CommandTimeout = 600
            foreach ($k in $P.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $P[$k]) }
            if ($Mode -eq 'scalar') { return $c.ExecuteScalar() }
            if ($Mode -eq 'reader') {
                $rd = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                try { while ($rd.Read()) { $h = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $rows.Add($h) } } finally { $rd.Dispose() }
                return , $rows.ToArray()
            }
            [void]$c.ExecuteNonQuery()
        }
        # the seam as the data sync's own (New-SIDataSqlInvoke): a reader answers its rows as ONE list
        $script:Invoke = { param($sql, $p, $mode) Sql $sql $p $mode }
        # the schema twice: additive and idempotent
        Sql $script:Schema; Sql $script:Schema
        $script:Cid = [int](Sql "INSERT sidata.Collection (CollectionTime, Kind, Status) VALUES ('2026-10-28T09:00:00', 'Detailed', 'Complete'); SELECT CAST(SCOPE_IDENTITY() AS int)" -Mode scalar)
        # every shape a part can have: numbers as numbers and as texts (padded, with tabs and new lines), blanks, nulls, words,
        # lists and objects, signs and exponents; factor lists with empty entries, spaces, a name with '=', a point that is no number
        $num = @('4', '4.0', '17.25', '-2', '0', '"4"', '" 4 "', '"\t4\n"', '""', '"  "', 'null', '"abc"', '"1,000"', '"1e3"', '"+3"', '".5"', '[1]', '{"a":1}', '"NaN"', '"Infinity"', 'true')
        $list = @('"InternetExposed=4;HighMachineRisk=3"', '"A=3; ;B=4;"', '" RCE = 4 "', '"A=x;B"', '"Name=with=eq=2"', '""', '" "', 'null', '"OnlyName"', '[1,2]')
        $names = @('"InternetExposed;HighMachineRisk"', '""', 'null', '" A ; B "')
        $rows = New-Object System.Collections.Generic.List[string]
        $k = 0
        foreach ($b in @($num + '<absent>')) {
            foreach ($s in $num) {
                $k++
                $l1 = $list[$k % $list.Count]; $l2 = $list[($k + 3) % $list.Count]; $n1 = $names[$k % $names.Count]; $n2 = $names[($k + 1) % $names.Count]
                $p1 = $num[($k * 7) % $num.Count]; $p2 = $num[($k * 5) % $num.Count]; $w = $num[($k * 3) % $num.Count]
                $parts = New-Object System.Collections.Generic.List[string]
                if ($b -ne '<absent>') { $parts.Add('"RiskConsequenceBase":' + $b); $parts.Add('"RiskProbabilityBase":' + $num[($k * 11) % $num.Count]) }
                $parts.Add('"RiskConsequenceScore":' + $s); $parts.Add('"RiskProbabilityScore":' + $num[($k * 13) % $num.Count])
                $parts.Add('"RiskFactor_Consequence":' + $p1); $parts.Add('"RiskFactor_Probability":' + $p2)
                $parts.Add('"RiskFactor_Consequence_Impacts":' + $l1); $parts.Add('"RiskFactor_Probability_Impacts":' + $l2)
                $parts.Add('"RiskFactor_Consequence_Detailed":' + $n1); $parts.Add('"RiskFactor_Probability_Detailed":' + $n2)
                $parts.Add('"RiskScore_Weight_Factor":' + $w); $parts.Add('"RiskScore_Weight_Detailed":"cmdbCriticality=Critical; cmdbDataSensitivity=confidential"')
                $rows.Add('{' + ($parts -join ',') + '}')
            }
        }
        $rows.Add($null); $rows.Add('not json'); $rows.Add('{}'); $rows.Add('[1,2]')
        $dt = [System.Data.DataTable]::new()
        [void]$dt.Columns.Add('CollectionId', [int]); [void]$dt.Columns.Add('AssetKey', [string]); [void]$dt.Columns.Add('DetailJson', [string])
        $n = 0
        foreach ($j in $rows) { $n++; $r = $dt.NewRow(); $r.CollectionId = $script:Cid; $r.AssetKey = 'a{0}' -f ($n % 17); $r.DetailJson = if ($null -eq $j) { [DBNull]::Value } else { $j }; $dt.Rows.Add($r) }
        $bulk = [System.Data.SqlClient.SqlBulkCopy]::new($script:Cn); $bulk.DestinationTableName = 'sidata.Finding'
        foreach ($col in $dt.Columns) { [void]$bulk.ColumnMappings.Add($col.ColumnName, $col.ColumnName) }
        $bulk.WriteToServer($dt)
        $script:Rows = $rows.Count
    }
    AfterAll {
        if (-not $script:LocalSql) { return }
        if ($script:Cn) { $script:Cn.Dispose() }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = [System.Data.SqlClient.SqlConnection]::new('Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30')
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$script:Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:Db]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    It 'the backfill fills every row, stamps the collection, and every stored part equals the explained score''s reading of the row' -Skip:(-not $LocalSqlD) {
        $r = Invoke-SIDataRiskPartsBackfill -Invoke $script:Invoke -Log { param($l, $m) }
        $r.Error | Should -BeNullOrEmpty
        $r.Collections | Should -Be 1
        $r.Rows | Should -Be $script:Rows
        Sql 'SELECT COUNT(*) FROM sidata.Collection WHERE CollectionId = @c AND RiskPartsAt IS NOT NULL' @{ c = $script:Cid } 'scalar' | Should -Be 1
        # the explain grid's reading of each row (RiskExplainSql.Grid: one JSON_VALUE per part) beside what the fill stored
        $got = Sql @'
SELECT f.FindingId,
       JSON_VALUE(d.J, '$.RiskConsequenceBase') AS jcb, JSON_VALUE(d.J, '$.RiskFactor_Consequence_Impacts') AS jci,
       JSON_VALUE(d.J, '$.RiskConsequenceScore') AS jcs, JSON_VALUE(d.J, '$.RiskFactor_Consequence_Detailed') AS jcn,
       JSON_VALUE(d.J, '$.RiskFactor_Consequence') AS jcp,
       JSON_VALUE(d.J, '$.RiskProbabilityBase') AS jpb, JSON_VALUE(d.J, '$.RiskFactor_Probability_Impacts') AS jpi,
       JSON_VALUE(d.J, '$.RiskProbabilityScore') AS jps, JSON_VALUE(d.J, '$.RiskFactor_Probability_Detailed') AS jpn,
       JSON_VALUE(d.J, '$.RiskFactor_Probability') AS jpp,
       JSON_VALUE(d.J, '$.RiskScore_Weight_Factor') AS jw, JSON_VALUE(d.J, '$.RiskScore_Weight_Detailed') AS jwb,
       f.RiskAssetBase, f.RiskAssetDerived, f.RiskAssetFactors, f.RiskAssetPoints, f.RiskAssetSide,
       f.RiskVulnBase, f.RiskVulnDerived, f.RiskVulnFactors, f.RiskVulnPoints, f.RiskVulnSide, f.RiskWeightPct, f.RiskWeightBy
FROM sidata.Finding AS f CROSS APPLY (SELECT CASE WHEN ISJSON(f.DetailJson) = 1 THEN f.DetailJson END AS J) AS d WHERE f.CollectionId = @c ORDER BY f.FindingId
'@ @{ c = $script:Cid } 'reader'
        $got.Count | Should -Be $script:Rows
        $diff = New-Object System.Collections.Generic.List[string]
        $same = { param($a, $b) if ($null -eq $a) { return ($null -eq $b -or $b -is [DBNull]) }; if ($b -is [DBNull]) { return $false }; if ($a -is [double]) { return ([double]$b).Equals([double]$a) }; if ($a -is [bool]) { return [bool]$b -eq $a }; ([string]$b) -ceq ([string]$a) }
        $derived = 0; $recorded = 0
        foreach ($g in $got) {
            foreach ($side in @(
                @{ P = 'RiskAsset'; E = (Expect-Side $g.jcb $g.jci $g.jcn $g.jcp $g.jcs) },
                @{ P = 'RiskVuln'; E = (Expect-Side $g.jpb $g.jpi $g.jpn $g.jpp $g.jps) })) {
                $e = $side.E
                if ($e.Derived) { $derived++ } else { $recorded++ }
                foreach ($k in 'Base', 'Derived', 'Factors', 'Points', 'Side') {
                    if (-not (& $same $e[$k] $g[$side.P + $k]) -and $diff.Count -lt 15) { $diff.Add(('finding {0} {1}{2}: expected [{3}] stored [{4}]' -f $g.FindingId, $side.P, $k, $e[$k], $g[$side.P + $k])) }
                }
            }
            if (-not (& $same (Num $g.jw) $g.RiskWeightPct) -and $diff.Count -lt 15) { $diff.Add(('finding {0} weight: expected [{1}] stored [{2}]' -f $g.FindingId, (Num $g.jw), $g.RiskWeightPct)) }
            if (-not (& $same (Text $g.jwb) $g.RiskWeightBy) -and $diff.Count -lt 15) { $diff.Add(('finding {0} weight by: expected [{1}] stored [{2}]' -f $g.FindingId, $g.jwb, $g.RiskWeightBy)) }
        }
        ($diff -join "`n") | Should -BeNullOrEmpty
        $derived | Should -BeGreaterThan 20 -Because 'rows without a recorded base are worked out'
        $recorded | Should -BeGreaterThan 100 -Because 'rows with a recorded base list their factors with points'
        # a second run finds nothing left to do
        (Invoke-SIDataRiskPartsBackfill -Invoke $script:Invoke -Log { param($l, $m) }).Collections | Should -Be 0
    }
    It 'the sides page off their own index (the estimated plan seeks it)' -Skip:(-not $LocalSqlD) {
        Sql 'SET SHOWPLAN_XML ON'
        try { $plan = [string](Sql 'SELECT TOP (50) f.FindingId FROM sidata.Finding AS f WITH (INDEX(IX_Finding_AssetSidePage)) WHERE f.CollectionId = 1 ORDER BY f.RiskAssetSide DESC, f.FindingId' -Mode scalar) }
        finally { Sql 'SET SHOWPLAN_XML OFF' }
        $plan | Should -Match 'IX_Finding_AssetSidePage'
        $plan | Should -Match 'Index Seek'
    }
    It 'the Summary rows get the parts from the whole row, else worked out from their own columns' -Skip:(-not $LocalSqlD) {
        $t = '2026-10-28T09:00:00.000'
        Sql "INSERT sidata.SummaryLoad (CollectionTime, Status) VALUES (CONVERT(datetime2(3), @t, 126), 'Complete')" @{ t = $t }
        Sql @'
INSERT sidata.SummaryRow (CollectionTime, RowNo, RatingRank, RiskFactorConsequenceDetailed, RiskFactorConsequence, RiskFactorProbabilityDetailed, RiskFactorProbability,
                          RiskConsequenceScore, RiskProbabilityScore, RowJson)
VALUES (CONVERT(datetime2(3), @t, 126), 1, 1, N'InternetExposed;HighMachineRisk', 7, N'RCE', 4, 11, 8,
        N'{"RiskConsequenceBase":4,"RiskFactor_Consequence_Impacts":"InternetExposed=4;HighMachineRisk=3","RiskProbabilityBase":"4","RiskFactor_Probability_Impacts":"RCE=4"}'),
       (CONVERT(datetime2(3), @t, 126), 2, 1, N'InternetExposed', 4, NULL, NULL, 9, 5, NULL),
       (CONVERT(datetime2(3), @t, 126), 3, 1, NULL, NULL, NULL, NULL, NULL, NULL, N'not json');
'@ @{ t = $t }
        $r = Invoke-SIDataSummaryRiskParts -Invoke $script:Invoke -Batch 2 -Log { param($l, $m) }
        $r.Error | Should -BeNullOrEmpty
        $r.Rows | Should -Be 3
        $s = Sql 'SELECT RowNo, RiskAssetBase, RiskAssetDerived, RiskAssetFactors, RiskVulnBase, RiskVulnDerived, RiskVulnFactors FROM sidata.SummaryRow WHERE CollectionTime = CONVERT(datetime2(3), @t, 126) ORDER BY RowNo' @{ t = $t } 'reader'
        $s[0].RiskAssetBase | Should -Be 4; $s[0].RiskAssetDerived | Should -BeFalse; $s[0].RiskAssetFactors | Should -Be 'InternetExposed=4;HighMachineRisk=3'
        $s[0].RiskVulnBase | Should -Be 4; $s[0].RiskVulnDerived | Should -BeFalse; $s[0].RiskVulnFactors | Should -Be 'RCE=4'
        $s[1].RiskAssetBase | Should -Be 5; $s[1].RiskAssetDerived | Should -BeTrue; $s[1].RiskAssetFactors | Should -Be 'InternetExposed'
        $s[1].RiskVulnBase | Should -Be 5; $s[1].RiskVulnDerived | Should -BeTrue; $s[1].RiskVulnFactors | Should -BeOfType [DBNull]
        $s[2].RiskAssetBase | Should -BeOfType [DBNull]; $s[2].RiskAssetDerived | Should -BeTrue
        (Invoke-SIDataSummaryRiskParts -Invoke $script:Invoke -Log { param($l, $m) }).Rows | Should -Be 0
    }
}
