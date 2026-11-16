#Requires -Version 7.0
<#
    #1273 THE DERIVE READS EACH FINDING'S ROW ONCE -- AND WRITES THE SAME ROWS AND VALUES AS BEFORE (owner 2026-11-16:
    "the same rows and the same values as today ... every column, zero differences -- trust over speed").

    What these tests keep true:
      * the one-parse statement (Get-SIDataDeriveTypedSql) parses the row once (one OPENJSON, one ISJSON), never JSON_VALUE /
        JSON_QUERY per column; it carries the risk score's parts; the facet facts read no DetailJson when -Typed;
      * the derive takes it only when the database has its columns, clears TypedAt first and stamps it after the last range;
        the counted twin reads typed columns only for a collection that carries the stamp; any other database / collection
        goes exactly as before;
      * ON A REAL SQL SERVER (the runner's, SI_TEST_LOCALSQL): ONE generated collection loaded twice -- the OLD statements on
        one copy (the derive, the row values, the risk score's parts in their own pass, the facets and the counted facets
        reading DetailJson), the NEW derive (Invoke-SIDataDeriveCollection) on the other -- and EVERY column of EVERY finding
        row compared (zero differences), plus FindingFacet and FindingFacetCounted row for row. Three runs: the row values
        written by the derive; the row values filled earlier (the vulnerability step) with rows carried in afterwards; the
        CMDB columns on. The rows cover: values as strings, arrays, objects, numbers, booleans, JSON null, missing, empty,
        blank, padded, escaped, non-ASCII; lists with duplicates and empty items; texts of 3,999 / 4,000 / 4,001 characters
        (JSON_VALUE's limit) and past the columns' widths; a row that is not JSON, a NULL row, a JSON array row (one item and
        none), a row with leading white space; findings without a CVE, without a CI, exempted, carried.
      * the comparison is not blind: one changed value in one row is found.
    PS 7. Never a customer database.
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
    $script:DataSql = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1'))
    $script:Schema = [IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-data-schema.sql'))
}

Describe 'the statements' {
    It 'one parse per row: one ISJSON, one OPENJSON, no JSON_VALUE / JSON_QUERY of DetailJson; the parts in the same statement' {
        $s = Get-SIDataDeriveTypedSql -Services -Fix -Category -RowColumns -RiskParts
        # one OPENJSON for a row that is a JSON object (every row Risk Analysis writes); the second answers only for a JSON
        # array row (its argument is NULL for an object, so it parses nothing there)
        ([regex]::Matches($s, 'OPENJSON\(')).Count | Should -Be 2
        $s | Should -Match ([regex]::Escape("OUTER APPLY OPENJSON(CASE WHEN SUBSTRING(f.DetailJson, PATINDEX(N'%[^' + CHAR(9) + CHAR(10) + CHAR(13) + CHAR(32) + N']%', f.DetailJson), 1) = N'{' THEN NULL ELSE"))
        # ISJSON: the filter and inside the parse's own argument (worked out once per row) -- never in the SET list
        ([regex]::Matches($s, 'ISJSON\(')).Count | Should -Be 3
        $s.Substring(0, $s.IndexOf('OUTPUT inserted.FindingId')) | Should -Not -MatchExactly 'ISJSON\(|PATINDEX|DetailJson'
        $s | Should -Not -Match 'JSON_VALUE|JSON_QUERY'
        # the rows that are not JSON: found by what the first statement wrote, never by reading DetailJson again
        $s.Substring($s.IndexOf('DECLARE @n int')) | Should -Not -Match 'DetailJson'
        foreach ($c in 'RiskScoreWeighted', 'RiskRating', 'MitreTactics', 'MitreTechniques', 'ComplianceTags', 'Cvss', 'HasExploit', 'CmdbId', 'CmdbName',
                       'FixRemediation', 'FixRecommendedUpdate', 'FixRecommendedUpdateId', 'AffectedSoftware', 'RaCategory', 'RaRowAssetId', 'RaFillRiskFactorConsequence',
                       'RiskAssetSide', 'RiskVulnFactors', 'RiskWeightBy', 'DetailIsJson', 'ViewComponent') {
            $s | Should -Match ("(?m)^\s+{0}\s*=" -f $c)
        }
        $s | Should -Match 'WHERE f\.CollectionId = @CollectionId AND f\.FindingId > @After AND f\.FindingId <= @Upto AND ISJSON\(f\.DetailJson\) = 1;'
        # a row that is not JSON: only the parts (none, both sides worked out) and the two new columns
        $s | Should -Match 'UPDATE f SET DetailIsJson = 0, ViewComponent = NULL,\s+RiskAssetSide = NULL'
    }
    It 'the switches as the old derive: no CMDB / fix / category / parts / row values unless asked; carried rows by the old tail' {
        $s = Get-SIDataDeriveTypedSql
        $s | Should -Not -Match 'CmdbId|FixRemediation|RaCategory|RiskAssetSide|RaRowAssetId'
        $c = Get-SIDataDeriveTypedSql -Fix -CarriedRowColumns
        $c | Should -Match ([regex]::Escape((Get-SIDataRowColumnsSql -Carried -NoCount)))
        (Get-SIDataDeriveTypedSql -RowColumns -CarriedRowColumns) | Should -Not -Match 'CarriedFrom IS NOT NULL'
    }
    It 'the facet facts -Typed read typed columns only; without it, exactly as before' {
        $t = Get-SIDataFacetFactsSql -Where 'X' -FixColumn -Typed
        $t | Should -Not -Match 'DetailJson'
        $t | Should -Match 'CASE WHEN DetailIsJson = 1 THEN ViewComponent END AS Component'
        $t | Should -Match 'CASE WHEN DetailIsJson = 1 THEN FixRecommendedUpdate END AS FixUpdate'
        $o = Get-SIDataFacetFactsSql -Where 'X'
        $o | Should -Match ([regex]::Escape("CASE WHEN ISJSON(DetailJson) = 1 THEN LEFT(NULLIF(LTRIM(RTRIM(JSON_VALUE(DetailJson, '`$.si_component'))), N''), 64) END AS Component"))
        (Get-SIDataFacetRangeSql -Counted -Typed) | Should -Not -Match 'DetailJson'
        (Get-SIDataFacetSql -Counted -Typed) | Should -Not -Match 'DetailJson'
    }
    It 'the schema adds the columns (additive)' {
        $script:Schema | Should -Match ([regex]::Escape("IF COL_LENGTH('sidata.Finding', 'DetailIsJson') IS NULL ALTER TABLE sidata.Finding ADD DetailIsJson BIT NULL;"))
        $script:Schema | Should -Match ([regex]::Escape("IF COL_LENGTH('sidata.Finding', 'ViewComponent') IS NULL ALTER TABLE sidata.Finding ADD ViewComponent NVARCHAR(64) NULL;"))
        $script:Schema | Should -Match ([regex]::Escape("IF COL_LENGTH('sidata.Collection', 'TypedAt') IS NULL ALTER TABLE sidata.Collection ADD TypedAt DATETIME2(3) NULL;"))
    }
}

Describe 'the wiring' {
    It 'the derive: the one parse when the database has its columns, TypedAt cleared first and stamped (with the fix columns) before the facets' {
        $src = $script:DataSql
        $src | Should -Match ([regex]::Escape('$typed = ([string](& $Invoke (Get-SIDataTypedReadySql) @{} ''scalar'') -eq ''1'')'))
        $i0 = $src.IndexOf('SET TypedAt = NULL WHERE CollectionId = @CollectionId'); $i1 = $src.IndexOf('$done = Invoke-SIDataFindingRanges @rg')
        $i2 = $src.IndexOf('SET TypedAt = SYSUTCDATETIME() WHERE CollectionId = @CollectionId'); $i3 = $src.IndexOf('$facets = Invoke-SIDataFacet -Invoke $Invoke -CollectionId $CollectionId')
        $i0 | Should -BeGreaterThan 0
        $i1 | Should -BeGreaterThan $i0
        $i2 | Should -BeGreaterThan $i1
        $i3 | Should -BeGreaterThan $i2
        $src | Should -Match ([regex]::Escape('if ($typed -and $Fix) {'))
    }
    It 'with a fake database that has no new columns: the statements of before, the parts in their own pass, the facets read DetailJson' {
        $calls = New-Object System.Collections.ArrayList
        $inv = {
            param([string]$sql, $p, [string]$mode)
            [void]$calls.Add($sql)
            if ($sql -match 'MIN\(FindingId\) AS Lo') { return , @(@{ Lo = 1; Hi = 600 }) }
            if ($sql -match "COL_LENGTH\('sidata\.Finding', 'RiskAssetDerived'\)") { return 1 }
            if ($sql -match "OBJECT_ID\('sidata\.FindingFacetStage'\)") { return 1 }
            if ($mode -eq 'scalar') { return 0 }
        }.GetNewClosure()
        $null = Invoke-SIDataDeriveCollection -Invoke $inv -CollectionId 7 -Fix
        @($calls | Where-Object { $_ -match 'DECLARE @o TABLE' }).Count | Should -Be 0
        @($calls | Where-Object { $_ -match 'SET\s+RiskScoreWeighted = TRY_CONVERT\(float, JSON_VALUE' }).Count | Should -BeGreaterThan 0
        @($calls | Where-Object { $_ -match 'RiskAssetSide\s+= p\.ASide' -and $_ -notmatch 'DECLARE @o TABLE' }).Count | Should -BeGreaterThan 0
        @($calls | Where-Object { $_ -match 'INSERT sidata\.FindingFacetStage' -and $_ -match 'ISJSON\(DetailJson\)' }).Count | Should -BeGreaterThan 0
        @($calls | Where-Object { $_ -match 'TypedAt' -and $_ -notmatch 'COL_LENGTH' }).Count | Should -Be 0
    }
    It 'with a fake database that has them: one statement per range (parts included), the stamp, the facets typed' {
        $calls = New-Object System.Collections.ArrayList
        $inv = {
            param([string]$sql, $p, [string]$mode)
            [void]$calls.Add($sql)
            if ($sql -match 'MIN\(FindingId\) AS Lo') { return , @(@{ Lo = 1; Hi = 600 }) }
            if ($sql -match "COL_LENGTH\('sidata\.Finding', 'DetailIsJson'\)") { return 1 }
            if ($sql -match "COL_LENGTH\('sidata\.Finding', 'RiskAssetDerived'\)") { return 1 }
            if ($sql -match "OBJECT_ID\('sidata\.FindingFacetStage'\)") { return 1 }
            if ($mode -eq 'scalar') { return 0 }
        }.GetNewClosure()
        $null = Invoke-SIDataDeriveCollection -Invoke $inv -CollectionId 7 -Fix
        @($calls | Where-Object { $_ -match 'DECLARE @o TABLE' -and $_ -match 'RiskAssetSide\s+= p\.ASide' }).Count | Should -BeGreaterThan 0
        @($calls | Where-Object { $_ -match 'JSON_VALUE\(f\.DetailJson' }).Count | Should -Be 0
        @($calls | Where-Object { $_ -match 'INSERT sidata\.FindingFacetStage' }) | ForEach-Object { $_ | Should -Not -Match 'DetailJson' }
        @($calls | Where-Object { $_ -match 'SET TypedAt = SYSUTCDATETIME\(\)' }).Count | Should -Be 1
    }
    It 'the counted twin reads typed columns only when the collection carries the stamp' {
        $src = $script:DataSql
        $src | Should -Match ([regex]::Escape('$typedFacets = Test-SIDataCollectionTyped -Invoke $Invoke -CollectionId $cid'))
        $no = { param($s, $p, $m) throw 'no database' }
        Test-SIDataCollectionTyped -Invoke $no -CollectionId 1 | Should -BeFalse
    }
}

Describe 'on a real SQL Server: the new derive writes every column of every row exactly as the old statements' {
    BeforeAll {
        $script:LocalSql = $false
        try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
        if (-not $script:LocalSql) { return }
        $script:Db = 'siderivetyped_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
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
                    while ($r.Read()) { $h = [ordered]@{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add($h) }
                    $r.Close(); return , $rows.ToArray()
                } finally { $cn.Close() }
            }.GetNewClosure()
        }
        $script:Master = New-LocalInvoke 'master'
        [void](& $script:Master "CREATE DATABASE [$script:Db]" @{} 'nonquery')
        $script:Inv = New-LocalInvoke $script:Db
        # the seam answers a reader as ONE list: assigned first, then enumerated
        function script:Get-Rows([string]$Sql, $P) { $x = & $script:Inv $Sql $P 'reader'; , @($x) }
        function script:Get-Row([string]$Sql, $P) { $x = & $script:Inv $Sql $P 'reader'; @($x)[0] }
        $cfg =[System.IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-pro-settings.sql'))
        foreach ($pass in 1, 2) {
            foreach ($b in ([regex]::Split($cfg, '(?m)^\s*$'))) { if (([regex]::Replace($b, '(?m)^\s*--.*$', '')).Trim()) { [void](& $script:Inv $b @{} 'nonquery') } }
            [void](& $script:Inv $script:Schema @{} 'nonquery')
        }

        # ---- the generated rows: every field in many shapes, combined differently on each row ---------------------------
        $long = { param([int]$n, [string]$tail = '') '"' + ('x' * ($n - $tail.Length)) + $tail + '"' }
        $str = @('"High"', '""', '"   "', 'null', $null, '["a","b"]', '{"x":1}', '"  padded  "', '123', 'true', (& $long 4000), (& $long 4001), (& $long 4001 '  '),
                 (& $long 3999), '"Critical"', '"Ünïcødé ☃ 漢字"', '"a\"quote"', '"line\nbreak"', '[]', '"Other"', '"  Windows "', '"OS"', '"x;y; z"', '"Very High"')
        $num = @('7.5', '"7.5"', '"  8 "', '1e2', '"abc"', 'null', $null, '[1]', '0', '-3', '1.30', '"1,5"', '""', '"   "', (& $long 401 '1'), '1234567890123.25')
        $bool = @('true', 'false', '"true"', '"TRUE"', '1', '0', '"0"', '"1"', 'null', $null, '"yes"', '[true]')
        $lst = @('["TA0001","TA0002","TA0001"]', '"TA0003, TA0004,TA0003"', '"T1059; T1059.001 ;T1003"', '[]', '""', 'null', $null, '["a, b"]', '[1,2]',
                 '{"o":1}', ('"' + ((1..400 | ForEach-Object { 'T{0:0000}' -f $_ }) -join ', ') + '"'), '["x\"y"]', '"  ;  ; "', '["ISO","ISO", ""]', '"CIS; NIST ;  ; CIS"')
        $fieldsS = @('RiskRating', 'si_risk_rating', 'si_category', 'Category', 'si_subcategory', 'SubCategory', 'Subcategory', 'si_class', 'AssetClass', 'Component',
                     'si_component', 'si_patch_cycle', 'si_os_family', 'si_servicenow_subci', 'si_affected_product', 'AssetId', 'SolutionVersion', 'CriticalityTier',
                     'cmdbId', 'cmdbName', 'si_fix_remediation', 'si_fix_recommended_update', 'si_fix_recommended_update_id', 'si_affected_software',
                     'RiskFactor_Probability_Detailed', 'RiskFactor_Consequence_Detailed', 'RiskFactor_Consequence_Impacts', 'RiskFactor_Probability_Impacts', 'RiskScore_Weight_Detailed')
        $fieldsN = @('RiskScoreTotal_Weighted', 'MaxCvssScore', 'Impact', 'RiskConsequenceBase', 'RiskConsequenceScore', 'RiskFactor_Consequence', 'RiskProbabilityBase',
                     'RiskProbabilityScore', 'RiskFactor_Probability', 'RiskScore_Weight_Factor')
        $fieldsL = @('MITRE_Tactics', 'MITRE_Techniques', 'ComplianceTags')
        $script:N = 2400
        $rows = New-Object System.Collections.Generic.List[object]
        for ($i = 1; $i -le $script:N; $i++) {
            $parts = New-Object System.Collections.Generic.List[string]
            $k = 0
            foreach ($f in $fieldsS) { $k++; $v = $str[($i * 7 + $k * 13) % $str.Count]; if ($null -ne $v) { $parts.Add(('"{0}":{1}' -f $f, $v)) } }
            foreach ($f in $fieldsN) { $k++; $v = $num[($i * 5 + $k * 11) % $num.Count]; if ($null -ne $v) { $parts.Add(('"{0}":{1}' -f $f, $v)) } }
            foreach ($f in $fieldsL) { $k++; $v = $lst[($i * 3 + $k * 7) % $lst.Count]; if ($null -ne $v) { $parts.Add(('"{0}":{1}' -f $f, $v)) } }
            $hb = $bool[$i % $bool.Count]; if ($null -ne $hb) { $parts.Add(('"HasExploit":{0}' -f $hb)) }
            $parts.Add(('"Padding":"{0}"' -f ('p' * (($i * 37) % 900))))
            $obj = '{' + ($parts -join ',') + '}'
            $json = switch ($true) {
                ($i % 53 -eq 0) { 'not json {'; break }
                ($i % 59 -eq 0) { $null; break }
                ($i % 61 -eq 0) { '[' + $obj + ']'; break }
                ($i % 67 -eq 0) { '[]'; break }
                ($i % 71 -eq 0) { "`r`n `t " + $obj; break }
                default { $obj }
            }
            $rows.Add([ordered]@{
                AssetKey = $(if ($i % 37 -eq 0) { $null } else { 'asset-' + ($i % 211) }); AssetName = 'host-' + ($i % 211); ReportName = 'Report_' + ($i % 7)
                SecurityDomain = @('Endpoint', 'Identity', $null)[$i % 3]; ConfigurationId = 'CVE-2025-' + $i; Cve = $(if ($i % 3 -eq 0) { 'CVE-2025-' + $i } else { $null })
                Title = 'title ' + ($i % 50); Severity = @('High', 'Low', 'Very High', 'Medium', $null)[$i % 5]; Tier = $(if ($i % 9 -eq 0) { $null } else { $i % 4 })
                RiskScore = $(if ($i % 41 -eq 0) { $null } else { ($i % 97) / 7.0 }); DetailJson = $json; ExemptionId = $(if ($i % 5 -eq 0) { 100 + $i % 3 } else { $null })
            })
        }
        $script:Rows = $rows

        function script:New-Collection([string]$At, [object[]]$Rows) {
            $cid = [int](& $script:Inv "INSERT sidata.Collection (CollectionTime, Kind, Status, [Rows]) VALUES (@t, N'Detailed', N'Complete', @n); SELECT CONVERT(int, SCOPE_IDENTITY());" @{ t = $At; n = $Rows.Count } 'scalar')
            for ($o = 0; $o -lt $Rows.Count; $o += 400) {
                $chunk = @($Rows[$o..([Math]::Min($Rows.Count, $o + 400) - 1)])
                [void](& $script:Inv (Get-SIDataInsertFindingSql) @{ CollectionId = $cid; j = (ConvertTo-Json -InputObject $chunk -Depth 3 -Compress) } 'scalar')
            }
            $cid
        }
        # carried rows: added after the collection's own rows (and after the row values were filled), marked carried, their
        # row values empty (a source collection from before the row values) -- as the data sync carries them in
        function script:Add-Carried([int]$Cid, [object[]]$Rows) {
            $before = [long](& $script:Inv 'SELECT ISNULL(MAX(FindingId), 0) FROM sidata.Finding WHERE CollectionId = @c' @{ c = $Cid } 'scalar')
            [void](& $script:Inv (Get-SIDataInsertFindingSql) @{ CollectionId = $Cid; j = (ConvertTo-Json -InputObject @($Rows) -Depth 3 -Compress) } 'scalar')
            [void](& $script:Inv 'UPDATE sidata.Finding SET CarriedFrom = ''2026-11-01T04:00:00'' WHERE CollectionId = @c AND FindingId > @b' @{ c = $Cid; b = $before } 'nonquery')
        }
        # THE OLD PATH, exactly as Invoke-SIDataDeriveCollection ran it before #1273 (its statements, its order), then the
        # counted facets as the exempted step ran them (reading DetailJson)
        function script:Invoke-OldDerive([int]$Cid, [switch]$RowsDone, [switch]$Services) {
            $b = (Get-Row (Get-SIDataFindingBoundsSql) @{ CollectionId = $Cid })
            $sql = if ($RowsDone) { Get-SIDataDeriveFindingSql -Services:$Services -Fix -Category -CarriedRowColumns } else { Get-SIDataDeriveFindingSql -Services:$Services -Fix -Category -RowColumns }
            $bs = [long]97
            $n = Invoke-SIDataFindingRanges -Invoke $script:Inv -CollectionId $Cid -Lo ([long]$b['Lo']) -Hi ([long]$b['Hi']) -Sql $sql -BatchSize ([ref]$bs) -TargetMs 1
            if (-not $RowsDone) { $null = & $script:Inv 'UPDATE sidata.Collection SET RaRowsAt = SYSUTCDATETIME() WHERE CollectionId = @CollectionId; SELECT 1;' @{ CollectionId = $Cid } 'scalar' }
            $null = Invoke-SIDataFindingRanges -Invoke $script:Inv -CollectionId $Cid -Lo ([long]$b['Lo']) -Hi ([long]$b['Hi']) -Sql (Get-SIDataRiskPartsSql) -TargetMs 1
            $null = & $script:Inv (Get-SIDataRiskPartsStampSql) @{ CollectionId = $Cid; Upto = [long]$b['Hi'] } 'scalar'
            $fs = [long]300
            $null = Invoke-SIDataFacet -Invoke $script:Inv -CollectionId $Cid -FixColumn -BatchSize ([ref]$fs) -TargetMs 1
            $fs = [long]300
            $null = Invoke-SIDataFacet -Invoke $script:Inv -CollectionId $Cid -Counted -BatchSize ([ref]$fs) -TargetMs 1
            $n
        }
        function script:Invoke-NewDerive([int]$Cid, [switch]$Services) {
            $bs = [long]97
            $r = Invoke-SIDataDeriveCollection -Invoke $script:Inv -CollectionId $Cid -Fix -Services:$Services -BatchSize ([ref]$bs) -TargetMs 1
            $typed = Test-SIDataCollectionTyped -Invoke $script:Inv -CollectionId $Cid
            $fs = [long]300
            $null = Invoke-SIDataFacet -Invoke $script:Inv -CollectionId $Cid -Counted -Typed:$typed -BatchSize ([ref]$fs) -TargetMs 1
            [pscustomobject]@{ Findings = $r.Findings; Typed = $typed }
        }
        $script:Skip = @('FindingId', 'CollectionId', 'DetailIsJson', 'ViewComponent')
        function script:Read-Findings([int]$Cid) {
            Get-Rows 'SELECT * FROM sidata.Finding WHERE CollectionId = @c ORDER BY FindingId' @{ c = $Cid }
        }
        function script:Compare-Findings($A, $B) {
            $diff = New-Object System.Collections.Generic.List[string]
            if ($A.Count -ne $B.Count) { $diff.Add(('row count {0} vs {1}' -f $A.Count, $B.Count)); return , $diff.ToArray() }
            $cols = @($A[0].Keys | Where-Object { $_ -notin $script:Skip })
            for ($i = 0; $i -lt $A.Count; $i++) {
                foreach ($c in $cols) {
                    $x = $A[$i][$c]; $y = $B[$i][$c]
                    $same = if ($null -eq $x -or $null -eq $y) { $null -eq $x -and $null -eq $y }
                            elseif ($x -is [string]) { [string]::Equals($x, [string]$y, [StringComparison]::Ordinal) }
                            elseif ($x -is [double]) { ([double]$x).Equals([double]$y) }
                            elseif ($x -is [byte[]]) { [Convert]::ToBase64String($x) -eq [Convert]::ToBase64String($y) }
                            else { $x -eq $y }
                    if (-not $same) { $diff.Add(('row {0} column {1}: old [{2}] new [{3}]' -f $i, $c, $x, $y)) }
                }
            }
            , $diff.ToArray()
        }
        function script:Read-Facets([string]$Table, [int]$Cid) {
            Get-Rows ("SELECT Facet, Value, Findings, Assets, ScoreTotal, WeightedTotal, MaxScore FROM sidata.$Table WHERE CollectionId = @c ORDER BY Facet, Value") @{ c = $Cid }
        }
        function script:Assert-SameFacets($A, $B, [string]$What) {
            $B.Count | Should -Be $A.Count -Because "$What has the same number of rows"
            for ($i = 0; $i -lt $A.Count; $i++) {
                foreach ($k in 'Facet', 'Value', 'Findings', 'Assets') { $B[$i][$k] | Should -Be $A[$i][$k] -Because ("{0} row {1} ({2}/{3}) {4}" -f $What, $i, $A[$i]['Facet'], $A[$i]['Value'], $k) }
                foreach ($k in 'ScoreTotal', 'WeightedTotal', 'MaxScore') {
                    $x = $A[$i][$k]; $y = $B[$i][$k]
                    if ($null -eq $x -or $null -eq $y) { $y | Should -Be $x -Because ("{0} row {1} {2}" -f $What, $i, $k); continue }
                    # a sum of floats added in another order may differ in its last bits -- never more (as the ranged facets)
                    [Math]::Abs([double]$x - [double]$y) | Should -BeLessOrEqual ([Math]::Max(1e-9, 1e-12 * [Math]::Abs([double]$x))) -Because ("{0} row {1} {2}" -f $What, $i, $k)
                }
            }
        }
    }
    AfterAll {
        if (-not $script:LocalSql -or -not $script:Master) { return }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        [void](& $script:Master "ALTER DATABASE [$script:Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:Db]" @{} 'nonquery')
    }

    It 'the row values written by the derive: zero differences in every column of every row, the facets and the counted facets row for row' -Skip:(-not $script:LocalSql) {
        $a = New-Collection '2026-11-16T01:00:00' $script:Rows
        $b = New-Collection '2026-11-16T02:00:00' $script:Rows
        $oldN = Invoke-OldDerive $a
        $new = Invoke-NewDerive $b
        $new.Typed | Should -BeTrue -Because 'the new derive stamped the collection, so the counted facets read typed columns'
        $new.Findings | Should -Be $oldN -Because 'the derive answers the rows whose DetailJson is JSON, as before'
        $fa = Read-Findings $a; $fb = Read-Findings $b
        $d = Compare-Findings $fa $fb
        if ($d.Count) { Write-Host ("DIFFERENCES ({0}):`n{1}" -f $d.Count, (($d | Select-Object -First 30) -join "`n")) }
        $d.Count | Should -Be 0
        Write-Host ('DERIVE-TYPED-SAME: {0} rows x {1} columns compared, 0 differences' -f $fa.Count, (@($fa[0].Keys).Count - $script:Skip.Count))
        # the rows did get values (the comparison is not of two empty sets)
        @($fb | Where-Object { $null -ne $_['RiskScoreWeighted'] }).Count | Should -BeGreaterThan 100
        @($fb | Where-Object { $null -ne $_['MitreTactics'] }).Count | Should -BeGreaterThan 100
        @($fb | Where-Object { $null -ne $_['RaScopeCategory'] }).Count | Should -BeGreaterThan 100
        @($fb | Where-Object { $null -ne $_['RiskAssetSide'] }).Count | Should -BeGreaterThan 100
        @($fb | Where-Object { $null -ne $_['FixRecommendedUpdate'] }).Count | Should -BeGreaterThan 100
        # DetailIsJson is ISJSON exactly; ViewComponent the facet's own expression
        [int](& $script:Inv "SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = @c AND (DetailIsJson IS NULL OR DetailIsJson <> CASE WHEN ISJSON(DetailJson) = 1 THEN 1 ELSE 0 END)" @{ c = $b } 'scalar') | Should -Be 0
        [int](& $script:Inv "SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = @c AND ISNULL(ViewComponent, N'~') <> ISNULL(CASE WHEN ISJSON(DetailJson) = 1 THEN LEFT(NULLIF(LTRIM(RTRIM(JSON_VALUE(DetailJson, '$.si_component'))), N''), 64) END, N'~')" @{ c = $b } 'scalar') | Should -Be 0
        Assert-SameFacets (Read-Facets 'FindingFacet' $a) (Read-Facets 'FindingFacet' $b) 'FindingFacet'
        Assert-SameFacets (Read-Facets 'FindingFacetCounted' $a) (Read-Facets 'FindingFacetCounted' $b) 'FindingFacetCounted'
        @((Read-Facets 'FindingFacet' $b) | Where-Object { $_['Facet'] -eq 'component' }).Count | Should -BeGreaterThan 3
        @((Read-Facets 'FindingFacet' $b) | Where-Object { $_['Facet'] -eq 'update' }).Count | Should -BeGreaterThan 3
        # the comparison is not blind: one value changed in one row is found
        $fb[17]['RiskRating'] = 'changed'
        @(Compare-Findings $fa $fb).Count | Should -Be 1
    }
    It 'the row values filled earlier (the vulnerability step) and rows carried in afterwards: zero differences' -Skip:(-not $script:LocalSql) {
        $a = New-Collection '2026-11-16T03:00:00' $script:Rows
        $b = New-Collection '2026-11-16T04:00:00' $script:Rows
        foreach ($c in $a, $b) { (Invoke-SIDataRowColumnsFill -Invoke $script:Inv -CollectionId $c -TargetMs 1).Filled | Should -BeTrue }
        $carry = @($script:Rows | Select-Object -First 300 | ForEach-Object { $h = [ordered]@{}; foreach ($k in $_.Keys) { $h[$k] = $_[$k] }; $h.AssetKey = 'carried-' + $h.AssetName; $h })
        Add-Carried $a $carry; Add-Carried $b $carry
        $oldN = Invoke-OldDerive $a -RowsDone
        $new = Invoke-NewDerive $b
        $new.Typed | Should -BeTrue
        $new.Findings | Should -Be $oldN
        $fa = Read-Findings $a; $fb = Read-Findings $b
        $d = Compare-Findings $fa $fb
        if ($d.Count) { Write-Host ("DIFFERENCES ({0}):`n{1}" -f $d.Count, (($d | Select-Object -First 30) -join "`n")) }
        $d.Count | Should -Be 0
        @($fb | Where-Object { $null -ne $_['CarriedFrom'] -and $null -ne $_['RaScopeCategory'] }).Count | Should -BeGreaterThan 20 -Because 'the carried rows got their row values'
        Assert-SameFacets (Read-Facets 'FindingFacet' $a) (Read-Facets 'FindingFacet' $b) 'FindingFacet (carried)'
        Assert-SameFacets (Read-Facets 'FindingFacetCounted' $a) (Read-Facets 'FindingFacetCounted' $b) 'FindingFacetCounted (carried)'
    }
    It 'the CMDB columns on (the Services view): zero differences' -Skip:(-not $script:LocalSql) {
        $a = New-Collection '2026-11-16T05:00:00' $script:Rows
        $b = New-Collection '2026-11-16T06:00:00' $script:Rows
        # the services' own aggregates come after the per-row pass and are the same code on both sides: the rows are compared
        $bs = [long]97
        $bd = (Get-Row (Get-SIDataFindingBoundsSql) @{ CollectionId = $a })
        $null = Invoke-SIDataFindingRanges -Invoke $script:Inv -CollectionId $a -Lo ([long]$bd['Lo']) -Hi ([long]$bd['Hi']) -Sql (Get-SIDataDeriveFindingSql -Services -Fix -Category -RowColumns) -BatchSize ([ref]$bs) -TargetMs 1
        $null = Invoke-SIDataFindingRanges -Invoke $script:Inv -CollectionId $a -Lo ([long]$bd['Lo']) -Hi ([long]$bd['Hi']) -Sql (Get-SIDataRiskPartsSql) -TargetMs 1
        $bs = [long]97
        $bd = (Get-Row (Get-SIDataFindingBoundsSql) @{ CollectionId = $b })
        $null = Invoke-SIDataFindingRanges -Invoke $script:Inv -CollectionId $b -Lo ([long]$bd['Lo']) -Hi ([long]$bd['Hi']) -Sql (Get-SIDataDeriveTypedSql -Services -Fix -Category -RowColumns -RiskParts) -BatchSize ([ref]$bs) -TargetMs 1
        $fa = Read-Findings $a; $fb = Read-Findings $b
        $d = Compare-Findings $fa $fb
        if ($d.Count) { Write-Host ("DIFFERENCES ({0}):`n{1}" -f $d.Count, (($d | Select-Object -First 30) -join "`n")) }
        $d.Count | Should -Be 0
        @($fb | Where-Object { $null -ne $_['CmdbId'] }).Count | Should -BeGreaterThan 100
    }
}
