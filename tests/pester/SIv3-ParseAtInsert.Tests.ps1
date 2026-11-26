#Requires -Version 7.0
<#
    #1318 PARSE ONCE AT INSERT (SCALE-2 #1314) -- THE VIEW VALUES WORKED OUT WHEN RISK ANALYSIS STORES A FINDING, THE SAME
    VALUES AS THE DATA SYNC'S DERIVE (owner 2026-11-23: "data quality + stability in the runs are prio 1, performance is prio 2").

    What these tests keep true:
      * the setting SI_Data_ParseAtInsert: on (the default since owner 2026-11-23, anything unknown) | shadow | off; the
        switch-set mask;
      * ONE source of truth: Risk Analysis' insert runs the derive's own typed statement (Get-SIDataDeriveTypedSql) over the
        rows it just inserted, in the same transaction, and answers the insert's own count; off = the insert as before; the
        derive's own statement is unchanged by default; a carried row never takes the mark;
      * ON A REAL SQL SERVER (the runner's, _SITestSql): the same generated rows (values as strings, arrays, objects, numbers,
        booleans, JSON null, missing, empty, padded, long; lists with duplicates and empty items; rows that are not JSON, NULL,
        JSON arrays; CVE rows and others) inserted twice -- the OLD way (inserted, then derived with every switch on) and with
        the switch (typed at insert) -- carry byte-identical values in EVERY column of EVERY row; with on, the derive does no
        typed range for them, only the facets and the stamps (same facets as the old way); carried rows are still derived;
        shadow reports 0 differences on identical rows and a difference (FindingId + column name, never the value) when one
        is forced, keeping the derive's value; the vulnerability step's row-values fill leaves typed rows alone (on) or
        compares them (shadow); a trace-name update re-types its rows.
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
    $script:AllOn = [pscustomobject]@{ Mode = 'on'; Ready = $true; Why = ''; Services = $true; Fix = $true; Category = $true; RowColumns = $true; RiskParts = $true; Mask = 63; Print = (Get-SIDataTypedFingerprint -Services -Fix -Category -RowColumns -RiskParts) }
}

Describe 'the setting and the statements' {
    It 'the setting: ON by default (owner 2026-11-23) and for anything unknown; off / shadow / on in any case' {
        Get-SIDataParseAtInsertMode -Value $null | Should -Be 'on'
        Get-SIDataParseAtInsertMode -Value '' | Should -Be 'on'
        Get-SIDataParseAtInsertMode -Value ' Shadow ' | Should -Be 'shadow'
        Get-SIDataParseAtInsertMode -Value 'ON' | Should -Be 'on'
        Get-SIDataParseAtInsertMode -Value 'yes' | Should -Be 'on'
        # off stays reachable: today's behaviour, every row derived by the data sync
        Get-SIDataParseAtInsertMode -Value 'off' | Should -Be 'off'
        Get-SIDataParseAtInsertMode -Value ' OFF ' | Should -Be 'off'
        Get-SIDataParseAtInsertMode -Value $false | Should -Be 'off'
        Get-SIDataParseAtInsertMode -Value '0' | Should -Be 'off'
        Remove-Variable -Name SI_Data_ParseAtInsert -Scope Global -ErrorAction SilentlyContinue
        Get-SIDataParseAtInsertMode | Should -Be 'on'
        # off = the insert as before (no plan, nothing typed)
        $p = Get-SIDataParseAtInsertPlan -Invoke { throw 'off reads nothing' } -Mode off
        $p.Ready | Should -BeFalse
        $p.Why | Should -Be 'off'
    }
    It 'in the settings catalog: off / shadow / on, ON by default, a normal setting (no REMOVE-ME) in the reference' {
        $cat = Get-Content -Raw -LiteralPath (Join-Path $script:Root 'config\settings.catalog.locked.json') | ConvertFrom-Json
        $s = @($cat.settings | Where-Object { $_.name -eq 'SI_Data_ParseAtInsert' })[0]
        $s | Should -Not -BeNullOrEmpty
        @($s.values) | Should -Be @('off', 'shadow', 'on')
        $s.defaultText | Should -Match '^on'
        "$($s.description) $($s.effect) $($s.whenToChange)" | Should -Not -Match 'REMOVE-ME'
        $ref = [IO.File]::ReadAllText((Join-Path $script:Root 'config\SecurityInsight.custom.reference.ps1'))
        $ref | Should -Match "on \(the default\)[^\r\n]*\r?\n(#[^\r\n]*\r?\n)*# \`$global:SI_Data_ParseAtInsert = 'on'"
        $ref | Should -Not -Match "REMOVE-ME[^\r\n]*\r?\n(#[^\r\n]*\r?\n)*# \`$global:SI_Data_ParseAtInsert"
    }
    It 'the mask: one bit per switch' {
        Get-SIDataTypedMask | Should -Be 1
        Get-SIDataTypedMask -Services -Fix -Category -RowColumns -RiskParts | Should -Be 63
        Get-SIDataTypedMask -Fix -RiskParts | Should -Be 37
    }
    It 'the derive''s own statement is unchanged by default (no mark, no skip, its answer)' {
        $s = Get-SIDataDeriveTypedSql -Services -Fix -Category -RowColumns -RiskParts
        $s | Should -Not -Match 'TypedOnInsert'
        $s | Should -Match 'WHERE f\.CollectionId = @CollectionId AND f\.FindingId > @After AND f\.FindingId <= @Upto AND ISJSON\(f\.DetailJson\) = 1;'
        $s.TrimEnd() | Should -Match 'SELECT @n;$'
        (Get-SIDataRowColumnsSql) | Should -Not -Match 'TypedOnInsert'
        (Get-SIDataDeriveTypedSql -Fix -SkipPrint ('ab' * 16)) | Should -Match ([regex]::Escape('AND (f.TypedStatement IS NULL OR f.TypedStatement <> 0xABABABABABABABABABABABABABABABAB) AND ISJSON(f.DetailJson) = 1;'))
        (Get-SIDataRowColumnsSql -SkipPrint ('0f' * 16)) | Should -Match ([regex]::Escape('AND (f.TypedStatement IS NULL OR f.TypedStatement <> 0x0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F)'))
    }
    It 'the insert: the derive''s own SET list over the rows just inserted, marked, in the same transaction, its own count answered' {
        $old = Get-RAStreamInsertFindingSql
        $old | Should -Not -Match '@ins|TypedOnInsert'
        (Get-RAStreamInsertFindingSql -Typed $null) | Should -Be $old
        $new = Get-RAStreamInsertFindingSql -Typed $script:AllOn
        $new | Should -Match 'OUTPUT inserted\.FindingId INTO @ins \(id\)\s+SELECT CONVERT\(int, @CollectionId\),'
        $new | Should -Match 'f\.FindingId IN \(SELECT id FROM @ins\)'
        $new | Should -Match 'TypedOnInsert = 63'
        $new | Should -Match ('TypedStatement = 0x' + $script:AllOn.Print)
        $new.TrimEnd() | Should -Match 'COMMIT;\s+SELECT @w;$'
        $new.IndexOf('UPDATE f SET') | Should -BeGreaterThan $new.IndexOf('INSERT sidata.Finding')
        $new.IndexOf('UPDATE f SET') | Should -BeLessThan $new.IndexOf('COMMIT;')
        # one source of truth: the derive's SET list appears verbatim in the insert
        $d = Get-SIDataDeriveTypedSql -Services -Fix -Category -RowColumns -RiskParts
        $set = $d.Substring($d.IndexOf('UPDATE f SET'), $d.IndexOf('OUTPUT inserted.FindingId INTO @o') - $d.IndexOf('UPDATE f SET')).TrimEnd()
        $new | Should -Match ([regex]::Escape($set))
        # a plan that is not ready = the insert as before
        (Get-RAStreamInsertFindingSql -Typed ([pscustomobject]@{ Ready = $false })) | Should -Be $old
    }
    It 'the trace-name update re-types its rows when the plan is on; as before otherwise' {
        (Get-RAStreamTraceUpdateSql -Grain Detailed) | Should -Not -Match '@ins'
        $t = Get-RAStreamTraceUpdateSql -Grain Detailed -Typed $script:AllOn
        $t | Should -Match 'OUTPUT inserted\.FindingId INTO @ins \(id\)\s+FROM sidata\.Finding f JOIN OPENJSON\(@j\)'
        $t | Should -Match 'TypedOnInsert = 63'
        $t.TrimEnd() | Should -Match 'SELECT @w;$'
        (Get-RAStreamTraceUpdateSql -Grain Summary -Typed $script:AllOn) | Should -Not -Match '@ins'
    }
    It 'a carried row never takes the mark (it is derived by the data sync as before)' {
        $sync = [IO.File]::ReadAllText((Join-Path $script:Root 'engine\pro-data\_shared\SI-DataSync.ps1'))
        $sync | Should -Match "'RaInView', 'TypedOnInsert', 'TypedStatement'\) ORDER BY column_id"
    }
    It 'the schema: the mark column and its filtered index' {
        $script:Schema | Should -Match ([regex]::Escape("IF COL_LENGTH('sidata.Finding', 'TypedOnInsert') IS NULL ALTER TABLE sidata.Finding ADD TypedOnInsert TINYINT NULL;"))
        $script:Schema | Should -Match ([regex]::Escape("IF COL_LENGTH('sidata.Finding', 'TypedStatement') IS NULL ALTER TABLE sidata.Finding ADD TypedStatement BINARY(16) NULL;"))
        $script:Schema | Should -Match 'CREATE INDEX IX_Finding_TypedStatement ON sidata\.Finding \(CollectionId, TypedStatement\) WHERE TypedStatement IS NOT NULL'
    }
    It 'the fingerprint names the EXACT statement: stable, one per switch set, another one when any expression changes' {
        $a = Get-SIDataTypedFingerprint -Services -Fix -Category -RowColumns -RiskParts
        $a | Should -Match '^[0-9A-F]{32}$'
        Get-SIDataTypedFingerprint -Services -Fix -Category -RowColumns -RiskParts | Should -Be $a
        Get-SIDataTypedFingerprint -Fix -Category -RowColumns -RiskParts | Should -Not -Be $a
        $keep = $script:SIDataRowColumns['RaRowSolutionVersion'].Fields
        try {
            $script:SIDataRowColumns['RaRowSolutionVersion'].Fields = @('RiskRating')
            Get-SIDataTypedFingerprint -Services -Fix -Category -RowColumns -RiskParts | Should -Not -Be $a -Because 'one changed expression is another statement'
        } finally { $script:SIDataRowColumns['RaRowSolutionVersion'].Fields = $keep }
        Get-SIDataTypedFingerprint -Services -Fix -Category -RowColumns -RiskParts | Should -Be $a
        { ConvertTo-SIDataPrintLiteral "x'; DROP" } | Should -Throw
    }
    It 'the views step says both counts: rows stored with their values at insert and rows worked out here' {
        $sync = Join-Path $script:Root 'engine\pro-data\_shared\SI-DataSync.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($sync, [ref]$null, [ref]$null)
        foreach ($n in 'Get-SIDataViewsRowCounts', 'Format-SIDataViewsLine') {
            . ([scriptblock]::Create(($ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq $n }, $true)).Extent.Text))
        }
        $on = @([pscustomobject]@{ Findings = 200; Facets = 40; ParseAtInsert = 'on'; TypedAtInsert = 1500000 }, [pscustomobject]@{ Findings = 3; Facets = 2; ParseAtInsert = 'on'; TypedAtInsert = 0 })
        Format-SIDataViewsLine -Derived $on | Should -Be "views       : 2 collection(s) got their views' data (1500000 finding row(s) stored with their values at insert, 203 worked out here, 42 aggregate row(s))"
        (Get-SIDataViewsRowCounts -Derived $on).Total | Should -Be 1500203
        # off / shadow: the line and the count as before (shadow works every row out here)
        $off = @([pscustomobject]@{ Findings = 900; Facets = 12; ParseAtInsert = 'shadow'; TypedAtInsert = 900 })
        Format-SIDataViewsLine -Derived $off | Should -Be "views       : 1 collection(s) got their views' data (900 finding row(s), 12 aggregate row(s))"
        (Get-SIDataViewsRowCounts -Derived $off).Total | Should -Be 900
        $src = [IO.File]::ReadAllText($sync)
        $src | Should -Match ([regex]::Escape('& $ok (Format-SIDataViewsLine -Derived @($result.Derived))'))
        $src | Should -Match ([regex]::Escape("& `$phase 'views (derive)' ([long](Get-SIDataViewsRowCounts -Derived @(`$result.Derived)).Total)"))
    }
    It 'the shadow summary adds the ranges up; the line names ids and columns, never a value' {
        $s = Get-SIDataParseAtInsertShadowSummary -Answers @('10|0|', '7|2|FindingId 5: RiskRating; FindingId 9: Cvss, HasExploit', '3|1|FindingId 40: MitreTactics')
        $s.Compared | Should -Be 20; $s.Differ | Should -Be 3
        $s.Sample | Should -Be 'FindingId 5: RiskRating; FindingId 9: Cvss, HasExploit; FindingId 40: MitreTactics'
        $log = New-Object System.Collections.Generic.List[string]
        Write-SIDataParseAtInsertShadowLine -Summary $s -What 'views' -Log { param($l, $m) $log.Add("$l $m") }.GetNewClosure()
        $log[0] | Should -Match '^WARN views: 3 of 20 row\(s\)'
        $log[0] | Should -Match 'the values worked out here are kept'
    }
}

Describe 'on a real SQL Server: typed at insert = derived the old way, byte for byte' {
    BeforeAll {
        $script:LocalSql = $false
        try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
        if (-not $script:LocalSql) { return }
        $script:Db = 'siparseins_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $script:Calls = New-Object System.Collections.Generic.List[string]
        function script:New-LocalInvoke([string]$Db, $Calls) {
            $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH)"
            {
                param([string]$sql, $p, [string]$mode)
                if ($null -ne $Calls) { $Calls.Add($sql) }
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
        $script:Master = New-LocalInvoke 'master' $null
        [void](& $script:Master "CREATE DATABASE [$script:Db]" @{} 'nonquery')
        $script:Inv = New-LocalInvoke $script:Db $null
        $script:Spy = New-LocalInvoke $script:Db $script:Calls
        function script:Get-Rows([string]$Sql, $P) { $x = & $script:Inv $Sql $P 'reader'; , @($x) }
        function script:Get-Row([string]$Sql, $P) { $x = & $script:Inv $Sql $P 'reader'; @($x)[0] }
        $cfg = [System.IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-pro-settings.sql'))
        foreach ($pass in 1, 2) {
            foreach ($b in ([regex]::Split($cfg, '(?m)^\s*$'))) { if (([regex]::Replace($b, '(?m)^\s*--.*$', '')).Trim()) { [void](& $script:Inv $b @{} 'nonquery') } }
            [void](& $script:Inv $script:Schema @{} 'nonquery')
        }
        $script:Quiet = { param($l, $m) }
        $script:Plan = Get-SIDataParseAtInsertPlan -Invoke $script:Inv -Mode on

        # ---- the generated rows (the same shapes as SIv3-DeriveTyped): every field in many shapes ------------------------
        $long = { param([int]$n, [string]$tail = '') '"' + ('x' * ($n - $tail.Length)) + $tail + '"' }
        $str = @('"High"', '""', '"   "', 'null', $null, '["a","b"]', '{"x":1}', '"  padded  "', '123', 'true', (& $long 4000), (& $long 4001),
                 (& $long 3999), '"Critical"', '"Ünïcødé ☃ 漢字"', '"a\"quote"', '"line\nbreak"', '[]', '"Other"', '"  Windows "', '"x;y; z"', '"Very High"')
        $num = @('7.5', '"7.5"', '"  8 "', '1e2', '"abc"', 'null', $null, '[1]', '0', '-3', '1.30', '"1,5"', '""', (& $long 401 '1'), '1234567890123.25')
        $bool = @('true', 'false', '"true"', '"TRUE"', '1', '0', '"0"', 'null', $null, '"yes"', '[true]')
        $lst = @('["TA0001","TA0002","TA0001"]', '"TA0003, TA0004,TA0003"', '"T1059; T1059.001 ;T1003"', '[]', '""', 'null', $null, '["a, b"]', '[1,2]',
                 '{"o":1}', '["x\"y"]', '"  ;  ; "', '["ISO","ISO", ""]', '"CIS; NIST ;  ; CIS"')
        $fieldsS = @('RiskRating', 'si_risk_rating', 'si_category', 'Category', 'si_subcategory', 'SubCategory', 'Subcategory', 'si_class', 'AssetClass', 'Component',
                     'si_component', 'si_patch_cycle', 'si_os_family', 'si_servicenow_subci', 'si_affected_product', 'AssetId', 'SolutionVersion', 'CriticalityTier',
                     'cmdbId', 'cmdbName', 'si_fix_remediation', 'si_fix_recommended_update', 'si_fix_recommended_update_id', 'si_affected_software',
                     'RiskFactor_Probability_Detailed', 'RiskFactor_Consequence_Detailed', 'RiskFactor_Consequence_Impacts', 'RiskFactor_Probability_Impacts', 'RiskScore_Weight_Detailed')
        $fieldsN = @('RiskScoreTotal_Weighted', 'MaxCvssScore', 'Impact', 'RiskConsequenceBase', 'RiskConsequenceScore', 'RiskFactor_Consequence', 'RiskProbabilityBase',
                     'RiskProbabilityScore', 'RiskFactor_Probability', 'RiskScore_Weight_Factor')
        $fieldsL = @('MITRE_Tactics', 'MITRE_Techniques', 'ComplianceTags')
        $script:N = 900
        $items = New-Object System.Collections.Generic.List[object]
        for ($i = 1; $i -le $script:N; $i++) {
            $parts = New-Object System.Collections.Generic.List[string]
            $k = 0
            foreach ($f in $fieldsS) { $k++; $v = $str[($i * 7 + $k * 13) % $str.Count]; if ($null -ne $v) { $parts.Add(('"{0}":{1}' -f $f, $v)) } }
            foreach ($f in $fieldsN) { $k++; $v = $num[($i * 5 + $k * 11) % $num.Count]; if ($null -ne $v) { $parts.Add(('"{0}":{1}' -f $f, $v)) } }
            foreach ($f in $fieldsL) { $k++; $v = $lst[($i * 3 + $k * 7) % $lst.Count]; if ($null -ne $v) { $parts.Add(('"{0}":{1}' -f $f, $v)) } }
            $hb = $bool[$i % $bool.Count]; if ($null -ne $hb) { $parts.Add(('"HasExploit":{0}' -f $hb)) }
            $obj = '{' + ($parts -join ',') + '}'
            $json = switch ($true) {
                ($i % 53 -eq 0) { 'not json {'; break }
                ($i % 59 -eq 0) { $null; break }
                ($i % 61 -eq 0) { '[' + $obj + ']'; break }
                ($i % 67 -eq 0) { '[]'; break }
                ($i % 71 -eq 0) { "`r`n `t " + $obj; break }
                ($i % 73 -eq 0) { '{}'; break }
                default { $obj }
            }
            $items.Add((ConvertTo-Json -Compress -Depth 3 -InputObject ([ordered]@{
                AssetKey = $(if ($i % 37 -eq 0) { $null } else { 'asset-' + ($i % 211) }); AssetName = 'host-' + ($i % 211); ReportName = 'Report_' + ($i % 7)
                SecurityDomain = @('Endpoint', 'Identity', $null)[$i % 3]; ConfigurationId = 'CVE-2025-' + $i; Cve = $(if ($i % 3 -eq 0) { 'CVE-2025-' + $i } else { $null })
                Title = 'title ' + ($i % 50); Severity = @('High', 'Low', 'Very High', 'Medium', $null)[$i % 5]; Tier = $(if ($i % 9 -eq 0) { $null } else { $i % 4 })
                RiskScore = $(if ($i % 41 -eq 0) { $null } else { ($i % 97) / 7.0 }); DetailJson = $json; ExemptionId = $(if ($i % 5 -eq 0) { 100 + $i % 3 } else { $null })
                RaReport = 1 + ($i % 3); RaBucket = '1/1'; RaSeq = $i; RaSort = ($i % 97) / 7.0; RaInView = $true; RaTraceSuffixed = $false
                RaTraceKey = 'k' + $i; RaFindingKey = 'fk' + $i; RaAssetId = 'aid-' + ($i % 211); RaAssetTier = ($i % 4)
            })))
        }
        $script:Items = $items.ToArray()

        function script:New-Collection([string]$At) {
            [int](& $script:Inv "INSERT sidata.Collection (CollectionTime, Kind, Status, [Rows]) VALUES (@t, N'Detailed', N'Complete', @n); SELECT CONVERT(int, SCOPE_IDENTITY());" @{ t = $At; n = $script:N } 'scalar')
        }
        # Risk Analysis' insert, exactly as Write-RAStreamRows sends it (Write-SIDataJsonRows, chunks); -Plan = the switch on
        function script:Add-RaRows([int]$Cid, $Plan) {
            $ch = [ref][long]60000
            $n = Write-SIDataJsonRows -Invoke $script:Inv -Sql (Get-RAStreamInsertFindingSql -Typed $Plan) -Items $script:Items -Params @{ CollectionId = [string]$Cid } -ChunkChars $ch -What 'test'
            $n | Should -Be $script:N
        }
        # rows the data sync carries in (CarriedFrom; never marked)
        function script:Add-Carried([int]$Cid) {
            $before = [long](& $script:Inv 'SELECT ISNULL(MAX(FindingId), 0) FROM sidata.Finding WHERE CollectionId = @c' @{ c = $Cid } 'scalar')
            $carry = @($script:Items | Select-Object -First 200 | ForEach-Object { $h = $_ | ConvertFrom-Json -AsHashtable; $h.AssetKey = 'carried-' + $h.AssetName; $h })
            [void](& $script:Inv (Get-SIDataInsertFindingSql) @{ CollectionId = $Cid; j = (ConvertTo-Json -InputObject $carry -Depth 3 -Compress) } 'scalar')
            [void](& $script:Inv 'UPDATE sidata.Finding SET CarriedFrom = ''2026-11-01T04:00:00'' WHERE CollectionId = @c AND FindingId > @b' @{ c = $Cid; b = $before } 'nonquery')
        }
        # THE OLD WAY: the derive with every switch on, the setting off
        function script:Invoke-OldDerive([int]$Cid) {
            $bs = [long]97
            Invoke-SIDataDeriveCollection -Invoke $script:Inv -CollectionId $Cid -Fix -Services -BatchSize ([ref]$bs) -TargetMs 1 -ParseAtInsert off -Log $script:Quiet
        }
        $script:Skip = @('FindingId', 'CollectionId', 'TypedOnInsert', 'TypedStatement')
        function script:Read-Findings([int]$Cid) { Get-Rows 'SELECT * FROM sidata.Finding WHERE CollectionId = @c ORDER BY FindingId' @{ c = $Cid } }
        function script:Compare-Findings($A, $B) {
            $diff = New-Object System.Collections.Generic.List[string]
            if ($A.Count -ne $B.Count) { $diff.Add(('row count {0} vs {1}' -f $A.Count, $B.Count)); return , $diff.ToArray() }
            $cols = @($A[0].Keys | Where-Object { $_ -notin $script:Skip })
            for ($i = 0; $i -lt $A.Count; $i++) {
                foreach ($c in $cols) {
                    $x = $A[$i][$c]; $y = $B[$i][$c]
                    $same = if ($null -eq $x -or $null -eq $y) { $null -eq $x -and $null -eq $y }
                            elseif ($x -is [string]) { [string]::Equals($x, [string]$y, [StringComparison]::Ordinal) }
                            elseif ($x -is [double]) { [BitConverter]::DoubleToInt64Bits([double]$x) -eq [BitConverter]::DoubleToInt64Bits([double]$y) }
                            elseif ($x -is [byte[]]) { [Convert]::ToBase64String($x) -eq [Convert]::ToBase64String($y) }
                            else { $x -eq $y }
                    if (-not $same) { $diff.Add(('row {0} column {1}: old [{2}] new [{3}]' -f $i, $c, $x, $y)) }
                }
            }
            , $diff.ToArray()
        }
        function script:Read-Facets([int]$Cid) { Get-Rows 'SELECT Facet, Value, Findings, Assets, ScoreTotal, WeightedTotal, MaxScore FROM sidata.FindingFacet WHERE CollectionId = @c ORDER BY Facet, Value' @{ c = $Cid } }
        function script:Assert-SameFacets($A, $B) {
            $B.Count | Should -Be $A.Count
            for ($i = 0; $i -lt $A.Count; $i++) {
                foreach ($k in 'Facet', 'Value', 'Findings', 'Assets') { $B[$i][$k] | Should -Be $A[$i][$k] -Because ("facet row {0} {1}" -f $i, $k) }
                foreach ($k in 'ScoreTotal', 'WeightedTotal', 'MaxScore') {
                    $x = $A[$i][$k]; $y = $B[$i][$k]
                    if ($null -eq $x -or $null -eq $y) { $y | Should -Be $x; continue }
                    [Math]::Abs([double]$x - [double]$y) | Should -BeLessOrEqual ([Math]::Max(1e-9, 1e-12 * [Math]::Abs([double]$x)))
                }
            }
        }
        function script:Show-Diff($d) { if ($d.Count) { Write-Host ("DIFFERENCES ({0}):`n{1}" -f $d.Count, (($d | Select-Object -First 30) -join "`n")) } }
    }
    AfterAll {
        if (-not $script:LocalSql -or -not $script:Master) { return }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        [void](& $script:Master "ALTER DATABASE [$script:Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:Db]" @{} 'nonquery')
    }

    It 'the plan from the database: every switch on, mask 63; off = not ready' -Skip:(-not $script:LocalSql) {
        $p = Get-SIDataParseAtInsertPlan -Invoke $script:Inv -Mode on
        $p.Ready | Should -BeTrue
        foreach ($k in 'Services', 'Fix', 'Category', 'RowColumns', 'RiskParts') { $p.$k | Should -BeTrue -Because $k }
        $p.Mask | Should -Be 63
        (Get-SIDataParseAtInsertPlan -Invoke $script:Inv -Mode off).Ready | Should -BeFalse
    }
    It 'rows typed at insert carry byte-identical values to the same rows derived the old way; on: the derive does facets and stamps only' -Skip:(-not $script:LocalSql) {
        $a = New-Collection '2026-11-23T01:00:00'; $b = New-Collection '2026-11-23T02:00:00'
        Add-RaRows $a $null
        Add-RaRows $b $script:Plan
        [int](& $script:Inv 'SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = @c AND TypedOnInsert = 63' @{ c = $b } 'scalar') | Should -Be $script:N
        [int](& $script:Inv 'SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = @c AND TypedOnInsert IS NOT NULL' @{ c = $a } 'scalar') | Should -Be 0
        $oldR = Invoke-OldDerive $a
        $oldR.Findings | Should -BeGreaterThan 700
        # straight after the insert, BEFORE any derive of b: every column of every row as the old way left it
        $fa = Read-Findings $a; $fb = Read-Findings $b
        $d = Compare-Findings $fa $fb; Show-Diff $d
        $d.Count | Should -Be 0
        Write-Host ('PARSE-AT-INSERT-SAME: {0} rows x {1} columns compared, 0 differences' -f $fa.Count, (@($fa[0].Keys).Count - $script:Skip.Count))
        # the comparison is of filled values, and it is not blind
        @($fb | Where-Object { $null -ne $_['RiskScoreWeighted'] }).Count | Should -BeGreaterThan 100
        @($fb | Where-Object { $null -ne $_['MitreTactics'] }).Count | Should -BeGreaterThan 100
        @($fb | Where-Object { $null -ne $_['RaScopeCategory'] }).Count | Should -BeGreaterThan 100
        @($fb | Where-Object { $null -ne $_['RiskAssetSide'] }).Count | Should -BeGreaterThan 100
        @($fb | Where-Object { $null -ne $_['CmdbId'] }).Count | Should -BeGreaterThan 100
        @($fb | Where-Object { $null -ne $_['Cvss'] }).Count | Should -BeGreaterThan 50
        @($fb | Where-Object { $null -ne $_['Cve'] }).Count | Should -BeGreaterThan 200
        @($fb | Where-Object { $_['DetailIsJson'] -eq $false }).Count | Should -BeGreaterThan 10
        $fb[17]['RiskRating'] = 'changed'
        $neg = Compare-Findings $fa $fb; $neg.Count | Should -Be 1
        # on: no typed range statement, the facets and the stamps as the old way
        $script:Calls.Clear()
        $bs = [long]97
        $log = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataDeriveCollection -Invoke $script:Spy -CollectionId $b -Fix -Services -BatchSize ([ref]$bs) -TargetMs 1 -ParseAtInsert on -Log { param($l, $m) $log.Add("$l $m") }.GetNewClosure()
        $r.ParseAtInsert | Should -Be 'on'
        $r.TypedAtInsert | Should -Be $script:N
        $r.Findings | Should -Be 0
        @($script:Calls | Where-Object { $_ -match 'DECLARE @o TABLE' }).Count | Should -Be 0 -Because 'no row is typed again'
        @($script:Calls | Where-Object { $_ -match 'FindingFacet' }).Count | Should -BeGreaterThan 0
        @($log | Where-Object { $_ -match "^INFO views .*$($script:N) finding row\(s\) got their view values when Risk Analysis stored them; 0 more" }).Count | Should -Be 1
        $st = Get-Row 'SELECT TypedAt, RaRowsAt, RiskPartsAt, DerivedAt FROM sidata.Collection WHERE CollectionId = @c' @{ c = $b }
        foreach ($k in 'TypedAt', 'RaRowsAt', 'RiskPartsAt', 'DerivedAt') { $st[$k] | Should -Not -BeNullOrEmpty -Because "$k is stamped" }
        $d2 = Compare-Findings (Read-Findings $a) (Read-Findings $b); Show-Diff $d2
        $d2.Count | Should -Be 0
        Assert-SameFacets (Read-Facets $a) (Read-Facets $b)
    }
    It 'on: rows carried in afterwards (no mark) are still derived, the same as the old way' -Skip:(-not $script:LocalSql) {
        $a = New-Collection '2026-11-23T03:00:00'; $b = New-Collection '2026-11-23T04:00:00'
        Add-RaRows $a $null; Add-RaRows $b $script:Plan
        Add-Carried $a; Add-Carried $b
        $null = Invoke-OldDerive $a
        $bs = [long]97
        $r = Invoke-SIDataDeriveCollection -Invoke $script:Inv -CollectionId $b -Fix -Services -BatchSize ([ref]$bs) -TargetMs 1 -ParseAtInsert on -Log $script:Quiet
        $r.TypedAtInsert | Should -Be $script:N
        $r.Findings | Should -BeGreaterThan 150 -Because 'the carried rows are derived here'
        $r.Findings | Should -BeLessOrEqual 200
        $d = Compare-Findings (Read-Findings $a) (Read-Findings $b); Show-Diff $d
        $d.Count | Should -Be 0
        @((Read-Findings $b) | Where-Object { $null -ne $_['CarriedFrom'] -and $null -ne $_['RaScopeCategory'] }).Count | Should -BeGreaterThan 20
        Assert-SameFacets (Read-Facets $a) (Read-Facets $b)
    }
    It 'rows typed by an earlier statement (fingerprint A) are typed again by the current one (B) and equal a fresh derive' -Skip:(-not $script:LocalSql) {
        $a = New-Collection '2026-11-23T12:00:00'; $b = New-Collection '2026-11-23T13:00:00'
        Add-RaRows $a $null
        $null = Invoke-OldDerive $a
        # "the earlier release": one expression different (a row value read from another field), its own fingerprint
        $keep = $script:SIDataRowColumns['RaRowSolutionVersion'].Fields
        try {
            $script:SIDataRowColumns['RaRowSolutionVersion'].Fields = @('RiskRating')
            $planA = Get-SIDataParseAtInsertPlan -Invoke $script:Inv -Mode on
            Add-RaRows $b $planA
        } finally { $script:SIDataRowColumns['RaRowSolutionVersion'].Fields = $keep }
        $planA.Print | Should -Not -Be $script:Plan.Print
        [int](& $script:Inv ('SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = @c AND TypedStatement = 0x' + $planA.Print) @{ c = $b } 'scalar') | Should -Be $script:N
        # the earlier statement really wrote other values (the check is not blind)
        $pre = Compare-Findings (Read-Findings $a) (Read-Findings $b)
        @($pre | Where-Object { $_ -match 'column RaRowSolutionVersion' }).Count | Should -BeGreaterThan 100
        # the current release, setting on: nothing counts as typed, every row is derived again
        $bs = [long]97
        $r = Invoke-SIDataDeriveCollection -Invoke $script:Inv -CollectionId $b -Fix -Services -BatchSize ([ref]$bs) -TargetMs 1 -ParseAtInsert on -Log $script:Quiet
        $r.TypedAtInsert | Should -Be 0
        $r.Findings | Should -Be $( (Read-Findings $a) | Where-Object { $_['DetailIsJson'] } | Measure-Object ).Count
        $d = Compare-Findings (Read-Findings $a) (Read-Findings $b); Show-Diff $d
        $d.Count | Should -Be 0
        Assert-SameFacets (Read-Facets $a) (Read-Facets $b)
        # the row-values fill does not skip them either
        $c = New-Collection '2026-11-23T14:00:00'
        try { $script:SIDataRowColumns['RaRowSolutionVersion'].Fields = @('RiskRating'); Add-RaRows $c $planA } finally { $script:SIDataRowColumns['RaRowSolutionVersion'].Fields = $keep }
        (Invoke-SIDataRowColumnsFill -Invoke $script:Inv -CollectionId $c -TargetMs 1 -ParseAtInsert on).Rows | Should -Be $r.Findings
        $dc = Compare-Findings (Read-Findings $a) (Read-Findings $c)
        @($dc | Where-Object { $_ -match 'column (RaRow|RaScope|RaFill)' }).Count | Should -Be 0
    }
    It 'shadow: 0 differences on identical rows; a forced difference is found (id + column, never the value) and the derive''s value kept' -Skip:(-not $script:LocalSql) {
        $a = New-Collection '2026-11-23T05:00:00'; $b = New-Collection '2026-11-23T06:00:00'; $c = New-Collection '2026-11-23T07:00:00'
        Add-RaRows $a $null; Add-RaRows $b $script:Plan; Add-RaRows $c $script:Plan
        $null = Invoke-OldDerive $a
        $bs = [long]97
        $log = New-Object System.Collections.Generic.List[string]
        $r = Invoke-SIDataDeriveCollection -Invoke $script:Inv -CollectionId $b -Fix -Services -BatchSize ([ref]$bs) -TargetMs 1 -ParseAtInsert shadow -Log { param($l, $m) $log.Add("$l $m") }.GetNewClosure()
        $r.ParseAtInsert | Should -Be 'shadow'
        $r.Findings | Should -Be $( (Read-Findings $a) | Where-Object { $_['DetailIsJson'] } | Measure-Object ).Count -Because 'shadow derives every row as before'
        $r.Shadow.Compared | Should -Be $script:N
        $r.Shadow.Differ | Should -Be 0
        @($log | Where-Object { $_ -match "^INFO views .*$($script:N) row\(s\) .* all identical" }).Count | Should -Be 1
        # one forced difference: a typed value changed after the insert
        $id = [long](& $script:Inv "SELECT MIN(FindingId) FROM sidata.Finding WHERE CollectionId = @c AND DetailIsJson = 1 AND RiskRating IS NOT NULL" @{ c = $c } 'scalar')
        [void](& $script:Inv "UPDATE sidata.Finding SET RiskRating = N'tampered-x' WHERE FindingId = @i" @{ i = $id } 'nonquery')
        $bs = [long]97
        $log2 = New-Object System.Collections.Generic.List[string]
        $r2 = Invoke-SIDataDeriveCollection -Invoke $script:Inv -CollectionId $c -Fix -Services -BatchSize ([ref]$bs) -TargetMs 1 -ParseAtInsert shadow -Log { param($l, $m) $log2.Add("$l $m") }.GetNewClosure()
        $r2.Shadow.Differ | Should -Be 1
        $r2.Shadow.Sample | Should -Be ("FindingId {0}: RiskRating" -f $id)
        $w = @($log2 | Where-Object { $_ -match '^WARN views' })
        $w.Count | Should -Be 1
        $w[0] | Should -Match ("1 of {0} row\(s\).*FindingId {1}: RiskRating" -f $script:N, $id)
        $w[0] | Should -Not -Match 'tampered'
        # the derive's value is what stays: every row as the old way
        $d = Compare-Findings (Read-Findings $a) (Read-Findings $c); Show-Diff $d
        $d.Count | Should -Be 0
    }
    It 'the vulnerability step''s row-values fill: on leaves the typed rows alone, shadow compares them' -Skip:(-not $script:LocalSql) {
        $a = New-Collection '2026-11-23T08:00:00'; $b = New-Collection '2026-11-23T09:00:00'; $c = New-Collection '2026-11-23T10:00:00'
        Add-RaRows $a $null; Add-RaRows $b $script:Plan; Add-RaRows $c $script:Plan
        $fa = Invoke-SIDataRowColumnsFill -Invoke $script:Inv -CollectionId $a -TargetMs 1 -ParseAtInsert off
        $fa.Filled | Should -BeTrue; $fa.Rows | Should -BeGreaterThan 700
        $fb = Invoke-SIDataRowColumnsFill -Invoke $script:Inv -CollectionId $b -TargetMs 1 -ParseAtInsert on
        $fb.Filled | Should -BeTrue; $fb.Rows | Should -Be 0 -Because 'every row got its row values when it was stored'
        $log = New-Object System.Collections.Generic.List[string]
        $fc = Invoke-SIDataRowColumnsFill -Invoke $script:Inv -CollectionId $c -TargetMs 1 -ParseAtInsert shadow -Log { param($l, $m) $log.Add("$l $m") }.GetNewClosure()
        $fc.Rows | Should -Be $fa.Rows
        $fc.Shadow.Compared | Should -Be $script:N
        $fc.Shadow.Differ | Should -Be 0
        @($log | Where-Object { $_ -match '^INFO row values .* all identical' }).Count | Should -Be 1
        foreach ($x in $b, $c) {
            $d = Compare-Findings (Read-Findings $a) (Read-Findings $x)
            # only the row values were filled on a; b / c carry every typed column -- compare the row values only
            $d2 = @($d | Where-Object { $_ -match 'column (RaRow|RaScope|RaFill)' }); Show-Diff $d2
            $d2.Count | Should -Be 0
        }
    }
    It 'a trace-name update re-types its rows (the shadow then finds no difference)' -Skip:(-not $script:LocalSql) {
        $b = New-Collection '2026-11-23T11:00:00'
        Add-RaRows $b $script:Plan
        $ids = @((Get-Rows "SELECT TOP (5) FindingId FROM sidata.Finding WHERE CollectionId = @c AND DetailIsJson = 1 AND LEFT(LTRIM(DetailJson), 1) = N'{' ORDER BY FindingId" @{ c = $b }) | ForEach-Object { [long]$_['FindingId'] })
        # a stale typed value on those rows: the trace update must work them out again from the stored text
        [void](& $script:Inv ("UPDATE sidata.Finding SET RaCategory = N'stale', ViewComponent = N'stale' WHERE CollectionId = @c AND FindingId IN ({0})" -f ($ids -join ',')) @{ c = $b } 'nonquery')
        $fix = @($ids | ForEach-Object { ConvertTo-SIDataJsonObject -Values ([ordered]@{ Id = $_; N = "trace-$_"; I = 'abcd' }) })
        $ch = [ref][long]60000
        $n = Write-SIDataJsonRows -Invoke $script:Inv -Sql (Get-RAStreamTraceUpdateSql -Grain Detailed -Typed $script:Plan) -Items $fix -Params @{ CollectionId = [string]$b } -ChunkChars $ch -What 'trace names'
        $n | Should -Be $ids.Count
        [int](& $script:Inv "SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = @c AND RaTraceSuffixed = 1 AND TypedOnInsert = 63 AND JSON_VALUE(DetailJson, '$.TraceName') LIKE N'trace-%'" @{ c = $b } 'scalar') | Should -Be $ids.Count
        [int](& $script:Inv "SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = @c AND (RaCategory = N'stale' OR ViewComponent = N'stale')" @{ c = $b } 'scalar') | Should -Be 0
        $bs = [long]97
        $r = Invoke-SIDataDeriveCollection -Invoke $script:Inv -CollectionId $b -Fix -Services -BatchSize ([ref]$bs) -TargetMs 1 -ParseAtInsert shadow -Log $script:Quiet
        $r.Shadow.Differ | Should -Be 0
    }
}
