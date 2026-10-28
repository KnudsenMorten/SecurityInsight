#Requires -Version 5.1
<#
    #638 / #641 -- RISK ANALYSIS WRITES ITS RESULT TO SQL A BUCKET AT A TIME, AND LOSES NOTHING.

    Owner 2026-10-13: "ra must newer only be in memory, as memory will newer support millions of rows" / "we can NOT loose
    data, as customers will loose trust".

    What this file pins:
      * PARITY: the same canned query results, through the OLD path (every bucket gathered in memory, then scored, merged,
        traced and sorted as one) and the NEW path (scored per bucket, written to SQL, finished in SQL, read back in pages),
        give the same rows, the same Summary groups, the same trace ids, the same trend rollup and the same counts -- and
        the order differs only among rows of EQUAL score (said in DESIGN.md);
      * a retried bucket never doubles; a report that starts again with more buckets, or fails, keeps none of its rows;
      * a finding two buckets both return is kept once; two assets sharing a trace name in different buckets get the id;
      * the BUCKET INVARIANT (#641): the union of a report's buckets is the unbucketed result -- for the main loop, a bucket
        count that went up (escalation), the sub-bucket split and a late retry, and through the SQL writer with retries,
        a complete bucket and re-runs: the stored set equals the whole;
      * the completeness verdict per report (#641); the data sync never loads a Risk Analysis-written collection from Log
        Analytics, and completes it from what Risk Analysis wrote;
      * the CI context of one bucket is read from sidata.Ci -- by an id the CI carries, or a name only ONE CI has.
    The engine is one large script that cannot be dot-sourced: its wiring is asserted on the comment-stripped source, the
    pieces it calls are run for real. The SQL parts run against the test VM's SQL Server Express and skip, saying so,
    where there is none.
#>

# decided at discovery (as SIv3-CiBuildSql): the SQL Describe below is skipped -- and says so -- where no local SQL Server runs
$script:HasSql = [bool](Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')
# Risk Analysis' SQL path is core (both editions); the SQL block also builds the database from the data schema and checks
# the data sync's side (adopting what RA wrote) -- both Pro files, so that block runs only where Test-Path finds them
$script:HasSql = $script:HasSql -and (Test-Path -LiteralPath ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'sql', 'si-data-schema.sql')))

BeforeAll {
    $script:SIRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $ra = Join-Path $script:SIRoot 'engine\risk-analysis\_shared'
    function script:Write-Info { param($m) }
    function script:Write-Warn2 { param($m) }
    function script:Write-Ok { param($m) }
    function script:Write-Diag { param($m) }
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ra 'RA-ExcelReport.ps1'), [ref]$null, [ref]$null)
    . ([scriptblock]::Create(($ast.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'New-RiskIndex' }, $true)).Extent.Text))
    $ast2 = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $ra 'RA-ProfileAugment.ps1'), [ref]$null, [ref]$null)
    . ([scriptblock]::Create(($ast2.Find({ param($x) $x -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -eq 'Get-SISha256Bucket' }, $true)).Extent.Text))
    foreach ($f in 'RA-RiskIndexOrder.ps1', 'RA-RiskIndexSi.ps1', 'RA-FactorKeys.ps1', 'RA-CiContext.ps1', 'RA-RiskScore.ps1', 'RA-RowShaping.ps1', 'RA-SummaryBucketMerge.ps1',
                   'RA-Findings.ps1', 'RA-ColumnFillGuard.ps1', 'RA-SqlStream.ps1') { . (Join-Path $ra $f) }
    foreach ($f in 'engine\_shared\data-sql\SI-DataModel.ps1', 'engine\_shared\data-sql\SI-DataSql.ps1', 'engine\_shared\data-sql\SI-DataSummary.ps1',
                   'engine\asset-trend\_shared\SI-TrendRollup.ps1') { . (Join-Path $script:SIRoot $f) }
    # the data sync's side (Pro): only the real-SQL block uses it, and that block runs only where Test-Path finds these files
    foreach ($f in 'engine\pro-data\_shared\SI-DataKql.ps1', 'engine\pro-data\_shared\SI-DataSync.ps1') {
        $p = Join-Path $script:SIRoot $f; if (Test-Path -LiteralPath $p) { . $p }
    }
    . (Join-Path $script:SIRoot 'engine\_shared\SI-Yaml.ps1')
    $global:RA_FactorAliasMap = $null; $global:RA_FactorImpactMap = $null; $global:RA_FactorCatalogFactors = $null; $global:RA_FactorCatalog = $null
    $script:Index = New-RiskIndex -CsvRows @(Import-Csv -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\riskscore.index.locked.csv'))
    $script:Catalog = Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml') | ConvertFrom-SIYaml
    $script:CveQ = [string]($script:Catalog.Reports | Where-Object ReportName -eq 'Device_Missing_CVEs_Summary').ReportQuery
    $script:Tiers = @('Critical - tier 0', 'High - tier 1', 'Medium - tier 2', 'Low - tier 3')
    $ProgressPreference = 'SilentlyContinue'

    # ---- canned query results ---------------------------------------------------------------------------------------
    # Detailed: 40 assets x 3 CVEs; two assets share a NAME (different ids -- the trace name needs the id); one finding is
    # returned twice (once in another bucket: a duplicate the scoring keeps once).
    function script:New-DetailedRows {
        $out = New-Object System.Collections.Generic.List[object]
        for ($a = 0; $a -lt 40; $a++) {
            $name = if ($a -eq 7 -or $a -eq 23) { 'shared-name' } else { "host$a" }
            for ($c = 0; $c -lt 3; $c++) {
                $out.Add([pscustomobject][ordered]@{ SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs'; ConfigurationName = "CVE-2026-$c"
                    ConfigurationId = "CVE-2026-$c"; SecuritySeverity = @('High', 'Medium', 'Low')[$c]; CriticalityTier = ($a % 4); CriticalityTierLevel = $script:Tiers[$a % 4]
                    AssetName = $name; SI_AssetId = "aid-$a"; MdeDeviceId = "dev-$a"; DeviceKey = "dev-$a"
                    RiskFactor_Probability_Detailed = ''; RiskFactor_Consequence_Detailed = ''; LastSeen = [datetime]::SpecifyKind([datetime]'2026-10-12T10:00:00', 'Utc') })
            }
        }
        $out.ToArray()
    }
    function script:Score([object[]]$Rows, [string]$Report = 'Inv_Detailed') {
        @(Calculate-RiskScore -Rows @($Rows) -RiskIndex $script:Index -CategoryInputName Category -SubCategoryInputName Subcategory -ConfigurationIdInputName ConfigurationId `
            -SecuritySeverityInputName SecuritySeverity -CriticalityTierLevelInputName CriticalityTierLevel -SecurityDomainInputName SecurityDomain -ReportName $Report)
    }
    function script:Copy-Rows([object[]]$Rows) { @($Rows | ForEach-Object { $_.PSObject.Copy() }) }
    function script:Split-Buckets([object[]]$Rows, [int]$N) {
        $b = @{}; for ($i = 0; $i -lt $N; $i++) { $b[$i] = New-Object System.Collections.Generic.List[object] }
        foreach ($r in $Rows) { $b[[int](Get-SISha256Bucket -Key ([string]$r.DeviceKey) -BucketCount $N)].Add($r) }
        $b
    }
    function script:Sig($r) { '{0}|{1}|{2}|{3}|{4}' -f $r.AssetName, $r.ConfigurationId, $r.TraceName, $r.TraceID, ([double]$r.RiskScoreTotal_Weighted) }
    # a Device_Missing_CVEs_Summary row as the report's query projects it
    function script:New-CveRow($tier, $assets, $sw, $fix, $fixId, $tags) {
        $rem = if ($fix) { 'Install the security updates ' + $fix.Replace(';', ', ') + ' on the impacted devices; update the other affected software to versions that fix the listed CVEs.' } else { 'Update the affected software on the impacted devices to versions that fix the listed CVEs.' }
        [pscustomobject][ordered]@{ SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs (Missing Updates)'; ConfigurationName = 'Update vulnerable software'
            ConfigurationId = 'CVE'; Impact = 5; SecuritySeverity = 'High'; CriticalityTier = $tier; CriticalityTierLevel = $script:Tiers[$tier]
            cmdbId = ''; cmdbName = ''; cmdbCriticality = ''; cmdbDataSensitivity = ''; RiskFactor_Consequence = 1; RiskFactor_Consequence_Detailed = 'RemoteCodeExec'
            RiskFactor_Probability = 1; RiskFactor_Probability_Detailed = 'ExploitSignals'; RiskFactorIds = ''; RiskScore_Weight_Detailed = ''; RiskScore_Weight_Factor = 100; RiskFactor_Weight = 100
            ImpactedAssetCount = @($assets).Count; ImpactedAssetsList = [object[]]@($assets); ImpactedAssetPairs = [object[]]@($assets | ForEach-Object { "$_|id-$_" })
            UniqueIssues = 1; IssueList = [object[]]@('CVE-1'); MoreDetails = 'CVE-1 => https://nvd/CVE-1'
            si_affected_software = $sw; si_fix_recommended_update = $fix; si_fix_recommended_update_id = $fixId; si_fix_remediation = $rem
            si_epss = 0.5; si_published = '2026-01-01T00:00:00Z'; si_cve_tags = $tags }
    }

    # ---- the local SQL Server (test VM): a fresh database per Describe, the engine's seam over one connection ---------
    # (whether the local SQL Server runs is decided at discovery, above -- so -Skip sees it)
    function script:Open-TestDb {
        $name = 'si_test_rastream_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$name]"; $c.CommandTimeout = 300; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
        $cn = New-Object System.Data.SqlClient.SqlConnection ("Server=.\SQLEXPRESS;Database=$name;Integrated Security=SSPI;Connection Timeout=30;Pooling=false")
        $cn.Open()
        foreach ($f in 'sql\si-data-schema.sql', 'sql\si-identity-schema.sql') { $c = $cn.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = [IO.File]::ReadAllText((Join-Path $script:SIRoot $f)); [void]$c.ExecuteNonQuery() }
        # the engine as setup grants it: read + write, no DDL
        $c = $cn.CreateCommand(); $c.CommandText = 'CREATE USER si_engine WITHOUT LOGIN; ALTER ROLE db_datareader ADD MEMBER si_engine; ALTER ROLE db_datawriter ADD MEMBER si_engine;'; [void]$c.ExecuteNonQuery()
        $c = $cn.CreateCommand(); $c.CommandText = "EXECUTE AS USER = N'si_engine';"; [void]$c.ExecuteNonQuery()
        $script:Conn = $cn
        $name
    }
    function script:Close-TestDb([string]$Name) {
        if ($script:Conn) { try { $script:Conn.Dispose() } catch { }; $script:Conn = $null }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        $m = New-Object System.Data.SqlClient.SqlConnection 'Server=.\SQLEXPRESS;Database=master;Integrated Security=SSPI;Connection Timeout=30'
        $m.Open(); try { $c = $m.CreateCommand(); $c.CommandTimeout = 300; $c.CommandText = "ALTER DATABASE [$Name] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$Name]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
    }
    # the production seam's shape (New-SIDataSqlInvoke): 'reader' answers ONE array of hashtables
    $script:Seam = {
        param($Sql, $Params, $Mode)
        $c = $script:Conn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 120
        if ($Params) { foreach ($k in $Params.Keys) { $v = $Params[$k]; [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $v) { [System.DBNull]::Value } else { $v })) } }
        switch ($Mode) {
            { $_ -in 'reader', 'rows' } {
                $rd = $c.ExecuteReader(); $out = New-Object System.Collections.Generic.List[object]
                try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $out.Add($h) } } finally { $rd.Close() }
                , $out.ToArray()
            }
            'scalar' { $c.ExecuteScalar() }
            default { [void]$c.ExecuteNonQuery() }
        }
    }
    function script:Q([string]$Sql) { @(& $script:Seam $Sql @{} 'reader') | ForEach-Object { $_ } }
    $script:NoLog = { param($l, $m) }
}

Describe 'whether the result goes to SQL, when a setting is not set at all' {
    # live 2026-10-13: the internal install's Risk Analysis stopped before its first report -- SI_RA_ResultInSql was not set
    It 'a missing switch neither throws nor turns the stream off; off / false / 0 / no turn it off' {
        { Test-RAStreamWanted -Globals @{ SI_ProSqlServer = 's'; SI_ProSqlDatabase = 'd' } } | Should -Not -Throw
        Test-RAStreamWanted -Globals @{ SI_ProSqlServer = 's'; SI_ProSqlDatabase = 'd' } | Should -BeTrue
        foreach ($v in 'off', 'false', '0', 'no') { Test-RAStreamWanted -Globals @{ SI_RA_ResultInSql = $v; SI_ProSqlServer = 's'; SI_ProSqlDatabase = 'd' } | Should -BeFalse }
        Test-RAStreamWanted -Globals @{ SI_RA_ResultInSql = 'on' } | Should -BeFalse -Because 'no Pro database configured'
    }
    It 'reading the globals (no hashtable): an unset switch does not throw' {
        Remove-Variable -Name SI_RA_ResultInSql -Scope Global -ErrorAction SilentlyContinue
        { Test-RAStreamWanted } | Should -Not -Throw
    }
}

Describe 'the stored row is the row (pure)' {
    It 'keeps every value with a legal name, drops null / empty text / empty lists (as the data sync''s DetailJson), and reads back in the report''s columns' {
        $dc = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $t = [datetime]::SpecifyKind([datetime]'2026-10-13T08:30:00', 'Utc')
        $row = [pscustomobject][ordered]@{ A = 'x'; B = 5; C = 7.5; D = $true; E = $null; F = ''; G = @(); H = @('a', 'b'); I = $t; 'Bad@odata.type' = '#Int64'; J = [pscustomobject]@{ k = 1 } }
        $j = ConvertTo-RAStreamJson -Row $row -DateCols $dc
        $j.Illegal | Should -Be 1 -Because ("one artefact name is left out; the stored row: " + $j.Json)
        $j.Json | Should -Not -Match '"E"|"F"|"G"|odata'
        $back = ConvertFrom-RAStreamJson -Json $j.Json -Columns @('I', 'A', 'B', 'C', 'D', 'E', 'H', 'J') -DateCols $dc
        @($back.PSObject.Properties.Name)[0..6] | Should -Be @('I', 'A', 'B', 'C', 'D', 'E', 'H')
        $back.A | Should -Be 'x'; [long]$back.B | Should -Be 5; [double]$back.C | Should -Be 7.5; $back.D | Should -BeTrue
        $back.E | Should -BeNullOrEmpty
        @($back.H) | Should -Be @('a', 'b')
        $back.I | Should -BeOfType [datetime]
        $back.I.ToUniversalTime() | Should -Be $t
        $back.J.k | Should -Be 1 -Because ("a rich value comes back as an object; the stored row: " + $j.Json)
    }
    It 'keeps a string that only LOOKS like a date a string (no guessing)' {
        $back = ConvertFrom-RAStreamJson -Json (ConvertTo-RAStreamJson -Row ([pscustomobject]@{ S = '2026-10-13T08:30:00Z' })).Json
        $back.S | Should -BeOfType [string]
    }
    It 'the completeness verdict: equal = Complete, different = NotComplete (named numbers), no count = Unverified' {
        (Get-RACompletenessVerdict -Expected 10 -Retrieved 10).State | Should -Be 'Complete'
        (Get-RACompletenessVerdict -Expected 3 -Retrieved 4).State | Should -Be 'Complete' -Because 'more rows than the count is no loss (customer G 2026-10-15)'
        $v = Get-RACompletenessVerdict -Expected 12 -Retrieved 10
        $v.State | Should -Be 'NotComplete'; $v.Reason | Should -Match '12' ; $v.Reason | Should -Match '10'
        (Get-RACompletenessVerdict -Expected $null -Retrieved 10 -CountError '413').State | Should -Be 'Unverified'
    }
    It 'per-bucket column-fill snapshots add up to the whole report''s snapshot' {
        $rows = @(1..10 | ForEach-Object { [pscustomobject]@{ A = $(if ($_ % 2) { 'x' } else { '' }); B = $_ } })
        $whole = Get-RAColumnFillSnapshot -Rows $rows
        $m = Merge-RAColumnFillSnapshot -Into (Get-RAColumnFillSnapshot -Rows $rows[0..3]) -Add (Get-RAColumnFillSnapshot -Rows $rows[4..9])
        foreach ($k in $whole.Keys) { [long]$m[$k] | Should -Be ([long]$whole[$k]) -Because $k }
    }
    It 'the de-duplication key is the one the scoring de-duplicates on: two rows it keeps once share a key, the others differ' {
        $rows = @(New-DetailedRows)
        $dup = $rows[5].PSObject.Copy()
        $scored = @(Score -Rows (@($rows) + @($dup)))
        $scored.Count | Should -Be $rows.Count -Because 'the scoring keeps the duplicate once'
        $keys = @($rows | ForEach-Object { Get-RARowDedupKey -Row $_ })
        @($keys | Select-Object -Unique).Count | Should -Be $rows.Count
        (Get-RARowDedupKey -Row $dup) | Should -Be $keys[5]
    }
}

Describe 'the BUCKET INVARIANT: the union of a report''s buckets is the unbucketed result (#641)' {
    BeforeAll { $script:Keys = @(0..499 | ForEach-Object { "device-$_" }) }
    It 'the main loop: every bucket count from 1 to 64 partitions the rows -- every row in exactly one bucket' {
        foreach ($n in 1, 2, 3, 7, 16, 64) {
            $seen = @{}
            foreach ($k in $script:Keys) { $b = Get-SISha256Bucket -Key $k -BucketCount $n; $b | Should -BeLessThan $n; $seen[$k] = 1 + [int]$seen[$k] }
            @($seen.Values | Where-Object { $_ -ne 1 }).Count | Should -Be 0
            $seen.Count | Should -Be $script:Keys.Count
        }
    }
    It 'escalation (a bucket count that goes up and the report runs again) and a late retry (the same bucket again): the union is still the whole' {
        foreach ($pair in @(@(2, 4), @(4, 16), @(16, 64))) {
            $u = New-Object 'System.Collections.Generic.HashSet[string]'
            for ($b = 0; $b -lt $pair[1]; $b++) { foreach ($k in $script:Keys) { if ((Get-SISha256Bucket -Key $k -BucketCount $pair[1]) -eq $b) { [void]$u.Add($k) } } }
            $u.Count | Should -Be $script:Keys.Count
        }
    }
    It 'the sub-bucket split: the children of a bucket (count T*K, index N + j*T) are exactly that bucket''s rows, at every depth' {
        foreach ($t in 2, 4) {
            foreach ($n in 0..($t - 1)) {
                $parent = @($script:Keys | Where-Object { (Get-SISha256Bucket -Key $_ -BucketCount $t) -eq $n })
                $kids = @(foreach ($j in 0..3) { $script:Keys | Where-Object { (Get-SISha256Bucket -Key $_ -BucketCount ($t * 4)) -eq ($n + $j * $t) } })
                ($kids | Sort-Object) -join ',' | Should -Be (($parent | Sort-Object) -join ',')
                # one level deeper: each child split again the same way
                $j0 = @($script:Keys | Where-Object { (Get-SISha256Bucket -Key $_ -BucketCount ($t * 4)) -eq $n })
                $g = @(foreach ($j in 0..3) { $script:Keys | Where-Object { (Get-SISha256Bucket -Key $_ -BucketCount ($t * 16)) -eq ($n + $j * $t * 4) } })
                ($g | Sort-Object) -join ',' | Should -Be (($j0 | Sort-Object) -join ',')
            }
        }
    }
    It 'the engine routes EVERY path''s rows through the same writer: main loop, complete bucket, late retry, sub-buckets, a single query' {
        $raw = [regex]::Replace((Get-Content -Raw -LiteralPath (Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1')), '(?s)<#.*?#>', '')
        $code = (($raw -split "`r?`n") | Where-Object { $_ -notmatch '^\s*#' }) -join "`n"
        $code | Should -Match "Add-RAStreamBucketGuarded -Rows \`$bucketResult -Bucket \('\{0\}/\{1\}' -f \`$bucketNo, \`$bucketCountToUse\) -Complete:\`$bucketIsComplete"
        # #848: the late retry goes through the memory guard too; a sub-slice's label is unique per row part
        $code | Should -Match "Add-RAStreamBucketGuarded -Rows @\(\`$conv\.Rows\) -Bucket \('late:"
        $code | Should -Match "Add-RAStreamBucketGuarded -Rows @\(\`$subConv\.Rows\) -Bucket \`$subLabel"
        $code | Should -Match "\`$subLabel   = if \(\`$subRC -gt 1\) \{ \('sub:\{0\}/\{1\}/row:\{2\}/\{3\}' -f \`$subN, \`$newT, \`$subRI, \`$subRC\) \} else \{ \('sub:\{0\}/\{1\}' -f \`$subN, \`$newT\) \}"
        $code | Should -Match "Add-RAStreamBucket -Rows @\(\`$ResultSingle\) -Bucket 'whole'"
        ([regex]::Matches($code, 'Add-RAStreamBucket -Rows @\(\) -Bucket .* -Complete')).Count | Should -Be 2
        # a report that starts again with more buckets, or is not in the run, or fails keeps none of its rows
        $code | Should -Match "Clear-RAStreamReport -Stream \`$script:RAStream -Why 'the report runs again with more query slices'"
        $code | Should -Match "Clear-RAStreamReport -Stream \`$script:RAStream -Why 'the report is not in this run'"
        $code | Should -Match "Clear-RAStreamReport -Stream \`$script:RAStream -Why 'the report failed'"
        # no row is gathered across buckets while the result goes to SQL
        $code | Should -Match 'if \(\$script:RAStreamOn\) \{ Add-RAStreamBucket'
        # the end: completeness for every report, then complete in SQL, then run health
        $code.IndexOf('Complete-RAStream -Stream $script:RAStream') | Should -BeLessThan $code.IndexOf("Send-RARunHealthEnd -ExitReason 'success'")
        $code | Should -Match 'is NOT COMPLETE in this run'
    }
}

Describe 'the first live run of the result in SQL (internal, 2026-10-13): 28 reports NotComplete, 8 Unverified' {
    It 'DEFECT 1: the chunk size of the database writes never overflows -- many small writes in one run (each fast) do not double it every time' {
        # live: "Cannot convert value 4.294967296E+19 to type System.Int64" failed 20+ reports -- the stream's chunk size
        # (one for the whole run) doubled on every write of a small bucket, until the next size no longer fit a [long]
        $fake = { param($Sql, $p, $Mode) @(ConvertFrom-Json -InputObject $p['j']).Count }
        $chunk = [ref]0L
        { for ($k = 0; $k -lt 120; $k++) { $null = Write-SIDataJsonRows -Invoke $fake -Sql 'x' -Items @('{"a":1}', '{"a":2}') -ChunkChars $chunk -What 't' } } | Should -Not -Throw
        $chunk.Value | Should -BeLessOrEqual 2000000 -Because 'a write that took every item in one part chunk says nothing about a larger chunk'
        { Get-SIDataNextSize -Current ([long]::MaxValue - 1) -ElapsedMs 0 -TargetMs 10000 } | Should -Not -Throw
        { Get-SIDataNextSize -Current 4000000000000000000 -ElapsedMs 1 -TargetMs 10000 } | Should -Not -Throw
        Get-SIDataNextSize -Current 100000 -ElapsedMs 1000 -TargetMs 10000 | Should -Be 200000 -Because 'a full chunk still grows at most double'
        Get-SIDataNextSize -Current 100000 -ElapsedMs 20000 -TargetMs 10000 -Minimum 1 | Should -Be 50000 -Because 'a slow chunk still shrinks at once'
        # a FULL chunk (the size ended it, not the items) still sizes the next one up
        $big = @(1..60 | ForEach-Object { '{"a":"' + ('x' * 1000) + '"}' })
        $chunk2 = [ref]50000L
        $null = Write-SIDataJsonRows -Invoke $fake -Sql 'x' -Items $big -ChunkChars $chunk2 -What 't'
        $chunk2.Value | Should -BeGreaterThan 50000
    }

    It 'DEFECT 1: a summed column of a group that spans buckets past a [long] stays a number -- never an overflow' {
        $q = "T`n| summarize Total = sum(V), Assets = make_set(A) by K"
        $rows = @([pscustomobject]@{ K = 'g'; Total = [long]6000000000000000000; Assets = [object[]]@('a') }, [pscustomobject]@{ K = 'g'; Total = [long]6000000000000000000; Assets = [object[]]@('b') })
        $m = $null
        { $script:__m = Merge-RASummaryBucketRows -Rows $rows -Query $q } | Should -Not -Throw
        @($script:__m.Rows).Count | Should -Be 1
        [double]$script:__m.Rows[0].Total | Should -Be 1.2E19
    }

    It 'DEFECT 2: the completeness count is asked slice by slice with the slice''s own filter -- never one unbucketed query that carries every lookup whole' {
        $script:__seen = New-Object System.Collections.Generic.List[int]
        $r = Measure-RAReportExpectedRows -BucketCount 4 -RunSlice { param($i) $script:__seen.Add($i); @{ Ok = $true; Rows = @([pscustomobject]@{ Count = [long](10 + $i) }); Error = $null } }
        ($script:__seen -join ',') | Should -Be '0,1,2,3'
        $r.Count | Should -Be 46 -Because 'the slices partition the rows: their counts add up'
        # a slice whose count cannot be made: no count -> Unverified, never Complete
        $bad = Measure-RAReportExpectedRows -BucketCount 4 -RunSlice { param($i) if ($i -eq 2) { throw 'Response status code does not indicate success: 413 (Request Entity Too Large).' }; @{ Ok = $true; Rows = @([pscustomobject]@{ Count = 1L }) } }
        $bad.Count | Should -BeNullOrEmpty
        $bad.Error | Should -Match 'slice 3/4: .*413'
        (Get-RACompletenessVerdict -Expected $bad.Count -Retrieved 3 -CountError $bad.Error).State | Should -Be 'Unverified'
        # the count text: '| count', or the group identities of a Summary report
        Get-RAReportCountKql -Query "T | where x;`n" | Should -Match '(?s)T \| where x\s*\n\| count$'
        $g = Get-RAReportCountKql -Query 'T' -GroupKeys @('Tier', 'cmdbId')
        $g | Should -Match 'hash_sha256\(tolower\(strcat_delim\("\|~\|", tostring\(Tier\), tostring\(cmdbId\)\)\)\)'
        $g | Should -Match '\| distinct SIGroupHash$'
        # the engine asks it that way: in the report's own slices, with the slice coordinates the lookup cut reads
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $fn = [regex]::Match($src, '(?s)function Get-RAReportExpectedRows \{.*?\n\}').Value
        # the whole count FIRST (only it sees a row no slice returns), the slices only when it cannot be sent
        $fn.IndexOf('Measure-RAReportExpectedRows -BucketCount 1 -RunSlice $slice') | Should -BeGreaterThan 0
        $fn.IndexOf('Measure-RAReportExpectedRows -BucketCount 1 -RunSlice $slice') | Should -BeLessThan $fn.IndexOf('Measure-RAReportExpectedRows -BucketCount $n -GroupKeys $keys -RunSlice $slice')
        $fn | Should -Match 'New-BucketFilterKql -BucketCount \$script:__cntN -BucketIndex \$i'
        $fn | Should -Match '\$script:_CurrentBucketCount = \$script:__cntN; \$script:_CurrentBucketIndex = \$i'
        $fn | Should -Not -Match 'New-BucketFilterKql -BucketCount 1 -BucketIndex 0'
        $src | Should -Match '-BucketCount \(\[int\]\$script:RACountBuckets\)'
        $src | Should -Match '\$script:RACountBuckets = \$\(if \(\$completeBucketDone\) \{ 1 \} else \{ \[int\]\$bucketCountToUse \}\)'
    }

    It 'speed: when the whole count cannot be sent, the slices'' own rows are the count -- the slices are never asked twice' {
        # live 2026-10-14: each heavy report was counted in 29 slices and then fetched in the same 29 (10-23 min per report)
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        . ([scriptblock]::Create([regex]::Match($src, '(?s)function Get-RAReportExpectedRows \{.*?\n\}').Value))
        function Test-QueryHasBucketFilterBlock { param($Query) $true }
        function Replace-BucketFilterBlock { param($Query, $BucketFilterKql) $Query }
        function New-BucketFilterKql { param($BucketCount, $BucketIndex, $ReportName) '' }
        function Get-RASummaryMergePlan { param($Query) $null }
        function Get-RABucketRows { param($Resp) $Resp }
        function Invoke-GraphHuntingQuery { param($Query, $ReconnectMaxAgeMinutes, $MaxRetries)
            $script:__asked++
            if ($script:_CurrentBucketCount -le 1) { throw 'Response status code does not indicate success: 413 (Request Entity Too Large).' }
            @{ Ok = $true; Rows = @([pscustomobject]@{ Count = 7L }) } }
        $script:__asked = 0; $script:RALakeAnswered = $false
        $r = Get-RAReportExpectedRows -Query 'T' -ReportName 'R_Detailed' -BucketCount 29 -Retrieved 120
        $r.Count | Should -Be 120
        $r.How | Should -Match 'every one of the report''s 29 slices answered below the row limit.*413'
        $script:__asked | Should -Be 1 -Because 'only the whole count is asked; the 29 slices are not asked again'
        (Get-RACompletenessVerdict -Expected $r.Count -Retrieved 120 -CountError $r.Error).State | Should -Be 'Complete'
        # an answer the lake gave is not checked for a cut: then the slices are still counted
        $script:__asked = 0; $script:RALakeAnswered = $true
        $l = Get-RAReportExpectedRows -Query 'T' -ReportName 'R_Detailed' -BucketCount 29 -Retrieved 120
        $script:__asked | Should -Be 30
        $l.Count | Should -Be 203
        $script:RALakeAnswered = $false
        # the cut answer is refused where the rows are fetched -- the rule the shortcut rests on
        $gh = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'))
        $gh | Should -Match '-ge \$__ahCap\) \{\s*\n\s*throw'
        $gh | Should -Match '\$script:RALakeAnswered = \$true'
        $src | Should -Match '-RowColumns \$RowColumns -Retrieved \$(Retrieved|__srcRetrieved)'   # #673: plan B passes the rows retrieved before the Defender filter
    }

    It 'DEFECT 4/6: Complete needs what was STORED to be what was retrieved less what is named -- an unnamed difference is rows lost' {
        # live (Detailed run): 27 reports Complete with 3,124 expected and 3,100 stored; one report retrieved 6, stored 2
        $acct = @{ '1/2' = @{ In = 4L; Scope = 1L; Excluded = 0L; Duplicate = 1L; Written = 2L }; '2/2' = @{ In = 2L; Scope = 0L; Excluded = 1L; Duplicate = 0L; Written = 1L } }
        $tot = Get-RAStreamAccountTotal -Account $acct
        $tot.Scope | Should -Be 1; $tot.Excluded | Should -Be 1; $tot.Duplicate | Should -Be 1; $tot.Written | Should -Be 3
        $ok = Get-RAStoredVerdict -Retrieved 6 -Stored 2 -Total $tot -CrossSliceDuplicates 1
        $ok.State | Should -Be 'Complete'
        $ok.Reason | Should -Match 'stored 2 of 6 retrieved: 1 outside the report''s tier / severity scope, 1 left out by the default exclusion rules, 1 duplicate finding\(s\) kept once by the scoring, 1 finding\(s\) two query slices both returned'
        $lost = Get-RAStoredVerdict -Retrieved 6 -Stored 2 -Total @{ Scope = 0L; Excluded = 0L; Duplicate = 0L }
        $lost.State | Should -Be 'NotComplete'
        $lost.Reason | Should -Match '4 row\(s\) are neither stored nor accounted for'
        (Get-RAStoredVerdict -Retrieved 5 -Stored 5 -Total $null).State | Should -Be 'Complete'
        # the engine accounts every slice and the completeness verdict uses it
        $src = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        foreach ($k in 'In = \$ResultAll.Count; Scope = ', 'Excluded = \(\[int\]\$totalAfter', 'Duplicate = \(@\(\$ResultFiltered\).Count - @\(\$RiskScoreArray\).Count\)', 'Written = \[long\]', 'Get-RAStoredVerdict -Retrieved \$(Retrieved|__svRetrieved) -Stored', '-CrossSliceDuplicates \(\[long\]\$fin.Duplicates\)') { $src | Should -Match $k }
        # a slice written again replaces its own account; a report that starts again starts with none
        $s = [pscustomobject]@{ Current = @{ Account = @{} } }
        Set-RAStreamAccount -Stream $s -Bucket 'b' -Values @{ In = 9; Written = 9 }
        Set-RAStreamAccount -Stream $s -Bucket 'b' -Values @{ In = 3; Written = 3 }
        (Get-RAStreamAccountTotal -Account $s.Current.Account).In | Should -Be 3
    }

    It 'DEFECT 3: a Summary report''s count is its GROUPS -- a group in two slices is counted once' {
        $r = Measure-RAReportExpectedRows -BucketCount 2 -GroupKeys @('K') -RunSlice { param($i) @{ Ok = $true; Rows = @(@('g1', 'g2'), @('g2', 'g3'))[$i] | ForEach-Object { [pscustomobject]@{ SIGroupHash = $_ } } } }
        $r.Count | Should -Be 3 -Because 'g2 spans both slices and is one row after the merge'
    }

    It 'DEFECT 3: Device_Missing_CVEs_Summary -- a group in two buckets with different software and fixes is ONE row (it was refused and kept twice)' {
        # live: "the source holds 26 row(s) for this report, the run retrieved 38" -- si_affected_software, si_fix_* and
        # si_cve_tags are built after the summarize from lists the report projects away: the merge called them unknown and
        # refused every group whose buckets listed different software
        $rows = @((New-CveRow 0 @('a', 'b') 'Edge 1;Chrome 2' 'KB1' 'id1' ''), (New-CveRow 2 @('c') 'Edge 1' '' '' ''), (New-CveRow 0 @('d') 'Chrome 2;Zoom 3' 'KB2' 'id2' 'tagX'))
        $m = Merge-RASummaryBucketRows -Rows (Copy-Rows $rows) -Query $script:CveQ
        $m.Refused | Should -Be 0 -Because $m.Reason
        @($m.Rows).Count | Should -Be 2 -Because 'two groups (tier 0 in both buckets, tier 2)'
        $t0 = @($m.Rows | Where-Object { $_.CriticalityTier -eq 0 })[0]
        $t0.si_affected_software | Should -Be 'Edge 1;Chrome 2;Zoom 3'
        $t0.si_fix_recommended_update | Should -Be 'KB1;KB2'
        $t0.si_fix_recommended_update_id | Should -Be 'id1;id2'
        $t0.si_cve_tags | Should -Be 'tagX'
        $t0.si_fix_remediation | Should -Be 'Install the security updates KB1, KB2 on the impacted devices; update the other affected software to versions that fix the listed CVEs.'
        (@($t0.ImpactedAssetsList) | Sort-Object) -join ',' | Should -Be 'a,b,d'
        $t2 = @($m.Rows | Where-Object { $_.CriticalityTier -eq 2 })[0]
        $t2.si_fix_remediation | Should -Be 'Update the affected software on the impacted devices to versions that fix the listed CVEs.'
    }
}

Describe 'the stream in SQL (real SQL Server)' -Skip:(-not $script:HasSql) {
    BeforeAll { $script:Db = $null; try { $script:Db = Open-TestDb } catch { $script:DbError = $_.Exception.Message } }
    AfterAll { if ($script:Db) { Close-TestDb $script:Db } }
    BeforeEach { if (-not $script:Db) { Set-ItResult -Skipped -Because ('the local SQL Server did not answer: ' + $script:DbError) } }

    It 'PARITY (Detailed): per bucket scored + written + finished in SQL = the whole report scored in memory -- rows, trace ids, scores; order only differs among equal scores' {
        $all = @(New-DetailedRows)
        $dup = $all[4].PSObject.Copy()      # the same finding, returned by ANOTHER bucket
        $k = 0; while ((Get-SISha256Bucket -Key "other-$k" -BucketCount 4) -eq (Get-SISha256Bucket -Key ([string]$all[4].DeviceKey) -BucketCount 4)) { $k++ }
        $dup.DeviceKey = "other-$k"
        $inRows = @($all) + @($dup)
        # OLD: every bucket gathered, then scored + traced as one, then sorted by the weighted score
        $old = @(Score -Rows (Copy-Rows $inRows))
        Set-RATraceIdentity -Rows $old -IsDetailed $true
        $oldSorted = @($old | Sort-Object -Stable -Descending -Property @{ Expression = { ConvertTo-RADouble -Value $_.RiskScoreTotal_Weighted -Default 0.0 } })
        # NEW: 4 buckets, each scored + traced + written; a retried bucket written twice
        $s = New-RAStream -Invoke $script:Seam -Grain Detailed -CollectionTime ([datetime]'2026-10-13T01:00:00Z') -RunId 'r1' -SolutionVersion '3.0.0+v3' -Log $script:NoLog
        $null = Start-RAStreamReport -Stream $s -ReportName 'Inv_Detailed' -Staged $false
        $bk = Split-Buckets -Rows (Copy-Rows $inRows) -N 4
        foreach ($i in 0..3) {
            $sc = @(Score -Rows $bk[$i].ToArray())
            Set-RATraceIdentity -Rows $sc -IsDetailed $true
            Add-RAStreamColumns -Stream $s -Columns @($sc[0].PSObject.Properties.Name)
            $null = Write-RAStreamRows -Stream $s -Rows $sc -Bucket ("{0}/4" -f ($i + 1)) -IsDetailedShape $true
            if ($i -eq 1) { $null = Write-RAStreamRows -Stream $s -Rows $sc -Bucket ("{0}/4" -f ($i + 1)) -IsDetailedShape $true }   # the retry
        }
        $fin = Complete-RAStreamReport -Stream $s
        $fin.Duplicates | Should -Be 1
        $fin.Stored | Should -Be $old.Count
        $pg = New-RARowPager -Stream $s -Source All -TargetChars 4KB      # small pages: the paging itself is exercised
        $new = New-Object System.Collections.Generic.List[object]
        while ($null -ne ($p = $pg.Next())) { foreach ($r in $p) { $new.Add($r) } }
        $new.Count | Should -Be $old.Count
        (@($new | ForEach-Object { Sig $_ }) | Sort-Object) -join "`n" | Should -Be ((@($old | ForEach-Object { Sig $_ }) | Sort-Object) -join "`n")
        # the shared name: BOTH assets carry their id in the trace name, although they were in different buckets
        @($new | Where-Object { $_.AssetName -eq 'shared-name' -and $_.TraceName -notmatch 'aid-(7|23)-SI$' }).Count | Should -Be 0
        # the order: highest score first; the scores in the same sequence as the old sort
        @($new | ForEach-Object { [double]$_.RiskScoreTotal_Weighted }) -join ',' | Should -Be (@($oldSorted | ForEach-Object { [double]$_.RiskScoreTotal_Weighted }) -join ',')
        # the row reads back in the report's column order with its date
        $new[0].LastSeen | Should -BeOfType [datetime]
        $script:DetStream = $s
    }

    It 'a report that runs again (more buckets) or fails keeps none of its rows; the view and the finding pager read what was written' {
        $s = $script:DetStream
        $null = Start-RAStreamReport -Stream $s -ReportName 'Inv_Second_Detailed' -Staged $false
        $rows = @(Score -Rows (Copy-Rows @(New-DetailedRows)[0..5]) -Report 'Inv_Second_Detailed')
        Set-RATraceIdentity -Rows $rows -IsDetailed $true
        $view = New-Object 'System.Collections.Generic.HashSet[object]' ([System.Collections.Generic.ReferenceEqualityComparer]::Instance); [void]$view.Add($rows[0])
        $null = Write-RAStreamRows -Stream $s -Rows $rows -Bucket '1/2' -IsDetailedShape $true -InView $view
        Clear-RAStreamReport -Stream $s -Why 'test'
        (Complete-RAStreamReport -Stream $s).Stored | Should -Be 0
        $null = Write-RAStreamRows -Stream $s -Rows $rows -Bucket '1/4' -IsDetailedShape $true -InView $view
        (Complete-RAStreamReport -Stream $s).Stored | Should -Be 6
        (Get-RAStreamCount -Stream $s -Source View) | Should -Be ($script:DetStreamView = (Get-RAStreamCount -Stream $s -Source All) - 5)
        # the SI finding pager: grouped by finding, every row with a key once
        $pg = New-RARowPager -Stream $s -Source FindingKey -TargetChars 2KB
        $keys = New-Object System.Collections.Generic.List[string]
        while ($null -ne ($p = $pg.Next())) { foreach ($r in $p) { $keys.Add((Get-SIFindingGroupKey -Row $r)) } }
        $keys.Count | Should -Be (Get-RAStreamCount -Stream $s -Source All)
        $done = New-Object 'System.Collections.Generic.HashSet[string]'; $prev = $null
        foreach ($k in $keys) { if ($k -ne $prev) { $done.Add($k) | Should -BeTrue -Because 'the rows of one finding come together, never split'; $prev = $k } }
        # the findings published per page are the findings of the whole
        $direct = @(ConvertTo-SIFindingRows -Rows @(& { $pg2 = New-RARowPager -Stream $s -Source All; while ($null -ne ($q = $pg2.Next())) { $q } }))
        $direct.Count | Should -BeGreaterThan 0
        Set-RAStreamReportStatus -Stream $s -ReportName 'Inv_Detailed' -Expected 121 -Retrieved 121 -Stored 120 -State Complete
        @(Q "SELECT State FROM sidata.RaReportStatus WHERE ReportName = 'Inv_Detailed'")[0]['State'] | Should -Be 'Complete'
    }

    It 'the END: only a whole result is marked in; the data sync does not load it from Log Analytics and completes it from what Risk Analysis wrote' {
        $s = $script:DetStream
        $rows = Complete-RAStream -Stream $s -Partial ''
        $rows | Should -Be (Get-RAStreamCount -Stream $s -Source All)
        { Complete-RAStream -Stream $s } | Should -Throw
        $c = @(Q "SELECT CollectionId, Status, Source, RaCompletedAt FROM sidata.Collection")[0]
        $c['Status'] | Should -Be 'Loading' -Because 'the web app sees it only once the data sync completed it'
        $c['Source'] | Should -Be 'risk-analysis'
        # the plan: the Log Analytics copy of the same collection is SKIPPED (never loaded twice)
        $loaded = @(@(& $script:Seam (Get-SIDataLoadedSql) @{ Kind = 'Detailed'; Since = '2026-10-01T00:00:00.000' } 'reader') | ForEach-Object { $_ } | ForEach-Object { [pscustomobject]@{ CollectionId = $_['CollectionId']; CollectionTime = $_['CollectionTime']; Status = $_['Status']; Source = [string]$_['Source'] } })
        $plan = @(Get-SIDataLoadPlan -Collections @([pscustomobject]@{ CollectionTime = [datetime]'2026-10-13T01:00:00Z'; Rows = $rows; Bytes = 1; SolutionVersion = '3.0.0+v3'; NoConfigurationId = 0 }) -Loaded $loaded -Runs @() -Now ([datetime]'2026-10-13T02:00:00Z'))
        $plan[0].Action | Should -Be 'Skip'
        $pend = @(@(& $script:Seam (Get-SIDataRaPendingSql) @{} 'reader') | ForEach-Object { $_ })
        $pend.Count | Should -Be 1
        # completed from SQL: the CI keys, the CIs, the daily aggregate, 'Complete'
        $item = [pscustomobject]@{ CollectionId = [int]$pend[0]['CollectionId']; CollectionTime = [datetime]::SpecifyKind([datetime]$pend[0]['CollectionTime'], 'Utc'); RaPartialReason = ''; SolutionVersion = '3.0.0+v3' }
        $noRecs = { param($kql) @([pscustomobject]@{ PageRows = 0; PageBytes = 0 }) }
        $chunk = [long]0
        $one = Invoke-SIDataAdoptRaCollection -Item $item -Query $noRecs -Invoke $script:Seam -ChunkChars ([ref]$chunk) -Log $script:NoLog
        $one.Findings | Should -Be $rows
        $one.Assets | Should -BeGreaterThan 0
        @(Q "SELECT Status FROM sidata.Collection")[0]['Status'] | Should -Be 'Complete'
        @(Q "SELECT COUNT(*) AS n FROM sidata.Finding WHERE AssetKey IS NULL")[0]['n'] | Should -Be 0
        @(@(& $script:Seam (Get-SIDataRaPendingSql) @{} 'reader') | ForEach-Object { $_ }).Count | Should -Be 0
    }

    It 'PARITY (Summary): a group split over buckets is staged, combined by the same rules, scored, written -- the same groups, assets and trend as in memory' {
        function New-Grp($tier, $assets, $prob) {
            [pscustomobject][ordered]@{ SecurityDomain = 'Endpoint'; Category = 'Vulnerabilities'; Subcategory = 'CVEs (Missing Updates)'; ConfigurationName = 'Update vulnerable software'
                ConfigurationId = 'CVE'; Impact = 5; SecuritySeverity = 'High'; CriticalityTier = $tier; CriticalityTierLevel = $script:Tiers[$tier]
                cmdbId = ''; cmdbName = ''; cmdbCriticality = ''; cmdbDataSensitivity = ''; RiskFactor_Consequence = 0; RiskFactor_Probability = $prob; RiskFactor_Probability_Detailed = ''
                RiskScore_Weight_Detailed = ''; RiskScore_Weight_Factor = 100; RiskFactor_Weight = 100
                ImpactedAssetCount = @($assets).Count; ImpactedAssetsList = [object[]]@($assets); ImpactedAssetPairs = [object[]]@($assets | ForEach-Object { "$_|id-$_" })
                UniqueIssues = 1; IssueList = [object[]]@('CVE-1'); MoreDetails = 'CVE-1 => https://nvd/CVE-1'; AssetId = "id-$($assets[0])" }
        }
        $b1 = @((New-Grp 0 @('a', 'b') 1), (New-Grp 2 @('c') 1))
        $b2 = @((New-Grp 0 @('d') 1), (New-Grp 3 @('e', 'f') 1))
        # OLD: every bucket's rows, merged by the report's own summarize-by, scored as one
        $m = Merge-RASummaryBucketRows -Rows (Copy-Rows (@($b1) + @($b2))) -Query $script:CveQ
        $old = @(Score -Rows @($m.Rows) -Report 'Device_Missing_CVEs_Summary')
        Set-RATraceIdentity -Rows $old -IsDetailed $false
        # NEW: staged per bucket, combined a page of whole groups at a time, scored, written
        $s = New-RAStream -Invoke $script:Seam -Grain Summary -CollectionTime ([datetime]'2026-10-13T02:00:00Z') -RunId 'r2' -Log $script:NoLog
        $null = Start-RAStreamReport -Stream $s -ReportName 'Device_Missing_CVEs_Summary' -Staged $true -Query $script:CveQ
        $null = Add-RAStreamStage -Stream $s -Rows (Copy-Rows $b1) -Bucket '1/2'
        $null = Add-RAStreamStage -Stream $s -Rows (Copy-Rows $b2) -Bucket '2/2'
        $null = Add-RAStreamStage -Stream $s -Rows (Copy-Rows $b2) -Bucket '2/2'      # a retried bucket: no doubles
        $script:SumMerged = 0; $script:SumPages = New-Object System.Collections.Generic.List[string]
        $null = Invoke-RAStreamStagePages -Stream $s -TargetChars 1 -OnPage {
            param($rows, $n)
            $mm = Merge-RASummaryBucketRows -Rows @($rows) -Query $script:CveQ
            $script:SumPages.Add(('page {0}: {1} row(s) in, {2} out, merged {3}, refused {4}, {5}' -f $n, @($rows).Count, @($mm.Rows).Count, $mm.Merged, $mm.Refused, $mm.Reason))
            $sc = @(Score -Rows @($mm.Rows) -Report 'Device_Missing_CVEs_Summary')
            Set-RATraceIdentity -Rows $sc -IsDetailed $false
            $script:SumMerged += $sc.Count
            Add-RAStreamColumns -Stream $s -Columns @($sc[0].PSObject.Properties.Name)
            $null = Write-RAStreamRows -Stream $s -Rows $sc -Bucket "page:$n" -IsDetailedShape $false -Dedup $false
        }
        $script:SumMerged | Should -Be $old.Count -Because ('the pages combine as in memory (in memory: merged {0}, refused {1}, {2}) -- {3}' -f $m.Merged, $m.Refused, $m.Reason, ($script:SumPages -join '; '))
        (Complete-RAStreamReport -Stream $s).Stored | Should -Be $old.Count -Because 'a group of two buckets is combined exactly as in memory (one row, or kept apart where the merge refuses)'
        $pg = New-RARowPager -Stream $s -Source All
        $new = @(while ($null -ne ($p = $pg.Next())) { $p })
        $sig = { param($r) '{0}|{1}|{2}|{3}' -f $r.CriticalityTier, ((@($r.ImpactedAssetsList) | Sort-Object) -join ','), $r.ImpactedAssetCount, [double]$r.RiskScoreTotal }
        (@($new | ForEach-Object { & $sig $_ }) | Sort-Object) -join "`n" | Should -Be ((@($old | ForEach-Object { & $sig $_ }) | Sort-Object) -join "`n")
        # the impacted assets the web app lists
        @(Q "SELECT COUNT(*) AS n FROM sidata.SummaryAsset")[0]['n'] | Should -Be ([int](@($old | ForEach-Object { [Math]::Max(@($_.ImpactedAssetsList).Count, @($_.ImpactedAssetIds).Count) }) | Measure-Object -Sum).Sum)
        # the trend rollup in SQL = the rollup over the rows in memory
        $sqlT = @(Get-RAStreamTrendRollup -Stream $s | ForEach-Object { '{0}|{1}|{2}|{3}|{4}' -f $_.Dimension, $_.DimensionValue, $_.Findings, $_.Assets, $_.ScoreTotal }) | Sort-Object
        $memT = @(ConvertTo-SITrendRollup -Rows $old | ForEach-Object { '{0}|{1}|{2}|{3}|{4}' -f $_.Dimension, $_.DimensionValue, $_.Findings, $_.Assets, $_.ScoreTotal }) | Sort-Object
        ($sqlT -join "`n") | Should -Be ($memT -join "`n")
        (Complete-RAStream -Stream $s) | Should -Be $old.Count -Because 'the run stored exactly the report''s rows'
        @(Q "SELECT Status FROM sidata.SummaryLoad")[0]['Status'] | Should -Be 'Complete'
        @(Q "SELECT COUNT(*) AS n FROM sidata.RaStage")[0]['n'] | Should -Be 0 -Because 'the stage is removed when the report is done'
    }

    It 'DEFECT 3 in SQL: Device_Missing_CVEs_Summary staged in two buckets reads back as its GROUPS -- a group in both buckets is one stored row' {
        $s = New-RAStream -Invoke $script:Seam -Grain Summary -CollectionTime ([datetime]'2026-10-13T03:00:00Z') -RunId 'r3' -Log $script:NoLog
        $null = Start-RAStreamReport -Stream $s -ReportName 'Device_Missing_CVEs_Summary' -Staged $true -Query $script:CveQ
        $null = Add-RAStreamStage -Stream $s -Rows @((New-CveRow 0 @('a', 'b') 'Edge 1;Chrome 2' 'KB1' 'id1' ''), (New-CveRow 2 @('c') 'Edge 1' '' '' '')) -Bucket '1/2'
        $null = Add-RAStreamStage -Stream $s -Rows @((New-CveRow 0 @('d') 'Chrome 2;Zoom 3' 'KB2' 'id2' 'tagX'), (New-CveRow 3 @('e') '' '' '' '')) -Bucket '2/2'
        $script:D3 = 0; $script:D3Refused = 0
        $null = Invoke-RAStreamStagePages -Stream $s -TargetChars 1 -OnPage {
            param($rows, $n)
            $mm = Merge-RASummaryBucketRows -Rows @($rows) -Query $script:CveQ
            $script:D3Refused += [int]$mm.Refused
            $sc = @(Score -Rows @($mm.Rows) -Report 'Device_Missing_CVEs_Summary')
            Set-RATraceIdentity -Rows $sc -IsDetailed $false
            $script:D3 += $sc.Count
            Add-RAStreamColumns -Stream $s -Columns @($sc[0].PSObject.Properties.Name)
            $null = Write-RAStreamRows -Stream $s -Rows $sc -Bucket "page:$n" -IsDetailedShape $false -Dedup $false
        }
        $script:D3Refused | Should -Be 0
        $script:D3 | Should -Be 3 -Because 'three groups at the source (tier 0 in both buckets, tier 2, tier 3) -- the count the completeness check compares with'
        (Complete-RAStreamReport -Stream $s).Stored | Should -Be 3
        $pg = New-RARowPager -Stream $s -Source All
        $t0 = @(while ($null -ne ($p = $pg.Next())) { $p }) | Where-Object { [int]$_.CriticalityTier -eq 0 }
        @($t0).Count | Should -Be 1
        $t0.si_affected_software | Should -Be 'Edge 1;Chrome 2;Zoom 3'
    }

    It 'the CI context of ONE bucket comes from sidata.Ci: by an id the CI carries, or a name only one current CI has' {
        $doc1 = '{"si_ci_id":"ci-1","si_asset_name":"srv01","si_tier":0,"si_link_mde":"mde-1"}'
        $doc2 = '{"si_ci_id":"ci-2","si_asset_name":"dup","si_tier":2}'
        $doc3 = '{"si_ci_id":"ci-3","si_asset_name":"dup","si_tier":3}'
        $sql = "INSERT sidata.Ci (CiId, Class, Name, CollectionTime, DocJson) VALUES ('ci-1','device','srv01','2026-10-13','$doc1'),('ci-2','device','dup','2026-10-13','$doc2'),('ci-3','device','dup','2026-10-13','$doc3');" +
               "INSERT sidata.CiLink (CiId, Provider, RecordType, NativeId, IsPrimary) VALUES ('ci-1','mde','device','mde:mde-1',1);"
        & $script:Seam $sql @{} 'nonquery'
        $rows = @([pscustomobject]@{ MdeDeviceId = 'mde-1'; AssetName = 'x' }, [pscustomobject]@{ AssetName = 'dup' }, [pscustomobject]@{ AssetName = 'srv01' })
        $idx = Get-RAStreamCiIndex -Invoke $script:Seam -Rows $rows
        (Find-RACiForRow -Row $rows[0] -Index $idx).Ci.si_ci_id | Should -Be 'ci-1'
        Find-RACiForRow -Row $rows[1] -Index $idx | Should -BeNullOrEmpty -Because 'two CIs share the name: it identifies nothing'
        (Find-RACiForRow -Row $rows[2] -Index $idx).Ci.si_ci_id | Should -Be 'ci-1'
    }
}

Describe 'a SHORT answer is caught, never taken as the whole (#641)' {
    BeforeAll {
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1')
        . (Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-AutoBucketing.ps1')
        $script:RaSrc = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
    }
    It 'a partial Log Analytics answer and an advanced-hunting answer at its row limit are refused -- worded so the slice is made SMALLER' {
        $la = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-LogAnalyticsQuery.ps1'))
        # #690 (37): the refusal is built from what the answer says (RA-LaPartedRead.ps1: Get-RALaPartialVerdict / New-RALaPartialError)
        $lp = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-LaPartedRead.ps1'))
        $lp | Should -Match 'Log Analytics returned a PARTIAL answer'
        $la | Should -Match ([regex]::Escape('throw (New-RALaPartialError -Verdict $__pv -Rows $__rows)'))
        $la.IndexOf('$resp.PSObject.Properties[''Error'']') | Should -BeLessThan $la.IndexOf('return ,@($resp.Results)')
        $ah = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\_shared\RA-GraphHunting.ps1'))
        $ah | Should -Match '@\(\$ahResp\.Results\)\.Count -ge \$__ahCap'
        Get-RABucketFailureAction -Err 'Log Analytics returned a PARTIAL answer (PartialError/E_QUERY_RESULT_SET_TOO_LARGE: x) -- Query execution has exceeded the allowed limits; the rows it returned are not the whole result' | Should -Be 'Split'
        Get-RABucketFailureAction -Err 'advanced hunting returned 100000 rows -- its row limit, so the answer may be cut: Query execution has exceeded the allowed limits' | Should -Be 'Split'
    }
    It 'each bucket is checked against the source''s own count of it: asked again once when short, its loss recorded when it stays short' {
        $script:RaSrc | Should -Match 'function Test-RABucketRowCount'
        # #673: the slice's rows before the Defender filter when plan B ran (Get-RADfcCountedRows), else its rows
        $i = $script:RaSrc.IndexOf('$__bc = Test-RABucketRowCount -Query $thisQuery -Rows $__bcRows')
        $script:RaSrc | Should -Match ([regex]::Escape('$__bcRows = Get-RADfcCountedRows -Rows ([long]$bucketCount)'))
        $i | Should -BeGreaterThan 0
        $i | Should -BeLessThan $script:RaSrc.IndexOf('$__slIn = Add-RAStreamBucketGuarded -Rows $bucketResult')
        $script:RaSrc | Should -Match 'Add-RABucketLoss \("bucket \{0\}/\{1\}: the source returned \{2\} of the \{3\} row\(s\) it counts"'
    }
}
Describe 'deliver from SQL first, the Log Analytics copy after (owner 2026-10-17)' {
    BeforeAll {
        $script:RaSrc743 = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'engine\risk-analysis\Invoke-RiskAnalysis.ps1'))
        $script:Calls743 = New-Object System.Collections.Generic.List[object]
        $script:Stream743 = [pscustomobject]@{ Grain = 'Detailed'; CollectionId = 42; TimeText = '2026-10-18T01:00:00.000'
                                               Invoke = { param($Sql, $Params, $Mode) $script:Calls743.Add([pscustomobject]@{ Sql = $Sql; Params = $Params }); 1 } }
    }
    BeforeEach { $script:Calls743.Clear() }
    It 'a copy in full: the collection is marked (LaCopyAt), one line, the run is not partial' {
        $r = Complete-RALaCopy -Stream $script:Stream743 -Sent $true
        $r.Marked | Should -BeTrue; $r.Partial | Should -BeFalse; $r.Level | Should -Be 'INFO'
        $script:Calls743.Count | Should -Be 1
        $script:Calls743[0].Sql | Should -Match 'SET LaCopyAt = SYSUTCDATETIME\(\)'
        $script:Calls743[0].Params['CollectionId'] | Should -Be '42'
    }
    It 'a copy NOT in full: the run is PARTIAL, said plainly, never failed and nothing marked' {
        $r = Complete-RALaCopy -Stream $script:Stream743 -Sent $true -NotDelivered @("SI_RiskAnalysis_Detailed_CL did not receive this run's result in full: boom")
        $r.Partial | Should -BeTrue; $r.Marked | Should -BeFalse; $r.Level | Should -Be 'WARN'
        @($r.Causes)[0] | Should -Match '^the Log Analytics copy of this run is not complete: '
        $r.Text | Should -Match 'complete in the database and delivered'
        $r.Text | Should -Match 'recorded as partial'
        $r.Text | Should -Not -Match '#\d'
        $script:Calls743.Count | Should -Be 0
        (Complete-RALaCopy -Stream $script:Stream743 -Sent $true -Refused @('every row has CollectionTime empty')).Partial | Should -BeTrue
    }
    It 'no copy on this install (Log Analytics off): nothing marked, nothing said; a collection not delivered is never marked' {
        $r = Complete-RALaCopy -Stream $script:Stream743 -Sent $false
        $r.Level | Should -Be ''; $r.Partial | Should -BeFalse; $script:Calls743.Count | Should -Be 0
        (Complete-RALaCopy -Stream $script:Stream743 -Sent $true -Delivered $false).Marked | Should -BeFalse
        $script:Calls743.Count | Should -Be 0
    }
    It 'NEVER throws: a mark the database refuses is one line, the run goes on' {
        $bad = [pscustomobject]@{ Grain = 'Summary'; CollectionId = $null; TimeText = '2026-10-18T01:00:00.000'; Invoke = { param($Sql, $Params, $Mode) throw 'login failed' } }
        { $script:R743 = Complete-RALaCopy -Stream $bad -Sent $true } | Should -Not -Throw
        $script:R743.Marked | Should -BeFalse
        $script:R743.Text | Should -Match 'mark could not be written'
    }
    It 'the mark is additive in the schema and guarded in the statement (both grains)' {
        $schema = [IO.File]::ReadAllText((Join-Path $script:SIRoot 'sql\si-data-schema.sql'))
        $schema | Should -Match "IF COL_LENGTH\('sidata\.Collection', 'LaCopyAt'\) IS NULL ALTER TABLE sidata\.Collection ADD LaCopyAt DATETIME2\(0\) NULL;"
        $schema | Should -Match "IF COL_LENGTH\('sidata\.SummaryLoad', 'LaCopyAt'\) IS NULL ALTER TABLE sidata\.SummaryLoad ADD LaCopyAt DATETIME2\(0\) NULL;"
        foreach ($g in 'Detailed', 'Summary') { Get-RALaCopySql -Grain $g | Should -Match "^IF COL_LENGTH\('sidata\.\w+', 'LaCopyAt'\) IS NOT NULL" }
    }
    It 'WIRING: with the result in SQL the collection is completed FIRST, the copy is sent after it, then the workbook; without it, as before' {
        $code = $script:RaSrc743
        $iBlock = $code.IndexOf('$script:RALaPhase = {')
        $iEarly = $code.IndexOf('if (-not $script:RAStreamOn) { . $script:RALaPhase }')
        $iComplete = $code.IndexOf('Complete-RAStream -Stream $script:RAStream -Partial $__raPartial -Scope $__raScope')
        $iLate = $code.IndexOf("if (`$script:RAStreamOn) {`r`n    . `$script:RALaPhase")
        if ($iLate -lt 0) { $iLate = $code.IndexOf("if (`$script:RAStreamOn) {`n    . `$script:RALaPhase") }
        $iCopy = $code.IndexOf('Complete-RALaCopy -Stream $script:RAStream')
        $iBook = $code.IndexOf('# THE WORKBOOK (RA-WorkbookExport.ps1) -- from the completed result')   # the block heading (#873 A wrapped the call in its phase timing)
        foreach ($i in $iBlock, $iEarly, $iComplete, $iLate, $iCopy, $iBook) { $i | Should -BeGreaterThan 0 }
        $iBlock | Should -BeLessThan $iEarly
        $iEarly | Should -BeLessThan $iComplete -Because 'the copy of a result held in memory goes out where it always did'
        $iComplete | Should -BeLessThan $iLate -Because 'the delivery from SQL never waits for the copy'
        $iLate | Should -BeLessThan $iCopy
        $iCopy | Should -BeLessThan $iBook
        # the posting itself lives once, inside the block
        ([regex]::Matches($code, 'Invoke-RALaPagedPost -Pager')).Count | Should -Be 1
        $code.IndexOf('Invoke-RALaPagedPost -Pager') | Should -BeGreaterThan $iBlock
        $code.IndexOf('Invoke-RALaPagedPost -Pager') | Should -BeLessThan $iEarly
        # a broken-off copy makes the run partial through the publish failures (the run record, the mail, the heartbeat)
        $code | Should -Match ([regex]::Escape('[void]$script:_RAPublishFailures.Add([string]$__pf)'))
    }
}

Describe 'the Log Analytics copy mark on a real SQL Server' -Skip:(-not $script:HasSql) {
    BeforeAll { $script:Db743 = $null; try { $script:Db743 = Open-TestDb } catch { $script:DbError743 = $_.Exception.Message } }
    AfterAll { if ($script:Db743) { Close-TestDb $script:Db743 } }
    It 'marks only the run''s own collection, as the engine user' {
        if (-not $script:Db743) { Set-ItResult -Skipped -Because ('the local SQL Server did not answer: ' + $script:DbError743); return }
        $s = New-RAStream -Invoke $script:Seam -Grain Detailed -CollectionTime ([datetime]'2026-10-18T01:00:00Z') -RunId 'r743' -SolutionVersion '3.0.0+v3' -Log $script:NoLog
        $r = Complete-RALaCopy -Stream $s -Sent $true
        $r.Marked | Should -BeTrue
        @(Q ("SELECT COUNT(*) AS N FROM sidata.Collection WHERE CollectionId = {0} AND LaCopyAt IS NOT NULL" -f [int]$s.CollectionId))[0]['N'] | Should -Be 1
        @(Q ("SELECT COUNT(*) AS N FROM sidata.Collection WHERE CollectionId <> {0} AND LaCopyAt IS NOT NULL" -f [int]$s.CollectionId))[0]['N'] | Should -Be 0
    }
}
