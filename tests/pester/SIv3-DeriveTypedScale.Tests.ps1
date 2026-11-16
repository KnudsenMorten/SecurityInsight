#Requires -Version 7.0
<#
    #1273 SCALE BENCH, ON DEMAND ONLY (Tag 'Scale' -- no gate runs it; the owner asked for it: "can you test the chg when
    build"). One synthetic Risk Analysis Detailed collection of SI_DERIVE_SCALE_N findings (default 250,000; each DetailJson a
    Risk Analysis row of about SI_DERIVE_SCALE_JSON characters, default 3,000, with every field the derive reads) is stored
    TWICE in a scratch database with the full schema (every index of sidata.Finding). The OLD path (the derive statement with a
    JSON_VALUE per column, the risk score's parts in their own pass, the facets and the counted facets reading DetailJson) runs
    on one copy, the NEW one (Invoke-SIDataDeriveCollection with the one-parse statement, the counted facets typed) on the
    other, each from a cold buffer pool. Printed: seconds and rows/s per part and in total (DERIVE-TYPED-BENCH lines).
    Asserted: every derived column of every row is the same in both copies (set-based EXCEPT both ways), and the facets too.
    Run on the test runner:
      . ./SOLUTIONS/SecurityInsight/tests/pester/_SITestSql.ps1; Initialize-SITestSqlEnv
      Invoke-Pester -Path ./SOLUTIONS/SecurityInsight/tests/pester/SIv3-DeriveTypedScale.Tests.ps1 -TagFilter Scale -Output Detailed
#>

BeforeDiscovery {
    $script:LocalSql = $false
    try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
}

Describe 'the derive at scale: old path vs one parse' -Tag 'Scale' {
    BeforeAll {
        $script:Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        . (Join-Path $script:Root 'engine\_shared\SI-SchemaGate.ps1')
        . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataModel.ps1')
        . (Join-Path $script:Root 'engine\_shared\data-sql\SI-DataSql.ps1')
        $script:LocalSql = $false
        try { $script:LocalSql = [bool]$env:SI_TEST_LOCALSQL -and $null -ne ('System.Data.SqlClient.SqlConnection' -as [type]) } catch { $script:LocalSql = $false }
        if (-not $script:LocalSql) { return }
        $script:N = if ($env:SI_DERIVE_SCALE_N -match '^\d+$') { [int]$env:SI_DERIVE_SCALE_N } else { 250000 }
        $script:JsonChars = if ($env:SI_DERIVE_SCALE_JSON -match '^\d+$') { [int]$env:SI_DERIVE_SCALE_JSON } else { 3000 }
        $script:Db = 'siderivescale_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
        function script:New-LocalInvoke([string]$Db) {
            $cs = "Server=$($env:SI_TEST_LOCALSQL);Database=$Db;$($env:SI_TEST_SQL_AUTH);TrustServerCertificate=True"
            {
                param([string]$sql, $p, [string]$mode)
                $cn = New-Object System.Data.SqlClient.SqlConnection($cs); $cn.Open()
                try {
                    $c = $cn.CreateCommand(); $c.CommandTimeout = 3600; $c.CommandText = $sql
                    if ($p) { foreach ($k in $p.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $p[$k]) { [DBNull]::Value } else { $p[$k] })) } }
                    if ($mode -eq 'scalar') { return $c.ExecuteScalar() }
                    if ($mode -eq 'nonquery') { return $c.ExecuteNonQuery() }
                    $r = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
                    while ($r.Read()) { $h = @{}; for ($i = 0; $i -lt $r.FieldCount; $i++) { $h[$r.GetName($i)] = $(if ($r.IsDBNull($i)) { $null } else { $r.GetValue($i) }) }; $rows.Add($h) }
                    $r.Close(); return , $rows.ToArray()
                } finally { $cn.Close() }
            }.GetNewClosure()
        }
        $script:Master = New-LocalInvoke 'master'
        [void](& $script:Master "CREATE DATABASE [$script:Db]; ALTER DATABASE [$script:Db] SET RECOVERY SIMPLE;" @{} 'nonquery')
        $script:Inv = New-LocalInvoke $script:Db
        # the seam answers a reader as ONE list: assigned first, then enumerated
        function script:Get-Row([string]$Sql, $P) { $x = & $script:Inv $Sql $P 'reader'; @($x)[0] }
        $cfg = [System.IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-pro-settings.sql'))
        foreach ($b in ([regex]::Split($cfg, '(?m)^\s*$'))) { if (([regex]::Replace($b, '(?m)^\s*--.*$', '')).Trim()) { [void](& $script:Inv $b @{} 'nonquery') } }
        [void](& $script:Inv ([System.IO.File]::ReadAllText((Join-Path $script:Root 'sql\si-data-schema.sql'))) @{} 'nonquery')
        [void](& $script:Inv 'CREATE TABLE dbo.Tally (i int NOT NULL PRIMARY KEY); WITH n AS (SELECT TOP (1000000) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b CROSS JOIN sys.all_objects c) INSERT dbo.Tally SELECT i FROM n;' @{} 'nonquery')
        $pad = [Math]::Max(0, $script:JsonChars - 1400)
        $script:Gen = @"
SET NOCOUNT ON;
DECLARE @c int;
INSERT sidata.Collection (CollectionTime, Kind, Status, [Rows]) VALUES (@t, N'Detailed', N'Complete', @n);
SET @c = SCOPE_IDENTITY();
DECLARE @from int = 0;
WHILE @from < @n
BEGIN
    INSERT sidata.Finding (CollectionId, AssetKey, AssetName, ReportName, SecurityDomain, ConfigurationId, Cve, Title, Severity, Tier, RiskScore, ExemptionId, DetailJson)
    SELECT @c, CONCAT(N'ci-', x.i % 9000), CONCAT(N'host-', x.i % 9000), CHOOSE(x.i % 3 + 1, N'Device_Missing_CVEs_Detailed', N'Endpoint_SecurityConfig_Detailed', N'Identity_Findings_Detailed'),
           CHOOSE(x.i % 3 + 1, N'Endpoint', N'Endpoint', N'Identity'), CONCAT(N'CVE-2026-', x.i % 9000), CASE WHEN x.i % 3 = 0 THEN CONCAT(N'CVE-2026-', x.i % 9000) END,
           CONCAT(N'Update software ', x.i % 9000), CHOOSE(x.i % 4 + 1, N'Critical', N'High', N'Medium', N'Low'), x.i % 4, (x.i % 100) * 0.5,
           CASE WHEN x.i % 20 = 0 THEN 100 + x.i % 3 END,
           CASE WHEN x.i % 997 = 0 THEN N'not json' ELSE CONCAT(
               N'{"AssetId":"mde-', x.i % 9000, N'","SolutionVersion":"3.1.28+v3","CriticalityTier":"', x.i % 4, N'","ConfigurationId":"CVE-2026-', x.i % 9000,
               N'","RiskScoreTotal_Weighted":', (x.i % 89) * 1.3, N',"RiskRating":"', CHOOSE(x.i % 4 + 1, N'Critical', N'High', N'Medium', N'Low'),
               N'","MITRE_Tactics":', CASE x.i % 3 WHEN 0 THEN N'["TA0001","TA0002"]' WHEN 1 THEN N'"TA0003, TA0004"' ELSE N'null' END,
               N',"MITRE_Techniques":', CASE x.i % 2 WHEN 0 THEN N'"T1059; T1003"' ELSE N'["T1110"]' END,
               N',"ComplianceTags":', CASE x.i % 2 WHEN 0 THEN N'"CIS; NIST"' ELSE N'["ISO"]' END,
               N',"MaxCvssScore":', CASE WHEN x.i % 6 = 0 THEN N'null' ELSE CAST(x.i % 11 AS nvarchar(10)) END, N',"Impact":', x.i % 10,
               N',"HasExploit":"', CHOOSE(x.i % 3 + 1, N'true', N'false', N'1'), N'","cmdbId":"svc-', x.i % 40, N'","cmdbName":"Service ', x.i % 40,
               N'","si_component":"', CHOOSE(x.i % 4 + 1, N'OS', N'Office', N'Browser', N'Other'), N'","si_category":"Vulnerability","Category":"Software","si_subcategory":"Patch",',
               N'"si_class":"Server","si_patch_cycle":"In monthly cycle","si_os_family":"Windows","si_servicenow_subci":"OS","si_affected_product":"windows_10",',
               N'"si_fix_remediation":"Install the update","si_fix_recommended_update":"KB', x.i % 300, N'","si_fix_recommended_update_id":"', x.i % 300, N'","si_affected_software":"Windows",',
               N'"RiskConsequenceBase":"', x.i % 7, N'","RiskConsequenceScore":"', x.i % 9, N'","RiskFactor_Consequence":"2","RiskFactor_Consequence_Impacts":"Tier=2;Internet=1",',
               N'"RiskFactor_Consequence_Detailed":"Tier 0 asset","RiskProbabilityBase":"3","RiskProbabilityScore":"', x.i % 8, N'","RiskFactor_Probability":"1",',
               N'"RiskFactor_Probability_Impacts":"Exploit=1","RiskFactor_Probability_Detailed":"Exploit known","RiskScore_Weight_Factor":"1.5","RiskScore_Weight_Detailed":"Tier weight",',
               N'"Description":"', REPLICATE(CONVERT(nvarchar(max), N'd'), $pad), N'"}') END
    FROM (SELECT @from + t.i AS i FROM dbo.Tally AS t WHERE t.i <= CASE WHEN @n - @from < 50000 THEN @n - @from ELSE 50000 END) AS x;
    SET @from += 50000;
END
SELECT @c;
"@
        $script:Out = [System.Collections.Generic.List[string]]::new()
        function script:Say([string]$Line) { $script:Out.Add($Line); Write-Host ('DERIVE-TYPED-BENCH ' + $Line) }
        function script:Cold { [void](& $script:Inv 'CHECKPOINT; DBCC DROPCLEANBUFFERS WITH NO_INFOMSGS;' @{} 'nonquery') }
        function script:Time([string]$What, [long]$Rows, [scriptblock]$Body) {
            $sw = [Diagnostics.Stopwatch]::StartNew(); $null = & $Body; $sw.Stop()
            Say ('{0,-44} {1,9:N1} s  {2,9:N0} rows/s' -f $What, $sw.Elapsed.TotalSeconds, ($Rows / [Math]::Max(0.001, $sw.Elapsed.TotalSeconds)))
            $sw.Elapsed.TotalSeconds
        }
    }
    AfterAll {
        if (-not $script:LocalSql -or -not $script:Master) { return }
        [System.Data.SqlClient.SqlConnection]::ClearAllPools()
        [void](& $script:Master "ALTER DATABASE [$script:Db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$script:Db]" @{} 'nonquery')
    }

    It 'measures the old and the new derive on the same collection, and they write the same values' -Skip:(-not $script:LocalSql) {
        $genS = [Diagnostics.Stopwatch]::StartNew()
        $a = [int](& $script:Inv $script:Gen @{ t = '2026-11-16T01:00:00'; n = $script:N } 'scalar')
        $b = [int](& $script:Inv $script:Gen @{ t = '2026-11-16T02:00:00'; n = $script:N } 'scalar')
        $mb = [double](& $script:Inv "SELECT SUM(a.total_pages) * 8 / 1024.0 FROM sys.partitions p JOIN sys.allocation_units a ON a.container_id = p.partition_id WHERE p.object_id = OBJECT_ID('sidata.Finding')" @{} 'scalar')
        Say ('data: {0:N0} findings per copy, two copies, DetailJson ~{1:N0} characters, sidata.Finding {2:N0} MB with its indexes (generated in {3:N0} s)' -f $script:N, $script:JsonChars, $mb, $genS.Elapsed.TotalSeconds)
        $bd = (Get-Row (Get-SIDataFindingBoundsSql) @{ CollectionId = $a })

        Cold
        $o1 = Time 'OLD derive (JSON_VALUE per column)' $script:N {
            $bs = [long]20000
            Invoke-SIDataFindingRanges -Invoke $script:Inv -CollectionId $a -Lo ([long]$bd['Lo']) -Hi ([long]$bd['Hi']) -Sql (Get-SIDataDeriveFindingSql -Fix -Category -RowColumns) -BatchSize ([ref]$bs)
        }
        $o2 = Time 'OLD risk score parts (own pass)' $script:N {
            Invoke-SIDataFindingRanges -Invoke $script:Inv -CollectionId $a -Lo ([long]$bd['Lo']) -Hi ([long]$bd['Hi']) -Sql (Get-SIDataRiskPartsSql)
        }
        $o3 = Time 'OLD facets (fix column, ISJSON + component)' $script:N { $fs = [long]20000; Invoke-SIDataFacet -Invoke $script:Inv -CollectionId $a -FixColumn -BatchSize ([ref]$fs) }
        Cold
        $o4 = Time 'OLD counted facets (reading DetailJson)' $script:N { $fs = [long]20000; Invoke-SIDataFacet -Invoke $script:Inv -CollectionId $a -Counted -BatchSize ([ref]$fs) }
        $old = $o1 + $o2 + $o3 + $o4
        Say ('OLD total {0,9:N1} s = {1,6:N1} min  {2,9:N0} rows/s' -f $old, ($old / 60), ($script:N / $old))

        Cold
        $n1 = Time 'NEW derive (one parse, parts, facets typed)' $script:N {
            $bs = [long]20000
            Invoke-SIDataDeriveCollection -Invoke $script:Inv -CollectionId $b -Fix -BatchSize ([ref]$bs)
        }
        Cold
        $n2 = Time 'NEW counted facets (typed columns)' $script:N {
            $fs = [long]20000; Invoke-SIDataFacet -Invoke $script:Inv -CollectionId $b -Counted -Typed:(Test-SIDataCollectionTyped -Invoke $script:Inv -CollectionId $b) -BatchSize ([ref]$fs)
        }
        $new = $n1 + $n2
        Say ('NEW total {0,9:N1} s = {1,6:N1} min  {2,9:N0} rows/s  ({3:N1}x faster)' -f $new, ($new / 60), ($script:N / $new), ($old / [Math]::Max(0.001, $new)))

        # both paths wrote (the comparison is not of two empty sets)
        foreach ($c in $a, $b) { [long](& $script:Inv 'SELECT COUNT(*) FROM sidata.Finding WHERE CollectionId = @c AND RiskScoreWeighted IS NOT NULL AND RiskAssetDerived IS NOT NULL AND RaRowAssetId IS NOT NULL' @{ c = $c } 'scalar') | Should -BeGreaterThan ($script:N / 2) }
        # every derived column of every row, both ways
        $cols = 'RiskScoreWeighted, RiskRating, MitreTactics, MitreTechniques, ComplianceTags, Cvss, HasExploit, FixRemediation, FixRecommendedUpdate, FixRecommendedUpdateId, AffectedSoftware, RaCategory, ' +
                'RaRowAssetId, RaRowSolutionVersion, RaRowCriticalityTier, RaRowSiComponent, RaScopeRiskRating, RaScopeCategory, RaScopeSubcategory, RaScopeClass, RaScopeComponent, RaScopePatchCycle, RaScopeOsFamily, RaScopeSubCi, RaScopeAffectedProduct, RaFillRiskFactorProbability, RaFillRiskFactorConsequence, ' +
                'RiskAssetBase, RiskAssetSide, RiskAssetPoints, RiskAssetFactors, RiskAssetDerived, RiskVulnBase, RiskVulnSide, RiskVulnPoints, RiskVulnFactors, RiskVulnDerived, RiskWeightPct, RiskWeightBy'
        $cmp = "SELECT COUNT(*) FROM (SELECT FindingId - @lo1 AS r, $cols FROM sidata.Finding WHERE CollectionId = @c1 EXCEPT SELECT FindingId - @lo2, $cols FROM sidata.Finding WHERE CollectionId = @c2) AS d"
        $lo1 = [long]$bd['Lo']; $lo2 = [long]((Get-Row (Get-SIDataFindingBoundsSql) @{ CollectionId = $b })['Lo'])
        [long](& $script:Inv $cmp @{ c1 = $a; lo1 = $lo1; c2 = $b; lo2 = $lo2 } 'scalar') | Should -Be 0
        [long](& $script:Inv $cmp @{ c1 = $b; lo1 = $lo2; c2 = $a; lo2 = $lo1 } 'scalar') | Should -Be 0
        $fcmp = "SELECT COUNT(*) FROM (SELECT Facet, Value, Findings, Assets FROM sidata.{0} WHERE CollectionId = @c1 EXCEPT SELECT Facet, Value, Findings, Assets FROM sidata.{0} WHERE CollectionId = @c2) AS d"
        foreach ($t in 'FindingFacet', 'FindingFacetCounted') {
            [long](& $script:Inv ($fcmp -f $t) @{ c1 = $a; c2 = $b } 'scalar') | Should -Be 0
            [long](& $script:Inv ($fcmp -f $t) @{ c1 = $b; c2 = $a } 'scalar') | Should -Be 0
        }
        Say ('same values: every derived column of all {0:N0} rows and both facet tables, 0 differences' -f $script:N)
        $new | Should -BeLessThan $old
    }
}
