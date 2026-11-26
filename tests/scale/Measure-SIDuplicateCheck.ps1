#Requires -Version 7.0
<#
.SYNOPSIS
    ON DEMAND (never in a gate): the duplicate check (#1365, Invoke-SIDataDuplicateCheck) on a generated database of -Cis CIs with
    -CvesPerCi CVE findings each (and the facts in sidata.Finding), -DupEvery: every Nth CI also has a Defender for Cloud "Update
    <software>" finding next to its CVEs of that software (an unmerged duplicate) and the matching task pair. Prints the rows,
    the seconds per phase and the duplicates found (they must equal the CIs seeded with one). Needs SI_TEST_LOCALSQL.
.EXAMPLE
    pwsh -File tests\scale\Measure-SIDuplicateCheck.ps1 -Cis 20000 -CvesPerCi 50 -DupEvery 10
#>
param([int]$Cis = 20000, [int]$CvesPerCi = 50, [int]$DupEvery = 10, [int]$CisPerRange = 2000, [int]$OwnersPerPage = 200, [switch]$Keep)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $root 'tests\pester\_SITestSql.ps1'); $null = Initialize-SITestSqlEnv
if (-not $env:SI_TEST_LOCALSQL) { throw 'needs SI_TEST_LOCALSQL (TEST_SQL_*)' }
. (Join-Path $root 'engine\data-model\SI-RecommendationEquivalence.ps1')
. (Join-Path $root 'engine\pro-data\_shared\SI-DataDuplicateCheck.ps1')
$db = 'si_dupscale_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$m = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30")
$m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$db]"; $c.CommandTimeout = 600; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() }
$cn = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=$db;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30;Pooling=false"); $cn.Open()
function Sql([string]$Text, [hashtable]$P = @{}, [string]$Mode = 'nonquery') {
    $c = $cn.CreateCommand(); $c.CommandText = $Text; $c.CommandTimeout = 0
    foreach ($k in $P.Keys) { [void]$c.Parameters.AddWithValue('@' + $k, $(if ($null -eq $P[$k]) { [DBNull]::Value } else { $P[$k] })) }
    if ($Mode -eq 'scalar') { return $c.ExecuteScalar() }
    if ($Mode -eq 'reader') { $rd = $c.ExecuteReader(); $rows = New-Object System.Collections.Generic.List[object]
        try { while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $rd.GetValue($i) }; $rows.Add($h) } } finally { $rd.Dispose() }
        return , $rows.ToArray() }
    [void]$c.ExecuteNonQuery()
}
try {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    Sql ([IO.File]::ReadAllText((Join-Path $root 'sql\si-pro-settings.sql')))
    Sql ([IO.File]::ReadAllText((Join-Path $root 'sql\si-vulnerability-target.sql'))); Sql ([IO.File]::ReadAllText((Join-Path $root 'sql\si-data-schema.sql')))
    $cid = [int](Sql "INSERT sidata.Collection (CollectionTime, Kind, Status, ContextAt, RemediationTasksAt) VALUES ('2026-11-24T21:00:00', 'Detailed', 'Complete', SYSUTCDATETIME(), SYSUTCDATETIME()); SELECT CAST(SCOPE_IDENTITY() AS int)" @{} 'scalar')
    # generated set-based in CI chunks (each its own statement, simple recovery: the test server's log stays small): CIs, CVE
    # findings (findings per CI as the database path makes them + their sidata.Finding facts), the duplicates, the tasks
    Sql "ALTER DATABASE CURRENT SET RECOVERY SIMPLE"
    Sql "SET NOCOUNT ON; WITH n AS (SELECT TOP ($Cis) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b) INSERT sidata.Ci (CiId, Class, Name, Tier, Lifecycle, CollectionTime) SELECT CONCAT(N'ci-', RIGHT(CONCAT(N'0000000', i), 7)), N'device', CONCAT(N'host', i), 2, N'active', '2026-11-24' FROM n;"
    for ($lo = 1; $lo -le $Cis; $lo += 1000) {
        $hi = [Math]::Min($Cis, $lo + 999)
        $rng = "CONVERT(int, SUBSTRING(c.CiId, 4, 7)) BETWEEN $lo AND $hi"
        Sql @"
SET NOCOUNT ON;
WITH k AS (SELECT TOP ($CvesPerCi) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS j FROM sys.all_objects)
INSERT sidata.CiFinding (CiId, AssetId, FindingKey, FindingType, Title, Severity, CollectionTime, DocJson)
SELECT c.CiId, N'', CONCAT(N'CVE-2025-', 10000 + k.j), N'cve', N'flaw', N'high', '2026-11-24T21:00:00', CONCAT(N'{"si_finding_key":"CVE-2025-', 10000 + k.j, N'","si_finding_source":"database"}')
FROM sidata.Ci c CROSS JOIN k WHERE $rng;
WITH k AS (SELECT TOP ($CvesPerCi) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS j FROM sys.all_objects)
INSERT sidata.Finding (CollectionId, AssetKey, ReportName, ConfigurationId, Cve, Title, Severity, AffectedProduct, RaFindingKey)
SELECT $cid, c.CiId, N'Device_Missing_CVEs_Detailed', CONCAT(N'CVE-2025-', 10000 + k.j), CONCAT(N'CVE-2025-', 10000 + k.j), N'flaw', N'High',
       CASE WHEN k.j % 10 IN (1, 2) THEN N'openssl' ELSE CONCAT(N'lib', k.j % 10) END, CONCAT(c.CiId, N'|cve-2025-', 10000 + k.j)
FROM sidata.Ci c CROSS JOIN k WHERE $rng;
INSERT sidata.CiFinding (CiId, AssetId, FindingKey, FindingType, Title, Severity, CollectionTime, DocJson)
SELECT c.CiId, N'', N'mdc-update-openssl', N'recommendation', N'Update openssl', N'high', '2026-11-24T21:00:00', N'{"si_finding_source":"database"}'
FROM sidata.Ci c WHERE $rng AND CONVERT(int, SUBSTRING(c.CiId, 4, 7)) % $DupEvery = 0;
INSERT sidata.RemediationTask (CollectionId, TaskId, OwnerKey, CiId, AssetKey, AssetName, TaskKey, TaskName, Kind, Product, Findings, Cves, Departments, FirstSeen, LastSeen, State, InThisCollection, RowHash, ChangedAt)
SELECT $cid, HASHBYTES('SHA2_256', c.CiId + v.n), c.CiId, c.CiId, c.CiId, c.Name, LOWER(v.k + N'|' + v.n), v.n, v.k, v.p, 1, 0, 0, SYSUTCDATETIME(), SYSUTCDATETIME(), N'open', 1, 0x00, SYSUTCDATETIME()
FROM sidata.Ci c CROSS APPLY (VALUES (N'Update openssl', N'configuration', NULL), (N'Update App (bundles openssl 3.0.1)', N'bundled-upgrade', N'openssl'), (N'Update lib5 1.0 (x)', N'software-upgrade', N'lib5')) v(n, k, p)
WHERE $rng AND (v.k <> N'configuration' OR CONVERT(int, SUBSTRING(c.CiId, 4, 7)) % $DupEvery = 0);
"@
    }
    $gen = $clock.Elapsed.TotalSeconds
    $rows = [long](Sql 'SELECT COUNT_BIG(*) FROM sidata.CiFinding' @{} 'scalar')
    $idx = ConvertTo-SIRecommendationEquivalenceIndex -Document ([IO.File]::ReadAllText((Join-Path $root 'data-model\recommendation-equivalence.locked.json')) | ConvertFrom-Json)
    $before = [GC]::GetTotalMemory($true)
    $r = Invoke-SIDataDuplicateCheck -Invoke { param($s, $p, $md) Sql $s $p $md } -Index $idx -CisPerRange $CisPerRange -OwnersPerPage $OwnersPerPage -Log { param($l, $x) Write-Host "[$l] $x" }
    $expected = [int][Math]::Floor($Cis / $DupEvery)
    Write-Host ('generated {0:N0} CIs, {1:N0} findings per CI, {2:N0} findings in {3:N1} s' -f $Cis, $CvesPerCi, $rows, $gen)
    Write-Host ('check: {0} in {1} s ({2}); {3:N0} candidate CIs, {4} ranges; managed memory after {5:N1} MB (before {6:N1} MB)' -f $r.Status, $r.Seconds, $r.Phases, $r.Candidates, $r.Ranges, ([GC]::GetTotalMemory($false) / 1MB), ($before / 1MB))
    foreach ($x in @($r.Rules)) { Write-Host ('  {0}: {1} on {2} CI(s)' -f $x.Id, $x.Duplicates, $x.Owners) }
    $fold = @($r.Rules | Where-Object Id -eq 'fold:mdc-update-software-on-mde-cve')[0].Duplicates
    $task = @($r.Rules | Where-Object Id -eq 'task-update-restates-software')[0].Duplicates
    Write-Host ('expected {0} fold and {0} task duplicates: fold {1}, task {2} -> {3}' -f $expected, $fold, $task, $(if ($fold -eq $expected -and $task -eq $expected) { 'OK' } else { 'MISMATCH' }))
    if ($fold -ne $expected -or $task -ne $expected) { exit 1 }
} finally {
    $cn.Dispose()
    if (-not $Keep) { $m = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30"); $m.Open(); try { $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]"; [void]$c.ExecuteNonQuery() } finally { $m.Dispose() } }
}
