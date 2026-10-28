#Requires -Version 7.0
param([string]$Server = '.\SQLEXPRESS', [int]$Rows = 300000, [int]$JsonChars = 3000, [string]$Database = 'si_bucket_delete_bench', [switch]$Keep)
# Vendor bench (not a test; run it on the test VM, which has SQL Express): how the statement that removes what one query
# slice stored before (Get-RAStreamDeleteBucketSql, Detailed) reads sidata.Finding when the current run already holds
# -Rows rows of the report. The table carries the same key and the same Risk Analysis indexes as si-data-schema.sql; the
# statement is run as the engine runs it (parameters), once AS IT WAS and once as it is now, with the pages it read.
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'engine\risk-analysis\_shared\RA-SqlStream.ps1')
$cs0 = "Server=$Server;Database=master;Integrated Security=True;TrustServerCertificate=True"
function Invoke-Q([string]$Cs, [string]$Sql, [hashtable]$P = @{}, [int]$Timeout = 1800) {
    $c = [System.Data.SqlClient.SqlConnection]::new($Cs); $c.Open()
    $msgs = [System.Collections.Generic.List[string]]::new()
    $c.add_InfoMessage({ param($s, $e) $msgs.Add($e.Message) }.GetNewClosure())
    try { $cmd = $c.CreateCommand(); $cmd.CommandText = $Sql; $cmd.CommandTimeout = $Timeout
        foreach ($k in $P.Keys) { $null = $cmd.Parameters.AddWithValue($k, [string]$P[$k]) }
        $r = $cmd.ExecuteScalar(); [pscustomobject]@{ Result = $r; Messages = $msgs.ToArray() } } finally { $c.Dispose() }
}
$null = Invoke-Q $cs0 "IF DB_ID('$Database') IS NOT NULL BEGIN ALTER DATABASE [$Database] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$Database]; END; CREATE DATABASE [$Database]; ALTER DATABASE [$Database] SET RECOVERY SIMPLE;"
$cs = "Server=$Server;Database=$Database;Integrated Security=True;TrustServerCertificate=True"
$null = Invoke-Q $cs @"
CREATE SCHEMA sidata;
"@
$null = Invoke-Q $cs @"
CREATE TABLE sidata.Finding (FindingId BIGINT IDENTITY(1,1) NOT NULL, CollectionId INT NOT NULL, AssetKey NVARCHAR(400) NULL, ReportName NVARCHAR(256) NULL,
  Severity NVARCHAR(30) NULL, Tier TINYINT NULL, RiskScore FLOAT NULL, DetailJson NVARCHAR(MAX) NULL,
  RaReport INT NULL, RaBucket NVARCHAR(64) NULL, RaSeq BIGINT NULL, RaDedup BINARY(16) NULL, RaSort FLOAT NULL, RaInView BIT NULL,
  CONSTRAINT PK_Finding PRIMARY KEY CLUSTERED (CollectionId, FindingId));
CREATE INDEX IX_Finding_Drilldown ON sidata.Finding (CollectionId, Tier, Severity, RiskScore DESC) INCLUDE (AssetKey, ReportName);
CREATE INDEX IX_Finding_RaOrder ON sidata.Finding (CollectionId, RaSort DESC, RaSeq) INCLUDE (RaReport, RaInView) WHERE RaSeq IS NOT NULL;
CREATE INDEX IX_Finding_RaBucket ON sidata.Finding (CollectionId, RaReport, RaBucket) WHERE RaSeq IS NOT NULL;
CREATE INDEX IX_Finding_RaDedup ON sidata.Finding (CollectionId, RaReport, RaDedup, RaSeq) WHERE RaDedup IS NOT NULL;
"@
$sw = [Diagnostics.Stopwatch]::StartNew()
# the run so far: report 3 has 56 slices of rows stored (collection 7), an older run below it (collection 6)
$null = Invoke-Q $cs @"
SET NOCOUNT ON;
DECLARE @pad nvarchar(max) = REPLICATE(CONVERT(nvarchar(max), N'x'), $JsonChars);
WITH n AS (SELECT TOP ($Rows) ROW_NUMBER() OVER (ORDER BY (SELECT NULL)) AS i FROM sys.all_objects a CROSS JOIN sys.all_objects b CROSS JOIN sys.all_objects c)
INSERT sidata.Finding (CollectionId, AssetKey, ReportName, Severity, Tier, RiskScore, DetailJson, RaReport, RaBucket, RaSeq, RaDedup, RaSort, RaInView)
SELECT CASE WHEN i % 4 = 0 THEN 6 ELSE 7 END, CONCAT(N'ci-', i % 2400), N'Device_Missing_CVEs_Detailed', N'High', CONVERT(tinyint, i % 4), i % 50,
       CONCAT(N'{"x":"', @pad, N'"}'), 3, CONCAT(CONVERT(nvarchar(10), 1 + i % 56), N'/64'), i, HASHBYTES('MD5', CONVERT(varchar(20), i)), i % 50, 1 FROM n;
"@ -Timeout 3600
Write-Host ("loaded {0:N0} rows ({1} characters of JSON each) in {2:N0} s" -f $Rows, $JsonChars, $sw.Elapsed.TotalSeconds)
$null = Invoke-Q $cs 'UPDATE STATISTICS sidata.Finding WITH FULLSCAN; CHECKPOINT;'
$old = "DELETE FROM sidata.Finding WHERE CollectionId = CONVERT(int, @CollectionId) AND RaReport = CONVERT(int, @Report) AND (@Bucket = '*' OR RaBucket = @Bucket);`nSELECT @@ROWCOUNT;"
$new = Get-RAStreamDeleteBucketSql -Grain Detailed
$p = @{ CollectionId = '7'; Report = '3'; Bucket = '57/64' }
foreach ($case in @(@('AS IT WAS', $old), @('NOW', $new), @('AS IT WAS', $old), @('NOW', $new))) {
    $null = Invoke-Q $cs 'CHECKPOINT; DBCC DROPCLEANBUFFERS;'
    $sw.Restart()
    $r = Invoke-Q $cs ("SET STATISTICS IO ON;`n" + $case[1]) $p
    $reads = (@($r.Messages | Where-Object { $_ -match "Table 'Finding'" }) -join ' ') -replace '\s+', ' '
    Write-Host ("{0,-10} {1,8:N2} s  removed {2}  {3}" -f $case[0], $sw.Elapsed.TotalSeconds, $r.Result, $reads)
}
# the same statement with rows to remove (a retried slice): both remove the same rows (slices 6 and 7 hold the same
# number of rows of the current run; slice 5 holds none of it -- its rows are all in the older run)
foreach ($case in @(@('AS IT WAS', $old, '6/64'), @('NOW', $new, '7/64'), @('AS IT WAS', $old, '5/64'), @('NOW', $new, '5/64'))) {
    $sw.Restart(); $r = Invoke-Q $cs $case[1] @{ CollectionId = '7'; Report = '3'; Bucket = $case[2] }
    Write-Host ("{0,-10} {1,8:N2} s  retried slice {2}: removed {3}" -f $case[0], $sw.Elapsed.TotalSeconds, $case[2], $r.Result)
}
if (-not $Keep) { $null = Invoke-Q $cs0 "ALTER DATABASE [$Database] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$Database];" }
