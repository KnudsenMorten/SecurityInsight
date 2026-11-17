#Requires -Version 7.0
<#
    The Azure test runner's SQL sidecar, as the scale suites see it: edition, version, the database size cap, memory, the
    disk under the data / log / tempdb files and their free space, the model database's file sizes and growth (a new
    database starts from it). Read-only; creates nothing.
      pwsh -NoProfile -File SOLUTIONS/SecurityInsight/tests/fixtures/review1/probe-sql.ps1
#>
$ErrorActionPreference = 'Stop'
$si = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
. (Join-Path $si 'tests\pester\_SITestSql.ps1')
$s = Initialize-SITestSqlEnv
Write-Host ("SQL: {0} ({1})" -f $s.Server, $s.Source)
$cn = [System.Data.SqlClient.SqlConnection]::new("Server=$($env:SI_TEST_LOCALSQL);Database=master;$($env:SI_TEST_SQL_AUTH);Connection Timeout=30")
$cn.Open()
function Show([string]$Title, [string]$Sql) {
    Write-Host "== $Title"
    $c = $cn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 120
    try {
        $r = $c.ExecuteReader()
        try {
            while ($r.Read()) {
                $parts = for ($i = 0; $i -lt $r.FieldCount; $i++) { '{0}={1}' -f $r.GetName($i), $r.GetValue($i) }
                Write-Host ('  ' + ($parts -join '  '))
            }
        } finally { $r.Dispose() }
    } catch { Write-Host ('  (not readable: {0})' -f $_.Exception.Message) }
}
Show 'server' "SELECT CONVERT(nvarchar(128), SERVERPROPERTY('Edition')) AS Edition, CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')) AS Version, CONVERT(nvarchar(128), SERVERPROPERTY('EngineEdition')) AS EngineEdition"
Show 'memory' "SELECT physical_memory_kb / 1024 AS PhysicalMB, committed_target_kb / 1024 AS TargetMB, cpu_count AS Cpus FROM sys.dm_os_sys_info"
Show 'max server memory' "SELECT name, value_in_use FROM sys.configurations WHERE name IN (N'max server memory (MB)', N'min server memory (MB)')"
Show 'files (model, tempdb, master)' "SELECT DB_NAME(database_id) AS Db, type_desc AS Kind, physical_name AS Path, size * 8 / 1024 AS SizeMB, CASE max_size WHEN -1 THEN -1 WHEN 0 THEN 0 ELSE CONVERT(bigint, max_size) * 8 / 1024 END AS MaxMB, CASE WHEN is_percent_growth = 1 THEN CONVERT(nvarchar(20), growth) + N'%' ELSE CONVERT(nvarchar(20), growth * 8 / 1024) + N'MB' END AS Growth FROM sys.master_files WHERE database_id IN (1, 2, 3)"
Show 'volumes' "SELECT DISTINCT vs.volume_mount_point AS Mount, vs.total_bytes / 1048576 AS TotalMB, vs.available_bytes / 1048576 AS FreeMB FROM sys.master_files f CROSS APPLY sys.dm_os_volume_stats(f.database_id, f.file_id) vs"
Show 'default paths' "SELECT CONVERT(nvarchar(400), SERVERPROPERTY('InstanceDefaultDataPath')) AS DataPath, CONVERT(nvarchar(400), SERVERPROPERTY('InstanceDefaultLogPath')) AS LogPath"
Show 'other databases' "SELECT name, recovery_model_desc FROM sys.databases WHERE database_id > 4"
$cn.Dispose()
