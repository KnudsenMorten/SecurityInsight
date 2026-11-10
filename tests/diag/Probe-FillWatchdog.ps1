# DIAGNOSTIC (test runner only, never shipped to an install): the field fill's watchdog against a held row lock, every step
# printed with its time, the call in a thread job with a hard outer limit -- so a hang shows WHERE it stops.
$ErrorActionPreference = 'Continue'
function P([string]$t) { [Console]::Out.WriteLine(('{0:HH:mm:ss.fff} {1}' -f [datetime]::UtcNow, $t)); [Console]::Out.Flush() }
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
# the runner's SQL (TEST_SQL_*) as the gate hands it to every suite
. (Join-Path $root 'tests/pester/_SITestSql.ps1'); Initialize-SITestSqlEnv
$db = 'si_probe_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$auth = $env:SI_TEST_SQL_AUTH; $srv = $env:SI_TEST_LOCALSQL
P "server=$srv"
$m = New-Object System.Data.SqlClient.SqlConnection "Server=$srv;Database=master;$auth;Connection Timeout=30"; $m.Open(); $c = $m.CreateCommand(); $c.CommandText = "CREATE DATABASE [$db]"; [void]$c.ExecuteNonQuery(); $m.Dispose()
$cs = "Server=$srv;Database=$db;$auth;Connection Timeout=30;Pooling=false"
$cn = New-Object System.Data.SqlClient.SqlConnection $cs; $cn.Open(); $c = $cn.CreateCommand(); $c.CommandText = 'CREATE TABLE dbo.R (Id bigint NOT NULL PRIMARY KEY, V int NOT NULL); INSERT dbo.R (Id, V) SELECT TOP (40) ROW_NUMBER() OVER (ORDER BY (SELECT 1)), 0 FROM sys.all_objects;'; [void]$c.ExecuteNonQuery(); $cn.Dispose()
P 'table made'
$hold = New-Object System.Data.SqlClient.SqlConnection ($cs + ';Application Name=si-test-lock-holder'); $hold.Open(); $tx = $hold.BeginTransaction()
$h = $hold.CreateCommand(); $h.Transaction = $tx; $h.CommandText = 'UPDATE dbo.R SET V = V + 100 WHERE Id = 15'; [void]$h.ExecuteNonQuery()
P 'lock held on row 15'
$job = Start-ThreadJob -ScriptBlock {
    param($root, $cs)
    . (Join-Path $root 'engine/pro-data/_shared/SI-DataViewContext.ps1')
    $log = { param($l, $t) [Console]::Out.WriteLine(('{0:HH:mm:ss.fff} LOG {1} {2}' -f [datetime]::UtcNow, $l, $t)); [Console]::Out.Flush() }
    try {
        $r = Invoke-SIDataParallelRanges -ConnectionInfo ({ @{ ConnectionString = $cs; AccessToken = '' } }.GetNewClosure()) -Sql 'UPDATE dbo.R WITH (ROWLOCK) SET V = V + 1 WHERE Id > @After AND Id <= @Upto AND @CollectionId = @CollectionId; SELECT @@ROWCOUNT;' -CollectionId 1 -Ranges @(@(0, 10), @(10, 20), @(20, 30)) -Log $log -StallSeconds 4 -WatchSeconds 1
        'RETURNED ' + (@($r | ForEach-Object { $_.N }) -join ',')
    } catch { 'THREW ' + $_.Exception.Message }
} -ArgumentList $root, $cs -StreamingHost $Host
P 'call started in a thread job'
$done = Wait-Job $job -Timeout 200
if ($done) { P ('job ended: ' + ((Receive-Job $job) -join ' | ')) } else { P 'JOB STILL RUNNING AFTER 200 s -- the hang is after the last LOG line above'; try { [Console]::Out.WriteLine((Get-Job | Format-List | Out-String)) } catch { } }
try { $tx.Rollback() } catch { }; $hold.Dispose(); P 'lock released'
if (-not $done) { $done2 = Wait-Job $job -Timeout 60; P ('after the release: ' + $(if ($done2) { 'ended: ' + ((Receive-Job $job) -join ' | ') } else { 'STILL running' })) }
[System.Data.SqlClient.SqlConnection]::ClearAllPools()
try { $m = New-Object System.Data.SqlClient.SqlConnection "Server=$srv;Database=master;$auth;Connection Timeout=30"; $m.Open(); $c = $m.CreateCommand(); $c.CommandText = "ALTER DATABASE [$db] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [$db]"; [void]$c.ExecuteNonQuery(); $m.Dispose() } catch { P "drop: $($_.Exception.Message)" }
P 'probe done'
[Environment]::Exit(0)
