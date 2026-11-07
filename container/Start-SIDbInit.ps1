#Requires -Version 5.1
<#
    caj-si-dbinit -- THE DATABASE SETUP JOB's entry point (framework SEC-08; setup\_shared\SI-DbInitJob.ps1 holds the design).
    Runs in the install's own engine image (/app = the SecurityInsight folder) as the job's OWN identity id-si-dbinit, a member
    of the SQL server's admin group. It reads its inputs from its environment (Read-SIDbInitInput), signs in to SQL with a
    token for THAT identity (the container's managed-identity endpoint, client_id = SI_DBINIT_MI_CLIENT_ID), runs the SQL the
    product's own scripts generate, reads every principal back, writes ONE result row (cfg.InstallState 'DbJob') and exits:
      0  every identity read back      1  a step or the read-back failed      2  refused inputs
    No module; SI's shared seams (Get-SIManagedIdentityToken, Open-SISqlConnectionRetry); no file is written (the release's VERSION file is read for the row).
#>
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($siRoot, 'setup', '_shared', 'SI-DbInitJob.ps1'))
. Import-SIDbInitSqlSources -SIRoot $siRoot

# SI's shared seams, no direct network call here: the managed-identity token (auth\SI-ManagedIdentity.ps1: the container's
# endpoint, the client id always sent) and the database open with its retry (engine\_shared\SI-SqlRetry.ps1). The image is
# the whole solution under /app, so both are there.
. ([IO.Path]::Combine($siRoot, 'auth', 'SI-ManagedIdentity.ps1'))
. ([IO.Path]::Combine($siRoot, 'engine', '_shared', 'SI-SqlRetry.ps1'))

$dbInput = Read-SIDbInitInput
$version = ''
try { $version = ([IO.File]::ReadAllText([IO.Path]::Combine($siRoot, 'VERSION'))).Trim() } catch { $version = '' }
$sql = {
    param([string]$Database, [string]$Query, $Params, [string]$Mode)
    # a token for Azure SQL for the job's own identity (client_id = SI_DBINIT_MI_CLIENT_ID); the open is retried with a fresh one
    $c = Open-SISqlConnectionRetry -Server $dbInput.Server -Database $Database -Token { param([bool]$Fresh) Get-SIManagedIdentityToken -Resource 'https://database.windows.net/' -ClientId ([string]$dbInput.MiClientId) -ForceRefresh:$Fresh }
    try {
        $cmd = $c.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0
        if ($Params) { foreach ($k in @($Params.Keys)) { $v = $Params[$k]; [void]$cmd.Parameters.AddWithValue('@' + $k, $(if ($null -eq $v) { [DBNull]::Value } else { $v })) } }
        if ($Mode -eq 'nonquery') { [void]$cmd.ExecuteNonQuery(); return }
        $rd = $cmd.ExecuteReader()
        $rows = New-Object System.Collections.Generic.List[object]
        try {
            do {
                $rows.Clear()
                while ($rd.Read()) { $h = @{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $h[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }; $rows.Add($h) }
            } while ($rd.NextResult())
        } finally { $rd.Close() }
        # the LAST result set (a batch that ends with its read-back SELECT)
        , $rows.ToArray()
    } finally { $c.Dispose() }
}
# Every line straight to the container's STANDARD OUTPUT, flushed at once: that stream is what Container Apps hands to the
# environment's console logs (ContainerAppConsoleLogs in the install's workspace) -- not the host's information stream, and
# nothing left in a buffer when the process exits (2026-11-05: a run's lines never reached the workspace).
$r = Invoke-SIDbInit -DbInput $dbInput -Sql $sql -Version $version -Log { param($m) [Console]::Out.WriteLine('[dbinit] ' + $m); [Console]::Out.Flush() }
[Console]::Out.Flush()
exit $r.ExitCode
