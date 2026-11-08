#Requires -Version 7.0
<#
.SYNOPSIS
    WHERE THE TESTS' SQL SERVER IS, AND HOW THEY SIGN IN TO IT -- one place, ONE code path: a SQL login from TEST_SQL_*
    (framework REQUIREMENTS 12.1 "HARNESS CONTRACT", rule 1; Invardia 2026-11-08: no Windows sign-in fallback -- a fallback
    hides exactly the drift this removes).

.DESCRIPTION
    Every SI suite builds its connection string from two environment variables:
        Server=$env:SI_TEST_LOCALSQL;Database=<db>;$env:SI_TEST_SQL_AUTH;...
    Initialize-SITestSqlEnv sets them from the Linux test runner's TEST_SQL_CONNECTION_STRING, or TEST_SQL_SERVER
    [+ TEST_SQL_PORT] + TEST_SQL_USER + TEST_SQL_PASSWORD: SI_TEST_LOCALSQL = the server (",port" when given),
    SI_TEST_SQL_AUTH = "User ID=..;Password=..;TrustServerCertificate=True". The gate (tests\Invoke-FastGate.ps1) and every
    shard (_Invoke-GateShard.ps1) call it; every process a test starts inherits them. SQL suites run on the Linux runner; the
    Windows VM runs only Windows-marked tests, which need no SQL.
    TEST_SQL_* not set = nothing is set (Source 'missing'), and the gate stops a run that has SQL suites or the web app's tests:
    "TEST_SQL_* not set" -- NOT TESTED, never a quiet skip. The login may create and drop its own databases.
    DbConnectionStringBuilder: set and read the text with set_/get_ConnectionString() -- `.ConnectionString` on the builder
    reaches a KEY of that name through PowerShell's dictionary adapter (framework 12.1 rule 7).
#>

function Get-SITestSqlSettings {
    <# PURE. -Environment: a hashtable of the variables (the process's own when left out). Returns @{ Server; Auth; Source }
       (Source 'TEST_SQL', or 'missing' with Server / Auth empty). #>
    param([hashtable]$Environment)
    if (-not $Environment) {
        $Environment = @{}
        foreach ($k in 'TEST_SQL_CONNECTION_STRING', 'TEST_SQL_SERVER', 'TEST_SQL_PORT', 'TEST_SQL_USER', 'TEST_SQL_PASSWORD') {
            $Environment[$k] = [Environment]::GetEnvironmentVariable($k)
        }
    }
    $v = { param($k) $x = $Environment[$k]; if ($null -eq $x) { '' } else { ([string]$x).Trim() } }
    $user = & $v 'TEST_SQL_USER'; $pw = [string]$Environment['TEST_SQL_PASSWORD']; $server = & $v 'TEST_SQL_SERVER'
    $cs = & $v 'TEST_SQL_CONNECTION_STRING'
    if ($cs) {
        $b = New-Object System.Data.Common.DbConnectionStringBuilder
        $b.set_ConnectionString($cs)
        foreach ($k in @($b.Keys)) {
            switch -Regex ([string]$k) {
                '^(server|data source|address|addr|network address)$' { if (-not $server) { $server = [string]$b[$k] } }
                '^(user id|uid|user)$'                               { if (-not $user) { $user = [string]$b[$k] } }
                '^(password|pwd)$'                                   { if (-not $pw) { $pw = [string]$b[$k] } }
            }
        }
    } elseif ($server -and (& $v 'TEST_SQL_PORT') -and $server -notmatch ',\d+$') {
        $server = '{0},{1}' -f $server, (& $v 'TEST_SQL_PORT')
    }
    if (-not ($server -and $user)) { return [pscustomobject]@{ Server = ''; Auth = ''; Source = 'missing' } }
    $a = New-Object System.Data.Common.DbConnectionStringBuilder
    $a['User ID'] = $user; $a['Password'] = $pw; $a['TrustServerCertificate'] = 'True'
    # tests open a second connection from an open one's .ConnectionString (an EXECUTE AS user, a second reader): SqlClient
    # drops the password from that text once a connection is open unless this is on -- a TEST login only, never product code
    $a['Persist Security Info'] = 'True'
    [pscustomobject]@{ Server = $server; Auth = $a.get_ConnectionString(); Source = 'TEST_SQL' }
}

function Initialize-SITestSqlEnv {
    <# Sets SI_TEST_LOCALSQL + SI_TEST_SQL_AUTH for this process and every process it starts (cleared when TEST_SQL_* is not
       set, so no stale value is used). Returns the settings. #>
    $s = Get-SITestSqlSettings
    $env:SI_TEST_LOCALSQL = $(if ($s.Source -eq 'TEST_SQL') { $s.Server } else { $null })
    $env:SI_TEST_SQL_AUTH = $(if ($s.Source -eq 'TEST_SQL') { $s.Auth } else { $null })
    $s
}
