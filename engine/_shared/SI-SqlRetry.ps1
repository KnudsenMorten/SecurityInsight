#Requires -Version 5.1
<#
    SecurityInsight -- THE ONE SQL CONNECTION RETRY (owner 2026-10-22: "why not use shared everywhere" / "stability is prio
    also"). Moved here from setup\_shared\SI-SetupArm.ps1 (Open-SISqlConnectionRetry, Test-SISqlNotYetAnswer) and
    engine\data-model\identity\SI-ObjectLedgerStore.ps1 (Test-SISqlTransientError), so the engine, the updater and setup open
    a database the same way.

    ONLY THE OPEN IS RETRIED. A statement that may already have run is never sent again by this file: an Open that failed
    sent nothing.

    PURE except Open-SISqlConnectionRetry's default -Connect (System.Data.SqlClient). PS 5.1 safe. Community + Pro.
#>

function Test-SISqlTransientError {
    <#
        Azure SQL faults worth another attempt at OPENING the connection. Deliberately a short, named list rather than
        "retry anything": retrying a permission or a syntax error just delays a real failure.
          40613 database not currently available (a serverless resume, or a failover)
          40197 / 40501 / 49918 / 49919 / 49920  service busy, throttled or moving
          4060  cannot open database right now
          10928 / 10929 resource limits
        -2 / 258 client timeouts
        -ErrorRecord: an ErrorRecord or an exception (inner exceptions are read too).
    #>
    param([Parameter(Mandatory)]$ErrorRecord)
    $codes = @(40613, 40197, 40501, 49918, 49919, 49920, 4060, 10928, 10929, -2, 258)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    while ($ex) {
        if ($ex -is [System.Data.SqlClient.SqlException] -and $codes -contains [int]$ex.Number) { return $true }
        $ex = $ex.InnerException
    }
    $msg = [string]$ErrorRecord
    if ($ErrorRecord -is [System.Exception]) { $msg = [string]$ErrorRecord.Message }
    return ($msg -match 'is not currently available|Please retry the connection later|too busy|try again')
}

function Test-SISqlStatementTransient {
    <#
        PURE and SELF-CONTAINED (it travels as a value into connection closures: it calls nothing by name). Is a failed SQL
        STATEMENT one of Azure SQL's platform answers, so the statement may be run again on a new connection? Live 2026-10-28:
        one statement of the data sync got 9001 (the log is not available) + 3314 (a rollback during recovery) + "A severe
        error occurred on the current command" after minutes of a saturated log, and a 52-hour run failed on it.
          transient: 9001, 3314, 40613, 40501, 40197, 49918 / 49919 / 49920 (not available, busy, moving), 4060 (cannot open
                     the database during a failover), 10928 / 10929 (resource limits), 1205 (chosen as a deadlock victim),
                     -2 / 258 (a client timeout), 10053 / 10054 / 233 / 64 (a reset or closed connection), 4083 ("the
                     connection was recovered and rowcount in the first query is not available": the driver re-made an idle
                     connection under the statement -- live 2026-11-04, a correlation run's CI build failed on it), "a severe error
                     occurred on the current command", a transport-level error, a broken pooled connection ("Internal .NET
                     Framework Data Provider error 6").
          never:     the database is full (1105 / 40544 / 1101), a query defect (syntax, a type mismatch), a permission -- they
                     fail on the first attempt.
        -ErrorRecord: an ErrorRecord, an exception (SqlException numbers and inner exceptions are read) or a text.
    #>
    param([AllowNull()]$ErrorRecord)
    if ($null -eq $ErrorRecord) { return $false }
    $codes = @(9001, 3314, 40613, 40501, 40197, 49918, 49919, 49920, 4060, 10928, 10929, 1205, -2, 258, 10053, 10054, 233, 64, 4083)
    $full = @(1105, 40544, 1101)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } elseif ($ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $null }
    $nums = New-Object System.Collections.Generic.List[int]
    $texts = New-Object System.Collections.Generic.List[string]
    while ($ex) {
        if ($ex -is [System.Data.SqlClient.SqlException]) {
            foreach ($er in @($ex.Errors)) { $nums.Add([int]$er.Number) }
            $nums.Add([int]$ex.Number)
        }
        try { if ($ex.Data -and $ex.Data.Contains('SISqlNumbers')) { foreach ($n in @($ex.Data['SISqlNumbers'])) { $nums.Add([int]$n) } } } catch { }
        $texts.Add([string]$ex.Message); $ex = $ex.InnerException
    }
    if (-not $texts.Count) { $texts.Add([string]$ErrorRecord) }
    $t = $texts -join ' | '
    foreach ($n in $nums) { if ($full -contains $n) { return $false } }
    if ($t -match '(?i)has reached its size quota|could not allocate (a new page|space)') { return $false }
    foreach ($n in $nums) { if ($codes -contains $n) { return $true } }
    [bool]($t -match '(?i)a severe error occurred on the current command|transport-level error|connection was forcibly closed|forcibly closed by the remote host|connection reset|Connection reset by peer|broken pipe|Internal \.NET Framework Data Provider error 6|is not currently available|log for database .* is not available|connection was recovered and rowcount|\b(9001|3314|40613|40501|40197|49918|49919|49920|4083)\b')
}

function Test-SISqlShapedFailure {
    <#
        PURE. Is this failure a SQL statement's own: a SqlException in the error's chain, the driver's text ('Exception calling
        "ExecuteScalar"', the reader, the non-query) or the engine's own 'SQL error <n>'? The words Test-SISqlStatementTransient
        reads ("connection reset", "is not currently available") also occur in other services' answers, so a text is only held
        against it when it is SQL's.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text, [AllowNull()]$ErrorRecord)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } elseif ($ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $null }
    while ($ex) { if ($ex -is [System.Data.SqlClient.SqlException]) { return $true }; $ex = $ex.InnerException }
    [bool]("$Text" -match '(?i)Exception calling "Execute(Scalar|Reader|NonQuery)(Async)?"|\bSQL error -?\d+\b')
}

function Get-SISqlErrorNumbers {
    <#
        PURE. SQL's own error numbers in a failure's chain, distinct and comma-joined ('9001,3314'), '' when it has none. The
        driver's message does not carry them. For the log and the uplink's Detail only: never the customer-visible reason.
    #>
    param([AllowNull()]$ErrorRecord)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } elseif ($ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $null }
    $nums = New-Object System.Collections.Generic.List[int]
    while ($ex) {
        if ($ex -is [System.Data.SqlClient.SqlException]) { foreach ($er in @($ex.Errors)) { $nums.Add([int]$er.Number) } }
        try { if ($ex.Data -and $ex.Data.Contains('SISqlNumbers')) { foreach ($n in @($ex.Data['SISqlNumbers'])) { $nums.Add([int]$n) } } } catch { }
        $ex = $ex.InnerException
    }
    (@($nums | Select-Object -Unique) -join ',')
}

function Test-SISqlConnectTransient {
    <#
        PURE and SELF-CONTAINED (it travels as a value; it calls nothing by name). Did the CONNECTION fail at the network /
        transport level, before anything was sent -- so opening it again a moment later is safe? Live 2026-11-07 (an install's
        pipeline runner, its settings read): "A network-related or instance-specific error occurred while establishing a
        connection to SQL Server ... (provider: TCP Provider, error: 40 - Could not open a connection to SQL Server)" stopped
        the run; every wake-up after it read the settings fine.
          transient: SqlException 40 / 53 / 10060 / 10061 / 10065 / 11001 / 1225 / 121 / 4060 / 40613 / 40197 / 40501 /
                     49918-49920 / -2 / 258 / 233 / 64 / 10053 / 10054, and the texts "network-related or instance-specific",
                     "Could not open a connection to SQL Server", "error: 40" / "error: 26" / "error: 0" of a provider, "semaphore
                     timeout", "connection attempt failed", "actively refused", "No such host is known", "server was not found".
          never:     a refused sign-in (18456 -- a grant, not the network), a permission, a missing database by name.
        -ErrorRecord: an ErrorRecord, an exception (SqlException numbers and inner exceptions are read) or a text.
    #>
    param([AllowNull()]$ErrorRecord)
    if ($null -eq $ErrorRecord) { return $false }
    $codes = @(40, 53, 10060, 10061, 10065, 11001, 1225, 121, 4060, 40613, 40197, 40501, 49918, 49919, 49920, -2, 258, 233, 64, 10053, 10054)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } elseif ($ErrorRecord -is [System.Exception]) { $ErrorRecord } else { $null }
    $nums = New-Object System.Collections.Generic.List[int]
    $texts = New-Object System.Collections.Generic.List[string]
    while ($ex) {
        if ($ex -is [System.Data.SqlClient.SqlException]) { foreach ($er in @($ex.Errors)) { $nums.Add([int]$er.Number) }; $nums.Add([int]$ex.Number) }
        $texts.Add([string]$ex.Message); $ex = $ex.InnerException
    }
    if (-not $texts.Count) { $texts.Add([string]$ErrorRecord) }
    $t = $texts -join ' | '
    # a refused sign-in is a grant, not the network (4060 "Cannot open database ... The login failed." IS the failover class)
    if ($nums -contains 18456 -or $t -match '(?i)Login failed for user|\b18456\b') { return $false }
    foreach ($n in $nums) { if ($codes -contains $n) { return $true } }
    [bool]($t -match '(?i)network-related or instance-specific error|Could not open a connection to SQL Server|\(provider: [^,]+, error: (0|26|35|40)\b|semaphore timeout|connection attempt failed|actively refused|No such host is known|server was not found or was not accessible|transport-level error|forcibly closed by the remote host|connection was forcibly closed|\b(40613|40197|40501|10060|10061|4060)\b')
}

function Get-SISqlConnectRetryWaits {
    <# #1147: the pauses before each new attempt to READ when the connection failed at the network level (Test-SISqlConnectTransient):
       4 more attempts over about 1.5 minutes -- a short network blip or a gateway that moved passes in seconds. #>
    @(5, 10, 20, 45)
}

function Get-SISqlStatementRetryWaits {
    <# The pauses before each new attempt of a statement that met an Azure SQL platform answer: 6 more attempts over about
       9 minutes (owner 2026-10-29). A failover or a resume passes in under a minute; a log that recovers after a rollback
       under load (the live case) takes minutes. A bound on Microsoft's errors, never on SI's own work. #>
    @(5, 15, 30, 60, 120, 300)
}

function Test-SISqlNotYetAnswer {
    <# PURE. Is this the refusal a database gives for a moment after its server's administrator or firewall rule changed:
       "Login failed" (18456) or "client with IP address ... is not allowed" (40615)? #>
    param([AllowEmptyString()][AllowNull()][string]$Text)
    [bool]("$Text" -match '(?i)Login failed|\b18456\b|\b40615\b|is not allowed to access the server')
}

function Open-SISqlConnectionRetry {
    <#
        Opens a database connection with an Entra token, and tries again -- a bounded number of times (Microsoft's errors),
        with a NEW token each time -- when the database answers
          * "Login failed" / 18456 / 40615: its administrator or firewall rule was changed a moment ago (Test-SISqlNotYetAnswer);
          * a transient Azure SQL fault: a failover, a serverless resume, busy, a client timeout (Test-SISqlTransientError).
        Any other failure is thrown at once. Only the OPEN is retried -- nothing has been sent yet.
          -Token    { param([bool]$Fresh) } -> the access token for https://database.windows.net/ ($Fresh = ask for a new one)
          -Waits    seconds between tries (default 6 x 20 s)
          -Connect  { param($Server, $Database, $Token) } -> an OPEN connection (tests; default: System.Data.SqlClient)
          -ConnectTimeoutSec  the driver's own connect timeout (default 30)
        Returns the open connection; the caller disposes it.
    #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][scriptblock]$Token,
          [int[]]$Waits = @(20, 20, 20, 20, 20, 20), [scriptblock]$Sleep, [scriptblock]$Connect, [int]$ConnectTimeoutSec = 30)
    if (-not $Connect) {
        $cto = $ConnectTimeoutSec
        $Connect = {
            param($Server, $Database, $Token)
            # BUILT, never formatted: a server or database value is always ONE value (a ';' in it never adds a keyword).
            # Self-contained (no function called by name -- this block travels as a value, see below).
            $csb = New-Object System.Data.SqlClient.SqlConnectionStringBuilder
            $h = "$Server".Trim(); if ($h.StartsWith('tcp:', [StringComparison]::OrdinalIgnoreCase)) { $h = $h.Substring(4) }
            $ci = $h.IndexOf(','); if ($ci -ge 0) { $h = $h.Substring(0, $ci) }
            $csb['Data Source'] = ('tcp:{0},1433' -f $h.Trim()); $csb['Initial Catalog'] = "$Database".Trim()
            $csb['Encrypt'] = $true; $csb['TrustServerCertificate'] = $false; $csb['Connect Timeout'] = $cto
            $cn = New-Object System.Data.SqlClient.SqlConnection($csb.ConnectionString)
            $cn.AccessToken = $Token
            try { $cn.Open() } catch { $cn.Dispose(); throw }
            $cn
        }.GetNewClosure()
    }
    $try = 0; $cn = $null
    while ($true) {
        $tok = ([string](& $Token ($try -gt 0))).Trim()
        if (-not $tok) { throw 'the sign-in could not issue an Azure SQL token for the caller.' }
        try { $cn = & $Connect $Server $Database $tok; break }
        catch {
            # SELF-CONTAINED (review 2, S3): the classification is written out here, never called by name -- this function
            # travels as a value into connection closures (SI-DataSql.ps1) that outlive the scope that loaded this file
            # (SI-Guard keeps one globally), where Test-SISqlNotYetAnswer / Test-SISqlTransientError are not visible: the
            # failed open then threw "not recognized", hid the real SQL error and lost the retry. The same rules as those two.
            $msgText = [string]$_.Exception.Message
            $notYet = [bool]($msgText -match '(?i)Login failed|\b18456\b|\b40615\b|is not allowed to access the server')
            $transient = $false
            if (-not $notYet) {
                $ex = $_.Exception
                while ($ex) {
                    if ($ex -is [System.Data.SqlClient.SqlException] -and @(40613, 40197, 40501, 49918, 49919, 49920, 4060, 10928, 10929, -2, 258) -contains [int]$ex.Number) { $transient = $true; break }
                    $ex = $ex.InnerException
                }
                if (-not $transient) { $transient = [bool]($msgText -match 'is not currently available|Please retry the connection later|too busy|try again') }
            }
            if ((-not $notYet -and -not $transient) -or $try -ge @($Waits).Count) { throw }
            $w = [int]@($Waits)[$try]; $try++
            $why = if ($notYet) { 'does not accept this sign-in yet (its administrator or firewall rule changed a moment ago)' } else { ('is not available for a moment ({0})' -f (([string]$_.Exception.Message -split "`n")[0].Trim())) }
            Write-Host ('       the database {0} {1} -- waiting {2} s and trying again ({3}/{4}) ...' -f $Database, $why, $w, $try, @($Waits).Count) -ForegroundColor DarkYellow
            if ($w -gt 0) { if ($Sleep) { & $Sleep $w } else { Start-Sleep -Seconds $w } }
        }
    }
    $cn
}
