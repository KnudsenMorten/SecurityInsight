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
                     -2 / 258 (a client timeout), 10053 / 10054 / 233 / 64 (a reset or closed connection), "a severe error
                     occurred on the current command", a transport-level error, a broken pooled connection ("Internal .NET
                     Framework Data Provider error 6").
          never:     the database is full (1105 / 40544 / 1101), a query defect (syntax, a type mismatch), a permission -- they
                     fail on the first attempt.
        -ErrorRecord: an ErrorRecord, an exception (SqlException numbers and inner exceptions are read) or a text.
    #>
    param([AllowNull()]$ErrorRecord)
    if ($null -eq $ErrorRecord) { return $false }
    $codes = @(9001, 3314, 40613, 40501, 40197, 49918, 49919, 49920, 4060, 10928, 10929, 1205, -2, 258, 10053, 10054, 233, 64)
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
    [bool]($t -match '(?i)a severe error occurred on the current command|transport-level error|connection was forcibly closed|forcibly closed by the remote host|connection reset|Connection reset by peer|broken pipe|Internal \.NET Framework Data Provider error 6|is not currently available|log for database .* is not available|\b(9001|3314|40613|40501|40197|49918|49919|49920)\b')
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
            $cn = New-Object System.Data.SqlClient.SqlConnection(("Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connect Timeout={2}" -f $Server, $Database, $cto))
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
