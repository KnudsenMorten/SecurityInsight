#Requires -Version 5.1
<#
    SI v3 -- the identity ledger's SQL persistence. THIN ON PURPOSE.

    Every decision lives in SI-ObjectIdentity.ps1, which is pure and has 24 tests. This file only moves
    rows in and out, so the part that can be wrong without a database stays provable without one.

    🔒 ENTRA-ONLY, CERTIFICATE AUTH. The server is created with azureADOnlyAuthentication, so there is
    no SQL login to leak and no password to store -- matching the connect rules (SPN + certificate,
    never a secret).

    🔴 DEGRADE LOUDLY, NEVER DIE. If the ledger is unreachable the run still publishes: the map is the
    customer's output and losing it to protect an id would be the wrong trade. What must NOT happen is
    silently emitting a derived id that LOOKS durable -- so the rows go out marked
    `SI_IdSource = derived-provisional`, which is true, and a connector is already forbidden from
    creating CIs from those. An outage costs a late CI, never a duplicate one.
#>

# The rule for an identifier value longer than the table's column (ConvertTo-SILedgerStoredValue) lives with the pure
# ledger functions; this file writes and looks up every value through it.
if (-not (Get-Command -Name ConvertTo-SILedgerStoredValue -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-ObjectIdentity.ps1') }

function Assert-SILedgerRowsFit {
    <#
        PURE. Refuses, BEFORE anything is written, a ledger row the table cannot hold -- in a moment, not after minutes of
        writes that are then undone (2026-10-12: 18,820 anchors written for 10 minutes and all of them lost to one value).
        -Rows: @{ Type; Value (as stored); CorrelationId }. The value's own length cannot fail any more (the short form
        of a long value always fits); the type and the id are checked all the same. Throws with the first row that does
        not fit and how many there are.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $bad = 0; $first = ''
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $why = ''
        if (([string]$r.Value).Length -gt 256) { $why = 'its value is {0} characters long (the most is 256)' -f ([string]$r.Value).Length }
        elseif (([string]$r.Type).Length -gt 64) { $why = 'its type name is {0} characters long (the most is 64)' -f ([string]$r.Type).Length }
        elseif (([string]$r.CorrelationId).Length -gt 64) { $why = 'its id is {0} characters long (the most is 64)' -f ([string]$r.CorrelationId).Length }
        if ($why) { $bad++; if (-not $first) { $v = [string]$r.Value; if ($v.Length -gt 80) { $v = $v.Substring(0, 80) + '...' }; $first = "identifier '{0}' = '{1}': {2}" -f [string]$r.Type, $v, $why } }
    }
    if ($bad -gt 0) { throw ("the identity ledger cannot hold {0} identifier(s) of this run, so nothing was written to it (first: {1})" -f $bad, $first) }
}

function Get-SILedgerCertificate {
    <#
        The engine SPN's certificate, found WITHOUT depending on the `Cert:` provider.

        🔑 The provider is not always there. A Windows PowerShell 5.1 child that inherits a pwsh 7
        parent's PSModulePath resolves Microsoft.PowerShell.Security to the PS7 build, fails to load it,
        and loses the `Cert:` drive with it -- so `Get-ChildItem Cert:\...` returns nothing for a
        certificate that is installed and readable. That is framework finding AUTH-1, and this file had
        its own copy of the same lookup. X509Store exists on both hosts, so the provider is the
        convenience and the store is the authority.
    #>
    param([Parameter(Mandatory)][string]$Thumbprint)

    $t = ($Thumbprint -replace '\s', '').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }

    foreach ($loc in 'LocalMachine', 'CurrentUser') {
        $found = $null
        if (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue) {
            $found = Get-ChildItem "Cert:\$loc\My" -ErrorAction SilentlyContinue |
                     Where-Object { $_.Thumbprint -eq $t -and $_.HasPrivateKey } | Select-Object -First 1
        }
        if (-not $found) {
            try {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', $loc)
                $store.Open('ReadOnly')
                $found = @($store.Certificates | Where-Object { $_.Thumbprint -eq $t -and $_.HasPrivateKey })[0]
                $store.Close()
            } catch {
                Write-Verbose ("ledger: X509Store {0}\My unreadable -- {1}" -f $loc, $_.Exception.Message)
            }
        }
        if ($found) { return $found }
    }
    return $null
}

function Get-SILedgerAccessToken {
    <#
        A database.windows.net access token for the engine SPN, via a certificate-signed client
        assertion.

        🔴 MSAL IS DELIBERATELY NOT USED, and this is the whole point of the function.
        `[Microsoft.Identity.Client.ConfidentialClientApplicationBuilder]` resolves under Windows
        PowerShell 5.1, because Az.Accounts loads MSAL into the default context there. Under pwsh 7
        Az.Accounts isolates its assemblies in a private load context, so the type does not exist and
        the call throws "Unable to find type". Measured on one machine within the same minute:
        5.1 -> ledger works, pwsh 7 -> ledger unavailable, publishing provisional ids.
        🔑 That mattered because the VisualCron nightly runs every SI launcher under **pwsh 7**, so the
        one host the schedule actually uses was the one host where durable ids silently stopped.
        A signed assertion needs only System.Security and an HTTPS POST, which behave identically on
        both hosts and cannot be disabled by someone else's module loading strategy.
    #>
    param(
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)][string]$AppId,
        [Parameter(Mandatory)][string]$TenantId,
        [string]$Scope = 'https://database.windows.net/.default'
    )

    # PS 5.1 defaults to TLS 1.0/1.1 on some hosts; the token endpoint requires 1.2+.
    try {
        if (([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) -ne [Net.SecurityProtocolType]::Tls12) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
    } catch { }

    $b64url = {
        param([byte[]]$Bytes)
        [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    }

    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $now      = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    $header  = @{ alg = 'RS256'; typ = 'JWT'; x5t = (& $b64url $Certificate.GetCertHash()) } | ConvertTo-Json -Compress
    $payload = @{ aud = $tokenUri; iss = $AppId; sub = $AppId; jti = [guid]::NewGuid().ToString()
                  nbf = $now; exp = ($now + 600) } | ConvertTo-Json -Compress

    $unsigned = (& $b64url ([Text.Encoding]::UTF8.GetBytes($header))) + '.' +
                (& $b64url ([Text.Encoding]::UTF8.GetBytes($payload)))

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if (-not $rsa) { throw ("ledger: certificate {0} has no usable RSA private key." -f $Certificate.Thumbprint) }
    $sig = & $b64url ($rsa.SignData([Text.Encoding]::UTF8.GetBytes($unsigned),
                                    [Security.Cryptography.HashAlgorithmName]::SHA256,
                                    [Security.Cryptography.RSASignaturePadding]::Pkcs1))

    # a time limit: without one this call waits for as long as the other side stays silent (PowerShell 7 has no default)
    $resp = Invoke-RestMethod -Method Post -Uri $tokenUri -TimeoutSec 60 -Body @{
        client_id             = $AppId
        scope                 = $Scope
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = "$unsigned.$sig"
        grant_type            = 'client_credentials'
    }
    if (-not $resp.access_token) { throw 'ledger: token endpoint returned no access_token.' }
    [string]$resp.access_token
}

# Test-SISqlTransientError: the shared SQL retry (engine\_shared\SI-SqlRetry.ps1) -- one list of transient Azure SQL faults
. ([IO.Path]::Combine($PSScriptRoot, '..', '..', '_shared', 'SI-SqlRetry.ps1'))

function Get-SIObjectLedgerConnection {
    <#
        A SqlConnection authenticated as the engine SPN with its certificate.
        Returns $null when the ledger is not configured -- which is the normal state until an operator
        points SI at a store, and must not be an error.
    #>
    param(
        [Parameter()][string]$Server   = [string]$global:SI_LedgerSqlServer,
        [Parameter()][string]$Database = [string]$global:SI_LedgerDatabase,
        [int]$MaxAttempts = 4
    )
    if ([string]::IsNullOrWhiteSpace($Server) -or [string]::IsNullOrWhiteSpace($Database)) { return $null }

    if ((Get-Command -Name Test-SIUseManagedIdentity -ErrorAction SilentlyContinue) -and (Test-SIUseManagedIdentity)) {
        # #209: a container job signing in as its managed identity. Its database user is created once by the
        # operator (CREATE USER [<identity name>] FROM EXTERNAL PROVIDER) -- setup prints that step.
        $token = Get-SIManagedIdentityToken -Resource 'https://database.windows.net/'
    } else {
        $thumb  = [string]$global:SI_SPN_CertThumbprint
        $appId  = [string]$global:SI_SPN_AppId
        $tenant = [string]$global:SI_SPN_TenantId
        if ([string]::IsNullOrWhiteSpace($thumb) -or [string]::IsNullOrWhiteSpace($appId)) {
            throw 'ledger: SI_SPN_AppId / SI_SPN_CertThumbprint are empty -- the engine bridges these from HighPriv_Modern_* at entry; if they are missing here that bridge did not run.'
        }

        $cert = Get-SILedgerCertificate -Thumbprint $thumb
        if (-not $cert) { throw ("ledger: certificate {0} not found with a private key in LocalMachine\My or CurrentUser\My (checked via the Cert: drive AND X509Store)." -f $thumb) }

        $token = Get-SILedgerAccessToken -Certificate $cert -AppId $appId -TenantId $tenant
    }

    # The database is provisioned to RUN CONTINUOUSLY (no auto-pause), so a cold-start resume is not
    # the expected path any more. The retry stays because Azure SQL is a shared service that can still
    # throttle or fail over, and because a single attempt against ANY managed database is a coin flip.
    # It is bounded and only covers the named transient codes -- see Test-SISqlTransientError.
    $delay = 5
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $conn = New-Object System.Data.SqlClient.SqlConnection
        $conn.ConnectionString = "Server=tcp:$Server,1433;Database=$Database;Encrypt=True;TrustServerCertificate=False;Connection Timeout=60;"
        $conn.AccessToken = $token
        try {
            $conn.Open()
            if ($attempt -gt 1) { Write-Warning ("ledger connected on attempt {0} of {1}" -f $attempt, $MaxAttempts) }
            return $conn
        } catch {
            try { $conn.Dispose() } catch { }
            $isTransient = Test-SISqlTransientError -ErrorRecord $_
            if (-not $isTransient -or $attempt -eq $MaxAttempts) { throw }
            # Write-Warning, not the engine's Write-Corr* helpers: those are defined in the CALLER, so a
            # test dot-sourcing this file on its own would fail inside the retry -- the one path that
            # must not add a second failure to the one it is recovering from.
            Write-Warning ("ledger connect attempt {0}/{1} hit a transient fault ({2}); retrying in {3}s" -f `
                            $attempt, $MaxAttempts, $_.Exception.Message.Split([char]10)[0].Trim(), $delay)
            Start-Sleep -Seconds $delay
            $delay = [Math]::Min($delay * 2, 40)
        }
    }
}

function Get-SIObjectLedger {
    <#
        The whole ledger as the hashtable Resolve-SIObjectIdentity expects:
        "type|value" -> @{ CorrelationId; FirstSeen }.

        Read whole rather than queried per anchor: a run resolves every object at once, and one round
        trip against a table of this shape beats thousands. Revisit only if a real estate makes it hurt
        -- not before, and with a measurement.
    #>
    param([Parameter()]$Connection)
    $ledger = @{}
    if ($null -eq $Connection) { return $ledger }

    $cmd = $Connection.CreateCommand()
    $cmd.CommandTimeout = 0
    $cmd.CommandText = 'SELECT IdentifierType, IdentifierValue, SI_CorrelationId, FirstSeen FROM si.ObjectIdentity'
    $rdr = $cmd.ExecuteReader()
    try {
        while ($rdr.Read()) {
            $k = '{0}|{1}' -f ([string]$rdr['IdentifierType']).ToLowerInvariant(), ([string]$rdr['IdentifierValue']).ToLowerInvariant()
            $ledger[$k] = @{ CorrelationId = [string]$rdr['SI_CorrelationId']; FirstSeen = [datetime]$rdr['FirstSeen'] }
        }
    } finally { $rdr.Close() }
    $ledger
}

function Save-SIObjectLedger {
    <#
        Persist one run's decisions: new anchors, and any merge supersessions.

        🔒 ONE TRANSACTION. A half-written merge is the worst possible state -- anchors re-pointed at a
        survivor while the superseded row is missing means the connector never learns old -> new and
        orphans a CI, which is precisely the failure the ledger exists to prevent. All or nothing.

        Anchors are UPSERTed by (type, value), never blind-inserted: an anchor already present under
        the same id is the normal case on every run after the first, and must be a no-op rather than a
        primary-key violation.
    #>
    param(
        [Parameter(Mandatory)]$Connection,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Decisions,
        [Parameter()][AllowEmptyCollection()][object[]]$Superseded,
        [Parameter()][datetime]$Now = ([datetime]::UtcNow)
    )

    # EVERY ROW IS MADE READY AND CHECKED BEFORE THE FIRST ONE IS WRITTEN: a value longer than the column goes in as its
    # short form (ConvertTo-SILedgerStoredValue), and a row the table cannot hold is refused here, in a moment -- not by
    # the database after minutes of writes that are then all undone.
    $anchors = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($Decisions)) {
        if ($null -eq $d -or [string]::IsNullOrWhiteSpace([string]$d.CorrelationId)) { continue }
        foreach ($n in @($d.NewIdentifiers)) {
            if ($null -eq $n) { continue }
            $anchors.Add([pscustomobject]@{ Type = [string]$n.Type; Value = (ConvertTo-SILedgerStoredValue -Value ([string]$n.Value)); CorrelationId = [string]$n.CorrelationId })
        }
    }
    Assert-SILedgerRowsFit -Rows $anchors.ToArray()

    # 🔑 ONE STATEMENT, not one round trip per anchor (2026-10-16, #605: a first run or a rebuild writes tens of thousands of
    # anchors, one MERGE each). The same rows land: an anchor written twice in one run keeps its LAST id (what the MERGEs
    # in order left), a supersession written twice keeps its FIRST new id (what 'insert when not there' left) -- decided
    # here, so the statement sees each key once. The same time: the run's time as the database stores a datetime
    # parameter. Still ONE transaction (Get-SIObjectLedgerSetSql), all or nothing.
    $byKey = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $order = New-Object System.Collections.Generic.List[string]
    foreach ($n in $anchors) {
        $k = $n.Type + '|' + $n.Value
        if (-not $byKey.ContainsKey($k)) { $order.Add($k) }
        $byKey[$k] = $n
    }
    $a = @(foreach ($k in $order) { $n = $byKey[$k]; [ordered]@{ ty = [string]$n.Type; va = [string]$n.Value; cid = [string]$n.CorrelationId } })
    $seenOld = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $s = @(foreach ($x in @($Superseded)) { if ($null -ne $x -and $seenOld.Add([string]$x.OldId)) { [ordered]@{ o = [string]$x.OldId; n = [string]$x.NewId } } })
    $nowText = ([System.Data.SqlTypes.SqlDateTime]$Now).Value.ToString('o')
    $p = @{ a = (ConvertTo-SILedgerJsonArray $a); s = (ConvertTo-SILedgerJsonArray $s); nowText = $nowText }
    $null = @(Invoke-SIObjectLedgerSql -Connection $Connection -Sql (Get-SIObjectLedgerSetSql) -Params $p)
    # the counts as before: every anchor and every supersession of the run's decisions
    [pscustomobject]@{ AnchorsWritten = $anchors.Count; SupersededWritten = @(@($Superseded) | Where-Object { $null -ne $_ }).Count }
}
function Get-SIObjectLedgerSubsetSql {
    <# The ledger rows of the given identifiers (@j = [{ t; v }]) and every row of the ids they point at. #>
    @'
SET NOCOUNT ON;
DECLARE @k TABLE (IdentifierType NVARCHAR(64), IdentifierValue NVARCHAR(450), PRIMARY KEY (IdentifierType, IdentifierValue));
INSERT @k SELECT DISTINCT t, v FROM OPENJSON(@j) WITH (t NVARCHAR(64), v NVARCHAR(450)) WHERE t IS NOT NULL AND v IS NOT NULL;
WITH hit AS (SELECT o.SI_CorrelationId FROM si.ObjectIdentity o JOIN @k k ON o.IdentifierType = k.IdentifierType AND o.IdentifierValue = k.IdentifierValue)
SELECT o.IdentifierType, o.IdentifierValue, o.SI_CorrelationId, o.FirstSeen FROM si.ObjectIdentity o
WHERE o.SI_CorrelationId IN (SELECT SI_CorrelationId FROM hit);
'@
}

function Invoke-SIObjectLedgerSql {
    <# One statement on the ledger's open connection -> rows (objects). The seam both ledger functions below use. #>
    param([Parameter(Mandatory)]$Connection, [Parameter(Mandatory)][string]$Sql, [hashtable]$Params = @{})
    $cmd = $Connection.CreateCommand(); $cmd.CommandTimeout = 0; $cmd.CommandText = $Sql
    foreach ($k in $Params.Keys) { $pp = $cmd.Parameters.Add('@' + $k, [System.Data.SqlDbType]::NVarChar, -1); $pp.Value = [string]$Params[$k] }
    $rdr = $cmd.ExecuteReader()
    try {
        $names = @(for ($i = 0; $i -lt $rdr.FieldCount; $i++) { $rdr.GetName($i) })
        while ($rdr.Read()) {
            $o = [ordered]@{}
            for ($i = 0; $i -lt $names.Count; $i++) { $v = $rdr.GetValue($i); if ($v -is [System.DBNull]) { $v = $null }; $o[$names[$i]] = $v }
            [pscustomobject]$o
        }
    } finally { $rdr.Close() }
}

function ConvertTo-SILedgerJsonArray {
    param([AllowNull()][AllowEmptyCollection()][object[]]$Items)
    if ($null -eq $Items -or @($Items).Count -eq 0) { return '[]' }
    $j = ConvertTo-Json -InputObject @($Items) -Compress -Depth 3
    if ($j.TrimStart().StartsWith('[')) { $j } else { '[' + $j + ']' }
}

function Get-SIObjectLedgerSubset {
    <#
        #477 / #501: the part of the ledger ONE batch of CIs needs, not the whole map -- the rows of the batch's identifiers
        and every row of the ids those point at (Resolve-SIObjectIdentity reports an id's anchors that did not appear).
        -Keys: @{ Type; Value } (canonical type). Same hashtable shape as Get-SIObjectLedger.
        -Invoke { param($Sql, $Params, $Mode) } is the seam (tests); default = the connection.
    #>
    param([Parameter()]$Connection, [AllowEmptyCollection()][object[]]$Keys = @(), [scriptblock]$Invoke)
    $ledger = @{}
    if (@($Keys).Count -eq 0) { return $ledger }
    # asked for as the table holds it: a value longer than the column under its short form (ConvertTo-SILedgerStoredValue).
    # The rows come back under that short form too, and Resolve-SIObjectIdentity finds them (Get-SILedgerEntryKey).
    $items = @(foreach ($k in $Keys) { [ordered]@{ t = [string]$k.Type; v = (ConvertTo-SILedgerStoredValue -Value ([string]$k.Value).ToLowerInvariant()) } })
    $p = @{ j = (ConvertTo-SILedgerJsonArray $items) }
    if ($Invoke) { $rows = @(& $Invoke (Get-SIObjectLedgerSubsetSql) $p 'rows') }
    else { $rows = @(Invoke-SIObjectLedgerSql -Connection $Connection -Sql (Get-SIObjectLedgerSubsetSql) -Params $p) }
    foreach ($r in $rows) {
        if ($null -eq $r) { continue }
        $k = '{0}|{1}' -f ([string]$r.IdentifierType).ToLowerInvariant(), ([string]$r.IdentifierValue).ToLowerInvariant()
        $ledger[$k] = @{ CorrelationId = [string]$r.SI_CorrelationId; FirstSeen = [datetime]$r.FirstSeen }
    }
    $ledger
}

function Get-SIObjectLedgerSetSql {
    <#
        #501: one batch's ledger changes in ONE statement and ONE transaction (Save-SIObjectLedger sends one MERGE per
        identifier -- a first run of a 100,000-record tenant is hundreds of thousands of round trips). The same rule:
        anchors upserted by (type, value), a supersession written once per old id. @a = anchors, @s = supersessions.
    #>
    @'
SET NOCOUNT ON;
SET XACT_ABORT ON;
DECLARE @now DATETIME2(3) = ISNULL(TRY_CONVERT(DATETIME2(3), @nowText, 127), SYSUTCDATETIME());
DECLARE @x TABLE (IdentifierType NVARCHAR(64), IdentifierValue NVARCHAR(450), SI_CorrelationId NVARCHAR(64), PRIMARY KEY (IdentifierType, IdentifierValue));
INSERT @x SELECT ty, va, MAX(cid) FROM OPENJSON(@a) WITH (ty NVARCHAR(64), va NVARCHAR(450), cid NVARCHAR(64))
WHERE ty IS NOT NULL AND va IS NOT NULL AND cid IS NOT NULL GROUP BY ty, va;
BEGIN TRANSACTION;
MERGE si.ObjectIdentity AS t USING @x AS s
   ON t.IdentifierType = s.IdentifierType AND t.IdentifierValue = s.IdentifierValue
WHEN MATCHED THEN UPDATE SET SI_CorrelationId = s.SI_CorrelationId, LastSeen = @now
WHEN NOT MATCHED THEN INSERT (IdentifierType, IdentifierValue, SI_CorrelationId, FirstSeen, LastSeen)
     VALUES (s.IdentifierType, s.IdentifierValue, s.SI_CorrelationId, @now, @now);
DECLARE @anchors INT = @@ROWCOUNT;
INSERT INTO si.ObjectIdentitySuperseded (OldId, NewId, SupersededAt, Reason)
SELECT s.o, MAX(s.n), @now, N'merge: anchors resolved to two ids' FROM OPENJSON(@s) WITH (o NVARCHAR(64), n NVARCHAR(64)) s
WHERE s.o IS NOT NULL AND NOT EXISTS (SELECT 1 FROM si.ObjectIdentitySuperseded x WHERE x.OldId = s.o) GROUP BY s.o;
DECLARE @sup INT = @@ROWCOUNT;
COMMIT TRANSACTION;
SELECT @anchors AS AnchorsWritten, @sup AS SupersededWritten;
'@
}

function Save-SIObjectLedgerSet {
    <# Persist one batch's decisions set-based (Get-SIObjectLedgerSetSql). -Invoke is the seam (tests). #>
    param([Parameter()]$Connection, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Decisions, [AllowEmptyCollection()][object[]]$Superseded = @(),
          [datetime]$Now = [datetime]::UtcNow, [scriptblock]$Invoke)
    $a = New-Object System.Collections.Generic.List[object]
    foreach ($d in @($Decisions)) {
        if ($null -eq $d -or [string]::IsNullOrWhiteSpace([string]$d.CorrelationId)) { continue }
        # a value longer than the column goes in as its short form (ConvertTo-SILedgerStoredValue) -- the statement would
        # otherwise drop it without a word (over 450 characters) or fail the whole batch (257 to 450)
        foreach ($n in @($d.NewIdentifiers)) { if ($n) { $a.Add([ordered]@{ ty = [string]$n.Type; va = (ConvertTo-SILedgerStoredValue -Value ([string]$n.Value)); cid = [string]$n.CorrelationId }) } }
    }
    # refused here, before the statement runs, when a row cannot be held at all
    Assert-SILedgerRowsFit -Rows @(foreach ($x in $a) { [pscustomobject]@{ Type = $x.ty; Value = $x.va; CorrelationId = $x.cid } })
    $s = @(foreach ($x in @($Superseded)) { if ($x) { [ordered]@{ o = [string]$x.OldId; n = [string]$x.NewId } } })
    if ($a.Count -eq 0 -and $s.Count -eq 0) { return [pscustomobject]@{ AnchorsWritten = 0; SupersededWritten = 0 } }
    $p = @{ a = (ConvertTo-SILedgerJsonArray $a.ToArray()); s = (ConvertTo-SILedgerJsonArray $s); nowText = $Now.ToUniversalTime().ToString('o') }
    if ($Invoke) { $rows = @(& $Invoke (Get-SIObjectLedgerSetSql) $p 'rows') }
    else { $rows = @(Invoke-SIObjectLedgerSql -Connection $Connection -Sql (Get-SIObjectLedgerSetSql) -Params $p) }
    if ($rows.Count -gt 0 -and $rows[0]) { return [pscustomobject]@{ AnchorsWritten = [int]$rows[0].AnchorsWritten; SupersededWritten = [int]$rows[0].SupersededWritten } }
    [pscustomobject]@{ AnchorsWritten = 0; SupersededWritten = 0 }
}
