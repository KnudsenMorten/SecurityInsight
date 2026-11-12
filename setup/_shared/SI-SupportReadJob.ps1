#Requires -Version 5.1
<#
    #1060 (owner 2026-11-02) -- Invardia support READS an install's data (SQL, and Key Vault METADATA) FROM INSIDE the
    install's own network: a one-time Container Apps job in the install's own environment, the same way as
    setup\_shared\SI-SupportSqlJob.ps1 (#681, PIM's Invoke-PimSupportSqlAccessJob.ps1).

      * NOTHING IS OPENED -- owner #681 "when we say it is private, it stays that way" and owner 2026-11-02 "in #1060, we
        will never open the fw": no firewall rule, no public network access, no IP or virtual-network exception, no change
        to any network setting of the database server, the Key Vault, storage or the registry -- on a private AND on a
        public install. ENFORCED, not only absent: every ARM call of a run goes through New-SISupportReadArmGuard, an
        ALLOW-LIST that lets through only the one-time job's own PUT / DELETE / start and a read-only Log Analytics query;
        any other write is refused before it is sent. A static scan (tests\pester\SIv3-SupportReadJob.Tests.ps1) fails when
        these files name a network setting at all.
      * WHAT IS READ: one entry of a NAMED, read-only diagnostic query set shipped here (Get-SISupportReadQueries). There is
        no free-text SQL: the job is told a query NAME and typed parameters only; it looks the statement up in the copy of
        the set it carries, checks it again (Test-SISupportReadSql: one SELECT, no writing or executing keyword) and binds
        the parameters (SqlParameter, never text).
      * WHICH IDENTITY: the Support app's standing read-only database user (#1021, S17) is not built yet, so SQL is read as
        the in-network SQL identity id-si-sql (the only identity a private database lets in from inside) -- every
        statement inside a transaction that is ALWAYS rolled back, READ UNCOMMITTED (it never holds a lock the engine
        waits on), behind the SELECT-only guard in the Support session AND inside the job. When #1021 ships, the job takes
        that user instead and nothing else here changes. Key Vault is read as the engine identity (it never carries
        id-si-sql), through the LIST endpoint only: names, enabled, expiry, created, updated, content type. It NEVER asks
        for a secret value (Test-SISupportReadVaultUri refuses /secrets/<name>).
      * THE RESULT comes back through the job's console log (the install's own workspace): one line per row, prefixed with
        a per-run nonce, size-capped (rows and bytes; each cell cut) and SCRUBBED inside the job -- the workspace never
        holds a secret -- and scrubbed again in the Support session before it is printed.
      * THE RUN: plan -> create the job (tagged as a one-time job) -> start it once -> wait (bounded) -> ALWAYS (finally)
        remove the job and read back that it is gone -> read the result lines. Every ARM / Log Analytics request is sent
        through the Invardia Support session's recorder (the customer's audit log), with the query named in the reason.

    Seams (the caller hands them in; tests pass fakes):
      -Arm   { param([string]$Method, [string]$Path, $Body) }   ARM; $null = not found on a GET; throws otherwise
      -Graph { param([string]$Method, [string]$Uri, $Body) }    Microsoft Graph (the member-side check of id-si-sql)
      -Logs  { param([string]$WorkspaceId, [string]$Execution, [string]$Nonce) }  the execution's console lines (strings)
    Needs SI-PrivateNetwork.ps1 and SI-SupportAppDatabase.ps1 loaded first. PS 5.1 safe; no module, no az, no native exe.
#>

$script:SISrjAppApi = '2025-07-01'
$script:SISrjSqlApi = '2021-11-01'
$script:SISrjMiApi  = '2023-01-31'

function Get-SISupportReadJobTag { [ordered]@{ Name = 'si-one-time-job'; Value = 'support-read' } }

function Get-SISupportReadJobName { 'caj-si-supportread' }

function Get-SISupportReadLimits {
    <# PURE. The size caps: rows and bytes of one result (default / most), and the longest cell. #>
    [ordered]@{ DefaultRows = 50; MaxRows = 500; DefaultBytes = 65536; MinBytes = 4096; MaxBytes = 262144; MaxCell = 512 }
}

function Get-SISupportReadQueries {
    <#
        PURE. THE NAMED, READ-ONLY DIAGNOSTIC QUERY SET -- the only SQL a support read ever runs. Each entry: Name,
        Scope ('pro' = the Pro database; 'each' = every product database on the server), What (one line), Sql (ONE fixed
        SELECT), Params (typed: int with Min/Max/Default, or string with a Pattern; bound as SqlParameter, never text).
        Adding an entry is a code change, reviewed and tested like any other (Test-SISupportReadSql must pass it).
    #>
    $top = { param([int]$Default, [int]$Max) [ordered]@{ Type = 'int'; Min = 1; Max = $Max; Default = $Default } }
    @(
        [ordered]@{ Name = 'run-state'; Scope = 'pro'; What = 'the latest pipeline runs: state, trigger, start / end, heartbeat, why it stopped'
                    Params = [ordered]@{ Top = (& $top 10 50) }
                    Sql = 'SELECT TOP (@Top) FlowRunId, FlowId, Day, Trg, FromStep, State, StartedUtc, EndedUtc, HeartbeatUtc, StopReason, Note FROM cfg.FlowRun ORDER BY StartedUtc DESC' }
        [ordered]@{ Name = 'run-steps'; Scope = 'pro'; What = 'the steps of one run (default: the newest run): job, state, execution, times, error'
                    Params = [ordered]@{ RunId = [ordered]@{ Type = 'string'; Pattern = '^[A-Za-z0-9._:-]{1,64}$'; Default = $null } }
                    Sql = 'SELECT s.FlowRunId, s.StepOrder, s.GroupNo, s.Job, s.State, s.Execution, s.StartedUtc, s.EndedUtc, s.ErrorClass, s.Error FROM cfg.FlowStepRun AS s WHERE s.FlowRunId = COALESCE(@RunId, (SELECT TOP (1) r.FlowRunId FROM cfg.FlowRun AS r ORDER BY r.StartedUtc DESC)) ORDER BY s.StepOrder' }
        [ordered]@{ Name = 'dataout-batches'; Scope = 'pro'; What = 'the latest data-out batches: output, connector, state, planned / sent / failed rows, reason'
                    Params = [ordered]@{ Top = (& $top 20 200) }
                    Sql = 'SELECT TOP (@Top) BatchId, OutputId, Connector, RunId, State, Mode, TargetTable, StartedAt, FinishedAt, PlannedRows, SentRows, FailedRows, NewRows, UpdateRows, CloseRows, ReopenRows, HeldRows, OutOfScopeRows, Reason FROM cfg.DataOutBatch ORDER BY StartedAt DESC' }
        [ordered]@{ Name = 'connector-runs'; Scope = 'pro'; What = 'the latest connector runs: connector, mode, outcome, planned and done counts, halt reason, error'
                    Params = [ordered]@{ Top = (& $top 20 200) }
                    Sql = 'SELECT TOP (@Top) ConnectorRunId, ConnectorName, Kind, RunId, StartedAt, EndedAt, Mode, Outcome, PlanOpen, PlanReopen, PlanUpdate, PlanClose, Held, Opened, Reopened, Updated, Closed, Errors, NotSent, HaltReason, Error FROM cfg.ConnectorRun ORDER BY ConnectorRunId DESC' }
        [ordered]@{ Name = 'install-state'; Scope = 'pro'; What = 'the install''s recorded state (cfg.InstallState): name, value, version, when, by whom'
                    Params = [ordered]@{ Top = (& $top 200 500) }
                    Sql = 'SELECT TOP (@Top) Name, Value, [Version], UpdatedAt, UpdatedBy FROM cfg.InstallState ORDER BY Name' }
        [ordered]@{ Name = 'row-counts'; Scope = 'each'; What = 'rows per table in every product database (largest first)'
                    Params = [ordered]@{ Top = (& $top 100 500) }
                    Sql = 'SELECT TOP (@Top) s.name AS SchemaName, t.name AS TableName, SUM(p.rows) AS TableRows FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id JOIN sys.partitions AS p ON p.object_id = t.object_id AND p.index_id IN (0, 1) GROUP BY s.name, t.name ORDER BY SUM(p.rows) DESC, s.name, t.name' }
        [ordered]@{ Name = 'sql-users'; Scope = 'each'; What = 'the database users (Entra, SQL) with their roles and client ids, in every product database'
                    Params = [ordered]@{}
                    Sql = 'SELECT p.name AS UserName, p.type_desc AS UserType, CASE WHEN p.type IN (''E'', ''X'') THEN CONVERT(varchar(36), CONVERT(uniqueidentifier, p.sid)) ELSE N'''' END AS ClientId, ISNULL((SELECT STRING_AGG(CONVERT(nvarchar(max), r.name), N'','') FROM sys.database_role_members AS m JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = p.principal_id), N'''') AS Roles FROM sys.database_principals AS p WHERE p.type IN (''E'', ''X'', ''S'') AND p.principal_id > 4 ORDER BY p.name' }
    )
}

function Test-SISupportReadSql {
    <#
        PURE. THE SELECT-ONLY GUARD (run in the Support session AND inside the job). @{ Ok; Why }. Refused: empty; a
        comment; more than one statement; not starting with SELECT or WITH; any writing, executing or session-changing
        keyword (outside string literals); a system procedure (sp_ / xp_). A refusal names the reason.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Sql)
    $no = { param($w) [pscustomobject]@{ Ok = $false; Why = $w } }
    $t = "$Sql".Trim()
    if (-not $t) { return (& $no 'empty') }
    if ($t.Contains('--') -or $t.Contains('/*')) { return (& $no 'a comment is not allowed') }
    $bare = [regex]::Replace($t, "N?'(?:[^']|'')*'", "''")
    $bare = $bare.TrimEnd().TrimEnd(';')
    if ($bare.Contains(';')) { return (& $no 'more than one statement') }
    if ($bare -notmatch '(?i)^\s*(SELECT|WITH)\b') { return (& $no 'not a SELECT') }
    $m = [regex]::Match($bare, '(?i)\b(INSERT|UPDATE|DELETE|MERGE|EXEC|EXECUTE|DROP|ALTER|CREATE|GRANT|REVOKE|DENY|TRUNCATE|INTO|OPENROWSET|OPENQUERY|OPENDATASOURCE|OPENXML|BULK|DBCC|BACKUP|RESTORE|SHUTDOWN|KILL|RECONFIGURE|WAITFOR|USE|SETUSER|DECLARE|SET|GO|BEGIN|COMMIT|ROLLBACK|SAVE|TRANSACTION|CHECKPOINT|NEXT|WRITETEXT|UPDATETEXT|READTEXT|ENABLE|DISABLE)\b')
    if ($m.Success) { return (& $no ('the keyword {0} is not allowed' -f $m.Value.ToUpperInvariant())) }
    if ($bare -match '(?i)\b(sp|xp)_\w+') { return (& $no 'a system procedure is not allowed') }
    [pscustomobject]@{ Ok = $true; Why = '' }
}

function Get-SISupportReadQuery {
    <# PURE. The named query -Name, or a THROW (free text, an unknown name). Only a name of the set is ever accepted. #>
    param([AllowEmptyString()][string]$Name)
    $n = "$Name".Trim()
    $q = @(Get-SISupportReadQueries | Where-Object { $_.Name -ceq $n })[0]
    if (-not $q) { throw ('Refused: ''{0}'' is not a named support query. The named queries are: {1}. Free-text SQL is never run.' -f $(if ($n.Length -gt 60) { $n.Substring(0, 60) + '...' } else { $n }), ((Get-SISupportReadQueries | ForEach-Object { $_.Name }) -join ', ')) }
    $g = Test-SISupportReadSql -Sql $q.Sql
    if (-not $g.Ok) { throw ('Refused: the named query {0} is not read-only ({1}).' -f $n, $g.Why) }
    $q
}

function Resolve-SISupportReadParams {
    <# PURE. The query's typed parameters from -Given (a hashtable): each checked against its type, range or pattern;
       an unknown name is refused; a missing one takes its default. Returns an ordered hashtable (name -> value). #>
    param([Parameter(Mandatory)]$Query, [System.Collections.IDictionary]$Given = @{})
    $out = [ordered]@{}
    foreach ($k in @($Given.Keys)) { if (-not $Query.Params.Contains([string]$k)) { throw ('Refused: the query {0} takes no parameter {1} (it takes: {2}).' -f $Query.Name, $k, $(if ($Query.Params.Count) { @($Query.Params.Keys) -join ', ' } else { 'none' })) } }
    foreach ($k in @($Query.Params.Keys)) {
        $d = $Query.Params[$k]
        $has = $Given.Contains($k) -and $null -ne $Given[$k] -and "$($Given[$k])" -ne ''
        if (-not $has) { $out[$k] = $d.Default; continue }
        $v = $Given[$k]
        if ($d.Type -eq 'int') {
            $i = 0
            if (-not [int]::TryParse("$v", [ref]$i) -or $i -lt $d.Min -or $i -gt $d.Max) { throw ('Refused: {0} must be a whole number from {1} to {2}.' -f $k, $d.Min, $d.Max) }
            $out[$k] = $i
        } else {
            $s = "$v"
            if ($s -notmatch $d.Pattern) { throw ('Refused: {0} does not have the expected form.' -f $k) }
            $out[$k] = $s
        }
    }
    $out
}

function Protect-SISupportReadText {
    <#
        PURE. SCRUBS a value before it is written or printed: connection-string secrets (Password, Pwd, AccountKey,
        SharedAccessKey, SharedAccessSignature, ClientSecret, ApiKey, Secret, Token, AccessKey = ...), Bearer tokens, JWTs,
        SAS signatures (sig=), Key Vault references and secret URIs, PEM private keys, Entra client-secret shapes and long
        base64 blobs (40+ characters mixing lower case, upper case and digits: keys, never a word, a hash or a GUID). Never throws.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text -or $Text -eq '') { return $Text }
    $t = $Text
    $t = [regex]::Replace($t, '(?is)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)', '[private key removed]')
    $t = [regex]::Replace($t, '(?i)@Microsoft\.KeyVault\([^)]*\)?', '[key vault reference removed]')
    $t = [regex]::Replace($t, '(?i)https://[a-z0-9-]+\.vault(core)?\.azure\.net(:443)?/(secrets|keys|certificates)/[^\s"''<>;,]*', '[key vault reference removed]')
    $t = [regex]::Replace($t, '(?i)\b(Password|Pwd|AccountKey|SharedAccessKey|SharedAccessSignature|Client_?Secret|ApiKey|Api-Key|Secret|Token|AccessKey|AccessToken|RefreshToken)(\s*["'']?\s*[=:]\s*["'']?)[^;"''\s,&}]+', '$1$2***')
    $t = [regex]::Replace($t, '(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer ***')
    $t = [regex]::Replace($t, '\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*', '[token removed]')
    $t = [regex]::Replace($t, '(?i)([?&]sig=)[^&\s"'']+', '$1***')
    $t = [regex]::Replace($t, '\b[A-Za-z0-9_~.-]{3}8Q~[A-Za-z0-9_~.-]{31,}', '[secret removed]')
    # a key-shaped run: 40+ base64 characters with lower case, upper case AND a digit (a word, a hash or a GUID never is)
    $t = [regex]::Replace($t, '[A-Za-z0-9+/]{40,}={0,2}', { param($m) if ($m.Value -cmatch '[a-z]' -and $m.Value -cmatch '[A-Z]' -and $m.Value -match '[0-9]') { '[base64 removed]' } else { $m.Value } })
    $t
}

function ConvertTo-SISupportReadLines {
    <#
        PURE. Rows (ordered hashtables or objects) -> the RESULT lines, SCRUBBED and CAPPED: at most -MaxRows rows and
        -MaxBytes bytes (UTF-8) of row lines, each cell cut to -MaxCell characters. Every line starts with -Prefix.
        Returns @{ Lines[]; Rows; Bytes; Truncated }. -More = the source had more rows than were handed in.
    #>
    param([object[]]$Rows = @(), [Parameter(Mandatory)][string]$Prefix, [string]$Database = '', [int]$MaxRows = 50, [int]$MaxBytes = 65536, [int]$MaxCell = 512, [switch]$More)
    $lines = New-Object System.Collections.Generic.List[string]
    $n = 0; $bytes = 0; $cut = [bool]$More
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        if ($n -ge $MaxRows) { $cut = $true; break }
        $o = [ordered]@{}
        $props = if ($r -is [System.Collections.IDictionary]) { @($r.Keys | ForEach-Object { @{ N = [string]$_; V = $r[$_] } }) } else { @($r.PSObject.Properties | ForEach-Object { @{ N = $_.Name; V = $_.Value } }) }
        foreach ($p in $props) {
            $v = $p.V
            if ($null -eq $v -or $v -is [System.DBNull]) { $o[$p.N] = $null; continue }
            if ($v -is [datetime]) { $v = $v.ToString('yyyy-MM-ddTHH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) }
            elseif ($v -is [bool] -or $v -is [int] -or $v -is [long] -or $v -is [decimal] -or $v -is [double]) { $o[$p.N] = $v; continue }
            $s = Protect-SISupportReadText -Text ([string]$v)
            if ($s.Length -gt $MaxCell) { $s = $s.Substring(0, $MaxCell) + '...[cut]' }
            $o[$p.N] = $s
        }
        $body = [ordered]@{}; if ($Database) { $body['db'] = $Database }; $body['row'] = $o
        $line = '{0} ROW {1}' -f $Prefix, ($body | ConvertTo-Json -Depth 4 -Compress)
        $b = [Text.Encoding]::UTF8.GetByteCount($line)
        if ($bytes + $b -gt $MaxBytes) { $cut = $true; break }
        $lines.Add($line); $n++; $bytes += $b
    }
    [pscustomobject]@{ Lines = $lines.ToArray(); Rows = $n; Bytes = $bytes; Truncated = $cut }
}

function Test-SISupportReadVaultUri {
    <# PURE. Is -Uri the Key Vault secrets LIST of -Vault (names and metadata, never a value)? Only
       https://<vault>.vault.azure.net[:443]/secrets?... -- a /secrets/<name> (which returns the value) is never one. #>
    param([AllowEmptyString()][string]$Uri, [Parameter(Mandatory)][string]$Vault)
    $u = $null; try { $u = [uri]$Uri } catch { return $false }
    if (-not $u -or -not $u.IsAbsoluteUri -or $u.Scheme -ne 'https') { return $false }
    if ($u.Host -ine ('{0}.vault.azure.net' -f $Vault)) { return $false }
    [bool]($u.AbsolutePath -match '^/secrets/?$')
}

function Get-SISupportReadVaultList {
    <#
        Key Vault: secret NAMES and metadata only, through the LIST endpoint, following nextLink. -Get { param($Uri) } ->
        the parsed page. Every URI is checked with Test-SISupportReadVaultUri BEFORE it is asked (a refused one stops the
        listing). Only these fields are kept: name, enabled, expires, notBefore, created, updated, contentType, managed --
        a value (should one ever come back) is dropped. Returns @{ Items[]; More }.
    #>
    param([Parameter(Mandatory)][string]$Vault, [Parameter(Mandatory)][scriptblock]$Get, [int]$MaxItems = 500)
    $items = New-Object System.Collections.Generic.List[object]
    $uri = 'https://{0}.vault.azure.net/secrets?api-version=7.4&maxresults=25' -f $Vault
    $more = $false
    $epoch = [datetime]::new(1970, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $at = { param($s) if ($null -ne $s -and "$s" -ne '') { $epoch.AddSeconds([double]$s).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) } else { $null } }
    for ($i = 0; $uri -and $i -lt 200; $i++) {
        if (-not (Test-SISupportReadVaultUri -Uri $uri -Vault $Vault)) { throw 'Refused: a Key Vault request that is not the secrets LIST -- a secret value is never asked for.' }
        $page = & $Get $uri
        foreach ($s in @($page.value)) {
            if ($null -eq $s) { continue }
            if ($items.Count -ge $MaxItems) { $more = $true; break }
            $a = $s.attributes
            $items.Add([ordered]@{ name = ([string]$s.id -split '/')[-1]; enabled = $(if ($a) { $a.enabled } else { $null }); expires = $(if ($a) { & $at $a.exp } else { $null })
                                   notBefore = $(if ($a) { & $at $a.nbf } else { $null }); created = $(if ($a) { & $at $a.created } else { $null }); updated = $(if ($a) { & $at $a.updated } else { $null })
                                   contentType = [string]$s.contentType; managed = [bool]$s.managed })
        }
        if ($more) { break }
        $uri = [string]$page.nextLink
    }
    [pscustomobject]@{ Items = $items.ToArray(); More = $more }
}

function Get-SISupportReadJobFunctionNames {
    <# PURE. The functions the job carries, word for word, in load order. Nothing else runs inside. #>
    @('Get-SISupportReadLimits', 'Get-SISupportReadQueries', 'Test-SISupportReadSql', 'Get-SISupportReadQuery', 'Resolve-SISupportReadParams',
      'Protect-SISupportReadText', 'ConvertTo-SISupportReadLines', 'Test-SISupportReadVaultUri', 'Get-SISupportReadVaultList')
}

function Get-SISupportReadJobScript {
    <#
        PURE (reads only the functions loaded in this process). The PowerShell the one-time job runs: the functions above
        word for word, a token from the container's managed-identity endpoint for SI_SUPPORTREAD_MI_CLIENT_ID, then ONE
        named query (each database inside a transaction that is always rolled back) or ONE Key Vault listing. Lines:
        "[supportread <nonce>] BEGIN|ROW|NOTE|END {json}". Exit 0 only when every part was read.
    #>
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add('$ErrorActionPreference = ''Stop''')
    foreach ($n in (Get-SISupportReadJobFunctionNames)) {
        $c = Get-Command -Name $n -CommandType Function -ErrorAction SilentlyContinue
        if (-not $c) { throw ('Get-SISupportReadJobScript: the function {0} is not loaded -- load setup\_shared\SI-SupportReadJob.ps1 first.' -f $n) }
        $l.Add(('function {0} {{{1}}}' -f $n, $c.ScriptBlock.ToString()))
    }
    $l.Add(@'
$nonce = [string]$env:SI_SUPPORTREAD_NONCE
if ($nonce -notmatch '^[a-f0-9]{16}$') { $nonce = 'unknown' }
$pre = '[supportread ' + $nonce + ']'
$mode = [string]$env:SI_SUPPORTREAD_MODE; $mi = [string]$env:SI_SUPPORTREAD_MI_CLIENT_ID
$lim = Get-SISupportReadLimits
$maxRows = 0; [void][int]::TryParse([string]$env:SI_SUPPORTREAD_MAXROWS, [ref]$maxRows); if ($maxRows -lt 1 -or $maxRows -gt $lim.MaxRows) { $maxRows = $lim.DefaultRows }
$maxBytes = 0; [void][int]::TryParse([string]$env:SI_SUPPORTREAD_MAXBYTES, [ref]$maxBytes); if ($maxBytes -lt $lim.MinBytes -or $maxBytes -gt $lim.MaxBytes) { $maxBytes = $lim.DefaultBytes }
function Get-SISrjToken([string]$Resource) {
    $u = '{0}?resource={1}&api-version=2019-08-01&client_id={2}' -f $env:IDENTITY_ENDPOINT, [uri]::EscapeDataString($Resource), $mi
    [string](Invoke-RestMethod -Method GET -Uri $u -Headers @{ 'X-IDENTITY-HEADER' = [string]$env:IDENTITY_HEADER }).access_token
}
function Write-SISrj([string]$Kind, $Body) { Write-Output ('{0} {1} {2}' -f $pre, $Kind, ($Body | ConvertTo-Json -Depth 5 -Compress)) }
$ok = $true; $rowsOut = 0; $bytesOut = 0; $cut = $false
try {
    if (-not $mi) { throw 'the job was not told its identity' }
    if ($mode -eq 'sql') {
        $q = Get-SISupportReadQuery -Name ([string]$env:SI_SUPPORTREAD_QUERY)
        $given = @{}; $pj = [string]$env:SI_SUPPORTREAD_PARAMS
        if ($pj) { $po = $pj | ConvertFrom-Json; foreach ($p in $po.PSObject.Properties) { $given[$p.Name] = $p.Value } }
        $pv = Resolve-SISupportReadParams -Query $q -Given $given
        $server = [string]$env:SI_SUPPORTREAD_SERVER
        $dbs = @(([string]$env:SI_SUPPORTREAD_DATABASES) -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if (-not $server -or -not $dbs.Count) { throw 'the job was not told the server or the databases' }
        Write-SISrj 'BEGIN' ([ordered]@{ mode = 'sql'; query = $q.Name; databases = $dbs; maxRows = $maxRows; maxBytes = $maxBytes })
        $token = Get-SISrjToken 'https://database.windows.net/'
        foreach ($db in $dbs) {
            if ($bytesOut -ge $maxBytes -or $rowsOut -ge $maxRows) { $cut = $true; break }
            $c = New-Object System.Data.SqlClient.SqlConnection(('Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connect Timeout=30;Application Name=SecurityInsight support read' -f $server, $db))
            $c.AccessToken = $token
            $tx = $null; $rd = $null
            try {
                $c.Open()
                # READ ONLY BY CONSTRUCTION: one named SELECT (checked again here), inside a transaction that is ALWAYS rolled back
                $tx = $c.BeginTransaction([System.Data.IsolationLevel]::ReadUncommitted)
                $g = Test-SISupportReadSql -Sql $q.Sql
                if (-not $g.Ok) { throw ('refused: ' + $g.Why) }
                $cmd = $c.CreateCommand(); $cmd.Transaction = $tx; $cmd.CommandText = $q.Sql; $cmd.CommandTimeout = 0
                foreach ($k in @($pv.Keys)) {
                    $d = $q.Params[$k]
                    $sp = if ($d.Type -eq 'int') { New-Object System.Data.SqlClient.SqlParameter(('@' + $k), [System.Data.SqlDbType]::Int) } else { New-Object System.Data.SqlClient.SqlParameter(('@' + $k), [System.Data.SqlDbType]::NVarChar, 64) }
                    $sp.Value = $(if ($null -eq $pv[$k]) { [System.DBNull]::Value } else { $pv[$k] })
                    [void]$cmd.Parameters.Add($sp)
                }
                $rd = $cmd.ExecuteReader()
                $left = $maxRows - $rowsOut
                $rows = New-Object System.Collections.Generic.List[object]; $more = $false
                while ($rd.Read()) {
                    if ($rows.Count -ge $left) { $more = $true; break }
                    $o = [ordered]@{}; for ($i = 0; $i -lt $rd.FieldCount; $i++) { $o[$rd.GetName($i)] = $(if ($rd.IsDBNull($i)) { $null } else { $rd.GetValue($i) }) }
                    $rows.Add($o)
                }
                $r = ConvertTo-SISupportReadLines -Rows $rows.ToArray() -Prefix $pre -Database $db -MaxRows $left -MaxBytes ($maxBytes - $bytesOut) -MaxCell $lim.MaxCell -More:$more
                foreach ($x in $r.Lines) { Write-Output $x }
                $rowsOut += $r.Rows; $bytesOut += $r.Bytes; if ($r.Truncated) { $cut = $true }
            } catch {
                $ok = $false
                Write-SISrj 'NOTE' ([ordered]@{ db = $db; error = (Protect-SISupportReadText -Text ([string]$_.Exception.Message)) })
            } finally {
                if ($rd) { try { $rd.Dispose() } catch { } }
                if ($tx) { try { $tx.Rollback() } catch { } }
                $c.Dispose()
            }
        }
    } elseif ($mode -eq 'keyvault') {
        $vault = [string]$env:SI_SUPPORTREAD_VAULT
        if ($vault -notmatch '^[A-Za-z0-9-]{3,24}$') { throw 'the job was not told a Key Vault name' }
        Write-SISrj 'BEGIN' ([ordered]@{ mode = 'keyvault'; vault = $vault; maxRows = $maxRows; maxBytes = $maxBytes })
        $kvToken = Get-SISrjToken 'https://vault.azure.net'
        $get = { param($Uri) Invoke-RestMethod -Method GET -Uri $Uri -Headers @{ Authorization = ('Bearer ' + $kvToken) } }
        $list = Get-SISupportReadVaultList -Vault $vault -Get $get -MaxItems $maxRows
        $r = ConvertTo-SISupportReadLines -Rows $list.Items -Prefix $pre -MaxRows $maxRows -MaxBytes $maxBytes -MaxCell $lim.MaxCell -More:$list.More
        foreach ($x in $r.Lines) { Write-Output $x }
        $rowsOut = $r.Rows; $bytesOut = $r.Bytes; $cut = $r.Truncated
    } else { throw 'the job was not told what to read' }
} catch {
    $ok = $false
    Write-SISrj 'NOTE' ([ordered]@{ error = (Protect-SISupportReadText -Text ([string]$_.Exception.Message)) })
}
Write-SISrj 'END' ([ordered]@{ state = $(if ($ok) { 'ok' } else { 'failed' }); rows = $rowsOut; bytes = $bytesOut; truncated = $cut })
$global:SISrjExitCode = $(if ($ok) { 0 } else { 1 })
exit $global:SISrjExitCode
'@)
    $l -join "`n"
}

function ConvertTo-SISupportReadJobPayload {
    <# PURE. The script as gzip-compressed UTF-8, base64 (the job's script is large; uncompressed and UTF-16 encoded it
       would be over 50,000 characters on one command line). #>
    param([Parameter(Mandatory)][string]$Script)
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
    $b = [Text.Encoding]::UTF8.GetBytes($Script); $gz.Write($b, 0, $b.Length); $gz.Dispose()
    [Convert]::ToBase64String($ms.ToArray())
}

function ConvertFrom-SISupportReadJobPayload {
    <# PURE. The payload back to the script (what the bootstrap does in the container). #>
    param([Parameter(Mandatory)][string]$Payload)
    $ms = New-Object System.IO.MemoryStream(, [Convert]::FromBase64String($Payload))
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
    $sr = New-Object System.IO.StreamReader($gz, [Text.Encoding]::UTF8)
    try { $sr.ReadToEnd() } finally { $sr.Dispose() }
}

function ConvertTo-SISupportReadJobCommand {
    <# PURE. The container's start command: pwsh with a short bootstrap as an encoded command (UTF-16LE, base64) that
       unpacks the compressed script (ConvertTo-SISupportReadJobPayload) and runs it; exit 1 unless the script set its
       own exit code. No file in the image, nothing quoted wrong. #>
    param([Parameter(Mandatory)][string]$Script)
    $boot = ('$ms = New-Object System.IO.MemoryStream(, [Convert]::FromBase64String(''{0}'')); ' +
             '$gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress); ' +
             '$sr = New-Object System.IO.StreamReader($gz, [Text.Encoding]::UTF8); $s = $sr.ReadToEnd(); $sr.Dispose(); ' +
             '$global:SISrjExitCode = 1; & ([scriptblock]::Create($s)); exit $global:SISrjExitCode') -f (ConvertTo-SISupportReadJobPayload -Script $Script)
    @('pwsh', '-NoProfile', '-NonInteractive', '-EncodedCommand', [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($boot)))
}

function Get-SISupportReadJobBody {
    <# PURE. The one-time job: manual, one replica, no retry, the READ identity and the pull identity only, the image
       pulled the way the engine job pulls it, tagged as a one-time job. The job is told a query NAME, never SQL. #>
    param([Parameter(Mandatory)]$Plan, [Parameter(Mandatory)][string]$Nonce, [int]$TimeoutSeconds = 900, [string]$Script = '')
    if (-not $Script) { $Script = Get-SISupportReadJobScript }
    $t = Get-SISupportReadJobTag
    $ua = [ordered]@{}; $ua[$Plan.ReadIdentityId] = [ordered]@{}; if (-not (Test-SIPnSameId $Plan.PullIdentityId $Plan.ReadIdentityId)) { $ua[$Plan.PullIdentityId] = [ordered]@{} }
    $tags = [ordered]@{}; $tags[$t.Name] = $t.Value
    $env = New-Object System.Collections.Generic.List[object]
    $env.Add([ordered]@{ name = 'SI_SUPPORTREAD_MODE'; value = $Plan.Mode })
    $env.Add([ordered]@{ name = 'SI_SUPPORTREAD_NONCE'; value = $Nonce })
    $env.Add([ordered]@{ name = 'SI_SUPPORTREAD_MI_CLIENT_ID'; value = $Plan.ReadIdentityClientId })
    $env.Add([ordered]@{ name = 'SI_SUPPORTREAD_MAXROWS'; value = [string]$Plan.MaxRows })
    $env.Add([ordered]@{ name = 'SI_SUPPORTREAD_MAXBYTES'; value = [string]$Plan.MaxBytes })
    if ($Plan.Mode -eq 'sql') {
        $env.Add([ordered]@{ name = 'SI_SUPPORTREAD_QUERY'; value = $Plan.Query })
        $env.Add([ordered]@{ name = 'SI_SUPPORTREAD_PARAMS'; value = ($Plan.Params | ConvertTo-Json -Compress) })
        $env.Add([ordered]@{ name = 'SI_SUPPORTREAD_SERVER'; value = $Plan.Server })
        $env.Add([ordered]@{ name = 'SI_SUPPORTREAD_DATABASES'; value = (@($Plan.Databases) -join ';') })
    } else {
        $env.Add([ordered]@{ name = 'SI_SUPPORTREAD_VAULT'; value = $Plan.Vault })
    }
    [ordered]@{
        location = $Plan.Location; tags = $tags
        identity = [ordered]@{ type = 'UserAssigned'; userAssignedIdentities = $ua }
        properties = [ordered]@{
            environmentId = $Plan.EnvironmentId
            configuration = [ordered]@{
                triggerType = 'Manual'; replicaTimeout = $TimeoutSeconds; replicaRetryLimit = 0
                manualTriggerConfig = [ordered]@{ parallelism = 1; replicaCompletionCount = 1 }
                registries = @([ordered]@{ server = $Plan.RegistryServer; identity = $Plan.PullIdentityId })
            }
            template = [ordered]@{ containers = @([ordered]@{
                name = 'supportread'; image = $Plan.Image; command = @(ConvertTo-SISupportReadJobCommand -Script $Script)
                resources = [ordered]@{ cpu = 0.5; memory = '1Gi' }
                env = $env.ToArray() }) }
        }
    }
}

function Test-SISupportReadJobOneTime {
    <# PURE. Is -Job (as ARM returns it) one this script made (its tag)? Only such a job is ever removed. #>
    param($Job)
    $t = Get-SISupportReadJobTag
    [string](Get-SIPnProp $Job @('tags', $t.Name)) -eq $t.Value
}

function New-SISupportReadArmGuard {
    <#
        THE NETWORK RULE, ENFORCED (owner 2026-11-02: "we will never open the fw"). Wraps -Arm in an ALLOW-LIST: a GET goes
        through; of everything else ONLY the one-time job's own PUT and DELETE (-JobId), its start (POST <job>/start) and a
        read-only Log Analytics query (POST https://api.loganalytics.io/v1/workspaces/<id>/query). Any other write -- to the
        database server, the Key Vault, storage, the registry, a network or anything else -- THROWS before it is sent.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$JobId)
    $jid = $JobId.TrimEnd('/')
    {
        param([string]$Method, [string]$Path, $Body)
        $m = "$Method".ToUpperInvariant()
        if ($m -ne 'GET') {
            $p = ("$Path" -split '\?')[0].TrimEnd('/')
            $allowed = (($m -eq 'PUT' -or $m -eq 'DELETE') -and [string]::Equals($p, $jid, [StringComparison]::OrdinalIgnoreCase)) -or
                       ($m -eq 'POST' -and [string]::Equals($p, ($jid + '/start'), [StringComparison]::OrdinalIgnoreCase)) -or
                       ($m -eq 'POST' -and $p -match '(?i)^https://api\.loganalytics\.io/v1/workspaces/[0-9a-f-]{36}/query$')
            if (-not $allowed) { throw ('Refused: {0} {1} -- a support read changes nothing but its own one-time job; no network setting, firewall rule or public access is ever changed (owner rule). Nothing was sent.' -f $m, $p) }
        }
        & $Arm $Method $Path $Body
    }.GetNewClosure()
}

function Get-SISupportReadLogQuery {
    <# PURE. The KQL for one execution's result lines (the nonce in them); $null for a name that is not an execution. #>
    param([Parameter(Mandatory)][string]$Execution, [Parameter(Mandatory)][string]$Nonce)
    if ($Execution -notmatch '^[a-z0-9][a-z0-9\-]{0,126}$' -or $Nonce -notmatch '^[a-f0-9]{16}$') { return $null }
    ("union isfuzzy=true (ContainerAppConsoleLogs | where TimeGenerated > ago(1d) | where tostring(column_ifexists('ContainerGroupName', '')) startswith '{0}' | project TimeGenerated, L = tostring(column_ifexists('Log', ''))), " +
     "(ContainerAppConsoleLogs_CL | where TimeGenerated > ago(1d) | where tostring(column_ifexists('ContainerGroupName_s', '')) startswith '{0}' | project TimeGenerated, L = tostring(column_ifexists('Log_s', ''))) " +
     "| where L has '{1}' | order by TimeGenerated asc | project L") -f $Execution, $Nonce
}

function Read-SISupportReadLogLines {
    <# The execution's result lines over the (guarded) ARM seam: a read-only Log Analytics query (recorded as a read). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [string]$WorkspaceId, [string]$Execution, [string]$Nonce)
    $q = Get-SISupportReadLogQuery -Execution $Execution -Nonce $Nonce
    if (-not $q -or $WorkspaceId -notmatch '^[0-9a-fA-F-]{36}$') { return @() }
    $r = & $Arm 'POST' ('https://api.loganalytics.io/v1/workspaces/{0}/query' -f $WorkspaceId) ([ordered]@{ query = $q; timespan = 'P1D' })
    $t = @(Get-SIPnProp $r @('tables'))[0]
    @(@(Get-SIPnProp $t @('rows')) | Where-Object { $null -ne $_ } | ForEach-Object { [string]@($_)[0] })
}

function ConvertFrom-SISupportReadLines {
    <# PURE. The job's console lines -> @{ Begin; Rows[]; Notes[]; End } for -Nonce (other lines ignored); every value
       scrubbed AGAIN and capped AGAIN (-MaxRows / -MaxBytes) here, whatever the job wrote. #>
    param([string[]]$Lines = @(), [Parameter(Mandatory)][string]$Nonce, [int]$MaxRows = 50, [int]$MaxBytes = 65536)
    $pre = '[supportread {0}] ' -f $Nonce
    $out = [ordered]@{ Begin = $null; Rows = New-Object System.Collections.Generic.List[string]; Notes = New-Object System.Collections.Generic.List[string]; End = $null; Truncated = $false; Bytes = 0 }
    foreach ($l in @($Lines)) {
        $s = [string]$l; $i = $s.IndexOf($pre); if ($i -lt 0) { continue }
        $rest = $s.Substring($i + $pre.Length)
        $sp = $rest.IndexOf(' '); if ($sp -lt 0) { continue }
        $kind = $rest.Substring(0, $sp); $json = Protect-SISupportReadText -Text $rest.Substring($sp + 1)
        switch ($kind) {
            'BEGIN' { $out.Begin = $json }
            'END'   { try { $out.End = $json | ConvertFrom-Json } catch { $out.End = $null } }
            'NOTE'  { $out.Notes.Add($json) }
            'ROW'   {
                $b = [Text.Encoding]::UTF8.GetByteCount($json)
                if ($out.Rows.Count -ge $MaxRows -or $out.Bytes + $b -gt $MaxBytes) { $out.Truncated = $true }
                else { $out.Rows.Add($json); $out.Bytes += $b }
            }
        }
    }
    [pscustomobject]$out
}

function Get-SISupportReadJobPlan {
    <#
        READ ONLY. What the one-time read job needs, read from the install: the environment, the image and the pull
        identity of an engine job, the workspace its console lines go to, and per mode: (sql) the database server, the
        databases of the query's scope and the in-network SQL identity id-si-sql, a member of the server's admin group;
        (keyvault) the install's Key Vault and the engine identity. Never changes anything.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Graph, [Parameter(Mandatory)]$Shape, [Parameter(Mandatory)][ValidateSet('sql', 'keyvault')][string]$Mode,
          $Query, [System.Collections.IDictionary]$Params = @{}, [string]$VaultName = '', [string]$JobName = '', [int]$MaxRows = 50, [int]$MaxBytes = 65536)
    if (-not $JobName) { $JobName = Get-SISupportReadJobName }
    $n = Get-SIPrivateNetworkNames
    $rgId = '/subscriptions/{0}/resourceGroups/{1}' -f $Shape.SubscriptionId, $Shape.ResourceGroup
    $p = [ordered]@{ Ok = $false; Problems = New-Object System.Collections.Generic.List[string]; Lines = New-Object System.Collections.Generic.List[string]
                     Mode = $Mode; Query = $(if ($Query) { $Query.Name } else { '' }); Params = $Params; JobName = $JobName
                     JobId = ('{0}/providers/Microsoft.App/jobs/{1}' -f $rgId, $JobName); Leftover = $false
                     EnvironmentId = ''; Location = ''; Image = ''; RegistryServer = ''; PullIdentityId = ''; WorkspaceId = ''
                     ReadIdentityId = ''; ReadIdentityClientId = ''; ReadIdentityName = ''; Server = [string]$Shape.SqlFqdn; Databases = @(); Vault = ''
                     MaxRows = $MaxRows; MaxBytes = $MaxBytes }
    # 1. the environment, the image and the pull identity: those of an engine job
    $eng = @(@($Shape.Jobs) | Where-Object { [string](Get-SIPnProp $_ @('name')) -notmatch '(?i)updater|tagging|supportsql|supportread' -and -not (Test-SIPnSupportOneTime $_) })
    $tpl = $eng | Select-Object -First 1
    if (-not $tpl) { $p.Problems.Add('no engine job was found to take the environment, the image and the pull identity from') }
    else {
        $p.EnvironmentId = [string](Get-SIPnProp $tpl @('properties', 'environmentId')); $p.Location = [string](Get-SIPnProp $tpl @('location'))
        $p.Image = [string](Get-SIPnProp @(Get-SIPnProp $tpl @('properties', 'template', 'containers'))[0] @('image'))
        $reg = @(Get-SIPnProp $tpl @('properties', 'configuration', 'registries') | Where-Object { $_ })[0]
        $p.RegistryServer = [string](Get-SIPnProp $reg @('server'))
        $pull = [string](Get-SIPnProp $reg @('identity'))
        if ([string](Get-SIPnProp $reg @('passwordSecretRef'))) { $p.Problems.Add(('{0} pulls its image with a password -- the one-time job copies no secret' -f [string]$tpl.name)) }
        elseif ($pull -notmatch '(?i)/providers/Microsoft\.ManagedIdentity/userAssignedIdentities/') { $p.Problems.Add(('{0} pulls its image with {1} -- the one-time job carries a user-assigned identity only' -f [string]$tpl.name, $(if ($pull) { $pull } else { 'no identity' }))) }
        else { $p.PullIdentityId = $pull }
        if (-not $p.Image) { $p.Problems.Add(('{0} names no image' -f [string]$tpl.name)) }
        $env = if ($p.EnvironmentId) { & $Arm 'GET' ('{0}?api-version={1}' -f $p.EnvironmentId, $script:SISrjAppApi) $null } else { $null }
        $p.WorkspaceId = [string](Get-SIPnProp $env @('properties', 'appLogsConfiguration', 'logAnalyticsConfiguration', 'customerId'))
        if (-not $p.WorkspaceId) { $p.Problems.Add('the environment sends no console lines to a Log Analytics workspace -- the result could not be read back') }
        $p.Lines.Add(('job: {0} in {1} ({2}), image {3}' -f $JobName, ($p.EnvironmentId -split '/')[-1], $(if (Test-SIEnvironmentPrivate -Environment $env) { 'private' } else { 'not private: the read runs inside all the same' }), $p.Image))
    }
    # 2. what is read, and as whom
    if ($Mode -eq 'sql') {
        if (-not $Query) { $p.Problems.Add('no named query was given') }
        if (-not $Shape.SqlServerId) { $p.Problems.Add('the install''s database server was not found (give -SqlServerName)') }
        else {
            $dbs = @(Get-SIPnArmList -Arm $Arm -Path ('{0}/databases?api-version={1}' -f $Shape.SqlServerId, $script:SISrjSqlApi) | ForEach-Object { [string](Get-SIPnProp $_ @('name')) } | Where-Object { $_ -and $_ -ne 'master' } | Sort-Object -Unique)
            if ($Query -and $Query.Scope -eq 'pro') {
                $pro = @(@($Shape.Jobs) | ForEach-Object { @(Get-SIPnProp $_ @('properties', 'template', 'containers')) } | ForEach-Object { @(Get-SIPnProp $_ @('env')) } | Where-Object { $_ -and [string](Get-SIPnProp $_ @('name')) -eq 'SI_ProSqlDatabase' } | ForEach-Object { [string](Get-SIPnProp $_ @('value')) } | Where-Object { $_ })[0]
                if (-not $pro) { $pro = [string]$Shape.Database }
                if ($pro -and $dbs -contains $pro) { $dbs = @($pro) } elseif ($pro) { $p.Problems.Add(('the Pro database {0} is not on the server' -f $pro)); $dbs = @() } else { $p.Problems.Add('the install names no Pro database'); $dbs = @() }
            }
            $p.Databases = $dbs
            if ($dbs.Count) { $p.Lines.Add(('databases: {0}' -f ($dbs -join ', '))) } elseif (-not $p.Problems.Count) { $p.Problems.Add('no database was found on the server') }
        }
        $mi = & $Arm 'GET' ('{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/{1}?api-version={2}' -f $rgId, $n.SqlIdentity, $script:SISrjMiApi) $null
        if (-not $mi) { $p.Problems.Add(('the install has no in-network SQL identity {0} -- it is made by setup\Set-SIPrivateNetworking.ps1 -Steps sql-identity; this script never makes one' -f $n.SqlIdentity)) }
        else {
            $p.ReadIdentityId = [string](Get-SIPnProp $mi @('id')); $p.ReadIdentityClientId = [string](Get-SIPnProp $mi @('properties', 'clientId')); $p.ReadIdentityName = $n.SqlIdentity
            $gid = if ($Shape.EntraAdmin -and [string]$Shape.EntraAdmin.Type -eq 'Group') { [string]$Shape.EntraAdmin.Sid } else { '' }
            $mpid = [string](Get-SIPnProp $mi @('properties', 'principalId'))
            if (-not $gid) { $p.Problems.Add('the database server''s administrator is not a group -- the in-network identity has no way in') }
            elseif ($Graph -and $mpid) {
                try {
                    if (Test-SISupportAppGroupMember -Graph $Graph -GroupId $gid -ServicePrincipalId $mpid) { $p.Lines.Add(('identity: {0} (client {1}), read only: one named SELECT in a transaction that is always rolled back' -f $n.SqlIdentity, $p.ReadIdentityClientId)) }
                    else { $p.Problems.Add(('{0} is not a member of the database server''s admin group -- this script never gives a membership' -f $n.SqlIdentity)) }
                } catch { $p.Problems.Add(('whether {0} is a member of the admin group could not be read: {1}' -f $n.SqlIdentity, $_.Exception.Message)) }
            }
        }
    } else {
        $p.Vault = $(if ($VaultName) { $VaultName } else { [string]$Shape.KeyVaultName })
        if ($p.Vault -notmatch '^[A-Za-z0-9-]{3,24}$') { $p.Problems.Add('the install''s Key Vault is not known (give -VaultName)'); $p.Vault = '' }
        else { $p.Lines.Add(('key vault: {0} -- names and metadata only, never a value' -f $p.Vault)) }
        $e = $Shape.EngineIdentity
        if (-not $e -or -not $e.Id -or -not $e.ClientId) { $p.Problems.Add('the engine identity (SI_UAMI_ClientId on the engine jobs) was not found -- the Key Vault is read as it') }
        else { $p.ReadIdentityId = [string]$e.Id; $p.ReadIdentityClientId = [string]$e.ClientId; $p.ReadIdentityName = [string]$e.Name; $p.Lines.Add(('identity: {0} (client {1}), the secrets LIST only' -f $e.Name, $e.ClientId)) }
    }
    # 3. a job of the one-time name: a leftover of this script is removed first; any other job of that name stops the run
    $have = & $Arm 'GET' ('{0}?api-version={1}' -f $p.JobId, $script:SISrjAppApi) $null
    if ($have) {
        if (Test-SISupportReadJobOneTime $have) { $p.Leftover = $true; $p.Lines.Add(('a leftover {0} of an earlier run is removed first' -f $JobName)) }
        else { $p.Problems.Add(('a job named {0} is there that this script did not make -- it is not touched; give -JobName' -f $JobName)) }
    }
    $p.Ok = -not $p.Problems.Count
    $p
}

function Test-SIPnSupportOneTime {
    <# PURE. A one-time support job (the grant's or the read's), never the template of another. #>
    param($Job)
    [bool]([string](Get-SIPnProp $Job @('tags', 'si-one-time-job')))
}

function Invoke-SISupportReadJob {
    <#
        The one-time read job: -Plan (Ok) from Get-SISupportReadJobPlan. Creates it, starts it once, waits (at most
        -TimeoutSeconds) -- and in a FINALLY removes the job and reads back that it is gone (also when a step failed) --
        then reads the result lines from the workspace (at most -LogWaitSeconds; the lines lag). -Arm MUST be the guarded
        seam (New-SISupportReadArmGuard). Returns @{ Ok; Verdict; Lines[]; Execution; Removed; Status; Result }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [scriptblock]$Logs, [Parameter(Mandatory)]$Plan,
          [int]$TimeoutSeconds = 900, [int]$PollSeconds = 10, [int]$LogWaitSeconds = 1200,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [string]$Nonce = '')
    if (-not $Nonce) { $Nonce = ([guid]::NewGuid().ToString('N')).Substring(0, 16) }
    $lines = New-Object System.Collections.Generic.List[string]
    $path = '{0}?api-version={1}' -f $Plan.JobId, $script:SISrjAppApi
    $exec = ''; $status = ''; $removed = $false; $made = $false
    try {
        if ($Plan.Leftover) {
            $null = & $Arm 'DELETE' $path $null
            $g = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 30 -PauseSeconds 10 -Test { param($o) $null -eq $o }
            if ($g) { throw ('the leftover {0} is still there after its removal' -f $Plan.JobName) }
            $lines.Add(('leftover {0} removed (read back)' -f $Plan.JobName))
        }
        $body = Get-SISupportReadJobBody -Plan $Plan -Nonce $Nonce -TimeoutSeconds $TimeoutSeconds
        $made = $true
        $null = & $Arm 'PUT' $path $body
        $back = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 30 -PauseSeconds 10 -Test { param($o) [string](Get-SIPnProp $o @('properties', 'provisioningState')) -in 'Succeeded', 'Failed', 'Canceled' }
        if (-not (Test-SIPnSucceeded $back)) { throw ('the one-time job {0} was not made (Azure shows: {1})' -f $Plan.JobName, [string](Get-SIPnProp $back @('properties', 'provisioningState'))) }
        $lines.Add(('one-time job {0} made in {1} (read back)' -f $Plan.JobName, ($Plan.EnvironmentId -split '/')[-1]))
        $start = & $Arm 'POST' ('{0}/start?api-version={1}' -f $Plan.JobId, $script:SISrjAppApi) ([ordered]@{})
        $exec = [string](Get-SIPnProp $start @('name')); if (-not $exec) { $exec = (([string](Get-SIPnProp $start @('id'))) -split '/')[-1] }
        if (-not $exec) { throw 'the job was started but Azure named no execution' }
        $lines.Add(('started: execution {0}' -f $exec))
        $deadline = [datetime]::UtcNow.AddSeconds($TimeoutSeconds + 120)
        while ($true) {
            $e = & $Arm 'GET' ('{0}/executions/{1}?api-version={2}' -f $Plan.JobId, $exec, $script:SISrjAppApi) $null
            $status = [string](Get-SIPnProp $e @('properties', 'status'))
            if ($status -in 'Succeeded', 'Failed', 'Stopped', 'Degraded') { break }
            if ([datetime]::UtcNow -ge $deadline) { $status = 'TimedOut'; break }
            & $Sleep $PollSeconds
        }
        $lines.Add(('execution {0}: {1}' -f $exec, $status))
    } catch { $lines.Add(('FAILED: {0}' -f (Protect-SISupportReadText -Text $_.Exception.Message))) }
    finally {
        if ($made -or $Plan.Leftover) {
            try {
                $null = & $Arm 'DELETE' $path $null
                $g = Read-SIPnBack -Arm $Arm -Path $path -Sleep $Sleep -Tries 30 -PauseSeconds 10 -Test { param($o) $null -eq $o }
                $removed = ($null -eq $g)
            } catch { $removed = $false; $lines.Add(('the job could not be removed: {0}' -f $_.Exception.Message)) }
            $lines.Add($(if ($removed) { 'one-time job {0} removed (read back: gone)' -f $Plan.JobName } else { 'the one-time job {0} is STILL THERE -- delete it in the resource group' -f $Plan.JobName }))
        } else { $removed = $true }
    }
    # the result: the job's console lines (they reach the workspace minutes later)
    $res = $null
    if ($exec -and $status -in 'Succeeded', 'Failed') {
        $until = [datetime]::UtcNow.AddSeconds($LogWaitSeconds)
        while ($true) {
            $got = @()
            try { $got = @(if ($Logs) { & $Logs $Plan.WorkspaceId $exec $Nonce } else { Read-SISupportReadLogLines -Arm $Arm -WorkspaceId $Plan.WorkspaceId -Execution $exec -Nonce $Nonce }) } catch { $lines.Add(('the result lines could not be read: {0}' -f $_.Exception.Message)); break }
            $res = ConvertFrom-SISupportReadLines -Lines $got -Nonce $Nonce -MaxRows $Plan.MaxRows -MaxBytes $Plan.MaxBytes
            if ($res.End) { break }
            if ([datetime]::UtcNow -ge $until) { $lines.Add(('the result lines had not all reached the workspace after {0} s -- run it again later' -f $LogWaitSeconds)); break }
            & $Sleep $PollSeconds
        }
    }
    $read = $res -and $res.End -and [string]$res.End.state -eq 'ok'
    $pass = ($status -eq 'Succeeded') -and $removed -and $read
    @{ Ok = $pass; Verdict = $(if ($pass) { 'PASS' } else { 'FAIL' }); Lines = $lines.ToArray(); Execution = $exec; Removed = $removed; Status = $status; Result = $res; Nonce = $Nonce }
}
