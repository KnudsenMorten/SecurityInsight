#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE PRO DATABASE SCHEMA, APPLIED ONE WAY BY EVERY PATH (#352, framework UPDATE-1.6 (j)).

    WHY. Until 2026-10-05 the Pro schema was applied by setup only (the guided install, Initialize-SIDataSql,
    Initialize-SIVulnTargetSql, Import-SIProSettings -CreateSchema, and the internal ring-1 build), so a Pro install updated by
    caj-si-updater got new code without its tables (cfg.PipelineLock / cfg.PipelineQueue, cfg.WebKeyRing, new columns).
    Rule: NEVER RUN NEW CODE ON AN OLD SCHEMA. The updater now applies the release's own schema BEFORE it rolls anything,
    with the same list, order, batching and gate as setup -- this file -- so the two can never drift.

    THE LIST, in the order setup applies it (one database, the Pro database):
        vuln      sql\si-vulnerability-target.sql   one batch   (Initialize-SIVulnTargetSql)
        data      sql\si-data-schema.sql            one batch   (Initialize-SIDataSql)
        cmdbsync  sql\si-cmdbsync-schema.sql        one batch   (Initialize-SIDataSql)
        settings  sql\si-pro-settings.sql           a batch per blank-line-separated block (Import-SIProSettings -CreateSchema):
                                                    a later block reads a column an earlier one added, so they cannot share
                                                    one batch
    NOT HERE: sql\si-identity-schema.sql -- the identity ledger is its own database and its SCHEMA-1 gate needs a recorded
    HUMAN approval per tenant and schema version (Get-SISchemaApplyPlan); an unattended updater cannot give one.
    sql\si-cmdb-handoff-target.sql belongs to the customer's own hand-off database and is applied by its connector.

    THE GATE: every file is checked by Test-SISchemaIsAdditive BEFORE anything is sent; one non-additive file refuses the
    whole set (nothing is applied). Additive + idempotent: re-running is a no-op.

    ONE TRANSACTION PER FILE where possible: with the caller's -RunFile (New-SIProSchemaRunner -- the updater's: one
    connection, one transaction, the LONG schema timeout) EVERY file runs through it, a one-batch file too. Without one
    (setup's per-call invoke) a one-batch file is wrapped in SET XACT_ABORT ON / BEGIN TRAN / COMMIT by this code and a
    multi-batch file runs batch by batch. A failed file is rolled back; the files before it stay applied (additive, so
    the old code keeps working on them).
    WHY EVERY FILE (2026-10-12): the data schema is one batch, so it went through the caller's general -Invoke, whose
    command timeout is the one of a small statement (120 s in the updater). A release that added ~30 indexes to tables
    with rows timed out there on a real database: the update stopped and rolled nothing. Building an index takes the
    time the rows need, so the schema runs under the runner's timeout, never under a small statement's.

    THE RECORD: cfg.InstallState 'SchemaVersion' -- Value = {"hash","files","grants","at"} (hash = SHA-256 over every file's
    SHA-256 and the caller's extra fingerprint, e.g. the grants), [Version] = the release. A run whose fingerprint equals
    the record is a visible, fast no-op.
    Pure except -Invoke / -RunFile, which are seams.
#>

# The gate of THIS copy (a release is judged by its own gate, never by an older one already loaded).
. ([System.IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', '_shared', 'SI-SchemaGate.ps1'))

function Get-SIUpdaterDatabaseAccessSql {
    <#
        PURE. The ONE-TIME statements that let the product updater apply a release's schema and grants on the Pro database
        (#352): the identity's contained user by its client id (reused when the install already made one, whatever its
        name -- found by SID), db_datareader + db_datawriter (its state rows, the template gate), db_ddladmin (the additive
        schema) and db_securityadmin (the web app's / MCP server's grants, the audit role, the DENYs). Run ONCE by the
        server's Entra admin (setup\Grant-SIUpdaterDatabase.ps1, or Install-SIUpdaterJob.ps1 -GrantSql). Idempotent.
    #>
    param([Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$ClientId,
          # #672 (REMOVE-ME with SI_Setup_SignedGrantProcedure): the full model -- NO db_securityadmin; the grants go through
          # the certificate-signed procedure (engine\pro-settings\SI-GrantProcedure.ps1, installed by the same admin run)
          [switch]$NoSecurityAdmin)
    $sid = '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
    $n = $UserName.Replace(']', ']]'); $q = $UserName.Replace("'", "''")
    $sec = if ($NoSecurityAdmin) { '' } else { "SET @s = N'ALTER ROLE db_securityadmin ADD MEMBER ' + QUOTENAME(@n); EXEC (@s);`n" }
    @"
DECLARE @n sysname = (SELECT name FROM sys.database_principals WHERE sid = $sid);
IF @n IS NULL BEGIN CREATE USER [$n] WITH SID = $sid, TYPE = E; SET @n = N'$q'; END
DECLARE @s nvarchar(400);
SET @s = N'ALTER ROLE db_datareader ADD MEMBER ' + QUOTENAME(@n); EXEC (@s);
SET @s = N'ALTER ROLE db_datawriter ADD MEMBER ' + QUOTENAME(@n); EXEC (@s);
SET @s = N'ALTER ROLE db_ddladmin ADD MEMBER ' + QUOTENAME(@n); EXEC (@s);
$sec
SELECT @n AS UserName,
       IS_ROLEMEMBER(N'db_ddladmin', @n) AS DdlAdmin, IS_ROLEMEMBER(N'db_securityadmin', @n) AS SecurityAdmin,
       IS_ROLEMEMBER(N'db_datareader', @n) AS DataReader, IS_ROLEMEMBER(N'db_datawriter', @n) AS DataWriter;
"@
}

function Get-SITaggingDatabaseAccessSql {
    <#
        PURE. Asset tagging (#236) runs under its OWN identity, and like every Pro engine it reads its settings from the Pro
        database at run start -- so that identity needs a contained user there with db_datareader, and INSERT on
        cfg.AuditEvent: the settings layer writes the job's 'settings.change.apply' rows at run start (refused before --
        "The INSERT permission was denied on the object 'AuditEvent'", the audit rows lost). Nothing else is written. The
        grant only when cfg.AuditEvent exists (the guided install runs this again in its settings step, once it does). Without it the 05:50 run fails its settings check
        on every install (fix request 85bd728f, 2026-10-07/08). The user is found by SID (the client id), reused whatever
        its name. Run by the server's Entra admin: the guided install (pro-schema) or setup\Grant-SITaggingDatabase.ps1.
    #>
    param([Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$ClientId)
    $sid = '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
    $n = $UserName.Replace(']', ']]'); $q = $UserName.Replace("'", "''")
    @"
DECLARE @n sysname = (SELECT name FROM sys.database_principals WHERE sid = $sid);
IF @n IS NULL BEGIN CREATE USER [$n] WITH SID = $sid, TYPE = E; SET @n = N'$q'; END
DECLARE @s nvarchar(400);
SET @s = N'ALTER ROLE db_datareader ADD MEMBER ' + QUOTENAME(@n); EXEC (@s);
IF OBJECT_ID(N'cfg.AuditEvent') IS NOT NULL BEGIN SET @s = N'GRANT INSERT ON OBJECT::cfg.AuditEvent TO ' + QUOTENAME(@n); EXEC (@s); END
SELECT @n AS UserName, IS_ROLEMEMBER(N'db_datareader', @n) AS DataReader;
"@
}

function Get-SIProSchemaFileList {
    <# The Pro schema files, in the order setup applies them. Split: 'whole' (one batch) or 'blank' (a batch per blank-line block). #>
    @(
        [pscustomobject]@{ Name = 'vuln';     File = 'sql/si-vulnerability-target.sql'; Split = 'whole' }
        [pscustomobject]@{ Name = 'data';     File = 'sql/si-data-schema.sql';          Split = 'whole' }
        [pscustomobject]@{ Name = 'cmdbsync'; File = 'sql/si-cmdbsync-schema.sql';      Split = 'whole' }
        [pscustomobject]@{ Name = 'settings'; File = 'sql/si-pro-settings.sql';         Split = 'blank' }
    )
}

function Split-SIProSchemaBatches {
    <# PURE. The batches of one file: 'whole' = the file; 'blank' = every blank-line-separated block that is not only comments. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Sql, [ValidateSet('whole', 'blank')][string]$Split = 'whole')
    if ($Split -eq 'whole') {
        if (($Sql -replace '(?m)^\s*--.*$', '').Trim()) { return , @($Sql) }
        return , @()
    }
    , @(($Sql -split '(?m)^\s*$') | Where-Object { ($_ -replace '(?m)^\s*--.*$', '').Trim() })
}

# ---- INDEXES ON LARGE TABLES (2026-10-20, owner: "Build it once + fix") ----------------------------------------------
# A plain CREATE INDEX inside a file's one transaction builds over every row there is. At a large install (sidata.Finding
# 19,2 M rows) that took longer than the updater's 1-hour limit: the job was cut off, the whole file rolled back, and every
# hourly update started again -- the install never left the old release. So an index on a LARGE table that is not there
# yet is NOT built in the file: its statement is replaced by a no-op in the batch, and after the files are applied it is
# built on its own, outside any transaction, ONLINE + RESUMABLE with a MAX_DURATION inside a budget per update. At the end
# of the budget it PAUSES (never rolls back); the next update RESUMES it; one that is running is left alone. A pending
# index never fails the update -- the release's code works without it (an index only makes a read faster).
$script:SIProSchemaLargeTableRows = 1000000
$script:SIProSchemaIndexBudgetMinutes = @{ Applied = 10; Current = 40 }

function Get-SIProSchemaIndexStatements {
    <#
        PURE. The plain index statements of one schema file that can be built on their own: CREATE [UNIQUE] [NONCLUSTERED]
        INDEX <name> ON <schema>.<table> ... with no WITH clause (a DROP_EXISTING rebuild and a CLUSTERED index stay in the
        file), written as a statement (ended by ';') or as EXEC ('...') / EXEC (N'...'). Never one inside a comment or inside
        a longer string (a procedure body that builds an index itself).
        Returns @{ Name; Table; Statement (runnable text); Start; Length (the span in -Sql that a no-op replaces) }.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Sql)
    # where strings and comments are: one pass, so a match inside either is never taken for a statement
    $n = $Sql.Length; $mask = New-Object 'bool[]' ($n + 1); $i = 0
    $strStart = New-Object System.Collections.Generic.List[int]; $strEnd = New-Object System.Collections.Generic.List[int]
    while ($i -lt $n) {
        $c = $Sql[$i]
        if ($c -eq '-' -and $i + 1 -lt $n -and $Sql[$i + 1] -eq '-') { while ($i -lt $n -and $Sql[$i] -ne "`n") { $mask[$i] = $true; $i++ }; continue }
        if ($c -eq '/' -and $i + 1 -lt $n -and $Sql[$i + 1] -eq '*') { $e = $Sql.IndexOf('*/', $i + 2); if ($e -lt 0) { $e = $n - 2 }; for ($k = $i; $k -le $e + 1 -and $k -lt $n; $k++) { $mask[$k] = $true }; $i = $e + 2; continue }
        if ($c -eq "'") {
            $s = $i; $i++
            while ($i -lt $n) { if ($Sql[$i] -eq "'") { if ($i + 1 -lt $n -and $Sql[$i + 1] -eq "'") { $i += 2; continue }; break }; $i++ }
            for ($k = $s; $k -le $i -and $k -lt $n; $k++) { $mask[$k] = $true }
            $strStart.Add($s); $strEnd.Add($i); $i++; continue
        }
        $i++
    }
    $head = '(CREATE\s+(?:UNIQUE\s+)?(?:NONCLUSTERED\s+)?INDEX\s+(\w+)\s+ON\s+(\w+\.\w+)\s*\()'
    $out = New-Object System.Collections.Generic.List[object]
    # only an index whose ONE guard is "this index is not there" -- any other condition (a column, a table, an older shape)
    # is the file's own decision and stays in the file
    $guarded = { param([int]$at, [string]$name, [string]$table)
        $from = [Math]::Max(0, $at - 400); $pre = $Sql.Substring($from, $at - $from)
        $g = "(?is)IF\s+NOT\s+EXISTS\s*\(\s*SELECT\s+1\s+FROM\s+sys\.indexes\s+WHERE\s+name\s*=\s*N?'" + [regex]::Escape($name) + "'\s+AND\s+object_id\s*=\s*OBJECT_ID\(\s*N?'" + [regex]::Escape($table) + "'\s*\)\s*\)\s*$"
        $pre -match $g -and $pre -notmatch ('(?is)(\bAND\b|\bOR\b)[^\n]*' + $g) }
    # EXEC ('CREATE INDEX ...') -- the whole string literal is the statement
    foreach ($m in [regex]::Matches($Sql, "(?i)\bEXEC\s*\(\s*N?'" + $head)) {
        if ($mask[$m.Index]) { continue }
        $q = $m.Groups[1].Index - 1                      # the opening quote
        $at = $strStart.IndexOf($q); if ($at -lt 0) { continue }
        $close = $strEnd[$at]
        $inner = $Sql.Substring($q + 1, $close - $q - 1)
        $after = $Sql.Substring($close + 1, [Math]::Min(20, $n - $close - 1))
        if ($after -notmatch '^\s*\)') { continue }       # not EXEC ('...') alone: left in the file
        $plain = $inner -replace "''", "'"
        if ($plain -match '(?i)\bWITH\s*\(') { continue }
        if (-not (& $guarded $m.Index $m.Groups[2].Value $m.Groups[3].Value)) { continue }
        $out.Add([pscustomobject]@{ Name = $m.Groups[2].Value; Table = $m.Groups[3].Value; Statement = $plain.Trim().TrimEnd(';'); Start = $q + 1; Length = $close - $q - 1 })
    }
    # CREATE INDEX ... ; -- written as a statement, outside any string or comment
    foreach ($m in [regex]::Matches($Sql, '(?i)(?<![\w.])' + $head)) {
        if ($mask[$m.Index]) { continue }
        $end = $m.Index
        while ($end -lt $n -and ($Sql[$end] -ne ';' -or $mask[$end])) { $end++ }
        if ($end -ge $n) { continue }
        $text = $Sql.Substring($m.Index, $end - $m.Index)
        if ($text -match '(?i)\bWITH\s*\(' -or $text -match "'") { continue }
        if (-not (& $guarded $m.Index $m.Groups[2].Value $m.Groups[3].Value)) { continue }
        $out.Add([pscustomobject]@{ Name = $m.Groups[2].Value; Table = $m.Groups[3].Value; Statement = $text.Trim(); Start = $m.Index; Length = $end - $m.Index })
    }
    # emitted one by one (callers wrap the call in @()): a statement list is never one array-in-an-array
    $out | Sort-Object Start
}

function Get-SIProSchemaIndexState {
    <#
        The database's side of the deferral, ONE read: the edition (resumable index builds: Azure SQL Database 5, Managed
        Instance 8, Enterprise 3), the tables at or over -LargeTableRows rows, the indexes that are there, and the resumable
        builds (PAUSED / RUNNING). Returns @{ Resumable; Large (set of 'schema.table'); Indexes (set of 'schema.table|name');
        Builds (hashtable 'schema.table|name' -> @{ State; Percent }) }. Throws on a read error (the caller decides).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [long]$LargeTableRows = $script:SIProSchemaLargeTableRows)
    # ONE result set (every reader seam reads the first): the resumable builds go through a table variable, as the view is
    # read only where it exists
    $sql = @"
SET NOCOUNT ON;
DECLARE @b TABLE (A nvarchar(300) NOT NULL, B nvarchar(300) NOT NULL, N bigint NOT NULL);
IF OBJECT_ID(N'sys.index_resumable_operations') IS NOT NULL
  INSERT @b (A, B, N) EXEC (N'SELECT OBJECT_SCHEMA_NAME(object_id) COLLATE DATABASE_DEFAULT + N''.'' + OBJECT_NAME(object_id) COLLATE DATABASE_DEFAULT, name COLLATE DATABASE_DEFAULT + N''|'' + state_desc COLLATE DATABASE_DEFAULT, CONVERT(bigint, percent_complete) FROM sys.index_resumable_operations');
-- catalog names carry the server's catalog collation: every one is read in the database's (one UNION, no conflict)
SELECT N'edition' AS K, CONVERT(nvarchar(300), SERVERPROPERTY('EngineEdition')) COLLATE DATABASE_DEFAULT AS A, CONVERT(nvarchar(300), N'') AS B, CONVERT(bigint, 0) AS N
UNION ALL
SELECT N'build', A, B, N FROM @b
UNION ALL
SELECT N'large', s.name COLLATE DATABASE_DEFAULT + N'.' + t.name COLLATE DATABASE_DEFAULT, N'', SUM(p.rows) FROM sys.tables AS t JOIN sys.schemas AS s ON s.schema_id = t.schema_id
  JOIN sys.partitions AS p ON p.object_id = t.object_id AND p.index_id IN (0, 1) GROUP BY s.name, t.name HAVING SUM(p.rows) >= $LargeTableRows
UNION ALL
SELECT N'index', s.name COLLATE DATABASE_DEFAULT + N'.' + t.name COLLATE DATABASE_DEFAULT, i.name COLLATE DATABASE_DEFAULT, CONVERT(bigint, 0) FROM sys.indexes AS i JOIN sys.tables AS t ON t.object_id = i.object_id
  JOIN sys.schemas AS s ON s.schema_id = t.schema_id WHERE i.name IS NOT NULL;
"@
    $rows = @(& $Invoke $sql @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
    $st = [pscustomobject]@{ Resumable = $false; Large = @{}; Indexes = @{}; Builds = @{} }
    foreach ($r in $rows) {
        $get = { param($k) if ($r -is [System.Collections.IDictionary]) { $r[$k] } else { $r.$k } }
        $k = [string](& $get 'K'); $a = [string](& $get 'A'); $b = [string](& $get 'B')
        switch ($k) {
            'edition' { $st.Resumable = @('3', '5', '8') -contains $a }
            'large'   { $st.Large[$a.ToLowerInvariant()] = $true }
            'index'   { $st.Indexes[('{0}|{1}' -f $a, $b).ToLowerInvariant()] = $true }
            'build'   { $nm, $state = $b -split '\|', 2; $st.Builds[('{0}|{1}' -f $a, $nm).ToLowerInvariant()] = [pscustomobject]@{ State = $state; Percent = [int](& $get 'N') } }
        }
    }
    $st
}

function Get-SIProSchemaDeferredIndexes {
    <#
        PURE. Of -Statements (Get-SIProSchemaIndexStatements), the ones built OUTSIDE the file: on a large table, not there
        yet, and only where the database can build resumably (elsewhere -- SQL Express, a new install's empty tables -- the
        file builds them as before). A build in progress (paused or running) is always deferred: a second CREATE would fail.
    #>
    param([object[]]$Statements = @(), [Parameter(Mandatory)]$State)
    # a batch without any index statement passes $null: @($null) is ONE $null element, and on a resumable database (Azure,
    # never SQL Express) $null.Table.ToLowerInvariant() threw -- the 3.0.0.202610200620 update at a large install
    @($Statements | Where-Object { $null -ne $_ -and $_.Table -and $_.Name }) | Where-Object {
        $key = ('{0}|{1}' -f $_.Table, $_.Name).ToLowerInvariant()
        if ($State.Indexes.ContainsKey($key)) { return $false }
        if ($State.Builds.ContainsKey($key)) { return $true }
        $State.Resumable -and $State.Large.ContainsKey($_.Table.ToLowerInvariant())
    }
}

function Remove-SIProSchemaDeferredIndexes {
    <# PURE. -Sql with every deferred statement's span replaced by PRINT 0 (inside EXEC ('...') too), so the file still runs. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Sql, [object[]]$Deferred = @())
    $sb = New-Object System.Text.StringBuilder $Sql
    foreach ($d in @($Deferred | Sort-Object Start -Descending)) { [void]$sb.Remove($d.Start, $d.Length).Insert($d.Start, 'PRINT 0') }
    $sb.ToString()
}

function Get-SIProSchemaIndexBuildSql {
    <# PURE. The statement for one deferred index: RESUME a paused build, else CREATE it ONLINE + RESUMABLE, both with MAX_DURATION. #>
    param([Parameter(Mandatory)]$Index, [string]$BuildState = '', [Parameter(Mandatory)][int]$Minutes)
    $m = [Math]::Max(1, $Minutes)
    if ($BuildState -eq 'PAUSED') { return ('ALTER INDEX {0} ON {1} RESUME WITH (MAX_DURATION = {2} MINUTES)' -f $Index.Name, $Index.Table, $m) }
    '{0} WITH (ONLINE = ON, RESUMABLE = ON, MAX_DURATION = {1} MINUTES)' -f $Index.Statement.TrimEnd(';').TrimEnd(), $m
}

function Invoke-SIProSchemaIndexStep {
    <#
        Builds the deferred indexes, in file order, inside -BudgetMinutes. -Run (statement): runs ONE statement outside any
        transaction (the runner's '#index' mode, or the plain invoke). Per index: there = built; RUNNING elsewhere = pending;
        PAUSED = resumed; else created. A build that ends paused (its MAX_DURATION) is pending; any other error is a WARNING
        and pending -- never a failed update. When the budget is spent the rest stay pending. NEVER throws.
        Returns @{ Built; Pending; Warnings }.
    #>
    param([object[]]$Deferred = @(), [Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][scriptblock]$Run, [int]$BudgetMinutes = 10,
          [scriptblock]$Log = { param($m) }, [datetime]$StartUtc = [datetime]::UtcNow, [scriptblock]$Now = { [datetime]::UtcNow })
    $res = [pscustomobject]@{ Built = @(); Pending = @(); Warnings = @() }
    $built = New-Object System.Collections.Generic.List[string]; $pending = New-Object System.Collections.Generic.List[string]; $warn = New-Object System.Collections.Generic.List[string]
    foreach ($d in @($Deferred | Where-Object { $null -ne $_ })) {
        $key = ('{0}|{1}' -f $d.Table, $d.Name).ToLowerInvariant()
        $st = $null; try { $st = Get-SIProSchemaIndexState -Invoke $Invoke -LargeTableRows ([long]::MaxValue) } catch { $warn.Add(('{0}: the database could not be read ({1})' -f $d.Name, $_.Exception.Message)); $pending.Add($d.Name); continue }
        if ($st.Indexes.ContainsKey($key)) { $built.Add($d.Name); continue }
        $b = $st.Builds[$key]
        if ($b -and $b.State -eq 'RUNNING') { & $Log ('  index {0} on {1}: being built elsewhere ({2}%) -- pending' -f $d.Name, $d.Table, $b.Percent); $pending.Add($d.Name); continue }
        $rem = $BudgetMinutes - ((& $Now) - $StartUtc).TotalMinutes
        if ($rem -lt 1) { $pending.Add($d.Name); continue }
        $left = [int][Math]::Floor($rem + 0.05)                  # whole minutes (a few seconds of reading do not cost one)
        $sql = Get-SIProSchemaIndexBuildSql -Index $d -BuildState $(if ($b) { $b.State } else { '' }) -Minutes $left
        & $Log ('  index {0} on {1}: {2} (up to {3} min)' -f $d.Name, $d.Table, $(if ($b) { "resumed at $($b.Percent)%" } else { 'built online, resumable' }), $left)
        $err = $null
        try { & $Run $sql } catch { $err = $_.Exception.Message }
        $after = $null; try { $after = Get-SIProSchemaIndexState -Invoke $Invoke -LargeTableRows ([long]::MaxValue) } catch { }
        if ($after -and $after.Indexes.ContainsKey($key)) { $built.Add($d.Name); & $Log ('  index {0}: built' -f $d.Name); continue }
        $pb = if ($after) { $after.Builds[$key] } else { $null }
        if ($pb) { $pending.Add($d.Name); & $Log ('  index {0}: paused at {1}% -- the next update resumes it' -f $d.Name, $pb.Percent); continue }
        $pending.Add($d.Name)
        $warn.Add(('{0} on {1} was not built ({2}) -- the next update tries again; the release works without it' -f $d.Name, $d.Table, $(if ($err) { $err } else { 'no error, not there' })))
    }
    $res.Built = $built.ToArray(); $res.Pending = $pending.ToArray(); $res.Warnings = $warn.ToArray()
    $res
}

# ---- A PAUSED INDEX BUILD THAT BLOCKS THE SCHEMA (2026-10-20, a large install, 1322 -> 3.0.0.202610201855) ----------
# A deferred build (above) that ended its budget is PAUSED, and SQL Server refuses any change to its table while it is:
# error 10637 "Cannot perform this operation on 'object' with ID <id> as one or more indexes are currently in resumable
# index rebuild state". A release that adds a column to that table then failed at the schema and the install stayed on the
# old release. Now, ONLY on that failure: the paused build(s) on the table the error names are ABORTED (ALTER INDEX ... ABORT,
# outside any transaction), one plain line says so, and the file is applied again ONCE. The index step after the files then
# finds the index missing and builds it again (ONLINE + RESUMABLE, in its budget). A RUNNING build is never aborted: it is
# waited for inside the update's budget (it pauses at its own MAX_DURATION or ends), then the file is tried again. A schema
# that changes nothing on that table never fails, so a paused build there is left to finish over the next updates.
$script:SIProSchemaResumableBlockError = 10637
$script:SIProSchemaRunningWaitMinutes = 10

function Get-SIProSchemaResumableBlock {
    <#
        PURE. Is -Exception (any depth of InnerException) SQL Server's refusal to change a table that has a resumable index
        build (error 10637)? By the SqlException's number, else by its text (an invoke seam may hand the message only).
        Returns $null (another error) or @{ ObjectId (the id the message names, 0 when it names none); Message }.
    #>
    param($Exception)
    $e = $Exception
    while ($null -ne $e) {
        $hit = $false
        $num = $null; try { if ($e.PSObject.Properties['Number']) { $num = [int]$e.Number } } catch { }
        if ($num -eq $script:SIProSchemaResumableBlockError) { $hit = $true }
        if (-not $hit) { try { foreach ($x in @($e.Errors)) { if ($x -and $x.PSObject.Properties['Number'] -and [int]$x.Number -eq $script:SIProSchemaResumableBlockError) { $hit = $true } } } catch { } }
        $msg = [string]$e.Message
        if ($hit -or $msg -match '(?i)as one or more indexes are currently in resumable index rebuild state') {
            $id = 0L; if ($msg -match '(?i)with ID (-?\d+)') { $id = [long]$Matches[1] }
            return [pscustomobject]@{ ObjectId = $id; Message = $msg }
        }
        $e = $e.InnerException
    }
    $null
}

function Get-SIProSchemaChangedTables {
    <# PURE. The tables a schema text changes (ALTER TABLE <schema>.<table>, CREATE INDEX ... ON <schema>.<table>), lower case. #>
    param([string[]]$Batches = @())
    $set = @{}
    foreach ($b in @($Batches)) {
        if (-not $b) { continue }
        $clean = [regex]::Replace($b, '--[^\r\n]*', '')
        foreach ($m in [regex]::Matches($clean, '(?i)\bALTER\s+TABLE\s+\[?(\w+)\]?\.\[?(\w+)\]?')) { $set[('{0}.{1}' -f $m.Groups[1].Value, $m.Groups[2].Value).ToLowerInvariant()] = $true }
        foreach ($m in [regex]::Matches($clean, '(?i)\bINDEX\s+\[?\w+\]?\s+ON\s+\[?(\w+)\]?\.\[?(\w+)\]?')) { $set[('{0}.{1}' -f $m.Groups[1].Value, $m.Groups[2].Value).ToLowerInvariant()] = $true }
    }
    @($set.Keys | Sort-Object)
}

function Get-SIProSchemaResumableBuilds {
    <#
        The resumable index builds there are (sys.index_resumable_operations), ONE result set: @{ ObjectId; Table
        ('schema.table'); Name; State (PAUSED / RUNNING); Percent }. None where the view does not exist. Throws on a read error.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $sql = @"
SET NOCOUNT ON;
DECLARE @b TABLE (O bigint NOT NULL, T nvarchar(300) NOT NULL, I nvarchar(300) NOT NULL, S nvarchar(60) NOT NULL, P bigint NOT NULL);
IF OBJECT_ID(N'sys.index_resumable_operations') IS NOT NULL
  INSERT @b (O, T, I, S, P) EXEC (N'SELECT CONVERT(bigint, object_id), OBJECT_SCHEMA_NAME(object_id) COLLATE DATABASE_DEFAULT + N''.'' + OBJECT_NAME(object_id) COLLATE DATABASE_DEFAULT, name COLLATE DATABASE_DEFAULT, state_desc COLLATE DATABASE_DEFAULT, CONVERT(bigint, percent_complete) FROM sys.index_resumable_operations');
SELECT N'resumablebuild' AS K, O, T, I, S, P FROM @b;
"@
    @(& $Invoke $sql @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ }) | ForEach-Object {
        $r = $_; $get = { param($k) if ($r -is [System.Collections.IDictionary]) { $r[$k] } else { $r.$k } }
        if ([string](& $get 'K') -ne 'resumablebuild') { return }
        [pscustomobject]@{ ObjectId = [long](& $get 'O'); Table = [string](& $get 'T'); Name = [string](& $get 'I'); State = [string](& $get 'S'); Percent = [int](& $get 'P') }
    }
}

function Get-SIProSchemaIndexAbortSql {
    <# PURE. ALTER INDEX [name] ON [schema].[table] ABORT -- every name quoted. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Table)
    $q = { param($s) '[' + $s.Replace(']', ']]') + ']' }
    $sch, $tab = $Table -split '\.', 2
    'ALTER INDEX {0} ON {1}.{2} ABORT' -f (& $q $Name), (& $q $sch), (& $q $tab)
}

function Clear-SIProSchemaResumableBlock {
    <#
        After a file failed with -Block (Get-SIProSchemaResumableBlock): makes the table the error names changeable again.
        The builds on it: by the error's object id, else on the tables the file changes (-Batches). A RUNNING one is waited
        for (-WaitMinutes, read every -PollSeconds) -- never aborted; each PAUSED one is ABORTED through -Run (outside any
        transaction) with one plain line. -Deferred: the release's deferred indexes (a stopped build that is one of them is
        built again by the index step after the files). NEVER throws.
        Returns @{ Ok (apply the file again); Aborted (names); Reason }.
    #>
    param([Parameter(Mandatory)]$Block, [string[]]$Batches = @(), [Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][scriptblock]$Run,
          [object[]]$Deferred = @(), [scriptblock]$Log = { param($m) }, [int]$WaitMinutes = $script:SIProSchemaRunningWaitMinutes, [int]$PollSeconds = 30,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s }, [datetime]$StartUtc = [datetime]::UtcNow, [scriptblock]$Now = { [datetime]::UtcNow })
    $out = { param($ok, $why, $ab) [pscustomobject]@{ Ok = $ok; Aborted = @($ab); Reason = $why } }
    $tables = @(Get-SIProSchemaChangedTables -Batches $Batches)
    $pick = { param($all) @($all | Where-Object { $null -ne $_ -and $(if ($Block.ObjectId) { $_.ObjectId -eq $Block.ObjectId } else { $tables -contains $_.Table.ToLowerInvariant() }) }) }
    $builds = @()
    try { $builds = & $pick @(Get-SIProSchemaResumableBuilds -Invoke $Invoke) } catch { return (& $out $false ('the index builds on the table could not be read ({0})' -f $_.Exception.Message) @()) }
    # a RUNNING build: wait for it inside the budget (it pauses at its own MAX_DURATION or ends) -- never aborted
    while (@($builds | Where-Object { $_.State -eq 'RUNNING' }).Count) {
        $r = @($builds | Where-Object { $_.State -eq 'RUNNING' })[0]
        if (((& $Now) - $StartUtc).TotalMinutes -ge $WaitMinutes) {
            return (& $out $false ('an index build is running on {0} ({1}, {2}%) and the update cannot change the table while it runs -- the next update tries again' -f $r.Table, $r.Name, $r.Percent) @())
        }
        & $Log ('  an index build is running on {0} ({1}, {2}%) -- the update waits for it before it changes the table' -f $r.Table, $r.Name, $r.Percent)
        & $Sleep $PollSeconds
        try { $builds = & $pick @(Get-SIProSchemaResumableBuilds -Invoke $Invoke) } catch { return (& $out $false ('the index builds on the table could not be read ({0})' -f $_.Exception.Message) @()) }
    }
    $ours = @{}; foreach ($d in @($Deferred | Where-Object { $null -ne $_ })) { $ours[('{0}|{1}' -f $d.Table, $d.Name).ToLowerInvariant()] = $true }
    $aborted = New-Object System.Collections.Generic.List[string]
    foreach ($b in @($builds | Where-Object { $_.State -eq 'PAUSED' })) {
        try { & $Run (Get-SIProSchemaIndexAbortSql -Name $b.Name -Table $b.Table) }
        catch { return (& $out $false ('an index build paused on {0} ({1}) blocks the change to the table and could not be stopped ({2})' -f $b.Table, $b.Name, $_.Exception.Message) $aborted.ToArray()) }
        $aborted.Add($b.Name)
        $again = if ($ours.ContainsKey(('{0}|{1}' -f $b.Table, $b.Name).ToLowerInvariant())) { 'it is built again by the update after the change (this update starts it, the next ones finish it)' } else { 'it is not one of this release''s indexes, so it is not started again' }
        & $Log ('  an index build that was paused on {0} ({1}, {2}%) was stopped so the update could change the table; {3}' -f $b.Table, $b.Name, $b.Percent, $again)
    }
    # none left (it finished, or another session stopped it): the file is tried again all the same -- once
    & $out $true $(if ($aborted.Count) { 'stopped: ' + ($aborted -join ', ') } else { 'no paused build is left on the table' }) $aborted.ToArray()
}

function Get-SIProSchemaIndexBudget {
    <#
        The minutes this update may spend on deferred indexes: the small budget when it applies new schema (the code still
        has to roll inside the updater's limit); the large one when the schema is already current AND the code that goes with
        it is rolled (cfg.InstallState EngineFingerprint's version = the recorded schema's release) -- then the indexes are
        all that is left. Never throws (unknown = the small budget).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [bool]$SchemaCurrent)
    if (-not $SchemaCurrent) { return $script:SIProSchemaIndexBudgetMinutes.Applied }
    try {
        $rows = @(& $Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT (SELECT [Version] FROM cfg.InstallState WHERE Name = N'SchemaVersion') AS S, (SELECT Value FROM cfg.InstallState WHERE Name = N'EngineFingerprint') AS E" @{} 'reader' | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
        if (-not $rows.Count) { return $script:SIProSchemaIndexBudgetMinutes.Applied }
        $r = $rows[0]; $get = { param($k) if ($r -is [System.Collections.IDictionary]) { $r[$k] } else { $r.$k } }
        $s = [string](& $get 'S'); $e = ''; try { $e = [string]((ConvertFrom-Json -InputObject ([string](& $get 'E'))).version) } catch { $e = '' }
        if ($s -and $e -and $s -eq $e) { return $script:SIProSchemaIndexBudgetMinutes.Current }
    } catch { }
    $script:SIProSchemaIndexBudgetMinutes.Applied
}

function Get-SIProSchemaSha256 {
    <# PURE. Lower-case hex SHA-256 of a text's UTF-8 bytes. #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) | ForEach-Object { $_.ToString('x2') }) -join '') }
    finally { $sha.Dispose() }
}

function Get-SIProSchemaPlan {
    <#
        PURE apart from reading the files. The set to apply from a release (-SIRoot): every file read, checked by the gate,
        split into batches and hashed. -Names: a subset (setup applies its own files; the updater all of them).
        -ExtraFingerprint: folded into the hash (the updater's grants), so a change there is not a no-op either.
        Returns @{ Ok; Files = @{ Name; File; Split; Sha256; Batches; Additive; Findings }; Hash; Refused; Reason }.
        A file that is not in this release is left out (a Community copy has none of them).
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string[]]$Names, [string]$ExtraFingerprint = '')
    $files = New-Object System.Collections.Generic.List[object]
    $refused = New-Object System.Collections.Generic.List[object]
    foreach ($f in (Get-SIProSchemaFileList)) {
        if ($Names -and $Names -notcontains $f.Name) { continue }
        $path = [System.IO.Path]::Combine($SIRoot, ($f.File -replace '/', [System.IO.Path]::DirectorySeparatorChar))
        if (-not (Test-Path -LiteralPath $path)) { continue }
        $text = [System.IO.File]::ReadAllText($path)
        $gate = Test-SISchemaIsAdditive -Sql $text
        $row = [pscustomobject]@{ Name = $f.Name; File = $f.File; Split = $f.Split; Sha256 = (Get-SIProSchemaSha256 $text)
                                  Batches = (Split-SIProSchemaBatches -Sql $text -Split $f.Split); Additive = $gate.IsAdditive; Findings = @($gate.Findings) }
        $files.Add($row)
        if (-not $gate.IsAdditive) { $refused.Add($row) }
    }
    $lines = @($files | ForEach-Object { '{0}:{1}' -f $_.Name, $_.Sha256 })
    if ($ExtraFingerprint) { $lines += ('extra:{0}' -f (Get-SIProSchemaSha256 $ExtraFingerprint)) }
    $hash = Get-SIProSchemaSha256 ($lines -join "`n")
    $reason = if ($refused.Count) {
        $r = $refused[0]; $first = @($r.Findings)[0]
        ('REFUSED: {0} is not additive -- line {1} {2}. Nothing was applied: SecurityInsight applies additive, idempotent schema only.' -f $r.File, $first.Line, $first.Why)
    } elseif (-not $files.Count) { 'this release carries no Pro schema' } else { ('{0} schema file(s) ready ({1})' -f $files.Count, (($files | ForEach-Object { $_.Name }) -join ', ')) }
    [pscustomobject]@{ Ok = ($refused.Count -eq 0); Files = $files.ToArray(); Hash = $hash; Refused = $refused.ToArray(); Reason = $reason }
}

function Read-SIProSchemaState {
    <# The recorded schema (cfg.InstallState 'SchemaVersion') -> @{ Hash; Version; At; Files; Grants } or $null (none / no table). #>
    param([Parameter(Mandatory)][scriptblock]$Invoke)
    $rows = @(& $Invoke "IF OBJECT_ID('cfg.InstallState') IS NOT NULL SELECT Value, [Version] FROM cfg.InstallState WHERE Name = N'SchemaVersion'" @{} 'reader' | ForEach-Object { $_ })
    if (-not $rows.Count) { return $null }
    $r = $rows[0]
    $get = { param($k) if ($r -is [System.Collections.IDictionary]) { $r[$k] } else { $r.$k } }
    $v = $null; try { $v = ConvertFrom-Json -InputObject ([string](& $get 'Value')) } catch { return $null }
    [pscustomobject]@{ Hash = [string]$v.hash; Version = [string](& $get 'Version'); At = [string]$v.at; Files = [string]$v.files; Grants = [string]$v.grants }
}

function ConvertTo-SIProSchemaStateValue {
    <# PURE. The compact JSON stored in cfg.InstallState.Value (NVARCHAR(400)). #>
    param([Parameter(Mandatory)][string]$Hash, [string[]]$Files = @(), [string[]]$Grants = @(), [datetime]$NowUtc = [datetime]::UtcNow)
    $o = [ordered]@{ hash = $Hash; files = (@($Files) -join ','); grants = (@($Grants) -join ','); at = $NowUtc.ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    $json = ConvertTo-Json -InputObject $o -Compress
    if ($json.Length -gt 400) { $o.grants = ''; $json = ConvertTo-Json -InputObject $o -Compress }
    $json
}

function Save-SIProSchemaState {
    <# Records the applied schema (upsert of cfg.InstallState 'SchemaVersion'). Throws on failure -- the caller decides. #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$Hash, [string]$Version = '', [string[]]$Files = @(), [string[]]$Grants = @(),
          [string]$By = 'SecurityInsight', [datetime]$NowUtc = [datetime]::UtcNow)
    $sql = @'
SET XACT_ABORT ON;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.InstallState WITH (UPDLOCK, HOLDLOCK) WHERE Name = N'SchemaVersion')
    UPDATE cfg.InstallState SET Value = @Value, [Version] = @Version, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By WHERE Name = N'SchemaVersion';
ELSE
    INSERT cfg.InstallState (Name, Value, [Version], UpdatedBy) VALUES (N'SchemaVersion', @Value, @Version, @By);
COMMIT;
'@
    $v = if ($Version) { $Version.Substring(0, [Math]::Min(32, $Version.Length)) } else { $null }
    & $Invoke $sql ([ordered]@{ Value = (ConvertTo-SIProSchemaStateValue -Hash $Hash -Files $Files -Grants $Grants -NowUtc $NowUtc); Version = $v; By = $By }) 'nonquery'
}

function New-SIProSchemaRunner {
    <#
        -RunFile for Invoke-SIProSchemaApply: ONE connection, ONE transaction for all batches of one file; rolled back on any
        error. -GetToken returns an Entra access token for https://database.windows.net/.
        -CommandTimeoutSec is per batch, 0 = no limit (owner 2026-10-22: "i accept no limits"): a schema batch builds indexes over every row that is there.
    #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][scriptblock]$GetToken, [int]$CommandTimeoutSec = 0)
    $cs = 'Server=tcp:{0},1433;Database={1};Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;' -f $Server, $Database
    $timeout = $CommandTimeoutSec
    {
        param([string]$Name, [string[]]$Batches)
        $cn = New-Object System.Data.SqlClient.SqlConnection($cs)
        $cn.AccessToken = [string](& $GetToken)
        $cn.Open()
        $tx = $null
        try {
            if ($Name -eq '#index') {
                # a deferred index (ONLINE, RESUMABLE): never inside a transaction -- a resumable build cannot be
                foreach ($b in $Batches) { $cmd = $cn.CreateCommand(); $cmd.CommandText = $b; $cmd.CommandTimeout = $timeout; [void]$cmd.ExecuteNonQuery() }
                return
            }
            $tx = $cn.BeginTransaction()
            foreach ($b in $Batches) {
                $cmd = $cn.CreateCommand(); $cmd.Transaction = $tx; $cmd.CommandText = $b; $cmd.CommandTimeout = $timeout
                [void]$cmd.ExecuteNonQuery()
            }
            $tx.Commit(); $tx = $null
        } catch {
            if ($tx) { try { $tx.Rollback() } catch { } }
            throw
        } finally { $cn.Dispose() }
    }.GetNewClosure()
}

function Invoke-SIProSchemaApply {
    <#
        THE ONE APPLY (setup, the internal build and the updater call this). In order:
          1. plan the set from -SIRoot (Get-SIProSchemaPlan) -- one non-additive file = 'refused', NOTHING sent;
          2. -SkipWhenRecorded: the recorded fingerprint equals this one = 'noop' (visible and fast; nothing sent);
          3. every file in order, each in its own transaction (see the header) -- a failure stops at that file = 'failed';
          4. 'applied'. Recording is the caller's (Save-SIProSchemaState): the updater records after its grants too.
        -Invoke (sql, params, mode): the database; -RunFile (name, batches): optional, a one-connection transaction.
        Returns @{ Action = applied | noop | refused | failed; Hash; Files; Applied; FailedFile; Reason; Findings; Plan }.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$RunFile, [string[]]$Names,
          [string]$ExtraFingerprint = '', [switch]$SkipWhenRecorded, [scriptblock]$Log, [long]$LargeTableRows = $script:SIProSchemaLargeTableRows,
          # a RUNNING index build on a table a file changes is waited for this long, never aborted (seams: -Sleep)
          [int]$RunningWaitMinutes = $script:SIProSchemaRunningWaitMinutes, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    if (-not $Log) { $Log = { param([string]$m) Write-Host $m } }
    $plan = Get-SIProSchemaPlan -SIRoot $SIRoot -Names $Names -ExtraFingerprint $ExtraFingerprint
    $names = @($plan.Files | ForEach-Object { $_.Name })
    $out = { param($a, $why, $applied, $failed, $findings)
        [pscustomobject]@{ Action = $a; Hash = $plan.Hash; Files = $names; Applied = @($applied); FailedFile = $failed; Reason = $why; Findings = @($findings); Plan = $plan } }
    if (-not $plan.Ok) { return (& $out 'refused' $plan.Reason @() $plan.Refused[0].File $plan.Refused[0].Findings) }
    if (-not $plan.Files.Count) { return (& $out 'noop' $plan.Reason @() '' @()) }
    # indexes on large tables: which statements are built outside the files (see the header of that section). A failed read
    # defers nothing -- the files then build every index as before.
    $ixState = $null
    try { $ixState = Get-SIProSchemaIndexState -Invoke $Invoke -LargeTableRows $LargeTableRows } catch { & $Log ('  indexes on large tables: the database could not be read ({0}) -- every index is built in its file' -f $_.Exception.Message) }
    $deferred = New-Object System.Collections.Generic.List[object]
    $batchesOf = @{}
    foreach ($f in $plan.Files) {
        $bs = New-Object System.Collections.Generic.List[string]
        foreach ($b in @($f.Batches)) {
            $d = if ($ixState) { @(Get-SIProSchemaDeferredIndexes -Statements @(Get-SIProSchemaIndexStatements -Sql $b) -State $ixState) } else { @() }
            foreach ($x in $d) { $deferred.Add($x) }
            $bs.Add($(if ($d.Count) { Remove-SIProSchemaDeferredIndexes -Sql $b -Deferred $d } else { $b }))
        }
        $batchesOf[$f.Name] = $bs.ToArray()
    }
    $runIx = if ($RunFile) { { param($s) & $RunFile '#index' @($s) } } else { { param($s) & $Invoke $s @{} 'nonquery' } }
    $ixStep = { param([bool]$current)
        if (-not $deferred.Count) { return $null }
        $budget = Get-SIProSchemaIndexBudget -Invoke $Invoke -SchemaCurrent $current
        if (-not $RunFile) { $budget = [Math]::Min($budget, 1) }    # the plain invoke's statement timeout is short: one minute per build, it resumes
        & $Log ('  indexes on large tables: {0} built outside the schema transaction, up to {1} min this update ({2})' -f $deferred.Count, $budget, (($deferred | ForEach-Object { $_.Name }) -join ', '))
        $r = Invoke-SIProSchemaIndexStep -Deferred $deferred.ToArray() -Invoke $Invoke -Run $runIx -BudgetMinutes $budget -Log $Log
        foreach ($w in @($r.Warnings)) { & $Log ('  WARNING: index {0}' -f $w) }
        $r
    }
    $ixText = { param($r) if ($r -and @($r.Pending).Count) { '; {0} index(es) on large tables still being built -- the next update goes on with them ({1})' -f @($r.Pending).Count, (@($r.Pending) -join ', ') } elseif ($r -and @($r.Built).Count) { '; {0} index(es) on large tables built' -f @($r.Built).Count } else { '' } }
    if ($SkipWhenRecorded) {
        $state = $null; try { $state = Read-SIProSchemaState -Invoke $Invoke } catch { $state = $null }
        if ($state -and $state.Hash -eq $plan.Hash) {
            # the schema is current -- but an index on a large table may still be pending from an earlier update: go on with it
            $ix = & $ixStep $true
            $o = & $out 'noop' ('the database schema is current (fingerprint {0}, recorded {1}{2}) -- nothing to apply{3}' -f $plan.Hash.Substring(0, 12), $state.At, $(if ($state.Version) { " for $($state.Version)" } else { '' }), (& $ixText $ix)) @() '' @()
            $o | Add-Member -NotePropertyName Indexes -NotePropertyValue $ix -Force
            return $o
        }
    }
    $done = New-Object System.Collections.Generic.List[string]
    foreach ($f in $plan.Files) {
        $batches = @($batchesOf[$f.Name])
        if (-not $batches.Count) { $done.Add($f.Name); continue }
        $tries = 0
        while ($true) {
            try {
                if ($RunFile) {
                    # the caller's runner: one connection, one transaction, the long schema timeout -- for a one-batch file too
                    & $RunFile $f.Name $batches
                } elseif ($batches.Count -eq 1) {
                    # one batch: its own transaction through any invoke; XACT_ABORT rolls the whole file back on an error
                    & $Invoke ("SET XACT_ABORT ON;`nBEGIN TRANSACTION;`n{0}`n;COMMIT TRANSACTION;" -f $batches[0]) @{} 'nonquery'
                } else {
                    foreach ($b in $batches) { & $Invoke $b @{} 'nonquery' }
                }
                break
            } catch {
                $failure = $_.Exception
                # a resumable index build on a table this file changes (error 10637): stop a PAUSED one, wait for a RUNNING
                # one, then the file once more -- only on this failure, so a schema that does not touch the table never stops it
                $block = if ($tries -eq 0) { Get-SIProSchemaResumableBlock -Exception $failure } else { $null }
                if (-not $block) {
                    return (& $out 'failed' ('{0} could not be applied ({1}) -- that file was rolled back; nothing after it was applied' -f $f.File, $failure.Message) $done.ToArray() $f.File @())
                }
                $tries++
                $clear = Clear-SIProSchemaResumableBlock -Block $block -Batches $batches -Invoke $Invoke -Run $runIx -Deferred $deferred.ToArray() -Log $Log -WaitMinutes $RunningWaitMinutes -Sleep $Sleep
                if (-not $clear.Ok) {
                    return (& $out 'failed' ('{0} could not be applied: {1} -- that file was rolled back; nothing after it was applied' -f $f.File, $clear.Reason) $done.ToArray() $f.File @())
                }
            }
        }
        $done.Add($f.Name)
        & $Log ('  schema {0} applied ({1} batch(es), {2})' -f $f.File, $batches.Count, $f.Sha256.Substring(0, 12))
    }
    # the deferred indexes, after the files are committed (their columns are there now) -- never a failed update
    $ix = & $ixStep $false
    $o = & $out 'applied' ('{0} schema file(s) applied: {1}{2}' -f $done.Count, ($done -join ', '), (& $ixText $ix)) $done.ToArray() '' @()
    $o | Add-Member -NotePropertyName Indexes -NotePropertyValue $ix -Force
    $o
}
