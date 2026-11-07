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

function Get-SITaggingDatabaseStateSql {
    <#
        PURE. READ-ONLY, one row: what asset tagging's identity holds in the Pro database today -- its user (found by SID, the
        client id; NULL = none), read access (db_datareader, or the component role si_tagging), whether cfg.AuditEvent is
        there and whether the identity may INSERT into it (a grant to the user or to one of its roles, on the table or on
        the cfg schema, or db_datawriter). The product updater reads it on every update (no person needed; framework
        SEC-08) and gives what is missing (Get-SITaggingDatabaseUpdatePlan).
    #>
    param([Parameter(Mandatory)][string]$ClientId)
    $sid = '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
    @"
DECLARE @n sysname, @pid int;
SELECT @n = name, @pid = principal_id FROM sys.database_principals WHERE sid = $sid;
SELECT @n AS UserName,
       CASE WHEN @n IS NULL THEN 0 ELSE ISNULL(IS_ROLEMEMBER(N'db_owner', @n), 0) END AS DbOwner,
       CASE WHEN @n IS NULL THEN 0 ELSE ISNULL(IS_ROLEMEMBER(N'db_datareader', @n), 0) END AS DataReader,
       CASE WHEN @n IS NULL OR DATABASE_PRINCIPAL_ID(N'si_tagging') IS NULL THEN 0 ELSE ISNULL(IS_ROLEMEMBER(N'si_tagging', @n), 0) END AS TaggingRole,
       CASE WHEN OBJECT_ID(N'cfg.AuditEvent') IS NULL THEN 0 ELSE 1 END AS AuditTable,
       CASE WHEN @n IS NULL THEN 0
            WHEN ISNULL(IS_ROLEMEMBER(N'db_datawriter', @n), 0) = 1 THEN 1
            WHEN EXISTS (SELECT 1 FROM sys.database_permissions AS dp
                         WHERE dp.permission_name = N'INSERT' AND dp.[state] IN ('G', 'W')
                           AND ((dp.class = 1 AND dp.major_id = OBJECT_ID(N'cfg.AuditEvent') AND dp.minor_id = 0) OR (dp.class = 3 AND dp.major_id = SCHEMA_ID(N'cfg')))
                           AND (dp.grantee_principal_id = @pid
                                OR dp.grantee_principal_id IN (SELECT m.role_principal_id FROM sys.database_role_members AS m WHERE m.member_principal_id = @pid))) THEN 1
            ELSE 0 END AS AuditInsert;
"@
}

function Get-SITaggingDatabaseUpdatePlan {
    <#
        PURE. What the product updater does about asset tagging's database access on THIS update -- the same end state
        setup\Grant-SITaggingDatabase.ps1 gives (a user, read access, INSERT on cfg.AuditEvent), made by the product instead
        of a person who is the SQL server's admin (framework SEC-08: existing installs reach the new-install state through
        the update). -State: the row of Get-SITaggingDatabaseStateSql ($null = it could not be read). Returns
        @{ Action; Missing; Sql; Rows; Line }, Action one of:
          unknown    the state could not be read -- nothing is done, said in one line;
          current    everything is there -- nothing is done, nothing is said;
          procedure  the install has the signed grant procedure (-Procedure): ONE call gives all of it -- the identity's
                     contained user by its client id into its component role si_tagging (USER row), SELECT on the product
                     schemas, INSERT on cfg.AuditEvent and a DENY of SELECT on the sign-in key ring, all to si_tagging;
          grant      today's grant path (the updater holds db_securityadmin, never ALTER ANY USER or a fixed role): the
                     user and its read access are there and only the INSERT on cfg.AuditEvent is missing -- one GRANT;
          task       what is missing needs the server's admin on this install (no user, or no read access, and no grant
                     procedure): one plain warning naming the one-time customer action. The update goes on.
        -Schemas: the product schemas the role may read (default: the grant procedure's list).
    #>
    param($State, [Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$ClientId, [switch]$Procedure,
          [string[]]$Schemas = @('sidata', 'cfg', 'vuln', 'cmdbsync', 'snowstage'))
    $out = { param($a, $missing = @(), $sql = '', $rows = @(), $line = '') [pscustomobject]@{ Action = $a; Missing = @($missing); Sql = $sql; Rows = @($rows); Line = $line } }
    if ($null -eq $State) { return (& $out 'unknown' @() '' @() "asset tagging's database access could not be read -- it is checked again at the next update") }
    $get = { param($k) $v = if ($State -is [System.Collections.IDictionary]) { $State[$k] } elseif ($State -is [System.Data.DataRow]) { $State[$k] } elseif ($State.PSObject.Properties[$k]) { $State.$k } else { $null }
             if ($null -eq $v -or $v -is [System.DBNull]) { '' } else { [string]$v } }
    $on = { param($k) (& $get $k) -in '1', 'True' }
    $user = (& $get 'UserName').Trim()
    if ($user -and (& $on 'DbOwner')) { return (& $out 'current') }   # an owner holds every right (and is never handled by the procedure)
    $missing = New-Object System.Collections.Generic.List[string]
    if (-not $user) { $missing.Add('its database user') }
    if (-not $user -or -not ((& $on 'DataReader') -or (& $on 'TaggingRole'))) { $missing.Add('read access to its settings') }
    if ((& $on 'AuditTable') -and -not (& $on 'AuditInsert')) { $missing.Add('writing its audit rows (INSERT on cfg.AuditEvent)') }
    if (-not $missing.Count) { return (& $out 'current') }
    $what = $missing -join ', '
    if ($Procedure) {
        # the existing user's own name when the procedure accepts it (a safe name); else the identity's name (the procedure
        # finds the user by SID anyway and never renames it)
        $n = if ($user -and $user -match '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$') { $user } else { $UserName }
        $rows = New-Object System.Collections.Generic.List[object]
        $rows.Add([pscustomobject]@{ action = 'USER'; component = 'tagging'; user = $n; appId = ([guid]$ClientId).ToString() })
        foreach ($s in $Schemas) { $rows.Add([pscustomobject]@{ action = 'GRANT'; permission = 'SELECT'; on = ('SCHEMA::' + $s); to = 'si_tagging' }) }
        $rows.Add([pscustomobject]@{ action = 'GRANT'; permission = 'INSERT'; on = 'cfg.AuditEvent'; to = 'si_tagging' })
        $rows.Add([pscustomobject]@{ action = 'DENY'; permission = 'SELECT'; on = 'cfg.WebKeyRing'; to = 'si_tagging' })
        return (& $out 'procedure' $missing.ToArray() '' $rows.ToArray() ("asset tagging's database access: {0} -- given by this update through the product's grant procedure" -f $what))
    }
    if ($user -and $missing.Count -eq 1 -and $missing[0] -like 'writing its audit rows*') {
        $q = $user.Replace(']', ']]')
        return (& $out 'grant' $missing.ToArray() ("IF OBJECT_ID(N'cfg.AuditEvent') IS NOT NULL GRANT INSERT ON OBJECT::cfg.AuditEvent TO [{0}];" -f $q) @() ("asset tagging's database access: {0} -- given by this update" -f $what))
    }
    & $out 'task' $missing.ToArray() '' @() ("WARNING: asset tagging's database access: {0} -- this update may not give it on this install, so the asset tagging run stops at its settings check. One time, as the SQL server's admin (or through the Support app): setup\Grant-SITaggingDatabase.ps1 -Apply" -f $what)
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
# #1050 (live 2026-11-01, a ring 2 install: a FILTERED index on 17.2 M rows ran over two hours inside an update that said
# "up to 10 min"): a filtered index cannot be resumable, so it cannot pause at the budget. It is started in an update ONLY
# when its estimate (the table's pages at this database's measured rate, engine\_shared\SI-IndexBuild.ps1) fits the minutes
# left; otherwise it WAITS (cfg.IndexBuild) and is built in an idle window by the index build job caj-si-index-build (#1111).
# Every build runs on its own connection with the install's lock beaten while it runs (-Beat).
$script:SIProSchemaLargeTableRows = 1000000
$script:SIProSchemaIndexBudgetMinutes = @{ Applied = 10; Current = 40 }
# #1112: how long a deferred build's table locks wait behind the readers before they queue as before (Azure SQL only)
$script:SIProSchemaLowPriorityMinutes = 5
$siIxBuildFile = [IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-IndexBuild.ps1')
if (Test-Path -LiteralPath $siIxBuildFile) { . $siIxBuildFile }

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

# ---- CODE OBJECTS THAT ARE ALREADY CURRENT ARE NOT RE-CREATED (#1112, live 2026-11-05) ----------------------------------
# Every file runs in ONE transaction, and a schema file re-creates its procedures, functions and triggers with an unconditional
# CREATE OR ALTER on every applied update. An ALTER takes a schema-modification lock that is held to the END of the file's
# transaction -- and a trigger's lock is on its TABLE: cfg.TR_AccessAssignment_Journal locked cfg.AccessAssignment (read at
# every sign-in), cfg.TR_Setting_Journal cfg.Setting, cfg.TR_Template_Journal cfg.Template ... for as long as the settings
# file's 308 batches ran. At internal the web app's probes and a sign-in waited behind them (45 s). So, at run time (the file
# and its fingerprint are unchanged): an EXEC (N'CREATE OR ALTER PROCEDURE | TRIGGER | scalar FUNCTION <name> ...') runs only
# when the object's stored text differs from the file's -- compared byte for byte (a binary collation: a change in case is a
# change). A new object, a changed one, or a text that cannot be read (no right to see it: NULL) is created exactly as
# before. VIEWS and table-valued functions are always re-created: their stored column list is refreshed only by the ALTER.
function Add-SIProSchemaModuleGuards {
    <#
        PURE. -Sql with every EXEC ('CREATE OR ALTER PROCEDURE|PROC|TRIGGER|FUNCTION <schema>.<name> ...') -- a single string
        literal, outside comments and other strings, a function only when it returns a scalar -- preceded by
        IF ISNULL(SUBSTRING(OBJECT_DEFINITION(<name>), CHARINDEX(N'<name>', <that text>), ...), N'') COLLATE Latin1_General_BIN2
           <> N'<the file's text from the name on>' COLLATE Latin1_General_BIN2
        so the EXEC runs only when the object is missing or different. Everything else is returned as it was.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Sql)
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
    $rx = "(?i)\bEXEC(?:UTE)?\s*\(\s*(N?)'(\s*CREATE\s+OR\s+ALTER\s+(PROCEDURE|PROC|TRIGGER|FUNCTION)\s+((?:\[[^\]']+\]|\w+)\.(?:\[[^\]']+\]|\w+)))"
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($m in [regex]::Matches($Sql, $rx)) {
        if ($mask[$m.Index]) { continue }                  # inside a comment or a string: not a statement
        $q = $m.Groups[2].Index - 1                        # the opening quote
        $at = $strStart.IndexOf($q); if ($at -lt 0) { continue }
        $close = $strEnd[$at]
        if ($close -ge $n -or $Sql[$close] -ne "'") { continue }
        $after = $Sql.Substring($close + 1, [Math]::Min(20, $n - $close - 1))
        if ($after -notmatch '^\s*\)') { continue }       # EXEC ('...' + ...) or anything but one literal: left as it is
        $literal = $Sql.Substring($q + 1, $close - $q - 1)
        if ($m.Groups[3].Value -match '(?i)^FUNCTION$' -and $literal -match '(?is)\bRETURNS\s+(?:@\w+\s+)?TABLE\b') { continue }
        # compared FROM THE NAME ON: SQL Server stores a CREATE OR ALTER's text with "OR ALTER" blanked out (the REAL SQL test
        # of SIv3-WebDuringUpdate found it), so the head is never compared -- the kind cannot change under the same name anyway
        $tail = $Sql.Substring($m.Groups[4].Index, $close - $m.Groups[4].Index)
        $hits.Add([pscustomobject]@{ At = $m.Index; Name = $m.Groups[4].Value; Tail = $tail })    }
    if (-not $hits.Count) { return $Sql }
    $sb = New-Object System.Text.StringBuilder $Sql
    foreach ($h in @($hits | Sort-Object At -Descending)) {
        $def = "OBJECT_DEFINITION(OBJECT_ID(N'{0}'))" -f $h.Name
        $guard = "IF ISNULL(SUBSTRING({0}, CHARINDEX(N'{1}' COLLATE Latin1_General_BIN2, {0}), 2147483647), N'') COLLATE Latin1_General_BIN2 <> N'{2}' COLLATE Latin1_General_BIN2`n" -f $def, $h.Name, $h.Tail
        [void]$sb.Insert($h.At, $guard)
    }
    $sb.ToString()
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
-- #1112: CREATE INDEX ... WAIT_AT_LOW_PRIORITY -- Azure SQL Database (5) and Managed Instance (8)
SELECT N'lowpriority', CONVERT(nvarchar(300), CASE WHEN CONVERT(int, SERVERPROPERTY('EngineEdition')) IN (5, 8) THEN N'1' ELSE N'0' END) COLLATE DATABASE_DEFAULT, N'', CONVERT(bigint, 0)
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
    $st = [pscustomobject]@{ Resumable = $false; Large = @{}; Indexes = @{}; Builds = @{}; LowPriority = $false }
    foreach ($r in $rows) {
        $get = { param($k) if ($r -is [System.Collections.IDictionary]) { $r[$k] } else { $r.$k } }
        $k = [string](& $get 'K'); $a = [string](& $get 'A'); $b = [string](& $get 'B')
        switch ($k) {
            'edition' { $st.Resumable = @('3', '5', '8') -contains $a }
            'lowpriority' { $st.LowPriority = ($a -eq '1') }
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
    <# PURE. The statement for one deferred index: RESUME a paused build, else CREATE it ONLINE + RESUMABLE, both with MAX_DURATION.
       A FILTERED index (CREATE ... WHERE ...) is built ONLINE only: SQL Server refuses RESUMABLE for it ("The RESUMABLE option
       is not supported for creating a filtered index", seen 2026-10-29 on a Developer edition, the same engine as Azure SQL),
       and MAX_DURATION needs RESUMABLE -- with both, such an index was never built and stayed pending on every update. It
       still runs outside the schema's transaction and keeps the table readable and writable while it builds. #>
    param([Parameter(Mandatory)]$Index, [string]$BuildState = '', [Parameter(Mandatory)][int]$Minutes, [switch]$LowPriority)
    $m = [Math]::Max(1, $Minutes)
    # #1112 (live 2026-11-05: the web app's requests queued behind the update's locks): -LowPriority (Azure SQL Database /
    # Managed Instance, where CREATE INDEX takes it) -- the build's short table locks at its start and its end wait BEHIND the
    # web app's and the engine's queries for up to $script:SIProSchemaLowPriorityMinutes, then as before (ABORT_AFTER_WAIT =
    # NONE: never a lost build). Without it a build waiting for its lock queued every new reader of the table behind it.
    $lp = 'WAIT_AT_LOW_PRIORITY (MAX_DURATION = {0} MINUTES, ABORT_AFTER_WAIT = NONE)' -f [int]$script:SIProSchemaLowPriorityMinutes
    if ($BuildState -eq 'PAUSED') {
        if ($LowPriority) { return ('ALTER INDEX {0} ON {1} RESUME WITH (MAX_DURATION = {2} MINUTES, {3})' -f $Index.Name, $Index.Table, $m, $lp) }
        return ('ALTER INDEX {0} ON {1} RESUME WITH (MAX_DURATION = {2} MINUTES)' -f $Index.Name, $Index.Table, $m)
    }
    $stmt = $Index.Statement.TrimEnd(';').TrimEnd()
    $online = if ($LowPriority) { 'ONLINE = ON ({0})' -f $lp } else { 'ONLINE = ON' }
    if (Test-SIProSchemaIndexFiltered -Index $Index) { return ('{0} WITH ({1})' -f $stmt, $online) }
    '{0} WITH ({1}, RESUMABLE = ON, MAX_DURATION = {2} MINUTES)' -f $stmt, $online, $m
}

function Test-SIProSchemaLowPriority {
    <# PURE. Does this database take WAIT_AT_LOW_PRIORITY on CREATE INDEX (Get-SIProSchemaIndexState's 'lowpriority' row)?
       Azure SQL Database (engine edition 5) and Managed Instance (8) -- a boxed Enterprise / Developer (3) may be a version
       before SQL Server 2022 and is left as before; a state without the row (an older reader) = no. #>
    param($State)
    [bool]($State -and $State.PSObject.Properties['LowPriority'] -and $State.LowPriority)
}

function Test-SIProSchemaIndexFiltered {
    <# PURE. Is -Index (Get-SIProSchemaIndexStatements) a filtered index -- a WHERE after its column list? #>
    param([Parameter(Mandatory)]$Index)
    [bool]([string]$Index.Statement -match '(?is)^\s*CREATE\b.*?\bON\b.*?\)\s*(INCLUDE\s*\([^)]*\)\s*)?WHERE\b')
}

function Invoke-SIProSchemaIndexStep {
    <#
        Builds the deferred indexes, in file order, inside -BudgetMinutes. -Run (statement, beat): runs ONE statement outside
        any transaction (the runner's '#index' mode, or the plain invoke) and calls the beat while it runs. Per index: there =
        built; RUNNING elsewhere = pending; PAUSED = resumed; else created. A build that ends paused (its MAX_DURATION) is
        pending; any other error is a WARNING and pending -- never a failed update. When the budget is spent the rest stay
        pending. NEVER throws.
        #1050: a FILTERED index (it cannot pause) is started only when -Estimate { param($Index) } -> @{ Known; Minutes; Pages;
        Source } fits the minutes left; otherwise it WAITS (-Record 'waiting': cfg.IndexBuild, built later in an idle window)
        with one plain line. -Force: the window's one-time build after 7 days (the estimate does not hold it back). -Record
        { param($What, $Index, $Data) } -- 'waiting' / 'building' / 'built' / 'failed' / 'rate'; default: nothing recorded.
        -Beat { param($What) }: the install's lock, while a build runs. Returns @{ Built; Pending; Waiting; Warnings; Lines }.
    #>
    param([object[]]$Deferred = @(), [Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][scriptblock]$Run, [int]$BudgetMinutes = 10,
          [scriptblock]$Log = { param($m) }, [datetime]$StartUtc = [datetime]::UtcNow, [scriptblock]$Now = { [datetime]::UtcNow },
          [scriptblock]$Estimate, [scriptblock]$Record = { param($What, $Index, $Data) }, [scriptblock]$Beat = { param($What) }, [switch]$Force)
    $res = [pscustomobject]@{ Built = @(); Pending = @(); Waiting = @(); Warnings = @(); Lines = @() }
    $built = New-Object System.Collections.Generic.List[string]; $pending = New-Object System.Collections.Generic.List[string]; $warn = New-Object System.Collections.Generic.List[string]
    $waiting = New-Object System.Collections.Generic.List[string]; $lines = New-Object System.Collections.Generic.List[string]
    $rec = { param($w, $i, $x) try { $null = & $Record $w $i $x } catch { } }
    foreach ($d in @($Deferred | Where-Object { $null -ne $_ })) {
        $key = ('{0}|{1}' -f $d.Table, $d.Name).ToLowerInvariant()
        $st = $null; try { $st = Get-SIProSchemaIndexState -Invoke $Invoke -LargeTableRows ([long]::MaxValue) } catch { $warn.Add(('{0}: the database could not be read ({1})' -f $d.Name, $_.Exception.Message)); $pending.Add($d.Name); continue }
        $filtered = Test-SIProSchemaIndexFiltered -Index $d
        if ($st.Indexes.ContainsKey($key)) { $built.Add($d.Name); if ($filtered) { & $rec 'built' $d $null }; continue }
        $b = $st.Builds[$key]
        if ($b -and $b.State -eq 'RUNNING') { & $Log ('  index {0} on {1}: being built elsewhere ({2}%) -- pending' -f $d.Name, $d.Table, $b.Percent); $pending.Add($d.Name); continue }
        $rem = $BudgetMinutes - ((& $Now) - $StartUtc).TotalMinutes
        if ($rem -lt 1 -and -not $Force) { $pending.Add($d.Name); continue }
        $left = [int][Math]::Max(1, [Math]::Floor($rem + 0.05))  # whole minutes (a few seconds of reading do not cost one)
        # #1050: a filtered index runs to its end -- started only when its estimate fits what this update has left
        $est = $null
        if ($filtered -and -not $b) {
            $est = if ($Estimate) { try { & $Estimate $d } catch { $null } } else { $null }
            if (-not $est) { $est = [pscustomobject]@{ Known = $false; Minutes = 0; Pages = 0; Source = 'no estimate was made' } }
            if (-not $Force -and (-not $est.Known -or [int]$est.Minutes -gt $left)) {
                $line = Get-SIIndexWaitText -Name $d.Name -Table $d.Table -Estimate $est -BudgetMinutes $left
                & $Log ('  ' + $line); $lines.Add($line); $waiting.Add($d.Name)
                & $rec 'waiting' $d ([pscustomobject]@{ Statement = (Get-SIProSchemaIndexBuildSql -Index $d -Minutes $left); Estimate = $est; Why = $line })
                continue
            }
        }
        $sql = Get-SIProSchemaIndexBuildSql -Index $d -BuildState $(if ($b) { $b.State } else { '' }) -Minutes $left -LowPriority:(Test-SIProSchemaLowPriority -State $st)
        $how = if ($b) { "resumed at $($b.Percent)%" }
               elseif ($filtered -and $est -and $est.Known) { 'built online (a filtered index cannot pause: about {0} at this database''s rate, {1})' -f (Format-SIIndexDuration ([int]$est.Minutes)), $est.Source }
               elseif ($filtered) { 'built online (a filtered index cannot pause: its time is not known -- built now, once)' }
               else { 'built online, resumable' }
        & $Log ('  index {0} on {1}: {2} (up to {3} min)' -f $d.Name, $d.Table, $how, $(if ($filtered -and $est -and $est.Known) { [int]$est.Minutes } else { $left }))
        if ($filtered) { & $rec 'building' $d ([pscustomobject]@{ Estimate = $est }) }
        $say = [pscustomobject]@{ Last = [datetime]::UtcNow }
        $ixName = $d.Name; $beatOuter = $Beat; $logOuter = $Log
        $beatThis = {
            param($Minutes)
            try { $null = & $beatOuter ('building index {0} ({1} min)' -f $ixName, $Minutes) } catch { }
            if (([datetime]::UtcNow - $say.Last).TotalMinutes -ge 5) { $say.Last = [datetime]::UtcNow; & $logOuter ('  index {0}: still building ({1} min so far)' -f $ixName, $Minutes) }
        }.GetNewClosure()
        $err = $null; $sw = [Diagnostics.Stopwatch]::StartNew()
        try { $null = & $Run $sql $beatThis } catch { $err = $_.Exception.Message }
        $sw.Stop()
        $after = $null; try { $after = Get-SIProSchemaIndexState -Invoke $Invoke -LargeTableRows ([long]::MaxValue) } catch { }
        if ($after -and $after.Indexes.ContainsKey($key)) {
            $built.Add($d.Name); & $Log ('  index {0}: built ({1:N0} s)' -f $d.Name, $sw.Elapsed.TotalSeconds)
            # a create that ran from start to end measures this database's rate (a resumed one does not: part of it ran before)
            if (-not $b -and $sw.Elapsed.TotalSeconds -ge 60) { & $rec 'rate' $d ([pscustomobject]@{ Seconds = $sw.Elapsed.TotalSeconds }) }
            if ($filtered -or $b) { & $rec 'built' $d $null }
            continue
        }
        $pb = if ($after) { $after.Builds[$key] } else { $null }
        if ($pb) {
            # #1111: a resumable build paused at the update's time is RECORDED 'paused' -- the index build job resumes it in the
            # next idle window (the next update still resumes it too, within its own time)
            $pending.Add($d.Name); & $Log ('  index {0}: paused at {1}% -- it resumes in the next idle window (or the next update)' -f $d.Name, $pb.Percent)
            & $rec 'paused' $d ([pscustomobject]@{ Statement = (Get-SIProSchemaIndexBuildSql -Index $d -Minutes $left); Why = ('paused at {0}% at the end of the update''s index time' -f $pb.Percent) })
            continue
        }
        $pending.Add($d.Name)
        $w = '{0} on {1} was not built ({2}) -- the next update tries again; the release works without it' -f $d.Name, $d.Table, $(if ($err) { $err } else { 'no error, not there' })
        $warn.Add($w)
        if ($filtered) { & $rec 'failed' $d ([pscustomobject]@{ Why = $w }) }
    }
    $res.Built = $built.ToArray(); $res.Pending = $pending.ToArray(); $res.Waiting = $waiting.ToArray(); $res.Warnings = $warn.ToArray(); $res.Lines = $lines.ToArray()
    $res
}

function New-SIProSchemaIndexRecorder {
    <#
        #1050: the -Record of the index step on a real database: 'waiting' / 'building' / 'built' / 'failed' -> the index's
        cfg.IndexBuild row (Save-SIIndexBuildRow); 'rate' -> one measured build into this database's rate (the table's pages /
        the seconds). Never throws (a row that cannot be written is said once in -Log).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$Log = { param($m) }, [string]$By = 'caj-si-updater')
    $inv = $Invoke; $lg = $Log; $who = $By
    # the functions, captured (a closure's own scope does not see functions dot-sourced into the updater's database step)
    $fSave = ${function:Save-SIIndexBuildRow}; $fPages = ${function:Get-SIIndexTablePages}; $fRate = ${function:Add-SIIndexBuildRateSample}
    {
        param($What, $Index, $Data)
        if (-not $fSave) { return }
        $est = if ($Data -and $Data.PSObject.Properties['Estimate']) { $Data.Estimate } else { $null }
        switch ($What) {
            'rate' {
                $pg = & $fPages -Invoke $inv -Table $Index.Table
                if ($pg -and (& $fRate -Invoke $inv -Pages $pg.Pages -Seconds ([double]$Data.Seconds) -By $who)) { & $lg ('  index {0}: this database''s build rate recorded ({1:N0} pages in {2:N0} s)' -f $Index.Name, $pg.Pages, [double]$Data.Seconds) }
            }
            default {
                $ok = & $fSave -Invoke $inv -Table $Index.Table -Index $Index.Name -State $What `
                        -Statement $(if ($Data -and $Data.PSObject.Properties['Statement']) { [string]$Data.Statement } else { '' }) `
                        -Pages $(if ($est -and $est.Pages) { [long]$est.Pages } else { $null }) -EstMinutes $(if ($est -and $est.Known) { [int]$est.Minutes } else { $null }) `
                        -Source $(if ($est) { [string]$est.Source } else { '' }) -Why $(if ($Data -and $Data.PSObject.Properties['Why']) { [string]$Data.Why } else { '' }) -By $who
                if (-not $ok -and $What -eq 'waiting') { & $lg ('  WARNING: index {0}: why it waits could not be recorded -- the next update records it again' -f $Index.Name) }
            }
        }
    }.GetNewClosure()
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
    # #1050: the build that beats while it runs, captured (this closure's own scope does not see a function dot-sourced into
    # the updater's database step; a captured one runs where it was defined)
    $buildCmd = ${function:Invoke-SIIndexBuildCommand}; $beatSec = if ($script:SIIndexBuild) { [int]$script:SIIndexBuild.BeatSeconds } else { 30 }
    {
        param([string]$Name, [string[]]$Batches, [scriptblock]$Beat)
        $cn = New-Object System.Data.SqlClient.SqlConnection($cs)
        $cn.AccessToken = [string](& $GetToken)
        $cn.Open()
        $tx = $null
        try {
            if ($Name -eq '#index') {
                # a deferred index (ONLINE, RESUMABLE): never inside a transaction -- a resumable build cannot be. #1050: run so
                # that -Beat is called while it builds (the install's lock never looks abandoned during a long build)
                foreach ($b in $Batches) {
                    if ($buildCmd) { $null = & $buildCmd -Connection $cn -Sql $b -Beat $Beat -BeatSeconds $beatSec }
                    else { $cmd = $cn.CreateCommand(); $cmd.CommandText = $b; $cmd.CommandTimeout = $timeout; [void]$cmd.ExecuteNonQuery() }
                }
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
        -Invoke (sql, params, mode): the database; -RunFile (name, batches[, beat]): optional, a one-connection transaction.
        Returns @{ Action = applied | noop | refused | failed; Hash; Files; Applied; FailedFile; Reason; Findings; Plan }.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][scriptblock]$Invoke, [scriptblock]$RunFile, [string[]]$Names,
          [string]$ExtraFingerprint = '', [switch]$SkipWhenRecorded, [scriptblock]$Log, [long]$LargeTableRows = $script:SIProSchemaLargeTableRows,
          # a RUNNING index build on a table a file changes is waited for this long, never aborted (seams: -Sleep)
          [int]$RunningWaitMinutes = $script:SIProSchemaRunningWaitMinutes, [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
          # #1050: -Beat { param($What) } while an index builds (the updater: the install's lock); -IndexEstimate / -IndexRecord:
          # seams for the estimate of a filtered index and the record of one that waits (default: the real database)
          [scriptblock]$Beat, [scriptblock]$IndexEstimate, [scriptblock]$IndexRecord,
          # #1112: -Window { param([bool]$On) } -- told when the files' transactions start ($true) and when they have all ended
          # ($false; also on a failure): the updater marks the install's lock so the web app answers "being updated" meanwhile.
          # Never around a no-op, never around the deferred index builds (they run ONLINE, outside the transactions).
          [scriptblock]$Window)
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
            $one = if ($d.Count) { Remove-SIProSchemaDeferredIndexes -Sql $b -Deferred $d } else { $b }
            # #1112: a procedure / trigger / scalar function that is already current is not re-created (no table lock held to commit)
            $bs.Add((Add-SIProSchemaModuleGuards -Sql $one))
        }
        $batchesOf[$f.Name] = $bs.ToArray()
    }
    $runIx = if ($RunFile) { { param($s, $b) & $RunFile '#index' @($s) $b } } else { { param($s, $b) & $Invoke $s @{} 'nonquery' } }
    # #1050: the estimate of a filtered index (this database's measured rate) and the record of one that waits -- on the real
    # database unless the caller brings its own (tests)
    if (-not $IndexEstimate -and (Get-Command -Name New-SIIndexBuildEstimator -ErrorAction SilentlyContinue)) { $IndexEstimate = New-SIIndexBuildEstimator -Invoke $Invoke }
    if (-not $IndexRecord -and (Get-Command -Name New-SIProSchemaIndexRecorder -ErrorAction SilentlyContinue) -and (Get-Command -Name Save-SIIndexBuildRow -ErrorAction SilentlyContinue)) { $IndexRecord = New-SIProSchemaIndexRecorder -Invoke $Invoke -Log $Log }
    if (-not $IndexRecord) { $IndexRecord = { param($What, $Index, $Data) } }
    if (-not $Beat) { $Beat = { param($What) } }
    $ixStep = { param([bool]$current)
        if (-not $deferred.Count) { return $null }
        $budget = Get-SIProSchemaIndexBudget -Invoke $Invoke -SchemaCurrent $current
        if (-not $RunFile) { $budget = [Math]::Min($budget, 1) }    # the plain invoke's statement timeout is short: one minute per build, it resumes
        & $Log ('  indexes on large tables: {0} built outside the schema transaction, up to {1} min this update -- a filtered one only when its estimate fits ({2})' -f $deferred.Count, $budget, (($deferred | ForEach-Object { $_.Name }) -join ', '))
        $r = Invoke-SIProSchemaIndexStep -Deferred $deferred.ToArray() -Invoke $Invoke -Run $runIx -BudgetMinutes $budget -Log $Log -Estimate $IndexEstimate -Record $IndexRecord -Beat $Beat
        foreach ($w in @($r.Warnings)) { & $Log ('  WARNING: index {0}' -f $w) }
        $r
    }
    $ixText = { param($r)
        $t = ''
        if ($r -and @($r.Pending).Count) { $t += '; {0} index(es) on large tables still being built -- the next update goes on with them ({1})' -f @($r.Pending).Count, (@($r.Pending) -join ', ') }
        if ($r -and @($r.Waiting).Count) { $t += '; {0} index(es) on large tables wait for an idle window (they do not fit an update; the release works without them): {1}' -f @($r.Waiting).Count, (@($r.Waiting) -join ', ') }
        if (-not $t -and $r -and @($r.Built).Count) { $t = '; {0} index(es) on large tables built' -f @($r.Built).Count }
        $t }
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
    # #1112: the window in which the files' transactions run (the web app answers "being updated"); always closed again
    $win = { param([bool]$on) if ($Window) { try { $null = & $Window $on } catch { & $Log ('  (the update window could not be marked: {0})' -f $_.Exception.Message) } } }
    & $win $true
    try {
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
    } finally { & $win $false }
    # the deferred indexes, after the files are committed (their columns are there now) -- never a failed update
    $ix = & $ixStep $false
    $o = & $out 'applied' ('{0} schema file(s) applied: {1}{2}' -f $done.Count, ($done -join ', '), (& $ixText $ix)) $done.ToArray() '' @()
    $o | Add-Member -NotePropertyName Indexes -NotePropertyValue $ix -Force
    $o
}
