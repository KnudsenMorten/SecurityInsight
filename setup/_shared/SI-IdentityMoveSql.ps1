#Requires -Version 5.1
<#
    SecurityInsight -- THE IDENTITY MOVE's SQL (framework §5.5 names, §12.11c "THE IDENTITY MOVE"). PURE builders only, no
    I/O and no other file: the identity move (setup\_shared\SI-IdentityMove.ps1) and the database setup job (caj-si-dbinit,
    setup\_shared\SI-DbInitJob.ps1, which runs them as a member of the SQL admin group) both load this one file, so the
    statements that copy an identity's database rights -- and the one that drops the old user -- exist once.

    THE RULE THESE CARRY (owner: never lose SQL access): the new identity's user is made from its client id (WITH SID,
    TYPE = E; never a directory lookup, never a placeholder SID), it gets exactly the old user's roles and explicit
    permissions, and the old user is dropped only by Get-SIIdentityMoveSqlDropSql AFTER the caller has read the new user
    back holding every one of them (Test-SIIdentityMoveSqlCovered). The server's Entra administrator is a server-level
    principal and is never named by any of these statements.
    PS 5.1 and 7.
#>

function ConvertTo-SIMoveSid {
    <# PURE. The SQL SID literal of an Entra client id (the SI way: CREATE USER ... WITH SID, TYPE = E). #>
    param([Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$ClientId)
    '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function ConvertTo-SIMoveSqlName {
    <# PURE. [name] with ] doubled. #>
    param([Parameter(Mandatory)][string]$Name)
    '[' + $Name.Replace(']', ']]') + ']'
}

function ConvertTo-SIMoveSqlText {
    <# PURE. N'text' with ' doubled; NULL for $null. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [DBNull]) { return 'NULL' }
    "N'" + ([string]$Value).Replace("'", "''") + "'"
}

function Get-SIIdentityMoveSqlReadSql {
    <# PURE. ONE read of a database: the old and new users (by SID), their database roles, their explicit permissions and the
       schemas they own -- one row set (Kind user | role | perm | owns; Who old | new). #>
    param([Parameter(Mandatory)][string]$OldClientId, [string]$NewClientId)
    $o = ConvertTo-SIMoveSid $OldClientId
    # No new identity yet: @new = @old, so only the old identity's rows come back. NEVER a placeholder SID -- 0x00 is the
    # SID of the database's guest user, and a plan read that way granted guest the old identity's rights (live at an install
    # 2026-11-04; guest had no CONNECT, the grants were removed and read back).
    $n = if ($NewClientId) { ConvertTo-SIMoveSid $NewClientId } else { $o }
    @"
SET NOCOUNT ON;
DECLARE @old varbinary(85) = $o, @new varbinary(85) = $n;
-- every text column in one collation: the catalog views' columns differ (Latin1_General_CI_AS_KS_WS vs the database's), and
-- a UNION ALL across them is refused without it (seen live 2026-11-04)
SELECT N'user' AS Kind, CASE WHEN dp.sid = @old THEN N'old' ELSE N'new' END AS Who, dp.name COLLATE DATABASE_DEFAULT AS Name,
       CAST(NULL AS nvarchar(400)) AS Securable, CAST(NULL AS nvarchar(128)) AS Permission, CAST(NULL AS nvarchar(60)) AS State,
       CONVERT(nvarchar(200), dp.sid, 1) COLLATE DATABASE_DEFAULT AS Sid
  FROM sys.database_principals dp WHERE dp.sid IN (@old, @new)
UNION ALL
SELECT N'role', CASE WHEN m.sid = @old THEN N'old' ELSE N'new' END, r.name COLLATE DATABASE_DEFAULT, NULL, NULL, NULL, NULL
  FROM sys.database_role_members rm
  JOIN sys.database_principals r ON r.principal_id = rm.role_principal_id
  JOIN sys.database_principals m ON m.principal_id = rm.member_principal_id
 WHERE m.sid IN (@old, @new)
UNION ALL
SELECT N'perm', CASE WHEN g.sid = @old THEN N'old' ELSE N'new' END, p.class_desc COLLATE DATABASE_DEFAULT,
       CASE WHEN p.minor_id <> 0 THEN NULL
            WHEN p.class = 0 THEN N''
            WHEN p.class = 1 THEN N'OBJECT::' + QUOTENAME(OBJECT_SCHEMA_NAME(p.major_id)) + N'.' + QUOTENAME(OBJECT_NAME(p.major_id))
            WHEN p.class = 3 THEN N'SCHEMA::' + QUOTENAME(SCHEMA_NAME(p.major_id))
            ELSE NULL END COLLATE DATABASE_DEFAULT,
       p.permission_name COLLATE DATABASE_DEFAULT, p.state_desc COLLATE DATABASE_DEFAULT, NULL
  FROM sys.database_permissions p JOIN sys.database_principals g ON g.principal_id = p.grantee_principal_id
 WHERE g.sid IN (@old, @new)
UNION ALL
SELECT N'owns', CASE WHEN o.sid = @old THEN N'old' ELSE N'new' END, s.name COLLATE DATABASE_DEFAULT, NULL, NULL, NULL, NULL
  FROM sys.schemas s JOIN sys.database_principals o ON o.principal_id = s.principal_id
 WHERE o.sid IN (@old, @new);
"@
}

function Get-SIIdentityMoveSqlCopy {
    <#
        PURE. From one database's read (Get-SIIdentityMoveSqlReadSql rows): the statements that give the NEW identity exactly
        the old user's database roles and explicit permissions -- its contained user first (WITH SID = its client id,
        TYPE = E: the SI way, no directory lookup). CONNECT comes with the user. Returns @{ Sql ('' = nothing to do);
        Items (what); Unsupported (a permission this cannot copy -> the caller stops); OldUser; NewUser }.
    #>
    param([object[]]$Rows = @(), [Parameter(Mandatory)][string]$NewName, [Parameter(Mandatory)][string]$NewClientId)
    $get = { param($r, $n) if ($null -eq $r) { return $null }; if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($n)) { return $r[$n] }; return $null }; $p = $r.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    $norm = @($Rows | Where-Object { $null -ne $_ } | ForEach-Object {
        [pscustomobject]@{ Kind = [string](& $get $_ 'Kind'); Who = [string](& $get $_ 'Who'); Name = [string](& $get $_ 'Name'); Securable = (& $get $_ 'Securable')
                           Permission = [string](& $get $_ 'Permission'); State = [string](& $get $_ 'State'); Sid = [string](& $get $_ 'Sid') } })
    $old = @($norm | Where-Object { $_.Who -eq 'old' }); $new = @($norm | Where-Object { $_.Who -eq 'new' })
    $oldUser = @($old | Where-Object { $_.Kind -eq 'user' })[0]; $newUser = @($new | Where-Object { $_.Kind -eq 'user' })[0]
    $items = New-Object System.Collections.Generic.List[string]; $unsupported = New-Object System.Collections.Generic.List[string]
    $sql = New-Object System.Text.StringBuilder
    if (-not $oldUser) { return [pscustomobject]@{ Sql = ''; Items = @(); Unsupported = @(); OldUser = ''; NewUser = $(if ($newUser) { [string]$newUser.Name } else { '' }) } }
    $target = if ($newUser) { [string]$newUser.Name } else { $NewName }
    # the new identity must be a real one: its client id read back from Azure (a GUID), never empty or a placeholder
    if ("$NewClientId" -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        return [pscustomobject]@{ Sql = ''; Items = @(); Unsupported = @("the new identity's client id is not known (read back) -- nothing is copied"); OldUser = [string]$oldUser.Name; NewUser = '' }
    }
    # an existing "new" user must carry exactly the new identity's SID (the read matched it by that SID)
    if ($newUser -and $newUser.Sid -and $newUser.Sid -ne (ConvertTo-SIMoveSid $NewClientId)) {
        return [pscustomobject]@{ Sql = ''; Items = @(); Unsupported = @("the database user '$($newUser.Name)' does not carry the new identity's SID -- nothing is copied"); OldUser = [string]$oldUser.Name; NewUser = [string]$newUser.Name }
    }
    # a built-in principal is never a target (a wrong read once named guest, live 2026-11-04)
    if ($target -in @('guest', 'dbo', 'public', 'sys', 'INFORMATION_SCHEMA') -or $target -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$') {
        return [pscustomobject]@{ Sql = ''; Items = @(); Unsupported = @("the new user would be '$target', which is not the new identity -- nothing is copied"); OldUser = [string]$oldUser.Name; NewUser = $target }
    }
    $q = ConvertTo-SIMoveSqlName $target
    if (-not $newUser) {
        [void]$sql.AppendLine(('CREATE USER {0} WITH SID = {1}, TYPE = E;' -f $q, (ConvertTo-SIMoveSid $NewClientId)))
        $items.Add("user $target (from its client id)")
    }
    foreach ($r in @($old | Where-Object { $_.Kind -eq 'role' })) {
        if (@($new | Where-Object { $_.Kind -eq 'role' -and $_.Name -eq $r.Name }).Count) { continue }
        [void]$sql.AppendLine(('ALTER ROLE {0} ADD MEMBER {1};' -f (ConvertTo-SIMoveSqlName ([string]$r.Name)), $q))
        $items.Add("role $($r.Name)")
    }
    foreach ($p in @($old | Where-Object { $_.Kind -eq 'perm' })) {
        $perm = [string]$p.Permission; $state = [string]$p.State
        if ($perm -eq 'CONNECT' -and [string]$p.Name -eq 'DATABASE') { continue }
        if ($null -eq $p.Securable -or $p.Securable -is [DBNull] -or $perm -notmatch '^[A-Z ]{3,60}$' -or $state -notin 'GRANT', 'DENY', 'GRANT_WITH_GRANT_OPTION') {
            $unsupported.Add(('{0} {1} on {2}' -f $state, $perm, [string]$p.Name)); continue
        }
        $sec = [string]$p.Securable
        if (@($new | Where-Object { $_.Kind -eq 'perm' -and [string]$_.Securable -eq $sec -and [string]$_.Permission -eq $perm -and [string]$_.State -eq $state }).Count) { continue }
        # a schema the new user OWNS: the owner holds every right on it, and SQL records no grant to its owner (the web
        # identity's sign-in front made the signin schema, live 2026-11-06) -- covered, nothing to copy
        if ($state -ne 'DENY' -and $sec -like 'SCHEMA::*' -and @($new | Where-Object { $_.Kind -eq 'owns' -and ('SCHEMA::' + (ConvertTo-SIMoveSqlName ([string]$_.Name))) -eq $sec }).Count) { continue }
        $on = if ($sec) { " ON $sec" } else { '' }
        $verb = if ($state -eq 'DENY') { 'DENY' } else { 'GRANT' }
        $tail = if ($state -eq 'GRANT_WITH_GRANT_OPTION') { ' WITH GRANT OPTION' } else { '' }
        [void]$sql.AppendLine(('{0} {1}{2} TO {3}{4};' -f $verb, $perm, $on, $q, $tail))
        $items.Add(('{0} {1}{2}' -f $verb, $perm, $on))
    }
    $text = $sql.ToString()
    if ($text) { $text = "SET XACT_ABORT ON;`nBEGIN TRAN;`n" + $text + "COMMIT;`n" }
    [pscustomobject]@{ Sql = $text; Items = $items.ToArray(); Unsupported = $unsupported.ToArray(); OldUser = [string]$oldUser.Name; NewUser = $(if ($newUser) { [string]$newUser.Name } else { '' }) }
}

function Test-SIIdentityMoveSqlCovered {
    <#
        PURE. THE DROP GATE (never lose SQL access): may the old identity's user in this database be dropped? Only when the
        new identity's user EXISTS (by its SID) and the copy from old to new is EMPTY -- it already holds every role and every
        explicit permission the old one holds, nothing unsupported. -Rows: one read (Get-SIIdentityMoveSqlReadSql with
        old = the one to drop, new = the one that stays). Returns @{ Drop; Why; OldUser }. No old user = nothing to drop.
    #>
    param([object[]]$Rows = @(), [Parameter(Mandatory)][string]$KeepName, [Parameter(Mandatory)][string]$KeepClientId)
    $c = Get-SIIdentityMoveSqlCopy -Rows $Rows -NewName $KeepName -NewClientId $KeepClientId
    if (-not $c.OldUser) { return [pscustomobject]@{ Drop = $false; Why = 'the old identity has no user here'; OldUser = '' } }
    if (-not $c.NewUser) { return [pscustomobject]@{ Drop = $false; Why = ('the new identity {0} has no user here yet -- the old user {1} is kept' -f $KeepName, $c.OldUser); OldUser = $c.OldUser } }
    if (@($c.Unsupported).Count) { return [pscustomobject]@{ Drop = $false; Why = ('the old user {0} holds a right this cannot compare ({1}) -- it is kept' -f $c.OldUser, (@($c.Unsupported) -join '; ')); OldUser = $c.OldUser } }
    if ($c.Sql) { return [pscustomobject]@{ Drop = $false; Why = ('the new user {0} does not hold everything the old user {1} holds yet ({2}) -- the old user is kept' -f $c.NewUser, $c.OldUser, (@($c.Items) -join '; ')); OldUser = $c.OldUser } }
    [pscustomobject]@{ Drop = $true; Why = ('the new user {0} holds every right of the old user {1} (read back)' -f $c.NewUser, $c.OldUser); OldUser = $c.OldUser }
}

function Get-SIIdentityMoveSqlModuleNames {
    <# PURE. The procedures SecurityInsight makes WITH EXECUTE AS SELF (by the marker in their text) -- the only modules the
       move re-makes as the new user. Today one: sidata.StatisticsRefreshTable (sql\si-data-schema.sql), made by whoever
       applies the schema -- on an existing install the updater, so it runs as the updater's user. #>
    @('si-statistics-refresh v1')
}

function Get-SIIdentityMoveSqlModuleSql {
    <#
        PURE. #1164 (live 2026-11-10: the old updater user "is set as the execution context of one or more procedures ... and
        cannot be dropped"). ONE batch, run by a database owner (the database setup job, or a Support session) BEFORE the
        drop: every module whose execution context is the OLD user (sys.sql_modules.execute_as_principal_id) --
          * an UNSIGNED procedure SecurityInsight makes (its marker, Get-SIIdentityMoveSqlModuleNames) is made again AS THE NEW
            USER: EXECUTE AS USER = <new>, its own stored text as CREATE OR ALTER (permissions kept: ALTER keeps them), REVERT
            -- then READ BACK in the same transaction: it runs as the new user, its marker is there, its permissions are
            exactly those read before; anything else rolls it back;
          * a SIGNED module (re-making it would lose its signature), one SecurityInsight does not make, or any module when
            the new user is not here: KEPT -- nothing changed.
        Returns rows (Module, Action moved | kept, Why) and a last row (Module = N'', Action = N'left', Why = the number of
        modules still running as the old user). No GRANT, no ADD SIGNATURE, no DROP. -OldSid / -NewSid: SID literals (0x...).
    #>
    param([Parameter(Mandatory)][ValidatePattern('^0x[0-9A-Fa-f]{2,170}$')][string]$OldSid, [Parameter(Mandatory)][ValidatePattern('^0x[0-9A-Fa-f]{2,170}$')][string]$NewSid,
          [string[]]$Markers = (Get-SIIdentityMoveSqlModuleNames))
    $mk = (@($Markers | Where-Object { "$_".Trim() } | ForEach-Object { "SELECT N'{0}'" -f ([string]$_).Replace("'", "''") }) -join ' UNION ALL ')
    if (-not $mk) { $mk = "SELECT CAST(NULL AS nvarchar(200)) WHERE 1 = 0" }
    @"
SET NOCOUNT ON; SET XACT_ABORT ON;
DECLARE @old int = (SELECT principal_id FROM sys.database_principals WHERE sid = $OldSid);
DECLARE @newId int = (SELECT principal_id FROM sys.database_principals WHERE sid = $NewSid);
DECLARE @new sysname = USER_NAME(@newId), @me sysname = USER_NAME();
DECLARE @out TABLE (N int IDENTITY(1, 1), Module nvarchar(400), Action nvarchar(10), Why nvarchar(2000));
DECLARE @marks TABLE (M nvarchar(200));
INSERT @marks (M) $mk;
IF @old IS NOT NULL
BEGIN
    DECLARE @id int, @name nvarchar(400), @t nvarchar(max), @mark nvarchar(200), @before nvarchar(max), @after nvarchar(max), @p int;
    DECLARE mods CURSOR LOCAL FAST_FORWARD FOR SELECT m.object_id FROM sys.sql_modules AS m WHERE m.execute_as_principal_id = @old;
    OPEN mods; FETCH NEXT FROM mods INTO @id;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        SET @name = QUOTENAME(OBJECT_SCHEMA_NAME(@id)) + N'.' + QUOTENAME(OBJECT_NAME(@id));
        SET @t = OBJECT_DEFINITION(@id);
        SET @mark = (SELECT TOP (1) M FROM @marks WHERE CHARINDEX(M, ISNULL(@t, N'')) > 0);
        IF EXISTS (SELECT 1 FROM sys.crypt_properties WHERE major_id = @id AND class = 1)
            INSERT @out (Module, Action, Why) VALUES (@name, N'kept', N'it is signed -- making it again would lose its signature');
        ELSE IF @newId IS NULL
            INSERT @out (Module, Action, Why) VALUES (@name, N'kept', N'the new identity has no user here');
        ELSE IF @mark IS NULL OR OBJECTPROPERTY(@id, N'IsProcedure') <> 1
            INSERT @out (Module, Action, Why) VALUES (@name, N'kept', N'it is not a procedure SecurityInsight makes');
        ELSE
        BEGIN
            -- its own text, as CREATE OR ALTER (ALTER keeps its permissions)
            SET @p = PATINDEX(N'%CREATE%PROC%', @t);
            IF @p = 0 OR PATINDEX(N'%CREATE OR ALTER PROC%', @t) = @p
                SET @p = 0;
            IF @p > 0 SET @t = STUFF(@t, @p, 6, N'CREATE OR ALTER');
            SET @before = ISNULL((SELECT STRING_AGG(CONVERT(nvarchar(max), CONCAT(p.grantee_principal_id, N':', p.permission_name, N':', p.state)), N',') WITHIN GROUP (ORDER BY p.grantee_principal_id, p.permission_name, p.state)
                                  FROM sys.database_permissions AS p WHERE p.class = 1 AND p.major_id = @id), N'');
            BEGIN TRY
                BEGIN TRAN;
                EXECUTE AS USER = @new;
                EXEC (@t);
                REVERT;
                SET @after = ISNULL((SELECT STRING_AGG(CONVERT(nvarchar(max), CONCAT(p.grantee_principal_id, N':', p.permission_name, N':', p.state)), N',') WITHIN GROUP (ORDER BY p.grantee_principal_id, p.permission_name, p.state)
                                     FROM sys.database_permissions AS p WHERE p.class = 1 AND p.major_id = @id), N'');
                IF NOT EXISTS (SELECT 1 FROM sys.sql_modules WHERE object_id = @id AND execute_as_principal_id = @newId)
                    THROW 50011, N'it does not read back running as the new user', 1;
                IF CHARINDEX(@mark, ISNULL(OBJECT_DEFINITION(@id), N'')) = 0
                    THROW 50012, N'its marker does not read back', 1;
                IF @after <> @before
                    THROW 50013, N'its permissions do not read back as they were', 1;
                COMMIT;
                INSERT @out (Module, Action, Why) VALUES (@name, N'moved', N'it now runs as ' + @new + N' (read back: the new user, its marker, its permissions)');
            END TRY
            BEGIN CATCH
                IF USER_NAME() <> @me REVERT;
                IF @@TRANCOUNT > 0 ROLLBACK;
                INSERT @out (Module, Action, Why) VALUES (@name, N'kept', N'it could not be made as the new user: ' + ERROR_MESSAGE());
            END CATCH
        END
        FETCH NEXT FROM mods INTO @id;
    END
    CLOSE mods; DEALLOCATE mods;
END
SELECT Module, Action, Why FROM @out
UNION ALL
SELECT N'', N'left', CONVERT(nvarchar(20), (SELECT COUNT(*) FROM sys.sql_modules WHERE @old IS NOT NULL AND execute_as_principal_id = @old))
ORDER BY 1, 2;
"@
}

function Resolve-SIIdentityMoveSqlModules {
    <# PURE. The module batch's rows -> @{ Clear (no module runs as the old user any more); Moved = @(lines); Kept = @(lines) }. #>
    param([object[]]$Rows = @())
    $val = { param($r, $k) if ($null -eq $r) { '' } elseif ($r -is [System.Collections.IDictionary]) { [string]$r[$k] } elseif ($r.PSObject.Properties[$k]) { [string]$r.$k } else { '' } }
    $moved = New-Object System.Collections.Generic.List[string]; $kept = New-Object System.Collections.Generic.List[string]; $left = -1
    foreach ($r in @($Rows | Where-Object { $null -ne $_ })) {
        $a = & $val $r 'Action'; $m = & $val $r 'Module'; $w = & $val $r 'Why'
        if ($a -eq 'left') { $n = 0; if ([int]::TryParse($w, [ref]$n)) { $left = $n } }
        elseif ($a -eq 'moved') { $moved.Add(('the procedure {0}: {1}' -f $m, $w)) }
        elseif ($a -eq 'kept') { $kept.Add(('the procedure {0} runs as the old user and is kept ({1})' -f $m, $w)) }
    }
    [pscustomobject]@{ Clear = ($left -eq 0); Moved = $moved.ToArray(); Kept = $kept.ToArray() }
}

function Get-SIIdentityMoveSqlDropSql {
    <# PURE. Clean-up: the old identity's contained user dropped (found by SID); refused by SQL when it owns a schema. The
       caller runs it ONLY after Test-SIIdentityMoveSqlCovered said Drop on a read made just before. #>
    param([Parameter(Mandatory)][string]$OldClientId)
    $o = ConvertTo-SIMoveSid $OldClientId
    @"
SET NOCOUNT ON;
DECLARE @n sysname = (SELECT name FROM sys.database_principals WHERE sid = $o);
IF @n IS NOT NULL
BEGIN
    IF EXISTS (SELECT 1 FROM sys.schemas s JOIN sys.database_principals p ON p.principal_id = s.principal_id WHERE p.sid = $o)
        THROW 50001, N'the old identity''s user owns a schema: it is not dropped', 1;
    DECLARE @s nvarchar(400) = N'DROP USER ' + QUOTENAME(@n);
    EXEC (@s);
END
"@
}
