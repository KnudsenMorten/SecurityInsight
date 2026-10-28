#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE CERTIFICATE-SIGNED GRANT PROCEDURE cfg.ApplyComponentGrants (#672; framework
    DOCS/REQUIREMENTS.md §12.23 SQL-ACCESS P4 + P9 "five years without contact").

    WHY. ~95% of installs have no Support app and no contact. After setup the SQL admin group may be EMPTY for years, so
    every update's schema AND grants must be applied by the updater's OWN contained user -- no admin, no person, no Support
    app. Until this file the updater held db_securityadmin for the grants (a standing security right: it could grant
    anything to anyone and undo the audit trail's DENYs), which P4 forbids. The replacement:
      * ONE procedure, cfg.ApplyComponentGrants, that applies ONLY the rows of the release's shipped grant list that pass
        FROZEN, general rules (below). Every rule is checked INSIDE the procedure -- a signed module never trusts its caller.
      * It is signed by an IN-DATABASE certificate created by the admin run (setup, or the Support-app cut-over
        setup\Install-SIGrantProcedure.ps1): EXPIRY_DATE 2099-12-31, a random password generated inside SQL and never
        returned, the PRIVATE KEY REMOVED right after signing. Nothing is stored, rotated or maintained (owner 2026-10-15:
        "Keep the in-database certificate"). The certificate's user holds exactly the rights the procedure exercises.
      * The updater gets EXECUTE on the procedure (role si_updater) and db_ddladmin for the schema -- nothing else of
        security. ALTERING the procedure drops its signature, so a tampered procedure has no rights at all; re-signing
        needs the private key, which no longer exists -- only an admin can install a new signed version (a new
        certificate). A release therefore NEVER changes the procedure: a design that needs a changed procedure is a design
        error (P9 point 2). The rules below are written to last.

    THE FROZEN RULES (one row of the shipped list = @{ action; permission; on; to; user; appId; component }):
      GRANT / DENY / REVOKE
        permission  SELECT, INSERT, UPDATE, DELETE or EXECUTE -- never CONTROL, ALTER, IMPERSONATE, TAKE OWNERSHIP, REFERENCES,
                    VIEW DEFINITION or any database-level right;
        on          SCHEMA::<s> or <s>.<object>, <s> one of the PRODUCT SCHEMAS compiled in; never EXECUTE on a whole schema
                    (it would reach this procedure); never this procedure itself; the object must be a table, view,
                    procedure or function (never a synonym: it could point outside the product schemas); an object that is
                    not there (yet) is SKIPPED, not refused;
        to          one of the product's COMPONENT ROLES compiled in -- never a fixed db_* role, never a user (except a
                    REVOKE from a user who is a member of a component role: the legacy direct grants), and `public` only
                    for a DENY or for GRANT EXECUTE on a procedure (the product's gated procedures check the caller
                    themselves);
        never       a GRANT or REVOKE that would lift an existing DENY of the same right (a DENY is lifted only by an admin).
      MEMBER        an EXISTING user into one of ITS component's roles (component + role compiled in); never the caller
                    itself, never dbo, a role, a certificate user or a member of db_owner.
      USER          a contained Entra user (WITH SID = the client id, TYPE = E -- the SI way: the server needs no directory
                    identity) for a COMPONENT compiled in, and only into that component's main role; a user whose SID is
                    already there is reused; a name held by another principal is refused (an admin resolves it).
      anything else is REFUSED. Every row comes back with its outcome (applied / skipped / refused / failed + the reason);
      one refused row never stops the others.

    WHO RUNS WHAT
      Get-SIGrantProcedureAdminSql      ONCE per install, by an admin (setup behind SI_Setup_SignedGrantProcedure, or the
                                        Support-app cut-over). Idempotent: a current, signed procedure is left alone.
      Get-SIReleaseGrantRows            the release's shipped list (SI-EngineGrants, SI-ManagementGrants, the schema files'
                                        own GRANT / DENY statements, the component members).
      Invoke-SIGrantProcedureApply      EVERY update, by the updater's own contained user (container\updater\_shared\
                                        SI-UpdaterDatabase.ps1) -- when the procedure is there and signed; else today's path.
    PURE except the -Invoke seams. Strict-mode safe; PS 5.1.
#>

$script:SIGrantProcName = 'cfg.ApplyComponentGrants'
$script:SIGrantProcMarker = 'si-component-grants v1'
$script:SIGrantSignerPrefix = 'si_grant_signer'
$script:SIGrantPermissions = @('SELECT', 'INSERT', 'UPDATE', 'DELETE', 'EXECUTE')
$script:SIGrantSchemas = @('sidata', 'cfg', 'vuln', 'cmdbsync', 'snowstage')

# THE COMPONENTS, compiled in (the procedure carries the same list). Main = the role a new user of the component gets.
# Today's: engine, web (+ its audit writer role), mcp, updater, tagging, templates. RESERVED for components that may come
# later (P9 point 3: a component added in year 3 needs no admin): loader (P6, collect and store separate), api, worker,
# report. Every role is created once by the admin run, empty until a release uses it.
$script:SIGrantComponents = @(
    [pscustomobject]@{ Component = 'engine';    Role = 'si_engine';       Main = $true }
    [pscustomobject]@{ Component = 'web';       Role = 'si_web';          Main = $true }
    [pscustomobject]@{ Component = 'web';       Role = 'si_audit_writer'; Main = $false }
    [pscustomobject]@{ Component = 'mcp';       Role = 'si_mcp';          Main = $true }
    [pscustomobject]@{ Component = 'updater';   Role = 'si_updater';      Main = $true }
    [pscustomobject]@{ Component = 'tagging';   Role = 'si_tagging';      Main = $true }
    [pscustomobject]@{ Component = 'templates'; Role = 'si_templates';    Main = $true }
    [pscustomobject]@{ Component = 'loader';    Role = 'si_loader';       Main = $true }
    [pscustomobject]@{ Component = 'api';       Role = 'si_api';          Main = $true }
    [pscustomobject]@{ Component = 'worker';    Role = 'si_worker';       Main = $true }
    [pscustomobject]@{ Component = 'report';    Role = 'si_report';       Main = $true }
)

function Get-SIGrantComponentRoles { <# PURE. Every compiled component role, once (unrolled: callers wrap in @()). #> @($script:SIGrantComponents | ForEach-Object { $_.Role } | Select-Object -Unique) }

function Test-SIGrantRow {
    <#
        PURE MIRROR of the procedure's rules that need no database (the static test runs every shipped row through it, so
        a bad list fails offline, not at a customer). What only the database knows (the object's type, an existing DENY,
        membership) is the procedure's alone. Returns @{ Ok; Why }.
    #>
    param([Parameter(Mandatory)]$Row)
    $g = { param($k) if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($k)) { [string]$Row[$k] } else { '' } } elseif ($Row.PSObject.Properties[$k]) { [string]$Row.$k } else { '' } }
    $a = (& $g 'action').Trim().ToUpperInvariant(); $p = (& $g 'permission').Trim().ToUpperInvariant(); $on = (& $g 'on').Trim(); $to = (& $g 'to').Trim()
    $roles = @(Get-SIGrantComponentRoles)
    $no = { param($w) [pscustomobject]@{ Ok = $false; Why = $w } }
    switch ($a) {
        { $_ -in 'GRANT', 'DENY', 'REVOKE' } {
            if ($p -notin $script:SIGrantPermissions) { return (& $no ('the permission must be {0}' -f ($script:SIGrantPermissions -join ', '))) }
            $schema = $null
            if ($on -match '^SCHEMA::(.+)$') {
                $schema = $Matches[1]
                if ($p -eq 'EXECUTE') { return (& $no 'EXECUTE on a whole schema is refused (it would reach the grant procedure)') }
            } elseif ($on -match '^([A-Za-z_]\w*)\.([A-Za-z_]\w*)$') {
                $schema = $Matches[1]
                if (('{0}.{1}' -f $Matches[1], $Matches[2]) -ieq $script:SIGrantProcName) { return (& $no 'the grant procedure is never granted through itself') }
            } else { return (& $no 'the target must be <schema>.<object> or SCHEMA::<schema>') }
            if ($schema -notin $script:SIGrantSchemas) { return (& $no ("'{0}' is not a product schema" -f $schema)) }
            if ($to -in $roles) { return [pscustomobject]@{ Ok = $true; Why = '' } }
            if ($to -ieq 'public') {
                if ($a -eq 'DENY') { return [pscustomobject]@{ Ok = $true; Why = '' } }
                if ($a -eq 'GRANT' -and $p -eq 'EXECUTE' -and $on -notlike 'SCHEMA::*') { return [pscustomobject]@{ Ok = $true; Why = '(the procedure checks that the object is a procedure)' } }
                return (& $no 'public may only be DENIED, or GRANTED EXECUTE on a procedure')
            }
            if ($a -eq 'REVOKE' -and $to -and $to -notmatch '^(?i)db_' -and $to -ine 'dbo') { return [pscustomobject]@{ Ok = $true; Why = '(the procedure checks that the user is a member of a component role)' } }
            return (& $no ("'{0}' is not one of the product's component roles" -f $to))
        }
        'MEMBER' {
            $c = (& $g 'component').Trim().ToLowerInvariant()
            if (-not @($script:SIGrantComponents | Where-Object { $_.Component -eq $c -and $_.Role -eq $to }).Count) { return (& $no ("'{0}' is not a role of the component '{1}'" -f $to, $c)) }
            if (-not (& $g 'user').Trim()) { return (& $no 'a member needs the user') }
            return [pscustomobject]@{ Ok = $true; Why = '' }
        }
        'USER' {
            $c = (& $g 'component').Trim().ToLowerInvariant()
            if (-not @($script:SIGrantComponents | Where-Object { $_.Component -eq $c }).Count) { return (& $no ("'{0}' is not one of the product's components" -f $c)) }
            if ((& $g 'user') -notmatch '^[A-Za-z0-9][A-Za-z0-9 ._@-]{0,127}$') { return (& $no 'a user needs a safe name (letters, digits, space . _ @ -)') }
            $guid = [guid]::Empty
            if (-not [guid]::TryParse((& $g 'appId'), [ref]$guid)) { return (& $no 'a user needs its application (client) id') }
            return [pscustomobject]@{ Ok = $true; Why = '' }
        }
        default { return (& $no ("unknown action '{0}' (GRANT, DENY, REVOKE, MEMBER, USER)" -f $a)) }
    }
}

function Get-SIGrantProcedureText {
    <#
        PURE. THE FROZEN PROCEDURE. Every rule is checked inside it; every name is QUOTENAME'd; the permission comes from a
        fixed list; dynamic SQL runs under the signature (a nested module would not). The marker line lets the admin run
        tell whether the deployed text is this version without comparing whitespace.
    #>
    $m = $script:SIGrantProcMarker
    $comp = ($script:SIGrantComponents | ForEach-Object { "(N'{0}', N'{1}', {2})" -f $_.Component, $_.Role, $(if ($_.Main) { 1 } else { 0 }) }) -join ', '
    $sch = ($script:SIGrantSchemas | ForEach-Object { "(N'$_')" }) -join ', '
    @"
CREATE OR ALTER PROCEDURE cfg.ApplyComponentGrants
    @Rows nvarchar(max)
AS
BEGIN
    -- $m -- SecurityInsight #672, framework DOCS/REQUIREMENTS.md 12.23 P4 + P9. FROZEN: general rules for every future
    -- release. Signed by an in-database certificate whose private key was removed: altering this text drops the signature,
    -- and an unsigned copy has no rights at all. Rows: a JSON array of {action, permission, on, to, user, appId, component}.
    SET NOCOUNT ON;
    DECLARE @out TABLE (Seq int NOT NULL, [Action] nvarchar(20) NULL, Permission nvarchar(40) NULL, [Target] nvarchar(300) NULL,
                        Grantee nvarchar(300) NULL, Outcome nvarchar(10) NOT NULL, Reason nvarchar(400) NULL);
    DECLARE @comp TABLE (Component sysname NOT NULL, RoleName sysname NOT NULL, IsMain bit NOT NULL);
    INSERT @comp (Component, RoleName, IsMain) VALUES $comp;
    DECLARE @sch TABLE (SchemaName sysname NOT NULL);
    INSERT @sch (SchemaName) VALUES $sch;
    IF @Rows IS NULL OR ISJSON(@Rows) <> 1 OR LEFT(LTRIM(@Rows), 1) <> N'['
    BEGIN
        SELECT 0 AS Seq, CAST(NULL AS nvarchar(20)) AS [Action], CAST(NULL AS nvarchar(40)) AS Permission, CAST(NULL AS nvarchar(300)) AS [Target],
               CAST(NULL AS nvarchar(300)) AS Grantee, N'refused' AS Outcome, N'the input is not a JSON array of rows -- nothing was applied' AS Reason;
        RETURN;
    END
    DECLARE @i int, @a nvarchar(4000), @p nvarchar(4000), @on nvarchar(4000), @to nvarchar(4000), @user nvarchar(4000), @app nvarchar(4000), @c nvarchar(4000),
            @why nvarchar(400), @skip nvarchar(400), @s nvarchar(max), @schema nvarchar(4000), @obj nvarchar(4000), @t nvarchar(600), @type char(2),
            @oid int, @sid varbinary(85), @name sysname, @pid int, @g uniqueidentifier, @isSchema bit;
    DECLARE r CURSOR LOCAL FAST_FORWARD FOR
        SELECT CONVERT(int, [key]) + 1,
               UPPER(LTRIM(RTRIM(JSON_VALUE([value], '$.action')))), UPPER(LTRIM(RTRIM(JSON_VALUE([value], '$.permission')))),
               LTRIM(RTRIM(JSON_VALUE([value], '$.on'))), LTRIM(RTRIM(JSON_VALUE([value], '$.to'))), LTRIM(RTRIM(JSON_VALUE([value], '$.user'))),
               LTRIM(RTRIM(JSON_VALUE([value], '$.appId'))), LOWER(LTRIM(RTRIM(JSON_VALUE([value], '$.component'))))
        FROM OPENJSON(@Rows) ORDER BY CONVERT(int, [key]);
    OPEN r;
    FETCH NEXT FROM r INTO @i, @a, @p, @on, @to, @user, @app, @c;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        SELECT @why = NULL, @skip = NULL, @s = NULL, @t = NULL, @type = NULL, @oid = NULL, @schema = NULL, @obj = NULL, @name = NULL, @pid = NULL, @isSchema = 0;
        IF @a IN (N'GRANT', N'DENY', N'REVOKE')
        BEGIN
            -- the permission: the five data verbs, nothing else
            IF @p IS NULL OR @p NOT IN (N'SELECT', N'INSERT', N'UPDATE', N'DELETE', N'EXECUTE')
                SET @why = N'the permission must be SELECT, INSERT, UPDATE, DELETE or EXECUTE';
            -- the target: a product schema, or an object in one
            ELSE IF @on IS NULL OR LEN(@on) > 270
                SET @why = N'the target must be <schema>.<object> or SCHEMA::<schema>';
            ELSE IF LEFT(@on, 8) = N'SCHEMA::'
            BEGIN
                SELECT @schema = SUBSTRING(@on, 9, 4000), @isSchema = 1;
                IF NOT EXISTS (SELECT 1 FROM @sch WHERE SchemaName = @schema) SET @why = N'not a product schema';
                ELSE IF @p = N'EXECUTE' SET @why = N'EXECUTE on a whole schema is refused (it would reach the grant procedure)';
                ELSE IF SCHEMA_ID(@schema) IS NULL SET @skip = N'the schema is not in this database';
                ELSE SET @t = N'SCHEMA::' + QUOTENAME(@schema);
            END
            ELSE
            BEGIN
                SELECT @schema = PARSENAME(@on, 2), @obj = PARSENAME(@on, 1);
                IF @schema IS NULL OR @obj IS NULL OR PARSENAME(@on, 3) IS NOT NULL SET @why = N'the target must be <schema>.<object> or SCHEMA::<schema>';
                ELSE IF NOT EXISTS (SELECT 1 FROM @sch WHERE SchemaName = @schema) SET @why = N'not a product schema';
                ELSE IF @schema = N'cfg' AND @obj = N'ApplyComponentGrants' SET @why = N'the grant procedure is never granted through itself';
                ELSE
                BEGIN
                    SET @oid = OBJECT_ID(QUOTENAME(@schema) + N'.' + QUOTENAME(@obj));
                    IF @oid IS NULL SET @skip = N'the object is not in this database (yet)';
                    ELSE
                    BEGIN
                        SELECT @type = [type] FROM sys.objects WHERE object_id = @oid;
                        IF @type NOT IN ('U', 'V', 'P', 'FN', 'IF', 'TF') SET @why = N'only a table, view, procedure or function (never a synonym or another kind)';
                        ELSE SET @t = N'OBJECT::' + QUOTENAME(@schema) + N'.' + QUOTENAME(@obj);
                    END
                END
            END
            -- the grantee: a component role; public only for a DENY or EXECUTE on a procedure; a REVOKE also from a member user
            IF @why IS NULL AND @t IS NOT NULL
            BEGIN
                IF EXISTS (SELECT 1 FROM @comp WHERE RoleName = @to)
                BEGIN
                    SELECT @pid = principal_id FROM sys.database_principals WHERE name = @to AND [type] = 'R' AND is_fixed_role = 0;
                    IF @pid IS NULL SET @why = N'the component role is not in this database -- the admin run creates every component role once';
                END
                ELSE IF @to = N'public'
                BEGIN
                    SET @pid = 0;
                    IF @a = N'REVOKE' SET @why = N'nothing is revoked from public (it could lift a DENY)';
                    ELSE IF @a = N'GRANT' AND NOT (@p = N'EXECUTE' AND @type = 'P') SET @why = N'public may only be DENIED, or GRANTED EXECUTE on a procedure';
                END
                ELSE IF @a = N'REVOKE'
                BEGIN
                    SELECT @pid = u.principal_id FROM sys.database_principals AS u
                    WHERE u.name = @to AND u.[type] IN ('E', 'X', 'S') AND u.principal_id > 4
                      AND EXISTS (SELECT 1 FROM sys.database_role_members AS m JOIN sys.database_principals AS rp ON rp.principal_id = m.role_principal_id
                                  JOIN @comp AS k ON k.RoleName = rp.name WHERE m.member_principal_id = u.principal_id);
                    IF @pid IS NULL SET @why = N'a REVOKE names a component role, or a user who is a member of one';
                END
                ELSE SET @why = N'the grantee must be one of the product''s component roles (never a fixed role, never a user)';
            END
            -- a product schema that came after the admin run: the signer holds no CONTROL there yet -- said, never a failure
            IF @why IS NULL AND @t IS NOT NULL AND ISNULL(HAS_PERMS_BY_NAME(QUOTENAME(@schema), N'SCHEMA', N'CONTROL'), 0) <> 1
                SET @why = N'the signer has no rights on this schema yet (it came after the admin run) -- an admin re-runs the rights step';
            -- a DENY is lifted only by an admin: no GRANT / REVOKE over an existing DENY of the same right
            IF @why IS NULL AND @t IS NOT NULL AND @a IN (N'GRANT', N'REVOKE')
               AND EXISTS (SELECT 1 FROM sys.database_permissions AS dp WHERE dp.grantee_principal_id = @pid AND dp.[state] = 'D' AND dp.permission_name = @p
                           AND ((@isSchema = 1 AND dp.class = 3 AND dp.major_id = SCHEMA_ID(@schema)) OR (@isSchema = 0 AND dp.class = 1 AND dp.major_id = @oid AND dp.minor_id = 0)))
                SET @why = N'it would lift an existing DENY -- only an admin lifts a DENY';
            IF @why IS NULL AND @t IS NOT NULL
                SET @s = @a + N' ' + @p + N' ON ' + @t + CASE WHEN @a = N'REVOKE' THEN N' FROM ' ELSE N' TO ' END + QUOTENAME(@to) + N';';
        END
        ELSE IF @a = N'MEMBER'
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM @comp WHERE Component = @c AND RoleName = @to) SET @why = N'the role is not one of this component''s roles';
            ELSE IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @to AND [type] = 'R' AND is_fixed_role = 0)
                SET @why = N'the component role is not in this database -- the admin run creates every component role once';
            ELSE
            BEGIN
                SELECT @pid = principal_id, @name = name FROM sys.database_principals WHERE name = @user AND [type] IN ('E', 'X', 'S') AND principal_id > 4;
                IF @pid IS NULL SET @why = N'the user is not an Entra (or local) user of this database';
                ELSE IF @pid = DATABASE_PRINCIPAL_ID() SET @why = N'the caller never adds itself to a role';
                ELSE IF IS_ROLEMEMBER(N'db_owner', @name) = 1 SET @why = N'a member of db_owner is never handled here';
                ELSE IF IS_ROLEMEMBER(@to, @name) = 1 SET @skip = N'already a member';
                ELSE SET @s = N'ALTER ROLE ' + QUOTENAME(@to) + N' ADD MEMBER ' + QUOTENAME(@name) + N';';
            END
            SET @t = @user;
        END
        ELSE IF @a = N'USER'
        BEGIN
            SELECT @to = RoleName FROM @comp WHERE Component = @c AND IsMain = 1;
            SET @g = TRY_CONVERT(uniqueidentifier, @app);
            IF @to IS NULL OR NOT EXISTS (SELECT 1 FROM @comp WHERE Component = @c) SET @why = N'not one of the product''s components';
            ELSE IF @user IS NULL OR LEN(@user) < 1 OR LEN(@user) > 128 OR @user LIKE N'%[^A-Za-z0-9 ._@-]%' OR LEFT(@user, 1) LIKE N'[^A-Za-z0-9]'
                SET @why = N'a user needs a safe name (letters, digits, space . _ @ -)';
            ELSE IF @g IS NULL SET @why = N'a user needs its application (client) id';
            ELSE IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @to AND [type] = 'R' AND is_fixed_role = 0)
                SET @why = N'the component role is not in this database -- the admin run creates every component role once';
            ELSE
            BEGIN
                SET @sid = CAST(@g AS varbinary(16));
                SELECT @pid = principal_id, @name = name FROM sys.database_principals WHERE sid = @sid;
                IF @pid IS NOT NULL AND (SELECT [type] FROM sys.database_principals WHERE principal_id = @pid) NOT IN ('E', 'X')
                    SET @why = N'that client id belongs to another kind of principal -- an admin resolves it';
                ELSE IF @pid IS NULL AND EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @user)
                    SET @why = N'another principal already has that name -- an admin resolves it';
                ELSE IF @pid = DATABASE_PRINCIPAL_ID() SET @why = N'the caller never adds itself to a role';
                ELSE IF @pid IS NULL
                BEGIN
                    -- Azure SQL (5) / Managed Instance (8): the contained Entra user by its client id. Any other engine is only the
                    -- test VM's local SQL Server, which has no Entra users: a user without login stands in for it there.
                    IF CONVERT(int, SERVERPROPERTY('EngineEdition')) IN (5, 8)
                        SET @s = N'CREATE USER ' + QUOTENAME(@user) + N' WITH SID = ' + CONVERT(nvarchar(40), @sid, 1) + N', TYPE = E; ';
                    ELSE SET @s = N'CREATE USER ' + QUOTENAME(@user) + N' WITHOUT LOGIN; ';
                    SET @s = @s + N'ALTER ROLE ' + QUOTENAME(@to) + N' ADD MEMBER ' + QUOTENAME(@user) + N';';
                END
                ELSE IF IS_ROLEMEMBER(N'db_owner', @name) = 1 SET @why = N'a member of db_owner is never handled here';
                ELSE IF IS_ROLEMEMBER(@to, @name) = 1 SET @skip = N'the user is there and in its role';
                ELSE SET @s = N'ALTER ROLE ' + QUOTENAME(@to) + N' ADD MEMBER ' + QUOTENAME(@name) + N';';
            END
            SET @t = @user;
        END
        ELSE SET @why = N'unknown action (GRANT, DENY, REVOKE, MEMBER, USER)';

        IF @why IS NOT NULL INSERT @out VALUES (@i, LEFT(@a, 20), LEFT(@p, 40), LEFT(@on, 300), LEFT(@to, 300), N'refused', @why);
        ELSE IF @s IS NULL INSERT @out VALUES (@i, @a, LEFT(@p, 40), LEFT(ISNULL(@on, @t), 300), LEFT(@to, 300), N'skipped', ISNULL(@skip, N'nothing to do'));
        ELSE
        BEGIN
            BEGIN TRY
                EXEC sys.sp_executesql @s;
                INSERT @out VALUES (@i, @a, LEFT(@p, 40), LEFT(ISNULL(@on, @t), 300), LEFT(@to, 300), N'applied', NULL);
            END TRY
            BEGIN CATCH
                INSERT @out VALUES (@i, @a, LEFT(@p, 40), LEFT(ISNULL(@on, @t), 300), LEFT(@to, 300), N'failed', LEFT(ERROR_MESSAGE(), 400));
            END CATCH
        END
        FETCH NEXT FROM r INTO @i, @a, @p, @on, @to, @user, @app, @c;
    END
    CLOSE r; DEALLOCATE r;
    SELECT Seq, [Action], Permission, [Target], Grantee, Outcome, Reason FROM @out ORDER BY Seq;
END
"@
}

function Get-SIGrantSignerRightsSql {
    <#
        PURE. The certificate user's rights -- exactly what the procedure exercises (idempotent; run by the admin after
        every signing and by every re-run of the admin step):
          CONTROL on each PRODUCT SCHEMA that is in the database (GRANT / DENY / REVOKE on its objects; proven on real SQL
            2026-10-15: a database-level grant option is NOT enough -- the signed module then cannot even see the object);
            the grants it makes are recorded with the schema owner (dbo) as grantor, so they outlive the certificate;
          ALTER ANY USER (CREATE USER for a component);
          ALTER on each component role (ADD MEMBER) -- never ALTER ANY ROLE, so never a fixed role.
        CONTROL on a schema could also pass on CONTROL / ALTER -- the PROCEDURE's frozen rules refuse those; the certificate
        user cannot log in and acts only inside the signed procedure.
        -SignerExpression: a T-SQL expression that yields the QUOTENAME'd certificate user.
    #>
    param([Parameter(Mandatory)][string]$SignerExpression)
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($s in $script:SIGrantSchemas) { $lines.Add("IF SCHEMA_ID(N'$s') IS NOT NULL BEGIN SET @s = N'GRANT CONTROL ON SCHEMA::[$s] TO ' + $SignerExpression + N';'; EXEC sys.sp_executesql @s; END") }
    $lines.Add("SET @s = N'GRANT ALTER ANY USER TO ' + $SignerExpression + N';'; EXEC sys.sp_executesql @s;")
    foreach ($r in (Get-SIGrantComponentRoles)) { $lines.Add("IF DATABASE_PRINCIPAL_ID(N'$r') IS NOT NULL BEGIN SET @s = N'GRANT ALTER ON ROLE::[$r] TO ' + $SignerExpression + N';'; EXEC sys.sp_executesql @s; END") }
    $lines -join "`n"
}

function Get-SIGrantProcedureAdminSql {
    <#
        PURE. ONCE per install, by an ADMIN (the server's Entra admin group: setup, or the Support-app cut-over). Idempotent:
        a current, signed procedure is left alone. Batches, in order (@{ Step; Purpose; Sql }):
          roles      every compiled component role (AUTHORIZATION dbo), so the procedure never creates a role;
          procedure  only when missing or another version (re-creating it drops the signature);
          sign       only when not signed by a current signer: earlier signer users / certificates dropped (the grants they
                     made name dbo as grantor and stay -- proven on real SQL), a NEW in-database certificate (EXPIRY
                     2099-12-31, a random password generated inside SQL, never returned), ADD SIGNATURE, then the PRIVATE KEY
                     REMOVED;
          rights     the signer's rights (Get-SIGrantSignerRightsSql) -- every run, so a product schema that came later is
                     covered the next time an admin runs this;
          updater    EXECUTE on the procedure to si_updater (its ONLY security-related right), VIEW DEFINITION (catalog
                     reads: the drift check, this state -- read-only metadata), a DENY of ALTER on the procedure (an update
                     can never drop the signature by accident), and with -UpdaterUser that user into si_updater.
    #>
    param([string]$UpdaterUser = '')
    $m = $script:SIGrantProcMarker
    $px = $script:SIGrantSignerPrefix
    $b = New-Object System.Collections.Generic.List[object]
    $roles = (Get-SIGrantComponentRoles | ForEach-Object { "IF DATABASE_PRINCIPAL_ID(N'$_') IS NULL EXEC (N'CREATE ROLE [$_] AUTHORIZATION [dbo]');" }) -join "`n"
    $b.Add([pscustomobject]@{ Step = 'roles'; Purpose = 'the product''s component roles (created once, empty until a release uses them)'; Sql = $roles })
    $proc = (Get-SIGrantProcedureText).Replace("'", "''")
    $b.Add([pscustomobject]@{ Step = 'procedure'; Purpose = 'the grant procedure cfg.ApplyComponentGrants (only when missing or another version)'; Sql = @"
IF OBJECT_ID(N'cfg.ApplyComponentGrants') IS NULL OR ISNULL(OBJECT_DEFINITION(OBJECT_ID(N'cfg.ApplyComponentGrants')), N'') NOT LIKE N'%$m%'
    EXEC sys.sp_executesql N'$proc';
"@ })
    $b.Add([pscustomobject]@{ Step = 'sign'; Purpose = 'sign it with a new in-database certificate (expiry 2099, private key removed) -- only when unsigned'; Sql = @"
IF NOT EXISTS (SELECT 1 FROM sys.crypt_properties AS cp JOIN sys.certificates AS c ON c.thumbprint = cp.thumbprint
               WHERE cp.major_id = OBJECT_ID(N'cfg.ApplyComponentGrants') AND c.name LIKE N'$px%')
BEGIN
    DECLARE @s nvarchar(max), @old sysname;
    DECLARE oldc CURSOR LOCAL FAST_FORWARD FOR SELECT name FROM sys.certificates WHERE name LIKE N'$px%';
    OPEN oldc; FETCH NEXT FROM oldc INTO @old;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        IF DATABASE_PRINCIPAL_ID(@old) IS NOT NULL BEGIN SET @s = N'DROP USER ' + QUOTENAME(@old) + N';'; EXEC sys.sp_executesql @s; END
        SET @s = N'DROP CERTIFICATE ' + QUOTENAME(@old) + N';'; EXEC sys.sp_executesql @s;
        FETCH NEXT FROM oldc INTO @old;
    END
    CLOSE oldc; DEALLOCATE oldc;
    DECLARE @cert sysname = N'${px}_' + FORMAT(SYSUTCDATETIME(), 'yyyyMMddHHmmssfff');
    DECLARE @pw nvarchar(200) = CONVERT(nvarchar(36), NEWID()) + N'Si1!' + CONVERT(nvarchar(36), NEWID());
    SET @s = N'CREATE CERTIFICATE ' + QUOTENAME(@cert) + N' ENCRYPTION BY PASSWORD = ' + QUOTENAME(@pw, '''')
           + N' WITH SUBJECT = ''SecurityInsight grant procedure signer'', EXPIRY_DATE = ''20991231'';';
    EXEC sys.sp_executesql @s;
    SET @s = N'CREATE USER ' + QUOTENAME(@cert) + N' FROM CERTIFICATE ' + QUOTENAME(@cert) + N';'; EXEC sys.sp_executesql @s;
    SET @s = N'ADD SIGNATURE TO cfg.ApplyComponentGrants BY CERTIFICATE ' + QUOTENAME(@cert) + N' WITH PASSWORD = ' + QUOTENAME(@pw, '''') + N';';
    EXEC sys.sp_executesql @s;
    SET @s = N'ALTER CERTIFICATE ' + QUOTENAME(@cert) + N' REMOVE PRIVATE KEY;'; EXEC sys.sp_executesql @s;
END
"@ })
    $b.Add([pscustomobject]@{ Step = 'rights'; Purpose = 'the signer certificate user''s rights (CONTROL on the product schemas, ALTER ANY USER, ALTER on the component roles)'; Sql = @"
DECLARE @s nvarchar(max);
DECLARE @signer sysname = (SELECT TOP (1) c.name FROM sys.crypt_properties AS cp JOIN sys.certificates AS c ON c.thumbprint = cp.thumbprint
                           WHERE cp.major_id = OBJECT_ID(N'cfg.ApplyComponentGrants') AND c.name LIKE N'$px%' ORDER BY c.name DESC);
IF @signer IS NULL THROW 51672, N'the grant procedure is not signed -- run the sign step first', 1;
IF DATABASE_PRINCIPAL_ID(@signer) IS NULL BEGIN SET @s = N'CREATE USER ' + QUOTENAME(@signer) + N' FROM CERTIFICATE ' + QUOTENAME(@signer) + N';'; EXEC sys.sp_executesql @s; END
$(Get-SIGrantSignerRightsSql -SignerExpression 'QUOTENAME(@signer)')
"@ })
    $upd = @"
DECLARE @s nvarchar(400);
GRANT EXECUTE ON OBJECT::cfg.ApplyComponentGrants TO [si_updater];
GRANT VIEW DEFINITION TO [si_updater];
DENY ALTER ON OBJECT::cfg.ApplyComponentGrants TO [si_updater];
"@
    if ($UpdaterUser) {
        $q = $UpdaterUser.Replace("'", "''")
        $upd += "`nIF DATABASE_PRINCIPAL_ID(N'$q') IS NOT NULL AND ISNULL(IS_ROLEMEMBER(N'si_updater', N'$q'), 0) = 0 BEGIN SET @s = N'ALTER ROLE [si_updater] ADD MEMBER ' + QUOTENAME(N'$q'); EXEC (@s); END"
    }
    $b.Add([pscustomobject]@{ Step = 'updater'; Purpose = 'the updater may EXECUTE the procedure (role si_updater) -- its only security-related right'; Sql = $upd })
    $b.ToArray()
}

function Get-SIGrantProcedureStateSql {
    <#
        PURE. READ-ONLY, one row: the procedure (exists, this version, signed by a current signer), the signer certificate
        (name, expiry, private key removed), si_updater's EXECUTE on it, and -- with -UpdaterUser -- that user's roles.
        Needs only catalog reads (the admin, or the updater: its signature-free view of sys.crypt_properties is enough).
    #>
    param([string]$UpdaterUser = '')
    $m = $script:SIGrantProcMarker; $px = $script:SIGrantSignerPrefix
    $u = if ($UpdaterUser) { "N'" + $UpdaterUser.Replace("'", "''") + "'" } else { 'NULL' }
    @"
SELECT CASE WHEN OBJECT_ID(N'cfg.ApplyComponentGrants') IS NULL THEN 0 ELSE 1 END AS ProcExists,
       CASE WHEN ISNULL(OBJECT_DEFINITION(OBJECT_ID(N'cfg.ApplyComponentGrants')), N'') LIKE N'%$m%' THEN 1 ELSE 0 END AS ProcCurrent,
       (SELECT TOP (1) c.name FROM sys.crypt_properties AS cp JOIN sys.certificates AS c ON c.thumbprint = cp.thumbprint
         WHERE cp.major_id = OBJECT_ID(N'cfg.ApplyComponentGrants') AND c.name LIKE N'$px%' ORDER BY c.name DESC) AS Signer,
       (SELECT TOP (1) CONVERT(nvarchar(10), c.expiry_date, 23) FROM sys.crypt_properties AS cp JOIN sys.certificates AS c ON c.thumbprint = cp.thumbprint
         WHERE cp.major_id = OBJECT_ID(N'cfg.ApplyComponentGrants') AND c.name LIKE N'$px%' ORDER BY c.name DESC) AS SignerExpiry,
       (SELECT TOP (1) CASE WHEN c.pvt_key_encryption_type = 'NA' THEN 1 ELSE 0 END FROM sys.crypt_properties AS cp JOIN sys.certificates AS c ON c.thumbprint = cp.thumbprint
         WHERE cp.major_id = OBJECT_ID(N'cfg.ApplyComponentGrants') AND c.name LIKE N'$px%' ORDER BY c.name DESC) AS PrivateKeyRemoved,
       CASE WHEN EXISTS (SELECT 1 FROM sys.database_permissions AS dp WHERE dp.class = 1 AND dp.major_id = OBJECT_ID(N'cfg.ApplyComponentGrants')
                         AND dp.grantee_principal_id = DATABASE_PRINCIPAL_ID(N'si_updater') AND dp.permission_name = N'EXECUTE' AND dp.[state] IN ('G', 'W')) THEN 1 ELSE 0 END AS UpdaterExecute,
       ISNULL(HAS_PERMS_BY_NAME(N'cfg.ApplyComponentGrants', N'OBJECT', N'EXECUTE'), 0) AS CallerExecute,
       $u AS UpdaterUser,
       CASE WHEN $u IS NULL OR DATABASE_PRINCIPAL_ID($u) IS NULL THEN 0 ELSE 1 END AS UpdaterPresent,
       (SELECT STRING_AGG(CONVERT(nvarchar(max), r.name), N',') WITHIN GROUP (ORDER BY r.name) FROM sys.database_role_members AS mm
          JOIN sys.database_principals AS r ON r.principal_id = mm.role_principal_id WHERE mm.member_principal_id = DATABASE_PRINCIPAL_ID($u)) AS UpdaterRoles,
       (SELECT Value FROM cfg.InstallState WHERE Name = N'GrantProcedureBefore') AS Record,
       (SELECT Value FROM cfg.InstallState WHERE Name = N'GrantProcedureLastApply') AS LastApply;
"@
}

function ConvertFrom-SIGrantProcedureState {
    <# PURE. The row of Get-SIGrantProcedureStateSql (hashtable / PSObject / DataRow) -> @{ Installed; Current; Signed; Signer; Expiry; KeyRemoved; UpdaterExecute; UpdaterPresent; UpdaterRoles; Record; LastApply }. #>
    param($Row)
    $get = { param($k) if ($null -eq $Row) { $null } elseif ($Row -is [System.Collections.IDictionary]) { $Row[$k] } elseif ($Row -is [System.Data.DataRow]) { $Row[$k] } else { $Row.$k } }
    $s = { param($k) $v = & $get $k; if ($null -eq $v -or $v -is [System.DBNull]) { '' } else { [string]$v } }
    $b = { param($k) (& $s $k) -eq '1' -or (& $s $k) -eq 'True' }
    [pscustomobject]@{
        Installed = (& $b 'ProcExists'); Current = (& $b 'ProcCurrent'); Signer = (& $s 'Signer'); Signed = [bool](& $s 'Signer')
        Expiry = (& $s 'SignerExpiry'); KeyRemoved = (& $b 'PrivateKeyRemoved'); UpdaterExecute = (& $b 'UpdaterExecute'); CallerExecute = (& $b 'CallerExecute')
        UpdaterPresent = (& $b 'UpdaterPresent'); UpdaterRoles = @((& $s 'UpdaterRoles') -split ',' | Where-Object { $_ })
        Record = (& $s 'Record'); LastApply = (& $s 'LastApply')
    }
}

function Test-SIGrantProcedureReady {
    <#
        PURE. Is the model in place on this database (the cut-over's read-back and the updater's choice of path)? Every one
        must hold: the procedure is there, this version, signed by a current signer whose private key is gone and whose
        certificate runs to 2099; si_updater may EXECUTE it; with -RequireUpdaterMember the updater's user is in si_updater.
        Returns @{ Ok; Lines }.
    #>
    param([Parameter(Mandatory)]$State, [switch]$RequireUpdaterMember)
    $l = New-Object System.Collections.Generic.List[string]
    if (-not $State.Installed) { $l.Add('the grant procedure cfg.ApplyComponentGrants is not in this database') }
    elseif (-not $State.Current) { $l.Add(('the grant procedure is another version than this release''s ({0}) -- it keeps working; an admin installs this one' -f $script:SIGrantProcMarker)) }
    if ($State.Installed -and -not $State.Signed) { $l.Add('the grant procedure is NOT signed (altered after signing?) -- it has no rights; an admin signs it again (the cut-over)') }
    if ($State.Signed -and -not $State.KeyRemoved) { $l.Add(('the signer certificate {0} still has its private key' -f $State.Signer)) }
    if ($State.Signed -and $State.Expiry -and $State.Expiry -notlike '2099-*') { $l.Add(('the signer certificate expires {0}, not 2099' -f $State.Expiry)) }
    if (-not $State.UpdaterExecute) { $l.Add('the role si_updater may not EXECUTE the grant procedure') }
    if ($RequireUpdaterMember) {
        if (-not $State.UpdaterPresent) { $l.Add('the updater''s user is not in this database') }
        elseif ($State.UpdaterRoles -notcontains 'si_updater') { $l.Add('the updater''s user is not in the role si_updater') }
    }
    [pscustomobject]@{ Ok = ($l.Count -eq 0); Lines = $l.ToArray() }
}

function Get-SISchemaSecurityRows {
    <#
        PURE (reads the release's own sql\ files). The schema files' own GRANT / DENY statements (on public and on the audit
        writer role) as rows for the procedure. The schema files run them only as an admin or an updater that still holds
        db_securityadmin (each is guarded by IF IS_ROLEMEMBER(...)); without that right the updater applies the same rights
        THROUGH the procedure right after the schema step. The static test proves every security statement of every
        schema file is guarded and is in this list.
    #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($f in @('sql/si-vulnerability-target.sql', 'sql/si-data-schema.sql', 'sql/si-cmdbsync-schema.sql', 'sql/si-pro-settings.sql')) {
        $p = [IO.Path]::Combine($SIRoot, $f)
        if (-not (Test-Path -LiteralPath $p)) { continue }
        $t = [IO.File]::ReadAllText($p)
        foreach ($m in [regex]::Matches($t, '(?im)^[^\S\r\n]*(?:IF\b[^\r\n]*?\)\s*=\s*1\s+)?(GRANT|DENY)\s+([A-Z]+(?:\s*,\s*[A-Z]+)*)\s+ON\s+OBJECT::([A-Za-z_]\w*\.[A-Za-z_]\w*)\s+TO\s+\[?([A-Za-z_]\w*)\]?\s*;')) {
            foreach ($v in ($m.Groups[2].Value -split '\s*,\s*')) {
                $rows.Add([pscustomobject]@{ action = $m.Groups[1].Value.ToUpperInvariant(); permission = $v.ToUpperInvariant(); on = $m.Groups[3].Value; to = $m.Groups[4].Value })
            }
        }
    }
    $rows.ToArray()
}

function Get-SIReleaseGrantRows {
    <#
        PURE (reads the release's own lists). THE RELEASE'S SHIPPED GRANT LIST for the procedure, in order:
          0. the members: -WebUser into si_web + si_audit_writer, -McpUser into si_mcp (existing users only; never a CREATE)
          1. the schema files' own GRANT / DENY (public, si_audit_writer)          Get-SISchemaSecurityRows
          2. the engine role si_engine (schema / object grants, its DENYs)        engine\pro-settings\SI-EngineGrants.ps1
          3. the web app's role si_web (cfg.Setting / cfg.ChangeLog + WebWriteGrants) and the revokes of what an earlier
             release granted the web app (from si_web and from the web app's user)  pro-management\deploy\SI-ManagementGrants.ps1
          4. the MCP server's role si_mcp (DENY SELECT on the sign-in key ring)

        The engine's user is NOT made a member here: the engine's cut-over (setup\Move-SIEngineToLeastPrivilege.ps1) or the
        install does that, with its rollback record.
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [string]$WebUser = '', [string]$McpUser = '')
    $rows = New-Object System.Collections.Generic.List[object]
    $add = { param($a, $p, $on, $to) $rows.Add([pscustomobject]@{ action = $a; permission = $p; on = $on; to = $to }) }
    # the members FIRST: a REVOKE from the web app's user needs it to be a member of a component role
    if ($WebUser) {
        $rows.Add([pscustomobject]@{ action = 'MEMBER'; component = 'web'; to = 'si_web'; user = $WebUser })
        $rows.Add([pscustomobject]@{ action = 'MEMBER'; component = 'web'; to = 'si_audit_writer'; user = $WebUser })
    }
    if ($McpUser) { $rows.Add([pscustomobject]@{ action = 'MEMBER'; component = 'mcp'; to = 'si_mcp'; user = $McpUser }) }
    foreach ($r in @(Get-SISchemaSecurityRows -SIRoot $SIRoot)) { $rows.Add($r) }
    $eng = [IO.Path]::Combine($SIRoot, 'engine', 'pro-settings', 'SI-EngineGrants.ps1')
    if (Test-Path -LiteralPath $eng) {
        . $eng
        foreach ($g in $script:SIEngineSchemaGrants) { foreach ($v in ($g.Verbs -split ',\s*')) { & $add 'GRANT' $v ('SCHEMA::' + $g.Schema) $script:SIEngineRole } }
        foreach ($g in $script:SIEngineObjectGrants) { foreach ($v in ($g.Verbs -split ',\s*')) { & $add 'GRANT' $v $g.Object $script:SIEngineRole } }
        foreach ($g in $script:SIEngineDenies) { foreach ($v in ($g.Verbs -split ',\s*')) { & $add 'DENY' $v $g.Object $script:SIEngineRole } }
    }
    $web = [IO.Path]::Combine($SIRoot, 'pro-management', 'deploy', 'SI-ManagementGrants.ps1')
    if (Test-Path -LiteralPath $web) {
        . $web
        foreach ($v in 'INSERT', 'UPDATE', 'DELETE') { & $add 'GRANT' $v 'cfg.Setting' 'si_web' }
        & $add 'GRANT' 'INSERT' 'cfg.ChangeLog' 'si_web'
        foreach ($g in $script:WebWriteGrants) { foreach ($v in ($g.Verbs -split ',\s*')) { & $add 'GRANT' $v $g.Object 'si_web' } }
        foreach ($r in $script:WebRevokedWrites) {
            $obj = ($r -split 'OBJECT::')[1]; $verbs = ($r -split '\s+ON\s+')[0]
            foreach ($v in ($verbs -split ',\s*')) {
                & $add 'REVOKE' $v.Trim() $obj 'si_web'
                if ($WebUser) { & $add 'REVOKE' $v.Trim() $obj $WebUser }
            }
        }
        & $add 'DENY' 'SELECT' 'cfg.WebKeyRing' 'si_mcp'
    }
    $rows.ToArray()
}

function ConvertTo-SIGrantRowsJson {
    <# PURE. Rows -> the procedure's JSON array (only the keys a row carries). Always an array, also for one row (PS 5.1). #>
    param([object[]]$Rows = @())
    $items = foreach ($r in @($Rows | Where-Object { $_ })) {
        $o = [ordered]@{}
        foreach ($k in 'action', 'permission', 'on', 'to', 'user', 'appId', 'component') {
            $v = if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($k)) { $r[$k] } else { $null } } elseif ($r.PSObject.Properties[$k]) { $r.$k } else { $null }
            if ($null -ne $v -and "$v" -ne '') { $o[$k] = [string]$v }
        }
        ConvertTo-Json -InputObject $o -Compress
    }
    '[' + (@($items) -join ',') + ']'
}

function Invoke-SIGrantProcedureApply {
    <#
        THE UPDATER'S PATH (framework §12.23 P4 / P9). -Invoke: the store's seam (sql, params, mode). Reads the state; when
        the procedure is not there, not signed, or si_updater may not EXECUTE it, returns Used = $false with the reason (the
        caller keeps today's path) and sends NOTHING. Otherwise sends the rows in ONE call and returns every row's outcome:
          @{ Used; Reason; State; Applied; Skipped; Refused (rows); Failed (rows); Results }.
        Never throws for a missing model; a failing call throws (the caller stops the update, as today's grant step does).
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [object[]]$Rows = @())
    $st = ConvertFrom-SIGrantProcedureState -Row (@(& $Invoke (Get-SIGrantProcedureStateSql) @{} 'reader' | ForEach-Object { $_ }) | Select-Object -First 1)
    $r = { param($used, $why, $res = @()) $res = @($res)
        $o = { param($x, $k) if ($x -is [System.Collections.IDictionary]) { [string]$x[$k] } else { [string]$x.$k } }
        [pscustomobject]@{ Used = $used; Reason = $why; State = $st; Results = $res
            Applied = @($res | Where-Object { (& $o $_ 'Outcome') -eq 'applied' }).Count; Skipped = @($res | Where-Object { (& $o $_ 'Outcome') -eq 'skipped' }).Count
            Refused = @($res | Where-Object { (& $o $_ 'Outcome') -eq 'refused' }); Failed = @($res | Where-Object { (& $o $_ 'Outcome') -eq 'failed' }) } }
    if (-not $st.Installed) { return (& $r $false 'the grant procedure is not installed on this database -- today''s grant path is used') }
    if (-not $st.Signed) { return (& $r $false 'the grant procedure is not signed (it would have no rights) -- today''s grant path is used; an admin signs it again') }
    if (-not $st.CallerExecute) { return (& $r $false 'this identity may not EXECUTE the grant procedure (not in si_updater) -- today''s grant path is used') }
    $json = ConvertTo-SIGrantRowsJson -Rows $Rows
    $res = @(& $Invoke 'EXEC cfg.ApplyComponentGrants @Rows = @Rows;' @{ Rows = $json } 'reader' | ForEach-Object { $_ })
    & $r $true ('through the signed procedure ({0})' -f $st.Signer) $res
}

function Format-SIGrantOutcome {
    <# PURE. A refused / failed row in plain words. #>
    param($Row)
    $o = { param($k) if ($Row -is [System.Collections.IDictionary]) { [string]$Row[$k] } else { [string]$Row.$k } }
    '{0} {1} {2} {3} {4}: {5} -- {6}' -f (& $o 'Outcome').ToUpperInvariant(), (& $o 'Action'), (& $o 'Permission'), (& $o 'Target'), $(if (& $o 'Grantee') { 'to/from ' + (& $o 'Grantee') } else { '' }), (& $o 'Seq'), (& $o 'Reason')
}

function Test-SIGrantProcedureSetup {
    <#
        REMOVE-ME once a fresh test install has proven the model (the same rule as SI_Setup_EngineLeastPrivilege: customer
        sites install with today's setup this week). PURE. Is SI_Setup_SignedGrantProcedure ON for this install? Read from
        the install's values, else the environment. OFF BY DEFAULT: only 'true' / '1' / 'yes' / 'on' turns it on.
          OFF  today's model: the updater gets db_securityadmin for the grants (setup\Grant-SIUpdaterDatabase.ps1);
          ON   the full model: the component roles, the signed procedure, si_updater with EXECUTE on it, and the updater
               WITHOUT db_securityadmin.
    #>
    param([System.Collections.IDictionary]$Values, [System.Collections.IDictionary]$Env)
    $name = 'SI_Setup_SignedGrantProcedure'
    $v = $null
    if ($Values -and $Values.Contains($name)) { $v = $Values[$name] }
    if ($null -eq $v -or "$v".Trim() -eq '') { $v = if ($Env) { if ($Env.Contains($name)) { $Env[$name] } else { $null } } else { [Environment]::GetEnvironmentVariable($name) } }
    "$v".Trim() -match '^(?i)(true|1|yes|on)$'
}
