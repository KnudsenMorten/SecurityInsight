#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE INVARDIA SUPPORT APP'S JUST-IN-TIME DATABASE GRANT: ITS TABLES, ITS FOUR SIGNED PROCEDURES AND
    THE ADMIN STEPS THAT INSTALL THEM (#1021; framework DOCS/REQUIREMENTS.md SECAUDIT-1a, 4a "never lose SQL access",
    4b "consent means support always works"). The ONE source of this SQL: sql\si-pro-settings.sql carries the schema block
    word for word (the static test compares them), setup\Install-SISupportGrantProcedure.ps1 and the guided install run
    the admin steps, the job caj-si-support-grant and the heartbeat call the procedures.

    THE MODEL
      * cfg.SupportConsent      ONE row: the Support app (client id) and the level the CUSTOMER consented to (troubleshoot |
                                setup). Written by the customer's admin (Grant-SISupportAccess, the guided install: Source
                                customer) or ONCE, into an empty table, by the updater (Source derived, from the Support
                                app's Key Vault role). A trigger refuses every other writer -- the engine can never name a
                                principal or raise a level.
      * cfg.SupportJitMarker    one row per role a grant holds open: the role, the Support app's SID, whether the membership
                                was there BEFORE the grant (PreExisting), when it expires. Written in the SAME transaction
                                as the ALTER ROLE, so a role is never added without its marker (a crash mid-grant leaves a
                                marker that expires; nothing else).
      * cfg.SupportGrant        the journal: every open, close and expiry, who asked, why, the outcome.
      * cfg.SupportGrantOpen    adds the role of the granted level (setup = db_owner, troubleshoot = db_datareader; ALWAYS
                                the lower of the asked and the consented level) to the Support app's OWN user -- the SID
                                comes from cfg.SupportConsent, never from a parameter -- with maxUntil at most 8 h ahead.
                                A new open extends the open markers.
      * cfg.SupportGrantClose   removes what the open markers added (PreExisting = 0) and NOTHING ELSE: never removes a user,
                                never the read-only role si_support_read, never another principal. The Support app's open
                                sessions are ended (best effort).
      * cfg.SupportGrantSweep   the same, for the markers past their expiry only. Called by the grant job on every start,
                                by the heartbeat on every tick and by the web app every 5 minutes -- three independent
                                revokers, so a grant never outlives maxUntil because one of them did not run.
      * cfg.SupportGrantStatus  read only: signed, consent, the user, the read-only role, the open grant, an overdue or a
                                standing db_owner (a membership no open marker explains).
    The procedures are SIGNED by an in-database certificate whose user is a member of db_owner (owner decision 2026-11-01)
    -- the only way a caller without rights can add a member to a fixed role. EXPIRY 2099-12-31, a random password made
    inside SQL and never returned, the PRIVATE KEY REMOVED after signing: ALTERING a procedure drops its signature and nobody
    can sign it again but an admin. The schema file creates the procedures ONCE (IF OBJECT_ID ... IS NULL) and never alters
    them -- the updater cannot change a signed procedure (DENY ALTER), so a release's changed procedure reaches an existing
    install ONLY through the admin steps: their schema step drops a procedure whose text is EXACTLY an earlier release's
    (its SHA-256 listed in Earlier) and creates it again from this release's text; the sign step then signs it. Until an
    admin runs them there, the earlier procedure stays signed and working. The admin signs only a procedure whose text is
    exactly this release's (SHA-256, line endings ignored); a text changed by hand is never dropped and never signed.
    Tables and procedures are plain dbo-owned objects in cfg: the procedures write the tables through the ownership chain;
    the signature is needed only for the role change, the catalog reads of another principal and ending its sessions.

    PURE (text only). Strict-mode safe; PS 5.1 and 7.
#>

$script:SISupportGrant = [ordered]@{
    Marker       = 'si-support-grant v1'
    # a support session is at most this long (framework rule, owner 2026-11-04): the open procedure and the job both refuse more
    MaxHours     = 8
    # the SHA-256 (as the sign step computes it) of each procedure text an EARLIER release created -- exactly these, nothing
    # else: the admin steps drop such a procedure and create it again from this release's text, then sign it. A text that
    # is neither this release's nor listed here (changed by hand) is never dropped; the sign step refuses it.
    Earlier      = [ordered]@{
        # the open procedure as released 2026-11-01..2026-11-05: a session of up to 24 hours
        Open = @('0x7EDB463124FA33DA4FA52CB12B19D7BA1B66ED4CF10A18492740A685DAE18C85')
    }
    SignerPrefix = 'si_support_signer'
    ReadRole     = 'si_support_read'
    Procedures   = @('cfg.SupportGrantOpen', 'cfg.SupportGrantClose', 'cfg.SupportGrantSweep', 'cfg.SupportGrantStatus')
    Tables       = @('cfg.SupportConsent', 'cfg.SupportGrant', 'cfg.SupportJitMarker')
    # the role each level grants -- the ONLY roles a grant ever adds or removes
    LevelRole    = [ordered]@{ troubleshoot = 'db_datareader'; setup = 'db_owner' }
    # who may EXECUTE what (the engine through SI-EngineGrants, the web app through SI-ManagementGrants -- the admin step
    # grants the same, so a database the updater never reaches -- the ledger, the data database -- has them too)
    Execute      = [ordered]@{ si_engine = @('cfg.SupportGrantOpen', 'cfg.SupportGrantClose', 'cfg.SupportGrantSweep', 'cfg.SupportGrantStatus'); si_web = @('cfg.SupportGrantSweep') }
    # the THROW numbers of the procedures -> the job's result word
    # (text keys: an ordered dictionary indexed with a NUMBER is indexed by position)
    Errors       = [ordered]@{ '51801' = 'not-prepared'; '51802' = 'bad-request'; '51803' = 'no-consent'; '51804' = 'not-prepared'; '51805' = 'failed'; '51806' = 'refused' }
}

function Get-SISupportGrantContract { $script:SISupportGrant }

function Get-SISupportGrantSignedCheckSql {
    <# PURE. The statement every changing procedure starts with: refuse when THIS procedure is not signed by a support signer. #>
    "IF (NOT EXISTS (SELECT 1 FROM sys.crypt_properties AS cp JOIN sys.certificates AS c ON c.thumbprint = cp.thumbprint WHERE cp.major_id = @@PROCID AND c.name LIKE N'$($script:SISupportGrant.SignerPrefix)%'))`n" +
    "        THROW 51801, N'the support grant procedure is not signed -- Install-SISupportGrantProcedure has not run on this database', 1;"
}

function Get-SISupportGrantProcedureText {
    <# PURE. The CREATE PROCEDURE text of one of the four procedures (-Name Open | Close | Sweep | Status), LF line endings,
       no trailing line break -- exactly what the schema block creates and SQL Server stores. #>
    param([Parameter(Mandatory)][ValidateSet('Open', 'Close', 'Sweep', 'Status')][string]$Name)
    $m = $script:SISupportGrant.Marker
    $px = $script:SISupportGrant.SignerPrefix
    $rr = $script:SISupportGrant.ReadRole
    $signed = Get-SISupportGrantSignedCheckSql
    $user = "type NOT IN ('R', 'A', 'C', 'K')"
    $hours = [int]$script:SISupportGrant.MaxHours
    $maxMinutes = $hours * 60 + 2   # two minutes for the clock difference between the job and SQL Server
    switch ($Name) {
        'Open' {
            $t = @"
CREATE PROCEDURE cfg.SupportGrantOpen
    @RequestId nvarchar(64), @Level nvarchar(16), @MaxUntilUtc nvarchar(40), @Reason nvarchar(400), @Ticket nvarchar(128) = NULL, @StartedBy nvarchar(256) = NULL
AS
BEGIN
    -- $m (SecurityInsight #1021): the Invardia Support app's just-in-time grant. The principal is ALWAYS the Support app of
    -- cfg.SupportConsent -- never a parameter; the level is the lower of the asked and the consented one; at most $hours hours.
    SET NOCOUNT ON; SET XACT_ABORT ON;
    $signed
    DECLARE @now datetime2(0) = SYSUTCDATETIME();
    DECLARE @until datetime2(0) = TRY_CONVERT(datetime2(0), REPLACE(REPLACE(@MaxUntilUtc, N'Z', N''), N'+00:00', N''), 126);
    IF @Level IS NULL OR @Level NOT IN (N'troubleshoot', N'setup') THROW 51802, N'the level must be troubleshoot or setup', 1;
    IF @until IS NULL OR @until <= @now OR @until > DATEADD(MINUTE, $maxMinutes, @now) THROW 51802, N'maxUntil must be a UTC time in the next $hours hours', 1;
    IF LEN(LTRIM(RTRIM(ISNULL(@Reason, N'')))) = 0 OR LEN(@Reason) > 200 THROW 51802, N'a reason of at most 200 characters is required', 1;
    IF TRY_CONVERT(uniqueidentifier, @RequestId) IS NULL THROW 51802, N'the request id must be a GUID', 1;
    DECLARE @app uniqueidentifier, @consent nvarchar(16);
    SELECT @app = AppId, @consent = [Level] FROM cfg.SupportConsent WHERE Id = 1;
    IF @app IS NULL THROW 51803, N'no consent: the customer has not granted the Invardia Support app access here (Grant-SISupportAccess)', 1;
    DECLARE @sid varbinary(85) = CONVERT(varbinary(16), @app);
    DECLARE @uid int, @user sysname;
    SELECT TOP (1) @uid = principal_id, @user = name FROM sys.database_principals WHERE sid = @sid AND principal_id > 4 AND $user;
    IF @uid IS NULL THROW 51804, N'the Invardia Support app has no database user here -- Install-SISupportGrantProcedure makes it', 1;
    DECLARE @granted nvarchar(16) = CASE WHEN @Level = N'setup' AND @consent = N'setup' THEN N'setup' ELSE N'troubleshoot' END;
    DECLARE @role sysname = CASE @granted WHEN N'setup' THEN N'db_owner' ELSE N'db_datareader' END;
    DECLARE @grant uniqueidentifier = CONVERT(uniqueidentifier, @RequestId), @pre bit, @s nvarchar(400), @lk int;
    BEGIN TRANSACTION;
    EXEC @lk = sys.sp_getapplock @Resource = N'si-support-grant', @LockMode = N'Exclusive', @LockOwner = N'Transaction', @LockTimeout = 60000;
    IF @lk < 0 THROW 51805, N'another support grant holds the lock -- try again', 1;
    -- a new open extends what is open
    UPDATE cfg.SupportJitMarker SET ExpiresUtc = @until WHERE ClosedUtc IS NULL AND ExpiresUtc < @until;
    IF (NOT EXISTS (SELECT 1 FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL AND RoleName = @role AND Sid = @sid))
    BEGIN
        SET @pre = CASE WHEN EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.member_principal_id = @uid AND m.role_principal_id = DATABASE_PRINCIPAL_ID(@role)) THEN 1 ELSE 0 END;
        IF @pre = 0 BEGIN SET @s = N'ALTER ROLE ' + QUOTENAME(@role) + N' ADD MEMBER ' + QUOTENAME(@user) + N';'; EXEC (@s); END
        INSERT cfg.SupportJitMarker (GrantId, RoleName, Sid, PreExisting, ExpiresUtc) VALUES (@grant, @role, @sid, @pre, @until);
    END
    INSERT cfg.SupportGrant (GrantId, Action, LevelAsked, LevelGranted, MaxUntilUtc, Reason, Ticket, StartedBy, Outcome)
    VALUES (@grant, N'open', @Level, @granted, @until, LEFT(@Reason, 200), LEFT(@Ticket, 64), LEFT(@StartedBy, 256), N'granted');
    COMMIT TRANSACTION;
    -- THE READ-BACK, from the catalog (never from the request)
    SELECT DB_NAME() AS [Database], @granted AS LevelGranted, @role AS RoleName,
           CONVERT(nvarchar(19), (SELECT MAX(ExpiresUtc) FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL), 126) + N'Z' AS UntilUtc,
           CASE WHEN EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.member_principal_id = @uid AND m.role_principal_id = DATABASE_PRINCIPAL_ID(@role)) THEN 1 ELSE 0 END AS RoleHeld,
           CASE WHEN EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.member_principal_id = @uid AND m.role_principal_id = DATABASE_PRINCIPAL_ID(N'$rr')) THEN 1 ELSE 0 END AS ReadOnlyHeld;
END
"@
        }
        { $_ -in 'Close', 'Sweep' } {
            $isClose = ($Name -eq 'Close')
            $filter = if ($isClose) { 'ClosedUtc IS NULL' } else { 'ClosedUtc IS NULL AND ExpiresUtc <= @now' }
            $params = if ($isClose) { '    @RequestId nvarchar(64), @Reason nvarchar(400) = NULL, @StartedBy nvarchar(256) = NULL' } else { '    @By nvarchar(64) = NULL' }
            $why = if ($isClose) { 'closed' } else { 'expired' }
            $check = if ($isClose) { "    IF TRY_CONVERT(uniqueidentifier, @RequestId) IS NULL THROW 51802, N'the request id must be a GUID', 1;`n" } else { '' }
            $journal = if ($isClose) {
                "    INSERT cfg.SupportGrant (GrantId, Action, Reason, StartedBy, Outcome, Detail) VALUES (CONVERT(uniqueidentifier, @RequestId), N'close', LEFT(@Reason, 200), LEFT(@StartedBy, 256), N'revoked', CONVERT(nvarchar(20), @closed) + N' open marker(s) closed, ' + CONVERT(nvarchar(20), @n) + N' role membership(s) removed');"
            } else {
                "    IF @closed > 0 INSERT cfg.SupportGrant (GrantId, Action, Reason, StartedBy, Outcome, Detail) VALUES (NEWID(), N'expire', N'maxUntil passed', LEFT(@By, 256), N'revoked', CONVERT(nvarchar(20), @closed) + N' open marker(s) expired, ' + CONVERT(nvarchar(20), @n) + N' role membership(s) removed');"
            }
            $t = @"
CREATE PROCEDURE cfg.SupportGrant$Name
$params
AS
BEGIN
    -- $m (SecurityInsight #1021): removes ONLY what the open grant markers added (PreExisting = 0) -- never a user, never
    -- the read-only role $rr, never another principal, never a membership the Support app had before the grant.
    SET NOCOUNT ON; SET XACT_ABORT ON;
    $signed
$check    DECLARE @now datetime2(0) = SYSUTCDATETIME(), @s nvarchar(400), @role sysname, @sid varbinary(85), @user sysname, @n int = 0, @closed int = 0, @lk int;
    DECLARE @todo TABLE (MarkerId bigint PRIMARY KEY, RoleName sysname, Sid varbinary(85), PreExisting bit);
    DECLARE @gone TABLE (Sid varbinary(85) PRIMARY KEY);
    BEGIN TRANSACTION;
    EXEC @lk = sys.sp_getapplock @Resource = N'si-support-grant', @LockMode = N'Exclusive', @LockOwner = N'Transaction', @LockTimeout = 60000;
    IF @lk < 0 THROW 51805, N'another support grant holds the lock -- try again', 1;
    INSERT @todo (MarkerId, RoleName, Sid, PreExisting) SELECT MarkerId, RoleName, Sid, PreExisting FROM cfg.SupportJitMarker WITH (UPDLOCK) WHERE $filter;
    SET @closed = @@ROWCOUNT;
    -- a role is removed only when a closing marker ADDED it and no marker that stays open holds the same role
    DECLARE c CURSOR LOCAL FAST_FORWARD FOR
        SELECT DISTINCT t.RoleName, t.Sid FROM @todo AS t
        WHERE t.PreExisting = 0 AND t.RoleName IN (N'db_owner', N'db_datareader')
          AND NOT EXISTS (SELECT 1 FROM cfg.SupportJitMarker AS k WHERE k.ClosedUtc IS NULL AND k.RoleName = t.RoleName AND k.Sid = t.Sid
                          AND NOT EXISTS (SELECT 1 FROM @todo AS x WHERE x.MarkerId = k.MarkerId));
    OPEN c; FETCH NEXT FROM c INTO @role, @sid;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        SET @user = (SELECT TOP (1) name FROM sys.database_principals WHERE sid = @sid AND principal_id > 4 AND $user);
        IF @user IS NOT NULL AND EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.member_principal_id = DATABASE_PRINCIPAL_ID(@user) AND m.role_principal_id = DATABASE_PRINCIPAL_ID(@role))
        BEGIN
            SET @s = N'ALTER ROLE ' + QUOTENAME(@role) + N' DROP MEMBER ' + QUOTENAME(@user) + N';'; EXEC (@s); SET @n = @n + 1;
            IF (NOT EXISTS (SELECT 1 FROM @gone WHERE Sid = @sid)) INSERT @gone (Sid) VALUES (@sid);
        END
        FETCH NEXT FROM c INTO @role, @sid;
    END
    CLOSE c; DEALLOCATE c;
    UPDATE m SET ClosedUtc = @now, CloseReason = N'$why' FROM cfg.SupportJitMarker AS m JOIN @todo AS t ON t.MarkerId = m.MarkerId;
$journal
    COMMIT TRANSACTION;
    -- the Support app's open sessions end with its grant (a role change reaches a session only when it signs in again).
    -- Best effort: a session that cannot be ended is counted, never a failure.
    DECLARE @spid int, @ended int = 0, @notEnded int = 0;
    DECLARE k CURSOR LOCAL FAST_FORWARD FOR
        SELECT DISTINCT s.session_id FROM sys.dm_exec_sessions AS s JOIN @gone AS g ON s.original_security_id = g.Sid OR s.security_id = g.Sid WHERE s.session_id <> @@SPID;
    OPEN k; FETCH NEXT FROM k INTO @spid;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        BEGIN TRY SET @s = N'KILL ' + CONVERT(nvarchar(12), @spid) + N';'; EXEC (@s); SET @ended = @ended + 1; END TRY
        BEGIN CATCH SET @notEnded = @notEnded + 1; END CATCH
        FETCH NEXT FROM k INTO @spid;
    END
    CLOSE k; DEALLOCATE k;
    -- THE READ-BACK (4a): what is still open, and whether the Support app still has its read-only access
    DECLARE @app uniqueidentifier = (SELECT AppId FROM cfg.SupportConsent WHERE Id = 1);
    DECLARE @asid varbinary(85) = CASE WHEN @app IS NULL THEN (SELECT TOP (1) Sid FROM @todo) ELSE CONVERT(varbinary(16), @app) END;
    DECLARE @auid int = (SELECT TOP (1) principal_id FROM sys.database_principals WHERE sid = @asid AND principal_id > 4 AND $user);
    SELECT DB_NAME() AS [Database], @closed AS Closed, @n AS RolesRemoved, @ended AS SessionsEnded, @notEnded AS SessionsNotEnded,
           (SELECT COUNT(*) FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL) AS StillOpen,
           CONVERT(nvarchar(19), (SELECT MAX(ExpiresUtc) FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL), 126) + N'Z' AS UntilUtc,
           (SELECT COUNT(*) FROM @todo AS t JOIN sys.database_principals AS u ON u.sid = t.Sid AND u.principal_id > 4
              JOIN sys.database_role_members AS m ON m.member_principal_id = u.principal_id AND m.role_principal_id = DATABASE_PRINCIPAL_ID(t.RoleName)
             WHERE t.PreExisting = 0 AND NOT EXISTS (SELECT 1 FROM cfg.SupportJitMarker AS o WHERE o.ClosedUtc IS NULL AND o.RoleName = t.RoleName AND o.Sid = t.Sid)) AS RolesStillHeld,
           CASE WHEN @auid IS NULL THEN 0 ELSE 1 END AS UserPresent,
           CASE WHEN EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.member_principal_id = @auid AND m.role_principal_id = DATABASE_PRINCIPAL_ID(N'$rr')) THEN 1 ELSE 0 END AS ReadOnlyHeld;
END
"@
        }
        'Status' {
            $t = @"
CREATE PROCEDURE cfg.SupportGrantStatus
AS
BEGIN
    -- $m (SecurityInsight #1021): READ ONLY -- the Support app's access in this database, for the heartbeat and the job.
    SET NOCOUNT ON;
    DECLARE @now datetime2(0) = SYSUTCDATETIME(), @app uniqueidentifier, @consent nvarchar(16), @sid varbinary(85), @uid int;
    SELECT @app = AppId, @consent = [Level] FROM cfg.SupportConsent WHERE Id = 1;
    IF @app IS NOT NULL SET @sid = CONVERT(varbinary(16), @app);
    SELECT TOP (1) @uid = principal_id FROM sys.database_principals WHERE sid = @sid AND principal_id > 4 AND $user;
    SELECT DB_NAME() AS [Database],
           CASE WHEN EXISTS (SELECT 1 FROM sys.crypt_properties AS cp JOIN sys.certificates AS c ON c.thumbprint = cp.thumbprint WHERE cp.major_id = @@PROCID AND c.name LIKE N'$px%') THEN 1 ELSE 0 END AS Signed,
           @consent AS Consent,
           CASE WHEN @uid IS NULL THEN 0 ELSE 1 END AS UserPresent,
           CASE WHEN EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.member_principal_id = @uid AND m.role_principal_id = DATABASE_PRINCIPAL_ID(N'$rr')) THEN 1 ELSE 0 END AS ReadOnlyHeld,
           (SELECT COUNT(*) FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL) AS JitOpen,
           CONVERT(nvarchar(19), (SELECT MAX(ExpiresUtc) FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL), 126) + N'Z' AS JitUntilUtc,
           CASE WHEN EXISTS (SELECT 1 FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL AND RoleName = N'db_owner') THEN N'setup'
                WHEN EXISTS (SELECT 1 FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL) THEN N'troubleshoot' ELSE NULL END AS JitLevel,
           (SELECT COUNT(*) FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL AND ExpiresUtc <= @now) AS JitOverdue,
           CASE WHEN @uid IS NOT NULL AND EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.member_principal_id = @uid AND m.role_principal_id = DATABASE_PRINCIPAL_ID(N'db_owner'))
                 AND NOT EXISTS (SELECT 1 FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL AND RoleName = N'db_owner' AND PreExisting = 0) THEN 1 ELSE 0 END AS StandingOwner;
END
"@
        }
    }
    # no trailing line break: the text is stored exactly as the schema block sends it (the sign step compares its hash)
    ($t -replace "`r`n", "`n").TrimEnd()
}

function Get-SISupportGrantProcedureSha256 {
    <# PURE. The SHA-256 (hex) of a procedure's text as SQL Server stores it (UTF-16LE), line endings removed -- what the
       sign step compares with REPLACE(OBJECT_DEFINITION(...), CHAR(13), '') before it signs anything. #>
    param([Parameter(Mandatory)][ValidateSet('Open', 'Close', 'Sweep', 'Status')][string]$Name)
    $bytes = [Text.Encoding]::Unicode.GetBytes((Get-SISupportGrantProcedureText -Name $Name))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { '0x' + (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('X2') }) -join '') } finally { $sha.Dispose() }
}

function Get-SISupportGrantSchemaSql {
    <#
        PURE. THE SCHEMA BLOCK -- the tables, the consent trigger and the four procedures, created ONCE (each guarded statement
        its own blank-line batch). sql\si-pro-settings.sql carries it between the GENERATED SUPPORT GRANT markers, word for
        word; the admin step runs it on the identity ledger and the data database (which the updater does not reach).
        Additive only; nothing here alters a procedure that is there (that would drop its signature).
    #>
    $b = New-Object System.Collections.Generic.List[string]
    $b.Add("IF SCHEMA_ID(N'cfg') IS NULL EXEC (N'CREATE SCHEMA cfg');")
    $b.Add(@"
-- the customer's consent to the Invardia Support app: ONE row (Id = 1)
IF OBJECT_ID(N'cfg.SupportConsent') IS NULL
CREATE TABLE cfg.SupportConsent (
    Id           TINYINT          NOT NULL CONSTRAINT PK_SupportConsent PRIMARY KEY CONSTRAINT CK_SupportConsent_One CHECK (Id = 1),
    AppId        UNIQUEIDENTIFIER NOT NULL,
    [Level]      NVARCHAR(16)     NOT NULL CONSTRAINT CK_SupportConsent_Level CHECK ([Level] IN (N'troubleshoot', N'setup')),
    Source       NVARCHAR(16)     NOT NULL CONSTRAINT CK_SupportConsent_Source CHECK (Source IN (N'customer', N'derived')),
    ConsentedBy  NVARCHAR(256)    NOT NULL,
    ConsentedUtc DATETIME2(0)     NOT NULL CONSTRAINT DF_SupportConsent_ConsentedUtc DEFAULT SYSUTCDATETIME()
);
"@)
    $b.Add(@"
-- the journal of every open, close and expiry
IF OBJECT_ID(N'cfg.SupportGrant') IS NULL
CREATE TABLE cfg.SupportGrant (
    EntryId      BIGINT           IDENTITY(1,1) NOT NULL CONSTRAINT PK_SupportGrant PRIMARY KEY,
    GrantId      UNIQUEIDENTIFIER NOT NULL,
    Action       NVARCHAR(8)      NOT NULL CONSTRAINT CK_SupportGrant_Action CHECK (Action IN (N'open', N'close', N'expire')),
    LevelAsked   NVARCHAR(16)     NULL,
    LevelGranted NVARCHAR(16)     NULL,
    MaxUntilUtc  DATETIME2(0)     NULL,
    Reason       NVARCHAR(200)    NULL,
    Ticket       NVARCHAR(64)     NULL,
    StartedBy    NVARCHAR(256)    NULL,
    Outcome      NVARCHAR(16)     NOT NULL,
    Detail       NVARCHAR(400)    NULL,
    AtUtc        DATETIME2(0)     NOT NULL CONSTRAINT DF_SupportGrant_AtUtc DEFAULT SYSUTCDATETIME()
);
"@)
    $b.Add(@"
-- one row per role a grant holds open, written with the role change in one transaction
IF OBJECT_ID(N'cfg.SupportJitMarker') IS NULL
CREATE TABLE cfg.SupportJitMarker (
    MarkerId     BIGINT           IDENTITY(1,1) NOT NULL CONSTRAINT PK_SupportJitMarker PRIMARY KEY,
    GrantId      UNIQUEIDENTIFIER NOT NULL,
    RoleName     SYSNAME          NOT NULL CONSTRAINT CK_SupportJitMarker_Role CHECK (RoleName IN (N'db_owner', N'db_datareader')),
    Sid          VARBINARY(85)    NOT NULL,
    PreExisting  BIT              NOT NULL,
    AddedUtc     DATETIME2(0)     NOT NULL CONSTRAINT DF_SupportJitMarker_AddedUtc DEFAULT SYSUTCDATETIME(),
    ExpiresUtc   DATETIME2(0)     NOT NULL,
    ClosedUtc    DATETIME2(0)     NULL,
    CloseReason  NVARCHAR(16)     NULL
);
"@)
    $b.Add(@"
-- the consent is the customer's: written by the database owner (the customer's admin: Grant-SISupportAccess, the guided
-- install), or ONCE into the empty table by the updater as a DERIVED consent (from the Support app's Key Vault role). Every
-- other writer is refused -- the engine can never name a principal or raise a level.
EXEC (N'CREATE OR ALTER TRIGGER cfg.TR_SupportConsent_Owner ON cfg.SupportConsent AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    IF ISNULL(IS_ROLEMEMBER(N''db_owner''), 0) = 1 RETURN;
    IF (NOT EXISTS (SELECT 1 FROM deleted)) AND NOT EXISTS (SELECT 1 FROM inserted WHERE Source <> N''derived'')
       AND (SELECT COUNT(*) FROM cfg.SupportConsent) = (SELECT COUNT(*) FROM inserted)
       AND (ISNULL(IS_ROLEMEMBER(N''si_updater''), 0) = 1 OR ISNULL(IS_ROLEMEMBER(N''db_ddladmin''), 0) = 1) RETURN;
    -- the level the customer set in the Invardia portal, applied by the UPDATER from its own call to Invardia (framework
    -- SUPPORT ACCESS point 2): it may write a row only as ConsentedBy N''Invardia portal'', or remove the row (level none)
    IF (ISNULL(IS_ROLEMEMBER(N''si_updater''), 0) = 1 OR ISNULL(IS_ROLEMEMBER(N''db_ddladmin''), 0) = 1)
       AND NOT EXISTS (SELECT 1 FROM inserted WHERE Source <> N''customer'' OR ConsentedBy <> N''Invardia portal'') RETURN;
    THROW 51806, N''cfg.SupportConsent: the consent is written by the customer admin (Grant-SISupportAccess) only'', 1;
END');
"@)
    foreach ($n in 'Open', 'Close', 'Sweep', 'Status') {
        $text = (Get-SISupportGrantProcedureText -Name $n).Replace("'", "''")
        $b.Add(("-- {0}: created once, never altered (that would drop its signature)`nIF OBJECT_ID(N'cfg.SupportGrant{1}') IS NULL EXEC (N'{2}');" -f $script:SISupportGrant.Marker, $n, $text.TrimEnd()))
    }
    # LF only, whatever line endings this file was checked out with (the schema file's block is compared with it)
    ($b.ToArray() -join "`n`n") -replace "`r`n", "`n"
}

function Get-SISupportGrantSchemaFileBlock {
    <# PURE. The block as sql\si-pro-settings.sql carries it: the markers + Get-SISupportGrantSchemaSql. #>
    "-- >>> GENERATED SUPPORT GRANT (engine\pro-settings\SI-SupportGrantSql.ps1, Get-SISupportGrantSchemaSql) -- do not edit by hand`n`n" +
    (Get-SISupportGrantSchemaSql) + "`n`n-- <<< GENERATED SUPPORT GRANT"
}

function Get-SISupportGrantRenewSql {
    <#
        PURE. ADMIN STEPS ONLY (never in the schema file the updater runs): drops each procedure whose stored text is EXACTLY
        an earlier release's (its SHA-256 in the contract's Earlier list, compared as the sign step compares), so the schema
        that follows creates it from this release's text and the sign step signs it. A text that is this release's, or that
        no release made (changed by hand), is left as it is. '' when no earlier text is listed.
    #>
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($script:SISupportGrant.Earlier.Keys)) {
        $hashes = @($script:SISupportGrant.Earlier[$n] | Where-Object { "$_" -match '^0x[0-9A-Fa-f]{64}$' })
        if (-not $hashes.Count) { continue }
        $p = 'cfg.SupportGrant' + $n
        $out.Add(("-- {2}: an earlier release's {0}: replaced by this release's text below, then signed by the sign step`nIF OBJECT_ID(N'{0}') IS NOT NULL AND HASHBYTES('SHA2_256', REPLACE(OBJECT_DEFINITION(OBJECT_ID(N'{0}')), NCHAR(13), N'')) IN ({1}) DROP PROCEDURE {0};" -f $p, ($hashes -join ', '), $script:SISupportGrant.Marker))
    }
    ($out.ToArray() -join "`n`n")
}

function ConvertTo-SISupportGrantSid {
    <# PURE. The SID of an Entra application's database user: its CLIENT id as [guid]::ToByteArray() (0x + 32 hex). #>
    param([Parameter(Mandatory)][string]$ClientId)
    '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-SISupportGrantAdminSteps {
    <#
        PURE. THE ADMIN STEPS, per database, in order -- run by the database owner (the guided install, or Invardia support
        through setup\Install-SISupportGrantProcedure.ps1). Each ONLY ADDS; nothing of today's access is removed (4a: the old
        path stays until the later, customer-run cut-over). @{ Step; Purpose; Sql }, each ending with one value (Value):
          schema   the tables, the trigger and the procedures (created once)
          user     the Support app's own database user (WITH SID = its client id, TYPE = E) when it has none, and the
                   read-only role si_support_read (VIEW DEFINITION, VIEW DATABASE STATE -- metadata and health, no data)
                   with the Support app in it: the standing read-only access 4a requires BEFORE anything is made JIT
          consent  the consent row (-Level, -Source customer | derived) -- a customer consent replaces a derived one; a
                   derived one never replaces a customer one
          sign     only a procedure whose text is THIS release's is signed (else refused, nothing signed); a new
                   certificate (2099, private key removed) whose user is in db_owner -- only when not signed yet
          grants   EXECUTE as the contract says (si_engine, si_web), DENY of writes on the three tables to the product's
                   roles, DENY ALTER on the procedures to si_updater
        -Level '' leaves the consent step out (a database whose consent is copied later).
    #>
    param([Parameter(Mandatory)][string]$ClientId, [string]$UserName = 'invardia-support-app', [ValidateSet('', 'troubleshoot', 'setup')][string]$Level = '',
          [ValidateSet('customer', 'derived')][string]$Source = 'customer', [string]$By = 'setup')
    $null = [guid]$ClientId
    $c = $script:SISupportGrant
    $sid = ConvertTo-SISupportGrantSid -ClientId $ClientId
    $un = $UserName.Replace(']', ']]'); $uq = $UserName.Replace("'", "''")
    $byq = ([string]$By).Replace("'", "''"); if ($byq.Length -gt 200) { $byq = $byq.Substring(0, 200) }
    $rr = $c.ReadRole; $px = $c.SignerPrefix
    $steps = [System.Collections.Generic.List[object]]::new()
    $steps.Add([pscustomobject]@{ Step = 'schema'; Purpose = 'the support grant tables, the consent trigger and the four procedures (created once, never altered; an earlier release''s procedure is replaced by this release''s)'
        Sql = (Get-SISupportGrantRenewSql) + "`n`n" + (Get-SISupportGrantSchemaSql) + "`nSELECT N'schema' AS Value;" })
    $steps.Add([pscustomobject]@{ Step = 'user'; Purpose = ('the Support app''s own database user and the standing READ-ONLY role {0} (metadata and health, no data)' -f $rr); Sql = @"
DECLARE @s nvarchar(400);
DECLARE @n sysname = (SELECT TOP (1) name FROM sys.database_principals WHERE sid = $sid AND principal_id > 4 AND type NOT IN ('R', 'A', 'C', 'K'));
IF @n IS NULL BEGIN EXEC (N'CREATE USER [$($un.Replace("'", "''"))] WITH SID = $sid, TYPE = E'); SET @n = N'$uq'; END
IF DATABASE_PRINCIPAL_ID(N'$rr') IS NULL EXEC (N'CREATE ROLE [$rr] AUTHORIZATION [dbo]');
GRANT VIEW DEFINITION TO [$rr];
GRANT VIEW DATABASE STATE TO [$rr];
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.role_principal_id = DATABASE_PRINCIPAL_ID(N'$rr') AND m.member_principal_id = DATABASE_PRINCIPAL_ID(@n))
BEGIN SET @s = N'ALTER ROLE [$rr] ADD MEMBER ' + QUOTENAME(@n) + N';'; EXEC (@s); END
SELECT @n + N'|' + CASE WHEN EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.role_principal_id = DATABASE_PRINCIPAL_ID(N'$rr') AND m.member_principal_id = DATABASE_PRINCIPAL_ID(@n)) THEN N'1' ELSE N'0' END AS Value;
"@ })
    if ($Level) {
        $guard = if ($Source -eq 'derived') { "AND NOT EXISTS (SELECT 1 FROM cfg.SupportConsent WHERE Id = 1 AND Source = N'customer')" } else { '' }
        $steps.Add([pscustomobject]@{ Step = 'consent'; Purpose = ('the customer''s consent: level {0} ({1})' -f $Level, $Source); Sql = @"
IF NOT EXISTS (SELECT 1 FROM cfg.SupportConsent WHERE Id = 1)
    INSERT cfg.SupportConsent (Id, AppId, [Level], Source, ConsentedBy) VALUES (1, CONVERT(uniqueidentifier, N'$(([guid]$ClientId).ToString())'), N'$Level', N'$Source', N'$byq');
ELSE IF NOT EXISTS (SELECT 1 FROM cfg.SupportConsent WHERE Id = 1 AND AppId = CONVERT(uniqueidentifier, N'$(([guid]$ClientId).ToString())') AND [Level] = N'$Level' AND Source = N'$Source') $guard
    UPDATE cfg.SupportConsent SET AppId = CONVERT(uniqueidentifier, N'$(([guid]$ClientId).ToString())'), [Level] = N'$Level', Source = N'$Source', ConsentedBy = N'$byq', ConsentedUtc = SYSUTCDATETIME() WHERE Id = 1;
SELECT [Level] + N'|' + Source AS Value FROM cfg.SupportConsent WHERE Id = 1;
"@ })
    }
    $hashes = foreach ($n in 'Open', 'Close', 'Sweep', 'Status') { "(N'cfg.SupportGrant$n', $(Get-SISupportGrantProcedureSha256 -Name $n))" }
    $steps.Add([pscustomobject]@{ Step = 'sign'; Purpose = 'sign the four procedures with a new in-database certificate in db_owner (expiry 2099, private key removed) -- only this release''s text, only when unsigned'; Sql = @"
DECLARE @want TABLE (Name sysname PRIMARY KEY, Sha varbinary(32));
INSERT @want (Name, Sha) VALUES $($hashes -join ', ');
IF EXISTS (SELECT 1 FROM @want AS w WHERE OBJECT_ID(w.Name) IS NULL)
    THROW 51807, N'a support grant procedure is missing -- run the schema step first; nothing was signed', 1;
IF EXISTS (SELECT 1 FROM @want AS w WHERE HASHBYTES('SHA2_256', REPLACE(OBJECT_DEFINITION(OBJECT_ID(w.Name)), NCHAR(13), N'')) <> w.Sha)
    THROW 51807, N'a support grant procedure is not this release''s text (changed by hand?) -- nothing was signed', 1;
IF EXISTS (SELECT 1 FROM @want AS w WHERE NOT EXISTS (SELECT 1 FROM sys.crypt_properties AS cp JOIN sys.certificates AS c ON c.thumbprint = cp.thumbprint
                                                     WHERE cp.major_id = OBJECT_ID(w.Name) AND c.name LIKE N'$px%'))
BEGIN
    DECLARE @s nvarchar(max), @name sysname;
    DECLARE @cert sysname = N'${px}_' + FORMAT(SYSUTCDATETIME(), 'yyyyMMddHHmmssfff');
    DECLARE @pw nvarchar(200) = CONVERT(nvarchar(36), NEWID()) + N'Si1!' + CONVERT(nvarchar(36), NEWID());
    SET @s = N'CREATE CERTIFICATE ' + QUOTENAME(@cert) + N' ENCRYPTION BY PASSWORD = ' + QUOTENAME(@pw, '''')
           + N' WITH SUBJECT = ''SecurityInsight support grant signer'', EXPIRY_DATE = ''20991231'';';
    EXEC sys.sp_executesql @s;
    SET @s = N'CREATE USER ' + QUOTENAME(@cert) + N' FROM CERTIFICATE ' + QUOTENAME(@cert) + N';'; EXEC sys.sp_executesql @s;
    SET @s = N'ALTER ROLE db_owner ADD MEMBER ' + QUOTENAME(@cert) + N';'; EXEC sys.sp_executesql @s;
    DECLARE w CURSOR LOCAL FAST_FORWARD FOR SELECT Name FROM @want ORDER BY Name;
    OPEN w; FETCH NEXT FROM w INTO @name;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        -- an earlier support signature on the procedure goes first (one signer per procedure)
        DECLARE @old sysname = (SELECT TOP (1) c.name FROM sys.crypt_properties AS cp JOIN sys.certificates AS c ON c.thumbprint = cp.thumbprint WHERE cp.major_id = OBJECT_ID(@name) AND c.name LIKE N'$px%');
        IF @old IS NOT NULL BEGIN SET @s = N'DROP SIGNATURE FROM ' + @name + N' BY CERTIFICATE ' + QUOTENAME(@old) + N';'; EXEC sys.sp_executesql @s; END
        SET @s = N'ADD SIGNATURE TO ' + @name + N' BY CERTIFICATE ' + QUOTENAME(@cert) + N' WITH PASSWORD = ' + QUOTENAME(@pw, '''') + N';';
        EXEC sys.sp_executesql @s;
        FETCH NEXT FROM w INTO @name;
    END
    CLOSE w; DEALLOCATE w;
    SET @s = N'ALTER CERTIFICATE ' + QUOTENAME(@cert) + N' REMOVE PRIVATE KEY;'; EXEC sys.sp_executesql @s;
END
SELECT CONVERT(nvarchar(10), COUNT(*)) AS Value FROM @want AS w WHERE EXISTS (SELECT 1 FROM sys.crypt_properties AS cp JOIN sys.certificates AS c ON c.thumbprint = cp.thumbprint
                                                     WHERE cp.major_id = OBJECT_ID(w.Name) AND c.name LIKE N'$px%' AND c.pvt_key_encryption_type = 'NA');
"@ })
    $g = New-Object System.Collections.Generic.List[string]
    foreach ($role in $c.Execute.Keys) {
        foreach ($p in $c.Execute[$role]) { $g.Add("IF DATABASE_PRINCIPAL_ID(N'$role') IS NOT NULL GRANT EXECUTE ON OBJECT::$p TO [$role];") }
    }
    foreach ($t in $c.Tables) { foreach ($role in 'si_engine', 'si_web', 'si_mcp', 'si_tagging', 'si_templates') { $g.Add("IF DATABASE_PRINCIPAL_ID(N'$role') IS NOT NULL DENY INSERT, UPDATE, DELETE ON OBJECT::$t TO [$role];") } }
    foreach ($p in $c.Procedures) { $g.Add("IF DATABASE_PRINCIPAL_ID(N'si_updater') IS NOT NULL DENY ALTER ON OBJECT::$p TO [si_updater];") }
    $g.Add("SELECT N'grants' AS Value;")
    $steps.Add([pscustomobject]@{ Step = 'grants'; Purpose = 'EXECUTE for the engine (open, close, sweep, status) and the web app (sweep); no product role may write the three tables; the updater may not alter the procedures'; Sql = ($g.ToArray() -join "`n") })
    $steps.ToArray()
}

function Get-SISupportGrantStateSql {
    <#
        PURE. READ ONLY, one row -- the read-back of the admin steps (the caller's own catalog view; the admin sees all):
        the tables, the procedures (there / this release's text / signed / private key gone / signer in db_owner), the
        Support app's user and its read-only role, the consent, si_engine's EXECUTE on the four procedures.
    #>
    param([Parameter(Mandatory)][string]$ClientId)
    $sid = ConvertTo-SISupportGrantSid -ClientId $ClientId
    $c = $script:SISupportGrant; $px = $c.SignerPrefix; $rr = $c.ReadRole
    $hashes = foreach ($n in 'Open', 'Close', 'Sweep', 'Status') { "(N'cfg.SupportGrant$n', $(Get-SISupportGrantProcedureSha256 -Name $n))" }
    @"
DECLARE @want TABLE (Name sysname PRIMARY KEY, Sha varbinary(32));
INSERT @want (Name, Sha) VALUES $($hashes -join ', ');
DECLARE @uid int = (SELECT TOP (1) principal_id FROM sys.database_principals WHERE sid = $sid AND principal_id > 4 AND type NOT IN ('R', 'A', 'C', 'K'));
SELECT DB_NAME() AS [Database],
       (SELECT COUNT(*) FROM (VALUES (N'cfg.SupportConsent'), (N'cfg.SupportGrant'), (N'cfg.SupportJitMarker')) AS t(n) WHERE OBJECT_ID(t.n) IS NOT NULL) AS Tables,
       (SELECT COUNT(*) FROM @want WHERE OBJECT_ID(Name) IS NOT NULL) AS Procedures,
       (SELECT COUNT(*) FROM @want AS w WHERE HASHBYTES('SHA2_256', REPLACE(OBJECT_DEFINITION(OBJECT_ID(w.Name)), NCHAR(13), N'')) = w.Sha) AS [Current],
       (SELECT COUNT(*) FROM @want AS w WHERE EXISTS (SELECT 1 FROM sys.crypt_properties AS cp JOIN sys.certificates AS c ON c.thumbprint = cp.thumbprint
           WHERE cp.major_id = OBJECT_ID(w.Name) AND c.name LIKE N'$px%' AND c.pvt_key_encryption_type = 'NA' AND c.expiry_date >= '20991231')) AS Signed,
       CASE WHEN EXISTS (SELECT 1 FROM sys.certificates AS c JOIN sys.database_principals AS u ON u.sid = c.sid
                         JOIN sys.database_role_members AS m ON m.member_principal_id = u.principal_id AND m.role_principal_id = DATABASE_PRINCIPAL_ID(N'db_owner')
                         WHERE c.name LIKE N'$px%') THEN 1 ELSE 0 END AS SignerOwner,
       CASE WHEN @uid IS NULL THEN 0 ELSE 1 END AS UserPresent,
       CASE WHEN EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.member_principal_id = @uid AND m.role_principal_id = DATABASE_PRINCIPAL_ID(N'$rr')) THEN 1 ELSE 0 END AS ReadOnlyHeld,
       CASE WHEN OBJECT_ID(N'cfg.SupportConsent') IS NULL THEN NULL ELSE (SELECT [Level] + N'|' + Source FROM cfg.SupportConsent WHERE Id = 1) END AS Consent,
       (SELECT COUNT(*) FROM @want AS w JOIN sys.database_permissions AS dp ON dp.class = 1 AND dp.major_id = OBJECT_ID(w.Name)
         WHERE dp.grantee_principal_id = DATABASE_PRINCIPAL_ID(N'si_engine') AND dp.permission_name = N'EXECUTE' AND dp.[state] IN ('G', 'W')) AS EngineExecute;
"@
}

function ConvertFrom-SISupportGrantState {
    <# PURE. The row of Get-SISupportGrantStateSql -> @{ Database; Tables; Procedures; Current; Signed; SignerOwner; UserPresent;
       ReadOnlyHeld; Consent; EngineExecute; Ok; Lines }. Ok = the model is in place on this database. #>
    param($Row)
    $get = { param($k) if ($null -eq $Row) { $null } elseif ($Row -is [System.Collections.IDictionary]) { $Row[$k] } elseif ($Row -is [System.Data.DataRow]) { $Row[$k] } elseif ($Row.PSObject.Properties[$k]) { $Row.$k } else { $null } }
    $s = { param($k) $v = & $get $k; if ($null -eq $v -or $v -is [System.DBNull]) { '' } else { [string]$v } }
    $i = { param($k) $n = 0; [void][int]::TryParse((& $s $k), [ref]$n); $n }
    $b = { param($k) (& $s $k) -in '1', 'True' }
    $o = [ordered]@{ Database = (& $s 'Database'); Tables = (& $i 'Tables'); Procedures = (& $i 'Procedures'); Current = (& $i 'Current'); Signed = (& $i 'Signed')
                     SignerOwner = (& $b 'SignerOwner'); UserPresent = (& $b 'UserPresent'); ReadOnlyHeld = (& $b 'ReadOnlyHeld'); Consent = (& $s 'Consent')
                     EngineExecute = (& $i 'EngineExecute'); Ok = $false; Lines = @() }
    $l = New-Object System.Collections.Generic.List[string]
    if ($o.Tables -lt 3) { $l.Add(('{0} of the 3 support grant tables are there' -f $o.Tables)) }
    if ($o.Procedures -lt 4) { $l.Add(('{0} of the 4 support grant procedures are there' -f $o.Procedures)) }
    elseif ($o.Current -lt 4) { $l.Add(('{0} of the 4 procedures are this release''s text' -f $o.Current)) }
    if ($o.Signed -lt 4) { $l.Add(('{0} of the 4 procedures are signed (certificate to 2099, private key removed)' -f $o.Signed)) }
    if (-not $o.SignerOwner) { $l.Add('the signer certificate''s user is not in db_owner') }
    if (-not $o.UserPresent) { $l.Add('the Support app has no database user here') }
    elseif (-not $o.ReadOnlyHeld) { $l.Add(('the Support app is not in the read-only role {0}' -f $script:SISupportGrant.ReadRole)) }
    if (-not $o.Consent) { $l.Add('no consent is recorded here') }
    if ($o.EngineExecute -lt 4) { $l.Add(('the engine (si_engine) may EXECUTE {0} of the 4 procedures' -f $o.EngineExecute)) }
    $o.Lines = $l.ToArray(); $o.Ok = ($l.Count -eq 0)
    [pscustomobject]$o
}

function Get-SISupportStandingOffSql {
    <#
        PURE. #1151 (1) SEC-01 / OPEN-01 -- THE SUPPORT APP'S STANDING db_owner TAKEN OFF, IN ONE DATABASE, ONLY WHEN THE
        JUST-IN-TIME PATH READS BACK IN THAT SAME DATABASE, IN THE SAME BATCH. Run by the database setup job (caj-si-dbinit,
        a member of the SQL admin group) when the updater names the Support app (SI_DBINIT_SUPPORT_STANDING_OFF).
        The read-back that must hold before anything is changed -- every item, in this database:
          * the Support app's own user (by the SID of its client id) is in the read-only role si_support_read;
          * the four support grant procedures are there, THIS release's text, signed (signer certificate to 2099, private key
            removed) and the signer's user is in db_owner;
          * the engine (si_engine) may EXECUTE all four; the customer's consent is recorded (cfg.SupportConsent);
          * no just-in-time grant is open right now (an open grant's db_owner is never taken here).
        Only then: ONE transaction that takes the Support app's own user out of db_owner -- nothing else. The user and
        its read-only role stay; no other principal, no group, no server administrator is ever touched (the break-glass
        Entra admin of the server is the admin GROUP, outside any database: this batch cannot reach it).
        Never THROWS for "not ready": it answers. ONE row: State (off = taken off now and read back | none = it holds no
        db_owner | absent = it has no user here | kept = not ready, nothing changed), Roles (its roles after), Why (kept: the
        items that do not hold).
    #>
    param([Parameter(Mandatory)][string]$ClientId)
    $c = $script:SISupportGrant
    $sid = ConvertTo-SISupportGrantSid -ClientId $ClientId
    $px = $c.SignerPrefix; $rr = $c.ReadRole
    $hashes = foreach ($n in 'Open', 'Close', 'Sweep', 'Status') { "(N'cfg.SupportGrant$n', $(Get-SISupportGrantProcedureSha256 -Name $n))" }
    @"
SET XACT_ABORT ON;
DECLARE @want TABLE (Name sysname PRIMARY KEY, Sha varbinary(32));
INSERT @want (Name, Sha) VALUES $($hashes -join ', ');
DECLARE @uid int = (SELECT TOP (1) principal_id FROM sys.database_principals WHERE sid = $sid AND principal_id > 4 AND type NOT IN ('R', 'A', 'C', 'K'));
DECLARE @state nvarchar(10) = N'kept', @why nvarchar(1000) = N'', @s nvarchar(400), @consent int = 0, @open int = 0;
IF @uid IS NULL SET @state = N'absent';
ELSE IF NOT EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.member_principal_id = @uid AND m.role_principal_id = DATABASE_PRINCIPAL_ID(N'db_owner')) SET @state = N'none';
ELSE
BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.member_principal_id = @uid AND m.role_principal_id = DATABASE_PRINCIPAL_ID(N'$rr')) SET @why += N'not in the read-only role $rr; ';
    IF (SELECT COUNT(*) FROM @want AS w WHERE HASHBYTES('SHA2_256', REPLACE(OBJECT_DEFINITION(OBJECT_ID(w.Name)), NCHAR(13), N'')) = w.Sha) < 4 SET @why += N'the 4 support grant procedures are not all this release''s text; ';
    IF (SELECT COUNT(*) FROM @want AS w WHERE EXISTS (SELECT 1 FROM sys.crypt_properties AS cp JOIN sys.certificates AS c ON c.thumbprint = cp.thumbprint
           WHERE cp.major_id = OBJECT_ID(w.Name) AND c.name LIKE N'$px%' AND c.pvt_key_encryption_type = 'NA' AND c.expiry_date >= '20991231')) < 4 SET @why += N'the 4 procedures are not all signed; ';
    IF NOT EXISTS (SELECT 1 FROM sys.certificates AS c JOIN sys.database_principals AS u ON u.sid = c.sid
                   JOIN sys.database_role_members AS m ON m.member_principal_id = u.principal_id AND m.role_principal_id = DATABASE_PRINCIPAL_ID(N'db_owner')
                   WHERE c.name LIKE N'$px%') SET @why += N'the signer is not in db_owner; ';
    IF (SELECT COUNT(*) FROM @want AS w JOIN sys.database_permissions AS dp ON dp.class = 1 AND dp.major_id = OBJECT_ID(w.Name)
        WHERE dp.grantee_principal_id = DATABASE_PRINCIPAL_ID(N'si_engine') AND dp.permission_name = N'EXECUTE' AND dp.[state] IN ('G', 'W')) < 4 SET @why += N'the engine may not run all 4 procedures; ';
    IF OBJECT_ID(N'cfg.SupportConsent') IS NOT NULL EXEC sys.sp_executesql N'SELECT @o = COUNT(*) FROM cfg.SupportConsent WHERE Id = 1;', N'@o int OUTPUT', @o = @consent OUTPUT;
    IF @consent = 0 SET @why += N'no consent is recorded; ';
    IF OBJECT_ID(N'cfg.SupportJitMarker') IS NOT NULL EXEC sys.sp_executesql N'SELECT @o = COUNT(*) FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL AND ExpiresUtc > SYSUTCDATETIME();', N'@o int OUTPUT', @o = @open OUTPUT;
    IF @open > 0 SET @why += N'a just-in-time grant is open now; ';
    IF @why = N''
    BEGIN
        BEGIN TRANSACTION;
        SET @s = N'ALTER ROLE db_owner DROP MEMBER ' + QUOTENAME(USER_NAME(@uid)) + N';'; EXEC (@s);
        COMMIT TRANSACTION;
        IF NOT EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.member_principal_id = @uid AND m.role_principal_id = DATABASE_PRINCIPAL_ID(N'db_owner')) SET @state = N'off';
        ELSE SET @why = N'db_owner is still read back after the change; ';
    END
END
SELECT @state AS State,
       ISNULL((SELECT STRING_AGG(CONVERT(nvarchar(max), r.name), N',') FROM sys.database_role_members AS m
               JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = @uid), N'') AS Roles,
       LEFT(@why, 400) AS Why;
"@
}

function ConvertFrom-SISupportStandingOffRow {
    <# PURE. The row of Get-SISupportStandingOffSql -> @{ State (off | none | absent | kept); Roles[]; Why }. Anything that is not
       one of the four words is 'kept' (never read as "taken off"). #>
    param($Row)
    $get = { param($k) if ($null -eq $Row) { '' } elseif ($Row -is [System.Collections.IDictionary]) { [string]$Row[$k] } elseif ($Row -is [System.Data.DataRow]) { $v = $Row[$k]; if ($v -is [System.DBNull]) { '' } else { [string]$v } } elseif ($Row.PSObject.Properties[$k]) { [string]$Row.$k } else { '' } }
    $st = (& $get 'State').Trim().ToLowerInvariant()
    if ($st -notin 'off', 'none', 'absent', 'kept') { $st = 'kept' }
    $roles = @((& $get 'Roles') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $why = (& $get 'Why').Trim().TrimEnd(';').Trim()
    if ($st -eq 'kept' -and -not $why) { $why = 'no answer from the database' }
    if ($st -eq 'off' -and $roles -contains 'db_owner') { $st = 'kept'; $why = 'db_owner is still read back after the change' }
    [pscustomobject]@{ State = $st; Roles = $roles; Why = $why }
}

function Get-SISupportGrantCallSql {
    <# PURE. The one statement the job / the heartbeat / the web app sends: parameters only (never a value in the text). #>
    param([Parameter(Mandatory)][ValidateSet('Open', 'Close', 'Sweep', 'Status')][string]$Name)
    switch ($Name) {
        'Open'   { 'EXEC cfg.SupportGrantOpen @RequestId = @RequestId, @Level = @Level, @MaxUntilUtc = @MaxUntilUtc, @Reason = @Reason, @Ticket = @Ticket, @StartedBy = @StartedBy;' }
        'Close'  { 'EXEC cfg.SupportGrantClose @RequestId = @RequestId, @Reason = @Reason, @StartedBy = @StartedBy;' }
        'Sweep'  { 'EXEC cfg.SupportGrantSweep @By = @By;' }
        'Status' { "IF OBJECT_ID(N'cfg.SupportGrantStatus') IS NOT NULL EXEC cfg.SupportGrantStatus;" }
    }
}

function Get-SISupportGrantErrorResult {
    <#
        PURE. What a failed call means: the procedure's THROW number (from the exception, its inner exceptions, or the text)
        -> the job's result word (not-prepared | bad-request | no-consent | failed | refused). Anything else = 'failed'.
    #>
    param($ErrorRecord)
    $ex = if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ErrorRecord.Exception } else { $ErrorRecord }
    $nums = New-Object System.Collections.Generic.List[int]
    $text = ''
    for ($e = $ex; $null -ne $e; $e = $e.InnerException) {
        $text += ' ' + [string]$e.Message
        if ($e.PSObject.Properties['Number']) { try { $nums.Add([int]$e.Number) } catch { } }
    }
    foreach ($m in [regex]::Matches($text, '\b(518\d\d)\b')) { $nums.Add([int]$m.Groups[1].Value) }
    foreach ($n in $nums) { $k = [string]$n; if ($script:SISupportGrant.Errors.Contains($k)) { return [string]$script:SISupportGrant.Errors[$k] } }
    if ($text -match '(?i)not signed') { return 'not-prepared' }
    if ($text -match '(?i)no consent') { return 'no-consent' }
    if ($text -match '(?i)Could not find stored procedure') { return 'not-prepared' }
    'failed'
}
