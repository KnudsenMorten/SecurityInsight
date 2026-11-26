#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight -- the Invardia Support app's database access: a STANDING READ-ONLY user, admin ONLY JUST IN TIME
    (framework SECAUDIT-1a; owner 2026-11-04 point 3, and 2026-11-25: "the old support scripts can only give just-in-time
    access, never permanent").

.DESCRIPTION
    The Support app (the install answer supportAppId: an Entra application in the customer's tenant, created and
    consented to by the customer) runs the product's setup scripts for the customer later, through a recorded support
    session.

    WHAT IT HOLDS STANDING -- the only thing any install, update, repair or private-network path gives it:
      * ITS OWN CONTAINED DATABASE USER in each product database (the Pro database, the identity ledger, the data database
        where the install has one), made from the application's CLIENT id without a directory lookup --
            CREATE USER [<name>] WITH SID = 0x<the client id's 16 bytes, [guid]::ToByteArray() order, as hex>, TYPE = E
        -- in the read-only role si_support_read (VIEW DEFINITION + VIEW DATABASE STATE: metadata and health, no data);
      * with the support grant's tables, its four SIGNED procedures and the customer's consent next to it (engine\
        pro-settings\SI-SupportGrantSql.ps1, Get-SISupportGrantAdminSteps -- the one source of those steps).
    ADMIN ONLY JUST IN TIME: more than read-only comes only through the signed support grant procedures (the support grant
    job caj-si-support-grant, started through its queue), for at most 8 hours, at most at the level the customer consented
    to, and it closes by itself. The Support app is NEVER made a member of the SQL admin group and NEVER put in db_owner
    by an install, an update, a repair or the private-network move.

    THE STANDING-ADMIN FUNCTIONS of earlier releases (Get-SISupportAppDatabaseAccessSql = db_owner, Set-SISupportAppGroupMember
    = the SQL admin group, Invoke-SISupportAppDatabaseAccess -Apply, Invoke-SISupportAppDatabaseEnsure -Apply) stay ONLY for
    the two deliberate ways back: setup\Remove-SISupportStandingAccess.ps1 -Rollback (puts back what its record says) and
    -LegacyStandingAccess (OFF; only on Invardia's word: setup\Grant-SISupportAccess.ps1, setup\Grant-SISupportAppDatabase.ps1).
    Without -LegacyStandingAccess each of them REFUSES to write (said, nothing changed). A source scan test holds every
    other path to that (tests\pester\SIv3-SupportStandingGuards.Tests.ps1).
    This SUPERSEDES framework section 4.1b's "both parts, permanently, never removed" (owner 2026-10-18), which SECAUDIT-1a
    replaced. The generic add of a managed identity to the SQL admin group (id-si-sql, id-si-dbinit) is
    Set-SISqlAdminGroupMember -- never called for the Support app.

    The UPDATE never adds anything for the Support app; it only takes the standing db_owner of an earlier release off where
    the just-in-time path reads back (setup\_shared\SI-SupportStandingUpdate.ps1). The heartbeat REPORTS the state, read only
    (engine\_shared\SI-SupportSqlAccess.ps1, which is also the one home of the SID and the read statements -- loaded below).
    Every function takes its outside calls as script blocks, so the tests run them offline:
        -Graph { param([string]$Method, [string]$Uri, $Body) }   Microsoft Graph; returns the answer, throws on a refusal
        -Sql   { param([string]$Database, [string]$Query) }      ONE scalar from that database; throws on a refusal
#>

# cfg.InstallState 'SupportApp' = the Support app's client id, so the heartbeat (which has no install answers) knows which
# application this is about. (The name is written out in each function: a file loaded from inside a function must not
# depend on a value of its own script scope.)

# the SID, the read of its user, the record's read, the service principal and the member-side membership check
. ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', '_shared', 'SI-SupportSqlAccess.ps1'))
# #1092: a member added right after its group was made waits out Entra replication, then is read back
. ([IO.Path]::Combine($PSScriptRoot, 'SI-GroupMemberAdd.ps1'))

# ======================================================================================================================
# THE STANDING ACCESS EVERY PATH GIVES (SECAUDIT-1a): its own user in the read-only role si_support_read -- nothing more.
# ======================================================================================================================

function Get-SISupportStandingRefusalText {
    <# PURE. The one sentence a refused standing grant says (SECAUDIT-1a, #1374). -What: what would have been given. #>
    param([string]$What = 'standing admin (db_owner, the SQL admin group)')
    ('refused: {0} is not given to the Invardia Support app -- it holds only its read-only database user (si_support_read); admin comes only just in time, through the signed support grant procedures (max 8 h, at the consented level). Only -LegacyStandingAccess (on Invardia''s word) or setup\Remove-SISupportStandingAccess.ps1 -Rollback puts standing admin back' -f $What)
}

function Get-SISupportAppReadOnlyAccessSql {
    <# PURE, SELF-CONTAINED (the support SQL job carries it word for word). The statements that give the Support app its
       own database user (by SID -- no directory lookup; an existing user with that SID is reused whatever its name) in the
       read-only role si_support_read (made when the database has none: VIEW DEFINITION + VIEW DATABASE STATE -- metadata and
       health, no data). The same right as the support grant's 'user' step (engine\pro-settings\SI-SupportGrantSql.ps1).
       NEVER db_owner, never any other role: it only ADDS the user and that one membership. Ends with ONE value:
       '<user>|<db_owner 1/0>|<si_support_read 1/0>' (a db_owner of an earlier release is READ, never changed here). #>
    param([Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$ClientId)
    $sid = '0x' + ((([guid]$ClientId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
    $un = $UserName.Replace(']', ']]').Replace("'", "''"); $uq = $UserName.Replace("'", "''")
    $has = { param($r) "CASE WHEN EXISTS (SELECT 1 FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = u.principal_id AND r.name = N'$r') THEN N'1' ELSE N'0' END" }
    @"
DECLARE @s nvarchar(400);
DECLARE @n sysname = (SELECT TOP (1) name FROM sys.database_principals WHERE sid = $sid AND principal_id > 4 AND type NOT IN ('R', 'A', 'C', 'K'));
IF @n IS NULL BEGIN EXEC (N'CREATE USER [$un] WITH SID = $sid, TYPE = E'); SET @n = N'$uq'; END
IF DATABASE_PRINCIPAL_ID(N'si_support_read') IS NULL EXEC (N'CREATE ROLE [si_support_read] AUTHORIZATION [dbo]');
GRANT VIEW DEFINITION TO [si_support_read];
GRANT VIEW DATABASE STATE TO [si_support_read];
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.role_principal_id = DATABASE_PRINCIPAL_ID(N'si_support_read') AND m.member_principal_id = DATABASE_PRINCIPAL_ID(@n))
BEGIN SET @s = N'ALTER ROLE [si_support_read] ADD MEMBER ' + QUOTENAME(@n) + N';'; EXEC (@s); END
SELECT ISNULL((SELECT TOP (1) u.name COLLATE DATABASE_DEFAULT + N'|' + $(& $has 'db_owner') + N'|' + $(& $has 'si_support_read')
    FROM sys.database_principals u WHERE u.sid = $sid AND u.principal_id > 4), N'') AS Value;
"@
}

function ConvertFrom-SISupportAppReadRoleAnswer {
    <# PURE, SELF-CONTAINED. '<user>|<db_owner 1/0>|<si_support_read 1/0>' (Get-SISupportAppReadRoleCheckSql,
       Get-SISupportAppReadOnlyAccessSql) -> @{ User; Owner; ReadOnly; Hidden }. '' = no user; '?' = Hidden. #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = ([string]$Text).Trim()
    if ($t -eq '?') { return [pscustomobject]@{ User = ''; Owner = $false; ReadOnly = $false; Hidden = $true } }
    if (-not $t) { return [pscustomobject]@{ User = ''; Owner = $false; ReadOnly = $false; Hidden = $false } }
    $p = $t.Split('|')
    if ($p.Count -lt 3) { return [pscustomobject]@{ User = $p[0]; Owner = ($p.Count -gt 1 -and $p[1] -eq '1'); ReadOnly = $false; Hidden = $false } }
    $user = ($p[0..($p.Count - 3)]) -join '|'
    [pscustomobject]@{ User = $user; Owner = ($p[$p.Count - 2] -eq '1'); ReadOnly = ($p[$p.Count - 1] -eq '1'); Hidden = $false }
}

function Invoke-SISupportAppReadOnlyAccess {
    <#
        SECAUDIT-1a: the Support app's own database user in the READ-ONLY role si_support_read, in each of -Databases. READ
        FIRST: a database that already has it gets no statement. With -Apply a missing user / membership is made and READ
        BACK. NEVER db_owner, never the SQL admin group. A db_owner held from an earlier release is READ and said (Owner),
        never changed here (the update takes it off where the just-in-time path reads back; Invardia support's
        Remove-SISupportStandingAccess.ps1 otherwise). Never throws. SELF-CONTAINED apart from
        ConvertTo-SISqlSidFromClientId, ConvertFrom-SISupportAppReadRoleAnswer, Get-SISupportAppReadOnlyAccessSql and
        Get-SISupportAppRightHint (the support SQL job carries all of them). Returns one @{ Database; State; User; Owner; Detail }:
          present   it was there                      granted   made now, and read back
          missing   not there (-Apply not given, or made but not there when read back)
          failed    the statements were refused       unchecked the database could not be read / hides its users
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][string[]]$Databases, [Parameter(Mandatory)][string]$ClientId,
          [string]$UserName, [switch]$Apply, [scriptblock]$Retry)
    $null = [guid]$ClientId
    if (-not $UserName) { $UserName = 'invardia-support-app' }
    $sid = ConvertTo-SISqlSidFromClientId -ClientId $ClientId
    $check = @"
SELECT ISNULL((SELECT TOP (1) u.name COLLATE DATABASE_DEFAULT + N'|' + CASE WHEN EXISTS (SELECT 1 FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = u.principal_id AND r.name = N'db_owner') THEN N'1' ELSE N'0' END
    + N'|' + CASE WHEN EXISTS (SELECT 1 FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = u.principal_id AND r.name = N'si_support_read') THEN N'1' ELSE N'0' END
    FROM sys.database_principals u WHERE u.sid = $sid AND u.principal_id > 4),
    CASE WHEN ISNULL(HAS_PERMS_BY_NAME(NULL, NULL, N'VIEW DEFINITION'), 0) = 1 THEN N'' ELSE N'?' END) AS Value;
"@
    $ownerNote = { param($o) if ($o) { ' -- it STILL holds db_owner from an earlier release (not changed here; the update or Invardia support takes it off)' } else { '' } }
    foreach ($db in @($Databases | Where-Object { $_ } | Select-Object -Unique)) {
        $row = { param($s, $u, $o, $d) [pscustomobject]@{ Database = $db; State = $s; User = [string]$u; Owner = [bool]$o; Detail = [string]$d } }
        $have = $null; $readWhy = ''
        try { $have = ConvertFrom-SISupportAppReadRoleAnswer ([string](& $Sql $db $check)) }
        catch {
            $readWhy = [string]$_.Exception.Message
            if ($Retry) { try { $have = ConvertFrom-SISupportAppReadRoleAnswer ([string](& $Retry $db $check)); $readWhy = '' } catch { $readWhy = [string]$_.Exception.Message } }
        }
        if ($readWhy) { & $row 'unchecked' '' $false ('could not be checked: {0}' -f $readWhy); continue }
        if ($have.User -and $have.ReadOnly) { & $row 'present' $have.User $have.Owner ('its own database user is there, in the read-only role si_support_read' + (& $ownerNote $have.Owner)); continue }
        if (-not $Apply) {
            if ($have.Hidden) { & $row 'unchecked' '' $false 'could not be checked: this connection cannot see the database''s users (no VIEW DEFINITION)'; continue }
            & $row 'missing' $have.User $have.Owner ($(if ($have.User) { 'its own database user is there, but not in the read-only role si_support_read' } else { 'it has no database user of its own' }) + (& $ownerNote $have.Owner))
            continue
        }
        try {
            $now = ConvertFrom-SISupportAppReadRoleAnswer ([string](& $Sql $db (Get-SISupportAppReadOnlyAccessSql -UserName $UserName -ClientId $ClientId)))
            if ($now.User -and $now.ReadOnly) { & $row 'granted' $now.User $now.Owner ('its own database user was made in the read-only role si_support_read (no db_owner), and read back' + (& $ownerNote $now.Owner)) }
            else { & $row 'missing' $now.User $now.Owner 'the statements ran, but its own database user in the read-only role is not there when read back' }
        } catch { & $row 'failed' '' $false ('its own read-only database user could not be made: {0}{1}' -f $_.Exception.Message, (Get-SISupportAppRightHint -Message $_.Exception.Message -Kind database)) }
    }
}

# ======================================================================================================================
# STANDING ADMIN OF EARLIER RELEASES -- ONLY for -LegacyStandingAccess (on Invardia's word). Every write below REFUSES
# without it. (setup\Remove-SISupportStandingAccess.ps1 -Rollback writes its own statements from its record.)
# ======================================================================================================================

function Get-SISupportAppDatabaseAccessSql {
    <# PURE. The statements that give the Support app its own database user (by SID -- no directory lookup, no FROM
       EXTERNAL PROVIDER; an existing user with that SID is reused whatever its name) and db_owner. Safe to repeat: each
       statement runs only when its result is not there. It only ADDS. Ends with the same scalar as the check. #>
    param([Parameter(Mandatory)][string]$UserName, [Parameter(Mandatory)][string]$ClientId)
    $sid = ConvertTo-SISqlSidFromClientId -ClientId $ClientId
    $n = $UserName.Replace(']', ']]'); $q = $UserName.Replace("'", "''")
    @"
DECLARE @n sysname = (SELECT TOP (1) name FROM sys.database_principals WHERE sid = $sid AND principal_id > 4);
IF @n IS NULL BEGIN CREATE USER [$n] WITH SID = $sid, TYPE = E; SET @n = N'$q'; END
IF NOT EXISTS (SELECT 1 FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id
               JOIN sys.database_principals u ON u.principal_id = m.member_principal_id WHERE r.name = N'db_owner' AND u.sid = $sid AND u.principal_id > 4)
BEGIN DECLARE @s nvarchar(400) = N'ALTER ROLE db_owner ADD MEMBER ' + QUOTENAME(@n); EXEC (@s); END
$(Get-SISupportAppDatabaseCheckSql -ClientId $ClientId)
"@
}

function Get-SISupportAppWhoAmISql {
    <# PURE. READS ONLY. Who this connection is in the database, and whether it has the owner role: '<user>|1' or '<user>|0'. #>
    "SELECT USER_NAME() + N'|' + CAST(ISNULL(IS_ROLEMEMBER(N'db_owner'), 0) AS nvarchar(4))"
}

function Get-SISupportAppSignedInName {
    <# PURE. Who a database says the Support app is, for the proof's sentence: "dbo" = let in through the server's admin
       group; any other name = its own database user. Both are its access (section 4.1b). #>
    param([AllowNull()][AllowEmptyString()][string]$User)
    if (([string]$User).Trim() -ieq 'dbo') { return 'dbo (through the server''s admin group)' }
    '{0} (its own database user)' -f [string]$User
}

function Get-SISupportAppRecordSql {
    <# PURE. Records the Support app's client id on the install (cfg.InstallState 'SupportApp'), so the heartbeat -- which
       has no install answers -- knows which application to report on. Nothing when the table is not there; nothing
       written when the value is already that. Ends with the recorded value as one scalar. #>
    param([Parameter(Mandatory)][string]$ClientId, [string]$By = 'setup')
    $id = ([guid]$ClientId).ToString(); $b = ([string]$By).Replace("'", "''")
    if ($b.Length -gt 200) { $b = $b.Substring(0, 200) }
    $name = 'SupportApp'
    @"
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL
BEGIN
    IF NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'$name')
        INSERT cfg.InstallState (Name, Value, UpdatedBy) VALUES (N'$name', N'$id', N'$b');
    ELSE IF NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'$name' AND Value = N'$id')
        UPDATE cfg.InstallState SET Value = N'$id', UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'$b' WHERE Name = N'$name';
END
SELECT CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'$name'), N'') END;
"@
}

function Get-SISupportAppRightHint {
    <# PURE. Why a refused write was refused, in the words of the right it needs -- appended to "could not be added / made: ...".
       -Kind group: a member of the admin group (role-assignable: Privileged Role Administrator); database: CREATE USER +
       db_owner (the database owner role, or the server's admin group). '' when the error does not say it is a right. #>
    param([AllowNull()][AllowEmptyString()][string]$Message, [ValidateSet('group', 'database')][string]$Kind)
    if ([string]$Message -notmatch '(?i)Authorization_RequestDenied|Insufficient privileges|\b403\b|Forbidden|permission|not have permission|denied') { return '' }
    if ($Kind -eq 'group') { return ' -- adding a member to the database admin group (a role-assignable group) needs Privileged Role Administrator (or Global Administrator), which this identity does not hold' }
    ' -- making a database user and adding it to a database role needs the database owner role (or membership of the server''s admin group), which this identity does not hold'
}

function Set-SISupportAppGroupMember {
    <#
        STANDING ADMIN (earlier releases) -- the Support app's service principal as a member of the database server's admin
        group. ONLY with -LegacyStandingAccess (OFF; on Invardia's word); without it -Apply is REFUSED (State 'refused',
        nothing changed) and a plan only READS. A managed identity of the install (id-si-sql, id-si-dbinit) is added with
        Set-SISqlAdminGroupMember, never through this function. Returns Set-SISqlAdminGroupMember's @{ State; Detail }.
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$ServicePrincipalId,
          [switch]$Apply, [switch]$LegacyStandingAccess, [scriptblock]$Sleep, [int[]]$Waits = @(5, 10, 15, 30), [int]$LimitSeconds = 300, [scriptblock]$Print)
    if ($Apply -and -not $LegacyStandingAccess) {
        return [pscustomobject]@{ State = 'refused'; Detail = (Get-SISupportStandingRefusalText -What 'membership of the SQL admin group') }
    }
    Set-SISqlAdminGroupMember -Graph $Graph -GroupId $GroupId -ServicePrincipalId $ServicePrincipalId -Apply:$Apply -Sleep $Sleep -Waits $Waits -LimitSeconds $LimitSeconds -Print $Print
}

function Set-SISqlAdminGroupMember {
    <#
        A service principal (an install's OWN managed identity: id-si-sql, id-si-dbinit -- never the Invardia Support app,
        SECAUDIT-1a) is a member of the database server's admin group: added when it is not (a member is never added twice,
        NOTHING IS EVER REMOVED) and READ BACK from the directory. Never throws.
        Returns @{ State; Detail }:  present | added | planned (-Apply not given) | failed (the add was refused: "the member
        could not be added: ...") | unchecked (the directory could not be asked, or the add was accepted but does not read back yet).
    #>
    param([Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][string]$GroupId, [Parameter(Mandatory)][string]$ServicePrincipalId,
          [switch]$Apply, [scriptblock]$Sleep, [int[]]$Waits = @(5, 10, 15, 30),
          # #1092: how long a "not found" answer to the add (a group made moments ago) is waited for, and where that is said
          [int]$LimitSeconds = 300, [scriptblock]$Print)
    $res = { param($s, $d) [pscustomobject]@{ State = $s; Detail = [string]$d } }
    $is = $false
    try { $is = Test-SISupportAppGroupMember -Graph $Graph -GroupId $GroupId -ServicePrincipalId $ServicePrincipalId }
    catch { return (& $res 'unchecked' ('could not be checked: the directory did not answer whether it is a member ({0})' -f $_.Exception.Message)) }
    if ($is) { return (& $res 'present' 'already a member') }
    if (-not $Apply) { return (& $res 'planned' 'not a member -- it would be added') }
    # #1092: a group made minutes ago (Set-SISqlAdminGroup) answers 404 "Resource 'Group_<id>' does not exist" until Entra
    # has replicated it -- that answer is waited for and the add tried again, up to a stated limit, then READ BACK
    # (setup\_shared\SI-GroupMemberAdd.ps1); only past the limit is it a failure
    $a = Invoke-SIGroupMemberAddRetry -What 'the member' -Sleep $Sleep -Print $Print -LimitSeconds $LimitSeconds -ReadBackWaits $Waits `
        -Add { & $Graph 'POST' ("https://graph.microsoft.com/v1.0/groups/$GroupId/members/`$ref") @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$ServicePrincipalId" } } `
        -Test { Test-SISupportAppGroupMember -Graph $Graph -GroupId $GroupId -ServicePrincipalId $ServicePrincipalId }
    switch ($a.State) {
        'added' { return (& $res 'added' $(if ($a.WaitedSeconds) { 'added after {0} s of Entra replication, and read back from the directory' -f $a.WaitedSeconds } else { 'added, and read back from the directory' })) }
        'unchecked' { return (& $res 'unchecked' $a.Detail) }
        'notfound' { return (& $res 'failed' $a.Detail) }
        default { return (& $res 'failed' ('the member could not be added: {0}{1}' -f $a.Error, (Get-SISupportAppRightHint -Message $a.Error -Kind group))) }
    }
}

function Invoke-SISupportAppDatabaseAccess {
    <#
        STANDING ADMIN (earlier releases): the Support app's own database user with db_owner, in each of -Databases. READ
        FIRST: a database that already has it gets no statement at all. -Apply writes ONLY with -LegacyStandingAccess (OFF;
        on Invardia's word) -- without it every database answers 'refused' and NO statement is sent. It only adds. Never throws.
        Returns one @{ Database; State; User; Detail } per database:
          present   it was there                      granted   made now, and read back
          missing   not there (-Apply not given, or made but not there when read back)
          failed    the statements were refused ("its own database user could not be made: ...")
          unchecked the database could not be read, or hides its users from this connection ("could not be checked: ...")
          refused   -Apply without -LegacyStandingAccess (SECAUDIT-1a): nothing sent
    #>
    param([Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][string[]]$Databases, [Parameter(Mandatory)][string]$ClientId,
          [string]$UserName, [switch]$Apply, [switch]$LegacyStandingAccess, [scriptblock]$Retry)
    $null = [guid]$ClientId
    if (-not $UserName) { $UserName = 'invardia-support-app' }
    if ($Apply -and -not $LegacyStandingAccess) {
        $why = Get-SISupportStandingRefusalText -What 'db_owner'
        foreach ($db in @($Databases | Where-Object { $_ } | Select-Object -Unique)) { [pscustomobject]@{ Database = $db; State = 'refused'; User = ''; Detail = $why } }
        return
    }
    $check = Get-SISupportAppDatabaseCheckSql -ClientId $ClientId
    foreach ($db in @($Databases | Where-Object { $_ } | Select-Object -Unique)) {
        $row = { param($s, $u, $d) [pscustomobject]@{ Database = $db; State = $s; User = [string]$u; Detail = [string]$d } }
        $have = $null; $readWhy = ''
        try { $have = ConvertFrom-SISupportAppDatabaseAnswer ([string](& $Sql $db $check)) }
        catch {
            $readWhy = [string]$_.Exception.Message
            # a sign-in that was refused a moment after this run changed the group is tried once more, waiting (-Retry)
            if ($Retry) { try { $have = ConvertFrom-SISupportAppDatabaseAnswer ([string](& $Retry $db $check)); $readWhy = '' } catch { $readWhy = [string]$_.Exception.Message } }
        }
        if ($readWhy) { & $row 'unchecked' '' ('could not be checked: {0}' -f $readWhy); continue }
        if ($have.User -and $have.Owner) { & $row 'present' $have.User 'its own database user is there, with the owner role'; continue }
        if (-not $Apply) {
            if ($have.Hidden) { & $row 'unchecked' '' 'could not be checked: this connection cannot see the database''s users (no VIEW DEFINITION)'; continue }
            & $row 'missing' $have.User $(if ($have.User) { 'its own database user is there, but without the owner role' } else { 'it has no database user of its own' })
            continue
        }
        try {
            $now = ConvertFrom-SISupportAppDatabaseAnswer ([string](& $Sql $db (Get-SISupportAppDatabaseAccessSql -UserName $UserName -ClientId $ClientId)))
            if ($now.User -and $now.Owner) { & $row 'granted' $now.User 'its own database user was made with the owner role, and read back' }
            elseif ($now.Hidden) { & $row 'unchecked' '' 'could not be checked: the statements ran, but this connection cannot see the database''s users to read it back' }
            else { & $row 'missing' $now.User 'the statements ran, but its own database user with the owner role is not there when read back' }
        } catch { & $row 'failed' '' ('its own database user could not be made: {0}{1}' -f $_.Exception.Message, (Get-SISupportAppRightHint -Message $_.Exception.Message -Kind database)) }
    }
}

function Get-SISupportAppAdminGroupRefusal {
    <# PURE. '' when -Group (Find-SISqlAdminGroup's Group: IsAssignableToRole, SecurityEnabled) may be used as the database
       server's admin group, else why not. $null = '' (nothing found is not a refusal). #>
    param([AllowNull()]$Group)
    if ($null -eq $Group) { return '' }
    $why = @()
    if (-not [bool]$Group.IsAssignableToRole) { $why += 'it is not role-assignable' }
    if (-not [bool]$Group.SecurityEnabled) { $why += 'it is not a security group' }
    if (-not $why.Count) { return '' }
    ('{0} -- the admin group setup makes is a role-assignable security group (setup\Set-SISqlAdminGroup.ps1 makes or fixes it)' -f ($why -join ' and '))
}

function Invoke-SISupportAppDatabaseEnsure {
    <#
        STANDING ADMIN OF EARLIER RELEASES (section 4.1b, superseded by SECAUDIT-1a) -- ONLY with -LegacyStandingAccess
        (OFF; on Invardia's word). -Apply WITHOUT it is REFUSED before anything is read or written: Refused = the reason,
        Ok = $false, nothing changed. The plan (no -Apply) still reads and says what the earlier model would do.
        With -LegacyStandingAccess -- added where missing, read back, never removed. In order:
          1. READ: the Support app's service principal, the server's administrator (and the kind the server records it
             as) and the admin group -- the group the server names, else the group by any of its names (-GroupName);
          2. (a) THE SUPPORT APP IS A MEMBER of the admin group: added when it is not (-Apply), read back;
          3. THE SERVER'S ADMINISTRATOR IS THAT GROUP, RECORDED AS A GROUP. When the server names the group under another
             kind, or the Support app itself is still the administrator (a hand-back that failed), a run that was given
             -SetAdmin puts the group there as a group (-Apply) and READS IT BACK. Any other administrator (a person,
             another application) is never replaced here: the run says so, with the command;
          4. (b) ITS OWN DATABASE USER with db_owner in each database (Invoke-SISupportAppDatabaseAccess, -Apply): made
             where it is not there, read back;
          5. the client id is recorded in -RecordDatabase;
          6. THE PROOF, where it can be made: a run signed in as the Support app signs in to each database again and says
             who it is there (dbo through the group, or its own user -- either with the owner role). Otherwise "not proven".
        Without -Apply nothing is written and NO database connection is opened (the plan).
        Seams:  -GetAdmin { } -> @{ Sid; Login; PrincipalType } / $null (none set); throws when the server cannot be read
                -SetAdmin { param([string]$Name, [string]$Sid, [string]$Type) }   throws when it does not change
                -Sql      { param([string]$Database, [string]$Query, [bool]$NoWait) } -> one scalar
                -Say      { param([string]$State, [string]$Text) }
        Never throws. Returns @{ Ok; Applied; ServicePrincipal; Group; Admin; Member; Databases; GroupOk; DbUserOk; Added;
          Proof; Problems }.  Member / Admin = @{ State; Detail }; Databases = Invoke-SISupportAppDatabaseAccess's rows;
          GroupOk = (a) read back; DbUserOk = (b) read back in every database; Added = what this run added
          ('group', '<database>'); Ok = GroupOk and DbUserOk.
    #>
    param([Parameter(Mandatory)][string]$ClientId, [Parameter(Mandatory)][string[]]$Databases, [string]$RecordDatabase,
          [Parameter(Mandatory)][scriptblock]$Graph, [Parameter(Mandatory)][scriptblock]$Sql, [Parameter(Mandatory)][scriptblock]$GetAdmin, [scriptblock]$SetAdmin,
          [string]$CallerAppId, [string]$GroupName = 'grp-si-sql-admins', [switch]$Apply, [switch]$LegacyStandingAccess, [scriptblock]$Sleep, [scriptblock]$Say, [string]$By = 'setup',
          # how long a run signed in as the Support app waits for a database to let it in through the group, after THIS
          # run added the member or changed the administrator (seconds, one try after each)
          [int[]]$GroupWaits = @(30, 60))
    $null = [guid]$ClientId
    $problems = New-Object System.Collections.Generic.List[string]
    $tell = { param($s, $t) if ($Say) { try { & $Say ([string]$s) ([string]$t) } catch { } } }
    $prop = { param($o, $k) if ($null -eq $o) { $null } elseif ($o -is [System.Collections.IDictionary]) { $o[$k] } elseif ($o.PSObject.Properties[$k]) { $o.$k } else { $null } }
    $st = { param($s, $d) [pscustomobject]@{ State = [string]$s; Detail = [string]$d } }
    $nap = { param($n) if ($Sleep) { & $Sleep $n } else { Start-Sleep -Seconds $n } }
    $out = [ordered]@{ Ok = $false; Applied = [bool]$Apply; ServicePrincipal = $null; Group = $null; Admin = $null; Member = $null; Databases = @()
                       GroupOk = $false; DbUserOk = $false; Added = @(); Proof = ''; Problems = @(); Refused = '' }
    # SECAUDIT-1a (#1374): no standing admin without -LegacyStandingAccess -- refused before anything is read or written
    if ($Apply -and -not $LegacyStandingAccess) {
        $out.Applied = $false; $out.Refused = Get-SISupportStandingRefusalText
        $out.Problems = @($out.Refused); & $tell 'refused' $out.Refused
        return [pscustomobject]$out
    }
    $added = New-Object System.Collections.Generic.List[string]
    $dbs = @($Databases | Where-Object { $_ } | Select-Object -Unique)
    $callerIsSupportApp = [bool](([string]$CallerAppId).Trim() -and ($CallerAppId -ieq $ClientId))

    # ---- 1. read: the application, the server's administrator, the admin group ----
    $sp = $null; $spWhy = ''
    try { $sp = Get-SISupportAppServicePrincipal -Graph $Graph -ClientId $ClientId; if (-not $sp) { $problems.Add(('the tenant has no service principal for the application {0} -- the customer creates the Invardia Support app first' -f $ClientId)) } }
    catch { $spWhy = [string]$_.Exception.Message; $problems.Add(('the Support app''s service principal could not be checked: {0}' -f $spWhy)) }
    $out.ServicePrincipal = $sp
    if ($sp) { & $tell 'present' ('the Support app in this tenant: "{0}" (client id {1})' -f $sp.DisplayName, $ClientId) }
    $admin = $null; $adminRead = $false; $adminWhy = ''
    try { $admin = & $GetAdmin; $adminRead = $true } catch { $adminWhy = [string]$_.Exception.Message }
    $adminSid = [string](& $prop $admin 'Sid'); $adminLogin = [string](& $prop $admin 'Login'); $adminKind = [string](& $prop $admin 'PrincipalType')
    $group = $null; $adminIsTheGroup = $false
    if ($adminSid) {
        try {
            $g = & $Graph 'GET' ("https://graph.microsoft.com/v1.0/groups/${adminSid}?`$select=id,displayName") $null
            if ($g -and [string](& $prop $g 'id')) { $group = [pscustomobject]@{ Id = [string](& $prop $g 'id'); DisplayName = [string](& $prop $g 'displayName') }; $adminIsTheGroup = $true }
        } catch { }
    }
    if (-not $group) {
        # the administrator is not a group at this moment (an application, a person): the admin group by ANY of its names
        # (CR5 #655: grp-si-sql-admins, "SecurityInsight SQL admins" after the rename, its mailNickname -- SI-DisplayNames.ps1)
        try {
            if (-not (Get-Command -Name Find-SISqlAdminGroup -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, 'SI-DisplayNames.ps1')) }
            $fg = Find-SISqlAdminGroup -Graph $Graph -GroupName $GroupName
            # a group found BY NAME is taken only when it is the kind setup makes (as setup\Set-SISqlAdminGroup.ps1 refuses
            # any other): role-assignable (only a Privileged Role Administrator can create one or change its members) and
            # a security group. Any user who can create groups could make a plain group with the same name.
            $rgWhy = Get-SISupportAppAdminGroupRefusal -Group $fg.Group
            if ($fg.Group -and -not $rgWhy) { $group = [pscustomobject]@{ Id = [string]$fg.Group.Id; DisplayName = [string]$fg.Group.DisplayName } }
            elseif ($fg.Group) { $problems.Add(('the group {0} found by its name is not used as the admin group: {1}' -f [string]$fg.Group.DisplayName, $rgWhy)) }
        } catch { $problems.Add(('the admin group could not be checked: {0}' -f $_.Exception.Message)) }
    }
    $out.Group = $group
    if ($adminRead) { & $tell 'present' ('the database server''s administrator: {0}{1}' -f $(if ($adminLogin) { $adminLogin } else { '(none)' }), $(if ($adminKind) { ' (recorded as ' + $adminKind + ')' } else { '' })) }

    # ---- 2. (a) a member of the admin group -- before the administrator is touched, so nobody is ever shut out ----
    if ($sp -and $group) { $out.Member = Set-SISupportAppGroupMember -Graph $Graph -GroupId $group.Id -ServicePrincipalId $sp.Id -Apply:$Apply -LegacyStandingAccess:$LegacyStandingAccess -Sleep $Sleep }
    elseif (-not $group) { $out.Member = & $st 'unchecked' ('could not be checked: the admin group was not found (the server''s administrator is not a group and no single group is named {0})' -f $GroupName) }
    elseif ($spWhy) { $out.Member = & $st 'unchecked' ('could not be checked: the Support app''s service principal could not be read ({0})' -f $spWhy) }
    else { $out.Member = & $st 'failed' 'the tenant has no service principal for the Support app to add' }
    & $tell $out.Member.State ('(a) member of the admin group{0}: {1}' -f $(if ($group) { ' ' + $group.DisplayName } else { '' }), $out.Member.Detail)
    $out.GroupOk = [bool]($out.Member.State -in 'present', 'added')
    if ($out.Member.State -eq 'added') { $added.Add('group') }

    # ---- 3. the server's administrator is that group, recorded as a group ----
    $changed = ($out.Member.State -eq 'added')
    if (-not $adminRead) { $out.Admin = & $st 'unchecked' ('could not be checked: the database server''s administrator could not be read ({0})' -f $adminWhy) }
    elseif (-not $group) { $out.Admin = & $st 'not' ('the server''s administrator is {0}, and the admin group was not found' -f $(if ($adminLogin) { $adminLogin } else { 'not set' })) }
    elseif ($adminIsTheGroup -and $adminKind -ieq 'Group') { $out.Admin = & $st 'present' ('the admin group {0}, recorded as a group' -f $group.DisplayName) }
    else {
        # what is wrong, and whether THIS run may put it right: only a group the server names under another kind, or the
        # Support app itself still being the administrator. A person or another application is never replaced here --
        # setup\Set-SISqlAdminGroup.ps1 does that, and keeps that administrator as a member of the group.
        $what = $(if ($adminIsTheGroup) { 'the server names the admin group {0} as "{1}", not as a group' -f $group.DisplayName, $(if ($adminKind) { $adminKind } else { 'no kind' }) }
                  elseif (-not $adminSid) { 'the server has no Entra administrator' }
                  else { 'the server''s administrator is {0}{1}, not the admin group {2}' -f $adminLogin, $(if ($adminKind) { ' (' + $adminKind + ')' } else { '' }), $group.DisplayName })
        $mayFix = $adminIsTheGroup -or ($adminSid -and ($adminSid -ieq $ClientId) -and $out.GroupOk)
        if (-not $mayFix) { $out.Admin = & $st 'not' ($what + ' -- make the group the administrator with setup\Set-SISqlAdminGroup.ps1 (it keeps today''s administrator as a member), then run this again') }
        elseif (-not $Apply) { $out.Admin = & $st 'planned' ($what + ' -- the group would be made the administrator, as a group') }
        elseif (-not $SetAdmin) { $out.Admin = & $st 'not' ($what + ' -- this run cannot change the database server''s administrator') }
        else {
            try {
                & $SetAdmin $group.DisplayName $group.Id 'Group'
                $back = & $GetAdmin   # READ BACK from the server, not taken from the request
                if ([string](& $prop $back 'Sid') -ieq $group.Id -and [string](& $prop $back 'PrincipalType') -ieq 'Group') {
                    $out.Admin = & $st 'set' ('the admin group {0} was made the administrator as a group ({1}), and read back' -f $group.DisplayName, $what); $changed = $true
                } else { $out.Admin = & $st 'not' ('the group was sent as the administrator, but the server shows {0} as {1} when read back' -f [string](& $prop $back 'Login'), [string](& $prop $back 'PrincipalType')) }
            } catch { $out.Admin = & $st 'not' ($what + (' -- and it could not be changed: {0}' -f $_.Exception.Message)) }
        }
    }
    & $tell $out.Admin.State ('the database server''s administrator is the admin group, as a group: {0}' -f $out.Admin.Detail)

    # ---- 4. (b) its own database user with db_owner, in every product database ----
    $name = $(if ($sp -and $sp.DisplayName) { $sp.DisplayName } else { 'invardia-support-app' })
    if (-not $Apply) {
        $out.Databases = @($dbs | ForEach-Object { [pscustomobject]@{ Database = $_; State = 'planned'; User = $name; Detail = 'its own database user with the owner role would be made if it is not there (the plan opens no database connection)' } })
        foreach ($d in $out.Databases) { & $tell 'planned' ('(b) {0}: {1}' -f $d.Database, $d.Detail) }
        $out.Proof = 'not proven: the plan opens no database connection'
        $out.Problems = $problems.ToArray()
        return [pscustomobject]$out
    }
    $__siSupSqlSeam = $Sql; $__siSupNap = $nap; $__siSupWaits = $GroupWaits
    $quick = { param([string]$Database, [string]$Query) & $__siSupSqlSeam $Database $Query $true }
    $slow  = { param([string]$Database, [string]$Query) & $__siSupSqlSeam $Database $Query $false }
    # a run signed in AS the Support app, that changed the group / administrator a moment ago: the database may let it in
    # only after some minutes (bounded waits); any other run is retried once the slow way (a new token, the server's waits)
    $retry = $(if ($callerIsSupportApp -and $changed) {
        { param([string]$Database, [string]$Query) $last = $null
          foreach ($w in @($__siSupWaits)) { & $__siSupNap $w; try { return (& $__siSupSqlSeam $Database $Query $false) } catch { $last = $_ } }
          throw $last }
    } else { $slow })
    $res = @(Invoke-SISupportAppDatabaseAccess -Sql $quick -Retry $retry -Databases $dbs -ClientId $ClientId -UserName $name -Apply -LegacyStandingAccess:$LegacyStandingAccess)
    $out.Databases = $res
    foreach ($d in $res) { & $tell $d.State ('(b) {0}: {1}' -f $d.Database, $d.Detail); if ($d.State -eq 'granted') { $added.Add([string]$d.Database) } }
    $out.DbUserOk = [bool]($dbs.Count -gt 0 -and @($res | Where-Object { $_.State -in 'present', 'granted' }).Count -eq $dbs.Count)
    $out.Added = $added.ToArray()
    $out.Ok = [bool]($out.GroupOk -and $out.DbUserOk)

    # ---- 5. the record (written only when it is missing or names another application) ----
    if ($RecordDatabase) {
        try { $null = & $quick $RecordDatabase (Get-SISupportAppRecordSql -ClientId $ClientId -By $By) }
        catch { & $tell 'note' ('the Support app''s client id could not be recorded in {0} ({1})' -f $RecordDatabase, $_.Exception.Message) }
    }

    # ---- 6. the proof ----
    if (-not $callerIsSupportApp) {
        $out.Proof = 'not proven: this run is not signed in as the Support app, so it cannot sign in to the databases as it' +
            $(if ($out.Ok) { '; its membership of the admin group and its own database user in each database were read back' } else { '' })
    } else {
        $said = New-Object System.Collections.Generic.List[string]; $all = $true
        $who = Get-SISupportAppWhoAmISql
        foreach ($db in $dbs) {
            try {
                $p = ConvertFrom-SISupportAppDatabaseAnswer ([string](& $slow $db $who))
                if ($p.User -and $p.Owner) { $said.Add(('{0}: signed in as {1}, with the owner role' -f $db, (Get-SISupportAppSignedInName $p.User))) }
                else { $all = $false; $said.Add(('{0}: signed in as {1}, WITHOUT the owner role' -f $db, (Get-SISupportAppSignedInName $p.User))) }
            } catch { $all = $false; $said.Add(('{0}: could not be checked: {1}' -f $db, $_.Exception.Message)) }
        }
        $out.Proof = $(if ($all -and $dbs.Count) { 'proven: ' } else { 'not proven: ' }) + ($said.ToArray() -join '; ')
    }
    & $tell $(if ($out.Proof -like 'proven:*') { 'proven' } else { 'note' }) ('a database sign-in as the Support app -- {0}' -f $out.Proof)
    $out.Problems = $problems.ToArray()
    [pscustomobject]$out
}
