#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Pro: takes the Invardia Support app's STANDING database admin away from an existing install, once its
    just-in-time access is in place. PLAN by default.

.DESCRIPTION
    Until now the Invardia Support app held two standing rights at every install: its own database user in db_owner in
    each product database, and membership of the SQL admin group (the group the database server names as its Entra
    administrator). With the just-in-time support grant, the Support app gets admin only while a support session is open
    (at most 8 hours, at the level the customer consented to) and keeps a standing READ-ONLY role (si_support_read:
    metadata and health, no data). This script removes the two standing rights -- and nothing else:

      db-owner      the Support app's user leaves db_owner in every product database (one transaction per database).
                    The user itself and its read-only role si_support_read STAY.
      admin-group   the Support app's service principal leaves the SQL admin group. The group stays the server's Entra
                    administrator with its other members (your administrators, the install's database setup identity).

    It refuses -- nothing is changed -- unless ALL of these are read back first:
      * every product database has the four support grant procedures, this release's text, signed (certificate to 2099,
        private key removed), the signer in db_owner; the engine (si_engine) may run them and the engine's user is in
        si_engine; the Support app's user is in the read-only role; the customer's consent is recorded; no support
        grant is open right now;
      * the support request queue (si-support-requests) and the support grant job (caj-si-support-grant) are there;
      * the database setup job's last result (cfg.InstallState 'DbJob') is ok;
      * the database server's Entra administrator is a GROUP, and that group keeps at least one OTHER member that is not
        the Support app -- read from the group's member list AND from each of the install's identities (a group's member
        list can hide service principals). Nobody ever loses access to the database.

    Run by Invardia support inside the install's Support session: every statement goes through Invardia's audited
    Invoke-InvardiaSupportSql, every Azure and Microsoft Graph call through its recorder. Without a Support session the
    script refuses; it never signs in or opens a connection of its own. The SQL server, the databases, the engine identity
    and the queue are read from the install's OWN jobs (never a name pattern); -Server / -Databases / -StorageAccount
    override them.

    -Apply makes the steps (all, or the ones named in -Steps), each READ BACK, and writes ONE rollback record with what was
    there before: a JSON file on this machine (the path is printed) and a short row in the install's database
    (cfg.InstallState 'SupportStandingAccess' -- the heartbeat reads it and reports the new state as expected). Then it
    waits -ObserveMinutes and counts the install's runs since the change and the failures. One install at a time.
    -Rollback <record> -Apply puts back exactly what the record says was there: the group membership first, then db_owner.

    Afterwards: a support session opens admin through the support grant job (just in time) and closes it again; the
    heartbeat reports "just in time" as the expected state and names it when a standing right comes back. The record's
    row in the install is written the same way once the Support app is read-only there (the grant opened for the row and
    closed again, each said in one line); when the grant cannot be opened the row is not written -- a warning, the local
    file stays the record.

    THE STATE ROW (cfg.InstallState 'SupportStanding', what the heartbeat's setup step support-grant-jit reads; the same row
    and shape the updater writes, setup\_shared\SI-SupportStandingUpdate.ps1): -Apply writes it 'ok' ONLY when every step
    completed AND this run's own read-back proves the end state -- no db_owner in any product database AND not a member of
    the SQL admin group. When the plan already reads that end state, -Apply changes nothing (no rollback record) and writes
    only the row. A read-back that does not prove it writes no row (said). -Rollback -Apply writes it 'missing' (put back on
    purpose), in the same statement as the record's row. Under the support grant like the record's row (live 2026-11-09:
    without it the heartbeat kept "standing admin remains" from an old updater row until the next release).

    THE READS once the Support app is read-only (si_support_read: no data): the install's records (cfg.InstallState), the
    support grant (cfg.SupportConsent) and the Support app's roles are read under ONE troubleshoot grant (db_datareader),
    opened only when the probe says read-only, closed again before anything is written. Refused: said, the reads run
    without it, every precondition that needs it says "could not be read" -- refused, nothing written (live 2026-11-09).

.EXAMPLE
    . Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'SI support: remove standing admin (plan)'
    .\setup\Remove-SISupportStandingAccess.ps1 -ResourceGroup <rg>
    The plan: the install's shape, the Support app's roles in each product database, its group memberships, every
    precondition, and exactly what -Apply would change. Nothing is changed.
.EXAMPLE
    .\setup\Remove-SISupportStandingAccess.ps1 -ResourceGroup <rg> -Apply
    Removes db_owner in every product database, then the admin group membership; reads each back; writes the rollback record.
.EXAMPLE
    .\setup\Remove-SISupportStandingAccess.ps1 -ResourceGroup <rg> -Rollback <record.json> -Apply
    Puts back what the record says was there (without -Apply: shows what it would put back).
#>
[CmdletBinding()]
param(
    # the install's resource group (where its jobs are)
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9_.()-]{1,90}$')][string]$ResourceGroup,
    [string]$SubscriptionId,
    [switch]$Apply,
    # db-owner, admin-group (default: both, in that order)
    [string[]]$Steps = @(),
    # a rollback record (the JSON file an -Apply run printed)
    [string]$Rollback = '',
    # overrides (an install whose jobs do not name them); never guessed
    [string]$Server,
    [string]$Databases,
    [string]$StorageAccount,
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$SupportAppId = '',
    [string]$Environment = '',
    [string]$Reason = 'SI support: remove the Support app''s standing admin (just-in-time access in place)',
    [string]$RecordDirectory = '',
    [ValidateRange(0, 30)][int]$ObserveMinutes = 6,
    # the directory and database read-backs after a change: tries, and seconds between them (membership takes minutes)
    [ValidateRange(1, 120)][int]$ReadBackTries = 20,
    [ValidateRange(0, 300)][int]$ReadBackSeconds = 15,
    # TEST SEAMS (setup\_shared\SI-SupportCutover.ps1)
    [scriptblock]$Arm, [scriptblock]$Sql, [scriptblock]$Graph,
    [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
    [switch]$PassThru,
    # TEST SEAM: the support grant's open / close (the Support session's Open- / Close-InvardiaSupportGrant)
    [System.Collections.IDictionary]$SupportGrant
)
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportCutover.ps1'))
. ([IO.Path]::Combine($siRoot, 'engine', 'pro-settings', 'SI-SupportGrantSql.ps1'))
if (-not (Get-Command -Name Get-SISupportAppServicePrincipal -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($siRoot, 'engine', '_shared', 'SI-SupportSqlAccess.ps1')) }
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportWrite.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportStandingUpdate.ps1'))

$scriptName = 'Remove-SISupportStandingAccess'
$stateName = 'SupportStandingAccess'
# the state row the heartbeat's setup step support-grant-jit reads -- the SAME row and shape the updater writes
# (setup\_shared\SI-SupportStandingUpdate.ps1: New-SISupportStandingStateValue)
$standingRow = [string](Get-SISupportStandingNames).StateRow
$savePurpose = 'the rollback record''s row in the install (cfg.InstallState)'
$known = @('db-owner', 'admin-group')
$readRole = [string](Get-SISupportGrantContract).ReadRole

if (-not $Sql -and -not (Get-Command -Name Invoke-InvardiaSupportSql -ErrorAction SilentlyContinue)) {
    throw ('Refused: Invoke-InvardiaSupportSql is not available in this shell. Every statement of this change goes through ' +
           'Invardia''s audited SQL call -- open the install''s Support session (Connect-InvardiaSupport.ps1) and run again. ' +
           'Nothing was read or changed; this script never opens a database connection of its own.')
}
$seams = New-SICutoverSeams -Arm $Arm -Sql $Sql -Graph $Graph -Reason $Reason
$sess = $null; if (Get-Command -Name Get-SISupportSession -ErrorAction SilentlyContinue) { try { $sess = Get-SISupportSession } catch { $sess = $null } }
if (-not $Environment) { $Environment = if ($sess -and [string]$sess.Environment) { [string]$sess.Environment } else { '' } }
if (-not $SubscriptionId) { $SubscriptionId = if ($sess) { [string]$sess.SubscriptionId } else { '' } }
if (-not $SupportAppId) { $SupportAppId = if ($sess) { [string]$sess.AppId } else { '' } }
if (-not $RecordDirectory) { $RecordDirectory = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'si', 'logs', 'cutover') }
$who = if ($Environment) { " ($Environment)" } else { '' }
$S = $seams.Sql; $G = $seams.Graph
$q = { param([string]$s) "N'" + $s.Replace("'", "''") + "'" }
function Get-Val($Row, [string]$Name) { $v = Get-SICutoverProp $Row @($Name); if ($null -eq $v) { '' } else { [string]$v } }
function Invoke-Db([string]$Database, [string]$Purpose, [string]$Query, [switch]$ReadOnly) {
    @(& $S $Server $Database $Query ('SI support standing access{0}: {1}' -f $who, $Purpose) ([bool]$ReadOnly) | ForEach-Object { $_ } | Where-Object { $null -ne $_ })
}
function Write-Line([string]$Text, [string]$Color = 'Gray') { Write-Host ('  ' + $Text) -ForegroundColor $Color }
# THE RECORD'S ROW in the install (cfg.InstallState): once the Support app is read-only there (after this change, or a
# rollback whose admin group membership has not reached the database yet), the row is written under the support grant --
# opened for it and closed again. A grant that cannot be opened leaves the row unwritten: Save-SICutoverRecord says so
# (a warning; the local file is the record), the change itself is never undone for it.
$saveSql = {
    param([string]$Server, [string]$Database, [string]$Query, [string]$Reason, [bool]$ReadOnly)
    $sg = $SupportGrant
    if (-not $sg) { $sg = New-SISupportGrantSeams -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -StorageAccount $StorageAccount }
    $ga = Get-SISupportGrantArgs -SupportGrant $sg -Say { param([string]$t, [string]$c) Write-Host ('  ' + $t) -ForegroundColor $(if ($c) { $c } else { 'Gray' }) }
    $ga['Purpose'] = $savePurpose; $ga['Tool'] = $scriptName; $ga['GrantLevel'] = 'setup'; $ga['WriteKind'] = 'audit'
    $ga['Do'] = { & $S $Server $Database $Query $Reason $ReadOnly }
    $ga['Probe'] = { & $S $Server $Database (Get-SISupportAccessProbeSql) ('SI support standing access{0}: the Support app''s own rights (read-only)' -f $who) $true }
    $g = Invoke-SISupportWithGrant @ga
    if (-not $g.Done) { throw $g.Why }
    $g.Value
}
# THE STATE ROW (cfg.InstallState 'SupportStanding'): the statement that writes it -- -Outcome ok only after this run's OWN
# read-back proved the end state (Test-StandingEndState), rollback = 'missing' with its reason. Literal values (Invardia's
# audited SQL call takes no parameters); the value is the updater's shape, never a second format.
function Get-StandingRowSql([ValidateSet('ok', 'rollback')][string]$Outcome, [string]$DbOwner = 'kept', [string]$Group = 'member') {
    $verdict = if ($Outcome -eq 'ok') { New-SISupportStandingStepVerdict -Outcome ok } else { New-SISupportStandingStepVerdict -Outcome rollback -DbOwner $DbOwner -Group $Group }
    Get-SICutoverInstallStateSql -Name $standingRow -Value (New-SISupportStandingStateValue -Verdict $verdict -NowUtc ([datetime]::UtcNow)) -By $scriptName
}
# writes the 'ok' row in the Pro database under the support grant (the Support app is read-only by now: opened for the row,
# closed again). Never undoes or fails the change: a row that cannot be written is ONE warning line.
function Save-StandingRow {
    $script:savePurpose = 'the support standing state row in the install (cfg.InstallState SupportStanding)'
    try {
        $null = & $saveSql $Server $proDb (Get-StandingRowSql -Outcome ok) ('SI support standing access{0}: the state row (no standing admin, read back)' -f $who) $false
        'state row: no standing admin recorded for the heartbeat (cfg.InstallState SupportStanding, ok)'
    } catch { 'state row: NOT written ({0}) -- the heartbeat names the standing admin until the row is written: run -Apply again' -f (($_.Exception.Message -split "`n")[0]) }
    finally { $script:savePurpose = 'the rollback record''s row in the install (cfg.InstallState)' }
}

# ---------------------------------------------------------------------------------------------------- THE STATEMENTS
function Get-StandingStateSql([string]$AppId, [string]$EngineClientId) {
    # READ ONLY, one row: the Support app's user and its roles, the engine's user in si_engine, open support grants
    $sid = ConvertTo-SISupportGrantSid -ClientId $AppId
    $eng = if ($EngineClientId) { 'sid = ' + (ConvertTo-SISupportGrantSid -ClientId $EngineClientId) } else { '1 = 0' }
@"
DECLARE @uid int = (SELECT TOP (1) principal_id FROM sys.database_principals WHERE sid = $sid AND principal_id > 4 AND type NOT IN ('R', 'A', 'C', 'K'));
DECLARE @eid int = (SELECT TOP (1) principal_id FROM sys.database_principals WHERE $eng AND principal_id > 4 AND type NOT IN ('R', 'A', 'C', 'K'));
DECLARE @open int = 0;
IF OBJECT_ID(N'cfg.SupportJitMarker') IS NOT NULL
    EXEC sys.sp_executesql N'SELECT @o = COUNT(*) FROM cfg.SupportJitMarker WHERE ClosedUtc IS NULL AND ExpiresUtc > SYSUTCDATETIME();', N'@o int OUTPUT', @o = @open OUTPUT;
SELECT DB_NAME() AS [Database], ISNULL(USER_NAME(@uid), N'') AS UserName,
       ISNULL((SELECT STRING_AGG(CONVERT(nvarchar(max), r.name), N',') FROM sys.database_role_members AS m
               JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = @uid), N'') AS Roles,
       ISNULL(USER_NAME(@eid), N'') AS EngineUser,
       CASE WHEN @eid IS NOT NULL AND EXISTS (SELECT 1 FROM sys.database_role_members AS m WHERE m.member_principal_id = @eid AND m.role_principal_id = DATABASE_PRINCIPAL_ID(N'si_engine')) THEN 1 ELSE 0 END AS EngineInRole,
       @open AS OpenGrants;
"@
}
function Get-InstallStateReadSql {
    # READ ONLY, the Pro database: the database setup job's result, the recorded Support app, the other product databases
    # with the support grant, and this script's own record
@"
SELECT CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'-' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'DbJob'), N'') END AS DbJob,
       CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'SupportApp'), N'') END AS SupportApp,
       CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'SupportGrantDatabases'), N'') END AS SupportGrantDatabases,
       CASE WHEN OBJECT_ID(N'cfg.InstallState') IS NULL THEN N'' ELSE ISNULL((SELECT Value FROM cfg.InstallState WHERE Name = N'$stateName'), N'') END AS Record;
"@
}
function Get-DbOwnerChangeSql([string]$AppId, [ValidateSet('remove', 'restore')][string]$Change) {
    # ONE transaction: only db_owner, only the Support app's own user; the user and its read-only role stay
    $sid = ConvertTo-SISupportGrantSid -ClientId $AppId
    $guard = if ($Change -eq 'remove') {
        "IF NOT EXISTS (SELECT 1 FROM sys.database_role_members WHERE role_principal_id = DATABASE_PRINCIPAL_ID(N'$readRole') AND member_principal_id = DATABASE_PRINCIPAL_ID(@n)) THROW 51674, N'the Support app is not in the read-only role $readRole here -- nothing was changed', 1;"
    } else { '' }
    $act = if ($Change -eq 'remove') {
        "IF EXISTS (SELECT 1 FROM sys.database_role_members WHERE role_principal_id = DATABASE_PRINCIPAL_ID(N'db_owner') AND member_principal_id = DATABASE_PRINCIPAL_ID(@n)) BEGIN SET @s = N'ALTER ROLE db_owner DROP MEMBER ' + QUOTENAME(@n) + N';'; EXEC (@s); END"
    } else {
        "IF NOT EXISTS (SELECT 1 FROM sys.database_role_members WHERE role_principal_id = DATABASE_PRINCIPAL_ID(N'db_owner') AND member_principal_id = DATABASE_PRINCIPAL_ID(@n)) BEGIN SET @s = N'ALTER ROLE db_owner ADD MEMBER ' + QUOTENAME(@n) + N';'; EXEC (@s); END"
    }
@"
SET XACT_ABORT ON;
DECLARE @s nvarchar(400);
DECLARE @n sysname = (SELECT TOP (1) name FROM sys.database_principals WHERE sid = $sid AND principal_id > 4 AND type NOT IN ('R', 'A', 'C', 'K'));
IF @n IS NULL THROW 51674, N'the Support app has no database user here -- nothing was changed', 1;
$guard
BEGIN TRANSACTION;
$act
COMMIT TRANSACTION;
SELECT @n AS UserName, ISNULL((SELECT STRING_AGG(CONVERT(nvarchar(max), r.name), N',') FROM sys.database_role_members AS m
       JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = DATABASE_PRINCIPAL_ID(@n)), N'') AS Roles;
"@
}
function Get-RolesSql([string]$AppId) {
    # READ ONLY, sys.* only: the Support app's user and its roles. The read-back after the removal runs as the read-only
    # role, which may not read cfg (cfg.SupportJitMarker) -- reading it there reported a made removal as NOT removed
    # (live 2026-11-09, both databases changed, both said "NOT removed")
    $sid = ConvertTo-SISupportGrantSid -ClientId $AppId
@"
DECLARE @uid int = (SELECT TOP (1) principal_id FROM sys.database_principals WHERE sid = $sid AND principal_id > 4 AND type NOT IN ('R', 'A', 'C', 'K'));
SELECT DB_NAME() AS [Database], ISNULL(USER_NAME(@uid), N'') AS UserName,
       ISNULL((SELECT STRING_AGG(CONVERT(nvarchar(max), r.name), N',') FROM sys.database_role_members AS m
               JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = @uid), N'') AS Roles,
       1 AS RolesOnly;
"@
}
function Get-Roles([string]$Database, [string]$AppId) {
    $r = @(Invoke-Db -Database $Database -Purpose 'read back -- the Support app''s roles (read-only)' -ReadOnly -Query (Get-RolesSql -AppId $AppId))[0]
    @((Get-Val $r 'Roles') -split ',' | Where-Object { $_ })
}
function Test-Member([string]$SpId, [string]$GroupId) {
    # from the MEMBER's side: a group's member list can hide service principals
    $mo = & $G 'GET' ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}/memberOf?$select=id,displayName&$top=999' -f $SpId) $null
    [bool]@(@(Get-SICutoverProp $mo @('value')) | Where-Object { $_ -and [string](Get-SICutoverProp $_ @('id')) -eq $GroupId }).Count
}
function Wait-Member([string]$SpId, [string]$GroupId, [bool]$Want) {
    for ($i = 1; $i -le $ReadBackTries; $i++) {
        if ((Test-Member -SpId $SpId -GroupId $GroupId) -eq $Want) { return $true }
        if ($i -lt $ReadBackTries) { & $Sleep $ReadBackSeconds }
    }
    $false
}

$result = [ordered]@{ Action = $(if ($Rollback) { 'rollback' } elseif ($Apply) { 'apply' } else { 'plan' }); Ok = $false; Ready = $false; Refused = $false
                      Server = ''; Databases = @(); Preconditions = @(); Plan = @(); Lines = @(); RolesAfter = [ordered]@{}; MemberAfter = $null
                      SignInAfter = ''; RecordPath = $null; InstallLine = ''; Observation = $null; ReadGrant = '' }
function Complete-Run([int]$Code) {
    if ($PassThru) { return [pscustomobject]$result }
    if ($Code) { exit $Code }
}

# ---------------------------------------------------------------------------------------------------- ROLLBACK
if ($Rollback) {
    if (-not (Test-Path -LiteralPath $Rollback)) { throw ('Refused: the rollback record {0} is not there. Nothing was changed.' -f $Rollback) }
    $rec = Get-Content -LiteralPath $Rollback -Raw | ConvertFrom-Json
    if ([string]$rec.script -ne $scriptName) { throw ('Refused: {0} is a record of {1}, not of {2}. Nothing was changed.' -f $Rollback, [string]$rec.script, $scriptName) }
    if ([string]$rec.resourceGroup -and [string]$rec.resourceGroup -ne $ResourceGroup) { throw ('Refused: the record is for resource group {0}, not {1}. Nothing was changed.' -f [string]$rec.resourceGroup, $ResourceGroup) }
    $Server = [string]$rec.sqlServer; $result.Server = $Server
    $grp = Get-SICutoverProp $rec @('before', 'admin-group')
    $dbo = Get-SICutoverProp $rec @('before', 'db-owner')
    $app = [string](Get-SICutoverProp $rec @('supportAppId'))
    $dbsBefore = @(@(Get-SICutoverProp $dbo @('databases')) | Where-Object { $_ -and (@([string](Get-SICutoverProp $_ @('roles')) -split ',') -contains 'db_owner') })
    $wantGroup = $grp -and [bool](Get-SICutoverProp $grp @('member'))
    Write-Host ('SecurityInsight -- put the Support app''s standing admin back{0}: {1}{2}' -f $who, $Server, $(if ($Apply) { '' } else { ' -- PLAN (nothing is changed; add -Apply)' })) -ForegroundColor Cyan
    $result.Plan = @(
        $(if ($wantGroup) { 'admin-group: the Support app back into {0} (it was a member)' -f [string](Get-SICutoverProp $grp @('groupName')) } else { 'admin-group: nothing to put back (it was not a member)' })
        $(if ($dbsBefore.Count) { 'db-owner: the Support app''s user back into db_owner in {0}' -f ((@($dbsBefore | ForEach-Object { [string](Get-SICutoverProp $_ @('database')) })) -join ', ') } else { 'db-owner: nothing to put back' })
    )
    foreach ($l in $result.Plan) { Write-Line $l 'White' }
    if (-not $Apply) { Write-Line 'PLAN ONLY -- nothing was changed. Add -Apply to put it back.' 'Yellow'; $result.Ok = $true; return (Complete-Run 0) }
    $started = [datetime]::UtcNow
    $record = New-SICutoverRecord -Script $scriptName -Environment $Environment -Shape ([pscustomobject]@{ SubscriptionId = [string]$rec.subscriptionId; ResourceGroup = $ResourceGroup; SqlFqdn = $Server; Database = [string]$rec.database }) -Now $started
    $record['supportAppId'] = $app; $record['rollbackOf'] = (Split-Path -Leaf $Rollback)
    $recPath = Get-SICutoverRecordPath -Directory $RecordDirectory -Script $scriptName -Environment $Environment -Now $started
    $ok = $true; $lines = New-Object System.Collections.Generic.List[string]
    # ADD in the reverse order of the removal: the group first (it gives the right to put db_owner back)
    if ($wantGroup) {
        $gid = [string](Get-SICutoverProp $grp @('groupId')); $spId = [string](Get-SICutoverProp $grp @('servicePrincipalId'))
        try {
            if (-not (Test-Member -SpId $spId -GroupId $gid)) {
                $null = & $G 'POST' ('https://graph.microsoft.com/v1.0/groups/{0}/members/$ref' -f $gid) @{ '@odata.id' = ('https://graph.microsoft.com/v1.0/directoryObjects/{0}' -f $spId) }
            }
            $back = Wait-Member -SpId $spId -GroupId $gid -Want $true
            $result.MemberAfter = $back
            $record.applied = @($record.applied) + @('rollback-admin-group')
            if ($back) { $lines.Add('admin-group: the Support app is a member again (read back from its memberOf)') } else { $ok = $false; $lines.Add('admin-group: sent, but not read back as a member yet -- run the rollback again in a few minutes') }
        } catch { $ok = $false; $lines.Add(('admin-group: NOT put back ({0})' -f $_.Exception.Message)) }
    }
    foreach ($d in $dbsBefore) {
        $db = [string](Get-SICutoverProp $d @('database'))
        $done = $false; $why = ''
        for ($i = 1; $i -le $ReadBackTries -and -not $done; $i++) {
            try {
                $r = @(Invoke-Db -Database $db -Purpose 'rollback -- the Support app''s user back into db_owner (one transaction)' -Query (Get-DbOwnerChangeSql -AppId $app -Change 'restore'))[0]
                $roles = @((Get-Val $r 'Roles') -split ',' | Where-Object { $_ })
                $result.RolesAfter[$db] = $roles
                $done = $roles -contains 'db_owner'
            } catch { $why = $_.Exception.Message }
            # the restored group membership reaches the database's sign-in after a few minutes: tried again
            if (-not $done -and $i -lt $ReadBackTries) { & $Sleep $ReadBackSeconds }
        }
        if ($done) { $lines.Add(('{0}: db_owner again (read back: {1})' -f $db, (@($result.RolesAfter[$db]) -join ', '))) } else { $ok = $false; $lines.Add(('{0}: db_owner NOT put back{1}' -f $db, $(if ($why) { " ($why)" } else { '' }))) }
    }
    if ($dbsBefore.Count) { $record.applied = @($record.applied) + @('rollback-db-owner') }
    # the state row goes with the record's row, in the SAME statement (one support grant at most): 'missing', put back on
    # purpose -- never 'ok' after a rollback; the updater does not re-check or take it again after a rollback
    $rbDb = if (@($result.RolesAfter.Keys | Where-Object { @($result.RolesAfter[$_]) -contains 'db_owner' }).Count) { 'kept' } else { 'unknown' }
    $rbGroup = if ($result.MemberAfter -eq $true) { 'member' } else { 'unknown' }
    $rbRowSql = Get-StandingRowSql -Outcome rollback -DbOwner $rbDb -Group $rbGroup
    $rbSql = { param([string]$Server, [string]$Database, [string]$Query, [string]$Reason, [bool]$ReadOnly) & $saveSql $Server $Database ($Query + "`n" + $rbRowSql) $Reason $ReadOnly }
    $sv = Save-SICutoverRecord -Record $record -Path $recPath -Sql $rbSql -StateName $stateName
    $result.RecordPath = $recPath; $result.InstallLine = [string]$sv.InstallLine
    $result.Lines = $lines.ToArray(); $result.Ok = $ok
    foreach ($l in $result.Lines) { Write-Line $l $(if ($ok) { 'Green' } else { 'Yellow' }) }
    Write-Line ('record: {0}{1}' -f $recPath, $(if ($sv.InstallLine) { ' -- ' + $sv.InstallLine } else { '' })) 'Cyan'
    return (Complete-Run $(if ($ok) { 0 } else { 1 }))
}

# ---------------------------------------------------------------------------------------------------- SHAPE
if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the Support session names no subscription. Nothing was read or changed.' }
if (-not $SupportAppId) { throw 'Give -SupportAppId: the Invardia Support app''s client id (the Support session names none). Nothing was read or changed.' }
$shape = Get-SIInstallShape -Arm $seams.Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SqlServerName $Server -FindSqlInResourceGroup
$engineJobs = @($shape.Jobs | Where-Object { [string](Get-SICutoverProp $_ @('name')) -notmatch '(?i)updater|tagging' })
$proSrv = Get-SICutoverEnv -Resources $engineJobs -Name 'SI_ProSqlServer'
if (-not $Server -and $proSrv) {
    $proFqdn = if ($proSrv -notmatch '\.') { $proSrv + '.database.windows.net' } else { $proSrv }
    if ($proFqdn.ToLowerInvariant() -ne ([string]$shape.SqlFqdn).ToLowerInvariant()) { $shape = Get-SIInstallShape -Arm $seams.Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -SqlServerName $proSrv }
}
$Server = [string]$shape.SqlFqdn; $result.Server = $Server
if (-not $Server) { throw ('Refused: the install''s database server is not known ({0}) -- give -Server. Nothing was changed.' -f $(if ($shape.SqlProblem) { $shape.SqlProblem } else { 'its jobs name none' })) }
if (-not $shape.SqlServerId) { throw ('Refused: the database server {0} is not in subscription {1}. Nothing was changed.' -f $Server, $SubscriptionId) }
# the product databases, the Pro database first: -Databases, else the jobs' settings (+ the support grant's record below)
$dbs = New-Object System.Collections.Generic.List[string]
$addDb = { param([string]$n) $n = "$n".Trim(); if ($n -and -not $dbs.Contains($n)) { $dbs.Add($n) } }
$otherServer = @()
if ($Databases) { foreach ($n in ($Databases -split '\s*;\s*')) { & $addDb $n } }
else {
    $pro = Get-SICutoverEnv -Resources $engineJobs -Name 'SI_ProSqlDatabase'; if (-not $pro) { $pro = [string]$shape.Database }
    & $addDb $pro
    foreach ($pair in @(@('SI_LedgerDatabase', 'SI_LedgerSqlServer'), @('SI_Pro_DataSqlDatabase', 'SI_Pro_DataSqlServer'))) {
        $n = Get-SICutoverEnv -Resources $engineJobs -Name $pair[0]; if (-not $n) { continue }
        $sv = Get-SICutoverEnv -Resources $engineJobs -Name $pair[1]
        if ($sv) { $f = if ($sv -notmatch '\.') { $sv + '.database.windows.net' } else { $sv }; if ($f.ToLowerInvariant() -ne $Server.ToLowerInvariant()) { $otherServer += ('{0} on {1}' -f $n, $f); continue } }
        & $addDb $n
    }
}
if (-not $dbs.Count) { throw 'Refused: the install names no product database -- give -Databases (the Pro database first). Nothing was changed.' }
$proDb = $dbs[0]

Write-Host ('SecurityInsight -- the Support app''s standing admin{0}: {1}{2}' -f $who, $Server, $(if ($Apply) { '' } else { ' -- PLAN (nothing is changed; add -Apply)' })) -ForegroundColor Cyan

# ---------------------------------------------------------------------------------------------------- READ: PRECONDITIONS
$pre = New-Object System.Collections.Generic.List[object]
$need = { param([string]$Name, [bool]$Ok, [string]$Detail) $pre.Add([pscustomobject]@{ Name = $Name; Ok = $Ok; Detail = $Detail }) }
$sp = $null
try { $sp = Get-SISupportAppServicePrincipal -Graph $G -ClientId $SupportAppId } catch { $sp = $null; & $need 'the Support app' $false ('could not be read in the directory: {0}' -f $_.Exception.Message) }
if ($sp) { & $need 'the Support app' $true ('{0} -- client {1}, service principal {2}' -f $sp.DisplayName, $SupportAppId, $sp.Id) }
elseif (-not @($pre | Where-Object { $_.Name -eq 'the Support app' }).Count) { & $need 'the Support app' $false ('no service principal for client {0} in this tenant' -f $SupportAppId) }
# the support grant job and its storage account (the support grant's open call is pointed at them)
$sgJob = @($shape.Jobs | Where-Object { [string](Get-SICutoverProp $_ @('name')) -eq 'caj-si-support-grant' })[0]
if (-not $StorageAccount -and $sgJob) { $StorageAccount = Get-SICutoverEnv -Resources @($sgJob) -Name 'SI_STORAGE_ACCOUNT' }

# THE SQL READS (the database users, the install's records, the support grant, the Support app's roles): once the standing
# admin is gone the Support app is READ-ONLY (si_support_read: metadata, no data) and cfg.InstallState / cfg.SupportConsent
# refuse it (live 2026-11-09 at 4 installs: "SELECT permission was denied on the object 'InstallState'" -> refused, nothing
# written). They run under ONE troubleshoot grant (db_datareader) through Invoke-SISupportWithGrant -- asked only when the
# Support app is read-only (a standing admin asks none), closed again in every case BEFORE anything is written (the state
# row's write asks its own setup grant). Refused / never read back: said, and the reads run without it -- what needs it says
# "could not be read", nothing is changed, no row is written. The block keeps its results in $rd (it runs in a child scope).
$rd = @{ Shape = $shape; St = $null; Ran = $false }
$readSql = {
    $rd.Shape = Add-SIInstallSqlShape -Shape $rd.Shape -Sql $S -Graph $G -Reason ('SI support standing access{0}: read the database users (read-only)' -f $who)
    # the Pro database's own record: the database setup job, the recorded Support app, the other product databases
    try { $rd.St = @(Invoke-Db -Database $proDb -Purpose 'the install''s records (read-only)' -ReadOnly -Query (Get-InstallStateReadSql))[0] } catch { & $need 'the install''s records' $false ('could not be read: {0}' -f $_.Exception.Message) }
    $st = $rd.St
    if ($st) {
    if (-not $Databases) { foreach ($n in ((Get-Val $st 'SupportGrantDatabases') -split '\s*;\s*')) { & $addDb $n } }
    $dj = Get-Val $st 'DbJob'; $djState = ''
    if ($dj -and $dj -ne '-') { try { $djState = [string](($dj | ConvertFrom-Json).state) } catch { $djState = '' } }
    & $need 'the database setup job' ($djState -eq 'ok') $(if ($djState -eq 'ok') { 'its last result (cfg.InstallState DbJob) is ok' } elseif ($djState) { "its last result is '$djState' -- run it until it is ok first" } else { 'it has no result yet (cfg.InstallState DbJob) -- run it first' })
    $recApp = (Get-Val $st 'SupportApp').Trim()
    & $need 'the Support app on record' (-not $recApp -or $recApp -ieq $SupportAppId) $(if (-not $recApp) { 'none recorded (cfg.InstallState SupportApp): the heartbeat does not report its access' } elseif ($recApp -ieq $SupportAppId) { 'the install records this Support app' } else { "the install records another Support app ($recApp)" })
    }
    # per product database: the support grant in place, the engine in si_engine, the Support app's roles, no open grant
    foreach ($db in $dbs) {
        try {
            $grant = ConvertFrom-SISupportGrantState -Row (@(Invoke-Db -Database $db -Purpose 'the support grant (read-only)' -ReadOnly -Query (Get-SISupportGrantStateSql -ClientId $SupportAppId))[0])
            $r = @(Invoke-Db -Database $db -Purpose 'the Support app''s roles, the engine''s role, open support grants (read-only)' -ReadOnly -Query (Get-StandingStateSql -AppId $SupportAppId -EngineClientId $rd.Shape.EngineClientId))[0]
            $roles = @((Get-Val $r 'Roles') -split ',' | Where-Object { $_ })
            $dbRead[$db] = [pscustomobject]@{ User = (Get-Val $r 'UserName'); Roles = $roles; EngineUser = (Get-Val $r 'EngineUser'); EngineInRole = ((Get-Val $r 'EngineInRole') -in '1', 'True'); Open = [int]("0" + (Get-Val $r 'OpenGrants')) }
            & $need ('{0}: the support grant' -f $db) $grant.Ok $(if ($grant.Ok) { ('4 procedures signed (2099, key removed), signer in db_owner, the engine may run them, the read-only role {0}, consent {1}' -f $readRole, $grant.Consent) } else { $grant.Lines -join '; ' })
            & $need ('{0}: the engine in si_engine' -f $db) ($dbRead[$db].EngineInRole) $(if ($dbRead[$db].EngineInRole) { ('{0} is in si_engine' -f $dbRead[$db].EngineUser) } elseif (-not $rd.Shape.EngineClientId) { 'the install''s jobs name no engine identity (SI_UAMI_ClientId)' } else { ('the engine''s user {0} is not in si_engine' -f $(if ($dbRead[$db].EngineUser) { $dbRead[$db].EngineUser } else { '(none)' })) })
        } catch { & $need ('{0}: read' -f $db) $false ('could not be read: {0}' -f $_.Exception.Message) }
    }
}
$dbRead = [ordered]@{}
$rsg = $SupportGrant
if (-not $rsg) { $rsg = New-SISupportGrantSeams -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup -StorageAccount $StorageAccount }
$rga = Get-SISupportGrantArgs -SupportGrant $rsg -Say { param([string]$t, [string]$c) Write-Host ('  ' + $t) -ForegroundColor $(if ($c) { $c } else { 'Gray' }) }
$rga['Purpose'] = 'read the install''s records, the support grant and the Support app''s roles (plan and preconditions; nothing written)'
$rga['Tool'] = $scriptName; $rga['GrantLevel'] = 'troubleshoot'; $rga['WriteKind'] = 'audit'
$rga['Do'] = { $rd.Ran = $true; & $readSql }
$rga['Probe'] = { & $S $Server $proDb (Get-SISupportAccessProbeSql) ('SI support standing access{0}: the Support app''s own rights (read-only)' -f $who) $true }
$rg = Invoke-SISupportWithGrant @rga
if ($rd.Ran) {
    $result.ReadGrant = if (-not $rg.Asked) { 'support grant for the reads: none asked (the Support app holds the right already, or the install is not on just-in-time access)' }
                        else { 'support grant for the reads: troubleshoot opened, read back, {0}' -f $(if ($rg.Closed) { 'closed again' } else { 'NOT closed from here -- it ends by itself within the hour' }) }
} else {
    # asked, not granted: the reads run without it -- what needs it says "could not be read"; refused below, nothing written
    $rgWhy = (([string]$rg.Why) -split "`n")[0]
    $result.ReadGrant = 'support grant for the reads: troubleshoot NOT in place ({0}) -- read without it: what needs it says could not be read, nothing is changed' -f $rgWhy
    & $readSql
}
Write-Line $result.ReadGrant $(if ($rd.Ran -and (-not $rg.Asked -or $rg.Closed)) { 'Gray' } else { 'Yellow' })
# no support grant open (read in each database): this run's OWN read grant, opened for the reads and closed again, is not
# counted (its marker was open while the reads ran)
$ownRead = if ($rd.Ran -and $rg.Opened) { 1 } else { 0 }
foreach ($db in $dbRead.Keys) {
    $o = [int]$dbRead[$db].Open
    & $need ('{0}: no support grant open' -f $db) ($o -le $ownRead) $(if ($o -eq 0) { 'none open' } elseif ($o -le $ownRead) { 'only this run''s own read grant (closed again)' } else { ('{0} open -- run this after the support session has closed' -f $o) })
}
$shape = $rd.Shape
foreach ($l in (Format-SIInstallShape -Shape $shape)) { Write-Host ('   ' + $l) }
foreach ($o in $otherServer) { & $need 'one database server' $false ('{0}: a product database on another server -- not handled here; give -Databases' -f $o) }
$result.Databases = $dbs.ToArray()

# the support request queue and the support grant job
$queueOk = $false; $queueWhy = ''
if (-not $sgJob) { $queueWhy = 'the support grant job caj-si-support-grant is not in the resource group' }
elseif (-not $StorageAccount) { $queueWhy = 'the support grant job names no storage account (SI_STORAGE_ACCOUNT) -- give -StorageAccount' }
else {
    try {
        $qa = & $seams.Arm 'GET' ('/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}/queueServices/default/queues/si-support-requests?api-version=2023-05-01' -f $SubscriptionId, $ResourceGroup, $StorageAccount) $null
        $queueOk = [bool]$qa; if (-not $queueOk) { $queueWhy = ('the queue si-support-requests is not in {0}' -f $StorageAccount) }
    } catch { $queueWhy = ('the queue could not be read: {0}' -f $_.Exception.Message) }
}
& $need 'the support request queue' $queueOk $(if ($queueOk) { ('si-support-requests in {0}, the job caj-si-support-grant' -f $StorageAccount) } else { $queueWhy })

# NEVER LOSE SQL ACCESS: the server's Entra admin is the group, and the group keeps another member
$gid = ''; $member = $false; $memberKnown = $false; $others = @()
$adminIsGroup = $shape.EntraAdmin -and $shape.EntraAdmin.Type -eq 'Group' -and $shape.EntraAdmin.Sid -and $shape.AdminGroup
& $need 'the server''s Entra admin is the SQL admin group' ([bool]$adminIsGroup) $(if ($adminIsGroup) { ('{0} ({1})' -f [string]$shape.AdminGroup.displayName, $shape.EntraAdmin.Sid) } elseif ($shape.EntraAdmin) { ('it is {0} ({1}), not a group that could be read' -f $shape.EntraAdmin.Login, $shape.EntraAdmin.Type) } else { 'the server names no Entra admin' })
if ($adminIsGroup) {
    $gid = [string]$shape.EntraAdmin.Sid
    if ($sp) { try { $member = Test-Member -SpId $sp.Id -GroupId $gid; $memberKnown = $true } catch { & $need 'the Support app''s membership' $false ('could not be read: {0}' -f $_.Exception.Message) } }
    $others = @(@(@($shape.AdminGroupMembers) | Where-Object { $_ -and (-not $sp -or [string]$_.Id -ne [string]$sp.Id) } | ForEach-Object { [string]$_.Name }) + @($shape.AdminGroupMemberOf) | Where-Object { $_ } | Select-Object -Unique)
    & $need 'another member stays in the SQL admin group' ($others.Count -gt 0) $(if ($others.Count) { 'it keeps: ' + ($others -join ', ') } else { 'no other member could be read (not from the group, not from the install''s identities) -- the Support app would be the last one: refused' })
}
$result.Preconditions = $pre.ToArray()
$ready = -not @($pre | Where-Object { -not $_.Ok }).Count
$result.Ready = $ready

# THE END STATE, from THIS run's reads only ('' = proven; else why not): no db_owner in ANY product database (read after the
# change where one was made, else read above) AND not a member of the SQL admin group (read back after the removal, else
# read above from the Support app's memberOf). Anything not read is NOT proven -- the 'ok' row is then never written.
function Test-StandingEndState {
    foreach ($db in $dbs) {
        $roles = if ($result.RolesAfter.Contains($db)) { @($result.RolesAfter[$db]) } elseif ($dbRead.Contains($db)) { @($dbRead[$db].Roles) } else { return ('{0}: the Support app''s roles were not read' -f $db) }
        if ($roles -contains 'db_owner') { return ('{0}: db_owner is still read back' -f $db) }
    }
    if (-not $sp -or -not $gid) { return 'the SQL admin group membership is not known (see the preconditions)' }
    if ($null -ne $result.MemberAfter) { if ([bool]$result.MemberAfter) { return 'still read back as a member of the SQL admin group' } else { return '' } }
    if (-not $memberKnown) { return 'the SQL admin group membership could not be read' }
    if ($member) { return 'a member of the SQL admin group' }
    ''
}
$endBefore = Test-StandingEndState

# ---------------------------------------------------------------------------------------------------- PLAN
$want = @(if ($Steps.Count) { Resolve-SICutoverSteps -Steps $Steps -Known $known } else { $known })
$ownerIn = @($dbRead.Keys | Where-Object { @($dbRead[$_].Roles) -contains 'db_owner' })
# the membership goes LAST: never while the standing db_owner is still there and not taken in this run
$groupBlocked = ($want -contains 'admin-group') -and ($want -notcontains 'db-owner') -and $ownerIn.Count
if ($groupBlocked) { & $need 'the order' $false ('the admin group membership goes last: db_owner is still held in {0} -- run with -Steps db-owner first (or both)' -f ($ownerIn -join ', ')); $result.Preconditions = $pre.ToArray(); $ready = $false; $result.Ready = $false }
$planLines = [ordered]@{
    'db-owner'    = $(if ($ownerIn.Count) { ('take the Support app''s user out of db_owner in {0} (its user and {1} stay)' -f ($ownerIn -join ', '), $readRole) } else { 'nothing to do: the Support app''s user is in db_owner in no product database' })
    'admin-group' = $(if ($groupBlocked) { 'BLOCKED: db_owner first' } elseif (-not $sp -or -not $gid) { 'not known (see the preconditions)' } elseif ($member) { ('take the Support app out of {0} (the group stays the server''s Entra admin; {1} stay)' -f [string]$shape.AdminGroup.displayName, ($others -join ', ')) } else { 'nothing to do: the Support app is not a member' })
}
Write-Line ('Support app      : {0}' -f $(if ($sp) { '{0} (client {1}, service principal {2})' -f $sp.DisplayName, $SupportAppId, $sp.Id } else { $SupportAppId }))
foreach ($db in $dbRead.Keys) { Write-Line ('{0,-17}: user {1}, roles {2}' -f $db, $(if ($dbRead[$db].User) { $dbRead[$db].User } else { '(none)' }), $(if (@($dbRead[$db].Roles).Count) { @($dbRead[$db].Roles) -join ', ' } else { '(none)' })) }
if ($gid) { Write-Line ('admin group      : {0} -- the Support app is {1}a member' -f [string]$shape.AdminGroup.displayName, $(if ($member) { '' } else { 'NOT ' })) }
foreach ($p in $pre) { Write-Line ('{0} {1}: {2}' -f $(if ($p.Ok) { '[ok]     ' } else { '[NOT OK] ' }), $p.Name, $p.Detail) $(if ($p.Ok) { 'Gray' } else { 'Yellow' }) }
foreach ($k in $want) { Write-Line ('{0,-12}: {1}' -f $k, $planLines[$k]) $(if ($planLines[$k] -match '^nothing|^not known') { 'DarkGray' } else { 'White' }) }
$result.Plan = @($want | ForEach-Object { '{0}: {1}' -f $_, $planLines[$_] })
Write-Line 'Today Invardia''s daily support check and a re-run of Grant-SISupportAccess / Grant-SISupportAppDatabase / a support repair of the database setup job add both rights again -- after the change the heartbeat names it when a standing right is back.' 'DarkGray'

if (-not $endBefore) { Write-Line 'already in the end state (read in this run): no db_owner in any product database, not a member of the SQL admin group -- -Apply changes nothing and records it for the heartbeat (cfg.InstallState SupportStanding)' 'White' }

if (-not $Apply) {
    Write-Line $(if ($ready) { 'PLAN ONLY -- nothing was changed. Every precondition holds; -Apply makes the steps above.' } else { 'PLAN ONLY -- nothing was changed. NOT READY: -Apply refuses until every precondition above is ok.' }) 'Yellow'
    $result.Ok = $true
    return (Complete-Run 0)
}
# NOTHING TO DO (live 2026-11-09: the heartbeat kept "standing admin remains" from an old updater row after the change was
# made): already in the end state, read in this run -- nothing is changed, no rollback record; ONLY the state row is written
if (-not $endBefore) {
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('db-owner: nothing to do -- the Support app''s user is in db_owner in no product database (read in this run)')
    $lines.Add('admin-group: nothing to do -- the Support app is not a member (read in this run from its memberOf)')
    $lines.Add((Save-StandingRow))
    $result.MemberAfter = $false
    $result.Lines = $lines.ToArray(); $result.Ok = $true
    foreach ($l in $result.Lines) { Write-Line $l $(if ($l -match 'NOT written') { 'Yellow' } else { 'Green' }) }
    return (Complete-Run 0)
}
if (-not $ready) {
    $result.Refused = $true
    $result.Lines = @('Refused: not every precondition holds (see above) -- nothing was changed.')
    Write-Line $result.Lines[0] 'Red'
    return (Complete-Run 1)
}

# ---------------------------------------------------------------------------------------------------- APPLY
$started = [datetime]::UtcNow
$record = New-SICutoverRecord -Script $scriptName -Environment $Environment -Shape $shape -Now $started
$record['sqlServer'] = $Server; $record['database'] = $proDb; $record['supportAppId'] = $SupportAppId
$record.before['db-owner'] = [ordered]@{ databases = @(foreach ($db in $dbRead.Keys) { [ordered]@{ database = $db; user = $dbRead[$db].User; roles = (@($dbRead[$db].Roles) -join ',') } }) }
$record.before['admin-group'] = [ordered]@{ groupId = $gid; groupName = [string]$shape.AdminGroup.displayName; servicePrincipalId = [string]$sp.Id; member = [bool]$member; others = $others }
$recPath = Get-SICutoverRecordPath -Directory $RecordDirectory -Script $scriptName -Environment $Environment -Now $started
$result.RecordPath = $recPath
$ok = $true; $lines = New-Object System.Collections.Generic.List[string]
$save = { $sv = Save-SICutoverRecord -Record $record -Path $recPath -Sql $saveSql -StateName $stateName; $result.InstallLine = [string]$sv.InstallLine }
foreach ($k in $want) {
    if (-not $ok) { $lines.Add(('{0}: not made -- an earlier step did not complete' -f $k)); continue }
    # the record names the step BEFORE it is made (while the Support app may still write the install's record)
    $record.applied = @($record.applied) + @($k); & $save
    switch ($k) {
        'db-owner' {
            foreach ($db in $dbs) {
                try {
                    $r = @(Invoke-Db -Database $db -Purpose 'db-owner -- the Support app''s user out of db_owner (one transaction; its user and the read-only role stay)' -Query (Get-DbOwnerChangeSql -AppId $SupportAppId -Change 'remove'))[0]
                    $now = @(Get-Roles -Database $db -AppId $SupportAppId)
                    $result.RolesAfter[$db] = $now
                    if (($now -contains 'db_owner') -or ($now -notcontains $readRole)) { $ok = $false; $lines.Add(('{0}: read back {1} -- NOT as intended' -f $db, ($now -join ', '))) }
                    else { $lines.Add(('{0}: db_owner removed (read back: {1})' -f $db, ($now -join ', '))) }
                } catch { $ok = $false; $lines.Add(('{0}: db_owner NOT removed ({1})' -f $db, $_.Exception.Message)) }
            }
        }
        'admin-group' {
            if (-not $member) { $lines.Add('admin-group: nothing to do -- the Support app is not a member'); $result.MemberAfter = $false; break }
            try {
                $null = & $G 'DELETE' ('https://graph.microsoft.com/v1.0/groups/{0}/members/{1}/$ref' -f $gid, $sp.Id) $null
                $gone = Wait-Member -SpId $sp.Id -GroupId $gid -Want $false
                $result.MemberAfter = -not $gone
                if ($gone) { $lines.Add(('admin-group: the Support app is no longer a member of {0} (read back from its memberOf)' -f [string]$shape.AdminGroup.displayName)) }
                else { $ok = $false; $lines.Add('admin-group: removed, but still read back as a member -- run the plan again in a few minutes; -Rollback puts it back') }
            } catch { $ok = $false; $result.MemberAfter = $true; $lines.Add(('admin-group: NOT removed ({0})' -f $_.Exception.Message)) }
        }
    }
    if (-not $ok -and $k -eq 'admin-group' -and $result.MemberAfter) {
        # not made: the record says so (the Support app is still an admin here, so the install's row can be written)
        $record.applied = @(@($record.applied) | Where-Object { $_ -ne $k }); & $save
    }
}
# the Support app's own sign-in, on a new connection: no longer dbo (membership reaches a sign-in after some minutes)
if ($ok -and $want -contains 'admin-group' -and $member) {
    for ($i = 1; $i -le $ReadBackTries; $i++) {
        try {
            $w = @(Invoke-Db -Database $proDb -Purpose 'read back -- who the Support app signs in as (read-only)' -ReadOnly -Query "SELECT USER_NAME() AS U, ISNULL(IS_ROLEMEMBER(N'db_owner'), 0) AS O;")[0]
            $result.SignInAfter = ('{0}, db_owner {1}' -f (Get-Val $w 'U'), (Get-Val $w 'O'))
            if ((Get-Val $w 'U') -ne 'dbo' -and (Get-Val $w 'O') -in '0', 'False') { break }
        } catch { $result.SignInAfter = ('could not be read ({0})' -f $_.Exception.Message) }
        if ($i -lt $ReadBackTries) { & $Sleep $ReadBackSeconds }
    }
    $lines.Add(('the Support app signs in as: {0}{1}' -f $result.SignInAfter, $(if ($result.SignInAfter -match '^dbo') { ' -- still dbo on this connection (its sign-in carries the old membership for a while): run the plan again later' } else { '' })))
}
# THE STATE ROW: 'ok' ONLY when every step completed AND this run's read-back proves the end state; else it is not written
# (the row keeps what it said -- never 'ok' on a read-back that did not prove it)
if ($ok) {
    $endAfter = Test-StandingEndState
    if (-not $endAfter) { $lines.Add((Save-StandingRow)) }
    else { $lines.Add(('state row: not written -- the end state is not proven by this run''s read-back ({0})' -f $endAfter)) }
} else { $lines.Add('state row: not written -- not every step completed') }
$result.Lines = $lines.ToArray(); $result.Ok = $ok
foreach ($l in $result.Lines) { Write-Line $l $(if ($ok) { 'Green' } else { 'Yellow' }) }
Write-Line ('rollback record: {0}{1}' -f $recPath, $(if ($result.InstallLine) { ' -- ' + $result.InstallLine } else { '' })) 'Cyan'
Write-Line ('rollback: .\setup\{0}.ps1 -ResourceGroup {1} -Rollback ''{2}'' -Apply' -f $scriptName, $ResourceGroup, $recPath) 'DarkGray'
if (@($shape.Jobs).Count) {
    Write-Line ('waiting {0} minute(s), then counting the runs since the change ...' -f $ObserveMinutes) 'DarkGray'
    $obs = Wait-SICutoverObservation -Arm $seams.Arm -Shape $shape -Since $started -Minutes $ObserveMinutes -Sleep $Sleep
    $result.Observation = $obs
    Write-Line $obs.Line $(if ($obs.Failed) { 'Red' } elseif ($obs.Runs) { 'Green' } else { 'Yellow' })
    foreach ($l in @($obs.Lines)) { Write-Line ('   ' + $l) 'Red' }
}
Complete-Run $(if ($ok) { 0 } else { 1 })
