#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Pro: moves an EXISTING install's engine identity from db_datareader + db_datawriter on the whole Pro
    database to its least-privilege role si_engine (framework DOCS/REQUIREMENTS.md §12.23 SQL-ACCESS P8).

.DESCRIPTION
    Run per environment by Invardia support inside the environment's Support session
    (. Connect-InvardiaSupport.ps1 -Environment <handle> -Reason ...). The pattern is setup\_shared\SI-SupportCutover.ps1:
    EVERY statement goes through Invardia's audited Invoke-InvardiaSupportSql (the audit row first: server, database, the
    statement's SHA-256, the purpose line; then the outcome), every Azure read through Invoke-InvardiaSupportArm. Without a
    Support session the script refuses; it never opens a database connection of its own.

    PLAN BY DEFAULT: prints the install's shape (resource group, image, identities with client ids, the SQL server and its
    Entra admin, the database users with their roles, the admin group's members), then the read-only proof and what each
    step WOULD do. Nothing is changed. The SQL server, the database and the engine user are found from the install's OWN
    jobs (SI_ProSqlServer / SI_ProSqlDatabase and SI_UAMI_ClientId -> the identity's name), never by a name pattern;
    -Server / -Database / -EngineUser override them and the user is still confirmed by its client id when one is known.
      -Apply -Steps <list>   (string names, in this order; ADD before REMOVE):
        proof                the role's real grants against every statement the engine runs (the inventory of THIS
                             release's code): every one allowed, no procedure still letting only db_datawriter in. Read-only.
        grants               the role si_engine and its grants (engine\pro-settings\SI-EngineGrants.ps1, idempotent).
        membership           the engine user into si_engine, with the in-database rollback record (its roles before, kept
                             in cfg.InstallState 'EngineSqlAccessBefore', written once) -- one transaction. The broad
                             roles STAY. Nothing to do when the user is already in si_engine.
        remove-broad-roles   a SEPARATE, LATER run -- after the pipeline ran green on the role: the proof again, and only
                             when it is green, db_datareader + db_datawriter removed (one transaction that also refuses
                             when the user is not in si_engine or there is no in-database record).
      -Rollback <record> -Apply   the user's roles back as the in-database record says (db_datareader / db_datawriter
                             re-added, si_engine left when it was not there before) and that record cleared.
    Every change is read back (the user's roles after are printed). ONE rollback record per run: a JSON file here (the
    path is printed; the roles before) plus the in-database record. After -Apply the script waits -ObserveMinutes (default
    6), then counts the install's runs since the cut-over and the failures. One environment at a time.

    The updater never changes these rights; at each update it only checks them and warns on drift.

.EXAMPLE
    . C:\claude-sessions\Invardia\tools\Connect-InvardiaSupport.ps1 -Environment <handle> -Reason 'SI engine least privilege'
    .\setup\Move-SIEngineToLeastPrivilege.ps1 -ResourceGroup <rg>
    .\setup\Move-SIEngineToLeastPrivilege.ps1 -ResourceGroup <rg> -Apply -Steps grants,membership
.EXAMPLE
    .\setup\Move-SIEngineToLeastPrivilege.ps1 -ResourceGroup <rg> -Apply -Steps remove-broad-roles
    .\setup\Move-SIEngineToLeastPrivilege.ps1 -ResourceGroup <rg> -Rollback <record.json> -Apply
#>
[CmdletBinding()]
param(
    # the install's resource group (where its jobs are): the server, database and engine user are read from its jobs
    [string]$ResourceGroup,
    [string]$SubscriptionId,
    [switch]$Apply,
    [string[]]$Steps = @(),
    [string]$Rollback = '',
    # overrides (a test, or an install whose jobs cannot be read); never guessed
    [string]$Server,
    [string]$Database,
    [string]$EngineUser,
    [string]$EngineClientId,
    [string]$Environment = '',
    [string]$Reason = 'SI engine least privilege',
    [string]$RecordDirectory = '',
    [ValidateRange(0, 30)][int]$ObserveMinutes = 6,
    # TEST SEAMS (setup\_shared\SI-SupportCutover.ps1)
    [scriptblock]$Arm, [scriptblock]$Sql, [scriptblock]$Graph,
    [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s },
    [switch]$PassThru
)
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($siRoot, 'engine', 'pro-settings', 'SI-EngineGrants.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportCutover.ps1'))
$known = @('proof', 'grants', 'membership', 'remove-broad-roles')
$role = $script:SIEngineRole

# refused without the audited SQL call (the Support session) unless a test passes its own seams
if (-not $Sql -and -not (Get-Command -Name Invoke-InvardiaSupportSql -ErrorAction SilentlyContinue)) {
    throw ('Refused: Invoke-InvardiaSupportSql is not available in this shell. Every statement of this cut-over goes through ' +
           'Invardia''s audited SQL call -- sign in with Connect-InvardiaSupport.ps1 (a version that has it) and run again. ' +
           'Nothing was sent; this script never opens a database connection of its own.')
}
if (-not $ResourceGroup) {
    # -Server given: the install's jobs are not read, so ARM and Graph are not used
    if (-not $Arm) { $Arm = { param($Method, $Path, $Body) throw 'ARM is not read when -Server is given (give -ResourceGroup)' } }
    if (-not $Graph) { $Graph = { param($Method, $Uri, $Body) throw 'Graph is not read when -Server is given' } }
}
$seams = New-SICutoverSeams -Arm $Arm -Sql $Sql -Graph $Graph -Reason $Reason
$sess = $null; if (Get-Command -Name Get-SISupportSession -ErrorAction SilentlyContinue) { try { $sess = Get-SISupportSession } catch { $sess = $null } }
if (-not $Environment) { $Environment = if ($sess -and [string]$sess.Environment) { [string]$sess.Environment } else { '' } }
if (-not $RecordDirectory) { $RecordDirectory = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'si', 'logs', 'cutover') }
$who = if ($Environment) { " ($Environment)" } else { '' }
$want = @(Resolve-SICutoverSteps -Steps $Steps -Known $known)
if ($Apply -and -not $Rollback -and -not $want.Count) { throw ('-Apply needs -Steps: name the steps to make ({0}). Nothing was changed.' -f ($known -join ', ')) }

# ---------------------------------------------------------------------------------------------------- SHAPE
$shape = $null
if ($ResourceGroup) {
    if (-not $SubscriptionId) { $SubscriptionId = if ($sess) { [string]$sess.SubscriptionId } else { '' } }
    if (-not $SubscriptionId) { throw 'Give -SubscriptionId: the Support session names no subscription.' }
    $shape = Get-SIInstallShape -Arm $seams.Arm -SubscriptionId $SubscriptionId -ResourceGroup $ResourceGroup
    if (-not $Server) { $Server = $shape.SqlFqdn }
    if (-not $Database) { $Database = $shape.Database }
    if (-not $EngineUser -and $shape.EngineIdentity) { $EngineUser = $shape.EngineIdentity.Name }
    if (-not $EngineClientId) { $EngineClientId = $shape.EngineClientId }
    if ($shape.SqlFqdn -and -not $shape.SqlServerId) { throw ('Refused: the database server the jobs use ({0}) is not in subscription {1} -- nothing was changed.' -f $shape.SqlFqdn, $SubscriptionId) }
} else {
    $shape = [pscustomobject]@{ SubscriptionId = ''; ResourceGroup = '(not read: -Server given)'; Jobs = @(); Apps = @(); Image = ''; Identities = @(); EngineIdentity = $null; EngineClientId = $EngineClientId
                                SqlFqdn = $Server; Database = $Database; SqlServer = $null; SqlServerId = ''; EntraAdmin = $null; WorkspaceResourceId = ''; KeyVaultName = ''
                                DbUsers = @(); AdminGroup = $null; AdminGroupMembers = @(); AdminGroupMemberOf = @(); Problems = @() }
}
if (-not $Database) { $Database = 'sqldb-si-pro'; $shape.Database = $Database }
if (-not $Server) { throw 'Refused: the database server is not known -- give -ResourceGroup (the install''s jobs name it) or -Server. Nothing was changed.' }
if (-not $EngineUser) { throw 'Refused: the engine''s database user is not known -- the jobs name no engine identity (SI_UAMI_ClientId); give -EngineUser. Nothing was changed.' }
$shape = Add-SIInstallSqlShape -Shape $shape -Sql $seams.Sql -Graph $(if ($ResourceGroup) { $seams.Graph } else { $null }) -Reason ('SI engine least privilege{0}: read the database users (read-only)' -f $who)
Write-Host ("SecurityInsight engine least privilege{0} -- {1}/{2}, engine user {3}" -f $who, $Server, $Database, $EngineUser)
foreach ($l in (Format-SIInstallShape -Shape $shape)) { Write-Host ('   ' + $l) }

$S = $seams.Sql
$q = { param([string]$s) "N'" + $s.Replace("'", "''") + "'" }
$u = & $q $EngineUser
function Invoke-Step([string]$Purpose, [string]$Query, [switch]$ReadOnly) {
    Write-Host ("  {0}" -f $Purpose)
    , @(& $S $Server $Database $Query ('SI engine least privilege{0}: {1}' -f $who, $Purpose) ([bool]$ReadOnly) | ForEach-Object { $_ })
}
function Get-RowValue($Row, [string]$Name) { [string](Get-SICutoverProp $Row @($Name)) }
function Invoke-Proof {
    $rows = Invoke-Step -Purpose 'proof (read-only) -- the role''s grants against every statement the engine runs' -Query (Get-SIEngineAccessStateSql -UserName $EngineUser) -ReadOnly
    $state = ConvertFrom-SIEngineAccessRows -Rows $rows
    $req = Get-SIEngineRequiredPermission -References (Get-SIEngineSqlReference -SIRoot $siRoot)
    $ready = Test-SIEngineCutoverReady -State $state -Required $req -UserName $EngineUser
    [pscustomobject]@{ State = $state; Ready = $ready; Statements = @($req).Count }
}
function Get-RolesNow {
    $rows = Invoke-Step -Purpose 'read back -- the engine user''s roles now (read-only)' -ReadOnly -Query ("SELECT r.name AS RoleName FROM sys.database_role_members AS m JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = DATABASE_PRINCIPAL_ID({0});" -f $u)
    @(@($rows) | ForEach-Object { Get-RowValue $_ 'RoleName' } | Where-Object { $_ })
}

$result = [ordered]@{ Server = $Server; Database = $Database; EngineUser = $EngineUser; Action = $(if ($Rollback) { 'rollback' } elseif ($Apply) { 'apply' } else { 'plan' }); Steps = $want
                      Ok = $false; Lines = @(); RolesBefore = ''; RolesAfter = @(); RecordPath = $null; Observation = $null }

# the engine user, confirmed by its client id (its SID) when one is known
if ($EngineClientId) {
    $null = [guid]$EngineClientId
    $rows = Invoke-Step -Purpose 'confirm the engine user by its client id (read-only)' -ReadOnly -Query ("SELECT name FROM sys.database_principals WHERE sid = CONVERT(varbinary(16), CAST({0} AS uniqueidentifier))" -f (& $q $EngineClientId))
    $name = if (@($rows).Count) { Get-RowValue @($rows)[0] 'name' } else { '' }
    if ($name -ne $EngineUser) { throw ("Refused: the client id {0} is the database user '{1}', not '{2}' -- nothing was changed" -f $EngineClientId, $name, $EngineUser) }
}

# ---------------------------------------------------------------------------------------------------- ROLLBACK
if ($Rollback) {
    if (-not $Apply) {
        Write-Host '  PLAN ONLY -- nothing was changed. Add -Apply to put the engine user''s roles back as the in-database record says.' -ForegroundColor Yellow
        $result.Ok = $true; $result.RolesAfter = Get-RolesNow
        if ($PassThru) { return [pscustomobject]$result } else { return }
    }
    $rbSql = @"
SET XACT_ABORT ON;
DECLARE @u sysname = $u, @s nvarchar(400);
DECLARE @rec nvarchar(400) = (SELECT Value FROM cfg.InstallState WHERE Name = N'EngineSqlAccessBefore');
IF @rec IS NULL THROW 51672, N'there is no rollback record -- nothing was changed', 1;
IF JSON_VALUE(@rec, '$.user') <> @u THROW 51672, N'the rollback record is for another user -- nothing was changed', 1;
DECLARE @before nvarchar(300) = N',' + ISNULL(JSON_VALUE(@rec, '$.roles'), N'') + N',';
BEGIN TRANSACTION;
IF CHARINDEX(N',db_datareader,', @before) > 0 BEGIN SET @s = N'ALTER ROLE db_datareader ADD MEMBER ' + QUOTENAME(@u); EXEC (@s); END
IF CHARINDEX(N',db_datawriter,', @before) > 0 BEGIN SET @s = N'ALTER ROLE db_datawriter ADD MEMBER ' + QUOTENAME(@u); EXEC (@s); END
IF CHARINDEX(N',$role,', @before) = 0 AND ISNULL(IS_ROLEMEMBER(N'$role', @u), 0) = 1 BEGIN SET @s = N'ALTER ROLE [$role] DROP MEMBER ' + QUOTENAME(@u); EXEC (@s); END
DELETE FROM cfg.InstallState WHERE Name = N'EngineSqlAccessBefore';
COMMIT TRANSACTION;
SELECT r.name AS RoleName FROM sys.database_role_members AS m JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = DATABASE_PRINCIPAL_ID(@u);
"@
    $rows = Invoke-Step -Purpose 'rollback -- the engine user''s roles as the in-database record says, and that record cleared' -Query $rbSql
    $result.RolesAfter = @(@($rows) | ForEach-Object { Get-RowValue $_ 'RoleName' })
    $result.Ok = $true
    $result.Lines = @(('rolled back: the engine user now has {0} (read back)' -f $(if ($result.RolesAfter.Count) { $result.RolesAfter -join ', ' } else { 'no role' })))
    foreach ($l in @($result.Lines)) { Write-Host ('  ' + $l) -ForegroundColor Green }
    if ($PassThru) { return [pscustomobject]$result } else { return }
}

# ---------------------------------------------------------------------------------------------------- PROOF + PLAN
$rolesBefore = @(Get-RolesNow)
$p = Invoke-Proof
$inRole = $rolesBefore -contains $role
$broad = @($rolesBefore | Where-Object { $_ -in 'db_datareader', 'db_datawriter' })
$plan = [ordered]@{
    'grants'             = ('the role {0} and its grants as this release ships them (idempotent: run again changes nothing that is already there)' -f $role)
    'membership'         = $(if ($inRole) { ('nothing to do: {0} is already in {1}' -f $EngineUser, $role) } else { ('add {0} to {1} (the broad roles stay)' -f $EngineUser, $role) })
    'remove-broad-roles' = $(if (-not $broad.Count) { 'nothing to do: no broad role left' } elseif (-not $inRole) { ('BLOCKED: {0} is not in {1} yet (membership first)' -f $EngineUser, $role) } elseif (-not $p.Ready.Ok) { 'BLOCKED: the proof is not green' } else { ('remove {0} (a later run, after a green pipeline on the role)' -f ($broad -join ', ')) })
}
Write-Host ('  roles now   : {0}' -f $(if ($rolesBefore.Count) { $rolesBefore -join ', ' } else { '(none)' }))
Write-Host ('  proof       : {0}' -f $(if ($p.Ready.Ok) { ('green -- the role allows all {0} statement kinds the engine runs' -f $p.Statements) } else { 'NOT green: ' + (@($p.Ready.Lines) -join '; ') })) -ForegroundColor $(if ($p.Ready.Ok) { 'Green' } else { 'Yellow' })
foreach ($k in $plan.Keys) { Write-Host ('  {0,-18}: {1}' -f $k, $plan[$k]) -ForegroundColor $(if ($plan[$k] -match '^(BLOCKED|nothing)') { 'DarkGray' } else { 'White' }) }
$result.RolesBefore = $rolesBefore -join ','
if (-not $Apply) {
    Write-Host ('  PLAN ONLY -- nothing was changed. Apply: -Apply -Steps <{0}>' -f ($known -join ',')) -ForegroundColor Yellow
    $result.Ok = $p.Ready.Ok; $result.Lines = $p.Ready.Lines; $result.RolesAfter = $rolesBefore
    if ($PassThru) { return [pscustomobject]$result } else { return }
}

# ---------------------------------------------------------------------------------------------------- APPLY
$started = [datetime]::UtcNow
$record = New-SICutoverRecord -Script 'Move-SIEngineToLeastPrivilege' -Environment $Environment -Shape $shape -Now $started
$record['sqlServer'] = $Server; $record['database'] = $Database
$recPath = Get-SICutoverRecordPath -Directory $RecordDirectory -Script 'Move-SIEngineToLeastPrivilege' -Environment $Environment -Now $started
$lines = New-Object System.Collections.Generic.List[string]
$ok = $true
foreach ($k in $want) {
    switch ($k) {
        'proof' { }   # read again AFTER the changes below (the proof of what this run left)
        'grants' {
            $record.before[$k] = [ordered]@{ user = $EngineUser; roles = ($rolesBefore -join ',') }; $record.applied = @($record.applied) + @($k)
            $null = Save-SICutoverRecord -Record $record -Path $recPath
            $null = Invoke-Step -Purpose ('grants -- the role {0} and its grants (idempotent)' -f $role) -Query (Get-SIEngineGrantSql)
            $lines.Add(('grants: the role {0} and its grants are as this release ships them' -f $role))
            # #881 the role's read right on the database's own load: a batch of its own; refused = said, never a stop
            try {
                $dg = @(Invoke-Step -Purpose ('grants -- the role {0}''s read right on the database''s own load (its own batch)' -f $role) -Query (Get-SIEngineDatabaseGrantSql)) | Select-Object -First 1
                $dgl = Format-SIEngineDatabaseGrantLine -Granted (Get-RowValue $dg 'Granted') -Reason (Get-RowValue $dg 'Reason')
                if ($dgl) { $lines.Add($dgl) }
            } catch { $lines.Add(('WARNING: grants: the read right on the database''s own load was not granted ({0})' -f $_.Exception.Message)) }
        }
        'membership' {
            if ($inRole) { $lines.Add(('membership: nothing to do -- {0} is already in {1}' -f $EngineUser, $role)); break }
            $record.before[$k] = [ordered]@{ user = $EngineUser; roles = ($rolesBefore -join ',') }; $record.applied = @($record.applied) + @($k)
            $null = Save-SICutoverRecord -Record $record -Path $recPath
            $memberSql = @"
SET XACT_ABORT ON;
DECLARE @u sysname = $u;
IF DATABASE_PRINCIPAL_ID(@u) IS NULL THROW 51672, N'the engine user is not in this database -- nothing was changed', 1;
IF DATABASE_PRINCIPAL_ID(N'$role') IS NULL THROW 51672, N'the role $role is not there -- run the step grants first', 1;
DECLARE @before nvarchar(300) = ISNULL((SELECT STRING_AGG(CONVERT(nvarchar(max), r.name), N',') FROM sys.database_role_members AS m
    JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = DATABASE_PRINCIPAL_ID(@u)), N'');
BEGIN TRANSACTION;
IF NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'EngineSqlAccessBefore')
    INSERT cfg.InstallState (Name, Value, UpdatedBy)
    VALUES (N'EngineSqlAccessBefore', (SELECT @u AS [user], @before AS roles, CONVERT(nvarchar(20), SYSUTCDATETIME(), 126) AS [at] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER), N'Move-SIEngineToLeastPrivilege');
DECLARE @s nvarchar(400) = N'ALTER ROLE [$role] ADD MEMBER ' + QUOTENAME(@u); EXEC (@s);
COMMIT TRANSACTION;
SELECT @before AS RolesBefore, (SELECT Value FROM cfg.InstallState WHERE Name = N'EngineSqlAccessBefore') AS Record;
"@
            $rows = Invoke-Step -Purpose ('membership -- the engine user into {0}, with the in-database rollback record (its roles before)' -f $role) -Query $memberSql
            if (@($rows).Count) { $result.RolesBefore = Get-RowValue @($rows)[0] 'RolesBefore' }
            $now = @(Get-RolesNow)
            if ($now -notcontains $role) { $ok = $false }
            $lines.Add(('membership: the engine user now has {0} (read back); the broad roles STAY until a later run with -Steps remove-broad-roles' -f ($now -join ', ')))
        }
        'remove-broad-roles' {
            $p2 = Invoke-Proof
            if (-not $p2.Ready.Ok) { $ok = $false; $lines.Add('Refused: the broad roles stay -- the proof is not green:'); foreach ($x in @($p2.Ready.Lines)) { $lines.Add($x) }; break }
            $now0 = @(Get-RolesNow)
            if (-not @($now0 | Where-Object { $_ -in 'db_datareader', 'db_datawriter' }).Count) { $lines.Add('remove-broad-roles: nothing to do -- no broad role left'); break }
            $record.before[$k] = [ordered]@{ user = $EngineUser; roles = ($now0 -join ',') }; $record.applied = @($record.applied) + @($k)
            $null = Save-SICutoverRecord -Record $record -Path $recPath
            $removeSql = @"
SET XACT_ABORT ON;
DECLARE @u sysname = $u, @s nvarchar(400);
IF ISNULL(IS_ROLEMEMBER(N'$role', @u), 0) <> 1 THROW 51672, N'the engine user is not in $role -- the broad roles stay', 1;
IF NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'EngineSqlAccessBefore') THROW 51672, N'there is no rollback record -- run the step membership first; the broad roles stay', 1;
BEGIN TRANSACTION;
IF ISNULL(IS_ROLEMEMBER(N'db_datareader', @u), 0) = 1 BEGIN SET @s = N'ALTER ROLE db_datareader DROP MEMBER ' + QUOTENAME(@u); EXEC (@s); END
IF ISNULL(IS_ROLEMEMBER(N'db_datawriter', @u), 0) = 1 BEGIN SET @s = N'ALTER ROLE db_datawriter DROP MEMBER ' + QUOTENAME(@u); EXEC (@s); END
UPDATE cfg.InstallState SET UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'Move-SIEngineToLeastPrivilege remove-broad-roles' WHERE Name = N'EngineSqlAccessBefore';
COMMIT TRANSACTION;
SELECT r.name AS RoleName FROM sys.database_role_members AS m JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = DATABASE_PRINCIPAL_ID(@u);
"@
            $rows = Invoke-Step -Purpose 'remove-broad-roles -- db_datareader + db_datawriter off the engine user (the proof was green)' -Query $removeSql
            $now = @(@($rows) | ForEach-Object { Get-RowValue $_ 'RoleName' })
            if (-not (($now -contains $role) -and -not @($now | Where-Object { $_ -in 'db_datareader', 'db_datawriter' }).Count)) { $ok = $false }
            $lines.Add(('remove-broad-roles: the engine user now has {0} (read back)' -f ($now -join ', ')))
        }
    }
}
# the proof of what this run left (read-only): after grants / membership it must be green
if (@($want | Where-Object { $_ -in 'proof', 'grants', 'membership' }).Count) {
    $pf = Invoke-Proof
    if (-not $pf.Ready.Ok) { $ok = $false; $lines.Add('proof: NOT green -- ' + (@($pf.Ready.Lines) -join '; ')) }
    else { $lines.Add(('proof: green -- the role allows all {0} statement kinds the engine runs' -f $pf.Statements)) }
}
$result.RolesAfter = @(Get-RolesNow)
$result.Ok = $ok
$result.Lines = $lines.ToArray()
foreach ($l in @($result.Lines)) { Write-Host ('  ' + $l) -ForegroundColor $(if ($ok) { 'Green' } else { 'Yellow' }) }
if (@($record.applied).Count) {
    $result.RecordPath = $recPath
    Write-Host ('  rollback record: {0} (and cfg.InstallState ''EngineSqlAccessBefore'' in the database)' -f $recPath) -ForegroundColor Cyan
    if (@($shape.Jobs).Count) {
        Write-Host ('  waiting {0} minute(s), then counting the runs since the cut-over ...' -f $ObserveMinutes) -ForegroundColor DarkGray
        $obs = Wait-SICutoverObservation -Arm $seams.Arm -Shape $shape -Since $started -Minutes $ObserveMinutes -Sleep $Sleep
        $result.Observation = $obs
        Write-Host ('  ' + $obs.Line) -ForegroundColor $(if ($obs.Failed) { 'Red' } elseif ($obs.Runs) { 'Green' } else { 'Yellow' })
        foreach ($l in @($obs.Lines)) { Write-Host ('     ' + $l) -ForegroundColor Red }
    } else { Write-Host '  the install''s jobs were not read (-Server given): count the runs since the cut-over yourself before the next environment' -ForegroundColor Yellow }
}
if ($PassThru) { [pscustomobject]$result }
elseif (-not $result.Ok) { exit 1 }
