#Requires -Version 5.1
<#
.SYNOPSIS
    SecurityInsight Pro: installs the CERTIFICATE-SIGNED GRANT PROCEDURE cfg.ApplyComponentGrants on an EXISTING install,
    so every later update applies its grants without db_securityadmin and without any admin (#672; framework
    DOCS/REQUIREMENTS.md §12.23 SQL-ACCESS P4 / P8 / P9).

.DESCRIPTION
    Run per environment by Invardia support, signed in through the Invardia Support app
    (. Connect-InvardiaSupport.ps1 -Environment <handle> -Reason ...). EVERY statement goes through Invardia's audited
    Invoke-InvardiaSupportSql (the audit row first: server, database, SHA-256, the purpose line). Without that function the
    script refuses; it never opens a connection of its own.

    PLAN BY DEFAULT: without -Apply it reads the state (read-only) and prints every statement it would send -- nothing is
    changed. -Apply runs the chosen steps (-Steps, ;-separated; default all), one call per step, each with its purpose line:
      record     the ROLLBACK RECORD, written once: cfg.InstallState 'GrantProcedureBefore' = {"user","roles","procedure",
                 "signer","at"} -- the updater's roles before and whether a procedure was there;
      roles      every compiled component role (si_engine, si_web, si_audit_writer, si_mcp, si_updater, ... the reserved ones);
      procedure  the procedure (only when missing or another version);
      sign       a NEW in-database certificate (EXPIRY 2099-12-31, random password never returned), ADD SIGNATURE, the
                 private key REMOVED -- only when unsigned;
      rights     the signer certificate user's rights (CONTROL on the product schemas, ALTER ANY USER, ALTER on the
                 component roles);
      updater    si_updater may EXECUTE it (+ VIEW DEFINITION, a DENY of ALTER on the procedure), the updater's user into
                 si_updater;
    then the READ-BACK (read-only): procedure current + signed + 2099 + private key gone + si_updater EXECUTE + the updater
    a member. Nothing is removed: the updater keeps db_securityadmin, and its next update applies the release's grants
    THROUGH the procedure (it records the outcome in cfg.InstallState 'GrantProcedureLastApply').

      -RemoveSecurityAdmin  a SEPARATE, LATER run, only after the procedure is proven: the read-back green AND the
                            updater's own record of an update through the procedure with no failed row. Then
                            db_securityadmin is removed from the updater (one transaction that refuses without the record).
      -Rollback             puts db_securityadmin back if the record says the updater had it, takes the updater out of
                            si_updater if it was not there before, clears the record. The procedure and its certificate
                            stay (without si_updater's member nobody runs it); an update then takes today's path again.

.EXAMPLE
    . C:\claude-sessions\Invardia\tools\Connect-InvardiaSupport.ps1 -Environment si-internal -Reason 'SI signed grant procedure'
    .\setup\Install-SIGrantProcedure.ps1 -Server <sql server> -Database sqldb-si-pro -UpdaterUser uami-si-updater
    (the plan) -- then the same with -Apply
.EXAMPLE
    .\setup\Install-SIGrantProcedure.ps1 -Server <sql server> -Database sqldb-si-pro -UpdaterUser uami-si-updater -RemoveSecurityAdmin -Apply
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory)][string]$Server,
    [string]$Database = 'sqldb-si-pro',
    # the updater identity's database user (uami-si-updater); -UpdaterClientId as well makes the script confirm it by SID
    [Parameter(Mandatory)][string]$UpdaterUser,
    [string]$UpdaterClientId,
    [string]$Environment = '',
    [switch]$Apply,
    # ;-separated subset of: record;roles;procedure;sign;rights;updater (default all, in that order)
    [Parameter(ParameterSetName = 'Install')][string]$Steps = 'record;roles;procedure;sign;rights;updater',
    [Parameter(ParameterSetName = 'Remove')][switch]$RemoveSecurityAdmin,
    [Parameter(ParameterSetName = 'Rollback')][switch]$Rollback,
    # TEST SEAM: param([string]$Query, [string]$Reason, [bool]$ReadOnly) -> the rows. Default: Invoke-InvardiaSupportSql.
    [scriptblock]$SqlCall,
    [switch]$PassThru
)
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($siRoot, 'engine', 'pro-settings', 'SI-GrantProcedure.ps1'))

$who = if ($Environment) { " ($Environment)" } else { '' }
if (-not $SqlCall) {
    if (-not (Get-Command -Name Invoke-InvardiaSupportSql -ErrorAction SilentlyContinue)) {
        throw ('Refused: Invoke-InvardiaSupportSql is not available in this shell. Every statement of this cut-over goes through ' +
               'Invardia''s audited SQL call -- sign in with Connect-InvardiaSupport.ps1 (a version that has it) and run again. ' +
               'Nothing was sent; this script never opens a database connection of its own.')
    }
    $srv = $Server; $dbn = $Database
    $SqlCall = {
        param([string]$Query, [string]$Reason, [bool]$ReadOnly)
        $r = Invoke-InvardiaSupportSql -Server $srv -Database $dbn -Query $Query -Reason $Reason -ReadOnly:$ReadOnly
        if ($r -and $r.PSObject.Properties['Rows']) { , @($r.Rows) } else { , @() }
    }.GetNewClosure()
}
$valid = @('record', 'roles', 'procedure', 'sign', 'rights', 'updater')
$chosen = @($Steps -split '\s*;\s*' | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
$bad = @($chosen | Where-Object { $_ -notin $valid })
if ($bad.Count) { throw ("Refused: unknown step(s) {0} -- the steps are {1} (;-separated). Nothing was sent." -f ($bad -join ', '), ($valid -join ';')) }
$u = "N'" + $UpdaterUser.Replace("'", "''") + "'"

function Invoke-Step([string]$Purpose, [string]$Query, [switch]$ReadOnly) {
    Write-Host ("  {0}" -f $Purpose)
    , @(& $SqlCall $Query ('SI signed grant procedure{0}: {1}' -f $who, $Purpose) ([bool]$ReadOnly) | ForEach-Object { $_ })
}
function Read-State([string]$Purpose) {
    $rows = Invoke-Step -Purpose $Purpose -Query (Get-SIGrantProcedureStateSql -UpdaterUser $UpdaterUser) -ReadOnly
    ConvertFrom-SIGrantProcedureState -Row (@($rows) | Select-Object -First 1)
}

$result = [ordered]@{ Server = $Server; Database = $Database; UpdaterUser = $UpdaterUser; Action = $PSCmdlet.ParameterSetName; Applied = [bool]$Apply
                      Ok = $false; Lines = @(); Sent = @(); State = $null }
Write-Host ("SecurityInsight signed grant procedure{0} -- {1}/{2}, updater user {3}{4}" -f $who, $Server, $Database, $UpdaterUser, $(if ($Apply) { '' } else { ' -- PLAN (nothing is changed; add -Apply)' }))

if ($UpdaterClientId) {
    $null = [guid]$UpdaterClientId
    $rows = Invoke-Step -Purpose 'confirm the updater user by its client id (read-only)' -ReadOnly -Query ("SELECT name FROM sys.database_principals WHERE sid = CONVERT(varbinary(16), CAST(N'{0}' AS uniqueidentifier))" -f $UpdaterClientId)
    $name = if (@($rows).Count) { $r0 = @($rows)[0]; if ($r0 -is [System.Collections.IDictionary] -or $r0 -is [System.Data.DataRow]) { [string]$r0['name'] } else { [string]$r0.name } } else { '' }
    if ($name -ne $UpdaterUser) { throw ("Refused: the client id {0} is the database user '{1}', not '{2}' -- nothing was changed" -f $UpdaterClientId, $name, $UpdaterUser) }
}

$before = Read-State -Purpose 'read the state before (read-only)'
$result.State = $before

$recordSql = @"
SET XACT_ABORT ON;
DECLARE @u sysname = $u;
IF DATABASE_PRINCIPAL_ID(@u) IS NULL THROW 51672, N'the updater user is not in this database -- nothing was changed', 1;
IF NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'GrantProcedureBefore')
    INSERT cfg.InstallState (Name, Value, UpdatedBy)
    VALUES (N'GrantProcedureBefore', (SELECT @u AS [user],
        ISNULL((SELECT STRING_AGG(CONVERT(nvarchar(max), r.name), N',') WITHIN GROUP (ORDER BY r.name) FROM sys.database_role_members AS m JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id
                WHERE m.member_principal_id = DATABASE_PRINCIPAL_ID(@u)), N'') AS roles,
        CASE WHEN OBJECT_ID(N'cfg.ApplyComponentGrants') IS NULL THEN 0 ELSE 1 END AS [procedure],
        CONVERT(nvarchar(20), SYSUTCDATETIME(), 126) AS [at] FOR JSON PATH, WITHOUT_ARRAY_WRAPPER), N'Install-SIGrantProcedure');
SELECT Value AS Record FROM cfg.InstallState WHERE Name = N'GrantProcedureBefore';
"@

switch ($PSCmdlet.ParameterSetName) {
    'Install' {
        $batches = @(Get-SIGrantProcedureAdminSql -UpdaterUser $UpdaterUser)
        $plan = New-Object System.Collections.Generic.List[object]
        foreach ($s in $chosen) {
            if ($s -eq 'record') { $plan.Add([pscustomobject]@{ Step = 'record'; Purpose = 'the rollback record (the updater''s roles before), written once'; Sql = $recordSql }) }
            else { $plan.Add(@($batches | Where-Object Step -eq $s)[0]) }
        }
        # the steps run in their fixed order, whatever order -Steps named them in
        $plan = @($plan | Sort-Object { $valid.IndexOf($_.Step) })
        $n = $plan.Count; $i = 0
        foreach ($p in $plan) {
            $i++
            $purpose = 'step {0} of {1} ({2}) -- {3}' -f $i, $n, $p.Step, $p.Purpose
            if (-not $Apply) {
                Write-Host ("  PLAN {0}" -f $purpose) -ForegroundColor Cyan
                Write-Host (($p.Sql -split "`n" | Select-Object -First 12 | ForEach-Object { '      ' + $_.TrimEnd() }) -join "`n") -ForegroundColor DarkGray
                $result.Sent += ('PLAN ' + $p.Step)
                continue
            }
            $null = Invoke-Step -Purpose $purpose -Query $p.Sql
            $result.Sent += $p.Step
        }
        if (-not $Apply) {
            $result.Ok = $true
            $result.Lines = @(('PLAN only -- nothing was changed. Now: {0}. Re-run with -Apply.' -f $(if ((Test-SIGrantProcedureReady -State $before -RequireUpdaterMember).Ok) { 'the model is already in place' } else { ((Test-SIGrantProcedureReady -State $before -RequireUpdaterMember).Lines -join '; ') })))
            break
        }
        $after = Read-State -Purpose 'read-back (read-only): procedure, signature, certificate, the updater''s EXECUTE'
        $result.State = $after
        $ready = Test-SIGrantProcedureReady -State $after -RequireUpdaterMember
        $result.Ok = $ready.Ok
        $result.Lines = if ($ready.Ok) { @(('in place: cfg.ApplyComponentGrants signed by {0} (expires {1}, private key removed); {2} may EXECUTE it. db_securityadmin STAYS until a later run with -RemoveSecurityAdmin -- after an update has applied its grants through the procedure.' -f $after.Signer, $after.Expiry, $UpdaterUser)) } else { $ready.Lines }
    }
    'Remove' {
        $ready = Test-SIGrantProcedureReady -State $before -RequireUpdaterMember
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($l in $ready.Lines) { $lines.Add($l) }
        $last = $null
        try { if ($before.LastApply) { $last = $before.LastApply | ConvertFrom-Json } } catch { $last = $null }
        if (-not $last) { $lines.Add('no update has applied its grants through the procedure yet (cfg.InstallState ''GrantProcedureLastApply'') -- let one update run first') }
        elseif ([int]$last.failed -gt 0 -or [int]$last.applied + [int]$last.skipped -lt 1) { $lines.Add(('the last update through the procedure was not clean ({0} failed, {1} applied)' -f $last.failed, $last.applied)) }
        if (-not $before.Record) { $lines.Add('there is no rollback record -- run the install steps first') }
        if ($lines.Count) { $result.Lines = @('Refused: db_securityadmin stays -- the procedure is not proven yet:') + $lines.ToArray(); break }
        $sql = @"
SET XACT_ABORT ON;
DECLARE @u sysname = $u, @s nvarchar(400);
IF NOT EXISTS (SELECT 1 FROM cfg.InstallState WHERE Name = N'GrantProcedureBefore') THROW 51672, N'there is no rollback record -- db_securityadmin stays', 1;
IF ISNULL(IS_ROLEMEMBER(N'si_updater', @u), 0) <> 1 THROW 51672, N'the updater user is not in si_updater -- db_securityadmin stays', 1;
BEGIN TRANSACTION;
IF ISNULL(IS_ROLEMEMBER(N'db_securityadmin', @u), 0) = 1 BEGIN SET @s = N'ALTER ROLE db_securityadmin DROP MEMBER ' + QUOTENAME(@u); EXEC (@s); END
UPDATE cfg.InstallState SET UpdatedAt = SYSUTCDATETIME(), UpdatedBy = N'Install-SIGrantProcedure -RemoveSecurityAdmin' WHERE Name = N'GrantProcedureBefore';
COMMIT TRANSACTION;
"@
        if (-not $Apply) {
            Write-Host '  PLAN remove db_securityadmin from the updater user (the procedure is proven)' -ForegroundColor Cyan
            $result.Ok = $true; $result.Lines = @('PLAN only -- the procedure is proven; re-run with -Apply to remove db_securityadmin.'); break
        }
        $null = Invoke-Step -Purpose 'remove db_securityadmin from the updater user (the procedure is proven)' -Query $sql
        $after = Read-State -Purpose 'read-back (read-only): the updater''s roles'
        $result.State = $after
        $result.Ok = ($after.UpdaterRoles -notcontains 'db_securityadmin') -and ($after.UpdaterRoles -contains 'si_updater')
        $result.Lines = @(('the updater user now has: {0}' -f ($after.UpdaterRoles -join ', ')))
    }
    'Rollback' {
        $sql = @"
SET XACT_ABORT ON;
DECLARE @u sysname = $u, @s nvarchar(400);
DECLARE @rec nvarchar(400) = (SELECT Value FROM cfg.InstallState WHERE Name = N'GrantProcedureBefore');
IF @rec IS NULL THROW 51672, N'there is no rollback record -- nothing was changed', 1;
IF JSON_VALUE(@rec, '$.user') <> @u THROW 51672, N'the rollback record is for another user -- nothing was changed', 1;
DECLARE @before nvarchar(300) = N',' + ISNULL(JSON_VALUE(@rec, '$.roles'), N'') + N',';
BEGIN TRANSACTION;
IF CHARINDEX(N',db_securityadmin,', @before) > 0 AND ISNULL(IS_ROLEMEMBER(N'db_securityadmin', @u), 0) = 0 BEGIN SET @s = N'ALTER ROLE db_securityadmin ADD MEMBER ' + QUOTENAME(@u); EXEC (@s); END
IF CHARINDEX(N',si_updater,', @before) = 0 AND ISNULL(IS_ROLEMEMBER(N'si_updater', @u), 0) = 1 BEGIN SET @s = N'ALTER ROLE [si_updater] DROP MEMBER ' + QUOTENAME(@u); EXEC (@s); END
DELETE FROM cfg.InstallState WHERE Name = N'GrantProcedureBefore';
COMMIT TRANSACTION;
"@
        if (-not $Apply) { $result.Ok = $true; $result.Lines = @('PLAN only -- the rollback would restore the recorded roles; re-run with -Apply.'); break }
        $null = Invoke-Step -Purpose 'rollback -- the updater''s roles as the record says, and the record cleared' -Query $sql
        $after = Read-State -Purpose 'read-back (read-only): the updater''s roles'
        $result.State = $after; $result.Ok = $true
        $result.Lines = @(('rolled back: the updater user now has {0}' -f $(if ($after.UpdaterRoles.Count) { $after.UpdaterRoles -join ', ' } else { 'no role' })))
    }
}

foreach ($l in @($result.Lines)) { Write-Host ('  ' + $l) -ForegroundColor $(if ($result.Ok) { 'Green' } else { 'Yellow' }) }
if ($PassThru) { [pscustomobject]$result }
elseif (-not $result.Ok) { exit 1 }
