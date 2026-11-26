<#
.SYNOPSIS
    SecurityInsight Pro -- LEGACY ONLY: the STANDING database admin earlier releases gave the Invardia Support app (its
    place in the database admin group, and db_owner for its own database user). REFUSED unless -LegacyStandingAccess.

.DESCRIPTION
    NO STANDING ADMIN (framework SECAUDIT-1a; owner 2026-11-25: "the old support scripts can only give just-in-time access,
    never permanent"). The Invardia Support app keeps only its own READ-ONLY database user (si_support_read); admin comes
    only just in time, through the signed support grant procedures, for at most 8 hours at the level you consented to.
    That access is put in place by the install's database setup job (caj-si-dbinit), by setup\Grant-SISupportAccess.ps1
    -AppId <id> -Level <troubleshoot|setup> (you, the customer) and by setup\Install-SISupportGrantProcedure.ps1 (Invardia
    support, in a Support session) -- use those.

    WITHOUT -LegacyStandingAccess THIS SCRIPT REFUSES (in every mode, also the plan): it says the commands above and
    changes nothing (exit 1). -LegacyStandingAccess (OFF; only on Invardia's word, for an install that cannot use the
    just-in-time grant yet) runs the earlier model described below. To take standing admin away again: Invardia support's
    setup\Remove-SISupportStandingAccess.ps1.

    THE EARLIER MODEL (-LegacyStandingAccess only):

    The Invardia Support app is an application in YOUR tenant that you created and consented to for support. Setup
    scripts that touch the Pro database (a setting, a grant, a repair) are run for you through it. For that it must be
    able to sign in to the product databases after the install, permanently (framework section 4.1b).
    Everything is read from the install (config\SecurityInsight.custom.ps1).

    What this script does -- each step only when it is needed, each read back, NOTHING IS EVER REMOVED:
      1. the Support app is a MEMBER of the database server's admin group (grp-si-sql-admins, or your own group). Added
         when it is not.
      2. the database server's administrator is that group, and the server records it AS A GROUP. A server that names
         the group under another kind is put right. A server whose administrator is a person or another application
         is NOT changed here: the script says so, with the command (setup\Set-SISqlAdminGroup.ps1).
      3. the Support app has ITS OWN DATABASE USER in each product database (the Pro database, the identity ledger, the
         data database where there is one), made from its client id (CREATE USER ... WITH SID = ..., TYPE = E -- no
         directory lookup), with the owner role (db_owner). Made where it is not there.
      4. the Support app's client id is recorded in the Pro database (which application this install's support access
         belongs to; the heartbeat reports both parts for it).

    Run by a person: you must be an administrator of the database server (a member of its admin group) and may add
    members to that group (a role-assignable group: Privileged Role Administrator). Run through a support session
    (signed in as the Support app itself): afterwards it signs in to each database again, which proves the access.
    A second run changes nothing.

    While the install's updater runs (a lock row it beats in the Pro database, or a running execution of its job), -Apply
    refuses and changes nothing: start it again after the update has ended.

    Without -Apply (or with -WhatIf) nothing is changed and no database connection is opened: the plan is shown.
    The only way the Support app's access is taken away is your own switch-off: setup\Grant-SISupportAccess.ps1 -AppId
    <id> -Remove (this script never removes anything).
.PARAMETER AppId
    The Support app's client id. Not needed in a support session: the session's own application is used.
.PARAMETER ConfigPath
    The install's configuration. Default: config\SecurityInsight.custom.ps1 of this copy.
.PARAMETER GroupName
    The admin group's name, used only when the server's administrator is not a group at that moment.

.PARAMETER LegacyStandingAccess
    OFF. Only on Invardia's word: runs the earlier standing-admin model. Without it the script refuses and changes nothing.

.EXAMPLE
    .\setup\Grant-SISupportAccess.ps1 -AppId <the Support app's client id> -Level troubleshoot
    What to run instead: the Support app's read-only database user and the just-in-time support grant.
.EXAMPLE
    .\setup\Grant-SISupportAppDatabase.ps1 -AppId <the Support app's client id> -LegacyStandingAccess
    LEGACY, on Invardia's word only -- the plan of the earlier standing model. Nothing is changed.

.LINK
    https://invardia.com/docs/si/scripts/Grant-SISupportAppDatabase/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')][string]$AppId = '',
    [string]$ConfigPath,
    [string]$SqlServer,
    [string[]]$Databases = @(),
    [string]$SubscriptionId,
    [string]$ResourceGroupName,
    [string]$GroupName = 'grp-si-sql-admins',
    [switch]$Apply,
    # OFF: the earlier STANDING admin model, only on Invardia's word (framework SECAUDIT-1a). Without it: refused.
    [switch]$LegacyStandingAccess,
    [switch]$PassThru
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Grant-SISupportAppDatabase' -Quiet:($false)
if ($WhatIfPreference) { $Apply = [switch]$false }   # -WhatIf = the plan: nothing is changed
$siExit = 0
try {
$ErrorActionPreference = 'Stop'
# #1374 SECAUDIT-1a (owner 2026-11-25): no standing admin for the Support app -- REFUSED before anything is read or signed
# in, unless -LegacyStandingAccess. The just-in-time path is what to run instead.
if (-not $LegacyStandingAccess) {
    $lvl = 'troubleshoot'
    Write-Host 'REFUSED: this script gives the Invardia Support app STANDING database admin (db_owner, the SQL admin group) -- earlier releases'' model. SecurityInsight gives it only its read-only database user (si_support_read); admin comes only just in time, through the signed support grant procedures (at most 8 hours, at the level you consented to). Nothing was read or changed.' -ForegroundColor Red
    Write-Host '  Run instead (you, the customer, in this install''s folder):' -ForegroundColor Yellow
    Write-Host ('    ./setup/Grant-SISupportAccess.ps1 -AppId {0} -Level {1}' -f $(if ($AppId) { $AppId } else { '<the Support app''s client id>' }), $lvl) -ForegroundColor Yellow
    Write-Host '  Invardia support, in the install''s Support session: ./setup/Install-SISupportGrantProcedure.ps1 -ResourceGroup <rg> -Server <sql server> -Databases ''<pro>;<ledger>''' -ForegroundColor Yellow
    Write-Host '  Only on Invardia''s word: -LegacyStandingAccess runs the earlier standing model.' -ForegroundColor DarkGray
    if ($PassThru) { [pscustomobject]@{ Ok = $false; Refused = 'standing admin without -LegacyStandingAccess (SECAUDIT-1a)' } }
    exit 1   # (the finally below still ends the script's transcript)
}
$siRoot = Split-Path -Parent $PSScriptRoot
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportAppDatabase.ps1'))
# Azure over native REST, no PowerShell module. An existing sign-in in this process (a support session, the guided
# install) is reused; otherwise a person signs in here (Azure Cloud Shell, or the browser).
if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1')) }
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupArm.ps1'))   # ALWAYS: its API versions are script values of THIS script's scope
if (-not (Get-Command -Name Invoke-SIRestMethod -ErrorAction SilentlyContinue)) {
    & { . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'engine', '_shared', 'SI-AzRest.ps1')) }
}
$azCtx = Get-SISetupAzureContext -SubscriptionId $SubscriptionId
if (-not $azCtx) { $azCtx = Connect-SISetupAzure -SubscriptionId $SubscriptionId }

# ---- the install that is there ----
if (-not $ConfigPath) { $ConfigPath = Join-Path $siRoot 'config\SecurityInsight.custom.ps1' }
if (Test-Path -LiteralPath $ConfigPath) { . $ConfigPath }
elseif (-not $SqlServer -or -not @($Databases | Where-Object { $_ }).Count) { throw "the install's configuration was not found ($ConfigPath) -- give -ConfigPath, or -SqlServer and -Databases" }
if (-not $SqlServer) { $SqlServer = [string]$global:SI_ProSqlServer }
if (-not $SqlServer) { throw 'this install has no Pro database (SI_ProSqlServer is not set in its configuration) -- there is nothing to do' }
if ($SqlServer -notmatch '\.') { $SqlServer = $SqlServer + '.database.windows.net' }
$recordDb = [string]$global:SI_ProSqlDatabase
$dbs = @($Databases | Where-Object { $_ })
if (-not $dbs.Count) { $dbs = @(@([string]$global:SI_ProSqlDatabase, [string]$global:SI_LedgerDatabase, [string]$global:SI_Pro_DataSqlDatabase) | Where-Object { $_ } | Select-Object -Unique) }
elseif (-not $recordDb) { $recordDb = [string]$dbs[0] }
if (-not $dbs.Count) { throw 'this install names no product database (SI_ProSqlDatabase / SI_LedgerDatabase) -- there is nothing to do' }

# ---- who runs this, and for which application ----
$callerType = [string]$azCtx.Account.Type; $callerId = [string]$azCtx.Account.Id
$callerApp = ''
if ($callerType -and $callerType -ne 'User' -and $callerId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $callerApp = $callerId }
if (-not $AppId) {
    if ($callerApp -and [string]$azCtx.SignInMethod -eq 'Support') { $AppId = $callerApp }
    else { throw 'give -AppId: the client id of the Invardia Support app in this tenant (in a support session the session''s own application is used)' }
}

# ---- the database server, found in the subscription by its name ----
$short = $SqlServer.Split('.')[0]
if (-not $ResourceGroupName) {
    $srv = @(Get-SIArmResource -ResourceType 'Microsoft.Sql/servers' -Name $short -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue)[0]
    if ($srv) { $ResourceGroupName = [string]$srv.ResourceGroupName }
}
if (-not $SubscriptionId -and $azCtx.Subscription) { $SubscriptionId = [string]$azCtx.Subscription.Id }

Write-Host ('SecurityInsight -- the Invardia Support app''s database access (the admin group and its own database user) on {0} ({1}){2}' -f $SqlServer, ($dbs -join ', '), $(if ($Apply) { '' } else { ' -- plan only' }))
Write-Host ('  run as: {0}' -f $(if ($callerApp) { 'the application ' + $callerApp } else { 'a person (' + $callerId + ')' }))

# ---- the seams of the shared worker, on the real thing ----
function Invoke-SISupportAppGraphCall {
    param([string]$Method, [string]$Uri, $Body)
    $a = @{ Method = $Method; Uri = $Uri; Headers = @{ Authorization = 'Bearer ' + [string](Get-SISetupAccessToken -Resource 'https://graph.microsoft.com') } }
    if ($null -ne $Body) { $a.ContentType = 'application/json'; $a.Body = ($Body | ConvertTo-Json -Compress -Depth 5) }
    Invoke-SIRestMethod @a   # through the support recorder in a support session
}
$graph = { param([string]$Method, [string]$Uri, $Body) Invoke-SISupportAppGraphCall -Method $Method -Uri $Uri -Body $Body }
$getAdmin = {
    if (-not $ResourceGroupName) { throw ('the database server {0} was not found in subscription {1} -- give -ResourceGroupName / -SubscriptionId' -f $short, $SubscriptionId) }
    Get-SISqlServerEntraAdmin -ResourceGroupName $ResourceGroupName -Name $short -SubscriptionId $SubscriptionId
}
# only ever called with the admin GROUP, as a group (the worker decides when; it reads the server back afterwards)
$setAdmin = {
    param([string]$Name, [string]$Sid, [string]$Type)
    $null = Set-SISqlServerEntraAdmin -ResourceGroupName $ResourceGroupName -Name $short -AdminName $Name -AdminSid $Sid -AdminType $Type -SubscriptionId $SubscriptionId
}
$sql = {
    param([string]$Database, [string]$Query, [bool]$NoWait)
    # "Login failed" / a firewall rule a moment old is waited for (a new token each time) unless the caller only asks
    $o = @{ Server = $SqlServer; Database = $Database; Token = { param([bool]$Fresh) ([string](Get-SISetupAccessToken -Resource 'https://database.windows.net/' -ForceRefresh:$Fresh)).Trim() } }
    if ($NoWait) { $o.Waits = @() }
    $cn = Open-SISqlConnectionRetry @o
    try { $cmd = $cn.CreateCommand(); $cmd.CommandText = $Query; $cmd.CommandTimeout = 0; $cmd.ExecuteScalar() } finally { $cn.Dispose() }
}
$say = { param([string]$State, [string]$Text) Write-Host ('  [{0,-9}] {1}' -f $State, $Text) -ForegroundColor $(switch ($State) { 'failed' { 'Red' } 'not' { 'Yellow' } 'unchecked' { 'Yellow' } 'set' { 'Cyan' } 'proven' { 'Green' } 'granted' { 'Green' } 'missing' { 'Yellow' } 'added' { 'Green' } default { 'Gray' } }) }

if (-not $Apply) {
    Write-Host '  the statements, per database (run only with -Apply, and only where its own user with the owner role is not there):' -ForegroundColor DarkGray
    Write-Host ((((Get-SISupportAppDatabaseAccessSql -UserName 'Invardia Support' -ClientId $AppId) -split "`n") | ForEach-Object { '      ' + $_.TrimEnd() }) -join "`n") -ForegroundColor DarkGray
}
# Never beside a running update (its grants and the update's can meet in a deadlock): -Apply
# REFUSES while the updater runs -- a lock row it beats in the Pro database, or a running execution of its job in the
# database server's resource group. A part that cannot be read from here is said and does not block.
if ($Apply) {
    . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-DbInitJob.ps1'))
    $lockText = $null
    if ($recordDb) { try { $lockText = [string](& $sql $recordDb (Get-SIDbInitUpdaterLockSql) $true) } catch { $lockText = $null; Write-Host ('  the updater''s lock row could not be read here ({0})' -f (($_.Exception.Message) -split "`n")[0]) -ForegroundColor DarkGray } }
    $siArmFn = ${function:Invoke-SIArm}
    $armRead = if ($siArmFn) { { param([string]$Method, [string]$Path, $Body) & $siArmFn -Method GET -Path $Path -AllowNotFound }.GetNewClosure() } else { $null }
    $updBusy = Test-SIDbInitUpdaterBusy -Arm $armRead -SubscriptionId ([string]$SubscriptionId) -ResourceGroup ([string]$ResourceGroupName) -LockText $lockText
    foreach ($l in @($updBusy.Read)) { Write-Host ('  checked: {0}' -f $l) -ForegroundColor DarkGray }
    if ($updBusy.Busy) {
        Write-Host ('  ' + (Get-SIDbInitUpdaterBusyText -Why $updBusy.Why -What 'the Support app''s database access')) -ForegroundColor Red
        if ($PassThru) { [pscustomobject]@{ Ok = $false; Refused = $updBusy.Why } }
        exit 1   # (the finally below still ends the script's transcript)
    }
}
Write-Host '  LEGACY (-LegacyStandingAccess, on Invardia''s word): the earlier STANDING admin model -- setup\Remove-SISupportStandingAccess.ps1 takes it away again' -ForegroundColor Yellow
$res = Invoke-SISupportAppDatabaseEnsure -ClientId $AppId -Databases $dbs -RecordDatabase $recordDb -Graph $graph -Sql $sql -GetAdmin $getAdmin -SetAdmin $setAdmin `
    -CallerAppId $callerApp -GroupName $GroupName -Apply:$Apply -LegacyStandingAccess:$LegacyStandingAccess -Say $say -By ('setup: ' + $(if ($callerApp) { 'the Support app' } else { $callerId }))
foreach ($p in @($res.Problems)) { Write-Warning $p }
if (-not $Apply) { Write-Host 'Plan only -- nothing was changed. Run again with -Apply.' -ForegroundColor Yellow }
elseif ($res.Ok) { Write-Host 'Done: the Invardia Support app is a member of the database admin group and has its own database user, with the owner role, in every product database.' -ForegroundColor Green }
else {
    Write-Warning ('Not every part of the Invardia Support app''s database access is in place -- {0}. See the lines above.' -f (@(
        $(if (-not $res.GroupOk) { '(a) the admin group: ' + [string]$res.Member.Detail }),
        $(if (-not $res.DbUserOk) { '(b) its own database user: ' + ((@($res.Databases | Where-Object { $_.State -notin 'present', 'granted' } | ForEach-Object { '{0}: {1}' -f $_.Database, $_.Detail })) -join '; ') })) | Where-Object { $_ }) -join ' / ')
    $siExit = 1
}
if ($Apply -and $res.Admin -and $res.Admin.State -eq 'not' -and $ResourceGroupName) {
    Write-Warning ('The database server''s administrator is not the admin group, as a group: {0}' -f $res.Admin.Detail)
    Write-Host ('  .\setup\Set-SISqlAdminGroup.ps1 -SqlServerName {0} -ResourceGroupName {1} -SubscriptionId {2}' -f $short, $ResourceGroupName, $SubscriptionId) -ForegroundColor Yellow
}
if ($PassThru) { $res }
} finally { Stop-SIScriptRun -Run $siRun }
if ($siExit) { exit $siExit }
