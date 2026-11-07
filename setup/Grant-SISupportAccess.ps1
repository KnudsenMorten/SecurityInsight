<#
.SYNOPSIS
    Gives the customer's Invardia Support app the access only SecurityInsight can grant -- or takes it away (#227).

.DESCRIPTION
    THE PRODUCT DOES THIS NOW: the install's database setup job (caj-si-dbinit) makes the database part: the Invardia Support app's own database user (in the install's run, and a support repair, that names the Support app)
    as its own identity -- at the install and on every update -- so no person needs database admin rights for it. This
    script stays as a fallback: run it only when Invardia support asks for it.

    The Invardia Support app ("Invardia Support" -- framework 12.11c; an older one may still carry its earlier, longer name.
    Invardia names it; SecurityInsight finds it only by its client id, never by a name), one per
    tenant, created by the customer with Invardia's New-InvardiaSupportApp.ps1) is used for installs, upgrades and
    troubleshooting, on the customer's request only. Its Azure roles and API permissions come from that script. This
    script adds what only SecurityInsight knows about:

      Key Vault (the install's, SI_KeyVaultName)     troubleshoot: Key Vault Reader (names and metadata, NO secret values)
                                                     setup:        Key Vault Secrets Officer
      Pro database(s), Entra-only SQL                both levels (framework section 4.1b, BOTH parts, permanently):
                                                                   (a) member of the server's Entra admin GROUP, and
                                                                   (b) its OWN database user in each product database,
                                                                   from its client id (WITH SID, TYPE = E -- never FROM
                                                                   EXTERNAL PROVIDER) + db_owner. Each added when it is
                                                                   not there and KEPT afterwards; only -Remove takes them
                                                                   away. An install that is there:
                                                                   setup\Grant-SISupportAppDatabase.ps1
      SI's app registrations                         both levels:  the support app becomes an OWNER (so the app's published
                                                                   Application.ReadWrite.OwnedBy is enough later): the engine
                                                                   app (SI_SPN_AppId, when the install has one) and the web app
                                                                   (-ManagementAppId or SI_Management_AppId)

      Just-in-time support grant (#1021)             both levels:  the CONSENT (this level) in each product database, the
                                                                   standing READ-ONLY role si_support_read, the signed
                                                                   procedures, and Storage Queue Data Message Sender on the
                                                                   queue si-support-requests + Container Apps Jobs Operator on
                                                                   the job caj-si-support-grant (where the install has them)

    -Remove takes every one of these away again (the group membership, its own database users and the ownership): the
    CUSTOMER's off-switch for the Support app (framework section 4.1a), and the ONLY removal of its database access in
    SecurityInsight -- no other script, step or update calls it.
    -WhatIf shows the plan and changes nothing. A grant this account cannot make is printed as a ready-to-run task for
    someone who can, and the script exits 1; nothing is half-done silently.

    Signs in without any PowerShell module (Azure Cloud Shell or the browser; an existing sign-in is reused) as an account that may assign roles on the vault, sign in to the Pro SQL server as an Entra
    admin, and change app owners / group members (Application owner, Groups owner, or Privileged Role Administrator).

.EXAMPLE
    .\Grant-SISupportAccess.ps1 -AppId <support app client id> -Level troubleshoot
.EXAMPLE
    .\Grant-SISupportAccess.ps1 -AppId <support app client id> -Remove

.LINK
    https://invardia.com/docs/si/scripts/Grant-SISupportAccess/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$AppId,
    [ValidateSet('troubleshoot', 'setup')][string]$Level = 'troubleshoot',
    [switch]$Remove,
    [string]$ConfigPath,
    [ValidatePattern('^$|^[0-9a-fA-F-]{36}$')][string]$ManagementAppId = ''
)

#Requires -Version 7.0   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Grant-SISupportAccess' -Quiet:($false)
try {
$ErrorActionPreference = 'Stop'
$siRoot = Split-Path -Parent $PSScriptRoot
# Azure over native REST, no PowerShell module (#305). An existing sign-in in this process (the guided install) is reused;
# otherwise a person signs in here (Azure Cloud Shell, or the browser).
if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1')) }
if (-not (Get-SISetupAzureContext)) { $null = Connect-SISetupAzure }
# #1092: a member added right after its group was made waits out Entra replication, then is read back;
# #1093: the support grant's statements compile in a database without the consent table (both free files)
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-GroupMemberAdd.ps1'))
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SupportConsentSql.ps1'))
if (-not $ConfigPath) { $ConfigPath = Join-Path $siRoot 'config\SecurityInsight.custom.ps1' }
if (-not (Test-Path -LiteralPath $ConfigPath)) { throw "config not found: $ConfigPath" }
. $ConfigPath
if (-not $ManagementAppId -and $global:SI_Management_AppId) { $ManagementAppId = [string]$global:SI_Management_AppId }

$tasks = New-Object System.Collections.Generic.List[string]
$failed = 0
function Show([string]$State, [string]$What) { Write-Host ('  [{0,-8}] {1}' -f $State, $What) }
function Get-Token([string]$Resource) {
    [string](Get-SIAzureToken -Resource $Resource)
}
$graphHdr = @{ Authorization = 'Bearer ' + (Get-Token 'https://graph.microsoft.com') }
function Invoke-Graph([string]$Method, [string]$Url, $Body) {
    $a = @{ Method = $Method; Uri = $Url; Headers = $graphHdr }
    if ($null -ne $Body) { $a.ContentType = 'application/json'; $a.Body = ($Body | ConvertTo-Json -Compress) }
    Invoke-SIRestMethod @a   # #548: through the support recorder in a support session
}

# ---- the support app's service principal ----
$sp = @((Invoke-Graph Get "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$AppId'&`$select=id,appId,displayName").value)[0]
if (-not $sp) { throw "No service principal for app $AppId in this tenant -- create the Invardia Support app first (New-InvardiaSupportApp.ps1)." }
Write-Host ('SecurityInsight -- {0} support access for "{1}" ({2}){3}' -f $(if ($Remove) { 'REMOVING' } else { $Level }), $sp.displayName, $AppId, $(if ($WhatIfPreference) { ' -- plan only (-WhatIf)' } else { '' }))

# ---- 1. Key Vault ----
$kvName = [string]$global:SI_KeyVaultName
if ($kvName) {
    $kv = Get-SIKeyVault -VaultName $kvName -ErrorAction SilentlyContinue
    if (-not $kv) { Show 'MISSING' "Key Vault $kvName not found"; $failed++ }
    else {
        $want = if ($Level -eq 'setup') { 'Key Vault Secrets Officer' } else { 'Key Vault Reader' }
        foreach ($role in 'Key Vault Secrets Officer', 'Key Vault Reader') {
            $have = @(Get-SIAzRoleAssignment -ObjectId $sp.id -Scope $kv.ResourceId -RoleDefinitionName $role -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $kv.ResourceId })
            $should = (-not $Remove) -and $role -eq $want
            if ($should -and -not $have.Count) {
                if ($PSCmdlet.ShouldProcess("$role on $kvName", 'grant')) {
                    try { New-SIRoleAssignment -ObjectId $sp.id -Scope $kv.ResourceId -RoleDefinitionName $role -PrincipalType ServicePrincipal | Out-Null; Show 'granted' "$role on $kvName" }
                    # #564: the write's own error is kept; the hand-over is a portal path (a customer has no az CLI)
                    catch { $failed++; Show 'FAILED' ("$role on $kvName -- " + $_.Exception.Message); $tasks.Add(('# Azure role "{1}" on "{2}" for the Invardia support app ({0}) -- Azure portal: Key vaults > {3} > Access control (IAM) > Add > Add role assignment > {1}' -f $sp.id, $role, $kv.ResourceId, $kvName)) }
                } else { Show 'plan' "grant $role on $kvName" }
            } elseif (-not $should -and $have.Count) {
                if ($PSCmdlet.ShouldProcess("$role on $kvName", 'remove')) {
                    try { Remove-SIRoleAssignment -ObjectId $sp.id -Scope $kv.ResourceId -RoleDefinitionName $role | Out-Null; Show 'removed' "$role on $kvName" }
                    catch { $failed++; Show 'FAILED' ("remove $role on $kvName -- " + $_.Exception.Message); $tasks.Add(('# remove Azure role "{1}" on "{2}" from the Invardia support app ({0}) -- Azure portal: Key vaults > {3} > Access control (IAM) > Role assignments > {1} > Remove' -f $sp.id, $role, $kv.ResourceId, $kvName)) }
                } else { Show 'plan' "remove $role on $kvName" }
            } elseif ($should) { Show 'present' "$role on $kvName" }
        }
    }
} else { Show 'skipped' 'no Key Vault in this install (SI_KeyVaultName)' }

# ---- 2. Pro database(s) ----
$sqlServer = [string]$global:SI_ProSqlServer
$dbs = @(@([string]$global:SI_ProSqlDatabase, [string]$global:SI_LedgerDatabase, [string]$global:SI_Pro_DataSqlDatabase) | Where-Object { $_ } | Select-Object -Unique)
if ($sqlServer -and $dbs.Count) {
    $short = $sqlServer.Split('.')[0]
    $srv = @(Get-SIArmResource -ResourceType 'Microsoft.Sql/servers' -Name $short -ErrorAction SilentlyContinue)[0]
    $admin = $null
    if ($srv) { try { $admin = (Invoke-SIAzRestMethod -Method GET -Path ($srv.ResourceId + '/administrators/ActiveDirectory?api-version=2021-11-01')).Content | ConvertFrom-Json } catch { } }
    $sid = '0x' + ((([guid]$AppId).ToByteArray() | ForEach-Object { $_.ToString('X2') }) -join '')
    # Framework section 4.1b (owner 2026-10-18: "make sure it never gets removed again"): at BOTH levels the Support app
    # gets its OWN database user (from its client id: WITH SID, TYPE = E -- no directory lookup) with db_owner in each
    # product database, where it is not there. The DROP below runs ONLY with -Remove: the customer's own off-switch.
    if (-not $Remove) {
        # the same statements as setup\_shared\SI-SupportAppDatabase.ps1 (Get-SISupportAppDatabaseAccessSql), written out here:
        # this script is a free one and loads no Pro file. Each statement runs only when its result is not there; it only ADDS.
        $un = ([string]$sp.displayName).Replace(']', ']]'); $uq = ([string]$sp.displayName).Replace("'", "''")
        $sql = ("DECLARE @n sysname = (SELECT TOP (1) name FROM sys.database_principals WHERE sid = $sid AND principal_id > 4); " +
                "IF @n IS NULL BEGIN CREATE USER [$un] WITH SID = $sid, TYPE = E; SET @n = N'$uq'; END " +
                "IF NOT EXISTS (SELECT 1 FROM sys.database_role_members m JOIN sys.database_principals r ON r.principal_id = m.role_principal_id JOIN sys.database_principals u ON u.principal_id = m.member_principal_id WHERE r.name = N'db_owner' AND u.sid = $sid AND u.principal_id > 4) " +
                "BEGIN DECLARE @s nvarchar(400) = N'ALTER ROLE db_owner ADD MEMBER ' + QUOTENAME(@n); EXEC (@s); END " +
                "SELECT ISNULL((SELECT TOP (1) u.name + N'|' + CAST(ISNULL(IS_ROLEMEMBER(N'db_owner', u.name), 0) AS nvarchar(4)) FROM sys.database_principals u WHERE u.sid = $sid AND u.principal_id > 4), N'');")
        $sqlTok = Get-Token 'https://database.windows.net/'
        foreach ($db in $dbs) {
            if (-not $PSCmdlet.ShouldProcess("$db on $sqlServer", 'its own database user + db_owner, where it is not there')) { Show 'plan' ("{0}: its own database user (WITH SID, TYPE = E) + db_owner, where it is not there" -f $db); continue }
            try {
                $cn = New-Object System.Data.SqlClient.SqlConnection("Server=tcp:$sqlServer,1433;Database=$db;Encrypt=True;Connect Timeout=30;")
                $cn.AccessToken = $sqlTok; $cn.Open()
                $got = $null
                try { $c = $cn.CreateCommand(); $c.CommandText = $sql; $got = ([string]$c.ExecuteScalar()).Trim() } finally { $cn.Dispose() }
                if ($got -match '\|1$') { Show 'present' ("{0}: its own database user {1}, with db_owner (read back)" -f $db, $got.Substring(0, $got.Length - 2)) }
                else { $failed++; Show 'FAILED' ("{0}: its own database user with db_owner is not there when read back" -f $db); $tasks.Add(("-- as the SQL Entra admin, in database {0}:`n{1}" -f $db, $sql)) }
            } catch {
                $failed++; Show 'FAILED' ("{0}: {1}" -f $db, $_.Exception.Message)
                $tasks.Add(("-- as the SQL Entra admin, in database {0}:`n{1}" -f $db, $sql))
            }
        }
    }
    if ($Remove) {
        $sqlTok = Get-Token 'https://database.windows.net/'
        foreach ($db in $dbs) {
            $sql = "IF EXISTS (SELECT 1 FROM sys.database_principals WHERE sid = $sid AND principal_id > 4) BEGIN DECLARE @n sysname = (SELECT name FROM sys.database_principals WHERE sid = $sid AND principal_id > 4); EXEC(N'DROP USER ' + QUOTENAME(@n)); SELECT 'removed'; END ELSE SELECT 'absent';"
            if (-not $PSCmdlet.ShouldProcess("$db on $sqlServer", 'drop the support user')) { Show 'plan' ("{0}: drop the support user" -f $db); continue }
            try {
                $cn = New-Object System.Data.SqlClient.SqlConnection("Server=tcp:$sqlServer,1433;Database=$db;Encrypt=True;Connect Timeout=30;")
                $cn.AccessToken = $sqlTok; $cn.Open()
                try { $c = $cn.CreateCommand(); $c.CommandText = $sql; Show ([string]$c.ExecuteScalar()) ("{0}: support user" -f $db) } finally { $cn.Dispose() }
            } catch {
                $failed++; Show 'FAILED' ("{0}: {1}" -f $db, $_.Exception.Message)
                $tasks.Add(("-- as the SQL Entra admin, in database {0}:  {1}" -f $db, $sql))
            }
        }
    }
    # (a) membership of the server's Entra admin GROUP, at BOTH levels: ADDED when it is not there, and taken away ONLY by
    # -Remove (owner 2026-10-13: "support app must be permanently included in sql admin group"; framework section 4.1b).
    if ($admin -and $admin.properties) {
        $isGroup = ([string]$admin.properties.administratorType -eq 'ActiveDirectory') -and $admin.properties.sid
        $grpId = [string]$admin.properties.sid
        $grp = $null; if ($isGroup) { try { $grp = Invoke-Graph Get "https://graph.microsoft.com/v1.0/groups/${grpId}?`$select=id,displayName" $null } catch { } }
        if (-not $grp) {
            if ($Level -eq 'setup' -and -not $Remove) { $failed++; Show 'WARN' 'the SQL server''s Entra admin is not a group -- make it a group, then re-run (database access = membership of that group)' }
            elseif (-not $Remove) { Show 'note' 'the SQL server''s Entra admin is not a group at this moment -- make the admin group the server''s Entra admin first (Set-SISqlAdminGroup), then run this again' }
        } else {
            # asked from the MEMBER's side: a plain /members listing leaves service principals out for many callers
            # (seen live 2026-10-03), which would read a real member as missing
            $member = $false; try { $member = @((Invoke-Graph Post "https://graph.microsoft.com/v1.0/directoryObjects/$($sp.id)/checkMemberGroups" @{ groupIds = @([string]$grp.id) }).value) -contains [string]$grp.id } catch { }
            $should = -not $Remove
            if ($should -and -not $member) {
                if ($PSCmdlet.ShouldProcess("group $($grp.displayName)", 'add member')) {
                    # #1092: the group may have been made minutes ago (the install's database steps) -- a 404 on it is Entra
                    # replication: waited for and tried again for up to 5 minutes (said in the log), then READ BACK
                    $gmAdd = Invoke-SIGroupMemberAddRetry -What 'the Support app' -LimitSeconds 300 `
                        -Add { Invoke-Graph Post "https://graph.microsoft.com/v1.0/groups/$($grp.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($sp.id)" } | Out-Null } `
                        -Test { @((Invoke-Graph Post "https://graph.microsoft.com/v1.0/directoryObjects/$($sp.id)/checkMemberGroups" @{ groupIds = @([string]$grp.id) }).value) -contains [string]$grp.id }
                    if ($gmAdd.State -eq 'added') { Show 'granted' "member of the SQL admin group $($grp.displayName) (read back)" }
                    elseif ($gmAdd.State -eq 'unchecked') { Show 'granted' ("member of the SQL admin group {0} -- {1}" -f $grp.displayName, $gmAdd.Detail) }
                    else { $failed++; Show 'FAILED' ("member of {0} -- {1}" -f $grp.displayName, $gmAdd.Detail); $tasks.Add(("# Entra admin center: Groups -> {0} -> Members -> add '{1}'" -f $grp.displayName, $sp.displayName)) }
                } else { Show 'plan' "add to the SQL admin group $($grp.displayName)" }
            } elseif ($Remove -and $member) {
                if ($PSCmdlet.ShouldProcess("group $($grp.displayName)", 'remove member')) {
                    try { Invoke-Graph Delete "https://graph.microsoft.com/v1.0/groups/$($grp.id)/members/$($sp.id)/`$ref" $null | Out-Null; Show 'removed' "member of $($grp.displayName)" }
                    catch { $failed++; Show 'FAILED' "remove from $($grp.displayName)"; $tasks.Add(("# Entra admin center: Groups -> {0} -> Members -> remove '{1}'" -f $grp.displayName, $sp.displayName)) }
                } else { Show 'plan' "remove from the SQL admin group $($grp.displayName)" }
            } elseif ($member) { Show $(if ($should) { 'present' } else { 'kept' }) "member of the SQL admin group $($grp.displayName)" }
        }
    } elseif ($Level -eq 'setup' -and -not $Remove) { $failed++; Show 'WARN' "could not read the Entra admin of $sqlServer" }
} else { Show 'skipped' 'no Pro database in this install' }

# ---- 2b. THE JUST-IN-TIME SUPPORT GRANT (#1021; framework SECAUDIT-1a) ----
# This script IS the customer's consent: its level is recorded in each product database (cfg.SupportConsent, Source
# customer), with the Support app's standing READ-ONLY role and the signed procedures the support grant job opens and closes
# its access through -- at most at this level, for at most 8 hours. Plus its two Azure roles for the support grant ONLY:
# Storage Queue Data Message Sender on the queue si-support-requests and Container Apps Jobs Operator on the job
# caj-si-support-grant. Nothing of the access above is changed here. -Remove takes the consent and the two roles away.
# Only where the database carries the support grant's tables (a Pro install the update has reached). The statements are
# written out here (this script is a free one and loads no Pro file); the signed procedures themselves are installed by the
# guided install or setup\Install-SISupportGrantProcedure.ps1 (they need the release's own text).
if ($sqlServer -and $dbs.Count) {
    $sgTok = Get-Token 'https://database.windows.net/'
    $AppId = ([guid]$AppId).ToString()
    $sgRun = {
        param([string]$Db, [string]$Sql)
        $cn = New-Object System.Data.SqlClient.SqlConnection("Server=tcp:$sqlServer,1433;Database=$Db;Encrypt=True;Connect Timeout=30;")
        $cn.AccessToken = $sgTok; $cn.Open()
        try { $c = $cn.CreateCommand(); $c.CommandText = $Sql; $c.CommandTimeout = 0; [string]$c.ExecuteScalar() } finally { $cn.Dispose() }
    }
    foreach ($db in $dbs) {
        if ($Remove) {
            if (-not $PSCmdlet.ShouldProcess("$db on $sqlServer", 'remove the consent to the support grant')) { Show 'plan' ("{0}: remove the consent to the support grant" -f $db); continue }
            try { $null = & $sgRun $db "IF OBJECT_ID(N'cfg.SupportConsent') IS NOT NULL DELETE FROM cfg.SupportConsent WHERE Id = 1; SELECT N'removed';"; Show 'removed' ("{0}: the consent to the support grant" -f $db) }
            catch { $failed++; Show 'FAILED' ("{0}: remove the consent -- {1}" -f $db, $_.Exception.Message); $tasks.Add(("-- as the SQL Entra admin, in database {0}:  DELETE FROM cfg.SupportConsent WHERE Id = 1;" -f $db)) }
            continue
        }
        # the Support app in the standing READ-ONLY role where the database has it (the role and its rights -- metadata and health,
        # no data -- are made by the support grant's own install step), and the consent at this level where the database
        # carries cfg.SupportConsent. #1093: the consent's statements are dynamic SQL, so the batch compiles in a database that
        # does not carry the table yet -- the identity ledger of a new install, whose support grant tables come right after
        # this script (setup\_shared\SI-SupportConsentSql.ps1)
        if (-not $PSCmdlet.ShouldProcess("$db on $sqlServer", "the read-only role and the consent ($Level)")) { Show 'plan' ("{0}: the read-only role si_support_read and the consent to the support grant ({1})" -f $db, $Level); continue }
        $sgRes = Invoke-SISupportGrantDatabase -Run $sgRun -Database $db -Sid $sid -AppId $AppId -Level $Level
        if ($sgRes.State -eq 'ok') { Show 'ok' $sgRes.Text }
        else { $failed++; Show 'FAILED' $sgRes.Text; $tasks.Add(("-- as the SQL Entra admin, in database {0}:`n{1}" -f $db, $sgRes.Sql)) }
    }
    # the two Azure roles, each on its ONE resource
    $sgRg = [string]$global:SI_Bootstrap_ResourceGroupName
    $sgAcct = [string]$global:SI_StorageAccount
    $sgScopes = @()
    if ($sgAcct) { $a = @(Get-SIArmResource -ResourceType 'Microsoft.Storage/storageAccounts' -Name $sgAcct -ErrorAction SilentlyContinue)[0]; if ($a) { $sgScopes += [pscustomobject]@{ Role = 'Storage Queue Data Message Sender'; Scope = ($a.ResourceId + '/queueServices/default/queues/si-support-requests') } } }
    $j = @(Get-SIArmResource -ResourceType 'Microsoft.App/jobs' -Name 'caj-si-support-grant' -ErrorAction SilentlyContinue)[0]
    if ($j) { $sgScopes += [pscustomobject]@{ Role = 'Container Apps Jobs Operator'; Scope = [string]$j.ResourceId } }
    elseif (-not $Remove) { Show 'note' 'the job caj-si-support-grant is not there yet (the next update makes it) -- run this again after the update for its role' }
    foreach ($s in $sgScopes) {
        $have = @(Get-SIAzRoleAssignment -ObjectId $sp.id -Scope $s.Scope -RoleDefinitionName $s.Role -ErrorAction SilentlyContinue | Where-Object { ([string]$_.Scope).TrimEnd('/') -ieq $s.Scope.TrimEnd('/') })
        if (-not $Remove -and -not $have.Count) {
            if ($PSCmdlet.ShouldProcess("$($s.Role) on $(($s.Scope -split '/')[-1])", 'grant')) {
                try { New-SIRoleAssignment -ObjectId $sp.id -Scope $s.Scope -RoleDefinitionName $s.Role -PrincipalType ServicePrincipal | Out-Null; Show 'granted' ("{0} on {1}" -f $s.Role, ($s.Scope -split '/')[-1]) }
                catch { $failed++; Show 'FAILED' ("{0} on {1} -- {2}" -f $s.Role, ($s.Scope -split '/')[-1], $_.Exception.Message); $tasks.Add(('# Azure role "{0}" on "{1}" for the Invardia support app ({2}) -- Azure portal: the resource > Access control (IAM) > Add > Add role assignment > {0}' -f $s.Role, $s.Scope, $sp.id)) }
            } else { Show 'plan' ("grant {0} on {1}" -f $s.Role, ($s.Scope -split '/')[-1]) }
        } elseif ($Remove -and $have.Count) {
            if ($PSCmdlet.ShouldProcess("$($s.Role) on $(($s.Scope -split '/')[-1])", 'remove')) {
                try { Remove-SIRoleAssignment -ObjectId $sp.id -Scope $s.Scope -RoleDefinitionName $s.Role | Out-Null; Show 'removed' ("{0} on {1}" -f $s.Role, ($s.Scope -split '/')[-1]) }
                catch { $failed++; Show 'FAILED' ("remove {0} -- {1}" -f $s.Role, $_.Exception.Message) }
            } else { Show 'plan' ("remove {0} on {1}" -f $s.Role, ($s.Scope -split '/')[-1]) }
        } elseif (-not $Remove) { Show 'present' ("{0} on {1}" -f $s.Role, ($s.Scope -split '/')[-1]) }
    }
}

# ---- 3. owner of SI's app registrations ----
$apps = @(@([string]$global:SI_SPN_AppId, $ManagementAppId) | Where-Object { $_ } | Select-Object -Unique)
if (-not $apps.Count) { Show 'skipped' 'no SI app registration in this install (managed identity, no web app id given)' }
foreach ($a in $apps) {
    $app = $null; try { $app = Invoke-Graph Get "https://graph.microsoft.com/v1.0/applications(appId='$a')?`$select=id,displayName" $null } catch { }
    if (-not $app) { $failed++; Show 'MISSING' "app registration $a (not found, or this account cannot read it)"; continue }
    $owner = $false; try { $owner = @((Invoke-Graph Get "https://graph.microsoft.com/v1.0/applications/$($app.id)/owners?`$select=id" $null).value | Where-Object { $_.id -eq $sp.id }).Count -gt 0 } catch { }
    if (-not $Remove -and -not $owner) {
        if ($PSCmdlet.ShouldProcess("app $($app.displayName)", 'add owner')) {
            try { Invoke-Graph Post "https://graph.microsoft.com/v1.0/applications/$($app.id)/owners/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($sp.id)" } | Out-Null; Show 'granted' "owner of $($app.displayName)" }
            catch { $failed++; Show 'FAILED' "owner of $($app.displayName)"; $tasks.Add(("# Entra admin center: App registrations -> {0} -> Owners -> add '{1}'" -f $app.displayName, $sp.displayName)) }
        } else { Show 'plan' "add as owner of $($app.displayName)" }
    } elseif ($Remove -and $owner) {
        if ($PSCmdlet.ShouldProcess("app $($app.displayName)", 'remove owner')) {
            try { Invoke-Graph Delete "https://graph.microsoft.com/v1.0/applications/$($app.id)/owners/$($sp.id)/`$ref" $null | Out-Null; Show 'removed' "owner of $($app.displayName)" }
            catch { $failed++; Show 'FAILED' "remove owner of $($app.displayName)"; $tasks.Add(("# Entra admin center: App registrations -> {0} -> Owners -> remove '{1}'" -f $app.displayName, $sp.displayName)) }
        } else { Show 'plan' "remove as owner of $($app.displayName)" }
    } elseif (-not $Remove) { Show 'present' "owner of $($app.displayName)" }
}

if ($failed) {
    Write-Warning ('{0} item(s) not done. For someone with the rights:' -f $failed)
    foreach ($t in $tasks) { Write-Host ('  ' + $t) -ForegroundColor Yellow }
    exit 1
}
Write-Host '  Done.' -ForegroundColor Green
exit 0
} finally { Stop-SIScriptRun -Run $siRun }
