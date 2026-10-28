<#
.SYNOPSIS
    Gives the customer's Invardia Support app the access only SecurityInsight can grant -- or takes it away (#227).

.DESCRIPTION
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

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
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
                    try { Invoke-Graph Post "https://graph.microsoft.com/v1.0/groups/$($grp.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($sp.id)" } | Out-Null; Show 'granted' "member of the SQL admin group $($grp.displayName)" }
                    catch { $failed++; Show 'FAILED' "member of $($grp.displayName)"; $tasks.Add(("# Entra admin center: Groups -> {0} -> Members -> add '{1}'" -f $grp.displayName, $sp.displayName)) }
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
