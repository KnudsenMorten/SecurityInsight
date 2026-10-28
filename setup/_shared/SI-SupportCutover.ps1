#Requires -Version 5.1
<#
    THE SUPPORT-APP CUT-OVER PATTERN, shared by every SecurityInsight cut-over script (setup\Set-SISecurityBaseline.ps1,
    setup\Move-SIEngineToLeastPrivilege.ps1). Framework DOCS/REQUIREMENTS.md §12.23 P8: an EXISTING install moves by a
    scripted cut-over per environment, run by Invardia support inside that environment's Support session. The pattern
    (learned from PIM's cut-over of all its environments, 2026-10-14):

      * PLAN by default. Every run first prints the install's SHAPE: resource group, image, identities with client ids,
        the SQL server and its Entra admin, the database users with their roles, the admin group's members.
      * -Apply -Steps <list> makes exactly those steps; -Rollback <record> -Apply puts the record back.
      * Steps have STRING keys (an [ordered] hashtable with int keys treats $h[2] as an INDEX), are idempotent, and a step
        with nothing to do says "nothing to do" and writes nothing. The first step is a read-only PROOF.
      * Every write is read back and the new state printed.
      * ONE rollback record per run with the BEFORE value of everything changed: a JSON file on this machine AND a short
        row in the install's own database (cfg.InstallState).
      * Add before remove; nothing restarts.
      * One environment at a time; after each, wait 5-7 minutes, then count the runs since the cut-over and the failures
        (Wait-SICutoverObservation) -- never "it looked fine".
      * The SQL server is found from the PRODUCT'S OWN JOBS in the install's resource group (SI_ProSqlServer /
        SI_ProSqlDatabase, the settings the engine uses) -- NEVER by a name pattern (that found a Community server).
      * An admin group's member list can read back EMPTY from the group side: each identity's memberOf is read too.
      * SQL goes ONLY through Invardia's audited Invoke-InvardiaSupportSql; ARM through Invoke-InvardiaSupportArm; Graph
        through Invoke-InvardiaSupportGraph -- all recorded in the customer's audit log. Without a Support session the
        scripts refuse (tests pass their own seams).

    Seams (all three are what New-SICutoverSeams returns; tests pass fakes):
      Arm   { param([string]$Method, [string]$Path, $Body) }  parsed answer; $null = not found on a GET; throws otherwise
      Sql   { param([string]$Server, [string]$Database, [string]$Query, [string]$Reason, [bool]$ReadOnly) }  rows (hashtables
            or DataRows) of the last result set
      Graph { param([string]$Method, [string]$Uri, $Body) }  parsed answer; throws on an error
    PS 5.1 safe.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.

# Whether a Support session is open is decided in ONE place: engine\_shared\SI-AzRest.ps1 Get-SISupportSession (loaded here
# into the caller's scope when it is not there yet).
# LIVE 2026-10-18 (Set-SISecurityBaseline at internal): "Invoke-SISupportHttp is not recognized" unless the caller had
# dot-sourced SI-AzRest.ps1 first -- the file was loaded only when Get-SISupportSession was missing, and otherwise INSIDE
# New-SICutoverSeams, where its functions end with the function. Loaded HERE, in the caller's scope, whenever either is missing.
if (-not (Get-Command -Name Get-SISupportSession -ErrorAction SilentlyContinue) -or -not (Get-Command -Name Invoke-SISupportHttp -ErrorAction SilentlyContinue)) {
    . ([IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'engine', '_shared', 'SI-AzRest.ps1'))
}

$script:SICutoverAppApi = '2025-07-01'
$script:SICutoverSqlApi = '2021-11-01'
$script:SICutoverMiApi  = '2023-01-31'

function Get-SICutoverProp {
    <# PURE. A nested property (PSCustomObject, hashtable or DataRow), $null when any step is missing. #>
    param($Object, [string[]]$Names)
    $o = $Object
    foreach ($n in $Names) {
        if ($null -eq $o) { return $null }
        if ($o -is [System.Data.DataRow]) { if ($o.Table.Columns.Contains($n)) { $o = $o[$n]; if ($o -is [System.DBNull]) { $o = $null } } else { return $null }; continue }
        if ($o -is [System.Collections.IDictionary]) { if ($o.Contains($n)) { $o = $o[$n] } else { return $null }; continue }
        $p = $o.PSObject.Properties[$n]
        if (-not $p) { return $null }
        $o = $p.Value
    }
    $o
}

function New-SICutoverSeams {
    <# The three seams over the open Invardia Support session (refused without one), or the given test seams.
       -Reason is recorded with every call. #>
    param([scriptblock]$Arm, [scriptblock]$Sql, [scriptblock]$Graph, [Parameter(Mandatory)][string]$Reason)
    $needSession = (-not $Arm) -or (-not $Sql) -or (-not $Graph)
    if ($needSession) {
        $sess = if (Get-Command -Name Get-SISupportSession -ErrorAction SilentlyContinue) { Get-SISupportSession } else { $null }
        foreach ($f in @('Invoke-InvardiaSupportSql')) {   # (ARM / Graph go through Invoke-SISupportHttp, which refuses without a session and its recorder)
            if (-not $sess -or -not (Test-Path -LiteralPath ('Function:\' + $f))) {
                throw ('Refused: no Invardia Support session with {0} is open in this PowerShell session. Open the environment''s session first (. Connect-InvardiaSupport.ps1 -Environment <handle> -Reason ''<why>''). Nothing was read or changed; this script never signs in or opens a connection of its own.' -f $f)
            }
        }
    }
    $why = $Reason
    # #548: every Support request through the ONE seam (engine\_shared\SI-AzRest.ps1, Invoke-SISupportHttp), which sends it
    # through Invardia's recording wrapper and refuses a subscription the environment does not name. The file is loaded at
    # the top of this file (the caller's scope -- never here: what a function dot-sources ends with the function), and the
    # seams hold the command itself, so they find it wherever they are called from.
    $http = Get-Command -Name Invoke-SISupportHttp -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $http -and ((-not $Arm) -or (-not $Graph))) { throw 'Invoke-SISupportHttp (engine\_shared\SI-AzRest.ps1) is not loaded -- dot-source setup\_shared\SI-SupportCutover.ps1 at the top of the script. Nothing was read or changed.' }
    if (-not $Arm) {
        $Arm = {
            param([string]$Method, [string]$Path, $Body)
            $p = @{ Method = $Method; Uri = $(if ($Path -match '^https://') { $Path } else { 'https://management.azure.com' + $(if ($Path.StartsWith('/')) { $Path } else { "/$Path" }) }) }
            if ($null -ne $Body) { $p['Body'] = $(if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 30 -Compress }); $p['ContentType'] = 'application/json' }
            $r = & $http @p
            $code = [int]$r.StatusCode
            if ($code -eq 404 -and $Method -eq 'GET') { return $null }
            if ($code -ge 400 -or $code -eq 0) {
                $msg = try { [string](($r.Content | ConvertFrom-Json).error.message) } catch { [string]$r.Content }
                throw ('Azure answered {0} to {1} {2}: {3}' -f $code, $Method, ($Path -replace '\?.*$', ''), $msg)
            }
            if ([string]::IsNullOrWhiteSpace([string]$r.Content)) { return $null }
            $r.Content | ConvertFrom-Json
        }.GetNewClosure()
    }
    if (-not $Sql) {
        $Sql = {
            param([string]$Server, [string]$Database, [string]$Query, [string]$Reason, [bool]$ReadOnly)
            $r = Invoke-InvardiaSupportSql -Server $Server -Database $Database -Query $Query -Reason $(if ($Reason) { $Reason } else { $why }) -ReadOnly:$ReadOnly
            if ($r -and $r.PSObject.Properties['Rows']) { , @($r.Rows) } else { , @() }
        }.GetNewClosure()
    }
    if (-not $Graph) {
        $Graph = {
            param([string]$Method, [string]$Uri, $Body)
            $p = @{ Method = $Method; Uri = $(if ($Uri -match '^https://') { $Uri } else { 'https://graph.microsoft.com' + $(if ($Uri.StartsWith('/')) { $Uri } else { "/$Uri" }) }) }
            if ($null -ne $Body) { $p['Body'] = $(if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 30 -Compress }); $p['ContentType'] = 'application/json' }
            $r = & $http @p
            $code = [int]$r.StatusCode
            if ($code -ge 400 -or $code -eq 0) {
                $msg = try { [string](($r.Content | ConvertFrom-Json).error.message) } catch { [string]$r.Content }
                throw ('Microsoft Graph answered {0} to {1} {2}: {3}' -f $code, $Method, ($p.Uri -replace '\?.*$', ''), $msg)
            }
            if ([string]::IsNullOrWhiteSpace([string]$r.Content)) { return $null }
            $r.Content | ConvertFrom-Json
        }.GetNewClosure()
    }
    [pscustomobject]@{ Arm = $Arm; Sql = $Sql; Graph = $Graph; Reason = $Reason }
}

function Get-SICutoverArmList {
    <# Every item of an ARM list (follows nextLink). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$Path)
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Path
    for ($i = 0; $next -and $i -lt 50; $i++) {
        $page = & $Arm 'GET' $next $null
        if (-not $page) { break }
        foreach ($v in @(Get-SICutoverProp $page @('value'))) { if ($null -ne $v) { $items.Add($v) } }
        $nl = [string](Get-SICutoverProp $page @('nextLink'))
        $next = if ($nl) { $nl -replace '^https://management\.azure\.com', '' } else { '' }
    }
    $items.ToArray()
}

function Get-SICutoverEnv {
    <# PURE. The first non-empty value of environment variable -Name on the given jobs / apps (first container). #>
    param([object[]]$Resources = @(), [Parameter(Mandatory)][string]$Name)
    foreach ($r in @($Resources | Where-Object { $null -ne $_ })) {
        foreach ($c in @(Get-SICutoverProp $r @('properties', 'template', 'containers'))) {
            foreach ($e in @(Get-SICutoverProp $c @('env'))) {
                if ($null -ne $e -and [string](Get-SICutoverProp $e @('name')) -eq $Name) {
                    $v = [string](Get-SICutoverProp $e @('value')); if ($v.Trim()) { return $v.Trim() }
                }
            }
        }
    }
    ''
}

function Resolve-SICutoverSteps {
    <# PURE. -Steps (names, or 'a,b' strings) checked against -Known (string keys, in their order). Unknown = refused. #>
    param([string[]]$Steps = @(), [Parameter(Mandatory)][string[]]$Known)
    $want = @($Steps | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    foreach ($w in $want) { if ($Known -notcontains $w) { throw ('Unknown step ''{0}'' -- the steps are: {1}' -f $w, ($Known -join ', ')) } }
    @($Known | Where-Object { $want -contains $_ })
}

function Get-SIInstallShape {
    <#
        The install's shape from ARM, read in its resource group: jobs and apps, the engine image, the user-assigned
        identities (name, client id, principal id, which jobs / apps use it), the engine identity (SI_UAMI_ClientId on the
        engine jobs), the SQL server FROM THE JOBS' OWN SETTINGS (SI_Pro_DataSqlServer / SI_ProSqlServer as an FQDN,
        matched EXACTLY to a server's fullyQualifiedDomainName -- never a name pattern) and its Entra admin, the Pro
        database, the workspace, the Key Vault the jobs name, the registry they pull from.
    #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)][string]$SubscriptionId, [Parameter(Mandatory)][string]$ResourceGroup,
          # the database server when the caller names it (a name or an FQDN) -- wins over everything below
          [string]$SqlServerName = '',
          # CR8 (live 2026-10-18: internal's jobs name no SI_ProSqlServer): when neither the jobs nor the apps name the server,
          # take THE ONE Microsoft.Sql server in the install's own resource group (more than one = not guessed)
          [switch]$FindSqlInResourceGroup)
    $rgPath = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ResourceGroup
    $jobs = @(Get-SICutoverArmList -Arm $Arm -Path ('{0}/providers/Microsoft.App/jobs?api-version={1}' -f $rgPath, $script:SICutoverAppApi))
    $apps = @(Get-SICutoverArmList -Arm $Arm -Path ('{0}/providers/Microsoft.App/containerApps?api-version={1}' -f $rgPath, $script:SICutoverAppApi))
    $mis = @(Get-SICutoverArmList -Arm $Arm -Path ('{0}/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version={1}' -f $rgPath, $script:SICutoverMiApi))
    $all = @($jobs) + @($apps)
    $engineJobs = @($jobs | Where-Object { [string](Get-SICutoverProp $_ @('name')) -notmatch '(?i)updater|tagging' })
    $image = ''
    foreach ($j in $engineJobs) { $c = @(Get-SICutoverProp $j @('properties', 'template', 'containers'))[0]; $image = [string](Get-SICutoverProp $c @('image')); if ($image) { break } }
    $ids = New-Object System.Collections.Generic.List[object]
    foreach ($m in $mis) {
        $mid = ([string](Get-SICutoverProp $m @('id'))).ToLowerInvariant()
        $users = @($all | Where-Object { $ui = Get-SICutoverProp $_ @('identity', 'userAssignedIdentities'); $ui -and @($ui.PSObject.Properties | Where-Object { $_.Name.ToLowerInvariant() -eq $mid }).Count } | ForEach-Object { [string](Get-SICutoverProp $_ @('name')) })
        $ids.Add([pscustomobject]@{ Name = [string](Get-SICutoverProp $m @('name')); ClientId = [string](Get-SICutoverProp $m @('properties', 'clientId'))
                                    PrincipalId = [string](Get-SICutoverProp $m @('properties', 'principalId')); Id = [string](Get-SICutoverProp $m @('id')); UsedBy = $users })
    }
    $engineCid = Get-SICutoverEnv -Resources $engineJobs -Name 'SI_UAMI_ClientId'
    $engineId = @($ids | Where-Object { $engineCid -and $_.ClientId -eq $engineCid })[0]
    # the database server, in this order (each source named on the shape, SqlSource): -SqlServerName; the engine jobs' own
    # settings; the apps' settings (the web app / MCP server: Estate__SqlServer, or SI_ProSqlServer); with
    # -FindSqlInResourceGroup the one server in the install's resource group. Never a name pattern.
    $src = ''
    $fqdn = "$SqlServerName".Trim(); if ($fqdn) { $src = '-SqlServerName' }
    if (-not $fqdn) { $fqdn = Get-SICutoverEnv -Resources $engineJobs -Name 'SI_Pro_DataSqlServer'; if ($fqdn) { $src = 'the jobs (SI_Pro_DataSqlServer)' } }
    if (-not $fqdn) { $fqdn = Get-SICutoverEnv -Resources $engineJobs -Name 'SI_ProSqlServer'; if ($fqdn) { $src = 'the jobs (SI_ProSqlServer)' } }
    if (-not $fqdn) { $fqdn = Get-SICutoverEnv -Resources $apps -Name 'Estate__SqlServer'; if ($fqdn) { $src = 'the web app (Estate__SqlServer)' } }
    if (-not $fqdn) { $fqdn = Get-SICutoverEnv -Resources $apps -Name 'SI_ProSqlServer'; if ($fqdn) { $src = 'the web app (SI_ProSqlServer)' } }
    $db = Get-SICutoverEnv -Resources $engineJobs -Name 'SI_Pro_DataSqlDatabase'
    if (-not $db) { $db = Get-SICutoverEnv -Resources $engineJobs -Name 'SI_ProSqlDatabase' }
    if (-not $db) { $db = Get-SICutoverEnv -Resources $apps -Name 'Estate__SqlDatabase' }
    if (-not $db) { $db = Get-SICutoverEnv -Resources $apps -Name 'SI_ProSqlDatabase' }
    $bare = if ($fqdn -and $fqdn -notmatch '\.') { $fqdn } else { '' }
    if ($bare) { $fqdn = $fqdn + '.database.windows.net' }
    $server = $null; $sqlProblem = ''
    if ($fqdn) {
        $server = @(Get-SICutoverArmList -Arm $Arm -Path ('/subscriptions/{0}/providers/Microsoft.Sql/servers?api-version={1}' -f $SubscriptionId, $script:SICutoverSqlApi) |
                    Where-Object { ([string](Get-SICutoverProp $_ @('properties', 'fullyQualifiedDomainName'))).ToLowerInvariant() -eq $fqdn.ToLowerInvariant() -or
                                   ($bare -and ([string](Get-SICutoverProp $_ @('name'))).ToLowerInvariant() -eq $bare.ToLowerInvariant()) })[0]
        if ($server) { $f2 = [string](Get-SICutoverProp $server @('properties', 'fullyQualifiedDomainName')); if ($f2) { $fqdn = $f2 } }
    } elseif ($FindSqlInResourceGroup) {
        $inRg = @(Get-SICutoverArmList -Arm $Arm -Path ('{0}/providers/Microsoft.Sql/servers?api-version={1}' -f $rgPath, $script:SICutoverSqlApi))
        if ($inRg.Count -eq 1) {
            $server = $inRg[0]; $fqdn = [string](Get-SICutoverProp $server @('properties', 'fullyQualifiedDomainName'))
            $src = 'the one database server in the resource group'
        } elseif ($inRg.Count -gt 1) {
            $sqlProblem = ('the jobs name no database server and {0} servers are in {1} ({2}) -- give -SqlServerName' -f $inRg.Count, $ResourceGroup, ((@($inRg | ForEach-Object { [string](Get-SICutoverProp $_ @('name')) })) -join ', '))
        }
    }
    $admin = Get-SICutoverProp $server @('properties', 'administrators')
    [pscustomobject]@{
        SubscriptionId = $SubscriptionId; ResourceGroup = $ResourceGroup; Jobs = $jobs; Apps = $apps; Image = $image
        Identities = $ids.ToArray(); EngineIdentity = $engineId; EngineClientId = $engineCid
        SqlFqdn = $fqdn; Database = $db; SqlServer = $server; SqlServerId = [string](Get-SICutoverProp $server @('id')); SqlSource = $src; SqlProblem = $sqlProblem
        EntraAdmin = $(if ($admin) { [pscustomobject]@{ Login = [string](Get-SICutoverProp $admin @('login')); Sid = [string](Get-SICutoverProp $admin @('sid')); Type = [string](Get-SICutoverProp $admin @('principalType')) } } else { $null })
        WorkspaceResourceId = Get-SICutoverEnv -Resources $all -Name 'SI_WorkspaceResourceId'
        KeyVaultName = Get-SICutoverEnv -Resources $all -Name 'SI_KeyVaultName'
        DbUsers = @(); AdminGroup = $null; AdminGroupMembers = @(); AdminGroupMemberOf = @(); Problems = @()
    }
}

function Get-SIDbUsersSql {
    <# PURE. The database's Entra users with their roles and client ids (read-only). #>
@'
SELECT p.name AS UserName, p.type_desc AS UserType,
       CONVERT(varchar(36), CONVERT(uniqueidentifier, p.sid)) AS ClientId,
       ISNULL((SELECT STRING_AGG(CONVERT(nvarchar(max), r.name), N',') FROM sys.database_role_members AS m
               JOIN sys.database_principals AS r ON r.principal_id = m.role_principal_id WHERE m.member_principal_id = p.principal_id), N'') AS Roles
FROM sys.database_principals AS p WHERE p.type IN ('E', 'X') ORDER BY p.name;
'@
}

function Add-SIInstallSqlShape {
    <# The database users + roles (through the audited SQL seam, read-only) and the admin group's members, read from BOTH
       sides (the group's member list, and each identity's memberOf). Problems are noted on the shape, never thrown. #>
    param([Parameter(Mandatory)]$Shape, [scriptblock]$Sql, [scriptblock]$Graph, [string]$Reason = 'read the install''s database users')
    if ($Sql -and $Shape.SqlFqdn -and $Shape.Database) {
        try {
            $rows = @(& $Sql $Shape.SqlFqdn $Shape.Database (Get-SIDbUsersSql) $Reason $true | ForEach-Object { $_ })
            $Shape.DbUsers = @($rows | ForEach-Object { [pscustomobject]@{ Name = [string](Get-SICutoverProp $_ @('UserName')); Type = [string](Get-SICutoverProp $_ @('UserType'))
                                                                             ClientId = [string](Get-SICutoverProp $_ @('ClientId')); Roles = @(([string](Get-SICutoverProp $_ @('Roles'))) -split ',' | Where-Object { $_ }) } })
        } catch { $Shape.Problems = @($Shape.Problems) + @(('the database users could not be read: {0}' -f $_.Exception.Message)) }
    }
    if ($Graph -and $Shape.EntraAdmin -and $Shape.EntraAdmin.Sid -and $Shape.EntraAdmin.Type -eq 'Group') {
        $gid = $Shape.EntraAdmin.Sid
        try {
            $Shape.AdminGroup = & $Graph 'GET' ('https://graph.microsoft.com/v1.0/groups/{0}?$select=id,displayName,isAssignableToRole' -f $gid) $null
            $mem = & $Graph 'GET' ('https://graph.microsoft.com/v1.0/groups/{0}/members?$select=id,displayName' -f $gid) $null
            $Shape.AdminGroupMembers = @(@(Get-SICutoverProp $mem @('value')) | Where-Object { $_ } | ForEach-Object { [pscustomobject]@{ Id = [string]$_.id; Name = [string]$_.displayName } })
        } catch { $Shape.Problems = @($Shape.Problems) + @(('the SQL admin group could not be read: {0}' -f $_.Exception.Message)) }
        # the identity side: a member list can read back EMPTY when the reader may not list other apps' objects
        $Shape.AdminGroupMemberOf = @(foreach ($i in @($Shape.Identities)) {
            if (-not $i.PrincipalId) { continue }
            try {
                $mo = & $Graph 'GET' ('https://graph.microsoft.com/v1.0/servicePrincipals/{0}/memberOf?$select=id,displayName' -f $i.PrincipalId) $null
                if (@(@(Get-SICutoverProp $mo @('value')) | Where-Object { $_ -and [string]$_.id -eq $gid }).Count) { $i.Name }
            } catch { $Shape.Problems = @($Shape.Problems) + @(('memberOf of {0} could not be read: {1}' -f $i.Name, $_.Exception.Message)) }
        })
    }
    $Shape
}

function Format-SIInstallShape {
    <# PURE. The shape as lines (printed first by every cut-over run). #>
    param([Parameter(Mandatory)]$Shape)
    $l = New-Object System.Collections.Generic.List[string]
    $l.Add(('resource group : {0} (subscription {1}) -- {2} job(s), {3} app(s)' -f $Shape.ResourceGroup, $Shape.SubscriptionId, @($Shape.Jobs).Count, @($Shape.Apps).Count))
    $l.Add(('image          : {0}' -f $(if ($Shape.Image) { $Shape.Image } else { '(none found)' })))
    foreach ($i in @($Shape.Identities)) { $l.Add(('identity       : {0}  client {1}{2}{3}' -f $i.Name, $i.ClientId, $(if ($Shape.EngineIdentity -and $i.ClientId -eq $Shape.EngineIdentity.ClientId) { '  [engine]' } else { '' }), $(if (@($i.UsedBy).Count) { '  used by ' + (@($i.UsedBy) -join ', ') } else { '' }))) }
    $sqlSrc = if ($Shape.PSObject.Properties['SqlSource'] -and "$($Shape.SqlSource)".Trim()) { '  (from {0})' -f $Shape.SqlSource } else { '' }
    $sqlNone = if ($Shape.PSObject.Properties['SqlProblem'] -and "$($Shape.SqlProblem)".Trim()) { "($($Shape.SqlProblem))" } else { '(the jobs name none)' }
    $l.Add(('SQL server     : {0}{1}{2}' -f $(if ($Shape.SqlServerId) { $Shape.SqlFqdn } elseif ($Shape.SqlFqdn) { $Shape.SqlFqdn + ' (NOT found in the subscription)' } else { $sqlNone }), $(if ($Shape.Database) { ' / ' + $Shape.Database } else { '' }), $(if ($Shape.SqlFqdn) { $sqlSrc } else { '' })))
    if ($Shape.EntraAdmin) { $l.Add(('Entra admin    : {0} ({1}, {2})' -f $Shape.EntraAdmin.Login, $Shape.EntraAdmin.Type, $Shape.EntraAdmin.Sid)) }
    foreach ($u in @($Shape.DbUsers)) { $l.Add(('database user  : {0}  client {1}  roles {2}' -f $u.Name, $u.ClientId, $(if (@($u.Roles).Count) { @($u.Roles) -join ', ' } else { '(none)' }))) }
    if ($Shape.AdminGroup) {
        $l.Add(('admin group    : {0} -- members (group side): {1}; identities that are members (their memberOf): {2}' -f [string]$Shape.AdminGroup.displayName,
            $(if (@($Shape.AdminGroupMembers).Count) { (@($Shape.AdminGroupMembers) | ForEach-Object { $_.Name }) -join ', ' } else { '(none read)' }),
            $(if (@($Shape.AdminGroupMemberOf).Count) { @($Shape.AdminGroupMemberOf) -join ', ' } else { '(none)' })))
    }
    if ($Shape.WorkspaceResourceId) { $l.Add(('workspace      : {0}' -f ($Shape.WorkspaceResourceId -split '/')[-1])) }
    if ($Shape.KeyVaultName) { $l.Add(('key vault      : {0}' -f $Shape.KeyVaultName)) }
    foreach ($p in @($Shape.Problems)) { $l.Add(('NOT READ       : {0}' -f $p)) }
    $l.ToArray()
}

function New-SICutoverRecord {
    <# A new rollback record (an ordered dictionary: steps 'applied', each one's 'before'). #>
    param([Parameter(Mandatory)][string]$Script, [string]$Environment, $Shape, [datetime]$Now = [datetime]::UtcNow)
    [ordered]@{ script = $Script; environment = $Environment; utc = $Now.ToString('o')
                subscriptionId = [string](Get-SICutoverProp $Shape @('SubscriptionId')); resourceGroup = [string](Get-SICutoverProp $Shape @('ResourceGroup'))
                sqlServer = [string](Get-SICutoverProp $Shape @('SqlFqdn')); database = [string](Get-SICutoverProp $Shape @('Database'))
                applied = @(); before = [ordered]@{} }
}

function Get-SICutoverRecordPath {
    <# PURE. Where the local record of this run goes. #>
    param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string]$Script, [string]$Environment, [datetime]$Now = [datetime]::UtcNow)
    [IO.Path]::Combine($Directory, ('{0}-{1}-{2}.json' -f $Script, $(if ($Environment) { $Environment -replace '[^A-Za-z0-9_.-]', '_' } else { 'environment' }), $Now.ToString('yyyyMMdd-HHmmss')))
}

function Get-SICutoverInstallStateSql {
    <# PURE. The statement that keeps a SHORT copy of the record in the install (cfg.InstallState: Name <= 64, Value <= 400):
       which steps were applied when, and where the full record is. The full before-values are in the local file. #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Value, [string]$By = 'SecurityInsight cut-over')
    $q = { param([string]$s) "N'" + $s.Replace("'", "''") + "'" }
    $n = if ($Name.Length -gt 64) { $Name.Substring(0, 64) } else { $Name }
    $v = if ($Value.Length -gt 400) { $Value.Substring(0, 400) } else { $Value }
    ("IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL MERGE cfg.InstallState AS t USING (SELECT {0} AS Name) AS s ON t.Name = s.Name " +
     "WHEN MATCHED THEN UPDATE SET Value = {1}, UpdatedAt = SYSUTCDATETIME(), UpdatedBy = {2} " +
     "WHEN NOT MATCHED THEN INSERT (Name, Value, UpdatedBy) VALUES ({0}, {1}, {2});") -f (& $q $n), (& $q $v), (& $q $By)
}

function Save-SICutoverRecord {
    <# Writes the record to -Path (always) and, with -Sql and the shape's database, a short copy into cfg.InstallState
       (best effort: a failure is RETURNED as a line, never hidden, never stops the cut-over). Returns @{ Path; InstallLine }. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Record, [Parameter(Mandatory)][string]$Path, [scriptblock]$Sql, [string]$StateName)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Force -Path $dir }
    [IO.File]::WriteAllText($Path, ($Record | ConvertTo-Json -Depth 30))
    $line = ''
    if ($Sql -and $StateName -and $Record['sqlServer'] -and $Record['database']) {
        $short = (@{ at = $Record['utc']; applied = (@($Record['applied']) -join ','); file = (Split-Path -Leaf $Path) } | ConvertTo-Json -Compress)
        try { $null = & $Sql ([string]$Record['sqlServer']) ([string]$Record['database']) (Get-SICutoverInstallStateSql -Name $StateName -Value $short -By ([string]$Record['script'])) 'keep the cut-over''s rollback record in the install' $false; $line = 'kept in the install too (cfg.InstallState ' + $StateName + ')' }
        catch { $line = ('NOT kept in the install ({0}) -- the local file is the record' -f $_.Exception.Message) }
    }
    @{ Path = $Path; InstallLine = $line }
}

function Get-SICutoverObservation {
    <# The runs since -Since of the install's jobs, and how many failed (from each job's executions). @{ Runs; Failed;
       Running; Lines }. #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)]$Shape, [Parameter(Mandatory)][datetime]$Since)
    $runs = 0; $failed = 0; $running = 0; $lines = New-Object System.Collections.Generic.List[string]
    foreach ($j in @($Shape.Jobs)) {
        $id = [string](Get-SICutoverProp $j @('id')); if (-not $id) { continue }
        $ex = @(Get-SICutoverArmList -Arm $Arm -Path ('{0}/executions?api-version={1}' -f $id, $script:SICutoverAppApi))
        foreach ($e in $ex) {
            $st = Get-SICutoverProp $e @('properties', 'startTime'); $t = [datetime]::MinValue
            if (-not $st -or -not [datetime]::TryParse([string]$st, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$t)) { continue }
            if ($t -lt $Since.ToUniversalTime()) { continue }
            $runs++
            $s = [string](Get-SICutoverProp $e @('properties', 'status'))
            if ($s -in 'Failed', 'Degraded') { $failed++; $lines.Add(('{0}: {1} {2}' -f [string](Get-SICutoverProp $j @('name')), [string](Get-SICutoverProp $e @('name')), $s)) }
            elseif ($s -in 'Running', 'Processing') { $running++ }
        }
    }
    @{ Runs = $runs; Failed = $failed; Running = $running; Lines = $lines.ToArray() }
}

function Wait-SICutoverObservation {
    <# After an environment's cut-over: wait -Minutes (5-7), then COUNT the runs since the cut-over and the failures.
       Returns the observation; its Line says it plainly (never "looked fine"). #>
    param([Parameter(Mandatory)][scriptblock]$Arm, [Parameter(Mandatory)]$Shape, [Parameter(Mandatory)][datetime]$Since, [ValidateRange(0, 30)][int]$Minutes = 6,
          [scriptblock]$Sleep = { param($s) Start-Sleep -Seconds $s })
    if ($Minutes -gt 0) { & $Sleep ($Minutes * 60) }
    $o = Get-SICutoverObservation -Arm $Arm -Shape $Shape -Since $Since
    $o['Line'] = ('since the cut-over ({0:yyyy-MM-dd HH:mm} UTC): {1} run(s), {2} failed, {3} still running{4}' -f $Since.ToUniversalTime(), $o.Runs, $o.Failed, $o.Running, $(if ($o.Runs -eq 0) { ' -- NO run yet: start one or check again later before the next environment' } else { '' }))
    $o
}
