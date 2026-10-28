<#
.SYNOPSIS
    SecurityInsight Pro: the SQL server's Entra admin is ONE role-assignable group, named the same everywhere (#227).

.DESCRIPTION
    Operator rule 2026-10-03: "we need consistent naming ... one group per app and then the spn becomes member of that.
    this must be identically with any prod env". So the Pro SQL server's Entra admin is the group 'grp-si-sql-admins'
    (the same name in every environment and at every customer -- no environment or ring in it; PIM4EntraPS has
    'grp-pim-sql-admins'), never an SPN or a person directly. Whoever administers the database -- the setup /
    management SPN, the Invardia Support app at setup level -- is a MEMBER of the group.

    The group is ROLE-ASSIGNABLE (isAssignableToRole). An ordinary security group can be changed by anyone with Groups
    Administrator or User Administrator, and by its owners: any of them could add themselves and take over the
    SecurityInsight SQL store. Only Privileged Role Administrators (and Global Administrators) can change the members of
    a role-assignable group. The setting exists only at creation, so an existing group with this name that is NOT
    role-assignable is refused, never used, and the steps to recreate it are printed.

    Steps (idempotent; -WhatIf shows the plan):
      1. the group exists, role-assignable (security group, not mail-enabled) -- created when missing
      2. members: -MemberObjectIds, plus the server's CURRENT Entra admin when it is a user or an app (so switching
         never locks anyone out). A role-assignable group cannot contain groups: when the current admin is another
         group, its members are passed with -MemberObjectIds and the switch confirmed with -ReplaceCurrentAdminGroup.
      3. the server's Entra admin = the group (Entra-only authentication stays on)
      4. the server records that admin AS A GROUP (a server made with a person or an application as its admin keeps that
         kind otherwise, and the group's members are then not let in) -- set when it is not, and read back
    Members are only ever ADDED here; nothing takes a member out of the group.
    Existing database users (the engine identity, the identity ledger's users) are untouched.

    RIGHTS. Creating a role-assignable group, and adding members to it, needs Privileged Role Administrator (or Global
    Administrator) for a person, or Microsoft Graph RoleManagement.ReadWrite.Directory (with Group.ReadWrite.All) for an
    app. Changing the SQL server's Entra admin needs Contributor on the server.

.EXAMPLE
    .\Set-SISqlAdminGroup.ps1 -SqlServerName sql-si-prod-pro-ca -ResourceGroupName rg-si-prod-pro-ca

.LINK
    https://invardia.com/docs/si/scripts/Set-SISqlAdminGroup/
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SqlServerName,
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [string]$SubscriptionId,
    [string[]]$MemberObjectIds = @(),
    [string]$GroupName = 'grp-si-sql-admins',
    # the display name a NEW group is created with (default: -GroupName). CR5: a new install passes 'SecurityInsight SQL admins';
    # the mailNickname always follows -GroupName, so every later run finds the group under either name.
    [string]$DisplayName = '',
    # The server's current admin is ANOTHER group (for example the group this one replaces). A role-assignable group
    # cannot contain it, so its members must be in -MemberObjectIds; this switch confirms that they are.
    [switch]$ReplaceCurrentAdminGroup
)

#Requires -Version 5.1   # after the help and the param block: before the help, it hides the help from Get-Help
# framework section 12.7 / 12.10: the documentation link first, a transcript of the run, -WhatIf writes nothing
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Set-SISqlAdminGroup' -Quiet:($false)
try {
$ErrorActionPreference = 'Stop'
# Azure over native REST, no PowerShell module (#305). An existing sign-in in this process (the guided install) is reused;
# otherwise a person signs in here (Azure Cloud Shell, or the browser).
if (-not (Get-Command -Name Get-SISetupAzureContext -ErrorAction SilentlyContinue)) { . ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SetupAzure.ps1')) }
# #548: this script calls Invoke-SIRestMethod (engine\_shared\SI-AzRest.ps1, which publishes it globally). When the sign-in
# above came from a caller that did not load the REST layer, load it here -- in a child scope, so only the published
# Invoke-SIRestMethod arrives and nothing the caller already has (its own token or ARM helpers) is replaced.
if (-not (Get-Command -Name Invoke-SIRestMethod -ErrorAction SilentlyContinue)) {
    & { . ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'engine', '_shared', 'SI-AzRest.ps1')) }
}
$azCtx = Get-SISetupAzureContext
if (-not $azCtx) { $azCtx = Connect-SISetupAzure -SubscriptionId $SubscriptionId }
if (-not $SubscriptionId) { $SubscriptionId = [string]$azCtx.Subscription.Id }
$t = [string](Get-SIAzureToken -Audience Graph)
$hdr = @{ Authorization = 'Bearer ' + $t }
function Graph([string]$Method, [string]$Url, $Body) {
    $a = @{ Method = $Method; Uri = $Url; Headers = $hdr }
    if ($null -ne $Body) { $a.ContentType = 'application/json'; $a.Body = ($Body | ConvertTo-Json -Compress -Depth 5) }
    Invoke-SIRestMethod @a   # #548: through the support recorder in a support session
}
# #695: a new Entra admin is waited for until Azure has FINISHED the write (setup\_shared\SI-SqlAdminReady.ps1)
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-SqlAdminReady.ps1'))
$siAdminRest = { param([string]$Method, [string]$Path) Invoke-SIAzRestMethod -Method $Method -Path $Path }
$siAdminPrint = { param([string]$Text) Write-Host $Text -ForegroundColor DarkYellow }
$serverPath = '/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Sql/servers/{2}' -f $SubscriptionId, $ResourceGroupName, $SqlServerName
$adminPath = $serverPath + '/administrators/ActiveDirectory?api-version=2021-11-01'
Write-Host ("SecurityInsight -- SQL Entra admin group '{0}' for {1}{2}" -f $GroupName, $SqlServerName, $(if ($WhatIfPreference) { ' -- plan only (-WhatIf)' } else { '' }))
$selfCmd = '.\setup\Set-SISqlAdminGroup.ps1 -SqlServerName {0} -ResourceGroupName {1}' -f $SqlServerName, $ResourceGroupName

# ---- 1. the group (role-assignable, or refused) ----
# CR5 (#655 item 5): found under ANY of its names -- grp-si-sql-admins, its display name "SecurityInsight SQL admins" after
# the rename, or its mailNickname -- never by one display name alone: a renamed group would not be found and a second one
# would be created (setup\_shared\SI-DisplayNames.ps1, Find-SISqlAdminGroup).
. ([IO.Path]::Combine($PSScriptRoot, '_shared', 'SI-DisplayNames.ps1'))
$fg = Find-SISqlAdminGroup -Graph { param($m, $u, $b) Graph $m $u $b } -GroupName $GroupName
if ($fg.Count -gt 1) { throw ("{0} groups are named '{1}' (or carry its other name) -- resolve that by hand first: {2}" -f $fg.Count, $GroupName, ($fg.Ids -join ', ')) }
$grp = $fg.Group
if ($grp -and $grp.DisplayName -cne $GroupName) { Write-Host ('  [present ] the group {0} is shown as "{1}"' -f $GroupName, $grp.DisplayName) }
if ($grp -and -not [bool]$grp.isAssignableToRole) {
    $temp = '{0}-new' -f $GroupName
    $steps = @(
        ("The group '{0}' ({1}) is NOT role-assignable, so it is not used and no member is added." -f $GroupName, $grp.id),
        'Anyone with Groups Administrator or User Administrator, or an owner of the group, could add themselves to it and administer the SecurityInsight SQL store.',
        'Role-assignable can only be set when a group is created. Recreate it (needs Privileged Role Administrator):',
        '  1. List the old group''s members (service principals too -- a listing can leave them out; add the setup and management identities yourself):',
        ('       Microsoft Entra admin center: Groups > All groups > {0} > Members (note each member''s Object ID)' -f $grp.id),
        '  2. Create the role-assignable group under a temporary name and point the server at it:',
        ('       {0} -GroupName ''{1}'' -MemberObjectIds <the ids from step 1> -ReplaceCurrentAdminGroup' -f $selfCmd, $temp),
        '  3. Delete the old group:',
        ('       Microsoft Entra admin center: Groups > All groups > {0} > Delete' -f $grp.id),
        ('  4. Give the new group the standard name (its id is printed by step 2), then confirm:'),
        ('       Microsoft Entra admin center: Groups > All groups > <new-group-id> > Properties > Group name = {0} > Save' -f $GroupName),
        ('       {0}' -f $selfCmd),
        ('  If no SQL server uses the old group: delete it (step 3) and re-run {0}' -f $selfCmd)
    )
    foreach ($l in $steps) { Write-Host $l -ForegroundColor Yellow }
    throw ("The group '{0}' is not role-assignable and must be recreated -- the steps are printed above." -f $GroupName)
}
if ($grp) { Write-Host ('  [present ] group {0} ({1}), role-assignable' -f $GroupName, $grp.id) }
elseif ($PSCmdlet.ShouldProcess($GroupName, 'create role-assignable security group')) {
    $nick = ($GroupName -replace '[^A-Za-z0-9]', '')
    try {
        $grp = Graph Post 'https://graph.microsoft.com/v1.0/groups' @{ displayName = $(if ("$DisplayName".Trim()) { "$DisplayName".Trim() } else { $GroupName }); mailEnabled = $false; mailNickname = $nick; securityEnabled = $true
            isAssignableToRole = $true
            description = 'SecurityInsight Pro: the Entra admin of the SecurityInsight SQL server(s). Members administer the Pro database. Role-assignable: only Privileged Role Administrators change its members.' }
    } catch {
        throw ("Creating the role-assignable group '{0}' failed: {1}. It needs Privileged Role Administrator (or Global Administrator), or RoleManagement.ReadWrite.Directory for an app." -f $GroupName, $_.Exception.Message)
    }
    Write-Host ('  [created ] group {0} ({1}), role-assignable' -f $GroupName, $grp.id)
    # a new directory object answers 404 for a few seconds (replication) -- wait until it is readable
    foreach ($i in 1..24) { try { $null = Graph Get "https://graph.microsoft.com/v1.0/groups/$($grp.id)?`$select=id" $null; break } catch { Start-Sleep -Seconds 5 } }
} else { Write-Host ('  [plan    ] create role-assignable group {0}' -f $GroupName) }

# ---- 2. members (the current admin first, so the switch never locks anyone out) ----
$cur = $null
try { $cur = (Invoke-SIAzRestMethod -Method GET -Path $adminPath).Content | ConvertFrom-Json } catch { }
$curSid = if ($cur -and $cur.properties) { [string]$cur.properties.sid } else { '' }
$want = New-Object System.Collections.Generic.List[string]
if ($curSid -and (-not $grp -or $curSid -ne [string]$grp.id)) {
    # the current admin's sid is an object id for a user/group; for an app it is the app's client id -> its SP object id
    $curObj = $null; $curType = ''
    try { $o = Graph Get "https://graph.microsoft.com/v1.0/directoryObjects/$curSid" $null; $curObj = $o.id; $curType = [string]$o.'@odata.type' } catch { }
    if (-not $curObj) { try { $curObj = @((Graph Get "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$curSid'&`$select=id" $null).value)[0].id } catch { } }
    if ($curType -eq '#microsoft.graph.group') {
        # A role-assignable group cannot contain a group. Its members must be carried over by hand -- never guessed from
        # a listing, which can leave service principals out.
        if (-not $ReplaceCurrentAdminGroup) {
            Write-Host ("The server's admin today is the group '{0}' ({1}). A role-assignable group cannot contain it." -f $cur.properties.login, $curSid) -ForegroundColor Yellow
            Write-Host ('  1. List its members -- Microsoft Entra admin center: Groups > All groups > {0} > Members (note each Object ID; add the setup and management identities if they are missing)' -f $curSid) -ForegroundColor Yellow
            Write-Host ('  2. Re-run: {0} -MemberObjectIds <those ids> -ReplaceCurrentAdminGroup' -f $selfCmd) -ForegroundColor Yellow
            throw ("The server's admin is another group ('{0}'): pass its members with -MemberObjectIds and confirm with -ReplaceCurrentAdminGroup." -f $cur.properties.login)
        }
        if (@($MemberObjectIds | Where-Object { $_ }).Count -eq 0) { throw '-ReplaceCurrentAdminGroup needs -MemberObjectIds: the members that keep administering the database.' }
        Write-Host ('  [replace ] the current admin group {0} -- its members come from -MemberObjectIds' -f $cur.properties.login)
    } elseif ($curObj) { $want.Add([string]$curObj) }
    else { Write-Warning "the current admin ($($cur.properties.login)) could not be resolved -- add it to the group by hand before switching" }
}
foreach ($m in $MemberObjectIds) { if ($m -and -not $want.Contains($m)) { $want.Add($m) } }
foreach ($m in $want) {
    # asked from the MEMBER's side: a plain /members listing leaves service principals out for many callers (seen live
    # 2026-10-03), so a real member read as missing and the re-add failed
    $isMember = $false
    if ($grp -and $grp.id) { try { $isMember = @((Graph Post "https://graph.microsoft.com/v1.0/directoryObjects/$m/checkMemberGroups" @{ groupIds = @([string]$grp.id) }).value) -contains [string]$grp.id } catch { } }
    if ($isMember) { Write-Host ('  [present ] member {0}' -f $m); continue }
    if ($grp -and $grp.id -and $PSCmdlet.ShouldProcess($m, "add to $GroupName")) {
        # A group (or a member) created seconds ago answers "not found" for a moment: ONLY that answer is waited for and
        # the add tried again HERE -- never by running the whole script again, whose look-up by name could miss the new
        # group and create a second one. A refusal stops at once, with its reason.
        $memberAdded = $false; $memberError = $null
        foreach ($memberWait in 0, 5, 10, 20, 30, 30) {
            if ($memberWait) { Start-Sleep -Seconds $memberWait }
            try {
                Graph Post "https://graph.microsoft.com/v1.0/groups/$($grp.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$m" } | Out-Null
                $memberAdded = $true; break
            } catch {
                $memberError = $_
                $memberText = '{0} {1}' -f [string]$_.Exception.Message, $(if ($_.ErrorDetails) { [string]$_.ErrorDetails.Message } else { '' })
                if ($memberText -match '(?i)already exist') { $memberAdded = $true; break }
                if ($memberText -match '(?i)\b403\b|Authorization_RequestDenied|Insufficient privileges' -or $memberText -notmatch '(?i)\b404\b|Request_ResourceNotFound|does not exist|not found') {
                    throw ("adding {0} to the group '{1}' was refused: {2}" -f $m, $GroupName, $memberText.Trim())
                }
                Write-Host ('  [waiting ] the directory does not know the new group or member yet -- trying again') -ForegroundColor DarkGray
            }
        }
        if (-not $memberAdded) { throw ("adding {0} to the group '{1}' failed: the directory still answers not found (404) -- run the same command again in a minute. {2}" -f $m, $GroupName, [string]$memberError.Exception.Message) }
        Write-Host ('  [added   ] member {0}' -f $m)
    } else { Write-Host ('  [plan    ] add member {0}' -f $m) }
}

# ---- 3. the server's Entra admin = the group ----
$curLogin = if ($cur -and $cur.properties) { [string]$cur.properties.login } else { '' }
# the login is only the server's label for the group: either of the group's two names is the group (CR5: renamed groups keep their login)
if ($grp -and $grp.id -and $curSid -eq [string]$grp.id -and @(Get-SIDisplayNameAliases -Role SqlAdminGroup -Name $GroupName) -contains $curLogin) { Write-Host ('  [present ] {0} is the Entra admin of {1}' -f $GroupName, $SqlServerName) }
elseif ($grp -and $grp.id -and $PSCmdlet.ShouldProcess($SqlServerName, "set Entra admin = $GroupName")) {
    $tenant = [string]$azCtx.Tenant.Id
    $body = @{ properties = @{ administratorType = 'ActiveDirectory'; login = $GroupName; sid = [string]$grp.id; tenantId = $tenant } } | ConvertTo-Json -Depth 4
    $r = Invoke-SIAzRestMethod -Method PUT -Path $adminPath -Payload $body
    if ($r.StatusCode -ge 300) { throw ("setting the Entra admin failed ({0}): {1}" -f $r.StatusCode, $r.Content) }
    # #695 (customer B 2026-10-15): Azure answers this write Accepted and finishes it seconds later, while the admin
    # already READS BACK as set -- a sign-in in between was refused. Wait until Azure has FINISHED the write, then read back.
    $null = Wait-SISqlAdminWrite -Response $r -Rest $siAdminRest -AdminPath $adminPath -Sid ([string]$grp.id) -Login $GroupName `
        -TimeoutSec 600 -PollSec 10 -Print $siAdminPrint -What ('the new Entra admin of {0}' -f $SqlServerName)
    Write-Host ('  [set     ] {0} is now the Entra admin of {1} (was {2})' -f $GroupName, $SqlServerName, $(if ($cur) { $cur.properties.login } else { 'none' }))
} else { Write-Host ('  [plan    ] set Entra admin of {0} = {1}' -f $SqlServerName, $GroupName) }

# ---- 4. the server records that admin AS A GROUP ----
# Step 3 names the group through the server's administrators resource, which has no field for the KIND. A server that was
# made with a person or an application as its admin keeps that kind although the group is named there now -- and Azure
# SQL then does not let the group's MEMBERS in (an application was refused on 2026-10-12; with the kind Group the same
# application was let in on 2026-10-13). The kind is on the SERVER itself: read there, set there when it is not Group,
# and read back. A server whose kind cannot be read is left as it is, and that is said.
if ($grp -and $grp.id) {
    $serverUri = $serverPath + '?api-version=2021-11-01'
    $readAdmins = {
        $s = $null; try { $s = (Invoke-SIAzRestMethod -Method GET -Path $serverUri).Content | ConvertFrom-Json } catch { $s = $null }
        if ($s -and $s.PSObject.Properties['properties'] -and $s.properties -and $s.properties.PSObject.Properties['administrators']) { $s.properties.administrators } else { $null }
    }
    $adm = & $readAdmins
    $admSid = if ($adm -and $adm.PSObject.Properties['sid']) { [string]$adm.sid } else { '' }
    $admKind = if ($adm -and $adm.PSObject.Properties['principalType']) { [string]$adm.principalType } else { '' }
    if ($admSid -ne [string]$grp.id) {
        if ($WhatIfPreference) { Write-Host ('  [plan    ] record the Entra admin of {0} as a group' -f $SqlServerName) }
        else { Write-Host ('  [note    ] the kind {0} records for its Entra admin could not be read -- it must be Group for the members of {1} to be let in' -f $SqlServerName, $GroupName) -ForegroundColor Yellow }
    } elseif ($admKind -ieq 'Group') { Write-Host ('  [present ] {0} records its Entra admin as a group' -f $SqlServerName) }
    elseif ($PSCmdlet.ShouldProcess($SqlServerName, "record the Entra admin $GroupName as a group")) {
        $block = [ordered]@{ administratorType = 'ActiveDirectory'; principalType = 'Group'; login = $GroupName; sid = [string]$grp.id; tenantId = [string]$azCtx.Tenant.Id }
        # the server's own "Entra-only sign-in" setting goes back exactly as it is: the block is written whole
        if ($adm.PSObject.Properties['azureADOnlyAuthentication'] -and "$($adm.azureADOnlyAuthentication)" -ne '') { $block.azureADOnlyAuthentication = [bool]$adm.azureADOnlyAuthentication }
        $r = Invoke-SIAzRestMethod -Method PATCH -Path $serverUri -Payload (@{ properties = @{ administrators = $block } } | ConvertTo-Json -Depth 5)
        if ($r.StatusCode -ge 300) { throw ("recording the Entra admin as a group failed ({0}): {1}" -f $r.StatusCode, $r.Content) }
        # #695: this write is asynchronous too -- waited until Azure has finished it, then read back
        $null = Wait-SIArmAsyncOperation -Response $r -Rest $siAdminRest -TimeoutSec 600 -PollSec 10 -Print $siAdminPrint -What ('the change of the Entra admin of {0} to a group' -f $SqlServerName)
        $back = $null
        foreach ($i in 1..36) {
            $back = & $readAdmins
            if ($back -and [string]$back.sid -eq [string]$grp.id -and [string]$back.principalType -ieq 'Group') { break }
            Start-Sleep -Seconds 5
        }
        if (-not ($back -and [string]$back.sid -eq [string]$grp.id -and [string]$back.principalType -ieq 'Group')) { throw ('the server still records its Entra admin as "{0}", not as a group -- check the server' -f $(if ($back) { [string]$back.principalType } else { 'unreadable' })) }
        Write-Host ('  [set     ] {0} now records its Entra admin as a group (was "{1}")' -f $SqlServerName, $admKind)
    } else { Write-Host ('  [plan    ] record the Entra admin of {0} as a group (it is "{1}")' -f $SqlServerName, $admKind) }
}
} finally { Stop-SIScriptRun -Run $siRun }
