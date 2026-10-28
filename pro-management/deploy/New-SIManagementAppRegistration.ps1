#Requires -Version 5.1
<#
.SYNOPSIS
    Creates or updates the Entra app registration the SecurityInsight Pro management web app signs in with, and the
    MCP server validates bearer tokens for. PLAN BY DEFAULT; -Apply makes the changes.

.DESCRIPTION
    One app registration serves both hosts:
      * the web app (Microsoft.Identity.Web, ID token only -- no client secret, no certificate, no credential at all);
      * the MCP server (JwtBearer: an access token for this app's API, carrying the Admin or Viewer app role).

    What -Apply does (Microsoft Graph REST, as whoever setup signed in as -- SecurityInsight's own REST sign-in: the guided
    install's, an Invardia support session's tokens, a person in Cloud Shell or the browser, or an app with a certificate;
    no az CLI, no PowerShell module). Least privilege (#223 b): a SERVICE PRINCIPAL
    needs only the APPLICATION permissions Application.ReadWrite.OwnedBy (or .All) + AppRoleAssignment.ReadWrite.All --
    creating the app makes the caller its owner; an EXISTING app must have the caller as an OWNER (with OwnedBy the
    caller sees and changes only apps it owns, so name an existing app by -AppId). Directory.ReadWrite.All is never
    needed. -SuperAdminUser / -AdminUser / -ViewerUser / -WallboardUser take a UPN (looked up: needs User.ReadBasic.All)
    or an object id (no lookup).
      1. the application: single tenant; app roles SuperAdmin + Admin + Viewer (shown as "SecurityInsight Reader") +
         Wallboard -- the roles of PIM Manager: Reader / (Delegated, assigned in the web app) / Admin / SuperAdmin.
         SuperAdmin/Admin/Viewer for users, groups AND applications, so an MCP client running as a service principal can
         be granted one; Wallboard for users only -- the kiosk account of a big screen, which sees the wall board page and
         nothing else; Department for users only (-DepartmentUser) -- sign-in for an external advisor invited as a B2B
         guest, or a department owner with no other role: it grants nothing itself, the web app shows only the
         departments that list the person. The Viewer role keeps its value and id, so every existing assignment keeps
         working as Reader.
         Security-group ids in the sign-in token (groupMembershipClaims), so the web app's Access page can map groups.
         Identifier URI api://<appId>; v2 access tokens;
         one delegated scope `Estate.Read` for user-delegated MCP clients (the app role still decides access);
         web platform with ID-token issuance; the redirect + logout URLs when -Fqdn is given;
      2. its service principal, with "assignment required" = No (#765, owner 2026-10-19 "SI decides"): any person of
         the directory may sign in, and the web app shows them nothing until a SuperAdmin gives them a role on its Access
         page (an app role assigned here is carried over into that page once, then the page decides);
      3. the SuperAdmin / Admin / Viewer / Wallboard role for every -SuperAdminUser / -AdminUser / -ViewerUser /
         -WallboardUser (an app role assignment only -- nobody signs in). Setup passes the person who runs it as
         -SuperAdminUser: the first SuperAdmin of the web app is whoever holds this app role; a SuperAdmin then assigns
         every other role and scope in the web app (Configuration > Access (roles + scopes)).
    It never adds a password or key credential. Re-running is safe: everything is looked up first and patched.

    Run it twice around the Container App deploy: once without -Fqdn (to get the client id the app needs), and once
    with -Fqdn (the redirect URI only exists after the Container App does).

.EXAMPLE
    .\New-SIManagementAppRegistration.ps1 -TenantId <tenant> -AdminUser admin@contoso.com
    # -> 'SecurityInsight Management' -- the same name in every environment (no ring, no environment in it).
    # An app created earlier under another name is found by -AppId (or -DisplayName '<its name>').
    .\New-SIManagementAppRegistration.ps1 -TenantId <tenant> -Fqdn ca-si-management.internal.<env-domain> -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TenantId,
    # ONE product-level name, identical in every environment (operator 2026-10-04: no release ring in names -- the name is
    # what a user sees on the consent screen). Several installs in one tenant share the name, so name an existing app by
    # -AppId (the deploy records it as SI_Management_AppId); a name that matches two apps is refused. -DisplayName wins.
    [string]$DisplayName = '',
    # kept for callers of earlier releases; it is no longer part of the name
    [ValidateSet('r0', 'r1', 'r2', 'prod')][string]$Ring = 'prod',
    # an EXISTING app by its appId (client id) instead of by display name -- use it when the caller holds only
    # Application.ReadWrite.OwnedBy, which lists only the apps the caller owns
    [ValidatePattern('^$|^[0-9a-fA-F-]{36}$')][string]$AppId = '',
    # the web app's host name (no scheme); adds https://<fqdn>/signin-oidc + the logout URL
    [string]$Fqdn = '',
    # the web app's top role (roles + scopes, licence, updates, template releases): setup passes the person who runs it
    [string[]]$SuperAdminUser = @(),
    [string[]]$AdminUser = @(),
    [string[]]$ViewerUser = @(),
    # the kiosk account(s) of a big screen: the Wallboard role sees only /Wallboard
    [string[]]$WallboardUser = @(),
    # #258: a person of a department who signs in with Entra and holds no other role -- an external advisor invited as a
    # B2B guest, or an owner. The role only lets them sign in; the web app scopes them to the departments that list them.
    [string[]]$DepartmentUser = @(),
    # #443 (a): the web app's user-assigned managed identity (its OBJECT / principal id). Given: the app trusts that
    # identity through a FEDERATED credential (no secret, no certificate), so the web app can redeem a sign-in for the
    # admin's delegated Exchange token -- the "Set up mail" click flow. Several installs in one tenant share the app:
    # each adds its own credential (named after its identity); nothing another install added is touched.
    [ValidatePattern('^$|^[0-9a-fA-F-]{36}$')][string]$WebIdentityPrincipalId = '',
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

# the refused tenants: an internal list (internal\SI-RefusedTenants.ps1 -- publish strips it, so the public copy names none)
$refusedList = [IO.Path]::Combine($PSScriptRoot, 'internal', 'SI-RefusedTenants.ps1')
$refused = @(if (Test-Path -LiteralPath $refusedList) { & $refusedList })
if ($refused -contains $TenantId.ToLowerInvariant()) { throw "Tenant $TenantId is refused for SecurityInsight deployments." }

if (-not "$DisplayName".Trim()) { $DisplayName = 'SecurityInsight Management' }

$graph = 'https://graph.microsoft.com/v1.0'
. (Join-Path $PSScriptRoot 'SI-ManagementSignInCredential.ps1')
# #521: the Graph token comes from SecurityInsight's own REST sign-in (SI-ManagementArm.ps1) -- no az CLI, no module
. (Join-Path $PSScriptRoot 'SI-ManagementArm.ps1')
# #852: the web app's own API for the sign-in front 1.4.0 (the scope user_impersonation + its organisation-wide consent)
. (Join-Path $PSScriptRoot 'SI-SigninFrontApi.ps1')
$mode =if ($Apply) { 'APPLY' } else { 'PLAN (nothing is changed; add -Apply)' }

# Stable ids, so a re-run patches the same roles and scope instead of minting new ones.
$roleAdminId = '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a01'
$roleViewerId = '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a02'
$scopeId = '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a03'
$roleWallboardId = '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a04'
$roleSuperAdminId = '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a05'
$roleDepartmentId = '5f1e6c62-6a3b-4c38-9d8f-2a1d0c9e7a06'

$ownerHint = 'this identity needs Application.ReadWrite.OwnedBy (or .All) and must be an OWNER of the existing app (Entra admin center -> App registrations -> the app -> Owners)'
$userHint = 'looking up a user by UPN needs User.ReadBasic.All -- or pass the user''s OBJECT ID to -AdminUser / -ViewerUser / -WallboardUser (no lookup)'

function Write-Step([string]$Text) { Write-Host ''; Write-Host ('== ' + $Text) -ForegroundColor Cyan }

function Invoke-Graph {
    <# One Graph call (Invoke-RestMethod) with a token of setup's own sign-in (Get-GraphToken). Writes run only with -Apply;
       -Read runs in plan mode too. #>
    param([Parameter(Mandatory)][string]$Method, [Parameter(Mandatory)][string]$Url, $Body = $null, [switch]$Read,
          # a READ of something THIS RUN created a moment ago: "not found" is "not there yet" and is tried again, as for a write
          [switch]$JustCreated)
    Write-Host ('  {0} {1}' -f $Method.ToUpperInvariant(), $Url.Replace($graph, '')) -ForegroundColor DarkGray
    if (-not $Apply -and -not $Read) { return $null }
    $p = @{ Method = $Method; Uri = $Url; Headers = @{ Authorization = 'Bearer ' + (Get-GraphToken) }; ErrorAction = 'Stop' }
    if ($null -ne $Body) {
        $p.ContentType = 'application/json; charset=utf-8'
        $p.Body = [System.Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 12))
    }
    for ($attempt = 1; ; $attempt++) {
        try { return (Invoke-SIRestMethod @p) }   # #548: through the support recorder in a support session
        catch {
            $status = 0
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            # an object Graph just created is not readable on every replica yet: a write that 404s, or 400s naming an
            # object that "does not exist", on a fresh id is retried for a minute before it counts as a failure. Any other
            # 400 is the request itself (e.g. "Not a valid reference update": a principal the app role does not allow --
            # live 2026-10-06) and fails at once: waiting a minute does not change it.
            $detail = "$($_.ErrorDetails) $($_.Exception.Message)"
            $replication = $status -eq 404 -or ($status -eq 400 -and $detail -match '(?i)does not exist|not found|ResourceNotFound|Request_ResourceNotFound|does not reference a valid application object|NoBackingApplicationObject' -and $detail -notmatch '(?i)Not a valid reference update')
            if (($Method -ne 'get' -or $JustCreated) -and $replication -and $attempt -lt 13) { Start-Sleep -Seconds $script:GraphRetrySeconds; continue }   # customer A 2026-10-08: the service principal of a just-created app (NoBackingApplicationObject)
            $hint = ''
            if ($status -eq 403) {
                $hint = if ($Url -match '/users[/?]') { ' -- ' + $userHint }
                        elseif ($Url -match '/(applications|servicePrincipals)') { ' -- ' + $ownerHint }
                        else { ' -- the signed-in identity lacks the permission for this call' }
            }
            throw ('Graph {0} {1} failed: {2} {3}{4}' -f $Method.ToUpperInvariant(), $Url, $_.Exception.Message, $_.ErrorDetails, $hint)
        }
    }
}

$script:graphToken = $null
# the pause between two tries of a call that answered "not there yet" (tests set $global:SI_ManagementGraphRetrySeconds = 0)
$script:GraphRetrySeconds = 10
$siGraphRetry = Get-Variable -Scope Global -Name SI_ManagementGraphRetrySeconds -ValueOnly -ErrorAction Ignore
if ($null -ne $siGraphRetry) { $script:GraphRetrySeconds = [int]$siGraphRetry }
function Get-GraphToken {
    <# A Microsoft Graph token of the one sign-in: the guided install's own ($global:SI_InstallTokenProvider), else setup's
       REST sign-in (an existing sign-in of this process is reused; else Connect-SISetupAzure). Its tenant must be -TenantId. #>
    if (-not $script:graphToken) {
        if (-not (Get-Variable -Scope Global -Name SI_InstallTokenProvider -ValueOnly -ErrorAction Ignore)) { $null = Connect-SIManagementRest -TenantId $TenantId }
        $t = Get-SIManagementToken -Resource 'https://graph.microsoft.com'
        if (-not $t) { throw 'The sign-in could not issue a Microsoft Graph token.' }
        Assert-SIManagementTokenTenant -Token $t -TenantId $TenantId -What 'The Microsoft Graph sign-in'
        $script:graphToken = $t
    }
    return $script:graphToken
}

Write-Host ('SecurityInsight Pro management -- app registration {0}' -f $mode) -ForegroundColor White
Write-Host ('  tenant {0}; display name "{1}"' -f $TenantId, $DisplayName)

# ---------------------------------------------------------------------------------------------------------------
Write-Step '1. The application (roles, API, web sign-in)'
$app = $null
if ($AppId) {
    # by appId: with Application.ReadWrite.OwnedBy an app the caller does not own answers 403/404 -- say why
    try { $app = Invoke-Graph -Method get -Url ("$graph/applications(appId='{0}')?`$select=id,appId,displayName,passwordCredentials,keyCredentials,web" -f $AppId) -Read }
    catch { throw ('The application {0} could not be read: {1}. If it exists, {2}.' -f $AppId, $_.Exception.Message, $ownerHint) }
    if ($app) { Write-Host ('  exists: appId {0} -- patched' -f $app.appId) }
    elseif ($Apply) { throw ('The application {0} was not found -- {1}.' -f $AppId, $ownerHint) }
} else {
    $filter = [uri]::EscapeDataString(("displayName eq '{0}'" -f $DisplayName.Replace("'", "''")))
    $found = Invoke-Graph -Method get -Url ("$graph/applications?`$filter=$filter&`$select=id,appId,displayName,passwordCredentials,keyCredentials,web,appRoles") -Read
    # CR5 (#655 step 2): the new-install name "SecurityInsight" is ALSO the name of SecurityInsight's engine app registration
    # (a Community install's sign-in with a secret). Under any name but today's, an app found by name is taken only when it
    # carries one of THIS app's stable role ids -- the engine's app is never patched into the web app's sign-in. Today's
    # name keeps today's behaviour exactly.
    if ($found -and $DisplayName -cne 'SecurityInsight Management') {
        $ours = @($roleSuperAdminId, $roleAdminId, $roleViewerId, $roleWallboardId, $roleDepartmentId)
        $mine = @(@($found.value) | Where-Object { $_ -and @(@($_.appRoles) | Where-Object { $_ -and $ours -contains [string]$_.id }).Count })
        $skipped = @($found.value).Count - $mine.Count
        if ($skipped -gt 0) { Write-Host ('  {0} other application(s) named "{1}" (not this web app''s sign-in: none of its roles) -- left alone' -f $skipped, $DisplayName) -ForegroundColor DarkGray }
        $found = [pscustomobject]@{ value = $mine }
    }
    # CR5 (#655 item 5): the sign-in application may carry its other name -- "SecurityInsight Management" renamed to
    # "SecurityInsight" by the update (setup\_shared\SI-DisplayNames.ps1), or the reverse. Not found under the name asked for:
    # the other name, taken only with THIS app's role ids (the engine's application "SecurityInsight" is never adopted).
    $alias = @{ 'SecurityInsight Management' = 'SecurityInsight'; 'SecurityInsight' = 'SecurityInsight Management' }
    if (-not ($found -and @($found.value).Count) -and $alias.ContainsKey($DisplayName)) {
        $other = [string]$alias[$DisplayName]
        $f2 = [uri]::EscapeDataString(("displayName eq '{0}'" -f $other))
        $found2 = Invoke-Graph -Method get -Url ("$graph/applications?`$filter=$f2&`$select=id,appId,displayName,passwordCredentials,keyCredentials,web,appRoles") -Read
        $ours = @($roleSuperAdminId, $roleAdminId, $roleViewerId, $roleWallboardId, $roleDepartmentId)
        $mine = @(@($(if ($found2) { $found2.value })) | Where-Object { $_ -and @(@($_.appRoles) | Where-Object { $_ -and $ours -contains [string]$_.id }).Count })
        if ($mine.Count) { Write-Host ('  found under its other name "{0}"' -f $other) -ForegroundColor DarkGray; $found = [pscustomobject]@{ value = $mine } }
    }
    if ($found -and @($found.value).Count -gt 1) { throw ("{0} applications are named '{1}' -- resolve that by hand first." -f @($found.value).Count, $DisplayName) }
    if ($found -and @($found.value).Count -eq 1) { $app = @($found.value)[0]; Write-Host ('  exists: appId {0} -- patched' -f $app.appId) }
    else { Write-Host '  (with Application.ReadWrite.OwnedBy only the caller''s own apps are listed: an existing app owned by someone else is not seen -- name it by -AppId)' -ForegroundColor DarkGray }
}
# CR5 (#655 item 5): an existing sign-in application keeps the name it HAS when that is one of its two names -- a setup run
# never names it back ("SecurityInsight" -> "SecurityInsight Management") nor renames an existing install (the update does
# that, setup\_shared\SI-DisplayNames.ps1). A name of the customer's own is still replaced by -DisplayName, as before.
if ($app -and $app.PSObject.Properties['displayName']) {
    $has = [string]$app.displayName
    if ($has -cne $DisplayName -and @('SecurityInsight Management', 'SecurityInsight') -ccontains $has -and @('SecurityInsight Management', 'SecurityInsight') -ccontains $DisplayName) {
        Write-Host ('  keeps its name "{0}"' -f $has) -ForegroundColor DarkGray
        $DisplayName = $has
    }
}

# PATCH-safe: a PATCH replaces the whole appRoles list, so EVERY role is always sent, each with its stable id and value
# (an id or value that changed would orphan the assignments made to it). Only display names / descriptions may change.
$roles = @(
    @{ id = $roleSuperAdminId; value = 'SuperAdmin'; displayName = 'SecurityInsight SuperAdmin'; isEnabled = $true
       description = 'Everything an Admin can do, plus roles and scopes in the web app, the licence, updates, template releases and support access.'
       allowedMemberTypes = @('User', 'Application') },
    @{ id = $roleAdminId; value = 'Admin'; displayName = 'SecurityInsight Admin'; isEnabled = $true
       description = 'Everything in the installation except roles and its own lifecycle; every MCP tool including settings_read.'
       allowedMemberTypes = @('User', 'Application') },
    @{ id = $roleViewerId; value = 'Viewer'; displayName = 'SecurityInsight Reader'; isEnabled = $true
       description = 'Reader: every view, export and the chat, no changes; the read-only MCP tools except settings_read.'
       allowedMemberTypes = @('User', 'Application') },
    @{ id = $roleWallboardId; value = 'Wallboard'; displayName = 'SecurityInsight Wallboard'; isEnabled = $true
       description = 'The big-screen kiosk account: the wall board page (KPIs + top 50 issues, auto-refresh) and nothing else.'
       allowedMemberTypes = @('User') },
    @{ id = $roleDepartmentId; value = 'Department'; displayName = 'SecurityInsight Department'; isEnabled = $true
       description = 'Sign-in for a person of a department (an external advisor as a B2B guest, an owner): grants nothing by itself; the web app shows only the departments that list them.'
       allowedMemberTypes = @('User') }
)
$scope = @{ id = $scopeId; value = 'Estate.Read'; type = 'Admin'; isEnabled = $true
            adminConsentDisplayName = 'Read SecurityInsight estate data'
            adminConsentDescription = 'Lets an MCP client call the read-only SecurityInsight tools as the signed-in user. The user still needs the Admin or Viewer app role.'
            userConsentDisplayName = 'Read SecurityInsight estate data'
            userConsentDescription = 'Lets the app call the read-only SecurityInsight tools as you.' }
$web = @{ implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } }
if ($Fqdn) {
    $h = $Fqdn.Trim().TrimEnd('/') -replace '^https?://', ''
    # ADDED to the app's redirect URIs, never replacing them: with one product-level name, every install in a tenant
    # shares the one app, and a replace would cut sign-in off for the others.
    $have = @()
    if ($app -and $app.PSObject.Properties['web'] -and $app.web -and $app.web.PSObject.Properties['redirectUris']) { $have = @($app.web.redirectUris | Where-Object { $_ }) }
    $web.redirectUris = @(@($have) + @("https://$h/signin-oidc") | Select-Object -Unique)
    $web.logoutUrl = "https://$h/signout-callback-oidc"
    Write-Host ('  redirect https://{0}/signin-oidc' -f $h)
}

if (-not $app) {
    $created = Invoke-Graph -Method post -Url "$graph/applications" -Body @{
        displayName = $DisplayName; signInAudience = 'AzureADMyOrg'; appRoles = $roles; web = $web
        # the security groups a user is in travel in the sign-in token, for the web app's group mapping
        groupMembershipClaims = 'SecurityGroup'
        # sign-in only: openid + profile (User.Read is the default delegated permission an ID-token app carries)
        requiredResourceAccess = @(@{ resourceAppId = '00000003-0000-0000-c000-000000000000'
                                      resourceAccess = @(@{ id = 'e1fe6dd8-ba31-4d61-89e7-88639da4683d'; type = 'Scope' }) })
    }
    $app = if ($created) { $created } else { [pscustomobject]@{ id = '<object id>'; appId = '<app id>' } }
} else {
    # A PATCH replaces a whole complex property: `web` is sent only with -Fqdn, so a re-run without it keeps the
    # redirect URI. (Both roles are always sent, so a patch never drops one.)
    # the name too: an app created by an earlier release carries the environment in its name; a re-run renames it
    $patch = @{ appRoles = $roles; displayName = $DisplayName }
    $patch.groupMembershipClaims = 'SecurityGroup'
    if ($Fqdn) { $patch.web = $web }
    Invoke-Graph -Method patch -Url ("$graph/applications/{0}" -f $app.id) -Body $patch | Out-Null
}
# not $appId: PowerShell names are case-insensitive, so that would re-validate the -AppId parameter and refuse the
# plan-mode placeholder of an app that does not exist yet
$clientId = [string]$app.appId
# #852: the scope the sign-in front 1.4.0 asks for (user_impersonation) is sent WITH Estate.Read -- a PATCH replaces the
# whole list, and Graph refuses to drop an enabled scope; an app that has it keeps its id
$siScopeId = $script:SISigninApiScopeId
if ($app.id -notlike '<*') {
    try {
        $apiNow = Invoke-Graph -Method get -Url ("$graph/applications/{0}?`$select=api" -f $app.id) -Read -JustCreated
        $mine = @(@($(if ($apiNow -and $apiNow.api) { $apiNow.api.oauth2PermissionScopes })) | Where-Object { $_ -and [string]$_.value -ceq 'user_impersonation' }) | Select-Object -First 1
        if ($mine -and [string]$mine.id) { $siScopeId = [string]$mine.id }
    } catch { }
}
Invoke-Graph -Method patch -Url ("$graph/applications/{0}" -f $app.id) -Body @{
    identifierUris = @("api://$clientId")
    api = @{ requestedAccessTokenVersion = 2; oauth2PermissionScopes = @($scope, (New-SISigninApiScope -Id $siScopeId)) }
} | Out-Null
if ($Apply) {
    # read one second after the create it answered "not found" and stopped a new install: retried while it is "not there yet"
    $check = Invoke-Graph -Method get -Url ("$graph/applications/{0}?`$select=passwordCredentials,keyCredentials" -f $app.id) -Read -JustCreated
    if ($check -and ((@($check.passwordCredentials).Count + @($check.keyCredentials).Count) -gt 0)) {
        Write-Warning 'The application carries a password or key credential. The management app needs none -- review and remove it.'
    }
}

# ---------------------------------------------------------------------------------------------------------------
Write-Step '2. The service principal (no assignment required: SecurityInsight decides who has access)'
$sp = $null
if ($Apply -or $app.appId -notlike '<*') {
    $spFound = Invoke-Graph -Method get -Url ("$graph/servicePrincipals?`$filter={0}&`$select=id,appId" -f [uri]::EscapeDataString("appId eq '$clientId'")) -Read
    if ($spFound -and @($spFound.value).Count -eq 1) { $sp = @($spFound.value)[0]; Write-Host '  exists -- reused' }
}
if (-not $sp) { $sp = Invoke-Graph -Method post -Url "$graph/servicePrincipals" -Body @{ appId = $clientId } }
$spId = if ($sp) { $sp.id } else { '<service principal id>' }
# the enterprise app keeps its own copy of the name -- the one users see at sign-in -- so it is renamed with the app
# #765: appRoleAssignmentRequired = $false -- SecurityInsight decides (its Access page); the web app refuses every page to a
# signed-in person it gives no role. An install made before reaches this state through its update (SI-UpdaterWebApp.ps1,
# Set-SIUpdaterSignInOpen) or a re-run of this script.
Invoke-Graph -Method patch -Url "$graph/servicePrincipals/$spId" -Body @{ appRoleAssignmentRequired = $false; tags = @('WindowsAzureActiveDirectoryIntegratedApp'); displayName = $DisplayName } | Out-Null

# ---------------------------------------------------------------------------------------------------------------
# #616 (a new customer install, 2026-10-12): a tenant that does not let users consent to applications stopped the first
# sign-in at "Approval required -- this app requires your admin's approval to: View users' basic profile; Maintain access
# to data you have given it access to". The web app asks for the sign-in permissions only; they are consented to here for
# the whole organisation, so nobody is asked. Needs DelegatedPermissionGrant.ReadWrite.All (or a role that may consent);
# without it this is a warning with what an administrator does, never a stop.
Write-Step '2b. Consent to the sign-in permissions for the organisation (sign in, read the signed-in person''s own profile)'
# ONE implementation (SI-ManagementSignInCredential.ps1, Invoke-SISignInConsent) -- the sign-in front's switch
# (setup\Set-SISigninFront.ps1) and the updater check the same grant: read, POST or PATCH (scopes only added), read back.
$signInScopes = (Get-SISignInConsentScopes) -join ' '
$signInConsent = 'not done'; $signInConsentError = ''
if ($sp -and $spId -notlike '<*') {
    try {
        $consentGraph = { param([string]$Method, [string]$Uri, $Body) if ($Method -eq 'GET') { Invoke-Graph -Method get -Url $Uri -Read } else { Invoke-Graph -Method $Method.ToLowerInvariant() -Url $Uri -Body $Body } }
        $c = Invoke-SISignInConsent -Graph $consentGraph -ServicePrincipalId $spId -ClientId $clientId -Apply:$Apply -GraphBase $graph
        if ($c.State -in 'in-place', 'given') { $signInConsent = 'in place'; Write-Host ('  ' + $c.Line) }
        elseif ($c.State -eq 'planned') { Write-Host ('  ' + $c.Line) }
        else { throw $c.Line }
    } catch {
        # reported in the result too (SignInConsent / SignInConsentError): the guided install ends its web app step as a
        # WARNING then -- a green install whose first sign-in says "Approval required" is not a finished install
        $signInConsent = 'failed'; $signInConsentError = [string]$_.Exception.Message
        Write-Warning ('The sign-in permissions were not consented to for the organisation: {0}' -f $_.Exception.Message)
    }
} else { Write-Host ('  POST /oauth2PermissionGrants  (for the organisation: {0})' -f $signInScopes) }

# #852: the sign-in front 1.4.0 sends the web app an access token for its own API -- the app's organisation-wide consent to
# its own scope user_impersonation (SI-SigninFrontApi.ps1: the URI and the scope checked, the grant added, read back). Without
# the right it is a warning; the update's step 9h and setup\Set-SISigninFront.ps1 -Apply make it later.
Write-Step '2c. The web app''s own API for the sign-in front (api://<client id>/user_impersonation, consented for the organisation)'
if ($sp -and $spId -notlike '<*') {
    $apiGraph = { param([string]$Method, [string]$Uri, $Body) if ($Method -eq 'GET') { Invoke-Graph -Method get -Url $Uri -Read } else { Invoke-Graph -Method $Method.ToLowerInvariant() -Url $Uri -Body $Body } }
    $fa = Invoke-SISigninFrontApi -Graph $apiGraph -ClientId $clientId -Apply:$Apply -GraphBase $graph
    foreach ($l in @($fa.Lines)) { if ($fa.State -in 'no-read', 'no-rights', 'failed') { Write-Warning $l } else { Write-Host ('  ' + $l) } }
} else { Write-Host ('  POST /oauth2PermissionGrants  (the app to itself, for the organisation: user_impersonation)') }

# ---------------------------------------------------------------------------------------------------------------
Write-Step '3. App role assignments (no sign-in as anyone)'
$wanted = @()
foreach ($u in $SuperAdminUser) { if ($u) { $wanted += [pscustomobject]@{ User = $u; RoleId = $roleSuperAdminId; Role = 'SuperAdmin' } } }
foreach ($u in $AdminUser) { if ($u) { $wanted += [pscustomobject]@{ User = $u; RoleId = $roleAdminId; Role = 'Admin' } } }
foreach ($u in $ViewerUser) { if ($u) { $wanted += [pscustomobject]@{ User = $u; RoleId = $roleViewerId; Role = 'Viewer' } } }
foreach ($u in $WallboardUser) { if ($u) { $wanted += [pscustomobject]@{ User = $u; RoleId = $roleWallboardId; Role = 'Wallboard' } } }
foreach ($u in $DepartmentUser) { if ($u) { $wanted += [pscustomobject]@{ User = $u; RoleId = $roleDepartmentId; Role = 'Department' } } }
if ($wanted.Count -eq 0) { Write-Host '  (none requested)' }
foreach ($w in $wanted) {
    # an object id needs no directory read; a UPN is looked up (User.ReadBasic.All)
    if ($w.User -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $uid = $w.User }
    else {
        $user = Invoke-Graph -Method get -Url ("$graph/users/{0}?`$select=id,userPrincipalName" -f [uri]::EscapeDataString($w.User)) -Read
        $uid = if ($user) { $user.id } else { '<user object id>' }
    }
    $have = $null
    if ($uid -notlike '<*' -and $sp) {
        # the resource side (the app's own service principal): AppRoleAssignment.ReadWrite.All is enough
        # the service principal may be seconds old: "not found" on its own id is "not there yet"
        $existing = Invoke-Graph -Method get -Url ("$graph/servicePrincipals/$spId/appRoleAssignedTo?`$top=999") -Read -JustCreated
        if ($existing) { $have = @($existing.value) | Where-Object { $_.principalId -eq $uid -and $_.appRoleId -eq $w.RoleId } | Select-Object -First 1 }
    }
    if ($have) { Write-Host ('  {0} already has {1}' -f $w.User, $w.Role); continue }
    if ($w.User -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        # An object id may be an application. The role says who may hold it (allowedMemberTypes); an app given a
        # people-only role is refused HERE with a reason, not by Graph's "Not a valid reference update".
        $obj = $null; try { $obj = Invoke-Graph -Method get -Url ("$graph/directoryObjects/{0}?`$select=id" -f $uid) -Read } catch { }
        $kind = if ($obj -and $obj.PSObject.Properties['@odata.type']) { [string]$obj.'@odata.type' } else { '' }
        $allowed = @(@($roles | Where-Object { $_.id -eq $w.RoleId })[0].allowedMemberTypes)
        if ($kind -match '(?i)servicePrincipal$' -and $allowed -notcontains 'Application') {
            throw ("{0} is an application (a service principal), and the {1} role is for people only (allowed: {2}): an application cannot sign in to the web app. Name a person instead." -f $w.User, $w.Role, ($allowed -join ', '))
        }
    }
    Write-Host ('  {0} -> {1}' -f $w.User, $w.Role)
    Invoke-Graph -Method post -Url "$graph/servicePrincipals/$spId/appRoleAssignedTo" -Body @{ principalId = $uid; resourceId = $spId; appRoleId = $w.RoleId } | Out-Null
}

# ---------------------------------------------------------------------------------------------------------------
Write-Step '4. The web app''s federated credential (its managed identity -- no secret, no certificate)'
$ficPresent = $false
if ($WebIdentityPrincipalId) {
    $fic = Get-SIManagementFederatedCredentialSpec -TenantId $TenantId -PrincipalId $WebIdentityPrincipalId
    $haveFic = @()
    if ($app.id -notlike '<*') {
        $list = Invoke-Graph -Method get -Url ("$graph/applications/{0}/federatedIdentityCredentials" -f $app.id) -Read
        if ($list) { $haveFic = @($list.value) }
    }
    if (Test-SIManagementFederatedCredential -Credentials $haveFic -TenantId $TenantId -PrincipalId $WebIdentityPrincipalId) {
        Write-Host ('  {0} exists -- reused' -f $fic.name); $ficPresent = $true
    } else {
        Write-Host ('  {0}: issuer {1}, subject {2}' -f $fic.name, $fic.issuer, $fic.subject)
        $made = Invoke-Graph -Method post -Url ("$graph/applications/{0}/federatedIdentityCredentials" -f $app.id) -Body $fic
        $ficPresent = [bool]$made
    }
} else { Write-Host '  -WebIdentityPrincipalId not given: the "Set up mail" click flow stays off (the page hands over setup\Set-SIMail.ps1).' }

Write-Host ''
Write-Host ('  client id (AzureAd__ClientId):   {0}' -f $clientId)
Write-Host ('  API (MCP token audience):        api://{0}   (a client asks for api://{0}/.default)' -f $clientId)
Write-Host ('  service principal object id:     {0}' -f $spId)
if (-not $Fqdn) { Write-Host '  No redirect URI yet: re-run with -Fqdn <web app host> after the Container App exists.' -ForegroundColor Yellow }
if (-not $Apply) { Write-Host 'Plan only -- nothing was changed. Re-run with -Apply to make these changes.' -ForegroundColor Yellow }

[pscustomobject]@{ AppId = $clientId; ApplicationObjectId = $app.id; ServicePrincipalId = $spId; WebFederatedCredential = $ficPresent
                   SignInConsent = $signInConsent; SignInConsentError = $signInConsentError }
