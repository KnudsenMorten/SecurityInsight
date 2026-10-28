<#
.SYNOPSIS
    SecurityInsight Setup Wizard -- local-only HTTP launcher.

.DESCRIPTION
    Hosts the Config Wizard HTML (Setup-SecurityInsight.html) on
    http://localhost:<Port> and exposes the /api/* endpoints the wizard's
    final Apply page calls to provision the SPN + Log Analytics + Storage
    and write config/SecurityInsight.custom.ps1.

    Status (v2.2.105): backend cmdlets + /api/apply orchestration LIVE.
    The HTML wizard's last page POSTs the collected wizard state to /api/apply,
    which calls New-SISpn -> Initialize-SIInfra -> Write-SICustomConfig in
    sequence and returns a JSON result with all provisioned resource IDs.

    Endpoint contract:
      GET  /api/state              wizard metadata + capability flags       -> json
      POST /api/validate-name      { type, name }  (stub: name-availability checks land in v2.2.106)
      POST /api/apply              { state: <full wizard state> }           -> result json
      GET  /api/log-stream         SSE tail of the running provisioner       (stub)

.PARAMETER Port
    TCP port to bind. Default 8766.

.PARAMETER NoBrowser
    Don't auto-launch the default browser.

.EXAMPLE
    .\Start-SetupWizard.ps1
    Opens http://localhost:8766 in your browser.

.NOTES
    Localhost-only binding -- no remote machine on the network can hit it.
    Stop with Ctrl+C.
#>
[CmdletBinding()]
param(
    [int]$Port = 8766,
    [switch]$NoBrowser,
    # The tenant (and optionally the subscription) to sign in to. Without -TenantId the browser sign-in lets you pick
    # the account; Azure Cloud Shell uses the tenant it is signed in to.
    [string]$TenantId,
    [string]$SubscriptionId,
    # How a person signs in: Auto (Cloud Shell when in Cloud Shell, else the browser), CloudShell or Browser.
    [ValidateSet('Auto', 'CloudShell', 'Browser')][string]$UserSignIn = 'Auto'
    # The day-2 Settings mode (-Mode Settings) was removed 2026-10-03: the GUI is SecurityInsight Pro only (its web
    # app); Community changes settings in its config files. This wizard is the first-time setup only.
)

# SI #547 / framework section 12.7: "<Script> version <v> - documentation: <link>" first, and a transcript of the run
. ([IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-ScriptRun.ps1'))
$siRun = Start-SIScriptRun -Script 'Start-SetupWizard'
try {
$ErrorActionPreference = 'Stop'

# ----- Resolve paths -----
$scriptDir = $PSScriptRoot
$indexHtml = Join-Path $scriptDir 'Setup-SecurityInsight.html'

if (-not (Test-Path -LiteralPath $indexHtml)) {
    throw "wizard HTML missing: $indexHtml"
}

function _Info ([string]$msg) { Write-Host "  [INFO] $msg" -ForegroundColor Gray }
function _Ok   ([string]$msg) { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function _Warn ([string]$msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function _Err  ([string]$msg) { Write-Host "  [ERR]  $msg" -ForegroundColor Red }

# Recursively convert ConvertFrom-Json's PSCustomObject tree to Hashtables so
# our backend cmdlets (which take [hashtable]) can splat properties cleanly.
function ConvertTo-HashtableFromPso {
    # AllowNull: optional sub-properties (e.g. smtp.User, cmdb.RefreshHours) can
    # arrive as $null; without it the recursion at $h[$p.Name] = ... throws
    # "Cannot bind argument to parameter 'InputObject' because it is null"
    # because [Parameter(Mandatory)] rejects $null at binding time, before the
    # function body's null guard runs.
    param([Parameter(Mandatory)][AllowNull()] $InputObject)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [hashtable]) { return $InputObject }
    if ($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        return @($InputObject | ForEach-Object { ConvertTo-HashtableFromPso $_ })
    }
    if ($InputObject -is [PSCustomObject]) {
        $h = @{}
        foreach ($p in $InputObject.PSObject.Properties) {
            $h[$p.Name] = ConvertTo-HashtableFromPso $p.Value
        }
        return $h
    }
    return $InputObject
}

# Read SI VERSION so we display + serve the actual shipping number, not a
# hardcoded string drift between releases.
$siVersionFile = Join-Path (Split-Path -Parent (Split-Path -Parent $scriptDir)) 'VERSION'
$siVersion = if (Test-Path -LiteralPath $siVersionFile) { (Get-Content -Raw -LiteralPath $siVersionFile).Trim() } else { 'dev' }

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " SecurityInsight Setup Wizard"                                       -ForegroundColor Cyan
Write-Host (" v{0}" -f $siVersion)                                               -ForegroundColor DarkCyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " Built by Morten Knudsen, Microsoft MVP"                             -ForegroundColor Gray
Write-Host " Web    : https://mortenknudsen.net"                                 -ForegroundColor Gray
Write-Host " GitHub : https://github.com/KnudsenMorten/SecurityInsight"          -ForegroundColor Gray
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

# Path to the backend cmdlets (relative to this script).
$backendDir = Join-Path $scriptDir 'backend'
$cmdletNewSISpn      = Join-Path $backendDir 'New-SISpn.ps1'
$cmdletInitInfra     = Join-Path $backendDir 'Initialize-SIInfra.ps1'
$cmdletWriteConfig   = Join-Path $backendDir 'Write-SICustomConfig.ps1'
$cmdletEntraDiag     = Join-Path $backendDir 'Set-SIEntraDiagnosticSetting.ps1'
$cmdletContainer     = Join-Path $backendDir 'Initialize-SIContainerInfra.ps1'
foreach ($c in $cmdletNewSISpn, $cmdletInitInfra, $cmdletWriteConfig, $cmdletEntraDiag, $cmdletContainer) {
    if (-not (Test-Path -LiteralPath $c)) { throw "backend cmdlet missing: $c" }
}
# The sign-in decision (default: a managed identity; a certificate or a secret is an explicit choice) and the naming.
. (Join-Path $backendDir 'SI-WizardSignIn.ps1')
. (Join-Path (Split-Path -Parent $scriptDir) '_shared\SI-SetupNaming.ps1')
_Info ("port        : {0}" -f $Port)
_Info ("wizard html : {0}" -f $indexHtml)
_Info  "backend     : New-SISpn / Initialize-SIInfra / Write-SICustomConfig / Set-SIEntraDiagnosticSetting / Initialize-SIContainerInfra"
Write-Host ""

# ----- Pre-flight: the wizard's own Azure sign-in (no PowerShell modules) -----
# /api/apply needs it. The wizard signs you in ONCE, here, before it accepts any POST: in Azure Cloud Shell
# automatically, on a workstation in your browser (setup\_shared\SI-SetupAzure.ps1 -- native REST, no Az module,
# no device code). The backend scripts run IN THIS PROCESS, so every apply call reuses this one sign-in. Microsoft
# Graph is plain REST with a token from the same sign-in (setup\_shared\SI-GraphRest.ps1).
. (Join-Path (Split-Path -Parent $scriptDir) '_shared\SI-SetupAzure.ps1')
. (Join-Path (Split-Path -Parent $scriptDir) '_shared\SI-GraphRest.ps1')
function Test-PreflightAuth {
    $azCtx = $null; $mgCtx = $null
    try { $azCtx = Get-SISetupAzureContext } catch { }
    if ($azCtx) { $mgCtx = Get-SIGraphContext }
    return @{ Az = $azCtx; Mg = $mgCtx }
}

function Get-PreflightRoleAssignments {
    <# The Azure roles the signed-in account holds that apply to -SubscriptionId: at the subscription or above
       (management group, tenant root), directly or through a group. #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$SubscriptionId)
    $subScope = "/subscriptions/$SubscriptionId"
    $oid = $null
    if ($Context.Account.Type -eq 'User') { $oid = Get-SISetupSignedInObjectId }
    else {
        # an app: the role assignments belong to its service principal (the SP, not the app registration)
        $sp = @(Get-SIAzADServicePrincipal -ApplicationId $Context.Account.Id -ErrorAction SilentlyContinue) | Select-Object -First 1
        if ($sp) { $oid = [string]$sp.Id }
    }
    if (-not $oid) { return @() }
    return @(Get-SIRoleAssignmentAssignedTo -ObjectId $oid -Scope $subScope |
             Where-Object { $subScope -like "$($_.Scope)*" -or $_.Scope -eq '/' -or $_.Scope -like '/providers/Microsoft.Management/managementGroups/*' })
}

# Permission probe -- distinguishes "authenticated" from "actually able to do
# the work". Returns @{ Blockers; Warnings; Roles } so the wizard can surface
# WHICH role is missing (not just "auth failed mid-phase"). Called at startup
# (whatever default sub we have) and on demand via /api/preflight.
function Test-PreflightPermissions {
    param(
        [Parameter()] [string]$TenantId,
        [Parameter()] [string]$SubscriptionId
    )
    $blockers = @(); $warnings = @(); $roles = @{ Graph = @(); AzureRbac = @(); Directory = @() }
    $azCtx = Get-SISetupAzureContext
    $mgCtx = if ($azCtx) { Get-SIGraphContext } else { $null }

    # 1. Microsoft Graph: required permissions present?
    # NOTE: DelegatedPermissionGrant.ReadWrite.All is NOT in this list. The
    # wizard only does application-only role assignments which need
    # AppRoleAssignment.ReadWrite.All; older docs listed the delegated scope
    # but it's unnecessary and triggers AADSTS650053 in some tenants.
    if ($mgCtx) {
        $reqScopes = @('Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.Read.All')
        # Same equivalences as New-SISpn (#223): a service principal may hold the least-privilege variants.
        $scopeEquivalents = @{
            'Application.ReadWrite.All' = @('Application.ReadWrite.All', 'Application.ReadWrite.OwnedBy')
            'Directory.Read.All' = @('Directory.Read.All', 'Directory.ReadWrite.All')
        }
        $roles.Graph = @($mgCtx.Scopes | Where-Object { $reqScopes -contains $_ -or $_ -eq 'Directory.AccessAsUser.All' })
        $missing = @(Get-SIGraphMissingScopes -Context $mgCtx -Required $reqScopes -Equivalents $scopeEquivalents)
        if ($missing.Count -gt 0) {
            $blockers += ("The Microsoft Graph sign-in is missing permissions: {0}. Restart the wizard and sign in to tenant {1} with an account or app that holds {2}." -f ($missing -join ','), $TenantId, ($reqScopes -join ','))
        }
    }

    # 2. Entra directory roles -- best-effort (only meaningful when operator is
    # a user, not a SPN). Surface as a WARNING (not blocker) since admin consent
    # can be handed off to another admin via the consent URL.
    if ($mgCtx -and $mgCtx.Account -and $mgCtx.Account -notmatch '^[0-9a-f-]{36}$') {
        try {
            $roleNames = Get-SIGraphUserDirectoryRoleNames -UserPrincipalName $mgCtx.Account
            if ($null -ne $roleNames) {
                $roleNames = @($roleNames)
                $roles.Directory = $roleNames
                $consentRoles = @('Global Administrator','Privileged Role Administrator','Cloud Application Administrator','Application Administrator')
                $hasConsent = @($roleNames | Where-Object { $consentRoles -contains $_ }).Count -gt 0
                if (-not $hasConsent) {
                    $warnings += ("Operator '{0}' has no admin consent role ({1}). Graph permission grants will be marked 'pending' and a separate admin must click the consent URL." -f $mgCtx.Account, ($consentRoles -join ' / '))
                }
            }
        } catch {
            $warnings += ("Could not enumerate operator's directory roles: {0}" -f $_.Exception.Message)
        }
    }

    # 3. Azure RBAC at the target subscription -- need Contributor/Owner/UAA to
    # provision resources + grant SPN role assignments. Without it Phase 2 (infra)
    # will fail with 403 on the first resource group. BLOCKER.
    if ($azCtx -and $SubscriptionId) {
        try {
            if (-not $azCtx.Subscription -or $azCtx.Subscription.Id -ne $SubscriptionId) {
                $null = Set-SIAzContext -Subscription $SubscriptionId
            }
            $signIn = $azCtx.Account.Id
            $azRoles = @(Get-PreflightRoleAssignments -Context $azCtx -SubscriptionId $SubscriptionId)
            $writeRoleNames = @('Owner','Contributor','User Access Administrator')
            $writeRoles = @($azRoles | Where-Object { $writeRoleNames -contains $_.RoleDefinitionName })
            $roles.AzureRbac = @($azRoles | ForEach-Object { ('{0} @ {1}' -f $_.RoleDefinitionName, $_.Scope) })
            if ($writeRoles.Count -eq 0) {
                $blockers += ("Operator '{0}' has no Owner/Contributor/User Access Administrator role at sub {1}. Phase 2 (infra prestage) will fail with 403 on the first resource creation." -f $signIn, $SubscriptionId)
            }
            $uaaRoles = @($azRoles | Where-Object { $_.RoleDefinitionName -in @('Owner','User Access Administrator') })
            if ($uaaRoles.Count -eq 0 -and $writeRoles.Count -gt 0) {
                $warnings += ("Operator has Contributor but NOT Owner/User Access Administrator. SPN role assignments at sub scope (Storage Blob/Table/Queue Data Contributor) will FAIL -- you need Owner or UAA to grant RBAC. Have a sub Owner re-run, or pre-grant the SPN those roles manually.")
            }
        } catch {
            $warnings += ("Could not enumerate Azure RBAC at sub: {0}" -f $_.Exception.Message)
        }
    }

    return @{ Blockers = $blockers; Warnings = $warnings; Roles = $roles }
}

# The sign-in: reused when this PowerShell session is already signed in to the same tenant, else a person signs in
# (Cloud Shell: automatic; workstation: the browser opens). -TenantId / -SubscriptionId pick the target up front.
_Info "sign in to Azure (Azure Cloud Shell: automatic; workstation: your browser)"
try {
    $null = Connect-SISetupAzure -TenantId $TenantId -SubscriptionId $SubscriptionId -UserSignIn $UserSignIn
} catch {
    Write-Host ""
    Write-Host "  [BLOCKED]" -ForegroundColor Red -NoNewline; Write-Host (" The Azure sign-in did not complete: {0}" -f $_.Exception.Message)
    Write-Host ""
    Write-Host "  Run the wizard again and complete the sign-in. In Azure Cloud Shell it signs you in by itself;" -ForegroundColor Cyan
    Write-Host "  on a workstation it opens your browser:" -ForegroundColor Cyan
    Write-Host ("    .\Start-SetupWizard.ps1{0}" -f $(if ($TenantId) { " -TenantId $TenantId" } else { ' -TenantId <tenant-id>' })) -ForegroundColor White
    Write-Host ""
    throw "Setup Wizard pre-flight failed: no Azure sign-in. See instructions above."
}
$pre = Test-PreflightAuth

# (#521: no Azure CLI -- the container option builds its image in the registry over ARM REST, as the same sign-in.)

# ----- Unified pre-flight gate (sign-in + Microsoft Graph) -----
if (-not $pre.Az -or -not $pre.Mg) {
    $tenantHint = if ($pre.Mg) { $pre.Mg.TenantId } elseif ($pre.Az) { $pre.Az.Tenant.Id } elseif ($TenantId) { $TenantId } else { '<tenant-id>' }
    Write-Host ""
    Write-Host "  [BLOCKED]" -ForegroundColor Red -NoNewline; Write-Host " /api/apply needs the wizard's Azure sign-in (it also reaches Microsoft Graph)."
    Write-Host ""
    # ----- Connections (line per service) -----
    if (-not $pre.Az)   { Write-Host "    Azure sign-in           : NOT SIGNED IN" -ForegroundColor Yellow }
    else                { Write-Host ("    Azure sign-in           : {0} (sub: {1})" -f $pre.Az.Account.Id, $(if ($pre.Az.Subscription) { $pre.Az.Subscription.Name } else { '-' })) -ForegroundColor Green }
    if (-not $pre.Mg)   { Write-Host "    Microsoft Graph         : NO TOKEN from the sign-in" -ForegroundColor Yellow }
    else                { Write-Host ("    Microsoft Graph         : {0} (tenant: {1})" -f $pre.Mg.Account, $pre.Mg.TenantId) -ForegroundColor Green }
    Write-Host ""
    Write-Host "  Do this, then re-launch the wizard:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("    .\Start-SetupWizard.ps1 -TenantId {0}" -f $tenantHint) -ForegroundColor White
    Write-Host ""
    Write-Host "  (The wizard signs you in itself -- no PowerShell modules, no device codes, no per-call re-auth.)" -ForegroundColor Gray
    Write-Host ""
    throw "Setup Wizard pre-flight failed: missing sign-in / Microsoft Graph. See instructions above."
}

_Ok ("Azure sign-in  : {0} (sub: {1} / {2})" -f $pre.Az.Account.Id, $(if ($pre.Az.Subscription) { $pre.Az.Subscription.Name } else { '-' }), $(if ($pre.Az.Subscription) { $pre.Az.Subscription.Id } else { '-' }))
_Ok ("Graph          : {0} (tenant: {1})" -f $pre.Mg.Account, $pre.Mg.TenantId)
Write-Host ""

# ----- Build listener -----
$listener = New-Object System.Net.HttpListener
$prefix   = "http://localhost:$Port/"
$listener.Prefixes.Add($prefix)

try {
    $listener.Start()
} catch {
    _Err "Failed to start HttpListener on $prefix"
    _Err $_.Exception.Message
    Write-Host ""
    _Warn "If this is 'Access is denied', either pick a different -Port, or run once as admin:"
    _Warn "  netsh http add urlacl url=$prefix user=`"$env:USERDOMAIN\$env:USERNAME`""
    return
}

_Ok "listening on $prefix"
Write-Host ""

if (-not $NoBrowser) {
    try { Start-Process $prefix | Out-Null; _Info "browser launched" }
    catch { _Warn "could not auto-launch browser: $($_.Exception.Message)" }
}

# ----- Graceful Ctrl+C handling -----
# HttpListener.GetContext() is a synchronous blocking call -- Ctrl+C in pwsh
# can NOT interrupt it because the wait happens in the kernel HTTP.sys driver.
# The operator was forced to close the pwsh window (or kill the PID from
# another shell) to stop the listener, which left orphaned URL prefixes in
# HTTP.sys until the kernel released them.
#
# Fix: register a Console.CancelKeyPress handler that flips a flag + calls
# $listener.Stop(). The Stop() unblocks any pending GetContext() with an
# HttpListenerException, our outer try/catch sees the flag, and the loop
# exits cleanly. URL prefix gets released immediately.
$script:_stopRequested = $false
try {
    [Console]::TreatControlCAsInput = $false
    $cancelHandler = [System.ConsoleCancelEventHandler] {
        param($sender, $e)
        $e.Cancel = $true   # don't terminate the process; let our loop unwind cleanly
        $script:_stopRequested = $true
        Write-Host ""
        Write-Host "  Ctrl+C received -- stopping listener gracefully..." -ForegroundColor Yellow
        try { $listener.Stop() } catch {}
    }
    [Console]::add_CancelKeyPress($cancelHandler)
} catch {
    _Warn "Could not register Ctrl+C handler -- you'll have to kill the process to stop. ($($_.Exception.Message))"
}

Write-Host ""
Write-Host "  >>> press Ctrl+C to stop <<<" -ForegroundColor Magenta
Write-Host ""

$mime = @{
    '.html' = 'text/html; charset=utf-8'
    '.htm'  = 'text/html; charset=utf-8'
    '.js'   = 'application/javascript; charset=utf-8'
    '.css'  = 'text/css; charset=utf-8'
    '.json' = 'application/json; charset=utf-8'
    '.png'  = 'image/png'
    '.svg'  = 'image/svg+xml'
    '.ico'  = 'image/x-icon'
}

# ONLY THIS WIZARD'S OWN PAGE MAY CALL /api/*. /api/apply creates an app registration, grants it
# permissions and writes a config the scheduled engines run -- and it accepted ANY POST. Any web page
# open in the operator's browser could send a text/plain "simple request" (no CORS preflight) to
# localhost and drive it with state of its choosing; a DNS-rebinding page could also read /api/state.
# Returns $null when allowed, else the reason. Pure, so it is tested directly.
function Test-SIWizardRequestAllowed {
    param([string]$HostHeader, [string]$Origin, [string]$Method, [string]$ContentType, [int]$Port)
    $self = @(("localhost:{0}" -f $Port), ("127.0.0.1:{0}" -f $Port))
    if ($self -notcontains ([string]$HostHeader).Trim().ToLowerInvariant()) {
        return ("host '{0}' is not this wizard" -f $HostHeader)
    }
    if (-not [string]::IsNullOrWhiteSpace($Origin)) {
        $selfOrigins = @($self | ForEach-Object { 'http://' + $_ })
        if ($selfOrigins -notcontains $Origin.Trim().TrimEnd('/').ToLowerInvariant()) {
            return ("cross-origin request refused (origin '{0}')" -f $Origin)
        }
    }
    if ($Method -ne 'GET' -and $Method -ne 'HEAD') {
        # A cross-origin page can only send application/json after a CORS preflight, and this
        # listener never grants one.
        if ([string]$ContentType -notmatch '^\s*application/json\s*(;|$)') {
            return 'requests that change anything must be application/json'
        }
    }
    return $null
}

function Send-Bytes {
    param($Response, [byte[]]$Bytes, [string]$ContentType, [int]$Status = 200)
    $Response.StatusCode    = $Status
    $Response.ContentType   = $ContentType
    $Response.ContentLength64 = $Bytes.Length
    $Response.OutputStream.Write($Bytes, 0, $Bytes.Length)
    $Response.OutputStream.Close()
}
function Send-Text {
    param($Response, [string]$Text, [string]$ContentType = 'text/plain; charset=utf-8', [int]$Status = 200)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    Send-Bytes -Response $Response -Bytes $bytes -ContentType $ContentType -Status $Status
}
function Send-Json {
    param($Response, $Object, [int]$Status = 200)
    $json = $Object | ConvertTo-Json -Depth 30 -Compress
    Send-Text -Response $Response -Text $json -ContentType 'application/json; charset=utf-8' -Status $Status
}

try {
    while ($listener.IsListening -and -not $script:_stopRequested) {
        $ctx = $null
        try { $ctx = $listener.GetContext() } catch {
            # GetContext throws HttpListenerException when Stop() is called from
            # the Ctrl+C handler -- expected, exit cleanly.
            break
        }
        if ($script:_stopRequested) { break }

        $req = $ctx.Request
        $res = $ctx.Response
        $url = $req.Url.AbsolutePath
        Write-Host ("  [{0}] {1,-4} {2}" -f (Get-Date -Format 'HH:mm:ss'), $req.HttpMethod, $url) -ForegroundColor DarkGray

        try {
            if ($url -like '/api/*') {
                $refusal = Test-SIWizardRequestAllowed -HostHeader $req.Headers['Host'] -Origin $req.Headers['Origin'] `
                             -Method $req.HttpMethod -ContentType $req.ContentType -Port $Port
                if ($refusal) {
                    _Warn ("refused {0} {1}: {2}" -f $req.HttpMethod, $url, $refusal)
                    Send-Json -Response $res -Object @{ error = $refusal } -Status 403
                    continue
                }
            }
            switch -Regex ($url) {
                '^/$|^/index\.html$' {
                    $bytes = [System.IO.File]::ReadAllBytes($indexHtml)
                    Send-Bytes -Response $res -Bytes $bytes -ContentType $mime['.html']
                    break
                }
                '^/api/state$' {
                    # Surface the wizard's own Azure + Graph sign-in so the
                    # wizard JS can auto-prefill blank tenantId / subscriptionId
                    # fields. Avoids "I just authenticated -- why am I retyping
                    # what I authenticated WITH?" friction. Pre-flight has already
                    # required both contexts to be loaded, so they're guaranteed
                    # present here.
                    $azCtx = Get-SISetupAzureContext
                    $mgCtx = if ($azCtx) { Get-SIGraphContext } else { $null }
                    Send-Json -Response $res -Object @{
                        wizardVersion  = $siVersion
                        mode           = 'Setup'
                        applyAvailable = $true
                        cmdlets        = @{
                            NewSISpn          = (Test-Path -LiteralPath $cmdletNewSISpn)
                            InitializeSIInfra = (Test-Path -LiteralPath $cmdletInitInfra)
                            WriteSICustomCfg  = (Test-Path -LiteralPath $cmdletWriteConfig)
                        }
                        operatorContext = @{
                            tenantId       = if ($azCtx) { $azCtx.Tenant.Id } else { $null }
                            subscriptionId = if ($azCtx -and $azCtx.Subscription) { $azCtx.Subscription.Id } else { $null }
                            subscriptionName = if ($azCtx -and $azCtx.Subscription) { $azCtx.Subscription.Name } else { $null }
                            azAccount      = if ($azCtx) { $azCtx.Account.Id } else { $null }
                            mgAccount      = if ($mgCtx) { $mgCtx.Account } else { $null }
                            mgScopes       = if ($mgCtx) { @($mgCtx.Scopes) } else { @() }
                        }
                        notes          = 'Apply orchestration LIVE. operatorContext auto-prefills tenant + subscription in the wizard.'
                    }
                    break
                }
                '^/api/validate-name$' {
                    # Stub. Name-availability checks (Storage/Workspace/KV) land in a later tag.
                    Send-Json -Response $res -Object @{
                        ok      = $true
                        stub    = $true
                        message = 'name-availability checks coming in a later tag; for now any name is accepted -- create-time validation will catch collisions.'
                    }
                    break
                }
                '^/api/preflight$' {
                    # Permission probe: distinguishes "authenticated" from "actually
                    # able to do the work". Pass {tenantId, subscriptionId} to scope
                    # the Azure RBAC check; returns { blockers, warnings, roles, ready }.
                    # Wizard JS Apply page can call this before clicking the real Apply
                    # so the operator sees missing roles BEFORE any provisioning starts.
                    $tid = $null; $sid = $null
                    if ($req.HttpMethod -eq 'POST') {
                        try {
                            $bodyReader = New-Object System.IO.StreamReader($req.InputStream, $req.ContentEncoding)
                            $bodyText = $bodyReader.ReadToEnd()
                            $bodyReader.Dispose()
                            if ($bodyText) {
                                $body = $bodyText | ConvertFrom-Json
                                $tid = $body.tenantId
                                $sid = $body.subscriptionId
                            }
                        } catch { }
                    } else {
                        $tid = $req.QueryString['tenantId']
                        $sid = $req.QueryString['subscriptionId']
                    }
                    $report = Test-PreflightPermissions -TenantId $tid -SubscriptionId $sid
                    Send-Json -Response $res -Object @{
                        ok       = $true
                        blockers = $report.Blockers
                        warnings = $report.Warnings
                        roles    = $report.Roles
                        ready    = ($report.Blockers.Count -eq 0)
                    }
                    break
                }
                '^/api/apply$' {
                    if ($req.HttpMethod -ne 'POST') {
                        Send-Json -Response $res -Object @{ error = 'apply requires POST' } -Status 405
                        break
                    }
                    # Read body
                    $reader = New-Object System.IO.StreamReader($req.InputStream, [System.Text.Encoding]::UTF8)
                    $body   = $reader.ReadToEnd()
                    $reader.Close()
                    if ([string]::IsNullOrWhiteSpace($body)) {
                        Send-Json -Response $res -Object @{ error = 'empty body; expected JSON wizard state' } -Status 400
                        break
                    }
                    try { $st = $body | ConvertFrom-Json -ErrorAction Stop }
                    catch {
                        Send-Json -Response $res -Object @{ error = 'invalid JSON: ' + $_.Exception.Message } -Status 400
                        break
                    }

                    Write-Host ''
                    Write-Host '======================  /api/apply  ======================' -ForegroundColor Magenta
                    $applyLog = New-Object System.Collections.Generic.List[string]
                    $phaseStatus = @{ spn = 'pending'; infra = 'pending'; config = 'pending'; entraDiag = 'pending'; container = 'pending' }
                    $spnOut    = $null
                    $infraOut  = $null
                    $cfgOut    = $null
                    $diagOut   = $null
                    $containerOut = $null

                    # Phase 0 -- pre-flight checks. Runs BEFORE any Azure write so that
                    # missing prerequisites fail the whole apply cleanly, with no orphan
                    # SPN / workspace / storage / diag setting left behind. Today's checks:
                    #   - When hostType=azureContainerMI: the wizard's REST sign-in is still there and on the
                    #     target subscription (#521: no az CLI -- Phase 5 builds the image over ARM REST as this
                    #     same sign-in). We refuse to start the apply at all rather than create Phases 1-4 then
                    #     crash on Phase 5.
                    if ($st.hostType -eq 'azureContainerMI') {
                        $applyLog.Add('phase=preflight start (hostType=azureContainerMI: the Azure sign-in on the target subscription)')
                        $azCtxNow = $null
                        try { $azCtxNow = Get-SISetupAzureContext } catch { }
                        if (-not $azCtxNow) {
                            $msg = "The wizard's Azure sign-in is gone. Re-launch the wizard (it signs you in: Azure Cloud Shell automatically, a workstation in the browser), then re-click Setup. (Or change Step 1's engine host to a VM option to skip Phase 5 entirely.)"
                            $applyLog.Add('phase=preflight FAILED: ' + $msg)
                            Send-Json -Response $res -Object @{
                                ok = $false; phase = 'preflight'; error = $msg; log = $applyLog; phaseStatus = $phaseStatus
                            } -Status 500
                            break
                        }
                        $azSub = if ($azCtxNow.Subscription) { [string]$azCtxNow.Subscription.Id } else { '' }
                        $applyLog.Add(('  Azure sign-in       : {0} (sub {1})' -f [string]$azCtxNow.Account.Id, $azSub))
                        $switchFailed = $null
                        if ($azSub -ne [string]$st.subscriptionId) {
                            $applyLog.Add(('  subscription        : was {0}, switching to {1}' -f $azSub, $st.subscriptionId))
                            try { $null = Set-SIAzContext -Subscription ([string]$st.subscriptionId) } catch { $switchFailed = $_.Exception.Message }
                        }
                        if ($switchFailed) {
                            $msg = "The Azure sign-in cannot switch to target subscription $($st.subscriptionId): $switchFailed. Sign in with an account that has access to it (re-launch the wizard with -TenantId $($st.tenantId))."
                            $applyLog.Add('phase=preflight FAILED: ' + $msg)
                            Send-Json -Response $res -Object @{
                                ok = $false; phase = 'preflight'; error = $msg; log = $applyLog; phaseStatus = $phaseStatus
                            } -Status 500
                            break
                        }
                        $applyLog.Add('phase=preflight ok')
                    }

                    # The sign-in (SI-WizardSignIn.ps1). DEFAULT: a managed identity (user-assigned) -- a service principal
                    # by certificate or by secret only when chosen. A server outside Azure cannot have one: certificate
                    # first, then secret.
                    try {
                        $signIn = Resolve-SIWizardSignIn -HostType ([string]$st.hostType) -CredKind ([string]$st.spn.credKind) -ExistingAppId ([string]$st.spn.existingAppId)
                    } catch {
                        $applyLog.Add('phase=spn FAILED: ' + $_.Exception.Message)
                        Send-Json -Response $res -Object @{ ok = $false; phase = 'spn'; error = $_.Exception.Message; log = $applyLog; phaseStatus = $phaseStatus } -Status 500
                        break
                    }
                    $applyLog.Add(('sign-in             : {0} -- {1}' -f $signIn.CredKind, $signIn.Note))
                    $miName = $null
                    if ($signIn.Identity -eq 'user-assigned') {
                        $miName = Get-SIWizardIdentityName -Name ([string]$st.spn.managedIdentityName) -ResourceGroupName ([string]$st.infra.resourceGroupName)
                    }

                    # Phase 1 -- SPN. A managed identity has no app registration: the container setup creates and grants
                    # the jobs' identity (phase 5); on a VM the identity is created with the resource group (phase 2) and
                    # granted right after it (phase 1b).
                    if ($signIn.CredKind -eq 'ManagedIdentity') {
                        $spnOut = New-SIWizardManagedIdentityResult -TenantId ([string]$st.tenantId) -Name ([string]$miName)
                        $phaseStatus.spn = 'ok'
                        $applyLog.Add($(if ($signIn.Identity -eq 'container-jobs') { 'phase=spn ok (managed identity: created and granted by the container setup)' } else { ('phase=spn deferred (managed identity {0}: created with the resource group, then granted)' -f $miName) }))
                    } else {
                    try {
                        $applyLog.Add('phase=spn start')
                        $spnArgs = @{
                            DisplayName    = $st.spn.displayName
                            TenantId       = $st.tenantId
                            SubscriptionId = $st.subscriptionId
                            CredKind       = $signIn.CredKind
                            CredStorage    = if ($st.spn.credStorage) { $st.spn.credStorage } elseif ($signIn.CredKind -eq 'Cert') { 'LocalCertStore' } else { 'Inline' }
                        }
                        if ($st.spn.keyVaultName)   { $spnArgs.KeyVaultName    = $st.spn.keyVaultName }
                        if ($st.spn.kvSecretName)   { $spnArgs.KvSecretName    = $st.spn.kvSecretName }
                        if ($st.spn.kvCertName)     { $spnArgs.KvCertName      = $st.spn.kvCertName }
                        if ($st.spn.rootMgId)       { $spnArgs.RootMgId        = $st.spn.rootMgId }
                        if ($st.spn.msiClientId)    { $spnArgs.ManagedIdentityClientId = $st.spn.msiClientId }
                        if ($st.spn.skipTenantRbac) { $spnArgs.SkipTenantRbac  = $true }
                        if ($st.spn.skipAdminConsent) { $spnArgs.SkipAdminConsent = $true }
                        if ($st.spn.includeTagContributor) { $spnArgs.IncludeTagContributor = $true }
                        if ($st.spn.existingAppId) {
                            # Existing SPN: never look up or create by name. The backend re-uses an
                            # existing app with its certificate; an existing app with a Key Vault
                            # secret is not something Apply can wire, so say so instead of guessing.
                            if (-not $st.spn.existingThumbprint) {
                                throw 'Apply supports an existing SPN only with a certificate thumbprint. For an existing SPN with a Key Vault secret, use the generated configuration snippet instead of Apply.'
                            }
                            $spnArgs.Remove('DisplayName'); $spnArgs.Remove('CredStorage')
                            $spnArgs.CredKind           = 'Cert'
                            $spnArgs.UseExistingAppId   = $true
                            $spnArgs.ExistingAppId      = [string]$st.spn.existingAppId
                            $spnArgs.ExistingThumbprint = [string]$st.spn.existingThumbprint
                        }
                        $spnOut = & $cmdletNewSISpn @spnArgs
                        # Soft-failure on consent: SPN was created and the perms requested,
                        # but a Global Admin still has to click the consent URL. Don't fail
                        # the whole apply -- continue with infra + config so the operator
                        # can run the engines as soon as consent is granted (no re-apply
                        # needed). Phase status reflects the partial state.
                        $applyLog.Add(('  app reg created     : {0} ({1})' -f $spnOut.DisplayName, $spnOut.AppId))
                        $applyLog.Add(('  service principal   : {0}' -f $spnOut.ObjectId))
                        $applyLog.Add(('  cred kind / storage : {0} / {1}' -f $spnOut.CredKind, ($spnArgs.CredStorage)))
                        if ($spnOut.ExpiresUtc) { $applyLog.Add(('  cred expires (UTC)  : {0}' -f $spnOut.ExpiresUtc)) }
                        if ($spnOut.GraphPermissionResults) {
                            foreach ($pr in $spnOut.GraphPermissionResults) {
                                $applyLog.Add(('  Graph perm {0,-12} : {1}' -f $pr.Status, $pr.Name))
                            }
                        }
                        if ($spnOut.AzureRbacResults) {
                            foreach ($rr in $spnOut.AzureRbacResults) {
                                $applyLog.Add(('  Azure RBAC {0,-12} : {1} @ {2}' -f $rr.Status, $rr.Name, $rr.Scope))
                            }
                        }
                        if ($spnOut.ConsentStatus -ne 'granted') {
                            $phaseStatus.spn = 'consent-pending'
                            $applyLog.Add(('phase=spn consent-pending  pending={0} consentUrl={1}' -f ($spnOut.PendingPermissions -join ','), $spnOut.ConsentUrl))
                        } else {
                            $phaseStatus.spn = 'ok'
                            $applyLog.Add('phase=spn ok')
                        }
                    } catch {
                        $phaseStatus.spn = 'failed'
                        $applyLog.Add('phase=spn FAILED: ' + $_.Exception.Message)
                        Send-Json -Response $res -Object @{
                            ok = $false; phase = 'spn'; error = $_.Exception.Message; log = $applyLog; phaseStatus = $phaseStatus
                        } -Status 500
                        break
                    }
                    }

                    # Phase 2 -- Infrastructure (LA + DCE + Storage + RBAC)
                    try {
                        $applyLog.Add('phase=infra start')
                        $infraArgs = @{
                            SpnObjectId         = [string]$spnOut.ObjectId
                            TenantId            = $st.tenantId
                            SubscriptionId      = $st.subscriptionId
                            ResourceGroupName   = $st.infra.resourceGroupName
                            Location            = $st.infra.location
                            WorkspaceName       = $st.infra.workspaceName
                            DceName             = $st.infra.dceName
                            StorageAccountName  = $st.infra.storageAccountName
                            # the 'hosting' tag of a resource group setup creates; the edition comes from the licence
                            Hosting             = $(if ($st.hostType -eq 'azureContainerMI') { 'ca' } else { 'vm' })
                        }
                        # The wizard page sends dceResourceGroup / storageResourceGroup; this read only the
                        # *Name spellings, so both RG fields the operator filled in were silently dropped.
                        $dcrRg = if ($st.infra.dcrResourceGroupName) { $st.infra.dcrResourceGroupName } else { $st.infra.dceResourceGroup }
                        $stgRg = if ($st.infra.storageResourceGroupName) { $st.infra.storageResourceGroupName } else { $st.infra.storageResourceGroup }
                        if ($dcrRg) { $infraArgs.DcrResourceGroupName     = $dcrRg }
                        if ($stgRg) { $infraArgs.StorageResourceGroupName = $stgRg }
                        if ($st.infra.createKeyVault)           { $infraArgs.CreateKeyVault           = $true }
                        if ($st.infra.keyVaultName)             { $infraArgs.KeyVaultName             = $st.infra.keyVaultName }
                        if ($miName)                            { $infraArgs.ManagedIdentityName      = $miName }
                        $applyLog.Add(('  resource group      : {0}' -f $st.infra.resourceGroupName))
                        $applyLog.Add(('  region              : {0}' -f $st.infra.location))
                        $applyLog.Add(('  workspace           : {0}' -f $st.infra.workspaceName))
                        $applyLog.Add(('  DCE                 : {0}' -f $st.infra.dceName))
                        $applyLog.Add(('  storage account     : {0} (container={1})' -f $st.infra.storageAccountName, $st.infra.storageContainer))
                        $infraOut = & $cmdletInitInfra @infraArgs
                        if ($infraOut.WorkspaceResourceId) { $applyLog.Add(('  workspace ResourceId: {0}' -f $infraOut.WorkspaceResourceId)) }
                        if ($infraOut.DceResourceId)       { $applyLog.Add(('  DCE ResourceId      : {0}' -f $infraOut.DceResourceId)) }
                        if ($infraOut.StorageResourceId)   { $applyLog.Add(('  storage ResourceId  : {0}' -f $infraOut.StorageResourceId)) }
                        if ($infraOut.RbacScopes) {
                            foreach ($sc in $infraOut.RbacScopes) { $applyLog.Add(('  RBAC granted        : {0}' -f $sc)) }
                        }
                        $phaseStatus.infra = 'ok'
                        $applyLog.Add('phase=infra ok')
                    } catch {
                        $phaseStatus.infra = 'failed'
                        $applyLog.Add('phase=infra FAILED: ' + $_.Exception.Message)
                        Send-Json -Response $res -Object @{
                            ok = $false; phase = 'infra'; error = $_.Exception.Message;
                            spn = $spnOut; log = $applyLog; phaseStatus = $phaseStatus
                        } -Status 500
                        break
                    }

                    # Phase 1b -- the VM's user-assigned managed identity: grant it (the same read-only Graph, Defender and
                    # Azure permissions New-SISpn grants a service principal) and attach it to the VM when it is named.
                    if ($signIn.Identity -eq 'user-assigned') {
                        try {
                            $applyLog.Add('phase=spn start (managed identity grants)')
                            if (-not $infraOut -or -not $infraOut.ManagedIdentityClientId) { throw ('The managed identity {0} was not created.' -f $miName) }
                            $spnArgs = @{
                                TenantId = $st.tenantId; SubscriptionId = $st.subscriptionId; CredKind = 'ManagedIdentity'
                                ManagedIdentityClientId = [string]$infraOut.ManagedIdentityClientId; DisplayName = $miName
                            }
                            if ($st.spn.rootMgId)       { $spnArgs.RootMgId = $st.spn.rootMgId }
                            if ($st.spn.skipTenantRbac) { $spnArgs.SkipTenantRbac = $true }
                            if ($st.spn.skipAdminConsent) { $spnArgs.SkipAdminConsent = $true }
                            $grantOut = & $cmdletNewSISpn @spnArgs
                            $spnOut = New-SIWizardManagedIdentityResult -TenantId ([string]$st.tenantId) -ClientId ([string]$infraOut.ManagedIdentityClientId) `
                                          -PrincipalId ([string]$infraOut.ManagedIdentityPrincipalId) -Name $miName -ResourceId ([string]$infraOut.ManagedIdentityResourceId)
                            foreach ($p in 'GraphPermissionResults', 'PendingPermissions', 'ConsentStatus', 'ConsentUrl', 'AzureRbacScopes', 'AzureRbacResults') {
                                if ($grantOut -and $grantOut.PSObject.Properties[$p]) { $spnOut.$p = $grantOut.$p }
                            }
                            $applyLog.Add(('  managed identity    : {0} (client id {1})' -f $miName, $infraOut.ManagedIdentityClientId))
                            foreach ($pr in @($spnOut.GraphPermissionResults)) { if ($pr) { $applyLog.Add(('  Graph perm {0,-12} : {1}' -f $pr.Status, $pr.Name)) } }
                            if ($st.spn.vmName) {
                                $vmRg = if ($st.spn.vmResourceGroup) { [string]$st.spn.vmResourceGroup } else { [string]$st.infra.resourceGroupName }
                                $changed = Add-SIVmUserAssignedIdentity -ResourceGroupName $vmRg -VmName ([string]$st.spn.vmName) -IdentityResourceId ([string]$infraOut.ManagedIdentityResourceId) -SubscriptionId $st.subscriptionId
                                $applyLog.Add(('  attached to VM      : {0}/{1}{2}' -f $vmRg, $st.spn.vmName, $(if ($changed) { '' } else { ' (already attached)' })))
                            } else {
                                $applyLog.Add(('  attach it to the server that runs SecurityInsight: Azure portal > the VM > Identity > User assigned > Add > {0}' -f $miName))
                                $applyLog.Add('  (an Azure Arc server uses its own system-assigned identity instead: setup\Grant-SIIdentity.ps1 -ArcMachineName <name> -ArcResourceGroup <rg> -Apply)')
                            }
                            if ($spnOut.ConsentStatus -and $spnOut.ConsentStatus -ne 'granted') {
                                $phaseStatus.spn = 'consent-pending'
                                $applyLog.Add(('phase=spn consent-pending  pending={0}' -f (@($spnOut.PendingPermissions) -join ',')))
                            } else { $phaseStatus.spn = 'ok'; $applyLog.Add('phase=spn ok') }
                        } catch {
                            $phaseStatus.spn = 'failed'
                            $applyLog.Add('phase=spn FAILED: ' + $_.Exception.Message)
                            Send-Json -Response $res -Object @{ ok = $false; phase = 'spn'; error = $_.Exception.Message; infra = $infraOut; log = $applyLog; phaseStatus = $phaseStatus } -Status 500
                            break
                        }
                    }

                    # Phase 3 -- Write custom config
                    try {
                        $applyLog.Add('phase=config start')
                        $cfgArgs = @{ Spn = $spnOut; Infra = $infraOut }
                        if ($st.smtp)     { $cfgArgs.Smtp     = (ConvertTo-HashtableFromPso $st.smtp) }
                        if ($st.openAi)   { $cfgArgs.OpenAi   = (ConvertTo-HashtableFromPso $st.openAi) }
                        if ($st.shodan)   { $cfgArgs.Shodan   = (ConvertTo-HashtableFromPso $st.shodan) }
                        if ($st.cmdb)     { $cfgArgs.Cmdb     = (ConvertTo-HashtableFromPso $st.cmdb) }
                        if ($st.enableJsonSink) { $cfgArgs.EnableJsonSink = $true }
                        if ($st.defenderWorkspaceResourceId) { $cfgArgs.DefenderWorkspaceResourceId = $st.defenderWorkspaceResourceId }
                        # #176: an existing config is UPGRADED (every value kept, missing settings added) -- it
                        # used to throw "Refusing to overwrite" here, AFTER the SPN and infrastructure phases ran.
                        $cfgArgs.Merge = $true
                        $cfgOut = & $cmdletWriteConfig @cfgArgs
                        $applyLog.Add(('  config path         : {0}' -f $cfgOut.Path))
                        $applyLog.Add(('  config size         : {0} bytes' -f $cfgOut.Bytes))
                        if ($cfgOut.PSObject.Properties['Merged'] -and $cfgOut.Merged) {
                            $applyLog.Add(('  existing config kept: {0} setting(s) added{1}' -f @($cfgOut.Added).Count, $(if (@($cfgOut.Added).Count) { ' -- ' + (@($cfgOut.Added) -join ', ') } else { '' })))
                        }
                        if ($cfgOut.Sections) { $applyLog.Add(('  sections written    : {0}' -f ($cfgOut.Sections -join ', '))) }
                        $phaseStatus.config = 'ok'
                        $applyLog.Add('phase=config ok')
                    } catch {
                        $phaseStatus.config = 'failed'
                        $applyLog.Add('phase=config FAILED: ' + $_.Exception.Message)
                        Send-Json -Response $res -Object @{
                            ok = $false; phase = 'config'; error = $_.Exception.Message;
                            spn = $spnOut; infra = $infraOut; log = $applyLog; phaseStatus = $phaseStatus
                        } -Status 500
                        break
                    }

                    # Phase 4 -- Entra ID Diagnostic Setting (optional, gated on wizard toggle).
                    # Skipped when the operator linked an existing Defender / Sentinel workspace,
                    # since their existing Diagnostic Setting already streams the same categories.
                    if ($st.entraDiagnosticSetting -and $st.entraDiagnosticSetting.Enabled) {
                        try {
                            $applyLog.Add('phase=entraDiag start')
                            $diagArgs = @{ WorkspaceResourceId = $infraOut.WorkspaceResourceId }
                            if ($st.entraDiagnosticSetting.Name)       { $diagArgs.Name       = $st.entraDiagnosticSetting.Name }
                            if ($st.entraDiagnosticSetting.Categories) { $diagArgs.Categories = @($st.entraDiagnosticSetting.Categories) }
                            $diagOut = & $cmdletEntraDiag @diagArgs
                            $applyLog.Add(('  diag setting name : {0}' -f $diagOut.Name))
                            $applyLog.Add(('  workspace target  : {0}' -f $diagOut.WorkspaceResourceId))
                            $applyLog.Add(('  categories        : {0}' -f ($diagOut.Categories -join ', ')))
                            $phaseStatus.entraDiag = 'ok'
                            $applyLog.Add('phase=entraDiag ok')
                        } catch {
                            $phaseStatus.entraDiag = 'failed'
                            $applyLog.Add('phase=entraDiag FAILED: ' + $_.Exception.Message)
                            Send-Json -Response $res -Object @{
                                ok = $false; phase = 'entraDiag'; error = $_.Exception.Message;
                                spn = $spnOut; infra = $infraOut; configFile = $cfgOut;
                                log = $applyLog; phaseStatus = $phaseStatus
                            } -Status 500
                            break
                        }
                    } else {
                        $phaseStatus.entraDiag = 'skipped'
                        $applyLog.Add('phase=entraDiag skipped (toggle off or Defender workspace linked)')
                    }

                    # Phase 5 -- Container Apps Job runtime (optional, gated on engine-host choice).
                    # Only fires when the operator picked 'azureContainerMI' on Step 1's engine-host
                    # dropdown. VM hosts skip Phase 5 entirely (no need for ACR / CAE / Jobs when
                    # the engines run as Windows Scheduled Tasks).
                    if ($st.hostType -eq 'azureContainerMI') {
                        try {
                            $applyLog.Add('phase=container start')
                            $containerArgs = @{
                                ResourceGroupName = $st.infra.resourceGroupName
                                Location          = $st.infra.location
                                SubscriptionId    = $st.subscriptionId
                            }
                            if ($st.container) {
                                if ($st.container.AcrName)         { $containerArgs.AcrName         = $st.container.AcrName }
                                if ($st.container.EnvName)         { $containerArgs.EnvName         = $st.container.EnvName }
                                if ($null -ne $st.container.UseKEDA) { $containerArgs.UseKEDA       = [bool]$st.container.UseKEDA }
                                if ($st.container.KedaMaxReplicas) { $containerArgs.KedaMaxReplicas = [int]$st.container.KedaMaxReplicas }
                            }
                            # The jobs' managed identity is the install's sign-in: the container setup grants it here.
                            if ($signIn.Identity -eq 'container-jobs') { $containerArgs.GrantIdentityRoles = $true }
                            $containerOut = & $cmdletContainer @containerArgs
                            if ($containerOut.AcrLoginServer) { $applyLog.Add(('  ACR login server   : {0}' -f $containerOut.AcrLoginServer)) }
                            if ($containerOut.EnvResourceId)  { $applyLog.Add(('  CAE ResourceId     : {0}' -f $containerOut.EnvResourceId)) }
                            $applyLog.Add(('  KEDA               : {0} (max replicas {1})' -f $containerOut.UseKEDA, $containerOut.KedaMaxReplicas))
                            if ($containerOut.Jobs) {
                                foreach ($j in $containerOut.Jobs) {
                                    $applyLog.Add(('  Job created        : {0}  (engine={1}, cron={2})' -f $j.Name, $j.Engine, $j.Cron))
                                }
                            }
                            $phaseStatus.container = 'ok'
                            $applyLog.Add('phase=container ok')
                        } catch {
                            $phaseStatus.container = 'failed'
                            $applyLog.Add('phase=container FAILED: ' + $_.Exception.Message)
                            Send-Json -Response $res -Object @{
                                ok = $false; phase = 'container'; error = $_.Exception.Message;
                                spn = $spnOut; infra = $infraOut; configFile = $cfgOut; entraDiag = $diagOut;
                                log = $applyLog; phaseStatus = $phaseStatus
                            } -Status 500
                            break
                        }
                    } else {
                        $phaseStatus.container = 'skipped'
                        $applyLog.Add(('phase=container skipped (hostType={0} -- container infra only built for azureContainerMI)' -f $st.hostType))
                    }

                    Write-Host '======================  /api/apply DONE  ======================' -ForegroundColor Magenta
                    Send-Json -Response $res -Object @{
                        ok           = $true
                        phaseStatus  = $phaseStatus
                        spn          = $spnOut
                        infra        = $infraOut
                        configFile   = $cfgOut
                        entraDiag    = $diagOut
                        container    = $containerOut
                        log          = $applyLog
                    }
                    break
                }
                '^/api/log-stream$' {
                    # Stub SSE -- streaming lands in v2.2.108 with the HTML Apply page.
                    Send-Text -Response $res -Text 'log streaming lands in v2.2.108 with the HTML Apply page' -Status 501
                    break
                }
                default {
                    # static asset under setup/ConfigWizard/
                    $rel = ($url -replace '^/+','')
                    $path = Join-Path $scriptDir $rel
                    $resolved = $null
                    try { $resolved = (Resolve-Path -LiteralPath $path -ErrorAction Stop).Path } catch { }
                    if (-not $resolved -or -not $resolved.StartsWith($scriptDir, [System.StringComparison]::OrdinalIgnoreCase)) {
                        Send-Text -Response $res -Text "404 Not Found" -Status 404
                        break
                    }
                    $ext = [System.IO.Path]::GetExtension($resolved).ToLower()
                    $ct  = if ($mime.ContainsKey($ext)) { $mime[$ext] } else { 'application/octet-stream' }
                    $bytes = [System.IO.File]::ReadAllBytes($resolved)
                    Send-Bytes -Response $res -Bytes $bytes -ContentType $ct
                }
            }
        } catch {
            try { Send-Text -Response $res -Text ('server error: ' + $_.Exception.Message) -Status 500 } catch { }
            _Err "request failed: $($_.Exception.Message)"
        }
    }
}
finally {
    # De-register the Ctrl+C handler so subsequent commands in the same shell
    # respond to Ctrl+C normally (default = terminate).
    if ($cancelHandler) {
        try { [Console]::remove_CancelKeyPress($cancelHandler) } catch { }
    }
    try { $listener.Stop();  } catch { }
    try { $listener.Close(); } catch { }
    Write-Host ""
    _Ok ("wizard stopped -- port {0} released" -f $Port)
    Write-Host ""
}
} finally { Stop-SIScriptRun -Run $siRun }
