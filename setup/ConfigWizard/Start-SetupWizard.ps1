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
    [switch]$NoBrowser
)

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
foreach ($c in $cmdletNewSISpn, $cmdletInitInfra, $cmdletWriteConfig, $cmdletEntraDiag) {
    if (-not (Test-Path -LiteralPath $c)) { throw "backend cmdlet missing: $c" }
}
_Info ("port        : {0}" -f $Port)
_Info ("wizard html : {0}" -f $indexHtml)
_Info  "backend     : New-SISpn / Initialize-SIInfra / Write-SICustomConfig / Set-SIEntraDiagnosticSetting"
Write-Host ""

# ----- Pre-flight: require Az + Microsoft Graph contexts -----
# /api/apply needs both. Fail fast (don't accept POSTs against an unauthed
# listener) -- the operator has to run Connect-AzAccount + Connect-MgGraph
# in THIS shell before launching the wizard, so the contexts are inherited
# by this process and reused for every apply call.
function Test-PreflightAuth {
    $azCtx = $null; $mgCtx = $null
    try { $azCtx = Get-AzContext -ErrorAction Stop } catch { }
    try { $mgCtx = Get-MgContext -ErrorAction Stop } catch { }
    return @{ Az = $azCtx; Mg = $mgCtx }
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
    $azCtx = Get-AzContext -ErrorAction SilentlyContinue
    $mgCtx = Get-MgContext -ErrorAction SilentlyContinue

    # 1. Microsoft Graph: required scopes present?
    # NOTE: DelegatedPermissionGrant.ReadWrite.All is NOT in this list. The
    # wizard only does application-only role assignments which need
    # AppRoleAssignment.ReadWrite.All; older docs listed the delegated scope
    # but it's unnecessary and triggers AADSTS650053 in some tenants.
    if ($mgCtx) {
        $reqScopes = @('Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.ReadWrite.All')
        $roles.Graph = @($mgCtx.Scopes | Where-Object { $reqScopes -contains $_ })
        $missing = @($reqScopes | Where-Object { $mgCtx.Scopes -notcontains $_ })
        if ($missing.Count -gt 0) {
            $blockers += ("Graph context is missing scopes: {0}. Reconnect with: Connect-MgGraph -TenantId {1} -Scopes {2}" -f ($missing -join ','), $TenantId, ($reqScopes -join ','))
        }
    }

    # 2. Entra directory roles -- best-effort (only meaningful when operator is
    # a user, not a SPN). Surface as a WARNING (not blocker) since admin consent
    # can be handed off to another admin via the consent URL.
    if ($mgCtx -and $mgCtx.Account -and $mgCtx.Account -notmatch '^[0-9a-f-]{36}$') {
        try {
            $me = Get-MgUser -Filter ("userPrincipalName eq '{0}'" -f $mgCtx.Account) -ErrorAction Stop
            if ($me) {
                $myRoles = @(Get-MgUserMemberOf -UserId $me.Id -All -ErrorAction Stop |
                    Where-Object { $_.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.directoryRole' })
                $roleNames = @($myRoles | ForEach-Object { $_.AdditionalProperties['displayName'] })
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
    # will fail with 403 on the first New-AzResourceGroup. BLOCKER.
    if ($azCtx -and $SubscriptionId) {
        try {
            if ($azCtx.Subscription.Id -ne $SubscriptionId) {
                Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
            }
            $signIn   = $azCtx.Account.Id
            $subScope = "/subscriptions/$SubscriptionId"
            # SPN auth -> Account.Id is the AppId GUID; user auth -> UPN. Look up
            # role assignments by the appropriate property.
            $isSpn = ($signIn -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
            if ($isSpn) {
                # ApplicationId param requires the SPN's ObjectId (the SP, not the app reg).
                $sp = Get-AzADServicePrincipal -ApplicationId $signIn -ErrorAction SilentlyContinue
                if ($sp) {
                    $azRoles = @(Get-AzRoleAssignment -ObjectId $sp.Id -Scope $subScope -ErrorAction SilentlyContinue)
                    if (-not $azRoles -or $azRoles.Count -eq 0) {
                        $azRoles = @(Get-AzRoleAssignment -ObjectId $sp.Id -ErrorAction SilentlyContinue |
                                     Where-Object { $subScope -like "$($_.Scope)*" -or $_.Scope -eq '/' -or $_.Scope -like '/providers/Microsoft.Management/managementGroups/*' })
                    }
                } else { $azRoles = @() }
            } else {
                $azRoles = @(Get-AzRoleAssignment -SignInName $signIn -Scope $subScope -ErrorAction SilentlyContinue)
                if (-not $azRoles -or $azRoles.Count -eq 0) {
                    $azRoles = @(Get-AzRoleAssignment -SignInName $signIn -ErrorAction SilentlyContinue |
                                 Where-Object { $subScope -like "$($_.Scope)*" -or $_.Scope -eq '/' -or $_.Scope -like '/providers/Microsoft.Management/managementGroups/*' })
                }
            }
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
$pre = Test-PreflightAuth
if (-not $pre.Az -or -not $pre.Mg) {
    Write-Host ""
    Write-Host "  [BLOCKED]" -ForegroundColor Red -NoNewline; Write-Host " /api/apply needs both Az PowerShell and Microsoft Graph contexts."
    Write-Host ""
    if (-not $pre.Az) { Write-Host "    Az PowerShell : NOT CONNECTED" -ForegroundColor Yellow }
    else              { Write-Host ("    Az PowerShell : {0} (sub: {1})" -f $pre.Az.Account.Id, $pre.Az.Subscription.Name) -ForegroundColor Green }
    if (-not $pre.Mg) { Write-Host "    Microsoft Graph: NOT CONNECTED" -ForegroundColor Yellow }
    else              { Write-Host ("    Microsoft Graph: {0} (tenant: {1})" -f $pre.Mg.Account, $pre.Mg.TenantId) -ForegroundColor Green }
    Write-Host ""
    Write-Host "  Run these in THIS shell, then re-launch the wizard:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    Connect-AzAccount -Tenant <tenant-id>" -ForegroundColor White
    Write-Host "    Connect-MgGraph -TenantId <tenant-id> -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.ReadWrite.All' -NoWelcome" -ForegroundColor White
    Write-Host "    .\Start-SetupWizard.ps1" -ForegroundColor White
    Write-Host ""
    Write-Host "  (The wizard process inherits both contexts -- no popups, no device codes, no per-call re-auth.)" -ForegroundColor Gray
    Write-Host ""
    throw "Setup Wizard pre-flight failed: missing Az and/or Microsoft Graph context. See instructions above."
}
_Ok ("Az context     : {0} (sub: {1} / {2})" -f $pre.Az.Account.Id, $pre.Az.Subscription.Name, $pre.Az.Subscription.Id)
_Ok ("Graph context  : {0} (tenant: {1})" -f $pre.Mg.Account, $pre.Mg.TenantId)
Write-Host ""

# ----- Pre-flight: Az/Azure.Identity binary-compat smoke test -----
# Some pwsh shells end up with side-loaded mismatched versions of Az.Accounts
# vs the Azure.Identity / Azure.Identity.Broker assemblies it depends on. The
# symptom is a "Method not found: 'Void Azure.Identity.Broker.SharedToken
# CacheCredentialBrokerOptions..ctor(...)'" exception that BEGINS with the
# misleading message "Your Azure credentials have not been set up or have
# expired" -- even though Get-AzContext returns a valid context. Without
# this smoke test the operator clicks Setup, watches Phase 1 (which only
# uses Microsoft.Graph) succeed, then Phase 2 fails on the FIRST Az PS call.
# Fail fast here with a clear remediation BEFORE accepting Setup clicks.
_Info "verify Az PowerShell binary-compat (Get-AzAccessToken smoke test)"
try {
    $null = Get-AzAccessToken -ResourceUrl 'https://management.azure.com/' -ErrorAction Stop
    _Ok "Az PowerShell smoke test passed -- assemblies are binary-compatible"
} catch {
    $msg = $_.Exception.Message
    $isAssemblyMismatch = (
        $msg -match 'Method not found' -or
        $msg -match 'Azure\.Identity' -or
        $msg -match 'SharedTokenCache' -or
        $msg -match 'credentials have not been set up'
    )
    Write-Host ""
    if ($isAssemblyMismatch) {
        Write-Host "  [BLOCKED]" -ForegroundColor Red -NoNewline; Write-Host " Az PowerShell assemblies in this pwsh process are binary-incompatible."
        Write-Host ""
        Write-Host "    Symptom : $msg" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  This is a known side-loaded-assembly version mismatch between Az.Accounts and the" -ForegroundColor Cyan
        Write-Host "  Azure.Identity.Broker extension. The wizard's /api/apply would fail mid-Phase-2"  -ForegroundColor Cyan
        Write-Host "  on the first Az PowerShell call. Fix in your interactive shell (NOT this one):" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "    Update-Module Az -Force" -ForegroundColor White
        Write-Host "    # Then close THIS pwsh window entirely (the broken assemblies live in-process)" -ForegroundColor Gray
        Write-Host "    # Open a fresh pwsh, re-run Connect-AzAccount + Connect-MgGraph, re-launch the wizard." -ForegroundColor Gray
        Write-Host ""
        throw "Setup Wizard pre-flight failed: Az PowerShell binary-compat issue. See instructions above."
    } else {
        Write-Host "  [BLOCKED]" -ForegroundColor Red -NoNewline; Write-Host " Get-AzAccessToken failed: $msg"
        Write-Host ""
        Write-Host "  Re-run Connect-AzAccount in your interactive shell and re-launch the wizard." -ForegroundColor Cyan
        Write-Host ""
        throw "Setup Wizard pre-flight failed: Az token check threw. See instructions above."
    }
}
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
            switch -Regex ($url) {
                '^/$|^/index\.html$' {
                    $bytes = [System.IO.File]::ReadAllBytes($indexHtml)
                    Send-Bytes -Response $res -Bytes $bytes -ContentType $mime['.html']
                    break
                }
                '^/api/state$' {
                    # Surface the operator's connected Az + Graph contexts so the
                    # wizard JS can auto-prefill blank tenantId / subscriptionId
                    # fields. Avoids "I just authenticated -- why am I retyping
                    # what I authenticated WITH?" friction. Pre-flight has already
                    # required both contexts to be loaded, so they're guaranteed
                    # present here.
                    $azCtx = Get-AzContext -ErrorAction SilentlyContinue
                    $mgCtx = Get-MgContext -ErrorAction SilentlyContinue
                    Send-Json -Response $res -Object @{
                        wizardVersion  = $siVersion
                        applyAvailable = $true
                        cmdlets        = @{
                            NewSISpn          = (Test-Path -LiteralPath $cmdletNewSISpn)
                            InitializeSIInfra = (Test-Path -LiteralPath $cmdletInitInfra)
                            WriteSICustomCfg  = (Test-Path -LiteralPath $cmdletWriteConfig)
                        }
                        operatorContext = @{
                            tenantId       = if ($azCtx) { $azCtx.Tenant.Id } else { $null }
                            subscriptionId = if ($azCtx) { $azCtx.Subscription.Id } else { $null }
                            subscriptionName = if ($azCtx) { $azCtx.Subscription.Name } else { $null }
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
                    $phaseStatus = @{ spn = 'pending'; infra = 'pending'; config = 'pending'; entraDiag = 'pending' }
                    $spnOut    = $null
                    $infraOut  = $null
                    $cfgOut    = $null
                    $diagOut   = $null

                    # Phase 1 -- SPN
                    try {
                        $applyLog.Add('phase=spn start')
                        $spnArgs = @{
                            DisplayName    = $st.spn.displayName
                            TenantId       = $st.tenantId
                            SubscriptionId = $st.subscriptionId
                            CredKind       = if ($st.spn.credKind)    { $st.spn.credKind }    else { 'Secret' }
                            CredStorage    = if ($st.spn.credStorage) { $st.spn.credStorage } else { 'Inline' }
                        }
                        if ($st.spn.keyVaultName)   { $spnArgs.KeyVaultName    = $st.spn.keyVaultName }
                        if ($st.spn.kvSecretName)   { $spnArgs.KvSecretName    = $st.spn.kvSecretName }
                        if ($st.spn.kvCertName)     { $spnArgs.KvCertName      = $st.spn.kvCertName }
                        if ($st.spn.rootMgId)       { $spnArgs.RootMgId        = $st.spn.rootMgId }
                        if ($st.spn.msiClientId)    { $spnArgs.ManagedIdentityClientId = $st.spn.msiClientId }
                        if ($st.spn.skipTenantRbac) { $spnArgs.SkipTenantRbac  = $true }
                        if ($st.spn.skipAdminConsent) { $spnArgs.SkipAdminConsent = $true }
                        if ($st.spn.includeTagContributor) { $spnArgs.IncludeTagContributor = $true }
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

                    # Phase 2 -- Infrastructure (LA + DCE + Storage + RBAC)
                    try {
                        $applyLog.Add('phase=infra start')
                        $infraArgs = @{
                            SpnObjectId         = $spnOut.ObjectId
                            TenantId            = $st.tenantId
                            SubscriptionId      = $st.subscriptionId
                            ResourceGroupName   = $st.infra.resourceGroupName
                            Location            = $st.infra.location
                            WorkspaceName       = $st.infra.workspaceName
                            DceName             = $st.infra.dceName
                            StorageAccountName  = $st.infra.storageAccountName
                        }
                        if ($st.infra.dcrResourceGroupName)     { $infraArgs.DcrResourceGroupName     = $st.infra.dcrResourceGroupName }
                        if ($st.infra.storageResourceGroupName) { $infraArgs.StorageResourceGroupName = $st.infra.storageResourceGroupName }
                        if ($st.infra.createKeyVault)           { $infraArgs.CreateKeyVault           = $true }
                        if ($st.infra.keyVaultName)             { $infraArgs.KeyVaultName             = $st.infra.keyVaultName }
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
                        $cfgOut = & $cmdletWriteConfig @cfgArgs
                        $applyLog.Add(('  config path         : {0}' -f $cfgOut.Path))
                        $applyLog.Add(('  config size         : {0} bytes' -f $cfgOut.Bytes))
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

                    Write-Host '======================  /api/apply DONE  ======================' -ForegroundColor Magenta
                    Send-Json -Response $res -Object @{
                        ok           = $true
                        phaseStatus  = $phaseStatus
                        spn          = $spnOut
                        infra        = $infraOut
                        configFile   = $cfgOut
                        entraDiag    = $diagOut
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
