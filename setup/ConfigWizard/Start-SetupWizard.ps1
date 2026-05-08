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
    param([Parameter(Mandatory)] $InputObject)
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

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " SecurityInsight Setup Wizard (localhost, no auth)"                  -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
_Info "wizard html : $indexHtml"
_Info "port        : $Port"
_Info ""
_Ok   "v2.2.105: backend cmdlets + /api/apply orchestration LIVE"
_Info "Apply page calls New-SISpn -> Initialize-SIInfra -> Write-SICustomConfig"
_Info "HTML 'Apply' button hookup lands in v2.2.108 (until then the API is callable directly)"
Write-Host ""

# Path to the backend cmdlets (relative to this script).
$backendDir = Join-Path $scriptDir 'backend'
$cmdletNewSISpn      = Join-Path $backendDir 'New-SISpn.ps1'
$cmdletInitInfra     = Join-Path $backendDir 'Initialize-SIInfra.ps1'
$cmdletWriteConfig   = Join-Path $backendDir 'Write-SICustomConfig.ps1'
foreach ($c in $cmdletNewSISpn, $cmdletInitInfra, $cmdletWriteConfig) {
    if (-not (Test-Path -LiteralPath $c)) { throw "backend cmdlet missing: $c" }
}
_Info "backend cmdlets : New-SISpn / Initialize-SIInfra / Write-SICustomConfig"
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
    while ($listener.IsListening) {
        $ctx = $null
        try { $ctx = $listener.GetContext() } catch { break }

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
                        wizardVersion  = '2.2.114'
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
                    $phaseStatus = @{ spn = 'pending'; infra = 'pending'; config = 'pending' }
                    $spnOut    = $null
                    $infraOut  = $null
                    $cfgOut    = $null

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
                        $spnOut = & $cmdletNewSISpn @spnArgs
                        # Soft-failure on consent: SPN was created and the perms requested,
                        # but a Global Admin still has to click the consent URL. Don't fail
                        # the whole apply -- continue with infra + config so the operator
                        # can run the engines as soon as consent is granted (no re-apply
                        # needed). Phase status reflects the partial state.
                        if ($spnOut.ConsentStatus -ne 'granted') {
                            $phaseStatus.spn = 'consent-pending'
                            $applyLog.Add(('phase=spn consent-pending appId={0} pendingPerms={1} consentUrl={2}' -f $spnOut.AppId, ($spnOut.PendingPermissions -join ','), $spnOut.ConsentUrl))
                        } else {
                            $phaseStatus.spn = 'ok'
                            $applyLog.Add('phase=spn ok appId=' + $spnOut.AppId)
                        }
                    } catch {
                        $phaseStatus.spn = 'failed'
                        $applyLog.Add('phase=spn FAILED: ' + $_.Exception.Message)
                        Send-Json -Response $res -Object @{
                            ok = $false; phase = 'spn'; error = $_.Exception.Message; log = $applyLog
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
                        $infraOut = & $cmdletInitInfra @infraArgs
                        $phaseStatus.infra = 'ok'
                        $applyLog.Add('phase=infra ok workspace=' + $infraOut.WorkspaceResourceId)
                    } catch {
                        $phaseStatus.infra = 'failed'
                        $applyLog.Add('phase=infra FAILED: ' + $_.Exception.Message)
                        Send-Json -Response $res -Object @{
                            ok = $false; phase = 'infra'; error = $_.Exception.Message;
                            spn = $spnOut; log = $applyLog
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
                        $phaseStatus.config = 'ok'
                        $applyLog.Add('phase=config ok path=' + $cfgOut.Path + ' bytes=' + $cfgOut.Bytes)
                    } catch {
                        $phaseStatus.config = 'failed'
                        $applyLog.Add('phase=config FAILED: ' + $_.Exception.Message)
                        Send-Json -Response $res -Object @{
                            ok = $false; phase = 'config'; error = $_.Exception.Message;
                            spn = $spnOut; infra = $infraOut; log = $applyLog
                        } -Status 500
                        break
                    }

                    Write-Host '======================  /api/apply DONE  ======================' -ForegroundColor Magenta
                    Send-Json -Response $res -Object @{
                        ok           = $true
                        phaseStatus  = $phaseStatus
                        spn          = $spnOut
                        infra        = $infraOut
                        configFile   = $cfgOut
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
    try { $listener.Stop();  } catch { }
    try { $listener.Close(); } catch { }
    Write-Host ""
    _Ok "wizard stopped"
}
