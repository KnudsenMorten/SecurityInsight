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
                    Send-Json -Response $res -Object @{
                        wizardVersion  = '2.2.105'
                        applyAvailable = $true
                        cmdlets        = @{
                            NewSISpn          = (Test-Path -LiteralPath $cmdletNewSISpn)
                            InitializeSIInfra = (Test-Path -LiteralPath $cmdletInitInfra)
                            WriteSICustomCfg  = (Test-Path -LiteralPath $cmdletWriteConfig)
                        }
                        notes          = 'Apply orchestration LIVE. HTML Apply button hookup ships in v2.2.108.'
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
                        $spnOut = & $cmdletNewSISpn @spnArgs
                        $phaseStatus.spn = 'ok'
                        $applyLog.Add('phase=spn ok appId=' + $spnOut.AppId)
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
