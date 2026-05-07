<#
.SYNOPSIS
    SecurityInsight Setup Wizard -- local-only HTTP launcher.

.DESCRIPTION
    Hosts the Config Wizard HTML (Setup-SecurityInsight.html) on
    http://localhost:<Port> and exposes the /api/* endpoints the wizard's
    final Apply page calls to provision the SPN + Log Analytics + Storage
    and write config/SecurityInsight.custom.ps1.

    Status (v2.2.103): HttpListener + HTML serving live; /api/* endpoints
    return stubs while the provisioner cmdlets are being built across
    v2.2.104..v2.2.109. See ROADMAP.md.

    Endpoint contract (when complete):
      POST /api/validate-name      { type: 'storage'|'workspace'|'kv', name } -> { available: bool, reason }
      POST /api/apply              { state: <full wizard state> }            -> 202 + run id
      GET  /api/log-stream?run=ID  Server-Sent Events tail of the run        -> stream
      GET  /api/state              current in-flight run status              -> json

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

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " SecurityInsight Setup Wizard (localhost, no auth)"                  -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
_Info "wizard html : $indexHtml"
_Info "port        : $Port"
_Info ""
_Warn "v2.2.103: skeleton -- HTML serves OK; /api/apply is a stub until v2.2.107."
_Warn "Use Steps 3-7 of the README in the meantime (Bootstrap-Auth + Bootstrap-Storage)."
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
                        wizardVersion  = '2.2.103'
                        applyAvailable = $false
                        roadmapTag     = 'v2.2.107'
                        notes          = 'apply orchestration scheduled for v2.2.107; see ROADMAP.md'
                    }
                    break
                }
                '^/api/validate-name$' {
                    # Stub. v2.2.106 will check Storage / Workspace / KV name availability via Az SDK.
                    Send-Json -Response $res -Object @{
                        ok      = $true
                        stub    = $true
                        message = 'name-availability checks land in v2.2.106'
                    }
                    break
                }
                '^/api/apply$' {
                    # Stub. v2.2.107 will orchestrate New-SISpn -> Initialize-SIInfra -> Write-SICustomConfig.
                    Send-Json -Response $res -Object @{
                        ok      = $false
                        stub    = $true
                        message = 'Apply orchestration is being built across v2.2.104..v2.2.107. For now follow Steps 4-7 in the README (Bootstrap-Auth.ps1 + Bootstrap-Storage.ps1 + Setup Configurator copy/paste).'
                    } -Status 501
                    break
                }
                '^/api/log-stream$' {
                    # Stub SSE -- v2.2.107 will tail the running provisioner output.
                    Send-Text -Response $res -Text 'log streaming lands in v2.2.107' -Status 501
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
