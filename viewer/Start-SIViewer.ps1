<#
.SYNOPSIS
    SecurityInsight Risk Analysis viewer -- local-only HTTP server.

.DESCRIPTION
    Spins up a tiny System.Net.HttpListener on http://localhost:<Port> that
    serves the static viewer HTML + the latest Risk Analysis JSON files
    produced by Invoke-RiskAnalysis.ps1 (output/RiskAnalysis_*.json).

    No IIS, no auth, localhost-only binding -- this is the test rig. Anyone
    who can sign into the VM can hit it. Add MSAL.js + IIS later for the
    multi-user / production deployment.

.PARAMETER Port
    TCP port to listen on. Default 8765 (avoids the more commonly squatted
    8080 and the IANA-reserved low ports, no admin needed for HttpListener
    on localhost).

.PARAMETER OutputDir
    Folder to scan for RiskAnalysis_*.json files. Default: the SI solution's
    output/ folder one level up from this script.

.PARAMETER NoBrowser
    Don't open the default browser on startup.

.EXAMPLE
    .\Start-SIViewer.ps1
    Launches on http://localhost:8765 and opens the browser.

.EXAMPLE
    .\Start-SIViewer.ps1 -Port 9000 -NoBrowser
    Launches on http://localhost:9000 without opening the browser.

.NOTES
    Stop with Ctrl+C. The listener cleans itself up on exit.

    HttpListener notes:
    - http://localhost:<port>/ usually works for the current user with no
      URL ACL. If you hit "Access is denied" on Start(), run once as admin:
        netsh http add urlacl url=http://localhost:8765/ user="DOMAIN\user"
      ...and you'll never need admin again on that port.
#>
[CmdletBinding()]
param(
    [int]$Port = 8765,
    [string]$OutputDir,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

# ----- Resolve paths -----
$scriptDir = $PSScriptRoot
$webDir    = Join-Path $scriptDir 'web'
$indexHtml = Join-Path $webDir   'index.html'

if (-not (Test-Path -LiteralPath $indexHtml)) {
    throw "viewer asset missing: $indexHtml"
}

if (-not $OutputDir) {
    # Walk up from the viewer folder to find the SI solution root, then
    # default to <solution>/output/.
    $candidate = $scriptDir
    while ($candidate -and -not (Test-Path -LiteralPath (Join-Path $candidate 'VERSION'))) {
        $parent = Split-Path -Parent $candidate
        if (-not $parent -or $parent -eq $candidate) { $candidate = $null; break }
        $candidate = $parent
    }
    if ($candidate) { $OutputDir = Join-Path $candidate 'output' }
    else            { $OutputDir = Join-Path $scriptDir 'output' }
}

if (-not (Test-Path -LiteralPath $OutputDir)) {
    Write-Warning "Output directory '$OutputDir' does not exist. The viewer will load with no data files."
}

# ----- Color helpers -----
function _Info ([string]$msg) { Write-Host "  [INFO] $msg" -ForegroundColor Gray }
function _Ok   ([string]$msg) { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function _Warn ([string]$msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function _Err  ([string]$msg) { Write-Host "  [ERR]  $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host " SecurityInsight Risk Analysis Viewer (test mode, no auth)"        -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
_Info "script dir : $scriptDir"
_Info "web dir    : $webDir"
_Info "output dir : $OutputDir"
_Info "port       : $Port"
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

# ----- Open browser -----
if (-not $NoBrowser) {
    try {
        Start-Process $prefix | Out-Null
        _Info "browser launched"
    } catch {
        _Warn "could not auto-launch browser: $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "  >>> press Ctrl+C to stop <<<" -ForegroundColor Magenta
Write-Host ""

# ----- MIME map -----
$mime = @{
    '.html' = 'text/html; charset=utf-8'
    '.htm'  = 'text/html; charset=utf-8'
    '.js'   = 'application/javascript; charset=utf-8'
    '.css'  = 'text/css; charset=utf-8'
    '.json' = 'application/json; charset=utf-8'
    '.svg'  = 'image/svg+xml'
    '.png'  = 'image/png'
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

function Get-DataFiles {
    param([string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir)) { return @() }
    Get-ChildItem -LiteralPath $Dir -Filter 'RiskAnalysis_*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object -Property LastWriteTime -Descending |
        ForEach-Object {
            [pscustomobject]@{
                name      = $_.Name
                sizeBytes = $_.Length
                mtime     = $_.LastWriteTime.ToString('o')
                age       = ((Get-Date) - $_.LastWriteTime).TotalMinutes
            }
        }
}

# ----- Request loop -----
try {
    while ($listener.IsListening) {
        $ctx = $null
        try { $ctx = $listener.GetContext() } catch { break }

        $req = $ctx.Request
        $res = $ctx.Response
        $url = $req.Url.AbsolutePath
        $stamp = (Get-Date).ToString('HH:mm:ss')
        Write-Host ("  [{0}] {1,-4} {2}" -f $stamp, $req.HttpMethod, $url) -ForegroundColor DarkGray

        try {
            switch -Regex ($url) {
                '^/$' {
                    $bytes = [System.IO.File]::ReadAllBytes($indexHtml)
                    Send-Bytes -Response $res -Bytes $bytes -ContentType $mime['.html']
                    break
                }
                '^/api/files$' {
                    Send-Json -Response $res -Object @{
                        outputDir = $OutputDir
                        files     = @(Get-DataFiles -Dir $OutputDir)
                    }
                    break
                }
                '^/api/data$' {
                    $name = $req.QueryString['file']
                    if ([string]::IsNullOrWhiteSpace($name) -or $name -match '[\\/:]') {
                        Send-Json -Response $res -Object @{ error = 'invalid file parameter' } -Status 400
                        break
                    }
                    $path = Join-Path $OutputDir $name
                    if (-not (Test-Path -LiteralPath $path)) {
                        Send-Json -Response $res -Object @{ error = "file not found: $name" } -Status 404
                        break
                    }
                    $bytes = [System.IO.File]::ReadAllBytes($path)
                    Send-Bytes -Response $res -Bytes $bytes -ContentType $mime['.json']
                    break
                }
                '^/health$' {
                    Send-Json -Response $res -Object @{
                        ok       = $true
                        time     = (Get-Date).ToString('o')
                        port     = $Port
                        outputDir= $OutputDir
                    }
                    break
                }
                default {
                    # static asset under web/
                    $rel = ($url -replace '^/+','')
                    $path = Join-Path $webDir $rel
                    # block path traversal
                    $resolved = $null
                    try { $resolved = (Resolve-Path -LiteralPath $path -ErrorAction Stop).Path } catch { }
                    if (-not $resolved -or -not $resolved.StartsWith($webDir, [System.StringComparison]::OrdinalIgnoreCase)) {
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
            try {
                Send-Text -Response $res -Text ("server error: " + $_.Exception.Message) -Status 500
            } catch { }
            _Err "request failed: $($_.Exception.Message)"
        }
    }
}
finally {
    try { $listener.Stop();  } catch { }
    try { $listener.Close(); } catch { }
    Write-Host ""
    _Ok "viewer stopped"
}
