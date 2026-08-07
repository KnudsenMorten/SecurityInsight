#Requires -Version 5.1
<#
.SYNOPSIS
    Audit + maintain the PowerShell-module version pins baked into the SI
    container image. Unattended; no prompts.

.DESCRIPTION
    The image at container/Dockerfile pre-installs a fixed set of modules
    (Az.*, AzLogDcrIngestPS, ImportExcel, powershell-yaml) with -RequiredVersion
    pins so every container in every customer tenant runs the exact same
    surface. Drift between Dockerfile pins and PSGallery latest is the #1
    source of "works locally, breaks in container" bugs.

    This script:
      1. Parses the Dockerfile and prints the currently-pinned versions.
      2. Optionally queries PSGallery for the newest available version of each.
      3. Optionally writes a new Dockerfile with chosen pins.
      4. Optionally triggers `az acr build` to rebuild the image and rolls all
         caj-si-* Container App Jobs onto the new image tag.

    Maintenance loop (typical):
      .\Sync-ContainerModules.ps1 -Audit                  # see drift
      .\Sync-ContainerModules.ps1 -BumpAll -Build -Roll   # ship the bumps

.PARAMETER Audit
    Print current Dockerfile pins next to PSGallery latest. No file changes.

.PARAMETER BumpAll
    Rewrite Dockerfile -RequiredVersion lines to PSGallery latest for every
    module. Use with caution; for surgical bumps use -BumpModule.

.PARAMETER BumpModule
    Hashtable @{ 'Az.Accounts'='5.5.0'; 'ImportExcel'='7.8.11' } -- bump only
    the listed modules to the listed exact versions. Wins over -BumpAll.

.PARAMETER Build
    Run `az acr build` after the Dockerfile edit. Requires -AcrName +
    -ResourceGroupName. Tag = $ImageTag (default: timestamp).

.PARAMETER Roll
    After a successful build, `az containerapp job update --image ...` every
    caj-si-* job in -ResourceGroupName to the new tag. In-flight executions
    finish on the old image; next trigger pulls the new one.

.PARAMETER AcrName
    Required with -Build / -Roll. ACR registry name (no .azurecr.io suffix).

.PARAMETER ResourceGroupName
    Required with -Build / -Roll. RG holding the ACR + Container App Jobs.

.PARAMETER ImageTag
    Tag to apply on -Build (default: yyyyMMddHHmm).

.PARAMETER DockerfilePath
    Override Dockerfile path. Default: <this-script-dir>\Dockerfile.

.EXAMPLE
    # Daily-style audit -- no writes, just drift report
    .\Sync-ContainerModules.ps1 -Audit

.EXAMPLE
    # Bump everything to latest, build, and roll in one shot (typical monthly)
    .\Sync-ContainerModules.ps1 -BumpAll -Build -Roll -AcrName acrsicont -ResourceGroupName rg-sicontainertest

.EXAMPLE
    # Surgical -- bump only ImportExcel (security fix) and roll
    .\Sync-ContainerModules.ps1 -BumpModule @{ 'ImportExcel' = '7.8.11' } -Build -Roll -AcrName acrsicont -ResourceGroupName rg-sicontainertest

.NOTES
    Drift policy:
      - Major.Minor bumps require a manual test pass on stsicont/sicont tenant
        before -Roll on real customer RGs.
      - Patch bumps may be auto-rolled (no API surface change).
      - AzLogDcrIngestPS is owned by us -- pin to whatever we just published.
        Memory: v1.6.3 has a cert-only-auth gate bug; pin 1.6.2 until 1.6.4 ships.

    Status: v2.2.309 -- new in this release.
#>
[CmdletBinding()]
param(
    [Parameter()] [switch]$Audit,
    [Parameter()] [switch]$BumpAll,
    [Parameter()] [hashtable]$BumpModule,
    [Parameter()] [switch]$Build,
    [Parameter()] [switch]$Roll,
    [Parameter()] [string]$AcrName,
    [Parameter()] [string]$ResourceGroupName,
    [Parameter()] [string]$ImageTag = (Get-Date -Format 'yyyyMMddHHmm'),
    [Parameter()] [string]$DockerfilePath
)

$ErrorActionPreference = 'Stop'
function _Step([string]$m) { Write-Host ("  [STEP] {0}" -f $m) -ForegroundColor Cyan }
function _Ok  ([string]$m) { Write-Host ("  [OK]   {0}" -f $m) -ForegroundColor Green }
function _Info([string]$m) { Write-Host ("  [INFO] {0}" -f $m) -ForegroundColor Gray }
function _Warn([string]$m) { Write-Host ("  [WARN] {0}" -f $m) -ForegroundColor Yellow }
function _Err ([string]$m) { Write-Host ("  [ERR]  {0}" -f $m) -ForegroundColor Red }

if (-not $DockerfilePath) { $DockerfilePath = Join-Path $PSScriptRoot 'Dockerfile' }
if (-not (Test-Path -LiteralPath $DockerfilePath)) { throw "Dockerfile not found: $DockerfilePath" }

# ----------- Parse current pins -----------
$rxPin = 'Install-Module -Name (?<n>\S+)\s+-RequiredVersion (?<v>\d+\.\d+\.\d+(?:\.\d+)?)'
$lines = Get-Content -LiteralPath $DockerfilePath
$pins  = [ordered]@{}
foreach ($l in $lines) {
    foreach ($m in [regex]::Matches($l, $rxPin)) {
        $pins[$m.Groups['n'].Value] = $m.Groups['v'].Value
    }
}
if ($pins.Count -eq 0) { throw "No '-RequiredVersion' lines found in $DockerfilePath -- is the format intact?" }

_Info ("Dockerfile: {0}" -f $DockerfilePath)
_Info ("Found {0} pinned modules" -f $pins.Count)

# ----------- Query PSGallery latest -----------
function Get-PSGalleryLatest([string]$Name) {
    try {
        $m = Find-Module -Name $Name -ErrorAction Stop -Repository PSGallery | Select-Object -First 1
        return $m.Version.ToString()
    } catch { return $null }
}

_Step "Querying PSGallery latest for each module..."
$report = foreach ($name in $pins.Keys) {
    $pinned = $pins[$name]
    $latest = Get-PSGalleryLatest -Name $name
    [pscustomobject]@{
        Module = $name
        Pinned = $pinned
        Latest = $latest
        Drift  = if ($latest -and $latest -ne $pinned) { '*' } else { '' }
    }
}

Write-Host ''
$report | Format-Table -AutoSize | Out-String | Write-Host

$driftCount = ($report | Where-Object Drift -eq '*' | Measure-Object).Count
if ($driftCount) { _Warn ("{0} module(s) drift from PSGallery latest" -f $driftCount) }
else             { _Ok   "all pins match PSGallery latest" }

if ($Audit -and -not ($BumpAll -or $BumpModule)) { return }

# ----------- Apply bumps -----------
$targetPins = [ordered]@{}
foreach ($name in $pins.Keys) { $targetPins[$name] = $pins[$name] }   # start from current

if ($BumpAll) {
    foreach ($r in $report) {
        if ($r.Latest) { $targetPins[$r.Module] = $r.Latest }
    }
}
if ($BumpModule) {
    foreach ($k in $BumpModule.Keys) {
        if (-not $targetPins.Contains($k)) { _Warn "BumpModule key '$k' not in Dockerfile -- ignoring"; continue }
        $targetPins[$k] = [string]$BumpModule[$k]
    }
}

$changed = @()
foreach ($k in $targetPins.Keys) { if ($targetPins[$k] -ne $pins[$k]) { $changed += $k } }

if (-not $changed) {
    _Info "no version bumps requested -- Dockerfile unchanged"
} else {
    _Step ("rewriting Dockerfile with {0} bumped pin(s): {1}" -f $changed.Count, ($changed -join ', '))
    $content = Get-Content -LiteralPath $DockerfilePath -Raw
    foreach ($name in $changed) {
        $old = "Install-Module -Name $name`s+-RequiredVersion " + [regex]::Escape($pins[$name])
        # Anchor by name to avoid clobbering similar lines
        $pattern = "(Install-Module\s+-Name\s+" + [regex]::Escape($name) + "\s+-RequiredVersion\s+)" + [regex]::Escape($pins[$name])
        $repl    = "`${1}" + $targetPins[$name]
        $newContent = [regex]::Replace($content, $pattern, $repl)
        if ($newContent -eq $content) { _Warn "could not rewrite pin for $name -- regex miss" }
        $content = $newContent
    }
    Set-Content -LiteralPath $DockerfilePath -Value $content -Encoding UTF8
    _Ok ("Dockerfile updated: {0}" -f $DockerfilePath)
}

if (-not $Build) { return }

# ----------- Build image via ACR Tasks -----------
if (-not $AcrName)           { throw "-AcrName is required when -Build is set" }
if (-not $ResourceGroupName) { throw "-ResourceGroupName is required when -Build is set" }

_Step "verify az CLI"
$null = & az version --output json 2>&1
if ($LASTEXITCODE -ne 0) { throw "az CLI not installed / not on PATH" }
$null = & az account show --output none 2>&1
if ($LASTEXITCODE -ne 0) { throw "az CLI not logged in -- run 'az login' first" }

$buildCtx = Split-Path -Parent $PSScriptRoot   # <repo>/SOLUTIONS/SecurityInsight/
_Step ("az acr build  --registry {0}  --image si-orchestrator:{1}" -f $AcrName, $ImageTag)
$null = & az acr build --registry $AcrName --image ("si-orchestrator:{0}" -f $ImageTag) --image 'si-orchestrator:latest' --file (Join-Path $PSScriptRoot 'Dockerfile') $buildCtx
if ($LASTEXITCODE -ne 0) { throw "az acr build failed" }
_Ok ("image built + pushed: {0}.azurecr.io/si-orchestrator:{1} (+ :latest)" -f $AcrName, $ImageTag)

if (-not $Roll) { return }

# ----------- Roll Container App Jobs onto new image -----------
$image = "{0}.azurecr.io/si-orchestrator:{1}" -f $AcrName, $ImageTag
_Step ("rolling Container App Jobs in {0} -> {1}" -f $ResourceGroupName, $image)

$jobsJson = & az containerapp job list --resource-group $ResourceGroupName --query "[?starts_with(name,'caj-si-')].name" -o json
if ($LASTEXITCODE -ne 0) { throw "az containerapp job list failed" }
$jobs = $jobsJson | ConvertFrom-Json
if (-not $jobs -or $jobs.Count -eq 0) { _Warn "no caj-si-* jobs found in $ResourceGroupName -- nothing to roll"; return }

foreach ($j in $jobs) {
    _Step ("update {0} -> {1}" -f $j, $image)
    $null = & az containerapp job update --name $j --resource-group $ResourceGroupName --image $image --output none 2>&1
    if ($LASTEXITCODE -ne 0) { _Err "failed to update $j" } else { _Ok ("rolled {0}" -f $j) }
}
_Ok ("rolled {0} job(s)" -f $jobs.Count)
