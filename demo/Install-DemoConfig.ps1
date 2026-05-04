#Requires -Version 5.1
<#
.SYNOPSIS
    One-click refresh helper for the SecurityInsight v2.2 community demo VM.

.DESCRIPTION
    Copies every file under `demo/community/` into the corresponding live path
    under `v2.2/` (Direction = ToLive, default), or copies the live files back
    into `demo/community/` (Direction = FromLive) so you can capture a known-good
    snapshot.

    Files under `demo/community/` are gitignored (real customer values), so this
    script lets you stage them anywhere on disk and reapply on demand without
    manually re-locating each `.custom.ps1` file.

.PARAMETER Direction
    'ToLive'   (default) -- copy demo/community/* -> live v2.2/* paths.
    'FromLive'           -- capture current live config back into demo/community/.

.PARAMETER DryRun
    Print what would be copied without writing anything.

.EXAMPLE
    .\Install-DemoConfig.ps1
    Refreshes the demo VM from the snapshot.

.EXAMPLE
    .\Install-DemoConfig.ps1 -Direction FromLive
    Captures current live config into the snapshot.
#>
[CmdletBinding()]
param(
    [ValidateSet('ToLive','FromLive')]
    [string]$Direction = 'ToLive',
    [switch]$DryRun,
    # Skip the git pull step (default: ToLive auto-pulls so the demo VM is always
    # on the latest v2.2 code before the snapshot is reapplied).
    [switch]$NoGitPull
)
$ErrorActionPreference = 'Stop'

$here   = $PSScriptRoot
$v22    = Split-Path -Parent $here   # demo -> v2.2
$repo   = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $v22))   # v2.2 -> SecurityInsight -> SOLUTIONS -> AutomateIT
$source = Join-Path $here 'community'

# Auto-create demo/community/ subfolder skeleton if missing. Lets a fresh
# install of the demo helper "just work" even on an empty machine.
if (-not (Test-Path -LiteralPath $source)) {
    Write-Host "demo/community/ not found -- creating skeleton folders." -ForegroundColor Yellow
    foreach ($sub in 'config','launcher\endpoint','launcher\identity','launcher\azure','launcher\publicip','launcher\risk-analysis','launcher\privilege-tier-classifier') {
        $p = Join-Path $source $sub
        if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
    if ($Direction -eq 'ToLive') {
        Write-Host "Skeleton created but EMPTY. Run -Direction FromLive on a configured demo VM first to populate it, then re-run -Direction ToLive on the demo VM you want to refresh." -ForegroundColor Yellow
        return
    }
}

# ToLive flow: git-pull the v2.2 code before applying snapshot, so the demo VM
# is always on the latest preview tag before the customer config gets layered on.
if ($Direction -eq 'ToLive' -and -not $NoGitPull) {
    Write-Host "Pulling latest v2.2 code from git ..." -ForegroundColor Cyan
    if ($DryRun) {
        Write-Host "  DRY: would run 'git -C $repo fetch --tags && git -C $repo pull'" -ForegroundColor Cyan
    } else {
        try {
            & git -C $repo fetch --tags 2>&1 | Out-Host
            & git -C $repo pull 2>&1 | Out-Host
            Write-Host "  OK : git pull done" -ForegroundColor Green
        } catch {
            Write-Host "  WARN: git pull failed -- $($_.Exception.Message). Continuing with local code." -ForegroundColor Yellow
        }
    }
}

# Mapping table: demo-relative -> live-relative (both under v2.2 root)
$mapping = @(
    @{ Demo = 'config\SecurityInsight.custom.ps1'                                ; Live = 'config\SecurityInsight.custom.ps1' }
    @{ Demo = 'launcher\endpoint\LauncherConfig.custom.ps1'                      ; Live = 'launcher\endpoint\LauncherConfig.custom.ps1' }
    @{ Demo = 'launcher\identity\LauncherConfig.custom.ps1'                      ; Live = 'launcher\identity\LauncherConfig.custom.ps1' }
    @{ Demo = 'launcher\azure\LauncherConfig.custom.ps1'                         ; Live = 'launcher\azure\LauncherConfig.custom.ps1' }
    @{ Demo = 'launcher\publicip\LauncherConfig.custom.ps1'                      ; Live = 'launcher\publicip\LauncherConfig.custom.ps1' }
    @{ Demo = 'launcher\risk-analysis\LauncherConfig.custom.ps1'                 ; Live = 'launcher\risk-analysis\LauncherConfig.custom.ps1' }
    @{ Demo = 'launcher\privilege-tier-classifier\LauncherConfig.custom.ps1'     ; Live = 'launcher\privilege-tier-classifier\LauncherConfig.custom.ps1' }
)

$copied = 0
$skipped = 0
foreach ($m in $mapping) {
    $demoPath = Join-Path $source $m.Demo
    $livePath = Join-Path $v22    $m.Live

    if ($Direction -eq 'ToLive') {
        $src = $demoPath
        $dst = $livePath
    } else {
        $src = $livePath
        $dst = $demoPath
    }

    if (-not (Test-Path -LiteralPath $src)) {
        Write-Host ("  SKIP (source missing): $src") -ForegroundColor Yellow
        $skipped++
        continue
    }

    if ($DryRun) {
        Write-Host ("  DRY: $src -> $dst") -ForegroundColor Cyan
    } else {
        $dstDir = Split-Path -Parent $dst
        if (-not (Test-Path -LiteralPath $dstDir)) { New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }
        Copy-Item -LiteralPath $src -Destination $dst -Force
        Write-Host ("  OK : $src") -ForegroundColor Green
    }
    $copied++
}

$verb = if ($DryRun) { 'Would copy' } else { 'Copied' }
Write-Host ""
Write-Host ("$verb $copied file(s) ($Direction). Skipped: $skipped.") -ForegroundColor Cyan
if ($Direction -eq 'ToLive' -and -not $DryRun -and $copied -gt 0) {
    Write-Host "Demo VM refreshed. Run any launcher to verify (e.g. .\launcher\risk-analysis\launcher.community-vm.ps1)." -ForegroundColor Cyan
}
