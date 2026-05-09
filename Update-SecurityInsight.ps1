<#
.SYNOPSIS
    Updates this SecurityInsight install to the latest stable release.

.DESCRIPTION
    One-liner update tool. Runs `git pull` against the local clone of the
    KnudsenMorten/SecurityInsight repo, reports the version delta, and
    optionally dumps the curated release notes for everything new.

    What it does:
      1. Verifies git is on PATH and the current directory IS a git clone
         of KnudsenMorten/SecurityInsight (sanity check).
      2. Captures the current VERSION + commit hash.
      3. Runs `git pull --ff-only` (fast-forward only -- never merges; if
         your local has diverged, the pull fails cleanly so you can decide
         what to do).
      4. Prints the new VERSION + commit, plus a "what's next" reminder.

    Idempotent. Re-runnable. Safe -- never overwrites your config\
    SecurityInsight.custom.ps1 or LauncherConfig.custom.ps1 (those are
    gitignored).

.PARAMETER ShowReleaseNotes
    Print the curated RELEASENOTES.md entries between your previous
    version and the latest pulled version.

.EXAMPLE
    cd C:\SecurityInsight
    .\Update-SecurityInsight.ps1
    # Pulls latest stable, prints version delta.

.EXAMPLE
    cd C:\SecurityInsight
    .\Update-SecurityInsight.ps1 -ShowReleaseNotes
    # Pulls + dumps the curated release notes for everything new since
    # your previous version.

.NOTES
    Status: v2.2.152 -- new in this release.
    Developed by Morten Knudsen, Microsoft MVP | https://mortenknudsen.net
#>
[CmdletBinding()]
param(
    [Parameter()] [switch]$ShowReleaseNotes
)

$ErrorActionPreference = 'Stop'

function _Info ([string]$msg) { Write-Host "  [INFO] $msg" -ForegroundColor Gray }
function _Ok   ([string]$msg) { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function _Warn ([string]$msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function _Err  ([string]$msg) { Write-Host "  [ERR]  $msg" -ForegroundColor Red }

$repoRoot = $PSScriptRoot

Write-Host ""
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host " SecurityInsight Updater" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
_Info ("repo root  : {0}" -f $repoRoot)

# ----- Pre-flight: git on PATH -----
$gitFound = $false
try { $null = & git --version 2>&1; if ($LASTEXITCODE -eq 0) { $gitFound = $true } } catch { }
if (-not $gitFound) {
    Write-Host ""
    _Err 'git is not on PATH. Install Git for Windows + close + reopen PowerShell, then re-run.'
    _Info 'Install command (run elevated):'
    _Info '  $ProgressPreference = "SilentlyContinue"'
    _Info '  $gitUrl = ((Invoke-RestMethod "https://api.github.com/repos/git-for-windows/git/releases/latest").assets |'
    _Info '    Where-Object { $_.name -like "*-64-bit.exe" -and $_.name -notlike "PortableGit*" -and $_.name -notlike "MinGit*" } |'
    _Info '    Select-Object -First 1).browser_download_url'
    _Info '  Invoke-WebRequest -Uri $gitUrl -OutFile .\GitInstaller.exe'
    _Info '  Start-Process .\GitInstaller.exe -Wait -ArgumentList "/VERYSILENT","/NORESTART","/NOCANCEL","/SP-"'
    exit 1
}

# ----- Pre-flight: this folder must be a git clone of the SI repo -----
Push-Location $repoRoot
try {
    $remoteUrl = & git config --get remote.origin.url 2>&1
    if ($LASTEXITCODE -ne 0) {
        _Err ("not a git repository: {0}" -f $repoRoot)
        _Info "Re-clone with:  git clone https://github.com/KnudsenMorten/SecurityInsight.git C:\SecurityInsight"
        exit 1
    }
    if ($remoteUrl -notmatch '(?i)KnudsenMorten/SecurityInsight') {
        _Warn ("git remote 'origin' is {0}" -f $remoteUrl)
        _Warn 'Expected https://github.com/KnudsenMorten/SecurityInsight.git -- continuing anyway.'
    } else {
        _Ok ("remote     : {0}" -f $remoteUrl)
    }

    # ----- Capture current state -----
    $oldVersion = if (Test-Path -LiteralPath (Join-Path $repoRoot 'VERSION')) {
        (Get-Content -LiteralPath (Join-Path $repoRoot 'VERSION') -Raw).Trim()
    } else { 'unknown' }
    $oldCommit  = (& git rev-parse --short HEAD 2>$null).Trim()
    _Info ("current    : v{0} (commit {1})" -f $oldVersion, $oldCommit)

    # ----- Pull -----
    Write-Host ""
    Write-Host "  [STEP] git pull --ff-only origin main" -ForegroundColor Cyan
    $pullOutput = & git pull --ff-only origin main 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        _Err 'git pull failed. Output:'
        $pullOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        Write-Host ""
        _Info 'Common causes:'
        _Info '  - Your local branch has diverged (you committed local changes)'
        _Info '    Fix: git stash; .\Update-SecurityInsight.ps1; git stash pop'
        _Info '  - Network / proxy blocks GitHub'
        _Info '  - Repo permissions changed (rare)'
        exit 1
    }
    $pullOutput | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }

    # ----- Capture new state -----
    Write-Host ""
    $newVersion = (Get-Content -LiteralPath (Join-Path $repoRoot 'VERSION') -Raw).Trim()
    $newCommit  = (& git rev-parse --short HEAD 2>$null).Trim()

    if ($oldCommit -eq $newCommit) {
        _Ok ("already on latest: v{0} (commit {1})" -f $newVersion, $newCommit)
    } else {
        _Ok ("updated: v{0} -> v{1}  (commit {2} -> {3})" -f $oldVersion, $newVersion, $oldCommit, $newCommit)
    }

    # ----- Optional: show release notes since previous version -----
    if ($ShowReleaseNotes -and $oldCommit -ne $newCommit) {
        Write-Host ""
        Write-Host "  [INFO] release notes since v$oldVersion :" -ForegroundColor Gray
        Write-Host ""
        $rnPath = Join-Path $repoRoot 'RELEASENOTES.md'
        if (Test-Path -LiteralPath $rnPath) {
            $lines = Get-Content -LiteralPath $rnPath
            $emit  = $false
            foreach ($l in $lines) {
                if ($l -match ("^## v" + [regex]::Escape($oldVersion) + "\b")) { break }
                $emit = $emit -or ($l -match '^## v')
                if ($emit) { Write-Host "    $l" -ForegroundColor Gray }
            }
        } else {
            _Warn 'RELEASENOTES.md not found (nothing to dump).'
        }
    }

    Write-Host ""
    _Info "What's next:"
    _Info "  - Re-launch the Setup Wizard if you upgraded across a major release boundary:"
    _Info "      .\setup\ConfigWizard\Start-SetupWizard.ps1"
    _Info "  - Re-run your scheduled engines next cycle (no manual action needed)."
    Write-Host ""
} finally {
    Pop-Location
}
