#Requires -Version 5.1
<#
.SYNOPSIS
    Step 0 -- Install or update SecurityInsight from GitHub, preserving customer files.

.DESCRIPTION
    Downloads the latest SecurityInsight release ZIP from GitHub, extracts it into
    the target folder, and MERGES -- customer-owned files (LauncherConfig.ps1,
    launcher.override.ps1, CUSTOMDATA\*, *_Custom.yaml, etc.) are NEVER overwritten.

    Safe to run on a fresh VM (first install) or an existing VM (update in place).

    Run this script from anywhere. It places the code under -DestinationPath and
    optionally cd's into a launcher folder so you can run Step 1 immediately.

.PARAMETER Repo
    GitHub owner/repo. Default: KnudsenMorten/SecurityInsight.

.PARAMETER DestinationPath
    Local folder to install / update into. Default: C:\SCRIPTS\SecurityInsight.
    Created if missing.

.PARAMETER Channel
    'stable' (default) -- latest tagged release. Recommended for production.
    'preview'          -- HEAD of the preview branch. Use for testing new features.

.PARAMETER Engine
    Optional. Name of a launcher folder to cd into after install. E.g.
    'Step1_OnboardValidate-SecurityInsight-Permissions' to land ready to run.

.PARAMETER PreservePatterns
    Glob patterns (relative to DestinationPath) that will NEVER be overwritten
    on update. Default covers customer configs + customer YAML overrides.

.EXAMPLE
    # Fresh install, land in Step1 so you can run it immediately:
    .\Step0_OnboardUpdate_SecurityInsight_from_Github_Repo.ps1 -Engine Step1_OnboardValidate-SecurityInsight-Permissions

.EXAMPLE
    # Bootstrap from ANYWHERE (no local copy of the repo yet). Resolves the
    # latest release tag first so the fetched Step0.ps1 is always current --
    # the tag-pinned raw URL is immutable and not CDN-cached, unlike
    # raw/main/... which GitHub edge-caches for ~5 minutes and can return
    # a stale Step0 right after a release.
    # Invoke-WebRequest -OutFile (NOT `irm | Out-File`) preserves raw bytes --
    # see "Unexpected attribute 'CmdletBinding'" pitfall with PS 5.1 + UTF-8
    # BOM + Out-File default Unicode encoding.
    $repo      = 'KnudsenMorten/SecurityInsight'
    $latestTag = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name
    $u         = "https://raw.githubusercontent.com/$repo/$latestTag/scripts/Step0_OnboardUpdate_SecurityInsight_from_Github_Repo.ps1"
    Invoke-WebRequest -UseBasicParsing -Uri $u -OutFile "$env:TEMP\Step0.ps1"
    & "$env:TEMP\Step0.ps1" -Engine Step1_OnboardValidate-SecurityInsight-Permissions

.EXAMPLE
    # Scheduled "keep up to date" run -- same command, idempotent:
    .\Step0_OnboardUpdate_SecurityInsight_from_Github_Repo.ps1

.NOTES
    Solution       : SecurityInsight
    Developed by   : Morten Knudsen, Microsoft MVP (Security, Azure, Security Copilot)
    Blog           : https://mortenknudsen.net   (alias https://aka.ms/morten)
    GitHub         : https://github.com/KnudsenMorten
    Support        : GitHub Issues on https://github.com/KnudsenMorten/SecurityInsight
#>
[CmdletBinding()]
param(
    # =========================================================================
    # EDIT-ME DEFAULTS -- change the values on the right if you want your
    # own path / channel / target launcher pinned in-place. Any value you
    # pass as a -Param on the command line STILL wins over what's edited
    # here. Re-runs for "keep up to date" pipelines typically set these
    # once and then just invoke the script with no arguments.
    # =========================================================================
    [string]$DestinationPath = 'C:\SCRIPTS\SecurityInsight',              # <-- install path
    [ValidateSet('stable','preview')][string]$Channel = 'stable',          # <-- 'stable' or 'preview'
    [string]$Engine          = '',                                         # <-- optional: launcher folder to cd into afterwards, e.g. 'Step1_OnboardValidate-SecurityInsight-Permissions'
    [string]$Repo            = 'KnudsenMorten/SecurityInsight',            # <-- change if you fork the solution
    [string[]]$PreservePatterns = @(
        'launchers\*\LauncherConfig.ps1',
        'launchers\*\LauncherConfig.custom.ps1',
        'launchers\*\launcher.override.ps1',
        'CUSTOMDATA\*',
        'data\*_Custom.*',
        'DATA\*_Custom.*'
    )
    # =========================================================================
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$m) Write-Host "[STEP]  $m" -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Info { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor Gray  }
function Write-Warn { param([string]$m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }

Write-Host ""
Write-Host "========================================================================================" -ForegroundColor Cyan
Write-Host "  SecurityInsight -- Step 0: Install / Update from GitHub"                               -ForegroundColor Cyan
Write-Host "  Repo           : $Repo"                                                                 -ForegroundColor Gray
Write-Host "  Destination    : $DestinationPath"                                                      -ForegroundColor Gray
Write-Host "  Channel        : $Channel"                                                              -ForegroundColor Gray
if ($Engine) {
    Write-Host "  Target launcher: $Engine"                                                           -ForegroundColor Gray
}
Write-Host "========================================================================================" -ForegroundColor Cyan
Write-Host ""

# ---- 1. Download into a temp staging folder ------------------------------
$staging = Join-Path $env:TEMP ("csol-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path $staging | Out-Null

try {
    if ($Channel -eq 'stable') {
        Write-Step "Resolving latest stable release"
        $rel   = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
        $asset = $rel.assets | Where-Object name -Like '*.zip' | Select-Object -First 1
        if (-not $asset) { throw "No .zip asset on latest release of $Repo." }
        $zip = Join-Path $env:TEMP $asset.name
        Write-Info ("tag    : {0}" -f $rel.tag_name)
        Write-Info ("asset  : {0}" -f $asset.name)
        Write-Step "Downloading"
        Invoke-WebRequest $asset.browser_download_url -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $staging -Force
        Remove-Item $zip
        $version = $rel.tag_name
    } else {
        Write-Step "Downloading preview branch HEAD"
        $zip = Join-Path $env:TEMP ("$($Repo -replace '.+/','')-preview.zip")
        Invoke-WebRequest "https://github.com/$Repo/archive/refs/heads/preview.zip" -OutFile $zip -UseBasicParsing
        $tmp = Join-Path $env:TEMP ("expand-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        $inner = Get-ChildItem -Path $tmp -Directory | Select-Object -First 1
        Move-Item -Path (Join-Path $inner.FullName '*') -Destination $staging -Force
        Remove-Item $tmp -Recurse -Force
        Remove-Item $zip
        $version = 'preview HEAD'
    }
    Write-Ok ("downloaded: {0}" -f $version)

    # ---- 2. Merge into destination, preserving customer files ----------------
    Write-Step "Merging into $DestinationPath (preserving customer files)"
    if (-not (Test-Path $DestinationPath)) {
        New-Item -ItemType Directory -Force -Path $DestinationPath | Out-Null
        Write-Info "created destination"
    }

    # Policy:
    #   * Locked content (`*_Locked.*`, SCRIPTS/*, LAUNCHERS/*.template.ps1,
    #     LauncherConfig.defaults.ps1, README.md, etc.) is ALWAYS overwritten
    #     from the GitHub release -- these are curated by the maintainer and
    #     must stay in sync with the engine code.
    #   * Customer content (everything in $PreservePatterns) is NEVER touched
    #     if a destination copy already exists -- these are the customer's
    #     own config, YAML overrides, and working data.
    $copied       = 0
    $lockedUpdate = 0
    $preserved    = 0
    Get-ChildItem -Path $staging -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($staging.Length + 1)
        $dst = Join-Path $DestinationPath $rel

        $shouldPreserve = $false
        foreach ($pat in $PreservePatterns) {
            if ($rel -like $pat) { $shouldPreserve = $true; break }
        }
        if ($shouldPreserve -and (Test-Path -LiteralPath $dst)) {
            Write-Host ("[PRESERVE] {0}" -f $rel) -ForegroundColor DarkGray
            $preserved++
            return
        }

        $dstDir = Split-Path -Parent $dst
        if (-not (Test-Path -LiteralPath $dstDir)) {
            New-Item -ItemType Directory -Force -Path $dstDir | Out-Null
        }
        Copy-Item -LiteralPath $_.FullName -Destination $dst -Force
        if ($rel -like '*_Locked.*') {
            Write-Host ("[UPDATE]   {0}  (locked content -- force-refreshed from release)" -f $rel) -ForegroundColor Green
            $lockedUpdate++
        }
        $copied++
    }
    Write-Ok ("copied: $copied files  ({0} of which are *_Locked.* force-refreshed)  |  preserved: $preserved customer file(s)" -f $lockedUpdate)

    # ---- 3. Land in the launcher folder --------------------------------------
    $launchersRoot = Get-ChildItem -Path $DestinationPath -Directory |
                     Where-Object { $_.Name -ieq 'launchers' -or $_.Name -ieq 'LAUNCHERS' } |
                     Select-Object -First 1
    if (-not $launchersRoot) {
        Write-Warn "No launchers/ folder under $DestinationPath -- staying at install root."
        Set-Location -LiteralPath $DestinationPath
        return
    }

    $engineDirs = Get-ChildItem -Path $launchersRoot.FullName -Directory | Where-Object { $_.Name -ne '_lib' } | Sort-Object Name

    if ($Engine) {
        $match = $engineDirs | Where-Object { $_.Name -ieq $Engine } | Select-Object -First 1
        if (-not $match) {
            Write-Warn "Engine '$Engine' not found. Available:"
            $engineDirs | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor Gray }
            Set-Location -LiteralPath $launchersRoot.FullName
            return
        }
        Set-Location -LiteralPath $match.FullName
        Write-Host ""
        Write-Host "Now in: $($match.FullName)" -ForegroundColor Cyan
        Get-ChildItem -LiteralPath $match.FullName | Format-Table Name, Length -AutoSize | Out-String | Write-Host
    }
    elseif ($engineDirs.Count -eq 1) {
        Set-Location -LiteralPath $engineDirs[0].FullName
        Write-Host ""
        Write-Host "Now in: $($engineDirs[0].FullName)" -ForegroundColor Cyan
    }
    else {
        Set-Location -LiteralPath $launchersRoot.FullName
        Write-Host ""
        Write-Host "Multiple engines available under $($launchersRoot.FullName):" -ForegroundColor Cyan
        $engineDirs | ForEach-Object { Write-Host "  $($_.Name)" -ForegroundColor Gray }
        Write-Host ""
        Write-Host "Next up: open the Setup Configurator in a browser to build your .custom.ps1 files:" -ForegroundColor Yellow
        $configurator = Join-Path $DestinationPath 'TOOLS\SetupConfigurator\index.html'
        if (Test-Path -LiteralPath $configurator) {
            Write-Host "  $configurator" -ForegroundColor Yellow
            Write-Host "  -- or run -- " -ForegroundColor Gray
            Write-Host "  Start-Process '$configurator'" -ForegroundColor Yellow
        } else {
            Write-Host "  TOOLS\SetupConfigurator\index.html (once this build includes it)" -ForegroundColor Gray
        }
        Write-Host ""
        Write-Host "Then run the Steps in order:" -ForegroundColor Yellow
        Write-Host "  1. .\Step1_OnboardValidate-SecurityInsight-Permissions\launcher.community-vm.template.ps1" -ForegroundColor Yellow
        Write-Host "  2. .\Step2_OnboardValidate-SecurityInsight-LogAnalytics\launcher.community-vm.template.ps1" -ForegroundColor Yellow
        Write-Host "  3. (optional) .\Step3_OnboardValidate-SecurityInsight-OpenAI-PAYG-Instance-Azure\launcher.community-vm.template.ps1" -ForegroundColor Yellow
    }
}
finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue }
}
