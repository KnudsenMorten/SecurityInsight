#Requires -Version 5.1
<#
.SYNOPSIS
    Demo / first-run helper. Optionally clones the public SI repo + drops in
    customer config, then fires every SecurityInsight launcher in its own
    visible PowerShell window so a demo audience can watch all engines +
    Risk Analysis run side-by-side.

.DESCRIPTION
    Two modes:

    DEFAULT (no -Install): assumes -Root is an existing SI install, fires the
    launchers immediately.

    -Install: full fresh-VM setup --
      1. Clone the public stable repo to -Root if not already present
      2. If demo/community/ snapshot exists alongside this script, run
         Install-DemoConfig.ps1 to copy customer config into -Root
      3. Fire all 7 launcher windows

    Window order:
      Endpoint -> Azure -> Identity -> PublicIP -> PrivilegeTierClassifier
      -> Risk Analysis Detailed -> Risk Analysis Summary

    Each window opens via `cmd /c start "title" powershell.exe -NoExit -File <launcher>`.
    cmd's start command is rock-solid for parallel spawns on Windows --
    avoids the AV throttling / Defender SmartScreen rate-limiting that can
    silently drop windows when 7 powershell.exe processes spawn in <1 sec.

    Each window stays open after the launcher finishes (-NoExit) so the demo
    audience can scroll through the run output.

.PARAMETER Root
    Install root. Default: 'C:\Demo\SecurityInsight'. With -Install, the
    public repo is cloned here if missing.

.PARAMETER Install
    Fresh-VM mode. Clones the public repo to -Root if missing + drops customer
    config from the demo/community/ snapshot via Install-DemoConfig.ps1.

.PARAMETER GitRepoUrl
    Public-repo URL (used by -Install when cloning). Default points at
    KnudsenMorten/SecurityInsight.git.

.PARAMETER Tag
    Pin to a specific git tag (e.g. v2.2.2) after cloning. Default: stay on
    main (latest).

.PARAMETER SkipPull
    Skip `git pull` before firing windows (default mode only). Useful when
    iterating offline.

.PARAMETER StaggerSeconds
    Delay between window launches. Default 2s. Bump to 3-4 if your AV / VM
    drops some launches.

.PARAMETER Sequential
    Wait for each window to close before launching the next. By default all
    7 fire near-simultaneously (parallel) -- visually impressive for a demo
    but small-tenant API paths may rate-limit when 7 collectors hammer
    Defender + Graph + ARG at once.

.PARAMETER NoForceFullRun
    Default behaviour passes -ForceFullRun to all 5 collectors so the first
    demo run shows data even when cadence-skip would otherwise silence them.
    Pass this switch on subsequent runs to respect tier cadence.

.EXAMPLE
    .\Run-AllEngines.ps1
    Refresh existing install + fire 7 parallel windows.

.EXAMPLE
    .\Run-AllEngines.ps1 -Install
    Fresh demo VM: clone public repo to C:\Demo\SecurityInsight, drop customer
    config, then fire 7 windows.

.EXAMPLE
    .\Run-AllEngines.ps1 -Install -Tag v2.2.2 -Root D:\Demo\SI
    Fresh install pinned to v2.2.2 at a non-default path.

.EXAMPLE
    .\Run-AllEngines.ps1 -Sequential -NoForceFullRun
    Wait for each window to close, respect tier cadence (faster on warm runs).

.NOTES
    Public helper -- ships with the stable + preview repos under tools/.

    For first-time users: run `Setup-SecurityInsight.ps1 -Wizard` first to
    generate config\SecurityInsight.custom.ps1 + the per-engine
    LauncherConfig.custom.ps1 files, then `tools\Run-AllEngines.ps1` fires
    every engine in parallel windows.

    -Install mode is primarily for the maintainer's demo VMs (uses
    demo/community/ snapshot which is gitignored / not shipped). Public
    users skip -Install and use the wizard instead.

    Developed by : Morten Knudsen, Microsoft MVP
#>
[CmdletBinding()]
param(
    # Default: walk up from this script's location -- if running from
    # <install>\SOLUTIONS\SecurityInsight\tools\Run-AllEngines.ps1, $PSScriptRoot
    # is .../tools, so two ups = the SI install root. Falls back to the
    # legacy C:\Demo\SecurityInsight when $PSScriptRoot can't be resolved
    # (e.g. dot-sourced from a wrapper that broke the script-root context).
    [string]$Root                    = $(if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { 'C:\Demo\SecurityInsight' }),
    [switch]$Install,
    [string]$GitRepoUrl              = 'https://github.com/KnudsenMorten/SecurityInsight.git',
    [string]$Tag                     = '',
    [switch]$SkipPull,
    [int]   $StaggerSeconds          = 2,
    [switch]$Sequential,
    [switch]$NoForceFullRun,
    [switch]$PrivilegeTierClassifier,
    # Subset switches (mutually exclusive with each other and -PrivilegeTierClassifier).
    # Useful when you only need to refresh one slice of the pipeline:
    #   -InitialProfilersOnly  -- Endpoint + Identity + Azure (skip PublicIP + RA)
    #                             First-run pattern: get the three core profile tables
    #                             populated before firing PublicIP (which depends on
    #                             tier signals from the others) or RA (which queries
    #                             all four Profile_CL tables).
    #   -ProfilersOnly         -- Endpoint + Identity + Azure + PublicIP (skip RA)
    #                             Use when Profile tables need a refresh but RA
    #                             output is still current.
    #   -RiskAnalysisOnly      -- RA Detailed + RA Summary only
    #                             Use after Profile tables are already fresh; cheaper
    #                             rerun for RA-only (~5 min vs the full ~hour fanout).
    [switch]$InitialProfilersOnly,
    [switch]$ProfilersOnly,
    [switch]$RiskAnalysisOnly,
    # Launcher flavour. 'community' = launcher.community-vm.ps1 (auth from
    # custom.ps1's $Spn* block; demo VMs / community customers). 'internal' =
    # launcher.internal-vm.ps1 (auth via upstream Initialize-PlatformAutomationFramework
    # cert+KV). Mandatory -- forcing an explicit choice prevents internal
    # customers from accidentally firing the community-flavour launchers
    # (which would skip Initialize-PlatformAutomationFramework + KV secret fetch).
    [Parameter(Mandatory)]
    [ValidateSet('community','internal')]
    [string]$Flavour
)

# Mutually-exclusive subset switches. Catch the obvious user error early
# rather than firing a confusing fan-out.
$__subsetSwitches = @($PrivilegeTierClassifier, $InitialProfilersOnly, $ProfilersOnly, $RiskAnalysisOnly) | Where-Object { $_ }
if ($__subsetSwitches.Count -gt 1) {
    Write-Host 'ERROR: pick at most ONE of -PrivilegeTierClassifier, -InitialProfilersOnly, -ProfilersOnly, -RiskAnalysisOnly.' -ForegroundColor Red
    exit 1
}
$ErrorActionPreference = 'Continue'

# Auto-redirect: if -Root points at an AutomateIT install root (no engine/ here
# but SOLUTIONS\SecurityInsight\engine\ exists), silently rewrite to the SI dir.
# Lets internal callers run `.\Run-AllEngines.ps1 -Root D:\AutomateIT` without
# having to remember the SOLUTIONS\SecurityInsight suffix.
if ($Root -and -not (Test-Path -LiteralPath (Join-Path $Root 'engine'))) {
    $siUnderAutomateit = Join-Path $Root 'SOLUTIONS\SecurityInsight'
    if (Test-Path -LiteralPath (Join-Path $siUnderAutomateit 'engine')) {
        Write-Host ("  (auto-redirect: -Root '{0}' is an AutomateIT install -- using '{1}')" -f $Root, $siUnderAutomateit) -ForegroundColor DarkGray
        $Root = $siUnderAutomateit
    }
}

Write-Host ('=' * 80) -ForegroundColor Cyan
Write-Host '  SecurityInsight -- Run-AllEngines' -ForegroundColor Cyan
Write-Host ('  Root: ' + $Root) -ForegroundColor Cyan
if ($Install) { Write-Host '  Mode: -Install (fresh VM setup)' -ForegroundColor Yellow }
Write-Host ('=' * 80) -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Install mode -- clone public repo + drop customer config
# ---------------------------------------------------------------------------
if ($Install) {
    Write-Host "`n==> [Install] Step 1: ensure $Root exists with SI install" -ForegroundColor Cyan
    $hasInstall = (Test-Path -LiteralPath (Join-Path $Root 'engine'))
    if ($hasInstall) {
        Write-Host '  install already present (engine/ folder found) -- skipping clone' -ForegroundColor Gray
    } else {
        if (Test-Path -LiteralPath $Root) {
            Write-Host "  $Root exists but has no engine/ folder -- cloning into it would conflict. Aborting." -ForegroundColor Red
            Write-Host "  Either pass a different -Root or delete $Root manually first." -ForegroundColor Red
            exit 1
        }
        Write-Host "  cloning $GitRepoUrl -> $Root" -ForegroundColor Cyan
        & git clone --depth 50 $GitRepoUrl $Root 2>&1 | ForEach-Object { Write-Host $_ }
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  git clone failed (exit $LASTEXITCODE). Check network / repo URL." -ForegroundColor Red
            exit 1
        }
        if ($Tag) {
            Write-Host "  pinning to tag $Tag" -ForegroundColor Cyan
            & git -C $Root fetch --tags 2>&1 | ForEach-Object { Write-Host $_ }
            & git -C $Root checkout $Tag 2>&1 | ForEach-Object { Write-Host $_ }
        }
    }

    Write-Host "`n==> [Install] Step 2: drop customer config (from demo/community/ snapshot)" -ForegroundColor Cyan
    # tools/Run-AllEngines.ps1 lives at <SI>/tools/, demo/community/ at <SI>/demo/community/.
    # Walk one level up from tools/ then into demo/community. Public installs
    # don't have demo/ at all (excluded from publish) -- they should populate
    # config via `Setup-SecurityInsight.ps1 -Wizard` instead.
    $siRoot = Split-Path -Parent $PSScriptRoot
    $communityRoot = Join-Path $siRoot 'demo\community'
    if (-not (Test-Path -LiteralPath $communityRoot)) {
        Write-Host "  demo/community/ snapshot not present (expected on public installs)." -ForegroundColor Yellow
        Write-Host "  Public users: run '$siRoot\Setup-SecurityInsight.ps1 -Wizard' to generate config files." -ForegroundColor Yellow
    } else {
            $mapping = @(
                @{ S = 'config\SecurityInsight.custom.ps1';                                 D = 'config\SecurityInsight.custom.ps1' }
                @{ S = 'launcher\endpoint\LauncherConfig.custom.ps1';                       D = 'launcher\endpoint\LauncherConfig.custom.ps1' }
                @{ S = 'launcher\identity\LauncherConfig.custom.ps1';                       D = 'launcher\identity\LauncherConfig.custom.ps1' }
                @{ S = 'launcher\azure\LauncherConfig.custom.ps1';                          D = 'launcher\azure\LauncherConfig.custom.ps1' }
                @{ S = 'launcher\publicip\LauncherConfig.custom.ps1';                       D = 'launcher\publicip\LauncherConfig.custom.ps1' }
                @{ S = 'launcher\risk-analysis\LauncherConfig.custom.ps1';                  D = 'launcher\risk-analysis\LauncherConfig.custom.ps1' }
                @{ S = 'launcher\privilege-tier-classifier\LauncherConfig.custom.ps1';      D = 'launcher\privilege-tier-classifier\LauncherConfig.custom.ps1' }
            )
            $copied = 0; $skipped = 0
            foreach ($m in $mapping) {
                $src = Join-Path $communityRoot $m.S
                $dst = Join-Path $Root          $m.D
                if (-not (Test-Path -LiteralPath $src)) { Write-Host ("    SKIP (no source): " + $m.S) -ForegroundColor Yellow; $skipped++; continue }
                $dstDir = Split-Path -Parent $dst
                if (-not (Test-Path -LiteralPath $dstDir)) { New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }
                Copy-Item -LiteralPath $src -Destination $dst -Force
                Write-Host ("    OK: " + $m.D) -ForegroundColor Green
                $copied++
            }
        Write-Host ("  customer config: $copied copied, $skipped skipped") -ForegroundColor Cyan
    }
}

# ---------------------------------------------------------------------------
# 2. Verify Root has an SI install before firing engines
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath (Join-Path $Root 'engine'))) {
    Write-Host "`nERROR: $Root has no engine/ folder. Either:" -ForegroundColor Red
    Write-Host '  - pass -Install to clone it now, or' -ForegroundColor Red
    Write-Host '  - point -Root at an existing SI install' -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------------------------
# 3. Refresh repo (skip in -Install mode -- we just cloned)
# ---------------------------------------------------------------------------
if (-not $Install -and -not $SkipPull) {
    # Stream-extract installs (no .git/ + no git binary on the host) skip git pull.
    # Updates flow through Sync-AutomateIT.ps1 (internal) or Update-SecurityInsight.ps1
    # (community) on those hosts; this engine wrapper just runs the engines.
    $haveGit  = [bool](Get-Command git -ErrorAction SilentlyContinue)
    $isGitRepo = Test-Path -LiteralPath (Join-Path $Root '.git')
    if (-not $haveGit -or -not $isGitRepo) {
        $reason = if (-not $haveGit) { 'git command not on PATH' } else { 'no .git/ in install root' }
        Write-Host ("`n==> skipping git pull -- {0}. Updates flow through Sync-AutomateIT.ps1 or Update-SecurityInsight.ps1 on this host." -f $reason) -ForegroundColor DarkGray
    } else {
        Write-Host "`n==> git pull" -ForegroundColor Cyan
        Push-Location $Root
        try {
            # Pipe to ForEach so PowerShell treats git's stderr lines as data, not exceptions.
            # (`& git ... 2>&1 | Out-Host` still triggers the red 'NativeCommandError' display.)
            & git pull 2>&1 | ForEach-Object { Write-Host $_ }
        } finally { Pop-Location }
    }
}
$ver = Get-Content -LiteralPath (Join-Path $Root 'VERSION') -ErrorAction SilentlyContinue | Select-Object -First 1
Write-Host ('VERSION: ' + $ver) -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# 4. Kill stale community-vm launcher processes (skipped in -PrivilegeTierClassifier
#    mode -- standalone PTC runs alongside an existing fan-out and must NOT
#    terminate sibling collector windows still in flight).
# ---------------------------------------------------------------------------
$mePid = $PID
if ($PrivilegeTierClassifier) {
    Write-Host "`n==> -PrivilegeTierClassifier mode -- skipping stale-process kill (leave sibling launchers alone)" -ForegroundColor Cyan
} else {
    Write-Host "`n==> killing stale launcher.$Flavour-vm.ps1 processes" -ForegroundColor Cyan
    # Match the launcher name for the CURRENT flavour. Earlier versions hardcoded
    # 'community-vm' regardless of -Flavour, so internal-vm reruns left every
    # prior window alive -- the screen filled with N copies of each engine.
    $launcherPattern = 'launcher\.{0}-vm\.ps1' -f [regex]::Escape($Flavour)
    $stale = Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessId -ne $mePid -and $_.CommandLine -match $launcherPattern }
    if ($stale) {
        foreach ($p in $stale) {
            Write-Host ('  killing PID ' + $p.ProcessId) -ForegroundColor Yellow
            Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host '  (none found)' -ForegroundColor Gray
    }
}

# ---------------------------------------------------------------------------
# 5. Run plan
# ---------------------------------------------------------------------------
$ff = if ($NoForceFullRun) { '' } else { '-ForceFullRun' }
# Per-launcher args. PrivilegeTierClassifier doesn't accept -ForceFullRun
# (it always rebuilds the full tier-definitions JSON by design -- no cadence
# skip to bypass). RA launchers take -ReportTemplate, not -ForceFullRun.
#
# Default plan = 6 collectors + 2 RA passes. PrivilegeTierClassifier (PTC)
# is OFF by default because it's slow (rebuilds the full tier-definitions
# JSON via Azure OpenAI every run) and the catalog rarely changes between
# demos. To run PTC standalone (no other engines, single window), pass
# -PrivilegeTierClassifier. Identity discovery requires the catalog JSON;
# if missing on a fresh install, run -PrivilegeTierClassifier once first,
# then the default plan.
#
# WaitForFile = a path the orchestrator polls (up to WaitTimeoutSec) before
# launching the next plan item. Reserved for future use; current plans
# don't set it (PTC always runs solo when -PrivilegeTierClassifier is on).
# Reusable plan-item definitions. Build the actual $plan from these based on
# which subset switch was passed. Order in the per-subset arrays = launch order.
$endpointItem  = @{ Title = 'SI - Endpoint';    Path = "$Root\launcher\endpoint\launcher.$Flavour-vm.ps1";    Args = $ff }
$azureItem     = @{ Title = 'SI - Azure';       Path = "$Root\launcher\azure\launcher.$Flavour-vm.ps1";       Args = $ff }
$identityItem  = @{ Title = 'SI - Identity';    Path = "$Root\launcher\identity\launcher.$Flavour-vm.ps1";    Args = $ff }
$publicIpItem  = @{ Title = 'SI - PublicIP';    Path = "$Root\launcher\publicip\launcher.$Flavour-vm.ps1";    Args = $ff }
$raDetailedItem= @{ Title = 'SI - RA Detailed'; Path = "$Root\launcher\risk-analysis\launcher.$Flavour-vm.ps1"; Args = '-ReportTemplate "RiskAnalysis_Detailed"' }
$raSummaryItem = @{ Title = 'SI - RA Summary';  Path = "$Root\launcher\risk-analysis\launcher.$Flavour-vm.ps1"; Args = '-ReportTemplate "RiskAnalysis_Summary"' }
$ptcItem       = @{ Title = 'SI - PrivilegeTierClassifier'; Path = "$Root\launcher\privilege-tier-classifier\launcher.$Flavour-vm.ps1"; Args = '' }

if ($PrivilegeTierClassifier) {
    $plan = @($ptcItem)
} elseif ($InitialProfilersOnly) {
    # First-run pattern: get core Profile_CL tables populated before downstream
    # engines (PublicIP needs tier signals; RA queries all four tables).
    $plan = @($endpointItem, $azureItem, $identityItem)
} elseif ($ProfilersOnly) {
    # All four collectors, no RA. Use to refresh Profile tables when RA output
    # is still current.
    $plan = @($endpointItem, $azureItem, $identityItem, $publicIpItem)
} elseif ($RiskAnalysisOnly) {
    # RA-only rerun. Cheaper than the full fanout when Profile tables already fresh.
    $plan = @($raDetailedItem, $raSummaryItem)
} else {
    # Default: 4 collectors + 2 RA passes (full fanout).
    $plan = @($endpointItem, $azureItem, $identityItem, $publicIpItem, $raDetailedItem, $raSummaryItem)
}

# ---------------------------------------------------------------------------
# 6. Fire each window via cmd /c start (rock-solid for parallel spawns)
# ---------------------------------------------------------------------------
$mode = if ($Sequential) { 'sequential' } else { 'parallel' }
Write-Host ("`n==> launching {0} windows ({1} mode, {2}s stagger)" -f $plan.Count, $mode, $StaggerSeconds) -ForegroundColor Cyan

$launched = @()
$skipped  = @()
$i = 0
foreach ($p in $plan) {
    $i++
    Write-Host ("[{0}/{1}] {2}" -f $i, $plan.Count, $p.Title) -ForegroundColor Cyan
    if (-not (Test-Path -LiteralPath $p.Path)) {
        Write-Host ('    SKIP: not found at ' + $p.Path) -ForegroundColor Red
        $skipped += $p.Title
        continue
    }
    $psCmd = ('powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File "{0}" {1}' -f $p.Path, $p.Args).Trim()
    $cmdLine = ('start "{0}" /D "{1}" {2}' -f $p.Title, (Split-Path -Parent $p.Path), $psCmd)
    & cmd.exe /c $cmdLine
    if ($LASTEXITCODE -eq 0) {
        Write-Host '    OK -- launched' -ForegroundColor Green
        $launched += $p.Title
    } else {
        Write-Host ('    FAIL -- cmd exit ' + $LASTEXITCODE) -ForegroundColor Red
        $skipped += $p.Title
    }
    if ($Sequential) {
        Write-Host '    (sequential mode -- waiting for window to close)' -ForegroundColor Gray
        do {
            Start-Sleep -Seconds 2
            $running = Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.ProcessId -ne $mePid -and $_.CommandLine -like ('*' + (Split-Path -Leaf $p.Path) + '*') }
        } while ($running)
    } elseif ($p.ContainsKey('WaitForFile') -and $p.WaitForFile) {
        # Block before firing the next launcher until this one writes its
        # gate file. PrivilegeTierClassifier must finish before the 6
        # collectors fan out; identity discovery throws without the catalog.
        $waitSec = if ($p.ContainsKey('WaitTimeoutSec')) { [int]$p.WaitTimeoutSec } else { 300 }
        Write-Host ("    (gating: waiting up to {0}s for {1})" -f $waitSec, $p.WaitForFile) -ForegroundColor Gray
        $deadline = (Get-Date).AddSeconds($waitSec)
        while ((Get-Date) -lt $deadline -and -not (Test-Path -LiteralPath $p.WaitForFile)) {
            Start-Sleep -Seconds 3
        }
        if (Test-Path -LiteralPath $p.WaitForFile) {
            Write-Host '    (gate file present -- continuing)' -ForegroundColor Green
        } else {
            Write-Host ('    (gate file STILL missing after {0}s -- continuing anyway; downstream launchers may fail)' -f $waitSec) -ForegroundColor Yellow
        }
    } elseif ($i -lt $plan.Count) {
        Start-Sleep -Seconds $StaggerSeconds
    }
}

# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------
Write-Host ('=' * 80) -ForegroundColor Cyan
Write-Host ('Launched: {0} / {1}' -f $launched.Count, $plan.Count) -ForegroundColor Green
$launched | ForEach-Object { Write-Host ('  + ' + $_) -ForegroundColor Green }
if ($skipped.Count -gt 0) {
    Write-Host 'SKIPPED / FAILED:' -ForegroundColor Red
    $skipped | ForEach-Object { Write-Host ('  - ' + $_) -ForegroundColor Red }
}
Write-Host ('=' * 80) -ForegroundColor Cyan
Write-Host "`nIf any windows aren't visible: Alt-Tab through them, or check Windows taskbar (each shows the SI - <Engine> title)." -ForegroundColor Yellow
