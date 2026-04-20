#Requires -Version 5.1
<#
.SYNOPSIS
    Ensure one or more PowerShell modules are installed (and optionally imported).

.DESCRIPTION
    Single source of truth for module dependency checks across every
    SecurityInsight engine and launcher. Replaces the per-file `Ensure-Module`
    helpers in engines and the per-launcher `Test-LauncherModule` helpers.

    Usage from an engine (under SCRIPTS/):
        . (Join-Path $PSScriptRoot '_shared\Ensure-Module.ps1')
        Ensure-Module -Name Az.Accounts, powershell-yaml, AzLogDcrIngestPS -Import

    Usage from a launcher (under LAUNCHERS/<engine>/):
        . (Join-Path $InstallPath 'SCRIPTS\_shared\Ensure-Module.ps1')
        Ensure-Module -Name Az.Accounts, Az.KeyVault -Import

.PARAMETER Name
    One or more module names. Required.

.PARAMETER Scope
    'CurrentUser' (default; no admin needed), 'AllUsers' (needs admin), or
    'Auto' (AllUsers if elevated, CurrentUser otherwise).

.PARAMETER Required
    Throw if install fails. Without this, install failures log + continue
    so other modules still get a chance.

.PARAMETER Import
    Also Import-Module after ensuring it's installed. Useful when the
    engine wants the module loaded into the current session.

.PARAMETER Quiet
    Suppress the per-module status lines (still surfaces errors).

.OUTPUTS
    Hashtable mapping <ModuleName> -> $true (installed) / $false (failed).

.NOTES
    Solution   : SecurityInsight
    File       : _shared\Ensure-Module.ps1
    Call it ONCE at the top of each engine / launcher. Safe to call with a
    module that's already loaded -- the Get-Module check short-circuits.
#>

function Ensure-Module {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Name,

        [ValidateSet('CurrentUser','AllUsers','Auto')]
        [string]$Scope = 'Auto',

        [switch]$Required,
        [switch]$Import,
        [switch]$Quiet
    )

    function _SayStep ([string]$m) { if (-not $Quiet) { Write-Host "[MODULE] $m" -ForegroundColor Cyan } }
    function _SayOk   ([string]$m) { if (-not $Quiet) { Write-Host "[MODULE] $m" -ForegroundColor Green } }
    function _SayWarn ([string]$m) { if (-not $Quiet) { Write-Host "[MODULE] $m" -ForegroundColor Yellow } }
    function _SayErr  ([string]$m) { Write-Host "[MODULE] $m" -ForegroundColor Red }

    $results = @{}

    # Announce up front so the user doesn't think the script has hung. On a cold
    # machine the first Get-Module -ListAvailable + PSGallery trust probe + NuGet
    # provider bootstrap can take 10-60 seconds with no other output, which looks
    # exactly like a freeze.
    if (-not $Quiet) {
        Write-Host ""
        Write-Host ("[MODULE] Checking {0} PowerShell module(s) -- this can take a moment on the first run (no output != hung)..." -f @($Name).Count) -ForegroundColor Cyan
    }

    # Resolve scope once. 'Auto' uses AllUsers when elevated, else CurrentUser.
    $effectiveScope = $Scope
    if ($Scope -eq 'Auto') {
        $isAdmin = $false
        try {
            $cur = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = [Security.Principal.WindowsPrincipal]::new($cur)
            $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch { }
        $effectiveScope = if ($isAdmin) { 'AllUsers' } else { 'CurrentUser' }
    }

    # PSGallery must be trusted for non-interactive installs. Skip if already trusted.
    try {
        $gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($gallery -and $gallery.InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        }
    } catch { }

    # Well-known module roots -- probe these directly as a belt-and-suspenders
    # fallback if Get-Module -ListAvailable misses something (e.g. a corrupted
    # module manifest, a meta-module with no exported commands, a PSModulePath
    # that doesn't include the scope where the customer installed the module).
    $pf = [Environment]::GetFolderPath('ProgramFiles')
    $moduleRoots = @(
        (Join-Path $pf 'WindowsPowerShell\Modules'),   # PS 5.1 AllUsers
        (Join-Path $pf 'PowerShell\Modules'),           # PS 7+ AllUsers
        (Join-Path $env:USERPROFILE 'Documents\WindowsPowerShell\Modules'),
        (Join-Path $env:USERPROFILE 'Documents\PowerShell\Modules')
    )

    foreach ($mod in $Name) {
        if ([string]::IsNullOrWhiteSpace($mod)) { continue }

        if (-not $Quiet) {
            Write-Host ("[MODULE] probing {0} ..." -f $mod) -ForegroundColor DarkGray
        }

        # FAST PATH: direct directory lookup in the 4 well-known module roots.
        # `Get-Module -ListAvailable -Name X` is bafflingly slow for Az /
        # Microsoft.Graph / Microsoft.Graph.Beta because PowerShell scans
        # EVERY sibling module's manifest on $env:PSModulePath before
        # filtering -- with 70+ Az.* submodules installed that can stall
        # for 30+ seconds per call. Doing a Test-Path + single manifest
        # read finishes in milliseconds.
        $existing = $null
        foreach ($root in $moduleRoots) {
            $modDir = Join-Path $root $mod
            if (-not (Test-Path -LiteralPath $modDir)) { continue }

            # Module files live at <root>\<mod>\<version>\<mod>.psd1 --
            # pick the highest-version subfolder that has a readable manifest.
            $versionDir = Get-ChildItem -LiteralPath $modDir -Directory -ErrorAction SilentlyContinue |
                          Sort-Object { try { [version]$_.Name } catch { [version]'0.0.0' } } -Descending |
                          Select-Object -First 1
            if (-not $versionDir) { continue }

            $psd = Join-Path $versionDir.FullName "$mod.psd1"
            if (-not (Test-Path -LiteralPath $psd)) {
                # Some modules ship the manifest directly under <mod>\ with no version subfolder.
                $psd = Join-Path $modDir "$mod.psd1"
                if (-not (Test-Path -LiteralPath $psd)) { continue }
            }

            $ver = try {
                $man = Import-PowerShellDataFile -LiteralPath $psd -ErrorAction Stop
                $man.ModuleVersion
            } catch { $versionDir.Name }

            $existing = [pscustomobject]@{
                Name    = $mod
                Version = $ver
                Path    = $psd
            }
            break
        }

        # SLOW FALLBACK: only if the directory scan found nothing. This
        # covers modules installed to non-standard locations added to
        # $env:PSModulePath manually (e.g. system-specific tooling paths).
        if (-not $existing) {
            $existing = Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue |
                        Sort-Object Version -Descending | Select-Object -First 1
        }

        if ($existing) {
            _SayOk ("{0} v{1} present" -f $mod, $existing.Version)
        } else {
            _SayWarn ("{0} missing -- installing to {1}..." -f $mod, $effectiveScope)
            try {
                # NuGet PackageManagement provider is a dependency for Install-Module.
                # Bootstrap silently if the policy prompts.
                if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue |
                          Where-Object { $_.Version -ge [version]'2.8.5.201' })) {
                    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope $effectiveScope -Force -ErrorAction Stop | Out-Null
                }
                Install-Module -Name $mod -Scope $effectiveScope -Force -AllowClobber -ErrorAction Stop
                _SayOk ("{0} installed" -f $mod)
            } catch {
                $errMsg = "{0} install failed: {1}" -f $mod, $_.Exception.Message
                if ($Required) { _SayErr $errMsg; throw $errMsg }
                _SayErr $errMsg
                $results[$mod] = $false
                continue
            }
        }

        if ($Import) {
            try {
                Import-Module -Name $mod -ErrorAction Stop -WarningAction SilentlyContinue
            } catch {
                $errMsg = "{0} import failed: {1}" -f $mod, $_.Exception.Message
                if ($Required) { _SayErr $errMsg; throw $errMsg }
                _SayWarn $errMsg
                $results[$mod] = $false
                continue
            }
        }

        $results[$mod] = $true
    }

    return $results
}

# =====================================================================
#  CANONICAL SecurityInsight MODULE SET
# =====================================================================
# Single source of truth for "which PowerShell modules must exist on
# any VM that runs any SecurityInsight engine". Every engine calls
# Ensure-SecurityInsightModules once at the top, so a fresh customer
# VM auto-installs the full set from PSGallery on first run and no
# engine can trip on a missing module.
#
# Coverage rationale:
#   Az                    -- meta-module that installs every Az.* sub-
#                            module (Az.Accounts, Az.Resources,
#                            Az.OperationalInsights, Az.Monitor, etc.)
#   Az.ResourceGraph      -- NOT part of the Az meta-module; required
#                            separately for Search-AzGraph queries.
#   Microsoft.Graph       -- meta-module for v1.0 Graph submodules
#                            (Authentication, Security, Applications,
#                            Identity.Governance, Identity.DirectoryMgmt).
#   Microsoft.Graph.Beta  -- beta endpoints (used by some inventory paths).
#   AzLogDcrIngestPS      -- custom DCR ingest module (Morten Knudsen).
#   MicrosoftGraphPS      -- Graph helper module (Morten Knudsen).
#   ImportExcel           -- XLSX export used by the report engines.
#   powershell-yaml       -- YAML parse for *_Locked.yaml / *_Custom.yaml.
$script:SecurityInsight_RequiredModules = @(
    'Az'
    'Az.ResourceGraph'
    'Microsoft.Graph'
    'Microsoft.Graph.Beta'
    'AzLogDcrIngestPS'
    'MicrosoftGraphPS'
    'ImportExcel'
    'powershell-yaml'
)

function Ensure-SecurityInsightModules {
<#
.SYNOPSIS
    Ensure every module any SecurityInsight engine might need is installed + imported.

.DESCRIPTION
    Calls Ensure-Module with the canonical SecurityInsight module set. Safe to call
    from any engine; already-present modules short-circuit instantly.

.PARAMETER Scope
    Passed through to Ensure-Module (CurrentUser / AllUsers / Auto).

.PARAMETER Quiet
    Suppress per-module status lines.

.PARAMETER Required
    Throw if any install fails.
#>
    [CmdletBinding()]
    param(
        [ValidateSet('CurrentUser','AllUsers','Auto')]
        [string]$Scope = 'Auto',
        [switch]$Quiet,
        [switch]$Required
    )

    # Discard the returned hashtable so callers don't need `$null = ...` --
    # otherwise PowerShell prints the per-module True/False table to stdout.
    $null = Ensure-Module `
        -Name $script:SecurityInsight_RequiredModules `
        -Scope $Scope `
        -Import `
        -Quiet:$Quiet `
        -Required:$Required
}
