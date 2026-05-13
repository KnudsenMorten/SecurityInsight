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
        [string]$Scope = 'AllUsers',

        [switch]$Required,
        [switch]$Import,
        [switch]$Quiet,

        # v2.2.238 -- modules in this list get an additional PSGallery version
        # check after the on-disk probe. When the gallery has a newer version
        # than the local copy, Install-Module is called to pull the update.
        # Throttled per module via $env:TEMP\si-modcheck-<mod>.json (one hit
        # per 24h max) so repeated engine runs don't spam Find-Module.
        # Default empty; Ensure-SecurityInsightModules passes
        # @('AzLogDcrIngestPS','MicrosoftGraphPS') (Morten's own modules where
        # we want customers on the latest).
        [string[]]$KeepLatest = @(),

        # Force the gallery check to run even when the per-module marker file
        # says we already checked within the last 24h. Useful for ad-hoc runs.
        [switch]$ForceUpdateCheck
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

    # Resolve scope once.
    #   'AllUsers'    -- C:\Program Files\WindowsPowerShell\Modules (shared; needs admin).
    #   'CurrentUser' -- %USERPROFILE%\Documents\WindowsPowerShell\Modules.
    #   'Auto'        -- AllUsers when elevated, CurrentUser otherwise.
    $isAdmin = $false
    try {
        $cur = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]::new($cur)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { }

    $effectiveScope = $Scope
    if ($Scope -eq 'Auto') {
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
            Write-Host ("[MODULE] probing {0} ..." -f $mod) -ForegroundColor White
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

            # v2.2.238 -- PSGallery upgrade probe for modules in $KeepLatest.
            # Hits Find-Module at most once per 24h per module (marker file in
            # $env:TEMP) so we don't spam the gallery on every engine run.
            if ($KeepLatest -contains $mod) {
                $markerPath = Join-Path $env:TEMP ("si-modcheck-{0}.json" -f $mod)
                $checkNow   = [bool]$ForceUpdateCheck
                if (-not $checkNow) {
                    if (Test-Path -LiteralPath $markerPath) {
                        try {
                            $last = (Get-Item -LiteralPath $markerPath).LastWriteTimeUtc
                            if (([datetime]::UtcNow - $last).TotalHours -ge 24) { $checkNow = $true }
                        } catch { $checkNow = $true }
                    } else { $checkNow = $true }
                }

                if ($checkNow) {
                    try {
                        $gallery = Find-Module -Name $mod -Repository PSGallery -ErrorAction Stop
                        $localV  = try { [version]$existing.Version } catch { [version]'0.0.0' }
                        $remoteV = try { [version]$gallery.Version }  catch { [version]'0.0.0' }
                        if ($remoteV -gt $localV) {
                            _SayWarn ("{0} update available: local v{1} -> PSGallery v{2} -- installing..." -f $mod, $localV, $remoteV)
                            try {
                                Install-Module -Name $mod -Scope $effectiveScope -Force -AllowClobber -ErrorAction Stop
                                _SayOk ("{0} upgraded to v{1}" -f $mod, $remoteV)
                                # Force re-import so the new version is the one PowerShell uses
                                # this run (otherwise the old loaded version sticks until next session).
                                Remove-Module -Name $mod -Force -ErrorAction SilentlyContinue
                                if ($Import) { Import-Module -Name $mod -RequiredVersion $remoteV -ErrorAction SilentlyContinue -WarningAction SilentlyContinue }
                            } catch {
                                _SayWarn ("{0} upgrade attempt failed (continuing with local v{1}): {2}" -f $mod, $localV, $_.Exception.Message)
                            }
                        } else {
                            _SayOk ("{0} is current (PSGallery v{1})" -f $mod, $remoteV)
                        }
                    } catch {
                        _SayWarn ("{0} PSGallery version check failed (continuing with local): {1}" -f $mod, $_.Exception.Message)
                    }
                    # Stamp the marker even when the gallery query failed so a
                    # broken PSGallery doesn't make every run pay for the probe.
                    try { '' | Out-File -FilePath $markerPath -Encoding ASCII -Force } catch { }
                }
            }
        } else {
            # Fail fast with a clear message if we need to install to AllUsers
            # but the session is not elevated. Without this the customer gets
            # a cryptic PackageManagement / NuGet "access denied" trace.
            if ($effectiveScope -eq 'AllUsers' -and -not $isAdmin) {
                $errMsg = @"
'$mod' is not installed and -Scope AllUsers requires an elevated PowerShell session.
Options:
  (a) Re-launch PowerShell as Administrator and run Step 0 again, OR
  (b) Call Ensure-Module / Ensure-SecurityInsightModules with -Scope CurrentUser
      if you accept a per-user install under %USERPROFILE%\Documents\WindowsPowerShell\Modules.
"@
                _SayErr $errMsg
                throw $errMsg
            }
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
    Ensure every module any SecurityInsight engine might need is INSTALLED on disk.

.DESCRIPTION
    Calls Ensure-Module with the canonical SecurityInsight module set. Safe to call
    from any engine; already-present modules short-circuit instantly.

    Does NOT call Import-Module. PowerShell's automatic module loading imports
    a module the first time any of its cmdlets is invoked, which is both faster
    (meta-modules like Az would otherwise force-load 70+ submodules upfront)
    and quieter (no "unapproved verbs" warnings). If an engine needs a specific
    module's exports visible in a non-default scope (e.g. -Global for cross-
    dot-source visibility), it should call Import-Module explicitly.

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
        [string]$Scope = 'AllUsers',
        [switch]$Quiet,
        [switch]$Required
    )

    # Install / verify every required module is present on disk. NO Import-Module
    # anywhere. PowerShell auto-loads a module the first time a cmdlet from it
    # is called (Connect-AzAccount -> Az.Accounts, Get-MgContext -> Microsoft.Graph.Authentication,
    # ConvertFrom-Yaml -> powershell-yaml, Export-Excel -> ImportExcel, etc.).
    # Eagerly importing Az or Microsoft.Graph meta-modules force-loads 70+ submodules
    # and blocks the script for 2-5 minutes with noisy "unapproved verbs" warnings.
    #
    # v2.2.238 -- KeepLatest = Morten's own modules (AzLogDcrIngestPS, MicrosoftGraphPS).
    # PSGallery query throttled to once per 24h per module (marker in $env:TEMP).
    $null = Ensure-Module `
        -Name       $script:SecurityInsight_RequiredModules `
        -Scope      $Scope `
        -Quiet:$Quiet `
        -Required:$Required `
        -KeepLatest @('AzLogDcrIngestPS','MicrosoftGraphPS')
}
