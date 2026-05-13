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
        # v2.2.244 -- the per-module 24h throttle marker was REMOVED. It locked
        # customers to stale versions for up to a day when an upstream module
        # author published a fresh version, defeating the purpose. Find-Module
        # against PSGallery is one HTTPS call (<1s) so probing every run is
        # fine. Module-author publishes a hotfix at 16:00, customer's next
        # engine run picks it up.
        # Default empty; Ensure-SecurityInsightModules passes
        # @('AzLogDcrIngestPS','MicrosoftGraphPS') (Morten's own modules where
        # we want customers on the latest).
        [string[]]$KeepLatest = @(),

        # v2.2.244 -- hard minimum versions. Module-name -> minimum-version
        # string (e.g. @{ AzLogDcrIngestPS = '1.6.3' }). After the on-disk
        # probe + KeepLatest upgrade attempt, if the loaded version is STILL
        # below the minimum, throw a clear error instead of letting downstream
        # calls fail with confusing "parameter not found" messages. The
        # minimum encodes "the engine code requires AT LEAST this version's
        # public surface" -- e.g. AzAppCertificateThumbprint /
        # AzAppCertificateStoreLocation landed in 1.6.3.
        [hashtable]$MinimumVersions = @{}
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

            # v2.2.244 -- PSGallery upgrade probe for modules in $KeepLatest.
            # Probes Find-Module every run (no 24h throttle -- it locked
            # customers to stale versions when the module author published a
            # newer build same day; same-day publish/upgrade is the WHOLE
            # POINT). The probe is one HTTPS call to PSGallery and completes
            # in <1s, cheap enough to run unconditionally.
            #
            # POLICY: install ONLY when remote version > local version
            # (strict greater-than). Module-author workflow is "every publish
            # bumps the version by at least +1 patch", so same-version
            # on disk and gallery means we're already current.
            if ($KeepLatest -contains $mod) {
                # v2.2.263 -- KeepLatest modules (Morten's PSGallery modules:
                # AzLogDcrIngestPS, MicrosoftGraphPS) MUST live in AllUsers
                # (`C:\Program Files\WindowsPowerShell\Modules\`). CurrentUser
                # scope -- especially the OneDrive-redirected Documents folder
                # that most domain-joined Windows machines have these days --
                # is rejected for two reasons:
                #   1. Scheduled tasks / service accounts running under a
                #      different identity don't see CurrentUser modules.
                #   2. OneDrive sync chaos can corrupt or hide module files
                #      mid-run.
                # Operator: "i dont support currentuser".

                # ---- step 1: detect where the currently-installed copy lives ----
                $_inAllUsers   = $existing.Path -like (Join-Path $pf 'WindowsPowerShell\Modules\*') -or
                                 $existing.Path -like (Join-Path $pf 'PowerShell\Modules\*')
                $_isUserScope  = -not $_inAllUsers

                # ---- step 2: ALWAYS emit version snapshot for diagnosis ----
                $_loadedSnapshot = @(Get-Module -Name $mod -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Version)
                $_loadedLabel = if ($_loadedSnapshot.Count -gt 0) { ($_loadedSnapshot -join ',') } else { '<none loaded>' }
                $_scopeLabel = if ($_inAllUsers) { 'AllUsers' } else { 'CurrentUser (REJECTED)' }
                _SayStep ("{0} version snapshot: loaded={1}  on-disk=v{2} @ {3}  PSGallery probe next" -f $mod, $_loadedLabel, $existing.Version, $_scopeLabel)
                _SayStep ("    on-disk path : {0}" -f $existing.Path)

                # ---- step 3: HARD REJECT user-scope copies ----
                # We won't try to "fix" by reinstalling to AllUsers because
                # the old user-scope copy will still be on PSModulePath and
                # auto-load might re-pick it. Operator must remove it manually
                # or run elevated so Install-Module can target AllUsers cleanly.
                if ($_isUserScope) {
                    if (-not $isAdmin) {
                        $errMsg = @"
'$mod' is installed under CurrentUser scope:
    $($existing.Path)
SecurityInsight refuses to run on CurrentUser-scope copies of $mod (scheduled
tasks / service accounts running under a different identity won't see it; OneDrive
sync can corrupt module files mid-run). Fix:
    1) Open an ELEVATED PowerShell session (Run as Administrator)
    2) Run: Install-Module $mod -Scope AllUsers -Force -AllowClobber
    3) Run: Uninstall-Module -Name $mod -RequiredVersion '$($existing.Version)'
       (or delete the user-scope folder manually:
        Remove-Item -Recurse -Force '$($existing.Path | Split-Path -Parent | Split-Path -Parent)')
    4) Close this PowerShell session, open a fresh one, and re-run the launcher.
"@
                        _SayErr $errMsg
                        throw $errMsg
                    }
                    # Admin AND user-scope copy detected: install to AllUsers
                    # (which we'll prefer below) and leave the user-scope copy
                    # for the operator to clean up.
                    _SayWarn ("{0} is in user scope at {1} -- installing fresh copy to AllUsers (you should remove the user-scope folder afterwards)." -f $mod, $existing.Path)
                }

                # ---- step 4: PSGallery upgrade probe ----
                try {
                    $gallery = Find-Module -Name $mod -Repository PSGallery -ErrorAction Stop
                    $localV  = try { [version]$existing.Version } catch { [version]'0.0.0' }
                    $remoteV = try { [version]$gallery.Version }  catch { [version]'0.0.0' }
                    if ($remoteV -gt $localV -or $_isUserScope) {
                        if ($_isUserScope) {
                            _SayWarn ("{0} forced-reinstall to AllUsers (current copy is user-scope) -> PSGallery v{1}" -f $mod, $remoteV)
                        } else {
                            _SayWarn ("{0} update available: local v{1} -> PSGallery v{2} -- installing to AllUsers..." -f $mod, $localV, $remoteV)
                        }
                        if (-not $isAdmin) {
                            $errMsg = "$mod requires upgrade to v$remoteV but AllUsers install needs an elevated PowerShell session. Re-launch PowerShell as Administrator and re-run the launcher."
                            _SayErr $errMsg
                            throw $errMsg
                        }
                        try {
                            Install-Module -Name $mod -Scope AllUsers -Force -AllowClobber -ErrorAction Stop
                            _SayOk ("{0} upgraded to v{1} in AllUsers" -f $mod, $remoteV)
                            # Re-probe disk so $existing reflects the AllUsers install.
                            $_newPsd = Join-Path $pf ("WindowsPowerShell\Modules\$mod\$remoteV\$mod.psd1")
                            if (Test-Path -LiteralPath $_newPsd) {
                                $existing = [pscustomobject]@{ Name = $mod; Version = $remoteV; Path = $_newPsd }
                            } else {
                                $existing = [pscustomobject]@{ Name = $mod; Version = $remoteV; Path = $existing.Path }
                            }
                        } catch {
                            $errMsg = "{0} upgrade to AllUsers FAILED: {1}. Re-launch PowerShell as Administrator and re-run the launcher." -f $mod, $_.Exception.Message
                            _SayErr $errMsg
                            throw $errMsg
                        }
                    } else {
                        _SayOk ("{0} is current (PSGallery v{1}, AllUsers)" -f $mod, $remoteV)
                    }
                } catch {
                    if ($_.Exception.Message -like '*Install-Module*' -or $_.Exception.Message -like '*Re-launch*') { throw }
                    _SayWarn ("{0} PSGallery version check failed (continuing with local): {1}" -f $mod, $_.Exception.Message)
                }

                # ---- step 5: force-reload from AllUsers path ----
                # We Remove-Module first so PowerShell drops any stale in-session
                # copy (including a user-scope one auto-loaded earlier), then
                # Import-Module with an explicit AllUsers manifest path. Path-
                # pinning here is the only way to guarantee we don't re-auto-load
                # the user-scope copy on next cmdlet call.
                $diskV = try { [version]$existing.Version } catch { [version]'0.0.0' }
                $_allUsersPsd = Join-Path $pf ("WindowsPowerShell\Modules\$mod\$diskV\$mod.psd1")
                $_importTarget = if (Test-Path -LiteralPath $_allUsersPsd) { $_allUsersPsd } else { $existing.Path }
                try {
                    Remove-Module -Name $mod -Force -ErrorAction SilentlyContinue
                    Import-Module -Name $_importTarget -Force -ErrorAction Stop -WarningAction SilentlyContinue
                } catch {
                    $errMsg = "{0} force-reload failed: {1}" -f $mod, $_.Exception.Message
                    _SayErr $errMsg
                    throw $errMsg
                }

                # ---- step 6: verify the loaded version came from AllUsers ----
                $_postLoad = Get-Module -Name $mod -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $_postLoad) {
                    $errMsg = "$mod failed to load after force-reload."
                    _SayErr $errMsg
                    throw $errMsg
                }
                $_postPath = [string]$_postLoad.Path
                $_postInAllUsers = $_postPath -like (Join-Path $pf 'WindowsPowerShell\Modules\*') -or
                                   $_postPath -like (Join-Path $pf 'PowerShell\Modules\*')
                if (-not $_postInAllUsers) {
                    $errMsg = @"
'$mod' loaded after force-reload but NOT from AllUsers:
    Loaded: v$($_postLoad.Version) @ $_postPath
SecurityInsight requires $mod to come from AllUsers
(C:\Program Files\WindowsPowerShell\Modules\$mod\<version>\). The user-scope
copy is taking precedence on the PSModulePath. Remove it:
    Remove-Item -Recurse -Force '$($existing.Path | Split-Path -Parent | Split-Path -Parent)'
…and re-run the launcher in a fresh PowerShell session.
"@
                    _SayErr $errMsg
                    throw $errMsg
                }
                _SayOk ("{0} v{1} loaded from AllUsers: {2}" -f $mod, $_postLoad.Version, $_postPath)
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

        # v2.2.261 -- hard minimum-version enforcement looks at the LOADED
        # version, not just on-disk. The force-reload above ensures these
        # match for KeepLatest modules; the check below catches the case
        # where Install-Module silently lost the race (offline tenant,
        # PSGallery throttling) or some other code path imported an older
        # version after Ensure-Module ran. Either way -- if the in-session
        # version is below the declared minimum, throw with a clear message.
        if ($MinimumVersions.ContainsKey($mod) -and $MinimumVersions[$mod]) {
            $minV = try { [version]$MinimumVersions[$mod] } catch { $null }
            if ($minV) {
                $loaded = Get-Module -Name $mod -ErrorAction SilentlyContinue |
                          Sort-Object Version -Descending | Select-Object -First 1
                $onDisk = Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue |
                          Sort-Object Version -Descending | Select-Object -First 1
                # Prefer the loaded version (that's what cmdlet calls will use).
                # If nothing is loaded yet, fall back to the on-disk highest --
                # PowerShell's auto-load picks that one on first cmdlet call.
                $finalV = if ($loaded)  { try { [version]$loaded.Version } catch { [version]'0.0.0' } }
                          elseif ($onDisk) { try { [version]$onDisk.Version } catch { [version]'0.0.0' } }
                          else { [version]'0.0.0' }
                if ($finalV -lt $minV) {
                    # v2.2.263 -- ALWAYS throw on min-version violation. The
                    # previous "soft-fail unless -Required" path silently
                    # logged an error and let the engine continue, which
                    # produced the confusing "A parameter cannot be found
                    # matching 'AzAppCertificateStoreLocation'" failure 100s
                    # of seconds later when the actual cmdlet call missed
                    # a newer parameter. Min-version represents "the engine
                    # WILL crash without this version" -- always terminal.
                    $errMsg = "{0} v{1} is below the engine's required minimum v{2}. The engine code calls cmdlet parameters that didn't exist in older versions. Fix: run 'Install-Module {0} -Force -AllowClobber -Scope AllUsers' (elevated) to force-pull the current PSGallery version, then re-run the engine in a FRESH PowerShell session. If PSGallery is unreachable, install the module manually from https://github.com/KnudsenMorten/{0}." -f $mod, $finalV, $minV
                    _SayErr $errMsg
                    throw $errMsg
                }
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
    # v2.2.244 -- KeepLatest = Morten's own modules (AzLogDcrIngestPS,
    # MicrosoftGraphPS). PSGallery probe runs every engine run (no 24h
    # throttle); strict version comparison (install only when remote > local).
    # MinimumVersions encodes engine-level "must have at least this version's
    # public surface" so engine code that uses newer parameters fails fast
    # with a clear message instead of confusing "parameter not found" errors.
    # AzLogDcrIngestPS 1.6.3 added -AzAppCertificateThumbprint /
    # -AzAppCertificateStoreLocation / -UseManagedIdentity / -EnableCompression.
    # 1.6.4 fixed CheckCreateUpdate-TableDcr-Structure's gate so cert-only
    # auth (no client secret) actually enters the create block instead of
    # returning silently.
    # 1.6.5 and 1.6.6 were intended to add MI to the create chain but shipped
    # without those edits (PSGallery upload race). 1.6.7 carries the actual
    # MI extensions: -UseManagedIdentity / -ManagedIdentityClientId on every
    # function in the DCR create + read chain (CheckCreateUpdate,
    # CreateUpdate-AzData..., CreateUpdate-AzLogAnalytics..., Get-AzDce/DcrListAll,
    # Get-AzLogAnalyticsTableAzDcrStatus), plus the gate widening to accept MI.
    # SI v2.2.262+ requires 1.6.7 minimum so customers running UAMI mode
    # don't hit "A parameter cannot be found matching UseManagedIdentity".
    $null = Ensure-Module `
        -Name            $script:SecurityInsight_RequiredModules `
        -Scope           $Scope `
        -Quiet:$Quiet `
        -Required:$Required `
        -KeepLatest      @('AzLogDcrIngestPS','MicrosoftGraphPS') `
        -MinimumVersions @{ AzLogDcrIngestPS = '1.6.7' }
}
