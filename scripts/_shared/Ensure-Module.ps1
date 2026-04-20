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
        [string]$Scope = 'CurrentUser',

        [switch]$Required,
        [switch]$Import,
        [switch]$Quiet
    )

    function _SayStep ([string]$m) { if (-not $Quiet) { Write-Host "[MODULE] $m" -ForegroundColor Cyan } }
    function _SayOk   ([string]$m) { if (-not $Quiet) { Write-Host "[MODULE] $m" -ForegroundColor Green } }
    function _SayWarn ([string]$m) { if (-not $Quiet) { Write-Host "[MODULE] $m" -ForegroundColor Yellow } }
    function _SayErr  ([string]$m) { Write-Host "[MODULE] $m" -ForegroundColor Red }

    $results = @{}

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

    foreach ($mod in $Name) {
        if ([string]::IsNullOrWhiteSpace($mod)) { continue }

        $existing = Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue |
                    Sort-Object Version -Descending | Select-Object -First 1

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
