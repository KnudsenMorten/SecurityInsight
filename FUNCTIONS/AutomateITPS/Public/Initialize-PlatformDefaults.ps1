function Initialize-PlatformDefaults {
<#
.SYNOPSIS
    Dot-sources the Layer-1 platform-wide defaults file so engines can rely on
    shared $global:* values (Mail_*, *LogAnalytics*, AD_*, AzMGPolicy_*, etc.)
    that used to live in v1 Automation-DefaultVariables.psm1.

.DESCRIPTION
    4-layer config model in v2:

      Layer 1  Shared platform-wide defaults   THIS function
      Layer 2  Per-solution launcher override  launcher.override.ps1 sibling
      Layer 3  Secrets (KV)                     Initialize-PlatformAutomationFramework
      Layer 4  Shipped solution defaults        SOLUTIONS/<X>/DATA/*

    Layer 1 lives under:
      <repo-root>\SOLUTIONS\PlatformConfiguration\CUSTOMDATA\platform-defaults.ps1

    That path is per-host (customer owns it, gitignored, never overwritten by
    Update-Platform). A committed .sample.ps1 sibling documents the schema and
    lists every expected $global:* name; customers copy sample -> real and
    fill in their tenant values. First-time setup:

      cd C:\AutomateIT\SOLUTIONS\PlatformConfiguration\CUSTOMDATA
      Copy-Item platform-defaults.sample.ps1 platform-defaults.ps1
      notepad platform-defaults.ps1

    Engines call this early in their AutomationFramework branch, after
    Initialize-PlatformAutomationFramework (which sets the Layer-3 secrets +
    v1-contract HighPriv_* names), so that $global:* values referenced by
    engine bodies resolve.

.PARAMETER RepoRoot
    Repo root to locate platform-defaults.ps1 from. Auto-discovered by walking
    up from the caller's location if omitted.

.PARAMETER Path
    Explicit file path, overrides all path discovery.

.PARAMETER RequireFile
    Throw if no platform-defaults.ps1 exists at the resolved path. Default is
    to warn and return 0 (engines that do not need Layer-1 defaults still run).

.OUTPUTS
    [int] number of new $global:* names populated (0 if no file was loaded).

.EXAMPLE
    # Typical engine usage
    $ctx = Initialize-PlatformAutomationFramework -IgnoreMissingSecrets
    Initialize-PlatformDefaults | Out-Null
    # $global:Mail_From, $global:MainLogAnalyticsWorkspaceResourceId, etc. now set.
#>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [string]$RepoRoot,
        [string]$Path,
        [switch]$RequireFile
    )

    if (-not $Path) {
        if (-not $RepoRoot) {
            # Walk up from either $PSScriptRoot of the caller (via $MyInvocation)
            # or the current working directory, looking for the AutomateITPS module.
            $start = $PWD.Path
            if ($MyInvocation.PSCommandPath) {
                $start = Split-Path -Parent $MyInvocation.PSCommandPath
            }
            $cur = $start
            while ($cur) {
                if (Test-Path (Join-Path $cur 'FUNCTIONS\AutomateITPS\AutomateITPS.psd1')) { $RepoRoot = $cur; break }
                $parent = Split-Path -Parent $cur
                if (-not $parent -or $parent -eq $cur) { break }
                $cur = $parent
            }
        }
        if (-not $RepoRoot) {
            if ($RequireFile) {
                throw "Initialize-PlatformDefaults: cannot locate repo root; pass -RepoRoot or -Path."
            }
            Write-Verbose "Initialize-PlatformDefaults: repo root not found; no defaults loaded."
            return 0
        }
        $Path = Join-Path $RepoRoot 'SOLUTIONS\PlatformConfiguration\CUSTOMDATA\platform-defaults.ps1'
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        if ($RequireFile) {
            throw ("Initialize-PlatformDefaults: file not found at {0}. Copy platform-defaults.sample.ps1 -> platform-defaults.ps1 and fill in tenant values." -f $Path)
        }
        Write-Verbose "Initialize-PlatformDefaults: $Path not present; no defaults loaded."
        return 0
    }

    $before = @(Get-Variable -Scope Global -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)

    try {
        $src = Get-Content -LiteralPath $Path -Raw
        # Scriptblock-dot-source so $global:* assignments from the file land in
        # the caller's (= the engine's) global scope.
        # The file may reference $global:PathScripts or other AF-mode globals
        # that are not always populated yet; disable StrictMode for the span
        # of the load so missing-variable reads do not hard-fail.
        $prevStrict = Get-Variable -Name StrictModeVersion -Scope Global -ErrorAction SilentlyContinue
        try { Set-StrictMode -Off } catch {}
        try {
            $sb = [scriptblock]::Create($src)
            . $sb
        } finally {
            # Restore StrictMode if the caller had it set; otherwise leave off.
            if ($prevStrict) {
                try { Set-StrictMode -Version $prevStrict.Value } catch {}
            }
        }
    } catch {
        throw ("Initialize-PlatformDefaults: failed loading '{0}': {1}" -f $Path, $_.Exception.Message)
    }

    $after = @(Get-Variable -Scope Global -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    $new   = @($after | Where-Object { $_ -notin $before })
    Write-Verbose ("Initialize-PlatformDefaults: loaded {0} new global(s) from {1}" -f $new.Count, $Path)
    return $new.Count
}
