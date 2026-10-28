function Get-PlatformConfig {
<#
.SYNOPSIS
    Read bootstrap\platform-config.json (the 5-field per-VM platform-foundation file).

.DESCRIPTION
    Convenience reader. Auto-resolves <repo>\bootstrap\platform-config.json from
    $PSScriptRoot if -Path is omitted. Returns a [pscustomobject] with the 5
    fields: TenantId, SubscriptionId, KeyVaultName, BootstrapAppId,
    BootstrapThumbprint.

    Use this when an ops script needs to know the platform identity without
    actually connecting (Connect-Platform reads the same file internally).

.PARAMETER Path
    Override path to platform-config.json. Default: auto-resolve.

.OUTPUTS
    PSCustomObject -- the parsed config.

.EXAMPLE
    $cfg = Get-PlatformConfig
    Write-Host "Platform KV: $($cfg.KeyVaultName)"
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()] [string]$Path
    )

    if (-not $Path) {
        $repoRoot = $PSScriptRoot
        while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'bootstrap'))) {
            $parent = Split-Path -Parent $repoRoot
            if ($parent -eq $repoRoot) { break }
            $repoRoot = $parent
        }
        if (-not $repoRoot) {
            throw "Get-PlatformConfig: cannot locate repo root from $PSScriptRoot. Pass -Path."
        }
        $Path = Join-Path $repoRoot 'bootstrap\platform-config.json'
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Get-PlatformConfig: not found at $Path. Run Initialize-PlatformVm to create one."
    }

    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}
