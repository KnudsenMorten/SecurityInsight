function Set-PlatformConfig {
<#
.SYNOPSIS
    Write bootstrap\platform-config.json (the per-VM platform-foundation file).

.DESCRIPTION
    Used by Initialize-PlatformVm + Convert-V1ToPlatform to lay down a fresh
    config. Validates per-mode required fields, writes pretty JSON (UTF-8 no
    BOM).

    Two auth modes:
      ManagedIdentity (Azure-hosted compute) -- only TenantId/SubId/KvName
                                                required; no AppId/Thumb.
      Certificate    (anywhere, incl. on-prem) -- TenantId/SubId/KvName +
                                                  BootstrapAppId +
                                                  BootstrapThumbprint required.
      Auto           -- BootstrapAuth='Auto' written to file. AppId/Thumb
                        optional; if present, used as Certificate fallback
                        when IMDS isn't reachable at runtime.

.PARAMETER Path
    Override path. Default: <repo>\bootstrap\platform-config.json.

.PARAMETER TenantId
    Azure AD tenant GUID.

.PARAMETER SubscriptionId
    Azure subscription GUID where the platform Key Vault lives.

.PARAMETER KeyVaultName
    Platform KV short name (no FQDN).

.PARAMETER BootstrapAuth
    'Auto' | 'ManagedIdentity' | 'Certificate'. Default 'Auto'.

.PARAMETER BootstrapAppId
    Bootstrap SPN AppId (cert-auth, KV-read-only). Required if
    BootstrapAuth=Certificate. Optional for Auto. Ignored for ManagedIdentity.

.PARAMETER BootstrapThumbprint
    Bootstrap SPN cert thumbprint. Same rules as BootstrapAppId.

.PARAMETER Force
    Overwrite existing platform-config.json without prompting.

.EXAMPLE
    # MI mode (Azure VM / Container)
    Set-PlatformConfig -TenantId $t -SubscriptionId $s -KeyVaultName 'kv-x' `
                       -BootstrapAuth ManagedIdentity -Force

.EXAMPLE
    # Cert mode (on-prem)
    Set-PlatformConfig -TenantId $t -SubscriptionId $s -KeyVaultName 'kv-x' `
                       -BootstrapAuth Certificate `
                       -BootstrapAppId $a -BootstrapThumbprint $tp -Force
#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter()] [string]$Path,
        [Parameter(Mandatory)] [string]$TenantId,
        [Parameter(Mandatory)] [string]$SubscriptionId,
        [Parameter(Mandatory)] [string]$KeyVaultName,
        [ValidateSet('Auto','ManagedIdentity','Certificate')]
        [string]$BootstrapAuth = 'Auto',
        [string]$BootstrapAppId,
        [string]$BootstrapThumbprint,
        [switch]$Force
    )

    if ($BootstrapAuth -eq 'Certificate') {
        if ([string]::IsNullOrWhiteSpace($BootstrapAppId) -or [string]::IsNullOrWhiteSpace($BootstrapThumbprint)) {
            throw "Set-PlatformConfig: BootstrapAuth=Certificate requires both -BootstrapAppId and -BootstrapThumbprint."
        }
    }

    if (-not $Path) {
        $repoRoot = $PSScriptRoot
        while ($repoRoot -and -not (Test-Path (Join-Path $repoRoot 'bootstrap'))) {
            $parent = Split-Path -Parent $repoRoot
            if ($parent -eq $repoRoot) { break }
            $repoRoot = $parent
        }
        if (-not $repoRoot) {
            throw "Set-PlatformConfig: cannot locate repo root from $PSScriptRoot. Pass -Path."
        }
        $Path = Join-Path $repoRoot 'bootstrap\platform-config.json'
    }

    if ((Test-Path -LiteralPath $Path) -and -not $Force) {
        throw "Set-PlatformConfig: $Path exists. Use -Force to overwrite."
    }

    $obj = [ordered]@{
        '$schema'      = 'AutomateIT.PlatformConfig/v2.3'
        TenantId       = $TenantId
        SubscriptionId = $SubscriptionId
        KeyVaultName   = $KeyVaultName
        BootstrapAuth  = $BootstrapAuth
    }
    if ($BootstrapAppId)      { $obj['BootstrapAppId']      = $BootstrapAppId }
    if ($BootstrapThumbprint) { $obj['BootstrapThumbprint'] = ($BootstrapThumbprint -replace '\s','').ToUpperInvariant() }

    if ($PSCmdlet.ShouldProcess($Path, 'Write platform-config.json')) {
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

        $json = $obj | ConvertTo-Json -Depth 4
        [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
        Write-Verbose "Set-PlatformConfig: wrote $Path"
    }
}
