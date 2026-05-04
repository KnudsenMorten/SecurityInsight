#Requires -Version 5.1
<#
    Read-EntraProviderData.ps1

    Provider-contract function (ARCHITECTURE.md § 6 / _PROVIDER_CONTRACT.md).
    Bulk-fetches Entra identities for the identity engine. Wraps the
    existing v2.2 discovery scripts so the legacy `discovery/Get-Discovery
    FromEntra*.ps1` callers continue to work unchanged.

    Returns: array of [hashtable] asset rows (the same shape Stage Collect
    receives today).
#>

function Read-EntraProviderData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter()]$RunContext
    )

    if ($Engine -ne 'identity') {
        Write-Verbose ("Read-EntraProviderData: skipping engine '{0}' (entra provider serves only 'identity')" -f $Engine)
        return @()
    }

    # Resolve discovery script paths
    $v22Root  = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $discRoot = Join-Path $v22Root 'engine\asset-profiling\discovery'
    $usersScript = Join-Path $discRoot 'Get-DiscoveryFromEntraUsers.ps1'
    $spsScript   = Join-Path $discRoot 'Get-DiscoveryFromEntraServicePrincipals.ps1'

    if (-not (Test-Path $usersScript) -or -not (Test-Path $spsScript)) {
        throw ('Read-EntraProviderData: missing legacy discovery scripts under {0}. Provider wraps the existing implementation; bare-metal Graph calls land in .' -f $discRoot)
    }

    . $usersScript
    . $spsScript

    $rows = New-Object System.Collections.ArrayList

    Write-Verbose 'Read-EntraProviderData: fetching users (active + deleted)...'
    $users = Get-DiscoveryFromEntraUsers
    if ($users) { foreach ($u in $users) { [void]$rows.Add($u) } }

    Write-Verbose 'Read-EntraProviderData: fetching service principals...'
    $sps = Get-DiscoveryFromEntraServicePrincipals
    if ($sps) { foreach ($s in $sps) { [void]$rows.Add($s) } }

    Write-Verbose ('Read-EntraProviderData: returned {0} rows ({1} users + SPs)' -f $rows.Count, $rows.Count)
    return $rows.ToArray()
}
