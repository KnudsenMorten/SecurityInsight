#Requires -Version 5.1
<#
    Test-EntraProviderConnection.ps1

    Provider-contract function (ARCHITECTURE.md § 6 / _PROVIDER_CONTRACT.md).
    Lightweight Microsoft Graph round-trip to verify auth + reachability.

    Returns: @{ Ok = <bool>; Error = <string?>; Detail = <string?> }
#>

function Get-EntraProviderManifest {
    $manifest = Get-Content -Raw (Join-Path $PSScriptRoot 'manifest.json') | ConvertFrom-Json
    return $manifest
}

function Test-EntraProviderConnection {
    [CmdletBinding()]
    param()

    try {
        # Use existing Get-SIGraphToken helper.
        # $PSScriptRoot = providers/entra -> two parents = v2.2 root.
        $v22Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        . (Join-Path $v22Root 'auth\Get-SIGraphToken.ps1')
        $token = Get-SIGraphToken
        if ([string]::IsNullOrWhiteSpace($token)) {
            return @{ Ok = $false; Error = 'Get-SIGraphToken returned empty.'; Detail = 'Check $global:SI_SPN_AppId/Secret/TenantId in custom.ps1.' }
        }

        # Cheapest possible Graph call: count users with $top=1.
        $headers = @{ Authorization = "Bearer $token"; ConsistencyLevel = 'eventual' }
        $resp = Invoke-RestMethod -Method Get `
            -Uri 'https://graph.microsoft.com/v1.0/users?$top=1&$count=true' `
            -Headers $headers -ErrorAction Stop
        return @{
            Ok     = $true
            Detail = ('Graph reachable; total users (count): {0}' -f $resp.'@odata.count')
        }
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        return @{ Ok = $false; Error = $msg; Detail = 'Test-EntraProviderConnection failed -- check SPN scopes (Directory.Read.All).' }
    }
}
