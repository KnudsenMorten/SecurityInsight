#Requires -Version 5.1
<#
    Returns the Shodan REST API key. Lookup order:
      1. $global:SI_Shodan_ApiKey  (canonical SI-prefixed name, v2.2+)
      2. $global:SHODAN_ApiKey     (legacy v1 alias, still accepted)
      3. $env:SHODAN_API_KEY       (env var fallback for one-off CLI runs)

    Returns $null when neither is set -- callers are expected to skip Shodan
    enrichment gracefully (the publicip engine still emits rows, Shodan-source
    fields land as null with InShodan=false).

    The key is NEVER written to logs, files, or telemetry. Only used as a
    POST/GET query parameter to api.shodan.io. Treat-as-secret rules:
      - Customer rotates via Shodan portal -> reset key, push new value to KV
      - Bootstrap step pulls from KV at run start (same pattern as SI_SPN_Secret)
      - .gitignore covers custom.ps1 so the key never lands in git
#>

function Get-SIShodanKey {
    [CmdletBinding()]
    param([switch]$Quiet)

    $key = $null
    if ($global:SI_Shodan_ApiKey -and -not [string]::IsNullOrWhiteSpace($global:SI_Shodan_ApiKey)) {
        $key = [string]$global:SI_Shodan_ApiKey
    } elseif ($global:SHODAN_ApiKey -and -not [string]::IsNullOrWhiteSpace($global:SHODAN_ApiKey)) {
        $key = [string]$global:SHODAN_ApiKey
    } elseif ($env:SHODAN_API_KEY -and -not [string]::IsNullOrWhiteSpace($env:SHODAN_API_KEY)) {
        $key = [string]$env:SHODAN_API_KEY
    }

    if (-not $key) {
        if (-not $Quiet) {
            Write-Warning 'Shodan API key not configured. Set $global:SI_Shodan_ApiKey in config/SecurityInsight.custom.ps1 (or $env:SHODAN_API_KEY for CLI runs). PublicIP engine will run but Shodan-source fields will be null.'
        }
        return $null
    }
    return $key
}
