#Requires -Version 5.1
<#
    Centralized AI-integration gate for all SI engines.

    AI is OFF BY DEFAULT. Customer must explicitly opt in. Two flags:

      $global:SI_EnableAI                  -- tenant-wide opt-in for all engines
      $global:SI_EnableAI_<engine> = $true -- per-engine opt-in
                                              ($engine in identity, endpoint, azure, publicip)

    Force-OFF takes precedence:
      $global:SI_DisableAI = $true                -- legacy kill-switch
      $global:SI_DisableAI_<engine> = $true       -- per-engine kill
      Engine == 'identity' is hard-disabled regardless (catalog-driven since
        52; AOAI is never appropriate for identity tier classification).

    AI also requires creds (OpenAI_apiKey/endpoint/deployment); when missing,
    the gate returns $false even if the opt-in is set so callers don't blow up
    on credential resolution.

    Used by:
      Invoke-Classify.ps1     -- per-asset Classify call
      Invoke-Enrich.ps1       -- signal-map / asset-group AI helpers
      Invoke-SchemaPropose.ps1 -- schema-discovery propose
#>

function Test-SIAIEnabled {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Engine)

    # Identity is catalog-driven -- never call AI.
    if ($Engine -eq 'identity') { return $false }

    # Public IPs have no AI step: the classifier accepts endpoint / identity / azure only, so an AI call for
    # publicip failed on every asset (#257). Refused for the tenant-wide switch too; an explicit per-engine
    # opt-in left in a config is said ONCE per session, not once per asset.
    if ($Engine -eq 'publicip') {
        if ([bool](Get-Variable -Name 'SI_EnableAI_publicip' -ValueOnly -Scope Global -ErrorAction SilentlyContinue) -and
            -not [bool](Get-Variable -Name 'SI_AIPublicIpWarned' -ValueOnly -Scope Global -ErrorAction SilentlyContinue)) {
            Write-Warning 'SI_EnableAI_publicip is set, but the public IP engine has no AI step -- the setting is ignored. Remove it from your configuration to silence this warning.'
            $global:SI_AIPublicIpWarned = $true
        }
        return $false
    }

    # Legacy + new kill-switch wins over opt-in.
    if ([bool]$global:SI_DisableAI) { return $false }
    $disablePerEngine = "SI_DisableAI_$Engine"
    if ([bool](Get-Variable -Name $disablePerEngine -ValueOnly -Scope Global -ErrorAction SilentlyContinue)) {
        return $false
    }

    # Opt-in: tenant-wide OR per-engine.
    $enablePerEngine = "SI_EnableAI_$Engine"
    $optedIn = [bool]$global:SI_EnableAI -or `
               [bool](Get-Variable -Name $enablePerEngine -ValueOnly -Scope Global -ErrorAction SilentlyContinue)
    if (-not $optedIn) { return $false }

    # Creds present?
    if (-not ($global:OpenAI_apiKey -and $global:OpenAI_endpoint -and $global:OpenAI_deployment)) {
        return $false
    }

    return $true
}

function Get-SIOpenAIApiVersion {
    <#
        The Azure OpenAI API version for a call: $global:OpenAI_apiVersion, else the same fallback Risk Analysis and the
        tier classifier use (launcher\risk-analysis\LauncherConfig.defaults.ps1). The profiling engines had none, so an
        install that set only key / endpoint / deployment sent "api-version=" and every AI call failed (#257).
    #>
    $v = [string]$global:OpenAI_apiVersion
    if ([string]::IsNullOrWhiteSpace($v)) { return '2024-08-01-preview' }
    return $v.Trim()
}
