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
