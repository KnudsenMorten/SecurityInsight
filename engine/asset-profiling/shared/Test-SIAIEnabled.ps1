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

    AI also requires the Azure OpenAI endpoint + deployment; when missing, the
    gate returns $false even if the opt-in is set. #1257: NO KEY is needed -- the
    engine signs in to Azure OpenAI as its own identity (engine/_shared/
    SI-OpenAIAuth.ps1, loaded below); a configured OpenAI_apiKey is only the
    fallback.

    Used by:
      Invoke-Classify.ps1     -- per-asset Classify call
      Invoke-Enrich.ps1       -- signal-map / asset-group AI helpers
      Invoke-SchemaPropose.ps1 -- schema-discovery propose
#>

# #1257: the AI sign-in (the engine's identity first, the key only as the fallback) -- every AI caller loads this file
if (-not (Get-Command -Name Invoke-SIOpenAIChat -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared/SI-OpenAIAuth.ps1') }

function Test-SIAIMasterSwitchOff {
    <# PURE. $true when the tenant-wide AI switch is set OFF (SI_EnableAI = false, as a bool or as the text "false" / "0").
       #1304 (Invardia 2026-11-21): AI switched off WINS over every other AI switch -- every SI_EnableAI_<engine>, the
       report-mail AI summary (BuildSummaryByAI) and the tier classifier's RunAI. Not set ($null / empty) is not "off":
       a per-engine opt-in still decides then. #>
    param([AllowNull()]$Value = $global:SI_EnableAI)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return (-not $Value) }
    $t = "$Value".Trim().Trim('"').Trim()
    if (-not $t) { return $false }
    return ($t -match '^(?i:false|0|no|off)$')
}

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

    # #1304: AI switched off for the whole install wins over a per-engine opt-in (SI_EnableAI_<engine> = true)
    if (Test-SIAIMasterSwitchOff) { return $false }

    # Opt-in: tenant-wide OR per-engine.
    $enablePerEngine = "SI_EnableAI_$Engine"
    $optedIn = [bool]$global:SI_EnableAI -or `
               [bool](Get-Variable -Name $enablePerEngine -ValueOnly -Scope Global -ErrorAction SilentlyContinue)
    if (-not $optedIn) { return $false }

    # Endpoint + deployment present? (#1257: no key needed -- the engine signs in as its own identity)
    if (-not ($global:OpenAI_endpoint -and $global:OpenAI_deployment)) {
        return $false
    }

    # The token (or the fallback key) goes ONLY to an Azure OpenAI endpoint (https, an Azure OpenAI / AI services host): another one is left out
    # and said once per session -- AI is skipped, the run goes on.
    $why = Test-SIOpenAIEndpoint -Endpoint ([string]$global:OpenAI_endpoint)
    if ($why) {
        if (-not [bool](Get-Variable -Name 'SI_AIEndpointWarned' -ValueOnly -Scope Global -ErrorAction SilentlyContinue)) {
            Write-Warning ('OpenAI_endpoint is not used: {0}. AI is skipped in this run.' -f $why)
            $global:SI_AIEndpointWarned = $true
        }
        return $false
    }

    return $true
}

function Test-SIOpenAIEndpoint {
    <#
        PURE. '' = -Endpoint (the base, or a full request URI) is an Azure OpenAI endpoint the api-key may go to: https, no
        user info, a host under one of the Azure OpenAI / AI services suffixes (public and sovereign clouds). Else why not.
    #>
    param([AllowEmptyString()][string]$Endpoint = '')
    $suffixes = @('.openai.azure.com', '.cognitiveservices.azure.com', '.services.ai.azure.com',
        '.openai.azure.us', '.cognitiveservices.azure.us', '.openai.azure.cn', '.cognitiveservices.azure.cn',
        # an Azure API Management gateway in front of Azure OpenAI (the web app's OutboundHostPolicy.OpenAiSuffixes)
        '.azure-api.net', '.azure-api.us', '.azure-api.cn')
    $e = "$Endpoint".Trim()
    if (-not $e) { return 'no endpoint is set' }
    $u = $null
    if (-not [Uri]::TryCreate($e, [UriKind]::Absolute, [ref]$u)) { return ("'{0}' is not an address" -f $e) }
    if ($u.Scheme -ne 'https') { return ("'{0}' is not https" -f $e) }
    if ($u.UserInfo) { return ("'{0}' carries a user name" -f $u.Host) }
    $h = $u.Host.ToLowerInvariant()
    foreach ($s in $suffixes) { if ($h.EndsWith($s) -and $h.Length -gt $s.Length) { return '' } }
    ("'{0}' is not an Azure OpenAI host (*.openai.azure.com or *.cognitiveservices.azure.com)" -f $u.Host)
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
