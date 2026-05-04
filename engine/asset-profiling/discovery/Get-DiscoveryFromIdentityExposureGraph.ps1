#Requires -Version 5.1
<#
    Identity-side Exposure Graph enrichment connector.

    Pulls EG nodes labeled 'user', 'serviceprincipal', 'group',
    'managedidentity'. Returns a name+id-keyed map ready for join with
    EntraUsers / EntraServicePrincipals discovered from Graph (master).

    Master vs enrichment contract:
      Entra is the SOURCE OF TRUTH for identity existence + canonical
      attributes (UPN, displayName, accountEnabled, etc.). EG is OPTIONAL
      enrichment: when present, contributes high-signal fields like
      hasAdLeakedCredentials, hasLeakedCredentials, isActive, identityType,
      adSid. When absent (new identity Entra knows about but EG hasn't seen
      yet), the asset still flows through with Entra fields populated and
      EG fields null -- no exception, no block.

    Enrichment fields we extract (from NodeProperties.rawData JSON):
      ENTRA_HasAdLeakedCredentials   (high-criticality signal)
      ENTRA_HasLeakedCredentials     (high-criticality signal)
      ENTRA_IsActive                 (active in last 30d)
      ENTRA_IdentityType             (User|ServiceAccount|Computer)
      ENTRA_AccountDomain            (on-prem AD domain when synced)
      ENTRA_PrimaryProvider          (ActiveDirectory|AzureAD)
      ENTRA_AdSid                    (on-prem AD SID when synced)
      ENTRA_DistinguishedName        (on-prem AD DN)
      ENTRA_HasServicePrincipalName  (SPN-bearing user/computer account)
      EG_NodeId                      (for cross-engine joins)
      EG_NodePropertiesRaw           (full props JSON for AI metaprofile reuse)
#>

function Get-DiscoveryFromIdentityExposureGraph {
    [CmdletBinding()]
    param([switch]$AllowEmptyOnStub)

    if ($AllowEmptyOnStub) {
        Write-Warning 'IdentityExposureGraph stubbed off via -AllowEmptyOnStub. Returning empty map.'
        return @{}
    }

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")
    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('IdentityExposureGraph: token failed -- {0}' -f $_.Exception.Message)
        return @{}
    }

    # NodeProperties is dynamic; cast to string to avoid 'distinct on dynamic'
    # 400 errors (same fix used in endpoint EG connector).
    $kql = @'
ExposureGraphNodes
| where NodeLabel in~ ('user','serviceprincipal','managedidentity','group')
| project NodeId, NodeName, NodeLabel, NodePropertiesJson = tostring(NodeProperties)
'@

    try {
        $resp = Invoke-RestMethod -Method Post `
            -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } `
            -Body (@{ Query = $kql } | ConvertTo-Json -Compress) -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        Write-Warning ('IdentityExposureGraph: query failed -- {0}' -f $msg)
        return @{}
    }

    $rows = if ($resp.results) { $resp.results } elseif ($resp.Results) { $resp.Results } else { @() }

    # Build a multi-keyed map so the join in Stage Collect can hit by
    # any of: lowercased UPN, lowercased displayName, EG NodeId.
    # Entra-master record carries UPN + displayName + objectId; the EG
    # NodeName usually matches displayName (best-effort match).
    $byKey = @{}
    foreach ($r in $rows) {
        $rawData = $null
        if (-not [string]::IsNullOrWhiteSpace($r.NodePropertiesJson)) {
            try {
                $props = ConvertFrom-Json -InputObject $r.NodePropertiesJson -ErrorAction Stop
                $rawData = if ($props.rawData) { $props.rawData } else { $props }
            } catch { }
        }

        $enrichment = @{
            ENTRA_HasAdLeakedCredentials  = if ($rawData -and $rawData.PSObject.Properties['hasAdLeakedCredentials']) { [bool]$rawData.hasAdLeakedCredentials } else { $null }
            ENTRA_HasLeakedCredentials    = if ($rawData -and $rawData.PSObject.Properties['hasLeakedCredentials'])   { [bool]$rawData.hasLeakedCredentials }   else { $null }
            ENTRA_IsActive                = if ($rawData -and $rawData.PSObject.Properties['isActive'])                { [bool]$rawData.isActive }                else { $null }
            ENTRA_IdentityType            = if ($rawData -and $rawData.PSObject.Properties['identityType'])            { [string]$rawData.identityType }          else { $null }
            ENTRA_AccountDomain           = if ($rawData -and $rawData.PSObject.Properties['accountDomain'])           { [string]$rawData.accountDomain }         else { $null }
            ENTRA_PrimaryProvider         = if ($rawData -and $rawData.PSObject.Properties['primaryProvider'])         { [string]$rawData.primaryProvider }       else { $null }
            ENTRA_AdSid                   = if ($rawData -and $rawData.PSObject.Properties['adSid'])                   { [string]$rawData.adSid }                 else { $null }
            ENTRA_DistinguishedName       = if ($rawData -and $rawData.PSObject.Properties['distinguishedName'])       { [string]$rawData.distinguishedName }     else { $null }
            ENTRA_HasServicePrincipalName = if ($rawData -and $rawData.PSObject.Properties['hasServicePrincipalName']) { [bool]$rawData.hasServicePrincipalName } else { $null }
            EG_NodeId                     = $r.NodeId
            EG_NodeLabel                  = $r.NodeLabel
            EG_NodePropertiesRaw          = $r.NodePropertiesJson
            # Audit-gap-fill: MS-computed risk + identity-context signals
            EG_MsCriticalityLevel         = if ($rawData -and $rawData.PSObject.Properties['criticalityLevel'])      { [string]$rawData.criticalityLevel }      else { $null }
            EG_IsCompromisedRecently      = if ($rawData -and $rawData.PSObject.Properties['isCompromisedRecently']) { [bool]$rawData.isCompromisedRecently }   else { $null }
            EG_IsExternalUser             = if ($rawData -and $rawData.PSObject.Properties['externalUser'])          { [bool]$rawData.externalUser }            else { $null }
            EG_OnPremSyncEnabled          = if ($rawData -and $rawData.PSObject.Properties['onPremSyncEnabled'])     { [bool]$rawData.onPremSyncEnabled }       else { $null }
            EG_IsMfaCapable               = if ($rawData -and $rawData.PSObject.Properties['isMfaCapable'])          { [bool]$rawData.isMfaCapable }            else { $null }
            EG_IsMfaRegistered            = if ($rawData -and $rawData.PSObject.Properties['isMfaRegistered'])       { [bool]$rawData.isMfaRegistered }         else { $null }
            EG_AccountObjectId            = if ($rawData -and $rawData.PSObject.Properties['accountObjectId'])       { [string]$rawData.accountObjectId }       else { $null }
        }

        if ($r.NodeName) {
            $key = ([string]$r.NodeName).ToLowerInvariant()
            if (-not $byKey.ContainsKey($key)) { $byKey[$key] = $enrichment }
        }
        if ($r.NodeId) {
            $byKey[[string]$r.NodeId] = $enrichment
        }
        # Also key by AccountUpn/AccountObjectId when available in the rawData
        if ($rawData -and $rawData.PSObject.Properties['accountObjectId'] -and $rawData.accountObjectId) {
            $byKey[([string]$rawData.accountObjectId).ToLowerInvariant()] = $enrichment
        }
        if ($rawData -and $rawData.PSObject.Properties['accountUpn'] -and $rawData.accountUpn) {
            $byKey[([string]$rawData.accountUpn).ToLowerInvariant()] = $enrichment
        }
    }
    return $byKey
}
