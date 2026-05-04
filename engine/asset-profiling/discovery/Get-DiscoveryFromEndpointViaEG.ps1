#Requires -Version 5.1
<#
    Endpoint-engine EG-as-source discovery.

    Pulls every device-class node from ExposureGraphNodes verbatim. EG's
    `device` rawData carries Microsoft's curated security posture view
    (onboardingStatus, sensorHealth, antivirusEnabled, atpOnboarded,
    asrRules, lastSeenTime, exposureScore, etc.) -- the things that
    actually matter for tier classification.

    This is now the PRIMARY endpoint discovery source. Existing
    Entra / ARG / MDE connectors continue to run as supplements (they
    catch devices EG hasn't ingested yet, e.g. a freshly-joined Entra
    device or an ARC machine waiting for first heartbeat). Stage Discover
    unions all sources + dedupes by NormalizedKey (lowercased name);
    Entra-master priority stays.

    Asset shape:
      AssetId               -- 'eg:dev:<lowercased-NodeId>'
      Source                -- 'EndpointExposureGraph'
      Hint                  -- 'endpoint' (set by EG NodeProperties.deviceCategory)
      Name                  -- device short name
      NormalizedKey         -- lowercased name for cross-source dedup
      EG_NodeId             -- 32-char EG UUID (! != MDE 40-char SHA1)
      EG_DeviceCategory     -- Endpoint | Server | IoT | NetworkDevice | ...
      EG_OS / EG_OSVersion / EG_OnboardingStatus / EG_SensorHealth / EG_LastSeen
      AZ_PropertiesRawJson  -- VERBATIM EG rawData JSON (same Properties
                                column shape as azure engine for query consistency)
#>

function Get-DiscoveryFromEndpointViaEG {
    [CmdletBinding()]
    param()

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")
    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('Get-DiscoveryFromEndpointViaEG: token failed -- {0}' -f $_.Exception.Message)
        return @()
    }

    # broaden NodeLabel filter to also include Azure VMs and Arc
    # machines. Most servers (DCs, app servers, Linux hosts) are NOT labeled
    # 'device' in ExposureGraphNodes -- they're labeled by their ARM type
    # (microsoft.compute/virtualmachines or microsoft.hybridcompute/machines).
    # The previous narrow filter was missing them entirely, so MDE-merged server
    # records had no AZ_PropertiesRawJson -> Collect's EG-merge branch never
    # fired for them -> Properties.collect.exposureGraph stayed null on every
    # server row in the tenant. Same labels that ADDomainController rule uses.
    $kql = @'
ExposureGraphNodes
| where NodeLabel == "device"
    or NodeLabel == "microsoft.compute/virtualmachines"
    or NodeLabel == "microsoft.hybridcompute/machines"
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
        Write-Warning ('Get-DiscoveryFromEndpointViaEG: query failed -- {0}' -f $msg)
        return @()
    }

    $rows = if ($resp.results) { $resp.results } elseif ($resp.Results) { $resp.Results } else { @() }
    Write-SIInfo ("   EG endpoint discovery: {0} device nodes" -f $rows.Count)

    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'EgEndpointNodes' -ErrorAction SilentlyContinue
    foreach ($r in $rows) {
        $_i++
        try { Write-SIProgress -Label 'EgEndpointNodes' -Index $_i -Total $_total } catch { }
        $rawData = $null
        if (-not [string]::IsNullOrWhiteSpace($r.NodePropertiesJson)) {
            try {
                $props = $r.NodePropertiesJson | ConvertFrom-Json -ErrorAction Stop
                $rawData = if ($props.rawData) { $props.rawData } else { $props }
            } catch { }
        }

        $name = $r.NodeName
        if (-not $name -and $rawData -and $rawData.deviceName) { $name = [string]$rawData.deviceName }

        @{
            AssetId               = 'eg:dev:' + ([string]$r.NodeId).ToLowerInvariant()
            Source                = 'EndpointExposureGraph'
            Hint                  = if ($rawData -and $rawData.PSObject.Properties['deviceCategory']) { [string]$rawData.deviceCategory } else { 'endpoint' }
            Name                  = $name
            NormalizedKey         = if ($name) { ([string]$name).ToLowerInvariant() } else { ([string]$r.NodeId).ToLowerInvariant() }
            EG_NodeId             = $r.NodeId
            EG_NodeLabel          = $r.NodeLabel
            EG_DeviceCategory     = if ($rawData -and $rawData.PSObject.Properties['deviceCategory']) { [string]$rawData.deviceCategory } else { $null }
            EG_OS                 = if ($rawData -and $rawData.PSObject.Properties['osPlatform']) { [string]$rawData.osPlatform } else { $null }
            EG_OSVersion          = if ($rawData -and $rawData.PSObject.Properties['osVersion']) { [string]$rawData.osVersion } else { $null }
            EG_OnboardingStatus   = if ($rawData -and $rawData.PSObject.Properties['onboardingStatus']) { [string]$rawData.onboardingStatus } else { $null }
            EG_SensorHealth       = if ($rawData -and $rawData.PSObject.Properties['sensorHealthState']) { [string]$rawData.sensorHealthState } else { $null }
            EG_LastSeen           = if ($rawData -and $rawData.PSObject.Properties['lastSeen']) { [string]$rawData.lastSeen } else { $null }
            # fix: EG returns exposureScore as STRING enum
            # ('None'|'Low'|'Medium'|'High') for some node types -- coerce
            # to string regardless.
            EG_ExposureScore      = if ($rawData -and $rawData.PSObject.Properties['exposureScore']) { [string]$rawData.exposureScore } else { $null }
            EG_Criticality        = if ($rawData -and $rawData.PSObject.Properties['criticality']) { [string]$rawData.criticality } else { $null }
            EG_BusinessApp        = if ($rawData -and $rawData.PSObject.Properties['businessApplicationName']) { [string]$rawData.businessApplicationName } else { $null }
            EG_AntivirusEnabled   = if ($rawData -and $rawData.PSObject.Properties['antivirusEnabled']) { [bool]$rawData.antivirusEnabled } else { $null }
            # surface aadDeviceId at top level for cross-source merge in
            # Invoke-Discover (second-pass merge by AadDeviceId joins MDE/EG/Entra
            # rows for the same AAD-joined device when their NormalizedKeys differ).
            EG_AadDeviceId        = if ($rawData -and $rawData.PSObject.Properties['aadDeviceId']) { [string]$rawData.aadDeviceId } else { $null }
            # Audit-gap-fill: MS-computed risk + asset-context signals.
            # MsCriticalityLevel is comparison-only (Tier sources from CL only per
            # feedback_si_ra_tier_source). The boolean flags feed RiskFactor_*_Detailed.
            EG_MsCriticalityLevel    = if ($rawData -and $rawData.PSObject.Properties['criticalityLevel']) { [string]$rawData.criticalityLevel } else { $null }
            EG_MachineRiskState      = if ($rawData -and $rawData.PSObject.Properties['machineRiskState']) { [string]$rawData.machineRiskState } else { $null }
            EG_IsCompromisedRecently = if ($rawData -and $rawData.PSObject.Properties['isCompromisedRecently']) { [bool]$rawData.isCompromisedRecently } else { $null }
            EG_IsProductionEnvironment = if ($rawData -and $rawData.PSObject.Properties['isProductionEnvironment']) { [bool]$rawData.isProductionEnvironment } else { $null }
            EG_IsAdfsServer          = if ($rawData -and $rawData.PSObject.Properties['isAdfsServer']) { [bool]$rawData.isAdfsServer } else { $null }
            EG_IsCustomerFacing      = if ($rawData -and $rawData.PSObject.Properties['isCustomerFacing']) { [bool]$rawData.isCustomerFacing } else { $null }
            EG_IsExcluded            = if ($rawData -and $rawData.PSObject.Properties['isExcluded']) { [bool]$rawData.isExcluded } else { $null }
            EG_HasInternetExposureSignal = if ($rawData -and $rawData.PSObject.Properties['hasInternetExposureSignal']) { [bool]$rawData.hasInternetExposureSignal } else { $null }
            AZ_PropertiesRawJson  = $r.NodePropertiesJson    # same column name as azure engine for schema consistency
        }
    }
}
