#Requires -Version 5.1
<#
    Discovery source: Defender ExposureGraph (via Microsoft Graph Advanced
    Hunting).

    KQL:
        ExposureGraphNodes
        | where NodeLabel == 'device'
        | distinct NodeId, NodeName, NodeProperties

    Returns every device the ExposureGraph knows about -- includes managed
    Defender devices PLUS unmanaged devices Defender discovered via network
    scanning. This is the broadest endpoint discovery source.

    Auth: Microsoft Graph token with ThreatHunting.Read.All on the
    ExposureGraph schema. License: Microsoft Defender for Endpoint Plan 2 OR
    Microsoft Defender Vulnerability Management.

    Endpoint: POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
#>

function Get-DiscoveryFromExposureGraph {
    [CmdletBinding()]
    param([switch]$AllowEmptyOnStub)

    if ($AllowEmptyOnStub) {
        Write-Warning 'ExposureGraph discovery stubbed off via -AllowEmptyOnStub. Returning 0 assets.'
        return @()
    }

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")

    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('ExposureGraph: token acquisition failed -- {0}' -f $_.Exception.Message)
        return @()
    }

    # NodeProperties is a 'dynamic' column -- can't be used in `distinct`
    # (returns 400). Convert to string first; NodeId is already unique so
    # `distinct` isn't needed.
    $kql = @'
ExposureGraphNodes
| where NodeLabel == 'device'
| project NodeId, NodeName, NodePropertiesJson = tostring(NodeProperties)
'@

    Write-SIInfo "   ExposureGraph: fetching device nodes from advanced hunting (this can take 30-120s for large tenants) ..."
    $_egStart = [datetime]::UtcNow
    try {
        $resp = Invoke-RestMethod -Method Post `
            -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } `
            -Body (@{ Query = $kql } | ConvertTo-Json -Compress)
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        Write-Warning ('ExposureGraph: hunting query failed -- {0}' -f $msg)
        return @()
    }

    $rows = if ($resp.results) { $resp.results } elseif ($resp.Results) { $resp.Results } else { @() }
    Write-SIInfo ("   ExposureGraph: received {0} device node(s) in {1:n1}s" -f $rows.Count, ([datetime]::UtcNow - $_egStart).TotalSeconds)

    foreach ($r in $rows) {
        $name = if ($r.NodeName) { $r.NodeName } else { $r.NodeId }

        # Parse NodeProperties for OS-hint inference + a few load-bearing
        # downstream fields. Format from the EG schema:
        #   { "rawData": { "osPlatform": "...", "deviceType": "...",
        #                  "deviceCategory": "...", "machineGroup": "...",
        #                  "exposureScore": "...", "riskScore": "...",
        #                  "onboardingStatus": "...", ... } }
        $os         = $null
        $devType    = $null
        $devCat     = $null
        $mdeOnboard = $null
        $exposure   = $null
        $risk       = $null
        if ($r.NodePropertiesJson) {
            try {
                $raw = ($r.NodePropertiesJson | ConvertFrom-Json).rawData
                if ($raw) {
                    $os         = $raw.osPlatform
                    $devType    = $raw.deviceType
                    $devCat     = $raw.deviceCategory
                    $mdeOnboard = $raw.onboardingStatus
                    $exposure   = $raw.exposureScore
                    $risk       = $raw.riskScore
                }
            } catch { }
        }

        $hint = switch -Wildcard ($os) {
            'Windows*'        { if ($devType -eq 'Server') { 'windows-server' } else { 'windows' } }
            '*Server*'        { 'windows-server' }
            'macOS*'          { 'mac' }
            'Linux*'          { 'linux' }
            'Ubuntu*'         { 'linux' }
            'Centos*'         { 'linux' }
            'iOS'             { 'mobile-ios' }
            'iPadOS'          { 'mobile-ios' }
            'Android*'        { 'mobile-android' }
            default           { if ($devCat -eq 'IoT') { 'iot' } else { 'unknown' } }
        }

        @{
            AssetId          = 'eg:' + $r.NodeId
            Source           = 'ExposureGraph'
            Hint             = $hint
            Name             = $name
            NormalizedKey    = $name.ToLowerInvariant()
            EgNodeId         = $r.NodeId
            EgOS             = $os
            EgDeviceType     = $devType
            EgDeviceCategory = $devCat
            EgOnboardStatus  = $mdeOnboard
            EgExposureScore  = $exposure
            EgRiskScore      = $risk
        }
    }
}
