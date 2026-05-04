#Requires -Version 5.1
<#
    Discovery sidecar for the AZURE engine: pulls relationship edges from
    Microsoft Defender's Exposure Graph (XDR Advanced Hunting tables
    ExposureGraphNodes + ExposureGraphEdges).

    Two outputs (exposed as separate functions, one round-trip each):
      Get-AzureExposureGraphResourceNodes -- enriches resource records with
        EG-side metadata (exposure score, criticality, business application
        name -- whatever Defender already inferred). Joined to discovered
        resources by NodeName == AZ_Name + NodeLabel matching.

      Get-AzureExposureGraphAccessEdges -- 'has access to' / 'has permission'
        edges where SOURCE is an identity (user / SP) and TARGET is an Azure
        resource. Used by Stage Enrich's cross-engine block to derive
        XENG_AccessedByT0/T1 counters.

    Failure modes are non-fatal -- empty maps are returned on Graph error,
    license missing, schema drift. Azure engine still classifies via ARG
    + AI metaprofile alone.
#>

# Node labels that identify Azure resources in the EG schema. Customer can
# extend via $global:SI_AzureExposureGraph_ResourceLabels.
$script:SI_AzureEG_ResourceLabels_Default = @(
    'storageaccount',
    'keyvault',
    'sqldatabase',
    'sqlmanagedinstance',
    'cosmosdb',
    'webapp',
    'functionapp',
    'aksdeployment',
    'aksserviceaccount',
    'containerregistry',
    'eventhub',
    'servicebus',
    'redis',
    'azureresource',
    'azureappgateway',
    'azureloadbalancer'
)

# Node labels that identify identities (sources of has-access-to edges).
$script:SI_AzureEG_IdentityLabels_Default = @(
    'user',
    'serviceprincipal',
    'managedidentity',
    'group'
)

# Edge labels meaning "this identity has reach into this resource". XDR
# names these in lowercase with spaces; coerce both sides for matching.
$script:SI_AzureEG_AccessEdgeLabels_Default = @(
    'has access to',
    'can authenticate as',
    'has permissions to',
    'has role on',
    'has data action on'
)

function Get-AzureExposureGraphResourceNodes {
    [CmdletBinding()]
    param()

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")

    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('AzureExposureGraph nodes: token failed -- {0}' -f $_.Exception.Message)
        return @{}
    }

    $labels = if ($global:SI_AzureExposureGraph_ResourceLabels) { @($global:SI_AzureExposureGraph_ResourceLabels) } else { $script:SI_AzureEG_ResourceLabels_Default }
    $labelList = ($labels | ForEach-Object { "'$_'" }) -join ','

    # NodeProperties is dynamic so projecting tostring() avoids the
    # `distinct` 400-on-dynamic gotcha (same fix used in the endpoint EG
    # connector). Also project NodeLabel so the caller can pivot on type.
    $kql = @"
ExposureGraphNodes
| where NodeLabel in~ ($labelList)
| project NodeId, NodeName, NodeLabel, NodePropertiesJson = tostring(NodeProperties)
"@

    try {
        $resp = Invoke-RestMethod -Method Post `
            -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } `
            -Body (@{ Query = $kql } | ConvertTo-Json -Compress) -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        Write-Warning ('AzureExposureGraph nodes: query failed -- {0}' -f $msg)
        return @{}
    }

    $rows = if ($resp.results) { $resp.results } elseif ($resp.Results) { $resp.Results } else { @() }
    # Map keyed by lowercased NodeName for join with AZ_Name (resource short
    # name). Collisions are rare across types but possible -- keep first hit.
    $byName = @{}
    foreach ($r in $rows) {
        if (-not $r.NodeName) { continue }
        $key = ([string]$r.NodeName).ToLowerInvariant()
        if (-not $byName.ContainsKey($key)) {
            $byName[$key] = @{
                NodeId             = $r.NodeId
                NodeName           = $r.NodeName
                NodeLabel          = $r.NodeLabel
                NodePropertiesJson = $r.NodePropertiesJson
            }
        }
    }
    return $byName
}

function Get-AzureExposureGraphAccessEdges {
    [CmdletBinding()]
    param()

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")

    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('AzureExposureGraph edges: token failed -- {0}' -f $_.Exception.Message)
        return @{}
    }

    $resourceLabels = if ($global:SI_AzureExposureGraph_ResourceLabels) { @($global:SI_AzureExposureGraph_ResourceLabels) } else { $script:SI_AzureEG_ResourceLabels_Default }
    $identityLabels = if ($global:SI_AzureExposureGraph_IdentityLabels) { @($global:SI_AzureExposureGraph_IdentityLabels) } else { $script:SI_AzureEG_IdentityLabels_Default }
    $edgeLabels     = if ($global:SI_AzureExposureGraph_AccessEdgeLabels) { @($global:SI_AzureExposureGraph_AccessEdgeLabels) } else { $script:SI_AzureEG_AccessEdgeLabels_Default }

    $rList = ($resourceLabels | ForEach-Object { "'$_'" }) -join ','
    $iList = ($identityLabels | ForEach-Object { "'$_'" }) -join ','
    $eList = ($edgeLabels     | ForEach-Object { "'$_'" }) -join ','

    $kql = @"
ExposureGraphEdges
| where EdgeLabel in~ ($eList)
| where SourceNodeLabel in~ ($iList) and TargetNodeLabel in~ ($rList)
| project SourceNodeId, SourceNodeName, SourceNodeLabel,
          TargetNodeId, TargetNodeName, TargetNodeLabel, EdgeLabel
"@

    try {
        $resp = Invoke-RestMethod -Method Post `
            -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } `
            -Body (@{ Query = $kql } | ConvertTo-Json -Compress) -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        Write-Warning ('AzureExposureGraph edges: query failed -- {0}' -f $msg)
        return @{}
    }

    $rows = if ($resp.results) { $resp.results } elseif ($resp.Results) { $resp.Results } else { @() }
    # Map: lowercased TargetNodeName -> ArrayList of @{ SourceName; SourceLabel; EdgeLabel }
    $byTargetName = @{}
    foreach ($r in $rows) {
        if (-not $r.TargetNodeName) { continue }
        $key = ([string]$r.TargetNodeName).ToLowerInvariant()
        if (-not $byTargetName.ContainsKey($key)) {
            $byTargetName[$key] = New-Object System.Collections.ArrayList
        }
        [void]$byTargetName[$key].Add(@{
            SourceName  = $r.SourceNodeName
            SourceId    = $r.SourceNodeId
            SourceLabel = $r.SourceNodeLabel
            EdgeLabel   = $r.EdgeLabel
        })
    }
    return $byTargetName
}
