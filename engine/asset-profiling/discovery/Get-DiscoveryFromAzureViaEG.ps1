#Requires -Version 5.1
<#
    Discovery source for the AZURE engine -- Exposure Graph as primary.

    Microsoft has already done the work of curating which Azure asset types
    matter for security posture: the ExposureGraphNodes table only carries
    the ~20 microsoft.* types Defender considers exploitable / posture-
    relevant. ARG returns 600+ types including disks,
    snapshots, alert instances, recovery points -- pure noise for a
    posture engine.

    This connector:
      1. Enumerates the microsoft.* node-label allowlist (cached 24h to
         avoid the round-trip on every shard / replica).
      2. Pulls EVERY node for those types via a single ExposureGraphNodes
         query. Returns NodeName + NodePropertiesJson verbatim --
         downstream stages mirror rawData 1:1 into the Properties JSON
         column without a per-type AI metaprofile call.

    Falls back gracefully (returns empty) on API failure -- the existing
    Get-DiscoveryFromAzureResources ARG connector handles brand-new
    resources EG hasn't ingested yet.

    Asset shape:
      AssetId             -- 'eg:az:<lowercased-NodeId>'  (NodeId is the
                             Azure resource ID per EG schema)
      Source              -- 'ExposureGraph'
      Hint                -- short type label (e.g. 'key-vault', 'storage-account')
      Name                -- short resource name
      NormalizedKey       -- lowercased resource ID for ARG dedup
      AZ_NodeLabel        -- 'microsoft.<provider>/<type>'
      AZ_ResourceId       -- mirrors NormalizedKey
      AZ_PropertiesRawJson -- VERBATIM EG rawData JSON (the security view)
      AZ_NodeId           -- EG node ID (== Azure resource ID)
      EG_*                -- exposureScore, criticality, businessApplicationName
                             extracted as shortcut fields (also remain in rawData)
#>

function Get-EGAzureTypeAllowlist {
    <#
        One-shot enumeration of microsoft.* node labels in EG. Cached in
        $script: scope so a single run only round-trips once. Customer
        can override via $global:SI_AzureEgTypeAllowlist (extends or
        replaces).
    #>
    [CmdletBinding()]
    param([switch]$ForceRefresh)

    if (-not $ForceRefresh -and $script:SI_AzureEgTypeAllowlist_Cache) {
        return $script:SI_AzureEgTypeAllowlist_Cache
    }

    if ($global:SI_AzureEgTypeAllowlist) {
        $script:SI_AzureEgTypeAllowlist_Cache = @($global:SI_AzureEgTypeAllowlist)
        return $script:SI_AzureEgTypeAllowlist_Cache
    }

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")
    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('Get-EGAzureTypeAllowlist: token failed -- {0}' -f $_.Exception.Message)
        return @()
    }

    $kql = @'
ExposureGraphNodes
| where NodeLabel contains "microsoft."
| distinct NodeLabel
'@
    Write-SIInfo "   ExposureGraph: discovering Azure node-label allowlist (one-time per run) ..."
    $_alStart = [datetime]::UtcNow
    try {
        $resp = Invoke-RestMethod -Method Post `
            -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } `
            -Body (@{ Query = $kql } | ConvertTo-Json -Compress) -ErrorAction Stop
    } catch {
        Write-Warning ('Get-EGAzureTypeAllowlist: query failed -- {0}' -f $_.Exception.Message)
        return @()
    }
    Write-SIInfo ("   ExposureGraph: allowlist query returned in {0:n1}s" -f ([datetime]::UtcNow - $_alStart).TotalSeconds)

    $rows = if ($resp.results) { $resp.results } elseif ($resp.Results) { $resp.Results } else { @() }
    $script:SI_AzureEgTypeAllowlist_Cache = @($rows | ForEach-Object { [string]$_.NodeLabel } | Where-Object { $_ } | Sort-Object)
    Write-SIInfo ("   EG Azure type allowlist: {0} node labels (microsoft.*)" -f $script:SI_AzureEgTypeAllowlist_Cache.Count)
    return $script:SI_AzureEgTypeAllowlist_Cache
}

function Get-DiscoveryFromAzureViaEG {
    [CmdletBinding()]
    param()

    $types = Get-EGAzureTypeAllowlist
    if ($types.Count -eq 0) {
        Write-Warning 'Get-DiscoveryFromAzureViaEG: empty allowlist; returning 0 assets.'
        return @()
    }

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) "auth/Get-SIGraphToken.ps1")
    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('Get-DiscoveryFromAzureViaEG: token failed -- {0}' -f $_.Exception.Message)
        return @()
    }

    # Single query for ALL allowlisted types. NodeProperties is dynamic;
    # cast to string to avoid 'distinct on dynamic' 400.
    $typeList = ($types | ForEach-Object { "'$_'" }) -join ','
    $kql = @"
ExposureGraphNodes
| where NodeLabel in~ ($typeList)
| project NodeId, NodeName, NodeLabel, NodePropertiesJson = tostring(NodeProperties)
"@
    Write-SIInfo ("   ExposureGraph: fetching Azure resource nodes from advanced hunting ({0} types; this can take 30-120s) ..." -f $types.Count)
    $_egStart = [datetime]::UtcNow
    try {
        $resp = Invoke-RestMethod -Method Post `
            -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } `
            -Body (@{ Query = $kql } | ConvertTo-Json -Compress) -ErrorAction Stop
    } catch {
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
        Write-Warning ('Get-DiscoveryFromAzureViaEG: query failed -- {0}' -f $msg)
        return @()
    }

    $rows = if ($resp.results) { $resp.results } elseif ($resp.Results) { $resp.Results } else { @() }
    Write-SIInfo ("   EG Azure discovery: {0} nodes across {1} types  ({2:n1}s)" -f $rows.Count, $types.Count, ([datetime]::UtcNow - $_egStart).TotalSeconds)

    # Hint mapping (last segment of node label -> short label)
    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'EgAzureNodes' -ErrorAction SilentlyContinue
    foreach ($r in $rows) {
        $_i++
        try { Write-SIProgress -Label 'EgAzureNodes' -Index $_i -Total $_total } catch { }
        $hint = if ($r.NodeLabel -match '/([^/]+)$') { $matches[1] } else { 'azure-resource' }

        # Extract shortcuts from rawData (also kept in NodePropertiesJson verbatim)
        $rawData = $null
        if (-not [string]::IsNullOrWhiteSpace($r.NodePropertiesJson)) {
            try {
                $props = $r.NodePropertiesJson | ConvertFrom-Json -ErrorAction Stop
                $rawData = if ($props.rawData) { $props.rawData } else { $props }
            } catch { }
        }
        $resourceId = $null
        if ($rawData -and $rawData.PSObject.Properties['resourceId']) { $resourceId = [string]$rawData.resourceId }
        if (-not $resourceId) { $resourceId = [string]$r.NodeId }
        $resourceIdLower = $resourceId.ToLowerInvariant()

        @{
            AssetId               = 'eg:az:' + $resourceIdLower
            Source                = 'ExposureGraph'
            Hint                  = $hint
            Name                  = $r.NodeName
            NormalizedKey         = $resourceIdLower
            AZ_NodeLabel          = $r.NodeLabel
            AZ_NodeId             = $r.NodeId
            AZ_ResourceId         = $resourceIdLower
            AZ_PropertiesRawJson  = $r.NodePropertiesJson
            # fix: EG returns exposureScore as STRING enum
            # ('None'|'Low'|'Medium'|'High') for some node types and as
            # numeric for others. Coerce to string -- callers do their own
            # parsing/comparison.
            EG_ExposureScore      = if ($rawData -and $rawData.PSObject.Properties['exposureScore']) { [string]$rawData.exposureScore } else { $null }
            EG_Criticality        = if ($rawData -and $rawData.PSObject.Properties['criticality']) { [string]$rawData.criticality } else { $null }
            EG_BusinessApp        = if ($rawData -and $rawData.PSObject.Properties['businessApplicationName']) { [string]$rawData.businessApplicationName } else { $null }
            EG_HandlesSensitiveData = if ($rawData -and $rawData.PSObject.Properties['handlesSensitiveData']) { [bool]$rawData.handlesSensitiveData } else { $null }
            # Audit-gap-fill: MS-computed risk + asset-context signals (parity with endpoint EG discovery)
            EG_MsCriticalityLevel    = if ($rawData -and $rawData.PSObject.Properties['criticalityLevel']) { [string]$rawData.criticalityLevel } else { $null }
            EG_IsCompromisedRecently = if ($rawData -and $rawData.PSObject.Properties['isCompromisedRecently']) { [bool]$rawData.isCompromisedRecently } else { $null }
            EG_IsProductionEnvironment = if ($rawData -and $rawData.PSObject.Properties['isProductionEnvironment']) { [bool]$rawData.isProductionEnvironment } else { $null }
            EG_HasInternetExposureSignal = if ($rawData -and $rawData.PSObject.Properties['hasInternetExposureSignal']) { [bool]$rawData.hasInternetExposureSignal } else { $null }
        }
    }
}
