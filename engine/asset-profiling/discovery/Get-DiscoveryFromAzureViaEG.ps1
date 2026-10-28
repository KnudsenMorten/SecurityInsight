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

# #412 one pull per source -- see shared\SI-FullAssetProperties.ps1. Nothing changes at the security level.
if (-not (Get-Command -Name Add-SIFullSourceObject -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-FullAssetProperties.ps1') }

function Get-SIEgAzureNodeArmId {
    <#
        PURE. The Azure resource id one Exposure Graph node names, lower case; '' when it names none.
        🔴 An Azure node carries NO rawData.resourceId -- its ARM id is in EntityIds ({ type AzureResourceId; id }), and the
        hunting API hands EntityIds back as an array of JSON TEXT, one string per id (or the whole array as one text).
        The full-metadata anchor took rawData.resourceId, else the node id (hex), so no Exposure Graph node ever matched an
        Azure profile row's AzureResourceId: every azure run said "exposure-graph N object(s), 0 resolved".
    #>
    param($Row)
    if ($null -eq $Row) { return '' }
    $p = $Row.PSObject.Properties['EntityIds']; if ($Row -is [System.Collections.IDictionary]) { $e = $Row['EntityIds'] } elseif ($p) { $e = $p.Value } else { $e = $null }
    if ($e -is [string]) { $t = $e.Trim(); $e = $null; if ($t.StartsWith('[') -or $t.StartsWith('{')) { try { $e = $t | ConvertFrom-Json -ErrorAction Stop } catch { $e = $null } } }
    foreach ($x in @($e)) {
        if ($x -is [string]) { $t = $x.Trim(); $x = $null; if ($t.StartsWith('{')) { try { $x = $t | ConvertFrom-Json -ErrorAction Stop } catch { $x = $null } } }
        if ($null -eq $x) { continue }
        if ($x -is [System.Collections.IDictionary]) { $ty = [string]$x['type']; $id = [string]$x['id'] } else { $ty = [string]$x.type; $id = [string]$x.id }
        if ($ty -eq 'AzureResourceId' -and -not [string]::IsNullOrWhiteSpace($id)) { return $id.Trim().ToLowerInvariant() }
    }
    ''
}

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
    # 🔒 NON-ASSET TYPES ARE EXCLUDED HERE -- operator, 2026-08-28: "remove the role assignments. it
    # makes no sense to think of this as an asset. maybe there is a definition inside azure to fetch
    # these non-asset types."
    #
    # 🔑 THERE IS ONE, AND IT IS AZURE'S OWN: these are EXTENSION RESOURCES. They do not exist
    # independently -- they extend another resource, carry no location, and Azure Resource Graph keeps
    # them in SEPARATE tables (`authorizationresources`, `policyresources`) rather than in `resources`.
    # The exposure graph makes no such split, so `NodeLabel contains "microsoft."` swept them in.
    #
    # 📊 MEASURED on the live snapshot before this filter existed: of 769 azure rows, **346 were
    # `microsoft.authorization/roleassignments`** -- 45% of the entire azure "estate" was RBAC
    # assignments. They also dominated the duplicate-name problem, because an extension resource has no
    # name of its own to inherit.
    # 📌 Customer-overridable via $global:SI_AzureEgNonAssetTypes (replaces the list, so a customer who
    # genuinely wants one of these back can have it).
    $nonAsset = if ($global:SI_AzureEgNonAssetTypes) { @($global:SI_AzureEgNonAssetTypes) } else {
        @(
            'microsoft.authorization/roleassignments'      # who may do what -- a grant, not an asset
            'microsoft.authorization/roledefinitions'      # the definition of a grant
            'microsoft.authorization/policyassignments'
            'microsoft.authorization/policydefinitions'
            'microsoft.authorization/locks'
            'microsoft.insights/diagnosticsettings'        # configuration ON a resource
        )
    }
    $all = @($rows | ForEach-Object { [string]$_.NodeLabel } | Where-Object { $_ } | Sort-Object)
    $script:SI_AzureEgTypeAllowlist_Cache = @($all | Where-Object { $nonAsset -notcontains $_.ToLowerInvariant() })
    $dropped = $all.Count - $script:SI_AzureEgTypeAllowlist_Cache.Count
    # NOT silent. A type disappearing from the estate is exactly the kind of change that must be
    # visible in the run log rather than discovered later as missing rows.
    if ($dropped -gt 0) {
        Write-Verbose ("Get-EGAzureTypeAllowlist: excluded {0} NON-ASSET type(s) (extension resources -- role/policy assignments, locks, diagnostic settings). Override with `$global:SI_AzureEgNonAssetTypes." -f $dropped)
    }
    Write-SIInfo ("   EG Azure type allowlist: {0} node labels (microsoft.*)" -f $script:SI_AzureEgTypeAllowlist_Cache.Count)
    return $script:SI_AzureEgTypeAllowlist_Cache
}

function Get-DiscoveryFromAzureViaEG {
    [CmdletBinding()]
    param([switch]$CountOnly)   # #475: only the number of Azure nodes this source would return, or $null

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
| project NodeId, NodeName, NodeLabel, EntityIds, NodePropertiesJson = tostring(NodeProperties)
"@
    # #475: the number of nodes, and the hunting call -- the whole-set path and the streaming buckets use the same call
    $huntEg = {
        param([string]$Query)
        $resp = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } `
            -Body (@{ Query = $Query } | ConvertTo-Json -Compress) -ErrorAction Stop
        if ($resp.results) { $resp.results } elseif ($resp.Results) { $resp.Results } else { @() }
    }
    $countEg = {
        try { $c = @(& $huntEg ("ExposureGraphNodes | where NodeLabel in~ ({0}) | count" -f $typeList)); $n = 0L; if ($c.Count -gt 0 -and [long]::TryParse([string]$c[0].Count, [ref]$n)) { return $n } } catch { }
        return $null
    }
    if ($CountOnly) { return (& $countEg) }

    # The asset of ONE graph node -- shared by the whole-set loop below and the streaming buckets (#475).
    $buildEg = {
        param($r)
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
        # #412 full asset metadata: the node this query already returned, kept whole and tied to its Azure resource
        # every level: the record capture needs each node (the full metadata keeps it only at the full level)
        # the anchor is the ARM id the node names in EntityIds (the profile's AzureResourceId), else the id above (Get-SIEgAzureNodeArmId)
        $anchorArmId = Get-SIEgAzureNodeArmId -Row $r
        if (-not $anchorArmId) { $anchorArmId = $resourceIdLower }
        if ($true) { Add-SIFullSourceObject -SourceSystem 'exposure-graph' -Object (ConvertTo-SIFullExposureGraphNode -Row $r) -AnchorColumn 'AzureResourceId' -AnchorValue $anchorArmId }

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

    # #475 STREAMING (the discover phase of a run collected in parts): one hunting query for every Azure node is cut off at
    # the advanced hunting row limit on a large estate, so the nodes are read in BUCKETS of ~20,000 (hash of the node id),
    # each turned into assets and sent straight into the parts.
    $stream = $global:SI_DiscoverStream
    if ($stream) {
        $total = & $countEg
        $buckets = 1
        if ($null -ne $total) { $buckets = [int][Math]::Max(1, [Math]::Ceiling($total / 20000.0)) }
        else { Write-SIWarn 'EG Azure discovery: the number of nodes could not be read -- one query (a large estate may be cut off at the hunting row limit).' }
        $taken = 0; $failed = 0
        for ($b = 0; $b -lt $buckets; $b++) {
            $q = $kql
            if ($buckets -gt 1) { $q = $kql.TrimEnd() + ("`n| where hash(NodeId, {0}) == {1}" -f $buckets, $b) }
            try { $bucketRows = @(& $huntEg $q) }
            catch {
                $failed++
                $msg = $_.Exception.Message; if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $msg = $_.ErrorDetails.Message }
                Write-Warning ('EG Azure discovery: bucket {0} of {1} failed -- {2}. Its nodes are UNKNOWN this run, not removed.' -f ($b + 1), $buckets, $msg)
                continue
            }
            $batch = New-Object System.Collections.Generic.List[object]
            foreach ($r in $bucketRows) { $batch.Add((& $buildEg $r)) }
            $null = Add-SIDiscoverStreamAssets -Stream $stream -Assets $batch.ToArray()
            $taken += $batch.Count
            $bucketRows = $null; $batch = $null
        }
        Set-SIFullSourcePull -SourceSystem 'exposure-graph' -Complete ($failed -eq 0)
        if ($global:SI_DiscoverStreamCounts) { $global:SI_DiscoverStreamCounts['ExposureGraph'] = $taken }
        Write-SIInfo ("   EG Azure discovery: {0} node(s) in {1} bucket(s) streamed into {2} part(s){3}" -f $taken, $buckets, $stream.Parts, $(if ($failed) { (', {0} bucket(s) failed' -f $failed) } else { '' }))
        return
    }

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
    Set-SIFullSourcePull -SourceSystem 'exposure-graph' -Complete $true

    # Hint mapping (last segment of node label -> short label)
    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'EgAzureNodes' -ErrorAction SilentlyContinue
    foreach ($r in $rows) {
        $_i++
        try { Write-SIProgress -Label 'EgAzureNodes' -Index $_i -Total $_total } catch { }
        & $buildEg $r
    }
}
