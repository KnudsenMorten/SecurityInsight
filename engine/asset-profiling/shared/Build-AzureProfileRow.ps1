#Requires -Version 5.1
<#
    Build-AzureProfileRow.ps1

    Schema-driven row builder for the azure engine. Mirrors Build-Identity /
    Build-Endpoint / Build-PublicIp -- iterates profiles/azure.schema.json
    fields[] and resolves EACH declared field via Resolve-SIAzureSourceValue.
    Emits a flat row whose column names exactly match the schema (no SI_
    prefix per ARCHITECTURE.md rule 4).

    Source resolution (per field.source):
      azure         -- ARG-discovered fields
                       sourcePath patterns:
                         arm.<resource>.id              -> AZ_ResourceId
                         arm.<resource>.subscriptionId  -> regex on id
                         arm.<resource>.resourceGroup   -> regex on id
                         arm.<resource>.name            -> last segment of id
                         arm.<resource>.type            -> AZ_ResourceType
                         arm.<resource>.location        -> AZ_Location
                         arm.<resource>.kind            -> AZ_Kind
                         arm.<resource>.tags.<X>        -> AZ_Tags (parsed) walk
                         arm.<resource>.properties.<dotted.path>
                           -> walk AZ_PropertiesJson (which IS the .properties subtree)
                         arm.<resource>.identity.<X>    -> not in PropertiesJson; null today (TODO)
      exposureGraph -- EG-discovered fields
                       sourcePath patterns:
                         eg.node.NodeId                                 -> AZ_NodeId
                         eg.node.NodeLabel                              -> AZ_NodeLabel
                         eg.node.NodeProperties.rawData.<dotted.path>   -> walk parsed AZ_PropertiesRawJson
      derived       -- computed in this builder (Tier, AssetType, IsEnabledActive,
                       SIRules, plus the run-tracking columns)

    Falls back to the keymap for fields that don't carry a sourcePath in
    the schema (back-compat with the hardcoded set).

    replaces the minimal-keymap-only approach. ~282
    declared azure fields now resolve when their source data is available
    in metadata, vs the previous ~15.
#>

if (-not (Get-Variable -Name _SISchemaCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:_SISchemaCache = @{}
}

function Get-SIFieldRequiredKeys {
    <# v2.2.372 -- given a schema field, return the LIST of metadata keys
       whose presence is REQUIRED for the field to possibly resolve to a
       non-null value. Build-SIAzureProfileRow uses this to fast-null
       fields whose required sources are absent from the current row's
       metadata, skipping the expensive Resolve-SIAzureSourceValue call
       entirely (regex + path walk + JSON cache).

       Returns an empty list when the field has no determinable source
       requirement (source='derived', or unmappable sourcePath) -- those
       fields fall through to the normal Resolve path. #>
    param($Field)
    $src  = [string]$Field.source
    $path = [string]$Field.sourcePath
    $name = [string]$Field.name
    $keys = New-Object System.Collections.Generic.List[string]

    # Keymap aliases (any of these populating the row means this field could resolve)
    if ($script:_SIAzureKeyMap.ContainsKey($name)) {
        foreach ($a in @($script:_SIAzureKeyMap[$name])) { [void]$keys.Add([string]$a) }
    }

    if ($src -eq 'azure') {
        $rel = $path -replace '^arm\.[^.]+\.', ''
        if ($rel -ne $path) {
            if     ($rel -eq 'id' -or $rel -eq 'subscriptionId' -or $rel -eq 'resourceGroup' -or $rel -eq 'name') { [void]$keys.Add('AZ_ResourceId') }
            elseif ($rel -eq 'type')            { [void]$keys.Add('AZ_Type'); [void]$keys.Add('AZ_ResourceType') }
            elseif ($rel -eq 'location')        { [void]$keys.Add('AZ_Location') }
            elseif ($rel -eq 'kind')            { [void]$keys.Add('AZ_Kind') }
            elseif ($rel.StartsWith('tags.'))   { [void]$keys.Add('AZ_TagsJson'); [void]$keys.Add('AZ_Tags') }
            elseif ($rel.StartsWith('properties.')) { [void]$keys.Add('AZ_PropertiesJson'); [void]$keys.Add('AZ_Properties') }
        }
    } elseif ($src -eq 'exposureGraph') {
        if     ($path -eq 'eg.node.NodeId')    { [void]$keys.Add('AZ_NodeId') }
        elseif ($path -eq 'eg.node.NodeLabel') { [void]$keys.Add('AZ_NodeLabel') }
        elseif ($path.StartsWith('eg.node.NodeProperties.rawData.') -or $path.StartsWith('rawData.')) {
            [void]$keys.Add('AZ_PropertiesRawJson'); [void]$keys.Add('AZ_PropertiesRaw')
        }
    }
    return $keys
}

function Get-SIAzureSchema {
    if ($script:_SISchemaCache.ContainsKey('AzureSchema')) { return $script:_SISchemaCache['AzureSchema'] }
    . (Join-Path $PSScriptRoot 'Get-SISchemaWithCustomMerge.ps1')
    $schema = Get-SISchemaWithCustomMerge -Engine azure
    $script:_SISchemaCache['AzureSchema'] = $schema
    # v2.2.371 -- pre-filter the EMIT-able fields once at first call so per-row
    # iteration doesn't re-check emit/purpose/name flags for ~282 fields on
    # every row. At ~13K rows that's ~3.6M wasted property checks. Cached as
    # an [array] (not pipeline) so the foreach in Build-SIAzureProfileRow gets
    # an O(1) length lookup.
    # v2.2.372 -- ALSO annotate each emit-field with `_SIRequiredKeys` (List[string])
    # so per-row iteration can fast-null fields whose required metadata source
    # isn't present, skipping the regex+path-walk in Resolve-SIAzureSourceValue.
    $script:_SISchemaCache['AzureEmitFields'] = @(
        $schema.fields | Where-Object {
            $fn = [string]$_.name
            $fn -and `
            (-not $_.PSObject.Properties['emit'] -or $_.emit -ne $false) -and `
            ([string]$_.purpose -notin 'enrichment','forensic','raw') -and `
            ($fn -notin 'CollectHash','EnrichHash','PostureHash','ClassifyHash','EntityIds')
        } | ForEach-Object {
            $reqKeys = Get-SIFieldRequiredKeys -Field $_
            Add-Member -InputObject $_ -MemberType NoteProperty -Name '_SIRequiredKeys' -Value $reqKeys -Force
            $_
        }
    )
    return $schema
}

# ---------------------------------------------------------------------------
# Keymap fallback -- direct schema-col -> AZ_*/EG_* metadata-key mapping.
# Used when a schema field has no resolvable sourcePath.
# ---------------------------------------------------------------------------
# keymap key NAMES corrected to match what Discover/Collect actually
# stamp on Metadata (AZ_Type not AZ_ResourceType, AZ_RG not AZ_ResourceGroup,
# AZ_Subscription not AZ_SubscriptionId, AZ_EnvTag not AZ_EnvironmentTag).
# Multiple aliases per schema column so either Discover convention works.
# Az* prefix on subscription / resource-group fields (was
# AzureSubscriptionId / SubscriptionId / ResourceGroup -- now AzSubscriptionId
# / AzResourceGroup). AzureResourceId stays as-is (full ARM path).
$script:_SIAzureKeyMap = @{
    'AzureResourceId'         = @('AZ_ResourceId')
    'AzureResourceId_Guid'    = @('AZ_NodeId')   # short hex form (EG NodeId)
    'NodeId'                  = @('AZ_NodeId')
    'NodeLabel'               = @('AZ_NodeLabel')
    'ExposureGraphNodeId'     = @('AZ_NodeId')
    'AzSubscriptionId'        = @('AZ_Subscription','AZ_SubscriptionId')
    'AzResourceGroup'         = @('AZ_RG','AZ_ResourceGroup')
    'ResourceType'            = @('AZ_Type','AZ_ResourceType')
    'Location'                = @('AZ_Location')
    'Name'                    = @('AZ_Name')
    'AssetName'               = @('AZ_Name')   # cross-engine asset-name alias
    'Kind'                    = @('AZ_Kind')
    'EnvironmentTag'          = @('AZ_EnvTag','AZ_EnvironmentTag')
    'OwnerTag'                = @('AZ_OwnerTag')
    'EG_ExposureScore'        = @('EG_ExposureScore')
    'EG_Criticality'          = @('EG_Criticality')
    'EG_BusinessApp'          = @('EG_BusinessApp')
    'EG_HandlesSensitiveData' = @('EG_HandlesSensitiveData')
    # Audit-gap-fill: MS-computed risk + asset-context signals (parity with endpoint)
    'MsCriticalityLevel'      = @('EG_MsCriticalityLevel')
    'IsCompromisedRecently'   = @('EG_IsCompromisedRecently')
    'IsProductionEnvironment' = @('EG_IsProductionEnvironment')
    'HasInternetExposureSignal' = @('EG_HasInternetExposureSignal')
}

function Get-SIAzureMetaValue {
    param([Parameter(Mandatory)]$Meta, [Parameter(Mandatory)][string]$Key)
    if ($null -eq $Meta) { return $null }
    if ($Meta -is [System.Collections.IDictionary]) {
        if ($Meta.Contains($Key)) { return $Meta[$Key] }
        return $null
    }
    $p = $Meta.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
    return $null
}

function Get-SIWalkPath {
    <# Walks a dotted path against an object (hashtable / pscustomobject).
       Returns $null when any segment is unresolved. Wildcards not supported
       (segment with '*' returns $null -- caller must fall back to keymap). #>
    param([Parameter()]$Obj, [Parameter(Mandatory)][string]$Path)
    if ($null -eq $Obj) { return $null }
    $cur = $Obj
    foreach ($seg in ($Path -split '\.')) {
        if ($null -eq $cur) { return $null }
        if ($seg -match '[\*\?\[]') { return $null }   # wildcard / array indexer not handled here
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains($seg)) { $cur = $cur[$seg] } else { return $null }
        } else {
            if ($cur.PSObject.Properties[$seg]) { $cur = $cur.$seg } else { return $null }
        }
    }
    return $cur
}

function Get-SIAzureCachedBlob {
    <# Lazily parse + cache AZ_PropertiesJson (ARG resource .properties) and
       AZ_PropertiesRawJson (EG rawData) so the schema iteration walks parsed
       objects, not strings. Cache key on the metadata hashtable itself
       (per-record) so each record only parses once. #>
    param([Parameter(Mandatory)]$Meta, [Parameter(Mandatory)][ValidateSet('Properties','Raw','Tags')][string]$Kind)
    $cacheKey = "_SIAzureBlobCache_$Kind"
    if ($Meta -is [System.Collections.IDictionary]) {
        if ($Meta.Contains($cacheKey)) { return $Meta[$cacheKey] }
    } else {
        if ($Meta.PSObject.Properties[$cacheKey]) { return $Meta.$cacheKey }
    }
    $sourceKey = switch ($Kind) {
        'Properties' { 'AZ_PropertiesJson' }
        'Raw'        { 'AZ_PropertiesRawJson' }
        'Tags'       { 'AZ_TagsJson' }
    }
    $raw = Get-SIAzureMetaValue -Meta $Meta -Key $sourceKey
    if (-not $raw) { $raw = Get-SIAzureMetaValue -Meta $Meta -Key ($sourceKey -replace 'Json$','') }   # tolerate non-Json-suffixed
    $parsed = $null
    if ($raw -is [string] -and -not [string]::IsNullOrWhiteSpace($raw)) {
        try { $parsed = $raw | ConvertFrom-Json -ErrorAction Stop } catch { $parsed = $null }
    } elseif ($null -ne $raw) {
        $parsed = $raw   # already an object
    }
    if ($Kind -eq 'Raw' -and $parsed -and $parsed.PSObject.Properties['rawData']) {
        # EG NodeProperties has a top-level rawData wrapper -- unwrap so callers
        # can walk straight into the data fields.
        $parsed = $parsed.rawData
    }
    # Cache on metadata
    if ($Meta -is [System.Collections.IDictionary]) { $Meta[$cacheKey] = $parsed }
    else { Add-Member -InputObject $Meta -MemberType NoteProperty -Name $cacheKey -Value $parsed -Force }
    return $parsed
}

function Resolve-SIAzureSourceValue {
    <# Resolve one schema field to a value from $Meta. Handles all source/
       sourcePath patterns documented at the top of this file. Returns $null
       for unresolvable fields (caller emits null). #>
    param([Parameter(Mandatory)]$Field, [Parameter(Mandatory)]$Meta)
    $src  = [string]$Field.source
    $path = [string]$Field.sourcePath

    # Explicit keymap override beats sourcePath -- keeps fast-path
    # working for fields without a meaningful sourcePath. keymap
    # values are now arrays (alias lists), so we try each alias in order and
    # take the first non-null. Lets one schema column resolve from either of
    # Discover's naming conventions (AZ_Type or AZ_ResourceType, etc).
    if ($script:_SIAzureKeyMap.ContainsKey([string]$Field.name)) {
        foreach ($mapped in @($script:_SIAzureKeyMap[$Field.name])) {
            $val = Get-SIAzureMetaValue -Meta $Meta -Key $mapped
            if ($null -ne $val -and "$val" -ne '') { return $val }
        }
    }

    if ($src -eq 'azure') {
        # v2.2.372 -- Strip 'arm.<resource>.' prefix to get the dotted path
        # inside the resource. Done via Substring() instead of regex when
        # possible (this hot path runs hundreds of times per row).
        # Layout is always 'arm.<single-resource-name>.<rest>'.
        if (-not $path.StartsWith('arm.')) { return $null }
        $afterArm = $path.Substring(4)
        $dot = $afterArm.IndexOf('.')
        if ($dot -lt 0) { return $null }
        $rel = $afterArm.Substring($dot + 1)

        # v2.2.372 -- replaced switch -Regex (recompiles regex per call) with
        # if/elseif chain using string equality + StartsWith. PS 5.1 measurement:
        # switch-Regex ~50us/call, if/StartsWith ~3us/call. At ~282 fields x
        # 13K rows = 3.7M calls, this alone shaves ~3 min off Output phase.
        if ($rel -eq 'id') {
            return [string](Get-SIAzureMetaValue -Meta $Meta -Key 'AZ_ResourceId')
        }
        if ($rel -eq 'subscriptionId') {
            $resId = [string](Get-SIAzureMetaValue -Meta $Meta -Key 'AZ_ResourceId')
            if ($resId -match '/subscriptions/([^/]+)') { return $matches[1] }
            return $null
        }
        if ($rel -eq 'resourceGroup') {
            $resId = [string](Get-SIAzureMetaValue -Meta $Meta -Key 'AZ_ResourceId')
            if ($resId -match '/resourceGroups/([^/]+)') { return $matches[1] }
            return $null
        }
        if ($rel -eq 'name') {
            $resId = [string](Get-SIAzureMetaValue -Meta $Meta -Key 'AZ_ResourceId')
            if (-not $resId) { return $null }
            $segs = $resId.TrimEnd('/').Split('/')
            if ($segs.Length -gt 0) { return $segs[-1] }
            return $null
        }
        if ($rel -eq 'type') {
            $t = Get-SIAzureMetaValue -Meta $Meta -Key 'AZ_Type'
            if (-not $t) { $t = Get-SIAzureMetaValue -Meta $Meta -Key 'AZ_ResourceType' }
            return [string]$t
        }
        if ($rel -eq 'location') { return [string](Get-SIAzureMetaValue -Meta $Meta -Key 'AZ_Location') }
        if ($rel -eq 'kind')     { return [string](Get-SIAzureMetaValue -Meta $Meta -Key 'AZ_Kind') }
        if ($rel.StartsWith('tags.')) {
            $tagPath = $rel.Substring(5)
            $tags = Get-SIAzureCachedBlob -Meta $Meta -Kind Tags
            return Get-SIWalkPath -Obj $tags -Path $tagPath
        }
        if ($rel.StartsWith('properties.')) {
            $propPath = $rel.Substring(11)
            $props = Get-SIAzureCachedBlob -Meta $Meta -Kind Properties
            return Get-SIWalkPath -Obj $props -Path $propPath
        }
        # 'identity.principalId', 'systemData.<...>', etc. -- top-level resource
        # fields not in AZ_PropertiesJson. Not yet collected.
        return $null
    }

    if ($src -eq 'exposureGraph') {
        if ($path -eq 'eg.node.NodeId')    { return [string](Get-SIAzureMetaValue -Meta $Meta -Key 'AZ_NodeId') }
        if ($path -eq 'eg.node.NodeLabel') { return [string](Get-SIAzureMetaValue -Meta $Meta -Key 'AZ_NodeLabel') }
        if ($path.StartsWith('eg.node.NodeProperties.rawData.')) {
            $rawPath = $path.Substring('eg.node.NodeProperties.rawData.'.Length)
            $raw = Get-SIAzureCachedBlob -Meta $Meta -Kind Raw
            return Get-SIWalkPath -Obj $raw -Path $rawPath
        }
        if ($path.StartsWith('rawData.')) {
            $rawPath = $path.Substring(8)
            $raw = Get-SIAzureCachedBlob -Meta $Meta -Kind Raw
            return Get-SIWalkPath -Obj $raw -Path $rawPath
        }
        return $null
    }

    # source='derived' is handled by the caller (per-field switch in Build-SIAzureProfileRow).
    return $null
}

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

function Build-SIAzureProfileRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Record,
        [Parameter()]$RunContext
    )

    $schema = Get-SIAzureSchema
    $meta   = if ($Record.Metadata) { $Record.Metadata } else { @{} }
    $verdict = if ($Record.Verdict) { $Record.Verdict } else { $null }

    $row = [ordered]@{}

    # Standard run-tracking columns required by AzLogDcrIngestPS pipeline
    $row['TimeGenerated']     = if ($Record.TimeGenerated)    { $Record.TimeGenerated }    else { ([datetime]::UtcNow.ToString('o')) }
    $row['CollectionTime']    = if ($RunContext -and $RunContext.CollectionTime) { $RunContext.CollectionTime } else { ([datetime]::UtcNow.ToString('o')) }
    $row['RunId']             = if ($RunContext -and $RunContext.RunId)         { [string]$RunContext.RunId }    else { [string]$Record.SI_RunId }
    # dropped Engine field -- always 'azure' for this engine, redundant
    $row['PrimaryEntityId']   = if ($Record.PrimaryEntityId) { [string]$Record.PrimaryEntityId } else { [string]$Record.AssetId }
    $row['PrimaryEntityType'] = 'AzureResource'
    # dropped AssetId -- always == PrimaryEntityId, redundant

    # Verdict columns -- unprefixed per ARCHITECTURE.md rule 4.
    # ServiceName = classify-stage business-service-name (e.g. "Active Directory"
    # set by AssetProfileByCmdbTag rule). NOT the same as Azure resource Name.
    # dropped Group -- per user, not used downstream.
    if ($verdict) {
        $row['Tier']             = if ($null -ne $verdict.SI_Tier) { [int]$verdict.SI_Tier } else { 3 }
        $row['ServiceType']      = [string]$verdict.SI_ServiceType
        $row['ServiceName']      = [string]$verdict.SI_ServiceName
        $row['Classify_Status']  = [string]$Record.SI_Classify_Status
        $row['SIRules']          = if ($verdict.PSObject.Properties['SI_RuleMatches']) { @($verdict.SI_RuleMatches) } else { @() }
    } else {
        $row['Tier']             = 3
        $row['ServiceType']      = $null
        $row['ServiceName']      = $null
        $row['Classify_Status']  = 'no-verdict'
        $row['SIRules']          = @()
    }

    $row['IsEnabledActive'] = $(
        $stale = if ($global:SI_ActiveStaleDays) { [int]$global:SI_ActiveStaleDays } else { 30 }
        $hasArg = (Get-SIAzureMetaValue -Meta $meta -Key 'AZ_ResourceId') -or (Get-SIAzureMetaValue -Meta $meta -Key 'AZ_PropertiesJson')
        $egLastSeen = Get-SIAzureMetaValue -Meta $meta -Key 'EG_LastSeen'
        if ([string]::IsNullOrWhiteSpace([string]$egLastSeen)) {
            [bool]$hasArg
        } else {
            # v2.2.373 -- ConvertFrom-Json (which produced EG_LastSeen) may have
            # already materialized this as [DateTime]. If so, use directly. If
            # it's a string, parse with InvariantCulture so non-en-US boxes
            # (da-DK etc) don't crash on M/d/yyyy-format strings.
            try {
                $dt = if ($egLastSeen -is [DateTime]) { [DateTime]$egLastSeen } else { [DateTime]::Parse([string]$egLastSeen, [System.Globalization.CultureInfo]::InvariantCulture) }
                $age = ([datetime]::UtcNow - $dt.ToUniversalTime()).TotalDays
                ($age -le $stale)
            } catch { [bool]$hasArg }
        }
    )

    # ---- explicit derivation for top-level Azure columns ----
    # AzureResourceId is the FULL ARM path (/subscriptions/.../providers/...).
    # AzureResourceId_Guid is the short GUID (final segment for resource-id-style,
    # or the EG NodeId hex for EG-only rows).
    # AzSubscriptionId / AzResourceGroup get the Az prefix to be unambiguously
    # Azure-namespaced (replaces 's SubscriptionId/ResourceGroup).
    # Name is the resource short name from ARM (AZ_Name); empty for EG-only
    # opaque-hex nodes (no longer falls back to the hex -- prevents GUID-as-name).
    $resId = [string](Get-SIAzureMetaValue -Meta $meta -Key 'AZ_ResourceId')
    $egNodeId = [string](Get-SIAzureMetaValue -Meta $meta -Key 'AZ_NodeId')
    if ($resId -and $resId -like '/subscriptions/*') {
        # Full ARM path
        $row['AzureResourceId']      = $resId
        $row['AzureResourceId_Guid'] = if ($egNodeId) { $egNodeId } else {
            # Last segment of ARM path is usually the resource name (not a GUID),
            # so fall back to empty when no separate EG hex available.
            ''
        }
        if ($resId -match '/subscriptions/([^/]+)')   { $row['AzSubscriptionId'] = $matches[1] }
        if ($resId -match '/resourceGroups/([^/]+)')  { $row['AzResourceGroup']  = $matches[1] }
        if ($resId -match '/providers/(.+)$') {
            $segs = $resId.TrimEnd('/').Split('/')
            if ($segs.Length -gt 0) { $row['Name'] = $segs[-1] }
            $afterProviders = $matches[1] -split '/'
            if ($afterProviders.Count -ge 3) {
                $row['ResourceType'] = ($afterProviders[0..($afterProviders.Count - 2)] -join '/')
            }
        }
    } elseif ($egNodeId) {
        # EG-only (opaque hex). No ARM path available.
        $row['AzureResourceId']      = ''     # unknown -- caller can detect via empty + non-empty Guid
        $row['AzureResourceId_Guid'] = $egNodeId
        $row['AzSubscriptionId']     = ''
        $row['AzResourceGroup']      = ''
        $azName = [string](Get-SIAzureMetaValue -Meta $meta -Key 'AZ_Name')
        if ($azName -and $azName -ne $egNodeId) { $row['Name'] = $azName } else { $row['Name'] = '' }
    }
    # AZ_Type from Discover wins over the regex-derived form (it's lowercased and authoritative).
    $azType = Get-SIAzureMetaValue -Meta $meta -Key 'AZ_Type'
    if (-not $azType) { $azType = Get-SIAzureMetaValue -Meta $meta -Key 'AZ_ResourceType' }
    if ($azType) { $row['ResourceType'] = [string]$azType }
    # EG-only nodes (no ARG match) have an opaque NodeId hex in
    # AzureResourceId -- the /providers/.../  regex fails. Fall back to AZ_NodeLabel
    # (which carries 'microsoft.<provider>/<type>' for these rows).
    if (-not $row['ResourceType']) {
        $nl = Get-SIAzureMetaValue -Meta $meta -Key 'AZ_NodeLabel'
        if ($nl) { $row['ResourceType'] = [string]$nl }
    }
    # EG-only rows -- pull Location + AzureSubscriptionId from
    # parsed AZ_PropertiesRawJson.rawData (EG carries them as
    # nativeEnvironmentRegionName + hierarchyIdentifier when hierarchyType ==
    # 'subscriptionid').
    $egRawForDerive = Get-SIAzureCachedBlob -Meta $meta -Kind Raw
    if ($egRawForDerive) {
        if (-not $row['Location'] -and $egRawForDerive.PSObject.Properties['nativeEnvironmentRegionName']) {
            $row['Location'] = [string]$egRawForDerive.nativeEnvironmentRegionName
        }
        if ((-not $row['AzureSubscriptionId']) -and
            $egRawForDerive.PSObject.Properties['hierarchyType'] -and
            $egRawForDerive.hierarchyType -eq 'subscriptionid' -and
            $egRawForDerive.PSObject.Properties['hierarchyIdentifier']) {
            $row['AzureSubscriptionId'] = [string]$egRawForDerive.hierarchyIdentifier
            $row['SubscriptionId']      = [string]$egRawForDerive.hierarchyIdentifier
        }
    }
    # Location / Kind / NodeId / NodeLabel / Tag columns -- direct map from Discover.
    foreach ($pair in @(
        @{ Col='Location';            Keys=@('AZ_Location') },
        @{ Col='Kind';                Keys=@('AZ_Kind') },
        @{ Col='NodeId';              Keys=@('AZ_NodeId') },
        @{ Col='NodeLabel';           Keys=@('AZ_NodeLabel') },
        @{ Col='ExposureGraphNodeId'; Keys=@('AZ_NodeId') },
        @{ Col='EnvironmentTag';      Keys=@('AZ_EnvTag','AZ_EnvironmentTag') },
        @{ Col='OwnerTag';            Keys=@('AZ_OwnerTag') }
    )) {
        foreach ($k in $pair.Keys) {
            $v = Get-SIAzureMetaValue -Meta $meta -Key $k
            if ($null -ne $v -and "$v" -ne '') { $row[$pair.Col] = $v; break }
        }
    }

    # ---- schema-driven iteration ----
    # Walk every declared field in azure.schema.json and resolve via the unified
    # resolver. Skip fields already explicitly set above (run-tracking, verdict,
    # IsEnabledActive). Skip purpose=enrichment/forensic/raw (they belong under
    # Properties.collect, not as flat columns). Skip fields with emit=false.
    $alreadySet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($k in $row.Keys) { [void]$alreadySet.Add([string]$k) }

    # v2.2.371 -- iterate the pre-filtered emit-fields cache built in
    # Get-SIAzureSchema instead of re-checking emit/purpose/name flags per row.
    # v2.2.372 -- build a per-row availKeys HashSet (which metadata keys are
    # populated for this record) so we can fast-null fields whose required
    # source keys are absent, skipping the regex+path-walk in
    # Resolve-SIAzureSourceValue. Customer 13K Azure run showed 182 of 311
    # columns always-null = ~58% of per-row iteration is provably wasted work.
    $availKeys = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
    if ($meta -is [System.Collections.IDictionary]) {
        foreach ($k in $meta.Keys) {
            $v = $meta[$k]
            if ($null -ne $v -and "$v" -ne '') { [void]$availKeys.Add([string]$k) }
        }
    } else {
        foreach ($p in $meta.PSObject.Properties) {
            if ($null -ne $p.Value -and "$p.Value" -ne '') { [void]$availKeys.Add([string]$p.Name) }
        }
    }
    foreach ($f in $script:_SISchemaCache['AzureEmitFields']) {
        $fname = [string]$f.name
        if ($alreadySet.Contains($fname)) { continue }
        # ALWAYS emit the column (even as $null) so AzLogDcrIngestPS
        # discovers it in the schema-sample dataset and adds it to the DCR + LA
        # table. Previously we only set non-null values, which meant sparse
        # per-type fields (Pip*, Acr*, Sql*, ...) were never seen by AzLogDcr-
        # IngestPS for resource types that don't carry them -- the table only
        # surfaced the union of POPULATED fields (~120) instead of the full
        # schema (~282).
        # v2.2.372 fast-null: if the field declares required metadata keys
        # and NONE of them are populated on this row, skip Resolve and emit
        # $null directly. Column is still in the row, schema contract preserved,
        # downstream RA queries unchanged -- just no wasted regex+walk per row.
        $reqKeys = $f._SIRequiredKeys
        if ($reqKeys -and $reqKeys.Count -gt 0) {
            $hasAny = $false
            foreach ($rk in $reqKeys) { if ($availKeys.Contains($rk)) { $hasAny = $true; break } }
            if (-not $hasAny) { $row[$fname] = $null; continue }
        }
        $val = Resolve-SIAzureSourceValue -Field $f -Meta $meta
        $row[$fname] = $val
    }

    # ---- Properties JSON envelope ----
    # properties bucket reorg. Was: {meta, collect:{azure, cmdb}}
    # where collect.azure conflated ARG resource properties + EG rawData.
    # Now: {meta, azure (ARG), exposuregraph (EG NodeProperties + edges),
    # collect:{cmdb (Reconcile-stamped CMDB_* keys)}}. Tags get their own
    # bucket: properties.azure.tags (direct).
    # parent-sub + parent-MG tag inheritance + name chain wired in.
    $argBlob = Get-SIAzureCachedBlob -Meta $meta -Kind Properties   # parsed AZ_PropertiesJson
    $egBlob  = Get-SIAzureCachedBlob -Meta $meta -Kind Raw          # parsed AZ_PropertiesRawJson (EG rawData)
    $tagsBlob = Get-SIAzureCachedBlob -Meta $meta -Kind Tags        # parsed AZ_TagsJson
    if (-not $argBlob) { $argBlob = @{} }
    if (-not $egBlob)  { $egBlob = @{} }
    if (-not $tagsBlob) { $tagsBlob = @{} }
    # Attach direct tags into the azure properties bucket.
    if ($tagsBlob -and $argBlob -is [System.Collections.IDictionary]) { $argBlob['tags'] = $tagsBlob }
    elseif ($tagsBlob) {
        try { Add-Member -InputObject $argBlob -MemberType NoteProperty -Name 'tags' -Value $tagsBlob -Force } catch {}
    }

    # ---- parent-scope tag + name inheritance ----
    # Lazy-load the parent-scope cache helpers (per-run singletons inside).
    if (-not (Get-Command -Name Get-SIAzureSubscriptionScope -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'AzureParentScopeCache.ps1')
    }
    $parentTags  = @{}
    $parentNames = @{}
    $mgChain     = @()
    $subIdForLookup = [string]$row['AzSubscriptionId']
    if (-not $subIdForLookup -and $resId -match '/subscriptions/([^/]+)') { $subIdForLookup = $matches[1] }
    if ($subIdForLookup) {
        try {
            $subScope = Get-SIAzureSubscriptionScope -SubscriptionId $subIdForLookup
            if ($subScope) {
                if ($subScope.Tags -and $subScope.Tags.Count -gt 0) { $parentTags['subscription'] = $subScope.Tags }
                if ($subScope.Name) { $parentNames['subscription'] = [string]$subScope.Name }
            }
        } catch {
            # Cache failure must not crash row build -- swallow.
        }
        try {
            $mg = Get-SIAzureManagementGroupChain -SubscriptionId $subIdForLookup
            if ($mg) {
                if ($mg.MergedTags -and $mg.MergedTags.Count -gt 0) { $parentTags['managementGroups'] = $mg.MergedTags }
                if ($mg.ChainDisplayNames -and $mg.ChainDisplayNames.Count -gt 0) {
                    $parentNames['managementGroups'] = @($mg.ChainDisplayNames)
                    $mgChain = @($mg.ChainDisplayNames)
                }
            }
        } catch { }
    }
    if ($parentTags.Count -gt 0 -or $parentNames.Count -gt 0) {
        $azureBucketKeys = @{
            parentTags  = $parentTags
            parentNames = $parentNames
        }
        if ($argBlob -is [System.Collections.IDictionary]) {
            if ($parentTags.Count -gt 0)  { $argBlob['parentTags']  = $parentTags }
            if ($parentNames.Count -gt 0) { $argBlob['parentNames'] = $parentNames }
        } else {
            try {
                if ($parentTags.Count -gt 0)  { Add-Member -InputObject $argBlob -MemberType NoteProperty -Name 'parentTags'  -Value $parentTags  -Force }
                if ($parentNames.Count -gt 0) { Add-Member -InputObject $argBlob -MemberType NoteProperty -Name 'parentNames' -Value $parentNames -Force }
            } catch {}
        }
    }

    # ---- ParentMG_Structure flat column ----
    # Slash-separated path 'Tenant/Engineering/Production/<sub-name>'. The
    # sub-name is appended only when we resolved one (parent-sub cache hit);
    # when ARG didn't return a sub row, the path stops at the deepest MG.
    if ($mgChain.Count -gt 0) {
        $structureSegs = @($mgChain)
        if ($parentNames.ContainsKey('subscription') -and $parentNames['subscription']) {
            $structureSegs = $structureSegs + ,([string]$parentNames['subscription'])
        }
        $row['ParentMG_Structure'] = ($structureSegs -join '/')
    } elseif ($parentNames.ContainsKey('subscription') -and $parentNames['subscription']) {
        # No MG chain but we know the sub name -- emit the sub by itself so the
        # column isn't empty when the principal can read subs but not MGs.
        $row['ParentMG_Structure'] = [string]$parentNames['subscription']
    } else {
        $row['ParentMG_Structure'] = $null
    }
    $collectCmdb = @{}
    if ($meta -is [System.Collections.IDictionary]) {
        foreach ($k in $meta.Keys)            { if ($k -like 'CMDB_*')      { $collectCmdb[$k.Substring(5)]      = $meta[$k] } }
    } else {
        foreach ($p in $meta.PSObject.Properties) { if ($p.Name -like 'CMDB_*') { $collectCmdb[$p.Name.Substring(5)] = $p.Value } }
    }
    $propertiesObj = @{
        meta = @{
            schema_version   = if ($schema -and $schema.schemaVersion) { [string]$schema.schemaVersion } else { 'unknown' }
            schema_authority = 'v2.2/asset-profiling-schema/azure.schema.locked.json'
        }
        azure        = $argBlob
        exposuregraph = $egBlob
        collect      = @{
            cmdb = $collectCmdb
        }
    }
    # v2.2.373 -- reduced ConvertTo-Json depth from 15 to 8. Real Azure ARG
    # property trees rarely exceed 6 levels (deepest known: VM
    # .properties.osProfile.windowsConfiguration.winRM.listeners[].protocol = 6).
    # Plus our 2-level wrapper (azure -> properties) = 8. Depth 15 had ConvertTo-Json
    # walking impossible depths AND testing the recursion-limit on every nested
    # value, which dominates the per-row JSON cost. Depth 8 is the safe ceiling.
    $row['Properties'] = try { $propertiesObj | ConvertTo-Json -Depth 8 -Compress -WarningAction SilentlyContinue } catch { '{}' }

    # ---- EntityIds (cross-engine correlation handles) ----
    # Always emit AzureResourceId (when known) + EG NodeId (when known). Then
    # cross-correlate against SI_Endpoint_Profile_CL via the cross-engine cache
    # to attach an MdeDeviceId entry whenever the resource is an Azure VM or
    # Arc machine that the endpoint engine has profiled.
    $entityIds = New-Object System.Collections.Generic.List[object]
    if ($resId)    { [void]$entityIds.Add(@{ type='AzureResourceId';     id=$resId;    source='azure' }) }
    if ($egNodeId -and ($egNodeId -ne $resId)) {
                    [void]$entityIds.Add(@{ type='ExposureGraphNodeId'; id=$egNodeId; source='exposureGraph' })
    }
    $rtForCorrelation = [string]$row['ResourceType']
    if ($rtForCorrelation) { $rtLower = $rtForCorrelation.ToLowerInvariant() } else { $rtLower = '' }
    if ($resId -and ($rtLower -eq 'microsoft.compute/virtualmachines' -or $rtLower -eq 'microsoft.hybridcompute/machines')) {
        if (-not (Get-Command -Name Get-SIEndpointMdeDeviceIdForAzureResource -ErrorAction SilentlyContinue)) {
            . (Join-Path $PSScriptRoot 'EndpointAzureCorrelationCache.ps1')
        }
        try {
            $mdeId = Get-SIEndpointMdeDeviceIdForAzureResource -AzureResourceId $resId
            if ($mdeId) { [void]$entityIds.Add(@{ type='MdeDeviceId'; id=$mdeId; source='mde-correlation' }) }
        } catch {
            # Correlation lookup must never fail row build.
        }
    }
    $row['EntityIds'] = $entityIds.ToArray()

    # ---- CMDB / Reconcile flat columns ----
    # 2026-05-02: defensive scalar coercion for cmdb* string columns. Without this,
    # @{} / pscustomobject values upstream serialize to the literal string "{}" in
    # LA + Excel. Empty containers collapse to '' instead.
    $cmdbStringFields = @('cmdbId','cmdbName','cmdbCriticality','cmdbDataSensitivity',
                          'CmdbMatchPhase','CmdbMatchState','CmdbMatchRule','LastSeenInCmdb')
    foreach ($f in $cmdbStringFields) {
        $v = if ($Record.PSObject.Properties[$f]) { $Record.$f } else { $null }
        if ($null -eq $v) { $row[$f] = $null; continue }
        if ($v -is [System.Collections.IDictionary] -or $v -is [pscustomobject] -or
            (($v -is [System.Collections.IEnumerable]) -and -not ($v -is [string]))) {
            $row[$f] = ''
            continue
        }
        $row[$f] = [string]$v
    }
    $v = if ($Record.PSObject.Properties['CmdbMatchConfidence']) { $Record.CmdbMatchConfidence } else { $null }
    $row['CmdbMatchConfidence'] = $v
    # cmdbCriticalityScore moved to riskscore_weighted.schema.json
    # (declarative model). See Build-EndpointProfileRow.ps1 for the rationale.

    # ---- profile-time risk-factor derivations ----
    if (-not (Get-Command -Name Get-SIAzureRiskFactors -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'Get-SIRiskFactors.ps1')
    }
    # v2.2.371 -- avoid Add-Member-per-key (~300 Add-Member calls per row).
    # Get-SIRecordValue walks Record.<key> | Record.Verdict.<key> | Record.Metadata.<key>;
    # building the pscustomobject from a single hashtable union is ~50x faster
    # than the equivalent Add-Member loop on PS 5.1.
    $rfHash = @{} + $row
    $rfHash['Verdict']  = $verdict
    $rfHash['Metadata'] = $meta
    $rf = Get-SIAzureRiskFactors -Record ([pscustomobject]$rfHash)
    foreach ($k in $rf.Keys) { $row[$k] = $rf[$k] }

    # AssetName: cross-engine alias resolved by walking provider sources in
    # priority order (per user directive "use all the providers
    # as options for the AssetName -- entra, mde, AD, azure, EG" + "in azure
    # it is called Name or ResourceName - look in ARG for the name" + "or
    # use last entry of resourceid"). Azure engine: ARG-supplied 'Name' (top
    # of metadata bag, set by Get-DiscoveryFromAzureResources) is the
    # canonical resource short-name. EG fallback via NodeName/NodeLabel.
    # Schema added the field but never wired the derivation ->
    # AssetName always null on Azure rows.
    if (-not $row['AssetName'] -or [string]::IsNullOrWhiteSpace([string]$row['AssetName'])) {
        $candidates = @(
            [string](Get-SIAzureMetaValue -Meta $meta -Key 'Name'),                   # ARG row.name + EG NodeName (top-of-bag, all azure discovery sources)
            [string](Get-SIAzureMetaValue -Meta $meta -Key 'AZ_Name'),                # legacy explicit key (unused by current discovery, kept for compat)
            [string]$row['Name'],                                                      # already-resolved last-ARM-segment short name
            [string](Get-SIAzureMetaValue -Meta $meta -Key 'AZ_NodeLabel'),           # EG node label (e.g. 'microsoft.compute/virtualmachines')
            [string](Get-SIAzureMetaValue -Meta $meta -Key 'EG_DeviceName'),          # EG device-name (rare)
            $(if ($row['AzureResourceId']) { ($row['AzureResourceId'] -split '/')[-1] } else { '' }),  # last segment of full ARM resourceId
            [string](Get-SIAzureMetaValue -Meta $meta -Key 'AZ_NodeId')               # last resort: opaque hex
        )
        foreach ($c in $candidates) {
            if (-not [string]::IsNullOrWhiteSpace($c)) { $row['AssetName'] = $c; break }
        }
    }

    # Schema-author audit
    $row['MetaSchemaAuthority'] = 'v2.2/asset-profiling-schema/azure.schema.locked.json'
    $row['MetaSchemaVersion']   = if ($schema -and $schema.schemaVersion) { [string]$schema.schemaVersion } else { 'unknown' }

    return [pscustomobject]$row
}
