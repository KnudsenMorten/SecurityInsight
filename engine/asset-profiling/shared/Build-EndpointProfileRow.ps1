#Requires -Version 5.1
<#
    Build-EndpointProfileRow.ps1

    Schema-driven row builder for the endpoint engine. Reads
    profiles/endpoint.schema.json once (cached), then for each declared
    field looks up the value via its `source` + `sourcePath` (or `derivation`)
    and emits a row whose columns EXACTLY match the schema -- no extras,
    no drops, no renames.

    Honored schema constructs (mirrors Build-IdentityProfileRow.ps1):
      - field.name                 -> output column name
      - field.purpose              -> determines flat vs nested. Nested
                                     purposes (enrichment, forensic, raw)
                                     are NOT emitted as flat columns; they
                                     belong under Properties.* if anywhere.
      - field.source               -> 'mde'|'exposureGraph'|'azure'|'derived'
      - field.sourcePath           -> path on the upstream object; resolved
                                     by Resolve-SISourceValue per source.
      - field.derivation.algorithm -> dispatched by Get-SIDerivedValue.
      - field.emit                 -> default true. When false, field is
                                     declared in schema (for documentation /
                                     downstream consumers) but NOT sent to LA.

    Schema fields this builder doesn't yet know how to populate emit as $null;
    operators see the gap in LA and we add the dispatch.
#>

# The default tier is a RULE (asset-profiling-enrichment/shared/AssetProfileByDefaultTier.locked.yaml), not a constant.
if (-not (Get-Command -Name Get-SIDefaultTierValue -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'Resolve-SIDefaultTier.ps1') }
# #562 the asset type / subtype come from the ONE classification (the CI build's rows and value maps).
if (-not (Get-Command -Name Get-SIProfileAssetClassification -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '..\..\data-model\SI-ProfileClassification.ps1') }

if (-not (Get-Variable -Name _SISchemaCache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:_SISchemaCache = @{}
}

# ---------------------------------------------------------------------------
# SCHEMA + CATALOG LOADERS
# ---------------------------------------------------------------------------

function Get-SIEndpointFieldRequiredKeys {
    <# v2.2.374 -- mirror of the Azure helper. Given a schema field, return the
       list of metadata keys whose presence is REQUIRED for the field to
       possibly resolve to non-null. Empty list = no fast-null possible (run
       Resolve normally; covers source='derived' and unmappable fields). #>
    param($Field)
    $src  = [string]$Field.source
    $name = [string]$Field.name
    $keys = New-Object System.Collections.Generic.List[string]
    if ($script:_SIEndpointKeyMap.ContainsKey($name)) {
        [void]$keys.Add([string]$script:_SIEndpointKeyMap[$name])
    }
    if ($src -eq 'exposureGraph') { [void]$keys.Add('EG_RawData') }
    return $keys
}

function Get-SIEndpointSchema {
    if ($script:_SISchemaCache.ContainsKey('EndpointSchema')) { return $script:_SISchemaCache['EndpointSchema'] }
    # locked + custom merge (profiles/endpoint.schema.json + profiles-custom/endpoint.schema.custom.json)
    . (Join-Path $PSScriptRoot 'Get-SISchemaWithCustomMerge.ps1')
    $schema = Get-SISchemaWithCustomMerge -Engine endpoint
    $script:_SISchemaCache['EndpointSchema'] = $schema
    # v2.2.374 -- pre-filter emit-able fields once + annotate each with
    # _SIRequiredKeys so per-row iteration can fast-null fields whose required
    # source data isn't present. Same pattern as Azure v2.2.371/372.
    $script:_SISchemaCache['EndpointEmitFields'] = @(
        $schema.fields | Where-Object {
            $fn = [string]$_.name
            $fn -and `
            (-not $_.PSObject.Properties['emit'] -or $_.emit -ne $false) -and `
            ([string]$_.purpose -notin 'enrichment','forensic','raw') -and `
            ($fn -notin 'CollectHash','EnrichHash','PostureHash','ClassifyHash')
        } | ForEach-Object {
            $reqKeys = Get-SIEndpointFieldRequiredKeys -Field $_
            Add-Member -InputObject $_ -MemberType NoteProperty -Name '_SIRequiredKeys' -Value $reqKeys -Force
            $_
        }
    )
    return $schema
}

function Get-SIEndpointCatalogVersion {
    if ($script:_SISchemaCache.ContainsKey('EndpointCatalogVersion')) { return $script:_SISchemaCache['EndpointCatalogVersion'] }
    $catPath = Join-Path $PSScriptRoot 'endpoint-tiering.json'
    if (-not (Test-Path $catPath)) { return 'unknown' }
    try {
        $raw = Get-Content $catPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $v = [string]$raw.Metadata.GeneratedAt
        $script:_SISchemaCache['EndpointCatalogVersion'] = $v
        return $v
    } catch { return 'unknown' }
}

# ---------------------------------------------------------------------------
# SOURCE EXTRACTORS
# Maps schema field -> location on $Record.Metadata. Engine reads the same
# Metadata blob the v2.2 endpoint engine already populates -- no re-collection.
#
# Endpoint metadata bag uses prefixes:
#   MDE_*    Microsoft Defender for Endpoint machine attributes (and DeviceInfo)
#   EG_*     Exposure Graph node properties (raw + extracted)
#   AZ_*     Azure ARM resource attributes (when device is Azure VM)
#   INTUNE_* Intune device attributes (future)
# ---------------------------------------------------------------------------

$script:_SIEndpointKeyMap = @{
    # Identity / correlation
    'MdeDeviceId'                              = 'MDE_DeviceId'
    'DeviceName'                               = 'MDE_DeviceName'
    'Hostname'                                 = 'MDE_DeviceName'
    'AadDeviceId'                              = 'EG_AadDeviceId'
    'AzureResourceId'                          = 'MDE_AzureResourceId'
    'HardwareUuid'                             = 'MDE_HardwareUuid'
    'AzureVmId'                                = 'MDE_AzureVmId'
    'AzureVmSubscriptionId'                    = 'MDE_AzureVmSubscriptionId'
    'AwsResourceName'                          = 'MDE_AwsResourceName'
    'GcpFullResourceName'                      = 'MDE_GcpFullResourceName'
    'HostDeviceId'                             = 'MDE_HostDeviceId'
    'MergedDeviceIds'                          = 'MDE_MergedDeviceIds'
    'MergedToDeviceId'                         = 'MDE_MergedToDeviceId'

    # Management ownership -- who actually manages this device, as MDE reports it. Read by
    # Get-SICmdbAssetType to tell an Intune-managed device from an unmanaged one, which decides whether
    # SI may ever create a CI for it (V3-ARCHITECTURE 4.8b). Without it every such device classified
    # `unknown` and routed to match-only: safe, but 94 of 238 assets invisible to the ownership map.
    'ManagedBy'                                = 'MDE_ManagedBy'
    'ManagedByStatus'                          = 'MDE_ManagedByStatus'

    # OS pivot
    'OsPlatform'                               = 'MDE_OSPlatform'
    'OsVersion'                                = 'MDE_OSVersion'
    'OsBuild'                                  = 'EG_OsBuild'
    'OsArchitecture'                           = 'EG_OsArchitecture'
    'OsProcessor'                              = 'MDE_OsProcessor'
    'OsBuildRevision'                          = 'MDE_OsBuildRevision'
    'OsVersionInfo'                            = 'MDE_OsVersionInfo'

    # Sensor / posture
    'SensorHealthState'                        = 'MDE_SensorHealthState'
    'SenseClientVersion'                       = 'EG_SenseClientVersion'
    'OnboardingStatus'                         = 'MDE_OnboardingStatus'
    'HealthStatus'                             = 'MDE_HealthStatus'
    'DefenderAvStatus'                         = 'MDE_DefenderAvStatus'
    'EdrMode'                                  = 'MDE_EdrMode'
    'IsPotentialDuplication'                   = 'MDE_IsPotentialDuplication'
    'IsExcluded'                               = 'MDE_IsExcluded'
    'ExclusionReason'                          = 'MDE_ExclusionReason'
    'IsTransient'                              = 'MDE_IsTransient'
    'MitigationStatus'                         = 'MDE_MitigationStatus'

    # Join state
    'IsAzureADJoined'                          = 'MDE_IsAzureADJoined'
    'IsHybridAzureADJoined'                    = 'MDE_IsHybridAzureADJoined'
    'AzureADJoinType'                          = 'EG_AzureADJoinType'

    # RBAC / grouping / tags
    'RbacGroupName'                            = 'MDE_RbacGroupName'
    'MachineGroup'                             = 'MDE_MachineGroup'
    'MachineTags'                              = 'MDE_MachineTags'

    # EG / MDE device classification. DeviceCategory / DeviceType / MachineGroup /
    # Vendor / Model are populated by the DeviceInfo enrichment branch in Stage
    # Collect (Invoke-Collect.ps1:200-216) under MDE_* prefix, NOT EG_*. The
    # earlier EG_* mapping was the cause of these columns landing empty even
    # for MDE-discovered devices.
    'DeviceCategory'                           = 'MDE_DeviceCategory'
    'DeviceType'                               = 'MDE_DeviceType'
    'DeviceSubtype'                            = 'EG_DeviceSubtype'
    'DeviceRole'                               = 'EG_DeviceRole'
    'DeviceDynamicTags'                        = 'EG_DeviceDynamicTags'
    'DeviceManualTags'                         = 'EG_DeviceManualTags'
    'GraphInternalLabel'                       = 'EG_GraphInternalLabel'
    'Vendor'                                   = 'MDE_Vendor'
    'Model'                                    = 'MDE_Model'

    # Network identity
    'PublicIp'                                 = 'MDE_PublicIp'

    # Lifecycle / freshness
    'LastSeen'                                 = 'MDE_LastSeen'
    'EgLastSeen'                               = 'EG_LastSeen'
    'FirstSeen'                                = 'MDE_FirstSeen'
    'FirstSeenByInventory'                     = 'EG_FirstSeenByInventory'
    'OnboardedDateTime'                        = 'MDE_OnboardedDateTime'
    'OffboardedDateTime'                       = 'MDE_OffboardedDateTime'

    # Risk / scores
    # MDE returns this field as 'ExposureScore' (None|Low|Medium|High),
    # not 'ExposureLevel'. Map the schema column to the actual MDE source key so
    # the column populates instead of staying empty for every device.
    'ExposureLevel'                            = 'MDE_ExposureScore'
    'RiskScore'                                = 'MDE_RiskScore'
    'DeviceValue'                              = 'MDE_DeviceValue'
    'AssetValue'                               = 'MDE_AssetValue'
    'JoinType'                                 = 'MDE_JoinType'
    'DefenderAvMode'                           = 'MDE_DefenderAvMode'
    # schema postfixed with source after dedup (`EffectiveIpAddresses_mde`
    # + `EffectiveIpAddresses_derived` -- the derived variant is populated in
    # Profile stage, not here). Output column LEFT side now matches the schema.
    'EffectiveIpAddresses_mde'                 = 'MDE_EffectiveIpAddresses'
    'IsCustomerFacing'                         = 'EG_IsCustomerFacing'
    'IsInternetFacing'                         = 'MDE_IsInternetFacing'
    # New EG-derived signals (preview audit gap fill).
    # MS-computed risk verdicts surfaced as comparison columns. Tier still sources
    # from CL only (per feedback_si_ra_tier_source); these populate MoreDetails
    # + RiskFactor_*_Detailed tokens.
    'MsCriticalityLevel'                       = 'EG_MsCriticalityLevel'
    'MachineRiskState'                         = 'EG_MachineRiskState'
    'IsCompromisedRecently'                    = 'EG_IsCompromisedRecently'
    'IsProductionEnvironment'                  = 'EG_IsProductionEnvironment'
    'IsAdfsServer'                             = 'EG_IsAdfsServer'

    # EG criticality
    # EG discovery emits this field as 'EG_Criticality' (matches
    # rawData.criticality), not 'EG_CriticalityLevel'. The mismatch made the
    # CriticalityLevel column report 0% in the audit forever.
    'CriticalityLevel'                         = 'EG_Criticality'
    'RuleBasedCriticalityLevel'                = 'EG_RuleBasedCriticalityLevel'
    'ManualCriticalityLevel'                   = 'EG_ManualCriticalityLevel'
    'CriticalityRuleNames'                     = 'EG_CriticalityRuleNames'

    # EG misconfigurations / dup hints
    'HasGuardMisconfigurations'                = 'EG_HasGuardMisconfigurations'
    'HasAuthorityMisConfigurations'            = 'EG_HasAuthorityMisConfigurations'
    'PotentialDuplicateOf'                     = 'EG_PotentialDuplicateOf'

    # EG attribution
    'DiscoverySourceProducts'                  = 'EG_DiscoverySourceProducts'
    'DeviceRegistryTags'                       = 'EG_DeviceRegistryTags'
    # schema postfixed -- `RegistryDeviceTag_exposureGraph` (this row)
    # plus `RegistryDeviceTag_mde` (populated when MDE source is wired up; the
    # current value came from EG, so the EG variant is what we emit today).
    'RegistryDeviceTag_exposureGraph'          = 'EG_RegistryDeviceTag'
    'MachineSid'                               = 'EG_MachineSid'

    # TPM
    'TpmSupported'                             = 'EG_TpmSupported'
    'TpmActivated'                             = 'EG_TpmActivated'
    'TpmEnabled'                               = 'EG_TpmEnabled'
    'TpmVersion'                               = 'EG_TpmVersion'

    # Remote services
    'SmbEnableSmb1Protocol'                    = 'EG_SmbEnableSmb1Protocol'
    'SmbRequireSecuritySignature'              = 'EG_SmbRequireSecuritySignature'
    'SmbEncryptData'                           = 'EG_SmbEncryptData'
    'RdpAllowConnections'                      = 'EG_RdpAllowConnections'
    'RdpNlaRequired'                           = 'EG_RdpNlaRequired'
    'RdpServiceRunning'                        = 'EG_RdpServiceRunning'
    'WinRmServiceRunning'                      = 'EG_WinRmServiceRunning'

    # Defender for Servers applicability
    'IsApplicableForDefenderForServers'        = 'EG_IsApplicableForDefenderForServers'
    'IsApplicableForDefenderForServersReason'  = 'EG_IsApplicableForDefenderForServersReason'
    'IsUsiServer'                              = 'EG_IsUsiServer'

    # Vulns
    'VulnerabilityCount'                       = 'MDE_VulnerabilityCount'
    'MissingKbCount'                           = 'MDE_MissingKbCount'

    # Internet exposure (EG-direct)
    'ExposedToInternet'                        = 'EG_ExposedToInternet'
    'ExposureSourceCidrs'                      = 'EG_ExposureSourceCidrs'
    'IdentifiedResourceUsersCount'             = 'EG_IdentifiedResourceUsersCount'

    # Logged-on users (DeviceInfo)
    # schema postfixed -- `LoggedOnUsersCount_mde` (this row) and
    # `LoggedOnUsersCount_derived` (populated in Profile stage from the dedup
    # of LoggedOnUsers[]). Today only the MDE variant flows through here.
    'LoggedOnUsersCount_mde'                   = 'MDE_LoggedOnUsersCount'
    'LoggedOnUsers'                            = 'MDE_LoggedOnUsers'
    'LoggedOnUserSids'                         = 'MDE_LoggedOnUserSids'

    # Cloud platform pivots
    'CloudPlatforms'                           = 'MDE_CloudPlatforms'
    'ConnectivityType'                         = 'MDE_ConnectivityType'
    'Site'                                     = 'MDE_Site'

    # Azure-source
    'Owner'                                    = 'AZ_Owner'
    'Region'                                   = 'AZ_Region'
}

function Resolve-SISourceValue {
    param([Parameter(Mandatory)] $Field, [Parameter(Mandatory)] $Record)
    $meta = if ($Record.Metadata) { $Record.Metadata } else { @{} }

    # PS 5.1 unwraps single-element arrays at function-return through the pipeline.
    # That collapsed 1-item arrays in dynamic-typed columns (e.g. LoggedOnUsers,
    # MachineTags) into scalar strings -- LA's Dynamic column then stored a JSON
    # scalar instead of a JSON array. The comma operator (`,$val`) wraps in an
    # outer 1-element array; PS unwraps the outer wrap, leaving the original
    # value's shape intact (works for arrays, hashtables, scalars, and $null).

    # source: exposureGraph -- walk the schema-declared sourcePath against the
    # cached EG rawData blob (populated by Get-SIExposureGraphEndpoints in
    # discovery and stashed as EG_RawData on the record). Path format:
    #   eg.node.NodeProperties.rawData.<dotted.path>
    # We strip the well-known prefix and walk the remainder. Adding a new
    # EG-sourced field is now a JSON edit only -- BUT only if the key is not
    # already extracted as an EG_* metadata key (in which case the key map
    # below short-circuits the EG raw walk).
    if ($Field.source -eq 'exposureGraph') {
        # First try the key map (EG fields the discovery already extracted).
        $mapped = $script:_SIEndpointKeyMap[$Field.name]
        if ($mapped) {
            if ($meta -is [System.Collections.IDictionary]) {
                if ($meta.Contains($mapped)) { return ,$meta[$mapped] }
            } else {
                if ($meta.PSObject.Properties[$mapped]) { return ,$meta.$mapped }
            }
        }

        # Fall back to walking EG_RawData (shape-tolerant: hashtable or pscustomobject).
        $eg = if ($meta -is [System.Collections.IDictionary]) {
                if ($meta.Contains('EG_RawData')) { $meta['EG_RawData'] } else { $null }
              } else {
                if ($meta.PSObject.Properties['EG_RawData']) { $meta.EG_RawData } else { $null }
              }
        if (-not $eg) { return $null }

        $sp = [string]$Field.sourcePath
        if (-not $sp) { return $null }
        $sp = $sp -replace '^eg\.node\.NodeProperties\.rawData\.', ''
        $cur = $eg
        foreach ($seg in ($sp -split '\.')) {
            if ($null -eq $cur) { return $null }
            $clean = $seg -replace '\[\*\]$', ''
            if ($cur -is [System.Collections.IDictionary]) {
                if ($cur.Contains($clean)) { $cur = $cur[$clean] } else { return $null }
            } else {
                if ($cur.PSObject.Properties[$clean]) { $cur = $cur.$clean } else { return $null }
            }
        }
        return ,$cur
    }

    # mde / azure / intune -- use the existing key map.
    # IMPORTANT: $meta from discovery is a [hashtable] -- PSObject.Properties[$key]
    # only works for [pscustomobject], so the universal accessor is `$meta.$key`
    # (returns $null gracefully if the key is absent on either shape).
    $key = $script:_SIEndpointKeyMap[$Field.name]
    if (-not $key) { return $null }
    if ($meta -is [System.Collections.IDictionary]) {
        if ($meta.Contains($key)) { return ,$meta[$key] }
    } else {
        if ($meta.PSObject.Properties[$key]) { return ,$meta.$key }
    }
    return $null
}

# ---------------------------------------------------------------------------
# DERIVED-VALUE DISPATCH
# ---------------------------------------------------------------------------

if (-not (Get-Variable -Name _SIDerivedSeen -Scope Script -ErrorAction SilentlyContinue)) { $script:_SIDerivedSeen = @{} }

function Get-SIEgValue {
    # Walks a dotted path against $meta.EG_RawData (EG NodeProperties.rawData).
    # Returns $null if EG data missing or any path segment unresolved. Shape-tolerant
    # (works for both [hashtable] and [pscustomobject]) since EG data may flow as either.
    param([object]$Meta, [string]$Path)
    $eg = if ($Meta -is [System.Collections.IDictionary]) {
            if ($Meta.Contains('EG_RawData')) { $Meta['EG_RawData'] } else { $null }
          } else {
            if ($Meta.PSObject.Properties['EG_RawData']) { $Meta.EG_RawData } else { $null }
          }
    if (-not $eg) { return $null }
    $cur = $eg
    foreach ($seg in ($Path -split '\.')) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) {
            if ($cur.Contains($seg)) { $cur = $cur[$seg] } else { return $null }
        } else {
            if ($cur.PSObject.Properties[$seg]) { $cur = $cur.$seg } else { return $null }
        }
    }
    return $cur
}

function Get-SIEndpointIdentityPair {
    <#
        Resolve SI_AssetName and SI_AssetId TOGETHER, from one source, ONCE per record.

        🔒 Operator, 2026-08-28: "do the pair properly - name drives id as id can change fx if client is
        known in entra id as device, then later it comes in mde, so id could change."

        🔑 MEMOISED ON $Context DELIBERATELY. The schema field loop calls the resolver once per field,
        so SI_AssetName and SI_AssetId arrive as two separate calls. Computing the pair twice would let
        them diverge the moment anything in the walk became order- or state-dependent -- which is
        exactly the class of bug this replaces. Caching makes "the two agree" true BY CONSTRUCTION
        rather than by a test that asserts it after the fact.

        THE CHAIN IS THE NAME PRIORITY (Entra > MDE > Azure > EG), unchanged from what shipped; the id
        now follows it. Each entry pairs the metadata key holding that source's NAME with the
        identifier TYPE that same source contributes to EntityIds.
    #>
    param([Parameter(Mandatory)]$Context, [Parameter()]$Meta)

    if ($Context -is [System.Collections.IDictionary] -and $Context.Contains('_SIIdentityPair')) {
        return $Context['_SIIdentityPair']
    }

    if (-not (Get-Command Resolve-SIAssetIdentityPair -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot '..\..\_shared\SI-AssetIdentity.ps1')
    }

    $chain = @(
        @{ NameKeys = 'ENTRA_DisplayName'; IdType = 'AadDeviceId';     Source = 'entra' }
        @{ NameKeys = 'MDE_DeviceName';    IdType = 'MdeDeviceId';     Source = 'mde'   }
        @{ NameKeys = 'AZ_Name';           IdType = 'AzureResourceId'; Source = 'azure' }
        # 🔴 `EG_Name`, NOT `EG_DeviceName` -- FIXED 2026-08-31. The exposure-graph endpoint collector
        # writes `EG_Name` (Invoke-Collect.ps1:402, `EG_Name = $a.Name`) and has always done so;
        # nothing anywhere ever produced `EG_DeviceName`. So this final chain link resolved to nothing
        # on every row since it was written -- the EG-sourced name was collected and then not asked for.
        # 🪤 AND THE GUARD THAT EXISTS TO CATCH THIS WAS PASSING. `IsProduced` scans engine\ for the key
        # permissively, and `EG_DeviceName` appeared there -- inside EndpointCatalogTierComputer's
        # endpoint-class half, which CONSUMED it and had no production caller. Dead code referencing a
        # dead key made the key look alive. Deleting those 16 functions (#87) is what exposed it, which
        # is the argument for deleting dead code rather than leaving it to be harmless.
        # 📌 Same species as ENTRA_UserPrincipalName -> ENTRA_UPN, recorded in the same guard's own
        # notes: MISSPELLED, never missing. The data was collected all along.
        @{ NameKeys = 'EG_Name';           IdType = 'EgNodeId';        Source = 'eg'    }
    )

    $pair = Resolve-SIAssetIdentityPair -Meta $Meta -EntityIds @($Context.EntityIds) -SourceChain $chain `
                -FallbackId ([string]$Context.PrimaryEntityId) `
                -FallbackIdType ([string]$Context.PrimaryEntityType) -Engine 'endpoint'

    # 🔴 The fallback id can still be a WEAK type -- endpoint's PrimaryEntityId chain ends in a
    # HOSTNAME, which SIWeakIdTypes defines as "NOT unique, must never join on these alone". Mark it so
    # a bare hostname cannot pass downstream as a durable identifier. 0 rows sit on that rung in this
    # estate, which is exactly why it went unnoticed for so long.
    if ($pair -and $pair.Synthetic) {
        $pair.Id = Resolve-SIAssetIdValue -Id ([string]$pair.Id) -Type ([string]$pair.IdType)
    }

    if ($null -eq $pair) { $pair = @{ Name = $null; Id = $null; IdType = ''; Source = 'none'; Synthetic = $true } }
    if ($Context -is [System.Collections.IDictionary]) { $Context['_SIIdentityPair'] = $pair }
    $pair
}

function Get-SIDerivedValue {
    param([Parameter(Mandatory)] $Field, [Parameter(Mandatory)] $Context)

    $meta = if ($Context.Record.Metadata) { $Context.Record.Metadata } else { @{} }
    $verdict = $Context.Verdict
    $perSource = $Context.PerSourceVerdicts

    # Per-source verdict family. `EndpointCatalogMatch` was an alternative here and is gone: the
    # v2.2 `TierSources.EndpointCatalog` blob it read has no producer anywhere in the product.
    if ($Field.name -match '^(PostureRuleTargetTier)Verdict_(Tier|TopMatch|MatchCount|MissCount)$') {
        $tag = $Matches[1]; $aspect = $Matches[2]
        $v = $perSource[$tag]
        if (-not $v) { return $null }
        return $v.$aspect
    }

    switch ($Field.name) {
        'PrimaryEntityId'   { return $Context.PrimaryEntityId }
        # v3 step 1 -- AssetId is SI's OWN unique asset identifier and was always MEANT to be 100%
        # populated (operator: "assetid and assetname was a custom unique id as an identifier so we
        # covered 100%"). Every schema declares it as "alias of PrimaryEntityId" and NOTHING EVER
        # WIRED IT: measured live at 0% on all three profile tables while PrimaryEntityId sat at 100%.
        # Exactly the defect this codebase already records for AssetName -- "declared the field but
        # never wired the derivation -> AssetName was always null on Endpoint rows".
        # 🔒 SI_AssetId goes through the SHARED identity rule (engine/_shared/SI-AssetIdentity.ps1), not
        # straight through PrimaryEntityId. The chain below ends in a HOSTNAME -- a type
        # SIWeakIdTypes classifies as "NOT unique, must never join on these alone" -- so this builder
        # was using as its asset id precisely the value the correlation engine forbids keying on. The
        # two rules lived in two modules that could not see each other, and nothing errored.
        # A weak value is MARKED (`weak:hostname:<value>`), never dropped: the row keeps a populated id,
        # and the weakness becomes visible instead of reading like a durable identifier.
        # ⏱️ 0 rows sit on that rung in this estate, which is exactly why it was never noticed.
        'SI_AssetId'        { return (Get-SIEndpointIdentityPair -Context $Context -Meta $meta).Id }
        'PrimaryEntityType' { return $Context.PrimaryEntityType }
        'EntityIds'         { return ,$Context.EntityIds }
        # v3 step 2 -- the exposure-graph node id is the cross-engine correlation key, and until now it
        # was collected, reached this builder as a local, went into EntityIds[], and was never emitted
        # as a column. Measured live: present on 72% of endpoint rows INSIDE EntityIds and 0% as a
        # column, so every consumer had to unpack a dynamic. Azure already emits the flat column.
        'ExposureGraphNodeId' { return $Context.EgNodeId }
        'RunId'             { return $Context.Record.SI_RunId }
        # V3-6 -- stamp WHICH RELEASE produced this row. si-v3 and main/prod write this SAME table and
        # the nightly runs the released code, so without this a profile row cannot be attributed to the
        # code that produced it. Risk Analysis has stamped it since v2.1 -- which is exactly why the two
        # trees interleaving was visible in the RA tables and invisible here.
        'SolutionVersion'   { if (-not (Get-Command Get-SISolutionVersion -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-SolutionVersion.ps1') }; return (Get-SISolutionVersion) }
        'CollectionTime'    { return $Context.RunContext.CollectionTime }
        'EndpointTieringCatalogVersion' { return $Context.CatalogVersion }
        # AssetName: cross-engine alias resolved by walking provider sources
        # in priority order (per user directive "use all the
        # providers as options for the AssetName -- entra, mde, AD, azure, EG").
        # Endpoint priority: Entra display-name > MDE device-name > AD computer
        # short-name > Azure resource short-name > EG device-name > host UUID.
        # Schema added the field but never wired the derivation
        # -> AssetName was always null on Endpoint rows.
        # 🔒 THE PAIR -- SI_AssetName and SI_AssetId are resolved TOGETHER, from ONE source.
        # Operator, 2026-08-28: "do the pair properly - NAME DRIVES ID as id can change fx if client is
        # known in entra id as device, then later it comes in mde, so id could change."
        #
        # 🔴 THAT IS A STABILITY ARGUMENT, NOT A COSMETIC ONE, and it is the defect this replaces.
        # The old model picked the ID first (mdeId -> egNodeId -> aadId -> hostname) while the name
        # walked a SEPARATE list starting at ENTRA_DisplayName. Two consequences, both silent:
        #   1. a row could ship Entra's display name beside MDE's device id -- one pair, two views of
        #      the asset, and nothing saying so;
        #   2. worse, a device first seen in Entra was keyed on its AadDeviceId, and the day MDE
        #      onboarded it MDE outranked Entra and THE SAME DEVICE CHANGED ITS SI_AssetId -- taking
        #      every downstream join with it, with no error and no trace.
        # Driving from the NAME inverts that: the name source is chosen first and its id comes along,
        # so a higher-priority ID source arriving later no longer re-keys the asset.
        #
        # 📌 The chain order below is the NAME priority and is unchanged from what shipped -- Entra >
        # MDE > Azure > EG. What changed is that the ID now follows it instead of being chosen apart
        # from it. Resolution happens ONCE per record and both fields read the cached result, so the
        # two cannot disagree by construction rather than by a test asserting they agree.
        'SI_AssetName'      { return (Get-SIEndpointIdentityPair -Context $Context -Meta $meta).Name }
        # SIRules carries the AssetProfileBy* YAML rule matches
        # produced by Stage Profile (Verdict.SI_RuleMatches). Always an array.
        'SIRules' {
            if ($verdict -and $verdict.PSObject.Properties['SI_RuleMatches']) { return ,@($verdict.SI_RuleMatches) }
            return ,@()
        }
        # IsEnabledActive = device is NOT offboarded AND has been
        # seen by at least one in-scope provider within $global:SI_ActiveStaleDays
        # (default 30). MDE OnboardingStatus 'Offboarded' wins immediately;
        # otherwise check MDE / EG lastSeen freshness OR sensor-health Active.
        'IsEnabledActive' {
            $stale = if ($global:SI_ActiveStaleDays) { [int]$global:SI_ActiveStaleDays } else { 30 }
            $onb = [string]$meta.MDE_OnboardingStatus
            if ($onb -eq 'Offboarded') { return $false }
            # Sensor health Active / ImpairedCommunication = real-time signal.
            $sh = [string]$meta.MDE_SensorHealthState
            if ($sh -in @('Active','ImpairedCommunication')) { return $true }
            # Otherwise check freshness via lastSeen (MDE first, then EG rawData).
            $lastSeen = if ($meta.MDE_LastSeen) { [string]$meta.MDE_LastSeen } else { [string](Get-SIEgValue $meta 'lastSeen') }
            if ([string]::IsNullOrWhiteSpace($lastSeen)) { return $false }
            try {
                # v2.2.373 -- InvariantCulture parse so non-en-US boxes don't fail on M/d/yyyy strings.
                $dt = [datetime]::Parse($lastSeen, [System.Globalization.CultureInfo]::InvariantCulture)
                $age = ([datetime]::UtcNow - $dt.ToUniversalTime()).TotalDays
                return ($age -le $stale)
            } catch { return $false }
        }

        # EG-derived booleans
        'IsDomainController' {
            # EG-first, then MDE machine-category fallback, then
            # hostname pattern. EG misses on-prem DCs not in Defender XDR.
            if ([bool](Get-SIEgValue $meta 'isDomainController')) { return $true }
            $mdeCat = $null
            if ($meta -is [System.Collections.IDictionary]) {
                if ($meta.Contains('MDE_DeviceCategory')) { $mdeCat = [string]$meta['MDE_DeviceCategory'] }
            } elseif ($meta.PSObject.Properties['MDE_DeviceCategory']) { $mdeCat = [string]$meta.MDE_DeviceCategory }
            if ($mdeCat -ieq 'DomainController') { return $true }
            # Hostname pattern fallback (DC* / DC-* / *-DC* common conventions).
            $hn = $null
            if ($meta -is [System.Collections.IDictionary]) {
                if ($meta.Contains('MDE_DeviceName')) { $hn = [string]$meta['MDE_DeviceName'] }
                elseif ($meta.Contains('EG_Name')) { $hn = [string]$meta['EG_Name'] }
            } elseif ($meta.PSObject.Properties['MDE_DeviceName']) { $hn = [string]$meta.MDE_DeviceName }
            elseif ($meta.PSObject.Properties['EG_Name']) { $hn = [string]$meta.EG_Name }
            if ($hn -and $hn -match '(?i)(^DC[-_0-9]|[-_]DC[-_0-9])') { return $true }
            return $false
        }
        'IsExchangeServer' {
            $a = [bool](Get-SIEgValue $meta 'isExchangeServerDnsName')
            $b = [bool](Get-SIEgValue $meta 'isTaggedAsExchangeServer')
            return ($a -or $b)
        }

        # Cross-engine join: device's user-based tier (most-frequent logon
        # users in last 3d -> Identity_Profile_CL.Tier lookup, MIN over set).
        # Stamped on $meta by Stage Enrich (Get-SIBulkDeviceUserCorrelation).
        'MostFrequentUserTier' {
            if ($meta -is [System.Collections.IDictionary]) {
                if ($meta.Contains('MostFrequentUserTier')) { return $meta['MostFrequentUserTier'] }
            } elseif ($meta.PSObject.Properties['MostFrequentUserTier']) {
                return $meta.MostFrequentUserTier
            }
            return $null
        }
        'MostFrequentUsers' {
            if ($meta -is [System.Collections.IDictionary]) {
                if ($meta.Contains('MostFrequentUsers')) { return $meta['MostFrequentUsers'] }
            } elseif ($meta.PSObject.Properties['MostFrequentUsers']) {
                return $meta.MostFrequentUsers
            }
            return @()
        }
        # MostFrequentUsersCount dropped -- pure duplicate of
        # array_length(MostFrequentUsers). Queries derive count when needed.

        # AssetTags = flat semicolon-joined string built from
        # MachineTags (MDE) + DeviceManualTags (EG) + DeviceDynamicTags (EG).
        # Each source may be: $null, an array of strings, OR a string already
        # semicolon-joined. We normalize to a string array per source, dedupe
        # case-insensitively, and join with ';'. Empty string when no tags.
        # The RA __EXCLUDED_ASSET_TAGS__ filter (8 endpoint reports) filters
        # against this column with `has_any (_excludedAssetTags)` -- a flat
        # column avoids the per-row JSON walk that the v2.1 EG-direct query
        # used to do (extend NoderawData = todynamic(...); etc).
        # v3: the union itself moved to Get-SIAssetTagUnion so the TIER REDUCTION can read the same tags
        # BEFORE this field loop runs. It must be one function, not two copies: the reduction and the
        # emitted column disagreeing about which tags an asset has would be undebuggable -- the row would
        # show one tag set and the tier would have been decided from another.
        'AssetTags' { return ((Get-SIAssetTagUnion -Meta $meta) -join ';') }

        # Tier aggregator outputs (mirror identity pattern)
        'Tier'            { return $Context.AggregatedTier }
        'Group'           { return [string]$verdict.SI_Group }
        'AssetType'       { return [string]$verdict.SI_ServiceType }
        'AssetSubtype'    { return '' }
        'AssetGroup'      { return [string]$verdict.SI_Group }

        # human-friendly display name. Fallback chain:
        #   1. ENTRA_DisplayName  (Entra device displayName -- preserves the user's
        #      casing as registered in Entra; e.g. "STRV-MOK-DT-03")
        #   2. MDE_DeviceName short-name  (strip FQDN suffix; e.g.
        #      "strv-mok-dt-03.contoso.local" -> "strv-mok-dt-03")
        #   3. EG rawData.deviceName  (last resort for EG-only devices)
        # 🔴 EVERY RUNG IS GUARDED -- A CANDIDATE EQUAL TO THE ASSET'S OWN IDENTIFIER IS NOT A NAME.
        # This chain used to take MDE's value verbatim, and MEASURED on the live estate 2026-09-01 it
        # published a bare 40-hex MDE machine id on 78 of 197 rows (`DisplayName == PrimaryEntityId` on
        # the same 78 -- the identifier verbatim, not a coincidence of shape).
        # 🪤 THE POINT IS THAT THIS EXACT DEFECT WAS ALREADY FOUND AND FIXED -- IN THE COLUMN NEXT DOOR.
        # `Resolve-SIAssetIdentityPair`'s own notes record it: "MEASURED 2026-08-27: 78 of 198 endpoint
        # rows carried a 40-hex MDE machine id in the name column, because Get-DiscoveryFromMDE
        # substitutes $m.id when MDE has no computerDnsName -- and it reached a customer's Excel reading
        # like a hostname." Same estate, same rows, same count: `SI_AssetName` got the guard and
        # `DisplayName` did not, so it kept shipping. Hence ONE rule in ONE home (Test-SINameIsIdentifier).
        # 📌 Guarded AFTER shortening, because the shortened value is what would be published -- and a
        # 40-hex id has no dot, so it survives the shortening unchanged and must still be refused.
        'DisplayName' {
            if (-not (Get-Command Test-SINameIsIdentifier -ErrorAction SilentlyContinue)) {
                . (Join-Path $PSScriptRoot '..\..\_shared\SI-AssetIdentity.ps1')
            }
            $pid_ = [string]$Context.PrimaryEntityId

            $entraName = $null
            if ($meta -is [System.Collections.IDictionary]) {
                if ($meta.Contains('ENTRA_DisplayName')) { $entraName = $meta['ENTRA_DisplayName'] }
            } elseif ($meta.PSObject.Properties['ENTRA_DisplayName']) { $entraName = $meta.ENTRA_DisplayName }
            if (-not [string]::IsNullOrWhiteSpace([string]$entraName) -and
                -not (Test-SINameIsIdentifier -Name ([string]$entraName) -Id $pid_)) { return [string]$entraName }

            $mdeName = $null
            if ($meta -is [System.Collections.IDictionary]) {
                if ($meta.Contains('MDE_DeviceName')) { $mdeName = $meta['MDE_DeviceName'] }
            } elseif ($meta.PSObject.Properties['MDE_DeviceName']) { $mdeName = $meta.MDE_DeviceName }
            if (-not [string]::IsNullOrWhiteSpace([string]$mdeName)) {
                $s = [string]$mdeName
                if ($s.Contains('.')) { $s = $s.Substring(0, $s.IndexOf('.')) }
                if (-not (Test-SINameIsIdentifier -Name $s -Id $pid_)) { return $s }
            }

            $egName = Get-SIEgValue $meta 'deviceName'
            if (-not [string]::IsNullOrWhiteSpace([string]$egName) -and
                -not (Test-SINameIsIdentifier -Name ([string]$egName) -Id $pid_)) { return [string]$egName }
            # 🔑 NULL, not a hash. Nothing names this asset; `SI_AssetName` says so with its marked
            # `unnamed-endpoint-<frag>` synthetic, and a display column that repeats the id reads like
            # data. 59 of the 197 rows are already empty here, so an empty DisplayName is an ordinary,
            # already-handled state -- not a new shape for a consumer to learn.
            return $null
        }

        default {
            if (-not $script:_SIDerivedSeen[$Field.name]) {
                Write-Verbose ('  [derive-gap] no dispatch for derived field "{0}"' -f $Field.name)
                $script:_SIDerivedSeen[$Field.name] = $true
            }
            return $null
        }
    }
}

# ---------------------------------------------------------------------------
# PER-SOURCE VERDICT (parses v2.2 TierSources -> per-source tuples)
# ---------------------------------------------------------------------------

function Get-SIAssetTagUnion {
    <#
        The asset's operator tags, deduped, in first-seen order: MDE machine tags + EG manual tags +
        EG dynamic tags. Returns a string ARRAY; the AssetTags column joins it with ';'.

        🔑 EXTRACTED so there is exactly ONE definition of "this asset's tags". The tier reduction needs
        them BEFORE the schema field loop runs (that loop is what produces the AssetTags column), and a
        second copy of this flattening would let the emitted column and the tier disagree about which
        tags the asset has -- a row showing one tag set while its tier was decided from another is not
        debuggable from the output.

        Each source may be $null, a string array, or a string already ';'-joined. All three occur: MDE
        hands back an array, EG's blob round-trips through JSON, and a staging-blob replay flattens.
    #>
    param([Parameter()][AllowNull()]$Meta)

    $normalize = {
        param($v)
        if ($null -eq $v) { return ,@() }
        if ($v -is [string]) {
            if ([string]::IsNullOrWhiteSpace($v)) { return ,@() }
            return ,@(($v -split ';') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
        if ($v -is [System.Collections.IEnumerable]) {
            $out = New-Object System.Collections.Generic.List[string]
            foreach ($e in $v) {
                if ($null -eq $e) { continue }
                $s = [string]$e
                if (-not [string]::IsNullOrWhiteSpace($s)) { $out.Add($s.Trim()) }
            }
            return ,$out.ToArray()
        }
        $s = [string]$v
        if ([string]::IsNullOrWhiteSpace($s)) { return ,@() }
        return ,@($s.Trim())
    }
    $get = {
        param($m, $k)
        if ($null -eq $m) { return $null }
        if ($m -is [System.Collections.IDictionary]) {
            if ($m.Contains($k)) { return $m[$k] } else { return $null }
        }
        if ($m.PSObject.Properties[$k]) { return $m.$k } else { return $null }
    }

    $all = New-Object System.Collections.Generic.List[string]
    foreach ($k in 'MDE_MachineTags','EG_DeviceManualTags','EG_DeviceDynamicTags') {
        foreach ($t in (& $normalize (& $get $Meta $k))) { $all.Add($t) }
    }
    if ($all.Count -eq 0) { return ,@() }

    # Case-insensitive dedupe, preserving first-seen casing and order.
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $uniq = New-Object System.Collections.Generic.List[string]
    foreach ($t in $all) { if ($seen.Add($t)) { $uniq.Add($t) } }
    # ,$array -- an empty or single-element return must stay an ARRAY, or the caller's -join produces
    # a bare string and the tag claim silently sees one tag where the asset has none.
    return ,$uniq.ToArray()
}

function ConvertTo-SIPerSourceVerdict {
    param([object]$TierSourceEntry, [string]$NameField)
    if (-not $TierSourceEntry -or -not $TierSourceEntry.CatalogMatches) {
        return [pscustomobject]@{ Tier=$null; TopMatch=$null; MatchCount=0; MissCount=0; Proofs=@() }
    }
    $matches = @($TierSourceEntry.CatalogMatches)
    if ($matches.Count -eq 0) {
        return [pscustomobject]@{ Tier=$null; TopMatch=$null; MatchCount=0; MissCount=0; Proofs=@() }
    }
    $minTier = [int]::MaxValue; $top = $null
    $proofs = New-Object System.Collections.Generic.List[object]
    foreach ($m in $matches) {
        $t = if ($m.PSObject.Properties['Tier']) { [int]$m.Tier } elseif ($m.PSObject.Properties['CatalogTier']) { [int]$m.CatalogTier } elseif ($m.PSObject.Properties['TargetTier']) { [int]$m.TargetTier } else { $null }
        if ($null -eq $t) { continue }
        $name = if ($m.PSObject.Properties[$NameField]) { [string]$m.($NameField) } else { '' }
        if ($t -lt $minTier) { $minTier = $t; $top = $name }
        $proofs.Add([ordered]@{ name=$name; tier=$t; reason = if ($m.PSObject.Properties['Reason']) { [string]$m.Reason } else { '' } })
    }
    $tierVal = if ($proofs.Count -gt 0) { $minTier } else { $null }
    [pscustomobject]@{
        Tier = $tierVal
        TopMatch = $top; MatchCount = $proofs.Count; MissCount = 0; Proofs = $proofs.ToArray()
    }
}

# ---------------------------------------------------------------------------
# HASH HELPERS
# ---------------------------------------------------------------------------

function Get-SICanonicalJson {
    param([object]$Bag)
    if ($Bag -is [System.Collections.IDictionary]) {
        $sorted = [ordered]@{}
        foreach ($k in ($Bag.Keys | Sort-Object)) { $sorted[$k] = $Bag[$k] }
        return ($sorted | ConvertTo-Json -Compress -Depth 20)
    }
    return ($Bag | ConvertTo-Json -Compress -Depth 20)
}
function Get-SIRowHash {
    param([object]$FieldBag)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes((Get-SICanonicalJson $FieldBag))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hex = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
        $hex.Substring(0, 16)
    } finally { $sha.Dispose() }
}

function _SIHashBag { param($Names, $Row); $h = @{}; foreach ($n in $Names) { if ($Row.Contains($n)) { $h[$n] = $Row[$n] } }; return $h }

# ---------------------------------------------------------------------------
# MAIN ENTRY: Build-SIEndpointProfileRow
# ---------------------------------------------------------------------------

function Build-SIEndpointProfileRow {
    param(
        [Parameter(Mandatory)] $Record,
        [Parameter(Mandatory)] $RunContext
    )

    $schema = Get-SIEndpointSchema
    $meta   = if ($Record.Metadata) { $Record.Metadata } else { @{} }
    $verdict = $Record.Verdict

    # Parse v2.2 TierSources blob -> per-source verdicts
    $tierSources = $null
    if ($verdict.TierSources) { try { $tierSources = $verdict.TierSources | ConvertFrom-Json } catch { } }
    # 🪤 `EndpointCatalogMatch` was read from `$tierSources.EndpointCatalog` here and ALWAYS took the
    # empty branch: nothing in the product writes that key -- the class-catalog matcher that used to
    # was deleted, and no other producer ever existed. It therefore fed an always-null per-source
    # verdict into attribution and into a schema-field family the schema does not declare. Removed.
    $perSource = @{
        PostureRuleTargetTier = if ($tierSources -and $tierSources.PSObject.Properties['PostureRules']) {
                                    ConvertTo-SIPerSourceVerdict -TierSourceEntry $tierSources.PostureRules -NameField 'RuleName'
                                } else { [pscustomobject]@{ Tier=$null; TopMatch=$null; MatchCount=0; MissCount=0; Proofs=@() } }
    }

    # endpoint default = 3 when no rule fires (per user direction
    # 2026-04-30: "i would like for endpoints to default to tier 3 if no hits").
    # Plus guard against [int]$null=0 silent coercion.
    # The default is now the default tier RULE (Resolve-SIDefaultTier.ps1, shipped as Tier 3 for devices) -- $null when it
    # is turned off, and the device is then Unclassified, listed on the Tier board to be given a tier.
    $aggTier = if ($null -ne $verdict.SI_Tier -and "$($verdict.SI_Tier)" -ne '') {
        try { [int]$verdict.SI_Tier } catch { Get-SIDefaultTierValue -Engine endpoint }
    } else { Get-SIDefaultTierValue -Engine endpoint }

    # ================= v3 Phase 4 step 3: THE REDUCER, ON THE PRODUCTION PATH =================
    # Until now Resolve-SITierClaims had exactly one caller -- Get-SITierFromEndpointDevice, which has
    # no caller of its own -- so the reducer could never execute. This is the wiring.
    #
    # 🔒 HERE, BEFORE $ctx IS BUILT, AND THAT POSITION IS THE WHOLE DESIGN. $ctx.AggregatedTier feeds
    # the schema field loop that emits the `Tier` column, so reducing AFTER it would mean overwriting
    # $row['Tier'] afterwards -- and that is a defect this codebase has already shipped: an override
    # that updated $aggTier while the published row kept the computed tier, which a tally taken at the
    # decision point reported as a success. Reduce first, and there is nothing to override.
    #
    # THE MODEL, unchanged from Resolve-SITierClaims' four stages: admissibility -> contradiction ->
    # observed-beats-asserted -> MIN. Operator ruling: an ASSERTED claim (a human wrote a tag) YIELDS
    # when an OBSERVED claim disagrees; observed claims never suppress each other and go to MIN.
    # 🔑 "LOW PRIORITY" MEANS LOSES TO OBSERVATION, NOT IGNORED (operator, 2026-08-25: "tags must
    # continue to be used, just low prio"). So a tag sets the tier ONLY where nothing observed has an
    # opinion -- and "no opinion" is not "claimed tier 3": the T3 default is the ABSENCE of a claim, so
    # an unobserved asset carrying a --tier2--SI tag becomes T2.
    #
    # DEGRADE, DO NOT DIE. If the reducer or the trust list is unavailable (sync/ PreservePatterns has
    # known gaps -- audit #34), the plain MIN stands. Tiering is the product; arbitrating it is not
    # worth losing it for.
    $reducedFrom = $null
    if (-not (Get-Command -Name Get-SITierFromAssetTags -ErrorAction SilentlyContinue)) {
        try { . (Join-Path $PSScriptRoot 'Get-SITierAttribution.ps1') } catch { }
    }
    if (-not (Get-Command -Name Resolve-SITierClaims -ErrorAction SilentlyContinue)) {
        try { . (Join-Path $PSScriptRoot 'Resolve-SITierClaims.ps1') } catch { }
    }
    if (-not (Get-Command -Name Get-SITierTrustList -ErrorAction SilentlyContinue)) {
        try { . (Join-Path $PSScriptRoot 'Get-SITierTrustList.ps1') } catch { }
    }
    if ((Get-Command -Name Resolve-SITierClaims    -ErrorAction SilentlyContinue) -and
        (Get-Command -Name Get-SITierTrustList     -ErrorAction SilentlyContinue) -and
        (Get-Command -Name Get-SITierFromAssetTags -ErrorAction SilentlyContinue)) {
        try {
            $rClaims = New-Object System.Collections.Generic.List[object]

            # --- OBSERVED. Each is added ONLY when it actually claimed, because an absent claim and a
            # --- claim of tier 3 are different statements and collapsing them would let the default
            # --- masquerade as an observation that outranks the tag.
            if ($null -ne $verdict.SI_RuleTier -and "$($verdict.SI_RuleTier)" -ne '') {
                [void]$rClaims.Add([pscustomobject]@{ SourceId='endpoint_catalog_match'; Tier=[int]$verdict.SI_RuleTier; Evidence='asset-profiling rule' })
            }
            $_mfu = if ($meta -is [System.Collections.IDictionary]) { if ($meta.Contains('MostFrequentUserTier')) { $meta['MostFrequentUserTier'] } else { $null } }
                    elseif ($meta.PSObject.Properties['MostFrequentUserTier']) { $meta.MostFrequentUserTier } else { $null }
            if ($null -ne $_mfu -and "$_mfu" -ne '') {
                [void]$rClaims.Add([pscustomobject]@{ SourceId='endpoint_user_based_tier'; Tier=[int]$_mfu; Evidence='most frequent interactive user' })
            }
            if ($null -ne $perSource.PostureRuleTargetTier -and $null -ne $perSource.PostureRuleTargetTier.Tier -and "$($perSource.PostureRuleTargetTier.Tier)" -ne '') {
                [void]$rClaims.Add([pscustomobject]@{ SourceId='posture_rule_target_tier'; Tier=[int]$perSource.PostureRuleTargetTier.Tier; Evidence=[string]$perSource.PostureRuleTargetTier.TopMatch })
            }

            # --- ASSERTED. The operator's tier tag, read through the SAME union the AssetTags column
            # --- emits, so the row cannot show one tag set while its tier came from another.
            $_tagV = Get-SITierFromAssetTags -Tags (Get-SIAssetTagUnion -Meta $meta) `
                        -TagPattern (Get-SITierTagPatternFromSchema -Schema $schema)
            if ($null -ne $_tagV) {
                [void]$rClaims.Add([pscustomobject]@{ SourceId='tenant_si_manual_tag'; Tier=[int]$_tagV.Tier; Evidence=[string]$_tagV.TopMatch })
            }

            # Only worth reducing when the tag is in play. With observed claims alone the reducer is
            # byte-identical to MIN, so this skips the work for the ~88% of assets that carry no tier
            # tag -- and, more importantly, guarantees this change cannot move a tier on an asset that
            # has no operator assertion at all.
            # (never with no engine tier: -DefaultTier is an [int], and $null would bind as Tier 0)
            if ($null -ne $_tagV -and $rClaims.Count -gt 0 -and $null -ne $aggTier) {
                $_tl = Get-SITierTrustList -Aggregator $schema.aggregator `
                        -LockedKinds @{ 'tenant_si_manual_tag' = 'asserted' }
                # DefaultTier is the ENGINE's tier, not 3: if every claim were somehow inadmissible the
                # answer must be what the engine already decided, never a reset to the default.
                $_r = Resolve-SITierClaims -Claims $rClaims.ToArray() -TrustList $_tl -DefaultTier $aggTier
                if ($null -ne $_r -and $null -ne $_r.Tier -and [int]$_r.Tier -ne $aggTier) {
                    $reducedFrom = $aggTier
                    $aggTier     = [int]$_r.Tier
                }
            }
        } catch {
            Write-Warning ("tier reduction failed for this asset ({0}) -- the engine's MIN stands unchanged." -f $_.Exception.Message)
        }
    }

    # ---- EntityIds -- merged across MDE + EG + AAD + Hostname (priority order) ----
    $mdeId = $null; $egNodeId = $null; $aadId = $null; $hostName = $null; $azResId = $null
    if ($meta -is [System.Collections.IDictionary]) {
        if ($meta.Contains('MDE_DeviceId') -and $meta['MDE_DeviceId']) { $mdeId = [string]$meta['MDE_DeviceId'] }
        if ($meta.Contains('EG_NodeId')    -and $meta['EG_NodeId'])    { $egNodeId = [string]$meta['EG_NodeId'] }
        # #204 -- MDE discovery emits MDE_AadDeviceId; MDE_AzureADDeviceId was never produced, so the device's own
        # Entra id reached the correlation identifiers only when the Exposure Graph happened to carry it.
        if ($meta.Contains('MDE_AadDeviceId') -and $meta['MDE_AadDeviceId']) { $aadId = [string]$meta['MDE_AadDeviceId'] }
        elseif ($meta.Contains('MDE_AzureADDeviceId') -and $meta['MDE_AzureADDeviceId']) { $aadId = [string]$meta['MDE_AzureADDeviceId'] }
        elseif ($meta.Contains('EG_AadDeviceId') -and $meta['EG_AadDeviceId'])      { $aadId = [string]$meta['EG_AadDeviceId'] }
        if ($meta.Contains('MDE_DeviceName') -and $meta['MDE_DeviceName']) { $hostName = [string]$meta['MDE_DeviceName'] }
        elseif ($meta.Contains('EG_Name') -and $meta['EG_Name']) { $hostName = [string]$meta['EG_Name'] }
        if ($meta.Contains('MDE_AzureResourceId') -and $meta['MDE_AzureResourceId']) { $azResId = [string]$meta['MDE_AzureResourceId'] }
        # EG fallback when MDE didn't tag the device with its Azure
        # resource ID (Azure VMs / Azure Arc machines also surface in EG with
        # the AzureResourceId on the node properties).
        elseif ($meta.Contains('EG_AzureResourceId') -and $meta['EG_AzureResourceId']) { $azResId = [string]$meta['EG_AzureResourceId'] }
    } else {
        if ($meta.PSObject.Properties['MDE_DeviceId']        -and $meta.MDE_DeviceId)        { $mdeId = [string]$meta.MDE_DeviceId }
        if ($meta.PSObject.Properties['EG_NodeId']           -and $meta.EG_NodeId)           { $egNodeId = [string]$meta.EG_NodeId }
        if ($meta.PSObject.Properties['MDE_AadDeviceId']     -and $meta.MDE_AadDeviceId)     { $aadId = [string]$meta.MDE_AadDeviceId }
        elseif ($meta.PSObject.Properties['MDE_AzureADDeviceId'] -and $meta.MDE_AzureADDeviceId) { $aadId = [string]$meta.MDE_AzureADDeviceId }
        elseif ($meta.PSObject.Properties['EG_AadDeviceId'] -and $meta.EG_AadDeviceId)       { $aadId = [string]$meta.EG_AadDeviceId }
        if ($meta.PSObject.Properties['MDE_DeviceName']      -and $meta.MDE_DeviceName)      { $hostName = [string]$meta.MDE_DeviceName }
        elseif ($meta.PSObject.Properties['EG_Name']  -and $meta.EG_Name)        { $hostName = [string]$meta.EG_Name }
        if ($meta.PSObject.Properties['MDE_AzureResourceId'] -and $meta.MDE_AzureResourceId) { $azResId = [string]$meta.MDE_AzureResourceId }
        elseif ($meta.PSObject.Properties['EG_AzureResourceId'] -and $meta.EG_AzureResourceId) { $azResId = [string]$meta.EG_AzureResourceId }
    }

    # PrimaryEntityId / Type -- first non-null in priority order
    $primaryId = $null; $primaryType = $null
    if     ($mdeId)    { $primaryId = $mdeId;    $primaryType = 'MdeDeviceId' }
    elseif ($egNodeId) { $primaryId = $egNodeId; $primaryType = 'EgNodeId' }
    elseif ($aadId)    { $primaryId = $aadId;    $primaryType = 'AadDeviceId' }
    elseif ($hostName) { $primaryId = $hostName; $primaryType = 'Hostname' }
    else {
        # Fallback: derive from AssetId (e.g. 'endpoint-mde:<deviceId>')
        $primaryId = [string]$Record.AssetId
        if ($primaryId -match '^endpoint-(?:mde|eg):(?<id>.+)$') { $primaryId = $matches.id }
        $primaryType = 'MdeDeviceId'
    }

    $entityIds = New-Object System.Collections.Generic.List[object]
    if ($mdeId)    { $entityIds.Add(@{ type='MdeDeviceId';     id=$mdeId;    source='mde' }) }
    if ($egNodeId) { $entityIds.Add(@{ type='EgNodeId';        id=$egNodeId; source='exposureGraph' }) }
    if ($aadId)    { $entityIds.Add(@{ type='AadDeviceId';     id=$aadId;    source='entra' }) }
    if ($azResId)  { $entityIds.Add(@{ type='AzureResourceId'; id=$azResId;  source='azure' }) }
    if ($hostName) { $entityIds.Add(@{ type='Hostname';        id=$hostName; source='mde' }) }

    $catVer = Get-SIEndpointCatalogVersion

    # Properties.collect.<src> = <SRC>_* keys with the prefix stripped, mirroring
    # how identity collect.entra carries ENTRA_* keys without the prefix.
    # Excludes the EG_RawData blob (lands under collect.exposureGraph instead).
    $collectMde   = @{}
    $collectEg    = $null
    $collectAz    = @{}
    $collectEntra = @{}
    $collectCmdb  = @{}
    if ($meta -is [System.Collections.IDictionary]) {
        foreach ($k in $meta.Keys) {
            if ($k -eq 'EG_RawData') { $collectEg = $meta[$k]; continue }
            if ($k -like 'MDE_*')    { $collectMde[$k.Substring(4)]   = $meta[$k]; continue }
            if ($k -like 'AZ_*')     { $collectAz[$k.Substring(3)]    = $meta[$k]; continue }
            if ($k -like 'ENTRA_*')  { $collectEntra[$k.Substring(6)] = $meta[$k]; continue }
            if ($k -like 'CMDB_*')   { $collectCmdb[$k.Substring(5)]  = $meta[$k]; continue }
        }
    } else {
        foreach ($p in $meta.PSObject.Properties) {
            if ($p.Name -eq 'EG_RawData') { $collectEg = $p.Value; continue }
            if ($p.Name -like 'MDE_*')    { $collectMde[$p.Name.Substring(4)]   = $p.Value; continue }
            if ($p.Name -like 'AZ_*')     { $collectAz[$p.Name.Substring(3)]    = $p.Value; continue }
            if ($p.Name -like 'ENTRA_*')  { $collectEntra[$p.Name.Substring(6)] = $p.Value; continue }
            if ($p.Name -like 'CMDB_*')   { $collectCmdb[$p.Name.Substring(5)]  = $p.Value; continue }
        }
    }

    # strip *@odata.type keys recursively from EG rawData blob.
    if (-not (Get-Command -Name ConvertTo-SICleanedEgBlob -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'Convert-EgBlob.ps1')
    }
    $collectEg = ConvertTo-SICleanedEgBlob -Value $collectEg

    # drop classify.proofs from Properties. Per-source proofs are already
    # exposed as flat schema columns and as the Tier_Proofs JSON column. Duplicating
    # them here was useless data (mostly empty arrays) and surfaced bogus legacy
    # entries with all-blank fields.
    # ---- v3 Phase 5: PAYLOAD PROFILES -- two projections over ONE collection pass (§3.6) ----
    # `cmdb` (the default) is byte-for-byte the previous behaviour: everything Collect fetched. `security`
    # enforces the schema's declared includePaths, which the `_policy` string has always claimed happened
    # and which no code has ever done. Adopting this file therefore changes NOTHING until someone sets
    # $global:SI_PayloadProfile -- deliberately, because switching the default would drop columns on every
    # customer at once and Log Analytics keeps ~30 days with no backfill.
    # DEGRADE, DO NOT DIE: Properties is metadata, not the inventory. If the projection file is missing
    # (sync/ PreservePatterns has known gaps -- audit #34) the row still ships, unprojected.
    if (-not (Get-Command -Name Select-SIPayloadBucket -ErrorAction SilentlyContinue)) {
        try { . (Join-Path $PSScriptRoot 'Get-SIPayloadProfile.ps1') } catch {
            Write-Warning ("payload profile unavailable ({0}) -- Properties emitted unprojected (all collected metadata)." -f $_.Exception.Message)
        }
    }
    $payloadDropped = @()
    if (Get-Command -Name Select-SIPayloadBucket -ErrorAction SilentlyContinue) {
        try {
            $prof = Get-SIPayloadProfileName
            foreach ($b in @(
                @{ Name = 'mde';           Var = 'collectMde' }
                @{ Name = 'azure';         Var = 'collectAz' }
                @{ Name = 'entra';         Var = 'collectEntra' }
                @{ Name = 'cmdb';          Var = 'collectCmdb' }
            )) {
                $allowed = Get-SIPayloadAllowedKeys -Schema $schema -SourceName $b.Name -ProfileName $prof
                if ($null -eq $allowed) { continue }   # source not enforced / not declared -- pass through
                $r = Select-SIPayloadBucket -Bucket (Get-Variable -Name $b.Var -ValueOnly) -AllowedKeys $allowed -SourceName $b.Name
                Set-Variable -Name $b.Var -Value $r.Bucket
                if ($r.Dropped.Count -gt 0) { $payloadDropped += $r.Dropped }
            }
        } catch {
            Write-Warning ("payload projection failed for this asset ({0}) -- Properties emitted unprojected." -f $_.Exception.Message)
        }
    }

    $properties = @{
        meta = @{
            schema_version          = [string]$schema.schemaVersion
            tiering_catalog_version = $catVer
            schema_authority        = 'v2.2/asset-profiling-schema/endpoint.schema.locked.json'
            # Which projection produced this bag. Without it a consumer cannot tell a field that is
            # ABSENT from one the profile REMOVED, and those are different facts about the estate.
            payload_profile         = if (Get-Command -Name Get-SIPayloadProfileName -ErrorAction SilentlyContinue) { Get-SIPayloadProfileName } else { 'cmdb' }
        }
        collect = @{
            mde           = $collectMde
            exposureGraph = $collectEg     # whole NodeProperties.rawData blob (or $null), @odata.type stripped
            azure         = $collectAz
            entra         = $collectEntra  # Entra-joined device fields (OS, TrustType, ProfileType, Category)
            cmdb          = $collectCmdb   # matched CMDB service record (all CSV columns)
        }
    }

    # Per-row payload accounting, aggregated by the caller into ONE run-summary line. A projection that
    # drops fields without naming them is the same defect class as the silent truncation this replaces;
    # a budget nobody measures is how PropertyValueTooLarge gets discovered from a 400 instead.
    # Through the accessor, never by touching a $script: variable in the other file -- the two are not
    # always dot-sourced into the same scope, and a counter that silently stays 0 looks exactly like a
    # feature that is switched off. $hostName, NOT $row['AssetName']: $row is built BELOW this block.
    if (Get-Command -Name Add-SIPayloadMeasurement -ErrorAction SilentlyContinue) {
        try {
            [void](Add-SIPayloadMeasurement -Properties $properties -Schema $schema `
                    -AssetName ([string]$hostName) -Dropped $payloadDropped)
        } catch { }
    }

    $ctx = @{
        Record            = $Record
        Verdict           = $verdict
        TierSources       = $tierSources
        PerSourceVerdicts = $perSource
        EntityIds         = $entityIds.ToArray()
        PrimaryEntityId   = $primaryId
        PrimaryEntityType = $primaryType
        EgNodeId          = $egNodeId          # v3 step 2 -- emitted as ExposureGraphNodeId
        CatalogVersion    = $catVer
        AggregatedTier    = $aggTier
        RunContext        = $RunContext
    }

    # ---- Iterate schema.fields, emit ONLY declared fields per field.purpose/emit ----
    # v2.2.374 -- use cached emit-fields + per-row availKeys fast-null path.
    # Same pattern as Build-AzureProfileRow v2.2.371/372. Skips Resolve for
    # fields whose required source key is absent on this row.
    $row = [ordered]@{}
    $row['TimeGenerated'] = $Record.TimeGenerated
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
    foreach ($f in $script:_SISchemaCache['EndpointEmitFields']) {
        $fname = [string]$f.name
        # Fast-null path: if field requires source keys and NONE are populated, emit null directly.
        $reqKeys = $f._SIRequiredKeys
        $skipResolve = $false
        if ($f.source -ne 'derived' -and $reqKeys -and $reqKeys.Count -gt 0) {
            $hasAny = $false
            foreach ($rk in $reqKeys) { if ($availKeys.Contains($rk)) { $hasAny = $true; break } }
            if (-not $hasAny) { $skipResolve = $true }
        }
        if ($skipResolve) { $row[$fname] = $null; continue }
        $val = if ($f.source -eq 'derived') {
            Get-SIDerivedValue -Field $f -Context $ctx
        } else {
            Resolve-SISourceValue -Field $f -Record $Record
        }
        $row[$fname] = $val
    }

    $row['Properties'] = $properties

    # ---- CMDB / Reconcile flat columns ----
    # Stage Profile stamps `cmdbId` onto $Record top-level when a
    # YAML rule's `set.cmdbId` fires. Stage Reconcile adds the
    # CSV-derived enrichment (cmdbName/cmdbCriticality/cmdbDataSensitivity) into
    # both Properties.collect.cmdb (canonical) AND, when possible, as flat
    # top-level fields on $Record. Single source of truth: cmdbId comes from
    # the rule, the rest come from the CSV row matched by cmdbId.
    #
    # Defensive fallback: if Reconcile's flat-column writes didn't land for some
    # reason (timing / object-shape edge case) but Properties.collect.cmdb DID
    # populate, derive the flat columns from the JSON bag here. Keeps the RA
    # query simple -- it only ever reads flat columns.
    $cmdbBag = $null
    try {
        if ($properties -and $properties.PSObject.Properties['collect'] -and $properties.collect.PSObject.Properties['cmdb']) {
            $cmdbBag = $properties.collect.cmdb
        } elseif ($properties -and $properties['collect'] -and $properties['collect']['cmdb']) {
            $cmdbBag = $properties['collect']['cmdb']
        }
    } catch {}
    # 2026-05-02: defensive scalar coercion for cmdb* string columns. Without this,
    # @{} / pscustomobject values upstream serialize to the literal string "{}" in
    # LA + Excel. Empty containers collapse to '' instead. Numeric CmdbMatchConfidence
    # is handled separately at the bottom.
    $cmdbStringFields = @('cmdbId','cmdbName','cmdbCriticality','cmdbDataSensitivity',
                          'CmdbMatchPhase','CmdbMatchState','CmdbMatchRule','LastSeenInCmdb','CmdbSource',
                          'CmdbNameSource','CmdbCriticalitySource','CmdbDataSensitivitySource')
    $cmdbBagFilled = @{}
    foreach ($f in $cmdbStringFields) {
        $v = if ($Record.PSObject.Properties[$f]) { $Record.$f } else { $null }
        # cmdbBag fallback for the 3 enrichment cols when $Record value is empty.
        if (([string]::IsNullOrWhiteSpace([string]$v) -or
             $v -is [System.Collections.IDictionary] -or $v -is [pscustomobject]) -and
            $cmdbBag -and $f -in @('cmdbName','cmdbCriticality','cmdbDataSensitivity')) {
            $jsonKey = switch ($f) {
                'cmdbName'            { 'name' }
                'cmdbCriticality'     { 'criticality' }
                'cmdbDataSensitivity' { 'dataSensitivity' }
            }
            try {
                $bagVal = if ($cmdbBag -is [System.Collections.IDictionary]) { $cmdbBag[$jsonKey] } else { $cmdbBag.$jsonKey }
                if ($bagVal) { $v = $bagVal; $cmdbBagFilled[$f] = $true }
            } catch {}
        }
        # the bag IS the CMDB record: a value taken from it is sourced 'cmdb' (its *Source column comes later in the list)
        if ($f -in @('CmdbNameSource','CmdbCriticalitySource','CmdbDataSensitivitySource') -and [string]::IsNullOrWhiteSpace([string]$v)) {
            $valueCol = 'cmdb' + $f.Substring(4, $f.Length - 10)
            if ($cmdbBagFilled.ContainsKey($valueCol)) { $v = 'cmdb' }
        }
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
    # dropped cmdbCriticalityScore row-builder computation -- the
    # weighted-risk-score model lives in v2.2/risk-analysis-detection/riskscore_weighted.schema.custom.json
    # now (declarative + generic). Build-RiskAnalysis.ps1 reads that schema
    # and emits the value-mapping inline in each report's KQL via case().
    # The flat `cmdbCriticality` string column (set above) is still on every
    # Profile row, which is all the model needs.

    # ---- profile-time risk-factor derivations ----
    if (-not (Get-Command -Name Get-SIEndpointRiskFactors -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'Get-SIRiskFactors.ps1')
    }
    # v2.2.374 -- avoid Add-Member-per-key loop. Same hashtable-union trick as v2.2.371 Azure.
    $rfHash = @{} + $row
    $rfHash['Verdict']  = $verdict
    $rfHash['Metadata'] = $meta
    $rf = Get-SIEndpointRiskFactors -Record ([pscustomobject]$rfHash)
    foreach ($k in $rf.Keys) { $row[$k] = $rf[$k] }

    # ---- #61: OPERATOR DECISIONS -- override / exception / exemption ----
    # An OVERRIDE is the operator saying the computed tier is WRONG. It is applied here, after the
    # engine has finished deciding, so the computed value is never lost: SI_TierBeforeOverride keeps it,
    # and "why is this asset Tier 1" stays answerable with BOTH numbers visible.
    #
    # 🔒 THE FILE BEATS THE TAG (operator ruling, 2026-08-13). Tags stay valid for people working in the
    # Defender portal, but a tag cannot say WHO set it, WHEN, or WHY -- and an unattributed claim is the
    # stale tag this model exists to replace. Where both name one asset, the file is authoritative.
    #
    # 🔴 ONLY `override` LANDS HERE. `exception` and `exemption` never touch the tier: an exemption
    # removes the asset from scope VISIBLY (the excluded-assets report), and letting either quietly
    # lower a tier instead is how an estate fills with fake T3s nobody can audit. The resolver refuses
    # such entries outright; this is simply the other end of that guarantee.
    #
    # DEGRADE, DO NOT DIE -- same trade as the attribution columns below. A missing or broken decisions
    # file must never cost the customer their inventory row.
    $row['SI_TierBeforeOverride'] = ''
    $row['SI_TierOverrideBy']     = ''
    if ($global:SI_AssetDecisions -and @($global:SI_AssetDecisions).Count -gt 0) {
        if (-not (Get-Command -Name Resolve-SIAssetDecisions -ErrorAction SilentlyContinue)) {
            try { . (Join-Path $PSScriptRoot 'Resolve-SIAssetDecisions.ps1') } catch {
                Write-Warning ("operator decisions unavailable ({0}) -- overrides will NOT be applied this run; computed tiers stand." -f $_.Exception.Message)
            }
        }
        if (Get-Command -Name Resolve-SIAssetDecisions -ErrorAction SilentlyContinue) {
            try {
                $assetName = if ($row['Hostname']) { [string]$row['Hostname'] } else { [string]$row['DisplayName'] }
                $dec = Resolve-SIAssetDecisions -Decisions @($global:SI_AssetDecisions) -Asset $assetName -Now ([datetime]::UtcNow)
                if ($dec.Override) {
                    $newTier = [int]$dec.Override.tier
                    if ($newTier -ne $aggTier) {
                        $row['SI_TierBeforeOverride'] = [string]$aggTier
                        $aggTier = $newTier
                        # 🔴 THE ROW MUST BE UPDATED TOO, AND THIS LINE IS THE WHOLE FIX.
                        # `Tier` is resolved from $Context.AggregatedTier during the schema iteration
                        # ABOVE, so by the time this block runs $row['Tier'] is already written.
                        # Updating only $aggTier left the override completely INERT -- the log would
                        # claim an override was applied while the published row kept the computed
                        # tier. Caught before shipping, and it is the same defect class as
                        # MatchedClass contradicting its own reduced tier: the variable moved and the
                        # OUTPUT did not.
                        $row['Tier'] = $newTier
                    }
                    $row['SI_TierOverrideBy'] = ('{0} {1}: {2}' -f [string]$dec.Override.by, [string]$dec.Override.at, [string]$dec.Override.reason)
                }
            } catch {
                Write-Warning ("operator decision resolution failed for this asset ({0}) -- computed tier stands." -f $_.Exception.Message)
            }
        }
    }

    # ---- v3 Phase 4 step 1: WHY this asset has this tier ----
    # The per-source verdicts already exist in memory here and were being discarded. Tier is emitted as
    # a bare number, and SIRules lists what MATCHED without saying what WON -- so "why is this asset
    # Tier 0" was unanswerable per asset. Operator ruling (g): an all-Tier-0 estate loses prioritisation
    # unless the tier carries its reason. This DESCRIBES the current MIN reduction; it does not change
    # it, and $aggTier is passed in rather than recomputed so a second implementation of the tier
    # decision cannot silently disagree with the engine's.
    # DEGRADE, DO NOT DIE. These three columns are an AUDIT surface -- they explain the tier, they do
    # not decide it. If the file is missing (sync/ PreservePatterns has known gaps -- audit #34), a bare
    # dot-source would throw and take down EVERY endpoint row build, trading a complete profile run for
    # an explanatory column. That trade is never worth making: the customer would lose their entire
    # endpoint inventory to gain nothing.
    if (-not (Get-Command -Name Get-SITierAttribution -ErrorAction SilentlyContinue)) {
        try { . (Join-Path $PSScriptRoot 'Get-SITierAttribution.ps1') } catch {
            Write-Warning ("tier attribution unavailable ({0}) -- SI_TierSetBy/Reason/Claims will be empty for this run; the tier itself is unaffected." -f $_.Exception.Message)
        }
    }
    $tierSourcesForAttribution = @{
        PostureRuleTargetTier = $perSource.PostureRuleTargetTier
    }
    # THE RULE ENGINE DECIDES MOST TIERS, and it was not passed here at all. Measured live on
    # 2026-08-21, before this block existed: 142 of 150 rows carried SI_TierClaims = "[]" and read
    # "no tier source matched this asset", while Stage Profile had just evaluated 549 rules against
    # those same assets. Attribution was not wrong about the sources it knew -- it could not see the
    # one that mattered, and then asserted the negative.
    # SI_RuleTier is ALREADY MIN across matched rules (Invoke-Profile), so nothing is recomputed here
    # and a second reduction cannot silently disagree with the engine's.
    if ($null -ne $verdict -and $verdict.PSObject.Properties['SI_RuleTier'] -and
        $null -ne $verdict.SI_RuleTier -and "$($verdict.SI_RuleTier)" -ne '') {
        $ruleMatches = @()
        if ($verdict.PSObject.Properties['SI_RuleMatches']) { $ruleMatches = @($verdict.SI_RuleMatches) }
        # Evidence names a rule that actually claimed the WINNING tier, not merely the first match --
        # "which rule made this Tier 0" is the question this column exists to answer.
        $topRule = ''
        foreach ($m in $ruleMatches) {
            if ($null -eq $m -or $null -eq $m.Tier) { continue }
            if ([int]$m.Tier -eq [int]$verdict.SI_RuleTier) {
                $topRule = [string]$m.RuleId
                if ($m.DetectionId) { $topRule = '{0}/{1}' -f $topRule, [string]$m.DetectionId }
                break
            }
        }
        $tierSourcesForAttribution['SIRules'] = [pscustomobject]@{
            Tier       = [int]$verdict.SI_RuleTier
            TopMatch   = $topRule
            MatchCount = $ruleMatches.Count
        }
    }
    # Only pass the logon claim when the column actually carries one -- [int]$null coerces to 0, which
    # would fabricate a Tier 0 claim on every asset that has no most-frequent user.
    if ($null -ne $row['MostFrequentUserTier'] -and "$($row['MostFrequentUserTier'])" -ne '') {
        $tierSourcesForAttribution['MostFrequentUserTier'] = $row['MostFrequentUserTier']
    }
    # THE OPERATOR'S OWN TIER TAG -- the schema's ONLY `asserted` contributor, declared since 2.3.6 and
    # never produced by anything on the production path, so `tenant_si_manual_tag` emitted ZERO claims
    # and the reducer's whole observed-beats-asserted asymmetry had nothing to arbitrate.
    # 📌 SCALE, measured read-only on the live snapshot 2026-08-25 (162 rows): 105 assets carry SOME
    # `--SI` tag but 87 of those are `--Excluded--SI`, the RA opt-out, which has nothing to do with
    # tiering. Only 19 carry a TIER tag. The earlier "90 of 150" counted the wrong tag and overstated
    # the gap roughly five-fold. What did not shrink is the finding: 16 of those 19 carry tier tags that
    # CONTRADICT EACH OTHER, and 11 assert a tier the engine never gave the asset.
    # AssetTags is used deliberately rather than MDE_MachineTags: it is the already-deduped union of
    # MDE machine tags + EG manual tags + EG dynamic tags, built above in this same function, so the
    # claim sees every carrier an operator can actually tag through instead of one of the three.
    # 🔒 THIS DOES NOT MOVE THE TIER. Attribution describes; $aggTier is passed in, never recomputed --
    # and the claim is marked FeedsTier=$false because nothing consumes it yet, so it is reported as an
    # assertion the engine did not act on rather than counted as a source that set the tier.
    if ($null -ne $row['AssetTags'] -and "$($row['AssetTags'])" -ne '' -and
        (Get-Command -Name Get-SITierFromAssetTags -ErrorAction SilentlyContinue)) {
        $tagVerdict = $null
        try {
            $tagVerdict = Get-SITierFromAssetTags -Tags $row['AssetTags'] -TagPattern (Get-SITierTagPatternFromSchema -Schema $schema)
        } catch {
            Write-Warning ("tier tag claim failed for this asset ({0}) -- no tag claim recorded; the tier itself is unaffected." -f $_.Exception.Message)
        }
        # $null means NO TAG CARRIED A TIER, which is not "claimed tier 3" -- passing it anyway would
        # fabricate an assertion on every asset whose tags are ordinary labels.
        if ($null -ne $tagVerdict) { $tierSourcesForAttribution['tenant_si_manual_tag'] = $tagVerdict }
    }
    # The columns are ALWAYS emitted, empty if attribution is unavailable. A column that sometimes
    # exists and sometimes does not is worse than one that is sometimes empty: the schema declares
    # these, and a missing column breaks consumers at query time rather than showing them a blank.
    $row['SI_TierSetBy']  = ''
    $row['SI_TierReason'] = ''
    $row['SI_TierClaims'] = '[]'
    if (Get-Command -Name Get-SITierAttribution -ErrorAction SilentlyContinue) {
        try {
            # #244: an operator override that MOVED the tier is what set it -- say so, instead of "unattributed"
            $ovBy = $null; $ovFrom = $null
            if ([string]$row['SI_TierBeforeOverride'] -ne '') { $ovBy = [string]$row['SI_TierOverrideBy']; $ovFrom = [string]$row['SI_TierBeforeOverride'] }
            $attr = Get-SITierAttribution -FinalTier $aggTier -Sources $tierSourcesForAttribution -OverrideBy $ovBy -ComputedTier $ovFrom -DefaultTier (Get-SIDefaultTierValue -Engine endpoint)
            $row['SI_TierSetBy']  = [string]$attr.SI_TierSetBy
            $row['SI_TierReason'] = [string]$attr.SI_TierReason
            $row['SI_TierClaims'] = [string]$attr.SI_TierClaims
        } catch {
            # Never let an explanatory column cost the customer their inventory row.
            Write-Warning ("tier attribution failed for this asset ({0}) -- columns left empty; the tier itself is unaffected." -f $_.Exception.Message)
        }
    }

    # ---- #562 AssetType / AssetSubtype FROM THE ONE CLASSIFICATION (data-model/classification.locked.json) ----
    # 🔴 Was the Classify stage's free-text service type: measured live 2026-10-10, half the devices 'Unknown', domain
    # controllers and servers 'Workstation' (the AI error fallback), switches 'Unknown', subtype empty everywhere. Now the
    # row's source values go through the same value maps and rows as the CI build (SI-ProfileClassification.ps1). The
    # roles come from what the CI reads (Exposure Graph deviceRole / isDomainController / Exchange / ADFS flags) plus the
    # profile's own role detections (SIRules) -- NOT the IsDomainController column, whose hostname heuristic calls a
    # thermostat named 'Nest-DC14' a domain controller. The verdict's value stays only when no classification can run.
    if (Get-Command -Name ConvertTo-SIEndpointClassificationItem -ErrorAction SilentlyContinue) {
        $clsItem = ConvertTo-SIEndpointClassificationItem -Maps (Get-SIProfileValueMaps) -DeviceType ([string]$row['DeviceType']) `
            -DeviceCategory ([string]$row['DeviceCategory']) -DeviceSubtype ([string]$row['DeviceSubtype']) -OsPlatform ([string]$row['OsPlatform']) `
            -DeviceRoles $row['DeviceRole'] -IsDomainController ((ConvertTo-SIBoolOrNull (Get-SIEgValue $meta 'isDomainController')) -eq $true) `
            -IsExchangeServer (((ConvertTo-SIBoolOrNull (Get-SIEgValue $meta 'isExchangeServerDnsName')) -eq $true) -or ((ConvertTo-SIBoolOrNull (Get-SIEgValue $meta 'isTaggedAsExchangeServer')) -eq $true)) `
            -IsAdfsServer ((ConvertTo-SIBoolOrNull (Get-SIEgValue $meta 'isAdfsServer')) -eq $true) -RuleIds $row['SIRules']
        $cls = Get-SIProfileAssetClassification -Item $clsItem
        if ($null -ne $cls) { $row['AssetType'] = $cls.Type; $row['AssetSubtype'] = $cls.Subtype }
    }

    # ---- Hashes (4 per-stage) over schema-declared fields by writtenBy ----
    $collectFieldNames  = @($schema.fields | Where-Object { $_.stage.writtenBy -eq 'collect'         -and $_.purpose -notin 'enrichment','forensic','raw' } | ForEach-Object { $_.name })
    $enrichFieldNames   = @($schema.fields | Where-Object { $_.stage.writtenBy -eq 'enrich'          -and $_.purpose -notin 'enrichment','forensic','raw' } | ForEach-Object { $_.name })
    $postureFieldNames  = @($schema.fields | Where-Object { $_.stage.writtenBy -eq 'posture_analyze' -and $_.purpose -notin 'enrichment','forensic','raw' } | ForEach-Object { $_.name })
    $classifyFieldNames = @($schema.fields | Where-Object { $_.stage.writtenBy -eq 'classify'        -and $_.name -notmatch '^(CollectHash|EnrichHash|PostureHash|ClassifyHash)$' } | ForEach-Object { $_.name })

    $row['CollectHash']  = Get-SIRowHash (_SIHashBag $collectFieldNames  $row)
    $row['EnrichHash']   = Get-SIRowHash (_SIHashBag $enrichFieldNames   $row)
    $row['PostureHash']  = Get-SIRowHash (_SIHashBag $postureFieldNames  $row)
    $row['ClassifyHash'] = Get-SIRowHash (_SIHashBag $classifyFieldNames $row)

    return [pscustomobject]$row
}
