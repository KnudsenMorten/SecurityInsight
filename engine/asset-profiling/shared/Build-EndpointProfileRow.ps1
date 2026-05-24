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
    'AssetName'                                = 'MDE_DeviceName'   # cross-engine asset-name alias
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

function Get-SIDerivedValue {
    param([Parameter(Mandatory)] $Field, [Parameter(Mandatory)] $Context)

    $meta = if ($Context.Record.Metadata) { $Context.Record.Metadata } else { @{} }
    $verdict = $Context.Verdict
    $perSource = $Context.PerSourceVerdicts

    # Per-source verdict family (8 fields)
    if ($Field.name -match '^(EndpointCatalogMatch|PostureRuleTargetTier)Verdict_(Tier|TopMatch|MatchCount|MissCount)$') {
        $tag = $Matches[1]; $aspect = $Matches[2]
        $v = $perSource[$tag]
        if (-not $v) { return $null }
        return $v.$aspect
    }

    switch ($Field.name) {
        'PrimaryEntityId'   { return $Context.PrimaryEntityId }
        'PrimaryEntityType' { return $Context.PrimaryEntityType }
        'EntityIds'         { return ,$Context.EntityIds }
        'RunId'             { return $Context.Record.SI_RunId }
        'CollectionTime'    { return $Context.RunContext.CollectionTime }
        'EndpointTieringCatalogVersion' { return $Context.CatalogVersion }
        # AssetName: cross-engine alias resolved by walking provider sources
        # in priority order (per user directive "use all the
        # providers as options for the AssetName -- entra, mde, AD, azure, EG").
        # Endpoint priority: Entra display-name > MDE device-name > AD computer
        # short-name > Azure resource short-name > EG device-name > host UUID.
        # Schema added the field but never wired the derivation
        # -> AssetName was always null on Endpoint rows.
        'AssetName' {
            $get = {
                param($m, $k)
                if ($m -is [System.Collections.IDictionary]) { if ($m.Contains($k)) { return [string]$m[$k] } else { return '' } }
                if ($m.PSObject.Properties[$k]) { return [string]$m.$k } else { return '' }
            }
            $candidates = @(
                & $get $meta 'ENTRA_DisplayName'      # Entra (when device-cross-correlated)
                & $get $meta 'MDE_DeviceName'         # MDE (Defender-onboarded)
                & $get $meta 'AD_DnsHostName'         # on-prem AD computer FQDN
                & $get $meta 'AD_Name'                # on-prem AD short name
                & $get $meta 'AZ_Name'                # Azure resource (Arc / VM short name)
                & $get $meta 'EG_DeviceName'          # ExposureGraph
                & $get $meta 'MDE_HardwareUuid'       # last resort: hardware id
            )
            foreach ($c in $candidates) {
                if (-not [string]::IsNullOrWhiteSpace($c)) { return $c }
            }
            return $null
        }
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
                elseif ($meta.Contains('EG_DeviceName')) { $hn = [string]$meta['EG_DeviceName'] }
            } elseif ($meta.PSObject.Properties['MDE_DeviceName']) { $hn = [string]$meta.MDE_DeviceName }
            elseif ($meta.PSObject.Properties['EG_DeviceName']) { $hn = [string]$meta.EG_DeviceName }
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
        'AssetTags' {
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
                if ($m -is [System.Collections.IDictionary]) {
                    if ($m.Contains($k)) { return $m[$k] } else { return $null }
                }
                if ($m.PSObject.Properties[$k]) { return $m.$k } else { return $null }
            }
            $mt   = & $normalize (& $get $meta 'MDE_MachineTags')
            $dmt  = & $normalize (& $get $meta 'EG_DeviceManualTags')
            $ddt  = & $normalize (& $get $meta 'EG_DeviceDynamicTags')
            $all  = New-Object System.Collections.Generic.List[string]
            foreach ($a in @($mt, $dmt, $ddt)) {
                foreach ($t in $a) { $all.Add($t) }
            }
            if ($all.Count -eq 0) { return '' }
            # Case-insensitive dedupe, preserve first-seen casing + order.
            $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            $uniq = New-Object System.Collections.Generic.List[string]
            foreach ($t in $all) {
                if ($seen.Add($t)) { $uniq.Add($t) }
            }
            return ($uniq -join ';')
        }

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
        'DisplayName' {
            $entraName = $null
            if ($meta -is [System.Collections.IDictionary]) {
                if ($meta.Contains('ENTRA_DisplayName')) { $entraName = $meta['ENTRA_DisplayName'] }
            } elseif ($meta.PSObject.Properties['ENTRA_DisplayName']) { $entraName = $meta.ENTRA_DisplayName }
            if (-not [string]::IsNullOrWhiteSpace([string]$entraName)) { return [string]$entraName }

            $mdeName = $null
            if ($meta -is [System.Collections.IDictionary]) {
                if ($meta.Contains('MDE_DeviceName')) { $mdeName = $meta['MDE_DeviceName'] }
            } elseif ($meta.PSObject.Properties['MDE_DeviceName']) { $mdeName = $meta.MDE_DeviceName }
            if (-not [string]::IsNullOrWhiteSpace([string]$mdeName)) {
                $s = [string]$mdeName
                if ($s.Contains('.')) { return $s.Substring(0, $s.IndexOf('.')) }
                return $s
            }

            $egName = Get-SIEgValue $meta 'deviceName'
            if (-not [string]::IsNullOrWhiteSpace([string]$egName)) { return [string]$egName }
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
    $perSource = @{
        EndpointCatalogMatch  = if ($tierSources -and $tierSources.PSObject.Properties['EndpointCatalog']) {
                                    ConvertTo-SIPerSourceVerdict -TierSourceEntry $tierSources.EndpointCatalog -NameField 'Name'
                                } else { [pscustomobject]@{ Tier=$null; TopMatch=$null; MatchCount=0; MissCount=0; Proofs=@() } }
        PostureRuleTargetTier = if ($tierSources -and $tierSources.PSObject.Properties['PostureRules']) {
                                    ConvertTo-SIPerSourceVerdict -TierSourceEntry $tierSources.PostureRules -NameField 'RuleName'
                                } else { [pscustomobject]@{ Tier=$null; TopMatch=$null; MatchCount=0; MissCount=0; Proofs=@() } }
    }

    # endpoint default = 3 when no rule fires (per user direction
    # 2026-04-30: "i would like for endpoints to default to tier 3 if no hits").
    # Plus guard against [int]$null=0 silent coercion.
    $aggTier = if ($null -ne $verdict.SI_Tier -and "$($verdict.SI_Tier)" -ne '') {
        try { [int]$verdict.SI_Tier } catch { 3 }
    } else { 3 }

    # ---- EntityIds -- merged across MDE + EG + AAD + Hostname (priority order) ----
    $mdeId = $null; $egNodeId = $null; $aadId = $null; $hostName = $null; $azResId = $null
    if ($meta -is [System.Collections.IDictionary]) {
        if ($meta.Contains('MDE_DeviceId') -and $meta['MDE_DeviceId']) { $mdeId = [string]$meta['MDE_DeviceId'] }
        if ($meta.Contains('EG_NodeId')    -and $meta['EG_NodeId'])    { $egNodeId = [string]$meta['EG_NodeId'] }
        if ($meta.Contains('MDE_AzureADDeviceId') -and $meta['MDE_AzureADDeviceId']) { $aadId = [string]$meta['MDE_AzureADDeviceId'] }
        elseif ($meta.Contains('EG_AadDeviceId') -and $meta['EG_AadDeviceId'])      { $aadId = [string]$meta['EG_AadDeviceId'] }
        if ($meta.Contains('MDE_DeviceName') -and $meta['MDE_DeviceName']) { $hostName = [string]$meta['MDE_DeviceName'] }
        elseif ($meta.Contains('EG_DeviceName') -and $meta['EG_DeviceName']) { $hostName = [string]$meta['EG_DeviceName'] }
        if ($meta.Contains('MDE_AzureResourceId') -and $meta['MDE_AzureResourceId']) { $azResId = [string]$meta['MDE_AzureResourceId'] }
        # EG fallback when MDE didn't tag the device with its Azure
        # resource ID (Azure VMs / Azure Arc machines also surface in EG with
        # the AzureResourceId on the node properties).
        elseif ($meta.Contains('EG_AzureResourceId') -and $meta['EG_AzureResourceId']) { $azResId = [string]$meta['EG_AzureResourceId'] }
    } else {
        if ($meta.PSObject.Properties['MDE_DeviceId']        -and $meta.MDE_DeviceId)        { $mdeId = [string]$meta.MDE_DeviceId }
        if ($meta.PSObject.Properties['EG_NodeId']           -and $meta.EG_NodeId)           { $egNodeId = [string]$meta.EG_NodeId }
        if ($meta.PSObject.Properties['MDE_AzureADDeviceId'] -and $meta.MDE_AzureADDeviceId) { $aadId = [string]$meta.MDE_AzureADDeviceId }
        elseif ($meta.PSObject.Properties['EG_AadDeviceId'] -and $meta.EG_AadDeviceId)       { $aadId = [string]$meta.EG_AadDeviceId }
        if ($meta.PSObject.Properties['MDE_DeviceName']      -and $meta.MDE_DeviceName)      { $hostName = [string]$meta.MDE_DeviceName }
        elseif ($meta.PSObject.Properties['EG_DeviceName']  -and $meta.EG_DeviceName)        { $hostName = [string]$meta.EG_DeviceName }
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
    $properties = @{
        meta = @{
            schema_version          = [string]$schema.schemaVersion
            tiering_catalog_version = $catVer
            schema_authority        = 'v2.2/asset-profiling-schema/endpoint.schema.locked.json'
        }
        collect = @{
            mde           = $collectMde
            exposureGraph = $collectEg     # whole NodeProperties.rawData blob (or $null), @odata.type stripped
            azure         = $collectAz
            entra         = $collectEntra  # Entra-joined device fields (OS, TrustType, ProfileType, Category)
            cmdb          = $collectCmdb   # matched CMDB service record (all CSV columns)
        }
    }

    $ctx = @{
        Record            = $Record
        Verdict           = $verdict
        TierSources       = $tierSources
        PerSourceVerdicts = $perSource
        EntityIds         = $entityIds.ToArray()
        PrimaryEntityId   = $primaryId
        PrimaryEntityType = $primaryType
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
                          'CmdbMatchPhase','CmdbMatchState','CmdbMatchRule','LastSeenInCmdb')
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
                if ($bagVal) { $v = $bagVal }
            } catch {}
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
