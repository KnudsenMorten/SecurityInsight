#Requires -Version 5.1
<#
    Collect stage.

    For each shard from Discover: build per-asset Metadata, compute fp_meta
    from vital props, compare to the cached fingerprint, and decide:
    revalidate (skip Enrich + Classify) or proceed downstream.

    Real-Azure mode: for assets that have an EG DeviceId (sourced from
    ExposureGraph or merged with one), batch-pull DeviceInfo via Microsoft
    Graph Advanced Hunting in a single round-trip, then build metadata from
    the real Defender data. Assets without an EG DeviceId fall back to the
    source-of-record's own data (Entra OS, ARG resource info).

    Mock mode: synthetic metadata derived from the Hint field.
#>

function Get-SIDeviceInfoByName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$DeviceNames)

    if ($DeviceNames.Count -eq 0) { return @{} }

    . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth\Get-SIGraphToken.ps1')

    try {
        $token = Get-SIGraphToken -Resource Graph
    } catch {
        Write-Warning ('Get-SIDeviceInfoByName: token failed -- {0}' -f $_.Exception.Message)
        return @{}
    }

    # Name-based join because EG NodeId (32-char UUID) doesn't match MDE
    # DeviceInfo DeviceId (40-char SHA1). DeviceName matches across both
    # tables when MDE has discovered the device too.
    # Filter to ASCII-only names -- non-ASCII chars (e.g., Danish 'æ' that
    # comes back as '?') round-trip through JSON -> KQL parser badly and
    # produce 400 Bad Request on the whole batch.
    $cleanNames = $DeviceNames | Where-Object { $_ -match '^[\x20-\x7E]+$' }
    if ($cleanNames.Count -eq 0) { return @{} }

    $nameList = ($cleanNames | ForEach-Object { "'$($_.ToLowerInvariant() -replace '''', '''''')'" }) -join ','
    # Project DeviceName as-is and compute the lowercase key in PowerShell.
    # Reference only columns that EXIST in DeviceInfo across MDE tenants:
    # LocalIPv4 + HealthStatus from earlier versions are NOT in the current
    # schema and 400 Bad Request the whole query. Use SensorHealthState
    # (the actual schema column) instead of HealthStatus.
    # Schema-defensive projection: DeviceInfo evolves; columns get deprecated/
    # removed across tenants without warning. column_ifexists returns the
    # column when present, the typed default otherwise -- so a single missing
    # column doesn't 400 the whole batch and lose DeviceInfo for every endpoint
    # in the run. (IsAzureADJoined was deprecated in 2024; JoinType replaces it
    # in newer tenants.)
    $kql = @"
DeviceInfo
| where tolower(DeviceName) in ($nameList)
| summarize arg_max(Timestamp, *) by DeviceId
| project DeviceId,
          DeviceName,
          PublicIP          = column_ifexists('PublicIP',          ''),
          LoggedOnUsers     = column_ifexists('LoggedOnUsers',     dynamic([])),
          MachineGroup      = column_ifexists('MachineGroup',      ''),
          IsAzureADJoined   = column_ifexists('IsAzureADJoined',   bool(null)),
          JoinType          = column_ifexists('JoinType',          ''),
          SensorHealthState = column_ifexists('SensorHealthState', ''),
          OSPlatform        = column_ifexists('OSPlatform',        ''),
          OSVersion         = column_ifexists('OSVersion',         ''),
          Model             = column_ifexists('Model',             ''),
          Vendor            = column_ifexists('Vendor',            ''),
          OnboardingStatus  = column_ifexists('OnboardingStatus',  ''),
          DeviceCategory    = column_ifexists('DeviceCategory',    ''),
          DeviceType        = column_ifexists('DeviceType',        ''),
          IPAddresses       = column_ifexists('IPAddresses',       dynamic([]))
"@

    try {
        $resp = Invoke-RestMethod -Method Post `
            -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' `
            -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } `
            -Body (@{ Query = $kql } | ConvertTo-Json -Compress)
    } catch {
        # PS 5.1 doesn't always populate $_.ErrorDetails for WebException --
        # read the response stream directly so the real KQL error surfaces
        # (e.g., "Failed to resolve column 'X'") instead of just "(400) Bad Request".
        $msg = $_.Exception.Message
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $msg = $_.ErrorDetails.Message
        } elseif ($_.Exception.Response) {
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $body = $reader.ReadToEnd()
                if ($body) { $msg = ('{0} | body: {1}' -f $msg, $body) }
                $reader.Close()
            } catch { }
        }
        Write-Warning ('Get-SIDeviceInfoByName: hunting query failed -- {0}' -f $msg)
        return @{}
    }

    $rows = if ($resp.results) { $resp.results } elseif ($resp.Results) { $resp.Results } else { @() }
    $byName = @{}
    foreach ($r in $rows) {
        if ($r.DeviceName) { $byName[([string]$r.DeviceName).ToLowerInvariant()] = $r }
    }
    return $byName
}

function Invoke-SICollect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$RunContext
    )

    $assets = Read-SIStageShards -Context $RunContext.StorageContext `
                                  -ContainerName $RunContext.StagingContainer `
                                  -RunId $RunContext.RunId `
                                  -Stage 'Discover' `
                                  -ReplicaIndex ([int]$RunContext.ShardIndex)

    # ---- EG enrichment maps ------------------------------
    # Lazy-built per engine. Master discovery runs in Stage Discover; EG
    # is purely supplementary -- silent miss when EG hasn't seen the asset
    # yet. Kept as ONE round-trip per engine for the whole run, joined
    # per-asset in the loop below.
    $identityEgMap = @{}
    $azureEgMap    = @{}
    if ($RunContext.StorageContext.Mode -ne 'Mock') {
        # discovery moved from v2.2/engine/discovery/ to v2.2/engine/asset-profiling/discovery/
        $discoveryDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'discovery'
        if ($RunContext.Engine -eq 'identity') {
            . (Join-Path $discoveryDir 'Get-DiscoveryFromIdentityExposureGraph.ps1')
            try   { $identityEgMap = Get-DiscoveryFromIdentityExposureGraph } catch { Write-Warning ('Identity EG enrichment failed -- continuing master-only: {0}' -f $_.Exception.Message) }
        }
        elseif ($RunContext.Engine -eq 'azure') {
            . (Join-Path $discoveryDir 'Get-DiscoveryFromAzureExposureGraph.ps1')
            try   { $azureEgMap = Get-AzureExposureGraphResourceNodes } catch { Write-Warning ('Azure EG enrichment failed -- continuing master-only: {0}' -f $_.Exception.Message) }
        }
    }

    # Batch pull DeviceInfo for every asset that has a name we can match.
    # One round-trip. Name-based join (see Get-SIDeviceInfoByName for why).
    # Endpoint engine only -- for identity engine, asset names are UPNs that
    # don't match MDE DeviceName.
    $deviceInfoByName = @{}
    if ($RunContext.StorageContext.Mode -ne 'Mock' -and $RunContext.Engine -eq 'endpoint') {
        $names = New-Object System.Collections.ArrayList
        foreach ($a in $assets) {
            if ($a.Name) { [void]$names.Add([string]$a.Name) }
        }
        if ($names.Count -gt 0) {
            $deviceInfoByName = Get-SIDeviceInfoByName -DeviceNames $names.ToArray()
        }
    }

    $skipped         = 0
    $cadenceSkipped  = 0
    $proceed         = 0
    $devInfoMatches  = 0
    $egDriven        = 0
    $argDriven       = 0
    $egEnriched      = 0
    $proceedRecords  = New-Object System.Collections.ArrayList

    $totalToCollect  = $assets.Count
    $progressEvery   = if ($totalToCollect -lt 30) { 5 } elseif ($totalToCollect -lt 200) { 25 } else { 50 }
    $progressIdx     = 0
    $stageStart      = [datetime]::UtcNow

    foreach ($a in $assets) {
        $progressIdx++
        if ($progressIdx -eq 1 -or $progressIdx % $progressEvery -eq 0 -or $progressIdx -eq $totalToCollect) {
            $elapsed = ([datetime]::UtcNow - $stageStart).TotalSeconds
            Write-SIInfo ('[{0,4}/{1}] elapsed={2,5:N1}s  proceed={3} skipped={4} EG-src={5}' -f `
                $progressIdx, $totalToCollect, $elapsed, $proceedRecords.Count, ($progressIdx - $proceedRecords.Count), $egDriven)
        }
        $assetId = $a.AssetId

        # Build metadata. Source priority (highest first):
        #   1. ExposureGraph NodeProperties (richest -- already parsed in
        #      Get-DiscoveryFromExposureGraph; no extra round-trip needed).
        #      The MDE DeviceInfo table uses a different DeviceId scheme
        #      (40-char SHA1) than EG NodeId (32-char UUID), so a
        #      cross-table `where DeviceId in (egNodeIds)` always returns 0.
        #      Use EG's parsed properties directly instead.
        #   2. DeviceInfo batch (still wired but currently always empty
        #      because of the ID scheme mismatch above; will fire when we
        #      add a name-based correlator in a future preview).
        #   3. Entra device fields.
        #   4. ARG resource fields.
        #   5. Mock synthetic shape.
        if ($a.AZ_PropertiesRawJson -and $RunContext.Engine -eq 'endpoint') {
            # EG rawData mirror into Properties column.
            # dropped the `Source -eq 'EndpointExposureGraph'` gate.
            # Stage Discover applies Entra-master priority which
            # overwrites Source to 'EntraDevice' when both sources see the
            # asset -- the EG metadata block was then skipped, leaving
            # Properties = '{}'. Use the field's PRESENCE (AZ_PropertiesRawJson
            # is only set by EG discovery) instead of the now-overwritten Source.
            #
            # parse the EG rawData JSON to an object (was stored as string,
            # which broke (a) the @odata.type cleaner, (b) the walk in row builder,
            # (c) Properties.collect.exposureGraph display). Inner .rawData is what the
            # schema sourcePath strips down to. Then mirror common fields into MDE_*
            # keys so the existing keymap-based extraction populates Hostname /
            # OsPlatform / OsVersion / MachineGroup / etc. for EG-only devices.
            $egParsed = $null
            $egRaw    = $null
            try {
                if ($a.AZ_PropertiesRawJson) {
                    $egParsed = $a.AZ_PropertiesRawJson | ConvertFrom-Json -ErrorAction Stop
                    $egRaw    = if ($egParsed.PSObject.Properties['rawData']) { $egParsed.rawData } else { $egParsed }
                }
            } catch {
                Write-Warning ('       endpoint EG branch: failed to parse AZ_PropertiesRawJson for asset {0} -- {1}' -f $a.AssetId, $_.Exception.Message)
            }

            # Helper: read a property from the EG rawData object, returning $null when absent.
            function _eg($obj, $name) {
                if ($null -eq $obj) { return $null }
                if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] } else { return $null } }
                if ($obj.PSObject.Properties[$name]) { return $obj.$name } else { return $null }
            }
            # helper: only set if not already populated. Used so MDE_*
            # values that arrived from the MDE source on a cross-source-merged record
            # WIN over EG-mirrored fallbacks. MDE's source data is more precise than
            # EG's denormalized rawData (e.g., MDE.computerDnsName=FQDN vs EG.deviceName=short).
            function _setIfEmpty($h, $k, $v) {
                if ($null -eq $v) { return }
                if (-not $h.ContainsKey($k) -or $null -eq $h[$k] -or [string]::IsNullOrWhiteSpace([string]$h[$k])) { $h[$k] = $v }
            }

            # passthrough ALL MDE_*, ENTRA_*, AZ_* fields from $a first --
            # cross-source merge in Discover folds MDE + Entra fields onto the same
            # record when AadDeviceId joins them, so the EG branch must preserve
            # those source-of-truth values instead of building $metadata from scratch.
            $excludedTopLevel = @('AssetId','Source','Sources','Hint','Name','NormalizedKey','Raw','AZ_PropertiesRawJson')
            $metadata = @{ MDE_AssetType = 'Endpoint' }
            $allKeys = if ($a -is [System.Collections.IDictionary]) { @($a.Keys) } else { @($a.PSObject.Properties.Name) }
            foreach ($k in $allKeys) {
                if ($k -in $excludedTopLevel) { continue }
                $val = if ($a -is [System.Collections.IDictionary]) { $a[$k] } else { $a.$k }
                if ($k -like 'MDE_*' -or $k -like 'ENTRA_*' -or $k -like 'AZ_*' -or $k -like 'EG_*') {
                    $metadata[$k] = $val
                }
            }
            $metadata['EG_RawData'] = $egRaw     # parsed object, inner .rawData

            # mirror EG rawData fields into MDE_* keys so the row
            # builder's keymap-based extraction populates flat columns for
            # EG-only devices. only fill where MDE source didn't
            # already provide the value (MDE is the more precise source).
            # also mirror EG.deviceCategory + EG.deviceType so the
            # DeviceCategory / DeviceType flat columns populate for EG-only devices
            # (DeviceInfo doesn't always carry these for AAD-joined-only devices).
            _setIfEmpty $metadata 'MDE_DeviceCategory'    (_eg $egRaw 'deviceCategory')
            _setIfEmpty $metadata 'MDE_DeviceType'        (_eg $egRaw 'deviceType')
            _setIfEmpty $metadata 'MDE_DeviceName'        (_eg $egRaw 'deviceName')
            _setIfEmpty $metadata 'MDE_OSPlatform'        $(if ($_o = _eg $egRaw 'osPlatform') { $_o } else { _eg $egRaw 'osPlatformFriendlyName' })
            _setIfEmpty $metadata 'MDE_OSVersion'         $(if ($_v = _eg $egRaw 'osVersion') { $_v } else { _eg $egRaw 'osVersionFriendlyName' })
            _setIfEmpty $metadata 'MDE_MachineGroup'      (_eg $egRaw 'machineGroup')
            _setIfEmpty $metadata 'MDE_MachineTags'       (_eg $egRaw 'deviceDynamicTags')
            _setIfEmpty $metadata 'MDE_OnboardingStatus'  (_eg $egRaw 'onboardingStatus')
            _setIfEmpty $metadata 'MDE_SensorHealthState' (_eg $egRaw 'sensorHealthState')
            _setIfEmpty $metadata 'MDE_FirstSeen'         (_eg $egRaw 'firstSeenByInventory')
            _setIfEmpty $metadata 'MDE_LastSeen'          (_eg $egRaw 'lastSeen')
            _setIfEmpty $metadata 'MDE_RiskScore'         (_eg $egRaw 'riskScore')
            _setIfEmpty $metadata 'MDE_ExposureScore'     (_eg $egRaw 'exposureScore')
            _setIfEmpty $metadata 'MDE_Vendor'            (_eg $egRaw 'vendor')
            _setIfEmpty $metadata 'MDE_Model'             (_eg $egRaw 'model')
            _setIfEmpty $metadata 'MDE_AadDeviceId'       (_eg $egRaw 'aadDeviceId')
            _setIfEmpty $metadata 'MDE_PublicIp'          (_eg $egRaw 'publicIp')
            # surface IP-bearing EG fields as their own keys so the
            # ipInRange detect kind can scan them in addition to MDE sources.
            _setIfEmpty $metadata 'EG_LastIpAddress'      (_eg $egRaw 'lastIpAddress')
            _setIfEmpty $metadata 'EG_PublicIp'           (_eg $egRaw 'publicIp')

            # /121: DeviceInfo-batched IPAddresses (lookup keyed by SHORT
            # hostname Discover already normalised in $a.Name; MDE_DeviceName is FQDN).
            # union ALL SOURCES OF TRUTH into MDE_EffectiveIpAddresses
            # instead of letting MDE first-wins. Architectural contract -- the union
            # absorbs IP-bearing fields from every source the engine has access to:
            #
            #     LIVE TODAY:
            #     1. MDE DeviceInfo IPAddresses          (Defender XDR, name-batched)
            #     2. EG rawData internalIpAddresses[]    (Microsoft Security Exposure
            #                                             Graph -- curated security view)
            #     3. EG rawData lastIpAddress            (last EG-observed)
            #     4. ENTRA_PrivateIp / ENTRA_PublicIp    (Entra-joined device record)
            #     5. AZ_PrivateIpAddresses               (ARG: NIC ipConfigurations[*]
            #                                             .properties.privateIPAddress
            #                                             on linked Azure resource)
            #     6. existing MDE_EffectiveIpAddresses   (anything Discover stamped)
            #
            #     COMING (placeholder -- merged in if/when present):
            #     7. AD_IpAddress / AD_IpAddresses       (on-prem AD computer object,
            #                                             from msDS-AdditionalDnsHostName
            #                                             or sIDHistory enrichment)
            #     8. CMDB_PrivateIp / CMDB_IpAddresses   (CMDB CSV column folded by
            #                                             Reconcile when a CI matches)
            #
            # All deduplicated case-insensitively. ipInRange scans the union, so a
            # CIDR rule matches when ANY source has an IP in range.
            $allIps = New-Object System.Collections.Generic.List[string]

            # Source 5 -- existing values (first so we keep their order)
            if ($metadata.ContainsKey('MDE_EffectiveIpAddresses') -and $metadata['MDE_EffectiveIpAddresses']) {
                foreach ($v in @($metadata['MDE_EffectiveIpAddresses'])) { if ($v) { [void]$allIps.Add([string]$v) } }
            }

            # Source 1 -- MDE DeviceInfo (name-batched lookup)
            $nameKey = if ($a.Name) { ([string]$a.Name).ToLowerInvariant() } `
                       elseif ($metadata['MDE_DeviceName']) { ([string]$metadata['MDE_DeviceName']).Split('.')[0].ToLowerInvariant() } `
                       else { $null }
            if ($nameKey -and $deviceInfoByName.ContainsKey($nameKey)) {
                $di = $deviceInfoByName[$nameKey]
                if (-not $metadata['MDE_PublicIp'] -and $di.PublicIP)           { $metadata['MDE_PublicIp']      = $di.PublicIP }
                if (-not $metadata['MDE_LoggedOnUsers'] -and $di.LoggedOnUsers) { $metadata['MDE_LoggedOnUsers'] = $di.LoggedOnUsers }
                if ($di.IPAddresses) {
                    try {
                        $arr = $di.IPAddresses
                        if ($arr -is [string]) { $arr = $arr | ConvertFrom-Json -ErrorAction Stop }
                        foreach ($n in $arr) {
                            $ip = if ($n -and $n.PSObject -and $n.PSObject.Properties['IPAddress']) { [string]$n.IPAddress } else { [string]$n }
                            if ($ip) { [void]$allIps.Add($ip) }
                        }
                    } catch {}
                }
            }

            # Source 2 -- EG rawData.internalIpAddresses (array of {ipAddress, ...})
            $egInternal = _eg $egRaw 'internalIpAddresses'
            if ($egInternal) {
                foreach ($n in @($egInternal)) {
                    $ip = if ($n -and $n.PSObject -and $n.PSObject.Properties['ipAddress']) { [string]$n.ipAddress } `
                          elseif ($n -and $n.PSObject -and $n.PSObject.Properties['IpAddress']) { [string]$n.IpAddress } `
                          else { [string]$n }
                    if ($ip) { [void]$allIps.Add($ip) }
                }
            }

            # Source 3 -- EG lastIpAddress (single)
            $egLast = _eg $egRaw 'lastIpAddress'
            if ($egLast) { [void]$allIps.Add([string]$egLast) }

            # Source 4 -- Entra (when present on the cross-source-merged record)
            foreach ($k in @('ENTRA_PrivateIp','ENTRA_PublicIp','ENTRA_IpAddress')) {
                if ($metadata.ContainsKey($k) -and $metadata[$k]) { [void]$allIps.Add([string]$metadata[$k]) }
            }

            # Source 5 -- ARG (Azure VM linked NIC private IPs). When the asset is
            # an Azure VM, AZ_PropertiesJson.networkProfile.networkInterfaces[].id
            # references the NIC; stamps the resolved private IPs onto
            # AZ_PrivateIpAddresses upstream when ARG visibility allows it.
            foreach ($k in @('AZ_PrivateIpAddresses','AZ_PrivateIp')) {
                if ($metadata.ContainsKey($k) -and $metadata[$k]) {
                    foreach ($v in @($metadata[$k])) { if ($v) { [void]$allIps.Add([string]$v) } }
                }
            }

            # Sources 7/8 -- AD + CMDB (placeholders -- pulled if upstream stamped them).
            # AD_* lands during Enrich when the on-prem AD enrichment ships; CMDB_*
            # lands during Reconcile when a CI matches. Both keys are honored here
            # so future enrichers don't need a separate Collect change.
            foreach ($k in @('AD_IpAddress','AD_IpAddresses','CMDB_PrivateIp','CMDB_IpAddresses','CMDB_ip','CMDB_private_ip')) {
                if ($metadata.ContainsKey($k) -and $metadata[$k]) {
                    foreach ($v in @($metadata[$k])) { if ($v) { [void]$allIps.Add([string]$v) } }
                }
            }

            # De-dup (case-insensitive) while preserving first-seen order
            if ($allIps.Count -gt 0) {
                $seen = New-Object System.Collections.Generic.HashSet[string]
                $deduped = New-Object System.Collections.Generic.List[string]
                foreach ($ip in $allIps) {
                    $k2 = $ip.ToLowerInvariant()
                    if ($seen.Add($k2)) { [void]$deduped.Add($ip) }
                }
                $metadata['MDE_EffectiveIpAddresses'] = $deduped.ToArray()
            }
            $egDriven++
        }
        elseif ($a.EgNodeId) {
            $metadata = @{
                EG_NodeId          = $a.EgNodeId
                EG_OS              = $a.EgOS
                EG_DeviceType      = $a.EgDeviceType
                EG_DeviceCategory  = $a.EgDeviceCategory
                EG_OnboardStatus   = $a.EgOnboardStatus
                EG_ExposureScore   = $a.EgExposureScore
                EG_RiskScore       = $a.EgRiskScore
                EG_Name            = $a.Name
            }
            # If a DeviceInfo row was found via the name-based batch, fold
            # in MDE-side fields not present in EG (network, logged-on users,
            # machine group, AAD-join status, etc.)
            $nameKey = if ($a.Name) { ([string]$a.Name).ToLowerInvariant() } else { $null }
            if ($nameKey -and $deviceInfoByName.ContainsKey($nameKey)) {
                $di = $deviceInfoByName[$nameKey]
                $metadata['MDE_DeviceId']         = $di.DeviceId
                $metadata['MDE_DeviceName']       = $di.DeviceName
                $metadata['MDE_PublicIP']         = $di.PublicIP
                $metadata['MDE_LoggedOnUsers']    = $di.LoggedOnUsers
                $metadata['MDE_MachineGroup']     = $di.MachineGroup
                $metadata['MDE_IsAADJoined']      = $di.IsAzureADJoined
                $metadata['MDE_SensorHealth']     = $di.SensorHealthState
                $metadata['MDE_OnboardingStatus'] = $di.OnboardingStatus
                $metadata['MDE_DeviceCategory']   = $di.DeviceCategory
                $metadata['MDE_DeviceType']       = $di.DeviceType
                $metadata['MDE_OSVersion']        = $di.OSVersion
                $metadata['MDE_Vendor']           = $di.Vendor
                $metadata['MDE_Model']            = $di.Model
                # pull DeviceInfo.IPAddresses (dynamic array of
                # {IPAddress, MacAddress, Type, OperationalStatus}) and reduce
                # to a flat [string[]] of just IPAddress values for the
                # ipInRange detect kind. Schema column = MDE_EffectiveIpAddresses.
                if ($di.IPAddresses) {
                    $ipList = New-Object System.Collections.Generic.List[string]
                    try {
                        $arr = $di.IPAddresses
                        if ($arr -is [string]) { $arr = $arr | ConvertFrom-Json -ErrorAction Stop }
                        foreach ($n in $arr) {
                            $ip = if ($n.PSObject.Properties['IPAddress']) { [string]$n.IPAddress } else { [string]$n }
                            if ($ip) { $ipList.Add($ip) }
                        }
                    } catch {}
                    if ($ipList.Count -gt 0) { $metadata['MDE_EffectiveIpAddresses'] = $ipList.ToArray() }
                }
                $devInfoMatches++
            }
        } elseif ($a.ENTRA_UserId) {
            # Identity engine -- Entra user. copy ALL ENTRA_* fields.
            # Shape-tolerant -- $a may be [hashtable] (in-process from Discovery)
            # OR [pscustomobject] (after JSON round-trip via staging blob).
            $metadata = @{ ENTRA_AssetType = 'User' }
            $allKeys = if ($a -is [System.Collections.IDictionary]) { @($a.Keys) } else { @($a.PSObject.Properties.Name) }
            foreach ($k in $allKeys) {
                if ($k -like 'ENTRA_*' -and $k -ne 'ENTRA_AssetType') {
                    $val = if ($a -is [System.Collections.IDictionary]) { $a[$k] } else { $a.$k }
                    $metadata[$k] = $val
                }
            }
        } elseif ($a.ENTRA_SPObjectId) {
            # Identity engine -- Entra service principal. Same all-ENTRA_* pass-through.
            $metadata = @{ ENTRA_AssetType = 'ServicePrincipal'; ENTRA_SPHint = $a.Hint }
            $allKeys = if ($a -is [System.Collections.IDictionary]) { @($a.Keys) } else { @($a.PSObject.Properties.Name) }
            foreach ($k in $allKeys) {
                if ($k -like 'ENTRA_*' -and $k -ne 'ENTRA_AssetType') {
                    $val = if ($a -is [System.Collections.IDictionary]) { $a[$k] } else { $a.$k }
                    $metadata[$k] = $val
                }
            }
        } elseif ($a.MDE_DeviceId) {
            # Endpoint engine -- MDE-discovered device. Pass through every MDE_* key
            # from Discovery (it already emits with the prefix). Same exclusion-list
            # pattern as the identity branches above. Endpoint row builder's key map
            # expects these prefixes (DeviceName -> MDE_DeviceName, etc.).
            $excludedTopLevel = @('AssetId','Source','Sources','Hint','Name','NormalizedKey')
            $metadata = @{ MDE_AssetType = 'Endpoint' }
            $allKeys = if ($a -is [System.Collections.IDictionary]) { @($a.Keys) } else { @($a.PSObject.Properties.Name) }
            foreach ($k in $allKeys) {
                if ($k -in $excludedTopLevel) { continue }
                if ($k -eq 'MDE_AssetType') { continue }
                $val = if ($a -is [System.Collections.IDictionary]) { $a[$k] } else { $a.$k }
                $metadata[$k] = $val
            }
        } elseif ($a.OS) {
            # Entra-device-only path (endpoint engine -- Entra-joined devices that don't have an MDE record).
            $metadata = @{
                ENTRA_OS          = $a.OS
                ENTRA_TrustType   = $a.TrustType
                ENTRA_ProfileType = $a.ProfileType
                ENTRA_Category    = $a.Category
            }
        } elseif ($RunContext.Engine -eq 'azure' -and ($a.AZ_PropertiesRawJson -or $a.AZ_PropertiesJson -or $a.AZ_ResourceId)) {
            # Unified azure path -- supports BOTH ARG and EG lookups. Discovery
            # merges EG-source + ARG-source rows for the same ResourceId, so an
            # asset commonly carries both:
            #   AZ_PropertiesRawJson  -- EG NodeProperties.rawData (security posture view, Microsoft-curated)
            #   AZ_PropertiesJson     -- ARG resource.properties     (canonical ARM resource state)
            # EG-only assets (rare for Azure runtime services not yet ingested by ARG)
            # and ARG-only assets (resources EG hasn't picked up yet) both work.
            $metadata = @{
                AZ_AssetType         = 'AzureResource'
                AZ_ResourceId        = $a.AZ_ResourceId
                AZ_NodeLabel         = $a.AZ_NodeLabel
                AZ_NodeId            = $a.AZ_NodeId
                AZ_Type              = $a.AZ_Type
                AZ_Kind              = $a.AZ_Kind
                AZ_Location          = $a.AZ_Location
                AZ_RG                = $a.AZ_RG
                AZ_Subscription      = $a.AZ_Subscription
                AZ_EnvTag            = $a.AZ_EnvTag
                AZ_OwnerTag          = $a.AZ_OwnerTag
                AZ_Hint              = $a.Hint
                AZ_PropertiesJson    = $a.AZ_PropertiesJson
                AZ_TagsJson          = $a.AZ_TagsJson
                AZ_IdentityJson      = $a.AZ_IdentityJson
                AZ_SkuJson           = $a.AZ_SkuJson
                AZ_PropertiesRawJson = $a.AZ_PropertiesRawJson
                EG_ExposureScore     = $a.EG_ExposureScore
                EG_Criticality       = $a.EG_Criticality
                EG_BusinessApp       = $a.EG_BusinessApp
                EG_HandlesSensitiveData = $a.EG_HandlesSensitiveData
            }
            # Properties JSON column: prefer EG rawData (richer security view); fall
            # back to ARG properties when EG hasn't ingested this resource type yet.
            if ($a.AZ_PropertiesRawJson)    { $metadata['Properties'] = $a.AZ_PropertiesRawJson }
            elseif ($a.AZ_PropertiesJson)   { $metadata['Properties'] = $a.AZ_PropertiesJson }
            if ($a.AZ_NodeId)               { $egDriven++ }
            if ($a.AZ_PropertiesJson)       { $argDriven++ }
        } elseif ($a.RG) {
            # ARG-only path (endpoint engine fallback). The asset wasn't found
            # in MDE or EG -- classic case: an Azure VM not yet onboarded to
            # Defender for Endpoint AND not yet ingested by Microsoft Security
            # Exposure Management. We still want it to flow through with enough
            # info for name-pattern posture rules + Hostname column to populate.
            #
            # Stamp MDE_DeviceName from the ARG resource Name so the
            # row-builder's 'Hostname -> MDE_DeviceName' key map produces a
            # value, and so existing name-pattern posture rules
            # (DomainControllerDetection / PAW_NamePattern / etc.) can match
            # against it. ARG_* fields preserved for cross-engine queries
            # against the parent Azure resource.
            $metadata = @{
                MDE_AssetType    = 'Endpoint'
                MDE_DeviceName   = $a.Name
                ARG_Name         = $a.Name
                ARG_RG           = $a.RG
                ARG_Subscription = $a.Subscription
                ARG_Source       = $a.Source
                ARG_Hint         = $a.Hint
            }
        } elseif ($RunContext.Engine -eq 'publicip') {
            # v2.2.349 -- pass-through every discovery-emitted field as metadata.
            # The schema-driven row builder (Build-SIPublicIpProfileRow.ps1) reads
            # IP_* / EG_* / SHODAN_* / CMDB_* / AssetEngine / AssetTier / cmdb*
            # from metadata via its keymap + flat-readback. Without this branch
            # publicip rows fall through to the Mock fallback below and lose all
            # discovery data (IpAddress 0% populated in the pre-ingest audit).
            $excludedTopLevel = @('AssetId','Source','Sources','Hint','Name','NormalizedKey','Raw')
            $metadata = @{}
            $allKeys = if ($a -is [System.Collections.IDictionary]) { @($a.Keys) } else { @($a.PSObject.Properties.Name) }
            foreach ($k in $allKeys) {
                if ($k -in $excludedTopLevel) { continue }
                $val = if ($a -is [System.Collections.IDictionary]) { $a[$k] } else { $a.$k }
                if ($null -ne $val) { $metadata[$k] = $val }
            }
        } else {
            # Mock fallback
            $metadata = @{
                MDE_OS         = 'WindowsServer2022'
                MDE_Owner      = 'corp\admin'
                MDE_Subnet     = '10.0.1.0/24'
                MDE_Hardware   = 'VMware-Virtual-Machine'
                MDE_MgmtState  = 'managed'
                MDE_Apps       = if ($a.Hint -eq 'exchange-server') { @('iis','exchange_server') } else { @('iis') }
            }
        }

        # ---- EG enrichment join -----------------------------
        # Try to find this asset in the EG map (built once per run above).
        # Silent miss when EG hasn't seen the asset yet -- master fields
        # already populated, EG fields stay null.
        if ($RunContext.Engine -eq 'identity' -and $identityEgMap.Count -gt 0) {
            $egHit = $null
            $tryKeys = @()
            if ($a.ENTRA_UserId)      { $tryKeys += ([string]$a.ENTRA_UserId).ToLowerInvariant() }
            if ($a.ENTRA_UPN)         { $tryKeys += ([string]$a.ENTRA_UPN).ToLowerInvariant() }
            if ($a.ENTRA_DisplayName) { $tryKeys += ([string]$a.ENTRA_DisplayName).ToLowerInvariant() }
            if ($a.ENTRA_SPObjectId)  { $tryKeys += ([string]$a.ENTRA_SPObjectId).ToLowerInvariant() }
            if ($a.Name)              { $tryKeys += ([string]$a.Name).ToLowerInvariant() }
            foreach ($k in $tryKeys) {
                if ($identityEgMap.ContainsKey($k)) { $egHit = $identityEgMap[$k]; break }
            }
            if ($egHit) {
                foreach ($k in $egHit.Keys) {
                    if ($null -ne $egHit[$k]) { $metadata[$k] = $egHit[$k] }
                }
                $egEnriched++
            }
        }
        elseif ($RunContext.Engine -eq 'azure' -and $azureEgMap.Count -gt 0) {
            # Resource short name match (EG NodeName == AZ_Name typically)
            $key = if ($a.Name) { ([string]$a.Name).ToLowerInvariant() } else { $null }
            if ($key -and $azureEgMap.ContainsKey($key)) {
                $egHit = $azureEgMap[$key]
                # Parse nodeProperties for the few high-value fields EG inferred
                $rawData = $null
                try { $props = ConvertFrom-Json $egHit.NodePropertiesJson -ErrorAction Stop; $rawData = if ($props.rawData) { $props.rawData } else { $props } } catch { }
                if ($rawData) {
                    $metadata['EG_NodeId']               = $egHit.NodeId
                    $metadata['EG_NodeLabel']            = $egHit.NodeLabel
                    if ($rawData.PSObject.Properties['exposureScore'])         { $metadata['EG_ExposureScore'] = [double]$rawData.exposureScore }
                    if ($rawData.PSObject.Properties['criticality'])           { $metadata['EG_Criticality']   = [string]$rawData.criticality }
                    if ($rawData.PSObject.Properties['businessApplicationName']) { $metadata['EG_BusinessApp']  = [string]$rawData.businessApplicationName }
                    if ($rawData.PSObject.Properties['handlesSensitiveData'])  { $metadata['EG_HandlesSensitiveData'] = [bool]$rawData.handlesSensitiveData }
                }
                $egEnriched++
            }
        }

        # ---- Skip gate ----------------------
        # Cadence is the SINGLE skip mechanism. Fingerprint comparison was
        # dropped in the bounded-staleness guarantee from the
        # tier-cadence map is enough; within-cadence config drift is
        # acceptable noise (T0 = 12h, T3 = 7d). Trade-off documented in
        # RELEASENOTES .
        #
        # Two reasons to PROCEED (either wins):
        #   1. ForceFullRun                 -- explicit override
        #   2. Cache miss                   -- first time we've seen this asset
        #   3. Cadence elapsed              -- last_seen_at + cadence(tier) < now
        # Otherwise SKIP.
        $cached = Get-SIFingerprintRecord -Context $RunContext.StorageContext `
                                           -TableName $RunContext.FingerprintTable `
                                           -AssetId $assetId

        $skipReason = $null
        if (-not $RunContext.ForceFullRun -and $null -ne $cached) {
            $cachedTier = if ($cached.PSObject.Properties['si_tier']) { [string]$cached.si_tier } else { $null }
            $cadence    = Get-SITierCadence -CadenceMap $RunContext.TierCadence -Tier $cachedTier
            $lastSeenStr = if ($cached.PSObject.Properties['last_seen_at']) { [string]$cached.last_seen_at } else { $null }
            $lastSeenAt = $null
            if (-not [string]::IsNullOrWhiteSpace($lastSeenStr)) {
                try {
                    $lastSeenAt = [datetime]::Parse($lastSeenStr, $null,
                                    [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor `
                                    [System.Globalization.DateTimeStyles]::AssumeUniversal)
                } catch { }
            }
            if ($null -ne $lastSeenAt -and (($lastSeenAt + $cadence) -gt [datetime]::UtcNow)) {
                $skipReason = ('cadence-not-due (tier={0} cached_at={1:yyyy-MM-ddTHH:mmZ})' -f $cachedTier, $lastSeenAt)
            }
        }

        if ($skipReason) {
            $skipped++
            $cadenceSkipped++
            continue
        }

        $proceed++
        [void]$proceedRecords.Add(@{
            AssetId  = $assetId
            Source   = $a.Source
            Sources  = $a.Sources
            Metadata = $metadata
            Hint     = $a.Hint
        })
    }

    if ($proceedRecords.Count -gt 0) {
        Write-SIStageShard -Context $RunContext.StorageContext `
                            -ContainerName $RunContext.StagingContainer `
                            -RunId $RunContext.RunId `
                            -Stage 'Collect' `
                            -ShardIndex 0 `
                            -ReplicaIndex ([int]$RunContext.ShardIndex) `
                            -Records $proceedRecords.ToArray() | Out-Null
    }

    $azureNote = if ($RunContext.Engine -eq 'azure') { (', EG-source: {0}, ARG-source: {1}' -f $egDriven, $argDriven) } else { '' }
    $endpointNote = if ($RunContext.Engine -eq 'endpoint' -and $egDriven -gt 0) { (', EG-source: {0}' -f $egDriven) } else { '' }
    $egNote    = if ($egEnriched -gt 0)               { (', EG-enriched: {0}' -f $egEnriched) } else { '' }

    [pscustomobject]@{
        Stage              = 'Collect'
        AssetsScanned      = $assets.Count
        Skipped            = $skipped
        SkippedCadence     = $cadenceSkipped
        Proceeding         = $proceed
        DeviceInfoHits     = $devInfoMatches
        EgEnriched         = $egEnriched
        Summary            = ('{0} scanned -- {1} cadence-skipped, {2} -> Enrich (DeviceInfo: {3}){4}{5}{6}' -f $assets.Count, $cadenceSkipped, $proceed, $devInfoMatches, $azureNote, $endpointNote, $egNote)
    }
}
