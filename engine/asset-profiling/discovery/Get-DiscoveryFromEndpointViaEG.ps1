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

# #412 one pull per source -- see shared\SI-FullAssetProperties.ps1. Nothing changes at the security level.
if (-not (Get-Command -Name Add-SIFullSourceObject -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-FullAssetProperties.ps1') }

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
| project NodeId, NodeName, NodeLabel, EntityIds, NodePropertiesJson = tostring(NodeProperties)
'@

    # The asset of ONE Exposure Graph endpoint node row -- shared by the whole-set loop below and the streaming path (#475).
    $buildEgDevice = {
        param($r)
        # #412 full asset metadata: the node this query already returned, kept whole (a no-op at the security level)
        # every level: the record capture needs each node (the full metadata keeps it only at the full level)
        if ($true) { Add-SIFullSourceObject -SourceSystem 'exposure-graph' -Object (ConvertTo-SIFullExposureGraphNode -Row $r) -AnchorColumn 'ExposureGraphNodeId' -AnchorValue ([string]$r.NodeId) }
        $rawData = $null
        if (-not [string]::IsNullOrWhiteSpace($r.NodePropertiesJson)) {
            try {
                $props = $r.NodePropertiesJson | ConvertFrom-Json -ErrorAction Stop
                $rawData = if ($props.rawData) { $props.rawData } else { $props }
            } catch { }
        }

        # The node's own identifiers (#206). Defender puts the device's id on the graph node (SenseDeviceId / DeviceInventoryId)
        # and the VM's ARM id -- the ONLY reliable bridge to the MDE record: this source names a device by FQDN while MDE
        # discovery keys on the short name, so a server with no Entra id (pimhybridwrk, measured 2026-10-02) never merged.
        $egMde = $null; $egArm = @()
        foreach ($eid in @($r.EntityIds)) {
            $o = $eid; if ($o -is [string]) { try { $o = $o | ConvertFrom-Json -ErrorAction Stop } catch { continue } }
            if ($null -eq $o) { continue }
            $ty = [string]$o.type; $iv = [string]$o.id
            if (-not $iv) { continue }
            if ($ty -eq 'SenseDeviceId' -or ($ty -eq 'DeviceInventoryId' -and -not $egMde)) { $egMde = $iv.ToLowerInvariant() }
            elseif ($ty -eq 'AzureResourceId') { $egArm += $iv }
        }
        $egArm = @($egArm | Sort-Object -Unique)

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
            EG_MdeDeviceId        = $egMde
            # one ARM id or none: a node listing two (an old VM of the same name in another subscription, measured on mgmt1)
            # cannot say which one this machine is -- the MDE record's own ARM id is used instead
            EG_AzureResourceId    = $(if ($egArm.Count -eq 1) { [string]$egArm[0] } else { $null })
            EG_DeviceCategory     = if ($rawData -and $rawData.PSObject.Properties['deviceCategory']) { [string]$rawData.deviceCategory } else { $null }
            EG_OS                 = if ($rawData -and $rawData.PSObject.Properties['osPlatform']) { [string]$rawData.osPlatform } else { $null }
            EG_OSVersion          = if ($rawData -and $rawData.PSObject.Properties['osVersion']) { [string]$rawData.osVersion } else { $null }
            EG_OnboardingStatus   = if ($rawData -and $rawData.PSObject.Properties['onboardingStatus']) { [string]$rawData.onboardingStatus } else { $null }
            EG_SensorHealth       = if ($rawData -and $rawData.PSObject.Properties['sensorHealthState']) { [string]$rawData.sensorHealthState } else { $null }
            # ISO 8601, never [string]$dt: on pwsh 7 the JSON parser already made this a [datetime], and
            # [string] renders it "MM/dd/yyyy", which a da-DK host later reads day-first (#123).
            EG_LastSeen           = if ($rawData -and $rawData.PSObject.Properties['lastSeen']) { $__ls = $rawData.lastSeen; if ($__ls -is [datetime]) { $__ls.ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture) } else { [string]$__ls } } else { $null }
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

    # #475 STREAMING (the discover phase of a run collected in parts): one hunting query for every node is cut off at the
    # hunting row limit on a large estate -- the nodes are read in BUCKETS of ~20,000 (hash of the node id), each sent
    # straight into the parts.
    $stream = $global:SI_DiscoverStream
    if ($stream) {
        # every hunting request through the SHARED retrying request (Invoke-SIHuntingGraphRequest, HuntingQuery.ps1: 429 / 5xx /
        # no answer waited out, an expired token renewed); a failure that stays is thrown, named
        if (-not (Get-Command -Name Invoke-SIHuntingGraphRequest -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\HuntingQuery.ps1') }
        if (-not (Get-Command -Name New-SIGraphJsonBody -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-GraphRest.ps1') }
        $egToken = $token
        $hunt = { param([string]$Query) $a = Invoke-SIHuntingGraphRequest -Query $Query -Token { param([bool]$Force) $egToken }; if (-not $a.Ok) { throw ([string]$a.Error) }; @($a.Rows) }
        # the bucket count needs the node COUNT. It is retried like every request; when it still fails there is NO fallback to
        # one unbucketed query (at 500,000 nodes it is cut at Microsoft's 100,000-row limit): the discovery is INCOMPLETE
        # this run, said by name, and its nodes are UNKNOWN -- never removed
        $total = $null; $countErr = ''
        try { $c = @(& $hunt ($kql.TrimEnd() + "`n| count")); $n = 0L; if ($c.Count -gt 0 -and [long]::TryParse([string]$c[0].Count, [ref]$n)) { $total = $n } else { $countErr = 'the count came back without a number' } } catch { $countErr = $_.Exception.Message }
        if ($null -eq $total) {
            $egIncomplete = ('EndpointEG: the node count could not be read ({0}) -- the Exposure Graph discovery is INCOMPLETE this run: no nodes were read (one query without buckets would be cut at Microsoft''s 100,000-row limit). Its nodes are UNKNOWN this run, not removed.' -f $countErr)
            if (Get-Command -Name Set-SIFullSourcePull -ErrorAction SilentlyContinue) { Set-SIFullSourcePull -SourceSystem 'exposure-graph' -Complete $false -ErrorText ('node count failed: ' + $countErr) }
            if ($global:SI_DiscoverStreamCounts) { $global:SI_DiscoverStreamCounts['EndpointEG'] = 0 }
            # THROWN (review 2, S5): Invoke-Discover counts this source as NOT COMPLETE -- the run ends success-partial, the CMDB never reads the snapshot as complete
            throw $egIncomplete
        }
        $buckets = [int][Math]::Max(1, [Math]::Ceiling($total / 20000.0))
        $taken = 0; $failed = 0
        for ($bk = 0; $bk -lt $buckets; $bk++) {
            $q = $kql; if ($buckets -gt 1) { $q = $kql.TrimEnd() + ("`n| where hash(NodeId, {0}) == {1}" -f $buckets, $bk) }
            try { $bucketRows = @(& $hunt $q) } catch { $failed++; Write-Warning ('EndpointEG: bucket {0} of {1} failed -- {2}. Its nodes are UNKNOWN this run, not removed.' -f ($bk + 1), $buckets, $_.Exception.Message); continue }
            $batch = New-Object System.Collections.Generic.List[object]; foreach ($r in $bucketRows) { $x = & $buildEgDevice $r; if ($x) { $batch.Add($x) } }
            $null = Add-SIDiscoverStreamAssets -Stream $stream -Assets $batch.ToArray(); $taken += $batch.Count; $bucketRows = $null; $batch = $null
        }
        Set-SIFullSourcePull -SourceSystem 'exposure-graph' -Complete ($failed -eq 0)
        if ($global:SI_DiscoverStreamCounts) { $global:SI_DiscoverStreamCounts['EndpointEG'] = $taken }
        Write-SIInfo ('   EndpointEG: {0} node(s) in {1} bucket(s) streamed into {2} part(s)' -f $taken, $buckets, $stream.Parts)
        return
    }

    # through the SHARED retrying hunting request (429 / 5xx / no answer waited out, an expired token renewed)
    if (-not (Get-Command -Name Invoke-SIHuntingGraphRequest -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\HuntingQuery.ps1') }
    if (-not (Get-Command -Name New-SIGraphJsonBody -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-GraphRest.ps1') }
    $egToken = $token
    $a = Invoke-SIHuntingGraphRequest -Query $kql -Token { param([bool]$Force) $egToken }
    if (-not $a.Ok) {
        Write-Warning ('Get-DiscoveryFromEndpointViaEG: query failed -- {0}' -f $a.Error)
        return @()
    }

    $rows = @($a.Rows)
    Write-SIInfo ("   EG endpoint discovery: {0} device nodes" -f $rows.Count)
    Set-SIFullSourcePull -SourceSystem 'exposure-graph' -Complete $true

    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'EgEndpointNodes' -ErrorAction SilentlyContinue
    foreach ($r in $rows) {
        $_i++
        try { Write-SIProgress -Label 'EgEndpointNodes' -Index $_i -Total $_total } catch { }
        & $buildEgDevice $r
    }
}
