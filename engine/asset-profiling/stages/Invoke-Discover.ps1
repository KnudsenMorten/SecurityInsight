#Requires -Version 5.1
<#
    Discover stage.

    Multi-source dispatcher. For the endpoint engine, unions discovery
    results from every authoritative source and dedupes by NormalizedKey
    (lowercased device name). Sources for endpoint:

      * ARG            -- Azure VMs + ARC machines (control-plane truth)
      * ExposureGraph  -- everything Defender knows about (incl. unmanaged
                          devices found via network scanning)
      * Entra          -- registered/joined/hybrid devices (incl. BYOD)
      * MDE            -- onboarded Defender for Endpoint devices

    Sources are independent connectors under v2.2/engine/asset-profiling/discovery/Get-DiscoveryFrom*.ps1.
    Each returns the same hashtable shape so the dedup is mechanical.
    wires ARG only -- the other three are stubs that return 0
    with a warning. Pluggable architecture so adding a 5th source (Intune,
    Tenable, ServiceNow CMDB, ...) is one new file.
#>

function Invoke-SIDiscover {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$RunContext
    )

    if ($RunContext.StorageContext.Mode -eq 'Mock') {
        $assets = @(
            @{ AssetId='dev-srv-exch01'; Source='MDE'; Hint='exchange-server'  },
            @{ AssetId='dev-srv-iis01';  Source='MDE'; Hint='web-frontend'     },
            @{ AssetId='dev-srv-dc01';   Source='MDE'; Hint='domain-controller'},
            @{ AssetId='dev-wks-001';    Source='MDE'; Hint='workstation'      },
            @{ AssetId='dev-wks-002';    Source='MDE'; Hint='workstation'      }
        )
        if ($RunContext.AssetLimit -gt 0) {
            $assets = $assets | Select-Object -First $RunContext.AssetLimit
        }

        # bumped from 100 to 2000. Fewer larger blobs cut blob-op count
    # ~20x (and AzLogDcrIngestPS handles up to 1MB payloads, so 2000 small JSONL
    # records fit comfortably). Container parallelism still works because each
    # replica only writes its own slice (sliced upstream by hash mod ShardCount).
    $shardSize = 2000
        $shards    = @{}
        for ($i = 0; $i -lt $assets.Count; $i += $shardSize) {
            $shardIdx = [int]($i / $shardSize)
            $shards[$shardIdx] = @($assets[$i..([Math]::Min($i+$shardSize-1, $assets.Count-1))])
        }

        foreach ($k in $shards.Keys) {
            Write-SIStageShard -Context $RunContext.StorageContext `
                                -ContainerName $RunContext.StagingContainer `
                                -RunId $RunContext.RunId `
                                -Stage 'Discover' `
                                -ShardIndex $k `
                                -Records $shards[$k] | Out-Null
        }

        return [pscustomobject]@{
            Stage      = 'Discover'
            AssetCount = $assets.Count
            ShardCount = $shards.Count
            Summary    = ('{0} assets in {1} shard(s)' -f $assets.Count, $shards.Count)
        }
    }

    # ---- Real-Azure mode ----
    # discovery moved from v2.2/engine/discovery/ to v2.2/engine/asset-profiling/discovery/
    $discoveryDir = Join-Path (Split-Path -Parent $PSScriptRoot) 'discovery'

    # Engine -> connector list. Same dispatcher pattern, different sources
    # per engine. Adding a 4th engine = new branch + new connector files.
    if ($RunContext.Engine -eq 'endpoint') {
        # EG is the PRIMARY source. Pulls Microsoft's curated
        # device posture view (rawData includes onboardingStatus,
        # sensorHealth, antivirusEnabled, exposureScore, criticality,
        # businessApplicationName, etc.). Existing connectors stay as
        # supplements -- they catch devices EG hasn't ingested yet.
        . (Join-Path $discoveryDir 'Get-DiscoveryFromEndpointViaEG.ps1')
        . (Join-Path $discoveryDir 'Get-DiscoveryFromARG.ps1')
        . (Join-Path $discoveryDir 'Get-DiscoveryFromExposureGraph.ps1')
        . (Join-Path $discoveryDir 'Get-DiscoveryFromEntra.ps1')
        . (Join-Path $discoveryDir 'Get-DiscoveryFromMDE.ps1')
        $sources = @(
            @{ Name = 'EndpointEG';    Fn = { Get-DiscoveryFromEndpointViaEG } },
            @{ Name = 'ARG';           Fn = { Get-DiscoveryFromARG } },
            @{ Name = 'ExposureGraph'; Fn = { Get-DiscoveryFromExposureGraph } },
            @{ Name = 'Entra';         Fn = { Get-DiscoveryFromEntra } },
            @{ Name = 'MDE';           Fn = { Get-DiscoveryFromMDE } }
        )
    }
    elseif ($RunContext.Engine -eq 'identity') {
        . (Join-Path $discoveryDir 'Get-DiscoveryFromEntraUsers.ps1')
        . (Join-Path $discoveryDir 'Get-DiscoveryFromEntraServicePrincipals.ps1')
        $sources = @(
            @{ Name = 'EntraUsers';             Fn = { Get-DiscoveryFromEntraUsers } },
            @{ Name = 'EntraServicePrincipals'; Fn = { Get-DiscoveryFromEntraServicePrincipals } }
        )
    }
    elseif ($RunContext.Engine -eq 'azure') {
        # EG is the PRIMARY source. Microsoft's curated
        # microsoft.* node labels = the security-relevant Azure types
        # (~17 vs ARG's 600). Each EG node carries rawData verbatim --
        # the security posture view Microsoft has already done the work
        # of selecting. ARG stays as a backup for resources EG hasn't
        # ingested yet (rare; covers brand-new resources).
        . (Join-Path $discoveryDir 'Get-DiscoveryFromAzureViaEG.ps1')
        . (Join-Path $discoveryDir 'Get-DiscoveryFromAzureResources.ps1')
        $sources = @(
            @{ Name = 'ExposureGraph'; Fn = { Get-DiscoveryFromAzureViaEG } },
            @{ Name = 'AzureResources';     Fn = { Get-DiscoveryFromAzureResources } }
        )
    }
    elseif ($RunContext.Engine -eq 'publicip') {
        # External-attacker view of the customer's public IPs. Single connector
        # because IP candidates from ARG + EG + customer-supplied extras are
        # merged INSIDE Get-DiscoveryFromShodan -- per-IP /host enrichment runs
        # against the deduped candidate set (one row per unique IP).
        . (Join-Path $discoveryDir 'Get-DiscoveryFromShodan.ps1')
        $sources = @(
            @{ Name = 'Shodan'; Fn = { Get-DiscoveryFromShodan -RunContext $RunContext } }
        )
    }
    else {
        throw "Real-Azure Discover for engine '$($RunContext.Engine)' is not implemented."
    }

    $perSourceCounts = @{}
    $rawAssets       = New-Object System.Collections.ArrayList

    # per-source progress lines. Without these the operator can't
    # tell which connector is slow / hung / 403'ing -- only the final summary
    # printed before. Now each source logs start + finish + row count + elapsed.
    # dropped the NoNewline + \r in-place progress -- helper's [INFO]
    # writes were appending mid-line and producing glued output ('- EntraUsers ...
    # [INFO] [perms] fetching ...'). New pattern: announce start on its own line,
    # let helpers write freely, summarize on completion.
    Write-SIStep ("sources: {0}" -f (($sources | ForEach-Object { $_.Name }) -join ', '))
    foreach ($pair in $sources) {
        Write-SIStep ("source '{0}' starting ..." -f $pair.Name)
        $srcStart = [datetime]::UtcNow
        try {
            $sourceRows = & $pair.Fn
        } catch {
            Write-SIErr ("Discovery source '{0}' threw -- {1}. Continuing with 0 from this source." -f $pair.Name, $_.Exception.Message)
            $sourceRows = @()
        }
        $cnt = ($sourceRows | Measure-Object).Count
        $perSourceCounts[$pair.Name] = $cnt
        $elapsed = ([datetime]::UtcNow - $srcStart).TotalSeconds
        Write-SIInfo ("source '{0}' returned {1,5} rows  ({2,5:n1}s)" -f $pair.Name, $cnt, $elapsed)
        foreach ($a in $sourceRows) { [void]$rawAssets.Add($a) }
    }
    Write-Host ''
    Write-SIDiag ("{0} raw rows across {1} sources -- merging by NormalizedKey ..." -f $rawAssets.Count, $sources.Count)

    # Dedup by NormalizedKey. When the same device shows up in multiple
    # sources, merge into ONE record:
    #   * Canonical AssetId / Source / Hint come from the highest-priority
    #     source. As of , ENTRA IS THE MASTER -- many assets exist
    #     in Entra but not yet in EG/MDE (lazy ingestion), so Entra-master
    #     means new assets always carry authoritative directory identity.
    #     EG / MDE / ARG fields still flow through as enrichment.
    #   * Source-specific fields (EgNodeId, EntraId, MdeId, OS, RG, ...)
    #     are PROMOTED to the top of the merged record so downstream
    #     stages can read $a.EgNodeId without spelunking into Raw.
    #   * Sources accumulates the full list (e.g. @('AzureVM','EntraDevice')).
    # ExposureGraph + EndpointExposureGraph at the top
    # for canonical AssetId on dedupe -- they carry Microsoft's curated
    # rawData (the security view). Entra still wins WITHIN the device
    # set when both EG and Entra have the same device (master vs
    # enrichment, ). Azure resources only appear via EG OR ARG;
    # EG wins when both have it.
    # azure EG source renamed from 'AzureExposureGraph' to
    # 'ExposureGraph' -- one unified label across all engines (matches the
    # existing endpoint usage). Single sourcePriority entry shared across
    # engines; bumped to 5 (was 3) so EG wins over flatter sources everywhere.
    $sourcePriority = @{
        'ExposureGraph'         = 5
        'EndpointExposureGraph' = 5
        'EntraDevice'           = 4
        'MDEDevice'             = 2
        'AzureVM'               = 1
        'ARCMachine'            = 1
        'AzureResource'         = 1
    }
    $reservedKeys   = @('AssetId','Source','Hint','Name','NormalizedKey','Sources','Raw')
    $byKey = @{}
    foreach ($a in $rawAssets) {
        $k = $a.NormalizedKey
        if ([string]::IsNullOrWhiteSpace($k)) { $k = $a.AssetId }
        if (-not $byKey.ContainsKey($k)) {
            $byKey[$k] = @{
                AssetId       = $a.AssetId
                Source        = $a.Source
                Hint          = $a.Hint
                Name          = $a.Name
                NormalizedKey = $k
                Sources       = @($a.Source)
                Raw           = @($a)
            }
            $existing = $byKey[$k]
        } else {
            $existing = $byKey[$k]
            if (-not ($existing.Sources -contains $a.Source)) { $existing.Sources += $a.Source }
            $existing.Raw += $a
            $newPri = if ($sourcePriority.ContainsKey($a.Source)) { $sourcePriority[$a.Source] } else { 0 }
            $oldPri = if ($sourcePriority.ContainsKey($existing.Source)) { $sourcePriority[$existing.Source] } else { 0 }
            if ($newPri -gt $oldPri) {
                $existing.AssetId = $a.AssetId
                $existing.Source  = $a.Source
                $existing.Hint    = $a.Hint
            }
        }

        # Promote source-specific fields onto the merged record. Preserve
        # the FIRST non-null value seen so the highest-priority source's
        # data wins when sources conflict (priority order is the iteration
        # order if you sort rawAssets by priority -- not guaranteed, so
        # just preserve the first hit and rely on source priority for the
        # canonical AssetId/Source/Hint above).
        foreach ($field in $a.Keys) {
            if ($reservedKeys -contains $field) { continue }
            if (-not $existing.ContainsKey($field) -or $null -eq $existing[$field]) {
                $existing[$field] = $a[$field]
            }
        }
    }
    Write-SIDiag ("first-pass merge by NormalizedKey: {0} raw -> {1} merged" -f $rawAssets.Count, $byKey.Count)

    # SECOND-PASS merge by AadDeviceId. NormalizedKey-based merge
    # (above) handles devices whose name matches across sources -- the common
    # case. But MDE may return computerDnsName="strv-mok-dt-03.contoso.local"
    # while EG returns deviceName="strv-mok-dt-03" and Entra returns
    # displayName="STRV-MOK-DT-03" -- 3 different NormalizedKeys -> 3 separate
    # merged records for the same physical device. AadDeviceId is the AAD
    # device GUID, stable across MDE / EG / Entra for any AAD-joined device.
    # All 3 sources expose it. Iterate merged records, group by AadDeviceId,
    # collapse duplicates by folding their Raw[] + Sources[] into the first
    # one and dropping the rest.
    # Sentinel "no AAD join" GUID Windows / MDE / EG emit on devices that
    # aren't Entra-joined. Treating it as a real key collapses every workgroup
    # / un-joined device into one super-record.
    $zeroGuid = '00000000-0000-0000-0000-000000000000'

    # Helper: extract the AadDeviceId set from one Raw subrecord. We collect
    # ALL three (MDE / EG / ENTRA) instead of break-on-first because if a
    # record has MDE_AadDeviceId=X and EG_AadDeviceId=Y, the source has a
    # data-quality issue and we should NOT merge on either -- collapsing
    # would assert "same device" on conflicting evidence.
    function Get-SISubrecAadIds {
        param($r)
        $ids = New-Object System.Collections.Generic.List[string]
        foreach ($field in @('MDE_AadDeviceId','EG_AadDeviceId','ENTRA_AadDeviceId')) {
            $v = [string]$r.$field
            if ([string]::IsNullOrWhiteSpace($v)) { continue }
            $vLc = $v.ToLowerInvariant()
            if ($vLc -eq $zeroGuid) { continue }
            if (-not $ids.Contains($vLc)) { $ids.Add($vLc) | Out-Null }
        }
        return ,$ids
    }

    $byAadId          = @{}
    $keysToDrop       = New-Object System.Collections.Generic.List[string]
    $aadMergeCount    = 0
    $zeroSkipCount    = 0
    $conflictSkipCount = 0
    foreach ($entry in $byKey.GetEnumerator()) {
        $rec = $entry.Value

        # Build the union of all AadDeviceIds across this record's Raw subrecords.
        $allIds = New-Object System.Collections.Generic.HashSet[string]
        foreach ($r in $rec.Raw) {
            foreach ($id in (Get-SISubrecAadIds -r $r)) { [void]$allIds.Add($id) }
        }
        if ($allIds.Count -eq 0) {
            # No usable AadDeviceId at all (zero-GUID or absent) -- skip safely.
            # Don't touch $zeroSkipCount; this record just lacks the merge key.
            continue
        }
        if ($allIds.Count -gt 1) {
            # Conflicting AadDeviceIds within ONE record. Source data is unreliable
            # for this asset; refuse to use it as a merge key (would risk pulling
            # an unrelated device into the cluster). Log so the operator can fix
            # the upstream record (usually MDE has the wrong AadDeviceId).
            $conflictSkipCount++
            $name = if ($rec.Name) { [string]$rec.Name } else { [string]$rec.AssetId }
            Write-SIDiag ('discover: skipping AadDeviceId merge for "{0}" -- record has {1} conflicting AadDeviceIds across MDE/EG/Entra ({2}). Fix the upstream record.' -f $name, $allIds.Count, (($allIds) -join ', '))
            continue
        }

        $aadIdLc = @($allIds)[0]
        if ($byAadId.ContainsKey($aadIdLc)) {
            $primary = $byAadId[$aadIdLc]
            if ($primary.NormalizedKey -ne $rec.NormalizedKey) {
                # Sanity check: when two records have wildly different names,
                # they're almost certainly two different physical devices that
                # share an AadDeviceId due to upstream data corruption (device
                # re-image without proper AAD cleanup, lab cloning, etc.).
                # REFUSE the merge -- keep them as separate records. Fixing the
                # upstream record is the right answer; merging here would silently
                # conflate the two and downstream tier/logon assignments would be
                # wrong for both.
                # Hostname-similarity heuristic: strip FQDN tail, compare first
                # 3 chars (case-insensitive). Catches HEIM-NEW-LT-02 vs strv-paw-
                # lt-01 without false-positiving on case-variants or short-vs-FQDN.
                $pName = if ($primary.Name) { [string]$primary.Name } else { [string]$primary.AssetId }
                $rName = if ($rec.Name)     { [string]$rec.Name }     else { [string]$rec.AssetId }
                $pNorm = ($pName -replace '\..*$','').ToLowerInvariant()
                $rNorm = ($rName -replace '\..*$','').ToLowerInvariant()
                if ($pNorm -ne $rNorm -and $pNorm.Length -ge 3 -and $rNorm.Length -ge 3 -and $pNorm.Substring(0,3) -ne $rNorm.Substring(0,3)) {
                    $conflictSkipCount++
                    Write-SIDiag ('discover: REFUSING AadDeviceId merge of {0} -- claimed by 2 records with very different names: "{1}" + "{2}". Keeping both as separate records. Fix the upstream AadDeviceId mapping.' -f $aadIdLc, $pName, $rName)
                    continue
                }
                foreach ($r in $rec.Raw) {
                    if (-not ($primary.Sources -contains $r.Source)) { $primary.Sources += $r.Source }
                    $primary.Raw += $r
                    # Promote source-specific fields onto the primary's merged record.
                    foreach ($field in $r.Keys) {
                        if ($reservedKeys -contains $field) { continue }
                        if (-not $primary.ContainsKey($field) -or $null -eq $primary[$field]) {
                            $primary[$field] = $r[$field]
                        }
                    }
                }
                # Pick the higher-priority source's canonical AssetId / Source / Hint.
                $newPri = if ($sourcePriority.ContainsKey($rec.Source)) { $sourcePriority[$rec.Source] } else { 0 }
                $oldPri = if ($sourcePriority.ContainsKey($primary.Source)) { $sourcePriority[$primary.Source] } else { 0 }
                if ($newPri -gt $oldPri) {
                    $primary.AssetId = $rec.AssetId
                    $primary.Source  = $rec.Source
                    $primary.Hint    = $rec.Hint
                }
                $keysToDrop.Add($entry.Key) | Out-Null
                $aadMergeCount++
            }
        } else {
            $byAadId[$aadIdLc] = $rec
        }
    }
    foreach ($k in $keysToDrop) { [void]$byKey.Remove($k) }
    if ($conflictSkipCount -gt 0) {
        Write-SIDiag ('second-pass merge: {0} record(s) skipped due to conflicting AadDeviceIds (see warnings above)' -f $conflictSkipCount)
    }
    Write-SIDiag ('second-pass merge by AadDeviceId: collapsed {0} duplicate record(s) -> {1} final' -f $aadMergeCount, $byKey.Count)

    $assets = @($byKey.Values)

    # Sharding -- when run with parallelism>1 (Container Apps Job), each
    # replica handles only its assigned slice. Default ShardCount=1 means
    # every asset belongs to the only replica (no filtering).
    $shardCount = if ($RunContext.ShardCount -gt 0) { [int]$RunContext.ShardCount } else { 1 }
    $shardIndex = if ($null -ne $RunContext.ShardIndex) { [int]$RunContext.ShardIndex } else { 0 }
    if ($shardCount -gt 1) {
        $beforeShardCount = $assets.Count
        $assets = $assets | Where-Object {
            # Stable hash from NormalizedKey -- 8 hex chars from sha256, mod ShardCount
            $bytes = [System.Text.Encoding]::UTF8.GetBytes(($_.NormalizedKey -as [string]))
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $h = ([System.BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').Substring(0,8)
            } finally { $sha.Dispose() }
            ([Convert]::ToInt64($h, 16) % $shardCount) -eq $shardIndex
        }
        Write-SIInfo ("shard {0}/{1}: kept {2} of {3} assets" -f ($shardIndex+1), $shardCount, ($assets | Measure-Object).Count, $beforeShardCount)
    }

    if ($RunContext.AssetLimit -gt 0) {
        $assets = $assets | Select-Object -First $RunContext.AssetLimit
    }

    # bumped from 100 to 2000. Fewer larger blobs cut blob-op count
    # ~20x (and AzLogDcrIngestPS handles up to 1MB payloads, so 2000 small JSONL
    # records fit comfortably). Container parallelism still works because each
    # replica only writes its own slice (sliced upstream by hash mod ShardCount).
    $shardSize = 2000
    $shards    = @{}
    for ($i = 0; $i -lt $assets.Count; $i += $shardSize) {
        $shardIdx = [int]($i / $shardSize)
        $shards[$shardIdx] = @($assets[$i..([Math]::Min($i+$shardSize-1, $assets.Count-1))])
    }

    foreach ($k in $shards.Keys) {
        Write-SIStageShard -Context $RunContext.StorageContext `
                            -ContainerName $RunContext.StagingContainer `
                            -RunId $RunContext.RunId `
                            -Stage 'Discover' `
                            -ShardIndex $k `
                            -ReplicaIndex ([int]$RunContext.ShardIndex) `
                            -Records $shards[$k] | Out-Null
    }

    $perSourceSummary = ($perSourceCounts.GetEnumerator() | ForEach-Object { '{0}:{1}' -f $_.Key, $_.Value }) -join ' '

    [pscustomobject]@{
        Stage           = 'Discover'
        AssetCount      = $assets.Count
        ShardCount      = $shards.Count
        PerSourceCounts = $perSourceCounts
        Summary         = ('{0} assets in {1} shard(s) -- {2}' -f $assets.Count, $shards.Count, $perSourceSummary)
    }
}
