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

        # 🔴 A CONFIGURED SOURCE THAT RETURNS NOTHING IS A WARNING, NOT AN OBSERVATION.
        # Measured 2026-08-13, and this is exactly how it hurts: 'EndpointEG' returned 0 rows after
        # 180s (it returns 61 in ~12s on a healthy run -- a throttle or timeout, not an empty estate).
        # That source carries the last-seen ACTIVITY signal, so without it 51 assets fell outside the
        # 30-day active window and the OUTPUT stage dropped them. The run then reported
        # "asset filter: 109 -> 20 (dropped 89 inactive)" and finished GREEN.
        #
        # 🪤 The operator sees an inventory that shrank by 72% described as a correct filter decision.
        # Nothing in the run said a source had failed -- a 0 and a 61 printed at the same [INFO]
        # weight, one line apart from each other. This codebase already states the principle for CMDB
        # data ("wrong is worse than empty, BECAUSE EMPTY IS VISIBLE"); here empty was NOT visible,
        # because it was disguised as a filter result downstream.
        #
        # A source is only in $sources when it is configured and enabled, so zero is always worth
        # saying out loud. It is legitimately zero sometimes -- a tenant with no Azure Arc machines,
        # say -- which is why this warns and continues rather than failing the run. The elapsed time
        # is on the line because it is what separates "nothing to return" (fast) from "did not manage
        # to return it" (slow).
        if ($cnt -eq 0) {
            Write-SIWarn ("discovery source '{0}' returned NO rows after {1:n1}s. If this source normally returns data, treat every downstream count as suspect -- assets it uniquely contributes will be missing, and any that depend on it for their last-seen date can be dropped later as 'inactive' rather than reported as lost." -f $pair.Name, $elapsed)
        }

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

    # Helper: attribute this record's AadDeviceIds BY SOURCE -- "MDE=<id> | EG=<id> | ENTRA=<id>".
    # Which source disagrees is the whole remediation. Knowing an asset carries two ids tells the
    # operator nothing actionable; knowing EG and Entra agree while MDE says something else names
    # the record to go and fix. The previous message joined the ids with no attribution at all.
    function Get-SIRecordAadAttribution {
        param($r, [string]$ZeroGuid)
        $parts = New-Object System.Collections.Generic.List[string]
        foreach ($sub in $r.Raw) {
            foreach ($field in @('MDE_AadDeviceId','EG_AadDeviceId','ENTRA_AadDeviceId')) {
                $v = [string]$sub.$field
                if ([string]::IsNullOrWhiteSpace($v)) { continue }
                $vLc = $v.ToLowerInvariant()
                if ($vLc -eq $ZeroGuid) { continue }
                $pair = '{0}={1}' -f ($field -split '_')[0], $vLc
                if (-not $parts.Contains($pair)) { $parts.Add($pair) | Out-Null }
            }
        }
        if ($parts.Count -eq 0) { return '(none)' }
        return ($parts -join ' | ')
    }

    function Format-SIConflictList {
        <#
          Render the affected asset names for the summary WARN.

          WHY THIS EXISTS. Audit #27 promoted the conflict COUNTS out of -Verbose but deliberately
          left the per-record detail at DIAG, so the summary stayed readable. That decision was
          right and stands -- but it left the operator with "3 merge(s) refused" and no way to learn
          WHICH 3 without re-running the entire profiler with -Verbose. On 2026-08-12 a customer hit
          exactly that: the warning was seen, the assets were never identified, and the finding was
          carried across sessions un-chased because the only route to it was a full re-run against a
          live tenant mid-incident.

          Names are cheap and bounded -- refusals are rare by construction, since they need genuinely
          contradictory upstream data. So the summary names them; the DIAG lines keep the full
          per-source id detail and the remediation text.

          The bound is a LINE-LENGTH bound, not a data bound: the true total is always printed by the
          count line above, and the omitted names are all available at DIAG. It exists so one broken
          upstream sync cannot push every other warning off the operator's screen.
        #>
        param(
            [string[]]$Items,
            [int]$Max = 20
        )
        $all = @($Items)
        # 🪤 GUARD $Max < 1 BEFORE INDEXING. `$all[0..($Max-1)]` with $Max=0 becomes `$all[0..-1]`,
        # which PowerShell reads as "index 0, then index -1" -- the FIRST and LAST elements -- so
        # `-Max 0` on three items returned "a, c, and 3 more", wrong twice over. Unreachable today
        # (callers use the default), but a silent wrong answer from a bounds argument is the kind of
        # thing that only surfaces once someone passes a computed value.
        if ($Max -lt 1) { return ('{0} item(s) (list suppressed -- Max={1})' -f $all.Count, $Max) }
        if ($all.Count -le $Max) { return ($all -join ', ') }
        $shown = $all[0..($Max - 1)]
        return ('{0}, and {1} more (re-run with -Verbose to list every one)' -f ($shown -join ', '), ($all.Count - $Max))
    }

    function Get-SICorrelationCoverage {
        <#
          AUDIT #27 -- turn the second-pass merge counters into a coverage verdict.

          Pure on purpose: the arithmetic and BOTH warning thresholds are the part worth
          pinning in tests, and the stage around it cannot be executed offline. The stage
          only formats and prints what this returns.

          The headline number is CoveragePct, not Merged. An asset with no usable
          AadDeviceId can never be correlated across MDE/EG/Entra however good the merge
          logic is, so "merged N" on its own is not evidence that correlation works -- N
          could be small because the estate is clean, or because almost nothing carried a
          key. Only the ratio separates those two.
        #>
        param(
            [int]$Considered,
            [int]$Merged,
            [int]$NoKey,
            [int]$ConflictWithinRecord,
            [int]$ConflictSharedId,
            [int]$FinalCount
        )
        $conflicts = $ConflictWithinRecord + $ConflictSharedId
        $withKey   = $Considered - $NoKey
        if ($withKey -lt 0) { $withKey = 0 }
        $pct = if ($Considered -gt 0) { [math]::Round((100.0 * $withKey / $Considered), 1) } else { 0 }
        return [pscustomobject]@{
            Considered           = $Considered
            WithKey              = $withKey
            CoveragePct          = $pct
            Merged               = $Merged
            Conflicts            = $conflicts
            ConflictWithinRecord = $ConflictWithinRecord
            ConflictSharedId     = $ConflictSharedId
            NoKey                = $NoKey
            FinalCount           = $FinalCount
            HasConflicts         = ($conflicts -gt 0)
            # NOTE there is deliberately NO "coverage is poor" verdict here.
            # A first version warned below 50%. That was wrong, and the operator corrected it:
            # a large share of records CANNOT have an AadDeviceId by nature. An Azure resource --
            # a Key Vault, a storage account -- exists in Azure with no object in Entra ID at all,
            # so it has no device id to carry. A low percentage is therefore the NORMAL shape of a
            # mixed estate, not a fault, and warning on it would fire on every run and be learned
            # into background noise -- the exact failure this finding set out to fix.
        }
    }

    # AUDIT #27 -- these counters are the only evidence anyone has that cross-source
    # correlation is actually working, so they are reported on EVERY run (see the summary
    # at the end of this pass), not just under -Verbose.
    # The two refusal reasons are counted SEPARATELY on purpose: they are different
    # upstream data problems with different fixes.
    #   * within-record  -- MDE/EG/Entra disagree about one asset's AadDeviceId
    #   * shared-id      -- two differently-named assets claim the SAME AadDeviceId
    # ...and the NAMES behind those two counters, so the summary can say which assets are
    # affected without costing the operator a full -Verbose re-run of the whole profiler.
    $byAadId          = @{}
    $keysToDrop       = New-Object System.Collections.Generic.List[string]
    $aadMergeCount    = 0
    $noKeyCount       = 0
    $conflictWithinRecordCount = 0
    $conflictSharedIdCount     = 0
    $conflictWithinRecordNames = New-Object System.Collections.Generic.List[string]
    $conflictSharedIdNames     = New-Object System.Collections.Generic.List[string]
    $consideredCount  = $byKey.Count
    foreach ($entry in $byKey.GetEnumerator()) {
        $rec = $entry.Value

        # Build the union of all AadDeviceIds across this record's Raw subrecords.
        $allIds = New-Object System.Collections.Generic.HashSet[string]
        foreach ($r in $rec.Raw) {
            foreach ($id in (Get-SISubrecAadIds -r $r)) { [void]$allIds.Add($id) }
        }
        if ($allIds.Count -eq 0) {
            # No usable AadDeviceId at all (zero-GUID or absent) -- skip safely.
            # AUDIT #27: this IS counted now. It was previously left uncounted on the
            # grounds that the record "just lacks the merge key", but that is precisely
            # the number that says how much of the estate can never correlate at all.
            $noKeyCount++
            continue
        }
        if ($allIds.Count -gt 1) {
            # Conflicting AadDeviceIds within ONE record. Source data is unreliable
            # for this asset; refuse to use it as a merge key (would risk pulling
            # an unrelated device into the cluster). Log so the operator can fix
            # the upstream record (usually MDE has the wrong AadDeviceId).
            $conflictWithinRecordCount++
            $name = if ($rec.Name) { [string]$rec.Name } else { [string]$rec.AssetId }
            $conflictWithinRecordNames.Add(('"{0}"' -f $name)) | Out-Null
            Write-SIDiag ('discover: skipping AadDeviceId merge for "{0}" -- record has {1} conflicting AadDeviceIds across MDE/EG/Entra ({2}). Fix the upstream record.' -f $name, $allIds.Count, (Get-SIRecordAadAttribution -r $rec -ZeroGuid $zeroGuid))
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
                    $conflictSharedIdCount++
                    $conflictSharedIdNames.Add(('"{0}" vs "{1}"' -f $pName, $rName)) | Out-Null
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

    # AUDIT #27 -- report correlation coverage on EVERY run.
    #
    # Both of these lines used to be Write-SIDiag, which prints only under -Verbose. The
    # merge logic itself is sound (it lower-cases the key, skips the zero GUID, and refuses
    # to merge on contradictory evidence rather than asserting "same device") -- but every
    # OUTCOME of it was invisible. Correlation could fail across most of the estate and the
    # run still looked clean, which is exactly the shape of the operator's report that
    # correlation "isn't working as intended": it may be partly working, silently.
    #
    # Coverage is a data-quality metric, not a debug detail. The percentage is the headline
    # number: an asset with no usable AadDeviceId can NEVER be correlated across
    # MDE/EG/Entra, however good the merge logic is.
    $cov = Get-SICorrelationCoverage -Considered $consideredCount -Merged $aadMergeCount `
             -NoKey $noKeyCount -ConflictWithinRecord $conflictWithinRecordCount `
             -ConflictSharedId $conflictSharedIdCount -FinalCount $byKey.Count

    Write-SIInfo ('correlation (AadDeviceId): {0}/{1} record(s) carried a usable id ({2}%); merged {3}; refused {4}; {5} had no usable id (expected for records with no Entra object -- e.g. Azure resources such as Key Vaults or storage accounts); {6} asset(s) after merge.' -f `
        $cov.WithKey, $cov.Considered, $cov.CoveragePct, $cov.Merged, $cov.Conflicts, $cov.NoKey, $cov.FinalCount)

    if ($cov.HasConflicts) {
        # Deliberately a WARN, and deliberately split by cause -- the two have different
        # upstream fixes. These assets stay SPLIT across sources, so their tier and logon
        # assignments are computed from partial evidence.
        Write-SIWarn ('correlation: {0} merge(s) refused on conflicting AadDeviceIds -- {1} record(s) where MDE/EG/Entra disagree about one asset, {2} where two differently-named assets claim the same id. Those assets stay split across sources.' -f `
            $cov.Conflicts, $cov.ConflictWithinRecord, $cov.ConflictSharedId)

        # NAME them. The count alone is not actionable: knowing that 3 merges were refused tells the
        # operator nothing they can go and fix, and the only route to the identities was a -Verbose
        # re-run of the entire profiler -- which in a live tenant mid-incident nobody is going to do.
        # That is why this exact warning was seen by a customer on 2026-08-12 and then carried
        # across sessions un-chased. Names are bounded (refusals need contradictory upstream data),
        # so they belong in the summary; the full per-source id detail stays at DIAG.
        if ($conflictWithinRecordNames.Count -gt 0) {
            Write-SIWarn ('correlation: MDE/EG/Entra disagree about the AadDeviceId of {0}. Fix the upstream record (usually MDE); re-run with -Verbose to see which source claims which id.' -f `
                (Format-SIConflictList -Items $conflictWithinRecordNames))
        }
        if ($conflictSharedIdNames.Count -gt 0) {
            Write-SIWarn ('correlation: one AadDeviceId is claimed by two differently-named assets: {0}. Fix the upstream AadDeviceId mapping.' -f `
                (Format-SIConflictList -Items $conflictSharedIdNames))
        }
    }

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
