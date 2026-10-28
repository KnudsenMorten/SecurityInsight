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

function Get-SIDiscoverySourceNotInTenant {
    <#
        PURE. #876 (a first run on a bare tenant): when a discovery source's failure says the PRODUCT it reads is not part of
        this tenant -- Microsoft Defender XDR's advanced hunting answers "Account is not provisioned"; Defender for Endpoint
        answers that the tenant is not onboarded / not licensed -- the product it names, else ''. That is "not in this
        tenant": nothing to collect from it, information, never a failure. A permission refusal, a throttle or a timeout is
        NOT matched (they stay failures: the source exists and could not be read).
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $t = [string]$Text
    if ($t -match '(?i)Account is not provisioned|advanced hunting is not provisioned') { return 'Microsoft Defender XDR (advanced hunting)' }
    if ($t -match '(?i)tenant (?:is )?not (?:onboarded|provisioned)|not onboarded to (?:Microsoft )?Defender|\bInvalidLicense\b|\bMissingLicense\b|no valid licen[cs]e for (?:Microsoft )?Defender') { return 'Microsoft Defender for Endpoint' }
    return ''
}

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
            $assets = @($assets | Select-Object -First $RunContext.AssetLimit)   # @(): one survivor must stay an ARRAY, not unwrap to a bare hashtable
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

    # #721 THE RECORDS STREAM (owner 2026-10-16: "same method across all cust ... like streaming no matter size"): the
    # producer's discover phase writes every captured record part to its local record stream and lets it go; the hand-over
    # reads the stream back (Save-SIRecordHandover). The phase decides it -- never the size of the tenant.
    if ($RunContext.PSObject.Properties['Phase'] -and [string]$RunContext.Phase -eq 'discover' -and (Get-Command -Name Start-SIRecordCaptureStream -ErrorAction SilentlyContinue)) {
        $null = Start-SIRecordCaptureStream
        Write-SIInfo 'records: streamed as they are captured (written, then let go) -- handed over to the parts from the stream'
    }

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
        # #497 the AD computer accounts the Exposure Graph knows -- records only (no profile asset): they join the hybrid
        # Entra device / the Defender device by the AD ids, or stand alone as the AD computer's own device CI
        . (Join-Path $discoveryDir 'Get-SIEgAdComputers.ps1')
        $sources = @(
            @{ Name = 'EndpointEG';    Fn = { Get-DiscoveryFromEndpointViaEG } },
            @{ Name = 'ARG';           Fn = { Get-DiscoveryFromARG } },
            @{ Name = 'ExposureGraph'; Fn = { Get-DiscoveryFromExposureGraph } },
            @{ Name = 'Entra';         Fn = { Get-DiscoveryFromEntra } },
            @{ Name = 'MDE';           Fn = { Get-DiscoveryFromMDE } },
            # RecordsOnly: it hands its nodes to the record capture and never returns profile rows -- its own line says how
            # many it read, or that they are UNKNOWN; "returned NO rows" would be a false alarm on every run
            @{ Name = 'AdComputersEG'; RecordsOnly = $true; Fn = { $adc = Invoke-SIEgAdComputerCapture; Write-SIInfo ('   ' + $adc.Text); @() } }
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

    # #475 STREAMING DISCOVERY (identity, azure, endpoint): in the discover phase of a run collected in parts, the part count comes from the
    # sources' counts BEFORE anything is read, and each page a source reads goes straight into its part. A count that
    # cannot be read keeps the whole-set path (said below).
    $global:SI_DiscoverStream = $null; $global:SI_DiscoverStreamCounts = $null
    $streamParts = 0
    if ($RunContext.Engine -in 'identity', 'azure', 'endpoint') {
        if (-not (Get-Command -Name New-SIDiscoverStream -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared\SI-DiscoverStream.ps1') }
        $streamFull = [bool]((Get-Command -Name Test-SIFullAssetPropertiesOn -ErrorAction SilentlyContinue) -and (Test-SIFullAssetPropertiesOn))
        $streamWant = Test-SIDiscoverStreamWanted -RunContext $RunContext -FullProperties $streamFull
        if ($streamWant.Stream) {
            # the engine's objects before anything is read: identity = users + service principals ($count); azure = the
            # larger of the Resource Graph and Exposure Graph counts (the two describe mostly the same resources, which merge)
            $streamObjects = $null; $streamWhat = ''
            try {
                if ($RunContext.Engine -eq 'identity') {
                    if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth/Get-SIGraphToken.ps1') }
                    $sc = Get-SIIdentityDiscoverCount -Token (Get-SIGraphToken -Resource Graph)
                    if ($null -ne $sc) { $streamObjects = $sc.Objects; $streamWhat = ('{0:N0} users + {1:N0} service principals' -f $sc.Users, $sc.ServicePrincipals) }
                } elseif ($RunContext.Engine -eq 'endpoint') {
                    # devices: the larger of Entra's device count and the Exposure Graph's endpoint nodes (Defender's machines
                    # are the same devices); either one is enough to decide the parts
                    if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth/Get-SIGraphToken.ps1') }
                    $gt = Get-SIGraphToken -Resource Graph
                    $entraN = Get-SIGraphObjectCount -Collection 'devices' -Token $gt
                    $egN = Get-SIHuntingCount -Token $gt -Query 'ExposureGraphNodes | where NodeLabel in ("device", "microsoft.compute/virtualmachines", "microsoft.hybridcompute/machines") | count'
                    if ($null -ne $entraN -or $null -ne $egN) {
                        $streamObjects = [Math]::Max([long]$(if ($null -ne $entraN) { $entraN } else { 0 }), [long]$(if ($null -ne $egN) { $egN } else { 0 }))
                        $streamWhat = ('{0} Entra devices, {1} Exposure Graph endpoint nodes' -f $(if ($null -ne $entraN) { '{0:N0}' -f $entraN } else { 'an unknown number of' }), $(if ($null -ne $egN) { '{0:N0}' -f $egN } else { 'an unknown number of' }))
                    }                } else {
                    $argN = Get-DiscoveryFromAzureResources -CountOnly
                    $egN = $null; try { $egN = Get-DiscoveryFromAzureViaEG -CountOnly } catch { $egN = $null }
                    if ($null -ne $argN) {
                        $streamObjects = [Math]::Max([long]$argN, [long]$(if ($null -ne $egN) { $egN } else { 0 }))
                        $streamWhat = ('{0:N0} Resource Graph resources, {1} Exposure Graph nodes' -f $argN, $(if ($null -ne $egN) { '{0:N0}' -f $egN } else { 'an unknown number of' }))
                    }
                }
            } catch { $streamObjects = $null }
            # THE TENANT'S SIZE FOR THE UPDATE'S JOB SIZING: the counts just read (this collection's own directory rights) are
            # recorded in the Pro database, where the updater reads them -- the updater itself has no directory read
            # (engine\_shared\SI-TenantSizeMark.ps1). Never fails the run.
            try {
                $__tsCounts = $null
                if ($RunContext.Engine -eq 'identity' -and $null -ne $sc) {
                    $__tsGroups = $null; try { $__tsGroups = Get-SIGraphObjectCount -Collection 'groups' -Token (Get-SIGraphToken -Resource Graph) } catch { $__tsGroups = $null }
                    $__tsCounts = @{ Users = $sc.Users; ServicePrincipals = $sc.ServicePrincipals; Groups = $__tsGroups }
                } elseif ($RunContext.Engine -eq 'endpoint' -and $null -ne $streamObjects) {
                    $__tsCounts = @{ Devices = $streamObjects }
                }
                if ($__tsCounts) {
                    if (-not (Get-Command -Name Invoke-SITenantSizeMarkSave -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-TenantSizeMark.ps1') }
                    $null = Invoke-SITenantSizeMarkSave -Counts $__tsCounts -Log { param($l) Write-SIInfo $l }
                }
            } catch { }
            if ($null -ne $streamObjects) {
                $streamParts = Get-SICollectPartCount -Objects $streamObjects
                $global:SI_DiscoverStream = New-SIDiscoverStream -RunContext $RunContext -Parts $streamParts -SourcePriority $sourcePriority -ReservedKeys $reservedKeys
                $global:SI_DiscoverStreamCounts = @{}
                Write-SIInfo ('discovery streams: {0} counted -> {1} part(s); each page goes straight into its part' -f $streamWhat, $streamParts)
            } else {
                Write-SIWarn 'discovery: the number of objects could not be read -- this run discovers the whole set in one process (it holds every object in memory until it is split).'
            }
        } elseif ($RunContext.PSObject.Properties['Phase'] -and [string]$RunContext.Phase -eq 'discover') {
            Write-SIInfo ('discovery: the whole set in this process -- {0}' -f $streamWant.Reason)
        }
    }
    $perSourceCounts = @{}
    $rawAssets       = New-Object System.Collections.ArrayList
    # review 2, S5: the sources that did NOT complete this run (threw, or said so -- the Exposure Graph's node count). The
    # stage's summary then says INCOMPLETE, so the run-health END is 'success-partial' and the CMDB / lifecycle never read
    # this snapshot as complete (absence is not remediation)
    $notComplete = New-Object System.Collections.Generic.List[string]

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
            # #702 / owner's trust rule: a source that threw is NOT "0 from this source" -- its pulls are marked not complete,
            # so nothing is read as removed from what it did not reach (absence is not remediation). Said plainly, with the reason.
            $srcErr = $_
            $srcWhy = [string]$srcErr.Exception.Message
            if ($srcWhy.Length -gt 600) { $srcWhy = $srcWhy.Substring(0, 600) + ' ...' }
            # #876: the product this source reads is not in this tenant (no licence for it) -- information, not a failure:
            # nothing to collect from it, and nothing it holds can be missed (it holds nothing here)
            $srcAbsent = Get-SIDiscoverySourceNotInTenant -Text ('{0} {1}' -f $srcWhy, $(if ($srcErr.ErrorDetails) { [string]$srcErr.ErrorDetails.Message } else { '' }))
            if ($srcAbsent) {
                Write-SIInfo ("discovery source '{0}': not in this tenant -- {1} is not part of this tenant's licences, so there is nothing to collect from it." -f $pair.Name, $srcAbsent)
                $perSourceCounts[$pair.Name] = 0
                continue
            }
            if (Get-Command -Name Set-SIRecordPullsIncomplete -ErrorAction SilentlyContinue) {
                $null = Set-SIRecordPullsIncomplete -Reason ("discovery source '{0}' failed" -f $pair.Name)
            }
            # OUT OF MEMORY stops the collection (customer B 2026-10-15: both identity sources threw OutOfMemoryException and
            # were carried on with zero rows): the process can no longer be trusted, so the stream's parts written so far are
            # never handed to the workers and the collection stays on its last good one (#608). Any OTHER failed source keeps
            # the run going -- one optional source that fails (a licence the tenant lacks, a throttle) never blocks the rest.
            $oom = [bool]((Get-Command -Name Test-SIOutOfMemoryText -ErrorAction SilentlyContinue) -and (Test-SIOutOfMemoryText $srcErr))
            if ($oom) {
                Write-SIErr ("Discovery source '{0}' ran out of memory -- {1}. This collection is NOT COMPLETE: nothing is read as removed and the last good collection stays in use." -f $pair.Name, $srcWhy)
                $global:SI_DiscoverStream = $null; $global:SI_DiscoverStreamCounts = $null
                throw ("The discovery source '{0}' did not complete (si-col-0501: out of memory) -- this {1} collection is NOT COMPLETE and stays on its last good collection: {2}" -f $pair.Name, [string]$RunContext.Engine, $srcWhy)
            }
            Write-SIErr ("Discovery source '{0}' did not complete -- {1}. Its objects are NOT COMPLETE in this run: nothing from this source is read as removed." -f $pair.Name, $srcWhy)
            $notComplete.Add(("discovery source '{0}' did not complete ({1})" -f $pair.Name, $srcWhy))
            $sourceRows = @()
        }
        $cnt = ($sourceRows | Measure-Object).Count
        if ($global:SI_DiscoverStreamCounts -and $global:SI_DiscoverStreamCounts.ContainsKey($pair.Name)) { $cnt = [int]$global:SI_DiscoverStreamCounts[$pair.Name] }
        $perSourceCounts[$pair.Name] = $cnt
        $elapsed = ([datetime]::UtcNow - $srcStart).TotalSeconds
        if ($pair.RecordsOnly) { Write-SIInfo ("source '{0}' done -- records only, no profile rows  ({1,5:n1}s)" -f $pair.Name, $elapsed) }
        else { Write-SIInfo ("source '{0}' returned {1,5} rows  ({2,5:n1}s)" -f $pair.Name, $cnt, $elapsed) }

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
        # A records-only source (RecordsOnly: its objects go to the record capture, never to the profile) has no rows BY
        # DESIGN -- it says what it read, or that its objects are unknown, on its own line.
        if ($cnt -eq 0 -and -not $pair.RecordsOnly) {
            Write-SIWarn ("discovery source '{0}' returned NO rows after {1:n1}s. If this source normally returns data, treat every downstream count as suspect -- assets it uniquely contributes will be missing, and any that depend on it for their last-seen date can be dropped later as 'inactive' rather than reported as lost." -f $pair.Name, $elapsed)
        }

        foreach ($a in $sourceRows) { [void]$rawAssets.Add($a) }
    }

    # Intune managed devices -> records of provider 'intune' (encryption, primary user, ownership, check-in, the compliance
    # policies a device does not meet, its update ring). Endpoint only; switched in data-model/collection-scope; a read the
    # identity may not make is skipped and said; never fails the run. At the full level the same read feeds the asset metadata.
    $global:SIIntuneCapture = $null
    if ([string]$RunContext.Engine -eq 'endpoint') {
        try {
            if (-not (Get-Command -Name Invoke-SIIntuneCapture -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'discovery/Get-SIIntuneContext.ps1') }
            $null = Invoke-SIIntuneCapture -Log { param($l, $m) if ($l -eq 'WARN') { Write-SIWarn $m } else { Write-SIInfo $m } }
        } catch { Write-SIWarn ("Intune: the devices could not be read -- {0}. The profile is unaffected." -f $_.Exception.Message) }
    }

    # ENTRA CONTEXT (read only): what Entra knows about the identities / devices the sources just captured -- application
    # registrations, owners, managers, role scopes, Conditional Access, Identity Protection, access reviews ... -- one paged
    # read per kind for the whole tenant, added as parts to the captured records (discovery\Get-SIEntraContext.ps1). After
    # the sources, before the records are handed on; never fails the run.
    if ($RunContext.Engine -in 'identity', 'endpoint') {
        try {
            if (-not (Get-Command -Name Invoke-SIEntraContextCapture -ErrorAction SilentlyContinue)) { . (Join-Path $discoveryDir 'Get-SIEntraContext.ps1') }
            if ($RunContext.Engine -eq 'identity') { $null = Invoke-SIEntraContextCapture }
            else { $null = Invoke-SIEntraDeviceOwnerCapture }
        } catch { Write-SIWarn ('identity context: not added -- {0}. The discovery is unaffected.' -f $_.Exception.Message) }
    }

    # #412 full asset metadata: the sources no security record reads (Intune devices for the endpoint profiler, AD computer
    # objects for the identity profiler) are read here, once, and only at the full level -- they add nothing to the records
    # above. The Pro publisher provides the pulls; at the security level, and in the Community copy, nothing happens.
    if ((Get-Command -Name Test-SIFullAssetPropertiesOn -ErrorAction SilentlyContinue) -and (Test-SIFullAssetPropertiesOn) -and
        (Get-Command -Name Invoke-SIAssetPropertiesExtraPulls -ErrorAction SilentlyContinue)) {
        try { Invoke-SIAssetPropertiesExtraPulls -Engine ([string]$RunContext.Engine) }
        catch { Write-SIWarn ("full asset metadata: the extra sources could not be read -- {0}. The profile is unaffected." -f $_.Exception.Message) }
    }
    if ($global:SI_DiscoverStream) {
        # #721: every source has read -- the Exposure Graph identity index (read only by the two identity sources; one entry
        # per Entra-linked node, ~1.5 GB at the large ring-2 tenant) is let go BEFORE the parts are routed and merged, not
        # after Discover (Invoke-SIEngineRun): it was the largest thing held through the route, the measured peak
        if ((Get-Variable -Name _SICache -Scope Script -ErrorAction SilentlyContinue) -and $script:_SICache -is [hashtable] -and $script:_SICache.ContainsKey('EgIdentitiesMap')) {
            if (Get-Command -Name Remove-SIDiskLookup -ErrorAction SilentlyContinue) { Remove-SIDiskLookup $script:_SICache['EgIdentitiesMap'] }   # #726: its file goes too
            $script:_SICache.Remove('EgIdentitiesMap')
            [System.GC]::Collect()
            Write-SIInfo '[perms] EG identity nodes: released before the parts are routed'
        }
        $streamDone = Complete-SIDiscoverStream -Stream $global:SI_DiscoverStream
        $global:SI_DiscoverStream = $null; $global:SI_DiscoverStreamCounts = $null
        if ($global:SI_CollectRunInfo) { $global:SI_CollectRunInfo.Parts = $streamDone.Parts }
        $perSourceSummary = ($perSourceCounts.GetEnumerator() | ForEach-Object { '{0}:{1}' -f $_.Key, $_.Value }) -join ' '
        Write-SIInfo ('{0} object(s) from {1} source row(s) written into {2} part(s) for the workers, streamed and merged per part ({3} chunk(s); the largest group of linked rows: {4}{5})' -f $streamDone.Written, $streamDone.RawRows, $streamDone.Parts, $streamDone.Chunks, $streamDone.LargestGroup, $(if ($streamDone.EmptyParts) { (', {0} part(s) empty' -f $streamDone.EmptyParts) } else { '' }))
        return [pscustomobject]@{
            Stage           = 'Discover'
            AssetCount      = $streamDone.Written
            ShardCount      = $streamDone.Chunks
            PerSourceCounts = $perSourceCounts
            Summary         = ('{0}{1} assets in {2} part(s), streamed -- {3}' -f $(if ($notComplete.Count) { 'INCOMPLETE -- {0} -- ' -f ($notComplete -join ' | ') } else { '' }), $streamDone.Written, $streamDone.Parts, $perSourceSummary)
        }
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
    # ($sourcePriority and $reservedKeys are set before the sources run -- a streaming source merges with them, #475)
    $byKey = Merge-SIDiscoveredAssets -RawAssets $rawAssets.ToArray() -SourcePriority $sourcePriority -ReservedKeys $reservedKeys

    # In ORDINAL key order (#348), so the staged shards hold the same assets in the same order on every run.
    $assets = @((Get-SIOrdinalSortedEntries -Table $byKey) | ForEach-Object { $_.Value })

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
        # @(): a replica that keeps exactly ONE asset got a bare hashtable here -- .Count became its KEY
        # count and slicing it produced nulls, so the real asset was lost (#122).
        $assets = @($assets)
        Write-SIInfo ("shard {0}/{1}: kept {2} of {3} assets" -f ($shardIndex+1), $shardCount, ($assets | Measure-Object).Count, $beforeShardCount)
    }

    if ($RunContext.AssetLimit -gt 0) {
        $assets = @($assets | Select-Object -First $RunContext.AssetLimit)   # @(): one survivor must stay an ARRAY, not unwrap to a bare hashtable
    }

    # bumped from 100 to 2000. Fewer larger blobs cut blob-op count
    # ~20x (and AzLogDcrIngestPS handles up to 1MB payloads, so 2000 small JSONL
    # records fit comfortably). Container parallelism still works because each
    # replica only writes its own slice (sliced upstream by hash mod ShardCount).
    $shardSize = 2000
    $shards    = @{}
    $partsWritten = 0
    if ($RunContext.PSObject.Properties['Phase'] -and [string]$RunContext.Phase -eq 'discover') {
        # #475 -- the PRODUCER: every object goes into its PART (a stable hash of its key -- SI-CollectParts.ps1), the part
        # count decided by what was found; a part's objects are written under replica-<part>, where the part's worker reads.
        $partsWritten = Write-SIDiscoverParts -RunContext $RunContext -Assets @($assets) -ShardSize $shardSize
        if ($global:SI_CollectRunInfo) { $global:SI_CollectRunInfo.Parts = $partsWritten }
        Write-SIInfo ('{0} object(s) written into {1} part(s) for the workers' -f $assets.Count, $partsWritten)
    } else {
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
    }

    $perSourceSummary = ($perSourceCounts.GetEnumerator() | ForEach-Object { '{0}:{1}' -f $_.Key, $_.Value }) -join ' '

    [pscustomobject]@{
        Stage           = 'Discover'
        AssetCount      = $assets.Count
        ShardCount      = $shards.Count
        PerSourceCounts = $perSourceCounts
        Summary         = ('{0}{1} assets in {2} shard(s) -- {3}' -f $(if ($notComplete.Count) { 'INCOMPLETE -- {0} -- ' -f ($notComplete -join ' | ') } else { '' }), $assets.Count, $shards.Count, $perSourceSummary)
    }
}

function Write-SIDiscoverParts {
    <#
        #475 -- the PRODUCER's write: every discovered object into its PART (SI-CollectParts.ps1: a stable hash of its
        NormalizedKey; the part count from how many were found), in chunks of -ShardSize under replica-<part> of this run,
        where the part's worker reads (Invoke-Collect: Read-SIStageShards -ReplicaIndex <part>). Returns the part count.
    #>
    param([Parameter(Mandatory)]$RunContext, [AllowEmptyCollection()][object[]]$Assets = @(), [int]$ShardSize = 2000)
    if (-not (Get-Command -Name Get-SICollectPartIndex -ErrorAction SilentlyContinue)) {
        . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared\SI-CollectParts.ps1')
    }
    $parts = Get-SICollectPartCount -Objects $Assets.Count
    $byPart = @{}
    foreach ($a in $Assets) {
        $p = Get-SICollectPartIndex -Key ([string]$a.NormalizedKey) -Parts $parts
        if (-not $byPart.ContainsKey($p)) { $byPart[$p] = New-Object System.Collections.Generic.List[object] }
        $byPart[$p].Add($a)
    }
    foreach ($p in $byPart.Keys) {
        $list = $byPart[$p]
        for ($i = 0; $i -lt $list.Count; $i += $ShardSize) {
            $chunk = $list.GetRange($i, [Math]::Min($ShardSize, $list.Count - $i)).ToArray()
            Write-SIStageShard -Context $RunContext.StorageContext -ContainerName $RunContext.StagingContainer -RunId $RunContext.RunId `
                -Stage 'Discover' -ShardIndex ([int]($i / $ShardSize)) -ReplicaIndex $p -Records $chunk | Out-Null
        }
    }
    $parts
}

function Merge-SIDiscoverRecordsByMdeId {
    <#
        Merge discovered records that carry the same Defender device id -- MDE_DeviceId (Defender discovery) or
        EG_MdeDeviceId (the graph node's SenseDeviceId). In place on -ByKey; returns @{ Merged; Refused }.
        The id comes from Defender itself on both sides, so no name heuristic is applied; a record whose subrecords
        carry TWO different Defender ids is refused (never fused) and left as it is.
    #>
    param([Parameter(Mandatory)][hashtable]$ByKey, [Parameter(Mandatory)][string[]]$ReservedKeys, [Parameter(Mandatory)][hashtable]$SourcePriority)
    $byMde = @{}; $drop = New-Object System.Collections.Generic.List[string]; $merged = 0; $refused = 0
    # ORDINAL key order (#348): the first record of an id becomes the primary, so the order must be a contract.
    $ordKeys = @($ByKey.Keys | ForEach-Object { [string]$_ })
    if ($ordKeys.Count -gt 1) { [Array]::Sort($ordKeys, [System.StringComparer]::Ordinal) }
    foreach ($ordKey in $ordKeys) {
        $entry = New-Object System.Collections.DictionaryEntry($ordKey, $ByKey[$ordKey])
        $rec = $entry.Value
        $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($r in @($rec.Raw)) {
            foreach ($f in 'MDE_DeviceId', 'EG_MdeDeviceId') {
                if ($r -is [System.Collections.IDictionary] -and $r.Contains($f) -and -not [string]::IsNullOrWhiteSpace([string]$r[$f])) { [void]$ids.Add(([string]$r[$f]).Trim()) }
            }
        }
        if ($ids.Count -eq 0) { continue }
        if ($ids.Count -gt 1) { $refused++; continue }
        $id = @($ids)[0].ToLowerInvariant()
        if (-not $byMde.ContainsKey($id)) { $byMde[$id] = $entry.Key; continue }
        $primary = $ByKey[$byMde[$id]]
        foreach ($r in @($rec.Raw)) {
            if (-not ($primary.Sources -contains $r.Source)) { $primary.Sources += $r.Source }
            $primary.Raw += $r
            foreach ($field in $r.Keys) {
                if ($ReservedKeys -contains $field) { continue }
                if (-not $primary.ContainsKey($field) -or $null -eq $primary[$field]) { $primary[$field] = $r[$field] }
            }
        }
        $newPri = if ($SourcePriority.ContainsKey($rec.Source)) { $SourcePriority[$rec.Source] } else { 0 }
        $oldPri = if ($SourcePriority.ContainsKey($primary.Source)) { $SourcePriority[$primary.Source] } else { 0 }
        if ($newPri -gt $oldPri) {
            $primary.AssetId = $rec.AssetId; $primary.Source = $rec.Source; $primary.Hint = $rec.Hint
            # the name moves WITH the source (#124)
            if (-not [string]::IsNullOrWhiteSpace([string]$rec.Name)) { $primary.Name = $rec.Name }
        }
        $drop.Add($entry.Key); $merged++
    }
    foreach ($k in $drop) { [void]$ByKey.Remove($k) }
    [pscustomobject]@{ Merged = $merged; Refused = $refused }
}

function Merge-SIDiscoverRecordsByName {
    <#
        FIRST-PASS MERGE: one record per device NAME across all discovery sources (#348).
        PURE -- no I/O. Returns @{ ByKey; AmbiguousNames; SplitRecords }.

        WHY IT IS A FUNCTION AND WHY IT SORTS. Measured on ring 1 2026-10-05: 26 Exposure Graph device nodes
        share the name `DummyDeviceName` (devices excluded by tag, not onboarded), each with its own Defender
        device id. This merge keyed on the lowercased name, so all 26 collapsed into ONE asset, and the asset id,
        the name and every promoted field came from whichever row the hunting query happened to return FIRST.
        Advanced hunting does not guarantee row order, so the surviving device changed from run to run
        (10:58 kept `357483ba...`, 14:01 kept `acb6ef0b...`), and the changes view reported the same
        ENDPOINT-EXCLUDED-BY-TAG-001 finding as "no longer reported" on one run and "new" on the next. The other
        25 devices were never profiled at all -- an absence nobody could see.

        TWO RULES, BOTH INDEPENDENT OF ARRIVAL ORDER:
          1. The input is put in a STABLE order before anything is merged: source priority (highest first), then
             source name, then asset id, all compared ORDINALLY. Which record founds a bucket, which source wins
             a priority tie, and which value is promoted first are then the same on every run. Highest priority
             first is also what the field promotion below always intended ("the highest-priority source's data
             wins when sources conflict") and could not guarantee.
          2. A name shared by records carrying DIFFERENT Defender device ids (MDE_DeviceId / EG_MdeDeviceId) does
             not identify a device -- Defender itself says those are different machines. Those records are keyed
             by name + Defender id instead (a graph record without the id borrows it through its node id from the
             graph record that has both; failing that it is keyed by its own node id, then its own asset id).
             Every device is kept; none is chosen. No cap, nothing dropped -- the count is reported.
          A name with ONE Defender id (or none) merges exactly as before: the same machine seen as a device node
          and a VM node, or by Entra and Exposure Graph under one name, is still one asset.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RawAssets,
        [Parameter(Mandatory)][hashtable]$SourcePriority,
        [Parameter(Mandatory)][string[]]$ReservedKeys
    )

    $get = {
        param($r, [string]$f)
        if ($null -eq $r) { return $null }
        if ($r -is [System.Collections.IDictionary]) { if ($r.Contains($f)) { return $r[$f] } else { return $null } }
        $p = $r.PSObject.Properties[$f]; if ($p) { return $p.Value } else { return $null }
    }
    $nameKeyOf = {
        param($r)
        $k = [string](& $get $r 'NormalizedKey')
        if ([string]::IsNullOrWhiteSpace($k)) { $k = [string](& $get $r 'AssetId') }
        return $k
    }
    $defenderIdOf = {
        param($r)
        foreach ($f in 'MDE_DeviceId', 'EG_MdeDeviceId') {
            $v = [string](& $get $r $f)
            if (-not [string]::IsNullOrWhiteSpace($v)) { return $v.Trim().ToLowerInvariant() }
        }
        return $null
    }
    $nodeIdOf = {
        param($r)
        foreach ($f in 'EG_NodeId', 'EgNodeId') {
            $v = [string](& $get $r $f)
            if (-not [string]::IsNullOrWhiteSpace($v)) { return $v.Trim().ToLowerInvariant() }
        }
        return $null
    }

    # ---- 1. stable, ordinal order ----
    $n = @($RawAssets).Count
    $sortKeys = New-Object 'string[]' $n
    $items    = New-Object 'object[]' $n
    $sep = [string][char]0
    for ($i = 0; $i -lt $n; $i++) {
        $a = $RawAssets[$i]
        $src = [string](& $get $a 'Source')
        $pri = if ($src -and $SourcePriority.ContainsKey($src)) { [int]$SourcePriority[$src] } else { 0 }
        # priority DESCENDING as a fixed-width ascending key; the input index only separates exact duplicates
        # (the same source returning the same asset id twice), whose order cannot change what is merged.
        $sortKeys[$i] = ('{0:D6}' -f (500000 - $pri)) + $sep + $src + $sep + [string](& $get $a 'AssetId') + $sep + ('{0:D9}' -f $i)
        $items[$i] = $a
    }
    # The casts pick the non-generic (keys, items, IComparer) overload: without them PowerShell binds an overload
    # that leaves the items where they were (measured on pwsh 7 -- the merge then still followed arrival order).
    if ($n -gt 1) { [Array]::Sort([Array]$sortKeys, [Array]$items, [System.Collections.IComparer][System.StringComparer]::Ordinal) }

    # ---- 2. names that more than one Defender device carries ----
    $idsByName = @{}
    $nodeToDefender = @{}
    foreach ($a in $items) {
        $k = & $nameKeyOf $a
        $d = & $defenderIdOf $a
        if (-not $d) { continue }
        if (-not $idsByName.ContainsKey($k)) { $idsByName[$k] = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal) }
        [void]$idsByName[$k].Add($d)
        $node = & $nodeIdOf $a
        if ($node -and -not $nodeToDefender.ContainsKey($k + $sep + $node)) { $nodeToDefender[$k + $sep + $node] = $d }
    }
    $ambiguous = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($k in @($idsByName.Keys)) { if ($idsByName[$k].Count -gt 1) { [void]$ambiguous.Add([string]$k) } }

    # ---- 3. merge ----
    $byKey = @{}
    $split = 0
    foreach ($a in $items) {
        $k = & $nameKeyOf $a
        if ($ambiguous.Contains($k)) {
            $split++
            $d = & $defenderIdOf $a
            $node = & $nodeIdOf $a
            if (-not $d -and $node -and $nodeToDefender.ContainsKey($k + $sep + $node)) { $d = $nodeToDefender[$k + $sep + $node] }
            $k = if ($d) { '{0}|mde:{1}' -f $k, $d }
                 elseif ($node) { '{0}|eg:{1}' -f $k, $node }
                 else { '{0}|id:{1}' -f $k, ([string](& $get $a 'AssetId')).ToLowerInvariant() }
        }
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
            $newPri = if ($SourcePriority.ContainsKey([string]$a.Source)) { $SourcePriority[[string]$a.Source] } else { 0 }
            $oldPri = if ($SourcePriority.ContainsKey([string]$existing.Source)) { $SourcePriority[[string]$existing.Source] } else { 0 }
            if ($newPri -gt $oldPri) {
                $existing.AssetId = $a.AssetId
                $existing.Source  = $a.Source
                $existing.Hint    = $a.Hint
                # Name MOVES WITH THE SOURCE -- operator, 2026-08-28: "they must be consistent, so fx if eg node
                # name is used in assetname, then eg node id must be used in assetid." Before, Name was set by
                # whichever source arrived FIRST and never revisited, while AssetId/Source/Hint went to the
                # highest-priority source -- one pair, two sources. Fixed here once for all four engines.
                if (-not [string]::IsNullOrWhiteSpace([string]$a.Name)) { $existing.Name = $a.Name }
            }
        }

        # Promote source-specific fields onto the merged record: the FIRST non-null value wins, and because the
        # input is now in priority order, first means the highest-priority source's value.
        foreach ($field in @($a.Keys)) {
            if ($ReservedKeys -contains $field) { continue }
            if (-not $existing.ContainsKey($field) -or $null -eq $existing[$field]) {
                $existing[$field] = $a[$field]
            }
        }
    }

    $names = @($ambiguous | ForEach-Object { [string]$_ })
    if ($names.Count -gt 1) { [Array]::Sort($names, [System.StringComparer]::Ordinal) }
    return @{ ByKey = $byKey; AmbiguousNames = $names; SplitRecords = $split }
}

function Get-SIOrdinalSortedEntries {
    <# PURE. A hashtable's entries in ORDINAL key order -- hashtable enumeration order is not a contract (#348). #>
    param([Parameter(Mandatory)][AllowNull()][hashtable]$Table)
    if ($null -eq $Table -or $Table.Count -eq 0) { return ,@() }
    $keys = @($Table.Keys | ForEach-Object { [string]$_ })
    if ($keys.Count -gt 1) { [Array]::Sort($keys, [System.StringComparer]::Ordinal) }
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($k in $keys) { $out.Add((New-Object System.Collections.DictionaryEntry($k, $Table[$k]))) }
    return ,$out.ToArray()
}


function Merge-SIDiscoveredAssets {
    <#
        The ONE merge of discovered source rows into assets -- by name (the first pass, #348), by AadDeviceId (the second)
        and by the Defender device id (the third), with the correlation coverage said. Returns the merged records by key.
        One process runs it over every row; a run that streams discovery (#475) runs it over each part's rows, where every
        row of one device was routed (SI-DiscoverStream.ps1) -- the same code, so the same assets.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RawAssets, [Parameter(Mandatory)][hashtable]$SourcePriority, [Parameter(Mandatory)][string[]]$ReservedKeys)
    $sourcePriority = $SourcePriority; $reservedKeys = $ReservedKeys
    # First pass, by name -- in a STABLE order, and never fusing devices Defender says are different (#348).
    $nameMerge = Merge-SIDiscoverRecordsByName -RawAssets $RawAssets -SourcePriority $sourcePriority -ReservedKeys $reservedKeys
    $byKey = $nameMerge.ByKey
    Write-SIDiag ("first-pass merge by NormalizedKey: {0} raw -> {1} merged" -f @($RawAssets).Count, $byKey.Count)
    if (@($nameMerge.AmbiguousNames).Count -gt 0) {
        $_amb = @($nameMerge.AmbiguousNames)
        $_shown = if ($_amb.Count -gt 10) { (($_amb[0..9]) -join ', ') + (' (+{0} more)' -f ($_amb.Count - 10)) } else { $_amb -join ', ' }
        Write-SIInfo ('discovery: {0} device name(s) are carried by devices with DIFFERENT Defender ids ({1}); their {2} record(s) are kept apart by Defender id instead of being merged on the name -- every device is profiled.' -f $_amb.Count, $_shown, $nameMerge.SplitRecords)
    }

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
    # ORDINAL key order (#348): which record becomes the primary of an AadDeviceId group must not depend on
    # hashtable enumeration order.
    foreach ($entry in (Get-SIOrdinalSortedEntries -Table $byKey)) {
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
                    # The name moves WITH the source here too -- the same operator rule the first-pass
                    # merge above already follows. Without it this merge shipped one source's name beside
                    # another source's id (#124).
                    if (-not [string]::IsNullOrWhiteSpace([string]$rec.Name)) { $primary.Name = $rec.Name }
                }
                $keysToDrop.Add($entry.Key) | Out-Null
                $aadMergeCount++
            }
        } else {
            $byAadId[$aadIdLc] = $rec
        }
    }
    foreach ($k in $keysToDrop) { [void]$byKey.Remove($k) }

    # THIRD PASS -- by the Defender device id (#206). The graph node carries the MDE device id (SenseDeviceId) and MDE
    # discovery carries it as its own id, so the two records of one device meet here whatever each calls the machine.
    # Measured 2026-10-02: the PIM hybrid worker was two endpoint assets -- the MDE record (short name) and the graph
    # record (FQDN) never shared a name key, and a server has no Entra id for the second pass.
    $mdeMerge = Merge-SIDiscoverRecordsByMdeId -ByKey $byKey -ReservedKeys $reservedKeys -SourcePriority $sourcePriority
    Write-SIInfo ('correlation (Defender device id): merged {0}; refused {1} record(s) carrying two different Defender ids; {2} asset(s) after merge.' -f $mdeMerge.Merged, $mdeMerge.Refused, $byKey.Count)

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
    return $byKey
}