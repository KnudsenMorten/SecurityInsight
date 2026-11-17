#Requires -Version 5.1
<#
    RuleIndexes.ps1

    Bulk-source index builders for the 4 detect.kind values that need
    external data (per ARCHITECTURE.md § 9 performance contract). Each
    builder runs ONCE per engine run and produces an in-memory index that
    RuleEval handlers consult O(1) per asset.

    Index store: $script:SIRuleIndexes (module-scope hashtable). Reset by
    Reset-SIRuleIndexes between engine runs.

    Index shape:

      $script:SIRuleIndexes = @{
          tvmSoftware  = @{ <deviceId-lower> = @( '<vendor>/<name>', ... ) }
          GroupMembership = @{ <userObjectId-or-sid> = @( 'group-name', ... ) }
          parentChain  = @{ <resourceId-lower>   = @( @{ tag='cmdbId'; value='1'; level='resourceGroup|subscription|managementGroup|resource'; from='<name>' }, ... ) }   (nearest first)
          kustoSets    = @{ <ruleId> = <Set[string] of matching EntityIds> }
          BuildStats   = @{ <kind> = @{ Built=<bool>; Rows=<int>; Ms=<int> } }
      }

    Honest scope -- implements the structure + entry points. The
    actual bulk-fetch implementations are scaffolded with the right shape
    but UNTESTED in tenant. Stage Profile wires this up
    later; no stage calls it today and no setting turns it on.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }
# the management-group hierarchy + tags (one walker for the engine: the parent-chain index and the profile row share it)
if (-not (Get-Command -Name Get-SIAzureManagementGroupTagLevels -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'AzureParentScopeCache.ps1') }

if (-not (Get-Variable -Name SIRuleIndexes -Scope Script -ErrorAction SilentlyContinue)) {
    $script:SIRuleIndexes = @{
        tvmSoftware = @{}
        GroupMembership = @{}
        parentChain = @{}
        kustoSets   = @{}
        BuildStats  = @{}
    }
}

function Reset-SIRuleIndexes {
    $script:SIRuleIndexes = @{
        tvmSoftware = @{}
        GroupMembership = @{}
        parentChain = @{}
        kustoSets   = @{}
        BuildStats  = @{}
    }
}

function Get-SIRuleIndex {
    param([Parameter(Mandatory)][string]$Name)
    if (-not $script:SIRuleIndexes.ContainsKey($Name)) { return $null }
    return $script:SIRuleIndexes[$Name]
}

# ----------------------------------------------------------------------------
# Bulk index builders -- one per kind that needs external data
# ----------------------------------------------------------------------------

function Build-SITvmSoftwareIndex {
    <#
        Bulk-fetch DeviceTvmSoftwareInventory once. Build map:
            <deviceId-lower> -> @( '<vendor>/<name>', ... )

        Used by: hasSoftwareInstalled handler.
    #>
    [CmdletBinding()]
    param([Parameter()]$RunContext)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $idx = @{}
    try {
        $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        . (Join-Path $siRoot 'engine\asset-profiling\shared\HuntingQuery.ps1')
        $kql = @'
DeviceTvmSoftwareInventory
| where isnotempty(SoftwareVendor) and isnotempty(SoftwareName)
| project DeviceId, SoftwareVendor, SoftwareName
| summarize Pairs = make_set(strcat(tolower(SoftwareVendor), '/', tolower(SoftwareName))) by DeviceId
'@
        $rows = @(Invoke-SIHuntingQuery -Query $kql -QueryEngine 'DefenderGraph' -ErrorAction Stop)
        foreach ($r in $rows) {
            $key = ([string]$r.DeviceId).ToLower()
            $idx[$key] = @($r.Pairs)
        }
        $script:SIRuleIndexes.tvmSoftware = $idx
        $script:SIRuleIndexes.BuildStats['tvmSoftware'] = @{ Built=$true; Rows=$idx.Count; Ms=$sw.ElapsedMilliseconds }
        Write-Verbose ('Build-SITvmSoftwareIndex: {0} devices in {1} ms' -f $idx.Count, $sw.ElapsedMilliseconds)
    } catch {
        Write-Warning ('Build-SITvmSoftwareIndex failed: {0}' -f $_.Exception.Message)
        $script:SIRuleIndexes.BuildStats['tvmSoftware'] = @{ Built=$false; Error=$_.Exception.Message }
    }
}

function Build-SIGroupMembershipIndex {
    <#
        Build map: <user-key> -> @( 'group-name', ... )

        Sources -- in priority order:
          1. Per-asset row's ENTRA_Groups field (populated by
             discovery/Get-DiscoveryFromEntraUsers.ps1)
          2. Stub: bulk Get-ADUser -Properties memberOf

        Used by: groupMembership handler.
        Asset row IS the per-asset cache, so this builder only seeds the
        map from existing fields rather than making a fresh call.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]$Assets,
        [Parameter()]$RunContext
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $idx = @{}

    # walk both top-level AND .Metadata bag (post-Classify records
    # carry ENTRA_*/AZ_*/MDE_* fields nested under .Metadata, not top-level --
    # same gotcha that bit Test-SIKind_hasAzureTagDirectOrParent in ).
    # Also broaden key candidates: identity discovery emits ENTRA_UserId, not
    # AccountObjectId; PrimaryEntityId is set later in row-builder, not at this
    # stage. Without these fixes the adGroups index was always EMPTY for identity
    # records -> groupMembership rules never fired -> users like Anne who're in
    # 'org-finance' stayed at the catch-all default tier instead of T2.
    # index renamed adGroups -> GroupMembership for clarity (the
    # rule kind is already 'groupMembership'; the legacy 'adGroups' name is a
    # holdover from the AD-only era).
    $resolveField = {
        param($asset, $name)
        if ($null -eq $asset) { return $null }
        # Top-level
        if ($asset -is [System.Collections.IDictionary]) {
            if ($asset.Contains($name)) { $v = $asset[$name]; if ($null -ne $v -and "$v" -ne '') { return $v } }
        } else {
            $p = $asset.PSObject.Properties[$name]
            if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne '') { return $p.Value }
        }
        # Metadata fallback
        $meta = $null
        if ($asset -is [System.Collections.IDictionary]) {
            if ($asset.Contains('Metadata')) { $meta = $asset['Metadata'] }
        } else {
            $mp = $asset.PSObject.Properties['Metadata']
            if ($mp) { $meta = $mp.Value }
        }
        if ($null -eq $meta) { return $null }
        if ($meta -is [System.Collections.IDictionary]) {
            if ($meta.Contains($name)) { $mv = $meta[$name]; if ($null -ne $mv -and "$mv" -ne '') { return $mv } }
        } else {
            $mp2 = $meta.PSObject.Properties[$name]
            if ($mp2 -and $null -ne $mp2.Value -and "$($mp2.Value)" -ne '') { return $mp2.Value }
        }
        return $null
    }

    try {
        if ($Assets) {
            foreach ($a in $Assets) {
                # only USERS can be in a group for tier classification.
                # SPs/MIs may technically have app-role assignments to groups but
                # the groupMembership rule kind is user-only -- filter them out
                # at index build time so the index is small (e.g. 70 vs 1582)
                # and matcher lookups don't waste cycles on principals that
                # will never match.
                $aidPrefix = [string](& $resolveField $a 'AssetId')
                if ($aidPrefix -and $aidPrefix -notmatch '^entra-user:') {
                    continue
                }

                # Resolve key -- broadened candidate list (ENTRA_UserId added).
                $key = $null
                foreach ($f in @('PrimaryEntityId','AccountObjectId','ENTRA_UserId','ENTRA_ObjectId')) {
                    $v = [string](& $resolveField $a $f)
                    if ($v) { $key = $v.ToLower(); break }
                }
                # Last-resort: derive from AssetId (e.g. 'entra-user:<guid>').
                if (-not $key) {
                    $aid = [string](& $resolveField $a 'AssetId')
                    if ($aid -match '^entra-user:(?<id>.+)$') { $key = $matches.id.ToLower() }
                }
                if (-not $key) { continue }

                # Resolve ENTRA_Groups -- Metadata fallback included.
                # ToLowerInvariant() (locale-safe) + ensure single-
                # string entries are still iterated as a 1-element collection
                # (post-staging-blob round-trip can hand back either shape).
                $groups = & $resolveField $a 'ENTRA_Groups'
                if (-not $groups) { $groups = & $resolveField $a 'Groups' }
                if ($groups) {
                    $idx[$key] = @(@($groups) | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ })
                }
            }
        }
        $script:SIRuleIndexes.GroupMembership = $idx
        $script:SIRuleIndexes.BuildStats['GroupMembership'] = @{ Built=$true; Rows=$idx.Count; Ms=$sw.ElapsedMilliseconds }
        Write-Verbose ('Build-SIGroupMembershipIndex: {0} identities seeded in {1} ms' -f $idx.Count, $sw.ElapsedMilliseconds)
    } catch {
        Write-Warning ('Build-SIGroupMembershipIndex failed: {0}' -f $_.Exception.Message)
        $script:SIRuleIndexes.BuildStats['GroupMembership'] = @{ Built=$false; Error=$_.Exception.Message }
    }
}

function Get-SIArgPaged {
    <# Search-AzGraph paginated wrapper. Search-AzGraph -First caps
       at 1000; large tenants need SkipToken pagination. Returns the FULL set
       across all pages -- no page cap (a large tenant is read whole); the
       loop ends when Resource Graph hands no further token, or hands the
       SAME token again (a service fault -- said, never looped on). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Query, [int]$PageSize = 1000)
    $out = New-Object System.Collections.ArrayList
    $skipToken = $null
    $pages = 0
    do {
        $params = @{ Query = $Query; First = $PageSize; ErrorAction = 'Stop' }
        if ($skipToken) { $params['SkipToken'] = $skipToken }
        $batch = Search-SIAzGraph @params
        if ($batch) { foreach ($row in $batch) { [void]$out.Add($row) } }
        $prevToken = $skipToken
        $skipToken = $null
        if ($batch -and ($batch.PSObject.Properties['SkipToken']) -and $batch.SkipToken) { $skipToken = [string]$batch.SkipToken }
        $pages++
        if ($skipToken -and $skipToken -eq $prevToken) {
            Write-Warning ("Get-SIArgPaged: Resource Graph handed the same page token twice after {0} page(s) ({1} rows) -- the read stops here and is INCOMPLETE." -f $pages, $out.Count)
            break
        }
    } while ($skipToken)
    return $out.ToArray()
}

function ConvertTo-SITagPairs {
    <# shape-tolerant tag enumerator. Search-AzGraph may return
       tags as a hashtable, a JObject (Newtonsoft), a PSCustomObject, or a
       JSON string -- depends on Az.ResourceGraph build + PS version. PS 5.1
       has no `ConvertFrom-Json -AsHashtable` (that's PS 6+); the legacy code
       silently dropped tags and downstream `$tags.Keys` indexing then threw
       'Index operation failed; the array index evaluated to null'. #>
    param($Tags)
    $out = New-Object System.Collections.ArrayList
    if ($null -eq $Tags) { return $out }
    if ($Tags -is [System.Collections.IDictionary]) {
        foreach ($k in $Tags.Keys) {
            if ($null -eq $k) { continue }
            [void]$out.Add([pscustomobject]@{ Key = [string]$k; Value = [string]$Tags[$k] })
        }
        return $out
    }
    if ($Tags -is [string]) {
        try {
            $parsed = $Tags | ConvertFrom-Json -ErrorAction Stop
            if ($parsed -and $parsed.PSObject -and $parsed.PSObject.Properties) {
                foreach ($p in $parsed.PSObject.Properties) {
                    [void]$out.Add([pscustomobject]@{ Key = [string]$p.Name; Value = [string]$p.Value })
                }
            }
        } catch {}
        return $out
    }
    if ($Tags.PSObject -and $Tags.PSObject.Properties) {
        foreach ($p in $Tags.PSObject.Properties) {
            [void]$out.Add([pscustomobject]@{ Key = [string]$p.Name; Value = [string]$p.Value })
        }
    }
    return $out
}

function Build-SIParentResourceChainIndex {
    <#
        ARG bulk-fetch: every Azure management group + subscription + resource group (+ optionally every RESOURCE) and
        their tags, TENANT-WIDE (every subscription the engine's identity can read; never only the install's own).
        Build map:
            <container-or-resource-id-lower> -> @( @{ tag='<key>'; value='<val>'; level='<resource|resourceGroup|subscription|managementGroup>'; from='<container name>' }, ... )
            ORDER = NEAREST FIRST: resource -> resource group -> subscription -> management groups (the subscription's
            own parent first, the root last). from: the resource group's / subscription's name, the management group's
            DISPLAY name; a resource's own tags carry none.

        Used by: the azure engine's record capture (SI-RecordCapture.ps1 Add-SIRecordPartsFromRuleIndexes -> parts
        parentTags / parentTagScopes: parent tags are DATA on the CI, so the azure engine builds this on EVERY run,
        whatever its rules say -- Build-SIRuleIndexes), and the rule kinds hasAzureTagDirectOrParent / hasTag.

        Each RG entry carries its subscription's entries (which carry the subscription's management-group entries),
        each resource entry its RG's -- so a single lookup gives the FULL chain, flattened, nearest first.

        One paged ARG read per level (management groups + the subscription->MG chain via AzureParentScopeCache.ps1,
        subscriptions, resource groups, and -- -IncludeResources, only a tag rule needs them -- resources); no
        per-resource call; no cap. A level whose read fails is SAID (a warning that names the level) and the other
        levels are still indexed -- never a silent empty.
    #>
    [CmdletBinding()]
    param([Parameter()]$RunContext,
          # every resource's OWN tags too (one more paged ARG read over every tagged resource): a tag RULE needs them
          # (a tag set on the resource itself); a record's own tags come with the record, so the record parts do not
          [switch]$IncludeResources)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $idx = @{}
    $levels = [ordered]@{ managementGroup = $true; subscription = $true; resourceGroup = $true }
    try {
        # ---- Management groups: the hierarchy + each MG's tags (AzureParentScopeCache.ps1 -- the one MG walker) ----
        # reset first: this run's hierarchy, never a previous run's (a container session runs several engines)
        $mgSubs = @()
        try {
            Reset-SIAzureParentScopeCache
            Initialize-SIAzureManagementGroupCache
            $mgErr = Get-SIAzureParentScopeReadError -Level 'managementGroup'
            if ($mgErr) { throw $mgErr }
            # assigned, never @(...): the function hands its list back as ONE value (@() would make it a list of one list)
            $mgSubs = Get-SIAzureManagementGroupSubscriptionIds
            if ($null -eq $mgSubs) { $mgSubs = @() }
        } catch {
            $levels['managementGroup'] = $false
            Write-Warning ('management group tags could not be read: {0} -- the subscription and resource group tags are still attached' -f $_.Exception.Message)
        }
        $mgEntries = {
            param([string]$SubId)
            $list = New-Object System.Collections.ArrayList
            if (-not $levels['managementGroup'] -or -not $SubId) { return , $list }
            $mgLevels = Get-SIAzureManagementGroupTagLevels -SubscriptionId $SubId     # assigned: one value, the list
            foreach ($mg in $mgLevels) {       # nearest first
                if ($null -eq $mg -or $null -eq $mg.Tags) { continue }
                foreach ($k in @($mg.Tags.Keys)) {
                    if ([string]::IsNullOrWhiteSpace([string]$k)) { continue }
                    [void]$list.Add(@{ tag = [string]$k; value = [string]$mg.Tags[$k]; level = 'managementGroup'; from = [string]$mg.DisplayName })
                }
            }
            return , $list
        }

        # ---- Subscriptions + their tags (then their management groups' tags) ----
        $subKql = @"
ResourceContainers
| where type =~ 'microsoft.resources/subscriptions'
| project subscriptionId, name, tags
| order by subscriptionId asc
"@
        $subs = @()
        try { $subs = @(Get-SIArgPaged -Query $subKql) }
        catch {
            $levels['subscription'] = $false
            Write-Warning ('subscription tags could not be read: {0} -- the resource group and management group tags are still attached' -f $_.Exception.Message)
        }
        foreach ($s in $subs) {
            if ($null -eq $s) { continue }
            $tagsArr = New-Object System.Collections.ArrayList
            foreach ($p in (ConvertTo-SITagPairs $s.tags)) {
                # 'from' = the container's name, so a CI can say which subscription a tag it inherits comes from
                [void]$tagsArr.Add(@{ tag = $p.Key; value = $p.Value; level = 'subscription'; from = [string]$s.name })
            }
            $subId = [string]$s.subscriptionId
            if (-not [string]::IsNullOrWhiteSpace($subId)) {
                foreach ($t in (& $mgEntries $subId)) { [void]$tagsArr.Add($t) }
                $idx[('/subscriptions/{0}' -f $subId).ToLower()] = $tagsArr.ToArray()
            }
        }
        # a subscription the management-group walk knows but the subscription read did not return (that read failed):
        # still its management groups' tags
        foreach ($sid in $mgSubs) {
            if ([string]::IsNullOrWhiteSpace([string]$sid)) { continue }
            $k = ('/subscriptions/' + [string]$sid).ToLower()
            if ($idx.ContainsKey($k)) { continue }
            $mgOnly = (& $mgEntries ([string]$sid)).ToArray()
            if ($mgOnly.Count -gt 0) { $idx[$k] = $mgOnly }
        }
        $subCount = $idx.Count

        # ---- RGs + their tags (then the subscription's entries: its own tags, then its management groups') ----
        $rgKql = @"
ResourceContainers
| where type =~ 'microsoft.resources/subscriptions/resourcegroups'
| project id, name, tags, subscriptionId
| order by id asc
"@
        $rgs = @()
        try { $rgs = @(Get-SIArgPaged -Query $rgKql) }
        catch {
            $levels['resourceGroup'] = $false
            Write-Warning ('resource group tags could not be read: {0} -- the subscription and management group tags are still attached' -f $_.Exception.Message)
        }
        foreach ($r in $rgs) {
            if ($null -eq $r) { continue }
            $tagsArr = New-Object System.Collections.ArrayList
            foreach ($p in (ConvertTo-SITagPairs $r.tags)) {
                [void]$tagsArr.Add(@{ tag = $p.Key; value = $p.Value; level = 'resourceGroup'; from = [string]$r.name })
            }
            $subId = [string]$r.subscriptionId
            if (-not [string]::IsNullOrWhiteSpace($subId)) {
                $subKey = ('/subscriptions/{0}' -f $subId).ToLower()
                if ($idx.ContainsKey($subKey)) {
                    foreach ($t in $idx[$subKey]) { [void]$tagsArr.Add($t) }
                }
            }
            $rid = [string]$r.id
            if (-not [string]::IsNullOrWhiteSpace($rid)) {
                $idx[$rid.ToLower()] = $tagsArr.ToArray()
            }
        }
        $rgCount = $idx.Count - $subCount

        # ---- Resources + their tags (inherit RG + sub + MG tags via parent lookup) -- a tag RULE's need only ----
        # bulk-fetch every resource's own tags. The single ARG query
        # is fast (one round-trip) and lets the handler match `kind:
        # hasAzureTagDirectOrParent` rules where the tag is set on the resource
        # itself (key vault, vm, storage, etc.) -- not just on its container.
        $resKql = @"
Resources
| where notnull(tags) and notempty(tags)
| project id, tags, subscriptionId, resourceGroup
| order by id asc
"@
        $resCount = 0
        if ($IncludeResources) {
            try {
                $resPage = @(Get-SIArgPaged -Query $resKql)
                foreach ($r in $resPage) {
                    if ($null -eq $r) { continue }
                    $tagsArr = New-Object System.Collections.ArrayList
                    foreach ($p in (ConvertTo-SITagPairs $r.tags)) {
                        [void]$tagsArr.Add(@{ tag = $p.Key; value = $p.Value; level = 'resource' })
                    }
                    # Inherit RG tags (which already include sub + MG tags from above passes)
                    $subId = [string]$r.subscriptionId
                    $rgName = [string]$r.resourceGroup
                    if (-not [string]::IsNullOrWhiteSpace($subId) -and -not [string]::IsNullOrWhiteSpace($rgName)) {
                        $rgKey = ('/subscriptions/{0}/resourcegroups/{1}' -f $subId, $rgName).ToLower()
                        if ($idx.ContainsKey($rgKey)) {
                            foreach ($t in $idx[$rgKey]) { [void]$tagsArr.Add($t) }
                        }
                    }
                    $rid = [string]$r.id
                    if (-not [string]::IsNullOrWhiteSpace($rid) -and $tagsArr.Count -gt 0) {
                        $idx[$rid.ToLower()] = $tagsArr.ToArray()
                        $resCount++
                    }
                }
            } catch {
                Write-Warning ('resource tags could not be read (the resource group, subscription and management group tags are still indexed): {0}' -f $_.Exception.Message)
            }
        }

        $script:SIRuleIndexes.parentChain = $idx
        $mgCount = 0
        if ($levels['managementGroup']) { try { $mgCount = [int](Get-SIAzureParentScopeStats).Mgs } catch { $mgCount = 0 } }
        $subRead = @($subs | Where-Object { $null -ne $_ }).Count; $rgRead = @($rgs | Where-Object { $null -ne $_ }).Count
        $script:SIRuleIndexes.BuildStats['parentChain'] = @{ Built=$true; Rows=$idx.Count; Ms=$sw.ElapsedMilliseconds; Levels=$levels
                                                              ManagementGroups=$mgCount; Subscriptions=$subRead; ResourceGroups=$rgRead }
        # ONE line per collection, so a live run proves the read without a database read
        $line = 'inherited tags: {0} management group(s), {1} subscription(s), {2} resource group(s) read (tenant-wide)' -f $mgCount, $subRead, $rgRead
        if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $line } else { Write-Host ('[INFO] ' + $line) }
        Write-Verbose ('Build-SIParentResourceChainIndex: subs={0} rgs={1} resources={2} total={3} mg-read={4} in {5} ms' -f $subCount, $rgCount, $resCount, $idx.Count, $levels['managementGroup'], $sw.ElapsedMilliseconds)
    } catch {
        Write-Warning ('Build-SIParentResourceChainIndex failed: {0}' -f $_.Exception.Message)
        $script:SIRuleIndexes.BuildStats['parentChain'] = @{ Built=$false; Error=$_.Exception.Message }
    }
}

function Save-SIParentChainForParts {
    <#
        THE PRODUCER of an azure run collected in parts (#1089, Invoke-Discover's discover phase): the parent chain is read
        ONCE for the whole collection (Build-SIParentResourceChainIndex: tenant-wide, one paged read per level) and handed
        over in the state store beside the records (SI-CollectParts.ps1 Save-SIParentChainHandover) -- the process that
        merges the records attaches it to every azure record (Publish-SIRecordHandover). Live 3.0.35: the workers held none
        of discovery's records and the merge had no index, so not one record of a run in parts carried an inherited tag.
        Never throws: a failure is SAID (the merge then says the records carry no inherited tags). Returns the entries kept.
        -Store (tests): the state store; default = the install's (New-SICollectBlobStore).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Engine, [Parameter(Mandatory)][string]$RunId, $Store, $RunContext)
    try {
        if (-not (Get-Command -Name Save-SIParentChainHandover -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-CollectParts.ps1') }
        Reset-SIRuleIndexes
        Build-SIParentResourceChainIndex -RunContext $RunContext
        $st = $script:SIRuleIndexes.BuildStats['parentChain']
        if (-not ($st -and $st.Built)) { throw ('the parent chain was not read: {0}' -f $(if ($st) { [string]$st.Error } else { 'not built' })) }
        if ($null -eq $Store) { $Store = New-SICollectBlobStore -Account ([string]$global:SI_StorageAccount) }
        $stats = [ordered]@{ ManagementGroups = $st.ManagementGroups; Subscriptions = $st.Subscriptions; ResourceGroups = $st.ResourceGroups }
        $n = Save-SIParentChainHandover -Store $Store -Engine $Engine -RunId $RunId -Index $script:SIRuleIndexes.parentChain -Stats $stats
        $line = 'inherited tags: {0} subscription / resource group entr(ies) handed to the parts (attached when the records are merged)' -f $n
        if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $line } else { Write-Host ('[INFO] ' + $line) }
        return $n
    } catch {
        Write-Warning ('inherited tags could not be handed to the parts: {0} -- the azure records of this run carry no inherited tags (resource group / subscription / management group)' -f $_.Exception.Message)
        return 0
    }
}

function Build-SIEgKustoQuerySets {
    <#
        Per-rule pre-fetch: for each rule whose detect.any|all contains a
        kind: egKustoQuery, run the rule's KQL ONCE at IN, store matching
        EntityIds. Per-asset eval is then a set membership test.

        Used by: egKustoQuery handler.

        Index shape:
            kustoSets = @{ <ruleId> = HashSet[string] of EntityIds }

        OS-class skip: when -PresentOsClasses is supplied (the set of OS
        classes actually represented in this run's asset population), rules
        whose osPlatformScope doesn't intersect that set are skipped without
        running KQL. Defender Advanced Hunting queries cost 5-30s each cold;
        avoiding ones that can't possibly match any loaded asset is a big win
        on small/scoped runs (e.g. workstation-only fleets skip the AD/DC
        server rule's 11s round-trip).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Rules,
        [Parameter()]$RunContext,
        [Parameter()]$PresentOsClasses
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $sets = @{}
    $count = 0
    $skipped = 0
    try {
        $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        . (Join-Path $siRoot 'engine\asset-profiling\shared\HuntingQuery.ps1')

        $hasPresentSet = ($PresentOsClasses -is [System.Collections.IEnumerable] -and @($PresentOsClasses).Count -gt 0)

        foreach ($rule in $Rules) {
            # OS-class pre-filter: skip rules whose osPlatformScope doesn't intersect
            # any OS class present in the asset population. Unscoped rules (empty
            # osPlatformScope) always run since they apply to every asset class.
            if ($hasPresentSet -and $rule.osPlatformScope -and @($rule.osPlatformScope).Count -gt 0) {
                $intersects = $false
                foreach ($_c in @($rule.osPlatformScope)) {
                    if (@($PresentOsClasses) -contains [string]$_c) { $intersects = $true; break }
                }
                if (-not $intersects) {
                    $skipped++
                    continue
                }
            }
            foreach ($det in $rule.Detections) {
                $list = if ($det.Detect.any) { $det.Detect.any } elseif ($det.Detect.all) { $det.Detect.all } else { @() }
                foreach ($spec in $list) {
                    if ([string]$spec.kind -ne 'egKustoQuery') { continue }
                    $kql = [string]$spec.query
                    if ([string]::IsNullOrWhiteSpace($kql)) { continue }
                    try {
                        $rows = @(Invoke-SIHuntingQuery -Query $kql -QueryEngine 'DefenderGraph' -ErrorAction Stop)
                        $set = New-Object System.Collections.Generic.HashSet[string]
                        foreach ($r in $rows) {
                            # Try common id fields the query might project
                            $id = $null
                            foreach ($idField in @('NodeId','EntityId','DeviceId','AccountObjectId','PrimaryEntityId')) {
                                if ($r.$idField) { $id = ([string]$r.$idField).ToLower(); break }
                            }
                            if ($id) { [void]$set.Add($id) }
                        }
                        $sets[$rule.Id] = $set
                        $count++
                    } catch {
                        Write-Warning ('Build-SIEgKustoQuerySets: rule {0} KQL failed: {1}' -f $rule.Id, $_.Exception.Message)
                    }
                }
            }
        }
        $script:SIRuleIndexes.kustoSets = $sets
        $stats = @{ Built=$true; Rows=$count; Ms=$sw.ElapsedMilliseconds }
        if ($skipped -gt 0) { $stats['SkippedByOsClass'] = $skipped }
        $script:SIRuleIndexes.BuildStats['kustoSets'] = $stats
        Write-Verbose ('Build-SIEgKustoQuerySets: {0} per-rule sets in {1} ms (skipped {2} via osPlatformScope)' -f $count, $sw.ElapsedMilliseconds, $skipped)
    } catch {
        Write-Warning ('Build-SIEgKustoQuerySets failed: {0}' -f $_.Exception.Message)
        $script:SIRuleIndexes.BuildStats['kustoSets'] = @{ Built=$false; Error=$_.Exception.Message }
    }
}

# ----------------------------------------------------------------------------
# Master orchestrator
# ----------------------------------------------------------------------------

function Build-SIRuleIndexes {
    <#
        Top-level entry point called by Stage Profile at run start. Builds
        only the indexes that the supplied rule set actually needs (saves
        on bulk fetches when an engine doesn't use a particular kind) --
        EXCEPT the parent chain on the azure engine: the tags a resource
        inherits from its resource group, subscription and management groups
        are DATA on its CI (parts parentTags / parentTagScopes), not only rule
        input, so the azure engine builds it on every run, whatever the rules.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()]$Rules,
        [Parameter()]$Assets,
        [Parameter()]$RunContext
    )

    Reset-SIRuleIndexes

    # Inventory which kinds the rule set actually uses
    $kinds = New-Object System.Collections.Generic.HashSet[string]
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        foreach ($d in $r.Detections) {
            $list = if ($d.Detect.any) { $d.Detect.any } elseif ($d.Detect.all) { $d.Detect.all } else { @() }
            foreach ($spec in $list) { if ($spec.kind) { [void]$kinds.Add([string]$spec.kind) } }
        }
    }
    Write-Verbose ('Build-SIRuleIndexes: engine={0} kinds-needed={1}' -f $Engine, ($kinds -join ','))

    if ($kinds.Contains('hasSoftwareInstalled'))   { Build-SITvmSoftwareIndex            -RunContext $RunContext }
    if ($kinds.Contains('groupMembership'))        { Build-SIGroupMembershipIndex      -Assets $Assets -RunContext $RunContext }
    # hasTag also walks the ARM parent chain when the asset
    # has AZ_ResourceId / MDE_AzureResourceId, so build the index when EITHER
    # kind is in use.
    # The azure engine ALWAYS builds it (its records carry the inherited tags -- SI-RecordCapture.ps1
    # Add-SIRecordPartsFromRuleIndexes); the resources' own tags are read only when a tag rule needs them.
    # A WORKER of a run collected in parts (SI_COLLECT_PHASE = parts) holds none of discovery's records: the producer read the
    # parent chain once for the whole collection and the merge attaches it (Save-SIParentChainForParts) -- a worker reads it
    # only for a tag rule of its own.
    $tagRule = ($kinds.Contains('hasAzureTagDirectOrParent') -or $kinds.Contains('hasTag'))
    $inParts = ([string][Environment]::GetEnvironmentVariable('SI_COLLECT_PHASE') -eq 'parts')
    if (($Engine -eq 'azure' -and -not $inParts) -or $tagRule) {
        Build-SIParentResourceChainIndex -RunContext $RunContext -IncludeResources:$tagRule
    }
    if ($kinds.Contains('egKustoQuery')) {
        # Compute the set of OS classes actually represented in this run's
        # asset population so Build-SIEgKustoQuerySets can skip rules whose
        # osPlatformScope can't possibly match any loaded asset (e.g.
        # WindowsServer-only AD/DC rule on a workstation-only run = skip 11s
        # Defender Hunting round-trip).
        $presentOsClasses = $null
        if ($Assets) {
            try {
                . (Join-Path $PSScriptRoot 'RuleEval.ps1')
                $presentSet = New-Object System.Collections.Generic.HashSet[string]
                foreach ($a in $Assets) {
                    $cls = Get-SIAssetOsClass -Asset $a
                    if ($cls) { [void]$presentSet.Add([string]$cls) }
                }
                $presentOsClasses = @($presentSet)
                Write-Verbose ('Build-SIRuleIndexes: present OS classes = {0}' -f ($presentOsClasses -join ','))
            } catch {
                Write-Verbose ('Build-SIRuleIndexes: present-OS-class probe failed -- {0} (continuing without filter)' -f $_.Exception.Message)
            }
        }
        Build-SIEgKustoQuerySets -Rules $Rules -RunContext $RunContext -PresentOsClasses $presentOsClasses
    }

    # v3 data model: the record capture turns these indexes into record parts (installed software, inherited tags,
    # Exposure Graph query hits) -- handed over globally because it runs in another script's scope
    $global:SIRuleIndexesForRecords = $script:SIRuleIndexes

    return $script:SIRuleIndexes.BuildStats
}
