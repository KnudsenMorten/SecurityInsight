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
          parentChain  = @{ <resourceId-lower>   = @( @{ tag='cmdbId'; value='1' }, ... ) }
          kustoSets    = @{ <ruleId> = <Set[string] of matching EntityIds> }
          BuildStats   = @{ <kind> = @{ Built=<bool>; Rows=<int>; Ms=<int> } }
      }

    Honest scope -- implements the structure + entry points. The
    actual bulk-fetch implementations are scaffolded with the right shape
    but UNTESTED in tenant. Stage Profile wires this up
    behind $global:SI_UseNewRuleEngine opt-in.
#>

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
       across all pages. Defensive against missing SkipToken on legacy
       Az.ResourceGraph builds (loops at most 100 pages = 100K rows). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Query, [int]$PageSize = 1000)
    $out = New-Object System.Collections.ArrayList
    $skipToken = $null
    $pages = 0
    do {
        $params = @{ Query = $Query; First = $PageSize; ErrorAction = 'Stop' }
        if ($skipToken) { $params['SkipToken'] = $skipToken }
        $batch = Search-AzGraph @params
        if ($batch) { foreach ($row in $batch) { [void]$out.Add($row) } }
        $skipToken = $null
        if ($batch -and ($batch.PSObject.Properties['SkipToken']) -and $batch.SkipToken) { $skipToken = [string]$batch.SkipToken }
        $pages++
    } while ($skipToken -and $pages -lt 100)
    if ($pages -ge 100 -and $skipToken) {
        Write-Warning ("Get-SIArgPaged: hit 100-page safety cap ({0} rows) -- truncating. Increase if you legitimately have >100K rows." -f $out.Count)
    }
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
        ARG bulk-fetch: every Azure subscription + RG + RESOURCE + their tags.
        Build map:
            <resource-id-lower> -> @( @{ tag='<key>'; value='<val>'; level='<sub|rg|resource>' }, ... )

        Used by: hasAzureTagDirectOrParent handler.

        now ALSO indexes resource-level tags (was sub + RG only).
        User feedback: "remember it must go up the chain of the resource to read
        from the subscription or management group or the actual resource itself"
        + "consider to enum through ARG as it is fast" -> single Resources ARG
        query for every resource's own tags. Cheap: tens of thousands of rows
        in one round-trip vs per-asset ARM REST calls.

        Each resource entry inherits its RG's tags (which already include sub
        tags), so the handler can do a single-level lookup against the resource
        id and get the FULL chain (resource -> RG -> sub) flattened in one array.

        TODO: management-group level tags. Requires a separate
        ResourceContainers query for MGs + sub->MG mapping (not in ARG directly).
    #>
    [CmdletBinding()]
    param([Parameter()]$RunContext)

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $idx = @{}
    try {
        # ---- Subscriptions + their tags ----
        $subKql = @"
ResourceContainers
| where type =~ 'microsoft.resources/subscriptions'
| project subscriptionId, name, tags
"@
        $subs = @(Get-SIArgPaged -Query $subKql)
        foreach ($s in $subs) {
            if ($null -eq $s) { continue }
            $tagsArr = New-Object System.Collections.ArrayList
            foreach ($p in (ConvertTo-SITagPairs $s.tags)) {
                [void]$tagsArr.Add(@{ tag = $p.Key; value = $p.Value; level = 'subscription' })
            }
            $subId = [string]$s.subscriptionId
            if (-not [string]::IsNullOrWhiteSpace($subId)) {
                $idx[('/subscriptions/{0}' -f $subId).ToLower()] = $tagsArr.ToArray()
            }
        }
        $subCount = $idx.Count

        # ---- RGs + their tags (inherit subscription tags) ----
        $rgKql = @"
ResourceContainers
| where type =~ 'microsoft.resources/subscriptions/resourcegroups'
| project id, tags, subscriptionId
"@
        $rgs = @(Get-SIArgPaged -Query $rgKql)
        foreach ($r in $rgs) {
            if ($null -eq $r) { continue }
            $tagsArr = New-Object System.Collections.ArrayList
            foreach ($p in (ConvertTo-SITagPairs $r.tags)) {
                [void]$tagsArr.Add(@{ tag = $p.Key; value = $p.Value; level = 'resourceGroup' })
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

        # ---- Resources + their tags (inherit RG + sub tags via parent lookup) ----
        # bulk-fetch every resource's own tags. The single ARG query
        # is fast (one round-trip) and lets the handler match `kind:
        # hasAzureTagDirectOrParent` rules where the tag is set on the resource
        # itself (key vault, vm, storage, etc.) -- not just on its container.
        $resKql = @"
Resources
| where notnull(tags) and notempty(tags)
| project id, tags, subscriptionId, resourceGroup
"@
        $resCount = 0
        try {
            $resPage = @(Get-SIArgPaged -Query $resKql)
            foreach ($r in $resPage) {
                if ($null -eq $r) { continue }
                $tagsArr = New-Object System.Collections.ArrayList
                foreach ($p in (ConvertTo-SITagPairs $r.tags)) {
                    [void]$tagsArr.Add(@{ tag = $p.Key; value = $p.Value; level = 'resource' })
                }
                # Inherit RG tags (which already include sub tags from above pass)
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
            Write-Warning ('Build-SIParentResourceChainIndex: Resources tag bulk-fetch failed (continuing with sub+RG only): {0}' -f $_.Exception.Message)
        }

        $script:SIRuleIndexes.parentChain = $idx
        $script:SIRuleIndexes.BuildStats['parentChain'] = @{ Built=$true; Rows=$idx.Count; Ms=$sw.ElapsedMilliseconds }
        Write-Verbose ('Build-SIParentResourceChainIndex: subs={0} rgs={1} resources={2} total={3} in {4} ms' -f $subCount, $rgCount, $resCount, $idx.Count, $sw.ElapsedMilliseconds)
    } catch {
        Write-Warning ('Build-SIParentResourceChainIndex failed: {0}' -f $_.Exception.Message)
        $script:SIRuleIndexes.BuildStats['parentChain'] = @{ Built=$false; Error=$_.Exception.Message }
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
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Rules,
        [Parameter()]$RunContext
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $sets = @{}
    $count = 0
    try {
        $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
        . (Join-Path $siRoot 'engine\asset-profiling\shared\HuntingQuery.ps1')

        foreach ($rule in $Rules) {
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
        $script:SIRuleIndexes.BuildStats['kustoSets'] = @{ Built=$true; Rows=$count; Ms=$sw.ElapsedMilliseconds }
        Write-Verbose ('Build-SIEgKustoQuerySets: {0} per-rule sets in {1} ms' -f $count, $sw.ElapsedMilliseconds)
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
        on bulk fetches when an engine doesn't use a particular kind).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Engine,
        [Parameter(Mandatory)]$Rules,
        [Parameter()]$Assets,
        [Parameter()]$RunContext
    )

    Reset-SIRuleIndexes

    # Inventory which kinds the rule set actually uses
    $kinds = New-Object System.Collections.Generic.HashSet[string]
    foreach ($r in $Rules) {
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
    if ($kinds.Contains('hasAzureTagDirectOrParent') -or $kinds.Contains('hasTag')) {
        Build-SIParentResourceChainIndex -RunContext $RunContext
    }
    if ($kinds.Contains('egKustoQuery'))           { Build-SIEgKustoQuerySets  -Rules  $Rules  -RunContext $RunContext }

    return $script:SIRuleIndexes.BuildStats
}
