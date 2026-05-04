#Requires -Version 5.1
<#
    AzureParentScopeCache.ps1

    Per-run singleton caches for the two Azure parent scopes:

      Subscription scope:
        - sub-id -> @{ Name; Tags = @{key=value;...} }
        Source: ARG `resourcecontainers | where type =~ 'microsoft.resources/subscriptions'`

      Management-group scope:
        - mg-name -> @{ DisplayName; Parent = <parent-mg-name>; Tags = @{...} }
        - sub-id  -> @( <root>, <child>, ... <leaf-mg-name> )                (display-name chain, root first)
        - sub-id  -> @{ MergedTags = @{...} }                                (merged across the chain, deepest wins)
        Source: ARG `resourcecontainers | where type =~ 'microsoft.management/managementgroups'`
                + a second pass over the subscription nodes' .properties.managementGroupAncestorsChain
                (or .parent when ancestors aren't available -- different ARM versions emit different shapes).

    Design choices:
      - Lazy init on first lookup -- the row builder calls
        Get-SIAzureSubscriptionScope / Get-SIAzureManagementGroupChain and
        the cache initialises itself on the first hit per run.
      - Empty cache on ANY ARG failure -- the engine MUST NOT crash because
        the customer's principal lacks 'Reader' on the root MG. Missing
        parent tags is a degraded mode, not a fatal error.
      - "Deepest wins" tag-merge across MG chain: a tag set at the leaf MG
        overrides the same tag-name set at the root. Rationale: leaf scopes
        are more specific to the resource's actual operating context.
        Subscription tags are still emitted SEPARATELY under
        properties.azure.parentTags.subscription (NOT merged into the MG
        chain) so customers can still tell which scope a tag came from.

    Cost model:
      - 1 ARG query for subscriptions (typical tenant: <500 rows).
      - 1 ARG query for MGs (typical tenant: <50 rows).
      - O(depth) walk per resource at row-build time, where depth ~= 3-5.
#>

if (-not (Get-Variable -Name _SIAzureParentScope -Scope Script -ErrorAction SilentlyContinue)) {
    $script:_SIAzureParentScope = @{
        SubInitialized       = $false
        MgInitialized        = $false
        Subscriptions        = @{}    # subId (lowercased) -> @{ Name; Tags = @{...} }
        Mgs                  = @{}    # mgName (lowercased) -> @{ DisplayName; Parent = <parentMgName lowercased or $null>; Tags = @{...} }
        SubMgChain           = @{}    # subId (lowercased) -> @( displayName1, displayName2, ... )  root-first
        SubMgMergedTags      = @{}    # subId (lowercased) -> @{ tagName = tagValue; ... }   deepest wins
    }
}

function Reset-SIAzureParentScopeCache {
    [CmdletBinding()]
    param()
    $script:_SIAzureParentScope = @{
        SubInitialized       = $false
        MgInitialized        = $false
        Subscriptions        = @{}
        Mgs                  = @{}
        SubMgChain           = @{}
        SubMgMergedTags      = @{}
    }
}

function _Invoke-SIAzGraphQuerySafe {
    <# Internal helper. Wraps Search-AzGraph with skip-token paging + try/catch.
       Returns @() on failure (so init paths can fall back to empty caches). #>
    param(
        [Parameter(Mandatory)][string]$Kql,
        [int]$PageSize = 1000
    )
    if (-not (Get-Command -Name Search-AzGraph -ErrorAction SilentlyContinue)) {
        Write-Warning 'AzureParentScopeCache: Search-AzGraph not available (Az.ResourceGraph not loaded). Cache empty.'
        return @()
    }
    $rows = New-Object System.Collections.ArrayList
    $skipToken = $null
    do {
        $params = @{ Query = $Kql; First = $PageSize }
        if ($skipToken) { $params['SkipToken'] = $skipToken }
        try {
            $page = Search-AzGraph @params
        } catch {
            Write-Warning ('AzureParentScopeCache: ARG query failed -- {0}. Returning partial ({1} rows).' -f $_.Exception.Message, $rows.Count)
            return $rows.ToArray()
        }
        foreach ($r in $page) { [void]$rows.Add($r) }
        $skipToken = $page.SkipToken
    } while ($skipToken)
    return $rows.ToArray()
}

function Initialize-SIAzureSubscriptionScopeCache {
    <#
        Pulls subscription-level metadata + tags via ARG:
            resourcecontainers
            | where type =~ 'microsoft.resources/subscriptions'
            | project subscriptionId, name, tags

        Idempotent. Sets SubInitialized = $true even on failure so a bad ARG
        run doesn't loop on every row.
    #>
    [CmdletBinding()]
    param()
    if ($script:_SIAzureParentScope.SubInitialized) { return }
    $script:_SIAzureParentScope.SubInitialized = $true

    $kql = @'
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| project subscriptionId, name, tags
'@
    $rows = _Invoke-SIAzGraphQuerySafe -Kql $kql
    foreach ($r in $rows) {
        $subId = [string]$r.subscriptionId
        if ([string]::IsNullOrWhiteSpace($subId)) { continue }
        # Tags surface as a PSCustomObject (one note property per key) when the
        # ARG client deserializes JSON. Normalise to a hashtable so callers can
        # ConvertTo-Json it cleanly.
        $tagsHash = @{}
        if ($null -ne $r.tags) {
            if ($r.tags -is [System.Collections.IDictionary]) {
                foreach ($k in $r.tags.Keys) { $tagsHash[[string]$k] = [string]$r.tags[$k] }
            } else {
                foreach ($p in $r.tags.PSObject.Properties) { $tagsHash[$p.Name] = [string]$p.Value }
            }
        }
        $script:_SIAzureParentScope.Subscriptions[$subId.ToLowerInvariant()] = @{
            Name = [string]$r.name
            Tags = $tagsHash
        }
    }
    Write-Verbose ('AzureParentScopeCache: {0} subscription(s) cached.' -f $script:_SIAzureParentScope.Subscriptions.Count)
}

function Initialize-SIAzureManagementGroupCache {
    <#
        Pulls management-group hierarchy + tags via ARG:
            resourcecontainers
            | where type =~ 'microsoft.management/managementgroups'
            | project name, tags, parentName = tostring(properties.details.parent.name), displayName = tostring(properties.displayName)

        Then walks the subscription -> MG chain via:
            resourcecontainers
            | where type =~ 'microsoft.resources/subscriptions'
            | project subscriptionId, ancestors = properties.managementGroupAncestorsChain, parentMg = tostring(properties.parent.name)

        Builds:
          - $script:_SIAzureParentScope.Mgs[mgName] = @{ DisplayName; Parent; Tags }
          - $script:_SIAzureParentScope.SubMgChain[subId] = @(rootDisplay, ..., leafDisplay)
          - $script:_SIAzureParentScope.SubMgMergedTags[subId] = @{ ... }   (deepest wins)

        Idempotent + defensive. ARG failure -> empty caches, engine continues.
    #>
    [CmdletBinding()]
    param()
    if ($script:_SIAzureParentScope.MgInitialized) { return }
    $script:_SIAzureParentScope.MgInitialized = $true

    # ---- 1. MG metadata ----
    $kqlMgs = @'
resourcecontainers
| where type =~ 'microsoft.management/managementgroups'
| project name, tags, parentName = tostring(properties.details.parent.name), displayName = tostring(properties.displayName)
'@
    $mgRows = _Invoke-SIAzGraphQuerySafe -Kql $kqlMgs
    foreach ($r in $mgRows) {
        $mgName = [string]$r.name
        if ([string]::IsNullOrWhiteSpace($mgName)) { continue }
        $tagsHash = @{}
        if ($null -ne $r.tags) {
            if ($r.tags -is [System.Collections.IDictionary]) {
                foreach ($k in $r.tags.Keys) { $tagsHash[[string]$k] = [string]$r.tags[$k] }
            } else {
                foreach ($p in $r.tags.PSObject.Properties) { $tagsHash[$p.Name] = [string]$p.Value }
            }
        }
        $parentName = [string]$r.parentName
        $script:_SIAzureParentScope.Mgs[$mgName.ToLowerInvariant()] = @{
            DisplayName = if ([string]::IsNullOrWhiteSpace([string]$r.displayName)) { $mgName } else { [string]$r.displayName }
            Parent      = if ([string]::IsNullOrWhiteSpace($parentName)) { $null } else { $parentName.ToLowerInvariant() }
            Tags        = $tagsHash
        }
    }

    # ---- 2. Subscription -> MG ancestor chain ----
    # ARG exposes managementGroupAncestorsChain as an array of @{name; displayName}
    # ordered child-first (i.e. immediate parent at index 0, root at the end).
    # We reverse it so callers get a familiar root-first chain.
    $kqlSubChain = @'
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| project subscriptionId, ancestors = properties.managementGroupAncestorsChain, parentMg = tostring(properties.parent.name)
'@
    $subChainRows = _Invoke-SIAzGraphQuerySafe -Kql $kqlSubChain
    foreach ($r in $subChainRows) {
        $subId = [string]$r.subscriptionId
        if ([string]::IsNullOrWhiteSpace($subId)) { continue }

        $chain = New-Object System.Collections.Generic.List[string]    # root-first display names
        $merged = @{}                                                  # deepest wins

        # Prefer the explicit ancestors array; fall back to walking via .parent
        # when ancestors isn't populated (older ARG schemas / non-MG-attached
        # subs).
        $ancestors = $r.ancestors
        $haveAncestors = $false
        if ($null -ne $ancestors) {
            try {
                $arr = @($ancestors)
                if ($arr.Count -gt 0) {
                    # ARG order is child-first -- iterate in reverse to get root-first.
                    for ($i = $arr.Count - 1; $i -ge 0; $i--) {
                        $node = $arr[$i]
                        $name = if ($node.PSObject.Properties['name']) { [string]$node.name } else { $null }
                        if ([string]::IsNullOrWhiteSpace($name)) { continue }
                        $mgEntry = $script:_SIAzureParentScope.Mgs[$name.ToLowerInvariant()]
                        $display = if ($mgEntry) { [string]$mgEntry.DisplayName } else { $name }
                        if ($node.PSObject.Properties['displayName'] -and -not [string]::IsNullOrWhiteSpace([string]$node.displayName)) {
                            $display = [string]$node.displayName
                        }
                        [void]$chain.Add($display)
                        # Merge tags root-first so deeper (later) overrides earlier.
                        if ($mgEntry -and $mgEntry.Tags) {
                            foreach ($k in $mgEntry.Tags.Keys) { $merged[$k] = $mgEntry.Tags[$k] }
                        }
                    }
                    $haveAncestors = $true
                }
            } catch {
                # malformed ancestors -- fall through to .parent walk
                $haveAncestors = $false
            }
        }
        if (-not $haveAncestors) {
            # Walk via .parent. Cap the walk at 10 hops so a malformed cycle
            # in the cache (shouldn't happen, but be defensive) never spins.
            $current = [string]$r.parentMg
            $stack = New-Object System.Collections.Generic.List[string]
            $hop = 0
            while ($current -and $hop -lt 10) {
                $key = $current.ToLowerInvariant()
                $mgEntry = $script:_SIAzureParentScope.Mgs[$key]
                if (-not $mgEntry) { break }
                [void]$stack.Add($mgEntry.DisplayName)
                $current = $mgEntry.Parent
                $hop++
            }
            # $stack is leaf-first (we appended children before parents). Reverse for root-first.
            for ($i = $stack.Count - 1; $i -ge 0; $i--) {
                $disp = $stack[$i]
                [void]$chain.Add($disp)
                # Re-resolve and merge tags
                $entry = $null
                foreach ($k in $script:_SIAzureParentScope.Mgs.Keys) {
                    if ($script:_SIAzureParentScope.Mgs[$k].DisplayName -eq $disp) { $entry = $script:_SIAzureParentScope.Mgs[$k]; break }
                }
                if ($entry -and $entry.Tags) {
                    foreach ($t in $entry.Tags.Keys) { $merged[$t] = $entry.Tags[$t] }
                }
            }
        }

        $script:_SIAzureParentScope.SubMgChain[$subId.ToLowerInvariant()]      = $chain.ToArray()
        $script:_SIAzureParentScope.SubMgMergedTags[$subId.ToLowerInvariant()] = $merged
    }
    Write-Verbose ('AzureParentScopeCache: {0} MG(s), {1} sub->MG chains cached.' -f `
        $script:_SIAzureParentScope.Mgs.Count, $script:_SIAzureParentScope.SubMgChain.Count)
}

function Get-SIAzureSubscriptionScope {
    <# Returns @{ Name; Tags = @{...} } for a subscription id, or $null. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$SubscriptionId
    )
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) { return $null }
    if (-not $script:_SIAzureParentScope.SubInitialized) {
        Initialize-SIAzureSubscriptionScopeCache
    }
    $key = $SubscriptionId.ToLowerInvariant()
    if ($script:_SIAzureParentScope.Subscriptions.ContainsKey($key)) {
        return $script:_SIAzureParentScope.Subscriptions[$key]
    }
    return $null
}

function Get-SIAzureManagementGroupChain {
    <#
        Returns a hashtable describing the MG chain for a subscription:
          @{
            ChainDisplayNames = @( 'Tenant', 'Engineering', 'Production' )    # root-first
            MergedTags        = @{ key = value; ... }                          # deepest wins across the chain
          }
        Returns $null when no MG data is cached for this subscription.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$SubscriptionId
    )
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) { return $null }
    if (-not $script:_SIAzureParentScope.MgInitialized) {
        Initialize-SIAzureManagementGroupCache
    }
    $key = $SubscriptionId.ToLowerInvariant()
    $chain = $script:_SIAzureParentScope.SubMgChain[$key]
    $merged = $script:_SIAzureParentScope.SubMgMergedTags[$key]
    if (-not $chain -and -not $merged) { return $null }
    return @{
        ChainDisplayNames = if ($chain) { @($chain) } else { @() }
        MergedTags        = if ($merged) { $merged } else { @{} }
    }
}

function Get-SIAzureParentScopeStats {
    <# Diagnostic accessor. #>
    [CmdletBinding()]
    param()
    return [pscustomobject]@{
        SubInitialized = $script:_SIAzureParentScope.SubInitialized
        MgInitialized  = $script:_SIAzureParentScope.MgInitialized
        Subscriptions  = $script:_SIAzureParentScope.Subscriptions.Count
        Mgs            = $script:_SIAzureParentScope.Mgs.Count
        SubChains      = $script:_SIAzureParentScope.SubMgChain.Count
    }
}
