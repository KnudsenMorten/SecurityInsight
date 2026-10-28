#Requires -Version 5.1
<#
    THE TWO READS THE 'derived' RECORD PART NEEDS THAT NO COLLECTOR DID (engine/data-model/SI-RecordDerived.ps1):

      Invoke-SISpOwnerCapture         the owners of every service principal -> part 'owners' ({ count }) on its Entra record.
                                      Graph REST: GET /servicePrincipals?$select=id&$expand=owners($select=id,displayName,userPrincipalName)&$top=100, paged
                                      (Application.Read.All, the permission the service-principal discovery already uses).
                                      Feeds derived.ownerCount -> si_is_orphan_sp. A failed read records nothing: an unknown
                                      owner count is never 0.
      Invoke-SIManagementGroupCapture the management-group chain of every subscription -> part 'mg' ({ path }) on every
                                      Azure record of that subscription. Resource Graph REST: resourcecontainers,
                                      properties.managementGroupAncestorsChain (Reader). Feeds derived.managementGroupPath.
                                      The same read gives every NAME next to its id: the management group (id + name, and
                                      the chain as ids), the subscription's name, the tenant id and -- one small directory
                                      read, GET /organization -- the tenant's name.

    Both run in the discovery process right after the records they decorate were captured, and never fail the run.
    No PowerShell modules. PowerShell 5.1: no ?. / ??, no ternary.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1) -- loaded here, so this file works however it is loaded.
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

function Get-SISpOwnerCounts {
    <#
    .SYNOPSIS  Reads the owners of every service principal ONCE per run: @{ Read; Complete; Counts = @{ <sp id> = n } }.
               Graph REST GET /servicePrincipals?$select=id&$expand=owners($select=id,displayName,userPrincipalName)&$top=100, following @odata.nextLink
               (Graph caps the page size with $expand on directory objects). An expanded owners list can be truncated
               (owners@odata.nextLink, or a full 20-item expansion): such a principal HAS owners -- its count is never 0.
               A principal not in Counts (a failed or partial read) has an UNKNOWN owner count. Cached in
               $global:SISpOwnerState for the run; -Fetch (tests): { param($Url) } -> rows (id, owners[, owners@odata.nextLink]).
    #>
    param([string]$Token, [scriptblock]$Fetch, [switch]$Refresh)
    if (-not $Refresh -and $global:SISpOwnerState -is [hashtable] -and $global:SISpOwnerState.Read) { return $global:SISpOwnerState }
    # the owners WITH their sign-in name and display name (id AND name, side by side): Owners = @{ <sp id> = [{ id, upn, name, type }] }
    # LIST KEPT: a join read -- the service principal id and its owners as references (id + name + sign-in name); the service principal itself is read once, elsewhere
    $url = 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id&$expand=owners($select=id,displayName,userPrincipalName)&$top=100'
    $state = @{ Read = $false; Complete = $false; Counts = @{}; Owners = @{}; Url = $url }
    $rows = @(); $complete = $true
    try {
        if ($Fetch) { $rows = @(& $Fetch $url) }
        else {
            if (-not (Get-Command -Name Invoke-SIPagedRest -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/Invoke-SIPagedRest.ps1') }
            $page = Invoke-SIPagedRest -Url $url -Token $Token -SourceLabel 'EntraServicePrincipals owners'
            if (-not $page.Complete) { $complete = $false; Write-Warning ('Service principal owners: {0} -- the read is partial; principals not read keep an unknown owner count.' -f $page.Error) }
            $rows = @($page.Rows)
        }
    } catch {
        Write-Warning ('Service principal owners: not read ({0}) -- owner counts stay unknown this run (never "orphaned").' -f $_.Exception.Message)
        $global:SISpOwnerState = $state
        return $state
    }
    foreach ($r in $rows) {
        if ($null -eq $r) { continue }
        $id = ([string]$r.id).ToLowerInvariant(); if (-not $id) { continue }
        $owners = @($r.owners | Where-Object { $_ })
        $n = $owners.Count
        $more = $r.PSObject.Properties['owners@odata.nextLink'] -and [string]$r.'owners@odata.nextLink'
        if (($more -or $n -ge 20) -and $n -lt 1) { $n = 1 }      # truncated: has owners, never 0
        $state.Counts[$id] = $n
        if ($owners.Count -gt 0) { $state.Owners[$id] = @($owners | ForEach-Object { ConvertTo-SIOwnerItem $_ } | Where-Object { $_ }) }
    }
    $state.Read = $true; $state.Complete = $complete
    $global:SISpOwnerState = $state
    return $state
}

function ConvertTo-SIOwnerItem {
    <# PURE. One owner as Graph returns it (a user, a service principal ...) -> { id, upn, name, type }; $null without an id. #>
    param($Owner)
    if ($null -eq $Owner) { return $null }
    $g = { param($n) $p = $Owner.PSObject.Properties[$n]; if ($p -and $null -ne $p.Value) { [string]$p.Value } else { '' } }
    $id = (& $g 'id').ToLowerInvariant()
    if (-not $id) { return $null }
    $type = (& $g '@odata.type') -replace '^#microsoft\.graph\.', ''
    [pscustomobject][ordered]@{ id = $id; upn = (& $g 'userPrincipalName').ToLowerInvariant(); name = (& $g 'displayName'); type = $type }
}

function Get-SISpOwnerCount {
    <#
        PURE. The owner count of one service principal from a Get-SISpOwnerCounts state, or $null (unknown).
        -AppOwners: the owners of its APPLICATION registration (Get-SIEntraApplications, by application id) -- a service
        principal whose application has an owner is NOT orphaned, so the two are counted together, each person once.
        -AppOwnersKnown $false (the applications read did not complete and this is an application of this tenant): a count
        of 0 is then unknown ($null), never "no owner".
    #>
    param([string]$Id, $State = $global:SISpOwnerState, [AllowNull()][object[]]$AppOwners = $null, [bool]$AppOwnersKnown = $true)
    if ($null -eq $State -or -not $State.Read -or -not $Id) { return $null }
    $k = $Id.ToLowerInvariant()
    if (-not $State.Counts.ContainsKey($k)) { return $null }
    $n = [int]$State.Counts[$k]
    $extra = @(@($AppOwners) | Where-Object { $_ })
    if ($extra.Count -gt 0) {
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        if ($State.Owners -and $State.Owners.ContainsKey($k)) { foreach ($o in @($State.Owners[$k])) { if ($o -and $o.id) { [void]$seen.Add([string]$o.id) } } }
        $add = 0
        foreach ($o in $extra) { $oid = [string]$o.id; if ($oid -and $seen.Add($oid)) { $add++ } }
        # a truncated owners list keeps its count; the application's owners not among those read are added
        $n = [Math]::Max($n, $seen.Count - $add) + $add
    }
    if ($n -eq 0 -and -not $AppOwnersKnown) { return $null }
    return $n
}

function Invoke-SISpOwnerCapture {
    <#
    .SYNOPSIS  Adds part 'owners' ({ count }) to each captured Entra service-principal record from the run's owners read
               (Get-SISpOwnerCounts -- read once, shared with the identity profile). Returns the number of records decorated.
    #>
    param([string]$Token, [scriptblock]$Fetch)
    if ($null -eq $global:SIRecordCaptureState -or -not (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue)) { return 0 }
    $state = Get-SISpOwnerCounts -Token $Token -Fetch $Fetch -Refresh:([bool]$Fetch)
    if (-not $state.Read) { return 0 }
    $n = 0
    foreach ($id in @($state.Counts.Keys)) {
        # #721: held or streamed (the discover phase streams its records; their ids are remembered)
        if (Get-Command -Name Test-SIRecordCaptured -ErrorAction SilentlyContinue) { if (-not (Test-SIRecordCaptured -Id "entra|service_principal|$id")) { continue } }
        elseif (-not $global:SIRecordCaptureState.Records.ContainsKey("entra|service_principal|$id")) { continue }
        $items = @(); if ($state.Owners -and $state.Owners.ContainsKey($id)) { $items = @($state.Owners[$id]) }
        try { Add-SIRecordPart -Provider 'entra' -RecordType 'service_principal' -Key $id -Part 'owners' -Object ([pscustomobject]@{ count = [int]$state.Counts[$id]; items = $items }); $n++ } catch { }
    }
    return $n
}
function Get-SIManagementGroupKql {
    <# PURE. Every subscription with its name, its tenant and its management-group chain (Resource Graph). #>
    @"
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| project SubscriptionId = tolower(subscriptionId), SubscriptionName = tostring(name), TenantId = tolower(tostring(tenantId)), Chain = properties.managementGroupAncestorsChain
| order by SubscriptionId asc
"@
}

function ConvertTo-SISubscriptionContext {
    <#
    .SYNOPSIS  PURE. Resource Graph rows (Get-SIManagementGroupKql) -> @{ <subscription id> = the 'mg' part }: ids AND names
               side by side --
                 path / idPath       the management-group chain, root first: display names ('Tenant Root Group/Corp/Prod')
                                     and ids ('<root id>/corp/prod')
                 id / name           the management group the subscription sits in (the leaf of the chain)
                 subscriptionName    the subscription's display name
                 tenantId / tenantName  the subscription's tenant (the name from -TenantNames: tenant id -> display name)
               A value the row does not carry is left out (never guessed). A subscription with neither a name nor a chain
               gets no part.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [hashtable]$TenantNames = @{})
    $map = @{}
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $sub = ([string]$r.SubscriptionId).Trim().ToLowerInvariant()
        if (-not $sub) { continue }
        $chain = $r.Chain
        if ($chain -is [string]) { try { $chain = $chain | ConvertFrom-Json } catch { $chain = @() } }
        $names = New-Object System.Collections.Generic.List[string]
        $ids = New-Object System.Collections.Generic.List[string]
        foreach ($c in @($chain)) {
            if ($null -eq $c) { continue }
            $id = ([string]$c.name).Trim(); $dn = ([string]$c.displayName).Trim()
            if (-not $dn) { $dn = $id }
            if (-not $id) { $id = $dn }
            if (-not $dn) { continue }
            $names.Add($dn); $ids.Add($id)
        }
        $part = [ordered]@{}
        if ($names.Count -gt 0) {
            # the chain comes leaf first: the first item is the management group the subscription sits in
            $part['id'] = $ids[0]; $part['name'] = $names[0]
            $n = $names.ToArray(); $i = $ids.ToArray()
            [array]::Reverse($n); [array]::Reverse($i)
            $part['path'] = ($n -join '/'); $part['idPath'] = ($i -join '/')
        }
        $sn = ''; if ($r.PSObject.Properties['SubscriptionName']) { $sn = ([string]$r.SubscriptionName).Trim() }
        if ($sn) { $part['subscriptionName'] = $sn }
        $tid = ''; if ($r.PSObject.Properties['TenantId']) { $tid = ([string]$r.TenantId).Trim().ToLowerInvariant() }
        if ($tid) {
            $part['tenantId'] = $tid
            if ($TenantNames -and $TenantNames.ContainsKey($tid) -and [string]$TenantNames[$tid]) { $part['tenantName'] = [string]$TenantNames[$tid] }
        }
        if ($part.Count -gt 0) { $map[$sub] = [pscustomobject]$part }
    }
    return $map
}

function Get-SITenantNames {
    <#
    .SYNOPSIS  The display name of this install's tenant: @{ <tenant id> = <name> }. Microsoft Graph GET /organization
               (id, displayName -- Directory.Read.All, already held); read only. Azure Resource Manager's own tenant list
               carries no name for an application identity, so the directory is asked. A failed read answers an empty map:
               the tenant id is still written, its name is left out. -Fetch (tests): { param($Url) } -> rows (id, displayName).
    #>
    param([string]$Token, [scriptblock]$Fetch)
    $names = @{}
    # LIST KEPT: a name look-up -- the tenant id and name
    $url = 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName'
    try {
        $rows = @()
        if ($Fetch) { $rows = @(& $Fetch $url) }
        else {
            if (-not $Token) {
                if (-not (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../../auth/Get-SIGraphToken.ps1') }
                $Token = Get-SIGraphToken -Resource Graph
            }
            if (-not (Get-Command -Name Invoke-SIPagedRest -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/Invoke-SIPagedRest.ps1') }
            $page = Invoke-SIPagedRest -Url $url -Token $Token -SourceLabel 'tenant name' -WarningAction SilentlyContinue
            $rows = @($page.Rows)
        }
        foreach ($o in $rows) {
            if ($null -eq $o) { continue }
            $id = ([string]$o.id).Trim().ToLowerInvariant(); $dn = ([string]$o.displayName).Trim()
            if ($id -and $dn) { $names[$id] = $dn }
        }
    } catch { Write-Verbose ('tenant name: not read ({0}) -- the tenant id is written without its name.' -f $_.Exception.Message) }
    return $names
}

function ConvertTo-SIManagementGroupPaths {
    <#
    .SYNOPSIS  PURE. Resource Graph rows -> @{ <subscription id> = 'Root/.../Leaf' }. The chain comes leaf first; the path is
               root first, each management group by its display name (its name when it has none).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $map = @{}
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $sub = ([string]$r.SubscriptionId).Trim().ToLowerInvariant()
        $chain = $r.Chain
        if ($chain -is [string]) { try { $chain = $chain | ConvertFrom-Json } catch { $chain = @() } }
        $names = @(@($chain) | Where-Object { $_ } | ForEach-Object { $dn = [string]$_.displayName; if ($dn) { $dn } else { [string]$_.name } } | Where-Object { $_ })
        if (-not $sub -or $names.Count -eq 0) { continue }
        [array]::Reverse($names)
        $map[$sub] = ($names -join '/')
    }
    return $map
}

function Add-SIManagementGroupParts {
    <# Part 'mg' on every captured Azure record whose subscription is known. -Paths: @{ <subscription id> = path } writes
       { path }; -Context (ConvertTo-SISubscriptionContext) writes the whole part -- the management-group path, ids and names,
       the subscription's name, the tenant id and name. Returns the number decorated. #>
    param([hashtable]$Paths, [hashtable]$Context)
    if ($null -eq $global:SIRecordCaptureState) { return 0 }
    $hasPaths = ($null -ne $Paths -and $Paths.Count -gt 0); $hasContext = ($null -ne $Context -and $Context.Count -gt 0)
    if (-not $hasPaths -and -not $hasContext) { return 0 }
    $n = 0
    # #727: the producer streams its Azure records -- every one of them is in the stream's record index (on disk), and the
    # part goes to the stream as a line of that record (the same part the record held in memory)
    $cs = $global:SIRecordCaptureState
    if ($cs.PSObject.Properties['Stream'] -and $null -ne $cs.Stream -and $cs.Stream.PSObject.Properties['AzureIndex'] -and $null -ne $cs.Stream.AzureIndex) {
        $s = $cs.Stream
        foreach ($id in $s.AzureIndex.Keys) {
            $key = $id.Substring($id.IndexOf('|', 6) + 1)
            if ($key -notmatch '^/subscriptions/([^/]+)') { continue }
            $sub = $Matches[1].ToLowerInvariant()
            if ($hasContext -and $Context.ContainsKey($sub)) { Add-SIRecordStreamPart -Stream $s -Id $id -Part 'mg' -Object $Context[$sub]; $n++ }
            elseif ($hasPaths -and $Paths.ContainsKey($sub)) { Add-SIRecordStreamPart -Stream $s -Id $id -Part 'mg' -Object ([pscustomobject]@{ path = [string]$Paths[$sub] }); $n++ }
        }
    }
    foreach ($r in @($global:SIRecordCaptureState.Records.Values)) {
        if ($r.Provider -ne 'azure') { continue }
        if ([string]$r.Key -notmatch '^/subscriptions/([^/]+)') { continue }
        $sub = $Matches[1].ToLowerInvariant()
        if ($hasContext -and $Context.ContainsKey($sub)) { $r.Parts['mg'] = $Context[$sub]; $n++ }
        elseif ($hasPaths -and $Paths.ContainsKey($sub)) { $r.Parts['mg'] = [pscustomobject]@{ path = [string]$Paths[$sub] }; $n++ }
    }
    return $n
}

function Invoke-SIManagementGroupCapture {
    <# Reads every subscription's name, tenant and management-group chain and decorates the captured Azure records (part
       'mg': ids AND names). -Query (tests): { param($Kql) } -> rows. -TenantNames (tests): tenant id -> display name;
       default: read from the directory (Get-SITenantNames), and a failed read leaves the name out. #>
    param([string[]]$SubscriptionIds = @(), [scriptblock]$Query, [hashtable]$TenantNames)
    $rows = @()
    try {
        if ($Query) { $rows = @(& $Query (Get-SIManagementGroupKql)) }
        else {
            $p = @{ Query = (Get-SIManagementGroupKql); First = 1000 }
            if (@($SubscriptionIds).Count -gt 0) { $p['Subscription'] = $SubscriptionIds }
            $all = New-Object System.Collections.Generic.List[object]
            do {
                $page = Search-SIAzGraph @p -ErrorAction Stop
                foreach ($x in $page) { $all.Add($x) }
                $p['SkipToken'] = $page.SkipToken
            } while ($p['SkipToken'])
            $rows = $all.ToArray()
        }
    } catch { Write-Warning ('Management groups: not read ({0}) -- the management-group path stays empty this run.' -f $_.Exception.Message); return 0 }
    if (@($rows).Count -eq 0) { return 0 }
    # the tenant's display name next to its id (one small directory read; in a test with -Query nothing is read)
    if ($null -eq $TenantNames) {
        $TenantNames = @{}
        $hasTenant = @($rows | Where-Object { $null -ne $_ -and $_.PSObject.Properties['TenantId'] -and [string]$_.TenantId }).Count -gt 0
        if (-not $Query -and $hasTenant) { $TenantNames = Get-SITenantNames }
    }
    return (Add-SIManagementGroupParts -Context (ConvertTo-SISubscriptionContext -Rows $rows -TenantNames $TenantNames))
}
