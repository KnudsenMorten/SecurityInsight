#Requires -Version 5.1
<#
    SecurityInsight v2.2 -- identity role + permission fetcher.

    Bulk-fetches Entra role assignments, PIM eligible schedules, SP application
    permissions, and SP delegated permissions via Microsoft Graph REST.
    Per-asset Graph calls are too slow at scale (5-10 calls x 800 assets =
    minutes); this module pulls tenant-wide once and buckets by principalId.

    Used by Get-DiscoveryFromEntraServicePrincipals.ps1 +
    Get-DiscoveryFromEntraUsers.ps1 and
    Invoke-IdentityCatalogClassify.
#>

. (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth\Get-SIGraphToken.ps1')

# per-process bulk-fetch cache. The Entra User + Entra SP
# discoveries each ran the same 6 bulk fetches (~8 Graph + 1 LA + N Az
# subscription calls), wasting minutes. Cache-once-per-process here so the
# second discovery reuses the first's results.
# guard with Get-Variable so dot-sourcing this file a second time
# doesn't WIPE the cache populated by the first discovery's run.
if (-not (Get-Variable -Name _SICache -Scope Script -ErrorAction SilentlyContinue)) {
    $script:_SICache = @{}
}

function Reset-SIIdentityFetcherCache {
    # Clear all bulk-fetch caches. Use between Run-AssetProfiling.ps1 invocations
    # in the same PowerShell session if you want fresh data.
    $script:_SICache = @{}
    Write-SIInfo '[perms] cache cleared.'
}

function Resolve-SIWorkspaceFromResourceId {
    # Get-AzOperationalInsightsWorkspace -ResourceId is NOT a valid parameter
    # set in PS 5.1's Az.OperationalInsights. Parse the resource ID into
    # subscriptionId / RG / name, set context, then call by RG+Name.
    param([Parameter(Mandatory)][string]$ResourceId)
    if ($ResourceId -notmatch '^/subscriptions/(?<sub>[^/]+)/resourceGroups/(?<rg>[^/]+)/providers/Microsoft\.OperationalInsights/workspaces/(?<name>[^/]+)$') {
        throw "Workspace ResourceId not in expected format: $ResourceId"
    }
    $sub = $matches.sub; $rg = $matches.rg; $name = $matches.name
    $prevCtx = Get-AzContext
    if (-not $prevCtx -or $prevCtx.Subscription.Id -ne $sub) {
        Set-AzContext -SubscriptionId $sub -WarningAction SilentlyContinue | Out-Null
    }
    return Get-AzOperationalInsightsWorkspace -ResourceGroupName $rg -Name $name -ErrorAction Stop
}

function Get-SIGraphHttpStatus {
    # Extract numeric HTTP status from a Graph exception. Returns 0 if the
    # error wasn't an HTTP response (DNS, network reset, etc.).
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    $resp = $ErrorRecord.Exception.Response
    if ($resp -and $resp.StatusCode) { return [int]$resp.StatusCode }
    # PS5.1 sometimes wraps WebException differently; fall back to message scrape
    if ($ErrorRecord.Exception.Message -match '\((\d{3})\)') { return [int]$Matches[1] }
    return 0
}

function Invoke-SIGraphPaged {
    # Internal: GET a Graph endpoint with @odata.nextLink paging. Returns
    # combined .value array. Caller passes the full URL minus host (we add it).
    #
    # Retries transient errors (429 throttle, 502/503/504 gateway, network reset)
    # up to 3 attempts with exponential backoff (1s, 2s, 4s). Permanent errors
    # (401/403/404, malformed query) propagate immediately so the caller can
    # decide what to do (e.g. emit a domain-specific warning for "no P2 license").
    param(
        [Parameter(Mandatory)][string]$RelativeUrl,
        [Parameter(Mandatory)][string]$Token
    )
    $url = if ($RelativeUrl -match '^https?://') { $RelativeUrl } else { 'https://graph.microsoft.com/v1.0' + $RelativeUrl }
    $all = New-Object System.Collections.ArrayList
    $headers = @{ Authorization = ('Bearer ' + $Token); 'ConsistencyLevel' = 'eventual' }
    while ($url) {
        $attempt = 0
        $maxAttempts = 3
        $resp = $null
        while ($true) {
            $attempt++
            try {
                $resp = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
                break
            } catch {
                $status = Get-SIGraphHttpStatus -ErrorRecord $_
                $isTransient = ($status -in 429,502,503,504) -or ($status -eq 0)
                if (-not $isTransient -or $attempt -ge $maxAttempts) { throw }
                $delay = [Math]::Pow(2, $attempt - 1)   # 1s, 2s, 4s
                # Per-retry warnings on busy tenants (PIM scans across 80+
                # role-bearing groups can fire 50+ retries that all auto-
                # recover) drown the launcher trace. Bump a counter for an
                # end-of-phase summary line; keep the per-call detail
                # available via -Verbose for debugging.
                if (-not $script:_SIGraphRetryCount) { $script:_SIGraphRetryCount = @{} }
                $key = "HTTP$status"
                if (-not $script:_SIGraphRetryCount.ContainsKey($key)) { $script:_SIGraphRetryCount[$key] = 0 }
                $script:_SIGraphRetryCount[$key]++
                Write-Verbose ('Graph transient error (HTTP {0}) on {1} -- retry {2}/{3} in {4}s' -f $status, $url, $attempt, $maxAttempts, $delay)
                Start-Sleep -Seconds $delay
            }
        }
        if ($resp.value) {
            foreach ($v in $resp.value) { [void]$all.Add($v) }
        } elseif ($resp -and -not $resp.value -and $resp.PSObject.Properties['id']) {
            [void]$all.Add($resp)
        }
        $url = $resp.'@odata.nextLink'
    }
    return $all.ToArray()
}

function Get-SIEntraRoleDefinitionMap {
    # Returns @{ <roleDefinitionId GUID> = <displayName> } -- needed because
    # roleAssignments come back keyed by roleDefinitionId, but the catalog
    # matches by DisplayName ("Global Administrator", etc.).
    param([Parameter(Mandatory)][string]$Token)
    if ($script:_SICache.ContainsKey('RoleDefMap')) { Write-SIInfo '[perms] role definitions (cache hit)'; return $script:_SICache['RoleDefMap'] }
    $rows = Invoke-SIGraphPaged -RelativeUrl '/roleManagement/directory/roleDefinitions?$select=id,displayName' -Token $Token
    $map = @{}
    foreach ($r in $rows) {
        if ($r.id -and $r.displayName) { $map[[string]$r.id] = [string]$r.displayName }
    }
    $script:_SICache['RoleDefMap'] = $map
    return $map
}

function Get-SIEntraRoleAssignmentsByPrincipal {
    # Bulk fetch ALL Entra directory roleAssignments tenant-wide, bucket by
    # principalId. One Graph call (paged), then O(1) lookups per asset.
    # Returns @{ <principalId> = @(<roleDisplayName1>, <roleDisplayName2>, ...) }
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][hashtable]$RoleDefinitionMap
    )
    if ($script:_SICache.ContainsKey('PermRolesMap')) { Write-SIInfo '[perms] role assignments permanent (cache hit)'; return $script:_SICache['PermRolesMap'] }
    $rows = Invoke-SIGraphPaged -RelativeUrl '/roleManagement/directory/roleAssignments' -Token $Token
    $byPrincipal = @{}
    foreach ($r in $rows) {
        $objId = [string]$r.principalId
        $rid = [string]$r.roleDefinitionId
        if (-not $objId -or -not $rid) { continue }
        $name = $RoleDefinitionMap[$rid]
        if (-not $name) { continue }
        if (-not $byPrincipal.ContainsKey($objId)) { $byPrincipal[$objId] = New-Object System.Collections.ArrayList }
        if (-not ($byPrincipal[$objId] -contains $name)) { [void]$byPrincipal[$objId].Add($name) }
    }
    $script:_SICache['PermRolesMap'] = $byPrincipal
    return $byPrincipal
}

function Get-SIEntraMfaRegistrationByPrincipal {
    # ONE bulk paged call against /reports/authenticationMethods/userRegistrationDetails
    # returns MFA + SSPR + passwordless registration for every user. Replaces
    # legacy v1's per-user /authentication/methods loop (which was N+1 + 429-prone).
    #
    # Returns @{ <userObjectId> = pscustomobject@{
    #     IsMfaRegistered, IsMfaCapable, IsPasswordlessCapable,
    #     IsSsprRegistered, IsSsprCapable, IsSsprEnabled,
    #     MfaMethods=@(string), MfaMethodCount,
    #     DefaultMfaMethod, SystemPreferredAuthMethods=@(string),
    #     PreferredSecondaryAuthMethod, MfaLastUpdatedDateTime
    # } }
    #
    # Permission: UserAuthenticationMethod.Read.All (already required for
    # the legacy fallback path) OR AuditLog.Read.All for the bulk endpoint.
    param([Parameter(Mandatory)][string]$Token)
    if ($script:_SICache.ContainsKey('MfaRegMap')) {
        Write-SIInfo '[perms] MFA registration details (cache hit)'
        return $script:_SICache['MfaRegMap']
    }
    Write-SIInfo '[perms] fetching MFA registration details (one bulk call to userRegistrationDetails)...'
    $byPrincipal = @{}
    try {
        $rows = Invoke-SIGraphPaged -RelativeUrl '/reports/authenticationMethods/userRegistrationDetails?$top=999' -Token $Token
    } catch {
        Write-Warning ('MFA registration fetch failed (insufficient permission UserAuthenticationMethod.Read.All / AuditLog.Read.All?): {0}' -f $_.Exception.Message)
        $script:_SICache['MfaRegMap'] = $byPrincipal
        return $byPrincipal
    }
    foreach ($r in $rows) {
        $oid = [string]$r.id
        if (-not $oid) { continue }
        # Drop 'password' from method list -- holding a password isn't MFA on its own.
        $methodsRaw = if ($r.PSObject.Properties['methodsRegistered'] -and $r.methodsRegistered) { @($r.methodsRegistered) } else { @() }
        $mfaMethods = @($methodsRaw | Where-Object { $_ -and $_ -ne 'password' })
        $byPrincipal[$oid] = [pscustomobject]@{
            IsMfaRegistered             = if ($r.PSObject.Properties['isMfaRegistered'])             { [bool]$r.isMfaRegistered }             else { $false }
            IsMfaCapable                = if ($r.PSObject.Properties['isMfaCapable'])                { [bool]$r.isMfaCapable }                else { $false }
            IsPasswordlessCapable       = if ($r.PSObject.Properties['isPasswordlessCapable'])       { [bool]$r.isPasswordlessCapable }       else { $false }
            IsSsprRegistered            = if ($r.PSObject.Properties['isSsprRegistered'])            { [bool]$r.isSsprRegistered }            else { $false }
            IsSsprCapable               = if ($r.PSObject.Properties['isSsprCapable'])               { [bool]$r.isSsprCapable }               else { $false }
            IsSsprEnabled               = if ($r.PSObject.Properties['isSsprEnabled'])               { [bool]$r.isSsprEnabled }               else { $false }
            IsAdmin                     = if ($r.PSObject.Properties['isAdmin'])                     { [bool]$r.isAdmin }                     else { $false }
            MfaMethods                  = $mfaMethods
            MfaMethodCount              = $mfaMethods.Count
            DefaultMfaMethod            = if ($r.PSObject.Properties['defaultMfaMethod'])            { [string]$r.defaultMfaMethod }          else { '' }
            SystemPreferredAuthMethods  = if ($r.PSObject.Properties['systemPreferredAuthenticationMethods']) { @($r.systemPreferredAuthenticationMethods) } else { @() }
            PreferredSecondaryAuthMethod= if ($r.PSObject.Properties['userPreferredMethodForSecondaryAuthentication']) { [string]$r.userPreferredMethodForSecondaryAuthentication } else { '' }
            MfaLastUpdatedDateTime      = if ($r.PSObject.Properties['lastUpdatedDateTime'])         { [string]$r.lastUpdatedDateTime }       else { '' }
        }
    }
    Write-SIInfo ('[perms] MFA registration details: {0} users with registration data' -f $byPrincipal.Count)
    $script:_SICache['MfaRegMap'] = $byPrincipal
    return $byPrincipal
}

function Get-SIEntraPIMEligibleByPrincipal {
    # Same shape as Get-SIEntraRoleAssignmentsByPrincipal, but for PIM eligible
    # role assignments (roleEligibilitySchedules). User holds these but must
    # activate before use; still highly relevant for tier classification.
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][hashtable]$RoleDefinitionMap
    )
    if ($script:_SICache.ContainsKey('EligRolesMap')) { Write-SIInfo '[perms] role assignments PIM eligible (cache hit)'; return $script:_SICache['EligRolesMap'] }
    $byPrincipal = @{}
    try {
        $rows = Invoke-SIGraphPaged -RelativeUrl '/roleManagement/directory/roleEligibilitySchedules' -Token $Token
    } catch {
        # Classify the failure so the warning matches reality:
        #   403  -> truly insufficient (no Entra ID P2, or Token lacks RoleManagement.Read.Directory)
        #   5xx  -> Graph backend transient (we already retried 3x in Invoke-SIGraphPaged)
        #   429  -> throttled past retry budget
        #   else -> unknown; surface the raw message
        $status = Get-SIGraphHttpStatus -ErrorRecord $_
        $reason = switch ($status) {
            403     { 'no Entra ID P2 license, or token missing RoleManagement.Read.Directory' }
            429     { 'throttled by Graph after 3 retry attempts' }
            502     { 'Graph gateway error (502) after 3 retry attempts -- transient' }
            503     { 'Graph service unavailable (503) after 3 retry attempts -- transient' }
            504     { 'Graph gateway timeout (504) after 3 retry attempts -- transient' }
            default { ('HTTP {0}' -f $status) }
        }
        Write-Warning ('PIM eligible fetch skipped ({0}): {1}' -f $reason, $_.Exception.Message)
        return $byPrincipal
    }
    foreach ($r in $rows) {
        $objId = [string]$r.principalId
        $rid = [string]$r.roleDefinitionId
        if (-not $objId -or -not $rid) { continue }
        $name = $RoleDefinitionMap[$rid]
        if (-not $name) { continue }
        if (-not $byPrincipal.ContainsKey($objId)) { $byPrincipal[$objId] = New-Object System.Collections.ArrayList }
        if (-not ($byPrincipal[$objId] -contains $name)) { [void]$byPrincipal[$objId].Add($name) }
    }
    $script:_SICache['EligRolesMap'] = $byPrincipal
    return $byPrincipal
}

function Get-SIAppRolePermissionResolver {
    # Builds @{ <resourceSPid>|<appRoleId GUID> = <permission Value> } so we can
    # turn a SP's appRoleAssignments (which carry appRoleId GUIDs) into the
    # human-readable permission strings the catalog uses ("Directory.Read.All").
    # We pull all SPs once (already needed for discovery anyway) and harvest
    # their .appRoles[] -> {id, value}.
    param(
        [Parameter(Mandatory)][string]$Token
    )
    if ($script:_SICache.ContainsKey('AppRoleResolver')) { Write-SIInfo '[perms] appRole resolver (cache hit)'; return $script:_SICache['AppRoleResolver'] }
    $resolver = @{}
    $rows = Invoke-SIGraphPaged -RelativeUrl '/servicePrincipals?$select=id,appRoles' -Token $Token
    foreach ($sp in $rows) {
        $spId = [string]$sp.id
        if (-not $spId -or -not $sp.appRoles) { continue }
        foreach ($ar in $sp.appRoles) {
            $arId = [string]$ar.id
            $val  = [string]$ar.value
            if ($arId -and $val) { $resolver[("{0}|{1}" -f $spId, $arId)] = $val }
        }
    }
    $script:_SICache['AppRoleResolver'] = $resolver
    return $resolver
}

function Get-SISPAppRoleAssignments {
    # Per-SP: Application-permission grants (admin-consented). Returns the
    # human-readable permission Values resolved via the AppRole resolver.
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][hashtable]$AppRoleResolver
    )
    $perms = New-Object System.Collections.ArrayList
    try {
        $rows = Invoke-SIGraphPaged -RelativeUrl ('/servicePrincipals/{0}/appRoleAssignments' -f $ObjectId) -Token $Token
    } catch {
        return @()
    }
    foreach ($a in $rows) {
        $resourceId = [string]$a.resourceId
        $appRoleId  = [string]$a.appRoleId
        if (-not $resourceId -or -not $appRoleId) { continue }
        $val = $AppRoleResolver[("{0}|{1}" -f $resourceId, $appRoleId)]
        if ($val -and -not ($perms -contains $val)) { [void]$perms.Add($val) }
    }
    return $perms.ToArray()
}

function Get-SIRoleAssignedGroups {
    # identifies which GROUPS hold Entra directory roles (permanent
    # or PIM eligible). Output: @{<groupId> = @{Permanent=@(role); Eligible=@(role)}}.
    # We fetch group object types for all principalIds that appear in role
    # assignments (one /directoryObjects/getByIds batch) so we can filter to
    # actual groups (vs users + SPs in the same buckets).
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][hashtable]$PermanentRolesByPrincipal,    # from Get-SIEntraRoleAssignmentsByPrincipal
        [Parameter(Mandatory)][hashtable]$EligibleRolesByPrincipal      # from Get-SIEntraPIMEligibleByPrincipal
    )
    if ($script:_SICache.ContainsKey('GroupRoles')) { Write-SIInfo '[perms] role-assigned groups (cache hit)'; return $script:_SICache['GroupRoles'] }

    # Union of all principal IDs that appear in either map
    $allIds = New-Object System.Collections.Generic.HashSet[string]
    foreach ($id in $PermanentRolesByPrincipal.Keys) { [void]$allIds.Add($id) }
    foreach ($id in $EligibleRolesByPrincipal.Keys)  { [void]$allIds.Add($id) }
    if ($allIds.Count -eq 0) { return @{} }

    # /directoryObjects/getByIds is capped at 1000 per call; chunk + batch.
    $idArr = @($allIds)
    $byType = @{}        # principalId -> @odata.type ('#microsoft.graph.group' | '...user' | '...servicePrincipal')
    for ($i = 0; $i -lt $idArr.Count; $i += 1000) {
        $chunk = $idArr[$i..([Math]::Min($i+999, $idArr.Count-1))]
        $body  = @{ ids = $chunk; types = @('group','user','servicePrincipal') } | ConvertTo-Json -Compress
        try {
            $resp = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/directoryObjects/getByIds' `
                -Headers @{ Authorization = ('Bearer ' + $Token); 'Content-Type' = 'application/json' } `
                -Body $body -ErrorAction Stop
            foreach ($obj in $resp.value) {
                if ($obj.id -and $obj.'@odata.type') { $byType[[string]$obj.id] = [string]$obj.'@odata.type' }
            }
        } catch {
            Write-Warning ('directoryObjects/getByIds failed -- {0}' -f $_.Exception.Message)
        }
    }

    # Filter to GROUPS only and emit @{groupId = @{Permanent=...; Eligible=...}}
    $result = @{}
    foreach ($id in $allIds) {
        if ($byType[$id] -ne '#microsoft.graph.group') { continue }
        $perm = if ($PermanentRolesByPrincipal.ContainsKey($id)) { @($PermanentRolesByPrincipal[$id]) } else { @() }
        $elig = if ($EligibleRolesByPrincipal.ContainsKey($id))  { @($EligibleRolesByPrincipal[$id])  } else { @() }
        $result[$id] = @{ Permanent = $perm; Eligible = $elig }
    }
    $script:_SICache['GroupRoles'] = $result
    return $result
}

function Get-SIGroupTransitiveMembers {
    # for each role-assigned group, fetch transitiveMembers and
    # invert to @{<userOrSpId> = HashSet[<groupId>]} so per-asset lookup is O(1).
    # Only role-assigned groups are queried (typical tenant: 10-50 groups, not 1000s).
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][hashtable]$RoleAssignedGroupMap   # from Get-SIRoleAssignedGroups
    )
    if ($script:_SICache.ContainsKey('MemberToGroups')) { Write-SIInfo '[perms] group transitive members (cache hit)'; return $script:_SICache['MemberToGroups'] }
    $byMember = @{}     # userOrSpId -> HashSet[groupId]
    foreach ($gid in $RoleAssignedGroupMap.Keys) {
        try {
            $rows = Invoke-SIGraphPaged -RelativeUrl ('/groups/{0}/transitiveMembers?$select=id' -f $gid) -Token $Token
        } catch {
            Write-Warning ('transitiveMembers failed for group {0}: {1}' -f $gid, $_.Exception.Message)
            continue
        }
        foreach ($m in $rows) {
            $mid = [string]$m.id
            if (-not $mid) { continue }
            if (-not $byMember.ContainsKey($mid)) { $byMember[$mid] = New-Object System.Collections.Generic.HashSet[string] }
            [void]$byMember[$mid].Add($gid)
        }
    }
    $script:_SICache['MemberToGroups'] = $byMember
    return $byMember
}

function Get-SIPimForGroupsByPrincipal {
    # PIM-for-Groups: principals who are PIM-eligible OR have PIM-active membership
    # in a role-bearing group, but are NOT current static members. Without this,
    # users who can elevate INTO a role-bearing group (without being in it) are
    # missing from EntraRoles_Eligible.
    #
    # Two endpoints, both per-group (with $filter=groupId):
    #   /identityGovernance/privilegedAccess/group/eligibilitySchedules  -- not yet activated
    #   /identityGovernance/privilegedAccess/group/assignmentSchedules   -- already activated
    #
    # Both treated as "Eligible" downstream because the principal still requires
    # activation/membership-grant to actually USE the role.
    #
    # Returns @{<principalId> = HashSet[<groupId>]}
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][hashtable]$RoleAssignedGroupMap   # from Get-SIRoleAssignedGroups
    )
    if ($script:_SICache.ContainsKey('PimForGroupsMap')) { Write-SIInfo '[perms] PIM for Groups (cache hit)'; return $script:_SICache['PimForGroupsMap'] }
    Write-SIInfo ('[perms] PIM for Groups: scanning {0} role-bearing group(s)...' -f $RoleAssignedGroupMap.Count)
    $byPrincipal = @{}
    $totalRows = 0
    $_pimTotal = $RoleAssignedGroupMap.Count; $_pimIdx = 0
    Reset-SIProgress -Label 'PimForGroups' -ErrorAction SilentlyContinue
    foreach ($gid in $RoleAssignedGroupMap.Keys) {
        $_pimIdx++
        try { Write-SIProgress -Label 'PimForGroups' -Index $_pimIdx -Total $_pimTotal } catch { }
        foreach ($endpoint in @('eligibilitySchedules','assignmentSchedules')) {
            try {
                $rows = Invoke-SIGraphPaged -RelativeUrl ("/identityGovernance/privilegedAccess/group/{0}?`$filter=groupId eq '{1}'&`$select=principalId,groupId" -f $endpoint, $gid) -Token $Token
            } catch {
                # Tenant may lack Entra ID P2; skip silently per group/endpoint.
                continue
            }
            foreach ($r in $rows) {
                $principalId = [string]$r.principalId
                if (-not $principalId) { continue }
                if (-not $byPrincipal.ContainsKey($principalId)) {
                    $byPrincipal[$principalId] = New-Object System.Collections.Generic.HashSet[string]
                }
                if ($byPrincipal[$principalId].Add($gid)) { $totalRows++ }
            }
        }
    }
    Write-SIInfo ('[perms] PIM for Groups loaded: {0} principal->group entries across {1} principals' -f $totalRows, $byPrincipal.Count)
    $script:_SICache['PimForGroupsMap'] = $byPrincipal
    return $byPrincipal
}

function Get-SIRolesViaPimGroupChain {
    # Recursive expansion of nested PIM-for-Groups chains. Mirrors the v1
    # Get-AllGroupRoles helper. Loop-safe via $Visited.
    #   User -> PIM Group A (eligible) -> PIM Group B (eligible) -> Role
    # All roles surfaced via this chain are Eligible (the principal still
    # has to activate to become a member).
    # AllowEmptyCollection() on the HashSet params -- PS Mandatory binding
    # otherwise rejects an empty HashSet from the first call (no eligible
    # roles found yet, no groups visited yet).
    param(
        [Parameter(Mandatory)][string[]]$GroupIds,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$Eligible,
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$Visited,
        [Parameter(Mandatory)][hashtable]$RoleAssignedGroupMap,
        [Parameter(Mandatory)][hashtable]$PimGroupsByPrincipal
    )
    foreach ($gid in $GroupIds) {
        if (-not $Visited.Add($gid)) { continue }
        # Roles attached directly to this group -- both Permanent + Eligible go to Eligible
        # (because the principal isn't a current member; activation is required either way).
        if ($RoleAssignedGroupMap.ContainsKey($gid)) {
            $g = $RoleAssignedGroupMap[$gid]
            foreach ($r in $g.Permanent) { [void]$Eligible.Add([string]$r) }
            foreach ($r in $g.Eligible)  { [void]$Eligible.Add([string]$r) }
        }
        # Recurse: this group itself may be PIM-eligible to BECOME a member of another group.
        if ($PimGroupsByPrincipal.ContainsKey($gid)) {
            $nested = @($PimGroupsByPrincipal[$gid] | Where-Object { -not $Visited.Contains($_) })
            if ($nested.Count -gt 0) {
                Get-SIRolesViaPimGroupChain -GroupIds $nested -Eligible $Eligible `
                                             -Visited $Visited `
                                             -RoleAssignedGroupMap $RoleAssignedGroupMap `
                                             -PimGroupsByPrincipal $PimGroupsByPrincipal
            }
        }
    }
}

function Get-SIInheritedRolesForPrincipal {
    # Per-principal: walk the principal's role-via-group inheritance:
    #   1. Active transitive membership in role-bearing groups
    #   2. PIM-for-Groups eligibility/active (recursive nested chains)
    # Returns @{Permanent=string[]; Eligible=string[]}.
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][hashtable]$MemberToGroupsMap,        # from Get-SIGroupTransitiveMembers
        [Parameter(Mandatory)][hashtable]$RoleAssignedGroupMap,     # from Get-SIRoleAssignedGroups
        [hashtable]$PimGroupsByPrincipal = @{}                      # from Get-SIPimForGroupsByPrincipal (optional for back-compat)
    )
    $perm    = New-Object System.Collections.Generic.HashSet[string]
    $elig    = New-Object System.Collections.Generic.HashSet[string]
    $visited = New-Object System.Collections.Generic.HashSet[string]

    # 1. Active membership -- principal IS a member, so direct roles flow through unchanged.
    if ($MemberToGroupsMap.ContainsKey($ObjectId)) {
        foreach ($gid in $MemberToGroupsMap[$ObjectId]) {
            [void]$visited.Add($gid)
            if (-not $RoleAssignedGroupMap.ContainsKey($gid)) { continue }
            $g = $RoleAssignedGroupMap[$gid]
            foreach ($r in $g.Permanent) { [void]$perm.Add([string]$r) }
            foreach ($r in $g.Eligible)  { [void]$elig.Add([string]$r) }
        }
    }

    # 2. PIM-for-Groups -- principal can ELEVATE into the group; everything from this
    #    chain is Eligible. Recursive helper handles nested PIM-into-PIM.
    if ($PimGroupsByPrincipal.ContainsKey($ObjectId)) {
        $eligibleGroupIds = @($PimGroupsByPrincipal[$ObjectId] | Where-Object { -not $visited.Contains($_) })
        if ($eligibleGroupIds.Count -gt 0) {
            Get-SIRolesViaPimGroupChain -GroupIds $eligibleGroupIds -Eligible $elig `
                                         -Visited $visited `
                                         -RoleAssignedGroupMap $RoleAssignedGroupMap `
                                         -PimGroupsByPrincipal $PimGroupsByPrincipal
        }
    }

    return @{ Permanent = @($perm); Eligible = @($elig) }
}

function Get-SIAzureDelegationsByPrincipal {
    # Azure RBAC role assignments by ObjectId, scope-aware
    # tier (Max(RoleTier, ScopeLevel)) precomputed per assignment. Mirrors
    # legacy IAC's $azureDelegationLookup. Uses Az.Resources cmdlets --
    # caller must have run Connect-AzAccount.
    # Returns @{<objectId> = @(@{RoleName, Scope, ScopeLabel, SubscriptionId,
    #                            SubscriptionName, PrincipalType, PrincipalName,
    #                            RoleTier, ScopeLevel, EffectiveTier})}
    [CmdletBinding()]
    param(
        [string[]]$ExcludeSubscriptionPatterns = @()
    )
    if ($script:_SICache.ContainsKey('AzureLookup')) { Write-SIInfo '[perms] Azure RBAC delegations (cache hit)'; return $script:_SICache['AzureLookup'] }
    $lookup = @{}
    $count  = 0

    # Tier helpers need to be loaded (catalog computer dot-sources at module init)
    if (-not (Get-Command Get-SITierFromAzureRoles -ErrorAction SilentlyContinue)) {
        $catModule = Join-Path $PSScriptRoot 'IdentityCatalogTierComputer.ps1'
        if (Test-Path $catModule) {
            . $catModule
            Initialize-SIIdentityCatalog | Out-Null
        } else {
            Write-Warning 'Get-SIAzureDelegationsByPrincipal: catalog tier computer not loaded; skipping.'
            return $lookup
        }
    }

    try {
        $subs = @(Get-AzSubscription -ErrorAction Stop | Where-Object { $_.State -eq 'Enabled' })
    } catch {
        Write-Warning ('Get-AzSubscription failed -- Azure delegations skipped: {0}' -f $_.Exception.Message)
        return $lookup
    }

    if ($ExcludeSubscriptionPatterns.Count -gt 0) {
        $subs = @($subs | Where-Object {
            $sn = $_.Name
            -not ($ExcludeSubscriptionPatterns | Where-Object { $sn -like $_ })
        })
    }
    Write-SIInfo ('[perms] Azure RBAC: scanning {0} subscription(s) for role assignments' -f $subs.Count)

    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        foreach ($sub in $subs) {
            try {
                Set-AzContext -SubscriptionId $sub.Id -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
                $assignments = @(Get-AzRoleAssignment -ErrorAction Stop -WarningAction SilentlyContinue)
            } catch {
                Write-Warning ('  sub {0}: role-assignment read failed -- {1}' -f $sub.Name, $_.Exception.Message)
                continue
            }
            foreach ($a in $assignments) {
                $oid = [string]$a.ObjectId
                if ([string]::IsNullOrWhiteSpace($oid)) { continue }
                $roleName = [string]$a.RoleDefinitionName
                $scope    = [string]$a.Scope
                $roleTier = Get-SITierFromAzureRoles -Roles @($roleName)
                if ($null -eq $roleTier) { $roleTier = 2 }
                $scopeLvl = Get-SIAzureScopeLevel  -Scope $scope
                $effTier  = [Math]::Max($roleTier, $scopeLvl)
                $entry = [ordered]@{
                    RoleName         = $roleName
                    Scope            = $scope
                    ScopeLabel       = Get-SIAzureScopeLabel -Scope $scope
                    SubscriptionId   = [string]$sub.Id
                    SubscriptionName = [string]$sub.Name
                    PrincipalType    = [string]$a.ObjectType
                    PrincipalName    = [string]$a.DisplayName
                    RoleTier         = $roleTier
                    ScopeLevel       = $scopeLvl
                    EffectiveTier    = $effTier
                }
                if (-not $lookup.ContainsKey($oid)) { $lookup[$oid] = New-Object System.Collections.ArrayList }
                [void]$lookup[$oid].Add($entry)
                $count++
            }
        }
    } finally {
        $ProgressPreference = $prevProgress
    }
    Write-SIInfo ('[perms] Azure RBAC delegations: {0} assignments across {1} principals' -f $count, $lookup.Count)
    $script:_SICache['AzureLookup'] = $lookup
    return $lookup
}

function Get-SIIdentityInfoByObjectId {
    # bulk pull Defender XDR IdentityInfo (synced from on-prem AD +
    # Entra) and bucket by AccountObjectId for O(1) per-user lookup. Returns
    # @{<userObjectId> = <IdentityInfo row>} where each row carries:
    #   GroupMembership   (string, comma-separated on-prem AD groups)
    #   IsMFARegistered, IsAccountEnabled, IsServiceAccount
    #   RiskLevel, RiskState, EntityRiskScore, BlastRadius
    #   InvestigationPriority, AssignedRoles
    #   AccountUPN, AccountDisplayName, OnPremisesDistinguishedName
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [int]$LookbackDays = 14
    )
    if ($script:_SICache.ContainsKey('IdentityInfo')) { Write-SIInfo '[perms] IdentityInfo (cache hit)'; return $script:_SICache['IdentityInfo'] }
    $byOid = @{}
    if ([string]::IsNullOrWhiteSpace($WorkspaceResourceId)) {
        Write-Warning '$global:SI_WorkspaceResourceId not set -- IdentityInfo fetch skipped.'
        return $byOid
    }
    try {
        $ws = Resolve-SIWorkspaceFromResourceId -ResourceId $WorkspaceResourceId
        $wsGuid = $ws.CustomerId.Guid
    } catch {
        Write-Warning ('Workspace resolve failed -- IdentityInfo skipped: {0}' -f $_.Exception.Message)
        return $byOid
    }

    $kql = @"
IdentityInfo
| where TimeGenerated > ago($($LookbackDays)d)
| summarize arg_max(TimeGenerated, *) by AccountObjectId
| project AccountObjectId, AccountUPN, AccountDisplayName, AccountSID, AccountCloudSID,
          OnPremisesAccountObjectId, OnPremisesDistinguishedName, AccountDomain,
          IsAccountEnabled, IsMFARegistered, IsServiceAccount,
          AssignedRoles, GroupMembership,
          BlastRadius, Tags,
          InvestigationPriority, InvestigationPriorityPercentile,
          RiskLevel, RiskState, EntityRiskScore,
          AccountCreationTime, DeletedDateTime, LastSeenDate
"@

    try {
        $resp = Invoke-AzOperationalInsightsQuery -WorkspaceId $wsGuid -Query $kql -ErrorAction Stop
    } catch {
        Write-Warning ('IdentityInfo query failed -- AD groups + activity signals will be empty: {0}' -f $_.Exception.Message)
        return $byOid
    }

    foreach ($row in $resp.Results) {
        $oid = [string]$row.AccountObjectId
        if ([string]::IsNullOrWhiteSpace($oid)) { continue }
        $byOid[$oid] = $row
    }
    Write-SIInfo ('[perms] IdentityInfo: {0} users with on-prem / Defender enrichment' -f $byOid.Count)
    $script:_SICache['IdentityInfo'] = $byOid
    return $byOid
}

function ConvertTo-SIADGroupNames {
    # IdentityInfo.GroupMembership is a JSON array string of {GroupName, GroupSID, GroupType}.
    # Some tenants ship it as a plain string, other as the JSON. Normalise to string[].
    param($Raw)
    if ($null -eq $Raw)                           { return @() }
    if ($Raw -is [System.Array]) {
        return @($Raw | ForEach-Object {
            if ($_ -is [System.Collections.IDictionary] -and $_.Contains('GroupName')) { [string]$_['GroupName'] }
            elseif ($_.PSObject -and $_.PSObject.Properties['GroupName']) { [string]$_.GroupName }
            else { [string]$_ }
        } | Where-Object { $_ })
    }
    $s = [string]$Raw
    if ([string]::IsNullOrWhiteSpace($s)) { return @() }
    # Try JSON parse
    try {
        $obj = $s | ConvertFrom-Json -ErrorAction Stop
        if ($obj -is [System.Array]) {
            return @($obj | ForEach-Object {
                if ($_.PSObject.Properties['GroupName']) { [string]$_.GroupName } else { [string]$_ }
            } | Where-Object { $_ })
        }
    } catch { }
    # Fallback: comma-separated
    return @($s -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-SISpnSignInLastActivity {
    <#
        Bulk-fetch SP last sign-in. Returns @{<spObjectId> = <DateTime>}.

        cascade three sources -- try Defender XDR's modern GA
        EntraIdSpnSignInEvents first; fall back to AADSpnSignInEventsBeta;
        lastly fall back to LA AADServicePrincipalSignInLogs +
        AADManagedIdentitySignInLogs (the original v2.1 path). Errors only
        surface if all three fail. WorkspaceResourceId param kept for API
        compatibility but unused now -- routing handled by Invoke-SIHuntingQuery.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [int]$LookbackDays = 90
    )
    if ($script:_SICache.ContainsKey('SpnSignIn')) { Write-SIInfo '[perms] SP sign-in (cache hit)'; return $script:_SICache['SpnSignIn'] }
    $byOid = @{}
    $null = $WorkspaceResourceId   # explicit unused-but-required param

    # lazy-load HuntingQuery.ps1 -- IdentityRoleFetcher.ps1 may be
    # imported before HuntingQuery.ps1 in some launcher dot-source orders, so
    # Invoke-SIHuntingQuery isn't in scope yet. Mirrors the lazy-load pattern
    # in Build-EndpointProfileRow.ps1 for Get-SIRiskFactors / Convert-EgBlob.
    if (-not (Get-Command -Name Invoke-SIHuntingQuery -ErrorAction SilentlyContinue)) {
        . (Join-Path $PSScriptRoot 'HuntingQuery.ps1')
    }

    $xdrTail = @"
| where Timestamp > ago($($LookbackDays)d)
| project AccountObjectId, Timestamp
| summarize LastSignIn = max(Timestamp) by AccountObjectId
| extend ServicePrincipalId = AccountObjectId
| project-away AccountObjectId
"@
    $laQuery = @"
union isfuzzy=true
    (AADServicePrincipalSignInLogs
        | where TimeGenerated > ago($($LookbackDays)d)
        | project ServicePrincipalId, TimeGenerated
        | summarize LastSignIn = max(TimeGenerated) by ServicePrincipalId),
    (AADManagedIdentitySignInLogs
        | where TimeGenerated > ago($($LookbackDays)d)
        | project ServicePrincipalId, TimeGenerated
        | summarize LastSignIn = max(TimeGenerated) by ServicePrincipalId)
| summarize LastSignIn = max(LastSignIn) by ServicePrincipalId
"@

    $attempts = @(
        @{ Label = 'EntraIdSpnSignInEvents (XDR GA)';     Engine = 'DefenderGraph'; Query = "EntraIdSpnSignInEvents`n$xdrTail" },
        @{ Label = 'AADSpnSignInEventsBeta (XDR legacy)'; Engine = 'DefenderGraph'; Query = "AADSpnSignInEventsBeta`n$xdrTail" },
        @{ Label = 'AADServicePrincipalSignInLogs + AADManagedIdentitySignInLogs (LA)'; Engine = 'LogAnalytics'; Query = $laQuery }
    )

    # For LA route, target the Defender workspace (where AAD*SignInLogs live)
    # if customer has set SI_DefenderWorkspaceResourceId; else fall back to
    # SI_WorkspaceResourceId. Defender XDR routes (DefenderGraph) ignore this --
    # they use the SPN's Graph token directly.
    $laTargetWs = if (-not [string]::IsNullOrWhiteSpace([string]$global:SI_DefenderWorkspaceResourceId)) {
        [string]$global:SI_DefenderWorkspaceResourceId
    } else {
        [string]$global:SI_WorkspaceResourceId
    }

    $rows   = $null
    $errors = New-Object System.Collections.Generic.List[string]
    foreach ($a in $attempts) {
        $where = if ($a.Engine -eq 'LogAnalytics') { " (workspace=$laTargetWs)" } else { '' }
        Write-SIInfo ("[perms] SP sign-in source: trying {0}{1}..." -f $a.Label, $where)
        $w = $null
        $r = $null
        try {
            if ($a.Engine -eq 'LogAnalytics') {
                $r = @(Invoke-SIHuntingQuery -Query $a.Query -QueryEngine $a.Engine -WorkspaceResourceId $laTargetWs -WarningVariable w -WarningAction SilentlyContinue)
            } else {
                $r = @(Invoke-SIHuntingQuery -Query $a.Query -QueryEngine $a.Engine -WarningVariable w -WarningAction SilentlyContinue)
            }
        } catch {
            $errors.Add(("{0}: {1}" -f $a.Label, $_.Exception.Message))
            continue
        }
        if ($w -and $w.Count -gt 0) {
            $errors.Add(("{0}: {1}" -f $a.Label, ($w -join ' | ')))
            continue
        }
        $rows = $r
        Write-SIInfo ("[perms] SP sign-in source: OK -- {0} rows from {1}" -f $rows.Count, $a.Label)
        break
    }

    if ($null -eq $rows) {
        Write-SIWarn '[perms] SP sign-in lookup failed across all sources; LastSignIn for SPs will be empty'
        foreach ($e in $errors) { Write-SIWarn ("  - {0}" -f $e) }
        $script:_SICache['SpnSignIn'] = $byOid
        return $byOid
    }

    foreach ($row in $rows) {
        $oid = [string]$row.ServicePrincipalId
        if (-not $oid) { continue }
        try { $byOid[$oid] = [datetime]$row.LastSignIn } catch { }
    }
    Write-SIInfo ('[perms] SP sign-in: {0} principals with sign-in activity in last {1}d' -f $byOid.Count, $LookbackDays)
    $script:_SICache['SpnSignIn'] = $byOid
    return $byOid
}

function ConvertTo-SICustomSecurityAttributes {
    # Normalises the customSecurityAttributes block (PSCustomObject of attribute
    # sets, each containing key/value pairs) into a clean dictionary, stripping
    # OData annotation keys. Returns @{} when none present.
    param($Raw)
    if ($null -eq $Raw) { return @{} }
    $result = [ordered]@{}
    $keys = if ($Raw -is [System.Collections.IDictionary]) { @($Raw.Keys) }
            else { @($Raw.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($setName in $keys) {
        if ($setName -like '*@odata*') { continue }
        $setBlock = if ($Raw -is [System.Collections.IDictionary]) { $Raw[$setName] } else { $Raw.$setName }
        if (-not $setBlock) { continue }
        $setResult = [ordered]@{}
        $setKeys = if ($setBlock -is [System.Collections.IDictionary]) { @($setBlock.Keys) }
                   else { @($setBlock.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($k in $setKeys) {
            if ($k -like '*@odata*') { continue }
            $v = if ($setBlock -is [System.Collections.IDictionary]) { $setBlock[$k] } else { $setBlock.$k }
            if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
                $setResult[$k] = @($v | ForEach-Object { [string]$_ } | Where-Object { $_ })
            } else {
                $setResult[$k] = [string]$v
            }
        }
        if ($setResult.Count -gt 0) { $result[$setName] = $setResult }
    }
    return $result
}

function Get-SIDaysSince {
    param($DateValue)
    if (-not $DateValue) { return -1 }
    try {
        $d = if ($DateValue -is [datetime]) { $DateValue } else { [datetime]$DateValue }
        return [int]([datetime]::UtcNow - $d).TotalDays
    } catch { return -1 }
}

function Get-SIPrincipalAzureTier {
    # Per-principal: Min EffectiveTier across ObjectId + inherited group IDs.
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][hashtable]$AzureLookup,
        [string[]]$InheritedGroupIds = @()
    )
    $allIds = @($ObjectId) + @($InheritedGroupIds)
    $minTier = $null
    foreach ($id in $allIds) {
        if (-not $AzureLookup.ContainsKey($id)) { continue }
        foreach ($e in $AzureLookup[$id]) {
            $t = [int]$e.EffectiveTier
            if ($null -eq $minTier -or $t -lt $minTier) { $minTier = $t }
        }
    }
    return $minTier   # null when no Az delegations
}

function Get-SISPOauth2Grants {
    # Per-SP: Delegated-permission grants (oauth2). Permission strings are
    # already human-readable in the .scope field (space-separated).
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$ObjectId
    )
    $perms = New-Object System.Collections.ArrayList
    try {
        $rows = Invoke-SIGraphPaged -RelativeUrl ('/servicePrincipals/{0}/oauth2PermissionGrants' -f $ObjectId) -Token $Token
    } catch {
        return @()
    }
    foreach ($g in $rows) {
        if ($g.scope) {
            foreach ($s in ([string]$g.scope -split '\s+')) {
                if ($s -and -not ($perms -contains $s)) { [void]$perms.Add($s) }
            }
        }
    }
    return $perms.ToArray()
}

# Exposure Graph identity enrichment.
# Bulk-fetches EG nodes for identity NodeLabels (user, group, serviceprincipal,
# managedidentity) once per snapshot, indexes by AAD ObjectId so per-asset
# lookup is O(1). Mirrors the bulk-fetch + cache pattern of the other
# Get-SI* fetchers in this module.
#
# Returns @{ <aadObjectId> = pscustomobject{NodeId, NodeLabel, NodeName,
# Categories, EntityIds, RawData} }. The RawData field is the entire
# NodeProperties.rawData blob -- the schema-driven row builder
# (Build-IdentityProfileRow) walks arbitrary paths declared in
# identity.schema.json (source=exposureGraph, sourcePath=eg.node.NodeProperties.rawData.<path>).
# Adding a new EG-sourced flat column becomes a JSON edit, no engine code.
function Get-SIExposureGraphIdentities {
    [CmdletBinding()]
    param()

    if ($script:_SICache.ContainsKey('EgIdentitiesMap')) {
        Write-SIInfo '[perms] EG identity nodes (cache hit)'
        return $script:_SICache['EgIdentitiesMap']
    }
    $egMap = @{}

    # file moved from identity-catalog/ to engine/shared/.
    # $PSScriptRoot now = v2.2/engine/asset-profiling/shared/; three parents -> v2.2/
    $siRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $hqPath  = Join-Path $siRoot 'engine\asset-profiling\shared\HuntingQuery.ps1'
    if (-not (Test-Path $hqPath)) {
        Write-Warning ('Get-SIExposureGraphIdentities: HuntingQuery.ps1 not found at {0} -- skipping' -f $hqPath)
        return $egMap
    }
    . $hqPath

    Write-SIInfo '[perms] fetching identity nodes from Exposure Graph (per-label, bucket if > threshold)...'

    # Two-pass per label:
    #   1. count probe -- cheap, tells us how many rows we'll need
    #   2. fetch -- single query when count <= threshold; hash-bucketed
    #      otherwise. Bucketing splits a huge result set across multiple
    #      runHuntingQuery calls so each response stays under the API
    #      payload cap (NodeProperties rawData can be multi-KB per row).
    # Default threshold 30000 -- the Defender Advanced Hunting UI's default
    # row cap. Customer-tunable via $global:SI_EgIdentityBucketThreshold.
    $bucketThreshold = if ($global:SI_EgIdentityBucketThreshold) { [int]$global:SI_EgIdentityBucketThreshold } else { 30000 }
    $labels = @('user','serviceprincipal','managedidentity','group')
    $rows = New-Object System.Collections.ArrayList

    foreach ($label in $labels) {
        $rowCount = 0
        try {
            $countQ   = "ExposureGraphNodes | where NodeLabel == '$label' | count"
            $countRes = @(Invoke-SIHuntingQuery -Query $countQ -QueryEngine DefenderGraph)
            if ($countRes.Count -gt 0) {
                $first = $countRes[0]
                if ($first.PSObject.Properties['Count']) { $rowCount = [int]$first.Count }
                elseif ($first.PSObject.Properties['count_']) { $rowCount = [int]$first.count_ }
            }
        } catch {
            Write-Warning ('  EG count probe failed for label={0} -- {1}; falling back to bucketed fetch' -f $label, $_.Exception.Message)
            $rowCount = $bucketThreshold + 1   # force bucketed path on probe failure
        }

        $proj = "project NodeId, NodeLabel, NodeName, Categories, EntityIds, NodeProperties"
        $fetched = 0
        if ($rowCount -le $bucketThreshold) {
            # Single query
            try {
                $kql   = "ExposureGraphNodes | where NodeLabel == '$label' | $proj"
                $chunk = @(Invoke-SIHuntingQuery -Query $kql -QueryEngine DefenderGraph)
                foreach ($r in $chunk) { [void]$rows.Add($r) }
                $fetched = $chunk.Count
            } catch {
                Write-Warning ('  EG fetch failed for label={0} -- {1}' -f $label, $_.Exception.Message)
            }
            Write-SIInfo ('     [{0,-18}] count={1,5}  fetched={2,5}  (single)' -f $label, $rowCount, $fetched)
        } else {
            # Bucketed: ceil(rowCount / threshold) buckets, hash-distributed.
            $bucketCount = [int][Math]::Ceiling($rowCount / [double]$bucketThreshold)
            for ($b = 0; $b -lt $bucketCount; $b++) {
                # KQL hash(NodeId, N) returns a stable value in [0, N-1] (it does the
                # modulo itself) -- partitions every node into exactly one bucket so the
                # N bucket queries union to the full set. (Was hash_djb2(...) % N, which
                # is NOT a KQL function -> "Unknown function: 'hash_djb2'" BadRequest on
                # every bucket, breaking EG identity + RA group correlation. 2026-06-18.)
                $kql = ("ExposureGraphNodes | where NodeLabel == '{0}' | extend _bucket = hash(NodeId, {1}) | where _bucket == {2} | {3}" -f $label, $bucketCount, $b, $proj)
                try {
                    $chunk = @(Invoke-SIHuntingQuery -Query $kql -QueryEngine DefenderGraph)
                    foreach ($r in $chunk) { [void]$rows.Add($r) }
                    $fetched += $chunk.Count
                } catch {
                    Write-Warning ('  EG fetch failed for label={0} bucket={1}/{2} -- {3}' -f $label, $b, $bucketCount, $_.Exception.Message)
                }
            }
            Write-SIInfo ('     [{0,-18}] count={1,5}  fetched={2,5}  ({3} buckets)' -f $label, $rowCount, $fetched, $bucketCount)
        }
    }

    if ($rows.Count -eq 0) {
        Write-Warning '  EG returned 0 identity nodes (license or permission issue?)'
        $script:_SICache['EgIdentitiesMap'] = $egMap
        return $egMap
    }

    $skipNoProps = 0; $skipNoOid = 0; $kept = 0
    $perLabelTotal = @{}; $perLabelKept = @{}; $perLabelSkipNoOid = @{}
    $diagSamplesPerLabel = @{}   # per-label: capture first 1 raw EntityIds payload that fails to extract -- helps diagnose schema drift
    $_total = $rows.Count; $_i = 0
    Reset-SIProgress -Label 'EgIdentityNodes' -ErrorAction SilentlyContinue
    foreach ($row in $rows) {
        $_i++
        try { Write-SIProgress -Label 'EgIdentityNodes' -Index $_i -Total $_total } catch { }
        $label = [string]$row.NodeLabel
        if (-not $perLabelTotal.ContainsKey($label)) { $perLabelTotal[$label] = 0; $perLabelKept[$label] = 0; $perLabelSkipNoOid[$label] = 0 }
        $perLabelTotal[$label]++

        $entityIdsRaw = $row.EntityIds
        $entityIds = if ($entityIdsRaw -is [string]) { try { $entityIdsRaw | ConvertFrom-Json } catch { @() } } else { $entityIdsRaw }
        $nodeProps = if ($row.NodeProperties -is [string]) { try { $row.NodeProperties | ConvertFrom-Json } catch { $null } } else { $row.NodeProperties }
        if (-not $nodeProps) { $skipNoProps++; continue }
        # rawData may be nested under .rawData OR may BE the top-level NodeProperties blob (varies by EG version).
        $rawData = if ($nodeProps.PSObject.Properties['rawData'] -and $nodeProps.rawData) { $nodeProps.rawData } else { $nodeProps }

        # AadObjectId discovery -- iterate ALL EntityIds entries (groups have
        # SecurityIdentifier at [0] and AadObjectId at [1]), case-insensitive type
        # match. The id format is either a bare GUID or the legacy
        # 'tenantid=<guid>;objectid=<guid>' form -- the regex pulls any GUID
        # following 'objectid=' (length-agnostic). Fallback: any 36-char GUID
        # anywhere in the id string. rawData.<various oid keys> as last resort.
        $aadOid = $null
        $sid    = $null
        foreach ($eid in @($entityIds)) {
            # EG returns EntityIds as an array of JSON-encoded
            # STRINGS (not objects). ConvertFrom-Json on the outer array gives
            # an array of strings -- each entry still needs a second parse to
            # become an object with .type / .id properties. Without this
            # second-pass parse, $eid.type was always $null and EVERY service-
            # principal + many users got skip-no-aadOid'd silently.
            if ($eid -is [string]) {
                try { $eid = $eid | ConvertFrom-Json } catch { continue }
            }
            $etype = ([string]$eid.type).ToLowerInvariant()
            $raw   = [string]$eid.id
            if (-not $etype -or -not $raw) { continue }
            if ($etype -eq 'aadobjectid' -and -not $aadOid) {
                if ($raw -match 'objectid=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') { $aadOid = $matches[1].ToLower() }
                elseif ($raw -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')      { $aadOid = $matches[1].ToLower() }
            } elseif ($etype -eq 'securityidentifier' -and -not $sid) {
                $sid = $raw.ToLower()
            }
        }
        # rawData fallbacks -- different EG node types expose the AAD id under
        # different property names.
        if (-not $aadOid -and $rawData) {
            # added 'aadId' (used by EG group nodes per actual
            # rawData schema -- previously missing from the fallback list, so
            # groups whose only AAD identifier was rawData.aadId got skipped).
            foreach ($key in @('aadId','accountObjectId','objectId','aadObjectId','groupId','principalId','userId','id')) {
                if ($rawData.PSObject.Properties[$key] -and $rawData.$key) {
                    $cand = [string]$rawData.$key
                    if ($cand -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') { $aadOid = $matches[1].ToLower(); break }
                }
            }
        }
        if (-not $aadOid) {
            $skipNoOid++; $perLabelSkipNoOid[$label]++
            # Capture one diagnostic sample per label so the next run prints
            # the actual EntityIds + rawData key list -- no guessing about what
            # shape the API returned.
            if (-not $diagSamplesPerLabel.ContainsKey($label)) {
                $entitySample = if ($entityIdsRaw -is [string]) { $entityIdsRaw } else { ($entityIdsRaw | ConvertTo-Json -Compress -Depth 5) }
                $rawKeys      = if ($rawData) { (@($rawData.PSObject.Properties.Name) -join ',') } else { '<no rawData>' }
                $diagSamplesPerLabel[$label] = @{
                    EntitySample = if ($entitySample.Length -gt 200) { $entitySample.Substring(0,200) + '...' } else { $entitySample }
                    RawKeys      = if ($rawKeys.Length -gt 200) { $rawKeys.Substring(0,200) + '...' } else { $rawKeys }
                }
            }
            continue
        }

        $entry = [pscustomobject]@{
            NodeId     = [string]$row.NodeId
            NodeLabel  = $label
            NodeName   = [string]$row.NodeName
            Categories = $row.Categories
            EntityIds  = $entityIds
            RawData    = $rawData
        }
        # Multi-key indexing: AAD object id (primary), SID (groups via on-prem SID),
        # NodeName lowercased (display-name lookup), NodeId (EG-native lookup).
        $egMap[$aadOid] = $entry
        if ($sid) { $egMap[$sid] = $entry }
        if ($row.NodeName) {
            $nameKey = ([string]$row.NodeName).ToLowerInvariant()
            if (-not $egMap.ContainsKey($nameKey)) { $egMap[$nameKey] = $entry }
        }
        if ($row.NodeId) {
            $idKey = ([string]$row.NodeId).ToLowerInvariant()
            if (-not $egMap.ContainsKey($idKey)) { $egMap[$idKey] = $entry }
        }
        $kept++; $perLabelKept[$label]++
    }

    Write-SIInfo ('[perms] EG identity nodes: {0} entries indexed (rows={1}, skip-no-props={2}, skip-no-aadOid={3})' -f $egMap.Count, $rows.Count, $skipNoProps, $skipNoOid)
    foreach ($k in ($perLabelTotal.Keys | Sort-Object)) {
        Write-SIInfo ('     [{0,-18}] total={1,5}  kept={2,5}  skip-no-aadOid={3}' -f $k, $perLabelTotal[$k], $perLabelKept[$k], $perLabelSkipNoOid[$k])
    }
    if ($global:SI_Verbose) {
        foreach ($k in ($diagSamplesPerLabel.Keys | Sort-Object)) {
            Write-SIInfo ('     [{0,-18}] sample EntityIds: {1}' -f $k, $diagSamplesPerLabel[$k].EntitySample)
            Write-SIInfo ('     [{0,-18}] sample rawData keys: {1}' -f $k, $diagSamplesPerLabel[$k].RawKeys)
        }
    }
    if ($egMap.Count -eq 0 -and ($skipNoProps + $skipNoOid) -gt 0) {
        Write-Warning ('  EG: parsed 0 of {0} nodes. Sample row keys: {1}' -f `
            $rows.Count, (($rows[0].PSObject.Properties.Name) -join ','))
    }
    $script:_SICache['EgIdentitiesMap'] = $egMap
    return $egMap
}
