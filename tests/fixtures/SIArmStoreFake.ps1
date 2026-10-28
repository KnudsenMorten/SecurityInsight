#Requires -Version 5.1
<#
    A FAKE AZURE RESOURCE MANAGER for the private-networking (#681) and customer-managed-key (#683) tests: an in-memory
    store of resources by path, answering the -Arm seam { param([string]$Method, [string]$Path, $Body) } of
    setup\_shared\SI-PrivateNetwork.ps1 / SI-CustomerKeys.ps1 and the cut-over scripts.
      GET     the resource ($null = not there); a collection = its direct children { value = @(...) }; a subscription-level
              list (/subscriptions/<s>/providers/<type>) = every resource of that type in any resource group
      PUT     stores the body as the resource (id, name, provisioningState Succeeded, plus what Azure fills in per type)
      PATCH   merges the body into the resource
      DELETE  removes the resource and everything under it
    Every write is logged in $global:SIArmStore.Writes ('<METHOD> <path>'). Flags on $global:SIArmStore change behaviour:
      PendingEndpoints   private endpoints stay 'Pending' (never approved)
      RefuseKeyAccess    the first N writes that switch a resource to a Key Vault key fail "AzureKeyVaultMissingPermissions"
      ClusterState       the provisioning state a new Log Analytics cluster gets (default Succeeded)
      RefuseWrites       path prefixes (lower case) a write under which is refused 'AuthorizationFailed' (#866: the customer's hub)
    State and helpers are global (the scripts under test run in their own scope); New-SIArmStore resets the state, Remove-SIArmStore (AfterAll) drops the state and the helpers.
#>

function global:New-SIArmStore {
    $global:SIArmStore = @{ Items = [ordered]@{}; Writes = New-Object System.Collections.Generic.List[string]; PendingEndpoints = $false; RefuseKeyAccess = 0; ClusterState = 'Succeeded'; RefuseWrites = @(); Graph = @{}; Members = @{}; ServicePrincipals = @{} }
}
function global:Remove-SIArmStore { Remove-Variable -Scope Global -Name SIArmStore, SIArmStoreFake, SIArmStoreGraph -ErrorAction SilentlyContinue; foreach ($n in 'New-SIArmStore', 'ConvertTo-SIArmStoreObject', 'ConvertTo-SIArmStoreHash', 'Merge-SIArmStoreHash', 'Set-SIArmStoreItem', 'Get-SIArmStoreItem') { Remove-Item -Path ('Function:\' + $n) -ErrorAction SilentlyContinue } }

function global:ConvertTo-SIArmStoreObject { param($Value) if ($null -eq $Value) { return $null }; ($Value | ConvertTo-Json -Depth 40 -Compress) | ConvertFrom-Json }
function global:ConvertTo-SIArmStoreHash {
    param($Object)
    if ($null -eq $Object) { return $null }
    if ($Object -is [string] -or $Object -is [ValueType]) { return $Object }
    if ($Object -is [System.Collections.IDictionary]) { $h = [ordered]@{}; foreach ($k in @($Object.Keys)) { $h[[string]$k] = ConvertTo-SIArmStoreHash $Object[$k] }; return $h }
    if ($Object -is [System.Collections.IEnumerable]) { return , @(foreach ($i in $Object) { ConvertTo-SIArmStoreHash $i }) }
    $h = [ordered]@{}; foreach ($p in $Object.PSObject.Properties) { $h[$p.Name] = ConvertTo-SIArmStoreHash $p.Value }; $h
}
function global:Merge-SIArmStoreHash {
    param($Into, $From)
    foreach ($k in @($From.Keys)) {
        if ($From[$k] -is [System.Collections.IDictionary] -and $Into.Contains($k) -and $Into[$k] -is [System.Collections.IDictionary]) { Merge-SIArmStoreHash $Into[$k] $From[$k] }
        else { $Into[$k] = $From[$k] }
    }
}

function global:Set-SIArmStoreItem {
    <# Seeds a resource (a hashtable with at least id). #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Resource)
    $id = [string]$Resource['id']
    if (-not $Resource.Contains('name')) { $Resource['name'] = ($id -split '/')[-1] }
    $global:SIArmStore.Items[$id.ToLowerInvariant()] = ConvertTo-SIArmStoreHash $Resource
}
function global:Get-SIArmStoreItem { param([string]$Id) $global:SIArmStore.Items[$Id.TrimEnd('/').ToLowerInvariant()] }

$global:SIArmStoreFake = {
    param([string]$Method, [string]$Path, $Body)
    $S = $global:SIArmStore
    $p = (($Path -split '\?')[0]).TrimEnd('/'); $key = $p.ToLowerInvariant()
    # an Azure Resource Graph query (#866) is a read, not a write
    if ($Method -ne 'GET' -and $p -notmatch '(?i)/providers/Microsoft\.ResourceGraph/resources$') { $S.Writes.Add(('{0} {1}' -f $Method, $p)) }
    if ($Method -ne 'GET' -and @(@($S['RefuseWrites']) | Where-Object { $_ -and $key.StartsWith(([string]$_).ToLowerInvariant()) }).Count) { throw ('Azure answered 403: AuthorizationFailed -- the client may not perform action on scope {0}' -f $p) }
    switch ($Method) {
        'GET' {
            if ($S.Items.Contains($key)) { return (ConvertTo-SIArmStoreObject $S.Items[$key]) }
            $kids = @($S.Items.Keys | Where-Object { $_.StartsWith($key + '/') -and ($_.Substring($key.Length + 1) -notmatch '/') })
            $m = [regex]::Match($key, '^/subscriptions/([^/]+)/providers/(.+)$')
            if (-not $kids.Count -and $m.Success) {
                $re = '^/subscriptions/{0}/resourcegroups/[^/]+/providers/{1}/[^/]+$' -f [regex]::Escape($m.Groups[1].Value), [regex]::Escape($m.Groups[2].Value)
                $kids = @($S.Items.Keys | Where-Object { $_ -match $re })
            }
            if ($kids.Count) { return [pscustomobject]@{ value = @($kids | ForEach-Object { ConvertTo-SIArmStoreObject $S.Items[$_] }) } }
            return $null
        }
        'DELETE' { foreach ($k in @($S.Items.Keys | Where-Object { $_ -eq $key -or $_.StartsWith($key + '/') })) { $S.Items.Remove($k) }; return $null }
        'POST' { return $null }
    }
    $b = ConvertTo-SIArmStoreHash $Body
    if (-not $b) { $b = [ordered]@{} }
    $toKey = ($b.Contains('properties') -and $b['properties'] -and $b['properties'].Contains('encryption') -and [string]$b['properties']['encryption']['keySource'] -eq 'Microsoft.Keyvault') -or
             ($p -match '(?i)/encryptionProtector/current$' -and [string]$b['properties']['serverKeyType'] -eq 'AzureKeyVault')
    if ($toKey -and $S.RefuseKeyAccess -gt 0) { $S.RefuseKeyAccess--; throw 'Azure answered 400: AzureKeyVaultMissingPermissions -- the identity does not have the required permissions on the key' }
    if ($Method -eq 'PATCH') {
        if (-not $S.Items.Contains($key)) { throw ('Azure answered 404 to PATCH {0}' -f $p) }
        Merge-SIArmStoreHash $S.Items[$key] $b
        return (ConvertTo-SIArmStoreObject $S.Items[$key])
    }
    # PUT
    $r = $b; $r['id'] = $p; $r['name'] = ($p -split '/')[-1]
    if (-not $r.Contains('properties') -or -not $r['properties']) { $r['properties'] = [ordered]@{} }
    $r['properties']['provisioningState'] = 'Succeeded'
    switch -Regex ($p) {
        '(?i)/privateEndpoints/[^/]+$' {
            foreach ($c in @($r['properties']['privateLinkServiceConnections'])) { if ($c) { $c['properties']['privateLinkServiceConnectionState'] = [ordered]@{ status = $(if ($S.PendingEndpoints) { 'Pending' } else { 'Approved' }) } } }
            # #866: Azure fills in the endpoint's name(s) and private address(es) (customDnsConfigs)
            $sfx = @{ sqlserver = 'database.windows.net'; vault = 'vault.azure.net'; blob = 'blob.core.windows.net'; queue = 'queue.core.windows.net'; table = 'table.core.windows.net'; registry = 'azurecr.io' }
            $c0 = @($r['properties']['privateLinkServiceConnections'])[0]
            if ($c0) {
                $g = ([string]@($c0['properties']['groupIds'])[0]).ToLowerInvariant(); $res = ([string]$c0['properties']['privateLinkServiceId'] -split '/')[-1]
                $n = @($S.Items.Keys | Where-Object { $_ -match '/privateendpoints/[^/]+$' }).Count
                if ($sfx.Contains($g)) { $r['properties']['customDnsConfigs'] = @([ordered]@{ fqdn = ('{0}.{1}' -f $res, $sfx[$g]); ipAddresses = @(('10.200.13.{0}' -f (68 + $n))) }) }
            }
        }
        '(?i)/managedEnvironments/[^/]+$' { $r['properties']['defaultDomain'] = ('{0}.westeurope.azurecontainerapps.io' -f $r['name']); $r['properties']['staticIp'] = '10.20.0.10' }
        '(?i)/vaults/([^/]+)/keys/([^/]+)$' {
            $vn = [regex]::Match($p, '(?i)/vaults/([^/]+)/keys/').Groups[1].Value
            $r['properties']['keyUri'] = ('https://{0}.vault.azure.net/keys/{1}' -f $vn, $r['name']); $r['properties']['keyUriWithVersion'] = $r['properties']['keyUri'] + '/0123456789abcdef0123456789abcdef'; $r['properties']['kty'] = 'RSA'
        }
        '(?i)/userAssignedIdentities/[^/]+$' { $r['properties']['principalId'] = ('pid-' + $r['name']); $r['properties']['clientId'] = ('cid-' + $r['name']) }
        '(?i)/roleAssignments/[^/]+$' { $r['properties']['scope'] = ($p -replace '(?i)/providers/Microsoft\.Authorization/roleAssignments/[^/]+$', '') }
        '(?i)/containerApps/[^/]+$' {
            $envId = [string]$r['properties']['managedEnvironmentId']; $env = Get-SIArmStoreItem $envId
            if ($r['properties']['configuration'] -and $r['properties']['configuration']['ingress'] -and $env) { $r['properties']['configuration']['ingress']['fqdn'] = ('{0}.{1}' -f $r['name'], [string]$env['properties']['defaultDomain']) }
        }
        '(?i)/clusters/[^/]+$' { $r['properties']['provisioningState'] = $S.ClusterState }
        '(?i)/virtualNetworks/[^/]+/virtualNetworkPeerings/[^/]+$' {
            # #866: a peering reads Initiated until the other network has one pointing back; then BOTH read Connected
            $vn = ($p -replace '(?i)/virtualNetworkPeerings/[^/]+$', '').ToLowerInvariant(); $remote = ([string]$r['properties']['remoteVirtualNetwork']['id']).ToLowerInvariant()
            $back = @($S.Items.Keys | Where-Object { $_.StartsWith($remote + '/virtualnetworkpeerings/') -and ([string]$S.Items[$_]['properties']['remoteVirtualNetwork']['id']).ToLowerInvariant() -eq $vn })
            if ($back.Count) { $r['properties']['peeringState'] = 'Connected'; foreach ($k in $back) { $S.Items[$k]['properties']['peeringState'] = 'Connected' } } else { $r['properties']['peeringState'] = 'Initiated' }
        }
    }
    $S.Items[$key] = $r
    ConvertTo-SIArmStoreObject $r
}

$global:SIArmStoreGraph = {
    param([string]$Method, [string]$Uri, $Body)
    $G = $global:SIArmStore.Graph
    if ($Method -ne 'GET') { $global:SIArmStore.Writes.Add(('GRAPH {0} {1}' -f $Method, ($Uri -replace '\?.*$', ''))) }
    # #681: group membership (member side), service principals by app id -- $global:SIArmStore.Members = @{ <group> = list of ids },
    # $global:SIArmStore.ServicePrincipals = @{ <appId> = <object id> }
    if (-not $global:SIArmStore.Contains('Members')) { $global:SIArmStore.Members = @{} }
    if (-not $global:SIArmStore.Contains('ServicePrincipals')) { $global:SIArmStore.ServicePrincipals = @{} }
    if ($Method -eq 'POST' -and $Uri -match '/directoryObjects/([^/]+)/checkMemberGroups') {
        $who = $Matches[1]; $gids = @(ConvertTo-SIArmStoreHash $Body)[0]['groupIds']
        return [pscustomobject]@{ value = @(@($gids) | Where-Object { $global:SIArmStore.Members.Contains([string]$_) -and @($global:SIArmStore.Members[[string]$_]) -contains $who }) }
    }
    if ($Method -eq 'POST' -and $Uri -match '/groups/([^/]+)/members/\$ref') {
        $gid = $Matches[1]; $who = ([string](@(ConvertTo-SIArmStoreHash $Body)[0]['@odata.id']) -split '/')[-1]
        if (-not $global:SIArmStore.Members.Contains($gid)) { $global:SIArmStore.Members[$gid] = @() }
        if (@($global:SIArmStore.Members[$gid]) -contains $who) { throw 'One or more added object references already exist for the following modified properties: members.' }
        $global:SIArmStore.Members[$gid] = @(@($global:SIArmStore.Members[$gid]) + $who); return $null
    }
    if ($Method -eq 'DELETE' -and $Uri -match '/groups/([^/]+)/members/([^/]+)/\$ref') {
        $gid = $Matches[1]; $who = $Matches[2]
        if ($global:SIArmStore.Members.Contains($gid)) { $global:SIArmStore.Members[$gid] = @(@($global:SIArmStore.Members[$gid]) | Where-Object { $_ -ne $who }) }
        return $null
    }
    if ($Method -eq 'GET' -and $Uri -match "servicePrincipals\?.*appId eq '([^']+)'") {
        $sp = $global:SIArmStore.ServicePrincipals[$Matches[1]]
        return [pscustomobject]@{ value = @($(if ($sp) { [pscustomobject]@{ id = $sp; displayName = 'Invardia Support' } })) }
    }
    if ($Method -eq 'GET' -and $Uri -match "applications\?.*appId eq '([^']+)'") { $a = @($G.Values | Where-Object { $_.appId -eq $Matches[1] }); return [pscustomobject]@{ value = @($a | ForEach-Object { ConvertTo-SIArmStoreObject $_ }) } }
    if ($Uri -match '/applications/([^/?]+)') {
        $oid = $Matches[1]
        if ($Method -eq 'PATCH') { Merge-SIArmStoreHash $G[$oid] (ConvertTo-SIArmStoreHash $Body); return $null }
        return (ConvertTo-SIArmStoreObject $G[$oid])
    }
    [pscustomobject]@{ value = @() }
}
