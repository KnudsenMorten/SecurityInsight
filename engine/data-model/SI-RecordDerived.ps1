#Requires -Version 5.1
<#
    THE 'derived' RECORD PART -- facts a provider object implies but does not state, computed once from the parts the
    collectors already captured, so the mappings' derived.* paths fill (data-model/mappings: azure + entra).

    Before this file NO collector wrote a 'derived' part: derived.isPubliclyExposed, derived.credentialExpiryDays,
    derived.ownerCount (and the rest) were always empty, so Azure exposure, credential expiry and orphan service
    principals never reached the CI from records.

    Computed when a record is assembled (Get-SICapturedRecords), so every path -- one process, or a run collected in parts
    and published by its last step -- gets it from the same parts. A value that cannot be known is LEFT OUT, never guessed:
    an unknown owner count is not 0 (that would mark the service principal orphaned).

      azure (azure_resource / public_ip), from part 'resource' (the ARM resource) and 'mg':
        isPubliclyExposed       publicNetworkAccess Enabled, a storage account allowing blob public access, a network ACL
                                that allows by default (storage / Key Vault / Cognitive Services / ...), or a public IP
                                address that has an address
        inboundRdpFromInternet  a network security group with an Allow / Inbound rule from Internet / * / 0.0.0.0/0 that
        inboundSshFromInternet  covers port 3389 (RDP) / 22 (SSH)
        managementGroupPath     the subscription's management-group chain, root first ('Tenant Root Group/Corp/Prod'):
                                part 'mg', written by the Azure discovery (Add-SIManagementGroupParts)
      entra (service_principal), from parts 'sp', 'app' and 'owners':
        credentialExpiryDays    days until the first key / password credential of the service principal or its
                                application ends (negative = already expired); left out when it has none
        ownerCount              owners of the service principal: part 'owners', written by the owners read
                                (Invoke-SISpOwnerCapture); left out when it was not read
        isThirdPartyMultiTenant appOwnerOrganizationId is set and is not this tenant (left out when the tenant is not known)

    PURE (the tenant id and the clock are parameters). PowerShell 5.1: no ?. / ??, no ternary.
#>

function Get-SIDerivedValue {
    <# PURE. A named value of a hashtable / PSObject, or $null. #>
    param($Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { return $Item[$Name] }; return $null }
    $p = $Item.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    return $null
}

function Test-SIDerivedPortCovered {
    <# PURE. Does an NSG port spec ('*', '3389', '3000-4000') cover the port? #>
    param([string]$Spec, [int]$Port)
    $s = ([string]$Spec).Trim()
    if (-not $s) { return $false }
    if ($s -eq '*') { return $true }
    if ($s -match '^(\d+)-(\d+)$') { return ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) }
    if ($s -match '^\d+$') { return ([int]$s -eq $Port) }
    return $false
}

function Test-SIDerivedNsgOpen {
    <# PURE. An NSG's properties allow inbound traffic from the internet to the port. #>
    param($Properties, [int]$Port)
    $rules = @()
    foreach ($n in 'securityRules', 'defaultSecurityRules') { $v = Get-SIDerivedValue $Properties $n; if ($v) { $rules += @($v) } }
    foreach ($r in $rules) {
        $rp = Get-SIDerivedValue $r 'properties'; if ($null -eq $rp) { $rp = $r }
        if ([string](Get-SIDerivedValue $rp 'access') -notmatch '^(?i)Allow$') { continue }
        if ([string](Get-SIDerivedValue $rp 'direction') -notmatch '^(?i)Inbound$') { continue }
        $src = @([string](Get-SIDerivedValue $rp 'sourceAddressPrefix')) + @(Get-SIDerivedValue $rp 'sourceAddressPrefixes' | Where-Object { $_ })
        if (-not (@($src | Where-Object { $_ -in 'Internet', '*', '0.0.0.0/0', 'Any' }).Count)) { continue }
        $ports = @([string](Get-SIDerivedValue $rp 'destinationPortRange')) + @(Get-SIDerivedValue $rp 'destinationPortRanges' | Where-Object { $_ })
        foreach ($pp in $ports) { if (Test-SIDerivedPortCovered ([string]$pp) $Port) { return $true } }
    }
    return $false
}

function Get-SIAzureDerived {
    <# PURE. The derived values of an Azure record from its 'resource' and 'mg' parts. #>
    param($Object)
    $out = [ordered]@{}
    $res = Get-SIDerivedValue $Object 'resource'
    if ($null -ne $res) {
        $type = ([string](Get-SIDerivedValue $res 'type')).ToLowerInvariant()
        $p = Get-SIDerivedValue $res 'properties'
        if ($p -is [string]) { try { $p = $p | ConvertFrom-Json } catch { $p = $null } }
        if ($null -ne $p) {
            $exposed = $false
            $pna = [string](Get-SIDerivedValue $p 'publicNetworkAccess')
            if ($pna -match '^(?i)Enabled$') { $exposed = $true }
            $blob = Get-SIDerivedValue $p 'allowBlobPublicAccess'
            if ($blob -eq $true -or [string]$blob -eq 'true') { $exposed = $true }
            $acls = Get-SIDerivedValue $p 'networkAcls'; if ($null -eq $acls) { $acls = Get-SIDerivedValue $p 'networkRuleSet' }
            if ($null -ne $acls -and [string](Get-SIDerivedValue $acls 'defaultAction') -match '^(?i)Allow$' -and $pna -notmatch '^(?i)Disabled$') { $exposed = $true }
            if ($type -eq 'microsoft.network/publicipaddresses' -and [string](Get-SIDerivedValue $p 'ipAddress')) { $exposed = $true }
            $out['isPubliclyExposed'] = $exposed
            if ($type -eq 'microsoft.network/networksecuritygroups') {
                $out['inboundRdpFromInternet'] = (Test-SIDerivedNsgOpen -Properties $p -Port 3389)
                $out['inboundSshFromInternet'] = (Test-SIDerivedNsgOpen -Properties $p -Port 22)
            }
        }
    }
    $mg = Get-SIDerivedValue $Object 'mg'
    $path = [string](Get-SIDerivedValue $mg 'path')
    if ($path) { $out['managementGroupPath'] = $path }
    # the Azure child resources that roll up into this resource (part 'children', SI-AzureChildren.ps1): every child as
    # { id, type, name } (childResources -> si_child_resources), and each child's shape in the list its type names
    # (rollUpInto.field: si_vm_extensions, si_disks, ...) -- in id order, so the record's content is the same every run
    $kids = @(Get-SIDerivedValue $Object 'children' | Where-Object { $null -ne $_ } | Sort-Object { [string](Get-SIDerivedValue $_ 'id') })
    if ($kids.Count -gt 0) {
        $all = New-Object System.Collections.Generic.List[object]
        $byField = [ordered]@{}
        foreach ($c in $kids) {
            $cid = [string](Get-SIDerivedValue $c 'id'); if (-not $cid) { continue }
            $all.Add([pscustomobject][ordered]@{ id = $cid; type = [string](Get-SIDerivedValue $c 'type'); name = [string](Get-SIDerivedValue $c 'name') })
            $f = [string](Get-SIDerivedValue $c 'field')
            if (-not $f -or $f -notmatch '^si_[a-z0-9_]+$') { continue }
            if (-not $byField.Contains($f)) { $byField[$f] = New-Object System.Collections.Generic.List[object] }
            $sh = Get-SIDerivedValue $c 'shape'
            if ($null -eq $sh) { $sh = [pscustomobject]@{ name = [string](Get-SIDerivedValue $c 'name') } }
            $byField[$f].Add($sh)
        }
        if ($all.Count -gt 0) { $out['childResources'] = $all.ToArray() }
        foreach ($f in $byField.Keys) { $out[$f] = $byField[$f].ToArray() }
    }
    # rich context (Azure lane): the names next to the ids, the normalised tags, what the child resources say about the
    # machine (Defender / Azure Monitor agent extension, disk encryption), private endpoints
    $rich = Get-SIAzureRichDerived -Object $Object
    foreach ($k in @($rich.Keys)) { if (-not $out.Contains($k)) { $out[$k] = $rich[$k] } }
    return $out
}

# =====================================================================================================================
#  RICH CONTEXT -- AZURE, PUBLIC IP (Shodan)                                                              (Azure lane)
#  Owner 2026-10-11: "we need both ids like sub id + sub names. dont leave out info, better more than less".
#    azure (azure_resource / public_ip), from parts 'mg', 'resource', 'parentTags' and 'children':
#      subscriptionName / tenantId / tenantName          the subscription's name and its tenant (id + name)
#      managementGroupId / -Name / -IdPath               the management group the subscription sits in (id + name) and
#                                                        the chain as ids (managementGroupPath holds the names)
#      tagEnvironment / tagCostCenter / tagAppName / tagOwner
#                                                        the resource's tags (then its resource group's and subscription's)
#                                                        read through the customer's TAG-KEY MAP: the lists tag_keys_* of
#                                                        data-model/lists name which tag keys mean environment, cost
#                                                        center, application and owner (customer-editable like every list)
#      mdeExtension / amaExtension                       a machine's extensions (its child resources) include the Defender
#                                                        for Endpoint / Azure Monitor agent extension
#      diskEncryption                                    how a virtual machine's disks are encrypted, from the machine and
#                                                        its disks: encryption at host, Azure Disk Encryption, customer-
#                                                        or platform-managed key
#      privateEndpointCount                              private endpoint connections of the resource (when it lists them)
#    shodan (public_ip), from part 'host' -- the answer SecurityInsight already cached; NO extra Shodan request or credit:
#      exposedServices            each open service: port, transport, product, version
#      httpTitles / httpServers   what the web servers on the address answer
#      tlsCertificates            each certificate served: port, subject, issuer, expiry, expired, self-signed, versions
#      tlsCertExpired / tlsSelfSigned / tlsEarliestExpiry / tlsLegacyVersions
#      shodanTags, exposedOs, domains, cloudProvider / cloudRegion / cloudService, bannerFirstSeen / bannerLastSeen
#  A value that cannot be known is LEFT OUT, never guessed.
# =====================================================================================================================

function Get-SITagKeyMapDefault {
    <# PURE. The tag-key map used when data-model/lists cannot be read: the shipped lists' values. #>
    return @{
        environment = @('environment', 'env', 'stage')
        cost_center = @('costcenter', 'cost-center', 'cost_center', 'cost center', 'costcentre')
        app_name    = @('application', 'applicationname', 'application-name', 'app', 'appname', 'app-name', 'workload', 'service', 'system')
        owner       = @('owner', 'owners', 'technicalowner', 'technical-owner', 'businessowner', 'business-owner', 'team', 'contact')
    }
}

function ConvertTo-SITagKeyName {
    <# PURE. A tag key as the map compares it: lower case, letters and digits only ('Cost-Center' = 'cost_center' = 'CostCenter'). #>
    param([AllowNull()][AllowEmptyString()][string]$Key)
    return (([string]$Key).ToLowerInvariant() -replace '[^a-z0-9]', '')
}

function ConvertTo-SITagKeyMap {
    <# PURE. The lists document (data-model/lists, merged with the customer's overrides) -> the tag-key map: the values of
       the lists tag_keys_environment / tag_keys_cost_center / tag_keys_app_name / tag_keys_owner, in order (the first key
       that the resource carries wins). A list that is missing keeps its default. #>
    param($Document, [hashtable]$Default = (Get-SITagKeyMapDefault))
    $map = @{}
    foreach ($k in @($Default.Keys)) { $map[$k] = @($Default[$k]) }
    foreach ($l in @(Get-SIDerivedValue $Document 'lists')) {
        if ($null -eq $l) { continue }
        $id = [string](Get-SIDerivedValue $l 'id')
        if ($id -notmatch '^tag_keys_([a-z_]+)$') { continue }
        $name = $Matches[1]
        if (-not $map.ContainsKey($name)) { continue }
        $map[$name] = @(@(Get-SIDerivedValue $l 'values') | Where-Object { $_ } | ForEach-Object { [string]$_ })
    }
    return $map
}

function Set-SITagKeyMap {
    <# The tag-key map this process uses (tests; a caller that already holds the model). $null = load it on the next use. #>
    param([hashtable]$Map)
    $script:SITagKeyMap = $Map
    $script:SITagKeyMapLoaded = ($null -ne $Map)
}

function Get-SITagKeyMap {
    <# The tag-key map of this install, read ONCE per process from data-model/lists (shipped + the customer's overrides).
       Cannot be read: the shipped defaults -- never fewer fields because a file could not be read. #>
    if ($script:SITagKeyMapLoaded) { return $script:SITagKeyMap }
    $script:SITagKeyMapLoaded = $true
    $script:SITagKeyMap = Get-SITagKeyMapDefault
    try {
        if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1') }
        $t = Get-SIDataModelTemplate -Name 'lists' -OverlayRoot $global:SI_DataModelOverlayRoot
        $script:SITagKeyMap = ConvertTo-SITagKeyMap -Document $t.Document
    } catch { Write-Verbose ('tag keys: the lists could not be read ({0}) -- the shipped tag keys are used.' -f $_.Exception.Message) }
    return $script:SITagKeyMap
}

function Get-SIDerivedTagBag {
    <# PURE. Tags (an object, a dictionary, or JSON text) as @{ <normalised key> = value }; the first spelling of a key wins. #>
    param($Tags)
    $bag = @{}
    $t = $Tags
    if ($t -is [string]) { $s = $t.Trim(); if ($s.StartsWith('{')) { try { $t = $s | ConvertFrom-Json } catch { $t = $null } } else { $t = $null } }
    if ($null -eq $t) { return $bag }
    $pairs = New-Object System.Collections.Generic.List[object]
    if ($t -is [System.Collections.IDictionary]) { foreach ($k in @($t.Keys)) { $pairs.Add(@([string]$k, $t[$k])) } }
    else { foreach ($p in @($t.PSObject.Properties)) { $pairs.Add(@([string]$p.Name, $p.Value)) } }
    foreach ($kv in $pairs) {
        $k = ConvertTo-SITagKeyName $kv[0]
        $v = ([string]$kv[1]).Trim()
        if ($k -and $v -and -not $bag.ContainsKey($k)) { $bag[$k] = $v }
    }
    return $bag
}

function Get-SIAzureTagDerived {
    <# PURE. The normalised tags of an Azure resource: for each name of the tag-key map (environment, cost_center, app_name,
       owner) the value of the first listed key the resource carries -- its own tags first, then its resource group's and
       subscription's (part 'parentTags'). @{ tagEnvironment; tagCostCenter; tagAppName; tagOwner }, only those found. #>
    param($Tags, $ParentTags, [hashtable]$Map = (Get-SITagKeyMap))
    $out = [ordered]@{}
    if ($null -eq $Map) { return $out }
    $own = Get-SIDerivedTagBag $Tags; $parent = Get-SIDerivedTagBag $ParentTags
    if ($own.Count -eq 0 -and $parent.Count -eq 0) { return $out }
    $names = [ordered]@{ environment = 'tagEnvironment'; cost_center = 'tagCostCenter'; app_name = 'tagAppName'; owner = 'tagOwner' }
    foreach ($n in $names.Keys) {
        if (-not $Map.ContainsKey($n)) { continue }
        $hit = $null
        foreach ($bag in @($own, $parent)) {
            foreach ($key in @($Map[$n])) {
                $k = ConvertTo-SITagKeyName ([string]$key)
                if ($k -and $bag.ContainsKey($k)) { $hit = [string]$bag[$k]; break }
            }
            if ($null -ne $hit) { break }
        }
        if ($null -ne $hit) { $out[$names[$n]] = $hit }
    }
    return $out
}

function Get-SIAzureRichDerived {
    <# PURE. The rich-context derived values of an Azure record (see the block header). #>
    param($Object, [hashtable]$TagKeyMap)
    $out = [ordered]@{}
    # ---- names next to ids (part 'mg', written by the Azure discovery from the subscription list) --------------------
    $mg = Get-SIDerivedValue $Object 'mg'
    foreach ($pair in @(@('subscriptionName', 'subscriptionName'), @('tenantId', 'tenantId'), @('tenantName', 'tenantName'),
                        @('managementGroupId', 'id'), @('managementGroupName', 'name'), @('managementGroupIdPath', 'idPath'))) {
        $v = [string](Get-SIDerivedValue $mg $pair[1]); if ($v) { $out[$pair[0]] = $v }
    }
    $res = Get-SIDerivedValue $Object 'resource'
    if ($null -eq $res) { return $out }
    # ---- the tags, read through the customer's tag-key map -------------------------------------------------------------
    if ($null -eq $TagKeyMap) { $TagKeyMap = Get-SITagKeyMap }
    $tags = Get-SIAzureTagDerived -Tags (Get-SIDerivedValue $res 'tags') -ParentTags (Get-SIDerivedValue $Object 'parentTags') -Map $TagKeyMap
    foreach ($k in @($tags.Keys)) { $out[$k] = $tags[$k] }

    $type = ([string](Get-SIDerivedValue $res 'type')).ToLowerInvariant()
    $p = Get-SIDerivedValue $res 'properties'
    if ($p -is [string]) { try { $p = $p | ConvertFrom-Json } catch { $p = $null } }
    # ---- private endpoints: counted only when the resource lists them (a type without the list stays unknown) ----------
    # (the property is read in place: an EMPTY list handed back by a function would be lost, and "lists none" is a fact)
    $pecHas = $false; $pec = $null
    if ($p -is [System.Collections.IDictionary]) { if ($p.Contains('privateEndpointConnections')) { $pecHas = $true; $pec = $p['privateEndpointConnections'] } }
    elseif ($null -ne $p) { $pecProp = $p.PSObject.Properties['privateEndpointConnections']; if ($pecProp) { $pecHas = $true; $pec = $pecProp.Value } }
    if ($pecHas -and -not ($pec -is [string])) { $out['privateEndpointCount'] = @(@($pec) | Where-Object { $null -ne $_ }).Count }

    # ---- a machine: what its extensions and disks say ----------------------------------------------------------------
    if ($type -in 'microsoft.compute/virtualmachines', 'microsoft.hybridcompute/machines', 'microsoft.compute/virtualmachinescalesets') {
        $extTypes = New-Object System.Collections.Generic.List[string]
        $diskEnc = New-Object System.Collections.Generic.List[string]
        foreach ($c in @(Get-SIDerivedValue $Object 'children')) {
            if ($null -eq $c) { continue }
            $sh = Get-SIDerivedValue $c 'shape'
            $ct = ([string](Get-SIDerivedValue $c 'type')).ToLowerInvariant()
            if ($ct.EndsWith('/extensions')) {
                $et = [string](Get-SIDerivedValue $sh 'type'); if (-not $et) { $et = [string](Get-SIDerivedValue $c 'name') }
                if ($et) { $extTypes.Add($et.ToLowerInvariant()) }
            } elseif ($ct -eq 'microsoft.compute/disks') {
                $e = [string](Get-SIDerivedValue $sh 'encryption'); if ($e) { $diskEnc.Add($e.ToLowerInvariant()) }
            }
        }
        # said only when the machine's child resources were captured: without them "no extension" is unknown, never "no"
        if (@(@(Get-SIDerivedValue $Object 'children') | Where-Object { $null -ne $_ }).Count -gt 0) {
            $out['mdeExtension'] = (@($extTypes | Where-Object { $_ -match '^mde\.(windows|linux)$' }).Count -gt 0)
            $out['amaExtension'] = (@($extTypes | Where-Object { $_ -match '^azuremonitor(windows|linux)agent$' }).Count -gt 0)
        }
        if ($type -eq 'microsoft.compute/virtualmachines') {
            $how = New-Object System.Collections.Generic.List[string]
            $sp = Get-SIDerivedValue $p 'securityProfile'
            $eah = Get-SIDerivedValue $sp 'encryptionAtHost'
            if ($eah -eq $true -or [string]$eah -eq 'true') { $how.Add('encryption at host') }
            if (@($extTypes | Where-Object { $_ -match '^azurediskencryption(forlinux)?$' }).Count -gt 0) { $how.Add('Azure Disk Encryption') }
            $osDisk = Get-SIDerivedValue (Get-SIDerivedValue (Get-SIDerivedValue $p 'storageProfile') 'osDisk') 'managedDisk'
            $des = [string](Get-SIDerivedValue (Get-SIDerivedValue $osDisk 'diskEncryptionSet') 'id')
            if ([string](Get-SIDerivedValue (Get-SIDerivedValue $osDisk 'securityProfile') 'securityEncryptionType')) { $how.Add('confidential disk encryption') }
            if (@($diskEnc | Where-Object { $_ -match 'platformandcustomerkeys' }).Count -gt 0) { $how.Add('platform-managed and customer-managed keys') }
            elseif ($des -or @($diskEnc | Where-Object { $_ -match 'customerkey' }).Count -gt 0) { $how.Add('customer-managed key') }
            elseif (@($diskEnc | Where-Object { $_ -match 'platformkey' }).Count -gt 0) { $how.Add('platform-managed key') }
            if ($how.Count -gt 0) { $out['diskEncryption'] = ($how.ToArray() -join '; ') }
        }
    }
    return $out
}

function ConvertTo-SIShodanTime {
    <# PURE. A Shodan time ('2026-09-30T11:22:33.123456', or a certificate's '20270523235959Z') as UTC ISO text; ''. #>
    param($Value)
    $s = ([string]$Value).Trim()
    if (-not $s) { return '' }
    $t = [datetime]::MinValue
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    # a time without an offset is UTC (the scan's times are): never shifted by this machine's time zone
    if ($Value -is [datetime]) { $t = [datetime]$Value; if ($t.Kind -eq [System.DateTimeKind]::Unspecified) { $t = [datetime]::SpecifyKind($t, [System.DateTimeKind]::Utc) } else { $t = $t.ToUniversalTime() } }
    elseif (-not [datetime]::TryParseExact($s, [string[]]@('yyyyMMddHHmmssZ', 'yyyyMMddHHmmss'), $inv, $styles, [ref]$t)) {
        if (-not [datetime]::TryParse($s, $inv, $styles, [ref]$t)) { return '' }
    }
    if ($t.Year -lt 1990) { return '' }
    return $t.ToString("yyyy-MM-ddTHH:mm:ssZ", $inv)
}

function Get-SIShodanDerived {
    <# PURE. The derived values of a Shodan public-IP record from its 'host' part (the cached host answer): see the block
       header. Reads only what is already stored -- no request, no credit. #>
    param($Object, [datetime]$Now = [datetime]::UtcNow)
    $out = [ordered]@{}
    $h = Get-SIDerivedValue $Object 'host'
    if ($null -eq $h) { return $out }
    $addUnique = { param($List, $Value) $s = ([string]$Value).Trim(); if ($s -and -not $List.Contains($s)) { $List.Add($s) } }
    $services = New-Object System.Collections.Generic.List[object]; $svcSeen = New-Object 'System.Collections.Generic.HashSet[string]'
    $titles = New-Object System.Collections.Generic.List[string]; $servers = New-Object System.Collections.Generic.List[string]
    $certs = New-Object System.Collections.Generic.List[object]; $legacy = New-Object System.Collections.Generic.List[string]
    $tags = New-Object System.Collections.Generic.List[string]
    $os = ([string](Get-SIDerivedValue $h 'os')).Trim()
    $cloud = $null; $first = ''; $last = ''; $anyExpired = $false; $anySelf = $false; $earliest = ''
    foreach ($t in @(Get-SIDerivedValue $h 'tags')) { & $addUnique $tags $t }
    foreach ($b in @(Get-SIDerivedValue $h 'data')) {
        if ($null -eq $b) { continue }
        $port = Get-SIDerivedValue $b 'port'
        $transport = ([string](Get-SIDerivedValue $b 'transport')).Trim()
        if ($null -ne $port -and "$port" -ne '') {
            $svc = [ordered]@{ port = [int]$port }
            if ($transport) { $svc['transport'] = $transport }
            foreach ($n in 'product', 'version') { $v = ([string](Get-SIDerivedValue $b $n)).Trim(); if ($v) { $svc[$n] = $v } }
            if ($svcSeen.Add(('{0}/{1}' -f $svc['port'], $transport))) { $services.Add([pscustomobject]$svc) }
        }
        $http = Get-SIDerivedValue $b 'http'
        if ($null -ne $http) { & $addUnique $titles (Get-SIDerivedValue $http 'title'); & $addUnique $servers (Get-SIDerivedValue $http 'server') }
        foreach ($t in @(Get-SIDerivedValue $b 'tags')) { & $addUnique $tags $t }
        if (-not $os) { $os = ([string](Get-SIDerivedValue $b 'os')).Trim() }
        if ($null -eq $cloud) { $cloud = Get-SIDerivedValue $b 'cloud' }
        $ts = ConvertTo-SIShodanTime (Get-SIDerivedValue $b 'timestamp')
        if ($ts) { if (-not $first -or [string]::CompareOrdinal($ts, $first) -lt 0) { $first = $ts }; if (-not $last -or [string]::CompareOrdinal($ts, $last) -gt 0) { $last = $ts } }
        $ssl = Get-SIDerivedValue $b 'ssl'
        if ($null -eq $ssl) { continue }
        $accepted = @(@(Get-SIDerivedValue $ssl 'versions') | Where-Object { $_ -and -not ([string]$_).StartsWith('-') } | ForEach-Object { [string]$_ })
        foreach ($v in $accepted) { if ($v -match '^(?i)(SSLv2|SSLv3|TLSv1|TLSv1\.1)$') { & $addUnique $legacy $v } }
        $cert = Get-SIDerivedValue $ssl 'cert'
        if ($null -eq $cert) { continue }
        $subj = Get-SIDerivedValue $cert 'subject'; $iss = Get-SIDerivedValue $cert 'issuer'
        $c = [ordered]@{}
        if ($null -ne $port -and "$port" -ne '') { $c['port'] = [int]$port }
        $scn = ([string](Get-SIDerivedValue $subj 'CN')).Trim(); if ($scn) { $c['subject'] = $scn }
        $icn = ([string](Get-SIDerivedValue $iss 'CN')).Trim(); if (-not $icn) { $icn = ([string](Get-SIDerivedValue $iss 'O')).Trim() }; if ($icn) { $c['issuer'] = $icn }
        $exp = ConvertTo-SIShodanTime (Get-SIDerivedValue $cert 'expires')
        if ($exp) { $c['expires'] = $exp; if (-not $earliest -or [string]::CompareOrdinal($exp, $earliest) -lt 0) { $earliest = $exp } }
        $expired = $null
        $ev = Get-SIDerivedValue $cert 'expired'
        if ($ev -is [bool]) { $expired = $ev } elseif ($exp) { $expired = ([string]::CompareOrdinal($exp, $Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", [System.Globalization.CultureInfo]::InvariantCulture)) -lt 0) }
        if ($null -ne $expired) { $c['expired'] = [bool]$expired; if ($expired) { $anyExpired = $true } }
        $self = $false
        if ($null -ne $subj -and $null -ne $iss) { $self = ((ConvertTo-Json -InputObject $subj -Compress -Depth 4) -eq (ConvertTo-Json -InputObject $iss -Compress -Depth 4)) }
        if (@(@(Get-SIDerivedValue $b 'tags') | Where-Object { [string]$_ -eq 'self-signed' }).Count -gt 0) { $self = $true }
        $c['self_signed'] = $self; if ($self) { $anySelf = $true }
        if ($accepted.Count -gt 0) { $c['versions'] = $accepted }
        $certs.Add([pscustomobject]$c)
    }
    if ($services.Count -gt 0) { $out['exposedServices'] = @($services.ToArray() | Sort-Object { [int]$_.port }, { [string]$_.transport }) }
    if ($titles.Count -gt 0) { $out['httpTitles'] = $titles.ToArray() }
    if ($servers.Count -gt 0) { $out['httpServers'] = $servers.ToArray() }
    if ($certs.Count -gt 0) {
        $out['tlsCertificates'] = $certs.ToArray()
        $out['tlsCertExpired'] = $anyExpired
        $out['tlsSelfSigned'] = $anySelf
        if ($earliest) { $out['tlsEarliestExpiry'] = $earliest }
    }
    if ($legacy.Count -gt 0) { $out['tlsLegacyVersions'] = $legacy.ToArray() }
    if ($tags.Count -gt 0) { $out['shodanTags'] = $tags.ToArray() }
    if ($os) { $out['exposedOs'] = $os }
    $doms = @(@(Get-SIDerivedValue $h 'domains') | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Select-Object -Unique)
    if ($doms.Count -gt 0) { $out['domains'] = $doms }
    if ($null -ne $cloud) {
        foreach ($pair in @(@('cloudProvider', 'provider'), @('cloudRegion', 'region'), @('cloudService', 'service'))) {
            $v = ([string](Get-SIDerivedValue $cloud $pair[1])).Trim(); if ($v) { $out[$pair[0]] = $v }
        }
    }
    if ($first) { $out['bannerFirstSeen'] = $first }
    if ($last) { $out['bannerLastSeen'] = $last }
    return $out
}

function Get-SIEntraSpDerived {
    <# PURE. The derived values of a service-principal record from its 'sp', 'app' and 'owners' parts. #>
    param($Object, [string]$TenantId = '', [datetime]$Now = [datetime]::UtcNow)
    $out = [ordered]@{}
    $sp = Get-SIDerivedValue $Object 'sp'
    $app = Get-SIDerivedValue $Object 'app'
    $min = $null
    foreach ($o in @($sp, $app)) {
        if ($null -eq $o) { continue }
        foreach ($n in 'passwordCredentials', 'keyCredentials') {
            foreach ($c in @(Get-SIDerivedValue $o $n)) {
                if ($null -eq $c) { continue }
                $e = Get-SIDerivedValue $c 'endDateTime'
                if ($null -eq $e -or [string]$e -eq '') { continue }
                $t = $null
                if ($e -is [datetime]) { $t = $e.ToUniversalTime() }
                else { $d = [datetimeoffset]::MinValue; if ([datetimeoffset]::TryParse([string]$e, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { $t = $d.UtcDateTime } }
                if ($null -eq $t) { continue }
                $days = [int][Math]::Floor(($t - $Now.ToUniversalTime()).TotalDays)
                if ($null -eq $min -or $days -lt $min) { $min = $days }
            }
        }
    }
    if ($null -ne $min) { $out['credentialExpiryDays'] = $min }
    $own = Get-SIDerivedValue $Object 'owners'
    $cnt = Get-SIDerivedValue $own 'count'
    if ($null -ne $cnt -and "$cnt" -ne '') { $out['ownerCount'] = [int]$cnt }
    $org = ([string](Get-SIDerivedValue $sp 'appOwnerOrganizationId')).Trim()
    if ($org -and $TenantId) { $out['isThirdPartyMultiTenant'] = -not [string]::Equals($org, $TenantId.Trim(), [StringComparison]::OrdinalIgnoreCase) }
    return $out
}

# =====================================================================================================================
#  IDENTITY CONTEXT (rich context, identity) -- derived from the parts discovery\Get-SIEntraContext.ps1 adds. One block.
# =====================================================================================================================

function ConvertTo-SIDerivedUtc {
    <# PURE. A date value (a datetime, or ISO text) as UTC, or $null. #>
    param($Value)
    if ($null -eq $Value -or [string]$Value -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    $d = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) { return $d.UtcDateTime }
    return $null
}

function ConvertTo-SIDerivedList {
    <# PURE. A list value that may arrive as an array or as JSON text -> @{ Known; Items } (strings). #>
    param($Value)
    if ($null -eq $Value) { return @{ Known = $false; Items = @() } }
    $v = $Value
    if ($v -is [string]) {
        $s = $v.Trim()
        if (-not $s) { return @{ Known = $false; Items = @() } }
        if ($s.StartsWith('[')) { try { $v = $s | ConvertFrom-Json } catch { return @{ Known = $false; Items = @() } } } else { $v = @($s) }
    }
    return @{ Known = $true; Items = @(@($v) | Where-Object { $null -ne $_ -and [string]$_ -ne '' } | ForEach-Object { [string]$_ }) }
}

function Get-SIMfaStrength {
    <#
        PURE. The strongest way a user can do MFA, from the methods registered (Graph userRegistrationDetails):
          phishing-resistant  a FIDO2 key, a passkey, Windows Hello for Business, a certificate, a platform credential
          strong              Microsoft Authenticator (push or passwordless), a software or hardware one-time code
          weak                a phone call or text message
          none                the registration was read and holds none of these (e-mail and security questions are for
                              password reset, not MFA)
        $null (unknown) when the methods were not read.
    #>
    param($Methods)
    if ($null -eq $Methods) { return $null }
    $m = @(@($Methods) | Where-Object { $_ } | ForEach-Object { [string]$_ })
    if (@($m | Where-Object { $_ -match '(?i)fido2|passkey|windowsHello|x509|certificate|secureEnclave|platformCredential' }).Count -gt 0) { return 'phishing-resistant' }
    if (@($m | Where-Object { $_ -match '(?i)microsoftAuthenticator|softwareOneTimePasscode|hardwareOneTimePasscode' }).Count -gt 0) { return 'strong' }
    if (@($m | Where-Object { $_ -match '(?i)mobilePhone|officePhone|voice|sms' }).Count -gt 0) { return 'weak' }
    return 'none'
}

function Format-SIOwnerNames {
    <# PURE. Owners ({ id, upn, name }) as one text: "Ada Admin (ada@contoso.test); Build Service". #>
    param([AllowEmptyCollection()][object[]]$Owners = @())
    $parts = foreach ($o in @($Owners)) {
        if ($null -eq $o) { continue }
        $n = [string](Get-SIDerivedValue $o 'name'); $u = [string](Get-SIDerivedValue $o 'upn')
        if ($n -and $u) { '{0} ({1})' -f $n, $u } elseif ($n) { $n } elseif ($u) { $u } else { [string](Get-SIDerivedValue $o 'id') }
    }
    return (@($parts | Where-Object { $_ }) -join '; ')
}

function Get-SIEntraUserDerived {
    <#
        PURE. The derived values of an Entra user record:
          mfaStrength    from part 'registration' (Get-SIMfaStrength); left out when the registration was not read
          ownerNames     a guest's sponsors (part 'sponsors') as its owner -- left out for a user without sponsors
    #>
    param($Object)
    $out = [ordered]@{}
    $reg = Get-SIDerivedValue $Object 'registration'
    if ($null -ne $reg) {
        $s = Get-SIMfaStrength -Methods @(Get-SIDerivedValue $reg 'methodsRegistered')
        if ($s) { $out['mfaStrength'] = $s }
    }
    $sp = @(@(Get-SIDerivedValue (Get-SIDerivedValue $Object 'sponsors') 'items') | Where-Object { $_ })
    if ($sp.Count -gt 0) { $names = Format-SIOwnerNames -Owners $sp; if ($names) { $out['ownerNames'] = $names } }
    return $out
}

function Get-SIEntraSpContextDerived {
    <#
        PURE. The derived values of a service-principal record that come from the identity context parts:
          owners / ownerNames / ownerUpns / ownerIds   the owners of the principal (part 'owners'.items) AND of its
                             application registration (part 'app'.owners), each person once, with where they own
                             (of = service principal | application | both)
          ownerCount         both together. A principal whose application has an owner is NOT orphaned. 0 is only said
                             when the application's owners are known (part 'contextReads'.applications, or the app part
                             itself, or a managed identity / another tenant's application); otherwise ownerCountUnknown
          credentials        every secret and certificate of the principal and its application: keyId, type, name, where,
                             expires, daysLeft, state (expired | expiring | active), lastUsed (part 'credUsage'),
                             neverUsed (only when the last-use read completed), usedAfterExpiry
          credentialFix      what to do about the expired / expiring ones, in one text (the finding's how-to-fix)
          attachedResourceId / attachedResourceName / managedIdentityKind   a managed identity's resource
          permissionGap      requested (the application's manifest) against granted permissions
    #>
    param($Object, [string]$TenantId = '', [datetime]$Now = [datetime]::UtcNow)
    $out = [ordered]@{}
    $sp = Get-SIDerivedValue $Object 'sp'
    $app = Get-SIDerivedValue $Object 'app'
    $own = Get-SIDerivedValue $Object 'owners'
    $reads = Get-SIDerivedValue $Object 'contextReads'

    # ---- owners ----
    # `of` says where the person owns: 'service principal', 'application', or 'both' when the same person owns the principal
    # AND its application registration (each person is listed once) -- the owner-mismatch report compares the two sides
    $owners = New-Object System.Collections.Generic.List[object]
    $byId = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $appOnly = 0
    foreach ($src in @(@{ Items = (Get-SIDerivedValue $own 'items'); Of = 'service principal' }, @{ Items = (Get-SIDerivedValue $app 'owners'); Of = 'application' })) {
        foreach ($o in @($src.Items)) {
            if ($null -eq $o) { continue }
            $id = [string](Get-SIDerivedValue $o 'id')
            if (-not $id) { continue }
            if ($byId.ContainsKey($id)) {
                if ([string]$byId[$id].of -ne $src.Of) { $byId[$id].of = 'both' }
                continue
            }
            if ($src.Of -eq 'application') { $appOnly++ }
            $item = [pscustomobject][ordered]@{ id = $id; upn = [string](Get-SIDerivedValue $o 'upn'); name = [string](Get-SIDerivedValue $o 'name'); type = [string](Get-SIDerivedValue $o 'type'); of = $src.Of }
            $byId[$id] = $item
            $owners.Add($item)
        }
    }
    if ($owners.Count -gt 0) {
        $out['owners'] = $owners.ToArray()
        $names = Format-SIOwnerNames -Owners $owners.ToArray(); if ($names) { $out['ownerNames'] = $names }
        $upns = @($owners | ForEach-Object { [string]$_.upn } | Where-Object { $_ }); if ($upns.Count -gt 0) { $out['ownerUpns'] = $upns }
        $out['ownerIds'] = @($owners | ForEach-Object { [string]$_.id })
    }
    $cnt = Get-SIDerivedValue $own 'count'
    $spCount = $null; if ($null -ne $cnt -and "$cnt" -ne '') { $spCount = [int]$cnt }
    if ($null -ne $app -or $null -ne $reads) {
        $appKnown = ($null -ne $app) -or ((Get-SIDerivedValue $reads 'applications') -eq $true)
        if (-not $appKnown) {
            if ([string](Get-SIDerivedValue $sp 'servicePrincipalType') -eq 'ManagedIdentity') { $appKnown = $true }
            $org = ([string](Get-SIDerivedValue $sp 'appOwnerOrganizationId')).Trim()
            if ($org -and $TenantId -and -not [string]::Equals($org, $TenantId.Trim(), [StringComparison]::OrdinalIgnoreCase)) { $appKnown = $true }
        }
        if ($null -ne $spCount) {
            $n = $spCount + $appOnly
            if ($n -eq 0 -and -not $appKnown) { $out['ownerCountUnknown'] = $true } else { $out['ownerCount'] = $n }
        } elseif ($appOnly -gt 0) { $out['ownerCount'] = $appOnly }
    }

    # ---- credentials ----
    $used = @{}
    foreach ($u in @(Get-SIDerivedValue (Get-SIDerivedValue $Object 'credUsage') 'items')) {
        if ($null -eq $u) { continue }
        $k = ([string](Get-SIDerivedValue $u 'keyId')).ToLowerInvariant(); $t = ConvertTo-SIDerivedUtc (Get-SIDerivedValue $u 'lastUsed')
        if ($k -and $t) { $used[$k] = $t }
    }
    $useKnown = ((Get-SIDerivedValue $reads 'credentialUse') -eq $true)
    $creds = New-Object System.Collections.Generic.List[object]
    $nowUtc = $Now.ToUniversalTime()
    foreach ($src in @(@{ O = $sp; On = 'service principal' }, @{ O = $app; On = 'application registration' })) {
        if ($null -eq $src.O) { continue }
        foreach ($kind in @(@{ P = 'passwordCredentials'; T = 'secret' }, @{ P = 'keyCredentials'; T = 'certificate' })) {
            foreach ($c in @(Get-SIDerivedValue $src.O $kind.P)) {
                if ($null -eq $c) { continue }
                $keyId = ([string](Get-SIDerivedValue $c 'keyId')).ToLowerInvariant()
                $end = ConvertTo-SIDerivedUtc (Get-SIDerivedValue $c 'endDateTime')
                $item = [ordered]@{ keyId = $keyId; type = $kind.T; name = [string](Get-SIDerivedValue $c 'displayName'); on = $src.On }
                $state = 'active'
                if ($end) {
                    $days = [int][Math]::Floor(($end - $nowUtc).TotalDays)
                    $item['expires'] = $end.ToString('o'); $item['daysLeft'] = $days
                    if ($days -lt 0) { $state = 'expired' } elseif ($days -le 30) { $state = 'expiring' }
                }
                $item['state'] = $state
                if ($keyId -and $used.ContainsKey($keyId)) {
                    $item['lastUsed'] = $used[$keyId].ToString('o')
                    if ($end -and $used[$keyId] -gt $end) { $item['usedAfterExpiry'] = $true }
                } elseif ($useKnown) { $item['neverUsed'] = $true }
                $creds.Add([pscustomobject]$item)
            }
        }
    }
    if ($creds.Count -gt 0) {
        $sorted = @($creds | Sort-Object @{ Expression = { if ($_.PSObject.Properties['daysLeft']) { [int]$_.daysLeft } else { [int]::MaxValue } } }, keyId)
        $out['credentials'] = $sorted
        $fix = New-Object System.Collections.Generic.List[string]
        foreach ($c in $sorted) {
            if ([string]$c.state -notin 'expired', 'expiring') { continue }
            $label = ''
            $short = [string]$c.keyId; if ($short.Length -gt 8) { $short = $short.Substring(0, 8) }
            if ($c.name) { $label = ("'{0}' (key id {1})" -f [string]$c.name, $short) } else { $label = ('key id {0}' -f [string]$c.keyId) }
            $when = ([datetime]$c.expires).ToUniversalTime().ToString('yyyy-MM-dd')
            $verb = 'expires'; if ([string]$c.state -eq 'expired') { $verb = 'expired' }
            $useText = ''
            if ($c.PSObject.Properties['lastUsed']) { $useText = (', last used {0}' -f ([datetime]$c.lastUsed).ToUniversalTime().ToString('yyyy-MM-dd')) }
            elseif ($c.PSObject.Properties['neverUsed']) { $useText = ', no recorded use (remove it if nothing needs it)' }
            $fix.Add(('Rotate the {0} {1} on the {2}: {3} {4}{5}.' -f [string]$c.type, $label, [string]$c.on, $verb, $when, $useText))
        }
        if ($fix.Count -gt 0) { $out['credentialFix'] = ($fix -join ' ') }
    }

    # ---- a managed identity's resource ----
    $alt = @(Get-SIDerivedValue $sp 'alternativeNames' | Where-Object { $_ })
    if ($alt.Count -eq 0) { $alt = @(Get-SIDerivedValue (Get-SIDerivedValue $Object 'spExtra') 'alternativeNames' | Where-Object { $_ }) }
    $res = @($alt | Where-Object { [string]$_ -match '^/subscriptions/' } | Select-Object -First 1)
    if ($res.Count -gt 0) {
        $rid = [string]$res[0]
        $out['attachedResourceId'] = $rid.ToLowerInvariant()
        $out['attachedResourceName'] = ($rid.TrimEnd('/') -split '/')[-1]
        $explicit = @($alt | Where-Object { [string]$_ -match '^(?i)isExplicit=' } | Select-Object -First 1)
        if ($explicit.Count -gt 0) { $out['managedIdentityKind'] = $(if ([string]$explicit[0] -match '(?i)=true$') { 'user-assigned' } else { 'system-assigned' }) }
    }

    # ---- requested against granted permissions ----
    if ($null -ne $app) {
        $prof = Get-SIDerivedValue $Object 'profile'
        $grantedApp = ConvertTo-SIDerivedList (Get-SIDerivedValue $prof 'EntraAppPermissions_Application')
        $og = Get-SIDerivedValue $Object 'oauth2Grants'
        $grantedDel = @{ Known = $false; Items = @() }
        if ($null -ne $og) { $grantedDel = ConvertTo-SIDerivedList (Get-SIDerivedValue $og 'permissions'); $grantedDel.Known = $true }
        elseif ((Get-SIDerivedValue $reads 'delegatedGrants') -eq $true) { $grantedDel = @{ Known = $true; Items = @() } }
        else { $grantedDel = ConvertTo-SIDerivedList (Get-SIDerivedValue $prof 'EntraAppPermissions_Delegated') }
        if ($grantedApp.Known -and $grantedDel.Known) {
            $req = @(@(Get-SIDerivedValue $app 'requestedPermissions') | Where-Object { $_ } | ForEach-Object { $n = [string](Get-SIDerivedValue $_ 'permission'); if (-not $n) { $n = [string](Get-SIDerivedValue $_ 'permissionId') }; $n } | Where-Object { $_ } | Sort-Object -Unique)
            $granted = @(@($grantedApp.Items) + @($grantedDel.Items) | Sort-Object -Unique)
            $out['permissionGap'] = [pscustomobject][ordered]@{
                requested = $req.Count; granted = $granted.Count
                requestedNotGranted = @($req | Where-Object { $granted -notcontains $_ })
                grantedNotRequested = @($granted | Where-Object { $req -notcontains $_ })
            }
        }
    }
    return $out
}

function Get-SIRecordTenantId {
    <# This install's tenant id, from the settings every SI process has. '' when none is set. #>
    foreach ($n in 'AzureTenantID', 'SpnTenantId', 'SI_SPN_TenantId', 'SI_TenantId', 'HighPriv_Modern_TenantID', 'TenantId') {
        $v = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue
        if ($v) { return [string]$v }
    }
    return ''
}

function Add-SIRecordDerivedPart {
    <#
    .SYNOPSIS  PURE. An assembled record object with its 'derived' part added (azure, entra service-principal and Shodan public-IP records);
               any other record, or one with nothing to derive, comes back unchanged.
    #>
    param([string]$Provider, [string]$RecordType, $Object, [string]$TenantId = '', [datetime]$Now = [datetime]::UtcNow)
    if ($null -eq $Object) { return $Object }
    $d = $null
    if ($Provider -eq 'azure') { $d = Get-SIAzureDerived -Object $Object }
    elseif ($Provider -eq 'entra' -and $RecordType -eq 'service_principal') {
        $d = Get-SIEntraSpDerived -Object $Object -TenantId $TenantId -Now $Now
        # identity context (owners of the principal AND its application, the credential list, the managed identity's
        # resource, requested against granted permissions): its values are added, and its owner count replaces the
        # principal-only count -- left out when the application's owners are not known
        $c = Get-SIEntraSpContextDerived -Object $Object -TenantId $TenantId -Now $Now
        foreach ($k in @($c.Keys)) { if ($k -ne 'ownerCountUnknown') { $d[$k] = $c[$k] } }
        if ($c.Contains('ownerCountUnknown') -and $d.Contains('ownerCount')) { $d.Remove('ownerCount') }
    }
    elseif ($Provider -eq 'entra' -and $RecordType -eq 'user') { $d = Get-SIEntraUserDerived -Object $Object }
    # the public IP's Shodan record: services, web answers, certificates, tags from the cached host answer (Azure lane)
    elseif ($Provider -eq 'shodan' -and $RecordType -eq 'public_ip') { $d = Get-SIShodanDerived -Object $Object -Now $Now }
    if ($null -eq $d -or $d.Count -eq 0) { return $Object }
    $prev = Get-SIDerivedValue $Object 'derived'
    if ($null -ne $prev) { foreach ($k in @($d.Keys)) { if ($null -eq (Get-SIDerivedValue $prev $k)) { $prev | Add-Member -NotePropertyName $k -NotePropertyValue $d[$k] -Force } }; return $Object }
    $Object | Add-Member -NotePropertyName 'derived' -NotePropertyValue ([pscustomobject]$d) -Force
    return $Object
}
