#Requires -Version 5.1
<#
    SI v3 -- FULL ASSET PROPERTIES: the metadata additions (#301, operator 2026-10-05).

    What the CMDB hand-off needs and the first four sources did not carry:
      ad-computer       the Active Directory computer object, WHOLE -- where the AD source exists (a hybrid /
                        domain-joined host; LDAP through .NET System.DirectoryServices, no module). Elsewhere (a container) the source
                        is SKIPPED and says so; it is never a failure.
      exposure-graph    the Exposure Graph node of every device, Azure resource and identity -- one row per node.
                        #412: the node each PROFILER already reads (endpoint / azure / identity), kept whole -- the
                        separate Exposure Graph read this file used to make is gone (one pull per source).
      intune-device     the Intune managed device -- serial number and MAC addresses. Only where the app may read
                        it (DeviceManagementManagedDevices.Read.All); a refusal SKIPS the source and says so. Read by
                        the endpoint profiler at the full level (Invoke-SIAssetPropertiesExtraPulls).
      arm-vm-extension  every VM extension as its OWN row, keyed to its VM (ParentResourceId), never folded into
                        the VM's bag and never a CI of its own -- split out of the azure profiler's own ARM read.
    plus the two identifiers ServiceNow's identification rules rank highest after their own keys -- SERIAL NUMBER
    and MAC ADDRESS -- as typed envelope columns, with a stated precedence across sources (per asset, within the run
    of the profiler that read them).

    🔒 READ-ONLY. Every function here reads; none writes to AD, Intune, Defender or ARM. PS 5.1 + 7.
    🔒 Only at the full level (SI_AssetProperties = 'full'): nothing here runs otherwise.
    Every pull takes its transport as an injectable scriptblock, so each shape is a test, not a live experiment.
    NO Set-StrictMode here -- it leaks into the caller's scope.
#>

# ---------------------------------------------------------------------------------------------------
# Serial number + MAC: normalisation and precedence
# ---------------------------------------------------------------------------------------------------

# Values firmware ships when nobody set a serial. Sent to a CMDB they MATCH EVERY OTHER MACHINE WITH THE SAME
# PLACEHOLDER -- an identification rule on serial_number would fuse them into one CI. Refused, not passed on.
$script:SIPlaceholderSerials = @(
    'to be filled by o.e.m.', 'to be filled by oem', 'system serial number', 'default string', 'none', 'n/a', 'na',
    'not specified', 'not applicable', 'serial number', '0', '00000000', '0000000000', '123456789', 'chassis serial number',
    'invalid', 'unknown', 'oem', 'xxxxxxxxxx'
)

# 🔑 PRECEDENCE, AS DATA. The first source in the list that states a value wins for the asset; the source is
# carried with the value, so "where did this serial come from?" is answerable from the row.
#   serial: Intune reads it from the device's own firmware inventory; Defender's machine object carries it on
#           some tenants; the AD attribute is hand-maintained and the weakest; ARM has none for a VM.
#   MAC:    for an Azure VM the NIC resource is AUTHORITATIVE (the platform assigned it); then Intune's
#           ethernet, then its Wi-Fi address; Defender's machine object rarely carries one.
$script:SISerialPrecedence = @('intune-device', 'mde', 'ad-computer', 'entra-device', 'arm')
$script:SIMacPrecedence    = @('arm', 'intune-device', 'mde', 'ad-computer')

function Get-SIAssetPropertiesHardwarePrecedence {
    <# The precedence lists, for tests and for the documented mapping. #>
    [pscustomobject]@{ Serial = @($script:SISerialPrecedence); Mac = @($script:SIMacPrecedence) }
}

function ConvertTo-SISerialNumber {
    <# PURE. A serial a CMDB may identify on, or '' -- trimmed, placeholders and all-same-character values refused. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    $v = $Value
    if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) { $v = @($v | Where-Object { $_ } | Select-Object -First 1) | Select-Object -First 1 }
    $s = ([string]$v).Trim()
    if (-not $s) { return '' }
    if ($script:SIPlaceholderSerials -contains $s.ToLowerInvariant()) { return '' }
    if ($s.Length -ge 3 -and ($s.ToCharArray() | Select-Object -Unique).Count -eq 1) { return '' }
    $s
}

function ConvertTo-SIMacAddress {
    <#
        PURE. One MAC address as 'AA:BB:CC:DD:EE:FF', or '' when the value is not a usable one. ARM writes
        '00-0D-3A-12-34-56', Intune '000D3A123456', Defender '00:0d:3a:12:34:56' -- one fact, three spellings, and a
        CMDB identification rule compares strings. All-zero and broadcast addresses are refused.
    #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    $hex = (([string]$Value) -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
    if ($hex.Length -ne 12) { return '' }
    if ($hex -eq '000000000000' -or $hex -eq 'FFFFFFFFFFFF') { return '' }
    (($hex -split '(.{2})' | Where-Object { $_ }) -join ':')
}

function Get-SIAssetPropertiesNicMacMap {
    <#
        PURE. VM resource id (lower-case) -> MAC, from the ARM network interfaces in the same pull. A VM with several
        NICs gets its PRIMARY NIC's address (properties.primary), else the first one by NIC id -- deterministic, so
        the value does not flap between runs.
    #>
    param([AllowEmptyCollection()][object[]]$ArmRows = @())
    $byVm = @{}
    foreach ($r in @($ArmRows)) {
        if ($null -eq $r) { continue }
        if ([string]$r.type -ne 'microsoft.network/networkinterfaces' -and [string]$r.type -notlike 'microsoft.network/networkinterfaces') { continue }
        $p = $r.properties
        if ($null -eq $p) { continue }
        $vm = ''
        if ($p.PSObject.Properties['virtualMachine'] -and $p.virtualMachine) { $vm = [string]$p.virtualMachine.id }
        if (-not $vm) { continue }
        $mac = ConvertTo-SIMacAddress $(if ($p.PSObject.Properties['macAddress']) { $p.macAddress } else { $null })
        if (-not $mac) { continue }
        $primary = ($p.PSObject.Properties['primary'] -and [bool]$p.primary)
        $k = $vm.Trim().ToLowerInvariant()
        $cand = [pscustomobject]@{ Mac = $mac; Primary = $primary; NicId = [string]$r.id }
        if (-not $byVm.ContainsKey($k)) { $byVm[$k] = $cand; continue }
        $cur = $byVm[$k]
        if ($cand.Primary -and -not $cur.Primary) { $byVm[$k] = $cand; continue }
        if ($cand.Primary -eq $cur.Primary -and [string]::CompareOrdinal($cand.NicId.ToLowerInvariant(), $cur.NicId.ToLowerInvariant()) -lt 0) { $byVm[$k] = $cand }
    }
    $out = @{}
    foreach ($k in @($byVm.Keys)) { $out[$k] = $byVm[$k].Mac }
    $out
}

function Get-SIAssetPropertyHardwareIds {
    <#
        PURE. The serial number and MAC address ONE source object states for itself. '' where it states none.
          intune-device  serialNumber; MAC ethernetMacAddress, else wiFiMacAddress
          mde            serialNumber / macAddress when the machine object carries them (tenant-dependent)
          ad-computer    serialNumber (an AD attribute, multi-valued: the first usable one)
          arm            a network interface: its own macAddress; a virtual machine: its primary NIC's (-NicMacByVmId)
          entra-device   none (Entra keeps no hardware identifier)
    #>
    param([Parameter(Mandatory)][string]$SourceSystem, [AllowNull()]$SourceObject, [hashtable]$NicMacByVmId = @{})
    $serial = ''; $mac = ''
    if ($null -eq $SourceObject) { return [pscustomobject]@{ SerialNumber = ''; MacAddress = '' } }
    $f = { param($n) $p = $SourceObject.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    switch ($SourceSystem.Trim().ToLowerInvariant()) {
        'intune-device' {
            $serial = ConvertTo-SISerialNumber (& $f 'serialNumber')
            $mac = ConvertTo-SIMacAddress (& $f 'ethernetMacAddress')
            if (-not $mac) { $mac = ConvertTo-SIMacAddress (& $f 'wiFiMacAddress') }
        }
        'mde' {
            $serial = ConvertTo-SISerialNumber (& $f 'serialNumber')
            $mac = ConvertTo-SIMacAddress (& $f 'macAddress')
        }
        'ad-computer' { $serial = ConvertTo-SISerialNumber (& $f 'serialNumber') }
        'arm' {
            $type = ([string](& $f 'type')).ToLowerInvariant()
            if ($type -eq 'microsoft.network/networkinterfaces') {
                $p = & $f 'properties'
                if ($p -and $p.PSObject.Properties['macAddress']) { $mac = ConvertTo-SIMacAddress $p.macAddress }
            } elseif ($type -eq 'microsoft.compute/virtualmachines') {
                $k = ([string](& $f 'id')).Trim().ToLowerInvariant()
                if ($k -and $NicMacByVmId.ContainsKey($k)) { $mac = [string]$NicMacByVmId[$k] }
            }
        }
    }
    [pscustomobject]@{ SerialNumber = $serial; MacAddress = $mac }
}

function Set-SIAssetPropertiesHardwarePrecedence {
    <#
        Stamps the ASSET's serial number and MAC address (and the source each came from) on every row of the asset,
        chosen by the precedence above from what each of its rows states for itself:
            AssetSerialNumber / AssetSerialNumberSource / AssetMacAddress / AssetMacAddressSource
        One asset = one SI_CorrelationId (SI_AssetId when the row has none). A VM extension row states nothing and is
        stamped with its VM's values, so the hand-off can read any row of an asset. Returns the rows (same objects).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $groups = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $k = [string]$r.SI_CorrelationId; if (-not $k) { $k = 'aid|' + [string]$r.SI_AssetId }
        if (-not $groups.ContainsKey($k)) { $groups[$k] = New-Object System.Collections.Generic.List[object] }
        $groups[$k].Add($r)
    }
    foreach ($k in @($groups.Keys)) {
        $members = $groups[$k]
        $pick = {
            param([string[]]$order, [string]$col)
            foreach ($src in $order) {
                foreach ($m in $members) {
                    if ([string]$m.SourceSystem -ne $src) { continue }
                    $v = [string]$m.$col
                    if ($v) { return @($v, $src) }
                }
            }
            @('', '')
        }
        $s = & $pick $script:SISerialPrecedence 'SerialNumber'
        $m2 = & $pick $script:SIMacPrecedence 'MacAddress'
        foreach ($m in $members) {
            $m | Add-Member -NotePropertyName AssetSerialNumber -NotePropertyValue ([string]$s[0]) -Force
            $m | Add-Member -NotePropertyName AssetSerialNumberSource -NotePropertyValue ([string]$s[1]) -Force
            $m | Add-Member -NotePropertyName AssetMacAddress -NotePropertyValue ([string]$m2[0]) -Force
            $m | Add-Member -NotePropertyName AssetMacAddressSource -NotePropertyValue ([string]$m2[1]) -Force
        }
    }
    @($Rows)
}

# ---------------------------------------------------------------------------------------------------
# VM extensions as their own rows
# ---------------------------------------------------------------------------------------------------

$script:SIArmExtensionTypes = @('microsoft.compute/virtualmachines/extensions', 'microsoft.hybridcompute/machines/extensions',
                                'microsoft.compute/virtualmachinescalesets/extensions')

function Split-SIAssetPropertiesArmExtensions {
    <#
        PURE. Separates the VM extensions out of an ARM pull. Returns @{ Resources; Extensions }.
        Each extension gets `_siParentResourceId` (the VM's id: its own id up to '/extensions/') -- the anchor it
        resolves through (an extension is never a profile row of its own) -- and `_siExtensionName`.
        🔒 A separate ROW per extension, not a separate CI: level 4 stays structural (V3-ARCHITECTURE 3.6). The row
        carries ParentResourceId so the hand-off relates it to the VM; nothing makes it an asset.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $res = New-Object System.Collections.Generic.List[object]
    $ext = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $t = ([string]$r.type).ToLowerInvariant()
        if ($script:SIArmExtensionTypes -notcontains $t) { $res.Add($r); continue }
        $id = [string]$r.id
        $i = $id.ToLowerInvariant().LastIndexOf('/extensions/')
        if ($i -lt 1) { $res.Add($r); continue }
        $r | Add-Member -NotePropertyName _siParentResourceId -NotePropertyValue $id.Substring(0, $i) -Force
        $r | Add-Member -NotePropertyName _siExtensionName -NotePropertyValue $id.Substring($i + '/extensions/'.Length) -Force
        $ext.Add($r)
    }
    [pscustomobject]@{ Resources = $res.ToArray(); Extensions = $ext.ToArray() }
}

# ---------------------------------------------------------------------------------------------------
# The new sources
# ---------------------------------------------------------------------------------------------------

function ConvertTo-SIAdPlainObject {
    <#
        PURE. An AD object (ADComputer / a hashtable / a PSCustomObject) -> a plain object a JSON bag can carry:
        GUIDs and SIDs as strings, dates as ISO 8601 UTC, multi-valued attributes as string arrays, byte arrays
        (certificates, thumbnails) LEFT OUT and counted in _siBinaryAttributesOmitted -- a certificate blob is not
        CMDB metadata and would blow the row budget.
    #>
    param([Parameter(Mandatory)][AllowNull()]$InputObject)
    if ($null -eq $InputObject) { return $null }
    $o = [ordered]@{}
    $omitted = 0
    $props = if ($InputObject -is [System.Collections.IDictionary]) { @($InputObject.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $InputObject[$_] } }) }
             else { @($InputObject.PSObject.Properties | Where-Object { $_.MemberType -match 'Property' } | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } }) }
    foreach ($p in $props) {
        $n = [string]$p.Name; $v = $p.Value
        if ($n -in 'PropertyNames', 'AddedProperties', 'RemovedProperties', 'ModifiedProperties', 'PropertyCount') { continue }
        if ($null -eq $v) { continue }
        if ($v -is [byte[]]) { $omitted++; continue }
        if ($v -is [guid]) { $o[$n] = $v.ToString(); continue }
        if ($v -is [datetime]) { $o[$n] = $v.ToUniversalTime().ToString('o', [System.Globalization.CultureInfo]::InvariantCulture); continue }
        if ($v -is [System.Security.Principal.SecurityIdentifier]) { $o[$n] = $v.Value; continue }
        if ($v -is [string] -or $v -is [bool] -or $v -is [int] -or $v -is [long] -or $v -is [double]) { $o[$n] = $v; continue }
        if ($v -is [System.Collections.IEnumerable]) {
            $items = @(); $bin = $false
            foreach ($x in $v) { if ($x -is [byte[]]) { $bin = $true; continue }; if ($null -ne $x) { $items += [string]$x } }
            if ($bin -and $items.Count -eq 0) { $omitted++; continue }
            $o[$n] = $items
            continue
        }
        $o[$n] = [string]$v
    }
    if ($omitted -gt 0) { $o['_siBinaryAttributesOmitted'] = $omitted }
    [pscustomobject]$o
}

# ---------------------------------------------------------------------------------------------------
# The AD computer object through .NET System.DirectoryServices (LDAP) -- NO ActiveDirectory module (#471, #305).
# The object used to be read by the ActiveDirectory module's computer cmdlet (-Properties *); the runtime loads no
# PowerShell module, so the same object is read with a DirectorySearcher (paged, read-only) and rebuilt under the names
# the module gave it -- the row's fields do not move: the LDAP attributes under their lDAPDisplayName, plus the
# extended properties the module computed (Name, ObjectGUID, SID, Enabled, LastLogonDate, PasswordLastSet, Created,
# Modified ...).
# One difference, stated: the module's IPv4Address / IPv6Address were a DNS lookup per computer, not an AD attribute;
# they are not produced (the IP comes from the providers that observe it).
# ---------------------------------------------------------------------------------------------------

# lower-case LDAP name -> the property name the module gave it (its extended property where one exists, else the
# attribute's lDAPDisplayName). An attribute not listed keeps the name the directory returned.
$script:SIAdPropertyNames = @{
    'name' = 'Name'; 'cn' = 'CN'; 'dnshostname' = 'DNSHostName'; 'distinguishedname' = 'DistinguishedName'
    'samaccountname' = 'SamAccountName'; 'objectguid' = 'ObjectGUID'; 'objectclass' = 'ObjectClass'; 'objectcategory' = 'ObjectCategory'
    'operatingsystem' = 'OperatingSystem'; 'operatingsystemversion' = 'OperatingSystemVersion'
    'operatingsystemservicepack' = 'OperatingSystemServicePack'; 'operatingsystemhotfix' = 'OperatingSystemHotfix'
    'description' = 'Description'; 'displayname' = 'DisplayName'; 'location' = 'Location'; 'managedby' = 'ManagedBy'
    'serviceprincipalname' = 'servicePrincipalName'; 'serialnumber' = 'serialNumber'; 'memberof' = 'MemberOf'
    'useraccountcontrol' = 'userAccountControl'; 'lastlogontimestamp' = 'lastLogonTimestamp'; 'lastlogon' = 'lastLogon'
    'pwdlastset' = 'pwdLastSet'; 'accountexpires' = 'accountExpires'; 'badpasswordtime' = 'badPasswordTime'
    'badpwdcount' = 'badPwdCount'; 'logoncount' = 'logonCount'; 'primarygroupid' = 'primaryGroupID'
    'whencreated' = 'whenCreated'; 'whenchanged' = 'whenChanged'; 'usncreated' = 'uSNCreated'; 'usnchanged' = 'uSNChanged'
    'objectsid' = 'objectSid'; 'samaccounttype' = 'sAMAccountType'; 'iscriticalsystemobject' = 'isCriticalSystemObject'
    'localpolicyflags' = 'localPolicyFlags'; 'codepage' = 'codePage'; 'countrycode' = 'countryCode'
    'msds-supportedencryptiontypes' = 'msDS-SupportedEncryptionTypes'; 'ms-mcs-admpwdexpirationtime' = 'ms-Mcs-AdmPwdExpirationTime'
    'mslaps-passwordexpirationtime' = 'msLAPS-PasswordExpirationTime'; 'networkaddress' = 'networkAddress'
    'admincount' = 'adminCount'; 'instancetype' = 'instanceType'; 'dscorepropagationdata' = 'dSCorePropagationData'
    'usercertificate' = 'userCertificate'; 'thumbnailphoto' = 'thumbnailPhoto'
}
# multi-valued attributes stay arrays even with one value (as the module's value collection did)
$script:SIAdMultiValued = @('objectclass', 'serviceprincipalname', 'serialnumber', 'memberof', 'networkaddress', 'dscorepropagationdata', 'usercertificate', 'msds-allowedtodelegateto')

function ConvertFrom-SIAdFileTime {
    <# PURE. An AD large-integer time (100 ns since 1601) -> UTC [datetime], or $null for 0 / never (0x7FFF...). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    $n = 0L
    if (-not [long]::TryParse([string]$Value, [ref]$n)) { return $null }
    if ($n -le 0 -or $n -ge [long]::MaxValue) { return $null }
    try { [datetime]::FromFileTimeUtc($n) } catch { $null }
}

function ConvertFrom-SIAdSearchResult {
    <#
        PURE. One LDAP search result's attributes (a dictionary: attribute name -> its values, as DirectorySearcher
        returns them) -> the object the module gave for the same computer: the attributes under the module's names, the
        GUID as [guid], the SID as SecurityIdentifier, single values unwrapped, plus the extended properties the module
        computed. ConvertTo-SIAdPlainObject then makes it a JSON-safe row, as before.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Properties)
    $o = [ordered]@{}
    $raw = @{}
    foreach ($k in @($Properties.Keys)) {
        $lk = ([string]$k).ToLowerInvariant()
        if ($lk -eq 'adspath') { continue }   # the search's own path, not an attribute
        $vals = @($Properties[$k])
        $raw[$lk] = $vals
        $name = if ($script:SIAdPropertyNames.ContainsKey($lk)) { $script:SIAdPropertyNames[$lk] } else { [string]$k }
        $v = $null
        if ($lk -eq 'objectguid' -and $vals.Count -ge 1 -and $vals[0] -is [byte[]] -and $vals[0].Length -eq 16) { $v = New-Object guid (, [byte[]]$vals[0]) }
        elseif ($lk -eq 'objectsid' -and $vals.Count -ge 1 -and $vals[0] -is [byte[]]) { $v = New-Object System.Security.Principal.SecurityIdentifier ([byte[]]$vals[0]), 0 }
        elseif ($script:SIAdMultiValued -contains $lk -or $vals.Count -gt 1) { $v = $vals }
        elseif ($vals.Count -eq 1) { $v = $vals[0] }
        else { continue }
        $o[$name] = $v
    }
    # the extended properties the module computed from those attributes
    if ($o.Contains('objectSid')) { $o['SID'] = $o['objectSid'] }
    if ($raw.ContainsKey('useraccountcontrol')) {
        $uac = 0
        if ([int]::TryParse([string]@($raw['useraccountcontrol'])[0], [ref]$uac)) { $o['Enabled'] = -not [bool]($uac -band 2) }
    }
    foreach ($pair in @(@('lastlogontimestamp', 'LastLogonDate'), @('pwdlastset', 'PasswordLastSet'), @('accountexpires', 'AccountExpirationDate'), @('badpasswordtime', 'LastBadPasswordAttempt'))) {
        if ($raw.ContainsKey($pair[0])) { $d = ConvertFrom-SIAdFileTime @($raw[$pair[0]])[0]; if ($null -ne $d) { $o[$pair[1]] = $d } }
    }
    if ($raw.ContainsKey('whencreated')) { $o['Created'] = @($raw['whencreated'])[0] }
    if ($raw.ContainsKey('whenchanged')) { $o['Modified'] = @($raw['whenchanged'])[0] }
    [pscustomobject]$o
}

function Test-SIAdDirectoryAvailable {
    <# Is this host joined to an AD domain, so the directory can be searched? .NET only (no module). Never throws. #>
    try {
        Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
        $null = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        return $true
    } catch { return $false }
}

function Invoke-SIAdComputerSearch {
    <#
        Every computer object in the directory (or under -SearchBase), read-only, paged, ALL attributes -- through
        System.DirectoryServices.DirectorySearcher. Returns ConvertFrom-SIAdSearchResult objects.
        -NewSearcher { param($SearchBase) -> a searcher } -- the seam: anything with FindAll() returning results that
                     carry .Properties (attribute -> values). Default: a DirectorySearcher on LDAP://<SearchBase> (or the
                     computer's own domain), filter (objectClass=computer), page size 1000, subtree.
    #>
    [CmdletBinding()]
    param([string]$SearchBase = '', [scriptblock]$NewSearcher)
    if (-not $NewSearcher) {
        $NewSearcher = {
            param($Base)
            Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
            $root = if ($Base) { New-Object System.DirectoryServices.DirectoryEntry ('LDAP://' + $Base) } else { New-Object System.DirectoryServices.DirectoryEntry }
            $s = New-Object System.DirectoryServices.DirectorySearcher ($root)
            $s.Filter = '(objectClass=computer)'
            $s.PageSize = 1000
            $s.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $s
        }
    }
    $searcher = & $NewSearcher $SearchBase
    $found = $null
    try {
        $found = $searcher.FindAll()
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($r in $found) {
            if ($null -eq $r) { continue }
            $p = $r.Properties
            $d = @{}
            $names = if ($p.PSObject.Properties['PropertyNames']) { @($p.PropertyNames) } else { @($p.Keys) }
            foreach ($n in $names) { $d[[string]$n] = @($p[$n]) }
            $out.Add((ConvertFrom-SIAdSearchResult -Properties $d))
        }
        return $out.ToArray()
    } finally {
        if ($found -and $found.PSObject.Methods['Dispose']) { $found.Dispose() }
        if ($searcher -and $searcher.PSObject.Methods['Dispose']) { $searcher.Dispose() }
    }
}

function Get-SIWideAssetPropertiesFromAd {
    <#
        The AD computer objects, WHOLE (every attribute), read-only -- LDAP through .NET System.DirectoryServices,
        no PowerShell module (#471).
        -Available  { $true when the AD source exists here } -- default: this host is joined to an AD domain
                    (Test-SIAdDirectoryAvailable). A host that is not (a container, a non-domain VM) SKIPS the source
                    with the reason; that is the expected state there, not a failure.
        -Search     { param($SearchBase) -> AD objects } -- default Invoke-SIAdComputerSearch (DirectorySearcher).
    #>
    [CmdletBinding()]
    param([string]$SearchBase = '', [scriptblock]$Available, [scriptblock]$Search)
    if (-not $Available) { $Available = { Test-SIAdDirectoryAvailable } }
    if (-not (& $Available)) {
        return [pscustomobject]@{ SourceSystem = 'ad-computer'; Engine = 'identity'; Rows = @(); Complete = $true; Error = ''
                                  Skipped = 'the Active Directory source is not available on this host (not joined to an Active Directory domain) -- AD computer objects are collected where SecurityInsight runs on a domain-joined host' }
    }
    if (-not $Search) { $Search = { param($Base) Invoke-SIAdComputerSearch -SearchBase $Base } }
    try {
        $raw = @(& $Search $SearchBase)
    } catch {
        return [pscustomobject]@{ SourceSystem = 'ad-computer'; Engine = 'identity'; Rows = @(); Complete = $false; Error = $_.Exception.Message; Skipped = '' }
    }
    $rows = @($raw | Where-Object { $null -ne $_ } | ForEach-Object { ConvertTo-SIAdPlainObject -InputObject $_ })
    [pscustomobject]@{ SourceSystem = 'ad-computer'; Engine = 'identity'; Rows = $rows; Complete = $true; Error = ''; Skipped = '' }
}

function Test-SIGraphPermissionRefused {
    <# PURE. Did a Graph read fail because the app may not read it (403 / Forbidden / Authorization_RequestDenied)? #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    ([string]$Text) -match '(?i)\b403\b|forbidden|authorization_requestdenied|insufficient privileges|does not have .*permission'
}

function Get-SIWideAssetPropertiesFromIntune {
    <#
        Intune managed devices, WHOLE (deviceManagement/managedDevices) -- the serial number and MAC addresses.
        🔒 ONLY IF THE APP MAY READ THEM. A refused read (no DeviceManagementManagedDevices.Read.All) SKIPS the source
        with the permission named; it is not a failure, and nothing is asked for that the install did not grant.
        -Fetch  { param($Url, $Token, $Label) -> @{ Rows; Complete; Error } } -- default Invoke-SIPagedRest.
    #>
    [CmdletBinding()]
    param([string]$Token, [scriptblock]$Fetch)
    if (-not $Fetch) { $Fetch = { param($Url, $Tok, $Label) Invoke-SIPagedRest -Url $Url -Token $Tok -SourceLabel $Label } }
    $page = $null; $err = ''
    try { $page = & $Fetch 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=999' $Token 'assetprops Graph /deviceManagement/managedDevices' }
    catch { $err = $_.Exception.Message }
    if ($page -and $page.Error) { $err = [string]$page.Error }
    if ($err -and (Test-SIGraphPermissionRefused $err) -and -not ($page -and @($page.Rows).Count -gt 0)) {
        return [pscustomobject]@{ SourceSystem = 'intune-device'; Engine = 'endpoint'; Rows = @(); Complete = $true; Error = ''
                                  Skipped = 'not permitted: the app may not read Intune devices (DeviceManagementManagedDevices.Read.All) -- serial numbers and MAC addresses from Intune are not collected' }
    }
    $rows = @(); if ($page) { $rows = @($page.Rows) }
    [pscustomobject]@{ SourceSystem = 'intune-device'; Engine = 'endpoint'; Rows = $rows
                       Complete = $(if ($page -and $null -ne $page.Complete) { [bool]$page.Complete } else { $false }); Error = $err; Skipped = '' }
}
