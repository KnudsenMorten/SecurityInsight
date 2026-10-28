#Requires -Version 5.1
<#
    Get-SIDefenderDeviceContext -- what Defender knows ABOUT a device beyond its DeviceInfo row, read once per batch of
    devices with ONE advanced hunting query and kept as the 'defender' part of the device's Defender record
    (provider mde, record type device), so the data-model mappings (data-model/mappings/mde.locked.json, defender.*)
    fill the device fields:

      hardening   DeviceTvmInfoGathering AdditionalFields -- the device's own security settings as Defender read them
                  (attack surface reduction rules, TLS versions, SMBv1, Secure Boot, antivirus mode ...)       si_hardening
      hardware    DeviceTvmHardwareFirmware -- BIOS / firmware version, processor, hardware model     si_bios_version, si_cpu
      networks    DeviceNetworkInfo, 7 days -- connected networks (a Public network is said), default gateways,
                  addresses with their subnet prefix                    si_networks, si_on_public_network, si_default_gateways
      alerts      AlertEvidence + AlertInfo, 30 days -- how many alerts named the device and the newest one
                                              si_alerts_30d, si_last_alert_title, si_last_alert_severity, si_last_alert_time
      admin logon DeviceLogonEvents, 30 days -- the newest successful logon by a local administrator and who
                                                                          si_last_admin_logon, si_admin_logon_accounts

    Every table is summarised INSIDE the query to one row per device (no row cap, no per-device call). A table the tenant
    does not have is read as empty (union isfuzzy with a stub), a column it does not have as empty (column_ifexists).

    NO DATA. The hardening and hardware tables come with the Defender Vulnerability Management add-on. When a table
    holds no row for the WHOLE tenant, the device's cell says "no data (licence missing or not collected yet)" -- an empty
    cell would read as "nothing to harden". An empty table is NOT proof of a missing licence (the tables also stay
    empty until Defender has collected), so the licence is not claimed missing and si_not_licensed is not set from it.

    READ ONLY. Never throws: a query that fails is said once (with the reason, so a query defect is seen and FIXED rather
    than re-run) and the devices keep everything else. PURE except Get-SIDefenderDeviceContext. PowerShell 7, REST only.
#>

$script:SI_MdeNoDataTvm = 'no data (licence missing or not collected yet)'
$script:SI_MdeTvmLicenceName = 'Defender Vulnerability Management add-on'
# devices per hunting query (a page, not a limit: every device is read, page by page)
$script:SI_MdeContextPageDevices = 1000
if (-not (Get-Command -Name Read-SIHuntingPages -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) 'shared/SI-HuntingPages.ps1') }

function ConvertTo-SIDeviceInfoPart {
    <#
    .SYNOPSIS  PURE. A DeviceInfo row as the record part: every property that HAS a value. A column the tenant lacks comes
               back as '' / null from column_ifexists -- kept, an empty value would be mapped before the next source of the
               same field (an empty antivirus status would read as "unknown" although the machines API knows it).
    #>
    param($Row)
    if ($null -eq $Row) { return $null }
    $o = [ordered]@{}
    $props = @()
    if ($Row -is [System.Collections.IDictionary]) { $props = @($Row.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $Row[$_] } }) }
    else { $props = @($Row.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } }) }
    foreach ($p in $props) {
        $v = $p.Value
        if ($null -eq $v) { continue }
        if ($v -is [string]) { $t = $v.Trim(); if (-not $t -or $t -eq '[]' -or $t -eq '{}' -or $t -eq 'null') { continue } }
        elseif ($v -is [System.Collections.IEnumerable] -and -not ($v -is [System.Collections.IDictionary])) { if (@($v).Count -eq 0) { continue } }
        $o[$p.Name] = $v
    }
    # why Defender calls the device internet-facing: the InternetFacing* properties of AdditionalFields as one object
    # (the source's names without the prefix), so the reason travels with the yes / no
    if ($o.Contains('AdditionalFields')) {
        $af = ConvertFrom-SIDefenderJson $o['AdditionalFields']
        if ($null -ne $af -and $af -is [System.Management.Automation.PSCustomObject]) {
            $inet = [ordered]@{}
            foreach ($ap in $af.PSObject.Properties) {
                if ($ap.Name -notlike 'InternetFacing*' -or $null -eq $ap.Value -or "$($ap.Value)" -eq '') { continue }
                $k = $ap.Name.Substring('InternetFacing'.Length); if (-not $k) { $k = 'Value' }
                $inet[$k] = $ap.Value
            }
            if ($inet.Count -gt 0) { $o['InternetFacing'] = [pscustomobject]$inet }
        }
    }
    return [pscustomobject]$o
}

function ConvertFrom-SIDefenderJson {
    <# PURE. A dynamic column as an object: already an object, or JSON text; $null when empty or unreadable. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        $t = $Value.Trim()
        if (-not $t -or $t -eq 'null') { return $null }
        if ($t.StartsWith('{') -or $t.StartsWith('[')) { try { return ($t | ConvertFrom-Json) } catch { return $null } }
        return $null
    }
    return $Value
}

function Get-SIDefenderDeviceContextKql {
    <#
    .SYNOPSIS  PURE. The one advanced hunting query for a batch of Defender device ids: one row per device that has ANY of
               the context, plus the tenant-wide "this table has rows" marks. Ids are checked (hex), never free text.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$DeviceIds)
    $ids = @($DeviceIds | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ -match '^[0-9a-f]{16,64}$' } | Sort-Object -Unique)
    if ($ids.Count -eq 0) { return '' }
    $list = ($ids | ForEach-Object { '"' + $_ + '"' }) -join ','
    return @"
let _ids = dynamic([$list]);
let _hardAny = toscalar(union isfuzzy=true (datatable(DeviceId:string)[]), (DeviceTvmInfoGathering) | take 1 | count);
let _hwAny = toscalar(union isfuzzy=true (datatable(DeviceId:string)[]), (DeviceTvmHardwareFirmware) | take 1 | count);
let _hard = union isfuzzy=true (datatable(DeviceId:string)[]), (DeviceTvmInfoGathering)
    | extend DeviceId = tolower(tostring(DeviceId))
    | where DeviceId in (_ids)
    | extend _t = todatetime(column_ifexists("Timestamp", datetime(null))), _af = tostring(column_ifexists("AdditionalFields", ""))
    | summarize arg_max(_t, _af) by DeviceId
    | project DeviceId, Hardening = _af, HardeningTime = _t;
let _hw = union isfuzzy=true (datatable(DeviceId:string)[]), (DeviceTvmHardwareFirmware)
    | extend DeviceId = tolower(tostring(DeviceId))
    | where DeviceId in (_ids)
    | extend _ct = tostring(column_ifexists("ComponentType", "")), _mf = tostring(column_ifexists("Manufacturer", "")), _cn = tostring(column_ifexists("ComponentName", "")), _cv = tostring(column_ifexists("ComponentVersion", ""))
    | summarize BiosVersion = take_anyif(trim(" ", strcat(_mf, " ", _cv)), _ct =~ "Bios"),
                Cpu = take_anyif(trim(" ", strcat(_mf, " ", _cn)), _ct =~ "Processor"),
                HardwareModel = take_anyif(trim(" ", strcat(_mf, " ", _cn)), _ct =~ "Hardware") by DeviceId;
let _net = union isfuzzy=true (datatable(DeviceId:string)[]), (DeviceNetworkInfo | where Timestamp > ago(7d))
    | extend DeviceId = tolower(tostring(DeviceId))
    | where DeviceId in (_ids)
    | extend _t = todatetime(column_ifexists("Timestamp", datetime(null))), _mac = tostring(column_ifexists("MacAddress", "")), _st = tostring(column_ifexists("NetworkAdapterStatus", "")),
             _cn = tostring(column_ifexists("ConnectedNetworks", "")), _gw = tostring(column_ifexists("DefaultGateways", "")), _ip = tostring(column_ifexists("IPAddresses", ""))
    | summarize arg_max(_t, _st, _cn, _gw, _ip) by DeviceId, _mac
    | where _st =~ "Up" or isempty(_st)
    | summarize ConnectedNetworks = make_set_if(_cn, isnotempty(_cn) and _cn != "[]" and _cn != "null", 16),
                DefaultGateways = make_set_if(_gw, isnotempty(_gw) and _gw != "[]" and _gw != "null", 16),
                AdapterAddresses = make_set_if(_ip, isnotempty(_ip) and _ip != "[]" and _ip != "null", 16) by DeviceId;
let _al = union isfuzzy=true (datatable(DeviceId:string, AlertId:string)[]), (AlertEvidence | where Timestamp > ago(30d) | where isnotempty(DeviceId))
    | extend DeviceId = tolower(tostring(DeviceId))
    | where DeviceId in (_ids)
    | distinct AlertId, DeviceId
    | join kind=inner (union isfuzzy=true (datatable(AlertId:string)[]), (AlertInfo | where Timestamp > ago(30d))
        | extend _at = todatetime(column_ifexists("Timestamp", datetime(null))), _title = tostring(column_ifexists("Title", "")), _sev = tostring(column_ifexists("Severity", "")), _cat = tostring(column_ifexists("Category", ""))
        | summarize arg_max(_at, _title, _sev, _cat) by AlertId) on AlertId
    | summarize Alerts30d = dcount(AlertId), HighAlerts30d = dcountif(AlertId, _sev =~ "High"), arg_max(_at, _title, _sev, _cat) by DeviceId
    | project DeviceId, Alerts30d, HighAlerts30d, LastAlertTime = _at, LastAlertTitle = _title, LastAlertSeverity = _sev, LastAlertCategory = _cat;
let _lg = union isfuzzy=true (datatable(DeviceId:string)[]), (DeviceLogonEvents | where Timestamp > ago(30d) | where ActionType == "LogonSuccess")
    | extend DeviceId = tolower(tostring(DeviceId))
    | where DeviceId in (_ids)
    | where tobool(column_ifexists("IsLocalAdmin", bool(null))) == true
    | extend _lt = todatetime(column_ifexists("Timestamp", datetime(null))), _acct = strcat(tostring(column_ifexists("AccountDomain", "")), "\\", tostring(column_ifexists("AccountName", "")))
    | summarize LastAdminLogon = max(_lt), AdminLogons30d = count(), AdminLogonAccounts = make_set(_acct, 10) by DeviceId;
union (_hard | project DeviceId), (_hw | project DeviceId), (_net | project DeviceId), (_al | project DeviceId), (_lg | project DeviceId)
| distinct DeviceId
| join kind=leftouter _hard on DeviceId
| join kind=leftouter _hw on DeviceId
| join kind=leftouter _net on DeviceId
| join kind=leftouter _al on DeviceId
| join kind=leftouter _lg on DeviceId
| project DeviceId, Hardening, HardeningTime, BiosVersion, Cpu, HardwareModel, ConnectedNetworks, DefaultGateways, AdapterAddresses,
          Alerts30d, HighAlerts30d, LastAlertTime, LastAlertTitle, LastAlertSeverity, LastAlertCategory, LastAdminLogon, AdminLogons30d, AdminLogonAccounts,
          HasHardeningData = (_hardAny > 0), HasHardwareData = (_hwAny > 0)
"@
}

function ConvertTo-SIDefenderHardening {
    <#
    .SYNOPSIS  PURE. DeviceTvmInfoGathering AdditionalFields as the device's hardening facts: the source's own property
               names and values, nothing renamed or dropped (a property Microsoft adds appears with no code change), plus
               the antivirus mode in words when the source gives its number.
    #>
    param($AdditionalFields)
    $src = ConvertFrom-SIDefenderJson $AdditionalFields
    if ($null -eq $src) { return $null }
    $o = [ordered]@{}
    $props = @()
    if ($src -is [System.Collections.IDictionary]) { $props = @($src.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $src[$_] } }) }
    elseif ($src -is [System.Management.Automation.PSCustomObject]) { $props = @($src.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Value = $_.Value } }) }
    foreach ($p in ($props | Sort-Object Name)) { if ($null -ne $p.Value -and "$($p.Value)" -ne '') { $o[$p.Name] = $p.Value } }
    if ($o.Count -eq 0) { return $null }
    return [pscustomobject]$o
}

function Get-SIDefenderAvModeName {
    <# PURE. Defender Antivirus mode as the value map knows it (Active / Passive / Disabled / EDR Blocked), from the number or word the source gives; '' when not given. #>
    param($Hardening)
    if ($null -eq $Hardening) { return '' }
    $p = $Hardening.PSObject.Properties['AvMode']
    if (-not $p -or $null -eq $p.Value) { return '' }
    switch (([string]$p.Value).Trim().ToLowerInvariant()) {
        '0' { return 'Active' }      'active' { return 'Active' }
        '1' { return 'Passive' }     'passive' { return 'Passive' }
        '2' { return 'Disabled' }    'disabled' { return 'Disabled' }
        '4' { return 'EDR Blocked' } 'edrblocked' { return 'EDR Blocked' } 'edr blocked' { return 'EDR Blocked' }
        '5' { return 'Passive' }
        default { return '' }
    }
}

function ConvertTo-SIDefenderNetworks {
    <#
    .SYNOPSIS  PURE. The network rows of one device (JSON texts as DeviceNetworkInfo holds them) as
               @{ Networks = [{ name; category; internet }]; OnPublicNetwork = bool or $null; Gateways = [..]; Addresses = ['10.1.2.3/24', ..] }.
    #>
    param($ConnectedNetworks, $DefaultGateways, $AdapterAddresses)
    $nets = New-Object System.Collections.Generic.List[object]; $seenNet = @{}
    foreach ($txt in @(ConvertFrom-SIDefenderJson $ConnectedNetworks)) {
        foreach ($n in @(ConvertFrom-SIDefenderJson $txt)) {
            if ($null -eq $n -or $n -is [string]) { continue }
            $name = ''; $cat = ''; $inet = $null
            foreach ($pn in 'Name', 'name') { if ($n.PSObject.Properties[$pn]) { $name = ([string]$n.$pn).Trim(); break } }
            foreach ($pn in 'Category', 'category') { if ($n.PSObject.Properties[$pn]) { $cat = ([string]$n.$pn).Trim(); break } }
            foreach ($pn in 'IsConnectedToInternet', 'isConnectedToInternet') { if ($n.PSObject.Properties[$pn] -and $null -ne $n.$pn) { $inet = ([string]$n.$pn -in 'True', 'true', '1'); break } }
            $k = ($name + '|' + $cat).ToLowerInvariant()
            if ($k -eq '|' -or $seenNet.ContainsKey($k)) { continue }
            $seenNet[$k] = $true
            $nets.Add([pscustomobject][ordered]@{ name = $name; category = $cat; internet = $inet })
        }
    }
    $gws = New-Object System.Collections.Generic.List[string]
    foreach ($txt in @(ConvertFrom-SIDefenderJson $DefaultGateways)) {
        # an item is the JSON text of one adapter's list, or (a set of one, already read) the address itself
        $inner = ConvertFrom-SIDefenderJson $txt
        if ($null -eq $inner -and $txt -is [string] -and $txt.Trim() -and -not $txt.Trim().StartsWith('[')) { $inner = $txt }
        foreach ($g in @($inner)) { $s = ([string]$g).Trim(); if ($s -and -not $gws.Contains($s)) { $gws.Add($s) } }
    }
    $addrs = New-Object System.Collections.Generic.List[string]
    foreach ($txt in @(ConvertFrom-SIDefenderJson $AdapterAddresses)) {
        foreach ($a in @(ConvertFrom-SIDefenderJson $txt)) {
            if ($null -eq $a -or $a -is [string]) { continue }
            $ip = ''; $pre = ''
            if ($a.PSObject.Properties['IPAddress']) { $ip = ([string]$a.IPAddress).Trim() }
            if ($a.PSObject.Properties['SubnetPrefix'] -and $null -ne $a.SubnetPrefix) { $pre = ([string]$a.SubnetPrefix).Trim() }
            if (-not $ip) { continue }
            $v = $ip; if ($pre) { $v = $ip + '/' + $pre }
            if (-not $addrs.Contains($v)) { $addrs.Add($v) }
        }
    }
    $public = $null
    if ($nets.Count -gt 0) { $public = (@($nets | Where-Object { [string]$_.category -match '^(?i)public$' }).Count -gt 0) }
    return @{ Networks = $nets.ToArray(); OnPublicNetwork = $public; Gateways = @($gws | Sort-Object); Addresses = @($addrs | Sort-Object) }
}

function ConvertTo-SIDefenderDeviceContext {
    <#
    .SYNOPSIS  PURE. One row of the context query as the device's 'defender' record part -- only what has a value. The
               hardening and hardware cells say "no data (licence missing or not collected yet)" when the tenant has no row in
               that table at all (an empty table is the only evidence, so no licence is claimed missing).
    #>
    param($Row)
    if ($null -eq $Row) { return $null }
    $g = { param($n) $p = $Row.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    $o = [ordered]@{}
    $notLicensed = New-Object System.Collections.Generic.List[string]
    $hasHard = (& $g 'HasHardeningData'); $hasHw = (& $g 'HasHardwareData')
    $hard = ConvertTo-SIDefenderHardening (& $g 'Hardening')
    if ($null -ne $hard) {
        $o['Hardening'] = $hard
        $av = Get-SIDefenderAvModeName -Hardening $hard
        if ($av) { $o['AvMode'] = $av }
    } elseif ($null -ne $hasHard -and "$hasHard" -in 'False', 'false', '0') { $o['HardeningNote'] = $script:SI_MdeNoDataTvm }
    $bios = ([string](& $g 'BiosVersion')).Trim(); $cpu = ([string](& $g 'Cpu')).Trim(); $hwm = ([string](& $g 'HardwareModel')).Trim()
    if ($bios) { $o['BiosVersion'] = $bios }
    if ($cpu) { $o['Cpu'] = $cpu }
    if ($hwm) { $o['HardwareModel'] = $hwm }
    if (-not $bios -and -not $cpu -and -not $hwm -and $null -ne $hasHw -and "$hasHw" -in 'False', 'false', '0') {
        $o['BiosVersion'] = $script:SI_MdeNoDataTvm; $o['Cpu'] = $script:SI_MdeNoDataTvm
    }
    $net = ConvertTo-SIDefenderNetworks -ConnectedNetworks (& $g 'ConnectedNetworks') -DefaultGateways (& $g 'DefaultGateways') -AdapterAddresses (& $g 'AdapterAddresses')
    if (@($net.Networks).Count -gt 0) { $o['Networks'] = @($net.Networks); $o['OnPublicNetwork'] = [bool]$net.OnPublicNetwork }
    if (@($net.Gateways).Count -gt 0) { $o['DefaultGateways'] = @($net.Gateways) }
    if (@($net.Addresses).Count -gt 0) { $o['AdapterAddresses'] = @($net.Addresses) }
    $n = 0
    if ([int]::TryParse(([string](& $g 'Alerts30d')), [ref]$n) -and $n -gt 0) {
        $o['Alerts30d'] = $n
        $h = 0; if ([int]::TryParse(([string](& $g 'HighAlerts30d')), [ref]$h)) { $o['HighAlerts30d'] = $h }
        foreach ($pair in @(@('LastAlertTitle', 'LastAlertTitle'), @('LastAlertSeverity', 'LastAlertSeverity'), @('LastAlertCategory', 'LastAlertCategory'))) { $v = ([string](& $g $pair[0])).Trim(); if ($v) { $o[$pair[1]] = $v } }
        $lt = (& $g 'LastAlertTime'); if ($null -ne $lt -and "$lt" -ne '') { $o['LastAlertTime'] = $lt }
    }
    $la = (& $g 'LastAdminLogon')
    if ($null -ne $la -and "$la" -ne '') {
        $o['LastAdminLogon'] = $la
        $c = 0; if ([int]::TryParse(([string](& $g 'AdminLogons30d')), [ref]$c)) { $o['AdminLogons30d'] = $c }
        # the accounts as a list: an array, the JSON text of one, or (a set of one) the account itself
        $accRaw = @(& $g 'AdminLogonAccounts')
        if ($accRaw.Count -eq 1 -and $accRaw[0] -is [string] -and $accRaw[0].Trim().StartsWith('[')) { $accRaw = @(ConvertFrom-SIDefenderJson $accRaw[0]) }
        $acc = @($accRaw | ForEach-Object { ([string]$_).Trim().Trim('\') } | Where-Object { $_ } | Sort-Object -Unique)
        if ($acc.Count -gt 0) { $o['AdminLogonAccounts'] = $acc }
    }
    if ($notLicensed.Count -gt 0) { $o['NotLicensed'] = $notLicensed.ToArray() }
    if ($o.Count -eq 0) { return $null }
    return [pscustomobject]$o
}

function Get-SIDefenderDeviceContext {
    <#
    .SYNOPSIS  The context of a batch of devices: Defender device id (lower) -> the 'defender' part. Never throws.
    .PARAMETER Query  test seam: { param($kql) rows } instead of the Graph call.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$DeviceIds, [scriptblock]$Query, [int]$PageDevices = $script:SI_MdeContextPageDevices)
    $out = @{}
    # one query per page of devices, each retried, a failed page asked once more at the end (Read-SIHuntingPages); a page
    # that still failed is said and its devices keep their previous values -- never "no data"
    $read = Read-SIHuntingPages -Ids $DeviceIds -Kql { param($p) Get-SIDefenderDeviceContextKql -DeviceIds $p } -Query $Query -PageSize $PageDevices
    foreach ($fl in $read.Failed) {
        Write-Warning ('Defender device details (hardening, hardware, networks, alerts, administrator logons) were not read for {0} device(s): {1} -- {2}. Those device fields keep their previous values.' -f $fl.Count, (Get-SIHuntingFailureKind $fl), $fl.Error)
    }
    $rows = $read.Rows
    # the tenant-wide "this table has no row at all" marks are the same on every row; a device WITHOUT a row still needs them, so keep them
    $hasHard = $null; $hasHw = $null
    foreach ($r in $rows) {
        if ($null -eq $r) { continue }
        if ($null -eq $hasHard -and $r.PSObject.Properties['HasHardeningData']) { $hasHard = $r.HasHardeningData }
        if ($null -eq $hasHw -and $r.PSObject.Properties['HasHardwareData']) { $hasHw = $r.HasHardwareData }
        $id = ([string]$r.DeviceId).Trim().ToLowerInvariant()
        if (-not $id) { continue }
        $part = ConvertTo-SIDefenderDeviceContext -Row $r
        if ($null -ne $part) { $out[$id] = $part }
    }
    # a device none of the tables has a row for still says that the tenant has no data (known only when a row came back)
    if ($null -ne $hasHard -or $null -ne $hasHw) {
        foreach ($d in @($DeviceIds)) {
            $id = ([string]$d).Trim().ToLowerInvariant()
            if (-not $id -or $out.ContainsKey($id) -or -not $read.ReadIds.Contains($id)) { continue }
            $part = ConvertTo-SIDefenderDeviceContext -Row ([pscustomobject]@{ DeviceId = $id; HasHardeningData = $hasHard; HasHardwareData = $hasHw })
            if ($null -ne $part) { $out[$id] = $part }
        }
    }
    return $out
}

function Add-SIDefenderDeviceContextParts {
    <#
    .SYNOPSIS  Reads the context of the given Defender device ids and keeps each as the 'defender' part of the device's
               record. Returns the number of devices that got one. Does nothing without the record capture.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()][string[]]$DeviceIds, [scriptblock]$Query)
    if (-not (Get-Command -Name Add-SIRecordPart -ErrorAction SilentlyContinue)) { return 0 }
    $ids = @($DeviceIds | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
    if ($ids.Count -eq 0) { return 0 }
    $a = @{ DeviceIds = $ids }; if ($Query) { $a['Query'] = $Query }
    $ctx = Get-SIDefenderDeviceContext @a
    $n = 0
    foreach ($id in @($ctx.Keys)) {
        try { Add-SIRecordPart -Provider 'mde' -RecordType 'device' -Key $id -Part 'defender' -Object $ctx[$id]; $n++ } catch { }
    }
    return $n
}
