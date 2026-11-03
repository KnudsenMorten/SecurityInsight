#Requires -Version 5.1
<#
    Get-SIEgAdComputers -- on-premises Active Directory COMPUTER accounts from the cloud signals, as provider records
    (REQUIREMENTS #497, the decided order: cloud signals first; the optional on-prem hybrid collector is a later phase,
    its contract is in DESIGN.md "On-premises Active Directory in the model").

    WHAT. The Exposure Graph's AD computer-account nodes (NodeLabel 'computer-account' -- what Defender for Identity and
    Defender for Endpoint learnt of each AD computer). #1052 (owner 2026-11-02, "we must trust the data quality"): a
    computer account is an IDENTITY of a machine, never a device of its own. Each node becomes ONE record of provider eg,
    record type computer_account (Get-SIEgRecordType), mapped by data-model/mappings/eg.locked.json. Its ONLY strong
    identifier is the Defender device id of the machine it belongs to, and only when that match is SAFE
    (Resolve-SIEgAdComputerMatch):
      * its name (sAMAccountName without the trailing $, else NodeName; the first label) equals the first label of the
        name of EXACTLY ONE Defender device the tenant has reported in 30 days -- any join type, any onboarding state
        counts as a candidate, so a second machine with that name makes it ambiguous;
      * that device is onboarded and domain-joined (Domain Joined / Hybrid Azure AD Join);
      * its DOMAIN is proven: the node's own DNS domain (dnsHostName, a dotted NodeName or domain name, the DC= parts of
        its distinguished name) equals the device's DNS suffix -- else the domain of its SID (adSid minus the RID) points
        at that suffix: of the unique, onboarded, domain-joined name matches of that domain SID, the suffix holds a strict
        majority and at least two of them (Get-SIEgAdComputerDomainKql). Anything else is NOT matched.
    A matched account then joins its Defender device's CI by that id and brings what it knows (domain controller,
    Exchange, ADFS -> si_device_roles). An account with no safe match is kept as a record WITHOUT a strong identifier: it
    is no CI at all (counted and said, never silent); the identity model has no place for computer accounts yet.
    Its AD SID / object GUID stay on the node for the record (SIEntityIds) but are NOT strong identifiers of the record:
    as join keys they named the old wrong device CIs, and a merge with them could hand the real machine's CI id away.

    HOW. A count probe; the domain map (one aggregate query); then hash buckets of at most SI_EgAdComputerPageRows
    (default 5,000) nodes per answer, each node with its Defender name candidates joined in the query -- the number of
    buckets follows the count, every node in exactly one bucket; each answer becomes record parts (which the producer's
    record stream writes and lets go) and is released. The same code for every tenant size.
    COMPLETENESS. A bucket that fails, or the domain map, marks the Exposure Graph pull NOT complete (the accounts are
    unknown this run, never gone -- and the domain map failing writes no account at all: a half-proven run would move a
    role off a device and back). A tenant whose graph has no computer-account node captures nothing and says so: the
    source is not present.
    READ ONLY (advanced hunting, ThreatHunting.Read.All -- the permission the Exposure Graph reads already hold). Never
    throws into the discover stage. PowerShell 7, REST only.
#>

$script:SIEgAdComputerLabel = 'computer-account'
# the Defender join types that mean "a member of an Active Directory domain" (DeviceInfo.JoinType)
$script:SIEgAdComputerDomainJoinTypes = @('Domain Joined', 'Hybrid Azure AD Join', 'Hybrid Azure AD Joined')
# how far back a Defender device counts as a candidate (DeviceInfo keeps 30 days)
$script:SIEgAdComputerDeviceDays = 30
# the candidate list a node carries at most (the count is exact; more than one already means ambiguous)
$script:SIEgAdComputerCandidateCap = 10

function Get-SIEgAdComputerNameKql {
    <# PURE. The KQL expression of a computer-account node's short name (lower case, no trailing $, first label). #>
    "tolower(tostring(split(trim_end(@'\`$', coalesce(tostring(NodeProperties.rawData.sAMAccountName), tostring(NodeProperties.rawData.samAccountName), NodeName)), '.')[0]))"
}

function Get-SIEgAdComputerDeviceKql {
    <# PURE. The Defender devices of the last 30 days, one row per device, with their short name and DNS suffix. #>
    $days = [int]$script:SIEgAdComputerDeviceDays
    @"
DeviceInfo
| where Timestamp > ago(${days}d)
| summarize arg_max(Timestamp, DeviceName, JoinType, OnboardingStatus) by DeviceId
| extend _short = tolower(tostring(split(DeviceName, '.')[0])), _dot = indexof(DeviceName, '.')
| extend _suffix = iff(_dot > 0, tolower(substring(DeviceName, _dot + 1)), '')
| where isnotempty(_short)
"@
}

function Get-SIEgAdComputerKql {
    <# PURE. The node query (-Buckets > 1: one hash bucket of it) with each node's Defender name candidates, or the count probe (-Count). #>
    param([int]$Buckets = 1, [int]$Bucket = 0, [switch]$Count)
    $q = "ExposureGraphNodes`n| where NodeLabel == '$($script:SIEgAdComputerLabel)'"
    if ($Count) { return ($q + "`n| count") }
    if ($Buckets -gt 1) { $q += ("`n| where hash(NodeId, {0}) == {1}" -f $Buckets, $Bucket) }
    $cap = [int]$script:SIEgAdComputerCandidateCap
    $dev = (Get-SIEgAdComputerDeviceKql).TrimEnd() + "`n| summarize SIDeviceCandidateCount = count(), SIDeviceCandidates = make_list(bag_pack('DeviceId', DeviceId, 'DeviceName', DeviceName, 'JoinType', JoinType, 'OnboardingStatus', OnboardingStatus), $cap) by _short"
    "let _dev = $dev;`n" + $q + "`n| extend _short = " + (Get-SIEgAdComputerNameKql) + "`n| join kind=leftouter _dev on _short" +
        "`n| project NodeId, NodeLabel, NodeName, Categories, EntityIds, NodeProperties, SIDeviceCandidateCount, SIDeviceCandidates"
}

function Get-SIEgAdComputerDomainKql {
    <#
        PURE. THE DOMAIN MAP: per AD domain SID (a computer account's SID without its RID), the DNS suffixes of the Defender
        devices its accounts match uniquely by name (onboarded, domain-joined) -- one aggregate row per (DomainSid, Suffix).
    #>
    $jt = (@($script:SIEgAdComputerDomainJoinTypes) | ForEach-Object { "'" + ($_ -replace "'", '') + "'" }) -join ', '
    $dev = (Get-SIEgAdComputerDeviceKql).TrimEnd() + "`n| summarize _n = count(), _sfx = take_any(_suffix), _join = take_any(JoinType), _onb = take_any(OnboardingStatus) by _short" +
        "`n| where _n == 1 and isnotempty(_sfx) and _join in~ ($jt) and _onb =~ 'Onboarded'"
    "let _dev = $dev;`n" +
        "ExposureGraphNodes`n| where NodeLabel == '$($script:SIEgAdComputerLabel)'`n| extend _short = " + (Get-SIEgAdComputerNameKql) +
        "`n| extend _sid = toupper(coalesce(tostring(NodeProperties.rawData.adSid), tostring(NodeProperties.rawData.objectSid), tostring(NodeProperties.rawData.sid), tostring(NodeProperties.rawData.securityIdentifier)))" +
        "`n| extend DomainSid = extract(@'^(S-1-5-21-\d+-\d+-\d+)-\d+$', 1, _sid)" +
        "`n| where isnotempty(DomainSid)`n| join kind=inner _dev on _short`n| summarize Matches = count() by DomainSid, Suffix = _sfx"
}

function Get-SIEgAdComputerIds {
    <#
        PURE. The AD ids of one computer-account node row: @{ Sid; Guid } -- from EntityIds (SecurityIdentifier,
        ActiveDirectoryObjectGuid / OnPremisesObjectId), else rawData (adSid, sid, objectSid, securityIdentifier,
        onPremisesSecurityIdentifier; objectGuid, objectGUID, adObjectId). Only a well-formed SID (S-1-...) and GUID count.
    #>
    param([AllowNull()]$Row)
    $sid = ''; $guid = ''
    if ($null -eq $Row) { return @{ Sid = ''; Guid = '' } }
    $g = { param($o, $n) if ($null -eq $o) { return $null }; $p = $o.PSObject.Properties[$n]; if ($p) { $p.Value } else { $null } }
    $ids = & $g $Row 'EntityIds'
    if ($ids -is [string]) { try { $ids = $ids | ConvertFrom-Json } catch { $ids = @() } }
    foreach ($e in @($ids)) {
        if ($e -is [string]) { try { $e = $e | ConvertFrom-Json } catch { continue } }
        if ($null -eq $e) { continue }
        $t = ([string](& $g $e 'type')).ToLowerInvariant(); $v = ([string](& $g $e 'id')).Trim()
        if (-not $v) { continue }
        if (-not $sid -and $t -eq 'securityidentifier' -and $v -match '^(?i)s-1-\d+(-\d+)+$') { $sid = $v.ToUpperInvariant() }
        if (-not $guid -and $t -in 'activedirectoryobjectguid', 'onpremisesobjectid' -and $v -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $guid = $v.ToLowerInvariant() }
    }
    $raw = Get-SIEgAdComputerRaw -Row $Row
    if (-not $sid) {
        foreach ($k in 'adSid', 'sid', 'objectSid', 'securityIdentifier', 'onPremisesSecurityIdentifier') {
            $v = ([string](& $g $raw $k)).Trim()
            if ($v -match '^(?i)s-1-\d+(-\d+)+$') { $sid = $v.ToUpperInvariant(); break }
        }
    }
    if (-not $guid) {
        foreach ($k in 'objectGuid', 'objectGUID', 'adObjectId', 'onPremisesObjectId') {
            $v = ([string](& $g $raw $k)).Trim()
            if ($v -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $guid = $v.ToLowerInvariant(); break }
        }
    }
    @{ Sid = $sid; Guid = $guid }
}

function Get-SIEgAdComputerRaw {
    <# PURE. A node row's rawData (NodeProperties.rawData, NodeProperties itself when it has none; JSON text parsed). #>
    param([AllowNull()]$Row)
    if ($null -eq $Row) { return $null }
    $p = $Row.PSObject.Properties['NodeProperties']; if (-not $p) { $p = $Row.PSObject.Properties['NodePropertiesJson'] }
    $props = $null; if ($p) { $props = $p.Value }
    if ($props -is [string]) { try { $props = $props | ConvertFrom-Json } catch { $props = $null } }
    if ($null -eq $props) { return $null }
    $r = $props.PSObject.Properties['rawData']
    if ($r -and $null -ne $r.Value) { return $r.Value }
    $props
}

function Get-SIEgAdComputerShortName {
    <# PURE. The short name a computer account is matched by: sAMAccountName without the trailing $, else NodeName -- its first label, lower case. #>
    param([AllowNull()]$Row)
    if ($null -eq $Row) { return '' }
    $raw = Get-SIEgAdComputerRaw -Row $Row
    $n = ''
    foreach ($k in 'sAMAccountName', 'samAccountName') {
        if ($raw -and $raw.PSObject.Properties[$k] -and [string]$raw.$k) { $n = [string]$raw.$k; break }
    }
    if (-not $n -and $Row.PSObject.Properties['NodeName']) { $n = [string]$Row.NodeName }
    $n = $n.Trim().TrimEnd('$').Trim()
    $i = $n.IndexOf('.'); if ($i -ge 0) { $n = $n.Substring(0, $i) }
    $n.ToLowerInvariant()
}

function Get-SIEgAdComputerDnsDomain {
    <#
        PURE. The DNS domain a computer-account node names itself (lower case; '' when it names none): dnsHostName after its
        first label, a dotted NodeName after its first label, a dotted domain name (dnsDomainName / domainName / domain /
        accountDomain), else the DC= parts of its distinguished name. A NetBIOS name (no dot) is not a DNS domain.
    #>
    param([AllowNull()]$Row)
    if ($null -eq $Row) { return '' }
    $raw = Get-SIEgAdComputerRaw -Row $Row
    $val = { param($k) if ($raw -and $raw.PSObject.Properties[$k]) { ([string]$raw.$k).Trim() } else { '' } }
    $after = { param($s) $i = $s.IndexOf('.'); if ($i -gt 0 -and $i -lt $s.Length - 1) { $s.Substring($i + 1) } else { '' } }
    foreach ($k in 'dnsHostName', 'dNSHostName', 'fqdn') { $v = & $val $k; if ($v) { $d = & $after $v; if ($d) { return $d.TrimEnd('.').ToLowerInvariant() } } }
    if ($Row.PSObject.Properties['NodeName']) { $d = & $after ([string]$Row.NodeName).Trim(); if ($d) { return $d.TrimEnd('.').ToLowerInvariant() } }
    foreach ($k in 'dnsDomainName', 'domainName', 'domain', 'accountDomain') { $v = & $val $k; if ($v -match '^[^.\s]+(\.[^.\s]+)+$') { return $v.TrimEnd('.').ToLowerInvariant() } }
    foreach ($k in 'distinguishedName', 'distinguishedname') {
        $v = & $val $k
        if ($v) {
            $dc = @([regex]::Matches($v, '(?i)(?:^|,)\s*DC=([^,]+)') | ForEach-Object { $_.Groups[1].Value.Trim() } | Where-Object { $_ })
            if ($dc.Count -ge 2) { return (($dc -join '.').ToLowerInvariant()) }
        }
    }
    ''
}

function Get-SIEgAdComputerDomainSid {
    <# PURE. The domain part of an AD account SID (S-1-5-21-a-b-c of S-1-5-21-a-b-c-RID), upper case; '' when it is not a domain SID. #>
    param([AllowNull()][AllowEmptyString()][string]$Sid)
    if ([string]$Sid -match '^(?i)(S-1-5-21-\d+-\d+-\d+)-\d+$') { return $matches[1].ToUpperInvariant() }
    ''
}

function ConvertTo-SIEgAdComputerDomainMap {
    <#
        PURE. The domain map's rows (DomainSid, Suffix, Matches) -> domain SID -> @{ Suffix (the proven DNS suffix, '' = none);
        Suffixes (suffix -> matches) }. Proven: one suffix holds a STRICT majority of that SID's matches and at least two
        of them -- a domain whose machines point at two DNS suffixes evenly, or that only one machine vouches for, proves
        nothing.
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @())
    $by = @{}
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $ds = ([string]$r.DomainSid).Trim().ToUpperInvariant(); $sx = ([string]$r.Suffix).Trim().TrimEnd('.').ToLowerInvariant()
        if (-not $ds -or -not $sx) { continue }
        $n = 0L; [void][long]::TryParse([string]$r.Matches, [ref]$n)
        if ($n -le 0) { continue }
        if (-not $by.ContainsKey($ds)) { $by[$ds] = @{} }
        $by[$ds][$sx] = [long]$by[$ds][$sx] + $n
    }
    $out = @{}
    foreach ($ds in @($by.Keys)) {
        $tot = 0L; $best = ''; $bestN = 0L
        foreach ($sx in @($by[$ds].Keys)) { $n = [long]$by[$ds][$sx]; $tot += $n; if ($n -gt $bestN -or ($n -eq $bestN -and [string]::CompareOrdinal($sx, $best) -lt 0)) { $best = $sx; $bestN = $n } }
        $proven = ''
        if ($bestN -ge 2 -and ($bestN * 2) -gt $tot) { $proven = $best }
        $out[$ds] = @{ Suffix = $proven; Suffixes = $by[$ds] }
    }
    $out
}

function Resolve-SIEgAdComputerMatch {
    <#
    .SYNOPSIS  PURE. #1052 Which Defender device a computer-account node belongs to -- only when the match is SAFE.
    .OUTPUTS   @{ State; DeviceId; DeviceName; Reason }. State:
                 matched            exactly one candidate, onboarded, domain-joined, its domain proven
                 no_name            the node has no name to match by
                 no_device          no Defender device has its name
                 ambiguous          two or more Defender devices have its name (any join type / onboarding state)
                 not_onboarded      the one device is not onboarded (Defender only discovered it)
                 not_domain_joined  the one device is not domain-joined
                 domain_mismatch    the node's own domain, or its SID's proven domain, is another DNS domain
                 domain_unproven    nothing proves the device is in the account's domain
               Only 'matched' gives the record a strong identifier; every other state keeps it out of the CMDB.
    .PARAMETER Row        a node row of Get-SIEgAdComputerKql (SIDeviceCandidateCount, SIDeviceCandidates)
    .PARAMETER DomainMap  ConvertTo-SIEgAdComputerDomainMap
    #>
    param([AllowNull()]$Row, [hashtable]$DomainMap = @{})
    $res = { param($s, $why, $id = '', $nm = '') [pscustomobject]@{ State = $s; DeviceId = $id; DeviceName = $nm; Reason = $why } }
    $name = Get-SIEgAdComputerShortName -Row $Row
    if (-not $name) { return (& $res 'no_name' 'the computer account has no name to match by') }
    $raw = $null
    if ($Row.PSObject.Properties['SIDeviceCandidates']) { $raw = $Row.SIDeviceCandidates }
    if ($raw -is [string]) { $t = $raw.Trim(); if ($t) { try { $raw = $t | ConvertFrom-Json } catch { $raw = @() } } else { $raw = @() } }
    $cands = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($c in @($raw)) {
        if ($c -is [string]) { try { $c = $c | ConvertFrom-Json } catch { continue } }
        if ($null -eq $c) { continue }
        $id = ([string]$c.DeviceId).Trim().ToLowerInvariant()
        $dn = ([string]$c.DeviceName).Trim().TrimEnd('.')
        if ($id -notmatch '^[0-9a-f]{40}$' -or -not $dn) { continue }
        $first = $dn; $i = $first.IndexOf('.'); if ($i -ge 0) { $first = $first.Substring(0, $i) }
        if ($first.ToLowerInvariant() -ne $name) { continue }
        if ($seen.Add($id)) { $cands.Add($c) }
    }
    $count = 0L
    if ($Row.PSObject.Properties['SIDeviceCandidateCount']) { [void][long]::TryParse([string]$Row.SIDeviceCandidateCount, [ref]$count) }
    if ($cands.Count -gt $count) { $count = $cands.Count }
    if ($count -eq 0) { return (& $res 'no_device' ("no Defender device is named '{0}'" -f $name)) }
    if ($count -gt 1 -or $cands.Count -ne 1) { return (& $res 'ambiguous' ("{0} Defender devices are named '{1}' -- never merged by name" -f $count, $name)) }
    $c = $cands[0]
    $id = ([string]$c.DeviceId).Trim().ToLowerInvariant(); $dn = ([string]$c.DeviceName).Trim().TrimEnd('.').ToLowerInvariant()
    if (([string]$c.OnboardingStatus).Trim() -ne 'Onboarded') { return (& $res 'not_onboarded' ("the one Defender device named '{0}' ({1}) is not onboarded ({2})" -f $name, $dn, [string]$c.OnboardingStatus) $id $dn) }
    $jt = ([string]$c.JoinType).Trim()
    if (-not (@($script:SIEgAdComputerDomainJoinTypes) | Where-Object { $_ -eq $jt })) { return (& $res 'not_domain_joined' ("the one Defender device named '{0}' ({1}) is not domain-joined ({2})" -f $name, $dn, $(if ($jt) { $jt } else { 'no join type' })) $id $dn) }
    $suffix = ''; $i = $dn.IndexOf('.'); if ($i -gt 0) { $suffix = $dn.Substring($i + 1) }
    if (-not $suffix) { return (& $res 'domain_unproven' ("the Defender device '{0}' has no DNS domain to compare" -f $dn) $id $dn) }
    $own = Get-SIEgAdComputerDnsDomain -Row $Row
    if ($own) {
        if ($own -eq $suffix) { return (& $res 'matched' ("its name and its DNS domain {0} match the one Defender device {1}" -f $own, $dn) $id $dn) }
        return (& $res 'domain_mismatch' ("the account is in {0}, the Defender device {1} in {2}" -f $own, $dn, $suffix) $id $dn)
    }
    $dsid = Get-SIEgAdComputerDomainSid (Get-SIEgAdComputerIds -Row $Row).Sid
    if (-not $dsid) { return (& $res 'domain_unproven' ("the account names no domain (no DNS domain, no domain SID) -- '{0}' is not proven to be {1}" -f $name, $dn) $id $dn) }
    $dm = $null; if ($DomainMap) { $dm = $DomainMap[$dsid] }
    $proven = ''; if ($dm) { $proven = [string]$dm.Suffix }
    if (-not $proven) { return (& $res 'domain_unproven' ("the domain of its SID ({0}) is not proven to be {1} (too few or split name matches)" -f $dsid, $suffix) $id $dn) }
    if ($proven -ne $suffix) { return (& $res 'domain_mismatch' ("its SID's domain is {0}, the Defender device {1} is in {2}" -f $proven, $dn, $suffix) $id $dn) }
    & $res 'matched' ("its name matches the one Defender device {0}, in {1} -- the domain its SID's other machines are in" -f $dn, $suffix) $id $dn
}

function ConvertTo-SIEgAdComputerNode {
    <#
        PURE. One node row -> the node object the record capture keeps (the Exposure Graph node shape, the query's candidate
        columns left out), with SIEntityIds (the AD ids, and the Defender device id ONLY when -Match is 'matched' -- the one
        strong identifier the mapping reads) and SIDeviceMatch (the decision and why).
    #>
    param([Parameter(Mandatory)][AllowNull()]$Row, $Match)
    if ($null -eq $Row -or -not [string]$Row.NodeId) { return $null }
    $clean = [ordered]@{}
    foreach ($n in 'NodeId', 'NodeLabel', 'NodeName', 'Categories', 'EntityIds', 'NodeProperties') { if ($Row.PSObject.Properties[$n]) { $clean[$n] = $Row.$n } }
    $clean = [pscustomobject]$clean
    $node = $null
    if (Get-Command -Name ConvertTo-SIFullExposureGraphNode -ErrorAction SilentlyContinue) { $node = ConvertTo-SIFullExposureGraphNode -Row $clean }
    else { $node = $clean }
    $ids = Get-SIEgAdComputerIds -Row $Row
    $res = New-Object System.Collections.Generic.List[object]
    if ($ids.Sid) { $res.Add([pscustomobject]@{ type = 'SecurityIdentifier'; id = $ids.Sid }) }
    if ($ids.Guid) { $res.Add([pscustomobject]@{ type = 'ActiveDirectoryObjectGuid'; id = $ids.Guid }) }
    if ($null -ne $Match -and [string]$Match.State -eq 'matched' -and [string]$Match.DeviceId -match '^[0-9a-f]{40}$') {
        $res.Add([pscustomobject]@{ type = 'SenseDeviceId'; id = [string]$Match.DeviceId })
    }
    $node | Add-Member -NotePropertyName 'SIEntityIds' -NotePropertyValue $res.ToArray() -Force
    $node | Add-Member -NotePropertyName 'SIIdentitySource' -NotePropertyValue 'ad' -Force
    if ($null -ne $Match) {
        $node | Add-Member -NotePropertyName 'SIDeviceMatch' -NotePropertyValue ([pscustomobject][ordered]@{ state = [string]$Match.State; deviceId = [string]$Match.DeviceId; deviceName = [string]$Match.DeviceName; reason = [string]$Match.Reason }) -Force
    }
    $node
}

function Invoke-SIEgAdComputerQuery {
    <# One hunting query -> @{ Ok; Rows; Error }. Retries a transient failure (5 / 15 s); never throws. #>
    param([Parameter(Mandatory)][string]$Kql)
    $last = ''
    for ($a = 1; $a -le 3; $a++) {
        try {
            if (Get-Command -Name Invoke-SIEgIdentityQuery -ErrorAction SilentlyContinue) {
                $r = Invoke-SIEgIdentityQuery -Query $Kql -MaxAttempts 1
                if ($r.Ok) { return $r }
                $last = [string]$r.Error
            } else {
                . (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'auth\Get-SIGraphToken.ps1')
                $token = Get-SIGraphToken -Resource Graph
                $resp = Invoke-RestMethod -Method Post -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -ErrorAction Stop `
                    -Headers @{ Authorization = ('Bearer ' + $token); 'Content-Type' = 'application/json' } -Body (@{ Query = $Kql } | ConvertTo-Json -Compress)
                $rows = if ($resp.results) { @($resp.results) } elseif ($resp.Results) { @($resp.Results) } else { @() }
                return @{ Ok = $true; Rows = $rows; Error = '' }
            }
        } catch {
            $last = [string]$_.Exception.Message
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $last = [string]$_.ErrorDetails.Message }
            # a refused query (400) gives the same answer when asked again -- it must be fixed, not retried
            if ($last -match '(?i)semantic error|syntax error|BadRequest|\(400\)') { break }
        }
        if ($a -lt 3) { Start-Sleep -Seconds (5 * [Math]::Pow(3, $a - 1)) }
    }
    @{ Ok = $false; Rows = @(); Error = $last }
}

function Invoke-SIEgAdComputerCapture {
    <#
    .SYNOPSIS  Reads every computer-account node of the Exposure Graph, decides each one's Defender device (safe match only)
               and hands each to the record capture. Returns @{ Nodes; Buckets; Failed; Present; Matched; Ambiguous;
               NoDevice; Refused; Text } -- Present = $false when the graph has no such node (the source is not present).
               Never throws.
    .PARAMETER Query  test seam: { param($Kql) } -> @{ Ok; Rows; Error }.
    #>
    param([scriptblock]$Query, [int]$PageRows = 0)
    $out = @{ Nodes = 0; Buckets = 0; Failed = 0; Present = $true; Matched = 0; Ambiguous = 0; NoDevice = 0; Refused = 0; States = @{}; Text = '' }
    if (-not (Get-Command -Name Add-SIRecordPartFromSource -ErrorAction SilentlyContinue)) { $out.Text = 'AD computers from the Exposure Graph: the record capture is not loaded -- nothing read.'; return $out }
    if ($PageRows -le 0) { $PageRows = 5000; if ($global:SI_EgAdComputerPageRows -and [int]$global:SI_EgAdComputerPageRows -gt 0) { $PageRows = [int]$global:SI_EgAdComputerPageRows } }
    $ask = { param($k) if ($Query) { & $Query $k } else { Invoke-SIEgAdComputerQuery -Kql $k } }
    $notComplete = {
        param($why)
        if (Get-Command -Name Set-SIRecordPull -ErrorAction SilentlyContinue) { Set-SIRecordPull -Provider 'eg' -Complete $false -ErrorText ('AD computer accounts: ' + $why) }
    }
    try {
        $total = $null
        $probe = & $ask (Get-SIEgAdComputerKql -Count)
        if ($probe.Ok) {
            $first = @($probe.Rows) | Select-Object -First 1; $n = 0L
            foreach ($c in 'Count', 'count_') { if ($first -and $first.PSObject.Properties[$c] -and [long]::TryParse([string]$first.$c, [ref]$n)) { $total = $n; break } }
            if ($null -eq $total) { $total = 0L }
        }
        if ($null -ne $total -and $total -eq 0) {
            $out.Present = $false
            $out.Text = 'AD computers from the Exposure Graph: the graph has no AD computer account -- the source is not present on this tenant (nothing removed).'
            return $out
        }
        # THE DOMAIN MAP first: without it no match is proven -- and a run that writes the accounts unproven would move a
        # domain controller's role off its device and back. Not read = the accounts are unknown this run (not complete).
        $dmq = & $ask (Get-SIEgAdComputerDomainKql)
        if (-not $dmq.Ok) {
            $out.Failed++
            & $notComplete ('the domain map could not be read (' + [string]$dmq.Error + ')')
            $out.Text = ('AD computers from the Exposure Graph: the domain map could not be read ({0}) -- the accounts are UNKNOWN this run, not removed; no account is written.' -f [string]$dmq.Error)
            return $out
        }
        $domainMap = ConvertTo-SIEgAdComputerDomainMap -Rows @($dmq.Rows)
        # an unknown count (the probe failed): enough buckets that a large graph still answers in pages
        $buckets = 8
        if ($null -ne $total) { $buckets = [int][Math]::Max(1, [Math]::Ceiling($total / [double]$PageRows)) }
        $out.Buckets = $buckets
        $err = ''
        for ($b = 0; $b -lt $buckets; $b++) {
            $r = & $ask (Get-SIEgAdComputerKql -Buckets $buckets -Bucket $b)
            if (-not $r.Ok) { $out.Failed++; $err = [string]$r.Error; continue }
            foreach ($row in @($r.Rows)) {
                if ($null -eq $row -or -not [string]$row.NodeId) { continue }
                $m = Resolve-SIEgAdComputerMatch -Row $row -DomainMap $domainMap
                $node = ConvertTo-SIEgAdComputerNode -Row $row -Match $m
                if ($null -eq $node) { continue }
                Add-SIRecordPartFromSource -SourceSystem 'exposure-graph' -Object $node
                $out.Nodes++
                $s = [string]$m.State
                $out.States[$s] = [int]$out.States[$s] + 1
                switch ($s) { 'matched' { $out.Matched++ } 'ambiguous' { $out.Ambiguous++ } 'no_device' { $out.NoDevice++ } default { $out.Refused++ } }
            }
            $r = $null
        }
        $tally = ('{0} enrich their Defender device (a safe name + domain match); {1} ambiguous (two or more devices with the name), {2} without a Defender device, {3} not proven (not onboarded / not domain-joined / another or unproven domain) -- none of them is a device CI of its own' -f $out.Matched, $out.Ambiguous, $out.NoDevice, $out.Refused)
        if ($out.Failed -gt 0) {
            & $notComplete $err
            $out.Text = ('AD computers from the Exposure Graph: {0} node(s); {1} of {2} page(s) could not be read ({3}) -- their computers are UNKNOWN this run, not removed. Of those read: {4}.' -f $out.Nodes, $out.Failed, $buckets, $err, $tally)
        } else {
            if (Get-Command -Name Set-SIRecordPull -ErrorAction SilentlyContinue) { Set-SIRecordPull -Provider 'eg' -Complete $true }
            $out.Text = ('AD computers from the Exposure Graph: {0} computer account(s) in {1} page(s): {2}.' -f $out.Nodes, $buckets, $tally)
        }
    } catch {
        $out.Failed++
        & $notComplete $_.Exception.Message
        $out.Text = ('AD computers from the Exposure Graph: not read ({0}) -- they are UNKNOWN this run, not removed.' -f $_.Exception.Message)
    }
    $out
}
