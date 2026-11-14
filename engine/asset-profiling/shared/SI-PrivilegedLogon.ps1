#Requires -Version 5.1
<#
    THE PRIVILEGED LOGONS OF A DEVICE -- a tier source of the endpoint (#1209).

    Owner 2026-11-12: "Any privileged logon counts"; "remember we must also support tier 2 hr finance logins by group";
    "their devices must be tier 2 and patched before tier 3"; "goal is clear. if a priv logon happens then it is more
    important than tier 3. so if tier 0/1/2 logon happens classify device with tier"; on scale: "will not scale well if
    customer has 200000 devices", "optimize for first hit", "must not traverse 30 days for each across fleet"; "it must be
    dynamic"; "work autom in all tenants".

    WHAT IT DECIDES. A device where a Tier 0, 1 or 2 account logged on in the window takes that tier (the LOWEST such tier,
    MIN with the device's other sources), with the account, why it is privileged, the date and the logon type as evidence.
    The accounts are the Tier 0-2 identities of THIS run's identity profile (SI_Identity_Profile_CL, latest row; the
    identity engine runs first): their tier already carries every identity rule -- roles, and the group-membership rules
    that make HR / finance users Tier 2. Nothing here decides who is privileged.

    MODES (settings, Pro and Community alike; nothing to set up -- the defaults run in every install):
      SI_Endpoint_PrivilegedLogon_Mode       on (default) = a tier source in the MIN | shadow = computed and recorded on the
                                             device (PrivilegedLogonComputedTier + evidence), never changes its tier | off
      SI_Endpoint_MostFrequentUserTier_Mode  the frequent-user source (Exposure Graph): on (default, as before) | shadow | off
                                             (read in Invoke-Enrich; this file only reports it)
    THE SUPPORT FILTER (built, OFF by default -- by default every Tier 0-2 logon counts):
      SI_Endpoint_PrivilegedLogon_SupportFilter  off (default) | dynamic: a Tier 1/2 account with the SUPPORT pattern (many
                                             devices, one session each) never raises; a USER pattern account raises a
                                             device it came back to on 2+ days or whose primary user it is
      SI_Endpoint_PrivilegedLogon_MinDays    empty (default) | n: a Tier 1/2 logon counts only on a device the account used
                                             on n+ distinct days (or its primary user)
      SI_Endpoint_PrivilegedLogon_PrimaryUserCounts  true (default): the device's frequent user always counts (with a filter)
      SI_Endpoint_PrivilegedLogon_ExcludeGroups      empty (default) | group names / ids whose members never count (helpdesk)
      SI_Endpoint_PrivilegedLogon_Tier0Once  true (default): a Tier 0 logon counts on one logon under any filter
                                             (credential exposure)
      SI_Endpoint_PrivilegedLogon_WindowDays 30 (default; what advanced hunting keeps)
      SI_Endpoint_PrivilegedLogon_LogonTypes the counted logon types (default below)
    DYNAMIC SUPPORT PATTERN (per tenant, per run, from its own data -- recorded with the run): an account's FAN-OUT is the
      number of devices it logged on to in the window. The tenant's cut-off is median + 3 x max(1.4826 x MAD, 1) of the fan-
      outs of the Tier 0-2 accounts that logged on (MAD = median absolute deviation): a robust outlier rule (the median and
      MAD are not moved by the few support accounts themselves; 1.4826 x MAD estimates a standard deviation, 3 of them is
      the usual outlier bound; the floor of 1 keeps a tenant whose users all use one device from calling 2 devices support).
      SUPPORT = a fan-out above the cut-off AND one session per device (the median of its distinct days per device is 1).

    THE READ -- by account, never by device; incremental; summarised in the query:
      ACCOUNTS  each Tier 0-2 identity by its keys (on-premises SID, the cloud SID of its object id S-1-12-1-..., object id,
                UPN -- the last two via column_ifexists); the key lists travel IN the query, sized by text (a page, not a
                limit); a list refused even for a 1-3 day range is halved (empirical, no cap).
      QUERY     Defender advanced hunting DeviceLogonEvents (read only, ThreatHunting.Read.All -- already granted),
                successful logons of the counted types, summarised to one row per device and account key: logons counted
                after the last read point, the newest one and its type, the distinct days and the types seen.
                Default counted types (they put the account's credentials ON the device): Interactive (also runas),
                RemoteInteractive (RDP), CachedInteractive, CachedRemoteInteractive, Unlock, CachedUnlock. NOT: Network,
                Service, Batch, NetworkCleartext, NewCredentials (runas /netonly records the caller, not the credentials).
      INCREMENTAL  an account's first read covers the window; every later run reads only since its read point less a
                $script:SIPrivilegedLogonOverlapHours h overlap (late events; only events after the read point are
                counted -- nothing twice); a read stops $script:SIPrivilegedLogonLagHours h before now.
      STATE     one row per privileged account x device { device, account, last logon, types, count, distinct days } and
                each account's read point, in SI's storage account (blob privileged-logons.json in the ledger container,
                created on the first write by the engine's own identity -- Storage Blob Data Contributor, already granted for
                run state; no setup step). Days older than the window leave, a row with no day left leaves (DECAY: the
                device falls back by itself); an account no longer Tier 0-2 leaves; the tier always comes from this run's
                profile, so a tier change applies at once; a new account, a wider window or other logon types re-read the
                whole window. ETag-conditional; the parts of one run share it (the first part writes it with the run id,
                the later parts reuse it -- 0 queries).
      LIMITS    a refused read (throttled / timeout / too many results / quota / 5xx after the hunting request's own retries;
                a cut answer is read whole in hash parts) is split by time (3 halvings), then the account list is halved,
                down to 1 h / 1 account. What stays unread is UNKNOWN: read point not moved, devices "unknown -- ...", a run
                issue, never "no privileged logon"; the devices keep their other sources. No DeviceLogonEvents in the tenant
                (no Defender for Endpoint data): said once, unknown, the run goes on.
      FIRST HIT a device is evaluated account by account in tier order and stops at its first counted Tier 0 logon.
    COST: queries per run = account key lists x read groups (normally 1; 2 when accounts were added) -- never per device;
    rows = privileged accounts x the devices they touched in the read period (a daily run reads about one day).

    PowerShell 7, REST only, no modules. PURE except the default -Query / -PrivilegedIdentities / store.
#>

if (-not (Get-Command -Name Invoke-SIHuntingQueryResult -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'HuntingQuery.ps1') }

$script:SIPrivilegedLogonDefaultTypes = @('Interactive', 'RemoteInteractive', 'CachedInteractive', 'CachedRemoteInteractive', 'Unlock', 'CachedUnlock')
# every logon type Defender records (a setting may only name these)
$script:SIPrivilegedLogonKnownTypes = @('Interactive', 'RemoteInteractive', 'CachedInteractive', 'CachedRemoteInteractive', 'Unlock', 'CachedUnlock',
    'Network', 'NetworkCleartext', 'NewCredentials', 'Batch', 'Service')
$script:SIPrivilegedLogonMaxTier = 2
$script:SIPrivilegedLogonDefaultDays = 30
$script:SIPrivilegedLogonOverlapHours = 24
$script:SIPrivilegedLogonLagHours = 1
$script:SIPrivilegedLogonMinSplitMinutes = 60
# the characters of account keys per query (a page, not a limit: every account is asked, list after list)
$script:SIPrivilegedLogonKeyChars = 60000
# how many privileged accounts the PrivilegedLogons column lists per device (a display length; the tier uses every one)
$script:SIPrivilegedLogonListMax = 10
$script:SIPrivilegedLogonBlobName = 'privileged-logons.json'

function Get-SIPrivilegedLogonSettings {
    <# PURE (reads the globals). Every setting with its default; a value that is not valid falls back to the default. #>
    $g = { param($n) Get-Variable -Name $n -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
    $mode = { param($v, $def) $s = ([string]$v).Trim().ToLowerInvariant(); if ($s -in 'on', 'shadow', 'off') { $s } else { $def } }
    $bool = { param($v, $def) if ($null -eq $v -or "$v" -eq '') { return $def }; $s = ([string]$v).Trim().ToLowerInvariant(); if ($s -in 'true', '1', 'yes', 'on') { return $true }; if ($s -in 'false', '0', 'no', 'off') { return $false }; return $def }
    $int = { param($v) $d = 0; if ($null -ne $v -and [int]::TryParse(([string]$v).Trim(), [ref]$d) -and $d -ge 1) { $d } else { $null } }
    $list = { param($v) @(@($v) | ForEach-Object { ([string]$_) -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    $days = & $int (& $g 'SI_Endpoint_PrivilegedLogon_WindowDays'); if ($null -eq $days) { $days = $script:SIPrivilegedLogonDefaultDays }
    $types = @(& $list (& $g 'SI_Endpoint_PrivilegedLogon_LogonTypes') | ForEach-Object { $t = $_; @($script:SIPrivilegedLogonKnownTypes | Where-Object { $_ -ieq $t }) } | Select-Object -Unique)
    if ($types.Count -eq 0) { $types = $script:SIPrivilegedLogonDefaultTypes }
    $sfv = & $g 'SI_Endpoint_PrivilegedLogon_SupportFilter'; $sf = "$sfv".Trim().ToLowerInvariant(); if ($sf -ne 'dynamic') { $sf = 'off' }
    [pscustomobject]@{
        Mode               = & $mode (& $g 'SI_Endpoint_PrivilegedLogon_Mode') 'on'
        MostFrequentMode   = & $mode (& $g 'SI_Endpoint_MostFrequentUserTier_Mode') 'on'
        WindowDays         = $days
        LogonTypes         = [string[]]$types
        SupportFilter      = $sf
        MinDays            = & $int (& $g 'SI_Endpoint_PrivilegedLogon_MinDays')
        PrimaryUserCounts  = & $bool (& $g 'SI_Endpoint_PrivilegedLogon_PrimaryUserCounts') $true
        ExcludeGroups      = [string[]]@(& $list (& $g 'SI_Endpoint_PrivilegedLogon_ExcludeGroups'))
        Tier0Once          = & $bool (& $g 'SI_Endpoint_PrivilegedLogon_Tier0Once') $true
    }
}

function ConvertFrom-SICloudSid {
    <# PURE. The Entra object id a cloud account SID (S-1-12-1-a-b-c-d) is made from; '' for any other SID. #>
    param([string]$Sid)
    $s = ([string]$Sid).Trim()
    if ($s -notmatch '^(?i)S-1-12-1-(\d+)-(\d+)-(\d+)-(\d+)$') { return '' }
    $bytes = New-Object byte[] 16
    for ($i = 0; $i -lt 4; $i++) {
        $n = [uint64]0
        if (-not [uint64]::TryParse($Matches[$i + 1], [ref]$n) -or $n -gt [uint32]::MaxValue) { return '' }
        $part = [BitConverter]::GetBytes([uint32]$n)
        [Array]::Copy($part, 0, $bytes, $i * 4, 4)
    }
    $g = [guid]::new($bytes)
    return $g.ToString().ToLowerInvariant()
}

function ConvertTo-SICloudSid {
    <# PURE. The cloud account SID (S-1-12-1-a-b-c-d) of an Entra object id; '' when it is not a GUID. #>
    param([string]$ObjectId)
    $g = [guid]::Empty
    if (-not [guid]::TryParse(([string]$ObjectId).Trim(), [ref]$g)) { return '' }
    $b = $g.ToByteArray()
    $p = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt 4; $i++) { $p.Add([string][BitConverter]::ToUInt32($b, $i * 4)) }
    return ('S-1-12-1-' + ($p -join '-'))
}

function Get-SIPrivilegedIdentityReason {
    <#
        PURE. Why the identity has its tier, short: its own winning rule at that tier -- "<purpose> (<rule>/<detection>)",
        e.g. "Finance team member (AssetProfileByGroupMembership/OrgFinanceMember)" for a group-membership rule -- else its
        tier reason without the leading "Tier N set by "; '' when the profile carries neither.
    #>
    param($Tier, $SIRules, [string]$TierReason)
    $rules = $SIRules
    if ($rules -is [string]) { $t = $rules.Trim(); $rules = $null; if ($t.StartsWith('[') -or $t.StartsWith('{')) { try { $rules = $t | ConvertFrom-Json } catch { $rules = $null } } }
    foreach ($m in @($rules)) {
        if ($null -eq $m) { continue }
        $mt = $null; if ($m.PSObject.Properties['Tier']) { $mt = $m.Tier }
        if ($null -eq $mt -or "$mt" -ne "$Tier") { continue }
        $rid = [string]$m.RuleId; $did = ''; if ($m.PSObject.Properties['DetectionId']) { $did = [string]$m.DetectionId }
        $pur = ''; if ($m.PSObject.Properties['Purpose']) { $pur = ([string]$m.Purpose).Trim() }
        $ref = $rid; if ($did) { $ref = '{0}/{1}' -f $rid, $did }
        if ($pur -and $ref) { return ('{0} ({1})' -f $pur, $ref) }
        if ($ref) { return $ref }
    }
    $r = ([string]$TierReason).Trim()
    if (-not $r) { return '' }
    $r = $r -replace '^(?i)Tier \d set by ', ''
    if ($r.Length -gt 160) { $r = $r.Substring(0, 157) + '...' }
    return $r
}

function ConvertTo-SIPrivilegedAccount {
    <# PURE. One identity profile row (ObjectId, Sid = on-prem SID, Upn, Tier, SIRules, TierReason, Groups) as an account to
       ask for: @{ Id; Upn; Tier; Reason; Groups; Sids; Upns; Oids } -- $null when it is not Tier 0-2 or has no key. #>
    param($Row)
    if ($null -eq $Row) { return $null }
    $tv = 0
    if (-not [int]::TryParse(([string]$Row.Tier).Trim(), [ref]$tv) -or $tv -lt 0 -or $tv -gt $script:SIPrivilegedLogonMaxTier) { return $null }
    $oid = ([string]$Row.ObjectId).Trim().ToLowerInvariant()
    $sids = New-Object System.Collections.Generic.List[string]
    $onp = ([string]$Row.Sid).Trim().ToUpperInvariant()
    if ($onp -match '^S-1-[0-9-]+$') { $sids.Add($onp) }
    if ($oid -match '^s-1-[0-9-]+$' -and -not $sids.Contains($oid.ToUpperInvariant())) { $sids.Add($oid.ToUpperInvariant()) }   # an AD-only account: its id IS its SID
    $cloud = ConvertTo-SICloudSid $oid
    if ($cloud) { $sids.Add($cloud) }
    $upn = ([string]$Row.Upn).Trim()
    $upns = @(); if ($upn -match '^[^\s"\\]+@[^\s"\\]+$') { $upns = @($upn.ToLowerInvariant()) }
    $oids = @(); if ($oid -match '^[0-9a-f-]{36}$') { $oids = @($oid) }
    if (-not $oid -or ($sids.Count -eq 0 -and $upns.Count -eq 0 -and $oids.Count -eq 0)) { return $null }
    $rules = $null; if ($Row.PSObject.Properties['SIRules']) { $rules = $Row.SIRules }
    $tr = ''; if ($Row.PSObject.Properties['TierReason']) { $tr = [string]$Row.TierReason }
    $grp = ''; if ($Row.PSObject.Properties['Groups']) { $grp = [string]$Row.Groups }
    return @{ Id = $oid; Upn = $(if ($upn) { $upn } else { $oid }); Tier = $tv; Reason = (Get-SIPrivilegedIdentityReason -Tier $tv -SIRules $rules -TierReason $tr)
              Groups = $grp; Sids = $sids.ToArray(); Upns = $upns; Oids = $oids }
}

function Test-SIPrivilegedAccountExcluded {
    <# PURE. The excluded group (a name or id from -ExcludeGroups) the account is a member of, as the profile lists its
       groups (any text form: a JSON list of names / objects); '' when none. #>
    param($Account, [string[]]$ExcludeGroups)
    if (@($ExcludeGroups).Count -eq 0 -or -not $Account.Groups) { return '' }
    foreach ($x in $ExcludeGroups) {
        if ([regex]::IsMatch([string]$Account.Groups, ('(^|["\\,;\[\s:])' + [regex]::Escape($x) + '($|["\\,;\]\s])'), 'IgnoreCase')) { return $x }
    }
    return ''
}

function Split-SIPrivilegedAccountLists {
    <# PURE. The accounts in lists whose keys fit -MaxChars of query text (an account's keys stay together). #>
    param([AllowEmptyCollection()][object[]]$Accounts, [int]$MaxChars = $script:SIPrivilegedLogonKeyChars)
    $out = New-Object System.Collections.Generic.List[object]
    $cur = New-Object System.Collections.Generic.List[object]; $len = 0
    foreach ($a in @($Accounts | Where-Object { $null -ne $_ })) {
        $n = 0; foreach ($k in @($a.Sids) + @($a.Upns) + @($a.Oids)) { $n += ([string]$k).Length + 3 }
        if ($cur.Count -gt 0 -and ($len + $n) -gt $MaxChars) { $out.Add($cur.ToArray()); $cur = New-Object System.Collections.Generic.List[object]; $len = 0 }
        $cur.Add($a); $len += $n
    }
    if ($cur.Count -gt 0) { $out.Add($cur.ToArray()) }
    return , $out.ToArray()
}

function Get-SIKqlTime { param([datetime]$T) 'datetime({0})' -f $T.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture) }

function Get-SIPrivilegedLogonKql {
    <#
    .SYNOPSIS  PURE. The query for ONE list of privileged accounts and ONE time range (Since < Timestamp <= Until): the
               successful logons of the counted types of THOSE accounts only, summarised to one row per device and account
               key: Counted (the logons after -CountFrom -- an overlap read never counts a logon twice), the newest one and
               its type, the distinct days and the types seen. Keys are checked (SID / UPN / GUID shapes), never free text.
               No device id is ever in the query.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Accounts, [Parameter(Mandatory)][datetime]$Since,
          [Parameter(Mandatory)][datetime]$Until, [datetime]$CountFrom = $Since, [string[]]$LogonTypes = $script:SIPrivilegedLogonDefaultTypes)
    $sids = @($Accounts | ForEach-Object { @($_.Sids) } | Where-Object { $_ -match '^S-1-[0-9-]+$' } | Sort-Object -Unique)
    $upns = @($Accounts | ForEach-Object { @($_.Upns) } | Where-Object { $_ -match '^[^\s"\\]+@[^\s"\\]+$' } | Sort-Object -Unique)
    $oids = @($Accounts | ForEach-Object { @($_.Oids) } | Where-Object { $_ -match '^[0-9a-f-]{36}$' } | Sort-Object -Unique)
    if ($sids.Count + $upns.Count + $oids.Count -eq 0) { return '' }
    $lt = @($LogonTypes | Where-Object { $_ -match '^[A-Za-z]+$' })
    if ($lt.Count -eq 0) { $lt = $script:SIPrivilegedLogonDefaultTypes }
    $lit = { param($xs) (@($xs) | ForEach-Object { '"' + $_ + '"' }) -join ',' }
    return @"
let _sids = dynamic([$(& $lit $sids)]);
let _upns = dynamic([$(& $lit $upns)]);
let _oids = dynamic([$(& $lit $oids)]);
let _countFrom = $(Get-SIKqlTime $CountFrom);
DeviceLogonEvents
| where Timestamp > $(Get-SIKqlTime $Since) and Timestamp <= $(Get-SIKqlTime $Until)
| where ActionType == "LogonSuccess"
| where LogonType in ($(& $lit $lt))
| extend _sid = toupper(tostring(column_ifexists("AccountSid", ""))), _upn = tolower(tostring(column_ifexists("AccountUpn", ""))), _oid = tolower(tostring(column_ifexists("AccountObjectId", "")))
| where _sid in (_sids) or (isnotempty(_upn) and _upn in (_upns)) or (isnotempty(_oid) and _oid in (_oids))
| extend DeviceId = tolower(tostring(DeviceId)), _day = format_datetime(Timestamp, "yyyy-MM-dd")
| summarize Counted = countif(Timestamp > _countFrom), Days = make_set(_day, 400), Types = make_set(LogonType, 16), arg_max(Timestamp, LogonType) by DeviceId, AccountSid = _sid, AccountUpn = _upn, AccountObjectId = _oid
| project DeviceId, AccountSid, AccountUpn, AccountObjectId, LastLogonUtc = Timestamp, LastLogonType = LogonType, Counted, Days, Types
"@
}

function Invoke-SIPrivilegedLogonAsk {
    <# One query as @{ Ok; Rows; Error; Defect } -- the -Query seam (throws like a failed call), else the product's hunting request. #>
    param([Parameter(Mandatory)][string]$Kql, [scriptblock]$Query)
    if (-not $Query) { return (Invoke-SIHuntingQueryResult -Query $Kql) }
    try { return [pscustomobject]@{ Ok = $true; Rows = @(& $Query $Kql); Error = ''; Defect = $false } }
    catch { $m = $_.Exception.Message; return [pscustomobject]@{ Ok = $false; Rows = @(); Error = $m; Defect = (Test-SIHuntingQueryDefect -Message $m) } }
}

function Test-SIPrivilegedLogonTableMissing {
    <# PURE. The tenant has no DeviceLogonEvents (no Defender for Endpoint data): the service says the table does not resolve. #>
    param([string]$Message)
    return ([string]$Message -match "(?i)(Failed to resolve (table|scalar) expression named 'DeviceLogonEvents'|'DeviceLogonEvents'.*(not found|does not exist|could not be resolved)|DeviceLogonEvents.*(not found|does not exist))")
}

function Read-SIPrivilegedLogonRange {
    <#
        One list of accounts over one time range. A read that fails (after the hunting request's own retries) is SPLIT BY
        TIME (halved, 3 times in a row), then the account list is HALVED, down to -MinMinutes / one account (the size that
        answers is found, never assumed). A refused query (a defect: the same answer every time) is not split. Returns
        @{ Ok; Rows; Queries; Splits; Error; TableMissing } -- Ok only when EVERY part was read (the rows of a part-read are
        never used: the accounts' read point stays and the next run reads them again).
    #>
    param([Parameter(Mandatory)][object[]]$Accounts, [Parameter(Mandatory)][datetime]$Since, [Parameter(Mandatory)][datetime]$Until,
          [datetime]$CountFrom = $Since, [string[]]$LogonTypes = $script:SIPrivilegedLogonDefaultTypes, [scriptblock]$Query,
          [int]$MinMinutes = $script:SIPrivilegedLogonMinSplitMinutes)
    $out = [pscustomobject]@{ Ok = $true; Rows = (New-Object System.Collections.Generic.List[object]); Queries = 0; Error = ''; Splits = 0; TableMissing = $false }
    $todo = New-Object System.Collections.Generic.Stack[object]
    $todo.Push(@($Since, $Until, @($Accounts), 0))
    while ($todo.Count -gt 0) {
        $r = $todo.Pop(); $s = [datetime]$r[0]; $u = [datetime]$r[1]; $acc = @($r[2]); $depth = [int]$r[3]
        $kql = Get-SIPrivilegedLogonKql -Accounts $acc -Since $s -Until $u -CountFrom $CountFrom -LogonTypes $LogonTypes
        if (-not $kql) { continue }
        $out.Queries++
        $res = Invoke-SIPrivilegedLogonAsk -Kql $kql -Query $Query
        if ($res.Ok) { foreach ($row in @($res.Rows)) { if ($null -ne $row) { $out.Rows.Add($row) } }; continue }
        if (Test-SIPrivilegedLogonTableMissing -Message ([string]$res.Error)) { $out.Ok = $false; $out.TableMissing = $true; $out.Error = [string]$res.Error; break }
        if (-not $res.Defect) {
            $canTime = (($u - $s).TotalMinutes -gt (2 * $MinMinutes))
            if ($canTime -and ($depth -lt 3 -or $acc.Count -le 1)) {
                $mid = $s.AddTicks([long](($u - $s).Ticks / 2))
                $out.Splits++
                $todo.Push(@($s, $mid, $acc, ($depth + 1))); $todo.Push(@($mid, $u, $acc, ($depth + 1)))
                continue
            }
            if ($acc.Count -gt 1) {
                $h = [int][Math]::Floor($acc.Count / 2)
                $out.Splits++
                $todo.Push(@($s, $u, @($acc[0..($h - 1)]), 0)); $todo.Push(@($s, $u, @($acc[$h..($acc.Count - 1)]), 0))
                continue
            }
        }
        $out.Ok = $false
        $fmt = { param($d) $d.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) }
        $why = if ($res.Defect) { 'the query was refused and must be fixed (running it again gives the same answer)' } else { 'the read failed after it was asked again and split by time and by account' }
        $out.Error = ('{0} -- {1} to {2}: {3}' -f $why, (& $fmt $s), (& $fmt $u), [string]$res.Error)
        break
    }
    return $out
}

function Get-SIPrivilegedLogonTypeText {
    <# PURE. A logon type in the words a person reads. #>
    param([string]$LogonType)
    switch (([string]$LogonType).Trim()) {
        'RemoteInteractive'       { return 'RDP' }
        'CachedRemoteInteractive' { return 'RDP, cached credentials' }
        'Interactive'             { return 'at the device' }
        'CachedInteractive'       { return 'at the device, cached credentials' }
        'Unlock'                  { return 'unlock' }
        'CachedUnlock'            { return 'unlock, cached credentials' }
        default                   { return ([string]$LogonType).Trim() }
    }
}

function ConvertTo-SIUtcDate {
    <# PURE. A time (datetime or ISO text) as UTC; $null when unreadable. #>
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [DateTimeOffset]) { return $Value.UtcDateTime }
    $d = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return $null
}

function Get-SIPrivilegedLogonEvidence {
    <# PURE. "<account> (Tier N: <why>) logged on <yyyy-MM-dd> (<type>)" for one PrivilegedLogons entry (no why: "(Tier N)"). #>
    param($Entry)
    if ($null -eq $Entry) { return '' }
    $when = ConvertTo-SIUtcDate $Entry.LastLogonUtc
    $date = if ($when) { $when.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) } else { 'in the window' }
    $tier = 'Tier {0}' -f $Entry.Tier
    if ($Entry.PSObject.Properties['Reason'] -and $Entry.Reason) { $tier = '{0}: {1}' -f $tier, $Entry.Reason }
    return ('{0} ({1}) logged on {2} ({3})' -f $Entry.Upn, $tier, $date, (Get-SIPrivilegedLogonTypeText $Entry.LogonType))
}

function Get-SIPrivilegedIdentities {
    <#
        The Tier 0-2 identities of this run's identity profile (SI_Identity_Profile_CL, the latest row of each identity in
        the last 7 days -- an identity whose latest row is no longer Tier 0-2 is not in it), with why each has its tier
        (SIRules, SI_TierReason) and its groups (for SI_Endpoint_PrivilegedLogon_ExcludeGroups): @{ Complete; Missing; Rows }.
    #>
    $out = @{ Complete = $false; Missing = $false; Rows = (New-Object System.Collections.Generic.List[object]); Error = '' }
    if (-not (Get-Command -Name Resolve-SIEnrichWorkspaceGuid -ErrorAction SilentlyContinue)) { $out.Error = 'the identity profile look-up is not loaded'; return $out }
    $guid = Resolve-SIEnrichWorkspaceGuid -WorkspaceResourceId $global:SI_WorkspaceResourceId -What 'The Tier 0-2 accounts whose logons count for the devices'
    if (-not $guid) { $out.Error = 'the workspace could not be looked up'; return $out }
    $max = $script:SIPrivilegedLogonMaxTier
    $kql = @"
let _t = SI_Identity_Profile_CL
    | where TimeGenerated > ago(7d);
let _ids = _t | where toint(Tier) <= $max | distinct PrimaryEntityId;
_t
| where PrimaryEntityId in (_ids)
| summarize arg_max(TimeGenerated, *) by PrimaryEntityId
| where toint(Tier) <= $max
| project ObjectId = tolower(PrimaryEntityId), Sid = tostring(column_ifexists("OnPremSid", "")), Upn = tostring(column_ifexists("Upn", "")), Tier = tostring(Tier),
          SIRules = tostring(column_ifexists("SIRules", "")), TierReason = tostring(column_ifexists("SI_TierReason", "")),
          Groups = strcat(tostring(column_ifexists("NestedGroups", "")), " ", tostring(column_ifexists("AdNestedGroupNames", "")))
"@
    try {
        $resp = Invoke-SIAzOperationalInsightsQuery -WorkspaceId $guid -Query $kql -ErrorAction Stop
        foreach ($r in @($resp.Results)) {
            if ($null -ne $r) { $out.Rows.Add([pscustomobject]@{ ObjectId = [string]$r.ObjectId; Sid = [string]$r.Sid; Upn = [string]$r.Upn; Tier = $r.Tier; SIRules = [string]$r.SIRules; TierReason = [string]$r.TierReason; Groups = [string]$r.Groups }) }
        }
        $out.Complete = $true
    } catch {
        $out.Error = $_.Exception.Message
        $missing = $false
        try { Invoke-SIAzOperationalInsightsQuery -WorkspaceId $guid -Query 'SI_Identity_Profile_CL | take 0' -ErrorAction Stop | Out-Null } catch { $missing = $true }
        if ($missing) { $out.Missing = $true; $out.Complete = $true }
    }
    # #1223 ROOT CAUSE (found 2026-11-12, pwsh 7.6.9 / .NET 10.0.14 on the Linux test runner): the array subexpression @( )
    # around a System.Collections.Generic.List[object] throws "Argument types do not match" -- @($list), @($list).Count,
    # @($list)[0] all throw; List[string] / List[int] / List[psobject], $list.Count and piping the list do not. The caller
    # wrapped these rows in @( ), so the privileged-logon read failed at EVERY 3.1.10+ install on its first live run.
    # The rows go out as a plain array.
    $out.Rows = $out.Rows.ToArray()
    return $out
}

function New-SIPrivilegedLogonBlobStore {
    <#
        The state store in SI's own storage account: an object with Read() -> @{ Doc; ETag; Existed } and Write($Json, $ETag)
        (Write throws on a lost race: 412 / ConditionNotMet). $null without a storage context or in Mock mode (the state is
        then this run's only). A blob that is not there yet reads as no state (the first run); a blob that cannot be read
        THROWS (never an empty state written over a good one). The container is created on the first write.
    #>
    param($StorageContext, [string]$Container, [string]$Blob = $script:SIPrivilegedLogonBlobName)
    if ($null -eq $StorageContext -or [string]$StorageContext.Mode -eq 'Mock' -or -not $StorageContext.PSObject.Properties['AzContext']) { return $null }
    if (-not $Container) { $Container = $(if ($global:SI_LedgerContainer) { [string]$global:SI_LedgerContainer } else { 'siledger' }) }
    $st = [pscustomobject]@{ Container = $Container; Blob = $Blob; Context = $StorageContext.AzContext }
    Add-Member -InputObject $st -MemberType ScriptMethod -Name Read -Value {
        $r = @{ Doc = $null; ETag = $null; Existed = $false }
        $b = $null
        try { $b = Get-SIAzStorageBlob -Container $this.Container -Blob $this.Blob -Context $this.Context -ErrorAction Stop }
        catch { if ([string]$_.Exception.Message -match 'does not exist|NotFound|ResourceNotFound|BlobNotFound|ContainerNotFound') { return $r }; throw }
        $r.Existed = $true; $r.ETag = [string]$b.ICloudBlob.Properties.ETag
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('si-privlogon-{0}.json' -f [guid]::NewGuid().ToString('N'))
        try {
            $null = Get-SIAzStorageBlobContent -Container $this.Container -Blob $this.Blob -Context $this.Context -Destination $tmp -Force -ErrorAction Stop
            $json = [IO.File]::ReadAllText($tmp)
            if (-not [string]::IsNullOrWhiteSpace($json)) { $r.Doc = $json | ConvertFrom-Json -ErrorAction Stop }
        } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
        return $r
    }
    Add-Member -InputObject $st -MemberType ScriptMethod -Name Write -Value {
        param([string]$Json, [string]$ETag)
        $existing = Get-SIAzStorageContainer -Name $this.Container -Context $this.Context -ErrorAction SilentlyContinue
        if (-not $existing) { New-SIAzStorageContainer -Name $this.Container -Context $this.Context -Permission Off | Out-Null }
        $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('si-privlogon-out-{0}.json' -f [guid]::NewGuid().ToString('N'))
        try {
            [IO.File]::WriteAllText($tmp, $Json, (New-Object System.Text.UTF8Encoding($false)))
            if ($ETag) { Set-SIAzStorageBlobContentIfMatch -File $tmp -Container $this.Container -Blob $this.Blob -Context $this.Context -IfMatchETag $ETag }
            else { $null = Set-SIAzStorageBlobContent -File $tmp -Container $this.Container -Blob $this.Blob -Context $this.Context -Force -ErrorAction Stop }
        } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
    }
    return $st
}

function ConvertFrom-SIPrivilegedLogonState {
    <# PURE. The stored document as @{ RunId; Complete; WindowDays; Types; Summary; Accounts = @{ id -> readUntil };
       Rows = @{ 'dev|id' -> @{ D; A; T; Y; C; S = days (yyyy-MM-dd); P = types } } }. #>
    param($Doc)
    $s = @{ RunId = ''; Complete = $false; WindowDays = 0; Types = ''; Summary = $null; Accounts = @{}; Rows = @{} }
    if ($null -eq $Doc) { return $s }
    if ($Doc.PSObject.Properties['RunId']) { $s.RunId = [string]$Doc.RunId }
    if ($Doc.PSObject.Properties['Complete']) { $s.Complete = [bool]$Doc.Complete }
    if ($Doc.PSObject.Properties['WindowDays']) { $s.WindowDays = [int]$Doc.WindowDays }
    if ($Doc.PSObject.Properties['Types']) { $s.Types = [string]$Doc.Types }
    if ($Doc.PSObject.Properties['Summary']) { $s.Summary = $Doc.Summary }
    foreach ($a in @($Doc.Accounts)) {
        if ($null -eq $a) { continue }
        $u = ConvertTo-SIUtcDate $a.ReadUntil
        if ($a.Id -and $u) { $s.Accounts[([string]$a.Id).ToLowerInvariant()] = $u }
    }
    foreach ($r in @($Doc.Rows)) {
        if ($null -eq $r -or -not $r.D -or -not $r.A) { continue }
        $t = ConvertTo-SIUtcDate $r.T
        if (-not $t) { continue }
        $days = @(); if ($r.PSObject.Properties['S']) { $days = @($r.S | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
        if ($days.Count -eq 0) { $days = @($t.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)) }
        $types = @(); if ($r.PSObject.Properties['P']) { $types = @($r.P | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
        $k = ('{0}|{1}' -f ([string]$r.D).ToLowerInvariant(), ([string]$r.A).ToLowerInvariant())
        $s.Rows[$k] = @{ D = ([string]$r.D).ToLowerInvariant(); A = ([string]$r.A).ToLowerInvariant(); T = $t; Y = [string]$r.Y; C = [int]$r.C
                         S = (New-Object 'System.Collections.Generic.HashSet[string]' (, [string[]]$days)); P = (New-Object 'System.Collections.Generic.HashSet[string]' (, [string[]]$types)) }
    }
    return $s
}

function ConvertTo-SIPrivilegedLogonStateJson {
    <# PURE. The state as the stored document (compact row names: D device, A account object id, T last logon, Y its type,
       C count, S the distinct days, P the types seen). #>
    param([Parameter(Mandatory)]$State, [datetime]$Now = [datetime]::UtcNow)
    $iso = { param($d) $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture) }
    $doc = [ordered]@{
        SchemaVersion = 2
        WrittenUtc    = (& $iso $Now)
        RunId         = [string]$State.RunId
        Complete      = [bool]$State.Complete
        WindowDays    = [int]$State.WindowDays
        Types         = [string]$State.Types
        Summary       = $State.Summary
        Accounts      = @($State.Accounts.Keys | Sort-Object | ForEach-Object { [ordered]@{ Id = $_; ReadUntil = (& $iso $State.Accounts[$_]) } })
        Rows          = @($State.Rows.Values | ForEach-Object { [ordered]@{ D = $_.D; A = $_.A; T = (& $iso $_.T); Y = $_.Y; C = $_.C; S = @($_.S | Sort-Object); P = @($_.P | Sort-Object) } })
    }
    return (ConvertTo-Json -InputObject $doc -Depth 6 -Compress)
}

function Update-SIPrivilegedLogonState {
    <#
        PURE but for -Query. Brings the state up to date for -Accounts (this run's Tier 0-2 accounts): an account not read
        before (or a wider window / other logon types) is read for the whole window, the others since their read point less
        the overlap; one query per list of accounts per read group, never per device. Days older than the window leave
        (DECAY), rows with no day left leave, accounts no longer Tier 0-2 leave with their rows.
        Returns @{ State; Queries; Rows; Splits; Lists; Unknown = account ids not read; Errors; TableMissing }.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Accounts, [Parameter(Mandatory)]$State, [Parameter(Mandatory)][datetime]$Now,
          [int]$Days = $script:SIPrivilegedLogonDefaultDays, [string[]]$LogonTypes = $script:SIPrivilegedLogonDefaultTypes, [scriptblock]$Query,
          [int]$KeyChars = $script:SIPrivilegedLogonKeyChars)
    $windowStart = $Now.AddDays(-$Days)
    $firstDay = $windowStart.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)
    $until = $Now.AddHours(-$script:SIPrivilegedLogonLagHours)
    $typesKey = (@($LogonTypes | Sort-Object) -join ',')
    $byId = @{}; foreach ($a in $Accounts) { $byId[$a.Id] = $a }
    foreach ($id in @($State.Accounts.Keys)) { if (-not $byId.ContainsKey($id)) { $State.Accounts.Remove($id) } }
    foreach ($k in @($State.Rows.Keys)) {
        $r = $State.Rows[$k]
        if (-not $byId.ContainsKey($r.A)) { $State.Rows.Remove($k); continue }
        foreach ($d in @($r.S)) { if ([string]::CompareOrdinal($d, $firstDay) -lt 0) { [void]$r.S.Remove($d) } }
        if ($r.S.Count -eq 0 -or $r.T -le $windowStart) { $State.Rows.Remove($k) }
    }
    $reReadAll = (($State.WindowDays -gt 0 -and $Days -gt $State.WindowDays) -or ($State.Types -and $State.Types -ne $typesKey))
    if ($State.Types -and $State.Types -ne $typesKey) { $State.Rows.Clear(); $State.Accounts.Clear() }
    $groups = [ordered]@{}
    foreach ($a in $Accounts) {
        $prev = $null
        if (-not $reReadAll -and $State.Accounts.ContainsKey($a.Id)) { $prev = $State.Accounts[$a.Id] }
        if ($null -ne $prev -and $prev -le $windowStart) { $prev = $null }
        $gk = if ($null -eq $prev) { 'new' } else { $prev.ToString('o') }
        if (-not $groups.Contains($gk)) { $groups[$gk] = @{ Prev = $prev; Accounts = (New-Object System.Collections.Generic.List[object]) } }
        $groups[$gk].Accounts.Add($a)
    }
    $res = [pscustomobject]@{ State = $State; Queries = 0; Rows = 0; Splits = 0; Lists = 0; TableMissing = $false
                              Unknown = (New-Object System.Collections.Generic.List[string]); Errors = (New-Object System.Collections.Generic.List[string]) }
    foreach ($gk in @($groups.Keys)) {
        $g = $groups[$gk]
        $since = $windowStart; $countFrom = $windowStart
        if ($null -ne $g.Prev) { $countFrom = $g.Prev; $since = $g.Prev.AddHours(-$script:SIPrivilegedLogonOverlapHours); if ($since -lt $windowStart) { $since = $windowStart } }
        if ($since -ge $until) { continue }
        foreach ($list in (Split-SIPrivilegedAccountLists -Accounts $g.Accounts.ToArray() -MaxChars $KeyChars)) {
            $res.Lists++
            if ($res.TableMissing) { foreach ($a in $list) { $res.Unknown.Add($a.Id) }; continue }
            $a2 = @{ Accounts = @($list); Since = $since; Until = $until; CountFrom = $countFrom; LogonTypes = $LogonTypes }
            if ($Query) { $a2['Query'] = $Query }
            $rr = Read-SIPrivilegedLogonRange @a2
            $res.Queries += $rr.Queries; $res.Splits += $rr.Splits
            if (-not $rr.Ok) {
                foreach ($a in $list) { $res.Unknown.Add($a.Id) }
                $res.Errors.Add($rr.Error)
                if ($rr.TableMissing) { $res.TableMissing = $true }
                continue
            }
            $global:SI_PrivilegedLogonPart = 'combining the sign-ins Defender returned'
            $keyIdx = @{}
            foreach ($a in $list) { foreach ($k in @($a.Sids) + @($a.Upns) + @($a.Oids)) { $keyIdx[([string]$k).ToLowerInvariant()] = $a.Id } }
            foreach ($row in $rr.Rows) {
                $res.Rows++
                $id = $null
                foreach ($k in @([string]$row.AccountObjectId, [string]$row.AccountSid, [string]$row.AccountUpn)) {
                    $kk = $k.Trim().ToLowerInvariant(); if ($kk -and $keyIdx.ContainsKey($kk)) { $id = $keyIdx[$kk]; break }
                }
                $dev = ([string]$row.DeviceId).Trim().ToLowerInvariant()
                $t = ConvertTo-SIUtcDate $row.LastLogonUtc
                if (-not $id -or -not $dev -or -not $t) { continue }
                $n = 0; [void][int]::TryParse(([string]$row.Counted), [ref]$n)
                # (not $days: that is this function's -Days, an [int] -- PowerShell names are not case-sensitive)
                $dayList = @(@($row.Days) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                if ($dayList.Count -eq 1 -and $dayList[0].StartsWith('[')) { try { $dayList = @($dayList[0] | ConvertFrom-Json) } catch { } }
                $types = @(@($row.Types) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                if ($types.Count -eq 1 -and $types[0].StartsWith('[')) { try { $types = @($types[0] | ConvertFrom-Json) } catch { } }
                $k2 = '{0}|{1}' -f $dev, $id
                if (-not $State.Rows.ContainsKey($k2)) {
                    $State.Rows[$k2] = @{ D = $dev; A = $id; T = $t; Y = [string]$row.LastLogonType; C = 0
                                          S = (New-Object 'System.Collections.Generic.HashSet[string]'); P = (New-Object 'System.Collections.Generic.HashSet[string]') }
                }
                $x = $State.Rows[$k2]; $x.C += $n
                if ($t -ge $x.T) { $x.T = $t; $x.Y = [string]$row.LastLogonType }
                foreach ($d in $dayList) { if ([string]::CompareOrdinal([string]$d, $firstDay) -ge 0) { [void]$x.S.Add([string]$d) } }
                if ($x.S.Count -eq 0) { [void]$x.S.Add($t.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture)) }
                foreach ($ty in $types) { [void]$x.P.Add([string]$ty) }
                [void]$x.P.Add([string]$row.LastLogonType)
            }
            foreach ($a in $list) { $State.Accounts[$a.Id] = $until }
        }
    }
    $State.WindowDays = $Days
    $State.Types = $typesKey
    $State.Complete = ($res.Unknown.Count -eq 0)
    return $res
}

function Get-SIMedian {
    <# PURE. The median of numbers (0 for none). #>
    param([AllowEmptyCollection()][double[]]$Values)
    $v = @($Values | Sort-Object)
    if ($v.Count -eq 0) { return 0.0 }
    $m = [int][Math]::Floor($v.Count / 2)
    if ($v.Count % 2 -eq 1) { return [double]$v[$m] }
    return ([double]$v[$m - 1] + [double]$v[$m]) / 2.0
}

function Get-SIPrivilegedLogonPatterns {
    <#
        PURE. The tenant's support / user pattern of THIS run, from the stored logons of the window: per account its FAN-OUT
        (devices) and the median of its distinct days per device; the tenant cut-off = median + 3 x max(1.4826 x MAD, 1) of
        the fan-outs; SUPPORT = fan-out above the cut-off AND one session per device (median days per device <= 1).
        Returns @{ Accounts = @{ id -> @{ FanOut; MedianDays; Support } }; Median; Mad; CutOff; Support; User }.
    #>
    param([Parameter(Mandatory)]$State)
    $per = @{}
    foreach ($r in $State.Rows.Values) {
        if (-not $per.ContainsKey($r.A)) { $per[$r.A] = New-Object System.Collections.Generic.List[double] }
        $per[$r.A].Add([double]$r.S.Count)
    }
    $fan = @($per.Keys | ForEach-Object { [double]$per[$_].Count })
    $med = Get-SIMedian $fan
    $mad = Get-SIMedian @($fan | ForEach-Object { [Math]::Abs($_ - $med) })
    $cut = [Math]::Ceiling($med + 3.0 * [Math]::Max(1.4826 * $mad, 1.0))
    $acc = @{}; $sup = 0
    foreach ($id in $per.Keys) {
        $f = $per[$id].Count; $md = Get-SIMedian $per[$id].ToArray()
        $isSup = ($f -gt $cut -and $md -le 1)
        if ($isSup) { $sup++ }
        $acc[$id] = @{ FanOut = $f; MedianDays = $md; Support = $isSup }
    }
    return @{ Accounts = $acc; Median = $med; Mad = $mad; CutOff = $cut; Support = $sup; User = ($per.Count - $sup) }
}

function Get-SIPrivilegedLogonDecision {
    <#
        PURE. Does ONE account's logons on ONE device count? @{ Counted; Why; OneOff; Support; Excluded }. Default (no filter):
        every Tier 0-2 logon counts. ExcludeGroups always applies; the support filter (dynamic) and MinDays only when set;
        a Tier 0 logon counts on one logon under any filter when Tier0Once.
    #>
    param([Parameter(Mandatory)]$Account, [Parameter(Mandatory)]$Row, [Parameter(Mandatory)]$Settings, $Pattern, [bool]$IsPrimary = $false)
    $days = $Row.S.Count
    $oneOff = ($days -le 1 -and -not $IsPrimary)
    $isSup = ($null -ne $Pattern -and [bool]$Pattern.Support)
    $out = @{ Counted = $true; Why = ''; OneOff = $oneOff; Support = $isSup; Excluded = '' }
    $ex = Test-SIPrivilegedAccountExcluded -Account $Account -ExcludeGroups $Settings.ExcludeGroups
    if ($ex) { $out.Counted = $false; $out.Excluded = $ex; $out.Why = ('not counted: member of the excluded group {0}' -f $ex); return $out }
    $filtered = ($Settings.SupportFilter -eq 'dynamic' -or $null -ne $Settings.MinDays)
    if (-not $filtered) { $out.Why = $(if ($Account.Tier -eq 0) { 'Tier 0 logon' } else { 'privileged logon' }); return $out }
    if ($Account.Tier -eq 0 -and $Settings.Tier0Once) { $out.Why = 'Tier 0 logon (counts on one logon)'; return $out }
    if ($Settings.SupportFilter -eq 'dynamic' -and $isSup) {
        $out.Counted = $false; $out.Why = ('not counted: support pattern ({0} devices, one session each)' -f $Pattern.FanOut); return $out
    }
    $need = 2; if ($null -ne $Settings.MinDays) { $need = [int]$Settings.MinDays }
    if ($IsPrimary -and $Settings.PrimaryUserCounts) { $out.Why = 'the device''s primary user'; return $out }
    if ($days -ge $need) { $out.Why = ('returns: {0} days' -f $days); return $out }
    $out.Counted = $false; $out.Why = $(if ($days -le 1) { 'privileged logon seen once -- not counted' } else { ('not counted: {0} of {1} days' -f $days, $need) })
    return $out
}

function Write-SIPrivilegedLogonNote {
    <#
        #1227 (owner 2026-11-12: "it should be possible to include new rules and it must never break the pipeline"): a gap
        of the privileged-logon source is a SCOPED NOTE, never a run issue. One plain warning line with a stable code; the
        devices' own value says UNKNOWN and why; the run stays whole (Add-SIEnrichIssue -- which makes the Enrich step
        INCOMPLETE and so the whole run partial -- is NOT called). Kept in $global:SI_EnrichScopedNotes, AND its catalogue
        code in $global:SI_RunNoteCodes (@{ Code; Text; Step }) -- the run report to Invardia carries it as a Reports[] item
        (SI-TelemetrySend.ps1, ConvertTo-SIUplinkFailureItem), so the run monitor shows the code and a fix request opens
        where the catalogue says so -- a scoped note is never hidden. One entry per code per process. Never throws.
    #>
    param([Parameter(Mandatory)][string]$Code, [Parameter(Mandatory)][string]$Text)
    try {
        if (-not ($global:SI_EnrichScopedNotes -is [System.Collections.Generic.List[string]])) { $global:SI_EnrichScopedNotes = New-Object System.Collections.Generic.List[string] }
        $line = '{0} [{1}]' -f $Text.Trim(), $Code
        $global:SI_EnrichScopedNotes.Add($line)
        if (-not ($global:SI_RunNoteCodes -is [System.Collections.Generic.List[object]])) { $global:SI_RunNoteCodes = New-Object System.Collections.Generic.List[object] }
        if (-not @($global:SI_RunNoteCodes | Where-Object { $_ -and [string]$_.Code -eq $Code }).Count) {
            $global:SI_RunNoteCodes.Add([pscustomobject]@{ Code = $Code; Text = $Text.Trim(); Step = 'privileged-logons' })
        }
        Write-Warning $line
    } catch { }
}

function Get-SIBulkPrivilegedLogons {
    <#
    .SYNOPSIS  The privileged logons of the given Defender devices (this part of the run). Returns
               @{ ByDevice = @{ <mde id> = @{ PrivilegedLogonComputedTier; PrivilegedLogonTier; PrivilegedLogons;
                  PrivilegedLogonStatus; PrivilegedLogonEvidence } }; Settings; Summary; Accounts; Queries; Rows; Splits;
                  StateRows; Unknown; Read; Saved; Reused }
               ComputedTier = what the source decides; PrivilegedLogonTier = the same when the mode is on, empty in shadow
               (the tier never changes). Every device asked gets an entry: no privileged logon (empty, status read), a
               privileged logon, or UNKNOWN (status says why -- never "no privileged logon"). Never throws.
    .PARAMETER PrimaryUsers          @{ <mde id> = @(upn / object id, lower case) } -- the device's frequent user(s).
    .PARAMETER Query                 test seam: { param($kql) rows } instead of the Graph call (throws like a failed call).
    .PARAMETER PrivilegedIdentities  test seam: { } -> @{ Complete; Missing; Rows = @(@{ ObjectId; Sid; Upn; Tier; SIRules; TierReason; Groups }) }.
    .PARAMETER Store                 the state store (New-SIPrivilegedLogonBlobStore, or a test fake with Read() / Write()); none = this run only.
    .PARAMETER Settings              Get-SIPrivilegedLogonSettings (default: read from the globals).
    #>
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()][string[]]$MdeDeviceIds, [string]$RunId = '', [datetime]$Now = [datetime]::UtcNow,
          [hashtable]$PrimaryUsers = @{}, [scriptblock]$Query, [scriptblock]$PrivilegedIdentities, $Store, $Settings)
    if ($null -eq $Settings) { $Settings = Get-SIPrivilegedLogonSettings }
    # #1227 (owner 2026-11-12: "it must never break the pipeline"): a gap of THIS source is a scoped note -- each device's
    # privileged-logon value is UNKNOWN with why, the run itself stays whole (never INCOMPLETE because of this source)
    $say = { param($code, $t) Write-SIPrivilegedLogonNote -Code $code -Text $t }
    $info = { param($t) if (Get-Command -Name Write-SIInfo -ErrorAction SilentlyContinue) { Write-SIInfo $t } else { Write-Verbose $t } }
    $out = [pscustomobject]@{ ByDevice = @{}; Settings = $Settings; Summary = $null; Accounts = 0; Queries = 0; Rows = 0; Splits = 0; StateRows = 0
                              Unknown = 0; Read = 0; Saved = $false; Reused = $false }
    $ids = @($MdeDeviceIds | Where-Object { $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
    if ($ids.Count -eq 0 -or $Settings.Mode -eq 'off') { return $out }
    $Days = [int]$Settings.WindowDays
    $setUnknown = { param($why)
        foreach ($d in $ids) { $out.ByDevice[$d] = @{ PrivilegedLogonComputedTier = $null; PrivilegedLogonTier = $null; PrivilegedLogons = @(); PrivilegedLogonStatus = ('unknown -- ' + $why); PrivilegedLogonEvidence = '' } }
        $out.Unknown = $ids.Count
    }

    # 1. this run's Tier 0-2 accounts
    $global:SI_PrivilegedLogonPart = 'reading the Tier 0-2 accounts'
    $pi = $null
    try { if ($PrivilegedIdentities) { $pi = & $PrivilegedIdentities } else { $pi = Get-SIPrivilegedIdentities } } catch { $pi = @{ Complete = $false; Missing = $false; Rows = @(); Error = $_.Exception.Message } }
    if ($null -eq $pi -or -not $pi.Complete -or $pi.Missing) {
        $why = if ($pi -and $pi.Missing) { 'the identity profile is not there yet (the identity engine runs first)' } else { 'the identity tiers could not be read this run' }
        $detail = ''; if ($pi -and $pi.Error) { $detail = ' (' + [string]$pi.Error + ')' }
        & $say 'si-col-0504' ('The privileged logons of the devices could not be counted: {0}{1}. The privileged-logon tier is UNKNOWN this run, not "no privileged logon"; the devices keep their other tier sources.' -f $why, $detail)
        & $setUnknown $why
        return $out
    }
    $global:SI_PrivilegedLogonPart = 'reading the accounts'' sign-in keys'
    # #1223: the rows are PIPED, never wrapped in @( ) -- @( ) around a List[object] throws on pwsh 7.6 (see Get-SIPrivilegedIdentities)
    $accounts = @($pi.Rows | ForEach-Object { ConvertTo-SIPrivilegedAccount $_ } | Where-Object { $null -ne $_ })
    $acctById = @{}; foreach ($a in $accounts) { $acctById[$a.Id] = $a }
    $out.Accounts = $acctById.Count

    # 2. the stored state (another part of THIS run may already have read it)
    $global:SI_PrivilegedLogonPart = 'reading the stored sign-ins'
    $read = $null; $stateOk = $true
    if ($Store) {
        try { $read = $Store.Read() } catch { $stateOk = $false; & $info ('[perms] privileged logons: the stored logons could not be read ({0}) -- the whole window is read this run and the store is left as it is' -f $_.Exception.Message) }
    }
    $doc = $null; if ($read) { $doc = $read.Doc }
    $state = ConvertFrom-SIPrivilegedLogonState $doc
    $etag = ''; if ($read) { $etag = [string]$read.ETag }
    $typesKey = (@($Settings.LogonTypes | Sort-Object) -join ',')
    $upd = $null
    if ($RunId -and $state.RunId -eq $RunId -and $state.Complete -and $state.WindowDays -eq $Days -and $state.Types -eq $typesKey) {
        $out.Reused = $true
        foreach ($k in @($state.Rows.Keys)) { if (-not $acctById.ContainsKey($state.Rows[$k].A)) { $state.Rows.Remove($k) } }
    } else {
        $ua = @{ Accounts = $accounts; State = $state; Now = $Now; Days = $Days; LogonTypes = $Settings.LogonTypes }
        if ($Query) { $ua['Query'] = $Query }
        $global:SI_PrivilegedLogonPart = 'reading the sign-ins from Defender'
        $upd = Update-SIPrivilegedLogonState @ua
        $out.Queries = $upd.Queries; $out.Rows = $upd.Rows; $out.Splits = $upd.Splits
        $state.RunId = $RunId
        if ($upd.TableMissing) {
            & $say 'si-col-0503' 'The privileged logons of the devices were not read: this tenant has no Defender device logons (DeviceLogonEvents -- no Defender for Endpoint data). The privileged-logon tier is UNKNOWN, not "no privileged logon"; the devices keep their other tier sources.'
        } elseif ($upd.Unknown.Count -gt 0) {
            & $say 'si-col-0505' ('The logons of {0} of {1} Tier 0-2 account(s) were not read ({2}). Their privileged logons are UNKNOWN this run, not "no privileged logon"; they are read again on the next run and the devices keep their other tier sources.' -f $upd.Unknown.Count, $accounts.Count, ($upd.Errors | Select-Object -First 1))
        }
    }

    # 3. the tenant's pattern of this run (recorded; it decides only when the support filter is on)
    $global:SI_PrivilegedLogonPart = 'working out the tenant''s sign-in pattern'
    $pat = Get-SIPrivilegedLogonPatterns -State $state
    $sum = [ordered]@{
        RunId = $RunId; Mode = $Settings.Mode; MostFrequentMode = $Settings.MostFrequentMode; SupportFilter = $Settings.SupportFilter
        MinDays = $Settings.MinDays; ExcludeGroups = (@($Settings.ExcludeGroups) -join ';'); Tier0Once = [bool]$Settings.Tier0Once; WindowDays = $Days
        PrivilegedAccounts = $accounts.Count; AccountsWithLogons = ($pat.Support + $pat.User); SupportAccounts = $pat.Support; UserAccounts = $pat.User
        FanOutMedian = $pat.Median; FanOutMad = $pat.Mad; SupportCutOff = $pat.CutOff
        Queries = $out.Queries; RowsReturned = $out.Rows; StateRows = $state.Rows.Count
    }
    $out.Summary = $sum
    $global:SI_PrivilegedLogonPart = 'saving the sign-ins'
    if ($Store -and $stateOk -and $null -ne $upd) {
        $state.Summary = [pscustomobject]$sum
        try { $Store.Write((ConvertTo-SIPrivilegedLogonStateJson -State $state -Now $Now), $etag); $out.Saved = $true }
        catch {
            $m = [string]$_.Exception.Message
            if ($m -match 'ConditionNotMet|412|conditional header') {
                try {
                    $again = $Store.Read(); $other = ConvertFrom-SIPrivilegedLogonState $again.Doc
                    if ($RunId -and $other.RunId -eq $RunId -and $other.Complete) { $state = $other; $out.Reused = $true; $pat = Get-SIPrivilegedLogonPatterns -State $state }
                    else { & $info '[perms] privileged logons: another run wrote the stored logons meanwhile -- this run''s read is used, not stored; the next run reads from the stored point' }
                } catch { }
            } else { & $info ('[perms] privileged logons: the stored logons were not written ({0}) -- the next run reads from the previous point again' -f $m) }
        }
    }
    $out.StateRows = $state.Rows.Count

    # 4. per device, account by account in tier order -- FIRST HIT: a counted Tier 0 logon ends the device
    $global:SI_PrivilegedLogonPart = 'working out each device''s tier'
    $partial = ($null -ne $upd -and $upd.Unknown.Count -gt 0)
    $missing = ($null -ne $upd -and $upd.TableMissing)
    $perDev = @{}
    $windowStart = $Now.AddDays(-$Days)
    foreach ($r in $state.Rows.Values) {
        if ($r.T -le $windowStart -or -not $acctById.ContainsKey($r.A)) { continue }
        if (-not $perDev.ContainsKey($r.D)) { $perDev[$r.D] = New-Object System.Collections.Generic.List[object] }
        $perDev[$r.D].Add($r)
    }
    $cnt = @{ RaisedDevices = 0; RaisedByTier0 = 0; RaisedByOneOff = 0; RaisedBySupportAccount = 0; NotCountedOneOff = 0; NotCountedSupport = 0; NotCountedExcluded = 0 }
    foreach ($dev in $ids) {
        $entries = New-Object System.Collections.Generic.List[object]
        $tier = $null; $top = $null; $ev = ''; $firstNot = ''
        if ($perDev.ContainsKey($dev)) {
            $prim = @(); if ($PrimaryUsers.ContainsKey($dev)) { $prim = @($PrimaryUsers[$dev] | ForEach-Object { ([string]$_).ToLowerInvariant() }) }
            $rows = @($perDev[$dev].ToArray() | Sort-Object -Property @{ Expression = { $acctById[$_.A].Tier } }, @{ Expression = { $_.T }; Descending = $true })
            foreach ($r in $rows) {
                $a = $acctById[$r.A]
                $isPrim = (($prim -contains $a.Id) -or ($prim -contains ([string]$a.Upn).ToLowerInvariant()))
                $dec = Get-SIPrivilegedLogonDecision -Account $a -Row $r -Settings $Settings -Pattern $pat.Accounts[$r.A] -IsPrimary $isPrim
                if ($dec.Counted) {
                    if ($null -eq $tier) { $tier = $a.Tier; $top = $r; if ($dec.OneOff) { $cnt.RaisedByOneOff++ }; if ($dec.Support) { $cnt.RaisedBySupportAccount++ }; if ($a.Tier -eq 0) { $cnt.RaisedByTier0++ } }
                } else {
                    if ($dec.Excluded) { $cnt.NotCountedExcluded++ } elseif ($dec.Support -and $Settings.SupportFilter -eq 'dynamic') { $cnt.NotCountedSupport++ } else { $cnt.NotCountedOneOff++ }
                }
                $entry = [pscustomobject][ordered]@{
                    Upn = $a.Upn; Tier = $a.Tier; Reason = $a.Reason
                    LastLogonUtc = $r.T.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture)
                    LogonType = $r.Y; Count = $r.C; Days = $r.S.Count; Counted = [bool]$dec.Counted; Why = $dec.Why
                }
                if ($dec.Counted -and $null -ne $top -and [object]::ReferenceEquals($top, $r)) { $ev = Get-SIPrivilegedLogonEvidence $entry }
                elseif (-not $ev -and $null -eq $top -and -not $firstNot) { $firstNot = ('{0} -- {1}' -f (Get-SIPrivilegedLogonEvidence $entry), $dec.Why) }
                if ($entries.Count -lt $script:SIPrivilegedLogonListMax) { $entries.Add($entry) }
                # FIRST HIT: nothing is lower than a counted Tier 0
                if ($dec.Counted -and $a.Tier -eq 0) { break }
            }
        }
        if ($null -ne $tier) { $cnt.RaisedDevices++ }
        if ($null -eq $top -and $firstNot) { $ev = $firstNot }
        $status = 'read'
        if ($missing) { $status = 'unknown -- this tenant has no Defender device logons' }
        elseif ($partial -and -not ($null -ne $tier -and $tier -eq 0)) { $status = 'unknown -- the logons of some Tier 0-2 accounts could not be read this run' }
        if ($status -ne 'read') { $out.Unknown++ } else { $out.Read++ }
        $applied = $null; if ($Settings.Mode -eq 'on') { $applied = $tier }
        $out.ByDevice[$dev] = @{ PrivilegedLogonComputedTier = $tier; PrivilegedLogonTier = $applied; PrivilegedLogons = $entries.ToArray(); PrivilegedLogonStatus = $status; PrivilegedLogonEvidence = $ev }
    }
    foreach ($k in $cnt.Keys) { $sum[$k] = $cnt[$k] }
    $sum['Devices'] = $ids.Count; $sum['Unknown'] = $out.Unknown
    $out.Summary = $sum
    return $out
}
