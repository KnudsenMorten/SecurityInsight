#Requires -Version 5.1
<#
    A CUSTOMER'S CHOICE: WHICH EXPOSURE GRAPH IDENTITIES BECOME ASSETS (REQUIREMENTS #1056, owner approved 2026-11-01).

    Three per-install switches. Each one's default is its Default in $script:SIIdentityScopeSettings below, the same value as
    its default in config\settings.catalog.locked.json and launcher\_lib\SecurityInsight.shared-defaults.ps1 (the two
    older ones ON -- an install turns one off to keep these objects as assets; SI_Identity_SkipNeverSyncedAd OFF, owner
    2026-11-08 -- an install with very many never-synced AD accounts turns it on):
      SI_Identity_SkipNeverSyncedAd          (owner 2026-11-08)  an on-premises AD account the Exposure Graph lists but that
                                             was never synced to Entra ID (the node has no Entra object id) becomes an asset
                                             only while it is PRIVILEGED -- whatever its enabled state (the graph often lists
                                             such an account with its name only, and no enabled state). A non-privileged one
                                             gets no record and no CI; it is counted. A user node that is NOT an on-premises
                                             AD account (Test-SIEgIsAdAccount: no domain SID, no account name + domain) is
                                             never left out by it. It is the wider form of the next switch: while it is on, it
                                             decides the never-synced AD accounts and the next one decides nothing.
      SI_Identity_SkipNeverSyncedDisabledAd  (customer choice "1C")  an on-premises AD account the Exposure Graph lists but
                                             that was never synced to Entra ID (the node has no Entra object id) becomes an
                                             asset only while it is ENABLED or PRIVILEGED. A disabled, non-privileged one gets
                                             no record and no CI; it is counted. Applies only while SI_Identity_SkipNeverSyncedAd
                                             is off (Get-SIIdentityNeverSyncedSetting).
      SI_Identity_SkipDeletedGroups          (customer choice "2B")  a group node WITH an Entra object id becomes an asset
                                             only while Entra ID still has the group (active, or in its deleted items). A
                                             group Entra no longer returns at all gets no record and no CI; it is counted.
    Real users, groups, devices and findings are not affected: an account synced to Entra (it has an Entra object id), an
    AD-only group, a device, a service principal and every finding are never touched by any switch.

    THE STAGES
      collection   the Exposure Graph identity read (IdentityRoleFetcher.ps1) asks Get-SIEgIdentityScopeDecision for every
                   Exposure Graph user / group node it would record; a node left out is not recorded (no record part, no
                   full-metadata copy). The index that enriches the Entra objects is unchanged.
                   The never-synced switch that applies (SI_Identity_SkipNeverSyncedAd, or SI_Identity_SkipNeverSyncedDisabledAd
                   while the first is off) is ALSO applied in the hunting query itself
                   (Get-SIEgNeverSyncedSkipKql): the user nodes the decision could only leave out are not fetched and do
                   not count toward the buckets; the count probe counts them (NotFetched) and they join the left-out count.
                   Every test in the query leans the safe way, so the decision after the read still sees -- and keeps --
                   every node it would keep. A group Entra ID no longer has is decided after the read (it needs Entra's list).
      run report   one plain line per switch in the identity step's log (Format-SIIdentityScopeLine) and one row per switch
                   and run in sidata.CollectionLeftOut (Write-SIIdentityScopeCounts) -- the Data health page shows them.
      asset drop   the collection's asset-drop check adds the records a switch left out this run back to the count it
                   judges (Get-SIIdentityScopeLeftOutByFeed), so a customer's choice is never read as a broken source.
      CI build     a CI whose Exposure Graph record a switch now leaves out RETIRES with a reason naming the switch -- the
                   record's link is 'gone' (Get-SIRecordLeftOutByIdentityChoice, SI-CiBuild.ps1 Get-SIRecordLink), never
                   a silent vanish and never a 30-day "not seen" wait. Switched off again, the next collection records the
                   node again and the CI is reactivated.

    THE SIGNALS (all already in SecurityInsight)
      never synced  the node has no Entra object id (the identity read found none in EntityIds or rawData) --
                    only AD ids (SecurityIdentifier / ActiveDirectoryObjectGuid)
      AD account    a domain SID (S-1-5-21-...) in EntityIds or rawData, or an account name AND an account domain in rawData
                    (Test-SIEgIsAdAccount; the query's _siIsAd)
      disabled      rawData accountEnabled / isEnabled / enabled = false, or userAccountControl carries ACCOUNTDISABLE (the
                    flag name, or bit 0x2 of the number). Unknown = NOT disabled: nothing is left out on a guess
                    (the rule of SI-DisabledAssets.ps1)
      privileged    any of: adminCount > 0 (AD's protected-account marker), a nested critical AD group
                    (nestedCriticalAdGroups), membership of a tier 0 / tier 1 AD group of the privilege tier catalog
                    (nestedAdGroupNames), an assigned role (assignedRoles), a service account (hasServicePrincipalName /
                    isServiceAccount -- SI's service-account signal), a sensitive account (isSensitive), or a Microsoft
                    criticality level (criticalityLevel)
      group exists  its Entra object id is in Entra ID's groups or deleted groups (Read-SIEntraGroupIds: one paged read of
                    /groups and /directory/deletedItems/microsoft.graph.group, ids only). A read that is not complete
                    decides nothing: no group with an Entra id is recorded that run and the Exposure Graph pull is marked
                    not complete, so nothing is retired and nothing comes back (absence proves nothing).

    PURE functions except Read-SIEntraGroupIds (Graph, behind -Fetch), Write-SIIdentityScopeCounts and
    Get-SIIdentityScopeLeftOutByFeed (SQL, behind -Invoke). PowerShell 5.1 and 7: no ?. / ??, no ternary.
    Tests: tests\pester\SIv3-IdentityScopeChoice.Tests.ps1.
#>

# Default = the shipped default (config\settings.catalog.locked.json, launcher\_lib\SecurityInsight.shared-defaults.ps1):
# used when the global is unset -- a container that never stored the setting runs as the catalog says (the two older
# switches ON, SI_Identity_SkipNeverSyncedAd OFF). A stored value (true or false) is kept. (The container also applies every catalog default at start; this keeps the rule where the code reads it,
# the pattern of SI-DisabledAssets.ps1.)
$script:SIIdentityScopeSettings = [ordered]@{
    SkipNeverSyncedAd         = @{ Setting = 'SI_Identity_SkipNeverSyncedAd';         Default = $false }
    SkipNeverSyncedDisabledAd = @{ Setting = 'SI_Identity_SkipNeverSyncedDisabledAd'; Default = $true }
    SkipDeletedGroups         = @{ Setting = 'SI_Identity_SkipDeletedGroups';         Default = $true }
}

function ConvertTo-SIIdentityScopeFlag {
    <# PURE. $true / $false / $null from a bool, 'true' / 'false', 1 / 0. Anything else is unknown ($null). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [int] -or $Value -is [long]) { if ($Value -eq 1) { return $true }; if ($Value -eq 0) { return $false }; return $null }
    $s = ([string]$Value).Trim()
    if ($s -ieq 'true' -or $s -eq '1' -or $s -ieq 'on' -or $s -ieq 'yes') { return $true }
    if ($s -ieq 'false' -or $s -eq '0' -or $s -ieq 'off' -or $s -ieq 'no') { return $false }
    return $null
}

function Get-SIIdentityScopeChoice {
    <#
        PURE (reads the three globals unless -Values is passed). The install's choice:
        @{ SkipNeverSyncedAd; SkipNeverSyncedDisabledAd; SkipDeletedGroups; Any }. Not set (or not readable as yes / no) =
        each switch's shipped default (the two older ON, SI_Identity_SkipNeverSyncedAd OFF); a clear no (false, 0, off) =
        OFF, a clear yes = ON. Which never-synced switch decides:
        Get-SIIdentityNeverSyncedSetting.
    #>
    param([hashtable]$Values)
    $out = [ordered]@{}
    foreach ($k in $script:SIIdentityScopeSettings.Keys) {
        $name = $script:SIIdentityScopeSettings[$k].Setting
        $raw = $null
        if ($Values) { if ($Values.ContainsKey($name)) { $raw = $Values[$name] } elseif ($Values.ContainsKey($k)) { $raw = $Values[$k] } }
        else { $raw = Get-Variable -Name $name -Scope Global -ValueOnly -ErrorAction SilentlyContinue }
        $flag = ConvertTo-SIIdentityScopeFlag $raw
        $out[$k] = if ($null -eq $flag) { [bool]$script:SIIdentityScopeSettings[$k].Default } else { [bool]$flag }
    }
    $out['Any'] = [bool]($out.SkipNeverSyncedAd -or $out.SkipNeverSyncedDisabledAd -or $out.SkipDeletedGroups)
    [pscustomobject]$out
}

function Get-SIIdentityNeverSyncedSetting {
    <#
        PURE. The ONE switch that decides the never-synced on-premises AD accounts under -Choice (Get-SIIdentityScopeChoice):
        'SI_Identity_SkipNeverSyncedAd' while it is on (it is the wider form), else 'SI_Identity_SkipNeverSyncedDisabledAd'
        while that is on, else '' (none: every never-synced AD account is kept, as before either switch existed).
        A choice made before the wider switch existed (no SkipNeverSyncedAd property) reads it as off.
    #>
    param($Choice)
    if ($null -eq $Choice) { return '' }
    $p = $Choice.PSObject.Properties['SkipNeverSyncedAd']
    if ($p -and [bool]$p.Value) { return $script:SIIdentityScopeSettings.SkipNeverSyncedAd.Setting }
    $p = $Choice.PSObject.Properties['SkipNeverSyncedDisabledAd']
    if ($p -and [bool]$p.Value) { return $script:SIIdentityScopeSettings.SkipNeverSyncedDisabledAd.Setting }
    return ''
}

function Get-SIIdentityScopeValue {
    <# PURE. A named value of a dictionary or an object (case-insensitive), $null when it has none. #>
    param([AllowNull()]$Bag, [string]$Name)
    if ($null -eq $Bag) { return $null }
    if ($Bag -is [System.Collections.IDictionary]) {
        foreach ($k in $Bag.Keys) { if ([string]$k -ieq $Name) { return $Bag[$k] } }
        return $null
    }
    $p = $Bag.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-SIIdentityScopeList {
    <# PURE. A value as a list of non-empty items: an array, a comma / semicolon list in one text, a JSON array in text. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) {
        $t = $Value.Trim()
        if (-not $t) { return @() }
        if ($t.StartsWith('[')) { try { return @(@($t | ConvertFrom-Json) | Where-Object { $null -ne $_ -and "$_".Trim() }) } catch { } }
        return @($t -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [System.Collections.IDictionary])) {
        return @(@($Value) | Where-Object { $null -ne $_ -and "$_".Trim() })
    }
    return @($Value)
}

function Test-SIEgAdAccountDisabled {
    <#
        PURE. Does an Exposure Graph node's rawData SAY the account is disabled? $true, $false, or $null (it says nothing).
        accountEnabled / isEnabled / enabled = false -> disabled; userAccountControl with ACCOUNTDISABLE (the flag name, or
        bit 0x2 of the number) -> disabled. A DISABLED answer from any field wins; unknown is never disabled.
    #>
    param([AllowNull()]$RawData)
    if ($null -eq $RawData) { return $null }
    $sawEnabled = $false
    foreach ($k in 'accountEnabled', 'isEnabled', 'enabled') {
        $f = ConvertTo-SIIdentityScopeFlag (Get-SIIdentityScopeValue $RawData $k)
        if ($f -eq $false) { return $true }
        if ($f -eq $true) { $sawEnabled = $true }
    }
    $uac = Get-SIIdentityScopeValue $RawData 'userAccountControl'
    if ($null -ne $uac) {
        foreach ($v in (Get-SIIdentityScopeList $uac)) {
            $s = ([string]$v).Trim()
            if (-not $s) { continue }
            $n = 0L
            if ([long]::TryParse($s, [ref]$n)) { if ($n -band 2) { return $true }; $sawEnabled = $true; continue }
            if ($s -match '^(?i)(AccountDisabled|ACCOUNTDISABLE|Account_Disabled|Disabled)$') { return $true }
            $sawEnabled = $true   # a flag list without the disable flag says the account is enabled
        }
    }
    if ($sawEnabled) { return $false }
    return $null
}

function Test-SIEgIsAdAccount {
    <#
        PURE. Is an Exposure Graph node an on-premises AD account? The same test as the query's _siIsAd
        (Get-SIEgNeverSyncedSkipKql): a domain SID (S-1-5-21-...) -- -Sid (the SID the identity read resolved from EntityIds
        or rawData) or one of rawData's SID fields -- or an account name AND an account domain in rawData (both non-empty
        text). Field names without case. Anything else (another identity provider, a node with no AD sign) = $false: a
        switch about AD accounts never leaves it out.
    #>
    param([AllowNull()]$RawData, [AllowNull()][AllowEmptyString()][string]$Sid)
    if ($Sid -and $Sid.Trim() -match '^(?i)s-1-5-21-') { return $true }
    if ($null -eq $RawData) { return $false }
    foreach ($k in 'adSid', 'accountSid', 'onPremSid', 'onPremisesSecurityIdentifier', 'securityIdentifier', 'sid') {
        $v = Get-SIIdentityScopeValue $RawData $k
        if ($v -is [string] -and $v.Trim() -match '^(?i)s-1-5-21-') { return $true }
    }
    $n = Get-SIIdentityScopeValue $RawData 'accountName'
    $d = Get-SIIdentityScopeValue $RawData 'accountDomain'
    if ($n -is [string] -and $n.Length -gt 0 -and $d -is [string] -and $d.Length -gt 0) { return $true }
    return $false
}

function Get-SIIdentityCriticalAdGroupNames {
    <#
        The privilege tier catalog's tier 0 and tier 1 AD groups (Domain Admins, Enterprise Admins, Schema Admins, Account
        Operators, Backup Operators ...) as a case-insensitive set: the shipped catalog plus the tenant's own catalog
        (privilege-tier-catalog.custom.json) when it is there. -SIRoot: the solution folder. Never throws: a catalog that
        cannot be read adds nothing (the other privilege signals still hold).
    #>
    param([string]$SIRoot)
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if (-not $SIRoot) { $SIRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) }
    $dir = [IO.Path]::Combine($SIRoot, 'privilege-tier-catalog')
    foreach ($file in @('privilege-tier-catalog.locked.json', 'privilege-tier-catalog.custom.json')) {
        $p = [IO.Path]::Combine($dir, $file)
        if (-not [IO.File]::Exists($p)) { continue }
        try {
            $doc = [IO.File]::ReadAllText($p) | ConvertFrom-Json
            foreach ($sec in 'AD_BuiltInPermissionGroups_Tier0', 'AD_BuiltInPermissionGroups_Tier1', 'AD_CustomGroups_Tier0', 'AD_CustomGroups_Tier1') {
                foreach ($e in @(Get-SIIdentityScopeValue $doc $sec)) {
                    if ($null -eq $e) { continue }
                    $n = [string](Get-SIIdentityScopeValue $e 'Name')
                    if ($n -and $n.Trim()) { [void]$set.Add($n.Trim()) }
                }
            }
        } catch { Write-Warning ('identity scope choice: the privilege tier catalog {0} could not be read -- {1}' -f $file, $_.Exception.Message) }
    }
    , $set
}

function Get-SIEgAdPrivilege {
    <#
        PURE. Is the account behind an Exposure Graph node privileged? @{ IsPrivileged; Why (the signals that said so) }.
        -CriticalGroups: Get-SIIdentityCriticalAdGroupNames (names compared without case).
    #>
    param([AllowNull()]$RawData, [AllowNull()]$CriticalGroups)
    $why = New-Object System.Collections.Generic.List[string]
    if ($null -ne $RawData) {
        $ac = 0; if ([int]::TryParse([string](Get-SIIdentityScopeValue $RawData 'adminCount'), [ref]$ac) -and $ac -gt 0) { $why.Add('admin count') }
        # nestedCriticalAdGroups: the graph writes a dictionary { type, data: [ ... ] } (eg.locked.json #690 (29)); a plain list is read too
        $crit = Get-SIIdentityScopeValue $RawData 'nestedCriticalAdGroups'
        $critItems = @()
        if ($null -ne $crit) {
            $data = $null
            if ($crit -is [System.Collections.IDictionary] -or $crit -is [System.Management.Automation.PSCustomObject]) { $data = Get-SIIdentityScopeValue $crit 'data' }
            if ($null -ne $data) { $critItems = @(Get-SIIdentityScopeList $data) }
            elseif (-not ($crit -is [System.Management.Automation.PSCustomObject]) -and -not ($crit -is [System.Collections.IDictionary])) { $critItems = @(Get-SIIdentityScopeList $crit) }
        }
        if ($critItems.Count -gt 0) { $why.Add('critical AD group') }
        if ($null -ne $CriticalGroups -and $CriticalGroups.Count -gt 0) {
            foreach ($g in (Get-SIIdentityScopeList (Get-SIIdentityScopeValue $RawData 'nestedAdGroupNames'))) {
                $gn = ([string]$g).Trim()
                if ($gn -and $CriticalGroups.Contains($gn)) { $why.Add('tier 0/1 AD group ' + $gn); break }
            }
        }
        if (@(Get-SIIdentityScopeList (Get-SIIdentityScopeValue $RawData 'assignedRoles')).Count -gt 0) { $why.Add('assigned role') }
        foreach ($k in 'hasServicePrincipalName', 'isServiceAccount') {
            if ((ConvertTo-SIIdentityScopeFlag (Get-SIIdentityScopeValue $RawData $k)) -eq $true) { $why.Add('service account'); break }
        }
        if ((ConvertTo-SIIdentityScopeFlag (Get-SIIdentityScopeValue $RawData 'isSensitive')) -eq $true) { $why.Add('sensitive account') }
        $cl = Get-SIIdentityScopeValue $RawData 'criticalityLevel'
        if ($null -ne $cl) {
            $lvl = $cl
            if ($cl -is [System.Collections.IDictionary] -or $cl -is [System.Management.Automation.PSCustomObject]) { $lvl = Get-SIIdentityScopeValue $cl 'criticalityLevel' }
            if ($null -ne $lvl -and "$lvl".Trim() -ne '') { $why.Add('Microsoft criticality level') }
        }
    }
    [pscustomobject]@{ IsPrivileged = ($why.Count -gt 0); Why = $why.ToArray() }
}

function Get-SIEgNeverSyncedSkipKql {
    <#
        PURE. SI_Identity_SkipNeverSyncedDisabledAd IN THE HUNTING QUERY ITSELF: the KQL steps (to put after
        "ExposureGraphNodes | where NodeLabel == 'user'") that set the column _siSkip -- true for a user node the Exposure
        Graph read would only fetch to leave out (an on-premises AD account never synced to Entra ID, disabled and not
        privileged). The read asks only for the nodes where _siSkip is false and counts the others; the decision after the
        read (Get-SIEgIdentityScopeDecision) still runs on every node that is fetched.
        NEVER LEAVES OUT A NODE SI KEEPS: every test leans the safe way --
          rawData        only a node whose NodeProperties.rawData is an object (the object the decision reads) is ever skipped
          never synced   ANY mention of AadObjectId in EntityIds, or a GUID in any of the rawData fields the read takes an
                         Entra object id from, counts as synced (the read itself needs more to find one)
          disabled       only what the decision reads as disabled for certain: accountEnabled / isEnabled / enabled false
                         (false, 0, off, no), userAccountControl as a number with bit 0x2, or with the ACCOUNTDISABLE flag
                         name as a list item; anything else is not disabled
          privileged     ANY sign of a privilege signal: an admin count with a digit 1-9, nestedCriticalAdGroups that is not
                         plainly empty, a tier 0/1 group name of the privilege tier catalog anywhere in nestedAdGroupNames,
                         assignedRoles that is not plainly empty, a service-account or sensitive flag that is not plainly
                         false, a criticality level with any value
          AD identity    (so the count is the same count the decision makes) a domain SID, or an account name and domain
        Field names are compared without case (the rawData text is lower-cased once). -CriticalGroups:
        Get-SIIdentityCriticalAdGroupNames. A catalog name with characters outside letters, digits, space, '.', '_', '-'
        cannot be matched safely in the text: then any non-empty nestedAdGroupNames counts as privileged.
        -AnyEnabledState: SI_Identity_SkipNeverSyncedAd (the wider switch) -- the skip leaves out the enabled state:
        _siSkip = isnotnull(_siRl) and not(_siHasOid) and _siIsAd and not(_siPriv). Every other test is the same, and
        still leans the safe way (the AD identity test is what keeps a node of another identity provider).
    #>
    param([AllowNull()]$CriticalGroups, [switch]$AnyEnabledState)
    $names = New-Object System.Collections.Generic.List[string]
    $unsafeName = $false
    foreach ($g in @($CriticalGroups)) {
        if ($null -eq $g) { continue }
        $n = ([string]$g).Trim().ToLowerInvariant()
        if (-not $n) { continue }
        if ($n -cmatch '^[a-z0-9]([a-z0-9 _.\-]*[a-z0-9])?$') { $names.Add($n.Replace('.', '\.')) } else { $unsafeName = $true }
    }
    $groupTest = 'false'
    if ($unsafeName) { $groupTest = 'not(tostring(_siRl.nestedadgroupnames) in ("", "[]"))' }
    elseif ($names.Count -gt 0) {
        # a name as a whole item: what is before and after it is not a letter or digit (a quote, a comma, a space, an escape)
        $groupTest = 'tostring(_siRl.nestedadgroupnames) matches regex @"(^|[^a-z0-9]|\\u[0-9a-f]{4})(' + ($names -join '|') + ')($|[^a-z0-9])"'
    }
    $flagNotFalse = { param($f) ('not(trim(@"\s+", tostring(_siRl.{0})) in ("", "false", "0", "off", "no"))' -f $f) }
    $flagFalse = { param($f) ('trim(@"\s+", tostring(_siRl.{0})) in ("false", "0", "off", "no")' -f $f) }
    $guid = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    $sidKeys = @('adsid', 'accountsid', 'onpremsid', 'onpremisessecurityidentifier', 'securityidentifier', 'sid')
    $rawSid = 'case(' + ((@($sidKeys | ForEach-Object { 'tostring(_siRl.{0}) matches regex @"^s-1-[0-9]", tostring(_siRl.{0})' -f $_ })) -join ', ') + ', "")'
    $oidText = 'strcat(' + ((@('aadid', 'accountobjectid', 'objectid', 'aadobjectid', 'groupid', 'principalid', 'userid', 'id') | ForEach-Object { 'tostring(_siRl.{0})' -f $_ }) -join ', " ", ') + ')'
    $uac = '_siRl.useraccountcontrol'
    $uacNames = '"accountdisabled", "accountdisable", "account_disabled", "disabled"'
    $parts = @(
        '| extend _siIds = tolower(tostring(EntityIds)), _siRd = NodeProperties.rawData'
        '| extend _siRl = iff(gettype(_siRd) == "dictionary" and not(_siIds contains "aadobjectid"), todynamic(tolower(tostring(_siRd))), dynamic(null))'
        ('| extend _siHasOid = _siIds contains "aadobjectid" or {0} matches regex @"{1}"' -f $oidText, $guid)
        ('| extend _siSid = coalesce(extract(@"securityidentifier[^}}]*?(s-1-[0-9-]+)", 1, _siIds), {0})' -f $rawSid)
        '| extend _siIsAd = _siSid startswith "s-1-5-21-" or (gettype(_siRl.accountname) == "string" and isnotempty(tostring(_siRl.accountname)) and gettype(_siRl.accountdomain) == "string" and isnotempty(tostring(_siRl.accountdomain)))'
    )
    if (-not $AnyEnabledState) {
        $parts += @(
        ('| extend _siUacT = gettype({0}), _siUacS = trim(@"\s+", tostring({0}))' -f $uac)
        ('| extend _siDisabled = {0} or {1} or {2}' -f (& $flagFalse 'accountenabled'), (& $flagFalse 'isenabled'), (& $flagFalse 'enabled')) +
            (' or (_siUacT in ("long", "int") and binary_and(tolong({0}), 2) == 2)' -f $uac) +
            ' or (_siUacT == "string" and _siUacS matches regex @"^[0-9]+$" and binary_and(tolong(_siUacS), 2) == 2)' +
            (' or (_siUacT == "array" and array_length(set_intersect({0}, dynamic([{1}]))) > 0)' -f $uac, $uacNames) +
            ' or (_siUacT == "string" and not(_siUacS startswith "[") and _siUacS matches regex @"(^|[,;])\s*(accountdisabled|accountdisable|account_disabled|disabled)\s*($|[,;])")'
        )
    }
    $parts += @(
        ('| extend _siPriv = tostring(_siRl.admincount) matches regex @"[1-9]"' +
            ' or not(tostring(_siRl.nestedcriticaladgroups) in ("", "[]", "{}") or (gettype(_siRl.nestedcriticaladgroups) == "dictionary" and gettype(_siRl.nestedcriticaladgroups.data) == "array" and array_length(_siRl.nestedcriticaladgroups.data) == 0))' +
            (' or {0}' -f $groupTest) +
            ' or not(tostring(_siRl.assignedroles) in ("", "[]"))' +
            (' or {0} or {1} or {2}' -f (& $flagNotFalse 'hasserviceprincipalname'), (& $flagNotFalse 'isserviceaccount'), (& $flagNotFalse 'issensitive')) +
            ' or iff(gettype(_siRl.criticalitylevel) == "dictionary", isnotempty(tostring(_siRl.criticalitylevel.criticalitylevel)), isnotempty(tostring(_siRl.criticalitylevel))))')
    )
    if ($AnyEnabledState) { $parts += '| extend _siSkip = isnotnull(_siRl) and not(_siHasOid) and _siIsAd and not(_siPriv)' }
    else { $parts += '| extend _siSkip = isnotnull(_siRl) and not(_siHasOid) and _siIsAd and _siDisabled and not(_siPriv)' }
    ($parts -join ' ')
}

function Get-SIEgIdentityScopeDecision {
    <#
        PURE. Does one Exposure Graph identity node become a record (an asset) under the install's choice?
          -NodeLabel     user | group | serviceprincipal | managedidentity
          -AadObjectId   the Entra object id the identity read found ('' = never synced)
          -RawData       the node's rawData
          -Choice        Get-SIIdentityScopeChoice
          -EntraGroups   the ids Entra ID returns (Read-SIEntraGroupIds .Ids); $null = not read
          -GroupsUnknown the Entra group read was asked for and is NOT complete
          -CriticalGroups Get-SIIdentityCriticalAdGroupNames
          -Sid           the SID the identity read resolved (EntityIds or rawData), '' = none
        Returns @{ Keep; Setting (the switch that left it out, ''); Why; Held ($true = left out this run only because the
        Entra group read was not complete) }.
        A never-synced user is decided by ONE switch (Get-SIIdentityNeverSyncedSetting): SI_Identity_SkipNeverSyncedAd while
        it is on (kept when it is not an AD account, or privileged -- whatever its enabled state), else
        SI_Identity_SkipNeverSyncedDisabledAd (kept when it is not disabled for certain, or privileged).
    #>
    param([AllowEmptyString()][string]$NodeLabel = '', [AllowEmptyString()][string]$AadObjectId = '', [AllowNull()]$RawData,
          [Parameter(Mandatory)]$Choice, [AllowNull()]$EntraGroups, [switch]$GroupsUnknown, [AllowNull()]$CriticalGroups,
          [AllowNull()][AllowEmptyString()][string]$Sid = '')
    $keep = [pscustomobject]@{ Keep = $true; Setting = ''; Why = ''; Held = $false }
    if (-not $Choice -or -not $Choice.Any) { return $keep }
    $label = ([string]$NodeLabel).Trim().ToLowerInvariant()
    $oid = ([string]$AadObjectId).Trim().ToLowerInvariant()
    $neverSynced = Get-SIIdentityNeverSyncedSetting -Choice $Choice
    if ($label -eq 'user' -and -not $oid -and $neverSynced -eq $script:SIIdentityScopeSettings.SkipNeverSyncedAd.Setting) {
        if (-not (Test-SIEgIsAdAccount -RawData $RawData -Sid $Sid)) { return $keep }
        $priv = Get-SIEgAdPrivilege -RawData $RawData -CriticalGroups $CriticalGroups
        if ($priv.IsPrivileged) { return $keep }
        return [pscustomobject]@{ Keep = $false; Setting = $neverSynced; Why = 'an on-premises AD account never synced to Entra ID and not privileged'; Held = $false }
    }
    if ($label -eq 'user' -and -not $oid -and $neverSynced -eq $script:SIIdentityScopeSettings.SkipNeverSyncedDisabledAd.Setting) {
        if ((Test-SIEgAdAccountDisabled -RawData $RawData) -ne $true) { return $keep }
        $priv = Get-SIEgAdPrivilege -RawData $RawData -CriticalGroups $CriticalGroups
        if ($priv.IsPrivileged) { return $keep }
        return [pscustomobject]@{ Keep = $false; Setting = $script:SIIdentityScopeSettings.SkipNeverSyncedDisabledAd.Setting; Why = 'an on-premises AD account never synced to Entra ID, disabled and not privileged'; Held = $false }
    }
    if ($label -eq 'group' -and $oid -and $Choice.SkipDeletedGroups) {
        if ($GroupsUnknown) {
            return [pscustomobject]@{ Keep = $false; Setting = $script:SIIdentityScopeSettings.SkipDeletedGroups.Setting; Why = 'the Entra ID group read was not complete this run -- the group keeps its last state'; Held = $true }
        }
        if ($null -eq $EntraGroups) { return $keep }
        if ($EntraGroups.Contains($oid)) { return $keep }
        return [pscustomobject]@{ Keep = $false; Setting = $script:SIIdentityScopeSettings.SkipDeletedGroups.Setting; Why = 'a group Entra ID no longer has (neither active nor in its deleted items)'; Held = $false }
    }
    return $keep
}

function Read-SIEntraGroupIds {
    <#
        Every group id Entra ID has: active (/groups) and recently deleted (/directory/deletedItems/microsoft.graph.group),
        ids only, page by page. Returns @{ Ok; Ids (HashSet, lower-case); Active; Deleted; Error }. Ok = $false when either
        read failed: the caller then decides nothing about groups this run.
        -Fetch: test seam { param($Url, $OnPage) } -- calls $OnPage with each page's rows; throws on a failed read.
    #>
    param([scriptblock]$Fetch)
    $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $res = [ordered]@{ Ok = $false; Ids = $ids; Active = 0; Deleted = 0; Error = '' }
    if (-not $Fetch) {
        $Fetch = {
            param($Url, $OnPage)
            $tk = ''
            if (Get-Command -Name Get-SIGraphToken -ErrorAction SilentlyContinue) { $tk = [string](Get-SIGraphToken -Resource Graph) }
            if (-not $tk) { throw 'no Microsoft Graph token' }
            $null = Invoke-SIGraphPaged -RelativeUrl $Url -Token $tk -OnPage $OnPage
        }
    }
    $state = @{ Active = 0; Deleted = 0 }
    try {
        & $Fetch '/groups?$select=id&$top=999' { param($rows) foreach ($r in @($rows)) { $i = [string](Get-SIIdentityScopeValue $r 'id'); if ($i) { if ($ids.Add($i.Trim().ToLowerInvariant())) { $state.Active++ } } } }
        & $Fetch '/directory/deletedItems/microsoft.graph.group?$select=id&$top=999' { param($rows) foreach ($r in @($rows)) { $i = [string](Get-SIIdentityScopeValue $r 'id'); if ($i) { if ($ids.Add($i.Trim().ToLowerInvariant())) { $state.Deleted++ } } } }
        $res.Ok = $true
    } catch {
        $res.Error = [string]$_.Exception.Message
    }
    $res.Active = [int]$state.Active; $res.Deleted = [int]$state.Deleted
    [pscustomobject]$res
}

function New-SIIdentityScopeCounter {
    <# A counter per switch that decides this run: @{ <setting> = @{ LeftOut; Held; Kept; Applied; Detail } }. Of the two
       never-synced switches only the one that decides (Get-SIIdentityNeverSyncedSetting) gets a counter. #>
    param([Parameter(Mandatory)]$Choice)
    $c = [ordered]@{}
    $neverSynced = Get-SIIdentityNeverSyncedSetting -Choice $Choice
    foreach ($k in $script:SIIdentityScopeSettings.Keys) {
        if (-not $Choice.$k) { continue }
        if (($k -in @('SkipNeverSyncedAd', 'SkipNeverSyncedDisabledAd')) -and ($script:SIIdentityScopeSettings[$k].Setting -ne $neverSynced)) { continue }
        $c[$script:SIIdentityScopeSettings[$k].Setting] = [pscustomobject]@{ Setting = $script:SIIdentityScopeSettings[$k].Setting; Feed = 'eg|user'; LeftOut = 0L; Held = 0L; Kept = 0L; Applied = $true; Detail = ''; NotFetched = 0L }
    }
    $c
}

function Add-SIIdentityScopeCount {
    <# Counts one node's decision on the counter (a left-out node, or a node the switch looked at and kept). #>
    param([Parameter(Mandatory)]$Counter, [Parameter(Mandatory)]$Decision, [string]$KeptBy = '')
    if (-not $Decision.Keep) {
        $c = $Counter[[string]$Decision.Setting]
        if ($null -eq $c) { return }
        if ($Decision.Held) { $c.Held++ } else { $c.LeftOut++ }
        return
    }
    if ($KeptBy) { $c = $Counter[$KeptBy]; if ($null -ne $c) { $c.Kept++ } }
}

function Format-SIIdentityScopeLine {
    <# PURE. The one plain line the identity step logs per switch (customer-facing: the setting named, counts only). #>
    param([Parameter(Mandatory)]$Count)
    $n = '{0:N0}' -f [long]$Count.LeftOut
    switch ([string]$Count.Setting) {
        'SI_Identity_SkipNeverSyncedAd' {
            # left out in the hunting query itself (Get-SIEgNeverSyncedSkipKql -AnyEnabledState): part of the count, never fetched
            $nf = 0L; if ($Count.PSObject.Properties['NotFetched'] -and $null -ne $Count.NotFetched) { $nf = [long]$Count.NotFetched }
            if ($nf -gt 0) {
                return ('Exposure Graph identities: {0} on-premises AD account(s) never synced to Entra ID and not privileged got no asset (SI_Identity_SkipNeverSyncedAd is on): {1:N0} not fetched (left out in the Exposure Graph query itself), {2:N0} left out after the read; {3:N0} never-synced account(s) kept because they are privileged. Existing CIs of the accounts left out retire with that reason.' -f $n, $nf, ([long]$Count.LeftOut - $nf), [long]$Count.Kept)
            }
            return ('Exposure Graph identities: {0} on-premises AD account(s) never synced to Entra ID and not privileged got no asset (SI_Identity_SkipNeverSyncedAd is on); {1:N0} never-synced account(s) kept because they are privileged. Existing CIs of the accounts left out retire with that reason.' -f $n, [long]$Count.Kept)
        }
        'SI_Identity_SkipNeverSyncedDisabledAd' {
            # left out in the hunting query itself (Get-SIEgNeverSyncedSkipKql): part of the count, never fetched
            $nf = 0L; if ($Count.PSObject.Properties['NotFetched'] -and $null -ne $Count.NotFetched) { $nf = [long]$Count.NotFetched }
            if ($nf -gt 0) {
                return ('Exposure Graph identities: {0} on-premises AD account(s) never synced to Entra ID, disabled and not privileged, got no asset (SI_Identity_SkipNeverSyncedDisabledAd is on): {1:N0} not fetched (left out in the Exposure Graph query itself), {2:N0} left out after the read; {3:N0} never-synced account(s) kept because they are enabled or privileged. Existing CIs of the accounts left out retire with that reason.' -f $n, $nf, ([long]$Count.LeftOut - $nf), [long]$Count.Kept)
            }
            return ('Exposure Graph identities: {0} on-premises AD account(s) never synced to Entra ID, disabled and not privileged, got no asset (SI_Identity_SkipNeverSyncedDisabledAd is on); {1:N0} never-synced account(s) kept because they are enabled or privileged. Existing CIs of the accounts left out retire with that reason.' -f $n, [long]$Count.Kept)
        }
        'SI_Identity_SkipDeletedGroups' {
            if (-not $Count.Applied) {
                $why = 'no detail'; if ($Count.Detail) { $why = [string]$Count.Detail }
                return ('Exposure Graph identities: SI_Identity_SkipDeletedGroups is on, but the Entra ID group list could not be read completely ({0}) -- {1:N0} group(s) with an Entra id were not recorded this run and keep their last state (nothing retires, nothing comes back).' -f $why, [long]$Count.Held)
            }
            return ('Exposure Graph identities: {0} group(s) Entra ID no longer has (neither active nor in its deleted items) got no asset (SI_Identity_SkipDeletedGroups is on); {1:N0} group(s) that still exist in Entra ID kept. Existing CIs of the groups left out retire with that reason.' -f $n, [long]$Count.Kept)
        }
    }
    ('{0}: {1} left out' -f [string]$Count.Setting, $n)
}

function Get-SIIdentityScopeWriteSql {
    <# The ONE statement that records this run's counts (sidata.CollectionLeftOut; nothing when the table is not there yet) and
       keeps 400 days of them. @rows = [{ Setting; Feed; LeftOut; Kept; Held; Applied; Detail }], @engine. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.CollectionLeftOut') IS NULL BEGIN SELECT 0 AS Written; RETURN; END
INSERT sidata.CollectionLeftOut (Setting, Feed, Engine, LeftOut, Kept, Held, Applied, Detail)
SELECT LEFT(x.Setting, 64), LEFT(ISNULL(x.Feed, N''), 64), LEFT(ISNULL(@engine, N''), 32), ISNULL(x.LeftOut, 0), x.Kept, ISNULL(x.Held, 0), ISNULL(x.Applied, 1), LEFT(x.Detail, 400)
FROM OPENJSON(@rows) WITH (Setting NVARCHAR(64), Feed NVARCHAR(64), LeftOut BIGINT, Kept BIGINT, Held BIGINT, Applied BIT, Detail NVARCHAR(400)) x
WHERE x.Setting IS NOT NULL;
DECLARE @n INT = @@ROWCOUNT;
DELETE FROM sidata.CollectionLeftOut WHERE CollectedAt < DATEADD(day, -400, SYSUTCDATETIME());
SELECT @n AS Written;
'@
}

function Write-SIIdentityScopeCounts {
    <#
        Records this run's counts in the install's database (one row per switch). -Invoke: the SQL seam
        { param($Sql, $Params, $Mode) } (New-SIRecordSqlInvoke); none = no database, the log line is the record. Never throws.
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Counts, [scriptblock]$Invoke, [string]$Engine = 'identity')
    if (-not @($Counts).Count) { return 0 }
    if (-not $Invoke) {
        if (-not (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue)) {
            $rs = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'data-model', 'SI-RecordSql.ps1')
            if ([IO.File]::Exists($rs)) { try { . $rs } catch { } }
        }
        if (Get-Command -Name New-SIRecordSqlInvoke -ErrorAction SilentlyContinue) { $Invoke = New-SIRecordSqlInvoke }
    }
    if (-not $Invoke) { return 0 }
    try {
        $rows = @(foreach ($c in @($Counts)) { [ordered]@{ Setting = [string]$c.Setting; Feed = [string]$c.Feed; LeftOut = [long]$c.LeftOut; Kept = [long]$c.Kept; Held = [long]$c.Held; Applied = [bool]$c.Applied; Detail = [string]$c.Detail } })
        $j = ConvertTo-Json -InputObject @($rows) -Compress -Depth 4
        if (-not $j.TrimStart().StartsWith('[')) { $j = '[' + $j + ']' }
        $r = @(& $Invoke (Get-SIIdentityScopeWriteSql) @{ rows = $j; engine = $Engine } 'rows') | Select-Object -First 1
        return [int](Get-SIIdentityScopeValue $r 'Written')
    } catch {
        Write-Warning ('identity scope choice: the counts could not be recorded in the database -- {0}. The run log has them.' -f $_.Exception.Message)
        return 0
    }
}

function Get-SIIdentityScopeLeftOutSql {
    <# The records each feed's switches left out of the collection @ctText (rows written at or after it), per feed. #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.CollectionLeftOut') IS NULL BEGIN SELECT CAST(NULL AS NVARCHAR(64)) AS Feed, CAST(0 AS BIGINT) AS LeftOut WHERE 1 = 0; RETURN; END
DECLARE @ct DATETIME2(3) = TRY_CONVERT(DATETIME2(3), NULLIF(@ctText, N''), 127);
SELECT l.Feed, SUM(l.LeftOut) AS LeftOut
FROM sidata.CollectionLeftOut l
WHERE @ct IS NOT NULL AND l.CollectedAt >= @ct AND l.Applied = 1
  AND l.Id IN (SELECT MAX(i.Id) FROM sidata.CollectionLeftOut i WHERE i.CollectedAt >= @ct GROUP BY i.Setting)
GROUP BY l.Feed;
'@
}

function Get-SIIdentityScopeLeftOutByFeed {
    <#
        The records the switches left out of one collection, per feed ('eg|user' -> count) -- what the asset-drop check adds
        back before it judges a feed. Only read while a switch is on in this install (-Choice); otherwise, or on any failure,
        an empty map (the check judges as before). Never throws.
    #>
    param([Parameter(Mandatory)][scriptblock]$Invoke, [Parameter(Mandatory)][string]$CollectionTimeText, $Choice)
    $out = @{}
    if (-not $Choice) { $Choice = Get-SIIdentityScopeChoice }
    if (-not $Choice.Any) { return $out }
    try {
        foreach ($r in @(& $Invoke (Get-SIIdentityScopeLeftOutSql) @{ ctText = $CollectionTimeText } 'rows')) {
            if ($null -eq $r) { continue }
            $f = [string](Get-SIIdentityScopeValue $r 'Feed'); if (-not $f) { continue }
            $n = Get-SIIdentityScopeValue $r 'LeftOut'; if ($null -eq $n -or $n -is [DBNull]) { $n = 0 }
            $out[$f.ToLowerInvariant()] = [long]$n
        }
    } catch { Write-Warning ('identity scope choice: the left-out counts could not be read for the asset-drop check -- {0}' -f $_.Exception.Message) }
    $out
}

function Get-SIRecordLeftOutByIdentityChoice {
    <#
        PURE. The CI build's side: is this Exposure Graph record -- MISSING from a complete newer collection -- one the
        install's choice now leaves out? Decided from the record's own stored SI fields (the node is not read again):
          SI_Identity_SkipNeverSyncedDisabledAd  an eg user record of a user (si_identity_type user) with no Entra object id,
                                                 whose stored fields show no privilege (si_admin_count, si_ad_critical_groups,
                                                 si_is_sensitive_account, si_ms_criticality): the switch keeps every enabled
                                                 or privileged never-synced account listed, so one that is no longer listed
                                                 is disabled now (or gone from AD)
          SI_Identity_SkipNeverSyncedAd          the same record, while this wider switch is on (it then decides instead of
                                                 the one above), and only when the record shows it is an AD account (a domain
                                                 SID in ad_sid, or an account name + AD domain): the switch keeps every
                                                 privileged never-synced account listed, so one no longer listed is not
                                                 privileged (or gone from AD)
          SI_Identity_SkipDeletedGroups         an eg user record of a group (si_identity_type group) with an Entra object id:
                                                 the switch keeps every group Entra still has, so one no longer listed is gone
        Returns @{ Gone; Reason } -- Gone = $false for anything else (the lifecycle's usual "not seen" applies).
    #>
    param([AllowNull()]$Record, [Parameter(Mandatory)]$Choice)
    $no = [pscustomobject]@{ Gone = $false; Reason = '' }
    if ($null -eq $Record -or -not $Choice -or -not $Choice.Any) { return $no }
    if ([string](Get-SIIdentityScopeValue $Record 'si_provider') -ne 'eg' -or [string](Get-SIIdentityScopeValue $Record 'si_record_type') -ne 'user') { return $no }
    $type = ([string](Get-SIIdentityScopeValue $Record 'si_identity_type')).Trim().ToLowerInvariant()
    $oid = ([string]@(Get-SIIdentityScopeList (Get-SIIdentityScopeValue $Record 'entra_object_id'))[0]).Trim()
    $neverSynced = Get-SIIdentityNeverSyncedSetting -Choice $Choice
    if ($type -eq 'user' -and -not $oid -and $neverSynced) {
        $wide = ($neverSynced -eq $script:SIIdentityScopeSettings.SkipNeverSyncedAd.Setting)
        if ($wide) {
            # the wider switch never leaves out a node that is not an AD account: a record without an AD sign keeps the
            # usual "not seen" grace
            $adSid = ([string]@(Get-SIIdentityScopeList (Get-SIIdentityScopeValue $Record 'ad_sid'))[0]).Trim()
            $sam = [string](Get-SIIdentityScopeValue $Record 'si_sam_account_name')
            $dom = [string](Get-SIIdentityScopeValue $Record 'si_ad_domain')
            if (-not ($adSid -match '^(?i)s-1-5-21-') -and -not ($sam.Trim() -and $dom.Trim())) { return $no }
        }
        $ac = 0; if ([int]::TryParse([string](Get-SIIdentityScopeValue $Record 'si_admin_count'), [ref]$ac) -and $ac -gt 0) { return $no }
        if (@(Get-SIIdentityScopeList (Get-SIIdentityScopeValue $Record 'si_ad_critical_groups')).Count -gt 0) { return $no }
        if ((ConvertTo-SIIdentityScopeFlag (Get-SIIdentityScopeValue $Record 'si_is_sensitive_account')) -eq $true) { return $no }
        if ((ConvertTo-SIIdentityScopeFlag (Get-SIIdentityScopeValue $Record 'si_is_service_account')) -eq $true) { return $no }
        $crit = Get-SIIdentityScopeValue $Record 'si_ms_criticality'
        if ($null -ne $crit -and "$crit".Trim() -ne '') { return $no }
        if ($wide) {
            return [pscustomobject]@{ Gone = $true; Reason = 'left out by the install''s choice SI_Identity_SkipNeverSyncedAd: an on-premises AD account never synced to Entra ID that the Exposure Graph no longer lists as privileged' }
        }
        return [pscustomobject]@{ Gone = $true; Reason = 'left out by the install''s choice SI_Identity_SkipNeverSyncedDisabledAd: an on-premises AD account never synced to Entra ID that the Exposure Graph no longer lists as enabled or privileged' }
    }
    if ($type -eq 'group' -and $oid -and $Choice.SkipDeletedGroups) {
        return [pscustomobject]@{ Gone = $true; Reason = 'left out by the install''s choice SI_Identity_SkipDeletedGroups: a group Entra ID no longer has (neither active nor in its deleted items)' }
    }
    return $no
}
