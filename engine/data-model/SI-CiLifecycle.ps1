#Requires -Version 5.1
<#
    SecurityInsight -- THE ASSET LIFECYCLE, ONE MECHANISM (V3-DATA-MODEL 2.5.5, REQUIREMENTS #406, 60.5.0c / 60.5.0d).

    Owner 2026-10-06, verbatim: "14 day is not sufficient and auto-close graceperiod must be in the settings. for example a
    person on summer vacation for 5 weeks will then be closed as his laptop is turned off after 14 days (wrong). ... default
    auto close value should be 30 days but with option to override in the categories i listed".
    Owner 2026-10-19: "we have already defined the lifecycle in the docs for design, read the req there. read also the code
    of the actual impl." -- the core CI now carries the lifecycle the CMDB sync had alone.

    The PURE parts both users share -- the CI build (SI-CiBuild.ps1, every edition) and the CMDB sync's asset lifecycle
    (engine\asset-cmdb\_shared\SI-AssetLifecycle.ps1, Pro): the categories and their grace periods (the settings), the
    seen window, the state LastSeen alone gives, a CI's category, and the CI lifecycle decision over its linked objects.

    PER LINKED OBJECT (decided by Get-SIRecordLinkState, SI-CiBuild.ps1):
        active    listed in its feed's newest collection, and -- a DEVICE record, whose source keeps listing a machine it has
                  not heard from (Defender lists inactive devices) -- its source saw it within the seen window
        not_seen  missing from a COMPLETE newer collection, or listed but its source has not seen it within the seen window
        gone      POSITIVE evidence: offboarded
        frozen    the newer collection was partial, or the provider's collection scope changed since the record was last
                  listed (60.5.0d: an asset that leaves because we stopped looking has told us nothing) -- nothing changes
    PER CI (Get-SICiLifecycle):
        active    any link active
        not_seen  no link active, newest last seen within the grace period of the CI's category
        retired   beyond the grace period, or at once when EVERY link is gone; stays retired until a link is active again
        reactivated (a transition, not a state): active again after not_seen / retired -- the reason says so
        a CI whose only current links are frozen is active (absence proves nothing); one already retired stays retired
    PowerShell 5.1: no ?. / ??, no ternary. No Set-StrictMode.
#>

$script:SIAssetRetireCategorySettings = [ordered]@{
    'client-pc'         = 'SI_Pro_AssetRetire_GraceDays_ClientPc'
    'server'            = 'SI_Pro_AssetRetire_GraceDays_Server'
    'service-principal' = 'SI_Pro_AssetRetire_GraceDays_ServicePrincipal'
    'user'              = 'SI_Pro_AssetRetire_GraceDays_User'
    'azure-vm'          = 'SI_Pro_AssetRetire_GraceDays_AzureVm'
    'azure-resource'    = 'SI_Pro_AssetRetire_GraceDays_AzureResource'
}

# a source whose own "last seen" lags by design (V3-DATA-MODEL 2.6): Entra updates approximateLastSignInDateTime at most every
# ~14 days, AD replicates lastLogonTimestamp with a 9-14 day lag -- a device record of theirs is stale only past that lag
$script:SICiProviderSeenLagDays = @{ entra = 14; ad = 14 }

# =====================================================================================================================
#  SETTINGS AND CATEGORIES -- pure
# =====================================================================================================================
function Resolve-SIAssetRetireSettings {
    <#
        PURE. The grace periods from a name -> value map (the live globals):
          SI_Pro_AssetRetire_GraceDays                 default 30 -- every category without its own value, and 'other'
          SI_Pro_AssetRetire_GraceDays_<Category>      a category's own value (ClientPc, Server, ServicePrincipal, User, AzureVm, AzureResource)
          SI_Pro_CmdbSql_SeenWithinDays                default 8 -- seen this recently = active
          SI_Cmdb_RetireAfterDays                      default 7 -- the CI retire brake (owner 2026-10-11): the floor of every grace period
        A grace period shorter than the seen window would retire an asset the moment it is "not seen": it is raised to the
        seen window (or SI_Cmdb_RetireAfterDays when that is longer) and the warning says so. A value that is not a whole
        number uses the default and says so.
        Returns @{ DefaultDays; Days (category -> days, 'other' included); SeenWithinDays; RetireAfterDays; Warnings }.
    #>
    param([hashtable]$Globals = @{})
    if ($null -eq $Globals) { $Globals = @{} }
    $warn = New-Object System.Collections.Generic.List[string]
    $int = {
        param([string]$name, [int]$default, [int]$min)
        if (-not $Globals.ContainsKey($name) -or $null -eq $Globals[$name] -or "$($Globals[$name])".Trim() -eq '') { return $default }
        $n = 0
        if (-not [int]::TryParse("$($Globals[$name])".Trim(), [Globalization.NumberStyles]::Integer, [Globalization.CultureInfo]::InvariantCulture, [ref]$n)) {
            $warn.Add(("{0} = '{1}' is not a whole number of days -- using {2}." -f $name, "$($Globals[$name])", $default)); return $default
        }
        if ($n -lt $min) { $warn.Add(("{0} = {1} is shorter than the minimum of {2} day(s) (the seen window, never under SI_Cmdb_RetireAfterDays) -- using {2}." -f $name, $n, $min)); return $min }
        $n
    }
    $seen = & $int 'SI_Pro_CmdbSql_SeenWithinDays' 8 1
    # the CI retire brake (owner 2026-10-11): no grace period is shorter than SI_Cmdb_RetireAfterDays (default 7), whatever the
    # seen window -- an asset is never retired before it has been unseen that long
    $retireDays = & $int 'SI_Cmdb_RetireAfterDays' 7 1
    $floor = [Math]::Max($seen, $retireDays)
    $def = [Math]::Max((& $int 'SI_Pro_AssetRetire_GraceDays' 30 $floor), $floor)
    $days = [ordered]@{}
    foreach ($c in @($script:SIAssetRetireCategorySettings.Keys)) { $days[$c] = & $int ([string]$script:SIAssetRetireCategorySettings[$c]) $def $floor }
    $days['other'] = $def
    [pscustomobject]@{ DefaultDays = $def; Days = $days; SeenWithinDays = $seen; RetireAfterDays = $retireDays; Warnings = $warn.ToArray() }
}

function Get-SICiLifecycleSettings {
    <#
        The lifecycle settings as they are in force: Resolve-SIAssetRetireSettings over the live globals (the Pro settings
        store loads them; an edition without them gets the defaults: seen within 8 days, every grace period 30 days).
        -Globals: a name -> value map instead (tests).
    #>
    param([hashtable]$Globals)
    if ($null -eq $Globals) {
        $Globals = @{}
        $names = @('SI_Pro_CmdbSql_SeenWithinDays', 'SI_Cmdb_RetireAfterDays', 'SI_Pro_AssetRetire_GraceDays') + @($script:SIAssetRetireCategorySettings.Values)
        foreach ($n in $names) { $v = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue; if ($null -ne $v) { $Globals[$n] = $v } }
    }
    Resolve-SIAssetRetireSettings -Globals $Globals
}

function Get-SIAssetRetireCategory {
    <#
        PURE. The retire category of one CI from what the hand-off knows of it: its kind (endpoint | azure | identity), class
        hint, proposed ServiceNow class and ARM id. An Azure VM is an azure-vm whichever profile describes it (Defender's
        record of a VM comes first in the hand-off). Unknown = 'other' (the default grace period).
    #>
    param([AllowEmptyString()][string]$Kind = '', [AllowEmptyString()][string]$ClassHint = '', [AllowEmptyString()][string]$ProposedClass = '',
          [AllowEmptyString()][string]$AzureResourceId = '')
    $k = ([string]$Kind).Trim().ToLowerInvariant(); $h = ([string]$ClassHint).Trim().ToLowerInvariant(); $pc = ([string]$ProposedClass).Trim().ToLowerInvariant()
    $arm = ([string]$AzureResourceId).Trim().ToLowerInvariant()
    if ($pc -eq 'cmdb_ci_vm_instance' -or $arm -match '/providers/microsoft\.compute/virtualmachines(scalesets)?/') { return 'azure-vm' }
    if ($pc -eq 'u_cmdb_ci_entra_user') { return 'user' }
    if ($pc -eq 'u_cmdb_ci_entra_service_principal') { return 'service-principal' }
    if ($h -eq 'identity' -or $k -eq 'identity') { return 'other' }
    if ($pc -in 'cmdb_ci_win_server', 'cmdb_ci_linux_server', 'cmdb_ci_server') { return 'server' }
    if ($h -eq 'azure-resource' -or $k -eq 'azure') { return 'azure-resource' }
    if ($pc -eq 'cmdb_ci_computer' -or $h -eq 'device' -or $k -eq 'endpoint') { return 'client-pc' }
    'other'
}

function Get-SIAssetLifecycleTarget {
    <# PURE. The state LastSeen alone gives: active (within the seen window) | not-seen (within the grace) | retired. #>
    param([Parameter(Mandatory)][datetime]$LastSeen, [Parameter(Mandatory)][datetime]$Now, [int]$SeenWithinDays = 8, [int]$GraceDays = 30)
    $age = ($Now.ToUniversalTime() - $LastSeen.ToUniversalTime()).TotalDays
    if ($age -le $SeenWithinDays) { return 'active' }
    if ($age -le $GraceDays) { return 'not-seen' }
    'retired'
}

function Get-SILifecycleValue {
    <# PURE. A named value of a dictionary or an object ($null when it has none). #>
    param($Item, [string]$Name)
    if ($null -eq $Item) { return $null }
    if ($Item -is [System.Collections.IDictionary]) { if ($Item.Contains($Name)) { return $Item[$Name] }; return $null }
    $p = $Item.PSObject.Properties[$Name]; if ($p) { return $p.Value }
    $null
}

function Get-SICiRetireCategory {
    <#
        PURE. The retire category of a CORE CI (the same categories and the same Get-SIAssetRetireCategory decision the CMDB
        sync uses), from its class, its fields and its linked objects:
          an Azure virtual machine (scale set) link       azure-vm  (also when Defender describes it)
          a device whose OS is a server OS, or an Arc one server    -- any other device: client-pc
          an identity with a service principal link       service-principal  -- with a user link: user
          a cloud resource with an Azure link             azure-resource     -- anything else: other
    #>
    param([Parameter(Mandatory)]$Ci, [AllowEmptyCollection()][object[]]$Links = @())
    $class = [string](Get-SILifecycleValue $Ci 'si_class')
    $arm = ''
    foreach ($l in @($Links)) {
        if ($null -eq $l) { continue }
        $id = [string](Get-SILifecycleValue $l 'id')
        if ([string](Get-SILifecycleValue $l 'provider') -in 'azure', 'mdc' -and $id -match '^/subscriptions/') {
            if (-not $arm -or $id -match '/providers/microsoft\.compute/virtualmachines(scalesets)?/') { $arm = $id }
        }
    }
    switch ($class) {
        'device' {
            $os = ('{0} {1} {2}' -f (Get-SILifecycleValue $Ci 'si_os_name'), (Get-SILifecycleValue $Ci 'si_os_platform'), (Get-SILifecycleValue $Ci 'si_device_category')).ToLowerInvariant()
            $pc = 'cmdb_ci_computer'
            if ($os -match 'server' -or [string](Get-SILifecycleValue $Ci 'si_arc_status')) { $pc = 'cmdb_ci_server' }
            return (Get-SIAssetRetireCategory -Kind 'endpoint' -ClassHint 'device' -ProposedClass $pc -AzureResourceId $arm)
        }
        'identity' {
            $types = @(foreach ($l in @($Links)) { if ($l) { [string](Get-SILifecycleValue $l 'type') } })
            if ($types -contains 'service_principal') { return (Get-SIAssetRetireCategory -Kind 'identity' -ProposedClass 'u_cmdb_ci_entra_service_principal') }
            if ($types -contains 'user') { return (Get-SIAssetRetireCategory -Kind 'identity' -ProposedClass 'u_cmdb_ci_entra_user') }
            return 'other'
        }
        'cloud_resource' {
            if ($arm) { return (Get-SIAssetRetireCategory -Kind 'azure' -ClassHint 'azure-resource' -AzureResourceId $arm) }
            return 'other'
        }
        default { return 'other' }
    }
}

function Get-SIRecordSeenWindowDays {
    <#
        PURE. How long a record may go without its source seeing it before its link is not_seen, or 0 when the record's
        listing alone decides: only a DEVICE record carries a source heartbeat that its source keeps listing past (Defender
        lists a machine it has not heard from for months). An identity listed by Entra exists (a dormant account is a risk
        to report, never an asset to retire), and a cloud resource listed by Azure Resource Graph exists (ARM existence).
        A source whose last seen lags by design gets that lag (Entra devices, AD computers: 14 days).
    #>
    param($Record, [int]$SeenWithinDays = 8)
    if ($SeenWithinDays -le 0 -or $null -eq $Record) { return 0 }
    if ([string](Get-SILifecycleValue $Record 'si_class') -ne 'device') { return 0 }
    $lag = $script:SICiProviderSeenLagDays[[string](Get-SILifecycleValue $Record 'si_provider')]
    if ($lag -and [int]$lag -gt $SeenWithinDays) { return [int]$lag }
    $SeenWithinDays
}

function Get-SICiSeenThresholdDays {
    <# PURE. Every day count a CI's lifecycle can cross with time alone (the seen windows, every grace period) -- the CI build's time thresholds. #>
    param([Parameter(Mandatory)]$Settings)
    $out = New-Object System.Collections.Generic.List[int]
    $add = { param([int]$d) if ($d -gt 0 -and -not $out.Contains($d)) { $out.Add($d) } }
    & $add ([int]$Settings.SeenWithinDays)
    foreach ($v in @($script:SICiProviderSeenLagDays.Values)) { & $add ([Math]::Max([int]$v, [int]$Settings.SeenWithinDays)) }
    foreach ($k in @($Settings.Days.Keys)) { & $add ([int]$Settings.Days[$k]) }
    & $add ([int]$Settings.DefaultDays)
    $arr = $out.ToArray(); [Array]::Sort($arr); $arr
}

# =====================================================================================================================
#  THE COLLECTION SCOPE (60.5.0d) -- pure
# =====================================================================================================================
# the settings that narrow what a provider LISTS (a change of one makes assets vanish from a complete run)
$script:SICiCollectionScopeSettings = [ordered]@{
    azure  = @('SI_AzSubscriptionId', 'SI_AzureExcludeTypes', 'SI_AzureSubscriptionExcludePatterns')
    mdc    = @('SI_AzSubscriptionId', 'SI_AzureExcludeTypes', 'SI_AzureSubscriptionExcludePatterns')
    entra  = @('SI_IncludeFirstPartySpns', 'SI_DisabledAssets_Collect')
    mde    = @('SI_DisabledAssets_Collect')
    intune = @('SI_DisabledAssets_Collect')
    ad     = @('SI_DisabledAssets_Collect')
    eg     = @('SI_DisabledAssets_Collect')
    mdi    = @('SI_DisabledAssets_Collect')
}

function Get-SICiCollectionScope {
    <#
        PURE. The effective collection scope per provider: provider -> a hash of the scope settings' values (name=value, in
        order; a list joined). -Globals: name -> value (default: the live globals).
    #>
    param([hashtable]$Globals)
    $out = [ordered]@{}
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        foreach ($p in @($script:SICiCollectionScopeSettings.Keys)) {
            $parts = foreach ($n in @($script:SICiCollectionScopeSettings[$p])) {
                $v = $null
                if ($null -ne $Globals) { if ($Globals.ContainsKey($n)) { $v = $Globals[$n] } }
                else { $v = Get-Variable -Scope Global -Name $n -ValueOnly -ErrorAction SilentlyContinue }
                $t = if ($null -eq $v) { '' } elseif ($v -is [string]) { $v.Trim() } elseif ($v -is [System.Collections.IEnumerable]) { (@($v) | ForEach-Object { ([string]$_).Trim() } | Sort-Object) -join ',' } else { ([string]$v).Trim() }
                '{0}={1}' -f $n, $t
            }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes((@($parts) -join "`n"))
            $out[$p] = ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLowerInvariant()
        }
    } finally { $sha.Dispose() }
    $out
}

function Update-SICiScopeChanges {
    <#
        PURE. The collection scope compared with the one the last build recorded: provider -> the time its scope last changed.
        -Stored: the recorded state (provider -> @{ h; at }); -Current: Get-SICiCollectionScope; -Now. A provider seen for the
        first time records its scope (nothing changed). Returns @{ State (provider -> @{ h; at }, to record); ChangedAt
        (provider -> datetime, every provider whose scope ever changed); Changed (the providers that changed in THIS build) }.
    #>
    param([hashtable]$Stored = @{}, [Parameter(Mandatory)]$Current, [datetime]$Now = [datetime]::UtcNow)
    if ($null -eq $Stored) { $Stored = @{} }
    $state = [ordered]@{}; $at = @{}; $chg = New-Object System.Collections.Generic.List[string]
    foreach ($p in @($Current.Keys)) {
        $h = [string]$Current[$p]
        $prev = $Stored[$p]
        $ph = [string](Get-SILifecycleValue $prev 'h'); $pa = Get-SILifecycleValue $prev 'at'
        $paT = $null
        if ($pa -is [datetime]) { $paT = ([datetime]$pa).ToUniversalTime() } elseif ($pa) { $d = [datetime]::MinValue; if ([datetime]::TryParse([string]$pa, [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal), [ref]$d)) { $paT = $d } }
        if (-not $ph) { $state[$p] = [ordered]@{ h = $h; at = $(if ($paT) { $paT.ToString('o') } else { '' }) } }
        elseif ($ph -ne $h) { $state[$p] = [ordered]@{ h = $h; at = $Now.ToUniversalTime().ToString('o') }; $chg.Add($p); $paT = $Now.ToUniversalTime() }
        else { $state[$p] = [ordered]@{ h = $h; at = $(if ($paT) { $paT.ToString('o') } else { '' }) } }
        if ($paT) { $at[$p] = $paT }
    }
    [pscustomobject]@{ State = $state; ChangedAt = $at; Changed = $chg.ToArray() }
}

# =====================================================================================================================
#  THE CI LIFECYCLE -- pure
# =====================================================================================================================
function Get-SICiLifecycle {
    <#
        PURE. A CI's lifecycle from its linked objects (the record links: provider, type, state, last_seen, reason).
          -Category  Get-SICiRetireCategory      -Settings  Get-SICiLifecycleSettings      -Now  the build's time
          -Previous  what the CI was after the last build: @{ Lifecycle; Since; Reason } (none = a first build)
        Returns @{ Lifecycle (active | not_seen | retired); Since; NotSeenDays; Reason; Change ('' | not_seen | retired |
        reactivated | held); LastSeen; GraceDays; Category }.
          Since    active: when it became active (kept from the last build while it stays active) -- not_seen: the last time
                   any source saw it -- retired: when its grace period ran out, or when the last link was gone
          Reason   the evidence, in words (dates only, so it changes only with the state)
    #>
    param([AllowEmptyCollection()][object[]]$Links = @(), [string]$Category = 'other', [Parameter(Mandatory)]$Settings,
          [datetime]$Now = [datetime]::UtcNow, $Previous)
    $now = $Now.ToUniversalTime()
    $cat = if ($Category) { $Category } else { 'other' }
    $grace = [int]$Settings.DefaultDays; if ($Settings.Days.Contains($cat)) { $grace = [int]$Settings.Days[$cat] }
    $prevState = [string](Get-SILifecycleValue $Previous 'Lifecycle')
    $prevSince = Get-SILifecycleValue $Previous 'Since'
    if ($prevSince -and -not ($prevSince -is [datetime])) { $d = [datetime]::MinValue; if ([datetime]::TryParse([string]$prevSince, [Globalization.CultureInfo]::InvariantCulture, ([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal), [ref]$d)) { $prevSince = $d } else { $prevSince = $null } }
    $prevReason = [string](Get-SILifecycleValue $Previous 'Reason')
    $active = New-Object System.Collections.Generic.List[object]; $frozen = New-Object System.Collections.Generic.List[object]
    $notSeen = New-Object System.Collections.Generic.List[object]; $gone = New-Object System.Collections.Generic.List[object]
    foreach ($l in @($Links)) {
        if ($null -eq $l) { continue }
        switch ([string](Get-SILifecycleValue $l 'state')) { 'active' { $active.Add($l) } 'frozen' { $frozen.Add($l) } 'gone' { $gone.Add($l) } default { $notSeen.Add($l) } }
    }
    $newest = {
        param($xs)
        $best = $null
        foreach ($x in $xs) { $t = Get-SILifecycleValue $x 'last_seen'; if ($t -is [datetime] -and ($null -eq $best -or $t -gt $best)) { $best = ([datetime]$t).ToUniversalTime() } }
        $best
    }
    $fmt = { param($d) ([datetime]$d).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
    $names = { param($xs) (@(foreach ($x in $xs) { [string](Get-SILifecycleValue $x 'provider') }) | Select-Object -Unique) -join ', ' }
    $res = [ordered]@{ Lifecycle = 'active'; Since = $null; NotSeenDays = $null; Reason = ''; Change = ''; LastSeen = $null; GraceDays = $grace; Category = $cat }
    if ($active.Count -gt 0) {
        $last = & $newest $active
        $res.LastSeen = $last
        if ($prevState -eq 'active' -and $prevSince) { $res.Since = $prevSince; $res.Reason = $prevReason }
        elseif ($prevState -in 'not_seen', 'retired') {
            $res.Since = $now; $res.Change = 'reactivated'
            $res.Reason = ('reactivated: seen again by {0}{1} after it was {2}' -f (& $names $active), $(if ($last) { ' on ' + (& $fmt $last) } else { '' }), ($prevState -replace '_', ' '))
        } else {
            $res.Since = $(if ($prevSince -and $prevState -eq 'active') { $prevSince } else { $now })
            $res.Reason = ('seen by {0}' -f (& $names $active))
        }
        if (-not $res.Reason) { $res.Reason = ('seen by {0}' -f (& $names $active)) }
        return [pscustomobject]$res
    }
    if ($frozen.Count -gt 0) {
        # ABSENCE PROVES NOTHING: a link whose newest collection was partial (the source is on its last GOOD collection, which
        # listed it), or whose provider's scope changed, counts as listed -- the CI is active, never moved to not seen or
        # retired by it; only a CI already retired stays retired until a source sees it again
        $why = @(foreach ($f in $frozen) { $r = [string](Get-SILifecycleValue $f 'reason'); if ($r) { $r } }) | Select-Object -Unique
        $res.LastSeen = & $newest ($frozen.ToArray() + $notSeen.ToArray())
        $res.Change = 'held'
        if ($prevState -eq 'retired') { $res.Lifecycle = 'retired'; $res.Since = $prevSince; $res.Reason = $prevReason }
        elseif ($prevState -eq 'active') { $res.Lifecycle = 'active'; $res.Since = $prevSince; $res.Reason = $prevReason }
        else { $res.Lifecycle = 'active'; $res.Since = $now; $res.Reason = '' }
        if ($null -eq $res.Since) { $res.Since = $now }
        $held = ('held: {0} -- {1}' -f (& $names $frozen), $(if (@($why).Count) { @($why) -join '; ' } else { 'its newest collection was incomplete' }))
        if (-not $res.Reason) { $res.Reason = $held } elseif ($res.Reason -notmatch '^held: ') { $res.Reason = $res.Reason + ' (' + $held + ')' } else { $res.Reason = $held }
        if ($res.Lifecycle -ne 'active' -and $res.LastSeen) { $res.NotSeenDays = [int][Math]::Floor(($now - $res.LastSeen).TotalDays) }
        return [pscustomobject]$res
    }
    if ($notSeen.Count -eq 0) {
        # every link is gone (positive evidence): retired at once
        $res.Lifecycle = 'retired'; $res.LastSeen = & $newest $gone
        $res.Since = $(if ($prevState -eq 'retired' -and $prevSince) { $prevSince } else { $now })
        $res.Reason = ('retired at once: every linked object is gone ({0} -- {1})' -f (& $names $gone), $(@(foreach ($g in $gone) { $r = [string](Get-SILifecycleValue $g 'reason'); if ($r) { $r } }) | Select-Object -Unique | Select-Object -First 1))
        if ($res.Reason -match ' -- \)$') { $res.Reason = $res.Reason -replace ' -- \)$', ')' }
        if ($prevState -ne 'retired') { $res.Change = 'retired' } elseif ($prevReason) { $res.Reason = $prevReason }
        if ($res.LastSeen) { $res.NotSeenDays = [int][Math]::Floor(($now - $res.LastSeen).TotalDays) }
        return [pscustomobject]$res
    }
    # not seen: the newest sighting of any link that is not gone decides, against the category's grace period
    $last = & $newest $notSeen
    $res.LastSeen = $last
    if ($null -eq $last) {
        $res.Lifecycle = $(if ($prevState -eq 'retired') { 'retired' } else { 'not_seen' })
        $res.Since = $(if ($prevSince) { $prevSince } else { $now })
        $res.Reason = $(if ($prevReason -and $prevState -eq $res.Lifecycle) { $prevReason } else { 'not seen: no source reports when it last saw it' })
        if ($prevState -ne $res.Lifecycle) { $res.Change = $res.Lifecycle }
        return [pscustomobject]$res
    }
    $res.NotSeenDays = [int][Math]::Floor(($now - $last).TotalDays)
    $target = Get-SIAssetLifecycleTarget -LastSeen $last -Now $now -SeenWithinDays ([int]$Settings.SeenWithinDays) -GraceDays $grace
    $stale = @(foreach ($x in $notSeen) { $r = [string](Get-SILifecycleValue $x 'reason'); if ($r) { $r } }) | Select-Object -Unique | Select-Object -First 2
    $evidence = $(if (@($stale).Count) { ' (' + (@($stale) -join '; ') + ')' } else { '' })
    if ($target -eq 'retired' -or $prevState -eq 'retired') {
        $res.Lifecycle = 'retired'
        if ($prevState -eq 'retired' -and $prevSince) { $res.Since = $prevSince; $res.Reason = $prevReason }
        else {
            $res.Since = $last.AddDays($grace); if ($res.Since -gt $now) { $res.Since = $now }
            $res.Reason = ('retired: not seen since {0}, longer than the {1}-day grace period of a {2}{3}' -f (& $fmt $last), $grace, $cat, $evidence)
        }
        if (-not $res.Reason) { $res.Reason = ('retired: not seen since {0}, longer than the {1}-day grace period of a {2}{3}' -f (& $fmt $last), $grace, $cat, $evidence) }
        if ($prevState -ne 'retired') { $res.Change = 'retired' }
        return [pscustomobject]$res
    }
    $res.Lifecycle = 'not_seen'; $res.Since = $last
    $res.Reason = ('not seen since {0} -- retired on {1} unless it is seen again ({2}-day grace period of a {3}){4}' -f (& $fmt $last), (& $fmt ($last.AddDays($grace))), $grace, $cat, $evidence)
    if ($prevState -ne 'not_seen') { $res.Change = 'not_seen' }
    [pscustomobject]$res
}

function Get-SICiLifecycleDefinitions {
    <#
        PURE. The lifecycle in plain words, from the settings in force -- what every page and report says it shows (owner
        2026-10-19: "assumptions and filters should be transparent rgr lifecycle"). The web app has the same text
        (SI.Management.Core.ProData.CiLifecycleDefinitions); the test keeps the two the same.
    #>
    param([Parameter(Mandatory)]$Settings)
    $s = [int]$Settings.SeenWithinDays; $d = [int]$Settings.DefaultDays
    [ordered]@{
        active      = ('Active: at least one source lists the asset and -- for a device -- saw it within the last {0} days (Entra and Active Directory devices: 14 days, their last sign-in lags by design).' -f $s)
        not_seen    = ('Not seen: no source has seen the asset for more than {0} days; it stays in its grace period (default {1} days, per category) before it is retired.' -f $s, $d)
        retired     = 'Retired: not seen for longer than the grace period of its category, or every source gave positive evidence it is gone (offboarded). Its findings close as asset retired -- also those a source still reports -- never as fixed, and do not count as open; nothing is deleted.'
        reactivated = 'Reactivated: a not seen or retired asset that a source sees again is active again, and the change is recorded.'
    }
}
