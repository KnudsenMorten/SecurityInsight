#Requires -Version 5.1
<#
    SecurityInsight CI BUILD -- phase 2 of the v3 data model (V3-DATA-MODEL part 2, P2 + the first step of P3):
    the provider records of SI_Record_CL become CIs.

      1. GROUP     records that share a STRONG identifier (data-model field catalog, join = strong) are one asset:
                   connected components (union-find), transitive. Weak identifiers (names, IPs, MACs) never join.
                   A public IP address is the identity of a public_ip record (Shodan knows nothing else).
                   CMDB records are not grouped here: they are linked to a CI in the enrichment step.
      2. IDENTIFY  every group gets its CI id from the identity LEDGER -- the same ledger the correlation engine keeps,
                   the same identifier types, so a CI keeps the id it already has (and that a CMDB already holds):
                   mint (new), reuse (one known id), merge (two known ids: the oldest survives). No provisional ids:
                   no ledger, no CIs (a key that moves duplicates CIs in a CMDB).
      3. LINK      every record is a linked object of its CI: provider, type, native id, primary, state, last seen.
                   State: active (in its feed's newest collection), not_seen (missing from a COMPLETE newer
                   collection), frozen (missing, but the newer collection was incomplete -- absence proves nothing),
                   gone (positive evidence: offboarded). si_link_<provider> = the provider's primary record.
      4. RESOLVE   every SI field the records carry is resolved onto the CI by its catalog policy -- the source-of-
                   truth rule (V3-DATA-MODEL 2.6): fresh candidates only (record age <= staleDays), the first provider
                   in the field's authority order wins, risk booleans any-true, lists union; no fresh candidate -> the
                   newest value, marked stale. si_field_sources says, per field, which provider and record won.

    PURE: no I/O. Invoke-SICiBuild (SI-CiBuildRun.ps1) reads the records, the ledger, and publishes.
    PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

. (Join-Path $PSScriptRoot 'SI-Conditions.ps1')
# #459: conflicts beside the winner (fresh providers that disagree) -- SI-FieldResolution.ps1
. (Join-Path $PSScriptRoot 'SI-FieldResolution.ps1')
# the asset lifecycle (V3-DATA-MODEL 2.5.5, #406): categories, grace periods, seen window -- one mechanism with the CMDB sync
. (Join-Path $PSScriptRoot 'SI-CiLifecycle.ps1')

function Get-SICiLedgerTypeMap {
    <# The catalog's strong identifier fields -> the identity ledger's identifier types (shared with the correlation engine). #>
    return @{
        mde_device_id     = 'MdeDeviceId'
        entra_device_id   = 'AadDeviceId'
        eg_node_id        = 'ExposureGraphNodeId'
        azure_resource_id = 'AzureResourceId'
        entra_object_id   = 'AadObjectId'
        ad_object_guid    = 'ActiveDirectoryObjectGuid'
        ad_sid            = 'SecurityIdentifier'
        azure_vm_id       = 'AzureVmId'
        intune_device_id  = 'IntuneDeviceId'
        entra_app_id      = 'AadAppId'
        # #500 a resource in another cloud (AWS ARN / GCP resource name), as Defender for Cloud's multicloud connector reports it
        mdc_native_resource_id = 'CloudNativeResourceId'
    }
}

function Get-SICiClassRank {
    <# Which class a CI takes when its records differ: an Azure VM correlated with its Defender device is a device. #>
    param([string]$Class)
    switch ($Class) { 'device' { 0 } 'cloud_resource' { 1 } 'public_ip' { 2 } 'identity' { 3 } default { 9 } }
}

function Get-SIRecordIdentifiers {
    <# A record's strong identifiers as @{ Type; Value; Key } (ledger vocabulary, lower-cased value). #>
    param([Parameter(Mandatory)]$Record, [Parameter(Mandatory)][hashtable]$TypeMap)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $TypeMap.Keys) {
        foreach ($v in (Get-SIValueList (Get-SIItemValue $Record $f))) {
            $s = ([string]$v).Trim().ToLowerInvariant()
            if (-not $s) { continue }
            $t = $TypeMap[$f]
            $out.Add([pscustomobject]@{ Type = $t; Value = $s; Key = ('{0}|{1}' -f $t.ToLowerInvariant(), $s) })
        }
    }
    if ([string](Get-SIItemValue $Record 'si_class') -eq 'public_ip') {
        $ip = ([string](Get-SIItemValue $Record 'si_ip_address')).Trim().ToLowerInvariant()
        if ($ip) { $out.Add([pscustomobject]@{ Type = 'PublicIpAddress'; Value = $ip; Key = ('publicipaddress|{0}' -f $ip) }) }
    }
    return , $out
}

function Get-SICiGroups {
    <#
    .SYNOPSIS  Records -> groups of records that are one asset (connected components over strong identifiers).
    .OUTPUTS   @{ Groups = [ @{ Members = [ @{ Identifiers; Record } ] } ]; Unkeyable = <records without a strong id>; Largest }
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records, [hashtable]$TypeMap = (Get-SICiLedgerTypeMap))
    $parent = @{}
    $find = {
        param($x)
        $r = $x
        while ($parent[$r] -ne $r) { $r = $parent[$r] }
        $y = $x
        while ($parent[$y] -ne $r) { $n = $parent[$y]; $parent[$y] = $r; $y = $n }
        $r
    }
    $members = New-Object System.Collections.Generic.List[object]
    $unkeyable = New-Object System.Collections.Generic.List[object]
    foreach ($rec in $Records) {
        if ($null -eq $rec) { continue }
        if ([string](Get-SIItemValue $rec 'si_record_type') -eq 'cmdb_ci') { continue }
        $ids = Get-SIRecordIdentifiers -Record $rec -TypeMap $TypeMap
        if ($ids.Count -eq 0) { $unkeyable.Add($rec); continue }
        $m = [pscustomobject]@{ Identifiers = $ids.ToArray(); Record = $rec; Node = ('rec:' + [string](Get-SIItemValue $rec 'si_record_key')) }
        $members.Add($m)
        if (-not $parent.ContainsKey($m.Node)) { $parent[$m.Node] = $m.Node }
        foreach ($id in $ids) {
            if (-not $parent.ContainsKey($id.Key)) { $parent[$id.Key] = $id.Key }
            $a = & $find $m.Node; $b = & $find $id.Key
            if ($a -ne $b) { if ([string]::CompareOrdinal($a, $b) -lt 0) { $parent[$b] = $a } else { $parent[$a] = $b } }
        }
    }
    $byRoot = [ordered]@{}
    foreach ($m in $members) {
        $root = & $find $m.Node
        if (-not $byRoot.Contains($root)) { $byRoot[$root] = New-Object System.Collections.Generic.List[object] }
        $byRoot[$root].Add($m)
    }
    $groups = New-Object System.Collections.Generic.List[object]
    $largest = 0
    foreach ($k in $byRoot.Keys) {
        $groups.Add([pscustomobject]@{ Members = $byRoot[$k].ToArray() })
        if ($byRoot[$k].Count -gt $largest) { $largest = $byRoot[$k].Count }
    }
    return @{ Groups = $groups.ToArray(); Unkeyable = $unkeyable.ToArray(); Largest = $largest }
}

function Get-SIRecordFeed {
    <# A record's feed -- the unit whose newest collection says what is present: provider + record type. #>
    param($Record)
    '{0}|{1}' -f (Get-SIItemValue $Record 'si_provider'), (Get-SIItemValue $Record 'si_record_type')
}

function Get-SIFeedLatest {
    <# Per feed: the newest collection time and whether that collection was complete. #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Records)
    $latest = @{}
    foreach ($r in $Records) {
        $f = Get-SIRecordFeed $r
        $t = ConvertTo-SIUtcOrNull (Get-SIItemValue $r 'si_collection_time')
        if ($null -eq $t) { continue }
        $c = (ConvertTo-SIBoolOrNull (Get-SIItemValue $r 'si_collection_complete')) -ne $false
        if (-not $latest.ContainsKey($f) -or $t -gt $latest[$f].Time) { $latest[$f] = [pscustomobject]@{ Time = $t; Complete = $c } }
        elseif ($t -eq $latest[$f].Time -and -not $c) { $latest[$f].Complete = $false }
    }
    return $latest
}

function Get-SIRecordLink {
    <#
        PURE. One record's link state with its evidence: @{ State (active | not_seen | frozen | gone); Reason ('' when active) }.
          gone      positive evidence: the source says offboarded
          frozen    missing from its feed's newest collection and that collection was incomplete, or -- 60.5.0d -- the
                    provider's collection scope changed after the record was last listed (-ScopeChangedAt: provider ->
                    the time its scope changed): an asset that leaves because we stopped looking has told us nothing
          not_seen  missing from a COMPLETE newer collection; or (#406, -SeenWithinDays) LISTED, but a device record whose
                    source has not seen it within the seen window (Get-SIRecordSeenWindowDays) -- Defender keeps listing a
                    machine it has not heard from
          active    otherwise
        Without -SeenWithinDays (0) a listed record is active, as before the lifecycle was kept.
    #>
    param($Record, [hashtable]$FeedLatest, [datetime]$Now = [datetime]::UtcNow, [int]$SeenWithinDays = 0, [hashtable]$ScopeChangedAt)
    $p = [string](Get-SIItemValue $Record 'si_provider')
    if ([string](Get-SIItemValue $Record 'si_onboarding_status') -eq 'offboarded') { return [pscustomobject]@{ State = 'gone'; Reason = ('{0} says it is offboarded' -f $p) } }
    $t = ConvertTo-SIUtcOrNull (Get-SIItemValue $Record 'si_collection_time')
    $fl = $null; if ($FeedLatest) { $fl = $FeedLatest[(Get-SIRecordFeed $Record)] }
    $fmt = { param($d) ([datetime]$d).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
    if ($null -eq $fl -or $null -eq $t -or $t -ge $fl.Time) {
        $win = Get-SIRecordSeenWindowDays -Record $Record -SeenWithinDays $SeenWithinDays
        if ($win -gt 0) {
            # measured at the moment the source LISTED it (its collection time): a source that stops collecting proves nothing
            # about its devices -- only what it said when it last listed them counts (a source outage never retires)
            $sls = ConvertTo-SIUtcOrNull (Get-SIItemValue $Record 'si_source_last_seen')
            $at = $t; if ($null -eq $at -or $at -gt $Now.ToUniversalTime()) { $at = $Now.ToUniversalTime() }
            if ($null -ne $sls -and ($at - $sls).TotalDays -gt $win) {
                return [pscustomobject]@{ State = 'not_seen'; Reason = ('{0} lists it, but last saw it on {1} (more than {2} days)' -f $p, (& $fmt $sls), $win) }
            }
        }
        return [pscustomobject]@{ State = 'active'; Reason = '' }
    }
    if ($ScopeChangedAt -and $ScopeChangedAt.ContainsKey($p) -and $ScopeChangedAt[$p] -is [datetime] -and $t -lt $ScopeChangedAt[$p]) {
        return [pscustomobject]@{ State = 'frozen'; Reason = ('the {0} collection scope changed on {1}; it was last listed before that' -f $p, (& $fmt $ScopeChangedAt[$p])) }
    }
    # a device whose source -- when it last listed it -- had not seen it within the seen window is not seen, whatever the
    # newer collection was: that is the source's own evidence, not an absence
    $win = Get-SIRecordSeenWindowDays -Record $Record -SeenWithinDays $SeenWithinDays
    if ($win -gt 0) {
        # (as when it last listed it -- its collection time -- never "now": the newer collection was not complete)
        $sls = ConvertTo-SIUtcOrNull (Get-SIItemValue $Record 'si_source_last_seen')
        if ($null -ne $sls -and ($t - $sls).TotalDays -gt $win) {
            return [pscustomobject]@{ State = 'not_seen'; Reason = ('{0} last saw it on {1} (more than {2} days before it last listed it)' -f $p, (& $fmt $sls), $win) }
        }
    }
    if ($fl.Complete) { return [pscustomobject]@{ State = 'not_seen'; Reason = ('{0} no longer lists it (last listed {1})' -f $p, (& $fmt $t)) } }
    return [pscustomobject]@{ State = 'frozen'; Reason = ('the newest {0} collection was incomplete' -f $p) }
}

function Get-SIRecordLinkState {
    <# active | not_seen | frozen | gone for one record (Get-SIRecordLink's state). #>
    param($Record, [hashtable]$FeedLatest, [datetime]$Now = [datetime]::UtcNow, [int]$SeenWithinDays = 0, [hashtable]$ScopeChangedAt)
    (Get-SIRecordLink -Record $Record -FeedLatest $FeedLatest -Now $Now -SeenWithinDays $SeenWithinDays -ScopeChangedAt $ScopeChangedAt).State
}

function Get-SICiIdentityOrigin {
    <#
    .SYNOPSIS  PURE. #546 -- where an identity's on-premises facts come from: 'synced' | 'cloud' | '' (cannot tell).
                 synced  an Active Directory user record is linked to the CI, or any record says si_onprem_synced = true
                         (Entra onPremisesSyncEnabled, the Exposure Graph identity node)
                 cloud   an Entra record is linked and none of the above holds: Graph's onPremisesSyncEnabled is null for an
                         account that was never synchronised, and a service principal is always a cloud object
                 ''      neither (e.g. only an Exposure Graph or a Defender for Identity record) -- a field with an
                         origin-specific authority is then UNKNOWN on this CI, never guessed
    .PARAMETER Candidates  as Resolve-SICiField takes them: @{ Record; Provider; Key; State }
    #>
    param([AllowEmptyCollection()][object[]]$Candidates = @())
    $hasEntra = $false
    foreach ($c in $Candidates) {
        if ($null -eq $c) { continue }
        $p = [string]$c.Provider
        if ($p -eq 'ad' -and [string](Get-SIItemValue $c.Record 'si_record_type') -in 'user', '') { return 'synced' }
        if ((ConvertTo-SIBoolOrNull (Get-SIItemValue $c.Record 'si_onprem_synced')) -eq $true) { return 'synced' }
        if ($p -eq 'entra') { $hasEntra = $true }
    }
    if ($hasEntra) { return 'cloud' }
    return ''
}

function Get-SIFieldOriginRule {
    <#
    .SYNOPSIS  PURE. #546 -- a field's resolution for an identity origin (field catalog resolution.byOrigin.<origin>):
               @{ Policy; Authority; DecidedBy } or $null when the field has no origin-specific authority.
               Authority = the providers that may supply the value for that origin (in order; the others are ignored);
               DecidedBy = the providers one of which must be linked to the CI for the value -- or its absence -- to be
               known (default: Authority). A field with byOrigin on a CI whose origin is '' returns @{ Unknown = $true }.
               Customer-overridable like every catalog field: Community field-catalog.custom.json, Pro cfg.ItemOverride
               'field-catalog:<field>'.
    #>
    param([Parameter(Mandatory)]$Field, [AllowEmptyString()][string]$Origin)
    $bo = $null
    if ($Field.resolution) { $bo = Get-SIItemValue $Field.resolution 'byOrigin' }
    if ($null -eq $bo) { return $null }
    if (-not $Origin) { return @{ Unknown = $true } }
    $r = Get-SIItemValue $bo $Origin
    if ($null -eq $r) { return $null }
    $pol = [string](Get-SIItemValue $r 'policy'); if (-not $pol) { $pol = [string]$Field.resolution.policy }
    $auth = @(@(Get-SIItemValue $r 'authority') | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $dec = @(@(Get-SIItemValue $r 'decidedBy') | Where-Object { $_ } | ForEach-Object { [string]$_ })
    if ($dec.Count -eq 0) { $dec = $auth }
    return @{ Policy = $pol; Authority = $auth; DecidedBy = $dec; Unknown = $false }
}

function Test-SICiFieldUnknown {
    <#
    .SYNOPSIS  PURE. #546 -- is this field UNKNOWN on the CI: it has an origin-specific authority and either the origin cannot
               be told, or none of the providers that decide it for that origin has a current (active / frozen) record
               linked. A synchronised account without its Active Directory / Defender for Identity record has an unknown
               password age and on-premises sign-in -- never "stale", never "never signed in".
    #>
    param([Parameter(Mandatory)]$Field, [AllowEmptyString()][string]$Origin, [AllowEmptyCollection()][object[]]$Candidates = @())
    $rule = Get-SIFieldOriginRule -Field $Field -Origin $Origin
    if ($null -eq $rule) { return $false }
    if ($rule.Unknown) { return $true }
    foreach ($c in $Candidates) {
        if ($null -ne $c -and $rule.DecidedBy -contains [string]$c.Provider -and [string]$c.State -in 'active', 'frozen') { return $false }
    }
    return $true
}

function Resolve-SICiField {
    <#
    .SYNOPSIS  One SI field resolved from a CI's records by its catalog policy.
    .PARAMETER Origin  #546 the identity's origin (Get-SICiIdentityOrigin): a field with resolution.byOrigin takes that
                       origin's policy and authority, and ONLY the providers in it may supply the value (Entra never
                       decides a synchronised account's password age).
    .OUTPUTS   $null (no record carries it) or @{ Value; Provider; Record; ObservedAt; Stale }
    #>
    param([Parameter(Mandatory)]$Field, [Parameter(Mandatory)][object[]]$Candidates, [datetime]$Now, [string]$CmdbOwner = 'cmdb', [string]$Origin = '')
    $policy = [string]$Field.resolution.policy
    $rawAuth = @($Field.resolution.authority)
    # (an origin rule is used only with an origin: without one it is never applied -- not read)
    $originRule = $null; if ($Origin) { $originRule = Get-SIFieldOriginRule -Field $Field -Origin $Origin }
    if ($null -ne $originRule -and -not $originRule.Unknown) {
        $policy = $originRule.Policy
        $rawAuth = @($originRule.Authority)
        $allowed = $originRule.Authority
        $Candidates = @(foreach ($c in $Candidates) { if ($c -and $allowed -contains [string]$c.Provider) { $c } })
        if ($Candidates.Count -eq 0) { return $null }
    }
    # (2026-10-16, the CI build of a large install: this runs for every field of every CI -- loops, never a pipeline, and
    # a pool of ONE candidate is that candidate without a sort. The same answers.)
    # #463 the catalog's 'cmdb_owner' token is the tenant's ONE CMDB owner; a field whose authority is ONLY the owner
    # (si_cmdb_*) takes no value from any other provider -- a non-owner CMDB never decides (2.8.1, D11)
    $authority = @(foreach ($a in $rawAuth) { if ([string]$a -eq 'cmdb_owner') { $CmdbOwner } else { $a } })
    $notOwner = 0; foreach ($a in $rawAuth) { if ([string]$a -ne 'cmdb_owner') { $notOwner++ } }
    $ownerOnly = ($rawAuth.Count -gt 0 -and $notOwner -eq 0)
    if ($ownerOnly) { $Candidates = @(foreach ($c in $Candidates) { if ([string]$c.Provider -eq $CmdbOwner) { $c } }); if ($Candidates.Count -eq 0) { return $null } }
    $staleDays = 30
    if ($null -ne $Field.resolution.staleDays) { $staleDays = [double]$Field.resolution.staleDays }
    $cands = New-Object System.Collections.Generic.List[object]
    foreach ($c in $Candidates) {
        $v = Get-SIItemValue $c.Record ([string]$Field.name)
        if (Test-SIValueEmpty $v) { if (-not ($v -is [bool])) { continue } }
        $seen = ConvertTo-SIUtcOrNull (Get-SIItemValue $c.Record 'si_source_last_seen')
        $fresh = ($c.State -in 'active', 'frozen') -and ($null -ne $seen) -and ((($Now - $seen).TotalDays) -le $staleDays)
        $rank = [array]::IndexOf($authority, [string]$c.Provider)
        if ($rank -lt 0) { $rank = 999 }
        $cands.Add([pscustomobject]@{ Value = $v; Provider = $c.Provider; Record = $c.Key; ObservedAt = $seen; Fresh = $fresh; Rank = $rank })
    }
    if ($cands.Count -eq 0) { return $null }
    # plain arrays only: assigning @(<the generic list>) inside this branch threw "Argument types do not match" on both
    # hosts (measured on the test VM) -- the candidates are copied out once with ToArray()
    $candArr = $cands.ToArray()
    $freshArr = @(foreach ($c in $candArr) { if ($c.Fresh) { $c } })
    $stale = ($freshArr.Count -eq 0)
    $pool = @(if ($stale) { $candArr } else { $freshArr })
    $newest = { param($xs) $xa = @($xs); if ($xa.Count -eq 1) { return $xa[0] }; @($xa | Sort-Object @{ Expression = { if ($_.ObservedAt) { $_.ObservedAt } else { [datetime]::MinValue } }; Descending = $true }, @{ Expression = { $_.Rank } })[0] }
    switch ($policy) {
        'any_true' {
            $t = @(foreach ($c in $pool) { if ((ConvertTo-SIBoolOrNull $c.Value) -eq $true) { $c } })
            # Providers: EVERY provider that said true -- the evidence of a risk factor names them all (#464)
            if ($t.Count -gt 0) { $w = & $newest $t; return @{ Value = $true; Provider = $w.Provider; Record = $w.Record; ObservedAt = $w.ObservedAt; Stale = $stale; Providers = @($t | ForEach-Object { [string]$_.Provider } | Select-Object -Unique) } }
            $f = @(foreach ($c in $pool) { if ((ConvertTo-SIBoolOrNull $c.Value) -eq $false) { $c } })
            if ($f.Count -gt 0) { $w = & $newest $f; return @{ Value = $false; Provider = $w.Provider; Record = $w.Record; ObservedAt = $w.ObservedAt; Stale = $stale } }
            return $null
        }
        'union' {
            $list = New-Object System.Collections.Generic.List[object]
            $seenKeys = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            $byRank = $pool; if ($pool.Count -gt 1) { $byRank = @($pool | Sort-Object Rank) }
            foreach ($c in $byRank) {
                foreach ($x in (Get-SIValueList $c.Value)) {
                    $k = if ($x -is [string] -or $x -is [ValueType]) { [string]$x } else { ($x | ConvertTo-Json -Compress -Depth 6) }
                    if ($seenKeys.Add($k)) { $list.Add($x) }
                }
            }
            $w = & $newest $pool
            return @{ Value = $list.ToArray(); Provider = (@($pool | Select-Object -ExpandProperty Provider -Unique) -join ','); Record = $w.Record; ObservedAt = $w.ObservedAt; Stale = $stale }
        }
        { $_ -in 'min', 'max' } {
            # compared by the catalog TYPE: values read back from Log Analytics are text, so the value cannot tell
            $isDate = ([string]$Field.type -eq 'datetime')
            $best = $null; $bestV = $null
            foreach ($c in $cands) {
                $x = $null
                if ($isDate) { $x = ConvertTo-SIUtcOrNull $c.Value } else { $x = ConvertTo-SINumberOrNull $c.Value }
                if ($null -eq $x) { continue }
                if ($null -eq $best -or ($policy -eq 'max' -and $x -gt $bestV) -or ($policy -eq 'min' -and $x -lt $bestV)) { $best = $c; $bestV = $x }
            }
            if ($null -eq $best) { return $null }
            return @{ Value = $best.Value; Provider = $best.Provider; Record = $best.Record; ObservedAt = $best.ObservedAt; Stale = $false }
        }
        default {
            # authority (and anything else that reaches a CI from records): best authority rank, then newest
            if ($stale) { $w = & $newest $pool }
            elseif ($pool.Count -eq 1) { $w = $pool[0] }
            else { $w = @($pool | Sort-Object @{ Expression = { $_.Rank } }, @{ Expression = { if ($_.ObservedAt) { $_.ObservedAt } else { [datetime]::MinValue } }; Descending = $true })[0] }
            return @{ Value = $w.Value; Provider = $w.Provider; Record = $w.Record; ObservedAt = $w.ObservedAt; Stale = $stale }
        }
    }
}

function Get-SICiFieldPlan {
    <#
    .SYNOPSIS  PURE. The catalog fields a CI resolves from its records, in catalog order, each with what New-SICiDocument
               asks of it for every CI: its name, whether it is an identity field, whether it has an origin-specific
               authority (resolution.byOrigin). Read once per set of CIs instead of once per CI and field -- the catalog
               has several hundred fields.
               A field is in the plan when its level is 'both' and it is not computed (a computed field is
               SecurityInsight's own on the CI, never resolved from the records).
    #>
    param([Parameter(Mandatory)]$Catalog)
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($f in @($Catalog.fields)) {
        if ([string]$f.level -ne 'both') { continue }
        if ([string]$f.resolution.policy -eq 'computed') { continue }
        # as Get-SIFieldOriginRule reads it: no byOrigin = no origin rule, whatever the origin
        $bo = $null
        if ($f.resolution) { $bo = Get-SIItemValue $f.resolution 'byOrigin' }
        $plan.Add([pscustomobject]@{ Field = $f; Name = [string]$f.name; Identity = (@($f.classes) -contains 'identity'); ByOrigin = ($null -ne $bo) })
    }
    return $plan.ToArray()   # unrolled: the caller collects with @()
}

function New-SICiDocument {
    <#
    .SYNOPSIS  One CI from its records: id, class, links, lifecycle and every resolved SI field.
    #>
    param(
        [Parameter(Mandatory)][string]$CiId,
        [Parameter(Mandatory)][object[]]$Records,
        [Parameter(Mandatory)]$Catalog,
        [Parameter(Mandatory)][hashtable]$FeedLatest,
        [datetime]$Now = [datetime]::UtcNow,
        [string]$RunId = '',
        # #463 the tenant's one CMDB owner (cmdb | servicenow) -- the catalog's cmdb_owner authority
        [string]$CmdbOwner = 'cmdb',
        # the catalog's resolved fields, read once for a whole set of CIs (Get-SICiFieldPlan -Catalog <the same catalog>);
        # not given, it is read here -- the same result
        [AllowNull()][object[]]$FieldPlan,
        # #406 the lifecycle settings (Get-SICiLifecycleSettings: seen window, grace period per category); not given = the
        # settings in force
        $Lifecycle,
        # what this CI was after the last build: @{ Lifecycle; Since; Reason } (Get-SICiBatchStored) -- none = a first build
        $Previous,
        # 60.5.0d provider -> the time its collection scope changed (Update-SICiScopeChanges)
        [hashtable]$ScopeChangedAt
    )
    if ($null -eq $Lifecycle) { $Lifecycle = Get-SICiLifecycleSettings }
    $ci = [ordered]@{ si_ci_id = $CiId }
    $class = 'identity'; $bestRank = 99
    $cands = New-Object System.Collections.Generic.List[object]
    $links = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Records) {
        $rc = [string](Get-SIItemValue $r 'si_class')
        $rk = Get-SICiClassRank $rc
        if ($rk -lt $bestRank) { $bestRank = $rk; $class = $rc }
        $ls = Get-SIRecordLink -Record $r -FeedLatest $FeedLatest -Now $Now -SeenWithinDays ([int]$Lifecycle.SeenWithinDays) -ScopeChangedAt $ScopeChangedAt
        $state = [string]$ls.State
        $p = [string](Get-SIItemValue $r 'si_provider')
        $key = [string](Get-SIItemValue $r 'si_record_key')
        $native = $key; $i = $key.IndexOf(':'); if ($i -ge 0) { $native = $key.Substring($i + 1) }
        $lo = [pscustomobject][ordered]@{
                provider = $p; type = [string](Get-SIItemValue $r 'si_record_type'); id = $native; record_key = $key
                primary = $false; state = $state; last_seen = (ConvertTo-SIUtcOrNull (Get-SIItemValue $r 'si_source_last_seen'))
            }
        # the evidence of a link that is not active (dates only: it changes with the state, never by itself)
        if ($ls.Reason) { $lo | Add-Member -NotePropertyName 'reason' -NotePropertyValue ([string]$ls.Reason) }
        $links.Add($lo)
        $cands.Add([pscustomobject]@{ Record = $r; Provider = $p; Key = $key; State = $state })
    }
    # primary link per provider: active first, then the newest
    foreach ($grp in ($links | Group-Object provider)) {
        $pick = @($grp.Group | Sort-Object @{ Expression = { if ($_.state -in 'active', 'frozen') { 0 } else { 1 } } }, @{ Expression = { if ($_.last_seen) { $_.last_seen } else { [datetime]::MinValue } }; Descending = $true })[0]
        $pick.primary = $true
    }
    $ci['si_class'] = $class
    $ci['si_collection_time'] = $Now.ToUniversalTime()
    if ($RunId) { $ci['si_run_id'] = $RunId }
    # #546 field authority by identity origin: synchronised from AD vs cloud-only decides which provider is authoritative
    # for the on-premises facts (password age, on-premises sign-in); a field that cannot be decided is listed as unknown
    $candArr = $cands.ToArray()
    $origin = ''
    if ($class -eq 'identity') { $origin = Get-SICiIdentityOrigin -Candidates $candArr; if ($origin) { $ci['si_identity_origin'] = $origin } }
    $unknownFields = New-Object System.Collections.Generic.List[string]
    $resolvedSources = [ordered]@{}
    # THE FIELDS THE RECORDS CARRY AT ALL. A field no record of this CI carries resolves to nothing -- Resolve-SICiField
    # only ever reads the candidates' own value of the field -- so it is not asked for: the catalog has several hundred
    # fields, a CI's records carry a few dozen, and asking for every one was most of the CI build's time on a large tenant
    # (2026-10-12). A name is looked up the way Get-SIItemValue finds it: without case on an object's properties and on a
    # dictionary's keys, and through the dictionary's own Contains.
    $carried = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $dictRecords = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Records) {
        if ($null -eq $r) { continue }
        if ($r -is [System.Collections.IDictionary]) { $dictRecords.Add($r); foreach ($k in $r.Keys) { [void]$carried.Add([string]$k) } }
        else { foreach ($p in $r.PSObject.Properties) { [void]$carried.Add([string]$p.Name) } }
    }
    # a COMPUTED field (si_class, si_collection_time, si_run_id ...) is SecurityInsight's own on the CI -- never
    # resolved from the records, or a record's value would overwrite what the CI build decided (Get-SICiFieldPlan)
    if ($null -eq $FieldPlan) { $FieldPlan = @(Get-SICiFieldPlan -Catalog $Catalog) }
    foreach ($fp in $FieldPlan) {
        $f = $fp.Field
        $fOrigin = ''
        if ($class -eq 'identity' -and $fp.Identity) {
            $fOrigin = $origin
            # (a field without an origin-specific authority is never unknown: Test-SICiFieldUnknown answers false for it)
            if ($fp.ByOrigin -and (Test-SICiFieldUnknown -Field $f -Origin $origin -Candidates $candArr)) { $unknownFields.Add([string]$f.name) }
        }
        $has = $carried.Contains($fp.Name)
        if (-not $has) { foreach ($d in $dictRecords) { if ($d.Contains($fp.Name)) { $has = $true; break } } }
        if (-not $has) { continue }
        $res = Resolve-SICiField -Field $f -Candidates $candArr -Now $Now -CmdbOwner $CmdbOwner -Origin $fOrigin
        if ($null -eq $res) { continue }
        $ci[[string]$f.name] = $res.Value
        $resolvedSources[[string]$f.name] = [ordered]@{ provider = $res.Provider; record = $res.Record; observed_at = $res.ObservedAt; stale = [bool]$res.Stale }
        if ($fOrigin -and $fp.ByOrigin -and $null -ne (Get-SIFieldOriginRule -Field $f -Origin $fOrigin)) { $resolvedSources[[string]$f.name]['origin'] = $fOrigin }
        if ($unknownFields.Contains([string]$f.name)) { $resolvedSources[[string]$f.name]['unknown'] = $true }
        if ($res.Providers -and @($res.Providers).Count -gt 1) { $resolvedSources[[string]$f.name]['providers'] = @($res.Providers) }
        # a CI of ONE record has nothing to disagree with (Get-SICiFieldConflicts compares the other records only)
        if ($candArr.Count -ne 1 -or [string]$candArr[0].Key -ne [string]$res.Record) {
            $conf = Get-SICiFieldConflicts -Field $f -Candidates $candArr -Resolved $res -Now $Now
            if ($conf.Count -gt 0) { $resolvedSources[[string]$f.name]['conflicts'] = $conf }
        }
    }
    if ($unknownFields.Count -gt 0) { $ci['si_unknown_fields'] = $unknownFields.ToArray() }
    $recordLinks = $links.ToArray()
    # AZURE CHILD RESOURCES (owner 2026-10-11, SI-AzureChildren.ps1): every child resource a record of this CI lists
    # (si_child_resources -- a VM extension, a disk, a network interface, a SQL database ...) is a LINKED OBJECT of this CI, so
    # its id leads here (a finding reported on the child lands on its parent CI); a child is never a CI of its own. A child
    # link has no record of its own (record_key '') and takes the state of the record that lists it. In id order.
    $childLinks = New-Object System.Collections.Generic.List[object]
    $childSeen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $candArr) {
        foreach ($ch in (Get-SIValueList (Get-SIItemValue $c.Record 'si_child_resources'))) {
            $chId = ([string](Get-SIItemValue $ch 'id')).Trim().ToLowerInvariant()
            if (-not $chId -or -not $childSeen.Add($chId)) { continue }
            $childLinks.Add([pscustomobject][ordered]@{
                    provider = [string]$c.Provider; type = 'child_resource'; id = $chId; record_key = ''; primary = $false; state = [string]$c.State
                    last_seen = (ConvertTo-SIUtcOrNull (Get-SIItemValue $c.Record 'si_source_last_seen')); resource_type = [string](Get-SIItemValue $ch 'type')
                })
        }
    }
    $linkArr = @($recordLinks) + @($childLinks.ToArray() | Sort-Object { $_.id })
    $ci['si_linked_objects'] = $linkArr
    $ci['si_link_count'] = $linkArr.Count
    $linkField = @{ mde = 'si_link_mde'; entra = 'si_link_entra'; intune = 'si_link_intune'; azure = 'si_link_azure'; eg = 'si_link_eg'; ad = 'si_link_ad'; mdi = 'si_link_mdi'; shodan = 'si_link_shodan'; cmdb = 'si_link_cmdb'; servicenow = 'si_link_servicenow' }
    foreach ($l in $recordLinks) { if ($l.primary -and $linkField.ContainsKey($l.provider)) { $ci[$linkField[$l.provider]] = $l.id } }
    # THE LIFECYCLE (V3-DATA-MODEL 2.5.5, #406 -- SI-CiLifecycle.ps1, one mechanism with the CMDB sync) follows the CI's own
    # records (a child link carries its parent record's state): active when any link is active; not seen within the grace
    # period of the CI's category; retired after it, or at once when every link is gone; a CI whose only current links are
    # frozen keeps what it was. The evidence is on the CI: since when, how many days not seen, and why.
    $life = Get-SICiLifecycle -Links $recordLinks -Category (Get-SICiRetireCategory -Ci $ci -Links $recordLinks) -Settings $Lifecycle -Now $Now -Previous $Previous
    $ci['si_lifecycle'] = [string]$life.Lifecycle
    # (ISO text, seconds: the same text on every host and in the stored document, so "since" never changes a CI by itself)
    if ($null -ne $life.Since) { $ci['si_lifecycle_since'] = ([datetime]$life.Since).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture) }
    if ($life.Reason) { $ci['si_lifecycle_reason'] = [string]$life.Reason }
    if ($life.Lifecycle -ne 'active' -and $null -ne $life.NotSeenDays) { $ci['si_not_seen_days'] = [int]$life.NotSeenDays }
    # #642 A CLOUD RESOURCE'S LAST SEEN. Azure Resource Graph has no "last seen" of a resource (data-model/mappings/azure has no
    # si_last_seen) and the exposure graph gives one only for some nodes, so sidata.Ci.LastSeen stayed empty for every cloud
    # CI (found at a ring 1 install 2026-10-13). A resource is seen when its source lists it: the newest source time of its
    # current (active / frozen) records -- else of any record. Only for cloud resources: an identity or a device keeps the
    # last-seen its source reports (a sign-in, a check-in), never the collection time, or an account that never signs in would
    # look active.
    if ($class -eq 'cloud_resource' -and -not ($ci.Contains('si_last_seen') -and $ci['si_last_seen'])) {
        $pick = $null; $pickT = $null; $pickCur = $false
        foreach ($c in $candArr) {
            $st = ConvertTo-SIUtcOrNull (Get-SIItemValue $c.Record 'si_source_last_seen')
            if ($null -eq $st) { continue }
            $cur = ([string]$c.State -in 'active', 'frozen')
            if ($null -eq $pick -or ($cur -and -not $pickCur) -or ($cur -eq $pickCur -and $st -gt $pickT)) { $pick = $c; $pickT = $st; $pickCur = $cur }
        }
        if ($null -ne $pick) {
            $ci['si_last_seen'] = $pickT
            $resolvedSources['si_last_seen'] = [ordered]@{ provider = [string]$pick.Provider; record = [string]$pick.Key; observed_at = $pickT; stale = (-not $pickCur); from = 'listed_by_source' }
        }
    }
    if ($ci.Contains('si_last_seen') -and $ci['si_last_seen']) {
        $ls = ConvertTo-SIUtcOrNull $ci['si_last_seen']
        if ($ls) { $ci['si_days_inactive'] = [int][Math]::Floor(($Now - $ls).TotalDays) }
    }
    $ci['si_field_sources'] = $resolvedSources
    return $ci
}
