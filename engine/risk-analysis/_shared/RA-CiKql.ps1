#Requires -Version 5.1
<#
    THE CI IN RISK ANALYSIS'S KUSTO (REQUIREMENTS #505, V3-DATA-MODEL 2.10 / 2.19 / 2.21) -- the ONE definition of how a
    report reads its assets from SI_CI_CL. Every report carries one or both blocks below, verbatim, between its markers;
    the engine regenerates them at run time with the install's SI_ActiveStaleDays (the copy in the YAML is the 30-day
    default, so the query also runs pasted into the portal). tests/pester/SIv3-RaReadsCi.Tests.ps1 fails when a report's
    copy differs from what this file generates.

      _ciLink   one row per LINK KEY -- every id of every object linked to a CI (si_linked_objects + the si_link_* primary
                columns), lower-case, no SI prefix -- with the CI's context. A provider finding is tied to its CI with
                `join kind=leftouter (_ciLink) on $left.<provider id> == $right._ciKey`, never on AadDeviceId, SI_AssetId
                or a name. One key = one CI (the newest build wins a key two CIs claim), so the join cannot fan out.
                Columns: _ciKey, si_ci_id, si_class, si_asset_name, si_tier, si_tier_set_by, si_cmdb_id, si_cmdb_name,
                si_cmdb_criticality, si_cmdb_data_sensitivity, si_criticality_factor, si_rf_p, si_rf_c, si_stale_.
                An optional class filter keeps the inlined copy small (the hybrid path inlines it into advanced hunting,
                bucketed on _ciKey -- the report's DeviceKey must be the same provider id for the buckets to align).
      _ciAsset  one row per CI with every SI field Risk Analysis reads ($script:RACiAssetFields) -- for the reports
                whose finding IS a property of the asset (an identity without MFA, a stale account ...). Log Analytics
                only (those reports read no advanced hunting table).

    Both: the CI SET = the CIs with a row in the newest build; a CI's properties = its latest FULL row within the stale
    days (a 'seen' row only says the CI still exists); si_stale_ = no source saw it within the stale days (the newest
    si_last_seen). A table without si_row_kind = every row full.
    si_rf_p / si_rf_c = the ids of the CI's production asset risk factors with impact > 0, by axis
    (data-model/risk-factors.locked.json) -- a report's RF_P_* / RF_C_* for an asset factor is
    `iff(set_has_element(si_rf_p, "<factor id>"), 1, 0)`, never its own provider-column expression.

    KQL rules: no // comment inside an argument list, no colon in a // comment, one `let` per block, no `;` inside it (the
    hybrid pre-fetcher cuts a binding at its first `;`). PowerShell 5.1.
#>

$script:RACiLinkBegin  = '//__SI_CI_LINK_BEGIN__'
$script:RACiLinkEnd    = '//__SI_CI_LINK_END__'
$script:RACiAssetBegin = '//__SI_CI_ASSET_BEGIN__'
$script:RACiAssetEnd   = '//__SI_CI_ASSET_END__'
# #675 _subTierG -- one row per SUBSCRIPTION with the tier of its most critical CI (a CI with any link key under
# /subscriptions/<id>/...), read from SI_CI_CL on its own. It used to be computed from _ciLink, which the hybrid path cuts
# per query slice on _ciKey: a slice then saw only its own share of a subscription's CIs, and a subscription-level row got
# the minimum over that share -- a less critical tier than the subscription has. As its own lookup it is read once per run
# and, keyed on nothing the slices are cut on, copied whole into every slice (a handful of rows: one per subscription).
$script:RACiSubTierBegin = '//__SI_CI_SUBTIER_BEGIN__'
$script:RACiSubTierEnd   = '//__SI_CI_SUBTIER_END__'
# #677 _ciPeer -- the CI of the OTHER asset of a row (the device a user signs in to, the Azure target of a device's path):
# the same CIs and the same "one CI per link key" rule as _ciLink, with its own column names (_peerKey, peer_*). _ciLink is
# cut per query slice on _ciKey, and the slices of these reports are cut on the row's OWN asset -- so the other asset's CI
# row sat in the slice its own key hashes to, and in every other slice the row lost its tier, CMDB values and factors.
# _peerKey is not a key the engine cuts on (Get-SICLBucketKey), so the lookup travels whole while it fits; the reports
# declare it under LookupNeededKeys, so when it does not fit each slice gets only the rows its own rows can match.
$script:RACiPeerBegin = '//__SI_CI_PEER_BEGIN__'
$script:RACiPeerEnd   = '//__SI_CI_PEER_END__'

# The SI fields the asset block carries (name -> catalog type). Every one is in data-model/field-catalog.locked.json and
# in the SI_CI_CL full row (engine/data-model/SI-CiBuildSql.ps1, $script:SICiPostFields) -- the guard test checks both.
$script:RACiAssetFields = [ordered]@{
    si_class = 'string'
    si_asset_name = 'string'
    si_asset_type = 'string'
    si_display_name = 'string'
    si_tier = 'int'
    si_tier_set_by = 'string'
    si_tier_reason = 'string'
    si_cmdb_id = 'string'
    si_cmdb_name = 'string'
    si_cmdb_criticality = 'string'
    si_cmdb_data_sensitivity = 'string'
    si_criticality_factor = 'real'
    si_link_mde = 'string'
    si_link_entra = 'string'
    si_link_azure = 'string'
    si_link_eg = 'string'
    si_link_ad = 'string'
    si_link_intune = 'string'
    si_link_shodan = 'string'
    si_tags = 'dynamic'
    si_hostname = 'string'
    si_hostnames = 'dynamic'
    si_ip_address = 'string'
    si_identity_type = 'string'
    si_upn = 'string'
    si_account_enabled = 'bool'
    si_is_external = 'bool'
    si_external_user_state = 'string'
    si_mfa_registered = 'bool'
    si_created = 'datetime'
    si_last_sign_in = 'datetime'
    si_password_last_changed = 'datetime'
    si_leave_date = 'datetime'
    si_onprem_synced = 'bool'
    # #546 field authority by identity origin: the origin, and the fields the CI build could not decide (a report reads an
    # undecided value as unknown -- null -- never as a finding)
    si_identity_origin = 'string'
    si_unknown_fields = 'dynamic'
    si_org_department = 'string'
    si_country = 'string'
    si_employee_type = 'string'
    si_entra_roles_permanent = 'dynamic'
    si_entra_roles_eligible = 'dynamic'
    si_privilege_tier_permanent = 'int'
    si_privilege_tier_eligible = 'int'
    si_azure_role_assignments = 'dynamic'
    si_app_permissions = 'dynamic'
    si_group_memberships = 'dynamic'
    si_ad_critical_groups = 'dynamic'
    si_custom_security_attributes = 'dynamic'
    si_is_break_glass = 'bool'
    si_sp_type = 'string'
    si_app_id = 'string'
    si_publisher_name = 'string'
    si_publisher_verified = 'bool'
    si_app_owner_org_id = 'string'
    si_is_multitenant_app = 'bool'
    si_is_third_party_multitenant = 'bool'
    si_is_orphan_sp = 'bool'
    si_credential_expiry_days = 'int'
    si_high_risk_permission_grant = 'bool'
    si_owner = 'string'
    si_mdi_risk_state = 'string'
    si_mdi_blast_radius = 'string'
    si_is_sensitive_account = 'bool'
    si_has_leaked_credentials = 'bool'
    si_is_compromised_recently = 'bool'
    si_machine_risk = 'string'
    si_ms_criticality = 'string'
    si_internet_exposed = 'bool'
    si_open_ports = 'dynamic'
    si_open_port_count = 'int'
    si_vulns = 'dynamic'
    si_max_cvss = 'real'
    si_isp = 'string'
    si_org_name = 'string'
    si_os_platform = 'string'
    si_os_version = 'string'
    si_exposure_level = 'string'
    si_is_excluded = 'bool'
    si_excluded_reason = 'string'
    si_is_shadow_admin = 'bool'
    si_is_service_account = 'bool'
    si_password_never_expires = 'bool'
    si_passwordless_only = 'bool'
    si_mdi_investigation_priority_pct = 'int'
    # rich context, identity (one block): the owners with their sign-in names, the credential list and what to do about
    # it (the finding's how-to-fix names the secret, its expiry and its last use), a managed identity's resource, how a
    # role is held, MFA strength, Conditional Access and Identity Protection
    si_owner_upns = 'dynamic'
    # each owner with where they own (service principal / application / both) -- the owner-mismatch report compares the sides
    si_owners = 'dynamic'
    si_credentials = 'dynamic'
    si_credential_fix = 'string'
    si_attached_resource = 'string'
    si_role_paths = 'dynamic'
    si_mfa_strength = 'string'
    si_ca_mfa_enforced = 'bool'
    si_entra_risk_level = 'string'
    # the level inside Tier 0 (1 tenant-wide, 2 on an administrative unit or one object only) in words, and why an
    # account is break-glass
    si_privilege_tier_level = 'int'
    si_privilege_tier_level_text = 'string'
    si_break_glass_reason = 'string'
}

function Get-RACiKqlCast {
    <# PURE. The typed read of one SI_CI_CL column (column_ifexists keeps a report valid before the column's first row). #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Type)
    switch ($Type) {
        'bool'     { return ('tobool(column_ifexists("{0}", bool(null)))' -f $Name) }
        'int'      { return ('toint(column_ifexists("{0}", int(null)))' -f $Name) }
        'real'     { return ('todouble(column_ifexists("{0}", real(null)))' -f $Name) }
        'datetime' { return ('todatetime(column_ifexists("{0}", datetime(null)))' -f $Name) }
        'dynamic'  { return ('todynamic(column_ifexists("{0}", dynamic(null)))' -f $Name) }
        default    { return ('tostring(column_ifexists("{0}", ""))' -f $Name) }
    }
}

function Get-RACiKqlCore {
    <#
        PURE. The shared head of both blocks: the current CIs, each with its latest full row, its liveness and its factor
        ids. -FactorSet (#541): the report's factor set (RA-ScopePreamble.ps1, Get-RAReportFactorSet) -- si_rf_p / si_rf_c
        keep only those factors, so a report is fed exactly the factors that fit its subject. Empty = every factor.
        -FactorNames (owner 2026-10-10, "catalog display names"): factor id -> the catalog's name; si_rf_names_ = the
        names of si_rf_p's factors (the id where the catalog has no name) -- what a report SHOWS; the ids stay for machines.
    #>
    param([int]$StaleDays = 30, [string[]]$Classes = @(), [AllowEmptyCollection()][string[]]$FactorSet = @(), [hashtable]$FactorNames = @{})
    $d = '{0}d' -f $StaleDays
    $cls = ''
    if (@($Classes | Where-Object { $_ }).Count -gt 0) { $cls = "`n        | where tostring(si_class) in (" + ((@($Classes | Where-Object { $_ }) | ForEach-Object { '"' + $_ + '"' }) -join ', ') + ')' }
    $fs = ''
    $set = @($FactorSet | Where-Object { $_ -and [string]$_ -match '^[a-z][a-z0-9_]{0,60}$' } | Sort-Object -Unique)
    if ($set.Count -gt 0) {
        $dyn = 'dynamic([' + (($set | ForEach-Object { '"' + $_ + '"' }) -join ', ') + '])'
        $fs = "`n        | extend si_rf_p = set_intersect(si_rf_p, $dyn), si_rf_c = set_intersect(si_rf_c, $dyn)"
    }
    $names = ConvertTo-RACiNameBag -FactorNames $FactorNames -FactorSet $set
    $fs += "`n        | extend _ciRfNames = $names" +
           "`n        | mv-apply _ciRfN = si_rf_p to typeof(string) on (summarize si_rf_names_ = make_list(iff(isempty(tostring(_ciRfNames[_ciRfN])), _ciRfN, tostring(_ciRfNames[_ciRfN]))))"
    return @"
        SI_CI_CL
        | where TimeGenerated > ago($d)
        | extend _ciId = tostring(si_ci_id), _ciT = todatetime(si_collection_time), _ciKind = tostring(column_ifexists("si_row_kind", ""))
        | where isnotempty(_ciId)
        | summarize _ciBuild = max(_ciT), _ciSeen = max(todatetime(column_ifexists("si_last_seen", datetime(null)))), arg_max(iff(_ciKind == "seen", datetime(1900-01-01), _ciT), *) by _ciId
        | where _ciKind != "seen"
        | where _ciBuild == toscalar(SI_CI_CL | where TimeGenerated > ago($d) | summarize max(todatetime(si_collection_time)))$cls
        | mv-apply _ciRf = todynamic(column_ifexists("si_risk_factors", dynamic([]))) to typeof(dynamic) on (
            summarize si_rf_p = make_set_if(tostring(_ciRf.id), tostring(_ciRf.axis) == "probability" and tostring(_ciRf.stage) in ("production", "") and todouble(_ciRf.impact) > 0),
                      si_rf_c = make_set_if(tostring(_ciRf.id), tostring(_ciRf.axis) == "consequence" and tostring(_ciRf.stage) in ("production", "") and todouble(_ciRf.impact) > 0)
          )$fs
        | extend si_stale_ = isnotnull(_ciSeen) and _ciSeen < ago($d), si_last_seen_ = _ciSeen, si_tags_ = tolower(tostring(column_ifexists("si_tags", dynamic(null))))
"@
}

function Get-RACiKqlBlock {
    <#
    .SYNOPSIS  PURE. One canonical CI block, markers included: -Kind link (_ciLink), asset (_ciAsset), subtier (_subTierG,
               #675) or peer (_ciPeer, #677 -- the other asset's CI of a row sliced on its own asset).
    .PARAMETER Classes         optional si_class filter (device / identity / cloud_resource / public_ip)
    .PARAMETER FactorSet       the report's factor set (#541) -- si_rf_p / si_rf_c restricted to it
    .PARAMETER ScopePredicate  the report's in-scope test of a CI (#541, RA-ScopePreamble.ps1 Get-RAScopeCiPredicate):
                               _ciAsset keeps the CIs it accepts; _ciLink carries it as si_in_scope_ (the report keeps
                               coalesce(si_in_scope_, true) after its join). Empty / 'true' = no scope line.
    #>
    param([Parameter(Mandatory)][ValidateSet('link', 'asset', 'subtier', 'peer')][string]$Kind, [int]$StaleDays = 30, [string[]]$Classes = @(),
          [AllowEmptyCollection()][string[]]$FactorSet = @(), [AllowEmptyString()][string]$ScopePredicate = '', [hashtable]$FactorNames = @{})
    if ($StaleDays -le 0) { $StaleDays = 30 }
    if ($ScopePredicate -match '[;\r\n]') { throw 'a scope predicate may not contain a semicolon or a line break (the hybrid path cuts a CI block at its first semicolon)' }
    if ($Kind -eq 'subtier') {
        # #675: the same CI set and the same "one CI per link key" rule as _ciLink (so the tier is the one an unsliced
        # query gave), restricted to the keys under a subscription, then the most critical tier per subscription. No
        # factor set and no scope line: neither changes a tier.
        $d = '{0}d' -f $StaleDays
        $cls = ''
        if (@($Classes | Where-Object { $_ }).Count -gt 0) { $cls = "`n        | where tostring(si_class) in (" + ((@($Classes | Where-Object { $_ }) | ForEach-Object { '"' + $_ + '"' }) -join ', ') + ')' }
        $keysS = @('si_link_mde', 'si_link_entra', 'si_link_azure', 'si_link_eg', 'si_link_ad', 'si_link_intune') | ForEach-Object { 'tolower(tostring(column_ifexists("{0}", "")))' -f $_ }
        return @"
$($script:RACiSubTierBegin)
    let _subTierG =
        SI_CI_CL
        | where TimeGenerated > ago($d)
        | extend _ciId = tostring(si_ci_id), _ciT = todatetime(si_collection_time), _ciKind = tostring(column_ifexists("si_row_kind", ""))
        | where isnotempty(_ciId)
        | summarize _ciBuild = max(_ciT), arg_max(iff(_ciKind == "seen", datetime(1900-01-01), _ciT), *) by _ciId
        | where _ciKind != "seen"
        | where _ciBuild == toscalar(SI_CI_CL | where TimeGenerated > ago($d) | summarize max(todatetime(si_collection_time)))$cls
        | extend _ciKeys = set_union(extract_all(@'"id"\s*:\s*"([^"]+)"', tolower(tostring(column_ifexists("si_linked_objects", dynamic([]))))), pack_array($($keysS -join ', ')))
        | mv-expand _ciKey = _ciKeys to typeof(string)
        | where _ciKey startswith "/subscriptions/"
        | summarize arg_max(_ciBuild, *) by _ciKey
        | extend _sub = tostring(split(_ciKey, "/")[2])
        | where isnotempty(_sub)
        | summarize Tier_BySub = min(toint(column_ifexists("si_tier", int(null)))) by _sub;
$($script:RACiSubTierEnd)
"@
    }
    $core = Get-RACiKqlCore -StaleDays $StaleDays -Classes $Classes -FactorSet $FactorSet -FactorNames $FactorNames
    $hasScope = ($ScopePredicate -and $ScopePredicate.Trim() -ne 'true')
    if ($Kind -eq 'link') {
        $keys = @('si_link_mde', 'si_link_entra', 'si_link_azure', 'si_link_eg', 'si_link_ad', 'si_link_intune') | ForEach-Object { 'tolower(tostring(column_ifexists("{0}", "")))' -f $_ }
        $scopeLine = ''; $scopeCol = ''
        if ($hasScope) { $scopeLine = "`n        | extend si_in_scope_ = $ScopePredicate"; $scopeCol = ', si_in_scope_' }
        return @"
$($script:RACiLinkBegin)
    let _ciLink =
$core$scopeLine
        | extend _ciKeys = set_union(extract_all(@'"id"\s*:\s*"([^"]+)"', tolower(tostring(column_ifexists("si_linked_objects", dynamic([]))))), pack_array($($keys -join ', ')))
        | mv-expand _ciKey = _ciKeys to typeof(string)
        | where isnotempty(_ciKey)
        | summarize arg_max(_ciBuild, *) by _ciKey
        | project _ciKey, si_ci_id = _ciId, si_class = tostring(si_class), si_asset_name = tostring(si_asset_name),
                  si_tier = toint(column_ifexists("si_tier", int(null))), si_tier_set_by = tostring(column_ifexists("si_tier_set_by", "")),
                  si_cmdb_id = tostring(column_ifexists("si_cmdb_id", "")), si_cmdb_name = tostring(column_ifexists("si_cmdb_name", "")),
                  si_cmdb_criticality = tostring(column_ifexists("si_cmdb_criticality", "")), si_cmdb_data_sensitivity = tostring(column_ifexists("si_cmdb_data_sensitivity", "")),
                  si_criticality_factor = todouble(column_ifexists("si_criticality_factor", real(null))), si_rf_p, si_rf_c, si_rf_names_, si_stale_, si_tags_$scopeCol;
$($script:RACiLinkEnd)
"@
    }
    if ($Kind -eq 'peer') {
        # #677: the link block's CIs and keys, a lean projection under names the slice cut does not key on
        $keys = @('si_link_mde', 'si_link_entra', 'si_link_azure', 'si_link_eg', 'si_link_ad', 'si_link_intune') | ForEach-Object { 'tolower(tostring(column_ifexists("{0}", "")))' -f $_ }
        $scopeLine = ''; $scopeCol = ''
        if ($hasScope) { $scopeLine = "`n        | extend si_in_scope_ = $ScopePredicate"; $scopeCol = ', peer_in_scope = si_in_scope_' }
        return @"
$($script:RACiPeerBegin)
    let _ciPeer =
$core$scopeLine
        | extend _ciKeys = set_union(extract_all(@'"id"\s*:\s*"([^"]+)"', tolower(tostring(column_ifexists("si_linked_objects", dynamic([]))))), pack_array($($keys -join ', ')))
        | mv-expand _ciKey = _ciKeys to typeof(string)
        | where isnotempty(_ciKey)
        | summarize arg_max(_ciBuild, *) by _ciKey
        | project _peerKey = _ciKey, peer_ci_id = _ciId, peer_tier = toint(column_ifexists("si_tier", int(null))),
                  peer_cmdb_id = tostring(column_ifexists("si_cmdb_id", "")), peer_cmdb_name = tostring(column_ifexists("si_cmdb_name", "")),
                  peer_cmdb_criticality = tostring(column_ifexists("si_cmdb_criticality", "")), peer_cmdb_data_sensitivity = tostring(column_ifexists("si_cmdb_data_sensitivity", "")),
                  peer_rf_p = si_rf_p, peer_rf_names = si_rf_names_$scopeCol;
$($script:RACiPeerEnd)
"@
    }
    $cols = New-Object System.Collections.Generic.List[string]
    foreach ($k in $script:RACiAssetFields.Keys) {
        if ($k -eq 'si_class' -or $k -eq 'si_asset_name') { $cols.Add(('{0} = tostring({0})' -f $k)); continue }
        $cols.Add(('{0} = {1}' -f $k, (Get-RACiKqlCast -Name $k -Type ([string]$script:RACiAssetFields[$k]))))
    }
    $proj = New-Object System.Text.StringBuilder
    if ($hasScope) { [void]$proj.AppendLine('        | where ' + $ScopePredicate) }
    $line = '        | project si_ci_id = _ciId'
    foreach ($c in $cols) {
        if (($line.Length + $c.Length + 2) -gt 150) { [void]$proj.AppendLine($line + ','); $line = '                  ' + $c }
        else { $line = $line + ', ' + $c }
    }
    [void]$proj.Append($line + ',' + "`n" + '                  si_rf_p, si_rf_c, si_rf_names_, si_stale_, si_last_seen_, si_tags_;')
    return @"
$($script:RACiAssetBegin)
    let _ciAsset =
$core
$($proj.ToString())
$($script:RACiAssetEnd)
"@
}

function ConvertTo-RACiNameBag {
    <#
        PURE. The factor-name map as a KQL dynamic bag: dynamic({"<id>": "<catalog name>", ...}) -- ids checked, names through
        the escaping string builder rules (no control character; a ';' becomes ',' -- the hybrid path cuts a block at its first
        ';'). Only the report's factors (-FactorSet) when given. Empty = dynamic({}) (the ids show).
    #>
    param([hashtable]$FactorNames = @{}, [AllowEmptyCollection()][string[]]$FactorSet = @())
    $keys = @($FactorNames.Keys | Where-Object { [string]$_ -match '^[a-z][a-z0-9_]{0,60}$' } | Sort-Object)
    if (@($FactorSet).Count -gt 0) { $keys = @($keys | Where-Object { $FactorSet -contains $_ }) }
    $pairs = foreach ($k in $keys) {
        $v = ([string]$FactorNames[$k]) -replace '[\x00-\x1F]', ' ' -replace ';', ','
        if (-not $v.Trim()) { continue }
        '"' + $k + '": "' + $v.Replace('\', '\\').Replace('"', '\"') + '"'
    }
    return ('dynamic({' + (@($pairs) -join ', ') + '})')
}

function Get-RACiBlockClasses {
    <# PURE. The class filter a report's block was written with (so the engine regenerates the same block). #>
    param([string]$Block)
    $m = [regex]::Match([string]$Block, 'where tostring\(si_class\) in \(([^)]*)\)')
    if (-not $m.Success) { return @() }
    return @([regex]::Matches($m.Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
}

function Get-RACiBlockScope {
    <# PURE. The factor set and the scope predicate a block was written with: @{ FactorSet; Predicate } (kept when the block is regenerated without a new scope). #>
    param([string]$Block)
    $fs = @()
    $m = [regex]::Match([string]$Block, 'extend si_rf_p = set_intersect\(si_rf_p, dynamic\(\[([^\]]*)\]\)\)')
    if ($m.Success) { $fs = @([regex]::Matches($m.Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value }) }
    $pred = ''
    $p1 = [regex]::Match([string]$Block, '(?m)^[ \t]*\| extend si_in_scope_ = (?<p>[^\r\n]+?)[ \t]*\r?$')
    $p2 = [regex]::Match([string]$Block, '(?m)^[ \t]*\| where (?<p>[^\r\n]+?)[ \t]*\r?\n[ \t]*\| project si_ci_id = _ciId')
    if ($p1.Success) { $pred = $p1.Groups['p'].Value } elseif ($p2.Success) { $pred = $p2.Groups['p'].Value }
    $names = @{}
    $nm = [regex]::Match([string]$Block, '(?m)\| extend _ciRfNames = dynamic\((?<j>\{[^\r\n]*\})\)[ \t]*\r?$')
    if ($nm.Success) { try { $o = $nm.Groups['j'].Value | ConvertFrom-Json; foreach ($p in $o.PSObject.Properties) { $names[$p.Name] = [string]$p.Value } } catch { $names = @{} } }
    return @{ FactorSet = $fs; Predicate = $pred; FactorNames = $names }
}

function Resolve-RACiBlocks {
    <#
    .SYNOPSIS  Regenerates every CI block in -Query with the install's stale days (SI_ActiveStaleDays, default 30). The
               block's indentation in the report is kept (the YAML copy is indented under its report); a query without
               a block is returned unchanged.
    .PARAMETER Scope  the report's active scope (#541, RA-ScopePreamble.ps1 Get-RAScopeActive): the blocks get its factor
                      set and its in-scope predicate. Without it a block keeps the factor set and predicate it carries.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query, [int]$StaleDays = 0, [hashtable]$Scope)
    if ([string]::IsNullOrEmpty($Query)) { return $Query }
    if ($StaleDays -le 0) {
        $StaleDays = 30
        $d = 0
        if ($global:SI_ActiveStaleDays -and [int]::TryParse(([string]$global:SI_ActiveStaleDays).Trim(), [ref]$d) -and $d -gt 0) { $StaleDays = $d }
    }
    $newFs = $null; $newPred = $null; $newNames = $null
    if ($Scope) {
        $newFs = @($Scope.FactorSet)
        $newNames = @{}; if ($Scope.FactorNames) { $newNames = $Scope.FactorNames }
        if (Get-Command -Name Get-RAScopeCiPredicate -ErrorAction SilentlyContinue) { $newPred = Get-RAScopeCiPredicate -Active $Scope }
    }
    foreach ($kind in 'link', 'asset', 'subtier', 'peer') {
        $b = $script:RACiLinkBegin; $e = $script:RACiLinkEnd
        if ($kind -eq 'asset') { $b = $script:RACiAssetBegin; $e = $script:RACiAssetEnd }
        if ($kind -eq 'subtier') { $b = $script:RACiSubTierBegin; $e = $script:RACiSubTierEnd }
        if ($kind -eq 'peer') { $b = $script:RACiPeerBegin; $e = $script:RACiPeerEnd }
        $rx = '(?ms)^(?<ind>[ \t]*)' + [regex]::Escape($b) + '.*?' + [regex]::Escape($e)
        $Query = [regex]::Replace($Query, $rx, {
                param($m)
                $ind = $m.Groups['ind'].Value
                $old = Get-RACiBlockScope -Block $m.Value
                $fs = $old.FactorSet; $pr = $old.Predicate; $fn = $old.FactorNames
                if ($null -ne $newNames) { $fn = $newNames }
                if ($null -ne $newFs) { $fs = $newFs }
                if ($null -ne $newPred) { $pr = $newPred }
                $fresh = Get-RACiKqlBlock -Kind $kind -StaleDays $StaleDays -Classes (Get-RACiBlockClasses -Block $m.Value) -FactorSet $fs -ScopePredicate $pr -FactorNames $fn
                ConvertTo-RACiIndentedBlock -Block $fresh -Indent $ind
            })
    }
    return $Query
}

function ConvertTo-RACiIndentedBlock {
    <# PURE. A generated block with every line prefixed by -Indent (how it sits inside a YAML |- block). #>
    param([Parameter(Mandatory)][string]$Block, [string]$Indent = '')
    $lines = ($Block -replace "`r", '') -split "`n"
    return (($lines | ForEach-Object { if ($_.Length) { $Indent + $_ } else { $_ } }) -join "`n")
}
