#Requires -Version 5.1
<#
    SecurityInsight RISK-FACTOR CATALOG -- factor groups with their provider links (#458, V3-DATA-MODEL 2.7).

    One catalog of risk factors (data-model/risk-factors.locked.json). Every factor is defined ONCE over SI fields; what
    this file adds is the link back to the providers that can PROVE it:

      proof fields   the SI fields the factor's condition reads, minus the scoping fields (si_identity_type, si_class: they
                     say WHICH assets the factor is about, not whether it holds), plus the fields a conditions-list it uses
                     reads (unsupported_os reads si_os_name through its list)
      providers      per provider (mde, eg, entra, azure, mdi, ad, intune, shodan, ...) the provider fields that fill each
                     proof field -- read from the provider's field mapping (data-model/mappings), so a factor never names a
                     provider field of its own and a provider rename is fixed once, in the mapping
      network        an in_ranges condition is proven by a NETWORK RANGE list (internet_exposed_ranges: DMZ, online landing
                     zones) -- customer data: Community lists.custom.json, Pro / either edition the setting
                     SI_InternetExposedRanges (Merge-SIRiskFactorRanges)
      computed       a field SecurityInsight computes on the CI (si_tier from the enrichment rules, the CMDB criticality level,
                     privilege tiers, finding signals), named with what computes it (the field catalog's description)

    The catalog STORES each factor's providers block (what a person and the Pro pages read); Test-SIRiskFactorProviders
    proves the stored block equals what the mappings say, so the copy can never drift (SIv3-RiskFactorCatalog.Tests).
    Update-SIRiskFactorProviders rewrites it after a mapping change.

    PURE except Update-SIRiskFactorProviders (writes the catalog file). PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Get-SIConditionFields -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-Conditions.ps1') }

$script:SIRiskFactorScopingFields = @('si_identity_type', 'si_class')

function Get-SIRiskFactorConditionLeaves {
    <# PURE. Every leaf condition (field / op / value) of a condition group. #>
    param($Condition)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Condition) { return , $out }
    # kept per condition object (2026-10-16: asked again for every factor of every CI); a copy is handed out
    $cache = $script:SIRiskFactorLeavesCache
    if ($null -eq $cache) { $cache = New-Object 'System.Runtime.CompilerServices.ConditionalWeakTable[object,object]'; $script:SIRiskFactorLeavesCache = $cache }
    $hit = $null
    if ($Condition -isnot [string] -and $Condition -isnot [ValueType] -and $cache.TryGetValue($Condition, [ref]$hit)) { foreach ($l in $hit) { $out.Add($l) }; return , $out }
    $done = $false
    foreach ($k in 'all', 'any') {
        $hasK = ($Condition -is [System.Collections.IDictionary] -and $Condition.Contains($k)) -or ($Condition.PSObject.Properties[$k])
        if ($hasK) { foreach ($c in (Get-SIValueList (Get-SIItemValue $Condition $k))) { foreach ($l in (Get-SIRiskFactorConditionLeaves $c)) { $out.Add($l) } }; $done = $true; break }
    }
    if (-not $done -and (Get-SIItemValue $Condition 'field')) { $out.Add($Condition) }
    if ($Condition -isnot [string] -and $Condition -isnot [ValueType]) { try { $cache.Add($Condition, $out.ToArray()) } catch { } }
    return , $out
}

function Get-SIRiskFactorProofFields {
    <# PURE. The SI fields that prove a factor (see the header), in condition order, unique. #>
    param([Parameter(Mandatory)]$Factor, [hashtable]$Lists = @{})
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($leaf in (Get-SIRiskFactorConditionLeaves $Factor.when)) {
        $f = [string](Get-SIItemValue $leaf 'field'); $op = [string](Get-SIItemValue $leaf 'op'); $v = Get-SIItemValue $leaf 'value'
        $fields = @($f)
        if ($op -eq 'in_list' -and $v -is [string] -and $Lists.ContainsKey($v) -and [string](Get-SIItemValue $Lists[$v] 'type') -eq 'conditions') {
            $fields = @()
            foreach ($e in (Get-SIValueList (Get-SIItemValue $Lists[$v] 'entries'))) { foreach ($x in (Get-SIConditionFields (Get-SIItemValue $e 'when'))) { $fields += $x } }
        }
        foreach ($x in $fields) { if ($x -and $script:SIRiskFactorScopingFields -notcontains $x -and -not $out.Contains($x)) { $out.Add($x) } }
    }
    return , $out
}

function Get-SIRiskFactorProviderLinks {
    <#
    .SYNOPSIS  PURE. A factor's provider links from the data model: [ordered]@{ <provider> = @( @{ siField; sources; recordTypes } ) }
               plus 'network' (in_ranges lists) and 'rules' (si_tier). Providers in name order, items in mapping order.
    #>
    param([Parameter(Mandatory)]$Factor, [Parameter(Mandatory)]$Model)
    $lists = @{}; foreach ($l in @($Model['lists'].lists)) { if ($l) { $lists[[string]$l.id] = $l } }
    $proof = Get-SIRiskFactorProofFields -Factor $Factor -Lists $lists
    $out = [ordered]@{}
    foreach ($prov in @($Model.Mappings.Keys | Sort-Object)) {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($m in @($Model.Mappings[$prov].mappings)) {
            if ($null -eq $m -or -not $proof.Contains([string]$m.field)) { continue }
            $items.Add([ordered]@{ siField = [string]$m.field; sources = @(@($m.sources) | ForEach-Object { [string]$_ }); recordTypes = @(@($m.recordTypes) | ForEach-Object { [string]$_ }) })
        }
        if ($items.Count -gt 0) { $out[[string]$prov] = $items.ToArray() }
    }
    $net = New-Object System.Collections.Generic.List[object]
    foreach ($leaf in (Get-SIRiskFactorConditionLeaves $Factor.when)) {
        if ([string](Get-SIItemValue $leaf 'op') -eq 'in_ranges') { $net.Add([ordered]@{ siField = [string]$leaf.field; list = [string]$leaf.value; setting = 'SI_InternetExposedRanges' }) }
    }
    if ($net.Count -gt 0) { $out['network'] = $net.ToArray() }
    # fields SecurityInsight computes on the CI itself (tier from the rules, CMDB criticality level, privilege tiers,
    # finding signals): named with what computes them, from the field catalog
    $comp = New-Object System.Collections.Generic.List[object]
    foreach ($pf in $proof) {
        $fd = @($Model['field-catalog'].fields | Where-Object { $_ -and [string]$_.name -eq $pf })[0]
        if ($fd -and [string]$fd.resolution.policy -eq 'computed') { $comp.Add([ordered]@{ siField = $pf; sources = @([string]$fd.description) }) }
    }
    if ($comp.Count -gt 0) { $out['computed'] = $comp.ToArray() }
    return $out
}

function Test-SIRiskFactorProviders {
    <#
    .SYNOPSIS  PURE. Problems where a catalog factor's stored providers block differs from its derived provider links
               (empty = in step). Only catalog-evaluated factors are checked; a factor without a providers block is a problem.
    #>
    param([Parameter(Mandatory)]$Model)
    $p = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($Model['risk-factors'].factors)) {
        if ($null -eq $f -or [string]$f.evaluatedBy -ne 'catalog') { continue }
        $want = (Get-SIRiskFactorProviderLinks -Factor $f -Model $Model | ConvertTo-Json -Compress -Depth 8)
        $haveObj = Get-SIItemValue $f 'providers'
        if ($null -eq $haveObj) { $p.Add("risk-factors/$($f.id): no providers block"); continue }
        $have = ($haveObj | ConvertTo-Json -Compress -Depth 8)
        if ($have -ne $want) { $p.Add("risk-factors/$($f.id): the providers block is not what the mappings say -- run Update-SIRiskFactorProviders") }
        $comb = [string](Get-SIItemValue $f 'combine')
        $top = 'all'; if (($f.when -is [System.Collections.IDictionary] -and $f.when.Contains('any')) -or $f.when.PSObject.Properties['any']) { $top = 'any' }
        if ($comb -ne $top) { $p.Add("risk-factors/$($f.id): combine '$comb' but its condition is '$top'") }
        if (-not [string](Get-SIItemValue $f 'description')) { $p.Add("risk-factors/$($f.id): no description") }
    }
    return , $p
}

function Get-SIRiskFactorCiColumns {
    <# PURE. The factors that get their own SI_CI_CL column (si_rf_<id>): catalog asset factors marked ciColumn. #>
    param([Parameter(Mandatory)]$Factors)
    # a loop, not a pipeline: it runs for every CI of the build
    @(foreach ($f in @($Factors.factors)) { if ($f -and [string]$f.appliesTo -eq 'asset' -and [string]$f.evaluatedBy -eq 'catalog' -and (ConvertTo-SIBoolOrNull (Get-SIItemValue $f 'ciColumn')) -eq $true) { [string]$f.id } })
}

function Merge-SIRiskFactorRanges {
    <#
    .SYNOPSIS  PURE. The condition context's lists with the customer's network ranges added: SI_InternetExposedRanges (a Pro
               database setting; Community may set it in its custom file, or fill lists.custom.json) is appended to the
               internet_exposed_ranges list. A value that is not an IPv4 / IPv6 CIDR or address is left out.
    #>
    param([hashtable]$Lists = @{}, $Setting = $global:SI_InternetExposedRanges)
    $extra = New-Object System.Collections.Generic.List[string]
    foreach ($v in @($Setting)) {
        foreach ($s in ([string]$v -split '[,;\s]+')) {
            $t = $s.Trim(); if (-not $t) { continue }
            $ip = $t; $bits = $null; $i = $t.IndexOf('/'); if ($i -gt 0) { $ip = $t.Substring(0, $i); $bits = $t.Substring($i + 1) }
            $a = $null
            if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$a)) { continue }
            if ($null -ne $bits) { $n = 0; if (-not [int]::TryParse($bits, [ref]$n) -or $n -lt 0 -or $n -gt 128) { continue } }
            if (-not $extra.Contains($t)) { $extra.Add($t) }
        }
    }
    if ($extra.Count -eq 0) { return $Lists }
    $out = @{}; foreach ($k in $Lists.Keys) { $out[$k] = $Lists[$k] }
    $vals = New-Object System.Collections.Generic.List[object]
    if ($out.ContainsKey('internet_exposed_ranges')) { foreach ($x in (Get-SIValueList (Get-SIItemValue $out['internet_exposed_ranges'] 'values'))) { $vals.Add($x) } }
    foreach ($x in $extra) { if (-not $vals.Contains($x)) { $vals.Add($x) } }
    $out['internet_exposed_ranges'] = [pscustomobject]@{ id = 'internet_exposed_ranges'; type = 'ranges'; values = $vals.ToArray() }
    return $out
}

function Update-SIRiskFactorProviders {
    <#
    .SYNOPSIS  Rewrites every catalog factor's providers block from the mappings (vendor tool, after a mapping change).
               Each factor stays on its own lines; only the "providers" line is replaced or inserted.
    #>
    param([string]$Root)
    . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1')
    $Root = Get-SIDataModelRoot $Root
    $model = Get-SIDataModel -Root $Root
    $path = Join-Path $Root 'risk-factors.locked.json'
    $text = [System.IO.File]::ReadAllText($path)
    $nl = "`n"; if ($text.Contains("`r`n")) { $nl = "`r`n" }
    foreach ($f in @($model['risk-factors'].factors)) {
        if ([string]$f.evaluatedBy -ne 'catalog') { continue }
        $json = (Get-SIRiskFactorProviderLinks -Factor $f -Model $model | ConvertTo-Json -Compress -Depth 8)
        $line = '      "providers": ' + $json + ','
        $idRx = '(?m)^(\s*\{ "id": "' + [regex]::Escape([string]$f.id) + '",[^\r\n]*\r?\n)'
        $m = [regex]::Match($text, $idRx)
        if (-not $m.Success) { throw "factor $($f.id): its first line was not found" }
        $after = $text.Substring($m.Index + $m.Length)
        $pm = [regex]::Match($after, '^      "providers": [^\r\n]*\r?\n')
        if ($pm.Success) { $text = $text.Substring(0, $m.Index + $m.Length) + $line + $nl + $after.Substring($pm.Length) }
        else { $text = $text.Substring(0, $m.Index + $m.Length) + $line + $nl + $after }
    }
    [System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
}

function Add-SICiRiskFactorEvidence {
    <#
    .SYNOPSIS  PURE. #464 -- the catalog's factors PER CI, with their evidence, after Invoke-SICiRiskFactors evaluated them:
                 * every si_risk_factors entry gets 'evidence' (one item per provider that proves it: provider, SI field,
                   the provider fields of its mapping, the record, stale) and 'by' (those providers)
                 * de-duplicated across providers: ONE entry per factor, however many providers prove it
                 * si_rf_<id> = true / false for every factor the catalog marks ciColumn, si_rf_count = the factors that
                   count (production, impact > 0) -- the SI_CI_CL columns Risk Analysis can read without parsing JSON
               Evidence comes from si_field_sources (the CI build's source of truth per field); for a risk boolean resolved
               any-true it lists EVERY provider that said true (si_field_sources.<field>.providers). A computed field (si_tier)
               names what computed it; an address in a network range names the range list.
    #>
    param([Parameter(Mandatory)]$Ci, [Parameter(Mandatory)]$Factors, [hashtable]$Lists = @{},
          # read once for a set of CIs (New-SICiRiskFactorPlan): the factors by id and the factor columns; else read here
          [hashtable]$ById, [AllowNull()][AllowEmptyCollection()][string[]]$CiColumns)
    $byId = $ById
    if ($null -eq $byId) { $byId = @{}; foreach ($f in @($Factors.factors)) { if ($f) { $byId[[string]$f.id] = $f } } }
    $src = Get-SIItemValue $Ci 'si_field_sources'
    $count = 0
    $present = @{}
    foreach ($e in @($Ci['si_risk_factors'])) {
        if ($null -eq $e) { continue }
        $id = [string](Get-SIItemValue $e 'id')
        $f = $byId[$id]
        $ev = New-Object System.Collections.Generic.List[object]
        if ($f) {
            $provBlock = Get-SIItemValue $f 'providers'
            # an ANY factor: only the fields whose own condition holds are its evidence (an address outside every range
            # proves nothing); fields read through a conditions list always count
            $isAny = (($f.when -is [System.Collections.IDictionary] -and $f.when.Contains('any')) -or $f.when.PSObject.Properties['any'])
            $holds = @{}; $leafFields = @{}
            foreach ($leaf in (Get-SIRiskFactorConditionLeaves $f.when)) {
                $lf = [string]$leaf.field; $leafFields[$lf] = $true
                if ([string](Get-SIItemValue $leaf 'op') -eq 'in_list') { continue }
                $ok = $false; try { $ok = Test-SICondition -Condition $leaf -Item $Ci -Context @{ Lists = $Lists } } catch { $ok = $false }
                if ($ok) { $holds[$lf] = $true }
            }
            foreach ($field in (Get-SIRiskFactorProofFields -Factor $f -Lists $Lists)) {
                if ($isAny -and $leafFields.ContainsKey($field) -and -not $holds.ContainsKey($field)) { continue }
                $s = Get-SIItemValue $src $field
                $val = Get-SIItemValue $Ci $field
                if ($null -eq $s -and (Test-SIValueEmpty $val) -and -not ($val -is [bool])) { continue }
                $provs = @()
                if ($s) { $provs = (Get-SIValueList (Get-SIItemValue $s 'providers')).ToArray(); if ($provs.Count -eq 0 -and (Get-SIItemValue $s 'provider')) { $provs = @(([string](Get-SIItemValue $s 'provider')) -split ',' | Where-Object { $_ }) } }
                if ($provs.Count -eq 0) {
                    $why = ''; if ($field -eq 'si_tier') { $why = [string](Get-SIItemValue $Ci 'si_tier_reason') }
                    $ev.Add([ordered]@{ provider = 'computed'; field = $field; reason = $why }); continue
                }
                foreach ($pv in $provs) {
                    $pfs = @()
                    if ($provBlock) { foreach ($it in (Get-SIValueList (Get-SIItemValue $provBlock ([string]$pv)))) { if ([string](Get-SIItemValue $it 'siField') -eq $field) { $pfs += (Get-SIValueList (Get-SIItemValue $it 'sources')).ToArray() } } }
                    $rec = $null; if ($s -and [string](Get-SIItemValue $s 'provider') -eq [string]$pv) { $rec = Get-SIItemValue $s 'record' }
                    # no observed_at: it moves every build and would make every CI "changed" (the build sends only changed CIs)
                    $ev.Add([ordered]@{ provider = [string]$pv; field = $field; providerFields = @($pfs | Select-Object -Unique); record = $rec; stale = $(if ($s) { [bool](Get-SIItemValue $s 'stale') } else { $false }) })
                }
            }
            foreach ($leaf in (Get-SIRiskFactorConditionLeaves $f.when)) {
                if ([string](Get-SIItemValue $leaf 'op') -ne 'in_ranges') { continue }
                $one = [ordered]@{ field = [string]$leaf.field; op = 'in_ranges'; value = $leaf.value }
                $hit = $false; try { $hit = Test-SICondition -Condition $one -Item $Ci -Context @{ Lists = $Lists } } catch { $hit = $false }
                if ($hit) { $ev.Add([ordered]@{ provider = 'network'; field = [string]$leaf.field; list = [string]$leaf.value }) }
            }
        }
        if ($e -is [System.Collections.IDictionary]) { $e['evidence'] = $ev.ToArray(); $e['by'] = @($ev | ForEach-Object { $_.provider } | Select-Object -Unique) }
        else { $e | Add-Member -NotePropertyName evidence -NotePropertyValue $ev.ToArray() -Force; $e | Add-Member -NotePropertyName by -NotePropertyValue @($ev | ForEach-Object { $_.provider } | Select-Object -Unique) -Force }
        $imp = ConvertTo-SINumberOrNull (Get-SIItemValue $e 'impact')
        if ($null -ne $imp -and $imp -gt 0) { $count++; $present[$id] = $true }
    }
    # #546 a factor the CI could not decide (si_rf_unknown) is NULL in its column -- unknown, never false, never true
    $unk = @(foreach ($x in @(Get-SIItemValue $Ci 'si_rf_unknown')) { if ($x) { [string]$x } })
    if ($null -eq $CiColumns) { $CiColumns = @(Get-SIRiskFactorCiColumns -Factors $Factors) }
    foreach ($cid in $CiColumns) {
        if ($unk -contains $cid -and -not $present.ContainsKey($cid)) { $Ci['si_rf_' + $cid] = $null } else { $Ci['si_rf_' + $cid] = [bool]$present.ContainsKey($cid) }
    }
    $Ci['si_rf_count'] = $count
    return $Ci
}
function Add-SICiUnknownFactorCounts {
    <# PURE. #546 -- adds each CI's undecided factors (si_rf_unknown) to -Counts (factor id -> CIs). Returns -Counts. #>
    param([Parameter(Mandatory)][hashtable]$Counts, [AllowEmptyCollection()][object[]]$Cis = @())
    foreach ($c in $Cis) {
        if ($null -eq $c) { continue }
        foreach ($id in @(Get-SIItemValue $c 'si_rf_unknown')) { if ($id) { $k = [string]$id; if ($Counts.ContainsKey($k)) { $Counts[$k]++ } else { $Counts[$k] = 1 } } }
    }
    return $Counts
}

function Format-SICiUnknownFactorLine {
    <# PURE. #546 -- one plain run-log line: the factors the CIs could not decide (not counted as findings). '' when none. #>
    param([hashtable]$Counts = @{})
    if ($null -eq $Counts -or $Counts.Count -eq 0) { return '' }
    $parts = @($Counts.Keys | Sort-Object | ForEach-Object { '{0} {1}' -f $_, $Counts[$_] })
    return ('CIs: risk factors that could not be decided -- the value is unknown, so they are NOT findings (CIs per factor): {0}' -f ($parts -join ', '))
}

function Test-SIRiskFactorRules {
    <#
    .SYNOPSIS  PURE. #527 (5)-(7): the rules every risk factor (shipped or a customer's) must keep. Returns problems; empty = valid.
                 * exactly ONE scope: appliesTo is 'asset' (the asset's exposure, hygiene, importance) or 'finding' (extra
                   about the recommendation / vulnerability) -- never none, never both
                 * NO TIER: a condition never reads si_tier (tier is its own dimension: the risk index's asset base, #559)
                 * SI FIELDS ONLY: every field a condition reads (and every field of a conditions-list it uses) is an SI field
                   (si_*), and no value is a raw provider path (node.NodeProperties.rawData..., identity.BlastRadius,
                   ci.u_data_sensitivity) -- a renamed or new source field is a MAPPING change, never a factor change
    #>
    param([Parameter(Mandatory)]$Model)
    $p = New-Object System.Collections.Generic.List[string]
    $lists = @{}; foreach ($l in @($Model['lists'].lists)) { if ($l) { $lists[[string]$l.id] = $l } }
    foreach ($f in @($Model['risk-factors'].factors)) { foreach ($x in (Test-SIRiskFactorItem -Factor $f -Lists $lists)) { $p.Add($x) } }
    return , $p
}

# ================================================================================================================
# #559 RISK FACTOR MODEL V2 -- every factor: shortName, name (description), appliesTo, group, class, impact 1-5, state
# ================================================================================================================
$script:SIRiskFactorGroups = @('Exposure', 'Device health', 'Identity', 'Privilege', 'Apps', 'Importance', 'Exploitability', 'Impact', 'Severity', 'Lifecycle')

function Get-SIRiskFactorClass {
    <# PURE. 'builtin' or 'optional'. A factor WITHOUT a class is treated as builtin -- the contract the web app is built
       against (it reads a class-less factor as built-in), so the engine and the GUI never disagree; every shipped factor
       carries its class explicitly, and a customer's own factor should say 'optional' to be switchable. #>
    param($Factor)
    if ([string](Get-SIItemValue $Factor 'class') -eq 'optional') { return 'optional' }
    return 'builtin'
}

function Get-SIRiskFactorState {
    <#
    .SYNOPSIS  PURE. #559 the factor's state as the engine applies it: 'enabled' or 'disabled'.
                 * a BUILT-IN factor is always enabled -- a stored 'disabled' is refused by the validation and the web app,
                   and ignored here (the run-start check says so, Resolve-SIRiskFactorBuiltinState)
                 * state 'disabled' -> disabled; no state: the pre-v2 stage decides (not_used / testing -> disabled, so an
                   old customer override that switched a factor off stays off), else enabled
    #>
    param($Factor)
    if ($null -eq $Factor) { return 'disabled' }
    if ((Get-SIRiskFactorClass $Factor) -eq 'builtin') { return 'enabled' }
    $st = ([string](Get-SIItemValue $Factor 'state')).Trim().ToLowerInvariant()
    if ($st -eq 'disabled') { return 'disabled' }
    if ($st -eq 'enabled') { return 'enabled' }
    $stage = ([string](Get-SIItemValue $Factor 'stage')).Trim().ToLowerInvariant()
    if ($stage -in 'not_used', 'testing') { return 'disabled' }
    return 'enabled'
}

function Test-SIRiskFactorEnabled { param($Factor) return ((Get-SIRiskFactorState $Factor) -eq 'enabled') }

function Get-SIRiskFactorSide {
    <# PURE. #559 the side of the score a factor adds to: 'asset' (appliesTo asset) or 'vulnerability' (appliesTo finding). #>
    param($Factor)
    if ([string](Get-SIItemValue $Factor 'appliesTo') -eq 'finding') { return 'vulnerability' }
    return 'asset'
}

function Get-SIRiskFactorImpact {
    <# PURE. #559 what an ENABLED factor adds to its side: its impact, 1..5 (a value outside is held to the range; not a
       number = 1). A disabled factor adds 0. #>
    param($Factor)
    if (-not (Test-SIRiskFactorEnabled $Factor)) { return 0 }
    $n = ConvertTo-SINumberOrNull (Get-SIItemValue $Factor 'impact')
    if ($null -eq $n) { return 1 }
    if ($n -lt 1) { return 1 }
    if ($n -gt 5) { return 5 }
    return [int][Math]::Round($n)
}

function Get-SIRiskFactorShortName {
    <# PURE. The name reports show: shortName, else the description (name), else the id. #>
    param($Factor)
    $s = ([string](Get-SIItemValue $Factor 'shortName')).Trim(); if ($s) { return $s }
    $n = ([string](Get-SIItemValue $Factor 'name')).Trim(); if ($n) { return $n }
    return [string](Get-SIItemValue $Factor 'id')
}

function Resolve-SIRiskFactorBuiltinState {
    <#
    .SYNOPSIS  PURE. #558 / #559 the run-start check: a built-in factor is never switched off. Returns @{ Factors (the
               factors, a built-in one with state 'enabled' whatever was stored); Lines (one plain run-log line per built-in
               factor a customer override tried to disable -- empty when none) }.
    #>
    param([AllowEmptyCollection()][object[]]$Factors = @())
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($f in $Factors) {
        if ($null -eq $f -or (Get-SIRiskFactorClass $f) -ne 'builtin') { continue }
        $st = ([string](Get-SIItemValue $f 'state')).Trim().ToLowerInvariant()
        $stage = ([string](Get-SIItemValue $f 'stage')).Trim().ToLowerInvariant()
        if ($st -eq 'disabled' -or ($st -eq '' -and $stage -in 'not_used', 'testing')) {
            $lines.Add(("Risk factor {0} ({1}) is built-in and cannot be switched off -- it stays enabled. Lower its impact instead." -f (Get-SIRiskFactorShortName $f), [string]$f.id))
            if ($f -is [System.Collections.IDictionary]) { $f['state'] = 'enabled' } else { $f | Add-Member -NotePropertyName state -NotePropertyValue 'enabled' -Force }
        }
    }
    return @{ Factors = $Factors; Lines = $lines.ToArray() }
}

function Get-SIRiskFactorLegend {
    <#
    .SYNOPSIS  PURE. #558 / #559 the "Risk factors" legend every Excel export (a sheet) and every PDF (an appendix) carries:
               one row per factor -- ShortName, Description, AppliesTo ("Asset" / "Vulnerability"), Impact, Class, Group,
               State, Id -- asset factors first, then vulnerability factors, each by group then short name. Disabled factors
               are listed (State says so, Impact 0) unless -EnabledOnly.
    #>
    param([AllowEmptyCollection()][object[]]$Factors = @(), [switch]$EnabledOnly)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($f in $Factors) {
        if ($null -eq $f -or -not (Get-SIItemValue $f 'id')) { continue }
        $en = Test-SIRiskFactorEnabled $f
        if ($EnabledOnly -and -not $en) { continue }
        $side = Get-SIRiskFactorSide $f
        $desc = ([string](Get-SIItemValue $f 'name')).Trim(); if (-not $desc) { $desc = ([string](Get-SIItemValue $f 'description')).Trim() }
        $rows.Add([pscustomobject][ordered]@{
                ShortName   = (Get-SIRiskFactorShortName $f)
                Description = $desc
                AppliesTo   = $(if ($side -eq 'vulnerability') { 'Vulnerability' } else { 'Asset' })
                Impact      = (Get-SIRiskFactorImpact $f)
                Class       = $(if ((Get-SIRiskFactorClass $f) -eq 'builtin') { 'Built-in' } else { 'Optional' })
                Group       = [string](Get-SIItemValue $f 'group')
                State       = $(if ($en) { 'Enabled' } else { 'Disabled' })
                Id          = [string](Get-SIItemValue $f 'id')
            })
    }
    $gIdx = @{}; for ($i = 0; $i -lt $script:SIRiskFactorGroups.Count; $i++) { $gIdx[$script:SIRiskFactorGroups[$i]] = $i }
    $sorted = @($rows | Sort-Object -Property @{ Expression = { if ($_.AppliesTo -eq 'Asset') { 0 } else { 1 } } }, @{ Expression = { if ($gIdx.ContainsKey($_.Group)) { $gIdx[$_.Group] } else { 99 } } }, ShortName)
    return , $sorted
}

function Test-SIRiskFactorModelV2 {
    <#
    .SYNOPSIS  PURE. #559 the v2 fields of ONE factor. Returns problems; empty = valid.
                 shortName  PascalCase letters and digits, at most 24 characters, no editable number: a factor whose criteria
                            carry a threshold (days, a count) has no digit in its short name (EnabledNoSignInStale, not
                            NoSignIn90d); a fixed fact may (CVSS9Plus)
                 name       the description the GUI shows (not empty)
                 group      one of the ten groups
                 class      builtin | optional (a customer's own factor may leave it out: optional)
                 impact     a whole number 1..5
                 state      enabled | disabled; a builtin factor is never disabled
    #>
    param($Factor)
    $p = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Factor) { return $p.ToArray() }
    $id = [string](Get-SIItemValue $Factor 'id')
    $sn = [string](Get-SIItemValue $Factor 'shortName')
    if ($sn -cnotmatch '^[A-Z][A-Za-z0-9]{1,23}$') { $p.Add("risk-factors/${id}: shortName '$sn' must be PascalCase letters / digits, 2..24 characters (e.g. InternetExposed)") }
    else {
        $cr = Get-SIItemValue $Factor 'criteria'
        if ($cr -and @('threshold', 'range') -contains [string](Get-SIItemValue $cr 'kind') -and $sn -match '\d') { $p.Add("risk-factors/${id}: shortName '$sn' carries a number but the factor's number is editable (criteria) -- name what it means, not the number") }
    }
    if (-not ([string](Get-SIItemValue $Factor 'name')).Trim()) { $p.Add("risk-factors/${id}: no name (the description the GUI shows)") }
    $g = [string](Get-SIItemValue $Factor 'group')
    if ($script:SIRiskFactorGroups -cnotcontains $g) { $p.Add("risk-factors/${id}: group '$g' ($($script:SIRiskFactorGroups -join ', '))") }
    $cl = Get-SIItemValue $Factor 'class'
    if ($null -ne $cl -and @('builtin', 'optional') -cnotcontains [string]$cl) { $p.Add("risk-factors/${id}: class '$cl' (builtin | optional)") }
    $imp = ConvertTo-SINumberOrNull (Get-SIItemValue $Factor 'impact')
    if ($null -eq $imp -or $imp -lt 1 -or $imp -gt 5 -or $imp -ne [Math]::Floor($imp)) { $p.Add("risk-factors/${id}: impact '$(Get-SIItemValue $Factor 'impact')' must be a whole number 1..5 (very low .. very high)") }
    $st = [string](Get-SIItemValue $Factor 'state')
    if ($st -and @('enabled', 'disabled') -cnotcontains $st) { $p.Add("risk-factors/${id}: state '$st' (enabled | disabled)") }
    if ((Get-SIRiskFactorClass $Factor) -eq 'builtin' -and $st -eq 'disabled') { $p.Add("risk-factors/${id}: a built-in factor cannot be disabled -- lower its impact instead (a factor without a class is built-in)") }
    return $p.ToArray()
}

# ================================================================================================================
# #559 break glass naming patterns -- the data-model list break_glass_patterns (type values): glob patterns (* ?) over
# letters, digits, space and . _ @ -; a pattern of wildcards only is refused (it would make everyone break-glass).
# The web app validates the same rule (the contract both sides are built against).
# ================================================================================================================
function Test-SIBreakGlassPattern {
    <# PURE. Problems with ONE break-glass glob pattern; empty = valid. #>
    param([AllowNull()][AllowEmptyString()][string]$Pattern)
    $p = New-Object System.Collections.Generic.List[string]
    $s = [string]$Pattern
    if ($s -cnotmatch '^[A-Za-z0-9 ._@*?-]{1,128}$') { $p.Add("lists/break_glass_patterns: '$s' -- a pattern is letters, digits, space, . _ @ - and the wildcards * ?, at most 128 characters") }
    elseif ($s -match '^[\s*?]+$') { $p.Add("lists/break_glass_patterns: '$s' is wildcards only -- it would make every identity break-glass") }
    return $p.ToArray()
}

function Test-SIRiskRatingBands {
    <# PURE. The risk_rating_bands list of a model: type values, exactly three whole numbers > 0, strictly descending
       (Critical, High, Moderate thresholds). Empty = valid (no list: the engine's built-in 50 / 30 / 15). #>
    param([Parameter(Mandatory)]$Model)
    $p = New-Object System.Collections.Generic.List[string]
    $l = @(@($Model['lists'].lists) | Where-Object { $_ -and [string]$_.id -eq 'risk_rating_bands' })
    if ($l.Count -eq 0) { return $p.ToArray() }
    if ([string]$l[0].type -ne 'values') { $p.Add("lists/risk_rating_bands: type '$($l[0].type)' -- it is a values list of three numbers") }
    $v = @(@(Get-SIItemValue $l[0] 'values') | ForEach-Object { ConvertTo-SINumberOrNull $_ })
    $ok = ($v.Count -eq 3) -and (@($v | Where-Object { $null -eq $_ -or $_ -le 0 -or $_ -ne [Math]::Floor($_) }).Count -eq 0)
    if ($ok) { $ok = ($v[0] -gt $v[1]) -and ($v[1] -gt $v[2]) }
    if (-not $ok) { $p.Add("lists/risk_rating_bands: the values must be three whole numbers above 0, highest first (Critical, High, Moderate) -- has: $(ConvertTo-Json -InputObject @(Get-SIItemValue $l[0] 'values') -Compress)") }
    return $p.ToArray()
}

function Test-SIBreakGlassPatterns {
    <# PURE. The break_glass_patterns list of a model: type values, every value a valid pattern. Empty = valid (no list too). #>
    param([Parameter(Mandatory)]$Model)
    $p = New-Object System.Collections.Generic.List[string]
    $l = @(@($Model['lists'].lists) | Where-Object { $_ -and [string]$_.id -eq 'break_glass_patterns' })
    if ($l.Count -eq 0) { return $p.ToArray() }
    if ([string]$l[0].type -ne 'values') { $p.Add("lists/break_glass_patterns: type '$($l[0].type)' -- it is a values list of glob patterns") }
    foreach ($v in @(Get-SIItemValue $l[0] 'values')) { foreach ($x in (Test-SIBreakGlassPattern -Pattern ([string]$v))) { $p.Add($x) } }
    return $p.ToArray()
}

function Test-SIRiskFactorItem {
    <# PURE. Test-SIRiskFactorRules for ONE factor (a Pro cfg.ItemOverride 'risk-factors:<id>' is checked with it on write). #>
    param($Factor, [hashtable]$Lists = @{})
    $p = New-Object System.Collections.Generic.List[string]
    $rawRx = '^(?i)(node|identity|ci|machine|deviceInfo|resource|derived|user|sp|app|registration|signIn|computer|device|host|exposure|roles|azureRoles|record|properties|rawData)(\[\*\])?(\.[A-Za-z0-9_$@-]+(\[\*\])?)+$'
    $lists = $Lists
    foreach ($f in @($Factor)) {
        if ($null -eq $f) { continue }
        $id = [string]$f.id
        $scope = Get-SIItemValue $f 'appliesTo'
        if ($null -eq $scope -or ($scope -is [System.Collections.IEnumerable] -and $scope -isnot [string]) -or @('asset', 'finding') -notcontains [string]$scope) {
            $p.Add("risk-factors/${id}: must have exactly one scope -- appliesTo 'asset' or 'finding' (has: $(ConvertTo-Json -InputObject $scope -Compress))")
        }
        foreach ($x in (Test-SIRiskFactorModelV2 -Factor $f)) { $p.Add($x) }
        foreach ($x in (Test-SIRiskFactorCriteria -Factor $f -Lists $lists)) { $p.Add($x) }
        if ([string]$f.evaluatedBy -eq 'report') { continue }
        foreach ($leaf in (Get-SIRiskFactorConditionLeaves $f.when)) {
            $fields = @([string]$leaf.field)
            $op = [string](Get-SIItemValue $leaf 'op'); $v = Get-SIItemValue $leaf 'value'
            if ($op -eq 'in_list' -and $v -is [string] -and $lists.ContainsKey($v)) { foreach ($e in (Get-SIValueList (Get-SIItemValue $lists[$v] 'entries'))) { foreach ($x in (Get-SIConditionFields (Get-SIItemValue $e 'when'))) { $fields += [string]$x } } }
            foreach ($fn in $fields) {
                if ($fn -eq 'si_tier') { $p.Add("risk-factors/${id}: reads si_tier -- a risk factor never restates tier (tier counts once: the risk index's asset base)") }
                elseif ($fn -notmatch '^si_[a-z0-9_]+$') { $p.Add("risk-factors/${id}: reads '$fn' -- a factor reads SI fields (si_*) only; a source field belongs in its provider mapping") }
            }
            foreach ($x in (Get-SIValueList $v)) { if ($x -is [string] -and $x -match $rawRx) { $p.Add("risk-factors/${id}: value '$x' is a raw source path -- it belongs in a provider mapping") } }
        }
    }
    return , $p
}

function Test-SIRiskFactorCriteria {
    <#
    .SYNOPSIS  PURE. A factor's criteria block -- the part a customer changes through the web app's wizard, never as free
               text (#541 (7)). Returns problems; empty = valid (also for a factor without criteria).
                 criteria: { kind: list | threshold | range, field: si_*, source: collected | enum | lifecycle, ... }
                   list       list = the id of a lists.locked.json list the factor's condition reads (in_list / in_ranges /
                              contains_any); optional detailField (si_*) the wizard narrows an entry with
                   threshold  op + min / max (numbers, min <= max): the factor's condition has a leaf on field with that op
                              whose value is a number inside [min, max]
                   range      min / max (numbers, min <= max) on field
    #>
    param($Factor, [hashtable]$Lists = @{})
    $p = New-Object System.Collections.Generic.List[string]
    $cr = Get-SIItemValue $Factor 'criteria'
    if ($null -eq $cr) { return , $p }
    $id = [string]$Factor.id
    $kind = [string](Get-SIItemValue $cr 'kind'); $field = [string](Get-SIItemValue $cr 'field'); $src = [string](Get-SIItemValue $cr 'source')
    if (@('list', 'threshold', 'range') -notcontains $kind) { $p.Add("risk-factors/${id}: criteria kind '$kind' (list, threshold or range)") }
    if ($field -notmatch '^si_[a-z0-9_]+$' -or $field -eq 'si_tier') { $p.Add("risk-factors/${id}: criteria field '$field' must be an SI field (si_*), never si_tier") }
    if (@('collected', 'enum', 'lifecycle') -notcontains $src) { $p.Add("risk-factors/${id}: criteria source '$src' (collected, enum or lifecycle)") }
    $leaves = (Get-SIRiskFactorConditionLeaves $Factor.when).ToArray()
    switch ($kind) {
        'list' {
            $lid = [string](Get-SIItemValue $cr 'list')
            if (-not $lid -or ($Lists.Count -gt 0 -and -not $Lists.ContainsKey($lid))) { $p.Add("risk-factors/${id}: criteria list '$lid' is not a list") }
            if (-not @($leaves | Where-Object { [string]$_.value -eq $lid -and @('in_list', 'in_ranges', 'contains_any') -contains [string]$_.op }).Count) { $p.Add("risk-factors/${id}: its condition does not read the criteria list '$lid'") }
            $df = [string](Get-SIItemValue $cr 'detailField')
            if ($df -and ($df -notmatch '^si_[a-z0-9_]+$' -or $df -eq 'si_tier')) { $p.Add("risk-factors/${id}: criteria detailField '$df' must be an SI field") }
        }
        { $_ -in 'threshold', 'range' } {
            $min = ConvertTo-SINumberOrNull (Get-SIItemValue $cr 'min'); $max = ConvertTo-SINumberOrNull (Get-SIItemValue $cr 'max')
            if ($null -eq $min -or $null -eq $max -or $min -gt $max) { $p.Add("risk-factors/${id}: criteria min / max must be numbers, min <= max") }
            elseif ($kind -eq 'threshold') {
                $op = [string](Get-SIItemValue $cr 'op')
                $leaf = @($leaves | Where-Object { [string]$_.field -eq $field -and [string]$_.op -eq $op })
                if ($leaf.Count -eq 0) { $p.Add("risk-factors/${id}: its condition has no '$field $op' leaf for the criteria") }
                foreach ($l in $leaf) {
                    $v = ConvertTo-SINumberOrNull $l.value
                    if ($null -eq $v -or $v -lt $min -or $v -gt $max) { $p.Add("risk-factors/${id}: '$field $op $($l.value)' is outside the criteria range $min..$max") }
                }
            }
        }
    }
    return , $p
}