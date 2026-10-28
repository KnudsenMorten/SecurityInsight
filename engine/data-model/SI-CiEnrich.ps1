#Requires -Version 5.1
<#
    SecurityInsight CI ENRICHMENT -- phase 3 of the v3 data model (V3-DATA-MODEL part 2, P3 + 2.19.2), on the CI:

      RULES        the existing enrichment rules (asset-profiling-enrichment/**/*.yaml, shipped + custom + the Pro
                   overlay, loaded by Get-SIRuleSet) are converted ONCE per run into the closed condition language over
                   SI FIELDS (ConvertTo-SICiRules) -- so a rule never reads a provider column -- and evaluated on every CI.
                   One claim per matching detection: rule, stage, mechanism, what it sets, the evidence it read.
      STAGE+TRUST  a claim decides only when its stage is production AND its mechanism is trusted in the trust list AND
                   its evidence is not older than the mechanism's maxAgeDays. Anything else is RECORDED (si_tier_claims,
                   with the reason) and decides nothing -- the deviation report reads exactly that. Default: every rule
                   is production (a rule file may say `stage: testing`).
      TIER         MIN over the deciding claims (a true Tier 0 is never buried); the default-tier rule only when no
                   other claim decided. si_tier_set_by / si_tier_reason / si_tier_claims trace it.
      OTHER FIELDS purpose, category, CMDB values: from the winning tier claim, else the best-placed deciding claim
                   (trust position, then rule order). Rule tags are added to si_tags (source 'rule').
      BREAK GLASS  a classification, not a factor (#559): the provider's si_is_break_glass OR the platform signals and
                   naming patterns of the list break_glass_patterns (SI-BreakGlass.ps1) -- BEFORE the rules, so the tier
                   rules and the break-glass reports read it exactly as they read the old factor's field.
      RISK FACTORS asset factors from data-model/risk-factors.json (#559 model v2): enabled factors are evaluated and
                   count their impact 1..5, disabled ones are not evaluated (a built-in factor is always enabled).
                   CI-level coverage checks raise their factor (D12). -> si_risk_factors, si_coverage_gaps.
      CRITICALITY  the owning CMDB's criticality -> si_cmdb_criticality_level, si_criticality_factor, si_criticality_source
                   (data-model/criticality-mapping.json; one CMDB owner per tenant: SIWeb_CmdbSource, default SI's own).

    PURE: no I/O. PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

. (Join-Path $PSScriptRoot 'SI-Conditions.ps1')
. (Join-Path $PSScriptRoot 'SI-BreakGlass.ps1')          # #559 break glass: a classification (provider + break_glass_patterns), never a factor
. (Join-Path $PSScriptRoot 'SI-RiskFactorCatalog.ps1')   # factor groups + provider links, network ranges, per-CI factor columns (#458 / #464)
. (Join-Path $PSScriptRoot 'SI-CiRules.ps1')
. (Join-Path $PSScriptRoot 'SI-CiGraph.ps1')       # #496 the business services that own a CI and what it inherits (Set-SICiServices)

function Get-SICiRuleClassMap {
    return @{ endpoint = @('device'); identity = @('identity'); azure = @('cloud_resource'); publicip = @('public_ip'); any = @('device', 'identity', 'cloud_resource', 'public_ip') }
}

function Get-SICiOsScopeMap {
    <# The rule files' osPlatformScope classes -> si_os_platform values. #>
    return @{ windowsserver = @('windows_server'); windowsclient = @('windows'); linux = @('linux'); macos = @('macos'); ios = @('ios'); android = @('android'); iot = @('other'); other = @('other') }
}

function Get-SICiKindMechanism {
    <# Which trust-list mechanism a detection kind's evidence is. #>
    param([string]$Kind)
    switch ($Kind) {
        'hasSoftwareInstalled' { 'mde.installed_software' } 'egDetectedRoles' { 'eg.graph_field' } 'egKustoQuery' { 'mde.detection' }
        'nameMatches' { 'name.pattern' } 'osPlatform' { 'eg.graph_field' } 'hasMdeMachineGroupTag' { 'mde.machine_tag' }
        'hasEntraExtensionAttributeTag' { 'entra.extension_attribute' } 'groupMembership' { 'entra.directory' }
        'hasAzureTagDirectOrParent' { 'azure.resource_tag' } 'mostFrequentUserTier' { 'mde.logon_user' } 'ipInRange' { 'network.ip_range' }
        'hasTag' { 'mde.machine_tag' } 'assetKind' { 'default' } default { 'name.pattern' }
    }
}

function Test-SIBareTierTagPattern {
    <# PURE. True for a tag pattern that says nothing but a tier ('(?i)tier.?0', 'tier1', '^tier-2$'). #>
    param([string]$Pattern)
    return ([string]$Pattern -match '^(\(\?i\))?\^?tier(\.|\[[^\]]*\]|[_-])?[?*]?\d\$?$')
}

function ConvertTo-SITagMatchCondition {
    <# A tag test (tag and/or value, with a match operator) -> a condition over tag entries on the given fields. #>
    param([string[]]$Fields, [string]$Tag, $Value, [string]$Op = 'equal')
    $conds = New-Object System.Collections.Generic.List[object]
    $hasVal = -not (($null -eq $Value) -or ($Value -is [string] -and $Value -eq ''))
    foreach ($f in $Fields) {
        if ($Tag -and -not $hasVal) { $conds.Add([ordered]@{ field = $f; op = 'matches'; value = ('^' + [regex]::Escape($Tag) + '(=.*)?$') }); continue }
        $vals = @($Value)
        switch -Regex ($Op) {
            '^(regex|matches)$' { foreach ($v in $vals) { $conds.Add([ordered]@{ field = $f; op = 'matches'; value = $(if ($Tag) { '^' + [regex]::Escape($Tag) + '=' + ([string]$v).TrimStart('^') } else { [string]$v }) }) } }
            '^like$' { foreach ($v in $vals) { $conds.Add([ordered]@{ field = $f; op = 'like'; value = $(if ($Tag) { $Tag + '=' + [string]$v } else { [string]$v }) }) } }
            '^(has|contains)$' { foreach ($v in $vals) { $conds.Add([ordered]@{ field = $f; op = 'matches'; value = $(if ($Tag) { '^' + [regex]::Escape($Tag) + '=.*' + [regex]::Escape([string]$v) } else { [regex]::Escape([string]$v) }) }) } }
            '^startswith$' { foreach ($v in $vals) { $conds.Add([ordered]@{ field = $f; op = 'matches'; value = $(if ($Tag) { '^' + [regex]::Escape($Tag) + '=' + [regex]::Escape([string]$v) } else { '^' + [regex]::Escape([string]$v) }) }) } }
            '^endswith$' { foreach ($v in $vals) { $conds.Add([ordered]@{ field = $f; op = 'matches'; value = $(if ($Tag) { '^' + [regex]::Escape($Tag) + '=.*' + [regex]::Escape([string]$v) + '$' } else { [regex]::Escape([string]$v) + '$' }) }) } }
            default { foreach ($v in $vals) { $conds.Add([ordered]@{ field = $f; op = 'contains'; value = $(if ($Tag) { $Tag + '=' + [string]$v } else { [string]$v }) }) } }   # equal / in
        }
    }
    if ($conds.Count -eq 1) { return $conds[0] }
    return [ordered]@{ any = $conds.ToArray() }
}

function ConvertTo-SICiKindCondition {
    <#
    .SYNOPSIS  One old detection kind -> a condition over SI fields. $null = the kind cannot be expressed (reported).
    #>
    param([Parameter(Mandatory)]$Spec, [string]$RuleId)
    $k = [string](Get-SIItemValue $Spec 'kind')
    $g = { param($n) Get-SIItemValue $Spec $n }
    switch ($k) {
        'hasSoftwareInstalled' {
            $pats = New-Object System.Collections.Generic.List[string]
            foreach ($p in @(& $g 'tvmSoftwareNames')) { if ($p) { $pats.Add(([string]$p).ToLowerInvariant()); $pats.Add('*/' + ([string]$p).ToLowerInvariant()) } }
            return [ordered]@{ field = 'si_installed_software'; op = 'like'; value = $pats.ToArray() }
        }
        'nameMatches' {
            $pats = @(& $g 'namePatterns'); if (-not $pats -or -not $pats[0]) { $pats = @(& $g 'patterns') }
            return [ordered]@{ any = @(foreach ($f in 'si_asset_name', 'si_hostname', 'si_fqdn') { [ordered]@{ field = $f; op = 'matches'; value = @($pats) } }) }
        }
        'osPlatform' {
            $pats = @(& $g 'osPatterns'); if (-not $pats -or -not $pats[0]) { $pats = @(& $g 'patterns') }
            return [ordered]@{ field = 'si_os_name'; op = 'matches'; value = @($pats) }
        }
        'hasMdeMachineGroupTag' {
            $pats = @(& $g 'machineTagPatterns'); if (-not $pats -or -not $pats[0]) { $pats = @(& $g 'patterns') }
            # a bare tier pattern ('(?i)tier.?0') is not evidence of THIS role: it matches every operator tier tag
            # (PAWDevices--tier0--SI) and made a PAW a "Domain Controller" (internal 2026-10-11). The operator's tier tag is
            # its own low-priority claim (operator.tier_tag, ConvertTo-SICiTagTierRules) -- so it is left out here, also
            # for a custom rule copied from an old sample. No pattern left = a condition that never matches.
            $pats = @($pats | Where-Object { $_ -and -not (Test-SIBareTierTagPattern ([string]$_)) })
            return [ordered]@{ any = @([ordered]@{ field = 'si_machine_groups'; op = 'matches'; value = @($pats) }, [ordered]@{ field = 'si_tags'; op = 'matches'; value = @($pats) }) }
        }
        'egDetectedRoles' {
            $sig = @(& $g 'egSignals'); if (-not $sig -or -not $sig[0]) { $sig = @(& $g 'roles') }
            # Exposure Graph signals -> the role names si_device_roles carries (eg mapping); an unknown signal -> snake_case
            $known = @{ isdomaincontroller = 'domain_controller'; isexchangeserverdnsname = 'exchange'; istaggedasexchangeserver = 'exchange'; isadfsserver = 'adfs' }
            $roles = @(foreach ($s in $sig) { $sk = ([string]$s).ToLowerInvariant(); if ($known.ContainsKey($sk)) { $known[$sk] } else { (([string]$s) -replace '^(?i)is', '' -creplace '([a-z0-9])([A-Z])', '$1_$2').ToLowerInvariant() } })
            return [ordered]@{ field = 'si_device_roles'; op = 'in'; value = $roles }
        }
        'hasEntraExtensionAttributeTag' {
            $attr = [string](& $g 'attribute'); $val = [string](& $g 'value'); $m = [string](& $g 'match'); if (-not $m) { $m = 'exact' }
            $op = 'equal'; if ($m -ne 'exact') { $op = 'has' }
            return (ConvertTo-SITagMatchCondition -Fields @('si_tags') -Tag $attr -Value $val -Op $op)
        }
        'groupMembership' {
            $grp = @(& $g 'group') + @(& $g 'groups') | Where-Object { $_ }
            return [ordered]@{ field = 'si_group_memberships'; op = 'in'; value = @($grp) }
        }
        'hasAzureTagDirectOrParent' {
            $op = [string](& $g 'match'); if (-not $op) { $op = 'equal' }
            return (ConvertTo-SITagMatchCondition -Fields @('si_tags', 'si_azure_parent_tags') -Tag ([string](& $g 'tag')) -Value (& $g 'value') -Op $op)
        }
        'hasTag' {
            $op = [string](& $g 'match'); if (-not $op) { $op = 'equal' }
            return (ConvertTo-SITagMatchCondition -Fields @('si_tags', 'si_azure_parent_tags', 'si_machine_groups') -Tag ([string](& $g 'tag')) -Value (& $g 'value') -Op $op)
        }
        'mostFrequentUserTier' { return [ordered]@{ field = 'si_frequent_user_tier'; op = 'in'; value = @(& $g 'tierValues') } }
        'ipInRange' {
            $cidrs = @(& $g 'cidrs'); if (-not $cidrs -or -not $cidrs[0]) { $cidrs = @(& $g 'ranges') }
            return [ordered]@{ any = @([ordered]@{ field = 'si_ip_addresses'; op = 'in_ranges'; value = @($cidrs) }, [ordered]@{ field = 'si_public_ip'; op = 'in_ranges'; value = @($cidrs) }, [ordered]@{ field = 'si_ip_address'; op = 'in_ranges'; value = @($cidrs) }) }
        }
        'egKustoQuery' { return [ordered]@{ field = 'si_eg_query_rules'; op = 'contains'; value = $RuleId } }
        'assetKind' {
            $map = Get-SICiRuleClassMap
            $kinds = @(& $g 'kinds'); if (-not $kinds -or -not $kinds[0]) { $kinds = @(& $g 'values') }
            $cls = @(foreach ($x in $kinds) { foreach ($one in (([string]$x) -split '[,;]\s*')) { if ($map.ContainsKey($one.Trim().ToLowerInvariant())) { $map[$one.Trim().ToLowerInvariant()] } } })
            return [ordered]@{ field = 'si_class'; op = 'in'; value = @($cls | Select-Object -Unique) }
        }
        default { return $null }
    }
}

function Get-SICiRulePack {
    <# PURE (#462). The rule PACK a rule belongs to -- a grouping and a GUI label, never an engine path: the AssetProfileBy*
       family in its file path (AssetProfileByDeviceType, ...ApplicationServiceDetection, ...ExtensionAttributes ...), else
       the rule id. #>
    param([string]$File, [string]$Id)
    foreach ($seg in @(([string]$File) -split '[\\/]')) {
        $n = $seg -replace '\.(locked|custom)\.yaml$', ''
        if ($n -match '^AssetProfileBy[A-Za-z]+$' -or $n -match '^AssetTagging$') { return $n }
    }
    return $Id
}

function Get-SICiRuleKey {
    <#
        PURE. The key of the tier rule a CI rule was made from -- '<engine>/<rule id>' (engine: endpoint | identity | azure |
        shared, the folder its rule file lies in) -- which is what a rule change names (turn the rule off, move it to another
        tier, put it back). '' when no such rule made it: the file lies in none of the four folders, the id is not a rule
        id, or the rule is a pin written for ONE asset (id gui-pin-...: it is changed where it was set, as a pin).
    #>
    param([string]$File, [string]$Id)
    if ([string]::IsNullOrWhiteSpace($Id) -or $Id -notmatch '^[A-Za-z0-9][A-Za-z0-9_\-]{0,99}$' -or $Id -like 'gui-pin-*') { return '' }
    $segs = @(([string]$File) -split '[\\/]' | Where-Object { $_ })
    for ($i = 0; $i -lt ($segs.Count - 1); $i++) {
        $s = ([string]$segs[$i]).ToLowerInvariant()
        if ($s -eq 'endpoint' -or $s -eq 'identity' -or $s -eq 'azure' -or $s -eq 'shared') { return ('{0}/{1}' -f $s, $Id) }
    }
    return ''
}

function ConvertTo-SICiRules {
    <#
    .SYNOPSIS  The loaded rule set (Get-SIRuleSet objects, any engine) -> CI rules, one per detection.
    .OUTPUTS   @{ Rules = [...]; Unconverted = [ "<rule>/<detection>: <kind>" ] }
    #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$RuleSet)
    $classMap = Get-SICiRuleClassMap; $osMap = Get-SICiOsScopeMap
    $out = New-Object System.Collections.Generic.List[object]
    $bad = New-Object System.Collections.Generic.List[string]
    $order = 0
    foreach ($r in $RuleSet) {
        if ($null -eq $r -or [string]$r.Mode -eq 'disable') { continue }
        $classes = New-Object System.Collections.Generic.List[string]
        # the rule loader joins a multi-engine appliesTo into one 'endpoint,identity' string -- split it, or the lookup misses
        # and the rule falls through to every class
        foreach ($a in @(@($r.AppliesTo) | ForEach-Object { ([string]$_) -split '\s*,\s*' } | Where-Object { $_ })) { $ak = ([string]$a).ToLowerInvariant(); if ($classMap.ContainsKey($ak)) { foreach ($c in $classMap[$ak]) { if (-not $classes.Contains($c)) { $classes.Add($c) } } } }
        if ($classes.Count -eq 0) { foreach ($c in $classMap['any']) { $classes.Add($c) } }
        $os = New-Object System.Collections.Generic.List[string]
        foreach ($s in @($r.osPlatformScope)) { $sk = ([string]$s).ToLowerInvariant(); if ($osMap.ContainsKey($sk)) { foreach ($v in $osMap[$sk]) { $os.Add($v) } } }
        $stage = 'production'
        if ($r.PSObject.Properties['Stage'] -and $r.Stage) { $stage = ([string]$r.Stage).ToLowerInvariant() }
        $prio = 100
        if ($r.PSObject.Properties['Priority'] -and $null -ne $r.Priority) { $prio = [int]$r.Priority }
        foreach ($d in @($r.Detections)) {
            $order++
            $detId = '{0}/{1}' -f $r.Id, $d.Id
            $mode = 'any'; $specs = @(Get-SIItemValue $d.Detect 'any')
            if (-not $specs -or $null -eq $specs[0]) { $mode = 'all'; $specs = @(Get-SIItemValue $d.Detect 'all') }
            $conds = New-Object System.Collections.Generic.List[object]
            $mech = ''
            $mechs = New-Object System.Collections.Generic.List[string]   # one per condition, in order (the evidence that matched decides the mechanism)
            $ok = $true
            foreach ($sp in $specs) {
                if ($null -eq $sp) { continue }
                $c = ConvertTo-SICiKindCondition -Spec $sp -RuleId ([string]$r.Id)
                if ($null -eq $c) { $bad.Add(('{0}: {1}' -f $detId, (Get-SIItemValue $sp 'kind'))); $ok = $false; continue }
                $conds.Add($c); $mechs.Add((Get-SICiKindMechanism ([string](Get-SIItemValue $sp 'kind'))))
                if (-not $mech) { $mech = Get-SICiKindMechanism ([string](Get-SIItemValue $sp 'kind')) }
            }
            if ($conds.Count -eq 0 -or ($mode -eq 'all' -and -not $ok)) { continue }
            $when = [ordered]@{}; $when[$mode] = $conds.ToArray()
            $set = [ordered]@{}
            $s = $d.Set
            if ($null -ne $s) {
                $pairs = @{ Tier = 'si_tier'; Purpose = 'si_purpose'; Category = 'si_category'; cmdbId = 'si_cmdb_id'; cmdbName = 'si_cmdb_name'; cmdbCriticality = 'si_cmdb_criticality'; cmdbDataSensitivity = 'si_cmdb_data_sensitivity' }
                foreach ($k in $pairs.Keys) { $v = Get-SIItemValue $s $k; if ($null -ne $v -and "$v" -ne '') { $set[$pairs[$k]] = $v } }
                $tg = Get-SIItemValue $s 'Tags'; if ($null -ne $tg) { $set['si_tags'] = @($tg | ForEach-Object { [string]$_ }) }
            }
            if (-not $set.Contains('si_purpose') -and $r.Purpose) { $set['si_purpose'] = [string]$r.Purpose }
            if (-not $set.Contains('si_category') -and $r.Category) { $set['si_category'] = [string]$r.Category }
            $out.Add([pscustomobject][ordered]@{
                    id = $detId; family = [string]$r.Folder; file = [string]$r.File; name = $(if ($r.Description) { [string]$r.Description } else { [string]$r.Id })
                    stage = $stage; priority = $prio; pack = (Get-SICiRulePack -File ([string]$r.File) -Id ([string]$r.Id)); order = $order; classes = $classes.ToArray(); osScope = $os.ToArray(); fallback = [bool]$r.Fallback
                    mechanism = $mech; mechanisms = $mechs.ToArray(); when = $when; set = $set; exclude = @($d.ExcludeAssets)
                    key = (Get-SICiRuleKey -File ([string]$r.File) -Id ([string]$r.Id))
                })
        }
    }
    return @{ Rules = $out.ToArray(); Unconverted = $bad.ToArray() }
}

function Get-SICiTrustIndex {
    <# The trust list as id -> @{ Position; Trusted; MaxAgeDays }. #>
    param($Trust)
    $idx = @{}; $i = 0
    foreach ($e in @($Trust.order)) { $idx[[string]$e.id] = [pscustomobject]@{ Position = $i; Trusted = [bool]$e.trusted; MaxAgeDays = $e.maxAgeDays }; $i++ }
    return $idx
}

function Get-SICiEvidenceAge {
    <# Days since the oldest observation behind the fields a condition read (si_field_sources), or $null. #>
    param($Ci, [string[]]$Fields, [datetime]$Now)
    $src = Get-SIItemValue $Ci 'si_field_sources'
    $oldest = $null
    foreach ($f in $Fields) {
        $s = Get-SIItemValue $src $f
        $t = ConvertTo-SIUtcOrNull (Get-SIItemValue $s 'observed_at')
        if ($t -and ($null -eq $oldest -or $t -lt $oldest)) { $oldest = $t }
    }
    if ($null -eq $oldest) { return $null }
    return ($Now - $oldest).TotalDays
}

function Get-SICiRulesByClass {
    <#
        The CI rules grouped by the classes they apply to (class -> rules, in rule order), rules not in use left out. Built
        once per set of CIs: walking every rule on every CI was most of the CI build's time (ring 1, 2026-10-08: 587 rules
        x 9,745 CIs = 21 of 36 minutes).
    #>
    param([AllowEmptyCollection()][object[]]$Rules = @())
    $lists = @{}
    foreach ($r in $Rules) {
        if ($null -eq $r) { continue }
        # a rule not in use is left out -- except an asset-tagging rule switched off by the setting (strip_tags, #643): it
        # decides nothing (Invoke-SICiRules skips not_used), but the tags it names are taken off the CI
        if ($r.stage -eq 'not_used' -and -not ($r.PSObject.Properties['strip_tags'] -and [bool]$r.strip_tags)) { continue }
        foreach ($c in @($r.classes)) {
            $k = [string]$c
            if (-not $lists.ContainsKey($k)) { $lists[$k] = New-Object System.Collections.Generic.List[object] }
            $lists[$k].Add($r)
        }
    }
    $out = @{}
    foreach ($k in $lists.Keys) { $out[$k] = $lists[$k].ToArray() }
    return $out
}

function Get-SICiConditionMatches {
    <#
        PURE. What made a condition true on an item: one entry per leaf that matched -- { field; values } with the VALUES of the
        field that satisfy the leaf (the tag, the software, the name), not the whole field. An 'any' group gives the leaves that
        matched, an 'all' group every leaf. Feeds the tier explanation (si_tier_explanation, #579).
    #>
    param($Condition, $Item, [hashtable]$Context)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Condition) { return }
    foreach ($k in 'all', 'any') {
        $has = ($Condition -is [System.Collections.IDictionary] -and $Condition.Contains($k)) -or ($Condition -isnot [System.Collections.IDictionary] -and $Condition.PSObject.Properties[$k])
        if (-not $has) { continue }
        foreach ($c in (Get-SIValueList (Get-SIItemValue $Condition $k))) {
            $ok = $false; try { $ok = Test-SICondition -Condition $c -Item $Item -Context $Context } catch { $ok = $false }
            if ($ok) { foreach ($m in @(Get-SICiConditionMatches -Condition $c -Item $Item -Context $Context)) { $out.Add($m) } }
        }
        return $out.ToArray()   # unrolled: the caller collects with @()
    }
    $field = [string](Get-SIItemValue $Condition 'field'); if (-not $field) { return }
    $op = [string](Get-SIItemValue $Condition 'op')
    $actual = Get-SIItemValue $Item $field
    $vals = New-Object System.Collections.Generic.List[object]
    if (@('matches', 'like', 'contains', 'eq', 'in', 'contains_any', 'in_ranges', 'in_list') -contains $op) {
        # A TEXT VALUE OF A LONG LIST IS MATCHED IN PLACE (2026-10-16: a device's software list -- hundreds of names -- went
        # through a whole condition evaluation per name). For one text, 'like' / 'matches' is: does any pattern match the
        # text (Test-SICondition, with the same kept patterns); every other value or operation is evaluated as before.
        $pats = $null
        if ($op -eq 'like') { $pats = @(foreach ($p in (Get-SIValueList (Get-SIItemValue $Condition 'value'))) { Get-SIConditionWildcard ([string]$p) }) }
        elseif ($op -eq 'matches') { try { $pats = @(foreach ($p in (Get-SIValueList (Get-SIItemValue $Condition 'value'))) { Get-SIConditionRegex ([string]$p) }) } catch { $pats = $null } }
        foreach ($v in (Get-SIValueList $actual)) {
            if ($null -ne $pats -and $v -is [string]) {
                $hit = $false
                try { foreach ($px in $pats) { if ($px.IsMatch($v)) { $hit = $true; break } } } catch { $hit = $false }
                if ($hit) { $vals.Add($v) }
                continue
            }
            $one = @{}; $one[$field] = $v
            $ok = $false; try { $ok = Test-SICondition -Condition $Condition -Item $one -Context $Context } catch { $ok = $false }
            if ($ok) { $vals.Add($v) }
        }
    }
    if ($vals.Count -eq 0) { foreach ($v in (Get-SIValueList $actual)) { $vals.Add($v) } }
    $out.Add([ordered]@{ field = $field; values = $vals.ToArray() })
    return $out.ToArray()
}

function ConvertTo-SICiEvidenceText {
    <# PURE. One matched value of an SI field in the customer's words ("Defender tag PAWDevices--tier0--SI", "installed software
       microsoft/sql_server", "name dc1"). #>
    param([string]$Field, $Value)
    if (@('si_tags', 'si_azure_parent_tags', 'si_machine_groups') -contains $Field -and $null -ne $Value -and $Value -isnot [string] -and $null -ne (Get-SIItemValue $Value 'name')) {
        $n = [string](Get-SIItemValue $Value 'name'); $v = [string](Get-SIItemValue $Value 'value')
        $t = $n; if ($v) { $t = '{0}={1}' -f $n, $v }
        $who = switch ([string](Get-SIItemValue $Value 'source')) { 'mde' { 'Defender tag' } 'entra' { 'Entra attribute' } 'azure' { 'Azure tag' } 'eg' { 'Exposure Management tag' } 'rule' { 'SI tag' } default { 'tag' } }
        if ($Field -eq 'si_azure_parent_tags') { $who = 'Azure tag (inherited)' }
        return ('{0} {1}' -f $who, $t)
    }
    $s = ''
    if ($null -ne $Value -and $Value -isnot [string] -and $Value -isnot [ValueType]) { $nm = Get-SIItemValue $Value 'name'; if ($null -ne $nm) { $s = [string]$nm } else { $s = (ConvertTo-Json -InputObject $Value -Compress -Depth 3) } }
    else { $s = [string]$Value }
    if ($s.Length -gt 80) { $s = $s.Substring(0, 77) + '...' }
    switch ($Field) {
        'si_machine_groups' { return "Defender device group $s" }
        'si_installed_software' { return "installed software $s" }
        { @('si_asset_name', 'si_hostname', 'si_fqdn') -contains $_ } { return "name $s" }
        'si_device_roles' { return ('detected role {0}' -f ($s -replace '_', ' ')) }
        'si_group_memberships' { return "member of $s" }
        'si_frequent_user_tier' { return "its most frequent logon user is Tier $s" }
        'si_os_name' { return "operating system $s" }
        { @('si_ip_addresses', 'si_ip_address', 'si_public_ip') -contains $_ } { return "IP address $s" }
        'si_eg_query_rules' { return 'an Exposure Management detection' }
        'si_class' { return "asset kind $s" }
        default { return ('{0} {1}' -f (($Field -replace '^si_', '') -replace '_', ' '), $s) }
    }
}

function Get-SICiClaimLabel {
    <# PURE. A claim's name in one short line: the purpose it sets, else the first line of the rule's name. #>
    param($Set, [string]$Name, [string]$Rule)
    if ($null -ne $Set -and $Set.Contains('si_purpose') -and [string]$Set['si_purpose']) { return [string]$Set['si_purpose'] }
    $l = (([string]$Name) -split "`r?`n")[0].Trim()
    if (-not $l) { $l = $Rule }
    if ($l.Length -gt 80) { $l = $l.Substring(0, 77) + '...' }
    return $l
}

function Get-SICiTierExplanation {
    <#
        PURE (#579). The tier in one plain sentence, from what the CI build decided (si_tier, si_tier_set_by, si_tier_claims,
        si_overrides): the tier, WHO decided it (an SI rule with its name and the evidence it matched / the operator's tag /
        the manual override with who, reason and expiry / the default), then "Also claimed: ..." with every other claim and
        why it lost. No internal ids or numbers besides the tier.
          Tier 0 -- SI rule Privileged Access Workstation (Defender tag PAWDevices--tier0--SI). Also claimed: your tag
          EmployeeWorkstations--tier3--SI (a tag counts only when no SI rule decides); default Tier 3 (the default applies
          only when nothing claims).
    #>
    param([Parameter(Mandatory)]$Ci)
    $tier = Get-SIItemValue $Ci 'si_tier'
    $setBy = [string](Get-SIItemValue $Ci 'si_tier_set_by')
    $claims = @(@(Get-SIItemValue $Ci 'si_tier_claims') | Where-Object { $null -ne $_ -and $null -ne (Get-SIItemValue $_ 'tier') -and "$(Get-SIItemValue $_ 'tier')" -ne '' })
    if ($null -eq $tier -or "$tier" -eq '') { return 'No tier -- no SI rule, tag or default claims one.' }
    $kindOf = {
        param($c)
        $k = [string](Get-SIItemValue $c 'kind')
        if ($k) { return $k }
        if ([string](Get-SIItemValue $c 'mechanism') -eq 'operator.tier_tag') { return 'tag' }
        if ([string](Get-SIItemValue $c 'mechanism') -eq 'default') { return 'default' }
        return 'rule'
    }
    $labelOf = { param($c) $l = [string](Get-SIItemValue $c 'label'); if (-not $l) { $l = Get-SICiClaimLabel -Set $null -Name ([string](Get-SIItemValue $c 'name')) -Rule ([string](Get-SIItemValue $c 'rule')) }; $l }
    $matchedOf = { param($c) @(@(Get-SIItemValue $c 'matched') | Where-Object { $_ } | ForEach-Object { [string]$_ } | Select-Object -Unique -First 3) }
    $describe = {
        param($c, [bool]$withTier)
        $k = & $kindOf $c; $m = @(& $matchedOf $c); $t = [int](Get-SIItemValue $c 'tier')
        switch ($k) {
            'tag' { if ($m.Count -gt 0) { return ('your tag {0}' -f ($m -join ', ')) } else { return ('your tag (Tier {0})' -f $t) } }
            'default' { return ('default Tier {0}' -f $t) }
            default {
                $s = 'SI rule ' + (& $labelOf $c)
                if ($withTier) { $s += (' Tier {0}' -f $t) }
                if ($m.Count -gt 0) { $s += (' ({0})' -f ($m -join '; ')) }
                return $s
            }
        }
    }
    $win = @($claims | Where-Object { [bool](Get-SIItemValue $_ 'winner') } | Select-Object -First 1)
    $head = 'Tier {0} -- ' -f [int]$tier
    switch ($setBy) {
        'override' {
            $o = @(@(Get-SIItemValue $Ci 'si_overrides') | Where-Object { $_ -and [string](Get-SIItemValue $_ 'field') -eq 'si_tier' } | Select-Object -Last 1)
            $by = 'an administrator'; $why = ''; $exp = 'no expiry'
            if ($o.Count -gt 0) {
                if ([string](Get-SIItemValue $o[0] 'set_by')) { $by = [string](Get-SIItemValue $o[0] 'set_by') }
                $why = [string](Get-SIItemValue $o[0] 'reason')
                $e = ConvertTo-SIUtcOrNull (Get-SIItemValue $o[0] 'expires_at'); if ($e) { $exp = 'until ' + $e.ToString('yyyy-MM-dd', [System.Globalization.CultureInfo]::InvariantCulture) }
            }
            $head += ('manual override by {0}' -f $by)
            if ($why) { $head += (': {0}' -f $why.Trim().TrimEnd('.')) }
            $head += (' ({0})' -f $exp)
        }
        'default' { $head += 'the default tier (no SI rule or tag claims one)' }
        default {
            if ($win.Count -gt 0) { $head += (& $describe $win[0] $false) }
            elseif ($setBy -eq 'tag') { $head += 'your tag' }
            else { $head += ('{0}' -f $(if ($setBy) { $setBy } else { 'SI rules' })) }
        }
    }
    $winRef = $null; if ($win.Count -gt 0) { $winRef = $win[0] }
    # lowest tier first; at one tier the SI rules, then the tags, then the default; then by name (the same order every run)
    $kindRank = @{ rule = 0; tag = 1; default = 2 }
    $others = @($claims | Where-Object { -not [object]::ReferenceEquals($_, $winRef) } | Sort-Object @{ Expression = { [int](Get-SIItemValue $_ 'tier') } },
        @{ Expression = { $k = & $kindOf $_; if ($kindRank.ContainsKey($k)) { $kindRank[$k] } else { 0 } } }, @{ Expression = { [string](& $labelOf $_) } }, @{ Expression = { [string](Get-SIItemValue $_ 'rule') } })
    $parts = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($c in $others) {
        $k = & $kindOf $c; $t = [int](Get-SIItemValue $c 'tier')
        $lost = ''
        if (-not [bool](Get-SIItemValue $c 'admissible')) {
            $r = [string](Get-SIItemValue $c 'reason')
            if ($r -match '^stage: (.+)$') { $lost = 'the rule is in {0}, it decides nothing yet' -f $Matches[1] }
            elseif ($r -match '^source not trusted') { $lost = 'its source is not trusted' }
            elseif ($r -match '^stale: (\d+) days') { $lost = 'its evidence is {0} days old' -f $Matches[1] }
            else { $lost = 'it is not used' }
        }
        elseif ($setBy -eq 'override') { $lost = 'the manual override decides' }
        elseif ($k -eq 'default') { $lost = 'the default applies only when nothing claims' }
        elseif ($k -eq 'tag' -and $setBy -eq 'rule') { $lost = 'a tag counts only when no SI rule decides' }
        elseif ($t -gt [int]$tier) { $lost = 'a higher tier number; the lowest wins' }
        else { $lost = 'the same tier; another claim decided first' }
        $txt = '{0} ({1})' -f (& $describe $c ($k -eq 'rule')), $lost
        if ($seen.Add($txt)) { $parts.Add($txt) }
    }
    $s = $head + '.'
    if ($parts.Count -gt 0) {
        $max = 4
        $shown = @($parts | Select-Object -First $max)
        $tail = ''; if ($parts.Count -gt $max) { $tail = '; and {0} more' -f ($parts.Count - $max) }
        $s += (' Also claimed: {0}{1}.' -f ($shown -join '; '), $tail)
    }
    # an identity that holds a Tier 0 Entra role: the level inside Tier 0, with the role and -- for a role held on an
    # administrative unit or one object only -- the scope's name AND id. Said once (a Tier 0 claim may already carry it).
    $lvl = ([string](Get-SIItemValue $Ci 'si_privilege_tier_level_text')).Trim()
    if ($lvl -and [string](Get-SIItemValue $Ci 'si_class') -eq 'identity' -and $s.IndexOf($lvl, [System.StringComparison]::Ordinal) -lt 0) { $s += (' Entra roles: {0}.' -f $lvl.TrimEnd('.')) }
    return $s
}

function Invoke-SICiRules {
    <#
    .SYNOPSIS  Evaluates the CI rules on one CI and applies the result (tier + trace, purpose, category, CMDB values, tags).
    #>
    param([Parameter(Mandatory)]$Ci, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rules, [Parameter(Mandatory)][hashtable]$Trust, [hashtable]$Context, [datetime]$Now = [datetime]::UtcNow,
        # the rules grouped by class once for a whole set of CIs (Get-SICiRulesByClass) -- a CI then walks only its class's
        # rules; and each rule's evidence fields read once (rule id -> fields). Same result, without them it is per CI.
        [hashtable]$RulesByClass, [hashtable]$FieldCache,
        # ONE CI NEVER HOLDS THE BUILD (owner 2026-10-13): when the rules of this CI have taken longer than this many seconds,
        # the rules not yet tried are left out for this run and the CI is marked (si_ci_rules_cut = the seconds used). The
        # build takes the mark off and keeps the CI OUT of what it writes -- a tier from part of the rules is a wrong tier --,
        # names it in its log and builds it again in the next run (SI-CiBuildRun.ps1, Get-SICiHeld). 0 = no limit.
        [double]$BudgetSeconds = 0)
    $class = [string]$Ci['si_class']
    $budgetWatch = $null; if ($BudgetSeconds -gt 0) { $budgetWatch = [System.Diagnostics.Stopwatch]::StartNew() }
    $rulesCut = $false
    $platform = [string]$Ci['si_os_platform']
    if ($RulesByClass) { $Rules = @(); if ($RulesByClass.ContainsKey($class)) { $Rules = $RulesByClass[$class] } }
    $claims = New-Object System.Collections.Generic.List[object]
    foreach ($r in $Rules) {
        if ($null -ne $budgetWatch -and $budgetWatch.Elapsed.TotalSeconds -gt $BudgetSeconds) { $rulesCut = $true; break }
        if ($r.stage -eq 'not_used') { continue }
        if (@($r.classes) -notcontains $class) { continue }
        if (@($r.osScope).Count -gt 0 -and $platform -and @($r.osScope) -notcontains $platform) { continue }
        $excluded = $false
        foreach ($x in @($r.exclude)) { if ($x -and ([string]$Ci['si_asset_name']) -like [string]$x) { $excluded = $true } }
        if ($excluded) { continue }
        $hit = $false
        try { $hit = Test-SICondition -Condition $r.when -Item $Ci -Context $Context } catch { $hit = $false }
        if (-not $hit) { continue }
        $fields = $null
        if ($FieldCache -and $FieldCache.ContainsKey([string]$r.id)) { $fields = $FieldCache[[string]$r.id] }
        else {
            $fl = Get-SIConditionFields $r.when; $fields = @($fl | Select-Object -Unique)   # $fl is the list: piping the VARIABLE enumerates it
            if ($FieldCache) { $FieldCache[[string]$r.id] = $fields }
        }
        # the claim's mechanism is the evidence that MATCHED -- for an any-rule the best-placed of its matching detections
        # in the trust list, never just the rule's first detection kind (a Domain Controller rule matched by a tag ranked
        # as installed software and outranked the PAW rule of the same tier, internal 2026-10-11)
        $mech = [string]$r.mechanism
        if ($r.PSObject.Properties['mechanisms'] -and @($r.mechanisms).Count -gt 1 -and $r.when -is [System.Collections.IDictionary] -and $r.when.Contains('any')) {
            $grp = @($r.when['any']); $ms = @($r.mechanisms)
            if ($grp.Count -eq $ms.Count) {
                $bestPos = [int]::MaxValue; $best = ''
                for ($i = 0; $i -lt $grp.Count; $i++) {
                    $p = 999; if ($null -ne $Trust[[string]$ms[$i]]) { $p = $Trust[[string]$ms[$i]].Position }
                    if ($p -ge $bestPos) { continue }
                    $ok = $false; try { $ok = Test-SICondition -Condition $grp[$i] -Item $Ci -Context $Context } catch { $ok = $false }
                    if ($ok) { $bestPos = $p; $best = [string]$ms[$i] }
                }
                if ($best) { $mech = $best }
            }
        }
        $t = $Trust[$mech]
        $reason = ''
        $admissible = $true
        if ($r.stage -ne 'production') { $admissible = $false; $reason = 'stage: ' + $r.stage }
        elseif ($mech -ne 'default' -and $null -ne $t -and -not $t.Trusted) { $admissible = $false; $reason = 'source not trusted: ' + $mech }
        elseif ($null -ne $t -and $null -ne $t.MaxAgeDays) {
            $age = Get-SICiEvidenceAge -Ci $Ci -Fields $fields -Now $Now
            if ($null -ne $age -and $age -gt [double]$t.MaxAgeDays) { $admissible = $false; $reason = ('stale: {0} days (max {1})' -f [int]$age, $t.MaxAgeDays) }
        }
        $pos = 999; if ($null -ne $t) { $pos = $t.Position }
        $prio = 100; if ($r.PSObject.Properties['priority'] -and $null -ne $r.priority) { $prio = [int]$r.priority }
        $pack = ''; if ($r.PSObject.Properties['pack']) { $pack = [string]$r.pack }
        $asserted = $false; if ($r.PSObject.Properties['asserted']) { $asserted = [bool]$r.asserted }
        $ruleKey = ''; if ($r.PSObject.Properties['key'] -and $r.key) { $ruleKey = [string]$r.key }
        $claims.Add([pscustomobject][ordered]@{
                rule = $r.id; key = $ruleKey; name = $r.name; stage = $r.stage; mechanism = $mech; trust_position = $pos; order = $r.order; priority = $prio; pack = $pack
                fallback = [bool]$r.fallback; asserted = $asserted; tier = $(if ($r.set.Contains('si_tier')) { [int]$r.set['si_tier'] } else { $null })
                set = $r.set; evidence = $fields; admissible = $admissible; reason = $reason; winner = $false; when = $r.when
            })
    }
    $deciding = @($claims | Where-Object { $_.admissible -and -not $_.fallback })
    $tierClaims = @($deciding | Where-Object { $null -ne $_.tier })
    # an ASSERTED claim (a tier a person wrote down: the operator's tier tag, Get-SICiTagTierRules) is low priority (owner:
    # "tags must continue to be used, just low prio"): it decides the tier only when no observed rule claims one -- it never
    # moves the tier an observed claim gave, and it always beats the default rule
    $observedTier = @($tierClaims | Where-Object { -not $_.asserted })
    if ($observedTier.Count -gt 0) { $tierClaims = $observedTier }
    $setBy = 'rule'
    if ($tierClaims.Count -eq 0) { $tierClaims = @($claims | Where-Object { $_.admissible -and $_.fallback -and $null -ne $_.tier }); $setBy = 'default' }
    $win = $null
    if ($tierClaims.Count -gt 0) {
        $win = @($tierClaims | Sort-Object @{ Expression = { $_.tier } }, @{ Expression = { $_.trust_position } }, @{ Expression = { $_.order } })[0]
        $win.winner = $true
        # #579 who decided: an SI rule, the operator's tag (an asserted claim) or the default -- the web app filters on it
        if ($setBy -eq 'rule' -and $win.asserted) { $setBy = 'tag' }
        $Ci['si_tier'] = [int]$win.tier
        $Ci['si_tier_set_by'] = $setBy
        $why = [string]$win.name; if ($win.set.Contains('si_purpose')) { $why = [string]$win.set['si_purpose'] }
        $Ci['si_tier_reason'] = ('{0} ({1})' -f $why, $win.rule)
    }
    # other single-value fields (V3-DATA-MODEL 2.8): the HIGHEST-PRIORITY deciding claim; among equal priorities the winning
    # tier claim first, then the best-placed in the trust list, then rule order (all rules default to priority 100, so
    # without a declared priority this is exactly the order before #462)
    $ordered = @(@($deciding) | Where-Object { $null -ne $_ } | Sort-Object @{ Expression = { $_.priority }; Descending = $true }, @{ Expression = { if ($_.winner) { 0 } else { 1 } } },
        @{ Expression = { $_.trust_position } }, @{ Expression = { $_.order } })
    if ($null -ne $win -and @($ordered | Where-Object { [object]::ReferenceEquals($_, $win) }).Count -eq 0) { $ordered = @(@($win) + $ordered) }   # the default rule's own values
    foreach ($f in 'si_purpose', 'si_category', 'si_cmdb_id', 'si_cmdb_name', 'si_cmdb_criticality', 'si_cmdb_data_sensitivity') {
        foreach ($c in $ordered) { if ($c.set.Contains($f)) { $Ci[$f] = $c.set[$f]; break } }
    }
    $tags = New-Object System.Collections.Generic.List[object]
    # #643 asset tagging OFF (the setting SI_AssetTagging_Enabled): the tags its rules name are taken off the CI even when a
    # provider brings them back (an earlier tagging run wrote them to Defender) -- no report then treats the device as
    # excluded because of a tagging rule. The customer's own tags are kept.
    $strip = $null
    $stripKey = '__strip_tags|' + $class
    if ($FieldCache -and $FieldCache.ContainsKey($stripKey)) { $strip = $FieldCache[$stripKey] }
    elseif (Get-Command -Name Get-SITaggingRuleTagNames -ErrorAction SilentlyContinue) {
        $strip = Get-SITaggingRuleTagNames -Rules @($Rules)
        if ($FieldCache) { $FieldCache[$stripKey] = $strip }
    }
    $stripped = 0
    foreach ($x in (Get-SIValueList $Ci['si_tags'])) {
        if ($null -ne $strip -and $strip.Count -gt 0) {
            $nm = if ($x -is [string]) { $x } else { [string](Get-SIItemValue $x 'name') }
            if ($nm -and $strip.Contains($nm.Trim())) { $stripped++; continue }
        }
        $tags.Add($x)
    }
    foreach ($c in $deciding) { if ($c.set.Contains('si_tags')) { foreach ($tg in @($c.set['si_tags'])) { $tags.Add([ordered]@{ source = 'rule'; name = [string]$tg; value = '' }) } } }
    if ($tags.Count -gt 0 -or $stripped -gt 0) { $Ci['si_tags'] = $tags.ToArray() }
    # #462 the trace: every claim with its priority, pack and the VALUES of its evidence with the provider that supplied
    # them (si_field_sources); a claim that did not decide carries what it WOULD have set
    $srcMap = Get-SIItemValue $Ci 'si_field_sources'
    $lvlText = ''
    if ($class -eq 'identity') { $lvlText = ([string](Get-SIItemValue $Ci 'si_privilege_tier_level_text')).Trim() }
    $Ci['si_tier_claims'] = @($claims | ForEach-Object {
            $c = $_
            $ev = @(foreach ($fn in @($c.evidence)) {
                    $s = Get-SIItemValue $srcMap $fn
                    $v = $Ci[$fn]
                    if ($null -ne $v -and -not ($v -is [string]) -and -not ($v -is [ValueType])) { $v = (ConvertTo-Json -InputObject $v -Compress -Depth 4) }
                    if ($v -is [string] -and $v.Length -gt 200) { $v = $v.Substring(0, 200) + '...' }
                    [ordered]@{ field = $fn; value = $v; provider = [string](Get-SIItemValue $s 'provider') }
                })
            # #579 what the explanation says about the claim: its kind (rule / tag / default), a short label, and the values
            # that matched (only for a claim on the tier: the explanation names no other)
            $kind = 'rule'; if ($c.asserted) { $kind = 'tag' } elseif ($c.fallback) { $kind = 'default' }
            $matched = @()
            if ($null -ne $c.tier -and $kind -ne 'default') {
                if ($null -ne $c.when) {
                    $matched = @(foreach ($m in @(Get-SICiConditionMatches -Condition $c.when -Item $Ci -Context $Context)) {
                            foreach ($mv in @($m.values)) {
                                # a tag as written: its name, or name=value when the tier is in the value (an Azure / Entra tag)
                                if ($kind -eq 'tag') { $n = Get-SIItemValue $mv 'name'; if ($null -ne $n -and $mv -isnot [string]) { $tv = [string](Get-SIItemValue $mv 'value'); if ($tv) { '{0}={1}' -f $n, $tv } else { [string]$n } } else { [string]$mv } }
                                else { ConvertTo-SICiEvidenceText -Field ([string]$m.field) -Value $mv }
                            }
                        }) | Select-Object -Unique -First 5
                }
                # a Tier 0 claim on an identity says how far its Tier 0 role reaches: the level inside Tier 0 with the
                # role and, for a role held on a scope only, the scope's type, name AND id (si_privilege_tier_level_text)
                if ($lvlText -and [int]$c.tier -eq 0) { $matched = @(@($lvlText) + @($matched) | Select-Object -Unique -First 5) }
            }
            # the key of the rule that made the claim ('<engine>/<rule id>', what a rule change names); '' for a claim no
            # such rule made -- a tag, a pin, a rule pack
            $e = [ordered]@{ rule = $c.rule; rule_key = [string]$c.key; name = $c.name; label = (Get-SICiClaimLabel -Set $c.set -Name ([string]$c.name) -Rule ([string]$c.rule)); kind = $kind
                stage = $c.stage; mechanism = $c.mechanism; tier = $c.tier; admissible = $c.admissible; reason = $c.reason; winner = $c.winner; evidence = $c.evidence
                matched = @($matched); priority = $c.priority; pack = $c.pack; evidence_detail = $ev }
            if (-not $c.admissible) { $e['would_set'] = $c.set }
            $e
        })
    $Ci['si_tier_explanation'] = Get-SICiTierExplanation -Ci $Ci
    # #462 testing-stage (and untrusted / stale) claims never change a value; what they WOULD change is a proposal shown
    # beside it ("testing rule X would set Tier 1")
    $props = New-Object System.Collections.Generic.List[object]
    foreach ($c in @($claims | Where-Object { -not $_.admissible -and -not $_.fallback })) {
        if ($null -ne $c.tier) {
            $cur = $Ci['si_tier']
            if ($null -eq $cur -or "$cur" -eq '' -or [int]$c.tier -lt [int]$cur) { $props.Add([ordered]@{ rule = $c.rule; stage = $c.stage; reason = $c.reason; field = 'si_tier'; current = $cur; proposed = [int]$c.tier }) }
        }
        foreach ($f in 'si_purpose', 'si_category', 'si_cmdb_id', 'si_cmdb_name', 'si_cmdb_criticality', 'si_cmdb_data_sensitivity') {
            if (-not $c.set.Contains($f)) { continue }
            $cur = $Ci[$f]
            if ([string]$cur -ne [string]$c.set[$f]) { $props.Add([ordered]@{ rule = $c.rule; stage = $c.stage; reason = $c.reason; field = $f; current = $cur; proposed = $c.set[$f] }) }
        }
    }
    if ($props.Count -gt 0) { $Ci['si_rule_proposals'] = $props.ToArray() } elseif ($Ci.Contains('si_rule_proposals')) { $Ci.Remove('si_rule_proposals') }
    if ($rulesCut) { $Ci['si_ci_rules_cut'] = [Math]::Round($budgetWatch.Elapsed.TotalSeconds, 1) }
    return $Ci
}

function New-SICiRiskFactorPlan {
    <#
        PURE. What Invoke-SICiRiskFactors reads of the factor catalog, read ONCE for a set of CIs instead of once per CI
        (2026-10-16, the CI build of a large install): every factor by id, and the asset factors it evaluates (catalog,
        enabled) in catalog order with the name, short name and impact each one writes. The same values as read per CI.
    #>
    param([Parameter(Mandatory)]$Factors)
    $byId = @{}
    foreach ($f in @($Factors.factors)) { $byId[[string]$f.id] = $f }
    $eval = New-Object System.Collections.Generic.List[object]
    foreach ($f in @($Factors.factors)) {
        if ([string]$f.appliesTo -ne 'asset' -or [string]$f.evaluatedBy -ne 'catalog' -or -not (Test-SIRiskFactorEnabled $f)) { continue }
        $eval.Add([pscustomobject]@{ F = $f; Id = [string]$f.id; ShortName = (Get-SIRiskFactorShortName $f); Name = [string]$f.name; Axis = [string]$f.axis; Impact = (Get-SIRiskFactorImpact $f) })
    }
    [pscustomobject]@{ Factors = $Factors; ById = $byId; Asset = $eval.ToArray(); CiColumns = @(Get-SIRiskFactorCiColumns -Factors $Factors) }
}

function Invoke-SICiRiskFactors {
    <# Asset risk factors + CI-level coverage checks on one CI -> si_risk_factors, si_coverage_gaps.
       -Plan: New-SICiRiskFactorPlan of the same -Factors, made once for a set of CIs (else it is made here). #>
    param([Parameter(Mandatory)]$Ci, [Parameter(Mandatory)]$Factors, $Checks, [hashtable]$Context, $Plan)
    if ($null -eq $Plan -or -not [object]::ReferenceEquals($Plan.Factors, $Factors)) { $Plan = New-SICiRiskFactorPlan -Factors $Factors }
    $out = New-Object System.Collections.Generic.List[object]
    $byId = $Plan.ById
    # #546 UNKNOWN IS NEVER A FINDING: a factor whose value the CI cannot decide (a field in si_unknown_fields, or an age /
    # number that was never read) is listed in si_rf_unknown and counted -- never raised
    $unknownFields = @(foreach ($x in @($Ci['si_unknown_fields'])) { if ($x) { [string]$x } })
    $unknownFactors = New-Object System.Collections.Generic.List[string]
    # #559 risk factor model v2: an ENABLED factor is evaluated and counts its impact (1..5) on its side of the score; a
    # disabled one is not evaluated (a built-in factor is always enabled). Each entry keeps 'axis' (the report column its
    # short name is listed in -- the reports' CI blocks read si_rf_p / si_rf_c by it) and 'stage' = production (what the
    # pre-v2 readers and the shipped CI blocks filter on), and adds shortName / side / state.
    foreach ($p in $Plan.Asset) {
        $f = $p.F
        $hit = $false
        try { $hit = Test-SIConditionTri -Condition $f.when -Item $Ci -Context $Context -UnknownFields $unknownFields } catch { $hit = $false }
        if ($null -eq $hit) { $unknownFactors.Add($p.Id); continue }
        if ($hit -ne $true) { continue }
        $out.Add([ordered]@{ id = $p.Id; shortName = $p.ShortName; name = $p.Name; axis = $p.Axis; side = 'asset'; impact = $p.Impact; state = 'enabled'; stage = 'production'; tokens = @($f.legacyTokens) })
    }
    $gaps = New-Object System.Collections.Generic.List[object]
    foreach ($ck in @($Checks.checks)) {
        if ([string]$ck.scope -ne 'ci' -or $null -eq $ck.fail) { continue }
        $failed = $false
        try { $failed = Test-SICondition -Condition $ck.fail -Item $Ci -Context $Context } catch { $failed = $false }
        if (-not $failed) { continue }
        $gaps.Add([ordered]@{ id = [string]$ck.id; name = [string]$ck.name })
        $fid = [string]$ck.riskFactor
        if ($fid -and $byId.ContainsKey($fid) -and -not @($out | Where-Object { $_.id -eq $fid }).Count -and (Test-SIRiskFactorEnabled $byId[$fid])) {
            $f = $byId[$fid]
            $out.Add([ordered]@{ id = $fid; shortName = (Get-SIRiskFactorShortName $f); name = [string]$f.name; axis = [string]$f.axis; side = (Get-SIRiskFactorSide $f); impact = (Get-SIRiskFactorImpact $f); state = 'enabled'; stage = 'production'; tokens = @($f.legacyTokens); coverage = [string]$ck.id })
        }
    }
    $Ci['si_risk_factors'] = $out.ToArray()
    if ($gaps.Count -gt 0) { $Ci['si_coverage_gaps'] = $gaps.ToArray() }
    # a factor a coverage check raised is decided, not unknown
    foreach ($e in $out) { if ($unknownFactors.Contains([string]$e.id)) { $null = $unknownFactors.Remove([string]$e.id) } }
    if ($unknownFactors.Count -gt 0) { $Ci['si_rf_unknown'] = $unknownFactors.ToArray() } elseif ($Ci.Contains('si_rf_unknown')) { $Ci.Remove('si_rf_unknown') }
    # #464: each factor's evidence (which provider / field proves it), si_rf_<id> + si_rf_count (SI-RiskFactorCatalog.ps1)
    $lists = @{}; if ($Context -and $Context.Lists) { $lists = $Context.Lists }
    $null = Add-SICiRiskFactorEvidence -Ci $Ci -Factors $Factors -Lists $lists -ById $Plan.ById -CiColumns $Plan.CiColumns
    return $Ci
}

function New-SICiCmdbIndex {
    <#
        PURE. The owning CMDB's services and CIs (the CMDB cache the profilers read: sicmdbservices / sicmdbcis) -> lookups:
        service by id; CMDB CI by Azure resource id, by Entra object id and by FQDN.
    #>
    param([AllowEmptyCollection()][object[]]$Services = @(), [AllowEmptyCollection()][object[]]$CmdbCis = @())
    $svc = @{}; $byArm = @{}; $byEntra = @{}; $byFqdn = @{}
    foreach ($s in $Services) {
        if ($null -eq $s) { continue }
        $id = [string](Get-SIItemValue $s 'id'); if (-not $id) { $id = [string](Get-SIItemValue $s 'RowKey') }
        if ($id) { $svc[$id.ToLowerInvariant()] = $s }
    }
    foreach ($c in $CmdbCis) {
        if ($null -eq $c) { continue }
        $a = [string](Get-SIItemValue $c 'azure_resource_id'); if ($a) { $byArm[$a.ToLowerInvariant()] = $c }
        $e = [string](Get-SIItemValue $c 'entra_object_id'); if ($e) { $byEntra[$e.ToLowerInvariant()] = $c }
        $f = [string](Get-SIItemValue $c 'fqdn'); if ($f) { $byFqdn[$f.ToLowerInvariant()] = $c }
    }
    return @{ Services = $svc; ByArm = $byArm; ByEntra = $byEntra; ByFqdn = $byFqdn; Count = $svc.Count + $byArm.Count + $byEntra.Count + $byFqdn.Count }
}

function New-SICiCmdbIndexFromRecords {
    <#
        PURE (#463). An EXTERNAL owner's CMDB records (provider records of type cmdb_ci, mapped by data-model/mappings/<provider>:
        si_cmdb_id, si_cmdb_name ... azure_resource_id, entra_object_id, si_fqdn) -> the same lookups as New-SICiCmdbIndex:
        by CMDB id, Azure resource id, Entra object id and FQDN. The values stay on the provider's own record; the CI gets the
        one resolved set (Set-SICiCmdb).
    #>
    param([AllowEmptyCollection()][object[]]$Records = @())
    $svc = @{}; $byArm = @{}; $byEntra = @{}; $byFqdn = @{}
    foreach ($r in $Records) {
        if ($null -eq $r) { continue }
        $id = [string](Get-SIItemValue $r 'si_cmdb_id'); if (-not $id) { $id = [string](Get-SIItemValue $r 'cmdb_record_id') }; if (-not $id) { $id = [string](Get-SIItemValue $r 'servicenow_sys_id') }
        if ($id) { $svc[$id.ToLowerInvariant()] = $r }
        foreach ($a in (Get-SIValueList (Get-SIItemValue $r 'azure_resource_id'))) { if ($a) { $byArm[([string]$a).ToLowerInvariant()] = $r } }
        foreach ($e in (Get-SIValueList (Get-SIItemValue $r 'entra_object_id'))) { if ($e) { $byEntra[([string]$e).ToLowerInvariant()] = $r } }
        $f = [string](Get-SIItemValue $r 'si_fqdn'); if ($f) { $byFqdn[$f.ToLowerInvariant()] = $r }
    }
    return @{ Services = $svc; ByArm = $byArm; ByEntra = $byEntra; ByFqdn = $byFqdn; Count = $svc.Count + $byArm.Count + $byEntra.Count + $byFqdn.Count }
}

function Set-SICiCmdb {
    <#
        The owning CMDB's record onto the CI (V3-DATA-MODEL 2.8.1 -- one CMDB truth per tenant):
          1. the CMDB id the enrichment rules set (si_cmdb_id) -> that service's name, criticality, data sensitivity,
             environment, owner, department -- each only where no rule set the field (a rule's value wins, as before)
          2. no CMDB id: a CMDB CI that carries the CI's Azure resource id or Entra object id (strong), else its FQDN (weak)
        si_cmdb_source names the owning CMDB, si_cmdb_match_rule / si_cmdb_match_confidence how the record was found.
    #>
    param([Parameter(Mandatory)]$Ci, [Parameter(Mandatory)][hashtable]$Index, [string]$CmdbOwner = 'cmdb')
    if ($Index.Count -eq 0) { return $Ci }
    $rec = $null; $rule = ''; $conf = ''
    $id = [string]$Ci['si_cmdb_id']
    if ($id -and $Index.Services.ContainsKey($id.ToLowerInvariant())) { $rec = $Index.Services[$id.ToLowerInvariant()]; $rule = 'rule'; $conf = 'strong' }
    if ($null -eq $rec -and -not $id) {
        $arm = ([string]$Ci['si_link_azure']).ToLowerInvariant()
        $ent = ([string]$Ci['si_link_entra']).ToLowerInvariant()
        $fq = ([string]$Ci['si_fqdn']).ToLowerInvariant()
        if ($arm -and $Index.ByArm.ContainsKey($arm)) { $rec = $Index.ByArm[$arm]; $rule = 'identifier'; $conf = 'strong' }
        elseif ($ent -and $Index.ByEntra.ContainsKey($ent)) { $rec = $Index.ByEntra[$ent]; $rule = 'identifier'; $conf = 'strong' }
        elseif ($fq -and $Index.ByFqdn.ContainsKey($fq)) { $rec = $Index.ByFqdn[$fq]; $rule = 'name'; $conf = 'weak' }
        if ($rec) {
            $cid = [string](Get-SIItemValue $rec 'id'); if (-not $cid) { $cid = [string](Get-SIItemValue $rec 'si_cmdb_id') }
            if ($cid) { $Ci['si_cmdb_id'] = $cid }
        }
    }
    if ($null -eq $rec) { return $Ci }
    # #463 the catalog's CMDB fields (2.8.1): the CMDB cache's names, and the SI names a CMDB RECORD carries (an external
    # owner's cmdb_ci records, New-SICiCmdbIndexFromRecords)
    $map = [ordered]@{ si_cmdb_name = @('si_cmdb_name', 'name', 'cmdbName'); si_cmdb_class = @('si_cmdb_class', 'class', 'Class', 'sys_class_name')
        si_cmdb_criticality = @('si_cmdb_criticality', 'criticality', 'Criticality'); si_cmdb_data_sensitivity = @('si_cmdb_data_sensitivity', 'dataSensitivity', 'DataSensitivity')
        si_cmdb_environment = @('si_cmdb_environment', 'environment', 'Environment'); si_cmdb_owner = @('si_cmdb_owner', 'owner', 'Owner', 'OwnerMail')
        si_cmdb_owner_department = @('si_cmdb_owner_department', 'department', 'Department'); si_cmdb_service = @('si_cmdb_service', 'service', 'serviceName', 'name')
        si_cmdb_support_group = @('si_cmdb_support_group', 'supportGroup', 'SupportGroup', 'support_group') }
    foreach ($f in $map.Keys) {
        if ($Ci.Contains($f) -and -not (Test-SIValueEmpty $Ci[$f])) { continue }        # a rule's value wins
        foreach ($k in $map[$f]) { $v = Get-SIItemValue $rec $k; if (-not (Test-SIValueEmpty $v)) { $Ci[$f] = [string]$v; break } }
    }
    if ($Ci.Contains('si_cmdb_data_sensitivity') -and $Ci['si_cmdb_data_sensitivity']) { $Ci['si_cmdb_data_sensitivity'] = ([string]$Ci['si_cmdb_data_sensitivity']).ToLowerInvariant() }
    $Ci['si_cmdb_source'] = $CmdbOwner
    $Ci['si_cmdb_match_rule'] = $rule
    $Ci['si_cmdb_match_confidence'] = $conf
    return $Ci
}

function Set-SICiCriticality {
    <# The owning CMDB's criticality -> level + factor + its source (criticality-mapping.json). #>
    param([Parameter(Mandatory)]$Ci, [Parameter(Mandatory)]$Mapping, [string]$CmdbOwner = 'cmdb')
    $factor = [double]$Mapping.defaultFactor
    $source = [ordered]@{ cmdb = $CmdbOwner; field = 'si_cmdb_criticality'; value = $null; mapping = 'default'; factor = $factor }
    $crit = [string]$Ci['si_cmdb_criticality']
    $vocab = @(Get-SIItemValue $Mapping.criticality $CmdbOwner)
    if ($crit) {
        foreach ($e in $vocab) {
            if ([string]::Equals(([string]$e.value).Trim(), $crit.Trim(), [StringComparison]::OrdinalIgnoreCase)) {
                $factor = [double]$e.factor; $Ci['si_cmdb_criticality_level'] = [string]$e.level
                $source.value = $crit; $source.mapping = 'criticality'; $source.factor = $factor
                break
            }
        }
        if (-not $Ci.Contains('si_cmdb_criticality_level')) { $source.value = $crit; $source.mapping = 'unmapped value -> default' }
    }
    # #496 INHERITED from the business services that own the CI (Set-SICiServices): their strictest criticality wins when
    # its factor is higher than the CI's own -- the CI and its findings carry the service's criticality
    $svcCrit = [string]$Ci['si_service_criticality']
    if ($svcCrit -and (Get-Command -Name Get-SICiCriticalityEntry -ErrorAction SilentlyContinue)) {
        $se = Get-SICiCriticalityEntry -Mapping $Mapping -Section 'criticality' -Value $svcCrit -Owner $CmdbOwner
        if ($se -and [double]$se.factor -gt $factor) {
            $factor = [double]$se.factor; $Ci['si_cmdb_criticality_level'] = [string]$se.level
            $source.field = 'si_service_criticality'; $source.value = $svcCrit; $source.mapping = 'criticality'; $source.factor = $factor
            $source['inherited_from'] = 'service'
        }
    }
    $sens = [string]$Ci['si_cmdb_data_sensitivity']
    $sensEntry = $null
    if ($sens) {
        foreach ($e in @(Get-SIItemValue $Mapping.dataSensitivity $CmdbOwner)) {
            if ([string]::Equals(([string]$e.value).Trim(), $sens.Trim(), [StringComparison]::OrdinalIgnoreCase)) { $sensEntry = $e; break }
        }
    }
    # #496 the services' strictest data sensitivity, when it weighs more than the CI's own
    $svcSens = [string]$Ci['si_service_data_sensitivity']
    if ($svcSens -and (Get-Command -Name Get-SICiCriticalityEntry -ErrorAction SilentlyContinue)) {
        $se = Get-SICiCriticalityEntry -Mapping $Mapping -Section 'dataSensitivity' -Value $svcSens -Owner $CmdbOwner
        if ($se -and ($null -eq $sensEntry -or [double]$se.factor -gt [double]$sensEntry.factor)) { $sensEntry = $se; $sens = $svcSens; $source['data_sensitivity_inherited_from'] = 'service' }
    }
    if ($sensEntry) {
        $sf = [double]$sensEntry.factor
        if ([string]$Mapping.combine -eq 'product') { $factor = $factor * $sf } elseif ($sf -gt $factor) { $factor = $sf }
        $source['data_sensitivity'] = $sens; $source['data_sensitivity_factor'] = $sf
    }
    if ($null -ne $Mapping.cap -and $factor -gt [double]$Mapping.cap) { $factor = [double]$Mapping.cap }
    $source.factor = $factor
    $Ci['si_criticality_factor'] = $factor
    $Ci['si_criticality_source'] = $source
    return $Ci
}

# =====================================================================================================================
#  A BATCH THAT TAKES LONG SAYS WHICH CI IT IS WORKING ON (2026-10-13)
#  Building a batch's CIs works in memory only: no database and no Azure call shows that it is running. A batch that
#  stood still for more than an hour left nothing in the log to say in which CI. The WATCH is a second thread that
#  reads where the build stands and writes ONE line whenever a step has been running for -EverySeconds (2 minutes):
#      CIs: batch 8 of 11 -- applying the rules: 812 of 1,950 CI(s) done after 4 minute(s); working on srv-app-01
#      (device, 1,204 installed software) for 130 s
#  It names a CI by its name, kind and sizes -- never a property's content. The build only notes where it stands (one
#  assignment per CI); the line is written by the watch's own thread, so it also comes when ONE CI never finishes.
#  The line goes to the process's output (the job's log), in the '[INFO] ' form of the run log. A watch that cannot be
#  started is no watch: the build runs as before.
# =====================================================================================================================
$script:SICiWatchLoopText = @'
param($w)
$said = [long]0; $seen = ''
while (-not $w.Wake.Wait([int]$w.PollMs)) {
    try {
        $w['Turns'] = [int]$w['Turns'] + 1
        $ph = $w.Phase
        if ($null -eq $ph) { continue }
        $now = [datetime]::UtcNow.Ticks
        $key = [string]$ph[0] + '|' + [string]$ph[2]
        if ($key -ne $seen) { $seen = $key; $said = [long]$ph[2] }
        if ((($now - $said) / 1e7) -lt [double]$w.Every) { continue }
        $slots = $null
        [System.Threading.Monitor]::Enter($w.Slots.SyncRoot)
        try { $slots = $w.Slots.Clone() } finally { [System.Threading.Monitor]::Exit($w.Slots.SyncRoot) }
        $done = 0; $on = New-Object System.Collections.Generic.List[string]
        foreach ($k in $slots.Keys) {
            $s = $slots[$k]; if ($null -eq $s) { continue }
            $done += [int]$s[2]
            if ([string]$s[0]) { $on.Add(('{0} for {1:N0} s' -f [string]$s[0], (($now - [long]$s[1]) / 1e7))) }
        }
        $mins = [Math]::Floor((($now - [long]$ph[2]) / 1e7) / 60)
        $line = 'CIs: ' + [string]$w.What + [string]$ph[0]
        if ([int]$ph[1] -gt 0) { $line += (': {0:N0} of {1:N0} CI(s) done after {2:N0} minute(s)' -f $done, [int]$ph[1], $mins) } else { $line += (': {0:N0} minute(s) so far' -f $mins) }
        if ($on.Count -gt 0) { $line += '; working on ' + ((@($on) | Select-Object -First 4) -join '; ') }
        $said = $now
        [void]$w.Lines.Add($line)
        if ($w.Console) { [Console]::Out.WriteLine('[INFO] ' + $line) }
    } catch { $w['Error'] = [string]$_ }
}
'@

function Start-SICiWatch {
    <#
        Starts the watch of one CI build. Answers its state (a synchronised table the build writes where it stands in), or
        $null when it could not be started. -EverySeconds: a step running this long gets a line, and one more every time
        it has run as long again. -Quiet: the lines are only kept (Lines), not written (tests).
    #>
    param([int]$EverySeconds = 120, [int]$PollMs = 5000, [switch]$Quiet)
    try {
        $w = [hashtable]::Synchronized(@{ Every = $EverySeconds; PollMs = $PollMs; What = ''; Phase = $null; Console = (-not $Quiet)
                Slots = [hashtable]::Synchronized(@{}); Lines = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
                Wake = (New-Object System.Threading.ManualResetEventSlim($false)) })
        $ps = [powershell]::Create()
        $null = $ps.AddScript($script:SICiWatchLoopText).AddArgument($w)
        $w['PowerShell'] = $ps
        $w['Handle'] = $ps.BeginInvoke()
        return $w
    } catch { return $null }
}

function Stop-SICiWatch {
    <# Ends a watch (Start-SICiWatch). Never throws; $null = nothing to end. #>
    param($Watch)
    if ($null -eq $Watch) { return }
    try { $Watch.Phase = $null; $Watch.Wake.Set() } catch { }
    try { if ($Watch.Handle -and $Watch.Handle.AsyncWaitHandle.WaitOne(3000)) { $null = $Watch.PowerShell.EndInvoke($Watch.Handle) } } catch { }
    try { $Watch.PowerShell.Dispose() } catch { }
}

function Set-SICiWatchPhase {
    <# The step the build is in now ('' = none: between steps nothing is said). -Total: the CIs of the step (0 = not counted). #>
    param($Watch, [string]$Phase = '', [int]$Total = 0)
    if ($null -eq $Watch) { return }
    try {
        $Watch.Phase = $null
        $Watch.Slots.Clear()
        if ($Phase) { $Watch.Phase = @($Phase, $Total, [datetime]::UtcNow.Ticks) }
    } catch { }
}

function Get-SICiWatchLabel {
    <#
        PURE. A CI (or one of its records) in a log line: its name, its kind and how much it carries -- never a property's
        content. 'srv-app-01 (device, 1,204 installed software)' / 'la-orders (cloud_resource, microsoft.logic/workflows)'.
    #>
    param($Item, [int]$Records = 0)
    if ($null -eq $Item) { return 'a CI' }
    $text = { param($n) $v = Get-SIItemValue $Item $n; if ($v -is [string]) { $s = ($v -replace '[\x00-\x1F]+', ' ').Trim(); if ($s.Length -gt 80) { $s = $s.Substring(0, 77) + '...' }; $s } else { '' } }
    $name = & $text 'si_asset_name'
    if (-not $name) { $name = & $text 'si_hostname' }
    if (-not $name) { $name = & $text 'si_upn' }
    if (-not $name) { $name = & $text 'si_ci_id' }
    if (-not $name) { $name = & $text 'si_record_key' }
    if (-not $name) { $name = 'a CI without a name' }
    $about = New-Object System.Collections.Generic.List[string]
    $class = & $text 'si_class'; if ($class) { $about.Add($class) }
    $kind = & $text 'si_azure_resource_type'; if (-not $kind) { $kind = & $text 'si_asset_type' }
    if ($kind -and $kind -ne $class) { $about.Add($kind) }
    if ($Records -gt 1) { $about.Add(('{0:N0} records' -f $Records)) }
    foreach ($pair in @(@('si_installed_software', 'installed software'), @('si_logged_on_users', 'logged-on users'), @('si_child_resources', 'child resources'), @('si_tags', 'tags'), @('si_group_memberships', 'groups'))) {
        $v = Get-SIItemValue $Item $pair[0]
        if ($null -ne $v -and $v -isnot [string] -and $v -is [System.Collections.ICollection] -and $v.Count -ge 50) { $about.Add(('{0:N0} {1}' -f $v.Count, $pair[1])) }
    }
    if ($about.Count -eq 0) { return $name }
    return ('{0} ({1})' -f $name, ($about.ToArray() -join ', '))
}

function Get-SICiRulesBudgetSeconds {
    <#
        PURE. How long the rules of ONE CI may take before the rest of them is left out for this run (Invoke-SICiRules
        -BudgetSeconds): SI_CiRulesBudgetSeconds, default 60 -- the normal cost is milliseconds. 0 / off = no limit.
    #>
    param($Setting = $global:SI_CiRulesBudgetSeconds)
    $s = ([string]$Setting).Trim().ToLowerInvariant()
    if (-not $s) { return 60.0 }
    if ($s -in 'off', 'false', 'no', 'none') { return 0.0 }
    $v = 0.0
    if ([double]::TryParse($s, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v) -and $v -ge 0) { return $v }
    return 60.0
}

function Get-SICiParallelism {
    <#
        How many threads the CI enrichment uses: 1 (the plain loop) on PowerShell 5.1, with one CPU, below -MinCis CIs (a
        runspace costs more than it saves), or SI_CiParallel = off; else the CPUs the job has (SI_CiParallel = <n> sets it).
    #>
    param([int]$Count, [int]$MinCis = 500, $Setting = $global:SI_CiParallel, [int]$Cpus = [Environment]::ProcessorCount, [int]$PsMajor = $PSVersionTable.PSVersion.Major)
    if ($PsMajor -lt 7 -or $Count -lt $MinCis) { return 1 }
    $s = ([string]$Setting).Trim().ToLowerInvariant()
    if ($s -in 'off', 'false', '0', 'no') { return 1 }
    $n = $Cpus; $v = 0
    if ([int]::TryParse($s, [ref]$v) -and $v -gt 0) { $n = $v }
    return [Math]::Max(1, [Math]::Min($n, 16))
}

function Initialize-SICiSharedObjects {
    <#
        THE PARALLEL THREADS READ THE SAME RULES AND MODEL OBJECTS -- and PowerShell builds an object's property list the
        first time it is asked for (.PSObject.Properties). Two threads asking for it at the same moment, the first time, can
        get NOTHING back: "Cannot index into a null array" in Get-SIItemValue / Get-SIConditionFields, and the whole batch's
        CIs are not built ("CI enrichment failed on 1 of 8 chunk(s)"). Measured 2026-10-16 on the test VM: 8 threads reading
        3,000 fresh objects failed in 30 of 30 rounds; with every object's property list asked for once on ONE thread first,
        0 of 60 (tests\fixtures\ci-perf) -- dictionaries and lists the same. So every object the threads share is asked for its property list here, once, before
        the threads start (every batch: a set of CIs brings its own indexes). It reads nothing and changes nothing.
    #>
    param([AllowEmptyCollection()][object[]]$Roots = @())
    $seen = New-Object 'System.Collections.Generic.HashSet[object]' ([System.Collections.Generic.ReferenceEqualityComparer]::Instance)
    $stack = New-Object System.Collections.Generic.Stack[object]
    foreach ($r in $Roots) { if ($null -ne $r) { $stack.Push($r) } }
    $n = 0
    while ($stack.Count -gt 0) {
        $o = $stack.Pop()
        if ($null -eq $o -or $o -is [string] -or $o -is [ValueType]) { continue }
        if (-not $seen.Add($o)) { continue }
        $n++
        # every object, not only a PSCustomObject: a dictionary and a list fail the same way (measured: 18 to 20 of 20 rounds)
        try { $null = $o.PSObject.Properties['__si_shared__'] } catch { }
        if ($o -is [System.Collections.IDictionary]) { foreach ($v in @($o.Values)) { if ($null -ne $v) { $stack.Push($v) } }; continue }
        if ($o -is [System.Management.Automation.PSCustomObject] -or ($o -is [psobject] -and $o.PSObject.BaseObject -is [System.Management.Automation.PSCustomObject])) {
            foreach ($p in $o.PSObject.Properties) { $v = $p.Value; if ($null -ne $v) { $stack.Push($v) } }
            continue
        }
        if ($o -is [System.Collections.IEnumerable]) { foreach ($v in $o) { if ($null -ne $v) { $stack.Push($v) } } }
    }
    $n
}

function Invoke-SICiEnrichment {
    <#
    .SYNOPSIS  P3 over a set of CIs: rules (tier, purpose, category, CMDB values, tags), risk factors + coverage, criticality.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Cis,
        [Parameter(Mandatory)]$Model,
        [AllowEmptyCollection()][object[]]$Rules = @(),
        [string]$CmdbOwner = 'cmdb',
        # the owning CMDB's services / CIs (New-SICiCmdbIndex); none = only what the rules set
        [hashtable]$CmdbIndex,
        [datetime]$Now = [datetime]::UtcNow,
        # #462 manual CI overrides in force (ConvertTo-SICiOverrideIndex): CiId -> overrides, applied over the rules
        [hashtable]$Overrides,
        # #496 the business services (New-SICiServiceIndex): which services own each CI and what it inherits; none = not set
        [hashtable]$ServiceIndex,
        # the build's watch (Start-SICiWatch): where the step stands, so a step that takes long says which CI it is working on
        $Watch
    )
    . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1')
    # the customer's exposed network ranges (SI_InternetExposedRanges) join the internet_exposed_ranges list (#458)
    $ctx = @{ Lists = (Merge-SIRiskFactorRanges -Lists (Get-SIDataModelListContext $Model)); Now = $Now }
    $trust = Get-SICiTrustIndex $Model['trust']
    $byClass = Get-SICiRulesByClass -Rules $Rules
    # #496 the environments, strictest first (the list service_environment_order)
    $envOrder = [string[]]@()
    if ($ServiceIndex) { $el = $ctx.Lists['service_environment_order']; if ($el) { $envOrder = [string[]]@(@($el.values) | Where-Object { $_ } | ForEach-Object { [string]$_ }) } }
    # PowerShell 7 with more than one CPU: the CIs in chunks on parallel threads (each its own runspace with these files
    # loaded and its own field cache; a CI is only ever touched by one thread). 5.1 / one CPU: the loop below.
    $budget = Get-SICiRulesBudgetSeconds
    $threads = Get-SICiParallelism -Count @($Cis).Count
    Set-SICiWatchPhase -Watch $Watch -Phase 'applying the rules, the services and the risk factors' -Total @($Cis).Count
    if ($threads -gt 1) {
        $size = [int][Math]::Ceiling(@($Cis).Count / ($threads * 4))
        $chunks = New-Object System.Collections.Generic.List[object]
        for ($i = 0; $i -lt $Cis.Count; $i += $size) { $chunks.Add(@($Cis[$i..([Math]::Min($i + $size, $Cis.Count) - 1)])) }
        $dir = $PSScriptRoot
        # every object the threads share has its property list made here, on this thread (Initialize-SICiSharedObjects)
        $null = Initialize-SICiSharedObjects -Roots @($Rules, $Model, $ctx, $trust, $byClass, $Overrides, $CmdbIndex, $ServiceIndex, $envOrder)
        # the watch is shared too (its own thread is already running: only the two tables the threads write are prepared)
        if ($Watch) { try { $null = $Watch.PSObject.Properties['__si_shared__']; $null = $Watch.Slots.PSObject.Properties['__si_shared__'] } catch { } }
        # built from text: PowerShell 5.1 never parses a using-variable block it cannot run
        $body = [scriptblock]::Create(@'
try {
    . (Join-Path $using:dir 'SI-CiEnrich.ps1')
    . (Join-Path $using:dir 'SI-DataModelTemplates.ps1')
    $fc = @{}
    $rfPlan = New-SICiRiskFactorPlan -Factors ($using:Model)['risk-factors']
    $w = $using:Watch; $slot = [guid]::NewGuid().ToString('N'); $n = 0
    foreach ($ci in $_) {
        if ($w) { $w.Slots[$slot] = @((Get-SICiWatchLabel $ci), [datetime]::UtcNow.Ticks, $n) }
        $null = Set-SICiBreakGlass -Ci $ci -Context $using:ctx
        $null = Invoke-SICiRules -Ci $ci -Rules $using:Rules -Trust $using:trust -Context $using:ctx -Now $using:Now -RulesByClass $using:byClass -FieldCache $fc -BudgetSeconds $using:budget
        if ($using:Overrides) { $null = Set-SICiOverrides -Ci $ci -Index $using:Overrides }
        if ($using:CmdbIndex) { $null = Set-SICiCmdb -Ci $ci -Index $using:CmdbIndex -CmdbOwner $using:CmdbOwner }
        if ($using:ServiceIndex) { $null = Set-SICiServices -Ci $ci -Index $using:ServiceIndex -Mapping ($using:Model)['criticality-mapping'] -EnvironmentOrder $using:envOrder -CmdbOwner $using:CmdbOwner }
        $null = Set-SICiCriticality -Ci $ci -Mapping ($using:Model)['criticality-mapping'] -CmdbOwner $using:CmdbOwner
        $null = Invoke-SICiRiskFactors -Ci $ci -Factors ($using:Model)['risk-factors'] -Checks ($using:Model)['coverage-checks'] -Context $using:ctx -Plan $rfPlan
        $n++
    }
    if ($w) { $w.Slots[$slot] = @('', [datetime]::UtcNow.Ticks, $n) }
} catch { [pscustomobject]@{ SIEnrichError = ('{0} (at {1})' -f $_.Exception.Message, ((([string]$_.ScriptStackTrace) -split "`n")[0]).Trim()) } }
'@)
        $failed = @($chunks | ForEach-Object -ThrottleLimit $threads -Parallel $body | Where-Object { $_ -and $_.PSObject.Properties['SIEnrichError'] })
        if ($failed.Count -gt 0) { throw ('CI enrichment failed on {0} of {1} chunk(s): {2}' -f $failed.Count, $chunks.Count, $failed[0].SIEnrichError) }
        return , $Cis
    }
    $fieldCache = @{}
    $rfPlan = New-SICiRiskFactorPlan -Factors $Model['risk-factors']
    $n = 0
    foreach ($ci in $Cis) {
        if ($Watch) { $Watch.Slots['main'] = @((Get-SICiWatchLabel $ci), [datetime]::UtcNow.Ticks, $n) }
        $n++
        $null = Set-SICiBreakGlass -Ci $ci -Context $ctx
        $null = Invoke-SICiRules -Ci $ci -Rules $Rules -Trust $trust -Context $ctx -Now $Now -RulesByClass $byClass -FieldCache $fieldCache -BudgetSeconds $budget
        if ($Overrides) { $null = Set-SICiOverrides -Ci $ci -Index $Overrides }
        if ($CmdbIndex) { $null = Set-SICiCmdb -Ci $ci -Index $CmdbIndex -CmdbOwner $CmdbOwner }
        if ($ServiceIndex) { $null = Set-SICiServices -Ci $ci -Index $ServiceIndex -Mapping $Model['criticality-mapping'] -EnvironmentOrder $envOrder -CmdbOwner $CmdbOwner }
        $null = Set-SICiCriticality -Ci $ci -Mapping $Model['criticality-mapping'] -CmdbOwner $CmdbOwner
        $null = Invoke-SICiRiskFactors -Ci $ci -Factors $Model['risk-factors'] -Checks $Model['coverage-checks'] -Context $ctx -Plan $rfPlan
    }
    return , $Cis
}
