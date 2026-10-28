#Requires -Version 5.1
<#
    SecurityInsight CI RULES -- the generic enrichment rule model run ON THE CI (#462, V3-DATA-MODEL 2.8 / 2.19.2).

      NATIVE RULES   rule packs in the design's own shape, over SI FIELDS only (a rule never names a provider):
                       data-model/rules/<Pack>.locked.yaml                (shipped)
                       data-model/rules/<Pack>.custom.yaml                (the customer's, beside it)
                       <SI_DataModelOverlayRoot>/rules/<Pack>.custom.yaml (the operator overlay -- wins)
                     (data-model/, not asset-profiling-enrichment/: those folders hold the AssetProfileBy* rule files that the
                     profilers, the Pro template packs and the rule lint read in their own shape)
                     rules:
                       - id: domain-controllers
                         stage: production            # production | testing | not_used
                         priority: 100                # a single-value field: the highest-priority deciding rule wins
                         applies_to: [ device ]       # device | identity | cloud_resource | public_ip
                         mechanism: eg.graph_field    # the trust-list entry the evidence belongs to (default name.pattern)
                         when:
                           any:
                             - si_device_roles: { contains: domain_controller }
                             - si_installed_software: { like: "*active directory domain services*" }
                         set: { si_tier: 0, si_purpose: Domain controller, si_tags: [ AD-Tier0 ] }
                     A condition is `<si field>: { <op>: <value> }` (ops: Get-SIConditionOps, the closed set) or
                     `<si field>: <value>` (eq). The override grain is ONE RULE: a custom rule with a shipped id
                     replaces it; `stage: not_used` turns it off. The result is the same CI-rule shape the converted
                     AssetProfileBy* rules have (ConvertTo-SICiRules), evaluated by the same Invoke-SICiRules.
      ASSET TAGGING  the tagging engine's auto-exclusion tags (AssetTagging.locked.yaml: KQL against Defender) expressed
                     as a native pack (data-model/rules/AssetTagging.locked.yaml) over si_onboarding_status / si_asset_name, so the CI
                     carries the same tag the engine writes; its per-rule switches (config/asset-tagging.config.json
                     AutoExcludeRules.*) and the device-name patterns are honoured (Get-SIAssetTaggingCiRules).
      OVERRIDES      a manual CI override (Admin, with a reason and an optional expiry; precedence 1 in 2.8) --
                     sidata.CiOverride in the install database (both editions have one, #477). Applied after the rules:
                     si_tier -> si_tier_set_by = override. Every override in force is listed on the CI (si_overrides).

    PURE except Get-SICiNativeRules / Get-SIAssetTaggingCiRules (read rule files) and Read-SICiOverrides (one SQL read).
    PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

if (-not (Get-Command -Name Test-SICondition -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-Conditions.ps1') }

function ConvertTo-SICiNativeCondition {
    <#
        PURE. A design-shape condition -> the closed condition language ({ field; op; value } / { any } / { all }).
          { any: [ ... ] } / { all: [ ... ] }      groups (nested)
          { si_x: { op: value } }                 one leaf per op key (several keys = all of them)
          { si_x: value }                         eq
        Throws on an operation outside Get-SIConditionOps or a field that is not an SI field (si_ / properties.).
    #>
    param([Parameter(Mandatory)]$When, [string]$RuleId = '')
    $ops = Get-SIConditionOps
    $keys = @()
    if ($When -is [System.Collections.IDictionary]) { $keys = @($When.Keys | ForEach-Object { [string]$_ }) } else { $keys = @($When.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($g in 'any', 'all') {
        if ($keys -contains $g) {
            $items = @(foreach ($c in (Get-SIValueList (Get-SIItemValue $When $g))) { if ($null -ne $c) { ConvertTo-SICiNativeCondition -When $c -RuleId $RuleId } })
            $o = [ordered]@{}; $o[$g] = $items; return $o
        }
    }
    $leaves = New-Object System.Collections.Generic.List[object]
    foreach ($f in $keys) {
        if ($f -cnotmatch '^(si_[a-z0-9_]+|properties\..+)$') { throw ("rule '{0}': '{1}' is not an SI field -- a rule reads SI fields only, never a provider column" -f $RuleId, $f) }
        $spec = Get-SIItemValue $When $f
        $isMap = ($spec -is [System.Collections.IDictionary]) -or ($spec -is [System.Management.Automation.PSCustomObject])
        if (-not $isMap) {
            # a list is "one of these" (in), a single value is eq
            if ($spec -is [System.Collections.IEnumerable] -and -not ($spec -is [string])) { $leaves.Add([ordered]@{ field = $f; op = 'in'; value = @($spec) }) }
            else { $leaves.Add([ordered]@{ field = $f; op = 'eq'; value = $spec }) }
            continue
        }
        $sk = @(); if ($spec -is [System.Collections.IDictionary]) { $sk = @($spec.Keys | ForEach-Object { [string]$_ }) } else { $sk = @($spec.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($op in $sk) {
            if ($ops -notcontains $op) { throw ("rule '{0}': '{1}' uses '{2}', which is not a condition operation ({3})" -f $RuleId, $f, $op, ($ops -join ', ')) }
            $leaves.Add([ordered]@{ field = $f; op = $op; value = (Get-SIItemValue $spec $op) })
        }
    }
    if ($leaves.Count -eq 1) { return $leaves[0] }
    return [ordered]@{ all = $leaves.ToArray() }
}

function ConvertTo-SICiNativeRule {
    <#
        PURE. One native rule item -> a CI rule (the shape ConvertTo-SICiRules gives, so Invoke-SICiRules evaluates both).
        -Pack: the pack (file) it came from; -Order: its place in the rule order.
    #>
    param([Parameter(Mandatory)]$Item, [string]$Pack = '', [int]$Order = 0, [string]$File = '', [int]$DefaultPriority = 100)
    $id = [string](Get-SIItemValue $Item 'id')
    if (-not $id) { throw ("a rule in pack '{0}' has no id" -f $Pack) }
    $stage = ([string](Get-SIItemValue $Item 'stage')).Trim().ToLowerInvariant(); if (-not $stage) { $stage = 'production' }
    if ($stage -notin 'production', 'testing', 'not_used') { throw ("rule '{0}': stage '{1}' (production | testing | not_used)" -f $id, $stage) }
    # a rule without its own priority takes its pack's (Get-SIRulePackHeader; 100 when the pack names none)
    $prio = $DefaultPriority; $pv = Get-SIItemValue $Item 'priority'; if ($null -ne $pv -and [string]$pv -match '^-?\d+$') { $prio = [int]$pv }
    $classes = @((Get-SIValueList (Get-SIItemValue $Item 'applies_to')).ToArray() | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ })
    foreach ($c in $classes) { if ($c -notin 'device', 'identity', 'cloud_resource', 'public_ip') { throw ("rule '{0}': applies_to '{1}' (device | identity | cloud_resource | public_ip)" -f $id, $c) } }
    if ($classes.Count -eq 0) { $classes = @('device', 'identity', 'cloud_resource', 'public_ip') }
    $whenRaw = Get-SIItemValue $Item 'when'
    if ($null -eq $whenRaw) { throw ("rule '{0}' has no when" -f $id) }
    $when = ConvertTo-SICiNativeCondition -When $whenRaw -RuleId $id
    if (-not ($when.Contains('any') -or $when.Contains('all'))) { $when = [ordered]@{ all = @($when) } }
    $set = [ordered]@{}
    $rawSet = Get-SIItemValue $Item 'set'
    if ($null -ne $rawSet) {
        $sk = @(); if ($rawSet -is [System.Collections.IDictionary]) { $sk = @($rawSet.Keys | ForEach-Object { [string]$_ }) } else { $sk = @($rawSet.PSObject.Properties | ForEach-Object { $_.Name }) }
        foreach ($k in $sk) {
            if ($k -cnotmatch '^si_[a-z0-9_]+$') { throw ("rule '{0}': set '{1}' is not an SI field" -f $id, $k) }
            $v = Get-SIItemValue $rawSet $k
            if ($k -eq 'si_tags') { $set[$k] = @((Get-SIValueList $v).ToArray() | ForEach-Object { [string]$_ }); continue }
            if ($k -eq 'si_tier') { $t = 0; if (-not [int]::TryParse([string]$v, [ref]$t) -or $t -lt 0 -or $t -gt 3) { throw ("rule '{0}': si_tier '{1}' (0-3)" -f $id, $v) }; $set[$k] = $t; continue }
            $set[$k] = $v
        }
    }
    if ($set.Count -eq 0) { throw ("rule '{0}' sets nothing" -f $id) }
    $mech = [string](Get-SIItemValue $Item 'mechanism'); if (-not $mech) { $mech = 'name.pattern' }
    $os = @((Get-SIValueList (Get-SIItemValue $Item 'os_scope')).ToArray() | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ })
    $ex = @((Get-SIValueList (Get-SIItemValue $Item 'exclude')).ToArray() | ForEach-Object { [string]$_ } | Where-Object { $_ })
    $name = [string](Get-SIItemValue $Item 'name'); if (-not $name) { $name = $id }
    [pscustomobject][ordered]@{
        id = $id; family = 'ci'; file = $File; name = $name; stage = $stage; priority = $prio; pack = $Pack; order = $Order; classes = $classes; osScope = $os
        fallback = $false; mechanism = $mech; when = $when; set = $set; exclude = $ex; native = $true
    }
}

function Merge-SICiNativeRuleItems {
    <#
        PURE. Rule items of one pack, shipped then custom (then overlay): the override grain is ONE RULE -- a later item with
        the same id replaces the earlier one in its place; a new id is added at the end.
    #>
    param([AllowEmptyCollection()][object[]]$Layers = @())
    $order = New-Object System.Collections.Generic.List[string]
    $by = @{}
    foreach ($layer in $Layers) {
        foreach ($it in @($layer)) {
            if ($null -eq $it) { continue }
            $id = [string](Get-SIItemValue $it 'id'); if (-not $id) { continue }
            if (-not $by.ContainsKey($id)) { $order.Add($id) }
            $by[$id] = $it
        }
    }
    foreach ($id in $order) { $by[$id] }
}

# ---------------------------------------------------------------------------------------------------
# Rule PACKS (#462 GUI): one pack = one rule file. Besides its rules a pack carries a header -- its stage, whether it is
# on, its default priority and where it came from -- so a whole pack is turned on or off, or promoted from testing to
# live, in one decision:
#   name / description   what the pack is for (shown on the Rule packs page)
#   stage                production (live) | testing: a testing pack's rules only PROPOSE (si_rule_proposals)
#   enabled              false = every rule of the pack is not_used
#   priority             the priority of a rule that names none (default 100)
#   source               shipped (SecurityInsight) | invardia (delivered through the template channel) | customer
# An Invardia pack is NOT auto-imported: it arrives switched off and, once an Admin stages it, as testing -- it decides
# only when an Admin promotes it to live (Pro: a cfg.ItemOverride on its header, 'rules/<pack>'; Community: the same keys
# at the top of <Pack>.custom.yaml).
# ---------------------------------------------------------------------------------------------------

function Get-SIRulePackKey {
    <# PURE. The data-model template name of a pack ('rules/<lower-case pack>'): what the Pro rows and overrides key on. #>
    param([Parameter(Mandatory)][string]$Pack)
    $k = ($Pack.ToLowerInvariant() -replace '[^a-z0-9_\-]', '')
    if (-not $k) { throw ("rule pack '{0}' has no usable name" -f $Pack) }
    if ($k.Length -gt 60) { $k = $k.Substring(0, 60) }
    'rules/' + $k
}

function Get-SIRulePackHeader {
    <#
        PURE. A pack's header from its document layers (shipped, then custom / overlay / the Pro override: a later layer's
        key wins). Returns @{ pack; name; description; stage; enabled; priority; source }. An Invardia pack defaults to
        switched off and testing (never auto-imported).
    #>
    param([Parameter(Mandatory)][string]$Pack, [AllowEmptyCollection()][object[]]$Layers = @())
    $h = [ordered]@{ pack = $Pack; name = $Pack; description = ''; stage = ''; enabled = $null; priority = 100; source = 'shipped' }
    foreach ($l in @($Layers)) {
        if ($null -eq $l) { continue }
        foreach ($k in 'name', 'description', 'source') { $v = Get-SIItemValue $l $k; if ($null -ne $v -and [string]$v -ne '') { $h[$k] = [string]$v } }
        $st = Get-SIItemValue $l 'stage'; if ($null -ne $st -and [string]$st -ne '') { $h.stage = ([string]$st).Trim().ToLowerInvariant() }
        $en = Get-SIItemValue $l 'enabled'; if ($null -ne $en -and [string]$en -ne '') { $h.enabled = ((ConvertTo-SIBoolOrNull $en) -eq $true) }
        $pr = Get-SIItemValue $l 'priority'; if ($null -ne $pr -and [string]$pr -match '^-?\d+$') { $h.priority = [int]$pr }
    }
    $h.source = ([string]$h.source).Trim().ToLowerInvariant(); if ($h.source -notin 'shipped', 'invardia', 'customer') { $h.source = 'shipped' }
    if ($h.stage -eq 'live') { $h.stage = 'production' }
    if (-not $h.stage) { if ($h.source -eq 'invardia') { $h.stage = 'testing' } else { $h.stage = 'production' } }
    if ($h.stage -notin 'production', 'testing') { $h.stage = 'testing' }   # an unknown stage never decides
    if ($null -eq $h.enabled) { $h.enabled = ($h.source -ne 'invardia') }
    $h
}

function Set-SIRulePackState {
    <#
        PURE. A pack's header applied to its converted rules: switched off -> every rule not_used; a testing pack -> its
        production rules become testing (they propose, never decide). A rule's own not_used / testing stays.
    #>
    param([AllowEmptyCollection()][object[]]$Rules = @(), [Parameter(Mandatory)]$Header)
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        if (-not $Header.enabled) { $r.stage = 'not_used' }
        elseif ($Header.stage -eq 'testing' -and $r.stage -eq 'production') { $r.stage = 'testing' }
        $r
    }
}

function Get-SICiNativeRules {
    <#
        The native rule packs -> CI rules. -Root: the solution root (default: two folders up); -OverlayRoot: the operator
        overlay (default $global:SI_DataModelOverlayRoot); -ProRoot: Pro's run data model exported from the settings
        database (default $global:SI_DataModelRoot) -- a pack it holds (rules/<pack>.locked.json: the published pack with
        the customer's overrides) replaces the file layers of that pack. A pack that does not parse, or a rule that is not
        valid, is SKIPPED with a warning naming it -- the other rules still run. Every pack's header (stage, on / off,
        priority) is applied to its rules (Set-SIRulePackState).
        Returns @{ Rules; Problems; Packs (pack -> header) }.
    #>
    param([string]$Root, [string]$OverlayRoot = $global:SI_DataModelOverlayRoot, [int]$StartOrder = 100000, [string]$ProRoot = $global:SI_DataModelRoot)
    if (-not (Get-Command -Name ConvertFrom-SIYaml -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-Yaml.ps1') }
    if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
    $dirs = @([System.IO.Path]::Combine($Root, 'data-model', 'rules'))
    $packs = [ordered]@{}
    $heads = @{}
    $problems = New-Object System.Collections.Generic.List[string]
    $read = {
        param([string]$Path, [string]$Pack)
        try {
            $y = ConvertFrom-SIYaml -Yaml ([System.IO.File]::ReadAllText($Path)) -SourceName $Path
            if (-not $heads.ContainsKey($Pack)) { $heads[$Pack] = New-Object System.Collections.Generic.List[object] }
            $heads[$Pack].Add($y)
            return @(Get-SIValueList (Get-SIItemValue $y 'rules'))
        }
        catch { $problems.Add(('{0}: does not parse -- {1}' -f [System.IO.Path]::GetFileName($Path), $_.Exception.Message)); return @() }
    }
    foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        foreach ($f in @(Get-ChildItem -LiteralPath $d -File -Filter '*.locked.yaml' | Sort-Object Name)) { $p = $f.Name -replace '\.locked\.yaml$', ''; $packs[$p] = @(, (& $read $f.FullName $p)) }
        foreach ($f in @(Get-ChildItem -LiteralPath $d -File -Filter '*.custom.yaml' | Sort-Object Name)) { $p = $f.Name -replace '\.custom\.yaml$', ''; if (-not $packs.Contains($p)) { $packs[$p] = @() }; $packs[$p] = @($packs[$p]) + @(, (& $read $f.FullName $p)) }
    }
    if ($OverlayRoot) {
        $od = [System.IO.Path]::Combine($OverlayRoot, 'rules')
        if (Test-Path -LiteralPath $od) {
            foreach ($f in @(Get-ChildItem -LiteralPath $od -File -Filter '*.custom.yaml' | Sort-Object Name)) { $p = $f.Name -replace '\.custom\.yaml$', ''; if (-not $packs.Contains($p)) { $packs[$p] = @() }; $packs[$p] = @($packs[$p]) + @(, (& $read $f.FullName $p)) }
        }
    }
    # Pro: a pack the settings database holds (published + overridden in SQL, no custom files) replaces its file layers
    if ($ProRoot) {
        $pd = [System.IO.Path]::Combine($ProRoot, 'rules')
        if (Test-Path -LiteralPath $pd) {
            foreach ($f in @(Get-ChildItem -LiteralPath $pd -File -Filter '*.locked.json' | Sort-Object Name)) {
                try {
                    $doc = [System.IO.File]::ReadAllText($f.FullName).TrimStart([char]0xFEFF) | ConvertFrom-Json
                    $p = [string](Get-SIItemValue $doc 'pack'); if (-not $p) { $p = $f.Name -replace '\.locked\.json$', '' }
                    foreach ($k in @($packs.Keys)) { if ([string]$k -ieq $p) { $packs.Remove($k) } }
                    foreach ($k in @($heads.Keys)) { if ([string]$k -ieq $p) { $heads.Remove($k) } }
                    # one layer = the rules (Get-SIValueList returns ONE list: @() around it made the layer a single item)
                    $packs[$p] = @(, (Get-SIValueList (Get-SIItemValue $doc 'rules')).ToArray())
                    $heads[$p] = New-Object System.Collections.Generic.List[object]; $heads[$p].Add($doc)
                } catch { $problems.Add(('{0}: does not parse -- {1}' -f $f.Name, $_.Exception.Message)) }
            }
        }
    }
    $rules = New-Object System.Collections.Generic.List[object]
    $packHeads = [ordered]@{}
    $order = $StartOrder
    foreach ($p in $packs.Keys) {
        $hl = @(); if ($heads.ContainsKey($p)) { $hl = $heads[$p].ToArray() }
        $head = Get-SIRulePackHeader -Pack $p -Layers $hl
        $packHeads[$p] = $head
        $conv = New-Object System.Collections.Generic.List[object]
        foreach ($it in @(Merge-SICiNativeRuleItems -Layers @($packs[$p]))) {
            $order++
            try { $conv.Add((ConvertTo-SICiNativeRule -Item $it -Pack $p -Order $order -File ("data-model/rules/{0}" -f $p) -DefaultPriority ([int]$head.priority))) }
            catch { $problems.Add(('{0}: {1}' -f $p, $_.Exception.Message)) }
        }
        foreach ($r in @(Set-SIRulePackState -Rules $conv.ToArray() -Header $head)) { $rules.Add($r) }
    }
    foreach ($x in $problems) { Write-Warning ("CI rules: {0} -- skipped; the other rules run." -f $x) }
    @{ Rules = $rules.ToArray(); Problems = $problems.ToArray(); Packs = $packHeads }
}

function Get-SIAssetTaggingCiRules {
    <#
        The tagging engine's switches and device-name patterns applied to the AssetTagging pack's CI rules (#462):
          * a rule with `config_flag: AutoExcludeRules.<X>` is used ONLY when the tagging config sets that flag true -- no
            config file, no flag, or anything but true = not_used. Every one of these rules writes an EXCLUSION tag
            (<bucket>--Excluded--SI), and every report drops a CI that carries one, so an exclusion is the customer's choice,
            never a default. The same rule as the tagging engine (AssetTagging.ps1 Test-TaggingConfigFlag: missing = false)
            and the shipped sample (every switch false). #643: this used to read "no file = on" -- from the 10-12 CI build on,
            every device CI whose onboarding status read "can be onboarded" (774 of 1,890 at a large install, 704 of them
            onboarded in Defender) carried Auto-CanBeOnboarded--Excluded--SI and left every report, although nobody had chosen it;
          * the name-pattern rule (`config_patterns: DeviceNamePatterns`) gets its condition from the config's
            StartsWith / Contains / MatchesRegex lists (any of them); with no pattern configured it stays not_used --
            on a CI a rule that matches every device would tag every device.
          * ABOVE ALL OF IT: the customer setting "Asset tagging" (SI_AssetTagging_Enabled, owner 2026-10-13: "tagging must be
            disabled by default. customer must enable it in settings"). Not a real true = EVERY rule of the pack is not_used,
            whatever the switches say, and each carries strip_tags = $true: the CI build then also takes the tags these
            rules name off the CI when a provider brings them back (a tag an earlier tagging run wrote to Defender) -- off
            means no report treats a device as excluded because of a tagging rule. A customer's own tags are untouched.
        -Rules: the CI rules (Get-SICiNativeRules); -Config: the parsed asset-tagging.config.json (or $null); -Enabled: the
        setting SI_AssetTagging_Enabled. Returns the rules.
    #>
    param([AllowEmptyCollection()][object[]]$Rules = @(), $Config, [hashtable]$RawItems = @{}, [AllowNull()]$Enabled = $global:SI_AssetTagging_Enabled)
    $taggingOn = Test-SIAssetTaggingEnabled -Value $Enabled
    foreach ($r in $Rules) {
        if ($null -eq $r -or [string]$r.pack -ne 'AssetTagging') { $r; continue }
        if (-not $taggingOn) {
            $r.stage = 'not_used'
            if ($r.PSObject.Properties['strip_tags']) { $r.strip_tags = $true } else { Add-Member -InputObject $r -NotePropertyName 'strip_tags' -NotePropertyValue $true }
            $r; continue
        }
        $raw = $RawItems[[string]$r.id]
        $flag = [string](Get-SIItemValue $raw 'config_flag')
        if ($flag) {
            $on = $false
            if ($null -ne $Config) {
                $v = $Config
                foreach ($part in $flag.Split('.')) { $v = Get-SIItemValue $v $part }
                $on = ($null -ne $v -and (ConvertTo-SIBoolOrNull $v) -eq $true)
            }
            if (-not $on) { $r.stage = 'not_used' }
        }
        if ([string](Get-SIItemValue $raw 'config_patterns') -eq 'DeviceNamePatterns') {
            $np = Get-SIItemValue $Config 'DeviceNamePatterns'
            $leaves = New-Object System.Collections.Generic.List[object]
            foreach ($s in (Get-SIValueList (Get-SIItemValue $np 'StartsWith'))) { if ($s) { $leaves.Add([ordered]@{ field = 'si_asset_name'; op = 'like'; value = ([string]$s + '*') }) } }
            foreach ($s in (Get-SIValueList (Get-SIItemValue $np 'Contains'))) { if ($s) { $leaves.Add([ordered]@{ field = 'si_asset_name'; op = 'like'; value = ('*' + [string]$s + '*') }) } }
            foreach ($s in (Get-SIValueList (Get-SIItemValue $np 'MatchesRegex'))) { if ($s) { $leaves.Add([ordered]@{ field = 'si_asset_name'; op = 'matches'; value = [string]$s }) } }
            if ($leaves.Count -eq 0) { $r.stage = 'not_used' } else { $r.when = [ordered]@{ any = $leaves.ToArray() } }
        }
        $r
    }
}

function Test-SIAssetTaggingEnabled {
    <# PURE. The customer setting "Asset tagging" (SI_AssetTagging_Enabled): ONLY a real true turns it on -- $true, 'true',
       '$true' or 1. Missing, empty, false or anything else = off (the shipped default, #643). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    return ("$Value".Trim().Trim('$').ToLowerInvariant() -in @('true', '1'))
}

function Get-SITaggingRuleTagNames {
    <# PURE. The tags the asset-tagging rules that are switched off by the setting name (strip_tags) -- what the CI build
       takes off a CI while asset tagging is off. A HashSet, case-insensitive. #>
    param([AllowEmptyCollection()][object[]]$Rules = @())
    $names = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $Rules) {
        if ($null -eq $r -or -not $r.PSObject.Properties['strip_tags'] -or -not [bool]$r.strip_tags) { continue }
        $set = $r.set
        if ($null -ne $set -and $set.Contains('si_tags')) { foreach ($t in @($set['si_tags'])) { if ($t) { [void]$names.Add([string]$t) } } }
    }
    , $names
}

function Read-SIAssetTaggingConfig {
    <# The tagging engine's config (config/asset-tagging.config.json), or $null when there is none / it does not parse. #>
    param([string]$Root)
    if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
    $p = [System.IO.Path]::Combine($Root, 'config', 'asset-tagging.config.json')
    if ($global:SI_ProConfigRoot) { $pp = [System.IO.Path]::Combine([string]$global:SI_ProConfigRoot, 'asset-tagging.config.json'); if (Test-Path -LiteralPath $pp) { $p = $pp } }
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    try { return ([System.IO.File]::ReadAllText($p) | ConvertFrom-Json) } catch { Write-Warning ("CI rules: {0} does not parse -- the tagging switches are the defaults." -f $p); return $null }
}

function Get-SICiAllNativeRules {
    <# Every native CI rule, with the tagging switches applied. Returns @{ Rules; Problems }. #>
    param([string]$Root, [string]$OverlayRoot = $global:SI_DataModelOverlayRoot)
    $n = Get-SICiNativeRules -Root $Root -OverlayRoot $OverlayRoot
    $raw = @{}
    if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
    $atFile = [System.IO.Path]::Combine($Root, 'data-model', 'rules', 'AssetTagging.locked.yaml')
    if (Test-Path -LiteralPath $atFile) {
        try { foreach ($it in (Get-SIValueList (Get-SIItemValue (ConvertFrom-SIYaml -Yaml ([System.IO.File]::ReadAllText($atFile)) -SourceName $atFile) 'rules'))) { $raw[[string](Get-SIItemValue $it 'id')] = $it } } catch { }
    }
    $rules = @(Get-SIAssetTaggingCiRules -Rules @($n.Rules) -Config (Read-SIAssetTaggingConfig -Root $Root) -RawItems $raw)
    @{ Rules = $rules; Problems = @($n.Problems); Packs = $n.Packs }
}

# ---------------------------------------------------------------------------------------------------
# The operator's tier tag (the profile's tenant_si_manual_tag contributor) on the CI
# ---------------------------------------------------------------------------------------------------

$script:SICiDefaultTierTagPattern = '(?i)tier[_-]?(?<tier>[0-3])(--SI)?'

function ConvertTo-SICiTagTierRules {
    <#
        PURE. The operator's tier tag (e.g. EmployeeWorkstations--tier2--SI) as CI rules: one rule per tier 0..3, each matching
        si_tags with the schema's tagPattern narrowed to that tier (its named group `tier` replaced by the digit). The profile
        has done this since 2.3.6 (Get-SITierFromAssetTags); without it on the CI a device tagged tier 2 got the default
        tier 3 and fell out of the tier-filtered reports.
        Owner: "tags must continue to be used, just low prio" -- so every rule is ASSERTED (Invoke-SICiRules: it decides only
        when no observed rule claims a tier, and always beats the default rule) and its mechanism, operator.tier_tag, is last
        in the trust list. Several tier tags on one device: MIN, as everywhere else.
        Devices only (the endpoint schema declares the contributor). A pattern without a `tier` group, or one that is not a
        valid regex, gives no rules and a warning -- never a rule that matches every device.
    #>
    param([AllowNull()][string]$TagPattern, [int]$StartOrder = 900000)
    if ([string]::IsNullOrWhiteSpace($TagPattern)) { $TagPattern = $script:SICiDefaultTierTagPattern }
    try { $null = New-Object System.Text.RegularExpressions.Regex($TagPattern) }
    catch { Write-Warning ("CI rules: the tier tag pattern '{0}' is not a valid regex ({1}) -- tier tags are not used." -f $TagPattern, $_.Exception.Message); return @() }
    $group = New-Object System.Text.RegularExpressions.Regex('\(\?(?:<tier>|''tier'')(?:\\.|\[(?:\\.|[^\]\\])*\]|[^()\\])*\)')
    if (-not $group.IsMatch($TagPattern)) { Write-Warning ("CI rules: the tier tag pattern '{0}' has no (?<tier>...) group -- tier tags are not used." -f $TagPattern); return @() }
    $order = $StartOrder
    foreach ($t in 0..3) {
        $order++
        $pat = $group.Replace($TagPattern, ('(?<tier>{0})' -f $t), 1)
        [pscustomobject][ordered]@{
            id = ('operator-tier-tag/tier{0}' -f $t); family = 'ci'; file = 'asset-profiling-schema/endpoint.schema (tenant_si_manual_tag)'
            name = ('Operator tier tag: tier {0}' -f $t); stage = 'production'; priority = 1; pack = 'OperatorTierTag'; order = $order
            classes = @('device'); osScope = @(); fallback = $false; mechanism = 'operator.tier_tag'
            when = [ordered]@{ any = @([ordered]@{ field = 'si_tags'; op = 'matches'; value = $pat }) }
            set = [ordered]@{ si_tier = $t }; exclude = @(); native = $true; asserted = $true
        }
    }
}

function Get-SICiTagTierRules {
    <# The tier tag rules with the tagPattern of the merged endpoint schema (locked + custom + Pro overlay); the shipped default when it cannot be read. #>
    $pattern = $null
    try {
        if (-not (Get-Command -Name Get-SISchemaWithCustomMerge -ErrorAction SilentlyContinue)) {
            . (Join-Path (Split-Path -Parent $PSScriptRoot) 'asset-profiling\shared\Get-SISchemaWithCustomMerge.ps1')
        }
        $schema = Get-SISchemaWithCustomMerge -Engine endpoint
        foreach ($c in @(Get-SIItemValue (Get-SIItemValue $schema 'aggregator') 'contributors')) {
            if ($null -ne $c -and [string](Get-SIItemValue $c 'id') -eq 'tenant_si_manual_tag') { $pattern = [string](Get-SIItemValue $c 'tagPattern'); break }
        }
    } catch { Write-Warning ("CI rules: the endpoint schema could not be read for the tier tag pattern ({0}) -- the shipped pattern is used." -f $_.Exception.Message) }
    @(ConvertTo-SICiTagTierRules -TagPattern $pattern)
}

# ---------------------------------------------------------------------------------------------------
# #690 (48) The identity's tier = the tier of the HIGHEST privilege it holds today (owner 2026-10-15: "identity follows the
# highest perm a user has today"), as SI tier rules over the privilege tier catalog
# ---------------------------------------------------------------------------------------------------

function ConvertTo-SICiPrivilegeTierRules {
    <#
        PURE. The privilege tier catalog (privilege-tier-catalog.locked.json; -Custom = the tenant's .custom.json, which moves
        or adds an entry by its key) -> CI tier rules for identities, one per privilege kind and tier 0..2:
          entra-role-tier<t>      a permanent or eligible Entra role of tier t (the profiler's catalog verdict on the record,
                                  si_privilege_tier_permanent / _eligible, or the role's name in si_entra_roles_permanent /
                                  _eligible -- custom roles included)
          azure-rbac-tier<t>      an Azure RBAC assignment whose effective tier (role tier at its scope) is t
                                  (si_azure_role_assignments, EffectiveTier)
          app-permission-tier<t>  an application permission of tier t (si_app_permissions)
          ad-group-tier<t>        a critical AD group of tier t (si_ad_critical_groups)
        Every rule is an observed claim (mechanism privilege_catalog, never a fallback, never asserted); the CI's tier is the
        MIN of every claim, so the account takes the tier of its highest privilege. Tier 3 has no rule: holding only Tier 3
        privileges is what the default tier already says. Nothing is hard-coded: the names come from the catalog.
    #>
    param([Parameter(Mandatory)]$Catalog, $Custom, [int]$StartOrder = 800000)
    $sect = {
        param($Doc, [string]$Name)
        if ($null -eq $Doc) { return @() }
        $v = Get-SIItemValue $Doc $Name
        if ($null -eq $v) { return @() }
        @((Get-SIValueList $v).ToArray())
    }
    # key -> tier, the catalog first, then the tenant's file (a custom entry moves its key to its own tier)
    $byKind = @{ entra = @{}; app = @{}; ad = @{} }
    $collect = {
        param($Doc)
        foreach ($t in 0..3) {
            foreach ($s in @('EntraID_BuiltInRoles_Tier{0}' -f $t), @('EntraID_CustomRoles_Tier{0}' -f $t)) {
                foreach ($e in (& $sect $Doc $s)) { $k = [string](Get-SIItemValue $e 'DisplayName'); if ($k) { $byKind.entra[$k.ToLowerInvariant()] = @($k, $t) } }
            }
            foreach ($e in (& $sect $Doc ('EntraID_APIPermissions_Tier{0}' -f $t))) {
                if ([string](Get-SIItemValue $e 'PermissionType') -ne 'Application') { continue }
                $k = [string](Get-SIItemValue $e 'Value'); if ($k) { $byKind.app[$k.ToLowerInvariant()] = @($k, $t) }
            }
            foreach ($s in @('AD_BuiltInPermissionGroups_Tier{0}' -f $t), @('AD_CustomGroups_Tier{0}' -f $t)) {
                foreach ($e in (& $sect $Doc $s)) { $k = [string](Get-SIItemValue $e 'Name'); if ($k) { $byKind.ad[$k.ToLowerInvariant()] = @($k, $t) } }
            }
        }
    }
    & $collect $Catalog
    if ($null -ne $Custom) { & $collect $Custom }
    $namesOf = { param([hashtable]$Map, [int]$Tier) @($Map.Values | Where-Object { $_[1] -eq $Tier } | ForEach-Object { [string]$_[0] } | Sort-Object -Unique) }
    $rule = {
        param([string]$Id, [string]$Name, [int]$Tier, $When)
        $script:__siPtOrder++
        [pscustomobject][ordered]@{
            id = ('identity-privilege/{0}' -f $Id); family = 'ci'; file = 'privilege-tier-catalog/privilege-tier-catalog.locked.json'
            name = $Name; stage = 'production'; priority = 100; pack = 'IdentityPrivilegeTier'; order = ($StartOrder + $script:__siPtOrder)
            classes = @('identity'); osScope = @(); fallback = $false; mechanism = 'privilege_catalog'
            when = $When; set = [ordered]@{ si_tier = $Tier }; exclude = @(); native = $true; asserted = $false
        }
    }
    $script:__siPtOrder = 0
    foreach ($t in 0..2) {
        $roles = @(& $namesOf $byKind.entra $t)
        $any = New-Object System.Collections.Generic.List[object]
        $any.Add([ordered]@{ field = 'si_privilege_tier_permanent'; op = 'eq'; value = $t })
        $any.Add([ordered]@{ field = 'si_privilege_tier_eligible'; op = 'eq'; value = $t })
        if ($roles.Count) {
            $any.Add([ordered]@{ field = 'si_entra_roles_permanent'; op = 'in'; value = $roles })
            $any.Add([ordered]@{ field = 'si_entra_roles_eligible'; op = 'in'; value = $roles })
        }
        & $rule ('entra-role-tier{0}' -f $t) ('Holds a Tier {0} Entra role (permanent or eligible)' -f $t) $t ([ordered]@{ any = $any.ToArray() })
        & $rule ('azure-rbac-tier{0}' -f $t) ('Holds a Tier {0} Azure RBAC role at its scope' -f $t) $t ([ordered]@{ any = @([ordered]@{ field = 'si_azure_role_assignments'; op = 'matches'; value = ('(EffectiveTier=|"EffectiveTier"\s*:\s*){0}(?![0-9])' -f $t) }) })
        $perms = @(& $namesOf $byKind.app $t)
        if ($perms.Count) { & $rule ('app-permission-tier{0}' -f $t) ('Holds a Tier {0} application permission' -f $t) $t ([ordered]@{ any = @([ordered]@{ field = 'si_app_permissions'; op = 'in'; value = $perms }) }) }
        $groups = @(& $namesOf $byKind.ad $t)
        if ($groups.Count) { & $rule ('ad-group-tier{0}' -f $t) ('Member of a Tier {0} AD group' -f $t) $t ([ordered]@{ any = @([ordered]@{ field = 'si_ad_critical_groups'; op = 'in'; value = $groups }) }) }
    }
}

function Get-SICiPrivilegeTierRules {
    <# The identity privilege tier rules from the shipped privilege tier catalog and the tenant's custom file beside it; none (and a warning) when the catalog cannot be read. #>
    param([string]$Root)
    if (-not $Root) { $Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
    $dir = [System.IO.Path]::Combine($Root, 'privilege-tier-catalog')
    try {
        $cat = [System.IO.File]::ReadAllText([System.IO.Path]::Combine($dir, 'privilege-tier-catalog.locked.json')).TrimStart([char]0xFEFF) | ConvertFrom-Json
        $cus = $null
        $cp = [System.IO.Path]::Combine($dir, 'privilege-tier-catalog.custom.json')
        if (Test-Path -LiteralPath $cp) {
            try { $cus = [System.IO.File]::ReadAllText($cp).TrimStart([char]0xFEFF) | ConvertFrom-Json } catch { Write-Warning ("CI rules: the tenant's privilege tier catalog could not be read ({0}) -- the shipped catalog is used." -f $_.Exception.Message) }
        }
        return @(ConvertTo-SICiPrivilegeTierRules -Catalog $cat -Custom $cus)
    } catch {
        Write-Warning ("CI rules: the privilege tier catalog could not be read ({0}) -- identities get no privilege tier this run." -f $_.Exception.Message)
        return @()
    }
}

# ---------------------------------------------------------------------------------------------------
# Manual CI overrides (precedence 1)
# ---------------------------------------------------------------------------------------------------

function Get-SICiOverrideReadSql {
    <# Every override in force (not expired). A database without the table answers no rows (it is created by the updater). #>
    @'
SET NOCOUNT ON;
IF OBJECT_ID('sidata.CiOverride') IS NULL
    SELECT CAST(NULL AS NVARCHAR(64)) AS CiId, CAST(NULL AS NVARCHAR(64)) AS Field, CAST(NULL AS NVARCHAR(400)) AS Value, CAST(NULL AS NVARCHAR(1000)) AS Reason,
           CAST(NULL AS NVARCHAR(256)) AS SetBy, CAST(NULL AS DATETIME2(0)) AS SetAt, CAST(NULL AS DATETIME2(0)) AS ExpiresAt WHERE 1 = 0;
ELSE
    EXEC sp_executesql N'SELECT CiId, Field, Value, Reason, SetBy, SetAt, ExpiresAt FROM sidata.CiOverride WHERE (ExpiresAt IS NULL OR ExpiresAt > SYSUTCDATETIME()) AND ISNULL(Removed, 0) = 0';
'@
}

function ConvertTo-SICiOverrideIndex {
    <#
        PURE. Override rows -> CiId (case-insensitive) -> [ { field; value; reason; set_by; set_at; expires_at } ]. Expired rows
        (ExpiresAt <= -Now) and rows for a field that may not be overridden are left out. Overridable: si_tier, si_purpose,
        si_category, si_department, si_cmdb_* (CMDB fields), si_lifecycle is NOT (it is evidence, never a decision).
    #>
    param([AllowEmptyCollection()][object[]]$Rows = @(), [datetime]$Now = [datetime]::UtcNow)
    $idx = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $Rows) {
        if ($null -eq $r) { continue }
        $ci = [string](Get-SIItemValue $r 'CiId'); $f = ([string](Get-SIItemValue $r 'Field')).Trim().ToLowerInvariant()
        if (-not $ci -or -not $f) { continue }
        if ($f -notmatch '^(si_tier|si_purpose|si_category|si_department|si_cmdb_[a-z_]+)$') { continue }
        $exp = ConvertTo-SIUtcOrNull (Get-SIItemValue $r 'ExpiresAt')
        if ($exp -and $exp -le $Now) { continue }
        if (-not $idx.ContainsKey($ci)) { $idx[$ci] = New-Object System.Collections.Generic.List[object] }
        $idx[$ci].Add([ordered]@{ field = $f; value = (Get-SIItemValue $r 'Value'); reason = [string](Get-SIItemValue $r 'Reason'); set_by = [string](Get-SIItemValue $r 'SetBy')
                set_at = (ConvertTo-SIUtcOrNull (Get-SIItemValue $r 'SetAt')); expires_at = $exp })
    }
    # plain arrays (a caller's @() around a generic list throws "Argument types do not match")
    foreach ($k in @($idx.Keys)) { $idx[$k] = $idx[$k].ToArray() }
    $idx
}

function Set-SICiOverrides {
    <#
        PURE. The manual overrides of one CI applied OVER the rules' result (precedence 1, V3-DATA-MODEL 2.8): the field takes
        the override's value; si_tier sets si_tier_set_by = override and si_tier_reason = the override's reason; the claim the
        rules would have chosen stays in si_tier_claims (marked not winning). Every override in force -> si_overrides.
    #>
    param([Parameter(Mandatory)]$Ci, [hashtable]$Index)
    if ($null -eq $Index) { return $Ci }
    $id = [string]$Ci['si_ci_id']
    if (-not $id -or -not $Index.ContainsKey($id)) { return $Ci }
    $applied = New-Object System.Collections.Generic.List[object]
    foreach ($o in $Index[$id]) {
        $f = [string]$o.field
        if ($f -eq 'si_tier') {
            $t = 0
            if (-not [int]::TryParse([string]$o.value, [ref]$t) -or $t -lt 0 -or $t -gt 3) { continue }
            $was = $Ci['si_tier']
            $Ci['si_tier'] = $t
            $Ci['si_tier_set_by'] = 'override'
            $Ci['si_tier_reason'] = ('manual override by {0}: {1}' -f $(if ($o.set_by) { $o.set_by } else { 'an administrator' }), $o.reason)
            foreach ($c in @($Ci['si_tier_claims'])) { if ($c -and $c['winner']) { $c['winner'] = $false } }
            $applied.Add([ordered]@{ field = $f; value = $t; rules_value = $was; reason = $o.reason; set_by = $o.set_by; set_at = $o.set_at; expires_at = $o.expires_at })
            continue
        }
        $was = $Ci[$f]
        $Ci[$f] = $o.value
        $applied.Add([ordered]@{ field = $f; value = $o.value; rules_value = $was; reason = $o.reason; set_by = $o.set_by; set_at = $o.set_at; expires_at = $o.expires_at })
    }
    if ($applied.Count -gt 0) { $Ci['si_overrides'] = $applied.ToArray() }
    # #579 the explanation names the override (who, reason, expiry) and what the rules would have chosen
    if (@($applied | Where-Object { $_.field -eq 'si_tier' }).Count -gt 0 -and (Get-Command -Name Get-SICiTierExplanation -ErrorAction SilentlyContinue)) { $Ci['si_tier_explanation'] = Get-SICiTierExplanation -Ci $Ci }
    return $Ci
}
