#Requires -Version 5.1
<#
    SecurityInsight BREAK GLASS -- a CLASSIFICATION, not a risk factor (REQUIREMENTS #559, owner 2026-10-10: "break glass
    is not a factor: an SI classification (feeds tier and its own reports), detected from the platform (CA exclusions, the
    emergency-access group) plus naming patterns SI and the customer set in a wizard").

    An identity CI (users and guests) is break-glass when ANY of these holds:
      provider    its provider already says so (si_is_break_glass true: the identity profiler's value on the Entra record)
      naming      a pattern of the data-model list break_glass_patterns (type values: glob patterns, * and ?, over letters,
                  digits, space and . _ @ -; never wildcards only -- Test-SIBreakGlassPattern) matches its sign-in name
                  (si_upn), its display name (si_display_name)
      group       ... or the name of one of its groups (si_group_memberships): a member of an emergency-access group
      attribute   it carries the EXTENSION ATTRIBUTE and VALUE the customer defines (owner 2026-10-11: "extension attr tag
                  value i define") -- the data-model list break_glass_attribute, entries "attribute=value"; NOTHING is
                  shipped. The collector reads the attribute with the user and says which entry matched
                  (si_break_glass_attribute)
      ca_excluded_from_all
                  it holds a PERMANENT TIER 0 role (si_privilege_tier_permanent = 0) and is excluded from ALL the enabled Conditional Access policies that would apply to it (owner: "or
                  excluded all policies": si_ca_excluded_from_all true). Being excluded from ONE policy is NOT break-glass
                  any more -- si_ca_excluded_policies still lists every policy that excludes the account, as context.
    The customer overrides the lists (Community lists.custom.json; Pro the list's override -- the patterns in a wizard; the
    web app holds a pattern to the same rule). The CI build calls Set-SICiBreakGlass BEFORE the enrichment rules
    (SI-CiEnrich.ps1), so the tier rules and the break-glass reports read si_is_break_glass exactly as they read the old
    factor's field. si_break_glass_reason says in plain words WHICH rule matched. Nothing here touches si_risk_factors or a
    score.

    #546 UNKNOWN IS NEVER A FINDING: a field the CI build could not decide (si_unknown_fields) is not read. A provider's
    true is never cleared; a provider's false stays false unless a signal matches.

    PURE. PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Get-SIItemValue -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-Conditions.ps1') }

$script:SIBreakGlassListId = 'break_glass_patterns'
$script:SIBreakGlassAttributeListId = 'break_glass_attribute'

function Get-SIBreakGlassPatterns {
    <# PURE. The valid glob patterns of the break_glass_patterns list in -Lists (a pattern of wildcards only, or with a
       character outside the contract, is skipped -- the validation reports it). #>
    param([hashtable]$Lists = @{})
    $out = New-Object System.Collections.Generic.List[string]
    if (-not $Lists -or -not $Lists.ContainsKey($script:SIBreakGlassListId)) { return , $out.ToArray() }
    foreach ($v in (Get-SIValueList (Get-SIItemValue $Lists[$script:SIBreakGlassListId] 'values'))) {
        $s = ([string]$v).Trim()
        if ($s -cmatch '^[A-Za-z0-9 ._@*?-]{1,128}$' -and $s -notmatch '^[\s*?]+$') { $out.Add($s) }
    }
    return , $out.ToArray()
}

function ConvertTo-SIBreakGlassAttributeRule {
    <#
        PURE. One entry of the break_glass_attribute list -- "attribute=value" -- as @{ Attribute; Value; Kind; Text }, or
        $null when it is not a valid entry.
          attribute   extensionAttribute1 .. extensionAttribute15 (the user's on-premises extension attributes), or the
                      name of a directory extension (extension_<application id without dashes>_<name>)
          value       the text the attribute must hold, compared whole and without regard to case; never empty (an empty
                      value would make every account break-glass)
    #>
    param([AllowNull()][AllowEmptyString()][string]$Entry)
    $s = [string]$Entry
    $i = $s.IndexOf('=')
    if ($i -lt 1) { return $null }
    $a = $s.Substring(0, $i).Trim(); $v = $s.Substring($i + 1).Trim()
    if (-not $v -or $v.Length -gt 256) { return $null }
    $kind = ''
    if ($a -match '^(?i)extensionAttribute(?<n>1[0-5]|[1-9])$') { $kind = 'extensionAttribute'; $a = 'extensionAttribute' + $Matches['n'] }
    elseif ($a -cmatch '^extension_[0-9a-fA-F]{32}_[A-Za-z0-9_]{1,128}$') { $kind = 'directoryExtension' }
    else { return $null }
    return @{ Attribute = $a; Value = $v; Kind = $kind; Text = ('{0}={1}' -f $a, $v) }
}

function Test-SIBreakGlassAttributeEntry {
    <# PURE. Problems with ONE entry of the break_glass_attribute list; empty = valid. #>
    param([AllowNull()][AllowEmptyString()][string]$Entry)
    $p = New-Object System.Collections.Generic.List[string]
    if ($null -eq (ConvertTo-SIBreakGlassAttributeRule -Entry $Entry)) {
        $p.Add("lists/break_glass_attribute: '$Entry' -- an entry is attribute=value, the attribute extensionAttribute1 to extensionAttribute15 or a directory extension name (extension_<application id>_<name>), the value not empty and at most 256 characters")
    }
    return $p.ToArray()
}

function Test-SIBreakGlassAttributeList {
    <# PURE. The break_glass_attribute list of a model: type values, every value a valid entry. Empty = valid (no list too). #>
    param([Parameter(Mandatory)]$Model)
    $p = New-Object System.Collections.Generic.List[string]
    $l = @(@($Model['lists'].lists) | Where-Object { $_ -and [string]$_.id -eq $script:SIBreakGlassAttributeListId })
    if ($l.Count -eq 0) { return $p.ToArray() }
    if ([string]$l[0].type -ne 'values') { $p.Add("lists/break_glass_attribute: type '$($l[0].type)' -- it is a values list of attribute=value entries") }
    foreach ($v in @(Get-SIItemValue $l[0] 'values')) {
        if ($null -eq $v) { continue }
        foreach ($x in (Test-SIBreakGlassAttributeEntry -Entry ([string]$v))) { $p.Add($x) }
    }
    return $p.ToArray()
}

function Get-SIBreakGlassAttributeRules {
    <# PURE. The valid entries of the break_glass_attribute list in -Lists (an invalid entry is skipped -- the validation
       reports it). Nothing shipped: empty until the customer defines one.
       The rules are written to the output ONE BY ONE, never as one wrapped array: every caller reads them as
       @(Get-SIBreakGlassAttributeRules ...) or in a foreach, and a wrapped array inside @( ) is ONE element -- an empty
       list then counts as one rule, and two rules as one that matches nobody. #>
    param([hashtable]$Lists = @{})
    $out = New-Object System.Collections.Generic.List[object]
    if (-not $Lists -or -not $Lists.ContainsKey($script:SIBreakGlassAttributeListId)) { return }
    foreach ($v in (Get-SIValueList (Get-SIItemValue $Lists[$script:SIBreakGlassAttributeListId] 'values'))) {
        $r = ConvertTo-SIBreakGlassAttributeRule -Entry ([string]$v)
        if ($null -ne $r) { $out.Add($r) }
    }
    return $out.ToArray()
}

function Get-SIBreakGlassAttributeSelect {
    <# PURE. The properties the user read must ask Microsoft Graph for so the rules can be decided:
       onPremisesExtensionAttributes when a rule names an extensionAttributeN, and each directory extension by its name.
       Empty when there is no rule -- the user read is then exactly as before. Written to the output one by one, as the
       rules are: read it as @(Get-SIBreakGlassAttributeSelect ...). #>
    param([AllowEmptyCollection()][object[]]$Rules = @())
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $n = 'onPremisesExtensionAttributes'; if ([string]$r.Kind -eq 'directoryExtension') { $n = [string]$r.Attribute }
        if (-not $out.Contains($n)) { $out.Add($n) }
    }
    return $out.ToArray()
}

function Get-SIBreakGlassAttributeMatch {
    <#
        PURE. The first rule the user object (as Microsoft Graph returned it) satisfies: { attribute; value; match } --
        match is "attribute=value" as the rule reads -- or $null. An attribute the read did not return is not a match
        (unknown is never break-glass).
    #>
    param($User, [AllowEmptyCollection()][object[]]$Rules = @())
    if ($null -eq $User) { return $null }
    $get = {
        param($o, $n)
        if ($null -eq $o) { return $null }
        if ($o -is [System.Collections.IDictionary]) { foreach ($k in @($o.Keys)) { if ([string]$k -ieq $n) { return $o[$k] } }; return $null }
        $p = $o.PSObject.Properties[$n]; if ($p) { return $p.Value }
        return $null
    }
    foreach ($r in @($Rules)) {
        if ($null -eq $r) { continue }
        $have = $null
        if ([string]$r.Kind -eq 'directoryExtension') { $have = & $get $User ([string]$r.Attribute) }
        else { $have = & $get (& $get $User 'onPremisesExtensionAttributes') ([string]$r.Attribute) }
        if ($null -eq $have) { continue }
        foreach ($h in @($have)) {
            if ($null -ne $h -and ([string]$h).Trim() -ieq [string]$r.Value) { return [ordered]@{ attribute = [string]$r.Attribute; value = ([string]$h).Trim(); match = [string]$r.Text } }
        }
    }
    return $null
}

function Test-SIBreakGlassName {
    <# PURE. $true when -Text matches any glob pattern (case-insensitive, the whole text). #>
    param([AllowNull()][AllowEmptyString()][string]$Text, [string[]]$Patterns = @())
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    # a pattern is built once and kept (2026-10-16: it was built again for every group of every identity of the CI build)
    $cache = $script:SIBreakGlassWildcardCache
    if ($null -eq $cache -or $cache.Count -gt 5000) { $cache = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal); $script:SIBreakGlassWildcardCache = $cache }
    $t = $Text.Trim()
    foreach ($p in $Patterns) {
        $wc = $null
        if (-not $cache.TryGetValue([string]$p, [ref]$wc)) { $wc = New-Object System.Management.Automation.WildcardPattern($p, [System.Management.Automation.WildcardOptions]::IgnoreCase); $cache[[string]$p] = $wc }
        if ($wc.IsMatch($t)) { return $true }
    }
    return $false
}

function Get-SIBreakGlassReasonText {
    <# PURE. The reasons (Get-SIBreakGlassClassification) in plain words: WHICH rule made the account break-glass. #>
    param([AllowEmptyCollection()][string[]]$Reasons = @(), $Ci)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($code in @($Reasons)) {
        $c = [string]$code
        if ($c -eq 'provider') { $out.Add('the identity collection marks it as an emergency-access account') }
        elseif ($c -eq 'naming:si_upn') { $out.Add('its sign-in name matches a break-glass naming pattern') }
        elseif ($c -eq 'naming:si_display_name') { $out.Add('its display name matches a break-glass naming pattern') }
        elseif ($c -eq 'group') { $out.Add('it is a member of a group whose name matches a break-glass naming pattern') }
        elseif ($c -eq 'attribute') {
            $a = ''; if ($null -ne $Ci) { $a = [string](Get-SIItemValue $Ci 'si_break_glass_attribute') }
            if ($a) { $out.Add(('it carries the extension attribute and value you defined ({0})' -f $a)) } else { $out.Add('it carries the extension attribute and value you defined') }
        }
        elseif ($c -eq 'ca_excluded_from_all') {
            $n = 0; if ($null -ne $Ci) { $n = @((Get-SIValueList (Get-SIItemValue $Ci 'si_ca_excluded_policies')).ToArray() | Where-Object { $_ }).Count }
            if ($n -gt 0) { $out.Add(('it holds a permanent Tier 0 role and is excluded from all {0} enabled Conditional Access policies that would apply to it' -f $n)) }
            else { $out.Add('it holds a permanent Tier 0 role and is excluded from all the enabled Conditional Access policies that would apply to it') }
        }
        elseif ($c) { $out.Add($c) }
    }
    if ($out.Count -eq 0) { return '' }
    return ('Break-glass because ' + ($out.ToArray() -join '; ') + '.')
}

function Get-SIBreakGlassClassification {
    <#
    .SYNOPSIS  PURE. One CI -> @{ IsBreakGlass = $true | $false | $null (not an identity user / guest, or nothing known);
               Reasons = provider / naming:<field> / group / attribute / ca_excluded_from_all }.
    #>
    param([Parameter(Mandatory)]$Ci, [hashtable]$Context = @{})
    $reasons = New-Object System.Collections.Generic.List[string]
    $cls = [string](Get-SIItemValue $Ci 'si_class')
    if ($cls -and $cls -ne 'identity') { return @{ IsBreakGlass = $null; Reasons = @() } }
    $type = [string](Get-SIItemValue $Ci 'si_identity_type')
    if ($type -and @('user', 'guest') -notcontains $type) { return @{ IsBreakGlass = $null; Reasons = @() } }
    $unknown = @{}; foreach ($u in @(Get-SIItemValue $Ci 'si_unknown_fields')) { if ($u) { $unknown[[string]$u] = $true } }
    $prov = ConvertTo-SIBoolOrNull (Get-SIItemValue $Ci 'si_is_break_glass')
    if ($prov -eq $true) { $reasons.Add('provider') }
    $lists = @{}; if ($Context -and $Context.Lists) { $lists = $Context.Lists }
    $pats = Get-SIBreakGlassPatterns -Lists $lists
    if ($pats.Count -gt 0) {
        foreach ($fn in 'si_upn', 'si_display_name') {
            if ($unknown.ContainsKey($fn)) { continue }
            if (Test-SIBreakGlassName -Text ([string](Get-SIItemValue $Ci $fn)) -Patterns $pats) { $reasons.Add('naming:' + $fn) }
        }
        if (-not $unknown.ContainsKey('si_group_memberships')) {
            foreach ($g in (Get-SIValueList (Get-SIItemValue $Ci 'si_group_memberships'))) {
                $names = @()
                if ($g -is [string]) { $names = @($g) } else { $names = @((Get-SIItemValue $g 'displayName'), (Get-SIItemValue $g 'name')) }
                $hit = $false
                foreach ($n in $names) { if (Test-SIBreakGlassName -Text ([string]$n) -Patterns $pats) { $hit = $true } }
                if ($hit) { $reasons.Add('group'); break }
            }
        }
    }
    # (a) the extension attribute and value the customer defines: the collector matched it on the user it read
    # (si_break_glass_attribute = "attribute=value"); it counts only while that entry is still in the list
    if (-not $unknown.ContainsKey('si_break_glass_attribute')) {
        $have = ([string](Get-SIItemValue $Ci 'si_break_glass_attribute')).Trim()
        if ($have) {
            foreach ($rule in (Get-SIBreakGlassAttributeRules -Lists $lists)) { if ([string]$rule.Text -ieq $have) { $reasons.Add('attribute'); break } }
        }
    }
    # (b) a PERMANENT TIER 0 account that is excluded from ALL the enabled Conditional Access policies that would apply to it --
    # one policy is not enough, and an ordinary account in a broad exclusion group is not break-glass (the rule has always
    # been about the accounts that hold the tenant: si_privilege_tier_permanent = 0)
    if (-not $unknown.ContainsKey('si_ca_excluded_from_all') -and -not $unknown.ContainsKey('si_privilege_tier_permanent')) {
        $pt = ConvertTo-SINumberOrNull (Get-SIItemValue $Ci 'si_privilege_tier_permanent')
        if ((ConvertTo-SIBoolOrNull (Get-SIItemValue $Ci 'si_ca_excluded_from_all')) -eq $true -and $null -ne $pt -and $pt -eq 0) { $reasons.Add('ca_excluded_from_all') }
    }
    if ($reasons.Count -gt 0) { return @{ IsBreakGlass = $true; Reasons = $reasons.ToArray() } }
    return @{ IsBreakGlass = $prov; Reasons = @() }
}

function Set-SICiBreakGlass {
    <#
    .SYNOPSIS  PURE. Sets si_is_break_glass (true when classified; a provider's value is kept otherwise),
               si_break_glass_reasons (the rules that matched) and si_break_glass_reason (the same in plain words) on one
               identity CI. Returns the CI. Never touches the risk factors.
    #>
    param([Parameter(Mandatory)]$Ci, [hashtable]$Context = @{})
    $r = Get-SIBreakGlassClassification -Ci $Ci -Context $Context
    if ($r.IsBreakGlass -eq $true) {
        $Ci['si_is_break_glass'] = $true
        $Ci['si_break_glass_reasons'] = @($r.Reasons)
        $Ci['si_break_glass_reason'] = Get-SIBreakGlassReasonText -Reasons @($r.Reasons) -Ci $Ci
    } elseif ($Ci -is [System.Collections.IDictionary]) {
        foreach ($n in 'si_break_glass_reasons', 'si_break_glass_reason') { if ($Ci.Contains($n)) { $Ci.Remove($n) } }
    }
    return $Ci
}
