#Requires -Version 5.1
<#
    SecurityInsight condition evaluator -- the ONE implementation of the closed condition language that risk factors,
    enrichment rules, coverage checks and lists use (data-model/*.json, V3-DATA-MODEL part 2).

    A condition is a leaf or a group:
        leaf   { "field": "si_tier", "op": "lte", "value": 1 }
        group  { "all": [ ... ] }   { "any": [ ... ] }      (an empty "all" is true, an empty "any" is false)

    THE OPERATION SET IS CLOSED. A template (and a customer override) can only combine these operations; there is no
    expression language, so a customer-authored file can never run code in the engine:
        eq ne in not_in is_true is_false is_empty not_empty gt gte lt lte like contains contains_any matches
        older_than_days newer_than_days in_ranges in_list
    An unknown operation throws -- a condition must never evaluate as something its author did not write.

    The item is anything with named values: a hashtable, an ordered dictionary or a PSObject (a CI, a record, a finding).
    String comparison is case-insensitive. Dates are read with InvariantCulture and compared in UTC.

    Context (optional hashtable):
        Lists = @{ <id> = <list object from lists.json: type conditions | values | ranges> }
        Now   = [datetime] UTC   (default: the current time; tests pass a fixed one)

    PowerShell 5.1: no ?. / ??, no ternary; no Set-StrictMode here (it would leak into the caller).
#>

function Get-SIItemValue {
    <# The value of a named field on a hashtable / dictionary / PSObject, or $null. Case-insensitive. #>
    param($Item, [string]$Name)
    if ($null -eq $Item -or [string]::IsNullOrEmpty($Name)) { return $null }
    if ($Item -is [System.Collections.IDictionary]) {
        if ($Item.Contains($Name)) { return $Item[$Name] }
        foreach ($k in $Item.Keys) { if ([string]::Equals([string]$k, $Name, [StringComparison]::OrdinalIgnoreCase)) { return $Item[$k] } }
        return $null
    }
    $p = $Item.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Test-SIValueEmpty {
    param($Value)
    if ($null -eq $Value) { return $true }
    if ($Value -is [string]) { return [string]::IsNullOrWhiteSpace($Value) }
    if ($Value -is [System.Collections.IDictionary]) { return ($Value.Count -eq 0) }
    if ($Value -is [System.Collections.IEnumerable]) { foreach ($x in $Value) { return $false }; return $true }
    return $false
}

function ConvertTo-SIBoolOrNull {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    if ($s -in 'true', '1', 'yes', 'y', 'on', 'enabled') { return $true }
    if ($s -in 'false', '0', 'no', 'n', 'off', 'disabled') { return $false }
    return $null
}

function ConvertTo-SINumberOrNull {
    <# A number, or the leading number of a version-like string ("12.6.1" -> 12.6), or $null. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) { return [double]$Value }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    $d = 0.0
    if ([double]::TryParse($s, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    $m = [regex]::Match($s, '^-?\d+(\.\d+)?')
    if ($m.Success -and [double]::TryParse($m.Value, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    return $null
}

function ConvertTo-SIUtcOrNull {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $s = ([string]$Value).Trim()
    if ($s -eq '') { return $null }
    $dto = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) { return $dto.UtcDateTime }
    return $null
}

function Get-SIValueList {
    <# A value as a flat list: $null -> empty; a scalar -> one item; a list -> its items. Strings are never split. #>
    param($Value)
    $out = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Value) { return , $out }
    if ($Value -is [string] -or $Value -is [System.Collections.IDictionary] -or -not ($Value -is [System.Collections.IEnumerable])) { $out.Add($Value); return , $out }
    foreach ($x in $Value) { if ($null -ne $x) { $out.Add($x) } }
    return , $out
}

function Test-SIScalarEqual {
    param($A, $B)
    if ($null -eq $A -or $null -eq $B) { return ($null -eq $A -and $null -eq $B) }
    if ($A -is [bool] -or $B -is [bool]) {
        $x = ConvertTo-SIBoolOrNull $A; $y = ConvertTo-SIBoolOrNull $B
        return ($null -ne $x -and $x -eq $y)
    }
    $na = $null; $nb = $null
    if (-not ($A -is [string]) -or -not ($B -is [string])) { $na = ConvertTo-SINumberOrNull $A; $nb = ConvertTo-SINumberOrNull $B }
    if ($null -ne $na -and $null -ne $nb) { return ($na -eq $nb) }
    return [string]::Equals(([string]$A).Trim(), ([string]$B).Trim(), [StringComparison]::OrdinalIgnoreCase)
}

function Test-SIIpInCidr {
    <# True when the address is inside the CIDR (IPv4 or IPv6). A bare address is a /32 or /128. #>
    param([string]$Ip, [string]$Cidr)
    $addr = $null
    if (-not [System.Net.IPAddress]::TryParse(($Ip -split '/')[0].Trim(), [ref]$addr)) { return $false }
    $parts = $Cidr.Trim() -split '/'
    $net = $null
    if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$net)) { return $false }
    if ($addr.AddressFamily -ne $net.AddressFamily) {
        if ($addr.IsIPv4MappedToIPv6) { $addr = $addr.MapToIPv4() } else { return $false }
        if ($addr.AddressFamily -ne $net.AddressFamily) { return $false }
    }
    $a = $addr.GetAddressBytes(); $n = $net.GetAddressBytes()
    $bits = $a.Length * 8
    if ($parts.Count -gt 1) { $bits = [int]$parts[1] }
    if ($bits -lt 0 -or $bits -gt $a.Length * 8) { return $false }
    for ($i = 0; $i -lt $a.Length; $i++) {
        $take = [Math]::Min(8, [Math]::Max(0, $bits - ($i * 8)))
        if ($take -eq 0) { break }
        $mask = [byte]((0xFF -shl (8 - $take)) -band 0xFF)
        if (($a[$i] -band $mask) -ne ($n[$i] -band $mask)) { return $false }
    }
    return $true
}

function Resolve-SIListValues {
    <# A "value" that names a list (a string id found in Context.Lists) -> that list's values; otherwise the value itself as a list. #>
    param($Value, $Context)
    if ($Value -is [string] -and $Context -and $Context.Lists -and $Context.Lists.ContainsKey($Value)) {
        $l = $Context.Lists[$Value]
        $v = Get-SIItemValue $l 'values'
        return , (Get-SIValueList $v)
    }
    return , (Get-SIValueList $Value)
}

function Get-SIMatchTexts {
    <# The texts a value is matched as: a tag entry {source, name, value} -> 'name=value', name, value; anything else -> itself. #>
    param($Value)
    if ($null -eq $Value) { return }
    $n = Get-SIItemValue $Value 'name'
    if ($null -ne $n -and -not ($Value -is [string])) {
        $v = [string](Get-SIItemValue $Value 'value')
        if ($v) { '{0}={1}' -f $n, $v }
        [string]$n
        if ($v) { $v }
        return
    }
    [string]$Value
    # #690 (48) an OBJECT value (an Azure role assignment {RoleName, Scope, EffectiveTier ...}) is matched as its compact
    # JSON as well -- its text form alone is the type name for a dictionary, so no pattern could read its properties
    if ($Value -is [System.Collections.IDictionary] -or $Value -is [System.Management.Automation.PSCustomObject]) {
        try { ConvertTo-Json -InputObject $Value -Compress -Depth 4 } catch { }
    }
}

# =====================================================================================================================
#  A LONG LIST IS MATCHED ONCE PER PATTERN, NOT ONCE PER PATTERN AND VALUE (2026-10-13)
#  A device's installed software is a list of several hundred to a few thousand names, and the device rules test it with
#  about three thousand name patterns ('like'). Every test built its pattern again and walked the list value by value
#  through a function call: a device with 1,200 names took MINUTES to classify, and a batch of such devices stood still
#  for hours without a line in the log (measured on the test VM, tests/pester/SIv3-CiBuildHeavyResources.Tests.ps1).
#    * a pattern is built once and kept (Get-SIConditionRegex, Get-SIConditionWildcard) -- the same pattern object, so
#      the same answer;
#    * a list of 16 values or more is turned into its match texts once per item and field (Get-SIMatchTextList), and
#    * a wildcard made of plain text and '*' only is answered by ONE search over those texts joined together
#      (Get-SIWildcardLineRegex). Every other wildcard ('?', '[a-z]', an escape) is matched text by text as before.
#  The answers are the same as before. One known difference: the joined search compares the lower-case forms of the
#  texts and the pattern (invariant rules), a wildcard compares letter by letter in the process's culture -- the same for the names SecurityInsight reads (they are
#  lower-cased when they are mapped; only a culture with its own letter-case rules, such as Turkish, could differ).
#  Kept per process (a parallel thread has its own): nothing here is shared between threads.
# =====================================================================================================================

function Get-SIConditionRegex {
    <# A 'matches' pattern as its Regex (no case, invariant, 200 ms per match), built once. A pattern that is not valid throws, as before. #>
    param([string]$Pattern)
    $cache = $script:SIConditionRegexCache
    if ($null -eq $cache -or $cache.Count -gt 20000) { $cache = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal); $script:SIConditionRegexCache = $cache }
    $rx = $null
    if ($cache.TryGetValue($Pattern, [ref]$rx)) { return $rx }
    $rx = New-Object System.Text.RegularExpressions.Regex($Pattern, ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant), ([TimeSpan]::FromMilliseconds(200)))
    $cache[$Pattern] = $rx
    return $rx
}

function Get-SIConditionWildcard {
    <# A 'like' pattern as its WildcardPattern (no case), built once. #>
    param([string]$Pattern)
    $cache = $script:SIConditionWildcardCache
    if ($null -eq $cache -or $cache.Count -gt 20000) { $cache = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal); $script:SIConditionWildcardCache = $cache }
    $wc = $null
    if ($cache.TryGetValue($Pattern, [ref]$wc)) { return $wc }
    $wc = New-Object System.Management.Automation.WildcardPattern($Pattern, [System.Management.Automation.WildcardOptions]::IgnoreCase)
    $cache[$Pattern] = $wc
    return $wc
}

function Get-SIWildcardLineRegex {
    <#
        PURE. A wildcard made of plain text and '*' only -> the Regex that finds a WHOLE text matching it in texts joined
        with the character U+0001 (also before the first and after the last text); $null for any other wildcard ('?',
        '[', ']', an escape), which is matched text by text.
          'sql*'    -> <sep>sql            '*/sql*' -> /sql            'a*b' -> <sep>a[^<sep>]*b<sep>
    #>
    param([string]$Pattern)
    $cache = $script:SIConditionLineCache
    if ($null -eq $cache -or $cache.Count -gt 20000) { $cache = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::Ordinal); $script:SIConditionLineCache = $cache }
    $hit = $null
    if ($cache.TryGetValue($Pattern, [ref]$hit)) { if ($hit -is [regex]) { return $hit }; return $null }
    $rx = $null
    if ($Pattern.IndexOfAny([char[]]@('?', '[', ']', '`', [char]1)) -lt 0) {
        $sep = '\u0001'
        # the texts are searched in lower case (Get-SIMatchTextList), so the pattern is lower case too and the search is exact
        $parts = @($Pattern.ToLowerInvariant().Split('*') | Where-Object { $_ -ne '' } | ForEach-Object { [regex]::Escape($_) })
        $text = ($parts -join ('[^' + $sep + ']*'))
        if (-not $Pattern.StartsWith('*')) { $text = $sep + $text }
        if (-not $Pattern.EndsWith('*')) { $text = $text + $sep }
        try { $rx = New-Object System.Text.RegularExpressions.Regex($text, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant, ([TimeSpan]::FromSeconds(2))) } catch { $rx = $null }
    }
    $cache[$Pattern] = $(if ($null -ne $rx) { $rx } else { $false })
    return $rx
}

function Get-SIMatchTextList {
    <#
        The match texts of a LONG list value (16 values or more), made once per item and field: @{ Texts (every value's
        Get-SIMatchTexts, in order); Joined (the texts in lower case joined with U+0001, one before and one after -- $null when a text
        holds that character) }. $null for anything else (a scalar, a short list): the caller walks it as before.
        Kept for the last value seen per field, recognised by the list object itself -- a rule set is evaluated item by
        item, so every rule that reads the field of one item gets the same texts.
    #>
    param([string]$Field, $Actual)
    if ($null -eq $Actual -or $Actual -is [string] -or $Actual -isnot [System.Collections.IList] -or $Actual -is [System.Collections.IDictionary]) { return $null }
    $n = $Actual.Count
    if ($n -lt 16) { return $null }
    $cache = $script:SIConditionTextCache
    if ($null -eq $cache) { $cache = @{}; $script:SIConditionTextCache = $cache }
    $e = $cache[$Field]
    if ($null -ne $e -and [object]::ReferenceEquals($e.Ref, $Actual) -and $e.Count -eq $n) { return $e }
    $texts = New-Object System.Collections.Generic.List[string]
    foreach ($v in $Actual) {
        if ($null -eq $v) { continue }
        if ($v -is [string]) { $texts.Add($v) } else { foreach ($s in (Get-SIMatchTexts $v)) { $texts.Add([string]$s) } }
    }
    $arr = $texts.ToArray()
    $joined = $null
    if ($arr.Length -gt 0) {
        $sep = [string][char]1
        $body = [string]::Join($sep, $arr)
        # a text that holds the separator itself cannot be told apart: such a list is matched text by text
        if ($body.Split([char]1).Length -eq $arr.Length) { $joined = ($sep + $body + $sep).ToLowerInvariant() }
    }
    $e = [pscustomobject]@{ Ref = $Actual; Count = $n; Texts = $arr; Joined = $joined }
    $cache[$Field] = $e
    return $e
}

function Get-SIConditionOps { return , @('eq', 'ne', 'in', 'not_in', 'is_true', 'is_false', 'is_empty', 'not_empty', 'gt', 'gte', 'lt', 'lte', 'like',
        'contains', 'contains_any', 'matches', 'older_than_days', 'newer_than_days', 'in_ranges', 'in_list') }

function Test-SICondition {
    <#
    .SYNOPSIS  Evaluates a condition (leaf or all/any group) against an item. Returns $true / $false.
    #>
    param([Parameter(Mandatory)]$Condition, $Item, [hashtable]$Context)
    if ($null -eq $Condition) { return $true }
    # (2026-10-16, the CI build of a large install: this runs some hundred times for every CI. A dictionary's group / leaf
    # keys are read with its own Contains, an object's with its properties -- what Get-SIItemValue does, without a function
    # call each time when the name is there as written. A dictionary has no 'all' / 'any' PROPERTY, so the group test is
    # the one before.)
    $isDict = $Condition -is [System.Collections.IDictionary]
    if ($isDict) { $hasAll = $Condition.Contains('all'); $hasAny = $Condition.Contains('any') }
    else { $hasAll = [bool]$Condition.PSObject.Properties['all']; $hasAny = [bool]$Condition.PSObject.Properties['any'] }
    if ($hasAll) {
        foreach ($c in (Get-SIValueList (Get-SIItemValue $Condition 'all'))) { if (-not (Test-SICondition -Condition $c -Item $Item -Context $Context)) { return $false } }
        return $true
    }
    if ($hasAny) {
        foreach ($c in (Get-SIValueList (Get-SIItemValue $Condition 'any'))) { if (Test-SICondition -Condition $c -Item $Item -Context $Context) { return $true } }
        return $false
    }

    if ($isDict) {
        if ($Condition.Contains('field')) { $field = [string]$Condition['field'] } else { $field = [string](Get-SIItemValue $Condition 'field') }
        if ($Condition.Contains('op')) { $op = [string]$Condition['op'] } else { $op = [string](Get-SIItemValue $Condition 'op') }
        if ($Condition.Contains('value')) { $expected = $Condition['value'] } else { $expected = Get-SIItemValue $Condition 'value' }
    } else {
        $pp = $Condition.PSObject.Properties['field']; if ($pp) { $field = [string]$pp.Value } else { $field = '' }
        $pp = $Condition.PSObject.Properties['op']; if ($pp) { $op = [string]$pp.Value } else { $op = '' }
        $pp = $Condition.PSObject.Properties['value']; if ($pp) { $expected = $pp.Value } else { $expected = $null }
    }
    if ([string]::IsNullOrEmpty($field)) { throw "condition without a field: $($Condition | ConvertTo-Json -Compress -Depth 5)" }
    if ($Item -is [System.Collections.IDictionary] -and $Item.Contains($field)) { $actual = $Item[$field] } else { $actual = Get-SIItemValue $Item $field }

    # TWO TEXTS ARE COMPARED IN PLACE (2026-10-16, the CI build of a large install): Test-SIScalarEqual compares two texts as
    # trimmed and without case -- the same comparison is made here without a function call per value pair; every other pair
    # (a number, a yes / no, an empty value) still goes through Test-SIScalarEqual. Same answers.
    $ic = [StringComparison]::OrdinalIgnoreCase
    switch ($op) {
        'eq' {
            foreach ($v in (Get-SIValueList $actual)) {
                if ($v -is [string] -and $expected -is [string]) { if ([string]::Equals($v.Trim(), $expected.Trim(), $ic)) { return $true }; continue }
                if (Test-SIScalarEqual $v $expected) { return $true }
            }
            return $false
        }
        'ne' {
            foreach ($v in (Get-SIValueList $actual)) {
                if ($v -is [string] -and $expected -is [string]) { if ([string]::Equals($v.Trim(), $expected.Trim(), $ic)) { return $false }; continue }
                if (Test-SIScalarEqual $v $expected) { return $false }
            }
            return (-not (Test-SIValueEmpty $actual))
        }
        'in' {
            $set = Resolve-SIListValues $expected $Context
            foreach ($v in (Get-SIValueList $actual)) {
                $vs = $null; if ($v -is [string]) { $vs = $v.Trim() }
                foreach ($e in $set) {
                    if ($null -ne $vs -and $e -is [string]) { if ([string]::Equals($vs, $e.Trim(), $ic)) { return $true }; continue }
                    if (Test-SIScalarEqual $v $e) { return $true }
                }
            }
            return $false
        }
        'not_in' {
            if (Test-SIValueEmpty $actual) { return $false }
            $set = Resolve-SIListValues $expected $Context
            foreach ($v in (Get-SIValueList $actual)) {
                $vs = $null; if ($v -is [string]) { $vs = $v.Trim() }
                foreach ($e in $set) {
                    if ($null -ne $vs -and $e -is [string]) { if ([string]::Equals($vs, $e.Trim(), $ic)) { return $false }; continue }
                    if (Test-SIScalarEqual $v $e) { return $false }
                }
            }
            return $true
        }
        'is_true' { return ((ConvertTo-SIBoolOrNull $actual) -eq $true) }
        'is_false' { $b = ConvertTo-SIBoolOrNull $actual; return ($null -ne $b -and $b -eq $false) }
        'is_empty' { return (Test-SIValueEmpty $actual) }
        'not_empty' { return (-not (Test-SIValueEmpty $actual)) }
        { $_ -in 'gt', 'gte', 'lt', 'lte' } {
            $e = ConvertTo-SINumberOrNull $expected
            if ($null -eq $e) { throw "condition '$field $op' needs a number, got '$expected'" }
            foreach ($v in (Get-SIValueList $actual)) {
                $n = ConvertTo-SINumberOrNull $v
                if ($null -eq $n) { continue }
                $ok = switch ($op) { 'gt' { $n -gt $e } 'gte' { $n -ge $e } 'lt' { $n -lt $e } 'lte' { $n -le $e } }
                if ($ok) { return $true }
            }
            return $false
        }
        'contains' {
            if ($actual -is [string]) { return ($actual.IndexOf([string]$expected, [StringComparison]::OrdinalIgnoreCase) -ge 0) }
            foreach ($v in (Get-SIValueList $actual)) {
                if (Test-SIScalarEqual $v $expected) { return $true }
                $vn = Get-SIItemValue $v 'name'; $vv = Get-SIItemValue $v 'value'          # si_tags entries {source, name, value}
                if ($null -ne $vn -and ((Test-SIScalarEqual $vn $expected) -or (Test-SIScalarEqual $vv $expected) -or (Test-SIScalarEqual ("{0}={1}" -f $vn, $vv) $expected))) { return $true }
            }
            return $false
        }
        'contains_any' {
            $set = Resolve-SIListValues $expected $Context
            foreach ($v in (Get-SIValueList $actual)) {
                $vs = $null; if ($v -is [string]) { $vs = $v.Trim() }
                foreach ($e in $set) {
                    if ($null -ne $vs -and $e -is [string]) { if ([string]::Equals($vs, $e.Trim(), $ic)) { return $true }; continue }
                    if (Test-SIScalarEqual $v $e) { return $true }
                }
            }
            return $false
        }
        'matches' {
            # bounded: a pathological pattern times out instead of hanging the run. value = one pattern or a list (any).
            # A tag entry {source, name, value} is matched as "name=value", as its name and as its value.
            # A pattern is built once and kept; a long list's match texts are made once per item (Get-SIMatchTextList).
            $tl = Get-SIMatchTextList $field $actual
            foreach ($pat in (Get-SIValueList $expected)) {
                $rx = Get-SIConditionRegex ([string]$pat)
                if ($null -ne $tl) { foreach ($s in $tl.Texts) { if ($rx.IsMatch($s)) { return $true } } }
                else { foreach ($v in (Get-SIValueList $actual)) { foreach ($s in (Get-SIMatchTexts $v)) { if ($rx.IsMatch($s)) { return $true } } } }
            }
            return $false
        }
        'like' {
            # PowerShell wildcards (* ? [ab]), case-insensitive; value = one pattern or a list (any). Tag entries as in matches.
            # A pattern is built once and kept. A long list (a device's installed software) is matched ONCE per pattern: a
            # wildcard of plain text and '*' by one search over the list's texts joined together, any other wildcard text
            # by text -- never value by value through a function call (see the block above Get-SIConditionRegex).
            $tl = Get-SIMatchTextList $field $actual
            foreach ($pat in (Get-SIValueList $expected)) {
                $p = [string]$pat
                if ($null -ne $tl) {
                    if ($tl.Texts.Length -eq 0) { continue }
                    if ($null -ne $tl.Joined) {
                        $line = Get-SIWildcardLineRegex $p
                        if ($null -ne $line) {
                            $found = $null
                            try { $found = $line.IsMatch($tl.Joined) } catch { $found = $null }
                            if ($found -eq $true) { return $true }
                            if ($found -eq $false) { continue }
                        }
                    }
                    $wc = Get-SIConditionWildcard $p
                    foreach ($s in $tl.Texts) { if ($wc.IsMatch($s)) { return $true } }
                    continue
                }
                $wc = Get-SIConditionWildcard $p
                foreach ($v in (Get-SIValueList $actual)) { foreach ($s in (Get-SIMatchTexts $v)) { if ($wc.IsMatch($s)) { return $true } } }
            }
            return $false
        }
        { $_ -in 'older_than_days', 'newer_than_days' } {
            $days = ConvertTo-SINumberOrNull $expected
            if ($null -eq $days) { throw "condition '$field $op' needs a number of days, got '$expected'" }
            $now = [datetime]::UtcNow
            if ($Context -and $Context.Now) { $now = ([datetime]$Context.Now).ToUniversalTime() }
            $t = ConvertTo-SIUtcOrNull $actual
            if ($null -eq $t) { return $false }
            $age = ($now - $t).TotalDays
            if ($op -eq 'older_than_days') { return ($age -gt $days) }
            return ($age -le $days)
        }
        'in_ranges' {
            $ranges = Resolve-SIListValues $expected $Context
            foreach ($ip in (Get-SIValueList $actual)) { foreach ($r in $ranges) { if (Test-SIIpInCidr ([string]$ip) ([string]$r)) { return $true } } }
            return $false
        }
        'in_list' {
            $id = [string]$expected
            if (-not ($Context -and $Context.Lists -and $Context.Lists.ContainsKey($id))) { throw "condition '$field in_list $id': no such list" }
            $l = $Context.Lists[$id]
            $type = [string](Get-SIItemValue $l 'type')
            if ($type -eq 'conditions') {
                foreach ($entry in (Get-SIValueList (Get-SIItemValue $l 'entries'))) {
                    $w = Get-SIItemValue $entry 'when'
                    # an entry that needs a field the item does not carry is false (Get-SIConditionNullFalseField) -- not evaluated
                    $rf = Get-SIConditionNullFalseField $w
                    if ($rf -and $null -eq (Get-SIItemValue $Item $rf)) { continue }
                    if (Test-SICondition -Condition $w -Item $Item -Context $Context) { return $true }
                }
                return $false
            }
            foreach ($v in (Get-SIValueList $actual)) { foreach ($e in (Get-SIValueList (Get-SIItemValue $l 'values'))) { if (Test-SIScalarEqual $v $e) { return $true } } }
            return $false
        }
        default { throw "unknown condition operation '$op' (field '$field')" }
    }
}

function Get-SIConditionNullFalseField {
    <#
        The field that makes a condition FALSE when the item does not carry it (no value at all), or '' when there is none:
        a leaf -- or the FIRST condition of an 'all' group -- that compares the field (eq, ne, in, not_in, is_true, is_false,
        not_empty, contains, contains_any, like, in_ranges; matches when its patterns are valid) answers false for no value,
        and an 'all' stops at its first false. Such a condition need not be evaluated on an item without the field: the
        answer is the same (2026-10-16: the unsupported_os list's 25 entries were evaluated on every identity). Kept per
        condition object.
    #>
    param($Condition)
    if ($null -eq $Condition -or $Condition -is [string] -or $Condition -is [ValueType]) { return '' }
    $cache = $script:SIConditionNullFalseCache
    if ($null -eq $cache) { $cache = New-Object 'System.Runtime.CompilerServices.ConditionalWeakTable[object,object]'; $script:SIConditionNullFalseCache = $cache }
    $hit = $null
    if ($cache.TryGetValue($Condition, [ref]$hit)) { return [string]$hit }
    $leaf = $Condition
    $isDict = $Condition -is [System.Collections.IDictionary]
    if ($isDict) { $hasAll = $Condition.Contains('all'); $hasAny = $Condition.Contains('any') }
    else { $hasAll = [bool]$Condition.PSObject.Properties['all']; $hasAny = [bool]$Condition.PSObject.Properties['any'] }
    $field = ''
    if ($hasAll) {
        $kids = Get-SIValueList (Get-SIItemValue $Condition 'all')
        $leaf = $null; if ($kids.Count -gt 0) { $leaf = $kids[0] }
    } elseif ($hasAny) { $leaf = $null }
    if ($null -ne $leaf -and $leaf -isnot [string] -and $leaf -isnot [ValueType]) {
        $lAll = $false; $lAny = $false
        if ($leaf -is [System.Collections.IDictionary]) { $lAll = $leaf.Contains('all'); $lAny = $leaf.Contains('any') } else { $lAll = [bool]$leaf.PSObject.Properties['all']; $lAny = [bool]$leaf.PSObject.Properties['any'] }
        if (-not $lAll -and -not $lAny) {
            $lf = [string](Get-SIItemValue $leaf 'field'); $op = [string](Get-SIItemValue $leaf 'op')
            if ($lf -and $op -in 'eq', 'ne', 'in', 'not_in', 'is_true', 'is_false', 'not_empty', 'contains', 'contains_any', 'like', 'in_ranges') { $field = $lf }
            elseif ($lf -and $op -eq 'matches') {
                $ok = $true
                try { foreach ($p in (Get-SIValueList (Get-SIItemValue $leaf 'value'))) { $null = Get-SIConditionRegex ([string]$p) } } catch { $ok = $false }
                if ($ok) { $field = $lf }
            }
        }
    }
    try { $cache.Add($Condition, $field) } catch { }
    return $field
}

function Test-SIConditionTri {
    <#
    .SYNOPSIS  #546 UNKNOWN IS NEVER A FINDING. A condition evaluated in THREE states: $true, $false, or $null = unknown.
               A leaf is unknown when
                 * its field is in -UnknownFields (the CI build could not decide the field: the provider that decides it for
                   this identity's origin is not linked -- si_unknown_fields), or
                 * it compares a date or a number (older_than_days, newer_than_days, gt, gte, lt, lte) and the value is empty:
                   an age that was never read is not "older than 365 days".
               Every other leaf is Test-SICondition (so an empty value in a population leaf -- in, eq -- stays false: the
               item is simply not in the population). all: any false -> false, else any unknown -> unknown, else true.
               any: any true -> true, else any unknown -> unknown, else false.
               A caller counts a finding ONLY on $true; $null is counted as unknown.
    #>
    param([Parameter(Mandatory)]$Condition, $Item, [hashtable]$Context, [string[]]$UnknownFields = @())
    if ($null -eq $Condition) { return $true }
    # (the group test as in Test-SICondition: a dictionary's own Contains, an object's properties)
    $isDict = $Condition -is [System.Collections.IDictionary]
    if ($isDict) { $hasAll = $Condition.Contains('all'); $hasAny = $Condition.Contains('any') }
    else { $hasAll = [bool]$Condition.PSObject.Properties['all']; $hasAny = [bool]$Condition.PSObject.Properties['any'] }
    if ($hasAll) {
        $unknown = $false
        foreach ($c in (Get-SIValueList (Get-SIItemValue $Condition 'all'))) {
            $r = Test-SIConditionTri -Condition $c -Item $Item -Context $Context -UnknownFields $UnknownFields
            if ($r -eq $false) { return $false }
            if ($null -eq $r) { $unknown = $true }
        }
        if ($unknown) { return $null }
        return $true
    }
    if ($hasAny) {
        $unknown = $false
        foreach ($c in (Get-SIValueList (Get-SIItemValue $Condition 'any'))) {
            $r = Test-SIConditionTri -Condition $c -Item $Item -Context $Context -UnknownFields $UnknownFields
            if ($r -eq $true) { return $true }
            if ($null -eq $r) { $unknown = $true }
        }
        if ($unknown) { return $null }
        return $false
    }
    if ($isDict) {
        if ($Condition.Contains('field')) { $field = [string]$Condition['field'] } else { $field = [string](Get-SIItemValue $Condition 'field') }
        if ($Condition.Contains('op')) { $op = [string]$Condition['op'] } else { $op = [string](Get-SIItemValue $Condition 'op') }
    } else {
        $pp = $Condition.PSObject.Properties['field']; if ($pp) { $field = [string]$pp.Value } else { $field = '' }
        $pp = $Condition.PSObject.Properties['op']; if ($pp) { $op = [string]$pp.Value } else { $op = '' }
    }
    foreach ($u in @($UnknownFields)) { if ($u -and [string]::Equals([string]$u, $field, [StringComparison]::OrdinalIgnoreCase)) { return $null } }
    # A FIELD THE ITEM DOES NOT CARRY AT ALL (no value) is answered here, without a second evaluation (2026-10-16: most
    # factor and classification leaves read a field the CI does not have) -- the answers Test-SICondition gives for $null:
    # a comparison, a text or list test is false, is_empty is true, a date / number test is unknown (below). in_list,
    # matches (an invalid pattern throws even on no value) and anything else are evaluated as before.
    if ($field) {
        if ($Item -is [System.Collections.IDictionary] -and $Item.Contains($field)) { $av = $Item[$field] } else { $av = Get-SIItemValue $Item $field }
        if ($null -eq $av) {
            if ($op -in 'eq', 'ne', 'in', 'not_in', 'is_true', 'is_false', 'not_empty', 'contains', 'contains_any', 'like', 'in_ranges') { return $false }
            # matches: false too when its patterns are valid (an invalid one throws, as before)
            if ($op -eq 'matches' -and (Get-SIConditionNullFalseField $Condition) -ceq $field) { return $false }
            if ($op -eq 'is_empty') { return $true }
            if ($op -in 'older_than_days', 'newer_than_days', 'gt', 'gte', 'lt', 'lte') { return $null }
        }
    }
    if ($op -in 'older_than_days', 'newer_than_days', 'gt', 'gte', 'lt', 'lte') {
        if (Test-SIValueEmpty (Get-SIItemValue $Item $field)) { return $null }
    }
    return [bool](Test-SICondition -Condition $Condition -Item $Item -Context $Context)
}

function Get-SIConditionFields {
    <# Every field name a condition reads (for template validation). #>
    param($Condition)
    $out = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Condition) { return $out.ToArray() }
    foreach ($k in 'all', 'any') {
        $g = Get-SIItemValue $Condition $k
        if ($null -ne $g -or (($Condition -is [System.Collections.IDictionary] -and $Condition.Contains($k)) -or $Condition.PSObject.Properties[$k])) {
            foreach ($c in (Get-SIValueList $g)) { foreach ($f in (Get-SIConditionFields $c)) { $out.Add($f) } }
            return $out.ToArray()
        }
    }
    $f = [string](Get-SIItemValue $Condition 'field')
    if ($f) { $out.Add($f) }
    return $out.ToArray()
}
