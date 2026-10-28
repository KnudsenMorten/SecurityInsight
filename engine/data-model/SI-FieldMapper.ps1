#Requires -Version 5.1
<#
    SecurityInsight field mapper -- turns one provider object into one SI RECORD, using the provider's field mapping
    (data-model/mappings/<provider>.json), the shared value maps and the field catalog. V3-DATA-MODEL part 2, P1.

    A mapping item:  { field, recordTypes[], sources[], normalize[], combine?, resourceTypes? }
      sources    dot paths into the provider object, case-insensitive; "[*]" walks an array. Tried in order.
      normalize  a chain from the CLOSED operation set below, applied to every value a source produced.
      combine    first (default: the first source with a value) | max | min | any_true | union (all sources).
      resourceTypes  the item applies only to records of these Azure resource types.
    For one field, the first applicable mapping item that yields a value wins (more specific items come first).

    THE OPERATION SET IS CLOSED (a template or a customer override cannot run code):
      lower upper trim split:<sep> first require_contains:<text> ip mac cidr enum:<value-map> bool not equals:<value>
      present int number count datetime_utc filetime_utc parse_json to_list tags:<source> select:<key>=<value>:<take>
      base64_guid regex_extract:<pattern> host_from_url uac_enabled uac_flag:<n> dn_cn if_true:<value>
    An unknown operation throws.

    A source field that is missing is NOT an error: the SI field stays empty and the field is reported in .Missing, so
    the collector can count "mapped field missing" per (provider, field) -- the signal Invardia's provider scan uses.

    PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

. (Join-Path $PSScriptRoot 'SI-Conditions.ps1')

function Get-SIFieldMapperOps {
    return , @('lower', 'upper', 'trim', 'split', 'first', 'require_contains', 'ip', 'mac', 'cidr', 'enum', 'bool', 'not', 'equals',
        'present', 'int', 'number', 'count', 'datetime_utc', 'filetime_utc', 'parse_json', 'to_list', 'tags', 'select',
        'base64_guid', 'regex_extract', 'host_from_url', 'uac_enabled', 'uac_flag', 'dn_cn', 'if_true')
}

function Get-SIMapItemWhenAbsent {
    <#
        PURE. A mapping item's `whenAbsent` -- the value the field gets when the record carries the source OBJECT but none of
        the item's paths has a value (si_publisher_verified: an SP without verifiedPublisher.verifiedPublisherId is NOT
        verified, so false). Returns @{ Has; Value }.
        Opt-in per item on purpose, not a change to `present`: present feeds si_fix_available too, and the zero-day factor
        fires on si_fix_available false -- a generic "absent = false" would have marked every CVE without a named security
        update (all third-party software) a zero-day.
    #>
    param($MapItem)
    if ($null -eq $MapItem) { return @{ Has = $false; Value = $null } }
    if ($MapItem -is [System.Collections.IDictionary]) {
        if ($MapItem.Contains('whenAbsent')) { return @{ Has = $true; Value = $MapItem['whenAbsent'] } }
        return @{ Has = $false; Value = $null }
    }
    $p = $MapItem.PSObject.Properties['whenAbsent']
    if ($null -ne $p -and $null -ne $p.Value) { return @{ Has = $true; Value = $p.Value } }
    return @{ Has = $false; Value = $null }
}

function Test-SISourceRootPresent {
    <#
        PURE. Is the OBJECT a source path starts in there (sp in "sp.verifiedPublisher.verifiedPublisherId")? Only then is a
        missing rest of the path a real "absent" (whenAbsent applies). A one-segment path, or an object without that root,
        says nothing: a record that never carried the object must not be told the value is absent.
    #>
    param($Object, [string]$Path)
    if ($null -eq $Object -or [string]::IsNullOrEmpty($Path)) { return $false }
    $i = $Path.IndexOf('.')
    if ($i -le 0) { return $false }
    $root = $Path.Substring(0, $i) -replace '\[\*\]$', ''
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in $Object.Keys) { if ([string]::Equals([string]$k, $root, [StringComparison]::OrdinalIgnoreCase)) { return ($null -ne $Object[$k]) } }
        return $false
    }
    $p = $Object.PSObject.Properties[$root]
    return ($null -ne $p -and $null -ne $p.Value)
}

function Resolve-SISourcePath {
    <#
    .SYNOPSIS  Every value at a dot path in an object (case-insensitive). "a.b[*].c" walks the array b. Returns a list.
               Without [*] an array value is returned as ONE value (so count / select / tags can see the whole array).
               A JSON string met on the way (e.g. an advanced-hunting dynamic column) is parsed and walked into.
    #>
    param($Object, [Parameter(Mandatory)][string]$Path)
    $current = [System.Collections.Generic.List[object]]::new()
    $current.Add($Object)
    foreach ($segRaw in $Path.Split('.')) {
        $walk = $segRaw.EndsWith('[*]')
        $seg = $segRaw
        if ($walk) { $seg = $segRaw.Substring(0, $segRaw.Length - 3) }
        $next = [System.Collections.Generic.List[object]]::new()
        foreach ($o in $current) {
            if ($null -eq $o) { continue }
            $node = $o
            if ($node -is [string]) {
                $t = $node.Trim()
                if ($t.StartsWith('{') -or $t.StartsWith('[')) { try { $node = $t | ConvertFrom-Json } catch { continue } } else { continue }
            }
            # Get-SIItemValue, inline (the innermost call of every mapped field of every record -- #475)
            $v = $null
            if ([string]::IsNullOrEmpty($seg)) { continue }
            if ($node -is [System.Collections.IDictionary]) {
                if ($node.Contains($seg)) { $v = $node[$seg] }
                else { foreach ($k in $node.Keys) { if ([string]::Equals([string]$k, $seg, [StringComparison]::OrdinalIgnoreCase)) { $v = $node[$k]; break } } }
            } else {
                $pp0 = $node.PSObject.Properties[$seg]
                if ($pp0) { $v = $pp0.Value }
            }
            if ($null -eq $v) { continue }
            if ($walk) {
                if ($v -is [string]) {
                    $t = $v.Trim()
                    if ($t.StartsWith('[')) { try { $v = $t | ConvertFrom-Json } catch { } }
                }
                if ($v -is [System.Collections.IDictionary]) {
                    # [*] over an object keyed by name (Shodan's vulns: { "CVE-...": {...} }) walks its values
                    foreach ($x in $v.Values) { if ($null -ne $x) { $next.Add($x) } }
                } elseif ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
                    foreach ($x in $v) { if ($null -ne $x) { $next.Add($x) } }
                } elseif ($v -is [System.Management.Automation.PSCustomObject]) {
                    foreach ($pp in $v.PSObject.Properties) { if ($null -ne $pp.Value) { $next.Add($pp.Value) } }
                } else { $next.Add($v) }
            } else { $next.Add($v) }
        }
        $current = $next
    }
    return , $current
}

function Get-SIValueMapResult {
    <# Looks a value up in a value map: { "$match": exact|prefix|contains, "<key>": <value>, ..., "$default": ... }. #>
    param($Map, $Value)
    $mode = [string](Get-SIItemValue $Map '$match'); if (-not $mode) { $mode = 'exact' }
    $s = ([string]$Value).Trim()
    $keys = @()
    if ($Map -is [System.Collections.IDictionary]) { $keys = @($Map.Keys) } else { $keys = @($Map.PSObject.Properties.Name) }
    # longest key first, so "WindowsServer" wins over "Windows" in prefix / contains mode
    foreach ($k in ($keys | Where-Object { -not ([string]$_).StartsWith('$') } | Sort-Object { ([string]$_).Length } -Descending)) {
        $ks = [string]$k
        $hit = $false
        switch ($mode) {
            'prefix' { $hit = $s.StartsWith($ks, [StringComparison]::OrdinalIgnoreCase) }
            'contains' { $hit = ($s.IndexOf($ks, [StringComparison]::OrdinalIgnoreCase) -ge 0) }
            default { $hit = [string]::Equals($s, $ks, [StringComparison]::OrdinalIgnoreCase) }
        }
        if ($hit) { return , @{ Found = $true; Value = (Get-SIItemValue $Map $ks) } }
    }
    $hasDefault = ($Map -is [System.Collections.IDictionary] -and $Map.Contains('$default')) -or ($Map.PSObject.Properties['$default'])
    if ($hasDefault) {
        $d = Get-SIItemValue $Map '$default'
        if ([string]$d -eq '$self_lower') { return , @{ Found = $true; Value = $s.ToLowerInvariant() } }
        return , @{ Found = $true; Value = $d }
    }
    return , @{ Found = $false; Value = $null }
}

function Invoke-SINormalizeOp {
    <# One operation over a list of values -> a new list. #>
    param([System.Collections.Generic.List[object]]$Values, [string]$Op, [string]$Arg, $ValueMaps)
    $out = [System.Collections.Generic.List[object]]::new()
    switch ($Op) {
        'lower' { foreach ($v in $Values) { $out.Add(([string]$v).ToLowerInvariant()) } }
        'upper' { foreach ($v in $Values) { $out.Add(([string]$v).ToUpperInvariant()) } }
        'trim' { foreach ($v in $Values) { if ($v -is [string]) { $t = $v.Trim(); if ($t) { $out.Add($t) } } else { $out.Add($v) } } }
        'split' { foreach ($v in $Values) { foreach ($p in ([string]$v).Split([string[]]@($Arg), [StringSplitOptions]::None)) { $out.Add($p) } } }
        'first' { if ($Values.Count -gt 0) { $out.Add($Values[0]) } }
        'require_contains' { foreach ($v in $Values) { if (([string]$v).Contains($Arg)) { $out.Add($v) } } }
        'ip' {
            foreach ($v in $Values) {
                $a = $null
                if ([System.Net.IPAddress]::TryParse(([string]$v).Trim(), [ref]$a)) { $out.Add($a.ToString().ToLowerInvariant()) }
            }
        }
        'mac' {
            foreach ($v in $Values) {
                $hex = ([string]$v -replace '[^0-9A-Fa-f]', '').ToLowerInvariant()
                if ($hex.Length -eq 12 -and $hex -ne '000000000000' -and $hex -ne 'ffffffffffff') {
                    $out.Add((($hex -split '(..)' | Where-Object { $_ }) -join ':'))
                }
            }
        }
        'cidr' {
            foreach ($v in $Values) {
                $s = ([string]$v).Trim(); $parts = $s.Split('/')
                $a = $null
                if ([System.Net.IPAddress]::TryParse($parts[0], [ref]$a)) { $out.Add($s.ToLowerInvariant()) }
                elseif ($s -in '*', 'Internet', 'Any') { $out.Add('0.0.0.0/0') }
            }
        }
        'enum' {
            $map = Get-SIItemValue $ValueMaps $Arg
            if ($null -eq $map) { throw "normalize enum:${Arg}: no such value map" }
            foreach ($v in $Values) {
                $r = Get-SIValueMapResult -Map $map -Value $v
                if ($r.Found -and $null -ne $r.Value) { $out.Add($r.Value) }
            }
        }
        'bool' { foreach ($v in $Values) { $b = ConvertTo-SIBoolOrNull $v; if ($null -ne $b) { $out.Add($b) } } }
        'not' { foreach ($v in $Values) { $b = ConvertTo-SIBoolOrNull $v; if ($null -ne $b) { $out.Add((-not $b)) } } }
        'equals' { foreach ($v in $Values) { $out.Add((Test-SIScalarEqual $v $Arg)) } }
        'present' { $out.Add(($Values.Count -gt 0 -and -not (Test-SIValueEmpty $Values[0]))) }
        'int' { foreach ($v in $Values) { $n = ConvertTo-SINumberOrNull $v; if ($null -ne $n) { $out.Add([long][Math]::Truncate($n)) } } }
        'number' { foreach ($v in $Values) { $n = ConvertTo-SINumberOrNull $v; if ($null -ne $n) { $out.Add([double]$n) } } }
        'count' {
            if ($Values.Count -eq 1 -and $Values[0] -is [System.Collections.IEnumerable] -and -not ($Values[0] -is [string])) {
                $c = 0; foreach ($x in $Values[0]) { $c++ }; $out.Add([long]$c)
            } else { $out.Add([long]$Values.Count) }
        }
        'datetime_utc' { foreach ($v in $Values) { $t = ConvertTo-SIUtcOrNull $v; if ($null -ne $t -and $t.Year -gt 1601) { $out.Add($t) } } }
        'filetime_utc' {
            foreach ($v in $Values) {
                $n = ConvertTo-SINumberOrNull $v
                if ($null -ne $n -and $n -gt 0 -and $n -lt 2650467743999999999) { $out.Add([datetime]::FromFileTimeUtc([long]$n)) }
            }
        }
        'parse_json' {
            # #690 (35) a text that is not JSON is the value itself: the identity profile writes a ONE-item list as the bare
            # item ("Global Administrator", not ["Global Administrator"]) -- dropping it lost every identity with exactly one
            # role, permission or group (internal 2026-10-15: 3 of 6 Global Administrators, 17 of 22 standing roles). A text
            # that parses is taken parsed, as before; only a text that looks like JSON ([ { ") and does not parse is dropped.
            foreach ($v in $Values) {
                if ($v -is [string]) {
                    $t = $v.Trim()
                    if (-not $t) { continue }
                    $parsed = $null; $ok = $false
                    try { $parsed = ($t | ConvertFrom-Json); $ok = $true } catch { $ok = $false }
                    if ($ok) { if ($null -ne $parsed) { $out.Add($parsed) } }
                    elseif (-not ($t.StartsWith('[') -or $t.StartsWith('{') -or $t.StartsWith('"'))) { $out.Add($t) }
                } else { $out.Add($v) }
            }
        }
        'to_list' { foreach ($v in $Values) { $out.Add($v) } }
        'tags' {
            foreach ($v in $Values) {
                $node = $v
                if ($node -is [string] -and $node.Trim().StartsWith('{')) { try { $node = $node | ConvertFrom-Json } catch { } }
                if ($node -is [string]) {
                    $kv = $node.Split([char[]]@('=', ':'), 2)
                    if ($kv.Count -eq 2) { $out.Add([ordered]@{ source = $Arg; name = $kv[0].Trim(); value = $kv[1].Trim() }) }
                    elseif ($node.Trim()) { $out.Add([ordered]@{ source = $Arg; name = $node.Trim(); value = '' }) }
                } elseif ($node -is [System.Collections.IDictionary]) {
                    foreach ($k in $node.Keys) { if (-not (Test-SIValueEmpty $node[$k])) { $out.Add([ordered]@{ source = $Arg; name = [string]$k; value = [string]$node[$k] }) } }
                } elseif ($null -ne $node) {
                    foreach ($p in $node.PSObject.Properties) { if (-not (Test-SIValueEmpty $p.Value)) { $out.Add([ordered]@{ source = $Arg; name = $p.Name; value = [string]$p.Value }) } }
                }
            }
        }
        'select' {
            # select:<key>=<value>:<take>  -- e.g. select:type=AadDeviceId:id over an EntityIds array
            # <value> may name alternatives a|b: the values of the FIRST alternative come first (then 'first' picks it)
            $m = [regex]::Match($Arg, '^(?<k>[^=]+)=(?<v>[^:]+):(?<t>.+)$')
            if (-not $m.Success) { throw "normalize select:${Arg}: expected <key>=<value>:<take>" }
            # 🔴 Exposure Graph's EntityIds is an array of JSON TEXT, one string per id
            # (["{\"type\":\"DeviceInventoryId\",\"id\":\"...\"}"]): an element that is JSON text is read as its object. It was
            # not, so no Exposure Graph device or resource record carried its Defender device id or resource id, the CI build
            # never joined it with its Defender / Azure record, and the two groups collided on one CI id -- ring 1 2026-10-10:
            # 211 of 218 device CIs without their Defender link, every CVE finding without its CI (tier, factors).
            $toObj = { param($x) if ($x -is [string]) { $t = $x.Trim(); if ($t.StartsWith('[') -or $t.StartsWith('{')) { try { return ($t | ConvertFrom-Json) } catch { return $null } }; return $null }; $x }
            $alts = @($m.Groups['v'].Value -split '\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $elems = New-Object System.Collections.Generic.List[object]
            foreach ($v in $Values) {
                # an array, or ONE object (select:<key>=<value>:<take> as a condition on an object, e.g. Exposure Graph rawData)
                $arr = & $toObj $v
                if ($null -eq $arr) { continue }
                foreach ($e in (Get-SIValueList $arr)) { $o = & $toObj $e; if ($null -ne $o) { $elems.Add($o) } }
            }
            foreach ($alt in $alts) {
                foreach ($e in $elems) {
                    if (Test-SIScalarEqual (Get-SIItemValue $e $m.Groups['k'].Value) $alt) {
                        $x = Get-SIItemValue $e $m.Groups['t'].Value
                        if (-not (Test-SIValueEmpty $x)) { $out.Add($x) }
                    }
                }
            }
        }
        'base64_guid' {
            foreach ($v in $Values) {
                try { $b = [Convert]::FromBase64String([string]$v); if ($b.Length -eq 16) { $out.Add((New-Object Guid (, $b)).ToString()) } } catch { }
            }
        }
        'regex_extract' {
            $rx = New-Object System.Text.RegularExpressions.Regex($Arg, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, ([TimeSpan]::FromMilliseconds(200)))
            foreach ($v in $Values) {
                $mm = $rx.Match([string]$v)
                if ($mm.Success) { if ($mm.Groups.Count -gt 1) { $out.Add($mm.Groups[1].Value) } else { $out.Add($mm.Value) } }
            }
        }
        'host_from_url' {
            foreach ($v in $Values) {
                $s = [string]$v; $u = $null
                if ($s -match '^[a-z]+://' -and [Uri]::TryCreate($s, [UriKind]::Absolute, [ref]$u)) { $out.Add($u.Host.ToLowerInvariant()) } else { $out.Add($s.TrimEnd('/')) }
            }
        }
        'if_true' { foreach ($v in $Values) { if ((ConvertTo-SIBoolOrNull $v) -eq $true) { $out.Add($Arg) } } }
        'uac_enabled' { foreach ($v in $Values) { $n = ConvertTo-SINumberOrNull $v; if ($null -ne $n) { $out.Add((([long]$n -band 2) -eq 0)) } } }
        # #546 one userAccountControl flag set (true) or clear (false), e.g. uac_flag:65536 = DONT_EXPIRE_PASSWORD; no value = nothing
        'uac_flag' {
            $bit = [long]0
            if (-not [long]::TryParse([string]$Arg, [ref]$bit) -or $bit -le 0) { throw "uac_flag needs a positive flag value, got '$Arg'" }
            foreach ($v in $Values) { $n = ConvertTo-SINumberOrNull $v; if ($null -ne $n) { $out.Add((([long]$n -band $bit) -ne 0)) } }
        }
        'dn_cn' { foreach ($v in $Values) { $mm = [regex]::Match([string]$v, '^CN=(?<cn>(\\,|[^,])+)', 'IgnoreCase'); if ($mm.Success) { $out.Add(($mm.Groups['cn'].Value -replace '\\,', ',')) } } }
        default { throw "unknown normalize operation '$Op'" }
    }
    return , $out
}

function Invoke-SINormalize {
    <# A normalisation chain ("op" or "op:arg" strings, split on the FIRST colon) over a list of values. #>
    param([System.Collections.Generic.List[object]]$Values, [string[]]$Chain, $ValueMaps)
    $cur = $Values
    foreach ($step in @($Chain)) {
        if ([string]::IsNullOrWhiteSpace($step)) { continue }
        $i = $step.IndexOf(':')
        $op = $step; $arg = ''
        if ($i -ge 0) { $op = $step.Substring(0, $i); $arg = $step.Substring($i + 1) }
        $cur = Invoke-SINormalizeOp -Values $cur -Op $op -Arg $arg -ValueMaps $ValueMaps
        if ($cur.Count -eq 0 -and $op -ne 'present') { break }
    }
    return , $cur
}

function ConvertTo-SIFieldValue {
    <# The final value of a field from the values its mapping produced, by the catalog type. #>
    param([System.Collections.Generic.List[object]]$Values, [string]$Type)
    if ($null -eq $Values -or $Values.Count -eq 0) { return $null }
    switch ($Type) {
        'dynamic' {
            # de-duplicate scalars, keep objects as they are
            $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            $list = [System.Collections.Generic.List[object]]::new()
            foreach ($v in $Values) {
                if ($v -is [string] -or $v -is [ValueType]) { if ($seen.Add([string]$v)) { $list.Add($v) } }
                elseif ($v -is [System.Collections.IDictionary]) {
                    $k = (($v.Keys | Sort-Object | ForEach-Object { "$_=$($v[$_])" }) -join '|')
                    if ($seen.Add($k)) { $list.Add($v) }
                } elseif ($v -is [System.Collections.IEnumerable]) { foreach ($x in $v) { $list.Add($x) } }
                else { $list.Add($v) }
            }
            return , $list.ToArray()
        }
        'bool' { return (ConvertTo-SIBoolOrNull $Values[0]) }
        'int' { $n = ConvertTo-SINumberOrNull $Values[0]; if ($null -eq $n) { return $null }; return [long][Math]::Truncate($n) }
        'real' { return (ConvertTo-SINumberOrNull $Values[0]) }
        'datetime' { return (ConvertTo-SIUtcOrNull $Values[0]) }
        default { $v = $Values[0]; if ($null -eq $v) { return $null }; return [string]$v }
    }
}

function Get-SIMappingValues {
    <# The normalised values of ONE mapping item for an object, honouring "combine". #>
    param($MapItem, $Object, $ValueMaps)
    $combine = [string](Get-SIItemValue $MapItem 'combine'); if (-not $combine) { $combine = 'first' }
    $chain = @(Get-SIItemValue $MapItem 'normalize')
    $all = [System.Collections.Generic.List[object]]::new()
    $wa = Get-SIMapItemWhenAbsent $MapItem
    $absent = $false
    foreach ($src in @(Get-SIItemValue $MapItem 'sources')) {
        $raw = Resolve-SISourcePath -Object $Object -Path ([string]$src)
        if ($raw.Count -eq 0) {
            if ($wa.Has -and (Test-SISourceRootPresent -Object $Object -Path ([string]$src))) { $absent = $true }
            continue
        }
        $vals = Invoke-SINormalize -Values $raw -Chain $chain -ValueMaps $ValueMaps
        $vals = @($vals | Where-Object { -not (Test-SIValueEmpty $_) -or $_ -is [bool] })
        if ($vals.Count -eq 0) { continue }
        if ($combine -eq 'first') { $l = [System.Collections.Generic.List[object]]::new(); foreach ($v in $vals) { $l.Add($v) }; return , $l }
        foreach ($v in $vals) { $all.Add($v) }
    }
    if ($all.Count -eq 0 -and $absent) {
        # the object is there, no path had a value: the item's whenAbsent (Get-SIMapItemWhenAbsent)
        $all.Add($wa.Value)
        if ($combine -eq 'first') { return , $all }
    }
    $res = [System.Collections.Generic.List[object]]::new()
    if ($all.Count -eq 0) { return , $res }
    switch ($combine) {
        'max' {
            $best = $null
            foreach ($v in $all) {
                if ($null -eq $best) { $best = $v; continue }
                $a = $v; $b = $best
                if ($v -is [datetime] -or $best -is [datetime]) { if ((ConvertTo-SIUtcOrNull $a) -gt (ConvertTo-SIUtcOrNull $b)) { $best = $v } }
                elseif ((ConvertTo-SINumberOrNull $a) -gt (ConvertTo-SINumberOrNull $b)) { $best = $v }
            }
            $res.Add($best)
        }
        'min' {
            $best = $null
            foreach ($v in $all) {
                if ($null -eq $best) { $best = $v; continue }
                if ($v -is [datetime] -or $best -is [datetime]) { if ((ConvertTo-SIUtcOrNull $v) -lt (ConvertTo-SIUtcOrNull $best)) { $best = $v } }
                elseif ((ConvertTo-SINumberOrNull $v) -lt (ConvertTo-SINumberOrNull $best)) { $best = $v }
            }
            $res.Add($best)
        }
        'any_true' {
            $sawFalse = $false
            foreach ($v in $all) { $b = ConvertTo-SIBoolOrNull $v; if ($b -eq $true) { $res.Add($true); return , $res }; if ($b -eq $false) { $sawFalse = $true } }
            if ($sawFalse) { $res.Add($false) }
        }
        'union' { foreach ($v in $all) { $res.Add($v) } }
        default { throw "unknown combine '$combine'" }
    }
    return , $res
}

function ConvertTo-SIRecord {
    <#
    .SYNOPSIS  One provider object -> one SI record (ordered dictionary of SI fields) + the fields whose sources were missing.
    .OUTPUTS   @{ Record = [ordered]; Missing = [string[]] }
    #>
    param(
        [Parameter(Mandatory)]$Object,
        [Parameter(Mandatory)]$Mapping,        # one parsed mappings/<provider>.json (merged with overrides)
        [Parameter(Mandatory)][string]$RecordType,
        [Parameter(Mandatory)]$Catalog,        # parsed field catalog (merged)
        [Parameter(Mandatory)]$ValueMaps,      # the "maps" object of value-maps.json (merged)
        [string]$ResourceType,
        [datetime]$CollectionTime = [datetime]::UtcNow,
        [string]$RunId
    )
    $plan = Get-SIMapperPlan -Mapping $Mapping -RecordType $RecordType -ResourceType $ResourceType -Catalog $Catalog
    $provider = $plan.Provider

    $rec = [ordered]@{}
    $keyVals = Resolve-SISourcePath -Object $Object -Path $plan.KeyPath
    $nativeKey = $null; if ($keyVals.Count -gt 0) { $nativeKey = ([string]$keyVals[0]).ToLowerInvariant() }
    $rec['si_provider'] = $provider
    $rec['si_record_type'] = $RecordType
    $rec['si_class'] = $plan.Class
    $rec['si_record_key'] = if ($nativeKey) { "${provider}:$nativeKey" } else { $null }
    $rec['si_collection_time'] = $CollectionTime.ToUniversalTime()
    if ($RunId) { $rec['si_run_id'] = $RunId }
    $tsPath = $plan.TsPath
    $ts = $null
    if ($tsPath -and $tsPath -ne '$collection_time') {
        $tv = Resolve-SISourcePath -Object $Object -Path $tsPath
        if ($tv.Count -gt 0) {
            $tn = Invoke-SINormalize -Values $tv -Chain @('datetime_utc') -ValueMaps $ValueMaps
            if ($tn.Count -eq 0 -and $provider -eq 'ad') { $tn = Invoke-SINormalize -Values $tv -Chain @('filetime_utc') -ValueMaps $ValueMaps }
            if ($tn.Count -gt 0) { $ts = $tn[0] }
        }
    }
    if ($null -eq $ts) { $ts = $CollectionTime.ToUniversalTime() }
    $rec['si_source_last_seen'] = $ts

    $done = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($it in $plan.Items) {
        $field = $it.Field
        if ($done.Contains($field)) { continue }
        # the values of this item (Get-SIMappingValues, compiled: the item's settings were read once, no pipeline)
        $vals = $null
        $all = $null
        $absent = $false
        foreach ($src in $it.Sources) {
            # Resolve-SISourcePath, inline for a path without [*]: at most ONE value; a JSON string met on the way (or a
            # [*] path) takes the full resolver, which handles both
            $raw = $null
            if ($src.Simple) {
                $node = $Object; $hit = $true
                foreach ($seg in $src.Segs) {
                    if ($null -eq $node) { $hit = $false; break }
                    if ($node -is [string]) { $raw = Resolve-SISourcePath -Object $Object -Path $src.Path; break }
                    $nx = $null
                    if ([string]::IsNullOrEmpty($seg)) { $hit = $false; break }
                    if ($node -is [System.Collections.IDictionary]) {
                        if ($node.Contains($seg)) { $nx = $node[$seg] }
                        else { foreach ($k in $node.Keys) { if ([string]::Equals([string]$k, $seg, [StringComparison]::OrdinalIgnoreCase)) { $nx = $node[$k]; break } } }
                    } else {
                        $pp1 = $node.PSObject.Properties[$seg]
                        if ($pp1) { $nx = $pp1.Value }
                    }
                    if ($null -eq $nx) { $hit = $false; break }
                    $node = $nx
                }
                if ($null -eq $raw) {
                    $raw = [System.Collections.Generic.List[object]]::new()
                    if ($hit) { $raw.Add($node) }
                }
            } else { $raw = Resolve-SISourcePath -Object $Object -Path $src.Path }
            if ($raw.Count -eq 0) {
                if ($it.WhenAbsent.Has -and (Test-SISourceRootPresent -Object $Object -Path $src.Path)) { $absent = $true }
                continue
            }
            # Invoke-SINormalize, inline: lower / trim / upper here, every other operation by Invoke-SINormalizeOp
            $nv = $raw
            foreach ($st in $it.Steps) {
                switch ($st.Op) {
                    'lower' { $n2 = [System.Collections.Generic.List[object]]::new(); foreach ($y in $nv) { $n2.Add(([string]$y).ToLowerInvariant()) }; $nv = $n2 }
                    'upper' { $n2 = [System.Collections.Generic.List[object]]::new(); foreach ($y in $nv) { $n2.Add(([string]$y).ToUpperInvariant()) }; $nv = $n2 }
                    'trim' { $n2 = [System.Collections.Generic.List[object]]::new(); foreach ($y in $nv) { if ($y -is [string]) { $ty = $y.Trim(); if ($ty) { $n2.Add($ty) } } else { $n2.Add($y) } }; $nv = $n2 }
                    default { $nv = Invoke-SINormalizeOp -Values $nv -Op $st.Op -Arg $st.Arg -ValueMaps $ValueMaps }
                }
                if ($nv.Count -eq 0 -and $st.Op -ne 'present') { break }
            }
            # Test-SIValueEmpty, inline (a bool is always kept)
            $kept = [System.Collections.Generic.List[object]]::new()
            foreach ($x in $nv) {
                $empty = $false
                if ($null -eq $x) { $empty = $true }
                elseif ($x -is [string]) { $empty = [string]::IsNullOrWhiteSpace($x) }
                elseif ($x -is [System.Collections.IDictionary]) { $empty = ($x.Count -eq 0) }
                elseif ($x -is [System.Collections.IEnumerable]) { $empty = $true; foreach ($z in $x) { $empty = $false; break } }
                if (-not $empty -or $x -is [bool]) { $kept.Add($x) }
            }
            if ($kept.Count -eq 0) { continue }
            if ($it.Combine -eq 'first') { $vals = $kept; break }
            if ($null -eq $all) { $all = [System.Collections.Generic.List[object]]::new() }
            foreach ($x in $kept) { $all.Add($x) }
        }
        if ($absent -and $null -eq $vals -and ($null -eq $all -or $all.Count -eq 0)) {
            # the object is there, no path had a value: the item's whenAbsent (Get-SIMapItemWhenAbsent)
            $all = [System.Collections.Generic.List[object]]::new(); $all.Add($it.WhenAbsent.Value)
            if ($it.Combine -eq 'first') { $vals = $all }
        }
        if ($null -eq $vals -and $it.Combine -ne 'first') { $vals = Get-SIMapperCombined -Values $all -Combine $it.Combine }
        if ($null -eq $vals -or $vals.Count -eq 0) { continue }
        # ConvertTo-SIFieldValue; its default branch (every type but dynamic / bool / int / real / datetime) inline
        if ($it.PlainType) { $v = $vals[0]; if ($null -ne $v) { $v = [string]$v } }
        else { $v = ConvertTo-SIFieldValue -Values $vals -Type $it.Type }
        if ($null -eq $v) { continue }
        if ($it.Union) {
            # a union field ADDS up over every applicable item (several Exposure Graph flags -> one si_device_roles)
            if ($rec.Contains($field)) {
                $acc = [System.Collections.Generic.List[object]]::new()
                foreach ($x in @($rec[$field])) { $acc.Add($x) }
                foreach ($x in @($v)) { if (-not ($acc -contains $x)) { $acc.Add($x) } }
                $rec[$field] = $acc.ToArray()
            } else { $rec[$field] = $v }
            continue
        }
        $rec[$field] = $v
        [void]$done.Add($field)
    }
    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($it in $plan.Items) {
        $field = $it.Field
        if ($done.Contains($field) -or $rec.Contains($field) -or $missing.Contains($field)) { continue }
        $missing.Add($field)
    }
    return @{ Record = $rec; Missing = $missing.ToArray() }
}

function Get-SIMapperCombined {
    <# The "combine" of a mapping item over every source's values (max / min / any_true / union) -- as Get-SIMappingValues. #>
    param([System.Collections.Generic.List[object]]$Values, [string]$Combine)
    $res = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Values -or $Values.Count -eq 0) { return , $res }
    switch ($Combine) {
        'max' {
            $best = $null
            foreach ($v in $Values) {
                if ($null -eq $best) { $best = $v; continue }
                $a = $v; $b = $best
                if ($v -is [datetime] -or $best -is [datetime]) { if ((ConvertTo-SIUtcOrNull $a) -gt (ConvertTo-SIUtcOrNull $b)) { $best = $v } }
                elseif ((ConvertTo-SINumberOrNull $a) -gt (ConvertTo-SINumberOrNull $b)) { $best = $v }
            }
            $res.Add($best)
        }
        'min' {
            $best = $null
            foreach ($v in $Values) {
                if ($null -eq $best) { $best = $v; continue }
                if ($v -is [datetime] -or $best -is [datetime]) { if ((ConvertTo-SIUtcOrNull $v) -lt (ConvertTo-SIUtcOrNull $best)) { $best = $v } }
                elseif ((ConvertTo-SINumberOrNull $v) -lt (ConvertTo-SINumberOrNull $best)) { $best = $v }
            }
            $res.Add($best)
        }
        'any_true' {
            $sawFalse = $false
            foreach ($v in $Values) { $b = ConvertTo-SIBoolOrNull $v; if ($b -eq $true) { $res.Add($true); return , $res }; if ($b -eq $false) { $sawFalse = $true } }
            if ($sawFalse) { $res.Add($false) }
        }
        'union' { foreach ($v in $Values) { $res.Add($v) } }
        default { throw "unknown combine '$Combine'" }
    }
    return , $res
}

$script:SIMapperPlans = @{}

function Get-SIMapperPlan {
    <#
        The mapping of ONE (provider mapping, record type, resource type), read ONCE (#475): the object definition, the field
        types from the catalog and the applicable mapping items in their order, each with its sources, normalisation chain,
        combine and type. Every record of that kind reuses it -- before, every record re-read the whole catalog and walked
        every mapping item twice through the generic accessors (measured: ~90% of the time of publishing a run's records).
        Cached by the mapping and catalog OBJECTS (reference), so a changed or different mapping is never mistaken for one
        already read.
    #>
    param([Parameter(Mandatory)]$Mapping, [Parameter(Mandatory)][string]$RecordType, [string]$ResourceType, [Parameter(Mandatory)]$Catalog)
    $rt = ''; if ($ResourceType) { $rt = $ResourceType.ToLowerInvariant() }
    $key = '{0}|{1}|{2}|{3}' -f [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Mapping), [System.Runtime.CompilerServices.RuntimeHelpers]::GetHashCode($Catalog), $RecordType, $rt
    $p = $script:SIMapperPlans[$key]
    if ($p -and [object]::ReferenceEquals($p.Mapping, $Mapping) -and [object]::ReferenceEquals($p.Catalog, $Catalog)) { return $p }

    $provider = [string](Get-SIItemValue $Mapping 'provider')
    $objDef = $null
    foreach ($o in @(Get-SIItemValue $Mapping 'objects')) { if ([string](Get-SIItemValue $o 'recordType') -eq $RecordType) { $objDef = $o; break } }
    if ($null -eq $objDef) { throw "mapping '$provider' has no object for record type '$RecordType'" }
    $types = @{}
    foreach ($f in @(Get-SIItemValue $Catalog 'fields')) { $types[[string]$f.name] = [string]$f.type }
    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @(Get-SIItemValue $Mapping 'mappings')) {
        if (@($item.recordTypes) -notcontains $RecordType) { continue }
        $rts = @(Get-SIItemValue $item 'resourceTypes')
        if ($rts.Count -gt 0 -and $rts[0]) { if (-not $rt -or $rts -notcontains $rt) { continue } }
        $field = [string]$item.field
        $combine = [string](Get-SIItemValue $item 'combine'); if (-not $combine) { $combine = 'first' }
        $type = $types[$field]; if (-not $type) { $type = 'string' }
        # the normalisation chain as steps (Invoke-SINormalize's parsing: blank steps skipped, "op:arg" split on the FIRST colon)
        $steps = [System.Collections.Generic.List[object]]::new()
        foreach ($c in @(Get-SIItemValue $item 'normalize')) {
            $cs = [string]$c
            if ([string]::IsNullOrWhiteSpace($cs)) { continue }
            $ci = $cs.IndexOf(':'); $op = $cs; $arg = ''
            if ($ci -ge 0) { $op = $cs.Substring(0, $ci); $arg = $cs.Substring($ci + 1) }
            $steps.Add([pscustomobject]@{ Op = $op; Arg = $arg })
        }
        # each source path split once; "Simple" = no [*] (walked inline; a [*] path goes through Resolve-SISourcePath)
        $srcs = [System.Collections.Generic.List[object]]::new()
        foreach ($s in @(Get-SIItemValue $item 'sources')) {
            $sp = [string]$s
            $srcs.Add([pscustomobject]@{ Path = $sp; Segs = $sp.Split('.'); Simple = ($sp -ne '' -and $sp.IndexOf('[*]') -lt 0) })
        }
        $items.Add([pscustomobject]@{ Field = $field; Combine = $combine; Type = $type; Union = ($combine -eq 'union' -and $type -eq 'dynamic')
                PlainType = ($type -notin @('dynamic', 'bool', 'int', 'real', 'datetime'))
                WhenAbsent = (Get-SIMapItemWhenAbsent $item)
                Steps = $steps.ToArray(); Sources = $srcs.ToArray() })
    }
    $p = [pscustomobject]@{ Mapping = $Mapping; Catalog = $Catalog; Provider = $provider; Class = [string](Get-SIItemValue $objDef 'class')
        KeyPath = [string](Get-SIItemValue $objDef 'key'); TsPath = [string](Get-SIItemValue $objDef 'timestamp'); Items = $items.ToArray() }
    if ($script:SIMapperPlans.Count -ge 500) { $script:SIMapperPlans.Clear() }
    $script:SIMapperPlans[$key] = $p
    $p
}
