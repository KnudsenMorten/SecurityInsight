#Requires -Version 5.1
<#
    SecurityInsight's own YAML reader -- replaces the powershell-yaml module.

    WHY. SecurityInsight v3 carries no PowerShell module dependencies. About 1,100 shipped YAML files
    (tier rules, the Risk Analysis report catalogue, asset tagging, operator decisions) were read
    with powershell-yaml's ConvertFrom-Yaml. This file reads them with plain PowerShell instead.

    WHAT IT READS -- exactly the YAML subset the shipped files use (measured over every shipped
    *.yaml, see docs/DESIGN.md "YAML reader"):
      - block mappings and block sequences, including a sequence written at the same indentation as
        its parent key, and "- key: value" maps inside a sequence
      - flow sequences on one line:  [a, 'b c', 3]   (a trailing comma is allowed)
      - plain scalars, also over several lines (folded with spaces, as YAML does)
      - 'single-quoted' ('' escapes a quote) and "double-quoted" (backslash escapes) on one line
      - literal and folded block scalars:  |  |-  >  >-   (KQL with | # : // inside is plain text)
      - full-line and trailing comments, CRLF or LF line ends, a UTF-8 BOM, one leading ---
    Anything else -- anchors, aliases, tags, flow mappings, multi-line quoted strings, |+ / >+,
    explicit indentation indicators, more than one document, tab indentation, quoted keys,
    duplicate keys -- is REFUSED with "<file>:<line>: <reason>". A rule file must never load as
    something different from what its author wrote.

    WHAT IT RETURNS -- the same shapes and types as powershell-yaml 0.4.12, so callers do not change:
      mapping  -> [hashtable] (case-insensitive), or [ordered] with -Ordered
      sequence -> [System.Collections.Generic.List[object]]
      plain    -> [bool] / [int] / [long] / [BigInteger] / [decimal] / [double] / $null / [string],
                  decided by the same .NET TryParse calls in the same order
      quoted / block scalars -> [string]
      an empty or comment-only text -> nothing ($null)
    tests/pester/SIv3-SIYaml.Tests.ps1 proves this deep-equal against powershell-yaml on every
    shipped file whenever that module is present.

    PERFORMANCE. One function, one pass over the lines, explicit stacks instead of recursion, and
    the number test only for plain values whose first character could start a number, a boolean or
    a null. Measured against powershell-yaml in docs/TESTS.md.
#>

# NO Set-StrictMode here -- it leaks into the caller's scope.
# NO script-scope variables either: callers dot-source this file from inside functions as well as
# at file level, and a $script: value set in one place is not the one read in the other.

function ConvertTo-SIYamlPlainValue {
    <# The plain-scalar typing rule of powershell-yaml 0.4.12, call for call. #>
    param([string]$Value)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $b = $false
    if ([bool]::TryParse($Value, [ref]$b)) { return $b }
    $bi = [System.Numerics.BigInteger]::Zero
    if ([System.Numerics.BigInteger]::TryParse($Value, ([System.Globalization.NumberStyles]::Float -bor [System.Globalization.NumberStyles]::Integer), $inv, [ref]$bi)) {
        $x = $bi -as [int];  if ($null -ne $x) { return $x }
        $x = $bi -as [long]; if ($null -ne $x) { return $x }
        return $bi
    }
    $d = [decimal]0
    if ([decimal]::TryParse($Value, [System.Globalization.NumberStyles]::Float, $inv, [ref]$d)) { return $d }
    $db = [double]0
    if ([double]::TryParse($Value, [System.Globalization.NumberStyles]::Float, $inv, [ref]$db)) { return $db }
    if ($Value -in '', '~', 'null', 'Null', 'NULL') { return $null }
    return $Value
}

function ConvertFrom-SIYamlJsonValue {
    <#
        One value of a JSON document, in powershell-yaml's shapes. JSON is valid YAML, and SecurityInsight Pro
        materialises its catalogues as JSON in *.yaml files. JSON strings are double-quoted YAML scalars, so they
        stay strings; numbers / true / false / null are plain scalars, so they get the same typing as plain YAML.
    #>
    param($Value, [bool]$Ordered)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [bool]) { return $Value }
    if ($Value -is [datetime]) { return $Value.ToString('o', [System.Globalization.CultureInfo]::InvariantCulture) }   # only a pwsh without -DateKind
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $cmp = [System.StringComparer]::CurrentCultureIgnoreCase
        $h = if ($Ordered) { [System.Collections.Specialized.OrderedDictionary]::new($cmp) } else { [hashtable]::new($cmp) }
        foreach ($p in $Value.PSObject.Properties) { $h[$p.Name] = ConvertFrom-SIYamlJsonValue -Value $p.Value -Ordered $Ordered }
        return $h
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $l = [System.Collections.Generic.List[object]]::new()
        foreach ($x in $Value) { $l.Add((ConvertFrom-SIYamlJsonValue -Value $x -Ordered $Ordered)) }
        return , $l
    }
    return (ConvertTo-SIYamlPlainValue -Value ([System.Convert]::ToString($Value, [System.Globalization.CultureInfo]::InvariantCulture)))
}

function ConvertFrom-SIYamlDoubleQuoted {
    <# Body of a one-line "double-quoted" scalar (without the quotes) -> string. #>
    param([string]$Body, [string]$Where)
    if ($Body.IndexOf([char]'\') -lt 0) { return $Body }
    $sb = [System.Text.StringBuilder]::new()
    $k = 0
    while ($k -lt $Body.Length) {
        $c = $Body[$k]
        if ($c -ne [char]'\') { [void]$sb.Append($c); $k++; continue }
        if ($k + 1 -ge $Body.Length) { throw ('{0}: a double-quoted string ends in a lone backslash' -f $Where) }
        $e = $Body[$k + 1]; $k += 2
        switch -CaseSensitive ([string]$e) {
            '0'  { [void]$sb.Append([char]0) }
            'a'  { [void]$sb.Append([char]7) }
            'b'  { [void]$sb.Append([char]8) }
            't'  { [void]$sb.Append([char]9) }
            "`t" { [void]$sb.Append([char]9) }
            'n'  { [void]$sb.Append([char]10) }
            'v'  { [void]$sb.Append([char]11) }
            'f'  { [void]$sb.Append([char]12) }
            'r'  { [void]$sb.Append([char]13) }
            'e'  { [void]$sb.Append([char]27) }
            ' '  { [void]$sb.Append(' ') }
            '"'  { [void]$sb.Append('"') }
            '/'  { [void]$sb.Append('/') }
            '\'  { [void]$sb.Append('\') }
            'N'  { [void]$sb.Append([char]0x85) }
            '_'  { [void]$sb.Append([char]0xA0) }
            'L'  { [void]$sb.Append([char]0x2028) }
            'P'  { [void]$sb.Append([char]0x2029) }
            { $_ -ceq 'x' -or $_ -ceq 'u' -or $_ -ceq 'U' } {
                $len = if ($e -ceq 'x') { 2 } elseif ($e -ceq 'u') { 4 } else { 8 }
                $hex = if ($k + $len -le $Body.Length) { $Body.Substring($k, $len) } else { '' }
                if ($hex -notmatch '^[0-9A-Fa-f]+$' -or $hex.Length -ne $len) { throw ('{0}: a double-quoted string has a bad \{1} escape' -f $Where, $e) }
                [void]$sb.Append([char]::ConvertFromUtf32([Convert]::ToInt32($hex, 16)))
                $k += $len
            }
            default { throw ('{0}: a double-quoted string uses the unknown escape \{1}' -f $Where, $e) }
        }
    }
    return $sb.ToString()
}

function ConvertFrom-SIYaml {
    <#
    .SYNOPSIS
        Read SecurityInsight YAML into hashtables / lists / scalars -- the drop-in for powershell-yaml's
        ConvertFrom-Yaml, for the YAML subset SecurityInsight's files use.
    .PARAMETER Yaml
        The YAML text. Pipeline input is joined with line breaks, as ConvertFrom-Yaml does.
    .PARAMETER Path
        Read this file (UTF-8) instead; its path is named in every error.
    .PARAMETER SourceName
        The name errors cite for -Yaml text (a file path, usually). Default '<yaml>'.
    .PARAMETER Ordered
        Mappings become [ordered] dictionaries (key order kept), as ConvertFrom-Yaml -Ordered.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Text')]
    param(
        [Parameter(ParameterSetName = 'Text', Position = 0, ValueFromPipeline = $true)]
        [AllowEmptyString()][AllowNull()]
        [string]$Yaml,
        [Parameter(ParameterSetName = 'Path', Mandatory = $true)]
        [string]$Path,
        [string]$SourceName,
        [switch]$Ordered
    )
    begin { $text = $null }
    process {
        # Pipeline pieces are joined with line breaks, as ConvertFrom-Yaml does.
        if ($null -ne $Yaml) { if ($null -eq $text) { $text = $Yaml + "`n" } else { $text = $text + $Yaml + "`n" } }
    }
    end {
        if ($Path) {
            $text = [System.IO.File]::ReadAllText($Path)
            if ([string]::IsNullOrEmpty($SourceName)) { $SourceName = $Path }
        } elseif ($null -eq $text) { return }
        if ([string]::IsNullOrEmpty($SourceName)) { $SourceName = '<yaml>' }
        $result = ConvertFrom-SIYamlText -Text $text -Source $SourceName -Ordered:$Ordered
        if ($result -is [System.Collections.Generic.List[object]]) { return , $result }
        return $result
    }
}

function ConvertFrom-SIYamlText {
    <#
        The parser. One pass over the lines, explicit stacks instead of recursion. Internal: call
        ConvertFrom-SIYaml. Written for speed on PowerShell 5.1: no function calls on the common
        paths, ordinal string searches (the culture-aware overloads cost ~10x), characters and
        comparers held in locals.
    #>
    param([string]$Text, [string]$Source, [switch]$Ordered)

    if ($Text.Length -gt 0 -and $Text[0] -eq [char]0xFEFF) { $Text = $Text.Substring(1) }
    # A JSON document (SecurityInsight Pro writes its materialised catalogues as JSON, which is YAML).
    $first = $Text.TrimStart()
    if ($first.Length -gt 0 -and ($first[0] -eq [char]'{' -or $first[0] -eq [char]'[')) {
        $cj = Get-Command -Name ConvertFrom-Json
        $ja = @{ InputObject = $Text; ErrorAction = 'Stop' }
        if ($cj.Parameters.ContainsKey('DateKind')) { $ja['DateKind'] = 'String' }
        if ($cj.Parameters.ContainsKey('Depth')) { $ja['Depth'] = 1024 }
        if ($cj.Parameters.ContainsKey('NoEnumerate')) { $ja['NoEnumerate'] = $true }   # a one-item top-level array stays an array
        try { $doc = ConvertFrom-Json @ja }
        catch { throw ('{0}:1: the document starts with "{1}" but is not valid JSON (YAML flow style is only read as JSON): {2}' -f $Source, $first[0], $_.Exception.Message) }
        $r = ConvertFrom-SIYamlJsonValue -Value $doc -Ordered ([bool]$Ordered)
        if ($r -is [System.Collections.Generic.List[object]]) { return , $r }
        return $r
    }
    $lines = $Text.Replace("`r`n", "`n").Split([char]"`n")
    $n = $lines.Length
    $useOrdered = [bool]$Ordered
    # First characters a plain value needs to become anything but a string: digits, sign, dot (numbers),
    # t/f (true/false), n/N (null, NaN), i/I (Infinity), ~ (null).
    $typedFirst = '0123456789+-.tTfFnNiI~'
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $ORD = [System.StringComparison]::Ordinal
    # The comparer PowerShell gives @{} and [ordered]@{} -- so these are the same dictionaries.
    $cmp = [System.StringComparer]::CurrentCultureIgnoreCase
    $SP = [char]' '; $TAB = [char]"`t"; $HASH = [char]'#'; $DASH = [char]'-'; $COLON = [char]':'
    $SQ = [char]"'"; $DQ = [char]'"'; $LB = [char]'['; $RB = [char]']'; $LC = [char]'{'
    $PIPE = [char]'|'; $GT = [char]'>'; $BS = [char]'\'; $COMMA = [char]','; $CR = [char]"`r"
    $SPTAB = [char[]]@(' ', "`t")
    $keyBad   = '[{&*!|>@`?:,]}'
    $plainBad = '{]},&*!%@`'
    $flowBad  = '#&*!|>%@`'
    # Only these plain values can come out as anything but a string (bool / number / null), so only
    # these go through the full replica of powershell-yaml's typing; the rest stay strings untouched.
    # .NET's number parsing (Float | Integer, invariant) accepts nothing outside [0-9.eE+-] apart from
    # the NaN / Infinity words; bool.TryParse accepts true/false in any case; null is ~ / null.
    $numLike  = '^[0-9.eE+\-]+$'
    $wordLike = '^[+-]?(true|false|null|nan|infinity|~)$'

    # Frame stacks: indentation, kind (1 = mapping, 2 = sequence), container.
    $fInd  = [System.Collections.Generic.List[int]]::new()
    $fKind = [System.Collections.Generic.List[int]]::new()
    $fObj  = [System.Collections.Generic.List[object]]::new()

    $root = $null; $rootSet = $false; $sawDocStart = $false
    # A slot waiting for its value from the following lines: 1 = mapping key, 2 = sequence item.
    $pend = 0; $pObj = $null; $pKey = $null; $pInd = -1

    $i = 0
    while ($i -lt $n) {
        $line = $lines[$i]
        $t = $line.TrimStart($SP)
        $tl = $t.Length
        if ($tl -eq 0) { $i++; continue }
        $c0 = $t[0]
        if ($c0 -eq $HASH) { $i++; continue }
        if ($c0 -eq $TAB -or $c0 -eq $CR) {
            if ($t.Trim().Length -eq 0) { $i++; continue }
            throw ('{0}:{1}: a tab is used for indentation (YAML allows spaces only)' -f $Source, ($i + 1))
        }
        $ind = $line.Length - $tl
        $ln = $i + 1
        $last = $t[$tl - 1]
        if ($last -eq $SP -or $last -eq $TAB -or $last -eq $CR) { $t = $t.TrimEnd(); $tl = $t.Length }

        $isSeq = $false
        if ($c0 -eq $DASH) {
            if ($tl -eq 1 -or $t[1] -eq $SP) { $isSeq = $true }
            elseif ($ind -eq 0 -and $t.StartsWith('---', $ORD) -and ($tl -eq 3 -or $t[3] -eq $SP)) {
                if ($rootSet -or $sawDocStart) { throw ('{0}:{1}: more than one YAML document in one file is not supported' -f $Source, $ln) }
                if ($tl -gt 3 -and $t.Substring(3).TrimStart()[0] -ne $HASH) { throw ('{0}:{1}: content on the --- line is not supported' -f $Source, $ln) }
                $sawDocStart = $true; $i++; continue
            }
        } elseif ($c0 -eq [char]'.' -and $ind -eq 0 -and $t.StartsWith('...', $ORD)) {
            throw ('{0}:{1}: a YAML document end marker (...) is not supported' -f $Source, $ln)
        } elseif ($c0 -eq [char]'%') {
            throw ('{0}:{1}: YAML directives (%) are not supported' -f $Source, $ln)
        }

        # ---- where does this line's value go? -------------------------------------------------
        $slot = 0; $sObj = $null; $sKey = $null; $vt = $null; $vp = 0

        if ($pend -ne 0) {
            $newObj = $null; $newKind = 0
            if ($isSeq -and ($ind -gt $pInd -or ($ind -eq $pInd -and $pend -eq 1))) {
                $newObj = [System.Collections.Generic.List[object]]::new(); $newKind = 2
            } elseif ($ind -gt $pInd) {
                # A mapping key on this line, or a scalar value written on its own line?
                $isKey = $false
                if ($c0 -ne $SQ -and $c0 -ne $DQ -and $c0 -ne $LB -and $c0 -ne $LC -and $c0 -ne $PIPE -and $c0 -ne $GT) {
                    $ci = $t.IndexOf(': ', $ORD)
                    if ($ci -lt 0 -and $t[$tl - 1] -eq $COLON) { $ci = $tl - 1 }
                    if ($ci -gt 0) { $hi = $t.IndexOf(' #', $ORD); if ($hi -lt 0 -or $hi -gt $ci) { $isKey = $true } }
                }
                if ($isKey) {
                    if ($useOrdered) { $newObj = [System.Collections.Specialized.OrderedDictionary]::new($cmp) } else { $newObj = [hashtable]::new($cmp) }
                    $newKind = 1
                } else {
                    $slot = $pend; $sObj = $pObj; $sKey = $pKey; $vt = $t; $vp = $pInd
                }
            }
            if ($slot -eq 0) {
                if ($pend -eq 1) { $pObj[$pKey] = $newObj } else { $pObj.Add($newObj) }
                if ($newKind -ne 0) { $fInd.Add($ind); $fKind.Add($newKind); $fObj.Add($newObj) }
            }
            $pend = 0
        }

        if ($slot -eq 0) {
            if ($fInd.Count -eq 0) {
                if ($rootSet) { throw ('{0}:{1}: this line is outside the document (indented less than its first line)' -f $Source, $ln) }
                $rootSet = $true
                if ($isSeq) { $root = [System.Collections.Generic.List[object]]::new(); $rk = 2 }
                else {
                    if ($useOrdered) { $root = [System.Collections.Specialized.OrderedDictionary]::new($cmp) } else { $root = [hashtable]::new($cmp) }
                    $rk = 1
                }
                $fInd.Add($ind); $fKind.Add($rk); $fObj.Add($root)
            }
            $top = $fInd.Count - 1
            while ($top -ge 0 -and $fInd[$top] -gt $ind) { $fInd.RemoveAt($top); $fKind.RemoveAt($top); $fObj.RemoveAt($top); $top-- }
            if ($top -ge 0 -and -not $isSeq -and $fInd[$top] -eq $ind -and $fKind[$top] -eq 2) {
                # the end of a sequence written at the same indentation as its parent key
                $fInd.RemoveAt($top); $fKind.RemoveAt($top); $fObj.RemoveAt($top); $top--
            }
            if ($top -lt 0 -or $fInd[$top] -ne $ind) { throw ('{0}:{1}: the indentation of this line does not match any open mapping or sequence' -f $Source, $ln) }

            $mapText = $null
            if ($fKind[$top] -eq 2) {
                if (-not $isSeq) { throw ('{0}:{1}: expected a "- item" line in this sequence' -f $Source, $ln) }
                $seqObj = $fObj[$top]
                $rest = if ($tl -gt 2) { $t.Substring(2).TrimStart($SP) } else { '' }
                $rl = $rest.Length
                if ($rl -eq 0 -or $rest[0] -eq $HASH) {
                    $pend = 2; $pObj = $seqObj; $pKey = $null; $pInd = $ind
                    $i++; continue
                }
                $r0 = $rest[0]
                if ($r0 -eq $DASH -and ($rl -eq 1 -or $rest[1] -eq $SP)) { throw ('{0}:{1}: a sequence written directly inside a sequence item ("- - x") is not supported' -f $Source, $ln) }
                $isKey = $false
                if ($r0 -ne $SQ -and $r0 -ne $DQ -and $r0 -ne $LB -and $r0 -ne $LC -and $r0 -ne $PIPE -and $r0 -ne $GT) {
                    $ci = $rest.IndexOf(': ', $ORD)
                    if ($ci -lt 0 -and $rest[$rl - 1] -eq $COLON) { $ci = $rl - 1 }
                    if ($ci -gt 0) { $hi = $rest.IndexOf(' #', $ORD); if ($hi -lt 0 -or $hi -gt $ci) { $isKey = $true } }
                } elseif ($r0 -eq $SQ -or $r0 -eq $DQ) {
                    $q = $rest.IndexOf($r0, 1)
                    if ($q -gt 0 -and $rl -gt $q + 1 -and $rest[$q + 1] -eq $COLON) { throw ('{0}:{1}: quoted mapping keys are not supported' -f $Source, $ln) }
                }
                if ($isKey) {
                    if ($useOrdered) { $mapObj = [System.Collections.Specialized.OrderedDictionary]::new($cmp) } else { $mapObj = [hashtable]::new($cmp) }
                    $seqObj.Add($mapObj)
                    $mapInd = $ind + ($tl - $rl)
                    $fInd.Add($mapInd); $fKind.Add(1); $fObj.Add($mapObj)
                    $mapText = $rest
                } else {
                    $slot = 2; $sObj = $seqObj; $vt = $rest; $vp = $ind
                }
            } else {
                if ($isSeq) { throw ('{0}:{1}: a "- item" line where a "key: value" line was expected' -f $Source, $ln) }
                $mapObj = $fObj[$top]; $mapInd = $ind; $mapText = $t
            }

            if ($null -ne $mapText) {
                # ---- key: value ----
                $m0 = $mapText[0]
                $ml = $mapText.Length
                if ($m0 -eq $SQ -or $m0 -eq $DQ) { throw ('{0}:{1}: quoted mapping keys are not supported' -f $Source, $ln) }
                if ($keyBad.IndexOf($m0) -ge 0) { throw ('{0}:{1}: this line is not a "key: value" line (it starts with "{2}")' -f $Source, $ln, $m0) }
                $ci = $mapText.IndexOf(': ', $ORD)
                if ($ci -lt 0 -and $mapText[$ml - 1] -eq $COLON) { $ci = $ml - 1 }
                if ($ci -le 0) { throw ('{0}:{1}: expected "key: value" (a colon followed by a space)' -f $Source, $ln) }
                $hi = $mapText.IndexOf(' #', 0, $ci, $ORD)
                if ($hi -ge 0) { throw ('{0}:{1}: expected "key: value" (a colon followed by a space)' -f $Source, $ln) }
                $key = $mapText.Substring(0, $ci)
                if ($key[$ci - 1] -eq $SP -or $key[$ci - 1] -eq $TAB) { $key = $key.TrimEnd() }
                if ($mapObj.Contains($key)) {
                    foreach ($ek in @($mapObj.Keys)) {
                        if ([string]::Equals([string]$ek, $key, $ORD)) { throw ('{0}:{1}: duplicate key "{2}"' -f $Source, $ln, $key) }
                    }
                }
                $after = if ($ci + 2 -lt $ml) { $mapText.Substring($ci + 2).TrimStart($SP) } else { '' }
                if ($after.Length -eq 0 -or $after[0] -eq $HASH) {
                    $mapObj[$key] = $null
                    $pend = 1; $pObj = $mapObj; $pKey = $key; $pInd = $mapInd
                    $i++; continue
                }
                $slot = 1; $sObj = $mapObj; $sKey = $key; $vt = $after; $vp = $mapInd
            }
        }

        # ---- the value text $vt (first line), its parent indentation $vp ----------------------------
        $v0 = $vt[0]
        $vl = $vt.Length
        $val = $null
        if ($v0 -eq $SQ) {
            $k = 1; $closed = -1
            while ($k -lt $vl) {
                $q = $vt.IndexOf($SQ, $k)
                if ($q -lt 0) { break }
                if ($q + 1 -lt $vl -and $vt[$q + 1] -eq $SQ) { $k = $q + 2; continue }
                $closed = $q; break
            }
            if ($closed -lt 0) { throw ('{0}:{1}: a single-quoted string must end on the same line' -f $Source, $ln) }
            $val = $vt.Substring(1, $closed - 1)
            if ($val.IndexOf($SQ) -ge 0) { $val = $val.Replace("''", "'") }
            if ($closed + 1 -lt $vl) {
                $tail = $vt.Substring($closed + 1); $tt = $tail.TrimStart($SPTAB)
                if ($tt.Length -gt 0 -and ($tt[0] -ne $HASH -or $tt.Length -eq $tail.Length)) { throw ('{0}:{1}: unexpected text after a quoted string' -f $Source, $ln) }
            }
        } elseif ($v0 -eq $DQ) {
            $k = 1; $closed = -1
            while ($k -lt $vl) {
                $ch = $vt[$k]
                if ($ch -eq $BS) { $k += 2; continue }
                if ($ch -eq $DQ) { $closed = $k; break }
                $k++
            }
            if ($closed -lt 0) { throw ('{0}:{1}: a double-quoted string must end on the same line' -f $Source, $ln) }
            $val = $vt.Substring(1, $closed - 1)
            if ($val.IndexOf($BS) -ge 0) { $val = ConvertFrom-SIYamlDoubleQuoted -Body $val -Where ('{0}:{1}' -f $Source, $ln) }
            if ($closed + 1 -lt $vl) {
                $tail = $vt.Substring($closed + 1); $tt = $tail.TrimStart($SPTAB)
                if ($tt.Length -gt 0 -and ($tt[0] -ne $HASH -or $tt.Length -eq $tail.Length)) { throw ('{0}:{1}: unexpected text after a quoted string' -f $Source, $ln) }
            }
        } elseif ($v0 -eq $LB) {
            $val = [System.Collections.Generic.List[object]]::new()
            $k = 1; $closed = $false; $needItem = $true
            while ($k -lt $vl) {
                $ch = $vt[$k]
                if ($ch -eq $SP -or $ch -eq $TAB) { $k++; continue }
                if ($ch -eq $RB) { $closed = $true; $k++; break }
                if ($ch -eq $COMMA) {
                    if ($needItem) { throw ('{0}:{1}: an empty item in a [ ] list' -f $Source, $ln) }
                    $needItem = $true; $k++; continue
                }
                if (-not $needItem) { throw ('{0}:{1}: a comma is missing between items of a [ ] list' -f $Source, $ln) }
                if ($ch -eq $LB -or $ch -eq $LC) { throw ('{0}:{1}: nested [ ] / {{ }} inside a [ ] list are not supported' -f $Source, $ln) }
                if ($ch -eq $SQ) {
                    $s = $k + 1; $e = -1
                    while ($s -lt $vl) {
                        $q = $vt.IndexOf($SQ, $s)
                        if ($q -lt 0) { break }
                        if ($q + 1 -lt $vl -and $vt[$q + 1] -eq $SQ) { $s = $q + 2; continue }
                        $e = $q; break
                    }
                    if ($e -lt 0) { throw ('{0}:{1}: a quoted item in a [ ] list is not closed on the same line' -f $Source, $ln) }
                    $val.Add($vt.Substring($k + 1, $e - $k - 1).Replace("''", "'")); $k = $e + 1
                } elseif ($ch -eq $DQ) {
                    $s = $k + 1; $e = -1
                    while ($s -lt $vl) { $cc = $vt[$s]; if ($cc -eq $BS) { $s += 2; continue }; if ($cc -eq $DQ) { $e = $s; break }; $s++ }
                    if ($e -lt 0) { throw ('{0}:{1}: a quoted item in a [ ] list is not closed on the same line' -f $Source, $ln) }
                    $val.Add((ConvertFrom-SIYamlDoubleQuoted -Body $vt.Substring($k + 1, $e - $k - 1) -Where ('{0}:{1}' -f $Source, $ln))); $k = $e + 1
                } else {
                    if ($flowBad.IndexOf($ch) -ge 0) { throw ('{0}:{1}: a [ ] list item starts with "{2}", which is not supported' -f $Source, $ln, $ch) }
                    $s = $k
                    while ($k -lt $vl -and $vt[$k] -ne $COMMA -and $vt[$k] -ne $RB) { $k++ }
                    $item = $vt.Substring($s, $k - $s).TrimEnd($SPTAB)
                    if ($item.IndexOf(': ', $ORD) -ge 0 -or $item[$item.Length - 1] -eq $COLON -or $item.IndexOf(' #', $ORD) -ge 0 -or $item.IndexOf($LB) -ge 0 -or $item.IndexOf($LC) -ge 0) {
                        throw ('{0}:{1}: a [ ] list item "{2}" is not a plain value' -f $Source, $ln, $item)
                    }
                    if ($typedFirst.IndexOf($item[0]) -lt 0) { $val.Add($item) }
                    elseif ($item.Length -le 9 -and $item -cmatch '^[0-9]+$') { $val.Add([int]::Parse($item, $inv)) }
                    elseif ($item -cmatch $numLike -or $item -match $wordLike) { $val.Add((ConvertTo-SIYamlPlainValue -Value $item)) }
                    else { $val.Add($item) }
                }
                $needItem = $false
            }
            if (-not $closed) { throw ('{0}:{1}: a [ ] list must end on the same line' -f $Source, $ln) }
            if ($k -lt $vl) {
                $tail = $vt.Substring($k); $tt = $tail.TrimStart($SPTAB)
                if ($tt.Length -gt 0 -and ($tt[0] -ne $HASH -or $tt.Length -eq $tail.Length)) { throw ('{0}:{1}: unexpected text after a [ ] list' -f $Source, $ln) }
            }
        } elseif ($v0 -eq $PIPE -or $v0 -eq $GT) {
            # ---- block scalar ----
            $hdr = $vt
            $hc = $hdr.IndexOf($HASH)
            if ($hc -ge 0) {
                if ($hc -eq 0 -or ($hdr[$hc - 1] -ne $SP -and $hdr[$hc - 1] -ne $TAB)) { throw ('{0}:{1}: unexpected text after a block scalar indicator' -f $Source, $ln) }
                $hdr = $hdr.Substring(0, $hc).TrimEnd()
            }
            $strip = $false
            if ($hdr.Length -eq 2 -and $hdr[1] -eq $DASH) { $strip = $true }
            elseif ($hdr.Length -ne 1) { throw ('{0}:{1}: block scalar header "{2}" is not supported (use | |- > >-)' -f $Source, $ln, $hdr) }
            $folded = ($v0 -eq $GT)
            # List[object], not List[string]: PowerShell turns $null into '' on the way into a string list,
            # and $null is how an empty line is told apart from content.
            $buf = [System.Collections.Generic.List[object]]::new()
            $mi = -1; $j = $i + 1
            while ($j -lt $n) {
                $l = $lines[$j]
                $lt = $l.TrimStart($SP)
                if ($lt.Length -eq 0) {
                    if ($mi -ge 0 -and $l.Length -gt $mi) { $buf.Add($l.Substring($mi)) } else { $buf.Add($null) }
                    $j++; continue
                }
                $li = $l.Length - $lt.Length
                if ($mi -lt 0) {
                    if ($li -le $vp) { break }
                    if ($lt[0] -eq $TAB) { throw ('{0}:{1}: a tab is used for indentation (YAML allows spaces only)' -f $Source, ($j + 1)) }
                    $mi = $li
                } elseif ($li -lt $mi) { break }
                $buf.Add($l.Substring($mi)); $j++
            }
            # $null entries are empty lines. Trailing empty lines are dropped (clip / strip).
            $lastC = $buf.Count - 1
            while ($lastC -ge 0 -and $null -eq $buf[$lastC]) { $lastC-- }
            if ($lastC -lt 0) { $val = '' }
            else {
                $sb = [System.Text.StringBuilder]::new()
                if (-not $folded) {
                    for ($x = 0; $x -le $lastC; $x++) {
                        if ($x -gt 0) { [void]$sb.Append("`n") }
                        if ($null -ne $buf[$x]) { [void]$sb.Append($buf[$x]) }
                    }
                } else {
                    # Folding: a line break between two ordinary lines becomes a space; N empty lines
                    # become N line breaks; around a more-indented line the break is kept.
                    $x = 0
                    while ($x -le $lastC -and $null -eq $buf[$x]) { [void]$sb.Append("`n"); $x++ }
                    $prev = $buf[$x]; [void]$sb.Append($prev); $x++
                    while ($x -le $lastC) {
                        $empties = 0
                        while ($null -eq $buf[$x]) { $empties++; $x++ }
                        $cur = $buf[$x]
                        $spaced = ($prev.Length -gt 0 -and ($prev[0] -eq $SP -or $prev[0] -eq $TAB)) -or
                                  ($cur.Length -gt 0 -and ($cur[0] -eq $SP -or $cur[0] -eq $TAB))
                        if ($spaced) { [void]$sb.Append("`n"); if ($empties -gt 0) { [void]$sb.Append("`n" * $empties) } }
                        elseif ($empties -eq 0) { [void]$sb.Append(' ') }
                        else { [void]$sb.Append("`n" * $empties) }
                        [void]$sb.Append($cur); $prev = $cur; $x++
                    }
                }
                if (-not $strip) { [void]$sb.Append("`n") }
                $val = $sb.ToString()
            }
            $i = $j - 1
        } else {
            # ---- plain scalar ----
            if ($plainBad.IndexOf($v0) -ge 0) { throw ('{0}:{1}: a value starting with "{2}" is not supported (anchors, aliases, tags and {{ }} maps are not used by SecurityInsight)' -f $Source, $ln, $v0) }
            if (($v0 -eq $DASH -or $v0 -eq [char]'?' -or $v0 -eq $COLON) -and ($vl -eq 1 -or $vt[1] -eq $SP)) {
                throw ('{0}:{1}: a value cannot start with "{2} " here' -f $Source, $ln, $v0)
            }
            $ended = $false
            $hi = $vt.IndexOf(' #', $ORD)
            if ($vt.IndexOf($TAB) -ge 0) { $ti = $vt.IndexOf("`t#", $ORD); if ($ti -ge 0 -and ($hi -lt 0 -or $ti -lt $hi)) { $hi = $ti } }
            if ($hi -ge 0) { $pv = $vt.Substring(0, $hi).TrimEnd($SPTAB); $ended = $true } else { $pv = $vt }
            if ($pv.IndexOf($COLON) -ge 0 -and ($pv.IndexOf(': ', $ORD) -ge 0 -or $pv[$pv.Length - 1] -eq $COLON -or $pv.IndexOf(":`t", $ORD) -ge 0)) {
                throw ('{0}:{1}: a plain value contains ": " -- quote it' -f $Source, $ln)
            }
            if (-not $ended) {
                # continuation lines: more indented than the parent, until a comment or a less-indented line
                $j = $i + 1; $empt = 0; $sb = $null; $lastJ = $i
                while ($j -lt $n) {
                    $l = $lines[$j]
                    $lt = $l.TrimStart($SP)
                    if ($lt.Length -eq 0) { $empt++; $j++; continue }
                    $li = $l.Length - $lt.Length
                    if ($li -le $vp) { break }
                    $ct = $lt.Trim()
                    if ($ct.Length -eq 0) { $empt++; $j++; continue }
                    if ($ct[0] -eq $HASH) { break }
                    $hi = $ct.IndexOf(' #', $ORD); $ti = $ct.IndexOf("`t#", $ORD)
                    if ($ti -ge 0 -and ($hi -lt 0 -or $ti -lt $hi)) { $hi = $ti }
                    $stop = $false
                    if ($hi -ge 0) { $ct = $ct.Substring(0, $hi).TrimEnd($SPTAB); $stop = $true }
                    if ($ct.IndexOf(': ', $ORD) -ge 0 -or $ct[$ct.Length - 1] -eq $COLON -or $ct.IndexOf(":`t", $ORD) -ge 0) {
                        throw ('{0}:{1}: this line continues a plain value but contains ": " (a key indented too far, or a value that needs quotes)' -f $Source, ($j + 1))
                    }
                    if ($null -eq $sb) { $sb = [System.Text.StringBuilder]::new(); [void]$sb.Append($pv) }
                    if ($empt -eq 0) { [void]$sb.Append(' ') } else { [void]$sb.Append("`n" * $empt) }
                    [void]$sb.Append($ct)
                    $empt = 0; $lastJ = $j; $j++
                    if ($stop) { break }
                }
                if ($null -ne $sb) { $pv = $sb.ToString() }
                $i = $lastJ
            }
            # Typing, as powershell-yaml does it. Common cases inline (a function call costs more than
            # the rest of the line); everything else through the call-for-call replica.
            if ($typedFirst.IndexOf($pv[0]) -lt 0) { $val = $pv }
            elseif ($pv.Length -le 9 -and $pv -cmatch '^[0-9]+$') { $val = [int]::Parse($pv, $inv) }
            elseif ($pv -cmatch $numLike -or $pv -match $wordLike) { $val = ConvertTo-SIYamlPlainValue -Value $pv }
            else { $val = $pv }
        }

        if ($slot -eq 1) { $sObj[$sKey] = $val } else { $sObj.Add($val) }
        $i++
    }

    # A "- " item with nothing after it at the end of the text is a null item (a "key:" was set to null already).
    if ($pend -eq 2) { $pObj.Add($null) }
    if (-not $rootSet) { return $null }
    if ($root -is [System.Collections.Generic.List[object]]) { return , $root }
    return $root
}
