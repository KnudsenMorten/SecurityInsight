#Requires -Version 5.1
<#
    BUCKETED SUMMARY REPORTS: ONE GROUP IS ONE ROW, WITH EVERY ASSET OF EVERY BUCKET IN IT.

    A bucketed report runs its query once per slice of the assets. A Summary query ends in
    `summarize ... by <group>`, so each bucket returns its OWN row for a group -- aggregated over only
    that bucket's assets. The engine concatenated those rows, and the risk-score de-duplication then
    kept the FIRST row of each group and dropped the rest, together with every asset they listed.
    Measured on the internal tenant 2026-09-28 (2 buckets): Device_Missing_CVEs_Summary dropped 11 of
    31 rows -- the two devices with the most CVEs (3,603 and 2,979) appeared in no Summary row at all --
    and Device_Recommendations_Summary dropped 57 of 182.

    The rows are MERGED instead, by the report's own final `summarize ... by` clause, each column the
    way that summarize built it:
        make_set / make_list            -> union                (sorted again when it was sorted)
        strcat_array(<set>, "<d>")      -> union of the tokens, joined with the same delimiter
        max / maxif  /  min / minif     -> max  /  min
        count / countif / sum / dcount  -> sum   (bucketing partitions the ASSETS, so each is counted
                                                  in exactly one bucket; a dcount of findings that span
                                                  buckets is recomputed from its list when there is one)
        arg_max(M, a, b)                -> M max, a / b from the row that holds it
        any / take_any / anything else  -> first non-empty value
    and after it: `X = array_length(Y)` is recomputed from the merged Y.

    Refuses rather than guesses: when the `by` clause cannot be read, or names a column the rows do not
    carry, the rows are returned UNCHANGED (never merged on a wrong key). Pure -- no I/O.
#>

# Columns that identify ONE asset. Bucketing partitions the assets, so a dcount over one of these is
# additive across buckets.
$script:RA_AssetIdentityColumns = @('PrimaryEntityId','DeviceKey','AssetName','AssetId','SI_AssetId','AadDeviceId','DeviceId','MdeDeviceId','UserNodeId','IdentityNodeId','FinalTargetId','NodeId','DeviceNodeId','AccountObjectId','EntraObjectId')

function Get-RASummaryMergePlan {
    <# Parse the query's FINAL `summarize ... by` into { Keys; Agg (col -> rule); Derived (col -> list col) }.
       $null when there is no final summarize, or its by clause cannot be read. #>
    param([Parameter(Mandatory)][string]$Query)

    # comments and string literals out (a "|" or "," inside them must not split anything) -- but keep
    # each literal's text in a side table so strcat_array's delimiter can be read back.
    $lits = New-Object System.Collections.Generic.List[string]
    $q = [regex]::Replace($Query, '//[^\r\n]*', '')
    $q = [regex]::Replace($q, '"((?:[^"\\\r\n]|\\.)*)"', { param($m) $lits.Add($m.Groups[1].Value); '"#' + ($lits.Count - 1) + '"' })

    $ms = [regex]::Matches($q, '\|\s*summarize\b')
    if ($ms.Count -eq 0) { return $null }
    $start = $ms[$ms.Count - 1].Index + $ms[$ms.Count - 1].Length

    # split the rest at top-level pipes: [0] = summarize body, [1..] = what follows it
    $segs = New-Object System.Collections.Generic.List[string]
    $depth = 0; $from = $start
    for ($i = $start; $i -lt $q.Length; $i++) {
        $ch = $q[$i]
        if ($ch -eq '(' -or $ch -eq '[') { $depth++ } elseif ($ch -eq ')' -or $ch -eq ']') { $depth-- }
        elseif ($depth -eq 0 -and $ch -eq '|') { $segs.Add($q.Substring($from, $i - $from)); $from = $i + 1 }
        elseif ($depth -eq 0 -and $ch -eq ';') { break }
    }
    if ($from -lt $q.Length) { $segs.Add($q.Substring($from)) }
    $body = $segs[0]

    $byM = [regex]::Match($body, '(?s)^(.*)\bby\b(.*)$')
    if (-not $byM.Success) { return $null }
    $aggText = $byM.Groups[1].Value
    $byText  = $byM.Groups[2].Value

    function _splitTop([string]$s) {
        $out = New-Object System.Collections.Generic.List[string]
        $d = 0; $f = 0
        for ($k = 0; $k -le $s.Length; $k++) {
            $c = if ($k -lt $s.Length) { $s[$k] } else { ',' }
            if ($c -eq '(' -or $c -eq '[') { $d++ } elseif ($c -eq ')' -or $c -eq ']') { $d-- }
            elseif ($d -eq 0 -and $c -eq ',') { $t = $s.Substring($f, $k - $f).Trim(); if ($t) { $out.Add($t) }; $f = $k + 1 }
        }
        , $out
    }

    $keys = New-Object System.Collections.Generic.List[string]
    foreach ($item in (_splitTop $byText)) {
        if     ($item -match '^([A-Za-z_]\w*)\s*=') { $keys.Add($Matches[1]) }
        elseif ($item -match '^([A-Za-z_]\w*)$')    { $keys.Add($Matches[1]) }
        else   { return $null }          # an unnamed expression -- the output column name is not knowable
    }
    if ($keys.Count -eq 0) { return $null }

    $agg = @{}
    foreach ($item in (_splitTop $aggText)) {
        if ($item -match '^(?s)arg_max\s*\(\s*([A-Za-z_]\w*)\s*,(.*)\)$') {
            $measure = $Matches[1]
            $agg[$measure] = @{ Kind = 'max' }
            foreach ($comp in ($Matches[2] -split ',')) {
                $n = $comp.Trim()
                if ($n -match '^[A-Za-z_]\w*$') { $agg[$n] = @{ Kind = 'argmax'; Measure = $measure } }
            }
            continue
        }
        if ($item -notmatch '^(?s)([A-Za-z_]\w*)\s*=\s*(.*)$') { continue }
        $name = $Matches[1]; $expr = $Matches[2].Trim()
        $sorted = $false
        if ($expr -match '^(?s)array_sort_asc\s*\((.*)\)$') { $sorted = $true; $expr = $Matches[1].Trim() }
        $fn = if ($expr -match '^([A-Za-z_]\w*)\s*\(') { $Matches[1].ToLowerInvariant() } else { '' }
        $rule = switch ($fn) {
            { $_ -in 'make_set','make_list','make_set_if','make_list_if' } { @{ Kind = 'union'; Sorted = $sorted; Arg = $(if ($expr -match '^\w+\s*\(\s*([A-Za-z_]\w*)\s*[,)]') { $Matches[1] } else { '' }) } }
            'strcat_array' {
                $lm = [regex]::Matches($expr, '"#(\d+)"')
                $delim = if ($lm.Count -gt 0) { $lits[[int]$lm[$lm.Count - 1].Groups[1].Value] } else { ';' }
                @{ Kind = 'tokens'; Delim = $delim; Sorted = ($sorted -or $expr -match 'array_sort_asc') }
            }
            { $_ -in 'max','maxif' } { @{ Kind = 'max' } }
            { $_ -in 'min','minif' } { @{ Kind = 'min' } }
            { $_ -in 'count','countif','sum','sumif' } { @{ Kind = 'sum' } }
            { $_ -in 'dcount','dcountif' } { @{ Kind = 'dcount'; Arg = $(if ($expr -match '^\w+\s*\(\s*([A-Za-z_]\w*)\s*[,)]') { $Matches[1] } else { '' }) } }
            default { @{ Kind = 'first' } }
        }
        $agg[$name] = $rule
    }

    # After the summarize, columns DERIVED from the aggregates (`extend X = ...`). Each gets a rule, or is
    # marked 'unknown' -- a group whose unknown columns differ between its rows is then NOT merged:
    #   X = array_length(Y)        -> count of the merged Y
    #   X = strcat_array(Y, "d")   -> the merged Y joined with d (or, when Y is projected away, the union of X's tokens)
    #   X = f(<one max aggregate>) -> taken from the row that holds that max (e.g. a severity band of max(Impact))
    #   X = f(<group keys / constants only>) -> identical across the group
    $derived = @{}; $derivedOrder = New-Object System.Collections.Generic.List[string]
    $fnNames = '^(?:iff|iif|case|coalesce|strcat|strcat_array|array_length|tostring|toint|tolong|todouble|toreal|tobool|isnotempty|isempty|isnull|isnotnull|max_of|min_of|round|array_sort_asc|array_sort_desc|dynamic|pack_array|and|or|not|true|false|null)$'
    for ($s = 1; $s -lt $segs.Count; $s++) {
        $seg = $segs[$s].Trim()
        if ($seg -notmatch '^(?s)extend\s+(.*)$') { continue }
        foreach ($item in (_splitTop $Matches[1])) {
            if ($item -notmatch '^(?s)([A-Za-z_]\w*)\s*=\s*(.*)$') { continue }
            $name = $Matches[1]; $expr = $Matches[2].Trim()
            if ($expr -match '^array_length\s*\(\s*([A-Za-z_]\w*)\s*\)$') { $derived[$name] = @{ Kind = 'count'; Src = $Matches[1] }; continue }
            # `X = array_sort_asc(X)` on a merged set just means: sort the union
            if ($expr -match '^array_sort_asc\s*\(\s*([A-Za-z_]\w*)\s*\)$' -and $Matches[1] -eq $name -and $agg.ContainsKey($name) -and $agg[$name].Kind -eq 'union') { $agg[$name].Sorted = $true; continue }
            if ($expr -match '^strcat_array\s*\(\s*([A-Za-z_]\w*)\s*,\s*"#(\d+)"\s*\)$') { $derived[$name] = @{ Kind = 'join'; Src = $Matches[1]; Delim = $lits[[int]$Matches[2]] }; continue }
            # #402: `X = strcat("text", tostring(<column>), ...)` over literals and columns (a merged count, a key, a merged
            # list text) -> rebuilt from the merged row. Endpoint_ExcludedAssets_Summary builds its Impact sentence from
            # ImpactedAssetCount this way; refused as 'unknown', one group stayed two rows (55 + 60 assets).
            if ($expr -match '^(?s)strcat\s*\((.*)\)$') {
                $parts = New-Object System.Collections.Generic.List[object]; $ok = $true
                foreach ($arg in (_splitTop $Matches[1])) {
                    $a = $arg.Trim()
                    if ($a -match '^"#(\d+)"$') { $parts.Add(@{ Lit = [string]$lits[[int]$Matches[1]] }); continue }
                    $am = [regex]::Match($a, '^(?:tostring\s*\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*))$')
                    if ($am.Success) {
                        $ref = if ($am.Groups[1].Success) { $am.Groups[1].Value } else { $am.Groups[2].Value }
                        if ($ref -match $fnNames -or -not ($agg.ContainsKey($ref) -or ($derived.ContainsKey($ref) -and $derived[$ref].Kind -ne 'unknown') -or $keys -contains $ref)) { $ok = $false; break }
                        $parts.Add(@{ Col = $ref }); continue
                    }
                    $ok = $false; break
                }
                if ($ok -and $parts.Count -gt 0) { $derived[$name] = @{ Kind = 'strcat'; Parts = $parts.ToArray() }; $derivedOrder.Add($name); continue }
            }
            # `X = iff(array_length(Y) == 0, "", strcat_array(set_difference(set_union(split(strcat_array(Y, "d"), "d"), ...), ...), "d"))`
            # over ONE collected list Y: X is the distinct d-separated tokens of Y's texts. Merged = the distinct tokens of the
            # rows' X (Device_Missing_CVEs_Summary's si_affected_software / si_fix_recommended_update(_id) / si_cve_tags --
            # refused as 'unknown', a group whose two buckets listed different software stayed two rows: live 2026-10-13,
            # 38 rows where the source holds 26 groups).
            $tu = [regex]::Match($expr, '^(?s)iff\s*\(\s*array_length\s*\(\s*([A-Za-z_]\w*)\s*\)\s*==\s*0\s*,\s*"#(\d+)"\s*,\s*strcat_array\s*\(.*\bsplit\s*\(.*,\s*"#(\d+)"\s*\)\s*\)$')
            if ($tu.Success -and $agg.ContainsKey($tu.Groups[1].Value) -and $agg[$tu.Groups[1].Value].Kind -eq 'union' -and [string]$lits[[int]$tu.Groups[2].Value] -eq '') {
                $derived[$name] = @{ Kind = 'tokenunion'; Delim = [string]$lits[[int]$tu.Groups[3].Value] }; $derivedOrder.Add($name); continue
            }
            # `X = iff(isnotempty(Z), strcat(<literals, columns, replace_string(column, "a", "b")>), "text")` over columns the
            # merged row carries -> rebuilt from the merged row (si_fix_remediation)
            $ic = [regex]::Match($expr, '^(?s)iff\s*\(\s*isnotempty\s*\(\s*([A-Za-z_]\w*)\s*\)\s*,\s*strcat\s*\((.*)\)\s*,\s*"#(\d+)"\s*\)$')
            if ($ic.Success) {
                $cond = $ic.Groups[1].Value
                $known = { param($ref) ($ref -notmatch $fnNames) -and ($agg.ContainsKey($ref) -or ($derived.ContainsKey($ref) -and $derived[$ref].Kind -ne 'unknown') -or $keys -contains $ref) }
                $parts = New-Object System.Collections.Generic.List[object]; $ok = [bool](& $known $cond)
                foreach ($arg in (_splitTop $ic.Groups[2].Value)) {
                    if (-not $ok) { break }
                    $a = $arg.Trim()
                    if ($a -match '^"#(\d+)"$') { $parts.Add(@{ Lit = [string]$lits[[int]$Matches[1]] }); continue }
                    $rm = [regex]::Match($a, '^replace_string\s*\(\s*([A-Za-z_]\w*)\s*,\s*"#(\d+)"\s*,\s*"#(\d+)"\s*\)$')
                    if ($rm.Success -and (& $known $rm.Groups[1].Value)) { $parts.Add(@{ Col = $rm.Groups[1].Value; From = [string]$lits[[int]$rm.Groups[2].Value]; To = [string]$lits[[int]$rm.Groups[3].Value] }); continue }
                    $am = [regex]::Match($a, '^(?:tostring\s*\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*))$')
                    if ($am.Success) { $ref = if ($am.Groups[1].Success) { $am.Groups[1].Value } else { $am.Groups[2].Value }; if (& $known $ref) { $parts.Add(@{ Col = $ref }); continue } }
                    $ok = $false
                }
                if ($ok -and $parts.Count -gt 0) { $derived[$name] = @{ Kind = 'iffstrcat'; Cond = $cond; Parts = $parts.ToArray(); Else = [string]$lits[[int]$ic.Groups[3].Value] }; $derivedOrder.Add($name); continue }
            }
            $ids = @([regex]::Matches(([regex]::Replace($expr, '"#\d+"', '')), '\b([A-Za-z_]\w*)\b(?!\s*\()') | ForEach-Object { $_.Groups[1].Value } |
                     Where-Object { $_ -notmatch $fnNames -and $_ -notmatch '^\d' } | Sort-Object -Unique)
            $aggRefs = @($ids | Where-Object { $agg.ContainsKey($_) -or $derived.ContainsKey($_) })
            $otherRefs = @($ids | Where-Object { -not $agg.ContainsKey($_) -and -not $derived.ContainsKey($_) -and $keys -notcontains $_ })
            if ($aggRefs.Count -eq 0 -and $otherRefs.Count -eq 0) { $derived[$name] = @{ Kind = 'key' }; continue }
            if ($otherRefs.Count -eq 0 -and $aggRefs.Count -eq 1 -and $agg.ContainsKey($aggRefs[0]) -and $agg[$aggRefs[0]].Kind -eq 'max') {
                $derived[$name] = @{ Kind = 'argmax'; Measure = $aggRefs[0] }; continue
            }
            $derived[$name] = @{ Kind = 'unknown' }
        }
    }
    [pscustomobject]@{ Keys = @($keys); Agg = $agg; Derived = $derived; DerivedOrder = $derivedOrder.ToArray() }
}

function Get-RASummaryGroupKey {
    <# PURE. The group a Summary row belongs to: its values of the query's final summarize-by columns, lower-cased (the key
       Merge-RASummaryBucketRows groups on). $null when there is no plan or the row lacks a group column (nothing is merged). #>
    param([Parameter(Mandatory)]$Row, $Plan)
    if ($null -eq $Plan) { return $null }
    foreach ($k in $Plan.Keys) { if (-not $Row.PSObject.Properties[$k]) { return $null } }
    (@($Plan.Keys | ForEach-Object { [string]$Row.PSObject.Properties[$_].Value }) -join [char]31).ToLowerInvariant()
}

function Merge-RASummaryBucketRows {
    <# Returns @{ Rows; Merged (rows folded away); Applied (bool); Reason }. #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][string]$Query
    )
    $rowsIn = @($Rows | Where-Object { $null -ne $_ })
    if ($rowsIn.Count -lt 2) { return @{ Rows = $rowsIn; Merged = 0; Applied = $false; Reason = 'fewer than two rows' } }
    $plan = Get-RASummaryMergePlan -Query $Query
    if ($null -eq $plan) { return @{ Rows = $rowsIn; Merged = 0; Applied = $false; Reason = 'no readable final summarize-by' } }
    foreach ($k in $plan.Keys) {
        if (-not $rowsIn[0].PSObject.Properties[$k]) { return @{ Rows = $rowsIn; Merged = 0; Applied = $false; Reason = "group column '$k' is not on the rows" } }
    }

    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    function _num($v) { $d = 0.0; if ($null -ne $v -and [double]::TryParse([string]$v, [System.Globalization.NumberStyles]::Float, $inv, [ref]$d)) { $d } else { $null } }
    # a whole number as [long] while it fits one; a larger value stays the number it is (never an overflow)
    function _whole([double]$d) { if ([Math]::Abs($d) -lt 9.2e18) { [long]$d } else { $d } }
    function _isEmpty($v) { $null -eq $v -or ($v -is [string] -and $v -eq '') }
    # an array value may arrive as a real array (advanced hunting) or as JSON text (Log Analytics direct)
    function _asList($v) {
        if ($null -eq $v) { return @{ Items = @(); Json = $false } }
        if ($v -is [string]) {
            $t = $v.Trim()
            # piped through ForEach-Object on purpose: PS 5.1's ConvertFrom-Json emits a JSON array as ONE object
            if ($t.StartsWith('[')) { try { return @{ Items = @((ConvertFrom-Json -InputObject $t) | ForEach-Object { $_ }); Json = $true } } catch { } }
            if ($t -eq '') { return @{ Items = @(); Json = $false } }
            return @{ Items = @($t); Json = $false }
        }
        if ($v -is [System.Collections.IEnumerable]) { return @{ Items = @($v); Json = $false } }
        @{ Items = @($v); Json = $false }
    }
    function _isSorted($items) {
        for ($i = 1; $i -lt $items.Count; $i++) { if ([string]::Compare([string]$items[$i-1], [string]$items[$i], [StringComparison]::OrdinalIgnoreCase) -gt 0) { return $false } }
        $true
    }

    # group, keeping first-seen order
    $order = New-Object System.Collections.Generic.List[string]
    $groups = @{}
    foreach ($r in $rowsIn) {
        $key = Get-RASummaryGroupKey -Row $r -Plan $plan
        if (-not $groups.ContainsKey($key)) { $groups[$key] = New-Object System.Collections.Generic.List[object]; $order.Add($key) }
        $groups[$key].Add($r)
    }

    function _canon($v) {
        if ($null -eq $v) { return '' }
        if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { return ((@($v) | ForEach-Object { [string]$_ }) -join [char]30) }
        [string]$v
    }

    $out = New-Object System.Collections.Generic.List[object]
    $folded = 0; $refused = 0
    foreach ($key in $order) {
        $g = $groups[$key]
        if ($g.Count -eq 1) { $out.Add($g[0]); continue }
        $cols = @($g[0].PSObject.Properties | ForEach-Object Name)

        # REFUSE a group the merge cannot reproduce: a column with no rule (or derived from something it
        # cannot recompute) whose value differs between the rows. Its rows are kept as they are -- two rows
        # for one group is untidy, a merged row that lost one of them is data loss.
        $cannot = $false
        foreach ($c in $cols) {
            if ($plan.Keys -contains $c -or $plan.Agg.ContainsKey($c)) { continue }
            $d = $plan.Derived[$c]
            if ($d -and $d.Kind -eq 'join') { continue }
            # #402: a sentence built from columns the merged row carries is rebuilt below
            if ($d -and $d.Kind -eq 'strcat' -and @($d.Parts | Where-Object { $_.Col -and $cols -notcontains $_.Col }).Count -eq 0) { continue }
            # the distinct tokens of a merged list (si_affected_software, si_fix_*, si_cve_tags) are the union of the rows' tokens
            if ($d -and $d.Kind -eq 'tokenunion') { continue }
            # a sentence built from such a column when it is not empty (si_fix_remediation) is rebuilt from the merged row
            if ($d -and $d.Kind -eq 'iffstrcat' -and $cols -contains $d.Cond -and @($d.Parts | Where-Object { $_.Col -and $cols -notcontains $_.Col }).Count -eq 0) { continue }
            if ($d -and $d.Kind -eq 'count' -and $cols -contains $d.Src) { continue }
            if ($d -and $d.Kind -eq 'argmax' -and $cols -contains $d.Measure) { continue }
            # derived from a max that was projected away (`coalesce(max(...), 0)`): numeric -> its own max
            if ($d -and $d.Kind -eq 'argmax' -and @($g | Where-Object { $null -eq (_num $_.$c) }).Count -eq 0) { continue }
            $first = _canon $g[0].$c
            foreach ($r in $g) { if ((_canon $r.$c) -ne $first) { $cannot = $true; break } }
            if ($cannot) { break }
        }
        if ($cannot) { foreach ($r in $g) { $out.Add($r) }; $refused++; continue }

        $folded += ($g.Count - 1)
        $m = $g[0].PSObject.Copy()

        # arg_max measures first, so their companions can follow the winning row
        $winner = @{}
        foreach ($c in $cols) {
            $rule = $plan.Agg[$c]
            if ($null -eq $rule -or $rule.Kind -ne 'max') { continue }
            $best = $null; $bestRow = $g[0]
            foreach ($r in $g) { $n = _num $r.$c; if ($null -ne $n -and ($null -eq $best -or $n -gt $best)) { $best = $n; $bestRow = $r } }
            $winner[$c] = $bestRow
        }

        foreach ($c in $cols) {
            if ($plan.Keys -contains $c) { continue }
            $rule = $plan.Agg[$c]
            $vals = @($g | ForEach-Object { $_.PSObject.Properties[$c].Value })
            $kind = if ($rule) { $rule.Kind } else { 'first' }
            switch ($kind) {
                'max'    { $m.$c = $winner[$c].$c }
                'argmax' { if ($winner.ContainsKey($rule.Measure)) { $m.$c = $winner[$rule.Measure].$c } }
                'min'    { $best = $null; $bv = $vals[0]; foreach ($v in $vals) { $n = _num $v; if ($null -ne $n -and ($null -eq $best -or $n -lt $best)) { $best = $n; $bv = $v } elseif ($null -eq $n -and -not (_isEmpty $v) -and $null -eq $best -and ([string]$v -lt [string]$bv -or (_isEmpty $bv))) { $bv = $v } }; $m.$c = $bv }
                'sum'    { $t = 0.0; foreach ($v in $vals) { $n = _num $v; if ($null -ne $n) { $t += $n } }; $m.$c = if ($vals[0] -is [double] -or $vals[0] -is [decimal]) { $t } else { _whole $t } }
                'union'  {
                    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                    $items = New-Object System.Collections.Generic.List[object]; $json = $false
                    foreach ($v in $vals) { $l = _asList $v; if ($l.Json) { $json = $true }; foreach ($it in $l.Items) { if ($seen.Add([string]$it)) { $items.Add($it) } } }
                    [object[]]$arr = if ($rule.Sorted) { @($items | Sort-Object { [string]$_ }) } else { $items.ToArray() }
                    # assigned in two statements on purpose: an `if` expression would unroll a one-item array
                    if ($json) { $m.$c = ConvertTo-Json -InputObject $arr -Compress } else { $m.$c = $arr }
                }
                'tokens' {
                    $d = [string]$rule.Delim
                    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                    $items = New-Object System.Collections.Generic.List[string]; $allSorted = $true
                    foreach ($v in $vals) {
                        if (_isEmpty $v) { continue }
                        $parts = @(([string]$v).Split([string[]]@($d), [StringSplitOptions]::None) | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
                        if (-not (_isSorted $parts)) { $allSorted = $false }
                        foreach ($p in $parts) { if ($seen.Add($p)) { $items.Add($p) } }
                    }
                    $arr = if ($rule.Sorted -or $allSorted) { @($items | Sort-Object) } else { $items.ToArray() }
                    $m.$c = ($arr -join $d)
                }
                default  { foreach ($v in $vals) { if (-not (_isEmpty $v)) { $m.$c = $v; break } } }
            }
        }
        # dcount: an ASSET identity is counted in exactly one bucket (the buckets partition the assets),
        # so the per-bucket counts add up; a value the report also collects with make_set is recounted
        # from the merged set; anything else takes the largest per-bucket count -- a lower bound, never
        # inflated (a finding present in both buckets must not count twice).
        foreach ($c in $cols) {
            $rule = $plan.Agg[$c]
            if ($null -eq $rule -or $rule.Kind -ne 'dcount') { continue }
            $vals = @($g | ForEach-Object { $_.PSObject.Properties[$c].Value })
            $setCol = @($plan.Agg.Keys | Where-Object { $plan.Agg[$_].Kind -eq 'union' -and $plan.Agg[$_].Arg -and $plan.Agg[$_].Arg -eq $rule.Arg -and $m.PSObject.Properties[$_] }) | Select-Object -First 1
            if ($setCol) { $m.$c = [long]@((_asList $m.$setCol).Items).Count }
            elseif ($script:RA_AssetIdentityColumns -contains $rule.Arg) { $t = 0.0; foreach ($v in $vals) { $n = _num $v; if ($null -ne $n) { $t += $n } }; $m.$c = _whole $t }
            else { $best = $null; foreach ($v in $vals) { $n = _num $v; if ($null -ne $n -and ($null -eq $best -or $n -gt $best)) { $best = $n } }; if ($null -ne $best) { $m.$c = _whole $best } }
        }
        foreach ($c in $cols) {
            $d = $plan.Derived[$c]
            if ($null -eq $d -or $plan.Agg.ContainsKey($c)) { continue }
            switch ($d.Kind) {
                'count'  { if ($m.PSObject.Properties[$d.Src]) { $m.$c = [long]@((_asList $m.($d.Src)).Items).Count } }
                'join'   {
                    if ($m.PSObject.Properties[$d.Src]) { $m.$c = (@((_asList $m.($d.Src)).Items | ForEach-Object { [string]$_ }) -join [string]$d.Delim) }
                    else {
                        # the list itself was projected away -- union the joined text token by token
                        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
                        $items = New-Object System.Collections.Generic.List[string]
                        foreach ($r in $g) { foreach ($p in ([string]$r.$c).Split([string[]]@([string]$d.Delim), [StringSplitOptions]::None)) { $p = $p.Trim(); if ($p -and $seen.Add($p)) { $items.Add($p) } } }
                        $m.$c = ($items -join [string]$d.Delim)
                    }
                }
                'argmax' {
                    if ($winner.ContainsKey($d.Measure)) { $m.$c = $winner[$d.Measure].$c }
                    else { $best = $null; $bv = $m.$c; foreach ($r in $g) { $n = _num $r.$c; if ($null -ne $n -and ($null -eq $best -or $n -gt $best)) { $best = $n; $bv = $r.$c } }; $m.$c = $bv }
                }
            }
        }
        # #402: sentences built with strcat from the merged values, in the order the query builds them (one may use another)
        foreach ($c in @($plan.DerivedOrder)) {
            $d = $plan.Derived[$c]
            if ($null -eq $d -or $d.Kind -notin 'strcat', 'tokenunion', 'iffstrcat' -or -not $m.PSObject.Properties[$c] -or $plan.Agg.ContainsKey($c)) { continue }
            if ($d.Kind -eq 'tokenunion') {
                # the distinct tokens of every row's text, in first-seen order (the KQL set_union of the split texts)
                $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
                $items = New-Object System.Collections.Generic.List[string]
                foreach ($r in $g) { foreach ($p in ([string]$r.$c).Split([string[]]@([string]$d.Delim), [StringSplitOptions]::None)) { if ($p -ne '' -and $seen.Add($p)) { $items.Add($p) } } }
                $m.$c = ($items -join [string]$d.Delim)
                continue
            }
            $parts = $d.Parts
            if ($d.Kind -eq 'iffstrcat') {
                $cv = $m.($d.Cond)
                if ($null -eq $cv -or ([string]$cv) -eq '') { $m.$c = [string]$d.Else; continue }
            }
            $sb = New-Object System.Text.StringBuilder
            foreach ($p in $parts) {
                if ($p.ContainsKey('Lit')) { [void]$sb.Append([string]$p.Lit); continue }
                $v = $m.($p.Col)
                $t = if ($null -eq $v) { '' }
                     elseif ($v -is [string]) { $v }
                     elseif ($v -is [System.IFormattable]) { $v.ToString($null, $inv) }
                     elseif ($v -is [System.Collections.IEnumerable]) { ConvertTo-Json -InputObject @($v) -Compress }
                     else { [string]$v }
                if ($p.ContainsKey('From')) { $t = $t.Replace([string]$p.From, [string]$p.To) }
                [void]$sb.Append($t)
            }
            $m.$c = $sb.ToString()
        }
        $out.Add($m)
    }
    @{ Rows = $out.ToArray(); Merged = $folded; Refused = $refused; Applied = $true; Reason = '' }
}
