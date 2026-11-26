#Requires -Version 5.1
<#
    SecurityInsight FINDING FIELD MAPPER -- the generic fields a finding carries to an output (ServiceNow first), as
    CONFIGURATION, never code (owner 2026-11-16: "the next column is configuration, not code").

    THE FORMAT is the provider mapping format (data-model/mappings/*.locked.json, SI-FieldMapper.ps1), keyed by FINDING TYPE
    instead of record type -- data-model/finding-fields.locked.json, kind 'finding-field-map', items in 'mappings':

        { "field": "si_security_grouping_parent", "recordTypes": [ "cve" ],
          "when": { "field": "si_component", "op": "eq", "value": "OS" },          (optional: a condition, SI-Conditions.ps1)
          "label": "security-update",                                              (optional: read back by "$label:<field>")
          "sources": [ "si_fix_recommended_update" ],
          "normalize": [ "split:;", "trim", "strip:\\s*\\(Last updated at[^)]*\\)\\s*$", "sorted_join:; " ] }

      field        the target field (si_<name>); the carrier key and what an output column reads as extra.<field>
      recordTypes  the finding types the item applies to (cve, endpoint-recommendation, azure-recommendation, identity,
                   attack-path, exposure, recommendation) or "*" for every type
      sources      tried in order, the FIRST that yields a value wins:
                     <path>                 a dot path into the finding item (SI fields: si_title, si_affected_product ...)
                     $template:<text>       the text with every {<path>} filled in -- every placeholder must have a value,
                                            or the source yields nothing (never a half text); a list placeholder is its
                                            distinct values, sorted, joined with ", "
                     $label:<field>         the label of the item that gave <field> its value (an earlier field)
                     $value:<field>         the value an earlier field was given
      normalize    the provider mapper's CLOSED operation set (SI-FieldMapper.ps1) plus four of its own:
                     strip:<pattern>   remove what the pattern matches (a value left empty is dropped)
                     prefix:<text>     put the text before the value       suffix:<text>   after it
                     sorted_join:<sep> the distinct values (case-insensitive), sorted, joined -- one value
      For ONE field the items are tried in their order (more specific first); the first item that yields a value wins.
      EMPTY STAYS EMPTY: no item with a value = the field is left out (never a guessed value). A value equal to the finding's
      asset name (si_asset_name, si_cmdb_name) is never taken -- the next source is tried (a fix is never named after an
      asset or a person).

    Customer changes: Pro cfg.ItemOverride (kind 'datamodel', key 'finding-fields:<field>|<types>|'), Community
    data-model/finding-fields.custom.json -- merged per item by the data-model loader, as every other template.

    THE CARRIER: the values of one finding are ONE object (ConvertTo-SIFindingFieldValues); an output column reads one
    of them with "from": "extra.<field>" (SI-OutputMapper.ps1), the SQL hand-off stores the object as one JSON column
    (vuln.VulnerabilityItem.Extra). A new generic column is therefore a mapping item + an output column -- no table column.

    PURE. PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

if (-not (Get-Command -Name Invoke-SINormalizeOp -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-FieldMapper.ps1') }

# (the lists are returned by functions, never read from a script variable: a file dot-sourced inside a function keeps its
# variables in THAT scope -- the trap of #961 -- and an empty list here would refuse every finding type)
# the names a value must never be (a fix is never named after the asset or a person)
$script:SIFindingFieldMapCache = @{}

function Get-SIFindingFieldTypes { <# PURE. The finding types a mapping item may name (besides "*"). #> , @('cve', 'endpoint-recommendation', 'azure-recommendation', 'identity', 'attack-path', 'exposure', 'recommendation') }

function Get-SIFindingFieldOps {
    <# PURE. Every normalisation operation a finding field mapping may use: the provider mapper's + this mapper's own. #>
    $base = Get-SIFieldMapperOps   # assigned first: the call hands its array back wrapped
    , [string[]](@($base) + @('strip', 'prefix', 'suffix', 'sorted_join'))
}

function Get-SIFindingFieldType {
    <#
        PURE. The finding type of an item as the mapping names it: si_finding_type lower case, '_' as '-'
        (endpoint_recommendation = endpoint-recommendation); none = 'cve' for a CVE key, else 'recommendation'.
    #>
    param($Item)
    $t = ([string](Get-SIItemValue $Item 'si_finding_type')).Trim().ToLowerInvariant().Replace('_', '-')
    if ($t) { return $t }
    if (([string](Get-SIItemValue $Item 'si_finding_key')).Trim() -match '^(?i)CVE-\d{4}-\d+$') { return 'cve' }
    'recommendation'
}

function Get-SIFindingFieldMap {
    <#
        The finding field map in force: -Model's (Get-SIDataModel) when given, else the data model of the run
        (Get-SIDataModelRoot: Pro's materialised model with the customer's overrides, else the shipped folder), read once per
        folder. $null when the folder has no finding-fields template (a model from before it existed): nothing is mapped.
    #>
    param($Model, [string]$Root)
    if ($Model -and $Model -is [System.Collections.IDictionary] -and $Model.Contains('finding-fields')) { return $Model['finding-fields'] }
    if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1') }
    $r = Get-SIDataModelRoot $Root
    if (-not (Test-Path -LiteralPath (Join-Path $r 'finding-fields.locked.json'))) { return $null }
    $k = $r.ToLowerInvariant()
    if ($null -eq $script:SIFindingFieldMapCache) { $script:SIFindingFieldMapCache = @{} }
    if (-not $script:SIFindingFieldMapCache.ContainsKey($k)) { $script:SIFindingFieldMapCache[$k] = (Get-SIDataModelTemplate -Name 'finding-fields' -Root $r).Document }
    $script:SIFindingFieldMapCache[$k]
}

function Get-SIFindingFieldPlan {
    <# PURE. The map's items grouped per field, in the order each field first appears (the carrier's key order). #>
    param([Parameter(Mandatory)]$Map)
    $order = New-Object System.Collections.Generic.List[string]
    $by = @{}
    foreach ($it in @(Get-SIItemValue $Map 'mappings')) {
        if ($null -eq $it) { continue }
        $f = [string](Get-SIItemValue $it 'field')
        if (-not $f) { continue }
        if (-not $by.ContainsKey($f)) { $by[$f] = New-Object System.Collections.Generic.List[object]; $order.Add($f) }
        $steps = New-Object System.Collections.Generic.List[object]
        foreach ($c in @(Get-SIItemValue $it 'normalize')) {
            $cs = [string]$c
            if ([string]::IsNullOrWhiteSpace($cs)) { continue }
            $ci = $cs.IndexOf(':'); $op = $cs; $arg = ''
            if ($ci -ge 0) { $op = $cs.Substring(0, $ci); $arg = $cs.Substring($ci + 1) }
            $steps.Add([pscustomobject]@{ Op = $op; Arg = $arg })
        }
        $types = @(@(Get-SIItemValue $it 'recordTypes') | ForEach-Object { ([string]$_).Trim().ToLowerInvariant().Replace('_', '-') } | Where-Object { $_ })
        $by[$f].Add([pscustomobject]@{ Field = $f; Types = $types; When = (Get-SIItemValue $it 'when'); Label = [string](Get-SIItemValue $it 'label')
                                        Sources = @(@(Get-SIItemValue $it 'sources') | ForEach-Object { [string]$_ } | Where-Object { $_ }); Steps = $steps.ToArray() })
    }
    [pscustomobject]@{ Fields = $order.ToArray(); Items = $by }
}

function Get-SIFindingFieldFlat {
    <# PURE. A source's raw values, flat: a list value is its items (a JSON array text too), nulls left out. #>
    param([System.Collections.Generic.List[object]]$Values)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($v in $Values) {
        if ($null -eq $v -or $v -is [System.DBNull]) { continue }
        $x = $v
        if ($x -is [string]) {
            $t = $x.Trim()
            if ($t.StartsWith('[')) { try { $x = ConvertFrom-Json -InputObject $t } catch { $x = $v } }
        }
        if ($x -is [string] -or $x -is [System.Collections.IDictionary] -or -not ($x -is [System.Collections.IEnumerable])) { $out.Add($x); continue }
        foreach ($y in $x) { if ($null -ne $y -and -not ($y -is [System.DBNull])) { $out.Add($y) } }
    }
    , $out
}

function Get-SIFindingFieldSortedText {
    <# PURE. The distinct non-blank texts of a list (case-insensitive), sorted (ordinal, case-insensitive), joined. #>
    param([System.Collections.Generic.List[object]]$Values, [string]$Separator = ', ')
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $l = New-Object System.Collections.Generic.List[string]
    foreach ($v in $Values) { $s = ([string]$v).Trim(); if ($s -and $seen.Add($s)) { $l.Add($s) } }
    if ($l.Count -eq 0) { return '' }
    $a = $l.ToArray(); [Array]::Sort($a, [StringComparer]::OrdinalIgnoreCase)
    [string]::Join($Separator, $a)
}

function Invoke-SIFindingFieldStep {
    <# PURE. One normalisation step over a list of values: this mapper's own four, else the provider mapper's. #>
    param([System.Collections.Generic.List[object]]$Values, [string]$Op, [string]$Arg, $ValueMaps)
    $out = New-Object System.Collections.Generic.List[object]
    switch ($Op) {
        'strip' {
            $rx = New-Object System.Text.RegularExpressions.Regex($Arg, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, ([TimeSpan]::FromMilliseconds(200)))
            foreach ($v in $Values) { $s = $rx.Replace([string]$v, '').Trim(); if ($s) { $out.Add($s) } }
        }
        'prefix' { foreach ($v in $Values) { $out.Add($Arg + [string]$v) } }
        'suffix' { foreach ($v in $Values) { $out.Add([string]$v + $Arg) } }
        'sorted_join' { $s = Get-SIFindingFieldSortedText -Values $Values -Separator $Arg; if ($s) { $out.Add($s) } }
        default { return , (Invoke-SINormalizeOp -Values $Values -Op $Op -Arg $Arg -ValueMaps $ValueMaps) }
    }
    , $out
}

function Resolve-SIFindingFieldSource {
    <# PURE. The raw values one source gives for an item (a path, a template or a label), flat. #>
    param($Item, [string]$Source, [hashtable]$Labels, [System.Collections.IDictionary]$Done)
    $none = New-Object System.Collections.Generic.List[object]
    if ($Source.StartsWith('$label:')) {
        $f = $Source.Substring(7)
        if ($Labels -and $Labels.ContainsKey($f) -and $Labels[$f]) { $none.Add([string]$Labels[$f]) }
        return , $none
    }
    if ($Source.StartsWith('$value:')) {
        $f = $Source.Substring(7)
        if ($Done -and $Done.Contains($f) -and $null -ne $Done[$f]) { $none.Add($Done[$f]) }
        return , $none
    }
    if ($Source.StartsWith('$template:')) {
        $tpl = $Source.Substring(10)
        $sb = New-Object System.Text.StringBuilder
        $at = 0
        foreach ($m in [regex]::Matches($tpl, '\{([A-Za-z_][A-Za-z0-9_\.]*)\}')) {
            $vals = Get-SIFindingFieldFlat (Resolve-SISourcePath -Object $Item -Path $m.Groups[1].Value)
            $s = Get-SIFindingFieldSortedText -Values $vals -Separator ', '
            # every placeholder must have a value: never a half text
            if (-not $s) { return , $none }
            [void]$sb.Append($tpl.Substring($at, $m.Index - $at)).Append($s)
            $at = $m.Index + $m.Length
        }
        [void]$sb.Append($tpl.Substring($at))
        $t = ($sb.ToString() -replace '\s{2,}', ' ').Trim()
        if ($t) { $none.Add($t) }
        return , $none
    }
    , (Get-SIFindingFieldFlat (Resolve-SISourcePath -Object $Item -Path $Source))
}

#region #1384 A FINDING IN SEVERAL PRODUCTS (one CVE in nodejs and .net). The source fills the product, version and vendor lists
# independently (unpaired, in any order); the pairs are the finding's own affected software ("<name> <version> (<vendor>)" per
# copy). ONE place for the rule the task build (one task per product and version) and every output's grouping value (all
# those task names, sorted, "; " -- owner 2026-11-25 "Sorted, stable list") both read.

function Get-SIFindingFieldList {
    <# PURE. An item field's values as distinct non-blank texts (a list, or a ';'-separated text), in order. #>
    param($Item, [string]$Path)
    $out = New-Object 'System.Collections.Generic.List[string]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($v in (Get-SIFindingFieldFlat (Resolve-SISourcePath -Object $Item -Path $Path))) {
        foreach ($p in ([string]$v).Split(';')) { $t = $p.Trim(); if ($t -and $seen.Add($t)) { $out.Add($t) } }
    }
    , $out.ToArray()
}

function Get-SIFindingSoftwarePairs {
    <#
    .SYNOPSIS  PURE. The software of one finding as aligned pairs: each item of -Software ("<name> <version> (<vendor>)", the
               source's own text) whose product is one of -Products (exactly; the longest first) -> @{ Product (as the list
               has it); Version and Vendor (the item's own -- the source caps each list at 8 values on its own; the vendor as
               the list has it, lower case) }, one per product / version / vendor, sorted (ordinal, case-insensitive). An item
               naming no product of the finding is left out (never guessed).
    #>
    param([string[]]$Products = @(), [string[]]$Vendors = @(), $Software)
    $out = New-Object System.Collections.Generic.List[object]
    $items = New-Object 'System.Collections.Generic.List[string]'
    foreach ($v in (Get-SIFindingFieldFlat ([System.Collections.Generic.List[object]]@(, $Software)))) { foreach ($p in ([string]$v).Split(';')) { $t = $p.Trim(); if ($t) { $items.Add($t) } } }
    # #1403 a text stored cut to its column is read in full by the SQL that reads it, or without its last (cut) item
    # (engine\_shared\data-sql\SI-FullListSql.ps1) -- the pairing never guesses a cut from the length
    if ($items.Count -eq 0 -or @($Products).Count -eq 0) { return , $out.ToArray() }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $pl = @($Products | Sort-Object -Property @{ Expression = { $_.Length }; Descending = $true }, @{ Expression = { $_ } })
    foreach ($it in $items) {
        # #1403 an item with a bracket left open is a cut one: never paired
        $depth = 0; foreach ($ch in $it.ToCharArray()) { if ($ch -eq '(') { $depth++ } elseif ($ch -eq ')' -and $depth -gt 0) { $depth-- } }
        if ($depth -gt 0) { continue }
        # the vendor is the LAST bracket group (a product or vendor with its own brackets, "foo (x64) 1.0 (bar (eu))"); the
        # whole item without a vendor is tried too ("foo (x64)" -- a product with brackets and no vendor)
        $cands = New-Object System.Collections.Generic.List[object]
        if ($it.EndsWith(')')) {
            $open = -1; $dd = 0
            for ($i = $it.Length - 1; $i -ge 0; $i--) {
                if ($it[$i] -eq ')') { $dd++ } elseif ($it[$i] -eq '(') { $dd--; if ($dd -eq 0) { $open = $i; break } }
            }
            if ($open -lt 0) { $open = $it.LastIndexOf('(') }
            if ($open -ge 0) { $cands.Add(@($it.Substring(0, $open).Trim(), $it.Substring($open + 1, $it.Length - $open - 2).Trim())) }
        }
        $cands.Add(@($it, ''))
        $hit = $null
        foreach ($cd in $cands) {
            $rest0 = [string]$cd[0]; $d = [string]$cd[1]
            if (-not $rest0) { continue }
            foreach ($p in $pl) {
                $v = $null
                if ([string]::Equals($rest0, $p, [StringComparison]::OrdinalIgnoreCase)) { $v = '' }
                # #1403 a version with a space in it ("2.1 build 7") is the remainder after the product's name
                elseif ($rest0.StartsWith($p + ' ', [StringComparison]::OrdinalIgnoreCase)) { $v = ($rest0.Substring($p.Length).Trim() -replace '\s{2,}', ' ') }
                if ($null -eq $v) { continue }
                $dv = $d
                foreach ($x in @($Vendors)) { if ([string]::Equals($x, $d, [StringComparison]::OrdinalIgnoreCase)) { $dv = $x; break } }
                $hit = @{ Product = $p; Version = $v; Vendor = $dv.ToLowerInvariant() }
                break
            }
            if ($null -ne $hit) { break }
        }
        if ($null -eq $hit) { continue }
        if ($seen.Add(('{0}|{1}|{2}' -f $hit.Product, $hit.Version, $hit.Vendor))) { $out.Add([pscustomobject]$hit) }
    }
    $out.Sort([Comparison[object]] { param($a, $b)
            $c = [StringComparer]::OrdinalIgnoreCase.Compare($a.Product, $b.Product); if ($c -ne 0) { return $c }
            $c = [StringComparer]::Ordinal.Compare($a.Version, $b.Version); if ($c -ne 0) { return $c }
            [StringComparer]::OrdinalIgnoreCase.Compare($a.Vendor, $b.Vendor) })
    , $out.ToArray()
}

function Get-SIFindingSoftwareVariants {
    <#
    .SYNOPSIS  PURE. The software variants of one finding item: @() when it names at most one product (nothing to split);
               else one per product and version, each @{ si_affected_product; si_affected_version; si_affected_vendor;
               NoVersion } -- the pairs of its affected software, and for every product no pair covers (#1403): one version
               named = that version (the vendors, when several, sorted); else its version not named (NoVersion). Sorted.
    #>
    param($Item)
    $prods = Get-SIFindingFieldList $Item 'si_affected_product'
    if ($prods.Count -le 1) { return , @() }
    $vers = Get-SIFindingFieldList $Item 'si_affected_version'
    $vends = Get-SIFindingFieldList $Item 'si_affected_vendor'
    $sortedVend = { $x = New-Object 'System.Collections.Generic.List[string]'; foreach ($i in $vends) { $x.Add($i) }; $x.Sort([StringComparer]::OrdinalIgnoreCase); ($x.ToArray() -join ';') }
    $out = New-Object System.Collections.Generic.List[object]
    $pairs = Get-SIFindingSoftwarePairs -Products $prods -Vendors $vends -Software (Resolve-SISourcePath -Object $Item -Path 'si_affected_software')
    # #1403 (review of 3.1.51, owner "data quality is key. trust" / "no data drop"): EVERY product of the finding has a
    # variant -- its pairs, and a product no pair covers (its software item capped away by the source, cut, or spelled
    # otherwise) its own. What a product without a pair gets depends only on the finding's own lists, never on which OTHER
    # items survived the source's cap: one version named = that version; else its version not named (NoVersion,
    # "Update <product> (<vendor>)")
    $covered = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($s in @($pairs)) { [void]$covered.Add([string]$s.Product); $out.Add(@{ si_affected_product = $s.Product; si_affected_version = $s.Version; si_affected_vendor = $s.Vendor; NoVersion = $false }) }
    foreach ($p in $prods) {
        if ($covered.Contains($p)) { continue }
        if ($vers.Count -eq 1) { $out.Add(@{ si_affected_product = $p; si_affected_version = $vers[0]; si_affected_vendor = $(if ($vends.Count -eq 1) { $vends[0] } else { & $sortedVend }); NoVersion = $false }) }
        else { $out.Add(@{ si_affected_product = $p; si_affected_version = ''; si_affected_vendor = $(if ($vends.Count -eq 1) { $vends[0] } else { '' }); NoVersion = $true }) }
    }
    # sorted (product, version, vendor): the same variants in the same order whatever order the lists come in
    $out.Sort([Comparison[object]] { param($a, $b)
            $c = [StringComparer]::OrdinalIgnoreCase.Compare([string]$a['si_affected_product'], [string]$b['si_affected_product']); if ($c -ne 0) { return $c }
            $c = [StringComparer]::Ordinal.Compare([string]$a['si_affected_version'], [string]$b['si_affected_version']); if ($c -ne 0) { return $c }
            [StringComparer]::OrdinalIgnoreCase.Compare([string]$a['si_affected_vendor'], [string]$b['si_affected_vendor']) })
    , $out.ToArray()
}

function Get-SIFindingNoVersionName {
    <# PURE. The product's own task over every installed version, when no version is named: "Update <product> (<vendor>)". #>
    param([hashtable]$Variant)
    $nm = ('Update {0}' -f $Variant['si_affected_product']); if ($Variant['si_affected_vendor']) { $nm = ('{0} ({1})' -f $nm, $Variant['si_affected_vendor']) }
    $nm
}

function New-SIFindingFieldOverlay {
    <# PURE. A copy of an item (dictionary or object) with some fields replaced -- the item itself is never changed. #>
    param($Item, [System.Collections.IDictionary]$Set)
    $h = [ordered]@{}
    if ($Item -is [System.Collections.IDictionary]) { foreach ($k in $Item.Keys) { $v = $Item[$k]; if ($v -is [System.DBNull]) { $v = $null }; $h[[string]$k] = $v } }
    elseif ($null -ne $Item) { foreach ($p in $Item.PSObject.Properties) { $h[$p.Name] = $p.Value } }
    foreach ($k in $Set.Keys) { if ($k -ne 'NoVersion') { $h[[string]$k] = $Set[$k] } }
    [pscustomobject]$h
}
#endregion

function ConvertTo-SIFindingFieldValues {
    <#
    .SYNOPSIS  PURE. One finding item (the data-out item: the finding document with its CI's values) -> its mapped values,
               the CARRIER: an ordered dictionary field -> value, only the fields a source gave a value (empty stays empty).
               -Fields: only these (and the fields their labels read); none = every field of the map.
    .OUTPUTS   [ordered] field -> value
    #>
    param([Parameter(Mandatory)]$Item, [Parameter(Mandatory)]$Map, $ValueMaps, [string[]]$Fields = @(), $Plan)
    if ($null -eq $Plan) { $Plan = Get-SIFindingFieldPlan -Map $Map }
    $type = Get-SIFindingFieldType $Item
    $never = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($n in @('si_asset_name', 'si_cmdb_name')) { $nv = ([string](Get-SIItemValue $Item $n)).Trim(); if ($nv) { [void]$never.Add($nv) } }
    $want = $null; $work = $null
    $asked = @(@($Fields) | ForEach-Object { [string]$_ } | Where-Object { $_ })
    if ($asked.Count) {
        $want = @{}; $work = @{}
        foreach ($f in $asked) { $want[$f] = $true; $work[$f] = $true }
        # a field a wanted field reads by its label or value is worked out too (not returned)
        foreach ($f in $asked) {
            if (-not $Plan.Items.ContainsKey($f)) { continue }
            foreach ($it in $Plan.Items[$f]) { foreach ($s in @($it.Sources)) { $m = [regex]::Match([string]$s, '^\$(label|value):(.+)$'); if ($m.Success) { $work[$m.Groups[2].Value] = $true } } }
        }
    }
    $out = [ordered]@{}
    $all = [ordered]@{}
    $labels = @{}
    $variants = $null
    foreach ($field in $Plan.Fields) {
        if ($null -ne $work -and -not $work.ContainsKey($field)) { continue }
        foreach ($it in $Plan.Items[$field]) {
            if ($it.Types -notcontains '*' -and $it.Types -notcontains $type) { continue }
            if ($null -ne $it.When -and -not (Test-SICondition -Condition $it.When -Item $Item)) { continue }
            $got = $null
            # #1384 an item whose text names the affected product, for a finding in SEVERAL products: the item worked out once
            # per product and version (the task build's own variants), every name it gives, sorted, "; " -- never the lists'
            # own order (which moves run to run)
            $multi = $false
            foreach ($src in $it.Sources) { if (([string]$src).StartsWith('$template:') -and ([string]$src).Contains('{si_affected_product}')) { $multi = $true; break } }
            if ($multi) {
                if ($null -eq $variants) { $variants = Get-SIFindingSoftwareVariants -Item $Item }
                if (@($variants).Count -gt 1) {
                    $names = New-Object System.Collections.Generic.List[object]
                    foreach ($var in @($variants)) {
                        $ov = New-SIFindingFieldOverlay -Item $Item -Set $var
                        $one = $null
                        foreach ($src in $it.Sources) {
                            $vals = Resolve-SIFindingFieldSource -Item $ov -Source $src -Labels $labels -Done $all
                            if ($vals.Count -eq 0) { continue }
                            foreach ($st in $it.Steps) { $vals = Invoke-SIFindingFieldStep -Values $vals -Op $st.Op -Arg $st.Arg -ValueMaps $ValueMaps; if ($vals.Count -eq 0) { break } }
                            foreach ($v in $vals) { $s = ([string]$v).Trim(); if ($s -and -not $never.Contains($s)) { $one = $s; break } }
                            if ($null -ne $one) { break }
                        }
                        if ($null -eq $one -and $var['NoVersion'] -and $type -eq 'cve') { $one = Get-SIFindingNoVersionName $var; if ($never.Contains($one)) { $one = $null } }
                        if ($null -ne $one) { $names.Add($one) }
                    }
                    $joined = Get-SIFindingFieldSortedText -Values $names -Separator '; '
                    if ($joined) { $got = $joined }
                    if ($null -ne $got) {
                        $labels[$field] = $it.Label
                        $all[$field] = $got
                        if ($null -eq $want -or $want.Contains($field)) { $out[$field] = $got }
                        break
                    }
                    continue
                }
            }
            foreach ($src in $it.Sources) {
                $vals = Resolve-SIFindingFieldSource -Item $Item -Source $src -Labels $labels -Done $all
                if ($vals.Count -eq 0) { continue }
                foreach ($st in $it.Steps) {
                    $vals = Invoke-SIFindingFieldStep -Values $vals -Op $st.Op -Arg $st.Arg -ValueMaps $ValueMaps
                    if ($vals.Count -eq 0) { break }
                }
                foreach ($v in $vals) {
                    if ($null -eq $v -or $v -is [System.DBNull]) { continue }
                    if ($v -is [string]) { $v = $v.Trim(); if (-not $v) { continue } }
                    elseif (Test-SIValueEmpty $v) { continue }
                    # never an asset or a person name
                    if ($never.Contains(([string]$v).Trim())) { continue }
                    $got = $v; break
                }
                if ($null -ne $got) { break }
            }
            if ($null -ne $got) {
                $labels[$field] = $it.Label
                $all[$field] = $got
                if ($null -eq $want -or $want.Contains($field)) { $out[$field] = $got }
                break
            }
        }
    }
    $out
}

function ConvertTo-SIFindingFieldJson {
    <# PURE. The carrier as the ONE JSON text stored with a vulnerable item ('' when empty). Keys in the map's order. #>
    param([System.Collections.IDictionary]$Values)
    if ($null -eq $Values -or $Values.Count -eq 0) { return '' }
    ConvertTo-Json -InputObject $Values -Compress -Depth 4
}

function Get-SIOutputExtraFields {
    <# PURE. The carrier fields an output map's columns read (from "extra.<field>"), in column order, each once. #>
    param($Map)
    $l = New-Object System.Collections.Generic.List[string]
    foreach ($c in @(Get-SIItemValue $Map 'columns')) {
        if ($null -eq $c) { continue }
        $m = [regex]::Match([string](Get-SIItemValue $c 'from'), '^extra\.([A-Za-z_][A-Za-z0-9_]*)$')
        if ($m.Success -and -not $l.Contains($m.Groups[1].Value)) { $l.Add($m.Groups[1].Value) }
    }
    , $l.ToArray()
}

function Test-SIFindingFieldMap {
    <#
    .SYNOPSIS  PURE. The problems of a finding field map (empty = valid): every item names a field (si_<name>), known finding
               types, at least one source, known operations, a valid condition; a template names paths only; a label source
               reads a field defined EARLIER in the map.
    #>
    param([Parameter(Mandatory)]$Map, $ValueMaps)
    $p = New-Object System.Collections.Generic.List[string]
    $ops = Get-SIFindingFieldOps         # assigned first: the calls hand their arrays back wrapped
    $types = Get-SIFindingFieldTypes
    $types = [string[]](@($types) + '*')
    $condOps = Get-SIConditionOps
    $defined = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($it in @(Get-SIItemValue $Map 'mappings')) {
        if ($null -eq $it) { continue }
        $f = [string](Get-SIItemValue $it 'field')
        if ($f -cnotmatch '^si_[a-z0-9_]{1,60}$') { $p.Add(("finding-fields: '{0}' is not a field name (si_ and lower snake_case)" -f $f)); continue }
        $rts = @(Get-SIItemValue $it 'recordTypes')
        if ($rts.Count -eq 0) { $p.Add("finding-fields: '$f' names no finding type (recordTypes; ""*"" = every type)") }
        foreach ($t in $rts) { if ($types -notcontains ([string]$t).Trim().ToLowerInvariant().Replace('_', '-')) { $p.Add("finding-fields: '$f' names unknown finding type '$t'") } }
        $srcs = @(@(Get-SIItemValue $it 'sources') | Where-Object { $_ })
        if ($srcs.Count -eq 0) { $p.Add("finding-fields: '$f' has no source") }
        foreach ($s in $srcs) {
            $ss = [string]$s
            if ($ss.StartsWith('$label:') -or $ss.StartsWith('$value:')) {
                $lf = $ss.Substring(7)
                if (-not $defined.Contains($lf)) { $p.Add("finding-fields: '$f' reads '$ss', but '$lf' is not a field defined before it") }
            } elseif ($ss.StartsWith('$template:')) {
                if (-not [regex]::IsMatch($ss, '\{[A-Za-z_][A-Za-z0-9_\.]*\}')) { $p.Add("finding-fields: '$f' has a template without a {field}") }
                if ($ss.Length -gt 300) { $p.Add("finding-fields: '$f' has a template longer than 300 characters") }
            } elseif ($ss.StartsWith('$')) { $p.Add("finding-fields: '$f' has unknown source '$ss' (a path, `$template:<text>, `$label:<field> or `$value:<field>)") }
            elseif ($ss -notmatch '^[A-Za-z_][A-Za-z0-9_]*(\[\*\])?(\.[A-Za-z_][A-Za-z0-9_]*(\[\*\])?)*$') { $p.Add("finding-fields: '$f' has a source that is not a path: '$ss'") }
        }
        foreach ($step in @(Get-SIItemValue $it 'normalize')) {
            if (-not $step) { continue }
            $sx = [string]$step
            $op = $sx.Split(':')[0]
            if ($ops -notcontains $op) { $p.Add("finding-fields: '$f' uses unknown operation '$op'"); continue }
            if ($op -eq 'strip' -or $op -eq 'regex_extract') { try { [void][regex]::new($sx.Substring($op.Length + 1)) } catch { $p.Add("finding-fields: '$f' has an invalid pattern in '$sx'") } }
            if ($op -eq 'enum' -and $null -ne $ValueMaps) { $id = $sx.Substring(5); if ($null -eq (Get-SIItemValue $ValueMaps $id)) { $p.Add("finding-fields: '$f' names unknown value map '$id'") } }
        }
        $w = Get-SIItemValue $it 'when'
        if ($null -ne $w) {
            $leaves = New-Object System.Collections.Generic.List[object]
            $walk = { param($c) foreach ($g in 'all', 'any') { $gv = Get-SIItemValue $c $g; if ($null -ne $gv) { foreach ($x in @($gv)) { & $walk $x }; return } }; $leaves.Add($c) }
            & $walk $w
            foreach ($l in $leaves) { if ($condOps -notcontains [string](Get-SIItemValue $l 'op')) { $p.Add("finding-fields: '$f' has a condition with unknown operation '$(Get-SIItemValue $l 'op')'") } }
        }
        $lb = [string](Get-SIItemValue $it 'label'); if ($lb.Length -gt 64) { $p.Add("finding-fields: '$f' has a label longer than 64 characters") }
        [void]$defined.Add($f)
    }
    $p.ToArray()
}
