#Requires -Version 5.1
<#
    THE SUMMARY GROUPINGS -- ONE DEFINITION, ONE FUNCTION, BOTH EDITIONS (REQUIREMENTS #636, owner 2026-10-19: "summary could
    be build as views with the detailed data instead. it is just views with groupings of data instead, like group per tier
    category" / "community must switch" / "same core functionality").

    The Summary-shaped views (one row per recommendation with its affected assets, per asset, per tier, per Domain > Category
    > Subcategory, per risk rating, per department, per severity, per report) are GROUPINGS OF THE DETAILED FINDINGS -- never
    a second Risk Analysis. data-model\summary-groupings.locked.json declares them (keys and measures); this file is the ONE
    engine function that computes them, Invoke-SISummaryGrouping:

      * -Rows / -Pager  the Detailed result in the run (Community: no SQL -- its management mail and outputs read it);
      * -AsSql          the statement that computes the very same groupings for ONE stored collection (@CollectionId) in the
                        Pro database and writes them, typed and indexed, into sidata.SummaryGroup / SummaryGroupCounted /
                        SummaryGroupState (the data sync runs it: engine\pro-data\_shared\SI-DataSummaryGroups.ps1).

    Both read ONE compiled plan of the definition (Get-SISummaryGroupingPlan): the same fields, the same normalisation of each
    value (the same trimming, the same tier words, the same severity words), the same measures. A test holds the two paths
    equal on the same findings (tests\pester\SIv3-SummaryGroupings.Tests.ps1, on a real SQL Server too). There is no second
    summary logic anywhere: a new grouping is one entry in the definition.

    Every finding counts: no cap, no sample. The counted variant (#264) leaves out the rows with an exemption mark.
    PURE except Invoke-SISummaryGrouping -AsSql (returns text) -- nothing here reads or writes a database.
#>

$script:SISummaryGroupingDefinitionPath = [IO.Path]::Combine((Split-Path -Parent (Split-Path -Parent $PSScriptRoot)), 'data-model', 'summary-groupings.locked.json')
$script:SISummaryGroupingPlanCache = $null

function Get-SISummaryGroupingDefinition {
    <# The definition (data-model\summary-groupings.locked.json) as an object, with .Hash = SHA-256 of its text (the data sync
       writes a collection again when the definition changed). -Path: another file (tests). #>
    param([string]$Path = $script:SISummaryGroupingDefinitionPath)
    $text = [IO.File]::ReadAllText($Path)
    $def = $text | ConvertFrom-Json
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($text -replace "`r`n", "`n"))) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
    $def | Add-Member -NotePropertyName Hash -NotePropertyValue $hash.Substring(0, 32) -Force
    $def
}

function Get-SISummaryGroupingPlan {
    <#
        PURE. The definition compiled once: .Fields (name -> @{ Kind; Max; Sql; Row; PathRow }), .Measures, .Groupings
        (each with .Keys[3] -- '' for an unused key -- and .LabelField), .SeverityWords, .Exempted, .Hash, .MeasureIds.
        Refuses a definition that names an unknown field, an unknown kind or op, or more than three keys.
    #>
    param($Definition)
    if (-not $Definition) {
        if ($script:SISummaryGroupingPlanCache) { return $script:SISummaryGroupingPlanCache }
        $Definition = Get-SISummaryGroupingDefinition
        $cache = $true
    } else { $cache = $false }
    # 'tokens' (#812): a ';'-list -- a finding counts once under each distinct token (MITRE tactics / techniques, compliance
    # controls); 'band': a number into the labelled bands the field declares (the CVSS bands)
    # 'date' (2026-10-20): the day yyyy-MM-dd, none = no value -- an attribute's first seen
    $kinds = @('text', 'tier', 'tierNumber', 'severity', 'id', 'number', 'flag', 'presence', 'tokens', 'band', 'date')
    $ops = @('count', 'countDistinct', 'max', 'min', 'sum')
    $fields = [ordered]@{}
    foreach ($p in $Definition.fields.PSObject.Properties) {
        $f = $p.Value
        if ($kinds -cnotcontains [string]$f.kind) { throw ("summary groupings: field '{0}' has an unknown kind '{1}'" -f $p.Name, $f.kind) }
        if ([string]$p.Name -notmatch '^[a-zA-Z][a-zA-Z0-9]{0,30}$') { throw ("summary groupings: '{0}' is not a field name" -f $p.Name) }
        $max = 0; if ($f.PSObject.Properties['max']) { $max = [int]$f.max }
        if ($f.kind -in 'text', 'tokens' -and $max -le 0) { throw ("summary groupings: {0} field '{1}' needs 'max'" -f $f.kind, $p.Name) }
        if ($f.kind -eq 'tokens' -and $max -gt 400) { throw ("summary groupings: tokens field '{0}': a token is a key, at most 400 characters" -f $p.Name) }
        $split = @(); if ($f.PSObject.Properties['split']) { $split = @($f.split | ForEach-Object { [string]$_ } | Where-Object { $_ -and $_ -ne ';' }) }
        $bands = @(); $else = ''
        if ($f.kind -eq 'band') {
            foreach ($b in @($f.bands)) {
                $atLeast = $b.PSObject.Properties['atLeast']; $above = $b.PSObject.Properties['above']
                if (-not ($atLeast -or $above) -or -not [string]$b.label) { throw ("summary groupings: band field '{0}': every band needs 'atLeast' or 'above' and a 'label'" -f $p.Name) }
                $bands += [pscustomobject]@{ Op = $(if ($atLeast) { '>=' } else { '>' }); Value = [double]$(if ($atLeast) { $atLeast.Value } else { $above.Value }); Label = [string]$b.label }
            }
            if ($bands.Count -eq 0 -or -not $f.PSObject.Properties['else']) { throw ("summary groupings: band field '{0}' needs 'bands' and 'else'" -f $p.Name) }
            $else = [string]$f.else
        }
        $fields[$p.Name] = [pscustomobject]@{ Name = $p.Name; Kind = [string]$f.kind; Max = $max; Sql = [string]$f.sql; Split = $split; Bands = $bands; Else = $else
            Row = @($f.row | ForEach-Object { [string]$_ }); PathRow = @($(if ($f.PSObject.Properties['pathRow']) { $f.pathRow | ForEach-Object { [string]$_ } })) }
    }
    $need = { param($n, $what) if (-not $fields.Contains([string]$n)) { throw ("summary groupings: {0} names the unknown field '{1}'" -f $what, $n) } }
    # a tokens field is only ever a grouping key (one per grouping): a finding stands under several of its values
    $noTokens = { param($n, $what) if ($n -and $fields[[string]$n].Kind -eq 'tokens') { throw ("summary groupings: {0} names the tokens field '{1}' -- a tokens field is a grouping key only" -f $what, $n) } }
    $measures = foreach ($m in @($Definition.measures)) {
        if ($ops -cnotcontains [string]$m.op) { throw ("summary groupings: measure '{0}' has an unknown op '{1}'" -f $m.id, $m.op) }
        if ([string]$m.id -notmatch '^[A-Z][A-Za-z0-9]{0,40}$') { throw ("summary groupings: '{0}' is not a measure id" -f $m.id) }
        $fld = ''; if ($m.PSObject.Properties['field'] -and $m.field) { $fld = [string]$m.field; & $need $fld ("measure '{0}'" -f $m.id); & $noTokens $fld ("measure '{0}'" -f $m.id) }
        if ($m.op -ne 'count' -and -not $fld) { throw ("summary groupings: measure '{0}' needs a field" -f $m.id) }
        $wf = ''; $wv = ''
        if ($m.PSObject.Properties['where'] -and $m.where) { $wf = [string]$m.where.field; $wv = [string]$m.where.equals; & $need $wf ("measure '{0}' (where)" -f $m.id); & $noTokens $wf ("measure '{0}' (where)" -f $m.id) }
        [pscustomobject]@{ Id = [string]$m.id; Op = [string]$m.op; Field = $fld; WhereField = $wf; WhereEquals = $wv }
    }
    $groupings = foreach ($g in @($Definition.groupings)) {
        $keys = @($g.keys | ForEach-Object { [string]$_ })
        if ($keys.Count -lt 1 -or $keys.Count -gt 3) { throw ("summary groupings: grouping '{0}' needs 1 to 3 keys" -f $g.id) }
        foreach ($k in $keys) { & $need $k ("grouping '{0}'" -f $g.id) }
        if (@($keys | Where-Object { $fields[$_].Kind -eq 'tokens' }).Count -gt 1) { throw ("summary groupings: grouping '{0}' has more than one tokens key" -f $g.id) }
        if ([string]$g.id -notmatch '^[a-z][a-z0-9\-]{0,39}$') { throw ("summary groupings: '{0}' is not a grouping id" -f $g.id) }
        $lf = ''; if ($g.PSObject.Properties['labelField'] -and $g.labelField) { $lf = [string]$g.labelField; & $need $lf ("grouping '{0}' (label)" -f $g.id); & $noTokens $lf ("grouping '{0}' (label)" -f $g.id) }
        # attributes (owner 2026-10-20, the Summary report's columns per row): max / min of a field, or a list of its distinct
        # values -- never over a tokens field, and only on a grouping without a tokens key (the rows of a key are looked up)
        $attrs = @(foreach ($a in @($(if ($g.PSObject.Properties['attributes']) { $g.attributes }))) {
            if ([string]$a.id -notmatch '^[A-Z][A-Za-z0-9]{0,40}$') { throw ("summary groupings: '{0}' is not an attribute id (grouping '{1}')" -f $a.id, $g.id) }
            if (@('max', 'min', 'list', 'first') -cnotcontains [string]$a.op) { throw ("summary groupings: attribute '{0}' of grouping '{1}' has an unknown op '{2}'" -f $a.id, $g.id, $a.op) }
            $ord = @(); if ($a.PSObject.Properties['order']) { $ord = @($a.order | ForEach-Object { [string]$_ } | Where-Object { $_ }) }
            if ($a.op -eq 'first' -and $ord.Count -lt 1) { throw ("summary groupings: attribute '{0}' of grouping '{1}' ('first') needs 'order'" -f $a.id, $g.id) }
            & $need ([string]$a.field) ("grouping '{0}' (attribute '{1}')" -f $g.id, $a.id); & $noTokens ([string]$a.field) ("grouping '{0}' (attribute '{1}')" -f $g.id, $a.id)
            if ($fields[[string]$a.field].Kind -notin 'text', 'date', 'tier', 'severity', 'band') { throw ("summary groupings: attribute '{0}' of grouping '{1}' reads a {2} field -- a text or date field only" -f $a.id, $g.id, $fields[[string]$a.field].Kind) }
            $am = 0; if ($a.PSObject.Properties['max']) { $am = [int]$a.max }
            if ($a.op -eq 'list' -and ($am -lt 1 -or $am -gt 100)) { throw ("summary groupings: list attribute '{0}' of grouping '{1}' needs 'max' 1..100" -f $a.id, $g.id) }
            [pscustomobject]@{ Id = [string]$a.id; Op = [string]$a.op; Field = [string]$a.field; Max = $am; Order = $ord }
        })
        if ($attrs.Count -and @($keys | Where-Object { $fields[$_].Kind -eq 'tokens' }).Count) { throw ("summary groupings: grouping '{0}' has attributes and a tokens key" -f $g.id) }
        if (@($attrs | ForEach-Object Id | Select-Object -Unique).Count -ne $attrs.Count) { throw ("summary groupings: grouping '{0}' names an attribute twice" -f $g.id) }
        while ($keys.Count -lt 3) { $keys += '' }
        [pscustomobject]@{ Id = [string]$g.id; Label = [string]$g.label; Keys = $keys; LabelField = $lf; Attributes = $attrs }
    }
    $sev = [ordered]@{}
    foreach ($p in $Definition.severityWords.PSObject.Properties) { $sev[[string]$p.Name] = [string]$p.Value }
    $ex = [string]$Definition.exempted; & $need $ex 'exempted'
    $plan = [pscustomobject]@{ Fields = $fields; Measures = @($measures); Groupings = @($groupings); SeverityWords = $sev; Exempted = $ex
        Hash = $(if ($Definition.PSObject.Properties['Hash']) { [string]$Definition.Hash } else { '' }); MeasureIds = @($measures | ForEach-Object { $_.Id }) }
    if ($cache) { $script:SISummaryGroupingPlanCache = $plan }
    $plan
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE NORMALISATION -- the same rule on both paths (PowerShell here, the SQL expression below)
# ---------------------------------------------------------------------------------------------------------------------

function ConvertTo-SISummaryGroupingValue {
    <# PURE. One raw value normalised by its field's kind (see the definition's comment). Returns a string, a [double] or $null. #>
    param($Field, [AllowNull()]$Value, $Plan)
    if ($Field.Kind -eq 'tokens') { return , (ConvertTo-SISummaryGroupingTokens -Field $Field -Value $Value) }
    if ($Field.Kind -eq 'date') { return (ConvertTo-SISummaryGroupingDay $Value) }
    $s = ''
    if ($null -ne $Value -and -not ($Value -is [DBNull])) {
        if ($Value -is [bool]) { $s = $(if ($Value) { 'true' } else { 'false' }) }
        elseif ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) { $s = ([double]$Value).ToString('R', [Globalization.CultureInfo]::InvariantCulture) }
        else { $s = ([string]$Value).Trim() }
        # Log Analytics returns an empty dynamic value as text
        if (@('{}', '[]', 'null', '@{}') -contains $s) { $s = '' }
    }
    switch ($Field.Kind) {
        'text' { if ($s.Length -gt $Field.Max) { return $s.Substring(0, $Field.Max) }; return $s }
        'tier' { $t = ConvertTo-SISummaryGroupingTier $s; if ($null -eq $t) { return 'Unclassified' }; return [string]$t }
        'tierNumber' { return (ConvertTo-SISummaryGroupingTier $s) }
        'severity' {
            if (-not $s) { return 'None' }
            $k = ($s.ToLowerInvariant() -replace '[\s\-_]', '')
            if ($Plan.SeverityWords.Contains($k)) { return [string]$Plan.SeverityWords[$k] }
            return 'Other'
        }
        'id' { $n = 0L; if ([long]::TryParse($s, [ref]$n)) { return [string]$n }; return '0' }
        'number' { $d = 0.0; if ($s -and [double]::TryParse($s, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }; return $null }
        'flag' { if ($s -match '^(?i:true|1)$') { return '1' }; return '0' }
        'presence' { if ($s) { return '1' }; return '0' }
        'band' {
            $d = 0.0
            if (-not $s -or -not [double]::TryParse($s, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return '' }
            foreach ($b in $Field.Bands) { if (($b.Op -eq '>=' -and $d -ge $b.Value) -or ($b.Op -eq '>' -and $d -gt $b.Value)) { return $b.Label } }
            return $Field.Else
        }
    }
    $s
}

function ConvertTo-SISummaryGroupingTokens {
    <#
        PURE. A tokens field's value as its distinct tokens (string[]): a list (an array, a JSON array text, or a text) joined
        with ';', every separator of the field's 'split' turned into ';', split on ';', each trimmed and cut to 'max', empty ones
        dropped, distinct ignoring case (as SQL groups) -- the first spelling kept. Written to the pipeline one by one (wrap the call in @()). The twin of the SQL CROSS APPLY in
        Get-SISummaryGroupingSqlText (and of the data sync's derive of the list columns).
    #>
    param($Field, [AllowNull()]$Value)
    $items = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Value -or $Value -is [DBNull]) { return }
    if ($Value -is [string]) {
        $t = $Value.Trim()
        if ($t.StartsWith('[') -and $t.EndsWith(']')) {
            try { foreach ($x in @($t | ConvertFrom-Json)) { if ($null -ne $x) { $items.Add([string]$x) } } } catch { $items.Add($t) }
        } else { $items.Add($t) }
    } elseif ($Value -is [System.Collections.IEnumerable]) {
        foreach ($x in $Value) { if ($null -ne $x) { $items.Add([string]$x) } }
    } else { $items.Add([string]$Value) }
    $s = $items -join ';'
    foreach ($sep in $Field.Split) { $s = $s.Replace($sep, ';') }
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($p in $s.Split(';')) {
        $v = $p.Trim()
        if ($v.Length -gt $Field.Max) { $v = $v.Substring(0, $Field.Max) }
        if ($v -and @('{}', '[]', 'null', '@{}') -notcontains $v -and $seen.Add($v)) { $out.Add($v) }
    }
    $out.ToArray()
}

function ConvertTo-SISummaryGroupingDay {
    <# PURE. A date as its day 'yyyy-MM-dd' (a [datetime] / [datetimeoffset], or a text read in the invariant culture -- an
       offset is taken to UTC); anything else = $null. The twin of CONVERT(nvarchar(10), CONVERT(date, x), 23). #>
    param([AllowNull()]$Value)
    if ($null -eq $Value -or $Value -is [DBNull]) { return $null }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) }
    $t = ([string]$Value).Trim()
    if (-not $t) { return $null }
    $d = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$d)) {
        return $d.UtcDateTime.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    }
    $null
}

function ConvertTo-SISummaryGroupingTier {
    <# PURE. 0..3 from '0', 2, 'Tier1', '1.0'; else $null. #>
    param([AllowNull()][string]$Text)
    if (-not $Text) { return $null }
    $t = $Text -replace '(?i)^tier\s*', ''
    $d = 0.0
    if (-not [double]::TryParse($t, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $null }
    if ($d -ne [Math]::Floor($d) -or $d -lt 0 -or $d -gt 3) { return $null }
    [int]$d
}

function Get-SISummaryGroupingSqlValue {
    <# The SQL expression of one field's normalised value over sidata.Finding (alias f) -- the twin of ConvertTo-SISummaryGroupingValue. #>
    param($Field, $Plan)
    $x = $Field.Sql
    switch ($Field.Kind) {
        'text' { return ("LEFT(LTRIM(RTRIM(ISNULL(CONVERT(nvarchar(4000), {0}), N''))), {1})" -f $x, $Field.Max) }
        'tier' { return ("CASE WHEN {0} BETWEEN 0 AND 3 THEN CONVERT(nvarchar(12), {0}) ELSE N'Unclassified' END" -f $x) }
        'tierNumber' { return ("CASE WHEN {0} BETWEEN 0 AND 3 THEN CONVERT(tinyint, {0}) END" -f $x) }
        'severity' {
            $norm = "LOWER(REPLACE(REPLACE(REPLACE(LTRIM(RTRIM(COALESCE({0}, N''))), N' ', N''), N'-', N''), N'_', N''))" -f $x
            $when = foreach ($k in $Plan.SeverityWords.Keys) { "WHEN N'{0}' THEN N'{1}'" -f $k.Replace("'", "''"), ([string]$Plan.SeverityWords[$k]).Replace("'", "''") }
            return ("CASE {0} WHEN N'' THEN N'None' {1} ELSE N'Other' END" -f $norm, ($when -join ' '))
        }
        'id' { return ("CONVERT(nvarchar(32), ISNULL(CONVERT(bigint, {0}), 0))" -f $x) }
        'number' { return ("CONVERT(float, {0})" -f $x) }
        'flag' { return ("CASE WHEN {0} = 1 THEN N'1' ELSE N'0' END" -f $x) }
        'presence' { return ("CASE WHEN {0} IS NULL THEN N'0' ELSE N'1' END" -f $x) }
        # the list as stored, every separator of 'split' turned into ';' -- the grouping splits it (Get-SISummaryGroupingSqlText, one CROSS APPLY)
        'tokens' {
            $e = "ISNULL(CONVERT(nvarchar(4000), {0}), N'')" -f $x
            foreach ($sep in $Field.Split) { $e = "REPLACE({0}, N'{1}', N';')" -f $e, $sep.Replace("'", "''") }
            return $e
        }
        'band' {
            $when = foreach ($b in $Field.Bands) { "WHEN CONVERT(float, {0}) {1} {2} THEN N'{3}'" -f $x, $b.Op, $b.Value.ToString('R', [Globalization.CultureInfo]::InvariantCulture), $b.Label.Replace("'", "''") }
            return ("CASE WHEN {0} IS NULL THEN N'' {1} ELSE N'{2}' END" -f $x, ($when -join ' '), $Field.Else.Replace("'", "''"))
        }
        'date' { return ("CONVERT(nvarchar(10), CONVERT(date, {0}), 23)" -f $x) }
    }
    throw ("summary groupings: no SQL for kind '{0}'" -f $Field.Kind)
}

function Get-SISummaryGroupingRowValues {
    <# PURE. One Detailed row -> @{ field = normalised value } for every field of the plan (the row's first present column wins;
       an attack-path row takes the 'pathRow' column for the tier when it has it -- Get-SIDataRowTiers). #>
    param([Parameter(Mandatory)]$Row, [Parameter(Mandatory)]$Plan)
    $props = $Row.PSObject.Properties
    $get = {
        param([string[]]$names)
        foreach ($n in $names) {
            if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { $v = $Row[$n]; if ($null -ne $v -and "$v" -ne '') { return $v } } ; continue }
            $p = $props[$n]; if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne '') { return $p.Value }
        }
        $null
    }
    $rep = [string](& $get @('AssetDetectedInReportName', 'ReportName')); $cat = [string](& $get @('Category'))
    $isPath = $rep.StartsWith('Attack_Paths') -or $cat.StartsWith('AttackPath') -or $cat -eq 'Attack Paths'
    $out = @{}
    foreach ($f in $Plan.Fields.Values) {
        $raw = $null
        if ($isPath -and $f.PathRow.Count) { $raw = & $get $f.PathRow; if ($null -ne $raw -and $null -eq (ConvertTo-SISummaryGroupingTier ([string]$raw))) { $raw = $null } }
        if ($null -eq $raw) { $raw = & $get $f.Row }
        $out[$f.Name] = ConvertTo-SISummaryGroupingValue -Field $f -Value $raw -Plan $Plan
    }
    $out
}

# ---------------------------------------------------------------------------------------------------------------------
#  THE ONE FUNCTION
# ---------------------------------------------------------------------------------------------------------------------

function Invoke-SISummaryGrouping {
    <#
    .SYNOPSIS  THE summary groupings of the Detailed findings (data-model\summary-groupings.locked.json) -- in the run, or as SQL.
    .DESCRIPTION
        -Rows / -Pager (Community; and any caller with the Detailed rows): the groupings computed in memory. A pager is any
        object with .Next() returning the next page of rows or $null (New-RARowPager) -- the rows are never held all at once.
        Returns one object per (grouping, counted, keys): GroupingId, Counted (False = every finding, True = without the
        exempted ones), Key1, Key2, Key3 ('' when unused), Label, then one property per measure (Findings, Assets, ...).
        -AsSql (Pro): the statement that computes exactly these rows for ONE stored collection (@CollectionId, plus @Hash: the
        definition's hash) from sidata.Finding and replaces the collection's sidata.SummaryGroup / SummaryGroupCounted /
        SummaryGroupState rows in ONE transaction. It answers the number of groups (every finding). One read of the
        collection's narrow finding columns (never DetailJson), no cap, no sample.
        -Grouping: only these grouping ids (default: every one).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Rows')]
    param(
        [Parameter(ParameterSetName = 'Rows')][AllowNull()][AllowEmptyCollection()][object[]]$Rows = @(),
        [Parameter(ParameterSetName = 'Pager', Mandatory)]$Pager,
        [Parameter(ParameterSetName = 'Sql', Mandatory)][switch]$AsSql,
        $Plan,
        [string[]]$Grouping
    )
    if (-not $Plan) { $Plan = Get-SISummaryGroupingPlan }
    $groupings = @($Plan.Groupings | Where-Object { -not $Grouping -or $Grouping -contains $_.Id })
    if ($AsSql) { return (Get-SISummaryGroupingSqlText -Plan $Plan -Groupings $groupings) }

    $acc = @{}                                     # "<grouping>|<counted>|k1|k2|k3" -> accumulator (case-insensitive, as SQL groups)
    $order = New-Object System.Collections.Generic.List[string]
    $sep = [string][char]31
    $add = {
        param($vals)
        $exempt = ([string]$vals[$Plan.Exempted]) -eq '1'
        foreach ($g in $groupings) {
          # a tokens key: the finding stands under each of its distinct tokens (none = not in this grouping), as the SQL's CROSS APPLY
          $ti = -1; for ($i = 0; $i -lt 3; $i++) { if ($g.Keys[$i] -and $Plan.Fields[$g.Keys[$i]].Kind -eq 'tokens') { $ti = $i } }
          $base = @(foreach ($kf in $g.Keys) { if ($kf -and $Plan.Fields[$kf].Kind -ne 'tokens') { [string]$vals[$kf] } else { '' } })
          $tuples = New-Object System.Collections.Generic.List[object]
          if ($ti -lt 0) { $tuples.Add($base) }
          else { foreach ($tok in @($vals[$g.Keys[$ti]] | Where-Object { $_ })) { $t = [object[]]$base.Clone(); $t[$ti] = [string]$tok; $tuples.Add($t) } }
          foreach ($k in $tuples) {
            foreach ($counted in @($false, $true)) {
                if ($counted -and $exempt) { continue }
                $id = $g.Id + $sep + $(if ($counted) { '1' } else { '0' }) + $sep + ($k -join $sep)
                $a = $acc[$id]
                if ($null -eq $a) {
                    $a = @{ G = $g.Id; C = $counted; K = $k; Label = $null; M = @{}; A = @{} }
                    foreach ($at in @($g.Attributes)) {
                        $a.A[$at.Id] = switch ($at.Op) {
                            'list' { , [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
                            'first' { @{ Rank = [int]::MaxValue; V = $null } }
                            default { $null }
                        }
                    }
                    foreach ($m in $Plan.Measures) {
                        # assigned directly, never through a pipeline (an empty set written to the pipeline would arrive as nothing)
                        if ($m.Op -eq 'count') { $a.M[$m.Id] = [long]0 }
                        elseif ($m.Op -eq 'countDistinct') { $a.M[$m.Id] = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
                        else { $a.M[$m.Id] = $null }
                    }
                    $acc[$id] = $a; $order.Add($id)
                }
                if ($g.LabelField) {
                    $lv = [string]$vals[$g.LabelField]
                    if ($null -eq $a.Label -or [string]::Compare($lv, $a.Label, [StringComparison]::OrdinalIgnoreCase) -gt 0) { $a.Label = $lv }
                }
                # the attributes: the empty text / no date never counts (the SQL's NULLIF)
                foreach ($at in @($g.Attributes)) {
                    $v = $vals[$at.Field]
                    if ($null -eq $v -or ([string]$v) -eq '') { continue }
                    $v = [string]$v
                    switch ($at.Op) {
                        'max' { if ($null -eq $a.A[$at.Id] -or [string]::Compare($v, $a.A[$at.Id], [StringComparison]::OrdinalIgnoreCase) -gt 0) { $a.A[$at.Id] = $v } }
                        'min' { if ($null -eq $a.A[$at.Id] -or [string]::Compare($v, $a.A[$at.Id], [StringComparison]::OrdinalIgnoreCase) -lt 0) { $a.A[$at.Id] = $v } }
                        'list' { [void]$a.A[$at.Id].Add($v) }
                        'first' {
                            $rank = 1000; for ($i = 0; $i -lt $at.Order.Count; $i++) { if ([string]::Equals($at.Order[$i], $v, [StringComparison]::OrdinalIgnoreCase)) { $rank = $i + 1; break } }
                            $cur = $a.A[$at.Id]
                            if ($rank -lt $cur.Rank -or ($rank -eq 1000 -and $cur.Rank -eq 1000 -and [string]::Compare($v, $cur.V, [StringComparison]::OrdinalIgnoreCase) -gt 0)) { $cur.Rank = $rank; $cur.V = $v }
                        }
                    }
                }
                foreach ($m in $Plan.Measures) {
                    if ($m.WhereField -and [string]$vals[$m.WhereField] -ne $m.WhereEquals) { continue }
                    switch ($m.Op) {
                        'count' { $a.M[$m.Id] = $a.M[$m.Id] + 1 }
                        'countDistinct' { $v = [string]$vals[$m.Field]; if ($v) { [void]$a.M[$m.Id].Add($v) } }
                        'max' { $v = $vals[$m.Field]; if ($null -ne $v -and ($null -eq $a.M[$m.Id] -or [double]$v -gt [double]$a.M[$m.Id])) { $a.M[$m.Id] = [double]$v } }
                        'min' { $v = $vals[$m.Field]; if ($null -ne $v -and ($null -eq $a.M[$m.Id] -or [double]$v -lt [double]$a.M[$m.Id])) { $a.M[$m.Id] = $v } }
                        'sum' { $v = $vals[$m.Field]; if ($null -ne $v) { $a.M[$m.Id] = $(if ($null -eq $a.M[$m.Id]) { [double]$v } else { [double]$a.M[$m.Id] + [double]$v }) } }
                    }
                }
            }
          }
        }
    }
    if ($PSCmdlet.ParameterSetName -eq 'Pager') {
        while ($null -ne ($page = $Pager.Next())) { foreach ($r in @($page)) { if ($null -ne $r) { & $add (Get-SISummaryGroupingRowValues -Row $r -Plan $Plan) } } }
    } else {
        foreach ($r in @($Rows)) { if ($null -ne $r) { & $add (Get-SISummaryGroupingRowValues -Row $r -Plan $Plan) } }
    }
    foreach ($id in $order) {
        $a = $acc[$id]
        $o = [ordered]@{ GroupingId = $a.G; Counted = [bool]$a.C; Key1 = $a.K[0]; Key2 = $a.K[1]; Key3 = $a.K[2]; Label = $a.Label }
        foreach ($m in $Plan.Measures) {
            $v = $a.M[$m.Id]
            $o[$m.Id] = switch ($m.Op) { 'count' { [long]$v } 'countDistinct' { [long]$v.Count } default { $v } }
        }
        $o['AttributesJson'] = Get-SISummaryGroupingAttributesJson -Grouping @($groupings | Where-Object { $_.Id -eq $a.G })[0] -Values $a.A
        [pscustomobject]$o
    }
}

function Get-SISummaryGroupingAttributesJson {
    <# PURE. One group's attributes as the compact JSON the SQL path stores (FOR JSON PATH, WITHOUT_ARRAY_WRAPPER): a property
       per attribute in the definition's order, an attribute without a value left out, a list = its first 'max' distinct values
       in ascending order joined with '; '. $null for a grouping without attributes (or none with a value). #>
    param($Grouping, [hashtable]$Values)
    if (-not $Grouping -or -not @($Grouping.Attributes).Count) { return $null }
    $o = [ordered]@{}
    foreach ($at in $Grouping.Attributes) {
        $v = $Values[$at.Id]
        switch ($at.Op) {
            'list' { $items = @($v | Sort-Object { $_ } -Culture ([Globalization.CultureInfo]::InvariantCulture) | Select-Object -First $at.Max); if ($items.Count) { $o[$at.Id] = $items -join '; ' } }
            'first' { if ($null -ne $v.V) { $o[$at.Id] = [string]$v.V } }
            default { if ($null -ne $v) { $o[$at.Id] = [string]$v } }
        }
    }
    if ($o.Count -eq 0) { return $null }
    [pscustomobject]$o | ConvertTo-Json -Compress
}

function Get-SISummaryGroupingLifecycleSql {
    <#
        PURE. #855 (owner 2026-10-21: "default filter is active, so it should be active only"): the Pro database's grouped rows
        are of the findings of ACTIVE CIs only (sidata.Finding.CiLifecycle; a finding no CI carries, or of a collection stored
        before the lifecycle was stamped, counts as active). The definition's keys (Key1-3) are the groupings' own, so the
        lifecycle is a filter of the rows, never a fourth key; the pages say so. The row path (Risk Analysis) is unchanged.
    #>
    " AND (f.CiLifecycle IS NULL OR f.CiLifecycle = N'active')"
}

function Get-SISummaryGroupingSqlText {
    <# The -AsSql statement (see Invoke-SISummaryGrouping). One pass over the collection into #f (the normalised fields), one
       aggregate per grouping into #s, then ONE transaction replaces the stored rows and the state row. #>
    param([Parameter(Mandatory)]$Plan, [Parameter(Mandatory)][object[]]$Groupings)
    $used = New-Object System.Collections.Generic.List[string]
    $use = { param($n) if ($n -and -not $used.Contains($n)) { $used.Add($n) } }
    & $use $Plan.Exempted
    foreach ($g in $Groupings) { foreach ($k in $g.Keys) { & $use $k }; & $use $g.LabelField; foreach ($at in @($g.Attributes)) { & $use $at.Field } }
    foreach ($m in $Plan.Measures) { & $use $m.Field; & $use $m.WhereField }
    $colType = {
        param($f)
        switch ($f.Kind) { 'text' { "nvarchar($($f.Max)) COLLATE DATABASE_DEFAULT NOT NULL" } 'tokens' { 'nvarchar(4000) COLLATE DATABASE_DEFAULT NOT NULL' } 'band' { 'nvarchar(64) COLLATE DATABASE_DEFAULT NOT NULL' } 'tierNumber' { 'tinyint NULL' } 'number' { 'float NULL' } 'date' { 'nvarchar(10) COLLATE DATABASE_DEFAULT NULL' } default { 'nvarchar(32) COLLATE DATABASE_DEFAULT NOT NULL' } }
    }
    $cols = @($used | ForEach-Object { 'x_' + $_ })
    $def = @($used | ForEach-Object { '{0} {1}' -f ('x_' + $_), (& $colType $Plan.Fields[$_]) }) -join ', '
    $sel = @($used | ForEach-Object { Get-SISummaryGroupingSqlValue -Field $Plan.Fields[$_] -Plan $Plan }) -join ",`r`n       "
    $mCols = @($Plan.Measures | ForEach-Object { $_.Id })
    $mDef = @($Plan.Measures | ForEach-Object { if ($_.Op -in 'count', 'countDistinct') { '{0} INT NOT NULL' -f $_.Id } elseif ($_.Field -and $Plan.Fields[$_.Field].Kind -eq 'tierNumber') { '{0} TINYINT NULL' -f $_.Id } else { '{0} FLOAT NULL' -f $_.Id } }) -join ', '
    $mExpr = foreach ($m in $Plan.Measures) {
        $cond = if ($m.WhereField) { "f.x_{0} = N'{1}'" -f $m.WhereField, $m.WhereEquals.Replace("'", "''") } else { '' }
        $val = if ($m.Field) { 'f.x_' + $m.Field } else { '' }
        switch ($m.Op) {
            'count' { if ($cond) { "SUM(CASE WHEN $cond THEN 1 ELSE 0 END)" } else { 'COUNT(*)' } }
            'countDistinct' { if ($cond) { "COUNT(DISTINCT CASE WHEN $cond THEN NULLIF($val, N'') END)" } else { "COUNT(DISTINCT NULLIF($val, N''))" } }
            'max' { if ($cond) { "MAX(CASE WHEN $cond THEN $val END)" } else { "MAX($val)" } }
            'min' { if ($cond) { "MIN(CASE WHEN $cond THEN $val END)" } else { "MIN($val)" } }
            'sum' { if ($cond) { "SUM(CASE WHEN $cond THEN $val END)" } else { "SUM($val)" } }
        }
    }
    $ins = foreach ($g in $Groupings) {
        # a tokens key (#812): each distinct trimmed token of the finding's list, cut to the field's 'max' -- the finding stands
        # under each (ConvertTo-SISummaryGroupingTokens is the row path's twin)
        $keyOf = {
            param($kf)
            if (-not $kf) { return "N''" }
            if ($Plan.Fields[$kf].Kind -eq 'tokens') { return 'tk.V' }
            'f.x_' + $kf
        }
        $k = @(foreach ($kf in $g.Keys) { & $keyOf $kf })
        $grp = @(@('v.Counted') + @($g.Keys | Where-Object { $_ } | ForEach-Object { & $keyOf $_ })) -join ', '
        $lab = if ($g.LabelField) { 'MAX(f.x_{0})' -f $g.LabelField } else { 'NULL' }
        $tok = @($g.Keys | Where-Object { $_ -and $Plan.Fields[$_].Kind -eq 'tokens' })
        $apply = ''
        if ($tok.Count) {
            $tf = $Plan.Fields[$tok[0]]
            $apply = "`r`nCROSS APPLY (SELECT DISTINCT LEFT(LTRIM(RTRIM(ts.[value])), $($tf.Max)) AS V FROM STRING_SPLIT(f.x_$($tf.Name), N';') AS ts WHERE LTRIM(RTRIM(ts.[value])) <> N'') AS tk"
        }
@"
INSERT #s (GroupingId, Counted, Key1, Key2, Key3, Label, $($mCols -join ', '))
SELECT N'$($g.Id)', v.Counted, $($k -join ', '), $lab,
       $($mExpr -join ', ')
FROM #f AS f CROSS APPLY (VALUES (CONVERT(bit, 0)), (CONVERT(bit, 1))) AS v(Counted)$apply
WHERE v.Counted = 0 OR f.x_$($Plan.Exempted) = N'0'
GROUP BY $grp;
"@
    }
    # the attributes (owner 2026-10-20): per grouping that has them, an index on its keys and ONE update of its rows -- each
    # row's attributes read from the findings of its keys (the counted variant without the exempted), as one JSON object
    $attr = foreach ($g in @($Groupings | Where-Object { @($_.Attributes).Count })) {
        $kf = @($g.Keys | Where-Object { $_ })
        $match = { param($alias) @(for ($i = 0; $i -lt $kf.Count; $i++) { '{0}.x_{1} = s.Key{2}' -f $alias, $kf[$i], ($i + 1) }) -join ' AND ' }
        $cnt = { param($alias) "(s.Counted = 0 OR {0}.x_{1} = N'0')" -f $alias, $Plan.Exempted }
        $items = foreach ($at in $g.Attributes) {
            $x = 'f.x_' + $at.Field
            $nz = "NULLIF({0}, N'')" -f $x
            switch ($at.Op) {
                'max' { 'MAX({0}) AS [{1}]' -f $nz, $at.Id }
                'min' { 'MIN({0}) AS [{1}]' -f $nz, $at.Id }
                'first' {
                    $rank = "CASE WHEN {0} IS NULL THEN NULL {1} ELSE 1000 END" -f $nz, ((@(for ($i = 0; $i -lt $at.Order.Count; $i++) { "WHEN {0} = N'{1}' THEN {2}" -f $x, $at.Order[$i].Replace("'", "''"), ($i + 1) })) -join ' ')
                    $back = @(for ($i = 0; $i -lt $at.Order.Count; $i++) { "WHEN {0} THEN N'{1}'" -f ($i + 1), $at.Order[$i].Replace("'", "''") }) -join ' '
                    'CASE MIN({0}) {1} WHEN 1000 THEN MAX({2}) END AS [{3}]' -f $rank, $back, $nz, $at.Id
                }
                'list' {
                    $f2 = 'f2.x_' + $at.Field
                    "(SELECT STRING_AGG(n.V, N'; ') WITHIN GROUP (ORDER BY n.V) FROM (SELECT DISTINCT TOP ({0}) {1} AS V FROM #f AS f2 WHERE {2} AND {3} AND {1} <> N'' ORDER BY V) AS n) AS [{4}]" -f $at.Max, $f2, (& $match 'f2'), (& $cnt 'f2'), $at.Id
                }
            }
        }
        $ix = 'IX_f_' + ($g.Id -replace '[^A-Za-z0-9]', '_')
        $inc = @(@($g.Attributes | ForEach-Object { 'x_' + $_.Field }) + @('x_' + $Plan.Exempted) | Select-Object -Unique | Where-Object { $kf -notcontains $_.Substring(2) })
@"
CREATE INDEX $ix ON #f ($((@($kf | ForEach-Object { 'x_' + $_ })) -join ', ')) INCLUDE ($($inc -join ', '));
UPDATE s SET AttributesJson = (SELECT $($items -join ",`r`n       ")
    FROM #f AS f WHERE $(& $match 'f') AND $(& $cnt 'f')
    FOR JSON PATH, WITHOUT_ARRAY_WRAPPER)
FROM #s AS s WHERE s.GroupingId = N'$($g.Id)';
"@
    }
    $list = "GroupingId, Key1, Key2, Key3, Label, $($mCols -join ', '), AttributesJson"
    # #812: the groupings these rows hold -- a page whose grouping is not among them says the collection is being prepared
    $gids = ';' + ((@($Groupings | ForEach-Object { $_.Id })) -join ';') + ';'
@"
SET NOCOUNT ON;
SET XACT_ABORT ON;
CREATE TABLE #f ($def);
INSERT #f ($($cols -join ', '))
SELECT $sel
FROM sidata.Finding AS f
WHERE f.CollectionId = @CollectionId$(Get-SISummaryGroupingLifecycleSql);
CREATE TABLE #s (GroupingId VARCHAR(40) COLLATE DATABASE_DEFAULT NOT NULL, Counted BIT NOT NULL, Key1 NVARCHAR(400) COLLATE DATABASE_DEFAULT NOT NULL,
                 Key2 NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, Key3 NVARCHAR(256) COLLATE DATABASE_DEFAULT NOT NULL, Label NVARCHAR(1000) NULL, $mDef, AttributesJson NVARCHAR(MAX) NULL);
$($ins -join "`r`n")
$($attr -join "`r`n")
DECLARE @groups INT = (SELECT COUNT(*) FROM #s WHERE Counted = 0);
DECLARE @counted INT = (SELECT COUNT(*) FROM #s WHERE Counted = 1);
DECLARE @findings BIGINT = (SELECT COUNT_BIG(*) FROM #f);
BEGIN TRAN;
DELETE FROM sidata.SummaryGroup WHERE CollectionId = @CollectionId;
INSERT sidata.SummaryGroup (CollectionId, $list)
SELECT @CollectionId, $list FROM #s WHERE Counted = 0;
DELETE FROM sidata.SummaryGroupCounted WHERE CollectionId = @CollectionId;
INSERT sidata.SummaryGroupCounted (CollectionId, $list)
SELECT @CollectionId, $list FROM #s WHERE Counted = 1;
DELETE FROM sidata.SummaryGroupState WHERE CollectionId = @CollectionId;
INSERT sidata.SummaryGroupState (CollectionId, BuiltAt, DefinitionHash, Groups, CountedGroups, Findings, Groupings) VALUES (@CollectionId, SYSUTCDATETIME(), @Hash, @groups, @counted, @findings, N'$($gids)');
COMMIT;
SELECT @groups;
"@
}

# ---------------------------------------------------------------------------------------------------------------------
#  READING THE RESULT (both editions): one grouping's rows, the most findings first
# ---------------------------------------------------------------------------------------------------------------------

function Select-SISummaryGroupingRows {
    <# PURE. The rows of one grouping and variant from a result of Invoke-SISummaryGrouping, sorted: most findings, then the key. #>
    param([AllowEmptyCollection()][object[]]$Result = @(), [Parameter(Mandatory)][string]$GroupingId, [bool]$Counted = $false, [int]$Top = 0)
    $r = @($Result | Where-Object { $_ -and $_.GroupingId -eq $GroupingId -and [bool]$_.Counted -eq $Counted } |
        Sort-Object -Property @{ Expression = { [long]$_.Findings }; Descending = $true }, @{ Expression = { [string]$_.Key1 } }, @{ Expression = { [string]$_.Key2 } }, @{ Expression = { [string]$_.Key3 } })
    if ($Top -gt 0) { return @($r | Select-Object -First $Top) }
    $r
}
