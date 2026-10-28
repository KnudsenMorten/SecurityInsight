#Requires -Version 5.1
<#
    THE SCOPE PREAMBLE -- Risk Analysis's ONE reader of the customer's scope (REQUIREMENTS #541).

    A report query states WHAT it finds over SI fields and SI factors. WHICH assets and findings are in scope, and WHICH
    risk factors fit the report, is not written in the query: the engine generates it per run from the data model and the
    customer's settings and exclusions, and feeds it to every query in two places:

      1. the scope block  //__SI_SCOPE_BEGIN__ ... //__SI_SCOPE_END__  at the top of the query -- one `let` per value
         the query may name: SI_ScopeTiers, SI_ExcludedAssets, SI_ExcludedAssetTags, SI_ExcludedConfigurationIds,
         SI_ExcludedCves, SI_CveMinAgeDays, SI_ExcludedIpRanges, SI_ReportFactors, the in-scope functions
         (SI_InScopeIp, SI_InScopeCve, SI_InScopeConfiguration) and, where the query names them, the data-model lists
         (SI_List_<id>) and criteria functions (SI_InList_<id>, e.g. SI_InList_unsupported_os). The YAML carries the
         shipped default copy, so a query pasted into the portal still runs; the engine replaces it.
      2. the CI blocks (_ciAsset / _ciLink, RA-CiKql.ps1) -- generated with the same values: _ciAsset keeps the CIs in
         scope only; _ciLink marks each CI si_in_scope_ and the report keeps `coalesce(si_in_scope_, true)` after its
         join (a finding with no CI has nothing to scope it by). Both carry si_rf_p / si_rf_c restricted to the report's
         factor set. The CI blocks inline their values (no reference to the scope block): the hybrid path runs a CI
         block alone in Log Analytics.

    And one final filter appended to the query: the excluded configuration ids (every report has a ConfigurationId).

    WHAT A REPORT GETS is data, not KQL: data-model/report-scope.locked.json (a data-model template -- Pro customers
    override a report through cfg.ItemOverride 'report-scope:<report>', Community in report-scope.custom.json):
      subjects  what the report is about: identity-user, service-principal, managed-identity, device, azure-resource,
                public-ip, and the finding kinds vulnerability / recommendation
      scope     which scope parts apply: disabled (setting | exclude | include), stale, tier, excludedAssets,
                assetTags, configurationIds, cves, ipRanges
      factors   include / exclude -- exceptions only; the factor set is DERIVED from the risk-factor catalog: an asset
                factor fits when the record types its providers map (or the classes of the fields its condition reads)
                meet the report's subjects; a finding factor fits the finding kinds it names (findingKinds). An identity
                report never gets a network or device factor; a customer factor reaches every report it fits.

    WHERE THE VALUES COME FROM (Get-RAScopeInputs, the one reader):
      disabled          SI_DisabledAssets_RiskAnalysis (Get-SIDisabledAssetPolicy, #533)
      stale             SI_ActiveStaleDays (the CI block's window; a CI no source saw within it is out of scope)
      tier              the report's CriticalityTierLevelScope
      excluded assets / asset tags / ip ranges   the Exclusions page (global + the report's own document)
      configuration ids / CVEs / CVE minimum age the report's exclusion document
      lists / criteria  data-model/lists.locked.json + the customer's overrides
    KQL is only ever built through the typed builders below (string, number, dynamic array, regex) -- never by
    concatenating free text.

    KQL rules: no // comment inside an argument list, no colon in a // comment, no `;` inside a let. PowerShell 5.1.
#>

$script:RAScopeBegin = '//__SI_SCOPE_BEGIN__'
$script:RAScopeEnd   = '//__SI_SCOPE_END__'
$script:RAScopePartNames = @('disabled', 'stale', 'tier', 'excludedAssets', 'assetTags', 'configurationIds', 'cves', 'ipRanges')
$script:RAScopeDisabledModes = @('setting', 'exclude', 'include')
# used when the template carries no subjects header (it always does; this keeps a broken overlay from breaking a run)
$script:RAScopeDefaultSubjects = [ordered]@{
    'identity-user'     = @{ class = 'identity'; recordTypes = @('user') }
    'service-principal' = @{ class = 'identity'; recordTypes = @('service_principal') }
    'managed-identity'  = @{ class = 'identity'; recordTypes = @('service_principal') }
    'device'            = @{ class = 'device'; recordTypes = @('device') }
    'azure-resource'    = @{ class = 'cloud_resource'; recordTypes = @('azure_resource') }
    'public-ip'         = @{ class = 'public_ip'; recordTypes = @('public_ip') }
    'vulnerability'     = @{ finding = 'vulnerability' }
    'recommendation'    = @{ finding = 'recommendation' }
}
$script:RATierLabels = @{ 'critical - tier 0' = 0; 'high - tier 1' = 1; 'medium - tier 2' = 2; 'low - tier 3' = 3 }

function Get-RAValues {
    <# PURE. A value as its items, one per pipeline object (Get-SIValueList returns ONE list object, which @() would not unroll). #>
    param($Value)
    foreach ($x in (Get-SIValueList $Value)) { $x }
}

# ================================================================================================================
# Typed KQL builders -- the ONLY way a value reaches a query
# ================================================================================================================

function ConvertTo-RAKqlString {
    <# PURE. A KQL string literal: "..." with \ and " escaped; line breaks and other control characters are refused. #>
    param([AllowNull()][AllowEmptyString()][string]$Value)
    $s = [string]$Value
    if ($s -match '[\x00-\x1F]') { throw ("a KQL value may not contain a line break or control character: '{0}'" -f ($s -replace '[\x00-\x1F]', '?')) }
    return ('"' + $s.Replace('\', '\\').Replace('"', '\"') + '"')
}

function ConvertTo-RAKqlNumber {
    <# PURE. A KQL number literal (invariant culture). Refuses anything that is not a finite number. #>
    param([AllowNull()]$Value, [switch]$Integer)
    $d = 0.0
    if ($null -eq $Value -or -not [double]::TryParse(([string]$Value).Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d) -or [double]::IsNaN($d) -or [double]::IsInfinity($d)) {
        throw ("'{0}' is not a number" -f $Value)
    }
    if ($Integer) { return ([string][long][Math]::Round($d)) }
    return $d.ToString('R', [System.Globalization.CultureInfo]::InvariantCulture)
}

function ConvertTo-RAKqlDynamic {
    <#
    .SYNOPSIS  PURE. dynamic([...]) from a list of values, each through its typed builder. Empty / blank values dropped;
               -Lower lower-cases strings (for the tolower()'d columns: tags, names); -Type string | number | int.
    #>
    param([AllowNull()][AllowEmptyCollection()][object[]]$Values, [ValidateSet('string', 'number', 'int')][string]$Type = 'string', [switch]$Lower)
    $out = New-Object System.Collections.Generic.List[string]
    $seen = @{}
    foreach ($v in @($Values)) {
        if ($null -eq $v -or [string]::IsNullOrWhiteSpace([string]$v)) { continue }
        $lit = switch ($Type) {
            'number' { ConvertTo-RAKqlNumber $v }
            'int'    { ConvertTo-RAKqlNumber $v -Integer }
            default  { $s = ([string]$v).Trim(); if ($Lower) { $s = $s.ToLowerInvariant() }; ConvertTo-RAKqlString $s }
        }
        if (-not $seen.ContainsKey($lit)) { $seen[$lit] = $true; $out.Add($lit) }
    }
    return ('dynamic([' + ($out.ToArray() -join ', ') + '])')
}

function ConvertTo-RAKqlRegex {
    <#
    .SYNOPSIS  PURE. A data-model pattern (.NET syntax, matched case-insensitively) as a KQL `matches regex` literal.
               KQL runs RE2: look-arounds and back-references are refused; `\ ` becomes a plain space; named groups are
               rewritten (?P<n>...); (?i) is added. The pattern must compile and may not hold a double quote.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Pattern)
    $p = [string]$Pattern
    if (-not $p) { throw 'an empty pattern' }
    if ($p.Contains('"')) { throw ("pattern '{0}': a double quote is not allowed" -f $p) }
    if ($p -match '[\x00-\x1F]') { throw 'a pattern may not contain a line break or control character' }
    if ($p -match '\(\?<?[=!]') { throw ("pattern '{0}': look-ahead / look-behind is not supported by Kusto" -f $p) }
    if ($p -match '\\[1-9]|\\k<') { throw ("pattern '{0}': back-references are not supported by Kusto" -f $p) }
    try { $null = New-Object System.Text.RegularExpressions.Regex($p, [System.Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromMilliseconds(200)) }
    catch { throw ("pattern '{0}' does not compile: {1}" -f $p, $_.Exception.Message) }
    $k = $p.Replace('\ ', ' ') -replace '\(\?<([A-Za-z_][A-Za-z0-9_]*)>', '(?P<$1>'
    if ($k -notmatch '^\(\?[a-z]*i[a-z]*\)') { $k = '(?i)' + $k }
    return ('@"' + $k + '"')
}

function Test-RAKqlIdentifier {
    <# PURE. Is the text a plain KQL column / parameter name? #>
    param([string]$Name)
    return ([string]$Name -cmatch '^[A-Za-z_][A-Za-z0-9_]{0,63}$')
}

# ================================================================================================================
# Criteria -- a data-model condition (a list entry, a factor's when) as KQL, and its validator
# ================================================================================================================

$script:RACriterionOps = [ordered]@{
    eq = 'scalar'; ne = 'scalar'; in = 'list'; not_in = 'list'; is_true = 'none'; is_false = 'none'; is_empty = 'none'; not_empty = 'none'
    gt = 'number'; gte = 'number'; lt = 'number'; lte = 'number'; contains = 'scalar'; contains_any = 'list'; matches = 'pattern'
    like = 'pattern'; older_than_days = 'days'; newer_than_days = 'days'; in_ranges = 'list'; in_list = 'listid'
}

function Get-RACriterionOps { , @($script:RACriterionOps.Keys) }

function Test-RAKqlCondition {
    <#
    .SYNOPSIS  PURE. The reasons a data-model condition cannot safely become Kusto (empty = it can) -- the KQL half of
               the criteria check: Test-SIRiskFactorCriteria (data model, C# FactorCriteria.cs) checks the factor's
               criteria block; this checks every leaf of the condition the criteria feed (closed op set, value shapes,
               RE2-safe patterns). A condition is a leaf { field, op, value } or a group { all: [...] } / { any: [...] }.
               in_list names a list: its entries are checked through -Lists.
    .PARAMETER Fields  the field catalog's fields (name -> type), when known: an unknown field is refused
    .OUTPUTS   string[]
    .NOTES     Value shapes per op: scalar (text or number, max 256 characters), list (1..500 scalars), number, days
               (0..36500), pattern (a pattern ConvertTo-RAKqlRegex accepts; like = wildcards * ?), none (no value).
    #>
    param([AllowNull()]$Criterion, [hashtable]$Fields, [hashtable]$Lists = @{}, [int]$Depth = 0)
    $why = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Criterion) { $why.Add('the criterion is empty'); return $why.ToArray() }
    if ($Depth -gt 6) { $why.Add('the criterion nests too deep (more than 6 groups)'); return $why.ToArray() }
    foreach ($g in 'all', 'any') {
        $has = ($Criterion -is [System.Collections.IDictionary] -and $Criterion.Contains($g)) -or ($Criterion.PSObject.Properties[$g])
        if ($has) {
            $items = @(Get-RAValues (Get-SIItemValue $Criterion $g))
            if ($items.Count -eq 0) { $why.Add("an empty '$g' group") }
            foreach ($c in $items) { foreach ($w in (Test-RAKqlCondition -Criterion $c -Fields $Fields -Lists $Lists -Depth ($Depth + 1))) { $why.Add($w) } }
            return $why.ToArray()
        }
    }
    $field = [string](Get-SIItemValue $Criterion 'field'); $op = [string](Get-SIItemValue $Criterion 'op'); $v = Get-SIItemValue $Criterion 'value'
    if (-not (Test-RAKqlIdentifier $field)) { $why.Add(("'{0}' is not a field name" -f $field)); return $why.ToArray() }
    if ($Fields -and -not $Fields.ContainsKey($field)) { $why.Add(("'{0}' is not in the field catalog" -f $field)) }
    if (-not $script:RACriterionOps.Contains($op)) { $why.Add(("'{0}' is not an operation ({1})" -f $op, ($script:RACriterionOps.Keys -join ', '))); return $why.ToArray() }
    $shape = $script:RACriterionOps[$op]
    $num = { param($x) $d = 0.0; [double]::TryParse(([string]$x).Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d) }
    switch ($shape) {
        'listid'  {
            $lid = [string]$v
            if ($lid -notmatch '^[a-z][a-z0-9_]{0,60}$') { $why.Add(("'{0}' is not a list id" -f $lid)); break }
            if ($Lists.Count -and -not $Lists.ContainsKey($lid)) { $why.Add(("'{0}' is not a list" -f $lid)); break }
            if ($Lists.ContainsKey($lid) -and [string](Get-SIItemValue $Lists[$lid] 'type') -eq 'conditions' -and $Depth -lt 6) {
                foreach ($e in @(Get-RAValues (Get-SIItemValue $Lists[$lid] 'entries'))) {
                    foreach ($w in (Test-RAKqlCondition -Criterion (Get-SIItemValue $e 'when') -Fields $Fields -Lists $Lists -Depth ($Depth + 1))) { $why.Add(("list {0}, entry '{1}': {2}" -f $lid, (Get-SIItemValue $e 'name'), $w)) }
                }
            }
        }
        'none'    { if ($null -ne $v -and [string]$v -ne '') { $why.Add(("'{0}' takes no value" -f $op)) } }
        'scalar'  { if ($null -eq $v -or [string]$v -eq '') { $why.Add(("'{0}' needs a value" -f $op)) } elseif (([string]$v).Length -gt 256) { $why.Add('a value is longer than 256 characters') } elseif ([string]$v -match '[\x00-\x1F]') { $why.Add('a value may not contain a line break') } }
        'list'    {
            if ($v -is [string] -and $v -match '^[a-z][a-z0-9_]*$') { break }     # a list id (in / in_ranges / contains_any)
            $items = @(Get-RAValues $v)
            if ($items.Count -eq 0) { $why.Add(("'{0}' needs at least one value" -f $op)) }
            if ($items.Count -gt 500) { $why.Add(("'{0}' takes at most 500 values" -f $op)) }
            foreach ($i in $items) { if ([string]$i -match '[\x00-\x1F]' -or ([string]$i).Length -gt 256) { $why.Add(("'{0}' is not a valid value" -f $i)) } }
            if ($op -eq 'in_ranges') { foreach ($i in $items) { if ([string]$i -notmatch '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$') { $why.Add(("'{0}' is not an IPv4 address or range (a.b.c.d/nn)" -f $i)) } } }
        }
        'number'  { if (-not (& $num $v)) { $why.Add(("'{0}' needs a number, got '{1}'" -f $op, $v)) } }
        'days'    { $d = 0.0; if (-not [double]::TryParse(([string]$v).Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d) -or $d -lt 0 -or $d -gt 36500) { $why.Add(("'{0}' needs a number of days from 0 to 36500, got '{1}'" -f $op, $v)) } }
        'pattern' {
            foreach ($pat in @(Get-RAValues $v)) {
                if ($op -eq 'like') { if ([string]$pat -match '["\x00-\x1F]' -or -not [string]$pat) { $why.Add(("'{0}' is not a valid wildcard pattern" -f $pat)) }; continue }
                try { $null = ConvertTo-RAKqlRegex -Pattern ([string]$pat) } catch { $why.Add($_.Exception.Message) }
            }
        }
    }
    if ($Fields -and $Fields.ContainsKey($field)) {
        $t = [string]$Fields[$field]
        if ($shape -in 'number' -and $t -notin 'int', 'real', 'string') { $why.Add(("'{0}' is a {1} field: '{2}' compares numbers" -f $field, $t, $op)) }
        if ($shape -eq 'days' -and $t -ne 'datetime') { $why.Add(("'{0}' is a {1} field: '{2}' needs a date" -f $field, $t, $op)) }
        if ($op -in 'is_true', 'is_false' -and $t -ne 'bool') { $why.Add(("'{0}' is a {1} field: '{2}' needs a yes/no field" -f $field, $t, $op)) }
    }
    return $why.ToArray()
}

function ConvertTo-RAKqlCondition {
    <#
    .SYNOPSIS  PURE. A data-model condition as one KQL boolean expression, through the typed builders only.
    .PARAMETER FieldMap  field -> the KQL expression that holds it (a parameter or column name, checked)
    .PARAMETER Lists     list id -> list (for in / contains_any / in_ranges naming a list)
    #>
    param([Parameter(Mandatory)]$When, [Parameter(Mandatory)][hashtable]$FieldMap, [hashtable]$Lists = @{})
    foreach ($g in 'all', 'any') {
        $has = ($When -is [System.Collections.IDictionary] -and $When.Contains($g)) -or ($When.PSObject.Properties[$g])
        if ($has) {
            $parts = @(@(Get-RAValues (Get-SIItemValue $When $g)) | ForEach-Object { '(' + (ConvertTo-RAKqlCondition -When $_ -FieldMap $FieldMap -Lists $Lists) + ')' })
            if ($parts.Count -eq 0) { if ($g -eq 'all') { return 'true' } else { return 'false' } }
            $j = ' and '; if ($g -eq 'any') { $j = ' or ' }
            return ($parts -join $j)
        }
    }
    $field = [string](Get-SIItemValue $When 'field'); $op = [string](Get-SIItemValue $When 'op'); $v = Get-SIItemValue $When 'value'
    if (-not $FieldMap.ContainsKey($field)) { throw ("the condition reads '{0}', which this KQL function does not receive" -f $field) }
    $x = [string]$FieldMap[$field]
    if (-not (Test-RAKqlIdentifier $x)) { throw ("'{0}' is not a column or parameter name" -f $x) }
    $vals = {
        param($val)
        if ($val -is [string] -and $Lists.ContainsKey($val)) { $l = $Lists[$val]; return @(Get-RAValues (Get-SIItemValue $l 'values')) }
        return @(Get-RAValues $val)
    }
    $isNum = { param($val) $d = 0.0; ($val -isnot [string] -or $val -match '^\s*-?\d') -and [double]::TryParse(([string]$val).Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d) }
    $numOf = ('todouble(extract(@"(-?\d+(\.\d+)?)", 1, tostring({0})))' -f $x)
    switch ($op) {
        'eq'        { if (& $isNum $v) { return ('{0} == {1}' -f $numOf, (ConvertTo-RAKqlNumber $v)) }; return ('tostring({0}) =~ {1}' -f $x, (ConvertTo-RAKqlString ([string]$v))) }
        'ne'        { if (& $isNum $v) { return ('{0} != {1}' -f $numOf, (ConvertTo-RAKqlNumber $v)) }; return ('isnotempty(tostring({0})) and tostring({0}) !~ {1}' -f $x, (ConvertTo-RAKqlString ([string]$v))) }
        'in'        { return ('tolower(tostring({0})) in ({1})' -f $x, (ConvertTo-RAKqlDynamic -Values (& $vals $v) -Lower)) }
        'not_in'    { return ('isnotempty(tostring({0})) and not(tolower(tostring({0})) in ({1}))' -f $x, (ConvertTo-RAKqlDynamic -Values (& $vals $v) -Lower)) }
        'is_true'   { return ('tobool({0}) == true' -f $x) }
        'is_false'  { return ('tobool({0}) == false' -f $x) }
        'is_empty'  { return ('isempty(tostring({0}))' -f $x) }
        'not_empty' { return ('isnotempty(tostring({0}))' -f $x) }
        'gt'        { return ('{0} > {1}' -f $numOf, (ConvertTo-RAKqlNumber $v)) }
        'gte'       { return ('{0} >= {1}' -f $numOf, (ConvertTo-RAKqlNumber $v)) }
        'lt'        { return ('{0} < {1}' -f $numOf, (ConvertTo-RAKqlNumber $v)) }
        'lte'       { return ('{0} <= {1}' -f $numOf, (ConvertTo-RAKqlNumber $v)) }
        'contains'  { return ('tostring({0}) contains {1}' -f $x, (ConvertTo-RAKqlString ([string]$v))) }
        'contains_any' { return ('tostring({0}) has_any ({1})' -f $x, (ConvertTo-RAKqlDynamic -Values (& $vals $v))) }
        'matches'   { return ('(' + ((@(Get-RAValues $v) | ForEach-Object { 'tostring({0}) matches regex {1}' -f $x, (ConvertTo-RAKqlRegex -Pattern ([string]$_)) }) -join ' or ') + ')') }
        'like'      {
            $rx = @(Get-RAValues $v) | ForEach-Object {
                $w = [string]$_
                if ($w -match '["\x00-\x1F]') { throw ("'{0}' is not a valid wildcard pattern" -f $w) }
                '^' + ([regex]::Escape($w) -replace '\\\*', '.*' -replace '\\\?', '.') + '$'
            }
            return ('(' + ((@($rx) | ForEach-Object { 'tostring({0}) matches regex {1}' -f $x, (ConvertTo-RAKqlRegex -Pattern $_) }) -join ' or ') + ')')
        }
        'older_than_days' { return ('todatetime({0}) < ago({1}d)' -f $x, (ConvertTo-RAKqlNumber $v -Integer)) }
        'newer_than_days' { return ('todatetime({0}) >= ago({1}d)' -f $x, (ConvertTo-RAKqlNumber $v -Integer)) }
        'in_ranges' { return ('ipv4_is_in_any_range(tostring({0}), {1})' -f $x, (ConvertTo-RAKqlDynamic -Values (& $vals $v))) }
        'in_list'   {
            $lid = [string]$v
            if (-not $Lists.ContainsKey($lid)) { throw ("the condition names list '{0}', which is not in the data model" -f $lid) }
            $l = $Lists[$lid]
            if ([string](Get-SIItemValue $l 'type') -eq 'conditions') {
                # a conditions list: any entry matches -- every entry reads its own fields, which must be in -FieldMap
                $es = @(@(Get-RAValues (Get-SIItemValue $l 'entries')) | ForEach-Object { '(' + (ConvertTo-RAKqlCondition -When (Get-SIItemValue $_ 'when') -FieldMap $FieldMap -Lists $Lists) + ')' })
                if ($es.Count -eq 0) { return 'false' }
                return ('(' + ($es -join ' or ') + ')')
            }
            if ([string](Get-SIItemValue $l 'type') -eq 'ranges') { return ('ipv4_is_in_any_range(tostring({0}), {1})' -f $x, (ConvertTo-RAKqlDynamic -Values @(Get-RAValues (Get-SIItemValue $l 'values')))) }
            return ('tolower(tostring({0})) in ({1})' -f $x, (ConvertTo-RAKqlDynamic -Values @(Get-RAValues (Get-SIItemValue $l 'values')) -Lower))
        }
        default     { throw ("operation '{0}' cannot be turned into Kusto" -f $op) }
    }
}

function Get-RAConditionFieldsDeep {
    <# PURE. Every field a condition reads, the entries of a conditions list it names (in_list) included. Sorted, unique. #>
    param($Condition, [hashtable]$Lists = @{}, [int]$Depth = 0)
    $set = New-Object System.Collections.Generic.SortedSet[string]
    if ($null -eq $Condition -or $Depth -gt 6) { return @() }
    foreach ($g in 'all', 'any') {
        $has = ($Condition -is [System.Collections.IDictionary] -and $Condition.Contains($g)) -or ($Condition.PSObject.Properties[$g])
        if ($has) {
            foreach ($c in @(Get-RAValues (Get-SIItemValue $Condition $g))) { foreach ($x in (Get-RAConditionFieldsDeep -Condition $c -Lists $Lists -Depth ($Depth + 1))) { [void]$set.Add($x) } }
            return @($set)
        }
    }
    $op = [string](Get-SIItemValue $Condition 'op'); $v = [string](Get-SIItemValue $Condition 'value')
    if ($op -eq 'in_list' -and $Lists.ContainsKey($v) -and [string](Get-SIItemValue $Lists[$v] 'type') -eq 'conditions') {
        foreach ($e in @(Get-RAValues (Get-SIItemValue $Lists[$v] 'entries'))) { foreach ($x in (Get-RAConditionFieldsDeep -Condition (Get-SIItemValue $e 'when') -Lists $Lists -Depth ($Depth + 1))) { [void]$set.Add($x) } }
    } else {
        $f = [string](Get-SIItemValue $Condition 'field'); if ($f) { [void]$set.Add($f) }
    }
    return @($set)
}

function Get-RAListKqlFunction {
    <#
    .SYNOPSIS  PURE. A data-model list as KQL: a conditions list as `let SI_InList_<id> = (<field>:string, ...) { <any entry> };`
               (parameters = the fields its entries read, sorted, named after the field); a values / ranges list as
               `let SI_List_<id> = dynamic([...]);`.
    #>
    param([Parameter(Mandatory)]$List, [hashtable]$Lists = @{})
    $id = [string](Get-SIItemValue $List 'id')
    if ($id -notmatch '^[a-z][a-z0-9_]{0,60}$') { throw ("'{0}' is not a list id" -f $id) }
    $type = [string](Get-SIItemValue $List 'type')
    if ($type -eq 'conditions') {
        $all = @{}; foreach ($k in $Lists.Keys) { $all[$k] = $Lists[$k] }; $all[$id] = $List
        $fields = @(Get-RAConditionFieldsDeep -Condition ([pscustomobject]@{ field = '_'; op = 'in_list'; value = $id }) -Lists $all)
        $map = @{}; foreach ($f in $fields) { $map[$f] = $f }
        $body = ConvertTo-RAKqlCondition -When ([pscustomobject]@{ field = '_'; op = 'in_list'; value = $id }) -FieldMap (@{ '_' = '_' } + $map) -Lists $all
        $sig = (@($fields) | ForEach-Object { '{0}:string' -f $_ }) -join ', '
        return ('let SI_InList_{0} = ({1}) {{ {2} }};' -f $id, $sig, $body)
    }
    $t = 'string'
    $vals = @(Get-RAValues (Get-SIItemValue $List 'values'))
    if ($type -eq 'values' -and $vals.Count -gt 0 -and @($vals | Where-Object { $_ -is [string] }).Count -eq 0) { $t = 'number' }
    return ('let SI_List_{0} = {1};' -f $id, (ConvertTo-RAKqlDynamic -Values $vals -Type $t))
}

function Get-RAFactorKqlFunction {
    <#
    .SYNOPSIS  PURE. A catalog factor's condition (its criteria applied -- the threshold / list the customer set lives in
               the condition) as `let SI_Factor_<id> = (<field>:string, ...) { ... };` -- for a report that must test a
               factor on an object that is not a CI (an attack path's intermediate node). A report on a CI reads the CI's
               evaluation (si_rf_p / si_rf_c) instead.
    #>
    param([Parameter(Mandatory)]$Factor, [hashtable]$Lists = @{})
    $id = [string]$Factor.id
    if ($id -notmatch '^[a-z][a-z0-9_]{0,60}$') { throw ("'{0}' is not a factor id" -f $id) }
    $fields = @(Get-RAConditionFieldsDeep -Condition $Factor.when -Lists $Lists)
    $map = @{}; foreach ($f in $fields) { $map[$f] = $f }
    $body = ConvertTo-RAKqlCondition -When $Factor.when -FieldMap $map -Lists $Lists
    $sig = (@($fields) | ForEach-Object { '{0}:string' -f $_ }) -join ', '
    return ('let SI_Factor_{0} = ({1}) {{ {2} }};' -f $id, $sig, $body)
}

function Test-SIRiskFactorCriteriaKql {
    <#
    .SYNOPSIS  The criteria check's Kusto half, for the web app's wizards and the template validation: a factor (with the
               criteria the customer set) is accepted only when (1) Test-SIRiskFactorCriteria accepts its criteria block,
               (2) every leaf of its condition can safely become Kusto (Test-RAKqlCondition), (3) it compiles through the
               typed builders and (4) -- with a workspace -- Kusto runs it: `print <every field> | where <condition> |
               take 0`, so a criterion that would make a report fail is refused before it is saved.
    .OUTPUTS   @{ Ok; Problems; Kql }. Without a workspace (or -NoRun) steps 1-3 only.
    #>
    param([Parameter(Mandatory)]$Factor, [hashtable]$Lists = @{}, [hashtable]$Fields, [string]$WorkspaceResourceId = [string]$global:SI_WorkspaceResourceId, [switch]$NoRun)
    $why = New-Object System.Collections.Generic.List[string]
    if (Get-Command -Name Test-SIRiskFactorCriteria -ErrorAction SilentlyContinue) { foreach ($w in (Test-SIRiskFactorCriteria -Factor $Factor -Lists $Lists)) { $why.Add([string]$w) } }
    foreach ($w in (Test-RAKqlCondition -Criterion $Factor.when -Fields $Fields -Lists $Lists)) { $why.Add(("risk-factors/{0}: {1}" -f $Factor.id, $w)) }
    if ($why.Count) { return @{ Ok = $false; Problems = $why.ToArray(); Kql = '' } }
    $fn = $null
    try { $fn = Get-RAFactorKqlFunction -Factor $Factor -Lists $Lists }
    catch { return @{ Ok = $false; Problems = @(("risk-factors/{0}: {1}" -f $Factor.id, $_.Exception.Message)); Kql = '' } }
    $condFields = @(Get-RAConditionFieldsDeep -Condition $Factor.when -Lists $Lists)
    $cols = (@($condFields) | ForEach-Object { '{0} = ""' -f $_ }) -join ', '
    if (-not $cols) { $cols = 'x_ = ""' }
    $call = ('SI_Factor_{0}({1})' -f $Factor.id, (@($condFields) -join ', '))
    $kql = "$fn`nprint $cols | where $call | take 0"
    if ($NoRun -or -not $WorkspaceResourceId -or -not (Get-Command -Name Invoke-LogAnalyticsKqlQuery -ErrorAction SilentlyContinue)) { return @{ Ok = $true; Problems = @(); Kql = $kql } }
    try { $null = Invoke-LogAnalyticsKqlQuery -WorkspaceResourceId $WorkspaceResourceId -Query $kql -TimeoutSec 60 }
    catch { return @{ Ok = $false; Problems = @(('risk-factors/{0}: Kusto refused the condition: {1}' -f $Factor.id, $_.Exception.Message)); Kql = $kql } }
    return @{ Ok = $true; Problems = @(); Kql = $kql }
}


# ================================================================================================================
# What a report gets -- report-scope.locked.json
# ================================================================================================================

function Get-RAReportScopeTemplate {
    <# The run's report-scope template (shipped + the customer's overrides), cached. $null when it cannot be read. #>
    if ($null -ne $global:RA_ReportScopeTemplate) { return $global:RA_ReportScopeTemplate }
    $doc = $null
    try {
        if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) {
            . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model\SI-DataModelTemplates.ps1')
        }
        $doc = (Get-SIDataModelTemplate -Name 'report-scope' -OverlayRoot $global:SI_DataModelOverlayRoot).Document
    } catch {
        # a Pro run folder materialised before the template was published: the shipped copy (no customer override yet)
        try { $doc = (Get-SIDataModelTemplate -Name 'report-scope' -Root (Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))) 'data-model')).Document }
        catch { Write-Warning ('report scope: the template could not be read ({0}) -- every report gets the default scope.' -f $_.Exception.Message) }
    }
    $global:RA_ReportScopeTemplate = $doc
    return $doc
}

function Get-RAReportScope {
    <#
    .SYNOPSIS  PURE (given -Template). One report's scope spec: @{ Report; Subjects; Scope (part -> value); Include; Exclude; Known }.
               A report the template does not list (a customer's own report) gets the default: every part that cannot
               hide a finding the report asks for (disabled by the setting, excluded assets, asset tags, configuration
               ids), no tier / stale / CVE / address part, every asset factor.
    #>
    param([Parameter(Mandatory)][string]$ReportName, $Template)
    $item = $null
    if ($Template) { $item = @(@($Template.reports) | Where-Object { $_ -and [string]$_.id -eq $ReportName }) | Select-Object -First 1 }
    $scope = [ordered]@{ disabled = 'setting'; stale = $false; tier = $false; excludedAssets = $true; assetTags = $true; configurationIds = $true; cves = $false; ipRanges = $false }
    $spec = @{ Report = $ReportName; Subjects = @(); Scope = $scope; Include = @(); Exclude = @(); Known = ($null -ne $item) }
    if ($null -eq $item) { return $spec }
    $spec.Subjects = @(@(Get-RAValues (Get-SIItemValue $item 'subjects')) | ForEach-Object { [string]$_ })
    $s = Get-SIItemValue $item 'scope'
    if ($s) {
        foreach ($n in $script:RAScopePartNames) {
            $v = Get-SIItemValue $s $n
            if ($null -eq $v) { continue }
            if ($n -eq 'disabled') { if ($script:RAScopeDisabledModes -contains [string]$v) { $scope[$n] = [string]$v } }
            else { $b = ConvertTo-SIBoolOrNull $v; if ($null -ne $b) { $scope[$n] = [bool]$b } }
        }
    }
    $f = Get-SIItemValue $item 'factors'
    if ($f) {
        $spec.Include = @(@(Get-RAValues (Get-SIItemValue $f 'include')) | ForEach-Object { [string]$_ })
        $spec.Exclude = @(@(Get-RAValues (Get-SIItemValue $f 'exclude')) | ForEach-Object { [string]$_ })
    }
    return $spec
}

function Test-RAReportScopeTemplate {
    <# PURE. Problems in a report-scope document (empty = valid): unknown subjects, parts, disabled modes, factor ids. #>
    param([Parameter(Mandatory)]$Template, [object[]]$Factors = @())
    $p = New-Object System.Collections.Generic.List[string]
    $subj = Get-RASubjectDefinitions -Template $Template
    $ids = @{}; foreach ($f in @($Factors)) { if ($f -and $f.id) { $ids[[string]$f.id] = $true } }
    $seen = @{}
    foreach ($r in @($Template.reports)) {
        $id = [string]$r.id
        if (-not $id) { $p.Add('report-scope: an entry without an id'); continue }
        if ($seen.ContainsKey($id)) { $p.Add("report-scope: '$id' is listed twice") }
        $seen[$id] = $true
        foreach ($s in @(Get-RAValues (Get-SIItemValue $r 'subjects'))) { if (-not $subj.Contains([string]$s)) { $p.Add("report-scope/${id}: unknown subject '$s'") } }
        $sc = Get-SIItemValue $r 'scope'
        if ($sc) {
            foreach ($pp in $sc.PSObject.Properties) {
                if ($pp.Name.StartsWith('$')) { continue }
                if ($script:RAScopePartNames -notcontains $pp.Name) { $p.Add("report-scope/${id}: unknown scope part '$($pp.Name)'") }
                elseif ($pp.Name -eq 'disabled' -and $script:RAScopeDisabledModes -notcontains [string]$pp.Value) { $p.Add("report-scope/${id}: disabled must be setting, exclude or include") }
            }
        }
        $fa = Get-SIItemValue $r 'factors'
        if ($fa -and $ids.Count) {
            foreach ($x in @(Get-RAValues (Get-SIItemValue $fa 'include')) + @(Get-RAValues (Get-SIItemValue $fa 'exclude'))) { if ($x -and -not $ids.ContainsKey([string]$x)) { $p.Add("report-scope/${id}: unknown factor '$x'") } }
        }
    }
    return $p.ToArray()
}

function Get-RASubjectDefinitions {
    <# PURE. subject -> @{ class; recordTypes; finding } from the template's header (or the defaults). #>
    param($Template)
    $out = [ordered]@{}
    $h = $null; if ($Template) { $h = Get-SIItemValue $Template 'subjects' }
    if ($h) {
        foreach ($pp in $h.PSObject.Properties) {
            if ($pp.Name.StartsWith('$')) { continue }
            $out[$pp.Name] = @{ class = [string](Get-SIItemValue $pp.Value 'class'); recordTypes = @(Get-RAValues (Get-SIItemValue $pp.Value 'recordTypes')); finding = [string](Get-SIItemValue $pp.Value 'finding') }
        }
    }
    if ($out.Count -eq 0) { foreach ($k in $script:RAScopeDefaultSubjects.Keys) { $d = $script:RAScopeDefaultSubjects[$k]; $out[$k] = @{ class = [string]$d.class; recordTypes = @($d.recordTypes); finding = [string]$d.finding } } }
    return $out
}

function Get-RAFactorRecordTypes {
    <# PURE. The record types a factor's providers map (its providers block), and the classes of the fields its condition reads. #>
    param([Parameter(Mandatory)]$Factor, [hashtable]$FieldClasses = @{})
    $rts = New-Object System.Collections.Generic.HashSet[string]
    $cls = New-Object System.Collections.Generic.HashSet[string]
    $prov = Get-SIItemValue $Factor 'providers'
    if ($prov) {
        foreach ($pp in $prov.PSObject.Properties) {
            foreach ($link in @($pp.Value)) { foreach ($rt in @(Get-RAValues (Get-SIItemValue $link 'recordTypes'))) { if ($rt) { [void]$rts.Add([string]$rt) } } }
        }
    }
    $when = Get-SIItemValue $Factor 'when'
    $perField = New-Object System.Collections.Generic.List[object]
    if ($when) {
        foreach ($fn in (Get-SIConditionFields $when)) {
            if (-not $FieldClasses.ContainsKey([string]$fn)) { continue }
            $fcl = @(@($FieldClasses[[string]$fn]) | Where-Object { $_ } | ForEach-Object { [string]$_ })
            foreach ($c in $fcl) { [void]$cls.Add($c) }
            if ($fcl.Count) { $perField.Add($fcl) }
        }
    }
    return @{ RecordTypes = @($rts); Classes = @($cls); FieldClasses = $perField.ToArray() }
}

function Get-RAReportFactorSet {
    <#
    .SYNOPSIS  PURE. The risk-factor ids that fit one report -- DERIVED from the catalog and the report's subjects, then
               the report's include / exclude exceptions. Disabled factors (#559 state) are in no set.
      asset factor    fits when a record type its providers map is one of the subjects' record types; a CMDB factor
                      (cmdb_ci) fits every asset subject; a factor without provider record types fits when a field its
                      condition reads belongs to a subject's class (a customer factor with no providers block)
      finding factor  fits when it names one of the report's finding kinds (findingKinds) -- and, when it names
                      assetClasses, the report is about one of them; report_scoped always fits
      both            every field the factor's condition reads must exist on one of the report's classes
    .PARAMETER FieldClasses  field name -> its catalog classes (for factors without providers)
    #>
    param([Parameter(Mandatory)][hashtable]$Spec, [AllowEmptyCollection()][object[]]$Factors = @(), $Subjects, [hashtable]$FieldClasses = @{})
    if (-not $Subjects) { $Subjects = Get-RASubjectDefinitions -Template $null }
    $rtWanted = New-Object System.Collections.Generic.HashSet[string]
    $clsWanted = New-Object System.Collections.Generic.HashSet[string]
    $kinds = New-Object System.Collections.Generic.HashSet[string]
    $subs = @($Spec.Subjects)
    foreach ($s in $subs) {
        if (-not $Subjects.Contains($s)) { continue }
        $d = $Subjects[$s]
        foreach ($rt in @($d.recordTypes)) { if ($rt) { [void]$rtWanted.Add([string]$rt) } }
        if ($d.class) { [void]$clsWanted.Add([string]$d.class) }
        if ($d.finding) { [void]$kinds.Add([string]$d.finding) }
    }
    $anyAsset = ($rtWanted.Count -gt 0 -or $clsWanted.Count -gt 0)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($f in @($Factors)) {
        if ($null -eq $f -or -not $f.id) { continue }
        $id = [string]$f.id
        # #559: a disabled factor is in no report (a built-in one is never disabled); pre-v2 stage not_used likewise
        if (Get-Command -Name Test-SIRiskFactorEnabled -ErrorAction SilentlyContinue) { if (-not (Test-SIRiskFactorEnabled $f)) { continue } }
        elseif ([string](Get-SIItemValue $f 'state') -eq 'disabled' -or [string](Get-SIItemValue $f 'stage') -eq 'not_used') { continue }
        $fit = $false
        if ([string]$f.appliesTo -eq 'finding') {
            if ($id -eq 'report_scoped') { $fit = $true }
            else { foreach ($k in @(Get-RAValues (Get-SIItemValue $f 'findingKinds'))) { if ($kinds.Contains([string]$k)) { $fit = $true } } }
            # a finding factor about one kind of asset (assetClasses, e.g. a public IP's CVSS) fits only reports on that asset
            $ac = @(Get-RAValues (Get-SIItemValue $f 'assetClasses'))
            if ($fit -and $ac.Count) { if (-not @($ac | Where-Object { $clsWanted.Contains([string]$_) }).Count) { $fit = $false } }
        } elseif ($subs.Count -eq 0) {
            $fit = $true                                   # a report without subjects (a customer's own): every asset factor
        } elseif ($anyAsset) {
            $r = Get-RAFactorRecordTypes -Factor $f -FieldClasses $FieldClasses
            foreach ($rt in $r.RecordTypes) { if ($rtWanted.Contains($rt) -or $rt -eq 'cmdb_ci') { $fit = $true } }
            if (-not $fit -and @($r.RecordTypes).Count -eq 0) { foreach ($c in $r.Classes) { if ($clsWanted.Contains($c)) { $fit = $true } } }
            # every field the condition reads must exist on one of the report's classes: old_account reads si_identity_type,
            # so it never reaches a device report although Active Directory maps a computer's creation date
            if ($fit -and $clsWanted.Count) { foreach ($fcl in @($r.FieldClasses)) { if (-not @(@($fcl) | Where-Object { $clsWanted.Contains([string]$_) }).Count) { $fit = $false } } }
        }
        if ($fit) { $out.Add($id) }
    }
    foreach ($i in @($Spec.Include)) { if ($i -and -not $out.Contains([string]$i)) { $out.Add([string]$i) } }
    foreach ($e in @($Spec.Exclude)) { if ($e) { [void]$out.Remove([string]$e) } }
    return $out.ToArray()
}

# ================================================================================================================
# The inputs (the ONE reader) and the generated KQL
# ================================================================================================================

function Get-RAScopeTiers {
    <# PURE. CriticalityTierLevelScope labels -> tier numbers (0..3). Empty = every tier. #>
    param([AllowEmptyCollection()][object[]]$Labels = @())
    $t = New-Object System.Collections.Generic.List[int]
    foreach ($l in @($Labels)) { $k = ([string]$l).Trim().ToLowerInvariant(); if ($script:RATierLabels.ContainsKey($k) -and -not $t.Contains($script:RATierLabels[$k])) { $t.Add($script:RATierLabels[$k]) } }
    if ($t.Count -eq 0) { return @(0, 1, 2, 3) }
    return @($t | Sort-Object)
}

function Get-RAScopeDefaults {
    <# PURE. The shipped values (no setting, no exclusion): what the YAML copy carries so a pasted query runs. #>
    param([hashtable]$Spec, [AllowEmptyCollection()][object[]]$TierLabels = @(), [AllowEmptyCollection()][string[]]$FactorSet = @(), [int]$StaleDays = 30)
    @{
        IncludeDisabled = $false; StaleDays = $StaleDays; Tiers = @(Get-RAScopeTiers $TierLabels)
        ExcludedAssets = @(); ExcludedAssetTags = @(); ExcludedConfigurationIds = @(); ExcludedCves = @(); CveMinAgeDays = 0; ExcludedIpRanges = @()
        FactorSet = @($FactorSet); Lists = @{}; Factors = @{}; FactorNames = @{}
    }
}

function Get-RAFactorNameMap {
    <#
    .SYNOPSIS  PURE. factor id -> the catalog's SHORT name (#558 / #559, owner 2026-10-10: "it is to long words when you use
               them in excel or pdf files" -- reports show the short name, e.g. InternetExposed; the GUI shows the
               description; a customer renames a factor once, in the catalog -- the ids stay in the technical column
               RiskFactorIds). Only the factors of -FactorSet when given; a factor without a short name shows its name,
               else its id.
    #>
    param([AllowEmptyCollection()][object[]]$Factors = @(), [AllowEmptyCollection()][string[]]$FactorSet = @())
    $m = @{}
    foreach ($f in @($Factors)) {
        if ($null -eq $f -or -not $f.id) { continue }
        $id = [string]$f.id
        if (@($FactorSet).Count -gt 0 -and $FactorSet -notcontains $id) { continue }
        $n = ([string](Get-SIItemValue $f 'shortName')).Trim()
        if (-not $n) { $n = ([string](Get-SIItemValue $f 'name')).Trim() }
        if ($n) { $m[$id] = $n } else { $m[$id] = $id }
    }
    return $m
}

function Get-RAScopeInputs {
    <#
    .SYNOPSIS  The ONE reader of everything that decides a report's scope (see the header). Returns the values hashtable
               New-RAScopeBlock / Get-RACiKqlBlock take. Pro reads the exclusions from its settings database through the
               same Get-ExcludedListForReport path (layer 5b materialises them), Community from its files.
    #>
    param([Parameter(Mandatory)][string]$ReportName, [Parameter(Mandatory)][hashtable]$Spec, [AllowEmptyCollection()][object[]]$TierLabels = @(), $Policy)
    $stale = 30; if (Get-Command -Name Get-RAStaleDays -ErrorAction SilentlyContinue) { $stale = Get-RAStaleDays }
    $v = Get-RAScopeDefaults -Spec $Spec -TierLabels $TierLabels -StaleDays $stale
    if (-not $Policy -and (Get-Command -Name Get-SIDisabledAssetPolicy -ErrorAction SilentlyContinue)) { $Policy = Get-SIDisabledAssetPolicy }
    if ($Policy) { $v.IncludeDisabled = [bool]$Policy.Effective.RiskAnalysis }
    $list = {
        param([string[]]$props, [string]$token)
        if (-not (Get-Command -Name Get-ExcludedListForReport -ErrorAction SilentlyContinue)) { return @() }
        @(Get-ExcludedListForReport -ReportName $ReportName -PropertyNames $props -Token $token)
    }
    $v.ExcludedAssets           = @(& $list @('ExcludedAssets', 'Assets') '__EXCLUDED_ASSETS__')
    $v.ExcludedAssetTags        = @(& $list @('ExcludedAssetTags', 'AssetTags', 'Tags') '__EXCLUDED_ASSET_TAGS__')
    $v.ExcludedConfigurationIds = @(& $list @('ExcludedConfigurationIds', 'ConfigurationIds', 'ConfigIds') '__EXCLUDED_CONFIGURATION_IDS__')
    $v.ExcludedCves             = @(& $list @('ExcludedCves', 'Cves', 'Excluded') '__EXCLUDED_CVES__')
    $v.ExcludedIpRanges         = @(@(& $list @('ExcludedIpRanges', 'IpRanges') '__EXCLUDED_IP_RANGES__') | Where-Object { [string]$_ -match '^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$' })
    if (Get-Command -Name Get-ScalarValueForReport -ErrorAction SilentlyContinue) {
        $age = 0; [void][int]::TryParse([string](Get-ScalarValueForReport -ReportName $ReportName -PropertyNames @('CveMinAgeDays', 'CveMinDays') -Default 0), [ref]$age)
        if ($age -gt 0 -and $age -le 3650) { $v.CveMinAgeDays = $age }
    }
    # the factor set and the lists come from the data model (with the customer's overrides)
    try {
        if (-not (Get-Command -Name Get-SIDataModel -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model\SI-DataModelTemplates.ps1') }
        if ($null -eq $global:RA_ScopeModel) { $global:RA_ScopeModel = Get-SIDataModel -OverlayRoot $global:SI_DataModelOverlayRoot }
        $m = $global:RA_ScopeModel
        $fc = @{}; foreach ($f in @($m['field-catalog'].fields)) { $fc[[string]$f.name] = @($f.classes) }
        $v.FactorSet = @(Get-RAReportFactorSet -Spec $Spec -Factors @($m['risk-factors'].factors) -Subjects (Get-RASubjectDefinitions -Template (Get-RAReportScopeTemplate)) -FieldClasses $fc)
        foreach ($l in @($m['lists'].lists)) { if ($l -and $l.id) { $v.Lists[[string]$l.id] = $l } }
        foreach ($f in @($m['risk-factors'].factors)) { if ($f -and $f.id) { $v.Factors[[string]$f.id] = $f } }
        $v.FactorNames = Get-RAFactorNameMap -Factors @($m['risk-factors'].factors) -FactorSet @($v.FactorSet)
    } catch { Write-Verbose ('report scope: the data model could not be read ({0}) -- every factor stays in.' -f $_.Exception.Message) }
    return $v
}

function Get-RAScopeActive {
    <# PURE. The values with the parts the report does NOT declare neutralised (what reaches its KQL). #>
    param([Parameter(Mandatory)][hashtable]$Spec, [Parameter(Mandatory)][hashtable]$Values)
    $s = $Spec.Scope
    $a = @{}
    foreach ($k in $Values.Keys) { $a[$k] = $Values[$k] }
    # the disabled part: ONE decision, through Resolve-SIDisabledAssetsRaFilter (SI-DisabledAssets.ps1) when it is loaded
    $mode = [string]$s.disabled; if ($script:RAScopeDisabledModes -notcontains $mode) { $mode = 'setting' }
    $a.DisabledPredicate = $null
    if (Get-Command -Name Resolve-SIDisabledAssetsRaFilter -ErrorAction SilentlyContinue) {
        $settingInclude = $null; if ($mode -eq 'setting') { $settingInclude = [bool]$Values.IncludeDisabled }
        $d = Resolve-SIDisabledAssetsRaFilter -Mode $mode -Include $settingInclude
        $a.IncludeDisabled = [bool]$d.Include; $a.DisabledPredicate = [string]$d.Predicate
    } else {
        switch ($mode) { 'include' { $a.IncludeDisabled = $true } 'exclude' { $a.IncludeDisabled = $false } }
    }
    # the values stay (a report may name a list for its own question -- the excluded-assets report lists the CIs the
    # exclusion tags match); WHERE they cut is the report's declared parts
    # the shipped exclusion tags (data-model list excluded_asset_tags, the customer may override it) + the Exclusions page
    if ($Values.Lists -and $Values.Lists.ContainsKey('excluded_asset_tags')) {
        $tags = New-Object System.Collections.Generic.List[string]
        foreach ($x in @(@(Get-RAValues (Get-SIItemValue $Values.Lists['excluded_asset_tags'] 'values')) + @($Values.ExcludedAssetTags))) { if ($x -and -not $tags.Contains([string]$x)) { $tags.Add([string]$x) } }
        $a.ExcludedAssetTags = $tags.ToArray()
    }
    $a.ApplyStale = [bool]$s.stale
    $a.Apply = @{ tier = [bool]$s.tier; excludedAssets = [bool]$s.excludedAssets; assetTags = [bool]$s.assetTags; configurationIds = [bool]$s.configurationIds; cves = [bool]$s.cves; ipRanges = [bool]$s.ipRanges }
    if (-not $s.cves) { $a.CveMinAgeDays = 0; $a.ExcludedCves = @() }
    return $a
}

function Get-RAScopeCiPredicate {
    <#
    .SYNOPSIS  PURE. The in-scope test of one CI row (the CI blocks' columns), with every value inlined -- the CI blocks
               run alone in Log Analytics on the hybrid path, so they cannot name the scope block's lets.
    #>
    param([Parameter(Mandatory)][hashtable]$Active)
    $parts = New-Object System.Collections.Generic.List[string]
    if ($Active.DisabledPredicate) { if ($Active.DisabledPredicate -ne 'true') { $parts.Add([string]$Active.DisabledPredicate) } }
    elseif (-not $Active.IncludeDisabled) { $parts.Add('coalesce(tobool(column_ifexists("si_account_enabled", bool(null))), true)') }
    if ($Active.ApplyStale) { $parts.Add('not(si_stale_)') }
    $tiers = @($Active.Tiers)
    if ($Active.Apply -and -not $Active.Apply.tier) { $tiers = @() }
    if ($tiers.Count -gt 0 -and $tiers.Count -lt 4) { $parts.Add(('(isnull(toint(column_ifexists("si_tier", int(null)))) or toint(column_ifexists("si_tier", int(null))) in ({0}))' -f ((ConvertTo-RAKqlDynamic -Values $tiers -Type int) -replace '^dynamic\(\[|\]\)$', ''))) }
    $on = { param($p) (-not $Active.Apply) -or [bool]$Active.Apply[$p] }
    if ((& $on 'excludedAssets') -and @($Active.ExcludedAssets).Count) { $parts.Add(('not(tolower(_ciId) in ({0}) or tolower(tostring(si_asset_name)) in ({0}))' -f (ConvertTo-RAKqlDynamic -Values @($Active.ExcludedAssets) -Lower))) }
    if ((& $on 'assetTags') -and @($Active.ExcludedAssetTags).Count) { $parts.Add(('not(si_tags_ has_any ({0}))' -f (ConvertTo-RAKqlDynamic -Values @($Active.ExcludedAssetTags) -Lower))) }
    # #690 (35) an address Shodan scans is a public IP whatever CI owns it -- an Azure public IP resource is a cloud_resource
    # CI with a Shodan link -- so the excluded ranges apply to it as well
    if ((& $on 'ipRanges') -and @($Active.ExcludedIpRanges).Count) { $parts.Add(('not((tostring(si_class) == "public_ip" or isnotempty(tostring(column_ifexists("si_link_shodan", "")))) and ipv4_is_in_any_range(tostring(column_ifexists("si_ip_address", "")), {0}))' -f (ConvertTo-RAKqlDynamic -Values @($Active.ExcludedIpRanges)))) }
    if ($parts.Count -eq 0) { return 'true' }
    return ($parts.ToArray() -join ' and ')
}

function New-RAScopeBlock {
    <#
    .SYNOPSIS  PURE. The scope block (markers included) for one report from its active values. -Query: the lists and
               criteria functions the query names (SI_List_<id> / SI_InList_<id>) are added.
    #>
    param([Parameter(Mandatory)][hashtable]$Active, [AllowEmptyString()][string]$Query = '')
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add($script:RAScopeBegin)
    $L.Add('// the report scope, generated by the engine from the data model and the customer settings (Exclusions, disabled assets, stale days, tier scope)')
    $L.Add(('let SI_ScopeTiers = {0};' -f (ConvertTo-RAKqlDynamic -Values @($Active.Tiers) -Type int)))
    $L.Add(('let SI_ScopeIncludeDisabled = {0};' -f $(if ($Active.IncludeDisabled) { 'true' } else { 'false' })))
    $L.Add(('let SI_ExcludedAssets = {0};' -f (ConvertTo-RAKqlDynamic -Values @($Active.ExcludedAssets) -Lower)))
    $L.Add(('let SI_ExcludedAssetTags = {0};' -f (ConvertTo-RAKqlDynamic -Values @($Active.ExcludedAssetTags) -Lower)))
    $L.Add(('let SI_ExcludedConfigurationIds = {0};' -f (ConvertTo-RAKqlDynamic -Values @($Active.ExcludedConfigurationIds))))
    $L.Add(('let SI_ExcludedCves = {0};' -f (ConvertTo-RAKqlDynamic -Values @(@($Active.ExcludedCves) | ForEach-Object { ([string]$_).ToUpperInvariant() }))))
    $L.Add(('let SI_CveMinAgeDays = {0};' -f (ConvertTo-RAKqlNumber ([int]$Active.CveMinAgeDays) -Integer)))
    $L.Add(('let SI_ExcludedIpRanges = {0};' -f (ConvertTo-RAKqlDynamic -Values @($Active.ExcludedIpRanges))))
    $L.Add(('let SI_ReportFactors = {0};' -f (ConvertTo-RAKqlDynamic -Values @($Active.FactorSet))))
    $nameMap = @{}; if ($Active.FactorNames) { $nameMap = $Active.FactorNames }
    $L.Add(('let SI_FactorNames = {0};' -f (ConvertTo-RACiNameBag -FactorNames $nameMap -FactorSet @($Active.FactorSet))))
    $L.Add('let SI_InScopeIp = (ip:string) { array_length(SI_ExcludedIpRanges) == 0 or not(ipv4_is_in_any_range(ip, SI_ExcludedIpRanges)) };')
    $L.Add('let SI_InScopeCve = (cve:string, lastModified:datetime) { not(toupper(cve) in (SI_ExcludedCves)) and (SI_CveMinAgeDays == 0 or isnull(lastModified) or lastModified < ago(SI_CveMinAgeDays * 1d)) };')
    $L.Add('let SI_InScopeConfiguration = (configurationId:string) { not(configurationId in (SI_ExcludedConfigurationIds)) };')
    $lists = @{}; if ($Active.Lists) { $lists = $Active.Lists }
    if ($Query) {
        $named = New-Object System.Collections.Generic.SortedSet[string]
        foreach ($m in [regex]::Matches($Query, '\bSI_(?:In)?List_([a-z][a-z0-9_]*)\b')) { [void]$named.Add($m.Groups[1].Value) }
        foreach ($id in $named) {
            if ($lists.ContainsKey($id)) { $L.Add((Get-RAListKqlFunction -List $lists[$id] -Lists $lists)) }
        }
        $factors = @{}; if ($Active.Factors) { $factors = $Active.Factors }
        $namedF = New-Object System.Collections.Generic.SortedSet[string]
        foreach ($m in [regex]::Matches($Query, '\bSI_Factor_([a-z][a-z0-9_]*)\b')) { [void]$namedF.Add($m.Groups[1].Value) }
        foreach ($id in $namedF) {
            if ($factors.ContainsKey($id)) { $L.Add((Get-RAFactorKqlFunction -Factor $factors[$id] -Lists $lists)) }
        }
    }
    $L.Add($script:RAScopeEnd)
    return ($L.ToArray() -join "`n")
}

function Get-RAScopeBlockDefault {
    <# PURE. The scope block a report's YAML copy carries (the shipped values; the data-model lists it names, as shipped). #>
    param([Parameter(Mandatory)][hashtable]$Spec, [AllowEmptyCollection()][object[]]$TierLabels = @(), [AllowEmptyCollection()][string[]]$FactorSet = @(), [hashtable]$Lists = @{}, [hashtable]$Factors = @{}, [AllowEmptyString()][string]$Query = '')
    $d = Get-RAScopeDefaults -Spec $Spec -TierLabels $TierLabels -FactorSet $FactorSet
    $d.Lists = $Lists
    $d.Factors = $Factors
    $d.FactorNames = Get-RAFactorNameMap -Factors @($Factors.Values) -FactorSet @($FactorSet)
    $a = Get-RAScopeActive -Spec $Spec -Values $d
    return (New-RAScopeBlock -Active $a -Query $Query)
}

function Add-RAFinalScopeFilter {
    <# PURE. The excluded configuration ids as the query's last filter (every report emits a ConfigurationId). #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query, [Parameter(Mandatory)][hashtable]$Active)
    $ids = @($Active.ExcludedConfigurationIds)
    if ($Active.Apply -and -not $Active.Apply.configurationIds) { $ids = @() }
    if ($ids.Count -eq 0 -or [string]::IsNullOrWhiteSpace($Query)) { return $Query }
    return ($Query.TrimEnd() + "`n| where not(tostring(column_ifexists(""ConfigurationId"", """")) in (" + (ConvertTo-RAKqlDynamic -Values $ids) + '))')
}

function Get-RAReportActiveScope {
    <#
    .SYNOPSIS  One report's ACTIVE scope values outside a query -- the same three steps Resolve-RAScopePreamble takes
               (Get-RAReportScope -> Get-RAScopeInputs -> Get-RAScopeActive), for a reader that must judge a finding as
               the report does (the data health check, CR2). Never a second reader of the exclusions.
    #>
    param([Parameter(Mandatory)][string]$ReportName, $Template, [AllowEmptyCollection()][object[]]$TierLabels = @(), $Policy)
    if ($null -eq $Template) { $Template = Get-RAReportScopeTemplate }
    $spec = Get-RAReportScope -ReportName $ReportName -Template $Template
    $values = Get-RAScopeInputs -ReportName $ReportName -Spec $spec -TierLabels $TierLabels -Policy $Policy
    Get-RAScopeActive -Spec $spec -Values $values
}

function Test-RAInScopeFinding {
    <#
    .SYNOPSIS  PURE. Would the report keep this finding? The PowerShell form of the scope block's SI_InScopeCve and
               SI_InScopeConfiguration (New-RAScopeBlock) -- the SAME rule, written next to its KQL form so the two never
               drift (SIv3-DataHealth checks the KQL text it mirrors): a CVE in the report's ExcludedCves is out; with a
               minimum age, a CVE whose last modification is newer than that age is out (no date = in); a configuration id
               in ExcludedConfigurationIds is out. -Active: Get-RAScopeActive (a part the report does not declare is
               already neutralised there).
    #>
    param([Parameter(Mandatory)][hashtable]$Active, [AllowEmptyString()][AllowNull()][string]$Cve, [AllowEmptyString()][AllowNull()][string]$ConfigurationId,
          [AllowNull()]$LastModified, [datetime]$NowUtc = [datetime]::UtcNow)
    $c = "$Cve".Trim().ToUpperInvariant()
    if ($c) {
        foreach ($x in @($Active.ExcludedCves)) { if (([string]$x).Trim().ToUpperInvariant() -eq $c) { return $false } }
        $age = 0; [void][int]::TryParse([string]$Active.CveMinAgeDays, [ref]$age)
        if ($age -gt 0 -and $null -ne $LastModified -and "$LastModified" -ne '') {
            $lm = $null
            if ($LastModified -is [datetime]) { $lm = $LastModified.ToUniversalTime() }
            else { $d = [datetime]::MinValue; if ([datetime]::TryParse([string]$LastModified, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal', [ref]$d)) { $lm = $d } }
            if ($null -ne $lm -and -not ($lm -lt $NowUtc.ToUniversalTime().AddDays(-$age))) { return $false }
        }
    }
    $cfg = "$ConfigurationId".Trim()
    if ($cfg -and ($null -eq $Active.Apply -or [bool]$Active.Apply.configurationIds)) {
        foreach ($x in @($Active.ExcludedConfigurationIds)) { if ([string]$x -ceq $cfg) { return $false } }
    }
    $true
}

function Resolve-RAScopePreamble {
    <#
    .SYNOPSIS  The engine's one call per report: the scope block replaced (or prepended when the report has none), the
               CI blocks regenerated with the scope and the factor set, the excluded configuration ids appended, and any
               legacy disabled-asset marker line rewritten from the same setting. Returns @{ Query; Spec; Active }.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Query, [Parameter(Mandatory)][string]$ReportName,
          [AllowEmptyCollection()][object[]]$TierLabels = @(), $Template, [hashtable]$Values, $Policy)
    if ([string]::IsNullOrWhiteSpace($Query)) { return @{ Query = $Query; Spec = $null; Active = $null } }
    if ($null -eq $Template) { $Template = Get-RAReportScopeTemplate }
    $spec = Get-RAReportScope -ReportName $ReportName -Template $Template
    if (-not $Values) { $Values = Get-RAScopeInputs -ReportName $ReportName -Spec $spec -TierLabels $TierLabels -Policy $Policy }
    $active = Get-RAScopeActive -Spec $spec -Values $Values
    $block = New-RAScopeBlock -Active $active -Query $Query
    $rx = '(?ms)^[ \t]*' + [regex]::Escape($script:RAScopeBegin) + '.*?' + [regex]::Escape($script:RAScopeEnd) + '[ \t]*'
    if ([regex]::IsMatch($Query, $rx)) { $q = [regex]::Replace($Query, $rx, { param($m) $block }, 'None', [TimeSpan]::FromSeconds(5)) }
    else { $q = $block + "`n" + $Query }
    if (Get-Command -Name Resolve-RACiBlocks -ErrorAction SilentlyContinue) { $q = Resolve-RACiBlocks -Query $q -StaleDays ([int]$active.StaleDays) -Scope $active }
    if (Get-Command -Name Resolve-SIDisabledAssetsRaFilter -ErrorAction SilentlyContinue) {
        $q = (Resolve-SIDisabledAssetsRaFilter -Query $q -ReportName $ReportName -Policy $Policy -Include ([bool]$active.IncludeDisabled)).Query
    }
    $q = Add-RAFinalScopeFilter -Query $q -Active $active
    return @{ Query = $q; Spec = $spec; Active = $active }
}
