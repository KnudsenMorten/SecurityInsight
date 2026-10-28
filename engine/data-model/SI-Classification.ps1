#Requires -Version 5.1
<#
    SecurityInsight -- ONE GENERIC CLASSIFICATION MECHANISM (REQUIREMENTS #561 dimensions, #562 asset type / subtype).

    Every classification SI assigns from what the sources say -- the asset type, the asset subtype, the component of a
    finding and the components of an asset, and every dimension that comes later -- is the SAME thing: rows of
        source + field + match (equals | in | prefix | pattern) -> target SI field = set, with a priority
    evaluated with the SAME condition engine the risk factors use (SI-Conditions.ps1, tri-state Test-SIConditionTri: a
    field the CI could not decide is unknown and never matches). No code per dimension, no code per source.

    TEMPLATES (the contract the web app's classification wizard is built against)
      data-model/dimensions.locked.json      kind 'dimension', items 'dimensions', Pro key 'dimensions:<id>':
                                             { id, name, values[] } -- ONLY the closed list of values
      data-model/classification.locked.json  kind 'classification', items 'rules', Pro key 'classification:<row id>':
                                             { id,
                                               source    the provider whose naming the row normalises (documentation),
                                               field     an SI field (si_*) or a source path (a dot path into the item),
                                               match     equals | in      -> values  (a list)
                                                         prefix | pattern -> pattern (a glob: * ? [..]; a list = any of them;
                                                                             prefix = the glob followed by *),
                                               target    the SI field the row sets (si_component, si_asset_type, ...),
                                               set       the value (one of the target dimension's values),
                                               priority  an integer 0..10000 (higher wins),
                                               state     enabled | disabled,
                                               when      OPTIONAL extra condition (the condition language, SI fields only)
                                                         that must ALSO hold -- e.g. "a server" AND "SQL Server installed",
                                               verify    true = the source spelling is still to be confirmed on live rows,
                                               note }
                                             HEADER 'targets' (Pro key 'classification'): per target field -- dimension,
                                             appliesTo asset | finding, multi (an asset carries every matching value),
                                             fallback (no row matches; '$keep' = the value the sources gave, then
                                             fallbackEmpty), keepSourceIn. Evaluated in the header's order.
    CUSTOMER  Pro: one cfg.ItemOverride per row / dimension -- override, disable or add. Community: classification.custom.json
              / dimensions.custom.json, only the items that differ. Both through the data-model merge (Get-SIDataModelTemplate).
              The web app's validators: Test-SIClassificationRule / Test-SIDimensionItem, and the C# mirror
              SI.Management.Web/Changes/ClassificationItemValidator.cs (same closed sets, Get-SIClassificationShape).

    EVALUATION
      asset    the CI build (Invoke-SICiClassification, after enrichment): the asset targets in header order, each value
               written before the next target is evaluated (so a component row may read si_asset_subtype).
               single  the highest-priority enabled row whose condition is TRUE (file order breaks a tie)
               multi   every matching row's value, in the dimension's value order
               none    the target's fallback -- never blank
      finding  Risk Analysis, per row (Set-SIRaRowDimensions): the row's own finding fields (title, category, affected
               product / vendor / CPE, the Azure resource type of the asset it is on) -> one value per finding target. An
               OS vulnerability on a SQL Server VM stays OS -- the VM carries both OS and SQL, the finding the one that
               matches it. The finding targets in header order, each value written before the next is evaluated -- the
               ServiceNow sub-CI (si_servicenow_subci, #772) reads the component it follows.

    PURE except Get-SIClassificationIndex (reads the templates). PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Test-SIConditionTri -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-Conditions.ps1') }
# #772 the release dates of Microsoft's updates per KB (the patch cycle reads them; loaded once per run by Risk Analysis)
if (-not (Get-Command -Name Get-SIKbReleaseDate -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-KbReleaseDates.ps1') }

function Get-SIClassificationMatchOps { return , @('equals', 'in', 'prefix', 'pattern') }

function Get-SIClassificationShape {
    <#
    .SYNOPSIS  PURE. The shape the validators enforce, as data -- the contract the C# mirror and the web app's wizard read.
    #>
    [ordered]@{
        dimension      = [ordered]@{ template = 'dimensions'; kind = 'dimension'; key = 'id'; idPattern = '^[a-z][a-z0-9_]{0,47}$'; valueMaxLength = 64 }
        classification = [ordered]@{ template = 'classification'; kind = 'classification'; key = 'id'; idPattern = '^[a-z0-9][a-z0-9_\-\.]{0,99}$'
                                     matchOps = (Get-SIClassificationMatchOps); valuesFor = @('equals', 'in'); patternFor = @('prefix', 'pattern')
                                     states = @('enabled', 'disabled'); priorityMin = 0; priorityMax = 10000
                                     fieldPattern = '^(si_[a-z0-9_]+|[A-Za-z_][A-Za-z0-9_]*(\[\*\])?(\.[A-Za-z0-9_$@-]+(\[\*\])?)*)$'
                                     targetPattern = '^si_[a-z0-9_]+$'; sourcePattern = '^[a-z][a-z0-9_]{0,31}$' }
    }
}

function Get-SIClassificationSqlAzureTypes {
    <# The Azure resource types SI treats as SQL (documentation + tests; the shipped rows list them themselves). #>
    return , @('microsoft.sql/servers', 'microsoft.sql/servers/databases', 'microsoft.sql/managedinstances', 'microsoft.sql/managedinstances/databases',
        'microsoft.sqlvirtualmachine/sqlvirtualmachines', 'microsoft.dbforpostgresql/servers', 'microsoft.dbforpostgresql/flexibleservers',
        'microsoft.dbformysql/servers', 'microsoft.dbformysql/flexibleservers', 'microsoft.dbformariadb/servers')
}

function Test-SIClassificationSiField { param([string]$Name) return ($Name -cmatch '^si_[a-z0-9_]+$') }

function ConvertTo-SIClassificationCondition {
    <#
    .SYNOPSIS  PURE. A row's match -> a condition of the shared language (field = '$value' when the row reads a source path:
               the evaluator resolves the path first). equals / in -> in (values); prefix -> like '<pattern>*'; pattern ->
               like '<pattern>' (globs, case-insensitive). An extra 'when' is ANDed.
    #>
    param($Rule)
    $field = [string](Get-SIItemValue $Rule 'field')
    $leafField = $field; if (-not (Test-SIClassificationSiField $field)) { $leafField = '$value' }
    $op = [string](Get-SIItemValue $Rule 'match')
    $leaf = $null
    switch ($op) {
        { $_ -in 'equals', 'in' } { $leaf = @{ field = $leafField; op = 'in'; value = (Get-SIValueList (Get-SIItemValue $Rule 'values')).ToArray() } }
        'prefix' { $leaf = @{ field = $leafField; op = 'like'; value = @(foreach ($x in (Get-SIValueList (Get-SIItemValue $Rule 'pattern'))) { $s = [string]$x; if ($s.EndsWith('*')) { $s } else { $s + '*' } }) } }
        'pattern' { $leaf = @{ field = $leafField; op = 'like'; value = @(foreach ($x in (Get-SIValueList (Get-SIItemValue $Rule 'pattern'))) { [string]$x }) } }
        default { throw ("classification row '{0}': unknown match '{1}'" -f [string](Get-SIItemValue $Rule 'id'), $op) }
    }
    $when = Get-SIItemValue $Rule 'when'
    if ($null -ne $when) { return @{ all = @($leaf, $when) } }
    return $leaf
}

function Resolve-SIClassificationPath {
    <# PURE. Every value at a dot path in an item ("a.b[*].c"), case-insensitive -- a source-path row's field. #>
    param($Item, [string]$Path)
    $cur = [System.Collections.Generic.List[object]]::new(); $cur.Add($Item)
    foreach ($segRaw in $Path.Split('.')) {
        $walk = $segRaw.EndsWith('[*]'); $seg = $segRaw; if ($walk) { $seg = $segRaw.Substring(0, $segRaw.Length - 3) }
        $next = [System.Collections.Generic.List[object]]::new()
        foreach ($o in $cur) {
            $v = Get-SIItemValue $o $seg
            if ($null -eq $v) { continue }
            if ($walk -or ($v -is [System.Collections.IEnumerable] -and $v -isnot [string] -and $v -isnot [System.Collections.IDictionary])) { foreach ($x in $v) { $next.Add($x) } } else { $next.Add($v) }
        }
        $cur = $next
        if ($cur.Count -eq 0) { break }
    }
    , $cur.ToArray()
}

function Test-SIDimensionItem {
    <# PURE. The reasons one dimension is not accepted (empty = accepted). The web app calls it on a 'dimensions:<id>' override. #>
    param($Dimension)
    $why = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Dimension) { $why.Add('a dimension is empty'); return $why.ToArray() }
    $id = [string](Get-SIItemValue $Dimension 'id')
    if ($id -cnotmatch '^[a-z][a-z0-9_]{0,47}$') { $why.Add(("dimension id '{0}': a lower snake_case word of at most 48 characters" -f $id)) }
    $values = @(@(Get-SIItemValue $Dimension 'values') | Where-Object { $null -ne $_ -and ([string]$_).Trim() } | ForEach-Object { [string]$_ })
    if ($values.Count -eq 0) { $why.Add(("dimension '{0}': values names at least one value" -f $id)) }
    $seen = @{}
    foreach ($v in $values) {
        if ($v.Length -gt 64 -or $v -match '[\r\n\t;]') { $why.Add(("dimension '{0}': value '{1}' must be one line of at most 64 characters without ';'" -f $id, $v)) }
        if ($seen.ContainsKey($v.ToLowerInvariant())) { $why.Add(("dimension '{0}': value '{1}' is listed twice" -f $id, $v)) }
        $seen[$v.ToLowerInvariant()] = 1
    }
    # #772 an optional default: the fallback of the dimension's finding / single-value targets -- one of its own values
    $def = Get-SIItemValue $Dimension 'default'
    if ($null -ne $def -and ([string]$def).Trim() -and -not $seen.ContainsKey(([string]$def).Trim().ToLowerInvariant())) {
        $why.Add(("dimension '{0}': default '{1}' is not one of its values" -f $id, [string]$def))
    }
    $why.ToArray()
}

function Get-SIClassificationFallback {
    <#
    .SYNOPSIS  PURE. #772 the fallback a target uses: the dimension's own 'default' (one of its values) when it names one and
               the target is not '$keep', else the target's fallback. So a customer who renames or removes the fallback
               bucket (the ServiceNow sub-CI: Other) names the new one in the same dimension item -- never blank.
    #>
    param($Target, $Dimension)
    $fb = [string](Get-SIItemValue $Target 'fallback')
    if ($fb -eq '$keep' -or $null -eq $Dimension) { return $fb }
    $def = ([string](Get-SIItemValue $Dimension 'default')).Trim()
    if (-not $def) { return $fb }
    foreach ($v in @(Get-SIItemValue $Dimension 'values')) { if ($null -ne $v -and ([string]$v).Trim() -ieq $def) { return ([string]$v).Trim() } }
    $fb
}

function Test-SIClassificationTarget {
    <# PURE. One target of the classification header (where a dimension's values are written, and the fallback). #>
    param($Target, [hashtable]$Dimensions)
    $why = [System.Collections.Generic.List[string]]::new()
    $f = [string](Get-SIItemValue $Target 'field')
    if ($f -cnotmatch '^si_[a-z0-9_]+$') { $why.Add(("target '{0}': must be an SI field (si_*)" -f $f)) }
    $dimId = [string](Get-SIItemValue $Target 'dimension')
    $vals = @()
    $dimDoc = $null
    if ($null -ne $Dimensions) {
        if (-not $Dimensions.ContainsKey($dimId)) { $why.Add(("target '{0}': dimension '{1}' is not defined (dimensions.locked.json)" -f $f, $dimId)) }
        else { $dimDoc = $Dimensions[$dimId]; $vals = @(@(Get-SIItemValue $dimDoc 'values') | ForEach-Object { ([string]$_).ToLowerInvariant() }) }
    }
    $scope = [string](Get-SIItemValue $Target 'appliesTo')
    if ($scope -notin 'asset', 'finding') { $why.Add(("target '{0}': appliesTo '{1}' (asset or finding)" -f $f, $scope)) }
    $multi = (ConvertTo-SIBoolOrNull (Get-SIItemValue $Target 'multi')) -eq $true
    if ($multi -and $scope -eq 'finding') { $why.Add(("target '{0}': a finding carries ONE value per dimension (multi is for assets)" -f $f)) }
    # #772 the dimension's default (when it names one of its values) is the fallback
    $fb = Get-SIClassificationFallback -Target $Target -Dimension $dimDoc
    if (-not $fb) { $why.Add(("target '{0}': a fallback is required -- a classification is never blank" -f $f)) }
    elseif ($fb -eq '$keep') {
        if ($scope -ne 'asset' -or $multi) { $why.Add(("target '{0}': '`$keep' is for a single-value asset target" -f $f)) }
        $fe = [string](Get-SIItemValue $Target 'fallbackEmpty')
        if (-not $fe -or ($vals.Count -and $vals -notcontains $fe.ToLowerInvariant())) { $why.Add(("target '{0}': '`$keep' needs a fallbackEmpty that is one of the dimension's values" -f $f)) }
    } elseif ($vals.Count -and $vals -notcontains $fb.ToLowerInvariant()) { $why.Add(("target '{0}': fallback '{1}' is not a value of dimension '{2}'" -f $f, $fb, $dimId)) }
    $k = [string](Get-SIItemValue $Target 'keepSourceIn')
    if ($k -and $k -cnotmatch '^si_[a-z0-9_]+$') { $why.Add(("target '{0}': keepSourceIn '{1}' must be an SI field" -f $f, $k)) }
    $why.ToArray()
}

function Test-SIClassificationRule {
    <#
    .SYNOPSIS  PURE. The reasons one classification row is not accepted (empty = accepted). -Targets: target field -> header
               target; -Dimensions: id -> dimension (both from the merged templates); without them the row is checked on its
               own shape only. The web app calls it on a 'classification:<id>' override; the C# mirror checks the same shape.
    #>
    param($Rule, [hashtable]$Targets, [hashtable]$Dimensions)
    $why = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $Rule) { $why.Add('a classification row is empty'); return $why.ToArray() }
    $shape = (Get-SIClassificationShape).classification
    $id = [string](Get-SIItemValue $Rule 'id')
    if ($id -notmatch $shape.idPattern) { $why.Add(("row id '{0}': lower-case letters, digits, - _ . (at most 100)" -f $id)) }
    $field = [string](Get-SIItemValue $Rule 'field')
    if ($field -cnotmatch $shape.fieldPattern) { $why.Add(("row '{0}': field '{1}' must be an SI field (si_*) or a source path (a.b[*].c)" -f $id, $field)) }
    $op = [string](Get-SIItemValue $Rule 'match')
    if ((Get-SIClassificationMatchOps) -notcontains $op) { $why.Add(("row '{0}': match '{1}' (equals | in | prefix | pattern)" -f $id, $op)) }
    $values = @(@(Get-SIItemValue $Rule 'values') | Where-Object { $null -ne $_ -and ([string]$_) -ne '' })
    $pattern = @(@(Get-SIItemValue $Rule 'pattern') | Where-Object { $null -ne $_ -and ([string]$_).Trim() })
    if ($op -in 'equals', 'in') {
        if ($values.Count -eq 0) { $why.Add(("row '{0}': match '{1}' needs values (a list)" -f $id, $op)) }
        if ($op -eq 'equals' -and $values.Count -gt 1) { $why.Add(("row '{0}': equals takes one value -- use in for several" -f $id)) }
        if ($pattern.Count) { $why.Add(("row '{0}': match '{1}' reads values, not pattern" -f $id, $op)) }
    }
    if ($op -in 'prefix', 'pattern') {
        if ($pattern.Count -eq 0) { $why.Add(("row '{0}': match '{1}' needs a pattern (a glob)" -f $id, $op)) }
        if ($values.Count) { $why.Add(("row '{0}': match '{1}' reads pattern, not values" -f $id, $op)) }
        foreach ($p in $pattern) { try { $null = New-Object System.Management.Automation.WildcardPattern([string]$p) } catch { $why.Add(("row '{0}': invalid glob '{1}'" -f $id, $p)) } }
    }
    $target = [string](Get-SIItemValue $Rule 'target')
    $set = [string](Get-SIItemValue $Rule 'set')
    if ($target -cnotmatch $shape.targetPattern) { $why.Add(("row '{0}': target '{1}' must be an SI field (si_*)" -f $id, $target)) }
    if (-not $set.Trim()) { $why.Add(("row '{0}': set (the value) is required" -f $id)) }
    if ($null -ne $Targets) {
        if (-not $Targets.ContainsKey($target)) { $why.Add(("row '{0}': target '{1}' is not a classification target (the template's targets)" -f $id, $target)) }
        elseif ($null -ne $Dimensions) {
            $dimId = [string](Get-SIItemValue $Targets[$target] 'dimension')
            if ($Dimensions.ContainsKey($dimId)) {
                $vals = @(@(Get-SIItemValue $Dimensions[$dimId] 'values') | ForEach-Object { ([string]$_).ToLowerInvariant() })
                if ($set -and $vals -notcontains $set.ToLowerInvariant()) { $why.Add(("row '{0}': '{1}' is not a value of dimension '{2}'" -f $id, $set, $dimId)) }
            }
        }
    }
    $prio = Get-SIItemValue $Rule 'priority'
    $pn = ConvertTo-SINumberOrNull $prio
    if ($null -eq $pn -or $pn -lt $shape.priorityMin -or $pn -gt $shape.priorityMax -or [Math]::Floor($pn) -ne $pn) { $why.Add(("row '{0}': priority must be an integer 0..10000 (higher wins)" -f $id)) }
    $st = [string](Get-SIItemValue $Rule 'state')
    if ($st -and $st -notin 'enabled', 'disabled') { $why.Add(("row '{0}': state '{1}' (enabled | disabled)" -f $id, $st)) }
    $src = [string](Get-SIItemValue $Rule 'source')
    if ($src -and $src -cnotmatch $shape.sourcePattern) { $why.Add(("row '{0}': source '{1}' is not a provider name" -f $id, $src)) }
    $when = Get-SIItemValue $Rule 'when'
    if ($null -ne $when) {
        $ops = Get-SIConditionOps
        foreach ($leafField in (Get-SIConditionFields $when)) { if (-not (Test-SIClassificationSiField $leafField)) { $why.Add(("row '{0}': when reads '{1}' -- an extra condition reads SI fields (si_*) only" -f $id, $leafField)) } }
        $stack = New-Object System.Collections.Generic.Stack[object]; $stack.Push($when)
        while ($stack.Count -gt 0) {
            $c = $stack.Pop()
            $isGroup = $false
            foreach ($k in 'all', 'any') {
                $has = ($c -is [System.Collections.IDictionary] -and $c.Contains($k)) -or ($null -ne $c -and $null -ne $c.PSObject.Properties[$k])
                if ($has) { $isGroup = $true; foreach ($x in (Get-SIValueList (Get-SIItemValue $c $k))) { $stack.Push($x) } }
            }
            if (-not $isGroup) {
                $o = [string](Get-SIItemValue $c 'op')
                if ($o -eq 'in_list') { $why.Add(("row '{0}': in_list is not available to a classification row -- list the values (in)" -f $id)) }
                elseif ($ops -notcontains $o) { $why.Add(("row '{0}': unknown condition operation '{1}'" -f $id, $o)) }
                if ($o -eq 'matches') { foreach ($p in (Get-SIValueList (Get-SIItemValue $c 'value'))) { try { [void][regex]::new([string]$p) } catch { $why.Add(("row '{0}': invalid pattern '{1}'" -f $id, $p)) } } }
            }
        }
    }
    $why.ToArray()
}

function Get-SIClassificationTargets {
    <# PURE. The classification header's targets: field -> target (ordered, header order). #>
    param($Classification)
    $t = [ordered]@{}
    foreach ($x in @(Get-SIItemValue $Classification 'targets')) { if ($null -ne $x) { $t[[string](Get-SIItemValue $x 'field')] = $x } }
    $t
}

function Test-SIClassifications {
    <#
    .SYNOPSIS  PURE. Both templates together: every dimension, target and row valid, every id once, every SI field a row reads
               or a target writes is in the field catalog (-Fields: name -> catalog entry; optional) at the right level.
    #>
    param($Dimensions, $Classification, [hashtable]$Fields)
    $p = [System.Collections.Generic.List[string]]::new()
    $dims = @{}
    foreach ($d in @(Get-SIItemValue $Dimensions 'dimensions')) {
        if ($null -eq $d) { continue }
        foreach ($x in (Test-SIDimensionItem -Dimension $d)) { $p.Add('dimensions: ' + $x) }
        $did = [string](Get-SIItemValue $d 'id')
        if ($dims.ContainsKey($did)) { $p.Add(("dimensions: '{0}' is defined twice" -f $did)) }
        $dims[$did] = $d
    }
    $targets = @{}
    foreach ($t in @(Get-SIItemValue $Classification 'targets')) {
        if ($null -eq $t) { continue }
        foreach ($x in (Test-SIClassificationTarget -Target $t -Dimensions $dims)) { $p.Add('classification: ' + $x) }
        $tf = [string](Get-SIItemValue $t 'field')
        if ($targets.ContainsKey($tf)) { $p.Add(("classification: target '{0}' is defined twice" -f $tf)) }
        $targets[$tf] = $t
        if ($null -ne $Fields) {
            foreach ($fn in @($tf, [string](Get-SIItemValue $t 'keepSourceIn'))) {
                if (-not $fn) { continue }
                if (-not $Fields.ContainsKey($fn)) { $p.Add(("classification: target '{0}' writes '{1}', which is not in the field catalog" -f $tf, $fn)); continue }
                $lvl = [string]$Fields[$fn].level
                $scope = [string](Get-SIItemValue $t 'appliesTo')
                if ($scope -eq 'asset' -and $lvl -eq 'finding') { $p.Add(("classification: asset target '{0}' writes finding field '{1}'" -f $tf, $fn)) }
                if ($scope -eq 'finding' -and $lvl -ne 'finding') { $p.Add(("classification: finding target '{0}' writes '{1}', which is not a finding field" -f $tf, $fn)) }
            }
        }
    }
    $ids = @{}
    foreach ($r in @(Get-SIItemValue $Classification 'rules')) {
        if ($null -eq $r) { continue }
        $rid = [string](Get-SIItemValue $r 'id')
        foreach ($x in (Test-SIClassificationRule -Rule $r -Targets $targets -Dimensions $dims)) { $p.Add('classification: ' + $x) }
        if ($ids.ContainsKey($rid)) { $p.Add(("classification: row '{0}' is defined twice" -f $rid)) }
        $ids[$rid] = 1
        if ($null -ne $Fields) {
            $scope = ''; $tg = $targets[[string](Get-SIItemValue $r 'target')]; if ($tg) { $scope = [string](Get-SIItemValue $tg 'appliesTo') }
            $read = [System.Collections.Generic.List[string]]::new()
            $f = [string](Get-SIItemValue $r 'field'); if (Test-SIClassificationSiField $f) { $read.Add($f) }
            $w = Get-SIItemValue $r 'when'; if ($null -ne $w) { foreach ($x in (Get-SIConditionFields $w)) { $read.Add([string]$x) } }
            foreach ($fn in $read) {
                if (-not $Fields.ContainsKey($fn)) { $p.Add(("classification/{0}: reads '{1}', which is not in the field catalog" -f $rid, $fn)); continue }
                if ($scope -eq 'asset' -and [string]$Fields[$fn].level -eq 'finding') { $p.Add(("classification/{0}: an asset row reads finding field '{1}'" -f $rid, $fn)) }
            }
        }
    }
    $p.ToArray()
}

function New-SIClassificationIndex {
    <#
    .SYNOPSIS  PURE. The merged templates -> what the evaluators walk: the targets in header order, each with its dimension's
               values and its rows (enabled and valid only), highest priority first (file order breaks a tie), each row's
               condition compiled once.
    #>
    param($Dimensions, $Classification)
    $dims = @{}
    foreach ($d in @(Get-SIItemValue $Dimensions 'dimensions')) { if ($null -ne $d -and @(Test-SIDimensionItem -Dimension $d).Count -eq 0) { $dims[[string]$d.id] = $d } }
    $targets = [System.Collections.Generic.List[object]]::new()
    $byField = @{}
    foreach ($t in @(Get-SIItemValue $Classification 'targets')) {
        if ($null -eq $t -or @(Test-SIClassificationTarget -Target $t -Dimensions $dims).Count -gt 0) { continue }
        $d = $dims[[string]$t.dimension]
        $e = [pscustomobject]@{ Field = [string]$t.field; Dimension = [string]$t.dimension; AppliesTo = [string]$t.appliesTo
                                Multi = ((ConvertTo-SIBoolOrNull (Get-SIItemValue $t 'multi')) -eq $true); Fallback = (Get-SIClassificationFallback -Target $t -Dimension $d)
                                FallbackEmpty = [string](Get-SIItemValue $t 'fallbackEmpty'); KeepSourceIn = [string](Get-SIItemValue $t 'keepSourceIn')
                                Values = @(@($d.values) | ForEach-Object { [string]$_ }); Rules = ([System.Collections.Generic.List[object]]::new()) }
        $targets.Add($e); $byField[$e.Field] = $e
    }
    $tgDocs = @{}; foreach ($t in @(Get-SIItemValue $Classification 'targets')) { if ($t) { $tgDocs[[string]$t.field] = $t } }
    $n = 0
    foreach ($r in @(Get-SIItemValue $Classification 'rules')) {
        if ($null -eq $r) { continue }
        $n++
        if ([string](Get-SIItemValue $r 'state') -eq 'disabled') { continue }
        if (@(Test-SIClassificationRule -Rule $r -Targets $tgDocs -Dimensions $dims).Count -gt 0) { continue }
        $e = $byField[[string]$r.target]; if ($null -eq $e) { continue }
        $f = [string]$r.field
        $cond = ConvertTo-SIClassificationCondition -Rule $r
        # the SI field the row's own match reads (none for a source-path row): Get-SIClassificationValue decides the row false
        # without evaluating it when the CI does not carry that field
        $lf = ''; if (Test-SIClassificationSiField $f) { $lf = $f }
        $e.Rules.Add([pscustomobject]@{ Id = [string]$r.id; Value = [string]$r.set; Priority = [double](ConvertTo-SINumberOrNull $r.priority); Order = $n
                                        SourcePath = $(if (Test-SIClassificationSiField $f) { '' } else { $f }); Condition = $cond; LeafField = $lf })
    }
    foreach ($e in $targets) {
        $sorted = @($e.Rules.ToArray() | Sort-Object -Property @{ Expression = { $_.Priority }; Descending = $true }, @{ Expression = { $_.Order }; Descending = $false })
        $e.Rules.Clear(); foreach ($x in $sorted) { $e.Rules.Add($x) }
    }
    # .ToArray(), never @() around a List[object] held in an object: pwsh 7 throws "Argument types do not match"
    $hasPath = (@($targets.ToArray() | ForEach-Object { $_.Rules.ToArray() } | Where-Object { $_.SourcePath }).Count -gt 0)
    [pscustomobject]@{ Targets = $targets.ToArray(); HasSourcePath = $hasPath; Cache = @{} }
}

function Get-SIClassificationValue {
    <#
    .SYNOPSIS  PURE. One target over one item: @{ Values (the value, or for multi every value); Rules (the deciding row ids);
               Unknown (rows whose condition could not be decided) }. Values is empty when no row matched -- the caller
               applies the fallback.
    #>
    param([Parameter(Mandatory)]$Target, $Item, [hashtable]$Context, [string[]]$UnknownFields = @())
    $vals = [System.Collections.Generic.List[string]]::new()
    $ids = [System.Collections.Generic.List[string]]::new()
    $unknown = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $Target.Rules) {
        if ($Target.Multi -and $vals.Contains($r.Value)) { continue }
        $subject = $Item
        if ($r.SourcePath) {
            # a source-path row: the path's values become '$value' of a view that also carries the item's SI fields (for 'when')
            $view = @{}
            if ($Item -is [System.Collections.IDictionary]) { foreach ($k in @($Item.Keys)) { $view[[string]$k] = $Item[$k] } }
            elseif ($null -ne $Item) { foreach ($pp in $Item.PSObject.Properties) { $view[$pp.Name] = $pp.Value } }
            $view['$value'] = @(Resolve-SIClassificationPath -Item $Item -Path $r.SourcePath)
            $subject = $view
        }
        # A ROW WHOSE FIELD THE CI DOES NOT CARRY IS FALSE (2026-10-16, the CI build of a large install: most rows read an Azure
        # resource type, which an identity or a device never has). The row's match is 'in' or 'like' on that field and comes
        # FIRST in its condition (ConvertTo-SIClassificationCondition), so an empty field -- no value, or a list without one --
        # makes the whole row false, exactly as evaluating it would; a field the CI cannot decide (UnknownFields) is evaluated.
        if ($r.PSObject.Properties['LeafField'] -and $r.LeafField -and -not $r.SourcePath) {
            $lv = Get-SIItemValue $subject $r.LeafField
            if ($null -eq $lv -or (Get-SIValueList $lv).Count -eq 0) {
                $unk = $false; foreach ($u in $UnknownFields) { if ($u -and [string]::Equals([string]$u, [string]$r.LeafField, [StringComparison]::OrdinalIgnoreCase)) { $unk = $true; break } }
                if (-not $unk) { continue }
            }
        }
        $hit = $false
        try { $hit = Test-SIConditionTri -Condition $r.Condition -Item $subject -Context $Context -UnknownFields $UnknownFields } catch { $hit = $false }
        if ($null -eq $hit) { $unknown.Add($r.Id); continue }
        if ($hit -ne $true) { continue }
        $vals.Add($r.Value); $ids.Add($r.Id)
        if (-not $Target.Multi) { break }
    }
    if ($Target.Multi -and $vals.Count -gt 1) {
        # the dimension's own value order, so the same asset always reads the same way
        $ordered = @($Target.Values | Where-Object { $vals -contains $_ })
        $vals.Clear(); foreach ($v in $ordered) { $vals.Add($v) }
    }
    @{ Values = $vals.ToArray(); Rules = $ids.ToArray(); Unknown = $unknown.ToArray() }
}

function Set-SICiSqlIaasLinks {
    <#
    .SYNOPSIS  PURE. #561 / #562: a VM registered with the SQL IaaS extension has a microsoft.sqlvirtualmachine/sqlvirtualmachines
               resource whose virtualMachineResourceId (si_sql_vm_resource_id) names the VM. The VM's CI (si_link_azure or a
               linked Azure id) gets si_sql_iaas = true. Only within the CIs given (one build batch); a VM whose SQL resource is
               in another batch is decided by its software inventory instead. Returns the number of VMs marked.
    #>
    param([AllowEmptyCollection()][object[]]$Cis = @())
    $vmIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $Cis) { foreach ($v in (Get-SIValueList (Get-SIItemValue $c 'si_sql_vm_resource_id'))) { if ($v) { [void]$vmIds.Add(([string]$v).Trim()) } } }
    if ($vmIds.Count -eq 0) { return 0 }
    $n = 0
    foreach ($c in $Cis) {
        $ids = [System.Collections.Generic.List[string]]::new()
        $la = [string](Get-SIItemValue $c 'si_link_azure'); if ($la) { $ids.Add($la) }
        foreach ($lo in (Get-SIValueList (Get-SIItemValue $c 'si_linked_objects'))) { $lid = [string](Get-SIItemValue $lo 'id'); if ($lid -like '/subscriptions/*') { $ids.Add($lid) } }
        foreach ($i in $ids) {
            if ($vmIds.Contains($i.Trim())) {
                if ($c -is [System.Collections.IDictionary]) { $c['si_sql_iaas'] = $true } else { $c | Add-Member -NotePropertyName si_sql_iaas -NotePropertyValue $true -Force }
                $n++; break
            }
        }
    }
    $n
}

function Invoke-SIAssetClassification {
    <#
    .SYNOPSIS  PURE. Every asset target on ONE CI (an ordered dictionary): writes the target field (and keepSourceIn), and
               si_classified_by (target field -> the row ids that decided, or 'fallback').
    #>
    param([Parameter(Mandatory)]$Ci, [Parameter(Mandatory)]$Index, [hashtable]$Context)
    $unknownFields = @(foreach ($x in @(Get-SIItemValue $Ci 'si_unknown_fields')) { if ($x) { [string]$x } })
    $by = [ordered]@{}
    foreach ($t in @($Index.Targets)) {
        if ($t.AppliesTo -ne 'asset') { continue }
        $src = Get-SIItemValue $Ci $t.Field
        if ($t.KeepSourceIn) {
            # the value the sources gave, kept once: a CI classified before (an incremental build) keeps its source value
            $prev = Get-SIItemValue $Ci $t.KeepSourceIn
            if (-not (Test-SIValueEmpty $prev)) { $src = $prev } else { $Ci[$t.KeepSourceIn] = $src }
        }
        $r = Get-SIClassificationValue -Target $t -Item $Ci -Context $Context -UnknownFields $unknownFields
        $vals = @($r.Values); $decided = @($r.Rules)
        if ($vals.Count -eq 0) {
            if ($t.Fallback -eq '$keep') {
                $sv = @((Get-SIValueList $src).ToArray() | Where-Object { -not (Test-SIValueEmpty $_) })
                if ($sv.Count) { $vals = @([string]$sv[0]) } else { $vals = @($t.FallbackEmpty) }
            } else { $vals = @($t.Fallback) }
            $decided = @('fallback')
        }
        if ($t.Multi) { $Ci[$t.Field] = [string[]]$vals } else { $Ci[$t.Field] = [string]$vals[0] }
        $by[$t.Field] = $decided
    }
    $Ci['si_classified_by'] = $by
    $Ci
}

function Invoke-SICiClassification {
    <#
    .SYNOPSIS  The CI build step: SQL IaaS links over the set, then every CI classified. Never throws (a classification that
               cannot run leaves the CIs as the sources gave them, with a warning). Returns the number of CIs classified.
    #>
    param([AllowEmptyCollection()][object[]]$Cis = @(), [Parameter(Mandatory)]$Model, [hashtable]$Context)
    try {
        $dimDoc = $Model['dimensions']; $clsDoc = $Model['classification']
        if ($null -eq $dimDoc -or $null -eq $clsDoc) { return 0 }
        $idx = New-SIClassificationIndex -Dimensions $dimDoc -Classification $clsDoc
        if (@($idx.Targets).Count -eq 0) { return 0 }
        $null = Set-SICiSqlIaasLinks -Cis @($Cis)
        $n = 0
        foreach ($ci in $Cis) { if ($null -eq $ci) { continue }; $null = Invoke-SIAssetClassification -Ci $ci -Index $idx -Context $Context; $n++ }
        return $n
    } catch {
        Write-Warning ('classification (asset type / subtype / components) not applied -- {0}' -f $_.Exception.Message)
        return 0
    }
}

function ConvertFrom-SIAzureResourceIdType {
    <# PURE. '/subscriptions/../providers/Microsoft.Sql/servers/s1/databases/d1' -> 'microsoft.sql/servers/databases'; '' when it is not one. #>
    param([AllowNull()][AllowEmptyString()][string]$Id)
    if (-not $Id) { return '' }
    $i = $Id.ToLowerInvariant().LastIndexOf('/providers/')
    if ($i -lt 0) { return '' }
    $segs = @($Id.Substring($i + 11).Split('/') | Where-Object { $_ -ne '' })
    if ($segs.Count -lt 3) { return '' }
    $t = $segs[0] + '/' + $segs[1]
    for ($k = 3; $k -lt $segs.Count; $k += 2) { $t += '/' + $segs[$k] }
    $t.ToLowerInvariant()
}

function ConvertTo-SIFindingClassificationItem {
    <#
    .SYNOPSIS  PURE. A Risk Analysis row (any report) -> the SI finding fields a classification row reads:
               si_title (ConfigurationName), si_category, si_subcategory, si_security_domain, si_finding_key (ConfigurationId),
               si_report_name (AssetDetectedInReportName / ReportName, #772),
               si_affected_product / _vendor / _version / _cpe (the row's own si_* columns or SI_Affected*; ';'-joined lists
               become lists) and si_azure_resource_type (AssetType when it is an Azure type, else parsed from
               AzureResourceId / ResourceId / AssetId). The row's own columns stay readable by a source-path row. A field the
               row does not carry is absent -- unknown, never guessed.
    #>
    param([Parameter(Mandatory)]$Row, [switch]$WithRow)
    # PERFORMANCE (Risk Analysis calls this once per finding row): Get-SIItemValue's own rule -- the exact key first, else the
    # first key equal ignoring case (in key order) -- with the case-insensitive view of a dictionary's keys built ONCE per
    # row instead of a walk over every key for each name the row does not carry
    $ciKeys = $null; $isDict = $false
    if ($Row -is [System.Collections.IDictionary]) {
        $isDict = $true
        # a dictionary whose own lookup already ignores case (PowerShell's @{} and [ordered]@{}, probed on a key that has
        # letters) needs no second view: the walk could find nothing its lookup missed
        $insens = $false
        if ($Row -is [hashtable] -or $Row -is [System.Collections.Specialized.OrderedDictionary]) {
            foreach ($k in $Row.Keys) { $ks = [string]$k; $ku = $ks.ToUpperInvariant(); $kl = $ks.ToLowerInvariant(); if ($ku -cne $kl) { $insens = ($Row.Contains($ku) -and $Row.Contains($kl)); break } }
        }
        if (-not $insens) {
            $ciKeys = [System.Collections.Generic.Dictionary[string,object]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($k in $Row.Keys) { $ks = [string]$k; if (-not $ciKeys.ContainsKey($ks)) { $ciKeys[$ks] = $k } }
        }
    }
    # every name this reads, read ONCE, inline (no script block call per name): its value as trimmed text, or $null when
    # absent / null / blank -- what the per-name reader returned
    $tv = @{}
    foreach ($n in $script:SIFindingItemReadNames) {
        $v = $null
        if ($isDict) {
            if ($Row.Contains($n)) { $v = $Row[$n] }
            elseif ($null -ne $ciKeys) { $ok = $null; if ($ciKeys.TryGetValue($n, [ref]$ok)) { $v = $Row[$ok] } }
        } else { $v = Get-SIItemValue $Row $n }
        $t = $null
        if ($null -ne $v) { $s = [string]$v; if ($s.Trim()) { $t = $s.Trim() } }
        $tv[$n] = $t
    }
    $o = @{}
    # the row's own columns only when a source-path row reads them (a copy per row costs on 80,000-row reports)
    if ($WithRow) {
        if ($Row -is [System.Collections.IDictionary]) { foreach ($k in @($Row.Keys)) { $o[[string]$k] = $Row[$k] } }
        else { foreach ($pp in $Row.PSObject.Properties) { $o[$pp.Name] = $pp.Value } }
    }
    foreach ($p in $script:SIFindingItemPairs) {
        foreach ($src in $p[1]) {
            $v = $tv[$src]
            if ($null -eq $v) { continue }
            if ($p[0] -like 'si_affected_*' -and $v.Contains(';')) { $o[$p[0]] = @($v.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } else { $o[$p[0]] = $v }
            break
        }
    }
    $rt = $tv['si_azure_resource_type']
    if (-not $rt) { $at = $tv['AssetType']; if ($at -and $at -match '^(?i)microsoft\.[a-z0-9]+/[a-z0-9/]+$') { $rt = $at.ToLowerInvariant() } }
    if (-not $rt) {
        foreach ($n in 'AzureResourceId', 'ResourceId', 'AssetId', 'AssetName') {
            $idv = $tv[$n]
            # ConvertFrom-SIAzureResourceIdType returns '' for an empty id and for one without '/providers/' (its own first
            # two tests, made here so the call is skipped for the ids that are no Azure resource id)
            if (-not $idv -or $idv.ToLowerInvariant().LastIndexOf('/providers/') -lt 0) { continue }
            $t = ConvertFrom-SIAzureResourceIdType $idv; if ($t) { $rt = $t; break }
        }
    }
    if ($rt) { $o['si_azure_resource_type'] = $rt }
    $o
}
$script:SIFindingItemPairs = @(
    @('si_title', @('si_title', 'ConfigurationName')), @('si_category', @('si_category', 'Category')), @('si_subcategory', @('si_subcategory', 'Subcategory')),
    @('si_security_domain', @('si_security_domain', 'SecurityDomain')), @('si_finding_key', @('si_finding_key', 'ConfigurationId')),
    @('si_affected_product', @('si_affected_product', 'SI_AffectedProduct')), @('si_affected_vendor', @('si_affected_vendor', 'SI_AffectedVendor')),
    @('si_affected_version', @('si_affected_version', 'SI_AffectedVersion')), @('si_affected_cpe', @('si_affected_cpe', 'SI_AffectedCpe')),
    # #772 the report that found it (a ServiceNow sub-CI rule may route by report)
    @('si_report_name', @('si_report_name', 'AssetDetectedInReportName', 'ReportName')))
$script:SIFindingItemReadNames = @(@($script:SIFindingItemPairs | ForEach-Object { $_[1] }) + @('si_azure_resource_type', 'AssetType', 'AzureResourceId', 'ResourceId', 'AssetId', 'AssetName'))

function Get-SIFindingDimensionValues {
    <#
    .SYNOPSIS  PURE. Every finding target over one finding item -> ordered @{ <target field> = value } plus '_rules'
               (target field -> the deciding row id or 'fallback'). One value per target, never blank.
    #>
    param([Parameter(Mandatory)]$Item, [Parameter(Mandatory)]$Index, [hashtable]$Context)
    $out = [ordered]@{}
    $rules = [ordered]@{}
    foreach ($t in @($Index.Targets)) {
        if ($t.AppliesTo -ne 'finding') { continue }
        $r = Get-SIClassificationValue -Target $t -Item $Item -Context $Context
        if (@($r.Values).Count) { $out[$t.Field] = [string]$r.Values[0]; $rules[$t.Field] = [string]$r.Rules[0] }
        else { $out[$t.Field] = $t.Fallback; $rules[$t.Field] = 'fallback' }
        # #772 each value is written before the next target is evaluated (as the asset targets are), so a later finding target
        # reads an earlier one -- the ServiceNow sub-CI reads the finding's component
        if ($Item -is [System.Collections.IDictionary]) { $Item[$t.Field] = $out[$t.Field] }
    }
    $out['_rules'] = $rules
    $out
}

$script:SIClassificationIndexCache = $null

# =====================================================================================================================
# #772 THE PATCH CYCLE (owner 2026-10-19: "we need a filter option, where we filter between 'being fixed during monthly
# lifecycle' vs. 'catch-up older than 1 month'"). si_patch_cycle is a finding target of the classification like every
# other dimension -- its values and which facts give which value are DATA (data-model/classification.locked.json, rows
# patch-cycle-*; the customer's overrides as for any row). What is CODE is the two facts the rows read, worked out once here
# for both editions:
#   si_patch_fix   'none' when the source says no fix exists (si_fix_available false, or a fix text such as "No fix")
#   si_patch_age   'within' | 'over' -- the fix's RELEASE date (the month a "<Month> <Year> Security Updates" / "2026-10
#                  Cumulative Update" text names -> that month's Patch Tuesday, the 2nd Tuesday; an explicit date wins,
#                  e.g. an out-of-band update), else the finding's age since it was first detected, against
#                  SI_PatchCycle_CatchUpDays (default 30; exactly the threshold is still within) at the collection time.
# Nothing known -> neither fact -> the target's fallback (Unknown).
# =====================================================================================================================

function Get-SIPatchCycleCatchUpDays {
    <# The catch-up threshold in days: SI_PatchCycle_CatchUpDays (a whole number of at least 1), else 30. #>
    $v = $global:SI_PatchCycle_CatchUpDays
    $n = 0
    if ($null -ne $v -and [int]::TryParse(([string]$v).Trim(), [ref]$n) -and $n -ge 1) { return $n }
    30
}

function Get-SIPatchTuesday {
    <# PURE. The second Tuesday of a month (UTC midnight) -- Microsoft's monthly security release. #>
    param([Parameter(Mandatory)][int]$Year, [Parameter(Mandatory)][int]$Month)
    $first = [datetime]::new($Year, $Month, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
    $off = (([int][System.DayOfWeek]::Tuesday) - ([int]$first.DayOfWeek) + 7) % 7
    $first.AddDays($off + 7)
}

$script:SIPatchMonths = @{ jan = 1; feb = 2; mar = 3; apr = 4; may = 5; jun = 6; jul = 7; aug = 8; sep = 9; oct = 10; nov = 11; dec = 12 }

function ConvertFrom-SIFixReleaseDate {
    <#
    .SYNOPSIS  PURE. The release date a fix text names, or $null: an explicit date (2026-10-21, an out-of-band update) as it
               is; a month -- "October 2026 Security Updates", "Oct 2026 (Hotpatch)", "2026-10 Cumulative Update for
               Windows 11 (KB5127648)", "2026-10 Out-of-band update" -- as that month's Patch Tuesday. Several updates
               (';'-joined): the newest one. A KB number alone names no date.
    #>
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $best = $null
    foreach ($part in $Text.Split(';')) {
        $p = $part.Trim(); if (-not $p) { continue }
        $d = $null
        $m = [regex]::Match($p, '(?<!\d)(20\d{2})-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])(?!\d)')
        if ($m.Success) {
            try { $d = [datetime]::new([int]$m.Groups[1].Value, [int]$m.Groups[2].Value, [int]$m.Groups[3].Value, 0, 0, 0, [System.DateTimeKind]::Utc) } catch { $d = $null }
        }
        if ($null -eq $d) {
            $m = [regex]::Match($p, '(?i)\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s*,?\s*(20\d{2})\b')
            if ($m.Success) { $d = Get-SIPatchTuesday -Year ([int]$m.Groups[2].Value) -Month $script:SIPatchMonths[$m.Groups[1].Value.ToLowerInvariant()] }
        }
        if ($null -eq $d) {
            $m = [regex]::Match($p, '(?<!\d)(20\d{2})-(0[1-9]|1[0-2])(?![\d-])')
            if ($m.Success) { $d = Get-SIPatchTuesday -Year ([int]$m.Groups[1].Value) -Month ([int]$m.Groups[2].Value) }
        }
        if ($null -ne $d -and ($null -eq $best -or $d -gt $best)) { $best = $d }
    }
    $best
}

function ConvertTo-SIPatchDate {
    <# PURE. A date value of a row (a datetime, or ISO / invariant text) as UTC, or $null. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) { $d = [datetime]$Value; if ($d.Kind -eq [System.DateTimeKind]::Unspecified) { $d = [datetime]::SpecifyKind($d, [System.DateTimeKind]::Utc) }; return $d.ToUniversalTime() }
    $s = ([string]$Value).Trim(); if (-not $s) { return $null }
    $o = [datetime]::MinValue
    if ([datetime]::TryParse($s, [System.Globalization.CultureInfo]::InvariantCulture, ([System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal), [ref]$o)) { return [datetime]::SpecifyKind($o, [System.DateTimeKind]::Utc) }
    $null
}

$script:SIPatchFixTextNames = @('si_fix_recommended_update', 'RecommendedSecurityUpdate', 'SI_FixReference', 'si_fix_reference')
$script:SIPatchFixDateNames = @('si_fix_release_date', 'FixReleaseDate', 'si_fix_published')
# #906: si_source_first_seen is the field Risk Analysis writes (RA-SourceFirstSeen.ps1, Defender's software vulnerabilities
# export) -- without it here every browser / third-party CVE (no dated update) had no age and fell to Unknown
$script:SIPatchFirstNames = @('si_first_detected', 'si_source_first_seen', 'si_source_first_detected', 'FirstDetected', 'FirstSeenTimestamp', 'FirstSeen', 'si_first_seen')
$script:SIPatchUpdateNames = @('si_fix_recommended_update', 'RecommendedSecurityUpdate', 'si_fix_recommended_update_id', 'RecommendedSecurityUpdateId')
$script:SIPatchNowNames = @('si_collection_time', 'CollectionTime')

function Get-SIPatchCycleFacts {
    <#
    .SYNOPSIS  PURE. The two facts the patch-cycle rows read, from one finding row: @{ si_patch_fix = 'none' | ''; si_patch_age =
               'within' | 'over' | ''; Basis = 'fix release' | 'first detected' | ''; ReleaseDate; AgeDays }.
               -Now: the collection time (default: the row's, else now); -CatchUpDays: the threshold (default the setting).
    #>
    param([Parameter(Mandatory)]$Row, $Now, [int]$CatchUpDays = 0)
    $g = { param([string]$n) if ($Row -is [System.Collections.IDictionary]) { if ($Row.Contains($n)) { $Row[$n] } else { $null } } elseif ($null -ne $Row.PSObject.Properties[$n]) { $Row.$n } else { $null } }
    if ($CatchUpDays -lt 1) { $CatchUpDays = Get-SIPatchCycleCatchUpDays }
    $out = @{ si_patch_fix = ''; si_patch_age = ''; Basis = ''; ReleaseDate = $null; AgeDays = $null }
    $fixText = ''
    foreach ($n in $script:SIPatchFixTextNames) { $v = & $g $n; if ($null -ne $v -and ([string]$v).Trim()) { $fixText = ([string]$v).Trim(); break } }
    $avail = ConvertTo-SIBoolOrNull (& $g 'si_fix_available')
    if ($avail -eq $false -or $fixText -match '^(?i)(no (known )?(fix|patch|security update|update|remediation)( available)?|none|not available|n/?a)\.?$') {
        $out.si_patch_fix = 'none'; return $out
    }
    $at = $null
    foreach ($n in $script:SIPatchNowNames) { $at = ConvertTo-SIPatchDate (& $g $n); if ($null -ne $at) { break } }
    if ($null -ne $Now) { $at = ConvertTo-SIPatchDate $Now }
    if ($null -eq $at) { $at = [datetime]::UtcNow }
    $rel = $null
    foreach ($n in $script:SIPatchFixDateNames) { $rel = ConvertTo-SIPatchDate (& $g $n); if ($null -ne $rel) { break } }
    $basis = 'fix release'
    # #772 (owner: "read the fix release date"): a Microsoft update's own release date by its KB (the Security Update Guide,
    # Get-SIKbReleaseDate -- Defender names the KB, never its date), before the month the update's name says
    if ($null -eq $rel) {
        $kbs = [System.Collections.Generic.List[string]]::new()
        foreach ($n in 'si_fix_recommended_update_id', 'RecommendedSecurityUpdateId') { $v = & $g $n; if ($null -ne $v) { foreach ($x in (Get-SIKbKeysFromText ([string]$v))) { $kbs.Add($x) } } }
        if ($fixText) { foreach ($x in (Get-SIKbKeysFromText $fixText)) { $kbs.Add($x) } }
        if ($kbs.Count) { $rel = Get-SIKbReleaseDate -Kbs $kbs.ToArray(); if ($null -ne $rel) { $basis = 'kb release' } }
    }
    if ($null -eq $rel -and $fixText) { $rel = ConvertFrom-SIFixReleaseDate $fixText }
    if ($null -eq $rel) {
        $basis = 'first detected'
        foreach ($n in $script:SIPatchFirstNames) { $rel = ConvertTo-SIPatchDate (& $g $n); if ($null -ne $rel) { break } }
    }
    if ($null -eq $rel) {
        # #906: no dated update and no first-seen. A finding that names NO recommended update (no update name, no update id --
        # a generic fix text such as "Update the affected software ..." is no update) has no single update: group 3, the same
        # rule as the SQL twin and SI-PatchCycle.ps1 (no update = nofix). Unknown stays only for an update whose month
        # cannot be read (a KB number alone, an update name without a month).
        $hasUpd = $false
        foreach ($n in $script:SIPatchUpdateNames) { $v = & $g $n; if ($null -ne $v -and -not ($v -is [System.DBNull]) -and ([string]$v).Trim()) { $hasUpd = $true; break } }
        if (-not $hasUpd) { $out.si_patch_fix = 'none' }
        return $out
    }
    $age = ($at - $rel).TotalDays
    $out.Basis = $basis; $out.ReleaseDate = $rel; $out.AgeDays = [Math]::Floor($age)
    # exactly the threshold is still in the cycle: catch-up is OLDER than it
    $out.si_patch_age = $(if ($age -gt $CatchUpDays) { 'over' } else { 'within' })
    $out
}

function Add-SIPatchCycleFacts {
    <# The patch cycle's facts onto a finding classification item (only the ones that are known). The collection time is the
       run's (RA_CollectionTime) when Risk Analysis set it. Never throws. #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Item, [Parameter(Mandatory)]$Row)
    try {
        $now = $null; if ($null -ne $global:RA_CollectionTime) { $now = $global:RA_CollectionTime }
        $f = Get-SIPatchCycleFacts -Row $Row -Now $now
        foreach ($k in 'si_patch_fix', 'si_patch_age') { if ($f[$k]) { $Item[$k] = $f[$k] } }
        if ($Row -is [System.Collections.IDictionary]) {
            # the fix's release date when the Security Update Guide gave it (si_fix_release_date), and the CVE's published date
            # as its own field (si_cve_published: exposure age -- the patch cycle never reads it)
            if ($f.Basis -eq 'kb release' -and -not $Row.Contains('si_fix_release_date')) { $Row['si_fix_release_date'] = ([datetime]$f.ReleaseDate).ToString('yyyy-MM-dd') }
            if (-not $Row.Contains('si_cve_published')) {
                foreach ($pn in 'si_published', 'PublishedDate', 'CVEPublishedDate', 'si_published_date') {
                    $pv = $null; if ($Row.Contains($pn)) { $pv = ConvertTo-SIPatchDate $Row[$pn] }
                    if ($null -ne $pv) { $Row['si_cve_published'] = $pv.ToString('yyyy-MM-ddTHH:mm:ssZ', [System.Globalization.CultureInfo]::InvariantCulture); break }
                }
            }
        }
    } catch { }
    $Item
}

function Set-SIRaRowOsFamily {
    <#
    .SYNOPSIS  #772. A finding carries its asset's OS family (si_os_family, set on the row by the CI context). A row without
               one -- no CI was found for its asset -- is classified from its OWN OS fields (si_os_platform / OSPlatform,
               si_os_name / OSName / OsVersion..., DeviceCategory) with the SAME rows as the CIs (the asset target
               si_os_family); nothing known = the fallback (Unknown). No OS family target in the model = the row is left as
               it is. Never throws.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Row, $Index)
    try {
        if ($Row.Contains('si_os_family') -and -not (Test-SIValueEmpty $Row['si_os_family'])) { return $Row }
        if ($null -eq $Index) { return $Row }
        $t = $null
        foreach ($x in @($Index.Targets)) { if ($x.Field -eq 'si_os_family') { $t = $x; break } }
        if ($null -eq $t) { return $Row }
        $item = @{}
        foreach ($p in $script:SIOsFamilyRowPairs) {
            foreach ($src in $p[1]) {
                $v = $null; if ($Row.Contains($src)) { $v = $Row[$src] }
                if ($null -ne $v -and ([string]$v).Trim()) { $item[$p[0]] = ([string]$v).Trim(); break }
            }
        }
        $ck = 'osf' + [char]31 + [string]$item['si_os_platform'] + [char]31 + [string]$item['si_os_name'] + [char]31 + [string]$item['si_device_category']
        $val = $null
        if ($null -ne $Index.Cache -and $Index.Cache.ContainsKey($ck)) { $val = [string]$Index.Cache[$ck] }
        else {
            $r = Get-SIClassificationValue -Target $t -Item $item
            $val = $t.Fallback; if (@($r.Values).Count) { $val = [string]$r.Values[0] }
            if ($null -ne $Index.Cache) { $Index.Cache[$ck] = $val }
        }
        if ($val) { $Row['si_os_family'] = $val }
    } catch { }
    $Row
}
$script:SIOsFamilyRowPairs = @(
    @('si_os_platform', @('si_os_platform', 'OSPlatform', 'OsPlatform', 'DeviceOsPlatform')),
    @('si_os_name', @('si_os_name', 'OSName', 'OsName', 'OperatingSystem', 'OSVersion', 'OsVersion')),
    @('si_device_category', @('si_device_category', 'DeviceCategory')))

function Get-SIClassificationIndex {
    <#
    .SYNOPSIS  The merged templates (shipped + the customer's) as an index, read once per process; $null when there are none
               or they cannot be read (nothing is classified -- never fails). -Refresh re-reads.
    #>
    param([string]$Root, [string]$OverlayRoot = $global:SI_DataModelOverlayRoot, [switch]$Refresh)
    if ($script:SIClassificationIndexCache -and -not $Refresh -and -not $Root) { return $script:SIClassificationIndexCache }
    try {
        if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1') }
        $r = Get-SIDataModelRoot $Root
        if (-not (Test-Path -LiteralPath (Join-Path $r 'classification.locked.json'))) {
            # Pro: a data model exported before these templates were published -- the shipped templates (no override yet)
            $r = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model'
            if (-not (Test-Path -LiteralPath (Join-Path $r 'classification.locked.json'))) { return $null }
        }
        $d = (Get-SIDataModelTemplate -Name 'dimensions' -Root $r -OverlayRoot $OverlayRoot).Document
        $c = (Get-SIDataModelTemplate -Name 'classification' -Root $r -OverlayRoot $OverlayRoot).Document
        foreach ($p in (Test-SIClassifications -Dimensions $d -Classification $c)) { Write-Warning ('classification: {0} -- not applied' -f $p) }
        $idx = New-SIClassificationIndex -Dimensions $d -Classification $c
        if (-not $Root) { $script:SIClassificationIndexCache = $idx }
        return $idx
    } catch {
        Write-Warning ('classification could not be read -- {0}. Findings get the fallback values.' -f $_.Exception.Message)
        return $null
    }
}

function Set-SIRaRowDimensions {
    <#
    .SYNOPSIS  Risk Analysis, per output row (RA-RiskScore.ps1): the row's finding targets (si_component, ...) from the
               classification rows. -Index: a prepared index (tests); default the cached one. A row the rows cannot classify
               gets each target's fallback; no index at all = the row is left as it is. Never throws.
    #>
    param([Parameter(Mandatory)][System.Collections.IDictionary]$Row, $Index)
    try {
        if ($null -eq $Index) { $Index = Get-SIClassificationIndex }
        if ($null -eq $Index) { return $Row }
        $item = ConvertTo-SIFindingClassificationItem -Row $Row -WithRow:([bool]$Index.HasSourcePath)
        # #772 the patch cycle's two facts (the rows patch-cycle-* read them): the fix's release / the finding's age
        $null = Add-SIPatchCycleFacts -Item $item -Row $Row
        # the same finding fields classify the same way: one evaluation per distinct combination (a report's rows repeat them)
        $vals = $null; $ck = $null
        if (-not $Index.HasSourcePath -and $null -ne $Index.Cache) {
            # PERFORMANCE: the cache key is the values of the fields the finding rows' conditions READ (worked out once per
            # index), not of every field of the item -- a value no condition reads (the affected version, the finding key)
            # cannot change the result, and keying on it made almost every row of a CVE report a miss. Built in a loop.
            $kfp = $Index.PSObject.Properties['SIKeyFields']
            if (-not $kfp) {
                $kfSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($kt in @($Index.Targets)) {
                    if ($null -eq $kt -or $kt.AppliesTo -ne 'finding') { continue }
                    foreach ($kr in $kt.Rules) { foreach ($kfn in (Get-SIConditionFields $kr.Condition)) { [void]$kfSet.Add([string]$kfn) } }
                }
                $kfArr = [string[]]@($kfSet)
                [System.Array]::Sort($kfArr, [System.StringComparer]::Ordinal)
                Add-Member -InputObject $Index -NotePropertyName 'SIKeyFields' -NotePropertyValue $kfArr -Force
                $kfp = $Index.PSObject.Properties['SIKeyFields']
            }
            $ckParts = [System.Collections.Generic.List[string]]::new()
            $ckParts.Add('k2')
            foreach ($ckn in $kfp.Value) {
                $ckv = $item[$ckn]
                $ckText = '~'
                if ($null -ne $ckv) {
                    if ($ckv -is [string] -or $ckv -is [System.Collections.IDictionary] -or -not ($ckv -is [System.Collections.IEnumerable])) { $ckText = 's' + [string]$ckv }
                    else { $ckl = [System.Collections.Generic.List[object]]::new(); foreach ($x in $ckv) { if ($null -ne $x) { $ckl.Add($x) } }; $ckText = 'l' + $ckl.Count + ':' + ($ckl -join [char]30) }
                }
                $ckParts.Add(('{0}={1}' -f $ckn, $ckText))
            }
            $ck = $ckParts -join [char]31
            if ($Index.Cache.ContainsKey($ck)) { $vals = $Index.Cache[$ck] }
        }
        if ($null -eq $vals) {
            $vals = Get-SIFindingDimensionValues -Item $item -Index $Index
            if ($null -ne $ck) { if ($Index.Cache.Count -ge 20000) { $Index.Cache.Clear() }; $Index.Cache[$ck] = $vals }
        }
        foreach ($k in @($vals.Keys)) { if ($k -ne '_rules') { $Row[$k] = $vals[$k] } }
        # #772 the OS family: the asset's (the CI context set it); a row no CI was found for, from its own OS fields
        $null = Set-SIRaRowOsFamily -Row $Row -Index $Index
        foreach ($k in 'si_affected_product', 'si_affected_vendor', 'si_affected_version', 'si_affected_cpe') {
            if ($item.ContainsKey($k) -and -not $Row.Contains($k)) { $Row[$k] = ((Get-SIValueList $item[$k]) -join ';') }
        }
    } catch { }
    $Row
}
