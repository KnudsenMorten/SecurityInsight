#Requires -Version 5.1
<#
    SecurityInsight data-model templates: load, merge customer overrides PER ITEM, flag conflicts, and validate.
    V3-DATA-MODEL part 2 (2.4.5). Folder: <solution>\data-model\

      <name>.locked.json    shipped by Invardia, updated automatically (never edit)
      <name>.custom.json    the customer's overrides: the SAME shape, holding only the items that differ
                            (Community: on disk, never shipped, never overwritten; Pro: materialised from the settings
                            database into an overlay folder the same way)

    MERGE RULES -- the same for every template kind; only the item key differs (Get-SIDataModelItemKey):
      * a custom item with the same key REPLACES the shipped item (override); "remove": true drops it (disabled)
      * a custom item with a new key is ADDED (the customer's own)
      * a custom item may carry "baseHash" = the hash of the shipped item it was written against. When the shipped
        item has changed since, the item's state is UpgradeAvailable: the override still wins, and the change is
        flagged for review -- never merged silently (same states as the Pro template store:
        UpToDate | Overridden | Disabled | UpgradeAvailable | Own)
      * value maps merge one level deeper (per key inside a map); the trust list keeps the shipped ORDER and a custom
        entry changes trust by id (silence = inherit), and may move with "after": <id>

    PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

. (Join-Path $PSScriptRoot 'SI-Conditions.ps1')
. (Join-Path $PSScriptRoot 'SI-FieldMapper.ps1')
. (Join-Path $PSScriptRoot 'SI-RiskFactorCatalog.ps1')
# #561 / #562 the one classification mechanism (asset type / subtype, dimensions)
. (Join-Path $PSScriptRoot 'SI-Classification.ps1')
# #560 the generic SI finding fields of SI's own reports, as data
. (Join-Path $PSScriptRoot 'SI-FindingTexts.ps1')
# the Azure CI scope and the child resources that roll up into their parent (collection-scope rollUpInto, validated below)
. (Join-Path $PSScriptRoot 'SI-AzureChildren.ps1')

function Get-SIDataModelRoot {
    param([string]$Root)
    if ($Root) { return $Root }
    # #456 Pro: the run's data model from the settings database (templates + the customer's overrides), materialised by
    # the settings layer (Export-SIDataModelProRoot) -- the shipped folder is then not read
    if ($global:SI_DataModelRoot -and (Test-Path -LiteralPath ([string]$global:SI_DataModelRoot))) { return [string]$global:SI_DataModelRoot }
    return (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model')
}

function Get-SIDataModelItemHash {
    <# SHA-256 of an item's compact JSON -- what a custom item's baseHash refers to. #>
    param($Item)
    $json = $Item | ConvertTo-Json -Compress -Depth 30
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($json))) -replace '-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-SIDataModelItemKey {
    <# The key that identifies one item of a template kind (what a custom override matches on). #>
    param([string]$Kind, $Item)
    switch ($Kind) {
        'field-catalog' { return [string]$Item.name }
        'field-mapping' {
            $rt = @($Item.recordTypes) -join ','
            $res = @(Get-SIItemValue $Item 'resourceTypes') -join ','
            return ('{0}|{1}|{2}' -f $Item.field, $rt, $res)
        }
        'output-map' { return [string]$Item.target }
        'collection-scope' { return [string]$Item.type }
        default { return [string]$Item.id }
    }
}

function Get-SIDataModelItemArrayName {
    <# Which array of a template holds its items. #>
    param([string]$Kind)
    switch ($Kind) {
        'field-catalog' { 'fields' } 'field-mapping' { 'mappings' } 'risk-factor' { 'factors' } 'list' { 'lists' }
        'output-map' { 'columns' } 'trust' { 'order' } 'coverage-check' { 'checks' } 'collection-scope' { 'azureResourceTypes' }
        # #462 a CI rule pack (one rule per id); #464 the recommendation equivalence (one group per id)
        'ci-rule-pack' { 'rules' } 'recommendation-equivalence' { 'groups' } 'report-scope' { 'reports' }
        'relation' { 'relations' }
        # #546 the default exclusion rules for known false positives of a provider's recommendation
        'recommendation-exclusion' { 'rules' }
        # #561 / #562 the classification dimensions (one per id: its values) and the classification rows (one per id)
        'dimension' { 'dimensions' } 'classification' { 'rules' }
        # #560 the finding texts of SI's own reports (one item per report)
        'finding-text' { 'reports' }
        # #690 (15) the severity model: one item per report (its ordered metric kinds + its own severity)
        'severity-model' { 'reports' }
        default { $null }
    }
}

function Merge-SIDataModelItems {
    <# Merges one item array: shipped + custom -> merged list + per-item state. #>
    param([string]$Kind, $Locked, $Custom)
    $states = New-Object System.Collections.Generic.List[object]
    # A field mapping may hold SEVERAL items for one field and record type (eg: four si_device_roles|device items, each
    # a different flag, unioned by the mapper). They used to share one key, so only the last survived the merge. Each
    # repeat now gets its own key -- the first keeps the plain key (existing overrides still match it), the n-th is
    # '<key>#<n>' -- and a custom file's n-th item with that key overrides the shipped n-th. The mapper then merges the
    # items by the field's own rule (union for a list field, first-wins for a single value). Other kinds keep one item
    # per key: a repeat there is a template error the validator reports.
    $occ = @{}
    $keyOf = {
        param($item, $counts)
        $base = Get-SIDataModelItemKey $Kind $item
        if ($Kind -ne 'field-mapping') { return $base }
        $n = 1; if ($counts.ContainsKey($base)) { $n = [int]$counts[$base] + 1 }
        $counts[$base] = $n
        if ($n -eq 1) { return $base }
        return ('{0}#{1}' -f $base, $n)
    }
    $byKey = [ordered]@{}
    foreach ($it in @($Locked)) { if ($null -ne $it) { $byKey[(& $keyOf $it $occ)] = $it } }
    $result = [ordered]@{}
    foreach ($k in $byKey.Keys) { $result[$k] = $byKey[$k] }
    $customKeys = @{}
    $occC = @{}
    foreach ($c in @($Custom)) {
        if ($null -eq $c) { continue }
        $k = & $keyOf $c $occC
        $customKeys[$k] = $true
        $remove = (ConvertTo-SIBoolOrNull (Get-SIItemValue $c 'remove')) -eq $true
        if ($byKey.Contains($k)) {
            $lockedHash = Get-SIDataModelItemHash $byKey[$k]
            $base = [string](Get-SIItemValue $c 'baseHash')
            $state = 'Overridden'
            if ($remove) { $state = 'Disabled' }
            if ($base -and $base -ne $lockedHash) { $state = 'UpgradeAvailable' }
            $states.Add([pscustomobject]@{ Key = $k; State = $state; LockedHash = $lockedHash; BaseHash = $base })
            if ($remove) { $result.Remove($k) } else { $result[$k] = $c }
        } else {
            if (-not $remove) { $result[$k] = $c; $states.Add([pscustomobject]@{ Key = $k; State = 'Own'; LockedHash = $null; BaseHash = $null }) }
        }
    }
    foreach ($k in $byKey.Keys) { if (-not $customKeys.ContainsKey($k)) { $states.Add([pscustomobject]@{ Key = $k; State = 'UpToDate'; LockedHash = $null; BaseHash = $null }) } }
    return @{ Items = @($result.Values); States = $states.ToArray() }
}

function Merge-SITrustOrder {
    <# The trust list: shipped order; a custom entry changes fields by id; "after": <id> moves it; a new id is appended (or placed after). #>
    param($Locked, $Custom)
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($Locked)) { $list.Add(($e | ConvertTo-Json -Depth 10 | ConvertFrom-Json)) }
    foreach ($c in @($Custom)) {
        $id = [string]$c.id
        $idx = -1
        for ($i = 0; $i -lt $list.Count; $i++) { if ([string]$list[$i].id -eq $id) { $idx = $i; break } }
        $entry = $null
        if ($idx -ge 0) {
            $entry = $list[$idx]
            foreach ($p in $c.PSObject.Properties) { if ($p.Name -notin 'id', 'after') { $entry | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force } }
            $list.RemoveAt($idx)
        } else { $entry = $c }
        $after = [string](Get-SIItemValue $c 'after')
        $at = $idx
        if ($after) { for ($i = 0; $i -lt $list.Count; $i++) { if ([string]$list[$i].id -eq $after) { $at = $i + 1; break } } }
        if ($at -lt 0 -or $at -gt $list.Count) { $at = $list.Count }
        $list.Insert($at, $entry)
    }
    return , $list.ToArray()
}

function Read-SIJsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $text = [System.IO.File]::ReadAllText($Path)
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    try { return ($text | ConvertFrom-Json) } catch { throw "data-model template ${Path}: not valid JSON -- $($_.Exception.Message)" }
}

function Get-SIDataModelTemplate {
    <#
    .SYNOPSIS  One template (shipped + customer overrides), merged.
    .PARAMETER Name         the file name without .locked.json, e.g. 'field-catalog', 'mappings/mde', 'outputs/servicenow-ci'
    .PARAMETER OverlayRoot  where the customer's *.custom.json live (default: next to the shipped file)
    .OUTPUTS   @{ Document; States; Kind; Name }
    #>
    param([Parameter(Mandatory)][string]$Name, [string]$Root, [string]$OverlayRoot)
    $Root = Get-SIDataModelRoot $Root
    $lockedPath = Join-Path $Root ($Name + '.locked.json')
    $locked = Read-SIJsonFile $lockedPath
    if ($null -eq $locked) { throw "data-model template '$Name' not found ($lockedPath)" }
    $customRoot = $Root; if ($OverlayRoot) { $customRoot = $OverlayRoot }
    $custom = Read-SIJsonFile (Join-Path $customRoot ($Name + '.custom.json'))
    $kind = [string]$locked.kind
    $doc = $locked | ConvertTo-Json -Depth 30 | ConvertFrom-Json      # a copy: callers may change it
    $states = @()
    if ($null -ne $custom) {
        if ($custom.kind -and [string]$custom.kind -ne $kind) { throw "data-model override '$Name': kind '$($custom.kind)' does not match '$kind'" }
        $arr = Get-SIDataModelItemArrayName $kind
        if ($kind -eq 'trust') {
            $doc.order = Merge-SITrustOrder -Locked $locked.order -Custom $custom.order
        } elseif ($kind -eq 'value-map') {
            foreach ($mp in $custom.maps.PSObject.Properties) {
                $target = $doc.maps.PSObject.Properties[$mp.Name]
                if ($null -eq $target) { $doc.maps | Add-Member -NotePropertyName $mp.Name -NotePropertyValue $mp.Value; continue }
                foreach ($kv in $mp.Value.PSObject.Properties) { $target.Value | Add-Member -NotePropertyName $kv.Name -NotePropertyValue $kv.Value -Force }
            }
        } elseif ($kind -eq 'criticality-mapping') {
            foreach ($sect in 'criticality', 'dataSensitivity') {
                $cs = Get-SIItemValue $custom $sect
                if ($null -eq $cs) { continue }
                foreach ($prov in $cs.PSObject.Properties) {
                    if ($prov.Name.StartsWith('$')) { continue }
                    $doc.$sect | Add-Member -NotePropertyName $prov.Name -NotePropertyValue $prov.Value -Force   # a provider's vocabulary is replaced as a whole
                }
            }
            foreach ($p in 'defaultFactor', 'combine', 'cap') { $v = Get-SIItemValue $custom $p; if ($null -ne $v) { $doc.$p = $v } }
        } elseif ($arr) {
            $m = Merge-SIDataModelItems -Kind $kind -Locked $locked.$arr -Custom $custom.$arr
            $doc.$arr = $m.Items
            $states = $m.States
            if ($kind -eq 'collection-scope' -and $custom.providers) {
                foreach ($pp in $custom.providers.PSObject.Properties) { $doc.providers | Add-Member -NotePropertyName $pp.Name -NotePropertyValue $pp.Value -Force }
            }
        }
    }
    return @{ Document = $doc; States = $states; Kind = $kind; Name = $Name }
}

function Get-SIDataModel {
    <#
    .SYNOPSIS  Every data-model template, merged, in one object the pipeline steps share.
    #>
    param([string]$Root, [string]$OverlayRoot)
    $Root = Get-SIDataModelRoot $Root
    $model = [ordered]@{ Root = $Root; Mappings = [ordered]@{}; Outputs = [ordered]@{}; States = [ordered]@{} }
    foreach ($n in 'field-catalog', 'value-maps', 'risk-factors', 'lists', 'trust', 'criticality-mapping', 'collection-scope', 'coverage-checks', 'report-scope') {
        # #541: report-scope is Risk Analysis's -- optional, so a run folder materialised before the template was published
        # (Pro, the first run after the update) still loads; Risk Analysis then reads the shipped copy (RA-ScopePreamble.ps1)
        if ($n -eq 'report-scope' -and -not (Test-Path -LiteralPath (Join-Path $Root ($n + '.locked.json')))) { continue }
        $t = Get-SIDataModelTemplate -Name $n -Root $Root -OverlayRoot $OverlayRoot
        $model[$n] = $t.Document
        $model.States[$n] = $t.States
    }
    # the relations between CIs (#493, the asset graph): a template like the others; a data-model folder without it (a test
    # root, a model materialised before it existed) has no relations, never an error
    if (Test-Path -LiteralPath (Join-Path $Root 'relations.locked.json')) {
        $t = Get-SIDataModelTemplate -Name 'relations' -Root $Root -OverlayRoot $OverlayRoot
        $model['relations'] = $t.Document
        $model.States['relations'] = $t.States
    } else {
        $model['relations'] = [pscustomobject]@{ kind = 'relation'; version = '0'; relations = @() }
    }
    # #561 / #562 the classification dimensions and rows: optional -- a data-model folder without them (a test root, a model
    # materialised before they were published) classifies nothing, never an error
    foreach ($n in 'dimensions', 'classification', 'finding-texts', 'severity-model') {
        if (-not (Test-Path -LiteralPath (Join-Path $Root ($n + '.locked.json')))) { continue }
        $t = Get-SIDataModelTemplate -Name $n -Root $Root -OverlayRoot $OverlayRoot
        $model[$n] = $t.Document
        $model.States[$n] = $t.States
    }
    foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $Root 'mappings') -Filter '*.locked.json' | Sort-Object Name)) {
        $n = 'mappings/' + $f.Name.Replace('.locked.json', '')
        $t = Get-SIDataModelTemplate -Name $n -Root $Root -OverlayRoot $OverlayRoot
        $model.Mappings[[string]$t.Document.provider] = $t.Document
        $model.States[$n] = $t.States
    }
    foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $Root 'outputs') -Filter '*.locked.json' | Sort-Object Name)) {
        $n = 'outputs/' + $f.Name.Replace('.locked.json', '')
        $t = Get-SIDataModelTemplate -Name $n -Root $Root -OverlayRoot $OverlayRoot
        $model.Outputs[[string]$t.Document.id] = $t.Document
        $model.States[$n] = $t.States
    }
    return $model
}

function Get-SIDataModelStatusLine {
    <#
    .SYNOPSIS  PURE. One plain line about the customer's data-model overrides (Community *.custom.json): how many items are
               overridden / own / disabled, and which templates hold an override whose shipped item changed since it was
               written (UpgradeAvailable -- review it; it is never merged). '' when nothing is overridden.
    #>
    param([Parameter(Mandatory)]$Model)
    $c = @{ Overridden = 0; Own = 0; Disabled = 0; UpgradeAvailable = 0 }
    $up = New-Object System.Collections.Generic.List[string]
    foreach ($n in @($Model.States.Keys)) {
        foreach ($s in @($Model.States[$n])) {
            if ($null -eq $s -or -not $c.ContainsKey([string]$s.State)) { continue }
            $c[[string]$s.State]++
            if ($s.State -eq 'UpgradeAvailable') { $up.Add(('{0}:{1}' -f $n, $s.Key)) }
        }
    }
    if (($c.Overridden + $c.Own + $c.Disabled + $c.UpgradeAvailable) -eq 0) { return '' }
    $line = 'data model: your overrides are in force -- {0} overridden, {1} own, {2} removed' -f ($c.Overridden + $c.UpgradeAvailable), $c.Own, $c.Disabled
    if ($up.Count) { $line += ('; {0} of them were written against an older shipped item (UpgradeAvailable -- compare and keep yours or take ours): {1}' -f $up.Count, (@($up | Select-Object -First 5) -join ', ')) }
    return $line
}

function Get-SIDataModelListContext {
    <# The condition context's Lists hashtable from the merged lists template. #>
    param($Model)
    $lists = @{}
    foreach ($l in @($Model['lists'].lists)) { $lists[[string]$l.id] = $l }
    return $lists
}

function Get-SIOutputMapOps { return , @('enum', 'first', 'join', 'join_ids', 'render', 'format_date', 'round', 'mask', 'domain_part', 'if_class', 'lower', 'upper') }

function Test-SIDataModel {
    <#
    .SYNOPSIS  Validates every template against every other. Returns a list of problems ("<template>: <problem>"); empty = valid.
               What it proves: every field a mapping, factor, rule, check or output names exists in the catalog at the right
               level and class; every operation is in its closed set; every value map and list a template names exists.
    #>
    param($Model)
    $p = New-Object System.Collections.Generic.List[string]
    $cat = $Model['field-catalog']
    $validClasses = @($cat.classes) + 'finding'
    $validTypes = 'string', 'bool', 'int', 'real', 'datetime', 'dynamic'
    $validLevels = @($cat.levels.PSObject.Properties.Name)
    $validPolicies = @($cat.policies.PSObject.Properties.Name)
    $providers = @($cat.providers) + @($cat.authorityTokens.PSObject.Properties.Name)
    $fields = @{}
    foreach ($f in @($cat.fields)) {
        $n = [string]$f.name
        if ($fields.ContainsKey($n)) { $p.Add("field-catalog: '$n' is defined twice") }
        $fields[$n] = $f
        if ($n -cnotmatch '^[a-z][a-z0-9_]*$') { $p.Add("field-catalog: '$n' is not lower snake_case") }
        if ($n -notmatch '^(si_|properties_)' -and -not ($providers -contains ($n.Split('_')[0])) -and $n -notmatch '^cmdb_record_id$') { $p.Add("field-catalog: '$n' has no owner prefix (si_ or a provider)") }
        if ($validTypes -notcontains [string]$f.type) { $p.Add("field-catalog: '$n' has type '$($f.type)'") }
        if ($validLevels -notcontains [string]$f.level) { $p.Add("field-catalog: '$n' has level '$($f.level)'") }
        foreach ($c in @($f.classes)) { if ($validClasses -notcontains [string]$c) { $p.Add("field-catalog: '$n' has class '$c'") } }
        if ($validPolicies -notcontains [string]$f.resolution.policy) { $p.Add("field-catalog: '$n' has policy '$($f.resolution.policy)'") }
        foreach ($a in @($f.resolution.authority)) { if ($a -and $providers -notcontains [string]$a) { $p.Add("field-catalog: '$n' authority names unknown provider '$a'") } }
        # #546 field authority by identity origin: resolution.byOrigin.<synced|cloud> = { policy, authority, decidedBy }
        $bo = $null; if ($f.resolution) { $bo = Get-SIItemValue $f.resolution 'byOrigin' }
        if ($null -ne $bo) {
            foreach ($op in @($bo.PSObject.Properties)) {
                if ($op.Name -notin 'synced', 'cloud') { $p.Add("field-catalog: '$n' byOrigin names unknown origin '$($op.Name)' (synced or cloud)"); continue }
                $r = $op.Value
                $rp = [string](Get-SIItemValue $r 'policy')
                if ($rp -and ($validPolicies -notcontains $rp -or $rp -eq 'computed')) { $p.Add("field-catalog: '$n' byOrigin.$($op.Name) has policy '$rp'") }
                $ra = @(@(Get-SIItemValue $r 'authority') | Where-Object { $_ })
                if ($ra.Count -eq 0) { $p.Add("field-catalog: '$n' byOrigin.$($op.Name) names no authority provider") }
                foreach ($a in $ra + @(@(Get-SIItemValue $r 'decidedBy') | Where-Object { $_ })) { if ($providers -notcontains [string]$a) { $p.Add("field-catalog: '$n' byOrigin.$($op.Name) names unknown provider '$a'") } }
                foreach ($a in @(@(Get-SIItemValue $r 'decidedBy') | Where-Object { $_ })) { if ($ra -notcontains $a) { $p.Add("field-catalog: '$n' byOrigin.$($op.Name) decidedBy '$a' is not one of its authority providers") } }
            }
        }
        if (@('strong', 'weak', 'none') -notcontains [string]$f.join) { $p.Add("field-catalog: '$n' has join '$($f.join)'") }
    }

    $vmaps = $Model['value-maps'].maps
    $mapOps = Get-SIFieldMapperOps
    foreach ($prov in $Model.Mappings.Keys) {
        $m = $Model.Mappings[$prov]
        if ($providers -notcontains $prov) { $p.Add("mappings/${prov}: provider is not in the catalog's provider list") }
        $objs = @{}
        foreach ($o in @($m.objects)) {
            $objs[[string]$o.recordType] = [string]$o.class
            if (-not $o.key) { $p.Add("mappings/${prov}: object '$($o.recordType)' has no key") }
            if (-not $o.timestamp) { $p.Add("mappings/${prov}: object '$($o.recordType)' has no timestamp") }
        }
        foreach ($i in @($m.mappings)) {
            $f = $fields[[string]$i.field]
            if (-not $f) { $p.Add("mappings/${prov}: unknown field '$($i.field)'"); continue }
            # #560 a FINDING record type (object class 'finding': a provider's vulnerability / recommendation) maps the generic SI
            # finding fields -- a finding field, or a CI field that is also carried on a finding (its catalog 'finding' block);
            # any other record type maps record fields only, as before
            $rtsI = @(@($i.recordTypes) | Where-Object { $objs.ContainsKey([string]$_) })
            $onFinding = ($rtsI.Count -gt 0 -and @($rtsI | Where-Object { $objs[[string]$_] -ne 'finding' }).Count -eq 0)
            $alsoFinding = ($null -ne (Get-SIItemValue $f 'finding'))
            if ($onFinding) {
                if ([string]$f.level -ne 'finding' -and -not $alsoFinding) { $p.Add("mappings/${prov}: '$($i.field)' is not a finding field (a finding record type maps finding fields)") }
            } elseif ([string]$f.level -in 'ci', 'finding') { $p.Add("mappings/${prov}: '$($i.field)' is a $($f.level) field and cannot be mapped") }
            if (@(@($i.recordTypes) | Where-Object { $objs.ContainsKey([string]$_) -and $objs[[string]$_] -eq 'finding' }).Count -gt 0 -and -not $onFinding) { $p.Add("mappings/${prov}: '$($i.field)' mixes a finding record type with an asset record type") }
            foreach ($rt in @($i.recordTypes)) {
                if (-not $objs.ContainsKey([string]$rt)) { $p.Add("mappings/${prov}: '$($i.field)' names record type '$rt' with no object"); continue }
                $cls = $objs[[string]$rt]
                if ($cls -eq 'finding') { continue }
                if ($cls -ne '*' -and @($f.classes) -notcontains $cls) { $p.Add("mappings/${prov}: '$($i.field)' is not a $cls field") }
            }
            if (@($i.sources).Count -eq 0) { $p.Add("mappings/${prov}: '$($i.field)' has no source") }
            foreach ($step in @($i.normalize)) {
                if (-not $step) { continue }
                $op = ([string]$step).Split(':')[0]
                if ($mapOps -notcontains $op) { $p.Add("mappings/${prov}: '$($i.field)' uses unknown operation '$op'") }
                if ($op -eq 'enum') { $id = ([string]$step).Substring(5); if ($null -eq $vmaps.PSObject.Properties[$id]) { $p.Add("mappings/${prov}: '$($i.field)' names unknown value map '$id'") } }
            }
            if ($i.combine -and @('first', 'max', 'min', 'any_true', 'union') -notcontains [string]$i.combine) { $p.Add("mappings/${prov}: '$($i.field)' has combine '$($i.combine)'") }
            # #455: an authority field says which provider wins -- a provider that fills it must have its place in that
            # order (a CMDB provider's place is the cmdb_owner token), or its value only ever wins by accident
            if ([string]$f.resolution.policy -eq 'authority') {
                $auth = @($f.resolution.authority)
                $placed = ($auth -contains $prov) -or ($prov -in 'cmdb', 'servicenow' -and $auth -contains 'cmdb_owner')
                if (-not $placed) { $p.Add("mappings/${prov}: fills '$($i.field)' but '$prov' has no place in the field's authority order") }
            }
        }
    }

    $lists = @{}
    foreach ($l in @($Model['lists'].lists)) {
        if ($lists.ContainsKey([string]$l.id)) { $p.Add("lists: '$($l.id)' is defined twice") }
        $lists[[string]$l.id] = $l
        if (@('conditions', 'values', 'ranges') -notcontains [string]$l.type) { $p.Add("lists: '$($l.id)' has type '$($l.type)'") }
        if ([string]$l.type -eq 'ranges') { foreach ($r in @($l.values)) { if ($r -and -not (Test-SIIpInCidr ([string]$r).Split('/')[0] ([string]$r))) { $p.Add("lists: '$($l.id)' range '$r' is not a CIDR") } } }
    }
    $condOps = Get-SIConditionOps
    $checkCondition = {
        param([string]$Where, $Cond)
        if ($null -eq $Cond) { return }
        foreach ($g in 'all', 'any') {
            if ($Cond.PSObject.Properties[$g]) { foreach ($c in @($Cond.$g)) { & $checkCondition $Where $c }; return }
        }
        $fn = [string]$Cond.field
        if (-not $fields.ContainsKey($fn) -and $fn -notmatch '^properties\.') { $p.Add("${Where}: condition reads unknown field '$fn'") }
        if ($condOps -notcontains [string]$Cond.op) { $p.Add("${Where}: unknown condition operation '$($Cond.op)'") }
        if ([string]$Cond.op -in 'in_list', 'in_ranges' -and -not $lists.ContainsKey([string]$Cond.value)) { $p.Add("${Where}: names unknown list '$($Cond.value)'") }
        if ([string]$Cond.op -eq 'contains_any' -and $Cond.value -is [string] -and -not $lists.ContainsKey([string]$Cond.value)) { $p.Add("${Where}: names unknown list '$($Cond.value)'") }
        if ([string]$Cond.op -eq 'matches') { try { [void][regex]::new([string]$Cond.value) } catch { $p.Add("${Where}: invalid pattern '$($Cond.value)'") } }
    }
    foreach ($l in $lists.Values) { if ([string]$l.type -eq 'conditions') { foreach ($e in @($l.entries)) { & $checkCondition "lists/$($l.id)/$($e.name)" $e.when } } }

    $factorIds = @{}; $tokens = @{}; $shortNames = @{}
    foreach ($fc in @($Model['risk-factors'].factors)) {
        $id = [string]$fc.id
        if ($factorIds.ContainsKey($id)) { $p.Add("risk-factors: '$id' is defined twice") }
        $factorIds[$id] = $fc
        if (@('asset', 'finding') -notcontains [string]$fc.appliesTo) { $p.Add("risk-factors: '$id' appliesTo '$($fc.appliesTo)'") }
        if (@('probability', 'consequence') -notcontains [string]$fc.axis) { $p.Add("risk-factors: '$id' axis '$($fc.axis)'") }
        # #559 risk factor model v2: state replaces stage (shortName / group / class / impact 1-5 / a builtin is never
        # disabled are checked per item by Test-SIRiskFactorItem, below, so a customer override is held to them too)
        if (@('enabled', 'disabled') -notcontains [string](Get-SIItemValue $fc 'state')) { $p.Add("risk-factors: '$id' state '$(Get-SIItemValue $fc 'state')' (enabled | disabled)") }
        if (@('catalog', 'report') -notcontains [string]$fc.evaluatedBy) { $p.Add("risk-factors: '$id' evaluatedBy '$($fc.evaluatedBy)'") }
        if ($null -eq (ConvertTo-SINumberOrNull $fc.impact)) { $p.Add("risk-factors: '$id' impact is not a number") }
        $sn = ([string](Get-SIItemValue $fc 'shortName')).ToLowerInvariant()
        if ($sn) { if ($shortNames.ContainsKey($sn)) { $p.Add("risk-factors: short name '$(Get-SIItemValue $fc 'shortName')' is used by '$($shortNames[$sn])' and '$id'") } else { $shortNames[$sn] = $id } }
        foreach ($t in @($fc.legacyTokens)) { if ($t) { if ($tokens.ContainsKey([string]$t)) { $p.Add("risk-factors: legacy token '$t' is claimed by '$($tokens[[string]$t])' and '$id'") }; $tokens[[string]$t] = $id } }
        if ([string]$fc.evaluatedBy -eq 'catalog') {
            & $checkCondition "risk-factors/$id" $fc.when
            foreach ($fn in (Get-SIConditionFields $fc.when)) {
                $fd = $fields[$fn]
                if ($fd -and [string]$fc.appliesTo -eq 'asset' -and [string]$fd.level -eq 'finding') { $p.Add("risk-factors/${id}: an asset factor reads finding field '$fn'") }
            }
        }
    }

    # the Azure CI scope: every Azure type is an ARM type, and a child type's rollUpInto names its parent types, 'path' or
    # dot paths to find the parent, and a catalog field to be listed in (SI-AzureChildren.ps1)
    if ($null -ne $Model['collection-scope']) {
        foreach ($x in @(Test-SIAzureCiScopeItems -Document $Model['collection-scope'] -Fields $fields)) { $p.Add("collection-scope: $x") }
    }

    foreach ($ck in @($Model['coverage-checks'].checks)) {
        if (@('tenant', 'subscription', 'ci') -notcontains [string]$ck.scope) { $p.Add("coverage-checks: '$($ck.id)' scope '$($ck.scope)'") }
        if ([string]$ck.scope -eq 'ci') { & $checkCondition "coverage-checks/$($ck.id)" $ck.fail }
        if ($ck.riskFactor -and -not $factorIds.ContainsKey([string]$ck.riskFactor)) { $p.Add("coverage-checks: '$($ck.id)' names unknown risk factor '$($ck.riskFactor)'") }
    }

    $outOps = Get-SIOutputMapOps
    foreach ($oid in $Model.Outputs.Keys) {
        $o = $Model.Outputs[$oid]
        if (@('ci', 'ci_finding', 'finding_summary', 'record') -notcontains [string]$o.grain) { $p.Add("outputs/${oid}: grain '$($o.grain)'") }
        $targets = @{}
        $names = @{}
        foreach ($c in @($o.columns)) {
            if ($targets.ContainsKey([string]$c.target)) { $p.Add("outputs/${oid}: column '$($c.target)' appears twice") }
            $targets[[string]$c.target] = 1
            # the name the output gives the column: 'as' (a customer's rename) or the target -- one line, unique per output
            $as = [string](Get-SIItemValue $c 'as')
            $name = [string]$c.target
            if (-not [string]::IsNullOrWhiteSpace($as)) {
                $name = $as.Trim()
                if ($name.Length -gt 128 -or $name -match '[\r\n\t]') { $p.Add("outputs/${oid}: column '$($c.target)' has a name ('as') that is not one line of at most 128 characters") }
            }
            if ($names.ContainsKey($name.ToLowerInvariant())) { $p.Add("outputs/${oid}: two columns are named '$name'") }
            $names[$name.ToLowerInvariant()] = 1
            $from = [string]$c.from
            if (-not ($from.StartsWith('$') -or $from -match '^(finding|summary|record)\.' -or $fields.ContainsKey($from))) { $p.Add("outputs/${oid}: column '$($c.target)' reads unknown field '$from'") }
            if ($c.op) {
                $op = ([string]$c.op).Split(':')[0]
                if ($outOps -notcontains $op) { $p.Add("outputs/${oid}: column '$($c.target)' uses unknown operation '$op'") }
                if ($op -eq 'enum') { $id = ([string]$c.op).Substring(5); if ($null -eq $vmaps.PSObject.Properties[$id]) { $p.Add("outputs/${oid}: column '$($c.target)' names unknown value map '$id'") } }
            }
        }
    }

    $seen = @{}
    foreach ($t in @($Model['trust'].order)) { if ($seen.ContainsKey([string]$t.id)) { $p.Add("trust: '$($t.id)' appears twice") }; $seen[[string]$t.id] = 1 }

    foreach ($sect in 'criticality', 'dataSensitivity') {
        foreach ($prov in $Model['criticality-mapping'].$sect.PSObject.Properties) {
            if ($prov.Name.StartsWith('$')) { continue }
            if (@('cmdb', 'servicenow') -notcontains $prov.Name) { $p.Add("criticality-mapping: $sect names unknown CMDB provider '$($prov.Name)'") }
            foreach ($e in @($prov.Value)) {
                if ($null -eq (ConvertTo-SINumberOrNull $e.factor)) { $p.Add("criticality-mapping: $sect/$($prov.Name) '$($e.value)' has no numeric factor") }
                if ($sect -eq 'criticality' -and @('critical', 'high', 'medium', 'low') -notcontains [string]$e.level) { $p.Add("criticality-mapping: $($prov.Name) '$($e.value)' has level '$($e.level)'") }
            }
        }
    }
    # #527 (5)-(7): one scope per factor, no tier, SI fields only (SI-RiskFactorCatalog.ps1) -- a customer override is held to them too
    # (Test-SIRiskFactorRules includes #559 Test-SIRiskFactorModelV2: shortName, group, class, impact 1-5, a built-in factor
    #  is never disabled -- the engine-side twin of the web app's check)
    foreach ($x in (Test-SIRiskFactorRules -Model $Model)) { $p.Add($x) }
    # #559 break_glass_patterns: a values list of glob patterns, never wildcards only (the web app's rule too)
    foreach ($x in (Test-SIBreakGlassPatterns -Model $Model)) { $p.Add($x) }
    # the break-glass extension attribute the customer defines: attribute=value entries (engine/data-model/SI-BreakGlass.ps1)
    if (-not (Get-Command -Name Test-SIBreakGlassAttributeList -ErrorAction SilentlyContinue)) { $bgFile = Join-Path $PSScriptRoot 'SI-BreakGlass.ps1'; if (Test-Path -LiteralPath $bgFile) { . $bgFile } }
    if (Get-Command -Name Test-SIBreakGlassAttributeList -ErrorAction SilentlyContinue) { foreach ($x in (Test-SIBreakGlassAttributeList -Model $Model)) { $p.Add($x) } }
    # the risk rating bands are data (owner decision pending): three whole numbers, highest first
    foreach ($x in (Test-SIRiskRatingBands -Model $Model)) { $p.Add($x) }

    # #493 the relations between CIs: every relation reads a catalog field valid on its classes, names a known target kind,
    # an identifier type for 'id', a node type for 'node'; a reversed relation must point at CI ids
    $relSeen = @{}
    foreach ($r in @(Get-SIItemValue $Model['relations'] 'relations')) {
        if ($null -eq $r) { continue }
        $rid = [string]$r.id
        if (-not $rid -or $rid -cnotmatch '^[a-z][a-z0-9_]{0,47}$') { $p.Add("relations: '$rid' is not a lower snake_case id of at most 48 characters"); continue }
        if ($relSeen.ContainsKey($rid)) { $p.Add("relations: '$rid' is defined twice") }
        $relSeen[$rid] = 1
        if ([string]$r.kind -cnotmatch '^[a-z][a-z0-9_]{0,47}$') { $p.Add("relations/${rid}: kind '$($r.kind)' is not a lower snake_case word of at most 48 characters") }
        $fd = $fields[[string]$r.field]
        if (-not $fd) { $p.Add("relations/${rid}: reads unknown field '$($r.field)'") }
        elseif ([string]$fd.level -eq 'finding') { $p.Add("relations/${rid}: '$($r.field)' is a finding field") }
        foreach ($c in @($r.from)) {
            if (@($cat.classes) -notcontains [string]$c) { $p.Add("relations/${rid}: from names unknown class '$c'") }
            elseif ($fd -and @($fd.classes) -notcontains [string]$c) { $p.Add("relations/${rid}: '$($r.field)' is not a $c field") }
        }
        if (@($r.from).Count -eq 0) { $p.Add("relations/${rid}: names no 'from' class") }
        switch ([string]$r.target) {
            'ci' { }
            'id' { if (-not ([string]$r.idType)) { $p.Add("relations/${rid}: target 'id' needs an idType") } }
            'node' { if (-not ([string]$r.nodeType)) { $p.Add("relations/${rid}: target 'node' needs a nodeType") } }
            default { $p.Add("relations/${rid}: target '$($r.target)' (ci | id | node)") }
        }
        if ((Get-SIItemValue $r 'reverse') -eq $true -and [string]$r.target -ne 'ci') { $p.Add("relations/${rid}: only a relation to CI ids can be reversed") }
        $q = [string](Get-SIItemValue $r 'qualifyWith'); if ($q -and -not $fields.ContainsKey($q)) { $p.Add("relations/${rid}: qualifyWith names unknown field '$q'") }
        if (@('exact', 'strong', 'weak') -notcontains [string]$r.confidence) { $p.Add("relations/${rid}: confidence '$($r.confidence)' (exact | strong | weak)") }
        $st = [string](Get-SIItemValue $r 'stage'); if ($st -and @('production', 'testing', 'not_used') -notcontains $st) { $p.Add("relations/${rid}: stage '$st'") }
    }
    # #561 / #562 the classification dimensions and rows: valid, and every field they read or write is in the catalog
    if ($null -ne $Model['dimensions'] -or $null -ne $Model['classification']) {
        foreach ($x in (Test-SIClassifications -Dimensions $Model['dimensions'] -Classification $Model['classification'] -Fields $fields)) { $p.Add([string]$x) }
    }
    # #560 the finding texts of SI's own reports: every field they fill is a finding field of the catalog
    if ($null -ne $Model['finding-texts']) {
        $ff = [string[]]@($fields.Keys | Where-Object { [string]$fields[$_].level -eq 'finding' -or $null -ne (Get-SIItemValue $fields[$_] 'finding') })
        foreach ($x in (Test-SIFindingTexts -Document $Model['finding-texts'] -FindingFields $ff)) { $p.Add([string]$x) }
    }
    # #690 (15) the severity model: five SI values, every report ends with its own severity
    if ($null -ne $Model['severity-model']) {
        foreach ($x in (Test-SISeverityModel -Model $Model['severity-model'])) { $p.Add([string]$x) }
    }
    # one problem per output item: @(Test-SIDataModel ...) and a pipeline filter see each problem, never one array
    return $p.ToArray()
}

# ------------------------------------------------------------------------------------------------------------------
#  THE SEVERITY MODEL (#690 (15), data-model/severity-model.locked.json)
#  Owner 2026-10-15: "all security findings must have severity" / "it comes from different metrics, often impact score or
#  directly from the source" / "unknown is not supported in any report" / "field must be normalized". Every report declares
#  an ORDERED list of metric kinds; the first kind whose metric a row carries decides; owner_defined is always last, so a
#  row always ends with exactly one of the five SI values. The reports' queries do not read the model yet (the generated
#  severity block is the next step) -- these functions are the model's one reader and its validation.
# ------------------------------------------------------------------------------------------------------------------

function Get-SISeverityScale { <# The five SI severities -- the only values a report's SecuritySeverity may hold. #> @('Very High', 'High', 'Medium-High', 'Medium', 'Low') }

function Get-SISeverityModel {
    <# The severity model of the run (the data model + its overrides), else the shipped file next to this file's data model. #>
    param($Model, [string]$Root)
    if ($Model -and $null -ne $Model['severity-model']) { return $Model['severity-model'] }
    $r = Get-SIDataModelRoot $Root
    $f = Join-Path $r 'severity-model.locked.json'
    if (-not (Test-Path -LiteralPath $f)) { return $null }
    return (Get-SIDataModelTemplate -Name 'severity-model' -Root $r).Document
}

function Test-SISeverityModel {
    <# PURE. The problems of a severity model (none = valid): the scale is exactly the five SI values, every kind maps
       only into it, every report's order names known kinds and ends with owner_defined, and its own severity is one of
       the five. #>
    param([Parameter(Mandatory)]$Model)
    $p = New-Object System.Collections.Generic.List[string]
    $scale = @(Get-SIItemValue $Model 'scale' | ForEach-Object { [string]$_ })
    if (($scale -join '|') -cne ((Get-SISeverityScale) -join '|')) { $p.Add("severity-model: the scale must be exactly $((Get-SISeverityScale) -join ', ')") }
    $kinds = @{}
    foreach ($m in @(Get-SIItemValue $Model 'models')) {
        $id = [string](Get-SIItemValue $m 'id'); $ty = [string](Get-SIItemValue $m 'type')
        if (-not $id) { $p.Add('severity-model: a model has no id'); continue }
        if ($kinds.ContainsKey($id)) { $p.Add("severity-model: '$id' is defined twice") }
        $kinds[$id] = $m
        if (@('map', 'bands', 'fixed') -cnotcontains $ty) { $p.Add("severity-model/${id}: type '$ty' (map | bands | fixed)") }
        if ($ty -eq 'map') {
            $map = Get-SIItemValue $m 'map'
            if ($null -eq $map) { $p.Add("severity-model/${id}: a map model has a 'map'") }
            else { foreach ($e in $map.PSObject.Properties) { if ((Get-SISeverityScale) -cnotcontains [string]$e.Value) { $p.Add("severity-model/${id}: '$($e.Name)' maps to '$($e.Value)', not an SI severity") } } }
        }
        if ($ty -eq 'bands') {
            $prev = [double]::MaxValue
            $bands = @(Get-SIItemValue $m 'bands')
            if ($bands.Count -eq 0) { $p.Add("severity-model/${id}: a bands model has 'bands'") }
            foreach ($b in $bands) {
                $min = ConvertTo-SINumberOrNull (Get-SIItemValue $b 'min')
                if ($null -eq $min) { $p.Add("severity-model/${id}: a band has no numeric min"); continue }
                if ($min -ge $prev) { $p.Add("severity-model/${id}: bands are highest first") }
                $prev = $min
                if ((Get-SISeverityScale) -cnotcontains [string](Get-SIItemValue $b 'severity')) { $p.Add("severity-model/${id}: band $min maps to '$(Get-SIItemValue $b 'severity')', not an SI severity") }
            }
        }
    }
    if (-not $kinds.ContainsKey('owner_defined')) { $p.Add("severity-model: the owner_defined kind is missing") }
    $seen = @{}
    foreach ($r in @(Get-SIItemValue $Model 'reports')) {
        $rid = [string](Get-SIItemValue $r 'id')
        if (-not $rid) { $p.Add('severity-model: a report has no id'); continue }
        if ($seen.ContainsKey($rid)) { $p.Add("severity-model: report '$rid' is listed twice") }
        $seen[$rid] = $true
        $order = @(Get-SIItemValue $r 'order' | ForEach-Object { [string]$_ })
        if ($order.Count -eq 0 -or $order[$order.Count - 1] -cne 'owner_defined') { $p.Add("severity-model/${rid}: the order ends with owner_defined (every row gets a severity)") }
        foreach ($k in $order) { if (-not $kinds.ContainsKey($k)) { $p.Add("severity-model/${rid}: unknown kind '$k'") } }
        if ((Get-SISeverityScale) -cnotcontains [string](Get-SIItemValue $r 'ownerDefined')) { $p.Add("severity-model/${rid}: ownerDefined '$(Get-SIItemValue $r 'ownerDefined')' is not an SI severity") }
    }
    return $p.ToArray()
}

function Test-SISeverityModelReportItem {
    <# PURE. One report item of the severity model on its own (a Pro override): the problems, none = accepted. The kinds
       it names are checked against the model when the run's whole model is validated (Test-SIDataModel). #>
    param([Parameter(Mandatory)]$Item)
    $p = New-Object System.Collections.Generic.List[string]
    $rid = [string](Get-SIItemValue $Item 'id')
    $order = @(Get-SIItemValue $Item 'order' | ForEach-Object { [string]$_ })
    if ($order.Count -eq 0 -or $order[$order.Count - 1] -cne 'owner_defined') { $p.Add("severity-model/${rid}: the order ends with owner_defined (every row gets a severity)") }
    if ((Get-SISeverityScale) -cnotcontains [string](Get-SIItemValue $Item 'ownerDefined')) { $p.Add("severity-model/${rid}: ownerDefined must be one of $((Get-SISeverityScale) -join ', ')") }
    return $p.ToArray()
}

function Resolve-SISeverity {
    <#
        PURE. One row's severity: the report's kinds in order, the first whose metric -Metrics carries (a hashtable kind ->
        value: a word for a map kind, a number for a bands kind) decides; owner_defined (the report's ownerDefined) last.
        A report the model does not list returns $null -- never a guessed value (SIv3-SeverityModel keeps every shipped
        report listed). Always one of the five SI values or $null; never 'Unknown'.
    #>
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][string]$ReportName, [hashtable]$Metrics = @{})
    $rep = @(@(Get-SIItemValue $Model 'reports') | Where-Object { [string](Get-SIItemValue $_ 'id') -eq $ReportName }) | Select-Object -First 1
    if ($null -eq $rep) { return $null }
    $kinds = @{}; foreach ($m in @(Get-SIItemValue $Model 'models')) { $kinds[[string](Get-SIItemValue $m 'id')] = $m }
    foreach ($k in @(Get-SIItemValue $rep 'order' | ForEach-Object { [string]$_ })) {
        if ($k -eq 'owner_defined') { return [string](Get-SIItemValue $rep 'ownerDefined') }
        $m = $kinds[$k]; if ($null -eq $m -or -not $Metrics.ContainsKey($k)) { continue }
        $v = $Metrics[$k]; if ($null -eq $v -or ([string]$v).Trim() -eq '') { continue }
        switch ([string](Get-SIItemValue $m 'type')) {
            'map' {
                $map = Get-SIItemValue $m 'map'; $key = ([string]$v).Trim().ToLowerInvariant()
                $hit = $null; foreach ($e in $map.PSObject.Properties) { if ($e.Name.ToLowerInvariant() -eq $key) { $hit = [string]$e.Value; break } }
                if ($hit) { return $hit }
            }
            'bands' {
                $n = ConvertTo-SINumberOrNull $v
                if ($null -eq $n) { break }
                foreach ($b in @(Get-SIItemValue $m 'bands')) { if ($n -ge [double](ConvertTo-SINumberOrNull (Get-SIItemValue $b 'min'))) { return [string](Get-SIItemValue $b 'severity') } }
            }
        }
    }
    return [string](Get-SIItemValue $rep 'ownerDefined')
}
