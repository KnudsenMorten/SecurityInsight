#Requires -Version 5.1
<#
    SECURITYINSIGHT PRO -- THE DATA-MODEL TEMPLATES IN SQL (REQUIREMENTS #456, V3-DATA-MODEL 2.4.5).

    The data model (data-model/*.locked.json: the field catalog, the provider MAPPINGS, value maps, lists, trust, risk
    factors, criticality mapping, collection scope, coverage checks, output maps) travels through the same template channel
    as every other vendor template: one cfg.Template row per ITEM, kind 'datamodel', so a customer overrides, disables or
    adds ONE mapping / field / factor (cfg.ItemOverride) and an update keeps it -- the conformance view flags
    UpgradeAvailable when the shipped item changed underneath an override, never merges it (SI-TemplateVersioning.ps1).

    ITEM KEYS ('datamodel' kind, max 128 characters):
      <template>               the template's HEADER: the document without its item array (kind, version, objects ...);
                               for a template without items (value-maps, criticality-mapping) the whole document
      <template>:<item key>    one item -- the key the file-based merge uses (Get-SIDataModelItemKey: a mapping's
                               'field|recordTypes|resourceTypes', a repeat '#<n>', a field's name, a factor's id ...).
                               A key that would pass 128 characters keeps its first part and ends '~<12 hex of SHA-256>'.
      <template> = field-catalog | value-maps | risk-factors | lists | trust | criticality-mapping | collection-scope |
                   coverage-checks | relations | dimensions | classification | finding-texts | mappings/<provider> | outputs/<id>

    RUN START (Export-SIDataModelProRoot): the effective items (template, override or own; disabled ones are left out)
    are put back together per template, in the shipped order (SortOrder) with the customer's own items after, and written
    as <run>\data-model\<template>.locked.json -- the folder the record writer, the CI build and the outputs read
    ($global:SI_DataModelRoot). The whole model is validated (Test-SIDataModel) before a run may use it.

    Classification (#405): 'fix' -- installed with the code on every install and every update (CONVERGE-DEFAULTS:
    existing installs receive the rows on their next update), never held; a customer's override is never changed.

    PURE except the file writer. PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Get-SIDataModelItemKey -ErrorAction SilentlyContinue)) {
    . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-DataModelTemplates.ps1'))
}

$script:SIDataModelProKeyMax = 128
$script:SIDataModelProKeyPattern = '^[a-z][a-z0-9\-]{0,40}(/[a-z0-9][a-z0-9_\-]{0,60})?(:[^\r\n]{1,126})?$'
$script:SIDataModelProTopNames = @('field-catalog', 'value-maps', 'risk-factors', 'lists', 'trust', 'criticality-mapping', 'collection-scope', 'coverage-checks', 'recommendation-equivalence', 'report-scope', 'relations', 'recommendation-exclusions', 'dimensions', 'classification', 'finding-texts', 'severity-model')

function Get-SIDataModelProKeyPattern { $script:SIDataModelProKeyPattern }

function Get-SIDataModelProTemplateKind {
    <# PURE. The data-model kind a template name holds (what decides its item key). #>
    param([Parameter(Mandatory)][string]$Name)
    if ($Name -like 'mappings/*') { return 'field-mapping' }
    if ($Name -like 'outputs/*') { return 'output-map' }
    # #462: a CI rule pack (data-model/rules/<Pack>.locked.yaml) -- its header (stage, on / off, priority, source) + one row per rule
    if ($Name -like 'rules/*') { return 'ci-rule-pack' }
    if ($Name -eq 'recommendation-equivalence') { return 'recommendation-equivalence' }
    if ($Name -eq 'recommendation-exclusions') { return 'recommendation-exclusion' }
    # #561 / #562 the classification dimensions and rows (one generic classification mechanism)
    if ($Name -eq 'dimensions') { return 'dimension' }
    if ($Name -eq 'classification') { return 'classification' }
    # #560 the finding texts of SI's own reports (one item per report)
    if ($Name -eq 'finding-texts') { return 'finding-text' }
    # #690 (15) the severity model (one item per report)
    if ($Name -eq 'severity-model') { return 'severity-model' }
    switch ($Name) {
        'field-catalog' { 'field-catalog' } 'value-maps' { 'value-map' } 'risk-factors' { 'risk-factor' } 'lists' { 'list' }
        'trust' { 'trust' } 'criticality-mapping' { 'criticality-mapping' } 'collection-scope' { 'collection-scope' }
        'coverage-checks' { 'coverage-check' } 'report-scope' { 'report-scope' } 'relations' { 'relation' } default { '' }
    }
}

function Get-SIDataModelProItemKey {
    <# PURE. '<template>:<item key>', shortened with a hash suffix when it would pass 128 characters. #>
    param([Parameter(Mandatory)][string]$Name, [AllowEmptyString()][string]$ItemKey)
    if (-not $ItemKey) { return $Name }
    $full = '{0}:{1}' -f $Name, $ItemKey
    if ($full.Length -le $script:SIDataModelProKeyMax) { return $full }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $h = (-join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($ItemKey)) | ForEach-Object { $_.ToString('x2') })).Substring(0, 12) } finally { $sha.Dispose() }
    $keep = $script:SIDataModelProKeyMax - $Name.Length - 1 - 13
    return ('{0}:{1}~{2}' -f $Name, $ItemKey.Substring(0, $keep), $h)
}

function Split-SIDataModelProKey {
    <# PURE. @{ Name; ItemKey (as stored, '' for a header) }. #>
    param([Parameter(Mandatory)][string]$Key)
    $i = $Key.IndexOf(':')
    if ($i -lt 0) { return @{ Name = $Key; ItemKey = '' } }
    return @{ Name = $Key.Substring(0, $i); ItemKey = $Key.Substring($i + 1) }
}

function Get-SIDataModelProTemplateNames {
    <# The data-model templates a release ships, in a fixed order: the top-level files, then mappings/*, then outputs/*. #>
    param([Parameter(Mandatory)][string]$DataModelRoot)
    $names = New-Object System.Collections.Generic.List[string]
    foreach ($n in $script:SIDataModelProTopNames) { if (Test-Path -LiteralPath (Join-Path $DataModelRoot ($n + '.locked.json'))) { $names.Add($n) } }
    foreach ($sub in 'mappings', 'outputs') {
        $dir = Join-Path $DataModelRoot $sub
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        $fs = [string[]]@(Get-ChildItem -LiteralPath $dir -Filter '*.locked.json' | ForEach-Object { $_.Name })
        [Array]::Sort($fs, [StringComparer]::Ordinal)
        foreach ($f in $fs) { $names.Add(('{0}/{1}' -f $sub, $f.Replace('.locked.json', ''))) }
    }
    return $names.ToArray()   # unrolled: foreach and @() both read it as the list of names
}

function Get-SIDataModelProItems {
    <#
    .SYNOPSIS  PURE. One parsed template document -> its rows: the header and one per item, keyed as the file-based merge
               keys them (a repeated mapping key gets '#<n>', as Merge-SIDataModelItems does).
    .OUTPUTS   [ @{ Key; ItemKey; Value; SortOrder } ]
    #>
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Document)
    $kind = [string]$Document.kind
    if (-not $kind) { $kind = Get-SIDataModelProTemplateKind $Name }
    $arr = Get-SIDataModelItemArrayName $kind
    $out = New-Object System.Collections.Generic.List[object]
    $header = [ordered]@{}
    # the item array stays in the header as null, so the document is put back with its properties in the shipped order
    foreach ($p in $Document.PSObject.Properties) { if ($arr -and $p.Name -eq $arr) { $header[$p.Name] = $null } else { $header[$p.Name] = $p.Value } }
    $out.Add([pscustomobject]@{ Key = $Name; ItemKey = ''; Value = [pscustomobject]$header; SortOrder = 0 })
    if ($arr) {
        $occ = @{}; $i = 0
        foreach ($it in @($Document.$arr)) {
            if ($null -eq $it) { continue }
            $i++
            $base = Get-SIDataModelItemKey $kind $it
            $k = $base
            if ($kind -eq 'field-mapping') {
                $n = 1; if ($occ.ContainsKey($base)) { $n = [int]$occ[$base] + 1 }
                $occ[$base] = $n
                if ($n -gt 1) { $k = '{0}#{1}' -f $base, $n }
            }
            $out.Add([pscustomobject]@{ Key = (Get-SIDataModelProItemKey -Name $Name -ItemKey $k); ItemKey = $k; Value = $it; SortOrder = $i })
        }
    }
    # the rows one by one (never ', $array'): @(Get-SIDataModelProItems ...) is then the rows, not ONE item holding them all
    foreach ($r in $out) { $r }
}

function Get-SIDataModelTemplateRows {
    <#
    .SYNOPSIS  The 'datamodel' template rows a release ships, from its data-model folder: @{ Key; Body; SortOrder; Source }.
               Bodies are written by -ToJson (the template store's canonical writer, ConvertTo-SIProJson).
    #>
    param([Parameter(Mandatory)][string]$SIRoot, [Parameter(Mandatory)][scriptblock]$ToJson)
    $dm = Join-Path $SIRoot 'data-model'
    $rows = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $dm)) { return }
    $base = 0
    foreach ($n in (Get-SIDataModelProTemplateNames -DataModelRoot $dm)) {
        $path = Join-Path $dm ($n + '.locked.json')
        $doc = [IO.File]::ReadAllText($path).TrimStart([char]0xFEFF) | ConvertFrom-Json
        foreach ($r in (Get-SIDataModelProItems -Name $n -Document $doc)) {
            # one SortOrder series over every template, so the store's order is the shipped order
            $rows.Add([pscustomobject]@{ Key = $r.Key; Body = (& $ToJson $r.Value); SortOrder = ($base + [int]$r.SortOrder); Source = ('data-model/{0}.locked.json' -f $n) })
        }
        $base += 100000
    }
    # #462: the CI rule packs (YAML) -- one template per pack, 'rules/<lower-case pack>', its header + one row per rule
    foreach ($p in @(Get-SIRulePackTemplateDocuments -DataModelRoot $dm)) {
        foreach ($r in (Get-SIDataModelProItems -Name $p.Name -Document $p.Document)) {
            $rows.Add([pscustomobject]@{ Key = $r.Key; Body = (& $ToJson $r.Value); SortOrder = ($base + [int]$r.SortOrder); Source = $p.Source })
        }
        $base += 100000
    }
    # one by one (never ', $array'): @(Get-SIDataModelTemplateRows ...) is then the rows, not ONE item holding them all
    foreach ($x in $rows) { $x }
}

function Get-SIRulePackTemplateDocuments {
    <#
    .SYNOPSIS  The shipped CI rule packs (data-model/rules/*.locked.yaml) as data-model documents: kind 'ci-rule-pack', the
               pack's header (pack, name, description, stage, priority, source) and its rules. A pack that does not parse
               is skipped with a warning (the release's rule lint refuses it before it ships).
    .OUTPUTS   [ @{ Name ('rules/<pack>'); Document; Source } ]
    #>
    param([Parameter(Mandatory)][string]$DataModelRoot)
    $dir = Join-Path $DataModelRoot 'rules'
    $out = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $dir)) { return }
    if (-not (Get-Command -Name Get-SIRulePackKey -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-CiRules.ps1')) }
    if (-not (Get-Command -Name ConvertFrom-SIYaml -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), '_shared', 'SI-Yaml.ps1')) }
    $fs = [string[]]@(Get-ChildItem -LiteralPath $dir -File -Filter '*.locked.yaml' | ForEach-Object { $_.Name })
    [Array]::Sort($fs, [StringComparer]::Ordinal)
    foreach ($f in $fs) {
        $pack = $f -replace '\.locked\.yaml$', ''
        try {
            $y = ConvertFrom-SIYaml -Yaml ([IO.File]::ReadAllText((Join-Path $dir $f))) -SourceName $f
            $doc = [ordered]@{ kind = 'ci-rule-pack'; pack = $pack }
            foreach ($k in 'name', 'description', 'stage', 'priority', 'enabled', 'source') { $v = Get-SIItemValue $y $k; if ($null -ne $v -and [string]$v -ne '') { $doc[$k] = $v } }
            if (-not $doc.Contains('source')) { $doc['source'] = 'shipped' }
            # Get-SIValueList returns ONE list (', $out'): @() around it would make the rules a single item holding every rule
            $doc['rules'] = (Get-SIValueList (Get-SIItemValue $y 'rules')).ToArray()
            # one JSON shape (the YAML reader's dictionaries -> objects), as every other data-model document
            $obj = ConvertTo-Json -InputObject $doc -Depth 30 | ConvertFrom-Json
            $out.Add([pscustomobject]@{ Name = (Get-SIRulePackKey -Pack $pack); Document = $obj; Source = ('data-model/rules/{0}' -f $f) })
        } catch { Write-Warning ("rule pack {0} could not be published -- {1}" -f $f, $_.Exception.Message) }
    }
    # one by one: @(Get-SIRulePackTemplateDocuments ...) -- as the rows above read it -- is then the packs, not ONE item holding them
    foreach ($x in $out) { $x }
}

function Test-SIDataModelProItem {
    <#
    .SYNOPSIS  PURE. The reasons a 'datamodel' item is not accepted (empty = accepted). -Value: the parsed body.
               A header must carry the template's kind; an item's body must give back the key it is stored under (the key
               names the item, as for every other kind), so an override can never land on another item.
    #>
    param([Parameter(Mandatory)][string]$Key, $Value)
    $why = New-Object System.Collections.Generic.List[string]
    if ($Key.Length -gt $script:SIDataModelProKeyMax -or $Key -notmatch $script:SIDataModelProKeyPattern) { $why.Add(("'{0}' is not a data-model key ('<template>' or '<template>:<item key>')" -f $Key)); return $why.ToArray() }
    if ($Value -isnot [System.Management.Automation.PSCustomObject]) { $why.Add('a data-model item must be a JSON object'); return $why.ToArray() }
    $s = Split-SIDataModelProKey $Key
    $kind = Get-SIDataModelProTemplateKind $s.Name
    if (-not $kind) { $why.Add(("'{0}' is not a data-model template" -f $s.Name)); return $why.ToArray() }
    if (-not $s.ItemKey) {
        if ($Value.PSObject.Properties['kind'] -and [string]$Value.kind -ne $kind) { $why.Add(("the {0} header must have kind '{1}'" -f $s.Name, $kind)) }
        return $why.ToArray()
    }
    if (-not (Get-SIDataModelItemArrayName $kind)) { $why.Add(("{0} has no items -- it is one document ('{0}')" -f $s.Name)); return $why.ToArray() }
    $own = Get-SIDataModelItemKey $kind $Value
    if (-not $own) { $why.Add('the item has no key (field / name / id / target / type)'); return $why.ToArray() }
    $expect = Get-SIDataModelProItemKey -Name $s.Name -ItemKey $own
    $ok = ($Key -ceq $expect)
    if (-not $ok -and $kind -eq 'field-mapping') {
        # a repeated mapping key ('#<n>'; inside the hashed part when the key was shortened)
        for ($n = 2; $n -le 64 -and -not $ok; $n++) { $ok = ($Key -ceq (Get-SIDataModelProItemKey -Name $s.Name -ItemKey ('{0}#{1}' -f $own, $n))) }
    }
    if (-not $ok) { $why.Add(("the key must be '{0}' -- it is made of the item's own key" -f $expect)) }
    # #527 (5)-(7): a risk factor keeps one scope, no tier, SI fields only -- a customer's override too (SI-RiskFactorCatalog.ps1)
    if ($kind -eq 'risk-factor' -and (Get-Command -Name Test-SIRiskFactorItem -ErrorAction SilentlyContinue)) { foreach ($x in (Test-SIRiskFactorItem -Factor $Value)) { $why.Add([string]$x) } }
    # #462: a rule of a CI rule pack must convert (SI fields only, a known stage / class / operation, sets something)
    if ($kind -eq 'ci-rule-pack') {
        if (-not (Get-Command -Name ConvertTo-SICiNativeRule -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-CiRules.ps1')) }
        try { $null = ConvertTo-SICiNativeRule -Item $Value -Pack $s.Name } catch { $why.Add([string]$_.Exception.Message) }
    }
    # #464: one equivalence group (SI-RecommendationEquivalence.ps1)
    # #546: one default exclusion rule (SI-RecommendationExclusions.ps1)
    if ($kind -eq 'recommendation-exclusion') {
        if (-not (Get-Command -Name Test-SIRecommendationExclusionRule -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-RecommendationExclusions.ps1')) }
        foreach ($x in (Test-SIRecommendationExclusionRule -Rule $Value)) { $why.Add([string]$x) }
    }
    # #561 / #562: one dimension / one classification row (SI-Classification.ps1); a row is checked on its shape here, against
    # the dimensions in force when the run's whole model is validated (Test-SIDataModel)
    if ($kind -eq 'finding-text') {
        if (-not (Get-Command -Name Test-SIFindingTextItem -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-FindingTexts.ps1')) }
        foreach ($x in (Test-SIFindingTextItem -Item $Value)) { $why.Add([string]$x) }
    }
    # #690 (15): one report of the severity model -- its order ends with owner_defined, its own severity is one of the five
    if ($kind -eq 'severity-model') { foreach ($x in (Test-SISeverityModelReportItem -Item $Value)) { $why.Add([string]$x) } }
    if ($kind -in 'dimension', 'classification') {
        if (-not (Get-Command -Name Test-SIClassificationRule -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-Classification.ps1')) }
        if ($kind -eq 'dimension') { foreach ($x in (Test-SIDimensionItem -Dimension $Value)) { $why.Add([string]$x) } }
        else { foreach ($x in (Test-SIClassificationRule -Rule $Value)) { $why.Add([string]$x) } }
    }
    if ($kind -eq 'recommendation-equivalence') {
        if (-not (Get-Command -Name Test-SIRecommendationEquivalenceGroup -ErrorAction SilentlyContinue)) { . ([System.IO.Path]::Combine((Split-Path -Parent $PSScriptRoot), 'data-model', 'SI-RecommendationEquivalence.ps1')) }
        foreach ($x in (Test-SIRecommendationEquivalenceGroup -Group $Value)) { $why.Add([string]$x) }
    }
    return $why.ToArray()
}

function ConvertTo-SIDataModelProDocuments {
    <#
    .SYNOPSIS  PURE. The run's effective 'datamodel' items -> one document per template, the items in store order
               (SortOrder; the customer's own items after the shipped ones, by key).
    .OUTPUTS   ordered hashtable  template name -> document (pscustomobject)
    #>
    param([AllowEmptyCollection()][object[]]$Items = @(), [Parameter(Mandatory)][scriptblock]$FromJson)
    $byName = [ordered]@{}
    foreach ($it in @($Items)) {
        if ($null -eq $it) { continue }
        $s = Split-SIDataModelProKey ([string]$it.Key)
        if (-not $byName.Contains($s.Name)) { $byName[$s.Name] = @{ Header = $null; Items = (New-Object System.Collections.Generic.List[object]) } }
        $v = & $FromJson ([string]$it.Body)
        if (-not $s.ItemKey) { $byName[$s.Name].Header = $v }
        else { $byName[$s.Name].Items.Add([pscustomobject]@{ Order = [long]$it.SortOrder; Key = [string]$s.ItemKey; Value = $v }) }
    }
    $docs = [ordered]@{}
    foreach ($n in $byName.Keys) {
        $e = $byName[$n]
        if ($null -eq $e.Header) { throw ("data-model template '{0}': items without its header -- republish the templates" -f $n) }
        $kind = [string]$e.Header.kind
        if (-not $kind) { $kind = Get-SIDataModelProTemplateKind $n }
        $arr = Get-SIDataModelItemArrayName $kind
        $doc = [ordered]@{}
        foreach ($p in $e.Header.PSObject.Properties) { $doc[$p.Name] = $p.Value }
        if ($arr) {
            $its = $e.Items.ToArray()
            $keys = [string[]]@($its | ForEach-Object { '{0:D20}|{1}' -f $_.Order, $_.Key })
            $idx = [int[]]@(0..([Math]::Max(0, $its.Count - 1)))
            if ($its.Count -gt 0) { [Array]::Sort($keys, $idx, [StringComparer]::Ordinal) }
            $doc[$arr] = @(if ($its.Count -gt 0) { foreach ($i in $idx) { $its[$i].Value } })
        }
        $docs[$n] = [pscustomobject]$doc
    }
    return $docs
}

function Export-SIDataModelProRoot {
    <#
    .SYNOPSIS  Writes the run's data model to <RunFolder>\data-model\<template>.locked.json and validates it.
               Templates the database does not hold (none published yet for that file) are copied from -ShippedRoot, so
               the folder is always a whole model. A model that does not validate NEVER stops the run: the templates a
               problem names go back to the shipped copy, and if that is not enough the whole shipped model is used -- said
               in Notes. Throws only when the SHIPPED model itself does not validate (a product defect).
    .OUTPUTS   @{ Root; Templates (written from the database); Copied (from the installation); Fallback (shipped for this run); Notes }
    #>
    param([AllowEmptyCollection()][object[]]$Items = @(), [Parameter(Mandatory)][string]$RunFolder, [Parameter(Mandatory)][string]$ShippedRoot,
          [Parameter(Mandatory)][scriptblock]$FromJson, [Parameter(Mandatory)][scriptblock]$ToJson)
    $root = [IO.Path]::Combine($RunFolder, 'data-model')
    foreach ($d in @($root, [IO.Path]::Combine($root, 'mappings'), [IO.Path]::Combine($root, 'outputs'), [IO.Path]::Combine($root, 'rules'))) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
    $docs = ConvertTo-SIDataModelProDocuments -Items @($Items) -FromJson $FromJson
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    foreach ($n in $docs.Keys) { [IO.File]::WriteAllText([IO.Path]::Combine($root, ($n.Replace('/', [IO.Path]::DirectorySeparatorChar) + '.locked.json')), (& $ToJson $docs[$n]), $utf8) }
    $copied = New-Object System.Collections.Generic.List[string]
    foreach ($n in (Get-SIDataModelProTemplateNames -DataModelRoot $ShippedRoot)) {
        if ($docs.Contains($n)) { continue }
        $rel = $n.Replace('/', [IO.Path]::DirectorySeparatorChar) + '.locked.json'
        [IO.File]::Copy([IO.Path]::Combine($ShippedRoot, $rel), [IO.Path]::Combine($root, $rel), $true)
        $copied.Add($n)
    }
    $check = { @(Test-SIDataModel -Model (Get-SIDataModel -Root $root) | ForEach-Object { $_ } | Where-Object { $_ }) }
    $short = { param($p) (@($p | Select-Object -First 5) -join '; ') + $(if (@($p).Count -gt 5) { (' (+{0} more)' -f (@($p).Count - 5)) } else { '' }) }
    $problems = & $check
    $notes = New-Object System.Collections.Generic.List[string]; $fallback = New-Object System.Collections.Generic.List[string]
    $shippedNames = @(Get-SIDataModelProTemplateNames -DataModelRoot $ShippedRoot)
    # A SETTINGS PROBLEM NEVER STOPS THE RUN (owner, ring 1 2026-10-10: a run that read the settings database while the
    # template publish was half-way -- the field catalog partly written, its mappings not yet -- stopped the whole pipeline
    # with "unknown field" x471). Step 1: every template from the database a problem names goes back to the shipped copy
    # for this run. Step 2: still not valid -> this run uses the whole shipped data model. Each is said, per template.
    if ($problems.Count) {
        $named = New-Object System.Collections.Generic.List[string]
        foreach ($p in $problems) {
            $m = [regex]::Match([string]$p, '^([a-z][a-z0-9\-]*(?:/[a-z0-9][a-z0-9\-]*)?):')
            if ($m.Success -and $docs.Contains($m.Groups[1].Value) -and -not $named.Contains($m.Groups[1].Value)) { $named.Add($m.Groups[1].Value) }
        }
        foreach ($n in $named) {
            if ($shippedNames -notcontains $n) { continue }
            $rel = $n.Replace('/', [IO.Path]::DirectorySeparatorChar) + '.locked.json'
            [IO.File]::Copy([IO.Path]::Combine($ShippedRoot, $rel), [IO.Path]::Combine($root, $rel), $true)
            $fallback.Add($n)
        }
        $first = $problems
        if ($fallback.Count) { $problems = & $check }
        if ($problems.Count) {
            foreach ($n in $shippedNames) {
                $rel = $n.Replace('/', [IO.Path]::DirectorySeparatorChar) + '.locked.json'
                [IO.File]::Copy([IO.Path]::Combine($ShippedRoot, $rel), [IO.Path]::Combine($root, $rel), $true)
            }
            foreach ($n in @($docs.Keys)) { if ($shippedNames -notcontains $n) { Remove-Item -LiteralPath ([IO.Path]::Combine($root, ($n.Replace('/', [IO.Path]::DirectorySeparatorChar) + '.locked.json'))) -Force -ErrorAction SilentlyContinue } }
            $notes.Add(('the data model in the settings database does not validate ({0}) -- this run uses the data model shipped with this release; your data-model changes apply again once it validates (a template publish that was still running finishes; otherwise review the data model on the web app)' -f (& $short $first)))
            $fallback.Clear(); foreach ($n in $shippedNames) { $fallback.Add($n) }
            $problems = & $check
            # the shipped model itself does not validate: a product defect, not a setting -- nothing else to fall back to
            if ($problems.Count) { throw ('the data model shipped with this release does not validate -- ' + (& $short $problems)) }
        } else {
            $notes.Add(('the data model in the settings database does not validate ({0}) -- this run uses the shipped {1} for: {2}' -f (& $short $first), $(if ($fallback.Count -eq 1) { 'template' } else { 'templates' }), ($fallback -join ', ')))
        }
    }
    return @{ Root = $root; Templates = @($docs.Keys); Copied = $copied.ToArray(); Fallback = $fallback.ToArray(); Notes = $notes.ToArray() }
}
