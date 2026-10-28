#Requires -Version 5.1
<#
    SecurityInsight -- THE GENERIC SI FINDING FIELDS OF SI'S OWN REPORTS, AS DATA (REQUIREMENTS #560).

    TEMPLATE  data-model/finding-texts.locked.json (kind 'finding-text', items 'reports', key = the report name):
                reports[]   { id (ReportName), securityDomain, source report | provider,
                              si_description / si_remediation / si_remediation_type / si_reference_url /
                              si_compliance_tags / si_mitre_tactics / si_mitre_techniques ... (any SI finding field) }
                rowColumns  SI finding field -> the Risk Analysis row columns that fill it (first non-empty)
                inference   mitre / compliance: keyword rows (first match) + the security domain's default -- what a row
                            gets when neither its source nor its report says (the rows the engine held in code before)
    CUSTOMER  Pro: one cfg.ItemOverride per report ('finding-texts:<report>'); Community: finding-texts.custom.json.

    WHO FILLS WHAT (one rule, every finding):
      1. the row's own columns (the source's text: Defender's description, remediation, KB tags / MITRE ...) -- rowColumns
      2. the report's item (SI's own text: what the finding is, how to fix it, its compliance and MITRE references)
      3. MITRE / compliance only: the inference rows over SecurityDomain + Subcategory + ConfigurationName, then the
         security domain's default
      4. nothing says: the field is absent -- unknown, never guessed.

    PURE except Get-SIFindingTextCatalog (reads the template). PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Get-SIItemValue -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-Conditions.ps1') }

$script:SIFindingTextCache = $null

function Test-SIFindingTextItem {
    <# PURE. The reasons one report item is not accepted (empty = accepted). -FindingFields: the catalog's finding field names (optional). #>
    param($Item, [string[]]$FindingFields)
    $why = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Item) { $why.Add('a finding-text item is empty'); return $why.ToArray() }
    $id = [string](Get-SIItemValue $Item 'id')
    if ($id -notmatch '^[A-Za-z0-9][A-Za-z0-9_\-\.]{0,199}$') { $why.Add(("finding-texts: '{0}' is not a report name" -f $id)) }
    $src = [string](Get-SIItemValue $Item 'source')
    if ($src -and $src -notin 'report', 'provider') { $why.Add(("finding-texts/{0}: source '{1}' (report | provider)" -f $id, $src)) }
    $rt = [string](Get-SIItemValue $Item 'si_remediation_type')
    if ($rt -and $rt -notin 'patch', 'configuration', 'upgrade', 'policy', 'manual') { $why.Add(("finding-texts/{0}: si_remediation_type '{1}' (patch | configuration | upgrade | policy | manual)" -f $id, $rt)) }
    $props = @(); if ($Item -is [System.Collections.IDictionary]) { $props = @($Item.Keys) } else { $props = @($Item.PSObject.Properties.Name) }
    foreach ($p in $props) {
        if ($p -in 'id', 'securityDomain', 'source', 'note', 'remove', 'baseHash') { continue }
        if ($p -cnotmatch '^si_[a-z0-9_]+$') { $why.Add(("finding-texts/{0}: '{1}' is not an SI field" -f $id, $p)); continue }
        if ($FindingFields -and $FindingFields -notcontains $p) { $why.Add(("finding-texts/{0}: '{1}' is not a finding field of the catalog" -f $id, $p)) }
    }
    foreach ($p in 'si_mitre_tactics') { foreach ($v in (Get-SIValueList (Get-SIItemValue $Item $p))) { if ($v -and [string]$v -notmatch '^TA\d{4}$') { $why.Add(("finding-texts/{0}: tactic '{1}' is not TA####" -f $id, $v)) } } }
    foreach ($p in 'si_mitre_techniques') { foreach ($v in (Get-SIValueList (Get-SIItemValue $Item $p))) { if ($v -and [string]$v -notmatch '^T\d{4}(\.\d{3})?$') { $why.Add(("finding-texts/{0}: technique '{1}' is not T####" -f $id, $v)) } } }
    $why.ToArray()
}

function Test-SIFindingTexts {
    <# PURE. The whole template: every report item valid and once, every inference row's pattern compiles, every rowColumns field an SI field. #>
    param($Document, [string[]]$FindingFields)
    $p = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Document) { return $p.ToArray() }
    $ids = @{}
    foreach ($r in @(Get-SIItemValue $Document 'reports')) {
        if ($null -eq $r) { continue }
        foreach ($x in (Test-SIFindingTextItem -Item $r -FindingFields $FindingFields)) { $p.Add([string]$x) }
        $id = [string](Get-SIItemValue $r 'id'); if ($ids.ContainsKey($id)) { $p.Add(("finding-texts: report '{0}' is listed twice" -f $id)) }; $ids[$id] = 1
    }
    $inf = Get-SIItemValue $Document 'inference'
    foreach ($k in 'mitre', 'compliance') {
        foreach ($r in @(Get-SIItemValue $inf $k)) {
            if ($null -eq $r) { continue }
            try { [void][regex]::new([string](Get-SIItemValue $r 'match')) } catch { $p.Add(("finding-texts: inference {0}/{1} has an invalid pattern" -f $k, [string](Get-SIItemValue $r 'id'))) }
        }
    }
    $rc = Get-SIItemValue $Document 'rowColumns'
    if ($null -ne $rc) { foreach ($pp in $rc.PSObject.Properties) { if ($pp.Name -cnotmatch '^si_[a-z0-9_]+$' -or ($FindingFields -and $FindingFields -notcontains $pp.Name)) { $p.Add(("finding-texts: rowColumns '{0}' is not a finding field" -f $pp.Name)) } } }
    $p.ToArray()
}

function ConvertTo-SIFindingTextCatalog {
    <# PURE. The merged template -> @{ Reports (name -> item, case-insensitive); RowColumns; Mitre; MitreDomains; Compliance; ComplianceDomains }. #>
    param($Document)
    $rep = New-Object System.Collections.Hashtable ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in @(Get-SIItemValue $Document 'reports')) { if ($null -ne $r -and @(Test-SIFindingTextItem -Item $r).Count -eq 0) { $rep[[string]$r.id] = $r } }
    $inf = Get-SIItemValue $Document 'inference'
    @{ Reports = $rep; RowColumns = (Get-SIItemValue $Document 'rowColumns')
       Mitre = @(Get-SIItemValue $inf 'mitre'); MitreDomains = (Get-SIItemValue $inf 'mitreDomains')
       Compliance = @(Get-SIItemValue $inf 'compliance'); ComplianceDomains = (Get-SIItemValue $inf 'complianceDomains') }
}

function Get-SIFindingTextCatalog {
    <# The merged template, read once per process; $null when it cannot be read (nothing is filled -- never fails). #>
    param([string]$Root, [string]$OverlayRoot = $global:SI_DataModelOverlayRoot, [switch]$Refresh)
    if ($script:SIFindingTextCache -and -not $Refresh -and -not $Root) { return $script:SIFindingTextCache }
    try {
        if (-not (Get-Command -Name Get-SIDataModelTemplate -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1') }
        $r = Get-SIDataModelRoot $Root
        if (-not (Test-Path -LiteralPath (Join-Path $r 'finding-texts.locked.json'))) {
            $r = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'data-model'
            if (-not (Test-Path -LiteralPath (Join-Path $r 'finding-texts.locked.json'))) { return $null }
        }
        $doc = (Get-SIDataModelTemplate -Name 'finding-texts' -Root $r -OverlayRoot $OverlayRoot).Document
        foreach ($p in (Test-SIFindingTexts -Document $doc)) { Write-Warning ('finding texts: {0}' -f $p) }
        $cat = ConvertTo-SIFindingTextCatalog -Document $doc
        if (-not $Root) { $script:SIFindingTextCache = $cat }
        return $cat
    } catch {
        Write-Warning ('finding texts could not be read -- {0}. The generic finding fields keep what the rows say.' -f $_.Exception.Message)
        return $null
    }
}

function Resolve-SIFindingTextInference {
    <#
    .SYNOPSIS  PURE. MITRE or compliance references for a row nothing else describes: the first inference row whose pattern
               matches -Blob (case-insensitive), else the security domain's default, else nothing.
    .OUTPUTS   @{ Tactics; Techniques } (mitre) or @{ Tags } (compliance), each a ';'-joined string ('' = none)
    #>
    param([Parameter(Mandatory)]$Catalog, [ValidateSet('mitre', 'compliance')][string]$Kind, [AllowEmptyString()][string]$Blob = '', [AllowEmptyString()][string]$Domain = '')
    $rows = $Catalog.Mitre; $doms = $Catalog.MitreDomains
    if ($Kind -eq 'compliance') { $rows = $Catalog.Compliance; $doms = $Catalog.ComplianceDomains }
    $hit = $null
    foreach ($r in @($rows)) {
        if ($null -eq $r) { continue }
        $pat = [string](Get-SIItemValue $r 'match'); if (-not $pat) { continue }
        $ok = $false; try { $ok = [regex]::IsMatch($Blob, $pat, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, [TimeSpan]::FromMilliseconds(200)) } catch { $ok = $false }
        if ($ok) { $hit = $r; break }
    }
    if ($null -eq $hit -and $Domain -and $null -ne $doms) { $hit = Get-SIItemValue $doms $Domain }
    $j = { param($o, $n) (((Get-SIValueList (Get-SIItemValue $o $n)).ToArray() | Where-Object { $_ }) -join ';') }
    if ($Kind -eq 'mitre') { return @{ Tactics = $(if ($hit) { & $j $hit 'si_mitre_tactics' } else { '' }); Techniques = $(if ($hit) { & $j $hit 'si_mitre_techniques' } else { '' }) } }
    @{ Tags = $(if ($hit) { & $j $hit 'si_compliance_tags' } else { '' }) }
}

function Get-SIFindingTextReport {
    <# PURE. The report's item of the catalog, or $null. #>
    param($Catalog, [AllowEmptyString()][string]$ReportName)
    if ($null -eq $Catalog -or -not $ReportName) { return $null }
    if ($Catalog.Reports.ContainsKey($ReportName)) { return $Catalog.Reports[$ReportName] }
    $null
}

function ConvertTo-SIFindingTextFields {
    <#
    .SYNOPSIS  PURE. The generic SI finding fields of one Risk Analysis row: the row's own columns (rowColumns, first
               non-empty), then the report's item for what the row left empty. Lists (compliance, MITRE, affected
               software, fix references) become lists; a field nothing fills is absent.
    .OUTPUTS   ordered hashtable si_* -> value
    #>
    param([Parameter(Mandatory)]$Row, $Catalog, [AllowEmptyString()][string]$ReportName = '')
    $out = [ordered]@{}
    if ($null -eq $Catalog) { return $out }
    $lists = @('si_compliance_tags', 'si_mitre_tactics', 'si_mitre_techniques', 'si_affected_product', 'si_affected_vendor', 'si_affected_version', 'si_fix_reference')
    $norm = {
        param([string]$f, $v)
        if ($null -eq $v) { return $null }
        if ($lists -contains $f) {
            $xs = @(foreach ($x in (Get-SIValueList $v)) { foreach ($y in ([string]$x).Split(';')) { $t = $y.Trim(); if ($t) { $t } } })
            if ($xs.Count -eq 0) { return $null }
            return , ([string[]]@($xs | Select-Object -Unique))
        }
        $s = ([string]$v).Trim(); if (-not $s) { return $null }
        $s
    }
    $rc = $Catalog.RowColumns
    if ($null -ne $rc) {
        foreach ($pp in $rc.PSObject.Properties) {
            # Get-SIValueList returns its list whole: @() around it would make the column list ONE item ("A B C")
            foreach ($col in (Get-SIValueList $pp.Value)) {
                $v = & $norm $pp.Name (Get-SIItemValue $Row ([string]$col))
                if ($null -ne $v) { $out[$pp.Name] = $v; break }
            }
        }
    }
    $rep = Get-SIFindingTextReport -Catalog $Catalog -ReportName $ReportName
    if ($null -ne $rep) {
        foreach ($pp in $rep.PSObject.Properties) {
            if ($pp.Name -cnotmatch '^si_[a-z0-9_]+$' -or $out.Contains($pp.Name)) { continue }
            $v = & $norm $pp.Name $pp.Value
            if ($null -ne $v) { $out[$pp.Name] = $v }
        }
    }
    $out
}
