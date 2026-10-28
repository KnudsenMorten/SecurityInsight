#Requires -Version 5.1
<#
    SecurityInsight BASELINE DATASET -- REQUIREMENTS #455, V3-DATA-MODEL part 2 (2.4.2).

    The SI field catalog (data-model/field-catalog.locked.json) IS the baseline: every security-relevant field Risk
    Analysis, the risk factors, correlation, the outputs and the GUI read, each with type, description and resolution.
    This file answers the two questions the catalog alone cannot:

      * WHICH PROVIDERS CAN FILL A FIELD -- derived from the provider mappings (data-model/mappings/*.json), never a second
        list in the catalog that could drift from them (Get-SIFieldProviders).
      * IS THE BASELINE COMPLETE FOR RISK ANALYSIS -- every v2 profile column a Risk Analysis report reads
        (risk-analysis-detection/RiskAnalysis_Queries_Locked.yaml over SI_*_Profile_CL) has its SI field: the column map in
        risk-analysis-detection/ra-ci-migration.locked.json names it (an SI field, an expression over SI fields, 'provider'
        when the report keeps reading that column from a provider table, or dropped with a reason), and that field exists
        in the catalog (Get-SIFieldBaseline -> Gaps).

    Raw data per provider is optional and lives outside the baseline (properties_<provider>_raw, SI_RawData; see
    SI-RecordCapture.ps1).

    PURE (files in, objects out). PowerShell 5.1: no ?. / ??, no ternary.
#>

if (-not (Get-Command -Name Get-SIDataModel -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot 'SI-DataModelTemplates.ps1') }

# KQL columns the Risk Analysis CI blocks derive from catalog fields (si_risk_factors -> si_rf_p / si_rf_c, si_tags ->
# si_tags_): legal in a column map expression without being catalog fields themselves.
$script:SIBaselineDerivedColumns = @{ si_rf_p = 'si_risk_factors'; si_rf_c = 'si_risk_factors'; si_tags_ = 'si_tags'; si_stale_ = 'si_last_seen'; si_last_seen_ = 'si_last_seen' }

function Get-SIFieldProviders {
    <#
    .SYNOPSIS  Per SI field: the providers whose mapping can fill it, with the record types and the source paths.
    .OUTPUTS   ordered hashtable  field -> [ @{ Provider; RecordTypes; Sources } ]  (providers in mapping order)
    #>
    param([Parameter(Mandatory)]$Model)
    $out = [ordered]@{}
    foreach ($p in $Model.Mappings.Keys) {
        foreach ($i in @($Model.Mappings[$p].mappings)) {
            if ($null -eq $i) { continue }
            $f = [string]$i.field
            if (-not $out.Contains($f)) { $out[$f] = New-Object System.Collections.Generic.List[object] }
            $have = $null
            foreach ($e in $out[$f]) { if ($e.Provider -eq $p) { $have = $e; break } }
            if ($null -eq $have) {
                $have = [pscustomobject]@{ Provider = [string]$p; RecordTypes = (New-Object System.Collections.Generic.List[string]); Sources = (New-Object System.Collections.Generic.List[string]) }
                $out[$f].Add($have)
            }
            foreach ($rt in @($i.recordTypes)) { if ($rt -and -not $have.RecordTypes.Contains([string]$rt)) { $have.RecordTypes.Add([string]$rt) } }
            foreach ($s in @($i.sources)) { if ($s -and -not $have.Sources.Contains([string]$s)) { $have.Sources.Add([string]$s) } }
        }
    }
    return $out
}

function Get-SIProfileColumnNames {
    <# The v2 profile tables' column names: asset-profiling-schema/*.schema.locked.json plus the columns every profile row
       carries that the per-engine files do not list. #>
    param([Parameter(Mandatory)][string]$SIRoot)
    $cols = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    $dir = Join-Path $SIRoot 'asset-profiling-schema'
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.schema.locked.json' -ErrorAction SilentlyContinue)) {
        $j = [IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json
        foreach ($x in @($j.fields)) { if ($x -and $x.name) { [void]$cols.Add([string]$x.name) } }
    }
    foreach ($c in 'PrimaryEntityId', 'CollectionTime', 'Tier', 'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity', 'SI_AssetId',
        'SI_AssetName', 'AssetName', 'AssetId', 'AssetType', 'AssetTags', 'IsExcludedByTag', 'UnsupportedOSDetected') { [void]$cols.Add($c) }
    return , $cols
}

function Get-SIRaProfileColumnReads {
    <#
    .SYNOPSIS  The v2 profile columns each Risk Analysis report reads.
               A report "reads" a profile column when it reads an SI_*_Profile_CL table and names the column (an identifier
               of its query outside comments and string literals, or a column_ifexists("<name>", ...) argument).
    .OUTPUTS   @{ Columns = ordered column -> [report names]; Reports = <reports reading a profile table> }
    #>
    param([Parameter(Mandatory)][string]$YamlText, [Parameter(Mandatory)][System.Collections.Generic.HashSet[string]]$ProfileColumns,
          [string[]]$OutputOnly = @())
    if (-not (Get-Command -Name ConvertFrom-SIYaml -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-Yaml.ps1') }
    $doc = ConvertFrom-SIYaml -Yaml $YamlText -SourceName 'RiskAnalysis_Queries_Locked.yaml'
    $cols = [ordered]@{}
    $n = 0
    foreach ($r in @($doc['Reports'])) {
        if ($null -eq $r) { continue }
        $q = (@($r['ReportQuery']) -join "`n")
        $s = [regex]::Replace($q, '(?m)//[^\r\n]*', '')
        $s = [regex]::Replace($s, '@?"(?:[^"\\\r\n]|\\.)*"', '""')
        $s = [regex]::Replace($s, "@?'(?:[^'\\\r\n]|\\.)*'", "''")
        if ($s -notmatch '\bSI_\w+?_Profile_CL\b') { continue }
        $n++
        $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($m in [regex]::Matches($s, '\b[A-Za-z_][A-Za-z0-9_]*\b')) { [void]$ids.Add($m.Value) }
        foreach ($m in [regex]::Matches($q, 'column_ifexists\(\s*[''"]([^''"]+)[''"]')) { [void]$ids.Add($m.Groups[1].Value) }
        foreach ($id in $ids) {
            if (-not $ProfileColumns.Contains($id) -or $OutputOnly -ccontains $id) { continue }
            if (-not $cols.Contains($id)) { $cols[$id] = New-Object System.Collections.Generic.List[string] }
            $cols[$id].Add([string]$r['ReportName'])
        }
    }
    return @{ Columns = $cols; Reports = $n }
}

function Get-SIRaCiFieldReads {
    <#
    .SYNOPSIS  The catalog SI fields each Risk Analysis report reads from the CI (SI_CI_CL) -- since #505 every report reads
               the CI, never a profile table, so this is what the baseline must hold for Risk Analysis.
               A report "reads" a field when it reads SI_CI_CL and names it (an identifier of its query outside comments and
               string literals, or a column_ifexists("<name>", ...) argument) and the catalog defines it.
    .OUTPUTS   @{ Fields = ordered field -> [report names]; Reports = <reports reading SI_CI_CL> }
    #>
    param([Parameter(Mandatory)][string]$YamlText, [Parameter(Mandatory)][hashtable]$CatalogFields)
    if (-not (Get-Command -Name ConvertFrom-SIYaml -ErrorAction SilentlyContinue)) { . (Join-Path (Split-Path -Parent $PSScriptRoot) '_shared\SI-Yaml.ps1') }
    $doc = ConvertFrom-SIYaml -Yaml $YamlText -SourceName 'RiskAnalysis_Queries_Locked.yaml'
    $out = [ordered]@{}
    $n = 0
    foreach ($r in @($doc['Reports'])) {
        if ($null -eq $r) { continue }
        $q = (@($r['ReportQuery']) -join "`n")
        $s = [regex]::Replace($q, '(?m)//[^\r\n]*', '')
        $s = [regex]::Replace($s, '@?"(?:[^"\\\r\n]|\\.)*"', '""')
        $s = [regex]::Replace($s, "@?'(?:[^'\\\r\n]|\\.)*'", "''")
        if ($s -notmatch '\bSI_CI_CL\b') { continue }
        $n++
        $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($m in [regex]::Matches($s, '\bsi_[a-z0-9_]+\b')) { [void]$ids.Add($m.Value) }
        foreach ($m in [regex]::Matches($q, 'column_ifexists\(\s*[''"](si_[a-z0-9_]+)[''"]')) { [void]$ids.Add($m.Groups[1].Value) }
        foreach ($id in $ids) {
            if (-not $CatalogFields.ContainsKey($id)) { continue }
            if (-not $out.Contains($id)) { $out[$id] = New-Object System.Collections.Generic.List[string] }
            $out[$id].Add([string]$r['ReportName'])
        }
    }
    return @{ Fields = $out; Reports = $n }
}

function Get-SIFieldBaseline {
    <#
    .SYNOPSIS  The baseline dataset as a table + its gaps.
    .OUTPUTS   @{
                 Fields   one row per catalog field the baseline holds (level record / both; not computed):
                          Name, Type, Classes, Group, Level, Policy, Description, Providers (fill it), RaColumns (the v2
                          profile columns Risk Analysis read that it replaces)
                 Gaps     [ @{ Kind; Item; Detail } ]:
                          ra-column-unmapped     a profile column a report reads has no entry in the column map
                          ra-field-missing       the column map names an SI field the catalog does not define
                          no-provider            a baseline field no provider mapping fills
                          needs-read             a field no provider fills BY DESIGN: what it would take is in the catalog
                                                 ('needsRead': the read and the permission) -- not left in Fields
                          authority-no-mapping   a field's authority order names a provider that has no mapping for it
                                                 (informational: the order is ready for a mapping that does not exist yet)
                 RaReports  how many reports read a profile table;  RaColumns  how many distinct columns they read (both 0
                            since #505: no report reads a profile table)
                 RaCiReports  how many reports read the CI (SI_CI_CL);  RaFields  how many distinct catalog fields they read
               }
    #>
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][string]$SIRoot, [string]$YamlText, $Migration)
    $cat = $Model['field-catalog']
    $fields = @{}; foreach ($f in @($cat.fields)) { $fields[[string]$f.name] = $f }
    $prov = Get-SIFieldProviders -Model $Model
    $gaps = New-Object System.Collections.Generic.List[object]
    if (-not $YamlText) { $YamlText = [IO.File]::ReadAllText((Join-Path $SIRoot 'risk-analysis-detection\RiskAnalysis_Queries_Locked.yaml')) }
    if ($null -eq $Migration) { $Migration = [IO.File]::ReadAllText((Join-Path $SIRoot 'risk-analysis-detection\ra-ci-migration.locked.json')) | ConvertFrom-Json }
    $map = @{}; foreach ($p in @($Migration.columnMap.PSObject.Properties)) { $map[$p.Name] = $p.Value }
    # report OUTPUT columns (kept names, filled from the CI) are not asset reads
    $outputOnly = @('AssetId', 'AssetName', 'AssetType', 'cmdbId', 'cmdbName', 'cmdbCriticality', 'cmdbDataSensitivity', 'MdeDeviceId', 'EntraAccountObjectId', 'AzureResourceId')
    $reads = Get-SIRaProfileColumnReads -YamlText $YamlText -ProfileColumns (Get-SIProfileColumnNames -SIRoot $SIRoot) -OutputOnly $outputOnly
    $raBy = @{}
    foreach ($col in $reads.Columns.Keys) {
        $e = $map[$col]
        if ($null -eq $e) { $gaps.Add([pscustomobject]@{ Kind = 'ra-column-unmapped'; Item = $col; Detail = ('read by ' + (@($reads.Columns[$col] | Select-Object -First 3) -join ', ')) }); continue }
    }
    foreach ($col in $map.Keys) {
        $si = [string]$map[$col].si
        if (-not $si -or $si -eq 'provider' -or $si -eq '_ciKey') { continue }
        foreach ($m in [regex]::Matches($si, '\bsi_[a-z0-9_]*')) {
            $tok = $m.Value
            if ($script:SIBaselineDerivedColumns.ContainsKey($tok)) { $tok = $script:SIBaselineDerivedColumns[$tok] }
            if (-not $fields.ContainsKey($tok)) { $gaps.Add([pscustomobject]@{ Kind = 'ra-field-missing'; Item = $tok; Detail = ('profile column ' + $col) }); continue }
            if (-not $raBy.ContainsKey($tok)) { $raBy[$tok] = New-Object System.Collections.Generic.List[string] }
            if (-not $raBy[$tok].Contains($col)) { $raBy[$tok].Add($col) }
        }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($f in @($cat.fields)) {
        $n = [string]$f.name
        if ([string]$f.level -notin 'record', 'both' -or [string]$f.resolution.policy -eq 'computed') { continue }
        $ps = @(); if ($prov.Contains($n)) { $ps = @($prov[$n] | ForEach-Object { $_.Provider }) }
        # a field SecurityInsight cannot fill from what it collects says so in the catalog ('needsRead': the read and the
        # permission it would take) -- an honest gap, never a mapping to a column nobody writes
        $needs = [string](Get-SIItemValue $f 'needsRead')
        if ($ps.Count -eq 0 -and $needs) { $gaps.Add([pscustomobject]@{ Kind = 'needs-read'; Item = $n; Detail = $needs }); continue }
        if ($ps.Count -eq 0) { $gaps.Add([pscustomobject]@{ Kind = 'no-provider'; Item = $n; Detail = 'no provider mapping fills it' }) }
        foreach ($a in @($f.resolution.authority)) {
            if (-not $a -or $a -eq 'cmdb_owner') { continue }
            if ($ps -notcontains [string]$a) { $gaps.Add([pscustomobject]@{ Kind = 'authority-no-mapping'; Item = $n; Detail = ('authority names ' + $a) }) }
        }
        $ra = @(); if ($raBy.ContainsKey($n)) { $ra = $raBy[$n].ToArray() }
        $rows.Add([pscustomobject][ordered]@{ Name = $n; Type = [string]$f.type; Classes = @($f.classes); Group = [string]$f.group; Level = [string]$f.level
                Policy = [string]$f.resolution.policy; Description = [string]$f.description; Providers = $ps; RaColumns = $ra })
    }
    $ciReads = Get-SIRaCiFieldReads -YamlText $YamlText -CatalogFields $fields
    return @{ Fields = $rows.ToArray(); Gaps = $gaps.ToArray(); RaReports = $reads.Reports; RaColumns = $reads.Columns.Count
              RaCiReports = $ciReads.Reports; RaFields = $ciReads.Fields.Count }
}
