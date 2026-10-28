#Requires -Version 5.1
<#
    SecurityInsight OUTPUT FIELD MAPPER -- P5 of the v3 data model (V3-DATA-MODEL part 2, 2.12; operator 2026-10-08: "we
    also need an output field mapper for excel, connectors, etc. so we can define what is sent out").

    Every output reads ONE thing -- the CI document (or a finding / record row) -- and an OUTPUT MAP
    (data-model/outputs/<id>.json, shipped + the customer's overrides per column) says which columns it receives:

        { "target": "u_tier", "from": "si_tier" }
        { "target": "Linked objects", "from": "si_linked_objects", "op": "render:provider:id" }

      from   an SI field of the item | finding.<x> / summary.<x> / record.<x> (a property of the item) |
             a system token: $run_id  $run_time  $changed_at  $row_hash  $const:<value>
             #914 the contract envelope, filled by the data-out writer: $action $batch_id $cleared $reason $replaces
      op     the CLOSED output operation set (no code runs from a map):
             enum:<value-map>  first  join:<sep>  join_ids:<sep>  render:<a>:<b>  format_date  round:<n>  mask
             domain_part  if_class:<class>  lower  upper
      filter { "<field>": [ values ] } -- only items whose field is one of the values
      as     optional: the name the output gives the column (the customer's rename); default the target. The target stays
             the column's KEY -- what an override matches on -- so a renamed column keeps its place and its UpgradeAvailable
             check. Customer changes: Pro cfg.ItemOverride (kind 'datamodel', key 'outputs/<id>:<target>'), Community
             data-model/outputs/<id>.custom.json; both merged per column by the data-model loader.
    $row_hash is the SHA-256 of the row's other columns (not of the run time) -- what a connector's delta compares.

    The same mapper serves Excel, the connectors and (Pro) the web app's grids, whose column chooser edits the same maps.
    PowerShell 5.1: no ?. / ??, no ternary, no Set-StrictMode.
#>

. (Join-Path $PSScriptRoot 'SI-FieldMapper.ps1')

function Get-SIOutputColumnName {
    <# PURE. The name an output gives one column: its 'as' (the customer's rename) when set, else its target. #>
    param($Column)
    $as = [string](Get-SIItemValue $Column 'as')
    if (-not [string]::IsNullOrWhiteSpace($as)) { return $as.Trim() }
    return [string]$Column.target
}

function Get-SIOutputColumnsInOrder {
    <#
    .SYNOPSIS  PURE. The columns of an output map in the order they are sent (owner 2026-10-19, the column builder of
               Configuration > Connectors > Fields sent): the map's order, then every column with a 'position' (1 = first;
               the customer moved it) taken out and put back at that place -- lowest place first, a place past the end is
               the end, equal places keep the map's order. The web app's twin: OutputMapRules.Arrange (a test compares).
    #>
    param([AllowEmptyCollection()][object[]]$Columns = @())
    $plain = New-Object System.Collections.Generic.List[object]
    $placed = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($c in @($Columns)) {
        if ($null -eq $c) { continue }
        $p = Get-SIItemValue $c 'position'
        $n = 0
        if ($null -ne $p -and [int]::TryParse([string]$p, [ref]$n) -and $n -ge 1) { $placed.Add([pscustomobject]@{ Pos = $n; Index = $i; Column = $c }) }
        else { $plain.Add($c) }
        $i++
    }
    foreach ($x in @($placed | Sort-Object -Property @{ Expression = 'Pos' }, @{ Expression = 'Index' })) {
        $at = [Math]::Min([Math]::Max($x.Pos - 1, 0), $plain.Count)
        $plain.Insert($at, $x.Column)
    }
    # unrolled: callers collect it with @(...)
    return $plain.ToArray()
}

function Get-SIOutputValue {
    <# One column's raw value from an item, before its op. #>
    param($Item, [string]$From, [hashtable]$Context)
    if ($From.StartsWith('$const:')) { return $From.Substring(7) }
    switch ($From) {
        '$run_id' { return [string]$Context.RunId }
        '$run_time' { return $Context.RunTime }
        '$changed_at' { if ($Context.ChangedAt) { return $Context.ChangedAt }; return $Context.RunTime }
        '$row_hash' { return $null }      # filled after the other columns
        # #914 the contract's envelope (u_action, u_si_batch_id, u_si_cleared, u_si_reason, u_si_replaces): the data-out
        # writer fills them; never part of the row hash
        { $_ -in '$action', '$batch_id', '$cleared', '$reason', '$replaces' } { return $null }
    }
    $m = [regex]::Match($From, '^(finding|summary|record)\.(.+)$')
    if ($m.Success) { return (Get-SIItemValue $Item $m.Groups[2].Value) }
    return (Get-SIItemValue $Item $From)
}

function Invoke-SIOutputOp {
    <# One output operation over a value. #>
    param($Value, [string]$Op, $Item, $ValueMaps)
    if (-not $Op) { return $Value }
    $i = $Op.IndexOf(':'); $name = $Op; $arg = ''
    if ($i -ge 0) { $name = $Op.Substring(0, $i); $arg = $Op.Substring($i + 1) }
    switch ($name) {
        'enum' {
            if ($null -eq $Value) { return $null }
            $map = Get-SIItemValue $ValueMaps $arg
            if ($null -eq $map) { throw "output enum:${arg}: no such value map" }
            $r = Get-SIValueMapResult -Map $map -Value $Value
            if ($r.Found) { return $r.Value }; return $null
        }
        'first' { foreach ($x in (Get-SIValueList $Value)) { return $x }; return $null }
        'join' { $sep = $arg; if (-not $sep) { $sep = ';' }; $vl = Get-SIValueList $Value; return ((@($vl | ForEach-Object { [string]$_ })) -join $sep) }
        'join_ids' {
            $sep = $arg; if (-not $sep) { $sep = ';' }
            # Get-SIValueList returns its list as ONE object: pipe the VARIABLE (that enumerates it), never @(<the call>)
            $vl = Get-SIValueList $Value
            return ((@($vl | ForEach-Object { $id = Get-SIItemValue $_ 'id'; if ($null -ne $id -and -not ($_ -is [string])) { [string]$id } else { [string]$_ } })) -join $sep)
        }
        'render' {
            $parts = $arg.Split(':')
            $vl = Get-SIValueList $Value
            return ((@($vl | ForEach-Object { $e = $_; (@($parts | ForEach-Object { [string](Get-SIItemValue $e $_) }) -join ':') })) -join '; ')
        }
        'format_date' { $t = ConvertTo-SIUtcOrNull $Value; if ($null -eq $t) { return $null }; return $t.ToString('yyyy-MM-dd HH:mm', [System.Globalization.CultureInfo]::InvariantCulture) }
        'round' { $n = ConvertTo-SINumberOrNull $Value; if ($null -eq $n) { return $null }; $d = 0; if ($arg) { $d = [int]$arg }; return [Math]::Round($n, $d) }
        'mask' { if (Test-SIValueEmpty $Value) { return $Value }; return '***' }
        'domain_part' { $s = [string]$Value; $j = $s.IndexOf('.'); if ($j -lt 0) { return '' }; return $s.Substring($j + 1) }
        'if_class' { if ([string](Get-SIItemValue $Item 'si_class') -eq $arg) { return $Value }; return $null }
        'lower' { if ($null -eq $Value) { return $null }; return ([string]$Value).ToLowerInvariant() }
        'upper' { if ($null -eq $Value) { return $null }; return ([string]$Value).ToUpperInvariant() }
        default { throw "unknown output operation '$name'" }
    }
}

function Test-SIOutputFilter {
    param($Item, $Filter)
    if ($null -eq $Filter) { return $true }
    foreach ($p in $Filter.PSObject.Properties) {
        $want = @($p.Value | ForEach-Object { [string]$_ })
        $have = [string](Get-SIItemValue $Item $p.Name)
        if ($want -notcontains $have) { return $false }
    }
    return $true
}

function Export-SIOutputWorkbookSheet {
    <#
        Items -> one worksheet of an .xlsx, through an output map (SI's own xlsx writer, no module). Values the map left as
        arrays or objects are flattened to text. Returns the number of rows written.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$SheetName, [Parameter(Mandatory)]$Map,
          [AllowEmptyCollection()][object[]]$Items = @(), $ValueMaps, [hashtable]$Context = @{})
    if (-not (Get-Command -Name Write-SIXlsxWorksheet -ErrorAction SilentlyContinue)) {
        . (Join-Path (Split-Path -Parent $PSScriptRoot) 'risk-analysis\_shared\RA-XlsxWriter.ps1')
    }
    $header = @((Get-SIOutputColumnsInOrder -Columns @($Map.columns)) | ForEach-Object { Get-SIOutputColumnName $_ })
    $rows = New-Object 'System.Collections.Generic.List[object[]]'
    foreach ($r in @(Invoke-SIOutputMap -Map $Map -Items $Items -ValueMaps $ValueMaps -Context $Context)) {
        $cells = foreach ($h in $header) {
            $v = $r.$h
            if ($null -eq $v -or $v -is [string] -or $v -is [ValueType]) { $v }
            elseif ($v -is [System.Collections.IEnumerable]) { (@($v | ForEach-Object { if ($_ -is [string] -or $_ -is [ValueType]) { [string]$_ } else { $_ | ConvertTo-Json -Compress -Depth 4 } }) -join '; ') }
            else { $v | ConvertTo-Json -Compress -Depth 4 }
        }
        $rows.Add([object[]]@($cells))
    }
    Write-SIXlsxWorksheet -Path $Path -SheetName $SheetName -Header $header -Rows $rows -TableName (($SheetName -replace '[^A-Za-z0-9]', '') + 'Table')
    return $rows.Count
}

function Invoke-SIOutputMap {
    <#
    .SYNOPSIS  Items (CI documents, findings, records) -> the output's rows, column by column, in the map's order.
    .OUTPUTS   one [pscustomobject] per item that passes the filter (plain output: callers write @(...))
    #>
    param(
        [Parameter(Mandatory)]$Map,
        [AllowEmptyCollection()][object[]]$Items = @(),
        $ValueMaps,
        [hashtable]$Context = @{}
    )
    if (-not $Context.ContainsKey('RunTime')) { $Context.RunTime = [datetime]::UtcNow }
    # the row's columns in the order they are sent; the row hash over the MAP's order, so moving a column never makes every
    # row look changed to a connector's delta
    $cols = @(Get-SIOutputColumnsInOrder -Columns @($Map.columns))
    $hashCols = @($Map.columns)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        foreach ($it in $Items) {
            if ($null -eq $it -or -not (Test-SIOutputFilter -Item $it -Filter $Map.filter)) { continue }
            $row = [ordered]@{}
            $hashCol = $null
            foreach ($c in $cols) {
                $from = [string]$c.from
                $name = Get-SIOutputColumnName $c
                if ($from -eq '$row_hash') { $hashCol = $name; $row[$hashCol] = $null; continue }
                $v = Get-SIOutputValue -Item $it -From $from -Context $Context
                $v = Invoke-SIOutputOp -Value $v -Op ([string]$c.op) -Item $it -ValueMaps $ValueMaps
                $row[$name] = $v
            }
            if ($hashCol) {
                $parts = foreach ($c in $hashCols) {
                    if ([string]$c.from -in '$row_hash', '$run_time', '$run_id', '$changed_at', '$action', '$batch_id', '$cleared', '$reason', '$replaces') { continue }
                    $x = $row[(Get-SIOutputColumnName $c)]
                    if ($x -is [datetime]) { $x.ToString('o') } elseif ($null -eq $x) { '' } else { ($x | ConvertTo-Json -Compress -Depth 6) }
                }
                $row[$hashCol] = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($parts -join '|')))) -replace '-', '').ToLowerInvariant()
            }
            [pscustomobject]$row
        }
    } finally { $sha.Dispose() }
}
