#Requires -Version 5.1
<#
    RA-ColumnTypeAlign -- make every posted value match the Log Analytics column it lands in.

    WHY (#148). A Log Analytics column's type is fixed once the table exists, and the ingest module
    declares types from a SAMPLE of the data. When a column was first created as `string` and a later
    run sends an `int` (or the other way round), Log Analytics DISCARDS the value -- no error, the row
    lands, the cell is empty. Measured on the internal workspace: SI_RiskAnalysis_Detailed_CL holds
    CriticalityTier as string, and the tier was missing on ~87% of Detailed rows (7,811 of 7,811 in one
    report), while the export beside it had every value.

    The cure is not to guess a type: read the table's REAL column types and convert each value to that
    type before the DCR is declared and before the rows are posted. A value that cannot be converted is
    reported (it cannot land either way), never silently nulled.
#>

# Azure access: plain REST, no PowerShell modules (engine/_shared/SI-AzRest.ps1).
if (-not (Get-Command -Name Invoke-SIArm -ErrorAction SilentlyContinue)) { . (Join-Path $PSScriptRoot '../../_shared/SI-AzRest.ps1') }

function Get-RALaTableColumnTypes {
    <#
      Returns @{ <column> = <lower-case LA type> } for an existing table, @{} when the table does not
      exist yet (the first ingest will create it from the data), or $null when the schema could not be
      read -- the caller then posts as before and says so.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$WorkspaceResourceId,
        [Parameter(Mandatory)][string]$TableName,
        [int]$MaxAttempts = 4
    )
    $t = if ($TableName -match '_CL$') { $TableName } else { $TableName + '_CL' }
    $path = ('{0}/tables/{1}?api-version=2022-10-01' -f $WorkspaceResourceId.TrimEnd('/'), $t)
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $resp = Invoke-SIAzRestMethod -Path $path -Method GET -ErrorAction Stop
            $code = [int]$resp.StatusCode
            if ($code -eq 404) { return @{} }
            if ($code -ge 200 -and $code -lt 300) {
                $j = $resp.Content | ConvertFrom-Json
                $map = @{}
                foreach ($c in @($j.properties.schema.columns) + @($j.properties.schema.standardColumns)) {
                    if ($c -and $c.name) { $map[[string]$c.name] = ([string]$c.type).ToLowerInvariant() }
                }
                return $map
            }
            if ($code -ne 429 -and $code -lt 500) { return $null }
        } catch {
            if ($attempt -ge $MaxAttempts) { return $null }
        }
        Start-Sleep -Seconds ([Math]::Min(30, 3 * [Math]::Pow(2, $attempt - 1)))
    }
    return $null
}

function ConvertTo-RADecimal {
    <#
      A number, or $null. Culture-proof: "7.9" is 7.9, and so is "7,9" (a comma DECIMAL -- one comma
      followed by 1-2 digits). Never "79": parsing with the host culture (da-DK) or with thousands
      separators allowed turns either spelling into seventy-nine.
    #>
    param($Value)
    if ($null -eq $Value -or $Value -is [bool]) { return $null }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal] -or $Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte]) { return [double]$Value }
    $s = ([string]$Value).Trim()
    if ($s -match '^-?\d+,\d{1,2}$') { $s = $s.Replace(',', '.') }
    $d = 0.0
    if ([double]::TryParse($s, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { return $d }
    $null
}

function Get-RALaDecimalCompanions {
    <#
      The whole-number (int / long) columns of the table that need a `<column>_Exact` companion: those
      that receive a FRACTIONAL value in these rows, plus those whose companion the table already has (so
      the companion stays filled on every run once it exists).
      WHY: a column's type is fixed once the table exists. `Impact` was born `int`, so a CVSS of 7.9 could
      not land at all. The companion carries the exact value; the int column carries it rounded.
      The companion is TEXT in invariant form ("7.9" -- `toreal()` reads it back), NOT a real column: the
      ingest module (AzLogDcrIngestPS 1.7.2) has no mapping for a `double` and types such a column after
      whatever column it inferred before it -- measured 2026-09-29, the first `Impact_Decimal` was created
      `int` and could hold no decimal at all. Text is inferred correctly.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][hashtable]$Types,
        [string]$Suffix = '_Exact'
    )
    $ints = @($Types.Keys | Where-Object { $Types[$_] -in 'int','long' -and $_ -notlike "*$Suffix" })
    $need = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($c in $ints) { if ($Types.ContainsKey($c + $Suffix)) { [void]$need.Add($c) } }
    $open = @($ints | Where-Object { -not $need.Contains($_) })
    if ($open.Count -gt 0) {
        foreach ($row in $Rows) {
            if ($null -eq $row) { continue }
            foreach ($c in $open) {
                if ($need.Contains($c)) { continue }
                $p = $row.PSObject.Properties[$c]
                if (-not $p -or $null -eq $p.Value) { continue }
                $d = ConvertTo-RADecimal $p.Value
                if ($null -ne $d -and [Math]::Floor($d) -ne $d) { [void]$need.Add($c) }
            }
        }
    }
    @($need | Sort-Object)
}

function Get-RALaTextCompanions {
    <#
      The numeric (int / long / real) columns of the table that need a `<column>_Text` companion: those
      that receive TEXT in these rows -- e.g. two endpoint Summaries write a sentence ("84 asset(s) at tier
      3 are suppressed ...") into `Impact`, born int -- plus those whose companion the table already has.
      Without it the sentence cannot land at all.
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][hashtable]$Types,
        [string]$Suffix = '_Text'
    )
    $nums = @($Types.Keys | Where-Object { $Types[$_] -in 'int','long','real' })
    $need = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($c in $nums) { if ($Types.ContainsKey($c + $Suffix)) { [void]$need.Add($c) } }
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        foreach ($c in $nums) {
            if ($need.Contains($c)) { continue }
            $p = $row.PSObject.Properties[$c]
            if (-not $p -or $null -eq $p.Value -or $p.Value -is [bool]) { continue }
            if (([string]$p.Value).Trim() -eq '') { continue }
            if ($null -eq (ConvertTo-RADecimal $p.Value)) { [void]$need.Add($c) }
        }
    }
    @($need | Sort-Object)
}

function Get-RALaNumberCompanions {
    <#
      The DATETIME columns of the table that need a `<column>_Number` companion: those that receive a NUMBER in these
      rows, plus those whose companion the table already has. Measured on ring 1 (2026-10-11): SI_RiskAnalysis_Detailed_CL
      got LastSignInDays as `datetime` (the old schema inference typed an unmatched column after the column read before
      it -- LastSignInDateTime), the reports send whole days, and every value was discarded. A column's type cannot be
      changed once the table exists, so the number lands in the companion (a whole number as long). New tables never get
      the wrong type (Get-SILogSchemaRest no longer inherits a type).
    #>
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][hashtable]$Types,
        [string]$Suffix = '_Number'
    )
    $dts = @($Types.Keys | Where-Object { $Types[$_] -eq 'datetime' -and $_ -ne 'TimeGenerated' })
    $need = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($c in $dts) { if ($Types.ContainsKey($c + $Suffix)) { [void]$need.Add($c) } }
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        foreach ($c in $dts) {
            if ($need.Contains($c)) { continue }
            $p = $row.PSObject.Properties[$c]
            if ($p -and (Test-RALaIsNumber $p.Value)) { [void]$need.Add($c) }
        }
    }
    @($need | Sort-Object)
}

function Test-RALaIsNumber {
    <# PURE. A number value (a .NET number, or text that is only a number) -- never a date, never a bool. #>
    param($Value)
    if ($null -eq $Value -or $Value -is [bool] -or $Value -is [datetime]) { return $false }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal] -or $Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte]) { return $true }
    $s = ([string]$Value).Trim()
    return ($s -match '^-?\d+([.,]\d+)?$')
}

function ConvertTo-RALaColumnValue {
    <#
      Convert one value to a Log Analytics type. Returns @{ Ok = $true; Value = ... } or
      @{ Ok = $false } when the value cannot be represented in that type.
    #>
    param($Value, [string]$Type)
    if ($null -eq $Value) { return @{ Ok = $true; Value = $null } }
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    switch ($Type) {
        'string' {
            if ($Value -is [string]) { return @{ Ok = $true; Value = $Value } }
            if ($Value -is [System.Collections.IDictionary] -or ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) -or $Value -is [System.Management.Automation.PSCustomObject]) {
                return @{ Ok = $true; Value = (ConvertTo-Json -InputObject $Value -Compress -Depth 10) }
            }
            if ($Value -is [datetime]) { return @{ Ok = $true; Value = $Value.ToUniversalTime().ToString('o', $inv) } }
            if ($Value -is [System.IFormattable]) { return @{ Ok = $true; Value = $Value.ToString($null, $inv) } }
            return @{ Ok = $true; Value = [string]$Value }
        }
        { $_ -in 'int', 'long' } {
            if ($Value -is [int] -or $Value -is [long] -or $Value -is [int16] -or $Value -is [byte]) { return @{ Ok = $true; Value = [long]$Value } }
            if ($Value -is [bool]) { return @{ Ok = $true; Value = [long][int]$Value } }
            if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
                $d = [double]$Value
                if ([Math]::Floor($d) -eq $d) { return @{ Ok = $true; Value = [long]$d } }
                return @{ Ok = $false }
            }
            $s = ([string]$Value).Trim()
            if ($s -eq '') { return @{ Ok = $true; Value = $null } }
            $l = 0L
            if ([long]::TryParse($s, [System.Globalization.NumberStyles]::Integer, $inv, [ref]$l)) { return @{ Ok = $true; Value = $l } }
            $d = ConvertTo-RADecimal $s
            if ($null -ne $d -and [Math]::Floor($d) -eq $d) { return @{ Ok = $true; Value = [long]$d } }
            return @{ Ok = $false }
        }
        'real' {
            if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal] -or $Value -is [int] -or $Value -is [long]) { return @{ Ok = $true; Value = [double]$Value } }
            $s = ([string]$Value).Trim()
            if ($s -eq '') { return @{ Ok = $true; Value = $null } }
            $d = ConvertTo-RADecimal $s
            if ($null -ne $d) { return @{ Ok = $true; Value = $d } }
            return @{ Ok = $false }
        }
        'boolean' {
            if ($Value -is [bool]) { return @{ Ok = $true; Value = $Value } }
            $s = ([string]$Value).Trim().ToLowerInvariant()
            if ($s -in 'true', '1')  { return @{ Ok = $true; Value = $true } }
            if ($s -in 'false', '0') { return @{ Ok = $true; Value = $false } }
            if ($s -eq '') { return @{ Ok = $true; Value = $null } }
            return @{ Ok = $false }
        }
        default { return @{ Ok = $true; Value = $Value } }   # dynamic, datetime, guid: the service accepts the value as sent
    }
}

function Set-RALaColumnTypes {
    <#
      Convert, IN PLACE, every value of every row to the declared type of its column. Only columns the
      table declares are touched. Returns a report: per column, how many values were converted and how
      many could not be (those keep their value and are named, so a loss is visible instead of silent).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows,
        [Parameter(Mandatory)][hashtable]$Types,
        # whole-number columns that get a `<column>_Exact` companion (Get-RALaDecimalCompanions): the exact
        # value goes there as invariant text ("7.9"), the whole-number column gets it rounded -- neither is
        # ever left empty
        [string[]]$DecimalCompanions = @(),
        [string]$Suffix = '_Exact',
        # the SCHEMA SAMPLE only (never posted): make sure each companion carries a value in at least one
        # row, so the column is declared `string` even when this sample happens to hold no value for it
        [switch]$EnsureCompanionTyped,
        # numeric columns that get a `<column>_Text` companion (Get-RALaTextCompanions): TEXT sent to a
        # number column goes there, the number column is left empty for that row
        [string[]]$TextCompanions = @(),
        [string]$TextSuffix = '_Text',
        # datetime columns that get a `<column>_Number` companion (Get-RALaNumberCompanions): a NUMBER sent to a datetime
        # column goes there (whole = long), the datetime column is left empty for that row
        [string[]]$NumberCompanions = @(),
        [string]$NumberSuffix = '_Number'
    )
    $converted = @{}; $failed = @{}; $rounded = @{}; $moved = @{}; $toNumber = @{}
    if ($NumberCompanions.Count -gt 0) {
        foreach ($row in $Rows) {
            if ($null -eq $row) { continue }
            foreach ($c in $NumberCompanions) {
                $p = $row.PSObject.Properties[$c]
                $num = $null
                if ($p -and (Test-RALaIsNumber $p.Value)) {
                    $d = ConvertTo-RADecimal $p.Value
                    if ($null -ne $d) {
                        if ([Math]::Floor($d) -eq $d) { $num = [long]$d } else { $num = $d }
                        $p.Value = $null; $toNumber[$c] = 1 + [int]$toNumber[$c]
                    }
                }
                $cn = $c + $NumberSuffix
                if ($row.PSObject.Properties[$cn]) { $row.$cn = $num } else { $row | Add-Member -NotePropertyName $cn -NotePropertyValue $num }
            }
        }
        if ($EnsureCompanionTyped) {
            # the sample only (never posted): a value in every row, so the new column is declared long, not dynamic
            foreach ($r in @($Rows | Where-Object { $null -ne $_ })) { foreach ($c in $NumberCompanions) { if ($null -eq $r.($c + $NumberSuffix)) { $r.($c + $NumberSuffix) = [long]0 } } }
        }
    }
    if ($TextCompanions.Count -gt 0) {
        foreach ($row in $Rows) {
            if ($null -eq $row) { continue }
            foreach ($c in $TextCompanions) {
                $p = $row.PSObject.Properties[$c]
                $txt = $null
                if ($p -and $null -ne $p.Value -and $p.Value -isnot [bool] -and ([string]$p.Value).Trim() -ne '' -and $null -eq (ConvertTo-RADecimal $p.Value)) {
                    $txt = [string]$p.Value; $p.Value = $null; $moved[$c] = 1 + [int]$moved[$c]
                }
                $cn = $c + $TextSuffix
                if ($row.PSObject.Properties[$cn]) { $row.$cn = $txt } else { $row | Add-Member -NotePropertyName $cn -NotePropertyValue $txt }
            }
        }
        if ($EnsureCompanionTyped) {
            # EVERY row, not the first: the ingest module types a new column from the first row that CARRIES it,
            # and an empty cell there makes it `dynamic` (measured: MaxCvssScore_Exact). The sample is never posted.
            foreach ($r in @($Rows | Where-Object { $null -ne $_ })) { foreach ($c in $TextCompanions) { if ($null -eq $r.($c + $TextSuffix)) { $r.($c + $TextSuffix) = '' } } }
        }
    }
    if ($DecimalCompanions.Count -gt 0) {
        $seenValue = @{}
        foreach ($row in $Rows) {
            if ($null -eq $row) { continue }
            foreach ($c in $DecimalCompanions) {
                $p = $row.PSObject.Properties[$c]
                $d = if ($p) { ConvertTo-RADecimal $p.Value } else { $null }
                $exact = if ($null -ne $d) { $d.ToString('R', [System.Globalization.CultureInfo]::InvariantCulture) } else { $null }
                $cn = $c + $Suffix
                if ($row.PSObject.Properties[$cn]) { $row.$cn = $exact } else { $row | Add-Member -NotePropertyName $cn -NotePropertyValue $exact }
                if ($null -ne $d) {
                    $seenValue[$c] = $true
                    $r = [long][Math]::Round($d, [MidpointRounding]::AwayFromZero)
                    if ([double]$r -ne $d) { $rounded[$c] = 1 + [int]$rounded[$c] }
                    $p.Value = $r
                }
            }
        }
        if ($EnsureCompanionTyped) {
            foreach ($r in @($Rows | Where-Object { $null -ne $_ })) { foreach ($c in $DecimalCompanions) { if ($null -eq $r.($c + $Suffix)) { $r.($c + $Suffix) = '' } } }
        }
    }
    $checkable = @{}
    foreach ($k in $Types.Keys) { if ($Types[$k] -in 'string','int','long','real','boolean') { $checkable[$k] = $Types[$k] } }
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        foreach ($p in $row.PSObject.Properties) {
            $type = $checkable[$p.Name]
            if (-not $type) { continue }
            $v = $p.Value
            if ($null -eq $v) { continue }
            $already = switch ($type) {
                'string'  { $v -is [string] }
                'int'     { $v -is [long] -or $v -is [int] }
                'long'    { $v -is [long] -or $v -is [int] }
                'real'    { $v -is [double] }
                'boolean' { $v -is [bool] }
            }
            if ($already) { continue }
            $r = ConvertTo-RALaColumnValue -Value $v -Type $type
            if ($r.Ok) {
                $p.Value = $r.Value
                $converted[$p.Name] = 1 + [int]$converted[$p.Name]
            } else {
                $failed[$p.Name] = 1 + [int]$failed[$p.Name]
            }
        }
    }
    [pscustomobject]@{ Converted = $converted; Failed = $failed; Rounded = $rounded; MovedToText = $moved; MovedToNumber = $toNumber }
}
