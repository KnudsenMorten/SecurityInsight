#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  Row shaping: field lookup, normalisation, de-duplication and scope filtering.
#
#  The row-level helpers every report path shares BEFORE scoring: pick a field by any of several
#  names, normalise it, build a dedupe key, choose the most complete of a set of duplicate rows, and
#  deep-convert nested structures to PSObjects. Pure data shaping - no I/O, no globals written.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

# First non-empty value among $Names on $Row, else $null.
#
# AUDIT #16: this function was DEFINED TWICE in this file (the other at ~line 304, deleted
# 2026-08-05). Both were top level, so the later definition -- this one -- silently won for all 23
# call sites; the earlier one never executed. They were NOT equivalent, which is why the duplicate
# mattered: the dead one returned "" and coerced to [string], this one returns $null and preserves
# the ORIGINAL TYPE, and only this one is null-safe on $Row. Anyone reading the dead copy would have
# had the contract exactly wrong.
#
# Keep this the only definition. Two same-named functions split across dot-sourced files would let
# LOAD ORDER decide which wins -- a behaviour change with no parse error to announce it.
# `tests/Get-EngineFunctionInventory.ps1` reports duplicate names for this reason.
function Get-RowValue {
  param(
    [Parameter(Mandatory=$true)] $Row,
    [Parameter(Mandatory=$true)] [string[]] $Names
  )
  foreach ($n in $Names) {
    if ($Row -and ($Row.PSObject.Properties.Name -contains $n)) {
      $v = $Row.$n
      if ($null -ne $v -and ("" + $v).Trim() -ne "") { return $v }
    }
  }
  return $null
}

function ConvertTo-NormalizedString {
  param([AllowNull()] $Value)

  if ($null -eq $Value) { return "" }

  # arrays / IEnumerable -> stable string
  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
    $items = [System.Collections.Generic.List[string]]::new()
    foreach ($x in $Value) {
      if ($null -eq $x) { continue }
      $s = ("" + $x).Trim()
      if ($s -ne "") { [void]$items.Add($s) }
    }
    if ($items.Count -eq 0) { return "" }
    $arr = $items.ToArray()
    [array]::Sort($arr)
    return ($arr -join ";").ToLowerInvariant()
  }

  return (("" + $Value).Trim()).ToLowerInvariant()
}

function New-DedupeKey {
  <#
    Generic key builder.

    KeyCandidates is tried in order. Each candidate is an array of "field alternatives".
    Example:
      @(
        @(@("DeviceId","MachineId"), @("ConfigurationId","Id")),
        @(@("EventId","RecordId","Id"))
      )
    Meaning:
      - For the first candidate, we need one value from (DeviceId OR MachineId) AND one value from (ConfigurationId OR Id)
      - If any part is missing/blank, the candidate fails and we try next.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)] $Row,
    [Parameter(Mandatory=$true)] [object[]] $KeyCandidates
  )

  foreach ($candidate in $KeyCandidates) {
    $parts = [System.Collections.Generic.List[string]]::new()
    $ok = $true

    foreach ($fieldAlternatives in $candidate) {
      $v = Get-RowValue -Row $Row -Names @($fieldAlternatives)
      $s = ConvertTo-NormalizedString $v
      if ($s -eq "") { $ok = $false; break }
      [void]$parts.Add($s)
    }

    if ($ok -and $parts.Count -gt 0) {
      return ($parts.ToArray() -join "|")
    }
  }

  return ""
}

function Get-GenericCompletenessScore {
  param(
    [Parameter(Mandatory=$true)] $Row,
    [string[]] $ColumnsToConsider = @()
  )

  $props =
    if ($ColumnsToConsider.Count -gt 0) {
      $Row.PSObject.Properties | Where-Object { $ColumnsToConsider -contains $_.Name }
    } else {
      $Row.PSObject.Properties
    }

  $filled = 0
  $total = 0
  $stringLen = 0

  foreach ($p in $props) {
    $total++
    $v = $p.Value
    if ($null -eq $v) { continue }

    if ($v -is [string]) {
      $t = $v.Trim()
      if ($t -eq "") { continue }
      $filled++
      $stringLen += $t.Length
      continue
    }

    if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) {
      $any = $false
      foreach ($x in $v) {
        if ($null -ne $x -and ("" + $x).Trim() -ne "") { $any = $true; break }
      }
      if (-not $any) { continue }
      $filled++
      continue
    }

    $filled++
  }

  return [pscustomobject]@{
    Filled    = $filled
    Total     = $total
    StringLen = $stringLen
  }
}

function Select-BestRow {
  <#
    Generic "best row" selector.

    PriorityRules (optional) are evaluated first (in order). If a rule can decide, it wins.
    If not, we fall back to generic completeness.

    PriorityRules examples:
      @{ Column="CriticalityTier"; Type="int"; Direction="asc"; MissingLast=$true }
      @{ Column="Impact"; Type="int"; Direction="desc"; MissingLast=$true }

    Supported Type: int | double | string
    Direction: asc | desc
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)] [object[]] $Rows,
    [object[]] $PriorityRules = @(),
    [string[]] $CompletenessColumns = @()
  )

  if ($Rows.Count -eq 1) { return $Rows[0] }

  $best = $null
  foreach ($r in $Rows) {
    if ($null -eq $best) { $best = $r; continue }

    $picked = $false

    foreach ($rule in $PriorityRules) {
      if ($null -eq $rule) { continue }
      $col = $rule.Column
      if (-not $col) { continue }

      $hasA = ($r.PSObject.Properties.Name -contains $col)
      $hasB = ($best.PSObject.Properties.Name -contains $col)

      $a = if ($hasA) { $r.$col } else { $null }
      $b = if ($hasB) { $best.$col } else { $null }

      $aEmpty = ($null -eq $a -or ("" + $a).Trim() -eq "")
      $bEmpty = ($null -eq $b -or ("" + $b).Trim() -eq "")

      if ($aEmpty -and $bEmpty) { continue }

      $missingLast = $true
      if ($rule.ContainsKey("MissingLast")) { $missingLast = [bool]$rule.MissingLast }

      if ($aEmpty -ne $bEmpty) {
        if ($missingLast) {
          if (-not $aEmpty) { $best = $r }
        } else {
          if ($aEmpty) { $best = $r }
        }
        $picked = $true
        break
      }

      $type = ("" + $rule.Type).ToLowerInvariant()
      $dir  = ("" + $rule.Direction).ToLowerInvariant()

      $cmp = 0
      try {
        if ($type -eq "int") {
          $ai = [int]$a; $bi = [int]$b
          $cmp = $ai.CompareTo($bi)
        } elseif ($type -eq "double") {
          $ad = [double]$a; $bd = [double]$b
          $cmp = $ad.CompareTo($bd)
        } else {
          $as = ConvertTo-NormalizedString $a
          $bs = ConvertTo-NormalizedString $b
          $cmp = [string]::Compare($as, $bs, $true)
        }
      } catch { $cmp = 0 }

      if ($cmp -ne 0) {
        if ($dir -eq "asc") {
          if ($cmp -lt 0) { $best = $r }
        } else {
          if ($cmp -gt 0) { $best = $r }
        }
        $picked = $true
        break
      }
    }

    if ($picked) { continue }

    $sA = Get-GenericCompletenessScore -Row $r -ColumnsToConsider $CompletenessColumns
    $sB = Get-GenericCompletenessScore -Row $best -ColumnsToConsider $CompletenessColumns

    if ($sA.Filled -gt $sB.Filled) { $best = $r; continue }
    if ($sA.Filled -lt $sB.Filled) { continue }

    if ($sA.StringLen -gt $sB.StringLen) { $best = $r; continue }
    if ($sA.StringLen -lt $sB.StringLen) { continue }

    # stable final tie-breaker
    $sigA = ConvertTo-NormalizedString (($r.PSObject.Properties | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "|")
    $sigB = ConvertTo-NormalizedString (($best.PSObject.Properties | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "|")
    if ([string]::Compare($sigA, $sigB, $true) -lt 0) { $best = $r }
  }

  return $best
}

function Deduplicate-RowsGeneric {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)] $Rows,
    [Parameter(Mandatory=$true)] [object[]] $KeyCandidates,
    [object[]] $PriorityRules = @(),
    [string[]] $CompletenessColumns = @(),
    [switch] $KeepUnkeyed
  )

  $rowsList = [System.Collections.Generic.List[object]]::new()
  foreach ($r in $Rows) { if ($null -ne $r) { $rowsList.Add($r) } }
  $rowsArr = $rowsList.ToArray()
  if ($rowsArr.Count -eq 0) { return @() }

  foreach ($r in $rowsArr) {
    $k = New-DedupeKey -Row $r -KeyCandidates $KeyCandidates
    $r | Add-Member -NotePropertyName "__DedupeKey" -NotePropertyValue $k -Force
  }

  $out = [System.Collections.Generic.List[object]]::new()

  $groups = $rowsArr | Group-Object "__DedupeKey"
  foreach ($g in $groups) {
    $key = $g.Name

    if ($key -eq "" -and -not $KeepUnkeyed) {
      foreach ($r in $g.Group) { [void]$out.Add($r) }
      continue
    }

    if ($g.Count -eq 1) {
      [void]$out.Add($g.Group[0])
      continue
    }

    $best = Select-BestRow -Rows $g.Group -PriorityRules $PriorityRules -CompletenessColumns $CompletenessColumns
    [void]$out.Add($best)
  }

  return @($out.ToArray())
}

function Deduplicate-Rows {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)] $Rows
  )

  # ----- StrictMode-safe global checks -----

  $KeyCandidates = $null
  if (Get-Variable -Name DedupeKeyCandidates -Scope Global -ErrorAction SilentlyContinue) {
      $KeyCandidates = $global:DedupeKeyCandidates
  }

  if (-not $KeyCandidates) {
      $KeyCandidates = @(
        @(@("DeviceId","DeviceGuid","MachineId","HostId"), @("ConfigurationId","ControlId","RuleId","RecommendationId","Id")),
        @(@("AadDeviceId","AzureAdDeviceId","DeviceKey"), @("ConfigurationId","ControlId","RuleId","RecommendationId","Id")),
        @(@("EventId","AlertId","IncidentId","RecordId","Id")),
        @(@("DeviceId","MachineId","AadDeviceId","DeviceKey","AssetName","DeviceName","Computer","HostName"), @("Title","Name","DisplayName"))
      )
  }

  $PriorityRules = $null
  if (Get-Variable -Name DedupePriorityRules -Scope Global -ErrorAction SilentlyContinue) {
      $PriorityRules = $global:DedupePriorityRules
  }

  if (-not $PriorityRules) {
      $PriorityRules = @(
        @{ Column="CriticalityTier"; Type="int"; Direction="asc"; MissingLast=$true },
        @{ Column="Impact";         Type="int"; Direction="desc"; MissingLast=$true }
      )
  }

  $CompletenessColumns = $null
  if (Get-Variable -Name DedupeCompletenessColumns -Scope Global -ErrorAction SilentlyContinue) {
      $CompletenessColumns = $global:DedupeCompletenessColumns
  }

  if (-not $CompletenessColumns) {
      $CompletenessColumns = @()
  }

  return Deduplicate-RowsGeneric `
    -Rows $Rows `
    -KeyCandidates $KeyCandidates `
    -PriorityRules $PriorityRules `
    -CompletenessColumns $CompletenessColumns `
    -KeepUnkeyed
}



function ConvertTo-PSObjectDeep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $InputObject,
        [switch] $StripOData,
        [switch] $CastPrimitiveArrays,
        [switch] $ConvertArraysToString,
        [string] $ArrayJoinChar = ', ',
        [switch] $PreserveRootArray = $true
    )

    function _IsPrimitive([object]$x) {
        if ($null -eq $x) { return $true }
        $t = $x.GetType()
        return ($t.IsPrimitive -or $t.FullName -in @(
            'System.String','System.Decimal','System.DateTime','System.Guid','System.TimeSpan'
        ))
    }

    function _Convert([object]$obj, [bool]$isRoot = $false) {

        if ($null -eq $obj) { return $null }

        # PERFORMANCE (a query slice is tens of thousands of rows x ~50 columns): a value that is returned as it is (no
        # object, no dictionary, no list -- the last line of this function) is taken over directly instead of through a
        # call of this function per cell. The test is exactly the branches below, in their order.
        if ($obj -is [pscustomobject]) {
            $ordered = [ordered]@{}
            foreach ($p in $obj.PSObject.Properties) {
                if ($StripOData -and ($p.Name -like '*@odata*')) { continue }
                $v = $p.Value
                if ($null -eq $v -or ($v -isnot [pscustomobject] -and $v -isnot [System.Collections.IDictionary] -and ($v -is [string] -or $v -isnot [System.Collections.IEnumerable]))) { $ordered[$p.Name] = $v }
                else { $ordered[$p.Name] = _Convert $v $false }
            }
            return [pscustomobject]$ordered
        }

        if ($obj -is [System.Collections.IDictionary]) {
            $ordered = [ordered]@{}
            # get_Keys(), never .Keys: on a dictionary that HAS an entry named 'Keys', .Keys is that entry's value.
            # Live 2026-10-13: the report field LookupNeededKeys carries one (the key lines of the lookup cut), so .Keys
            # gave the KQL text, the declaration came out as one empty property, and the per-slice cut never turned on.
            foreach ($k in @($obj.get_Keys())) {
                if ($StripOData -and ($k -is [string]) -and ($k -like '*@odata*')) { continue }
                $v = $obj[$k]
                if ($null -eq $v -or ($v -isnot [pscustomobject] -and $v -isnot [System.Collections.IDictionary] -and ($v -is [string] -or $v -isnot [System.Collections.IEnumerable]))) { $ordered[$k] = $v }
                else { $ordered[$k] = _Convert $v $false }
            }
            return [pscustomobject]$ordered
        }

        if (($obj -is [System.Collections.IEnumerable]) -and -not ($obj -is [string])) {

            # a list, never += on an array (that copies the whole array once per item)
            $itemList = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $obj) { $itemList.Add((_Convert $item $false)) }
            $items = $itemList.ToArray()

            if ($ConvertArraysToString -and -not ($isRoot -and $PreserveRootArray)) {
                $pieces = foreach ($e in $items) {
                    if (_IsPrimitive $e) { $e }
                    else {
                        try { ($e | ConvertTo-Json -Compress -Depth 12) }
                        catch { [string]$e }
                    }
                }
                return ($pieces -join $ArrayJoinChar)
            }

            if ($CastPrimitiveArrays -and -not $ConvertArraysToString -and $items.Count -gt 0) {

                # StrictMode-safe: always force arrays from pipelines
                $nonNull   = @($items | Where-Object { $_ -ne $null })
                $typeNames = @($nonNull | ForEach-Object { $_.GetType().FullName } | Select-Object -Unique)

                $allPrim = (@($nonNull | ForEach-Object { _IsPrimitive $_ } | Where-Object { -not $_ }).Count -eq 0)

                if ($allPrim -and $typeNames.Count -eq 1) {
                    switch ($typeNames[0]) {
                        'System.String'  { return [string[]] $items }
                        'System.Int32'   { return [int[]]    $items }
                        'System.Int64'   { return [long[]]   $items }
                        'System.Double'  { return [double[]] $items }
                        'System.Boolean' { return [bool[]]   $items }
                    }
                }
            }

            return @($items)
        }

        return $obj
    }

    $rootIsArray = (($InputObject -is [System.Collections.IEnumerable]) -and -not ($InputObject -is [string]))

    if ($rootIsArray -and $PreserveRootArray) {
        # a list, never += on an array: a 43,000-row slice copied the whole array once per row (minutes per slice)
        $out = [System.Collections.Generic.List[object]]::new()
        foreach ($i in $InputObject) { $out.Add((_Convert $i $false)) }
        return $out.ToArray()
    }

    return (_Convert $InputObject $true)
}

# Build the schema sample that CheckCreateUpdate-TableDcr-Structure uses to DECLARE the Log
# Analytics custom table + DCR columns. The module takes the UNION of the property names across
# every row it is handed (verified 2026-08-08: row 1 carried 53 columns, the union of the first 100
# was 69, and the live DCR declared exactly those 69) -- so any column absent from the sample is
# never declared, and Build-DataArrayToAlignWithSchema then SILENTLY DROPS it at ingest. The data
# posts, the run logs SUCCESS, and the column simply does not exist in the table.
#
# AUDIT #48 -- the previous sample was `$global:final | Select-Object -First 100`, a POSITIONAL
# sample. Measured on the 2026-08-08 Detailed export (2,216 rows / 151 columns): the first 100 rows
# carried only 69 columns, so 82 were dropped at ingest -- 57 of them holding real data, including
# RecommendedAction and RemediationOptions (first row 596) and the whole attack-path block
# (AttackPath first appears on row 2215 of 2216). This is the SAME defect family as #26, which
# fixed positional column discovery in the EXPORT while leaving the INGEST path untouched.
#
# Strategy: keep the leading $BaseCount rows (unchanged behaviour -- they carry the common shape and
# give the module representative values for the columns nearly every row has), then walk the REST and
# keep ONLY rows that introduce a column not yet seen. On that same export this produced ~109 rows
# covering all 151 columns; a pure coverage pass needs just 12, but the leading block is retained so
# this can never declare FEWER columns or worse types than the old code did.
#
# Types are inferred by the module from the sampled VALUES, which is why this picks real rows rather
# than synthesising one wide row of empty strings -- that would declare every added column as string
# and silently mistype the numeric ones (MaxCvssScore, EscalationWeight, SignInCount, ...).
function Get-RASchemaCoverageSample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()]$Rows,
        [int]$BaseCount = 100,
        [int]$MaxRows   = 500
    )

    $all = @($Rows)
    if ($all.Count -eq 0) { return @() }

    $sample = [System.Collections.Generic.List[object]]::new()
    $seen   = New-Object 'System.Collections.Generic.HashSet[string]'

    $take = [Math]::Min($BaseCount, $all.Count)
    for ($i = 0; $i -lt $take; $i++) {
        $row = $all[$i]
        if ($null -eq $row) { continue }
        $sample.Add($row)
        foreach ($n in $row.PSObject.Properties.Name) { [void]$seen.Add($n) }
    }

    for ($i = $take; $i -lt $all.Count; $i++) {
        if ($sample.Count -ge $MaxRows) { break }
        $row = $all[$i]
        if ($null -eq $row) { continue }
        $introducesNew = $false
        foreach ($n in $row.PSObject.Properties.Name) {
            if (-not $seen.Contains($n)) { $introducesNew = $true; break }
        }
        if ($introducesNew) {
            $sample.Add($row)
            foreach ($n in $row.PSObject.Properties.Name) { [void]$seen.Add($n) }
        }
    }

    # .ToArray() first: @(List[object] of PSCustomObjects) throws ArgumentException on PS 5.1.
    # Emit the array NORMALLY (no comma-wrap) so the pipeline unrolls it and the caller's @()
    # re-collects the rows. Comma-wrapping here was WRONG and was caught by the offline test: it
    # emitted the array as ONE object, so `@(Get-RASchemaCoverageSample ...)` yielded a single
    # element whose "columns" were object[]'s own members (Count, Length, ...) -- 1 row, 8 columns.
    # Callers MUST wrap the call in @() so a single-row result does not collapse to a scalar.
    return $sample.ToArray()
}

# TraceName + TraceID for one report's rows (stamped right after risk scoring).
#   TraceName = <ConfigurationName>-<SecuritySeverity>[-<cmdbName>][-<AssetName> on a Detailed row]-SI
#   TraceID   = the first 16 hex chars of SHA-256 over the LOWER-CASED TraceName -- the same inputs give the same id
#               on every run, so a finding can be followed over time.
# TWO DISTINCT ASSETS COULD SHARE ONE TraceID. Measured in the 2026-10-08 release test: 12 finding ids were shared
# by different assets with the same name -- service principals whose names differ only by case (the id is taken over
# the lower-cased name) and same-named SQL databases on two servers. So on a Detailed row whose TraceName another
# row of the SAME report shares while naming a DIFFERENT asset, the asset's id is added before '-SI'. Every other
# row keeps exactly the TraceName / TraceID it had, so ids that were already unique do not change.
function Get-RATraceBase {
    <# PURE. One row's trace name parts (without '-SI'), its lower-cased base name and the asset key that tells two assets apart. #>
    param([Parameter(Mandatory)]$Row, [bool]$IsDetailed)
    # (each column read directly, '' when absent or null -- no script block call per column)
    $rp = $Row.PSObject.Properties
    $parts = [System.Collections.Generic.List[string]]::new()
    $names = if ($IsDetailed) { @('ConfigurationName', 'SecuritySeverity', 'cmdbName', 'AssetName') } else { @('ConfigurationName', 'SecuritySeverity', 'cmdbName') }
    foreach ($n in $names) {
        $p = $rp[$n]
        if ($p -and $null -ne $p.Value) { $v = [string]$p.Value; if (-not [string]::IsNullOrWhiteSpace($v)) { $parts.Add($v) } }
    }
    $assetKey = ''
    if ($IsDetailed) {
        foreach ($n in 'SI_AssetId', 'AssetId', 'PrimaryEntityId', 'AzureResourceId', 'EntraAccountObjectId', 'MdeDeviceId', 'DeviceId') {
            $p = $rp[$n]
            if ($p -and $null -ne $p.Value) { $v = ([string]$p.Value).Trim(); if ($v) { $assetKey = $v; break } }
        }
    }
    [pscustomobject]@{ Parts = $parts.ToArray(); Lower = ((@($parts.ToArray()) + 'SI') -join '-').ToLowerInvariant(); AssetKey = $assetKey }
}

function Get-RATraceId {
    <# PURE. TraceID: the first 16 hex characters of SHA-256 over the lower-cased TraceName. #>
    param([Parameter(Mandatory)][string]$TraceName)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ([System.BitConverter]::ToString($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($TraceName.ToLowerInvariant()))) -replace '-', '').Substring(0, 16).ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Set-RATraceIdentity {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()][object[]]$Rows, [bool]$IsDetailed)
    if ($null -eq $Rows -or $Rows.Count -eq 0) { return }
    # PERFORMANCE: the parts of Get-RATraceBase (same columns, same order, same tests), read inline -- one call of a
    # function per row and two list copies per row were most of the time on a 43,000-row slice. Same names, same ids.
    $base = [System.Collections.Generic.List[object]]::new()
    $keysByName = @{}   # lower-cased TraceName -> distinct asset keys
    $assetKeyCols = @('SI_AssetId', 'AssetId', 'PrimaryEntityId', 'AzureResourceId', 'EntraAccountObjectId', 'MdeDeviceId', 'DeviceId')
    foreach ($row in $Rows) {
        if ($null -eq $row) { continue }
        $props = $row.PSObject.Properties
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($n in 'ConfigurationName', 'SecuritySeverity', 'cmdbName') {
            $p = $props[$n]
            if ($p -and $null -ne $p.Value) { $v = [string]$p.Value; if (-not [string]::IsNullOrWhiteSpace($v)) { $parts.Add($v) } }
        }
        $assetKey = ''
        if ($IsDetailed) {
            $p = $props['AssetName']
            if ($p -and $null -ne $p.Value) { $v = [string]$p.Value; if (-not [string]::IsNullOrWhiteSpace($v)) { $parts.Add($v) } }
            foreach ($n in $assetKeyCols) {
                $p = $props[$n]
                if ($p -and $null -ne $p.Value) { $v = ([string]$p.Value).Trim(); if ($v) { $assetKey = $v; break } }
            }
        }
        $joined = if ($parts.Count -gt 0) { ($parts -join '-') + '-SI' } else { 'SI' }
        $lower = $joined.ToLowerInvariant()
        if ($assetKey) {
            if (-not $keysByName.ContainsKey($lower)) { $keysByName[$lower] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase) }
            [void]$keysByName[$lower].Add($assetKey)
        }
        $base.Add(@($row, $joined, $lower, $assetKey))
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        foreach ($b in $base) {
            # the name is the parts + (the asset key, when another asset shares the name) + 'SI'
            $traceName = $b[1]
            if ($b[3] -and $keysByName.ContainsKey($b[2]) -and $keysByName[$b[2]].Count -gt 1) { $traceName = $traceName.Substring(0, $traceName.Length - 2) + $b[3] + '-SI' }
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($traceName.ToLowerInvariant())
            $traceId = [System.Convert]::ToHexString($sha.ComputeHash($bytes)).Substring(0, 16).ToLowerInvariant()
            Add-Member -InputObject $b[0] -NotePropertyName 'TraceName' -NotePropertyValue $traceName -Force
            Add-Member -InputObject $b[0] -NotePropertyName 'TraceID'   -NotePropertyValue $traceId   -Force
        }
    } finally { $sha.Dispose() }
}

# The report's column list with every repeat removed (case-INSENSITIVE, first place kept, blanks dropped). PSObject
# property names are case-insensitive, so `Select-Object -Property` throws on a name listed twice (the property
# 'RiskFactorIds' cannot be processed because it already exists) -- PublicIP_OpenPorts_Detailed failed every run because
# its OutputPropertyOrder named RiskFactorIds twice. A duplicate in a report can never stop it again.
# A LONG STAGE IS NEVER SILENT (live 2026-10-14 on internal: 26 minutes without a line between "rows after filters" and
# "calculating risk scores", and the run was stopped by hand as hung). A per-row stage says how far it is -- at most one
# line per SI_RA_ProgressSeconds (default 30 s), so a stage that takes seconds says nothing extra. Callers check
# ($done % 200) -eq 0 before calling Step-RAProgress, so the cost per row is one modulo.
function New-RAProgress {
    <# A stage's progress: -What = the plain words before the count ("scored", "prepared for the database"), -Total rows. #>
    param([string]$What, [long]$Total, $EverySeconds = $global:SI_RA_ProgressSeconds)
    $every = 30.0
    $n = 0.0
    if ($null -ne $EverySeconds -and ([string]$EverySeconds).Trim() -ne '' -and [double]::TryParse(([string]$EverySeconds).Trim(), [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$n) -and $n -ge 0) { $every = $n }
    [pscustomobject]@{ What = $What; Total = $Total; Sw = [System.Diagnostics.Stopwatch]::StartNew(); Last = 0.0; Every = $every }
}

function Step-RAProgress {
    <# Says '<what> <done> of <total> rows (<seconds> s)' when -Every seconds have passed since the last line. #>
    param($Progress, [long]$Done)
    if ($null -eq $Progress) { return }
    $t = $Progress.Sw.Elapsed.TotalSeconds
    if (($t - $Progress.Last) -lt $Progress.Every) { return }
    $Progress.Last = $t
    $line = '{0} {1:N0} of {2:N0} rows ({3:N0} s so far)' -f $Progress.What, $Done, $Progress.Total, $t
    if (Get-Command -Name Write-Info -ErrorAction SilentlyContinue) { Write-Info $line } else { Write-Host $line }
}

function Get-RAUniqueColumns {
    param([AllowNull()][object[]]$Columns)
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($c in @($Columns)) {
        if ($null -eq $c) { continue }
        $s = [string]$c
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        if ($seen.Add($s)) { $out.Add($s) }
    }
    return , $out.ToArray()
}
