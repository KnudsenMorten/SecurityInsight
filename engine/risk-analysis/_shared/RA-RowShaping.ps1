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
    $items = New-Object System.Collections.Generic.List[string]
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
    $parts = New-Object System.Collections.Generic.List[string]
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

  $rowsArr = @()
  foreach ($r in $Rows) { if ($null -ne $r) { $rowsArr += ,$r } }
  if ($rowsArr.Count -eq 0) { return @() }

  foreach ($r in $rowsArr) {
    $k = New-DedupeKey -Row $r -KeyCandidates $KeyCandidates
    $r | Add-Member -NotePropertyName "__DedupeKey" -NotePropertyValue $k -Force
  }

  $out = New-Object System.Collections.Generic.List[object]

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



function Apply-ScopeFilter {
  [CmdletBinding()]
  param(
    [Parameter()][AllowNull()]$Rows,
    [Parameter(Mandatory)][string]$ColumnName,
    [Parameter()][AllowNull()]$Scope
  )

  # Always return an array, never $null
  if ($null -eq $Rows) { return @() }

  # Normalize Rows to a plain array (works for List[object] too)
  $rowsArr = @()
  foreach ($r in $Rows) { $rowsArr += ,$r }

  # If no scope -> pass-through
  if ($null -eq $Scope -or ($Scope -is [string] -and [string]::IsNullOrWhiteSpace($Scope))) {
    return @($rowsArr)
  }

  # Normalize scope to array
  if ($Scope -is [string]) {
    $Scope = $Scope -split '\s*,\s*'
  }
  elseif ($Scope -isnot [System.Collections.IEnumerable]) {
    $Scope = @($Scope)
  }
  if (@($Scope).Count -eq 0) { return @($rowsArr) }

  # Filter (always return array)
  $filtered = @(Filter-ObjectsByColumn -InputObject $rowsArr -ColumnToFilter $ColumnName -InScopeData @($Scope) -CaseInsensitive)
  return @($filtered)
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

        if ($obj -is [pscustomobject]) {
            $ordered = [ordered]@{}
            foreach ($p in $obj.PSObject.Properties) {
                if ($StripOData -and ($p.Name -like '*@odata*')) { continue }
                $ordered[$p.Name] = _Convert $p.Value $false
            }
            return [pscustomobject]$ordered
        }

        if ($obj -is [System.Collections.IDictionary]) {
            $ordered = [ordered]@{}
            foreach ($k in $obj.Keys) {
                if ($StripOData -and ($k -is [string]) -and ($k -like '*@odata*')) { continue }
                $ordered[$k] = _Convert $obj[$k] $false
            }
            return [pscustomobject]$ordered
        }

        if (($obj -is [System.Collections.IEnumerable]) -and -not ($obj -is [string])) {

            $items = @()
            foreach ($item in $obj) { $items += ,(_Convert $item $false) }

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
        $out = @()
        foreach ($i in $InputObject) { $out += ,(_Convert $i $false) }
        return @($out)
    }

    return (_Convert $InputObject $true)
}
