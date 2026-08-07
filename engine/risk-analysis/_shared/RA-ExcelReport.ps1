#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  Excel workbook rendering: sheet sections, worksheet export and the risk index.
#
#  Everything that turns scored rows into the .xlsx deliverable. Kept together because the index sheet
#  and the per-report worksheets share formatting conventions.
#
#  AUDIT #16: moved VERBATIM out of Invoke-RiskAnalysis.ps1 on 2026-08-05. Dot-sourced back in at
#  exactly the position it occupied, so load order is unchanged. Every function body is
#  byte-identical to before the move - verified with tests/Get-EngineFunctionInventory.ps1,
#  which compares a SHA-256 of each function's source text before and after.
#
#  Do NOT add $PSScriptRoot-dependent code here: in this file it resolves to _shared/, one level
#  deeper than the engine root the main script derives $siRoot from.
#######################################################################################################

function Write-Section($text) {
  Write-Host ""
  Write-Host "==== $text ====" -ForegroundColor Cyan
}

function Get-RAColumnUnion {
  <#
    AUDIT #26 -- the export column list must be the UNION of every row's properties, never
    the first row's.

    Advanced-Hunting rows are rebuilt from the Graph additional-properties bag
    (RA-GraphHunting.ps1:448, `foreach ($k in $r.AdditionalProperties.Keys)`) and that bag
    OMITS null-valued columns. So two rows of the same report genuinely carry different
    property sets, and a column that merely happens to be empty on row 1 was absent from the
    discovery, never entered $DesiredColumns, and was then dropped by Select-Object -- out
    of the xlsx, the JSON sibling AND the Log Analytics ingest, for the whole report.

    A column declared in the YAML OutputPropertyOrder is protected because it is added
    regardless. RemediationOptions / RecommendedAction / Recommendation are declared
    nowhere, so they depended entirely on first-row luck -- which is why "remediation data
    is missing" was intermittent rather than total.

    Order is FIRST-SEEN, so the shape stays stable and human-readable rather than sorted.
    One pass over the rows: ~0.3s for the largest real report set (2,677 rows), ~19s at a
    deliberately pessimistic 200,000. Deliberately NOT capped -- a cap would silently
    reintroduce exactly the data loss this exists to stop.
  #>
  param([Parameter(Mandatory=$false)][object]$Rows)

  $ordered = New-Object 'System.Collections.Generic.List[string]'
  $seen    = New-Object 'System.Collections.Generic.HashSet[string]'
  if ($null -eq $Rows) { return @() }

  foreach ($row in $Rows) {
    if ($null -eq $row) { continue }
    foreach ($prop in $row.PSObject.Properties) {
      if ($prop.MemberType -ne 'NoteProperty') { continue }
      if ($seen.Add($prop.Name)) { [void]$ordered.Add($prop.Name) }
    }
  }
  return $ordered.ToArray()
}

# exporter (single-write workflow; still supports -ClearSheet)
function Export-Worksheet {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$SheetName,
    [Parameter(Mandatory)]$Rows,
    [string]$SortColumn,
    [switch]$SortDescending,
    [string[]]$DesiredColumns,
    [string[]]$ColumnsToFlatten = @(),
    [string]$TableStyle = 'Medium9'
  )

  function Convert-CellValue {
    param(
      [Parameter()][AllowNull()]$Value,
      [string]$JoinChar = ', '
    )

    if ($null -eq $Value) { return $null }

    if ($Value -is [string] -or
        $Value -is [int] -or $Value -is [long] -or
        $Value -is [double] -or $Value -is [decimal] -or
        $Value -is [datetime] -or $Value -is [bool] -or
        $Value -is [guid]) {
      return $Value
    }

    if ($Value -is [pscustomobject] -or $Value -is [hashtable] -or $Value -is [System.Collections.IDictionary]) {
      try { return ($Value | ConvertTo-Json -Compress -Depth 12) } catch { return ($Value | Out-String).Trim() }
    }

    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
      $items = @()
      foreach ($i in $Value) {
        if ($null -eq $i) { continue }
        if ($i -is [string] -or $i.GetType().IsPrimitive) {
          $items += [string]$i
        } else {
          try { $items += ($i | ConvertTo-Json -Compress -Depth 12) }
          catch { $items += ([string]($i | Out-String).Trim()) }
        }
      }
      return ($items -join $JoinChar)
    }

    return [string]$Value
  }

  $safeSheet = $SheetName.Substring(0, [Math]::Min(31, $SheetName.Length)) -replace '[:\\/?*\[\]]','_'
  $tableName = ($safeSheet -replace '\W','_')

  # AutoSize/AutoFitColumns trigger System.Drawing.Common which is unavailable
  # in PS7-on-Linux containers (even with libgdiplus). Skip the auto-fit pass
  # on Linux; widths fall back to ImportExcel default (10).
  $_canAutoFit = -not $IsLinux
  $_autoSizeArgs = if ($_canAutoFit) { @{ AutoSize = $true } } else { @{} }
  if (-not $Rows -or $Rows.Count -eq 0) {
    $excel = ([pscustomobject]@{ Info = 'No rows returned' }) |
      Export-Excel -Path $Path -WorksheetName $safeSheet -TableName $tableName -TableStyle $TableStyle `
        @_autoSizeArgs -FreezeTopRow -BoldTopRow -ClearSheet -PassThru
    $ws = $excel.Workbook.Worksheets[$safeSheet]
    if ($_canAutoFit) { $ws.Cells.AutoFitColumns() }
    # v2.2.226 -- enable WrapText on known multi-line columns so embedded
    # newlines (\r\n built by the MoreDetails post-process; IssueList /
    # RiskFactor_*_Detailed / ImpactedAssetsList aggregations) render as
    # line breaks in Excel. Without WrapText the cell shows one long
    # string and operators see "MoreDetails doesn't separate multiple
    # entries". Capping width at 50 (below) keeps cells readable when
    # wrap fires.
    $wrapTargets = @{
        'MoreDetails'                     = $true
        'IssueList'                       = $true
        'RiskFactor_Probability_Detailed' = $true
        'RiskFactor_Consequence_Detailed' = $true
        'ImpactedAssetsList'              = $true
        'AssetDetectedInReportName'       = $true
        'CVSSDesc'                        = $true
    }
    # Wider cap for known long-narrative columns -- 50 clipped CVSSDesc to ~1 sentence
    # which forced operators to widen the column manually after open. 90 fits most
    # CVSS descriptions in 2-3 wrapped lines.
    $wideTargets = @{ 'CVSSDesc' = 90 }
    for ($col = 1; $col -le $ws.Dimension.Columns; $col++) {
      $headerVal = [string]$ws.Cells[1, $col].Value
      $maxWidth  = if ($headerVal -and $wideTargets.ContainsKey($headerVal)) { [int]$wideTargets[$headerVal] } else { 50 }
      if ($ws.Column($col).Width -gt $maxWidth) { $ws.Column($col).Width = $maxWidth }
      if ($headerVal -and $wrapTargets.ContainsKey($headerVal)) {
        try { $ws.Column($col).Style.WrapText = $true } catch { }
      }
    }
    # All cells top-aligned (ImportExcel default is center). Operators read
    # left-to-right top-to-bottom; centered text in wrap-enabled cells creates
    # the visual ambiguity of which row a wrapped line belongs to.
    try { $ws.Cells.Style.VerticalAlignment = 'Top' } catch { }
    Close-ExcelPackage $excel
    $script:_sheetWritten[$safeSheet] = $true
    return
  }

  $Data = $Rows
  if ($DesiredColumns) { $Data = $Data | Select-Object -Property $DesiredColumns }

  if ($ColumnsToFlatten.Count -gt 0) {
    $Data = $Data | ForEach-Object {
      $o = [ordered]@{}
      foreach ($p in $_.PSObject.Properties) {
        $v = $p.Value
        if ($ColumnsToFlatten -contains $p.Name) {
          $v = Convert-CellValue -Value $v
        }
        $o[$p.Name] = $v
      }
      [pscustomobject]$o
    }
  }

  if ($SortColumn) {
    $Data = $Data | Sort-Object -Property $SortColumn -Descending:$SortDescending.IsPresent
  }

  # ALSO flatten any [object[]] / IDictionary / IEnumerable cell into
  # a string -- without this, ImportExcel calls .ToString() on arrays and emits
  # "System.Object[]" into the cell. ColumnsToFlatten was only narrowly applied
  # for explicitly-listed columns; this catches everything.
  # XLSX shared-strings safety: scrub control chars + lone surrogates from every
  # string property of every row before Export-Excel. Without this, any KQL extract()
  # result / CSA blob / pasted-in text containing such a character makes Excel pop
  # the "Repaired Records: String properties from sharedStrings.xml" dialog on
  # file open. v2.1.206.
  $Data = $Data | ForEach-Object {
    $o = [ordered]@{}
    foreach ($p in $_.PSObject.Properties) {
      $v = $p.Value
      # Universal flatten: any non-scalar (array / hashtable / pscustomobject)
      # gets joined / JSON-serialized so it lands as a readable string in the cell.
      if ($null -ne $v -and -not ($v -is [string]) -and (
            $v -is [System.Collections.IDictionary] -or
            $v -is [pscustomobject] -or
            ($v -is [System.Collections.IEnumerable] -and -not ($v.GetType().IsValueType))
          )) {
        $v = Convert-CellValue -Value $v
      }
      if ($v -is [string] -and -not [string]::IsNullOrEmpty($v)) {
        $v = ConvertTo-XlsxSafeString $v
      }
      $o[$p.Name] = $v
    }
    [pscustomobject]$o
  }

  # locale-defensive Excel write. PowerShell + EPPlus auto-stringify
  # doubles using CurrentCulture; on da-DK / nl-NL / de-DE / fr-FR / etc. (comma
  # decimal locales) `9.8` becomes the string "9,8", which Excel then re-parses
  # as `9 thousand 8 -> 98` (comma = thousands separator under en-US-ish locale
  # detection during xlsx import). Swap the running thread to InvariantCulture
  # for the duration of the Export-Excel call so every double serializes with
  # period-decimal regardless of the host locale. Restore in finally so the rest
  # of the engine sees its original culture (logs / dates / etc.). Works on ANY
  # locale because Invariant is locale-agnostic.
  $_savedCulture = [System.Threading.Thread]::CurrentThread.CurrentCulture
  try {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::InvariantCulture
    $excel = $Data | Export-Excel -Path $Path -WorksheetName $safeSheet -TableStyle $TableStyle `
      -TableName $tableName -AutoFilter -FreezeTopRow -BoldTopRow -ClearSheet -PassThru

    $ws = $excel.Workbook.Worksheets[$safeSheet]
    if (-not $IsLinux) { $ws.Cells.AutoFitColumns() }   # Linux: System.Drawing.Common unavailable
    # v2.2.226 -- enable WrapText on known multi-line columns so embedded
    # newlines (\r\n built by the MoreDetails post-process; IssueList /
    # RiskFactor_*_Detailed / ImpactedAssetsList aggregations) render as
    # line breaks in Excel. Without WrapText the cell shows one long
    # string and operators see "MoreDetails doesn't separate multiple
    # entries". Capping width at 50 (below) keeps cells readable when
    # wrap fires.
    $wrapTargets = @{
        'MoreDetails'                     = $true
        'IssueList'                       = $true
        'RiskFactor_Probability_Detailed' = $true
        'RiskFactor_Consequence_Detailed' = $true
        'ImpactedAssetsList'              = $true
        'AssetDetectedInReportName'       = $true
        'CVSSDesc'                        = $true
    }
    # Wider cap for known long-narrative columns. See empty-rows branch above.
    $wideTargets = @{ 'CVSSDesc' = 90 }
    for ($col = 1; $col -le $ws.Dimension.Columns; $col++) {
      $headerVal = [string]$ws.Cells[1, $col].Value
      $maxWidth  = if ($headerVal -and $wideTargets.ContainsKey($headerVal)) { [int]$wideTargets[$headerVal] } else { 50 }
      if ($ws.Column($col).Width -gt $maxWidth) { $ws.Column($col).Width = $maxWidth }
      if ($headerVal -and $wrapTargets.ContainsKey($headerVal)) {
        try { $ws.Column($col).Style.WrapText = $true } catch { }
      }
    }
    # All cells top-aligned (ImportExcel default is center). See empty-rows branch.
    try { $ws.Cells.Style.VerticalAlignment = 'Top' } catch { }
    Close-ExcelPackage $excel
  } finally {
    [System.Threading.Thread]::CurrentThread.CurrentCulture = $_savedCulture
  }

  $script:_sheetWritten[$safeSheet] = $true
}

function New-RiskIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object[]] $CsvRows,
        [Parameter(Mandatory=$true)][string] $ColSecurityDomain,
        [Parameter(Mandatory=$true)][string] $ColCategory,
        [Parameter(Mandatory=$true)][string] $ColSubCategory,
        [Parameter(Mandatory=$true)][string] $ColConfigId,
        [Parameter(Mandatory=$true)][string] $ColSevValue,
        [Parameter(Mandatory=$true)][string] $ColTierValue,
        [Parameter(Mandatory=$true)][string] $ColConseqScore,
        [Parameter(Mandatory=$true)][string] $ColProbScore
    )

    # StrictMode-safe normalization
    $CsvRows = @($CsvRows)
    if ($CsvRows.Count -eq 0) { throw "Risk definitions CSV is empty." }

    $firstCols = @($CsvRows[0].PSObject.Properties.Name)

    # Validate required columns (StrictMode-safe even when only 1 is missing)
    $required = @(
        $ColCategory,
        $ColSubCategory,
        $ColConfigId,
        $ColSevValue,
        $ColTierValue,
        $ColConseqScore,
        $ColProbScore
    )

    $missing = @($required | Where-Object { $firstCols -notcontains $_ })
    if ($missing.Count -gt 0) {
        throw "CSV missing required columns: $($missing -join ', ')"
    }

    function _MakeKey {
        param(
            [Parameter(Mandatory=$true)][object] $Row,
            [Parameter(Mandatory=$true)][string[]] $Pattern
        )

        $vals = foreach ($c in @($Pattern)) {
            $v = $Row.$c
            if ([string]::IsNullOrWhiteSpace([string]$v)) { return $null }
            [string]$v
        }
        if ($null -eq $vals) { return $null }
        (($vals -join '|').ToLowerInvariant())
    }

    # Matching sequences (ordered from most-specific to least-specific)
    $seqWithDomain_Conseq = @(
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId,$ColSevValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColSevValue),
        @($ColSecurityDomain,$ColCategory,$ColSevValue),
        @($ColSecurityDomain,$ColSevValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory),
        @($ColSecurityDomain,$ColCategory),
        @($ColSecurityDomain)
    )

    $seqNoDomain_Conseq = @(
        @($ColCategory,$ColSubCategory,$ColConfigId,$ColSevValue),
        @($ColCategory,$ColSubCategory,$ColSevValue),
        @($ColCategory,$ColSevValue),
        @($ColSevValue),
        @($ColCategory,$ColSubCategory,$ColConfigId),
        @($ColCategory,$ColSubCategory),
        @($ColCategory)
    )

    $seqWithDomain_Prob = @(
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId,$ColTierValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColTierValue),
        @($ColSecurityDomain,$ColCategory,$ColTierValue),
        @($ColSecurityDomain,$ColTierValue),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory,$ColConfigId),
        @($ColSecurityDomain,$ColCategory,$ColSubCategory),
        @($ColSecurityDomain,$ColCategory),
        @($ColSecurityDomain)
    )

    $seqNoDomain_Prob = @(
        @($ColCategory,$ColSubCategory,$ColConfigId,$ColTierValue),
        @($ColCategory,$ColSubCategory,$ColTierValue),
        @($ColCategory,$ColTierValue),
        @($ColTierValue),
        @($ColCategory,$ColSubCategory,$ColConfigId),
        @($ColCategory,$ColSubCategory),
        @($ColCategory)
    )

    # Maps per pattern (StrictMode-safe creation)
    $mapsConseq_With = @()
    foreach ($pat in $seqWithDomain_Conseq) { $mapsConseq_With += ,@{} }

    $mapsConseq_No = @()
    foreach ($pat in $seqNoDomain_Conseq) { $mapsConseq_No += ,@{} }

    $mapsProb_With = @()
    foreach ($pat in $seqWithDomain_Prob) { $mapsProb_With += ,@{} }

    $mapsProb_No = @()
    foreach ($pat in $seqNoDomain_Prob) { $mapsProb_No += ,@{} }

    foreach ($row in $CsvRows) {

        for ($i = 0; $i -lt @($seqWithDomain_Conseq).Count; $i++) {
            $k = _MakeKey -Row $row -Pattern $seqWithDomain_Conseq[$i]
            if ($k -and -not $mapsConseq_With[$i].ContainsKey($k)) { $mapsConseq_With[$i][$k] = $row }
        }

        for ($i = 0; $i -lt @($seqNoDomain_Conseq).Count; $i++) {
            $k = _MakeKey -Row $row -Pattern $seqNoDomain_Conseq[$i]
            if ($k -and -not $mapsConseq_No[$i].ContainsKey($k)) { $mapsConseq_No[$i][$k] = $row }
        }

        for ($i = 0; $i -lt @($seqWithDomain_Prob).Count; $i++) {
            $k = _MakeKey -Row $row -Pattern $seqWithDomain_Prob[$i]
            if ($k -and -not $mapsProb_With[$i].ContainsKey($k)) { $mapsProb_With[$i][$k] = $row }
        }

        for ($i = 0; $i -lt @($seqNoDomain_Prob).Count; $i++) {
            $k = _MakeKey -Row $row -Pattern $seqNoDomain_Prob[$i]
            if ($k -and -not $mapsProb_No[$i].ContainsKey($k)) { $mapsProb_No[$i][$k] = $row }
        }
    }

    [pscustomobject]@{
        SecurityDomainColumn = $ColSecurityDomain
        CategoryColumn       = $ColCategory
        SubCategoryColumn    = $ColSubCategory
        ConfigIdColumn       = $ColConfigId
        SevValueColumn       = $ColSevValue
        TierValueColumn      = $ColTierValue
        ConseqScoreColumn    = $ColConseqScore
        ProbScoreColumn      = $ColProbScore

        Conseq_WithDomainPatterns = $seqWithDomain_Conseq
        Conseq_NoDomainPatterns   = $seqNoDomain_Conseq
        Prob_WithDomainPatterns   = $seqWithDomain_Prob
        Prob_NoDomainPatterns     = $seqNoDomain_Prob

        Conseq_WithDomainMaps = $mapsConseq_With
        Conseq_NoDomainMaps   = $mapsConseq_No
        Prob_WithDomainMaps   = $mapsProb_With
        Prob_NoDomainMaps     = $mapsProb_No
    }
}
