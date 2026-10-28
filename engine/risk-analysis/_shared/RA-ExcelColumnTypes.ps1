#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  ONE TYPE PER COLUMN in the Risk Analysis workbook.
#
#  WHY (#242, operator 2026-10-04: "some fields show as numbers some shows as text, fx in
#  riskscore_weight_factor, criticalitytier"). The workbook writer types every cell by the .NET type of
#  its value, and the 'Details' sheet unions the rows of every report. Rows read from Log Analytics carry
#  every cell as TEXT (the REST layer and Az.OperationalInsights both hand cells over as strings), while
#  rows from Advanced Hunting, and values the engine computes, are real numbers. So one column held 1 in
#  some rows and "1" in others: measured on the shipped Detailed sample, CriticalityTier was a number in
#  12,884 rows and text in 2,391; RiskScore_Weight_Factor 12,885 / 2,406; MaxCvssScore 98 / 114.
#
#  THE FIX decides a type PER COLUMN, over the whole column, before the sheet is written:
#    1. TEXT columns that only look numeric -- ids, names, versions, hashes, zip codes. A number that
#       arrives in one of them is written as its text, so an id never becomes 6.0 or 5.29E+84.
#    2. NUMERIC columns -- known names (risk scores, weights, tiers, CVSS, counts, days) or a column the
#       KQL result declared numeric (int / long / real / decimal) in every report that returned it.
#       Numeric text is converted to a number (invariant culture; "0,5" with a comma decimal reads 0.5),
#       a blank stays blank, and text that is not a number (a sentence) stays text -- it cannot be a number.
#    3. Any other column is decided from its values: real numbers plus numeric text -> numeric; real
#       numbers plus non-numeric text -> text. A column that holds ONLY numeric-looking text is left as
#       text -- nothing tells an id from a count there, and an id must not become a number.
#  Only the cell grid handed to the writer changes; the rows (JSON sibling, Log Analytics ingest) do not.
#
#  The per-cell scan runs in a small compiled helper (C# 5, Add-Type, like RA-XlsxWriter.ps1) with a
#  PowerShell twin for hosts that block the compiler. Works on Windows PowerShell 5.1 and PowerShell 7.
#  No ?. / ?? / ternary.
#######################################################################################################

# Columns that are TEXT even when every value looks like a number. Explicit names first, then suffixes
# (case-SENSITIVE on purpose: 'AssetId' is an id, 'IsValid' is not).
$script:RAExcelTextColumns = @(
  'TraceID', 'TraceName', 'cmdbId', 'OsVersion', 'OsBuild', 'OsBuildRevision', 'OsVersionInfo',
  'SenseClientVersion', 'SolutionVersion', 'DisplayName', 'ZipCode', 'PostalCode', 'PhoneNumber',
  'ConfigurationId', 'ConfigurationName', 'ConfigurationDescription', 'MoreDetails', 'CVSSDesc',
  'IssueList', 'RiskFactor_Probability_Detailed', 'RiskFactor_Consequence_Detailed', 'RiskScore_Weight_Detailed',
  'ImpactedAssetsList', 'AssetDetectedInReportName', 'RiskFactor_Consequence_Impacts', 'RiskFactor_Probability_Impacts'
)
$script:RAExcelTextSuffix = New-Object System.Text.RegularExpressions.Regex('(Id|Ids|ID|IDs|Uuid|Guid|Sid|Sids|Hash|Version|Name|Names|Url|Upn|Ip|IpAddress|IpAddresses|Tags|Zip|PostalCode)$')

# Columns that are NUMERIC. Non-numeric text in them (e.g. a sentence in Impact) stays text.
$script:RAExcelNumericColumns = @(
  'CriticalityTier', 'SourceCriticalityTier', 'TargetCriticalityTier', 'Tier', 'TierEscalation',
  'RiskScore_Weight_Factor', 'RiskFactor_Weight', 'RiskScoreTotal', 'RiskScoreTotal_Weighted',
  'RiskConsequenceScore', 'RiskProbabilityScore', 'RiskFactor_Consequence', 'RiskFactor_Probability', 'RiskConsequenceBase', 'RiskProbabilityBase',
  'RiskScoreDomainKPI', 'RiskScoreKPI', 'Impact', 'MaxCvssScore', 'CvssScore', 'CVSSScore', 'CvssV3', 'BaseScore',
  'CmdbMatchConfidence', 'LoggedOnUsersCount_derived', 'LoggedOnUsersCount_mde', 'CriticalCveCount30d'
)
$script:RAExcelNumericSuffix = New-Object System.Text.RegularExpressions.Regex('(Count|Days|Score|Weight|Factor|KPI)$')

$script:RAExcelKqlNumericTypes = @('int', 'long', 'real', 'decimal', 'double')

function Reset-RAKqlColumnTypes {
  # One run, one map: called where the engine resets its per-run export state.
  $global:RA_KqlColumnTypes = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([System.StringComparer]::OrdinalIgnoreCase)
}

function Add-RAKqlColumnTypes {
  <#
    Record the column types a KQL result declared (its .Tables[0].Columns, name + type). A column two
    reports declare differently is recorded as 'mixed' and decided from its values instead. Never throws:
    a query result without types (the Az cmdlet path) simply records nothing.
  #>
  param([Parameter()][AllowNull()]$Columns)
  try {
    if ($null -eq $Columns) { return }
    if ($null -eq $global:RA_KqlColumnTypes) { Reset-RAKqlColumnTypes }
    foreach ($c in @($Columns)) {
      if ($null -eq $c) { continue }
      $n = $null; $t = $null
      if ($c.PSObject.Properties['name']) { $n = [string]$c.name } elseif ($c.PSObject.Properties['ColumnName']) { $n = [string]$c.ColumnName }
      if ($c.PSObject.Properties['type']) { $t = [string]$c.type } elseif ($c.PSObject.Properties['ColumnType']) { $t = [string]$c.ColumnType } elseif ($c.PSObject.Properties['DataType']) { $t = [string]$c.DataType }
      if ([string]::IsNullOrWhiteSpace($n) -or [string]::IsNullOrWhiteSpace($t)) { continue }
      $t = $t.Trim().ToLowerInvariant()
      if ($t -eq 'int32') { $t = 'int' } elseif ($t -eq 'int64') { $t = 'long' } elseif ($t -eq 'double') { $t = 'real' }
      $prev = $null
      if ($global:RA_KqlColumnTypes.TryGetValue($n, [ref]$prev)) {
        if ($prev -ne $t) { $global:RA_KqlColumnTypes[$n] = 'mixed' }
      } else {
        $global:RA_KqlColumnTypes[$n] = $t
      }
    }
  } catch { }
}

function Get-RAExcelColumnRule {
  <#
    'text', 'number' or 'infer' for one column name: the text list first (an id stays text whatever a
    query declared), then the numeric list, then the KQL type the reports agreed on, else 'infer'.
  #>
  param([Parameter(Mandatory)][string]$Name, $KqlTypes)
  foreach ($c in $script:RAExcelTextColumns) { if ([string]::Equals($c, $Name, [System.StringComparison]::OrdinalIgnoreCase)) { return 'text' } }
  foreach ($c in $script:RAExcelNumericColumns) { if ([string]::Equals($c, $Name, [System.StringComparison]::OrdinalIgnoreCase)) { return 'number' } }
  if ($script:RAExcelTextSuffix.IsMatch($Name)) { return 'text' }
  if ($script:RAExcelNumericSuffix.IsMatch($Name)) { return 'number' }
  if ($null -ne $KqlTypes) {
    $t = $null
    $found = $false
    if ($KqlTypes -is [System.Collections.Generic.Dictionary[string,string]]) { $found = $KqlTypes.TryGetValue($Name, [ref]$t) }
    elseif ($KqlTypes -is [System.Collections.IDictionary]) { foreach ($k in $KqlTypes.Keys) { if ([string]::Equals([string]$k, $Name, [System.StringComparison]::OrdinalIgnoreCase)) { $t = [string]$KqlTypes[$k]; $found = $true; break } } }
    if ($found) {
      if ($script:RAExcelKqlNumericTypes -contains $t) { return 'number' }
      if ($t -eq 'string' -or $t -eq 'guid') { return 'text' }
    }
  }
  return 'infer'
}

# =====================================================================================================
# THE COMPILED HELPER (C# 5 -- Windows PowerShell 5.1 compiles with the .NET Framework csc). Each
# method has a PowerShell twin below; SIv3-ExcelColumnTypes.Tests.ps1 runs both.
# =====================================================================================================
$script:RAXlsxTypesNativeType = 'RAXlsx.ColumnTypesV1'
$script:RAXlsxTypesNativeSource = @'
using System;
using System.Collections;
using System.Globalization;
using System.Management.Automation;
using System.Text.RegularExpressions;

namespace RAXlsx
{
    public static class ColumnTypesV1
    {
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
        static readonly Regex Num   = new Regex(@"^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$", RegexOptions.CultureInvariant);
        static readonly Regex Int   = new Regex(@"^[+-]?\d+$", RegexOptions.CultureInvariant);
        static readonly Regex Comma = new Regex(@"^-?\d+,\d{1,2}$", RegexOptions.CultureInvariant);

        static object Unwrap(object v)
        {
            PSObject po = v as PSObject;
            if (po != null && !(po.BaseObject is PSCustomObject)) return po.BaseObject;
            return v;
        }

        public static bool IsNumber(object v)
        {
            return v is int || v is long || v is double || v is float || v is decimal || v is short ||
                   v is byte || v is sbyte || v is ushort || v is uint || v is ulong;
        }

        // A number written as text, or null. Invariant; one comma followed by 1-2 digits is a decimal comma.
        public static object ParseText(string s)
        {
            if (s == null) return null;
            string t = s.Trim();
            if (t.Length == 0) return null;
            if (Comma.IsMatch(t)) t = t.Replace(',', '.');
            if (!Num.IsMatch(t)) return null;
            if (Int.IsMatch(t))
            {
                long l;
                if (long.TryParse(t, NumberStyles.AllowLeadingSign, Inv, out l)) return l;
            }
            double d;
            if (double.TryParse(t, NumberStyles.Float, Inv, out d) && !double.IsNaN(d) && !double.IsInfinity(d)) return d;
            return null;
        }

        // Per column: [0] real numbers, [1] numeric text, [2] other text, [3] blank text. Booleans and dates
        // are not counted -- they are their own types and are left alone.
        public static int[][] Scan(IList rows, int nCols)
        {
            int[][] c = new int[nCols][];
            for (int i = 0; i < nCols; i++) c[i] = new int[4];
            foreach (object ro in rows)
            {
                IList r = ro as IList;
                if (r == null) continue;
                int lim = Math.Min(nCols, r.Count);
                for (int i = 0; i < lim; i++)
                {
                    object v = Unwrap(r[i]);
                    if (v == null) continue;
                    string s = v as string;
                    if (s != null)
                    {
                        if (s.Trim().Length == 0) c[i][3]++;
                        else if (ParseText(s) != null) c[i][1]++;
                        else c[i][2]++;
                    }
                    else if (IsNumber(v)) c[i][0]++;
                }
            }
            return c;
        }

        // mode 1: numeric text -> number, blank text -> blank. mode 2: number -> its invariant text.
        // Returns how many cells changed.
        public static int Apply(IList rows, int col, int mode)
        {
            int n = 0;
            foreach (object ro in rows)
            {
                IList r = ro as IList;
                if (r == null || col >= r.Count) continue;
                object v = Unwrap(r[col]);
                if (v == null) continue;
                if (mode == 1)
                {
                    string s = v as string;
                    if (s == null) continue;
                    if (s.Trim().Length == 0) { r[col] = null; n++; continue; }
                    object p = ParseText(s);
                    if (p != null) { r[col] = p; n++; }
                }
                else if (mode == 2 && IsNumber(v))
                {
                    if (v is double) r[col] = ((double)v).ToString("R", Inv);
                    else if (v is float) r[col] = ((float)v).ToString("R", Inv);
                    else r[col] = ((IFormattable)v).ToString(null, Inv);
                    n++;
                }
            }
            return n;
        }
    }
}
'@

function _RAXlsxTypes-Native {
  # The compiled helper, or $null (the PowerShell twin is used). $script:RAXlsxTypesForcePowerShell forces the twin.
  if ($script:RAXlsxTypesForcePowerShell) { return $null }
  $t = $script:RAXlsxTypesNativeType -as [type]
  if ($null -ne $t) { return $t }
  if ($script:RAXlsxTypesNativeFailed) { return $null }
  try {
    Add-Type -TypeDefinition $script:RAXlsxTypesNativeSource -Language CSharp -ErrorAction Stop
    return ($script:RAXlsxTypesNativeType -as [type])
  } catch {
    $script:RAXlsxTypesNativeFailed = $true
    Write-Verbose ("[xlsx] column-typing helper unavailable, using the PowerShell path: {0}" -f $_.Exception.Message)
    return $null
  }
}

$script:RAXlsxRxNum   = New-Object System.Text.RegularExpressions.Regex('^[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$')
$script:RAXlsxRxInt   = New-Object System.Text.RegularExpressions.Regex('^[+-]?\d+$')
$script:RAXlsxRxComma = New-Object System.Text.RegularExpressions.Regex('^-?\d+,\d{1,2}$')

function ConvertFrom-RAExcelNumericText {
  # PowerShell twin of ColumnTypesV1.ParseText: [long] / [double] for numeric text, else $null.
  param([AllowNull()][string]$Text)
  if ($null -eq $Text) { return $null }
  $t = $Text.Trim()
  if ($t.Length -eq 0) { return $null }
  $inv = [System.Globalization.CultureInfo]::InvariantCulture
  if ($script:RAXlsxRxComma.IsMatch($t)) { $t = $t.Replace(',', '.') }
  if (-not $script:RAXlsxRxNum.IsMatch($t)) { return $null }
  if ($script:RAXlsxRxInt.IsMatch($t)) {
    $l = 0L
    if ([long]::TryParse($t, [System.Globalization.NumberStyles]::AllowLeadingSign, $inv, [ref]$l)) { return $l }
  }
  $d = 0.0
  if ([double]::TryParse($t, [System.Globalization.NumberStyles]::Float, $inv, [ref]$d) -and -not [double]::IsNaN($d) -and -not [double]::IsInfinity($d)) { return $d }
  return $null
}

function _RAXlsxTypes-IsNumber {
  param($v)
  return ($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [single] -or $v -is [decimal] -or
          $v -is [int16] -or $v -is [byte] -or $v -is [sbyte] -or $v -is [uint16] -or $v -is [uint32] -or $v -is [uint64])
}

function Set-RAExcelColumnTypes {
  <#
  .SYNOPSIS
    Give every column of a cell grid ONE type, in place (see the header of this file).
  .PARAMETER Rows
    The grid: one object[] per row in -Columns order (ConvertTo-SIXlsxRows' .Rows).
  .PARAMETER KqlTypes
    Column name -> KQL type, as recorded by Add-RAKqlColumnTypes. Optional.
  .OUTPUTS
    @{ Numeric = names made numeric; Text = names made text; Cells = cells changed; Mixed = numeric
    columns that still hold non-numeric text (name -> count) }
  #>
  param(
    [Parameter(Mandatory)][AllowEmptyCollection()]$Rows,
    [Parameter(Mandatory)][string[]]$Columns,
    $KqlTypes = $null,
    [ValidateSet('Auto','Native','PowerShell')][string]$Engine = 'Auto'
  )
  $res = @{ Numeric = @(); Text = @(); Cells = 0; Mixed = @{} }
  $nCols = $Columns.Count
  if ($null -eq $Rows -or $nCols -eq 0) { return $res }
  $nt = $null
  if ($Engine -ne 'PowerShell') { $nt = _RAXlsxTypes-Native }
  if ($Engine -eq 'Native' -and $null -eq $nt) { throw "the compiled column-typing helper is not available" }

  # ---- one scan: per column, how many real numbers / numeric text / other text / blank text ----------
  if ($null -ne $nt) { $counts = $nt::Scan($Rows, $nCols) }
  else {
    $counts = New-Object 'object[]' $nCols
    for ($i = 0; $i -lt $nCols; $i++) { $counts[$i] = New-Object 'int[]' 4 }
    foreach ($r in $Rows) {
      if ($null -eq $r) { continue }
      $lim = [Math]::Min($nCols, $r.Count)
      for ($i = 0; $i -lt $lim; $i++) {
        $v = $r[$i]
        if ($null -eq $v) { continue }
        if ($v -is [string]) {
          if ($v.Trim().Length -eq 0) { $counts[$i][3]++ }
          elseif ($null -ne (ConvertFrom-RAExcelNumericText $v)) { $counts[$i][1]++ }
          else { $counts[$i][2]++ }
        }
        elseif (_RAXlsxTypes-IsNumber $v) { $counts[$i][0]++ }
      }
    }
  }

  $numeric = New-Object System.Collections.Generic.List[string]
  $text    = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $nCols; $i++) {
    $c = $counts[$i]
    $nNum = $c[0]; $nNumTxt = $c[1]; $nOther = $c[2]; $nBlank = $c[3]
    $rule = Get-RAExcelColumnRule -Name $Columns[$i] -KqlTypes $KqlTypes
    $mode = 0
    if ($rule -eq 'text') {
      if ($nNum -gt 0) { $mode = 2 }
    } elseif ($rule -eq 'number') {
      if ($nNumTxt -gt 0 -or $nBlank -gt 0) { $mode = 1 }
      if ($nOther -gt 0) { $res.Mixed[$Columns[$i]] = $nOther }
    } else {
      # infer: only a column that already holds REAL numbers can be numeric
      if ($nNum -gt 0 -and $nOther -eq 0 -and ($nNumTxt -gt 0 -or $nBlank -gt 0)) { $mode = 1 }
      elseif ($nNum -gt 0 -and $nOther -gt 0) { $mode = 2 }
    }
    if ($mode -eq 0) { continue }

    if ($null -ne $nt) { $changed = $nt::Apply($Rows, $i, $mode) }
    else {
      $changed = 0
      $inv = [System.Globalization.CultureInfo]::InvariantCulture
      foreach ($r in $Rows) {
        if ($null -eq $r -or $i -ge $r.Count) { continue }
        $v = $r[$i]
        if ($null -eq $v) { continue }
        if ($mode -eq 1) {
          if ($v -isnot [string]) { continue }
          if ($v.Trim().Length -eq 0) { $r[$i] = $null; $changed++; continue }
          $p = ConvertFrom-RAExcelNumericText $v
          if ($null -ne $p) { $r[$i] = $p; $changed++ }
        } elseif (_RAXlsxTypes-IsNumber $v) {
          if ($v -is [double] -or $v -is [single]) { $r[$i] = $v.ToString('R', $inv) } else { $r[$i] = $v.ToString($null, $inv) }
          $changed++
        }
      }
    }
    $res.Cells += $changed
    if ($mode -eq 1) { [void]$numeric.Add($Columns[$i]) } else { [void]$text.Add($Columns[$i]) }
  }
  $res.Numeric = $numeric.ToArray()
  $res.Text = $text.ToArray()
  return $res
}
