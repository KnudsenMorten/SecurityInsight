#Requires -Version 5.1
<#
    Risk Analysis -- THE WORKBOOK STEP (live 2026-10-16: a Detailed run stored all 65 reports, 1,167,338 rows x ~94 columns,
    then gathered every row in memory to build the workbook and ran out of memory 23 minutes later; the run's collection
    was never marked and the replica started a whole new run).

    The workbook is a CONVENIENCE OUTPUT. The run's result is in the database (the web app) and in Log Analytics; the
    workbook is read from there and can never decide whether the collection is delivered:

      * ON / OFF PER GRAIN (owner 2026-10-16: "make excel export optional and a setting"): SI_RA_ExcelExport_Summary
        (default ON) and SI_RA_ExcelExport_Detailed (default OFF). Off: no workbook, no read of the rows for it, one plain
        line in the log, and the mail says the results are in the web app.
      * A SIZE A WORKBOOK HOLDS HERE (owner 2026-10-16: "calculate rows and if it is too big gray out option"):
        Get-RAWorkbookRowLimit. Above it the workbook is not tried -- the same line and mail note -- and the web app's
        Settings page shows the Detailed switch greyed out (SettingsWorkbookLimit.cs, the same number).
      * STREAMED, ONE METHOD FOR EVERY SIZE: the rows are read from the database a page at a time and written to the sheet
        as they come (Write-RAXlsxStreamed): the sheet XML goes straight into the zip entry, text cells are written inline
        (a shared-string table would hold every distinct string of the run in memory), and only one page is ever held.
        Excel's sheet limit (1,048,575 data rows) continues on a next sheet ('Details (2)', ...) -- never a truncation.
        The column widths are measured on the first page (the highest-risk rows; every width is capped at 50 anyway).
      * NEVER FAILS THE STEP: anything thrown while writing it (out of memory included) is one plain warning, the run
        record notes "the workbook was not produced", the mail says the results are in the web app, and the run goes on.

    PS 5.1 safe (the engine's container runs PowerShell 7; the VM path 5.1). C# 5 in the helper.
#>

# ---------------------------------------------------------------------------------------------------------------------
# THE SIZE A WORKBOOK HOLDS HERE. Measured on the test VM 2026-10-16 with the streamed writer below (tests/scale/
# Measure-RaWorkbookMemory.ps1): memory stays flat at any row count (one page held), so the limit is not memory -- it is
# what a workbook is still usable for and what the run's time allows: 2 sheets of Excel's 1,048,575 rows. Above that a
# workbook takes longer to write than the reports themselves and no one opens it; every row is in the web app.
# The web app's Settings page greys the Detailed switch above the same number (SettingsWorkbookLimit.cs -- a test pins both).
# ---------------------------------------------------------------------------------------------------------------------
$script:RAWorkbookRowLimit = 2097150L
$script:RAXlsxSheetRows = 1048575

function Get-RAWorkbookRowLimit { [long]$script:RAWorkbookRowLimit }

function ConvertTo-RAWorkbookSwitch {
    <# PURE. A setting value -> $true / $false / $null (not set). Accepts bools, 1/0 and the words on/off, true/false, yes/no. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return [bool]$Value }
    $t = ([string]$Value).Trim().ToLowerInvariant().Trim('$')
    if ($t -eq '') { return $null }
    if ($t -in @('1', 'true', 'on', 'yes')) { return $true }
    if ($t -in @('0', 'false', 'off', 'no')) { return $false }
    return $null
}

function Get-RAWorkbookPlan {
    <#
        PURE. Whether this run writes its workbook. -Grain Summary | Detailed; -Setting the value of SI_RA_ExcelExport_<grain>
        (not set = the default: Summary ON, Detailed OFF); -Rows the rows the workbook would show; -Limit the size a workbook
        holds here. Returns @{ Write; Reason = on | off | too-large; Line (the one log line when not written) }.
    #>
    param([Parameter(Mandatory)][ValidateSet('Summary', 'Detailed')][string]$Grain, [AllowNull()]$Setting, [long]$Rows = 0, [long]$Limit = 0)
    if ($Limit -le 0) { $Limit = Get-RAWorkbookRowLimit }
    $name = 'SI_RA_ExcelExport_{0}' -f $Grain
    $on = ConvertTo-RAWorkbookSwitch $Setting
    if ($null -eq $on) { $on = ($Grain -eq 'Summary') }
    $g = $Grain.ToLowerInvariant()
    if (-not $on) {
        return [pscustomobject]@{ Write = $false; Reason = 'off'; Grain = $Grain
            Line = ('no {0} workbook: the {0} Excel export is switched off ({1}) -- the results are in the web app' -f $g, $name) }
    }
    if ($Rows -gt $Limit) {
        return [pscustomobject]@{ Write = $false; Reason = 'too-large'; Grain = $Grain
            Line = ('no {0} workbook: the {0} results have {1:N0} rows, more than a workbook can hold here ({2:N0}) -- they are in the web app' -f $g, $Rows, $Limit) }
    }
    [pscustomobject]@{ Write = $true; Reason = 'on'; Grain = $Grain; Line = '' }
}

function Get-RAWebAppLink {
    <# This install's web app address ('' when not known). Never throws. #>
    try {
        if (Get-Command -Name Get-SITelemetryInstallEndpoints -ErrorAction SilentlyContinue) {
            foreach ($e in @(Get-SITelemetryInstallEndpoints)) { if ($e -and "$($e.kind)" -eq 'webapp' -and "$($e.url)") { return ([string]$e.url).TrimEnd('/') } }
        }
        if ("$($global:SIWeb_PublicBaseUrl)".Trim()) { return ([string]$global:SIWeb_PublicBaseUrl).Trim().TrimEnd('/') }
    } catch { }
    ''
}

function Get-RAWorkbookMailNote {
    <# PURE. The mail's paragraph when the run has no workbook: why, and that the results are in the web app (its link when known). #>
    param([Parameter(Mandatory)][ValidateSet('off', 'too-large', 'failed')][string]$Reason, [string]$Grain = 'Detailed', [long]$Rows = 0, [string]$Link = '')
    $g = $Grain.ToLowerInvariant()
    $why = switch ($Reason) {
        'off'       { 'The {0} Excel export is switched off.' -f $g }
        'too-large' { 'The {0} results have {1:N0} rows, more than a workbook can hold here.' -f $g, $Rows }
        'failed'    { 'The workbook could not be produced this time.' }
    }
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $where = if ($Link) { 'All results of this run are in the SecurityInsight web app: <a href="{0}">{1}</a>' -f (& $enc $Link), (& $enc $Link) } else { 'All results of this run are in the SecurityInsight web app.' }
    # #728: a "Topic: text" line of the one mail layout (the topic in bold), in a tinted block -- no table, no fixed width
    '<p style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.5;margin:0 0 14px 0;padding:10px 12px;border-left:4px solid #0063b1;background:#f3f8fc;"><b>No workbook is attached:</b> {0}<br/>{1}</p>' -f (& $enc $why), $where
}

# =====================================================================================================================
# THE STREAMED SHEET WRITER. C# 5 (Windows PowerShell 5.1 compiles with the .NET Framework csc). The cell rules are the
# writer's (RA-XlsxWriter.ps1 NativeV1.WriteRows: the same scrub, escaping, number / date / bool forms); only a text cell
# is written INLINE instead of as an index into a shared-string table. A PowerShell twin is used when Add-Type is not
# available (slower, same bytes).
# =====================================================================================================================
$script:RAXlsxStreamType = 'SIXlsxStream.StreamV1'
$script:RAXlsxStreamSource = @'
using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.Text;
using System.Management.Automation;

namespace SIXlsxStream
{
    public static class StreamV1
    {
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
        static bool IsHigh(char c) { return c >= (char)0xD800 && c <= (char)0xDBFF; }
        static bool IsLow(char c)  { return c >= (char)0xDC00 && c <= (char)0xDFFF; }
        static bool IsCtl(char c)  { return (c < (char)0x20 && c != '\t' && c != '\n' && c != '\r') || c == (char)0x7F; }
        static bool IsNon(char c)  { return c == (char)0xFFFE || c == (char)0xFFFF || c == (char)0x2028 || c == (char)0x2029; }

        public static string Scrub(string s)
        {
            if (string.IsNullOrEmpty(s)) return s;
            bool dirty = s.Length > 32767;
            for (int i = 0; i < s.Length && !dirty; i++)
            {
                char c = s[i];
                if (c < (char)0x20 || c == (char)0x7F) { if (IsCtl(c)) dirty = true; }
                else if (c >= (char)0xD800)
                {
                    if (IsHigh(c)) { if (i + 1 >= s.Length || !IsLow(s[i + 1])) dirty = true; else i++; }
                    else if (IsLow(c)) dirty = true;
                    else if (IsNon(c)) dirty = true;
                }
                else if (c == (char)0x2028 || c == (char)0x2029) dirty = true;
            }
            if (!dirty) return s;
            StringBuilder b = new StringBuilder(s.Length);
            foreach (char c in s) if (!IsCtl(c)) b.Append(c);
            string t = b.ToString(); b.Length = 0;
            for (int i = 0; i < t.Length; i++) { char c = t[i]; if (IsHigh(c) && (i + 1 >= t.Length || !IsLow(t[i + 1]))) continue; b.Append(c); }
            t = b.ToString(); b.Length = 0;
            for (int i = 0; i < t.Length; i++) { char c = t[i]; if (IsLow(c) && (i == 0 || !IsHigh(t[i - 1]))) continue; b.Append(c); }
            t = b.ToString(); b.Length = 0;
            foreach (char c in t) if (!IsNon(c)) b.Append(c);
            t = b.ToString();
            if (t.Length > 32767)
            {
                int clip = t.Length - 32767;
                string marker = string.Format(Inv, "... [truncated {0} chars]", clip);
                int cut = 32767 - marker.Length; if (cut < 0) cut = 0;
                clip = t.Length - cut;
                marker = string.Format(Inv, "... [truncated {0} chars]", clip);
                cut = 32767 - marker.Length; if (cut < 0) cut = 0;
                t = t.Substring(0, cut) + marker;
            }
            return t;
        }

        static object Unwrap(object v)
        {
            PSObject po = v as PSObject;
            if (po != null && !(po.BaseObject is PSCustomObject)) return po.BaseObject;
            return v;
        }

        public static void Esc(TextWriter w, string s)
        {
            int start = 0;
            for (int i = 0; i < s.Length; i++)
            {
                string rep;
                switch (s[i])
                {
                    case '\r':
                        rep = "\n";
                        if (i + 1 < s.Length && s[i + 1] == '\n') { if (i > start) w.Write(s.Substring(start, i - start)); w.Write(rep); start = i + 2; i++; continue; }
                        break;
                    case '&': rep = "&amp;"; break;
                    case '<': rep = "&lt;"; break;
                    case '>': rep = "&gt;"; break;
                    case '"': rep = "&quot;"; break;
                    case '\'': rep = "&apos;"; break;
                    default: continue;
                }
                if (i > start) w.Write(s.Substring(start, i - start));
                w.Write(rep);
                start = i + 1;
            }
            if (start == 0) w.Write(s);
            else if (start < s.Length) w.Write(s.Substring(start));
        }

        static void Inl(TextWriter w, string cOpen, string rq, string tInl, string s)
        {
            w.Write(cOpen); w.Write(rq); w.Write(tInl); Esc(w, s); w.Write("</t></is></c>");
        }

        // Rows [start, start+count) of one page, numbered from firstRowNum. Returns the next row number.
        public static int WriteRows(TextWriter w, IList rows, int start, int count, int firstRowNum, int nCols, string[] cOpen, string[] tInl, string[] tNum, string[] tDate, string[] tBool)
        {
            int rowNum = firstRowNum;
            for (int k = start; k < start + count; k++)
            {
                string rq = rowNum.ToString(Inv);
                w.Write("<row r=\""); w.Write(rq); w.Write("\">");
                IList r = rows[k] as IList;
                int lim = (r == null) ? 0 : Math.Min(nCols, r.Count);
                for (int i = 0; i < lim; i++)
                {
                    object v = Unwrap(r[i]);
                    if (v == null) continue;
                    string s = v as string;
                    if (s != null) { if (s.Length == 0) continue; Inl(w, cOpen[i], rq, tInl[i], Scrub(s)); }
                    else if (v is int || v is long) { w.Write(cOpen[i]); w.Write(rq); w.Write(tNum[i]); w.Write(((IFormattable)v).ToString(null, Inv)); w.Write("</v></c>"); }
                    else if (v is double || v is float)
                    {
                        double d = Convert.ToDouble(v, Inv);
                        if (double.IsNaN(d) || double.IsInfinity(d)) Inl(w, cOpen[i], rq, tInl[i], d.ToString(Inv));
                        else { w.Write(cOpen[i]); w.Write(rq); w.Write(tNum[i]); w.Write(d.ToString("R", Inv)); w.Write("</v></c>"); }
                    }
                    else if (v is DateTime)
                    {
                        DateTime dt = (DateTime)v;
                        if (dt.Year < 1900) Inl(w, cOpen[i], rq, tInl[i], dt.ToString("yyyy-MM-dd HH:mm:ss", Inv));
                        else { w.Write(cOpen[i]); w.Write(rq); w.Write(tDate[i]); w.Write(dt.ToOADate().ToString("R", Inv)); w.Write("</v></c>"); }
                    }
                    else if (v is bool) { w.Write(cOpen[i]); w.Write(rq); w.Write(tBool[i]); w.Write(((bool)v) ? "1" : "0"); w.Write("</v></c>"); }
                    else if (v is decimal || v is short || v is byte || v is sbyte || v is ushort || v is uint || v is ulong)
                    { w.Write(cOpen[i]); w.Write(rq); w.Write(tNum[i]); w.Write(((IFormattable)v).ToString(null, Inv)); w.Write("</v></c>"); }
                    else if (v is DateTimeOffset)
                    { w.Write(cOpen[i]); w.Write(rq); w.Write(tDate[i]); w.Write(((DateTimeOffset)v).DateTime.ToOADate().ToString("R", Inv)); w.Write("</v></c>"); }
                    else
                    {
                        string o = Scrub((string)LanguagePrimitives.ConvertTo(v, typeof(string), Inv));
                        if (!string.IsNullOrEmpty(o)) Inl(w, cOpen[i], rq, tInl[i], o);
                    }
                }
                w.Write("</row>");
                rowNum++;
            }
            return rowNum;
        }
    }
}
'@

function _RAXlsxStream-Native {
    <# The compiled helper's type, or $null (the PowerShell twin). $script:RAXlsxStreamForcePowerShell forces the twin (tests). #>
    if ($script:RAXlsxStreamForcePowerShell) { return $null }
    $t = $script:RAXlsxStreamType -as [type]
    if ($null -ne $t) { return $t }
    if ($script:RAXlsxStreamFailed) { return $null }
    try { Add-Type -TypeDefinition $script:RAXlsxStreamSource -Language CSharp -ErrorAction Stop; return ($script:RAXlsxStreamType -as [type]) }
    catch { $script:RAXlsxStreamFailed = $true; Write-Verbose ("[xlsx] streamed writer helper unavailable, using the PowerShell path: {0}" -f $_.Exception.Message); return $null }
}

function _RAXlsxStream-EscPS {
    param([string]$s)
    $s = $s -replace "`r`n", "`n" -replace "`r", "`n"
    [System.Security.SecurityElement]::Escape($s)
}

function _RAXlsxStream-WriteRowsPS {
    # PowerShell twin of StreamV1.WriteRows (inline text cells). Slow; used only when the compiler is not available.
    param($Writer, $Rows, [int]$Start, [int]$Count, [int]$FirstRowNum, [int]$NCols, [string[]]$COpen, [string[]]$TInl, [string[]]$TNum, [string[]]$TDate, [string[]]$TBool)
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $rowNum = $FirstRowNum
    for ($k = $Start; $k -lt $Start + $Count; $k++) {
        $rq = $rowNum.ToString($inv)
        $Writer.Write('<row r="' + $rq + '">')
        $r = $Rows[$k]
        $lim = 0; if ($null -ne $r) { $lim = [Math]::Min($NCols, $r.Count) }
        for ($i = 0; $i -lt $lim; $i++) {
            $v = $r[$i]
            if ($null -eq $v) { continue }
            $txt = $null
            if ($v -is [string]) { if ($v.Length -eq 0) { continue }; $txt = _SIXlsx-Scrub $v }
            elseif ($v -is [int] -or $v -is [long] -or $v -is [decimal] -or $v -is [int16] -or $v -is [byte] -or $v -is [sbyte] -or $v -is [uint16] -or $v -is [uint32] -or $v -is [uint64]) {
                $Writer.Write($COpen[$i] + $rq + $TNum[$i] + $v.ToString($null, $inv) + '</v></c>'); continue
            }
            elseif ($v -is [double] -or $v -is [single]) {
                $d = [double]$v
                if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { $txt = $d.ToString($inv) }
                else { $Writer.Write($COpen[$i] + $rq + $TNum[$i] + $d.ToString('R', $inv) + '</v></c>'); continue }
            }
            elseif ($v -is [datetime]) {
                if ($v.Year -lt 1900) { $txt = $v.ToString('yyyy-MM-dd HH:mm:ss', $inv) }
                else { $Writer.Write($COpen[$i] + $rq + $TDate[$i] + $v.ToOADate().ToString('R', $inv) + '</v></c>'); continue }
            }
            elseif ($v -is [bool]) { $Writer.Write($COpen[$i] + $rq + $TBool[$i] + $(if ($v) { '1' } else { '0' }) + '</v></c>'); continue }
            elseif ($v -is [System.DateTimeOffset]) { $Writer.Write($COpen[$i] + $rq + $TDate[$i] + $v.DateTime.ToOADate().ToString('R', $inv) + '</v></c>'); continue }
            else { $txt = _SIXlsx-Scrub ([string]$v); if ([string]::IsNullOrEmpty($txt)) { continue } }
            $Writer.Write($COpen[$i] + $rq + $TInl[$i] + (_RAXlsxStream-EscPS $txt) + '</t></is></c>')
        }
        $Writer.Write('</row>')
        $rowNum++
    }
    $rowNum
}

function ConvertTo-RAXlsxStreamGrid {
    <# One page of row objects -> its cell grid in -Columns order: lists joined, other composite values as JSON (Export-
       Worksheet's Convert-CellValue rules), one type per column for the page (Set-RAExcelColumnTypes). #>
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rows, [Parameter(Mandatory)][string[]]$Columns, $KqlTypes = $null)
    $g = ConvertTo-SIXlsxRows -InputObject $Rows -Columns $Columns
    $def = $g.Deferred
    for ($k = 0; $k -lt $def.Count; $k += 2) {
        $row = $g.Rows[$def[$k]]; $v = $row[$def[$k + 1]]
        if ($null -eq $v) { continue }
        try {
            if ($v -is [System.Collections.IDictionary] -or $v -is [System.Management.Automation.PSCustomObject]) { $row[$def[$k + 1]] = ($v | ConvertTo-Json -Compress -Depth 12) }
            else {
                $items = New-Object 'System.Collections.Generic.List[string]'
                foreach ($i in $v) { if ($null -eq $i) { continue }; if ($i -is [string] -or $i.GetType().IsPrimitive) { $items.Add([string]$i) } else { $items.Add([string]($i | ConvertTo-Json -Compress -Depth 12)) } }
                $row[$def[$k + 1]] = ($items -join ', ')
            }
        } catch { $row[$def[$k + 1]] = [string]$v }
    }
    try { $null = Set-RAExcelColumnTypes -Rows $g.Rows -Columns $Columns -KqlTypes $KqlTypes } catch { }
    , $g.Rows
}

function Write-RAXlsxStreamed {
    <#
        Writes a NEW workbook whose sheets hold the rows -NextPage hands over, a page at a time (an object[] of row objects,
        $null at the end) -- only one page is held. -SheetName 'Details' -> 'Details', then 'Details (2)', ... every
        -SheetRows rows (Excel's 1,048,575 data rows by default). Each sheet: a bold frozen header, an Excel table (banding
        + autofilter), widths measured on the first page (capped at -MaxColumnWidth / -WidthCaps), wrap + top alignment on
        -WrapColumns. Built beside the target and moved over it only when complete. Other sheets (the summary, the risk
        factor legend) are added afterwards by Write-SIXlsxWorksheet. Returns @{ Rows; Sheets = @(names) }.
    #>
    param([Parameter(Mandatory)][string]$Path, [string]$SheetName = 'Details', [Parameter(Mandatory)][string[]]$Columns,
          [Parameter(Mandatory)][scriptblock]$NextPage, [int]$SheetRows = 0, [string[]]$WrapColumns = @(), [double]$MaxColumnWidth = 50,
          [hashtable]$WidthCaps = @{}, [string]$TableStyle = 'Medium9', $KqlTypes = $null)
    if ($SheetRows -le 0) { $SheetRows = $script:RAXlsxSheetRows }
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    $inv = [System.Globalization.CultureInfo]::InvariantCulture
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $nt = _RAXlsxStream-Native
    $fullPath = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { [System.IO.Path]::Combine((Get-Location).Path, $Path) }
    $dir = [System.IO.Path]::GetDirectoryName($fullPath)
    if ($dir -and -not [System.IO.Directory]::Exists($dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }

    # the header: cleaned, non-empty, unique (case-insensitive) -- a table refuses blank or duplicate names
    $nCols = @($Columns).Count
    if ($nCols -lt 1) { throw 'Write-RAXlsxStreamed: at least one column is required.' }
    $hdr = New-Object 'string[]' $nCols
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    for ($i = 0; $i -lt $nCols; $i++) {
        $h = (_SIXlsx-CleanName $Columns[$i]).Trim(); if ($h.Length -eq 0) { $h = 'Column' + ($i + 1) }; if ($h.Length -gt 255) { $h = $h.Substring(0, 255) }
        $c = $h; $k = 2; while (-not $seen.Add($c)) { $c = $h + $k; $k++ }; $hdr[$i] = $c
    }
    $wrapSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($w in @($WrapColumns)) { if ($w) { [void]$wrapSet.Add($w) } }

    # the first page: the widths and the date columns are measured on it
    $page = & $NextPage
    $grid = if ($null -ne $page -and @($page).Count) { ConvertTo-RAXlsxStreamGrid -Rows @($page) -Columns $hdr -KqlTypes $KqlTypes } else { , @() }
    $page = $null
    $maxLen = New-Object 'int[]' $nCols; $isDate = New-Object 'bool[]' $nCols
    for ($i = 0; $i -lt $nCols; $i++) { $maxLen[$i] = $hdr[$i].Length }
    if ($null -ne (_SIXlsx-Native)) { (_SIXlsx-Native)::Measure($grid, $nCols, $maxLen, $isDate) } else { _SIXlsx-MeasurePS -Rows $grid -NCols $nCols -MaxLen $maxLen -IsDate $isDate }
    $widths = New-Object 'double[]' $nCols
    for ($i = 0; $i -lt $nCols; $i++) { $cap = $MaxColumnWidth; if ($WidthCaps.ContainsKey($hdr[$i])) { $cap = [double]$WidthCaps[$hdr[$i]] }; $widths[$i] = [Math]::Min($cap, [Math]::Max(8, $maxLen[$i] + 2)) }

    # per-column cell prefixes (style roles = the writer's cellXfs indices: 0 normal, 1 header, 2 wrap, 3 header on wrap, 4 date, 5 date on wrap)
    $cOpen = New-Object 'string[]' $nCols; $tInl = New-Object 'string[]' $nCols; $tNum = New-Object 'string[]' $nCols; $tDate = New-Object 'string[]' $nCols; $tBool = New-Object 'string[]' $nCols
    $colsXml = New-Object System.Text.StringBuilder
    $hdrXml = New-Object System.Text.StringBuilder
    [void]$hdrXml.Append('<row r="1">')
    for ($i = 0; $i -lt $nCols; $i++) {
        $wrap = $wrapSet.Contains($hdr[$i])
        $col = ConvertTo-SIXlsxColumnName ($i + 1)
        $cOpen[$i] = '<c r="' + $col
        $sTxt = if ($wrap) { ' s="2"' } else { '' }
        $sDt = if ($wrap) { ' s="5"' } else { ' s="4"' }
        $tInl[$i] = '"' + $sTxt + ' t="inlineStr"><is><t xml:space="preserve">'
        $tNum[$i] = '"' + $sTxt + '><v>'
        $tDate[$i] = '"' + $sDt + '><v>'
        $tBool[$i] = '"' + $sTxt + ' t="b"><v>'
        $colStyle = ''
        if ($isDate[$i]) { $colStyle = ' style="' + $(if ($wrap) { 5 } else { 4 }) + '"' } elseif ($wrap) { $colStyle = ' style="2"' }
        [void]$colsXml.Append('<col min="' + ($i + 1) + '" max="' + ($i + 1) + '" width="' + $widths[$i].ToString('0.##', $inv) + '" customWidth="1"' + $colStyle + '/>')
        [void]$hdrXml.Append('<c r="' + $col + '1" s="' + $(if ($wrap) { 3 } else { 1 }) + '" t="inlineStr"><is><t xml:space="preserve">' + (_RAXlsxStream-EscPS $hdr[$i]) + '</t></is></c>')
    }
    [void]$hdrXml.Append('</row>')
    $lastCol = ConvertTo-SIXlsxColumnName $nCols
    $nsMain = $script:SIXlsxNsMain; $nsRel = $script:SIXlsxNsRel; $nsPkg = $script:SIXlsxNsPkg; $nsCt = $script:SIXlsxNsCt

    $sheets = New-Object System.Collections.Generic.List[object]
    $total = 0L
    $tmp = $fullPath + '.si-xlsx.tmp'
    $fs = $null; $zip = $null; $sw = $null
    try {
        $fs = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite)
        $zip = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
        $level = [System.IO.Compression.CompressionLevel]::Optimal
        $openSheet = {
            $n = $sheets.Count + 1
            $name = if ($n -eq 1) { Get-SIXlsxSafeSheetName $SheetName } else { Get-SIXlsxSafeSheetName ('{0} ({1})' -f $SheetName, $n) }
            $sheets.Add([pscustomobject]@{ No = $n; Name = $name; Rows = 0 })
            $e = $zip.CreateEntry(('xl/worksheets/sheet{0}.xml' -f $n), $level)
            $w = New-Object System.IO.StreamWriter($e.Open(), $utf8, 65536)
            $w.Write('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="' + $nsMain + '" xmlns:r="' + $nsRel + '">')
            $w.Write('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A2" sqref="A2"/></sheetView></sheetViews>')
            $w.Write('<sheetFormatPr defaultRowHeight="15"/><cols>' + $colsXml.ToString() + '</cols><sheetData>' + $hdrXml.ToString())
            $w
        }
        $closeSheet = {
            param($w, $rows)
            if ($rows -eq 0) { $w.Write('<row r="2"/>') }
            $w.Write('</sheetData><pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/><tableParts count="1"><tablePart r:id="rId1"/></tableParts></worksheet>')
            $w.Close()
        }
        $sw = & $openSheet
        $rowNum = 2
        while ($true) {
            $at = 0; $n = @($grid).Count
            while ($at -lt $n) {
                $cur = $sheets[$sheets.Count - 1]
                if ($cur.Rows -ge $SheetRows) { & $closeSheet $sw $cur.Rows; $sw = $null; $sw = & $openSheet; $rowNum = 2; $cur = $sheets[$sheets.Count - 1] }
                $take = [Math]::Min($n - $at, $SheetRows - $cur.Rows)
                if ($null -ne $nt) { $rowNum = $nt::WriteRows($sw, $grid, $at, $take, $rowNum, $nCols, $cOpen, $tInl, $tNum, $tDate, $tBool) }
                else { $rowNum = _RAXlsxStream-WriteRowsPS -Writer $sw -Rows $grid -Start $at -Count $take -FirstRowNum $rowNum -NCols $nCols -COpen $cOpen -TInl $tInl -TNum $tNum -TDate $tDate -TBool $tBool }
                $cur.Rows += $take; $total += $take; $at += $take
            }
            $grid = $null
            $page = & $NextPage
            if ($null -eq $page) { break }
            if (@($page).Count -eq 0) { $page = $null; continue }
            $grid = ConvertTo-RAXlsxStreamGrid -Rows @($page) -Columns $hdr -KqlTypes $KqlTypes
            $page = $null
        }
        & $closeSheet $sw $sheets[$sheets.Count - 1].Rows; $sw = $null

        # the parts that need the row counts: one table per sheet, the workbook, its relationships, the content types, the styles
        $put = { param($name, [string]$text) $e = $zip.CreateEntry($name, $level); $s = $e.Open(); try { $b = $utf8.GetBytes($text); $s.Write($b, 0, $b.Length) } finally { $s.Close() } }
        $wbSheets = New-Object System.Text.StringBuilder; $wbRels = New-Object System.Text.StringBuilder; $ct = New-Object System.Text.StringBuilder
        [void]$wbRels.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="' + $nsPkg + '"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>')
        [void]$ct.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="' + $nsCt + '"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>')
        $tsn = if ($TableStyle -like 'TableStyle*') { $TableStyle } else { 'TableStyle' + $TableStyle }
        foreach ($s in $sheets) {
            $no = [int]$s.No
            $tName = ((_SIXlsx-CleanName $s.Name) -replace '\W', '_'); if ($tName -notmatch '^[A-Za-z_]' -or $tName -match '^(?i)(r|c|r\d+c\d+|r\d+|c\d+|[a-z]{1,3}\d+)$') { $tName = 'T_' + $tName }
            if ($no -gt 1) { $tName = ($tName.TrimEnd('_')) }
            $ref = 'A1:' + $lastCol + ([Math]::Max(2, [int]$s.Rows + 1))
            $tb = New-Object System.Text.StringBuilder
            [void]$tb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><table xmlns="' + $nsMain + '" id="' + $no + '" name="' + $tName + '" displayName="' + $tName + '" ref="' + $ref + '" totalsRowShown="0"><autoFilter ref="' + $ref + '"/><tableColumns count="' + $nCols + '">')
            for ($i = 0; $i -lt $nCols; $i++) {
                $tcn = [System.Security.SecurityElement]::Escape($hdr[$i]) -replace "`r", '_x000d_' -replace "`n", '_x000a_' -replace "`t", '_x0009_'
                [void]$tb.Append('<tableColumn id="' + ($i + 1) + '" name="' + $tcn + '"/>')
            }
            [void]$tb.Append('</tableColumns>')
            if ($TableStyle -and $TableStyle -ne 'None') { [void]$tb.Append('<tableStyleInfo name="' + $tsn + '" showFirstColumn="0" showLastColumn="0" showRowStripes="1" showColumnStripes="0"/>') }
            [void]$tb.Append('</table>')
            & $put ('xl/tables/table{0}.xml' -f $no) $tb.ToString()
            & $put ('xl/worksheets/_rels/sheet{0}.xml.rels' -f $no) ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="' + $nsPkg + '"><Relationship Id="rId1" Type="' + $script:SIXlsxRelTbl + '" Target="../tables/table' + $no + '.xml"/></Relationships>')
            [void]$wbSheets.Append('<sheet name="' + [System.Security.SecurityElement]::Escape($s.Name) + '" sheetId="' + $no + '" r:id="rId' + ($no + 1) + '"/>')
            [void]$wbRels.Append('<Relationship Id="rId' + ($no + 1) + '" Type="' + $script:SIXlsxRelWs + '" Target="worksheets/sheet' + $no + '.xml"/>')
            [void]$ct.Append('<Override PartName="/xl/worksheets/sheet' + $no + '.xml" ContentType="' + $script:SIXlsxCtWs + '"/><Override PartName="/xl/tables/table' + $no + '.xml" ContentType="' + $script:SIXlsxCtTbl + '"/>')
        }
        [void]$wbRels.Append('</Relationships>'); [void]$ct.Append('</Types>')
        & $put 'xl/workbook.xml' ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="' + $nsMain + '" xmlns:r="' + $nsRel + '"><bookViews><workbookView/></bookViews><sheets>' + $wbSheets.ToString() + '</sheets></workbook>')
        & $put 'xl/_rels/workbook.xml.rels' $wbRels.ToString()
        & $put 'xl/styles.xml' $script:SIXlsxStylesXml
        & $put '_rels/.rels' ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="' + $nsPkg + '"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        & $put '[Content_Types].xml' $ct.ToString()
        $zip.Dispose(); $zip = $null
        $fs.Close(); $fs = $null
    } catch {
        if ($null -ne $sw) { try { $sw.Dispose() } catch { } }
        if ($null -ne $zip) { try { $zip.Dispose() } catch { } }
        if ($null -ne $fs) { try { $fs.Close() } catch { } }
        if ([System.IO.File]::Exists($tmp)) { try { [System.IO.File]::Delete($tmp) } catch { } }
        throw
    }
    if ([System.IO.File]::Exists($fullPath)) { [System.IO.File]::Delete($fullPath) }
    [System.IO.File]::Move($tmp, $fullPath)
    [pscustomobject]@{ Rows = $total; Sheets = @($sheets | ForEach-Object { $_.Name }) }
}

function Get-RAWorkbookColumns {
    <# The workbook's columns: the run's final column list when it has one, else every report's columns in report order
       (the union, first spelling kept) -- never the first row's shape. #>
    param($Stream, [string[]]$Desired = @())
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out = New-Object System.Collections.Generic.List[string]
    $src = @($Desired | Where-Object { $_ -and [string]$_ -match '^[A-Za-z][A-Za-z0-9_]*$' })
    if (-not $src.Count -and $Stream -and $Stream.Reports) {
        $src = @(foreach ($k in @($Stream.Reports.Keys)) { $r = $Stream.Reports[$k]; if ($r -and $r.Columns) { $r.Columns.ToArray() } })
    }
    foreach ($c in $src) { if ($seen.Add([string]$c)) { $out.Add([string]$c) } }
    , $out.ToArray()
}

function Invoke-RAWorkbookStep {
    <#
        THE ENGINE'S WORKBOOK STEP (Invoke-RiskAnalysis.ps1): the plan (on / off for this grain, the size), then the workbook
        -- from the database a page at a time when the result is there ($script:RAStream), else the rows in memory as before
        -- then the 'Extract' note (a customer's own lower ceiling), the 'Risk factors' sheet and its JSON file.
        Sets $script:RAWorkbookSkipped, $script:RAWorkbookMailNote (the mail's paragraph) and $script:RAWorkbookRunNote (the
        run record). NEVER THROWS.
    #>
    $script:RAWorkbookSkipped = $false; $script:RAWorkbookMailNote = ''; $script:RAWorkbookRunNote = ''
    $grain = if ([bool]$global:Detailed) { 'Detailed' } else { 'Summary' }
    $rows = [long]$script:RAViewCount
    try {
        $setting = if ($grain -eq 'Detailed') { $global:SI_RA_ExcelExport_Detailed } else { $global:SI_RA_ExcelExport_Summary }
        $plan = Get-RAWorkbookPlan -Grain $grain -Setting $setting -Rows $rows
    } catch { $plan = [pscustomobject]@{ Write = $true; Reason = 'on'; Grain = $grain; Line = '' } }
    Write-Section "excel export"
    if (-not $plan.Write) {
        Write-Info $plan.Line
        $script:RAWorkbookSkipped = $true
        $script:RAWorkbookMailNote = Get-RAWorkbookMailNote -Reason $plan.Reason -Grain $grain -Rows $rows -Link (Get-RAWebAppLink)
        return
    }
    Write-Step ("exporting to excel ({0})" -f $(if ($script:RAStreamOn) { 'read from the database a page at a time' } else { 'single write' }))
    Write-Info ("path: {0}" -f $global:OutputXlsx)
    $flatten = @('ImpactedAssets','ImpactedAssetsList','IssueList','Logins','Benchmarks','EG_AssetProps','AssetProps','Properties')
    try {
        if (Get-Command -Name Tock -ErrorAction SilentlyContinue) { Tock }
        if ($rows -eq 0) {
            Write-Warn2 "no rows collected across reports; writing placeholder xlsx + empty json sibling"
            Export-Worksheet -Path $global:OutputXlsx -SheetName 'Details' -Rows @() -TableStyle 'Medium9'
        } elseif ($script:RAStreamOn) {
            $cols = Get-RAWorkbookColumns -Stream $script:RAStream -Desired @($global:FinalDesiredColumns)
            $pager = New-RARowPager -Stream $script:RAStream -Source View -TargetChars 8MB
            $max = if ($global:SI_ExcelMaxDataRows -gt 0) { [long]$global:SI_ExcelMaxDataRows } else { 0L }
            $state = @{ Pager = $pager; Left = $(if ($max -gt 0) { $max } else { [long]::MaxValue }) }
            $next = {
                if ($state.Left -le 0) { return $null }
                $p = $state.Pager.Next(); if ($null -eq $p) { return $null }
                if ($p.Count -gt $state.Left) { $p = @($p[0..([int]$state.Left - 1)]) }
                $state.Left -= $p.Count
                , $p
            }.GetNewClosure()
            $kql = $null; if (Get-Variable -Name RA_KqlColumnTypes -Scope Global -ErrorAction SilentlyContinue) { $kql = $global:RA_KqlColumnTypes }
            $res = Write-RAXlsxStreamed -Path $global:OutputXlsx -SheetName 'Details' -Columns $cols -NextPage $next `
                     -WrapColumns $script:RAExcelWrapColumns -MaxColumnWidth 50 -WidthCaps $script:RAExcelWidthCaps -TableStyle 'Medium9' -KqlTypes $kql
            $pager = $null; $state = $null
            if (@($res.Sheets).Count -gt 1) { Write-Info ("the workbook holds {0:N0} row(s) on {1} sheets ({2}) -- a sheet holds at most {3:N0}" -f $res.Rows, @($res.Sheets).Count, (@($res.Sheets) -join ', '), $script:RAXlsxSheetRows) }
            if ($max -gt 0 -and $rows -gt $max) {
                # a ceiling the customer set (SI_ExcelMaxDataRows): the workbook says it is an extract, inside it
                try {
                    $ex = [pscustomobject]@{ Info = ('This workbook is an EXTRACT: it shows the {0:N0} highest-risk of {1:N0} row(s) (SI_ExcelMaxDataRows). Every row is in SecurityInsight (the web app) and in Log Analytics.' -f $max, $rows) }
                    Export-Worksheet -Path $global:OutputXlsx -SheetName 'Extract' -Rows @($ex) -TableStyle 'Medium2'
                    Write-Warn2 ("the workbook is an extract: {0} of {1} row(s) -- said on its 'Extract' sheet" -f $max, $rows)
                } catch { Write-Warn2 ("the workbook's 'Extract' note could not be written: {0}" -f $_.Exception.Message) }
            }
        } else {
            # the result in memory (no database): as before -- the rows are already in memory
            Export-Worksheet -Path $global:OutputXlsx -SheetName 'Details' -Rows @($global:RA_ReportRows) -DesiredColumns $global:FinalDesiredColumns -ColumnsToFlatten $flatten -TableStyle 'Medium9'
        }
        if (Get-Command -Name Tick -ErrorAction SilentlyContinue) { Tick "excel export" }
        Write-Ok "report exported"
    } catch {
        $why = $_.Exception.Message
        for ($ex = $_.Exception; $null -ne $ex; $ex = $ex.InnerException) { if ($ex -is [System.OutOfMemoryException] -or "$($ex.Message)" -match 'OutOfMemoryException') { $why = 'not enough memory for the workbook'; break } }
        Write-Warn2 ("the workbook was not produced ({0}) -- the run's result is complete; every row is in the web app" -f $why)
        foreach ($f in @($global:OutputXlsx, ([string]$global:OutputXlsx + '.si-xlsx.tmp'))) { try { if ($f -and [System.IO.File]::Exists($f)) { [System.IO.File]::Delete($f) } } catch { } }
        $script:RAWorkbookSkipped = $true
        $script:RAWorkbookRunNote = 'the workbook was not produced'
        $script:RAWorkbookMailNote = Get-RAWorkbookMailNote -Reason 'failed' -Grain $grain -Rows $rows -Link (Get-RAWebAppLink)
        try { [System.GC]::Collect() } catch { }
        return
    }
    # #558 / #559 THE "Risk factors" LEGEND: every workbook carries a sheet that explains the short names in its factor
    # columns, and the same rows are written next to it as <name>.riskfactors.json for the PDF appendix.
    try {
        $legend = @(Get-RARiskFactorLegendRows)
        if ($legend.Count -gt 0) {
            Export-Worksheet -Path $global:OutputXlsx -SheetName 'Risk factors' -Rows $legend -TableStyle 'Medium2'
            $rfJson = [System.IO.Path]::ChangeExtension($global:OutputXlsx, 'riskfactors.json')
            ConvertTo-Json -InputObject @($legend) -Depth 4 | Out-File -FilePath $rfJson -Encoding UTF8 -Force
            Write-Info ("risk factor legend: {0} factor(s) -- the 'Risk factors' sheet and {1}" -f $legend.Count, $rfJson)
        }
    } catch { Write-Warn2 ("the 'Risk factors' sheet could not be written -- the report itself is complete: {0}" -f $_.Exception.Message) }
    Write-Host ""
    if (Test-Path -LiteralPath $global:OutputXlsx) { Write-Ok ("excel file ready: {0}" -f $global:OutputXlsx) }
}
