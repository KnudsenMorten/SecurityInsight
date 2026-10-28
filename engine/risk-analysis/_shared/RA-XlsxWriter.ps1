#######################################################################################################
#  SecurityInsight - Risk Analysis engine
#  SI's own .xlsx writer: pure .NET (System.IO.Compression + System.Xml), no module, no NuGet, no COM.
#
#  An .xlsx is a zip of Open XML parts. This file writes exactly the parts Risk Analysis needs -- one
#  worksheet per call, with a table (banding + autofilter), a bold frozen header, column widths, wrap +
#  top alignment on the narrative columns, numbers as numbers and dates as dates -- and ADDS that sheet
#  to the workbook already on disk, replacing a sheet of the same name. That is the accumulation
#  contract the engine relies on: 'Details' and the AI 'Summary' sheet are written by separate calls
#  against the same file.
#
#  WHY OUR OWN WRITER (REQUIREMENTS section 9.3 -- "Excel = keep everywhere, written with .NET"). The
#  ImportExcel module (and the EPPlus assembly inside it) was the last third-party module the RA engine
#  needed only to produce a file. It had to be installed on every VM and baked into every container
#  image, and it was where the 5h34m export came from (~0.55 ms per cell through Export-Excel).
#
#  HOW THE CELLS ARE WRITTEN. The sheet XML is streamed straight into the zip entry through one
#  StreamWriter: one string per cell, no per-cell objects, no DOM. Strings go to a SHARED table
#  (each distinct string stored once). Measured on the shipped Detailed sample: inline strings made
#  the file 1.65x larger (5.4 MB vs 3.3 MB), and the mail attachment cap is 20 MB. A sheet added to an
#  existing workbook APPENDS its strings to that workbook's table, so no other sheet's index moves.
#
#  EVERY STRING IS SCRUBBED HERE, with exactly ConvertTo-XlsxSafeString's rules (control characters,
#  lone surrogates, U+FFFE/FFFF/2028/2029, the 32,767-character cell limit with its truncation marker).
#  The writer therefore cannot produce a workbook Excel has to "repair", whatever a caller hands it; the
#  rules are idempotent, so a value the caller already scrubbed comes out unchanged.
#
#  THE PER-CELL WORK RUNS IN A SMALL COMPILED HELPER, WITH A POWERSHELL TWIN. Measured on PS 5.1, the
#  PowerShell loop that used to fetch, scrub and measure every cell before EPPlus saw it cost ~87 us per
#  cell -- 5+ minutes for 120,000 x 30 before a single byte was written. The helper (C# 5, compiled
#  once per process by Add-Type from the source below -- no file, no package) does the same work in
#  well under a microsecond. If Add-Type is unavailable (application control blocking the compiler, a
#  constrained host), the PowerShell implementations below produce the SAME BYTES, only slower: the
#  export must never be what fails a completed run. SIv3-XlsxWriter.Tests.ps1 asserts the parity.
#
#  Works on Windows PowerShell 5.1 and PowerShell 7 (Windows + Linux containers). No ?. / ?? / ternary.
#######################################################################################################

$script:SIXlsxNsMain = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
$script:SIXlsxNsRel  = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
$script:SIXlsxNsPkg  = 'http://schemas.openxmlformats.org/package/2006/relationships'
$script:SIXlsxNsCt   = 'http://schemas.openxmlformats.org/package/2006/content-types'
$script:SIXlsxRelWs  = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet'
$script:SIXlsxRelTbl = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/table'
$script:SIXlsxCtWs   = 'application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml'
$script:SIXlsxCtTbl  = 'application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml'

# The six cell formats every SI sheet uses, by ROLE. In a workbook this writer created, the role IS the
# cellXfs index. In a workbook something else created (an older EPPlus-written report that a run with
# OverwriteXlsx = $false appends to), the six are APPENDED to its styles and the roles map onto the new
# indices -- see _SIXlsx-MergeStyles.
#   0 normal (top)   1 header (bold, top)   2 wrap (top)   3 header on a wrap column   4 date   5 date on a wrap column
# cellStyleXfs[0] -- the Normal style -- carries vertical="top" too. That is what Excel reconciles
# every unstyled cell to, so a short value in a row made tall by a wrapped neighbour sits at the TOP of
# its row instead of reading as though it belongs to the row below. (Patching only cellXfs[0] does
# nothing in Excel: it rebuilds index 0 from cellStyleXfs.)
$script:SIXlsxStylesXml = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
  '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">' +
  '<numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm:ss"/></numFmts>' +
  '<fonts count="2"><font><sz val="11"/><name val="Calibri"/><family val="2"/></font><font><b/><sz val="11"/><name val="Calibri"/><family val="2"/></font></fonts>' +
  '<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>' +
  '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>' +
  '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" applyAlignment="1"><alignment vertical="top"/></xf></cellStyleXfs>' +
  '<cellXfs count="6">' +
  '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top"/></xf>' +
  '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment vertical="top"/></xf>' +
  '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>' +
  '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>' +
  '<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1" applyAlignment="1"><alignment vertical="top"/></xf>' +
  '<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>' +
  '</cellXfs>' +
  '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>' +
  '<dxfs count="0"/><tableStyles count="0" defaultTableStyle="TableStyleMedium2" defaultPivotStyle="PivotStyleLight16"/>' +
  '</styleSheet>'

function ConvertTo-SIXlsxColumnName {
  # 1 -> A, 26 -> Z, 27 -> AA, 16384 -> XFD
  param([Parameter(Mandatory)][int]$Index)
  $s = ''
  $n = $Index
  while ($n -gt 0) {
    $m = ($n - 1) % 26
    $s = [char](65 + $m) + $s
    $n = [int][Math]::Floor(($n - $m) / 26)
  }
  return $s
}

function Get-SIXlsxSafeSheetName {
  <# The sheet-name rules the export has always applied: at most 31 characters, and : \ / ? * [ ]
     replaced with '_'. Plus the two Excel rejects outright that the old path never met in practice: an
     empty name, and a name starting or ending with an apostrophe. #>
  param([Parameter()][AllowEmptyString()][AllowNull()][string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return 'Sheet' }
  $s = $Name.Substring(0, [Math]::Min(31, $Name.Length)) -replace '[:\\/?*\[\]]','_'
  if ($s.StartsWith("'")) { $s = '_' + $s.Substring(1) }
  if ($s.EndsWith("'"))   { $s = $s.Substring(0, $s.Length - 1) + '_' }
  return $s
}

# Scrub patterns, built from code points at load time so this file stays plain ASCII.
$script:SIXlsxRxCtl  = New-Object System.Text.RegularExpressions.Regex('[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]')
$script:SIXlsxRxHigh = New-Object System.Text.RegularExpressions.Regex(('[{0}-{1}](?![{2}-{3}])' -f [char]0xD800, [char]0xDBFF, [char]0xDC00, [char]0xDFFF))
$script:SIXlsxRxLow  = New-Object System.Text.RegularExpressions.Regex(('(?<![{0}-{1}])[{2}-{3}]' -f [char]0xD800, [char]0xDBFF, [char]0xDC00, [char]0xDFFF))
$script:SIXlsxRxNon  = New-Object System.Text.RegularExpressions.Regex(('[{0}{1}{2}{3}]' -f [char]0xFFFE, [char]0xFFFF, [char]0x2028, [char]0x2029))
# Any character the scrub might act on (every surrogate, paired or not) -- a cheap pre-check so the
# PowerShell path only calls the full scrub for the rare string that needs it.
$script:SIXlsxRxAny  = New-Object System.Text.RegularExpressions.Regex(('[\x00-\x08\x0B\x0C\x0E-\x1F\x7F{0}-{1}{2}{3}{4}{5}]' -f [char]0xD800, [char]0xDFFF, [char]0xFFFE, [char]0xFFFF, [char]0x2028, [char]0x2029))

function _SIXlsx-Scrub {
  <# ConvertTo-XlsxSafeString's rules, step for step and in the same order (RA-RunProgress.ps1). Kept
     as a copy rather than a call so the writer has no load-order dependency; the parity test pins the
     two (and the compiled twin) to identical output. #>
  param([AllowNull()][string]$Value)
  if ([string]::IsNullOrEmpty($Value)) { return $Value }
  $Value = $script:SIXlsxRxCtl.Replace($Value, '')
  $Value = $script:SIXlsxRxHigh.Replace($Value, '')
  $Value = $script:SIXlsxRxLow.Replace($Value, '')
  $Value = $script:SIXlsxRxNon.Replace($Value, '')
  if ($Value.Length -gt 32767) {
    $clip   = $Value.Length - 32767
    $marker = '... [truncated {0} chars]' -f $clip
    $cut    = 32767 - $marker.Length
    if ($cut -lt 0) { $cut = 0 }
    $clip   = $Value.Length - $cut
    $marker = '... [truncated {0} chars]' -f $clip
    $cut    = 32767 - $marker.Length
    if ($cut -lt 0) { $cut = 0 }
    $Value  = $Value.Substring(0, $cut) + $marker
  }
  return $Value
}

function _SIXlsx-CleanName {
  # Header / table text: the same scrub, never $null.
  param([AllowNull()][string]$Text)
  if ($null -eq $Text) { return '' }
  return (_SIXlsx-Scrub $Text)
}

# =====================================================================================================
# THE COMPILED HELPER. C# 5 on purpose: Windows PowerShell 5.1's Add-Type compiles with the .NET
# Framework's own csc, which knows nothing newer (no string interpolation, no ?., no out var).
# Each method has a PowerShell twin further down; keep the two in step -- the parity test will not.
# =====================================================================================================
$script:SIXlsxNativeType = 'SIXlsx.NativeV1'
$script:SIXlsxNativeSource = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Management.Automation;

namespace SIXlsx
{
    public static class NativeV1
    {
        static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

        static bool IsHigh(char c) { return c >= (char)0xD800 && c <= (char)0xDBFF; }
        static bool IsLow(char c)  { return c >= (char)0xDC00 && c <= (char)0xDFFF; }
        static bool IsCtl(char c)  { return (c < (char)0x20 && c != '\t' && c != '\n' && c != '\r') || c == (char)0x7F; }
        static bool IsNon(char c)  { return c == (char)0xFFFE || c == (char)0xFFFF || c == (char)0x2028 || c == (char)0x2029; }

        // ConvertTo-XlsxSafeString, same steps in the same order. The scan is the common case: a clean
        // string under the cell limit is returned as the SAME instance, without allocating.
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
            string t = b.ToString();
            b.Length = 0;
            for (int i = 0; i < t.Length; i++)
            {
                char c = t[i];
                if (IsHigh(c) && (i + 1 >= t.Length || !IsLow(t[i + 1]))) continue;
                b.Append(c);
            }
            t = b.ToString();
            b.Length = 0;
            for (int i = 0; i < t.Length; i++)
            {
                char c = t[i];
                if (IsLow(c) && (i == 0 || !IsHigh(t[i - 1]))) continue;
                b.Append(c);
            }
            t = b.ToString();
            b.Length = 0;
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

        static bool IsComposite(object v)
        {
            if (v == null || v is string) return false;
            if (v is IDictionary || v is PSCustomObject) return true;
            PSObject po = v as PSObject;
            if (po != null) return true;
            return (v is IEnumerable) && !v.GetType().IsValueType;
        }

        // Convert-CellValue's list rule for the common case: every item a string or a primitive, joined
        // with ', '. Anything else returns null and the caller defers the cell to PowerShell.
        static string TryJoin(object v)
        {
            if (v is IDictionary || v is PSCustomObject || v is PSObject) return null;
            IEnumerable e = v as IEnumerable;
            if (e == null) return null;
            StringBuilder b = new StringBuilder();
            bool first = true;
            foreach (object raw in e)
            {
                if (raw == null) continue;
                object it = Unwrap(raw);
                string s = it as string;
                if (s == null)
                {
                    if (it is PSObject || !it.GetType().IsPrimitive) return null;
                    s = (string)LanguagePrimitives.ConvertTo(it, typeof(string), Inv);
                }
                if (!first) b.Append(", ");
                b.Append(s);
                first = false;
            }
            return b.ToString();
        }

        // Every property name across every row, first-seen order, case-insensitive (first spelling wins).
        public static string[] ColumnUnion(IList rows)
        {
            List<string> outp = new List<string>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (object row in rows)
            {
                if (row == null) continue;
                foreach (PSPropertyInfo p in PSObject.AsPSObject(row).Properties)
                    if (seen.Add(p.Name)) outp.Add(p.Name);
            }
            return outp.ToArray();
        }

        // Rows (PSObjects) -> object[] per row in column order, by name. Composite values that are not
        // a plain list are left in place and their (row, col) appended to 'deferred'.
        public static object[][] Materialize(IList rows, string[] names, List<int> deferred)
        {
            int n = rows.Count, c = names.Length;
            Dictionary<string, int> idx = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < c; i++) if (!idx.ContainsKey(names[i])) idx[names[i]] = i;
            object[][] outp = new object[n][];
            for (int r = 0; r < n; r++)
            {
                object[] a = new object[c];
                outp[r] = a;
                object row = rows[r];
                if (row == null) continue;
                PSObject pso = PSObject.AsPSObject(row);
                foreach (PSPropertyInfo p in pso.Properties)
                {
                    int i;
                    if (!idx.TryGetValue(p.Name, out i) || a[i] != null) continue;
                    object v;
                    try { v = p.Value; } catch { v = null; }
                    v = Unwrap(v);
                    if (IsComposite(v))
                    {
                        string j = TryJoin(v);
                        if (j != null) v = j; else { deferred.Add(r); deferred.Add(i); }
                    }
                    a[i] = v;
                }
            }
            return outp;
        }

        static string Text(object v)
        {
            IFormattable f = v as IFormattable;
            if (f != null) return f.ToString(null, Inv);
            return v.ToString();
        }

        // Widest rendered value per column (scrubbed length for text) and which columns hold dates.
        public static void Measure(IList rows, int nCols, int[] maxLen, bool[] isDate)
        {
            foreach (object ro in rows)
            {
                IList r = ro as IList;
                if (r == null) continue;
                int lim = Math.Min(nCols, r.Count);
                for (int i = 0; i < lim; i++)
                {
                    object v = Unwrap(r[i]);
                    if (v == null) continue;
                    int len;
                    string s = v as string;
                    if (s != null) len = Scrub(s).Length;
                    else
                    {
                        if (v is DateTime || v is DateTimeOffset) isDate[i] = true;
                        len = Text(v).Length;
                    }
                    if (len > maxLen[i]) maxLen[i] = len;
                }
            }
        }

        static void Esc(TextWriter w, string s)
        {
            int start = 0;
            for (int i = 0; i < s.Length; i++)
            {
                string rep;
                switch (s[i])
                {
                    case '\r':
                        // CRLF and a lone CR are stored as LF -- what an XML parser (Excel's included)
                        // turns them into anyway, and what Excel itself writes for a line break.
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

        // A text cell is an index into the workbook's shared-string table; each distinct string is
        // stored once, which is what keeps a 100k-row report under the mail attachment cap.
        public static int SstId(string s, Dictionary<string, int> sst, List<string> sstList, int sstBase)
        {
            int id;
            if (!sst.TryGetValue(s, out id)) { id = sstBase + sstList.Count; sst[s] = id; sstList.Add(s); }
            return id;
        }

        static void Str(TextWriter w, string cOpen, string rq, string tStr, string s, Dictionary<string, int> sst, List<string> sstList, int sstBase)
        {
            w.Write(cOpen); w.Write(rq); w.Write(tStr); w.Write(SstId(s, sst, sstList, sstBase).ToString(Inv)); w.Write("</v></c>");
        }

        // The <si> entries for the strings this sheet added. Byte-for-byte what _SIXlsx-WriteSstPS writes.
        public static void WriteSst(TextWriter w, List<string> sstList)
        {
            foreach (string s in sstList) { w.Write("<si><t xml:space=\"preserve\">"); Esc(w, s); w.Write("</t></si>"); }
        }

        // The <row> elements from row 2 on. Byte-for-byte what _SIXlsx-WriteRowsPS writes.
        public static void WriteRows(TextWriter w, IList rows, int nCols, string[] cOpen, string[] tStr, string[] tNum, string[] tDate, string[] tBool, Dictionary<string, int> sst, List<string> sstList, int sstBase)
        {
            int rowNum = 1;
            foreach (object ro in rows)
            {
                rowNum++;
                string rq = rowNum.ToString(Inv);
                w.Write("<row r=\""); w.Write(rq); w.Write("\">");
                IList r = ro as IList;
                int lim = (r == null) ? 0 : Math.Min(nCols, r.Count);
                for (int i = 0; i < lim; i++)
                {
                    object v = Unwrap(r[i]);
                    if (v == null) continue;
                    string s = v as string;
                    if (s != null)
                    {
                        if (s.Length == 0) continue;
                        Str(w, cOpen[i], rq, tStr[i], Scrub(s), sst, sstList, sstBase);
                    }
                    else if (v is int || v is long)
                    {
                        w.Write(cOpen[i]); w.Write(rq); w.Write(tNum[i]); w.Write(((IFormattable)v).ToString(null, Inv)); w.Write("</v></c>");
                    }
                    else if (v is double || v is float)
                    {
                        double d = Convert.ToDouble(v, Inv);
                        if (double.IsNaN(d) || double.IsInfinity(d))
                        Str(w, cOpen[i], rq, tStr[i], d.ToString(Inv), sst, sstList, sstBase);
                        else
                        { w.Write(cOpen[i]); w.Write(rq); w.Write(tNum[i]); w.Write(d.ToString("R", Inv)); w.Write("</v></c>"); }
                    }
                    else if (v is DateTime)
                    {
                        DateTime dt = (DateTime)v;
                        if (dt.Year < 1900)
                        Str(w, cOpen[i], rq, tStr[i], dt.ToString("yyyy-MM-dd HH:mm:ss", Inv), sst, sstList, sstBase);
                        else
                        { w.Write(cOpen[i]); w.Write(rq); w.Write(tDate[i]); w.Write(dt.ToOADate().ToString("R", Inv)); w.Write("</v></c>"); }
                    }
                    else if (v is bool)
                    {
                        w.Write(cOpen[i]); w.Write(rq); w.Write(tBool[i]); w.Write(((bool)v) ? "1" : "0"); w.Write("</v></c>");
                    }
                    else if (v is decimal || v is short || v is byte || v is sbyte || v is ushort || v is uint || v is ulong)
                    {
                        w.Write(cOpen[i]); w.Write(rq); w.Write(tNum[i]); w.Write(((IFormattable)v).ToString(null, Inv)); w.Write("</v></c>");
                    }
                    else if (v is DateTimeOffset)
                    {
                        w.Write(cOpen[i]); w.Write(rq); w.Write(tDate[i]); w.Write(((DateTimeOffset)v).DateTime.ToOADate().ToString("R", Inv)); w.Write("</v></c>");
                    }
                    else
                    {
                        string o = Scrub((string)LanguagePrimitives.ConvertTo(v, typeof(string), Inv));
                        if (!string.IsNullOrEmpty(o)) Str(w, cOpen[i], rq, tStr[i], o, sst, sstList, sstBase);
                    }
                }
                w.Write("</row>");
            }
        }
    }
}
'@

function _SIXlsx-Native {
  <# The compiled helper's type, compiling it on first use; $null when it cannot be had -- the caller
     then takes the PowerShell path. $script:SIXlsxForcePowerShell = $true forces that path (tests). #>
  if ($script:SIXlsxForcePowerShell) { return $null }
  $t = $script:SIXlsxNativeType -as [type]
  if ($null -ne $t) { return $t }
  if ($script:SIXlsxNativeFailed) { return $null }
  try {
    Add-Type -TypeDefinition $script:SIXlsxNativeSource -Language CSharp -ErrorAction Stop
    return ($script:SIXlsxNativeType -as [type])
  } catch {
    $script:SIXlsxNativeFailed = $true
    Write-Verbose ("[xlsx] compiled helper unavailable, using the PowerShell path: {0}" -f $_.Exception.Message)
    return $null
  }
}

function Get-SIXlsxColumnUnion {
  <# Every property name across every row, first-seen order, case-insensitive (first spelling wins).
     Never row 1's shape alone -- Advanced Hunting rows omit null-valued columns. #>
  param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$InputObject)
  $nt = _SIXlsx-Native
  if ($null -ne $nt) { return ,$nt::ColumnUnion($InputObject) }
  $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $names = New-Object 'System.Collections.Generic.List[string]'
  foreach ($r in $InputObject) {
    if ($null -eq $r) { continue }
    foreach ($p in $r.PSObject.Properties) { if ($seen.Add($p.Name)) { [void]$names.Add($p.Name) } }
  }
  return ,$names.ToArray()
}

function ConvertTo-SIXlsxRows {  <#
  .SYNOPSIS
    Objects -> one object[] per row in -Columns order (by property name, case-insensitive).
  .DESCRIPTION
    A value that is a list of strings/primitives is joined with ', ' here (Convert-CellValue's list
    rule). Any other composite value -- a hashtable, a custom object, a list holding objects -- is left
    as it is and listed in .Deferred as (row, col) pairs for the caller to flatten its own way.
    Returns @{ Rows = object[][]; Deferred = int[] }.
  #>
  param(
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$InputObject,
    [Parameter(Mandatory)][string[]]$Columns,
    [ValidateSet('Auto','Native','PowerShell')][string]$Engine = 'Auto'
  )
  $deferred = New-Object 'System.Collections.Generic.List[int]'
  $nt = $null
  if ($Engine -ne 'PowerShell') { $nt = _SIXlsx-Native }
  if ($Engine -eq 'Native' -and $null -eq $nt) { throw "the compiled xlsx helper is not available" }
  if ($null -ne $nt) {
    $rows = $nt::Materialize($InputObject, $Columns, $deferred)
    return @{ Rows = $rows; Deferred = $deferred.ToArray() }
  }

  # ---- PowerShell twin of NativeV1.Materialize -------------------------------------------------------
  $nCols = $Columns.Count
  $idx = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::OrdinalIgnoreCase)
  for ($i = 0; $i -lt $nCols; $i++) { if (-not $idx.ContainsKey($Columns[$i])) { $idx[$Columns[$i]] = $i } }
  $out = New-Object 'object[][]' $InputObject.Count
  for ($r = 0; $r -lt $InputObject.Count; $r++) {
    $a = New-Object 'object[]' $nCols
    $out[$r] = $a
    $row = $InputObject[$r]
    if ($null -eq $row) { continue }
    foreach ($p in $row.PSObject.Properties) {
      $i = 0
      if (-not $idx.TryGetValue($p.Name, [ref]$i) -or $null -ne $a[$i]) { continue }
      $v = $null
      try { $v = $p.Value } catch { $v = $null }
      if ($null -ne $v -and -not ($v -is [string]) -and (
            $v -is [System.Collections.IDictionary] -or $v -is [System.Management.Automation.PSCustomObject] -or
            ($v -is [System.Collections.IEnumerable] -and -not $v.GetType().IsValueType))) {
        $j = $null
        if (-not ($v -is [System.Collections.IDictionary]) -and -not ($v -is [System.Management.Automation.PSCustomObject])) {
          $sb = New-Object System.Text.StringBuilder
          $first = $true
          $ok = $true
          foreach ($it in $v) {
            if ($null -eq $it) { continue }
            if ($it -is [System.Management.Automation.PSCustomObject]) { $ok = $false; break }
            if ($it -is [string]) { $s = [string]$it }
            elseif ($it.GetType().IsPrimitive) { $s = [string]$it }
            else { $ok = $false; break }
            if (-not $first) { [void]$sb.Append(', ') }
            [void]$sb.Append($s)
            $first = $false
          }
          if ($ok) { $j = $sb.ToString() }
        }
        if ($null -ne $j) { $v = $j } else { [void]$deferred.Add($r); [void]$deferred.Add($i) }
      }
      $a[$i] = $v
    }
  }
  return @{ Rows = $out; Deferred = $deferred.ToArray() }
}

function _SIXlsx-MeasurePS {
  # PowerShell twin of NativeV1.Measure.
  param($Rows, [int]$NCols, [int[]]$MaxLen, [bool[]]$IsDate)
  foreach ($r in $Rows) {
    if ($null -eq $r) { continue }
    $lim = [Math]::Min($NCols, $r.Count)
    for ($i = 0; $i -lt $lim; $i++) {
      $v = $r[$i]
      if ($null -eq $v) { continue }
      if ($v -is [string]) {
        $len = $v.Length
        if ($len -gt 32767 -or $script:SIXlsxRxAny.IsMatch($v)) { $len = (_SIXlsx-Scrub $v).Length }
      }
      else {
        if ($v -is [datetime] -or $v -is [System.DateTimeOffset]) { $IsDate[$i] = $true }
        if ($v -is [System.IFormattable]) { $len = $v.ToString($null, [System.Globalization.CultureInfo]::InvariantCulture).Length }
        else { $len = $v.ToString().Length }
      }
      if ($len -gt $MaxLen[$i]) { $MaxLen[$i] = $len }
    }
  }
}

function _SIXlsx-SstIdPS {
  # PowerShell twin of NativeV1.SstId.
  param([string]$S, $Sst, $SstList, [int]$SstBase)
  $id = 0
  if (-not $Sst.TryGetValue($S, [ref]$id)) { $id = $SstBase + $SstList.Count; $Sst[$S] = $id; [void]$SstList.Add($S) }
  return $id
}

function _SIXlsx-WriteSstPS {
  # PowerShell twin of NativeV1.WriteSst.
  param($Writer, $SstList)
  foreach ($s in $SstList) { $Writer.Write('<si><t xml:space="preserve">' + [System.Security.SecurityElement]::Escape($s.Replace("`r`n", "`n").Replace("`r", "`n")) + '</t></si>') }
}

function _SIXlsx-WriteRowsPS {  # PowerShell twin of NativeV1.WriteRows -- must write the same bytes.
  param($Writer, $Rows, [int]$NCols, [string[]]$COpen, [string[]]$TStr, [string[]]$TNum, [string[]]$TDate, [string[]]$TBool, $Sst, $SstList, [int]$SstBase)
  $inv = [System.Globalization.CultureInfo]::InvariantCulture
  $sw = $Writer
  $rxAny = $script:SIXlsxRxAny
  $id = 0
  $rowNum = 1
  foreach ($r in $Rows) {
    $rowNum++
    $rq = $rowNum.ToString($inv)
    $sw.Write('<row r="' + $rq + '">')
    $lim = 0; if ($null -ne $r) { $lim = [Math]::Min($NCols, $r.Count) }
    for ($i = 0; $i -lt $lim; $i++) {
      $v = $r[$i]
      if ($null -eq $v) { continue }
      if ($v -is [string]) {
        if ($v.Length -eq 0) { continue }
        # Inlined scrub check + table lookup: a function call per cell is what makes this path slow.
        if ($v.Length -gt 32767 -or $rxAny.IsMatch($v)) { $v = _SIXlsx-Scrub $v }
        if (-not $Sst.TryGetValue($v, [ref]$id)) { $id = $SstBase + $SstList.Count; $Sst[$v] = $id; [void]$SstList.Add($v) }
        $sw.Write($COpen[$i] + $rq + $TStr[$i] + $id.ToString($inv) + '</v></c>')
      }
      elseif ($v -is [int] -or $v -is [long]) {
        $sw.Write($COpen[$i] + $rq + $TNum[$i] + $v.ToString($null, $inv) + '</v></c>')
      }
      elseif ($v -is [double] -or $v -is [single]) {
        $d = [double]$v
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) {
          $sw.Write($COpen[$i] + $rq + $TStr[$i] + (_SIXlsx-SstIdPS $d.ToString($inv) $Sst $SstList $SstBase).ToString($inv) + '</v></c>')
        } else {
          $sw.Write($COpen[$i] + $rq + $TNum[$i] + $d.ToString('R', $inv) + '</v></c>')
        }
      }
      elseif ($v -is [datetime]) {
        if ($v.Year -lt 1900) {
          $sw.Write($COpen[$i] + $rq + $TStr[$i] + (_SIXlsx-SstIdPS $v.ToString('yyyy-MM-dd HH:mm:ss', $inv) $Sst $SstList $SstBase).ToString($inv) + '</v></c>')
        } else {
          $sw.Write($COpen[$i] + $rq + $TDate[$i] + $v.ToOADate().ToString('R', $inv) + '</v></c>')
        }
      }
      elseif ($v -is [bool]) {
        $sw.Write($COpen[$i] + $rq + $TBool[$i] + $(if ($v) { '1' } else { '0' }) + '</v></c>')
      }
      elseif ($v -is [decimal] -or $v -is [int16] -or $v -is [byte] -or $v -is [sbyte] -or
              $v -is [uint16] -or $v -is [uint32] -or $v -is [uint64]) {
        $sw.Write($COpen[$i] + $rq + $TNum[$i] + $v.ToString($null, $inv) + '</v></c>')
      }
      elseif ($v -is [System.DateTimeOffset]) {
        $sw.Write($COpen[$i] + $rq + $TDate[$i] + $v.DateTime.ToOADate().ToString('R', $inv) + '</v></c>')
      }
      else {
        $o = _SIXlsx-Scrub ([string]$v)
        if (-not [string]::IsNullOrEmpty($o)) {
          $sw.Write($COpen[$i] + $rq + $TStr[$i] + (_SIXlsx-SstIdPS $o $Sst $SstList $SstBase).ToString($inv) + '</v></c>')
        }
      }
    }
    $sw.Write('</row>')
  }
}

function _SIXlsx-ResolveTarget {
  # Resolve a relationship Target against the folder of the part that owns the .rels file.
  param([string]$SourceDir, [string]$Target)
  if ($Target.StartsWith('/')) { return $Target.TrimStart('/') }
  $segs = New-Object System.Collections.Generic.List[string]
  if ($SourceDir) { foreach ($x in $SourceDir.Split('/')) { if ($x) { [void]$segs.Add($x) } } }
  foreach ($x in $Target.Split('/')) {
    if ($x -eq '' -or $x -eq '.') { continue }
    if ($x -eq '..') { if ($segs.Count -gt 0) { $segs.RemoveAt($segs.Count - 1) }; continue }
    [void]$segs.Add($x)
  }
  return ($segs.ToArray() -join '/')
}

function _SIXlsx-RelsPathFor {
  # xl/workbook.xml -> xl/_rels/workbook.xml.rels
  param([string]$PartName)
  $i = $PartName.LastIndexOf('/')
  if ($i -lt 0) { return '_rels/' + $PartName + '.rels' }
  return $PartName.Substring(0, $i) + '/_rels/' + $PartName.Substring($i + 1) + '.rels'
}

function _SIXlsx-DirOf {
  param([string]$PartName)
  $i = $PartName.LastIndexOf('/')
  if ($i -lt 0) { return '' }
  return $PartName.Substring(0, $i)
}

function _SIXlsx-XmlBytes {
  # Serialise an XmlDocument as UTF-8 WITHOUT a BOM.
  param([System.Xml.XmlDocument]$Doc)
  $ms = New-Object System.IO.MemoryStream
  $set = New-Object System.Xml.XmlWriterSettings
  $set.Encoding = New-Object System.Text.UTF8Encoding($false)
  $set.Indent = $false
  $xw = [System.Xml.XmlWriter]::Create($ms, $set)
  try { $Doc.Save($xw) } finally { $xw.Close() }
  return $ms.ToArray()
}

function _SIXlsx-LoadXml {
  param([byte[]]$Bytes)
  $doc = New-Object System.Xml.XmlDocument
  $doc.PreserveWhitespace = $true
  $ms = New-Object System.IO.MemoryStream(,$Bytes)
  try { $doc.Load($ms) } finally { $ms.Dispose() }
  return $doc
}

function _SIXlsx-MergeStyles {
  <# Append SI's six cell formats to a FOREIGN styles.xml (one this writer did not create) and return
     the cellXfs index for each role. Only reached when a run appends to a workbook something else
     wrote; a workbook created here keeps the canonical stylesheet, whose indices ARE the roles. #>
  param([System.Xml.XmlDocument]$Doc)
  $ns = New-Object System.Xml.XmlNamespaceManager($Doc.NameTable)
  $ns.AddNamespace('m', $script:SIXlsxNsMain)
  $root = $Doc.DocumentElement

  # date number format -- a fresh custom id above every existing one
  $numFmts = $root.SelectSingleNode('m:numFmts', $ns)
  if ($null -eq $numFmts) {
    $numFmts = $Doc.CreateElement('numFmts', $script:SIXlsxNsMain)
    [void]$root.PrependChild($numFmts)
  }
  $fmtId = 163
  foreach ($f in $numFmts.SelectNodes('m:numFmt', $ns)) { $v = [int]$f.GetAttribute('numFmtId'); if ($v -gt $fmtId) { $fmtId = $v } }
  $fmtId++
  $nf = $Doc.CreateElement('numFmt', $script:SIXlsxNsMain)
  $nf.SetAttribute('numFmtId', [string]$fmtId); $nf.SetAttribute('formatCode', 'yyyy-mm-dd hh:mm:ss')
  [void]$numFmts.AppendChild($nf)
  $numFmts.SetAttribute('count', [string]$numFmts.SelectNodes('m:numFmt', $ns).Count)

  # bold font
  $fonts = $root.SelectSingleNode('m:fonts', $ns)
  $boldId = 0
  if ($null -ne $fonts) {
    $fn = $Doc.CreateElement('font', $script:SIXlsxNsMain)
    foreach ($pair in @(@('b',$null), @('sz','11'), @('name','Calibri'))) {
      $e = $Doc.CreateElement($pair[0], $script:SIXlsxNsMain)
      if ($null -ne $pair[1]) { $e.SetAttribute('val', $pair[1]) }
      [void]$fn.AppendChild($e)
    }
    [void]$fonts.AppendChild($fn)
    $boldId = $fonts.SelectNodes('m:font', $ns).Count - 1
    $fonts.SetAttribute('count', [string]($boldId + 1))
  }

  # top alignment on the Normal style (see the stylesheet comment above)
  $csx = $root.SelectSingleNode('m:cellStyleXfs/m:xf', $ns)
  if ($null -ne $csx) {
    $csx.SetAttribute('applyAlignment', '1')
    $al = $csx.SelectSingleNode('m:alignment', $ns)
    if ($null -eq $al) { $al = $Doc.CreateElement('alignment', $script:SIXlsxNsMain); [void]$csx.PrependChild($al) }
    $al.SetAttribute('vertical', 'top')
  }

  $cellXfs = $root.SelectSingleNode('m:cellXfs', $ns)
  $base = $cellXfs.SelectNodes('m:xf', $ns).Count
  $defs = @(
    @(0,       0,       $false),
    @(0,       $boldId, $false),
    @(0,       0,       $true),
    @(0,       $boldId, $true),
    @($fmtId,  0,       $false),
    @($fmtId,  0,       $true)
  )
  foreach ($d in $defs) {
    $xf = $Doc.CreateElement('xf', $script:SIXlsxNsMain)
    $xf.SetAttribute('numFmtId', [string]$d[0]); $xf.SetAttribute('fontId', [string]$d[1])
    $xf.SetAttribute('fillId', '0'); $xf.SetAttribute('borderId', '0'); $xf.SetAttribute('xfId', '0')
    if ($d[0] -ne 0) { $xf.SetAttribute('applyNumberFormat', '1') }
    if ($d[1] -ne 0) { $xf.SetAttribute('applyFont', '1') }
    $xf.SetAttribute('applyAlignment', '1')
    $al = $Doc.CreateElement('alignment', $script:SIXlsxNsMain)
    $al.SetAttribute('vertical', 'top')
    if ($d[2]) { $al.SetAttribute('wrapText', '1') }
    [void]$xf.AppendChild($al)
    [void]$cellXfs.AppendChild($xf)
  }
  $cellXfs.SetAttribute('count', [string]($base + 6))
  return @(($base), ($base + 1), ($base + 2), ($base + 3), ($base + 4), ($base + 5))
}

# The read buffer (characters) for an existing shared-string table, which is read as a stream, never whole. A buffer, not
# a limit: a table of any size is read through it. Tests set a tiny one to cross many buffer boundaries.
$script:SIXlsxSstChunkChars = 65536

function _SIXlsx-OpenSstReader {
  param($Zin, [string]$Part)
  # the same decoding as before (UTF-8, a byte-order mark dropped), so character offsets match between the two reads
  New-Object System.IO.StreamReader($Zin.GetEntry($Part).Open(), (New-Object System.Text.UTF8Encoding($false)), $true)
}

function _SIXlsx-SstScan {
  <#
    The workbook's existing shared-string table, read as a stream (constant memory, whatever its size). Returns
    @{ Head; Count; BodyStart; BodyLength }: Head = everything before the strings, with the open tag's count / uniqueCount
    dropped (and a self-closing tag opened); Count = its <si> entries; BodyStart / BodyLength = the strings between the
    open tag and the last </sst>, in characters. The same values the whole-table read gave.
  #>
  param([Parameter(Mandatory)]$Zin, [Parameter(Mandatory)][string]$Part)
  $chunk = [Math]::Max(8, [int]$script:SIXlsxSstChunkChars)
  $buf = New-Object 'char[]' $chunk
  $sr = _SIXlsx-OpenSstReader -Zin $Zin -Part $Part
  try {
    # 1. the head: read until the open tag is complete
    $acc = New-Object System.Text.StringBuilder
    $reOpen = [regex]'<sst\b[^>]*>'
    $m = $null
    while ($true) {
      $n = $sr.Read($buf, 0, $chunk)
      if ($n -le 0) { throw "the workbook's shared-string table is not readable" }
      [void]$acc.Append($buf, 0, $n)
      $m = $reOpen.Match($acc.ToString())
      if ($m.Success) { break }
    }
    $s = $acc.ToString(); $acc = $null
    $open = ($m.Value -replace '\s(count|uniqueCount)\s*=\s*"[^"]*"', '')
    $bodyStart = [long]($m.Index + $m.Length)
    if ($open.EndsWith('/>')) {
      return @{ Head = ($s.Substring(0, $m.Index) + $open.Substring(0, $open.Length - 2).TrimEnd() + '>'); Count = 0; BodyStart = $bodyStart; BodyLength = 0L }
    }
    $head = $s.Substring(0, $m.Index) + $open
    # 2. the strings: count <si> entries and find the last </sst>. A match is judged only once the characters after its
    #    start are read (the last K characters wait for the next buffer), so a tag split across two buffers counts once.
    $K = 6
    $reSi = [regex]'<si[\s>/]'; $reClose = [regex]'</sst>'
    $text = $s.Substring($m.Index + $m.Length); $s = $null
    $base = $bodyStart
    $count = 0L; $lastClose = -1L
    while ($true) {
      $n = $sr.Read($buf, 0, $chunk)
      $eof = ($n -le 0)
      if (-not $eof) { $text = $text + [string]::new($buf, 0, $n) }
      $limit = if ($eof) { $text.Length } else { [Math]::Max(0, $text.Length - $K) }
      foreach ($x in $reSi.Matches($text)) { if ($x.Index -lt $limit) { $count++ } }
      foreach ($x in $reClose.Matches($text)) { if ($x.Index -lt $limit) { $lastClose = $base + $x.Index } }
      if ($eof) { break }
      $text = $text.Substring($limit); $base += $limit
    }
    if ($lastClose -lt 0) { throw "the workbook's shared-string table is not readable" }
    @{ Head = $head; Count = [int]$count; BodyStart = $bodyStart; BodyLength = ($lastClose - $bodyStart) }
  } finally { $sr.Dispose() }
}

function _SIXlsx-SstCopyBody {
  <# Copies -Length characters from -Start of the existing shared-string table to -Writer, through one buffer. #>
  param([Parameter(Mandatory)]$Zin, [Parameter(Mandatory)][string]$Part, [long]$Start, [long]$Length, [Parameter(Mandatory)]$Writer)
  if ($Length -le 0) { return }
  $chunk = [Math]::Max(8, [int]$script:SIXlsxSstChunkChars)
  $buf = New-Object 'char[]' $chunk
  $sr = _SIXlsx-OpenSstReader -Zin $Zin -Part $Part
  try {
    $skip = $Start
    while ($skip -gt 0) { $r = $sr.Read($buf, 0, [int][Math]::Min([long]$chunk, $skip)); if ($r -le 0) { throw "the workbook's shared-string table ended early" }; $skip -= $r }
    $left = $Length
    while ($left -gt 0) { $r = $sr.Read($buf, 0, [int][Math]::Min([long]$chunk, $left)); if ($r -le 0) { throw "the workbook's shared-string table ended early" }; $Writer.Write($buf, 0, $r); $left -= $r }
  } finally { $sr.Dispose() }
}

function Write-SIXlsxWorksheet {
  <#
  .SYNOPSIS
    Write one worksheet into an .xlsx, creating the workbook or adding to the one already on disk.

  .DESCRIPTION
    Header row bold + frozen; an Excel table over the whole range (banded rows + autofilter); column
    widths in characters; wrap + top alignment on -WrapColumns. Cell typing follows the .NET type of
    each value: string -> text, any numeric -> number, [bool] -> boolean, [datetime] -> number with a
    yyyy-mm-dd hh:mm:ss format, $null / '' -> no cell at all. Anything else is written as its string
    form (callers flatten arrays and objects first).

    A sheet whose name already exists (compared case-insensitively, as Excel does) is REPLACED -- the
    old sheet, its table and its relationships are removed and the new sheet is appended last, which is
    where the previous writer put a re-written sheet too. Every other part of an existing workbook is
    copied through byte-for-byte.

    The new package is built beside the target and moved over it only once complete, so a failure
    mid-write never leaves a half-written workbook where the previous one was.

  .PARAMETER Rows
    Data rows only (no header), each an object[] in -Header order. A List[object[]] is ideal.

  .PARAMETER ColumnWidths
    Optional, one per column. When omitted, each width is the longest value in the column (header
    included) + 2 -- the +2 leaves room for the filter arrow -- with a floor of 8, capped at
    -MaxColumnWidth or at the column's own entry in -WidthCaps.

  .PARAMETER Engine
    Auto (compiled helper when available, else PowerShell), Native or PowerShell. Tests use the last
    two to prove both paths write the same bytes.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$SheetName,
    [Parameter(Mandatory)][AllowEmptyString()][AllowEmptyCollection()][string[]]$Header,
    [Parameter()][AllowNull()][AllowEmptyCollection()][object]$Rows,
    [double[]]$ColumnWidths,
    [string[]]$WrapColumns = @(),
    [double]$MaxColumnWidth = 50,
    [hashtable]$WidthCaps = @{},
    [string]$TableName,
    [string]$TableStyle = 'Medium9',
    [ValidateSet('Optimal','Fastest')][string]$Compression = 'Optimal',
    [ValidateSet('Auto','Native','PowerShell')][string]$Engine = 'Auto'
  )

  $nt = $null
  if ($Engine -ne 'PowerShell') { $nt = _SIXlsx-Native }
  if ($Engine -eq 'Native' -and $null -eq $nt) { throw "the compiled xlsx helper is not available" }

  Add-Type -AssemblyName System.IO.Compression            -ErrorAction Stop
  Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop

  $inv = [System.Globalization.CultureInfo]::InvariantCulture
  $safeSheet = Get-SIXlsxSafeSheetName $SheetName
  $fullPath = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { [System.IO.Path]::Combine((Get-Location).Path, $Path) }
  $dir = [System.IO.Path]::GetDirectoryName($fullPath)
  if ($dir -and -not [System.IO.Directory]::Exists($dir)) { [void][System.IO.Directory]::CreateDirectory($dir) }

  # ---- rows: anything enumerable, materialised once so the range is known before the first byte ------
  if ($null -eq $Rows) { $dataRows = @() }
  elseif ($Rows -is [System.Collections.ICollection]) { $dataRows = $Rows }
  else { $dataRows = @($Rows) }
  $nRows = $dataRows.Count

  # ---- header: cleaned, non-empty and unique -- a table refuses blank or duplicate column names -------
  $nCols = $Header.Count
  if ($nCols -lt 1) { throw "Write-SIXlsxWorksheet: at least one column is required." }
  $hdr = New-Object 'string[]' $nCols
  $seenHdr = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  for ($i = 0; $i -lt $nCols; $i++) {
    $h = (_SIXlsx-CleanName $Header[$i]).Trim()
    if ($h.Length -eq 0) { $h = 'Column' + ($i + 1) }
    if ($h.Length -gt 255) { $h = $h.Substring(0, 255) }
    $cand = $h; $k = 2
    while (-not $seenHdr.Add($cand)) { $cand = $h + $k; $k++ }
    $hdr[$i] = $cand
  }

  # ---- widths --------------------------------------------------------------------------------------
  # One measuring pass gives both the widths and which columns hold dates (those get the date format
  # as their COLUMN style too, so a value typed into the column later is shown the same way).
  $widths = New-Object 'double[]' $nCols
  $maxLen = New-Object 'int[]' $nCols
  $isDate = New-Object 'bool[]' $nCols
  for ($i = 0; $i -lt $nCols; $i++) { $maxLen[$i] = $hdr[$i].Length }
  if ($null -ne $nt) { $nt::Measure($dataRows, $nCols, $maxLen, $isDate) }
  else { _SIXlsx-MeasurePS -Rows $dataRows -NCols $nCols -MaxLen $maxLen -IsDate $isDate }
  if ($ColumnWidths -and $ColumnWidths.Count -eq $nCols) {
    for ($i = 0; $i -lt $nCols; $i++) { $widths[$i] = $ColumnWidths[$i] }
  } else {
    for ($i = 0; $i -lt $nCols; $i++) {
      $cap = $MaxColumnWidth
      if ($WidthCaps.ContainsKey($hdr[$i])) { $cap = [double]$WidthCaps[$hdr[$i]] }
      $widths[$i] = [Math]::Min($cap, [Math]::Max(8, $maxLen[$i] + 2))
    }
  }
  $wrapSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($w in @($WrapColumns)) { if ($w) { [void]$wrapSet.Add($w) } }

  # ---- existing package ------------------------------------------------------------------------------
  $existing = [System.IO.File]::Exists($fullPath)
  $zin = $null
  $tmp = $fullPath + '.si-xlsx.tmp'
  try {
    $partBytes = @{}      # parts read into memory (small XML only)
    $entryNames = New-Object System.Collections.Generic.List[string]
    if ($existing) {
      $zin = [System.IO.Compression.ZipFile]::OpenRead($fullPath)
      foreach ($e in $zin.Entries) { [void]$entryNames.Add($e.FullName) }
    }
    $readPart = {
      param($name)
      if ($partBytes.ContainsKey($name)) { return $partBytes[$name] }
      if ($null -eq $zin) { return $null }
      $e = $zin.GetEntry($name)
      if ($null -eq $e) { return $null }
      $ms = New-Object System.IO.MemoryStream
      $s = $e.Open(); try { $s.CopyTo($ms) } finally { $s.Close() }
      $b = $ms.ToArray(); $partBytes[$name] = $b
      return $b
    }

    $nsm = $null
    if ($existing) {
      # Package root -> workbook part
      $rootRels = _SIXlsx-LoadXml (& $readPart '_rels/.rels')
      $wbPart = $null
      foreach ($rel in $rootRels.DocumentElement.ChildNodes) {
        if ($rel.NodeType -ne 'Element') { continue }
        if ($rel.GetAttribute('Type') -like '*/officeDocument') { $wbPart = _SIXlsx-ResolveTarget '' $rel.GetAttribute('Target') }
      }
      if (-not $wbPart) { throw "not a spreadsheet package (no officeDocument relationship)" }
      $ctDoc    = _SIXlsx-LoadXml (& $readPart '[Content_Types].xml')
      $wbDoc    = _SIXlsx-LoadXml (& $readPart $wbPart)
      $wbRelsPart = _SIXlsx-RelsPathFor $wbPart
      $wbRelsDoc  = _SIXlsx-LoadXml (& $readPart $wbRelsPart)
    } else {
      $wbPart = 'xl/workbook.xml'
      $wbRelsPart = 'xl/_rels/workbook.xml.rels'
      $ctDoc = New-Object System.Xml.XmlDocument
      $ctDoc.LoadXml('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="' + $script:SIXlsxNsCt + '"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>')
      $rootRels = New-Object System.Xml.XmlDocument
      $rootRels.LoadXml('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="' + $script:SIXlsxNsPkg + '"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
      $wbDoc = New-Object System.Xml.XmlDocument
      $wbDoc.LoadXml('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="' + $script:SIXlsxNsMain + '" xmlns:r="' + $script:SIXlsxNsRel + '"><bookViews><workbookView/></bookViews><sheets/></workbook>')
      $wbRelsDoc = New-Object System.Xml.XmlDocument
      $wbRelsDoc.LoadXml('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="' + $script:SIXlsxNsPkg + '"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
    }
    $wbDir = _SIXlsx-DirOf $wbPart
    $nsm = New-Object System.Xml.XmlNamespaceManager($wbDoc.NameTable)
    $nsm.AddNamespace('m', $script:SIXlsxNsMain)
    $nsm.AddNamespace('r', $script:SIXlsxNsRel)
    $sheetsEl = $wbDoc.DocumentElement.SelectSingleNode('m:sheets', $nsm)

    $dropParts  = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $writeParts = @{}   # part name -> byte[]

    # wb rels by id
    $relById = @{}
    foreach ($rel in @($wbRelsDoc.DocumentElement.ChildNodes)) {
      if ($rel.NodeType -ne 'Element') { continue }
      $relById[$rel.GetAttribute('Id')] = $rel
    }

    # ---- remove a same-named sheet (case-insensitive) -----------------------------------------------
    $sheetNodes = @($sheetsEl.SelectNodes('m:sheet', $nsm))
    for ($si = 0; $si -lt $sheetNodes.Count; $si++) {
      $sn = $sheetNodes[$si]
      if (-not [string]::Equals($sn.GetAttribute('name'), $safeSheet, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
      $rid = $sn.GetAttribute('id', $script:SIXlsxNsRel)
      if ($relById.ContainsKey($rid)) {
        $rel = $relById[$rid]
        $sp = _SIXlsx-ResolveTarget $wbDir $rel.GetAttribute('Target')
        [void]$dropParts.Add($sp)
        $spRels = _SIXlsx-RelsPathFor $sp
        $spRelsBytes = & $readPart $spRels
        if ($null -ne $spRelsBytes) {
          [void]$dropParts.Add($spRels)
          $spRelsDoc = _SIXlsx-LoadXml $spRelsBytes
          foreach ($r2 in $spRelsDoc.DocumentElement.ChildNodes) {
            if ($r2.NodeType -ne 'Element') { continue }
            if ($r2.GetAttribute('TargetMode') -eq 'External') { continue }
            # Only parts that belong to the sheet alone (its tables, comments, drawings) are dropped.
            $tp = _SIXlsx-ResolveTarget (_SIXlsx-DirOf $sp) $r2.GetAttribute('Target')
            [void]$dropParts.Add($tp)
            [void]$dropParts.Add((_SIXlsx-RelsPathFor $tp))
          }
        }
        [void]$rel.ParentNode.RemoveChild($rel)
        $relById.Remove($rid)
      }
      [void]$sheetsEl.RemoveChild($sn)
      # Sheet-scoped defined names point at sheets by POSITION -- drop this sheet's, shift the later ones.
      foreach ($dn in @($wbDoc.DocumentElement.SelectNodes('m:definedNames/m:definedName', $nsm))) {
        if (-not $dn.HasAttribute('localSheetId')) { continue }
        $lsid = [int]$dn.GetAttribute('localSheetId')
        if ($lsid -eq $si) { [void]$dn.ParentNode.RemoveChild($dn) }
        elseif ($lsid -gt $si) { $dn.SetAttribute('localSheetId', [string]($lsid - 1)) }
      }
      foreach ($wv in @($wbDoc.DocumentElement.SelectNodes('m:bookViews/m:workbookView', $nsm))) {
        if ($wv.HasAttribute('activeTab')) { $wv.SetAttribute('activeTab', '0') }
        if ($wv.HasAttribute('firstSheet')) { $wv.SetAttribute('firstSheet', '0') }
      }
      # The calculation chain can name cells on the removed sheet; Excel rebuilds it when absent.
      foreach ($rel in @($relById.Values)) {
        if ($rel.GetAttribute('Type') -like '*/calcChain') {
          [void]$dropParts.Add((_SIXlsx-ResolveTarget $wbDir $rel.GetAttribute('Target')))
          [void]$rel.ParentNode.RemoveChild($rel)
          $relById.Remove($rel.GetAttribute('Id'))
        }
      }
      break
    }

    # ---- allocate names / ids --------------------------------------------------------------------------
    $live = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $entryNames) { if (-not $dropParts.Contains($n)) { [void]$live.Add($n) } }
    $k = 1; while ($live.Contains("xl/worksheets/sheet$k.xml")) { $k++ }
    $sheetPart = "xl/worksheets/sheet$k.xml"
    $k = 1; while ($live.Contains("xl/tables/table$k.xml")) { $k++ }
    $tablePart = "xl/tables/table$k.xml"
    $k = 1; while ($relById.ContainsKey("rId$k")) { $k++ }
    $sheetRelId = "rId$k"
    $sheetId = 0
    foreach ($sn in $sheetsEl.SelectNodes('m:sheet', $nsm)) { $v = [int]$sn.GetAttribute('sheetId'); if ($v -gt $sheetId) { $sheetId = $v } }
    $sheetId++

    # table id + name must be unique across the workbook: read every surviving table part
    $tblIdMax = 0
    $tblNames = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $live) {
      if ($n -notlike 'xl/tables/*.xml' -and $n -notlike '*/tables/*.xml') { continue }
      try {
        $td = _SIXlsx-LoadXml (& $readPart $n)
        $v = [int]$td.DocumentElement.GetAttribute('id'); if ($v -gt $tblIdMax) { $tblIdMax = $v }
        [void]$tblNames.Add($td.DocumentElement.GetAttribute('name'))
        [void]$tblNames.Add($td.DocumentElement.GetAttribute('displayName'))
      } catch { }
    }
    $tName = if ($TableName) { $TableName } else { $safeSheet }
    $tName = ((_SIXlsx-CleanName $tName) -replace '\W','_')
    if ($tName.Length -eq 0) { $tName = 'Table' }
    # A table name must start with a letter or underscore and must not read as a cell reference.
    if ($tName -notmatch '^[A-Za-z_]' -or $tName -match '^(?i)(r|c|r\d+c\d+|r\d+|c\d+|[a-z]{1,3}\d+)$') { $tName = 'T_' + $tName }
    if ($tName.Length -gt 250) { $tName = $tName.Substring(0, 250) }
    $cand = $tName; $k = 2
    while ($tblNames.Contains($cand)) { $cand = $tName + '_' + $k; $k++ }
    $tName = $cand

    # ---- styles ----------------------------------------------------------------------------------------
    $stylesPart = $null
    foreach ($rel in $relById.Values) { if ($rel.GetAttribute('Type') -like '*/styles') { $stylesPart = _SIXlsx-ResolveTarget $wbDir $rel.GetAttribute('Target') } }
    $roles = @(0, 1, 2, 3, 4, 5)
    if (-not $existing -or -not $stylesPart) {
      if (-not $stylesPart) {
        $stylesPart = (& { if ($wbDir) { $wbDir + '/styles.xml' } else { 'styles.xml' } })
        if ($existing) {
          $k = 1; while ($relById.ContainsKey("rId$k") -or "rId$k" -eq $sheetRelId) { $k++ }
          $nr = $wbRelsDoc.CreateElement('Relationship', $script:SIXlsxNsPkg)
          $nr.SetAttribute('Id', "rId$k"); $nr.SetAttribute('Type', 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles'); $nr.SetAttribute('Target', 'styles.xml')
          [void]$wbRelsDoc.DocumentElement.AppendChild($nr)
          $ov = $ctDoc.CreateElement('Override', $script:SIXlsxNsCt)
          $ov.SetAttribute('PartName', '/' + $stylesPart); $ov.SetAttribute('ContentType', 'application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml')
          [void]$ctDoc.DocumentElement.AppendChild($ov)
        }
      }
      $writeParts[$stylesPart] = (New-Object System.Text.UTF8Encoding($false)).GetBytes($script:SIXlsxStylesXml)
    } else {
      $sb = & $readPart $stylesPart
      $stText = (New-Object System.Text.UTF8Encoding($false)).GetString($sb).TrimStart([char]0xFEFF)
      if ($stText -ne $script:SIXlsxStylesXml) {
        $stDoc = _SIXlsx-LoadXml $sb
        $roles = _SIXlsx-MergeStyles $stDoc
        $writeParts[$stylesPart] = _SIXlsx-XmlBytes $stDoc
      }
    }
    $sAttr = New-Object 'string[]' 6
    for ($i = 0; $i -lt 6; $i++) { $sAttr[$i] = if ($roles[$i] -eq 0) { '' } else { ' s="' + $roles[$i] + '"' } }

    # ---- shared strings ----------------------------------------------------------------------------------
    # One table per WORKBOOK. An existing table is kept verbatim and this sheet's strings are APPENDED
    # after it, so no index another sheet holds ever moves. Strings only a replaced sheet used stay in
    # the table, unreferenced -- harmless; Excel drops them on its next save.
    $sstPart = $null
    foreach ($rel in $relById.Values) { if ($rel.GetAttribute('Type') -like '*/sharedStrings') { $sstPart = _SIXlsx-ResolveTarget $wbDir $rel.GetAttribute('Target') } }
    $sstHead = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst xmlns="' + $script:SIXlsxNsMain + '">'
    $sstBody = ''
    $sstBase = 0
    $sstScan = $null
    if ($sstPart -and $null -ne $zin -and $null -ne $zin.GetEntry($sstPart) -and -not $partBytes.ContainsKey($sstPart)) {
      # STREAMED (a large install 2026-10-13: adding the 'Risk factors' sheet next to ~68,000 x 320 cells ran out of
      # memory -- the existing table was read as bytes, as text and as a substring, and every string matched at once).
      # Read twice as a stream: here for its head and its string count, at the write for its strings.
      $sstScan = _SIXlsx-SstScan -Zin $zin -Part $sstPart
      $sstHead = $sstScan.Head
      $sstBase = $sstScan.Count
    } elseif ($sstPart) {
      $sstText = (New-Object System.Text.UTF8Encoding($false)).GetString((& $readPart $sstPart)).TrimStart([char]0xFEFF)
      $m = [regex]::Match($sstText, '<sst\b[^>]*>')
      if (-not $m.Success) { throw "the workbook's shared-string table is not readable" }
      # count/uniqueCount are optional; dropping them beats keeping two numbers that are now wrong.
      $open = ($m.Value -replace '\s(count|uniqueCount)\s*=\s*"[^"]*"', '')
      if ($open.EndsWith('/>')) {
        $open = $open.Substring(0, $open.Length - 2).TrimEnd() + '>'
      } else {
        $close = $sstText.LastIndexOf('</sst>')
        $sstBody = $sstText.Substring($m.Index + $m.Length, $close - ($m.Index + $m.Length))
      }
      $sstHead = $sstText.Substring(0, $m.Index) + $open
      $sstBase = [regex]::Matches($sstBody, '<si[\s>/]').Count
    } else {
      $sstPart = (& { if ($wbDir) { $wbDir + '/sharedStrings.xml' } else { 'sharedStrings.xml' } })
      $usedIds = New-Object 'System.Collections.Generic.HashSet[string]'
      [void]$usedIds.Add($sheetRelId)
      foreach ($rel in $wbRelsDoc.DocumentElement.ChildNodes) { if ($rel.NodeType -eq 'Element') { [void]$usedIds.Add($rel.GetAttribute('Id')) } }
      $k = 1; while ($usedIds.Contains("rId$k")) { $k++ }
      $nr = $wbRelsDoc.CreateElement('Relationship', $script:SIXlsxNsPkg)
      $nr.SetAttribute('Id', "rId$k"); $nr.SetAttribute('Type', 'http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings')
      $nr.SetAttribute('Target', $sstPart.Substring($sstPart.LastIndexOf('/') + 1))
      [void]$wbRelsDoc.DocumentElement.AppendChild($nr)
      $ov = $ctDoc.CreateElement('Override', $script:SIXlsxNsCt)
      $ov.SetAttribute('PartName', '/' + $sstPart); $ov.SetAttribute('ContentType', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml')
      [void]$ctDoc.DocumentElement.AppendChild($ov)
    }
    $sst     = New-Object 'System.Collections.Generic.Dictionary[string,int]' ([System.StringComparer]::Ordinal)
    $sstList = New-Object 'System.Collections.Generic.List[string]'

    # ---- workbook.xml, its rels, content types ----------------------------------------------------------
    $ns = $wbDoc.CreateElement('sheet', $script:SIXlsxNsMain)
    $ns.SetAttribute('name', $safeSheet)
    $ns.SetAttribute('sheetId', [string]$sheetId)
    [void]$ns.SetAttribute('id', $script:SIXlsxNsRel, $sheetRelId)
    [void]$sheetsEl.AppendChild($ns)

    $nr = $wbRelsDoc.CreateElement('Relationship', $script:SIXlsxNsPkg)
    $nr.SetAttribute('Id', $sheetRelId); $nr.SetAttribute('Type', $script:SIXlsxRelWs)
    $relTarget = if ($wbDir -and $sheetPart.StartsWith($wbDir + '/')) { $sheetPart.Substring($wbDir.Length + 1) } else { '/' + $sheetPart }
    $nr.SetAttribute('Target', $relTarget)
    [void]$wbRelsDoc.DocumentElement.AppendChild($nr)

    foreach ($ov in @($ctDoc.DocumentElement.ChildNodes)) {
      if ($ov.NodeType -ne 'Element' -or $ov.LocalName -ne 'Override') { continue }
      if ($dropParts.Contains($ov.GetAttribute('PartName').TrimStart('/'))) { [void]$ctDoc.DocumentElement.RemoveChild($ov) }
    }
    foreach ($pair in @(@($sheetPart, $script:SIXlsxCtWs), @($tablePart, $script:SIXlsxCtTbl))) {
      $ov = $ctDoc.CreateElement('Override', $script:SIXlsxNsCt)
      $ov.SetAttribute('PartName', '/' + $pair[0]); $ov.SetAttribute('ContentType', $pair[1])
      [void]$ctDoc.DocumentElement.AppendChild($ov)
    }

    $writeParts['[Content_Types].xml'] = _SIXlsx-XmlBytes $ctDoc
    $writeParts['_rels/.rels']        = _SIXlsx-XmlBytes $rootRels
    $writeParts[$wbPart]              = _SIXlsx-XmlBytes $wbDoc
    $writeParts[$wbRelsPart]          = _SIXlsx-XmlBytes $wbRelsDoc
    $writeParts[(_SIXlsx-RelsPathFor $sheetPart)] = (New-Object System.Text.UTF8Encoding($false)).GetBytes(
      '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="' + $script:SIXlsxNsPkg + '"><Relationship Id="rId1" Type="' + $script:SIXlsxRelTbl + '" Target="../tables/' + $tablePart.Substring($tablePart.LastIndexOf('/') + 1) + '"/></Relationships>')

    # ---- table -----------------------------------------------------------------------------------------
    $lastCol = ConvertTo-SIXlsxColumnName $nCols
    # A table needs at least one data row in its range; an empty sheet gets one empty row.
    $lastRow = [Math]::Max(2, $nRows + 1)
    $ref = 'A1:' + $lastCol + $lastRow
    $tsb = New-Object System.Text.StringBuilder
    [void]$tsb.Append('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><table xmlns="').Append($script:SIXlsxNsMain)
    [void]$tsb.Append('" id="').Append($tblIdMax + 1).Append('" name="').Append($tName).Append('" displayName="').Append($tName)
    [void]$tsb.Append('" ref="').Append($ref).Append('" totalsRowShown="0"><autoFilter ref="').Append($ref).Append('"/><tableColumns count="').Append($nCols).Append('">')
    for ($i = 0; $i -lt $nCols; $i++) {
      # Line breaks in a table column name are stored escaped -- Excel's own encoding.
      $tcn = [System.Security.SecurityElement]::Escape($hdr[$i]) -replace "`r", '_x000d_' -replace "`n", '_x000a_' -replace "`t", '_x0009_'
      [void]$tsb.Append('<tableColumn id="').Append($i + 1).Append('" name="').Append($tcn).Append('"/>')
    }
    [void]$tsb.Append('</tableColumns>')
    if ($TableStyle -and $TableStyle -ne 'None') {
      $tsn = if ($TableStyle -like 'TableStyle*') { $TableStyle } else { 'TableStyle' + $TableStyle }
      [void]$tsb.Append('<tableStyleInfo name="').Append($tsn).Append('" showFirstColumn="0" showLastColumn="0" showRowStripes="1" showColumnStripes="0"/>')
    }
    [void]$tsb.Append('</table>')
    $writeParts[$tablePart] = (New-Object System.Text.UTF8Encoding($false)).GetBytes($tsb.ToString())

    # ---- write the new package ----------------------------------------------------------------------
    $level = if ($Compression -eq 'Fastest') { [System.IO.Compression.CompressionLevel]::Fastest } else { [System.IO.Compression.CompressionLevel]::Optimal }
    $fs = [System.IO.File]::Open($tmp, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite)
    try {
      $zout = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
      try {
        # [Content_Types].xml first -- not required by the spec, but what every Office writer does.
        $order = New-Object System.Collections.Generic.List[string]
        [void]$order.Add('[Content_Types].xml')
        foreach ($n in $entryNames) { if ($n -ne '[Content_Types].xml') { [void]$order.Add($n) } }
        foreach ($n in @($writeParts.Keys | Sort-Object)) { if (-not $order.Contains($n)) { [void]$order.Add($n) } }

        foreach ($n in $order) {
          if ($dropParts.Contains($n) -and -not $writeParts.ContainsKey($n)) { continue }
          if ($n -eq $sstPart) { continue }   # rewritten after the sheet, once its strings are known
          $ne = $zout.CreateEntry($n, $level)
          $os = $ne.Open()
          try {
            if ($writeParts.ContainsKey($n)) {
              $b = [byte[]]$writeParts[$n]; $os.Write($b, 0, $b.Length)
            } elseif ($partBytes.ContainsKey($n)) {
              $b = [byte[]]$partBytes[$n]; $os.Write($b, 0, $b.Length)
            } else {
              $is = $zin.GetEntry($n).Open(); try { $is.CopyTo($os) } finally { $is.Close() }
            }
          } finally { $os.Close() }
        }

        # ---- the worksheet itself: streamed ----------------------------------------------------------
        $ne = $zout.CreateEntry($sheetPart, $level)
        $os = $ne.Open()
        $sw = New-Object System.IO.StreamWriter($os, (New-Object System.Text.UTF8Encoding($false)), 65536)
        try {
          $sw.Write('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="' + $script:SIXlsxNsMain + '" xmlns:r="' + $script:SIXlsxNsRel + '">')
          $sw.Write('<dimension ref="A1:' + $lastCol + [Math]::Max(1, $nRows + 1) + '"/>')
          $sw.Write('<sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/><selection pane="bottomLeft" activeCell="A2" sqref="A2"/></sheetView></sheetViews>')
          $sw.Write('<sheetFormatPr defaultRowHeight="15"/><cols>')

          # Per-column prefixes, built once: the per-cell work is then one concatenation and one Write.
          $cOpen  = New-Object 'string[]' $nCols   # '<c r="AB'
          $tStr   = New-Object 'string[]' $nCols   # '" s=".." t="s"><v>'
          $tNum   = New-Object 'string[]' $nCols   # '" s=".."><v>'
          $tDate  = New-Object 'string[]' $nCols
          $tBool  = New-Object 'string[]' $nCols
          for ($i = 0; $i -lt $nCols; $i++) {
            $wrap = $wrapSet.Contains($hdr[$i])
            $cOpen[$i] = '<c r="' + (ConvertTo-SIXlsxColumnName ($i + 1))
            $sTxt = if ($wrap) { $sAttr[2] } else { $sAttr[0] }
            $sDt  = if ($wrap) { $sAttr[5] } else { $sAttr[4] }
            $tStr[$i]  = '"' + $sTxt + ' t="s"><v>'
            $tNum[$i]  = '"' + $sTxt + '><v>'
            $tDate[$i] = '"' + $sDt + '><v>'
            $tBool[$i] = '"' + $sTxt + ' t="b"><v>'
            $colStyle = ''
            if ($isDate[$i]) { $colStyle = ' style="' + $(if ($wrap) { $roles[5] } else { $roles[4] }) + '"' }
            elseif ($wrap)    { $colStyle = ' style="' + $roles[2] + '"' }
            $sw.Write('<col min="' + ($i + 1) + '" max="' + ($i + 1) + '" width="' + $widths[$i].ToString('0.##', $inv) + '" customWidth="1"' + $colStyle + '/>')
          }
          $sw.Write('</cols><sheetData><row r="1">')
          for ($i = 0; $i -lt $nCols; $i++) {
            $sH = if ($wrapSet.Contains($hdr[$i])) { $sAttr[3] } else { $sAttr[1] }
            $sw.Write($cOpen[$i] + '1"' + $sH + ' t="s"><v>' + (_SIXlsx-SstIdPS $hdr[$i] $sst $sstList $sstBase).ToString($inv) + '</v></c>')
          }
          $sw.Write('</row>')

          # THE HOT LOOP -- one string per cell, in the compiled helper or its PowerShell twin. Numbers
          # go out invariant ('R' for double: the shortest round-trip form), so a comma-decimal host
          # locale cannot turn 9.8 into 98.
          if ($null -ne $nt) { $nt::WriteRows($sw, $dataRows, $nCols, $cOpen, $tStr, $tNum, $tDate, $tBool, $sst, $sstList, $sstBase) }
          else { _SIXlsx-WriteRowsPS -Writer $sw -Rows $dataRows -NCols $nCols -COpen $cOpen -TStr $tStr -TNum $tNum -TDate $tDate -TBool $tBool -Sst $sst -SstList $sstList -SstBase $sstBase }
          if ($nRows -eq 0) { $sw.Write('<row r="2"/>') }
          $sw.Write('</sheetData><pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/><tableParts count="1"><tablePart r:id="rId1"/></tableParts></worksheet>')
        } finally { $sw.Close() }

        # ---- shared strings: what was there, then this sheet's new strings ------------------------------
        $ne = $zout.CreateEntry($sstPart, $level)
        $sw = New-Object System.IO.StreamWriter($ne.Open(), (New-Object System.Text.UTF8Encoding($false)), 65536)
        try {
          $sw.Write($sstHead)
          if ($null -ne $sstScan) { _SIXlsx-SstCopyBody -Zin $zin -Part $sstPart -Start $sstScan.BodyStart -Length $sstScan.BodyLength -Writer $sw }
          else { $sw.Write($sstBody) }
          if ($null -ne $nt) { $nt::WriteSst($sw, $sstList) } else { _SIXlsx-WriteSstPS -Writer $sw -SstList $sstList }
          $sw.Write('</sst>')
        } finally { $sw.Close() }
      } finally { $zout.Dispose() }
    } finally { $fs.Close() }
  } catch {
    if ($null -ne $zin) { $zin.Dispose(); $zin = $null }
    if ([System.IO.File]::Exists($tmp)) { try { [System.IO.File]::Delete($tmp) } catch { } }
    throw
  } finally {
    if ($null -ne $zin) { $zin.Dispose() }
  }

  # Replace the real workbook only now that the new one is complete on disk.
  if ([System.IO.File]::Exists($fullPath)) { [System.IO.File]::Delete($fullPath) }
  [System.IO.File]::Move($tmp, $fullPath)
}

function Read-SIXlsxWorksheet {
  <#
  .SYNOPSIS
    Read one worksheet back: header, typed values, column widths/styles. The verification half of the
    writer -- used by the tests and handy for a quick look at a report without Excel.

  .DESCRIPTION
    Returns [pscustomobject]@{ Name; Header; Rows; Cells; Columns; Table; Frozen; Raw }. Rows are
    pscustomobjects keyed by the header (like Import-Excel). Cells is a hashtable 'B7' -> @{ Value;
    Type; Style; NumFmt; Bold; Wrap; VAlign }. Values come back typed: number -> [double], a number
    whose format is a date -> [datetime], boolean -> [bool], text -> [string]. Handles shared AND
    inline strings, so it reads workbooks written by Excel or EPPlus as well.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$SheetName
  )
  Add-Type -AssemblyName System.IO.Compression            -ErrorAction Stop
  Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
  $fullPath = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { [System.IO.Path]::Combine((Get-Location).Path, $Path) }
  $z = [System.IO.Compression.ZipFile]::OpenRead($fullPath)
  try {
    $get = {
      param($n)
      $e = $z.GetEntry($n); if ($null -eq $e) { return $null }
      $ms = New-Object System.IO.MemoryStream; $s = $e.Open(); try { $s.CopyTo($ms) } finally { $s.Close() }
      return (_SIXlsx-LoadXml $ms.ToArray())
    }
    $rootRels = & $get '_rels/.rels'
    $wbPart = $null
    foreach ($rel in $rootRels.DocumentElement.ChildNodes) { if ($rel.NodeType -eq 'Element' -and $rel.GetAttribute('Type') -like '*/officeDocument') { $wbPart = _SIXlsx-ResolveTarget '' $rel.GetAttribute('Target') } }
    $wb = & $get $wbPart
    $wbRels = & $get (_SIXlsx-RelsPathFor $wbPart)
    $wbDir = _SIXlsx-DirOf $wbPart
    $ns = New-Object System.Xml.XmlNamespaceManager($wb.NameTable); $ns.AddNamespace('m', $script:SIXlsxNsMain)
    $relT = @{}; $sstPart = $null; $stylesPart = $null
    foreach ($rel in $wbRels.DocumentElement.ChildNodes) {
      if ($rel.NodeType -ne 'Element') { continue }
      $t = _SIXlsx-ResolveTarget $wbDir $rel.GetAttribute('Target')
      $relT[$rel.GetAttribute('Id')] = $t
      if ($rel.GetAttribute('Type') -like '*/sharedStrings') { $sstPart = $t }
      if ($rel.GetAttribute('Type') -like '*/styles') { $stylesPart = $t }
    }
    $sheetEl = $null
    foreach ($sn in $wb.DocumentElement.SelectNodes('m:sheets/m:sheet', $ns)) {
      if (-not $SheetName -or [string]::Equals($sn.GetAttribute('name'), $SheetName, [System.StringComparison]::OrdinalIgnoreCase)) { $sheetEl = $sn; break }
    }
    if ($null -eq $sheetEl) { throw "sheet '$SheetName' not found in $Path" }
    $sheetPart = $relT[$sheetEl.GetAttribute('id', $script:SIXlsxNsRel)]

    # shared strings
    $sst = New-Object System.Collections.Generic.List[string]
    if ($sstPart) {
      $sd = & $get $sstPart
      $sns = New-Object System.Xml.XmlNamespaceManager($sd.NameTable); $sns.AddNamespace('m', $script:SIXlsxNsMain)
      foreach ($si in $sd.DocumentElement.SelectNodes('m:si', $sns)) {
        $txt = ''; foreach ($t in $si.SelectNodes('.//m:t', $sns)) { $txt += $t.InnerText }
        [void]$sst.Add($txt)
      }
    }
    # styles -> per xf: numFmt, bold, wrap, valign
    $xfs = New-Object System.Collections.Generic.List[object]
    if ($stylesPart) {
      $st = & $get $stylesPart
      $tns = New-Object System.Xml.XmlNamespaceManager($st.NameTable); $tns.AddNamespace('m', $script:SIXlsxNsMain)
      $fmts = @{}; foreach ($f in $st.DocumentElement.SelectNodes('m:numFmts/m:numFmt', $tns)) { $fmts[[int]$f.GetAttribute('numFmtId')] = $f.GetAttribute('formatCode') }
      $fonts = @($st.DocumentElement.SelectNodes('m:fonts/m:font', $tns))
      foreach ($xf in $st.DocumentElement.SelectNodes('m:cellXfs/m:xf', $tns)) {
        $nf = [int]$xf.GetAttribute('numFmtId'); $fid = [int]$xf.GetAttribute('fontId')
        $al = $xf.SelectSingleNode('m:alignment', $tns)
        $code = if ($fmts.ContainsKey($nf)) { $fmts[$nf] } else { '' }
        $isDate = ($nf -ge 14 -and $nf -le 22) -or ($code -match '[yd]' -and $code -notmatch '^\[')
        [void]$xfs.Add([pscustomobject]@{
          NumFmt = $code; IsDate = $isDate
          Bold   = ($fid -lt $fonts.Count -and $null -ne $fonts[$fid].SelectSingleNode('m:b', $tns))
          Wrap   = ($null -ne $al -and $al.GetAttribute('wrapText') -eq '1')
          VAlign = $(if ($null -ne $al) { $al.GetAttribute('vertical') } else { '' })
        })
      }
    }
    $ws = & $get $sheetPart
    $wns = New-Object System.Xml.XmlNamespaceManager($ws.NameTable); $wns.AddNamespace('m', $script:SIXlsxNsMain)
    $cells = @{}
    $maxRow = 0; $maxCol = 0
    foreach ($c in $ws.DocumentElement.SelectNodes('m:sheetData/m:row/m:c', $wns)) {
      $ref = $c.GetAttribute('r')
      $m = [regex]::Match($ref, '^([A-Z]+)(\d+)$')
      $colN = 0; foreach ($ch in $m.Groups[1].Value.ToCharArray()) { $colN = $colN * 26 + ([int]$ch - 64) }
      $rowN = [int]$m.Groups[2].Value
      if ($rowN -gt $maxRow) { $maxRow = $rowN }; if ($colN -gt $maxCol) { $maxCol = $colN }
      $t = $c.GetAttribute('t'); $s = 0; if ($c.HasAttribute('s')) { $s = [int]$c.GetAttribute('s') }
      $xf = if ($s -lt $xfs.Count) { $xfs[$s] } else { $null }
      $vNode = $c.SelectSingleNode('m:v', $wns)
      $val = $null
      switch ($t) {
        's'         { $val = $sst[[int]$vNode.InnerText] }
        'inlineStr' { $val = ''; foreach ($tn in $c.SelectNodes('m:is//m:t', $wns)) { $val += $tn.InnerText } }
        'str'       { $val = $vNode.InnerText }
        'b'         { $val = ($vNode.InnerText -eq '1') }
        default {
          if ($null -ne $vNode) {
            $val = [double]::Parse($vNode.InnerText, [System.Globalization.CultureInfo]::InvariantCulture)
            if ($null -ne $xf -and $xf.IsDate) { $val = [datetime]::FromOADate($val) }
          }
        }
      }
      $cells[$ref] = [pscustomobject]@{
        Value = $val; Type = $t; Style = $s; Row = $rowN; Col = $colN
        NumFmt = $(if ($xf) { $xf.NumFmt } else { '' }); Bold = ($xf -and $xf.Bold); Wrap = ($xf -and $xf.Wrap)
        VAlign = $(if ($xf) { $xf.VAlign } else { '' })
      }
    }
    $header = New-Object System.Collections.Generic.List[string]
    for ($ci = 1; $ci -le $maxCol; $ci++) {
      $hc = $cells[(ConvertTo-SIXlsxColumnName $ci) + '1']
      [void]$header.Add($(if ($hc) { [string]$hc.Value } else { '' }))
    }
    $rows = New-Object System.Collections.Generic.List[object]
    for ($ri = 2; $ri -le $maxRow; $ri++) {
      $o = [ordered]@{}; $any = $false
      for ($ci = 1; $ci -le $maxCol; $ci++) {
        $cc = $cells[(ConvertTo-SIXlsxColumnName $ci) + $ri]
        $o[$header[$ci - 1]] = $(if ($cc) { $any = $true; $cc.Value } else { $null })
      }
      if ($any) { [void]$rows.Add([pscustomobject]$o) }
    }
    $cols = @{}
    foreach ($col in $ws.DocumentElement.SelectNodes('m:cols/m:col', $wns)) {
      # A column with no style attribute is unstyled -- reported as such, not as whatever xf 0 says.
      $xf = $null
      if ($col.HasAttribute('style')) { $st2 = [int]$col.GetAttribute('style'); if ($st2 -lt $xfs.Count) { $xf = $xfs[$st2] } }
      for ($ci = [int]$col.GetAttribute('min'); $ci -le [int]$col.GetAttribute('max'); $ci++) {
        $cols[$ci] = [pscustomobject]@{
          Width = [double]::Parse($col.GetAttribute('width'), [System.Globalization.CultureInfo]::InvariantCulture)
          Wrap = ($xf -and $xf.Wrap); VAlign = $(if ($xf) { $xf.VAlign } else { '' })
        }
      }
    }
    $table = $null
    $sheetRels = & $get (_SIXlsx-RelsPathFor $sheetPart)
    if ($null -ne $sheetRels) {
      foreach ($rel in $sheetRels.DocumentElement.ChildNodes) {
        if ($rel.NodeType -eq 'Element' -and $rel.GetAttribute('Type') -like '*/table') {
          $td = & $get (_SIXlsx-ResolveTarget (_SIXlsx-DirOf $sheetPart) $rel.GetAttribute('Target'))
          $tns2 = New-Object System.Xml.XmlNamespaceManager($td.NameTable); $tns2.AddNamespace('m', $script:SIXlsxNsMain)
          $si2 = $td.DocumentElement.SelectSingleNode('m:tableStyleInfo', $tns2)
          $table = [pscustomobject]@{
            Name = $td.DocumentElement.GetAttribute('name'); Ref = $td.DocumentElement.GetAttribute('ref')
            AutoFilter = ($null -ne $td.DocumentElement.SelectSingleNode('m:autoFilter', $tns2))
            Style = $(if ($si2) { $si2.GetAttribute('name') } else { '' })
            Columns = @($td.DocumentElement.SelectNodes('m:tableColumns/m:tableColumn', $tns2) | ForEach-Object { $_.GetAttribute('name') })
          }
        }
      }
    }
    $pane = $ws.DocumentElement.SelectSingleNode('m:sheetViews/m:sheetView/m:pane', $wns)
    return [pscustomobject]@{
      Name    = $sheetEl.GetAttribute('name')
      Header  = $header.ToArray()
      Rows    = $rows.ToArray()
      Cells   = $cells
      Columns = $cols
      Table   = $table
      Frozen  = ($null -ne $pane -and $pane.GetAttribute('state') -eq 'frozen' -and $pane.GetAttribute('ySplit') -eq '1')
      RowCount = $maxRow
    }
  } finally { $z.Dispose() }
}

function Get-SIXlsxSheetNames {
  # Sheet names of a workbook, in tab order.
  param([Parameter(Mandatory)][string]$Path)
  Add-Type -AssemblyName System.IO.Compression            -ErrorAction Stop
  Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
  $z = [System.IO.Compression.ZipFile]::OpenRead($Path)
  try {
    $read = { param($n) $ms = New-Object System.IO.MemoryStream; $s = $z.GetEntry($n).Open(); try { $s.CopyTo($ms) } finally { $s.Close() }; _SIXlsx-LoadXml $ms.ToArray() }
    $rr = & $read '_rels/.rels'
    $wbPart = $null
    foreach ($rel in $rr.DocumentElement.ChildNodes) { if ($rel.NodeType -eq 'Element' -and $rel.GetAttribute('Type') -like '*/officeDocument') { $wbPart = _SIXlsx-ResolveTarget '' $rel.GetAttribute('Target') } }
    $wb = & $read $wbPart
    $ns = New-Object System.Xml.XmlNamespaceManager($wb.NameTable); $ns.AddNamespace('m', $script:SIXlsxNsMain)
    return @($wb.DocumentElement.SelectNodes('m:sheets/m:sheet', $ns) | ForEach-Object { $_.GetAttribute('name') })
  } finally { $z.Dispose() }
}
