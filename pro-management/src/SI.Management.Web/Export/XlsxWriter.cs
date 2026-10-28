using System.Globalization;
using System.IO.Compression;
using System.Text;
using System.Xml;

namespace SI.Management.Web.Export;

/// <summary>
/// The web app's one Excel (.xlsx) writer: a forward-only SpreadsheetML package written straight into a zip stream
/// (System.IO.Compression + XmlWriter, no third-party package). It looks like SecurityInsight's Risk Analysis workbook:
/// a bold, frozen header row; every sheet one Excel table with autofilter (TableStyleMedium9); column widths from the
/// content (8..50); numbers as numbers, dates as real dates (yyyy-mm-dd hh:mm:ss), booleans as booleans.
/// <para>Streaming: cells are inline strings (no shared-string table to hold), and a sheet keeps at most
/// <see cref="WidthSampleRows"/> rows in memory -- to size its columns -- before every further row goes straight out.</para>
/// <para>Safety: text is cleaned of control characters and lone surrogates and cut at Excel's 32,767-character cell limit
/// with <see cref="TruncationMarker"/>; a text cell is always an inline string, never a formula, and one that starts
/// with = + - @ also carries Excel's quote prefix, so editing it in Excel does not turn it into a formula either.</para>
/// </summary>
public sealed class XlsxWriter : IDisposable
{
    public const string ContentType = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    public const int MaxCellText = 32_767;
    public const string TruncationMarker = "… [truncated]";
    public const int MinWidth = 8;
    public const int MaxWidth = 50;
    public const int MaxSheetName = 31;
    public const int WidthSampleRows = 1_000;
    public const int MaxRows = 1_048_576;
    public const string TableStyle = "TableStyleMedium9";
    public const string DateFormat = "yyyy-mm-dd hh:mm:ss";

    // cellXfs indexes in styles.xml
    internal const int StyleHeader = 1;
    internal const int StyleDate = 2;
    internal const int StyleQuoted = 3;

    internal const string NsMain = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    internal const string NsRel = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    private const string NsPkgRel = "http://schemas.openxmlformats.org/package/2006/relationships";

    private readonly ZipArchive _zip;
    private readonly List<string> _sheets = new();
    private readonly HashSet<string> _names = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _title;
    private readonly DateTime _created;
    private SheetWriter? _open;
    private bool _completed;

    /// <param name="output">Any writable stream; it need not be seekable. It is left open.</param>
    public XlsxWriter(Stream output, string title = "SecurityInsight", DateTime? createdUtc = null)
    {
        _zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true, Encoding.UTF8);
        _title = Clean(title);
        _created = createdUtc ?? DateTime.UtcNow;
    }

    public IReadOnlyList<string> SheetNames => _sheets;

    /// Starts a sheet. The previous one must be disposed (completed) first; the name is made a legal, unique sheet name.
    public SheetWriter AddSheet(string name, IReadOnlyList<string> headers)
    {
        if (_completed) throw new InvalidOperationException("the workbook is complete");
        if (_open is not null) throw new InvalidOperationException($"the sheet '{_open.Name}' is still open");
        if (headers.Count == 0) throw new ArgumentException("a sheet needs at least one column", nameof(headers));
        if (headers.Count > 16_384) throw new ArgumentException("Excel has at most 16,384 columns", nameof(headers));
        var safe = SheetName(name, _names);
        _names.Add(safe);
        _sheets.Add(safe);
        _open = new SheetWriter(this, _sheets.Count, safe, Headers(headers));
        return _open;
    }

    /// One whole sheet from a sequence of rows (consumed once, as it is enumerated).
    public void WriteSheet(string name, IReadOnlyList<string> headers, IEnumerable<IReadOnlyList<object?>> rows)
    {
        using var s = AddSheet(name, headers);
        foreach (var r in rows) s.WriteRow(r);
    }

    internal ZipArchiveEntry Entry(string path) => _zip.CreateEntry(path, CompressionLevel.Fastest);

    internal void Closed(SheetWriter s) { if (ReferenceEquals(_open, s)) _open = null; }

    /// Writes the workbook, styles, relationships and content types. Without it the package is not a workbook.
    public void Complete()
    {
        if (_completed) return;
        if (_open is not null) _open.Dispose();
        if (_sheets.Count == 0) throw new InvalidOperationException("a workbook needs at least one sheet");
        _completed = true;

        Xml("xl/workbook.xml", w =>
        {
            w.WriteStartElement("workbook", NsMain);
            w.WriteAttributeString("xmlns", "r", null, NsRel);
            w.WriteStartElement("bookViews", NsMain);
            w.WriteStartElement("workbookView", NsMain); w.WriteAttributeString("activeTab", "0"); w.WriteEndElement();
            w.WriteEndElement();
            w.WriteStartElement("sheets", NsMain);
            for (var i = 0; i < _sheets.Count; i++)
            {
                w.WriteStartElement("sheet", NsMain);
                w.WriteAttributeString("name", _sheets[i]);
                w.WriteAttributeString("sheetId", Num(i + 1));
                w.WriteAttributeString("id", NsRel, "rId" + Num(i + 1));
                w.WriteEndElement();
            }
            w.WriteEndElement();
            w.WriteEndElement();
        });
        Xml("xl/_rels/workbook.xml.rels", w =>
        {
            w.WriteStartElement("Relationships", NsPkgRel);
            for (var i = 0; i < _sheets.Count; i++)
                Rel(w, "rId" + Num(i + 1), NsRel + "/worksheet", $"worksheets/sheet{i + 1}.xml");
            Rel(w, "rId" + Num(_sheets.Count + 1), NsRel + "/styles", "styles.xml");
            w.WriteEndElement();
        });
        Raw("xl/styles.xml", Styles);
        Xml("_rels/.rels", w =>
        {
            w.WriteStartElement("Relationships", NsPkgRel);
            Rel(w, "rId1", NsRel + "/officeDocument", "xl/workbook.xml");
            Rel(w, "rId2", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties", "docProps/core.xml");
            w.WriteEndElement();
        });
        Xml("docProps/core.xml", w =>
        {
            const string cp = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties";
            const string dc = "http://purl.org/dc/elements/1.1/";
            const string dcterms = "http://purl.org/dc/terms/";
            const string xsi = "http://www.w3.org/2001/XMLSchema-instance";
            w.WriteStartElement("cp", "coreProperties", cp);
            w.WriteAttributeString("xmlns", "dc", null, dc);
            w.WriteAttributeString("xmlns", "dcterms", null, dcterms);
            w.WriteAttributeString("xmlns", "xsi", null, xsi);
            w.WriteElementString("title", dc, _title);
            w.WriteElementString("creator", dc, "SecurityInsight Pro");
            w.WriteStartElement("dcterms", "created", dcterms);
            w.WriteAttributeString("type", xsi, "dcterms:W3CDTF");
            w.WriteString(_created.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture));
            w.WriteEndElement();
            w.WriteEndElement();
        });
        Xml("[Content_Types].xml", w =>
        {
            const string ct = "http://schemas.openxmlformats.org/package/2006/content-types";
            w.WriteStartElement("Types", ct);
            void Default(string ext, string type) { w.WriteStartElement("Default", ct); w.WriteAttributeString("Extension", ext); w.WriteAttributeString("ContentType", type); w.WriteEndElement(); }
            void Override(string part, string type) { w.WriteStartElement("Override", ct); w.WriteAttributeString("PartName", part); w.WriteAttributeString("ContentType", type); w.WriteEndElement(); }
            Default("rels", "application/vnd.openxmlformats-package.relationships+xml");
            Default("xml", "application/xml");
            Override("/xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml");
            Override("/xl/styles.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml");
            Override("/docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml");
            for (var i = 1; i <= _sheets.Count; i++)
            {
                Override($"/xl/worksheets/sheet{i}.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml");
                Override($"/xl/tables/table{i}.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml");
            }
            w.WriteEndElement();
        });
    }

    public void Dispose()
    {
        // an incomplete workbook is not "repaired" into a valid-looking one: only Complete() writes the workbook part
        _open?.Abandon();
        _zip.Dispose();
    }

    // ---- package helpers -------------------------------------------------------------------------------------------

    internal static XmlWriterSettings XmlSettings => new()
    {
        Encoding = new UTF8Encoding(false),
        Indent = false,
        NewLineHandling = NewLineHandling.Entitize,   // a \r in a cell survives as &#xD;
        CloseOutput = true,
    };

    private void Xml(string path, Action<XmlWriter> body)
    {
        using var w = XmlWriter.Create(Entry(path).Open(), XmlSettings);
        w.WriteStartDocument(true);
        body(w);
        w.WriteEndDocument();
    }

    private void Raw(string path, string xml)
    {
        using var s = Entry(path).Open();
        var b = new UTF8Encoding(false).GetBytes(xml);
        s.Write(b, 0, b.Length);
    }

    private static void Rel(XmlWriter w, string id, string type, string target)
    {
        w.WriteStartElement("Relationship", NsPkgRel);
        w.WriteAttributeString("Id", id);
        w.WriteAttributeString("Type", type);
        w.WriteAttributeString("Target", target);
        w.WriteEndElement();
    }

    internal static string Num(long v) => v.ToString(CultureInfo.InvariantCulture);

    private const string Styles = """
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm:ss"/></numFmts><fonts count="2"><font><sz val="11"/><name val="Calibri"/><family val="2"/></font><font><b/><sz val="11"/><name val="Calibri"/><family val="2"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="4"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/><xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" quotePrefix="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>
""";

    // ---- text and name rules ---------------------------------------------------------------------------------------

    /// Removes what Excel / XML cannot hold (C0 and C1 control characters except tab, line feed and carriage return;
    /// U+FFFE/U+FFFF; lone surrogates) and cuts the text at <see cref="MaxCellText"/> with <see cref="TruncationMarker"/>.
    public static string Clean(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        StringBuilder? sb = null;
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            bool keep; var pair = false;
            if (char.IsHighSurrogate(c)) { pair = i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]); keep = pair; }
            else if (char.IsLowSurrogate(c)) keep = false;
            else if (c < 0x20) keep = c is '\t' or '\n' or '\r';
            else if (c is >= '\u007F' and <= '\u009F') keep = false;
            else keep = c is not ('￾' or '￿');
            if (keep && sb is null) { if (pair) i++; continue; }
            if (sb is null) { sb = new StringBuilder(s.Length); sb.Append(s, 0, i); }
            if (keep) { sb.Append(c); if (pair) { sb.Append(s[i + 1]); i++; } }
        }
        var r = sb?.ToString() ?? s;
        if (r.Length <= MaxCellText) return r;
        var cut = MaxCellText - TruncationMarker.Length;
        if (char.IsHighSurrogate(r[cut - 1])) cut--;
        return r[..cut] + TruncationMarker;
    }

    /// A legal Excel sheet name: at most 31 characters, none of [ ] : * ? / \, not starting or ending with an apostrophe,
    /// not empty, not the reserved "History", and unique (case-insensitive) among <paramref name="taken"/>.
    public static string SheetName(string? name, ICollection<string>? taken = null)
    {
        var sb = new StringBuilder();
        foreach (var c in Clean(name)) sb.Append(c is '[' or ']' or ':' or '*' or '?' or '/' or '\\' ? '_' : c is '\t' or '\n' or '\r' ? ' ' : c);
        var s = Fit(sb.ToString().Trim(), MaxSheetName);
        if (s.Length == 0) s = "Sheet";
        if (s.Equals("History", StringComparison.OrdinalIgnoreCase)) s += "_";
        if (taken is null || !taken.Contains(s)) return s;
        for (var n = 2; ; n++)
        {
            var suffix = $" ({n})";
            var candidate = Fit(s, MaxSheetName - suffix.Length) + suffix;
            if (!taken.Contains(candidate)) return candidate;
        }
    }

    private static string Fit(string s, int max)
    {
        if (s.Length > max) s = s[..(char.IsHighSurrogate(s[max - 1]) ? max - 1 : max)];
        return s.Trim().Trim('\'').Trim();
    }

    /// Header texts as table column names: cleaned, one line, not empty, unique (case-insensitive).
    internal static string[] Headers(IReadOnlyList<string> headers)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var r = new string[headers.Count];
        for (var i = 0; i < headers.Count; i++)
        {
            var h = Clean(headers[i]).Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ').Trim();
            if (h.Length > 255) h = h[..255];
            if (h.Length == 0) h = "Column" + (i + 1).ToString(CultureInfo.InvariantCulture);
            var u = h;
            for (var n = 2; !seen.Add(u); n++) u = h + " (" + n.ToString(CultureInfo.InvariantCulture) + ")";
            r[i] = u;
        }
        return r;
    }

    /// A1-style column letters (0 -> A, 25 -> Z, 26 -> AA).
    public static string Column(int index)
    {
        var s = "";
        for (var n = index + 1; n > 0; n = (n - 1) / 26) s = (char)('A' + (n - 1) % 26) + s;
        return s;
    }
}

/// <summary>One sheet being written: rows go in with <see cref="WriteRow(IReadOnlyList{object?})"/>; Dispose ends the
/// sheet (and writes its table part).</summary>
public sealed class SheetWriter : IDisposable
{
    private enum Kind { Empty, Text, Number, Bool, Date }
    private readonly record struct Cell(Kind Kind, string? Text, double Number);

    private readonly XlsxWriter _book;
    private readonly int _index;
    private readonly string[] _headers;
    private readonly int[] _widths;
    private List<Cell[]>? _buffer = new();
    private XmlWriter? _xml;
    private long _rows;
    private bool _done;

    internal SheetWriter(XlsxWriter book, int index, string name, string[] headers)
    {
        _book = book; _index = index; Name = name; _headers = headers;
        _widths = headers.Select(h => h.Length + 3).ToArray();   // + room for the filter button
    }

    public string Name { get; }
    public IReadOnlyList<string> Headers => _headers;
    /// Data rows written so far (the header row not counted).
    public long RowCount => _rows;

    public void WriteRow(params object?[] cells) => WriteRow((IReadOnlyList<object?>)cells);

    public void WriteRow(IReadOnlyList<object?> values)
    {
        if (_done) throw new InvalidOperationException($"the sheet '{Name}' is complete");
        if (_rows + 2 > XlsxWriter.MaxRows) throw new InvalidOperationException($"the sheet '{Name}' is full (Excel's {XlsxWriter.MaxRows:N0} rows)");
        var row = new Cell[_headers.Length];
        for (var i = 0; i < row.Length; i++)
        {
            row[i] = Convert(i < values.Count ? values[i] : null);
            if (_buffer is not null) _widths[i] = Math.Max(_widths[i], Width(row[i]));
        }
        _rows++;
        if (_buffer is not null)
        {
            _buffer.Add(row);
            if (_buffer.Count >= XlsxWriter.WidthSampleRows) Flush();
        }
        else Row(row, _rows + 1);
    }

    /// The widths decided from the header and the first rows: written once, before the first row, then the buffer goes.
    private void Flush()
    {
        if (_buffer is null) return;
        var w = _xml = XmlWriter.Create(_book.Entry($"xl/worksheets/sheet{_index}.xml").Open(), XlsxWriter.XmlSettings);
        w.WriteStartDocument(true);
        w.WriteStartElement("worksheet", XlsxWriter.NsMain);
        w.WriteAttributeString("xmlns", "r", null, XlsxWriter.NsRel);
        w.WriteStartElement("sheetViews", XlsxWriter.NsMain);
        w.WriteStartElement("sheetView", XlsxWriter.NsMain);
        if (_index == 1) w.WriteAttributeString("tabSelected", "1");
        w.WriteAttributeString("workbookViewId", "0");
        w.WriteStartElement("pane", XlsxWriter.NsMain);
        w.WriteAttributeString("ySplit", "1"); w.WriteAttributeString("topLeftCell", "A2");
        w.WriteAttributeString("activePane", "bottomLeft"); w.WriteAttributeString("state", "frozen");
        w.WriteEndElement();
        w.WriteStartElement("selection", XlsxWriter.NsMain);
        w.WriteAttributeString("pane", "bottomLeft"); w.WriteAttributeString("activeCell", "A2"); w.WriteAttributeString("sqref", "A2");
        w.WriteEndElement();
        w.WriteEndElement();
        w.WriteEndElement();
        w.WriteStartElement("sheetFormatPr", XlsxWriter.NsMain); w.WriteAttributeString("defaultRowHeight", "15"); w.WriteEndElement();
        w.WriteStartElement("cols", XlsxWriter.NsMain);
        for (var i = 0; i < _headers.Length; i++)
        {
            w.WriteStartElement("col", XlsxWriter.NsMain);
            w.WriteAttributeString("min", XlsxWriter.Num(i + 1)); w.WriteAttributeString("max", XlsxWriter.Num(i + 1));
            w.WriteAttributeString("width", XlsxWriter.Num(Math.Clamp(_widths[i], XlsxWriter.MinWidth, XlsxWriter.MaxWidth)));
            w.WriteAttributeString("customWidth", "1");
            w.WriteEndElement();
        }
        w.WriteEndElement();
        w.WriteStartElement("sheetData", XlsxWriter.NsMain);
        w.WriteStartElement("row", XlsxWriter.NsMain);
        w.WriteAttributeString("r", "1");
        for (var i = 0; i < _headers.Length; i++) Text(w, XlsxWriter.Column(i) + "1", _headers[i], XlsxWriter.StyleHeader);
        w.WriteEndElement();
        var buffered = _buffer;
        _buffer = null;
        for (var i = 0; i < buffered.Count; i++) Row(buffered[i], i + 2);
    }

    private void Row(Cell[] row, long r)
    {
        var w = _xml!;
        var rr = XlsxWriter.Num(r);
        w.WriteStartElement("row", XlsxWriter.NsMain);
        w.WriteAttributeString("r", rr);
        for (var i = 0; i < row.Length; i++)
        {
            var c = row[i];
            if (c.Kind == Kind.Empty) continue;
            var at = XlsxWriter.Column(i) + rr;
            switch (c.Kind)
            {
                case Kind.Text:
                    Text(w, at, c.Text!, c.Text!.Length > 0 && c.Text[0] is '=' or '+' or '-' or '@' ? XlsxWriter.StyleQuoted : 0);
                    break;
                case Kind.Bool:
                    w.WriteStartElement("c", XlsxWriter.NsMain);
                    w.WriteAttributeString("r", at); w.WriteAttributeString("t", "b");
                    w.WriteElementString("v", XlsxWriter.NsMain, c.Number != 0 ? "1" : "0");
                    w.WriteEndElement();
                    break;
                default:
                    w.WriteStartElement("c", XlsxWriter.NsMain);
                    w.WriteAttributeString("r", at);
                    if (c.Kind == Kind.Date) w.WriteAttributeString("s", XlsxWriter.Num(XlsxWriter.StyleDate));
                    w.WriteElementString("v", XlsxWriter.NsMain, c.Number.ToString("R", CultureInfo.InvariantCulture));
                    w.WriteEndElement();
                    break;
            }
        }
        w.WriteEndElement();
    }

    /// Always an inline string: a text cell is never a formula, whatever it starts with.
    private static void Text(XmlWriter w, string at, string text, int style)
    {
        w.WriteStartElement("c", XlsxWriter.NsMain);
        w.WriteAttributeString("r", at);
        if (style != 0) w.WriteAttributeString("s", XlsxWriter.Num(style));
        w.WriteAttributeString("t", "inlineStr");
        w.WriteStartElement("is", XlsxWriter.NsMain);
        w.WriteStartElement("t", XlsxWriter.NsMain);
        if (text.Length > 0 && (char.IsWhiteSpace(text[0]) || char.IsWhiteSpace(text[^1]) || text.Contains('\n'))) w.WriteAttributeString("xml", "space", null, "preserve");
        w.WriteString(text);
        w.WriteEndElement();
        w.WriteEndElement();
        w.WriteEndElement();
    }

    private static readonly DateTime MinDate = new(1900, 3, 1);

    private static Cell Convert(object? v)
    {
        switch (v)
        {
            case null or DBNull: return default;
            case string s: return s.Length == 0 ? default : new Cell(Kind.Text, XlsxWriter.Clean(s), 0);
            case bool b: return new Cell(Kind.Bool, null, b ? 1 : 0);
            case DateTime d: return Date(d.Kind == DateTimeKind.Local ? d.ToUniversalTime() : d);
            case DateTimeOffset o: return Date(o.UtcDateTime);
            case DateOnly d: return Date(d.ToDateTime(TimeOnly.MinValue));
            case byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal:
                var n = System.Convert.ToDouble(v, CultureInfo.InvariantCulture);
                return double.IsFinite(n) ? new Cell(Kind.Number, null, n) : new Cell(Kind.Text, n.ToString(CultureInfo.InvariantCulture), 0);
            case IFormattable f: return Str(f.ToString(null, CultureInfo.InvariantCulture));
            default: return Str(v.ToString());
        }
        static Cell Str(string? s) => string.IsNullOrEmpty(s) ? default : new Cell(Kind.Text, XlsxWriter.Clean(s), 0);
        static Cell Date(DateTime d) => d >= MinDate
            ? new Cell(Kind.Date, null, d.ToOADate())
            : new Cell(Kind.Text, d.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), 0);   // Excel's calendar starts in 1900
    }

    private static int Width(Cell c) => c.Kind switch
    {
        Kind.Text => Longest(c.Text!) + 2,
        Kind.Number => c.Number.ToString("#,##0.##", CultureInfo.InvariantCulture).Length + 2,
        Kind.Date => 21,
        Kind.Bool => 7,
        _ => 0,
    };

    private static int Longest(string s)
    {
        int max = 0, run = 0;
        foreach (var ch in s)
        {
            if (ch == '\n') { max = Math.Max(max, run); run = 0; }
            else if (++run > XlsxWriter.MaxWidth) return XlsxWriter.MaxWidth;
        }
        return Math.Max(max, run);
    }

    /// Ends the sheet: the rows, the table part (autofilter + style) and the sheet's relationship to it.
    public void Dispose()
    {
        if (_done) return;
        Flush();
        var w = _xml!;
        w.WriteEndElement();   // sheetData
        w.WriteStartElement("tableParts", XlsxWriter.NsMain);
        w.WriteAttributeString("count", "1");
        w.WriteStartElement("tablePart", XlsxWriter.NsMain);
        w.WriteAttributeString("id", XlsxWriter.NsRel, "rId1");
        w.WriteEndElement();
        w.WriteEndElement();
        w.WriteEndElement();   // worksheet
        w.WriteEndDocument();
        w.Dispose();
        _xml = null;
        _done = true;

        // an Excel table needs a data row: an empty sheet's table spans the header and one empty row
        var last = XlsxWriter.Column(_headers.Length - 1) + XlsxWriter.Num(Math.Max(_rows, 1) + 1);
        var range = "A1:" + last;
        using (var t = XmlWriter.Create(_book.Entry($"xl/tables/table{_index}.xml").Open(), XlsxWriter.XmlSettings))
        {
            t.WriteStartDocument(true);
            t.WriteStartElement("table", XlsxWriter.NsMain);
            t.WriteAttributeString("id", XlsxWriter.Num(_index));
            t.WriteAttributeString("name", "Table" + XlsxWriter.Num(_index));
            t.WriteAttributeString("displayName", "Table" + XlsxWriter.Num(_index));
            t.WriteAttributeString("ref", range);
            t.WriteAttributeString("totalsRowShown", "0");
            t.WriteStartElement("autoFilter", XlsxWriter.NsMain); t.WriteAttributeString("ref", range); t.WriteEndElement();
            t.WriteStartElement("tableColumns", XlsxWriter.NsMain);
            t.WriteAttributeString("count", XlsxWriter.Num(_headers.Length));
            for (var i = 0; i < _headers.Length; i++)
            {
                t.WriteStartElement("tableColumn", XlsxWriter.NsMain);
                t.WriteAttributeString("id", XlsxWriter.Num(i + 1));
                t.WriteAttributeString("name", _headers[i]);
                t.WriteEndElement();
            }
            t.WriteEndElement();
            t.WriteStartElement("tableStyleInfo", XlsxWriter.NsMain);
            t.WriteAttributeString("name", XlsxWriter.TableStyle);
            t.WriteAttributeString("showFirstColumn", "0"); t.WriteAttributeString("showLastColumn", "0");
            t.WriteAttributeString("showRowStripes", "1"); t.WriteAttributeString("showColumnStripes", "0");
            t.WriteEndElement();
            t.WriteEndElement();
            t.WriteEndDocument();
        }
        using (var r = XmlWriter.Create(_book.Entry($"xl/worksheets/_rels/sheet{_index}.xml.rels").Open(), XlsxWriter.XmlSettings))
        {
            r.WriteStartDocument(true);
            r.WriteStartElement("Relationships", "http://schemas.openxmlformats.org/package/2006/relationships");
            r.WriteStartElement("Relationship", "http://schemas.openxmlformats.org/package/2006/relationships");
            r.WriteAttributeString("Id", "rId1");
            r.WriteAttributeString("Type", XlsxWriter.NsRel + "/table");
            r.WriteAttributeString("Target", $"../tables/table{_index}.xml");
            r.WriteEndElement();
            r.WriteEndElement();
            r.WriteEndDocument();
        }
        _book.Closed(this);
    }

    /// The workbook was disposed without Complete(): close the open entry, write nothing more.
    internal void Abandon()
    {
        _done = true;
        _xml?.Dispose();
        _xml = null;
        _buffer = null;
        _book.Closed(this);
    }
}
