using System.Globalization;
using System.IO.Compression;
using System.Security;
using System.Text;

namespace SI.Management.Web.Export;

/// How a card's change reads: better (green), worse (red), no change (grey) or nothing to compare (no line).
public enum PptxTone { None, Good, Bad, Neutral }

/// One number card: the value as shown, what it is, its change line.
public sealed record PptxCard(string Value, string Label, string? Change = null, PptxTone Tone = PptxTone.None);

/// One series of a chart: its name, its values (null = no value at that category), its colour (hex, null = the palette's).
public sealed record PptxSeries(string Name, IReadOnlyList<double?> Values, string? Color = null);

public enum PptxChartKind { Bar, Column, Line }

/// A native chart: its kind, the title above it, the categories and the series; the number format of its labels.
public sealed record PptxChart(PptxChartKind Kind, string Title, IReadOnlyList<string> Categories, IReadOnlyList<PptxSeries> Series, string NumberFormat = "#,##0");

/// A table: the title above it, its headers and rows (text, as shown).
public sealed record PptxTable(string Title, IReadOnlyList<string> Headers, IReadOnlyList<IReadOnlyList<string>> Rows);

/// The edition's look in a deck: the product name and the logo (a PNG, with the same logo as SVG kept sharp for PowerPoint).
public sealed record PptxBrand(string Product, byte[]? LogoPng, int LogoWidth, int LogoHeight, byte[]? LogoSvg);

/// <summary>
/// THE web app's PowerPoint (.pptx) writer, built the way <see cref="XlsxWriter"/> is: the Open XML parts written straight
/// into a zip (System.IO.Compression, no third-party package). 16:9, one slide master with the brand (the logo top right),
/// a brand theme (the edition's colours, Segoe UI), every slide with its speaker notes. Charts are NATIVE PowerPoint charts
/// with their data in an embedded workbook (written by <see cref="XlsxWriter"/>), so "Edit data" opens the numbers.
/// <para>Safety: every text goes through <see cref="XlsxWriter.Clean"/> (no control characters, no lone surrogates) and is
/// XML-escaped; the package is only a presentation after <see cref="Complete"/>.</para>
/// </summary>
public sealed class PptxWriter : IDisposable
{
    public const string ContentType = "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    public const long SlideWidth = 12_192_000, SlideHeight = 6_858_000;
    public const int MaxCards = 6;
    public const int MaxCellText = 80;

    private const long Inch = 914_400;
    private const long Margin = 457_200;
    private const long ContentWidth = SlideWidth - 2 * Margin;
    private const long ContentBottom = 6_217_920;   // 6.8 in: the footer sits under it

    internal const string NsA = "http://schemas.openxmlformats.org/drawingml/2006/main";
    internal const string NsR = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
    internal const string NsP = "http://schemas.openxmlformats.org/presentationml/2006/main";
    internal const string NsC = "http://schemas.openxmlformats.org/drawingml/2006/chart";
    private const string NsPkgRel = "http://schemas.openxmlformats.org/package/2006/relationships";
    private const string RelBase = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/";
    private const string SvgExt = "{96DAC541-7B7A-43D3-8B79-37D633B846F1}";
    private const string NsSvg = "http://schemas.microsoft.com/office/drawing/2016/SVG/main";
    /// The built-in "Medium Style 2 - Accent 1" table style (accent 1 = the brand blue).
    public const string TableStyleId = "{5C22544A-7EE6-4342-B048-85BDC9FD1C3A}";

    public const string Ink = "0B1633", Blue = "1B4FE4", Sky = "18B4F2", Wordmark = "9FC3FF", Panel = "F3F6FB", Line = "D0D7DE", Muted = "57606A",
        GoodColor = "1A7F37", BadColor = "CF222E";
    public static readonly IReadOnlyList<string> Palette = [Blue, Sky, Ink, Wordmark, "BF8700", GoodColor, BadColor];

    private readonly ZipArchive _zip;
    private readonly PptxBrand _brand;
    private readonly string _title;
    private readonly DateTime _created;
    private readonly List<Slide> _slides = new();
    private int _charts;
    private bool _completed;

    public PptxWriter(Stream output, PptxBrand brand, string title, DateTime? createdUtc = null)
    {
        _zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true, Encoding.UTF8);
        _brand = brand;
        _title = XlsxWriter.Clean(title);
        _created = createdUtc ?? DateTime.UtcNow;
    }

    public int SlideCount => _slides.Count;
    public int ChartCount => _charts;
    private bool HasLogo => _brand.LogoPng is { Length: > 0 } && _brand.LogoWidth > 0 && _brand.LogoHeight > 0;

    // ---- the slides ----------------------------------------------------------------------------------------------------

    /// The opening slide: a dark band with the title and subtitle, then the lines under it (audience, run, compared with).
    public void AddTitleSlide(string title, string subtitle, IReadOnlyList<string> lines, string notes)
    {
        var s = NewSlide(notes, masterShapes: false);
        s.Rect(0, 0, SlideWidth, 3_931_920, Ink);
        s.Rect(Margin, 3_840_480, 1_828_800, 54_864, Sky);
        s.Text(Margin, 1_463_040, ContentWidth, 1_097_280, [P(title, 4000, bold: true, color: "FFFFFF")], anchor: "b");
        s.Text(Margin, 2_651_760, ContentWidth, 822_960, [P(subtitle, 2000, color: Wordmark)]);
        s.Text(Margin, 4_206_240, ContentWidth - 2_286_000, 1_645_920, lines.Select(l => P(l, 1400, color: Ink)).ToList());
        if (HasLogo) s.Logo(SlideWidth - Margin - LogoWidthFor(457_200), SlideHeight - Margin - 457_200, 457_200);
    }

    /// The agenda: the sections of the deck as a list.
    public void AddAgendaSlide(string title, IReadOnlyList<string> items, string notes)
    {
        var s = NewSlide(notes);
        Heading(s, title);
        var cols = items.Count > 8 ? 2 : 1;
        var per = (items.Count + cols - 1) / Math.Max(1, cols);
        var w = (ContentWidth - (cols - 1) * 274_320) / cols;
        for (var c = 0; c < cols; c++)
        {
            var part = items.Skip(c * per).Take(per).Select((it, i) => P((c * per + i + 1).ToString(CultureInfo.InvariantCulture) + ".  " + it, 1800, color: Ink, spaceBefore: 600)).ToList();
            if (part.Count > 0) s.Text(Margin + c * (w + 274_320), 1_371_600, w, ContentBottom - 1_371_600, part);
        }
        Footer(s);
    }

    /// A section divider: the dark slide with the section's name.
    public void AddSectionSlide(string title, string? subtitle, string notes)
    {
        var s = NewSlide(notes, masterShapes: false, background: Ink);
        s.Rect(Margin, 3_383_280, 1_828_800, 54_864, Sky);
        s.Text(Margin, 2_011_680, ContentWidth, 1_280_160, [P(title, 3600, bold: true, color: "FFFFFF")], anchor: "b");
        if (subtitle is not null) s.Text(Margin, 3_566_160, ContentWidth, 914_400, [P(subtitle, 1800, color: Wordmark)]);
    }

    /// <summary>
    /// A content slide: the title, a line under it, up to <see cref="MaxCards"/> number cards with their change, plain
    /// lines (a suggested action), then a chart and / or a table in the room left (side by side when both).
    /// </summary>
    public void AddContentSlide(string title, string? lede, IReadOnlyList<PptxCard> cards, PptxChart? chart, PptxTable? table, IReadOnlyList<string>? lines, string notes)
    {
        var s = NewSlide(notes);
        Heading(s, title);
        long y = 1_234_440;
        if (!string.IsNullOrWhiteSpace(lede))
        {
            s.Text(Margin, y, ContentWidth, 320_040, [P(lede!, 1200, color: Muted)]);
            y += 393_192;
        }
        var shown = cards.Take(MaxCards).ToList();
        if (shown.Count > 0)
        {
            var cols = shown.Count <= 4 ? shown.Count : 3;
            var rows = (shown.Count + cols - 1) / cols;
            const long gap = 137_160;
            var h = chart is null && table is null ? 1_188_720L : 960_120L;
            var w = (ContentWidth - (cols - 1) * gap) / cols;
            for (var i = 0; i < shown.Count; i++)
                s.Card(Margin + i % cols * (w + gap), y + i / cols * (h + gap), w, h, shown[i]);
            y += rows * h + (rows - 1) * gap + 182_880;
        }
        if (lines is { Count: > 0 })
        {
            var est = lines.Sum(l => Math.Max(1, (XlsxWriter.Clean(l).Length + 139) / 140));
            var h = Math.Min(est * 228_600L + 91_440, 1_371_600);
            s.Text(Margin, y, ContentWidth, h, lines.Select(l => P(l, 1200, color: Ink, spaceBefore: 200)).ToList());
            y += h + 137_160;
        }
        var room = Math.Max(ContentBottom - y, 1_097_280);
        if (chart is not null && table is not null)
        {
            var cw = ContentWidth * 52 / 100;
            ChartAt(s, chart, Margin, y, cw, room);
            TableAt(s, table, Margin + cw + 182_880, y, ContentWidth - cw - 182_880, room);
        }
        else if (chart is not null) ChartAt(s, chart, Margin, y, ContentWidth, room);
        else if (table is not null) TableAt(s, table, Margin, y, ContentWidth, room);
        Footer(s);
    }

    private void Heading(Slide s, string title)
    {
        var logoW = HasLogo ? LogoWidthFor(LogoHeight) + 182_880 : 0;
        s.Text(Margin, 320_040, ContentWidth - logoW, 640_080, [P(title, 2600, bold: true, color: Ink)], anchor: "b");
        s.Rect(Margin, 1_005_840, ContentWidth, 27_432, Blue);
    }

    private void Footer(Slide s) =>
        s.Text(Margin, SlideHeight - 393_192, ContentWidth, 228_600,
            [P(_brand.Product + "  ·  " + _title + "  ·  " + s.Number.ToString(CultureInfo.InvariantCulture), 900, color: Muted)]);

    private void ChartAt(Slide s, PptxChart chart, long x, long y, long w, long h)
    {
        s.Text(x, y, w, 274_320, [P(chart.Title, 1200, bold: true, color: Ink)]);
        var n = ++_charts;
        var rid = s.Rel("chart", "../charts/chart" + Num(n) + ".xml");
        s.Shape($"<p:graphicFrame><p:nvGraphicFramePr><p:cNvPr id=\"{s.NextId()}\" name=\"Chart {Num(n)}\" descr=\"{X(chart.Title)}\"/><p:cNvGraphicFramePr/><p:nvPr/></p:nvGraphicFramePr>"
            + $"<p:xfrm><a:off x=\"{Num(x)}\" y=\"{Num(y + 301_752)}\"/><a:ext cx=\"{Num(w)}\" cy=\"{Num(Math.Max(h - 301_752, 457_200))}\"/></p:xfrm>"
            + $"<a:graphic><a:graphicData uri=\"{NsC}\"><c:chart xmlns:c=\"{NsC}\" r:id=\"{rid}\"/></a:graphicData></a:graphic></p:graphicFrame>");
        WriteChart(n, chart);
    }

    private static void TableAt(Slide s, PptxTable table, long x, long y, long w, long h)
    {
        s.Text(x, y, w, 274_320, [P(table.Title, 1200, bold: true, color: Ink)]);
        y += 301_752; h -= 301_752;
        var cols = Math.Max(1, table.Headers.Count);
        var rows = table.Rows.Count + 1;
        var rowH = Math.Clamp(h / Math.Max(1, rows), 228_600L, 320_040L);
        var size = cols > 6 || rows > 9 ? 900 : 1000;
        // the first column (the name) is wider than the numbers
        var weights = Enumerable.Range(0, cols).Select(i => i == 0 ? 2.4 : 1.0).ToArray();
        var widths = weights.Select(v => (long)(w * v / weights.Sum())).ToArray();
        widths[^1] = w - widths.Take(cols - 1).Sum();
        var sb = new StringBuilder();
        sb.Append($"<p:graphicFrame><p:nvGraphicFramePr><p:cNvPr id=\"{s.NextId()}\" name=\"Table\" descr=\"{X(table.Title)}\"/><p:cNvGraphicFramePr><a:graphicFrameLocks noGrp=\"1\"/></p:cNvGraphicFramePr><p:nvPr/></p:nvGraphicFramePr>");
        sb.Append($"<p:xfrm><a:off x=\"{Num(x)}\" y=\"{Num(y)}\"/><a:ext cx=\"{Num(w)}\" cy=\"{Num(rowH * rows)}\"/></p:xfrm>");
        sb.Append("<a:graphic><a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/table\"><a:tbl>");
        sb.Append($"<a:tblPr firstRow=\"1\" bandRow=\"1\"><a:tableStyleId>{TableStyleId}</a:tableStyleId></a:tblPr><a:tblGrid>");
        foreach (var cw in widths) sb.Append($"<a:gridCol w=\"{Num(cw)}\"/>");
        sb.Append("</a:tblGrid>");
        void Row(IReadOnlyList<string> cells, bool header)
        {
            sb.Append($"<a:tr h=\"{Num(rowH)}\">");
            for (var c = 0; c < cols; c++)
            {
                var t = Cut(c < cells.Count ? cells[c] : "");
                var right = !header && c > 0 && LooksNumeric(t);
                sb.Append("<a:tc><a:txBody><a:bodyPr/><a:lstStyle/><a:p>");
                if (right) sb.Append("<a:pPr algn=\"r\"/>");
                if (t.Length > 0) sb.Append($"<a:r><a:rPr lang=\"en-US\" sz=\"{size}\"{(header ? " b=\"1\"" : "")} dirty=\"0\"/><a:t>{X(t)}</a:t></a:r>");
                else sb.Append($"<a:endParaRPr lang=\"en-US\" sz=\"{size}\" dirty=\"0\"/>");
                sb.Append("</a:p></a:txBody><a:tcPr marL=\"68580\" marR=\"68580\" marT=\"22860\" marB=\"22860\" anchor=\"ctr\"/></a:tc>");
            }
            sb.Append("</a:tr>");
        }
        Row(table.Headers, true);
        foreach (var r in table.Rows) Row(r, false);
        sb.Append("</a:tbl></a:graphicData></a:graphic></p:graphicFrame>");
        s.Shape(sb.ToString());
    }

    /// A table cell's text: one line, at most <see cref="MaxCellText"/> characters.
    public static string Cut(string? s)
    {
        var t = XlsxWriter.Clean(s).Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ').Trim();
        if (t.Length <= MaxCellText) return t;
        var cut = MaxCellText - 1;
        if (char.IsHighSurrogate(t[cut - 1])) cut--;
        return t[..cut] + "…";
    }

    private static bool LooksNumeric(string t) => t.Length > 0 && (char.IsDigit(t[0]) || t == "–" || (t[0] is '+' or '-' && t.Length > 1 && char.IsDigit(t[1])));

    private long LogoHeight => 320_040;
    private long LogoWidthFor(long h) => HasLogo ? h * _brand.LogoWidth / _brand.LogoHeight : 0;

    // ---- one slide ---------------------------------------------------------------------------------------------------

    private Slide NewSlide(string notes, bool masterShapes = true, string? background = null)
    {
        if (_completed) throw new InvalidOperationException("the presentation is complete");
        var s = new Slide(this, _slides.Count + 1, notes, masterShapes, background);
        _slides.Add(s);
        return s;
    }

    private sealed class Slide(PptxWriter owner, int number, string notes, bool masterShapes, string? background)
    {
        private readonly StringBuilder _shapes = new();
        private int _id = 1;
        public int Number { get; } = number;
        public string Notes { get; } = notes;
        public bool MasterShapes { get; } = masterShapes;
        public string? Background { get; } = background;
        /// rId1 = the layout, rId2 = the notes; the rest in order.
        public List<(string Id, string Type, string Target)> Rels { get; } = new();
        private string? _png, _svg;

        public int NextId() => ++_id;
        public void Shape(string xml) => _shapes.Append(xml);
        public string Shapes => _shapes.ToString();

        public string Rel(string type, string target)
        {
            var id = "rId" + (Rels.Count + 3).ToString(CultureInfo.InvariantCulture);
            Rels.Add((id, RelBase + type, target));
            return id;
        }

        public void Rect(long x, long y, long w, long h, string fill) =>
            Shape($"<p:sp><p:nvSpPr><p:cNvPr id=\"{NextId()}\" name=\"Band\"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr>{Xfrm(x, y, w, h)}<a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom>"
                + $"<a:solidFill><a:srgbClr val=\"{fill}\"/></a:solidFill><a:ln><a:noFill/></a:ln></p:spPr></p:sp>");

        public void Text(long x, long y, long w, long h, IReadOnlyList<string> paragraphs, string anchor = "t") =>
            Shape($"<p:sp><p:nvSpPr><p:cNvPr id=\"{NextId()}\" name=\"Text\"/><p:cNvSpPr txBox=\"1\"/><p:nvPr/></p:nvSpPr><p:spPr>{Xfrm(x, y, w, h)}<a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom><a:noFill/></p:spPr>"
                + $"<p:txBody><a:bodyPr wrap=\"square\" lIns=\"0\" tIns=\"0\" rIns=\"0\" bIns=\"0\" anchor=\"{anchor}\"><a:normAutofit/></a:bodyPr><a:lstStyle/>{(paragraphs.Count == 0 ? Empty(1200) : string.Concat(paragraphs))}</p:txBody></p:sp>");

        public void Card(long x, long y, long w, long h, PptxCard card)
        {
            var value = XlsxWriter.Clean(card.Value);
            var size = value.Length <= 14 ? 2400 : value.Length <= 28 ? 1800 : 1400;
            var tone = card.Tone switch { PptxTone.Good => GoodColor, PptxTone.Bad => BadColor, _ => Muted };
            var paras = new List<string> { P(value, size, bold: true, color: Ink), P(card.Label, 1100, color: Muted, spaceBefore: 200) };
            if (!string.IsNullOrWhiteSpace(card.Change)) paras.Add(P(card.Change!, 1000, color: tone, spaceBefore: 200, bold: card.Tone is PptxTone.Good or PptxTone.Bad));
            Shape($"<p:sp><p:nvSpPr><p:cNvPr id=\"{NextId()}\" name=\"Card\"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr>{Xfrm(x, y, w, h)}<a:prstGeom prst=\"roundRect\"><a:avLst><a:gd name=\"adj\" fmla=\"val 8000\"/></a:avLst></a:prstGeom>"
                + $"<a:solidFill><a:srgbClr val=\"{Panel}\"/></a:solidFill><a:ln w=\"9525\"><a:solidFill><a:srgbClr val=\"{Line}\"/></a:solidFill></a:ln></p:spPr>"
                + $"<p:txBody><a:bodyPr wrap=\"square\" lIns=\"137160\" tIns=\"91440\" rIns=\"137160\" bIns=\"91440\" anchor=\"t\"><a:normAutofit/></a:bodyPr><a:lstStyle/>{string.Concat(paras)}</p:txBody></p:sp>");
        }

        public void Logo(long x, long y, long h)
        {
            _png ??= Rel("image", "../media/logo.png");
            if (owner._brand.LogoSvg is { Length: > 0 }) _svg ??= Rel("image", "../media/logo.svg");
            Shape(PictureXml(NextId(), x, y, owner.LogoWidthFor(h), h, _png, _svg, owner._brand.Product));
        }
    }

    internal static string PictureXml(int id, long x, long y, long w, long h, string png, string? svg, string alt) =>
        $"<p:pic><p:nvPicPr><p:cNvPr id=\"{id}\" name=\"Logo\" descr=\"{X(alt)}\"/><p:cNvPicPr><a:picLocks noChangeAspect=\"1\"/></p:cNvPicPr><p:nvPr/></p:nvPicPr>"
        + $"<p:blipFill><a:blip r:embed=\"{png}\">"
        + (svg is null ? "" : $"<a:extLst><a:ext uri=\"{SvgExt}\"><asvg:svgBlip xmlns:asvg=\"{NsSvg}\" r:embed=\"{svg}\"/></a:ext></a:extLst>")
        + $"</a:blip><a:stretch><a:fillRect/></a:stretch></p:blipFill><p:spPr>{Xfrm(x, y, w, h)}<a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></p:spPr></p:pic>";

    private static string Xfrm(long x, long y, long w, long h) => $"<a:xfrm><a:off x=\"{Num(x)}\" y=\"{Num(y)}\"/><a:ext cx=\"{Num(Math.Max(w, 1))}\" cy=\"{Num(Math.Max(h, 1))}\"/></a:xfrm>";

    /// One paragraph of one run.
    internal static string P(string text, int size, bool bold = false, string? color = null, int spaceBefore = 0)
    {
        var t = XlsxWriter.Clean(text).Replace("\r", "").Replace('\n', ' ').Replace('\t', ' ');
        var ppr = spaceBefore > 0 ? $"<a:pPr><a:spcBef><a:spcPts val=\"{spaceBefore}\"/></a:spcBef></a:pPr>" : "";
        if (t.Length == 0) return $"<a:p>{ppr}{Empty(size)[5..]}";
        return $"<a:p>{ppr}<a:r><a:rPr lang=\"en-US\" sz=\"{size}\"{(bold ? " b=\"1\"" : "")} dirty=\"0\">{(color is null ? "" : $"<a:solidFill><a:srgbClr val=\"{color}\"/></a:solidFill>")}</a:rPr><a:t>{X(t)}</a:t></a:r></a:p>";
    }

    private static string Empty(int size) => $"<a:p><a:endParaRPr lang=\"en-US\" sz=\"{size}\" dirty=\"0\"/></a:p>";

    internal static string X(string? s) => SecurityElement.Escape(XlsxWriter.Clean(s)) ?? "";
    internal static string Num(long v) => v.ToString(CultureInfo.InvariantCulture);
    private static string Dbl(double v) => v.ToString("R", CultureInfo.InvariantCulture);

    // ---- charts ------------------------------------------------------------------------------------------------------

    private void WriteChart(int n, PptxChart chart)
    {
        var cats = chart.Categories.Select(c => XlsxWriter.Clean(c)).ToList();
        var series = chart.Series.Count == 0 ? new List<PptxSeries> { new("Value", cats.Select(_ => (double?)null).ToList()) } : chart.Series.ToList();
        var headers = XlsxWriter.Headers(new[] { "Category" }.Concat(series.Select(s => s.Name)).ToList());
        // the data the chart shows, as a real workbook in the presentation ("Edit data" in PowerPoint opens it)
        using (var ms = new MemoryStream())
        {
            using (var x = new XlsxWriter(ms, chart.Title, _created))
            {
                using (var sh = x.AddSheet("Sheet1", headers))
                    for (var i = 0; i < cats.Count; i++)
                        sh.WriteRow(new object?[] { cats[i] }.Concat(series.Select(s => i < s.Values.Count && s.Values[i] is { } v && double.IsFinite(v) ? (object?)v : null)).ToArray());
                x.Complete();
            }
            Bytes($"ppt/embeddings/Microsoft_Excel_Worksheet{Num(n)}.xlsx", ms.ToArray());
        }
        Text($"ppt/charts/_rels/chart{Num(n)}.xml.rels", Rels([("rId1", RelBase + "package", $"../embeddings/Microsoft_Excel_Worksheet{Num(n)}.xlsx")]));

        var last = cats.Count + 1;
        var sb = new StringBuilder();
        sb.Append($"<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><c:chartSpace xmlns:c=\"{NsC}\" xmlns:a=\"{NsA}\" xmlns:r=\"{NsR}\">");
        sb.Append("<c:date1904 val=\"0\"/><c:lang val=\"en-US\"/><c:roundedCorners val=\"0\"/><c:chart><c:autoTitleDeleted val=\"1\"/><c:plotArea><c:layout/>");
        var single = series.Count == 1;
        var bar = chart.Kind != PptxChartKind.Line;
        if (bar) sb.Append($"<c:barChart><c:barDir val=\"{(chart.Kind == PptxChartKind.Bar ? "bar" : "col")}\"/><c:grouping val=\"clustered\"/><c:varyColors val=\"0\"/>");
        else sb.Append("<c:lineChart><c:grouping val=\"standard\"/><c:varyColors val=\"0\"/>");
        for (var s = 0; s < series.Count; s++)
        {
            var col = XlsxWriter.Column(s + 1);
            var color = series[s].Color ?? Palette[s % Palette.Count];
            sb.Append($"<c:ser><c:idx val=\"{s}\"/><c:order val=\"{s}\"/><c:tx><c:strRef><c:f>Sheet1!${col}$1</c:f><c:strCache><c:ptCount val=\"1\"/><c:pt idx=\"0\"><c:v>{X(headers[s + 1])}</c:v></c:pt></c:strCache></c:strRef></c:tx>");
            if (bar) sb.Append($"<c:spPr><a:solidFill><a:srgbClr val=\"{color}\"/></a:solidFill></c:spPr><c:invertIfNegative val=\"0\"/>");
            else sb.Append($"<c:spPr><a:ln w=\"28575\" cap=\"rnd\"><a:solidFill><a:srgbClr val=\"{color}\"/></a:solidFill><a:round/></a:ln></c:spPr>"
                + $"<c:marker><c:symbol val=\"circle\"/><c:size val=\"5\"/><c:spPr><a:solidFill><a:srgbClr val=\"{color}\"/></a:solidFill><a:ln><a:noFill/></a:ln></c:spPr></c:marker>");
            if (bar && single)
                sb.Append($"<c:dLbls><c:numFmt formatCode=\"{X(chart.NumberFormat)}\" sourceLinked=\"0\"/><c:spPr><a:noFill/><a:ln><a:noFill/></a:ln></c:spPr>"
                    + "<c:txPr><a:bodyPr/><a:lstStyle/><a:p><a:pPr><a:defRPr sz=\"900\"/></a:pPr><a:endParaRPr lang=\"en-US\"/></a:p></c:txPr>"
                    + "<c:showLegendKey val=\"0\"/><c:showVal val=\"1\"/><c:showCatName val=\"0\"/><c:showSerName val=\"0\"/><c:showPercent val=\"0\"/><c:showBubbleSize val=\"0\"/></c:dLbls>");
            sb.Append($"<c:cat><c:strRef><c:f>Sheet1!$A$2:$A${Num(Math.Max(last, 2))}</c:f><c:strCache><c:ptCount val=\"{cats.Count}\"/>");
            for (var i = 0; i < cats.Count; i++) sb.Append($"<c:pt idx=\"{i}\"><c:v>{X(cats[i])}</c:v></c:pt>");
            sb.Append($"</c:strCache></c:strRef></c:cat><c:val><c:numRef><c:f>Sheet1!${col}$2:${col}${Num(Math.Max(last, 2))}</c:f><c:numCache><c:formatCode>General</c:formatCode><c:ptCount val=\"{cats.Count}\"/>");
            for (var i = 0; i < cats.Count; i++)
                if (i < series[s].Values.Count && series[s].Values[i] is { } v && double.IsFinite(v)) sb.Append($"<c:pt idx=\"{i}\"><c:v>{Dbl(v)}</c:v></c:pt>");
            sb.Append("</c:numCache></c:numRef></c:val>");
            if (!bar) sb.Append("<c:smooth val=\"0\"/>");
            sb.Append("</c:ser>");
        }
        if (bar) sb.Append("<c:gapWidth val=\"60\"/>");
        else sb.Append("<c:marker val=\"1\"/>");
        sb.Append("<c:axId val=\"500001\"/><c:axId val=\"500002\"/>");
        sb.Append(bar ? "</c:barChart>" : "</c:lineChart>");
        const string axText = "<c:txPr><a:bodyPr/><a:lstStyle/><a:p><a:pPr><a:defRPr sz=\"900\"><a:solidFill><a:srgbClr val=\"57606A\"/></a:solidFill></a:defRPr></a:pPr><a:endParaRPr lang=\"en-US\"/></a:p></c:txPr>";
        // a horizontal bar chart lists its first category on top
        var reverse = chart.Kind == PptxChartKind.Bar;
        sb.Append($"<c:catAx><c:axId val=\"500001\"/><c:scaling><c:orientation val=\"{(reverse ? "maxMin" : "minMax")}\"/></c:scaling><c:delete val=\"0\"/><c:axPos val=\"{(chart.Kind == PptxChartKind.Bar ? "l" : "b")}\"/>"
            + "<c:numFmt formatCode=\"General\" sourceLinked=\"0\"/><c:majorTickMark val=\"none\"/><c:minorTickMark val=\"none\"/><c:tickLblPos val=\"nextTo\"/>"
            + $"<c:spPr><a:ln w=\"9525\"><a:solidFill><a:srgbClr val=\"{Line}\"/></a:solidFill></a:ln></c:spPr>{axText}"
            + "<c:crossAx val=\"500002\"/><c:crosses val=\"autoZero\"/><c:auto val=\"1\"/><c:lblAlgn val=\"ctr\"/><c:lblOffset val=\"100\"/><c:noMultiLvlLbl val=\"0\"/></c:catAx>");
        sb.Append($"<c:valAx><c:axId val=\"500002\"/><c:scaling><c:orientation val=\"minMax\"/></c:scaling><c:delete val=\"{(bar && single ? 1 : 0)}\"/><c:axPos val=\"{(chart.Kind == PptxChartKind.Bar ? "b" : "l")}\"/>"
            + $"<c:majorGridlines><c:spPr><a:ln w=\"6350\"><a:solidFill><a:srgbClr val=\"E6EAEF\"/></a:solidFill></a:ln></c:spPr></c:majorGridlines>"
            + $"<c:numFmt formatCode=\"{X(chart.NumberFormat)}\" sourceLinked=\"0\"/><c:majorTickMark val=\"none\"/><c:minorTickMark val=\"none\"/><c:tickLblPos val=\"nextTo\"/>"
            + $"<c:spPr><a:ln><a:noFill/></a:ln></c:spPr>{axText}<c:crossAx val=\"500001\"/><c:crosses val=\"{(reverse ? "max" : "autoZero")}\"/><c:crossBetween val=\"between\"/></c:valAx>");
        sb.Append("</c:plotArea>");
        if (!single) sb.Append($"<c:legend><c:legendPos val=\"b\"/><c:overlay val=\"0\"/>{axText}</c:legend>");
        sb.Append("<c:plotVisOnly val=\"1\"/><c:dispBlanksAs val=\"gap\"/></c:chart>");
        sb.Append("<c:txPr><a:bodyPr/><a:lstStyle/><a:p><a:pPr><a:defRPr sz=\"1000\"/></a:pPr><a:endParaRPr lang=\"en-US\"/></a:p></c:txPr>");
        sb.Append("<c:externalData r:id=\"rId1\"><c:autoUpdate val=\"0\"/></c:externalData></c:chartSpace>");
        Text($"ppt/charts/chart{Num(n)}.xml", sb.ToString());
    }

    // ---- the package ---------------------------------------------------------------------------------------------------

    /// Writes the presentation, its master, layouts, theme, notes and the content types. Without it the package is not a presentation.
    public void Complete()
    {
        if (_completed) return;
        if (_slides.Count == 0) throw new InvalidOperationException("a presentation needs at least one slide");
        _completed = true;
        const string head = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
        var ns = $"xmlns:a=\"{NsA}\" xmlns:r=\"{NsR}\" xmlns:p=\"{NsP}\"";
        const string grp = "<p:nvGrpSpPr><p:cNvPr id=\"1\" name=\"\"/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"0\" cy=\"0\"/><a:chOff x=\"0\" y=\"0\"/><a:chExt cx=\"0\" cy=\"0\"/></a:xfrm></p:grpSpPr>";
        const string clrMap = "<p:clrMap bg1=\"lt1\" tx1=\"dk1\" bg2=\"lt2\" tx2=\"dk2\" accent1=\"accent1\" accent2=\"accent2\" accent3=\"accent3\" accent4=\"accent4\" accent5=\"accent5\" accent6=\"accent6\" hlink=\"hlink\" folHlink=\"folHlink\"/>";

        if (HasLogo)
        {
            Bytes("ppt/media/logo.png", _brand.LogoPng!);
            if (_brand.LogoSvg is { Length: > 0 }) Bytes("ppt/media/logo.svg", _brand.LogoSvg);
        }

        for (var i = 0; i < _slides.Count; i++)
        {
            var s = _slides[i];
            var n = Num(i + 1);
            var bg = s.Background is null ? "" : $"<p:bg><p:bgPr><a:solidFill><a:srgbClr val=\"{s.Background}\"/></a:solidFill><a:effectLst/></p:bgPr></p:bg>";
            Text($"ppt/slides/slide{n}.xml", $"{head}<p:sld {ns}{(s.MasterShapes ? "" : " showMasterSp=\"0\"")}><p:cSld>{bg}<p:spTree>{grp}{s.Shapes}</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sld>");
            var rels = new List<(string, string, string)>
            {
                ("rId1", RelBase + "slideLayout", i == 0 ? "../slideLayouts/slideLayout1.xml" : "../slideLayouts/slideLayout2.xml"),
                ("rId2", RelBase + "notesSlide", $"../notesSlides/notesSlide{n}.xml"),
            };
            rels.AddRange(s.Rels);
            Text($"ppt/slides/_rels/slide{n}.xml.rels", Rels(rels));
            var notes = XlsxWriter.Clean(s.Notes).Replace("\r", "").Split('\n').Select(l => P(l, 1200)).ToList();
            Text($"ppt/notesSlides/notesSlide{n}.xml", $"{head}<p:notes {ns}><p:cSld><p:spTree>{grp}"
                + "<p:sp><p:nvSpPr><p:cNvPr id=\"2\" name=\"Slide Image\"/><p:cNvSpPr><a:spLocks noGrp=\"1\" noRot=\"1\" noChangeAspect=\"1\"/></p:cNvSpPr><p:nvPr><p:ph type=\"sldImg\"/></p:nvPr></p:nvSpPr><p:spPr/></p:sp>"
                + "<p:sp><p:nvSpPr><p:cNvPr id=\"3\" name=\"Notes\"/><p:cNvSpPr><a:spLocks noGrp=\"1\"/></p:cNvSpPr><p:nvPr><p:ph type=\"body\" idx=\"1\"/></p:nvPr></p:nvSpPr><p:spPr/>"
                + $"<p:txBody><a:bodyPr/><a:lstStyle/>{string.Concat(notes)}</p:txBody></p:sp></p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:notes>");
            Text($"ppt/notesSlides/_rels/notesSlide{n}.xml.rels", Rels([("rId1", RelBase + "notesMaster", "../notesMasters/notesMaster1.xml"), ("rId2", RelBase + "slide", $"../slides/slide{n}.xml")]));
        }

        // the master: the logo top right on every content slide (a slide that hides the master shapes has its own look)
        var masterShapes = "";
        var masterRels = new List<(string, string, string)> { ("rId1", RelBase + "slideLayout", "../slideLayouts/slideLayout1.xml"), ("rId2", RelBase + "slideLayout", "../slideLayouts/slideLayout2.xml"), ("rId3", RelBase + "theme", "../theme/theme1.xml") };
        if (HasLogo)
        {
            masterRels.Add(("rId4", RelBase + "image", "../media/logo.png"));
            if (_brand.LogoSvg is { Length: > 0 }) masterRels.Add(("rId5", RelBase + "image", "../media/logo.svg"));
            var w = LogoWidthFor(LogoHeight);
            masterShapes = PictureXml(2, SlideWidth - Margin - w, 466_344, w, LogoHeight, "rId4", _brand.LogoSvg is { Length: > 0 } ? "rId5" : null, _brand.Product);
        }
        const string lvl1 = "<a:lvl1pPr><a:defRPr sz=\"1800\"><a:solidFill><a:schemeClr val=\"tx1\"/></a:solidFill><a:latin typeface=\"+mn-lt\"/></a:defRPr></a:lvl1pPr>";
        Text("ppt/slideMasters/slideMaster1.xml", $"{head}<p:sldMaster {ns}><p:cSld><p:bg><p:bgRef idx=\"1001\"><a:schemeClr val=\"bg1\"/></p:bgRef></p:bg><p:spTree>{grp}{masterShapes}</p:spTree></p:cSld>{clrMap}"
            + "<p:sldLayoutIdLst><p:sldLayoutId id=\"2147483649\" r:id=\"rId1\"/><p:sldLayoutId id=\"2147483650\" r:id=\"rId2\"/></p:sldLayoutIdLst>"
            + $"<p:txStyles><p:titleStyle>{lvl1.Replace("+mn-lt", "+mj-lt")}</p:titleStyle><p:bodyStyle>{lvl1}</p:bodyStyle><p:otherStyle>{lvl1}</p:otherStyle></p:txStyles></p:sldMaster>");
        Text("ppt/slideMasters/_rels/slideMaster1.xml.rels", Rels(masterRels));
        foreach (var (n, name, type) in new[] { (1, "Title", "title"), (2, "Content", "titleOnly") })
        {
            Text($"ppt/slideLayouts/slideLayout{n}.xml", $"{head}<p:sldLayout {ns} type=\"{type}\" preserve=\"1\"><p:cSld name=\"{name}\"><p:spTree>{grp}</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr></p:sldLayout>");
            Text($"ppt/slideLayouts/_rels/slideLayout{n}.xml.rels", Rels([("rId1", RelBase + "slideMaster", "../slideMasters/slideMaster1.xml")]));
        }
        Text("ppt/notesMasters/notesMaster1.xml", $"{head}<p:notesMaster {ns}><p:cSld><p:bg><p:bgRef idx=\"1001\"><a:schemeClr val=\"bg1\"/></p:bgRef></p:bg><p:spTree>{grp}"
            + "<p:sp><p:nvSpPr><p:cNvPr id=\"2\" name=\"Slide Image\"/><p:cNvSpPr><a:spLocks noGrp=\"1\" noRot=\"1\" noChangeAspect=\"1\"/></p:cNvSpPr><p:nvPr><p:ph type=\"sldImg\" idx=\"2\"/></p:nvPr></p:nvSpPr>"
            + "<p:spPr><a:xfrm><a:off x=\"381000\" y=\"685800\"/><a:ext cx=\"6096000\" cy=\"3429000\"/></a:xfrm><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom><a:noFill/><a:ln w=\"12700\"><a:solidFill><a:prstClr val=\"black\"/></a:solidFill></a:ln></p:spPr></p:sp>"
            + "<p:sp><p:nvSpPr><p:cNvPr id=\"3\" name=\"Notes\"/><p:cNvSpPr><a:spLocks noGrp=\"1\"/></p:cNvSpPr><p:nvPr><p:ph type=\"body\" sz=\"quarter\" idx=\"3\"/></p:nvPr></p:nvSpPr>"
            + "<p:spPr><a:xfrm><a:off x=\"685800\" y=\"4343400\"/><a:ext cx=\"5486400\" cy=\"4114800\"/></a:xfrm><a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></p:spPr>"
            + "<p:txBody><a:bodyPr vert=\"horz\" lIns=\"91440\" tIns=\"45720\" rIns=\"91440\" bIns=\"45720\" rtlCol=\"0\"/><a:lstStyle/><a:p><a:endParaRPr lang=\"en-US\"/></a:p></p:txBody></p:sp>"
            + $"</p:spTree></p:cSld>{clrMap}<p:notesStyle><a:lvl1pPr marL=\"0\" algn=\"l\" rtl=\"0\"><a:defRPr sz=\"1200\"><a:solidFill><a:schemeClr val=\"tx1\"/></a:solidFill><a:latin typeface=\"+mn-lt\"/></a:defRPr></a:lvl1pPr></p:notesStyle></p:notesMaster>");
        Text("ppt/notesMasters/_rels/notesMaster1.xml.rels", Rels([("rId1", RelBase + "theme", "../theme/theme2.xml")]));
        Text("ppt/theme/theme1.xml", Theme("SecurityInsight"));
        Text("ppt/theme/theme2.xml", Theme("SecurityInsight notes"));

        var sldIds = string.Concat(Enumerable.Range(0, _slides.Count).Select(i => $"<p:sldId id=\"{Num(256 + i)}\" r:id=\"rId{Num(10 + i)}\"/>"));
        Text("ppt/presentation.xml", $"{head}<p:presentation {ns} saveSubsetFonts=\"1\"><p:sldMasterIdLst><p:sldMasterId id=\"2147483648\" r:id=\"rId1\"/></p:sldMasterIdLst>"
            + $"<p:notesMasterIdLst><p:notesMasterId r:id=\"rId2\"/></p:notesMasterIdLst><p:sldIdLst>{sldIds}</p:sldIdLst>"
            + $"<p:sldSz cx=\"{Num(SlideWidth)}\" cy=\"{Num(SlideHeight)}\"/><p:notesSz cx=\"6858000\" cy=\"9144000\"/>"
            + $"<p:defaultTextStyle><a:defPPr><a:defRPr lang=\"en-US\"/></a:defPPr>{lvl1}</p:defaultTextStyle></p:presentation>");
        var presRels = new List<(string, string, string)>
        {
            ("rId1", RelBase + "slideMaster", "slideMasters/slideMaster1.xml"), ("rId2", RelBase + "notesMaster", "notesMasters/notesMaster1.xml"),
            ("rId3", RelBase + "theme", "theme/theme1.xml"), ("rId4", RelBase + "presProps", "presProps.xml"),
            ("rId5", RelBase + "viewProps", "viewProps.xml"), ("rId6", RelBase + "tableStyles", "tableStyles.xml"),
        };
        for (var i = 0; i < _slides.Count; i++) presRels.Add(("rId" + Num(10 + i), RelBase + "slide", $"slides/slide{Num(i + 1)}.xml"));
        Text("ppt/_rels/presentation.xml.rels", Rels(presRels));
        Text("ppt/presProps.xml", $"{head}<p:presentationPr {ns}/>");
        Text("ppt/viewProps.xml", $"{head}<p:viewPr {ns}><p:normalViewPr><p:restoredLeft sz=\"15620\"/><p:restoredTop sz=\"80000\"/></p:normalViewPr><p:gridSpacing cx=\"76200\" cy=\"76200\"/></p:viewPr>");
        Text("ppt/tableStyles.xml", $"{head}<a:tblStyleLst xmlns:a=\"{NsA}\" def=\"{TableStyleId}\"/>");

        Text("_rels/.rels", Rels([
            ("rId1", RelBase + "officeDocument", "ppt/presentation.xml"),
            ("rId2", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties", "docProps/core.xml"),
            ("rId3", RelBase + "extended-properties", "docProps/app.xml")]));
        Text("docProps/core.xml", $"{head}<cp:coreProperties xmlns:cp=\"http://schemas.openxmlformats.org/package/2006/metadata/core-properties\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:dcterms=\"http://purl.org/dc/terms/\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
            + $"<dc:title>{X(_title)}</dc:title><dc:creator>{X(_brand.Product)}</dc:creator><dcterms:created xsi:type=\"dcterms:W3CDTF\">{_created.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)}</dcterms:created></cp:coreProperties>");
        Text("docProps/app.xml", $"{head}<Properties xmlns=\"http://schemas.openxmlformats.org/officeDocument/2006/extended-properties\"><Application>{X(_brand.Product)}</Application>"
            + $"<PresentationFormat>Widescreen</PresentationFormat><Slides>{Num(_slides.Count)}</Slides><Notes>{Num(_slides.Count)}</Notes></Properties>");

        var ct = new StringBuilder($"{head}<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">");
        void Default(string ext, string type) => ct.Append($"<Default Extension=\"{ext}\" ContentType=\"{type}\"/>");
        void Override(string part, string type) => ct.Append($"<Override PartName=\"{part}\" ContentType=\"{type}\"/>");
        const string pml = "application/vnd.openxmlformats-officedocument.presentationml.";
        Default("rels", "application/vnd.openxmlformats-package.relationships+xml");
        Default("xml", "application/xml");
        Default("png", "image/png");
        Default("svg", "image/svg+xml");
        Default("xlsx", XlsxWriter.ContentType);
        Override("/ppt/presentation.xml", pml + "presentation.main+xml");
        Override("/ppt/slideMasters/slideMaster1.xml", pml + "slideMaster+xml");
        Override("/ppt/slideLayouts/slideLayout1.xml", pml + "slideLayout+xml");
        Override("/ppt/slideLayouts/slideLayout2.xml", pml + "slideLayout+xml");
        Override("/ppt/notesMasters/notesMaster1.xml", pml + "notesMaster+xml");
        Override("/ppt/theme/theme1.xml", "application/vnd.openxmlformats-officedocument.theme+xml");
        Override("/ppt/theme/theme2.xml", "application/vnd.openxmlformats-officedocument.theme+xml");
        Override("/ppt/presProps.xml", pml + "presProps+xml");
        Override("/ppt/viewProps.xml", pml + "viewProps+xml");
        Override("/ppt/tableStyles.xml", pml + "tableStyles+xml");
        Override("/docProps/core.xml", "application/vnd.openxmlformats-package.core-properties+xml");
        Override("/docProps/app.xml", "application/vnd.openxmlformats-officedocument.extended-properties+xml");
        for (var i = 1; i <= _slides.Count; i++)
        {
            Override($"/ppt/slides/slide{Num(i)}.xml", pml + "slide+xml");
            Override($"/ppt/notesSlides/notesSlide{Num(i)}.xml", pml + "notesSlide+xml");
        }
        for (var i = 1; i <= _charts; i++) Override($"/ppt/charts/chart{Num(i)}.xml", "application/vnd.openxmlformats-officedocument.drawingml.chart+xml");
        ct.Append("</Types>");
        Text("[Content_Types].xml", ct.ToString());
    }

    public void Dispose() => _zip.Dispose();

    private static string Rels(IEnumerable<(string Id, string Type, string Target)> rels) =>
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" + $"<Relationships xmlns=\"{NsPkgRel}\">"
        + string.Concat(rels.Select(r => $"<Relationship Id=\"{r.Id}\" Type=\"{r.Type}\" Target=\"{X(r.Target)}\"/>")) + "</Relationships>";

    private void Text(string path, string xml) => Bytes(path, new UTF8Encoding(false).GetBytes(xml));

    private void Bytes(string path, byte[] bytes)
    {
        using var s = _zip.CreateEntry(path, CompressionLevel.Fastest).Open();
        s.Write(bytes, 0, bytes.Length);
    }

    /// The brand theme: the edition's colours (ink, blue, sky, the wordmark blue, then warning / bad / good) and Segoe UI.
    private static string Theme(string name) =>
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
        + $"<a:theme xmlns:a=\"{NsA}\" name=\"{X(name)}\"><a:themeElements><a:clrScheme name=\"SecurityInsight\">"
        + $"<a:dk1><a:srgbClr val=\"{Ink}\"/></a:dk1><a:lt1><a:srgbClr val=\"FFFFFF\"/></a:lt1><a:dk2><a:srgbClr val=\"{Ink}\"/></a:dk2><a:lt2><a:srgbClr val=\"{Panel}\"/></a:lt2>"
        + $"<a:accent1><a:srgbClr val=\"{Blue}\"/></a:accent1><a:accent2><a:srgbClr val=\"{Sky}\"/></a:accent2><a:accent3><a:srgbClr val=\"{Wordmark}\"/></a:accent3>"
        + $"<a:accent4><a:srgbClr val=\"BF8700\"/></a:accent4><a:accent5><a:srgbClr val=\"{BadColor}\"/></a:accent5><a:accent6><a:srgbClr val=\"{GoodColor}\"/></a:accent6>"
        + "<a:hlink><a:srgbClr val=\"0969DA\"/></a:hlink><a:folHlink><a:srgbClr val=\"8250DF\"/></a:folHlink></a:clrScheme>"
        + "<a:fontScheme name=\"SecurityInsight\"><a:majorFont><a:latin typeface=\"Segoe UI Semibold\"/><a:ea typeface=\"\"/><a:cs typeface=\"\"/></a:majorFont>"
        + "<a:minorFont><a:latin typeface=\"Segoe UI\"/><a:ea typeface=\"\"/><a:cs typeface=\"\"/></a:minorFont></a:fontScheme>"
        + "<a:fmtScheme name=\"SecurityInsight\"><a:fillStyleLst><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:fillStyleLst>"
        + "<a:lnStyleLst><a:ln w=\"6350\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln><a:ln w=\"12700\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln><a:ln w=\"19050\"><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:ln></a:lnStyleLst>"
        + "<a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>"
        + "<a:bgFillStyleLst><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill><a:solidFill><a:schemeClr val=\"phClr\"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme>"
        + "</a:themeElements><a:objectDefaults/><a:extraClrSchemeLst/></a:theme>";
}
