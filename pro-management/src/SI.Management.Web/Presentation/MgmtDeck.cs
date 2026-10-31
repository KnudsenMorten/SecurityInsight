using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using SI.Management.Core;
using SI.Management.Core.ProData;
using SI.Management.Web.Export;
using SI.Management.Web.Pages;
using SI.Management.Web.RiskExec;

namespace SI.Management.Web.Presentation;

/// <summary>
/// THE MANAGEMENT PRESENTATION (owner 2026-10-29: "a wizard for mgmt. reporting, where i can select what i want to export
/// and then get a powerpoint with the exported data ... A nice looking powerpoint" / "customer must be able to do this
/// themselves"). ONE generator for both: the wizard (Overview > Executive report > Presentation: the run, the run compared
/// with, the sections, title, audience, number format) and the fixed MONTHLY MANAGEMENT PACK (<see cref="PackSections"/>:
/// the one-click download and the attachment of the scheduled management summary mail).
/// <para>The figures are the SAME stored figures the Executive report shows (<see cref="ExecutiveFigures.ReportBlocks"/>,
/// one source), plus the stored aggregates of the other Management pages (the run's Top risky assets, the tier-0 ranking,
/// the daily domain aggregate, the daily opened / closed counts). Nothing is read from the findings themselves: a deck of
/// a large estate costs what the pages cost. Every table is cut to its top 10 rows.</para>
/// <para>The audience sets the detail (owner 2026-10-29): Board = number cards and charts, no tables; Management = plus the
/// top-10 tables; IT management = plus the patching group slides. Slide text is English; numbers and dates follow the
/// chosen number format (<see cref="DisplayCulture"/>). The explanation of each slide is in its speaker notes.</para>
/// </summary>
public static class MgmtDeck
{
    public const string Board = "board", Management = "management", It = "it";
    public static readonly IReadOnlyList<(string Code, string Label)> Audiences = [(Board, "Board"), (Management, "Management"), (It, "IT management")];
    public static string AudienceCode(string? a) => Audiences.Any(x => x.Code == a) ? a! : Management;
    public static string AudienceLabel(string? a) => Audiences.First(x => x.Code == AudienceCode(a)).Label;

    /// Every section a deck can carry, in the deck's order: the Executive report's blocks, then the other Management pages.
    public static readonly IReadOnlyList<(string Key, string Label)> Sections =
    [
        ("protection", "Protection Score"), ("patching", "Patching"), ("exposure", "Exposure"), ("coverage", "Coverage"), ("identity", "Identity"),
        ("cloud", "Cloud"), ("todo", "What to fix first"), ("trend", "Trend"),
        ("topassets", "Top risky assets"), ("tier0", "Tier 0 exposure"), ("domains", "Risk by domain"), ("closure", "Opened and closed"),
    ];

    /// The fixed Monthly management pack: the Executive report's blocks, in its order (owner 2026-10-29).
    public static readonly IReadOnlyList<string> PackSections = ["protection", "patching", "exposure", "coverage", "identity", "cloud", "todo", "trend"];
    public const string PackTitle = "Monthly management pack";

    /// The chosen sections in the deck's order (unknown keys left out; none chosen = the pack's).
    public static IReadOnlyList<string> Normalize(IEnumerable<string>? keys)
    {
        var set = (keys ?? Array.Empty<string>()).Select(k => (k ?? "").Trim().ToLowerInvariant()).ToHashSet();
        var list = Sections.Select(s => s.Key).Where(set.Contains).ToList();
        return list.Count > 0 ? list : PackSections;
    }

    public static string SectionLabel(string key) => Sections.FirstOrDefault(s => s.Key == key).Label ?? key;

    /// What one deck is made with.
    public sealed record Options(string Title, string Audience, IReadOnlyList<string> Sections, string ProtectionView = "lifecycle", bool AiNotes = true);

    /// The figures a deck is built from (read once by <see cref="LoadAsync"/>; a fixture in the tests).
    public sealed class Inputs
    {
        public required ExecutiveFigures Figures { get; init; }
        public IReadOnlyList<ExecTopAsset>? TopAssets { get; init; }
        public string? TopAssetsNote { get; init; }
        public IReadOnlyList<TopRisk>? Ranked { get; init; }
        public IReadOnlyList<TrendPoint>? RiskTrend { get; init; }
        public IReadOnlyList<DomainTrendPoint>? Domains { get; init; }
        public IReadOnlyList<LifecycleBucket>? Closure { get; init; }
        public string? AiSummary { get; init; }
        public int? SeenDays { get; init; }
        public int CatchUpDays { get; init; } = ExecutiveFigures.DefaultCatchUpDays;
        /// A section whose figures could not be read: its slide says so (never the whole deck).
        public Dictionary<string, string> Errors { get; } = new(StringComparer.Ordinal);
        public DateTime NowUtc { get; init; } = DateTime.UtcNow;
    }

    /// The deck as bytes, its slide count and its file name.
    public sealed record Deck(byte[] Bytes, int Slides, int Charts, string FileName);

    // ---- reading the figures ---------------------------------------------------------------------------------------

    /// <summary>
    /// Reads what the chosen sections need -- the stored key figures of the run and the run compared with (as the Executive
    /// report), and only for the sections chosen: the run's Top risky assets, the tier-0 ranking (cached per data version,
    /// as the Tier-0 page), the daily domain aggregate, the daily opened / closed counts. Each read on its own: a read that
    /// fails is one "not available" slide. Never throws (but for a cancelled request).
    /// </summary>
    public static async Task<Inputs> LoadAsync(IServiceProvider services, string? collectionId, string? compareId, IReadOnlyList<string> sections, bool aiNotes,
        CancellationToken ct, ExecutiveFigures? figures = null)
    {
        var f = figures ?? await ExecutiveFigures.LoadAsync(services, collectionId, ct, compareId);
        var errors = new Dictionary<string, string>(StringComparer.Ordinal);
        IReadOnlyList<ExecTopAsset>? top = null; string? topNote = null; string? ai = null;
        IReadOnlyList<TopRisk>? ranked = null; IReadOnlyList<TrendPoint>? riskTrend = null;
        IReadOnlyList<DomainTrendPoint>? domains = null; IReadOnlyList<LifecycleBucket>? closure = null;

        if (sections.Contains("topassets") || aiNotes)
        {
            try
            {
                if (services.GetService(typeof(IRiskExecViews)) is IRiskExecViews views)
                {
                    var summaryOn = services.GetService(typeof(SI.Management.Web.Jobs.ISummaryStep)) is not SI.Management.Web.Jobs.ISummaryStep step || await step.IsOnAsync(ct);
                    var all = (await views.ViewsAsync(ct)).Data.Views;
                    var sel = RiskExecSelector.Select(all, RiskExecSelector.DefaultGrain(all, summaryOn), summaryOn);
                    if (aiNotes && sel.Figures is { AISummaryEnabled: true, AISummaryText: { Length: > 0 } text }) ai = text;
                    if (sections.Contains("topassets") && sel.Figures is { } fig && services.GetService(typeof(ExecViewLoader)) is ExecViewLoader loader)
                    {
                        var t = await loader.TopAssetsAsync(fig, 10, ct);
                        top = t.Assets; topNote = t.Note;
                    }
                    else if (sections.Contains("topassets") && sel.Figures is null) errors["topassets"] = "No Risk Analysis run has kept its view yet: the list comes with the next run.";
                }
                else if (sections.Contains("topassets")) errors["topassets"] = "The Risk Analysis view is not available in this installation.";
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { if (sections.Contains("topassets")) errors["topassets"] = "The Risk Analysis view could not be read: " + ex.Message; }
        }
        if (sections.Contains("tier0"))
        {
            try
            {
                if (services.GetService(typeof(IEstateQueries)) is IEstateQueries q)
                {
                    var cache = services.GetService(typeof(ViewResultCache)) as ViewResultCache;
                    var r = cache is null ? await q.RankedAssetsAsync(QueryParameters.MaxRanked, ct)
                        : await cache.GetAsync("tier0.ranked|" + QueryParameters.MaxRanked.ToString(CultureInfo.InvariantCulture), () => q.RankedAssetsAsync(QueryParameters.MaxRanked, ct), ct, x => x.Data.Count > 0);
                    ranked = r.Data;
                    riskTrend = (await q.RiskTrendAsync(90, ct)).Data;
                }
                else errors["tier0"] = "The tier-0 ranking is not available in this installation.";
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { errors["tier0"] = "The tier-0 ranking could not be read: " + ex.Message; }
        }
        if (sections.Contains("domains") || sections.Contains("closure"))
        {
            var q = services.GetService(typeof(IProDataQueries)) as IProDataQueries;
            if (sections.Contains("domains"))
            {
                try
                {
                    if (q is null) errors["domains"] = "The domain scores are not available in this installation.";
                    else domains = SI.Management.Web.Pages.Management.DomainsModel.Build((await q.TrendAsync(ProDataFilters.Normalize(new TrendRequest { Days = 90, Dimension = TrendDimensions.Domain, Measure = TrendMeasures.Score }), ct)).Data);
                }
                catch (Exception ex) when (ex is not OperationCanceledException) { errors["domains"] = "The domain scores could not be read: " + ex.Message; }
            }
            if (sections.Contains("closure"))
            {
                try
                {
                    if (q is null) errors["closure"] = "The opened and closed counts are not available in this installation.";
                    else closure = ProDataQueries.Bucket((await q.LifecycleAsync(91, ct)).Data, Grains.Week);
                }
                catch (Exception ex) when (ex is not OperationCanceledException) { errors["closure"] = "The opened and closed counts could not be read: " + ex.Message; }
            }
        }
        var (seen, catchUp) = await ExecutiveFigures.ScopeDaysAsync(services, ct);
        var inputs = new Inputs
        {
            Figures = f, TopAssets = top, TopAssetsNote = topNote, Ranked = ranked, RiskTrend = riskTrend, Domains = domains, Closure = closure,
            AiSummary = ai, SeenDays = seen, CatchUpDays = catchUp,
        };
        foreach (var (k, v) in errors) inputs.Errors[k] = v;
        return inputs;
    }

    // ---- the brand ---------------------------------------------------------------------------------------------------

    private static readonly Lazy<(byte[]? Png, byte[]? Svg)> Logo = new(() => (Resource("Presentation/logo.png"), Resource("Presentation/logo.svg")));

    private static byte[]? Resource(string name)
    {
        using var s = typeof(MgmtDeck).Assembly.GetManifestResourceStream(name);
        if (s is null) return null;
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.ToArray();
    }

    /// The Pro brand of a deck: Invardia's Pro horizontal colour logo (the brand pack's PNG, unchanged, with its SVG).
    public static PptxBrand Brand()
    {
        var (png, svg) = Logo.Value;
        var (w, h) = PngSize(png);
        return new PptxBrand(SI.Management.Web.Licensing.EditionBrand.ProProduct, png, w, h, svg);
    }

    /// The pixel size of a PNG (its IHDR), (0, 0) when it is not one.
    public static (int Width, int Height) PngSize(byte[]? png)
    {
        if (png is not { Length: >= 24 } || png[1] != (byte)'P' || png[2] != (byte)'N' || png[3] != (byte)'G') return (0, 0);
        static int Be(byte[] b, int i) => (b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3];
        return (Be(png, 16), Be(png, 20));
    }

    // ---- building ----------------------------------------------------------------------------------------------------

    /// Runs <paramref name="build"/> with the chosen number format (a <see cref="DisplayCulture.Supported"/> name; anything
    /// else keeps the request's), and puts the previous one back.
    public static T WithCulture<T>(string? culture, Func<T> build)
    {
        var name = DisplayCulture.Supported.FirstOrDefault(c => string.Equals(c, culture, StringComparison.OrdinalIgnoreCase));
        if (name is null) return build();
        var (ui, cur) = (CultureInfo.CurrentUICulture, CultureInfo.CurrentCulture);
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo(name);
            return build();
        }
        finally { CultureInfo.CurrentUICulture = ui; CultureInfo.CurrentCulture = cur; }
    }

    /// The deck's file name: "SecurityInsight - Monthly management pack - 2026-10-29.pptx" (no characters a file system refuses).
    public static string FileName(string title, DateTime nowUtc)
    {
        var t = new string(XlsxWriter.Clean(title).Select(c => Path.GetInvalidFileNameChars().Contains(c) || c is '"' or '<' or '>' or '|' or ':' or '*' or '?' or '\\' or '/' ? ' ' : c).ToArray()).Trim();
        if (t.Length > 80) t = t[..80].Trim();
        if (t.Length == 0) t = PackTitle;
        return "SecurityInsight - " + t + " - " + nowUtc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + ".pptx";
    }

    /// Builds the deck (with the culture in force: call it inside <see cref="WithCulture{T}"/>).
    public static Deck Build(Options o, Inputs d, PptxBrand brand)
    {
        var title = string.IsNullOrWhiteSpace(o.Title) ? PackTitle : o.Title.Trim();
        if (title.Length > 120) title = title[..120];
        using var ms = new MemoryStream();
        int slides, charts;
        using (var w = new PptxWriter(ms, brand, title, d.NowUtc))
        {
            new Builder(w, o with { Title = title, Audience = AudienceCode(o.Audience), Sections = Normalize(o.Sections) }, d).Run();
            w.Complete();
            slides = w.SlideCount; charts = w.ChartCount;
        }
        return new Deck(ms.ToArray(), slides, charts, FileName(title, d.NowUtc));
    }

    /// A slide title without the report's numbering ("1. Patching" -> "Patching").
    public static string SlideTitle(string blockTitle) => Regex.Replace(blockTitle ?? "", @"^\s*\d+\.\s*", "", RegexOptions.None, TimeSpan.FromSeconds(1)).Trim();

    public static PptxTone Tone(ChangeSince? c) => c?.Tone switch { "good" => PptxTone.Good, "bad" => PptxTone.Bad, "neutral" => PptxTone.Neutral, _ => PptxTone.None };

    /// A figure line as a card: its value, label and change.
    public static PptxCard Card(FigureLine l) => new(l.Value, l.Label, l.Change?.Text is { Length: > 0 } t ? t : null, Tone(l.Change));

    /// Is a line a number (a card)? A line with a raw value or a change; the others are words (an action, an explanation).
    public static bool IsFigure(FigureLine l) => l.Raw is not null || l.Change is not null;

    /// Is a line an action the slide itself must show ("Suggested action", "First: catch-up")?
    public static bool IsAction(FigureLine l) => l.Key.EndsWith(".action", StringComparison.Ordinal) || l.Key == "todo.catchup";

    /// The AI-written analysis as plain lines for the speaker notes (headings, bullets and links in words).
    public static string PlainText(string markdown)
    {
        var sb = new StringBuilder();
        foreach (var raw in (markdown ?? "").Replace("\r", "").Split('\n'))
        {
            var l = raw.TrimEnd();
            l = Regex.Replace(l, @"^\s*#{1,6}\s*", "", RegexOptions.None, TimeSpan.FromSeconds(1));
            l = Regex.Replace(l, @"\[([^\]]+)\]\((https?://[^)\s]+)\)", "$1 ($2)", RegexOptions.None, TimeSpan.FromSeconds(1));
            l = l.Replace("**", "").Replace("__", "");
            l = Regex.Replace(l, @"^(\s*)[*-]\s+", "$1- ", RegexOptions.None, TimeSpan.FromSeconds(1));
            sb.Append(l).Append('\n');
        }
        return sb.ToString().Trim();
    }

    /// <summary>
    /// A chart from a block's table: its bar values when it has them, else its first column that is a number in every row
    /// (as shown, in the culture in force). The first column names the bars; at most 10. Null when nothing is a number.
    /// </summary>
    public static PptxChart? ChartFrom(FigureTable t, int top = 10)
    {
        if (t.Rows.Count < 1) return null;
        var rows = t.Rows.Take(top).ToList();
        string Cat(IReadOnlyList<string> r) => t.Key == "matrix" && r.Count > 1 ? r[0] + " · " + r[1] : r.Count > 0 ? r[0] : "";
        if (t.Bars is { Count: > 0 } bars && bars.Take(rows.Count).Any(b => b > 0))
        {
            var pct = t.Key.StartsWith("protection", StringComparison.Ordinal);
            var name = t.Headers.Count > 1 ? t.Headers[pct ? 1 : FirstNumeric(t) ?? 1] : "Value";
            return new PptxChart(PptxChartKind.Bar, t.Title, rows.Select(Cat).ToList(), [new PptxSeries(name, bars.Take(rows.Count).Select(b => (double?)b).ToList())], pct ? "0.0" : "#,##0");
        }
        if (FirstNumeric(t) is not { } col) return null;
        var values = rows.Select(r => Number(r[col])).ToList();
        if (!values.Any(v => v is > 0)) return null;
        return new PptxChart(PptxChartKind.Bar, t.Title, rows.Select(Cat).ToList(), [new PptxSeries(t.Headers[col], values)]);
    }

    private static int? FirstNumeric(FigureTable t)
    {
        for (var c = 1; c < t.Headers.Count; c++)
            if (t.Rows.Take(10).All(r => c < r.Count && Number(r[c]) is not null)) return c;
        return null;
    }

    /// A number as shown ("1,234", "1.234", "12.5 %", "53,7 %"), in the culture in force; null when it is not one.
    public static double? Number(string? shown)
    {
        var s = (shown ?? "").Trim().Replace(" ", " ").Replace(" ", " ");
        if (s.Length == 0 || !(char.IsDigit(s[0]) || (s[0] == '-' && s.Length > 1 && char.IsDigit(s[1])))) return null;
        s = s.TrimEnd('%').Trim();
        return double.TryParse(s, NumberStyles.Number, CultureInfo.CurrentCulture, out var v) && double.IsFinite(v) ? v : null;
    }

    // ---- the slides ------------------------------------------------------------------------------------------------

    private sealed class Builder(PptxWriter w, Options o, Inputs d)
    {
        private ExecutiveFigures F => d.Figures;
        private bool Tables => o.Audience != Board;
        private int MaxTables => o.Audience == It ? 6 : 2;
        private string Scope => F.ScopeLine(d.SeenDays, d.CatchUpDays);
        private string RunDay => F.Current is { } c ? Fmt.Day(DateOnly.FromDateTime(c.CollectionTime)) : "–";

        public void Run()
        {
            var audience = AudienceLabel(o.Audience);
            var lines = new List<string> { "Prepared for: " + audience };
            if (F.Current is not null) lines.Add("Data: the run of " + RunDay + (F.Since is { } since ? ", compared with the run of " + since : ""));
            lines.Add("Made on " + Fmt.Day(DateOnly.FromDateTime(d.NowUtc)) + " with " + SI.Management.Web.Licensing.EditionBrand.ProProduct);
            w.AddTitleSlide(o.Title, "Security status" + (F.Current is null ? "" : " · " + RunDay), lines,
                "This presentation was made from the stored figures of SecurityInsight. Each slide's explanation is in its speaker notes.\n" + Scope);
            w.AddAgendaSlide("Contents", new[] { "Key figures" }.Concat(o.Sections.Select(SectionLabel)).Concat(["About these figures"]).ToList(),
                "The sections of this presentation, in order. " + (o.Audience == Board ? "Made for the board: number cards and charts." : o.Audience == It ? "Made for IT management: with the tables and the patching groups." : "Made for management: number cards, charts and the top-10 tables."));
            KeyFigures();
            foreach (var key in o.Sections)
            {
                switch (key)
                {
                    case "topassets": TopAssets(); break;
                    case "tier0": Tier0(); break;
                    case "domains": Domains(); break;
                    case "closure": Closure(); break;
                    default:
                        foreach (var b in F.ReportBlocks(k => k == key, o.ProtectionView))
                            if (o.Audience == It || !b.Key.StartsWith("group-", StringComparison.Ordinal)) Block(b);
                        break;
                }
            }
            About();
        }

        private void NotAvailable(string title, string why) =>
            w.AddContentSlide(title, null, [], null, null, ["Not available: " + why], title + ": not available. " + why);

        private void KeyFigures()
        {
            if (!F.Ready) { NotAvailable("Key figures", F.Missing ?? "the key figures are not available yet."); return; }
            var heads = ExecutiveFigures.Headlines.Select(h => F.Headline(h.Key)).ToList();
            var notes = new StringBuilder("The headline figures of the run, each with its change since the run it is compared with.\n");
            foreach (var l in heads) notes.Append(l.Label).Append(": ").Append(l.Value).Append(l.Change?.Text is { Length: > 0 } c ? " (" + c + ")" : "").Append('\n');
            notes.Append(ExecutiveFigures.LifecycleName).Append(": accepted lifecycle ").Append(F.Grace).Append(" (per your settings).\n");
            notes.Append(Scope);
            if (F.CompareNote is { } cn) notes.Append('\n').Append(cn);
            if (d.AiSummary is { Length: > 0 } ai) notes.Append("\n\nThe analysis of the Risk Analysis run (written by AI):\n").Append(PlainText(ai));
            w.AddContentSlide("Key figures", "The run of " + RunDay + (F.Since is { } s ? ", compared with " + s : ""), heads.Select(Card).ToList(), ProtectionTrend(), null, null, notes.ToString());
        }

        /// The two Protection Scores over the kept runs (oldest first), when there are at least two.
        private PptxChart? ProtectionTrend()
        {
            var runs = F.Trend.GroupBy(p => p.CollectionId).OrderBy(g => g.First().CollectionTime).ToList();
            if (runs.Count < 2) return null;
            double? V(IGrouping<string, KeyFigurePoint> g, string f) => g.FirstOrDefault(p => p.Figure == f) is { Available: true, Value: { } v } ? Math.Round(v, 1) : null;
            return new PptxChart(PptxChartKind.Line, "Protection Score over the last 90 days (%)", runs.Select(g => Fmt.Day(DateOnly.FromDateTime(g.First().CollectionTime))).ToList(),
                [new PptxSeries(ExecutiveFigures.LifecycleName, runs.Select(g => V(g, "protection_lifecycle")).ToList()),
                 new PptxSeries(ExecutiveFigures.ActualName, runs.Select(g => V(g, "protection_technical")).ToList())], "0.0");
        }

        private PptxChart? TrendChart()
        {
            var runs = F.Trend.GroupBy(p => p.CollectionId).OrderBy(g => g.First().CollectionTime).ToList();
            if (runs.Count < 2) return null;
            double? V(IGrouping<string, KeyFigurePoint> g, string f) => g.FirstOrDefault(p => p.Figure == f) is { Available: true, Value: { } v } ? Math.Round(v) : null;
            return new PptxChart(PptxChartKind.Line, "Very High + High findings and known exploited CVEs, last 90 days", runs.Select(g => Fmt.Day(DateOnly.FromDateTime(g.First().CollectionTime))).ToList(),
                [new PptxSeries("Very High + High", runs.Select(g => V(g, "very_high_high")).ToList()), new PptxSeries("Known exploited CVEs", runs.Select(g => V(g, "known_exploited")).ToList(), PptxWriter.BadColor)]);
        }

        private void Block(ReportBlock b)
        {
            var title = SlideTitle(b.Title);
            if (b.Unavailable is not null) { NotAvailable(title, b.Unavailable); return; }
            var cards = b.Lines.Where(IsFigure).Select(Card).ToList();
            var actions = b.Lines.Where(l => !IsFigure(l) && IsAction(l)).Select(l => l.Label + ": " + l.Value).ToList();
            var tables = b.Tables.Where(t => t.Rows.Count > 0).ToList();
            var chart = b.Key switch
            {
                "protection" => ProtectionTrend() ?? tables.Select(t => ChartFrom(t)).FirstOrDefault(c => c is not null),
                "trend" => TrendChart(),
                _ => tables.Select(t => ChartFrom(t)).FirstOrDefault(c => c is not null),
            };
            var notes = new StringBuilder(title).Append(".\n");
            foreach (var l in b.Lines)
                notes.Append(l.Label).Append(": ").Append(l.Value).Append(l.Change?.Text is { Length: > 0 } c ? " (" + c + ")" : "").Append(l.Note is { Length: > 0 } n ? " -- " + n : "").Append('\n');
            foreach (var t in b.Tables.Where(t => t.Note is not null)) notes.Append(t.Title).Append(": ").Append(t.Note).Append('\n');
            notes.Append(Scope);
            var noteText = notes.ToString();
            // a block without a card or a chart (only a table, e.g. the trend of a first run) shows its first table even to the board
            var tableHere = chart is null && cards.Count == 0 && tables.Count > 0 ? Table(tables[0]) : null;
            w.AddContentSlide(title, null, cards.Take(PptxWriter.MaxCards).ToList(), chart, tableHere, actions, noteText);
            if (cards.Count > PptxWriter.MaxCards)
                w.AddContentSlide(title + " (continued)", null, cards.Skip(PptxWriter.MaxCards).Take(PptxWriter.MaxCards).ToList(), null, null, null, noteText);
            if (!Tables) return;
            foreach (var x in tables.Where(t => tableHere is null || !ReferenceEquals(t, tables[0])).Take(MaxTables))
                w.AddContentSlide(title + ": " + x.Title, null, [], null, Table(x), x.Note is null ? null : new[] { x.Note }, x.Title + ". The first 10 rows, as SecurityInsight shows them.\n" + (x.Note is null ? "" : x.Note + "\n") + Scope);
        }

        /// A table's top 10 rows, at most 7 columns.
        private static PptxTable Table(FigureTable t) =>
            new(t.Title, t.Headers.Take(7).ToList(), t.Rows.Take(10).Select(r => (IReadOnlyList<string>)r.Take(7).ToList()).ToList());

        private void TopAssets()
        {
            const string title = "Top risky assets";
            if (d.Errors.TryGetValue("topassets", out var err)) { NotAvailable(title, err); return; }
            var list = (d.TopAssets ?? Array.Empty<ExecTopAsset>()).Take(10).ToList();
            if (list.Count == 0) { NotAvailable(title, d.TopAssetsNote ?? "the run kept no list of risky assets."); return; }
            var tier0 = list.Count(a => SI.Management.Web.Pages.Management.Tier0Model.IsTier0(a.Tier));
            var cards = new List<PptxCard> { new(Fmt.Int(list.Count), "Assets in this list"), new(Fmt.Int(tier0), "Of them Tier 0") };
            var chart = new PptxChart(PptxChartKind.Bar, "Weighted risk score, the 10 riskiest assets", list.Select(a => a.Asset).ToList(),
                [new PptxSeries("Weighted risk score", list.Select(a => (double?)Math.Round(a.WeightedRiskScore)).ToList())]);
            var notes = "The riskiest assets of the last Risk Analysis run, in its order -- the same list as Top risky assets in SecurityInsight."
                + (d.TopAssetsNote is { } n ? "\n" + n : "") + "\n" + string.Join("\n", list.Select(a => a.Rank.ToString(CultureInfo.InvariantCulture) + ". " + a.Asset + " (" + TierWords(a.Tier) + "): weighted risk " + Fmt.Score(a.WeightedRiskScore) + ", " + Fmt.Int(a.Findings) + " findings"));
            w.AddContentSlide(title, null, cards, chart, null, null, notes);
            if (Tables)
                w.AddContentSlide(title + ": the list", null, [], null, new PptxTable("The 10 riskiest assets", ["#", "Asset", "Tier", "Weighted risk", "Findings", "Domains"],
                    list.Select(a => (IReadOnlyList<string>)[a.Rank.ToString(CultureInfo.InvariantCulture), a.Asset, TierWords(a.Tier), Fmt.Score(a.WeightedRiskScore), Fmt.Int(a.Findings), string.Join(", ", a.Domains)]).ToList()), null, notes);
        }

        private static string TierWords(string? tier) => string.IsNullOrWhiteSpace(tier) ? "Unclassified" : tier.Trim().StartsWith("Tier", StringComparison.OrdinalIgnoreCase) ? tier.Trim() : "Tier " + tier.Trim();

        private void Tier0()
        {
            const string title = "Tier 0 exposure";
            if (d.Errors.TryGetValue("tier0", out var err)) { NotAvailable(title, err); return; }
            var t0 = (d.Ranked ?? Array.Empty<TopRisk>()).Where(r => SI.Management.Web.Pages.Management.Tier0Model.IsTier0(r.Tier)).OrderBy(r => r.Rank).ToList();
            var inTop = t0.Count(SI.Management.Web.Pages.Management.Tier0Model.InTop);
            var cards = new List<PptxCard>
            {
                new(Fmt.Int(t0.Count), "Tier-0 assets with findings"),
                new(Fmt.Int(inTop), "Of them among the " + SI.Management.Web.Pages.Management.Tier0Model.TopN.ToString(CultureInfo.InvariantCulture) + " riskiest assets"),
            };
            var pts = (d.RiskTrend ?? Array.Empty<TrendPoint>()).OrderBy(p => p.Day).ToList();
            PptxChart? chart = pts.Count >= 2
                ? new PptxChart(PptxChartKind.Line, "Tier-0 assets with findings per day, last 90 days", pts.Select(p => Fmt.Day(p.Day)).ToList(), [new PptxSeries("Tier-0 assets with findings", pts.Select(p => (double?)p.Tier0Exposed).ToList())])
                : t0.Count > 0 ? new PptxChart(PptxChartKind.Bar, "Weighted risk score of the riskiest tier-0 assets", t0.Take(10).Select(r => r.AssetName).ToList(), [new PptxSeries("Weighted risk score", t0.Take(10).Select(r => (double?)Math.Round(r.WeightedRiskScore)).ToList())]) : null;
            var notes = "Tier 0 = the assets that control the estate (identity, management). The ranking is the estate's ranking by weighted risk score -- the same as the Tier-0 exposure page.\n"
                + string.Join("\n", t0.Take(10).Select(r => "#" + r.Rank.ToString(CultureInfo.InvariantCulture) + " " + r.AssetName + ": weighted risk " + Fmt.Score(r.WeightedRiskScore) + ", " + Fmt.Int(r.Findings) + " findings"));
            w.AddContentSlide(title, null, cards, chart, null, t0.Count == 0 ? new[] { "No tier-0 asset has findings in the newest collection." } : null, notes);
            if (Tables && t0.Count > 0)
                w.AddContentSlide(title + ": the riskiest tier-0 assets", null, [], null, new PptxTable("The riskiest tier-0 assets", ["Estate rank", "Asset", "Weighted risk", "Findings", "Domains"],
                    t0.Take(10).Select(r => (IReadOnlyList<string>)[r.Rank.ToString(CultureInfo.InvariantCulture), r.AssetName, Fmt.Score(r.WeightedRiskScore), Fmt.Int(r.Findings), string.Join(", ", r.Domains)]).ToList()), null, notes);
        }

        private void Domains()
        {
            const string title = "Risk by domain";
            if (d.Errors.TryGetValue("domains", out var err)) { NotAvailable(title, err); return; }
            var pts = d.Domains ?? Array.Empty<DomainTrendPoint>();
            var rows = pts.Select(p => p.Domain).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase).Select(dom =>
            {
                var mine = pts.Where(p => p.Domain.Equals(dom, StringComparison.OrdinalIgnoreCase)).OrderBy(p => p.Day).ToList();
                return (Domain: dom, Now: mine.Last().AverageRiskScore, Then: mine.Count > 1 ? mine.First().AverageRiskScore : null, mine.Last().Findings);
            }).OrderByDescending(r => r.Now ?? 0).ToList();
            if (rows.Count == 0) { NotAvailable(title, "no domain scores in the last 90 days."); return; }
            var chart = new PptxChart(PptxChartKind.Bar, "Average risk score per finding, per domain (newest day)", rows.Take(10).Select(r => r.Domain).ToList(),
                [new PptxSeries("Average risk score per finding", rows.Take(10).Select(r => r.Now is { } v ? (double?)ScoreFormat.Round(v) : null).ToList())]);
            var notes = "The average risk score per finding in each security domain -- the same daily aggregate as the Domains page. Lower is better.\n"
                + string.Join("\n", rows.Select(r => r.Domain + ": " + Fmt.Score(r.Now) + " now" + (r.Then is { } t ? ", " + Fmt.Score(t) + " 90 days ago" : "") + ", " + Fmt.Int(r.Findings) + " findings"));
            w.AddContentSlide(title, null, [], chart, null, null, notes);
            if (Tables)
                w.AddContentSlide(title + ": the figures", null, [], null, new PptxTable("Per domain", ["Domain", "Average risk now", "90 days ago", "Findings"],
                    rows.Take(10).Select(r => (IReadOnlyList<string>)[r.Domain, Fmt.Score(r.Now), r.Then is { } t ? Fmt.Score(t) : "–", Fmt.Int(r.Findings)]).ToList()), null, notes);
        }

        private void Closure()
        {
            const string title = "Opened and closed";
            if (d.Errors.TryGetValue("closure", out var err)) { NotAvailable(title, err); return; }
            var b = (d.Closure ?? Array.Empty<LifecycleBucket>()).ToList();
            if (b.Count == 0) { NotAvailable(title, "no vulnerability was opened or closed in the last 90 days."); return; }
            var openNow = b.LastOrDefault(x => x.OpenAtEnd is not null)?.OpenAtEnd;
            var cards = new List<PptxCard>
            {
                new(Fmt.Int(b.Sum(x => x.Opened)), "New vulnerabilities, last 90 days"),
                new(Fmt.Int(b.Sum(x => x.Closed)), "Closed, last 90 days"),
                new(Fmt.Int(b.Sum(x => x.Reopened)), "Reopened, last 90 days"),
                new(Fmt.Int(openNow), "Open now"),
            };
            var chart = new PptxChart(PptxChartKind.Column, "New and closed vulnerabilities per week", b.Select(x => x.Label).ToList(),
                [new PptxSeries("New", b.Select(x => (double?)x.Opened).ToList(), PptxWriter.BadColor), new PptxSeries("Closed", b.Select(x => (double?)x.Closed).ToList(), PptxWriter.GoodColor)]);
            var notes = "New, closed and reopened vulnerabilities per week over the last 90 days -- the same daily counts as Opened and closed in SecurityInsight. Closed counts every close (fixed, asset retired, other reason).\n"
                + string.Join("\n", b.Select(x => x.Label + ": " + Fmt.Int(x.Opened) + " new, " + Fmt.Int(x.Closed) + " closed, " + Fmt.Int(x.Reopened) + " reopened"));
            w.AddContentSlide(title, null, cards, chart, null, null, notes);
        }

        private void About()
        {
            var lines = new List<string>
            {
                Scope,
                ExecutiveFigures.LifecycleName + ": a patch finding younger than its accepted lifecycle (" + F.Grace + ", per your settings) does not count; " + ExecutiveFigures.ActualName + ": every finding counts.",
                "Every number is a stored figure of the run -- the same numbers as Executive report > Key figures in SecurityInsight.",
            };
            if (F.CompareNote is { } cn) lines.Add(cn);
            w.AddContentSlide("About these figures", null, [], null, null, lines,
                "Where the numbers come from and what they leave out. Open SecurityInsight > " + SI.Management.Web.Navigation.NavModel.PathOf("/Management/Report") + " to see each number and open the findings behind it.");
        }
    }
}
