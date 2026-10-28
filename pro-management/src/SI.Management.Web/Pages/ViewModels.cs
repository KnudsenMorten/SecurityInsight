using System.Globalization;
using SI.Management.Core;

namespace SI.Management.Web.Pages;

/// "The query behind this": every chart and table on every page shows the query that produced it. <see cref="Label"/>
/// names the section it feeds ("Plan, halts and push summaries"); the page lists every query ONCE, at the bottom, in
/// one disclosure (<see cref="PageQueries"/>; operator 2026-10-04: "one is enough").
public sealed record QueryInfo(string Query, string Source, DateTimeOffset? AsOf, string? Label = null)
{
    public static QueryInfo From<T>(QueryResult<T> r, string? label = null) => new(r.Query, r.Source, r.AsOf, label);
    public static QueryInfo Sql(string query, string? label = null) => new(query, "Pro database (SQL)", DateTimeOffset.UtcNow, label);
    /// The same query, labelled with the section it feeds.
    public QueryInfo For(string label) => this with { Label = label };
}

/// <summary>
/// The queries one page ran, collected while the page renders (the _Query partial ADDS here, it renders nothing) and
/// shown once by the layout: ONE "The query behind this" disclosure per page, at the bottom, each query labelled with
/// the section it feeds. The same query text twice (two cards fed by one read) is listed once with both labels -- so no
/// page shows two identical disclosures, and no card holds only a disclosure.
/// </summary>
public sealed class PageQueries
{
    private const string Key = "si-page-queries";
    private readonly List<(QueryInfo Info, List<string> Labels)> _items = new();

    public static PageQueries For(HttpContext ctx)
    {
        if (ctx.Items[Key] is PageQueries q) return q;
        q = new PageQueries();
        ctx.Items[Key] = q;
        return q;
    }

    public void Add(QueryInfo q, string? fallbackLabel)
    {
        if (string.IsNullOrWhiteSpace(q.Query)) return;
        var label = string.IsNullOrWhiteSpace(q.Label) ? fallbackLabel : q.Label;
        var hit = _items.FindIndex(i => string.Equals(i.Info.Query.Trim(), q.Query.Trim(), StringComparison.Ordinal));
        if (hit < 0) { _items.Add((q, label is null ? new List<string>() : new List<string> { label })); return; }
        if (label is not null && !_items[hit].Labels.Contains(label, StringComparer.OrdinalIgnoreCase)) _items[hit].Labels.Add(label);
    }

    /// Each distinct query with the sections it feeds (empty = the page as a whole).
    public IReadOnlyList<(QueryInfo Info, IReadOnlyList<string> Labels)> Items => _items.Select(i => (i.Info, (IReadOnlyList<string>)i.Labels)).ToList();
}

/// A period chooser: links ?<param>=<choice>.
public sealed record RangeInfo(int Current, int[] Choices, string Unit, string Param);

public sealed record ChartSeries(string Name, IReadOnlyList<double?> Data, int Slot);

/// A chart for wwwroot/js/site.js: rendered as a canvas + a JSON spec block, with an HTML legend when there are two or
/// more series. <c>TimeLabels</c>: the labels are UTC moments (ISO with Z) the browser shows in the viewer's zone (#313).
public sealed record ChartSpec(string Id, string Type, IReadOnlyList<string> Labels, IReadOnlyList<ChartSeries> Series, string? YLabel = null, string? AriaLabel = null, bool TimeLabels = false);

/// <summary>
/// The page formatters. NUMBERS follow the viewer's regional format (the request's display culture, from the browser's
/// Accept-Language -- see <see cref="DisplayCulture"/>): 12,205 in the USA, 12.205 in Denmark. Dates stay ISO;
/// TIMES are shown in the browser's own zone (<see cref="Time(DateTime?, string, bool, bool, string)"/>, BRAND-2.10).
/// One shared implementation underneath (<see cref="SI.Management.Core.ProData.ScoreFormat"/>).
/// </summary>
public static class Fmt
{
    private static CultureInfo C => SI.Management.Core.ProData.ScoreFormat.Culture;
    public static string Day(DateOnly d) => d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
    public static string Num(double v, int decimals = 1) => v.ToString("N" + decimals, C);
    /// A risk score on screen (a finding's, a weighted risk, an average, a highest): a whole number, grouped per the
    /// viewer's culture -- "2,293" / "2.293". Exports keep the raw number.
    public static string Score(double? v) => SI.Management.Core.ProData.ScoreFormat.Whole(v);
    public static string SignedScore(double v) => SI.Management.Core.ProData.ScoreFormat.SignedWhole(v);
    public static string Int(long v) => v.ToString("N0", C);
    /// A count that may be unknown (#295: a day whose distinct asset counts are not computed yet) -- "–", never 0.
    public static string Int(long? v) => v is { } x ? Int(x) : "–";
    /// A moment a person reads, as the &lt;time&gt; element the browser shows in ITS OWN time zone (BRAND-2.10, #313):
    /// "2026-10-04 20:54" in Denmark for a value stored 18:54 UTC. <c>zone</c>: a small zone label + the UTC value in
    /// the tooltip (audit / evidence views). See <see cref="LocalTime"/>.
    public static Microsoft.AspNetCore.Html.IHtmlContent Time(DateTime? v, string fmt = "datetime", bool zone = false, bool seconds = false, string empty = "") => LocalTime.Tag(v, fmt, zone, seconds, empty);
    public static Microsoft.AspNetCore.Html.IHtmlContent Time(DateTimeOffset? v, string fmt = "datetime", bool zone = false, bool seconds = false, string empty = "") => LocalTime.Tag(v, fmt, zone, seconds, empty);
    /// The UTC TEXT of a moment ("2026-10-04 18:54 UTC") -- only for a place that cannot hold an element (an option's
    /// text, a tooltip, a sentence built in C#), and only inside an element marked data-utc, which the browser formatter
    /// rewrites to the viewer's zone (#313). Exports, mails and generated files keep their own formats.
    public static string When(DateTimeOffset v) => LocalTime.Text(v);
    public static string When(DateTime v) => When((DateTime?)v);
    public static string When(DateTime? v) => LocalTime.Text(v);
    public static string Signed(double v, int decimals = 1) => (v > 0 ? "+" : "") + v.ToString("N" + decimals, C);
    /// A percentage on screen, in the viewer's format: "12,5 %" / "12.5%" (value in percent, not a fraction).
    public static string Pct(double v, int decimals = 0) => (v / 100).ToString("P" + decimals, C);
    /// The RAW number for a machine-read attribute (data-value on a sortable table cell, a chart spec): invariant, no
    /// grouping -- never shown to a person.
    public static string Raw(double? v) => v is { } d && double.IsFinite(d) ? d.ToString("0.######", CultureInfo.InvariantCulture) : "";
    public static string Raw(long v) => v.ToString(CultureInfo.InvariantCulture);
    /// #321: a number filter that came in by URL (a drilldown, a saved link) as a chip says it in words, in the viewer's
    /// number format: "1", "at least 7", "at most 1", "2 to 5". There is no box to type one into -- number columns sort only.
    public static string RangeWords(double? lo, double? hi)
    {
        static string N(double v) => v.ToString("#,##0.##", C);
        return (lo, hi) switch
        {
            ({ } l, { } h) when l == h => N(l),
            ({ } l, { } h) => N(l) + " to " + N(h),
            ({ } l, null) => "at least " + N(l),
            (null, { } h) => "at most " + N(h),
            _ => "any",
        };
    }

    /// The allowed range choices, so a query-string value cannot ask the query layer for an arbitrary window.
    public static int Pick(int requested, int fallback, params int[] allowed) => allowed.Contains(requested) ? requested : fallback;
}
