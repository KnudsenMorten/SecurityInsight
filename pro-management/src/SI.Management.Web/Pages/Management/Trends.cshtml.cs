using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Export;

namespace SI.Management.Web.Pages.Management;

/// <summary>
/// Trends (Pro; the menu's Changes &amp; trends > Trends, was "Trend analytics"): any dimension (asset tier, recommendation severity, security domain, report) over time,
/// filtered by the others, from the PRE-COMPUTED sidata.FindingDaily table (never the finding rows). A day links to
/// that day's collection in the findings browser. Not to be confused with Community's "Risk trend (daily summary)".
/// </summary>
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Management)]
public sealed class TrendsModel : PageModel
{
    public const int MaxSeries = 5;
    private readonly IProDataQueries _q;
    private readonly ILogger<TrendsModel> _log;
    public TrendsModel(IProDataQueries q, ILogger<TrendsModel> log) { _q = q; _log = log; }

    [BindProperty(SupportsGet = true)] public int Days { get; set; } = 90;
    [BindProperty(SupportsGet = true)] public string? Dim { get; set; }
    [BindProperty(SupportsGet = true)] public string? Measure { get; set; }
    [BindProperty(SupportsGet = true)] public string? Tier { get; set; }
    [BindProperty(SupportsGet = true)] public string? Sev { get; set; }
    [BindProperty(SupportsGet = true)] public string? Dom { get; set; }
    [BindProperty(SupportsGet = true)] public string? Rep { get; set; }

    public IReadOnlyList<TrendCell> Cells { get; private set; } = Array.Empty<TrendCell>();
    public IReadOnlyList<string> Series { get; private set; } = Array.Empty<string>();
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Facets { get; private set; } = new Dictionary<string, IReadOnlyList<string>>();
    public ChartSpec? Chart { get; private set; }
    public QueryInfo? Query { get; private set; }
    public string? Error { get; private set; }

    /// One cell's value of the chosen measure (the risk score per finding or at its highest, never summed).
    public double Value(TrendCell c) => TrendMath.Combine(new[] { c }, Measure ?? TrendMeasures.Findings) ?? 0;

    /// Several cells as ONE value of the chosen measure: counts add up, an average is re-computed from the parts,
    /// the highest stays the highest.
    public double? Combine(IEnumerable<TrendCell> cells) => TrendMath.Combine(cells, Measure ?? TrendMeasures.Findings);

    public string MeasureLabel => TrendMath.Label(Measure);

    /// #855 (owner 2026-10-21: "default filter is active, so it should be active only"): the CI lifecycle the trend counts --
    /// the address's lifecycle parameter, else the findings of ACTIVE CIs only (FindingDaily / AssetDaily carry it as a key).
    public LifecycleFilter Lifecycle => SI.Management.Web.Pages.LifecycleChoice.Read(HttpContext?.Request);

    /// The lifecycle rules in force (the words of the scope line, never a literal day count); the defaults until read.
    public CiLifecycleRules LifecycleRules { get; private set; } = CiLifecycleDefinitions.Defaults;

    /// The "What you're looking at" line: the lifecycle the trend counts, with the definitions from the settings.
    public SI.Management.Web.Pages.ViewScope Scope => new()
    {
        Lifecycle = Lifecycle.Words(LifecycleRules, "Findings"), LifecycleDefaulted = Lifecycle.IsDefault, Definitions = LifecycleRules.Definitions,
    };

    private string? Joined(string key, string? bound)
    {
        var values = HttpContext?.Request.Query[key];
        if (values is not { Count: > 1 } v) return bound;
        var joined = string.Join(ProDataFilters.ValueSeparator, v.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!.Trim()));
        return joined.Length == 0 ? null : joined;
    }

    /// The chosen values of one filter (tier, sev, dom, rep).
    public IReadOnlyList<string> Chosen(string key) => ProDataFilters.Values(key switch { "tier" => Tier, "sev" => Sev, "dom" => Dom, "rep" => Rep, _ => null });

    private static string? Or(string? joined) => joined is null ? null : string.Join(" or ", ProDataFilters.Values(joined));

    /// A combined value as the chart draws it: a risk score measure as a whole number (the shared score format).
    public double? Shown(IEnumerable<TrendCell> cells) =>
        Measure is TrendMeasures.Score or TrendMeasures.MaxScore ? ScoreFormat.Round(Combine(cells)) : Combine(cells);

    public async Task OnGetAsync(CancellationToken ct)
    {
        Days = Fmt.Pick(Days, 90, 30, 90, 180, 365);
        // every filter takes several values (owner 2026-10-19): one parameter per value; the model binds the first only
        (Tier, Sev, Dom, Rep) = (Joined("tier", Tier), Joined("sev", Sev), Joined("dom", Dom), Joined("rep", Rep));
        Dim = ProDataFilters.Pick(Dim, TrendDimensions.All, TrendDimensions.Tier);
        Measure = ProDataFilters.Pick(Measure, TrendMeasures.All, TrendMeasures.Findings);
        try { if (HttpContext?.RequestServices.GetService<ICiLifecycleRulesReader>() is { } lr) LifecycleRules = await lr.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the lifecycle settings could not be read; the defaults are said"); }
        try
        {
            var req = ProDataFilters.Normalize(new TrendRequest { Days = Days, Dimension = Dim, Measure = Measure, Tier = Tier, Severity = Sev, Domain = Dom, Report = Rep, Lifecycle = Lifecycle });
            var r = await _q.TrendAsync(req, ct);
            Cells = r.Data;
            Query = QueryInfo.Sql(r.Query);
            try { Facets = (await _q.FacetsAsync(ct)).Data; } catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "facets"); }
            Build();
        }
        catch (ArgumentException ex) { Error = "The filter is not valid: " + ex.Message; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "trend analytics failed");
            Error = "The trend could not be read: " + ex.Message;
        }
    }

    /// Excel workbook of the current trend: the chosen dimension, measure, period and filters -- every day and every
    /// group (the chart folds small groups into "Other"; the workbook does not).
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        await OnGetAsync(ct);
        if (Error is not null && Cells.Count == 0 && Error.StartsWith("The filter", StringComparison.Ordinal)) return BadRequest(Error);
        return await ExcelExport.FileAsync("trends", null, (x, info) =>
        {
            info.Add("Split by", Dim).Add("Measure", MeasureLabel).Add("Period (days)", Days)
                .Filter("Asset tier", Or(Tier)).Filter("Severity", Or(Sev)).Filter("Security domain", Or(Dom)).Filter("Report", Or(Rep))
                .Add("CI lifecycle", Lifecycle.Words(LifecycleRules, "Findings"));
            if (Error is not null) info.Notes.Add(Error);
            var group = Dim switch
            {
                TrendDimensions.Tier => "Asset tier", TrendDimensions.Severity => "Severity", TrendDimensions.Domain => "Security domain",
                TrendDimensions.Report => "Report", _ => "Group",
            };
            x.Sheet(info, "Trend", new[] { "Day", group, "Findings", "Assets with findings", "Average risk score per finding", "Highest risk score", "Very High + High findings", "Collection" },
                Cells.OrderBy(c => c.Day).ThenBy(c => c.Dimension, GroupOrder).Select(c => new object?[]
                {
                    c.Day, Dim == TrendDimensions.Tier ? ExcelExport.Tier(c.Dimension) : Label(c.Dimension), c.Findings, c.Assets,
                    c.ScoreAverage, c.ScoreMax, c.TopSeverityFindings, c.CollectionId,
                }));
            return Task.CompletedTask;
        }, ct);
    }

    /// #334: the split dimensions drawn as trend cards (one card per group, own scale) instead of a multi-line chart.
    /// A report split keeps the line chart: it can hold dozens of reports, folded into "Other".
    public static bool DrawsCards(string? dim) => dim is TrendDimensions.Tier or TrendDimensions.Severity or TrendDimensions.Domain or TrendDimensions.None;

    /// The trend cards (null = this split draws the line chart).
    public TrendCardSet? Cards { get; private set; }

    /// The measures that are COUNTS: a group missing from a day had none that day (0). The score measures have no value
    /// on such a day (a gap in the sparkline, never 0).
    private bool CountMeasure => Measure is TrendMeasures.Findings or TrendMeasures.TopSeverity or TrendMeasures.Assets;

    private void BuildCards()
    {
        var days = Cells.Select(c => c.Day).Distinct().OrderBy(d => d).ToList();
        IEnumerable<string> groups = Dim switch
        {
            // one card per tier, always all five (a filtered tier: that one), in the Tier board's order
            TrendDimensions.Tier => string.IsNullOrEmpty(Tier) ? ProDataFilters.Tiers : ProDataFilters.Tiers.Where(t => Chosen("tier").Contains(t)),
            TrendDimensions.Severity => Cells.Select(c => c.Dimension).Distinct(StringComparer.Ordinal).OrderBy(x => x, SeverityOrder.Comparer),
            TrendDimensions.None => Cells.Select(c => c.Dimension).Distinct(StringComparer.Ordinal).Take(1).DefaultIfEmpty(""),
            _ => Cells.Select(c => c.Dimension).Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.OrdinalIgnoreCase),
        };
        var cards = groups.Select((g, i) =>
        {
            var mine = Cells.Where(c => Dim == TrendDimensions.None || c.Dimension == g).ToList();
            var values = days.Select(d => mine.Where(c => c.Day == d).ToList() is { Count: > 0 } dc ? Shown(dc) : CountMeasure ? 0 : (double?)null).ToList();
            var tone = Dim switch
            {
                TrendDimensions.Tier => TrendCardMath.TierTone(g),
                TrendDimensions.Severity => TrendCardMath.SeverityTone(g),
                TrendDimensions.None => "s1",
                _ => "s" + (i % 6 + 1),
            };
            var newest = mine.OrderByDescending(c => c.Day).FirstOrDefault();
            var href = Drill(newest ?? new TrendCell(days.LastOrDefault(), g, 0, null, 0));
            return new TrendCard(g, Label(g), tone, href, values);
        }).ToList();
        var kind = Measure is TrendMeasures.Score or TrendMeasures.MaxScore ? TrendValueKind.Score : TrendValueKind.Count;
        Cards = new TrendCardSet("trend-cards", $"{MeasureLabel} by {(Dim == TrendDimensions.None ? "day" : Dim)}, last {Days} days", days, cards, kind);
    }

    private void Build()
    {
        if (DrawsCards(Dim)) { BuildCards(); return; }
        var days = Cells.Select(c => c.Day).Distinct().OrderBy(d => d).ToList();
        var lastDay = days.LastOrDefault();
        // the series that matter most NOW, then everything else folded into "Other" -- never more lines than colours
        var ranked = Cells.GroupBy(c => Label(c.Dimension))
            .OrderByDescending(g => Combine(g.Where(c => c.Day == lastDay)) ?? double.MinValue).ThenByDescending(g => g.Sum(Value)).Select(g => g.Key).ToList();
        if (Dim == TrendDimensions.Tier) ranked = ranked.OrderBy(x => x).ToList();
        var top = ranked.Take(ranked.Count > MaxSeries + 1 ? MaxSeries : MaxSeries + 1).ToList();
        var other = ranked.Count > top.Count;
        // severity series in RANK order (Very High first), so a colour always means the same severity
        if (Dim == TrendDimensions.Severity) top = top.OrderBy(x => x == "(none)" ? "" : x, SeverityOrder.Comparer).ToList();
        Series = other ? top.Append("Other").ToList() : top;
        var series = Series.Select((name, i) => new ChartSeries(name, days.Select(d => Shown(Cells
            .Where(c => c.Day == d && (name == "Other" && other ? !top.Contains(Label(c.Dimension)) : Label(c.Dimension) == name)))).ToList(), i + 1)).ToList();
        Chart = new ChartSpec("trend-analytics", "line", days.Select(Fmt.Day).ToList(), series, MeasureLabel,
            $"{MeasureLabel} per day by {Dim}, last {Days} days");
    }

    /// The order of the groups of one day: severity by RANK (Very High first), anything else by its value.
    public IComparer<string?> GroupOrder => Dim == TrendDimensions.Severity ? SeverityOrder.Comparer : StringComparer.Ordinal;

    public string Label(string dim) => Dim switch
    {
        TrendDimensions.Tier => dim == ProDataFilters.Unclassified ? "Unclassified" : "Tier " + dim,
        TrendDimensions.None => "All",
        _ => dim.Length == 0 ? "(none)" : dim,
    };

    /// The findings browser for one day's collection, carrying the trend's filters (and the series' own value).
    public string Drill(TrendCell c)
    {
        var p = new List<string>();
        if (c.CollectionId is { } id) p.Add("c=" + Uri.EscapeDataString(id));
        void Add(string k, string? v) { if (!string.IsNullOrEmpty(v)) p.Add(k + "=" + Uri.EscapeDataString(v)); }
        Add("tier", Dim == TrendDimensions.Tier ? c.Dimension : Tier);
        Add("sev", Dim == TrendDimensions.Severity ? c.Dimension : Sev);
        Add("dom", Dim == TrendDimensions.Domain ? c.Dimension : Dom);
        Add("rep", Dim == TrendDimensions.Report ? c.Dimension : Rep);
        // #855: the drill-down counts the same CI lifecycle as the trend
        Add(LifecycleFilter.Parameter, Lifecycle.QueryValue);
        // #264: the drill-down shows the same population as the trend (the tick travels)
        return SI.Management.Web.Exemptions.ExemptedTick.Carry(HttpContext, "/Findings?" + string.Join("&", p));
    }
}
