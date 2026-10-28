using System.Globalization;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Pages.Collection;

/// <summary>
/// Correlation quality: how well the sources were joined into one CI per real asset, per collection -- assets by the
/// number of sources that saw them, single-source assets per source, weak matches, conflicts, id changes and merges,
/// possible duplicates, and the CMDB match rate; a trend over the correlated collections; the CIs behind every figure
/// in the shared grid (export to Excel / CSV included). Reads the data sync's sidata.AssetCorrelation only.
/// </summary>
public sealed class CorrelationModel(ICollectionViews views, ILogger<CorrelationModel> log) : CollectionPageModel(views, log)
{
    public override string PagePath => "/Collection/Correlation";
    public override string Heading => "Correlation quality";
    public override string Lede => "SecurityInsight joins what every system knows about an asset into one record (a CI). This page shows how well that worked. Click any figure to list its assets.";
    public override string ExportName => "correlation-quality";

    public static readonly IReadOnlyList<string> KnownSources = ["Defender", "Entra", "Active Directory", "Azure", "Exposure Graph", "Shodan", "CMDB", "ServiceNow", "Risk Analysis"];

    public DateTime? CorrelatedAt { get; private set; }
    public CorrelationReport? Report { get; private set; }
    public IReadOnlyList<CorrelationTrendPoint> Trend { get; private set; } = Array.Empty<CorrelationTrendPoint>();
    public ChartSpec? TrendChart { get; private set; }

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        var cv = HttpContext?.RequestServices.GetService(typeof(ICorrelationViews)) as ICorrelationViews;
        if (!forExport && cv is not null)
        {
            try
            {
                var at = await cv.CorrelatedAtAsync(Current!.CollectionId, ct); CorrelatedAt = at.Data; Queries.Add(QueryInfo.From(at, "When the evidence was computed"));
                if (CorrelatedAt is null)
                    Notice ??= "The correlation evidence has not been computed for this collection. The data sync computes it with each load; a collection loaded before this version has none.";
                var s = await cv.SummaryAsync(Current.CollectionId, ct); Queries.Add(QueryInfo.From(s, "The figures"));
                Report = CorrelationReport.From(s.Data, Current.CollectionId);
                var t = await cv.TrendAsync(30, ct); Queries.Add(QueryInfo.From(t, "The trend"));
                Trend = CorrelationReport.Trend(t.Data);
                if (Trend.Count > 0)
                    TrendChart = new ChartSpec("corr-trend", "line", Trend.Select(p => LocalTime.Iso(p.CollectionTime)).ToList(),   // shown in the viewer's zone (#313)
                        new[]
                        {
                            new ChartSeries("Seen by 2 or more sources (%)", Trend.Select(p => (double?)p.MultiSourceShare).ToList(), 1),
                            new ChartSeries("Weak matches (%)", Trend.Select(p => (double?)p.WeakShare).ToList(), 2),
                            new ChartSeries("CMDB match rate (%)", Trend.Select(p => p.MatchRate).ToList(), 3),
                        }, "%", "Correlation quality per collection", TimeLabels: true);
            }
            catch (Exception ex) when (ex is not OperationCanceledException and not ArgumentException)
            {
                Log.LogWarning(ex, "correlation quality");
                Notice ??= "The correlation figures could not be read" + SchemaHint(ex.Message);
            }
        }
        var sources = (Report?.SingleSource.Select(f => f.Label) ?? Enumerable.Empty<string>()).Concat(KnownSources).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return new GridPlan(CorrelationViewSql.Grid, new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId }, Current.Version + "|corr",
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["AssetKind"] = Kinds, ["Tier"] = TierValues, ["Confidence"] = CorrelationViewSql.Confidences, ["JoinRule"] = CorrelationViewSql.JoinRules,
                ["CmdbState"] = CorrelationViewSql.CmdbStates, ["HasDuplicate"] = Flags, ["Sources"] = sources,
            });
    }

    /// A figure's drill-down: this page, this collection, the figure's filters and nothing else -- and the anchor of the
    /// list, so the browser lands ON the assets (without it the page reloaded at the top and the click looked dead).
    public string Drill(ReportFigure f) => Drill(f.Filter);
    public string Drill(IReadOnlyList<(string Column, string Value)> filter) => ViewLink(PagePath, filter.Select(x => ("f." + x.Column, (string?)x.Value)).ToArray()) + "#" + DrillAnchor;

    /// The id of the list's heading (the anchor every figure links to).
    public const string DrillAnchor = "assets";

    /// The overview without a filter (Clear filter / back to the overview).
    public string Overview => ViewLink(PagePath);

    /// The figures, grouped as the page shows them, each with its confidence tone.
    public IReadOnlyList<CorrelationGroup> Groups => _groups ??= Report is null ? Array.Empty<CorrelationGroup>() : CorrelationGroups.Of(Report);
    private IReadOnlyList<CorrelationGroup>? _groups;

    /// The column filters of this request (f.*), one (column, value) per value -- empty = the whole collection.
    public IReadOnlyList<(string Column, string Value)> UrlFilter => Request.Query
        .Where(kv => kv.Key.StartsWith("f.", StringComparison.OrdinalIgnoreCase))
        .SelectMany(kv => kv.Value.Where(v => !string.IsNullOrWhiteSpace(v))
            .SelectMany(v => v!.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Select(v => (kv.Key[2..], v)))
        .ToList();

    /// Whether the list is narrowed (a figure, a column filter or a search).
    public bool Drilled => UrlFilter.Count > 0 || !string.IsNullOrWhiteSpace(Request.Query["q"]);

    /// The figure whose filter the URL carries exactly (null = none, or a hand-made filter / a search on top).
    public CorrelationTile? ActiveTile => string.IsNullOrWhiteSpace(Request.Query["q"]) ? CorrelationGroups.Match(Groups, UrlFilter) : null;

    /// The list's heading: what the listed assets ARE, with the number actually listed ("4 assets seen only by the Exposure Graph").
    public string DrillHeading
    {
        get
        {
            var n = Grid?.Total ?? 0;
            if (ActiveTile is { } t) return CorrelationGroups.Assets(n) + " " + t.Title;
            return Drilled ? CorrelationGroups.Assets(n) + " matching the filter" : "All " + CorrelationGroups.Assets(n) + " in this collection";
        }
    }

    /// The Confidence cell of a grid row is a coloured chip (exact / strong / weak), like the figures above.
    public override string? CellTone(string column, IReadOnlyDictionary<string, object?> row) =>
        column == "Confidence" && Cell(row, "Confidence") is { } c ? CorrelationGroups.ConfidenceTone(c).Css() : null;

    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) => column switch
    {
        "AssetName" => Cell(row, "AssetKey") is { } k ? ViewLink("/Collection/Asset", ("key", k)) : null,
        "HasDuplicate" => Cell(row, "PossibleDuplicateOf") is { } d ? ViewLink("/Collection/Asset", ("key", d)) : null,
        _ => null,
    };
}
