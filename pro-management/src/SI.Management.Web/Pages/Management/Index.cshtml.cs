using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Pages.Management;

/// <summary>
/// Risk score and its trend (the estate's headline). ONE source for the risk score over time (operator 2026-10-05: the
/// two risk-score trends showed the same score from two places): the Pro database's daily aggregate, the same query as
/// Changes &amp; trends > Trends. One read split by asset tier gives every number: the day's total (the tiers added
/// together, an average re-computed from the parts) and the Tier-0 assets with findings.
/// </summary>
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Management)]
public sealed class IndexModel : PageModel
{
    private readonly IProDataQueries _q;
    private readonly ILogger<IndexModel> _log;
    public IndexModel(IProDataQueries q, ILogger<IndexModel> log) { _q = q; _log = log; }

    /// One day of the estate: what the tiles, the chart and the table show.
    public sealed record Point(DateOnly Day, double? AverageRiskScore, long Findings, long TopSeverityFindings, long? Tier0Assets);

    [BindProperty(SupportsGet = true)] public int Days { get; set; } = 90;
    public IReadOnlyList<Point> Points { get; private set; } = Array.Empty<Point>();
    public Point? Latest => Points.LastOrDefault();
    public Point? First => Points.FirstOrDefault();
    public ChartSpec? Chart { get; private set; }
    public QueryInfo? Query { get; private set; }
    public string? Error { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        Days = Fmt.Pick(Days, 90, 30, 90, 180, 365);
        try
        {
            var r = await _q.TrendAsync(ProDataFilters.Normalize(new TrendRequest { Days = Days, Dimension = TrendDimensions.Tier, Measure = TrendMeasures.Score }), ct);
            Query = QueryInfo.Sql(r.Query, "Risk score per day (the same daily aggregate as Trends)");
            Points = Build(r.Data);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "risk score trend failed");
            Error = "The risk score could not be read: " + ex.Message;
        }
        Chart = new ChartSpec("risk-trend", "line", Points.Select(p => Fmt.Day(p.Day)).ToList(),
            new[] { new ChartSeries("Average risk score per finding", Points.Select(p => ScoreFormat.Round(p.AverageRiskScore)).ToList(), 1) }, "Average risk score per finding",
            $"Average risk score per finding per day, last {Days} days");
    }

    /// The tier cells of each day as one estate point: counts added, the average re-computed from the parts, the Tier-0
    /// group's distinct assets with findings.
    public static IReadOnlyList<Point> Build(IEnumerable<TrendCell> cells) =>
        cells.GroupBy(c => c.Day).OrderBy(g => g.Key).Select(g =>
        {
            var findings = g.Sum(c => c.Findings);
            return new Point(g.Key, findings > 0 ? g.Sum(c => c.ScoreTotal) / findings : null, findings, g.Sum(c => c.TopSeverityFindings),
                g.FirstOrDefault(c => c.Dimension == "0")?.Assets ?? (g.Any(c => c.Assets is not null) ? 0 : null));
        }).ToList();
}
