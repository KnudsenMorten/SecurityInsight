using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Pages.Management;

/// <summary>
/// Domain scores over time (endpoint, identity, azure, public IP ...). ONE source with Trends (operator 2026-10-05): the
/// Pro database's daily aggregate split by security domain -- the same query as Changes &amp; trends > Trends split by
/// "Security domain", so the two pages show identical numbers.
/// </summary>
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Management)]
public sealed class DomainsModel : PageModel
{
    /// Categorical slots in fixed order; a fifth domain onward folds into "Other" (never a generated hue).
    public const int MaxSeries = 4;
    private readonly IProDataQueries _q;
    private readonly ILogger<DomainsModel> _log;
    public DomainsModel(IProDataQueries q, ILogger<DomainsModel> log) { _q = q; _log = log; }

    [BindProperty(SupportsGet = true)] public int Days { get; set; } = 90;
    public IReadOnlyList<DomainTrendPoint> Points { get; private set; } = Array.Empty<DomainTrendPoint>();
    public ChartSpec? Chart { get; private set; }
    public QueryInfo? Query { get; private set; }
    public string? Error { get; private set; }
    public IReadOnlyList<(string Domain, double? Now, double? Then, int Findings)> Summary { get; private set; } = Array.Empty<(string, double?, double?, int)>();

    public async Task OnGetAsync(CancellationToken ct)
    {
        Days = Fmt.Pick(Days, 90, 30, 90, 180, 365);
        try
        {
            var r = await _q.TrendAsync(ProDataFilters.Normalize(new TrendRequest { Days = Days, Dimension = TrendDimensions.Domain, Measure = TrendMeasures.Score }), ct);
            Query = QueryInfo.Sql(r.Query, "Average risk score per finding by domain (the same daily aggregate as Trends)");
            Points = Build(r.Data);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "domain trend failed");
            Error = "The domain scores could not be read: " + ex.Message;
        }
        var days = Points.Select(p => p.Day).Distinct().OrderBy(d => d).ToList();
        // Domain order is fixed by NAME (alphabetical), so a domain keeps its colour whatever the period shows.
        var domains = Points.Select(p => p.Domain).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(d => d, StringComparer.OrdinalIgnoreCase).ToList();
        var shown = domains.Take(domains.Count > MaxSeries ? MaxSeries - 1 : MaxSeries).ToList();
        var series = shown.Select((d, i) => new ChartSeries(d,
            days.Select(day => Points.Where(p => p.Day == day && p.Domain.Equals(d, StringComparison.OrdinalIgnoreCase)).Select(p => ScoreFormat.Round(p.AverageRiskScore)).FirstOrDefault()).ToList(), i + 1)).ToList();
        if (domains.Count > MaxSeries)
        {
            // several domains in one line: their combined average (every finding's score over every finding), never a sum
            var rest = domains.Skip(MaxSeries - 1).ToHashSet(StringComparer.OrdinalIgnoreCase);
            series.Add(new ChartSeries("Other", days.Select(day => ScoreFormat.Round(Average(Points.Where(p => p.Day == day && rest.Contains(p.Domain))))).ToList(), MaxSeries));
        }
        Chart = new ChartSpec("domain-trend", "line", days.Select(Fmt.Day).ToList(), series, "Average risk score per finding", $"Average risk score per finding per domain, last {Days} days");
        Summary = domains.Select(d =>
        {
            var pts = Points.Where(p => p.Domain.Equals(d, StringComparison.OrdinalIgnoreCase)).OrderBy(p => p.Day).ToList();
            return (d, pts.Last().AverageRiskScore, pts.Count > 1 ? pts.First().AverageRiskScore : null, pts.Last().Findings);
        }).ToList();
    }

    /// The Trends cells split by domain as one point per domain and day (the label Trends shows: "(none)" for no domain).
    public static IReadOnlyList<DomainTrendPoint> Build(IEnumerable<TrendCell> cells) =>
        cells.Select(c => new DomainTrendPoint(c.Day, c.Dimension.Length == 0 ? "(none)" : c.Dimension, c.ScoreAverage, (int)c.Findings)).ToList();

    /// The combined average of several domains on one day, weighted by their findings.
    public static double? Average(IEnumerable<DomainTrendPoint> points)
    {
        var withScore = points.Where(p => p.AverageRiskScore is not null && p.Findings > 0).ToList();
        var n = withScore.Sum(p => (long)p.Findings);
        return n == 0 ? null : withScore.Sum(p => p.AverageRiskScore!.Value * p.Findings) / n;
    }
}
