using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core;

namespace SI.Management.Web.Pages.Management;

/// Tier-0 exposure: how many tier-0 assets carry exposed findings over time, and which tier-0 assets rank highest.
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Management)]
public sealed class Tier0Model : SI.Management.Web.Columns.DataViewPageModel
{
    private readonly IEstateQueries _q;
    private readonly SI.Management.Core.ProData.ViewResultCache? _cache;
    /// <paramref name="cache"/>: the estate's whole ranking (every exposed asset -- the page loaded all of it on every
    /// open) is read once per data version; the page still holds every row, so its sort, search and exports work as before.
    public Tier0Model(IEstateQueries q, SI.Management.Core.ProData.ViewResultCache? cache = null) { _q = q; _cache = cache; }

    [BindProperty(SupportsGet = true)] public int Days { get; set; } = 90;
    public QueryResult<IReadOnlyList<TrendPoint>>? Trend { get; private set; }
    /// The estate's riskiest assets the "top 100" tile and marker refer to (the Top risks page's list).
    public const int TopN = 100;
    /// The whole ranking (estate-wide rank of every exposed asset).
    public QueryResult<IReadOnlyList<TopRisk>>? Risks { get; private set; }
    /// EVERY tier-0 asset with findings in the newest collection, in estate rank order.
    public IReadOnlyList<TopRisk> Tier0Risks { get; private set; } = Array.Empty<TopRisk>();
    /// Those of them within the estate's TopN riskiest assets.
    public int Tier0InTop => Tier0Risks.Count(r => InTop(r));
    public static bool InTop(TopRisk r) => r.Rank >= 1 && r.Rank <= TopN;
    public ChartSpec? Chart { get; private set; }

    /// Tier as the RA tables write it ("0", "Tier 0", "T0" ...): the tier-0 test is on the digit, not the spelling.
    public static bool IsTier0(string? tier)
    {
        if (string.IsNullOrWhiteSpace(tier)) return false;
        var digits = new string(tier.Where(char.IsDigit).ToArray());
        return digits == "0";
    }

    // #589: every tier-0 asset as THE data table (its CI with identifiers and context, the chooser, the exports)
    protected override Task LoadForExportAsync(CancellationToken ct) => OnGetAsync(ct);

    protected override IReadOnlyList<SI.Management.Web.Columns.DataTable> BuildTables() => new[] { ExecTables.Tier0(Tier0Risks, InTop, TopN) };

    public async Task OnGetAsync(CancellationToken ct)
    {
        Days = Fmt.Pick(Days, 90, 30, 90, 180, 365);
        Trend = await _q.RiskTrendAsync(Days, ct);
        // a ranking with rows is kept until the data version moves; an empty one (nothing loaded, or the source did not
        // answer) is read again on the next open
        Risks = _cache is null ? await _q.RankedAssetsAsync(QueryParameters.MaxRanked, ct)
            : await _cache.GetAsync("tier0.ranked|" + QueryParameters.MaxRanked.ToString(System.Globalization.CultureInfo.InvariantCulture),
                () => _q.RankedAssetsAsync(QueryParameters.MaxRanked, ct), ct, r => r.Data.Count > 0);
        Tier0Risks = Risks.Data.Where(r => IsTier0(r.Tier)).OrderBy(r => r.Rank).ToList();
        var pts = Trend.Data.OrderBy(p => p.Day).ToList();
        Chart = new ChartSpec("tier0-trend", "line", pts.Select(p => Fmt.Day(p.Day)).ToList(),
            new[] { new ChartSeries("Tier-0 assets with findings", pts.Select(p => (double?)p.Tier0Exposed).ToList(), 1) }, "Assets",
            $"Tier-0 assets with findings per day, last {Days} days");
    }
}
