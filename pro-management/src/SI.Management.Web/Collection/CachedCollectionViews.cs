using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Core;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Collection;

/// <summary>
/// The collection views' cache. A COMPLETE collection never changes, so what is read from its own rows (the grids over
/// sidata.Finding, its aggregates, the comparison of two collections) is kept <see cref="Long"/>; reads of state that
/// moves (the close-loop, connectors, exemptions, the current CI record, the collection list) are kept <see cref="Short"/>.
/// <para>Key = view + collection id + when its aggregates were computed (<see cref="ViewCollection.Version"/>) + the
/// query shape (sort, page, filters, search, selection) -- hashed, so a long filter does not make a long key. A
/// collection whose aggregates are recomputed gets new keys; nothing stale is served.</para>
/// <para>Its OWN bounded <see cref="MemoryCache"/> (<see cref="Capacity"/> entries), so the views can never crowd out the
/// rest of the app. An export is never cached.</para>
/// </summary>
public sealed class CachedCollectionViews : ICollectionViews, IDisposable
{
    public static readonly TimeSpan Long = TimeSpan.FromHours(6);
    public static readonly TimeSpan Short = TimeSpan.FromMinutes(2);
    public const int Capacity = 2_000;
    private readonly ICollectionViews _inner;
    private readonly MemoryCache _cache;

    public CachedCollectionViews(ICollectionViews inner)
    {
        _inner = inner;
        _cache = new MemoryCache(new MemoryCacheOptions { SizeLimit = Capacity });
    }

    public ICollectionViews Inner => _inner;
    public int Count => _cache.Count;

    /// How long a grid's answer is kept: long for one complete collection's own rows, short for anything that moves.
    public static TimeSpan TtlFor(GridSpec s) => s.Immutable ? Long : Short;

    /// The cache key of one read. Public so the tests can pin what makes two reads the same.
    public static string Key(string view, string scope, string shape)
    {
        var h = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(shape)));
        return "cv|" + view + "|" + scope + "|" + h[..32];
    }

    private async Task<T> Get<T>(string key, TimeSpan ttl, Func<Task<T>> read)
    {
        // #264: a read with exempted findings left out and one with them included are different answers
        key = Exempted.CacheKey + "|" + key;
        if (_cache.TryGetValue(key, out var hit) && hit is T t) return t;
        var v = await read().ConfigureAwait(false);
        _cache.Set(key, v, new MemoryCacheEntryOptions { Size = 1, AbsoluteExpirationRelativeToNow = ttl });
        return v;
    }

    public Task<QueryResult<IReadOnlyList<ViewCollection>>> CollectionsAsync(CancellationToken ct) =>
        Get(Key("collections", "-", "-"), TimeSpan.FromSeconds(60), () => _inner.CollectionsAsync(ct));

    public Task<QueryResult<GridPage>> GridAsync(GridQuery query, CancellationToken ct)
    {
        var st = GridSql.Normalize(query.Spec, query.Request);     // a bad value refuses before anything is cached
        var shape = st.Shape() + "|" + string.Join("|", query.SourceParameters.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => p.Key + "=" + Fmt(p.Value)));
        return Get(Key(query.Spec.Name, query.ScopeKey, shape), TtlFor(query.Spec), () => _inner.GridAsync(query, ct));
    }

    private static string Fmt(object? v) => v switch
    {
        null => "",
        DateTime d => d.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture),
        IFormattable f => f.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
        _ => v.ToString() ?? "",
    };

    public Task<QueryResult<GridPage>> ExportAsync(GridQuery query, CancellationToken ct) => _inner.ExportAsync(query, ct);
    /// #287: the counts per value of a filter column, read live when a filter is opened
    public Task<QueryResult<IReadOnlyList<CountRow>>> ValueCountsAsync(GridQuery query, string column, CancellationToken ct) => _inner.ValueCountsAsync(query, column, ct);

    public Task<QueryResult<IReadOnlyList<FacetRow>>> FacetsAsync(ViewCollection c, CancellationToken ct) =>
        Get(Key("facets", c.Version, "-"), c.DerivedAt is null ? Short : Long, () => _inner.FacetsAsync(c, ct));

    public Task<QueryResult<IReadOnlyList<CountRow>>> ChangeSummaryAsync(ViewCollection a, ViewCollection b, CancellationToken ct) =>
        Get(Key("changesummary", a.Version + "~" + b.Version, "-"), Long, () => _inner.ChangeSummaryAsync(a, b, ct));

    public Task<QueryResult<IReadOnlyList<CountRow>>> ExemptionStatesAsync(DateTime at, CancellationToken ct) =>
        Get(Key("exemptionstates", "-", Fmt(at)), Short, () => _inner.ExemptionStatesAsync(at, ct));

    public Task<QueryResult<IReadOnlyList<ExclusionDocRow>>> ExclusionDocumentsAsync(CancellationToken ct) =>
        Get(Key("exclusiondocs", "-", "-"), Short, () => _inner.ExclusionDocumentsAsync(ct));

    public Task<QueryResult<IReadOnlyList<CountRow>>> EventCountsAsync(DateTime from, DateTime to, CancellationToken ct) =>
        Get(Key("eventcounts", "-", Fmt(from) + "~" + Fmt(to)), Short, () => _inner.EventCountsAsync(from, to, ct));

    public Task<QueryResult<IReadOnlyList<LifecycleDay>>> LifecycleDaysAsync(DateOnly since, DateOnly until, CancellationToken ct) =>
        Get(Key("lifecycledays", "-", since.DayNumber + "~" + until.DayNumber), Short, () => _inner.LifecycleDaysAsync(since, until, ct));

    public Task<QueryResult<IReadOnlyList<ConnectorTotal>>> ConnectorTotalsAsync(DateTime from, DateTime to, CancellationToken ct) =>
        Get(Key("connectortotals", "-", Fmt(from) + "~" + Fmt(to)), Short, () => _inner.ConnectorTotalsAsync(from, to, ct));

    public Task<QueryResult<AssetInfo?>> AssetAsync(string assetKey, CancellationToken ct) =>
        Get(Key("asset", "-", assetKey), Short, () => _inner.AssetAsync(assetKey, ct));

    public Task<QueryResult<IReadOnlyList<IdentifierRow>>> IdentifiersAsync(string assetKey, CancellationToken ct) =>
        Get(Key("identifiers", "-", assetKey), Short, () => _inner.IdentifiersAsync(assetKey, ct));

    public Task<QueryResult<IReadOnlyList<RecommendationRow>>> RecommendationsAsync(ViewCollection c, string assetKey, CancellationToken ct) =>
        Get(Key("recommendations", c.Version, assetKey), Long, () => _inner.RecommendationsAsync(c, assetKey, ct));

    public Task<QueryResult<IReadOnlyList<AssetHistoryRow>>> AssetHistoryAsync(string assetKey, CancellationToken ct) =>
        Get(Key("assethistory", "-", assetKey), Short, () => _inner.AssetHistoryAsync(assetKey, ct));

    public Task<QueryResult<IReadOnlyList<AssetVulnRow>>> AssetVulnItemsAsync(string assetKey, CancellationToken ct) =>
        Get(Key("assetvulns", "-", assetKey), Short, () => _inner.AssetVulnItemsAsync(assetKey, ct));

    /// Short: it is what tells the Services grids (cached long) that the collection's membership was re-derived.
    public Task<QueryResult<ServicesState>> ServicesStateAsync(ViewCollection c, CancellationToken ct) =>
        Get(Key("servicesstate", c.Version, "-"), Short, () => _inner.ServicesStateAsync(c, ct));

    /// Short: it is what tells the one-row-per-CVE grid that the data sync wrote the collection's rows (or wrote them again).
    public Task<QueryResult<CveSummaryState>> CveSummaryStateAsync(ViewCollection c, CancellationToken ct) =>
        Get(Key("cvesummarystate", c.Version, "-"), Short, () => _inner.CveSummaryStateAsync(c, ct));

    /// Short: it is what tells What changed that the data sync wrote the collection's comparison (or wrote it again).
    public Task<QueryResult<ChangeState>> ChangeStateAsync(ViewCollection b, CancellationToken ct) =>
        Get(Key("changestate", b.Version, "-"), Short, () => _inner.ChangeStateAsync(b, ct));

    /// Short: it is what tells the per-CI grids that the data sync wrote the collection's rows (or wrote them again).
    public Task<QueryResult<AssetSummaryState>> AssetSummaryStateAsync(ViewCollection c, CancellationToken ct) =>
        Get(Key("assetsummarystate", c.Version, "-"), Short, () => _inner.AssetSummaryStateAsync(c, ct));

    /// Short: it is what tells a named view (#812) that the data sync wrote the collection's grouped rows (or wrote them again).
    public Task<QueryResult<GroupingState>> GroupingStateAsync(ViewCollection c, string groupingId, CancellationToken ct) =>
        Get(Key("groupingstate", c.Version, groupingId), Short, () => _inner.GroupingStateAsync(c, groupingId, ct));

    public Task<QueryResult<ServiceRow?>> ServiceAsync(ViewCollection c, string serviceKey, CancellationToken ct) =>
        Get(Key("service", c.Version, serviceKey), Short, () => _inner.ServiceAsync(c, serviceKey, ct));

    /// #360: short -- an imported CMDB shows up within minutes.
    public Task<QueryResult<CmdbState>> CmdbStateAsync(CancellationToken ct) =>
        Get(Key("cmdbstate", "-", "-"), Short, () => _inner.CmdbStateAsync(ct));

    /// #360: one collection's pivot never changes, but its criticality is the CMDB's (which moves): short.
    public Task<QueryResult<IReadOnlyList<IReadOnlyDictionary<string, object?>>>> PivotAsync(ViewCollection c, PivotRequest request, bool cmdb,
        RowVisibility? visibility, int max, CancellationToken ct, LifecycleFilter? lifecycle = null) =>
        Get(Key("pivot", c.Version + "|" + (cmdb ? "cmdb" : "-") + "|" + (visibility?.Key ?? "all") + "|lc=" + (lifecycle ?? LifecycleFilter.Active).Key, request.Shape() + "|" + max.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            Short, () => _inner.PivotAsync(c, request, cmdb, visibility, max, ct, lifecycle));

    public void Dispose() => _cache.Dispose();
}
