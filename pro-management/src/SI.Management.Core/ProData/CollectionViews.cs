namespace SI.Management.Core.ProData;

/// One complete collection a view can open. DerivedAt = when the data sync computed the views' columns and aggregates
/// for it (null = not yet: the facet views say so). NextTime = the next collection's time (null = this is the newest):
/// "what happened with this collection" is the window [CollectionTime, NextTime).
public sealed record ViewCollection(string CollectionId, DateTime CollectionTime, string Kind, long? Rows, DateTime? DerivedAt, DateTime? NextTime)
{
    /// When every finding of the collection got the risk score's parts as columns (sidata.Collection.RiskPartsAt; null =
    /// not yet: the parts' columns are empty and the explained score reads them from each finding's row).
    public DateTime? RiskPartsAt { get; init; }

    /// Part of every cache key: a collection whose aggregates are recomputed -- or whose risk score's parts arrive -- gets new keys.
    public string Version => CollectionId + "@" + (DerivedAt?.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "0")
        + (RiskPartsAt is { } rp ? "+" + rp.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) : "");
}

/// One pre-computed aggregate row (sidata.FindingFacet).
public sealed record FacetRow(string Facet, string Value, long Findings, long Assets, double ScoreTotal, double? WeightedTotal, double? MaxScore);

public static class Facets
{
    public const string Tactic = "tactic";
    public const string Technique = "technique";
    public const string Tag = "tag";
    public const string Rating = "rating";
    public const string Cvss = "cvss";
    public const string Score = "score";
    public const string Weighted = "weighted";
    public const string Severity = "severity";
    public const string Tier = "tier";
    public const string Domain = "domain";
    public const string Report = "report";
    // the findings grid's Category / Subcategory / Department dropdowns (owner 2026-10-28)
    public const string Category = "category";
    public const string Subcategory = "subcategory";
    public const string Department = "department";
}

/// A grid of one view, with the values its source needs (collection id, time window, CI key, ...).
public sealed record GridQuery(GridSpec Spec, IReadOnlyDictionary<string, object?> SourceParameters, string ScopeKey, GridRequest Request);

public sealed record CountRow(string Group, string Key, long N);

public sealed record AssetInfo(string AssetKey, string AssetName, string AssetKind, string Tier, string KeySource, DateTime? FirstSeen, DateTime? LastSeen, string? PropertiesJson);
public sealed record IdentifierRow(string Type, string Value, DateTime? FirstSeen, DateTime? LastSeen);
public sealed record RecommendationRow(string RecommendationId, string Name, string Severity);
public sealed record AssetHistoryRow(string CollectionId, DateTime CollectionTime, long Findings, double TotalRisk, double MaxRisk);
public sealed record AssetVulnRow(string Cve, string Severity, string State, DateTime? FirstSeen, DateTime? LastSeen, DateTime? ClosedAt, string? CloseReason);
public sealed record ExclusionDocRow(string Key, DateTime? UpdatedAt, string UpdatedBy, long BodyLength);
/// The Services view's state for one collection (#255): when its service aggregates were computed (null = not yet), how
/// many services, how many CIs are in no service. Part of the Services grids' cache scope, so a re-derived membership is
/// never served stale.
public sealed record ServicesState(DateTime? DerivedAt, long Services, long UnplacedAssets)
{
    public string Version => DerivedAt?.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "0";
}

/// <summary>
/// Whether a collection's one-row-per-CVE rows are written (sidata.CveSummaryState, the data sync): Schema = the database has
/// the tables; BuiltAt = when this collection's rows were written (null = not yet -- the page says the list is being
/// prepared and never groups the finding rows itself); Cves = how many CVE rows.
/// </summary>
public sealed record CveSummaryState(bool Schema, DateTime? BuiltAt, long Cves)
{
    /// What a reader that does not keep the state answers (the test fakes, the demo): the rows are there.
    public static CveSummaryState Ready { get; } = new(true, DateTime.MaxValue, 0);
    public bool Built => Schema && BuiltAt is not null;
    /// Part of the grid's cache scope: rows written again get new keys.
    public string Version => BuiltAt?.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "0";
    /// The rows were written before the collection's views' columns were derived again (an asset merge, a repair): they are
    /// shown, and the page says they are being brought up to date.
    public bool StaleFor(ViewCollection c) => Built && c.DerivedAt is { } d && BuiltAt!.Value < d;
}

/// <summary>
/// Whether a collection's one-row-per-CI rows are written (sidata.AssetRiskSummaryState, the data sync -- what Risks > Risk
/// score, the weighted score's distribution and Assets (CIs) at risk page over): Schema = the database has the tables;
/// BuiltAt = when this collection's rows were written (null = not yet -- the page says the list is being prepared and never
/// groups the finding rows itself); Assets = how many CI rows.
/// </summary>
/// <summary>
/// #812: which comparison the data sync wrote for a collection B (sidata.ChangeState): Schema = the database has the tables;
/// PrevCollectionId = the collection A it is compared with (null = none written yet); BuiltAt = when.
/// </summary>
public sealed record ChangeState(bool Schema, string? PrevCollectionId, DateTime? BuiltAt)
{
    /// What a reader that does not keep the state answers (the test fakes, the demo): every pair is there.
    public static ChangeState Ready { get; } = new(true, "*", DateTime.MaxValue);
    /// The stored comparison is the one of B with <paramref name="a"/>.
    public bool IsFor(ViewCollection a) => Schema && BuiltAt is not null && (PrevCollectionId == "*" || PrevCollectionId == a.CollectionId);
    /// Part of the grids' cache scope: a pair written again gets new keys.
    public string Version => BuiltAt?.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "0";
}

public sealed record AssetSummaryState(bool Schema, DateTime? BuiltAt, long Assets)
{
    /// What a reader that does not keep the state answers (the test fakes, the demo): the rows are there.
    public static AssetSummaryState Ready { get; } = new(true, DateTime.MaxValue, 0);
    public bool Built => Schema && BuiltAt is not null;
    /// Part of the grid's cache scope: rows written again get new keys.
    public string Version => BuiltAt?.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "0";
    /// The rows were written before the collection's views' columns were derived again (an asset merge, a repair).
    public bool StaleFor(ViewCollection c) => Built && c.DerivedAt is { } d && BuiltAt!.Value < d;
}

/// One service of a collection (the head of its drill-down). ServiceKey = <see cref="CollectionViewSql.NoServiceKey"/>
/// for the CIs in no service.
public sealed record ServiceRow(string ServiceKey, string ServiceName, long Assets, long SharedAssets, long Findings, double? WeightedTotal, double? WeightedPerAsset,
    long Critical, long High, long Medium, long Low, long Tier0, long Tier1, long Tier2, long Tier3, long TierUnclassified,
    string? TopAssetKey, string? TopAssetName, double? TopAssetWeighted, string? Sources)
{
    public bool IsNoService => ServiceKey == CollectionViewSql.NoServiceKey;
}

/// One connector on the Connector changes page (#429): EVERY registered connector -- the cfg.Connector rows and the built-in
/// ones that write outside SecurityInsight (the SQL CMDB connector, the ServiceNow CMDB connector, asset tagging) -- with
/// its runs in the window (0 = it did not run), when it last ran at all and the plain-words why of that run.
public sealed record ConnectorTotal(string Connector, long Runs, long Opened, long Reopened, long Updated, long Closed, long Errors, DateTime? LastRun,
    string? Kind = null, string? Direction = null, bool Enabled = true, DateTime? LastRunEver = null, string? LastWhy = null, long Unchanged = 0)
{
    /// What this connector changes and where, in plain words -- so a customer is told (operator 2026-10-07).
    public string What => ConnectorText.What(Connector, Kind, Direction);

    /// Why it has no run in the window, or "" when it ran.
    public string Status => Runs > 0 ? ""
        : !Enabled ? "did not run in this window: it is switched off (Configuration > Connectors > Setup)"
        : LastRunEver is null ? "has never run: not configured or not installed on this install"
        : "did not run in this window";
}

/// #429 -- the plain-words description of each kind of connector: WHAT it changes and WHERE.
public static class ConnectorText
{
    public static string What(string name, string? kind, string? direction) => (name ?? "").ToLowerInvariant() switch
    {
        "asset-cmdb-sql" => "Writes every configuration item (CI) SecurityInsight knows -- devices and Azure resources, with owner, services, tier and criticality -- to the CI table (cmdbsync.ConfigurationItem) and the ServiceNow hand-off tables (snowstage) in the SecurityInsight database. ServiceNow imports them with its own transform. Nothing is ever deleted: a CI that is gone is retired.",
        "asset-cmdb" => "ServiceNow CMDB: by default sends nothing (the SQL hand-off carries the CIs). With an Import Set table set, it stages every CI row there for ServiceNow's import; with direct write on, it creates and updates CIs in ServiceNow itself.",
        "asset-tagging" => "Sets tags on devices (Defender), Azure resources and Entra objects from the tagging rules -- only when asset tagging writes are on; otherwise it reports what it would set.",
        _ => ((kind ?? "").ToLowerInvariant(), (direction ?? "").ToLowerInvariant()) switch
        {
            ("sql", "cmdb") => "Writes the CI hand-off batch (CIs, key-values, relations) into its own SQL database; ServiceNow imports it with a JDBC data source.",
            ("sql", _) => "Opens, updates and closes vulnerability records (every finding SecurityInsight reports) in the SQL table vuln.VulnerabilityItem; ServiceNow Vulnerability Response imports them from the vulnerable-item view.",
            ("servicenow", _) => "Opens, updates and closes vulnerable items in ServiceNow -- or, with direct write off, stages them for ServiceNow's own import.",
            ("rest", _) => "Opens, updates and closes items in the system its mapping names (REST).",
            _ => "Sends SecurityInsight's results to another system.",
        },
    };
}

/// <summary>The reads of the fourteen collection views. Every result carries its statement.</summary>
public interface ICollectionViews
{
    Task<QueryResult<IReadOnlyList<ViewCollection>>> CollectionsAsync(CancellationToken ct);
    Task<QueryResult<GridPage>> GridAsync(GridQuery query, CancellationToken ct);
    /// Every matching row (bounded by <see cref="ProDataFilters.MaxExport"/>), never cached.
    Task<QueryResult<GridPage>> ExportAsync(GridQuery query, CancellationToken ct);
    /// #287: how many rows each value of one value-filter column has under the grid's OTHER filters (Group = the column,
    /// Key = the value). A reader that cannot count answers none, and the dropdown shows its values without counts.
    Task<QueryResult<IReadOnlyList<CountRow>>> ValueCountsAsync(GridQuery query, string column, CancellationToken ct) =>
        Task.FromResult(new QueryResult<IReadOnlyList<CountRow>>(Array.Empty<CountRow>(), "", "", DateTimeOffset.UtcNow));
    Task<QueryResult<IReadOnlyList<FacetRow>>> FacetsAsync(ViewCollection collection, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<CountRow>>> ChangeSummaryAsync(ViewCollection a, ViewCollection b, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<CountRow>>> ExemptionStatesAsync(DateTime at, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<ExclusionDocRow>>> ExclusionDocumentsAsync(CancellationToken ct);
    Task<QueryResult<IReadOnlyList<CountRow>>> EventCountsAsync(DateTime from, DateTime to, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<LifecycleDay>>> LifecycleDaysAsync(DateOnly since, DateOnly until, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<ConnectorTotal>>> ConnectorTotalsAsync(DateTime from, DateTime to, CancellationToken ct);
    Task<QueryResult<AssetInfo?>> AssetAsync(string assetKey, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<IdentifierRow>>> IdentifiersAsync(string assetKey, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<RecommendationRow>>> RecommendationsAsync(ViewCollection collection, string assetKey, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<AssetHistoryRow>>> AssetHistoryAsync(string assetKey, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<AssetVulnRow>>> AssetVulnItemsAsync(string assetKey, CancellationToken ct);
    /// The Services view (#255): whether the collection's services are computed, and how many.
    Task<QueryResult<ServicesState>> ServicesStateAsync(ViewCollection collection, CancellationToken ct);
    /// Whether the collection's one-row-per-CVE rows are written. A reader that does not keep them (a fake, the demo) answers
    /// <see cref="CveSummaryState.Ready"/>.
    Task<QueryResult<CveSummaryState>> CveSummaryStateAsync(ViewCollection collection, CancellationToken ct) =>
        Task.FromResult(new QueryResult<CveSummaryState>(CveSummaryState.Ready, "", "", DateTimeOffset.UtcNow));
    /// Whether the collection's one-row-per-CI rows are written. A reader that does not keep them (a fake, the demo) answers
    /// <see cref="AssetSummaryState.Ready"/>.
    Task<QueryResult<ChangeState>> ChangeStateAsync(ViewCollection b, CancellationToken ct) =>
        Task.FromResult(new QueryResult<ChangeState>(ChangeState.Ready, "", "", DateTimeOffset.UtcNow));
    Task<QueryResult<AssetSummaryState>> AssetSummaryStateAsync(ViewCollection collection, CancellationToken ct) =>
        Task.FromResult(new QueryResult<AssetSummaryState>(AssetSummaryState.Ready, "", "", DateTimeOffset.UtcNow));
    /// #812: whether the collection's #636 grouped rows are written and hold <paramref name="groupingId"/> (the named views). A
    /// reader that does not keep them answers <see cref="GroupingState.Ready"/>.
    Task<QueryResult<GroupingState>> GroupingStateAsync(ViewCollection collection, string groupingId, CancellationToken ct) =>
        Task.FromResult(new QueryResult<GroupingState>(GroupingState.Ready, "", "", DateTimeOffset.UtcNow));
    /// One service of the collection (null = not in it).
    Task<QueryResult<ServiceRow?>> ServiceAsync(ViewCollection collection, string serviceKey, CancellationToken ct);
    /// #360: what the database knows about the CMDB (and the other tables the weighted views read). A reader that cannot
    /// tell answers <see cref="CmdbState.None"/>: the page then reads the services without criticality and says so.
    Task<QueryResult<CmdbState>> CmdbStateAsync(CancellationToken ct) =>
        Task.FromResult(new QueryResult<CmdbState>(CmdbState.None, "", "", DateTimeOffset.UtcNow));
    /// #360: the grouped rows of one pivot (<see cref="PivotSql.Build"/>), at most <paramref name="max"/> + 1 (one more =
    /// the pivot was cut). #855 <paramref name="lifecycle"/>: the CI lifecycle it counts (null = active, the default).
    Task<QueryResult<IReadOnlyList<IReadOnlyDictionary<string, object?>>>> PivotAsync(ViewCollection collection, PivotRequest request, bool cmdb,
        RowVisibility? visibility, int max, CancellationToken ct, LifecycleFilter? lifecycle = null) => throw new NotSupportedException("this reader has no pivot");
}

/// <summary>
/// The SQL implementation over <see cref="IProSql"/>. Every statement passes <see cref="SqlGuard.AssertReadOnly"/>
/// BEFORE it is sent, and every call runs under <see cref="Timeout"/> (on top of the executor's command timeout).
/// </summary>
public sealed class CollectionViews : ICollectionViews
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(90);
    private readonly IProSql _sql;
    private readonly TimeProvider _clock;
    private readonly string _vulnSource;

    public CollectionViews(IProSql sql, string vulnerabilitySource = "SecurityInsight", TimeProvider? clock = null)
    {
        _sql = sql;
        _vulnSource = string.IsNullOrWhiteSpace(vulnerabilitySource) ? "SecurityInsight" : vulnerabilitySource;
        _clock = clock ?? TimeProvider.System;
    }

    public string VulnerabilitySource => _vulnSource;

    private async Task<(IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows, string Text)> Run(SqlQuery q, CancellationToken ct)
    {
        q = Exempted.Apply(q);   // #264: the request's exempted scope, before it runs and is described
        SqlGuard.AssertReadOnly(q.Text);
        // #284: running out of the time limit is a ViewTimeoutException (the page shows it), never a bare cancellation
        return (await ViewTimeout.Run(t => _sql.QueryAsync(q, t), Timeout, ct).ConfigureAwait(false), EstateQueries.DescribeSql(q.Text, q.Parameters));
    }

    private QueryResult<T> R<T>(T data, string text) => new(data, text, _sql.SourceName, _clock.GetUtcNow());

    private static string S(IReadOnlyDictionary<string, object?> r, string c) => ProDataQueries.S(r, c);
    private static string? SN(IReadOnlyDictionary<string, object?> r, string c) => ProDataQueries.SN(r, c);
    private static long L(IReadOnlyDictionary<string, object?> r, string c) => ProDataQueries.L(r, c);
    private static double D(IReadOnlyDictionary<string, object?> r, string c) => ProDataQueries.D(r, c);
    private static double? DN(IReadOnlyDictionary<string, object?> r, string c) => ProDataQueries.DN(r, c);
    private static DateTime? T(IReadOnlyDictionary<string, object?> r, string c) => ProDataQueries.T(r, c);

    private static string Key(string assetKey) => ProDataFilters.AssetKey(assetKey) ?? throw new ArgumentException("an asset key is required");

    /// How long "the database has no ready mark yet" is trusted (an update adds the column; noticed within this). Once it
    /// is there it stays: that answer is kept for the life of the process.
    public static readonly TimeSpan ReadySchemaTtl = TimeSpan.FromMinutes(5);
    private volatile bool _hasReadyMark;
    private long _readyAskedTicks = long.MinValue;

    /// Whether sidata.Collection says when a collection's view data was written (the list then shows only those). A
    /// failure to tell reads the list as before -- it never fails the page.
    private async Task<bool> HasReadyMarkAsync(CancellationToken ct)
    {
        if (_hasReadyMark) return true;
        var now = _clock.GetUtcNow().UtcTicks;
        var asked = Interlocked.Read(ref _readyAskedTicks);
        if (asked != long.MinValue && now - asked < ReadySchemaTtl.Ticks) return false;
        try
        {
            SqlGuard.AssertReadOnly(CollectionViewSql.ReadySchema);
            var rows = await ViewTimeout.Run(t => _sql.QueryAsync(new SqlQuery(CollectionViewSql.ReadySchema, new Dictionary<string, object?>()), t), Timeout, ct).ConfigureAwait(false);
            var has = rows.Count > 0 && rows[0].TryGetValue("HasViewsReady", out var v) && v is not null && Convert.ToInt64(v, System.Globalization.CultureInfo.InvariantCulture) != 0;
            if (has) _hasReadyMark = true;
            Interlocked.Exchange(ref _readyAskedTicks, now);
            return has;
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested) { return false; }
    }

    public async Task<QueryResult<IReadOnlyList<ViewCollection>>> CollectionsAsync(CancellationToken ct)
    {
        var (rows, text) = await Run(CollectionViewSql.CollectionsTop(120, await HasReadyMarkAsync(ct).ConfigureAwait(false)), ct).ConfigureAwait(false);
        return R<IReadOnlyList<ViewCollection>>(rows.Select(r => new ViewCollection(S(r, "CollectionId"), T(r, "CollectionTime") ?? default, S(r, "Kind"),
            ProDataQueries.LN(r, "RowTotal"), T(r, "DerivedAt"), T(r, "NextTime")) { RiskPartsAt = T(r, "RiskPartsAt") }).ToList(), text);
    }

    public Task<QueryResult<GridPage>> GridAsync(GridQuery query, CancellationToken ct) => Grid(query, export: false, ct);
    public Task<QueryResult<GridPage>> ExportAsync(GridQuery query, CancellationToken ct) => Grid(query, export: true, ct);

    private async Task<QueryResult<GridPage>> Grid(GridQuery query, bool export, CancellationToken ct)
    {
        var st = GridSql.Normalize(query.Spec, query.Request);
        var sp = new Dictionary<string, object?>(query.SourceParameters, StringComparer.Ordinal);
        if (query.Spec.SourceParameters.Contains("Source") && !sp.ContainsKey("Source")) sp["Source"] = _vulnSource;
        var (rows, text) = await Run(GridSql.Page(query.Spec, st, sp, export), ct).ConfigureAwait(false);
        var total = rows.Count > 0 ? L(rows[0], "TotalRows") : 0;
        var data = rows.Select(r => (IReadOnlyDictionary<string, object?>)query.Spec.Columns.ToDictionary(c => c.Key, c => r.TryGetValue(c.Key, out var v) ? v : null, StringComparer.OrdinalIgnoreCase)).ToList();
        return R(new GridPage(data, total, st), text);
    }

    public async Task<QueryResult<IReadOnlyList<CountRow>>> ValueCountsAsync(GridQuery query, string column, CancellationToken ct)
    {
        var st = GridSql.Normalize(query.Spec, query.Request);
        var sp = new Dictionary<string, object?>(query.SourceParameters, StringComparer.Ordinal);
        if (query.Spec.SourceParameters.Contains("Source") && !sp.ContainsKey("Source")) sp["Source"] = _vulnSource;
        var (rows, text) = await Run(GridSql.ValueCounts(query.Spec, st, sp, column), ct).ConfigureAwait(false);
        return R<IReadOnlyList<CountRow>>(rows.Select(r => new CountRow(column, S(r, "V"), L(r, "N"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<FacetRow>>> FacetsAsync(ViewCollection collection, CancellationToken ct)
    {
        var (rows, text) = await Run(CollectionViewSql.FacetsOf(collection.CollectionId), ct).ConfigureAwait(false);
        return R<IReadOnlyList<FacetRow>>(rows.Select(r => new FacetRow(S(r, "Facet"), S(r, "Value"), L(r, "Findings"), L(r, "Assets"), D(r, "ScoreTotal"),
            DN(r, "WeightedTotal"), DN(r, "MaxScore"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<CountRow>>> ChangeSummaryAsync(ViewCollection a, ViewCollection b, CancellationToken ct)
    {
        // #812: the headline the data sync wrote for the pair (the page reads it only when that pair is written: ChangeStateAsync)
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.ChangeSummaryStored, new Dictionary<string, object?>
        {
            ["A"] = CollectionViewSql.CollectionId(a.CollectionId), ["B"] = CollectionViewSql.CollectionId(b.CollectionId),
        }), ct).ConfigureAwait(false);
        return R<IReadOnlyList<CountRow>>(rows.Select(r => new CountRow(S(r, "What"), S(r, "Change"), L(r, "N"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<CountRow>>> ExemptionStatesAsync(DateTime at, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.ExemptionStates, new Dictionary<string, object?> { ["At"] = at }), ct).ConfigureAwait(false);
        return R<IReadOnlyList<CountRow>>(rows.Select(r => new CountRow(S(r, "State"), S(r, "Scope"), L(r, "N"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<ExclusionDocRow>>> ExclusionDocumentsAsync(CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.ExclusionDocuments, new Dictionary<string, object?>()), ct).ConfigureAwait(false);
        return R<IReadOnlyList<ExclusionDocRow>>(rows.Select(r => new ExclusionDocRow(S(r, "DocKey"), T(r, "UpdatedAt"), S(r, "UpdatedBy"), L(r, "BodyLength"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<CountRow>>> EventCountsAsync(DateTime from, DateTime to, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.EventCounts, new Dictionary<string, object?> { ["From"] = from, ["To"] = to }), ct).ConfigureAwait(false);
        return R<IReadOnlyList<CountRow>>(rows.Select(r => new CountRow("events", S(r, "Action"), L(r, "N"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<LifecycleDay>>> LifecycleDaysAsync(DateOnly since, DateOnly until, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.LifecycleDays, new Dictionary<string, object?>
        {
            ["Since"] = since.ToDateTime(TimeOnly.MinValue), ["Until"] = until.ToDateTime(TimeOnly.MinValue),
        }), ct).ConfigureAwait(false);
        return R<IReadOnlyList<LifecycleDay>>(rows.Select(r => new LifecycleDay(ProDataQueries.Day(r, "Day"), L(r, "Opened"), L(r, "Closed"), L(r, "Reopened"),
            ProDataQueries.LN(r, "OpenAtEndOfDay"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<ConnectorTotal>>> ConnectorTotalsAsync(DateTime from, DateTime to, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.ConnectorTotals, new Dictionary<string, object?> { ["From"] = from, ["To"] = to }), ct).ConfigureAwait(false);
        return R<IReadOnlyList<ConnectorTotal>>(rows.Select(r => new ConnectorTotal(S(r, "ConnectorName"), L(r, "Runs"), L(r, "Opened"), L(r, "Reopened"), L(r, "Updated"),
            L(r, "Closed"), L(r, "Errors"), T(r, "LastRun"), S(r, "Kind"), S(r, "Direction"), L(r, "Enabled") != 0, T(r, "LastRunEver"), S(r, "LastWhy"), L(r, "Unchanged"))).ToList(), text);
    }

    public async Task<QueryResult<AssetInfo?>> AssetAsync(string assetKey, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.Asset, new Dictionary<string, object?> { ["AssetKey"] = Key(assetKey) }), ct).ConfigureAwait(false);
        if (rows.Count == 0) return R<AssetInfo?>(null, text);
        var r = rows[0];
        var tier = SN(r, "TierRaw");
        return R<AssetInfo?>(new AssetInfo(S(r, "AssetKey"), S(r, "AssetName"), S(r, "AssetKind"),
            tier is not null && int.TryParse(tier, out var t) && t is >= 0 and <= 3 ? tier : ProDataFilters.Unclassified,
            S(r, "KeySource"), T(r, "FirstSeen"), T(r, "LastSeen"), SN(r, "PropertiesJson")), text);
    }

    public async Task<QueryResult<IReadOnlyList<IdentifierRow>>> IdentifiersAsync(string assetKey, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.AssetIdentifiers, new Dictionary<string, object?> { ["AssetKey"] = Key(assetKey) }), ct).ConfigureAwait(false);
        return R<IReadOnlyList<IdentifierRow>>(rows.Select(r => new IdentifierRow(S(r, "IdentifierType"), S(r, "IdentifierValue"), T(r, "FirstSeen"), T(r, "LastSeen"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<RecommendationRow>>> RecommendationsAsync(ViewCollection collection, string assetKey, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.AssetRecommendations, new Dictionary<string, object?>
        {
            ["CollectionId"] = CollectionViewSql.CollectionId(collection.CollectionId), ["AssetKey"] = Key(assetKey),
        }), ct).ConfigureAwait(false);
        return R<IReadOnlyList<RecommendationRow>>(rows.Select(r => new RecommendationRow(S(r, "RecommendationId"), S(r, "Name"), S(r, "Severity"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<AssetHistoryRow>>> AssetHistoryAsync(string assetKey, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.AssetHistory, new Dictionary<string, object?> { ["AssetKey"] = Key(assetKey) }), ct).ConfigureAwait(false);
        return R<IReadOnlyList<AssetHistoryRow>>(rows.Select(r => new AssetHistoryRow(S(r, "CollectionId"), T(r, "CollectionTime") ?? default, L(r, "Findings"),
            D(r, "TotalRisk"), D(r, "MaxRisk"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<AssetVulnRow>>> AssetVulnItemsAsync(string assetKey, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.AssetVulnItems, new Dictionary<string, object?> { ["AssetKey"] = Key(assetKey), ["Source"] = _vulnSource }), ct).ConfigureAwait(false);
        return R<IReadOnlyList<AssetVulnRow>>(rows.Select(r => new AssetVulnRow(S(r, "Cve"), S(r, "Severity"), S(r, "State"), T(r, "FirstSeen"), T(r, "LastSeen"),
            T(r, "ClosedAt"), SN(r, "CloseReason"))).ToList(), text);
    }

    public async Task<QueryResult<ServicesState>> ServicesStateAsync(ViewCollection collection, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.ServicesStatus, new Dictionary<string, object?> { ["CollectionId"] = CollectionViewSql.CollectionId(collection.CollectionId) }), ct).ConfigureAwait(false);
        var r = rows.FirstOrDefault();
        return R(r is null ? new ServicesState(null, 0, 0) : new ServicesState(T(r, "ServicesDerivedAt"), ProDataQueries.LN(r, "Services") ?? 0, ProDataQueries.LN(r, "UnplacedAssets") ?? 0), text);
    }

    public async Task<QueryResult<CveSummaryState>> CveSummaryStateAsync(ViewCollection collection, CancellationToken ct)
    {
        var q = new SqlQuery(CollectionViewSql.CveSummaryStatus, new Dictionary<string, object?> { ["CollectionId"] = CollectionViewSql.CollectionId(collection.CollectionId) });
        try
        {
            var (rows, text) = await Run(q, ct).ConfigureAwait(false);
            var r = rows.FirstOrDefault();
            return R(r is null ? new CveSummaryState(true, null, 0) : new CveSummaryState(true, T(r, "BuiltAt"), L(r, "Cves")), text);
        }
        // a database the update has not reached yet: no table -- the page says the update adds it (never the old live read)
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not ViewTimeoutException
                                   && ex.Message.Contains("Invalid object name", StringComparison.OrdinalIgnoreCase))
        {
            return R(new CveSummaryState(false, null, 0), EstateQueries.DescribeSql(q.Text, q.Parameters));
        }
    }

    public async Task<QueryResult<ChangeState>> ChangeStateAsync(ViewCollection b, CancellationToken ct)
    {
        var q = new SqlQuery(CollectionViewSql.ChangeStateSql, new Dictionary<string, object?> { ["B"] = CollectionViewSql.CollectionId(b.CollectionId) });
        try
        {
            var (rows, text) = await Run(q, ct).ConfigureAwait(false);
            var r = rows.FirstOrDefault();
            return R(r is null ? new ChangeState(true, null, null) : new ChangeState(true, S(r, "PrevCollectionId"), T(r, "BuiltAt")), text);
        }
        // a database the update has not reached yet: no table -- the page says the update adds it (never the old live read)
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not ViewTimeoutException
                                   && ex.Message.Contains("Invalid object name", StringComparison.OrdinalIgnoreCase))
        {
            return R(new ChangeState(false, null, null), EstateQueries.DescribeSql(q.Text, q.Parameters));
        }
    }

    public async Task<QueryResult<AssetSummaryState>> AssetSummaryStateAsync(ViewCollection collection, CancellationToken ct)
    {
        var q = new SqlQuery(CollectionViewSql.AssetSummaryStatus, new Dictionary<string, object?> { ["CollectionId"] = CollectionViewSql.CollectionId(collection.CollectionId) });
        try
        {
            var (rows, text) = await Run(q, ct).ConfigureAwait(false);
            var r = rows.FirstOrDefault();
            return R(r is null ? new AssetSummaryState(true, null, 0) : new AssetSummaryState(true, T(r, "BuiltAt"), L(r, "Assets")), text);
        }
        // a database the update has not reached yet: no table -- the page says the update adds it (never the old live read)
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not ViewTimeoutException
                                   && ex.Message.Contains("Invalid object name", StringComparison.OrdinalIgnoreCase))
        {
            return R(new AssetSummaryState(false, null, 0), EstateQueries.DescribeSql(q.Text, q.Parameters));
        }
    }

    public async Task<QueryResult<GroupingState>> GroupingStateAsync(ViewCollection collection, string groupingId, CancellationToken ct)
    {
        var q = new SqlQuery(SummaryGroupViewSql.State, new Dictionary<string, object?> { ["CollectionId"] = CollectionViewSql.CollectionId(collection.CollectionId), ["GroupingId"] = groupingId });
        try
        {
            var (rows, text) = await Run(q, ct).ConfigureAwait(false);
            var r = rows.FirstOrDefault();
            return R(r is not null && L(r, "HasGrouping") == 1 ? new GroupingState(true, T(r, "BuiltAt")) : new GroupingState(true, null), text);
        }
        // a database the update has not reached yet (no table, or the Groupings column): the page says the update adds it
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not ViewTimeoutException
                                   && (ex.Message.Contains("Invalid object name", StringComparison.OrdinalIgnoreCase) || ex.Message.Contains("Invalid column name", StringComparison.OrdinalIgnoreCase)))
        {
            return R(new GroupingState(false, null), EstateQueries.DescribeSql(q.Text, q.Parameters));
        }
    }

    public async Task<QueryResult<ServiceRow?>> ServiceAsync(ViewCollection collection, string serviceKey, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CollectionViewSql.Service, new Dictionary<string, object?>
        {
            ["CollectionId"] = CollectionViewSql.CollectionId(collection.CollectionId), ["Service"] = CollectionViewSql.ServiceKey(serviceKey),
        }), ct).ConfigureAwait(false);
        if (rows.Count == 0) return R<ServiceRow?>(null, text);
        var r = rows[0];
        return R<ServiceRow?>(new ServiceRow(S(r, "ServiceKey"), S(r, "ServiceName"), L(r, "Assets"), L(r, "SharedAssets"), L(r, "Findings"), DN(r, "WeightedTotal"),
            DN(r, "WeightedPerAsset"), L(r, "Critical"), L(r, "High"), L(r, "Medium"), L(r, "Low"), L(r, "Tier0"), L(r, "Tier1"), L(r, "Tier2"), L(r, "Tier3"),
            L(r, "TierUnclassified"), SN(r, "TopAssetKey"), SN(r, "TopAssetName"), DN(r, "TopAssetWeighted"), SN(r, "Sources")), text);
    }

    public async Task<QueryResult<CmdbState>> CmdbStateAsync(CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(WeightedServiceSql.Probe, new Dictionary<string, object?>()), ct).ConfigureAwait(false);
        var r = rows.FirstOrDefault();
        if (r is null) return R(CmdbState.None, text);
        bool B(string c) => L(r, c) == 1;
        long services = 0, crit = 0;
        if (B("HasCmdb"))
        {
            var (c, t2) = await Run(new SqlQuery(WeightedServiceSql.CmdbCounts, new Dictionary<string, object?>()), ct).ConfigureAwait(false);
            if (c.FirstOrDefault() is { } cr) { services = L(cr, "Services"); crit = ProDataQueries.LN(cr, "WithCriticality") ?? 0; }
            text += "\n\n" + t2;
        }
        return R(new CmdbState(B("HasCmdb"), services, crit, B("HasDepartments"), B("HasMembers")), text);
    }

    public async Task<QueryResult<IReadOnlyList<IReadOnlyDictionary<string, object?>>>> PivotAsync(ViewCollection collection, PivotRequest request, bool cmdb,
        RowVisibility? visibility, int max, CancellationToken ct, LifecycleFilter? lifecycle = null)
    {
        // #855: the CI lifecycle the pivot counts -- active unless a person chose another (the cube carries it as a key)
        lifecycle ??= LifecycleFilter.Active;
        // #812: an account that sees every department reads the collection's stored cube (never a GROUP BY over every finding);
        // a department-limited account keeps the live read restricted to its own findings (the cube spans every department)
        if (visibility is null)
        {
            if (!PivotSql.Storable(request))
                throw new PivotNotStoredException("The CVE / issue field is not pre-computed for the pivot (it would group every finding of the collection): one row per CVE is on Security recommendations > Vulnerabilities. Pick another field.", true);
            var sq = new SqlQuery(ProDataSql.FindingPivotStatusText, new Dictionary<string, object?> { ["CollectionId"] = CollectionViewSql.CollectionId(collection.CollectionId) });
            IReadOnlyList<IReadOnlyDictionary<string, object?>> st;
            try { st = (await Run(sq, ct).ConfigureAwait(false)).Rows; }
            catch (Exception ex) when (ex is not OperationCanceledException && ex is not ViewTimeoutException
                                       && ex.Message.Contains("Invalid object name", StringComparison.OrdinalIgnoreCase))
            {
                throw new PivotNotStoredException("The pivot needs the database update that adds its tables: the updater adds them (setup\\Initialize-SIDataSql.ps1 -- it only adds), and the next data sync fills them.", false);
            }
            if (st.Count > 0 && T(st[0], "BuiltAt") is null)
                throw new PivotNotStoredException("This collection's pivot is being prepared: the data sync works it out once per collection, right after the collection is loaded. It appears when the data sync that is running now, or the next one, has finished -- open this tab again in a few minutes.", true);
            var (srows, stext) = await Run(PivotSql.BuildStored(request, collection.CollectionId, cmdb, Exempted.Excluding, max, lifecycle), ct).ConfigureAwait(false);
            return R(srows, stext);
        }
        var (rows, text) = await Run(PivotSql.Build(request, collection.CollectionId, cmdb, visibility, max, lifecycle), ct).ConfigureAwait(false);
        return R(rows, text);
    }
}

/// #812: a pivot the stored cube does not answer (yet): the CVE / issue field, the cube not written yet, or no tables
/// (<see cref="Schema"/> false). The page says the message -- it never runs the pivot over every finding instead.
public sealed class PivotNotStoredException(string message, bool schema) : NotSupportedException(message)
{
    public bool Schema { get; } = schema;
}
