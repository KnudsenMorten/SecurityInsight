using System.Globalization;

namespace SI.Management.Core.ProData;

/// <summary>The seam the Pro data reads run through: one statement, its rows. The web app adapts its SQL executor,
/// the MCP server its read-only reader; tests record the statements.</summary>
public interface IProSql
{
    string SourceName { get; }
    Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> QueryAsync(SqlQuery query, CancellationToken ct);
}

/// The Core read-only SQL reader as an <see cref="IProSql"/> (the MCP server and chat).
public sealed class SqlReaderProSql(ISqlReader reader) : IProSql
{
    public string SourceName => reader.SourceName;
    public async Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> QueryAsync(SqlQuery query, CancellationToken ct)
        => (await reader.QueryAsync(query.Text, query.Parameters, ct).ConfigureAwait(false)).Cast<IReadOnlyDictionary<string, object?>>().ToList();
}

/// <summary>
/// Reads of the Pro data backend (sidata.*, vuln.*) per the §9.3.4 data contract. Every result carries the statement
/// and its parameter values. Pure mapping on top of <see cref="ProDataSql"/>.
/// </summary>
public interface IProDataQueries
{
    Task<QueryResult<IReadOnlyList<CollectionInfo>>> CollectionsAsync(int top, CancellationToken ct);
    Task<QueryResult<FindingPage>> FindingsAsync(FindingFilter filter, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<FindingRow>>> ExportAsync(FindingFilter filter, int max, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<PivotCell>>> PivotAsync(FindingFilter filter, CancellationToken ct);
    Task<QueryResult<FindingDetail?>> FindingAsync(string? collectionId, string findingId, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<TrendCell>>> TrendAsync(TrendRequest request, CancellationToken ct);
    Task<QueryResult<IReadOnlyDictionary<string, IReadOnlyList<string>>>> FacetsAsync(CancellationToken ct);
    /// The values each filter takes in one collection (severity, domain, report, tier). A reader without its own
    /// per-collection statement answers with the 30-day facets.
    Task<QueryResult<IReadOnlyDictionary<string, IReadOnlyList<string>>>> CollectionValuesAsync(string? collectionId, CancellationToken ct) => FacetsAsync(ct);
    Task<QueryResult<IReadOnlyList<LifecycleDay>>> LifecycleAsync(int days, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<OpenVulnCell>>> OpenVulnerabilitiesAsync(CancellationToken ct);
    /// The same for a page: never fails because the count took too long -- Known = false then (the page says so). A reader
    /// without its own statement answers with <see cref="OpenVulnerabilitiesAsync"/>.
    async Task<QueryResult<OpenVulnCounts>> OpenVulnerabilityCountsAsync(CancellationToken ct)
    {
        var r = await OpenVulnerabilitiesAsync(ct).ConfigureAwait(false);
        return new QueryResult<OpenVulnCounts>(new OpenVulnCounts(r.Data, true), r.Query, r.Source, r.AsOf);
    }
    Task<QueryResult<IReadOnlyList<TimeToFixRow>>> TimeToFixAsync(int days, CancellationToken ct);
    Task<QueryResult<WallboardKpis>> KpisAsync(CancellationToken ct);
    /// #855: the headline numbers of the CI lifecycle the board counts (null = active only). A reader without its own
    /// statement answers <see cref="KpisAsync(CancellationToken)"/>.
    Task<QueryResult<WallboardKpis>> KpisAsync(LifecycleFilter? lifecycle, CancellationToken ct) => KpisAsync(ct);
    /// #292: the wall board's top Tier-0 assets (Very High / High vulnerabilities, total risk). A reader without its own
    /// statement answers with none.
    Task<QueryResult<IReadOnlyList<Tier0Asset>>> Tier0TopAsync(int top, CancellationToken ct) =>
        Task.FromResult(new QueryResult<IReadOnlyList<Tier0Asset>>(Array.Empty<Tier0Asset>(), "", "", DateTimeOffset.UtcNow));
    /// #855 M9: the top Tier-0 assets of the counted CI lifecycle (null = active only).
    Task<QueryResult<IReadOnlyList<Tier0Asset>>> Tier0TopAsync(int top, LifecycleFilter? lifecycle, CancellationToken ct) => Tier0TopAsync(top, ct);
    /// #812: whether the shown collection's top Tier-0 assets are written by the data sync (false = being prepared; null = the
    /// database does not have the tables yet). A reader without its own statement answers true.
    Task<bool?> Tier0PreparedAsync(CancellationToken ct) => Task.FromResult<bool?>(true);
    Task<QueryResult<IReadOnlyList<string>>> ReportNamesAsync(CancellationToken ct);
    /// The Unclassified findings of the newest collection (the tier board's Unclassified lane explains the tables' count
    /// with it). A reader without its own statement answers null (not known).
    Task<QueryResult<UnclassifiedFindings?>> UnclassifiedFindingsAsync(CancellationToken ct) =>
        Task.FromResult(new QueryResult<UnclassifiedFindings?>(null, "", "", DateTimeOffset.UtcNow));
    /// #855 M15: the same of the CI lifecycle the tier board counts (null = active only).
    Task<QueryResult<UnclassifiedFindings?>> UnclassifiedFindingsAsync(LifecycleFilter? lifecycle, CancellationToken ct) => UnclassifiedFindingsAsync(ct);
    Task<QueryResult<IReadOnlyList<TierCount>>> TierCountsAsync(string? assetKind, string? text, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<TierSource>>> TierSourcesAsync(string? assetKind, string? text, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<TierAsset>>> TierAssetsAsync(TierBoardRequest request, CancellationToken ct);
    Task<QueryResult<TierAsset?>> AssetAsync(string assetKey, CancellationToken ct);
    /// #264: how many findings matching the filter carry an exemption mark (the "N exempted not counted" note). Null =
    /// not known (a reader without the statement, or a database without the mark).
    Task<long?> ExemptedCountAsync(FindingFilter filter, CancellationToken ct) => Task.FromResult<long?>(null);
    /// #812: a filter dropdown's counts from the stored cells (null = not answerable there, or not written yet: the page then
    /// counts the rows it reads itself, as before).
    Task<IReadOnlyList<(string Value, long N)>?> CellCountsAsync(FindingFilter filter, string col, CancellationToken ct) =>
        Task.FromResult<IReadOnlyList<(string Value, long N)>?>(null);
}

public sealed class ProDataQueries : IProDataQueries
{
    private readonly IProSql _sql;
    private readonly TimeProvider _clock;
    private readonly string _vulnSource;

    public ProDataQueries(IProSql sql, string vulnerabilitySource = "SecurityInsight", TimeProvider? clock = null)
    {
        _sql = sql;
        _vulnSource = string.IsNullOrWhiteSpace(vulnerabilitySource) ? "SecurityInsight" : vulnerabilitySource;
        _clock = clock ?? TimeProvider.System;
    }

    private DateTime Today => _clock.GetUtcNow().UtcDateTime.Date;

    // #264: the request's exempted scope applies to every statement BEFORE it runs and is described
    private async Task<(IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows, string Text)> Run(SqlQuery q, CancellationToken ct)
    {
        q = Exempted.Apply(q);
        return (await _sql.QueryAsync(q, ct).ConfigureAwait(false), EstateQueries.DescribeSql(q.Text, q.Parameters));
    }

    private QueryResult<T> R<T>(T data, string text) => new(data, text, _sql.SourceName, _clock.GetUtcNow());

    // ---- cell readers (SQL hands back CLR types; a fake hands back whatever it likes) ----
    internal static string S(IReadOnlyDictionary<string, object?> r, string c) =>
        r.TryGetValue(c, out var v) && v is not null ? (v is IFormattable f ? f.ToString(null, CultureInfo.InvariantCulture) : v.ToString() ?? "") : "";
    internal static string? SN(IReadOnlyDictionary<string, object?> r, string c) { var s = S(r, c); return s.Length == 0 ? null : s; }
    internal static long L(IReadOnlyDictionary<string, object?> r, string c) =>
        r.TryGetValue(c, out var v) && v is not null ? Convert.ToInt64(v is string s ? double.Parse(s, CultureInfo.InvariantCulture) : v, CultureInfo.InvariantCulture) : 0;
    internal static long? LN(IReadOnlyDictionary<string, object?> r, string c) => r.TryGetValue(c, out var v) && v is not null ? L(r, c) : null;
    internal static double D(IReadOnlyDictionary<string, object?> r, string c) => DN(r, c) ?? 0;
    internal static double? DN(IReadOnlyDictionary<string, object?> r, string c) =>
        r.TryGetValue(c, out var v) && v is not null ? Convert.ToDouble(v, CultureInfo.InvariantCulture) : null;
    internal static DateTime? T(IReadOnlyDictionary<string, object?> r, string c) => r.TryGetValue(c, out var v) ? v switch
    {
        DateTime d => d,
        DateTimeOffset o => o.UtcDateTime,
        DateOnly d => d.ToDateTime(TimeOnly.MinValue),
        string s when DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var p) => p,
        _ => null,
    } : null;
    internal static DateOnly Day(IReadOnlyDictionary<string, object?> r, string c) => T(r, c) is { } t ? DateOnly.FromDateTime(t) : default;

    internal static FindingRow MapFinding(IReadOnlyDictionary<string, object?> r) => new(
        S(r, "FindingId"), S(r, "CollectionId"), T(r, "CollectionTime"), S(r, "AssetKey"), S(r, "AssetName"), S(r, "AssetKind"),
        S(r, "ReportName"), S(r, "SecurityDomain"), S(r, "ConfigurationId"), S(r, "Cve"), S(r, "Title"), S(r, "Severity"),
        SN(r, "Tier") ?? ProDataFilters.Unclassified, D(r, "RiskScore"))
    {
        IsExempted = SN(r, "ExemptionId") is not null,
        ExemptedUntil = T(r, "ExemptedUntil"),
        AssetKinds = S(r, "AssetKinds"),
    };

    /// The "Category" of a Risk Analysis row (its DetailJson); null when it has none or the text is not JSON.
    public static string? CategoryOf(string? detailJson)
    {
        if (string.IsNullOrWhiteSpace(detailJson)) return null;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(detailJson);
            return doc.RootElement.ValueKind == System.Text.Json.JsonValueKind.Object
                   && doc.RootElement.TryGetProperty("Category", out var c) && c.ValueKind == System.Text.Json.JsonValueKind.String
                   && c.GetString() is { } s && s.Trim().Length > 0 ? s.Trim() : null;
        }
        catch (System.Text.Json.JsonException) { return null; }
    }

    internal static TierAsset MapAsset(IReadOnlyDictionary<string, object?> r) => new(
        S(r, "AssetKey"), S(r, "AssetName"), S(r, "AssetKind"), SN(r, "Tier") ?? ProDataFilters.Unclassified, T(r, "LastSeen"),
        SN(r, "TierSetBy"), SN(r, "TierReason"), SN(r, "TierClaims"));

    public async Task<QueryResult<IReadOnlyList<CollectionInfo>>> CollectionsAsync(int top, CancellationToken ct)
    {
        var (rows, text) = await Run(ProDataSql.CollectionsTop(top), ct).ConfigureAwait(false);
        return R<IReadOnlyList<CollectionInfo>>(rows.Select(r => new CollectionInfo(S(r, "CollectionId"), T(r, "CollectionTime") ?? default, S(r, "Kind"),
            LN(r, "RowTotal"), SN(r, "RunId"))).ToList(), text);
    }

    public async Task<QueryResult<FindingPage>> FindingsAsync(FindingFilter filter, CancellationToken ct)
    {
        var f = ProDataFilters.Normalize(filter);
        // #812: the default view reads the stored order and totals; while they are not written it says so (never the live read)
        if (ProDataSql.StoredPage(f))
        {
            var (built, schema, stateText) = await PivotStateAsync(f.CollectionId, ct).ConfigureAwait(false);
            if (!built) return R(new FindingPage(Array.Empty<FindingRow>(), 0, f.Skip, f.Take) { Prepared = false, Schema = schema }, stateText);
            var (srows, stext) = await Run(ProDataSql.FindingsPageStored(f), ct).ConfigureAwait(false);
            return R(new FindingPage(srows.Select(MapFinding).ToList(), srows.Count > 0 ? L(srows[0], "TotalRows") : 0, f.Skip, f.Take), stext);
        }
        var (rows, text) = await Run(ProDataSql.FindingsPage(f), ct).ConfigureAwait(false);
        var total = rows.Count > 0 ? L(rows[0], "TotalRows") : 0;
        return R(new FindingPage(rows.Select(MapFinding).ToList(), total, f.Skip, f.Take), text);
    }

    /// #812: whether the stored order and cells of the chosen (or the published) collection are written: (built, the database
    /// has the tables, the statement). No collection = built (nothing to prepare -- the page says there is no collection).
    public async Task<(bool Built, bool Schema, string Text)> PivotStateAsync(string? collectionId, CancellationToken ct)
    {
        var q = ProDataSql.FindingPivotStatus(collectionId);
        try
        {
            var (rows, text) = await Run(q, ct).ConfigureAwait(false);
            return (rows.Count == 0 || T(rows[0], "BuiltAt") is not null, true, text);
        }
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not ViewTimeoutException
                                   && ex.Message.Contains("Invalid object name", StringComparison.OrdinalIgnoreCase))
        {
            return (false, false, EstateQueries.DescribeSql(q.Text, q.Parameters));
        }
    }

    public async Task<QueryResult<IReadOnlyList<FindingRow>>> ExportAsync(FindingFilter filter, int max, CancellationToken ct)
    {
        var (rows, text) = await Run(ProDataSql.FindingsExport(filter, max), ct).ConfigureAwait(false);
        return R<IReadOnlyList<FindingRow>>(rows.Select(MapFinding).ToList(), text);
    }

    /// The pivot of the filtered view. Read once per data version when a cache is given (<see cref="ViewsCache"/>): the key
    /// is the statement as it runs -- the filter, the visibility and the request's exempted scope are all in it.
    public Task<QueryResult<IReadOnlyList<PivotCell>>> PivotAsync(FindingFilter filter, CancellationToken ct)
    {
        var nf = ProDataFilters.Normalize(filter);
        if (ProDataSql.StoredFilter(nf)) return StoredPivot(nf, ct);
        async Task<QueryResult<IReadOnlyList<PivotCell>>> Read()
        {
            var (rows, text) = await Run(ProDataSql.Pivot(filter), ct).ConfigureAwait(false);
            return R<IReadOnlyList<PivotCell>>(rows.Select(r => new PivotCell(SN(r, "Tier") ?? ProDataFilters.Unclassified, S(r, "Severity"), S(r, "SecurityDomain"),
                L(r, "Findings"), L(r, "Assets"))).ToList(), text);
        }
        return ViewsCache is null ? Read() : ViewsCache.GetAsync(ViewResultCache.Key("findings.pivot", Exempted.Apply(ProDataSql.Pivot(filter))), Read, ct);
    }

    public async Task<IReadOnlyList<(string Value, long N)>?> CellCountsAsync(FindingFilter filter, string col, CancellationToken ct)
    {
        var f = ProDataFilters.Normalize(filter);
        if (!ProDataSql.StoredFilter(f) || ProDataSql.CellColumn(col) is null) return null;
        if (!(await PivotStateAsync(f.CollectionId, ct).ConfigureAwait(false)).Built) return null;
        var (rows, _) = await Run(ProDataSql.CellCounts(f, col), ct).ConfigureAwait(false);
        return rows.Select(r => (S(r, "V"), L(r, "N"))).ToList();
    }

    /// #812: the pivot of a filter the stored cells answer -- none while they are not written (the page says so).
    private async Task<QueryResult<IReadOnlyList<PivotCell>>> StoredPivot(FindingFilter f, CancellationToken ct)
    {
        var (built, _, stateText) = await PivotStateAsync(f.CollectionId, ct).ConfigureAwait(false);
        if (!built) return R<IReadOnlyList<PivotCell>>(Array.Empty<PivotCell>(), stateText);
        var (rows, text) = await Run(ProDataSql.PivotStored(f), ct).ConfigureAwait(false);
        return R<IReadOnlyList<PivotCell>>(rows.Select(r => new PivotCell(SN(r, "Tier") ?? ProDataFilters.Unclassified, S(r, "Severity"), S(r, "SecurityDomain"),
            L(r, "Findings"), L(r, "Assets"))).ToList(), text);
    }

    /// The views' results per data version (set by the web app; null = every read is live).
    public ViewResultCache? ViewsCache { get; init; }

    public async Task<QueryResult<FindingDetail?>> FindingAsync(string? collectionId, string findingId, CancellationToken ct)
    {
        var (rows, text) = await Run(ProDataSql.Finding(collectionId, findingId), ct).ConfigureAwait(false);
        if (rows.Count == 0) return R<FindingDetail?>(null, text);
        var f = MapFinding(rows[0]);
        // #283: the finding's Category, from the Risk Analysis row this read already carries
        if (CategoryOf(SN(rows[0], "DetailJson")) is { } cat) f = f with { Category = cat };
        IReadOnlyList<(string, string)> ids = Array.Empty<(string, string)>();
        if (ProDataFilters.AssetKey(f.AssetKey) is { } key)
        {
            var (idRows, idText) = await Run(ProDataSql.Identifiers(key), ct).ConfigureAwait(false);
            ids = idRows.Select(r => (S(r, "IdentifierType"), S(r, "IdentifierValue"))).ToList();
            text += "\n;\n" + idText;
        }
        return R<FindingDetail?>(new FindingDetail(f, SN(rows[0], "DetailJson"), SN(rows[0], "PropertiesJson"), ids), text);
    }

    /// A Pro database whose FindingDaily predates the additive ScoreMax column (the data sync adds it on its next run).
    internal static bool IsMissingScoreMax(Exception ex) =>
        ex.Message.Contains("ScoreMax", StringComparison.OrdinalIgnoreCase) && ex.Message.Contains("column", StringComparison.OrdinalIgnoreCase);

    /// #295: a Pro database without sidata.AssetDaily (or its counted twin) yet -- the data sync adds them on its next run.
    internal static bool IsMissingAssetDaily(Exception ex) =>
        ex.Message.Contains("AssetDaily", StringComparison.OrdinalIgnoreCase) && ex.Message.Contains("Invalid object name", StringComparison.OrdinalIgnoreCase);

    public async Task<QueryResult<IReadOnlyList<TrendCell>>> TrendAsync(TrendRequest request, CancellationToken ct)
    {
        IReadOnlyList<IReadOnlyDictionary<string, object?>> rows; string text;
        try { (rows, text) = await Run(ProDataSql.Trend(request, Today), ct).ConfigureAwait(false); }
        catch (Exception ex) when (IsMissingScoreMax(ex) || IsMissingAssetDaily(ex))
        {
            // an older database: without the column / table that is missing, the rest of the trend is read as before
            var noMax = IsMissingScoreMax(ex);
            try { (rows, text) = await Run(ProDataSql.Trend(request, Today, withScoreMax: !noMax, withAssetDaily: noMax), ct).ConfigureAwait(false); }
            catch (Exception ex2) when (IsMissingScoreMax(ex2) || IsMissingAssetDaily(ex2))
            { (rows, text) = await Run(ProDataSql.Trend(request, Today, withScoreMax: false, withAssetDaily: false), ct).ConfigureAwait(false); }
        }
        // #295: Assets is the DISTINCT count at the grain shown; null = not computed yet for that day (shown as unknown)
        var cells = rows.Select(r => new TrendCell(Day(r, "Day"), S(r, "Dim"), L(r, "Findings"), LN(r, "Assets"), D(r, "ScoreTotal"), SN(r, "CollectionId"),
            DN(r, "ScoreMax"), L(r, "TopSeverityFindings"))).ToList();
        // within a day, a severity split reads Very High first -- never alphabetically
        var ordered = ProDataFilters.Normalize(request).Dimension == TrendDimensions.Severity
            ? cells.OrderBy(c => c.Day).ThenBy(c => c.Dimension, ProData.SeverityOrder.Comparer).ToList()
            : cells;
        return R<IReadOnlyList<TrendCell>>(ordered, text);
    }

    public async Task<QueryResult<IReadOnlyDictionary<string, IReadOnlyList<string>>>> FacetsAsync(CancellationToken ct)
    {
        var (rows, text) = await Run(ProDataSql.Facets(Today), ct).ConfigureAwait(false);
        IReadOnlyDictionary<string, IReadOnlyList<string>> d = rows.Where(r => S(r, "Value").Length > 0)
            .GroupBy(r => S(r, "Facet")).ToDictionary(g => g.Key, g => (IReadOnlyList<string>)(g.Key == "severity"
                ? g.Select(r => S(r, "Value")).Distinct().OrderBy(x => x, ProData.SeverityOrder.Comparer).ToList()
                : g.Select(r => S(r, "Value")).Distinct().OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList()));
        return R(d, text);
    }

    public async Task<QueryResult<IReadOnlyDictionary<string, IReadOnlyList<string>>>> CollectionValuesAsync(string? collectionId, CancellationToken ct)
    {
        var (rows, text) = await Run(ProDataSql.CollectionValues(collectionId), ct).ConfigureAwait(false);
        IReadOnlyDictionary<string, IReadOnlyList<string>> d = rows.Where(r => S(r, "Value").Length > 0)
            .GroupBy(r => S(r, "Facet")).ToDictionary(g => g.Key, g => (IReadOnlyList<string>)g.Select(r => S(r, "Value")).Distinct().OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList());
        return R(d, text);
    }

    public async Task<QueryResult<IReadOnlyList<LifecycleDay>>> LifecycleAsync(int days, CancellationToken ct)
    {
        // #855 W9: the closes by reason; a database without the columns yet (the data sync adds them) reads the total only
        IReadOnlyList<IReadOnlyDictionary<string, object?>> rows; string text;
        try { (rows, text) = await Run(ProDataSql.LifecycleSince(days, Today), ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex.Message.Contains("ClosedFixed", StringComparison.OrdinalIgnoreCase) || ex.Message.Contains("ClosedRetired", StringComparison.OrdinalIgnoreCase)
                                   || ex.Message.Contains("ClosedOther", StringComparison.OrdinalIgnoreCase))
        { (rows, text) = await Run(ProDataSql.LifecycleSince(days, Today, byReason: false), ct).ConfigureAwait(false); }
        return R<IReadOnlyList<LifecycleDay>>(rows.Select(r => new LifecycleDay(Day(r, "Day"), L(r, "Opened"), L(r, "Closed"), L(r, "Reopened"), LN(r, "OpenAtEndOfDay"))
        {
            ClosedFixed = LN(r, "ClosedFixed"), ClosedRetired = LN(r, "ClosedRetired"), ClosedOther = LN(r, "ClosedOther"),
        }).ToList(), text);
    }

    /// How long a page waits for its OWN count of the open vulnerabilities when the data sync has not counted them yet (a new
    /// install, a database before the update) -- then it says they are being counted instead of failing.
    public TimeSpan OpenVulnFallbackTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// The open vulnerabilities by severity and tier: the counts the data sync stored, else the statement that counts them.
    /// The fallback is not guarded here (a timeout surfaces as before); the page reads <see cref="OpenVulnerabilityCountsAsync"/>.
    public async Task<QueryResult<IReadOnlyList<OpenVulnCell>>> OpenVulnerabilitiesAsync(CancellationToken ct)
    {
        if (await OpenVulnsStoredAsync(ct).ConfigureAwait(false) is { } stored) return R(stored.Cells.Cells, stored.Text);
        var (rows, text) = await Run(ProDataSql.OpenVulns(_vulnSource), ct).ConfigureAwait(false);
        return R(OpenCells(rows), text);
    }

    /// <summary>
    /// The page's read: the stored counts (one small read); before the data sync counted them, the statement that counts them
    /// under <see cref="OpenVulnFallbackTimeout"/> -- running out of it answers Known = false (the page says the counts appear
    /// after the next data sync), never an error page. A database error other than a timeout still surfaces.
    /// </summary>
    public async Task<QueryResult<OpenVulnCounts>> OpenVulnerabilityCountsAsync(CancellationToken ct)
    {
        if (await OpenVulnsStoredAsync(ct).ConfigureAwait(false) is { } stored) return R(stored.Cells, stored.Text);
        var q = ProDataSql.OpenVulns(_vulnSource);
        try
        {
            var (rows, text) = await ViewTimeout.Run(t => Run(q, t), OpenVulnFallbackTimeout, ct).ConfigureAwait(false);
            return R(new OpenVulnCounts(OpenCells(rows), true), text);
        }
        catch (Exception ex) when (!ct.IsCancellationRequested && (ex is ViewTimeoutException || ViewTimeout.IsCommandTimeout(ex)))
        {
            return R(new OpenVulnCounts(Array.Empty<OpenVulnCell>(), false), EstateQueries.DescribeSql(Exempted.Apply(q).Text, q.Parameters));
        }
    }

    /// The stored counts of the configured source, or null when the data sync has not counted them yet (no state row, or a
    /// database without the tables).
    private async Task<(OpenVulnCounts Cells, string Text)?> OpenVulnsStoredAsync(CancellationToken ct)
    {
        IReadOnlyList<IReadOnlyDictionary<string, object?>> rows; string text;
        try { (rows, text) = await Run(ProDataSql.OpenVulnsStored(_vulnSource), ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not ViewTimeoutException
                                   && ex.Message.Contains("Invalid object name", StringComparison.OrdinalIgnoreCase)) { return null; }
        var at = rows.Select(r => T(r, "BuiltAt")).FirstOrDefault(t => t is not null);
        if (at is null) return null;
        return (new OpenVulnCounts(OpenCells(rows.Where(r => SN(r, "Severity") is not null)), true, at), text);
    }

    private static IReadOnlyList<OpenVulnCell> OpenCells(IEnumerable<IReadOnlyDictionary<string, object?>> rows) =>
        rows.Select(r => new OpenVulnCell(S(r, "Severity"), SN(r, "Tier") ?? ProDataFilters.Unclassified, L(r, "Items")))
            .OrderBy(x => x.Severity, ProData.SeverityOrder.Comparer).ThenBy(x => x.Tier, StringComparer.Ordinal).ToList();

    public async Task<QueryResult<IReadOnlyList<TimeToFixRow>>> TimeToFixAsync(int days, CancellationToken ct)
    {
        var (rows, text) = await Run(ProDataSql.TimeToFixSince(days, _vulnSource, Today), ct).ConfigureAwait(false);
        return R<IReadOnlyList<TimeToFixRow>>(rows.Select(r => new TimeToFixRow(S(r, "Severity"), L(r, "Fixed"), DN(r, "MedianDays"), DN(r, "P90Days")))
            .OrderBy(x => x.Severity, ProData.SeverityOrder.Comparer).ToList(), text);
    }

    public Task<QueryResult<WallboardKpis>> KpisAsync(CancellationToken ct) => KpisAsync(null, ct);

    public async Task<QueryResult<WallboardKpis>> KpisAsync(LifecycleFilter? lifecycle, CancellationToken ct)
    {
        IReadOnlyList<IReadOnlyDictionary<string, object?>> rows; string text;
        try { (rows, text) = await Run(ProDataSql.WallboardKpis(lifecycle: lifecycle), ct).ConfigureAwait(false); }
        catch (Exception ex) when (IsMissingScoreMax(ex)) { (rows, text) = await Run(ProDataSql.WallboardKpis(withScoreMax: false, lifecycle: lifecycle), ct).ConfigureAwait(false); }
        var r = rows.FirstOrDefault();
        var k = r is null ? new WallboardKpis(null, 0, 0, 0, 0, null, null)
            : new WallboardKpis(T(r, "CollectionTime"), L(r, "Findings"), L(r, "Tier0Findings"), L(r, "VeryHigh"), L(r, "High"), DN(r, "AverageRiskScore"), DN(r, "HighestRiskScore"));
        return R(k, text);
    }

    public Task<QueryResult<IReadOnlyList<Tier0Asset>>> Tier0TopAsync(int top, CancellationToken ct) => Tier0TopAsync(top, null, ct);

    public async Task<QueryResult<IReadOnlyList<Tier0Asset>>> Tier0TopAsync(int top, LifecycleFilter? lifecycle, CancellationToken ct)
    {
        // #812: the rows the data sync wrote for the collection (the counted twin when exempted findings are left out);
        // #855: of the counted CI lifecycle (default: active)
        var (rows, text) = await Run(ProDataSql.Tier0TopStored(top, lifecycle), ct).ConfigureAwait(false);
        return R<IReadOnlyList<Tier0Asset>>(rows.Select(r => new Tier0Asset(S(r, "AssetKey"), S(r, "AssetName"), S(r, "AssetKind"),
            L(r, "VeryHigh"), L(r, "High"), D(r, "RiskTotal"))).ToList(), text);
    }

    public async Task<bool?> Tier0PreparedAsync(CancellationToken ct)
    {
        try
        {
            var (rows, _) = await Run(ProDataSql.Tier0State(), ct).ConfigureAwait(false);
            return rows.FirstOrDefault() is { } r && L(r, "Ready") == 1;
        }
        catch (Exception ex) when (ex is not OperationCanceledException && ex.Message.Contains("Invalid object name", StringComparison.OrdinalIgnoreCase)) { return null; }
    }

    public Task<QueryResult<UnclassifiedFindings?>> UnclassifiedFindingsAsync(CancellationToken ct) => UnclassifiedFindingsAsync(null, ct);

    public async Task<QueryResult<UnclassifiedFindings?>> UnclassifiedFindingsAsync(LifecycleFilter? lifecycle, CancellationToken ct)
    {
        // 2026-10-19: the figures the data sync wrote for the collection (no row = not written yet: null, the board leaves the
        // line out); the counted ones when exempted findings are left out -- never the scan of every finding. #855 M15: of the
        // counted CI lifecycle, from the per-CI rows; a database without their columns yet reads the state row as before
        IReadOnlyList<IReadOnlyDictionary<string, object?>> rows; string text;
        try { (rows, text) = await Run(ProDataSql.UnclassifiedFindingsByLifecycle(lifecycle), ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException && (ex.Message.Contains("CiLifecycle", StringComparison.OrdinalIgnoreCase) || ex.Message.Contains("Unclassified", StringComparison.OrdinalIgnoreCase)))
        { (rows, text) = await Run(ProDataSql.UnclassifiedFindingsStored(), ct).ConfigureAwait(false); }
        var r = rows.FirstOrDefault();
        var p = Exempted.Excluding ? "Counted" : "";
        return R<UnclassifiedFindings?>(r is null ? null : new UnclassifiedFindings(L(r, p + "Findings"), L(r, p + "Assets"), L(r, p + "WithoutAsset")), text);
    }

    public async Task<QueryResult<IReadOnlyList<string>>> ReportNamesAsync(CancellationToken ct)
    {
        var (rows, text) = await Run(ProDataSql.ReportNames(), ct).ConfigureAwait(false);
        return R<IReadOnlyList<string>>(rows.Select(r => S(r, "ReportName")).Where(s => s.Length > 0).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<TierCount>>> TierCountsAsync(string? assetKind, string? text, CancellationToken ct)
    {
        var (rows, q) = await Run(ProDataSql.TierCounts(assetKind, text), ct).ConfigureAwait(false);
        return R<IReadOnlyList<TierCount>>(rows.Select(r => new TierCount(SN(r, "Tier") ?? ProDataFilters.Unclassified, L(r, "Assets"))).ToList(), q);
    }

    public async Task<QueryResult<IReadOnlyList<TierSource>>> TierSourcesAsync(string? assetKind, string? text, CancellationToken ct)
    {
        var (rows, q) = await Run(ProDataSql.TierSources(assetKind, text), ct).ConfigureAwait(false);
        // SI_TierSetBy is plural on purpose ("software+logon"): every source that agreed on the tier gets the asset.
        // An asset whose source is not recorded (empty, or 'unattributed') is counted under Source "" -- it is NEVER a
        // source of its own: a chip for "not recorded" would tell the reader nothing.
        var split = rows.SelectMany(r =>
            {
                var tier = SN(r, "Tier") ?? ProDataFilters.Unclassified;
                var known = TierSources.Split(SN(r, "SetBy"));
                return known.Length == 0
                    ? new[] { (Tier: tier, Source: "", Assets: L(r, "Assets")) }
                    : known.Select(s => (Tier: tier, Source: s, Assets: L(r, "Assets"))).ToArray();
            })
            .GroupBy(x => (x.Tier, x.Source)).Select(g => new TierSource(g.Key.Tier, g.Key.Source, g.Sum(x => x.Assets)))
            .OrderBy(x => x.Tier).ThenByDescending(x => x.Known).ThenByDescending(x => x.Assets).ThenBy(x => x.Source, StringComparer.Ordinal).ToList();
        return R<IReadOnlyList<TierSource>>(split, q);
    }

    public async Task<QueryResult<IReadOnlyList<TierAsset>>> TierAssetsAsync(TierBoardRequest request, CancellationToken ct)
    {
        var (rows, q) = await Run(ProDataSql.TierAssets(request), ct).ConfigureAwait(false);
        return R<IReadOnlyList<TierAsset>>(rows.Select(MapAsset).ToList(), q);
    }

    /// #264: the matching findings that carry a mark -- read with exempted findings included, whatever the request's scope.
    /// Only under a scope (one is set only where the database carries the mark); else null.
    public async Task<long?> ExemptedCountAsync(FindingFilter filter, CancellationToken ct)
    {
        if (Exempted.Current is null) return null;
        var nf = ProDataFilters.Normalize(filter);
        using var _ = Exempted.Use(ExemptedScope.IncludeAll);
        // #812: the stored cells answer it (every finding less the counted ones); not written yet = no count (no note)
        if (ProDataSql.StoredFilter(nf))
        {
            if (!(await PivotStateAsync(nf.CollectionId, ct).ConfigureAwait(false)).Built) return null;
            var (srows, _) = await Run(ProDataSql.ExemptedCountStored(nf), ct).ConfigureAwait(false);
            return srows.Count > 0 ? L(srows[0], "N") : 0;
        }
        var (rows, _) = await Run(ProDataSql.ExemptedCount(filter), ct).ConfigureAwait(false);
        return rows.Count > 0 ? L(rows[0], "N") : 0;
    }

    public async Task<QueryResult<TierAsset?>> AssetAsync(string assetKey, CancellationToken ct)
    {
        var (rows, q) = await Run(ProDataSql.Asset(assetKey), ct).ConfigureAwait(false);
        return R(rows.Count == 0 ? null : MapAsset(rows[0]), q);
    }

    /// The shared severity rank (<see cref="ProData.SeverityOrder.Rank"/>): Very High first, never alphabetical.
    public static int SeverityOrder(string? s) => ProData.SeverityOrder.Rank(s);

    /// Daily lifecycle rows -> day / week (Monday) / month buckets. OpenAtEnd is the bucket's last day's value.
    public static IReadOnlyList<LifecycleBucket> Bucket(IReadOnlyList<LifecycleDay> days, string grain)
    {
        DateOnly Start(DateOnly d) => grain switch
        {
            Grains.Week => d.AddDays(-(((int)d.DayOfWeek + 6) % 7)),
            Grains.Month => new DateOnly(d.Year, d.Month, 1),
            _ => d,
        };
        string Label(DateOnly s) => grain switch
        {
            Grains.Week => "Week of " + s.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            Grains.Month => s.ToString("yyyy-MM", CultureInfo.InvariantCulture),
            _ => s.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
        };
        return days.GroupBy(d => Start(d.Day)).OrderBy(g => g.Key).Select(g =>
        {
            var last = g.OrderBy(x => x.Day).Last();
            // #855 W9: the closes by reason are known for the bucket only when every day of it has them
            var known = g.All(x => x.ClosedFixed is not null);
            return new LifecycleBucket(g.Key, Label(g.Key), g.Sum(x => x.Opened), g.Sum(x => x.Closed), g.Sum(x => x.Reopened), last.OpenAtEndOfDay)
            {
                ClosedFixed = known ? g.Sum(x => x.ClosedFixed ?? 0) : null,
                ClosedRetired = known ? g.Sum(x => x.ClosedRetired ?? 0) : null,
                ClosedOther = known ? g.Sum(x => x.ClosedOther ?? 0) : null,
            };
        }).ToList();
    }
}
