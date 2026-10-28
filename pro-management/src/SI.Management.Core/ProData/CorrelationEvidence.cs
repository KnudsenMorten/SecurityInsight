using System.Globalization;

namespace SI.Management.Core.ProData;

// =====================================================================================================================
// CORRELATION EVIDENCE: why SecurityInsight says these source records are ONE CI, and how good the correlation is per
// collection. The data sync writes sidata.AssetEvidence / AssetIdHistory / AssetConflict / AssetCorrelation (see
// sql\si-data-schema.sql); this file only READS them -- read-only statements, every caller value a parameter, no
// per-row lookup into another table (the CollectionViewSql rule).
// =====================================================================================================================

/// One source record's key behind a CI (sidata.AssetEvidence).
public sealed record EvidenceRow(string Source, string RecordKind, string MemberAssetId, string KeyType, string KeyValue, string MatchRule, string Confidence,
    bool IsJoinKey, DateTime? SourceLastSeen, DateTime? RecordSeenAt, DateTime? FirstSeen, DateTime? LastSeen, long FirstLoadId, long LastLoadId);

/// One change of a CI's ids (sidata.AssetIdHistory): alias | rekey | merge.
public sealed record IdHistoryRow(string AssetKey, string EventType, string PreviousId, string CurrentId, string? ViaType, string? ViaValue, DateTime? DetectedAt);

/// One value the CI's source records disagree on, or a possible duplicate (sidata.AssetConflict).
public sealed record ConflictRow(string Field, string Source, string MemberAssetId, string Value, DateTime? FirstSeen, DateTime? LastSeen, long LastLoadId);

/// The CI's correlation in its newest correlated collection (sidata.AssetCorrelation).
public sealed record CorrelationCi(string CollectionId, DateTime CollectionTime, long Records, long SourceCount, string? Sources, string Confidence, string JoinRule,
    long Conflicts, long IdChanges, string? PossibleDuplicateOf, string? CmdbState, string? CmdbSource, string? CmdbId);

/// One count of the correlation-quality summary: per collection, a measure and a key (see <see cref="CorrelationViewSql.Summary"/>).
public sealed record CorrelationSummaryRow(string CollectionId, DateTime CollectionTime, string Measure, string Key, long N);

/// <summary>The reads of the Evidence section and the Correlation quality report. Every result carries its statement.</summary>
public interface ICorrelationViews
{
    Task<QueryResult<IReadOnlyList<EvidenceRow>>> EvidenceAsync(string assetKey, CancellationToken ct);
    /// The id history of a CI, and every row that names <paramref name="assetKey"/> as a previous id (the key now lives elsewhere).
    Task<QueryResult<IReadOnlyList<IdHistoryRow>>> IdHistoryAsync(string assetKey, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<ConflictRow>>> ConflictsAsync(string assetKey, CancellationToken ct);
    Task<QueryResult<CorrelationCi?>> LatestAsync(string assetKey, CancellationToken ct);
    /// The summary of one collection.
    Task<QueryResult<IReadOnlyList<CorrelationSummaryRow>>> SummaryAsync(string collectionId, CancellationToken ct);
    /// The same summary for the newest <paramref name="top"/> correlated collections.
    Task<QueryResult<IReadOnlyList<CorrelationSummaryRow>>> TrendAsync(int top, CancellationToken ct);
    /// When the collection's correlation evidence was computed (null = not yet).
    Task<QueryResult<DateTime?>> CorrelatedAtAsync(string collectionId, CancellationToken ct);
}

/// <summary>The statements. Fixed text, parameters only, read-only.</summary>
public static class CorrelationViewSql
{
    public const string Evidence = """
SELECT e.Source, e.RecordKind, e.MemberAssetId, e.KeyType, e.KeyValue, e.MatchRule, e.Confidence, e.IsJoinKey, e.SourceLastSeen, e.RecordSeenAt,
       e.FirstSeen, e.LastSeen, e.FirstLoadId, e.LastLoadId
FROM sidata.AssetEvidence AS e
WHERE e.AssetKey = @AssetKey
ORDER BY e.LastLoadId DESC, e.Source, e.MemberAssetId, e.IsJoinKey DESC, e.KeyType, e.KeyValue;
""";

    public const string IdHistory = """
SELECT h.AssetKey, h.EventType, h.PreviousId, h.CurrentId, h.ViaType, h.ViaValue, h.DetectedAt
FROM sidata.AssetIdHistory AS h
WHERE h.AssetKey = @AssetKey OR h.PreviousId = @AssetKey
ORDER BY h.DetectedAt DESC, h.EventType;
""";

    public const string Conflicts = """
SELECT k.Field, k.Source, k.MemberAssetId, k.Value, k.FirstSeen, k.LastSeen, k.LastLoadId
FROM sidata.AssetConflict AS k
WHERE k.AssetKey = @AssetKey
ORDER BY k.LastLoadId DESC, k.Field, k.Source, k.Value;
""";

    /// The CI's newest correlation row -- of the published run or before it, never of a run that is not trusted yet.
    public const string Latest = $"""
SELECT TOP (1) CONVERT(nvarchar(64), ac.CollectionId) AS CollectionId, c.CollectionTime, ac.Records, ac.SourceCount, ac.Sources, ac.Confidence, ac.JoinRule,
       ac.Conflicts, ac.IdChanges, ac.PossibleDuplicateOf, ac.CmdbState, ac.CmdbSource, ac.CmdbId
FROM sidata.AssetCorrelation AS ac
JOIN sidata.Collection AS c ON c.CollectionId = ac.CollectionId
WHERE ac.AssetKey = @AssetKey AND c.Status = N'Complete' AND c.CollectionTime <= ISNULL({PublishedRun.DetailedTime}, c.CollectionTime)
ORDER BY c.CollectionTime DESC;
""";

    public const string CorrelatedAt = """
SELECT c.CorrelatedAt
FROM sidata.Collection AS c
WHERE c.CollectionId = TRY_CONVERT(int, @CollectionId);
""";

    /// The counts of the report, one row per (collection, measure, key). Measures: assets | sources (1, 2, 3+) |
    /// single (the one source of a single-source CI) | confidence (exact, strong, weak) | join (the join rule) |
    /// conflicts (CIs with one) | idchanged (CIs with one) | idchanges (their sum) | duplicates (CIs with a possible
    /// duplicate) | cmdb (matched, si-only, stale) | cmdbsource (servicenow, generic-csv).
    private const string SummaryBody = """
ac AS (
    SELECT a.CollectionId, s.CollectionTime, a.SourceCount, a.Sources, a.Confidence, a.JoinRule, a.Conflicts, a.IdChanges, a.PossibleDuplicateOf,
           a.CmdbState, a.CmdbSource
    FROM sidata.AssetCorrelation AS a
    JOIN sel AS s ON s.CollectionId = a.CollectionId
)
SELECT CONVERT(nvarchar(64), x.CollectionId) AS CollectionId, x.CollectionTime, x.Measure, x.[Key], SUM(x.N) AS N
FROM (
    SELECT ac.CollectionId, ac.CollectionTime, N'assets' AS Measure, N'' AS [Key], CONVERT(bigint, 1) AS N FROM ac
    UNION ALL SELECT ac.CollectionId, ac.CollectionTime, N'sources', CASE WHEN ac.SourceCount >= 3 THEN N'3+' WHEN ac.SourceCount = 2 THEN N'2' ELSE N'1' END, 1 FROM ac
    UNION ALL SELECT ac.CollectionId, ac.CollectionTime, N'single', COALESCE(ac.Sources, N'(none)'), 1 FROM ac WHERE ac.SourceCount <= 1
    UNION ALL SELECT ac.CollectionId, ac.CollectionTime, N'confidence', ac.Confidence, 1 FROM ac
    UNION ALL SELECT ac.CollectionId, ac.CollectionTime, N'join', ac.JoinRule, 1 FROM ac
    UNION ALL SELECT ac.CollectionId, ac.CollectionTime, N'conflicts', N'', 1 FROM ac WHERE ac.Conflicts > 0
    UNION ALL SELECT ac.CollectionId, ac.CollectionTime, N'idchanged', N'', 1 FROM ac WHERE ac.IdChanges > 0
    UNION ALL SELECT ac.CollectionId, ac.CollectionTime, N'idchanges', N'', CONVERT(bigint, ac.IdChanges) FROM ac WHERE ac.IdChanges > 0
    UNION ALL SELECT ac.CollectionId, ac.CollectionTime, N'duplicates', N'', 1 FROM ac WHERE ac.PossibleDuplicateOf IS NOT NULL
    UNION ALL SELECT ac.CollectionId, ac.CollectionTime, N'cmdb', ac.CmdbState, 1 FROM ac WHERE ac.CmdbState IS NOT NULL
    UNION ALL SELECT ac.CollectionId, ac.CollectionTime, N'cmdbsource', ac.CmdbSource, 1 FROM ac WHERE ac.CmdbSource IS NOT NULL
) AS x
GROUP BY x.CollectionId, x.CollectionTime, x.Measure, x.[Key]
ORDER BY x.CollectionTime, x.Measure, x.[Key];
""";

    public const string Summary = """
WITH sel AS (
    SELECT c.CollectionId, c.CollectionTime FROM sidata.Collection AS c WHERE c.CollectionId = TRY_CONVERT(int, @CollectionId)
),
""" + SummaryBody;

    public const string Trend = $"""
WITH sel AS (
    SELECT TOP (@Top) c.CollectionId, c.CollectionTime FROM sidata.Collection AS c
    WHERE c.Status = N'Complete' AND c.Kind = N'Detailed' AND c.CorrelatedAt IS NOT NULL
      AND c.CollectionTime <= ISNULL({PublishedRun.DetailedTime}, c.CollectionTime)
    ORDER BY c.CollectionTime DESC
),
""" + SummaryBody;

    private static readonly string TierSort = "CASE WHEN g.[Tier] = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, g.[Tier]) END";

    public static readonly string[] Confidences = ["exact", "strong", "weak"];
    public static readonly string[] JoinRules = ["exact-id", "graph-link", "single-record", "unresolved"];
    public static readonly string[] CmdbStates = ["matched", "si-only", "stale"];

    /// The drill-down: one row per CI of one collection, with how it was correlated.
    public static readonly GridSpec Grid = GridSql.Check(new GridSpec("correlation", "", $"""
SELECT ac.AssetKey, COALESCE(ac.AssetName, ac.AssetKey) AS AssetName, ac.AssetKind, {ProDataSql.TierExpr("ac.Tier")} AS Tier,
       ac.Records, ac.SourceCount, ac.Sources, ac.Confidence, ac.JoinRule, ac.Conflicts, ac.IdChanges,
       CASE WHEN ac.PossibleDuplicateOf IS NULL THEN 0 ELSE 1 END AS HasDuplicate, ac.PossibleDuplicateOf,
       ac.CmdbState, ac.CmdbSource, ac.CmdbId
FROM sidata.AssetCorrelation AS ac
WHERE ac.CollectionId = TRY_CONVERT(int, @CollectionId)
""", new GridColumn[]
    {
        new("AssetKey", "Asset (CI) key", Search: true, Hidden: true),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        new("AssetName", "Asset (CI)", Filter: GridFilter.Contains, Search: true),
        // #431: NOT the any-part kind filter -- this view reads only the correlation tables (by contract); its Kind is the
        // CI's kind in THIS collection, and "Seen by" (Sources) already filters by every source system the CI is made of
        new("AssetKind", "Kind", Filter: GridFilter.Values),
        new("Records", "Source records", GridType.Number, GridFilter.Range),
        new("SourceCount", "Number of systems", GridType.Number, GridFilter.Range),
        new("Sources", "Seen by", Filter: GridFilter.Tokens, Search: true),
        new("Confidence", "Confidence", Filter: GridFilter.Values),
        new("JoinRule", "Joined by", Filter: GridFilter.Values),
        new("Conflicts", "Conflicts", GridType.Number, GridFilter.Range),
        new("IdChanges", "Id changes", GridType.Number, GridFilter.Range),
        new("HasDuplicate", "Possible duplicate", GridType.Flag, GridFilter.Values),
        new("PossibleDuplicateOf", "Possible duplicate of", Search: true, Hidden: true),
        new("CmdbState", "CMDB", Filter: GridFilter.Values),
        new("CmdbSource", "CMDB source", Filter: GridFilter.Values, Hidden: true),
        new("CmdbId", "CMDB id", Search: true, Hidden: true),
    }, "SourceCount", false, "AssetKey", ["CollectionId"], Immutable: true));
}

/// <summary>The SQL implementation over <see cref="IProSql"/>; every statement passes <see cref="SqlGuard"/> first.</summary>
public sealed class CorrelationViews : ICorrelationViews
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);
    private readonly IProSql _sql;
    private readonly TimeProvider _clock;

    private readonly ViewResultCache? _cache;

    /// <paramref name="cache"/>: the figures of a collection and the trend over the collections are read once per data
    /// version (the evidence is computed by the data sync; nothing else changes them); null = every read is live.
    public CorrelationViews(IProSql sql, TimeProvider? clock = null, ViewResultCache? cache = null) { _sql = sql; _clock = clock ?? TimeProvider.System; _cache = cache; }

    private async Task<(IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows, string Text)> Run(SqlQuery q, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(q.Text);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        return (await _sql.QueryAsync(q, cts.Token).ConfigureAwait(false), EstateQueries.DescribeSql(q.Text, q.Parameters));
    }

    private QueryResult<T> R<T>(T data, string text) => new(data, text, _sql.SourceName, _clock.GetUtcNow());
    private static string Key(string k) => ProDataFilters.AssetKey(k) ?? throw new ArgumentException("an asset key is required");
    private static Dictionary<string, object?> P(string k) => new() { ["AssetKey"] = Key(k) };
    private static string S(IReadOnlyDictionary<string, object?> r, string c) => ProDataQueries.S(r, c);
    private static string? SN(IReadOnlyDictionary<string, object?> r, string c) => ProDataQueries.SN(r, c);
    private static long L(IReadOnlyDictionary<string, object?> r, string c) => ProDataQueries.L(r, c);
    private static DateTime? T(IReadOnlyDictionary<string, object?> r, string c) => ProDataQueries.T(r, c);
    private static bool B(IReadOnlyDictionary<string, object?> r, string c) => r.TryGetValue(c, out var v) && v switch
    {
        bool b => b, null => false, string s => s is "1" or "True" or "true", _ => Convert.ToInt64(v, CultureInfo.InvariantCulture) != 0,
    };

    public async Task<QueryResult<IReadOnlyList<EvidenceRow>>> EvidenceAsync(string assetKey, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CorrelationViewSql.Evidence, P(assetKey)), ct).ConfigureAwait(false);
        return R<IReadOnlyList<EvidenceRow>>(rows.Select(r => new EvidenceRow(S(r, "Source"), S(r, "RecordKind"), S(r, "MemberAssetId"), S(r, "KeyType"), S(r, "KeyValue"),
            S(r, "MatchRule"), S(r, "Confidence"), B(r, "IsJoinKey"), T(r, "SourceLastSeen"), T(r, "RecordSeenAt"), T(r, "FirstSeen"), T(r, "LastSeen"),
            L(r, "FirstLoadId"), L(r, "LastLoadId"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<IdHistoryRow>>> IdHistoryAsync(string assetKey, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CorrelationViewSql.IdHistory, P(assetKey)), ct).ConfigureAwait(false);
        return R<IReadOnlyList<IdHistoryRow>>(rows.Select(r => new IdHistoryRow(S(r, "AssetKey"), S(r, "EventType"), S(r, "PreviousId"), S(r, "CurrentId"),
            SN(r, "ViaType"), SN(r, "ViaValue"), T(r, "DetectedAt"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<ConflictRow>>> ConflictsAsync(string assetKey, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CorrelationViewSql.Conflicts, P(assetKey)), ct).ConfigureAwait(false);
        return R<IReadOnlyList<ConflictRow>>(rows.Select(r => new ConflictRow(S(r, "Field"), S(r, "Source"), S(r, "MemberAssetId"), S(r, "Value"),
            T(r, "FirstSeen"), T(r, "LastSeen"), L(r, "LastLoadId"))).ToList(), text);
    }

    public async Task<QueryResult<CorrelationCi?>> LatestAsync(string assetKey, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CorrelationViewSql.Latest, P(assetKey)), ct).ConfigureAwait(false);
        if (rows.Count == 0) return R<CorrelationCi?>(null, text);
        var r = rows[0];
        return R<CorrelationCi?>(new CorrelationCi(S(r, "CollectionId"), T(r, "CollectionTime") ?? default, L(r, "Records"), L(r, "SourceCount"), SN(r, "Sources"),
            S(r, "Confidence"), S(r, "JoinRule"), L(r, "Conflicts"), L(r, "IdChanges"), SN(r, "PossibleDuplicateOf"), SN(r, "CmdbState"), SN(r, "CmdbSource"), SN(r, "CmdbId")), text);
    }

    private static IReadOnlyList<CorrelationSummaryRow> Rows(IReadOnlyList<IReadOnlyDictionary<string, object?>> rows) =>
        rows.Select(r => new CorrelationSummaryRow(S(r, "CollectionId"), T(r, "CollectionTime") ?? default, S(r, "Measure"), S(r, "Key"), L(r, "N"))).ToList();

    public Task<QueryResult<IReadOnlyList<CorrelationSummaryRow>>> SummaryAsync(string collectionId, CancellationToken ct) =>
        Figures("correlation.summary", new SqlQuery(CorrelationViewSql.Summary, new Dictionary<string, object?> { ["CollectionId"] = CollectionViewSql.CollectionId(collectionId) }), ct);

    public Task<QueryResult<IReadOnlyList<CorrelationSummaryRow>>> TrendAsync(int top, CancellationToken ct) =>
        Figures("correlation.trend", new SqlQuery(CorrelationViewSql.Trend, new Dictionary<string, object?> { ["Top"] = Math.Clamp(top, 1, 120) }), ct);

    /// The figures of one statement: read once per data version (the page ran the collection's passes and the trend over
    /// the collections on every load).
    private Task<QueryResult<IReadOnlyList<CorrelationSummaryRow>>> Figures(string view, SqlQuery q, CancellationToken ct)
    {
        async Task<QueryResult<IReadOnlyList<CorrelationSummaryRow>>> Read()
        {
            var (rows, text) = await Run(q, ct).ConfigureAwait(false);
            return R(Rows(rows), text);
        }
        return _cache is null ? Read() : _cache.GetAsync(ViewResultCache.Key(view, q), Read, ct);
    }

    public async Task<QueryResult<DateTime?>> CorrelatedAtAsync(string collectionId, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(CorrelationViewSql.CorrelatedAt, new Dictionary<string, object?> { ["CollectionId"] = CollectionViewSql.CollectionId(collectionId) }), ct).ConfigureAwait(false);
        return R(rows.Count == 0 ? null : T(rows[0], "CorrelatedAt"), text);
    }
}

// ---- the report: pure, so the math is provable from a fixture ---------------------------------------------------------

/// One figure of the report: its count, its share of the CIs (0..100) and the grid filter that lists those CIs.
public sealed record ReportFigure(string Label, long Count, double Share, IReadOnlyList<(string Column, string Value)> Filter);

/// The CMDB part. MatchRate = matched / (matched + SI only), 0..100; null when there is nothing to divide.
/// CMDB-only is NOT measured (SecurityInsight does not read the CMDB's own CI list) -- <see cref="CmdbOnlyMeasured"/> is false.
public sealed record CmdbMatch(long Matched, long SiOnly, long Stale, double? MatchRate, IReadOnlyList<string> Sources)
{
    public bool CmdbOnlyMeasured => false;
    public const string CmdbOnlyReason = "Not measured: SecurityInsight does not read the CMDB's own list of CIs yet, only the matches recorded on each asset.";
}

/// One point of the trend.
public sealed record CorrelationTrendPoint(string CollectionId, DateTime CollectionTime, long Assets, double MultiSourceShare, double WeakShare, long Conflicts, long IdChanges, double? MatchRate);

/// The report of one collection.
public sealed record CorrelationReport(long Assets, IReadOnlyList<ReportFigure> SourceBuckets, IReadOnlyList<ReportFigure> SingleSource,
    IReadOnlyList<ReportFigure> Confidence, ReportFigure WeakMatches, ReportFigure Conflicts, ReportFigure IdChanged, long IdChanges, ReportFigure PossibleDuplicates,
    CmdbMatch? Cmdb)
{
    public static double Share(long n, long total) => total <= 0 ? 0 : Math.Round(100.0 * n / total, 1);

    private static long N(IEnumerable<CorrelationSummaryRow> rows, string measure, string key = "") =>
        rows.Where(r => r.Measure == measure && r.Key == key).Sum(r => r.N);

    /// The report of ONE collection's summary rows (rows of other collections are ignored when <paramref name="collectionId"/> is set).
    public static CorrelationReport From(IEnumerable<CorrelationSummaryRow> rows, string? collectionId = null)
    {
        var rs = (collectionId is null ? rows : rows.Where(r => r.CollectionId == collectionId)).ToList();
        var total = N(rs, "assets");
        ReportFigure F(string label, long n, params (string, string)[] filter) => new(label, n, Share(n, total), filter);
        var buckets = new[]
        {
            F("1 source", N(rs, "sources", "1"), ("SourceCount", "..1")),
            F("2 sources", N(rs, "sources", "2"), ("SourceCount", "2..2")),
            F("3 or more sources", N(rs, "sources", "3+"), ("SourceCount", "3")),
        };
        var single = rs.Where(r => r.Measure == "single").OrderByDescending(r => r.N).ThenBy(r => r.Key, StringComparer.Ordinal)
            .Select(r => F(r.Key, r.N, ("SourceCount", "..1"), ("Sources", r.Key))).ToList();
        var conf = CorrelationViewSql.Confidences.Select(c => F(c, N(rs, "confidence", c), ("Confidence", c))).ToList();
        CmdbMatch? cmdb = null;
        var matched = N(rs, "cmdb", "matched"); var siOnly = N(rs, "cmdb", "si-only"); var stale = N(rs, "cmdb", "stale");
        if (matched + siOnly + stale > 0)
            cmdb = new CmdbMatch(matched, siOnly, stale, matched + siOnly == 0 ? null : Math.Round(100.0 * matched / (matched + siOnly), 1),
                rs.Where(r => r.Measure == "cmdbsource").OrderByDescending(r => r.N).Select(r => r.Key).ToList());
        return new CorrelationReport(total, buckets, single, conf,
            F("Weak matches", N(rs, "confidence", "weak"), ("Confidence", "weak")),
            F("With a conflict", N(rs, "conflicts"), ("Conflicts", "1")),
            F("With an id change", N(rs, "idchanged"), ("IdChanges", "1")), N(rs, "idchanges"),
            F("Possible duplicates", N(rs, "duplicates"), ("HasDuplicate", "1")),
            cmdb);
    }

    /// The trend: one point per collection, oldest first.
    public static IReadOnlyList<CorrelationTrendPoint> Trend(IEnumerable<CorrelationSummaryRow> rows) =>
        rows.GroupBy(r => (r.CollectionId, r.CollectionTime)).OrderBy(g => g.Key.CollectionTime).Select(g =>
        {
            var rep = From(g);
            return new CorrelationTrendPoint(g.Key.CollectionId, g.Key.CollectionTime, rep.Assets,
                Share(rep.SourceBuckets[1].Count + rep.SourceBuckets[2].Count, rep.Assets), rep.WeakMatches.Share, rep.Conflicts.Count, rep.IdChanges, rep.Cmdb?.MatchRate);
        }).ToList();
}

/// <summary>Plain language for the Evidence section: "Seen by Defender as device fd73f1d4… (exact id match)".</summary>
public static class EvidenceText
{
    public static string Rule(string matchRule) => matchRule switch
    {
        "exact-id" => "exact id match",
        "graph-link" => "linked through the Exposure Graph",
        "same-record" => "on the same source record",
        "cmdb-pinned" => "pinned to the CMDB CI",
        "cmdb-rule" => "matched to the CMDB by a rule",
        "cmdb-id" => "matched to the CMDB by an id",
        "cmdb-name" => "matched to the CMDB by name only",
        "unresolved" => "seen only in a finding -- no source record matched it",
        _ => matchRule,
    };

    public static string KeyLabel(string keyType) => keyType switch
    {
        "MdeDeviceId" or "AadDeviceId" => "device",
        "AadObjectId" => "object",
        "AzureResourceId" or "AzureVmId" => "resource",
        "ExposureGraphNodeId" or "EgNodeId" => "node",
        "Hostname" => "host name",
        "SecurityIdentifier" => "SID",
        "ActiveDirectoryObjectGuid" or "OnPremObjectGuid" => "object GUID",
        "IpAddress" => "IP address",
        "Upn" => "user",
        "Mail" => "mail",
        "CmdbId" => "CI",
        _ => "record",
    };

    /// Names in full; ids (anything else) shortened to their first 8 characters + "…".
    public static bool IsName(string keyType) => keyType is "Hostname" or "Upn" or "Mail" or "IpAddress";

    public static string Short(string keyType, string value) =>
        IsName(keyType) || value.Length <= 12 ? value : value[..8] + "…";

    /// An ARM id reads best by its last segment: "/subscriptions/.../virtualMachines/MGMT1" -> "MGMT1 (Azure resource)".
    private static string ValueText(string keyType, string value)
    {
        if (keyType == "AzureResourceId" && value.Contains('/'))
        {
            var last = value.TrimEnd('/').Split('/').Last();
            return last.Length > 0 ? last : Short(keyType, value);
        }
        return Short(keyType, value);
    }

    public static string Sentence(EvidenceRow e)
    {
        var who = e.Source is "Risk Analysis" ? "Risk Analysis" : e.Source;
        return $"Seen by {who} as {KeyLabel(e.KeyType)} {ValueText(e.KeyType, e.KeyValue)} ({Rule(e.MatchRule)})";
    }

    public static string Confidence(string c) => c switch { "exact" => "exact", "strong" => "strong", "weak" => "weak", _ => c };

    /// An id change in plain words.
    public static string History(IdHistoryRow h, string pageKey)
    {
        var via = h.ViaType is null ? "" : $" (both carry {KeyLabel(h.ViaType)} {Short(h.ViaType, h.ViaValue ?? "")})";
        if (h.PreviousId == pageKey && h.AssetKey != pageKey)
            return h.EventType == "merge" ? $"This id was merged into another CI{via}." : $"This id now belongs to another CI{via}.";
        return h.EventType switch
        {
            "alias" => $"A source record changed its id from {Short("", h.PreviousId)} to {Short("", h.CurrentId)}; it is the same asset{via}.",
            "rekey" => $"The CI's key changed from {Short("", h.PreviousId)} to {Short("", h.CurrentId)}{via}.",
            "merge" => $"The CI {Short("", h.PreviousId)} was merged into this one{via}.",
            _ => $"{h.EventType}: {h.PreviousId} -> {h.CurrentId}",
        };
    }
}
