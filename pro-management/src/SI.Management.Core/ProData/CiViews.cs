namespace SI.Management.Core.ProData;

// =====================================================================================================================
// THE CI VIEWS (V3-DATA-MODEL 2.13): the CIs, one CI with everything it carries, and the provider records -- read from
// the v3 tables the data sync fills (engine/pro-data/_shared/SI-DataCi.ps1): sidata.Ci, sidata.CiLink, sidata.CiFinding,
// sidata.CiDaily, sidata.CiRecord. An install that has not loaded them yet has no such tables: every read asks first
// (<see cref="CiSql.Schema"/>) and a missing table is an empty answer the page explains, never an error.
// Read-only statements, every caller value a parameter.
// =====================================================================================================================

/// Which v3 tables exist in this database. <paramref name="DocFields"/>: sidata.Ci carries the promoted document fields as
/// columns (<see cref="CiColumns.Promoted"/>; the schema update adds them).
/// <paramref name="CtxFields"/>: sidata.Ci also carries the columns of the view columns' list and their markers
/// (<see cref="ViewStoredColumns.CiSchemaColumns"/>).
/// <paramref name="FindingComponent"/>: sidata.CiFinding carries the finding's component as a column (the data sync adds
/// and fills it) -- the Findings per CI view then shows it and filters on it (<see cref="CiSql.FindingSpecFor"/>).
/// <paramref name="FindingSubCi"/> (#772): sidata.CiFinding also carries the finding's ServiceNow sub-CI (SubCi) -- shown and
/// filtered right after the component. <paramref name="CiOsFamily"/> (#772): sidata.Ci carries the OS family (OsFamily) --
/// the Findings per CI view shows and filters the OS family of each finding's CI.
public sealed record CiSchema(bool Ci, bool Links, bool Findings, bool Daily, bool Records, bool DocFields = false, bool CtxFields = false,
    bool FindingComponent = false, bool FindingSubCi = false, bool CiOsFamily = false)
{
    public static readonly CiSchema None = new(false, false, false, false, false);
}

/// <summary>
/// The state of sidata.Ci that decides how the CI views read it and when their cached filter values are stale:
/// <see cref="Mode"/> (<see cref="CiFieldMode"/>), and <see cref="Version"/> -- the newest collection time, the number of
/// CIs and of CIs whose columns are not filled yet. The CI build moves every CI's collection time each run, and the data
/// sync's fill moves the count of unfilled CIs, so a new version means new data.
/// </summary>
/// <see cref="CtxMode"/>: the same for the columns of the view columns' list (their own marker: CtxHash / CtxSet).
public sealed record CiDataState(CiFieldMode Mode, string Version, CiFieldMode CtxMode = CiFieldMode.Document)
{
    public static readonly CiDataState Unknown = new(CiFieldMode.Document, "");
}

/// One sidata.Ci row.
public sealed record CiRow(string CiId, string? Class, string? Name, string? AssetType, int? Tier, string? TierSetBy, string? TierReason, string? Lifecycle,
    bool? InternetExposed, string? CmdbId, string? CmdbName, string? CmdbCriticality, double? CriticalityFactor, string? RiskFactors, long? LinkCount,
    double? RiskScore, double? WeightedRiskScore, long? OpenFindings, DateTime? LastSeen, DateTime? CollectionTime, string? DocJson);

/// One linked object of a CI (sidata.CiLink).
public sealed record CiLinkRow(string Provider, string RecordType, string NativeId, bool IsPrimary, string? State, DateTime? LastSeen);

/// One finding of a CI, of the newest finding collection (sidata.CiFinding).
public sealed record CiFindingRow(string FindingKey, string? FindingType, string? Title, string? Severity, int? Tier, double? RiskScore, double? WeightedRiskScore,
    string? RiskRating, string? SecurityDomain, string? DetectedBy, string? RiskFactors, string? ExemptionId, DateTime? CollectionTime);

/// One day of a CI (sidata.CiDaily).
public sealed record CiDailyRow(DateOnly Day, int? Tier, double? RiskScore, double? WeightedRiskScore, long? OpenFindings);

/// One provider record (sidata.CiRecord) -- with its SI fields when read alone.
public sealed record CiRecordRow(string RecordKey, string? CiId, string Provider, string? RecordType, string? Class, string? Name, DateTime? SourceLastSeen,
    DateTime? CollectionTime, bool? Complete, string? DocJson);

/// One CI and everything the CI page shows.
public sealed record CiDetail(CiRow Ci, CiDocument Doc, IReadOnlyList<CiLinkRow> Links, IReadOnlyList<CiFindingRow> Findings, IReadOnlyList<CiDailyRow> Trend,
    IReadOnlyList<CiRecordRow> Records);

/// The values a filter offers (Facet = the column, V = a value, N = how many rows have it).
public sealed record CiFacet(string Facet, string Value, long N);

/// <summary>
/// One count of the tier board's tiles: how many CIs of one tier ("0".."3" or "Unclassified") have one value of one
/// column -- <see cref="Facet"/> "Class" (the kind of asset) or "TierSetBy" (who decided the tier); <see cref="Value"/> is
/// empty for the CIs that carry none. A tier's total is the sum of its "Class" counts.
/// </summary>
public sealed record CiTierCount(string Tier, string Facet, string Value, long N)
{
    public const string ClassFacet = "Class";
    public const string SetByFacet = "TierSetBy";
}

public interface ICiViews
{
    /// #812: whether the published collection's CI findings summary (sidata.CiFindingSummary) is written: true = written (or
    /// nothing published yet), false = being prepared, null = the database does not have the tables. A reader that does not keep
    /// it (a fake) answers true.
    Task<bool?> SummaryWrittenAsync(CancellationToken ct) => Task.FromResult<bool?>(true);
    Task<QueryResult<CiSchema>> SchemaAsync(CancellationToken ct);
    /// One page of a grid over sidata.Ci (<see cref="CiColumnCatalog.Spec"/>) or sidata.CiRecord (<see cref="CiSql.RecordSpec"/>);
    /// with <paramref name="export"/> every matching row up to <see cref="ProDataFilters.MaxExport"/>.
    Task<QueryResult<GridPage>> GridAsync(GridSpec spec, GridRequest request, bool export, CancellationToken ct);
    /// The values the CI filters offer (Class, Lifecycle).
    Task<QueryResult<IReadOnlyList<CiFacet>>> CiFacetsAsync(CancellationToken ct);
    /// How the CI grid reads sidata.Ci now, and the version its cached filter values belong to (<see cref="CiDataState"/>).
    Task<QueryResult<CiDataState>> DataStateAsync(CiSchema schema, CancellationToken ct) =>
        Task.FromResult(new QueryResult<CiDataState>(CiDataState.Unknown, "", "", DateTimeOffset.UtcNow));
    /// The values the CI filters offer, for a known state: cached per <see cref="CiDataState.Version"/> -- no table scan on a
    /// page load while the data did not change.
    Task<QueryResult<IReadOnlyList<CiFacet>>> CiFacetsAsync(CiDataState state, CancellationToken ct) => CiFacetsAsync(ct);
    /// #855 M25: the same choices counted over the CIs of a lifecycle (null = the default, active; the lifecycle facet itself
    /// always counts every state).
    Task<QueryResult<IReadOnlyList<CiFacet>>> CiFacetsAsync(CiDataState state, LifecycleFilter? lifecycle, CancellationToken ct) => CiFacetsAsync(state, ct);
    /// The values the record filters offer (Provider, RecordType, Class).
    Task<QueryResult<IReadOnlyList<CiFacet>>> RecordFacetsAsync(CancellationToken ct);
    /// How many rows of a CI grid hold each value of ONE value column, under the request's other filters (Facet = the
    /// column) -- what "+ Add filter" lists when it is first opened. None by default.
    Task<QueryResult<IReadOnlyList<CiFacet>>> ValueCountsAsync(GridSpec spec, GridRequest request, string column, CancellationToken ct) =>
        Task.FromResult(new QueryResult<IReadOnlyList<CiFacet>>(Array.Empty<CiFacet>(), "", "", DateTimeOffset.UtcNow));
    /// One CI with its links, findings, trend and records (null = no such CI).
    Task<QueryResult<CiDetail?>> CiAsync(string ciId, CiSchema schema, CancellationToken ct);
    Task<QueryResult<CiRecordRow?>> RecordAsync(string recordKey, CancellationToken ct);
    /// The tier board's tile counts: the CIs per tier and class, and per tier and who decided the tier -- two GROUP BYs over
    /// narrow columns of sidata.Ci (never the document), kept per data version.
    Task<QueryResult<IReadOnlyList<CiTierCount>>> TierCountsAsync(CancellationToken ct) =>
        Task.FromResult(new QueryResult<IReadOnlyList<CiTierCount>>(Array.Empty<CiTierCount>(), "", "", DateTimeOffset.UtcNow));
    /// The same counts over the CIs of the given lifecycle states only (null / empty = every CI) -- the board counts what its
    /// grid lists (owner 2026-10-19: the CI list, the tier board and the tab counts share the active default).
    Task<QueryResult<IReadOnlyList<CiTierCount>>> TierCountsAsync(IReadOnlyList<string>? lifecycles, CancellationToken ct) => TierCountsAsync(ct);
    /// The key of the asset (sidata.Asset) a CI is: mostly the CI id itself, else the id of one of its linked objects
    /// (the reverse of how a view finds a row's CI). Null = the asset table has no row for this CI.
    Task<QueryResult<string?>> AssetKeyOfCiAsync(string ciId, CiSchema schema, CancellationToken ct) =>
        Task.FromResult(new QueryResult<string?>(ciId, "", "", DateTimeOffset.UtcNow));
    /// The CI an asset key stands for: the CI of that id, else the CI that links it. Null = no CI.
    Task<QueryResult<string?>> CiOfAssetKeyAsync(string assetKey, CiSchema schema, CancellationToken ct) =>
        Task.FromResult(new QueryResult<string?>(assetKey, "", "", DateTimeOffset.UtcNow));
}

/// <summary>The statements. Fixed text, parameters only, read-only.</summary>
public static class CiSql
{
    /// How many days of the daily rows the CI page draws (the daily rows are kept 13 months by default).
    public const int TrendDays = 400;
    /// The most findings the CI page lists.
    public const int MaxFindings = 500;
    public const int MaxCiId = 64;
    public const int MaxRecordKey = 450;

    public static readonly string Schema = $"""
SELECT CASE WHEN OBJECT_ID(N'sidata.Ci') IS NULL THEN 0 ELSE 1 END AS HasCi,
       CASE WHEN OBJECT_ID(N'sidata.CiLink') IS NULL THEN 0 ELSE 1 END AS HasLink,
       CASE WHEN OBJECT_ID(N'sidata.CiFinding') IS NULL THEN 0 ELSE 1 END AS HasFinding,
       CASE WHEN OBJECT_ID(N'sidata.CiDaily') IS NULL THEN 0 ELSE 1 END AS HasDaily,
       CASE WHEN OBJECT_ID(N'sidata.CiRecord') IS NULL THEN 0 ELSE 1 END AS HasRecord,
       CASE WHEN COL_LENGTH(N'sidata.Ci', N'DocFieldsHash') IS NULL THEN 0 ELSE 1 END AS HasDocFields,
       CASE WHEN COL_LENGTH(N'sidata.CiFinding', N'Component') IS NULL THEN 0 ELSE 1 END AS HasFindingComponent,
       CASE WHEN COL_LENGTH(N'sidata.CiFinding', N'SubCi') IS NULL OR COL_LENGTH(N'sidata.CiFinding', N'PatchCycle') IS NULL OR COL_LENGTH(N'sidata.CiFinding', N'CvePublished') IS NULL THEN 0 ELSE 1 END AS HasFindingSubCi,
       CASE WHEN COL_LENGTH(N'sidata.Ci', N'OsFamily') IS NULL THEN 0 ELSE 1 END AS HasCiOsFamily,
       {ViewStoredColumns.CiSchemaProbe} AS HasCtxFields;
""";

    /// The state of sidata.Ci once the view columns' list is there too: also how many CIs' list columns are not filled from
    /// their current document for the shipped list (CtxUnfilled). Narrow columns only, never the document.
    public static readonly string StateCtx = $"""
SELECT MAX(c.CollectionTime) AS Newest, COUNT_BIG(*) AS Cis,
       SUM(CASE WHEN c.DocFieldsHash = ISNULL(c.ContentHash, 0x00) THEN 0 ELSE 1 END) AS Unfilled,
       SUM(CASE WHEN {ViewStoredColumns.CiContextFilledSql(ViewStoredColumns.CiSetLiteral)} THEN 0 ELSE 1 END) AS CtxUnfilled
FROM sidata.Ci AS c;
""";

    /// The state of sidata.Ci (<see cref="CiDataState"/>) once the promoted columns exist: narrow columns only, never the
    /// document (~20 ms over internal's 8,799 CIs; the hash columns are left out of every index so no index ties them).
    public const string State = """
SELECT MAX(c.CollectionTime) AS Newest, COUNT_BIG(*) AS Cis,
       SUM(CASE WHEN c.DocFieldsHash = ISNULL(c.ContentHash, 0x00) THEN 0 ELSE 1 END) AS Unfilled
FROM sidata.Ci AS c;
""";

    /// The same, on a database without the promoted columns yet.
    public const string StateNoFields = """
SELECT MAX(c.CollectionTime) AS Newest, COUNT_BIG(*) AS Cis, CONVERT(bigint, 0) AS Unfilled
FROM sidata.Ci AS c;
""";

    private const string CiFacetsColumns = """
SELECT N'Class' AS Facet, c.Class AS V, COUNT_BIG(*) AS N FROM sidata.Ci AS c WHERE c.Class IS NOT NULL AND c.Class <> N'' GROUP BY c.Class
UNION ALL
SELECT N'Lifecycle' AS Facet, c.Lifecycle AS V, COUNT_BIG(*) AS N FROM sidata.Ci AS c WHERE c.Lifecycle IS NOT NULL AND c.Lifecycle <> N'' GROUP BY c.Lifecycle
UNION ALL
SELECT N'AssetType' AS Facet, c.AssetType AS V, COUNT_BIG(*) AS N FROM sidata.Ci AS c WHERE c.AssetType IS NOT NULL AND c.AssetType <> N'' GROUP BY c.AssetType
UNION ALL
SELECT N'TierSetBy' AS Facet, c.TierSetBy AS V, COUNT_BIG(*) AS N FROM sidata.Ci AS c WHERE c.TierSetBy IS NOT NULL AND c.TierSetBy <> N'' GROUP BY c.TierSetBy
UNION ALL
""";

    /// The CI filters' values once every CI's promoted columns are current (<see cref="CiFieldMode.Columns"/>): columns only,
    /// no document read (owner 2026-10-11: the asset subtype's value list read every CI's DocJson, ~4 s per page load).
    public const string CiFacets = CiFacetsColumns + "\n" + """
SELECT N'AssetSubtype' AS Facet, c.AssetSubtype AS V, COUNT_BIG(*) AS N FROM sidata.Ci AS c WHERE c.AssetSubtype IS NOT NULL AND c.AssetSubtype <> N'' GROUP BY c.AssetSubtype
ORDER BY Facet, N DESC, V;
""";

    /// <see cref="CiFieldMode.Fallback"/>: the asset subtype from the column where it is current, else from the document.
    public const string CiFacetsFallback = CiFacetsColumns + "\n" + """
SELECT N'AssetSubtype' AS Facet, x.V, COUNT_BIG(*) AS N FROM sidata.Ci AS c
    CROSS APPLY (SELECT CONVERT(nvarchar(400), CASE WHEN c.DocFieldsHash = ISNULL(c.ContentHash, 0x00) THEN c.AssetSubtype
                                                    WHEN ISJSON(c.DocJson) = 1 THEN JSON_VALUE(c.DocJson, N'$.si_asset_subtype') END) AS V) AS x
    WHERE x.V IS NOT NULL AND x.V <> N'' GROUP BY x.V
ORDER BY Facet, N DESC, V;
""";

    /// <see cref="CiFieldMode.Document"/> (no promoted columns yet): the asset subtype from the document, as before.
    public const string CiFacetsDocument = CiFacetsColumns + "\n" + """
SELECT N'AssetSubtype' AS Facet, x.V, COUNT_BIG(*) AS N FROM sidata.Ci AS c
    CROSS APPLY (SELECT CONVERT(nvarchar(400), CASE WHEN ISJSON(c.DocJson) = 1 THEN JSON_VALUE(c.DocJson, N'$.si_asset_subtype') END) AS V) AS x
    WHERE x.V IS NOT NULL AND x.V <> N'' GROUP BY x.V
ORDER BY Facet, N DESC, V;
""";

    /// <summary>
    /// The value lists of the context filters (<see cref="CiColumnCatalog.ValueFilters"/>: Facet = the column key): each
    /// one GROUP BY over the column's own index (IX_Ci_&lt;column&gt;). Read only once every CI's list columns are filled
    /// (<see cref="CiFieldMode.Columns"/>), and cached per data version with the other filter values. "" = none.
    /// </summary>
    public static string ContextFacets(IReadOnlyList<CiColumn> filters) => filters.Count == 0 ? "" : string.Join("\nUNION ALL\n", filters.Select(c =>
        $"SELECT N'{c.Key}' AS Facet, CONVERT(nvarchar(400), c.[{c.Promoted}]) AS V, COUNT_BIG(*) AS N FROM sidata.Ci AS c WHERE c.[{c.Promoted}] IS NOT NULL AND c.[{c.Promoted}] <> N'' GROUP BY c.[{c.Promoted}]"))
        + "\nORDER BY Facet, N DESC, V;";

    public static string FacetsFor(CiFieldMode mode) => mode switch
    {
        CiFieldMode.Columns => CiFacets,
        CiFieldMode.Fallback => CiFacetsFallback,
        _ => CiFacetsDocument,
    };

    /// <summary>
    /// #855 M25: a facet statement counted over the CIs of <paramref name="lifecycle"/> (null or All = every CI, the statement
    /// as it is): every facet reads sidata.Ci through the lifecycle's predicate -- except the lifecycle facet itself, which
    /// always counts every state (it is the lifecycle choice's own counts). The predicate is written from the fixed state
    /// names only (<see cref="LifecycleFilter.Sql"/>).
    /// </summary>
    public static string LifecycleScoped(string sql, LifecycleFilter? lifecycle)
    {
        if (lifecycle is null || lifecycle.IsAll || sql.Length == 0) return sql;
        var scoped = "FROM (SELECT * FROM sidata.Ci AS c0 WHERE " + lifecycle.Sql("c0.Lifecycle") + ") AS c";
        return string.Join("\n", sql.Split('\n').Select(l => l.StartsWith("SELECT N'Lifecycle' AS Facet", StringComparison.Ordinal) ? l : l.Replace("FROM sidata.Ci AS c", scoped, StringComparison.Ordinal)));
    }

    public const string RecordFacets = """
SELECT N'Provider' AS Facet, r.Provider AS V, COUNT_BIG(*) AS N FROM sidata.CiRecord AS r WHERE r.Provider <> N'' GROUP BY r.Provider
UNION ALL
SELECT N'RecordType' AS Facet, r.RecordType AS V, COUNT_BIG(*) AS N FROM sidata.CiRecord AS r WHERE r.RecordType IS NOT NULL AND r.RecordType <> N'' GROUP BY r.RecordType
UNION ALL
SELECT N'Class' AS Facet, r.Class AS V, COUNT_BIG(*) AS N FROM sidata.CiRecord AS r WHERE r.Class IS NOT NULL AND r.Class <> N'' GROUP BY r.Class
ORDER BY Facet, N DESC, V;
""";

    public const string Ci = """
SELECT TOP (1) c.CiId, c.Class, c.Name, c.AssetType, c.Tier, c.TierSetBy, c.TierReason, c.Lifecycle, c.InternetExposed, c.CmdbId, c.CmdbName,
       c.CmdbCriticality, c.CriticalityFactor, c.RiskFactors, c.LinkCount, c.RiskScore, c.WeightedRiskScore, c.OpenFindings, c.LastSeen,
       c.CollectionTime, c.DocJson
FROM sidata.Ci AS c
WHERE c.CiId = @CiId;
""";

    public const string Links = """
SELECT l.Provider, l.RecordType, l.NativeId, l.IsPrimary, l.State, l.LastSeen
FROM sidata.CiLink AS l
WHERE l.CiId = @CiId
ORDER BY l.IsPrimary DESC, l.Provider, l.RecordType, l.NativeId;
""";

    public const string Findings = """
SELECT TOP (@Take) f.FindingKey, f.FindingType, f.Title, f.Severity, f.Tier, f.RiskScore, f.WeightedRiskScore, f.RiskRating, f.SecurityDomain,
       f.DetectedBy, f.RiskFactors, f.ExemptionId, f.CollectionTime
FROM sidata.CiFinding AS f
WHERE f.CiId = @CiId
ORDER BY CASE WHEN f.WeightedRiskScore IS NULL THEN 1 ELSE 0 END, f.WeightedRiskScore DESC, f.RiskScore DESC, f.FindingKey;
""";

    public const string Trend = """
SELECT d.[Day], d.Tier, d.RiskScore, d.WeightedRiskScore, d.OpenFindings
FROM sidata.CiDaily AS d
WHERE d.CiId = @CiId AND d.[Day] >= DATEADD(DAY, -@Days, CONVERT(date, SYSUTCDATETIME()))
ORDER BY d.[Day];
""";

    public const string CiRecords = """
SELECT r.RecordKey, r.CiId, r.Provider, r.RecordType, r.Class, r.Name, r.SourceLastSeen, r.CollectionTime, r.Complete
FROM sidata.CiRecord AS r
WHERE r.CiId = @CiId
ORDER BY r.Provider, r.RecordType, r.RecordKey;
""";

    public const string Record = """
SELECT TOP (1) r.RecordKey, r.CiId, r.Provider, r.RecordType, r.Class, r.Name, r.SourceLastSeen, r.CollectionTime, r.Complete, r.DocJson
FROM sidata.CiRecord AS r
WHERE r.RecordKey = @RecordKey;
""";

    /// <summary>
    /// The tier board's tiles: the CIs per tier and class (IX_Ci_Grid: Class, Tier) and per tier and who decided the tier
    /// (Tier and TierSetBy ride IX_Ci_Page) -- narrow columns only, never the document. The tier is the stored number;
    /// <see cref="TierOf"/> turns it into the one tier vocabulary of every page.
    /// </summary>
    public const string TierCounts = """
SELECT N'Class' AS Facet, c.Tier AS Tier, c.Class AS V, COUNT_BIG(*) AS N FROM sidata.Ci AS c GROUP BY c.Tier, c.Class
UNION ALL
SELECT N'TierSetBy' AS Facet, c.Tier AS Tier, c.TierSetBy AS V, COUNT_BIG(*) AS N FROM sidata.Ci AS c GROUP BY c.Tier, c.TierSetBy;
""";

    /// The same tiles over the CIs of some lifecycle states (@Lifecycles: a JSON list of stored values) -- what the board's
    /// grid lists under its lifecycle filter (the active default, owner 2026-10-19).
    public const string TierCountsByLifecycle = """
SELECT N'Class' AS Facet, c.Tier AS Tier, c.Class AS V, COUNT_BIG(*) AS N FROM sidata.Ci AS c
WHERE c.Lifecycle IN (SELECT v.[value] FROM OPENJSON(@Lifecycles) AS v) GROUP BY c.Tier, c.Class
UNION ALL
SELECT N'TierSetBy' AS Facet, c.Tier AS Tier, c.TierSetBy AS V, COUNT_BIG(*) AS N FROM sidata.Ci AS c
WHERE c.Lifecycle IN (SELECT v.[value] FROM OPENJSON(@Lifecycles) AS v) GROUP BY c.Tier, c.TierSetBy;
""";

    /// "0".."3", or "Unclassified" for anything else (no tier, or a number outside 0-3).
    public static string TierOf(long? tier) =>
        tier is >= 0 and <= 3 ? tier.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) : ProDataFilters.Unclassified;

    /// The asset (sidata.Asset) a CI is: the asset of the CI's own id, else the asset keyed by the id of one of its linked
    /// objects (as it is, or as 'az:' + an ARM id) -- the reverse of <see cref="DataColumnSql.CiKeyCte"/>. Seeks only.
    public const string AssetOfCi = """
SELECT TOP (1) x.AssetKey
FROM (
    SELECT a.AssetKey, 0 AS P FROM sidata.Asset AS a WHERE a.AssetKey = @CiId
    UNION ALL
    SELECT a.AssetKey, 1 AS P FROM sidata.CiLink AS l JOIN sidata.Asset AS a ON a.AssetKey = l.NativeId WHERE l.CiId = @CiId
    UNION ALL
    SELECT a.AssetKey, 2 AS P FROM sidata.CiLink AS l JOIN sidata.Asset AS a ON a.AssetKey = N'az:' + l.NativeId WHERE l.CiId = @CiId
) AS x
ORDER BY x.P, x.AssetKey;
""";

    /// The same on a database without sidata.CiLink: the asset of the CI's own id.
    public const string AssetOfCiNoLinks = """
SELECT TOP (1) a.AssetKey FROM sidata.Asset AS a WHERE a.AssetKey = @CiId;
""";

    /// The CI an asset key stands for: the CI of that id, else the CI that links it (as it is, or an 'az:' key by its ARM id).
    public const string CiOfAsset = """
SELECT TOP (1) x.CiId
FROM (
    SELECT c.CiId, 0 AS P FROM sidata.Ci AS c WHERE c.CiId = @Key
    UNION ALL
    SELECT l.CiId, 1 AS P FROM sidata.CiLink AS l WHERE l.NativeId = @Key
    UNION ALL
    SELECT l.CiId, 2 AS P FROM sidata.CiLink AS l WHERE @Key LIKE N'az:%' AND l.NativeId = SUBSTRING(@Key, 4, 450)
) AS x
ORDER BY x.P, x.CiId;
""";

    /// The same on a database without sidata.CiLink.
    public const string CiOfAssetNoLinks = """
SELECT TOP (1) c.CiId FROM sidata.Ci AS c WHERE c.CiId = @Key;
""";

    /// The Raw view's grid: one row per provider record.
    public static readonly GridSpec RecordSpec = GridSql.Check(new GridSpec("cirecords", "", """
SELECT r.RecordKey AS [RecordKey], r.Provider AS [Provider], r.RecordType AS [RecordType], r.Class AS [Class], r.Name AS [Name],
       r.CiId AS [CiId], r.SourceLastSeen AS [SourceLastSeen], r.CollectionTime AS [CollectionTime], CONVERT(int, r.Complete) AS [Complete]
FROM sidata.CiRecord AS r
""", new GridColumn[]
    {
        new("Provider", "Provider", Filter: GridFilter.Values),
        new("RecordType", "Record type", Filter: GridFilter.Values),
        new("Class", "Class", Filter: GridFilter.Values),
        new("Name", "Name", Filter: GridFilter.Contains, Search: true),
        new("RecordKey", "Record", Filter: GridFilter.Contains, Search: true),
        new("CiId", "CI", Filter: GridFilter.Contains, Search: true),
        new("SourceLastSeen", "Last seen by the source", GridType.Date, GridFilter.Dates),
        new("CollectionTime", "Collected", GridType.Date, GridFilter.Dates),
        new("Complete", "Complete collection", GridType.Flag, GridFilter.Values),
    }, "Name", false, "RecordKey", Array.Empty<string>(), Immutable: false));

    /// The Detailed view on CI data (V3-DATA-MODEL 2.13): one row per CI and finding, with the CI's values and the finding's
    /// lifecycle (sidata.CiFindingState: open / reopened / closed, first detected, last seen). The default columns follow the
    /// Detailed output map (data-model/outputs/excel-findings-detailed).
    /// <para>This is the grid of a database whose findings do not carry the component as a column yet; once the data sync
    /// added it the view reads <see cref="FindingSpecWithComponent"/> (<see cref="FindingSpecFor"/>). Both have the same
    /// name and the same column keys -- a saved layout fits either.</para>
    public static readonly GridSpec FindingSpec = FindingGrid(component: false);

    /// The same grid with the finding's COMPONENT (sidata.CiFinding.Component, a stored and indexed column: OS, SQL,
    /// Network, Hardware, Browser, Office, Application or Other -- the component classification's one value per finding):
    /// shown right after "Detected by", so the shipped layout has it next to the affected software, and filtered by its values.
    public static readonly GridSpec FindingSpecWithComponent = FindingGrid(component: true);

    /// #772 the same grid with the finding's SERVICENOW SUB-CI too (sidata.CiFinding.SubCi, stored and indexed: OS, SQL or Other
    /// by default -- the customer's buckets, Settings &gt; ServiceNow &gt; Sub-CI mapping), right after the component, filtered by
    /// its values (several at once).
    public static readonly GridSpec FindingSpecWithSubCi = FindingGrid(component: true, subci: true);

    /// #772 ... and the OS family of the finding's CI (sidata.Ci.OsFamily: Windows, Linux, ...), filtered by its values.
    public static readonly GridSpec FindingSpecWithOsFamily = FindingGrid(component: true, subci: true, osFamily: true);

    /// The column key of the CI's OS family on the Findings per CI grid, its heading and the shipped families (filter order).
    public const string FindingOsFamilyKey = "OsFamily";
    public const string FindingOsFamilyLabel = "OS family";
    public static readonly IReadOnlyList<string> OsFamilies = ["Windows", "Linux", "macOS", "iOS", "Android", "Network OS", "Other", "Unknown"];

    /// The column key of the finding's ServiceNow sub-CI on the Findings per CI grid, and its heading.
    public const string FindingSubCiKey = "SubCi";
    public const string FindingSubCiLabel = "ServiceNow sub-CI";

    /// #772 the finding's patch cycle (sidata.CiFinding.PatchCycle, stored with the sub-CI): its key, heading and values.
    public const string FindingPatchCycleKey = "PatchCycle";
    public const string FindingPatchCycleLabel = "Patch cycle";
    /// #772 the CVE's published date (sidata.CiFinding.CvePublished) and its age in days at the collection (a range filter).
    public const string FindingCvePublishedKey = "CvePublished";
    public const string FindingCveAgeKey = "CveAgeDays";
    public static readonly IReadOnlyList<string> PatchCycles = ["In monthly cycle", "Catch-up (older than 1 month)", "No fix available", "Unknown"];

    /// The shipped sub-CI buckets (data-model/dimensions: servicenow_subci) in the order the filter offers them; a customer's
    /// own bucket is still a valid filter value.
    public static readonly IReadOnlyList<string> FindingSubCis = ["OS", "SQL", "Other"];

    /// The column key of the finding's component on the Findings per CI grid.
    public const string FindingComponentKey = "Component";

    /// The values the component classification gives a finding (data-model/classification: the component dimension), in
    /// the order the filter offers them; any other value the data holds is still a valid filter value.
    public static readonly IReadOnlyList<string> FindingComponents = ["OS", "SQL", "Network", "Hardware", "Browser", "Office", "Application", "Other"];

    /// The Findings per CI grid of this database: with the component column where sidata.CiFinding has it.
    public static GridSpec FindingSpecFor(CiSchema schema) =>
        schema.FindingComponent ? (schema.FindingSubCi ? (schema.CiOsFamily ? FindingSpecWithOsFamily : FindingSpecWithSubCi) : FindingSpecWithComponent) : FindingSpec;

    /// <summary>
    /// #855 M5 (owner 2026-10-21: "default filter is active, so it should be active only"): the Findings per CI grid of this
    /// database over the CIs of <paramref name="lifecycle"/> (null = the default, active): the CI's lifecycle (sidata.Ci.Lifecycle;
    /// a finding no CI carries, or a CI without a lifecycle, is active) is a WHERE of the statement -- one spec per lifecycle
    /// choice, kept, so its text (and the result cache's key) differs per choice. All = the grid as it was.
    /// </summary>
    public static GridSpec FindingSpecFor(CiSchema schema, LifecycleFilter? lifecycle)
    {
        var life = lifecycle ?? LifecycleFilter.Active;
        if (life.IsAll) return FindingSpecFor(schema);
        var (component, subci, osFamily) = (schema.FindingComponent, schema.FindingComponent && schema.FindingSubCi, schema.FindingComponent && schema.FindingSubCi && schema.CiOsFamily);
        return LifecycleSpecs.GetOrAdd(string.Join("|", "findings", component, subci, osFamily, life.Key), _ => FindingGrid(component, subci, osFamily, life));
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, GridSpec> LifecycleSpecs = new(StringComparer.Ordinal);

    private static GridSpec FindingGrid(bool component, bool subci = false, bool osFamily = false, LifecycleFilter? lifecycle = null) => GridSql.Check(new GridSpec("cifindings", "", $"""
SELECT CONCAT(COALESCE(f.CiId, N'asset:' + f.AssetId), N'|', f.FindingKey) AS [RowKey], f.CiId AS [CiId], c.Name AS [Name], c.Class AS [Class],
       f.Tier AS [Tier], f.SecurityDomain AS [Domain], f.FindingKey AS [FindingKey], f.Title AS [Title], f.Severity AS [Severity],
       f.RiskScore AS [RiskScore], f.WeightedRiskScore AS [WeightedRiskScore], f.RiskRating AS [RiskRating], f.RiskFactors AS [RiskFactors],
       COALESCE(s.State, N'open') AS [State], s.FirstDetected AS [FirstDetected], s.LastSeen AS [LastSeen], c.CmdbName AS [CmdbName], c.CmdbId AS [CmdbId],
       f.DetectedBy AS [DetectedBy], f.CollectionTime AS [CollectionTime], f.FindingType AS [FindingType], f.ExemptionId AS [ExemptionId],
       c.AssetType AS [AssetType]{(component ? ", f.Component AS [Component]" : "")}{(subci ? ", f.SubCi AS [SubCi], f.PatchCycle AS [PatchCycle], f.CvePublished AS [CvePublished], DATEDIFF(day, f.CvePublished, f.CollectionTime) AS [CveAgeDays]" : "")}{(osFamily ? ", c.OsFamily AS [OsFamily]" : "")}
FROM sidata.CiFinding AS f
LEFT JOIN sidata.Ci AS c ON c.CiId = f.CiId
LEFT JOIN sidata.CiFindingState AS s ON s.OwnerKey = COALESCE(f.CiId, N'asset:' + f.AssetId) AND s.FindingKey = f.FindingKey{(lifecycle is null || lifecycle.IsAll ? "" : "\nWHERE " + lifecycle.Sql("c.Lifecycle"))}
""", FindingColumns(component, subci, osFamily), "WeightedRiskScore", true, "RowKey", Array.Empty<string>(), Immutable: false));

    private static GridColumn[] FindingColumns(bool component, bool subci, bool osFamily) =>
    [
        new("Name", "CI", Filter: GridFilter.Contains, Search: true),
        new("Class", "Class", Filter: GridFilter.Values),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values),
        new("Domain", "Security domain", Filter: GridFilter.Values),
        new("FindingKey", "Finding", Filter: GridFilter.Contains, Search: true),
        new("Title", "Title", Filter: GridFilter.Contains, Search: true),
        new("Severity", "Severity", Filter: GridFilter.Values, SortSql: SeverityOrder.SqlRank("g.[Severity]")),
        new("RiskScore", "Asset risk score", GridType.Number, GridFilter.Range),
        new("WeightedRiskScore", "Weighted asset risk score", GridType.Number, GridFilter.Range),
        new("RiskRating", "Risk rating", Filter: GridFilter.Values),
        new("RiskFactors", "Risk factors", Filter: GridFilter.Tokens),
        new("State", "State", Filter: GridFilter.Values),
        new("FirstDetected", "First detected", GridType.Date, GridFilter.Dates),
        new("LastSeen", "Last seen", GridType.Date, GridFilter.Dates),
        new("CmdbName", "CMDB name", Filter: GridFilter.Contains, Search: true),
        new("DetectedBy", "Detected by", Filter: GridFilter.Contains),
        // the component the finding concerns: the last shown column, so the affected software follows it in the shipped layout
        .. (component ? new GridColumn[] { new(FindingComponentKey, "Component", Filter: GridFilter.Values) } : Array.Empty<GridColumn>()),
        // #772 the ServiceNow sub-CI it is linked under, right after the component
        .. (subci ? new GridColumn[] { new(FindingSubCiKey, FindingSubCiLabel, Filter: GridFilter.Values), new(FindingPatchCycleKey, FindingPatchCycleLabel, Filter: GridFilter.Values),
            // the CVE's published date and, filtered as a range of days, its age at the collection (exposure age)
            new(FindingCvePublishedKey, "CVE published", GridType.Date, Hidden: true), new(FindingCveAgeKey, "CVE age (days)", GridType.Number, GridFilter.Range) } : Array.Empty<GridColumn>()),
        // #772 the OS family of the finding's CI (Windows vs. Linux)
        .. (osFamily ? new GridColumn[] { new(FindingOsFamilyKey, FindingOsFamilyLabel, Filter: GridFilter.Values) } : Array.Empty<GridColumn>()),
        // stored columns the view carries without showing them (the column chooser and "Export all columns" have them):
        // CVE or recommendation, the exemption the finding is under (empty = none), the CI's asset type
        new("FindingType", "Finding type", Filter: GridFilter.Values, Hidden: true),
        new("ExemptionId", "Exemption id", Filter: GridFilter.Contains, Hidden: true),
        new("AssetType", "Asset type", Filter: GridFilter.Values, Hidden: true),
        // the row's own CI reference (f.CiId) reads "CI key": the extra column "CI id" (the CI found in the CI list by that
        // key) is offered next to it, and a heading is one column's own
        new("CiId", "CI key", Filter: GridFilter.Contains, Search: true, Hidden: true),
        // a Findings summary row (its CMDB group) is read back through this grid when the action bar acts on it
        new("CmdbId", "CMDB id", Filter: GridFilter.Contains, Hidden: true),
        new("RowKey", "Row", Hidden: true),
    ];

    /// The Summary view on CI data: one row per finding x tier x severity x CMDB group, as in the spreadsheets -- how many
    /// CIs, the highest risk score and the weighted total. Follows the Summary output map (excel-findings-summary).
    // #812 (a large customer, 1,117,524 CI findings): the Summary view grouped every row of sidata.CiFinding on each request.
    // The data sync writes the groups once (sidata.CiFindingSummary, SI-DataViewContext.ps1 Invoke-SIDataCiFindingSummary, after
    // the CI build) under the collection the CI findings are of; the grid reads the groups of the collection the run published
    // -- the same columns, typed and indexed. A collection without them: no rows, and the page says they are being prepared.
    public static readonly GridSpec SummarySpec = GridSql.Check(new GridSpec("cisummary", "", $"""
SELECT s.RowKey AS [RowKey], s.Domain AS [Domain], s.FindingKey AS [FindingKey], s.Title AS [Title], s.Tier AS [Tier], s.Severity AS [Severity],
       s.CmdbId AS [CmdbId], s.CmdbName AS [CmdbName], s.CiCount AS [CiCount], s.MaxRiskScore AS [MaxRiskScore], s.WeightedTotal AS [WeightedTotal], s.RiskRating AS [RiskRating]
FROM sidata.CiFindingSummary AS s
WHERE s.CollectionId = {PublishedRun.DetailedId}
""", SummaryColumns(), "WeightedTotal", true, "RowKey", Array.Empty<string>(), Immutable: false));

    /// <summary>
    /// #855 M6: the Summary view over the CIs of <paramref name="lifecycle"/> (null = the default, active). The stored groups carry
    /// the CI's lifecycle as a KEY (sidata.CiFindingSummary.CiLifecycle; NULL = written before it, counted as active): ONE state
    /// reads its own rows (the RowKey stays one row); several states, or All, add the states' rows up per RowKey -- the CIs
    /// (each CI has one lifecycle, so the counts add up) and the weighted total summed, the highest score the highest.
    /// </summary>
    public static GridSpec SummarySpecFor(LifecycleFilter? lifecycle)
    {
        var life = lifecycle ?? LifecycleFilter.Active;
        return LifecycleSpecs.GetOrAdd("summary|" + life.Key, _ => life.States is { Count: 1 }
            ? GridSql.Check(new GridSpec("cisummary", "", $"""
SELECT s.RowKey AS [RowKey], s.Domain AS [Domain], s.FindingKey AS [FindingKey], s.Title AS [Title], s.Tier AS [Tier], s.Severity AS [Severity],
       s.CmdbId AS [CmdbId], s.CmdbName AS [CmdbName], s.CiCount AS [CiCount], s.MaxRiskScore AS [MaxRiskScore], s.WeightedTotal AS [WeightedTotal], s.RiskRating AS [RiskRating]
FROM sidata.CiFindingSummary AS s
WHERE s.CollectionId = {PublishedRun.DetailedId} AND {life.Sql("s.CiLifecycle")}
""", SummaryColumns(), "WeightedTotal", true, "RowKey", Array.Empty<string>(), Immutable: false))
            : GridSql.Check(new GridSpec("cisummary", "", $"""
SELECT s.RowKey AS [RowKey], MAX(s.Domain) AS [Domain], s.FindingKey AS [FindingKey], MAX(s.Title) AS [Title], s.Tier AS [Tier], s.Severity AS [Severity],
       s.CmdbId AS [CmdbId], MAX(s.CmdbName) AS [CmdbName], SUM(s.CiCount) AS [CiCount], MAX(s.MaxRiskScore) AS [MaxRiskScore], SUM(s.WeightedTotal) AS [WeightedTotal], MAX(s.RiskRating) AS [RiskRating]
FROM sidata.CiFindingSummary AS s
WHERE s.CollectionId = {PublishedRun.DetailedId}{(life.IsAll ? "" : " AND " + life.Sql("s.CiLifecycle"))}
GROUP BY s.RowKey, s.FindingKey, s.Tier, s.Severity, s.CmdbId
""", SummaryColumns(), "WeightedTotal", true, "RowKey", Array.Empty<string>(), Immutable: false)));
    }

    /// Whether the published collection's CI findings summary is written (Written = 1 also with no published collection; HasSchema
    /// = 0 on a database the update has not reached).
    /// TWO plain SELECTs (the web app runs only statements that start with SELECT / WITH -- SqlGuard; an IF ... ELSE batch was
    /// refused, "Only SELECT statements may run", on Findings per finding key): first whether the table is there, then --
    /// only when it is -- whether the published collection's summary is written.
    public const string SummarySchemaSql = "SELECT CONVERT(bit, CASE WHEN OBJECT_ID(N'sidata.CiFindingSummaryState') IS NULL THEN 0 ELSE 1 END) AS HasSchema;";
    public static readonly string SummaryStateSql = $"""
SELECT CONVERT(bit, CASE WHEN pc.Id IS NULL OR EXISTS (SELECT 1 FROM sidata.CiFindingSummaryState AS s WHERE s.CollectionId = pc.Id) THEN 1 ELSE 0 END) AS Written
FROM (SELECT {PublishedRun.DetailedId} AS Id) AS pc;
""";

    /// The same groups computed per request from every CI finding -- what the view read before 2026-10-19. Kept ONLY as the
    /// reference the equality check and the measurement compare the stored groups with; no page reads it.
    public static readonly GridSpec SummaryLiveSpec = GridSql.Check(new GridSpec("cisummary", "", """
SELECT CONCAT(f.FindingKey, N'|', COALESCE(CONVERT(nvarchar(4), f.Tier), N''), N'|', COALESCE(f.Severity, N''), N'|', COALESCE(c.CmdbId, N'')) AS [RowKey],
       MAX(f.SecurityDomain) AS [Domain], f.FindingKey AS [FindingKey], MAX(f.Title) AS [Title], f.Tier AS [Tier], f.Severity AS [Severity],
       c.CmdbId AS [CmdbId], MAX(c.CmdbName) AS [CmdbName], COUNT_BIG(DISTINCT COALESCE(f.CiId, f.AssetId)) AS [CiCount],
       MAX(f.RiskScore) AS [MaxRiskScore], SUM(ISNULL(f.WeightedRiskScore, 0)) AS [WeightedTotal], MAX(f.RiskRating) AS [RiskRating]
FROM sidata.CiFinding AS f
LEFT JOIN sidata.Ci AS c ON c.CiId = f.CiId
GROUP BY f.FindingKey, f.Tier, f.Severity, c.CmdbId
""", SummaryColumns(), "WeightedTotal", true, "RowKey", Array.Empty<string>(), Immutable: false));

    private static GridColumn[] SummaryColumns() =>
    [
        new("Domain", "Security domain", Filter: GridFilter.Values),
        new("FindingKey", "Finding", Filter: GridFilter.Contains, Search: true),
        new("Title", "Title", Filter: GridFilter.Contains, Search: true),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values),
        new("Severity", "Severity", Filter: GridFilter.Values, SortSql: SeverityOrder.SqlRank("g.[Severity]")),
        new("CmdbName", "CMDB group", Filter: GridFilter.Contains, Search: true),
        new("CiCount", "CIs", GridType.Number, GridFilter.Range),
        new("MaxRiskScore", "Highest risk score", GridType.Number, GridFilter.Range),
        new("WeightedTotal", "Weighted total", GridType.Number, GridFilter.Range),
        new("RiskRating", "Risk rating", Filter: GridFilter.Values),
        new("CmdbId", "CMDB id", Filter: GridFilter.Contains, Hidden: true),
        new("RowKey", "Row", Hidden: true),
    ];


    /// A CI id as it may reach a parameter (refused when it does not fit).
    public static string CiId(string? v)
    {
        var t = v?.Trim();
        if (string.IsNullOrEmpty(t)) throw new ArgumentException("a CI id is required");
        if (t.Length > MaxCiId || t.Any(char.IsControl)) throw new ArgumentException("the CI id is not valid");
        return t;
    }

    /// A record key as it may reach a parameter (provider + native id; ARM paths and UPNs included).
    public static string RecordKey(string? v)
    {
        var t = v?.Trim();
        if (string.IsNullOrEmpty(t)) throw new ArgumentException("a record key is required");
        if (t.Length > MaxRecordKey || t.Any(char.IsControl)) throw new ArgumentException("the record key is not valid");
        return t;
    }
}

/// <summary>The SQL implementation over <see cref="IProSql"/>; every statement passes <see cref="SqlGuard"/> first.</summary>
public sealed class CiViews : ICiViews
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);
    private readonly IProSql _sql;
    private readonly TimeProvider _clock;

    private readonly ViewResultCache? _cache;

    /// <paramref name="cache"/>: the views' results per data version (a page of All CIs, the findings per CI, the findings
    /// per finding key or the records is read once until the data sync stores new data); null = every read is live.
    /// <paramref name="keepProbes"/> (the web app): the two reads every CI view makes before its page -- which tables and
    /// columns exist, and the CIs' state -- are kept per process for <see cref="SchemaTtl"/> / <see cref="StateTtl"/>
    /// instead of being asked on every request; false = both are read every time.
    public CiViews(IProSql sql, TimeProvider? clock = null, ViewResultCache? cache = null, bool keepProbes = false)
    { _sql = sql; _clock = clock ?? TimeProvider.System; _cache = cache; _keepProbes = keepProbes; }

    /// How long the list of tables and columns is trusted (as the data version's: an update adds them; noticed within this).
    public static readonly TimeSpan SchemaTtl = TimeSpan.FromMinutes(5);
    /// How long the CIs' state is trusted (as one answer of the data version).
    public static readonly TimeSpan StateTtl = TimeSpan.FromSeconds(15);
    private readonly bool _keepProbes;
    private sealed record Kept<T>(DateTimeOffset At, T Value);
    private volatile Kept<QueryResult<CiSchema>>? _schemaKept;
    private volatile Kept<(CiSchema For, QueryResult<CiDataState> State)>? _stateKept;

    private async Task<(IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows, string Text)> Run(SqlQuery q, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(q.Text);
        var rows = await ViewTimeout.Run(t => _sql.QueryAsync(q, t), Timeout, ct).ConfigureAwait(false);
        return (rows, EstateQueries.DescribeSql(q.Text, q.Parameters));
    }

    private QueryResult<T> R<T>(T data, string text) => new(data, text, _sql.SourceName, _clock.GetUtcNow());
    private static Dictionary<string, object?> P(params (string K, object? V)[] p) => p.ToDictionary(x => x.K, x => x.V);

    /// 1 / true / "1" / "True" (whatever the reader hands back); anything else, a missing column included, false.
    internal static bool Flag(IReadOnlyDictionary<string, object?> r, string c) => r.TryGetValue(c, out var v) && v switch
    {
        bool b => b,
        null => false,
        string s => s is "1" or "True" or "true",
        IConvertible x => x.ToInt64(System.Globalization.CultureInfo.InvariantCulture) != 0,
        _ => false,
    };

    private static bool? FlagN(IReadOnlyDictionary<string, object?> r, string c) => r.TryGetValue(c, out var v) && v is not null ? Flag(r, c) : null;
    private static int? Int(IReadOnlyDictionary<string, object?> r, string c) => ProDataQueries.LN(r, c) is { } l ? (int)l : null;

    public async Task<QueryResult<CiSchema>> SchemaAsync(CancellationToken ct)
    {
        if (_keepProbes && _schemaKept is { } kept && _clock.GetUtcNow() - kept.At < SchemaTtl) return kept.Value;
        var (rows, text) = await Run(new SqlQuery(CiSql.Schema, P()), ct).ConfigureAwait(false);
        var r = rows.Count > 0 ? rows[0] : new Dictionary<string, object?>();
        var schema = R(new CiSchema(Flag(r, "HasCi"), Flag(r, "HasLink"), Flag(r, "HasFinding"), Flag(r, "HasDaily"), Flag(r, "HasRecord"), Flag(r, "HasDocFields"), Flag(r, "HasCtxFields"),
            Flag(r, "HasFindingComponent"), Flag(r, "HasFindingSubCi"), Flag(r, "HasCiOsFamily")), text);
        // a database without the CI table yet is asked again on the next request: the first CI build shows at once
        if (_keepProbes && schema.Data.Ci) _schemaKept = new Kept<QueryResult<CiSchema>>(_clock.GetUtcNow(), schema);
        return schema;
    }

    public async Task<QueryResult<CiDataState>> DataStateAsync(CiSchema schema, CancellationToken ct)
    {
        if (!schema.Ci) return R(CiDataState.Unknown, "");
        if (_keepProbes && _stateKept is { } kept && kept.Value.For == schema && _clock.GetUtcNow() - kept.At < StateTtl) return kept.Value.State;
        var state = await ReadDataState(schema, ct).ConfigureAwait(false);
        if (_keepProbes) _stateKept = new Kept<(CiSchema For, QueryResult<CiDataState> State)>(_clock.GetUtcNow(), (schema, state));
        return state;
    }

    private async Task<QueryResult<CiDataState>> ReadDataState(CiSchema schema, CancellationToken ct)
    {
        // the view columns' list is counted only on a database that has both sets of columns
        var ctx = schema.DocFields && schema.CtxFields;
        var (rows, text) = await Run(new SqlQuery(ctx ? CiSql.StateCtx : schema.DocFields ? CiSql.State : CiSql.StateNoFields, P()), ct).ConfigureAwait(false);
        var r = rows.Count > 0 ? rows[0] : new Dictionary<string, object?>();
        var newest = ProDataQueries.T(r, "Newest");
        var cis = ProDataQueries.LN(r, "Cis") ?? 0;
        var unfilled = ProDataQueries.LN(r, "Unfilled") ?? 0;
        var mode = !schema.DocFields ? CiFieldMode.Document : unfilled == 0 ? CiFieldMode.Columns : CiFieldMode.Fallback;
        var version = string.Join("|", mode, newest?.ToString("O", System.Globalization.CultureInfo.InvariantCulture) ?? "-", cis, unfilled);
        if (!ctx) return R(new CiDataState(mode, version), text);
        var ctxUnfilled = ProDataQueries.LN(r, "CtxUnfilled") ?? 0;
        var ctxMode = ctxUnfilled == 0 ? CiFieldMode.Columns : CiFieldMode.Fallback;
        return R(new CiDataState(mode, version + "|" + ctxMode + "|" + ctxUnfilled.ToString(System.Globalization.CultureInfo.InvariantCulture), ctxMode), text);
    }

    // the CI filters' values of the newest data version (one per process; CiViews is a singleton): a page load reads them
    // again only when the data changed -- a new CI build (collection time), more or fewer CIs, or the columns filled
    private readonly object _facetLock = new();
    // one entry per lifecycle choice of the newest data version (#855: the counts are the chosen lifecycle's)
    private readonly Dictionary<string, (string Version, QueryResult<IReadOnlyList<CiFacet>> Value)> _facets = new(StringComparer.Ordinal);

    /// Every CI's choices (all lifecycles) -- what a caller without a lifecycle choice reads, as before.
    public Task<QueryResult<IReadOnlyList<CiFacet>>> CiFacetsAsync(CiDataState state, CancellationToken ct) => CiFacetsAsync(state, LifecycleFilter.All, ct);

    public async Task<QueryResult<IReadOnlyList<CiFacet>>> CiFacetsAsync(CiDataState state, LifecycleFilter? lifecycle, CancellationToken ct)
    {
        var life = lifecycle ?? LifecycleFilter.Active;
        if (state.Version.Length > 0)
            lock (_facetLock) { if (_facets.TryGetValue(life.Key, out var f) && f.Version == state.Version) return f.Value; }
        var value = await Facets(CiSql.LifecycleScoped(CiSql.FacetsFor(state.Mode), life), ct).ConfigureAwait(false);
        // the context filters' values, once every CI's list columns are filled (each from its column's own index)
        if (state.CtxMode == CiFieldMode.Columns && CiSql.ContextFacets(CiColumns.Default.ValueFilters.Where(c => c.Ctx).ToList()) is { Length: > 0 } ctxSql)
        {
            var ctx = await Facets(CiSql.LifecycleScoped(ctxSql, life), ct).ConfigureAwait(false);
            value = R<IReadOnlyList<CiFacet>>(value.Data.Concat(ctx.Data).ToList(), value.Query + "\n\n" + ctx.Query);
        }
        // the CI grid's own columns with a value list (the department, the onboarding status), once every CI's columns are current
        if (state.Mode == CiFieldMode.Columns && CiSql.ContextFacets(CiColumns.Default.ValueFilters.Where(c => !c.Ctx).ToList()) is { Length: > 0 } ownSql)
        {
            var own = await Facets(CiSql.LifecycleScoped(ownSql, life), ct).ConfigureAwait(false);
            value = R<IReadOnlyList<CiFacet>>(value.Data.Concat(own.Data).ToList(), value.Query + "\n\n" + own.Query);
        }
        if (state.Version.Length > 0) lock (_facetLock) { _facets[life.Key] = (state.Version, value); }
        return value;
    }

    public Task<QueryResult<GridPage>> GridAsync(GridSpec spec, GridRequest request, bool export, CancellationToken ct)
    {
        var st = GridSql.Normalize(spec, request);      // a bad value refuses before anything is read or kept
        var q = GridSql.Page(spec, st, new Dictionary<string, object?>(), export);
        // a PAGE is read once per data version (the statement and every parameter are the key: sort, page, filters, search,
        // selection, the layout's columns); an export -- every matching row -- is always read live and never kept
        return export || _cache is null ? ReadGrid(spec, st, q, ct)
            : _cache.GetAsync(ViewResultCache.Key("cigrid." + spec.Name, q), () => ReadGrid(spec, st, q, ct), ct);
    }

    private async Task<QueryResult<GridPage>> ReadGrid(GridSpec spec, GridState st, SqlQuery q, CancellationToken ct)
    {
        var (rows, text) = await Run(q, ct).ConfigureAwait(false);
        var total = rows.Count > 0 ? ProDataQueries.L(rows[0], "TotalRows") : 0;
        var data = rows.Select(r => (IReadOnlyDictionary<string, object?>)spec.Columns.ToDictionary(c => c.Key, c => r.TryGetValue(c.Key, out var v) ? v : null, StringComparer.OrdinalIgnoreCase)).ToList();
        return R(new GridPage(data, total, st), text);
    }

    private async Task<QueryResult<IReadOnlyList<CiFacet>>> Facets(string sql, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(sql, P()), ct).ConfigureAwait(false);
        return R<IReadOnlyList<CiFacet>>(rows.Select(r => new CiFacet(ProDataQueries.S(r, "Facet"), ProDataQueries.S(r, "V"), ProDataQueries.L(r, "N")))
            .Where(f => f.Value.Length > 0).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<CiFacet>>> CiFacetsAsync(CancellationToken ct)
    {
        var schema = (await SchemaAsync(ct).ConfigureAwait(false)).Data;
        return await CiFacetsAsync((await DataStateAsync(schema, ct).ConfigureAwait(false)).Data, ct).ConfigureAwait(false);
    }
    public Task<QueryResult<IReadOnlyList<CiFacet>>> RecordFacetsAsync(CancellationToken ct) => Facets(CiSql.RecordFacets, ct);

    public async Task<QueryResult<IReadOnlyList<CiFacet>>> ValueCountsAsync(GridSpec spec, GridRequest request, string column, CancellationToken ct)
    {
        var q = GridSql.ValueCounts(spec, GridSql.Normalize(spec, request), new Dictionary<string, object?>(), column);
        var (rows, text) = await Run(q, ct).ConfigureAwait(false);
        return R<IReadOnlyList<CiFacet>>(rows.Select(r => new CiFacet(column, ProDataQueries.S(r, "V"), ProDataQueries.L(r, "N"))).Where(f => f.Value.Length > 0).ToList(), text);
    }

    internal static CiRow MapCi(IReadOnlyDictionary<string, object?> r) => new(ProDataQueries.S(r, "CiId"), ProDataQueries.SN(r, "Class"), ProDataQueries.SN(r, "Name"),
        ProDataQueries.SN(r, "AssetType"), Int(r, "Tier"), ProDataQueries.SN(r, "TierSetBy"), ProDataQueries.SN(r, "TierReason"), ProDataQueries.SN(r, "Lifecycle"),
        FlagN(r, "InternetExposed"), ProDataQueries.SN(r, "CmdbId"), ProDataQueries.SN(r, "CmdbName"), ProDataQueries.SN(r, "CmdbCriticality"),
        ProDataQueries.DN(r, "CriticalityFactor"), ProDataQueries.SN(r, "RiskFactors"), ProDataQueries.LN(r, "LinkCount"), ProDataQueries.DN(r, "RiskScore"),
        ProDataQueries.DN(r, "WeightedRiskScore"), ProDataQueries.LN(r, "OpenFindings"), ProDataQueries.T(r, "LastSeen"), ProDataQueries.T(r, "CollectionTime"),
        ProDataQueries.SN(r, "DocJson"));

    internal static CiRecordRow MapRecord(IReadOnlyDictionary<string, object?> r) => new(ProDataQueries.S(r, "RecordKey"), ProDataQueries.SN(r, "CiId"),
        ProDataQueries.S(r, "Provider"), ProDataQueries.SN(r, "RecordType"), ProDataQueries.SN(r, "Class"), ProDataQueries.SN(r, "Name"),
        ProDataQueries.T(r, "SourceLastSeen"), ProDataQueries.T(r, "CollectionTime"), FlagN(r, "Complete"), ProDataQueries.SN(r, "DocJson"));

    public async Task<QueryResult<CiDetail?>> CiAsync(string ciId, CiSchema schema, CancellationToken ct)
    {
        var id = CiSql.CiId(ciId);
        if (!schema.Ci) return R<CiDetail?>(null, "");
        var (rows, text) = await Run(new SqlQuery(CiSql.Ci, P(("CiId", id))), ct).ConfigureAwait(false);
        if (rows.Count == 0) return R<CiDetail?>(null, text);
        var ci = MapCi(rows[0]);
        var texts = new List<string> { text };
        IReadOnlyList<CiLinkRow> links = [];
        if (schema.Links)
        {
            var (lr, lt) = await Run(new SqlQuery(CiSql.Links, P(("CiId", id))), ct).ConfigureAwait(false);
            links = lr.Select(r => new CiLinkRow(ProDataQueries.S(r, "Provider"), ProDataQueries.S(r, "RecordType"), ProDataQueries.S(r, "NativeId"), Flag(r, "IsPrimary"),
                ProDataQueries.SN(r, "State"), ProDataQueries.T(r, "LastSeen"))).ToList();
            texts.Add(lt);
        }
        IReadOnlyList<CiFindingRow> findings = [];
        if (schema.Findings)
        {
            var (fr, ft) = await Run(new SqlQuery(CiSql.Findings, P(("CiId", id), ("Take", CiSql.MaxFindings))), ct).ConfigureAwait(false);
            findings = fr.Select(r => new CiFindingRow(ProDataQueries.S(r, "FindingKey"), ProDataQueries.SN(r, "FindingType"), ProDataQueries.SN(r, "Title"),
                ProDataQueries.SN(r, "Severity"), Int(r, "Tier"), ProDataQueries.DN(r, "RiskScore"), ProDataQueries.DN(r, "WeightedRiskScore"), ProDataQueries.SN(r, "RiskRating"),
                ProDataQueries.SN(r, "SecurityDomain"), ProDataQueries.SN(r, "DetectedBy"), ProDataQueries.SN(r, "RiskFactors"), ProDataQueries.SN(r, "ExemptionId"),
                ProDataQueries.T(r, "CollectionTime"))).ToList();
            texts.Add(ft);
        }
        IReadOnlyList<CiDailyRow> trend = [];
        if (schema.Daily)
        {
            var (dr, dt) = await Run(new SqlQuery(CiSql.Trend, P(("CiId", id), ("Days", CiSql.TrendDays))), ct).ConfigureAwait(false);
            trend = dr.Select(r => new CiDailyRow(ProDataQueries.Day(r, "Day"), Int(r, "Tier"), ProDataQueries.DN(r, "RiskScore"), ProDataQueries.DN(r, "WeightedRiskScore"),
                ProDataQueries.LN(r, "OpenFindings"))).ToList();
            texts.Add(dt);
        }
        IReadOnlyList<CiRecordRow> records = [];
        if (schema.Records)
        {
            var (rr, rt) = await Run(new SqlQuery(CiSql.CiRecords, P(("CiId", id))), ct).ConfigureAwait(false);
            records = rr.Select(MapRecord).ToList();
            texts.Add(rt);
        }
        return R<CiDetail?>(new CiDetail(ci, CiDoc.Parse(ci.DocJson), links, findings, trend, records), string.Join("\n\n", texts));
    }

    public async Task<QueryResult<CiRecordRow?>> RecordAsync(string recordKey, CancellationToken ct)
    {
        var key = CiSql.RecordKey(recordKey);
        var (rows, text) = await Run(new SqlQuery(CiSql.Record, P(("RecordKey", key))), ct).ConfigureAwait(false);
        return R(rows.Count == 0 ? null : MapRecord(rows[0]), text);
    }

    public async Task<bool?> SummaryWrittenAsync(CancellationToken ct)
    {
        static bool On(IReadOnlyDictionary<string, object?>? x, string c) => x is not null && x.TryGetValue(c, out var v) && v is not null && v is not DBNull && Convert.ToBoolean(v, System.Globalization.CultureInfo.InvariantCulture);
        var (schema, _) = await Run(new SqlQuery(CiSql.SummarySchemaSql, P()), ct).ConfigureAwait(false);
        if (!On(schema.FirstOrDefault(), "HasSchema")) return null;
        var (rows, _) = await Run(new SqlQuery(CiSql.SummaryStateSql, P()), ct).ConfigureAwait(false);
        return On(rows.FirstOrDefault(), "Written");
    }

    public Task<QueryResult<IReadOnlyList<CiTierCount>>> TierCountsAsync(CancellationToken ct) => TierCountsAsync(null, ct);

    public Task<QueryResult<IReadOnlyList<CiTierCount>>> TierCountsAsync(IReadOnlyList<string>? lifecycles, CancellationToken ct)
    {
        var states = (lifecycles ?? []).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var q = states.Count == 0 ? new SqlQuery(CiSql.TierCounts, P())
            : new SqlQuery(CiSql.TierCountsByLifecycle, P(("Lifecycles", System.Text.Json.JsonSerializer.Serialize(states))));
        // read once per data version: a page load of the tier board counts nothing while the data did not change
        return _cache is null ? ReadTierCounts(q, ct) : _cache.GetAsync(ViewResultCache.Key("citiers", q), () => ReadTierCounts(q, ct), ct);
    }

    private async Task<QueryResult<IReadOnlyList<CiTierCount>>> ReadTierCounts(SqlQuery q, CancellationToken ct)
    {
        var (rows, text) = await Run(q, ct).ConfigureAwait(false);
        // several stored numbers can be one tier of the board (no tier and a number outside 0-3 are both Unclassified)
        IReadOnlyList<CiTierCount> counts = rows
            .Select(r => new CiTierCount(CiSql.TierOf(ProDataQueries.LN(r, "Tier")), ProDataQueries.S(r, "Facet"), ProDataQueries.S(r, "V").Trim(), ProDataQueries.L(r, "N")))
            .GroupBy(c => (c.Tier, c.Facet, Value: c.Value.ToLowerInvariant()))
            .Select(g => new CiTierCount(g.Key.Tier, g.Key.Facet, g.First().Value, g.Sum(c => c.N)))
            .ToList();
        return R(counts, text);
    }

    public async Task<QueryResult<string?>> AssetKeyOfCiAsync(string ciId, CiSchema schema, CancellationToken ct)
    {
        var id = CiSql.CiId(ciId);
        var (rows, text) = await Run(new SqlQuery(schema.Links ? CiSql.AssetOfCi : CiSql.AssetOfCiNoLinks, P(("CiId", id))), ct).ConfigureAwait(false);
        return R(rows.Count == 0 ? null : ProDataQueries.SN(rows[0], "AssetKey"), text);
    }

    public async Task<QueryResult<string?>> CiOfAssetKeyAsync(string assetKey, CiSchema schema, CancellationToken ct)
    {
        var key = CiSql.RecordKey(assetKey);
        if (!schema.Ci) return R<string?>(null, "");
        var (rows, text) = await Run(new SqlQuery(schema.Links ? CiSql.CiOfAsset : CiSql.CiOfAssetNoLinks, P(("Key", key))), ct).ConfigureAwait(false);
        return R(rows.Count == 0 ? null : ProDataQueries.SN(rows[0], "CiId"), text);
    }
}
