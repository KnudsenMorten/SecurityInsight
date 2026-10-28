namespace SI.Management.Core.ProData;

/// <summary>
/// THE WEIGHTED RISK SCORE BY CMDB SERVICE (#360): the collection's business services ordered by how critical the CMDB
/// says each one is, then by weighted risk -- and the dimension turned around (asset -> its services). Same rules as
/// <see cref="CollectionViewSql"/>: fixed text, every caller value a parameter, read-only, one collection at a time, no
/// per-row lookup (the criticality per service key is a key set built ONCE and joined).
/// <para>WHERE THE DATA COMES FROM: the per-collection service aggregates the data sync computes (sidata.ServiceRisk /
/// sidata.ServiceAsset, one row per service and per (service, CI), #255) and the CMDB's services
/// (cfg.vCmdbService: the authoritative source's services in force, #256). A service row's key is the CMDB service number
/// (the CMDB membership source) or the Risk Analysis cmdbId (the fallback source, = a migrated service's ExternalId), so the
/// criticality is looked up on BOTH. A database without the CMDB tables reads the same statements over an EMPTY key set
/// (<see cref="NoCmdb"/>): every service then reads "not set" and the page says to import the CMDB.</para>
/// </summary>
public static class WeightedServiceSql
{
    /// The rank of a CMDB criticality: 1 = most critical. The words risk weighting reads (Critical / High / Medium / Low),
    /// their usual synonyms, and a number 1-5 ("1", "1 - most critical" as ServiceNow writes it). Anything else: unranked.
    public static int? Rank(string? criticality)
    {
        var t = criticality?.Trim();
        if (string.IsNullOrEmpty(t)) return null;
        switch (t.ToLowerInvariant())
        {
            case "critical": case "very high": return 1;
            case "high": return 2;
            case "medium": case "moderate": return 3;
            case "low": return 4;
            case "very low": case "none": case "not critical": return 5;
        }
        return t[0] is >= '1' and <= '5' && (t.Length == 1 || !char.IsDigit(t[1])) ? t[0] - '0' : null;
    }

    /// The same rank in SQL, over a criticality column (NULL = unranked).
    public static string RankSql(string col) =>
        $"CASE WHEN {col} IN (N'Critical', N'Very High') THEN 1 WHEN {col} = N'High' THEN 2 WHEN {col} IN (N'Medium', N'Moderate') THEN 3 " +
        $"WHEN {col} = N'Low' THEN 4 WHEN {col} IN (N'Very Low', N'None', N'Not critical') THEN 5 " +
        $"WHEN LEFT(LTRIM({col}), 1) IN (N'1', N'2', N'3', N'4', N'5') AND SUBSTRING(LTRIM({col}), 2, 1) NOT LIKE N'[0-9]' THEN CONVERT(int, LEFT(LTRIM({col}), 1)) END";

    /// The rank of an unranked service (and of the no-service group): after every ranked one.
    public const int Unranked = 9;

    /// The chip tone of a criticality (badge class): most critical red ... least green; unranked: none.
    public static string? Tone(string? criticality) => Rank(criticality) switch { 1 => "bad", 2 => "warn", 3 => "fair", 4 or 5 => "good", _ => null };

    /// The words of a service without a criticality in the CMDB.
    public const string NotSet = "not set";
    /// The words of the assets no CMDB service claims.
    public const string NoServiceName = "No service in the CMDB";

    // ---- the criticality per service key: built once, joined --------------------------------------------------------

    /// The CMDB's criticality, department and owner per service key (its number AND its external id). CritKey =
    /// "rank|criticality" (rank 9 = unranked), so MIN picks the most critical where a key is held twice.
    public static readonly string Cmdb = $"""
ck AS (
    SELECT s.ServiceNumber AS K, s.Criticality, s.Department, s.Owner FROM cfg.vCmdbService AS s
    UNION ALL
    SELECT s.ExternalId, s.Criticality, s.Department, s.Owner FROM cfg.vCmdbService AS s
    WHERE s.ExternalId IS NOT NULL AND s.ExternalId <> N'' AND s.ExternalId <> s.ServiceNumber
), crit AS (
    SELECT ck.K, MIN(CONCAT(COALESCE({RankSql("ck.Criticality")}, {Unranked}), N'|', COALESCE(ck.Criticality, N''))) AS CritKey,
           MAX(ck.Department) AS Department, MAX(ck.Owner) AS Owner
    FROM ck
    GROUP BY ck.K
)
""";

    /// The seam of a database without the CMDB tables: the same key set, empty.
    public const string NoCmdb = """
crit AS (
    SELECT CONVERT(nvarchar(256), NULL) AS K, CONVERT(nvarchar(80), NULL) AS CritKey, CONVERT(nvarchar(128), NULL) AS Department, CONVERT(nvarchar(256), NULL) AS Owner
    WHERE 1 = 0
)
""";

    private static string Crit(bool cmdb) => (cmdb ? Cmdb : NoCmdb).Trim();
    private const string CritWord = "NULLIF(SUBSTRING({0}, 3, 64), N'')";
    private const string CritRank = "TRY_CONVERT(int, NULLIF(LEFT({0}, 1), N'9'))";
    private static string Word(string key) => string.Format(System.Globalization.CultureInfo.InvariantCulture, CritWord, key);
    private static string RankOf(string key) => string.Format(System.Globalization.CultureInfo.InvariantCulture, CritRank, key);
    private static string OrderRank(string key) => $"COALESCE(TRY_CONVERT(int, LEFT({key}, 1)), {Unranked})";

    private static readonly string TierSort = "CASE WHEN g.[Tier] = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, g.[Tier]) END";

    /// The columns every by-service grid shares, after its own leading ones.
    private static GridColumn[] Measures(bool asset) =>
    [
        new("Assets", asset ? "Services" : "Assets (CIs)", GridType.Number, GridFilter.Range),
        new("Findings", "Findings", GridType.Number, GridFilter.Range),
        new("RiskTotal", "Risk total", GridType.Number, GridFilter.Range),
        new("WeightedRisk", "Weighted total", GridType.Number, GridFilter.Range),
        new("MaxWeightedRisk", "Highest weighted", GridType.Number, GridFilter.Range),
    ];

    // ---- (1) Service -> Asset: one row per CMDB service ----------------------------------------------------------------

    /// <summary>
    /// One row per service of the collection (the no-service group is shown apart, not in the grid). ServiceOrder is THE
    /// default order: most critical first (unranked last), then the highest weighted total, then the key -- so a click on
    /// "Criticality" orders by criticality THEN weighted risk.
    /// </summary>
    public static GridSpec ByService(bool cmdb) => GridSql.Check(new GridSpec("svccrit", Crit(cmdb), $"""
SELECT sr.ServiceKey, COALESCE(sr.ServiceName, sr.ServiceKey) AS ServiceName,
       {Word("crit.CritKey")} AS Criticality, {RankOf("crit.CritKey")} AS CriticalityRank,
       ROW_NUMBER() OVER (ORDER BY {OrderRank("crit.CritKey")}, CASE WHEN sr.WeightedTotal IS NULL THEN 1 ELSE 0 END, sr.WeightedTotal DESC, sr.ServiceKey) AS ServiceOrder,
       sr.Assets, sr.SharedAssets, sr.Findings, sr.RiskTotal, sr.WeightedTotal AS WeightedRisk, sr.MaxWeighted AS MaxWeightedRisk,
       sr.TopAssetKey, sr.TopAssetName, sr.TopAssetWeighted AS TopAssetWeightedRisk, crit.Department, crit.Owner
FROM sidata.ServiceRisk AS sr
LEFT JOIN crit ON crit.K = sr.ServiceKey
WHERE sr.CollectionId = TRY_CONVERT(int, @CollectionId) AND sr.ServiceKey <> N''
""", [
        new("ServiceKey", "Service id", Filter: GridFilter.Contains, Search: true, Hidden: true),
        new("ServiceName", "Service", Filter: GridFilter.Contains, Search: true),
        new("Criticality", "Criticality", Filter: GridFilter.Values, SortSql: "g.[ServiceOrder]"),
        new("CriticalityRank", "Criticality rank", GridType.Number, Hidden: true),
        new("ServiceOrder", "Order", GridType.Number, Hidden: true),
        .. Measures(asset: false),
        new("TopAssetName", "Top asset", Filter: GridFilter.Contains, Search: true),
        new("TopAssetWeightedRisk", "Top asset's weighted total", GridType.Number, Hidden: true),
        new("TopAssetKey", "Top asset key", Hidden: true),
        new("SharedAssets", "Also in another service", GridType.Number, Hidden: true),
        new("Department", "Department", Filter: GridFilter.Values, Hidden: true),
        new("Owner", "Service owner", Filter: GridFilter.Contains, Search: true, Hidden: true),
    ], "ServiceOrder", false, "ServiceKey", ["CollectionId"], Immutable: false));

    // ---- (2) Asset -> Service: the dimension turned around --------------------------------------------------------------

    /// <summary>
    /// One row per CI of the collection: its most critical service's criticality, how many services it is in (0 = none),
    /// their names, and its own findings and scores (the same in every service it is in). ServiceOrder: the CI in the most
    /// critical service first, then the highest weighted total.
    /// </summary>
    public static GridSpec ByAsset(bool cmdb) => GridSql.Check(new GridSpec("assetsvc", Crit(cmdb) + """
,
x AS (
    SELECT sa.AssetKey, MAX(sa.AssetName) AS AssetName, MIN(sa.Tier) AS Tier, MAX(sa.Findings) AS Findings, MAX(sa.RiskTotal) AS RiskTotal,
           MAX(sa.WeightedTotal) AS WeightedTotal, MAX(sa.MaxWeighted) AS MaxWeighted, MIN(crit.CritKey) AS CritKey,
           SUM(CASE WHEN sa.ServiceKey <> N'' THEN 1 ELSE 0 END) AS Services,
           STRING_AGG(CONVERT(nvarchar(max), CASE WHEN sa.ServiceKey <> N'' THEN COALESCE(sa.ServiceName, sa.ServiceKey) END), N'; ') AS ServiceNames
    FROM sidata.ServiceAsset AS sa
    LEFT JOIN crit ON crit.K = sa.ServiceKey
    WHERE sa.CollectionId = TRY_CONVERT(int, @CollectionId)
    GROUP BY sa.AssetKey
)
""", $"""
SELECT x.AssetKey, COALESCE(a.AssetName, x.AssetName, x.AssetKey) AS AssetName, a.AssetKind, {ProDataSql.AssetKindsExpr("a")} AS AssetKinds, {ProDataSql.TierExpr("x.Tier")} AS Tier,
       {Word("x.CritKey")} AS Criticality, {RankOf("x.CritKey")} AS CriticalityRank,
       ROW_NUMBER() OVER (ORDER BY {OrderRank("x.CritKey")}, CASE WHEN x.WeightedTotal IS NULL THEN 1 ELSE 0 END, x.WeightedTotal DESC, x.AssetKey) AS ServiceOrder,
       x.Services AS Assets, x.ServiceNames, x.Findings, x.RiskTotal, x.WeightedTotal AS WeightedRisk, x.MaxWeighted AS MaxWeightedRisk
FROM x
LEFT JOIN sidata.Asset AS a ON a.AssetKey = x.AssetKey
""", [
        new("AssetKey", "Asset (CI) key", Search: true, Hidden: true),
        new("AssetName", "Asset", Filter: GridFilter.Contains, Search: true),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        GridColumn.AssetKind(),
        new("Criticality", "Most critical service", Filter: GridFilter.Values, SortSql: "g.[ServiceOrder]"),
        new("CriticalityRank", "Criticality rank", GridType.Number, Hidden: true),
        new("ServiceOrder", "Order", GridType.Number, Hidden: true),
        new("ServiceNames", "In services", Filter: GridFilter.Contains, Search: true),
        .. Measures(asset: true),
    ], "ServiceOrder", false, "AssetKey", ["CollectionId"], Immutable: false));

    // ---- drill-downs -------------------------------------------------------------------------------------------------

    /// The CIs of ONE service (or of no service: <see cref="CollectionViewSql.NoServiceKey"/>), with the same measures.
    public static readonly GridSpec ServiceAssets = GridSql.Check(new GridSpec("svcassetw", "", $"""
SELECT sa.AssetKey, COALESCE(sa.AssetName, a.AssetName, sa.AssetKey) AS AssetName, a.AssetKind, {ProDataSql.AssetKindsExpr("a")} AS AssetKinds, {ProDataSql.TierExpr("sa.Tier")} AS Tier,
       sa.ServiceCount, sa.Findings, sa.RiskTotal, sa.WeightedTotal AS WeightedRisk, sa.MaxWeighted AS MaxWeightedRisk
FROM sidata.ServiceAsset AS sa
LEFT JOIN sidata.Asset AS a ON a.AssetKey = sa.AssetKey
WHERE sa.CollectionId = TRY_CONVERT(int, @CollectionId)
  AND sa.ServiceKey = CASE WHEN @Service = N'{CollectionViewSql.NoServiceKey}' THEN N'' ELSE @Service END
""", [
        new("AssetKey", "Asset (CI) key", Search: true, Hidden: true),
        new("AssetName", "Asset", Filter: GridFilter.Contains, Search: true),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        GridColumn.AssetKind(),
        new("ServiceCount", "Services it is in", GridType.Number, GridFilter.Range),
        new("Findings", "Findings", GridType.Number, GridFilter.Range),
        new("RiskTotal", "Risk total", GridType.Number, GridFilter.Range),
        new("WeightedRisk", "Weighted total", GridType.Number, GridFilter.Range),
        new("MaxWeightedRisk", "Highest weighted", GridType.Number, GridFilter.Range),
    ], "WeightedRisk", true, "AssetKey", ["CollectionId", "Service"], Immutable: true));

    /// The services of ONE CI (the Asset -> Service drill-down), most critical first.
    public static GridSpec AssetServices(bool cmdb) => GridSql.Check(new GridSpec("assetsvcs", Crit(cmdb), $"""
SELECT CASE WHEN sa.ServiceKey = N'' THEN N'{CollectionViewSql.NoServiceKey}' ELSE sa.ServiceKey END AS ServiceKey,
       CASE WHEN sa.ServiceKey = N'' THEN N'{NoServiceName}' ELSE COALESCE(sa.ServiceName, sa.ServiceKey) END AS ServiceName,
       {Word("crit.CritKey")} AS Criticality, {RankOf("crit.CritKey")} AS CriticalityRank,
       ROW_NUMBER() OVER (ORDER BY {OrderRank("crit.CritKey")}, sa.ServiceKey) AS ServiceOrder,
       sr.Assets, sr.Findings, sr.RiskTotal, sr.WeightedTotal AS WeightedRisk, sr.MaxWeighted AS MaxWeightedRisk
FROM sidata.ServiceAsset AS sa
LEFT JOIN crit ON crit.K = sa.ServiceKey
LEFT JOIN sidata.ServiceRisk AS sr ON sr.CollectionId = sa.CollectionId AND sr.ServiceKey = sa.ServiceKey
WHERE sa.CollectionId = TRY_CONVERT(int, @CollectionId) AND sa.AssetKey = @AssetKey
""", [
        new("ServiceKey", "Service id", Search: true, Hidden: true),
        new("ServiceName", "Service", Filter: GridFilter.Contains, Search: true),
        new("Criticality", "Criticality", Filter: GridFilter.Values, SortSql: "g.[ServiceOrder]"),
        new("CriticalityRank", "Criticality rank", GridType.Number, Hidden: true),
        new("ServiceOrder", "Order", GridType.Number, Hidden: true),
        .. Measures(asset: false),
    ], "ServiceOrder", false, "ServiceKey", ["CollectionId", "AssetKey"], Immutable: false));

    // ---- the CMDB's state ------------------------------------------------------------------------------------------------

    /// Which of the tables the page reads exist (a database set up before the CMDB, the departments or the services view).
    public const string Probe = """
SELECT CASE WHEN OBJECT_ID(N'cfg.vCmdbService') IS NOT NULL THEN 1 ELSE 0 END AS HasCmdb,
       CASE WHEN OBJECT_ID(N'cfg.Department') IS NOT NULL AND COL_LENGTH('sidata.Finding', 'DepartmentId') IS NOT NULL THEN 1 ELSE 0 END AS HasDepartments,
       CASE WHEN OBJECT_ID(N'sidata.ServiceMember') IS NOT NULL THEN 1 ELSE 0 END AS HasMembers;
""";

    /// The CMDB's services in force and how many carry a criticality (only run when cfg.vCmdbService exists).
    public const string CmdbCounts = """
SELECT COUNT_BIG(*) AS Services, SUM(CASE WHEN s.Criticality IS NOT NULL AND LTRIM(RTRIM(s.Criticality)) <> N'' THEN 1 ELSE 0 END) AS WithCriticality
FROM cfg.vCmdbService AS s;
""";

    /// Every statement of this view, for the read-only / parameter / no-APPLY tests.
    public static IEnumerable<GridSpec> Grids => [ByService(true), ByService(false), ByAsset(true), ByAsset(false), ServiceAssets, AssetServices(true), AssetServices(false)];
}

/// What the database knows about the CMDB (and the other tables the weighted views read). <see cref="None"/> = nothing.
public sealed record CmdbState(bool HasCmdb, long Services, long WithCriticality, bool HasDepartments, bool HasMembers)
{
    public static CmdbState None { get; } = new(false, 0, 0, false, false);
    /// The CMDB holds services with a criticality: the by-service view can order by it.
    public bool HasCriticality => HasCmdb && WithCriticality > 0;
    /// Part of the cache scope of every read that joins the CMDB.
    public string Version => (HasCmdb ? "cmdb" : "nocmdb") + (HasDepartments ? "+d" : "") + (HasMembers ? "+m" : "");
}
