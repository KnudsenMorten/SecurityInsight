using System.Globalization;

namespace SI.Management.Core.ProData;

/// <summary>
/// #636 -- the reads of the restructured menu that are NOT the finding grid of one collection: Security recommendations >
/// Summary (one row per recommendation with its affected assets -- the stored groupings of the Detailed findings), the
/// Remediations pages (sidata.Remediation / RemediationAsset, built by the data sync, SI-DataRemediation.ps1) and the
/// key figures of Overview > Executive overview and Executive report (sidata.KeyFigure, SI-DataKeyFigures.ps1). Same
/// rules as <see cref="CollectionViewSql"/>: fixed text, every caller value a parameter, read-only, one collection at a
/// time, never a GROUP BY over the findings at page load -- every figure is stored per collection.
/// </summary>
public static class RecommendationSql
{
    private const string ThisCollection = "TRY_CONVERT(int, @CollectionId)";
    private static readonly string TierSort = "CASE WHEN g.[Tier] = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, g.[Tier]) END";

    /// What the database holds for one collection: the remediations and key figures are built (when), and whether the
    /// Summary groupings of the Detailed findings exist (the summary builder's table).
    public const string State = """
SELECT CASE WHEN COL_LENGTH(N'sidata.Collection', N'RemediationAt') IS NULL THEN 0 ELSE 1 END AS HasRemediation,
       CASE WHEN COL_LENGTH(N'sidata.Collection', N'KeyFiguresAt') IS NULL THEN 0 ELSE 1 END AS HasKeyFigures,
       CASE WHEN OBJECT_ID(N'sidata.SummaryGroup') IS NULL OR OBJECT_ID(N'sidata.SummaryGroupCounted') IS NULL OR OBJECT_ID(N'sidata.SummaryGroupState') IS NULL THEN 0 ELSE 1 END AS HasSummaryGroups;
""";

    /// The two marks of one collection (run only when the columns exist).
    public const string Marks = """
SELECT c.RemediationAt, c.KeyFiguresAt FROM sidata.Collection AS c WHERE c.CollectionId = TRY_CONVERT(int, @CollectionId);
""";

    /// Whether the Summary groupings of one collection are written (sidata.SummaryGroupState: the data sync's mark, written in
    /// the same transaction as the rows -- run only when the tables exist). @Grouping (NULL = any): THAT grouping is among the
    /// written ones -- a grouping the definition added later (the report grouping, 2026-10-20) is "being prepared" until the
    /// data sync writes the collection again, never an empty table.
    public const string SummaryGroupsOf = """
SELECT TOP (1) 1 AS Ready FROM sidata.SummaryGroupState AS s
WHERE s.CollectionId = TRY_CONVERT(int, @CollectionId)
  AND (@Grouping IS NULL OR s.Groupings LIKE N'%;' + @Grouping + N';%'
       OR EXISTS (SELECT 1 FROM sidata.SummaryGroup AS g WHERE g.CollectionId = s.CollectionId AND g.GroupingId = @Grouping));
""";

    /// Which groupings ARE written for one collection (sidata.SummaryGroupState.Groupings: ';id;id;'), so a page whose grouping
    /// is not written yet can name the views that are there (run only when the tables exist). A state row written before the
    /// list was kept (Groupings NULL) answers from the rows themselves (SummaryGroupingsOfRows).
    public const string SummaryGroupingsBuilt = """
SELECT s.Groupings, CASE WHEN s.Groupings IS NULL THEN 1 ELSE 0 END AS FromRows FROM sidata.SummaryGroupState AS s
WHERE s.CollectionId = TRY_CONVERT(int, @CollectionId);
""";

    /// The groupings with rows for one collection (only for a state row without the list).
    public const string SummaryGroupingsOfRows = """
SELECT DISTINCT g.GroupingId FROM sidata.SummaryGroup AS g WHERE g.CollectionId = TRY_CONVERT(int, @CollectionId);
""";

    /// The ids of a written-groupings list (';a;b;'), in the definition's order; an id the definition does not know is left out.
    public static IReadOnlyList<string> ParseGroupings(string? list)
    {
        var have = (list ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return Groupings.Select(g => g.Id).Where(id => have.Contains(id, StringComparer.OrdinalIgnoreCase)).ToList();
    }

    // ---- Remediations > All remediations (one row per fix) and Top 10 fixes by reach ------------------------------------

    private static readonly string RemediationSelect = $"""
SELECT r.RemediationKey, r.Kind, r.Fix, r.WhatToDo, r.Effort, r.FixOwner,
       COALESCE(d.Name, CASE WHEN r.Departments > 1 THEN N'several' END) AS Department,
       r.Assets, r.Tier0Assets, {ProDataSql.TierExpr("r.BestTier")} AS Tier, r.Recommendations, r.Findings, r.ExemptedFindings,
       r.CriticalFindings, r.HighFindings, r.RiskRemoved, r.MaxRiskScore, r.HasExploit, r.Status
FROM sidata.Remediation AS r
LEFT JOIN cfg.Department AS d ON d.DepartmentId = r.DepartmentId
WHERE r.CollectionId = {ThisCollection}
""";

    private static GridColumn[] RemediationColumns() =>
    [
        new("RemediationKey", "Fix key", Filter: GridFilter.Contains, Search: true, Hidden: true),
        new("Fix", "Fix", Filter: GridFilter.Contains, Search: true),
        new("Kind", "Kind", Filter: GridFilter.Values),
        new("Assets", "Assets reached", GridType.Number, GridFilter.Range),
        new("Findings", "Findings closed", GridType.Number, GridFilter.Range),
        new("RiskRemoved", "Risk removed", GridType.Number, GridFilter.Range),
        new("Tier", "Most critical tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        new("Tier0Assets", "On Tier 0", GridType.Number, GridFilter.Range),
        new("Effort", "Effort", Filter: GridFilter.Values),
        new("FixOwner", "Owner", Filter: GridFilter.Contains, Search: true),
        new("Department", "Department", Filter: GridFilter.Values),
        new("Status", "Status", Filter: GridFilter.Values),
        new("CriticalFindings", "Critical", GridType.Number, GridFilter.Range),
        new("HighFindings", "High", GridType.Number, GridFilter.Range),
        new("HasExploit", "Exploit", GridType.Flag, GridFilter.Values),
        new("Recommendations", "Recommendations", GridType.Number, GridFilter.Range, Hidden: true),
        new("ExemptedFindings", "Exempted", GridType.Number, GridFilter.Range, Hidden: true),
        new("MaxRiskScore", "Highest risk score", GridType.Number, GridFilter.Range, Hidden: true),
        new("WhatToDo", "What to do", Filter: GridFilter.Contains, Search: true, Hidden: true),
    ];

    public static readonly GridSpec Remediations = GridSql.Check(new GridSpec("remediations", "", RemediationSelect, RemediationColumns(),
        "RiskRemoved", true, "RemediationKey", ["CollectionId"], Immutable: false));   // reads the department name (cfg): not cached long

    /// The fixes that close the most in one operation: the 10 that reach the most assets (then remove the most risk).
    public static readonly GridSpec TopFixes = GridSql.Check(new GridSpec("remediationtop", "",
        RemediationSelect.Replace("SELECT r.RemediationKey", "SELECT TOP (@Top) r.RemediationKey", StringComparison.Ordinal)
            + "  AND r.Status = N'open'\nORDER BY r.Assets DESC, r.RiskRemoved DESC, r.RemediationKey\n",
        RemediationColumns(), "Assets", true, "RemediationKey", ["CollectionId", "Top"], Immutable: false));

    // ---- Remediations > Top 10 assets to fix: the most important assets and what to do on each ---------------------------

    public static readonly GridSpec TopAssets = GridSql.Check(new GridSpec("remediationassets", "", $"""
SELECT RIGHT(CONCAT(N'00000', ra.AssetRank), 5) + N'|' + RIGHT(CONCAT(N'00000', ra.FixRank), 5) AS RowKey, ra.AssetRank, ra.FixRank, ra.AssetKey, COALESCE(ra.AssetName, ra.AssetKey) AS AssetName,
       {ProDataSql.TierExpr("ra.Tier")} AS Tier, ra.AssetRisk, ra.RemediationKey, ra.Kind, ra.Fix, ra.Findings, ra.RiskRemoved
FROM sidata.RemediationAsset AS ra
WHERE ra.CollectionId = {ThisCollection} AND ra.AssetRank <= @Top AND ra.FixRank <= @TopFixes
""", new GridColumn[]
    {
        new("RowKey", "Row", Hidden: true),
        new("AssetRank", "#", GridType.Number, GridFilter.Range),
        new("AssetName", "Asset (CI)", Filter: GridFilter.Contains, Search: true),
        new("AssetKey", "Asset (CI) key", Search: true, Hidden: true),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        new("AssetRisk", "Asset risk", GridType.Number, GridFilter.Range),
        new("FixRank", "Fix #", GridType.Number, GridFilter.Range),
        new("Fix", "What to do", Filter: GridFilter.Contains, Search: true),
        new("Kind", "Kind", Filter: GridFilter.Values),
        new("Findings", "Findings closed", GridType.Number, GridFilter.Range),
        new("RiskRemoved", "Risk removed", GridType.Number, GridFilter.Range),
        new("RemediationKey", "Fix key", Hidden: true),
    }, "AssetRank", false, "RowKey", ["CollectionId", "Top", "TopFixes"], Immutable: true));

    // ---- Security recommendations > Summary: the stored groupings of the Detailed findings ------------------------------
    // ONE page (rc14: the menu's Summary and the grouped view of the Summary-off work are one): the data sync writes every
    // grouping of data-model\summary-groupings.locked.json per collection (sidata.SummaryGroup and its counted twin
    // SummaryGroupCounted, sidata.SummaryGroupState its mark -- engine\pro-data\_shared\SI-DataSummaryGroups.ps1, the ONE
    // engine function of Pro and Community). The page reads ONE grouping of the published collection (the default: per
    // recommendation with its affected assets), never a GROUP BY over the findings at page load. The exempted scope reads
    // the counted twin (Exempted.Twins), as every other aggregate.

    /// One grouping of the definition: its id (sidata.SummaryGroup.GroupingId), its name, the words of its keys (Key1..Key3)
    /// and whether a name is stored next to the key (Label: a recommendation's title, an asset's name).
    public sealed record SummaryGroupingDef(string Id, string Label, IReadOnlyList<string> Keys, bool Named);

    /// The groupings, in the definition's order (a test holds them to data-model\summary-groupings.locked.json).
    public static readonly IReadOnlyList<SummaryGroupingDef> Groupings =
    [
        // owner 2026-10-20: "the summary view must be grouped data based on detailed data, but with output similar to what we
        // had for the old summary report where the same vulnerability existed in the report but with different tier" -- the
        // page's default: one row per recommendation AND tier, the Summary report's columns (its stored attributes)
        new("recommendation-tier", "Per recommendation and tier (as the Summary report)", ["Recommendation", "Tier"], true),
        new("recommendation", "Per recommendation (with its affected assets)", ["Recommendation"], true),
        new("asset", "Per asset", ["Asset key"], true),
        new("tier", "Per tier", ["Tier"], false),
        new("domain", "Per security domain", ["Domain"], false),
        new("domain-category", "Per domain > category", ["Domain", "Category"], false),
        new("domain-category-subcategory", "Per domain > category > subcategory", ["Domain", "Category", "Subcategory"], false),
        new("risk-rating", "Per risk rating", ["Risk rating"], false),
        new("department", "Per department", ["Department"], false),
        new("severity", "Per severity", ["Severity"], false),
        new("report", "Per report", ["Report"], false),
        // the perfviews groupings (the named views Risk rating / MITRE / Compliance / CVSS of Detailed read them too)
        new("mitre-tactic", "Per MITRE ATT&CK tactic", ["MITRE tactic"], false),
        new("mitre-technique", "Per MITRE ATT&CK technique", ["MITRE technique"], false),
        new("compliance-control", "Per compliance control", ["Compliance control"], false),
        new("cvss-band", "Per CVSS band", ["CVSS band"], false),
    ];

    public const string DefaultGrouping = ReportGrouping;
    /// The Summary report's shape: one row per recommendation and tier, with the report's columns.
    public const string ReportGrouping = "recommendation-tier";

    /// The words of the Severity and Risk rating attributes, the most severe first (the definition's 'first' order).
    public static readonly IReadOnlyList<string> SeverityWords = ["Very High", "High", "Medium-High", "Medium", "Low", "Informational"];
    public static readonly IReadOnlyList<string> RatingWords = ["Critical", "High", "Moderate", "Low"];

    /// "Riskiest first": the most critical tier, then the highest total risk -- every grouping's default order.
    private const string LeadSql = "(9 - ISNULL(CONVERT(float, s.BestTier), 4)) * 1000000000000000.0 + ISNULL(s.TotalRisk, 0)";

    private static string Attr(string id) => $"JSON_VALUE(s.AttributesJson, '$.{id}')";
    private static string WordSort(string col, IReadOnlyList<string> words) =>
        "CASE g.[" + col + "] " + string.Join(" ", words.Select((w, i) => $"WHEN N'{w}' THEN {i + 1}")) + " ELSE 99 END";

    /// The grouping a request names (an unknown or empty id = the default).
    public static SummaryGroupingDef GroupingOf(string? id) =>
        Groupings.FirstOrDefault(g => string.Equals(g.Id, id?.Trim(), StringComparison.OrdinalIgnoreCase)) ?? Groupings[0];

    /// The grid of one grouping ("summaryrecs" = per recommendation).
    public static GridSpec Grouped(string? id) => GroupedSpecs[GroupingOf(id).Id];

    private static readonly IReadOnlyDictionary<string, GridSpec> GroupedSpecs =
        Groupings.ToDictionary(g => g.Id, g => GridSql.Check(GroupedSpec(g)), StringComparer.OrdinalIgnoreCase);

    private static GridSpec GroupedSpec(SummaryGroupingDef g)
    {
        var keys = string.Join(", ", g.Keys.Select((_, i) => $"s.Key{i + 1} AS K{i + 1}"));
        var name = g.Named ? ",\n       COALESCE(NULLIF(s.Label, N''), s.Key1) AS Title" : "";
        var report = g.Id == ReportGrouping;
        // the Summary report's columns: the row's stored attributes (data-model\summary-groupings.locked.json); the asset names
        // are the first ten in order, "+N more" says how many it leaves out; last seen = the run the row is from
        var names = Attr("AssetNames");
        var attrs = report ? $"""
,
       {Attr("Domain")} AS Domain, {Attr("Category")} AS Category, {Attr("Subcategory")} AS Subcategory,
       {Attr("Severity")} AS Severity, {Attr("RiskRating")} AS RiskRating,
       CASE WHEN {names} IS NULL THEN NULL WHEN s.Assets > LEN({names}) - LEN(REPLACE({names}, N';', N'')) + 1
            THEN CONCAT({names}, N' +', s.Assets - (LEN({names}) - LEN(REPLACE({names}, N';', N'')) + 1), N' more') ELSE {names} END AS AssetNames,
       TRY_CONVERT(date, {Attr("FirstSeen")}) AS FirstSeen, (SELECT CONVERT(date, c.CollectionTime) FROM sidata.Collection AS c WHERE c.CollectionId = s.CollectionId) AS LastSeen,
       {Attr("Remediation")} AS Remediation
""".TrimEnd() : "";
        var source = $"""
SELECT CONCAT(s.Key1, N'|', s.Key2, N'|', s.Key3) AS RowKey, {keys}{name}{attrs},
       s.Findings, s.Assets, s.Recommendations, s.MaxRisk, s.TotalRisk, {ProDataSql.TierExpr("s.BestTier")} AS Tier, s.Tier0Findings,
       s.CriticalFindings, s.HighFindings, s.RatedCriticalFindings, s.RatedHighFindings, s.RatedCriticalFindings + s.RatedHighFindings AS RatedCriticalOrHigh,
       s.ExploitedRecommendations, CASE WHEN s.ExploitedRecommendations > 0 THEN 1 ELSE 0 END AS HasExploit, {LeadSql} AS Lead
FROM sidata.SummaryGroup AS s
WHERE s.CollectionId = {ThisCollection} AND s.GroupingId = N'{g.Id}'
""";
        var cols = new List<GridColumn> { new("RowKey", "Row key", Hidden: true) };
        for (var i = 0; i < g.Keys.Count; i++)
            cols.Add(g.Keys[i] == "Tier"
                ? new($"K{i + 1}", g.Keys[i], GridType.Tier, GridFilter.Values, SortSql: $"CASE WHEN g.[K{i + 1}] = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, g.[K{i + 1}]) END")
                : new($"K{i + 1}", g.Keys[i], Filter: GridFilter.Contains, Search: true, Hidden: g.Named && i == 0 && g.Id == "asset"));
        if (g.Named) cols.Add(new("Title", g.Id == "asset" ? "Asset" : "Security recommendation", Filter: GridFilter.Contains, Search: true));
        if (report)
            cols.AddRange(
            [
                new("Domain", "Security domain", Filter: GridFilter.Values),
                new("Category", "Category", Filter: GridFilter.Contains, Search: true),
                new("Subcategory", "Subcategory", Filter: GridFilter.Contains, Search: true),
                new("Severity", "Severity", Filter: GridFilter.Values, SortSql: WordSort("Severity", SeverityWords)),
                new("RiskRating", "Risk rating", Filter: GridFilter.Values, SortSql: WordSort("RiskRating", RatingWords)),
            ]);
        cols.AddRange(
        [
            new("Assets", "Affected assets", GridType.Number, GridFilter.Range),
        ]);
        if (report) cols.Add(new("AssetNames", "Affected assets (names)", Filter: GridFilter.Contains, Search: true));
        cols.AddRange(
        [
            new("Findings", "Findings", GridType.Number, GridFilter.Range),
            new("Recommendations", "Recommendations", GridType.Number, GridFilter.Range, Hidden: g.Id is "recommendation" or ReportGrouping),
            new("Tier", "Most critical tier", GridType.Tier, GridFilter.Values, SortSql: TierSort, Hidden: report),
            new("Tier0Findings", "Findings on Tier 0", GridType.Number, GridFilter.Range, Hidden: report),
            new("CriticalFindings", "Very High findings", GridType.Number, GridFilter.Range, Hidden: report),
            new("HighFindings", "High findings", GridType.Number, GridFilter.Range, Hidden: report),
            new("RatedCriticalFindings", "Rated Critical", GridType.Number, GridFilter.Range, Hidden: report),
            new("RatedHighFindings", "Rated High", GridType.Number, GridFilter.Range, Hidden: report),
            new("RatedCriticalOrHigh", "Rated Critical or High", GridType.Number, GridFilter.Range, Hidden: true),
            new("MaxRisk", "Highest risk score", GridType.Number, GridFilter.Range),
            new("TotalRisk", "Total risk score", GridType.Number, GridFilter.Range),
            // the report grouping heads its yes / no column "Known exploited": this count says what it counts (one heading per column)
            new("ExploitedRecommendations", report ? "Known exploited (recommendations)" : "Known exploited", GridType.Number, GridFilter.Range, Hidden: g.Id is "recommendation" or ReportGrouping),
            new("HasExploit", report ? "Known exploited" : "Exploit", GridType.Flag, GridFilter.Values),
        ]);
        if (report)
            cols.AddRange(
            [
                new("FirstSeen", "First seen", GridType.Date, GridFilter.Dates),
                new("LastSeen", "Last seen", GridType.Date, GridFilter.Dates),
                new("Remediation", "Remediation", Filter: GridFilter.Contains, Search: true),
            ]);
        cols.Add(new("Lead", "Most critical tier, then risk", GridType.Number, Hidden: true));
        return new GridSpec(g.Id == "recommendation" ? "summaryrecs" : "summary" + g.Id.Replace("-", "", StringComparison.Ordinal), "", source, cols,
            "Lead", true, "RowKey", ["CollectionId"], Immutable: true);
    }

    // ---- the key figures ----------------------------------------------------------------------------------------------

    /// Every figure of one collection.
    public const string KeyFigures = """
SELECT k.Block, k.Figure, k.Dim1, k.Dim2, k.Value, k.Assets, k.Total, CONVERT(int, k.Available) AS Available, k.Note, k.Items, k.VeryHigh, k.Servers, k.Clients
FROM sidata.KeyFigure AS k
WHERE k.CollectionId = TRY_CONVERT(int, @CollectionId)
ORDER BY k.Block, k.Figure, k.Dim1, k.Dim2;
""";

    /// The headline figures (no dimension) of every complete collection of the last @Days days: the trend.
    public const string KeyFigureTrend = """
SELECT CONVERT(nvarchar(64), c.CollectionId) AS CollectionId, c.CollectionTime, k.Figure, k.Value, k.Assets, CONVERT(int, k.Available) AS Available
FROM sidata.KeyFigure AS k
JOIN sidata.Collection AS c ON c.CollectionId = k.CollectionId
WHERE c.Kind = N'Detailed' AND c.Status = N'Complete' AND c.CollectionTime >= DATEADD(day, -@Days, SYSUTCDATETIME())
  AND k.Dim1 = N'' AND k.Dim2 = N'' AND k.Block = N'headline'
ORDER BY c.CollectionTime, k.Figure;
""";
}

/// What is built for one collection (null = not yet, or the database does not have it yet).
/// BuiltGroupings: when the asked grouping is not written for the collection, the groupings that ARE (the definition's order;
/// empty = none yet; null = not read).
public sealed record RecommendationState(bool HasRemediation, DateTime? RemediationAt, bool HasKeyFigures, DateTime? KeyFiguresAt, bool HasSummaryGroups, bool SummaryGroupsReady,
    IReadOnlyList<string>? BuiltGroupings = null);

/// One stored key figure: block, figure, its two dimensions ('' = none, '(all)' = every value), the value, the assets it
/// is on, the population it is a part of; Available false = the data cannot answer it (the reason in Note).
public sealed record KeyFigureRow(string Block, string Figure, string Dim1, string Dim2, double? Value, long? Assets, long? Total, bool Available, string? Note,
    long? Items = null, long? VeryHigh = null, long? Servers = null, long? Clients = null);

/// One point of the headline trend.
public sealed record KeyFigurePoint(string CollectionId, DateTime CollectionTime, string Figure, double? Value, long? Assets, bool Available);

public interface IRecommendationViews
{
    /// <paramref name="grouping"/>: whose Summary rows must be written for SummaryGroupsReady (null = any grouping).
    Task<QueryResult<RecommendationState>> StateAsync(string collectionId, CancellationToken ct, string? grouping = null);
    Task<QueryResult<IReadOnlyList<KeyFigureRow>>> KeyFiguresAsync(string collectionId, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<KeyFigurePoint>>> TrendAsync(int days, CancellationToken ct);
}

/// The SQL reads of <see cref="IRecommendationViews"/>; a database without the tables answers "not built".
public sealed class SqlRecommendationViews(IProSql sql, TimeProvider? clock = null) : IRecommendationViews
{
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;

    private async Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> Q(string text, Dictionary<string, object?> p, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(text);
        return await sql.QueryAsync(new SqlQuery(text, p), ct).ConfigureAwait(false);
    }

    public async Task<QueryResult<RecommendationState>> StateAsync(string collectionId, CancellationToken ct, string? grouping = null)
    {
        var id = CollectionViewSql.CollectionId(collectionId);
        var s = (await Q(RecommendationSql.State, new(), ct)).FirstOrDefault();
        bool B(string k) => s is not null && ProDataQueries.L(s, k) == 1;
        DateTime? rem = null, kf = null;
        if (B("HasRemediation") && B("HasKeyFigures"))
        {
            var m = (await Q(RecommendationSql.Marks, new() { ["CollectionId"] = id }, ct)).FirstOrDefault();
            rem = m?.TryGetValue("RemediationAt", out var a) == true ? a as DateTime? : null;
            kf = m?.TryGetValue("KeyFiguresAt", out var b) == true ? b as DateTime? : null;
        }
        var groups = B("HasSummaryGroups") && (await Q(RecommendationSql.SummaryGroupsOf, new() { ["CollectionId"] = id, ["Grouping"] = string.IsNullOrWhiteSpace(grouping) ? null : grouping }, ct)).Count > 0;
        IReadOnlyList<string>? built = null;
        if (B("HasSummaryGroups") && !groups)
        {
            // the views that ARE written for this collection: the page names them instead of a blank "being prepared"
            var st = (await Q(RecommendationSql.SummaryGroupingsBuilt, new() { ["CollectionId"] = id }, ct)).FirstOrDefault();
            if (st is null) built = [];
            else if (ProDataQueries.L(st, "FromRows") == 1)
                built = RecommendationSql.ParseGroupings(";" + string.Join(";", (await Q(RecommendationSql.SummaryGroupingsOfRows, new() { ["CollectionId"] = id }, ct))
                    .Select(r => ProDataQueries.S(r, "GroupingId"))) + ";");
            else built = RecommendationSql.ParseGroupings(ProDataQueries.S(st, "Groupings"));
        }
        return new(new RecommendationState(B("HasRemediation"), rem, B("HasKeyFigures"), kf, B("HasSummaryGroups"), groups, built),
            RecommendationSql.State, sql.SourceName, _clock.GetUtcNow());
    }

    public async Task<QueryResult<IReadOnlyList<KeyFigureRow>>> KeyFiguresAsync(string collectionId, CancellationToken ct)
    {
        var rows = await Q(RecommendationSql.KeyFigures, new() { ["CollectionId"] = CollectionViewSql.CollectionId(collectionId) }, ct);
        return new(rows.Select(r => new KeyFigureRow(ProDataQueries.S(r, "Block"), ProDataQueries.S(r, "Figure"), ProDataQueries.S(r, "Dim1"), ProDataQueries.S(r, "Dim2"),
            Dbl(r, "Value"), Lng(r, "Assets"), Lng(r, "Total"), ProDataQueries.L(r, "Available") == 1, r.TryGetValue("Note", out var n) ? n as string : null,
            Lng(r, "Items"), Lng(r, "VeryHigh"), Lng(r, "Servers"), Lng(r, "Clients"))).ToList(),
            RecommendationSql.KeyFigures, sql.SourceName, _clock.GetUtcNow());
    }

    public async Task<QueryResult<IReadOnlyList<KeyFigurePoint>>> TrendAsync(int days, CancellationToken ct)
    {
        var rows = await Q(RecommendationSql.KeyFigureTrend, new() { ["Days"] = Math.Clamp(days, 1, 400) }, ct);
        return new(rows.Select(r => new KeyFigurePoint(ProDataQueries.S(r, "CollectionId"), r.TryGetValue("CollectionTime", out var t) && t is DateTime d ? d : default,
            ProDataQueries.S(r, "Figure"), Dbl(r, "Value"), Lng(r, "Assets"), ProDataQueries.L(r, "Available") == 1)).ToList(),
            RecommendationSql.KeyFigureTrend, sql.SourceName, _clock.GetUtcNow());
    }

    private static double? Dbl(IReadOnlyDictionary<string, object?> r, string k) =>
        r.TryGetValue(k, out var v) && v is not null and not DBNull ? Convert.ToDouble(v, CultureInfo.InvariantCulture) : null;
    private static long? Lng(IReadOnlyDictionary<string, object?> r, string k) =>
        r.TryGetValue(k, out var v) && v is not null and not DBNull ? Convert.ToInt64(v, CultureInfo.InvariantCulture) : null;
}
