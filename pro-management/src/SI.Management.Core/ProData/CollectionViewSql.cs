namespace SI.Management.Core.ProData;

/// <summary>
/// The statements of the fourteen collection views (REQUIREMENTS #241). Same rules as <see cref="ProDataSql"/>: fixed
/// text, every caller value a parameter, read-only (<see cref="SqlGuard"/>), server-paged, one collection at a time.
/// 🔑 NO per-row lookup into another table: no OUTER/CROSS APPLY, no "key = a OR key = b" join. Every lookup is a key
/// set built ONCE (a grouped CTE) and joined -- the Closure fix (live 2026-10-04: a per-item OUTER APPLY with an OR
/// timed out after 120 s on 12,205 items; the joined key map answered in 0.3 s).
/// 🔑 Aggregates a view would otherwise compute by scanning every finding (counts per MITRE tactic, compliance tag,
/// risk rating, CVSS band, score) are PRE-COMPUTED by the data sync into sidata.FindingFacet, one set per collection.
/// The collection is compared on its native INT column through TRY_CONVERT of the parameter (a constant), so the
/// clustered (CollectionId, FindingId) range and the views index are used.
/// </summary>
public static class CollectionViewSql
{
    public const string ThisCollection = "f.CollectionId = TRY_CONVERT(int, @CollectionId)";

    /// The ranked form of a RA severity ("Very High" is Defender's critical), critical first -- the ONE shared rank
    /// (<see cref="SeverityOrder.SqlRank"/>, #246), so a view grid and the findings browser order severity alike.
    public static string SeverityRank(string col) => SeverityOrder.SqlRank(col);

    public static string RatingRank(string col) =>
        $"CASE {col} WHEN N'Critical' THEN 0 WHEN N'High' THEN 1 WHEN N'Moderate' THEN 2 WHEN N'Low' THEN 3 ELSE 4 END";

    private static readonly string TierSort = "CASE WHEN g.[Tier] = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, g.[Tier]) END";

    // ---- the collections a view can open --------------------------------------------------------------------------

    /// Complete Detailed collections, newest first, with when the views' aggregates were computed (DerivedAt) and the
    /// next collection's time (the end of "what happened with this collection").
    public const string Collections = """
SELECT TOP (@Top) CONVERT(nvarchar(64), col.CollectionId) AS CollectionId, col.CollectionTime, col.Kind, col.[Rows] AS RowTotal,
       col.DerivedAt, col.NextTime
FROM (
    SELECT x.CollectionId, x.CollectionTime, x.Kind, x.[Rows], x.DerivedAt,
           LEAD(x.CollectionTime) OVER (ORDER BY x.CollectionTime) AS NextTime
    FROM sidata.Collection AS x
    WHERE x.Status = N'Complete' AND x.Kind = N'Detailed'
) AS col
ORDER BY col.CollectionTime DESC;
""";

    /// Whether the database says when a collection's view data was written (sidata.Collection.ViewsReadyAt, set by the
    /// data sync after the views' aggregates, the prepared context, the departments and the counted aggregates).
    public const string ReadySchema = "SELECT CASE WHEN COL_LENGTH(N'sidata.Collection', N'ViewsReadyAt') IS NULL THEN 0 ELSE 1 END AS HasViewsReady;";

    /// The same list on a database that has the mark: a collection is listed only once its view data is written -- 'Complete'
    /// alone says its rows are loaded, minutes earlier, and a page that opened it then had to work its columns out row by
    /// row. A collection that never got ready (its data sync died) is left out, so the previous one stays the newest; the
    /// next data sync finishes it. While NO collection carries the mark (no data sync of this release ran yet) every
    /// complete collection is listed, as before. The next collection's time is the next LISTED one's.
    /// ONE TRUSTED RUN (owner 2026-10-19): never past the published run -- its collection is the newest a view opens.
    public const string CollectionsReady = $"""
SELECT TOP (@Top) CONVERT(nvarchar(64), col.CollectionId) AS CollectionId, col.CollectionTime, col.Kind, col.[Rows] AS RowTotal,
       col.DerivedAt, col.NextTime
FROM (
    SELECT x.CollectionId, x.CollectionTime, x.Kind, x.[Rows], x.DerivedAt,
           LEAD(x.CollectionTime) OVER (ORDER BY x.CollectionTime) AS NextTime
    FROM sidata.Collection AS x
    WHERE x.Status = N'Complete' AND x.Kind = N'Detailed'
      AND (x.ViewsReadyAt IS NOT NULL OR NOT EXISTS (SELECT 1 FROM sidata.Collection AS r WHERE r.ViewsReadyAt IS NOT NULL))
      AND x.CollectionTime <= ISNULL({PublishedRun.DetailedTime}, x.CollectionTime)
) AS col
ORDER BY col.CollectionTime DESC;
""";

    /// <paramref name="ready"/>: the database has the mark (<see cref="ReadySchema"/>).
    public static SqlQuery CollectionsTop(int top, bool ready = false) =>
        new(ready ? CollectionsReady : Collections, new Dictionary<string, object?> { ["Top"] = Math.Clamp(top, 1, 500) });

    // ---- pre-computed aggregates ------------------------------------------------------------------------------------

    public const string Facets = """
SELECT ff.Facet, ff.Value, ff.Findings, ff.Assets, ff.ScoreTotal, ff.WeightedTotal, ff.MaxScore
FROM sidata.FindingFacet AS ff
WHERE ff.CollectionId = TRY_CONVERT(int, @CollectionId)
ORDER BY ff.Facet, ff.Findings DESC;
""";

    public static SqlQuery FacetsOf(string collectionId) => new(Facets, new Dictionary<string, object?> { ["CollectionId"] = CollectionId(collectionId) });

    public static string CollectionId(string? id) => ProDataFilters.Id(id, "collection") ?? throw new ArgumentException("a collection is required");

    // ---- #855: the CI lifecycle a collection grid counts ---------------------------------------------------------------
    // Owner 2026-10-21: "default filter is active, so it should be active only". A grid over the collection's finding rows
    // (sidata.Finding.CiLifecycle) or its per-CI rows (sidata.AssetRiskSummary.CiLifecycle, one per CI) counts the lifecycle
    // a person chose -- active by default. The facet counts, the per-CVE rows and the Summary groupings are BUILT over active
    // CIs only (their key cannot take the lifecycle); those grids are left as they are and say so (LifecycleFilter.ActiveOnlyWords).

    /// The grids a lifecycle choice applies to (the finding rows and the per-CI rows, stored or live).
    public static readonly IReadOnlySet<string> LifecycleGrids = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "rows", "rowsofissue", "rowsoffix", "assets", "assetrisk", RiskExplainSql.Name };

    /// The grids whose stored rows are of active CIs only (no choice): the per-CVE rows and the Summary groupings.
    public static bool BuiltOverActive(string? grid) =>
        grid is not null && (grid.Equals("vulns", StringComparison.OrdinalIgnoreCase) || SummaryGroupViewSql.All.Any(v => v.Grid.Equals(grid, StringComparison.OrdinalIgnoreCase)));

    /// <summary>
    /// PURE. <paramref name="spec"/> narrowed to the CI lifecycle <paramref name="lifecycle"/> (null = not a lifecycle grid). The
    /// predicate is written from the fixed state names only (<see cref="LifecycleFilter.Sql"/>). The finding rows keep their
    /// index-ordered opening page only for the default (active): its stored total and counts (sidata.FindingFacet) are of active
    /// CIs; any other choice reads the generic page (counted live, over that lifecycle's rows -- a seek on IX_Finding_CiLifecycle).
    /// </summary>
    public static GridSpec? WithLifecycle(GridSpec spec, LifecycleFilter lifecycle)
    {
        if (!LifecycleGrids.Contains(spec.Name)) return null;
        if (spec.Name.StartsWith("rows", StringComparison.OrdinalIgnoreCase))
        {
            var pred = lifecycle.Sql("f.CiLifecycle");
            var source = spec.Source.Replace("WHERE " + ThisCollection, "WHERE " + ThisCollection + " AND " + pred, StringComparison.Ordinal);
            var keyset = spec.Keyset is { } k && lifecycle.IsActiveOnly ? k with { Keys = k.Keys + " AND " + pred } : null;
            return spec with { Source = source, Keyset = keyset };
        }
        // the per-CI rows: stored (alias cf, one row per CI with its lifecycle), or grouped live from the findings
        if (spec.Source.Contains(AssetSummaryWhere, StringComparison.Ordinal))
            return spec with { Source = spec.Source.Replace(AssetSummaryWhere, AssetSummaryWhere + " AND " + lifecycle.Sql("cf.CiLifecycle"), StringComparison.Ordinal) };
        return spec with { Ctes = spec.Ctes.Replace("WHERE " + ThisCollection + " AND f.AssetKey IS NOT NULL", "WHERE " + ThisCollection + " AND f.AssetKey IS NOT NULL AND " + lifecycle.Sql("f.CiLifecycle"), StringComparison.Ordinal) };
    }

    // ---- (1) raw rows, also the findings of one CI (3) and the facet views (7..10) ---------------------------------

    public static readonly GridSpec Rows = GridSql.Check(new GridSpec("rows", "", $"""
SELECT CONVERT(nvarchar(64), f.FindingId) AS FindingId, f.AssetKey, f.AssetName, a.AssetKind, {ProDataSql.AssetKindsExpr("a")} AS AssetKinds, {ProDataSql.TierExpr("f.Tier")} AS Tier,
       f.Severity, f.RiskRating, f.RiskScore, f.RiskScoreWeighted, f.Cvss, f.HasExploit, f.SecurityDomain, f.ReportName,
       f.Cve, f.ConfigurationId, f.Title, f.MitreTactics, f.MitreTechniques, f.ComplianceTags,
       f.Category, f.Subcategory, f.DepartmentName AS Department
FROM sidata.Finding AS f
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
WHERE {ThisCollection}
  AND (@AssetKey IS NULL OR f.AssetKey = @AssetKey)
""", new GridColumn[]
    {
        new("FindingId", "Id", Hidden: true),
        new("AssetKey", "Asset key", Search: true, Hidden: true),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        new("AssetName", "Asset", Filter: GridFilter.Contains, Search: true),
        GridColumn.AssetKind(),
        new("Title", "Finding", Filter: GridFilter.Contains, Search: true),
        new("Cve", "CVE", Filter: GridFilter.Contains, Search: true),
        new("ConfigurationId", "Configuration", Filter: GridFilter.Contains, Search: true, Hidden: true),
        new("Severity", "Severity", Filter: GridFilter.Values, SortSql: SeverityRank("g.[Severity]")),
        new("RiskRating", "Rating", Filter: GridFilter.Values, SortSql: RatingRank("g.[RiskRating]")),
        new("RiskScore", "Risk Score", GridType.Number, GridFilter.Range),
        new("RiskScoreWeighted", "Weighted", GridType.Number, GridFilter.Range),
        new("Cvss", "CVSS", GridType.Number, GridFilter.Range),
        new("HasExploit", "Exploit", GridType.Flag, GridFilter.Values),
        new("SecurityDomain", "Domain", Filter: GridFilter.Values),
        // #636: Domain > Category > Subcategory as filters (typed columns of sidata.Finding), and the department: its NAME is
        // stored on the finding row by the data sync (owner 2026-10-19, approved) -- an immutable grid never reads cfg
        new("Category", "Category", Filter: GridFilter.Values),
        new("Subcategory", "Subcategory", Filter: GridFilter.Values),
        new("Department", "Department", Filter: GridFilter.Values),
        new("ReportName", "Report", Filter: GridFilter.Values, Search: true),
        new("MitreTactics", "MITRE tactics", Filter: GridFilter.Tokens, Search: true),
        new("MitreTechniques", "MITRE techniques", Filter: GridFilter.Tokens, Search: true, Hidden: true),
        new("ComplianceTags", "Compliance", Filter: GridFilter.Tokens, Search: true),
    }, "RiskScore", true, "FindingId", ["CollectionId", "AssetKey"], Immutable: true, Keyset: RowsKeyset(), KeySortSql: RowKeySort));

    // ---- #812: the raw rows' opening view off an index, its total and its filter counts stored ------------------------
    // A large customer, 2026-10-19 (1,117,524 findings): the raw rows' first page counted every finding of the collection
    // (COUNT_BIG(*) OVER ()) and sorted them all before returning 50; every filter dropdown grouped them all again. The page a
    // view opens with (no filter, no search, no selection, a DESC sort on the risk score, the CVSS or the weighted score) now
    // reads its keys off IX_Finding_RiskPage / IX_Finding_CvssPage / IX_Finding_WeightedPage (CollectionId, score DESC; the
    // clustered FindingId follows), computes the row for those keys only, and takes the total from the counts the data sync
    // stored per collection (sidata.FindingFacet's tier facet: one value per finding; the counted twin when exempted findings
    // are left out) -- the narrowest index answers when a collection has none. The dropdowns' counts with nothing else
    // narrowing the view are the stored facet counts too. Ties are ordered by the finding's number (TRY_CONVERT(bigint)) on
    // every page, so the index page and the generic page are the same rows in the same order.

    /// The finding's number as the tie-break of every sort (the key text "10" would sort before "9").
    public const string RowKeySort = "TRY_CONVERT(bigint, g.[FindingId])";

    /// The stored total of the collection's findings (the tier facet holds every finding once), else the narrowest count.
    public const string StoredFindingTotal =
        "COALESCE((SELECT SUM(CONVERT(bigint, ff.Findings)) FROM sidata.FindingFacet AS ff WHERE ff.CollectionId = TRY_CONVERT(int, @CollectionId) AND ff.Facet = N'tier'), " +
        "(SELECT COUNT_BIG(*) FROM sidata.Finding AS f WHERE f.CollectionId = TRY_CONVERT(int, @CollectionId)))";

    /// A Values / Tokens column's stored counts (sidata.FindingFacet), exactly what the grid's live value counts give the
    /// unnarrowed view: the facet's '(none)' and '' left out as the live counts leave out NULL and ''; the tier as the grid
    /// words it (0..3, else Unclassified). Null = no stored facet: counted live.
    public static string? StoredRowCounts(string column)
    {
        var facet = column switch
        {
            "Severity" => "severity", "RiskRating" => "rating", "SecurityDomain" => "domain", "ReportName" => "report",
            "MitreTactics" => "tactic", "MitreTechniques" => "technique", "ComplianceTags" => "tag", "Tier" => "tier", _ => null,
        };
        if (facet is null) return null;
        var value = facet == "tier" ? "CASE WHEN ff.Value IN (N'0', N'1', N'2', N'3') THEN ff.Value ELSE N'Unclassified' END" : "ff.Value";
        var none = facet == "tier" ? "" : " AND ff.Value <> N'(none)'";
        return $"""
SELECT TOP ({GridSql.MaxCountedValues}) v.V AS V, SUM(CONVERT(bigint, ff.Findings)) AS N
FROM sidata.FindingFacet AS ff
CROSS APPLY (SELECT {value} AS V) AS v
WHERE ff.CollectionId = TRY_CONVERT(int, @CollectionId) AND ff.Facet = N'{facet}' AND ff.Value <> N''{none}
GROUP BY v.V
ORDER BY SUM(CONVERT(bigint, ff.Findings)) DESC, v.V;
""";
    }

    private static GridKeyset RowsKeyset() => new(
        "f.FindingId AS K FROM sidata.Finding AS f WHERE f.CollectionId = TRY_CONVERT(int, @CollectionId)",
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["RiskScore"] = "f.RiskScore DESC, f.FindingId",
            ["Cvss"] = "f.Cvss DESC, f.FindingId",
            ["RiskScoreWeighted"] = "f.RiskScoreWeighted DESC, f.FindingId",
        },
        source => source.Replace(ThisCollection, ThisCollection + " AND f.FindingId IN (SELECT pk.K FROM pk)", StringComparison.Ordinal),
        StoredFindingTotal,
        p => !p.TryGetValue("AssetKey", out var a) || a is null,
        StoredRowCounts);

    /// <summary>
    /// #330: the collection's findings of ONE issue (a CVE, else a configuration id, else a title) -- EXACT equality on the
    /// three columns. What an aggregated row (a CVE row, an issue row) stands for is read with this, never with the grid's
    /// free-text search: that was a LIKE '%CVE-...%' over all nine searchable columns of every finding in the collection
    /// (no index can serve it), which on a ring-1 collection ran into the 90 s view limit while the action dialog said
    /// "counting their findings...". Same columns as <see cref="Rows"/>, so the department restriction applies unchanged.
    /// </summary>
    public static readonly GridSpec RowsOfIssue = GridSql.Check(Rows with
    {
        Name = "rowsofissue",
        Source = Rows.Source.Replace("AND (@AssetKey IS NULL OR f.AssetKey = @AssetKey)", "AND (f.Cve = @Issue OR f.ConfigurationId = @Issue OR f.Title = @Issue)", StringComparison.Ordinal),
        SourceParameters = ["CollectionId", "Issue"],
        Keyset = null,   // narrowed to one issue by its own source: never the opening view's index page
    });

    /// #636: the collection's findings ONE remediation closes (Remediations > a fix > its findings): the stored key of each
    /// finding (sidata.Finding.RemediationKey, IX_Finding_Remediation). Same columns as <see cref="Rows"/>.
    /// 🔴 #864 (owner 2026-10-21, a ring 2 install: a fix's "findings closed" link showed "0 rows" for a fix that 578,285
    /// findings carry): this spec INHERITED <see cref="Rows"/>' #812 keyset, whose Applies test only looks for an AssetKey --
    /// which the fix plan removes. The opening view (no filter, sort on the risk score) then read the COLLECTION's top 50
    /// keys off IX_Finding_RiskPage and kept those of them the fix closes -- almost always none -- with the stored total of
    /// the whole collection. A source narrowed by its own parameter never pages off the collection's index (as RowsOfIssue).
    public static readonly GridSpec RowsOfFix = GridSql.Check(Rows with
    {
        Name = "rowsoffix",
        Source = NarrowRows("AND f.RemediationKey = @Fix"),
        SourceParameters = ["CollectionId", "Fix"],
        Keyset = null,   // narrowed to one fix by its own source: never the opening view's index page, never the stored counts
    });

    /// The rows' source with its one-CI condition swapped for <paramref name="condition"/> -- loud when the condition is no
    /// longer in the source (a later change to <see cref="Rows"/> would otherwise show EVERY finding under a narrowed name).
    private static string NarrowRows(string condition)
    {
        const string oneCi = "AND (@AssetKey IS NULL OR f.AssetKey = @AssetKey)";
        if (!Rows.Source.Contains(oneCi, StringComparison.Ordinal))
            throw new InvalidOperationException("CollectionViewSql.Rows no longer holds its one-CI condition; a narrowed rows view cannot be built from it.");
        return Rows.Source.Replace(oneCi, condition, StringComparison.Ordinal);
    }

    // ---- (2) correlated view: one row per CI with its linked objects ------------------------------------------------
    // 🔑 #284: the finding aggregate (cf) is referenced ONCE. The identifier counts are built from sidata.AssetIdentifier
    // ALONE (its narrow (AssetKey, IdentifierType, IdentifierValue) index, read once, in key order) and joined to cf at the
    // end. The earlier form narrowed the identifiers by joining cf a second time; with exempted findings left out (#264,
    // the default) the optimizer re-ran the whole finding aggregate once per CI -- live ring 1: 975 scans, 5,961,320
    // reads, 130 s, past the 90 s limit (the error page). Now: one scan, 1.5 s on the same data.

    // 🔑 2026-10-19 (a large customer, 1,117,524 finding rows / ~3,000 CIs): the per-CI aggregate (cf) is PRE-COMPUTED by the
    // data sync once per collection -- sidata.AssetRiskSummary, its counted twin for the exempted scope, and
    // sidata.AssetRiskSummaryState (SI-DataViewContext.ps1 Invoke-SIDataAssetRiskSummary) -- and the grids read those typed,
    // indexed rows (thousands, not a million) under the SAME alias cf, so every column, filter and sort is unchanged. A
    // collection without its rows is never grouped here: the pages say the list is being prepared. The live forms
    // (AssetsLive / AssetRiskLive) are kept ONLY for an account limited to departments: the pre-computed rows span every
    // department, and a department-limited read restricts the finding rows themselves (DepartmentScope.Restrict).

    /// The identifier map (sidata.AssetIdentifier alone, read once, joined at the end).
    private const string AssetIdentifierMaps = """
it AS (
    SELECT ai.AssetKey, ai.IdentifierType, COUNT_BIG(*) AS N
    FROM sidata.AssetIdentifier AS ai
    GROUP BY ai.AssetKey, ai.IdentifierType
), ids AS (
    SELECT it.AssetKey, SUM(it.N) AS Identifiers,
           SUM(CASE WHEN it.IdentifierType = N'SI_AssetId' THEN it.N ELSE 0 END) AS Members,
           STRING_AGG(CONVERT(nvarchar(max), it.IdentifierType), N', ') WITHIN GROUP (ORDER BY it.IdentifierType) AS LinkedTypes
    FROM it
    GROUP BY it.AssetKey
)
""";

    /// The pre-computed per-CI rows of the collection as cf (the counted twin when exempted findings are left out).
    public const string AssetSummaryFrom = "FROM sidata.AssetRiskSummary AS cf";
    public const string AssetSummaryWhere = "WHERE cf.[CollectionId] = TRY_CONVERT(int, @CollectionId)";

    private static string AssetsSelect(string from, string where) => $"""
SELECT cf.AssetKey, COALESCE(a.AssetName, cf.AssetKey) AS AssetName, a.AssetKind, {ProDataSql.AssetKindsExpr("a")} AS AssetKinds, {ProDataSql.TierExpr("a.Tier")} AS Tier, a.KeySource,
       COALESCE(ids.Members, 0) AS Members, COALESCE(ids.Identifiers, 0) AS Identifiers, ids.LinkedTypes,
       cf.Findings, cf.Vulnerabilities, cf.MaxRisk, cf.TotalRisk, cf.TotalWeighted, a.FirstSeen, a.LastSeen
{from}
LEFT JOIN sidata.Asset AS a ON a.AssetKey = cf.AssetKey
LEFT JOIN ids ON ids.AssetKey = cf.AssetKey{where}
""";

    public static readonly GridSpec Assets = GridSql.Check(new GridSpec("assets", AssetIdentifierMaps,
        AssetsSelect(AssetSummaryFrom, "\n" + AssetSummaryWhere), AssetsColumns(), "TotalRisk", true, "AssetKey", ["CollectionId"], Immutable: true));

    /// <summary>
    /// The same rows grouped LIVE from the findings -- ONLY for an account limited to departments (the pre-computed rows span
    /// every department; <see cref="DepartmentScope.Restrict(GridSpec, RowVisibility)"/> narrows the finding rows). Same name
    /// as <see cref="Assets"/> (one layout, one row map); never what an unrestricted page reads.
    /// </summary>
    public static readonly GridSpec AssetsLive = GridSql.Check(new GridSpec("assets", $"""
cf AS (
    SELECT f.AssetKey, COUNT_BIG(*) AS Findings, SUM(CASE WHEN f.Cve IS NOT NULL THEN 1 ELSE 0 END) AS Vulnerabilities,
           MAX(f.RiskScore) AS MaxRisk, SUM(f.RiskScore) AS TotalRisk, SUM(f.RiskScoreWeighted) AS TotalWeighted
    FROM sidata.Finding AS f
    WHERE {ThisCollection} AND f.AssetKey IS NOT NULL
    GROUP BY f.AssetKey
), {AssetIdentifierMaps}
""", AssetsSelect("FROM cf", ""), AssetsColumns(), "TotalRisk", true, "AssetKey", ["CollectionId"], Immutable: true));

    private static GridColumn[] AssetsColumns() =>
    [
        new("AssetKey", "Asset (CI) key", Search: true, Hidden: true),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        new("AssetName", "Asset (CI)", Filter: GridFilter.Contains, Search: true),
        GridColumn.AssetKind(),
        new("Members", "Linked objects", GridType.Number, GridFilter.Range),
        new("LinkedTypes", "Seen as", Filter: GridFilter.Contains, Search: true),
        new("Identifiers", "Identifiers", GridType.Number, GridFilter.Range),
        new("KeySource", "Key", Filter: GridFilter.Values),
        new("Findings", "Findings", GridType.Number, GridFilter.Range),
        new("Vulnerabilities", "CVEs", GridType.Number, GridFilter.Range),
        new("MaxRisk", "Max risk", GridType.Number, GridFilter.Range),
        new("TotalRisk", "Total risk", GridType.Number, GridFilter.Range),
        new("TotalWeighted", "Total weighted", GridType.Number, GridFilter.Range),
        new("FirstSeen", "First seen", GridType.Date, GridFilter.Dates),
        new("LastSeen", "Last seen", GridType.Date, GridFilter.Dates),
    ];

    // ---- (5) + (6) risk per CI: total, highest, average -- plain and weighted ---------------------------------------
    // The pre-computed per-CI rows (sidata.AssetRiskSummary, see above) under the alias cf -- the same projection as before.

    private static string AssetRiskSelect(string from, string where) => $"""
SELECT cf.AssetKey, COALESCE(a.AssetName, cf.AssetName, cf.AssetKey) AS AssetName, a.AssetKind, {ProDataSql.AssetKindsExpr("a")} AS AssetKinds, {ProDataSql.TierExpr("cf.Tier")} AS Tier,
       cf.Findings, cf.TotalRisk, cf.MaxRisk, cf.AvgRisk, cf.TotalWeighted, cf.MaxWeighted, cf.AvgWeighted, cf.CriticalRated, cf.HighRated
{from}
LEFT JOIN sidata.Asset AS a ON a.AssetKey = cf.AssetKey{where}
""";

    public static readonly GridSpec AssetRisk = GridSql.Check(new GridSpec("assetrisk", "",
        AssetRiskSelect(AssetSummaryFrom, "\n" + AssetSummaryWhere), AssetRiskColumns(), "TotalRisk", true, "AssetKey", ["CollectionId"], Immutable: true));

    /// When a collection's per-CI rows were written (no row = not yet). A database without the table answers "Invalid object
    /// name" -- the page then says the update adds it.
    public const string AssetSummaryStatus = """
SELECT s.BuiltAt, s.Assets, s.CountedAssets
FROM sidata.AssetRiskSummaryState AS s
WHERE s.CollectionId = TRY_CONVERT(int, @CollectionId);
""";

    /// <summary>
    /// The same rows grouped LIVE from the findings -- ONLY for an account limited to departments (as <see cref="AssetsLive"/>).
    /// Same name as <see cref="AssetRisk"/>; never what an unrestricted page reads.
    /// </summary>
    public static readonly GridSpec AssetRiskLive = GridSql.Check(new GridSpec("assetrisk", $"""
cf AS (
    SELECT f.AssetKey, MAX(f.AssetName) AS AssetName, MIN(f.Tier) AS Tier, COUNT_BIG(*) AS Findings,
           SUM(f.RiskScore) AS TotalRisk, MAX(f.RiskScore) AS MaxRisk, AVG(f.RiskScore) AS AvgRisk,
           SUM(f.RiskScoreWeighted) AS TotalWeighted, MAX(f.RiskScoreWeighted) AS MaxWeighted, AVG(f.RiskScoreWeighted) AS AvgWeighted,
           SUM(CASE WHEN f.RiskRating = N'Critical' THEN 1 ELSE 0 END) AS CriticalRated,
           SUM(CASE WHEN f.RiskRating = N'High' THEN 1 ELSE 0 END) AS HighRated
    FROM sidata.Finding AS f
    WHERE {ThisCollection} AND f.AssetKey IS NOT NULL
    GROUP BY f.AssetKey
)
""", AssetRiskSelect("FROM cf", ""), AssetRiskColumns(), "TotalRisk", true, "AssetKey", ["CollectionId"], Immutable: true));

    private static GridColumn[] AssetRiskColumns() =>
    [
        new("AssetKey", "Asset (CI) key", Search: true, Hidden: true),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        new("AssetName", "Asset (CI)", Filter: GridFilter.Contains, Search: true),
        GridColumn.AssetKind(),
        new("Findings", "Findings", GridType.Number, GridFilter.Range),
        new("TotalRisk", "Total risk", GridType.Number, GridFilter.Range),
        new("MaxRisk", "Highest risk", GridType.Number, GridFilter.Range),
        new("AvgRisk", "Average risk", GridType.Number, GridFilter.Range),
        new("TotalWeighted", "Total weighted", GridType.Number, GridFilter.Range),
        new("MaxWeighted", "Highest weighted", GridType.Number, GridFilter.Range),
        new("AvgWeighted", "Average weighted", GridType.Number, GridFilter.Range),
        new("CriticalRated", "Rated critical", GridType.Number, GridFilter.Range),
        new("HighRated", "Rated high", GridType.Number, GridFilter.Range),
    ];

    // ---- (4) vulnerabilities: one row per CVE in the collection, with the close-loop's open items ---------------------
    // 🔑 A large customer, 2026-10-19 (1,117,524 finding rows, an 800 DTU database mostly idle): "keeps loading and hangs for
    // minutes", then the 90 s limit. The grid grouped EVERY finding of the collection by CVE per request (a distinct count of
    // assets per CVE, the highest CVSS, the most critical severity and tier -- none of it served by an index: the covering
    // index is keyed by asset, so the whole collection was read and hashed), aggregated the close-loop's open items over
    // every CVE, then counted, sorted and paged the result; every filter's value counts ran the same aggregate again, and
    // the answer was cached two minutes only (the close-loop moves). Now the data sync writes the per-CVE rows once per
    // collection (sidata.CveSummary, its counted twin for the exempted scope, sidata.CveSummaryState -- SI-DataViewContext.ps1)
    // and the grid pages THOSE typed, indexed rows (thousands, not a million). The close-loop's open items are read for the
    // page's rows only (two index seeks per row on IX_VulnerabilityItem_StateCve) -- over every CVE only when a person sorts
    // or filters on them. A collection without its rows is never grouped here: the page says the list is being prepared.

    /// The per-CVE rows of the collection (the counted twin when exempted findings are left out -- Exempted.Apply).
    private const string VulnRows = """
SELECT v.Cve, v.Title, v.Severity, v.SeverityRank, v.Cvss, v.HasExploit, v.Assets, v.Findings, v.MaxRisk, v.TotalRisk, v.Tier, v.Tier0Findings{0}
FROM sidata.CveSummary AS v{1}
WHERE v.CollectionId = TRY_CONVERT(int, @CollectionId)
""";

    /// The close-loop's open items over every CVE: only when the request sorts, filters or searches on them.
    private const string VulnOpenAll = """
LEFT JOIN (
    SELECT i.Cve, COUNT_BIG(*) AS OpenItems, MIN(i.FirstSeen) AS OldestOpen
    FROM vuln.VulnerabilityItem AS i
    WHERE i.State = N'Open' AND i.Source = @Source
    GROUP BY i.Cve
) AS o ON o.Cve = v.Cve
""";

    private static readonly string VulnFull = string.Format(System.Globalization.CultureInfo.InvariantCulture, VulnRows,
        ", COALESCE(o.OpenItems, 0) AS OpenItems, o.OldestOpen", "\n" + VulnOpenAll.TrimEnd());

    /// The page's rows only: the open items of each (IX_VulnerabilityItem_StateCve = Source, State, Cve INCLUDE FirstSeen).
    public const string VulnOpenItemsLate = "(SELECT COUNT_BIG(*) FROM vuln.VulnerabilityItem AS i WHERE i.Source = @Source AND i.State = N'Open' AND i.Cve = g.[Cve])";
    public const string VulnOldestOpenLate = "(SELECT MIN(i.FirstSeen) FROM vuln.VulnerabilityItem AS i WHERE i.Source = @Source AND i.State = N'Open' AND i.Cve = g.[Cve])";

    /// The narrow source: the per-CVE rows without the close-loop -- unless the request needs its columns for every row.
    public static string VulnNarrow(IReadOnlyCollection<string> needed) =>
        needed.Count > 0 ? VulnFull : string.Format(System.Globalization.CultureInfo.InvariantCulture, VulnRows, "", "");

    public static readonly GridSpec Vulnerabilities = GridSql.Check(new GridSpec("vulns", "", VulnFull, VulnColumns(late: true),
        "MaxRisk", true, "Cve", ["CollectionId", "Source"], Immutable: false, Late: new GridLate(VulnNarrow, "")));

    private static GridColumn[] VulnColumns(bool late) =>
    [
        new("Cve", "CVE", Filter: GridFilter.Contains, Search: true),
        new("Title", "Vulnerability", Filter: GridFilter.Contains, Search: true),
        new("Severity", "Severity", Filter: GridFilter.Values, SortSql: "g.[SeverityRank]"),
        new("SeverityRank", "Severity rank", GridType.Number, Hidden: true),
        new("Cvss", "CVSS", GridType.Number, GridFilter.Range),
        new("HasExploit", "Exploit", GridType.Flag, GridFilter.Values),
        new("Assets", "Assets", GridType.Number, GridFilter.Range),
        new("Findings", "Findings", GridType.Number),
        new("MaxRisk", "Highest risk", GridType.Number, GridFilter.Range),
        new("TotalRisk", "Total risk", GridType.Number),
        new("Tier", "Most critical tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        new("Tier0Findings", "On tier 0", GridType.Number, GridFilter.Range),
        new("OpenItems", "Open in close-loop", GridType.Number, GridFilter.Range, LateSql: late ? VulnOpenItemsLate : null),
        new("OldestOpen", "Open since", GridType.Date, GridFilter.Dates, LateSql: late ? VulnOldestOpenLate : null),
    ];

    /// When a collection's per-CVE rows were written (no row = not yet). A database without the table answers "Invalid object
    /// name" -- the page then says the update adds it.
    public const string CveSummaryStatus = """
SELECT s.BuiltAt, s.Cves, s.CountedCves
FROM sidata.CveSummaryState AS s
WHERE s.CollectionId = TRY_CONVERT(int, @CollectionId);
""";

    /// <summary>
    /// The same rows grouped LIVE from the findings -- ONLY for an account limited to departments (the header search): the
    /// pre-computed rows span every department, and a department-limited read restricts the finding rows themselves
    /// (<see cref="DepartmentScope.Restrict(GridSpec, RowVisibility)"/>). Never what the Vulnerabilities page reads.
    /// </summary>
    public static readonly GridSpec VulnerabilitiesLive = GridSql.Check(new GridSpec("vulnslive", $"""
v AS (
    SELECT f.Cve, MAX(f.Title) AS Title,
           MIN(CONCAT({SeverityRank("f.Severity")}, N'|', f.Severity)) AS SevKey,
           MAX(f.Cvss) AS Cvss, MAX(CASE WHEN f.HasExploit = 1 THEN 1 ELSE 0 END) AS HasExploit,
           COUNT_BIG(DISTINCT f.AssetKey) AS Assets, COUNT_BIG(*) AS Findings, MAX(f.RiskScore) AS MaxRisk, SUM(f.RiskScore) AS TotalRisk,
           MIN(f.Tier) AS BestTier, SUM(CASE WHEN f.Tier = 0 THEN 1 ELSE 0 END) AS Tier0Findings
    FROM sidata.Finding AS f
    WHERE {ThisCollection} AND f.Cve IS NOT NULL
    GROUP BY f.Cve
), o AS (
    SELECT i.Cve, COUNT_BIG(*) AS OpenItems, MIN(i.FirstSeen) AS OldestOpen
    FROM vuln.VulnerabilityItem AS i
    WHERE i.State = N'Open' AND i.Source = @Source
    GROUP BY i.Cve
)
""", $"""
SELECT v.Cve, v.Title, SUBSTRING(v.SevKey, CHARINDEX(N'|', v.SevKey) + 1, 30) AS Severity, TRY_CONVERT(int, LEFT(v.SevKey, 1)) AS SeverityRank,
       v.Cvss, CONVERT(bit, v.HasExploit) AS HasExploit, v.Assets, v.Findings, v.MaxRisk, v.TotalRisk,
       {ProDataSql.TierExpr("v.BestTier")} AS Tier, v.Tier0Findings, COALESCE(o.OpenItems, 0) AS OpenItems, o.OldestOpen
FROM v
LEFT JOIN o ON o.Cve = v.Cve
""", VulnColumns(late: false), "MaxRisk", true, "Cve", ["CollectionId", "Source"], Immutable: false));

    // ---- (10b) #290: the Risk Analysis mail's Top critical findings ---------------------------------------------------
    // The list and its numbers are the mail's (the kept view, passed in as @Keys JSON: rank, name, severity, domain /
    // category, affected assets, scores, top affected assets); this collection adds how many findings of each issue it
    // holds and, for a CVE, when the close-loop first saw it open. A row stands for every finding of its issue.
    // 🔑 The issue of a finding is its configuration id, else its CVE. The count (cf) reads each half by the listed keys --
    // the configuration id through IX_Finding_Config, a finding without one through that index's "no configuration id"
    // range (it carries the CVE) -- never COALESCE(ConfigurationId, Cve) IN (...): no index answers that, and it read every
    // finding of the collection for the ~50 keys of the list.

    public static readonly GridSpec TopIssues = GridSql.Check(new GridSpec("topissues", $"""
k AS (
    SELECT * FROM OPENJSON(@Keys) WITH (IssueKey nvarchar(256) '$.k', [Rank] int '$.r', Name nvarchar(1000) '$.n', Severity nvarchar(30) '$.s',
        Domain nvarchar(128) '$.d', Category nvarchar(256) '$.c', Affected int '$.a', Weighted float '$.w', TotalRisk float '$.t', TopAssets nvarchar(1000) '$.x')
), cf AS (
    SELECT u.IssueKey, COUNT_BIG(*) AS Findings
    FROM (
        SELECT f.ConfigurationId AS IssueKey, f.FindingId
        FROM sidata.Finding AS f
        WHERE {ThisCollection} AND f.ConfigurationId IN (SELECT k.IssueKey FROM k)
        UNION ALL
        SELECT f.Cve, f.FindingId
        FROM sidata.Finding AS f
        WHERE {ThisCollection} AND f.ConfigurationId IS NULL AND f.Cve IN (SELECT k.IssueKey FROM k)
    ) AS u
    GROUP BY u.IssueKey
), fs AS (
    SELECT i.Cve, MIN(i.FirstSeen) AS FirstSeen
    FROM vuln.VulnerabilityItem AS i
    WHERE i.Cve IN (SELECT k.IssueKey FROM k)
    GROUP BY i.Cve
)
""", $"""
SELECT k.IssueKey, k.[Rank], k.Name, k.Severity, {SeverityRank("k.Severity")} AS SeverityRank, k.Domain, k.Category, k.Affected, k.Weighted, k.TotalRisk,
       k.TopAssets, COALESCE(cf.Findings, 0) AS Findings, fs.FirstSeen
FROM k
LEFT JOIN cf ON cf.IssueKey = k.IssueKey
LEFT JOIN fs ON fs.Cve = k.IssueKey
""", new GridColumn[]
    {
        new("Rank", "#", GridType.Number, GridFilter.Range),
        new("Name", "Finding", Filter: GridFilter.Contains, Search: true),
        new("IssueKey", "CVE / configuration", Filter: GridFilter.Contains, Search: true),
        new("TopAssets", "Top affected assets", Filter: GridFilter.Contains, Search: true),
        new("Domain", "Domain", Filter: GridFilter.Values),
        new("Category", "Category", Filter: GridFilter.Values),
        new("Severity", "Severity", Filter: GridFilter.Values, SortSql: "g.[SeverityRank]"),
        new("SeverityRank", "Severity rank", GridType.Number, Hidden: true),
        new("Affected", "Affected assets", GridType.Number, GridFilter.Range),
        new("Weighted", "Weighted Risk Score", GridType.Number, GridFilter.Range),
        new("TotalRisk", "Total Risk Score", GridType.Number, GridFilter.Range, Hidden: true),
        new("Findings", "Findings in this collection", GridType.Number, GridFilter.Range),
        new("FirstSeen", "First seen", GridType.Date, GridFilter.Dates),
    }, "Rank", false, "IssueKey", ["CollectionId", "Keys"], Immutable: false));

    /// #290: the issues of a collection, by key -- what a Top critical findings selection is read back through.
    public static readonly GridSpec IssueKeys = GridSql.Check(new GridSpec("issuekeys", "", $"""
SELECT COALESCE(f.ConfigurationId, f.Cve) AS IssueKey, COUNT_BIG(*) AS Findings
FROM sidata.Finding AS f
WHERE {ThisCollection} AND COALESCE(f.ConfigurationId, f.Cve) IS NOT NULL
GROUP BY COALESCE(f.ConfigurationId, f.Cve)
""", new GridColumn[]
    {
        new("IssueKey", "Issue", Filter: GridFilter.Contains, Search: true),
        new("Findings", "Findings", GridType.Number, GridFilter.Range),
    }, "Findings", true, "IssueKey", ["CollectionId"], Immutable: true));

    // ---- (11) exemptions and their state at the collection time -----------------------------------------------------

    public static readonly GridSpec Exemptions = GridSql.Check(new GridSpec("exemptions", "", """
SELECT CONVERT(nvarchar(64), e.ExemptionId) AS ExemptionId, e.Scope, e.ReportName, COALESCE(e.Cve, e.ConfigurationId) AS Issue,
       e.AssetKey, a.AssetName, e.Reason, e.CreatedBy, e.CreatedAt, e.ExpiresAt, e.RevokedAt,
       CASE WHEN e.CreatedAt > @At THEN N'created later'
            WHEN e.RevokedAt IS NOT NULL AND e.RevokedAt <= @At THEN N'revoked before'
            WHEN e.ExpiresAt IS NOT NULL AND e.ExpiresAt <= @At THEN N'expired before'
            ELSE N'in force' END AS StateAtCollection
FROM cfg.Exemption AS e
LEFT JOIN sidata.Asset AS a ON a.AssetKey = e.AssetKey
""", new GridColumn[]
    {
        new("ExemptionId", "Id"),
        new("StateAtCollection", "At this collection", Filter: GridFilter.Values),
        new("Scope", "Scope", Filter: GridFilter.Values),
        new("Issue", "Issue", Filter: GridFilter.Contains, Search: true),
        new("AssetName", "Asset", Filter: GridFilter.Contains, Search: true),
        new("AssetKey", "Asset key", Search: true, Hidden: true),
        new("ReportName", "Report", Filter: GridFilter.Values, Search: true),
        new("Reason", "Reason", Filter: GridFilter.Contains, Search: true),
        new("CreatedBy", "By", Filter: GridFilter.Contains),
        new("CreatedAt", "Created", GridType.Date, GridFilter.Dates),
        new("ExpiresAt", "Expires", GridType.Date, GridFilter.Dates),
        new("RevokedAt", "Revoked", GridType.Date, GridFilter.Dates),
    }, "CreatedAt", true, "ExemptionId", ["At"], Immutable: false));

    public const string ExemptionStates = """
SELECT CASE WHEN e.CreatedAt > @At THEN N'created later'
            WHEN e.RevokedAt IS NOT NULL AND e.RevokedAt <= @At THEN N'revoked before'
            WHEN e.ExpiresAt IS NOT NULL AND e.ExpiresAt <= @At THEN N'expired before'
            ELSE N'in force' END AS State, e.Scope, COUNT_BIG(*) AS N
FROM cfg.Exemption AS e
GROUP BY CASE WHEN e.CreatedAt > @At THEN N'created later'
              WHEN e.RevokedAt IS NOT NULL AND e.RevokedAt <= @At THEN N'revoked before'
              WHEN e.ExpiresAt IS NOT NULL AND e.ExpiresAt <= @At THEN N'expired before'
              ELSE N'in force' END, e.Scope;
""";

    /// The Risk Analysis exclusion documents (current), one row per report key -- the rules, not the hidden rows.
    public const string ExclusionDocuments = """
SELECT d.[Key] AS DocKey, d.UpdatedAt, d.UpdatedBy, LEN(d.Body) AS BodyLength
FROM cfg.Document AS d
WHERE d.Kind = N'exclusions'
ORDER BY d.[Key];
""";

    // ---- (12) lifecycle: the close-loop events in the window of this collection ------------------------------------

    public static readonly GridSpec Events = GridSql.Check(new GridSpec("events", "", """
SELECT CONVERT(nvarchar(64), e.EventId) AS EventId, e.[At], e.Action, e.FromState, e.ToState, e.Reason, e.RunId, e.Actor,
       i.Cve, i.AssetName, i.Severity, i.CorrelationId
FROM vuln.VulnerabilityEvent AS e
JOIN vuln.VulnerabilityItem AS i ON i.SysId = e.SysId
WHERE e.[At] >= @From AND e.[At] < @To AND e.Action <> N'Seen'
""", new GridColumn[]
    {
        new("EventId", "Id", Hidden: true),
        new("At", "When", GridType.Date, GridFilter.Dates),
        new("Action", "Change", Filter: GridFilter.Values),
        new("Cve", "CVE", Filter: GridFilter.Contains, Search: true),
        new("AssetName", "Asset", Filter: GridFilter.Contains, Search: true),
        new("Severity", "Severity", Filter: GridFilter.Values),
        new("FromState", "From"),
        new("ToState", "To"),
        new("Reason", "Reason", Filter: GridFilter.Contains, Search: true),
        new("Actor", "By", Filter: GridFilter.Values),
        new("RunId", "Run", Hidden: true),
        new("CorrelationId", "Asset key", Search: true, Hidden: true),
    }, "At", true, "EventId", ["From", "To"], Immutable: false));

    /// Per action in the window (Seen included -- the grid leaves it out), and the daily statistics around it.
    public const string EventCounts = """
SELECT e.Action, COUNT_BIG(*) AS N
FROM vuln.VulnerabilityEvent AS e
WHERE e.[At] >= @From AND e.[At] < @To
GROUP BY e.Action;
""";

    public const string LifecycleDays = """
SELECT v.[Day], v.Opened, v.Closed, v.Reopened, v.OpenAtEndOfDay
FROM sidata.VulnLifecycleDaily AS v
WHERE v.[Day] >= @Since AND v.[Day] <= @Until
ORDER BY v.[Day];
""";

    // ---- (13) what changed between two collections -----------------------------------------------------------------

    /// One row per finding of a collection. IdKey is what makes two collections' findings the SAME finding: the CI key, or
    /// -- for a row published without one (an Azure recommendation on a resource outside the asset inventory) -- the asset
    /// NAME. Keyed on an empty key instead, every such asset with the same recommendation was ONE row: four virtual networks
    /// read as one finding, and one of them losing it was invisible while the others kept it. AssetKey stays the real key
    /// (empty when there is none) for the links and the "absent" reason.
    private static string Keyed(string alias, string param) => $"""
{alias} AS (
    SELECT COALESCE(f.AssetKey, N'name:' + LOWER(COALESCE(f.AssetName, N''))) AS IdKey, MAX(COALESCE(f.AssetKey, N'')) AS AssetKey,
           COALESCE(f.Cve, f.ConfigurationId, f.Title, N'') AS IssueKey, COALESCE(f.ReportName, N'') AS ReportName,
           COALESCE(MAX(an.AssetName), MAX(f.AssetName)) AS AssetName, MAX(f.Title) AS Title, MAX(f.Severity) AS Severity, MAX(f.RiskScore) AS RiskScore,
           MIN(f.Tier) AS Tier, MAX(f.RiskRating) AS RiskRating
    FROM sidata.Finding AS f
    LEFT JOIN sidata.Asset AS an ON an.AssetKey = f.AssetKey
    WHERE f.CollectionId = TRY_CONVERT(int, @{param})
    GROUP BY COALESCE(f.AssetKey, N'name:' + LOWER(COALESCE(f.AssetName, N''))), COALESCE(f.Cve, f.ConfigurationId, f.Title, N''), COALESCE(f.ReportName, N'')
)
""";

    /// The change rule (the data sync's SI-DataChanges.ps1 carries the same text -- a test holds them equal).
    public const string ChangeCase = """
CASE WHEN ka.IssueKey IS NULL THEN N'new'
     WHEN kb.IssueKey IS NULL THEN N'gone'
     WHEN ISNULL(ka.Severity, N'') <> ISNULL(kb.Severity, N'') OR ISNULL(ka.RiskScore, -1) <> ISNULL(kb.RiskScore, -1)
       OR ISNULL(ka.Tier, 255) <> ISNULL(kb.Tier, 255) OR ISNULL(ka.RiskRating, N'') <> ISNULL(kb.RiskRating, N'') THEN N'changed'
     ELSE N'unchanged' END
""";

    /// <summary>
    /// The finding comparison of two collections. A finding missing from B is NEVER read as fixed (absence is not
    /// remediation): its Change stays the code 'gone' (the stored / URL / export-filter contract; the web app shows it as
    /// "No longer reported") and ChangeReason says what the same read can prove -- 'absent' = the asset IS in B with other
    /// findings, but not this one; 'exempted' = B still reports it, under an exemption, and the read leaves exempted
    /// findings out (only in <see cref="FindingChangesExcluding"/>: the mark exists only where the database has it);
    /// NULL = nothing more is known (the asset has no finding in B: gone, out of scope, clean or not collected look the
    /// same here). The side a row does not have (before of a new finding, after of a gone one) is NULL, never "Unclassified".
    /// </summary>
    private static GridSpec FindingChangesSpec(bool excluding) => GridSql.Check(new GridSpec("findingchanges", Keyed("ka", "A") + ",\n" + Keyed("kb", "B") + """
,
kbasset AS (
    SELECT kb.AssetKey FROM kb GROUP BY kb.AssetKey
)
""", $"""
SELECT COALESCE(kb.IdKey, ka.IdKey) + N'|' + COALESCE(kb.IssueKey, ka.IssueKey) + N'|' + COALESCE(kb.ReportName, ka.ReportName) AS ChangeKey,
       {ChangeCase} AS Change,
       CASE WHEN kb.IssueKey IS NOT NULL OR ka.IssueKey IS NULL THEN NULL{(excluding ? ExemptedInB : "")}
            WHEN kba.AssetKey IS NOT NULL AND ka.AssetKey <> N'' THEN N'absent' ELSE NULL END AS ChangeReason,
       COALESCE(kb.AssetKey, ka.AssetKey) AS AssetKey, COALESCE(kb.AssetName, ka.AssetName) AS AssetName,
       COALESCE(kb.IssueKey, ka.IssueKey) AS Issue, COALESCE(kb.Title, ka.Title) AS Title, COALESCE(kb.ReportName, ka.ReportName) AS ReportName,
       ka.Severity AS SeverityBefore, kb.Severity AS SeverityAfter, ka.RiskScore AS RiskBefore, kb.RiskScore AS RiskAfter,
       COALESCE(kb.RiskScore, 0) - COALESCE(ka.RiskScore, 0) AS RiskDelta,
       CASE WHEN ka.IssueKey IS NULL THEN NULL ELSE {ProDataSql.TierExpr("ka.Tier")} END AS TierBefore,
       CASE WHEN kb.IssueKey IS NULL THEN NULL ELSE {ProDataSql.TierExpr("kb.Tier")} END AS TierAfter
FROM ka
FULL OUTER JOIN kb ON kb.IdKey = ka.IdKey AND kb.IssueKey = ka.IssueKey AND kb.ReportName = ka.ReportName
LEFT JOIN kbasset AS kba ON kba.AssetKey = ka.AssetKey
""", new GridColumn[]
    {
        new("ChangeKey", "Key", Hidden: true),
        new("Change", "Change", Filter: GridFilter.Values),
        new("ChangeReason", "Why", Hidden: true),
        new("AssetName", "Asset", Filter: GridFilter.Contains, Search: true),
        new("AssetKey", "Asset key", Search: true, Hidden: true),
        new("Issue", "Issue", Filter: GridFilter.Contains, Search: true),
        new("Title", "Finding", Filter: GridFilter.Contains, Search: true),
        new("ReportName", "Report", Filter: GridFilter.Values),
        new("SeverityBefore", "Severity before"),
        new("SeverityAfter", "Severity after", Filter: GridFilter.Values),
        new("RiskBefore", "Risk before", GridType.Number),
        new("RiskAfter", "Risk after", GridType.Number, GridFilter.Range),
        new("RiskDelta", "Risk change", GridType.Number, GridFilter.Range),
        new("TierBefore", "Tier before", GridType.Tier),
        new("TierAfter", "Tier after", GridType.Tier, GridFilter.Values),
    }, "RiskDelta", true, "ChangeKey", ["A", "B"], Immutable: true));

    /// A finding missing from the counted rows of B that B still holds with an exemption mark. The alias starts with
    /// "ex_", so <see cref="Exempted.Exclude(string)"/> never rewrites it into the counted rows.
    public const string ExemptedInB = """

            WHEN EXISTS (SELECT 1 FROM sidata.Finding AS ex_xb
                         WHERE ex_xb.CollectionId = TRY_CONVERT(int, @B) AND ex_xb.ExemptionId IS NOT NULL
                           AND COALESCE(ex_xb.AssetKey, N'') = ka.AssetKey AND COALESCE(ex_xb.Cve, ex_xb.ConfigurationId, ex_xb.Title, N'') = ka.IssueKey
                           AND COALESCE(ex_xb.ReportName, N'') = ka.ReportName) THEN N'exempted'
""";

    /// The finding comparison of two collections (see <see cref="FindingChangesSpec"/>).
    public static readonly GridSpec FindingChanges = FindingChangesSpec(excluding: false);
    /// The same for a read that leaves exempted findings out: a finding B still reports under an exemption says so
    /// ('exempted') instead of reading as no longer reported. Used only when that read is in force (the mark then exists).
    public static readonly GridSpec FindingChangesExcluding = FindingChangesSpec(excluding: true);

    private static string AssetSet(string alias, string param) => $"""
{alias} AS (
    SELECT f.AssetKey, COALESCE(MAX(an.AssetName), MAX(f.AssetName)) AS AssetName, COUNT_BIG(*) AS Findings, SUM(f.RiskScore) AS TotalRisk, MIN(f.Tier) AS Tier
    FROM sidata.Finding AS f
    LEFT JOIN sidata.Asset AS an ON an.AssetKey = f.AssetKey
    WHERE f.CollectionId = TRY_CONVERT(int, @{param}) AND f.AssetKey IS NOT NULL
    GROUP BY f.AssetKey
)
""";

    public static readonly GridSpec AssetChanges = GridSql.Check(new GridSpec("assetchanges", AssetSet("aa", "A") + ",\n" + AssetSet("ab", "B"), $"""
SELECT COALESCE(ab.AssetKey, aa.AssetKey) AS AssetKey, COALESCE(ab.AssetName, aa.AssetName) AS AssetName,
       CASE WHEN aa.AssetKey IS NULL THEN N'new' WHEN ab.AssetKey IS NULL THEN N'gone'
            WHEN aa.Findings <> ab.Findings OR ISNULL(aa.TotalRisk, -1) <> ISNULL(ab.TotalRisk, -1) OR ISNULL(aa.Tier, 255) <> ISNULL(ab.Tier, 255) THEN N'changed'
            ELSE N'unchanged' END AS Change,
       aa.Findings AS FindingsBefore, ab.Findings AS FindingsAfter, aa.TotalRisk AS RiskBefore, ab.TotalRisk AS RiskAfter,
       COALESCE(ab.TotalRisk, 0) - COALESCE(aa.TotalRisk, 0) AS RiskDelta,
       CASE WHEN aa.AssetKey IS NULL THEN NULL ELSE {ProDataSql.TierExpr("aa.Tier")} END AS TierBefore,
       CASE WHEN ab.AssetKey IS NULL THEN NULL ELSE {ProDataSql.TierExpr("ab.Tier")} END AS TierAfter
FROM aa
FULL OUTER JOIN ab ON ab.AssetKey = aa.AssetKey
""", new GridColumn[]
    {
        new("AssetKey", "Asset (CI) key", Search: true, Hidden: true),
        new("Change", "Change", Filter: GridFilter.Values),
        new("AssetName", "Asset (CI)", Filter: GridFilter.Contains, Search: true),
        new("FindingsBefore", "Findings before", GridType.Number),
        new("FindingsAfter", "Findings after", GridType.Number, GridFilter.Range),
        new("RiskBefore", "Risk before", GridType.Number),
        new("RiskAfter", "Risk after", GridType.Number),
        new("RiskDelta", "Risk change", GridType.Number, GridFilter.Range),
        new("TierBefore", "Tier before", GridType.Tier),
        new("TierAfter", "Tier after", GridType.Tier, GridFilter.Values),
    }, "RiskDelta", true, "AssetKey", ["A", "B"], Immutable: true));

    // 🔑 #772 (2026-10-19, a large customer, 1,117,524 finding rows per collection): the comparison above grouped EVERY finding
    // of BOTH collections per request (and the headline twice more). The data sync now writes it once per collection B against
    // the previous listed collection A (engine\pro-data\_shared\SI-DataChanges.ps1): sidata.FindingChange (new / gone /
    // changed -- an unchanged finding is counted, not listed), sidata.AssetChange (every CI), sidata.ChangeCount and their
    // counted twins (#264: exempted findings left out on both sides, 'exempted' reasons included), sidata.ChangeState (the
    // pair). The page reads THOSE rows -- same columns, same codes -- for the pair the data sync wrote; another pair says it
    // is not prepared. The live forms above stay as the reference the equality check compares with.

    /// The stored finding comparison of B (@B) with A (@A) -- the counted twin when exempted findings are left out.
    public static readonly GridSpec FindingChangesStored = GridSql.Check(FindingChanges with
    {
        Ctes = "",
        Source = """
SELECT fc.ChangeKey, fc.Change, fc.ChangeReason, fc.AssetKey, fc.AssetName, fc.Issue, fc.Title, fc.ReportName,
       fc.SeverityBefore, fc.SeverityAfter, fc.RiskBefore, fc.RiskAfter, fc.RiskDelta, fc.TierBefore, fc.TierAfter
FROM sidata.FindingChange AS fc
WHERE fc.CollectionId = TRY_CONVERT(int, @B) AND fc.PrevCollectionId = TRY_CONVERT(int, @A)
""",
    });

    /// The stored CI comparison of B with A (every CI).
    public static readonly GridSpec AssetChangesStored = GridSql.Check(AssetChanges with
    {
        Ctes = "",
        Source = """
SELECT ac.AssetKey, ac.AssetName, ac.Change, ac.FindingsBefore, ac.FindingsAfter, ac.RiskBefore, ac.RiskAfter, ac.RiskDelta, ac.TierBefore, ac.TierAfter
FROM sidata.AssetChange AS ac
WHERE ac.CollectionId = TRY_CONVERT(int, @B) AND ac.PrevCollectionId = TRY_CONVERT(int, @A)
""",
    });

    /// The stored headline of B against A (findings and CIs per change, unchanged included).
    public const string ChangeSummaryStored = """
SELECT s.What, s.Change, s.N
FROM sidata.ChangeCount AS s
WHERE s.CollectionId = TRY_CONVERT(int, @B) AND s.PrevCollectionId = TRY_CONVERT(int, @A);
""";

    /// Which pair the data sync wrote for B, and when (no row = not yet). A database without the table answers "Invalid object
    /// name" -- the page then says the update adds it.
    public const string ChangeStateSql = """
SELECT CONVERT(nvarchar(64), s.PrevCollectionId) AS PrevCollectionId, s.BuiltAt, s.FindingRows
FROM sidata.ChangeState AS s
WHERE s.CollectionId = TRY_CONVERT(int, @B);
""";

    /// The headline of a comparison: findings and CIs new / gone / changed / unchanged. One statement, two scans.
    public static readonly string ChangeSummary = $"""
WITH {Keyed("ka", "A")},
{Keyed("kb", "B")},
{AssetSet("aa", "A")},
{AssetSet("ab", "B")},
fc AS (
    SELECT {ChangeCase} AS Change
    FROM ka
    FULL OUTER JOIN kb ON kb.IdKey = ka.IdKey AND kb.IssueKey = ka.IssueKey AND kb.ReportName = ka.ReportName
), ac AS (
    SELECT CASE WHEN aa.AssetKey IS NULL THEN N'new' WHEN ab.AssetKey IS NULL THEN N'gone'
                WHEN aa.Findings <> ab.Findings OR ISNULL(aa.TotalRisk, -1) <> ISNULL(ab.TotalRisk, -1) OR ISNULL(aa.Tier, 255) <> ISNULL(ab.Tier, 255) THEN N'changed'
                ELSE N'unchanged' END AS Change
    FROM aa
    FULL OUTER JOIN ab ON ab.AssetKey = aa.AssetKey
)
SELECT N'findings' AS What, fc.Change, COUNT_BIG(*) AS N FROM fc GROUP BY fc.Change
UNION ALL
SELECT N'assets', ac.Change, COUNT_BIG(*) FROM ac GROUP BY ac.Change;
""";

    // ---- (14) connector changes in the window of this collection -----------------------------------------------------

    public static readonly GridSpec ConnectorRuns = GridSql.Check(new GridSpec("connectorruns", "", """
SELECT CONVERT(nvarchar(64), r.ConnectorRunId) AS ConnectorRunId, r.ConnectorName, r.Kind, r.Mode, r.Outcome, r.StartedAt, r.EndedAt,
       r.PlanOpen, r.PlanReopen, r.PlanUpdate, r.PlanClose, r.Held, r.Opened, r.Reopened, r.Updated, r.Closed, r.Errors, r.NotSent, r.Unchanged, COALESCE(r.HaltReason, r.Error) AS HaltReason, r.RunId
FROM cfg.ConnectorRun AS r
WHERE r.StartedAt >= @From AND r.StartedAt < @To
""", new GridColumn[]
    {
        new("ConnectorRunId", "Id", Hidden: true),
        new("StartedAt", "Started", GridType.Date, GridFilter.Dates),
        new("ConnectorName", "Connector", Filter: GridFilter.Values, Search: true),
        new("Kind", "Kind", Filter: GridFilter.Values),
        new("Mode", "Mode", Filter: GridFilter.Values),
        new("Outcome", "Outcome", Filter: GridFilter.Values),
        new("PlanOpen", "Plan: open", GridType.Number),
        new("PlanReopen", "Plan: reopen", GridType.Number),
        new("PlanUpdate", "Plan: update", GridType.Number),
        new("PlanClose", "Plan: close", GridType.Number),
        new("Held", "Held", GridType.Number),
        new("Opened", "Opened", GridType.Number),
        new("Reopened", "Reopened", GridType.Number),
        new("Updated", "Updated", GridType.Number),
        new("Closed", "Closed", GridType.Number),
        new("Errors", "Errors", GridType.Number, GridFilter.Range),
        new("NotSent", "Not sent", GridType.Number),
        new("Unchanged", "Unchanged", GridType.Number),
        new("HaltReason", "Why", Filter: GridFilter.Contains, Search: true),
        new("EndedAt", "Ended", GridType.Date, GridFilter.Dates, Hidden: true),
        new("RunId", "Run", Search: true, Hidden: true),
    }, "StartedAt", true, "ConnectorRunId", ["From", "To"], Immutable: false));

    /// #429 -- THE ITEM CHANGE LOG (cfg.ConnectorChange): one row per field a connector changed on one item -- the time the
    /// connector wrote that item (UTC, shown in the viewer's zone), the SecurityInsight object, the target record, the field,
    /// its value before and now, and the action. An item with no field (a failure, a staged row) is one row without a field.
    public static readonly GridSpec ConnectorItems = GridSql.Check(new GridSpec("connectoritems", "", """
SELECT CONVERT(nvarchar(30), c.ChangeId) AS ItemKey, c.ChangedAt, c.ConnectorName, c.Action,
       c.ObjectName AS AssetName, c.ObjectKey AS CorrelationId, c.Finding AS Cve,
       CONCAT(c.TargetTable, CASE WHEN c.TargetKey IS NULL THEN N'' ELSE N' / ' + c.TargetKey END) AS TargetRecord,
       c.Field, c.ValueBefore, c.ValueNow, c.Reason, c.Error, c.RunId
FROM cfg.ConnectorChange AS c
WHERE c.ChangedAt >= @From AND c.ChangedAt < @To
""", new GridColumn[]
    {
        new("ItemKey", "Key", Hidden: true),
        new("ChangedAt", "Time", GridType.Date, GridFilter.Dates),
        new("AssetName", "Object", Filter: GridFilter.Contains, Search: true),
        new("CorrelationId", "Object id", Filter: GridFilter.Contains, Search: true, Hidden: true),
        new("Cve", "Finding", Filter: GridFilter.Contains, Search: true),
        new("TargetRecord", "Target record", Filter: GridFilter.Contains, Search: true),
        new("Field", "Field", Filter: GridFilter.Contains, Search: true),
        new("ValueBefore", "Before", Filter: GridFilter.Contains, Search: true),
        new("ValueNow", "Now", Filter: GridFilter.Contains, Search: true),
        new("Action", "Action", Filter: GridFilter.Values),
        new("ConnectorName", "Connector", Filter: GridFilter.Values),
        new("Reason", "Why", Filter: GridFilter.Contains, Search: true),
        new("Error", "Error", Filter: GridFilter.Contains, Search: true),
        new("RunId", "Run", Search: true, Hidden: true),
    }, "ChangedAt", true, "ItemKey", ["From", "To"], Immutable: false));

    /// #429 -- the actions the item change log records (the Action filter's values).
    public static readonly IReadOnlyList<string> ConnectorActions =
    [
        "opened", "reopened", "updated", "closed", "absence counted", "moved", "retired", "created", "reactivated", "written",
        "not opened", "not reopened", "not updated", "not closed", "not written",
    ];

    /// #429 -- EVERY registered connector, even with no run in the window: the cfg.Connector rows, the built-in connectors that
    /// write outside SecurityInsight (they have no cfg.Connector row) and any name that ran in the window.
    public const string ConnectorTotals = """
WITH n AS (
    SELECT x.ConnectorName, MAX(x.Kind) AS Kind, MAX(x.Direction) AS Direction, MAX(x.Enabled) AS Enabled
    FROM (
        SELECT c.Name AS ConnectorName, c.Kind, c.Direction, CAST(c.Enabled AS int) AS Enabled FROM cfg.Connector AS c
        UNION ALL
        SELECT v.Name, v.Kind, v.Direction, 1 FROM (VALUES (N'asset-cmdb-sql', N'sql', N'cmdb'), (N'asset-cmdb', N'servicenow', N'cmdb'),
                                                         (N'asset-tagging', N'defender-azure-entra', N'tags')) AS v(Name, Kind, Direction)
        UNION ALL
        SELECT r0.ConnectorName, r0.Kind, NULL, 1 FROM cfg.ConnectorRun AS r0 WHERE r0.StartedAt >= @From AND r0.StartedAt < @To
    ) AS x
    GROUP BY x.ConnectorName
)
SELECT n.ConnectorName, n.Kind, n.Direction, n.Enabled, COUNT_BIG(r.ConnectorRunId) AS Runs, ISNULL(SUM(r.Opened), 0) AS Opened,
       ISNULL(SUM(r.Reopened), 0) AS Reopened, ISNULL(SUM(r.Updated), 0) AS Updated, ISNULL(SUM(r.Closed), 0) AS Closed,
       ISNULL(SUM(r.Errors), 0) AS Errors, MAX(r.StartedAt) AS LastRun,
       (SELECT MAX(r2.StartedAt) FROM cfg.ConnectorRun AS r2 WHERE r2.ConnectorName = n.ConnectorName) AS LastRunEver,
       (SELECT TOP (1) COALESCE(r3.HaltReason, r3.Error) FROM cfg.ConnectorRun AS r3 WHERE r3.ConnectorName = n.ConnectorName ORDER BY r3.StartedAt DESC) AS LastWhy
FROM n
LEFT JOIN cfg.ConnectorRun AS r ON r.ConnectorName = n.ConnectorName AND r.StartedAt >= @From AND r.StartedAt < @To
GROUP BY n.ConnectorName, n.Kind, n.Direction, n.Enabled
ORDER BY n.ConnectorName;
""";

    // ---- (3) one CI: everything known about it ------------------------------------------------------------------------

    public const string Asset = """
SELECT a.AssetKey, a.AssetName, a.AssetKind, a.Tier AS TierRaw, a.KeySource, a.FirstSeen, a.LastSeen, a.UpdatedAt, a.PropertiesJson
FROM sidata.Asset AS a
WHERE a.AssetKey = @AssetKey;
""";

    public const string AssetIdentifiers = """
SELECT ai.IdentifierType, ai.IdentifierValue, ai.FirstSeen, ai.LastSeen
FROM sidata.AssetIdentifier AS ai
WHERE ai.AssetKey = @AssetKey
ORDER BY ai.IdentifierType, ai.IdentifierValue;
""";

    public const string AssetRecommendations = """
SELECT TOP (200) r.RecommendationId, r.Name, r.Severity
FROM sidata.Recommendation AS r
WHERE r.CollectionId = TRY_CONVERT(int, @CollectionId) AND r.AssetKey = @AssetKey
ORDER BY r.Severity, r.Name;
""";

    /// The CI's findings per collection (newest 30): its history, from the (AssetKey, CollectionId) index -- never past
    /// the published run.
    public const string AssetHistory = $"""
SELECT TOP (30) CONVERT(nvarchar(64), col.CollectionId) AS CollectionId, col.CollectionTime, h.Findings, h.TotalRisk, h.MaxRisk
FROM (
    SELECT f.CollectionId, COUNT_BIG(*) AS Findings, SUM(f.RiskScore) AS TotalRisk, MAX(f.RiskScore) AS MaxRisk
    FROM sidata.Finding AS f
    WHERE f.AssetKey = @AssetKey
    GROUP BY f.CollectionId
) AS h
JOIN sidata.Collection AS col ON col.CollectionId = h.CollectionId AND col.Status = N'Complete'
WHERE col.CollectionTime <= ISNULL({PublishedRun.DetailedTime}, col.CollectionTime)
ORDER BY col.CollectionTime DESC;
""";

    /// The close-loop's items of this CI: the key set (the CI key and every identifier it carries) is built ONCE and
    /// joined on the item's correlation id -- never an OR per item.
    public const string AssetVulnItems = """
WITH k AS (
    SELECT @AssetKey AS K
    UNION
    SELECT ai.IdentifierValue FROM sidata.AssetIdentifier AS ai WHERE ai.AssetKey = @AssetKey
)
SELECT TOP (500) i.Cve, i.Severity, i.State, i.FirstSeen, i.LastSeen, i.ClosedAt, i.CloseReason
FROM vuln.VulnerabilityItem AS i
JOIN k ON k.K = i.CorrelationId
WHERE i.Source = @Source
ORDER BY CASE WHEN i.State = N'Open' THEN 0 ELSE 1 END, i.Cve;
""";

    // ---- (15) services: the CMDB business services, ranked by weighted risk (#255) ------------------------------------
    // Read from the data sync's per-collection aggregates (sidata.ServiceRisk / ServiceAsset), never a GROUP BY over the
    // finding rows. Which service(s) a CI belongs to is decided by the data sync's ONE membership resolver; a CI in
    // several services is a row under each. The no-service row is stored with ServiceKey N'' and shown with NoServiceKey.

    /// The key the no-service row carries in a URL and a selection (stored as N'').
    public const string NoServiceKey = "~none";
    public const string NoServiceName = "(no service)";
    private const string StoredService = "CASE WHEN @Service = N'" + NoServiceKey + "' THEN N'' ELSE @Service END";

    public static readonly GridSpec Services = GridSql.Check(new GridSpec("services", "", $"""
SELECT CASE WHEN sr.ServiceKey = N'' THEN N'{NoServiceKey}' ELSE sr.ServiceKey END AS ServiceKey,
       CASE WHEN sr.ServiceKey = N'' THEN N'{NoServiceName}' ELSE COALESCE(sr.ServiceName, sr.ServiceKey) END AS ServiceName,
       sr.Assets, sr.SharedAssets, sr.Findings, sr.WeightedTotal AS WeightedRisk, sr.WeightedPerAsset AS WeightedRiskPerAsset, sr.RiskTotal, sr.MaxWeighted AS MaxWeightedRisk,
       sr.Critical, sr.High, sr.Medium, sr.Low, sr.Tier0, sr.Tier1, sr.Tier2, sr.Tier3, sr.TierUnclassified,
       sr.TopAssetKey, sr.TopAssetName, sr.TopAssetWeighted AS TopAssetWeightedRisk, sr.Sources
FROM sidata.ServiceRisk AS sr
WHERE sr.CollectionId = TRY_CONVERT(int, @CollectionId)
""", new GridColumn[]
    {
        new("ServiceKey", "Service id", Filter: GridFilter.Contains, Search: true),
        new("ServiceName", "Service", Filter: GridFilter.Contains, Search: true),
        new("WeightedRisk", "Weighted risk", GridType.Number, GridFilter.Range),
        new("WeightedRiskPerAsset", "Weighted per asset", GridType.Number, GridFilter.Range),
        new("Assets", "Assets", GridType.Number, GridFilter.Range),
        new("SharedAssets", "Also in another service", GridType.Number, GridFilter.Range),
        new("Findings", "Findings", GridType.Number, GridFilter.Range),
        new("Critical", "Very High", GridType.Number, GridFilter.Range),
        new("High", "High", GridType.Number, GridFilter.Range),
        new("Medium", "Medium", GridType.Number, GridFilter.Range),
        new("Low", "Low", GridType.Number, GridFilter.Range),
        new("Tier0", "On tier 0", GridType.Number, GridFilter.Range),
        new("Tier1", "On tier 1", GridType.Number, GridFilter.Range),
        new("Tier2", "On tier 2", GridType.Number),
        new("Tier3", "On tier 3", GridType.Number),
        new("TierUnclassified", "Unclassified", GridType.Number),
        new("TopAssetName", "Highest-risk asset", Filter: GridFilter.Contains, Search: true),
        new("TopAssetWeightedRisk", "Its weighted risk", GridType.Number),
        new("TopAssetKey", "Highest-risk asset key", Hidden: true),
        new("RiskTotal", "Risk (unweighted)", GridType.Number, Hidden: true),
        new("MaxWeightedRisk", "Highest finding (weighted)", GridType.Number, Hidden: true),
        new("Sources", "Placed by", Filter: GridFilter.Contains, Hidden: true),
    }, "WeightedRisk", true, "ServiceKey", ["CollectionId"], Immutable: true));

    /// The CIs of ONE service (or of no service) in the collection: the drill-down service -> its assets.
    public static readonly GridSpec ServiceAssets = GridSql.Check(new GridSpec("serviceassets", "", $"""
SELECT sa.AssetKey, COALESCE(sa.AssetName, a.AssetName, sa.AssetKey) AS AssetName, a.AssetKind, {ProDataSql.AssetKindsExpr("a")} AS AssetKinds, {ProDataSql.TierExpr("sa.Tier")} AS Tier,
       sa.ServiceCount, sa.Findings, sa.Critical, sa.High, sa.Medium, sa.Low, sa.WeightedTotal AS WeightedRisk, sa.RiskTotal, sa.MaxWeighted AS MaxWeightedRisk, sa.Source
FROM sidata.ServiceAsset AS sa
LEFT JOIN sidata.Asset AS a ON a.AssetKey = sa.AssetKey
WHERE sa.CollectionId = TRY_CONVERT(int, @CollectionId)
  AND sa.ServiceKey = {StoredService}
""", new GridColumn[]
    {
        new("AssetKey", "Asset (CI) key", Search: true, Hidden: true),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        new("AssetName", "Asset", Filter: GridFilter.Contains, Search: true),
        GridColumn.AssetKind(),
        new("WeightedRisk", "Weighted risk", GridType.Number, GridFilter.Range),
        new("Findings", "Findings", GridType.Number, GridFilter.Range),
        new("Critical", "Very High", GridType.Number, GridFilter.Range),
        new("High", "High", GridType.Number, GridFilter.Range),
        new("Medium", "Medium", GridType.Number, GridFilter.Range),
        new("Low", "Low", GridType.Number, GridFilter.Range),
        new("MaxWeightedRisk", "Highest finding (weighted)", GridType.Number, GridFilter.Range),
        new("ServiceCount", "Services it is in", GridType.Number, GridFilter.Range),
        new("RiskTotal", "Risk (unweighted)", GridType.Number, Hidden: true),
        new("Source", "Placed by", Filter: GridFilter.Values),
    }, "WeightedRisk", true, "AssetKey", ["CollectionId", "Service"], Immutable: true));

    /// Whether the collection's services are computed, how many there are, how many CIs are in no service.
    public const string ServicesStatus = """
SELECT c.ServicesDerivedAt, SUM(CASE WHEN sr.ServiceKey <> N'' THEN 1 ELSE 0 END) AS Services,
       SUM(CASE WHEN sr.ServiceKey = N'' THEN sr.Assets ELSE 0 END) AS UnplacedAssets
FROM sidata.Collection AS c
LEFT JOIN sidata.ServiceRisk AS sr ON sr.CollectionId = c.CollectionId
WHERE c.CollectionId = TRY_CONVERT(int, @CollectionId)
GROUP BY c.ServicesDerivedAt;
""";

    /// One service's row (the head of its drill-down).
    public static readonly string Service = $"""
SELECT CASE WHEN sr.ServiceKey = N'' THEN N'{NoServiceKey}' ELSE sr.ServiceKey END AS ServiceKey,
       CASE WHEN sr.ServiceKey = N'' THEN N'{NoServiceName}' ELSE COALESCE(sr.ServiceName, sr.ServiceKey) END AS ServiceName,
       sr.Assets, sr.SharedAssets, sr.Findings, sr.WeightedTotal, sr.WeightedPerAsset, sr.Critical, sr.High, sr.Medium, sr.Low,
       sr.Tier0, sr.Tier1, sr.Tier2, sr.Tier3, sr.TierUnclassified, sr.TopAssetKey, sr.TopAssetName, sr.TopAssetWeighted, sr.Sources
FROM sidata.ServiceRisk AS sr
WHERE sr.CollectionId = TRY_CONVERT(int, @CollectionId) AND sr.ServiceKey = {StoredService};
""";

    /// A service key from a URL: free text (CMDB numbers, names), no control characters, at most the stored width.
    public static string ServiceKey(string? v)
    {
        var t = ProDataFilters.Text(v) ?? throw new ArgumentException("a service is required");
        return t.Length <= 256 ? t : throw new ArgumentException("the service key is longer than 256 characters");
    }

    /// Every statement a view can run, for the read-only / parameter / no-APPLY tests.
    public static IEnumerable<GridSpec> Grids => [Rows, Assets, AssetRisk, Vulnerabilities, Exemptions, Events, FindingChanges, AssetChanges, ConnectorRuns, ConnectorItems, Services, ServiceAssets];
}
