namespace SI.Management.Core.ProData;

/// <summary>
/// The fixed, read-only statements over the Pro data backend (schema <c>sidata</c>, REQUIREMENTS §9.3.4 data contract)
/// and the close-loop schema <c>vuln</c>. Rules every builder keeps:
///   * the text is a constant; the only variable part is a sort fragment picked from <see cref="Sorts"/> by a whitelisted key;
///   * every caller value is a parameter (validated first by <see cref="ProDataFilters"/>);
///   * every statement starts with SELECT or WITH and carries no write verb, so the MCP server's read-only guard
///     (<see cref="SqlGuard"/>) accepts it unchanged;
///   * dashboards read only the pre-computed tables (sidata.FindingDaily, sidata.VulnLifecycleDaily); finding rows are
///     read for ONE collection at a time (browser, drill-down, top 50).
/// Ids whose SQL type the contract does not fix (CollectionId, FindingId) are compared as text; the join to
/// sidata.Finding is always on the native column so the CollectionId index is used.
/// </summary>
public static class ProDataSql
{
    /// The asset tier as '0'..'3' or 'Unclassified' -- accepts an int column, a numeric text, or "Tier 2".
    public static string TierExpr(string column) =>
        $"CASE WHEN TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), {column}), N'Tier', N'')) BETWEEN 0 AND 3 " +
        $"THEN CONVERT(nvarchar(12), TRY_CONVERT(int, REPLACE(CONVERT(nvarchar(32), {column}), N'Tier', N''))) ELSE N'Unclassified' END";

    /// <summary>
    /// #431 (operator 2026-10-07, "Match any part"): every kind a CI is made of, as a ';'-list -- sidata.Asset.AssetKinds
    /// ('endpoint;azure' for an Azure VM correlated into its MDE endpoint), or the one AssetKind on a row loaded before
    /// that column existed. AssetKind stays the most descriptive kind and is what a page SHOWS; this is what a kind
    /// FILTER and its per-kind counts read. Same row, same join: no extra lookup per finding.
    /// </summary>
    public static string AssetKindsExpr(string alias = "a") => $"COALESCE(NULLIF({alias}.AssetKinds, N''), {alias}.AssetKind)";

    /// #431: the asset-kind filter -- a CI matches a kind when ANY of its parts has it (NULL parameter = no filter). The
    /// kind is a whitelisted word (<see cref="ProDataFilters.Kind"/>), so it carries no LIKE wildcard.
    public static string KindMatch(string alias, string parameter) =>
        $"(@{parameter} IS NULL OR N';' + {AssetKindsExpr(alias)} + N';' LIKE N'%;' + @{parameter} + N';%')";

    /// The asset-kind filter of SEVERAL kinds (owner 2026-10-19, "device + azure"): the parameter is a JSON array of
    /// whitelisted kinds (<see cref="ProDataFilters.Json"/>); a CI matches when any of its parts has any chosen kind.
    public static string KindMatchAny(string alias, string parameter) =>
        $"(@{parameter} IS NULL OR EXISTS (SELECT 1 FROM OPENJSON(@{parameter}) AS kv WHERE N';' + {AssetKindsExpr(alias)} + N';' LIKE N'%;' + kv.[value] + N';%'))";

    /// One filter of one or more values as an IN-list over a JSON array parameter (NULL = no filter): the statement text
    /// never depends on how many values were chosen, and every value is a parameter.
    public static string InList(string expr, string parameter) =>
        $"(@{parameter} IS NULL OR {expr} IN (SELECT fv.[value] FROM OPENJSON(@{parameter}) AS fv))";

    /// The note every asset-kind filter carries: the per-kind counts can overlap; "All" counts each asset once.
    public const string KindOverlapNote = "Kinds can overlap: an asset made of several sources counts under each kind, so the kinds can add up to more than All.";

    /// Severity as a rank (Very High first) for sorting: the shared <see cref="SeverityOrder"/> rank over f.Severity.
    public static readonly string SeverityRank = SeverityOrder.SqlRank("f.Severity");

    private static readonly string TierOrder =
        $"CASE WHEN {TierExpr("f.Tier")} = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, {TierExpr("f.Tier")}) END";

    /// The ONLY sort fragments a query can carry, keyed by <see cref="FindingSorts"/>.
    public static readonly IReadOnlyDictionary<string, string> Sorts = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        [FindingSorts.Importance] = $"{TierOrder}, f.RiskScore DESC, f.AssetName, f.Title",
        [FindingSorts.Risk] = "f.RiskScore DESC, f.AssetName, f.Title",
        [FindingSorts.Severity] = $"{SeverityRank}, {TierOrder}, f.RiskScore DESC, f.AssetName, f.Title",
        [FindingSorts.SeverityAscending] = $"{SeverityRank} DESC, {TierOrder}, f.RiskScore DESC, f.AssetName, f.Title",
        [FindingSorts.Asset] = "f.AssetName, f.RiskScore DESC",
        [FindingSorts.Report] = "f.ReportName, f.RiskScore DESC",
    };

    /// The chosen collection -- or the PUBLISHED one (<see cref="PublishedRun"/>) -- as CTE "c". Owner 2026-10-19: a view
    /// never shows a collection while the data sync is still loading it -- the wall board showed 0 findings and a
    /// 25,794-row fragment of a 1.1M-row collection mid-run ("trust is broken") -- and never a part of a run that is not
    /// trusted: "the newest" is the published run's collection, for every view alike.
    public const string CollectionCte = $"""
WITH c AS (
    SELECT TOP (1) col.CollectionId, col.CollectionTime
    FROM sidata.Collection AS col
    WHERE (@CollectionId IS NULL AND col.CollectionId = {PublishedRun.DetailedId}) OR CONVERT(nvarchar(64), col.CollectionId) = @CollectionId
    ORDER BY CASE WHEN col.Kind = N'Detailed' THEN 0 ELSE 1 END, col.CollectionTime DESC
)
""";

    public static readonly string FindingWhere = $"""
WHERE {InList(TierExpr("f.Tier"), "Tier")}
  AND {InList("f.Severity", "Severity")}
  AND {InList("f.SecurityDomain", "Domain")}
  AND {InList("f.ReportName", "Report")}
  AND {KindMatchAny("a", "AssetKind")}
  AND (@AssetKey IS NULL OR f.AssetKey = @AssetKey)
  AND (@Text IS NULL OR f.AssetName LIKE @Text OR f.Title LIKE @Text OR f.Cve LIKE @Text OR f.ConfigurationId LIKE @Text OR f.ReportName LIKE @Text)
""";

    private static readonly string FindingColumnsBase = $"""
CONVERT(nvarchar(64), f.FindingId) AS FindingId, CONVERT(nvarchar(64), f.CollectionId) AS CollectionId, c.CollectionTime,
       f.AssetKey, f.AssetName, a.AssetKind, {AssetKindsExpr("a")} AS AssetKinds, f.ReportName, f.SecurityDomain, f.ConfigurationId, f.Cve, f.Title, f.Severity,
       {TierExpr("f.Tier")} AS Tier, f.RiskScore
""";

    /// The finding columns -- with the exemption mark (#264) when the request has an exempted scope (one is set only where
    /// the database carries the mark), so a view that shows exempted findings can mark them.
    private static string FindingColumns => Exempted.Current is null ? FindingColumnsBase
        : FindingColumnsBase.TrimEnd() + ", CONVERT(nvarchar(32), f.ExemptionId) AS ExemptionId, f.ExemptedUntil\n";

    /// #264: how many findings matching the filter carry an exemption mark.
    public static SqlQuery ExemptedCount(FindingFilter raw)
    {
        var f = ProDataFilters.Normalize(raw);
        var text = $"""
{CollectionCte}
SELECT COUNT_BIG(*) AS N
FROM sidata.Finding AS f
JOIN c ON f.CollectionId = c.CollectionId
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
{WhereOf(f).TrimEnd()}
  AND {Exempted.ExemptedSql("f")}
OPTION (RECOMPILE);
""";
        return new SqlQuery(text, FilterParams(f));
    }

    /// The collections a person can open: complete ones, never past the published run (a newer one is not trusted yet).
    public const string Collections = $"""
SELECT TOP (@Top) CONVERT(nvarchar(64), col.CollectionId) AS CollectionId, col.CollectionTime, col.Kind, col.[Rows] AS RowTotal, CONVERT(nvarchar(64), col.RunId) AS RunId
FROM sidata.Collection AS col
WHERE col.Status = N'Complete' AND col.CollectionTime <= ISNULL({PublishedRun.DetailedTime}, col.CollectionTime)
ORDER BY col.CollectionTime DESC;
""";

    public static SqlQuery CollectionsTop(int top) => new(Collections, new Dictionary<string, object?> { ["Top"] = Math.Clamp(top, 1, 500) });

    /// #855 (owner 2026-10-21: "default filter is active, so it should be active only"): the lifecycle a request counts -- its
    /// own, else the default: ACTIVE CIs only.
    public static LifecycleFilter Life(LifecycleFilter? l) => l ?? LifecycleFilter.Active;

    /// The finding WHERE plus, when the user's scopes restrict what they see, the visibility predicate (#253 hook), and
    /// (#855) the CI lifecycle the request counts (sidata.Finding.CiLifecycle; NULL = no CI / not stamped = active).
    public static string WhereOf(FindingFilter f)
    {
        var w = FindingWhere.TrimEnd() + $"\n  AND {Life(f.Lifecycle).Sql("f.CiLifecycle")}\n";
        return f.Visibility is { } v ? w.TrimEnd() + $"\n  AND ({v.Sql})\n" : w;
    }

    private static Dictionary<string, object?> FilterParams(FindingFilter f)
    {
        var p = new Dictionary<string, object?>
        {
            ["CollectionId"] = f.CollectionId,
            ["Tier"] = ProDataFilters.Json(f.Tier),
            ["Severity"] = ProDataFilters.Json(f.Severity),
            ["Domain"] = ProDataFilters.Json(f.Domain),
            ["Report"] = ProDataFilters.Json(f.Report),
            ["AssetKind"] = ProDataFilters.Json(f.AssetKind),
            ["AssetKey"] = f.AssetKey,
            ["Text"] = ProDataFilters.Like(f.Text),
        };
        if (f.Visibility is { } v) foreach (var kv in v.Parameters) p[kv.Key] = kv.Value;
        return p;
    }

    /// One page of findings of one collection, with the total for the pager.
    public static SqlQuery FindingsPage(FindingFilter raw)
    {
        var f = ProDataFilters.Normalize(raw);
        var text = $"""
{CollectionCte}
SELECT {FindingColumns},
       COUNT_BIG(*) OVER () AS TotalRows
FROM sidata.Finding AS f
JOIN c ON f.CollectionId = c.CollectionId
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
{WhereOf(f)}
ORDER BY {Sorts[f.Sort]}
OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY
OPTION (RECOMPILE);
""";
        var p = FilterParams(f);
        p["Skip"] = f.Skip;
        p["Take"] = f.Take;
        return new SqlQuery(text, p);
    }

    // ---- #812: the browser's default view from what the data sync stored per collection ----------------------------------
    // A large customer (1,117,524 findings): FindingsPage counted (COUNT OVER) and sorted every finding of the collection on
    // each open, Pivot grouped them with a distinct count, ExemptedCount counted them again. The data sync writes, once per
    // collection (engine\pro-data\_shared\SI-DataPivots.ps1): Finding.ImportanceRank (the default order as a number,
    // IX_Finding_Importance), sidata.FindingPivotCell + its counted twin (the pivot's cells over every report and per report)
    // and sidata.FindingPivotState. A request served from them: no CI, kind or text filter and no visibility predicate
    // (<see cref="StoredFilter"/>); a tier / severity / domain / report filter selects cells exactly. Any other filter keeps the
    // live read (a CI and a department are narrowed by their indexes; the text search and the kind filter are the user's
    // explicit narrowing and stay live -- REQUIREMENTS #812 says so).

    /// The request can be answered from the stored rows: only tier / severity / domain / report filters.
    public static bool StoredFilter(FindingFilter f) =>
        f.AssetKind is null && f.Text is null && f.AssetKey is null && f.Visibility is null;

    /// The stored page also needs the default order (the rank is the importance order).
    public static bool StoredPage(FindingFilter f) => StoredFilter(f) && f.Sort == FindingSorts.Importance;

    /// The cells a tier / severity / domain / report filter selects (alias): over every report, or the one report's.
    // rc14: every filter holds one or more values (the multi-select, a JSON array parameter -- InList), as the live read
    // #855: the cells carry the CI lifecycle as a key -- the request's lifecycle selects them (default: active)
    public static string CellWhere(string a, LifecycleFilter? lifecycle = null) =>
        $"{a}.ByReport = CASE WHEN @Report IS NULL THEN 0 ELSE 1 END AND {InList(a + ".ReportName", "Report")} " +
        $"AND {InList(a + ".Tier", "Tier")} AND {InList(a + ".Severity", "Severity")} AND {InList(a + ".SecurityDomain", "Domain")} " +
        $"AND {Life(lifecycle).Sql(a + ".CiLifecycle")}";

    private static Dictionary<string, object?> StoredParams(FindingFilter f) => new()
    {
        ["CollectionId"] = f.CollectionId, ["Tier"] = ProDataFilters.Json(f.Tier), ["Severity"] = ProDataFilters.Json(f.Severity), ["Domain"] = ProDataFilters.Json(f.Domain), ["Report"] = ProDataFilters.Json(f.Report),
    };

    /// Whether the stored rows of the chosen (or the published) collection are written: one row, BuiltAt NULL = not yet.
    public const string FindingPivotStatusText = CollectionCte + """
SELECT CONVERT(nvarchar(64), c.CollectionId) AS CollectionId, s.BuiltAt
FROM c
LEFT JOIN sidata.FindingPivotState AS s ON s.CollectionId = c.CollectionId;
""";

    public static SqlQuery FindingPivotStatus(string? collectionId) => new(FindingPivotStatusText, new Dictionary<string, object?> { ["CollectionId"] = collectionId });

    /// One page in the default order: the page's keys by a seek on the rank, then their columns; the total = the cells' sum.
    public static SqlQuery FindingsPageStored(FindingFilter raw)
    {
        var f = ProDataFilters.Normalize(raw);
        var text = $"""
{CollectionCte.TrimEnd()},
k AS (
    SELECT f.CollectionId, f.FindingId, f.ImportanceRank
    FROM sidata.Finding AS f
    JOIN c ON f.CollectionId = c.CollectionId
    WHERE f.ImportanceRank IS NOT NULL
      AND {InList(TierExpr("f.Tier"), "Tier")}
      AND {InList("f.Severity", "Severity")}
      AND {InList("f.SecurityDomain", "Domain")}
      AND {InList("f.ReportName", "Report")}
      AND {Life(f.Lifecycle).Sql("f.CiLifecycle")}
    ORDER BY f.ImportanceRank
    OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY
)
SELECT {FindingColumns.TrimEnd()},
       (SELECT ISNULL(SUM(pc.Findings), 0) FROM sidata.FindingPivotCell AS pc WHERE pc.CollectionId = c.CollectionId AND {CellWhere("pc", f.Lifecycle)}) AS TotalRows
FROM c
JOIN k ON k.CollectionId = c.CollectionId
JOIN sidata.Finding AS f ON f.CollectionId = k.CollectionId AND f.FindingId = k.FindingId
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
ORDER BY k.ImportanceRank
OPTION (RECOMPILE);
""";
        var p = StoredParams(f);
        p["Skip"] = f.Skip;
        p["Take"] = f.Take;
        return new SqlQuery(text, p);
    }

    /// The pivot from the stored cells -- exactly the cells <see cref="Pivot"/> groups, in its order. #855: a cell is stored per
    /// CI lifecycle; the lifecycles the request counts add up (an asset has one lifecycle, so its distinct count adds up too).
    public static SqlQuery PivotStored(FindingFilter raw)
    {
        var f = ProDataFilters.Normalize(raw);
        var text = $"""
{CollectionCte}
SELECT pc.Tier, pc.Severity, pc.SecurityDomain, SUM(pc.Findings) AS Findings, SUM(pc.Assets) AS Assets
FROM c
JOIN sidata.FindingPivotCell AS pc ON pc.CollectionId = c.CollectionId
WHERE {CellWhere("pc", f.Lifecycle)}
GROUP BY pc.Tier, pc.Severity, pc.SecurityDomain
ORDER BY CASE WHEN pc.Tier = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, pc.Tier) END, {SeverityOrder.SqlRank("pc.Severity")}, pc.Severity, pc.SecurityDomain;
""";
        return new SqlQuery(text, StoredParams(f));
    }

    /// The cell column one dropdown counts ("tier", "sev", "dom", "rep"); null = not a stored column (the kind).
    public static string? CellColumn(string col) => col switch { "tier" => "Tier", "sev" => "Severity", "dom" => "SecurityDomain", "rep" => "ReportName", _ => null };

    /// A dropdown's counts per value under the OTHER filters, from the stored cells (the report's counts read the per-report
    /// cells) -- the findings per value, as the browser's own count of its rows gives them.
    public static SqlQuery CellCounts(FindingFilter raw, string col)
    {
        var f = ProDataFilters.Normalize(raw);
        var c = CellColumn(col) ?? throw new ArgumentException($"'{col}' has no stored counts");
        var where = c == "ReportName"
            ? $"pc.ByReport = 1 AND {InList("pc.ReportName", "Report")} AND {InList("pc.Tier", "Tier")} AND {InList("pc.Severity", "Severity")} AND {InList("pc.SecurityDomain", "Domain")} AND {Life(f.Lifecycle).Sql("pc.CiLifecycle")}"
            : CellWhere("pc", f.Lifecycle);
        var text = $"""
{CollectionCte}
SELECT pc.{c} AS V, SUM(pc.Findings) AS N
FROM c
JOIN sidata.FindingPivotCell AS pc ON pc.CollectionId = c.CollectionId
WHERE {where} AND pc.{c} IS NOT NULL AND pc.{c} <> N''
GROUP BY pc.{c}
ORDER BY SUM(pc.Findings) DESC, pc.{c};
""";
        return new SqlQuery(text, StoredParams(f));
    }

    /// The exempted findings the filter matches: every finding's cells less the counted ones (read with no exempted rewrite).
    public static SqlQuery ExemptedCountStored(FindingFilter raw)
    {
        var f = ProDataFilters.Normalize(raw);
        var text = $"""
{CollectionCte}
SELECT (SELECT ISNULL(SUM(pa.Findings), 0) FROM sidata.FindingPivotCell AS pa WHERE pa.CollectionId = c.CollectionId AND {CellWhere("pa", f.Lifecycle)})
     - (SELECT ISNULL(SUM(pk.Findings), 0) FROM sidata.FindingPivotCellCounted AS pk WHERE pk.CollectionId = c.CollectionId AND {CellWhere("pk", f.Lifecycle)}) AS N
FROM c;
""";
        return new SqlQuery(text, StoredParams(f));
    }

    /// The whole filtered view (bounded) for the CSV export.
    public static SqlQuery FindingsExport(FindingFilter raw, int max)
    {
        var f = ProDataFilters.Normalize(raw);
        var text = $"""
{CollectionCte}
SELECT TOP (@Max) {FindingColumns}
FROM sidata.Finding AS f
JOIN c ON f.CollectionId = c.CollectionId
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
{WhereOf(f)}
ORDER BY {Sorts[f.Sort]}
OPTION (RECOMPILE);
""";
        var p = FilterParams(f);
        p["Max"] = Math.Clamp(max, 1, ProDataFilters.MaxExport);
        return new SqlQuery(text, p);
    }

    /// The dimension pivot (tier x severity x domain) of the filtered view of one collection.
    public static SqlQuery Pivot(FindingFilter raw)
    {
        var f = ProDataFilters.Normalize(raw);
        var text = $"""
{CollectionCte}
SELECT {TierExpr("f.Tier")} AS Tier, COALESCE(f.Severity, N'') AS Severity, COALESCE(f.SecurityDomain, N'') AS SecurityDomain,
       COUNT_BIG(*) AS Findings, COUNT_BIG(DISTINCT f.AssetKey) AS Assets
FROM sidata.Finding AS f
JOIN c ON f.CollectionId = c.CollectionId
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
{WhereOf(f)}
GROUP BY {TierExpr("f.Tier")}, COALESCE(f.Severity, N''), COALESCE(f.SecurityDomain, N'')
ORDER BY MIN({TierOrder}), MIN({SeverityRank}), COALESCE(f.Severity, N''), COALESCE(f.SecurityDomain, N'')
OPTION (RECOMPILE);
""";
        return new SqlQuery(text, FilterParams(f));
    }

    /// One finding (drill-down) with its detail JSON and its asset's properties.
    public static SqlQuery Finding(string? collectionId, string findingId)
    {
        var text = $"""
{CollectionCte}
SELECT {FindingColumns}, f.DetailJson, a.PropertiesJson
FROM sidata.Finding AS f
JOIN c ON f.CollectionId = c.CollectionId
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
WHERE CONVERT(nvarchar(64), f.FindingId) = @FindingId;
""";
        return new SqlQuery(text, new Dictionary<string, object?>
        {
            ["CollectionId"] = ProDataFilters.Id(collectionId, "collection"),
            ["FindingId"] = ProDataFilters.Id(findingId, "finding") ?? throw new ArgumentException("a finding id is required"),
        });
    }

    public const string AssetIdentifiers = """
SELECT TOP (200) ai.IdentifierType, ai.IdentifierValue
FROM sidata.AssetIdentifier AS ai
WHERE ai.AssetKey = @AssetKey
ORDER BY ai.IdentifierType, ai.IdentifierValue;
""";

    public static SqlQuery Identifiers(string assetKey) =>
        new(AssetIdentifiers, new Dictionary<string, object?> { ["AssetKey"] = ProDataFilters.AssetKey(assetKey) ?? throw new ArgumentException("an asset key is required") });

    /// Report names seen in the newest collection (what an exclusions document may be keyed by, besides 'global').
    public static SqlQuery ReportNames() => new($"""
{CollectionCte}
SELECT DISTINCT fd.ReportName
FROM sidata.FindingDaily AS fd
JOIN c ON fd.CollectionId = c.CollectionId
WHERE fd.ReportName IS NOT NULL
ORDER BY fd.ReportName;
""", new Dictionary<string, object?> { ["CollectionId"] = null });

    /// The column a trend dimension groups by. Whitelisted; never a caller's text.
    public static string DimensionExpr(string dimension) => DimensionExpr(dimension, "fd");

    /// The same, over another aggregate's alias (sidata.AssetDaily AS ad).
    public static string DimensionExpr(string dimension, string alias) => dimension switch
    {
        TrendDimensions.Tier => TierExpr(alias + ".Tier"),
        TrendDimensions.Severity => $"COALESCE({alias}.Severity, N'')",
        TrendDimensions.Domain => $"COALESCE({alias}.SecurityDomain, N'')",
        TrendDimensions.Report => $"COALESCE({alias}.ReportName, N'')",
        _ => "N'All'",
    };

    /// <summary>
    /// #295 -- which grain of sidata.AssetDaily answers a trend: GROUPING_ID(Tier, Severity, SecurityDomain, ReportName) with
    /// the split and every filtered column specific and the rest "all" (bit set). An asset counts ONCE per group shown --
    /// FindingDaily.Assets is distinct only within its own finest group and is never added up.
    /// </summary>
    public static int AssetGrain(TrendRequest r)
    {
        int g = 15;
        if (r.Dimension == TrendDimensions.Tier || r.Tier is not null) g &= ~8;
        if (r.Dimension == TrendDimensions.Severity || r.Severity is not null) g &= ~4;
        if (r.Dimension == TrendDimensions.Domain || r.Domain is not null) g &= ~2;
        if (r.Dimension == TrendDimensions.Report || r.Report is not null) g &= ~1;
        return g;
    }

    /// Trend analytics: per day, the newest collection of that day, grouped by one dimension, from the PRE-COMPUTED
    /// sidata.FindingDaily table (never the finding rows).
    /// Within a day: severity groups by RANK (Very High first), any other dimension by its value; nothing for 'none'
    /// (SQL Server refuses a constant in ORDER BY).
    private static string TrendOrder(string dimension, string dim) => dimension switch
    {
        TrendDimensions.None => "",
        TrendDimensions.Severity => $", MIN({SeverityOrder.SqlRank("fd.Severity")}), {dim}",
        _ => $", {dim}",
    };

    /// Findings at the top severities (Very High / Critical, High) of the aggregate rows -- the shared rank.
    public static string TopSeveritySum(string severityColumn, string findingsColumn) =>
        $"SUM(CASE WHEN {SeverityOrder.SqlRank(severityColumn)} <= {SeverityOrder.TopSeverityMaxRank} THEN {findingsColumn} ELSE 0 END)";

    /// <summary>
    /// The trend. Per group it returns the findings, the assets, the score total (only so groups can be combined into a
    /// correct average -- never shown), the HIGHEST finding score (FindingDaily.ScoreMax) and the findings at the top
    /// severities. <paramref name="withScoreMax"/> = false reads a database whose FindingDaily predates the ScoreMax
    /// column (the data sync adds it on its next run): the highest score then reads as unknown, nothing fails.
    /// </summary>
    public static SqlQuery Trend(TrendRequest raw, DateTime todayUtc, bool withScoreMax = true, bool withAssetDaily = true)
    {
        var r = ProDataFilters.Normalize(raw);
        var dim = DimensionExpr(r.Dimension);
        var max = withScoreMax ? "MAX(fd.ScoreMax)" : "CAST(NULL AS float)";
        // #295: the assets come from the DISTINCT-asset grain that matches the split and the filters (sidata.AssetDaily);
        // NULL (shown as unknown) for a day whose grains are not computed yet, never the sum of per-group counts. A database
        // without the table yet (the data sync adds it) reads the assets as unknown.
        // a distinct-asset grain counts ONE value per filter: with several values of a filter that is not the split, the
        // assets of the chosen values cannot be added (an asset can be in two) -- they read as unknown, never as a sum
        withAssetDaily = withAssetDaily && !SeveralOutsideSplit(r);
        var assetCte = withAssetDaily ? $"""
,
asd AS (
    -- #855: the grain is stored per CI lifecycle; an asset has one, so the counted lifecycles' distinct assets ADD UP
    SELECT x.Day, x.Dim, SUM(x.Assets) AS Assets
    FROM (SELECT ad.Day, {DimensionExpr(r.Dimension, "ad")} AS Dim, ad.CiLifecycle AS Lc, MAX(ad.Assets) AS Assets
          FROM sidata.AssetDaily AS ad
          JOIN pick AS pa ON pa.Day = ad.Day AND pa.CollectionId = ad.CollectionId AND pa.rn = 1
          WHERE ad.GroupingId = @AssetGrain
            AND {InList(TierExpr("ad.Tier"), "Tier")}
            AND {InList("ad.Severity", "Severity")}
            AND {InList("ad.SecurityDomain", "Domain")}
            AND {InList("ad.ReportName", "Report")}
            AND {Life(r.Lifecycle).Sql("ad.CiLifecycle")}
          GROUP BY ad.Day, ad.CiLifecycle{(r.Dimension == TrendDimensions.None ? "" : ", " + DimensionExpr(r.Dimension, "ad"))}) AS x
    GROUP BY x.Day, x.Dim
)
""" : "";
        var assets = withAssetDaily ? "MAX(asd.Assets)" : "CAST(NULL AS bigint)";
        var assetJoin = withAssetDaily ? $"\nLEFT JOIN asd ON asd.Day = fd.Day AND asd.Dim = {dim}" : "";
        var text = $"""
WITH pick AS (
    SELECT d.Day, d.CollectionId, ROW_NUMBER() OVER (PARTITION BY d.Day ORDER BY col.CollectionTime DESC) AS rn
    FROM (SELECT DISTINCT Day, CollectionId FROM sidata.FindingDaily WHERE Day >= @Since) AS d
    JOIN sidata.Collection AS col ON col.CollectionId = d.CollectionId
    WHERE {PublishedRun.NotAfter("col.CollectionTime")}
){assetCte}
SELECT fd.Day, MAX(CONVERT(nvarchar(64), fd.CollectionId)) AS CollectionId, {dim} AS Dim, SUM(fd.Findings) AS Findings, {assets} AS Assets,
       SUM(fd.ScoreTotal) AS ScoreTotal, {max} AS ScoreMax, {TopSeveritySum("fd.Severity", "fd.Findings")} AS TopSeverityFindings
FROM sidata.FindingDaily AS fd
JOIN pick AS p ON p.Day = fd.Day AND p.CollectionId = fd.CollectionId AND p.rn = 1{assetJoin}
WHERE {InList(TierExpr("fd.Tier"), "Tier")}
  AND {InList("fd.Severity", "Severity")}
  AND {InList("fd.SecurityDomain", "Domain")}
  AND {InList("fd.ReportName", "Report")}
  AND {Life(r.Lifecycle).Sql("fd.CiLifecycle")}
{(r.Dimension == TrendDimensions.None ? "GROUP BY fd.Day" : "GROUP BY fd.Day, " + dim)}
ORDER BY fd.Day{TrendOrder(r.Dimension, dim)}
OPTION (RECOMPILE);
""";
        var p = new Dictionary<string, object?>
        {
            ["Since"] = todayUtc.Date.AddDays(-r.Days),
            ["Tier"] = ProDataFilters.Json(r.Tier), ["Severity"] = ProDataFilters.Json(r.Severity), ["Domain"] = ProDataFilters.Json(r.Domain), ["Report"] = ProDataFilters.Json(r.Report),
            ["AssetGrain"] = AssetGrain(r),
        };
        return new SqlQuery(text, p);
    }

    /// Whether a trend filter that is not the split holds more than one value (its distinct assets cannot be read then).
    public static bool SeveralOutsideSplit(TrendRequest r) =>
        (r.Dimension != TrendDimensions.Tier && ProDataFilters.Values(r.Tier).Count > 1)
        || (r.Dimension != TrendDimensions.Severity && ProDataFilters.Values(r.Severity).Count > 1)
        || (r.Dimension != TrendDimensions.Domain && ProDataFilters.Values(r.Domain).Count > 1)
        || (r.Dimension != TrendDimensions.Report && ProDataFilters.Values(r.Report).Count > 1);

    /// The values a trend filter can take (from the newest 30 days of the aggregate table).
    public const string TrendFacets = """
SELECT DISTINCT N'severity' AS Facet, COALESCE(fd.Severity, N'') AS Value FROM sidata.FindingDaily AS fd WHERE fd.Day >= @Since
UNION SELECT DISTINCT N'domain', COALESCE(fd.SecurityDomain, N'') FROM sidata.FindingDaily AS fd WHERE fd.Day >= @Since
UNION SELECT DISTINCT N'report', COALESCE(fd.ReportName, N'') FROM sidata.FindingDaily AS fd WHERE fd.Day >= @Since;
""";

    public static SqlQuery Facets(DateTime todayUtc) => new(TrendFacets, new Dictionary<string, object?> { ["Since"] = todayUtc.Date.AddDays(-30) });

    /// The values each finding filter takes in ONE collection (the newest unless @CollectionId is given), from the
    /// pre-computed aggregate -- what the chat tools list as "values present" and use to read a guessed filter value.
    public static SqlQuery CollectionValues(string? collectionId) => new($"""
{CollectionCte}
SELECT DISTINCT N'severity' AS Facet, COALESCE(fd.Severity, N'') AS Value FROM sidata.FindingDaily AS fd JOIN c ON fd.CollectionId = c.CollectionId
UNION SELECT DISTINCT N'domain', COALESCE(fd.SecurityDomain, N'') FROM sidata.FindingDaily AS fd JOIN c ON fd.CollectionId = c.CollectionId
UNION SELECT DISTINCT N'report', COALESCE(fd.ReportName, N'') FROM sidata.FindingDaily AS fd JOIN c ON fd.CollectionId = c.CollectionId
UNION SELECT DISTINCT N'tier', {TierExpr("fd.Tier")} FROM sidata.FindingDaily AS fd JOIN c ON fd.CollectionId = c.CollectionId;
""", new Dictionary<string, object?> { ["CollectionId"] = ProDataFilters.Id(collectionId, "collection") });

    /// The close-loop's days, never past the published run's day (a day the trusted run has not reached is not shown).
    public const string Lifecycle = $"""
SELECT v.Day, v.Opened, v.Closed, v.Reopened, v.OpenAtEndOfDay
FROM sidata.VulnLifecycleDaily AS v
WHERE v.Day >= @Since AND v.Day <= ISNULL(CONVERT(date, {PublishedRun.DetailedTime}), v.Day)
ORDER BY v.Day;
""";

    /// #855 W9: the same days with the closes split by reason -- fixed (Remediated), asset retired (AssetRetired), any other
    /// reason (NULL on a day worked out before the split). A database without the columns reads <see cref="Lifecycle"/>.
    public const string LifecycleByReason = $"""
SELECT v.Day, v.Opened, v.Closed, v.Reopened, v.OpenAtEndOfDay, v.ClosedFixed, v.ClosedRetired, v.ClosedOther
FROM sidata.VulnLifecycleDaily AS v
WHERE v.Day >= @Since AND v.Day <= ISNULL(CONVERT(date, {PublishedRun.DetailedTime}), v.Day)
ORDER BY v.Day;
""";

    public static SqlQuery LifecycleSince(int days, DateTime todayUtc, bool byReason = true) =>
        new(byReason ? LifecycleByReason : Lifecycle, new Dictionary<string, object?> { ["Since"] = todayUtc.Date.AddDays(-ProDataFilters.Days(days)) });

    /// Open vulnerabilities (vuln current state) by severity and the asset's tier from sidata.Asset (matched on the
    /// asset key, or on an identifier carrying the close-loop's id while vuln is not yet re-keyed to the CI).
    /// The key -> tier map is built ONCE (the asset key wins over an identifier) and joined: a per-item lookup with an
    /// OR over both tables timed out after 120 s on 12,205 open items (live 2026-10-04); this form answers in 0.3 s.
    public static readonly string OpenVulnerabilities = $"""
WITH keyed AS (
    SELECT a.AssetKey AS K, a.Tier, 0 AS Pri FROM sidata.Asset AS a
    UNION ALL
    SELECT ai.IdentifierValue, a.Tier, 1 FROM sidata.AssetIdentifier AS ai JOIN sidata.Asset AS a ON a.AssetKey = ai.AssetKey
), t AS (
    SELECT K, Tier, ROW_NUMBER() OVER (PARTITION BY K ORDER BY Pri) AS rn FROM keyed
)
SELECT COALESCE(i.Severity, N'(none)') AS Severity, {TierExpr("t.Tier")} AS Tier, COUNT_BIG(*) AS Items
FROM vuln.VulnerabilityItem AS i
LEFT JOIN t ON t.K = i.CorrelationId AND t.rn = 1
WHERE i.State = N'Open' AND i.Source = @Source
GROUP BY COALESCE(i.Severity, N'(none)'), {TierExpr("t.Tier")};
""";

    /// #264: the open items leaving out what the NEWEST collection marks exempted -- the item's (asset, CVE) is an exempted
    /// finding there. The close-loop's items carry no mark of their own; the mark of the finding they track decides. The
    /// key set (the CI key and every identifier of an exempted finding's CI) is built ONCE and joined.
    public static readonly string OpenVulnerabilitiesCounted = $"""
WITH keyed AS (
    SELECT a.AssetKey AS K, a.Tier, 0 AS Pri FROM sidata.Asset AS a
    UNION ALL
    SELECT ai.IdentifierValue, a.Tier, 1 FROM sidata.AssetIdentifier AS ai JOIN sidata.Asset AS a ON a.AssetKey = ai.AssetKey
), t AS (
    SELECT K, Tier, ROW_NUMBER() OVER (PARTITION BY K ORDER BY Pri) AS rn FROM keyed
), nc AS (
    SELECT {PublishedRun.DetailedId} AS CollectionId
), xa AS (
    SELECT DISTINCT v.AssetKey, v.Cve FROM sidata.vExemptedFinding AS v JOIN nc ON nc.CollectionId = v.CollectionId WHERE v.Cve IS NOT NULL
), xk AS (
    SELECT DISTINCT k.K, xa.Cve
    FROM xa
    JOIN (SELECT a.AssetKey, a.AssetKey AS K FROM sidata.Asset AS a UNION SELECT ai.AssetKey, ai.IdentifierValue FROM sidata.AssetIdentifier AS ai) AS k ON k.AssetKey = xa.AssetKey
)
SELECT COALESCE(i.Severity, N'(none)') AS Severity, {TierExpr("t.Tier")} AS Tier, COUNT_BIG(*) AS Items
FROM vuln.VulnerabilityItem AS i
LEFT JOIN t ON t.K = i.CorrelationId AND t.rn = 1
LEFT JOIN xk ON xk.K = i.CorrelationId AND xk.Cve = i.Cve
WHERE i.State = N'Open' AND i.Source = @Source AND xk.K IS NULL
GROUP BY COALESCE(i.Severity, N'(none)'), {TierExpr("t.Tier")};
""";

    public static SqlQuery OpenVulns(string source) =>
        new(Exempted.Excluding ? OpenVulnerabilitiesCounted : OpenVulnerabilities, new Dictionary<string, object?> { ["Source"] = source });

    /// <summary>
    /// The same counts AS THE DATA SYNC WROTE THEM after the close-loop's statistics (engine\pro-data\_shared\SI-DataPageLists.ps1:
    /// sidata.VulnOpenCount per source, severity and tier, Counted = 1 the variant leaving exempted findings out, with its
    /// state row) -- the statements above joined every open item to every asset and identifier on each open: 39 s on a cold
    /// small database, the page failed after 40 s (2026-10-20). One row per cell (BuiltAt on each); a state without cells
    /// answers one row with a NULL Severity (nothing open); no row = not counted yet (the page then counts itself, guarded).
    /// </summary>
    public const string OpenVulnerabilitiesStoredText = """
SELECT s.BuiltAt, o.Severity, o.Tier, o.Items
FROM sidata.VulnOpenCountState AS s
LEFT JOIN sidata.VulnOpenCount AS o ON o.Source = @Source AND o.Counted = @Counted
WHERE s.Name = N'current';
""";

    /// The stored counts of one source, the variant of the request's exempted scope.
    public static SqlQuery OpenVulnsStored(string source) =>
        new(OpenVulnerabilitiesStoredText, new Dictionary<string, object?> { ["Source"] = source, ["Counted"] = Exempted.Excluding ? 1 : 0 });

    /// Time to fix: verified-remediated closes in the window, median and 90th percentile days, per severity.
    public const string TimeToFix = """
SELECT DISTINCT COALESCE(i.Severity, N'(none)') AS Severity,
       COUNT_BIG(*) OVER (PARTITION BY COALESCE(i.Severity, N'(none)')) AS Fixed,
       PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY DATEDIFF(minute, i.FirstSeen, i.ClosedAt) / 1440.0) OVER (PARTITION BY COALESCE(i.Severity, N'(none)')) AS MedianDays,
       PERCENTILE_CONT(0.9) WITHIN GROUP (ORDER BY DATEDIFF(minute, i.FirstSeen, i.ClosedAt) / 1440.0) OVER (PARTITION BY COALESCE(i.Severity, N'(none)')) AS P90Days
FROM vuln.VulnerabilityItem AS i
WHERE i.State = N'Closed' AND i.CloseReason = N'Remediated' AND i.ClosedAt >= @Since AND i.Source = @Source;
""";

    public static SqlQuery TimeToFixSince(int days, string source, DateTime todayUtc) =>
        new(TimeToFix, new Dictionary<string, object?> { ["Since"] = todayUtc.Date.AddDays(-ProDataFilters.Days(days)), ["Source"] = source });

    /// The wall board's headline numbers: the newest collection's aggregate rows. Severity by the shared rank (the
    /// reports write "Very High"; "Critical" is the same step), the risk score as the AVERAGE per finding and the
    /// HIGHEST -- never the sum.
    /// #855: the counted CI lifecycle selects the day's rows (FindingDaily carries it as a key; default: active CIs only).
    public static string KpisText(bool withScoreMax = true, LifecycleFilter? lifecycle = null) => $"""
{CollectionCte}
SELECT MAX(c.CollectionTime) AS CollectionTime,
       COALESCE(SUM(fd.Findings), 0) AS Findings,
       COALESCE(SUM(CASE WHEN {TierExpr("fd.Tier")} = N'0' THEN fd.Findings END), 0) AS Tier0Findings,
       COALESCE(SUM(CASE WHEN {SeverityOrder.SqlRank("fd.Severity")} = {SeverityOrder.Top} THEN fd.Findings END), 0) AS VeryHigh,
       COALESCE(SUM(CASE WHEN {SeverityOrder.SqlRank("fd.Severity")} = 1 THEN fd.Findings END), 0) AS High,
       CASE WHEN SUM(fd.Findings) > 0 THEN SUM(fd.ScoreTotal) / SUM(fd.Findings) END AS AverageRiskScore,
       {(withScoreMax ? "MAX(fd.ScoreMax)" : "CAST(NULL AS float)")} AS HighestRiskScore
FROM c
LEFT JOIN sidata.FindingDaily AS fd ON fd.CollectionId = c.CollectionId AND {Life(lifecycle).Sql("fd.CiLifecycle")};
""";

    public static readonly string Kpis = KpisText();

    /// #292: the wall board's top Tier-0 assets of the published run -- Very High and High VULNERABILITIES per asset and its
    /// total risk score; sorted by Very High, then High, then risk. Owner 2026-10-19: the NAME is the asset's own
    /// (sidata.Asset; the findings' name only when there is no asset row) -- MAX over the findings picked the report's
    /// "name (device id)" variant of a second device record of the same asset; the COUNTS are DISTINCT CVEs per asset per
    /// severity, so a CVE two device records of one asset report counts once. The finding rows themselves are not changed.
    public static readonly string Tier0TopText = $"""
{CollectionCte}
SELECT TOP (@Top) f.AssetKey, COALESCE(MAX(a.AssetName), MAX(f.AssetName)) AS AssetName, MAX(a.AssetKind) AS AssetKind,
       COUNT(DISTINCT CASE WHEN COALESCE(f.Cve, N'') <> N'' AND {SeverityOrder.SqlRank("f.Severity")} = {SeverityOrder.Top} THEN f.Cve END) AS VeryHigh,
       COUNT(DISTINCT CASE WHEN COALESCE(f.Cve, N'') <> N'' AND {SeverityOrder.SqlRank("f.Severity")} = 1 THEN f.Cve END) AS High,
       SUM(COALESCE(f.RiskScore, 0)) AS RiskTotal
FROM c
JOIN sidata.Finding AS f ON f.CollectionId = c.CollectionId
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
WHERE {TierExpr("f.Tier")} = N'0'
GROUP BY f.AssetKey
ORDER BY VeryHigh DESC, High DESC, RiskTotal DESC, f.AssetKey;
""";

    public static SqlQuery Tier0Top(int top) => new(Tier0TopText, new Dictionary<string, object?> { ["CollectionId"] = null, ["Top"] = Math.Clamp(top, 1, 50) });

    /// <summary>
    /// #812: the same top Tier-0 assets as the data sync wrote them once per collection (sidata.Tier0Asset; the counted twin
    /// when exempted findings are left out) -- the statement above grouped every finding of the collection on each refresh of
    /// the wall board. Kept above as the reference the equality check compares with; the board reads this.
    /// </summary>
    public static readonly string Tier0TopStoredText = Tier0TopStoredTextOf(null);

    /// #855 M9: the top ten are of the counted CI lifecycle (default: ACTIVE -- a retired tier-0 CI is never on the wall board).
    public static string Tier0TopStoredTextOf(LifecycleFilter? lifecycle) => $"""
{CollectionCte}
SELECT TOP (@Top) t.AssetKey, t.AssetName, t.AssetKind, t.VeryHigh, t.High, t.RiskTotal
FROM c
JOIN sidata.Tier0Asset AS t ON t.CollectionId = c.CollectionId
WHERE {Life(lifecycle).Sql("t.CiLifecycle")}
ORDER BY t.VeryHigh DESC, t.High DESC, t.RiskTotal DESC, t.AssetKey;
""";

    public static SqlQuery Tier0TopStored(int top, LifecycleFilter? lifecycle = null) =>
        new(Tier0TopStoredTextOf(lifecycle), new Dictionary<string, object?> { ["CollectionId"] = null, ["Top"] = Math.Clamp(top, 1, 50) });

    /// Whether the shown collection's tier-0 rows are written (1 also when no collection is loaded yet).
    public static readonly string Tier0StateText = $"""
{CollectionCte}
SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM c) OR EXISTS (SELECT 1 FROM c JOIN sidata.Tier0AssetState AS s ON s.CollectionId = c.CollectionId) THEN 1 ELSE 0 END AS Ready;
""";

    public static SqlQuery Tier0State() => new(Tier0StateText, new Dictionary<string, object?> { ["CollectionId"] = null });

    public static SqlQuery WallboardKpis(bool withScoreMax = true, LifecycleFilter? lifecycle = null) => new(KpisText(withScoreMax, lifecycle), new Dictionary<string, object?> { ["CollectionId"] = null });

    /// <summary>
    /// The Unclassified findings of the newest collection: how many, on how many assets, and how many name no asset -- as the
    /// data sync wrote them once per collection (sidata.AssetRiskSummaryState, 2026-10-19: the per-request form below scanned
    /// every finding of the collection on each open of the Tier board, its tier test served by no index). Both variants:
    /// every finding, and the Counted* columns (the findings without an exemption mark) the reader takes when exempted
    /// findings are left out. No row = not written yet (the board leaves the line out, never the scan).
    /// </summary>
    public static readonly string UnclassifiedFindingsStoredText = $"""
{CollectionCte}
SELECT s.UnclassifiedFindings AS Findings, s.UnclassifiedAssets AS Assets, s.UnclassifiedWithoutAsset AS WithoutAsset,
       s.CountedUnclassifiedFindings AS CountedFindings, s.CountedUnclassifiedAssets AS CountedAssets, s.CountedUnclassifiedWithoutAsset AS CountedWithoutAsset
FROM c
JOIN sidata.AssetRiskSummaryState AS s ON s.CollectionId = c.CollectionId;
""";

    public static SqlQuery UnclassifiedFindingsStored() => new(UnclassifiedFindingsStoredText, new Dictionary<string, object?> { ["CollectionId"] = null });

    /// <summary>
    /// #855 M15: the same line for the CI lifecycle the board counts (default: active) -- from the per-CI rows the data sync
    /// wrote (sidata.AssetRiskSummary + its counted twin, each with its CI's lifecycle and its unclassified findings), plus the
    /// findings that name no CI at all (the state row: not known to be gone, so counted with the active CIs). A collection
    /// whose rows predate the column (Unclassified NULL) reads the state row's figures, as before. No state row = not written.
    /// </summary>
    public static string UnclassifiedFindingsByLifecycleText(LifecycleFilter? lifecycle)
    {
        var life = Life(lifecycle);
        var noCi = life.Includes(null) ? "1" : "0";
        return $"""
{CollectionCte}
SELECT CASE WHEN x.Old > 0 THEN s.UnclassifiedFindings ELSE x.Findings + {noCi} * s.UnclassifiedWithoutAsset END AS Findings,
       CASE WHEN x.Old > 0 THEN s.UnclassifiedAssets ELSE x.Assets END AS Assets,
       {noCi} * s.UnclassifiedWithoutAsset AS WithoutAsset,
       CASE WHEN x.Old > 0 THEN s.CountedUnclassifiedFindings ELSE xc.Findings + {noCi} * s.CountedUnclassifiedWithoutAsset END AS CountedFindings,
       CASE WHEN x.Old > 0 THEN s.CountedUnclassifiedAssets ELSE xc.Assets END AS CountedAssets,
       {noCi} * s.CountedUnclassifiedWithoutAsset AS CountedWithoutAsset
FROM c
JOIN sidata.AssetRiskSummaryState AS s ON s.CollectionId = c.CollectionId
CROSS APPLY (SELECT ISNULL(SUM(a.Unclassified), 0) AS Findings, COUNT_BIG(CASE WHEN a.Unclassified > 0 THEN 1 END) AS Assets,
                    COUNT_BIG(CASE WHEN a.Unclassified IS NULL THEN 1 END) AS Old
             FROM sidata.AssetRiskSummary AS a WHERE a.CollectionId = c.CollectionId AND {life.Sql("a.CiLifecycle")}) AS x
CROSS APPLY (SELECT ISNULL(SUM(a.Unclassified), 0) AS Findings, COUNT_BIG(CASE WHEN a.Unclassified > 0 THEN 1 END) AS Assets
             FROM sidata.AssetRiskSummaryCounted AS a WHERE a.CollectionId = c.CollectionId AND {life.Sql("a.CiLifecycle")}) AS xc;
""";
    }

    public static SqlQuery UnclassifiedFindingsByLifecycle(LifecycleFilter? lifecycle) =>
        new(UnclassifiedFindingsByLifecycleText(lifecycle), new Dictionary<string, object?> { ["CollectionId"] = null });

    /// The same figures computed per request from every finding -- what the board read before 2026-10-19. Kept ONLY as the
    /// reference the equality check and the measurement compare the stored figures with; no page reads it.
    public static readonly string UnclassifiedFindingsText = $"""
{CollectionCte}
SELECT COUNT_BIG(*) AS Findings,
       COUNT_BIG(DISTINCT f.AssetKey) AS Assets,
       COUNT_BIG(CASE WHEN f.AssetKey IS NULL THEN 1 END) AS WithoutAsset
FROM c
JOIN sidata.Finding AS f ON f.CollectionId = c.CollectionId
WHERE {TierExpr("f.Tier")} = N'Unclassified';
""";

    public static SqlQuery UnclassifiedFindings() => new(UnclassifiedFindingsText, new Dictionary<string, object?> { ["CollectionId"] = null });

    // ---- tier board (sidata.Asset: the current CI view) -----------------------------------------------------------

    private static readonly string AssetWhere = $"""
WHERE {KindMatch("a", "AssetKind")}
  AND (@Text IS NULL OR a.AssetName LIKE @Text OR a.AssetKey LIKE @Text)
""";

    public static SqlQuery TierCounts(string? assetKind, string? text) => new($"""
SELECT {TierExpr("a.Tier")} AS Tier, COUNT_BIG(*) AS Assets
FROM sidata.Asset AS a
{AssetWhere}
GROUP BY {TierExpr("a.Tier")}
OPTION (RECOMPILE);
""", new Dictionary<string, object?> { ["AssetKind"] = ProDataFilters.Kind(assetKind), ["Text"] = ProDataFilters.Like(ProDataFilters.Text(text)) });

    /// Which source set each tier (SI_TierSetBy, e.g. "rule", "software+logon", "default"), counted per tier. An asset
    /// with nothing recorded comes back with SetBy NULL: it is counted, never turned into a source of its own.
    public static SqlQuery TierSources(string? assetKind, string? text) => new($"""
SELECT {TierExpr("a.Tier")} AS Tier,
       NULLIF(CASE WHEN ISJSON(a.PropertiesJson) = 1 THEN JSON_VALUE(a.PropertiesJson, '$.SI_TierSetBy') END, N'') AS SetBy,
       COUNT_BIG(*) AS Assets
FROM sidata.Asset AS a
{AssetWhere}
GROUP BY {TierExpr("a.Tier")}, NULLIF(CASE WHEN ISJSON(a.PropertiesJson) = 1 THEN JSON_VALUE(a.PropertiesJson, '$.SI_TierSetBy') END, N'')
OPTION (RECOMPILE);
""", new Dictionary<string, object?> { ["AssetKind"] = ProDataFilters.Kind(assetKind), ["Text"] = ProDataFilters.Like(ProDataFilters.Text(text)) });

    /// One page of one tier column, by name. The tier attribution travels so each card can say "set by ...". With a
    /// Source, only the assets that source set: SI_TierSetBy is plural ('software+logon'), so it is matched as one
    /// '+'-delimited item (the source is a validated word -- letters, digits and '-' -- so it holds no LIKE wildcard).
    public static SqlQuery TierAssets(TierBoardRequest raw)
    {
        var r = ProDataFilters.Normalize(raw);
        return new SqlQuery($"""
SELECT a.AssetKey, a.AssetName, a.AssetKind, {TierExpr("a.Tier")} AS Tier, a.LastSeen,
       CASE WHEN ISJSON(a.PropertiesJson) = 1 THEN JSON_VALUE(a.PropertiesJson, '$.SI_TierSetBy') END AS TierSetBy,
       CASE WHEN ISJSON(a.PropertiesJson) = 1 THEN JSON_VALUE(a.PropertiesJson, '$.SI_TierReason') END AS TierReason,
       CASE WHEN ISJSON(a.PropertiesJson) = 1 THEN COALESCE(JSON_QUERY(a.PropertiesJson, '$.SI_TierClaims'), JSON_VALUE(a.PropertiesJson, '$.SI_TierClaims')) END AS TierClaims
FROM sidata.Asset AS a
{AssetWhere}
  AND {TierExpr("a.Tier")} = @Tier
  AND (@SourceItem IS NULL OR CONCAT(N'+', REPLACE(CASE WHEN ISJSON(a.PropertiesJson) = 1 THEN JSON_VALUE(a.PropertiesJson, '$.SI_TierSetBy') END, N' ', N''), N'+') LIKE @SourceItem)
ORDER BY a.AssetName, a.AssetKey
OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY
OPTION (RECOMPILE);
""", new Dictionary<string, object?>
        {
            ["AssetKind"] = r.AssetKind, ["Text"] = ProDataFilters.Like(r.Text), ["Tier"] = r.Tier, ["Skip"] = r.Skip, ["Take"] = r.Take,
            ["SourceItem"] = r.Source is null ? null : "%+" + r.Source + "+%",
        });
    }

    public static SqlQuery Asset(string assetKey) => new($"""
SELECT a.AssetKey, a.AssetName, a.AssetKind, {TierExpr("a.Tier")} AS Tier, a.LastSeen,
       CASE WHEN ISJSON(a.PropertiesJson) = 1 THEN JSON_VALUE(a.PropertiesJson, '$.SI_TierSetBy') END AS TierSetBy,
       CASE WHEN ISJSON(a.PropertiesJson) = 1 THEN JSON_VALUE(a.PropertiesJson, '$.SI_TierReason') END AS TierReason,
       CASE WHEN ISJSON(a.PropertiesJson) = 1 THEN COALESCE(JSON_QUERY(a.PropertiesJson, '$.SI_TierClaims'), JSON_VALUE(a.PropertiesJson, '$.SI_TierClaims')) END AS TierClaims
FROM sidata.Asset AS a
WHERE a.AssetKey = @AssetKey;
""", new Dictionary<string, object?> { ["AssetKey"] = ProDataFilters.AssetKey(assetKey) ?? throw new ArgumentException("an asset key is required") });

    // ---- connector status ----------------------------------------------------------------------------------------

    /// Close-loop targets: per source, open / closed, and the newest change.
    public const string CloseLoopTargets = """
SELECT i.Source,
       SUM(CASE WHEN i.State = N'Open' THEN 1 ELSE 0 END) AS OpenItems,
       SUM(CASE WHEN i.State = N'Closed' THEN 1 ELSE 0 END) AS ClosedItems,
       MAX(i.UpdatedAt) AS LastChange
FROM vuln.VulnerabilityItem AS i
GROUP BY i.Source
ORDER BY i.Source;
""";

    /// What the newest close-loop runs actually wrote (event counts per run): the applied half of the plan.
    public const string CloseLoopRuns = """
SELECT TOP (@Top) e.RunId, MIN(e.At) AS FirstAt, MAX(e.At) AS LastAt,
       SUM(CASE WHEN e.Action = N'Open' THEN 1 ELSE 0 END) AS Opened,
       SUM(CASE WHEN e.Action = N'Close' THEN 1 ELSE 0 END) AS Closed,
       SUM(CASE WHEN e.Action = N'Reopen' THEN 1 ELSE 0 END) AS Reopened,
       SUM(CASE WHEN e.Action = N'Seen' THEN 1 ELSE 0 END) AS Seen
FROM vuln.VulnerabilityEvent AS e
WHERE e.RunId IS NOT NULL
GROUP BY e.RunId
ORDER BY MAX(e.At) DESC;
""";

    /// Engine runs recorded by the data sync (sidata.Run), newest first, for the connector engines.
    public const string ConnectorRuns = """
SELECT TOP (@Top) CONVERT(nvarchar(64), r.RunId) AS RunId, r.Engine, r.CollectionTime, r.Verdict, r.StartedAt, r.EndedAt, r.SolutionVersion
FROM sidata.Run AS r
WHERE r.Engine LIKE @Engine1 OR r.Engine LIKE @Engine2 OR r.Engine LIKE @Engine3
ORDER BY COALESCE(r.EndedAt, r.StartedAt) DESC;
""";

    public static SqlQuery ConnectorRunsTop(int top) => new(ConnectorRuns, new Dictionary<string, object?>
    {
        ["Top"] = Math.Clamp(top, 1, 200), ["Engine1"] = "%cmdb%", ["Engine2"] = "%vuln%", ["Engine3"] = "%close%",
    });
}
