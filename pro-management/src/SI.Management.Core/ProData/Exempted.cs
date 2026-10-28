using System.Text.RegularExpressions;

namespace SI.Management.Core.ProData;

/// <summary>
/// EXEMPTED FINDINGS AT READ TIME (#264) -- THE one place the web app decides whether a read counts exempted findings.
/// <para>An exemption never removes a finding: Risk Analysis marks the row (SI_ExemptionId, SI_ExemptedUntil,
/// SI_ExemptionRequestId) and the data sync copies the mark onto <c>sidata.Finding</c> (ExemptionId, ExemptedUntil,
/// ExemptionRequestId). Every surface then asks ONE predicate -- <see cref="CountedSql"/> -- and every pre-computed
/// aggregate has a "...Counted" twin (<see cref="Twins"/>) the data sync fills over the findings without a mark.</para>
/// <para>HOW A READ IS SCOPED: the surface (a page, its export) sets <see cref="Use"/> for the request -- the setting of the
/// surface, overridden by the view's tick -- and the read layers (<see cref="ProDataQueries"/>, <see cref="CollectionViews"/>,
/// <see cref="DepartmentViews"/>, <see cref="EstateQueries"/>, the CMDB store) pass every statement through
/// <see cref="Apply(string)"/> BEFORE they run and describe it, so "the query behind this" is the query that ran.
/// No scope set (the chat, the MCP server, a background read) = statements unchanged, as before #264.</para>
/// <para>THE REWRITE: every <c>sidata.Finding</c> source becomes the counted rows
/// (<c>(SELECT * FROM sidata.Finding WHERE ExemptionId IS NULL)</c> -- SQL Server inlines it, the indexes are used), and
/// every aggregate is read from its counted twin, falling back per collection to the base table for a collection whose
/// twin is not computed yet (loaded before #264, when Risk Analysis still left exempted rows out: its base holds none).
/// One rule for every statement, so no surface can count differently.</para>
/// </summary>
public static class Exempted
{
    /// The mark column on sidata.Finding.
    public const string Column = "ExemptionId";
    /// The query-string key of the per-view tick: "1" = show / include exempted findings, "0" = hide / leave them out.
    public const string QueryKey = "exempted";

    /// THE predicate: the row (alias) is counted -- it carries no exemption mark.
    public static string CountedSql(string alias = "f") => Alias(alias) + ".ExemptionId IS NULL";
    /// Its complement: the row is exempted.
    public static string ExemptedSql(string alias = "f") => Alias(alias) + ".ExemptionId IS NOT NULL";

    /// The same predicate over Log Analytics rows (Risk Analysis's mark).
    public const string KqlCounted = "isempty(tostring(column_ifexists(\"SI_ExemptionId\", \"\")))";

    /// The pre-computed aggregates that have a counted twin, with their columns (the twin has the same columns, same order).
    public static readonly IReadOnlyDictionary<string, string> Twins = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        // #855: the aggregates that carry the CI lifecycle (a key, or a per-CI column) keep it through the twin rewrite
        ["FindingDaily"] = "[Day], CollectionId, Tier, Severity, SecurityDomain, ReportName, Findings, Assets, ScoreTotal, ScoreMax, CiLifecycle",
        // #295: the distinct assets at every grain (sidata.AssetDaily), counted over the findings without a mark
        ["AssetDaily"] = "[Day], CollectionId, GroupingId, Tier, Severity, SecurityDomain, ReportName, Assets, CiLifecycle",
        ["FindingFacet"] = "CollectionId, Facet, Value, Findings, Assets, ScoreTotal, WeightedTotal, MaxScore",
        ["DepartmentFacet"] = "CollectionId, DepartmentId, Severity, Tier, Findings, Assets, ScoreTotal, WeightedTotal",
        ["ServiceRisk"] = "CollectionId, ServiceKey, ServiceName, Assets, SharedAssets, Findings, WeightedTotal, WeightedPerAsset, RiskTotal, MaxWeighted, Critical, High, Medium, Low, Tier0, Tier1, Tier2, Tier3, TierUnclassified, TopAssetKey, TopAssetName, TopAssetWeighted, Sources",
        ["ServiceAsset"] = "CollectionId, ServiceKey, AssetKey, ServiceName, Source, AssetName, Tier, ServiceCount, Findings, Critical, High, Medium, Low, WeightedTotal, RiskTotal, MaxWeighted",
        // 2026-10-19: one row per CVE (Security recommendations > Vulnerabilities), both variants written by the data sync
        // in one transaction (SI-DataViewContext.ps1 Invoke-SIDataCveSummary)
        ["CveSummary"] = "CollectionId, Cve, Title, Severity, SeverityRank, Cvss, HasExploit, Assets, Findings, MaxRisk, TotalRisk, Tier, Tier0Findings",
        // 2026-10-19: one row per CI (Risks > Risk score, Assets (CIs) at risk), both variants written by the data sync in one
        // transaction (SI-DataViewContext.ps1 Invoke-SIDataAssetRiskSummary)
        ["AssetRiskSummary"] = "CollectionId, AssetKey, AssetName, Tier, Findings, Vulnerabilities, TotalRisk, MaxRisk, AvgRisk, TotalWeighted, MaxWeighted, AvgWeighted, CriticalRated, HighRated, TotalWeightedOrRisk, CiLifecycle, Unclassified",
        // #812: What changed per collection pair (B = CollectionId) and the wall board's top tier-0 assets, both variants written
        // by the data sync in one transaction each (engine\pro-data\_shared\SI-DataChanges.ps1)
        ["FindingChange"] = "CollectionId, PrevCollectionId, ChangeKey, Change, ChangeReason, AssetKey, AssetName, Issue, Title, ReportName, SeverityBefore, SeverityAfter, RiskBefore, RiskAfter, RiskDelta, TierBefore, TierAfter",
        ["AssetChange"] = "CollectionId, PrevCollectionId, AssetKey, AssetName, Change, FindingsBefore, FindingsAfter, RiskBefore, RiskAfter, RiskDelta, TierBefore, TierAfter",
        ["ChangeCount"] = "CollectionId, PrevCollectionId, What, Change, N",
        ["Tier0Asset"] = "CollectionId, AssetKey, AssetName, AssetKind, VeryHigh, High, RiskTotal, CiLifecycle",
        // #812: the #636 groupings the named views Risk rating / MITRE ATT&CK / Compliance / CVSS page over (SummaryGroupViewSql)
        ["SummaryGroup"] = "CollectionId, GroupingId, Key1, Key2, Key3, Label, Findings, Assets, Recommendations, MaxRisk, TotalRisk, BestTier, Tier0Findings, CriticalFindings, HighFindings, RatedCriticalFindings, RatedHighFindings, CriticalRecommendations, HighRecommendations, ExploitedRecommendations, AttributesJson",
        // #812: the findings browser's pivot cells (over every report and per report), written with their state by the data sync
        ["FindingPivotCell"] = "CollectionId, ByReport, ReportName, Tier, Severity, SecurityDomain, Findings, Assets, CiLifecycle",
    };

    /// What the database must carry before a read may be rewritten (the mark and every twin) -- 1 = ready.
    public const string SchemaReadySql = """
SELECT CASE WHEN COL_LENGTH('sidata.Finding', 'ExemptionId') IS NOT NULL AND COL_LENGTH('sidata.Collection', 'ExemptedDerivedAt') IS NOT NULL
             AND OBJECT_ID('sidata.FindingDailyCounted') IS NOT NULL AND OBJECT_ID('sidata.FindingFacetCounted') IS NOT NULL
             AND OBJECT_ID('sidata.DepartmentFacetCounted') IS NOT NULL AND OBJECT_ID('sidata.ServiceRiskCounted') IS NOT NULL
             AND OBJECT_ID('sidata.ServiceAssetCounted') IS NOT NULL AND OBJECT_ID('sidata.vExemptedFinding') IS NOT NULL THEN 1 ELSE 0 END AS Ready;
""";

    /// The exempted findings of one collection (the published run's when @CollectionId is NULL), optionally of one
    /// department -- the number behind "N exempted not counted".
    public const string CountSql = $"""
WITH c AS (
    SELECT TOP (1) col.CollectionId FROM sidata.Collection AS col
    WHERE col.Status = N'Complete' AND col.Kind = N'Detailed'
      AND ((@CollectionId IS NULL AND col.CollectionId = {PublishedRun.DetailedId}) OR CONVERT(nvarchar(64), col.CollectionId) = @CollectionId)
    ORDER BY col.CollectionTime DESC
)
SELECT COUNT_BIG(*) AS N
FROM sidata.vExemptedFinding AS v
JOIN c ON c.CollectionId = v.CollectionId
WHERE (@DepartmentId IS NULL OR v.DepartmentId = TRY_CONVERT(int, @DepartmentId));
""";

    private static readonly AsyncLocal<ExemptedScope?> _current = new();

    /// The scope of the current request's reads; null = none set (statements are not rewritten).
    public static ExemptedScope? Current => _current.Value;

    /// True when the current scope leaves exempted findings out.
    public static bool Excluding => _current.Value is { Include: false };

    /// A key part for caches: reads under different scopes must never share an answer.
    public static string CacheKey => _current.Value switch { null => "ex:-", { Include: true } => "ex:in", _ => "ex:out" };

    /// Sets the scope for everything awaited inside the returned handle (AsyncLocal: it flows into awaited calls and is
    /// restored when the handle is disposed).
    public static IDisposable Use(ExemptedScope? scope)
    {
        var previous = _current.Value;
        _current.Value = scope;
        return new Restore(previous);
    }

    private sealed class Restore(ExemptedScope? previous) : IDisposable
    {
        public void Dispose() => _current.Value = previous;
    }

    /// A statement as the current scope reads it (unchanged unless the scope leaves exempted findings out).
    public static SqlQuery Apply(SqlQuery q) => Excluding ? q with { Text = Exclude(q.Text) } : q;
    public static string Apply(string sql) => Excluding ? Exclude(sql) : sql;
    public static GridSpec Apply(GridSpec spec) => Excluding ? spec with { Ctes = Exclude(spec.Ctes), Source = Exclude(spec.Source) } : spec;

    private static readonly HashSet<string> Keywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "WHERE", "JOIN", "ON", "GROUP", "ORDER", "LEFT", "RIGHT", "INNER", "OUTER", "FULL", "CROSS", "UNION", "WITH", "OPTION", "SELECT",
        "AND", "OR", "HAVING", "AS", "WHEN", "THEN", "ELSE", "END", "INTERSECT", "EXCEPT", "OFFSET", "FETCH", "PIVOT", "UNPIVOT",
    };

    // sidata.<Table> as a source (never inside a quoted name such as OBJECT_ID('sidata.Finding')), with its optional alias.
    // An alias starting with "ex_" is one this rewrite wrote: never rewritten again, so Exclude is idempotent.
    private static readonly Regex FindingRx = new(@"(?<![\w.'\[])sidata\.Finding(?![\w'\]])(?<alias>\s+(?:AS\s+)?(?<name>[A-Za-z_][A-Za-z0-9_]*))?", RegexOptions.Compiled);
    private static readonly Regex TwinRx = new(@"(?<![\w.'\[])sidata\.(?<table>FindingDaily|AssetDaily|FindingFacet|DepartmentFacet|ServiceRisk|ServiceAsset|CveSummary|AssetRiskSummary|FindingChange|AssetChange|ChangeCount|Tier0Asset|SummaryGroup|FindingPivotCell)(?![\w'\]])(?<alias>\s+(?:AS\s+)?(?<name>[A-Za-z_][A-Za-z0-9_]*))?", RegexOptions.Compiled);

    /// <summary>
    /// The statement with exempted findings left out: every <c>sidata.Finding</c> source is its counted rows, every aggregate
    /// its counted twin (base table for a collection whose twin is not computed yet). Idempotent.
    /// </summary>
    public static string Exclude(string sql)
    {
        if (string.IsNullOrEmpty(sql)) return sql;
        var text = FindingRx.Replace(sql, m =>
        {
            var (alias, keep) = AliasOf(m, "Finding");
            if (alias is null) return m.Value;
            return $"(SELECT * FROM sidata.Finding AS ex_f WHERE ex_f.ExemptionId IS NULL) AS {alias}{keep}";
        });
        return TwinRx.Replace(text, m =>
        {
            var table = m.Groups["table"].Value;
            var (alias, keep) = AliasOf(m, table);
            if (alias is null) return m.Value;
            return TwinSource(table, alias) + keep;
        });
    }

    /// The alias the rewritten source takes, and what of the match must be kept after it (a keyword that was not an alias).
    /// Null alias = leave the match alone (one of ours).
    private static (string? Alias, string Keep) AliasOf(Match m, string fallback)
    {
        if (!m.Groups["alias"].Success) return (fallback, "");
        var name = m.Groups["name"].Value;
        if (name.StartsWith("ex_", StringComparison.OrdinalIgnoreCase)) return (null, "");
        if (Keywords.Contains(name)) return (fallback, m.Groups["alias"].Value);
        return (name, "");
    }

    /// The counted twin of one aggregate, falling back per collection to the base table where the twin is not computed yet.
    public static string TwinSource(string table, string alias)
    {
        if (!Twins.TryGetValue(table, out var columns)) throw new ArgumentException($"'{table}' has no counted twin");
        var cols = string.Join(", ", columns.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(c => "ex_x." + c));
        return $"(SELECT {cols} FROM sidata.{table}Counted AS ex_x JOIN sidata.Collection AS ex_c ON ex_c.CollectionId = ex_x.CollectionId WHERE ex_c.ExemptedDerivedAt IS NOT NULL " +
               $"UNION ALL SELECT {cols} FROM sidata.{table} AS ex_x JOIN sidata.Collection AS ex_c ON ex_c.CollectionId = ex_x.CollectionId WHERE ex_c.ExemptedDerivedAt IS NULL) AS {Alias(alias)}";
    }

    private static string Alias(string a) => Regex.IsMatch(a, "^[A-Za-z_][A-Za-z0-9_]{0,31}$") ? a : throw new ArgumentException($"'{a}' is not an alias");

    /// <summary>
    /// A grid over finding rows (its key is FindingId) with the mark as a visible column "Exempted" ("until yyyy-MM-dd" /
    /// "no end date") -- for a view that SHOWS exempted findings, so each one is marked (and an export carries the column).
    /// A grid that does not read sidata.Finding AS f in its source is returned unchanged.
    /// </summary>
    public static GridSpec WithMark(GridSpec spec)
    {
        const string from = "\nFROM sidata.Finding AS f";
        var i = spec.Source.IndexOf(from, StringComparison.Ordinal);
        if (i < 0 || spec.Columns.Any(c => c.Key == MarkKey)) return spec;
        var source = spec.Source[..i] + ",\n       " + MarkExpr("f") + " AS " + MarkKey + spec.Source[i..];
        var cols = spec.Columns.ToList();
        cols.Insert(Math.Min(cols.Count, 1), new GridColumn(MarkKey, "Exempted", Filter: GridFilter.Contains));
        return spec with { Source = source, Columns = cols };
    }

    /// The column key of the mark in a grid.
    public const string MarkKey = "Exempted";

    /// The mark as text: NULL = not exempted, "until yyyy-MM-dd", or "no end date".
    public static string MarkExpr(string alias) =>
        $"CASE WHEN {Alias(alias)}.ExemptionId IS NULL THEN NULL WHEN {alias}.ExemptedUntil IS NULL THEN N'no end date' ELSE CONCAT(N'until ', CONVERT(nchar(10), {alias}.ExemptedUntil, 23)) END";

    /// "Exempted until yyyy-MM-dd" (or "Exempted, no end date") for a row the view shows marked.
    public static string Label(DateTime? until) => until is { } u ? "Exempted until " + u.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture) : "Exempted, no end date";
}

/// <summary>The read scope of one request: whether exempted findings are included, and why.</summary>
/// <param name="Include">true = exempted findings are shown / counted; false = they are left out.</param>
/// <param name="FromTick">true = the view's tick decided it (the query string); false = the surface's setting.</param>
public sealed record ExemptedScope(bool Include, bool FromTick = false)
{
    public static ExemptedScope Exclude { get; } = new(false);
    public static ExemptedScope IncludeAll { get; } = new(true);
}
