using System.Globalization;
using SI.Management.Web.Data;

namespace SI.Management.Web.Summary;

// =====================================================================================================================
// RISKS > SUMMARY AS GROUPINGS OF THE DETAILED FINDINGS (REQUIREMENTS #636, owner 2026-10-19: "summary could be build as views
// with the detailed data instead. it is just views with groupings of data instead, like group per tier category").
//
// The groupings of data-model\summary-groupings.locked.json -- per recommendation with its affected assets, per asset, tier,
// Domain > Category > Subcategory, risk rating, department, severity, report -- written ONCE per collection by the data sync
// (THE engine function engine\_shared\SI-SummaryGroupings.ps1 Invoke-SISummaryGrouping, stored in sidata.SummaryGroup /
// SummaryGroupCounted / SummaryGroupState). This page pages and sorts THOSE typed, indexed rows; it never groups the finding
// rows per request and never reads a Summary report. A collection without its rows says they are being prepared.
// Read-only statements; every caller value is a parameter.
// =====================================================================================================================

/// One grouping the page offers: its id in the definition, its words, its key columns' words.
public sealed record SummaryGrouping(string Id, string Label, IReadOnlyList<string> KeyLabels);

/// One stored group row (sidata.SummaryGroup / SummaryGroupCounted).
public sealed record SummaryGroupRow(string Key1, string Key2, string Key3, string? Label, long Findings, long Assets, long Recommendations,
    double? MaxRisk, double? TotalRisk, int? BestTier, long Tier0Findings, long CriticalFindings, long HighFindings,
    long CriticalRecommendations, long HighRecommendations, long ExploitedRecommendations);

/// The collection the page shows and whether its rows are written. Collection null = no complete Detailed collection yet.
public sealed record SummaryGroupState(bool HasTables, int? CollectionId, DateTime? CollectionTime, DateTime? BuiltAt, long? Findings)
{
    public bool Prepared => BuiltAt is not null;
}

public interface ISummaryGroupsStore
{
    Task<SummaryGroupState> StateAsync(CancellationToken ct);
    /// The rows of one grouping, most findings first (then the key), rows skip+1 .. skip+take; counted = without the exempted findings.
    Task<(IReadOnlyList<SummaryGroupRow> Rows, long Total)> RowsAsync(int collectionId, string groupingId, bool counted, int skip, int take, string? search, CancellationToken ct);
    /// Department id (as text) -> its name; empty when the table is not there.
    Task<IReadOnlyDictionary<string, string>> DepartmentNamesAsync(CancellationToken ct);
}

public static class SummaryGroups
{
    /// The groupings, in the order the page lists them (the ids are the definition's -- a test holds the two together).
    public static readonly IReadOnlyList<SummaryGrouping> All =
    [
        new("recommendation-tier", "Per recommendation and tier (as the Summary report)", ["Recommendation", "Tier"]),
        new("recommendation", "Per recommendation", ["Recommendation"]),
        new("asset", "Per asset", ["Asset"]),
        new("tier", "Per tier", ["Tier"]),
        new("domain", "Per security domain", ["Domain"]),
        new("domain-category", "Per domain > category", ["Domain", "Category"]),
        new("domain-category-subcategory", "Per domain > category > subcategory", ["Domain", "Category", "Subcategory"]),
        new("risk-rating", "Per risk rating", ["Risk rating"]),
        new("department", "Per department", ["Department"]),
        new("severity", "Per severity", ["Severity"]),
        new("report", "Per report", ["Report"]),
        // #812: the named views Risk rating / MITRE ATT&CK / Compliance / CVSS read these (Pages/Collection/Views.cs)
        new("mitre-tactic", "Per MITRE ATT&CK tactic", ["Tactic"]),
        new("mitre-technique", "Per MITRE ATT&CK technique", ["Technique"]),
        new("compliance-control", "Per compliance control", ["Control"]),
        new("cvss-band", "Per CVSS band", ["CVSS band"]),
    ];

    public const string Default = "recommendation-tier";
    public static readonly int[] Sizes = [25, 50, 100, 500];
    public const int DefaultSize = 50;

    public static SummaryGrouping Of(string? id) => All.FirstOrDefault(g => g.Id.Equals(id ?? "", StringComparison.OrdinalIgnoreCase)) ?? All[0];

    public const string ProbeSql = """
SELECT CASE WHEN OBJECT_ID(N'sidata.SummaryGroup') IS NOT NULL AND OBJECT_ID(N'sidata.SummaryGroupCounted') IS NOT NULL AND OBJECT_ID(N'sidata.SummaryGroupState') IS NOT NULL THEN 1 ELSE 0 END AS HasTables
""";

    /// The published run's collection (one trusted run), and when its grouped rows were written (NULL = being prepared).
    public const string StateSql = $"""
SELECT TOP (1) c.CollectionId, c.CollectionTime, s.BuiltAt, s.Findings
FROM sidata.Collection AS c LEFT JOIN sidata.SummaryGroupState AS s ON s.CollectionId = c.CollectionId
WHERE c.CollectionId = {SI.Management.Core.ProData.PublishedRun.DetailedId}
""";

    private const string Columns = "g.Key1, g.Key2, g.Key3, g.Label, g.Findings, g.Assets, g.Recommendations, g.MaxRisk, g.TotalRisk, g.BestTier, g.Tier0Findings, g.CriticalFindings, g.HighFindings, g.CriticalRecommendations, g.HighRecommendations, g.ExploitedRecommendations";

    /// One grouping's page of rows (IX_SummaryGroup_Findings: CollectionId, GroupingId, Findings DESC). The department's name
    /// comes from its table when it is there.
    public static string RowsSql(bool counted) => $"""
SELECT {Columns}, COUNT_BIG(*) OVER () AS Total
FROM sidata.{(counted ? "SummaryGroupCounted" : "SummaryGroup")} AS g
WHERE g.CollectionId = @CollectionId AND g.GroupingId = @GroupingId
  AND (@Like IS NULL OR g.Key1 LIKE @Like ESCAPE '\' OR g.Key2 LIKE @Like ESCAPE '\' OR g.Key3 LIKE @Like ESCAPE '\' OR g.Label LIKE @Like ESCAPE '\')
ORDER BY g.Findings DESC, g.Key1, g.Key2, g.Key3
OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY
""";

    public const string DepartmentNamesSql = """
IF OBJECT_ID(N'cfg.Department') IS NOT NULL SELECT CONVERT(nvarchar(32), DepartmentId) AS Id, Name FROM cfg.Department
""";

    public static string? Like(string? search) => string.IsNullOrWhiteSpace(search) ? null
        : "%" + search.Trim().Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_").Replace("[", "\\[") + "%";

    /// A key as a person reads it: the tier as "Tier 0", department 0 as "Unassigned", an empty value as "(none)".
    public static string KeyText(string groupingId, int keyIndex, string key, IReadOnlyDictionary<string, string>? departments = null)
    {
        if (groupingId == "tier" && keyIndex == 0) return key.Length == 1 && char.IsDigit(key[0]) ? "Tier " + key : "Unclassified";
        if (groupingId == "department" && keyIndex == 0)
            return key == "0" ? "Unassigned" : departments is not null && departments.TryGetValue(key, out var n) ? n : "Department " + key;
        return key.Length == 0 ? "(none)" : key;
    }
}

public sealed class SqlSummaryGroupsStore(ISqlExecutor sql) : ISummaryGroupsStore
{
    private static Dictionary<string, object?> P(params (string K, object? V)[] p) => p.ToDictionary(x => x.K, x => x.V);

    public async Task<SummaryGroupState> StateAsync(CancellationToken ct)
    {
        var probe = (await sql.QueryAsync(SummaryGroups.ProbeSql, P(), ct)).FirstOrDefault();
        if ((probe?.Long("HasTables") ?? 0) != 1) return new(false, null, null, null, null);
        var r = (await sql.QueryAsync(SummaryGroups.StateSql, P(), ct)).FirstOrDefault();
        if (r?.Long("CollectionId") is not { } id) return new(true, null, null, null, null);
        static DateTime? Utc(DateTime? d) => d is { } x ? DateTime.SpecifyKind(x, DateTimeKind.Utc) : null;
        return new(true, (int)id, Utc(r.Date("CollectionTime")), Utc(r.Date("BuiltAt")), r.Long("Findings"));
    }

    public async Task<(IReadOnlyList<SummaryGroupRow> Rows, long Total)> RowsAsync(int collectionId, string groupingId, bool counted, int skip, int take, string? search, CancellationToken ct)
    {
        var rows = await sql.QueryAsync(SummaryGroups.RowsSql(counted), P(("CollectionId", collectionId), ("GroupingId", groupingId), ("Like", SummaryGroups.Like(search)),
            ("Skip", Math.Max(0, skip)), ("Take", Math.Clamp(take, 1, 500))), ct);
        static double? D(SqlRow r, string c) => r.TryGetValue(c, out var v) && v is not null ? Convert.ToDouble(v, CultureInfo.InvariantCulture) : null;
        var list = rows.Select(r => new SummaryGroupRow(r.Str("Key1") ?? "", r.Str("Key2") ?? "", r.Str("Key3") ?? "", r.Str("Label"), r.Long("Findings") ?? 0, r.Long("Assets") ?? 0,
            r.Long("Recommendations") ?? 0, D(r, "MaxRisk"), D(r, "TotalRisk"), r.Long("BestTier") is { } t ? (int)t : null, r.Long("Tier0Findings") ?? 0, r.Long("CriticalFindings") ?? 0,
            r.Long("HighFindings") ?? 0, r.Long("CriticalRecommendations") ?? 0, r.Long("HighRecommendations") ?? 0, r.Long("ExploitedRecommendations") ?? 0)).ToList();
        return (list, rows.FirstOrDefault()?.Long("Total") ?? 0);
    }

    public async Task<IReadOnlyDictionary<string, string>> DepartmentNamesAsync(CancellationToken ct)
    {
        try { return (await sql.QueryAsync(SummaryGroups.DepartmentNamesSql, P(), ct)).Where(r => r.Str("Id") is not null).ToDictionary(r => r.Str("Id")!, r => r.Str("Name") ?? ""); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return new Dictionary<string, string>(); }
    }
}
