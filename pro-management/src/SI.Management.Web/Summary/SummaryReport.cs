using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using SI.Management.Web.Data;

namespace SI.Management.Web.Summary;

// =====================================================================================================================
// RISKS > SUMMARY (REQUIREMENTS #583, owner 2026-10-11: "where in the gui do i find the report or view similar to this,
// where the findings are grouped with the most important assets (summary)" -- "the summary report shows by default any
// asset in the tier group with the most critical risk. mgmt friendly").
//
// The RiskAnalysis_Summary workbook's rows -- one row per recommendation x tier x severity x risk factors x CMDB group, with
// the assets it impacts -- read from the tables the data sync fills from SI_RiskAnalysis_Summary_CL
// (engine\_shared\data-sql\SI-DataSummary.ps1: sidata.SummaryLoad / SummaryRow / SummaryAsset). The newest COMPLETE
// Summary collection only. Every filter and the default order run on real, indexed columns: no JSON is parsed per row.
// Read-only statements; every caller value is a parameter.
// =====================================================================================================================

/// The newest complete Summary collection (sidata.SummaryLoad).
public sealed record SummaryLoad(DateTime CollectionTime, int? Rows, DateTime? LoadedAt, string? SolutionVersion);

/// What the database holds: the Summary tables, the CI tables (to link an asset to its CI), the newest collection.
public sealed record SummaryState(bool HasTables, bool HasCi, SummaryLoad? Latest)
{
    public static readonly SummaryState Missing = new(false, false, null);
}

/// One Summary row (sidata.SummaryRow). TierGroup: the tier, or <see cref="SummaryReport.NoTier"/> when the row has none.
public sealed record SummaryRowView(
    int RowNo, int TierGroup, string? SecurityDomain, string? Category, string? Subcategory, string? ConfigurationName, string? ConfigurationId,
    string? Impact, string? SecuritySeverity, int? CriticalityTier, string? CriticalityTierLevel,
    string? RiskFactorConsequenceDetailed, double? RiskFactorConsequence, string? RiskFactorProbabilityDetailed, string? RiskFactorIds, double? RiskFactorProbability,
    double? RiskConsequenceScore, double? RiskProbabilityScore, double? RiskScoreTotal, double? RiskScoreWeightFactor, string? RiskScoreWeightDetailed,
    double? RiskScoreTotalWeighted, string? RiskRating, int RatingRank, string? CmdbId, string? CmdbName, string? CmdbCriticality, string? CmdbDataSensitivity,
    long ImpactedAssetCount, string? ImpactedAssetsList, string? ImpactedAssetIds, string? MoreDetails, string? ReportName,
    string? MitreTactics, string? MitreTechniques, string? ComplianceTags);

/// One impacted asset of a Summary row, in the row's order; CiId = the CI it is (null = not resolved to a CI).
public sealed record SummaryAssetRef(int RowNo, int Ordinal, string? Name, string? AssetId, string? CiId)
{
    /// Where the asset's name links: its CI page, else the CI list searched for the name (or the id).
    public string Href => CiId is { Length: > 0 } ci ? "/Cis/Detail?id=" + Uri.EscapeDataString(ci)
        : "/Cis?q=" + Uri.EscapeDataString(Name ?? AssetId ?? "");
    public string Label => !string.IsNullOrWhiteSpace(Name) ? Name! : AssetId ?? "";
}

/// The headline of one tier: its recommendations (all, Critical, High) and the distinct assets they impact.
public sealed record SummaryTierHead(int TierGroup, long Recommendations, long Critical, long High, long Assets, long CriticalAssets, long CriticalHighAssets);

/// A value a filter offers (Facet = the filter, Value, N = rows with it).
public sealed record SummaryFacet(string Facet, string Value, long N);

/// The filters of the page. Every value is a parameter; Tier is 0..9 or <see cref="SummaryReport.NoTier"/>. Owner
/// 2026-10-19 ("all filters support multi select"): every filter may hold SEVERAL values -- the text filters '|'-joined
/// (<see cref="SI.Management.Core.ProData.ProDataFilters.ValueSeparator"/>), the tiers in <see cref="Tiers"/> -- OR-ed within a
/// filter, AND-ed across; each one an IN-list over a JSON array parameter.
public sealed record SummaryFilter(int? Tier = null, string? Rating = null, string? Severity = null, string? Domain = null, string? Category = null,
    string? Subcategory = null, string? Cmdb = null, string? Report = null, string? Search = null)
{
    /// Several tiers at once (null = <see cref="Tier"/> alone).
    public IReadOnlyList<int>? Tiers { get; init; }

    /// Every tier chosen (none = all).
    public IReadOnlyList<int> AllTiers => Tiers is { Count: > 0 } t ? t : Tier is { } one ? [one] : [];

    public bool Any => AllTiers.Count > 0 || Rating is not null || Severity is not null || Domain is not null || Category is not null || Subcategory is not null
        || Cmdb is not null || Report is not null || Search is not null;

    /// The LIKE pattern of the search (wildcards in the text are literal), or null.
    public string? Like => string.IsNullOrWhiteSpace(Search) ? null
        : "%" + Search.Trim().Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_").Replace("[", "\\[") + "%";

    private static string? Json(string? joined) => SI.Management.Core.ProData.ProDataFilters.Json(joined);

    public Dictionary<string, object?> Parameters(DateTime at) => new()
    {
        ["At"] = SummaryReport.SqlTime(at), ["Tiers"] = AllTiers.Count == 0 ? null : System.Text.Json.JsonSerializer.Serialize(AllTiers),
        ["Rating"] = Json(Rating), ["Severity"] = Json(Severity), ["Domain"] = Json(Domain), ["Category"] = Json(Category),
        ["Subcategory"] = Json(Subcategory), ["Cmdb"] = Json(Cmdb), ["Report"] = Json(Report), ["Like"] = Like,
    };
}

public interface ISummaryReportStore
{
    Task<SummaryState> StateAsync(CancellationToken ct);
    /// One headline per tier, over the filtered rows, Tier 0 first.
    Task<IReadOnlyList<SummaryTierHead>> HeadsAsync(DateTime at, SummaryFilter filter, CancellationToken ct);
    /// The filtered rows in THE default order -- per tier (Tier 0 first, no tier last), the most critical rating first, then
    /// the highest risk score -- rows <paramref name="skip"/>+1 .. skip+take of EACH tier. <paramref name="full"/> also reads the
    /// long text columns (the lists, MoreDetails) for the export.
    Task<IReadOnlyList<SummaryRowView>> RowsAsync(DateTime at, SummaryFilter filter, int skip, int take, bool full, CancellationToken ct);
    /// One row with every column (null = no such row).
    Task<SummaryRowView?> RowAsync(DateTime at, int rowNo, CancellationToken ct);
    /// The first <paramref name="perRow"/> impacted assets of each row (in the row's order), each resolved to its CI.
    Task<IReadOnlyList<SummaryAssetRef>> AssetsAsync(DateTime at, IReadOnlyCollection<int> rowNos, int perRow, bool hasCi, CancellationToken ct);
    /// The values each filter offers.
    Task<IReadOnlyList<SummaryFacet>> FacetsAsync(DateTime at, CancellationToken ct);
}

/// <summary>The statements and the words, shared by the page, the store and the tests.</summary>
public static class SummaryReport
{
    /// A collection time as the statements receive it (datetime2(3) text: a DateTime parameter would round the milliseconds).
    public static string SqlTime(DateTime at) => at.ToString("yyyy-MM-ddTHH:mm:ss.fff", CultureInfo.InvariantCulture);

    /// The tier group of a row without a tier: shown last, as "No tier".
    public const int NoTier = 99;
    /// How many impacted assets a row lists inline before "+ N more".
    public const int InlineAssets = 5;
    /// The rows per tier the page offers.
    public static readonly int[] Sizes = [10, 25, 50, 100, 500];
    public const int DefaultSize = 25;
    public static readonly IReadOnlyList<string> Ratings = ["Critical", "High", "Moderate", "Low"];

    public const string ProbeSql = """
SELECT CASE WHEN OBJECT_ID(N'sidata.SummaryLoad') IS NOT NULL AND OBJECT_ID(N'sidata.SummaryRow') IS NOT NULL AND OBJECT_ID(N'sidata.SummaryAsset') IS NOT NULL THEN 1 ELSE 0 END AS HasSummary,
       CASE WHEN OBJECT_ID(N'sidata.Ci') IS NOT NULL AND OBJECT_ID(N'sidata.CiLink') IS NOT NULL THEN 1 ELSE 0 END AS HasCi
""";

    /// ONE TRUSTED RUN (owner 2026-10-19): the published run's own Summary -- never one of a run that is not trusted yet.
    public const string LatestSql = $"""
SELECT TOP (1) CollectionTime, [Rows], LoadedAt, SolutionVersion FROM sidata.SummaryLoad
WHERE Status = N'Complete' AND CollectionTime = {SI.Management.Core.ProData.PublishedRun.SummaryTime}
""";

    /// The filtered rows of one collection, each with its tier group. Every filter is a parameter (NULL = all): one or more
    /// values each, as an IN-list over a JSON array (the statement text never depends on how many were chosen).
    private const string Filtered = """
SELECT s.*, COALESCE(CONVERT(int, s.CriticalityTier), 99) AS TierGroup
FROM sidata.SummaryRow AS s
WHERE s.CollectionTime = CONVERT(datetime2(3), @At, 126)
  AND (@Tiers IS NULL OR COALESCE(CONVERT(int, s.CriticalityTier), 99) IN (SELECT TRY_CONVERT(int, tv.[value]) FROM OPENJSON(@Tiers) AS tv))
  AND (@Rating IS NULL OR s.RiskRating IN (SELECT fv.[value] FROM OPENJSON(@Rating) AS fv))
  AND (@Severity IS NULL OR s.SecuritySeverity IN (SELECT fv.[value] FROM OPENJSON(@Severity) AS fv))
  AND (@Domain IS NULL OR s.SecurityDomain IN (SELECT fv.[value] FROM OPENJSON(@Domain) AS fv))
  AND (@Category IS NULL OR s.Category IN (SELECT fv.[value] FROM OPENJSON(@Category) AS fv))
  AND (@Subcategory IS NULL OR s.Subcategory IN (SELECT fv.[value] FROM OPENJSON(@Subcategory) AS fv))
  AND (@Cmdb IS NULL OR s.CmdbName IN (SELECT fv.[value] FROM OPENJSON(@Cmdb) AS fv))
  AND (@Report IS NULL OR s.ReportName IN (SELECT fv.[value] FROM OPENJSON(@Report) AS fv))
  AND (@Like IS NULL OR s.ConfigurationName LIKE @Like ESCAPE '\' OR s.ConfigurationId LIKE @Like ESCAPE '\' OR s.Category LIKE @Like ESCAPE '\'
       OR s.Subcategory LIKE @Like ESCAPE '\' OR s.CmdbName LIKE @Like ESCAPE '\'
       OR EXISTS (SELECT 1 FROM sidata.SummaryAsset AS x WHERE x.CollectionTime = s.CollectionTime AND x.RowNo = s.RowNo
                  AND (x.AssetName LIKE @Like ESCAPE '\' OR x.AssetId LIKE @Like ESCAPE '\')))
""";

    /// THE default order inside a tier: the most critical rating first, then the highest risk score (then the weighted
    /// score, then the row's own order, so the order is stable).
    public const string OrderInTier = "f.RatingRank, f.RiskScoreTotal DESC, f.RiskScoreTotalWeighted DESC, f.RowNo";

    /// The columns a page row shows (the long text columns are read only for the export and the one-row view).
    private const string ShortColumns = """
f.RowNo, f.TierGroup, f.SecurityDomain, f.Category, f.Subcategory, f.ConfigurationName, f.ConfigurationId, f.Impact, f.SecuritySeverity, f.CriticalityTier,
f.CriticalityTierLevel, f.RiskFactorConsequenceDetailed, f.RiskFactorConsequence, f.RiskFactorProbabilityDetailed, f.RiskFactorIds, f.RiskFactorProbability,
f.RiskConsequenceScore, f.RiskProbabilityScore, f.RiskScoreTotal, f.RiskScoreWeightFactor, f.RiskScoreWeightDetailed, f.RiskScoreTotalWeighted, f.RiskRating,
f.RatingRank, f.CmdbId, f.CmdbName, f.CmdbCriticality, f.CmdbDataSensitivity, f.ImpactedAssetCount, f.ReportName, f.MitreTactics, f.MitreTechniques, f.ComplianceTags
""";
    private const string LongColumns = ", f.ImpactedAssetsList, f.ImpactedAssetIds, f.MoreDetails";

    public static string RowsSql(bool full) => "WITH f AS (\n" + Filtered + "),\nr AS (SELECT " + ShortColumns + (full ? LongColumns : "")
        + ",\n  ROW_NUMBER() OVER (PARTITION BY f.TierGroup ORDER BY " + OrderInTier + ") AS Rn FROM f)\n"
        + "SELECT r.* FROM r WHERE r.Rn > @Skip AND r.Rn <= @Skip + @Take ORDER BY r.TierGroup, r.Rn\nOPTION (RECOMPILE)";

    public static readonly string HeadsSql = "WITH f AS (\n" + Filtered + """
),
h AS (SELECT f.TierGroup, COUNT_BIG(*) AS Recommendations, SUM(CASE WHEN f.RatingRank = 1 THEN 1 ELSE 0 END) AS CriticalRecs,
             SUM(CASE WHEN f.RatingRank = 2 THEN 1 ELSE 0 END) AS HighRecs FROM f GROUP BY f.TierGroup),
a AS (SELECT f.TierGroup, f.RatingRank, COALESCE(NULLIF(x.AssetId, N''), x.AssetName) AS AssetKey
      FROM f JOIN sidata.SummaryAsset AS x ON x.CollectionTime = CONVERT(datetime2(3), @At, 126) AND x.RowNo = f.RowNo),
k AS (SELECT a.TierGroup, COUNT_BIG(DISTINCT a.AssetKey) AS Assets,
             COUNT_BIG(DISTINCT CASE WHEN a.RatingRank = 1 THEN a.AssetKey END) AS CriticalAssets,
             COUNT_BIG(DISTINCT CASE WHEN a.RatingRank <= 2 THEN a.AssetKey END) AS CriticalHighAssets FROM a GROUP BY a.TierGroup)
SELECT h.TierGroup, h.Recommendations, h.CriticalRecs, h.HighRecs, ISNULL(k.Assets, 0) AS Assets, ISNULL(k.CriticalAssets, 0) AS CriticalAssets,
       ISNULL(k.CriticalHighAssets, 0) AS CriticalHighAssets
FROM h LEFT JOIN k ON k.TierGroup = h.TierGroup
ORDER BY h.TierGroup
OPTION (RECOMPILE)
""";

    public const string RowSql = """
SELECT s.*, COALESCE(CONVERT(int, s.CriticalityTier), 99) AS TierGroup FROM sidata.SummaryRow AS s WHERE s.CollectionTime = CONVERT(datetime2(3), @At, 126) AND s.RowNo = @RowNo
""";

    /// The first assets of each row; each resolved to its CI -- the CI id itself, or an id one of its linked objects carries.
    public static string AssetsSql(bool hasCi) => """
SELECT a.RowNo, a.Ordinal, a.AssetName, a.AssetId,
""" + (hasCi
        ? "       COALESCE((SELECT TOP (1) c.CiId FROM sidata.Ci AS c WHERE c.CiId = a.AssetId), (SELECT TOP (1) l.CiId FROM sidata.CiLink AS l WHERE l.NativeId = a.AssetId)) AS CiId\n"
        : "       CAST(NULL AS nvarchar(64)) AS CiId\n") + """
FROM sidata.SummaryAsset AS a
WHERE a.CollectionTime = CONVERT(datetime2(3), @At, 126) AND a.Ordinal < @PerRow AND a.RowNo IN (SELECT TRY_CONVERT(int, value) FROM STRING_SPLIT(@RowNos, N','))
ORDER BY a.RowNo, a.Ordinal
""";

    public const string FacetsSql = """
SELECT N'domain' AS Facet, s.SecurityDomain AS V, COUNT_BIG(*) AS N FROM sidata.SummaryRow AS s WHERE s.CollectionTime = CONVERT(datetime2(3), @At, 126) AND s.SecurityDomain IS NOT NULL GROUP BY s.SecurityDomain
UNION ALL SELECT N'category', s.Category, COUNT_BIG(*) FROM sidata.SummaryRow AS s WHERE s.CollectionTime = CONVERT(datetime2(3), @At, 126) AND s.Category IS NOT NULL GROUP BY s.Category
UNION ALL SELECT N'subcategory', s.Subcategory, COUNT_BIG(*) FROM sidata.SummaryRow AS s WHERE s.CollectionTime = CONVERT(datetime2(3), @At, 126) AND s.Subcategory IS NOT NULL GROUP BY s.Subcategory
UNION ALL SELECT N'severity', s.SecuritySeverity, COUNT_BIG(*) FROM sidata.SummaryRow AS s WHERE s.CollectionTime = CONVERT(datetime2(3), @At, 126) AND s.SecuritySeverity IS NOT NULL GROUP BY s.SecuritySeverity
UNION ALL SELECT N'rating', s.RiskRating, COUNT_BIG(*) FROM sidata.SummaryRow AS s WHERE s.CollectionTime = CONVERT(datetime2(3), @At, 126) AND s.RiskRating IS NOT NULL GROUP BY s.RiskRating
UNION ALL SELECT N'cmdb', s.CmdbName, COUNT_BIG(*) FROM sidata.SummaryRow AS s WHERE s.CollectionTime = CONVERT(datetime2(3), @At, 126) AND s.CmdbName IS NOT NULL GROUP BY s.CmdbName
UNION ALL SELECT N'report', s.ReportName, COUNT_BIG(*) FROM sidata.SummaryRow AS s WHERE s.CollectionTime = CONVERT(datetime2(3), @At, 126) AND s.ReportName IS NOT NULL GROUP BY s.ReportName
""";

    // ---- the words ----------------------------------------------------------------------------------------------

    /// "Tier 0" .. "Tier 3"; the group without a tier: "No tier".
    public static string TierLabel(int tierGroup) => tierGroup == NoTier ? "No tier" : "Tier " + tierGroup.ToString(CultureInfo.InvariantCulture);

    /// The rating's badge class: rating-critical / -high / -moderate / -low (else rating-none).
    public static string RatingClass(string? rating) => (rating ?? "").Trim().ToLowerInvariant() switch
    {
        "critical" => "rating-critical",
        "high" or "very high" => "rating-high",
        "moderate" or "medium" => "rating-moderate",
        "low" => "rating-low",
        _ => "rating-none",
    };

    /// The order of a rating, most critical first (the data sync stores the same rank: Get-SIDataSummaryRatingRank).
    public static int RatingRank(string? rating) => (rating ?? "").Trim().ToLowerInvariant() switch
    {
        "critical" => 1,
        "high" or "very high" => 2,
        "moderate" or "medium" => 3,
        "low" => 4,
        _ => 5,
    };

    /// A risk factor list in plain words: "HighMachineRisk;InternetExposed;RCE" -> "high machine risk, internet exposed, RCE".
    public static string Words(string? factors)
    {
        if (string.IsNullOrWhiteSpace(factors)) return "";
        var parts = factors.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(Word).Where(p => p.Length > 0);
        return string.Join(", ", parts);
    }

    private static string Word(string token)
    {
        if (token.Contains('_')) token = token.Replace('_', ' ');
        // split lower->Upper and ACRONYM->Word boundaries; keep an acronym (RCE, MFA) as it is
        var spaced = Regex.Replace(token, "(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ");
        var words = spaced.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(w => w.Length > 1 && w.All(char.IsUpper) ? w : w.ToLowerInvariant());
        return string.Join(" ", words);
    }

    /// The row's risk factors in words: "Consequence: ... · Likelihood: ..." (an empty side is left out).
    public static string FactorsText(SummaryRowView r)
    {
        var c = Words(r.RiskFactorConsequenceDetailed);
        var p = Words(r.RiskFactorProbabilityDetailed);
        var parts = new List<string>();
        if (c.Length > 0) parts.Add("Consequence: " + c);
        if (p.Length > 0) parts.Add("Likelihood: " + p);
        return string.Join(" · ", parts);
    }

    /// "Endpoint / Vulnerabilities / CVEs (Missing Updates)" -- the parts the row carries.
    public static string Path(SummaryRowView r) => string.Join(" / ", new[] { r.SecurityDomain, r.Category, r.Subcategory }.Where(s => !string.IsNullOrWhiteSpace(s)));

    // ---- the export: the workbook's Summary columns, in the workbook's order ---------------------------------------

    /// The RiskAnalysis_Summary workbook's columns (its rows sheet), in order -- the export carries exactly these.
    public static readonly IReadOnlyList<string> ExportColumns =
    [
        "SecurityDomain", "Category", "Subcategory", "ConfigurationName", "ConfigurationId", "Impact", "SecuritySeverity", "CriticalityTier",
        "CriticalityTierLevel", "RiskFactor_Consequence_Detailed", "RiskFactor_Consequence", "RiskFactor_Probability_Detailed", "RiskFactorIds",
        "RiskFactor_Probability", "RiskConsequenceScore", "RiskProbabilityScore", "RiskScoreTotal", "RiskScore_Weight_Factor", "RiskScore_Weight_Detailed",
        "RiskScoreTotal_Weighted", "RiskRating", "cmdbId", "cmdbName", "cmdbCriticality", "cmdbDataSensitivity", "ImpactedAssetCount", "ImpactedAssetsList",
        "ImpactedAssetIds", "MoreDetails", "AssetDetectedInReportName", "MITRE_Tactics", "MITRE_Techniques", "ComplianceTags",
    ];

    /// Excel's limit of one cell's text.
    public const int CellLimit = 32767;

    private static object? T(string? s) => string.IsNullOrEmpty(s) ? null : s.Length > CellLimit ? s[..CellLimit] : s;

    /// One row as the export's cells, in <see cref="ExportColumns"/> order (numbers stay numbers).
    public static IReadOnlyList<object?> ExportCells(SummaryRowView r) =>
    [
        T(r.SecurityDomain), T(r.Category), T(r.Subcategory), T(r.ConfigurationName), T(r.ConfigurationId), T(r.Impact), T(r.SecuritySeverity), r.CriticalityTier,
        T(r.CriticalityTierLevel), T(r.RiskFactorConsequenceDetailed), r.RiskFactorConsequence, T(r.RiskFactorProbabilityDetailed), T(r.RiskFactorIds),
        r.RiskFactorProbability, r.RiskConsequenceScore, r.RiskProbabilityScore, r.RiskScoreTotal, r.RiskScoreWeightFactor, T(r.RiskScoreWeightDetailed),
        r.RiskScoreTotalWeighted, T(r.RiskRating), T(r.CmdbId), T(r.CmdbName), T(r.CmdbCriticality), T(r.CmdbDataSensitivity), r.ImpactedAssetCount, T(r.ImpactedAssetsList),
        T(r.ImpactedAssetIds), T(r.MoreDetails), T(r.ReportName), T(r.MitreTactics), T(r.MitreTechniques), T(r.ComplianceTags),
    ];

    // ---- reading a row ------------------------------------------------------------------------------------------

    private static double? D(SqlRow r, string c) => r.TryGetValue(c, out var v) && v is not null && v is not DBNull ? Convert.ToDouble(v, CultureInfo.InvariantCulture) : null;
    private static int? I(SqlRow r, string c) => r.Long(c) is { } l ? (int)l : null;

    public static SummaryRowView ToRow(SqlRow r) => new(
        I(r, "RowNo") ?? 0, I(r, "TierGroup") ?? (I(r, "CriticalityTier") ?? NoTier), r.Str("SecurityDomain"), r.Str("Category"), r.Str("Subcategory"),
        r.Str("ConfigurationName"), r.Str("ConfigurationId"), r.Str("Impact"), r.Str("SecuritySeverity"), I(r, "CriticalityTier"), r.Str("CriticalityTierLevel"),
        r.Str("RiskFactorConsequenceDetailed"), D(r, "RiskFactorConsequence"), r.Str("RiskFactorProbabilityDetailed"), r.Str("RiskFactorIds"), D(r, "RiskFactorProbability"),
        D(r, "RiskConsequenceScore"), D(r, "RiskProbabilityScore"), D(r, "RiskScoreTotal"), D(r, "RiskScoreWeightFactor"), r.Str("RiskScoreWeightDetailed"),
        D(r, "RiskScoreTotalWeighted"), r.Str("RiskRating"), I(r, "RatingRank") ?? RatingRank(r.Str("RiskRating")), r.Str("CmdbId"), r.Str("CmdbName"),
        r.Str("CmdbCriticality"), r.Str("CmdbDataSensitivity"), r.Long("ImpactedAssetCount") ?? 0, r.Str("ImpactedAssetsList"), r.Str("ImpactedAssetIds"),
        r.Str("MoreDetails"), r.Str("ReportName"), r.Str("MitreTactics"), r.Str("MitreTechniques"), r.Str("ComplianceTags"));
}

/// <summary>The SQL implementation over <see cref="ISqlExecutor"/>.</summary>
public sealed class SqlSummaryReportStore(ISqlExecutor sql) : ISummaryReportStore
{
    private static Dictionary<string, object?> P(params (string K, object? V)[] p) => p.ToDictionary(x => x.K, x => x.V);

    public async Task<SummaryState> StateAsync(CancellationToken ct)
    {
        var probe = (await sql.QueryAsync(SummaryReport.ProbeSql, P(), ct)).FirstOrDefault();
        if ((probe?.Long("HasSummary") ?? 0) != 1) return SummaryState.Missing;
        var hasCi = (probe!.Long("HasCi") ?? 0) == 1;
        var l = (await sql.QueryAsync(SummaryReport.LatestSql, P(), ct)).FirstOrDefault();
        SummaryLoad? latest = l?.Date("CollectionTime") is { } at
            ? new SummaryLoad(DateTime.SpecifyKind(at, DateTimeKind.Utc), l.Long("Rows") is { } n ? (int)n : null,
                l.Date("LoadedAt") is { } la ? DateTime.SpecifyKind(la, DateTimeKind.Utc) : null, l.Str("SolutionVersion"))
            : null;
        return new SummaryState(true, hasCi, latest);
    }

    public async Task<IReadOnlyList<SummaryTierHead>> HeadsAsync(DateTime at, SummaryFilter filter, CancellationToken ct) =>
        (await sql.QueryAsync(SummaryReport.HeadsSql, filter.Parameters(at), ct)).Select(r => new SummaryTierHead(
            (int)(r.Long("TierGroup") ?? SummaryReport.NoTier), r.Long("Recommendations") ?? 0, r.Long("CriticalRecs") ?? 0, r.Long("HighRecs") ?? 0,
            r.Long("Assets") ?? 0, r.Long("CriticalAssets") ?? 0, r.Long("CriticalHighAssets") ?? 0)).ToList();

    public async Task<IReadOnlyList<SummaryRowView>> RowsAsync(DateTime at, SummaryFilter filter, int skip, int take, bool full, CancellationToken ct)
    {
        var p = filter.Parameters(at);
        p["Skip"] = Math.Max(0, skip);
        p["Take"] = Math.Max(1, take);
        return (await sql.QueryAsync(SummaryReport.RowsSql(full), p, ct)).Select(SummaryReport.ToRow).ToList();
    }

    public async Task<SummaryRowView?> RowAsync(DateTime at, int rowNo, CancellationToken ct) =>
        (await sql.QueryAsync(SummaryReport.RowSql, P(("At", SummaryReport.SqlTime(at)), ("RowNo", rowNo)), ct)).Select(SummaryReport.ToRow).FirstOrDefault();

    public async Task<IReadOnlyList<SummaryAssetRef>> AssetsAsync(DateTime at, IReadOnlyCollection<int> rowNos, int perRow, bool hasCi, CancellationToken ct)
    {
        if (rowNos.Count == 0) return Array.Empty<SummaryAssetRef>();
        var list = string.Join(",", rowNos.Distinct().Select(n => n.ToString(CultureInfo.InvariantCulture)));
        return (await sql.QueryAsync(SummaryReport.AssetsSql(hasCi), P(("At", SummaryReport.SqlTime(at)), ("PerRow", Math.Max(1, perRow)), ("RowNos", list)), ct))
            .Select(r => new SummaryAssetRef((int)(r.Long("RowNo") ?? 0), (int)(r.Long("Ordinal") ?? 0), r.Str("AssetName"), r.Str("AssetId"), r.Str("CiId"))).ToList();
    }

    public async Task<IReadOnlyList<SummaryFacet>> FacetsAsync(DateTime at, CancellationToken ct) =>
        (await sql.QueryAsync(SummaryReport.FacetsSql, P(("At", SummaryReport.SqlTime(at))), ct))
            .Select(r => new SummaryFacet(r.Str("Facet") ?? "", r.Str("V") ?? "", r.Long("N") ?? 0)).Where(f => f.Value.Length > 0).ToList();
}
