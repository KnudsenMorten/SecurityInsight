namespace SI.Management.Core.ProData;

/// <summary>
/// #910 (owner 2026-10-27: "maybe add it to the risk score page as a view"): THE EXPLAINED RISK SCORE -- one row per finding
/// of the collection with how its score was made. The score is the asset side times the vulnerability side; each side is a
/// base (the risk index) plus the impacts of the factors that counted; the weighted score is the score times the weight.
/// Risk Analysis writes every part on the finding's row document (sidata.Finding.DetailJson): the sides
/// (RiskConsequenceScore / RiskProbabilityScore), the factor names (RiskFactor_*_Detailed) and their impact sums
/// (RiskFactor_*), the weight (RiskScore_Weight_Factor, in %) and what set it (RiskScore_Weight_Detailed) -- and, since the
/// explained score, each side's base (RiskConsequenceBase / RiskProbabilityBase) and each factor's impact
/// (RiskFactor_*_Impacts, "Name=impact;..."). A collection written before has no bases and no per-factor impacts: the page
/// works the base out as the side minus its factors' sum and says so.
/// Same rules as <see cref="CollectionViewSql"/>: fixed text, every caller value a parameter, set-based, one collection. The
/// opening page (sorted on the risk score, nothing narrowing it) reads its keys off the risk-score index
/// (<see cref="CollectionViewSql.Rows"/>' keyset) and reads the row documents of THAT page only; the document's parts are
/// neither sorted, filtered nor searched (only the typed columns are), so no request reads every document of the collection
/// to choose its page.
/// </summary>
public static class RiskExplainSql
{
    /// The grid's name: a finding-rows grid ("rows..." -- the CI lifecycle choice applies, <see cref="CollectionViewSql.WithLifecycle"/>).
    public const string Name = "rowsexplain";

    private static string J(string field) => $"JSON_VALUE(f.DetailJson, '$.{field}')";

    public static readonly GridSpec Grid = GridSql.Check(new GridSpec(Name, "", $"""
SELECT CONVERT(nvarchar(64), f.FindingId) AS FindingId, f.AssetKey, f.AssetName, {ProDataSql.TierExpr("f.Tier")} AS Tier,
       f.Title, f.Cve, f.Severity, f.RiskScore, f.RiskScoreWeighted, f.RiskRating, f.SecurityDomain, f.ReportName, f.DepartmentName AS Department,
       {J("RiskConsequenceBase")} AS AssetBase, {J("RiskFactor_Consequence_Impacts")} AS AssetFactors, {J("RiskConsequenceScore")} AS AssetSide,
       {J("RiskFactor_Consequence_Detailed")} AS AssetFactorNames, {J("RiskFactor_Consequence")} AS AssetFactorSum,
       {J("RiskProbabilityBase")} AS VulnBase, {J("RiskFactor_Probability_Impacts")} AS VulnFactors, {J("RiskProbabilityScore")} AS VulnSide,
       {J("RiskFactor_Probability_Detailed")} AS VulnFactorNames, {J("RiskFactor_Probability")} AS VulnFactorSum,
       {J("RiskScore_Weight_Factor")} AS Weight, {J("RiskScore_Weight_Detailed")} AS WeightBy, N'' AS Formula
FROM sidata.Finding AS f
WHERE {CollectionViewSql.ThisCollection}
""", new GridColumn[]
    {
        new("FindingId", "Id", Hidden: true),
        new("AssetKey", "Asset key", Search: true, Hidden: true),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: "CASE WHEN g.[Tier] = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, g.[Tier]) END"),
        new("AssetName", "Asset", Filter: GridFilter.Contains, Search: true),
        new("Title", "Finding", Filter: GridFilter.Contains, Search: true),
        new("Cve", "CVE", Filter: GridFilter.Contains, Search: true),
        new("Severity", "Severity", Filter: GridFilter.Values, SortSql: CollectionViewSql.SeverityRank("g.[Severity]"), Hidden: true),
        // the parts of the score: read from the row document, shown -- never sorted, filtered or searched (see above)
        new("AssetBase", "Asset base", Sortable: false),
        new("AssetFactors", "Asset factors", Sortable: false),
        new("AssetSide", "Asset side (consequence)", Sortable: false),
        new("VulnBase", "Vulnerability base", Sortable: false),
        new("VulnFactors", "Vulnerability factors", Sortable: false),
        new("VulnSide", "Vulnerability side (probability)", Sortable: false),
        new("RiskScore", "Risk Score", GridType.Number, GridFilter.Range),
        new("Weight", "Weight", Sortable: false),
        new("RiskScoreWeighted", "Weighted", GridType.Number, GridFilter.Range),
        new("RiskRating", "Rating", Filter: GridFilter.Values, SortSql: CollectionViewSql.RatingRank("g.[RiskRating]")),
        new("Formula", "Formula", Sortable: false),
        // what the shown parts are worked out from (an older collection: the names and the sums only)
        new("AssetFactorNames", "Asset factor names", Sortable: false, Hidden: true),
        new("AssetFactorSum", "Asset factor points", Sortable: false, Hidden: true),
        new("VulnFactorNames", "Vulnerability factor names", Sortable: false, Hidden: true),
        new("VulnFactorSum", "Vulnerability factor points", Sortable: false, Hidden: true),
        new("WeightBy", "Weight set by", Sortable: false, Hidden: true),
        new("SecurityDomain", "Domain", Filter: GridFilter.Values, Hidden: true),
        new("ReportName", "Report", Filter: GridFilter.Values, Hidden: true),
        new("Department", "Department", Filter: GridFilter.Values, Hidden: true),
    }, "RiskScore", true, "FindingId", ["CollectionId"], Immutable: true,
        Keyset: CollectionViewSql.Rows.Keyset, KeySortSql: CollectionViewSql.RowKeySort));

    /// <summary>
    /// The same grid over the parts as STORED COLUMNS (sidata.Finding.Risk<Side>*, filled by the data sync -- a collection
    /// stamped sidata.Collection.RiskPartsAt): no JSON read at all; the bases and sides sort and filter as numbers (the sides
    /// page off their own index, <see cref="CollectionViewSql.Rows"/>' keyset), the factors filter as text.
    /// </summary>
    public static readonly GridSpec GridStored = GridSql.Check(new GridSpec(Name, "", $"""
SELECT CONVERT(nvarchar(64), f.FindingId) AS FindingId, f.AssetKey, f.AssetName, {ProDataSql.TierExpr("f.Tier")} AS Tier,
       f.Title, f.Cve, f.Severity, f.RiskScore, f.RiskScoreWeighted, f.RiskRating, f.SecurityDomain, f.ReportName, f.DepartmentName AS Department,
       {CollectionViewSql.RiskPartsSelect},
       f.RiskWeightPct AS Weight, f.RiskWeightBy AS WeightBy, N'' AS Formula
FROM sidata.Finding AS f
WHERE {CollectionViewSql.ThisCollection}
""", [
        new("FindingId", "Id", Hidden: true),
        new("AssetKey", "Asset key", Search: true, Hidden: true),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: "CASE WHEN g.[Tier] = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, g.[Tier]) END"),
        new("AssetName", "Asset", Filter: GridFilter.Contains, Search: true),
        new("Title", "Finding", Filter: GridFilter.Contains, Search: true),
        new("Cve", "CVE", Filter: GridFilter.Contains, Search: true),
        new("Severity", "Severity", Filter: GridFilter.Values, SortSql: CollectionViewSql.SeverityRank("g.[Severity]"), Hidden: true),
        .. CollectionViewSql.RiskPartColumns,
        new("RiskScore", "Risk Score", GridType.Number, GridFilter.Range),
        new("Weight", "Weight", Sortable: false),
        new("RiskScoreWeighted", "Weighted", GridType.Number, GridFilter.Range),
        new("RiskRating", "Rating", Filter: GridFilter.Values, SortSql: CollectionViewSql.RatingRank("g.[RiskRating]")),
        new("Formula", "Formula", Sortable: false),
        new("WeightBy", "Weight set by", Sortable: false, Hidden: true),
        new("SecurityDomain", "Domain", Filter: GridFilter.Values, Hidden: true),
        new("ReportName", "Report", Filter: GridFilter.Values, Hidden: true),
        new("Department", "Department", Filter: GridFilter.Values, Hidden: true),
    ], "RiskScore", true, "FindingId", ["CollectionId"], Immutable: true,
        Keyset: CollectionViewSql.Rows.Keyset, KeySortSql: CollectionViewSql.RowKeySort));
}
