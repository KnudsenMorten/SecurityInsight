namespace SI.Management.Core.ProData;

/// <summary>
/// #812 (owner rule "SI views: SQL-cached + indexed columns"; a large customer, 1,117,524 findings): the named views Risk rating,
/// MITRE ATT&amp;CK, Compliance and CVSS page the #636 GROUPINGS of the Detailed findings -- ONE definition
/// (data-model\summary-groupings.locked.json: risk-rating, mitre-tactic, mitre-technique, compliance-control, cvss-band), ONE
/// engine function (engine\_shared\SI-SummaryGroupings.ps1), written once per collection by the data sync into
/// sidata.SummaryGroup / SummaryGroupCounted / SummaryGroupState. These views no longer count and sort every finding row of the
/// collection per request (the Raw rows grid they carried); a group row opens the Raw rows filtered on its value.
/// The exempted scope reads the counted twin through the #264 rewrite (<see cref="Exempted.Twins"/>). A collection whose state
/// row does not name the grouping is never read here: the page says it is being prepared (<see cref="State"/>).
/// </summary>
public static class SummaryGroupViewSql
{
    /// One named view's grouping: the grid name, the grouping id in the definition, the words of its key, the Raw rows column
    /// a key filters (null = none), and how a key becomes that filter's value (null = the key itself).
    public sealed record View(string Grid, string GroupingId, string KeyLabel, string? RowsColumn, Func<string, string?>? RowsValue = null);

    public static readonly View RiskRating = new("grprating", "risk-rating", "Risk rating", "RiskRating");
    public static readonly View MitreTactic = new("grptactic", "mitre-tactic", "Tactic", "MitreTactics");
    public static readonly View MitreTechnique = new("grptechnique", "mitre-technique", "Technique", "MitreTechniques");
    public static readonly View Compliance = new("grpcontrol", "compliance-control", "Compliance control", "ComplianceTags");
    public static readonly View Cvss = new("grpcvss", "cvss-band", "CVSS band", "Cvss", CvssRange);

    public static readonly IReadOnlyList<View> All = [RiskRating, MitreTactic, MitreTechnique, Compliance, Cvss];

    /// A CVSS band as the CVSS range the Raw rows filter on (the bands of sidata.FindingFacet's 'cvss' facet).
    public static string? CvssRange(string band) => band switch
    {
        "Critical (9.0-10)" => "9..10", "High (7.0-8.9)" => "7..8.99", "Medium (4.0-6.9)" => "4..6.99", "Low (0.1-3.9)" => "0.1..3.99", "None (0)" => "0..0", _ => null,
    };

    /// The grouping's rows of the collection (typed columns; IX_SummaryGroup_Findings = CollectionId, GroupingId, Findings DESC).
    public static readonly string Source = $"""
SELECT g.Key1 AS [Key], g.Findings, g.Assets, g.Recommendations, g.MaxRisk, g.TotalRisk, {ProDataSql.TierExpr("g.BestTier")} AS Tier,
       g.Tier0Findings, g.CriticalFindings, g.HighFindings, g.RatedCriticalFindings, g.RatedHighFindings, g.ExploitedRecommendations
FROM sidata.SummaryGroup AS g
WHERE g.CollectionId = TRY_CONVERT(int, @CollectionId) AND g.GroupingId = @GroupingId
""";

    private static readonly string TierSort = "CASE WHEN g.[Tier] = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, g.[Tier]) END";

    /// The grid of one named view (most findings first).
    public static GridSpec Spec(View v) => GridSql.Check(new GridSpec(v.Grid, "", Source, new GridColumn[]
    {
        new("Key", v.KeyLabel, Filter: GridFilter.Contains, Search: true),
        new("Findings", "Findings", GridType.Number, GridFilter.Range),
        new("Assets", "Assets", GridType.Number, GridFilter.Range),
        new("Recommendations", "Recommendations / CVEs", GridType.Number, GridFilter.Range),
        new("Tier", "Most critical tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        new("Tier0Findings", "On tier 0", GridType.Number, GridFilter.Range),
        new("CriticalFindings", "Very high severity", GridType.Number, GridFilter.Range),
        new("HighFindings", "High severity", GridType.Number, GridFilter.Range),
        new("RatedCriticalFindings", "Rated critical", GridType.Number, GridFilter.Range),
        new("RatedHighFindings", "Rated high", GridType.Number, GridFilter.Range),
        new("ExploitedRecommendations", "With a known exploit", GridType.Number, GridFilter.Range),
        new("MaxRisk", "Highest risk", GridType.Number, GridFilter.Range),
        new("TotalRisk", "Total risk", GridType.Number, GridFilter.Range),
    }, "Findings", true, "Key", ["CollectionId", "GroupingId"], Immutable: true));

    /// Whether the collection's grouped rows are written and hold the grouping (Groupings = ';id;id;'); BuiltAt for the cache scope.
    /// A database without the tables (or the Groupings column) answers "Invalid object name" / "Invalid column name".
    public const string State = """
SELECT s.BuiltAt, CASE WHEN s.Groupings LIKE N'%;' + @GroupingId + N';%' THEN 1 ELSE 0 END AS HasGrouping
FROM sidata.SummaryGroupState AS s
WHERE s.CollectionId = TRY_CONVERT(int, @CollectionId);
""";
}

/// Whether a collection's grouped rows of one grouping are written: Schema = the tables are there; BuiltAt = when (null = not
/// yet, or the rows do not hold this grouping: the page says it is being prepared).
public sealed record GroupingState(bool Schema, DateTime? BuiltAt)
{
    /// What a reader that does not keep the state answers (the test fakes, the demo).
    public static GroupingState Ready { get; } = new(true, DateTime.MaxValue);
    public bool Built => Schema && BuiltAt is not null;
    public string Version => BuiltAt?.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "0";
}
