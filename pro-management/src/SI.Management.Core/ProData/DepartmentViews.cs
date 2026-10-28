using System.Text.Json;

namespace SI.Management.Core.ProData;

/// <summary>
/// ASSET RESPONSIBILITY (REQUIREMENTS #254, phase 1) -- the read side. The data sync has already stamped every finding
/// with its department (sidata.Finding.DepartmentId + ResponsibilitySource) and aggregated each collection per department
/// (sidata.DepartmentFacet), so every read here is a key lookup or a precomputed row: no resolution per request, never
/// Log Analytics. Department 0 in the aggregates = Unassigned.
/// </summary>
public static class DepartmentSql
{
    /// Department id 0 in sidata.DepartmentFacet: the findings no department is responsible for.
    public const int Unassigned = 0;

    /// #855 (owner 2026-10-21: "default filter is active, so it should be active only"): the departments count the findings
    /// of ACTIVE CIs only -- sidata.DepartmentFacet is built over them (its key cannot take the lifecycle); the findings grid,
    /// the services and the owned CIs follow the same rule. A finding no CI carries counts as active.
    public const string ActiveFindings = "(f.CiLifecycle = N'active' OR f.CiLifecycle IS NULL)";

    /// One department's findings of a collection (or the Unassigned ones), with where the answer came from. Shown through
    /// the shared grid. Not immutable: an Admin's override re-resolves the collection on the next data sync.
    /// #855: the findings of ACTIVE CIs only -- as the department's counts above them (sidata.DepartmentFacet is built over
    /// active CIs); the pages say so (LifecycleFilter.ActiveOnlyWords).
    public static readonly GridSpec Findings = GridSql.Check(new GridSpec("department", "", $"""
SELECT CONVERT(nvarchar(64), f.FindingId) AS FindingId, f.AssetKey, f.AssetName, a.AssetKind, {ProDataSql.AssetKindsExpr("a")} AS AssetKinds, {ProDataSql.TierExpr("f.Tier")} AS Tier,
       f.Severity, f.RiskScore, f.RiskScoreWeighted, f.SecurityDomain, f.Cve, f.ConfigurationId,
       COALESCE(f.ConfigurationId, f.Cve) AS RecommendationKey, f.Title, d.Name AS Department, f.ResponsibilitySource, f.ResponsibilityDetail
FROM sidata.Finding AS f
LEFT JOIN sidata.Asset AS a ON a.AssetKey = f.AssetKey
LEFT JOIN cfg.Department AS d ON d.DepartmentId = f.DepartmentId
WHERE {CollectionViewSql.ThisCollection} AND {ActiveFindings}
  AND ((@Unassigned = 1 AND f.DepartmentId IS NULL) OR (@Unassigned = 0 AND (@DepartmentId IS NULL OR f.DepartmentId = TRY_CONVERT(int, @DepartmentId))))
""", new GridColumn[]
    {
        new("FindingId", "Id", Hidden: true),
        new("AssetKey", "Asset key", Search: true, Hidden: true),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: "CASE WHEN g.[Tier] = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, g.[Tier]) END"),
        new("AssetName", "Asset", Filter: GridFilter.Contains, Search: true),
        GridColumn.AssetKind(),
        new("Title", "Finding", Filter: GridFilter.Contains, Search: true),
        new("RecommendationKey", "Recommendation", Filter: GridFilter.Contains, Search: true),
        new("Cve", "CVE", Filter: GridFilter.Contains, Search: true, Hidden: true),
        new("ConfigurationId", "Configuration", Filter: GridFilter.Contains, Hidden: true),
        new("Severity", "Severity", Filter: GridFilter.Values, SortSql: CollectionViewSql.SeverityRank("g.[Severity]")),
        new("RiskScore", "Risk", GridType.Number, GridFilter.Range),
        new("RiskScoreWeighted", "Weighted", GridType.Number, GridFilter.Range),
        new("SecurityDomain", "Domain", Filter: GridFilter.Values),
        new("Department", "Department", Filter: GridFilter.Values),
        new("ResponsibilitySource", "Placed by", Filter: GridFilter.Values),
        new("ResponsibilityDetail", "Why", Filter: GridFilter.Contains, Search: true),
    }, "RiskScoreWeighted", true, "FindingId", ["CollectionId", "DepartmentId", "Unassigned"], Immutable: false));

    /// The responsibility sources as the data sync writes them, in precedence order.
    public static readonly IReadOnlyList<string> Sources = ["recommendation-override", "asset-override", "tag", "rule", "default", "unassigned"];

    public const string FacetsOfCollection = """
SELECT df.DepartmentId, COALESCE(d.Name, CASE WHEN df.DepartmentId = 0 THEN N'Unassigned' ELSE CONCAT(N'Department ', df.DepartmentId) END) AS Name,
       df.Severity, df.Tier, df.Findings, df.Assets, df.ScoreTotal, df.WeightedTotal
FROM sidata.DepartmentFacet AS df
LEFT JOIN cfg.Department AS d ON d.DepartmentId = df.DepartmentId
WHERE df.CollectionId = TRY_CONVERT(int, @CollectionId)
ORDER BY df.DepartmentId, df.Severity, df.Tier;
""";

    /// The department's figures per collection, newest first -- never past the published run.
    public const string Trend = $"""
SELECT TOP (@Top) CONVERT(nvarchar(64), c.CollectionId) AS CollectionId, c.CollectionTime, df.Findings, df.Assets, df.ScoreTotal, df.WeightedTotal
FROM sidata.DepartmentFacet AS df
JOIN sidata.Collection AS c ON c.CollectionId = df.CollectionId
WHERE df.DepartmentId = @DepartmentId AND df.Severity = N'*' AND df.Tier = N'*' AND c.Status = N'Complete' AND c.Kind = N'Detailed'
  AND c.CollectionTime <= ISNULL({PublishedRun.DetailedTime}, c.CollectionTime)
ORDER BY c.CollectionTime DESC;
""";

    /// The ACTIVE CIs each department owns now (sidata.Asset's own resolution; NULL = Unassigned -> 0). #855: a CI that is not
    /// seen or retired (sidata.Ci.Lifecycle) is not counted; an asset without a CI row counts as active.
    public const string AssetCounts = """
SELECT ISNULL(a.DepartmentId, 0) AS DepartmentId, COUNT_BIG(*) AS Assets
FROM sidata.Asset AS a
LEFT JOIN sidata.Ci AS ci ON ci.CiId = a.AssetKey
WHERE ISNULL(NULLIF(ci.Lifecycle, N'), N'active') = N'active'
GROUP BY ISNULL(a.DepartmentId, 0);
""";

    /// The department's CMDB services in the collection -- from the ONE service-membership resolver the Services view uses
    /// (sidata.ServiceMember, #255) -- with the department's CIs in each and the weighted risk of the department's findings
    /// on them. Key sets built once and joined (no per-row lookup).
    public const string Services = """
WITH s AS (
    SELECT sm.ServiceKey, MAX(COALESCE(sm.ServiceName, sm.ServiceKey)) AS ServiceName, sm.AssetKey
    FROM sidata.ServiceMember AS sm
    JOIN sidata.Asset AS a ON a.AssetKey = sm.AssetKey AND a.DepartmentId = @DepartmentId
    WHERE sm.CollectionId = TRY_CONVERT(int, @CollectionId)
    GROUP BY sm.ServiceKey, sm.AssetKey
), f AS (
    SELECT x.AssetKey, COUNT_BIG(*) AS Findings, SUM(x.RiskScoreWeighted) AS Weighted
    FROM sidata.Finding AS x
    WHERE x.CollectionId = TRY_CONVERT(int, @CollectionId) AND x.DepartmentId = @DepartmentId AND (x.CiLifecycle = N'active' OR x.CiLifecycle IS NULL)
    GROUP BY x.AssetKey
)
SELECT TOP (100) MAX(s.ServiceName) AS Service, COUNT_BIG(DISTINCT s.AssetKey) AS Assets, SUM(COALESCE(f.Findings, 0)) AS Findings, SUM(f.Weighted) AS Weighted
FROM s LEFT JOIN f ON f.AssetKey = s.AssetKey
GROUP BY s.ServiceKey
ORDER BY SUM(f.Weighted) DESC, MAX(s.ServiceName);
""";

    /// Departments by id -> name (active and retired), for the pages' labels.
    public const string Names = """
IF OBJECT_ID(N'cfg.Department') IS NOT NULL
SELECT d.DepartmentId, d.Name, CASE WHEN d.RetiredAt IS NULL THEN 0 ELSE 1 END AS Retired FROM cfg.Department AS d ORDER BY d.Name;
""";
}

public sealed record DepartmentName(int DepartmentId, string Name, bool Retired);
public sealed record DepartmentFacetRow(int DepartmentId, string Name, string Severity, string Tier, long Findings, long Assets, double ScoreTotal, double? WeightedTotal);
public sealed record DepartmentTrendPoint(string CollectionId, DateTime CollectionTime, long Findings, long Assets, double ScoreTotal, double? WeightedTotal);
public sealed record DepartmentServiceRow(string Service, long Assets, long Findings, double? Weighted);

/// One department's summary in one collection, from its precomputed rows.
public sealed record DepartmentSummary(int DepartmentId, string Name, long Findings, long FindingAssets, double ScoreTotal, double? WeightedTotal,
    IReadOnlyDictionary<string, long> BySeverity, IReadOnlyDictionary<string, long> ByTier)
{
    public long Count(string severity) => BySeverity.Where(kv => string.Equals(kv.Key, severity, StringComparison.OrdinalIgnoreCase)).Sum(kv => kv.Value);
    public long Critical => Count("Critical") + Count("Very High");
    public long High => Count("High");

    /// The summaries of every department in a collection's aggregate rows.
    public static IReadOnlyList<DepartmentSummary> From(IEnumerable<DepartmentFacetRow> rows) =>
        rows.GroupBy(r => r.DepartmentId).Select(g =>
        {
            var total = g.FirstOrDefault(r => r.Severity == "*" && r.Tier == "*");
            return new DepartmentSummary(g.Key, g.First().Name, total?.Findings ?? 0, total?.Assets ?? 0, total?.ScoreTotal ?? 0, total?.WeightedTotal,
                g.Where(r => r.Severity != "*" && r.Tier == "*").ToDictionary(r => r.Severity, r => r.Findings, StringComparer.OrdinalIgnoreCase),
                g.Where(r => r.Tier != "*" && r.Severity == "*").ToDictionary(r => r.Tier, r => r.Findings, StringComparer.OrdinalIgnoreCase));
        }).OrderByDescending(s => s.WeightedTotal ?? s.ScoreTotal).ToList();
}

/// <summary>The reads of the department pages. Every result carries its statement.</summary>
public interface IDepartmentViews
{
    Task<QueryResult<IReadOnlyList<DepartmentName>>> NamesAsync(CancellationToken ct);
    Task<QueryResult<IReadOnlyList<DepartmentFacetRow>>> FacetsAsync(ViewCollection collection, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<DepartmentTrendPoint>>> TrendAsync(int departmentId, int top, CancellationToken ct);
    Task<QueryResult<IReadOnlyDictionary<int, long>>> AssetCountsAsync(CancellationToken ct);
    Task<QueryResult<IReadOnlyList<DepartmentServiceRow>>> ServicesAsync(ViewCollection collection, int departmentId, CancellationToken ct);
}

public sealed class DepartmentViews : IDepartmentViews
{
    private readonly IProSql _sql;
    private readonly TimeProvider _clock;
    public DepartmentViews(IProSql sql, TimeProvider? clock = null) { _sql = sql; _clock = clock ?? TimeProvider.System; }

    private async Task<(IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows, string Text)> Run(SqlQuery q, CancellationToken ct)
    {
        q = Exempted.Apply(q);   // #264: the request's exempted scope, before it runs and is described
        // Names starts with IF OBJECT_ID (a missing table reads as no rows): checked as the SELECT it guards
        SqlGuard.AssertReadOnly(q.Text.StartsWith("IF ", StringComparison.Ordinal) ? q.Text[(q.Text.IndexOf("SELECT", StringComparison.Ordinal))..] : q.Text);
        return (await ViewTimeout.Run(t => _sql.QueryAsync(q, t), CollectionViews.Timeout, ct).ConfigureAwait(false), EstateQueries.DescribeSql(q.Text, q.Parameters));
    }

    private QueryResult<T> R<T>(T data, string text) => new(data, text, _sql.SourceName, _clock.GetUtcNow());
    private static int I(IReadOnlyDictionary<string, object?> r, string c) => (int)ProDataQueries.L(r, c);

    public async Task<QueryResult<IReadOnlyList<DepartmentName>>> NamesAsync(CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(DepartmentSql.Names, new Dictionary<string, object?>()), ct).ConfigureAwait(false);
        return R<IReadOnlyList<DepartmentName>>(rows.Select(r => new DepartmentName(I(r, "DepartmentId"), ProDataQueries.S(r, "Name"), ProDataQueries.L(r, "Retired") == 1)).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<DepartmentFacetRow>>> FacetsAsync(ViewCollection collection, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(DepartmentSql.FacetsOfCollection, new Dictionary<string, object?> { ["CollectionId"] = CollectionViewSql.CollectionId(collection.CollectionId) }), ct).ConfigureAwait(false);
        return R<IReadOnlyList<DepartmentFacetRow>>(rows.Select(r => new DepartmentFacetRow(I(r, "DepartmentId"), ProDataQueries.S(r, "Name"), ProDataQueries.S(r, "Severity"),
            ProDataQueries.S(r, "Tier"), ProDataQueries.L(r, "Findings"), ProDataQueries.L(r, "Assets"), ProDataQueries.D(r, "ScoreTotal"), ProDataQueries.DN(r, "WeightedTotal"))).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyList<DepartmentTrendPoint>>> TrendAsync(int departmentId, int top, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(DepartmentSql.Trend, new Dictionary<string, object?> { ["DepartmentId"] = departmentId, ["Top"] = Math.Clamp(top, 1, 500) }), ct).ConfigureAwait(false);
        return R<IReadOnlyList<DepartmentTrendPoint>>(rows.Select(r => new DepartmentTrendPoint(ProDataQueries.S(r, "CollectionId"), ProDataQueries.T(r, "CollectionTime") ?? default,
            ProDataQueries.L(r, "Findings"), ProDataQueries.L(r, "Assets"), ProDataQueries.D(r, "ScoreTotal"), ProDataQueries.DN(r, "WeightedTotal"))).OrderBy(p => p.CollectionTime).ToList(), text);
    }

    public async Task<QueryResult<IReadOnlyDictionary<int, long>>> AssetCountsAsync(CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(DepartmentSql.AssetCounts, new Dictionary<string, object?>()), ct).ConfigureAwait(false);
        return R<IReadOnlyDictionary<int, long>>(rows.ToDictionary(r => I(r, "DepartmentId"), r => ProDataQueries.L(r, "Assets")), text);
    }

    public async Task<QueryResult<IReadOnlyList<DepartmentServiceRow>>> ServicesAsync(ViewCollection collection, int departmentId, CancellationToken ct)
    {
        var (rows, text) = await Run(new SqlQuery(DepartmentSql.Services, new Dictionary<string, object?>
        {
            ["CollectionId"] = CollectionViewSql.CollectionId(collection.CollectionId), ["DepartmentId"] = departmentId,
        }), ct).ConfigureAwait(false);
        return R<IReadOnlyList<DepartmentServiceRow>>(rows.Select(r => new DepartmentServiceRow(ProDataQueries.S(r, "Service"), ProDataQueries.L(r, "Assets"),
            ProDataQueries.L(r, "Findings"), ProDataQueries.DN(r, "Weighted"))).ToList(), text);
    }
}

// =====================================================================================================================
//  THE DELEGATED SCOPE TYPE "department" (#253 x #254)
// =====================================================================================================================

/// <summary>
/// The rows a department-scoped user may see: <c>f.DepartmentId</c> in their departments. Same shape as the role
/// framework's visibility predicate (lane-roles: <c>VisibilityPredicate(Sql, Parameters)</c> over the finding alias f):
/// a fixed text plus every value as a parameter. <see cref="DepartmentScope.Predicate"/> builds it;
/// <see cref="DepartmentScope.Restrict"/> applies it to any grid whose source reads one collection's findings.
/// </summary>
public sealed record DepartmentVisibility(IReadOnlyList<int> Departments)
{
    /// The predicate over sidata.Finding AS f. No department = sees nothing.
    public string Sql => Departments.Count == 0 ? "1 = 0" : $"{DepartmentScope.ColumnSql} IN (SELECT TRY_CONVERT(int, sd.[value]) FROM OPENJSON(@{DepartmentScope.Parameter}) AS sd)";
    public IReadOnlyDictionary<string, object?> Parameters => new Dictionary<string, object?> { [DepartmentScope.Parameter] = JsonSerializer.Serialize(Departments.Distinct().OrderBy(d => d)) };
    /// A stable text for cache keys.
    public string Key => "dept:" + string.Join(",", Departments.Distinct().OrderBy(d => d));
    public RowVisibility Rows => new(Sql, Parameters, Key, Departments.Distinct().OrderBy(d => d).ToList());
}

/// <summary>
/// The rows a user may see, as the predicate every finding query carries: from the role framework's
/// <see cref="VisibilityPredicate"/> (a Delegated user's scopes, the department among them) or from
/// <see cref="DepartmentVisibility"/> (a person of a department without a role). <see cref="Departments"/> = the
/// departments the user may open on the department pages.
/// </summary>
public sealed record RowVisibility(string Sql, IReadOnlyDictionary<string, object?> Parameters, string Key, IReadOnlyList<int> Departments)
{
    /// The role framework's predicate, with the department ids its scopes name.
    public static RowVisibility From(VisibilityPredicate p, IEnumerable<int> departments)
    {
        var shape = p.Sql + "|" + string.Join("|", p.Parameters.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => kv.Key + "=" + kv.Value));
        var key = "vis:" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(shape)))[..24];
        return new RowVisibility(p.Sql, p.Parameters, key, departments.Distinct().OrderBy(d => d).ToList());
    }
}

/// <summary>
/// The scope type "department" of the role framework (#253): a Delegated user scoped to a department SEES only that
/// department's assets and findings, on every view.
/// <para>HOW IT PLUGS INTO THE ROLE FRAMEWORK (#253): <list type="number">
/// <item><c>ScopeTypes.DepartmentType</c> = <c>new ScopeType(DepartmentScope.ScopeType, "department", Anchor: true, RestrictsVisibility: true,
/// Column: DepartmentScope.VisibilityColumn, Wildcard: null, DepartmentScope.Check)</c>, in <c>ScopeTypes.All</c>;</item>
/// <item><c>VisibilityPredicate.Columns[DepartmentScope.VisibilityColumn] = DepartmentScope.ColumnSql</c> -- the role
/// framework's predicate then filters every finding query on the department like any other column;</item>
/// <item>the web app's <c>IDepartmentScopeResolver</c> answers from <c>IAccessScope.Visibility(user)</c> first; a person of a
/// department who holds no role at all is scoped to their departments by membership
/// (SI.Management.Web/Departments/DepartmentAccess.cs).</item></list></para>
/// </summary>
public static class DepartmentScope
{
    public const string ScopeType = "department";
    /// The key of the department column in the role framework's visibility columns.
    public const string VisibilityColumn = "department";
    /// The column over the finding queries' alias f (sidata.Finding), stamped by the data sync.
    public const string ColumnSql = "f.DepartmentId";
    public const string Parameter = "ScopeDepartments";

    /// Why a scope value is not a department id (null = it is).
    public static string? Check(string value) =>
        int.TryParse(value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var id) && id > 0
            ? null : $"'{value}' is not a department id";

    /// Whether a grid can be restricted: its source reads one collection's findings as f.
    public static bool CanRestrict(GridSpec spec) => spec.Source.Contains(CollectionViewSql.ThisCollection, StringComparison.Ordinal)
                                                     || spec.Ctes.Contains(CollectionViewSql.ThisCollection, StringComparison.Ordinal);

    /// The grid restricted to the visible departments: every "this collection" condition on f also requires f's department.
    /// A grid that does not read findings as f is REFUSED (InvalidOperationException) -- never shown unfiltered.
    public static GridSpec Restrict(GridSpec spec, DepartmentVisibility v) => Restrict(spec, v.Rows);

    /// The asset kind column of the role framework's predicate (alias a = sidata.Asset), as a lookup on f -- a grid's
    /// "this collection" condition does not always have the asset joined.
    public const string AssetKindLookup = "(SELECT va.AssetKind FROM sidata.Asset AS va WHERE va.AssetKey = f.AssetKey)";

    /// The grid restricted by any row predicate over f (the role framework's, or a department list).
    public static GridSpec Restrict(GridSpec spec, RowVisibility v)
    {
        if (!CanRestrict(spec)) throw new InvalidOperationException($"the view '{spec.Name}' cannot be limited to a department");
        var cond = CollectionViewSql.ThisCollection + " AND (" + v.Sql.Replace("a.AssetKind", AssetKindLookup, StringComparison.Ordinal) + ")";
        return spec with
        {
            Name = spec.Name + "@dept",
            Ctes = spec.Ctes.Replace(CollectionViewSql.ThisCollection, cond, StringComparison.Ordinal),
            Source = spec.Source.Replace(CollectionViewSql.ThisCollection, cond, StringComparison.Ordinal),
            SourceParameters = spec.SourceParameters.Concat(v.Parameters.Keys).Distinct(StringComparer.Ordinal).ToList(),
            // #812: the index page and the stored counts span every department -- a restricted grid always reads its own rows
            Keyset = null,
        };
    }
}

// =====================================================================================================================
//  PRECEDENCE, as a pure function -- the web app's "why is this asset in that department" check
// =====================================================================================================================

/// A platform tag of an asset (sidata.AssetTag).
public sealed record AssetTagValue(string Source, string Name, string Value);

/// One SI definition (cfg.ResponsibilityRule).
public sealed record ResponsibilityRuleDef(int RuleId, string Kind, string Pattern, int DepartmentId, int SortOrder, bool Enabled = true);

/// One active department: its id, name and the extra values a tag may carry for it.
public sealed record DepartmentDef(int DepartmentId, string Name, IReadOnlyList<string> MatchValues);

/// What the resolver answers: the department (null = Unassigned), the source and the detail -- the columns the data sync
/// writes on sidata.Finding.
public sealed record ResponsibilityAnswer(int? DepartmentId, string Source, string? Detail);

/// <summary>
/// The responsibility precedence of #254, the same order the data sync applies in SQL
/// (engine/pro-data/_shared/SI-DataResponsibility.ps1): recommendation override &gt; asset override &gt; the policy's sources
/// in their configured order (tags: the earlier tag name wins, on one name Azure &gt; Defender &gt; Entra &gt; the subscription;
/// rules: lowest SortOrder) &gt; the default department &gt; Unassigned.
/// </summary>
public static class ResponsibilityResolver
{
    public const string RecommendationOverride = "recommendation-override";
    public const string AssetOverride = "asset-override";
    public const string Tag = "tag";
    public const string Rule = "rule";
    public const string Default = "default";
    public const string UnassignedSource = "unassigned";

    public static readonly IReadOnlyList<string> RuleKinds = ["name", "kind", "service", "group", "tag"];
    private static readonly string[] TagSources = ["azure", "endpoint", "identity", "azure-subscription"];

    public static ResponsibilityAnswer Resolve(
        IReadOnlyList<DepartmentDef> departments,
        IReadOnlyList<string> sources, IReadOnlyList<string> tagNames, string? defaultDepartment,
        IReadOnlyList<ResponsibilityRuleDef> rules,
        (int OverrideId, int DepartmentId)? recommendationOverride, (int OverrideId, int DepartmentId)? assetOverride,
        string? assetName, string? assetKind, IReadOnlyList<AssetTagValue> tags)
    {
        var active = departments.ToDictionary(d => d.DepartmentId);
        if (recommendationOverride is { } ro && active.ContainsKey(ro.DepartmentId)) return new(ro.DepartmentId, RecommendationOverride, $"override {ro.OverrideId}");
        if (assetOverride is { } ao && active.ContainsKey(ao.DepartmentId)) return new(ao.DepartmentId, AssetOverride, $"override {ao.OverrideId}");
        foreach (var src in sources.Select(s => s.Trim().ToLowerInvariant()).Distinct())
        {
            var hit = src switch { "tags" => ByTag(departments, tagNames, tags), "rules" => ByRule(active, rules, assetName, assetKind, tags), _ => null };
            if (hit is not null) return hit;
        }
        var def = departments.FirstOrDefault(d => !string.IsNullOrWhiteSpace(defaultDepartment) && string.Equals(d.Name, defaultDepartment.Trim(), StringComparison.OrdinalIgnoreCase));
        return def is not null ? new(def.DepartmentId, Default, "the default department") : new(null, UnassignedSource, null);
    }

    private static ResponsibilityAnswer? ByTag(IReadOnlyList<DepartmentDef> departments, IReadOnlyList<string> tagNames, IReadOnlyList<AssetTagValue> tags)
    {
        // a value -> the lowest department id carrying it (the SQL's MIN)
        var byValue = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in departments.OrderBy(d => d.DepartmentId))
            foreach (var v in d.MatchValues.Prepend(d.Name).Select(v => v.Trim()).Where(v => v.Length > 0))
                byValue.TryAdd(v, d.DepartmentId);
        for (var n = 0; n < tagNames.Count; n++)
            foreach (var s in TagSources)
            {
                // several matching tags of one name and source: the lowest department id (the SQL's tie-break)
                var hit = tags.Where(t => t.Source == s && string.Equals(t.Name, tagNames[n], StringComparison.OrdinalIgnoreCase))
                    .Select(t => (t, id: byValue.TryGetValue(t.Value.Trim(), out var i) ? i : (int?)null))
                    .Where(x => x.id is not null).OrderBy(x => x.id).FirstOrDefault();
                if (hit.id is { } id) return new(id, Tag, $"{hit.t.Name} = {hit.t.Value} ({hit.t.Source})");
            }
        return null;
    }

    private static ResponsibilityAnswer? ByRule(IReadOnlyDictionary<int, DepartmentDef> active, IReadOnlyList<ResponsibilityRuleDef> rules, string? name, string? kind, IReadOnlyList<AssetTagValue> tags)
    {
        foreach (var r in rules.Where(r => r.Enabled && active.ContainsKey(r.DepartmentId)).OrderBy(r => r.SortOrder).ThenBy(r => r.DepartmentId))
        {
            var k = r.Kind.Trim().ToLowerInvariant();
            var match = k switch
            {
                "name" => Like(name, r.Pattern),
                "kind" => string.Equals(kind, r.Pattern, StringComparison.OrdinalIgnoreCase),
                "service" => tags.Any(t => t.Source == "service" && Like(t.Value, r.Pattern)),
                "group" => tags.Any(t => t.Source == "group" && Like(t.Value, r.Pattern)),
                "tag" => tags.Any(t => TagSources.Contains(t.Source) && (Like(t.Value, r.Pattern) || Like(t.Name + "=" + t.Value, r.Pattern))),
                _ => false,
            };
            if (match) return new(r.DepartmentId, Rule, $"rule {r.RuleId}: {k} {r.Pattern}");
        }
        return null;
    }

    /// The rules' wildcard match: * any run, ? one character, everything else literal, case-insensitive (as LIKE under the
    /// database's case-insensitive collation).
    public static bool Like(string? value, string pattern)
    {
        if (value is null) return false;
        var rx = "^" + System.Text.RegularExpressions.Regex.Escape(pattern).Replace("\\*", ".*").Replace("\\?", ".") + "$";
        return System.Text.RegularExpressions.Regex.IsMatch(value, rx, System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant | System.Text.RegularExpressions.RegexOptions.Singleline);
    }
}
