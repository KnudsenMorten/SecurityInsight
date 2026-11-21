using System.Text;
using System.Text.Json;

namespace SI.Management.Core.ProData;

/// Where a task report's dimension comes from: the task row, the task's CI, the CI's business services (the CMDB link), or
/// each finding of the task (a value that can differ finding by finding).
public enum TaskDimLevel { Task, Ci, Service, Finding }

/// <summary>
/// One dimension the task reports filter and group by. <see cref="Expr"/> is the value over the task row (t), its CI (c) or --
/// a <see cref="TaskDimLevel.Finding"/> dimension -- the task's link row (l); <see cref="ScopedExpr"/> the same value read from
/// the finding row (f) where a department-limited person's links are read (null = <see cref="Expr"/>).
/// </summary>
public sealed record TaskDimension(string Key, string Label, TaskDimLevel Level, string Expr, string? ScopedExpr = null, string? Help = null)
{
    /// The source parameter that carries the chosen values (JSON array; NULL = no filter).
    public string Param => "D_" + Key;
    /// The address parameter of the page ("d.Os=windows|linux").
    public string Query => "d." + Key;
}

/// <summary>
/// What a task report reads: the chosen dimension values (dimension key -> values; a task matches when its value is one of
/// them) and the person's visibility (null = sees everything).
/// THE MATCHING RULE for a dimension that differs per finding (severity, risk rating, security domain, category,
/// subcategory) -- the rule <see cref="RemediationTaskSql.TasksFor"/> uses for a limited person: a task matches when at least
/// one of its findings matches, and every count of it (findings, CVEs, highest severity, risk rating and risk, tier) is
/// worked out over its MATCHING findings only.
/// </summary>
public sealed record TaskSlice(IReadOnlyDictionary<string, IReadOnlyList<string>> Filters, RowVisibility? Visibility = null)
{
    public static TaskSlice None => new(new Dictionary<string, IReadOnlyList<string>>());

    /// Count over the links even without a finding-level value (the proof that the two ways give the same rows).
    public bool ForceLinks { get; init; }

    /// The tasks are counted over their links (a finding-level filter or grouping, or a limited person) -- else over the
    /// stored task rows.
    public bool OverLinks(TaskDimension? by = null) =>
        ForceLinks || Visibility is not null || by?.Level == TaskDimLevel.Finding
        || Filters.Keys.Any(k => RemediationTaskReports.Dimension(k)?.Level == TaskDimLevel.Finding);

    /// A stable text of the filters (the cache key's part).
    public string Key
    {
        get
        {
            var sb = new StringBuilder();
            foreach (var (k, v) in Filters.OrderBy(x => x.Key, StringComparer.Ordinal)) sb.Append(k).Append('=').Append(string.Join("\u001f", v)).Append(';');
            if (Visibility is not null) sb.Append("|v=").Append(Visibility.Key);
            return sb.ToString();
        }
    }

    /// Every dimension's parameter (NULL when not chosen) and the visibility's own.
    public Dictionary<string, object?> Parameters()
    {
        var p = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var d in RemediationTaskReports.Dimensions)
            p[d.Param] = Filters.TryGetValue(d.Key, out var v) && v.Count > 0 ? JsonSerializer.Serialize(v) : null;
        if (Visibility is not null) foreach (var kv in Visibility.Parameters) p[kv.Key] = kv.Value;
        return p;
    }
}

/// <summary>
/// #1283 THE TASK REPORTS FOR IT OPERATIONS (owner 2026-11-18: "a summarized version so we can figure out candidates for
/// large-scale deployment using patch tools, policies, deployments, etc" / "like products, assets count. think as an it
/// operation team"; "make it possible to filter on it services ... security domain, category, subcategory, os version";
/// "filtered on risk ratings"). Every report is a grouping of the SAME task rows the task grid shows (sidata.RemediationTask of
/// <see cref="RemediationTaskSql.MarkedCollection"/>), OPEN tasks only, so a report row is exactly the sum of the task rows
/// behind it (its drill-down opens them):
///   Actions   one row per distinct task across assets ("deploy once, fix many"), ranked: the mass-deployment candidates (open on
///             at least the minimum number of assets, Collection.RemediationTaskMinAssets) first, then by summed weighted risk
///   Products  one row per product (and, split, per product and version)
///   Groups    one row per value of a dimension (the tool, the owner, the department, the IT service, the OS ...)
///   Singles   the tasks whose action is open on fewer assets than the minimum (no mass action fits)
///   Trend     what was opened and closed per week (stored per collection: sidata.RemediationTaskTrend)
/// The unfiltered Actions report of a person who sees everything reads the stored rollup (sidata.RemediationTaskRollup, written by
/// the task build); every other one is grouped at read time. A limited person's reports are worked out over the findings they
/// may see (<see cref="TaskSlice"/>): nothing of a finding they may not see is in any count, value or export.
/// Same rules as <see cref="CollectionViewSql"/>: fixed text, every caller value a parameter, read-only, ONE collection.
/// </summary>
public static class RemediationTaskReports
{
    // ---- the tool that fits ---------------------------------------------------------------------------------------------

    /// The tools, in the order they are shown, each with what it means (the tooltip). The engine's task build writes the same
    /// words (Get-SIRemediationTaskChannelSql) -- a test holds the two together.
    public static readonly IReadOnlyList<(string Name, string Tip)> Channels =
    [
        ("Patch tool", "A security update: push it with your patch tool (Intune, Configuration Manager, WSUS, Windows Autopatch)."),
        ("Software deployment", "A software upgrade, or a new version of an application that carries the vulnerable component: deploy it with your software deployment tool."),
        ("Policy", "A configuration change: set it with a policy (Intune configuration, Group Policy)."),
        ("Azure", "A cloud recommendation: fix it in Azure, or enforce it with Azure Policy."),
        ("Manual", "An identity or attack-path finding: it needs a person to review and act."),
    ];

    public static string? ChannelTip(string? name) => Channels.FirstOrDefault(c => c.Name == name).Tip;

    /// The task's tool over a task row (alias): the stored one, else worked out from the kind (the same mapping).
    /// (The security update's kind is matched by its prefix: the read-only guard refuses any statement that holds the word of
    /// a write, and the kind's own name holds one.)
    public static string ChannelOf(string alias) =>
        $"ISNULL({alias}.Channel, CASE WHEN {alias}.Kind LIKE N'security[-]%' THEN N'Patch tool' ELSE CASE {alias}.Kind WHEN N'software-upgrade' THEN N'Software deployment' WHEN N'bundled-upgrade' THEN N'Software deployment'"
        + $" WHEN N'configuration' THEN N'Policy' WHEN N'cloud-recommendation' THEN N'Azure' ELSE N'Manual' END END)";

    // ---- risk rating and severity ---------------------------------------------------------------------------------------

    public static readonly IReadOnlyList<string> Ratings = ["Critical", "High", "Moderate", "Low"];

    /// A risk rating (Critical | High | Moderate | Low) as a rank 4..1; 0 = none.
    public static string RatingRank(string col) =>
        $"CASE LOWER(LTRIM(RTRIM(ISNULL({col}, N'')))) WHEN N'critical' THEN 4 WHEN N'high' THEN 3 WHEN N'moderate' THEN 2 WHEN N'medium' THEN 2 WHEN N'low' THEN 1 ELSE 0 END";

    public static string RatingText(string rank) => $"CASE {rank} WHEN 4 THEN N'Critical' WHEN 3 THEN N'High' WHEN 2 THEN N'Moderate' WHEN 1 THEN N'Low' END";

    /// Sorting a rating column by its rank (Critical highest).
    public static string RatingSort(string col) => $"CASE {col} WHEN N'Critical' THEN 4 WHEN N'High' THEN 3 WHEN N'Moderate' THEN 2 WHEN N'Low' THEN 1 END";

    private static string SevRank(string col) => $"CASE {col} WHEN N'critical' THEN 4 WHEN N'high' THEN 3 WHEN N'medium' THEN 2 WHEN N'low' THEN 1 ELSE 0 END";
    private static string SevText(string rank) => $"CASE {rank} WHEN 4 THEN N'critical' WHEN 3 THEN N'high' WHEN 2 THEN N'medium' WHEN 1 THEN N'low' ELSE N'info' END";
    private const string SevSort = "CASE g.[HighestSeverity] WHEN N'critical' THEN 4 WHEN N'high' THEN 3 WHEN N'medium' THEN 2 WHEN N'low' THEN 1 ELSE 0 END";

    // ---- the dimensions --------------------------------------------------------------------------------------------------

    public const string None = "(none)";
    public const string NoService = "(no IT service)";

    /// The age of an open task at its collection, in bands.
    private const string AgeExpr = "CASE WHEN DATEDIFF(day, t.FirstSeen, (SELECT ax.CollectionTime FROM sidata.Collection AS ax WHERE ax.CollectionId = t.CollectionId)) <= 30 THEN N'0-30 days'"
        + " WHEN DATEDIFF(day, t.FirstSeen, (SELECT ax.CollectionTime FROM sidata.Collection AS ax WHERE ax.CollectionId = t.CollectionId)) <= 90 THEN N'31-90 days'"
        + " WHEN DATEDIFF(day, t.FirstSeen, (SELECT ax.CollectionTime FROM sidata.Collection AS ax WHERE ax.CollectionId = t.CollectionId)) <= 180 THEN N'91-180 days' ELSE N'Over 180 days' END";

    /// Every dimension the reports filter and group by, in the order the page offers them.
    public static readonly IReadOnlyList<TaskDimension> Dimensions =
    [
        new("Channel", "Tool", TaskDimLevel.Task, ChannelOf("t"), Help: "The tool that fits the task: patch tool, software deployment, policy, Azure or manual."),
        new("Kind", "Kind", TaskDimLevel.Task, "t.Kind"),
        new("Product", "Product", TaskDimLevel.Task, "t.Product"),
        new("Tier", "Tier", TaskDimLevel.Task, ProDataSql.TierExpr("t.Tier")),
        new("Owner", "Owner", TaskDimLevel.Task, "t.CiOwner"),
        new("Department", "Department", TaskDimLevel.Task, "(SELECT dd.Name FROM cfg.Department AS dd WHERE dd.DepartmentId = t.DepartmentId)"),
        new("Age", "Open for", TaskDimLevel.Task, AgeExpr, Help: "How long the task has been open, at the collection shown."),
        new("Service", "IT service", TaskDimLevel.Service, "sv.ServiceName", Help: "The business services the asset belongs to (from the CMDB link). An asset in several services counts in each."),
        new("Os", "OS", TaskDimLevel.Ci, "c.OsName"),
        new("OsPlatform", "OS platform", TaskDimLevel.Ci, "c.OsPlatform"),
        new("OsVersion", "OS version", TaskDimLevel.Ci, "c.OsVersion"),
        new("DeviceType", "Device type", TaskDimLevel.Ci, "c.AssetType"),
        new("Subscription", "Cloud subscription", TaskDimLevel.Ci, "c.AzureSubscriptionName"),
        new("ResourceGroup", "Resource group", TaskDimLevel.Ci, "c.AzureResourceGroup"),
        new("Location", "Location", TaskDimLevel.Ci, "c.AzureLocation"),
        new("Environment", "Environment", TaskDimLevel.Ci, "c.Environment"),
        new("Severity", "Severity", TaskDimLevel.Finding, "l.Severity"),
        new("RiskRating", "Risk rating", TaskDimLevel.Finding, "l.RiskRating", "f.RiskRating"),
        new("SecurityDomain", "Security domain", TaskDimLevel.Finding, "l.SecurityDomain", "f.SecurityDomain"),
        new("Category", "Category", TaskDimLevel.Finding, "l.Category", "f.Category"),
        new("Subcategory", "Subcategory", TaskDimLevel.Finding, "l.Subcategory", "f.Subcategory"),
    ];

    public static TaskDimension? Dimension(string? key) => Dimensions.FirstOrDefault(d => string.Equals(d.Key, key, StringComparison.OrdinalIgnoreCase));

    /// The dimensions a report can be grouped by (all of them; Product has its own report).
    public static IReadOnlyList<TaskDimension> Groupings => Dimensions.Where(d => d.Key != "Product").ToList();

    /// The value of a dimension over the rows in reach (the finding value over l, or f for a limited person).
    private static string ValueOf(TaskDimension d, bool scoped) => d.Level == TaskDimLevel.Finding && scoped ? d.ScopedExpr ?? d.Expr : d.Expr;

    private static string Pred(TaskDimension d, bool scoped) => d.Level == TaskDimLevel.Service
        ? $"(@{d.Param} IS NULL OR EXISTS (SELECT 1 FROM sidata.CiService AS sv0 WHERE sv0.CiId = t.CiId AND sv0.ServiceName IN (SELECT dv.[value] FROM OPENJSON(@{d.Param}) AS dv)))"
        : $"(@{d.Param} IS NULL OR {ValueOf(d, scoped)} IN (SELECT dv.[value] FROM OPENJSON(@{d.Param}) AS dv))";

    /// The predicates over the task, its CI and its services (every one always present; a NULL parameter = no filter).
    private static string TaskPreds() => string.Join("\n  AND ", Dimensions.Where(d => d.Level != TaskDimLevel.Finding).Select(d => Pred(d, false)));
    /// The predicates over a link (l) -- and, for a limited person, its finding (f).
    private static string LinkPreds(bool scoped) => string.Join("\n      AND ", Dimensions.Where(d => d.Level == TaskDimLevel.Finding).Select(d => Pred(d, scoped)));

    private static IReadOnlyList<string> Params(TaskSlice s) =>
        new[] { "CollectionId" }.Concat(Dimensions.Select(d => d.Param)).Concat(s.Visibility?.Parameters.Keys ?? Enumerable.Empty<string>()).Distinct(StringComparer.Ordinal).ToList();

    private const string M = RemediationTaskSql.MarkedCollection;

    /// <summary>
    /// ONE ROW PER TASK (and group value) of the marked collection that the slice reaches: the task's own columns and its counts
    /// -- the stored ones, or (<see cref="TaskSlice.OverLinks"/>) worked out over its matching links: for a limited person only
    /// this collection's own links whose finding they may see (as <see cref="RemediationTaskSql.TasksFor"/>). G = the group
    /// value (<paramref name="by"/>; NULL group = <see cref="None"/>), absent without a grouping.
    /// </summary>
    public static string Slice(TaskSlice s, TaskDimension? by, bool openOnly)
    {
        var links = s.OverLinks(by);
        var scoped = s.Visibility is not null;
        var group = by is null ? "" : by.Level switch
        {
            TaskDimLevel.Service => $"ISNULL(sv.ServiceName, N'{NoService}') AS G, ",
            TaskDimLevel.Finding => "x.G AS G, ",
            _ => $"ISNULL(CONVERT(nvarchar(400), {by.Expr}), N'{None}') AS G, ",
        };
        var svJoin = by?.Level == TaskDimLevel.Service ? "LEFT JOIN sidata.CiService AS sv ON sv.CiId = t.CiId\n" : "";
        var state = openOnly ? "t.State = N'open'" : "1 = 1";
        var head = $"""
SELECT {group}t.CollectionId, t.TaskId, ISNULL(t.TaskKeyHash, HASHBYTES('SHA2_256', t.TaskKey)) AS TaskKeyHash, t.OwnerKey, t.CiId, t.AssetKey, t.AssetName, t.TaskName, t.Kind,
       {ChannelOf("t")} AS Channel, t.Product, t.Version, t.Application, t.ApplicationPaths, t.State, t.ClosedWhy, t.ClosedAt, t.FirstSeen, t.LastSeen, t.ReopenCount,
       t.InThisCollection, t.CiOwner, t.CiDepartment, t.DepartmentId,
""";
        if (!links)
            return head + $"""
       t.Findings, t.Cves, {SevRank("t.HighestSeverity")} AS SevRank, {RatingRank("t.HighestRiskRating")} AS RatingRank, t.MaxRiskScore, t.MaxWeightedRisk, t.Tier, t.SecurityDomain
FROM sidata.RemediationTask AS t
LEFT JOIN sidata.Ci AS c ON c.CiId = t.CiId
{svJoin}WHERE t.CollectionId = {M} AND {state}
  AND {TaskPreds()}
""";
        var w = scoped ? "ISNULL(f.RiskScoreWeighted, f.RiskScore)" : "l.WeightedRisk";
        var tier = scoped ? "f.Tier" : "l.Tier";
        var dom = scoped ? "f.SecurityDomain" : "l.SecurityDomain";
        var rating = scoped ? "f.RiskRating" : "l.RiskRating";
        var fg = by?.Level == TaskDimLevel.Finding ? $"ISNULL(CONVERT(nvarchar(400), {ValueOf(by, scoped)}), N'{None}')" : null;
        var from = scoped
            ? "sidata.RemediationTaskFinding AS l\n    JOIN sidata.Finding AS f ON f.CollectionId = l.CollectionId AND f.FindingId = l.FindingId"
            : "sidata.RemediationTaskFinding AS l";
        var scope = scoped ? $" AND l.InThisCollection = 1 AND l.FindingId IS NOT NULL AND ({RemediationTaskSql.Visible(s.Visibility!)})" : "";
        return head + $"""
       x.Findings, x.Cves, x.SevRank, x.RatingRank, x.MaxRiskScore, x.MaxWeightedRisk, x.Tier, CASE WHEN x.Doms = 1 THEN x.Dom END AS SecurityDomain
FROM sidata.RemediationTask AS t
LEFT JOIN sidata.Ci AS c ON c.CiId = t.CiId
{svJoin}CROSS APPLY (
    SELECT {(fg is null ? "" : fg + " AS G, ")}COUNT(*) AS Findings, COUNT(DISTINCT l.Cve) AS Cves, MAX({SevRank("l.Severity")}) AS SevRank, MAX({RatingRank(rating)}) AS RatingRank,
           MAX(l.RiskScore) AS MaxRiskScore, MAX({w}) AS MaxWeightedRisk, MIN({tier}) AS Tier,
           COUNT(DISTINCT ISNULL({dom}, N'')) AS Doms, MAX({dom}) AS Dom
    FROM {from}
    WHERE l.CollectionId = t.CollectionId AND l.TaskId = t.TaskId{scope}
      AND {LinkPreds(scoped)}
    {(fg is null ? "" : "GROUP BY " + fg)}
) AS x
WHERE t.CollectionId = {M} AND {state} AND x.Findings > 0
  AND {TaskPreds()}
""";
    }

    /// The distinct CVEs per group value: the links of the slice's tasks (only the matching ones, and for a limited person only
    /// those they may see; for a finding-level grouping only the links of that value).
    private static string CveCte(TaskSlice s, TaskDimension? by, string rows = "st", bool grouped = false)
    {
        var links = s.OverLinks(by);
        var scoped = s.Visibility is not null;
        var join = scoped ? "\n    JOIN sidata.Finding AS f ON f.CollectionId = l.CollectionId AND f.FindingId = l.FindingId" : "";
        var cond = !links ? "" : (scoped ? $" AND l.InThisCollection = 1 AND l.FindingId IS NOT NULL AND ({RemediationTaskSql.Visible(s.Visibility!)})" : "")
            + $"\n      AND {LinkPreds(scoped)}"
            + (by?.Level == TaskDimLevel.Finding ? $"\n      AND ISNULL(CONVERT(nvarchar(400), {ValueOf(by, scoped)}), N'{None}') = st.G" : "");
        var g = by is null && !grouped ? "st.TaskKeyHash" : "st.G";
        return $"""
cv AS (
    SELECT {g} AS G, COUNT(DISTINCT l.Cve) AS Cves
    FROM {rows} AS st
    JOIN sidata.RemediationTaskFinding AS l ON l.CollectionId = st.CollectionId AND l.TaskId = st.TaskId{join}
    WHERE l.Cve IS NOT NULL{cond}
    GROUP BY {g}
)
""";
    }

    private const string MinCte = $"""
mm AS (SELECT ISNULL(MAX(x.RemediationTaskMinAssets), 5) AS MinAssets FROM sidata.Collection AS x WHERE x.CollectionId = {M})
""";

    private static string Name(string grain, TaskSlice s, TaskDimension? by) =>
        "remtaskrep-" + grain + (by is null ? "" : "-" + by.Key.ToLowerInvariant()) + (s.OverLinks(by) ? "@links" : "") + (s.Visibility is not null ? "@dept" : "");

    // ---- the columns shared by the summaries ----------------------------------------------------------------------------

    private static GridColumn[] Measures(bool actions) =>
    [
        new("Assets", "Assets", GridType.Number, GridFilter.Range),
        new("Tier01Assets", "Tier 0/1 assets", GridType.Number, GridFilter.Range),
        .. actions ? Array.Empty<GridColumn>() : new GridColumn[] { new("Actions", "Different tasks", GridType.Number, GridFilter.Range), new("OpenTasks", "Open tasks", GridType.Number, GridFilter.Range) },
        new("Findings", "Findings closed", GridType.Number, GridFilter.Range),
        new("Cves", "CVEs removed", GridType.Number, GridFilter.Range),
        new("HighestSeverity", "Highest severity", Filter: GridFilter.Values, SortSql: SevSort),
        new("HighestRiskRating", "Highest risk rating", Filter: GridFilter.Values, SortSql: RatingSort("g.[HighestRiskRating]")),
        new("MaxWeightedRisk", "Highest weighted risk", GridType.Number, GridFilter.Range),
        new("SumWeightedRisk", "Weighted risk removed", GridType.Number, GridFilter.Range),
        new("OldestFirstSeen", "Open since", GridType.Date, GridFilter.Dates),
    ];

    /// The measures over st grouped by G (the same for every summary).
    private static string Aggregates => $"""
COUNT(DISTINCT st.OwnerKey) AS Assets, COUNT(DISTINCT CASE WHEN st.Tier IN (0, 1) THEN st.OwnerKey END) AS Tier01Assets,
       COUNT(DISTINCT st.TaskKeyHash) AS Actions, COUNT(*) AS OpenTasks, SUM(st.Findings) AS Findings,
       MAX(st.SevRank) AS SevRank, MAX(st.RatingRank) AS RatingRank, MAX(st.MaxWeightedRisk) AS MaxWeightedRisk, SUM(st.MaxWeightedRisk) AS SumWeightedRisk,
       MIN(st.FirstSeen) AS OldestFirstSeen
""";

    private static string Outputs(string a) => $"""
{a}.Assets, {a}.Tier01Assets, {a}.Findings, ISNULL(cv.Cves, 0) AS Cves, {SevText(a + ".SevRank")} AS HighestSeverity, {RatingText(a + ".RatingRank")} AS HighestRiskRating,
       {a}.MaxWeightedRisk, {a}.SumWeightedRisk, {a}.OldestFirstSeen
""";

    // ---- (a) Deploy once, fix many ---------------------------------------------------------------------------------------

    /// Whether the actions report reads the stored rollup: a person who sees everything, no filter.
    public static bool ActionsStored(TaskSlice s) => s.Visibility is null && s.Filters.Count == 0 && !s.ForceLinks;

    /// <summary>
    /// One row per distinct task across assets, OPEN tasks only, ranked: the candidates for one fleet-wide deployment (open on
    /// at least the collection's minimum of assets) first, then the summed weighted risk ("assets x risk"), then the key.
    /// Rank is that order over every row of the report (a column filter does not renumber).
    /// </summary>
    public static GridSpec Actions(TaskSlice s, bool fromRollup = true)
    {
        var cols = new List<GridColumn>
        {
            new("Rank", "#", GridType.Number, GridFilter.Range),
            new("TaskGroup", "Task across assets", Filter: GridFilter.Values, Hidden: true),
            new("Action", "Action", Filter: GridFilter.Contains, Search: true),
            new("Channel", "Tool", Filter: GridFilter.Values),
            new("Kind", "Kind", Filter: GridFilter.Values),
            new("Product", "Product", Filter: GridFilter.Contains, Search: true),
            new("Version", "Version", Filter: GridFilter.Contains, Search: true),
            new("Candidate", "Fleet-wide candidate", Filter: GridFilter.Values),
        };
        cols.AddRange(Measures(actions: true));
        string ctes, source;
        var stored = fromRollup && ActionsStored(s);
        if (stored)
        {
            ctes = MinCte;
            source = $"""
SELECT ROW_NUMBER() OVER (ORDER BY CASE WHEN r.Assets >= mm.MinAssets THEN 0 ELSE 1 END, r.SumWeightedRisk DESC, r.TaskKeyHash) AS Rank,
       LOWER(CONVERT(varchar(64), r.TaskKeyHash, 2)) AS TaskGroup, r.TaskName AS Action, r.Channel, r.Kind, r.Product, r.Version,
       CASE WHEN r.Assets >= mm.MinAssets THEN N'yes' ELSE N'no' END AS Candidate,
       r.Assets, r.Tier01Assets, r.Findings, r.Cves, r.HighestSeverity, r.HighestRiskRating, r.MaxWeightedRisk, r.SumWeightedRisk, r.OldestFirstSeen
FROM sidata.RemediationTaskRollup AS r
CROSS JOIN mm
WHERE r.CollectionId = {M}
""";
        }
        else
        {
            ctes = $"st AS (\n{Slice(s, null, openOnly: true)}\n),\n{CveCte(s, null)},\n{MinCte}";
            source = $"""
SELECT ROW_NUMBER() OVER (ORDER BY CASE WHEN a.Assets >= mm.MinAssets THEN 0 ELSE 1 END, a.SumWeightedRisk DESC, a.TaskKeyHash) AS Rank,
       LOWER(CONVERT(varchar(64), a.TaskKeyHash, 2)) AS TaskGroup, a.Action, a.Channel, a.Kind, a.Product, a.Version,
       CASE WHEN a.Assets >= mm.MinAssets THEN N'yes' ELSE N'no' END AS Candidate,
       {Outputs("a")}
FROM (SELECT st.TaskKeyHash, MAX(st.TaskName) AS Action, MAX(st.Channel) AS Channel, MAX(st.Kind) AS Kind,
             CASE WHEN MIN(ISNULL(st.Product, N'')) = MAX(ISNULL(st.Product, N'')) THEN MAX(st.Product) END AS Product,
             CASE WHEN MIN(ISNULL(st.Version, N'')) = MAX(ISNULL(st.Version, N'')) THEN MAX(st.Version) END AS Version,
             {Aggregates}
      FROM st GROUP BY st.TaskKeyHash) AS a
LEFT JOIN cv ON cv.G = a.TaskKeyHash
CROSS JOIN mm
""";
        }
        return GridSql.Check(new GridSpec(Name("actions", s, null) + (stored ? "@stored" : ""), ctes, source, cols, "Rank", false, "TaskGroup", Params(s), Immutable: false));
    }

    // ---- (b) by product (and version) -------------------------------------------------------------------------------------

    /// One row per product (<paramref name="perVersion"/>: per product and version) of the open tasks that name one.
    public static GridSpec Products(TaskSlice s, bool perVersion)
    {
        var g = perVersion ? "CONCAT(st.Product, NCHAR(31), ISNULL(st.Version, N''))" : "st.Product";
        var cols = new List<GridColumn>
        {
            new("Product", "Product", Filter: GridFilter.Contains, Search: true),
        };
        if (perVersion) cols.Add(new("Version", "Version", Filter: GridFilter.Contains, Search: true));
        else cols.Add(new("Versions", "Versions in use", GridType.Number, GridFilter.Range));
        cols.Add(new("GroupKey", "Key", Hidden: true));
        cols.AddRange(Measures(actions: false));
        var ctes = $"st AS (\n{Slice(s, null, openOnly: true)}\n),\nsp AS (SELECT {g} AS G, st.* FROM st WHERE st.Product IS NOT NULL),\n"
            + CveCte(s, null, rows: "sp", grouped: true);
        var source = $"""
SELECT a.Product, {(perVersion ? "a.Version" : "a.Versions")}, a.G AS GroupKey, a.Actions, a.OpenTasks,
       {Outputs("a")}
FROM (SELECT st.G, MAX(st.Product) AS Product, MAX(st.Version) AS Version, COUNT(DISTINCT ISNULL(st.Version, N'')) AS Versions,
             {Aggregates}
      FROM sp AS st GROUP BY st.G) AS a
LEFT JOIN cv ON cv.G = a.G
""";
        return GridSql.Check(new GridSpec(Name(perVersion ? "productversions" : "products", s, null), ctes, source, cols, "SumWeightedRisk", true, "GroupKey", Params(s), Immutable: false));
    }

    // ---- (c, d, e) by any dimension ---------------------------------------------------------------------------------------

    /// One row per value of <paramref name="by"/> over the open tasks: a task counts under every value it has (a CI in two
    /// services, a task with findings of two categories -- counted over that value's findings), so rows can overlap.
    public static GridSpec Groups(TaskSlice s, TaskDimension by)
    {
        var cols = new List<GridColumn> { new("Group", by.Label, Filter: GridFilter.Contains, Search: true) };
        cols.AddRange(Measures(actions: false));
        var ctes = $"st AS (\n{Slice(s, by, openOnly: true)}\n),\n{CveCte(s, by)}";
        var source = $"""
SELECT a.G AS [Group], a.Actions, a.OpenTasks,
       {Outputs("a")}
FROM (SELECT st.G, {Aggregates}
      FROM st GROUP BY st.G) AS a
LEFT JOIN cv ON cv.G = a.G
""";
        return GridSql.Check(new GridSpec(Name("groups", s, by), ctes, source, cols, "SumWeightedRisk", true, "Group", Params(s), Immutable: false));
    }

    // ---- the task rows themselves: the grid with the dimensions, and the tasks no mass action fits --------------------------

    private static string TaskCols(string from) => $"""
SELECT LOWER(CONVERT(varchar(64), {from}.TaskId, 2)) AS TaskId, {from}.AssetKey, {from}.OwnerKey, COALESCE({from}.AssetName, {from}.AssetKey, {from}.OwnerKey) AS AssetName,
       {ProDataSql.TierExpr(from + ".Tier")} AS Tier, {from}.TaskName, {from}.Kind, {from}.State, {from}.ClosedWhy, {from}.Findings, {from}.Cves,
       {SevText(from + ".SevRank")} AS HighestSeverity, {from}.MaxRiskScore, {from}.MaxWeightedRisk,
       {from}.Product, {from}.Version, {from}.Application, {from}.ApplicationPaths, {from}.FirstSeen, {from}.LastSeen, {from}.ClosedAt, {from}.ReopenCount,
       CASE WHEN {from}.InThisCollection = 1 THEN N'{RemediationTaskSql.SeenNow}' ELSE N'{RemediationTaskSql.SeenKept}' END AS Seen,
       {from}.CiOwner, {from}.CiDepartment, (SELECT dd.Name FROM cfg.Department AS dd WHERE dd.DepartmentId = {from}.DepartmentId) AS Department, {from}.SecurityDomain,
       LOWER(CONVERT(varchar(64), {from}.TaskKeyHash, 2)) AS TaskGroup, {from}.Channel, {RatingText(from + ".RatingRank")} AS HighestRiskRating,
       {RemediationTaskSql.DetectedPaths(from)} AS DetectedPaths
""";

    /// Remediations > Tasks per asset with dimensions chosen: the same columns as <see cref="RemediationTaskSql.Tasks"/>, every
    /// state, the tasks the slice reaches -- counted over their matching findings when a finding-level value is chosen (or the
    /// person is limited).
    public static GridSpec Tasks(TaskSlice s) => GridSql.Check(RemediationTaskSql.Tasks with
    {
        Name = Name("tasks", s, null),
        Ctes = $"st AS (\n{Slice(s, null, openOnly: false)}\n)",
        Source = TaskCols("st") + "\nFROM st\n",
        SourceParameters = Params(s),
        Keyset = null,
    });

    /// The tasks no mass action fits: open tasks whose action is open on fewer assets than the collection's minimum.
    public static GridSpec Singles(TaskSlice s) => GridSql.Check(RemediationTaskSql.Tasks with
    {
        Name = Name("singles", s, null),
        Ctes = $"st AS (\n{Slice(s, null, openOnly: true)}\n),\ngc AS (SELECT st.TaskKeyHash, COUNT(DISTINCT st.OwnerKey) AS N FROM st GROUP BY st.TaskKeyHash),\n{MinCte}",
        Source = TaskCols("st") + "\nFROM st\nJOIN gc ON gc.TaskKeyHash = st.TaskKeyHash\nCROSS JOIN mm\nWHERE gc.N < mm.MinAssets\n",
        SourceParameters = Params(s),
        Keyset = null,
    });

    /// Remediations > Task findings with dimensions chosen: only the findings that match the finding-level values (and, for a
    /// limited person, that they may see), of the tasks the task-level values reach.
    public static GridSpec TaskFindings(TaskSlice s)
    {
        var scoped = s.Visibility is not null;
        var from = scoped
            ? "sidata.RemediationTaskFinding AS l\nJOIN sidata.Finding AS f ON f.CollectionId = l.CollectionId AND f.FindingId = l.FindingId"
            : "sidata.RemediationTaskFinding AS l";
        var scope = scoped ? $"\n  AND l.InThisCollection = 1 AND l.FindingId IS NOT NULL AND ({RemediationTaskSql.Visible(s.Visibility!)})" : "";
        return GridSql.Check(RemediationTaskSql.TaskFindings with
        {
            Name = "remediationtaskfindings-d" + (scoped ? "@dept" : ""),
            Source = $"""
SELECT LOWER(CONVERT(varchar(64), l.TaskId, 2)) + N'|' + l.FindingKey AS LinkKey, LOWER(CONVERT(varchar(64), l.TaskId, 2)) AS TaskId, t.TaskName, t.Kind, t.State AS TaskState,
       COALESCE(t.AssetName, t.AssetKey, t.OwnerKey) AS AssetName, t.AssetKey, l.FindingKey, l.Cve AS CveId, l.Title, l.Severity, l.RiskScore,
       l.Version, t.Application, t.ApplicationPaths, CASE WHEN l.InThisCollection = 1 THEN N'{RemediationTaskSql.SeenNow}' ELSE N'{RemediationTaskSql.SeenKept}' END AS Seen,
       {RemediationTaskSql.DetectedPaths("t")} AS DetectedPaths
FROM {from}
JOIN sidata.RemediationTask AS t ON t.CollectionId = l.CollectionId AND t.TaskId = l.TaskId
LEFT JOIN sidata.Ci AS c ON c.CiId = t.CiId
WHERE l.CollectionId = {M}{scope}
  AND {LinkPreds(scoped)}
  AND {TaskPreds()}
""",
            SourceParameters = Params(s),
            Keyset = null,
        });
    }

    // ---- (e1) the trend --------------------------------------------------------------------------------------------------

    /// Opened and closed per week (ISO week, Monday), per tool or every tool (@Channel = '' ), from the stored trend rows of every
    /// collection up to the one picked; open = at the week's last collection. A person who sees everything only (the rows are
    /// counts over every department).
    public static readonly GridSpec Trend = GridSql.Check(new GridSpec("remtaskrep-trend", "", """
SELECT CONVERT(char(10), w.WeekStart, 23) AS Week, CONVERT(datetime2(0), w.WeekStart) AS WeekStart, w.Opened, w.ClosedFixed, w.ClosedOther, l.OpenTasks, l.OpenAssets, w.Runs
FROM (SELECT DATEADD(day, -((DATEDIFF(day, '19000101', r.CollectionTime)) % 7), CONVERT(date, r.CollectionTime)) AS WeekStart,
             SUM(r.Opened) AS Opened, SUM(r.ClosedFixed) AS ClosedFixed, SUM(r.ClosedOther) AS ClosedOther, COUNT(*) AS Runs, MAX(r.CollectionTime) AS LastTime
      FROM sidata.RemediationTaskTrend AS r
      WHERE r.Channel = ISNULL(@Channel, N'')
        AND r.CollectionTime <= (SELECT pc.CollectionTime FROM sidata.Collection AS pc WHERE pc.CollectionId = TRY_CONVERT(int, @CollectionId))
      GROUP BY DATEADD(day, -((DATEDIFF(day, '19000101', r.CollectionTime)) % 7), CONVERT(date, r.CollectionTime))) AS w
JOIN sidata.RemediationTaskTrend AS l ON l.Channel = ISNULL(@Channel, N'') AND l.CollectionTime = w.LastTime
""", new GridColumn[]
    {
        new("Week", "Week", Hidden: true),
        new("WeekStart", "Week starting", GridType.Date),
        new("Opened", "Opened", GridType.Number, GridFilter.Range),
        new("ClosedFixed", "Closed as fixed", GridType.Number, GridFilter.Range),
        new("ClosedOther", "Closed for another reason", GridType.Number, GridFilter.Range),
        new("OpenTasks", "Open at the week's end", GridType.Number, GridFilter.Range),
        new("OpenAssets", "Assets with an open task", GridType.Number, GridFilter.Range),
        new("Runs", "Runs", GridType.Number),
    }, "WeekStart", true, "Week", ["CollectionId", "Channel"], Immutable: false));

    // ---- the state: which collection the reports read, and whether its stored rows are there --------------------------------

    /// The marked collection for @CollectionId, its time, whether the task reports' rows are built for it, the minimum.
    public static readonly GridSpec State = GridSql.Check(new GridSpec("remtaskrep-state", "", $"""
SELECT CONVERT(nvarchar(12), mc.CollectionId) AS MarkedId, mc.CollectionTime AS MarkedTime, CASE WHEN mc.RemediationTaskRollupAt IS NULL THEN 0 ELSE 1 END AS Built,
       ISNULL(mc.RemediationTaskMinAssets, 5) AS MinAssets
FROM sidata.Collection AS mc
WHERE mc.CollectionId = {M}
""", new GridColumn[]
    {
        new("MarkedId", "Collection"), new("MarkedTime", "Time", GridType.Date), new("Built", "Built", GridType.Number), new("MinAssets", "Minimum", GridType.Number),
    }, "MarkedTime", true, "MarkedId", ["CollectionId"], Immutable: false));

    /// The trend rows of the marked collection and every earlier one after @Since (exclusive; NULL = only the marked one): what
    /// was opened and closed since the last report, per tool ('' = every tool), and the marked collection's open counts.
    public static readonly GridSpec Since = GridSql.Check(new GridSpec("remtaskrep-since", "", $"""
SELECT r.Channel, SUM(r.Opened) AS Opened, SUM(r.ClosedFixed) AS ClosedFixed, SUM(r.ClosedOther) AS ClosedOther,
       MAX(CASE WHEN r.CollectionId = mk.Id THEN r.OpenTasks END) AS OpenTasks, MAX(CASE WHEN r.CollectionId = mk.Id THEN r.OpenAssets END) AS OpenAssets,
       MIN(CASE WHEN r.CollectionId = mk.Id THEN r.OldestOpen END) AS OldestOpen
FROM sidata.RemediationTaskTrend AS r
CROSS JOIN (SELECT {M} AS Id) AS mk
WHERE r.CollectionTime <= (SELECT x.CollectionTime FROM sidata.Collection AS x WHERE x.CollectionId = mk.Id)
  AND (r.CollectionId = mk.Id OR (TRY_CONVERT(datetime2(3), @Since, 126) IS NOT NULL AND r.CollectionTime > TRY_CONVERT(datetime2(3), @Since, 126)))
GROUP BY r.Channel
""", new GridColumn[]
    {
        new("Channel", "Tool"), new("Opened", "Opened", GridType.Number), new("ClosedFixed", "Closed as fixed", GridType.Number), new("ClosedOther", "Closed otherwise", GridType.Number),
        new("OpenTasks", "Open tasks", GridType.Number), new("OpenAssets", "Assets", GridType.Number), new("OldestOpen", "Oldest open", GridType.Date),
    }, "OpenTasks", true, "Channel", ["CollectionId", "Since"], Immutable: false));

    // ---- the values a dimension can take (the page's choices) ------------------------------------------------------------

    /// <summary>
    /// The values each dimension has among the open tasks of the marked collection the person may see (for a limited person:
    /// only the values of tasks and findings they may see -- never a value of a finding they may not see). Dim, Value.
    /// </summary>
    public static GridSpec Values(RowVisibility? v)
    {
        var scoped = v is not null;
        var lf = scoped
            ? $"sidata.RemediationTaskFinding AS l JOIN sidata.Finding AS f ON f.CollectionId = l.CollectionId AND f.FindingId = l.FindingId WHERE l.CollectionId = {M} AND l.InThisCollection = 1 AND l.FindingId IS NOT NULL AND ({RemediationTaskSql.Visible(v!)})"
            : $"sidata.RemediationTaskFinding AS l WHERE l.CollectionId = {M}";
        var parts = new List<string>();
        foreach (var d in Dimensions)
        {
            // over vl (alias l) the finding values carry the link's column names, for a limited person too
            var val = d.Expr;
            parts.Add(d.Level switch
            {
                TaskDimLevel.Finding => $"SELECT N'{d.Key}' AS Dim, CONVERT(nvarchar(400), {val}) AS Value FROM vl AS l WHERE {val} IS NOT NULL",
                TaskDimLevel.Service => $"SELECT N'{d.Key}' AS Dim, CONVERT(nvarchar(400), sv.ServiceName) AS Value FROM vt AS t JOIN sidata.CiService AS sv ON sv.CiId = t.CiId WHERE sv.ServiceName IS NOT NULL",
                _ => $"SELECT N'{d.Key}' AS Dim, CONVERT(nvarchar(400), {val}) AS Value FROM vt AS t LEFT JOIN sidata.Ci AS c ON c.CiId = t.CiId WHERE {val} IS NOT NULL",
            });
        }
        var vlCols = scoped ? "l.TaskId, l.Severity, f.RiskRating, f.SecurityDomain, f.Category, f.Subcategory" : "l.TaskId, l.Severity, l.RiskRating, l.SecurityDomain, l.Category, l.Subcategory";
        var ctes = $"""
vl0 AS (SELECT {vlCols} FROM {lf}),
vt AS (SELECT t.* FROM sidata.RemediationTask AS t WHERE t.CollectionId = {M} AND t.State = N'open'{(scoped ? " AND EXISTS (SELECT 1 FROM vl0 WHERE vl0.TaskId = t.TaskId)" : "")}),
vl AS (SELECT vl0.* FROM vl0 JOIN vt ON vt.TaskId = vl0.TaskId)
""";
        var source = "SELECT x.Dim + N'|' + x.Value AS DimValue, x.Dim, x.Value FROM (\n" + string.Join("\nUNION\n", parts) + "\n) AS x";
        return GridSql.Check(new GridSpec("remtaskrep-values" + (scoped ? "@dept" : ""), ctes, source, new GridColumn[]
        {
            new("DimValue", "Key", Hidden: true), new("Dim", "Dimension"), new("Value", "Value"),
        }, "Dim", false, "DimValue", new[] { "CollectionId" }.Concat(v?.Parameters.Keys ?? Enumerable.Empty<string>()).Distinct(StringComparer.Ordinal).ToList(), Immutable: false));
    }

    /// The dimension values a page address carries ("d.Os=windows|linux", several values joined with '|' or as several
    /// parameters): known dimensions only, each value trimmed, at most <see cref="GridSql.MaxValues"/> per dimension.
    public static IReadOnlyDictionary<string, IReadOnlyList<string>> ReadFilters(IEnumerable<KeyValuePair<string, IEnumerable<string?>>> query)
    {
        var r = new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, vals) in query)
        {
            if (!k.StartsWith("d.", StringComparison.OrdinalIgnoreCase) || Dimension(k[2..]) is not { } d) continue;
            var list = vals.Where(x => !string.IsNullOrWhiteSpace(x)).SelectMany(x => x!.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .Select(x => ProDataFilters.Text(x)!).Where(x => x is { Length: > 0 }).Distinct(StringComparer.Ordinal).ToList();
            if (list.Count > GridSql.MaxValues) throw new ArgumentException($"at most {GridSql.MaxValues} values per dimension");
            if (list.Count > 0) r[d.Key] = list;
        }
        return r;
    }
}
