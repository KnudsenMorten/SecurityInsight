namespace SI.Management.Core.ProData;

/// <summary>
/// #1277 -- the REMEDIATION TASKS PER CI (owner 2026-11-16: "one vulnerability per CI per task to perform"; the findings the
/// task resolves are information on it). Built per collection by the data sync (sidata.RemediationTask /
/// RemediationTaskFinding, engine/pro-data/_shared/SI-DataRemediationTask.ps1): one row per CI and thing to do -- the
/// update, the software upgrade per version (a library bundled in another product: per application, with its paths), the
/// configuration change -- with its counts, its highest severity and risk, the CI's owner and department, and its state run
/// to run (open, or closed as fixed / asset retired / report changed / task changed; a task whose findings are not known
/// this run is kept as it was). Additive: the Remediations pages (sidata.Remediation) are not changed.
/// Same rules as <see cref="CollectionViewSql"/>: fixed text, every caller value a parameter, read-only, ONE collection, and
/// the task table read as <c>f</c>. A person limited to some rows does NOT get these grids restricted on the task row (a
/// task carries its CI's department, a finding may have its own): <see cref="TasksFor"/> / <see cref="TaskFindingsFor"/>
/// limit them at finding level.
/// </summary>
public static class RemediationTaskSql
{
    /// The task's id as the SQL hand-off and the ServiceNow output give it (lower-case hex).
    private static string Hex(string col) => $"LOWER(CONVERT(varchar(64), {col}, 2))";

    /// #1283 the same task on every asset: the hash of the task key as hex (a row written before the hash was stored: worked
    /// out from its key, the same value).
    public static string TaskGroupOf(string alias) => Hex($"ISNULL({alias}.TaskKeyHash, HASHBYTES('SHA2_256', {alias}.TaskKey))");

    private const string SevSort = "CASE g.[HighestSeverity] WHEN N'critical' THEN 0 WHEN N'high' THEN 1 WHEN N'medium' THEN 2 WHEN N'low' THEN 3 ELSE 4 END";
    private static readonly string TierSort = "CASE WHEN g.[Tier] = N'Unclassified' THEN 9 ELSE TRY_CONVERT(int, g.[Tier]) END";

    /// The values of the task's kind (the finding field map's grouping kinds, and the bundled split).
    public static readonly IReadOnlyList<string> Kinds = ["security-update", "software-upgrade", "bundled-upgrade", "configuration", "cloud-recommendation", "identity-rule", "identity-review", "attack-path", "other"];
    public static readonly IReadOnlyList<string> States = ["open", "closed"];
    public static readonly IReadOnlyList<string> ClosedWhy = ["fixed", "exempted", "asset retired", "report changed", "task changed"];
    public static readonly IReadOnlyList<string> Severities = ["critical", "high", "medium", "low", "info"];
    public const string SeenNow = "this collection", SeenKept = "kept as it was";
    public static readonly IReadOnlyList<string> Seen = [SeenNow, SeenKept];

    // ---- which collection's tasks are shown -------------------------------------------------------------------------------
    //
    // The data sync writes a collection's tasks a range of CIs at a time and marks the collection (Collection.RemediationTasksAt)
    // only after the last range -- a collection without the mark may be half written. The task grids therefore show the
    // NEWEST MARKED collection AT OR BEFORE the one picked (the picked one itself once its tasks are built; until then the one
    // before it; none = no rows). Never a collection whose tasks are not all written.

    /// The id of the collection whose tasks the grids read, from the picked one (@CollectionId).
    public const string MarkedCollection = """
(SELECT TOP (1) mc.CollectionId FROM sidata.Collection AS mc
 WHERE mc.RemediationTasksAt IS NOT NULL
   AND mc.CollectionTime <= (SELECT pc.CollectionTime FROM sidata.Collection AS pc WHERE pc.CollectionId = TRY_CONVERT(int, @CollectionId))
 ORDER BY mc.CollectionTime DESC, mc.CollectionId DESC)
""";

    // ---- Remediations > Tasks per asset: one row per CI and task ---------------------------------------------------------

    public static readonly GridSpec Tasks = GridSql.Check(new GridSpec("remediationtasks", "", $"""
SELECT {Hex("f.TaskId")} AS TaskId, f.AssetKey, f.OwnerKey, COALESCE(f.AssetName, f.AssetKey, f.OwnerKey) AS AssetName, {ProDataSql.TierExpr("f.Tier")} AS Tier,
       f.TaskName, f.Kind, f.State, f.ClosedWhy, f.Findings, f.Cves, f.HighestSeverity, f.MaxRiskScore, f.MaxWeightedRisk,
       f.Product, f.Version, f.Application, f.ApplicationPaths, f.FirstSeen, f.LastSeen, f.ClosedAt, f.ReopenCount,
       CASE WHEN f.InThisCollection = 1 THEN N'{SeenNow}' ELSE N'{SeenKept}' END AS Seen,
       f.CiOwner, f.CiDepartment, d.Name AS Department, f.SecurityDomain,
       {TaskGroupOf("f")} AS TaskGroup, {RemediationTaskReports.ChannelOf("f")} AS Channel, f.HighestRiskRating
FROM sidata.RemediationTask AS f
LEFT JOIN cfg.Department AS d ON d.DepartmentId = f.DepartmentId
WHERE f.CollectionId = {MarkedCollection}
""", new GridColumn[]
    {
        new("TaskId", "Task id", Filter: GridFilter.Contains, Search: true, Hidden: true),
        // #1283 the same task on every asset (a report row opens its tasks by it)
        new("TaskGroup", "Task across assets", Filter: GridFilter.Values, Hidden: true),
        new("AssetName", "Asset (CI)", Filter: GridFilter.Contains, Search: true),
        // the asset's key and the CI id a task belongs to match EXACTLY (one asset's or one CI's own tasks: a key is never
        // matched as part of another, "srv1" in "srv10")
        new("AssetKey", "Asset (CI) key", Filter: GridFilter.Values, Search: true, Hidden: true),
        new("OwnerKey", "CI id", Filter: GridFilter.Values, Hidden: true),
        new("TaskName", "Task", Filter: GridFilter.Contains, Search: true),
        new("Kind", "Kind", Filter: GridFilter.Values),
        new("Channel", "Tool", Filter: GridFilter.Values),
        new("State", "State", Filter: GridFilter.Values),
        new("HighestSeverity", "Highest severity", Filter: GridFilter.Values, SortSql: SevSort),
        new("HighestRiskRating", "Highest risk rating", Filter: GridFilter.Values, SortSql: RemediationTaskReports.RatingSort("g.[HighestRiskRating]")),
        new("MaxRiskScore", "Highest risk score", GridType.Number, GridFilter.Range),
        new("MaxWeightedRisk", "Highest weighted risk", GridType.Number, GridFilter.Range),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        new("SecurityDomain", "Security domain", Filter: GridFilter.Values),
        new("Findings", "Findings", GridType.Number, GridFilter.Range),
        new("Cves", "CVEs", GridType.Number, GridFilter.Range),
        new("Product", "Product", Filter: GridFilter.Contains, Search: true),
        new("Version", "Version", Filter: GridFilter.Contains, Search: true),
        new("Application", "Application (bundles it)", Filter: GridFilter.Contains, Search: true),
        new("ApplicationPaths", "Paths", Filter: GridFilter.Contains, Search: true),
        new("ClosedWhy", "Closed because", Filter: GridFilter.Values),
        new("ClosedAt", "Closed", GridType.Date, GridFilter.Dates),
        new("FirstSeen", "First seen", GridType.Date, GridFilter.Dates),
        new("LastSeen", "Last seen", GridType.Date, GridFilter.Dates),
        new("ReopenCount", "Reopened", GridType.Number, GridFilter.Range),
        new("Seen", "Worked out from", Filter: GridFilter.Values),
        new("CiOwner", "Owner", Filter: GridFilter.Contains, Search: true),
        new("CiDepartment", "Department (the asset's, when the task was worked out)", Filter: GridFilter.Contains, Hidden: true),
        new("Department", "Department", Filter: GridFilter.Values),
    }, "MaxRiskScore", true, "TaskId", ["CollectionId"], Immutable: false));   // reads the department name (cfg): not cached long

    // ---- Remediations > Task findings: the findings each task resolves (and, bundled, the paths of the copy) ---------------

    public static readonly GridSpec TaskFindings = GridSql.Check(new GridSpec("remediationtaskfindings", "", $"""
SELECT {Hex("l.TaskId")} + N'|' + l.FindingKey AS LinkKey, {Hex("l.TaskId")} AS TaskId, f.TaskName, f.Kind, f.State AS TaskState,
       COALESCE(f.AssetName, f.AssetKey, f.OwnerKey) AS AssetName, f.AssetKey, l.FindingKey, l.Cve AS CveId, l.Title, l.Severity, l.RiskScore,
       l.Version, f.Application, f.ApplicationPaths, CASE WHEN l.InThisCollection = 1 THEN N'{SeenNow}' ELSE N'{SeenKept}' END AS Seen
FROM sidata.RemediationTaskFinding AS l
JOIN sidata.RemediationTask AS f ON f.CollectionId = l.CollectionId AND f.TaskId = l.TaskId
WHERE f.CollectionId = {MarkedCollection}
""", new GridColumn[]
    {
        new("LinkKey", "Link", Hidden: true),
        new("TaskId", "Task id", Filter: GridFilter.Contains, Search: true, Hidden: true),
        new("TaskName", "Task", Filter: GridFilter.Contains, Search: true),
        new("Kind", "Kind", Filter: GridFilter.Values),
        new("TaskState", "Task state", Filter: GridFilter.Values),
        new("AssetName", "Asset (CI)", Filter: GridFilter.Contains, Search: true),
        new("AssetKey", "Asset (CI) key", Filter: GridFilter.Contains, Search: true, Hidden: true),
        new("FindingKey", "Finding", Filter: GridFilter.Contains, Search: true),
        new("CveId", "CVE", Filter: GridFilter.Contains, Search: true),
        new("Title", "Title", Filter: GridFilter.Contains, Search: true),
        new("Severity", "Severity", Filter: GridFilter.Values),
        new("RiskScore", "Risk score", GridType.Number, GridFilter.Range),
        new("Version", "Version", Filter: GridFilter.Contains, Search: true),
        new("Application", "Application (bundles it)", Filter: GridFilter.Contains, Search: true),
        new("ApplicationPaths", "Paths of the copy", Filter: GridFilter.Contains, Search: true),
        new("Seen", "Seen in", Filter: GridFilter.Values),
    }, "RiskScore", true, "LinkKey", ["CollectionId"], Immutable: false));

    // ---- a person limited to some rows (departments, or a role's visibility): scoped at FINDING level ------------------------
    //
    // A task belongs to ONE CI and carries that CI's department, but a finding can have a department of its own (a
    // recommendation override, SI-DataResponsibility.ps1) -- so the task row's department is NOT the department of every finding
    // it lists. For a limited person the visibility is applied to each LINKED FINDING (sidata.Finding, through the link's
    // FindingId, read as f with every visibility column the role framework names): a task is shown when the person may see at
    // least one of its findings, and its findings, CVEs, highest severity, highest risk scores, tier and security domain are
    // worked out over THOSE findings only. A link carried with its task (InThisCollection = 0, FindingId NULL: its finding is
    // not in this collection) has no department that can be known here: a limited person does not see it -- and a task with
    // only such links (a task kept as it was, or a closed one carried in the retention) is not shown to them. Nothing of a
    // finding the person may not see is in any column, count or export. People who see everything get Tasks / TaskFindings
    // above, unchanged.

    private const string SevRankOfLink = "CASE l.Severity WHEN N'critical' THEN 4 WHEN N'high' THEN 3 WHEN N'medium' THEN 2 WHEN N'low' THEN 1 ELSE 0 END";

    /// The visibility predicate over f = sidata.Finding (the asset kind looked up on f, as DepartmentScope.Restrict does).
    internal static string Visible(RowVisibility v) => v.Sql.Replace("a.AssetKind", DepartmentScope.AssetKindLookup, StringComparison.Ordinal);

    /// The links a limited person may see: this collection's own links, their finding visible to them.
    private const string VisibleLinks = """
sidata.RemediationTaskFinding AS l
JOIN sidata.Finding AS f ON f.CollectionId = l.CollectionId AND f.FindingId = l.FindingId
""";

    /// Remediations > Tasks per asset for a person limited to some rows: the tasks with at least one finding they may see,
    /// counted over those findings only. Same columns as <see cref="Tasks"/>.
    public static GridSpec TasksFor(RowVisibility v) => GridSql.Check(Tasks with
    {
        Name = Tasks.Name + "@dept",
        Source = $"""
SELECT {Hex("t.TaskId")} AS TaskId, t.AssetKey, t.OwnerKey, COALESCE(t.AssetName, t.AssetKey, t.OwnerKey) AS AssetName, {ProDataSql.TierExpr("s.Tier")} AS Tier,
       t.TaskName, t.Kind, t.State, t.ClosedWhy, s.Findings, s.Cves,
       CASE s.SevRank WHEN 4 THEN N'critical' WHEN 3 THEN N'high' WHEN 2 THEN N'medium' WHEN 1 THEN N'low' ELSE N'info' END AS HighestSeverity,
       s.MaxRiskScore, s.MaxWeightedRisk,
       t.Product, t.Version, t.Application, t.ApplicationPaths, t.FirstSeen, t.LastSeen, t.ClosedAt, t.ReopenCount,
       CASE WHEN t.InThisCollection = 1 THEN N'{SeenNow}' ELSE N'{SeenKept}' END AS Seen,
       t.CiOwner, t.CiDepartment, d.Name AS Department, CASE WHEN s.Doms = 1 THEN s.Dom END AS SecurityDomain,
       {TaskGroupOf("t")} AS TaskGroup, {RemediationTaskReports.ChannelOf("t")} AS Channel, {RemediationTaskReports.RatingText("s.RatingRank")} AS HighestRiskRating
FROM sidata.RemediationTask AS t
CROSS APPLY (
    SELECT COUNT(*) AS Findings, COUNT(DISTINCT l.Cve) AS Cves, MAX({SevRankOfLink}) AS SevRank, MAX(l.RiskScore) AS MaxRiskScore,
           MAX(ISNULL(f.RiskScoreWeighted, f.RiskScore)) AS MaxWeightedRisk, MIN(f.Tier) AS Tier,
           COUNT(DISTINCT ISNULL(f.SecurityDomain, N'')) AS Doms, MAX(f.SecurityDomain) AS Dom, MAX({RemediationTaskReports.RatingRank("f.RiskRating")}) AS RatingRank
    FROM {VisibleLinks}
    WHERE l.CollectionId = t.CollectionId AND l.TaskId = t.TaskId AND l.InThisCollection = 1 AND l.FindingId IS NOT NULL
      AND ({Visible(v)})
) AS s
LEFT JOIN cfg.Department AS d ON d.DepartmentId = t.DepartmentId
WHERE t.CollectionId = {MarkedCollection} AND s.Findings > 0
""",
        SourceParameters = Tasks.SourceParameters.Concat(v.Parameters.Keys).Distinct(StringComparer.Ordinal).ToList(),
        Keyset = null,
    });

    /// Remediations > Task findings for a person limited to some rows: only the findings they may see (this collection's own
    /// links). Same columns as <see cref="TaskFindings"/>.
    public static GridSpec TaskFindingsFor(RowVisibility v) => GridSql.Check(TaskFindings with
    {
        Name = TaskFindings.Name + "@dept",
        Source = $"""
SELECT {Hex("l.TaskId")} + N'|' + l.FindingKey AS LinkKey, {Hex("l.TaskId")} AS TaskId, t.TaskName, t.Kind, t.State AS TaskState,
       COALESCE(t.AssetName, t.AssetKey, t.OwnerKey) AS AssetName, t.AssetKey, l.FindingKey, l.Cve AS CveId, l.Title, l.Severity, l.RiskScore,
       l.Version, t.Application, t.ApplicationPaths, CASE WHEN l.InThisCollection = 1 THEN N'{SeenNow}' ELSE N'{SeenKept}' END AS Seen
FROM {VisibleLinks}
JOIN sidata.RemediationTask AS t ON t.CollectionId = l.CollectionId AND t.TaskId = l.TaskId
WHERE l.CollectionId = {MarkedCollection} AND l.InThisCollection = 1 AND l.FindingId IS NOT NULL AND ({Visible(v)})
""",
        SourceParameters = TaskFindings.SourceParameters.Concat(v.Parameters.Keys).Distinct(StringComparer.Ordinal).ToList(),
        Keyset = null,
    });

    // ---- the tasks of ONE asset (the asset page, the CI page) and of ONE finding (the finding page) ---------------------------
    //
    // The same rows as Tasks per asset (a limited person: TasksFor, unchanged), narrowed in the statement to one asset by an
    // exact key: the asset page by the asset's key (AssetKey, as Tasks per asset filters it), the CI page by the CI id -- the
    // task's owner (OwnerKey: the data sync keys every task on '<CI id>|<task>', SI-DataRemediationTask.ps1). Open tasks
    // first, the highest risk first; paged in SQL like every grid.

    /// Open first, then the highest risk score (one ascending order).
    public const string OpenFirstSort = "CASE WHEN g.[State] = N'open' THEN 0 ELSE 1 END * 1000000000.0 - ISNULL(g.[MaxRiskScore], 0)";

    /// Which key narrows the tasks to one asset.
    public enum OneAsset { AssetKey, CiId }

    private static readonly GridSpec OfAssetKey = One(Tasks, OneAsset.AssetKey, "f");
    private static readonly GridSpec OfCiId = One(Tasks, OneAsset.CiId, "f");

    /// The tasks of one asset: by the asset's key (@AssetKey) or by the CI id (@OwnerKey). A limited person gets
    /// <see cref="TasksFor"/> narrowed the same way (finding level, unchanged).
    public static GridSpec OfOne(OneAsset by, RowVisibility? v) =>
        v is null ? (by == OneAsset.AssetKey ? OfAssetKey : OfCiId) : One(TasksFor(v), by, "t");

    /// The source parameter (and the task column) that carries the key of <paramref name="by"/>.
    public static string KeyParameter(OneAsset by) => by == OneAsset.AssetKey ? "AssetKey" : "OwnerKey";

    private static GridSpec One(GridSpec spec, OneAsset by, string alias)
    {
        var key = KeyParameter(by);
        return GridSql.Check(spec with
        {
            Name = spec.Name + (by == OneAsset.AssetKey ? "@asset" : "@ci"),
            Source = spec.Source.TrimEnd() + "\n  AND " + alias + "." + key + " = @" + key + "\n",
            SourceParameters = spec.SourceParameters.Append(key).Distinct(StringComparer.Ordinal).ToList(),
            Columns = spec.Columns.Select(c => c.Key == "State" ? c with { SortSql = OpenFirstSort } : c).ToList(),
            DefaultSort = "State",
            DefaultDesc = false,
            Keyset = null,
        });
    }

    /// <summary>
    /// The task(s) ONE finding belongs to (the finding page). The finding (@CollectionId, @FindingId) is found among the links
    /// of the newest marked collection by its owner and key -- the parts of its Risk Analysis key the data sync links it by
    /// (Get-SIRemediationTaskKeyApplySql) -- or, in its own collection, by its row. A limited person gets only a task whose
    /// link to this finding they may see, as on Task findings (<see cref="TaskFindingsFor"/>: the collection's own link, its
    /// finding visible to them).
    /// </summary>
    public static GridSpec OfFinding(RowVisibility? v) => v is null ? OfFindingAll : FindingTasks(v);

    private static readonly GridSpec OfFindingAll = FindingTasks(null);

    private static GridSpec FindingTasks(RowVisibility? v)
    {
        var limited = v is null ? "" : $"""

      AND l.InThisCollection = 1 AND l.FindingId IS NOT NULL
      AND EXISTS (SELECT 1 FROM sidata.Finding AS f WHERE f.CollectionId = l.CollectionId AND f.FindingId = l.FindingId AND ({Visible(v)}))
""";
        var source = $"""
SELECT {Hex("t.TaskId")} AS TaskId, t.TaskName, t.Kind, t.State, t.ClosedWhy, t.HighestSeverity, t.MaxRiskScore, t.Findings,
       COALESCE(t.AssetName, t.AssetKey, t.OwnerKey) AS AssetName, t.AssetKey
FROM sidata.RemediationTask AS t
WHERE t.CollectionId = {MarkedCollection}
  AND t.TaskId IN (
    SELECT l.TaskId
    FROM sidata.Finding AS cf
    CROSS APPLY (SELECT CHARINDEX(N'|', ISNULL(cf.RaFindingKey, N'')) AS P) AS sp
    CROSS APPLY (SELECT CASE WHEN sp.P > 1 THEN LEFT(LEFT(cf.RaFindingKey, sp.P - 1), 450) END AS OwnerKey,
                        CASE WHEN sp.P > 1 THEN SUBSTRING(cf.RaFindingKey, sp.P + 1, 900) END AS KeyPart) AS o
    CROSS APPLY (SELECT LEFT(CASE WHEN LOWER(cf.ConfigurationId) = o.KeyPart THEN cf.ConfigurationId ELSE o.KeyPart END, 256) AS FKey) AS k
    JOIN sidata.RemediationTaskFinding AS l ON l.CollectionId = t.CollectionId
         AND ((l.OwnerKey = o.OwnerKey AND l.FindingKey = k.FKey) OR (l.CollectionId = cf.CollectionId AND l.FindingId = cf.FindingId))
    WHERE cf.CollectionId = TRY_CONVERT(int, @CollectionId) AND cf.FindingId = TRY_CONVERT(bigint, @FindingId){limited}
  )
""";
        var parameters = new List<string> { "CollectionId", "FindingId" };
        if (v is not null) parameters.AddRange(v.Parameters.Keys);
        return GridSql.Check(new GridSpec("remediationtasksoffinding" + (v is null ? "" : "@dept"), "", source, new GridColumn[]
        {
            new("TaskId", "Task id", Hidden: true),
            new("TaskName", "Task"),
            new("Kind", "Kind"),
            new("State", "State", SortSql: OpenFirstSort),
            new("ClosedWhy", "Closed because"),
            new("HighestSeverity", "Highest severity"),
            new("MaxRiskScore", "Highest risk score", GridType.Number),
            new("Findings", "Findings", GridType.Number),
            new("AssetName", "Asset (CI)"),
            new("AssetKey", "Asset (CI) key", Hidden: true),
        }, "State", false, "TaskId", parameters.Distinct(StringComparer.Ordinal).ToList(), Immutable: false));
    }

    /// The grid a limited person gets for one of the task grids (null = not a task grid).
    public static GridSpec? For(GridSpec spec, RowVisibility v) =>
        ReferenceEquals(spec, Tasks) || spec.Name == Tasks.Name ? TasksFor(v)
        : ReferenceEquals(spec, TaskFindings) || spec.Name == TaskFindings.Name ? TaskFindingsFor(v)
        : null;
}
