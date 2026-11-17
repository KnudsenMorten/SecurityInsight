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
SELECT {Hex("f.TaskId")} AS TaskId, f.AssetKey, COALESCE(f.AssetName, f.AssetKey, f.OwnerKey) AS AssetName, {ProDataSql.TierExpr("f.Tier")} AS Tier,
       f.TaskName, f.Kind, f.State, f.ClosedWhy, f.Findings, f.Cves, f.HighestSeverity, f.MaxRiskScore, f.MaxWeightedRisk,
       f.Product, f.Version, f.Application, f.ApplicationPaths, f.FirstSeen, f.LastSeen, f.ClosedAt, f.ReopenCount,
       CASE WHEN f.InThisCollection = 1 THEN N'{SeenNow}' ELSE N'{SeenKept}' END AS Seen,
       f.CiOwner, f.CiDepartment, d.Name AS Department, f.SecurityDomain
FROM sidata.RemediationTask AS f
LEFT JOIN cfg.Department AS d ON d.DepartmentId = f.DepartmentId
WHERE f.CollectionId = {MarkedCollection}
""", new GridColumn[]
    {
        new("TaskId", "Task id", Filter: GridFilter.Contains, Search: true, Hidden: true),
        new("AssetName", "Asset (CI)", Filter: GridFilter.Contains, Search: true),
        new("AssetKey", "Asset (CI) key", Filter: GridFilter.Contains, Search: true, Hidden: true),
        new("TaskName", "Task", Filter: GridFilter.Contains, Search: true),
        new("Kind", "Kind", Filter: GridFilter.Values),
        new("State", "State", Filter: GridFilter.Values),
        new("ClosedWhy", "Closed because", Filter: GridFilter.Values),
        new("Findings", "Findings", GridType.Number, GridFilter.Range),
        new("Cves", "CVEs", GridType.Number, GridFilter.Range),
        new("HighestSeverity", "Highest severity", Filter: GridFilter.Values, SortSql: SevSort),
        new("MaxRiskScore", "Highest risk score", GridType.Number, GridFilter.Range),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        new("Product", "Product", Filter: GridFilter.Contains, Search: true),
        new("Version", "Version", Filter: GridFilter.Contains, Search: true),
        new("Application", "Application (bundles it)", Filter: GridFilter.Contains, Search: true),
        new("ApplicationPaths", "Paths", Filter: GridFilter.Contains, Search: true, Hidden: true),
        new("FirstSeen", "First seen", GridType.Date, GridFilter.Dates),
        new("LastSeen", "Last seen", GridType.Date, GridFilter.Dates),
        new("ClosedAt", "Closed", GridType.Date, GridFilter.Dates, Hidden: true),
        new("Seen", "Worked out from", Filter: GridFilter.Values),
        new("CiOwner", "Owner", Filter: GridFilter.Contains, Search: true),
        new("CiDepartment", "Department (the asset's, when the task was worked out)", Filter: GridFilter.Contains, Hidden: true),
        new("Department", "Department", Filter: GridFilter.Values),
        new("ReopenCount", "Reopened", GridType.Number, GridFilter.Range, Hidden: true),
        new("MaxWeightedRisk", "Highest weighted risk", GridType.Number, GridFilter.Range, Hidden: true),
        new("SecurityDomain", "Security domain", Filter: GridFilter.Values, Hidden: true),
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
    private static string Visible(RowVisibility v) => v.Sql.Replace("a.AssetKind", DepartmentScope.AssetKindLookup, StringComparison.Ordinal);

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
SELECT {Hex("t.TaskId")} AS TaskId, t.AssetKey, COALESCE(t.AssetName, t.AssetKey, t.OwnerKey) AS AssetName, {ProDataSql.TierExpr("s.Tier")} AS Tier,
       t.TaskName, t.Kind, t.State, t.ClosedWhy, s.Findings, s.Cves,
       CASE s.SevRank WHEN 4 THEN N'critical' WHEN 3 THEN N'high' WHEN 2 THEN N'medium' WHEN 1 THEN N'low' ELSE N'info' END AS HighestSeverity,
       s.MaxRiskScore, s.MaxWeightedRisk,
       t.Product, t.Version, t.Application, t.ApplicationPaths, t.FirstSeen, t.LastSeen, t.ClosedAt, t.ReopenCount,
       CASE WHEN t.InThisCollection = 1 THEN N'{SeenNow}' ELSE N'{SeenKept}' END AS Seen,
       t.CiOwner, t.CiDepartment, d.Name AS Department, CASE WHEN s.Doms = 1 THEN s.Dom END AS SecurityDomain
FROM sidata.RemediationTask AS t
CROSS APPLY (
    SELECT COUNT(*) AS Findings, COUNT(DISTINCT l.Cve) AS Cves, MAX({SevRankOfLink}) AS SevRank, MAX(l.RiskScore) AS MaxRiskScore,
           MAX(ISNULL(f.RiskScoreWeighted, f.RiskScore)) AS MaxWeightedRisk, MIN(f.Tier) AS Tier,
           COUNT(DISTINCT ISNULL(f.SecurityDomain, N'')) AS Doms, MAX(f.SecurityDomain) AS Dom
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

    /// The grid a limited person gets for one of the task grids (null = not a task grid).
    public static GridSpec? For(GridSpec spec, RowVisibility v) =>
        ReferenceEquals(spec, Tasks) || spec.Name == Tasks.Name ? TasksFor(v)
        : ReferenceEquals(spec, TaskFindings) || spec.Name == TaskFindings.Name ? TaskFindingsFor(v)
        : null;
}
