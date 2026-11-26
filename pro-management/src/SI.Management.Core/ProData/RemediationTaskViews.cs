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
       f.Product, f.Version, f.Application, f.ApplicationVersion, f.ApplicationPaths, f.FirstSeen, f.LastSeen, f.ClosedAt, f.ReopenCount,
       CASE WHEN f.InThisCollection = 1 THEN N'{SeenNow}' ELSE N'{SeenKept}' END AS Seen,
       f.CiOwner, f.CiDepartment, d.Name AS Department, f.SecurityDomain,
       {TaskGroupOf("f")} AS TaskGroup, {RemediationTaskReports.ChannelOf("f")} AS Channel, f.HighestRiskRating,
       {DetectedPaths("f")} AS DetectedPaths
FROM sidata.RemediationTask AS f
LEFT JOIN cfg.Department AS d ON d.DepartmentId = f.DepartmentId
WHERE f.CollectionId = {MarkedCollection}
""", new GridColumn[]
    {
        // owner 2026-11-25 ("why are the paths + application paths still way out to the sort order of the page. it must be close
        // to the appliation name"): the task's own columns first -- the asset, the task and RIGHT AFTER it the application that
        // bundles it, its version, its paths and where it was detected -- then what the task is (kind, state, findings, risk,
        // dates), then the keys and who answers for the asset; the CI's own attributes after all of them
        // (DataViewDefaults.ForGrid). A remembered layout keeps that order too (DataViewDefaults.TaskOrder).
        new("AssetName", "Asset (CI)", Filter: GridFilter.Contains, Search: true),
        new("TaskName", "Task", Filter: GridFilter.Contains, Search: true),
        new("Application", "Application (bundles it)", Filter: GridFilter.Contains, Search: true),
        // owner 2026-11-24 ("Yes, separate column"): the bundling application's version(s), never part of the task's name or key
        new("ApplicationVersion", "Application version", Filter: GridFilter.Contains, Search: true),
        new("ApplicationPaths", "Paths", Filter: GridFilter.Contains, Search: true, Lines: true),
        // owner 2026-11-19: where the product was detected on the asset, shown by default ("so we know where it needs fixing")
        new("DetectedPaths", "Detected paths", Filter: GridFilter.Contains, Lines: true),
        new("Kind", "Kind", Filter: GridFilter.Values),
        new("Channel", "Tool", Filter: GridFilter.Values),
        new("State", "State", Filter: GridFilter.Values),
        new("ClosedWhy", "Closed because", Filter: GridFilter.Values),
        new("Findings", "Findings", GridType.Number, GridFilter.Range),
        new("Cves", "CVEs", GridType.Number, GridFilter.Range),
        new("HighestSeverity", "Highest severity", Filter: GridFilter.Values, SortSql: SevSort),
        new("HighestRiskRating", "Highest risk rating", Filter: GridFilter.Values, SortSql: RemediationTaskReports.RatingSort("g.[HighestRiskRating]")),
        new("MaxRiskScore", "Highest risk score", GridType.Number, GridFilter.Range),
        new("MaxWeightedRisk", "Highest weighted risk", GridType.Number, GridFilter.Range),
        new("Tier", "Tier", GridType.Tier, GridFilter.Values, SortSql: TierSort),
        new("SecurityDomain", "Security domain", Filter: GridFilter.Values),
        new("Product", "Product", Filter: GridFilter.Contains, Search: true),
        new("Version", "Version", Filter: GridFilter.Contains, Search: true),
        new("FirstSeen", "First seen", GridType.Date, GridFilter.Dates),
        new("LastSeen", "Last seen", GridType.Date, GridFilter.Dates),
        new("ClosedAt", "Closed", GridType.Date, GridFilter.Dates),
        new("ReopenCount", "Reopened", GridType.Number, GridFilter.Range),
        new("Seen", "Worked out from", Filter: GridFilter.Values),
        new("TaskId", "Task id", Filter: GridFilter.Contains, Search: true),
        // #1283 the same task on every asset (a report row opens its tasks by it)
        new("TaskGroup", "Task across assets", Filter: GridFilter.Values),
        // the asset's key and the CI id a task belongs to match EXACTLY (one asset's or one CI's own tasks: a key is never
        // matched as part of another, "srv1" in "srv10")
        new("AssetKey", "Asset (CI) key", Filter: GridFilter.Values, Search: true),
        new("OwnerKey", "CI key", Filter: GridFilter.Values),
        new("CiOwner", "Owner", Filter: GridFilter.Contains, Search: true),
        new("CiDepartment", "Department (the asset's, when the task was worked out)", Filter: GridFilter.Contains),
        new("Department", "Department", Filter: GridFilter.Values),
    }, "MaxRiskScore", true, "TaskId", ["CollectionId"], Immutable: false));   // reads the department name (cfg): not cached long

    /// owner 2026-11-19: the disk paths where Defender found the task's product on the task's CI -- "so we know where it needs
    /// fixing" -- one per line, EVERY path in full (owner 2026-11-24: "detected paths is cut off and it mentions multiple
    /// paths"): the task's OWN paths when it has them (a bundled task: its application's copy; the product's own task: the
    /// copies that are not bundled), else the CI's evidence of that product AND version (sidata.SoftwareEvidence of its
    /// Defender devices; a task of several versions: every version). Empty for a task without a product or a CI without
    /// Defender evidence.
    public static string DetectedPaths(string t) => $"""
COALESCE(REPLACE(NULLIF({t}.ApplicationPaths, N''), N';', NCHAR(10)),
(SELECT STRING_AGG(CAST(p.FullPath AS nvarchar(max)), NCHAR(10)) WITHIN GROUP (ORDER BY p.FullPath)
 FROM (SELECT DISTINCT e.FullPath
       FROM sidata.CiLink AS dpl
       JOIN sidata.SoftwareEvidence AS e ON e.DeviceId = LOWER(dpl.NativeId)
       WHERE dpl.CiId = {t}.OwnerKey AND dpl.Provider = N'mde' AND e.Product = {t}.Product AND e.PathType = N'disk'
         AND ({t}.Version IS NULL OR e.Version = {t}.Version)) AS p))
""";

    // ---- Remediations > Task findings: the findings each task resolves (and, bundled, the paths of the copy) ---------------

    public static readonly GridSpec TaskFindings = GridSql.Check(new GridSpec("remediationtaskfindings", "", $"""
SELECT {Hex("l.TaskId")} + N'|' + l.FindingKey AS LinkKey, {Hex("l.TaskId")} AS TaskId, f.TaskName, f.Kind, f.State AS TaskState,
       COALESCE(f.AssetName, f.AssetKey, f.OwnerKey) AS AssetName, f.AssetKey, l.FindingKey, l.Cve AS CveId, l.Title, l.Severity, l.RiskScore,
       l.Version, f.Application, f.ApplicationVersion, f.ApplicationPaths, CASE WHEN l.InThisCollection = 1 THEN N'{SeenNow}' ELSE N'{SeenKept}' END AS Seen,
       {DetectedPaths("f")} AS DetectedPaths
FROM sidata.RemediationTaskFinding AS l
JOIN sidata.RemediationTask AS f ON f.CollectionId = l.CollectionId AND f.TaskId = l.TaskId
WHERE f.CollectionId = {MarkedCollection}
""", new GridColumn[]
    {
        new("LinkKey", "Link", Hidden: true),
        new("TaskId", "Task id", Filter: GridFilter.Contains, Search: true),
        new("TaskName", "Task", Filter: GridFilter.Contains, Search: true),
        new("Kind", "Kind", Filter: GridFilter.Values),
        new("TaskState", "Task state", Filter: GridFilter.Values),
        new("AssetName", "Asset (CI)", Filter: GridFilter.Contains, Search: true),
        new("AssetKey", "Asset (CI) key", Filter: GridFilter.Contains, Search: true),
        new("FindingKey", "Finding", Filter: GridFilter.Contains, Search: true),
        new("CveId", "CVE", Filter: GridFilter.Contains, Search: true),
        new("Title", "Title", Filter: GridFilter.Contains, Search: true),
        new("Severity", "Severity", Filter: GridFilter.Values),
        new("RiskScore", "Risk score", GridType.Number, GridFilter.Range),
        new("Version", "Version", Filter: GridFilter.Contains, Search: true),
        new("Application", "Application (bundles it)", Filter: GridFilter.Contains, Search: true),
        // owner 2026-11-24 ("Yes, separate column"): the bundling application's version(s), never part of the task's name or key
        new("ApplicationVersion", "Application version", Filter: GridFilter.Contains, Search: true),
        // owner 2026-11-19: where the product was detected on the asset, shown by default
        new("DetectedPaths", "Detected paths", Filter: GridFilter.Contains, Lines: true),
        new("ApplicationPaths", "Paths of the copy", Filter: GridFilter.Contains, Search: true, Lines: true),
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
       t.Product, t.Version, t.Application, t.ApplicationVersion, t.ApplicationPaths, t.FirstSeen, t.LastSeen, t.ClosedAt, t.ReopenCount,
       CASE WHEN t.InThisCollection = 1 THEN N'{SeenNow}' ELSE N'{SeenKept}' END AS Seen,
       t.CiOwner, t.CiDepartment, d.Name AS Department, CASE WHEN s.Doms = 1 THEN s.Dom END AS SecurityDomain,
       {TaskGroupOf("t")} AS TaskGroup, {RemediationTaskReports.ChannelOf("t")} AS Channel, {RemediationTaskReports.RatingText("s.RatingRank")} AS HighestRiskRating,
       {DetectedPaths("t")} AS DetectedPaths
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
       l.Version, t.Application, t.ApplicationVersion, t.ApplicationPaths, CASE WHEN l.InThisCollection = 1 THEN N'{SeenNow}' ELSE N'{SeenKept}' END AS Seen,
       {DetectedPaths("t")} AS DetectedPaths
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

    // ---- ONE task: Remediations > Task, the task's own page (owner 2026-11-25: "i expected a landing page for each remeidation
    // task with all relevant info") ---------------------------------------------------------------------------------------------
    //
    // The task's row of Tasks per asset (a limited person: TasksFor, unchanged -- counted over the findings they may see) read
    // by its key -- the clustered key (CollectionId, TaskId): one seek -- with the few stored values Tasks per asset does not
    // show (the product's vendor, when its paths were read, the CMDB CI, the asset's kind) and what its findings say to do
    // (their recommended updates and remediation, each once); and the findings it resolves, read off the link table's
    // clustered key (CollectionId, TaskId, ...) with each finding's own row by ITS clustered key (CollectionId, FindingId).
    // Typed columns only: no source-record column and no JSON is read.

    /// The source parameter of one task: its id as the task grids show it (lower-case hex of the 32-byte hash).
    public const string TaskIdParameter = "TaskId";

    /// A task id from the address: hex, an even number of digits, at most the 64 of the hash (lower case); null = not one.
    public static string? TaskIdOf(string? raw)
    {
        var t = raw?.Trim();
        if (string.IsNullOrEmpty(t) || t.Length > 64 || t.Length % 2 != 0) return null;
        foreach (var ch in t) if (!Uri.IsHexDigit(ch)) return null;
        return t.ToLowerInvariant();
    }

    /// The task row (alias <paramref name="alias"/>) is the one asked for: a seek on the clustered key.
    private static string IsTask(string alias) => $"{alias}.TaskId = TRY_CONVERT(binary(32), @{TaskIdParameter}, 2)";

    /// The separator of the texts the findings of a task say to do (one text may hold line breaks).
    public const char FixSeparator = '\u001e';

    /// What the task's findings say to do -- <paramref name="column"/> of sidata.Finding, each distinct text once. A limited
    /// person: over the findings they may see only (the visibility on the finding, alias f).
    private static string FixesOf(string column, string task, RowVisibility? v)
    {
        var fin = v is null ? "fx" : "f";
        var limited = v is null ? "" : $" AND lx.InThisCollection = 1 AND ({Visible(v)})";
        return $"""
(SELECT STRING_AGG(CAST(x.V AS nvarchar(max)), NCHAR(30)) WITHIN GROUP (ORDER BY x.V)
 FROM (SELECT DISTINCT {fin}.{column} AS V
       FROM sidata.RemediationTaskFinding AS lx
       JOIN sidata.Finding AS {fin} ON {fin}.CollectionId = lx.CollectionId AND {fin}.FindingId = lx.FindingId
       WHERE lx.CollectionId = {task}.CollectionId AND lx.TaskId = {task}.TaskId AND NULLIF({fin}.{column}, N'') IS NOT NULL{limited}) AS x)
""";
    }

    /// <summary>
    /// The task's row, by its key (@CollectionId picks the collection as on every task grid, @TaskId the task): the columns
    /// of Tasks per asset and the task's other stored values. A limited person gets <see cref="TasksFor"/> narrowed the same
    /// way: a task none of whose findings they may see is not found.
    /// </summary>
    public static GridSpec OneTask(RowVisibility? v)
    {
        var (spec, t) = v is null ? (Tasks, "f") : (TasksFor(v), "t");
        var source = spec.Source.TrimStart();
        if (!source.StartsWith("SELECT ", StringComparison.Ordinal)) throw new InvalidOperationException($"grid {spec.Name}: not a SELECT");
        var extra = $"""
{t}.CollectionId AS TaskCollectionId, {t}.CiId, {t}.Vendor, {t}.EvidenceAt, {t}.CmdbId,
       (SELECT a.AssetKind FROM sidata.Asset AS a WHERE a.AssetKey = {t}.AssetKey) AS AssetKind,
       {FixesOf("FixRecommendedUpdate", t, v).Trim()} AS RecommendedUpdates,
       {FixesOf("FixRemediation", t, v).Trim()} AS Remediations,

""";
        return GridSql.Check(spec with
        {
            Name = spec.Name + "@task",
            Source = "SELECT " + extra + source["SELECT ".Length..].TrimEnd() + "\n  AND " + IsTask(t) + "\n",
            SourceParameters = spec.SourceParameters.Append(TaskIdParameter).Distinct(StringComparer.Ordinal).ToList(),
            Columns = spec.Columns.Concat(new GridColumn[]
            {
                new("TaskCollectionId", "Collection of the task", Hidden: true),
                new("CiId", "CI id of the task", Hidden: true),
                new("Vendor", "Product vendor"),
                new("EvidenceAt", "Paths read", GridType.Date),
                new("CmdbId", "CMDB CI of the task"),
                new("AssetKind", "Asset kind"),
                new("RecommendedUpdates", "Recommended updates"),
                new("Remediations", "Remediation of its findings"),
            }).ToList(),
            Keyset = null,
        });
    }

    /// The text the separator joined (<see cref="FixSeparator"/>), each item once, in full.
    public static IReadOnlyList<string> Fixes(string? joined) =>
        string.IsNullOrWhiteSpace(joined) ? Array.Empty<string>()
        : joined.Split(FixSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.Ordinal).ToList();

    /// The answer of the "Within Accepted Lifecycle" view for a link's finding (alias of the link <paramref name="l"/>): "yes"
    /// when the view counts it (sidata.FindingLifecycleRisk, #1355), "no" when it is counted by "Actual Risks" only; NULL when
    /// the collection's lifecycle rows are not stored (its key figures' marker) or the link has no finding row.
    private static string LifecycleOf(string l) => $"""
CASE WHEN {l}.FindingId IS NULL
       OR NOT EXISTS (SELECT 1 FROM sidata.KeyFigure AS kf WHERE kf.CollectionId = {l}.CollectionId AND kf.Block = N'meta' AND kf.Figure = N'lifecycle_rows') THEN NULL
     WHEN EXISTS (SELECT 1 FROM sidata.FindingLifecycleRisk AS lr WHERE lr.CollectionId = {l}.CollectionId AND lr.FindingId = {l}.FindingId) THEN N'yes'
     ELSE N'no' END
""";

    /// <summary>
    /// The findings ONE task resolves (@CollectionId, @TaskId), with each finding's own values: its risk rating and weighted
    /// risk (copied to the link at build), whether an exploit is known, when the source first detected it, its due date, its
    /// exemption, and the "Within Accepted Lifecycle" answer. Everyone who sees every row gets every link of the task (a link
    /// carried with its task included, as on Task findings); a limited person only the collection's own links whose finding
    /// they may see (<see cref="TaskFindingsFor"/>'s rule).
    /// </summary>
    public static GridSpec FindingsOfTask(RowVisibility? v) => v is null ? FindingsOfTaskAll : TaskFindingRows(v);

    private static readonly GridSpec FindingsOfTaskAll = TaskFindingRows(null);

    private static GridSpec TaskFindingRows(RowVisibility? v)
    {
        var fd = v is null ? "fd" : "f";
        var join = v is null
            ? "LEFT JOIN sidata.Finding AS fd ON fd.CollectionId = l.CollectionId AND fd.FindingId = l.FindingId"
            : "JOIN sidata.Finding AS f ON f.CollectionId = l.CollectionId AND f.FindingId = l.FindingId";
        var limited = v is null ? "" : $"\n  AND l.InThisCollection = 1 AND l.FindingId IS NOT NULL AND ({Visible(v)})";
        // #1388 the due date, as the ticket carries it: the provider's own where it is set (owner "Provider's date wins if set"),
        // the finding model's (CiFindingState.DueAt, the days to fix) for the rest
        var source = $"""
SELECT {Hex("l.TaskId")} + N'|' + l.FindingKey AS LinkKey, l.FindingKey, l.Cve AS CveId, l.Title, l.Severity, l.RiskScore, l.RiskRating, l.WeightedRisk,
       {fd}.HasExploit, {fd}.SourceFirstDetected AS FirstDetected, COALESCE({fd}.FixDueDate, dst.DueAt) AS DueDate, {fd}.ExemptedUntil,
       {LifecycleOf("l").Trim()} AS WithinAcceptedLifecycle,
       l.Version, CASE WHEN l.InThisCollection = 1 THEN N'{SeenNow}' ELSE N'{SeenKept}' END AS Seen,
       CONVERT(nvarchar(20), l.FindingId) AS FindingId, CONVERT(nvarchar(20), l.CollectionId) AS FindingCollectionId
FROM sidata.RemediationTaskFinding AS l
{join}
LEFT JOIN sidata.CiFindingState AS dst ON dst.OwnerKey = l.OwnerKey AND dst.FindingKey = l.FindingKey
WHERE l.CollectionId = {MarkedCollection} AND {IsTask("l")}{limited}
""";
        var parameters = new List<string> { "CollectionId", TaskIdParameter };
        if (v is not null) parameters.AddRange(v.Parameters.Keys);
        return GridSql.Check(new GridSpec(TaskFindings.Name + (v is null ? "@task" : "@dept@task"), "", source, new GridColumn[]
        {
            new("LinkKey", "Link", Hidden: true),
            new("FindingKey", "Finding", Filter: GridFilter.Contains, Search: true),
            new("CveId", "CVE", Filter: GridFilter.Contains, Search: true),
            new("Title", "Title", Filter: GridFilter.Contains, Search: true),
            new("Severity", "Severity", Filter: GridFilter.Values, SortSql: "CASE g.[Severity] WHEN N'critical' THEN 0 WHEN N'high' THEN 1 WHEN N'medium' THEN 2 WHEN N'low' THEN 3 ELSE 4 END"),
            new("RiskScore", "Risk score", GridType.Number, GridFilter.Range),
            new("RiskRating", "Risk rating", Filter: GridFilter.Values, SortSql: RemediationTaskReports.RatingSort("g.[RiskRating]")),
            new("WeightedRisk", "Weighted risk", GridType.Number, GridFilter.Range),
            new("HasExploit", "Exploit", GridType.Flag, GridFilter.Values),
            new("FirstDetected", "First detected", GridType.Date, GridFilter.Dates),
            new("DueDate", "Due date", GridType.Date, GridFilter.Dates),
            new("ExemptedUntil", "Exempted until", GridType.Date, GridFilter.Dates),
            new("WithinAcceptedLifecycle", "Within Accepted Lifecycle", Filter: GridFilter.Values),
            new("Version", "Version", Filter: GridFilter.Contains, Search: true),
            new("Seen", "Seen in", Filter: GridFilter.Values),
            new("FindingId", "Finding row", Hidden: true),
            new("FindingCollectionId", "Collection of the finding", Hidden: true),
        }, "RiskScore", true, "LinkKey", parameters.Distinct(StringComparer.Ordinal).ToList(), Immutable: false));
    }

    /// The grid a limited person gets for one of the task grids (null = not a task grid).
    public static GridSpec? For(GridSpec spec, RowVisibility v) =>
        ReferenceEquals(spec, Tasks) || spec.Name == Tasks.Name ? TasksFor(v)
        : ReferenceEquals(spec, TaskFindings) || spec.Name == TaskFindings.Name ? TaskFindingsFor(v)
        : null;
}
