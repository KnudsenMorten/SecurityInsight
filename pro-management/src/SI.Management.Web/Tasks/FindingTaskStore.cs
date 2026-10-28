using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Data;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Tasks;

/// <summary>THE seam to cfg.FindingTask / cfg.FindingTaskHistory (#265). Tests replace it with an in-memory store.</summary>
public interface IFindingTaskStore
{
    Task<bool> ReadyAsync(CancellationToken ct);
    /// The department people a signed-in person is ('member:&lt;id&gt;', 'advisor:&lt;id&gt;'): for a sign-in link session the
    /// person it was issued to; for an Entra user the departments' entries by object id (their own or a group) or by the
    /// UPN Entra issued.
    Task<IReadOnlyList<string>> PersonKeysAsync(IReadOnlyCollection<string> objectIds, string? upn, long? signInId, CancellationToken ct);
    /// The people of one department a task can be given to: its members (users, groups, mail-only) and active advisors.
    Task<IReadOnlyList<TaskPerson>> PeopleAsync(int departmentId, CancellationToken ct);
    /// Where the finding is in the newest complete collection (its collection and finding id), or nulls.
    Task<(string? CollectionId, string? FindingId)> LocateAsync(string assetKey, string recommendationKey, CancellationToken ct);
    /// Every task in ONE transaction, each with its history row and its change-log row. Returns the first new id.
    Task<(WriteResult Result, long? FirstId)> CreateAsync(IReadOnlyList<NewTask> tasks, string by, string byKey, CancellationToken ct);
    Task<FindingTaskRow?> GetAsync(long taskId, CancellationToken ct);
    Task<IReadOnlyList<FindingTaskRow>> ForFindingAsync(string assetKey, string recommendationKey, CancellationToken ct);
    Task<IReadOnlyList<TaskHistoryRow>> HistoryAsync(long taskId, CancellationToken ct);
    /// The history of every task on one finding (the thread's task entries).
    Task<IReadOnlyList<TaskHistoryRow>> FindingHistoryAsync(string assetKey, string recommendationKey, CancellationToken ct);
    /// Saved | Stale (the task is no longer in the expected status) | Gone. One transaction with its history and change-log rows.
    Task<string> ChangeStatusAsync(long taskId, string expectedStatus, string action, string? note, string by, string byKey, CancellationToken ct);
    Task<TaskPage> QueryAsync(TaskQuery q, CancellationToken ct);
    Task<TaskCounts> CountsAsync(IReadOnlyCollection<string> keys, IReadOnlyList<int>? departments, DateOnly today, int soonDays, CancellationToken ct);
}

/// <summary>
/// THE one class that knows the shape of cfg.FindingTask, cfg.FindingTaskHistory (si-pro-settings.sql, #265). Every write
/// is ONE transaction: the task row(s), the history row(s) and the cfg.ChangeLog row(s) -- Name 'finding-task/&lt;id&gt;',
/// Scope 'finding', Kind 'finding-task', the JSON naming the dotted action (<see cref="TaskActions.AuditName"/>). Nothing
/// is ever deleted. It never decides who may do what: <see cref="FindingTaskService"/> does.
/// </summary>
public sealed class SqlFindingTaskStore : IFindingTaskStore
{
    public const string ReadySql = "SELECT CASE WHEN OBJECT_ID(N'cfg.FindingTask') IS NULL OR OBJECT_ID(N'cfg.FindingTaskHistory') IS NULL THEN 0 ELSE 1 END AS Ready;";

    public const string PersonKeysSql = """
DECLARE @k TABLE (K nvarchar(96));
IF @SignInId IS NOT NULL
BEGIN
    IF OBJECT_ID(N'cfg.DepartmentSignIn') IS NOT NULL
        INSERT @k SELECT LOWER(CONCAT(s.PersonKind, N':', s.PersonId)) FROM cfg.DepartmentSignIn AS s WHERE s.SignInId = @SignInId;
END
ELSE
BEGIN
    IF OBJECT_ID(N'cfg.DepartmentMember') IS NOT NULL
        INSERT @k SELECT CONCAT(N'member:', m.MemberId) FROM cfg.DepartmentMember AS m
        WHERE m.ObjectId IN (SELECT j.[value] FROM OPENJSON(@ObjectIds) AS j) OR (m.ObjectId IS NULL AND @Upn IS NOT NULL AND m.Mail = @Upn);
    IF OBJECT_ID(N'cfg.DepartmentAdvisor') IS NOT NULL
        INSERT @k SELECT CONCAT(N'advisor:', a.AdvisorId) FROM cfg.DepartmentAdvisor AS a
        WHERE a.RevokedAt IS NULL AND (a.ObjectId IN (SELECT j.[value] FROM OPENJSON(@ObjectIds) AS j) OR (@Upn IS NOT NULL AND a.Mail = @Upn));
END;
SELECT DISTINCT K FROM @k;
""";

    public const string PeopleSql = """
DECLARE @p TABLE (DepartmentId int, Kind nvarchar(8), PersonId int, DisplayName nvarchar(256), Mail nvarchar(256), Role nvarchar(24));
IF OBJECT_ID(N'cfg.DepartmentMember') IS NOT NULL
    INSERT @p SELECT m.DepartmentId, N'member', m.MemberId, m.DisplayName, m.Mail, m.Role FROM cfg.DepartmentMember AS m WHERE m.DepartmentId = @DepartmentId;
IF OBJECT_ID(N'cfg.DepartmentAdvisor') IS NOT NULL
    INSERT @p SELECT a.DepartmentId, N'advisor', a.AdvisorId, a.DisplayName, a.Mail, N'advisor' FROM cfg.DepartmentAdvisor AS a WHERE a.DepartmentId = @DepartmentId AND a.RevokedAt IS NULL;
SELECT DepartmentId, Kind, PersonId, DisplayName, Mail, Role FROM @p ORDER BY Kind DESC, DisplayName, PersonId;
""";

    /// The finding in the published run's collection. The recommendation key is the ConfigurationId, else the CVE.
    public const string LocateSql = $"""
DECLARE @c int = {SI.Management.Core.ProData.PublishedRun.DetailedId};
SELECT TOP (1) CONVERT(nvarchar(32), f.CollectionId) AS CollectionId, CONVERT(nvarchar(32), f.FindingId) AS FindingId
FROM sidata.Finding AS f
WHERE f.CollectionId = @c AND f.AssetKey = @AssetKey AND COALESCE(NULLIF(f.ConfigurationId, N''), f.Cve) = @RecommendationKey
ORDER BY f.FindingId;
""";

    /// The tasks whose finding the vulnerability close-loop has CLOSED (and holds no open row for): "finding resolved --
    /// close the task?". The close-loop's table may not exist (no close-loop): nothing is resolved then.
    private const string ClosedPrelude = """
DECLARE @closed TABLE (AssetKey nvarchar(400) NOT NULL, Cve nvarchar(256) NOT NULL, ClosedAt datetime2(0) NULL, CloseReason nvarchar(400) NULL);
IF OBJECT_ID(N'vuln.VulnerabilityItem') IS NOT NULL
    INSERT @closed (AssetKey, Cve, ClosedAt, CloseReason)
    SELECT v.CorrelationId, v.Cve, MAX(v.ClosedAt), MAX(v.CloseReason)
    FROM vuln.VulnerabilityItem AS v
    WHERE v.State = N'Closed'
      AND EXISTS (SELECT 1 FROM cfg.FindingTask AS ot WHERE ot.Status = N'open' AND ot.AssetKey = v.CorrelationId AND ot.RecommendationKey = v.Cve)
      AND NOT EXISTS (SELECT 1 FROM vuln.VulnerabilityItem AS o WHERE o.CorrelationId = v.CorrelationId AND o.Cve = v.Cve AND o.State = N'Open')
    GROUP BY v.CorrelationId, v.Cve;
""";

    private const string Columns = """
t.TaskId, t.AssetKey, t.RecommendationKey, t.AssetName, t.FindingTitle, t.DepartmentId, d.Name AS DepartmentName, t.Title, t.Note, t.AssigneeKind, t.AssigneeId,
t.AssigneeKey, t.AssigneeName, t.AssigneeMail, CONVERT(datetime2(0), t.DueDate) AS DueDate, CONVERT(datetime2(0), t.RemindAt) AS RemindAt, t.Status, t.CreatedAt, t.CreatedBy,
t.CreatedByKey, t.CompletedAt, t.CompletedBy, t.CompletionNote, t.UpdatedAt, cl.ClosedAt AS ResolvedAt, cl.CloseReason AS ResolvedReason
""";

    private const string From = """
FROM cfg.FindingTask AS t
LEFT JOIN cfg.Department AS d ON d.DepartmentId = t.DepartmentId
LEFT JOIN @closed AS cl ON t.Status = N'open' AND cl.AssetKey = t.AssetKey AND cl.Cve = t.RecommendationKey
""";

    private const string NL = "\n";

    public const string GetSql = ClosedPrelude + NL + "SELECT " + Columns + NL + From + NL + "WHERE t.TaskId = @TaskId;";

    public const string ForFindingSql = ClosedPrelude + NL + "SELECT TOP (200) " + Columns + NL + From + NL +
        "WHERE t.AssetKey = @AssetKey AND t.RecommendationKey = @RecommendationKey ORDER BY CASE WHEN t.Status = N'open' THEN 0 ELSE 1 END, t.DueDate, t.TaskId;";

    public const string HistorySql = """
SELECT TOP (500) h.HistoryId, h.TaskId, h.Action, h.Status, h.Note, h.ChangedAt, h.ChangedBy, t.Title AS TaskTitle, t.AssigneeName, CONVERT(datetime2(0), t.DueDate) AS DueDate
FROM cfg.FindingTaskHistory AS h JOIN cfg.FindingTask AS t ON t.TaskId = h.TaskId
WHERE h.TaskId = @TaskId
ORDER BY h.ChangedAt, h.HistoryId;
""";

    public const string FindingHistorySql = """
SELECT TOP (500) h.HistoryId, h.TaskId, h.Action, h.Status, h.Note, h.ChangedAt, h.ChangedBy, t.Title AS TaskTitle, t.AssigneeName, CONVERT(datetime2(0), t.DueDate) AS DueDate
FROM cfg.FindingTaskHistory AS h JOIN cfg.FindingTask AS t ON t.TaskId = h.TaskId
WHERE t.AssetKey = @AssetKey AND t.RecommendationKey = @RecommendationKey
ORDER BY h.ChangedAt, h.HistoryId;
""";

    /// <summary>
    /// ONE write for 1..N tasks (a task from a finding's thread, or one per selected finding): the task rows, a 'created'
    /// history row each, and a change-log row each -- all or nothing.
    /// </summary>
    public const string CreateSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @new TABLE (TaskId bigint, AssetKey nvarchar(400), RecommendationKey nvarchar(256), DepartmentId int, Title nvarchar(200), AssigneeKey nvarchar(96), AssigneeName nvarchar(256), DueDate date);
INSERT cfg.FindingTask (AssetKey, RecommendationKey, AssetName, FindingTitle, DepartmentId, Title, Note, AssigneeKind, AssigneeId, AssigneeKey, AssigneeName, AssigneeMail,
                        DueDate, RemindAt, Status, CreatedBy, CreatedByKey, UpdatedBy)
OUTPUT inserted.TaskId, inserted.AssetKey, inserted.RecommendationKey, inserted.DepartmentId, inserted.Title, inserted.AssigneeKey, inserted.AssigneeName, inserted.DueDate INTO @new
SELECT j.AssetKey, j.RecommendationKey, j.AssetName, j.FindingTitle, j.DepartmentId, j.Title, j.Note, j.AssigneeKind, j.AssigneeId, j.AssigneeKey, j.AssigneeName, j.AssigneeMail,
       CONVERT(date, j.DueDate, 23), CONVERT(date, j.RemindAt, 23), N'open', @By, @ByKey, @By
FROM OPENJSON(@Tasks) WITH (
    AssetKey nvarchar(400) '$.assetKey', RecommendationKey nvarchar(256) '$.recommendationKey', AssetName nvarchar(400) '$.assetName',
    FindingTitle nvarchar(400) '$.findingTitle', DepartmentId int '$.departmentId', Title nvarchar(200) '$.title', Note nvarchar(2000) '$.note',
    AssigneeKind nvarchar(16) '$.assigneeKind', AssigneeId nvarchar(64) '$.assigneeId', AssigneeKey nvarchar(96) '$.assigneeKey',
    AssigneeName nvarchar(256) '$.assigneeName', AssigneeMail nvarchar(256) '$.assigneeMail', DueDate nvarchar(10) '$.dueDate', RemindAt nvarchar(10) '$.remindAt') AS j;
INSERT cfg.FindingTaskHistory (TaskId, Action, Status, Note, ChangedBy, ChangedByKey)
SELECT n.TaskId, N'created', N'open', NULL, @By, @ByKey FROM @new AS n;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
SELECT LEFT(CONCAT(N'finding-task/', n.TaskId), 128), N'finding', N'finding-task', N'Set', NULL,
       (SELECT N'finding.task.create' AS action, n.TaskId AS task, n.AssetKey AS asset, n.RecommendationKey AS recommendation, n.DepartmentId AS department, n.Title AS title,
               n.AssigneeKey AS assignee, n.AssigneeName AS assigneeName, CONVERT(nvarchar(10), n.DueDate, 23) AS due FOR JSON PATH, WITHOUT_ARRAY_WRAPPER),
       @By, LEFT(CONCAT(N'task created: ', n.Title, N' (', n.AssigneeName, N')'), 400)
FROM @new AS n;
COMMIT;
SELECT N'Saved' AS Outcome, COUNT_BIG(*) AS N, MIN(TaskId) AS FirstId FROM @new;
""";

    /// <summary>
    /// Complete / cancel / reopen ONE task: only from the status the person saw (else Stale -- someone else changed it),
    /// with its history row and its change-log row, in one transaction. A task is never deleted.
    /// </summary>
    public const string ChangeStatusSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
DECLARE @old nvarchar(16), @title nvarchar(200), @asset nvarchar(400), @rec nvarchar(256), @dept int;
SELECT @old = t.Status, @title = t.Title, @asset = t.AssetKey, @rec = t.RecommendationKey, @dept = t.DepartmentId
FROM cfg.FindingTask AS t WITH (UPDLOCK, HOLDLOCK) WHERE t.TaskId = @TaskId;
IF @old IS NULL BEGIN COMMIT; SELECT N'Gone' AS Outcome; RETURN; END;
IF @old <> @Expected BEGIN COMMIT; SELECT N'Stale' AS Outcome; RETURN; END;
UPDATE cfg.FindingTask
   SET Status = @Status,
       CompletedAt = CASE WHEN @Status = N'open' THEN NULL ELSE SYSUTCDATETIME() END,
       CompletedBy = CASE WHEN @Status = N'open' THEN NULL ELSE @By END,
       CompletionNote = CASE WHEN @Status = N'open' THEN NULL ELSE @Note END,
       UpdatedAt = SYSUTCDATETIME(), UpdatedBy = @By
 WHERE TaskId = @TaskId;
INSERT cfg.FindingTaskHistory (TaskId, Action, Status, Note, ChangedBy, ChangedByKey) VALUES (@TaskId, @Action, @Status, @Note, @By, @ByKey);
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(CONCAT(N'finding-task/', @TaskId), 128), N'finding', N'finding-task', N'Set', @old,
        (SELECT @AuditAction AS action, @TaskId AS task, @asset AS asset, @rec AS recommendation, @dept AS department, @Status AS status, @Note AS note FOR JSON PATH, WITHOUT_ARRAY_WRAPPER),
        @By, LEFT(CONCAT(N'task ', @Action, N': ', @title, CASE WHEN @Note IS NULL THEN N'' ELSE CONCAT(N' -- ', @Note) END), 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    /// The WHERE of every list: the view (mine / delegated / all), the departments the user may see, a department, a
    /// search text, and the "show" choice -- the same rules as <see cref="TaskDue"/>.
    private const string ListWhere = """
DECLARE @d date = CONVERT(date, @Today, 23);
WHERE (@View <> N'mine' OR t.AssigneeKey IN (SELECT j.[value] FROM OPENJSON(@Keys) AS j))
  AND (@View <> N'delegated' OR (t.CreatedByKey IN (SELECT j.[value] FROM OPENJSON(@PersonalKeys) AS j)
                                AND t.AssigneeKey NOT IN (SELECT j.[value] FROM OPENJSON(@Keys) AS j)))
  AND (@Departments IS NULL OR t.DepartmentId IN (SELECT TRY_CONVERT(int, j.[value]) FROM OPENJSON(@Departments) AS j))
  AND (@DepartmentIds IS NULL OR t.DepartmentId IN (SELECT TRY_CONVERT(int, dj.[value]) FROM OPENJSON(@DepartmentIds) AS dj)
       OR (t.DepartmentId IS NULL AND EXISTS (SELECT 1 FROM OPENJSON(@DepartmentIds) AS dj WHERE TRY_CONVERT(int, dj.[value]) = 0)))
  AND (@Like IS NULL OR t.Title LIKE @Like ESCAPE N'\' OR t.AssetName LIKE @Like ESCAPE N'\' OR t.FindingTitle LIKE @Like ESCAPE N'\'
       OR t.RecommendationKey LIKE @Like ESCAPE N'\' OR t.AssigneeName LIKE @Like ESCAPE N'\' OR t.CreatedBy LIKE @Like ESCAPE N'\')
  AND (   (@Show = N'open' AND t.Status = N'open')
       OR (@Show = N'overdue' AND t.Status = N'open' AND t.DueDate < @d)
       OR (@Show = N'soon' AND t.Status = N'open' AND t.DueDate >= @d AND t.DueDate <= DATEADD(day, @SoonDays, @d))
       OR (@Show = N'recent' AND t.Status = N'done' AND t.CompletedAt >= CONVERT(datetime2(0), DATEADD(day, -@RecentDays, @d)))
       OR (@Show = N'done' AND t.Status = N'done')
       OR (@Show = N'cancelled' AND t.Status = N'cancelled')
       OR @Show = N'any')
""";

    /// The ORDER BY of each sortable column -- a fixed map, so nothing a user sends reaches the statement text.
    public static readonly IReadOnlyDictionary<string, string> SortColumns = new Dictionary<string, string>
    {
        ["due"] = "t.DueDate", ["created"] = "t.CreatedAt", ["title"] = "t.Title", ["asset"] = "t.AssetName", ["assignee"] = "t.AssigneeName",
        ["creator"] = "t.CreatedBy", ["status"] = "t.Status", ["department"] = "d.Name", ["updated"] = "t.UpdatedAt",
    };

    /// The page statement for a sort (column + direction from <see cref="SortColumns"/> only).
    public static string ListSql(string sort, bool descending)
    {
        var col = SortColumns.TryGetValue(sort, out var c) ? c : SortColumns["due"];
        var dir = descending ? "DESC" : "ASC";
        // the DECLARE in ListWhere goes first: split it off
        var where = ListWhere;
        var nl = where.IndexOf('\n');
        return ClosedPrelude + NL + where[..(nl + 1)] + "SELECT " + Columns + ", COUNT_BIG(*) OVER () AS Total" + NL + From + NL + where[(nl + 1)..]
               + NL + $"ORDER BY {col} {dir}, t.TaskId {dir}" + NL + "OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY;";
    }

    public const string CountsSql = """
DECLARE @d date = CONVERT(date, @Today, 23);
SELECT COUNT_BIG(*) AS OpenTasks,
       ISNULL(SUM(CASE WHEN t.DueDate < @d THEN 1 ELSE 0 END), 0) AS Overdue,
       ISNULL(SUM(CASE WHEN t.DueDate >= @d AND t.DueDate <= DATEADD(day, @SoonDays, @d) THEN 1 ELSE 0 END), 0) AS DueSoon
FROM cfg.FindingTask AS t
WHERE t.Status = N'open' AND t.AssigneeKey IN (SELECT j.[value] FROM OPENJSON(@Keys) AS j)
  AND (@Departments IS NULL OR t.DepartmentId IN (SELECT TRY_CONVERT(int, j.[value]) FROM OPENJSON(@Departments) AS j));
""";

    private readonly ISqlExecutor _sql;
    public SqlFindingTaskStore(ISqlExecutor sql) => _sql = sql;

    private static string Iso(DateOnly d) => d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
    private static string? Json(IReadOnlyList<int>? ids) => ids is null ? null : JsonSerializer.Serialize(ids);
    private static string Like(string text) => "%" + text.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_").Replace("[", "\\[") + "%";

    public static FindingTaskRow Row(SqlRow r) => new(r.Long("TaskId") ?? 0, r.Str("AssetKey") ?? "", r.Str("RecommendationKey") ?? "", r.Str("AssetName"), r.Str("FindingTitle"),
        (int?)r.Long("DepartmentId"), r.Str("DepartmentName"), r.Str("Title") ?? "", r.Str("Note"), r.Str("AssigneeKind") ?? "", r.Str("AssigneeId") ?? "", r.Str("AssigneeKey") ?? "",
        r.Str("AssigneeName") ?? "", r.Str("AssigneeMail"), r.Date("DueDate") ?? DateTime.MinValue, r.Date("RemindAt"), r.Str("Status") ?? TaskStatuses.Open, r.Date("CreatedAt"),
        r.Str("CreatedBy") ?? "", r.Str("CreatedByKey") ?? "", r.Date("CompletedAt"), r.Str("CompletedBy"), r.Str("CompletionNote"), r.Date("UpdatedAt"), r.Date("ResolvedAt"),
        r.Str("ResolvedReason"));

    private static TaskHistoryRow History(SqlRow r) => new(r.Long("HistoryId") ?? 0, r.Long("TaskId") ?? 0, r.Str("Action") ?? "", r.Str("Status") ?? "", r.Str("Note"),
        r.Date("ChangedAt"), r.Str("ChangedBy") ?? "", r.Str("TaskTitle"), r.Str("AssigneeName"), r.Date("DueDate"));

    public async Task<bool> ReadyAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ReadySql, new Dictionary<string, object?>(), ct);
        return rows.Count > 0 && rows[0].Long("Ready") == 1;
    }

    public async Task<IReadOnlyList<string>> PersonKeysAsync(IReadOnlyCollection<string> objectIds, string? upn, long? signInId, CancellationToken ct) =>
        (await _sql.QueryAsync(PersonKeysSql, new Dictionary<string, object?>
        {
            ["ObjectIds"] = JsonSerializer.Serialize(objectIds.Select(o => o.Trim().ToLowerInvariant()).Distinct().ToArray()),
            ["Upn"] = string.IsNullOrWhiteSpace(upn) ? null : upn.Trim().ToLowerInvariant(), ["SignInId"] = signInId,
        }, ct)).Select(r => r.Str("K")).Where(k => !string.IsNullOrWhiteSpace(k)).Select(k => k!.ToLowerInvariant()).Distinct().ToList();

    public async Task<IReadOnlyList<TaskPerson>> PeopleAsync(int departmentId, CancellationToken ct) =>
        (await _sql.QueryAsync(PeopleSql, new Dictionary<string, object?> { ["DepartmentId"] = departmentId }, ct))
        .Where(r => r.Long("PersonId") is > 0)
        .Select(r => new TaskPerson((int)(r.Long("DepartmentId") ?? 0), r.Str("Kind") ?? "", (int)(r.Long("PersonId") ?? 0), r.Str("DisplayName") ?? "", r.Str("Mail"), r.Str("Role") ?? "")).ToList();

    public async Task<(string? CollectionId, string? FindingId)> LocateAsync(string assetKey, string recommendationKey, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(LocateSql, new Dictionary<string, object?> { ["AssetKey"] = assetKey, ["RecommendationKey"] = recommendationKey }, ct);
        return rows.Count == 0 ? (null, null) : (rows[0].Str("CollectionId"), rows[0].Str("FindingId"));
    }

    public async Task<(WriteResult Result, long? FirstId)> CreateAsync(IReadOnlyList<NewTask> tasks, string by, string byKey, CancellationToken ct)
    {
        var json = JsonSerializer.Serialize(tasks.Select(t => new
        {
            assetKey = t.AssetKey, recommendationKey = t.RecommendationKey, assetName = t.AssetName, findingTitle = t.FindingTitle, departmentId = t.DepartmentId,
            title = t.Title, note = t.Note, assigneeKind = t.Assignee.Kind, assigneeId = t.Assignee.Id, assigneeKey = t.Assignee.Key, assigneeName = t.Assignee.Name,
            assigneeMail = t.Assignee.Mail, dueDate = Iso(t.DueDate), remindAt = t.RemindAt is { } r ? Iso(r) : null,
        }));
        var rows = await _sql.QueryAsync(CreateSql, new Dictionary<string, object?> { ["Tasks"] = json, ["By"] = by, ["ByKey"] = byKey }, ct);
        if (rows.Count == 0 || rows[0].Str("Outcome") != "Saved") throw new InvalidOperationException("the task write returned no outcome");
        var n = rows[0].Long("N") ?? 0;
        return (new WriteResult(WriteStatus.Saved, n == 1 ? "task created" : $"{n} tasks created"), rows[0].Long("FirstId"));
    }

    public async Task<FindingTaskRow?> GetAsync(long taskId, CancellationToken ct) =>
        (await _sql.QueryAsync(GetSql, new Dictionary<string, object?> { ["TaskId"] = taskId }, ct)).Where(r => r.Long("TaskId") is > 0).Select(Row).FirstOrDefault();

    public async Task<IReadOnlyList<FindingTaskRow>> ForFindingAsync(string assetKey, string recommendationKey, CancellationToken ct) =>
        (await _sql.QueryAsync(ForFindingSql, new Dictionary<string, object?> { ["AssetKey"] = assetKey, ["RecommendationKey"] = recommendationKey }, ct))
        .Where(r => r.Long("TaskId") is > 0).Select(Row).ToList();

    public async Task<IReadOnlyList<TaskHistoryRow>> HistoryAsync(long taskId, CancellationToken ct) =>
        (await _sql.QueryAsync(HistorySql, new Dictionary<string, object?> { ["TaskId"] = taskId }, ct)).Where(r => r.Long("HistoryId") is > 0).Select(History).ToList();

    public async Task<IReadOnlyList<TaskHistoryRow>> FindingHistoryAsync(string assetKey, string recommendationKey, CancellationToken ct) =>
        (await _sql.QueryAsync(FindingHistorySql, new Dictionary<string, object?> { ["AssetKey"] = assetKey, ["RecommendationKey"] = recommendationKey }, ct))
        .Where(r => r.Long("HistoryId") is > 0).Select(History).ToList();

    public async Task<string> ChangeStatusAsync(long taskId, string expectedStatus, string action, string? note, string by, string byKey, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ChangeStatusSql, new Dictionary<string, object?>
        {
            ["TaskId"] = taskId, ["Expected"] = expectedStatus, ["Status"] = TaskActions.StatusAfter(action), ["Action"] = action, ["AuditAction"] = TaskActions.AuditName(action),
            ["Note"] = string.IsNullOrWhiteSpace(note) ? null : note.Trim(), ["By"] = by, ["ByKey"] = byKey,
        }, ct);
        return rows.Count > 0 ? rows[0].Str("Outcome") ?? "Gone" : throw new InvalidOperationException("the task write returned no outcome");
    }

    public async Task<TaskPage> QueryAsync(TaskQuery query, CancellationToken ct)
    {
        var q = query.Normalized();
        var rows = await _sql.QueryAsync(ListSql(q.Sort, q.Descending), new Dictionary<string, object?>
        {
            ["View"] = q.View, ["Keys"] = JsonSerializer.Serialize(q.Keys), ["PersonalKeys"] = JsonSerializer.Serialize(q.PersonalKeys), ["Departments"] = Json(q.Departments),
            // the department filter: one or more departments (0 = Unassigned), a JSON array its IN-list reads; null = every one
            ["DepartmentIds"] = q.AllDepartmentIds.Count == 0 ? null : JsonSerializer.Serialize(q.AllDepartmentIds), ["Like"] = q.Text is null ? null : Like(q.Text), ["Show"] = q.Show, ["Today"] = Iso(q.Today), ["SoonDays"] = q.SoonDays,
            ["RecentDays"] = q.RecentDays, ["Skip"] = (q.Page - 1) * q.Size, ["Take"] = q.Size,
        }, ct);
        var list = rows.Where(r => r.Long("TaskId") is > 0).ToList();
        return new TaskPage(list.Select(Row).ToList(), list.Count > 0 ? list[0].Long("Total") ?? list.Count : 0, q.Page, q.Size);
    }

    public async Task<TaskCounts> CountsAsync(IReadOnlyCollection<string> keys, IReadOnlyList<int>? departments, DateOnly today, int soonDays, CancellationToken ct)
    {
        if (keys.Count == 0) return new TaskCounts(0, 0, 0);
        var rows = await _sql.QueryAsync(CountsSql, new Dictionary<string, object?>
        {
            ["Keys"] = JsonSerializer.Serialize(keys), ["Departments"] = Json(departments), ["Today"] = Iso(today), ["SoonDays"] = soonDays,
        }, ct);
        return rows.Count == 0 ? new TaskCounts(0, 0, 0) : new TaskCounts(rows[0].Long("OpenTasks") ?? 0, rows[0].Long("Overdue") ?? 0, rows[0].Long("DueSoon") ?? 0);
    }
}
