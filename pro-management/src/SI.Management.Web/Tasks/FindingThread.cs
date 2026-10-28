using System.Globalization;
using System.Security.Claims;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Departments;
using SI.Management.Web.FindingComments;

namespace SI.Management.Web.Tasks;

/// <summary>
/// One entry of a finding's ONE thread (#265) -- read from the store it lives in, never copied: a governance log entry
/// (#254: a comment, or a status with its comment), a finding comment (#258: comment / recommend / approve), or a change
/// of one of the finding's tasks (created / completed / cancelled / reopened).
/// </summary>
/// <param name="Source">governance | comment | task</param>
/// <param name="Kind">status | comment | recommend | approve | task-created | task-completed | task-cancelled | task-reopened</param>
public sealed record ThreadItem(DateTime? At, string Source, string Kind, string Who, string? Badge, string Text, long Id,
    string? Status = null, long? TaskId = null, DateTime? ScheduledFor = null, long? ExemptionRequestId = null, string? Detail = null)
{
    public const string FromGovernance = "governance";
    public const string FromComment = "comment";
    public const string FromTask = "task";

    public string Label => Kind switch
    {
        "status" => "Status: " + GovernanceStatuses.Label(Status),
        "comment" => "Comment",
        "recommend" => "Recommendation",
        "approve" => "Approval",
        _ when Kind.StartsWith("task-", StringComparison.Ordinal) => TaskActions.Label(Kind["task-".Length..]),
        _ => Kind,
    };
}

/// <summary>
/// THE READ MODEL of a finding's thread (PURE): the governance log (cfg.GovernanceEntry), the comments (cfg.FindingComment)
/// and the task history (cfg.FindingTaskHistory) of ONE (AssetKey, RecommendationKey), merged into one list, oldest first.
/// Both earlier tables stay as they are -- nothing is moved or copied; this only reads them side by side.
/// </summary>
public static class FindingThread
{
    private static int Order(string source) => source switch { ThreadItem.FromGovernance => 0, ThreadItem.FromComment => 1, _ => 2 };

    public static IReadOnlyList<ThreadItem> Merge(IEnumerable<GovernanceEntryRow>? governance, IEnumerable<FindingCommentRow>? comments, IEnumerable<TaskHistoryRow>? tasks)
    {
        var items = new List<ThreadItem>();
        foreach (var e in governance ?? [])
            items.Add(new ThreadItem(e.CreatedAt, ThreadItem.FromGovernance, e.Status is null ? "comment" : "status", e.CreatedBy,
                e.Source == "web" ? null : e.Source == "flow" ? "remediation flow" : e.Source, e.Comment, e.EntryId, e.Status, null, e.ScheduledFor, e.ExemptionRequestId));
        foreach (var c in comments ?? [])
            items.Add(new ThreadItem(c.CreatedAt, ThreadItem.FromComment, c.Kind, c.Author, c.AuthorRole, c.Body, c.CommentId, Detail: "signed in by " + c.AuthMethod));
        foreach (var h in tasks ?? [])
        {
            var text = h.TaskTitle ?? "";
            if (h.Action == TaskActions.Created)
                text += " -- for " + (h.AssigneeName ?? "?") + (h.DueDate is { } d ? ", due " + d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "");
            if (!string.IsNullOrWhiteSpace(h.Note)) text += ": " + h.Note;
            items.Add(new ThreadItem(h.ChangedAt, ThreadItem.FromTask, "task-" + h.Action, h.ChangedBy, null, text, h.HistoryId, h.Status, h.TaskId));
        }
        return items.OrderBy(i => i.At ?? DateTime.MinValue).ThenBy(i => Order(i.Source)).ThenBy(i => i.Id).ToList();
    }
}

/// Everything the thread partial (Pages/Shared/_FindingThread.cshtml) shows and offers for one finding, for one user.
public sealed class FindingThreadView
{
    public required GovernanceTarget Target { get; init; }
    /// The collection + finding id the forms post with.
    public required string CollectionId { get; init; }
    public required string FindingId { get; init; }
    /// Where a write comes back to (the page that showed the thread).
    public required string ReturnUrl { get; init; }
    public bool Visible { get; init; } = true;
    public string? HiddenWhy { get; init; }
    public IReadOnlyList<ThreadItem> Items { get; init; } = Array.Empty<ThreadItem>();
    public IReadOnlyList<FindingTaskRow> Tasks { get; init; } = Array.Empty<FindingTaskRow>();
    public GovernanceStateRow? State { get; init; }
    public bool GovernanceReady { get; init; }
    public bool CommentsReady { get; init; }
    public bool TasksReady { get; init; }
    /// The governance log's writers (a comment / a status) -- and, the same people, who may create a task.
    public AccessDecision Write { get; init; } = AccessDecision.No("");
    public AccessDecision CreateTask { get; init; } = AccessDecision.No("");
    public AccessDecision Recommend { get; init; } = AccessDecision.No("");
    public AccessDecision Approve { get; init; } = AccessDecision.No("");
    /// A sign-in link session that has not passed the second check: approving asks for the one-time code first.
    public bool NeedsCode { get; init; }
    public IReadOnlyList<TaskPerson> People { get; init; } = Array.Empty<TaskPerson>();
    public bool MayAssignEntra { get; init; }
    public TaskIdentity? Me { get; init; }
    public DateOnly Today { get; init; }
    /// Shows the governance comment / status form (the department finding page does; the finding detail links to it).
    public bool ShowGovernanceForm { get; init; } = true;

    public string FindingPage => "/Departments/Finding?c=" + Uri.EscapeDataString(CollectionId) + "&id=" + Uri.EscapeDataString(FindingId);
}

/// <summary>
/// Builds the thread of ONE finding for ONE user: who may see it (the department scope -- a finding outside the user's
/// departments shows no thread), the merged entries, the finding's tasks, and every gate the forms need, each decided by
/// the service that decides it today (<see cref="GovernanceService.CanWriteAsync"/>, <see cref="FindingCommentService.Can"/>,
/// <see cref="FindingTaskService.CanCreateAsync"/>). A store that is not there yet (schema not applied) shows nothing of it.
/// </summary>
public sealed class FindingThreadService
{
    private readonly GovernanceService _gov;
    private readonly FindingCommentService _comments;
    private readonly FindingTaskService _tasks;
    private readonly IDepartmentScopeResolver _scope;
    private readonly ILogger<FindingThreadService> _log;

    public FindingThreadService(GovernanceService gov, FindingCommentService comments, FindingTaskService tasks, IDepartmentScopeResolver scope, ILogger<FindingThreadService> log)
    { _gov = gov; _comments = comments; _tasks = tasks; _scope = scope; _log = log; }

    /// The comment store's facts of a finding, from the finding itself (no second read).
    public static FindingFacts Facts(GovernanceTarget t) => new(t.AssetKey, t.RecommendationKey ?? "", t.Finding.AssetName, t.Finding.Title, t.Finding.Severity,
        t.Finding.SecurityDomain, string.IsNullOrWhiteSpace(t.Finding.AssetKind) ? null : t.Finding.AssetKind.ToLowerInvariant(),
        string.IsNullOrWhiteSpace(t.Finding.Tier) || t.Finding.Tier == ProDataFilters.Unclassified ? null : t.Finding.Tier, t.DepartmentId, t.CollectionId);

    /// The finding's department (the data sync's stamp), else none -- a failing read is "Unassigned", never a crash.
    public async Task<GovernanceTarget> TargetAsync(FindingRow f, CancellationToken ct)
    {
        try
        {
            var d = await _gov.Repository.FindingDepartmentAsync(f.CollectionId, f.FindingId, ct);
            return new GovernanceTarget(f, d?.DepartmentId, d?.DepartmentName, d?.CollectionId ?? f.CollectionId);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the department of a finding could not be read");
            return new GovernanceTarget(f, null, null, f.CollectionId);
        }
    }

    public async Task<FindingThreadView> LoadAsync(ClaimsPrincipal user, GovernanceTarget t, string returnUrl, CancellationToken ct, bool showGovernanceForm = true)
    {
        var f = t.Finding;
        var access = await _scope.ResolveAsync(user, ct);
        if (!access.Unrestricted && (t.DepartmentId is not { } dep || !access.Sees(dep)))
            return new FindingThreadView { Target = t, CollectionId = f.CollectionId, FindingId = f.FindingId, ReturnUrl = returnUrl, Visible = false,
                HiddenWhy = "This finding is not one of your departments', so its thread and tasks are not shown." };
        var rk = t.RecommendationKey;
        IReadOnlyList<GovernanceEntryRow> log = Array.Empty<GovernanceEntryRow>();
        IReadOnlyList<FindingCommentRow> comments = Array.Empty<FindingCommentRow>();
        IReadOnlyList<TaskHistoryRow> history = Array.Empty<TaskHistoryRow>();
        IReadOnlyList<FindingTaskRow> tasks = Array.Empty<FindingTaskRow>();
        GovernanceStateRow? state = null;
        bool govReady = false, comReady = false, taskReady = false;
        if (rk is not null)
        {
            try
            {
                govReady = await _gov.Repository.TablesExistAsync(ct);
                if (govReady) { log = await _gov.Repository.FindingLogAsync(t.AssetKey, rk, ct); state = await _gov.Repository.StateAsync(t.AssetKey, rk, ct); }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { govReady = false; _log.LogWarning(ex, "the governance log could not be read"); }
            try
            {
                comReady = await _comments.ReadyAsync(ct);
                if (comReady) comments = await _comments.ListAsync(t.AssetKey, rk, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { comReady = false; _log.LogWarning(ex, "the finding comments could not be read"); }
            try
            {
                taskReady = await _tasks.Store.ReadyAsync(ct);
                if (taskReady) { tasks = await _tasks.Store.ForFindingAsync(t.AssetKey, rk, ct); history = await _tasks.Store.FindingHistoryAsync(t.AssetKey, rk, ct); }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { taskReady = false; _log.LogWarning(ex, "the finding's tasks could not be read"); }
        }
        var facts = Facts(t);
        var write = rk is null ? AccessDecision.No("the finding has no recommendation (configuration id or CVE) to log against") : await _gov.CanWriteAsync(user, t, ct);
        var create = rk is null ? write : await _tasks.CanCreateAsync(user, t, ct);
        IReadOnlyList<TaskPerson> people = Array.Empty<TaskPerson>();
        if (create.Allowed && taskReady && t.DepartmentId is { } did)
        {
            try { people = await _tasks.Store.PeopleAsync(did, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the department's people could not be read"); }
        }
        return new FindingThreadView
        {
            Target = t, CollectionId = f.CollectionId, FindingId = f.FindingId, ReturnUrl = returnUrl,
            Items = FindingThread.Merge(log, comments, history), Tasks = tasks, State = state,
            GovernanceReady = govReady, CommentsReady = comReady, TasksReady = taskReady,
            Write = write, CreateTask = create,
            Recommend = rk is null ? write : _comments.Can(user, FindingCommentKinds.Recommend, facts),
            Approve = rk is null ? write : _comments.Can(user, FindingCommentKinds.Approve, facts),
            NeedsCode = DepartmentSessions.IsSession(user) && AuthMethods.Of(user) == AuthMethods.MagicLink,
            People = people, MayAssignEntra = create.Allowed && await _tasks.MayAssignEntraAsync(user, ct),
            Me = await _tasks.IdentityAsync(user, ct), Today = _tasks.Today, ShowGovernanceForm = showGovernanceForm,
        };
    }

    /// A local return address the forms may come back to (a finding page or a task list), else null.
    public static string? SafeReturn(string? url) =>
        url is { Length: > 1 and < 600 } u && u[0] == '/' && u[1] != '/' && u[1] != '\\'
        && (u.StartsWith("/Findings/Detail", StringComparison.OrdinalIgnoreCase) || u.StartsWith("/Departments/Finding", StringComparison.OrdinalIgnoreCase)
            || u.StartsWith("/Tasks", StringComparison.OrdinalIgnoreCase) || u.StartsWith("/Admin/Tasks", StringComparison.OrdinalIgnoreCase))
            ? u : null;
}
