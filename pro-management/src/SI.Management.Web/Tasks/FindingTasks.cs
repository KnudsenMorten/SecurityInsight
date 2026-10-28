using System.Globalization;
using System.Security.Claims;
using System.Text.RegularExpressions;
using SI.Management.Web.Auth;

namespace SI.Management.Web.Tasks;

/// <summary>
/// FOLLOW-UP TASKS ON ONE FINDING (#265): "waiting for X to come back", on one vulnerability on one asset, assigned to a
/// person, due on a day. Keyed by (AssetKey, RecommendationKey) like the governance log (#254) and the finding comments
/// (#258), so a task follows the finding across collections. Never deleted: completed, cancelled, reopened.
/// </summary>
public static class TaskStatuses
{
    public const string Open = "open";
    public const string Done = "done";
    public const string Cancelled = "cancelled";
    public static readonly IReadOnlyList<string> All = [Open, Done, Cancelled];

    public static string Label(string? s) => s switch { Open => "Open", Done => "Done", Cancelled => "Cancelled", _ => s ?? "" };
}

/// What changed a task (cfg.FindingTaskHistory.Action) and the dotted name the audit trail uses for it (#260 / AUDIT-1).
public static class TaskActions
{
    public const string Created = "created";
    public const string Completed = "completed";
    public const string Cancelled = "cancelled";
    public const string Reopened = "reopened";

    /// The stable dotted action name of each change -- the ONE place they are named, written into the change-log row's
    /// JSON (<c>action</c>) today; the audit writer of #260 takes the same names.
    public static string AuditName(string action) => action switch
    {
        Created => "finding.task.create",
        Completed => "finding.task.complete",
        Cancelled => "finding.task.cancel",
        Reopened => "finding.task.reopen",
        _ => "finding.task." + action,
    };

    public static string StatusAfter(string action) => action switch
    {
        Completed => TaskStatuses.Done,
        Cancelled => TaskStatuses.Cancelled,
        _ => TaskStatuses.Open,
    };

    public static string Label(string action) => action switch
    {
        Created => "Task created",
        Completed => "Task completed",
        Cancelled => "Task cancelled",
        Reopened => "Task reopened",
        _ => "Task " + action,
    };
}

/// Who a task is assigned to: an Entra user or group (object id), a person of a department (cfg.DepartmentMember), or an
/// advisor of a department (cfg.DepartmentAdvisor, #258).
public static partial class AssigneeKinds
{
    public const string User = "user";
    public const string Group = "group";
    public const string Member = "member";
    public const string Advisor = "advisor";
    public static readonly IReadOnlyList<string> All = [User, Group, Member, Advisor];

    [GeneratedRegex(@"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", RegexOptions.CultureInvariant)] private static partial Regex Guid();
    [GeneratedRegex(@"^[1-9][0-9]{0,9}$", RegexOptions.CultureInvariant)] private static partial Regex Id();

    public static bool IsObjectId(string? s) => s is not null && Guid().IsMatch(s.Trim());
    public static bool IsPersonId(string? s) => s is not null && Id().IsMatch(s.Trim());

    /// '&lt;kind&gt;:&lt;id&gt;' in lower case -- what cfg.FindingTask.AssigneeKey holds and "My tasks" matches.
    public static string Key(string kind, string id) => (kind.Trim() + ":" + id.Trim()).ToLowerInvariant();

    public static string Label(string kind) => kind switch { User => "user", Group => "group", Member => "department person", Advisor => "advisor", _ => kind };
}

/// One task, as the lists and the thread read it. <see cref="ResolvedAt"/>: the vulnerability close-loop closed the finding
/// (the task is shown as "finding resolved -- close the task?"; it is never closed automatically).
public sealed record FindingTaskRow(long TaskId, string AssetKey, string RecommendationKey, string? AssetName, string? FindingTitle, int? DepartmentId,
    string? DepartmentName, string Title, string? Note, string AssigneeKind, string AssigneeId, string AssigneeKey, string AssigneeName, string? AssigneeMail,
    DateTime DueDate, DateTime? RemindAt, string Status, DateTime? CreatedAt, string CreatedBy, string CreatedByKey, DateTime? CompletedAt, string? CompletedBy,
    string? CompletionNote, DateTime? UpdatedAt, DateTime? ResolvedAt = null, string? ResolvedReason = null)
{
    public bool IsOpen => Status == TaskStatuses.Open;
    public bool FindingResolved => ResolvedAt is not null;
}

/// One change of a task (cfg.FindingTaskHistory) -- with the task's finding and title, for the finding's thread.
public sealed record TaskHistoryRow(long HistoryId, long TaskId, string Action, string Status, string? Note, DateTime? ChangedAt, string ChangedBy,
    string? TaskTitle = null, string? AssigneeName = null, DateTime? DueDate = null);

/// A new task, validated: the finding (asset + recommendation, its name, title and department) and what was asked.
public sealed record NewTask(string AssetKey, string RecommendationKey, string? AssetName, string? FindingTitle, int? DepartmentId, string Title, string? Note,
    TaskAssignee Assignee, DateOnly DueDate, DateOnly? RemindAt);

/// The assignee as stored.
public sealed record TaskAssignee(string Kind, string Id, string Name, string? Mail)
{
    public string Key => AssigneeKinds.Key(Kind, Id);
}

/// A person of a department a task can be given to (a member -- user, group or mail-only -- or an advisor).
public sealed record TaskPerson(int DepartmentId, string Kind, int PersonId, string DisplayName, string? Mail, string Role)
{
    public string Key => AssigneeKinds.Key(Kind, PersonId.ToString(CultureInfo.InvariantCulture));
}

/// The open / overdue tasks of the signed-in person (the header group).
public sealed record TaskCounts(long Open, long Overdue, long DueSoon);

/// <summary>
/// The task lists (My tasks, Delegated tasks, Admin > All tasks): a SERVER-side grid -- filtered, sorted and paged in SQL
/// (BRAND-2.7). Every column the user can sort by is in <see cref="Sorts"/>; nothing else reaches the ORDER BY.
/// </summary>
public sealed record TaskQuery
{
    public const string ViewMine = "mine";
    public const string ViewDelegated = "delegated";
    public const string ViewAll = "all";
    public static readonly IReadOnlyList<string> Views = [ViewMine, ViewDelegated, ViewAll];

    /// open (default) | overdue | soon | recent (done in the last <see cref="RecentDays"/> days) | done | cancelled | any
    public static readonly IReadOnlyList<string> Shows = ["open", "overdue", "soon", "recent", "done", "cancelled", "any"];
    public static readonly IReadOnlyList<string> Sorts = ["due", "created", "title", "asset", "assignee", "creator", "status", "department", "updated"];
    public static readonly int[] Sizes = SI.Management.Core.ProData.GridSql.PageChoices;

    public string View { get; init; } = ViewMine;
    /// The signed-in person's keys (assignee side: their own, their groups, the department person they are).
    public IReadOnlyList<string> Keys { get; init; } = Array.Empty<string>();
    /// The keys a task's creator is matched on (their own, never their groups).
    public IReadOnlyList<string> PersonalKeys { get; init; } = Array.Empty<string>();
    /// The departments the user may see; null = every one (and the Unassigned tasks).
    public IReadOnlyList<int>? Departments { get; init; }
    public string Show { get; init; } = "open";
    public int? DepartmentId { get; init; }
    /// Several departments at once (owner 2026-10-19: every filter multi-select; 0 = Unassigned); null = <see cref="DepartmentId"/> alone.
    public IReadOnlyList<int>? DepartmentIds { get; init; }
    /// Every department the list is filtered to (none = every one).
    public IReadOnlyList<int> AllDepartmentIds => DepartmentIds is { Count: > 0 } d ? d : DepartmentId is { } one ? [one] : [];
    public string? Text { get; init; }
    public string Sort { get; init; } = "due";
    public bool Descending { get; init; }
    public int Page { get; init; } = 1;
    public int Size { get; init; } = 50;
    public DateOnly Today { get; init; } = DateOnly.FromDateTime(DateTime.UtcNow);
    public int SoonDays { get; init; } = TaskDue.SoonDays;
    public int RecentDays { get; init; } = TaskDue.RecentDays;

    public TaskQuery Normalized() => this with
    {
        View = Views.Contains(View) ? View : ViewMine,
        Show = Shows.Contains(Show) ? Show : "open",
        Sort = Sorts.Contains(Sort) ? Sort : "due",
        Page = Math.Clamp(Page, 1, int.MaxValue / Math.Max(1, SI.Management.Core.ProData.GridSql.PageSize(Size))),   // #881 no page ceiling of our own
        Size = SI.Management.Core.ProData.GridSql.PageSize(Size),
        Text = string.IsNullOrWhiteSpace(Text) ? null : Text.Trim().Length > 200 ? Text.Trim()[..200] : Text.Trim(),
    };
}

public sealed record TaskPage(IReadOnlyList<FindingTaskRow> Rows, long Total, int Page, int Size)
{
    public int Pages => Total == 0 ? 1 : (int)Math.Ceiling(Total / (double)Size);
}

/// <summary>
/// DUE AND OVERDUE (PURE): a task is OVERDUE when it is open and its due day has passed (the due day itself is not
/// overdue); DUE SOON when it is open and due today or within <see cref="SoonDays"/> days; its reminder is DUE when the
/// reminder day has come. All in UTC days. The SQL lists use the same rules (and the tests prove both agree).
/// </summary>
public static class TaskDue
{
    public const int SoonDays = 7;
    public const int RecentDays = 14;

    public static bool Overdue(string status, DateOnly due, DateOnly today) => status == TaskStatuses.Open && due < today;
    public static bool DueSoon(string status, DateOnly due, DateOnly today, int days = SoonDays) => status == TaskStatuses.Open && due >= today && due <= today.AddDays(days);
    public static bool ReminderDue(string status, DateOnly? remind, DateOnly today) => status == TaskStatuses.Open && remind is { } r && r <= today;

    /// overdue | soon | open | recent | done | cancelled -- what a row's badge says.
    public static string Bucket(string status, DateOnly due, DateTime? completedAt, DateOnly today, int soonDays = SoonDays, int recentDays = RecentDays)
    {
        if (status == TaskStatuses.Cancelled) return "cancelled";
        if (status == TaskStatuses.Done) return completedAt is { } c && DateOnly.FromDateTime(c) >= today.AddDays(-recentDays) ? "recent" : "done";
        if (Overdue(status, due, today)) return "overdue";
        return DueSoon(status, due, today, soonDays) ? "soon" : "open";
    }

    /// Whether a row is in a list's "show" choice (the fake store and the tests use this; the SQL has the same rules).
    public static bool InShow(string show, FindingTaskRow t, DateOnly today, int soonDays = SoonDays, int recentDays = RecentDays)
    {
        var due = DateOnly.FromDateTime(t.DueDate);
        return show switch
        {
            "overdue" => Overdue(t.Status, due, today),
            "soon" => DueSoon(t.Status, due, today, soonDays),
            "recent" => t.Status == TaskStatuses.Done && t.CompletedAt is { } c && DateOnly.FromDateTime(c) >= today.AddDays(-recentDays),
            "done" => t.Status == TaskStatuses.Done,
            "cancelled" => t.Status == TaskStatuses.Cancelled,
            "any" => true,
            _ => t.Status == TaskStatuses.Open,
        };
    }

    public static string Label(string bucket) => bucket switch
    {
        "overdue" => "Overdue",
        "soon" => "Due soon",
        "recent" => "Done recently",
        "done" => "Done",
        "cancelled" => "Cancelled",
        _ => "Open",
    };
}

/// <summary>
/// WHO the signed-in person is, for tasks: the keys a task's ASSIGNEE is matched on (their object id, every group in their
/// token, the department people they are -- an Entra user listed by a department, or the person a sign-in link stands
/// for) and the PERSONAL keys a task's CREATOR is matched on (never a group). Pure over the claims and the person keys
/// the store looked up.
/// </summary>
public sealed record TaskIdentity(IReadOnlyList<string> Keys, IReadOnlyList<string> PersonalKeys, string CreatorKey)
{
    public bool Is(string? key) => key is not null && Keys.Contains(key.ToLowerInvariant());
    public bool IsPersonally(string? key) => key is not null && PersonalKeys.Contains(key.ToLowerInvariant());

    public static string NameKey(ClaimsPrincipal user) => "name:" + user.ChangeName().Trim().ToLowerInvariant();

    public static TaskIdentity Of(ClaimsPrincipal user, IReadOnlyList<string> personKeys)
    {
        var personal = new List<string>();
        var oid = AccessClaims.ObjectId(user);
        // a sign-in link session (#258) is the department person it was issued to -- never an Entra user
        if (!DepartmentSessions.IsSession(user) && AssigneeKinds.IsObjectId(oid)) personal.Add(AssigneeKinds.Key(AssigneeKinds.User, oid!));
        personal.AddRange(personKeys.Select(k => k.ToLowerInvariant()));
        if (user.ChangeName().Trim().Length > 0) personal.Add(NameKey(user));
        personal = personal.Distinct().ToList();
        var keys = new List<string>(personal.Where(k => !k.StartsWith("name:", StringComparison.Ordinal)));
        if (!DepartmentSessions.IsSession(user))
            keys.AddRange(AccessClaims.Groups(user).Where(AssigneeKinds.IsObjectId).Select(g => AssigneeKinds.Key(AssigneeKinds.Group, g)));
        var creator = personal.FirstOrDefault(k => !k.StartsWith("name:", StringComparison.Ordinal)) ?? personal.FirstOrDefault() ?? "name:";
        return new TaskIdentity(keys.Distinct().ToList(), personal, creator);
    }
}
