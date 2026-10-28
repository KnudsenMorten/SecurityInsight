using System.Globalization;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Departments;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Tasks;

/// What a person typed to create a task: the title, an optional note, who (<see cref="Assignee"/>: "me", a department
/// person "member:&lt;id&gt;" / "advisor:&lt;id&gt;", or "entra" with <see cref="EntraKind"/> + object id + name), the due day
/// and an optional reminder day.
public sealed record TaskForm(string? Title, string? Note, string? Assignee, DateTime? Due, DateTime? Remind = null,
    string? EntraKind = null, string? EntraId = null, string? EntraName = null, string? EntraMail = null);

/// <summary>
/// THE decisions about follow-up tasks (#265). WHO MAY CREATE a task on a finding: whoever may write to its governance log
/// today (<see cref="GovernanceService.CanWriteAsync"/> -- the role framework's Comment on the finding's domain, kind, tier
/// and department, or a person of that department) AND sees the finding (the department scope). WHO it may be given to:
/// yourself, a person or advisor of the finding's department, or -- for someone whose view is not limited to departments --
/// any Entra user or group by object id. WHO MAY CHANGE it: complete = the assignee, the creator or a writer of the
/// department; cancel = the creator or a writer of the department; reopen = any of them. A task outside the departments a
/// person sees is invisible to them, in every list and on every page. Every write goes through
/// <see cref="IFindingTaskStore"/> -- one transaction with its history and change-log rows.
/// </summary>
public sealed partial class FindingTaskService
{
    /// The most findings one bulk "create a task for each selected" may cover -- the whole request is refused above it.
    public const int MaxBulk = 200;
    public const int MaxTitle = 200;
    public const int MaxNote = 2000;
    /// How far ahead a due day may be.
    public const int MaxDueDays = 3650;
    public const string Me = "me";
    public const string Entra = "entra";

    [GeneratedRegex(@"^[^@\s;,<>""]{1,64}@[^@\s;,<>""]{1,190}\.[A-Za-z]{2,}$", RegexOptions.CultureInvariant)] private static partial Regex MailPattern();

    private readonly IFindingTaskStore _store;
    private readonly GovernanceService _gov;
    private readonly IDepartmentScopeResolver _scope;
    private readonly IAccessScope _access;
    private readonly IMemoryCache? _cache;
    private readonly TimeProvider _clock;
    private readonly ILogger<FindingTaskService> _log;
    private static long _version;

    public FindingTaskService(IFindingTaskStore store, GovernanceService gov, IDepartmentScopeResolver scope, IAccessScope access, ILogger<FindingTaskService> log,
        IMemoryCache? cache = null, TimeProvider? clock = null)
    { _store = store; _gov = gov; _scope = scope; _access = access; _log = log; _cache = cache; _clock = clock ?? TimeProvider.System; }

    public IFindingTaskStore Store => _store;
    public DateOnly Today => DateOnly.FromDateTime(_clock.GetUtcNow().UtcDateTime);

    // ------------------------------------------------------------------------------------------------- who is who

    /// The signed-in person's task keys (see <see cref="TaskIdentity"/>). A store that cannot be read adds no department
    /// person -- the person keeps their own object id and groups.
    public async Task<TaskIdentity> IdentityAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        IReadOnlyList<string> people = Array.Empty<string>();
        try
        {
            var session = DepartmentSessions.SignInId(user);
            var ids = session is null ? MembershipDepartmentScope.ObjectIds(user) : Array.Empty<string>();
            var upn = session is null ? user.FindFirst("preferred_username")?.Value ?? user.FindFirst(ClaimTypes.Upn)?.Value : null;
            if (session is not null || ids.Count > 0 || !string.IsNullOrWhiteSpace(upn)) people = await _store.PersonKeysAsync(ids, upn, session, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the department people of a signed-in user could not be read for their tasks"); }
        return TaskIdentity.Of(user, people);
    }

    /// The departments the user may see tasks of; null = every one (and the Unassigned ones).
    public async Task<IReadOnlyList<int>?> VisibleDepartmentsAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        var a = await _scope.ResolveAsync(user, ct);
        return a.Unrestricted ? null : a.Departments;
    }

    public static bool Sees(IReadOnlyList<int>? departments, int? departmentId) => departments is null || (departmentId is { } d && departments.Contains(d));

    /// A writer of the department's findings (the role framework's Comment on the department): an Admin, a Delegated user
    /// scoped to it, its advisors and people.
    public AccessDecision DepartmentWriter(ClaimsPrincipal user, int? departmentId) =>
        _access.Can(user, AccessAction.Comment, new ScopeTarget(new Dictionary<string, string?> { [ScopeTypes.Department] = departmentId?.ToString(CultureInfo.InvariantCulture) }));

    // ------------------------------------------------------------------------------------------------- create

    /// May this user create a task on this finding? The governance-log writers who see the finding.
    public async Task<AccessDecision> CanCreateAsync(ClaimsPrincipal user, GovernanceTarget t, CancellationToken ct)
    {
        if (!Sees(await VisibleDepartmentsAsync(user, ct), t.DepartmentId)) return AccessDecision.No("this finding is not one of your departments'");
        var d = await _gov.CanWriteAsync(user, t, ct);
        return d.Allowed ? d : AccessDecision.No(d.Reason);
    }

    /// May this user give tasks to any Entra user or group (not only to people of the finding's department)?
    public async Task<bool> MayAssignEntraAsync(ClaimsPrincipal user, CancellationToken ct) =>
        !user.IsDepartmentScoped() && !DepartmentSessions.IsSession(user) && (await _scope.ResolveAsync(user, ct)).Unrestricted;

    /// What a task form must hold, before anyone is looked up (PURE).
    public static IReadOnlyList<string> Validate(TaskForm f, DateOnly today)
    {
        var why = new List<string>();
        var title = (f.Title ?? "").Trim();
        if (title.Length < 3) why.Add("give the task a title (at least 3 characters) -- e.g. \"waiting for the vendor to confirm the patch\"");
        if (title.Length > MaxTitle) why.Add($"the title is longer than {MaxTitle} characters");
        if ((f.Note ?? "").Trim().Length > MaxNote) why.Add($"the note is longer than {MaxNote} characters");
        if (title.Any(char.IsControl) || (f.Note ?? "").Any(ch => char.IsControl(ch) && ch is not ('\r' or '\n' or '\t'))) why.Add("the text has a control character");
        if (f.Due is not { } due) why.Add("choose the day it is due");
        else
        {
            var d = DateOnly.FromDateTime(due);
            if (d < today) why.Add("the due day has passed -- choose today or later");
            if (d > today.AddDays(MaxDueDays)) why.Add($"the due day is more than {MaxDueDays} days away");
            if (f.Remind is { } r && (DateOnly.FromDateTime(r) > d || DateOnly.FromDateTime(r) < today)) why.Add("the reminder is a day from today up to the due day");
        }
        if (string.IsNullOrWhiteSpace(f.Assignee)) why.Add("choose who the task is for");
        return why;
    }

    /// <summary>
    /// The assignee the form names, checked against EVERY finding the task is created on: yourself; a person or advisor of
    /// each finding's department; an Entra user / group by object id only for someone whose view is not limited to
    /// departments. Null + the reason when it is not allowed.
    /// </summary>
    public async Task<(TaskAssignee? Assignee, string? Why)> ResolveAssigneeAsync(ClaimsPrincipal user, TaskIdentity me, TaskForm f, IReadOnlyCollection<int?> departments, CancellationToken ct)
    {
        var choice = (f.Assignee ?? "").Trim().ToLowerInvariant();
        if (choice == Me)
        {
            var mine = me.PersonalKeys.FirstOrDefault(k => !k.StartsWith("name:", StringComparison.Ordinal));
            if (mine is null) return (null, "your sign-in carries no object id to give a task to -- choose a person instead");
            var (kind, id) = (mine[..mine.IndexOf(':')], mine[(mine.IndexOf(':') + 1)..]);
            var upn = user.ChangeName();
            var name = user.FindFirst("name")?.Value is { Length: > 0 } n ? n : upn;
            return (new TaskAssignee(kind, id, Cut(name, 256), MailPattern().IsMatch(upn) ? upn : null), null);
        }
        if (choice == Entra)
        {
            if (!await MayAssignEntraAsync(user, ct)) return (null, "you can give a task only to yourself or to a person of the finding's department");
            var k = (f.EntraKind ?? "").Trim().ToLowerInvariant();
            if (k is not (AssigneeKinds.User or AssigneeKinds.Group)) return (null, "an Entra assignee is a user or a group");
            if (!AssigneeKinds.IsObjectId(f.EntraId)) return (null, "the Entra object id is a GUID (Entra admin center > the user or group > Object ID)");
            var name = (f.EntraName ?? "").Trim();
            if (name.Length is < 1 or > 256 || name.Any(char.IsControl)) return (null, "give the user's or group's name, so the lists can show it");
            var mail = string.IsNullOrWhiteSpace(f.EntraMail) ? null : f.EntraMail.Trim();
            if (mail is not null && !MailPattern().IsMatch(mail)) return (null, $"'{mail}' is not a mail address");
            return (new TaskAssignee(k, f.EntraId!.Trim().ToLowerInvariant(), name, mail), null);
        }
        var colon = choice.IndexOf(':');
        var pk = colon > 0 ? choice[..colon] : "";
        var pid = colon > 0 ? choice[(colon + 1)..] : "";
        if (pk is not (AssigneeKinds.Member or AssigneeKinds.Advisor) || !AssigneeKinds.IsPersonId(pid)) return (null, "choose who the task is for");
        TaskPerson? found = null;
        foreach (var d in departments.Distinct())
        {
            if (d is not { } dept) return (null, "a finding with no department (Unassigned) has no department people -- give the task to yourself or an Entra user");
            var p = (await _store.PeopleAsync(dept, ct)).FirstOrDefault(x => x.Kind == pk && x.PersonId.ToString(CultureInfo.InvariantCulture) == pid);
            if (p is null) return (null, "that person is not a person or advisor of every selected finding's department");
            found = p;
        }
        if (found is null) return (null, "choose who the task is for");
        return (new TaskAssignee(found.Kind, pid, Cut(found.DisplayName, 256), string.IsNullOrWhiteSpace(found.Mail) ? null : found.Mail.Trim()), null);
    }

    private static string Cut(string s, int n) => s.Length > n ? s[..n] : s;

    /// <summary>
    /// Creates one task per finding (one from a finding's thread, or one per selected finding) -- refused AS A WHOLE when
    /// any finding is outside what the user may write to or see, when there are more than <see cref="MaxBulk"/>, or when
    /// the assignee does not fit every one of them. One transaction for all of them.
    /// </summary>
    public async Task<(WriteResult Result, long? FirstId)> CreateAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> targets, TaskForm form, CancellationToken ct)
    {
        if (user.Identity?.IsAuthenticated != true) return (new WriteResult(WriteStatus.Refused, "you are not signed in"), null);
        if (targets.Count == 0) return (new WriteResult(WriteStatus.Refused, "select at least one finding"), null);
        if (targets.Count > MaxBulk) return (new WriteResult(WriteStatus.Refused, $"at most {MaxBulk} findings at a time -- {targets.Count} were selected; narrow the selection"), null);
        var why = Validate(form, Today);
        if (why.Count > 0) return (new WriteResult(WriteStatus.Refused, string.Join("; ", why)), null);
        var refused = new List<string>();
        foreach (var t in targets)
        {
            if (t.RecommendationKey is null) { refused.Add($"{t.Finding.AssetName}: the finding has no recommendation (configuration id or CVE)"); continue; }
            var d = await CanCreateAsync(user, t, ct);
            if (!d.Allowed) refused.Add($"{t.Finding.AssetName}: {d.Reason}");
        }
        if (refused.Count > 0)
            return (new WriteResult(WriteStatus.Refused, targets.Count == 1 ? refused[0] : $"{refused.Count} of the {targets.Count} findings are outside what you may change, so no task was created. First: {refused[0]}"), null);
        if (!await _store.ReadyAsync(ct)) return (new WriteResult(WriteStatus.Refused, "the Pro database does not have the task tables yet -- apply sql\\si-pro-settings.sql again (it only adds)"), null);
        var me = await IdentityAsync(user, ct);
        var (assignee, whyNot) = await ResolveAssigneeAsync(user, me, form, targets.Select(t => t.DepartmentId).ToList(), ct);
        if (assignee is null) return (new WriteResult(WriteStatus.Refused, whyNot ?? "choose who the task is for"), null);
        var by = user.ChangeName();
        if (string.IsNullOrWhiteSpace(by)) return (new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record"), null);
        var due = DateOnly.FromDateTime(form.Due!.Value);
        DateOnly? remind = form.Remind is { } r ? DateOnly.FromDateTime(r) : null;
        var note = string.IsNullOrWhiteSpace(form.Note) ? null : form.Note.Trim();
        var tasks = targets.DistinctBy(t => (t.AssetKey, t.RecommendationKey)).Select(t => new NewTask(t.AssetKey, t.RecommendationKey!, Blank(t.Finding.AssetName, 400),
            Blank(t.Finding.Title, 400), t.DepartmentId, form.Title!.Trim(), note, assignee, due, remind)).ToList();
        var res = await _store.CreateAsync(tasks, Cut(by, 256), Cut(me.CreatorKey, 300), ct);
        if (res.Result.Status == WriteStatus.Saved) Interlocked.Increment(ref _version);
        return res;
    }

    private static string? Blank(string? s, int n) => string.IsNullOrWhiteSpace(s) ? null : Cut(s.Trim(), n);

    // ------------------------------------------------------------------------------------------------- change

    /// May this user complete / cancel / reopen this task (it must be one they see)?
    public async Task<AccessDecision> CanChangeAsync(ClaimsPrincipal user, TaskIdentity me, FindingTaskRow t, string action, CancellationToken ct)
    {
        if (!Sees(await VisibleDepartmentsAsync(user, ct), t.DepartmentId)) return AccessDecision.No("this task is not one of your departments'");
        var assignee = me.Is(t.AssigneeKey);
        var creator = me.IsPersonally(t.CreatedByKey);
        var writer = DepartmentWriter(user, t.DepartmentId).Allowed;
        var ok = action switch
        {
            TaskActions.Completed => assignee || creator || writer,
            TaskActions.Cancelled => creator || writer,
            TaskActions.Reopened => assignee || creator || writer,
            _ => false,
        };
        if (ok) return AccessDecision.Yes;
        return AccessDecision.No(action == TaskActions.Cancelled
            ? "only the person who created the task, or someone who writes to the department's findings, can cancel it"
            : "only the assignee, the person who created the task, or someone who writes to the department's findings, can change it");
    }

    /// Complete, cancel or reopen a task, from the status the person saw. Cancelling needs a reason.
    public async Task<WriteResult> ChangeAsync(ClaimsPrincipal user, long taskId, string? action, string? note, CancellationToken ct)
    {
        var a = (action ?? "").Trim().ToLowerInvariant();
        if (a is not (TaskActions.Completed or TaskActions.Cancelled or TaskActions.Reopened)) return new WriteResult(WriteStatus.Refused, "complete, cancel or reopen");
        var t = await _store.GetAsync(taskId, ct);
        if (t is null || !Sees(await VisibleDepartmentsAsync(user, ct), t.DepartmentId)) return new WriteResult(WriteStatus.Refused, "there is no such task");
        var me = await IdentityAsync(user, ct);
        var gate = await CanChangeAsync(user, me, t, a, ct);
        if (!gate.Allowed) return new WriteResult(WriteStatus.Refused, "Not allowed: " + gate.Reason);
        var expected = a == TaskActions.Reopened ? (t.Status == TaskStatuses.Open ? "" : t.Status) : TaskStatuses.Open;
        if (a != TaskActions.Reopened && t.Status != TaskStatuses.Open) return new WriteResult(WriteStatus.Stale, $"the task is already {TaskStatuses.Label(t.Status).ToLowerInvariant()}");
        if (a == TaskActions.Reopened && t.Status == TaskStatuses.Open) return new WriteResult(WriteStatus.Stale, "the task is already open");
        var n = (note ?? "").Trim();
        if (a == TaskActions.Cancelled && n.Length < 3) return new WriteResult(WriteStatus.Refused, "give the reason the task is cancelled (at least 3 characters)");
        if (n.Length > MaxNote) return new WriteResult(WriteStatus.Refused, $"the note is longer than {MaxNote} characters");
        if (n.Any(ch => char.IsControl(ch) && ch is not ('\r' or '\n' or '\t'))) return new WriteResult(WriteStatus.Refused, "the note has a control character");
        var by = user.ChangeName();
        if (string.IsNullOrWhiteSpace(by)) return new WriteResult(WriteStatus.Refused, "the signed-in user has no name to record");
        var o = await _store.ChangeStatusAsync(taskId, expected, a, n.Length == 0 ? null : n, Cut(by, 256), Cut(me.CreatorKey, 300), ct);
        if (o == "Saved") Interlocked.Increment(ref _version);
        return o switch
        {
            "Saved" => new WriteResult(WriteStatus.Saved, a switch { TaskActions.Completed => "task completed", TaskActions.Cancelled => "task cancelled", _ => "task reopened" }),
            "Stale" => new WriteResult(WriteStatus.Stale, "someone changed the task meanwhile -- look again"),
            _ => new WriteResult(WriteStatus.Refused, "there is no such task"),
        };
    }

    // ------------------------------------------------------------------------------------------------- read

    /// A task, only when the user sees its department.
    public async Task<FindingTaskRow?> GetAsync(ClaimsPrincipal user, long taskId, CancellationToken ct)
    {
        var t = await _store.GetAsync(taskId, ct);
        return t is not null && Sees(await VisibleDepartmentsAsync(user, ct), t.DepartmentId) ? t : null;
    }

    /// A list: the user's own keys and the departments they see are added here, never taken from the request.
    public async Task<TaskPage> ListAsync(ClaimsPrincipal user, TaskQuery q, CancellationToken ct)
    {
        var me = await IdentityAsync(user, ct);
        var depts = await VisibleDepartmentsAsync(user, ct);
        if (q.View == TaskQuery.ViewAll && !user.IsAdmin()) q = q with { View = TaskQuery.ViewMine };
        return await _store.QueryAsync(q with { Keys = me.Keys, PersonalKeys = me.PersonalKeys, Departments = depts, Today = Today }, ct);
    }

    /// The header's "my open / overdue tasks" -- cached for seconds; any task write refreshes it.
    public async Task<TaskCounts> CountsAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        var me = await IdentityAsync(user, ct);
        if (me.Keys.Count == 0) return new TaskCounts(0, 0, 0);
        var depts = await VisibleDepartmentsAsync(user, ct);
        var key = "si-task-counts|" + Interlocked.Read(ref _version).ToString(CultureInfo.InvariantCulture) + "|" + Today.ToString("yyyyMMdd", CultureInfo.InvariantCulture) + "|"
                  + string.Join(",", me.Keys.OrderBy(k => k, StringComparer.Ordinal)) + "|" + (depts is null ? "*" : string.Join(",", depts));
        if (_cache is not null && _cache.TryGetValue(key, out TaskCounts? hit) && hit is not null) return hit;
        var c = await _store.CountsAsync(me.Keys, depts, Today, TaskDue.SoonDays, ct);
        _cache?.Set(key, c, TimeSpan.FromSeconds(30));
        return c;
    }
}
