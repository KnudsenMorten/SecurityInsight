using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Settings;
using SI.Management.Web.Tasks;

namespace SI.Management.Web.Pages.Tasks;

/// <summary>
/// ONE follow-up task (#265): what, for whom, due when, on which finding, its history -- and, for whoever may, complete /
/// cancel / reopen. A task outside the departments the user sees does not exist for them (404). When the vulnerability
/// close-loop has closed the finding the page says so and offers to close the task; it is never closed automatically.
/// </summary>
public sealed class TaskModel : PageModel
{
    private readonly FindingTaskService _tasks;
    private readonly ILogger<TaskModel> _log;
    public TaskModel(FindingTaskService tasks, ILogger<TaskModel> log) { _tasks = tasks; _log = log; }

    [BindProperty(SupportsGet = true)] public long Id { get; set; }

    public FindingTaskRow? Item { get; private set; }
    public IReadOnlyList<TaskHistoryRow> History { get; private set; } = Array.Empty<TaskHistoryRow>();
    public AccessDecision? CanComplete { get; private set; }
    public AccessDecision? CanCancel { get; private set; }
    public AccessDecision? CanReopen { get; private set; }
    public string? Error { get; private set; }
    public DateOnly Today => _tasks.Today;
    public string Here => "/Tasks/Task?id=" + Id.ToString(System.Globalization.CultureInfo.InvariantCulture);

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        if (Id <= 0) { Error = "Open a task from a list or a finding."; return false; }
        try
        {
            if (!await _tasks.Store.ReadyAsync(ct)) { Error = "The Pro database does not have the task tables yet: apply sql\\si-pro-settings.sql again (it only adds)."; return false; }
            Item = await _tasks.GetAsync(User, Id, ct);
            if (Item is null) return false;
            History = await _tasks.Store.HistoryAsync(Id, ct);
            var me = await _tasks.IdentityAsync(User, ct);
            CanComplete = await _tasks.CanChangeAsync(User, me, Item, TaskActions.Completed, ct);
            CanCancel = await _tasks.CanChangeAsync(User, me, Item, TaskActions.Cancelled, ct);
            CanReopen = await _tasks.CanChangeAsync(User, me, Item, TaskActions.Reopened, ct);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading a task failed");
            Error = "The task could not be read: " + ex.Message;
            return false;
        }
    }

    public async Task<IActionResult> OnGetAsync(CancellationToken ct) => await LoadAsync(ct) || Error is not null ? Page() : NotFound();

    private async Task<IActionResult> ChangeAsync(string action, string? note, string? returnUrl, CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Error is not null ? Page() : NotFound();
        var gate = action == TaskActions.Completed ? CanComplete! : action == TaskActions.Cancelled ? CanCancel! : CanReopen!;
        if (!gate.Allowed) return AccessResults.Refused(Request, gate);
        var r = await _tasks.ChangeAsync(User, Id, action, note, ct);
        TempData["toast"] = r.Status == WriteStatus.Saved ? char.ToUpperInvariant(r.Message[0]) + r.Message[1..] + "." : "Nothing was changed: " + r.Message;
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? "ok" : "error";
        return LocalRedirect(FindingThreadService.SafeReturn(returnUrl) ?? Here);
    }

    [SI.Management.Web.Audit.Audited("finding.task.complete")]
    public Task<IActionResult> OnPostCompleteAsync(string? note, string? returnUrl, CancellationToken ct) => ChangeAsync(TaskActions.Completed, note, returnUrl, ct);
    [SI.Management.Web.Audit.Audited("finding.task.cancel")]
    public Task<IActionResult> OnPostCancelAsync(string? note, string? returnUrl, CancellationToken ct) => ChangeAsync(TaskActions.Cancelled, note, returnUrl, ct);
    [SI.Management.Web.Audit.Audited("finding.task.reopen")]
    public Task<IActionResult> OnPostReopenAsync(string? note, string? returnUrl, CancellationToken ct) => ChangeAsync(TaskActions.Reopened, note, returnUrl, ct);
}
