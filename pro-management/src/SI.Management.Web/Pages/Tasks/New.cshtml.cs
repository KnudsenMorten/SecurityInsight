using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Departments;
using SI.Management.Web.Settings;
using SI.Management.Web.Tasks;

namespace SI.Management.Web.Pages.Tasks;

/// <summary>
/// CREATING TASKS (#265): one from a finding's thread (handler Create -- the finding's collection + id travel, the form
/// comes back to the page it was on), or ONE PER SELECTED FINDING from the findings browser (Prepare shows the selection
/// and the form; Submit creates them all in one transaction). The page re-reads every finding itself -- only the ids
/// travel -- and <see cref="FindingTaskService.CreateAsync"/> refuses the request as a whole when one finding is outside
/// what the user may write to, or when more than <see cref="FindingTaskService.MaxBulk"/> are selected.
/// </summary>
public sealed class NewModel : PageModel
{
    private readonly FindingTaskService _tasks;
    private readonly FindingThreadService _threads;
    private readonly IProDataQueries _q;
    private readonly ILogger<NewModel> _log;

    public NewModel(FindingTaskService tasks, FindingThreadService threads, IProDataQueries q, ILogger<NewModel> log) { _tasks = tasks; _threads = threads; _q = q; _log = log; }

    [BindProperty] public string? C { get; set; }
    [BindProperty] public List<string> Sel { get; set; } = new();
    [BindProperty] public string? Title { get; set; }
    [BindProperty] public string? Note { get; set; }
    [BindProperty] public string? Assignee { get; set; }
    [BindProperty] public DateTime? Due { get; set; }
    [BindProperty] public DateTime? Remind { get; set; }
    [BindProperty] public string? EntraKind { get; set; }
    [BindProperty] public string? EntraId { get; set; }
    [BindProperty] public string? EntraName { get; set; }
    [BindProperty] public string? EntraMail { get; set; }

    public IReadOnlyList<GovernanceTarget> Targets { get; private set; } = Array.Empty<GovernanceTarget>();
    public IReadOnlyList<TaskPerson> People { get; private set; } = Array.Empty<TaskPerson>();
    public bool MayAssignEntra { get; private set; }
    public string? Error { get; private set; }
    public IReadOnlyList<string> Problems { get; private set; } = Array.Empty<string>();
    public DateOnly Today => _tasks.Today;
    public int Selected { get; private set; }

    private TaskForm Form => new(Title, Note, Assignee, Due, Remind, EntraKind, EntraId, EntraName, EntraMail);

    public void OnGet() => Error = "Select findings in Findings and choose \"Create a task for each selected\", or create a task from a finding's thread.";

    /// The findings the ids name, re-read from the collection (each with its department); more than the bulk limit = refused.
    private async Task<bool> LoadAsync(IEnumerable<string> ids, CancellationToken ct)
    {
        var list = ids.Where(s => !string.IsNullOrWhiteSpace(s) && s.Length <= 64).Distinct().ToList();
        Selected = list.Count;
        if (list.Count == 0) { Error = "Select at least one finding first."; return false; }
        if (list.Count > FindingTaskService.MaxBulk)
        {
            Error = $"{Fmt.Int(list.Count)} findings are selected -- at most {Fmt.Int(FindingTaskService.MaxBulk)} get a task at once. Narrow the selection.";
            return false;
        }
        try
        {
            var targets = new List<GovernanceTarget>();
            foreach (var id in list)
                if ((await _q.FindingAsync(C, id, ct)).Data is { } d) targets.Add(await _threads.TargetAsync(d.Finding, ct));
            Targets = targets;
            if (Targets.Count == 0) { Error = "None of the selected findings is in that collection."; return false; }
            MayAssignEntra = await _tasks.MayAssignEntraAsync(User, ct);
            var depts = Targets.Select(t => t.DepartmentId).Distinct().ToList();
            if (depts.Count == 1 && depts[0] is { } one && await _tasks.Store.ReadyAsync(ct)) People = await _tasks.Store.PeopleAsync(one, ct);
            return true;
        }
        catch (ArgumentException ex) { Error = "The selection is not valid: " + ex.Message; return false; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the findings of a task request failed");
            Error = "The selected findings could not be read: " + ex.Message;
            return false;
        }
    }

    /// From the findings browser's selection form (a POST: it carries that page's antiforgery token).
    [SI.Management.Web.Audit.NotAudited("fills the task form from a selection; nothing is written until Submit")]
    public async Task<IActionResult> OnPostPrepareAsync(CancellationToken ct)
    {
        await LoadAsync(Sel, ct);
        return Page();
    }

    /// One task per selected finding.
    [SI.Management.Web.Audit.Audited("finding.task.create")]
    public async Task<IActionResult> OnPostSubmitAsync(CancellationToken ct)
    {
        if (!await LoadAsync(Sel, ct)) return Page();
        // every selected finding must be one the user may write to -- one outside refuses the whole request (403)
        var refused = new List<string>();
        foreach (var t in Targets)
            if (await _tasks.CanCreateAsync(User, t, ct) is { Allowed: false } d) refused.Add($"{t.Finding.AssetName}: {d.Reason}");
        if (refused.Count > 0)
            return AccessResults.Refused(Request, AccessDecision.No(Targets.Count == 1 ? refused[0]
                : $"{refused.Count} of the {Targets.Count} selected findings are outside what you may change, so no task was created. First: {refused[0]}"));
        var (r, _) = await _tasks.CreateAsync(User, Targets, Form, ct);
        if (r.Status != WriteStatus.Saved) { Problems = [r.Message]; return Page(); }
        TempData["toast"] = $"{char.ToUpperInvariant(r.Message[0])}{r.Message[1..]} -- one per selected finding. They are in Delegated tasks (or My tasks when they are yours).";
        TempData["toastKind"] = "ok";
        return LocalRedirect(Assignee == FindingTaskService.Me ? "/Tasks" : "/Tasks/Delegated");
    }

    /// One task from a finding's thread (Findings > detail, the department finding page).
    [SI.Management.Web.Audit.Audited("finding.task.create")]
    public async Task<IActionResult> OnPostCreateAsync(string? id, string? returnUrl, CancellationToken ct)
    {
        if (!await LoadAsync(id is null ? [] : [id], ct)) return Page();
        var gate = await _tasks.CanCreateAsync(User, Targets[0], ct);
        if (!gate.Allowed) return AccessResults.Refused(Request, gate);
        var (r, first) = await _tasks.CreateAsync(User, Targets, Form, ct);
        TempData["toast"] = r.Status == WriteStatus.Saved ? char.ToUpperInvariant(r.Message[0]) + r.Message[1..] + "." : "No task was created: " + r.Message;
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? "ok" : "error";
        return LocalRedirect(FindingThreadService.SafeReturn(returnUrl)
            ?? (first is { } f ? "/Tasks/Task?id=" + f.ToString(CultureInfo.InvariantCulture) : "/Tasks"));
    }
}
