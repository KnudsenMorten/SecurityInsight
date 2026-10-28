using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Departments;
using SI.Management.Web.FindingComments;
using SI.Management.Web.Settings;
using SI.Management.Web.Tasks;

namespace SI.Management.Web.Pages.Departments;

/// <summary>
/// ONE FINDING'S GOVERNANCE (#254, phase 2 + 3) AND ITS ONE THREAD (#265): the finding, the department responsible for
/// it, its current status, the remediation flow that applies -- and the thread that merges the governance log, the
/// comments / recommendations / approvals of #258 and the follow-up tasks, with the forms to write to each. Under
/// /Departments, so a person of a department without a role (a technical owner, an advisor) reaches it from their
/// department page; they see it only for their own departments. Opened by collection + finding id, or by the finding's
/// stable key (asset + recommendation: the newest collection's row). Every write is checked server-side by the service
/// that decides it (<see cref="GovernanceService.CanWriteAsync"/>, <see cref="FindingCommentService"/>; 403 + the reason)
/// and audited in cfg.ChangeLog in the same transaction.
/// </summary>
public sealed class FindingModel : PageModel
{
    private readonly IProDataQueries _q;
    private readonly GovernanceService _gov;
    private readonly IDepartmentScopeResolver _scope;
    private readonly FindingThreadService _thread;
    private readonly FindingCommentService _comments;
    private readonly FindingTaskService _tasks;
    private readonly ILogger<FindingModel> _log;

    public FindingModel(IProDataQueries q, GovernanceService gov, IDepartmentScopeResolver scope, FindingThreadService thread, FindingCommentService comments,
        FindingTaskService tasks, ILogger<FindingModel> log)
    { _q = q; _gov = gov; _scope = scope; _thread = thread; _comments = comments; _tasks = tasks; _log = log; }

    [BindProperty(SupportsGet = true)] public string? C { get; set; }
    [BindProperty(SupportsGet = true)] public string? Id { get; set; }
    /// The finding's stable key, instead of c + id: the newest collection's row of (asset, recommendation).
    [BindProperty(SupportsGet = true)] public string? Asset { get; set; }
    [BindProperty(SupportsGet = true)] public string? Rec { get; set; }

    public GovernanceTarget? Target { get; private set; }
    public GovernanceStateRow? State { get; private set; }
    public RemediationFlowDef? Flow { get; private set; }
    public FindingThreadView? Thread { get; private set; }
    public bool MayWrite { get; private set; }
    public string? WhyNot { get; private set; }
    public string? Error { get; private set; }
    public bool Ready { get; private set; } = true;

    public string Here => "/Departments/Finding?c=" + Uri.EscapeDataString(C ?? "") + "&id=" + Uri.EscapeDataString(Id ?? "");

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        return Page();
    }

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(Id) && !string.IsNullOrWhiteSpace(Asset) && !string.IsNullOrWhiteSpace(Rec) && Asset.Length <= 400 && Rec.Length <= 256)
            {
                var (c, id) = await _tasks.Store.LocateAsync(Asset.Trim(), Rec.Trim(), ct);
                if (id is null) { Error = "This finding is not in the newest collection (fixed, or not loaded yet)."; return false; }
                C = c; Id = id;
            }
            if (string.IsNullOrWhiteSpace(Id)) { Error = "Open a finding from its department page."; return false; }
            var d = (await _q.FindingAsync(C, Id, ct)).Data;
            if (d is null) { Error = "There is no such finding in that collection."; return false; }
            var f = d.Finding;
            if (!await _gov.Repository.TablesExistAsync(ct))
            {
                Ready = false;
                Error = "The Pro database does not have the governance tables yet: apply the Pro settings schema again (sql\\si-pro-settings.sql; it only adds).";
                return false;
            }
            var dept = await _gov.Repository.FindingDepartmentAsync(f.CollectionId, f.FindingId, ct);
            var access = await _scope.ResolveAsync(User, ct);
            var deptId = dept?.DepartmentId;
            if (!access.Unrestricted && (deptId is null || !access.Sees(deptId.Value))) { Error = "This finding is not one of your departments'."; return false; }
            Target = new GovernanceTarget(f, deptId, dept?.DepartmentName, dept?.CollectionId ?? f.CollectionId);
            if (Target.RecommendationKey is { } rk) State = await _gov.Repository.StateAsync(f.AssetKey, rk, ct);
            Flow = await _gov.FlowForAsync(Target, ct);
            var can = await _gov.CanWriteAsync(User, Target, ct);
            MayWrite = can.Allowed; WhyNot = can.Allowed ? null : can.Reason;
            C ??= f.CollectionId;
            Thread = await _thread.LoadAsync(User, Target, Here, ct);
            return true;
        }
        catch (ArgumentException ex) { Error = ex.Message; return false; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading a finding's governance failed");
            Error = "The finding's governance could not be read: " + ex.Message;
            return false;
        }
    }

    private IActionResult Back(string? returnUrl) => FindingThreadService.SafeReturn(returnUrl) is { } r ? LocalRedirect(r) : RedirectToPage(new { c = C, id = Id });

    private async Task<IActionResult> WriteAsync(Func<GovernanceTarget, Task<WriteResult>> write, string? returnUrl, CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        var gate = await _gov.CanWriteAsync(User, Target!, ct);
        if (!gate.Allowed) return AccessResults.Refused(Request, gate);
        var r = await write(Target!);
        TempData["toast"] = r.Status == WriteStatus.Saved ? char.ToUpperInvariant(r.Message[0]) + r.Message[1..] + "." : "Nothing was written: " + r.Message;
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? "ok" : "error";
        return Back(returnUrl);
    }

    /// A comment, with or without a new status.
    [SI.Management.Web.Audit.Audited("finding.comment.add")]
    public Task<IActionResult> OnPostCommentAsync(string? status, string? comment, string? returnUrl, CancellationToken ct) =>
        WriteAsync(t => _gov.CommentAsync(User, t, status, comment, ct), returnUrl, ct);

    /// A remediation action (the flow's, or another one).
    [SI.Management.Web.Audit.Audited("governance.action.apply")]
    public Task<IActionResult> OnPostApplyAsync(string? action, string? comment, string? returnUrl, CancellationToken ct) =>
        WriteAsync(t => _gov.ApplyAsync(User, t, action, comment, ct), returnUrl, ct);

    /// #258 in the one thread (#265): a recommendation, or an approval of the recommended change -- decided by the role
    /// framework exactly as on the advisor thread; an approval by a sign-in link session asks for the one-time code first.
    [SI.Management.Web.Audit.Audited("finding.comment.add")]
    public async Task<IActionResult> OnPostAdviseAsync(string? kind, string? text, string? returnUrl, CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        var k = kind ?? "";
        if (!FindingCommentKinds.All.Contains(k)) return AccessResults.Refused(Request, AccessDecision.No("comment, recommend or approve"));
        var facts = FindingThreadService.Facts(Target!);
        var gate = _comments.Can(User, k, facts);
        if (!gate.Allowed)
        {
            if (k == FindingCommentKinds.Approve && DepartmentSessions.IsSession(User) && AuthMethods.Of(User) == AuthMethods.MagicLink)
                return LocalRedirect("/Departments/Confirm?returnUrl=" + Uri.EscapeDataString(Here));
            return AccessResults.Refused(Request, gate);
        }
        var r = await _comments.AddAsync(User, k, facts, text, ct);
        TempData["toast"] = r.Status == WriteStatus.Saved ? r.Message + "." : "Nothing was written: " + r.Message;
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? "ok" : "error";
        return Back(returnUrl);
    }

    public string? DepartmentLink => Target?.DepartmentId is { } id ? "/Departments/Detail?id=" + id.ToString(System.Globalization.CultureInfo.InvariantCulture) + (C is null ? "" : "&c=" + Uri.EscapeDataString(C)) : null;
}
