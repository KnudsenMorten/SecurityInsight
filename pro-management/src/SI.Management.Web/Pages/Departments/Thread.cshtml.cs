using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Departments;
using SI.Management.Web.FindingComments;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Departments;

/// <summary>
/// ONE finding of a department, and its thread (#258): comments, recommendations and approvals by the department's
/// advisors and people and the security team. Who may see it: anyone who sees the department (the department scope); a
/// person limited to departments only for a finding the newest collection places in THEIR department. Who may write:
/// the role framework decides (comment / recommend / approve on the finding's domain, kind, tier and department), and
/// approve asks for the strong sign-in -- a magic-link session confirms with a one-time code first.
/// </summary>
public sealed class ThreadModel : PageModel
{
    private readonly FindingCommentService _comments;
    private readonly IDepartmentScopeResolver _scope;
    private readonly ILogger<ThreadModel> _log;
    public ThreadModel(FindingCommentService comments, IDepartmentScopeResolver scope, ILogger<ThreadModel> log) { _comments = comments; _scope = scope; _log = log; }

    [BindProperty(SupportsGet = true)] public int Id { get; set; }
    [BindProperty(SupportsGet = true)] public string? Asset { get; set; }
    [BindProperty(SupportsGet = true)] public string? Rec { get; set; }

    public FindingFacts? Facts { get; private set; }
    public IReadOnlyList<FindingCommentRow> Thread { get; private set; } = Array.Empty<FindingCommentRow>();
    public string? Error { get; private set; }
    public string? Notice { get; private set; }
    public AccessDecision? CommentGate { get; private set; }
    public AccessDecision? RecommendGate { get; private set; }
    public AccessDecision? ApproveGate { get; private set; }
    /// A sign-in link session that has not passed the second check yet: approve offers the one-time code.
    public bool NeedsCode => DepartmentSessions.IsSession(User) && AuthMethods.Of(User) == AuthMethods.MagicLink;
    public string Here => $"/Departments/Thread?id={Id.ToString(CultureInfo.InvariantCulture)}&asset={Uri.EscapeDataString(Asset ?? "")}&rec={Uri.EscapeDataString(Rec ?? "")}";

    /// Null = carry on; otherwise the answer (403 when the finding is not the user's to see).
    private async Task<IActionResult?> LoadAsync(CancellationToken ct)
    {
        if (Id <= 0 || string.IsNullOrWhiteSpace(Asset) || string.IsNullOrWhiteSpace(Rec) || Asset.Length > 400 || Rec.Length > 256)
        { Error = "Open a finding from its department's page."; return null; }
        var access = await _scope.ResolveAsync(User, ct);
        if (!access.Sees(Id)) return Forbid();
        try
        {
            Facts = await _comments.FactsAsync(Asset.Trim(), Rec.Trim(), ct);
            // limited to departments: only a finding the newest collection places in their department
            if (!access.Unrestricted && Facts?.DepartmentId != Id) return Forbid();
            if (Facts is null) Notice = "This finding is not in the newest collection (fixed, or not loaded yet): its history is shown, nothing can be added.";
            else if (Facts.DepartmentId != Id) Notice = "The newest collection places this finding in another department.";
            if (await _comments.ReadyAsync(ct)) Thread = await _comments.ListAsync(Asset.Trim(), Rec.Trim(), ct);
            else Notice ??= "The Pro database does not have the finding comment table yet: apply sql\\si-pro-settings.sql again (it only adds).";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "finding thread");
            Error = "The finding could not be read from the Pro database: " + ex.Message;
            return null;
        }
        if (Facts is not null)
        {
            CommentGate = _comments.Can(User, FindingCommentKinds.Comment, Facts);
            RecommendGate = _comments.Can(User, FindingCommentKinds.Recommend, Facts);
            ApproveGate = _comments.Can(User, FindingCommentKinds.Approve, Facts);
        }
        return null;
    }

    /// #265: a finding still in the newest collection opens its ONE thread on the department finding page (governance log,
    /// comments, recommendations, approvals and tasks together); a finding that is gone keeps this page as its history.
    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (await LoadAsync(ct) is { } stop) return stop;
        if (Facts is not null && Error is null
            && HttpContext.RequestServices.GetService(typeof(SI.Management.Web.Tasks.IFindingTaskStore)) is SI.Management.Web.Tasks.IFindingTaskStore tasks)
        {
            try
            {
                var (c, id) = await tasks.LocateAsync(Facts.AssetKey, Facts.RecommendationKey, ct);
                if (c is not null && id is not null) return LocalRedirect("/Departments/Finding?c=" + Uri.EscapeDataString(c) + "&id=" + Uri.EscapeDataString(id));
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the finding could not be located for the unified thread"); }
        }
        return Page();
    }

    [SI.Management.Web.Audit.Audited("finding.comment.add")]
    public async Task<IActionResult> OnPostAsync(string? kind, string? text, CancellationToken ct)
    {
        if (await LoadAsync(ct) is { } stop) return stop;
        if (Facts is null) { TempData["toast"] = Error ?? Notice ?? "Nothing can be added to this finding."; TempData["toastKind"] = "error"; return LocalRedirect(Here); }
        var r = await _comments.AddAsync(User, kind ?? "", Facts, text, ct);
        TempData["toast"] = r.Message;
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? "ok" : "error";
        // approve refused for want of the second check: straight to the code
        if (r.Status != WriteStatus.Saved && kind == FindingCommentKinds.Approve && NeedsCode)
            return LocalRedirect("/Departments/Confirm?returnUrl=" + Uri.EscapeDataString(Here));
        return LocalRedirect(Here);
    }
}
