using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Advisors;
using SI.Management.Web.Auth;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.Departments;

/// What the advisors panel renders: one department; where its forms send the browser back to; compact = the department
/// page's short form (send a link only).
public sealed record AdvisorPanel(int DepartmentId, string ReturnUrl, bool Compact = false);

/// <summary>
/// Admin &gt; Departments &gt; a department's ADVISORS and SIGN-IN LINKS (#258). The panel is shown on the department's admin
/// page (and, compact, on its department page); its forms post here. Every change is one transaction with its
/// cfg.ChangeLog row. Admin (folder policy), and each handler asks the role framework again.
/// </summary>
public sealed class AdvisorsModel : PageModel
{
    private readonly IAdvisorStore _advisors;
    private readonly DepartmentSignInService _signIn;
    private readonly IAccessScope _access;
    public AdvisorsModel(IAdvisorStore advisors, DepartmentSignInService signIn, IAccessScope access) { _advisors = advisors; _signIn = signIn; _access = access; }

    [BindProperty(SupportsGet = true)] public int Id { get; set; }
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }

    public string Back => ReturnUrl is { Length: > 0 and <= 600 } r && !r.Contains("//", StringComparison.Ordinal) && !r.Contains('\\')
                          && (r.StartsWith("/Admin/Departments/", StringComparison.OrdinalIgnoreCase) || r.StartsWith("/Departments/", StringComparison.OrdinalIgnoreCase))
        ? r : "/Admin/Departments/Advisors?id=" + Id.ToString(CultureInfo.InvariantCulture);

    /// #335: the refusal of the last write (shown on this page and on the department's page), or that a post was lost.
    public string? Refusal { get; private set; }

    public void OnGet()
    {
        Refusal = TempData[DepartmentAdminModel.RefusalKey] as string;
        if (Refusal is null && !string.IsNullOrEmpty(Request.Query["handler"])) Refusal = DepartmentAdminModel.LostPostText;
    }

    /// A refused or failed write also leaves its reason for the page it returns to (a notice that does not fade, #335).
    private IActionResult Done(WriteResult r)
    {
        TempData["toast"] = r.Message;
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? "ok" : "error";
        if (r.Status != WriteStatus.Saved) TempData[DepartmentAdminModel.RefusalKey] = r.Message;
        return LocalRedirect(Back);
    }

    private static async Task<WriteResult> Safely(Func<Task<WriteResult>> write, string what)
    {
        try { return await write(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return new WriteResult(WriteStatus.Refused, $"{what} could not be saved -- the Pro database answered: {ex.Message}"); }
    }

    private AccessDecision Gate() => _access.Can(User, AccessAction.Administer);

    [SI.Management.Web.Audit.Audited("department.advisor.add")]
    public async Task<IActionResult> OnPostAddAsync(string? kind, string? displayName, string? company, string? mail, string? objectId, bool isExternal, string? note, CancellationToken ct)
    {
        if (Gate() is { Allowed: false } g) return Done(new WriteResult(WriteStatus.Refused, g.Reason));
        return Done(await Safely(() => _advisors.AddAsync(new AdvisorInput(Id, kind ?? AdvisorKinds.Person, displayName ?? "", company, mail, objectId, isExternal, note), User.ChangeName(), ct), "The advisor"));
    }

    [SI.Management.Web.Audit.Audited("department.advisor.revoke")]
    public async Task<IActionResult> OnPostRevokeAsync(int advisorId, string? reason, CancellationToken ct)
    {
        if (Gate() is { Allowed: false } g) return Done(new WriteResult(WriteStatus.Refused, g.Reason));
        return Done(await Safely(() => _advisors.RevokeAsync(Id, advisorId, reason ?? "", User.ChangeName(), ct), "The revocation"));
    }

    /// person = "advisor:&lt;id&gt;" or "member:&lt;id&gt;".
    [SI.Management.Web.Audit.Audited("signin.link.issue")]
    public async Task<IActionResult> OnPostSendLinkAsync(string? person, string? target, CancellationToken ct)
    {
        var parts = (person ?? "").Split(':');
        if (parts.Length != 2 || parts[0] is not (DepartmentPerson.AdvisorKind or DepartmentPerson.MemberKind)
            || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var pid) || pid <= 0)
            return Done(new WriteResult(WriteStatus.Refused, "pick the person to send the link to"));
        return Done(await Safely(() => _signIn.IssueAsync(User, Id, parts[0], pid, target, ct), "The sign-in link"));
    }

    [SI.Management.Web.Audit.Audited("signin.link.revoke")]
    public async Task<IActionResult> OnPostRevokeLinkAsync(long signInId, CancellationToken ct) => Done(await Safely(() => _signIn.RevokeAsync(User, Id, signInId, ct), "The revocation"));
}
