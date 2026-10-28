using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Advisors;
using SI.Management.Web.Auth;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Departments;

/// <summary>
/// The SECOND CHECK of a sign-in link session (#258): a one-time code mailed to the session's own mailbox. Confirmed, the
/// session counts as a strong sign-in (magiclink+otp) and may approve. An Entra sign-in needs no code.
/// </summary>
public sealed class ConfirmModel : PageModel
{
    private readonly DepartmentSignInService _signIn;
    public ConfirmModel(DepartmentSignInService signIn) => _signIn = signIn;

    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }
    public bool LinkSession => DepartmentSessions.IsSession(User);
    public string Method => AuthMethods.Of(User);

    /// Back to a department page only.
    public string Back => ReturnUrl is { Length: > 0 and <= 600 } r && r.StartsWith("/Departments/", StringComparison.OrdinalIgnoreCase) && !r.Contains("//", StringComparison.Ordinal) && !r.Contains('\\')
        ? r : "/Departments/Index";

    public void OnGet() { }

    private IActionResult Done(WriteResult r, bool back)
    {
        TempData["toast"] = r.Message;
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? "ok" : "error";
        return back ? LocalRedirect(Back) : LocalRedirect("/Departments/Confirm?returnUrl=" + Uri.EscapeDataString(Back));
    }

    [SI.Management.Web.Audit.Audited("signin.code.send")]
    public async Task<IActionResult> OnPostSendAsync(CancellationToken ct) => Done(await _signIn.SendCodeAsync(User, ct), false);

    [SI.Management.Web.Audit.Audited("signin.code.verify")]
    public async Task<IActionResult> OnPostCodeAsync(string? code, CancellationToken ct)
    {
        var r = await _signIn.ConfirmCodeAsync(User, code, ct);
        return Done(r, r.Status == WriteStatus.Saved);
    }
}
