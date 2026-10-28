using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;

namespace SI.Management.Web.Pages;

/// <summary>
/// #765 (owner 2026-10-19, "SI decides"): a person of the directory who signed in but has no role in SecurityInsight gets
/// this page and nothing else -- "You have no access to SecurityInsight yet", and the SuperAdmins who can give them one.
/// It shows no data: only the names (and mail) of the SuperAdmins on the Access page. Anyone with access goes to their
/// start page instead.
/// </summary>
public sealed class NoAccessModel(IAccessStore access, ILogger<NoAccessModel> log) : PageModel
{
    public IReadOnlyList<(string Name, string? Mail)> SuperAdmins { get; private set; } = Array.Empty<(string, string?)>();

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (AnyAccessHandler.HasRole(User)) return LocalRedirect("~/");
        try
        {
            SuperAdmins = (await access.ListAsync(ct))
                .Where(a => a.Role == SiRole.SuperAdmin && a.PrincipalType == AccessAssignment.User)
                .OrderBy(a => a.DisplayName, StringComparer.OrdinalIgnoreCase)
                .Select(a => (a.DisplayName, MailForward.IsAddress(a.AccountMail) ? a.AccountMail : null))
                .Take(10).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the SuperAdmins could not be read for the no-access page"); }
        return Page();
    }
}
