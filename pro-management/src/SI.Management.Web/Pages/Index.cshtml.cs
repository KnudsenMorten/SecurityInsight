using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;

namespace SI.Management.Web.Pages;

/// The landing page ("/": the brand logo and the menu's Home) sends each role to its start. #415 (operator 2026-10-06:
/// "i propose the wallboard is the default (home) page for SI, so people sees it as the first thing"): every role that
/// may see the wall board -- Reader and up, and the Wallboard kiosk account -- lands on it (the findings browser, the
/// landing page before, stays in the menu); a magic-link session -> its one page; a person of a department -> their
/// departments; anyone else -> "No access".
public sealed class IndexModel : PageModel
{
    /// The roles that land on the wall board: the same rule as the page's own policy (Policies.Wallboard).
    public static bool LandsOnWallboard(System.Security.Claims.ClaimsPrincipal user) => user.IsReader() || user.IsInRole(Roles.Wallboard);

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (LandsOnWallboard(User)) return RedirectToPage("/Wallboard");
        if (User.IsMagic() && User.FindFirst(Claims.MagicPage)?.Value is { } p && p.StartsWith('/'))
            return LocalRedirect(p + (User.FindFirst(Claims.MagicQuery)?.Value is { Length: > 0 } q ? "?" + q : ""));
        // a person of a department (#254), e.g. a business owner from the monthly report: their departments
        if (HttpContext?.RequestServices.GetService(typeof(SI.Management.Web.Departments.IDepartmentScopeResolver)) is SI.Management.Web.Departments.IDepartmentScopeResolver d
            && (await d.ResolveAsync(User, ct)).Any) return RedirectToPage("/Departments/Index");
        // #765: signed in, but no role in SecurityInsight -- the plain "no access yet" page, nothing else
        return RedirectToPage("/NoAccess");
    }
}
