using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;

namespace SI.Management.Web.Pages;

/// <summary>
/// "No access", told to the visitor's actual situation and effective role (Reader / Delegated / Admin / SuperAdmin).
/// A SuperAdmin can open every page, so a SuperAdmin here only followed a stale link and goes to the start page; so does an
/// Admin, unless the page refused was a SuperAdmin page (Admin &gt; Access). Everyone else is told their role and what the
/// page needs; only an account with no role gets the "ask for a role" text.
/// </summary>
public sealed class DeniedModel : PageModel
{
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }

    public bool SignedIn => User.Identity?.IsAuthenticated == true;
    public SiRole Role => User.EffectiveRole();
    public string Badge => AccessClaims.Badge(User);
    public bool IsViewer => Role == SiRole.Reader;
    public bool IsDelegated => Role == SiRole.Delegated;
    public bool IsAdmin => Role == SiRole.Admin;
    public bool IsWallboard => User.IsWallboardOnly();
    public string Scopes => string.Join(" | ", User.Scopes().Select(s => s.Describe()));

    /// The refused page was one only a SuperAdmin opens.
    public static bool IsSuperAdminPage(string? url) =>
        (url ?? "").Split('?')[0].TrimEnd('/').Equals("/Admin/Access", StringComparison.OrdinalIgnoreCase);

    public IActionResult OnGet()
    {
        if (Role == SiRole.SuperAdmin) return LocalRedirect("~/");
        // #765: a person with no role in SecurityInsight at all gets the one plain page that says so
        if (SignedIn && !AnyAccessHandler.HasRole(User)) return RedirectToPage("/NoAccess");
        if (Role == SiRole.Admin && !IsSuperAdminPage(ReturnUrl)) return LocalRedirect("~/");
        return Page();
    }
}
