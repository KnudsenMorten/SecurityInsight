using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SI.Management.Web.Pages.Management;

/// The old "New vs fixed" page (operator 2026-10-05: the Changes &amp; trends menu overlapped). It showed the close-loop's
/// new / fixed / reopened per week -- the same numbers as Vulnerabilities over time, per week -- so an old link or
/// bookmark opens that page, per week, over the same period.
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Management, Off = true)]
public sealed class VulnerabilitiesModel : PageModel
{
    [BindProperty(SupportsGet = true)] public int Weeks { get; set; } = 12;

    public IActionResult OnGet() => LocalRedirect(Target(Weeks));

    /// The weeks the old page offered (4, 12, 26, 52) as the days the new one offers (30, 90, 180, 365).
    public static string Target(int weeks) =>
        "/Management/Closure?days=" + (weeks switch { <= 4 => 30, <= 12 => 90, <= 26 => 180, _ => 365 }) + "&grain=week";
}
