using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SI.Management.Web.Pages.Management;

/// The old live "Top risks" page ("Riskiest assets now"). It answered "which assets are riskiest" from a second source
/// next to the Risk Analysis run's own ranking, so the two lists could disagree (operator 2026-10-05: keep one source,
/// the one the mail uses). An old link or bookmark opens Overview > Top risks > Top 50 risky assets.
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Management, Off = true)]
public sealed class TopRisksModel : PageModel
{
    public const string Target = "/Management/TopAssets";
    public IActionResult OnGet() => LocalRedirect(Target);
}
