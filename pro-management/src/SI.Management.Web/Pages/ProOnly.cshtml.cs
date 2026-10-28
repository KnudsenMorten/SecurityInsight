using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Licensing;

namespace SI.Management.Web.Pages;

/// <summary>
/// "Part of SecurityInsight Pro": where a page view of a paid feature lands on an installation without a Pro licence
/// (<see cref="ProFeaturePageFilter"/>). Says which feature, that nothing was done, and where a licence comes from. It is
/// itself in both versions; the feature in the query is only named, never trusted for anything.
/// </summary>
public sealed class ProOnlyModel : PageModel
{
    public string Feature { get; private set; } = "";
    public string Title { get; private set; } = "This feature";

    public void OnGet(string? feature)
    {
        Feature = (feature ?? "").Trim();
        Title = ProFeatures.Titles.TryGetValue(Feature, out var t) ? t : "This feature";
    }
}
