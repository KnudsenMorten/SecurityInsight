using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace SI.Management.Web.Pages;

/// <summary>
/// The viewer's own display preferences, chosen in the header's user menu. Today one: the Number format
/// (<see cref="DisplayCulture"/>). Stored in a cookie for this browser only -- a preference, not a setting: nothing is
/// written to the database and no review applies. Any signed-in person may choose their own.
/// </summary>
public sealed class PreferencesModel : PageModel
{
    public string Chosen { get; private set; } = DisplayCulture.Auto;

    public void OnGet() => Chosen = DisplayCulture.ChosenBy(HttpContext);

    [SI.Management.Web.Audit.NotAudited("the viewer's own display preference (a cookie in this browser): no product state changes")]
    public IActionResult OnPost(string? numberFormat, string? returnUrl)
    {
        var choice = DisplayCulture.Choice(numberFormat);
        if (choice is null) return BadRequest("Unknown number format.");
        if (choice == DisplayCulture.Auto) Response.Cookies.Delete(DisplayCulture.Cookie);
        else Response.Cookies.Append(DisplayCulture.Cookie, choice, new CookieOptions
        {
            // a display preference: read by nothing but this app, kept a year, never sent cross-site
            HttpOnly = true, Secure = Request.IsHttps, SameSite = SameSiteMode.Lax, IsEssential = true,
            MaxAge = TimeSpan.FromDays(365), Path = "/",
        });
        TempData["toast"] = "Number format: " + DisplayCulture.Choices.First(c => c.Value == choice).Label;
        // back to the page the menu was opened on -- only a local address, never an open redirect
        return LocalRedirect(Url.IsLocalUrl(returnUrl) ? returnUrl! : "/");
    }
}
