using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Docs;

namespace SI.Management.Web.Pages;

/// <summary>
/// Help &gt; What's new (framework WHATS-NEW-1): every release's What's new, newest first, as the files that ship INSIDE this
/// version of the web app (<see cref="WhatsNewLibrary"/>). The page draws them in the browser with Invardia's ONE renderer
/// (wwwroot/lib/whatsnew/whats-new.js, unchanged) -- the same cards, order and words as invardia.com and WHATSNEW.md on
/// GitHub. Every signed-in role may read it, in both editions; it reads nothing outside the app.
/// </summary>
public sealed class WhatsNewModel : PageModel
{
    public WhatsNewLibrary Library { get; } = WhatsNewLibrary.Shipped;

    public void OnGet() { }

    /// The shipped files as one JSON array (each file unchanged), for the renderer.
    public IActionResult OnGetFiles()
    {
        Response.Headers.CacheControl = "private, max-age=300";
        return Content(Library.FilesJson, "application/json; charset=utf-8");
    }
}
