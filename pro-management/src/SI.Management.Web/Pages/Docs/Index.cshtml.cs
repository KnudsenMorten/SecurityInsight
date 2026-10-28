using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Docs;

namespace SI.Management.Web.Pages.Docs;

/// <summary>
/// #679 Help &gt; Documentation: the documentation of THIS version, shipped inside the release (embedded in the web app,
/// <see cref="ProductDocLibrary"/>), so an install without contact reads the pages of the version it runs. Every signed-in
/// person may read it (no new permission). The page list, one page, a search over the shipped pages, the version, and a
/// link to the published pages on invardia.com -- only a link: the page itself never calls anything outside.
/// </summary>
public sealed class IndexModel : PageModel
{
    public ProductDocLibrary Library { get; } = ProductDocLibrary.Shipped;

    [BindProperty(SupportsGet = true)] public string? Slug { get; set; }
    [BindProperty(SupportsGet = true, Name = "q")] public string? Q { get; set; }

    public DocPage? Current { get; private set; }
    public IReadOnlyList<DocHit> Hits { get; private set; } = Array.Empty<DocHit>();
    public bool Missing { get; private set; }

    public IActionResult OnGet()
    {
        if (!string.IsNullOrWhiteSpace(Slug))
        {
            Current = Library.Find(Slug.Trim().ToLowerInvariant());
            if (Current is null) { Missing = true; Response.StatusCode = StatusCodes.Status404NotFound; }
        }
        if (!string.IsNullOrWhiteSpace(Q)) Hits = Library.Search(Q);
        return Page();
    }

    /// One shipped image of the pages (only the names the pack carries; anything else is 404).
    public IActionResult OnGetImage(string? name)
    {
        var bytes = Library.Image(name);
        if (bytes is null) return NotFound();
        Response.Headers.CacheControl = "private, max-age=86400";
        return File(bytes, ProductDocLibrary.ContentTypeOf(name!));
    }
}
