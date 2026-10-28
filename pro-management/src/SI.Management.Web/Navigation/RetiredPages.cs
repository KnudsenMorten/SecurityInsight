using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace SI.Management.Web.Navigation;

/// <summary>
/// #636 -- EVERY OLD ADDRESS STILL OPENS THE MATCHING PAGE OR VIEW (owner 2026-10-13, approved). The pages the menu
/// restructure retired, and where a person who opens one lands now (the collection, the filters and the search carried):
///   /Findings                 -> Security recommendations > Detailed (its filters as the grid's: tier, severity, domain,
///                                report, asset kind, search)
///   /Summary                  -> Security recommendations > Summary
///   /Collection/RiskRating    -> Detailed, view "Critical and High"
///   /Collection/Mitre         -> Detailed, view "MITRE"
///   /Collection/Compliance    -> Detailed, view "Compliance"
///   /Collection/Cvss          -> Detailed, view "CVSS"
///   /Collection/Vulnerabilities -> Summary, view "Vulnerabilities (CVE)"
///   /Collection/TopFindings   -> Summary, view "Critical and High" (the most weighted risk first)
/// A BROWSER NAVIGATION is redirected (a bookmark, a link in a mail, a typed address: the request says
/// Sec-Fetch-Mode: navigate). A handler of the old page (an export, the value counts) and a programmatic read keep
/// answering at the old address, so an export link that is still open somewhere keeps working.
/// </summary>
public static class RetiredPages
{
    /// A grid page's own state carries over as it is (the collection, the f.* filters, sort, dir, search, page size).
    private static readonly IReadOnlyDictionary<string, string> Grid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["c"] = "c", ["q"] = "q", ["sort"] = "sort", ["dir"] = "dir", ["size"] = "size",
    };
    /// old page -> (new page, named view, how the old query maps onto the new one)
    private static readonly Dictionary<string, (string Page, string? View, IReadOnlyDictionary<string, string> Map)> Table = new(StringComparer.OrdinalIgnoreCase)
    {
        ["/Findings"] = (NamedViews.DetailedPage, null, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["c"] = "c", ["tier"] = "f.Tier", ["sev"] = "f.Severity", ["dom"] = "f.SecurityDomain", ["rep"] = "f.ReportName", ["kind"] = "f.AssetKind", ["q"] = "q",
        }),
        ["/Summary"] = (NamedViews.SummaryPage, null, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["q"] = "q", ["by"] = "by" }),
        ["/Collection/RiskRating"] = (NamedViews.DetailedPage, "critical-high", Grid),
        ["/Collection/Mitre"] = (NamedViews.DetailedPage, "mitre", Grid),
        ["/Collection/Compliance"] = (NamedViews.DetailedPage, "compliance", Grid),
        ["/Collection/Cvss"] = (NamedViews.DetailedPage, "cvss", Grid),
        ["/Collection/Vulnerabilities"] = (NamedViews.SummaryPage, "cve", Grid),
        ["/Collection/TopFindings"] = (NamedViews.SummaryPage, "critical-high", new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["c"] = "c" }),
    };


    /// The retired addresses (without "/Index").
    public static IEnumerable<string> Paths => Table.Keys;

    /// Where an old address goes now (null = not a retired page). <paramref name="query"/>: the request's query.
    public static string? Target(string path, IEnumerable<KeyValuePair<string, StringValues>> query)
    {
        var p = (path ?? "").TrimEnd('/');
        if (p.EndsWith("/Index", StringComparison.OrdinalIgnoreCase)) p = p[..^"/Index".Length];
        if (!Table.TryGetValue(p, out var t)) return null;
        var view = t.View is null ? null : NamedViews.Find(t.Page, t.View);
        var parts = new List<string>();
        var given = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, vs) in query)
        {
            var key = t.Map.TryGetValue(k, out var m) ? m : k.StartsWith("f.", StringComparison.OrdinalIgnoreCase) && ReferenceEquals(t.Map, Grid) ? k : null;
            if (key is null) continue;
            foreach (var v in vs) if (!string.IsNullOrWhiteSpace(v)) { parts.Add(Uri.EscapeDataString(key) + "=" + Uri.EscapeDataString(v!)); given.Add(key); }
        }
        if (view is not null)
        {
            parts.Insert(given.Contains("c") ? 1 : 0, "view=" + Uri.EscapeDataString(view.Id));
            foreach (var (col, val) in view.Filters) if (!given.Contains("f." + col)) parts.Add("f." + Uri.EscapeDataString(col) + "=" + Uri.EscapeDataString(val));
            if (view.Sort is not null && !given.Contains("sort")) { parts.Add("sort=" + Uri.EscapeDataString(view.Sort)); if (view.Desc is { } d && !given.Contains("dir")) parts.Add("dir=" + (d ? "desc" : "asc")); }
        }
        return NavModel.HrefOf(t.Page) + (parts.Count > 0 ? "?" + string.Join("&", parts) : "");
    }

    /// A browser navigation to a page (not a handler, not a programmatic read).
    public static bool IsNavigation(HttpRequest r) =>
        (HttpMethods.IsGet(r.Method) || HttpMethods.IsHead(r.Method))
        && !r.Query.ContainsKey("handler")
        && string.Equals(r.Headers["Sec-Fetch-Mode"], "navigate", StringComparison.OrdinalIgnoreCase);

    /// The middleware: an old address opened by a browser goes to its page / view (302).
    public static async Task Middleware(HttpContext ctx, Func<Task> next)
    {
        if (IsNavigation(ctx.Request) && Target(ctx.Request.Path.Value ?? "", ctx.Request.Query) is { } to)
        {
            ctx.Response.Redirect(to);
            return;
        }
        await next();
    }
}
