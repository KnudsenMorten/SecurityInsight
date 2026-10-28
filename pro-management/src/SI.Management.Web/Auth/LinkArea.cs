using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace SI.Management.Web.Auth;

/// <summary>
/// CR7 Option A (owner 2026-10-18): the magic links behind the ONE shared sign-in front. The front lets through, without a
/// sign-in and with NO Authorization, exactly the paths of <see cref="SigninFront.AnonymousPaths"/> (its
/// SIGNIN_ANONYMOUS_PATHS) -- on those paths THIS app is the only guard:
/// <list type="bullet">
/// <item>/MagicLink redeems a link's own token (single use, consumed atomically in SQL; minutes of life; bound to its page /
/// department and person) and only then starts a LINK SESSION: its own cookie (<see cref="CookieName"/>, Path
/// <see cref="Prefix"/>, HttpOnly, Secure, a hard end at the token's / the row's expiry, never sliding);</item>
/// <item>the session browses under <see cref="Prefix"/> only: a request there has its prefix moved into PathBase, so the
/// app's own pages answer with the link session as the user -- and with the SAME policies as anywhere else, so a link
/// session opens exactly what it opens without the front (one page read-only, or its one department), nothing an Entra
/// user may see;</item>
/// <item>a request under <see cref="Prefix"/> is authenticated by the link cookie ONLY (never a bearer); every other request
/// by the front's bearer ONLY (never the link cookie). A request there without a valid link session gets nothing.</item>
/// </list>
/// The pages carry absolute links ("/Findings"): inside the area the HTML's href/src/action/formaction, a redirect's Location
/// and the scripts' fetch / XHR (wwwroot/js/link-area.js) are kept inside the prefix. OFF (switch off): none of this runs.
/// </summary>
public static class LinkArea
{
    /// Where a link session browses (under the front's anonymous entry "/MagicLink").
    public const string Prefix = "/MagicLink/s";
    public const string Scheme = "SI.LinkSession";
    public const string CookieName = ".SI.LinkSession";
    /// The authentication behind the front: the link cookie inside the area, the front's bearer everywhere else.
    public const string SelectorScheme = "SI.Front";
    private const string Flag = "si.link-area";

    public static bool IsLinkArea(HttpContext ctx) => ctx.Items.ContainsKey(Flag);

    /// Under the prefix (segment boundary, any case) -- the rest of the path, else null.
    public static string? Inside(PathString path)
    {
        if (!path.StartsWithSegments(Prefix, StringComparison.OrdinalIgnoreCase, out var rest)) return null;
        return rest.HasValue ? rest.Value! : "/";
    }

    /// A link session's start: the page the link opens, inside the area.
    public static string Url(string appPath) => Prefix + (appPath.StartsWith('/') ? appPath : "/" + appPath);

    public static void AddLinkSessionAuthentication(AuthenticationBuilder auth)
    {
        auth.AddPolicyScheme(SelectorScheme, "SI sign-in front", o =>
            o.ForwardDefaultSelector = ctx => IsLinkArea(ctx) ? Scheme : JwtBearerDefaults.AuthenticationScheme);
        auth.AddCookie(Scheme, o =>
        {
            o.Cookie.Name = CookieName;
            o.Cookie.Path = Prefix;
            o.Cookie.HttpOnly = true;
            o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            // Lax: the link is opened from a mail (a cross-site navigation) and redirects into the area
            o.Cookie.SameSite = SameSiteMode.Lax;
            o.Cookie.IsEssential = true;
            // a HARD end: the expiry the redeemer sets, never renewed by use
            o.SlidingExpiration = false;
            o.ExpireTimeSpan = TimeSpan.FromMinutes(Links.MagicTokenCodec.MaxLifetimeMinutes);
            o.Events = new CookieAuthenticationEvents
            {
                // no (or an ended) link session: nothing of the page -- a plain 401, never a sign-in redirect
                OnRedirectToLogin = c => { c.Response.StatusCode = StatusCodes.Status401Unauthorized; return Task.CompletedTask; },
                OnRedirectToAccessDenied = c => { c.Response.StatusCode = StatusCodes.Status403Forbidden; return Task.CompletedTask; },
            };
        });
    }

    /// The policies that know a link session -- each decides for itself what the session may open (Management: the one page
    /// a mail link names; Wallboard: the same; the department policy: the person's one department).
    public static readonly IReadOnlyList<string> LinkPolicies = [Policies.Management, Policies.Wallboard, Departments.DepartmentPolicy.Name];
    /// Pages with only "a signed-in user" that a link session still needs: the refusal page, the error page, the landing
    /// page (which sends a link session to its own page).
    public static readonly IReadOnlyList<string> LinkPlainPages = ["/Denied", "/Error", "/Index"];

    /// <summary>
    /// What a request inside the area may reach at all, from the endpoint alone (before authorization): an anonymous
    /// endpoint, an endpoint guarded by a link policy, or one of <see cref="LinkPlainPages"/>. Every other endpoint --
    /// whatever only "a signed-in user" opens (product docs, preferences, /about) and every Reader / Admin page -- is refused
    /// in the area, so a link session never reaches what only an Entra sign-in may see. No endpoint (a static file, an
    /// unknown path): left to the fallback policy (the link session's cookie, else 401).
    /// </summary>
    public static bool EndpointAllowed(Endpoint? endpoint)
    {
        if (endpoint is null) return true;
        if (endpoint.Metadata.GetMetadata<Microsoft.AspNetCore.Authorization.IAllowAnonymous>() is not null) return true;
        var policies = endpoint.Metadata.GetOrderedMetadata<Microsoft.AspNetCore.Authorization.IAuthorizeData>().Select(a => a.Policy).Where(p => !string.IsNullOrEmpty(p)).ToList();
        if (policies.Any(p => LinkPolicies.Contains(p!, StringComparer.Ordinal))) return true;
        var page = endpoint.Metadata.GetMetadata<Microsoft.AspNetCore.Mvc.RazorPages.PageActionDescriptor>()?.ViewEnginePath;
        return policies.Count == 0 && page is not null && LinkPlainPages.Contains(page, StringComparer.OrdinalIgnoreCase);
    }

    /// After routing: inside the area, an endpoint a link session may never reach answers 403 before anything runs.
    public static void UseLinkAreaEndpointGate(WebApplication app)
    {
        app.Use(async (ctx, next) =>
        {
            if (IsLinkArea(ctx) && !EndpointAllowed(ctx.GetEndpoint()))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                return;
            }
            await next();
        });
    }

    // the attributes that carry an app path: kept inside the area (a path already under /MagicLink, a //host link or an
    // absolute URL is left alone)
    private static readonly Regex AppPathAttr = new(@"(\s(?:href|src|action|formaction)\s*=\s*"")/(?!/)(?![Mm][Aa][Gg][Ii][Cc][Ll][Ii][Nn][Kk])",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static string RewriteHtml(string html) => AppPathAttr.Replace(html, m => m.Groups[1].Value + Prefix + "/");

    public static string? RewriteLocation(string? location)
    {
        if (string.IsNullOrEmpty(location) || location[0] != '/' || location.StartsWith("//", StringComparison.Ordinal)
            || location.StartsWith("/\\", StringComparison.Ordinal)
            || location.StartsWith("/MagicLink", StringComparison.OrdinalIgnoreCase)) return location;
        return Prefix + location;
    }

    /// The area's middleware (before routing): the prefix into PathBase, the flag, the area's sign-out, and the answer's
    /// paths kept inside the prefix.
    public static void UseLinkArea(WebApplication app)
    {
        app.Use(async (ctx, next) =>
        {
            var rest = Inside(ctx.Request.Path);
            if (rest is null) { await next(); return; }
            ctx.Items[Flag] = true;
            ctx.Request.PathBase = ctx.Request.PathBase.Add(Prefix);
            ctx.Request.Path = rest;
            ctx.Response.Headers.CacheControl = "no-store";
            // the link session's own sign-out (the front's /signout ends the front's session, never this one)
            if (string.Equals(rest, "/signout", StringComparison.OrdinalIgnoreCase))
            {
                await ctx.SignOutAsync(Scheme);
                ctx.Response.Redirect("/MagicLink?ended=1");
                return;
            }
            ctx.Response.OnStarting(() =>
            {
                if (ctx.Response.Headers.Location.Count == 1)
                    ctx.Response.Headers.Location = RewriteLocation(ctx.Response.Headers.Location.ToString());
                return Task.CompletedTask;
            });
            var original = ctx.Response.Body;
            await using var buffer = new MemoryStream();
            ctx.Response.Body = buffer;
            try { await next(); }
            finally { ctx.Response.Body = original; }
            buffer.Position = 0;
            if (ctx.Response.ContentType?.StartsWith("text/html", StringComparison.OrdinalIgnoreCase) == true)
            {
                var html = RewriteHtml(await new StreamReader(buffer, Encoding.UTF8).ReadToEndAsync(ctx.RequestAborted));
                var bytes = Encoding.UTF8.GetBytes(html);
                ctx.Response.ContentLength = bytes.Length;
                await original.WriteAsync(bytes, ctx.RequestAborted);
            }
            else
            {
                if (ctx.Response.ContentLength is not null) ctx.Response.ContentLength = buffer.Length;
                await buffer.CopyToAsync(original, ctx.RequestAborted);
            }
        });
    }
}
