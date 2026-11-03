using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace SI.Management.Web.Auth;

/// <summary>
/// #253 x #254, FAIL CLOSED: a person whose view is limited to some departments (a Delegated user with a department scope,
/// an advisor, a person of a department -- <see cref="IAccessScope.Visibility"/> is set) reaches ONLY the pages on
/// <see cref="Allowed"/>: pages that show no estate data, and pages that apply the person's departments to every row they
/// read. Every other page answers 403 before its handler runs -- so an estate-wide dashboard, a new page, or a page that
/// forgot the department scope is never shown unfiltered to such a person. A page joins the list only once every read on
/// it carries the person's visibility (a test holds every page to this list: DepartmentLimitedPersonTests).
/// </summary>
public sealed class DepartmentScopePageFilter(IAccessScope access, SI.Management.Web.Departments.IDepartmentScopeResolver? departments = null) : IAsyncPageFilter
{
    /// The pages a department-limited person may open (Razor view paths, exact, any case).
    public static readonly IReadOnlySet<string> AllowedPages = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        // no estate data: the landing page, the refusal / error pages, the link pages, the person's own preferences, the
        // product documentation, "part of Pro" (not /Help: it shows the estate's device count)
        "/Index", "/NoAccess", "/Denied", "/Error", "/MagicLink", "/MagicLinkRequest", "/Preferences", "/Docs/Index", "/ProOnly",
        // every read limited to the person's departments (the visibility predicate / the department resolver)
        "/Findings/Index", "/Findings/Detail", "/Search", "/Chat", "/Records/Index", "/Summary/Index",
        "/Cis/Index", "/Cis/Detail", "/Cis/NotOnboarded", "/Cis/Findings", "/Cis/Summary",
        "/Exemptions/Request", "/Changes/Index", "/Admin/History", "/Columns",
    };

    /// Whole folders whose every page applies the department scope itself (a collection view refuses, in its own words,
    /// every view it cannot limit to the person's departments -- CollectionPageModel.DepartmentScopedViews).
    public static readonly IReadOnlyList<string> AllowedFolders = ["/Collection/", "/Departments/", "/Tasks/", "/Actions/"];

    /// Inside an allowed folder, the pages that span every department (readers only).
    public static readonly IReadOnlySet<string> RefusedInFolders = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "/Departments/Unassigned" };

    /// PURE. May a department-limited person open this page?
    public static bool Allowed(string? viewEnginePath)
    {
        var p = (viewEnginePath ?? "").Trim();
        if (p.Length == 0) return false;
        if (AllowedPages.Contains(p)) return true;
        if (RefusedInFolders.Contains(p)) return false;
        return AllowedFolders.Any(f => p.StartsWith(f, StringComparison.OrdinalIgnoreCase));
    }

    /// Whether this person's view is limited to some rows (then only <see cref="Allowed"/> pages open): a role whose
    /// scopes limit what it sees, or -- decided as the pages decide it, by the department resolver -- a person of a
    /// department who holds no role and reaches the app through that membership alone.
    public async Task<bool> LimitedAsync(System.Security.Claims.ClaimsPrincipal user, CancellationToken ct)
    {
        if (user.Identity?.IsAuthenticated != true) return false;
        if (access.Visibility(user) is not null) return true;
        if (departments is null || AnyAccessHandler.HasRole(user)) return false;
        var mine = await departments.ResolveAsync(user, ct);
        return !mine.Unrestricted && mine.Any;
    }

    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        if (await LimitedAsync(context.HttpContext.User, context.HttpContext.RequestAborted) && !Allowed(context.ActionDescriptor.ViewEnginePath))
        {
            context.Result = new ForbidResult();
            return;
        }
        await next();
    }
}

/// The chat's per-person limits (Core/CallerLimits.cs): only a QUESTION is counted -- a POST to /Chat (the page's form or
/// its panel's Ask handler); reading the page is never limited.
public static class ChatLimits
{
    public static string? KeyOf(HttpContext ctx)
    {
        if (!HttpMethods.IsPost(ctx.Request.Method)) return null;
        if (!string.Equals((ctx.Request.Path.Value ?? "").TrimEnd('/'), "/Chat", StringComparison.OrdinalIgnoreCase)) return null;
        var u = ctx.User;
        return AccessClaims.ObjectId(u) ?? (u.ChangeName() is { Length: > 0 } n ? n : "unknown");
    }
}
