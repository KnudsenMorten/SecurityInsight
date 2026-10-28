using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace SI.Management.Web.Auth;

/// Entra app roles (the app registration's appRoles, delivered in the `roles` claim). #765: they no longer gate sign-in --
/// SecurityInsight decides (Admin > Access); an app role only counts until it was carried over there once -- see
/// <see cref="AccessClaims"/>.
public static class Roles
{
    /// The top role: everything an Admin can do, plus role and scope assignment, licence, updates / template releases and
    /// support access. Whoever runs setup holds it (the bootstrap SuperAdmin).
    public const string SuperAdmin = "SuperAdmin";
    public const string Admin = "Admin";
    /// The app role VALUE of Reader. Its value stays "Viewer" so every existing assignment keeps working; it is shown as
    /// "Reader" (PIM Manager's name for the same role).
    public const string Viewer = "Viewer";
    /// Accepted as Reader too, should an app registration carry a role with this value.
    public const string Reader = "Reader";
    /// The big-screen kiosk account: the wall board page and nothing else.
    public const string Wallboard = "Wallboard";
    /// Not an Entra role: carried only by the short-lived session a redeemed magic link creates (one page, read-only -- or,
    /// for a department sign-in link of #258, the person's one department).
    public const string MagicLink = "SI.MagicLink";
    /// The app role that lets a person of a department SIGN IN with Entra -- an external advisor invited as a B2B guest, or
    /// an owner with no other role (the app requires an assignment). It grants nothing itself: the web app scopes the
    /// person to the departments that list them (cfg.DepartmentAdvisor / cfg.DepartmentMember), or to nothing (#258).
    public const string Department = "Department";
}

public static class Policies
{
    /// Settings, Change history, Run health, Close-loop state, Jobs, Connectors: Admin or SuperAdmin.
    public const string Admin = "SI.Admin";
    /// Admin > Access (role and scope assignment): SuperAdmin only.
    public const string SuperAdmin = "SI.SuperAdmin";
    /// Review &amp; commit: anyone who may stage a change -- Delegated (their own changes, re-checked against their
    /// scopes on commit), Admin, SuperAdmin.
    public const string Change = "SI.Change";
    /// The Management dashboards, the findings browser, the tier board and the chat: Reader and up (or a magic-link
    /// session for exactly the page it was issued for).
    public const string Management = "SI.Management";
    /// The wall board: Wallboard, or Reader and up.
    public const string Wallboard = "SI.Wallboard";
    /// #765: signed in, nothing more -- ONLY the pages a person without a SecurityInsight role must still reach: "You have
    /// no access to SecurityInsight yet" (/NoAccess), the refusal page (/Denied) and the error page. Every other route falls
    /// under the fallback policy (<see cref="AnyAccessRequirement"/>).
    public const string SignedIn = "SI.SignedIn";
}

public static class Claims
{
    /// The one path a magic-link session may open.
    public const string MagicPage = "si_magic_page";
    /// The query a magic-link session was signed for (CR7): every parameter it names is pinned -- the session opens its page
    /// only with exactly those values (a link to finding X never opens finding Y); other parameters (paging, export) may vary.
    public const string MagicQuery = "si_magic_query";
}

public static class UserExtensions
{
    /// The name recorded in cfg.ChangeLog: the UPN when Entra sends one, else the name, else the object id.
    public static string ChangeName(this ClaimsPrincipal user) =>
        user.FindFirst("preferred_username")?.Value
        ?? user.FindFirst(ClaimTypes.Upn)?.Value
        ?? user.Identity?.Name
        ?? user.FindFirst(AccessClaims.LongOid)?.Value
        ?? user.FindFirst("oid")?.Value
        ?? "";

    /// The effective role: what the sign-in resolved (app role + portal mapping), else the Entra app role alone.
    public static SiRole EffectiveRole(this ClaimsPrincipal user) => AccessClaims.EffectiveRole(user);
    /// A Delegated user's scopes (empty for every other role).
    public static IReadOnlyList<AccessScope> Scopes(this ClaimsPrincipal user) => AccessClaims.Scopes(user);

    // by RANK, never by the enum's number: the off-ladder roles of #258 (Advisor, Department) have rank 0
    private static bool AtLeast(ClaimsPrincipal user, SiRole r) => RoleDefinitions.RankOf(user.EffectiveRole()) >= RoleDefinitions.RankOf(r);

    public static bool IsSuperAdmin(this ClaimsPrincipal user) => AtLeast(user, SiRole.SuperAdmin);
    /// Admin or SuperAdmin.
    public static bool IsAdmin(this ClaimsPrincipal user) => AtLeast(user, SiRole.Admin);
    /// Delegated exactly (scoped changes).
    public static bool IsDelegated(this ClaimsPrincipal user) => user.EffectiveRole() == SiRole.Delegated;
    /// May stage a change at all (Delegated inside their scopes, Admin, SuperAdmin).
    public static bool MayChange(this ClaimsPrincipal user) => AtLeast(user, SiRole.Delegated);
    /// Reader and up: every view, export and chat.
    public static bool IsReader(this ClaimsPrincipal user) => AtLeast(user, SiRole.Reader);
    /// An off-ladder, department-scoped role (#258): an Advisor, or a person of a department with no ladder role.
    public static bool IsDepartmentScoped(this ClaimsPrincipal user) => user.EffectiveRole() is SiRole.Advisor or SiRole.DepartmentMember;
    public static bool IsWallboardOnly(this ClaimsPrincipal user) => user.IsInRole(Roles.Wallboard) && !user.IsReader();
    public static bool IsMagic(this ClaimsPrincipal user) => user.IsInRole(Roles.MagicLink) && !user.IsReader();

    /// Reader and up -- or a magic-link session whose one page is the page being opened.
    public static bool MayRead(this AuthorizationHandlerContext ctx)
    {
        if (ctx.User.IsReader()) return true;
        if (!ctx.User.IsInRole(Roles.MagicLink)) return false;
        var page = ctx.User.FindFirst(Claims.MagicPage)?.Value;
        var http = ctx.Resource switch
        {
            HttpContext h => h,
            Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext f => f.HttpContext,
            _ => null,
        };
        var path = http?.Request.Path.Value;
        if (page is null || path is null || !string.Equals(page.TrimEnd('/'), path.TrimEnd('/'), StringComparison.OrdinalIgnoreCase)) return false;
        // the mail's one-page link is READ-ONLY: it reads its page and nothing else (CR7; a POST handler on the page -- a
        // staged exemption, a chat question -- is never a magic link's to call)
        if (!HttpMethods.IsGet(http!.Request.Method) && !HttpMethods.IsHead(http.Request.Method)) return false;
        return QueryMatches(ctx.User.FindFirst(Claims.MagicQuery)?.Value, http!.Request.Query);
    }

    /// <summary>
    /// The request carries every parameter the link was signed for with exactly its values (no claim = a session from
    /// before the claim existed: the page alone, as it was). A pinned parameter that is missing, repeated with another
    /// value or changed refuses.
    /// </summary>
    public static bool QueryMatches(string? signedQuery, IQueryCollection request)
    {
        if (signedQuery is null) return true;
        var pinned = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(signedQuery.Length > 0 ? "?" + signedQuery : "");
        foreach (var (key, values) in pinned)
        {
            if (!request.TryGetValue(key, out var got)) return false;
            var want = values.Where(v => v is not null).Select(v => v!).OrderBy(v => v, StringComparer.Ordinal).ToArray();
            var have = got.Where(v => v is not null).Select(v => v!).OrderBy(v => v, StringComparer.Ordinal).ToArray();
            if (!want.SequenceEqual(have, StringComparer.Ordinal)) return false;
        }
        return true;
    }
}
