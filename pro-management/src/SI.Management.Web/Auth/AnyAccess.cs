using Microsoft.AspNetCore.Authorization;

namespace SI.Management.Web.Auth;

/// <summary>
/// #765 (owner 2026-10-19, "SI decides"): the enterprise application no longer requires an assignment, so EVERY person of
/// the directory can sign in -- and must then see nothing until SecurityInsight gives them a role. This is the app's
/// FALLBACK policy (every page, handler and endpoint that names no policy of its own, and the static files): signed in AND
/// some access -- a role on the ladder (Reader and up), the wall board account, a magic-link session, or a person of a
/// department. A signed-in person with none of these reaches only the "no access yet" page (<see cref="Policies.SignedIn"/>)
/// and the static assets it needs (the style sheet and the brand -- no data).
/// </summary>
public sealed class AnyAccessRequirement : IAuthorizationRequirement { }

public sealed class AnyAccessHandler : AuthorizationHandler<AnyAccessRequirement>
{
    /// The static assets a page needs; they carry no data (served after authorization, under this policy).
    public static readonly IReadOnlyList<string> AssetPrefixes = ["/css/", "/js/", "/lib/", "/brand/", "/favicon"];

    private readonly SI.Management.Web.Departments.IDepartmentScopeResolver? _departments;
    public AnyAccessHandler(IServiceProvider services) => _departments = services.GetService<SI.Management.Web.Departments.IDepartmentScopeResolver>();

    public static bool IsAsset(HttpContext? http) =>
        http is not null && http.GetEndpoint() is null && AssetPrefixes.Any(p => (http.Request.Path.Value ?? "").StartsWith(p, StringComparison.OrdinalIgnoreCase));

    /// Holds some access without a database read: a role on the ladder, the wall board, a magic link, a department role.
    public static bool HasRole(System.Security.Claims.ClaimsPrincipal user) =>
        user.IsReader() || user.IsInRole(Roles.Wallboard) || user.IsInRole(Roles.MagicLink) || user.IsDepartmentScoped() || DepartmentSessions.IsSession(user);

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AnyAccessRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true) return;
        if (HasRole(context.User)) { context.Succeed(requirement); return; }
        var http = context.Resource switch
        {
            HttpContext h => h,
            Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext f => f.HttpContext,
            _ => null,
        };
        if (IsAsset(http)) { context.Succeed(requirement); return; }
        // a person of a department (an owner listed by object id or group): their departments, read like the pages do
        if (_departments is not null && (await _departments.ResolveAsync(context.User, CancellationToken.None)).Any) context.Succeed(requirement);
    }
}
