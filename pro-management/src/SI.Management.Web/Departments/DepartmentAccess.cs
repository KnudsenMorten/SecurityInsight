using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;

namespace SI.Management.Web.Departments;

/// <summary>
/// What a signed-in user may see: everything (<see cref="Unrestricted"/>), or only the rows of <see cref="Rows"/> -- the
/// predicate every data query must carry. <see cref="Departments"/> are the departments that user may open on the
/// department pages.
/// </summary>
public sealed record DepartmentAccess(bool Unrestricted, IReadOnlyList<int> Departments, RowVisibility? Restriction = null)
{
    public static readonly DepartmentAccess Everything = new(true, Array.Empty<int>());
    public static readonly DepartmentAccess Nothing = new(false, Array.Empty<int>());

    /// Null = sees every row; else the predicate every data query must carry.
    public RowVisibility? Rows => Unrestricted ? null : Restriction ?? new DepartmentVisibility(Departments).Rows;
    public bool Any => Unrestricted || Departments.Count > 0;
    public bool Sees(int departmentId) => Unrestricted || Departments.Contains(departmentId);
}

/// <summary>
/// THE hook every data query asks for the rows a user may see (the Delegated scope type "department", #253 x #254).
/// </summary>
public interface IDepartmentScopeResolver
{
    Task<DepartmentAccess> ResolveAsync(ClaimsPrincipal user, CancellationToken ct);
}

/// <summary>
/// In order: (1) the ROLE FRAMEWORK -- <see cref="IAccessScope.Visibility"/>: a Delegated user whose scopes restrict what
/// they see (a department scope) sees only those rows, and may open the departments their scopes name; (2) any other
/// role on the ladder (Reader, Admin, SuperAdmin; a Delegated user scoped only to security domains) sees everything;
/// (3) a signed-in user with NO role who is a person of a department (cfg.DepartmentMember: their object id, or a group in
/// their token) -- a business owner opening the link in their monthly report -- sees only those departments.
/// </summary>
public sealed class MembershipDepartmentScope : IDepartmentScopeResolver
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(2);
    private readonly DepartmentRepository _repo;
    private readonly IMemoryCache _cache;
    private readonly ILogger<MembershipDepartmentScope> _log;
    private readonly IAccessScope? _access;

    public MembershipDepartmentScope(DepartmentRepository repo, IMemoryCache cache, ILogger<MembershipDepartmentScope> log, IAccessScope? access = null)
    { _repo = repo; _cache = cache; _log = log; _access = access; }

    /// The object ids a user stands for: their own (oid) and every group in the token.
    public static IReadOnlyList<string> ObjectIds(ClaimsPrincipal user) =>
        user.FindAll("oid").Concat(user.FindAll("http://schemas.microsoft.com/identity/claims/objectidentifier")).Concat(user.FindAll("groups"))
            .Select(c => c.Value.Trim().ToLowerInvariant()).Where(v => v.Length > 0).Distinct().ToList();

    /// The department ids a user's role-framework scopes name.
    public static IReadOnlyList<int> ScopedDepartments(ClaimsPrincipal user) =>
        user.Scopes().SelectMany(s => s.ValuesOf(ScopeTypes.Department))
            .Select(v => int.TryParse(v, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var i) ? i : 0)
            .Where(i => i > 0).Distinct().OrderBy(i => i).ToList();

    public async Task<DepartmentAccess> ResolveAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        if (user.Identity?.IsAuthenticated != true) return DepartmentAccess.Nothing;
        if (_access?.Visibility(user) is { } vis) return new DepartmentAccess(false, ScopedDepartments(user), RowVisibility.From(vis, ScopedDepartments(user)));
        if (user.IsReader()) return DepartmentAccess.Everything;
        var ids = ObjectIds(user);
        if (ids.Count == 0) return DepartmentAccess.Nothing;
        var key = "si-dept-scope|" + string.Join(",", ids.OrderBy(i => i, StringComparer.Ordinal));
        if (_cache.TryGetValue(key, out DepartmentAccess? hit) && hit is not null) return hit;
        DepartmentAccess a;
        try { a = new DepartmentAccess(false, (await _repo.MembershipAsync(ids, ct)).Select(m => m.DepartmentId).Distinct().OrderBy(d => d).ToList()); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // fail CLOSED: a user whose departments cannot be read sees none
            _log.LogWarning(ex, "department membership could not be read");
            return DepartmentAccess.Nothing;
        }
        _cache.Set(key, a, Ttl);
        return a;
    }
}

/// <summary>
/// The department pages' policy: anyone on the role ladder, or a person of at least one department. What that user then
/// SEES is narrowed by <see cref="IDepartmentScopeResolver"/> on every read.
/// </summary>
public static class DepartmentPolicy
{
    public const string Name = "SI.Departments";
}

public sealed class DepartmentAccessRequirement : IAuthorizationRequirement { }

public sealed class DepartmentAccessHandler : AuthorizationHandler<DepartmentAccessRequirement>
{
    private readonly IDepartmentScopeResolver _scope;
    public DepartmentAccessHandler(IDepartmentScopeResolver scope) => _scope = scope;

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, DepartmentAccessRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true) return;
        if (context.User.IsReader()) { context.Succeed(requirement); return; }
        var a = await _scope.ResolveAsync(context.User, CancellationToken.None);
        if (a.Any) context.Succeed(requirement);
    }
}
