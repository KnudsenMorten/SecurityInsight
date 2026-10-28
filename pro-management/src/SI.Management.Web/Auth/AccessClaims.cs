using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;

namespace SI.Management.Web.Auth;

/// <summary>
/// The effective role and scopes of a signed-in user, as claims on an identity the app adds itself (authentication type
/// <see cref="IdentityType"/>). Entra never sends these claim types; any that arrive are dropped before they are
/// computed, so the only source is <see cref="AccessClaimsTransformation"/>.
/// </summary>
public static class AccessClaims
{
    public const string IdentityType = "SI.Access";
    /// Reader | Delegated | Admin | SuperAdmin.
    public const string Role = "si_role";
    /// One per Delegated assignment that applies: the scope as JSON.
    public const string Scope = "si_scope";
    /// Where the role came from, for the header and the Access page ("app role", "portal: Security team (group)").
    public const string Source = "si_role_source";
    /// Set when the token said the user is in too many groups to list and the groups could not be read otherwise.
    public const string GroupsIncomplete = "si_groups_incomplete";
    public const string LongOid = "http://schemas.microsoft.com/identity/claims/objectidentifier";

    private static readonly string[] Ours = [Role, Scope, Source, GroupsIncomplete, AuthMethods.Claim];

    /// The role's name from its definition (<see cref="RoleDefinitions"/>), so a new role needs no change here.
    public static string Label(SiRole r) => RoleDefinitions.Find(r)?.Name ?? "No role";

    public static SiRole? ParseRole(string? s) =>
        string.Equals(s?.Trim(), Roles.Viewer, StringComparison.OrdinalIgnoreCase) ? SiRole.Reader : RoleDefinitions.Find(s)?.Role;

    /// Whether the role's actions are bound to its scopes (Delegated today; the advisors of #258 later).
    public static bool IsScopeBound(SiRole r) => RoleDefinitions.Find(r)?.ScopeBound == true;

    /// The role the Entra app roles alone give (the `roles` claim): SuperAdmin, Admin, Viewer/Reader. Wallboard and the
    /// magic link are not on the ladder.
    public static SiRole AppRole(ClaimsPrincipal user)
    {
        if (user.IsInRole(Roles.SuperAdmin)) return SiRole.SuperAdmin;
        if (user.IsInRole(Roles.Admin)) return SiRole.Admin;
        if (user.IsInRole(Roles.Viewer) || user.IsInRole(Roles.Reader)) return SiRole.Reader;
        return SiRole.None;
    }

    /// Holds any app role of this app. #765: no longer a gate -- a person with no app role at all is resolved from
    /// SecurityInsight's own table like everyone else.
    public static bool HasSignInRole(ClaimsPrincipal user) => AppRole(user) > SiRole.None || user.IsInRole(Roles.Wallboard) || user.IsInRole(Roles.Department);

    public static SiRole EffectiveRole(ClaimsPrincipal user)
    {
        // #765 (SI decides): once the sign-in resolved the access identity, ITS role is the role -- "No role" included; the
        // Entra app role is no fallback for a person SecurityInsight gave nothing (before, a removed person kept it)
        var id = user.Identities.FirstOrDefault(i => i.AuthenticationType == IdentityType);
        if (id is not null) return id.FindFirst(Role) is { } c && ParseRole(c.Value) is { } r ? r : SiRole.None;
        return AppRole(user);
    }

    public static IReadOnlyList<AccessScope> Scopes(ClaimsPrincipal user)
    {
        if (!IsScopeBound(EffectiveRole(user))) return Array.Empty<AccessScope>();
        return user.Identities.Where(i => i.AuthenticationType == IdentityType).SelectMany(i => i.FindAll(Scope))
            .Select(c => AccessScope.Parse(c.Value)).Where(s => !s.IsEmpty).ToList();
    }

    /// The header badge: "Reader", "Delegated (Identity, Azure)", "Admin", "SuperAdmin".
    public static string Badge(ClaimsPrincipal user)
    {
        var r = EffectiveRole(user);
        if (!IsScopeBound(r)) return Label(r);
        // the anchors of every scope (security domains today; departments later)
        var what = Scopes(user).SelectMany(s => s.Entries.Where(e => ScopeTypes.Find(e.Type)?.Anchor == true)
                .Select(e => e.Value == AccessScope.AnyDomain ? "every domain" : e.Value))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        return what.Count == 0 ? Label(r) : $"{Label(r)} ({string.Join(", ", what)})";
    }

    public static string? SourceOf(ClaimsPrincipal user) =>
        user.Identities.Where(i => i.AuthenticationType == IdentityType).SelectMany(i => i.FindAll(Source)).FirstOrDefault()?.Value;

    public static string? ObjectId(ClaimsPrincipal user) => user.FindFirst("oid")?.Value ?? user.FindFirst(LongOid)?.Value;

    /// The group object ids in the token (`groups`); empty when none were sent.
    public static IReadOnlyList<string> Groups(ClaimsPrincipal user) =>
        user.FindAll("groups").Concat(user.FindAll("http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"))
            .Select(c => c.Value.Trim()).Where(v => v.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// Entra leaves `groups` out when the user is in more groups than a token holds (the "overage"): `_claim_names`
    /// then names groups, or `hasgroups` is true.
    public static bool GroupsOverage(ClaimsPrincipal user)
    {
        if (string.Equals(user.FindFirst("hasgroups")?.Value, "true", StringComparison.OrdinalIgnoreCase)) return true;
        var names = user.FindFirst("_claim_names")?.Value;
        if (string.IsNullOrWhiteSpace(names)) return false;
        try { using var d = JsonDocument.Parse(names); return d.RootElement.ValueKind == JsonValueKind.Object && d.RootElement.TryGetProperty("groups", out _); }
        catch (JsonException) { return names.Contains("groups", StringComparison.OrdinalIgnoreCase); }
    }

    /// The highest role the SecurityInsight assignments give (None when no row names the user or one of their groups).
    public static SiRole AssignedRole(IReadOnlyList<AccessAssignment> matching) =>
        matching.Where(a => RoleDefinitions.RankOf(a.Role) > 0).OrderByDescending(a => RoleDefinitions.RankOf(a.Role)).Select(a => a.Role).FirstOrDefault(SiRole.None);

    /// <summary>
    /// #765 (owner 2026-10-19, "SI decides"): does the Entra app role still count on its own? Only until it was carried over
    /// into SecurityInsight's table once (<paramref name="carried"/> holds "objectid|Role") -- from then on the table alone
    /// decides, so removing the person on the Access page removes their access. Two safety nets: a token without an object
    /// id (nothing can be carried over) keeps its app role; and while the table has NO SuperAdmin at all, an Entra SuperAdmin
    /// counts, so an install can never lock itself out.
    /// </summary>
    public static bool AppRoleCounts(ClaimsPrincipal user, IReadOnlySet<string> carried, bool anySuperAdminRow)
    {
        var app = AppRole(user);
        if (app == SiRole.None) return false;
        if (app == SiRole.SuperAdmin && !anySuperAdminRow) return true;
        var oid = ObjectId(user);
        return oid is null || !carried.Contains(SqlAccessStore.CarriedKey(oid, app));
    }

    /// The decision without the carry-over state (every app role counts) -- the shape before #765, kept for callers that
    /// resolve a role from rows alone.
    public static (SiRole Role, IReadOnlyList<AccessScope> Scopes, string Source) Resolve(ClaimsPrincipal user, IReadOnlyList<AccessAssignment> matching) =>
        Resolve(user, matching, new HashSet<string>(), anySuperAdminRow: true);

    /// <summary>
    /// The pure decision (#765: SI decides): the effective role = the highest SecurityInsight assignment that names the user
    /// or one of their groups; the Entra app role adds to it only while it has not been carried over yet
    /// (<see cref="AppRoleCounts"/>). No app role is needed to sign in any more: a person added on the Access page has
    /// exactly the role given there. A Delegated result carries every Delegated assignment's scope.
    /// </summary>
    public static (SiRole Role, IReadOnlyList<AccessScope> Scopes, string Source) Resolve(ClaimsPrincipal user, IReadOnlyList<AccessAssignment> matching,
        IReadOnlySet<string> carried, bool anySuperAdminRow)
    {
        var app = AppRoleCounts(user, carried, anySuperAdminRow) ? AppRole(user) : SiRole.None;
        var role = app; var source = app > SiRole.None ? "Entra app role" : "";
        // by rank; an off-ladder role (#258) is never assigned here, and a row that names one is ignored
        foreach (var a in matching.Where(a => RoleDefinitions.RankOf(a.Role) > 0).OrderByDescending(a => RoleDefinitions.RankOf(a.Role)))
        {
            if (RoleDefinitions.RankOf(a.Role) > RoleDefinitions.RankOf(role)) { role = a.Role; source = $"SecurityInsight access: {a.DisplayName} ({a.Kind.ToLowerInvariant()})"; }
        }
        var scopes = IsScopeBound(role)
            ? matching.Where(a => a.Role == role).Select(a => a.Scope).Where(s => !s.IsEmpty).ToList()
            : new List<AccessScope>();
        return (role, scopes, source);
    }

    /// Replaces any access identity / claims on the principal with these (Entra cannot inject them).
    public static ClaimsPrincipal Apply(ClaimsPrincipal user, SiRole role, IReadOnlyList<AccessScope> scopes, string source, bool groupsIncomplete, string? method = null)
    {
        var p = new ClaimsPrincipal();
        foreach (var i in user.Identities.Where(i => i.AuthenticationType != IdentityType))
        {
            var copy = i.Clone();
            foreach (var c in copy.Claims.Where(c => Ours.Contains(c.Type)).ToList()) copy.TryRemoveClaim(c);
            p.AddIdentity(copy);
        }
        var id = new ClaimsIdentity(IdentityType);
        id.AddClaim(new Claim(Role, Label(role)));
        // how this session signed in (oauth | magiclink | magiclink+otp), for actions a role guards with a strong sign-in
        // (a department sign-in link session passes its method from the server-side row: magiclink, or magiclink+otp once
        // its one-time code was confirmed -- never from anything the browser holds)
        id.AddClaim(new Claim(AuthMethods.Claim, method ?? AuthMethods.Detect(user)));
        foreach (var s in scopes) id.AddClaim(new Claim(Scope, s.ToJson()));
        if (source.Length > 0) id.AddClaim(new Claim(Source, source));
        if (groupsIncomplete) id.AddClaim(new Claim(GroupsIncomplete, "true"));
        p.AddIdentity(id);
        return p;
    }
}

/// What the departments give a signed-in person (#258): the off-ladder role (Advisor, or Department for an owner /
/// approver / delegate), the departments, where it came from, and -- for a sign-in link session -- how it signed in.
public sealed record DepartmentGrant(SiRole Role, IReadOnlyList<int> Departments, string Source, string? Method = null);

/// <summary>
/// The seam to the department people (#258), implemented in SI.Management.Web.Advisors: a sign-in link session's
/// grant from its server-side row, and an Entra user's grant from the departments that list them (an advisor by object
/// id or by the UPN Entra issued -- a B2B guest's home address -- and a person of a department by object id, a group in
/// the token, or a mail-only entry).
/// </summary>
public interface IDepartmentGrants
{
    /// A department sign-in link session: its grant, or null when the session is no longer valid.
    Task<DepartmentGrant?> SessionAsync(ClaimsPrincipal session, CancellationToken ct);
    /// An Entra user the role ladder gives nothing: the departments that list them, or null.
    Task<DepartmentGrant?> PersonAsync(ClaimsPrincipal user, IReadOnlyList<string> groups, CancellationToken ct);
}

/// <summary>
/// A session created by a redeemed DEPARTMENT sign-in link (#258) is a cookie identity of its own authentication type,
/// which no Entra token can produce; its only claim of substance is the sign-in id -- everything else is read from the
/// server-side row on every request.
/// </summary>
public static class DepartmentSessions
{
    public const string IdentityType = "SI.DepartmentLink";
    public const string SignInClaim = "si_dept_signin";

    public static bool IsSession(ClaimsPrincipal user) => SignInId(user) is not null;

    public static long? SignInId(ClaimsPrincipal user)
    {
        var c = user.Identities.Where(i => i.AuthenticationType == IdentityType && i.IsAuthenticated).SelectMany(i => i.FindAll(SignInClaim)).FirstOrDefault();
        return c is not null && long.TryParse(c.Value, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var id) && id > 0 ? id : null;
    }
}

/// <summary>
/// Runs on every authenticated request: reads the portal mapping (cached for seconds) and the user's groups, and adds
/// the effective role and scopes. When the mapping cannot be read, the user keeps exactly the Entra app role -- an
/// unreadable store never RAISES anyone.
/// </summary>
public sealed class AccessClaimsTransformation : IClaimsTransformation
{
    private readonly IAccessStore _store;
    private readonly IGroupMembershipSource _groups;
    private readonly ILogger<AccessClaimsTransformation> _log;
    private readonly IDepartmentGrants? _departments;

    public AccessClaimsTransformation(IAccessStore store, IGroupMembershipSource groups, ILogger<AccessClaimsTransformation> log, IDepartmentGrants? departments = null)
    { _store = store; _groups = groups; _log = log; _departments = departments; }

    private static ClaimsPrincipal None(ClaimsPrincipal p) => AccessClaims.Apply(p, SiRole.None, Array.Empty<AccessScope>(), "", false);

    /// The department role (#258) as claims: one scope per department, so the role framework's scope check and visibility
    /// predicate treat it like any Delegated department scope.
    public static ClaimsPrincipal Apply(ClaimsPrincipal p, DepartmentGrant g) => AccessClaims.Apply(p, g.Role,
        g.Departments.Distinct().OrderBy(d => d).Select(d => new AccessScope([new ScopeEntry(ScopeTypes.Department, d.ToString(System.Globalization.CultureInfo.InvariantCulture))])).ToList(),
        g.Source, false, g.Method);

    /// A user the ladder gives nothing: the departments that list them (an advisor, an owner), else no role. Fails CLOSED.
    private async Task<ClaimsPrincipal> PersonOrNoneAsync(ClaimsPrincipal principal, IReadOnlyList<string> groups, Func<ClaimsPrincipal> otherwise)
    {
        if (_departments is null) return otherwise();
        try
        {
            var g = await _departments.PersonAsync(principal, groups, CancellationToken.None);
            return g is null || g.Departments.Count == 0 ? otherwise() : Apply(principal, g);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the departments of a signed-in user could not be read; they get no department access");
            return otherwise();
        }
    }

    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity?.IsAuthenticated != true) return principal;
        // a DEPARTMENT SIGN-IN LINK session (#258): its server-side row decides on every request -- revoked, expired, the
        // advisor revoked or the department retired = no role at all from that request on
        if (DepartmentSessions.IsSession(principal))
        {
            if (_departments is null) return None(principal);
            try
            {
                var g = await _departments.SessionAsync(principal, CancellationToken.None);
                return g is null ? None(principal) : Apply(principal, g);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogWarning(ex, "a department sign-in session could not be checked; it gets no access");
                return None(principal);
            }
        }
        var app = AccessClaims.AppRole(principal);
        var oid = AccessClaims.ObjectId(principal);
        var groups = AccessClaims.Groups(principal).ToList();
        var incomplete = false;
        try
        {
            var all = await _store.ListAsync(CancellationToken.None);
            if (all.Count > 0 && oid is not null && groups.Count == 0 && AccessClaims.GroupsOverage(principal))
            {
                var looked = await _groups.GroupsOfAsync(oid, CancellationToken.None);
                if (looked is null) incomplete = true; else groups.AddRange(looked);
            }
            var matching = all.Where(a => a.Matches(oid, groups)).ToList();
            var carried = await _store.CarriedAsync(CancellationToken.None);
            // #765: an Entra app role not carried over yet is copied into SecurityInsight's table now, once -- the person
            // keeps exactly the access they had, and from then on the table decides
            if (app > SiRole.None && oid is not null && !carried.Contains(SqlAccessStore.CarriedKey(oid, app)))
            {
                try
                {
                    var markOnly = RoleDefinitions.RankOf(AccessClaims.AssignedRole(matching)) >= RoleDefinitions.RankOf(app);
                    var name = principal.FindFirst("name")?.Value ?? principal.ChangeName();
                    var w = await _store.CarryOverAsync(new CarryOver(oid, AccessAssignment.User, string.IsNullOrWhiteSpace(name) ? oid : name, principal.ChangeName(), app, markOnly), CancellationToken.None);
                    if (w.Status == SI.Management.Web.Settings.WriteStatus.Saved)
                    {
                        all = await _store.ListAsync(CancellationToken.None);
                        matching = all.Where(a => a.Matches(oid, groups)).ToList();
                        carried = await _store.CarriedAsync(CancellationToken.None);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    // not carried over: the app role keeps counting (nobody loses access); tried again on a later request
                    _log.LogWarning(ex, "an Entra app role could not be carried over into SecurityInsight's access table");
                }
            }
            var (role, scopes, source) = AccessClaims.Resolve(principal, matching, carried, all.Any(a => a.Role == SiRole.SuperAdmin));
            // only the Department (or Wallboard) app role and no mapping: the departments that list the person (#258)
            if (role == SiRole.None)
                return await PersonOrNoneAsync(principal, groups, () => AccessClaims.Apply(principal, role, scopes, source, incomplete));
            return AccessClaims.Apply(principal, role, scopes, source, incomplete);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the access assignments could not be read; the signed-in user keeps the Entra app role only");
            return AccessClaims.Apply(principal, app, Array.Empty<AccessScope>(), app > SiRole.None ? "Entra app role" : "", false);
        }
    }
}
