using System.Security.Claims;
using SI.Management.Core;

namespace SI.Management.Mcp;

/// One row of this install's access table (cfg.AccessAssignment) as the MCP server reads it.
public sealed record McpAccessRow(string PrincipalId, string PrincipalType, string Role);

/// Whether this caller is answered, as whom (<see cref="ToolCaller"/>), and why not.
public sealed record McpCallerDecision(bool Allowed, ToolCaller? Caller, string Why)
{
    public static McpCallerDecision No(string why) => new(false, null, why);
}

/// <summary>
/// WHO MAY USE THIS INSTALL'S MCP SERVER, decided the way the web app decides (#765 "SI decides"): the token must carry an
/// app role of the SecurityInsight app (the endpoint's policy) AND this install's own access table (cfg.AccessAssignment,
/// Admin &gt; Access) must give the person a role -- by their object id, or a group in their token. The table's role is the
/// role: a person removed or lowered on the Access page is removed or lowered here too, and a role given for ANOTHER
/// install of the same tenant (every install shares the one app registration) opens nothing here, because that install's
/// people are not in this install's table.
/// <list type="bullet">
/// <item>Reader: the read tools; Admin / SuperAdmin: also settings_read.</item>
/// <item>Delegated (limited to scopes, "portal only"): refused here -- the MCP server does not apply scopes.</item>
/// <item>No row, an unreadable table, no object id: refused (fail closed).</item>
/// <item>An APPLICATION (an app-only token, no delegated scope): the framework's sign-in rule for a read-only MCP (owner
/// 2026-10-31, APIDOC-1) -- answered with the read tools only, never settings_read, whatever app role it holds.</item>
/// </list>
/// PURE (<see cref="Decide"/>); <see cref="McpCallerResolver"/> reads the table.
/// </summary>
public static class McpCallerRule
{
    /// A plain SELECT (the MCP server's reader runs reads only); a database without the table fails the read = refused.
    public const string AccessSql = "SELECT PrincipalId, PrincipalType, Role FROM cfg.AccessAssignment;";

    public const string ScopeClaimLong = "http://schemas.microsoft.com/identity/claims/scope";
    public const string OidClaimLong = "http://schemas.microsoft.com/identity/claims/objectidentifier";

    public const string NotListed = "This SecurityInsight installation gives you no role: ask a SuperAdmin to add you on Admin > Access (the MCP server answers the people this installation lists).";
    public const string DelegatedRefused = "Your SecurityInsight role (Delegated) is limited to its scopes in the web app; the MCP server answers Reader and up.";
    public const string TableUnreadable = "This installation's access list could not be read, so nothing was answered. Try again shortly.";

    public static int Rank(string? role) => (role ?? "").Trim().ToLowerInvariant() switch
    {
        "reader" or "viewer" => 1,
        "delegated" => 2,
        "admin" => 3,
        "superadmin" => 4,
        _ => 0,
    };

    /// The highest app role in the token (Viewer / Reader = 1, Admin = 3, SuperAdmin = 4); 0 = none.
    public static int AppRoleRank(ClaimsPrincipal user) =>
        user.FindAll("roles").Concat(user.FindAll(ClaimTypes.Role)).Select(c => Rank(c.Value)).Where(r => r != 2).DefaultIfEmpty(0).Max();

    /// A delegated access token: it carries the scope it was issued for (scp).
    public static bool HasScope(ClaimsPrincipal user) => user.FindFirst("scp") is not null || user.FindFirst(ScopeClaimLong) is not null;

    /// The application a token was issued to (azp in a v2 access token, appid in a v1 one) -- an ID token names none.
    public static bool NamesClientApp(ClaimsPrincipal user) =>
        !string.IsNullOrWhiteSpace(user.FindFirst("azp")?.Value) || !string.IsNullOrWhiteSpace(user.FindFirst("appid")?.Value);

    /// An app-only token: Entra's idtyp = app, or no delegated scope (scp) AND the calling application named (azp / appid).
    public static bool IsAppOnly(ClaimsPrincipal user) =>
        string.Equals(user.FindFirst("idtyp")?.Value, "app", StringComparison.OrdinalIgnoreCase)
        || (!HasScope(user) && NamesClientApp(user));

    /// #999: a person's ID token for the sign-in application (the web app and the MCP share it: its audience, its issuer
    /// and its app roles all match) -- no scope, and no calling application. It proves a sign-in to the web app, it is not an
    /// access token for this server: refused, whatever role it carries.
    public static bool IsIdTokenShaped(ClaimsPrincipal user) =>
        !string.Equals(user.FindFirst("idtyp")?.Value, "app", StringComparison.OrdinalIgnoreCase) && !HasScope(user) && !NamesClientApp(user);

    public const string IdTokenRefused = "This is a sign-in (ID) token, not an access token for the SecurityInsight MCP server: sign in through your MCP client, which asks for an access token.";

    public static string? ObjectId(ClaimsPrincipal user) => user.FindFirst("oid")?.Value ?? user.FindFirst(OidClaimLong)?.Value;

    public static IReadOnlyList<string> Groups(ClaimsPrincipal user) =>
        user.FindAll("groups").Select(c => c.Value.Trim()).Where(v => v.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// The key a caller's limits are kept under: the object id, else the calling application, else "unknown".
    public static string PartitionKey(ClaimsPrincipal? user) =>
        user is null ? "unknown" : ObjectId(user) ?? user.FindFirst("azp")?.Value ?? user.FindFirst("appid")?.Value ?? "unknown";

    /// PURE. <paramref name="rows"/> null = the table could not be read.
    public static McpCallerDecision Decide(ClaimsPrincipal user, IReadOnlyList<McpAccessRow>? rows)
    {
        if (user.Identity?.IsAuthenticated != true) return McpCallerDecision.No("not signed in");
        if (AppRoleRank(user) == 0) return McpCallerDecision.No("the token carries no SecurityInsight app role");
        if (IsIdTokenShaped(user)) return McpCallerDecision.No(IdTokenRefused);
        if (IsAppOnly(user)) return new(true, ToolCaller.Unscoped(isAdmin: false), "application: the read tools");
        if (rows is null) return McpCallerDecision.No(TableUnreadable);
        var oid = ObjectId(user);
        if (string.IsNullOrWhiteSpace(oid)) return McpCallerDecision.No(NotListed);
        var groups = Groups(user);
        var rank = rows.Where(r => string.Equals(r.PrincipalType, "Group", StringComparison.OrdinalIgnoreCase)
                ? groups.Contains(r.PrincipalId.Trim(), StringComparer.OrdinalIgnoreCase)
                : string.Equals(r.PrincipalId.Trim(), oid.Trim(), StringComparison.OrdinalIgnoreCase))
            .Select(r => Rank(r.Role)).DefaultIfEmpty(0).Max();
        if (rank == 0) return McpCallerDecision.No(NotListed);
        if (rank == 2) return McpCallerDecision.No(DelegatedRefused);
        return new(true, ToolCaller.Unscoped(isAdmin: rank >= 3), rank >= 3 ? "listed: Admin" : "listed: Reader");
    }
}

/// Reads this install's access table for <see cref="McpCallerRule.Decide"/> (kept for 15 seconds; never throws: a table that
/// cannot be read refuses every person).
public sealed class McpCallerResolver(ISqlReader sql, TimeProvider? clock = null)
{
    public static readonly TimeSpan Keep = TimeSpan.FromSeconds(15);
    private readonly TimeProvider _clock = clock ?? TimeProvider.System;
    private (IReadOnlyList<McpAccessRow>? Rows, DateTimeOffset At)? _known;
    private readonly object _lock = new();

    public async Task<McpCallerDecision> ResolveAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        // an application (and an ID token, refused) never needs the table (and must not wait on it)
        if (McpCallerRule.IsAppOnly(user) || McpCallerRule.IsIdTokenShaped(user)) return McpCallerRule.Decide(user, Array.Empty<McpAccessRow>());
        return McpCallerRule.Decide(user, await RowsAsync(ct).ConfigureAwait(false));
    }

    private async Task<IReadOnlyList<McpAccessRow>?> RowsAsync(CancellationToken ct)
    {
        var now = _clock.GetUtcNow();
        lock (_lock) { if (_known is { } k && now - k.At < Keep) return k.Rows; }
        IReadOnlyList<McpAccessRow>? rows;
        try
        {
            rows = (await sql.QueryAsync(McpCallerRule.AccessSql, new Dictionary<string, object?>(), ct).ConfigureAwait(false))
                .Select(r => new McpAccessRow(Cell.Str(r, "PrincipalId") ?? "", Cell.Str(r, "PrincipalType") ?? "", Cell.Str(r, "Role") ?? ""))
                .Where(r => r.PrincipalId.Length > 0).ToList();
        }
        catch (OperationCanceledException) { throw; }
        catch { rows = null; }   // fail closed: no person is answered while the table cannot be read
        lock (_lock) { _known = (rows, now); }
        return rows;
    }
}
