using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace SI.Management.Web.Auth;

/// <summary>
/// A sign-in for the headless browser tests ONLY. Interactive Entra sign-in cannot run unattended, so a local run can
/// opt in to a fixed test user whose role comes from a request header (<c>X-SI-E2E-Role</c>) or cookie
/// (<c>si-e2e-role</c>): SuperAdmin, Admin, Viewer or Wallboard (optionally a named user, <c>X-SI-E2E-User</c>).
///
/// It is registered only when BOTH hold: the environment is Development AND the setting <c>SIWeb_E2EAuth</c> is true.
/// The setting anywhere else stops the process at start-up, so a hosted app can never be opened this way. Without the
/// setting nothing is registered -- the default build has no such scheme at all.
/// </summary>
public static class E2EAuth
{
    public const string Setting = "SIWeb_E2EAuth";
    public const string SchemeName = "SI.E2E";
    public const string RoleHeader = "X-SI-E2E-Role";
    public const string RoleCookie = "si-e2e-role";
    /// Optional: sign in as a named test user (letters, digits, . _ -) instead of e2e-&lt;role&gt;; its object id is derived
    /// from the name, so the Access page can map exactly that user. Same Development + opt-in gate as the role.
    public const string UserHeader = "X-SI-E2E-User";
    public static readonly string[] AllowedRoles = { Roles.SuperAdmin, Roles.Admin, Roles.Viewer, Roles.Wallboard };

    /// The fixed object id of a named test user (a name-based GUID, stable across runs).
    public static string ObjectIdOf(string user)
    {
        var h = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("si-e2e:" + user.ToLowerInvariant()));
        return new Guid(h.AsSpan(0, 16)).ToString();
    }

    /// Registers the test scheme when allowed; throws when the setting is on outside Development. Returns whether it
    /// was registered.
    public static bool AddIfEnabled(IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        if (!IsRequested(configuration)) return false;
        if (!environment.IsDevelopment())
            throw new InvalidOperationException(
                $"{Setting} is set, but the environment is '{environment.EnvironmentName}'. The test sign-in exists only for local headless browser tests and refuses to start outside Development.");
        services.AddAuthentication(o =>
            {
                // the test user authenticates and is challenged here; Forbid stays with the app's cookie scheme, so a
                // refused page answers exactly as hosted (a redirect to /Denied)
                o.DefaultAuthenticateScheme = SchemeName;
                o.DefaultChallengeScheme = SchemeName;
                o.DefaultForbidScheme = Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddScheme<AuthenticationSchemeOptions, E2EAuthHandler>(SchemeName, _ => { });
        return true;
    }

    public static bool IsRequested(IConfiguration configuration) =>
        string.Equals(configuration[Setting]?.Trim(), "true", StringComparison.OrdinalIgnoreCase)
        || configuration[Setting]?.Trim() == "1";
}

public sealed class E2EAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public E2EAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> o, ILoggerFactory l, UrlEncoder e) : base(o, l, e) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var role = Request.Headers[E2EAuth.RoleHeader].ToString();
        if (string.IsNullOrWhiteSpace(role)) role = Request.Cookies[E2EAuth.RoleCookie] ?? "";
        role = role.Trim();
        if (role.Length == 0) return Task.FromResult(AuthenticateResult.NoResult());
        var match = E2EAuth.AllowedRoles.FirstOrDefault(r => string.Equals(r, role, StringComparison.OrdinalIgnoreCase));
        if (match is null) return Task.FromResult(AuthenticateResult.Fail("unknown test role"));
        var named = Request.Headers[E2EAuth.UserHeader].ToString().Trim();
        if (named.Length > 0 && !System.Text.RegularExpressions.Regex.IsMatch(named, "^[A-Za-z0-9._-]{1,40}$")) return Task.FromResult(AuthenticateResult.Fail("unknown test user"));
        var user = named.Length > 0 ? named.ToLowerInvariant() + "@test.invalid" : "e2e-" + match.ToLowerInvariant() + "@test.invalid";
        // the claim types the Entra sign-in produces: name = "preferred_username", role = "roles"
        var id = new ClaimsIdentity(E2EAuth.SchemeName, "preferred_username", "roles");
        id.AddClaim(new Claim("preferred_username", user));
        id.AddClaim(new Claim("name", user));
        id.AddClaim(new Claim("oid", E2EAuth.ObjectIdOf(user)));
        id.AddClaim(new Claim("roles", match));
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(id), E2EAuth.SchemeName)));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}
