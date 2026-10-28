using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace SI.Management.Web.Auth;

/// <summary>
/// The shared sign-in front (framework section 12.11g, CR7): ONE sign-in component, FRAMEWORK/signin-front, runs as a
/// sidecar container in the SAME Container App revision as this web app and is the only container the ingress reaches.
/// It signs the user in (code flow + PKCE, the web app's managed identity as a federated credential -- no secret), strips
/// every inbound identity header and sends exactly one <c>Authorization: Bearer &lt;ID token&gt;</c> on each request.
///
/// With the switch <see cref="Setting"/> ON this app:
///   * listens on 127.0.0.1:<see cref="PortSetting"/> ONLY (the front reaches it inside the revision; nothing else can);
///   * verifies that JWT on EVERY request itself -- RS256 against the tenant's published keys, issuer, audience (the app
///     registration's client id) and lifetime -- and refuses anything without it (a header alone is never trusted);
///   * keeps the fallback policy "every route needs a signed-in user" and maps the roles exactly as the in-app sign-in
///     does (`roles`, `preferred_username`, no inbound claim remapping), so SuperAdmin / Admin / Viewer / Wallboard and the
///     portal mapping on top work unchanged;
///   * leaves /signout, the session and the security headers (CSP, HSTS, frame-ancestors) to the front.
/// OFF (the default): the in-app Entra sign-in exactly as before -- nothing of this is registered.
/// </summary>
public static class SigninFront
{
    /// The switch (an app setting on the web container). Default OFF.
    public const string Setting = "SI_Web_SigninFront";
    /// The port this app listens on behind the front (the front's SIGNIN_UPSTREAM_PORT).
    public const string PortSetting = "SIGNIN_UPSTREAM_PORT";
    public const int DefaultPort = 8081;
    /// The session of a sign-in, in hours: the shared front's SIGNIN_SESSION_HOURS (pro-management/signin-front.pin.json
    /// sessionHours). The in-app sign-in (switch OFF, the way back) keeps the SAME session -- fixed from the sign-in, never
    /// slid by activity -- so a person is sent back to Entra (Conditional Access, a disabled account) at least every 8 h
    /// whichever way the install signs in. A Pester test holds this equal to the pin.
    public const int SessionHours = 8;
    public static TimeSpan Session => TimeSpan.FromHours(SessionHours);
    /// The only signing algorithm accepted: Entra signs ID tokens with RS256.
    public static readonly string[] Algorithms = { SecurityAlgorithms.RsaSha256 };
    /// The clock difference allowed on exp / nbf.
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);

    public static bool IsOn(string? value)
    {
        var v = value?.Trim();
        return v is not null && (v.Equals("true", StringComparison.OrdinalIgnoreCase) || v == "1"
                                 || v.Equals("on", StringComparison.OrdinalIgnoreCase) || v.Equals("yes", StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsEnabled(IConfiguration configuration) => IsOn(configuration[Setting]);

    public static int UpstreamPort(IConfiguration configuration) =>
        int.TryParse(configuration[PortSetting]?.Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var p) && p is > 0 and < 65536 && p != 8080
            ? p : DefaultPort;

    /// The one address this app binds to behind the front: loopback only.
    public static string ListenUrl(IConfiguration configuration) => $"http://127.0.0.1:{UpstreamPort(configuration)}";

    /// The issuer of the tenant's v2.0 tokens (what the front signs the user in against).
    public static string Issuer(string instance, string tenantId) =>
        $"{(string.IsNullOrWhiteSpace(instance) ? "https://login.microsoftonline.com/" : instance.Trim().TrimEnd('/') + "/")}{tenantId.Trim()}/v2.0";

    /// <summary>
    /// Registers the bearer check of the front's token as THE authentication of this app outside the link area. The app's
    /// cookie scheme stays registered for a refusal (Forbid answers as today: a redirect to /Denied) -- that cookie never
    /// authenticates a request here. Inside the link area (/MagicLink/s/...) the link session's own cookie is the only
    /// authentication (LinkArea).
    /// </summary>
    public static void AddSigninFrontAuthentication(IServiceCollection services, IConfiguration configuration)
    {
        var ad = configuration.GetSection("AzureAd");
        var tenant = ad["TenantId"] ?? "";
        var client = ad["ClientId"] ?? "";
        if (!Guid.TryParse(tenant, out _) || !Guid.TryParse(client, out _))
            throw new InvalidOperationException($"{Setting} is on, but AzureAd:TenantId / AzureAd:ClientId are not set: the front's token cannot be verified, so the app does not start.");
        var instance = ad["Instance"] ?? "https://login.microsoftonline.com/";
        var auth = services.AddAuthentication(o =>
            {
                // the front's bearer everywhere, the link session's own cookie inside the link area only (LinkArea)
                o.DefaultScheme = LinkArea.SelectorScheme;
                o.DefaultAuthenticateScheme = LinkArea.SelectorScheme;
                o.DefaultChallengeScheme = LinkArea.SelectorScheme;
                o.DefaultForbidScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, o => ConfigureJwt(o, instance, tenant, client, IsOn(configuration[AccessTokenOnlySetting])))
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);
        LinkArea.AddLinkSessionAuthentication(auth);
    }

    /// <summary>
    /// The paths the front lets through WITHOUT a sign-in (its SIGNIN_ANONYMOUS_PATHS, set by setup from
    /// pro-management\signin-front.pin.json "anonymousPaths" -- the same list; a test holds the two equal). Exact prefixes,
    /// case-insensitive, on a segment boundary: "/MagicLink" also covers the link session's area "/MagicLink/s/...".
    /// On them this app is the only guard: the link's own token (single use, minutes, bound to its target) and then the link
    /// session's own cookie (LinkArea).
    /// </summary>
    public static readonly IReadOnlyList<string> AnonymousPaths = ["/MagicLink", "/MagicLinkRequest"];

    /// The front's matching rule (signin-front 1.1.0): the exact path, or a path under it ("/link" matches /link and
    /// /link/x, never /linkx), case-insensitive.
    public static bool IsAnonymousPath(PathString path) =>
        AnonymousPaths.Any(p => path.Equals(p, StringComparison.OrdinalIgnoreCase) || path.StartsWithSegments(p, StringComparison.OrdinalIgnoreCase));

    /// #852 / signin-front 1.4.0: ON = only the access token for this app's own API is accepted (an ID token is refused).
    /// Default OFF: both forms, so the front 1.3.0 (ID token) and 1.4.0 (access token, SIGNIN_UPSTREAM_SCOPE) both work.
    public const string AccessTokenOnlySetting = "SI_Web_SigninFrontAccessTokenOnly";
    /// The delegated scope the front 1.4.0 asks for on this app's own API (api://&lt;client id&gt;/user_impersonation).
    public const string Scope = "user_impersonation";

    /// The tenant's v1 issuer (an access token for an app that does not ask for v2 tokens carries it).
    public static string IssuerV1(string tenantId) => $"https://sts.windows.net/{tenantId.Trim()}/";

    /// <summary>
    /// PURE. Which form a token is that already passed the signature, lifetime, issuer (v2 or v1) and audience (client id or
    /// api://client id) checks -- and whether that form is accepted:
    ///   * an ACCESS token (it carries scp): any of the two issuers and the two audience forms; scp must hold
    ///     <see cref="Scope"/>;
    ///   * an ID token (no scp): only the v2 issuer and the bare client id as audience, exactly as before -- and refused when
    ///     <paramref name="accessTokenOnly"/> is on.
    /// Returns (Ok, Kind "access" | "id", Why).
    /// </summary>
    public static (bool Ok, string Kind, string Why) CheckTokenForm(ClaimsPrincipal principal, string issuerV2, string tenantId, string clientId, bool accessTokenOnly)
    {
        var iss = principal.FindFirst("iss")?.Value ?? "";
        var auds = principal.FindAll("aud").Select(c => c.Value.Trim()).ToList();
        var scp = principal.FindFirst("scp")?.Value;
        var client = clientId.Trim();
        if (!string.IsNullOrWhiteSpace(scp))
        {
            var okIss = iss == issuerV2 || iss == IssuerV1(tenantId);
            var okAud = auds.Any(a => a.Equals(client, StringComparison.OrdinalIgnoreCase) || a.Equals("api://" + client, StringComparison.OrdinalIgnoreCase));
            var okScp = scp.Split(' ', StringSplitOptions.RemoveEmptyEntries).Contains(Scope, StringComparer.Ordinal);
            if (!okIss) return (false, "access", "the access token's issuer is not this tenant");
            if (!okAud) return (false, "access", "the access token is not for this app");
            if (!okScp) return (false, "access", $"the access token does not carry the scope {Scope}");
            return (true, "access", "");
        }
        if (accessTokenOnly) return (false, "id", "an ID token is not accepted here (access tokens only)");
        if (iss != issuerV2) return (false, "id", "an ID token must come from the tenant's v2.0 issuer");
        if (!auds.Any(a => a.Equals(client, StringComparison.OrdinalIgnoreCase)) || auds.Count != 1) return (false, "id", "an ID token's audience must be this app's client id");
        return (true, "id", "");
    }

    /// The bearer check itself (also used by the tests to prove exactly what is accepted).
    public static void ConfigureJwt(JwtBearerOptions o, string instance, string tenantId, string clientId, bool accessTokenOnly = false)
    {
        var issuer = Issuer(instance, tenantId);
        // the tenant's published signing keys (jwks_uri of the v2.0 metadata), refreshed by the configuration manager
        o.Authority = issuer;
        o.MetadataAddress = issuer + "/.well-known/openid-configuration";
        o.RequireHttpsMetadata = true;
        o.MapInboundClaims = false;
        o.SaveToken = false;
        // the front reaches this app over plain HTTP inside the revision: the token is on every request, nothing else
        o.IncludeErrorDetails = false;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            // #852 / front 1.4.0: an access token for this app may carry the v1 issuer and the api:// audience; which form
            // is accepted with which is decided after validation (CheckTokenForm): an ID token still only v2 + client id
            ValidIssuers = new[] { IssuerV1(tenantId) },
            ValidateAudience = true,
            ValidAudience = clientId.Trim(),
            ValidAudiences = new[] { "api://" + clientId.Trim() },
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            ValidAlgorithms = Algorithms,
            ClockSkew = ClockSkew,
            RoleClaimType = "roles",
            NameClaimType = "preferred_username",
        };
        o.Events ??= new JwtBearerEvents();
        var before = o.Events.OnTokenValidated;
        o.Events.OnTokenValidated = async ctx =>
        {
            if (before is not null) await before(ctx);
            if (ctx.Result is not null || ctx.Principal is null) return;
            var (ok, _, why) = CheckTokenForm(ctx.Principal, issuer, tenantId, clientId, accessTokenOnly);
            if (!ok) { ctx.Fail(why); return; }
            AddNameFallback(ctx.Principal);
        };
    }

    /// <summary>
    /// A v1 access token carries no preferred_username: the name every page reads (preferred_username) falls back to upn,
    /// then unique_name -- added to the identity only when it is missing.
    /// </summary>
    public static void AddNameFallback(ClaimsPrincipal principal)
    {
        if (principal.FindFirst("preferred_username") is not null) return;
        var name = principal.FindFirst("upn")?.Value ?? principal.FindFirst("unique_name")?.Value;
        if (string.IsNullOrWhiteSpace(name)) return;
        (principal.Identity as ClaimsIdentity)?.AddClaim(new Claim("preferred_username", name));
    }
}
