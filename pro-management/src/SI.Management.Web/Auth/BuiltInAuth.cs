using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace SI.Management.Web.Auth;

/// <summary>
/// Microsoft's built-in Container Apps authentication in front of this web app (framework SECURE-WEB-1): the platform signs
/// the user in with Entra (the web app's managed identity as a federated credential -- no secret), keeps the session, and
/// -- its token store on -- hands each request to this app with the person's ID token (<see cref="IdTokenHeader"/>) and
/// access token (<see cref="AccessTokenHeader"/>), next to its own summary <see cref="HeaderName"/> (base64 JSON: auth_typ,
/// name_typ, role_typ, claims [{typ, val}]).
///
/// With the switch <see cref="Setting"/> ON this app:
///   * authenticates every request from a token IT VERIFIES (framework SECURE-WEB-1 "IDENTITY IN THE APP";
///     <see cref="BuiltInTokenVerifier"/>): the ID token, else the access token. The principal is the token's own claims
///     (oid, tid, preferred_username / upn / name, groups and the groups-overage marker, amr) on an identity with the same
///     name / role claim types as the in-app sign-in, so the access transformation, the policies and the department filter
///     work unchanged. <see cref="HeaderName"/> is a CROSS-CHECK only: when present, its object id must be the token's;
///     it is never the identity;
///   * answers a request without a verified token: a page navigation is sent to the platform's sign-in
///     (/.auth/login/aad), anything else (a script's fetch, a form post, a static file) gets 401;
///   * keeps the link area of the magic links exactly as behind the sign-in front (<see cref="LinkArea"/>): the platform lets
///     <see cref="SigninFront.AnonymousPaths"/> through only when magic links are on;
///   * signs out through the platform (<see cref="LogoutUrl"/>) and keeps no sign-in cookie of its own.
/// OFF (the default): neither the tokens nor the header are read -- no handler for them is even registered.
/// Built-in and the sign-in front are mutually exclusive: when both switches are on, built-in wins (<see cref="Resolve"/>).
/// </summary>
public static class BuiltInAuth
{
    /// The switch (an app setting the updater writes on the web container). Default OFF.
    public const string Setting = "SI_Web_BuiltInAuth";
    public const string Scheme = "SI.BuiltIn";
    public const string HeaderName = "X-MS-CLIENT-PRINCIPAL";
    /// The platform's token store: the person's ID token, and its access token for this app.
    public const string IdTokenHeader = "X-MS-TOKEN-AAD-ID-TOKEN";
    public const string AccessTokenHeader = "X-MS-TOKEN-AAD-ACCESS-TOKEN";
    /// The why of a request that carries no platform token at all (not signed in, not a failed sign-in).
    public const string NoToken = "no token";
    /// The platform's sign-in of the Microsoft (Entra) provider and its sign-out.
    public const string LoginPath = "/.auth/login/aad";
    public const string LogoutUrl = "/.auth/logout?post_logout_redirect_uri=/";
    /// "Sign in with another account" (owner 2026-11-14: admins often use a separate admin account, not the office account
    /// the browser is signed in with): the platform's sign-out, then straight back to its sign-in, where Entra shows the
    /// account picker (the authConfig asks for prompt=select_account).
    public const string SwitchAccountUrl = "/.auth/logout?post_logout_redirect_uri=/.auth/login/aad";
    /// The only provider configured: Microsoft (Entra).
    public const string Provider = "aad";
    /// A header longer than this is refused unread (a token with every group listed stays far below it).
    public const int MaxHeaderLength = 64 * 1024;
    /// At most this many claims, each value at most <see cref="MaxClaimValueLength"/> characters.
    public const int MaxClaims = 1000;
    public const int MaxClaimValueLength = 8 * 1024;

    public const string LongRole = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
    public const string LongTenant = "http://schemas.microsoft.com/identity/claims/tenantid";
    public const string LongUpn = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";
    public const string LongGroups = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups";

    /// The long claim types the platform may send, and the short type SI reads: the short one is added when missing.
    public static readonly IReadOnlyDictionary<string, string> ShortTypes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        [AccessClaims.LongOid] = "oid",
        [LongTenant] = "tid",
        [LongUpn] = "upn",
        [LongRole] = "roles",
        [LongGroups] = "groups",
    };

    public enum Mode { InApp, SigninFront, BuiltIn }

    public static bool IsEnabled(IConfiguration configuration) => SigninFront.IsOn(configuration[Setting]);

    /// <summary>
    /// The Referrer-Policy the app sends. Live 2026-11-14 (internal, the owner's first save): the platform's built-in
    /// authentication guards every cookie-authenticated POST against cross-site request forgery by its Referer header, and
    /// refuses one WITHOUT a Referer (HTTP 403.60, "Cross-site request forgery detected ... from referer ''") -- with
    /// "no-referrer" the browser sent none, so every form save failed. With built-in authentication: "same-origin" (the
    /// address goes to this site only, never to another site). Otherwise "no-referrer", as before.
    /// </summary>
    public static string ReferrerPolicy(bool builtIn) => builtIn ? "same-origin" : "no-referrer";

    /// The sign-in this process uses: built-in wins over the sign-in front; neither = the in-app sign-in.
    public static Mode Resolve(IConfiguration configuration) =>
        IsEnabled(configuration) ? Mode.BuiltIn : SigninFront.IsEnabled(configuration) ? Mode.SigninFront : Mode.InApp;

    /// Both switches on (built-in wins): worth one warning at start.
    public static bool BothOn(IConfiguration configuration) => IsEnabled(configuration) && SigninFront.IsEnabled(configuration);

    /// A redeemed link browses its own area (/MagicLink/s/, its own cookie) whenever a platform or the front signs people in.
    public static bool LinkAreaOn(IConfiguration configuration) => Resolve(configuration) != Mode.InApp;

    /// <summary>
    /// Registers the verified platform token as THE authentication of this app outside the link area; inside it the link
    /// session's own cookie (LinkArea). The cookie scheme stays registered for a refusal only (Forbid answers as today: a
    /// redirect to /Denied) -- it never authenticates a request here.
    /// </summary>
    public static void AddBuiltInAuthentication(IServiceCollection services, IConfiguration configuration)
    {
        services.AddSingleton(sp => new BuiltInTokenVerifier(sp.GetRequiredService<IConfiguration>()));
        var auth = services.AddAuthentication(o =>
            {
                o.DefaultScheme = LinkArea.SelectorScheme;
                o.DefaultAuthenticateScheme = LinkArea.SelectorScheme;
                o.DefaultChallengeScheme = LinkArea.SelectorScheme;
                o.DefaultForbidScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddScheme<AuthenticationSchemeOptions, BuiltInAuthHandler>(Scheme, "Container Apps authentication", _ => { })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);
        LinkArea.AddLinkSessionAuthentication(auth, Scheme);
    }

    /// <summary>
    /// PURE. The principal of one <see cref="HeaderName"/> value -- read for the CROSS-CHECK only (<see cref="AuthenticateAsync"/>),
    /// never the identity -- or null (with why) when it is not acceptable: not base64, not JSON, too long,
    /// another provider, no object id, another tenant (when <paramref name="tenantId"/> is known), another app's audience
    /// (when <paramref name="clientId"/> is known and the header names one), or an application's own token. Never throws.
    /// </summary>
    public static (ClaimsPrincipal? Principal, string Why) Parse(string? header, string? tenantId = null, string? clientId = null)
    {
        if (string.IsNullOrWhiteSpace(header)) return (null, "no header");
        if (header.Length > MaxHeaderLength) return (null, "the header is too long");
        try
        {
            var bytes = Convert.FromBase64String(header.Trim());
            var json = new UTF8Encoding(false, true).GetString(bytes);
            using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return (null, "the header is not an object");
            var authTyp = Str(root, "auth_typ");
            if (!string.Equals(authTyp, Provider, StringComparison.OrdinalIgnoreCase)) return (null, "the sign-in is not Microsoft Entra");
            if (!root.TryGetProperty("claims", out var arr) || arr.ValueKind != JsonValueKind.Array) return (null, "the header carries no claims");
            if (arr.GetArrayLength() > MaxClaims) return (null, "the header carries too many claims");

            var raw = new List<(string, string)>();
            foreach (var c in arr.EnumerateArray())
            {
                if (c.ValueKind != JsonValueKind.Object) continue;
                var typ = Str(c, "typ")?.Trim();
                var val = Str(c, "val");
                if (string.IsNullOrEmpty(typ) || val is null) continue;
                raw.Add((typ, val));
            }
            var p = PrincipalOf(raw);

            var oid = AccessClaims.ObjectId(p);
            if (string.IsNullOrWhiteSpace(oid)) return (null, "the sign-in carries no object id");
            if (Guid.TryParse(tenantId, out var t))
            {
                if (!Guid.TryParse(p.FindFirst("tid")?.Value, out var tid) || tid != t) return (null, "the sign-in is not of this tenant");
            }
            if (Guid.TryParse(clientId, out var app))
            {
                var auds = p.FindAll("aud").Select(a => a.Value.Trim()).ToList();
                var mine = app.ToString();
                if (auds.Count > 0 && !auds.Any(a => a.Equals(mine, StringComparison.OrdinalIgnoreCase) || a.Equals("api://" + mine, StringComparison.OrdinalIgnoreCase)))
                    return (null, "the sign-in is for another app");
            }
            // the platform also takes a bearer token for this app: an application's own token is not a person
            if (IsApplication(p)) return (null, "an application's token is not a signed-in person");
            return (p, "");
        }
        catch (Exception ex) when (ex is FormatException or JsonException or DecoderFallbackException or ArgumentException or InvalidOperationException)
        {
            return (null, "the header cannot be read");
        }
    }

    /// <summary>
    /// PURE. The principal SI reads from a sign-in's claims (a verified token's, or the cross-check header's): the short
    /// claim types, the same name / role claim types as the in-app sign-in, SecurityInsight's own claim types (role, scopes,
    /// magic-link page / query, one-time code, department session) and the magic-link session's role never taken from
    /// outside, each claim once, and the groups-overage marker when no groups are listed.
    /// </summary>
    public static ClaimsPrincipal PrincipalOf(IEnumerable<(string Type, string Value)> raw)
    {
        var claims = new List<Claim>();
        foreach (var (typ0, val) in raw)
        {
            var typ = typ0?.Trim();
            if (string.IsNullOrEmpty(typ) || val is null || val.Length > MaxClaimValueLength) continue;
            if (claims.Count >= MaxClaims) break;
            if (typ.StartsWith("si_", StringComparison.OrdinalIgnoreCase)) continue;
            var type = ShortTypes.TryGetValue(typ, out var s) ? s : typ;
            if (type == "roles" && string.Equals(val.Trim(), Roles.MagicLink, StringComparison.OrdinalIgnoreCase)) continue;
            // the long and the short form of one claim: once
            if (claims.Any(x => x.Type == type && x.Value == val)) continue;
            claims.Add(new Claim(type, val));
        }
        // proven at internal 2026-11-14: the platform's principal carries NO groups claim (only aud, name, oid,
        // preferred_username, tid), and an ID token without the groups claim configured carries none either. SecurityInsight
        // then reads the person's groups itself, exactly as for Entra's groups overage (AccessClaims.GroupsOverage -> the
        // directory read with the web app's own identity). The marker only makes SI read more; it never grants anything.
        if (!claims.Any(c => c.Type == "groups") && !claims.Any(c => c.Type is "hasgroups" or "_claim_names"))
            claims.Add(new Claim("hasgroups", "true"));
        var p = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme, "preferred_username", "roles"));
        SigninFront.AddNameFallback(p);
        return p;
    }

    /// <summary>
    /// The person of one request with built-in authentication on: the verified ID token, else the verified access token
    /// (each one JWT-shaped value); the platform's <see cref="HeaderName"/>, when present, must name the same object id.
    /// No token, an unverified token or a disagreeing header = null with why (never the header alone). Never throws.
    /// </summary>
    public static async Task<(ClaimsPrincipal? Principal, string Why)> AuthenticateAsync(IHeaderDictionary headers, BuiltInTokenVerifier verifier, CancellationToken ct = default)
    {
        var id = SI.Management.Web.Audit.SqlSignedRequestWriter.TokenOf(headers[IdTokenHeader]);
        var at = SI.Management.Web.Audit.SqlSignedRequestWriter.TokenOf(headers[AccessTokenHeader]);
        if (id is null && at is null) return (null, NoToken);
        ClaimsIdentity? verified = null; var why = "";
        if (id is not null) (verified, why) = await verifier.VerifyAsync(id, accessToken: false, ct);
        if (verified is null && at is not null)
        {
            var (v2, why2) = await verifier.VerifyAsync(at, accessToken: true, ct);
            verified = v2;
            why = id is null ? why2 : $"ID token: {why}; access token: {why2}";
        }
        if (verified is null) return (null, why);
        var p = PrincipalOf(verified.Claims.Select(c => (c.Type, c.Value)));
        var oid = AccessClaims.ObjectId(p);
        if (string.IsNullOrWhiteSpace(oid)) return (null, "the token carries no object id");
        if (headers.TryGetValue(HeaderName, out var hv) && hv.Count > 0)
        {
            if (hv.Count != 1) return (null, "more than one sign-in header");
            var (hp, hwhy) = Parse(hv.ToString());
            if (hp is null) return (null, "the platform's sign-in header cannot be read: " + hwhy);
            if (!string.Equals(AccessClaims.ObjectId(hp)?.Trim(), oid.Trim(), StringComparison.OrdinalIgnoreCase))
                return (null, "the platform's sign-in header names another person than the token");
        }
        return (p, "");
    }

    /// An application's token: Entra's marker idtyp = app, or a token without a delegated scope that names a calling
    /// application (azp / appid) -- a client-credentials token.
    public static bool IsApplication(ClaimsPrincipal p) =>
        string.Equals(p.FindFirst("idtyp")?.Value, "app", StringComparison.OrdinalIgnoreCase)
        || (p.FindFirst("scp") is null && (p.FindFirst("azp") is not null || p.FindFirst("appid") is not null));

    private static string? Str(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    /// A page the browser navigates to (sent to the sign-in) -- not a script's fetch, a form post or a file.
    public static bool IsNavigation(HttpRequest r)
    {
        if (!HttpMethods.IsGet(r.Method) && !HttpMethods.IsHead(r.Method)) return false;
        if (string.Equals(r.Headers["X-Requested-With"].ToString(), "XMLHttpRequest", StringComparison.OrdinalIgnoreCase)) return false;
        var mode = r.Headers["Sec-Fetch-Mode"].ToString();
        if (mode.Length > 0) return string.Equals(mode, "navigate", StringComparison.OrdinalIgnoreCase);
        return r.Headers.Accept.ToString().Contains("text/html", StringComparison.OrdinalIgnoreCase);
    }

    /// The platform's sign-in, back to this same page afterwards (a path on this site only, never another host).
    public static string LoginUrl(HttpRequest r)
    {
        var back = (r.PathBase + r.Path).ToString();
        if (back.Length == 0 || back[0] != '/' || back.StartsWith("//", StringComparison.Ordinal) || back.StartsWith("/\\", StringComparison.Ordinal)) back = "/";
        back += r.QueryString.ToString();
        return LoginPath + "?post_login_redirect_uri=" + Uri.EscapeDataString(back);
    }
}

/// <summary>
/// The token check (<see cref="BuiltInAuth"/>): registered ONLY when built-in authentication is on. No token = no sign-in;
/// an unverified token or a disagreeing header = a failed sign-in (never an exception, never a partial identity, never the
/// header alone).
/// </summary>
public sealed class BuiltInAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IConfiguration _configuration;
    private readonly BuiltInTokenVerifier _verifier;
    public BuiltInAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> o, ILoggerFactory l, UrlEncoder e, IConfiguration configuration, BuiltInTokenVerifier verifier) : base(o, l, e)
    { _configuration = configuration; _verifier = verifier; }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // defence in depth: the switch is read again -- the tokens count only while built-in authentication is on
        if (!BuiltInAuth.IsEnabled(_configuration)) return AuthenticateResult.NoResult();
        var (p, why) = await BuiltInAuth.AuthenticateAsync(Request.Headers, _verifier, Context.RequestAborted);
        if (p is null)
        {
            if (why == BuiltInAuth.NoToken) return AuthenticateResult.NoResult();
            Logger.LogWarning("the platform's sign-in was refused: {Why}", why);
            return AuthenticateResult.Fail(why);
        }
        return AuthenticateResult.Success(new AuthenticationTicket(p, BuiltInAuth.Scheme));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.CacheControl = "no-store";
        if (BuiltInAuth.IsNavigation(Request)) Response.Redirect(BuiltInAuth.LoginUrl(Request));
        else Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }
}
