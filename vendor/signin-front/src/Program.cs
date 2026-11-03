// signin-front -- the shared web sign-in front (framework DOCS/REQUIREMENTS.md §12.11g, named exception in GOVERNANCE).
// A SIDECAR: its own container in the app's revision, the only one the ingress reaches; the app listens on
// 127.0.0.1:<SIGNIN_UPSTREAM_PORT>. Contract, settings and setup: ../README.md.
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.TokenCacheProviders.Distributed;
using Azure.Identity;
using SigninFront;
using Yarp.ReverseProxy.Forwarder;

var builder = WebApplication.CreateBuilder(args);
var settings = FrontSettings.Load(builder.Configuration);   // invalid settings stop the container here

builder.WebHost.ConfigureKestrel(k =>
{
    k.AddServerHeader = false;
    // 1.3.0: accept up to 64 KB of request headers so a browser carrying old cookies gets the clear-and-retry page
    // (CookieHygiene.ClearBytes) instead of Kestrel's bare 431. Prevention keeps real headers far below this.
    k.Limits.MaxRequestHeadersTotalSize = 64 * 1024;
});
builder.Services.AddSingleton(settings);
builder.Services.TryAddSingleton(TimeProvider.System);
builder.Services.AddHttpForwarder();
builder.Services.AddSingleton(new UpstreamClient(UpstreamClient.CreateDefaultInvoker()));
builder.Services.AddScoped<IIdTokenProvider, SessionIdTokenProvider>();

builder.Services.AddAuthentication(o =>
    {
        o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    })
    .AddMicrosoftIdentityWebApp(o => FrontAuth.ConfigureIdentity(o, settings), c => FrontAuth.ConfigureCookie(c, settings))
    .EnableTokenAcquisitionToCallDownstreamApi(cca =>
        {
            cca.Instance = FrontSettings.Instance;
            cca.TenantId = settings.TenantId;
            cca.ClientId = settings.ClientId;
        }, new[] { settings.TokenScope })   // 1.4.0: the app's own API scope in access mode (openid profile offline_access are always added)
    .AddDistributedTokenCaches();
builder.Services.AddAuthentication().AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, o => FrontAuth.ConfigureBearer(o, settings));
builder.Services.PostConfigure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, o => FrontAuth.PostConfigureOidc(o, settings));
builder.Services.PostConfigure<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme, c => FrontAuth.ConfigureCookie(c, settings));

// 1.3.0 (framework §12.11g item 9): ALL state in the product's own SQL database (FrontState.cs) -- the sessions (the cookie
// carries only its key), the MSAL token cache and the Data Protection key ring, the keys wrapped by a Key Vault key. One
// store, one identity; a restart, a release roll or a second replica signs nobody out.
builder.Services.AddSingleton(sp => new SqlFrontStore(SqlFrontStore.ManagedIdentityConnectionString(settings), sp.GetRequiredService<ILoggerFactory>().CreateLogger("SigninFront")));
builder.Services.AddSingleton<IDistributedCache>(sp => sp.GetRequiredService<SqlFrontStore>());
builder.Services.AddHostedService<FrontStateCleanup>();
builder.Services.AddDataProtection()
    .SetApplicationName("signin-front")
    .ProtectKeysWithAzureKeyVault(new Uri(settings.KeyVaultKeyId), new ManagedIdentityCredential(settings.StateManagedIdentityClientId));
builder.Services.AddOptions<KeyManagementOptions>().Configure<SqlFrontStore>((o, store) => o.XmlRepository = store);
builder.Services.Configure<MsalDistributedTokenCacheAdapterOptions>(o =>
{
    o.Encrypt = true;                          // the refresh tokens are encrypted with the same keys before they reach SQL
    o.DisableL1Cache = true;                   // replicas share ONE cache: no per-replica copy that could go stale
    o.SlidingExpiration = settings.Session;    // a token entry lives as long as a session can
});
builder.Services.AddSingleton<ITicketStore, DistributedTicketStore>();
builder.Services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
    .PostConfigure<ITicketStore>((c, store) => c.SessionStore = store);

// EVERY route needs a signed-in user unless it is explicitly marked anonymous below (/healthz, /signout, the bearer paths).
builder.Services.AddAuthorization(o => o.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

var app = builder.Build();

// 1. The security headers on EVERY response, including the front's own 401 / 302 and every forwarded one.
app.Use(async (ctx, next) =>
{
    ctx.Response.OnStarting(() => { SecurityHeaders.Apply(ctx.Response.Headers); return Task.CompletedTask; });
    await next();
});
// 2. TLS ends at the platform ingress, the only thing that reaches this container: trust its X-Forwarded-Proto / -For.
var fwd = new ForwardedHeadersOptions { ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto };
fwd.KnownNetworks.Clear();
fwd.KnownProxies.Clear();
app.UseForwardedHeaders(fwd);
// 3. 1.2.0: warn on a Cookie header over 8 KB; remove 1.1.0 chunk cookies and piled-up correlation / nonce cookies.
//    1.3.0: also Easy Auth leftovers; over 16 KB the clear-and-retry page answers instead of the app.
var hygieneLog = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("SigninFront");
app.Use((ctx, next) => CookieHygiene.InvokeAsync(ctx, next, hygieneLog));
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapMethods("/healthz", new[] { "GET", "HEAD" }, () => Results.Ok()).AllowAnonymous();
app.Map("/signout", FrontEndpoints.SignOutAsync).AllowAnonymous();
foreach (var p in settings.BearerPaths)
{
    app.Map(p, FrontEndpoints.BearerAsync).AllowAnonymous();
    app.Map(p + "/{**rest}", FrontEndpoints.BearerAsync).AllowAnonymous();
}
// 1.1.0 SIGNIN_ANONYMOUS_PATHS (empty by default = no open path): no session, no Authorization forwarded.
foreach (var p in settings.AnonymousPaths)
{
    app.Map(p, FrontEndpoints.AnonymousAsync).AllowAnonymous();
    app.Map(p + "/{**rest}", FrontEndpoints.AnonymousAsync).AllowAnonymous();
}
app.Map("/{**path}", FrontEndpoints.BrowserAsync);   // the fallback policy applies

app.Run();

public static class FrontEndpoints
{
    /// <summary>Browser routes: a signed-in session is required (fallback policy); upstream gets the user's ID token.</summary>
    public static async Task BrowserAsync(HttpContext ctx)
    {
        var jwt = await ctx.RequestServices.GetRequiredService<IIdTokenProvider>().GetIdTokenAsync(ctx);
        // 1.4.4: only a PERSON's token is ever forwarded on a browser route -- an application's is refused for what it is
        // (its own reason in the log, never the token), and the session ends as for a missing token.
        if (PersonToken.AppOnlyReason(jwt) is { } appOnly)
        {
            ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("SigninFront")
                .LogWarning("signin-front: {Reason}; refused and the session is ended", appOnly);
            jwt = null;
        }
        if (string.IsNullOrEmpty(jwt))
        {
            await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (Navigation.IsNavigation(ctx.Request)) await ctx.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme);
            else ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }
        await ForwardAsync(ctx, jwt);
    }

    /// <summary>
    /// Bearer paths (SIGNIN_BEARER_PATHS): no session. A request WITH a bearer is forwarded only when the front validated
    /// it (signature against the tenant keys, issuer, audience, expiry) -- else 401 here. A request WITHOUT one is
    /// forwarded with no Authorization at all, so the app answers its own 401 + WWW-Authenticate (OAuth protected-resource
    /// discovery) or serves its public metadata. The app must still verify every bearer itself.
    /// </summary>
    public static async Task BearerAsync(HttpContext ctx)
    {
        var auth = ctx.Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(auth)) { await ForwardAsync(ctx, null); return; }
        const string prefix = "Bearer ";
        var r = auth.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            ? await ctx.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme)
            : AuthenticateResult.Fail("not a bearer");
        if (!r.Succeeded)
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            ctx.Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
            return;
        }
        await ForwardAsync(ctx, auth.Substring(prefix.Length).Trim());
    }

    /// <summary>
    /// Open paths (SIGNIN_ANONYMOUS_PATHS, 1.1.0): NO session required and NO Authorization forwarded -- an inbound one is
    /// stripped like every identity header and the front's cookies. The app proves the request itself (e.g. a single-use,
    /// short-life, target-bound link token). Security headers apply as everywhere.
    /// </summary>
    public static Task AnonymousAsync(HttpContext ctx) => ForwardAsync(ctx, null);

    /// <summary>/signout: ends the session here (never forwarded) and at Entra; signed out = a plain page.</summary>
    public static async Task SignOutAsync(HttpContext ctx)
    {
        var signedIn = (await ctx.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme)).Succeeded;
        await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (signedIn)
        {
            await ctx.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties { RedirectUri = "/signout" });
            return;
        }
        ctx.Response.StatusCode = StatusCodes.Status200OK;
        ctx.Response.ContentType = "text/plain; charset=utf-8";
        await ctx.Response.WriteAsync("Signed out.");
    }

    private static async Task ForwardAsync(HttpContext ctx, string? jwt)
    {
        var s = ctx.RequestServices.GetRequiredService<FrontSettings>();
        var up = ctx.RequestServices.GetRequiredService<UpstreamClient>();
        var forwarder = ctx.RequestServices.GetRequiredService<IHttpForwarder>();
        var err = await forwarder.SendAsync(ctx, s.UpstreamPrefix, up.Invoker, UpstreamClient.RequestConfig, new FrontTransformer(jwt));
        if (err != ForwarderError.None && !ctx.Response.HasStarted) ctx.Response.StatusCode = StatusCodes.Status502BadGateway;
    }
}

public partial class Program { }
