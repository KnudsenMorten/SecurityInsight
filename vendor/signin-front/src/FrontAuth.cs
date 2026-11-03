using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace SigninFront;

/// <summary>
/// The sign-in itself. OpenID Connect authorization-code flow with PKCE; the code is redeemed by Microsoft.Identity.Web
/// with a CLIENT ASSERTION = a token of the web app's user-assigned managed identity, which the app registration trusts as
/// a federated identity credential (issuer = the tenant's v2.0 issuer, subject = the managed identity's object id,
/// audience = api://AzureADTokenExchange). No secret, no certificate -- there is no setting for either.
/// </summary>
public static class FrontAuth
{
    public static void ConfigureIdentity(MicrosoftIdentityOptions o, FrontSettings s)
    {
        o.Instance = FrontSettings.Instance;
        o.TenantId = s.TenantId;
        o.ClientId = s.ClientId;
        o.ClientSecret = null;
        o.ClientCredentials = new[]
        {
            new CredentialDescription
            {
                SourceType = CredentialSource.SignedAssertionFromManagedIdentity,
                ManagedIdentityClientId = s.FicManagedIdentityClientId,
                TokenExchangeUrl = FrontSettings.TokenExchangeAudience,
            },
        };
        o.ResponseType = OpenIdConnectResponseType.Code;
        o.UsePkce = true;
        o.SaveTokens = true;
        o.UseTokenLifetime = false;
        o.CallbackPath = "/signin-oidc";
        o.SignedOutCallbackPath = "/signout-callback-oidc";
    }

    public static void ConfigureCookie(CookieAuthenticationOptions c, FrontSettings s)
    {
        // The 8 h PINNED session: a fixed end from the sign-in, never slid forward by activity or by a token refresh.
        c.ExpireTimeSpan = s.Session;
        c.SlidingExpiration = false;
        c.Cookie.Name = FrontCookie.Name;
        c.Cookie.HttpOnly = true;
        c.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        c.Cookie.SameSite = SameSiteMode.Lax;
        c.Cookie.Path = "/";
    }

    /// <summary>Applied AFTER Microsoft.Identity.Web's own configuration, so these values win.</summary>
    public static void PostConfigureOidc(OpenIdConnectOptions o, FrontSettings s)
    {
        o.ResponseType = OpenIdConnectResponseType.Code;
        o.UsePkce = true;
        o.SaveTokens = true;
        o.UseTokenLifetime = false;
        o.ClientSecret = null;
        // 1.3.0 (framework §12.11g item 9): AT MOST ONE pending sign-in's correlation + nonce pair in a browser, living 15
        // minutes. Path "/" on purpose: the front SEES the older pairs on the next challenge and deletes them there (a pair
        // scoped to /signin-oidc would be invisible until the callback, and abandoned sign-ins would pile up on it -- past a
        // corporate proxy's 8 KB the callback itself would never arrive).
        o.RemoteAuthenticationTimeout = SigninFailure.RetryWindow;
        o.CorrelationCookie.Path = "/";
        o.NonceCookie.Path = "/";
        o.NonceCookie.Expiration = SigninFailure.RetryWindow;
        o.ProtocolValidator.NonceLifetime = SigninFailure.RetryWindow;
        var previous = o.Events.OnRedirectToIdentityProvider;
        o.Events.OnRedirectToIdentityProvider = async ctx =>
        {
            // the handler has written THIS sign-in's pair already (new random names); every pair the browser still carries
            // is an earlier, abandoned sign-in -- deleted now (CookieHygiene.Delete: both paths a pair can have)
            foreach (var n in ctx.Request.Cookies.Keys.Where(CookieHygiene.IsPendingSignin).Take(CookieHygiene.MaxDeletesPerResponse))
                CookieHygiene.Delete(ctx.Response, n);
            // A script call (fetch / XHR) cannot follow a redirect to the sign-in page: it gets 401 and the page
            // reloads itself. Only a top-level navigation is redirected -- and the ONE retry after a failed sign-in (1.2.0),
            // which answers the browser's own form post from the sign-in page.
            var retry = ctx.Properties.Items.TryGetValue(SigninFailure.RetryItem, out var r) && r == "1";
            if (!retry && !Navigation.IsNavigation(ctx.Request))
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                ctx.HandleResponse();
                return;
            }
            if (previous is not null) await previous(ctx);
        };
        // 1.4.4: a sign-in is a PERSON's. An ID token that is an application's (idtyp = app, or application roles with no
        // user) is refused at the sign-in itself, with its own reason -- no session is created for it.
        var previousValidated = o.Events.OnTokenValidated;
        o.Events.OnTokenValidated = async ctx =>
        {
            if (previousValidated is not null) await previousValidated(ctx);
            if (ctx.Result is not null) return;   // an earlier handler already decided (failed / handled / skipped)
            if (PersonToken.AppOnlyReason(ctx.ProtocolMessage?.IdToken) is { } appOnly) ctx.Fail(appOnly);
        };
        // 1.2.0: the session holds the ID token ONLY (forwarded upstream). The refresh token stays in the server-side token
        // cache, where the silent refresh reads it; the access token is not needed. A completed sign-in clears the retry marker.
        var previousTicket = o.Events.OnTicketReceived;
        o.Events.OnTicketReceived = async ctx =>
        {
            if (previousTicket is not null) await previousTicket(ctx);
            if (ctx.Properties is { } p)
            {
                var keep = p.GetTokens().Where(t => t.Name == "id_token").ToList();
                p.StoreTokens(keep);
                p.Items.Remove(SigninFailure.RetryItem);
            }
            ctx.Response.Cookies.Delete(SigninFailure.RetryCookie, new CookieOptions { Secure = true, SameSite = SameSiteMode.None, Path = "/" });
        };
        // 1.2.0: a failed sign-in -- an error answer, a failed code redemption (invalid_grant / AADSTS70044), a lost
        // correlation / nonce cookie -- gets ONE fresh sign-in, then a readable page. Never a hang, a loop or a 500.
        o.Events.OnRemoteFailure = ctx =>
            SigninFailure.HandleAsync(ctx, ctx.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("SigninFront"));
    }

    public static void ConfigureBearer(JwtBearerOptions o, FrontSettings s)
    {
        o.Authority = s.Authority;
        o.MapInboundClaims = false;
        o.RequireHttpsMetadata = true;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuers = s.ValidIssuers,
            ValidateAudience = true,
            ValidAudiences = s.BearerAudiences,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
            ClockSkew = TimeSpan.FromMinutes(5),
        };
    }
}

public static class Navigation
{
    /// <summary>Is this a top-level browser navigation (redirect to sign-in) rather than a script call (401)?</summary>
    public static bool IsNavigation(HttpRequest r)
    {
        var mode = r.Headers["Sec-Fetch-Mode"].ToString();
        if (mode.Length > 0) return mode.Equals("navigate", StringComparison.OrdinalIgnoreCase);
        if (r.Headers.ContainsKey("X-Requested-With")) return false;
        return HttpMethods.IsGet(r.Method) || HttpMethods.IsHead(r.Method);
    }
}
