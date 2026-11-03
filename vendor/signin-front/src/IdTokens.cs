using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace SigninFront;

/// <summary>Where the front gets the signed-in user's ID token for the upstream Authorization header.</summary>
public interface IIdTokenProvider
{
    /// <summary>The current, unexpired ID token of this session -- or null: no session, session over, or no fresh token.</summary>
    Task<string?> GetIdTokenAsync(HttpContext ctx);
}

public static class JwtExpiry
{
    public static readonly TimeSpan RefreshMargin = TimeSpan.FromMinutes(5);

    /// <summary>The token's exp (UTC), or null when it cannot be read.</summary>
    public static DateTimeOffset? ReadExp(string jwt)
    {
        try
        {
            using var doc = ReadPayload(jwt);
            if (doc is not null && doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("exp", out var exp) && exp.TryGetInt64(out var secs))
                return DateTimeOffset.FromUnixTimeSeconds(secs);
            return null;
        }
        catch { return null; }
    }

    /// <summary>The token's payload as JSON (the caller disposes it), or null when it cannot be read. Not a validation.</summary>
    public static JsonDocument? ReadPayload(string jwt)
    {
        try
        {
            var parts = jwt.Split('.');
            if (parts.Length != 3) return null;
            var s = parts[1].Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4) { case 2: s += "=="; break; case 3: s += "="; break; case 1: return null; }
            return JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(s)));
        }
        catch { return null; }
    }

    /// <summary>True when the token is unreadable, expired, or expires within the margin.</summary>
    public static bool NeedsRefresh(string? jwt, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(jwt)) return true;
        var exp = ReadExp(jwt);
        return exp is null || exp.Value - now <= RefreshMargin;
    }
}

/// <summary>
/// 1.4.4: the token the front holds for a browser session is a PERSON's -- never an application's. Checked explicitly (each
/// kind with its own reason) at sign-in and before anything is forwarded upstream, so an application's token is refused for
/// what it is, not only because it happens to name no user. The bearer paths are NOT checked here: there the caller's own
/// token is forwarded and the app decides which callers it accepts (some accept applications on purpose).
/// </summary>
public static class PersonToken
{
    // "name": a person's token carries it even where a tenant drops the optional username claims; an app-only token has none
    private static readonly string[] UserClaims = { "preferred_username", "upn", "unique_name", "email", "name" };

    public const string AppIdtypReason = "an application token (idtyp = app) is not a person's sign-in";
    public const string AppRolesReason = "a token with application roles and no user is not a person's sign-in";

    /// <summary>Null for a person's token (or an unreadable one -- the callers refuse those on their own), else the reason.</summary>
    public static string? AppOnlyReason(string? jwt)
    {
        if (string.IsNullOrWhiteSpace(jwt)) return null;
        using var doc = JwtExpiry.ReadPayload(jwt);
        if (doc is null || doc.RootElement.ValueKind != JsonValueKind.Object) return null;
        var root = doc.RootElement;
        if (root.TryGetProperty("idtyp", out var t) && t.ValueKind == JsonValueKind.String &&
            string.Equals(t.GetString()?.Trim(), "app", StringComparison.OrdinalIgnoreCase))
            return AppIdtypReason;
        var hasRoles = false;
        if (root.TryGetProperty("roles", out var roles))
        {
            hasRoles = roles.ValueKind switch
            {
                JsonValueKind.Array => roles.EnumerateArray().Any(r => r.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(r.GetString())),
                JsonValueKind.String => !string.IsNullOrWhiteSpace(roles.GetString()),
                _ => false,
            };
        }
        if (!hasRoles) return null;
        foreach (var c in UserClaims)
            if (root.TryGetProperty(c, out var v) && v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString())) return null;
        return AppRolesReason;
    }
}

/// <summary>
/// Production provider. The ID token from the sign-in is kept in the (encrypted) session cookie. An ID token lives about
/// an hour; the session lives SIGNIN_SESSION_HOURS (pinned). Close to expiry the token is refreshed silently through MSAL
/// (the refresh token, client assertion = the managed identity's federated credential) and written back into the same
/// session -- IssuedUtc / ExpiresUtc are kept, so a refresh never lengthens the session. Past the session's end there is
/// no refresh. A refresh that fails (user disabled, consent revoked, token cache gone) returns null: the caller ends the
/// session and the user signs in again.
/// </summary>
public sealed class SessionIdTokenProvider : IIdTokenProvider
{
    private readonly ITokenAcquisition _tokens;
    private readonly FrontSettings _settings;
    private readonly TimeProvider _time;
    private readonly ILogger<SessionIdTokenProvider> _log;

    /// <summary>
    /// 1.4.2: every token call names the OIDC scheme. Without it Microsoft.Identity.Web takes the DEFAULT scheme -- the cookie
    /// scheme, which carries no app settings -- and throws InvalidOperationException: the access token at sign-in (1.4.1,
    /// PIM internal 2026-10-21) and the hourly ID token refresh (every version before, unseen because it came after an hour).
    /// </summary>
    public const string TokenScheme = OpenIdConnectDefaults.AuthenticationScheme;

    /// <summary>A configuration error's own message (never a token or claim) -- other failures: the type only.</summary>
    public static string ConfigDetail(Exception ex) =>
        ex is InvalidOperationException or ArgumentException ? ": " + new string((ex.Message ?? "").Take(240).ToArray()) : "";

    public SessionIdTokenProvider(ITokenAcquisition tokens, FrontSettings settings, TimeProvider time, ILogger<SessionIdTokenProvider> log)
    {
        _tokens = tokens; _settings = settings; _time = time; _log = log;
    }

    public async Task<string?> GetIdTokenAsync(HttpContext ctx)
    {
        var r = await ctx.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (!r.Succeeded || r.Properties is null || r.Principal is null) return null;
        var props = r.Properties;
        var now = _time.GetUtcNow();
        if (props.ExpiresUtc is { } end && end <= now) return null;                 // session over: no refresh past it
        if (props.IssuedUtc is { } start && start + _settings.Session <= now) return null;

        if (_settings.ForwardsAccessToken) return await AccessTokenAsync(r.Principal, now);

        var current = props.GetTokenValue("id_token");
        if (!JwtExpiry.NeedsRefresh(current, now)) return current;

        try
        {
            var res = await _tokens.GetAuthenticationResultForUserAsync(new[] { _settings.RefreshScope }, authenticationScheme: TokenScheme, user: r.Principal,
                tokenAcquisitionOptions: new TokenAcquisitionOptions { ForceRefresh = true });
            var fresh = res?.IdToken;
            if (JwtExpiry.NeedsRefresh(fresh, now)) return null;
            if (!props.UpdateTokenValue("id_token", fresh!))
            {
                var all = props.GetTokens().ToList();
                all.Add(new AuthenticationToken { Name = "id_token", Value = fresh! });
                props.StoreTokens(all);
            }
            // 1.2.1: renew the stored session IN PLACE (same key). A re-sign-in with a session store removes the old key and
            // stores a new one -- a page's parallel requests still carrying the old cookie then found no session (401 / a
            // sign-in bounce) at every hourly refresh. Without a store or a key (an older ticket): the re-sign-in, as before.
            var store = ctx.RequestServices.GetService<ITicketStore>();
            if (store is not null && props.Items.TryGetValue(DistributedTicketStore.KeyItem, out var key) && !string.IsNullOrEmpty(key))
                await store.RenewAsync(key, new AuthenticationTicket(r.Principal, props, CookieAuthenticationDefaults.AuthenticationScheme));
            else
                await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, r.Principal, props);
            return fresh;
        }
        catch (Exception ex)
        {
            // Never log the token or the exception text (it can carry claims) -- the type is enough to diagnose.
            _log.LogWarning("signin-front: silent ID token refresh failed ({Type}{Detail}); the session is ended", ex.GetType().Name, ConfigDetail(ex));
            return null;
        }
    }

    /// <summary>
    /// 1.4.0 access mode: the access token for the app's own API scope (SIGNIN_UPSTREAM_SCOPE), from the server-side MSAL
    /// cache -- MSAL redeems the refresh token itself when the cached one is near its end; one forced refresh if it still
    /// is. The session's pinned end was checked by the caller: no token is handed out past it. A failure ends the session.
    /// </summary>
    private async Task<string?> AccessTokenAsync(System.Security.Claims.ClaimsPrincipal user, DateTimeOffset now)
    {
        try
        {
            var scopes = new[] { _settings.UpstreamScope };
            var res = await _tokens.GetAuthenticationResultForUserAsync(scopes, authenticationScheme: TokenScheme, user: user);
            var at = res?.AccessToken;
            if (JwtExpiry.NeedsRefresh(at, now))
            {
                res = await _tokens.GetAuthenticationResultForUserAsync(scopes, authenticationScheme: TokenScheme, user: user, tokenAcquisitionOptions: new TokenAcquisitionOptions { ForceRefresh = true });
                at = res?.AccessToken;
            }
            return JwtExpiry.NeedsRefresh(at, now) ? null : at;
        }
        catch (Exception ex)
        {
            // Never log the token or the exception text (it can carry claims) -- the type is enough to diagnose.
            _log.LogWarning("signin-front: the access token for the app could not be acquired ({Type}{Detail}); the session is ended", ex.GetType().Name, ConfigDetail(ex));
            return null;
        }
    }
}
