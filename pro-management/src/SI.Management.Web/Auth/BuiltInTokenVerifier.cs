using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace SI.Management.Web.Auth;

/// <summary>
/// Framework SECURE-WEB-1 "IDENTITY IN THE APP": with Microsoft's built-in authentication in front, the person is the one a
/// token THIS APP VERIFIES -- the platform's token store hands every request the person's ID token
/// (X-MS-TOKEN-AAD-ID-TOKEN) and access token (X-MS-TOKEN-AAD-ACCESS-TOKEN). A token counts only when:
///   * it is signed by one of the tenant's signing keys (the tenant's OpenID configuration, read and cached; a key the
///     cache does not know makes it read again once);
///   * its issuer is the tenant's (v2 https://login.microsoftonline.com/&lt;tid&gt;/v2.0 or v1 https://sts.windows.net/&lt;tid&gt;/)
///     and its tid is the tenant;
///   * its audience is this app (&lt;clientId&gt; or api://&lt;clientId&gt;);
///   * it was issued within the platform's session (<see cref="IssuedWithinSession"/>): the platform keeps a FIXED 8-hour
///     session and does not refresh the ID token, so a token past its one-hour expiry but issued within the session is
///     accepted -- never one issued in the future, never one older than the session;
///   * it is a person's: an application's own token (idtyp = app, or an access token without a delegated scope that names a
///     calling application) is refused.
/// Never throws: the identity, or null with why.
/// </summary>
public sealed class BuiltInTokenVerifier
{
    /// The platform's fixed session, and the slack for the clocks of the platform, Entra and this app.
    public static readonly TimeSpan Session = TimeSpan.FromHours(8);
    public static readonly TimeSpan Slack = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan FutureSkew = TimeSpan.FromMinutes(5);

    private readonly string? _tenant;
    private readonly string? _client;
    private readonly IConfigurationManager<OpenIdConnectConfiguration>? _metadata;
    private readonly IReadOnlyList<SecurityKey>? _fixedKeys;
    private readonly Func<DateTime> _now;
    private readonly JsonWebTokenHandler _handler = new() { MapInboundClaims = false };

    /// The app: the keys from the tenant's OpenID configuration (AzureAd:TenantId / AzureAd:ClientId).
    public BuiltInTokenVerifier(IConfiguration configuration)
    {
        var ad = configuration.GetSection("AzureAd");
        _tenant = Guid.TryParse(ad["TenantId"], out var t) ? t.ToString() : null;
        _client = Guid.TryParse(ad["ClientId"], out var c) ? c.ToString() : null;
        _now = () => DateTime.UtcNow;
        if (_tenant is not null)
            _metadata = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"https://login.microsoftonline.com/{_tenant}/v2.0/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(), new HttpDocumentRetriever { RequireHttps = true });
    }

    /// Tests: fixed signing keys and, optionally, a fixed clock.
    public BuiltInTokenVerifier(string? tenantId, string? clientId, IEnumerable<SecurityKey> keys, Func<DateTime>? now = null)
    {
        _tenant = Guid.TryParse(tenantId, out var t) ? t.ToString() : null;
        _client = Guid.TryParse(clientId, out var c) ? c.ToString() : null;
        _fixedKeys = keys.ToList();
        _now = now ?? (() => DateTime.UtcNow);
    }

    public string? TenantId => _tenant;

    /// PURE. Issued within the platform's session: not in the future (beyond a small clock skew), and not before the
    /// session's length (plus slack) ago.
    public static bool IssuedWithinSession(DateTime issuedAtUtc, DateTime nowUtc) =>
        issuedAtUtc > DateTime.MinValue
        && issuedAtUtc <= nowUtc + FutureSkew
        && issuedAtUtc >= nowUtc - (Session + Slack);

    /// <summary>
    /// The verified identity of one token (its own claims, short types), or null with why. <paramref name="accessToken"/>:
    /// the token came as the platform's access token (the calling-application rule applies to it).
    /// </summary>
    public async Task<(ClaimsIdentity? Identity, string Why)> VerifyAsync(string? token, bool accessToken, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(token)) return (null, "no token");
        if (token.Length > BuiltInAuth.MaxHeaderLength) return (null, "the token is too long");
        if (_tenant is null || _client is null) return (null, "the app's tenant or client id is not configured");
        try
        {
            var keys = await KeysAsync(refresh: false, ct);
            if (keys is null) return (null, "the tenant's signing keys could not be read");
            var result = await _handler.ValidateTokenAsync(token, Parameters(keys));
            if (!result.IsValid && _metadata is not null && result.Exception is SecurityTokenSignatureKeyNotFoundException or SecurityTokenInvalidSignatureException)
            {
                // the keys roll: read the configuration again once (the manager limits how often)
                keys = await KeysAsync(refresh: true, ct);
                if (keys is not null) result = await _handler.ValidateTokenAsync(token, Parameters(keys));
            }
            if (!result.IsValid || result.SecurityToken is not JsonWebToken jwt) return (null, "the token is not valid: " + Reason(result.Exception));
            if (!IssuedWithinSession(jwt.IssuedAt, _now())) return (null, "the token was not issued within the sign-in session");
            if (!string.Equals(Claim(jwt, "tid"), _tenant, StringComparison.OrdinalIgnoreCase)) return (null, "the token is not of this tenant");
            var claims = jwt.Claims.ToList();
            if (string.Equals(Claim(jwt, "idtyp"), "app", StringComparison.OrdinalIgnoreCase)) return (null, "an application's token is not a signed-in person");
            if (accessToken && Claim(jwt, "scp") is null && (Claim(jwt, "azp") is not null || Claim(jwt, "appid") is not null))
                return (null, "an application's token is not a signed-in person");
            if (string.IsNullOrWhiteSpace(Claim(jwt, "oid"))) return (null, "the token carries no object id");
            return (new ClaimsIdentity(claims, BuiltInAuth.Scheme, "preferred_username", "roles"), "");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (null, "the token could not be checked: " + ex.GetType().Name);
        }
    }

    private TokenValidationParameters Parameters(IEnumerable<SecurityKey> keys) => new()
    {
        ValidateIssuer = true,
        ValidIssuers = new[] { $"https://login.microsoftonline.com/{_tenant}/v2.0", $"https://sts.windows.net/{_tenant}/" },
        ValidateAudience = true,
        ValidAudiences = new[] { _client!, "api://" + _client },
        ValidateIssuerSigningKey = true,
        IssuerSigningKeys = keys,
        RequireSignedTokens = true,
        // the session decides instead (IssuedWithinSession): the platform does not refresh the ID token within its 8 h
        ValidateLifetime = false,
        RequireExpirationTime = false,
        ValidateTokenReplay = false,
        TryAllIssuerSigningKeys = true,
    };

    private async Task<IReadOnlyList<SecurityKey>?> KeysAsync(bool refresh, CancellationToken ct)
    {
        if (_fixedKeys is not null) return _fixedKeys;
        if (_metadata is null) return null;
        try
        {
            if (refresh) _metadata.RequestRefresh();
            var cfg = await _metadata.GetConfigurationAsync(ct);
            return cfg.SigningKeys.ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    private static string? Claim(JsonWebToken jwt, string type) => jwt.Claims.FirstOrDefault(c => c.Type == type)?.Value;

    private static string Reason(Exception? ex) => ex switch
    {
        SecurityTokenInvalidAudienceException => "another app's audience",
        SecurityTokenInvalidIssuerException => "another issuer",
        SecurityTokenSignatureKeyNotFoundException or SecurityTokenInvalidSignatureException => "the signature is not the tenant's",
        SecurityTokenMalformedException => "not a token",
        null => "unknown",
        _ => ex.GetType().Name,
    };
}
