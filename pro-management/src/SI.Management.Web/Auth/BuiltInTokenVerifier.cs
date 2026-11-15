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
///   * it is within its lifetime, strictly (framework AUTH-MODERN-1): Microsoft's library checks exp and nbf with a
///     <see cref="ClockSkew"/> of five minutes -- an expired token is refused, however recently it was issued. The page keeps
///     the token fresh itself through the platform's /.auth/refresh (wwwroot/js/auth-refresh.js: before exp and once on a 401);
///   * it is a person's: an application's own token (idtyp = app, or an access token without a delegated scope that names a
///     calling application) is refused.
/// Never throws: the identity, or null with why.
/// </summary>
public sealed class BuiltInTokenVerifier
{
    /// The slack for the clocks of the platform, Entra and this app, on exp and nbf (Microsoft's default, stated here).
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    private readonly string? _tenant;
    private readonly string? _client;
    private readonly IConfigurationManager<OpenIdConnectConfiguration>? _metadata;
    private readonly IReadOnlyList<SecurityKey>? _fixedKeys;
    private readonly JsonWebTokenHandler _handler = new() { MapInboundClaims = false };

    /// The app: the keys from the tenant's OpenID configuration (AzureAd:TenantId / AzureAd:ClientId).
    public BuiltInTokenVerifier(IConfiguration configuration)
    {
        var ad = configuration.GetSection("AzureAd");
        _tenant = Guid.TryParse(ad["TenantId"], out var t) ? t.ToString() : null;
        _client = Guid.TryParse(ad["ClientId"], out var c) ? c.ToString() : null;
        if (_tenant is not null)
            _metadata = new ConfigurationManager<OpenIdConnectConfiguration>(
                $"https://login.microsoftonline.com/{_tenant}/v2.0/.well-known/openid-configuration",
                new OpenIdConnectConfigurationRetriever(), new HttpDocumentRetriever { RequireHttps = true });
    }

    /// Tests and the startup self-check (<see cref="WebAuthSelfCheck"/>): fixed signing keys.
    public BuiltInTokenVerifier(string? tenantId, string? clientId, IEnumerable<SecurityKey> keys)
    {
        _tenant = Guid.TryParse(tenantId, out var t) ? t.ToString() : null;
        _client = Guid.TryParse(clientId, out var c) ? c.ToString() : null;
        _fixedKeys = keys.ToList();
    }

    public string? TenantId => _tenant;

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
        // AUTH-MODERN-1: strict lifetime -- exp required and checked, nbf checked, five minutes of clock skew
        ValidateLifetime = true,
        RequireExpirationTime = true,
        ClockSkew = ClockSkew,
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
        SecurityTokenExpiredException => "the token has expired",
        SecurityTokenNotYetValidException => "the token is not valid yet",
        SecurityTokenNoExpirationException => "the token has no expiry",
        SecurityTokenInvalidAudienceException => "another app's audience",
        SecurityTokenInvalidIssuerException => "another issuer",
        SecurityTokenSignatureKeyNotFoundException or SecurityTokenInvalidSignatureException => "the signature is not the tenant's",
        SecurityTokenMalformedException => "not a token",
        null => "unknown",
        _ => ex.GetType().Name,
    };
}
