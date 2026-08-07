using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SIAnalyzer.Web.Auth;

/// <summary>
/// The authenticated principal Azure Easy Auth (Entra) injects into every proxied request
/// via the base64-encoded JSON <c>X-MS-CLIENT-PRINCIPAL</c> header. Easy Auth terminates the
/// sign-in at the platform layer in FRONT of the container; the app then trusts + parses this
/// header to know WHO is calling (and, for /mcp, to gate the tool surface behind the same
/// authenticated principal as the UI). A hosted analyzer of security findings is never
/// anonymous.
///
/// Header shape (base64 of UTF-8 JSON):
///   { "auth_typ": "aad", "name_typ": "...", "role_typ": "...",
///     "claims": [ { "typ": "...", "val": "..." }, ... ] }
/// </summary>
public sealed class ClientPrincipal
{
    /// <summary>The header Easy Auth injects with the encoded principal.</summary>
    public const string HeaderName = "X-MS-CLIENT-PRINCIPAL";

    /// <summary>The identity provider that authenticated the principal (e.g. "aad").</summary>
    [JsonPropertyName("auth_typ")]
    public string? AuthenticationType { get; set; }

    /// <summary>The claim type that holds the principal's display name.</summary>
    [JsonPropertyName("name_typ")]
    public string? NameClaimType { get; set; }

    /// <summary>The claim type that holds the principal's roles.</summary>
    [JsonPropertyName("role_typ")]
    public string? RoleClaimType { get; set; }

    [JsonPropertyName("claims")]
    public List<ClientPrincipalClaim> Claims { get; set; } = new();

    /// <summary>True when this looks like a real, authenticated principal (has an auth type
    /// and at least one claim). An empty/garbage header is treated as NOT authenticated.</summary>
    [JsonIgnore]
    public bool IsAuthenticated =>
        !string.IsNullOrWhiteSpace(AuthenticationType) && Claims.Count > 0;

    /// <summary>The principal's display name, resolved from the declared name claim type
    /// (falling back to the common AAD name/upn/email claims).</summary>
    [JsonIgnore]
    public string? Name => FindClaim(NameClaimType)
        ?? FindClaim("name")
        ?? FindClaim("preferred_username")
        ?? FindClaim("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
        ?? FindClaim("upn")
        ?? FindClaim("emails");

    private string? FindClaim(string? type)
    {
        if (string.IsNullOrEmpty(type)) return null;
        foreach (var c in Claims)
        {
            if (string.Equals(c.Type, type, StringComparison.OrdinalIgnoreCase))
                return c.Value;
        }
        return null;
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>
    /// Parse the base64-encoded JSON <c>X-MS-CLIENT-PRINCIPAL</c> header value into a
    /// <see cref="ClientPrincipal"/>. Returns null for a missing, empty or unparseable
    /// header (i.e. NOT authenticated) - it never throws, so a malformed header simply
    /// reads as anonymous rather than crashing the request.
    /// </summary>
    public static ClientPrincipal? FromHeaderValue(string? headerValue)
    {
        if (string.IsNullOrWhiteSpace(headerValue)) return null;
        try
        {
            var bytes = Convert.FromBase64String(headerValue.Trim());
            var json = Encoding.UTF8.GetString(bytes);
            var principal = JsonSerializer.Deserialize<ClientPrincipal>(json, JsonOpts);
            return principal?.IsAuthenticated == true ? principal : null;
        }
        catch
        {
            return null;
        }
    }
}

/// <summary>One claim from the Easy Auth client-principal header.</summary>
public sealed class ClientPrincipalClaim
{
    [JsonPropertyName("typ")]
    public string? Type { get; set; }

    [JsonPropertyName("val")]
    public string? Value { get; set; }
}
