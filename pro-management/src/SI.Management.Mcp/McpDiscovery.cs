using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace SI.Management.Mcp;

/// The RFC 9728 OAuth protected-resource metadata document: ONLY these four members (no data, no version, no estate).
public sealed record McpResourceMetadataDocument(
    [property: JsonPropertyName("resource")] string Resource,
    [property: JsonPropertyName("authorization_servers")] string[] AuthorizationServers,
    [property: JsonPropertyName("scopes_supported")] string[] ScopesSupported,
    [property: JsonPropertyName("bearer_methods_supported")] string[] BearerMethodsSupported);

/// <summary>
/// MCP DISCOVERY (framework SECURE-WEB-1 (3), RFC 9728): a NEW MCP client learns from this server where to sign in. The
/// platform's 401 in front of /mcp carries no resource_metadata, so a spec-strict client reads
/// /.well-known/oauth-protected-resource/mcp (or the root form) -- answered here WITHOUT a sign-in, the ONE named anonymous
/// MCP path besides /healthz: it says only which resource this is, which authorization server signs for it, the scope
/// (api://&lt;client id&gt;/mcp.access) and that the token goes in the Authorization header. No data, no version, no estate.
/// The server's own 401s on /mcp name the document in WWW-Authenticate (<see cref="Challenge"/>).
/// <para>THE PUBLIC ADDRESS: "Mcp:PublicBaseUrl" when configured (an absolute https URL, its scheme + host only); else the
/// request's Host (the platform's ingress keeps the client's Host) checked to be a plain host name. X-Forwarded-Host is a
/// header any client can set and is NEVER used; X-Forwarded-Proto only says "https". A host other than this machine is
/// always named https (the platform serves https only); plain http only for localhost (a local run, the tests).</para>
/// PURE apart from reading the request it is handed.
/// </summary>
public sealed class McpDiscovery
{
    public const string WellKnownPath = "/.well-known/oauth-protected-resource";
    public const string McpPath = "/mcp";
    public const string ScopeName = "mcp.access";

    private static readonly Regex HostRx = new(@"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?(?::[0-9]{1,5})?$", RegexOptions.CultureInvariant);

    public string TenantId { get; }
    public string ClientId { get; }
    public string? ConfiguredBase { get; }

    public McpDiscovery(string? tenantId, string? clientId, string? publicBaseUrl)
    {
        TenantId = Guid.TryParse(tenantId?.Trim(), out var t) ? t.ToString("D") : "";
        ClientId = Guid.TryParse(clientId?.Trim(), out var c) ? c.ToString("D") : "";
        ConfiguredBase = NormaliseConfiguredBase(publicBaseUrl);
    }

    public static McpDiscovery FromConfiguration(IConfiguration cfg) =>
        new(cfg["AzureAd:TenantId"], cfg["AzureAd:ClientId"], cfg["Mcp:PublicBaseUrl"]);

    /// Both ids known: the document can be answered.
    public bool Configured => TenantId.Length > 0 && ClientId.Length > 0;

    /// An absolute https URL -> "https://host[:port]"; anything else (http, a path, a query, garbage) -> null (not used).
    public static string? NormaliseConfiguredBase(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (!Uri.TryCreate(value.Trim(), UriKind.Absolute, out var u)) return null;
        if (!string.Equals(u.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) return null;
        if (u.AbsolutePath.Trim('/').Length > 0 || u.Query.Length > 0 || u.Fragment.Length > 0 || u.UserInfo.Length > 0) return null;
        return "https://" + u.Authority.ToLowerInvariant();
    }

    public static bool IsLoopback(string host)
    {
        var h = host.Split(':')[0];
        return string.Equals(h, "localhost", StringComparison.OrdinalIgnoreCase) || h == "127.0.0.1";
    }

    /// The server's public base ("https://host"), or null when the request names no usable host.
    public string? PublicBase(HttpRequest request)
    {
        if (ConfiguredBase is not null) return ConfiguredBase;
        var host = request.Host.HasValue ? request.Host.Value! : "";
        if (host.Length == 0 || !HostRx.IsMatch(host)) return null;
        host = host.ToLowerInvariant();
        var proto = request.Headers["X-Forwarded-Proto"].ToString().Split(',')[0].Trim();
        var https = request.IsHttps || string.Equals(proto, "https", StringComparison.OrdinalIgnoreCase) || !IsLoopback(host);
        return (https ? "https://" : "http://") + host;
    }

    public static string ResourceFor(string publicBase) => publicBase + McpPath;

    /// RFC 9728 section 3.1: the well-known path inserted before the resource's path (/mcp).
    public static string MetadataUrlFor(string publicBase) => publicBase + WellKnownPath + McpPath;

    public string Scope => $"api://{ClientId}/{ScopeName}";

    public string AuthorizationServer => $"https://login.microsoftonline.com/{TenantId}/v2.0";

    public McpResourceMetadataDocument Document(string publicBase) =>
        new(ResourceFor(publicBase), [AuthorizationServer], [Scope], ["header"]);

    /// The paths answered: the root form, and the form for the resource /mcp. Anything else under the well-known path = 404.
    public static bool IsAnsweredRest(string? rest) =>
        string.IsNullOrEmpty(rest) || string.Equals(rest.Trim('/'), McpPath.Trim('/'), StringComparison.OrdinalIgnoreCase);

    /// The WWW-Authenticate value of this server's own 401: Bearer resource_metadata="..." (+ error="invalid_token" when a
    /// token was sent and refused; never the reason).
    public static string Challenge(string metadataUrl, bool invalidToken) =>
        $"Bearer resource_metadata=\"{metadataUrl}\"" + (invalidToken ? ", error=\"invalid_token\"" : "");

    /// The endpoint: GET /.well-known/oauth-protected-resource[/mcp].
    public IResult Answer(HttpContext ctx, string? rest)
    {
        if (!IsAnsweredRest(rest) || !Configured) return Results.NotFound();
        var b = PublicBase(ctx.Request);
        if (b is null) return Results.BadRequest();
        ctx.Response.Headers.CacheControl = "no-store";
        return Results.Json(Document(b));
    }

    /// JwtBearer's OnChallenge: the 401 names the metadata document. Not configured / no usable host = the default challenge.
    public Task OnChallenge(JwtBearerChallengeContext ctx)
    {
        if (!Configured) return Task.CompletedTask;
        var b = PublicBase(ctx.Request);
        if (b is null) return Task.CompletedTask;
        ctx.HandleResponse();
        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        ctx.Response.Headers.WWWAuthenticate = Challenge(MetadataUrlFor(b), ctx.AuthenticateFailure is not null);
        return Task.CompletedTask;
    }
}
