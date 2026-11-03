namespace SigninFront;

/// <summary>
/// Every setting of the front, read ONCE at start from environment variables (README "Settings").
/// Invalid or missing values stop the container at start -- a front that cannot be configured correctly must never
/// come up half-configured. There is deliberately NO setting for a client secret or a certificate: the only client
/// credential is the federated credential of the web app's user-assigned managed identity.
/// </summary>
public sealed class FrontSettings
{
    public const string TokenExchangeAudience = "api://AzureADTokenExchange";
    public const string Instance = "https://login.microsoftonline.com/";

    public required string TenantId { get; init; }
    public required string ClientId { get; init; }
    public required string FicManagedIdentityClientId { get; init; }
    public required int UpstreamPort { get; init; }
    public required int SessionHours { get; init; }
    public required IReadOnlyList<string> BearerPaths { get; init; }
    public required IReadOnlyList<string> BearerAudiences { get; init; }
    /// <summary>SIGNIN_ANONYMOUS_PATHS: open paths (no session, no Authorization forwarded). Empty by default.</summary>
    public IReadOnlyList<string> AnonymousPaths { get; init; } = Array.Empty<string>();
    public required string RefreshScope { get; init; }
    /// <summary>1.3.0: the product's SQL server (FQDN) and database that hold the front's state (sessions, token cache, keys).</summary>
    public required string SqlServer { get; init; }
    public required string SqlDatabase { get; init; }
    /// <summary>1.3.0: the Key Vault key that wraps the Data Protection keys (https://&lt;vault&gt;/keys/&lt;name&gt;[/&lt;version&gt;]).</summary>
    public required string KeyVaultKeyId { get; init; }
    /// <summary>1.3.0: the managed identity (client id) that signs in to SQL and Key Vault; default = SIGNIN_FIC_MI_CLIENT_ID.</summary>
    public required string StateManagedIdentityClientId { get; init; }
    /// <summary>
    /// 1.4.0: SIGNIN_UPSTREAM_SCOPE -- the app's OWN delegated API scope (api://&lt;client id&gt;/&lt;name&gt;). Set: the front
    /// forwards an ACCESS token for it (OIDC / Microsoft guidance: an ID token is not an API credential). Empty: the ID token,
    /// as before 1.4.0 (deprecated).
    /// </summary>
    public string UpstreamScope { get; init; } = "";
    public bool ForwardsAccessToken => UpstreamScope.Length > 0;
    /// <summary>The scope requested at sign-in and refreshed silently: the upstream scope in access mode, else the refresh scope.</summary>
    public string TokenScope => ForwardsAccessToken ? UpstreamScope : RefreshScope;

    public TimeSpan Session => TimeSpan.FromHours(SessionHours);
    public string Authority => $"{Instance}{TenantId}/v2.0";
    public IReadOnlyList<string> ValidIssuers => new[] { $"{Instance}{TenantId}/v2.0", $"https://sts.windows.net/{TenantId}/" };

    /// <summary>The app container: ALWAYS loopback. There is no setting for the host, by design.</summary>
    public string UpstreamPrefix => $"http://127.0.0.1:{UpstreamPort}";

    // Names that would carry a secret. Present = refuse to start: "no secret" is a property of the component, not a
    // convention a deployment can break.
    private static readonly string[] ForbiddenSecretKeys =
    {
        "SIGNIN_CLIENT_SECRET", "SIGNIN_CLIENT_CERTIFICATE", "AzureAd:ClientSecret", "AzureAd:ClientCertificates",
        "AzureAd:ClientCredentials",
    };

    private static readonly string[] ReservedPaths = { "/", "/healthz", "/signout", "/signin-oidc", "/signout-callback-oidc" };

    public static FrontSettings Load(IConfiguration c)
    {
        foreach (var k in ForbiddenSecretKeys)
        {
            if (!string.IsNullOrWhiteSpace(c[k]) || c.GetSection(k).GetChildren().Any())
                throw new InvalidOperationException($"signin-front: '{k}' is set -- this component never uses a client secret or certificate (the client credential is the managed identity's federated credential). Remove it.");
        }

        var tenant = RequireGuid(c, "SIGNIN_TENANT_ID");
        var client = RequireGuid(c, "SIGNIN_CLIENT_ID");
        var mi = RequireGuid(c, "SIGNIN_FIC_MI_CLIENT_ID");

        var portRaw = (c["SIGNIN_UPSTREAM_PORT"] ?? "").Trim();
        if (!int.TryParse(portRaw, out var port) || port < 1 || port > 65535)
            throw new InvalidOperationException("signin-front: SIGNIN_UPSTREAM_PORT must be the app container's loopback port (1-65535).");
        var listen = ListenPort(c);
        if (port == listen)
            throw new InvalidOperationException($"signin-front: SIGNIN_UPSTREAM_PORT ({port}) is the front's own port -- the containers of one revision share the network; pick another port for the app.");

        var hoursRaw = (c["SIGNIN_SESSION_HOURS"] ?? "").Trim();
        var hours = 8;
        if (hoursRaw.Length > 0 && (!int.TryParse(hoursRaw, out hours) || hours < 1 || hours > 24))
            throw new InvalidOperationException("signin-front: SIGNIN_SESSION_HOURS must be a whole number of hours, 1-24 (default 8).");

        var pathsRaw = c["SIGNIN_BEARER_PATHS"];
        var paths = Split(string.IsNullOrWhiteSpace(pathsRaw) ? "/mcp,/.well-known" : pathsRaw);
        foreach (var p in paths)
        {
            if (!p.StartsWith('/') || p.EndsWith('/') || p.Contains('*') || p.Contains('?') || p.Contains('{') || p.Contains(' '))
                throw new InvalidOperationException($"signin-front: SIGNIN_BEARER_PATHS entry '{p}' must be a plain path prefix like /mcp (leading '/', no trailing '/', no wildcard).");
            if (ReservedPaths.Contains(p, StringComparer.OrdinalIgnoreCase))
                throw new InvalidOperationException($"signin-front: SIGNIN_BEARER_PATHS may not contain '{p}' -- that would take it out of the sign-in.");
        }

        var audRaw = c["SIGNIN_BEARER_AUDIENCES"];
        var auds = string.IsNullOrWhiteSpace(audRaw) ? new List<string> { client, $"api://{client}" } : Split(audRaw);

        var scope = (c["SIGNIN_REFRESH_SCOPE"] ?? "").Trim();
        if (scope.Length == 0) scope = "User.Read";

        var open = ParseAnonymousPaths(c["SIGNIN_ANONYMOUS_PATHS"], paths);

        // 1.3.0: the state store is REQUIRED -- no in-memory fallback (framework §12.11g item 9): a front that would lose every
        // session and every pending sign-in at its next restart must not start.
        var sqlServer = (c["SIGNIN_SQL_SERVER"] ?? "").Trim();
        if (!HostName.IsMatch(sqlServer))
            throw new InvalidOperationException("signin-front: SIGNIN_SQL_SERVER must be the product's SQL server host name (e.g. sql-x.database.windows.net) -- 1.3.0 keeps sessions, the token cache and the keys there.");
        var sqlDb = (c["SIGNIN_SQL_DATABASE"] ?? "").Trim();
        if (!DbName.IsMatch(sqlDb))
            throw new InvalidOperationException("signin-front: SIGNIN_SQL_DATABASE must be the product's database name (letters, digits, '-', '_').");
        var kvKey = (c["SIGNIN_KEYVAULT_KEY_ID"] ?? "").Trim();
        if (!Uri.TryCreate(kvKey, UriKind.Absolute, out var kvUri) || kvUri.Scheme != Uri.UriSchemeHttps || !kvUri.AbsolutePath.StartsWith("/keys/", StringComparison.OrdinalIgnoreCase) || kvUri.AbsolutePath.Length <= "/keys/".Length || kvUri.Query.Length > 0)
            throw new InvalidOperationException("signin-front: SIGNIN_KEYVAULT_KEY_ID must be a Key Vault key id, https://<vault>/keys/<name>[/<version>] -- it wraps the Data Protection keys.");
        var stateMiRaw = (c["SIGNIN_STATE_MI_CLIENT_ID"] ?? "").Trim();
        var stateMi = mi;
        if (stateMiRaw.Length > 0)
        {
            if (!Guid.TryParse(stateMiRaw, out var g)) throw new InvalidOperationException("signin-front: SIGNIN_STATE_MI_CLIENT_ID must be a GUID (or unset = SIGNIN_FIC_MI_CLIENT_ID).");
            stateMi = g.ToString("D");
        }

        // 1.4.0: only the app's OWN API (api://<this client id>/<name>) -- the front never forwards a token for another resource
        var upstreamScope = (c["SIGNIN_UPSTREAM_SCOPE"] ?? "").Trim();
        if (upstreamScope.Length > 0)
        {
            var m = UpstreamScopeRx.Match(upstreamScope);
            if (!m.Success || !Guid.TryParse(m.Groups[1].Value, out var sg) || sg.ToString("D") != client)
                throw new InvalidOperationException($"signin-front: SIGNIN_UPSTREAM_SCOPE must be this app's own delegated scope, api://{client}/<name> (e.g. api://{client}/user_impersonation).");
            upstreamScope = $"api://{client}/{m.Groups[2].Value}";
        }

        return new FrontSettings
        {
            TenantId = tenant, ClientId = client, FicManagedIdentityClientId = mi, UpstreamPort = port, SessionHours = hours,
            BearerPaths = paths, BearerAudiences = auds, RefreshScope = scope, AnonymousPaths = open,
            SqlServer = sqlServer, SqlDatabase = sqlDb, KeyVaultKeyId = kvKey, StateManagedIdentityClientId = stateMi,
            UpstreamScope = upstreamScope,
        };
    }

    private static readonly System.Text.RegularExpressions.Regex UpstreamScopeRx = new(@"^api://([0-9A-Fa-f-]{36})/([A-Za-z0-9_.-]{1,100})$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    private static readonly System.Text.RegularExpressions.Regex HostName = new(@"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$");
    private static readonly System.Text.RegularExpressions.Regex DbName = new(@"^[A-Za-z0-9_-]{1,128}$");

    private static readonly string[] FrontOwnedPaths = { "/signout", "/signin-oidc", "/signout-callback-oidc", "/healthz" };

    /// <summary>
    /// SIGNIN_ANONYMOUS_PATHS (1.1.0): comma-separated, whitespace around entries ignored, empty / unset = none. Each entry
    /// starts with '/', one trailing '/' is trimmed, and it may not be '/' alone, contain '*', '?', '..', '{' or '}', or
    /// equal or lie under a path the front owns (/signout, /signin-oidc, /signout-callback-oidc, /healthz) or a bearer path.
    /// Any invalid entry stops the container at start.
    /// </summary>
    public static List<string> ParseAnonymousPaths(string? raw, IReadOnlyList<string> bearerPaths)
    {
        var list = new List<string>();
        if (string.IsNullOrWhiteSpace(raw)) return list;
        foreach (var part in raw.Split(','))
        {
            var p = part.Trim();
            if (p.Length == 0) throw new InvalidOperationException("signin-front: SIGNIN_ANONYMOUS_PATHS has an empty entry.");
            if (!p.StartsWith('/')) throw new InvalidOperationException($"signin-front: SIGNIN_ANONYMOUS_PATHS entry '{p}' must start with '/'.");
            if (p.Length > 1 && p.EndsWith('/')) p = p.Substring(0, p.Length - 1);
            if (p == "/" || p.Length == 0 || p.EndsWith('/'))
                throw new InvalidOperationException($"signin-front: SIGNIN_ANONYMOUS_PATHS entry '{part.Trim()}' would open the whole app (or is malformed) -- refused.");
            if (p.Contains('*') || p.Contains('?') || p.Contains("..") || p.Contains('{') || p.Contains('}') || p.Any(char.IsWhiteSpace))
                throw new InvalidOperationException($"signin-front: SIGNIN_ANONYMOUS_PATHS entry '{p}' may not contain '*', '?', '..', braces or spaces.");
            foreach (var owned in FrontOwnedPaths.Concat(bearerPaths))
                if (PathMatches(p, owned))
                    throw new InvalidOperationException($"signin-front: SIGNIN_ANONYMOUS_PATHS entry '{p}' equals or lies under '{owned}' -- refused.");
            if (!list.Contains(p, StringComparer.OrdinalIgnoreCase)) list.Add(p);
        }
        return list;
    }

    /// <summary>Case-insensitive: the path IS the prefix, or starts with prefix + '/'. "/link" matches /link, /link/x -- never /linkx.</summary>
    public static bool PathMatches(string path, string prefix) =>
        path.Equals(prefix, StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase);

    public static int ListenPort(IConfiguration c)
    {
        var raw = (c["ASPNETCORE_HTTP_PORTS"] ?? "").Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
        return int.TryParse(raw, out var p) ? p : 8080;
    }

    private static string RequireGuid(IConfiguration c, string key)
    {
        var v = (c[key] ?? "").Trim();
        if (!Guid.TryParse(v, out var g))
            throw new InvalidOperationException($"signin-front: {key} must be set to a GUID.");
        return g.ToString("D");
    }

    private static List<string> Split(string raw) =>
        raw.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
}
