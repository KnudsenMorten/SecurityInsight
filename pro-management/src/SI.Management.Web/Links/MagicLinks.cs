using System.Globalization;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Azure.Core;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Data;

namespace SI.Management.Web.Links;

/// <summary>
/// Links into the web app for e-mails. A DEEP link is a plain https URL: opening it goes through Entra sign-in (SSO,
/// Conditional Access applies) and the page's own role check. A MAGIC link (OFF by default, setting
/// SIWeb_MagicLinksEnabled) additionally carries a token: signed (HMAC-SHA256, key from Key Vault), short-lived,
/// single-use (the nonce is recorded on redemption), and scoped to ONE read-only page.
/// </summary>
public sealed class DeepLinks
{
    /// The pages an e-mail may link to with a magic link: read-only views only.
    public static readonly IReadOnlyList<string> MagicPages = ["/Wallboard", "/Management/Closure", "/Management/Trends", "/Findings", "/Findings/Detail"];

    private readonly WebSettings _settings;
    private readonly MagicLinkService _magic;
    public DeepLinks(WebSettings settings, MagicLinkService magic) { _settings = settings; _magic = magic; }

    /// The https URL of a page (+ query). Null when SIWeb_PublicBaseUrl is not set.
    public static string? Build(string? baseUrl, string page, IReadOnlyDictionary<string, string?>? query = null)
    {
        if (string.IsNullOrWhiteSpace(baseUrl)) return null;
        if (!page.StartsWith('/') || page.Contains("//", StringComparison.Ordinal) || page.Contains("..", StringComparison.Ordinal)) throw new ArgumentException("page must be an app-relative path");
        var qs = query is null ? "" : string.Join("&", query.Where(kv => !string.IsNullOrEmpty(kv.Value)).Select(kv => Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(kv.Value!)));
        return baseUrl.TrimEnd('/') + page + (qs.Length > 0 ? "?" + qs : "");
    }

    public async Task<string?> DeepAsync(string page, IReadOnlyDictionary<string, string?>? query, CancellationToken ct) =>
        Build((await _settings.ReadAsync(ct)).PublicBaseUrl, page, query);

    /// A magic link when they are enabled and the page is allowed; otherwise the plain deep link.
    public async Task<string?> ForMailAsync(string page, IReadOnlyDictionary<string, string?>? query, CancellationToken ct)
    {
        var s = await _settings.ReadAsync(ct);
        var deep = Build(s.PublicBaseUrl, page, query);
        if (deep is null || !s.MagicLinksEnabled || !MagicPages.Contains(page, StringComparer.OrdinalIgnoreCase)) return deep;
        var token = await _magic.IssueAsync(page, deep[(s.PublicBaseUrl!.Length + page.Length)..].TrimStart('?'), ct);
        return token is null ? deep : Build(s.PublicBaseUrl, "/MagicLink", new Dictionary<string, string?> { ["t"] = token });
    }
}

public sealed record MagicToken(string Page, string Query, string Nonce, DateTimeOffset Expires);

/// The token format, pure: base64url(JSON {p,q,n,e}) "." base64url(HMAC-SHA256(key, first part)).
public static partial class MagicTokenCodec
{
    public const int MaxLifetimeMinutes = 1440;

    [GeneratedRegex(@"^[A-Za-z0-9_\-]{16,64}$", RegexOptions.CultureInvariant)] private static partial Regex Nonce();
    [GeneratedRegex(@"^[A-Za-z0-9_\-%.=&+]{0,400}$", RegexOptions.CultureInvariant)] private static partial Regex QueryText();

    public static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static byte[] UnB64(string s)
    {
        var t = s.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(t.PadRight(t.Length + (4 - t.Length % 4) % 4, '='));
    }

    public static string NewNonce() => B64(RandomNumberGenerator.GetBytes(16));

    public static string Issue(byte[] key, MagicToken t)
    {
        if (key.Length < 32) throw new InvalidOperationException("the magic-link key must be at least 32 bytes");
        var payload = B64(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { p = t.Page, q = t.Query, n = t.Nonce, e = t.Expires.ToUnixTimeSeconds() })));
        return payload + "." + B64(HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(payload)));
    }

    /// The token's content when it is genuine, unexpired and for an allowed page; otherwise null and why.
    public static (MagicToken? Token, string? Why) Validate(byte[] key, string? token, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 2048) return (null, "no token");
        var parts = token.Split('.');
        if (parts.Length != 2) return (null, "malformed");
        byte[] sig;
        try { sig = UnB64(parts[1]); } catch (FormatException) { return (null, "malformed"); }
        var expect = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(parts[0]));
        if (!CryptographicOperations.FixedTimeEquals(sig, expect)) return (null, "signature");
        try
        {
            var o = JsonNode.Parse(Encoding.UTF8.GetString(UnB64(parts[0]))) as JsonObject;
            var page = (string?)o?["p"]; var q = (string?)o?["q"] ?? ""; var n = (string?)o?["n"]; var e = (long?)o?["e"];
            if (page is null || n is null || e is null) return (null, "malformed");
            var exp = DateTimeOffset.FromUnixTimeSeconds(e.Value);
            if (exp <= now) return (null, "expired");
            if (exp > now.AddMinutes(MaxLifetimeMinutes + 1)) return (null, "lifetime");
            if (!DeepLinks.MagicPages.Contains(page, StringComparer.Ordinal)) return (null, "page");
            if (!Nonce().IsMatch(n) || !QueryText().IsMatch(q)) return (null, "malformed");
            return (new MagicToken(page, q, n, exp), null);
        }
        catch (Exception ex) when (ex is JsonException or FormatException or InvalidOperationException) { return (null, "malformed"); }
    }
}

/// Used nonces: a magic link works once.
public interface INonceStore
{
    /// True the FIRST time a nonce is used, false every time after.
    Task<bool> TryUseAsync(string nonce, string page, CancellationToken ct);
}

/// <summary>
/// The used nonces live in cfg.ChangeLog (Name 'magiclink/&lt;nonce&gt;', Scope 'magic-link', Kind 'magiclink') -- an
/// append-only table that also makes every redemption auditable. Check-and-insert is one transaction under
/// UPDLOCK/HOLDLOCK, so two simultaneous redemptions cannot both succeed.
/// </summary>
public sealed class ChangeLogNonceStore : INonceStore
{
    public const string UseSql = """
SET XACT_ABORT ON;
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.ChangeLog WITH (UPDLOCK, HOLDLOCK) WHERE Name = @Name AND Scope = N'magic-link')
BEGIN
    COMMIT;
    SELECT N'Used' AS Outcome;
    RETURN;
END;
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (@Name, N'magic-link', N'magiclink', N'Set', NULL, @Page, N'magic link', N'magic link redeemed');
COMMIT;
SELECT N'Fresh' AS Outcome;
""";

    private readonly ISqlExecutor _sql;
    public ChangeLogNonceStore(ISqlExecutor sql) => _sql = sql;

    public async Task<bool> TryUseAsync(string nonce, string page, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(UseSql, new Dictionary<string, object?> { ["Name"] = "magiclink/" + nonce, ["Page"] = page }, ct);
        return rows.Count > 0 && rows[0].Str("Outcome") == "Fresh";
    }
}

public interface IKeyVaultSecretReader
{
    Task<string> GetAsync(string vault, string secret, CancellationToken ct);
}

/// One Key Vault secret over REST with the process's credential (no SDK). Cached ten minutes.
public sealed class KeyVaultSecretReader : IKeyVaultSecretReader
{
    private static readonly string[] Scopes = ["https://vault.azure.net/.default"];
    private readonly HttpClient _http;
    private readonly TokenCredential _cred;
    private readonly IMemoryCache _cache;
    public KeyVaultSecretReader(HttpClient http, TokenCredential cred, IMemoryCache cache) { _http = http; _cred = cred; _cache = cache; }

    public async Task<string> GetAsync(string vault, string secret, CancellationToken ct)
    {
        if (!Regex.IsMatch(vault, "^[A-Za-z][A-Za-z0-9-]{2,23}$") || !Regex.IsMatch(secret, "^[0-9A-Za-z-]{1,127}$")) throw new ArgumentException("not a Key Vault / secret name");
        var key = "kv:" + vault + "/" + secret;
        if (_cache.TryGetValue(key, out string? hit) && hit is not null) return hit;
        var token = await _cred.GetTokenAsync(new TokenRequestContext(Scopes), ct);
        using var req = new HttpRequestMessage(HttpMethod.Get, $"https://{vault}.vault.azure.net/secrets/{secret}?api-version=7.4");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Token);
        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode) throw new InvalidOperationException($"Key Vault returned {(int)resp.StatusCode} for the magic-link key");
        var value = (string?)JsonNode.Parse(await resp.Content.ReadAsStringAsync(ct))?["value"] ?? throw new InvalidOperationException("the Key Vault secret has no value");
        _cache.Set(key, value, TimeSpan.FromMinutes(10));
        return value;
    }
}

/// Issues and redeems magic links -- only while SIWeb_MagicLinksEnabled is on and the key is configured.
public sealed class MagicLinkService
{
    private readonly WebSettings _settings;
    private readonly IKeyVaultSecretReader _kv;
    private readonly INonceStore _nonces;
    private readonly TimeProvider _clock;
    private readonly ILogger<MagicLinkService> _log;

    public MagicLinkService(WebSettings settings, IKeyVaultSecretReader kv, INonceStore nonces, ILogger<MagicLinkService> log, TimeProvider? clock = null)
    { _settings = settings; _kv = kv; _nonces = nonces; _log = log; _clock = clock ?? TimeProvider.System; }

    private async Task<(byte[]? Key, WebSettings.Values S)> KeyAsync(CancellationToken ct)
    {
        var s = await _settings.ReadAsync(ct);
        if (!s.MagicLinksEnabled || string.IsNullOrWhiteSpace(s.KeyVault) || string.IsNullOrWhiteSpace(s.KeySecretName)) return (null, s);
        var text = await _kv.GetAsync(s.KeyVault, s.KeySecretName, ct);
        byte[] key;
        try { key = Convert.FromBase64String(text.Trim()); } catch (FormatException) { key = Encoding.UTF8.GetBytes(text); }
        if (key.Length < 32) { _log.LogError("the magic-link key is shorter than 32 bytes -- magic links stay off"); return (null, s); }
        return (key, s);
    }

    public async Task<bool> IsEnabledAsync(CancellationToken ct) => (await _settings.ReadAsync(ct)).MagicLinksEnabled;

    public async Task<string?> IssueAsync(string page, string query, CancellationToken ct)
    {
        var (key, s) = await KeyAsync(ct);
        if (key is null) return null;
        return MagicTokenCodec.Issue(key, new MagicToken(page, query, MagicTokenCodec.NewNonce(), _clock.GetUtcNow().AddMinutes(s.MagicLinkMinutes)));
    }

    /// The page to open, or why not. Disabled = (null, "disabled"): the redeemer answers 404, as if the route did not exist.
    public async Task<(MagicToken? Token, string? Why)> RedeemAsync(string? token, CancellationToken ct)
    {
        var (key, s) = await KeyAsync(ct);
        if (!s.MagicLinksEnabled) return (null, "disabled");
        if (key is null) return (null, "not configured");
        var (t, why) = MagicTokenCodec.Validate(key, token, _clock.GetUtcNow());
        if (t is null) return (null, why);
        if (!await _nonces.TryUseAsync(t.Nonce, t.Page, ct)) return (null, "used");
        return (t, null);
    }
}
