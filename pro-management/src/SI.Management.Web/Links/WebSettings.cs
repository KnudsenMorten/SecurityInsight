using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Links;

/// <summary>
/// The management web app's OWN settings: edited on the Settings pages like every other setting (same validator, same
/// review, same change log) but stored only at scope 'engine:management-web', which no engine reads -- so a value here
/// can never be refused at run start and stop a run. Read with a one-minute cache.
/// </summary>
public sealed class WebSettings
{
    public const string Group = "Web app (Pro): links + wall board";
    /// The Settings page area these sit in: links in mails and the wall board are about telling people.
    public const string SettingsArea = "Mail & notifications";
    public const string PublicBaseUrl = "SIWeb_PublicBaseUrl";
    public const string MagicLinksEnabled = "SIWeb_MagicLinksEnabled";
    public const string MagicLinkMinutes = "SIWeb_MagicLinkMinutes";
    public const string MagicLinkKeyVault = "SIWeb_MagicLinkKeyVault";
    public const string MagicLinkKeySecret = "SIWeb_MagicLinkKeySecret";
    public const string WallboardRefreshSeconds = "SIWeb_WallboardRefreshSeconds";

    private static JsonElement J(string json) { using var d = JsonDocument.Parse(json); return d.RootElement.Clone(); }

    private static CatalogSetting S(string name, string type, string label, string description, string? def, double? min = null, double? max = null,
        string? pattern = null, string? hint = null, bool secret = false, string? defaultText = null, string? effect = null, string? when = null, string? unit = null) => new()
    {
        Name = name, Label = label, Group = SettingsArea, Type = type, Engines = new[] { "management-web" }, Edition = "pro", Secret = secret,
        Default = def is null ? null : J(def), Description = description, Min = min, Max = max, Pattern = pattern, PatternHint = hint, WebOnly = true,
        DefaultText = defaultText, Effect = effect, WhenToChange = when, Unit = unit,
        // the Settings page card: the wall board has its own; the rest is about the links in mails
        Card = name == WallboardRefreshSeconds ? "Wall board" : "Links in e-mails", Needs = name is MagicLinkMinutes or MagicLinkKeyVault or MagicLinkKeySecret ? MagicLinksEnabled : null,
    };

    public static readonly IReadOnlyList<CatalogSetting> Catalog =
    [
        S(PublicBaseUrl, "text", "Public address of the web app",
            "The https address people open (e.g. https://ca-si-management.<region>.azurecontainerapps.io). E-mail deep links are built on it; sign-in is Entra SSO.",
            "\"\"", pattern: "^https://[A-Za-z0-9.\\-]+(:[0-9]{2,5})?/?$", hint: "https://host[:port]",
            defaultText: "Not set: e-mails carry no links into the web app",
            effect: "Once set, e-mails link straight to the page they describe. A wrong address gives every mail a broken link.",
            when: "Once, after the web app is deployed, or when its address changes."),
        S(MagicLinksEnabled, "bool", "Magic links in e-mails",
            "OFF by default. When on, an e-mail link may carry a signed, short-lived, single-use token that opens ONE read-only page without a sign-in. Conditional Access does not apply to such a link -- turn it on only if that is acceptable.",
            "false", defaultText: "Off: every link goes through the normal sign-in",
            effect: "On lets a mail link open one read-only page without signing in; Conditional Access does not see that link.",
            when: "Only if readers must open mailed pages without signing in, and that is acceptable to your security policy."),
        S(MagicLinkMinutes, "int", "Magic link lifetime", "How long a magic link stays valid (5 to 1440). It works once.", "60", 5, 1440,
            defaultText: "60 minutes", effect: "Longer is more convenient for readers and gives a forwarded link longer to be misused.",
            when: "Rarely; only when readers open mails long after they arrive.", unit: "minutes"),
        S(MagicLinkKeyVault, "text", "Key Vault holding the magic-link key", "The vault NAME (not a URL). The web app's identity needs 'Key Vault Secrets User' on it.",
            "\"\"", pattern: "^[A-Za-z][A-Za-z0-9\\-]{2,23}$", hint: "a Key Vault name, 3-24 letters, digits and dashes",
            defaultText: "Not set: magic links cannot be issued", effect: "Names where the signing key is read from; a vault the app cannot read stops magic links.",
            when: "Only when magic links are turned on."),
        S(MagicLinkKeySecret, "text", "Magic-link signing key (Key Vault secret)", "The Key Vault secret holding the HMAC key (at least 32 random bytes, base64). Stored as the secret NAME only.",
            null, secret: true, defaultText: "Not set: magic links cannot be issued",
            effect: "Changing the key makes every magic link already sent stop working.", when: "Only when magic links are turned on, or to rotate the key."),
        S(WallboardRefreshSeconds, "int", "Wall board refresh", "How often the big-screen page reloads (60 to 3600).", "300", 60, 3600,
            defaultText: "300 seconds (5 minutes)", effect: "Shorter shows changes sooner and reads the database more often.",
            when: "Rarely; the data itself changes only when a run completes.", unit: "seconds"),
    ];

    private readonly ISettingsStoreReader _reader;
    private readonly IMemoryCache _cache;
    private readonly ILogger<WebSettings> _log;

    public WebSettings(ISettingsStoreReader reader, IMemoryCache cache, ILogger<WebSettings> log) { _reader = reader; _cache = cache; _log = log; }

    public sealed record Values(string? PublicBaseUrl, bool MagicLinksEnabled, int MagicLinkMinutes, string? KeyVault, string? KeySecretName, int WallboardRefreshSeconds);

    public async Task<Values> ReadAsync(CancellationToken ct)
    {
        if (_cache.TryGetValue("si-web-settings", out Values? hit) && hit is not null) return hit;
        IReadOnlyList<SettingRow> rows;
        try { rows = (await _reader.ReadSettingsAsync(ct)).Rows.Where(r => r.Scope == CatalogSetting.WebScope).ToList(); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // fail CLOSED: magic links off when the settings cannot be read
            _log.LogWarning(ex, "web settings could not be read -- magic links stay off");
            return new Values(null, false, 60, null, null, 300);
        }
        string? Str(string n) => rows.FirstOrDefault(r => r.Name == n) is { ValueJson: { } j } ? Parse(j) : null;
        string? Kv(string n) => rows.FirstOrDefault(r => r.Name == n)?.KeyVaultSecretName;
        int Int(string n, int def, int min, int max) => int.TryParse(Str(n), out var v) && v >= min && v <= max ? v : def;
        var v = new Values(
            string.IsNullOrWhiteSpace(Str(PublicBaseUrl)) ? null : Str(PublicBaseUrl)!.TrimEnd('/'),
            string.Equals(Str(MagicLinksEnabled), "true", StringComparison.OrdinalIgnoreCase),
            Int(MagicLinkMinutes, 60, 5, 1440), Str(MagicLinkKeyVault), Kv(MagicLinkKeySecret), Int(WallboardRefreshSeconds, 300, 60, 3600));
        _cache.Set("si-web-settings", v, TimeSpan.FromMinutes(1));
        return v;
    }

    private static string? Parse(string json)
    {
        try
        {
            using var d = JsonDocument.Parse(json);
            return d.RootElement.ValueKind switch
            {
                JsonValueKind.String => d.RootElement.GetString(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Null => null,
                _ => d.RootElement.GetRawText(),
            };
        }
        catch (JsonException) { return null; }
    }
}
