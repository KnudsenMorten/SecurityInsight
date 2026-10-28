using System.Text.Json;
using System.Text.Json.Nodes;

namespace SI.Management.Web.Outputs;

/// <summary>
/// #903 HOW A SERVICENOW CONNECTOR SIGNS IN (PURE): an API key (the secret reference 'apikey', sent as x-sn-apikey) OR a user
/// and a password ('user' + 'password', Basic over https). A customer's ServiceNow admin stored a PASSWORD under 'apikey' --
/// SecurityInsight sent it as an API key and ServiceNow answered 401 every day. So the page offers both ways, plainly, each
/// with its Set value box, and a wrong combination is said in plain words. The engine reads the same references
/// (SI-Connector.ps1 Get-SIConnectorCredentialProblem; a test keeps the words equal). Only Key Vault secret NAMES here.
/// </summary>
public static class ServiceNowCredential
{
    public const string ApiKey = "apikey";
    public const string UserPassword = "user-password";
    public const string None = "none";

    /// The words for half a credential, and for both -- the engine's (Get-SIConnectorCredentialProblem).
    public const string HalfText = "a user needs a password, and a password needs a user -- set both, or choose an API key";
    public const string BothText = "this connector names an API key and a user and password -- choose one: an API key, or a user and a password";

    private static JsonObject Obj(string? json)
    {
        try { return JsonNode.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json) as JsonObject ?? new JsonObject(); }
        catch (JsonException) { return new JsonObject(); }
    }

    private static string? Ref(JsonObject o, string key) =>
        o.FirstOrDefault(p => string.Equals(p.Key, key, StringComparison.OrdinalIgnoreCase)).Value is JsonValue v && v.TryGetValue<string>(out var s) && s.Trim().Length > 0 ? s.Trim() : null;

    /// The references of each way (reference -> Key Vault secret NAME).
    public sealed record Names(string? ApiKey, string? User, string? Password, string? Instance);

    public static Names NamesOf(string? refsJson)
    {
        var o = Obj(refsJson);
        return new Names(Ref(o, "apikey"), Ref(o, "user"), Ref(o, "password"), Ref(o, "instance"));
    }

    /// Which way the references name: apikey, user-password, or none (also for half a credential -- see <see cref="Problem"/>).
    public static string Of(string? refsJson)
    {
        var n = NamesOf(refsJson);
        return n.ApiKey is not null ? ApiKey : n.User is not null && n.Password is not null ? UserPassword : None;
    }

    /// Null = fine (one way, or none named yet); else the wrong combination in plain words.
    public static string? Problem(string? refsJson)
    {
        var n = NamesOf(refsJson);
        if (n.ApiKey is not null && (n.User is not null || n.Password is not null)) return BothText;
        if (n.ApiKey is null && (n.User is null) != (n.Password is null)) return HalfText;
        return null;
    }

    /// The default Key Vault secret names of a connector -- per connector, so a Test and a Prod connector never share a secret
    /// by accident (they start with SI-ServiceNow-, which the Set value allow-list accepts).
    public static (string ApiKey, string User, string Password) DefaultNames(string connector)
    {
        var n = new string((connector ?? "").Where(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-').ToArray()).Trim('-');
        if (n.Length == 0) n = "connector";
        if (n.Length > 80) n = n[..80];
        return ("SI-ServiceNow-" + n + "-ApiKey", "SI-ServiceNow-" + n + "-User", "SI-ServiceNow-" + n + "-Password");
    }

    /// PURE. The connector's secret references with the chosen way: <paramref name="choice"/> apikey sets 'apikey' and removes
    /// 'user' / 'password'; user-password the reverse. Every other reference (the instance) is kept. A Key Vault secret is
    /// never deleted -- only which names the connector reads changes.
    public static string RefsFor(string? currentRefsJson, string choice, string? apiKeyName, string? userName, string? passwordName)
    {
        var o = Obj(currentRefsJson);
        void Drop(string k) { foreach (var key in o.Select(p => p.Key).Where(x => string.Equals(x, k, StringComparison.OrdinalIgnoreCase)).ToList()) o.Remove(key); }
        if (choice == ApiKey)
        {
            Drop("user"); Drop("password"); Drop("apikey");
            o["apikey"] = (apiKeyName ?? "").Trim();
        }
        else if (choice == UserPassword)
        {
            Drop("apikey"); Drop("user"); Drop("password");
            o["user"] = (userName ?? "").Trim();
            o["password"] = (passwordName ?? "").Trim();
        }
        else throw new ArgumentException("choose an API key or a user and a password", nameof(choice));
        return o.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    /// Two connectors that name the same secret for their credential: almost always a mistake (Test and Prod sharing a key).
    public static IReadOnlyList<string> SharedWith(string connector, string? refsJson, IEnumerable<SI.Management.Web.Changes.ConnectorRow> others)
    {
        var mine = new[] { NamesOf(refsJson).ApiKey, NamesOf(refsJson).User, NamesOf(refsJson).Password }.Where(x => x is not null).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (mine.Count == 0) return Array.Empty<string>();
        return others.Where(r => r.Name != connector && r.Kind == "servicenow")
            .Where(r => { var n = NamesOf(r.SecretRefsJson); return new[] { n.ApiKey, n.User, n.Password }.Any(x => x is not null && mine.Contains(x)); })
            .Select(r => r.Name).OrderBy(x => x, StringComparer.Ordinal).ToList();
    }
}
