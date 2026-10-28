using System.Text.RegularExpressions;

namespace SI.Management.Web.Settings;

/// <summary>
/// WHICH SECRETS A PERSON MAY SET FROM THE WEB APP (#822, owner 2026-10-20: "i must have easy possibility to add things to
/// keyvault and configue it" / "i will provide servicenow user/password or api key and it must be stored into keyvault";
/// Invardia's review: an ALLOW-LIST, refused server-side). A POSITIVE list: the connector / integration secrets only --
///   * the settings of kind secret a customer sets (<see cref="Settings"/>: the AI key, the Shodan key, the SMTP password),
///     each stored under its ONE product name;
///   * a connector's secret references (<see cref="ConnectorRefs"/>: the ServiceNow instance / user / password / API key, a
///     REST connector's token or OAuth client), stored under the name the connector row gives -- which must start with
///     <see cref="ConnectorPrefixes"/>.
/// Everything else is refused, above all the secrets Invardia issues (<see cref="InvardiaIssued"/>: the per-install key the
/// licence checks, the uplink and support use, the licence, the update state / feed) -- whatever the request says. The
/// updater applies the SAME rules before it writes (container/updater/_shared/SI-UpdaterSecretHandover.ps1,
/// Test-SIHandoverAllowed); a test keeps the two lists equal.
/// </summary>
public static partial class SecretAllowList
{
    /// The settings of kind secret a person may set here -> the Key Vault secret name the product stores each under.
    public static readonly IReadOnlyDictionary<string, string> Settings = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["OpenAI_apiKey"] = "SI-OpenAI-Key",
        ["SMTPPassword"] = "SI-Smtp-Password",
        ["SI_Shodan_ApiKey"] = "SI-Shodan-ApiKey",
        ["SHODAN_ApiKey"] = "SI-Shodan-ApiKey",
    };

    /// The secret references of a connector row (SecretRefsJson keys) a person may set here.
    public static readonly IReadOnlySet<string> ConnectorRefs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "instance", "user", "password", "apikey", "token", "clientId", "clientSecret",
    };

    /// A connector's secret must be named with one of these prefixes (the product's templates: SI-ServiceNow-User, ...).
    public static readonly IReadOnlyList<string> ConnectorPrefixes = ["SI-ServiceNow-", "SI-Connector-"];

    /// The secrets Invardia issues or the product itself keeps -- never set from here, whatever is asked.
    public static readonly IReadOnlySet<string> InvardiaIssued = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "SI-Invardia-InstallKey", "SI-InstallId", "SI-License", "SI-Update-State", "SI-Settings-Handover",
        "SI-LicenceRequest-State", "SI-LicenceRequest-Notice", "SI-LicenceRequest-PullToken",
    };

    /// The prefix of a hand-over row that targets a connector secret (cfg.PendingSecret.SettingName): connector:name/ref.
    public const string ConnectorTargetPrefix = "connector:";

    [GeneratedRegex("^[0-9A-Za-z-]{1,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex KvName();

    [GeneratedRegex("^[A-Za-z0-9 _.-]{1,100}$", RegexOptions.CultureInvariant)]
    private static partial Regex ConnectorName();

    /// The hand-over key of a connector secret.
    public static string ConnectorTarget(string connector, string reference) => ConnectorTargetPrefix + connector + "/" + reference;

    /// Null = allowed; else why not, in plain words. <paramref name="target"/> is a setting name or <see cref="ConnectorTarget"/>.
    public static string? WhyNot(string target, string secretName)
    {
        target ??= ""; secretName ??= "";
        if (!KvName().IsMatch(secretName)) return "not a Key Vault secret name (letters, digits and '-', at most 127)";
        if (InvardiaIssued.Contains(secretName) || secretName.StartsWith("SI-Invardia-", StringComparison.OrdinalIgnoreCase) || secretName.StartsWith("SI-LicenceRequest-", StringComparison.OrdinalIgnoreCase))
            return "this secret is issued by Invardia or kept by the product itself -- it is never set here";
        if (target.StartsWith(ConnectorTargetPrefix, StringComparison.Ordinal))
        {
            var rest = target[ConnectorTargetPrefix.Length..];
            var slash = rest.LastIndexOf('/');
            if (slash <= 0) return "not a connector secret";
            var (name, reference) = (rest[..slash], rest[(slash + 1)..]);
            if (!ConnectorName().IsMatch(name)) return "not a connector name";
            if (!ConnectorRefs.Contains(reference)) return $"'{reference}' is not a connector secret that can be set here";
            if (!ConnectorPrefixes.Any(p => secretName.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
                return "a connector's secret is named " + string.Join(" or ", ConnectorPrefixes.Select(p => p + "...")) + " -- rename it on the connector first";
            return null;
        }
        if (!Settings.TryGetValue(target, out var expected)) return $"'{target}' is not a secret that can be set here";
        if (!string.Equals(expected, secretName, StringComparison.Ordinal)) return $"'{target}' is stored as {expected}";
        return null;
    }
}
