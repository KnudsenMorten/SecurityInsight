using System.Text.RegularExpressions;

namespace SI.Management.Web.Settings;

/// <summary>
/// WHICH KEY VAULT SECRET A SECRET SETTING MAY NAME, and WHICH SETTINGS ONLY A SUPERADMIN CHANGES.
/// A setting of kind secret names its own Key Vault secret only: the product's name for it (SMTPPassword -> SI-Smtp-Password)
/// or a name under the setting's own fixed prefix (SI-Smtp-...). Never a secret the product keeps for something else (the
/// install key, the licence, the engine's certificate, a connector's secrets) and never another setting's secret.
/// The engine applies the SAME rules when it reads a stored row (engine\pro-settings\SI-ProSettings.ps1,
/// Test-SISecretSettingReference); a test keeps the two lists equal.
///   * <see cref="WhyNotNew"/>    a NEW or CHANGED reference (the web app's save): only the setting's own names.
///   * <see cref="WhyNotStored"/> a reference already stored (a backup restored, an undo, the engine's read): its own names, or
///     a name the customer chose before this rule outside the product's SI- names -- an existing install keeps working.
/// </summary>
public static partial class SecretSettingPolicy
{
    /// One family of secret settings: the settings, the product's names for their secret, the fixed prefix a renamed one keeps.
    public sealed record Family(string Key, IReadOnlyList<string> Settings, IReadOnlyList<string> Names, string Prefix);

    public static readonly IReadOnlyList<Family> Families =
    [
        new("openai", ["OpenAI_apiKey"], ["SI-OpenAI-Key"], "SI-OpenAI-"),
        new("smtp", ["SMTPPassword"], ["SI-Smtp-Password"], "SI-Smtp-"),
        new("shodan", ["SI_Shodan_ApiKey", "SHODAN_ApiKey"], ["SI-Shodan-ApiKey"], "SI-Shodan-"),
        new("spn", ["SI_SPN_Secret", "SpnClientSecret", "SpnSecretName", "SI_Graph_Secret", "SI_LogIngest_Secret"], ["SI-SPN-Secret", "SecurityInsight-Secret"], "SI-SPN-Secret"),
    ];

    /// Secrets the product keeps for something else -- never named by any setting.
    public static readonly IReadOnlyList<string> Reserved =
    [
        "SI-Invardia-InstallKey", "SI-InstallId", "SI-License", "SI-Update-State", "SI-Settings-Handover",
        "SI-LicenceRequest-State", "SI-LicenceRequest-Notice", "SI-LicenceRequest-PullToken", "SI-SPN-Cert",
    ];

    /// Name prefixes the product keeps for something else (connector secrets, Invardia's, the licence request's, the engine's certificate).
    public static readonly IReadOnlyList<string> ReservedPrefixes =
        ["SI-Invardia-", "SI-LicenceRequest-", "SI-SPN-Cert", "SI-Connector-", "SI-ServiceNow-", "SI-Web-"];

    /// Settings only a SuperAdmin changes, beyond the secrets and the licence settings: the hosts a secret or the install's
    /// own credential is sent to, and the database server the engine signs in to.
    public static readonly IReadOnlySet<string> SecurityHosts = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "SmtpServer", "SMTPPort", "SMTP_UseSSL", "SMTPUser", "OpenAI_endpoint", "SI_Pro_DataSqlServer", "SI_Pro_DataSqlDatabase", "SI_Telemetry_Endpoint", "SI_LicenseRequest_BaseUrl",
    };

    [GeneratedRegex("^[0-9A-Za-z-]{1,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex KvName();

    /// The family of a secret setting; a secret setting the list does not name gets its own: SI-&lt;name with dashes&gt;.
    public static Family FamilyOf(string setting) =>
        Families.FirstOrDefault(f => f.Settings.Contains(setting, StringComparer.OrdinalIgnoreCase))
        ?? new Family(setting, [], [], "SI-" + setting.Replace('_', '-'));

    private static bool IsReserved(string name) =>
        Reserved.Contains(name, StringComparer.OrdinalIgnoreCase) || ReservedPrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    private static bool IsOwn(Family f, string name) =>
        f.Names.Contains(name, StringComparer.OrdinalIgnoreCase) || name.StartsWith(f.Prefix, StringComparison.OrdinalIgnoreCase);

    /// PURE. Is <paramref name="secretName"/> one of the setting's OWN names (the product's name or its fixed prefix)?
    public static bool IsOwnName(string setting, string? secretName) => IsOwn(FamilyOf(setting), (secretName ?? "").Trim());

    /// The words for the names a setting may use.
    public static string Allowed(string setting)
    {
        var f = FamilyOf(setting);
        var names = f.Names.Count > 0 ? string.Join(" or ", f.Names) + ", or " : "";
        return $"{names}a name that starts with {f.Prefix}";
    }

    /// Null = a new or changed reference may be stored; else why not, in plain words.
    public static string? WhyNotNew(string setting, string? secretName)
    {
        var n = (secretName ?? "").Trim();
        if (!KvName().IsMatch(n)) return $"'{n}' is not a Key Vault secret name (letters, digits and dashes, at most 127)";
        if (IsReserved(n)) return $"{n} is a secret SecurityInsight keeps for another purpose -- {setting} names its own secret: {Allowed(setting)}";
        if (!IsOwn(FamilyOf(setting), n)) return $"{setting} names its own Key Vault secret: {Allowed(setting)}";
        return null;
    }

    /// Null = a reference already stored is used; else why not. A name the customer chose before this rule (outside the
    /// product's SI- names and not another setting's) keeps working -- unless another secret setting's stored row names the
    /// same secret (<paramref name="alsoNamedBy"/>: those settings): a customer's own name belongs to one setting only.
    public static string? WhyNotStored(string setting, string? secretName, IEnumerable<string>? alsoNamedBy = null)
    {
        var n = (secretName ?? "").Trim();
        if (!KvName().IsMatch(n)) return $"'{n}' is not a Key Vault secret name";
        if (IsReserved(n)) return $"{n} is a secret SecurityInsight keeps for another purpose";
        var f = FamilyOf(setting);
        if (IsOwn(f, n)) return null;
        if (Families.Any(o => o.Key != f.Key && IsOwn(o, n))) return $"{n} is another setting's secret";
        if (n.StartsWith("SI-", StringComparison.OrdinalIgnoreCase)) return $"{n} is not {setting}'s own secret ({Allowed(setting)})";
        if ((alsoNamedBy ?? Array.Empty<string>()).FirstOrDefault(o => !string.IsNullOrWhiteSpace(o) && !string.Equals(o, setting, StringComparison.OrdinalIgnoreCase) && FamilyOf(o).Key != f.Key) is { } other)
            return $"{n} is also named by {other} -- a secret belongs to one setting";
        return null;
    }

    /// Does a change to this setting need SuperAdmin? The licence settings, every secret setting, and the hosts a secret is sent to.
    public static bool NeedsSuperAdmin(string? name, bool secret) =>
        secret || SI.Management.Web.Auth.AccessLifecycle.IsLicenceSetting(name) || SecurityHosts.Contains(name ?? "");

    /// The same for a stored cfg.Setting record (an undo or a restore): a record that names Key Vault is a secret's reference.
    public static bool NeedsSuperAdminRecord(string? name, string? keyVaultSecretName) =>
        NeedsSuperAdmin(name, !string.IsNullOrWhiteSpace(keyVaultSecretName) || Families.Any(f => f.Settings.Contains(name ?? "", StringComparer.OrdinalIgnoreCase)));
}
