using System.Globalization;
using System.Text.Json;

namespace SI.Management.Core.ProData;

// THE CI LIFECYCLE IN PLAIN WORDS (#406, V3-DATA-MODEL 2.5.5) -- ONE place the web app reads what "active", "not seen",
// "retired" and "reactivated" mean, from the settings in force (owner 2026-10-19: "it is important that we add these
// assumptions to each page, so the audience knows what they are looking at, like active devices seen last 30 days etc.
// assumptions and filters should be transparent rgr lifecycle").
// The CI build decides the lifecycle with the same settings and the same rules (engine\data-model\SI-CiLifecycle.ps1,
// Resolve-SIAssetRetireSettings / Get-SICiLifecycleDefinitions); the tests keep the two the same.

/// One lifecycle state: its stored value (sidata.Ci.Lifecycle), its label and its definition with the numbers in force.
public sealed record CiLifecycleState(string Value, string Label, string Definition);

/// The lifecycle rules in force: the seen window, the grace period per category (client-pc, server, service-principal, user,
/// azure-vm, azure-resource, other), the plain-language definitions, and what was wrong with a setting (it then has its default).
public sealed record CiLifecycleRules(int SeenWithinDays, int DefaultGraceDays, IReadOnlyDictionary<string, int> GraceDays,
    IReadOnlyList<CiLifecycleState> States, IReadOnlyList<string> Warnings)
{
    /// The CI list's named default filter (it says so, and a person can clear it).
    public string DefaultFilter => CiLifecycleDefinitions.DefaultFilter;

    /// The sentence a page says while the default filter is on.
    public string DefaultFilterText =>
        string.Format(CultureInfo.InvariantCulture,
            "Showing active CIs only (the default): a source lists them and -- for a device -- saw it within the last {0} days. Clear the lifecycle filter to include not seen and retired CIs.",
            SeenWithinDays);

    /// The definition of one state ("" for an unknown value).
    public string Definition(string? value) => States.FirstOrDefault(s => string.Equals(s.Value, value, StringComparison.OrdinalIgnoreCase))?.Definition ?? "";

    /// The grace period of one category (the default for a category without its own).
    public int Grace(string? category) => category is not null && GraceDays.TryGetValue(category, out var d) ? d : DefaultGraceDays;

    /// "30 days" -- a count of days in the viewer's number format (ScoreFormat.Culture).
    public static string Days(int n) => n.ToString("N0", ScoreFormat.Culture) + (n == 1 ? " day" : " days");

    /// "30 days" when every category has the default grace period; else "30 days (servers 14, client PCs 60)" -- the default,
    /// then the categories that differ from it (the order of <see cref="CiLifecycleDefinitions.CategoryWords"/>).
    public string GraceText
    {
        get
        {
            var differ = CiLifecycleDefinitions.CategoryWords.Where(c => Grace(c.Category) != DefaultGraceDays).ToList();
            return differ.Count == 0 ? Days(DefaultGraceDays)
                : Days(DefaultGraceDays) + " (" + string.Join(", ", differ.Select(c => c.Words + " " + Grace(c.Category).ToString("N0", ScoreFormat.Culture))) + ")";
        }
    }

    /// The words every view with CIs explains in its "What you're looking at" line, with the numbers in force.
    public IReadOnlyList<(string Term, string Meaning)> Definitions =>
    [
        ("Active", "a CI a source saw within the last " + Days(SeenWithinDays) + "."),
        ("Not seen", "no source has seen the CI for more than " + Days(SeenWithinDays) + "; it stays in its grace period of " + GraceText + "."),
        ("Retired", "still not seen when its grace period ended; its open vulnerabilities close as retired, never as fixed. A CI seen again is active again."),
    ];
}

public static class CiLifecycleDefinitions
{
    /// The CI list's default lifecycle filter.
    public const string DefaultFilter = "active";
    /// The address value that clears the default ("every lifecycle state").
    public const string ClearedFilter = "all";

    public const string SeenWithinSetting = "SI_Pro_CmdbSql_SeenWithinDays";
    public const string RetireAfterSetting = "SI_Cmdb_RetireAfterDays";
    public const string DefaultGraceSetting = "SI_Pro_AssetRetire_GraceDays";

    /// The categories and their settings (the same as SI-CiLifecycle.ps1 $script:SIAssetRetireCategorySettings).
    public static readonly IReadOnlyList<(string Category, string Setting)> CategorySettings =
    [
        ("client-pc", "SI_Pro_AssetRetire_GraceDays_ClientPc"),
        ("server", "SI_Pro_AssetRetire_GraceDays_Server"),
        ("service-principal", "SI_Pro_AssetRetire_GraceDays_ServicePrincipal"),
        ("user", "SI_Pro_AssetRetire_GraceDays_User"),
        ("azure-vm", "SI_Pro_AssetRetire_GraceDays_AzureVm"),
        ("azure-resource", "SI_Pro_AssetRetire_GraceDays_AzureResource"),
    ];

    /// The categories as a person names them, in the order the views list a grace period that differs.
    public static readonly IReadOnlyList<(string Category, string Words)> CategoryWords =
    [
        ("server", "servers"), ("client-pc", "client PCs"), ("user", "users"), ("service-principal", "service principals"),
        ("azure-vm", "Azure VMs"), ("azure-resource", "other Azure resources"),
    ];

    /// Every setting the rules read.
    public static IEnumerable<string> SettingNames =>
        new[] { SeenWithinSetting, RetireAfterSetting, DefaultGraceSetting }.Concat(CategorySettings.Select(c => c.Setting));

    /// The label of a stored lifecycle value.
    public static string Label(string? value) => value switch
    {
        "active" => "Active",
        "not_seen" => "Not seen",
        "retired" => "Retired",
        null or "" => "",
        _ => value.Replace('_', ' '),
    };

    /// The rules with every setting at its default (seen within 8 days, every grace period 30 days).
    public static CiLifecycleRules Defaults => FromSettings(new Dictionary<string, string?>());

    /// <summary>
    /// PURE. The rules from setting values (name -> value as text or JSON), as Resolve-SIAssetRetireSettings decides them:
    /// the seen window (default 8, at least 1), the retire brake SI_Cmdb_RetireAfterDays (default 7), the default grace
    /// (default 30) and each category's own -- never shorter than the seen window or the brake (raised, and said); a value
    /// that is not a whole number uses the default (said).
    /// </summary>
    public static CiLifecycleRules FromSettings(IReadOnlyDictionary<string, string?> values)
    {
        var warn = new List<string>();
        int Read(string name, int def, int min)
        {
            if (!values.TryGetValue(name, out var raw) || Text(raw) is not { Length: > 0 } t) return def;
            if (!int.TryParse(t, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n))
            {
                warn.Add($"{name} = '{t}' is not a whole number of days -- using {def}.");
                return def;
            }
            if (n < min)
            {
                warn.Add($"{name} = {n} is shorter than the minimum of {min} day(s) (the seen window, never under SI_Cmdb_RetireAfterDays) -- using {min}.");
                return min;
            }
            return n;
        }
        var seen = Read(SeenWithinSetting, 8, 1);
        var brake = Read(RetireAfterSetting, 7, 1);
        var floor = Math.Max(seen, brake);
        var def = Math.Max(Read(DefaultGraceSetting, 30, floor), floor);
        var days = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var (cat, setting) in CategorySettings) days[cat] = Read(setting, def, floor);
        days["other"] = def;
        var states = new List<CiLifecycleState>
        {
            new("active", "Active", string.Create(CultureInfo.InvariantCulture,
                $"Active: at least one source lists the asset and -- for a device -- saw it within the last {seen} days (Entra and Active Directory devices: 14 days, their last sign-in lags by design).")),
            new("not_seen", "Not seen", string.Create(CultureInfo.InvariantCulture,
                $"Not seen: no source has seen the asset for more than {seen} days; it stays in its grace period (default {def} days, per category) before it is retired.")),
            new("retired", "Retired",
                "Retired: not seen for longer than the grace period of its category, or every source gave positive evidence it is gone (offboarded). Its findings close as asset retired -- also those a source still reports -- never as fixed, and do not count as open; nothing is deleted."),
            new("reactivated", "Reactivated",
                "Reactivated: a not seen or retired asset that a source sees again is active again, and the change is recorded."),
        };
        return new CiLifecycleRules(seen, def, days, states, warn);
    }

    /// A setting's stored value as plain text: a JSON string or number unwrapped, anything else trimmed.
    private static string? Text(string? raw)
    {
        if (raw is null) return null;
        var s = raw.Trim();
        if (s.Length == 0) return s;
        if (s[0] is '"' or '-' or (>= '0' and <= '9'))
        {
            try
            {
                using var d = JsonDocument.Parse(s);
                return d.RootElement.ValueKind switch
                {
                    JsonValueKind.String => d.RootElement.GetString()?.Trim(),
                    JsonValueKind.Number => d.RootElement.GetRawText(),
                    JsonValueKind.Null => "",
                    _ => s,
                };
            }
            catch (JsonException) { return s; }
        }
        return s == "null" ? "" : s;
    }
}

/// The lifecycle rules in force, read from the Pro settings store.
public interface ICiLifecycleRulesReader
{
    Task<CiLifecycleRules> ReadAsync(CancellationToken ct);
}

/// <summary>
/// Reads the lifecycle settings (cfg.Setting through <see cref="ISettingsReader"/>) and returns the rules in force. A read
/// that fails returns the defaults with a warning that says so -- a page always has its definitions.
/// </summary>
public sealed class CiLifecycleRulesReader : ICiLifecycleRulesReader
{
    private readonly ISettingsReader _settings;
    public CiLifecycleRulesReader(ISettingsReader settings) => _settings = settings;

    public async Task<CiLifecycleRules> ReadAsync(CancellationToken ct)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var r = await _settings.ReadAsync(null, 1, 1, ct).ConfigureAwait(false);
            var wanted = CiLifecycleDefinitions.SettingNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var s in r.Data.Settings)
                if (wanted.Contains(s.Name) && !s.IsSecret) values[s.Name] = s.ValueJson;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            var d = CiLifecycleDefinitions.Defaults;
            return d with { Warnings = d.Warnings.Append("The lifecycle settings could not be read (" + ex.Message + ") -- the definitions show the defaults.").ToList() };
        }
        return CiLifecycleDefinitions.FromSettings(values);
    }
}
