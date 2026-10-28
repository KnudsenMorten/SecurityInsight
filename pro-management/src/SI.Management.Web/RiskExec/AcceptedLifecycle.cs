using System.Globalization;

namespace SI.Management.Web.RiskExec;

/// <summary>
/// THE ACCEPTED LIFECYCLE IN FORCE, in words (owner 2026-10-20: "people are confused with this when they cannot read the header
/// about accepted lifecycle (add: monthly patching as example) to show the audience the actual value in our lifecycle"): the
/// accepted time to fix per asset type (SI_ProtectionScore_GraceDays_Device | _Identity | _CloudResource | _PublicIp) and the
/// severities that count (SI_ProtectionScore_Severities) -- the same settings, defaults and rules the data sync computes the
/// score with (engine/_shared/SI-ProtectionScore.ps1 Get-SIProtectionScoreSettings: a missing or invalid value = 30 days /
/// Very High, Critical, High; a value not set is marked "(default)"). Read from the settings store in force -- the stored key
/// figures do not carry the values a run used; when the store cannot be read the line says so -- never a made-up number.
/// </summary>
public sealed record AcceptedLifecycle(bool Readable, IReadOnlyList<(string Type, int Days, bool Default)> Grace, IReadOnlyList<string> Severities,
    IReadOnlyList<(string Type, int Days, bool Default)>? Other = null)
{
    /// #860 (owner 2026-10-21: "grace 0 for non-patch"): the grace of a finding that is NOT a patch, per asset type
    /// (SI_ProtectionScore_OtherGraceDays_*; the engine's default 0 = it counts from the day it is found).
    public static readonly IReadOnlyList<(string Type, string Setting)> OtherTypes =
    [
        ("devices", "SI_ProtectionScore_OtherGraceDays_Device"), ("identities", "SI_ProtectionScore_OtherGraceDays_Identity"),
        ("cloud resources", "SI_ProtectionScore_OtherGraceDays_CloudResource"), ("public IPs", "SI_ProtectionScore_OtherGraceDays_PublicIp"),
    ];

    /// "This applies to patches ...; every other finding ... counts from the day it is found" (or its grace per asset type).
    public string OtherWords => Other is not { Count: > 0 } o || o.All(g => g.Days == 0)
        ? " This applies to patches (a vulnerability with a vendor fix); every other finding -- configuration, identity, Azure, attack paths -- counts from the day it is found."
        : " This applies to patches (a vulnerability with a vendor fix); every other finding -- configuration, identity, Azure, attack paths -- after: " + string.Join(", ", o.Select(g => g.Type + " " + D(g.Days) + (g.Default ? " (default)" : ""))) + ".";

    /// The engine's defaults (Get-SIProtectionScoreSettings).
    public const int DefaultDays = 30;
    private static readonly string[] DefaultSeverities = ["Very High", "Critical", "High"];

    /// The four asset types the score counts, in the order a reader sees them, with their setting.
    public static readonly IReadOnlyList<(string Type, string Setting)> Types =
    [
        ("devices", "SI_ProtectionScore_GraceDays_Device"), ("identities", "SI_ProtectionScore_GraceDays_Identity"),
        ("cloud resources", "SI_ProtectionScore_GraceDays_CloudResource"), ("public IPs", "SI_ProtectionScore_GraceDays_PublicIp"),
    ];

    /// Nothing could be read: no values are shown.
    public static readonly AcceptedLifecycle Unknown = new(false, [], []);

    private static string D(int d) => d.ToString(CultureInfo.InvariantCulture) + (d == 1 ? " day" : " days");

    /// The severities that count, as a reader names them ("Very High / High"; Critical is the source's word for Very High).
    public string SeverityWords
    {
        get
        {
            var names = Severities.Select(s => s.Trim()).Where(s => s.Length > 0)
                .Select(s => s.Equals("Critical", StringComparison.OrdinalIgnoreCase) ? "Very High" : s)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            return names.Count == 0 ? "Very High / High" : string.Join(" / ", names);
        }
    }

    /// The accepted time to fix per asset type: "devices 14 days, identities 30 days (default), ...".
    public string PerType => string.Join(", ", Grace.Select(g => g.Type + " " + D(g.Days) + (g.Default ? " (default)" : "")));

    /// The short form the scope lines use: "30 days" when every asset type has the same, else per type.
    public string Words => !Readable || Grace.Count == 0 ? D(DefaultDays) : Grace.Select(g => g.Days).Distinct().Count() == 1 ? D(Grace[0].Days)
        : string.Join(", ", Grace.Select(g => g.Type + " " + D(g.Days)));

    /// The line under the "within Accepted Lifecycle" score: what it means, with the values in force.
    public string Line => Readable && Grace.Count > 0
        ? "An open " + SeverityWords + " finding counts as a risk only after its accepted time to fix -- like monthly patching: " + PerType + "." + OtherWords
        : "A finding counts as a risk only after its accepted time to fix -- like monthly patching. The accepted time to fix could not be read from the settings, so it is not shown here.";

    /// The accepted lifecycle from the settings in force. Never throws: a store that cannot be read gives <see cref="Unknown"/>.
    public static async Task<AcceptedLifecycle> ReadAsync(IServiceProvider services, CancellationToken ct)
    {
        if (services.GetService(typeof(SI.Management.Web.Settings.ISettingsStoreReader)) is not SI.Management.Web.Settings.ISettingsStoreReader reader) return Unknown;
        try
        {
            var (rows, _) = await reader.ReadSettingsAsync(ct);
            return From(rows);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _ = ex; return Unknown; }
    }

    /// PURE. The accepted lifecycle from the setting rows (a missing or invalid value = the engine's default, as it computes).
    public static AcceptedLifecycle From(IReadOnlyList<SI.Management.Web.Settings.SettingRow> rows)
    {
        string? Val(string name) => rows.FirstOrDefault(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase))?.ValueJson?.Trim().Trim('"');
        var grace = Types.Select(t => int.TryParse(Val(t.Setting), NumberStyles.Integer, CultureInfo.InvariantCulture, out var d) && d is >= 0 and <= 3650
            ? (t.Type, d, false) : (t.Type, DefaultDays, true)).ToList();
        var sev = Val("SI_ProtectionScore_Severities") is { Length: > 0 } s
            ? s.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            : [];
        var other = OtherTypes.Select(t => int.TryParse(Val(t.Setting), NumberStyles.Integer, CultureInfo.InvariantCulture, out var d) && d is >= 0 and <= 3650
            ? (t.Type, d, false) : (t.Type, 0, true)).ToList();
        return new AcceptedLifecycle(true, grace, sev.Length > 0 ? sev : DefaultSeverities, other);
    }
}
