using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Settings;

namespace SI.Management.Web.ChangeJournal;

/// <summary>
/// #404 -- the web app's settings of undo / backup / restore / guard release / resend (scope 'engine:management-web',
/// edited on the Settings page like every other, audited). The backup and journal RETENTION are read by the backup job
/// and the database too, so they live in the engines' catalog (SI_Pro_ConfigBackupRetentionDays,
/// SI_Pro_ConfigJournalRetentionDays); the web app reads those from solution scope. One-minute cache; unreadable = the
/// defaults (second person off, 3 days of collections offered, 90 days of backups).
/// </summary>
public sealed class ConfigSettings
{
    public const string Group = "Undo, backup and restore";
    public const string SecondPerson = "SIWeb_ConfigSecondPerson";
    public const string ResendDays = "SIWeb_CollectionResendDays";
    public const string BackupRetentionDays = "SI_Pro_ConfigBackupRetentionDays";
    public const string JournalRetentionDays = "SI_Pro_ConfigJournalRetentionDays";

    private static JsonElement J(string json) { using var d = JsonDocument.Parse(json); return d.RootElement.Clone(); }

    private static CatalogSetting S(string name, string type, string label, string purpose, string effect, string def, string defText, double? min = null, double? max = null,
        string? when = null, string? unit = null) => new()
    {
        Name = name, Label = label, Group = Group, Type = type, Engines = new[] { "management-web" }, Edition = "pro",
        Default = J(def), DefaultText = defText, Description = purpose, Purpose = purpose, Effect = effect, WhenToChange = when, Unit = unit,
        Min = min, Max = max, WebOnly = true,
    };

    public static readonly IReadOnlyList<CatalogSetting> Catalog =
    [
        S(SecondPerson, "bool", "A second SuperAdmin approves releases and restores",
            "Whether releasing a guard and restoring from a configuration backup need a second SuperAdmin.",
            "Off (the default): the SuperAdmin who releases a guard or restores a backup does it directly (it is audited). On: the request waits on the Guards page or the Backups page until ANOTHER SuperAdmin approves or rejects it; the person who asked can never approve their own request.",
            "false", "off", when: "Turn on when your change process needs four eyes on these actions."),
        S(ResendDays, "int", "Collections you can send again (days)",
            "How many days back a complete Risk Analysis collection can be sent again into a connector by hand (" + SI.Management.Web.Navigation.NavModel.PathOf("/Admin/Resend") + ").",
            "Collections of the last this many days are offered. They are read from what the Pro database already keeps (Data & retention), so this can never be longer than that retention.",
            "3", "3 days", 1, 90, when: "When you want to be able to re-send older collections after an outage.", unit: "days"),
    ];

    public sealed record Values(bool SecondPerson, int ResendDays, int BackupRetentionDays, int? JournalRetentionDays)
    {
        public static Values Defaults { get; } = new(false, 3, 90, null);
    }

    private readonly ISettingsStoreReader _reader;
    private readonly IMemoryCache _cache;
    private readonly ILogger<ConfigSettings> _log;
    public ConfigSettings(ISettingsStoreReader reader, IMemoryCache cache, ILogger<ConfigSettings> log) { _reader = reader; _cache = cache; _log = log; }

    public async Task<Values> ReadAsync(CancellationToken ct)
    {
        if (_cache.TryGetValue("si-config-settings", out Values? hit) && hit is not null) return hit;
        IReadOnlyList<SettingRow> rows;
        try { rows = (await _reader.ReadSettingsAsync(ct)).Rows; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the undo / backup settings could not be read -- the defaults apply");
            return Values.Defaults;
        }
        var v = From(rows);
        _cache.Set("si-config-settings", v, TimeSpan.FromMinutes(1));
        return v;
    }

    /// PURE. The values from the setting rows; an unparsable or out-of-range value falls back to the default.
    public static Values From(IEnumerable<SettingRow> rows)
    {
        var list = rows.OrderBy(r => r.Scope == "solution" || r.Scope == CatalogSetting.WebScope ? 0 : 1).ToList();
        string? Str(string n) => list.FirstOrDefault(r => string.Equals(r.Name, n, StringComparison.OrdinalIgnoreCase)) is { ValueJson: { } j } ? Parse(j) : null;
        int? Int(string n, int min, int max) => int.TryParse(Str(n), System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var x) && x >= min && x <= max ? x : null;
        var d = Values.Defaults;
        var backup = Int(BackupRetentionDays, 1, 100000) ?? d.BackupRetentionDays;
        var journal = Int(JournalRetentionDays, 1, 1000000);
        // never shorter than the backups (CONFIG-1.1): a shorter value keeps the journal, as the job does
        if (journal is { } jd && jd < backup) journal = null;
        return new Values(Str(SecondPerson) == "true", Int(ResendDays, 1, 90) ?? d.ResendDays, backup, journal);
    }

    private static string? Parse(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.ValueKind switch
            {
                JsonValueKind.String => doc.RootElement.GetString(), JsonValueKind.True => "true", JsonValueKind.False => "false",
                JsonValueKind.Number => doc.RootElement.GetRawText(), _ => null,
            };
        }
        catch (JsonException) { return null; }
    }
}
