using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;

namespace SI.Management.Web.Settings;

/// <summary>
/// #772 THE PATCH CYCLE'S THRESHOLD AS THE SETTINGS SAY IT NOW (owner 2026-10-19: "we need a filter option, where we filter
/// between 'being fixed during monthly lifecycle' vs. 'catch-up older than 1 month'"): SI_PatchCycle_CatchUpDays (default
/// 30, at least 1) -- the same number Risk Analysis classifies with (engine\data-model\SI-Classification.ps1,
/// Get-SIPatchCycleCatchUpDays). Read through the settings store, so a view's "what you're looking at" line can say
/// "Catch-up = fix older than 30 days" with the real number (<see cref="PatchCycleRules.Definitions"/>).
/// </summary>
public sealed record PatchCycleRules(int CatchUpDays)
{
    public const int Default = 30;

    public static string Days(int n) => n.ToString("N0", CultureInfo.CurrentCulture) + (n == 1 ? " day" : " days");

    /// The words behind the patch-cycle values, with the real threshold.
    public IReadOnlyList<(string Term, string Meaning)> Definitions =>
    [
        ("In monthly cycle", "the fix was released (or, without one dated update, the finding was first detected) at most " + Days(CatchUpDays) + " before the collection."),
        ("Catch-up", "fix older than " + Days(CatchUpDays) + " (or, without one dated update, first detected longer ago)."),
        ("No fix available", "the source says no fix exists."),
        ("Unknown", "no fix release date and no first detection to count from."),
    ];

    /// One line, e.g. "Catch-up = fix older than 30 days".
    public string CatchUpText => "Catch-up = fix older than " + Days(CatchUpDays);
}

/// Reads <see cref="PatchCycleRules"/> from the settings (kept a minute); the shipped default when it cannot.
public sealed class PatchCycleSettings(ISettingsStoreReader store, SettingsCatalog catalog, IMemoryCache cache, ILogger<PatchCycleSettings> log)
{
    public const string Setting = "SI_PatchCycle_CatchUpDays";

    public async Task<PatchCycleRules> ReadAsync(CancellationToken ct) =>
        await cache.GetOrCreateAsync("viewscope:patchcycle", async e =>
        {
            e.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1);
            IReadOnlyList<SettingRow> rows = Array.Empty<SettingRow>();
            try { rows = (await store.ReadSettingsAsync(ct)).Rows; }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the patch cycle setting could not be read; the shipped default is said"); }
            return Rules(rows, catalog);
        }) ?? Rules(Array.Empty<SettingRow>(), catalog);

    /// The rules of a set of setting rows: the stored value (a whole number of at least 1), else the catalog's default, else 30.
    public static PatchCycleRules Rules(IReadOnlyList<SettingRow> rows, SettingsCatalog catalog)
    {
        var stored = rows.Where(r => r.Name.Equals(Setting, StringComparison.OrdinalIgnoreCase)).Select(r => Number(r.ValueJson)).FirstOrDefault(n => n is >= 1);
        var shipped = catalog.Find(Setting)?.Default is { ValueKind: not JsonValueKind.Null } d ? Number(d.GetRawText()) : null;
        return new PatchCycleRules(stored ?? (shipped is >= 1 ? shipped : null) ?? PatchCycleRules.Default);
    }

    private static int? Number(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var d = JsonDocument.Parse(json);
            var e = d.RootElement;
            if (e.ValueKind == JsonValueKind.Number && e.TryGetInt32(out var n)) return n;
            if (e.ValueKind == JsonValueKind.String && int.TryParse(e.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out var s)) return s;
        }
        catch (JsonException) { if (int.TryParse(json.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var raw)) return raw; }
        return null;
    }
}
