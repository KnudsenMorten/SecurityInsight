using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages;

/// One filter in force, as a removable chip: its words and the page without it.
public sealed record ScopeChip(string Text, string RemoveHref);

/// <summary>
/// THE "What you're looking at" line of every view (owner 2026-10-19: "it is important that we add these assumptions to
/// each page, so the audience knows what they are looking at, like active devices seen last 30 days etc. assumptions and
/// filters should be transparent rgr lifecycle"; Pages/Shared/_ViewScope.cshtml), directly under the page title, in plain
/// words, built from the REAL state of the page -- never fixed text: the run the data is from, what the view does with
/// the CIs' lifecycle, the other defaults in force (exempted findings, the report grain, a department scope, a default
/// filter), the person's own filters as removable chips, "Show everything" (the view without its defaults and filters)
/// and the definitions behind the words, with the numbers from the settings.
/// </summary>
public sealed record ViewScope
{
    /// The run the view reads (UTC; shown in the viewer's zone) and its kind (Detailed / Summary).
    public DateTime? RunTime { get; init; }
    public string? RunKind { get; init; }
    /// What the view does with the CIs' lifecycle, in words.
    /// (#406 true while the page's NAMED lifecycle default is on -- the line says it is the default)
    public bool LifecycleDefaulted { get; init; }
    public string? Lifecycle { get; init; }
    /// The other defaults in force, each a short sentence.
    public IReadOnlyList<string> Defaults { get; init; } = Array.Empty<string>();
    /// The person's own filters.
    public IReadOnlyList<ScopeChip> Chips { get; init; } = Array.Empty<ScopeChip>();
    /// The view without its defaults and filters (null = nothing to clear).
    public string? ShowEverythingHref { get; init; }
    /// The words used, with what they mean here (the numbers from the settings).
    public IReadOnlyList<(string Term, string Meaning)> Definitions { get; init; } = Array.Empty<(string, string)>();
}

/// <summary>
/// THE one reader of the CI lifecycle rules in the web app (rc14: the toolbar's own copy is gone): the settings store's
/// rows (cfg.Setting, a setting without a value = the shipped catalog default), turned into
/// <see cref="SI.Management.Core.ProData.CiLifecycleRules"/> by <see cref="SI.Management.Core.ProData.CiLifecycleDefinitions.FromSettings"/>
/// -- the same rules the CI build decides with. Kept a minute; a read that fails gives the defaults (said in the log).
/// </summary>
public sealed class CiLifecycleRulesStore(ISettingsStoreReader store, SettingsCatalog catalog, IMemoryCache cache, ILogger<CiLifecycleRulesStore> log)
    : SI.Management.Core.ProData.ICiLifecycleRulesReader
{
    public async Task<SI.Management.Core.ProData.CiLifecycleRules> ReadAsync(CancellationToken ct) =>
        await cache.GetOrCreateAsync("viewscope:lifecycle", async e =>
        {
            e.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1);
            IReadOnlyList<SettingRow> rows = Array.Empty<SettingRow>();
            try { rows = (await store.ReadSettingsAsync(ct)).Rows; }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the lifecycle settings could not be read; the shipped defaults are said"); }
            return Rules(rows, catalog);
        }) ?? Rules(Array.Empty<SettingRow>(), catalog);

    /// The rules of a set of setting rows: a row's value, else the catalog's shipped default, else the rules' own default.
    public static SI.Management.Core.ProData.CiLifecycleRules Rules(IReadOnlyList<SettingRow> rows, SettingsCatalog catalog)
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in SI.Management.Core.ProData.CiLifecycleDefinitions.SettingNames)
        {
            var row = rows.FirstOrDefault(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(r.ValueJson));
            values[name] = row?.ValueJson ?? (catalog.Find(name)?.Default is { } d && d.ValueKind is JsonValueKind.Number or JsonValueKind.String ? d.GetRawText() : null);
        }
        return SI.Management.Core.ProData.CiLifecycleDefinitions.FromSettings(values);
    }
}
