using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.Settings;

/// <summary>
/// Configuration &gt; Risk rating &amp; lifecycle &gt; Lifecycle and deadlines (owner 2026-10-20: "i need menuitem for risk
/// rating and lifecycle in menu under configuration" -- "important things will look for frequently and could chg"): the
/// three lifecycles a person looks up and changes, on one page instead of in the long settings list -- the accepted
/// lifecycle the Protection Score counts with (per asset kind), the days to fix a finding (per severity) and the days an
/// unseen asset is kept before it is retired. Each line shows the value in force (stored, else the shipped default) and
/// changes through the one settings editor (/Admin/Settings/Edit: review, reason, audited). Read on every visit. Admin.
/// </summary>
public sealed class LifecycleModel(SettingsCatalog catalog, ISettingsStoreReader reader, ILogger<LifecycleModel> log) : PageModel
{
    /// One section of the page: its heading, what it means in plain words, and its settings in display order.
    public sealed record Section(string Id, string Title, string Lede, IReadOnlyList<string> Settings);

    public static readonly IReadOnlyList<Section> Sections =
    [
        new("accepted", "Accepted lifecycle (Protection Score)",
            "How long a finding may exist before the Protection Score \"within Accepted Lifecycle\" counts it as a risk -- like monthly patching: a finding younger than its asset kind's days is within the accepted process. \"Actual Risks\" counts every finding, whatever its age.",
            ["SI_ProtectionScore_GraceDays_Device", "SI_ProtectionScore_GraceDays_Identity", "SI_ProtectionScore_GraceDays_CloudResource", "SI_ProtectionScore_GraceDays_PublicIp",
             // #860: the accepted lifecycle is for patches; every other finding has its own grace (default 0)
             "SI_ProtectionScore_OtherGraceDays_Device", "SI_ProtectionScore_OtherGraceDays_Identity", "SI_ProtectionScore_OtherGraceDays_CloudResource", "SI_ProtectionScore_OtherGraceDays_PublicIp"]),
        new("deadlines", "Days to fix a finding",
            "The due date of a finding by its severity, counted from when it was first seen (0 = no due date). Tasks, remediations and reports show a finding past it as overdue.",
            ["SI_Pro_FindingSla_CriticalDays", "SI_Pro_FindingSla_HighDays", "SI_Pro_FindingSla_MediumDays", "SI_Pro_FindingSla_LowDays"]),
        new("retire", "Days before an unseen asset is retired",
            "How long an asset may go unseen by every source before it is retired: its open vulnerabilities then close as retired, never as fixed. A kind left empty follows the general value.",
            ["SI_Pro_AssetRetire_GraceDays", "SI_Pro_AssetRetire_GraceDays_Server", "SI_Pro_AssetRetire_GraceDays_ClientPc", "SI_Pro_AssetRetire_GraceDays_AzureVm",
             "SI_Pro_AssetRetire_GraceDays_AzureResource", "SI_Pro_AssetRetire_GraceDays_User", "SI_Pro_AssetRetire_GraceDays_ServicePrincipal"]),
    ];

    /// One line: the setting, its value in force and whether that is the shipped default.
    public sealed record Line(CatalogSetting Setting, string Value, bool IsDefault, DateTime? UpdatedAt, string? UpdatedBy);

    public IReadOnlyList<(Section Section, IReadOnlyList<Line> Lines)> View { get; private set; } = Array.Empty<(Section, IReadOnlyList<Line>)>();
    public string? Error { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        IReadOnlyList<SettingRow> rows = Array.Empty<SettingRow>();
        try { rows = (await reader.ReadSettingsAsync(ct)).Rows; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the lifecycle settings could not be read");
            Error = "The stored values could not be read from the Pro database (" + ex.Message + "). The shipped defaults are shown; a value you changed may differ.";
        }
        View = Build(catalog, rows);
    }

    /// PURE. The sections with their lines: a setting the catalog does not know is left out (an older install).
    public static IReadOnlyList<(Section Section, IReadOnlyList<Line> Lines)> Build(SettingsCatalog catalog, IReadOnlyList<SettingRow> rows) =>
        Sections.Select(s => (s, (IReadOnlyList<Line>)s.Settings.Select(n => LineOf(catalog, rows, n)).Where(l => l is not null).Select(l => l!).ToList())).ToList();

    /// <summary>
    /// PURE. ONE setting's line: its value in force (the stored value, else the shipped default) -- the one reading of a
    /// setting's value both this page and the Assumptions page (#858) show; null for a setting the catalog does not know.
    /// </summary>
    public static Line? LineOf(SettingsCatalog catalog, IReadOnlyList<SettingRow> rows, string name)
    {
        if (catalog.Find(name) is not { } c) return null;
        var stored = rows.Where(r => r.Name.Equals(c.Name, StringComparison.OrdinalIgnoreCase))
                         .OrderBy(r => r.Scope == "solution" ? 0 : 1).FirstOrDefault(r => !string.IsNullOrWhiteSpace(SettingJson.ToFormText(r.ValueJson)));
        return stored is null
            ? new Line(c, c.DefaultText ?? c.DefaultDisplay, true, null, null)
            : new Line(c, c.WithUnit(SettingJson.ToFormText(stored.ValueJson)), false, stored.UpdatedAt, stored.UpdatedBy);
    }
}
