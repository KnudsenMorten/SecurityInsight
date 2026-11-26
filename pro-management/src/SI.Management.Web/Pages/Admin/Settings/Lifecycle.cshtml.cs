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
    /// <summary>
    /// One section of the page: its heading, what it means in plain words, and its settings in display order.
    /// #1390 (owner 2026-11-25: "i am missing something in the settings here"): a section that shows a catalog CARD
    /// (<see cref="Card"/>) shows EVERY setting of that card -- the ones named here first, in their order, then any other
    /// setting the catalog's card holds (a later release's included), so a hand-kept list can never silently drop a key
    /// again. A section that shows only part of a card says which card and why (<see cref="PartOf"/>).
    /// </summary>
    public sealed record Section(string Id, string Title, string Lede, IReadOnlyList<string> Settings, string? Card = null, string? PartOf = null, string? Note = null);

    /// The catalog card the "retire" section shows in full.
    public const string RetireCard = "Assets no longer seen";

    public static readonly IReadOnlyList<Section> Sections =
    [
        new("accepted", "Accepted lifecycle (Protection Score)",
            "How long a finding may exist before the Protection Score \"within Accepted Lifecycle\" counts it as a risk -- like monthly patching: a finding younger than its asset kind's days is within the accepted process. \"Actual Risks\" counts every finding, whatever its age.",
            ["SI_ProtectionScore_GraceDays_Device", "SI_ProtectionScore_GraceDays_Identity", "SI_ProtectionScore_GraceDays_CloudResource", "SI_ProtectionScore_GraceDays_PublicIp",
             // #860: the accepted lifecycle is for patches; every other finding has its own grace (default 0)
             "SI_ProtectionScore_OtherGraceDays_Device", "SI_ProtectionScore_OtherGraceDays_Identity", "SI_ProtectionScore_OtherGraceDays_CloudResource", "SI_ProtectionScore_OtherGraceDays_PublicIp"],
            PartOf: "Protection score: only its lifecycle days -- the score's points, tier shares and first-seen source are not lifecycles and stay on the Settings page's Protection score card"),
        new("deadlines", "Days to fix a finding",
            "The due date of a finding by its severity, counted from when it was first seen (0 = no due date); a vulnerability whose exploit is verified or in an exploit kit is due sooner when its own days are fewer. A due date set in Defender for Cloud governance is kept. Tasks, remediations and reports show a finding past it as overdue.",
            // #1388 owner 2026-11-25 "Stricter: 15/30/60/90" + exploited (verified / kit only) = 14 days ("Verified/kit, build now")
            ["SI_Pro_FindingSla_CriticalDays", "SI_Pro_FindingSla_HighDays", "SI_Pro_FindingSla_MediumDays", "SI_Pro_FindingSla_LowDays", "SI_Pro_FindingSla_ExploitedDays"]),
        new("retire", "Days before an unseen asset is retired",
            "How long an asset may go unseen by every source before it is retired: its open vulnerabilities then close as retired, never as fixed. A kind left empty follows the general value.",
            ["SI_Pro_AssetRetire_GraceDays", "SI_Pro_AssetRetire_GraceDays_Server", "SI_Pro_AssetRetire_GraceDays_ClientPc", "SI_Pro_AssetRetire_GraceDays_AzureVm",
             "SI_Pro_AssetRetire_GraceDays_AzureResource", "SI_Pro_AssetRetire_GraceDays_User", "SI_Pro_AssetRetire_GraceDays_ServicePrincipal",
             // #1057 / #1390: retire at once on PROOF of deletion, per source (owner 2026-11-25: on by default)
             "SI_DeletionProof_Entra", "SI_DeletionProof_Azure", "SI_DeletionProof_Intune"],
            Card: RetireCard,
            Note: "Retire at once when deleted in Entra ID, Azure or Intune: only a PROOF of deletion from the source counts (Entra ID's deleted items, a Delete in Azure's resource changes, a Delete of the device in Intune's audit events) -- an asset merely missing from a list waits the days above. The asset's findings close as \"asset deleted in <source>\", never as fixed. A deletion that is undone (an object restored in Entra ID, a resource or device listed again) makes the asset active again and its findings reopen."),
    ];

    /// <summary>
    /// PURE. The settings a section shows, in order: its named settings, then -- for a section that shows a card -- every
    /// other setting of that card in the catalog's order. Nothing of the card is ever left out.
    /// </summary>
    public static IReadOnlyList<string> SettingsOf(SettingsCatalog catalog, Section section)
    {
        var names = new List<string>(section.Settings);
        if (section.Card is { } card && catalog.Cards.FirstOrDefault(c => string.Equals(c.Name, card, StringComparison.Ordinal)) is { } cc)
            foreach (var n in cc.Settings)
                if (!names.Contains(n, StringComparer.OrdinalIgnoreCase)) names.Add(n);
        return names;
    }

    /// PURE. What the Value column shows: an on / off switch as On or Off, every other setting as its value in force.
    public static string Shown(Line l)
    {
        if (!string.Equals(l.Setting.Type, "bool", StringComparison.OrdinalIgnoreCase)) return l.Value;
        string? raw = l.IsDefault ? (l.Setting.Default is { } d ? d.GetRawText() : null) : l.Value;
        return raw?.Trim().Trim('"').ToLowerInvariant() switch
        {
            "true" or "1" or "on" or "yes" or "$true" => "On",
            "false" or "0" or "off" or "no" or "$false" => "Off",
            _ => l.Value,
        };
    }

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
            Error = "The stored values could not be read from the Pro database (" + ViewerError.Text(ex) + "). The shipped defaults are shown; a value you changed may differ.";
        }
        View = Build(catalog, rows);
    }

    /// PURE. The sections with their lines: a setting the catalog does not know is left out (an older install).
    public static IReadOnlyList<(Section Section, IReadOnlyList<Line> Lines)> Build(SettingsCatalog catalog, IReadOnlyList<SettingRow> rows) =>
        Sections.Select(s => (s, (IReadOnlyList<Line>)SettingsOf(catalog, s).Select(n => LineOf(catalog, rows, n)).Where(l => l is not null).Select(l => l!).ToList())).ToList();

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
