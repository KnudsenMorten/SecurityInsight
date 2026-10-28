using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Changes;
using SI.Management.Web.Pages.AssetTagging;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.Settings;

/// <summary>
/// #858 ONE PAGE OF ASSUMPTIONS (owner 2026-10-21: "do we have a view or setting somewhere where we define these
/// assumptions. i have started to loose track"): Configuration &gt; Risk rating &amp; lifecycle &gt; Assumptions -- in plain
/// words, with the values IN FORCE and a link to where each is set: what counts as an asset, the lifecycle windows and grace
/// periods, which views show active assets by default, how a tier is decided, what "fixed" means, the risk rating's
/// thresholds, the accepted lifecycle of the Protection Score and the days to fix, and what is NOT measured.
/// Built from the SAME readers the pages use -- the lifecycle rules (<see cref="ICiLifecycleRulesReader"/>), a setting's
/// value in force (<see cref="LifecycleModel.LineOf"/>), the risk rating in force (<see cref="RiskRatingThresholds.InForce"/>),
/// the asset tagging gates (<see cref="GatesFormModel.Flag"/>) -- never a second copy of a rule, so it cannot drift; a test
/// holds every value it shows to its reader. No number on this page is written in it: each comes from a reader.
/// </summary>
public sealed class AssumptionsModel(SettingsCatalog catalog, ISettingsStoreReader settings, ICiLifecycleRulesReader lifecycle, RiskFactorStore riskFactors,
    TaggingStore tagging, INotOnboardedViews notOnboarded, ILogger<AssumptionsModel> log) : PageModel
{
    public IReadOnlyList<Assumptions.Section> View { get; private set; } = Array.Empty<Assumptions.Section>();
    /// What could not be read (each then shows the shipped default, said).
    public List<string> Notes { get; } = new();

    public async Task OnGetAsync(CancellationToken ct)
    {
        IReadOnlyList<SettingRow> rows = Array.Empty<SettingRow>();
        try { rows = (await settings.ReadSettingsAsync(ct)).Rows; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the settings could not be read for the assumptions");
            Notes.Add("The stored settings could not be read (" + ex.Message + "): the shipped defaults are shown; a value you changed may differ.");
        }
        var rules = CiLifecycleDefinitions.Defaults;
        try { rules = await lifecycle.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the lifecycle rules could not be read for the assumptions"); Notes.Add("The lifecycle settings could not be read: the defaults are shown."); }
        var bands = RiskRatingBands.Default;
        try { bands = RiskRatingThresholds.InForce((await riskFactors.ListAsync(ct))?.FirstOrDefault(r => r.ItemKey == RiskRatingBands.ItemKey)); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the risk rating could not be read for the assumptions"); Notes.Add("The risk rating thresholds could not be read: the shipped thresholds are shown."); }
        JsonObject? gates = null;
        try { gates = TaggingStore.Parse((await tagging.LoadAsync(ct)).ConfigBody); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the asset tagging gates could not be read for the assumptions"); Notes.Add("The asset tagging switches could not be read: they are shown as off (the default)."); }
        long? waiting = null;
        try { if ((await notOnboarded.ReadAsync(null, 1, NotOnboarded.Sizes[0], ct)).Data is { Ready: true } d) waiting = d.Devices; }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogInformation(ex, "the devices not onboarded could not be counted for the assumptions"); }
        View = Assumptions.Build(new Assumptions.Inputs(catalog, rows, rules, bands, gates, waiting));
    }
}

/// <summary>THE assumptions, built from the readers' answers (PURE: a test gives it its own answers).</summary>
public static class Assumptions
{
    /// What the readers answered.
    public sealed record Inputs(SettingsCatalog Catalog, IReadOnlyList<SettingRow> Rows, CiLifecycleRules Lifecycle, RiskRatingBands Rating, JsonObject? Gates, long? NotOnboarded);

    /// One assumption: what it is (plain words), the value in force, where it is set (a link) and, for a setting, its name
    /// and whether it is the shipped default.
    public sealed record Line(string Key, string What, string Value, string? Href = null, string? HrefText = null, string? Setting = null, bool? IsDefault = null);

    public sealed record Section(string Id, string Title, string Lede, IReadOnlyList<Line> Lines);

    /// The views that show ACTIVE assets unless a person chooses otherwise (their lifecycle default is
    /// <see cref="CiLifecycleDefinitions.DefaultFilter"/>; a test holds each page to it).
    public static readonly IReadOnlyList<(string Key, string Page, string What)> ActiveViews =
    [
        ("cis", "/Cis/Index", "The CI list (Active CIs) and its tab count"),
        ("tiers", "/Tiers/Index", "The tier board: its tiles and its grid"),
        ("notonboarded", "/Cis/NotOnboarded", "Active devices not onboarded in Defender"),
        ("keyfigures", "/Management/Report", "The executive key figures: every count of assets and of their findings"),
    ];

    /// The asset tagging switches that leave discovered devices out automatically (asset tagging gates; off unless set).
    public static readonly IReadOnlyList<(string Gate, string What)> DiscoveredDeviceGates =
    [
        ("AutoExcludeRules.ExcludeCanBeOnboarded", "Exclude devices that can be onboarded"),
        ("AutoExcludeRules.ExcludeInsufficientInfo", "Exclude devices Defender has too little information about"),
        ("AutoExcludeRules.ExcludeUnsupported", "Exclude devices Defender does not support"),
    ];

    /// The settings that decide which accounts and applications are assets.
    public static readonly IReadOnlyList<string> InclusionSettings =
    [
        "SI_DisabledAssets_Collect", "SI_DisabledAssets_Correlate", "SI_DisabledAssets_RiskAnalysis", "SI_DisabledAssets_Connectors",
        "SI_IncludeFirstPartySpns", "SI_IncludeInactive_Identity", "SI_IncludeInactive_Endpoint",
    ];

    public static string EditHref(string setting) => "/Admin/Settings/Edit?name=" + Uri.EscapeDataString(setting);

    private static Line Setting(Inputs i, string key, string name, string? what = null)
    {
        var l = LifecycleModel.LineOf(i.Catalog, i.Rows, name);
        return l is null
            ? new Line(key, what ?? name, "not in this release's settings", null, null, name, null)
            : new Line(key, what ?? l.Setting.Title, l.Value, EditHref(name), "Change", name, l.IsDefault);
    }

    private static string Days(int n) => CiLifecycleRules.Days(n);

    public static IReadOnlyList<Section> Build(Inputs i)
    {
        var r = i.Lifecycle;
        var classes = CiColumns.FieldClasses.Values.SelectMany(c => c).Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(c => Array.IndexOf(ClassOrder, c) is var x && x >= 0 ? x : ClassOrder.Length).Select(ClassWords).ToList();
        var active = CiLifecycleDefinitions.Label(CiLifecycleDefinitions.DefaultFilter);

        var assets = new List<Line>
        {
            new("asset.classes", "The kinds of asset (CI classes) SecurityInsight builds from your sources", string.Join(", ", classes), "/Cis/Index", "The CIs"),
            new("asset.discovered", "A device Defender only DISCOVERED on the network (not onboarded) is an asset and counts: a real device that is not protected. Only while it is active -- a not seen or retired discovered device never counts. Exclude one by tag.",
                "counted while active (seen within " + Days(r.SeenWithinDays) + ")"
                + (i.NotOnboarded is { } n ? "; " + Fmt.Int(n) + " active device" + (n == 1 ? " is" : "s are") + " not onboarded now" : ""),
                "/Cis/NotOnboarded", "Active devices not onboarded"),
        };
        foreach (var (gate, what) in DiscoveredDeviceGates)
            assets.Add(new("asset.gate." + gate, what + " (an automatic exclusion tag)", GatesFormModel.Flag(i.Gates, gate) ? "on" : "off", "/AssetTagging/Index", "Asset tagging"));
        foreach (var s in InclusionSettings) assets.Add(Setting(i, "asset.setting." + s, s));

        var life = new List<Line>
        {
            Setting(i, "lifecycle.seen", CiLifecycleDefinitions.SeenWithinSetting, "Active: a source saw the asset within (the seen window)") with { Value = Days(r.SeenWithinDays) },
            Setting(i, "lifecycle.grace", CiLifecycleDefinitions.DefaultGraceSetting, "Not seen, then retired after (the general grace period)") with { Value = Days(r.DefaultGraceDays) },
        };
        foreach (var (cat, words) in CiLifecycleDefinitions.CategoryWords)
        {
            var setting = CiLifecycleDefinitions.CategorySettings.First(c => c.Category == cat).Setting;
            life.Add(Setting(i, "lifecycle.grace." + cat, setting, "Grace period of " + words) with { Value = Days(r.Grace(cat)) });
        }
        foreach (var s in r.States) life.Add(new("lifecycle.state." + s.Value, s.Label, s.Definition));
        foreach (var w in r.Warnings) life.Add(new("lifecycle.warning", "A setting was not used as written", w));

        var views = ActiveViews.Select(v => new Line("views." + v.Key, v.What, active + " (clear the lifecycle filter to include not seen and retired)", v.Page, "Open")).ToList();

        var tier = new List<Line>
        {
            new("tier.order", "Who decides a CI's tier, first that applies wins",
                string.Join(" -> ", new[] { "override", "rule", "tag", "default" }.Select(CiColumns.TierSetByText)), "/Tiers/Index", "Tier board"),
            new("tier.override", "A manual override (who, why, until) wins until it ends", CiColumns.TierSetByText("override"), "/Cis/Overrides", "Manual overrides"),
            new("tier.rule", "An SI rule: the lowest tier any SI rule claims (a true Tier 0 is never buried)", CiColumns.TierSetByText("rule"), "/RulePacks/Index", "Rule packs"),
            new("tier.tag", "Your tag counts only when no SI rule decides (a Defender tag such as ...--tier0--SI)", CiColumns.TierSetByText("tag"), "/AssetTagging/Index", "Asset tagging"),
            new("tier.default", "The default tier applies only when nothing claims one", CiColumns.TierSetByText("default"), "/RulePacks/Index", "Rule packs"),
        };

        var fixedLines = new List<Line>
        {
            new("fixed.meaning", "\"Fixed\" means remediated: the source stopped reporting the finding on an asset it still sees", "remediated only"),
            new("fixed.retired", "A finding of a retired asset closes as \"asset retired\"; one no longer monitored as \"no longer monitored\"", "never counted as fixed (fixed counts, mean time to fix, vulnerabilities over time)"),
        };

        var rating = new List<Line>
        {
            new("rating.critical", "Critical: a finding scoring at least", Fmt.Num(i.Rating.Critical, 0), "/Admin/Settings/RiskRating", "Change"),
            new("rating.high", "High: at least", Fmt.Num(i.Rating.High, 0) + " (below " + Fmt.Num(i.Rating.Critical, 0) + ")", "/Admin/Settings/RiskRating", "Change"),
            new("rating.moderate", "Moderate: at least", Fmt.Num(i.Rating.Moderate, 0) + " (below " + Fmt.Num(i.Rating.High, 0) + ")", "/Admin/Settings/RiskRating", "Change"),
            new("rating.low", "Low: less than Moderate", "below " + Fmt.Num(i.Rating.Moderate, 0), "/Admin/Settings/RiskRating", "Change"),
        };

        // the accepted lifecycle and the days to fix: the Lifecycle tab's own sections, read the same way
        var accepted = LifecycleModel.Sections.Where(s => s.Id is "accepted" or "deadlines")
            .SelectMany(s => s.Settings.Select(n => Setting(i, s.Id + "." + n, n))).ToList();

        var caveats = new List<Line>
        {
            new("caveat.notonboarded", "A device not onboarded in Defender has no Defender vulnerability data", "0 missing patches = NOT MEASURED, not patched", "/Cis/NotOnboarded", "Active devices not onboarded"),
            new("caveat.unknown", "A field the build cannot decide for an asset (unknown) is never a finding", "unknown = not measured"),
            new("caveat.absent", "An asset or field a source no longer reports is never read as fixed", "absence = not measured"),
        };

        return
        [
            new("assets", "What counts as an asset", "The kinds of asset, which discovered devices count, and the settings that leave accounts and applications in or out.", assets),
            new("lifecycle", "Active, not seen, retired", "How long an asset counts as active, and how long an unseen one is kept before it is retired -- with the values in force.", life),
            new("views", "Views that show active assets by default", "These views open on active assets and say so; a person chooses not seen or retired with the lifecycle filter.", views),
            new("tier", "How a tier is decided", "Who decided each CI's tier is shown on it (the \"decided by\" filter).", tier),
            new("fixed", "What \"fixed\" means", "Only a remediated finding is fixed; a retired or no longer monitored asset closes its findings without counting them as fixed.", fixedLines),
            new("rating", "The risk rating", "The thresholds a finding's score is rated with (Low is less than Moderate).", rating),
            new("accepted", "Accepted lifecycle and days to fix", "How long a finding may be open before the Protection Score's \"within Accepted Lifecycle\" view counts it, and the due date of a finding by severity.", accepted),
            new("caveats", "Not measured", "What a number cannot tell you.", caveats),
        ];
    }

    private static readonly string[] ClassOrder = ["device", "identity", "cloud_resource", "public_ip"];

    private static string ClassWords(string c) => c switch
    {
        "device" => "devices",
        "identity" => "identities",
        "cloud_resource" => "cloud resources",
        "public_ip" => "public IP addresses",
        _ => c.Replace('_', ' '),
    };
}
