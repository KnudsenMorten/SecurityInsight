using SI.Management.Core.ProData;
using SI.Management.Web.Navigation;
using SI.Management.Web.Pages.Collection;

namespace SI.Management.Web.Pages.Remediations;

/// <summary>
/// The Remediations menu (#636, owner 2026-10-13: "for remediation it could be a list of top 10 things to fix where you have
/// two angles: most imporant assets, and security findings remediations which can be solved by large scale operatons").
/// ONE REMEDIATION = THE SAME FIX APPLIED TO MANY ASSETS (one update, one configuration change, one software upgrade), built
/// per collection by the data sync (sidata.Remediation / RemediationAsset, SI-DataRemediation.ps1; the key rule is in
/// docs/DESIGN.md). Reporting only: nothing here changes a source; the place where actions (buttons, agents) come later.
/// A fix opens its findings in Security recommendations > Detailed.
/// </summary>
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Views, Off = true)]
public abstract class RemediationPageModel(ICollectionViews views, ILogger log) : CollectionPageModel(views, log)
{
    public override bool CompactFrame => true;
    /// #855: the remediations are the to-do list of active CIs (built over them: a retired CI's findings close as retired, a not
    /// seen CI is not worked on until it is seen again) -- said on the page, no lifecycle choice.
    protected override string LifecycleWords(SI.Management.Core.ProData.CiLifecycleRules? rules) =>
        SI.Management.Core.ProData.LifecycleFilter.ActiveOnlyWords(rules ?? SI.Management.Core.ProData.CiLifecycleDefinitions.Defaults, "fixes and findings");
    /// The collection's remediations are not built yet (the page says so).
    public bool Preparing { get; private set; }

    public const string PreparingText = "The remediations of this collection are being prepared: the data sync builds them from the Detailed findings after the collection's context. Until then every finding is in Security recommendations, Detailed.";

    protected abstract GridPlan RemediationPlan(ViewCollection current);

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        var rec = HttpContext?.RequestServices.GetService(typeof(IRecommendationViews)) as IRecommendationViews;
        RecommendationState? state = null;
        if (rec is not null)
        {
            try { var s = await rec.StateAsync(Current!.CollectionId, ct); state = s.Data; Queries.Add(QueryInfo.From(s, "What is built for this collection")); }
            catch (Exception ex) when (ex is not OperationCanceledException and not ArgumentException) { Log.LogWarning(ex, "remediation state"); }
        }
        if (state is not { RemediationAt: not null })
        {
            Preparing = true;
            Notice ??= PreparingText;
            return null;
        }
        return RemediationPlan(Current!);
    }

    /// A fix opens the findings it closes in Detailed; an asset opens its CI.
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) => column switch
    {
        "Fix" or "Findings" => Cell(row, "RemediationKey") is { } k ? ViewLink(NamedViews.DetailedPage, ("fix", k)) : null,
        "AssetName" => Cell(row, "AssetKey") is { } a ? ViewLink("/Collection/Asset", ("key", a)) : null,
        _ => null,
    };

    protected static readonly IReadOnlyList<string> Kinds5 = ["patch", "configuration", "upgrade", "policy", "manual"];
}

public sealed class IndexModel(ICollectionViews views, ILogger<IndexModel> log) : RemediationPageModel(views, log)
{
    public override string PagePath => "/Remediations/Index";
    public override string Heading => "All remediations";
    public override string Lede => "One row per fix: the same update, configuration change or upgrade applied to many assets -- its kind, the effort, how many assets it reaches, how many findings it closes and how much risk it removes, its owner and status. Open a fix for the findings it closes.";
    public override string ExportName => "remediations";
    protected override GridPlan RemediationPlan(ViewCollection current) => new(RecommendationSql.Remediations, new Dictionary<string, object?> { ["CollectionId"] = current.CollectionId },
        current.Version + "|rem", new Dictionary<string, IReadOnlyList<string>> { ["Kind"] = Kinds5, ["Effort"] = ["Low", "Moderate", "High"], ["Status"] = ["open", "exempted"], ["Tier"] = TierValues, ["HasExploit"] = Flags });
}

public sealed class TopFixesModel(ICollectionViews views, ILogger<TopFixesModel> log) : RemediationPageModel(views, log)
{
    public const int Top = 10;
    public override string PagePath => "/Remediations/TopFixes";
    public override string Heading => "Top 10 fixes by reach";
    public override string Lede => "The fixes that close the most in one operation: the 10 open fixes that reach the most assets (then remove the most risk) -- one update, one configuration change or one upgrade each.";
    public override string ExportName => "top-fixes";
    protected override GridPlan RemediationPlan(ViewCollection current) => new(RecommendationSql.TopFixes, new Dictionary<string, object?> { ["CollectionId"] = current.CollectionId, ["Top"] = Top },
        current.Version + "|remtop", new Dictionary<string, IReadOnlyList<string>> { ["Kind"] = Kinds5, ["Effort"] = ["Low", "Moderate", "High"], ["Tier"] = TierValues, ["HasExploit"] = Flags });
}

public sealed class TopAssetsModel(ICollectionViews views, ILogger<TopAssetsModel> log) : RemediationPageModel(views, log)
{
    public const int Top = 10;
    // owner 2026-10-21 ("bug": 26,196 rows on "Top 10 assets to fix"): a large asset has thousands of fixes -- the page shows
    // each of the 10 assets with its biggest fixes only; the asset's own page lists every fix
    public const int FixesPerAsset = 5;
    public override string PagePath => "/Remediations/TopAssets";
    public override string Heading => "Top 10 assets to fix";
    public override string Lede => "The 10 most important assets with open findings -- Tier 0 first, then the most weighted risk -- and what to do on each: its 5 fixes that remove the most risk. Click an asset's name to see every fix on it.";
    public override string ExportName => "top-assets";
    protected override GridPlan RemediationPlan(ViewCollection current) => new(RecommendationSql.TopAssets, new Dictionary<string, object?> { ["CollectionId"] = current.CollectionId, ["Top"] = Top, ["TopFixes"] = FixesPerAsset },
        current.Version + "|remassets", new Dictionary<string, IReadOnlyList<string>> { ["Kind"] = Kinds5, ["Tier"] = TierValues }, "AssetRank", false);
}
