namespace SI.Management.Web.Pages.Collection;

/// <summary>
/// At risk (/Collection/Assets): its layouts are stored under the view key it had before every view got the chooser, so a
/// layout saved then still applies. The chooser, the extra columns and "Export all columns" are the base's
/// (<see cref="CollectionPageModel"/>, #589) -- the same on every collection view.
/// </summary>
public sealed partial class AssetsModel
{
    public const string View = "collection-assets";
    protected override string LayoutKey(SI.Management.Core.ProData.GridSpec s) => View;

    /// The scope line of this view: the CIs with at least one finding in the run, of the lifecycle chosen (#855: active by
    /// default -- the per-CI rows carry each CI's lifecycle).
    protected override string LifecycleWords(SI.Management.Core.ProData.CiLifecycleRules? rules) =>
        "the CIs with at least one finding in that run: " + base.LifecycleWords(rules);
}
