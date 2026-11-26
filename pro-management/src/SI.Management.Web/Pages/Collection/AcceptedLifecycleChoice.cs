using SI.Management.Core.ProData;
using SI.Management.Web.RiskExec;

namespace SI.Management.Web.Pages.Collection;

/// <summary>
/// #1355 (owner 2026-11-24: "i would like a filter on the security recommendations views (summary, detailed) to select actual
/// risk vs. within accepted lifetime. default is actual risk (all)"): THE WALL BOARD'S CHOICE on Security recommendations >
/// Summary and Detailed -- the same two views, in the same order and words (<see cref="ExecutiveFigures.ProtectionViews"/>:
/// "Within Accepted Lifecycle" | "Actual Risks") under the same label ("The table below shows"), with the wall board's own
/// sentence of the accepted lifecycle in force (<see cref="AcceptedLifecycle.Line"/>).
/// <para>"Actual Risks" = every open finding, the DEFAULT (no parameter: the rows as before). "Within Accepted Lifecycle"
/// (?risk=lifecycle) = only the findings the wall board's "Within Accepted Lifecycle" view counts, as the key figures stored
/// them (sidata.FindingLifecycleRisk; the Summary reads their own groupings). A collection that does not have them (figured
/// before they were stored) does not offer the choice -- the parameter is then ignored and every finding is shown.</para>
/// </summary>
public sealed record AcceptedLifecycleChoice(bool Lifecycle, string Line, IReadOnlyList<AcceptedLifecycleChoice.Option> Options)
{
    /// One of the two views: the wall board's code and label, the link that chooses it, whether it is in force.
    public sealed record Option(string Code, string Label, string Href, bool Chosen);

    /// The query-string key (the named views already use "view").
    public const string Parameter = "risk";
    /// The wall board's code of the narrowed view (ExecutiveFigures.ProtectionViews); "Actual Risks" has no parameter.
    public const string LifecycleCode = "lifecycle";
    /// The wall board's label above the choice, word for word.
    public const string Label = "The table below shows";

    /// The request asks for "Within Accepted Lifecycle".
    public static bool Asked(string? value) => string.Equals(value?.Trim(), LifecycleCode, StringComparison.OrdinalIgnoreCase);

    /// The choice as shown: <paramref name="href"/>(the parameter's value, null = none) is the page's own link with it.
    public static AcceptedLifecycleChoice Of(bool lifecycle, string line, Func<string?, string> href) =>
        new(lifecycle, line, ExecutiveFigures.ProtectionViews
            .Select(v => new Option(v.Code, v.Label, href(v.Code == LifecycleCode ? LifecycleCode : null), (v.Code == LifecycleCode) == lifecycle)).ToList());

    /// <summary>
    /// What a page offers for its collection: null = the choice is not offered (the store does not know, or the collection has
    /// no stored lifecycle rows -- or, <paramref name="grouping"/> given, that grouping's lifecycle rows are not written);
    /// else whether the narrowed view is in force. Never throws for a read that fails (the choice is then not offered).
    /// </summary>
    public static async Task<bool?> OfferedAsync(HttpContext? ctx, string collectionId, string? grouping, bool asked, List<QueryInfo> queries, ILogger log, CancellationToken ct)
    {
        if (ctx?.RequestServices.GetService(typeof(IAcceptedLifecycleViews)) is not IAcceptedLifecycleViews rec) return null;
        try
        {
            var r = await rec.AcceptedLifecycleAsync(collectionId, grouping, ct);
            if (r.Query.Length > 0) queries.Add(QueryInfo.From(r));
            var ok = grouping is null ? r.Data.Rows : r.Data.Rows && r.Data.Groups;
            return ok ? asked : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "accepted lifecycle rows state");
            return null;
        }
    }
}
