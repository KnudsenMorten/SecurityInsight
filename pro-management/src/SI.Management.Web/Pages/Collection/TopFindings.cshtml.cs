using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.RiskExec;

namespace SI.Management.Web.Pages.Collection;

/// <summary>
/// Overview > Top 50 critical findings (#290): the Risk Analysis mail's "Top N critical findings" -- the same list and
/// numbers (the kept view, #288; Summary or Detailed with the agreement mode) -- as a grid of the collection, so the
/// shared action bar acts on the findings each row stands for (every finding of that CVE / configuration in the
/// collection). The collection adds how many findings of each it holds and, for a CVE, when it was first seen open.
/// </summary>
public sealed class TopFindingsModel(ICollectionViews views, ExecViewLoader loader, ILogger<TopFindingsModel> log) : CollectionPageModel(views, log)
{
    [BindProperty(SupportsGet = true)] public string? Grain { get; set; }
    public ExecViewLoader.Loaded? Exec { get; private set; }

    public override string PagePath => "/Collection/TopFindings";
    public override string Heading => "Top 50 critical findings";
    public override string Lede => "The highest-risk findings of the last Risk Analysis run, as the mail lists them (by Weighted Risk Score), with the findings each one has in this collection. Select rows to act on every finding behind them.";
    public override string? ActionSource => SI.Management.Web.Actions.SelectionSources.Rows;
    public override IEnumerable<(string Key, string Value)> ExtraState() => Grain is null ? Array.Empty<(string, string)>() : new[] { ("grain", Grain.ToLowerInvariant()) };

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        Exec = await loader.LoadAsync(HttpContext, Grain, ct);
        Grain = Exec.View.Grain;
        if (Exec.View.Figures is not { } f) return null;
        var keys = KeysJson(f);
        return new GridPlan(CollectionViewSql.TopIssues, new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId, ["Keys"] = keys },
            Current.Version + "|top|" + f.Grain + "|" + f.FiguresFromGrain + "|" + f.GeneratedAt.ToUnixTimeSeconds());
    }

    /// The kept view's top findings as the grid's source rows (the mail's own numbers).
    public static string KeysJson(ExecSnapshot f) => JsonSerializer.Serialize(f.TopFindings.Where(x => x.ConfigurationId.Length > 0).Select(x => new Dictionary<string, object?>
    {
        ["k"] = x.ConfigurationId, ["r"] = x.Rank, ["n"] = x.Name, ["s"] = x.Severity, ["d"] = x.Domain,
        ["c"] = string.Join(" / ", new[] { x.Category, x.Subcategory }.Where(s => s.Length > 0)),
        ["a"] = x.AffectedAssetCount, ["w"] = Math.Round(x.WeightedRiskScore), ["t"] = Math.Round(x.TotalRiskScore),
        ["x"] = string.Join(", ", x.TopAffectedAssets.Select(t => t.Asset)),
    }));

    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) =>
        column is "Name" or "IssueKey" && Cell(row, "IssueKey") is { } k
            ? ViewLink("/Collection/Rows", (k.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) ? "f.Cve" : "q", k))
            : null;
}
