using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core;
using SI.Management.Core.ProData;
using SI.Management.Web.RiskExec;

namespace SI.Management.Web.Pages.Management;

/// <summary>
/// Overview > Top 10 asset drilldown (#290): the mail's top 10 assets (the kept view, #288 -- same order, same scores),
/// each with its findings in the newest collection grouped by domain and category with severity counts, and its
/// highest-risk findings, each linked.
/// </summary>
public sealed class DrilldownModel(ExecViewLoader loader, ILogger<DrilldownModel> log) : SI.Management.Web.Columns.DataViewPageModel
{
    [BindProperty(SupportsGet = true)] public string? Grain { get; set; }
    public ExecViewLoader.Loaded? Data { get; private set; }
    public IReadOnlyDictionary<string, string> Keys { get; private set; } = new Dictionary<string, string>();
    public ExecAssetFindings Findings { get; private set; } = new([], []);
    public QueryResult<ExecAssetFindings>? FindingsQuery { get; private set; }
    public string? FindingsNote { get; private set; }
    public IReadOnlyList<ExecTopAsset> Assets { get; private set; } = [];
    /// #863: the list is the database's (the run kept none), and what the page says about it.
    public bool FromDatabase { get; private set; }
    public string? ListNote { get; private set; }

    public static readonly IReadOnlyList<string> Severities = ["Very High", "High", "Medium", "Low"];

    public async Task OnGetAsync(CancellationToken ct)
    {
        Data = await loader.LoadAsync(HttpContext, Grain, ct);
        Grain = Data.View.Grain;
        if (Data.View.Figures is not { } f) return;
        // #863: the run's own top 10, or -- a view without a list -- the riskiest active CIs from the database (said on the page)
        var top = await loader.TopAssetsAsync(f, 10, ct);
        Assets = top.Assets; Keys = top.Keys; FromDatabase = top.FromDatabase; ListNote = top.Note;
        var ci = Assets.Select(CiKey).Where(k => k is not null).Select(k => k!).ToList();
        if (ci.Count == 0) return;
        try { FindingsQuery = await loader.Views.AssetFindingsAsync(ci, 5, ct); Findings = FindingsQuery.Data; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "drilldown findings");
            FindingsNote = "The assets' findings could not be read from the Pro database right now; the list from the report is shown.";
        }
    }

    // #589: the ten assets as THE data table above their cards (the CI with its context, the chooser, the exports)
    protected override Task LoadForExportAsync(CancellationToken ct) => OnGetAsync(ct);

    protected override IReadOnlyList<SI.Management.Web.Columns.DataTable> BuildTables() =>
        new[] { ExecTables.TopAssets(Assets, Keys, Link, "drilldown", "management-drilldown", "Top 10 assets", FromDatabase ? RowCiKey.CiId : RowCiKey.AssetKey) };

    public string? CiKey(ExecTopAsset a) => a.AssetId is { } id && Keys.TryGetValue(id.ToLowerInvariant(), out var k) ? k : null;
    public string Link(ExecTopAsset a) => FromDatabase ? ExecViewLoader.CiLink(a) : ExecViewLoader.AssetLink(a, Keys);

    /// A severity in one of the four columns (Critical counts as Very High, Medium-High as High -- the mail's buckets).
    public static string Bucket(string severity) => severity.Trim().ToLowerInvariant() switch
    {
        "very high" or "critical" => "Very High",
        "high" or "medium-high" => "High",
        "medium" => "Medium",
        "low" => "Low",
        _ => "Other",
    };
}
