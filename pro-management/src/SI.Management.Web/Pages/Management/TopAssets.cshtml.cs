using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core;
using SI.Management.Core.ProData;
using SI.Management.Web.RiskExec;

namespace SI.Management.Web.Pages.Management;

/// <summary>
/// Overview > Top 50 risky assets (#290): the Risk Analysis mail's "Top N risky assets" section -- the same list, the same
/// numbers (the kept view, #288), Summary or Detailed with the agreement mode, each asset linked to its CI.
/// #863: a kept view without a list (Risk Analysis built it only with the AI summary on) is never "Top 0": the page says the
/// AI summary is off (and how to turn it on), and lists the riskiest ACTIVE CIs from the database in the mail's order.
/// </summary>
public sealed class TopAssetsModel(ExecViewLoader loader) : SI.Management.Web.Columns.DataViewPageModel
{
    [BindProperty(SupportsGet = true)] public string? Grain { get; set; }
    public ExecViewLoader.Loaded? Data { get; private set; }
    public IReadOnlyDictionary<string, string> Keys { get; private set; } = new Dictionary<string, string>();
    /// The list shown: the run's own, or (#863) the database's.
    public IReadOnlyList<ExecTopAsset> Assets { get; private set; } = [];
    public bool FromDatabase { get; private set; }
    public string? ListNote { get; private set; }
    public QueryResult<IReadOnlyList<ExecTopAsset>>? DatabaseQuery { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        Data = await loader.LoadAsync(HttpContext, Grain, ct);
        Grain = Data.View.Grain;
        if (Data.View.Figures is { } f)
        {
            var t = await loader.TopAssetsAsync(f, 50, ct);
            Assets = t.Assets; FromDatabase = t.FromDatabase; ListNote = t.Note; Keys = t.Keys; DatabaseQuery = t.Query;
        }
        if (!Exporting) await LoadTablesAsync(ct);
    }

    public string Link(ExecTopAsset a) => FromDatabase ? ExecViewLoader.CiLink(a) : ExecViewLoader.AssetLink(a, Keys);

    // #589: the list as THE data table (the CI of each asset with its context, the chooser, the exports)
    protected override Task LoadForExportAsync(CancellationToken ct) => OnGetAsync(ct);

    protected override IReadOnlyList<SI.Management.Web.Columns.DataTable> BuildTables() =>
        Data?.View.Figures is not null
            ? new[] { ExecTables.TopAssets(Assets, Keys, Link, "topassets", "management-topassets", "Top risky assets", FromDatabase ? RowCiKey.CiId : RowCiKey.AssetKey) }
            : Array.Empty<SI.Management.Web.Columns.DataTable>();
}