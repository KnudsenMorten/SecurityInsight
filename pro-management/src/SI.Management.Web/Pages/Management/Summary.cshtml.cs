using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.MgmtReports;
using SI.Management.Web.RiskExec;

namespace SI.Management.Web.Pages.Management;

/// <summary>
/// Overview > Management summary (#291): the management summary report -- every section -- as it would be mailed now,
/// for the Summary or the Detailed report's data (the agreement mode as the executive view).
/// </summary>
public sealed class SummaryModel(ExecViewLoader loader, MgmtReportSender sender) : PageModel
{
    [BindProperty(SupportsGet = true)] public string? Grain { get; set; }
    public ExecViewLoader.Loaded? Data { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        Data = await loader.LoadAsync(HttpContext, Grain, ct);
        Grain = Data.View.Grain;
    }

    public async Task<IActionResult> OnGetHtmlAsync(CancellationToken ct)
    {
        // #636: while the Summary step is off the preview is always the Detailed report
        var grain = await loader.SummaryOnAsync(ct) ? SI.Management.Core.ProData.RiskExecGrain.Parse(Grain) ?? SI.Management.Core.ProData.RiskExecGrain.Detailed : SI.Management.Core.ProData.RiskExecGrain.Detailed;
        var r = MgmtReport.New(sender.Now) with { Grain = grain };
        return await SI.Management.Web.Pages.Reports.ManagementModel.PreviewResult(HttpContext, sender, r, ct);
    }
}
