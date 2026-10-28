using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.EnvReport;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// The environment report (framework ENV-REPORT-1, SI #482) -- Admin and SuperAdmin (the folder's Admin rule): the
/// architecture and security facts of this install, read live at report time, print-designed (cover, contents, page
/// numbers, "Confidential" header) with Export PDF (the browser's print to PDF, A4, through the print stylesheet) and
/// Export JSON (the same data, for audits and diffing). Names, ids and states only -- never a secret value.
/// </summary>
public sealed class EnvironmentReportModel(EnvironmentReportService reports, ILogger<EnvironmentReportModel> log) : PageModel
{
    public EnvironmentReport? Report { get; private set; }
    public string? Error { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        try { Report = await reports.BuildAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogError(ex, "environment report"); Error = "The environment report could not be built: " + ex.Message; }
    }

    /// Export JSON: the same facts as the page.
    [Audited("report.environment.export")]
    public async Task<IActionResult> OnGetJsonAsync(CancellationToken ct)
    {
        var r = await reports.BuildAsync(ct);
        if (AuditScope.Current is { } a) { a.Target = "/Admin/EnvironmentReport/json"; a.Rows = r.Findings.Count; }
        return File(Encoding.UTF8.GetBytes(r.ToJson()), "application/json", $"securityinsight-environment-report-{r.ReadUtc:yyyyMMdd-HHmm}.json");
    }
}
