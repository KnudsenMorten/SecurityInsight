using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.RiskExec;

namespace SI.Management.Web.Pages.Management;

/// <summary>
/// Overview > Executive report > Key figures (#636, owner 2026-10-19: "we need to have some core stats relevant for mgmt
/// like Missing patches (cve's) on windows vs. linux, servers vs clients and others ... present them in the executive
/// report" / "one could be report and other could be click to see the stats"): ONE page to READ, top to bottom -- the scope
/// line, the headline figures, then the blocks in a fixed order (patching, exposure, coverage, identity, cloud, what to do
/// first, trend), each with "change since the last report". Export PDF prints it; the scheduled management mail carries the
/// same blocks (a choice per report, default all). Reads the SAME stored figures as the Executive overview.
/// </summary>
public sealed class ReportModel : PageModel
{
    [BindProperty(SupportsGet = true)] public string? C { get; set; }
    /// #818: the run the figures are compared with (null = the run before the shown one).
    [BindProperty(SupportsGet = true)] public string? Vs { get; set; }
    public ExecutiveFigures Figures { get; private set; } = new() { Missing = ExecutiveFigures.NotBuilt };

    /// The query of a link that keeps the shown run and the run compared with.
    public string RunQuery => (C is null ? "" : "c=" + Uri.EscapeDataString(C) + "&") + (Vs is null ? "" : "vs=" + Uri.EscapeDataString(Vs) + "&");

    public RunPickerModel Picker() => new(Figures, "/Management/Report", ViewKey == "technical" ? new[] { ("view", "technical") } : Array.Empty<(string, string)>());

    /// The protection score view: lifecycle (default) | technical -- both headline numbers stay visible either way.
    [BindProperty(SupportsGet = true)] public string? View { get; set; }
    public string ViewKey => ExecutiveFigures.ProtectionView(View);

    public IReadOnlyList<ReportBlock> Blocks => Figures.ReportBlocks(protectionView: ViewKey);

    public async Task OnGetAsync(CancellationToken ct) => Figures = await ExecutiveFigures.LoadAsync(HttpContext.RequestServices, C, ct, Vs);
}
