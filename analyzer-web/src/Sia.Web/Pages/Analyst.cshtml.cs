using Microsoft.AspNetCore.Mvc.RazorPages;
using Sia.Core.Kql;
using Sia.Web.Services;

namespace Sia.Web.Pages;

/// <summary>
/// The SECONDARY analyst surface (a separate tab, never the CIO's first screen):
/// the prompt box (exec + analyst grounding), the prestaged analyses, a guarded
/// raw-KQL box, and drill-down detail. Technical depth lives here, not on /exec.
/// </summary>
public sealed class AnalystModel : PageModel
{
    private readonly AnalyzerService _svc;
    public AnalystModel(AnalyzerService svc) => _svc = svc;

    public IReadOnlyList<PrestagedAnalysis> Prestaged { get; private set; } = Array.Empty<PrestagedAnalysis>();
    public bool AiAvailable => _svc.AiAvailable;
    public bool IsLive => _svc.IsLive;

    public void OnGet()
    {
        Prestaged = _svc.GetPrestaged();
    }
}
