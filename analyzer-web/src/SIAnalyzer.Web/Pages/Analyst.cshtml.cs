using Microsoft.AspNetCore.Mvc.RazorPages;
using SIAnalyzer.Core.Kql;
using SIAnalyzer.Web.Services;

namespace SIAnalyzer.Web.Pages;

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

    /// <summary>How complete the underlying read was (audit #10). The analyst worklist and every
    /// figure on this page come from the same rollup as the exec view, so a partial read has to
    /// be visible here too - not only on the surface the CIO happens to open.</summary>
    public DataQuality? Quality { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        Prestaged = _svc.GetPrestaged();
        Quality = await _svc.GetDataQualityAsync(ct);
    }
}
