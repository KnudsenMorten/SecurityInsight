using Microsoft.AspNetCore.Mvc.RazorPages;
using Sia.Web.Services;

namespace Sia.Web.Pages;

/// <summary>
/// The DEFAULT landing surface: the board-ready executive management view.
/// Plain language, chart-led, no KQL/jargon. Renders server-side from the
/// AnalyzerService so it works without client JS (charts enhance progressively).
/// </summary>
public sealed class ExecModel : PageModel
{
    private readonly AnalyzerService _svc;
    public ExecModel(AnalyzerService svc) => _svc = svc;

    public ExecViewModel View { get; private set; } = null!;

    /// <summary>The reporting period for the period-over-period panel (e.g. "quarter" =
    /// "since last board meeting"); bound from <c>?period=</c>. Null defaults to the quarter.</summary>
    [Microsoft.AspNetCore.Mvc.BindProperty(SupportsGet = true)]
    public string? Period { get; set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        View = await _svc.GetExecAsync(Period, ct);
    }
}
