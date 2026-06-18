using Microsoft.AspNetCore.Mvc.RazorPages;
using Sia.Web.Services;

namespace Sia.Web.Pages;

/// <summary>
/// The BOARD-DECK export surface: a clean, single-page, print/PDF-friendly executive
/// handout rendered from the SAME grounded <see cref="ExecViewModel"/> as the dashboard.
/// "Print / Save as PDF" yields a tidy one-page board handout. Same reporting period
/// support as /exec (?period=) so the handout matches the dashboard the CIO was viewing.
/// </summary>
public sealed class BoardModel : PageModel
{
    private readonly AnalyzerService _svc;
    public BoardModel(AnalyzerService svc) => _svc = svc;

    public ExecViewModel View { get; private set; } = null!;

    /// <summary>The reporting period the board summary snaps to (e.g. "quarter" = "since
    /// last board meeting"); bound from <c>?period=</c>. Null defaults to the quarter.</summary>
    [Microsoft.AspNetCore.Mvc.BindProperty(SupportsGet = true)]
    public string? Period { get; set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        View = await _svc.GetExecAsync(Period, ct);
    }
}
