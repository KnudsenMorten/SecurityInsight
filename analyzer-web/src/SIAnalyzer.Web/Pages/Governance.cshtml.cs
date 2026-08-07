using Microsoft.AspNetCore.Mvc.RazorPages;
using SIAnalyzer.Core.Governance;

namespace SIAnalyzer.Web.Pages;

/// <summary>
/// The governance surface (Phase 6) - the ONLY write path in SIA. Shows the exemption
/// register + audit trail + risk-accept comments, and the platform-exemption-sync controls
/// rendered visible-but-dimmed/disabled while the no-auto-revoke lock holds (a build never
/// ships an enable-able platform write). Everything else in SIA stays strictly read-only.
/// </summary>
public sealed class GovernanceModel : PageModel
{
    public GovernanceStore Store { get; }
    public GovernanceModel(GovernanceStore store) => Store = store;

    public void OnGet() { }
}
