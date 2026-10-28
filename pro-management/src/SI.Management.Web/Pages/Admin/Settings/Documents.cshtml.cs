using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.Admin.Settings;

/// The structured settings in the Pro database (cfg.Document: exclusions, weights, tier rules, and any kind the schema
/// adds), and the active exemptions (cfg.Exemption) with "revoke" -- every change staged for Review &amp; commit.
public sealed class DocumentsModel : PageModel
{
    private readonly DocumentRepository _docs;
    private readonly ExemptionRepository _exemptions;
    private readonly ChangeService _changes;
    private readonly ILogger<DocumentsModel> _log;

    public DocumentsModel(DocumentRepository docs, ExemptionRepository exemptions, ChangeService changes, ILogger<DocumentsModel> log)
    { _docs = docs; _exemptions = exemptions; _changes = changes; _log = log; }

    public IReadOnlyList<DocumentRow> Documents { get; private set; } = Array.Empty<DocumentRow>();
    public IReadOnlyList<ExemptionRow> Exemptions { get; private set; } = Array.Empty<ExemptionRow>();
    public List<string> Errors { get; } = new();
    public string ExemptionQuery => ExemptionRepository.ActiveSql;
    public string DocumentQuery => DocumentRepository.ListSql;

    [BindProperty] public string? ExemptionId { get; set; }
    [BindProperty] public string? Describe { get; set; }
    [BindProperty] public string? Reason { get; set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        try { Documents = await _docs.ListAsync(null, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogError(ex, "cfg.Document"); Errors.Add("The documents could not be read: " + ex.Message); }
        try { Exemptions = (await _exemptions.ActiveAsync(null, 1000, ct)).Rows; }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogError(ex, "cfg.Exemption"); Errors.Add("The exemptions could not be read: " + ex.Message); }
    }

    [SI.Management.Web.Audit.Audited("exemption.revoke.stage")]
    public async Task<IActionResult> OnPostRevokeAsync(CancellationToken ct)
    {
        var (c, why) = ChangeService.NewRevoke(ExemptionId ?? "", Describe ?? ExemptionId ?? "", Reason ?? "");
        if (c is null) { TempData["toast"] = "Not staged: " + string.Join("; ", why); TempData["toastKind"] = "error"; return RedirectToPage(); }
        await _changes.StageAsync(User, c, ct);
        TempData["toast"] = "Staged: " + c.Title + ". Nothing is written until you review and commit.";
        return RedirectToPage();
    }
}
