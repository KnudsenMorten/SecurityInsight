using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.Cis;

/// <summary>
/// #1219 (4) + (5) PER-SERVER SOFTWARE EXCEPTIONS (Pro: Licensing/ProFeatures.cs -- the page and its handlers are refused
/// without a Pro licence). Without a CI: the SUGGESTIONS -- the software tier detections whose every evidence path is in a user
/// profile or a data folder, or a copy bundled in another product -- for an Admin to review (nothing changes until an Admin
/// acts; one click opens the CI), and every exception (in force, recently undone). With a CI: its software detections with
/// their evidence, and the forms. Readers see everything; every change checks Admin itself and goes through Review &amp; commit
/// (<see cref="SoftwareExceptionChanges"/>): set = "false positive on this server" with a mandatory reason, undo = soft.
/// </summary>
public sealed class SoftwareExceptionsModel : PageModel
{
    private readonly SoftwareExceptionStore _store;
    private readonly SoftwareExceptionChanges _changes;
    private readonly ChangeService _service;
    private readonly ICiViews _cis;
    private readonly ILogger<SoftwareExceptionsModel> _log;

    public SoftwareExceptionsModel(SoftwareExceptionStore store, SoftwareExceptionChanges changes, ChangeService service, ICiViews cis, ILogger<SoftwareExceptionsModel> log)
    { _store = store; _changes = changes; _service = service; _cis = cis; _log = log; }

    [BindProperty(SupportsGet = true)] public string? Ci { get; set; }
    /// Where the suggestion page starts: after this key (CI, vendor, product); none = the first page.
    [BindProperty(SupportsGet = true)] public string? Ac { get; set; }
    [BindProperty(SupportsGet = true)] public string? Av { get; set; }
    [BindProperty(SupportsGet = true)] public string? Ap { get; set; }
    [BindProperty] public string? Rule { get; set; }
    [BindProperty] public string? Vendor { get; set; }
    [BindProperty] public string? Product { get; set; }
    [BindProperty] public string? Reason { get; set; }
    /// Where a change returns to: "ci" = the CI page, else this page.
    [BindProperty] public string? Back { get; set; }

    public bool TableMissing { get; private set; }
    public string? Error { get; private set; }
    public IReadOnlyList<CiSoftwareExceptionRow> Rows { get; private set; } = Array.Empty<CiSoftwareExceptionRow>();
    public IReadOnlyList<SoftwareExceptionSuggestion> Suggestions { get; private set; } = Array.Empty<SoftwareExceptionSuggestion>();
    /// The key the next page starts after (the last key READ on this page); null = this is the last page.
    public SuggestionKey? NextSuggestions { get; private set; }
    public bool FirstSuggestionPage => Ac is null && Av is null && Ap is null;
    /// The CI (with ?ci=): its software view, and its name.
    public CiSoftwareView? View { get; private set; }
    public string? CiName { get; private set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            if (!await _store.TableExistsAsync(ct)) { TableMissing = true; return; }
            if (!string.IsNullOrWhiteSpace(Ci))
            {
                var schema = await _cis.SchemaAsync(ct);
                CiDocument doc = CiDocument.Empty;
                if (schema.Data.Ci)
                {
                    var r = await _cis.CiAsync(Ci, schema.Data, ct);
                    if (r.Data is { } d) { doc = d.Doc; CiName = d.Ci.Name; }
                }
                View = await CiSoftwareView.LoadAsync(_store, Ci.Trim(), doc, _log, ct);
                Rows = View.Exceptions;
                return;
            }
            Rows = await _store.ListAsync(null, ct);
            var after = FirstSuggestionPage ? null : new SuggestionKey(Ac ?? "", Av ?? "", Ap ?? "");
            (Suggestions, NextSuggestions) = await _store.SuggestionsAsync(after, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the per-server software exceptions could not be read");
            Error = "The per-server software exceptions could not be read from the Pro database: " + ViewerError.Text(ex);
        }
    }

    /// Admin only: stage "false positive on this server" for one rule and software on one CI.
    [SI.Management.Web.Audit.Audited("cisoftwareexception.set.stage")]
    public async Task<IActionResult> OnPostSetAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var (change, why) = await _changes.NewSetAsync(Ci, Rule, Vendor, Product, Reason, ct);
        return await StageAsync(change, why, ct);
    }

    /// Admin only: stage the undo (soft) of one exception.
    [SI.Management.Web.Audit.Audited("cisoftwareexception.remove.stage")]
    public async Task<IActionResult> OnPostRemoveAsync(long id, CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var (change, why) = await _changes.NewRemoveAsync(id, Reason, ct);
        return await StageAsync(change, why, ct);
    }

    private async Task<IActionResult> StageAsync(StagedChange? change, IReadOnlyList<string> why, CancellationToken ct)
    {
        if (change is not null)
        {
            await _service.StageAsync(User, change, ct);
            TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
            TempData["toastKind"] = "ok";
        }
        else
        {
            TempData["toast"] = "Not staged: " + string.Join("; ", why);
            TempData["toastKind"] = "error";
        }
        if (Back == "ci" && !string.IsNullOrWhiteSpace(Ci)) return Redirect("/Cis/Detail?id=" + Uri.EscapeDataString(Ci.Trim()));
        return RedirectToPage(new { ci = Ci });
    }
}
