using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.QuerySplitting;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Operations &gt; Risk Analysis query splitting (#640, owner 2026-10-13: "maybe add somewhere in the menu current bucket size
/// + reset button"). One row per report and template: how many buckets (query slices) it runs with now, what its last run
/// started and ended with, the run before, its usual count, when the count last changed, the jump flag, and what that
/// means. Readers see it; an Admin stages a ONE-TIME reset of one report, or of every report, through Review &amp; commit --
/// the next run of that template sizes the report again and consumes the reset.
/// </summary>
public sealed class QuerySplittingModel : PageModel
{
    private readonly IQuerySplittingStore _store;
    private readonly QuerySplittingChanges _builder;
    private readonly ChangeService _changes;
    private readonly ILogger<QuerySplittingModel> _log;
    public QuerySplittingModel(IQuerySplittingStore store, QuerySplittingChanges builder, ChangeService changes, ILogger<QuerySplittingModel> log)
    { _store = store; _builder = builder; _changes = changes; _log = log; }

    public BucketView View { get; private set; } = BucketView.Missing;
    public string? Error { get; private set; }
    public List<string> Problems { get; } = new();

    [BindProperty] public string? Template { get; set; }
    [BindProperty] public string? Report { get; set; }
    [BindProperty] public string? Reason { get; set; }

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    private async Task LoadAsync(CancellationToken ct)
    {
        try { View = await _store.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the bucket counts could not be read");
            Error = "The bucket counts could not be read from the database: " + ex.Message;
        }
    }

    /// Stage a one-time reset of one report (Admin). Nothing is written until it is committed on Review &amp; commit.
    [Audited("riskanalysis.bucket-reset.stage")]
    public Task<IActionResult> OnPostResetAsync(CancellationToken ct) => StageAsync(Report, ct);

    /// Stage a one-time reset of every report (Admin).
    [Audited("riskanalysis.bucket-reset.stage")]
    public Task<IActionResult> OnPostResetAllAsync(CancellationToken ct) => StageAsync(null, ct);

    private async Task<IActionResult> StageAsync(string? report, CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var audit = AuditScope.Current;
        if (audit is not null) { audit.Target = "/Admin/QuerySplitting/" + (report is null ? "*" : Template + "/" + report); audit.Reason = Reason; }
        var (c, why) = await _builder.NewResetAsync(Template, report, Reason, ct);
        if (c is null)
        {
            audit?.Refused(string.Join("; ", why));
            Problems.AddRange(why);
            await LoadAsync(ct);
            return Page();
        }
        await _changes.StageAsync(User, c, ct);
        TempData["toast"] = "Staged: " + c.Title + ". Nothing is written until you review and commit.";
        return Redirect("/Changes");
    }
}
