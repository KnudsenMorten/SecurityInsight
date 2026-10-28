using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.RunReports;

namespace SI.Management.Web.Pages.Admin.RunHealth;

/// <summary>
/// Operations &gt; Run health &gt; Risk Analysis reports (#641, owner 2026-10-13: an incomplete report is told to him through
/// Invardia; the customer sees it HERE, in the web app). Every report of one Risk Analysis run (the RunId in the address --
/// the link the run's report carries), or of the newest run of each grain: what the source said it holds, what the run
/// retrieved and stored, and the verdict with its reason. Readers may view it.
/// #902: a report SI held ON PURPOSE is "Held: last good result kept" (amber) with its reason and the age of the kept result;
/// held escalateAfterDetailedRuns Detailed runs in a row it says SecurityInsight support has been told. An Admin may accept a
/// source that went silent as empty for good, per report, through Review &amp; commit (and undo it).
/// </summary>
public sealed class ReportsModel : PageModel
{
    private readonly IRunReportsStore _store;
    private readonly ISourceAcceptStore _accepts;
    private readonly SourceAcceptChanges _builder;
    private readonly ChangeService _changes;
    private readonly ILogger<ReportsModel> _log;
    private readonly TimeProvider _clock;
    // the app's clock (TimeProvider, registered in Program.cs): the kept result's age ("2 days old") is read against it, so a
    // test with a fixed clock never ages
    public ReportsModel(IRunReportsStore store, ISourceAcceptStore accepts, SourceAcceptChanges builder, ChangeService changes, ILogger<ReportsModel> log, TimeProvider clock)
    { _store = store; _accepts = accepts; _builder = builder; _changes = changes; _log = log; _clock = clock; }

    [BindProperty(SupportsGet = true)] public string? RunId { get; set; }
    [BindProperty] public string? Report { get; set; }
    [BindProperty] public string? Table { get; set; }
    [BindProperty] public long AcceptId { get; set; }
    [BindProperty] public string? Reason { get; set; }
    public RunReportsView View { get; private set; } = RunReportsView.Missing;
    public IReadOnlyList<SourceAccept> Accepts { get; private set; } = Array.Empty<SourceAccept>();
    public string? Error { get; private set; }
    public List<string> Problems { get; } = new();
    public DateTime NowUtc => _clock.GetUtcNow().UtcDateTime;

    public Task OnGetAsync(CancellationToken ct) => LoadAsync(ct);

    private async Task LoadAsync(CancellationToken ct)
    {
        try { View = await _store.ReadAsync(RunId, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the report verdicts could not be read");
            Error = "The report verdicts could not be read from the database: " + ex.Message;
        }
        try { Accepts = await _accepts.ActiveAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the source acceptances could not be read"); }
    }

    /// Stage the acceptance of one source as empty for good for one report (Admin). Nothing is written until it is committed.
    [Audited("riskanalysis.source-accept.stage")]
    public async Task<IActionResult> OnPostAcceptAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var audit = AuditScope.Current;
        if (audit is not null) { audit.Target = "/Admin/RunHealth/Reports/" + Report + "/" + Table; audit.Reason = Reason; }
        var (c, why) = await _builder.NewAcceptAsync(Report, Table, Reason, ct);
        return await StagedAsync(c, why, ct);
    }

    /// Stage the undo of one active acceptance (Admin).
    [Audited("riskanalysis.source-accept-undo.stage")]
    public async Task<IActionResult> OnPostUndoAcceptAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var audit = AuditScope.Current;
        if (audit is not null) { audit.Target = "/Admin/RunHealth/Reports/accept/" + AcceptId; audit.Reason = Reason; }
        var (c, why) = await _builder.NewUndoAsync(AcceptId, Reason, ct);
        return await StagedAsync(c, why, ct);
    }

    private async Task<IActionResult> StagedAsync(StagedChange? c, IReadOnlyList<string> why, CancellationToken ct)
    {
        if (c is null)
        {
            AuditScope.Current?.Refused(string.Join("; ", why));
            Problems.AddRange(why);
            await LoadAsync(ct);
            return Page();
        }
        await _changes.StageAsync(User, c, ct);
        TempData["toast"] = "Staged: " + c.Title + ". Nothing is written until you review and commit.";
        return Redirect("/Changes");
    }
}
