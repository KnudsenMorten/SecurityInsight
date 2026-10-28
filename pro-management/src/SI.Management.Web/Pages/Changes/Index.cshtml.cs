using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Changes;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Changes;

/// <summary>
/// Review &amp; commit -- the ONE place a staged change (exemption, tier pin, rule change, document edit) is written.
/// Each pending change shows what it replaces and what it becomes, and why it would be refused; the selected ones are
/// committed, each in its own transaction with its cfg.ChangeLog row. Refused or stale ones stay pending.
/// </summary>
public sealed class IndexModel : PageModel
{
    private readonly ChangeService _changes;
    public IndexModel(ChangeService changes) => _changes = changes;

    public IReadOnlyList<ChangePreview> Previews { get; private set; } = Array.Empty<ChangePreview>();
    public IReadOnlyList<CommitOutcome> Outcomes { get; private set; } = Array.Empty<CommitOutcome>();
    [BindProperty] public List<string> Ids { get; set; } = new();

    public async Task OnGetAsync(CancellationToken ct) => Previews = await _changes.PreviewAsync(User, ct);

    [SI.Management.Web.Audit.Audited("changes.batch.commit")]
    public async Task<IActionResult> OnPostCommitAsync(CancellationToken ct)
    {
        if (Ids.Count == 0) { TempData["toast"] = "Select at least one change to commit."; TempData["toastKind"] = "warn"; return RedirectToPage(); }
        // only changes that pass review NOW are sent (the state may have moved since the page was rendered)
        var ok = (await _changes.PreviewAsync(User, ct)).Where(p => p.CanCommit && Ids.Contains(p.Change.Id)).Select(p => p.Change.Id).ToList();
        Outcomes = await _changes.CommitAsync(User, ok, ct);
        var saved = Outcomes.Count(o => o.Status == WriteStatus.Saved);
        var skipped = Ids.Count - ok.Count;
        TempData["toast"] = $"{saved} change(s) committed" + (Outcomes.Count - saved > 0 ? $", {Outcomes.Count - saved} not written" : "") + (skipped > 0 ? $", {skipped} skipped (refused at review)" : "") + ".";
        TempData["toastKind"] = saved == Outcomes.Count && skipped == 0 ? "ok" : "warn";
        Previews = await _changes.PreviewAsync(User, ct);
        return Page();
    }

    /// A post that names neither Commit nor Discard does nothing and says so. Without this, Razor Pages rendered the
    /// page with no handler run: an empty list ("No pending changes") while the changes were still pending.
    [SI.Management.Web.Audit.NotAudited("a post naming neither Commit nor Discard: answered with a notice, nothing is read or written")]
    public IActionResult OnPost()
    {
        TempData["toast"] = "Nothing was committed or discarded: choose Commit selected or Discard selected.";
        TempData["toastKind"] = "warn";
        return RedirectToPage();
    }

    [SI.Management.Web.Audit.Audited("changes.batch.discard")]
    public async Task<IActionResult> OnPostDiscardAsync(CancellationToken ct)
    {
        await _changes.DiscardAsync(User, Ids, ct);
        TempData["toast"] = $"{Ids.Count} pending change(s) discarded. Nothing had been written.";
        return RedirectToPage();
    }
}
