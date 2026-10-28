using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Reports;
using ItemWrite = SI.Management.Core.ProData.ItemWrite; // the report designer's write (not the editors' Changes.ItemWrite)

namespace SI.Management.Web.Pages.Reports;

/// <summary>
/// Configuration > Reports (#274, #275 G7): the pages share the catalog read and the staging -- nothing is
/// written on any of them; every change goes to Review &amp; commit. Readers see everything read-only; every POST checks
/// Admin itself (server-side) before anything is read or staged.
/// </summary>
public abstract class ReportsPage : PageModel
{
    protected readonly IReportStore Store;
    protected readonly ChangeService Changes;
    protected readonly ILogger Log;

    protected ReportsPage(IReportStore store, ChangeService changes, ILogger log) { Store = store; Changes = changes; Log = log; }

    [BindProperty] public string? Reason { get; set; }

    public ReportState? State { get; protected set; }
    public bool SchemaMissing { get; protected set; }
    public string? Error { get; protected set; }
    public List<string> Messages { get; } = new();
    public bool CanEdit => User.IsAdmin() && State is not null;

    protected async Task<bool> LoadAsync(CancellationToken ct)
    {
        try
        {
            if (!await Store.SchemaAsync(ct)) { SchemaMissing = true; return false; }
            State = await Store.LoadAsync(ct);
            return true;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.LogError(ex, "the report catalog could not be read");
            Error = "The report catalog could not be read from the Pro database: " + ex.Message;
            return false;
        }
    }

    /// Stage one designer change; a pending designer change that writes any of the same items is replaced by it.
    protected async Task<IActionResult?> StageAsync(string kind, string title, IReadOnlyList<ItemWrite> writes, CancellationToken ct)
    {
        var (change, why) = ReportChanges.New(kind, title, writes, Reason);
        if (change is null) { Messages.AddRange(why.Select(w => "Not staged: " + w)); return null; }
        var mine = ReportChanges.Targets(change).ToHashSet(StringComparer.Ordinal);
        var pending = await Changes.PendingAsync(User, ct);
        var replace = pending.Where(p => ReportChanges.AllKinds.Contains(p.Kind) && ReportChanges.Targets(p).Any(mine.Contains)).Select(p => p.Id).ToList();
        if (replace.Count > 0) await Changes.DiscardAsync(User, replace, ct);
        await Changes.StageAsync(User, change, ct);
        TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
        TempData["toastKind"] = "ok";
        return RedirectToPage("/Changes/Index");
    }

    public static string OriginLabel(ReportOrigin o) => o switch { ReportOrigin.Vendor => "vendor", ReportOrigin.Changed => "changed", _ => "yours" };
}
