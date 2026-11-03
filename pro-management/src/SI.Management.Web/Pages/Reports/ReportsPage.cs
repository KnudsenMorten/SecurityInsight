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
            Error = "The report catalog could not be read from the Pro database: " + ViewerError.Text(ex);
            return false;
        }
    }

    /// Stage one designer change; a pending designer change that writes any of the same items is replaced by it.
    protected async Task<IActionResult?> StageAsync(string kind, string title, IReadOnlyList<ItemWrite> writes, CancellationToken ct)
    {
        var (change, why) = await StageDesignerAsync(Changes, User, kind, title, writes, Reason, ct);
        if (change is null) { Messages.AddRange(why.Select(w => "Not staged: " + w)); return null; }
        TempData["toast"] = "Staged: " + change.Title + ". Nothing is written until you review and commit.";
        TempData["toastKind"] = "ok";
        return RedirectToPage("/Changes/Index");
    }

    /// THE designer staging, for every page that stages a designer item (the reports pages, and #1055 the ServiceNow
    /// connector page's CI scope): built and checked (<see cref="ReportChanges.New"/>), a pending designer change of the
    /// same user that writes any of the same items replaced, staged. (null, why) when it cannot be staged.
    public static async Task<(SI.Management.Web.Changes.StagedChange? Change, IReadOnlyList<string> Problems)> StageDesignerAsync(ChangeService changes,
        System.Security.Claims.ClaimsPrincipal user, string kind, string title, IReadOnlyList<ItemWrite> writes, string? reason, CancellationToken ct)
    {
        var (change, why) = ReportChanges.New(kind, title, writes, reason);
        if (change is null) return (null, why);
        var mine = ReportChanges.Targets(change).ToHashSet(StringComparer.Ordinal);
        var pending = await changes.PendingAsync(user, ct);
        var replace = pending.Where(p => ReportChanges.AllKinds.Contains(p.Kind) && ReportChanges.Targets(p).Any(mine.Contains)).Select(p => p.Id).ToList();
        if (replace.Count > 0) await changes.DiscardAsync(user, replace, ct);
        await changes.StageAsync(user, change, ct);
        return (change, Array.Empty<string>());
    }

    public static string OriginLabel(ReportOrigin o) => o switch { ReportOrigin.Vendor => "vendor", ReportOrigin.Changed => "changed", _ => "yours" };
}
