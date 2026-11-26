using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Cmdb;

namespace SI.Management.Web.Pages.Cmdb;

/// <summary>
/// "Not seen anymore" (#406, operator decisions 2026-10-06): the assets SecurityInsight no longer sees and that are still in
/// the grace period of their category (default 30 days, per category in the Pro settings), with their open findings, and the
/// ones retired recently. Readers see the list; an Admin may retire an asset in its grace period EARLY (one row, audited) --
/// its open findings then close as "Asset retired" (never as fixed) in the vulnerability connector's next run and ServiceNow
/// gets the state. An asset that is seen again becomes active again by itself, whoever retired it.
/// </summary>
public sealed class NotSeenModel : SI.Management.Web.Columns.DataViewPageModel
{
    private readonly IAssetLifecycleStore _store;
    private readonly ILogger<NotSeenModel> _log;
    public NotSeenModel(IAssetLifecycleStore store, ILogger<NotSeenModel> log) { _store = store; _log = log; }

    /// How far back the "retired recently" list goes.
    public const int RetiredDays = 30;

    public NotSeenView View { get; private set; } = NotSeenView.Missing;
    public string? Error { get; private set; }
    /// #855 W12 / #859: the lifecycle rules in force (the seen window and the grace periods the page names).
    public SI.Management.Core.ProData.CiLifecycleRules LifecycleRules { get; private set; } = SI.Management.Core.ProData.CiLifecycleDefinitions.Defaults;

    [BindProperty] public string? CiKey { get; set; }
    [BindProperty] public string? Reason { get; set; }

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    private async Task LoadAsync(CancellationToken ct)
    {
        try { if (HttpContext?.RequestServices.GetService<SI.Management.Core.ProData.ICiLifecycleRulesReader>() is { } lr) LifecycleRules = await lr.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the lifecycle settings could not be read; the defaults are shown"); }
        try
        {
            // #1400 (owner 2026-11-26: "memory issues must not be a problem in any step"): each list a page at a time (?p= / ?rp=),
            // never every not-seen CI in one read; an export reads every page of its list (Chunks)
            var size = SqlAssetLifecycleStore.PageSize;
            View = await _store.ReadPageAsync(RetiredDays, new NotSeenPaging((PageOf("p") - 1) * size, (PageOf("rp") - 1) * size, size), ct);
            if (!Exporting) await LoadTablesAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the asset lifecycle could not be read");
            Error = "The assets SecurityInsight no longer sees could not be read from the Pro database: " + ViewerError.Text(ex);
        }
    }

    // ---- #589 both lists as the shared data table: the CI, its identifiers and context, every field, the exports ----

    protected override Task LoadForExportAsync(CancellationToken ct) => LoadAsync(ct);

    protected override IReadOnlyList<SI.Management.Web.Columns.DataTable> BuildTables() =>
    [
        Assets(View.NotSeen, "notseen", "cmdb-notseen", "Not seen anymore", "data-not-seen-table", User.IsAdmin(), Exporting ? ExportChunks(NotSeenPaging.NotSeen) : null, View.NotSeenTotal),
        Assets(View.Retired, "retired", "cmdb-retired", "Retired recently", "data-retired-table", false, Exporting ? ExportChunks(NotSeenPaging.RetiredList) : null, View.RetiredTotal),
    ];

    /// The page of a list the address asks for (?p= not seen, ?rp= retired; 1 = the first).
    private int PageOf(string key) =>
        int.TryParse(Request?.Query[key], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var n) && n >= 1
            ? Math.Min(n, int.MaxValue / SqlAssetLifecycleStore.PageSize) : 1;

    /// The number of pages of a list.
    public static long Pages(long total) => Math.Max(1, (total + SqlAssetLifecycleStore.PageSize - 1) / SqlAssetLifecycleStore.PageSize);

    /// This page's address with one list's page changed.
    public string PageLink(string key, long page)
    {
        var parts = Request.Query.Where(q => q.Key != key && q.Key != "handler").SelectMany(q => q.Value.Select(v => Uri.EscapeDataString(q.Key) + "=" + Uri.EscapeDataString(v ?? ""))).ToList();
        if (page > 1) parts.Add(key + "=" + page.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return Request.Path + (parts.Count == 0 ? "" : "?" + string.Join("&", parts));
    }

    /// #1400 an export's rows: EVERY row of one list, a chunk at a time (never the page shown alone, never all in one read).
    private Func<int, CancellationToken, Task<IReadOnlyList<object>>> ExportChunks(string list) => async (n, ct) =>
    {
        var size = SI.Management.Core.ProData.ProDataFilters.ExportChunk;
        var skip = (int)Math.Min(int.MaxValue, (n - 1L) * size);
        var v = await _store.ReadPageAsync(RetiredDays, new NotSeenPaging(skip, skip, size, list), ct);
        return (list == NotSeenPaging.NotSeen ? v.NotSeen : v.Retired).Cast<object>().ToList();
    };

    private static SI.Management.Web.Columns.DataTable Assets(IReadOnlyList<NotSeenAsset> rows, string id, string view, string title, string marker, bool retire,
        Func<int, CancellationToken, Task<IReadOnlyList<object>>>? chunks = null, long? total = null)
    {
        static NotSeenAsset A(object o) => (NotSeenAsset)o;
        var cols = new List<SI.Management.Web.Columns.DataColumn>
        {
            new("AssetName", "Asset", o => string.IsNullOrEmpty(A(o).Name) ? A(o).CiKey : A(o).Name),
            new("AssetKey", "Asset (CI) key", o => A(o).CiKey),
            new("Category", "Kind", o => CategoryLabel(A(o).Category)),
            new("Kind", "Asset kind", o => A(o).Kind),
            new("LastSeen", "Last seen", o => A(o).LastSeen),
            new("GraceDays", "Grace (days)", o => A(o).GraceDays, Number: true),
            new("RetireAt", "Retired on", o => A(o).RetireAt),
            new("State", "State", o => A(o).State),
            new("StateChangedAt", "State since", o => A(o).StateChangedAt),
            new("RetiredAt", "Retired", o => A(o).RetiredAt),
            new("RetiredBy", "By", o => A(o).RetiredBy),
            new("RetireReason", "Why", o => A(o).RetireReason),
            new("OpenFindings", id == "retired" ? "Still open" : "Open findings", o => A(o).OpenFindings, Number: true),
            new("TopFindings", "Findings", o => A(o).TopFindings is { } f ? f + (A(o).OpenFindings > 5 ? ", ..." : "") : null),
        };
        if (retire) cols.Add(new("Retire", "Retire now", _ => null));
        return new SI.Management.Web.Columns.DataTable
        {
            Id = id, View = view, Title = title, Rows = chunks is null ? rows.Cast<object>().ToList() : Array.Empty<object>(), Chunks = chunks, ExpectedRows = chunks is null ? null : total, KeyOf = o => A(o).CiKey, Columns = cols, Marker = marker,
            Ci = SI.Management.Core.ProData.RowCiKey.AssetKey, RefOf = o => new SI.Management.Web.Columns.RowRef(A(o).CiKey),
            RowAttributes = o => new Dictionary<string, string?> { ["data-asset"] = A(o).CiKey },
        };
    }

    /// Retire one asset in its grace period now (Admin). Only from "not seen"; the store checks it again inside its transaction.
    [SI.Management.Web.Audit.Audited("cmdb.asset.retire-early")]
    public async Task<IActionResult> OnPostRetireAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (string.IsNullOrWhiteSpace(Reason))
        {
            TempData["toast"] = "Not retired: say why (the reason is on the audit trail).";
            TempData["toastKind"] = "error";
            return RedirectToPage();
        }
        RetireEarlyResult r;
        try { r = await _store.RetireEarlyAsync(CiKey ?? "", User.ChangeName(), Reason, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "an early retirement failed");
            r = new RetireEarlyResult(false, "Not retired: " + ViewerError.Text(ex));
        }
        TempData["toast"] = r.Message;
        TempData["toastKind"] = r.Retired ? "ok" : "error";
        return RedirectToPage();
    }

    /// The category's name as a person reads it.
    public static string CategoryLabel(string category) => category switch
    {
        "client-pc" => "Client PC",
        "server" => "Server",
        "service-principal" => "Service principal",
        "user" => "User",
        "azure-vm" => "Azure VM",
        "azure-resource" => "Azure resource",
        _ => "Other",
    };
}
