using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Export;

namespace SI.Management.Web.Columns;

/// <summary>
/// #589: THE base of every data view page whose table is the page's own (<see cref="DataTable"/>): the tables a page lists,
/// and ONE export handler for them all (?handler=TableExport&amp;t=&lt;table&gt;&amp;f=csv|xlsx|all) -- every row the page
/// lists under its current filters (a page that pages its list loads every row for an export, <see cref="Exporting"/>), with
/// exactly the chosen columns, or every column on offer ("Export all columns"). A guard test holds every data page of the
/// menu to this base (or to a grid that has the same), with the chooser and the all-rows words.
/// </summary>
public abstract class DataViewPageModel : PageModel
{
    /// The tables the page shows (filled by <see cref="LoadTablesAsync"/>).
    public IReadOnlyList<DataTable> Tables { get; private set; } = Array.Empty<DataTable>();

    /// True while the page loads for an export: a page that pages its list loads every row.
    public bool Exporting { get; private set; }

    /// The page's tables from what it loaded (called after its GET handler ran, or after <see cref="LoadForExportAsync"/>).
    protected virtual IReadOnlyList<DataTable> BuildTables() => Array.Empty<DataTable>();

    /// Loads what the page lists, for an export (the same filters as the page; every row). Default: nothing.
    protected virtual Task LoadForExportAsync(CancellationToken ct) => Task.CompletedTask;

    protected ILogger TableLog => HttpContext?.RequestServices.GetService<ILoggerFactory>()?.CreateLogger(GetType()) ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance;

    private bool _tablesLoaded;

    /// <summary>
    /// The view key of a page whose FILTERS are its own address parameters, bound before its table exists (the Findings
    /// browser, the task lists, the Summary; its parameters are listed in <see cref="ViewState.Pages"/>): the person's
    /// remembered sort / filters are put into the request before the page binds them. Null (the default) = the page's
    /// tables are sorted and filtered in the browser only.
    /// </summary>
    protected virtual string? AddressStateView => null;

    /// The page shows the person's remembered sort / filters (its address named none).
    public bool StateRestored { get; private set; }

    /// Runs after the handler was chosen and BEFORE the page's properties are bound: where the remembered state goes in.
    public override async Task OnPageHandlerSelectionAsync(Microsoft.AspNetCore.Mvc.Filters.PageHandlerSelectedContext context)
    {
        OnPageHandlerSelected(context);
        if (AddressStateView is not { Length: > 0 } view) return;
        try { StateRestored = await DataViewLayout.RestoreAsync(HttpContext, view, TableLog, HttpContext.RequestAborted); }
        catch (Exception ex) when (ex is not OperationCanceledException) { TableLog.LogWarning(ex, "the remembered sort and filters of {View} could not be restored; the view's standard is shown", view); }
    }

    /// Builds the tables and reads their layouts and extra columns (the end of the page's GET handler; when a page does
    /// not call it, it runs after any handler that renders the page).
    protected async Task LoadTablesAsync(CancellationToken ct, bool allColumns = false)
    {
        var tables = BuildTables();
        // a page table is sorted and filtered in the browser: its remembered sort / filters are restored there, never put
        // into this request now (a page with filters of its own in the address had them restored before it bound them:
        // AddressStateView)
        if (HttpContext is not null) HttpContext.Items[ViewState.PageTablesItem] = true;
        foreach (var t in tables) await t.LoadAsync(HttpContext, TableLog, ct, allColumns);
        Tables = tables;
        _tablesLoaded = true;
    }

    /// After a handler that renders the page (a GET, or a POST that answers with the page), the tables are built from
    /// what it loaded -- so every page of this base shows its tables whatever path its handler took.
    public override async Task OnPageHandlerExecutionAsync(Microsoft.AspNetCore.Mvc.Filters.PageHandlerExecutingContext context, Microsoft.AspNetCore.Mvc.Filters.PageHandlerExecutionDelegate next)
    {
        // the page model's own synchronous hooks keep working (what the base implementation does)
        OnPageHandlerExecuting(context);
        if (context.Result is not null) return;
        var done = await next();
        OnPageHandlerExecuted(done);
        if (!Exporting && !_tablesLoaded && done.Exception is null && done.Result is null or PageResult)
        {
            try { await LoadTablesAsync(HttpContext.RequestAborted); }
            catch (Exception ex) when (ex is not OperationCanceledException) { TableLog.LogWarning(ex, "the page's tables could not be built"); }
        }
    }

    /// Loads what the page lists for an export (every row) and returns one table with the extra columns read -- for a
    /// page that writes its own workbook around the table (its file name, its filter words). Null = no such table.
    protected async Task<DataTable?> ExportTableAsync(string id, bool allColumns, CancellationToken ct)
    {
        Exporting = true;
        await LoadForExportAsync(ct);
        await LoadTablesAsync(ct, allColumns);
        return Table(id);
    }

    public DataTable? Table(string id) => Tables.FirstOrDefault(t => t.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// This page's URL with its query, for one table's export.
    public string TableExportLink(DataTable t, string format)
    {
        var parts = new List<string>();
        foreach (var kv in Request.Query)
        {
            if (kv.Key is "handler" or "t" or "f") continue;
            foreach (var v in kv.Value) if (!string.IsNullOrEmpty(v)) parts.Add(Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(v));
        }
        parts.Add("handler=TableExport");
        parts.Add("t=" + Uri.EscapeDataString(t.Id));
        parts.Add("f=" + format);
        return Request.Path + "?" + string.Join("&", parts);
    }

    /// The export buttons of one table.
    public ViewExports TableExports(DataTable t) => new(TableExportLink(t, "csv"), TableExportLink(t, "xlsx"), TableExportLink(t, "all"));

    /// What Pages/Shared/_DataTable.cshtml renders for one table: the table, its export buttons, its chooser.
    public DataTableView TableView(DataTable t) => new(t, TableExports(t),
        t.Layout.Chooser(Request.Path + Request.QueryString, SI.Management.Web.Auth.UserExtensions.IsAdmin(User)));

    /// The table of this id, ready to render (null when the page has none: nothing to show).
    public DataTableView? TableView(string id) => Table(id) is { } t ? TableView(t) : null;

    /// <summary>
    /// The export of one table: every row the page lists (its filters, every page), as CSV or Excel with the chosen
    /// columns, or (f=all) as Excel with every column on offer.
    /// </summary>
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetTableExportAsync(string? t, string? f, CancellationToken ct)
    {
        Exporting = true;
        await LoadForExportAsync(ct);
        var all = f == "all";
        await LoadTablesAsync(ct, all);
        if (t is null || Table(t) is not { } table) return NotFound("That table is not on this page.");
        var keys = table.ExportKeys(all);
        var stem = new string(table.Title.ToLowerInvariant().Select(ch => char.IsAsciiLetterOrDigit(ch) ? ch : '-').ToArray()).Trim('-');
        if (f == "csv")
        {
            var name = stem + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + "Z.csv";
            return File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(table.Csv(keys))).ToArray(), "text/csv; charset=utf-8", name);
        }
        return await ExcelExport.FileAsync(all ? stem + "-all-columns" : stem, null, (x, info) =>
        {
            info.Add("Columns", all ? "every column this view offers" : table.Layout.SourceWords);
            foreach (var kv in Request.Query.Where(q => q.Key is not ("handler" or "t" or "f"))) info.Add(kv.Key, string.Join(", ", kv.Value.ToArray()));
            x.Sheet(info, table.Title, keys.Select(table.Label).ToList(), table.Rows.Select(row => (IReadOnlyList<object?>)keys.Select(k => table.Excel(row, k)).ToList()));
            return Task.CompletedTask;
        }, ct);
    }
}
