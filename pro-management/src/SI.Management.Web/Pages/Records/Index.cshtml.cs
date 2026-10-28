using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Export;
using SI.Management.Web.Pages.Collection;

namespace SI.Management.Web.Pages.Records;

/// <summary>
/// The records per source (V3-DATA-MODEL 2.13 "Raw"): one row per provider record (sidata.CiRecord) -- what each source
/// system reported, before the records were joined into CIs -- filtered by provider, record type and class, searched by
/// name, exported to Excel / CSV. <c>?key=</c> opens one record and its SI fields. Until the data sync has loaded the
/// records the page says so and shows nothing.
/// </summary>
public sealed class IndexModel : PageModel
{
    private readonly ICiViews _cis;
    private readonly ILogger<IndexModel> _log;

    public IndexModel(ICiViews cis, ILogger<IndexModel> log) { _cis = cis; _log = log; }

    [BindProperty(SupportsGet = true)] public string? Key { get; set; }

    public static GridSpec Spec => CiSql.RecordSpec;
    public bool NotLoaded { get; private set; }
    public GridPage? Grid { get; private set; }
    public IReadOnlyList<CiFacet> Facets { get; private set; } = Array.Empty<CiFacet>();
    public CiRecordRow? Selected { get; private set; }
    public IReadOnlyList<CiFieldValue> SelectedFields { get; private set; } = Array.Empty<CiFieldValue>();
    public List<QueryInfo> Queries { get; } = new();
    public string? Error { get; private set; }

    public IReadOnlyList<string> FacetValues(string facet) => Facets.Where(f => f.Facet == facet).Select(f => f.Value).ToList();

    /// The query parameter of each filter and its grid column.
    public static readonly IReadOnlyList<(string Param, string Column, string Label)> Filters =
        [("provider", "Provider", "Provider"), ("type", "RecordType", "Record type"), ("class", "Class", "Class")];

    public GridRequest ReadGrid()
    {
        var q = Request.Query;
        var filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (param, col, _) in Filters)
        {
            var joined = string.Join("|", q[param].Where(v => !string.IsNullOrWhiteSpace(v)));
            if (joined.Length > 0) filters[col] = joined;
        }
        var dir = (string?)q["dir"];
        return new GridRequest
        {
            Sort = q["sort"],
            Desc = dir is "desc" ? true : dir is "asc" ? false : null,
            Page = int.TryParse(q["p"], NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : 1,
            Size = GridSql.PageSize((string?)q["size"]),
            Search = q["q"],
            Filters = filters,
            Selected = q["sel"].Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v!).ToList(),
        };
    }

    public string Link(params (string Key, string? Value)[] overrides)
    {
        var over = overrides.Select(o => o.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var parts = new List<(string, string)>();
        foreach (var kv in Request.Query)
        {
            if (kv.Key.Equals("handler", StringComparison.OrdinalIgnoreCase) || over.Contains(kv.Key)) continue;
            if (kv.Key.Equals("p", StringComparison.OrdinalIgnoreCase) && overrides.Length > 0) continue;
            foreach (var v in kv.Value) if (!string.IsNullOrEmpty(v)) parts.Add((kv.Key, v));
        }
        foreach (var (k, v) in overrides) if (!string.IsNullOrEmpty(v)) parts.Add((k, v));
        var qs = string.Join("&", parts.Select(x => Uri.EscapeDataString(x.Item1) + "=" + Uri.EscapeDataString(x.Item2)));
        return "/Records" + (qs.Length > 0 ? "?" + qs : "");
    }

    public string HandlerLink(string handler) { var l = Link(("key", null)); return l + (l.Contains('?') ? "&" : "?") + "handler=" + handler; }

    // ---- #589 every column: the record's CI with its identifiers, linked objects, fields and every source property ------

    public const string View = "records";
    public SI.Management.Web.Columns.DataViewLayout? ViewLayout { get; private set; }
    public IReadOnlyList<GridColumn> DisplayColumns { get; private set; } = Array.Empty<GridColumn>();
    private GridSpec? _applied;
    public GridSpec Applied => _applied ?? Spec;

    private async Task<bool> LayoutAsync(CancellationToken ct)
    {
        var own = SI.Management.Web.Columns.GridLayout.Own(Spec);
        var probe = new SI.Management.Web.Columns.DataViewLayout { View = View, Own = own, Ci = RowCiKey.CiId };
        ViewLayout = await new SI.Management.Web.Columns.DataViewLayout
        {
            View = View, Own = own, Ci = RowCiKey.CiId, Shipped = SI.Management.Web.Columns.DataViewDefaults.ForGrid(Spec, RowCiKey.CiId, RowFindingKey.None, probe.Known),
        }.LoadAsync(HttpContext, _log, ct);
        _applied = SI.Management.Web.Columns.GridLayout.Apply(Spec, ViewLayout.Layout);
        DisplayColumns = SI.Management.Web.Columns.GridLayout.Display(_applied, ViewLayout);
        return true;
    }

    private Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> FillAsync(IReadOnlyList<GridColumn> cols, IReadOnlyList<IReadOnlyDictionary<string, object?>> rows, CancellationToken ct) =>
        ViewLayout is null ? Task.FromResult(rows)
            : SI.Management.Web.Columns.GridLayout.FillAsync(HttpContext, _log, ViewLayout, cols, rows, r => new SI.Management.Web.Columns.RowRef(Cell(r, "CiId")), null, ct);

    public SI.Management.Web.Cis.ColumnChooser? Chooser => ViewLayout?.Chooser(Link(("key", null)), SI.Management.Web.Auth.UserExtensions.IsAdmin(User));

    public SI.Management.Web.Columns.ViewExports Exports => SI.Management.Web.Columns.ViewExports.Of(HandlerLink);

    /// "Export all columns": every record matching the filters with every own column and every column its CI offers.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAllAsync(CancellationToken ct)
    {
        GridPage? page;
        try { page = await ExportRowsAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (page is null || ViewLayout is null) return NotFound(Error ?? SI.Management.Web.Pages.Cis.IndexModel.NotLoadedText);
        var cols = SI.Management.Web.Columns.GridLayout.All(Spec, ViewLayout);
        var rows = await FillAsync(cols, page.Rows, ct);
        return await ExcelExport.FileAsync("records-all-columns", null, (x, info) =>
        {
            info.Add("Columns", "every column of the view, and every column of the record's CI (its identifiers, linked objects, fields, source properties)");
            info.Filter("Search", page.State.Search);
            foreach (var f in page.State.Filters) info.Add("Filter: " + (Spec.Column(f.Key)?.Label ?? f.Key), CollectionPageModel.FilterText(f));
            x.Sheet(info, "Records", cols.Select(c => c.Label).ToList(), rows.Select(row => (IReadOnlyList<object?>)cols.Select(c => SI.Management.Web.Columns.GridLayout.IsExtra(c) ? SI.Management.Web.Columns.GridLayout.Excel(row, c.Key) : CollectionPageModel.ExcelValue(c, row)).ToList()));
            if (page.Rows.Count >= ProDataFilters.MaxExport) info.Notes.Add($"The export stops at {ProDataFilters.MaxExport:N0} rows; narrow the filter to get the rest.");
            return Task.CompletedTask;
        }, ct);
    }

    private async Task<bool> PrepareAsync(CancellationToken ct)
    {
        var resolver = HttpContext?.RequestServices.GetService<SI.Management.Web.Departments.IDepartmentScopeResolver>();
        if (resolver is not null && (await resolver.ResolveAsync(User, ct)).Rows is not null)
        {
            Error = "This view is not available to an account limited to departments: it shows records across every department.";
            return false;
        }
        var schema = await _cis.SchemaAsync(ct);
        if (!schema.Data.Records) { NotLoaded = true; return false; }
        return true;
    }

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            if (!await PrepareAsync(ct)) return;
            await LayoutAsync(ct);
            var req = ReadGrid();
            try { GridSql.Normalize(Spec, req); }
            catch (ArgumentException ex) { Error = "The filter is not valid: " + ex.Message; return; }
            var g = await _cis.GridAsync(Applied, req, false, ct);
            Grid = g.Data with { Rows = await FillAsync(DisplayColumns, g.Data.Rows, ct) };
            Queries.Add(QueryInfo.From(g, "The records"));
            try
            {
                var f = await _cis.RecordFacetsAsync(ct);
                Facets = f.Data;
                Queries.Add(QueryInfo.From(f, "The filter choices"));
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the record filter choices could not be read"); }
            if (!string.IsNullOrWhiteSpace(Key))
            {
                var r = await _cis.RecordAsync(Key, ct);
                Selected = r.Data;
                SelectedFields = CiDoc.AllFields(Selected?.DocJson);
                Queries.Add(QueryInfo.From(r, "The open record"));
                if (Selected is null) Error = "That record is not in the Pro database (it may have passed retention).";
            }
        }
        catch (ArgumentException ex) { Error = "The request is not valid: " + ex.Message; }
        catch (ViewTimeoutException ex) { Error = CollectionPageModel.TimeoutText(ex.Limit, null); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the records could not be read");
            Error = "The records could not be read from the Pro database: " + ex.Message;
        }
    }

    public string? Cell(IReadOnlyDictionary<string, object?> row, string col) =>
        row.TryGetValue(col, out var v) && v is not null ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;

    /// Where a cell links: the record opens itself, the CI its CI page.
    public string? CellLink(GridColumn c, IReadOnlyDictionary<string, object?> row) => c.Key switch
    {
        "Name" or "RecordKey" when Cell(row, "RecordKey") is { Length: > 0 } k => Link(("key", k)) + "#record",
        "CiId" when Cell(row, "CiId") is { Length: > 0 } id => "/Cis/Detail?id=" + Uri.EscapeDataString(id),
        _ => null,
    };

    private async Task<GridPage?> ExportRowsAsync(CancellationToken ct) =>
        // "Export this page" reads the page shown; every other export every matching record
        await PrepareAsync(ct) && await LayoutAsync(ct) ? (await _cis.GridAsync(Applied, ReadGrid(), !SI.Management.Web.Columns.ExportChoices.PageOnly(Request), ct)).Data : null;

    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        GridPage? page;
        try { page = await ExportRowsAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (page is null) return NotFound(Error ?? SI.Management.Web.Pages.Cis.IndexModel.NotLoadedText);
        var cols = DisplayColumns.Count > 0 ? DisplayColumns : CollectionPageModel.Visible(Spec);
        var rows = await FillAsync(cols, page.Rows, ct);
        return await ExcelExport.FileAsync("records", null, (x, info) =>
        {
            info.Add("Sort", page.State.Sort + (page.State.Desc ? " (descending)" : ""));
            info.Filter("Search", page.State.Search);
            foreach (var f in page.State.Filters) info.Add("Filter: " + (Spec.Column(f.Key)?.Label ?? f.Key), CollectionPageModel.FilterText(f));
            if (page.State.Selected.Count > 0) info.Add("Selected rows", page.State.Selected.Count);
            x.Sheet(info, "Records", cols.Select(c => c.Label).ToList(), rows.Select(row => (IReadOnlyList<object?>)cols.Select(c => SI.Management.Web.Columns.GridLayout.IsExtra(c) ? SI.Management.Web.Columns.GridLayout.Excel(row, c.Key) : CollectionPageModel.ExcelValue(c, row)).ToList()));
            if (page.Rows.Count >= ProDataFilters.MaxExport) info.Notes.Add($"The export stops at {ProDataFilters.MaxExport:N0} rows; narrow the filter to get the rest.");
            return Task.CompletedTask;
        }, ct);
    }

    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetCsvAsync(CancellationToken ct)
    {
        GridPage? page;
        try { page = await ExportRowsAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (page is null) return NotFound(Error ?? SI.Management.Web.Pages.Cis.IndexModel.NotLoadedText);
        var cols = DisplayColumns.Count > 0 ? DisplayColumns : CollectionPageModel.Visible(Spec);
        var rows = await FillAsync(cols, page.Rows, ct);
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", cols.Select(c => Findings.IndexModel.Csv(c.Label))));
        foreach (var row in rows) sb.AppendLine(string.Join(",", cols.Select(c => Findings.IndexModel.Csv(SI.Management.Web.Columns.GridLayout.IsExtra(c) ? SI.Management.Web.Columns.GridLayout.Text(row, c.Key) : CollectionPageModel.Text(c, row, csv: true)))));
        var name = "records-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + "Z.csv";
        return File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray(), "text/csv; charset=utf-8", name);
    }
}
