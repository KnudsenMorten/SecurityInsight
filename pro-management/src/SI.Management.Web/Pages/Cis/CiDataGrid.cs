using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Export;
using SI.Management.Web.Pages.Collection;

namespace SI.Management.Web.Pages.Cis;

/// <summary>
/// A grid over the CI data (V3-DATA-MODEL 2.13): the Detailed (CI x finding) and Summary (finding x tier x severity x CMDB
/// group) views. One spec, fixed filter choices from the URL, search, sort, paging, row selection, Excel / CSV export --
/// the Records page's pattern. A department-limited account sees none of it (the rows span every department); until the
/// data sync has loaded the findings per CI the page says so.
/// </summary>
public abstract class CiDataGridModel : PageModel
{
    protected readonly ICiViews Cis;
    protected readonly ILogger Log;
    protected CiDataGridModel(ICiViews cis, ILogger log) { Cis = cis; Log = log; }

    public abstract GridSpec Spec { get; }
    /// The page's URL ("/Cis/Findings").
    public abstract string Route { get; }
    /// What a row is called ("finding(s)").
    public abstract string Noun { get; }
    /// The export file's name stem.
    public abstract string ExportName { get; }
    /// The filters of the bar: URL parameter, grid column, label, the fixed choices.
    public abstract IReadOnlyList<(string Param, string Column, string Label, IReadOnlyList<string> Choices)> Filters { get; }
    /// The filters (URL parameters) first built to take SEVERAL values at once (devices and Azure resources in one list, OS
    /// and SQL findings in one list). Since 2026-10-19 EVERY filter of the bar is the shared multi-select (MultiFilter) and
    /// every filter accepts several values in the address; the list stays for what reads it.
    public virtual IReadOnlySet<string> MultiFilters => NoMultiFilters;
    private static readonly IReadOnlySet<string> NoMultiFilters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    /// Which CI tables and columns this database has (read with the page; none until then).
    protected CiSchema Schema { get; private set; } = CiSchema.None;

    /// #855 M5 / M6 (owner 2026-10-21: "default filter is active, so it should be active only"): the CI lifecycle the grid
    /// counts -- the address's lifecycle choice, default ACTIVE -- and the rules its words come from. Said above the grid with
    /// the choice (Active / Not seen / Retired / All).
    public LifecycleFilter Lifecycle => SI.Management.Web.Pages.LifecycleChoice.Read(HttpContext?.Request);
    public CiLifecycleRules LifecycleRules { get; private set; } = CiLifecycleDefinitions.Defaults;

    /// The most rows an export of this view holds.
    public static long ExportLimit => ProDataFilters.MaxExport;

    /// What an export that reached the limit says on its Export sheet: that it stops there, and how many rows the view has.
    public static string ExportLimitNote(long total) =>
        $"The export stops at {ProDataFilters.MaxExport:N0} rows; narrow the filter to get the rest."
        + (total > ProDataFilters.MaxExport ? $" The view has {total:N0} rows; this file holds the first {ProDataFilters.MaxExport:N0} of them in the sort order." : "");

    public static readonly IReadOnlyList<string> Severities = ["Critical", "High", "Medium", "Low"];
    public static readonly IReadOnlyList<string> Tiers = ["0", "1", "2", "3"];
    public static readonly IReadOnlyList<string> States = ["open", "reopened", "closed"];
    public static readonly IReadOnlyList<string> Classes = ["device", "identity", "cloud_resource", "public_ip"];

    public bool NotLoaded { get; private set; }
    public GridPage? Grid { get; private set; }
    public List<QueryInfo> Queries { get; } = new();
    public string? Error { get; private set; }
    /// #812: said above the grid while its stored rows are not written yet (the CI findings summary).
    public string? Notice { get; private set; }

    /// #812: what the grid says while its stored rows are not written (null = they are, or the grid stores none).
    protected virtual Task<string?> PreparingAsync(CancellationToken ct) => Task.FromResult<string?>(null);

    // ---- #589 every column: the layout, the extra columns (the CI, its identifiers and context, the finding context) ----

    public SI.Management.Web.Columns.DataViewLayout? ViewLayout { get; private set; }
    public IReadOnlyList<GridColumn> DisplayColumns { get; private set; } = Array.Empty<GridColumn>();
    private GridSpec? _applied;
    /// The spec with the person's layout (only which columns show and in what order differs; the statement is the same).
    public GridSpec Applied => _applied ?? Spec;

    /// The rows' CI (a CI id column) and their finding (the finding key: a CVE or a configuration id of the newest collection).
    private RowCiKey RowCi => Spec.Column("CiId") is not null ? RowCiKey.CiId : RowCiKey.None;
    private RowFindingKey RowFinding => Spec.Column("FindingKey") is not null ? RowFindingKey.Issue : RowFindingKey.None;

    private async Task<bool> LayoutAsync(CancellationToken ct)
    {
        var own = SI.Management.Web.Columns.GridLayout.Own(Spec);
        var probe = new SI.Management.Web.Columns.DataViewLayout { View = "cidata-" + Spec.Name, Own = own, Ci = RowCi, Findings = RowFinding };
        ViewLayout = await new SI.Management.Web.Columns.DataViewLayout
        {
            View = probe.View, Own = own, Ci = RowCi, Findings = RowFinding, Shipped = SI.Management.Web.Columns.DataViewDefaults.ForGrid(Spec, RowCi, RowFinding, probe.Known),
        }.LoadAsync(HttpContext, Log, ct);
        _applied = SI.Management.Web.Columns.GridLayout.Apply(Spec, ViewLayout.Layout);
        DisplayColumns = SI.Management.Web.Columns.GridLayout.Display(_applied, ViewLayout);
        return true;
    }

    private Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> FillAsync(IReadOnlyList<GridColumn> cols, IReadOnlyList<IReadOnlyDictionary<string, object?>> rows, CancellationToken ct) =>
        ViewLayout is null ? Task.FromResult(rows)
            : SI.Management.Web.Columns.GridLayout.FillAsync(HttpContext, Log, ViewLayout, cols, rows,
                r => SI.Management.Web.Columns.GridLayout.RefOf(r, RowCi == RowCiKey.CiId ? "CiId" : null, null, RowFinding == RowFindingKey.Issue ? "FindingKey" : null), "", ct);

    /// The grid's chooser (null until the grid is planned).
    public SI.Management.Web.Cis.ColumnChooser? Chooser => ViewLayout?.Chooser(Link(), SI.Management.Web.Auth.UserExtensions.IsAdmin(User));

    public SI.Management.Web.Columns.ViewExports Exports => SI.Management.Web.Columns.ViewExports.Of(HandlerLink);

    /// "Export all columns": every row matching the filters with every own column and every extra column on offer.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAllAsync(CancellationToken ct)
    {
        GridPage? page;
        try { page = await ExportRowsAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (page is null || ViewLayout is null) return NotFound(Error ?? IndexModel.NotLoadedText);
        var cols = SI.Management.Web.Columns.GridLayout.All(Spec, ViewLayout);
        var rows = await FillAsync(cols, page.Rows, ct);
        return await ExcelExport.FileAsync(ExportName + "-all-columns", null, (x, info) =>
        {
            info.Add("Columns", "every column of the view, and every column its rows can carry (the CI, its identifiers, linked objects, CI fields, source properties, the finding context)");
            info.Add("Sort", page.State.Sort + (page.State.Desc ? " (descending)" : ""));
            info.Filter("Search", page.State.Search);
            foreach (var f in page.State.Filters) info.Add("Filter: " + (Spec.Column(f.Key)?.Label ?? f.Key), CollectionPageModel.FilterText(f));
            x.Sheet(info, ExportName, cols.Select(c => c.Label).ToList(), rows.Select(row => (IReadOnlyList<object?>)cols.Select(c => SI.Management.Web.Columns.GridLayout.IsExtra(c) ? SI.Management.Web.Columns.GridLayout.Excel(row, c.Key) : CollectionPageModel.ExcelValue(c, row)).ToList()));
            if (page.Rows.Count >= ProDataFilters.MaxExport) info.Notes.Add(ExportLimitNote(page.Total));
            return Task.CompletedTask;
        }, ct);
    }

    public GridRequest ReadGrid()
    {
        var q = Request.Query;
        var filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (param, col, _, _) in Filters)
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
        return Route + (qs.Length > 0 ? "?" + qs : "");
    }

    public string HandlerLink(string handler) { var l = Link(); return l + (l.Contains('?') ? "&" : "?") + "handler=" + handler; }

    /// <summary>
    /// THE shared action bar (#272) on this grid: its rows stand for findings of the newest collection (the grid's
    /// row-to-finding mapping, <see cref="SI.Management.Web.Actions.FindingRowMaps"/>), so the selected rows get the same
    /// actions as every other finding grid -- exemption, comment, status, task, department, export -- on the findings they
    /// stand for, read back on the server. Null when the grid declares no mapping.
    /// </summary>
    public SI.Management.Web.Actions.FindingActionBar? ActionBar(string stripId)
    {
        if (Grid is null || SI.Management.Web.Actions.FindingRowMaps.Of(Spec.Name) is not { Acts: true } map) return null;
        var hidden = new List<(string, string)>();
        if (SI.Management.Web.Exemptions.ExemptedView.Of(HttpContext)?.Carry is { } carry) hidden.Add((SI.Management.Core.ProData.Exempted.QueryKey, carry));
        return new SI.Management.Web.Actions.FindingActionBar
        {
            Source = SI.Management.Web.Actions.SelectionSources.Rows, StripId = stripId, Total = Grid.Total,
            Narrowed = Grid.State.Filters.Count > 0 || !string.IsNullOrWhiteSpace(Grid.State.Search),
            InGetForm = true, ShowOnlySelected = true, Hidden = hidden, Grid = Spec.Name, Map = map.Aggregated ? map : null,
        };
    }

    public string? Cell(IReadOnlyDictionary<string, object?> row, string col) =>
        row.TryGetValue(col, out var v) && v is not null ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;

    /// Where a cell links: a CI's name opens the CI; a finding opens the Detailed view of that finding.
    public virtual string? CellLink(GridColumn c, IReadOnlyDictionary<string, object?> row) => c.Key switch
    {
        "Name" when Cell(row, "CiId") is { Length: > 0 } id => "/Cis/Detail?id=" + Uri.EscapeDataString(id),
        "FindingKey" when Cell(row, "FindingKey") is { Length: > 0 } k => "/Cis/Findings?q=" + Uri.EscapeDataString(k),
        _ => null,
    };

    private async Task<bool> PrepareAsync(CancellationToken ct)
    {
        var resolver = HttpContext?.RequestServices.GetService<SI.Management.Web.Departments.IDepartmentScopeResolver>();
        if (resolver is not null && (await resolver.ResolveAsync(User, ct)).Rows is not null)
        {
            Error = "This view is not available to an account limited to departments: it shows findings across every department.";
            return false;
        }
        var schema = await Cis.SchemaAsync(ct);
        Schema = schema.Data;
        if (!schema.Data.Findings || !schema.Data.Ci) { NotLoaded = true; return false; }
        try { if (HttpContext?.RequestServices.GetService<ICiLifecycleRulesReader>() is { } lr) LifecycleRules = await lr.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log.LogWarning(ex, "the lifecycle settings could not be read; the defaults are shown"); }
        Notice = await PreparingAsync(ct);
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
            var g = await Cis.GridAsync(Applied, req, false, ct);
            Grid = g.Data with { Rows = await FillAsync(DisplayColumns, g.Data.Rows, ct) };
            Queries.Add(QueryInfo.From(g, "The " + Noun));
        }
        catch (ArgumentException ex) { Error = "The request is not valid: " + ex.Message; }
        catch (ViewTimeoutException ex) { Error = CollectionPageModel.TimeoutText(ex.Limit, null); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.LogError(ex, "the CI grid {Grid} could not be read", Spec.Name);
            Error = "The " + Noun + " could not be read from the Pro database: " + ex.Message;
        }
    }

    private async Task<GridPage?> ExportRowsAsync(CancellationToken ct) =>
        // "Export this page" reads the page shown; every other export every matching row
        await PrepareAsync(ct) && await LayoutAsync(ct) ? (await Cis.GridAsync(Applied, ReadGrid(), !SI.Management.Web.Columns.ExportChoices.PageOnly(Request), ct)).Data : null;

    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        GridPage? page;
        try { page = await ExportRowsAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (page is null) return NotFound(Error ?? IndexModel.NotLoadedText);
        var cols = DisplayColumns.Count > 0 ? DisplayColumns : CollectionPageModel.Visible(Spec);
        var rows = await FillAsync(cols, page.Rows, ct);
        return await ExcelExport.FileAsync(ExportName, null, (x, info) =>
        {
            info.Add("Sort", page.State.Sort + (page.State.Desc ? " (descending)" : ""));
            info.Filter("Search", page.State.Search);
            foreach (var f in page.State.Filters) info.Add("Filter: " + (Spec.Column(f.Key)?.Label ?? f.Key), CollectionPageModel.FilterText(f));
            if (page.State.Selected.Count > 0) info.Add("Selected rows", page.State.Selected.Count);
            x.Sheet(info, ExportName, cols.Select(c => c.Label).ToList(), rows.Select(row => (IReadOnlyList<object?>)cols.Select(c => SI.Management.Web.Columns.GridLayout.IsExtra(c) ? SI.Management.Web.Columns.GridLayout.Excel(row, c.Key) : CollectionPageModel.ExcelValue(c, row)).ToList()));
            if (page.Rows.Count >= ProDataFilters.MaxExport) info.Notes.Add(ExportLimitNote(page.Total));
            return Task.CompletedTask;
        }, ct);
    }

    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetCsvAsync(CancellationToken ct)
    {
        GridPage? page;
        try { page = await ExportRowsAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (page is null) return NotFound(Error ?? IndexModel.NotLoadedText);
        var cols = DisplayColumns.Count > 0 ? DisplayColumns : CollectionPageModel.Visible(Spec);
        var rows = await FillAsync(cols, page.Rows, ct);
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", cols.Select(c => Findings.IndexModel.Csv(c.Label))));
        foreach (var row in rows) sb.AppendLine(string.Join(",", cols.Select(c => Findings.IndexModel.Csv(SI.Management.Web.Columns.GridLayout.IsExtra(c) ? SI.Management.Web.Columns.GridLayout.Text(row, c.Key) : CollectionPageModel.Text(c, row, csv: true)))));
        var name = ExportName + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + "Z.csv";
        return File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray(), "text/csv; charset=utf-8", name);
    }
}

/// The Detailed view on CI data: one row per CI and finding, with the finding's state.
public sealed class FindingsModel : CiDataGridModel
{
    public FindingsModel(ICiViews cis, ILogger<FindingsModel> log) : base(cis, log) { }
    /// With the finding's component (OS, SQL, ...) as a column and a filter once the database stores it (the data sync adds it);
    /// #855 M5: over the CIs of the lifecycle chosen (default: active).
    public override GridSpec Spec => CiSql.FindingSpecFor(Schema, Lifecycle);
    public override string Route => "/Cis/Findings";
    public override string Noun => "finding(s)";
    public override string ExportName => "ci-findings";

    private static readonly IReadOnlyList<(string Param, string Column, string Label, IReadOnlyList<string> Choices)> BaseFilters =
        [("severity", "Severity", "Severity", Severities), ("tier", "Tier", "Tier", Tiers), ("state", "State", "State", States), ("class", "Class", "Class", Classes)];
    private static readonly IReadOnlyList<(string Param, string Column, string Label, IReadOnlyList<string> Choices)> ComponentFilters =
        [.. BaseFilters, (ComponentParam, CiSql.FindingComponentKey, "Component", CiSql.FindingComponents)];
    // #772 the ServiceNow sub-CI next to the component (the database stores both)
    private static readonly IReadOnlyList<(string Param, string Column, string Label, IReadOnlyList<string> Choices)> SubCiFilters =
        [.. ComponentFilters, (SubCiParam, CiSql.FindingSubCiKey, CiSql.FindingSubCiLabel, CiSql.FindingSubCis), (PatchCycleParam, CiSql.FindingPatchCycleKey, CiSql.FindingPatchCycleLabel, CiSql.PatchCycles)];
    private static readonly IReadOnlyList<(string Param, string Column, string Label, IReadOnlyList<string> Choices)> OsFamilyFilters =
        [.. SubCiFilters, (OsFamilyParam, CiSql.FindingOsFamilyKey, CiSql.FindingOsFamilyLabel, CiSql.OsFamilies)];

    /// The URL parameter of the component filter.
    public const string ComponentParam = "component";
    /// The URL parameter of the ServiceNow sub-CI filter (#772).
    public const string SubCiParam = "subci";
    /// The URL parameter of the OS family filter (#772).
    public const string OsFamilyParam = "osfamily";
    /// The URL parameter of the patch cycle filter (#772).
    public const string PatchCycleParam = "patchcycle";

    public override IReadOnlyList<(string Param, string Column, string Label, IReadOnlyList<string> Choices)> Filters =>
        Schema.FindingComponent ? (Schema.FindingSubCi ? (Schema.CiOsFamily ? OsFamilyFilters : SubCiFilters) : ComponentFilters) : BaseFilters;

    /// The class, the component and the ServiceNow sub-CI take several values: the findings of devices and Azure resources, of
    /// OS and SQL, in one list.
    public override IReadOnlySet<string> MultiFilters => Several;
    private static readonly IReadOnlySet<string> Several = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "class", ComponentParam, SubCiParam, OsFamilyParam, PatchCycleParam };
}

/// The Summary view on CI data: one row per finding, tier, severity and CMDB group.
public sealed class SummaryModel : CiDataGridModel
{
    public SummaryModel(ICiViews cis, ILogger<SummaryModel> log) : base(cis, log) { }
    /// #855 M6: the groups of the CIs of the lifecycle chosen (default: active).
    public override GridSpec Spec => CiSql.SummarySpecFor(Lifecycle);
    public override string Route => "/Cis/Summary";
    public override string Noun => "finding group(s)";
    public override string ExportName => "ci-summary";
    public override IReadOnlyList<(string Param, string Column, string Label, IReadOnlyList<string> Choices)> Filters { get; } =
        [("severity", "Severity", "Severity", Severities), ("tier", "Tier", "Tier", Tiers)];

    /// #812: the groups are the data sync's (sidata.CiFindingSummary, after the CI build) -- never grouped here per request.
    protected override async Task<string?> PreparingAsync(CancellationToken ct) => await Cis.SummaryWrittenAsync(ct) switch
    {
        false => PreparingText,
        null => NoSchemaText,
        _ => null,
    };

    public const string PreparingText = "The summary of this collection's CI findings is being prepared: the data sync works it out once per run, right after the CI build. It appears when that data sync has finished -- open this page again in a few minutes. Meanwhile every CI finding is on Findings per CI.";
    public const string NoSchemaText = "The summary of the CI findings needs the database update that adds its table: the updater adds it (setup\\Initialize-SIDataSql.ps1 -- it only adds), and the next data sync fills it. Meanwhile every CI finding is on Findings per CI.";
}
