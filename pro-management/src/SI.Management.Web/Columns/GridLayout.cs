using System.Globalization;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Columns;

/// <summary>
/// The column mechanism (<see cref="DataViewLayout"/>) on a SQL grid (<see cref="GridSpec"/>: the collection views, All
/// CIs, the CI data views, the records): the grid statement keeps every column it has (hidden or not -- only what is shown
/// and exported changes, so the SQL and its cache never depend on a person's layout); the chosen own columns are shown in
/// the chosen order; the chosen extra columns are added to the rows of the page (or the export) afterwards, by each row's
/// keys. PURE apart from <see cref="FillAsync"/>.
/// </summary>
public static class GridLayout
{
    /// Columns a view always shows whatever the layout (the exempted mark: a finding shown although exempted says so).
    public static readonly IReadOnlySet<string> AlwaysShown = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { Exempted.MarkKey };

    /// The own columns of a grid: every column, shown out of the box when it is not hidden.
    public static IReadOnlyList<ViewColumn> Own(GridSpec spec) => spec.Columns.Select(c => new ViewColumn(c.Key, c.Label, !c.Hidden)).ToList();

    /// The spec with a layout: the chosen own columns shown in the chosen order, every other column carried hidden.
    public static GridSpec Apply(GridSpec spec, IReadOnlyList<string> layout)
    {
        var chosen = layout.Select(spec.Column).Where(c => c is not null).Select(c => c!).DistinctBy(c => c.Key, StringComparer.OrdinalIgnoreCase).ToList();
        if (chosen.Count == 0) return spec;
        var rest = spec.Columns.Where(c => !chosen.Any(x => x.Key.Equals(c.Key, StringComparison.OrdinalIgnoreCase)))
            .Select(c => AlwaysShown.Contains(c.Key) ? c : c with { Hidden = true });
        return spec with { Columns = chosen.Select(c => c with { Hidden = false }).Concat(rest).ToList() };
    }

    /// An extra column as a grid column: text, no filter, not sortable (it is read for the rows of the page only).
    public static GridColumn Extra(string key, string label) => new(key, label, GridType.Text, GridFilter.None, Search: false, Sortable: false);

    public static bool IsExtra(GridColumn c) => DataColumnKeys.IsExtra(c.Key);

    /// The columns shown, in the layout's order: the chosen own columns (shown in <paramref name="applied"/>) and the chosen
    /// extras; a column the view always shows that the layout does not name stays where the grid has it.
    public static IReadOnlyList<GridColumn> Display(GridSpec applied, DataViewLayout layout)
    {
        var visible = applied.Columns.Where(c => !c.Hidden).ToList();
        var shown = new List<GridColumn>();
        var anyOwn = false;
        foreach (var k in layout.Layout)
        {
            if (DataColumnKeys.IsExtra(k)) { shown.Add(Extra(k, layout.Label(k))); continue; }
            if (visible.FirstOrDefault(c => c.Key.Equals(k, StringComparison.OrdinalIgnoreCase)) is { } c) { shown.Add(c); anyOwn = true; }
        }
        // no own column chosen (a layout of extras only) -> the grid's own visible columns first
        if (!anyOwn) shown.InsertRange(0, visible);
        foreach (var c in visible.Where(c => !shown.Contains(c))) shown.Insert(Math.Min(1, shown.Count), c);
        return shown;
    }

    /// Every column the view can offer (Export all columns): every own column of the grid, then every extra on offer (and
    /// any extra column the view shows that the offer does not list).
    public static IReadOnlyList<GridColumn> All(GridSpec spec, DataViewLayout layout) =>
        spec.Columns.Concat(layout.AllExtras.Select(k => Extra(k, layout.Label(k)))).ToList();

    /// A row's keys from its cells: the CI key column, the finding id column, the CVE column (each optional).
    public static RowRef RefOf(IReadOnlyDictionary<string, object?> row, string? ciColumn, string? findingColumn, string? cveColumn) => new(
        ciColumn is not null && row.TryGetValue(ciColumn, out var ci) ? Convert.ToString(ci, CultureInfo.InvariantCulture) : null,
        findingColumn is not null && row.TryGetValue(findingColumn, out var f) ? DataViewLayout.FindingId(f) : null,
        cveColumn is not null && row.TryGetValue(cveColumn, out var cve) ? Convert.ToString(cve, CultureInfo.InvariantCulture) : null);

    /// <summary>
    /// The rows with the values of the <paramref name="columns"/>' extra columns added (read once, by the rows' keys). Rows
    /// keep every cell they had; a row without a key gets empty extra cells.
    /// </summary>
    public static async Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> FillAsync(HttpContext? http, ILogger log, DataViewLayout layout,
        IReadOnlyList<GridColumn> columns, IReadOnlyList<IReadOnlyDictionary<string, object?>> rows, Func<IReadOnlyDictionary<string, object?>, RowRef> refOf,
        string? collectionId, CancellationToken ct)
    {
        var extras = columns.Where(IsExtra).Select(c => c.Key).ToList();
        if (extras.Count == 0 || rows.Count == 0) return rows;
        var refs = rows.Select(refOf).ToList();
        var cells = await layout.CellsAsync(http, log, extras, refs, collectionId, ct);
        var result = new List<IReadOnlyDictionary<string, object?>>(rows.Count);
        for (var i = 0; i < rows.Count; i++)
        {
            var d = new Dictionary<string, object?>(rows[i], StringComparer.OrdinalIgnoreCase);
            foreach (var k in extras) d[k] = DataViewLayout.Cell(cells, k, refs[i]);
            result.Add(d);
        }
        return result;
    }

    /// An extra cell of a row as text (screen / CSV).
    public static string Text(IReadOnlyDictionary<string, object?> row, string key) => row.TryGetValue(key, out var v) ? DataViewLayout.Text(v) : "";

    /// An extra cell of a row as Excel holds it.
    public static object? Excel(IReadOnlyDictionary<string, object?> row, string key) => row.TryGetValue(key, out var v) ? DataViewLayout.Excel(v) : null;
}
