using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Html;
using SI.Management.Core.ProData;
using SI.Management.Web.Pages;

namespace SI.Management.Web.Columns;

/// A header the server sorts on: its link, aria-sort, arrow and the data-sort token the page's scripts and tests know it by.
public sealed record ServerSortLink(string Href, string AriaSort, string Arrow, string Token);

/// <summary>
/// One column of a page's own table (<see cref="DataTable"/>): its key, its label, the value of a row (Excel keeps numbers,
/// dates and booleans typed), and optionally the words on screen, a link, whether it is a number.
/// </summary>
public sealed record DataColumn(string Key, string Label, Func<object, object?> Value, bool Number = false, bool Shown = true,
    Func<object, string?>? Link = null, Func<object, string?>? Text = null, string? Description = null)
{
    /// #1382 (owner 2026-11-25: "some dont have a title"): the title is words, never a raw field name -- the header, the
    /// chooser and the exports read the same (DataColumnKeys.Title); the key stays the column's id.
    public string Label { get; init; } = SI.Management.Core.ProData.DataColumnKeys.Title(Label);
}

/// <summary>
/// #589: a data view's table that is not a SQL grid (CMDB, exemptions, tasks, the management drill-downs, findings,
/// summary...) under THE column mechanism: the person's columns (own + the extra columns its rows can carry -- the CI id,
/// identifiers, linked objects, CI fields, source properties, the finding context), the chooser, and the exports of every
/// row the page lists with exactly the chosen columns, plus "Export all columns". Rendered by
/// Pages/Shared/_DataTable.cshtml; the page may give a column its own HTML (<see cref="Html"/>: a badge, a form).
/// </summary>
public sealed class DataTable
{
    /// The table's id on the page (an element id and the export's t= value): letters, digits and '-'.
    public required string Id { get; init; }
    /// The key its layouts are stored under (cfg.ColumnLayout).
    public required string View { get; init; }
    /// The sheet's name and the export file's stem.
    public required string Title { get; init; }
    public required IReadOnlyList<DataColumn> Columns { get; init; }
    public required IReadOnlyList<object> Rows { get; init; }
    public RowCiKey Ci { get; init; }
    public RowFindingKey Findings { get; init; }
    /// A row's keys (its CI key, finding id, CVE / issue); required when <see cref="Ci"/> or <see cref="Findings"/> is set.
    public Func<object, RowRef>? RefOf { get; init; }
    /// The collection the findings belong to ("" = the newest).
    public string? CollectionId { get; init; }
    /// The shipped layout (own + extra keys); null = the own columns shown out of the box, with the context its rows carry.
    public IReadOnlyList<string>? Shipped { get; init; }
    /// The words above an empty table.
    public string Empty { get; init; } = "None.";
    /// Extra attributes of the table element (e.g. data-exemptions for the page's own scripts and tests).
    public string? Marker { get; init; }
    /// HTML of its own for a column of the page (key -> the cell); a column without one is its text, linked when it has a link.
    public Dictionary<string, Func<object, IHtmlContent>> Html { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// Row selection (a page whose list feeds an action bar): the checkbox's form field name and a row's value; null = none.
    public string? SelectName { get; init; }
    public Func<object, string?>? SelectValue { get; init; }
    /// The element id of the form the checkboxes belong to (null = the form around the table).
    public string? SelectForm { get; init; }
    /// A column the SERVER sorts on (a paged list): its header link, aria-sort and arrow; null = sorted in the browser.
    public Func<string, ServerSortLink?>? ServerSort { get; init; }
    /// The attributes of a row (e.g. data-request="7") -- the page's own scripts and tests read them.
    public Func<object, IReadOnlyDictionary<string, string?>>? RowAttributes { get; init; }

    /// <summary>
    /// #1400 (owner 2026-11-26: "memory issues must not be a problem in any step"; "SI never fewer rows than the source"): an
    /// export's rows after <see cref="Rows"/>, read a CHUNK at a time (the chunk number, 1, 2, ...; no rows = the end) --
    /// every matching row, each chunk's extra columns read for that chunk only and written on before the next is read. Null =
    /// the export writes <see cref="Rows"/> (a page's own small list).
    /// </summary>
    public Func<int, CancellationToken, Task<IReadOnlyList<object>>>? Chunks { get; init; }
    /// #1400 the rows the source counted when the export began (null = not counted): an export whose rows differ says so
    /// (<see cref="SI.Management.Web.Data.ExportSession.Note"/>: the Export sheet, the audit row, the log).
    public long? ExpectedRows { get; init; }
    /// #1400 a row's unique key (with <see cref="Chunks"/>: a key that comes twice aborts the export); null = not compared.
    public Func<object, string?>? KeyOf { get; init; }

    public DataViewLayout Layout { get; private set; } = null!;
    public DataColumnCells Cells { get; private set; } = DataColumnCells.None;
    public bool Loaded { get; private set; }
    private HttpContext? _http;
    private ILogger? _log;
    private IReadOnlyList<string> _wanted = Array.Empty<string>();

    /// The own columns as the layout knows them.
    public IReadOnlyList<ViewColumn> Own => Columns.Select(c => new ViewColumn(c.Key, c.Label, c.Shown, c.Description)).ToList();

    public DataColumn? Column(string key) => Columns.FirstOrDefault(c => c.Key.Equals(key, StringComparison.OrdinalIgnoreCase));

    /// The keys shown, in order.
    public IReadOnlyList<string> Shown => Layout.Layout.Count > 0 ? Layout.Layout : Columns.Where(c => c.Shown).Select(c => c.Key).ToList();

    /// <summary>
    /// Reads the layout and the extra columns' values for the rows (<paramref name="allColumns"/>: every extra column on
    /// offer -- "Export all columns"; else the chosen ones).
    /// </summary>
    public async Task<DataTable> LoadAsync(HttpContext? http, ILogger log, CancellationToken ct, bool allColumns = false)
    {
        var probe = new DataViewLayout { View = View, Own = Own, Ci = Ci, Findings = Findings };
        IReadOnlyList<string> shipped = Shipped ?? DefaultShipped(probe);
        Layout = await new DataViewLayout { View = View, Own = Own, Ci = Ci, Findings = Findings, Shipped = DataViewDefaults.Complete(shipped, probe.Known) }
            .LoadAsync(http, log, ct);
        var wanted = allColumns ? Layout.AllExtras : Layout.ChosenExtras;
        (_http, _log, _wanted) = (http, log, wanted.ToList());
        if (RefOf is not null && wanted.Count > 0 && Rows.Count > 0)
            Cells = await Layout.CellsAsync(http, log, wanted, Rows.Select(RefOf), CollectionId, ct);
        Loaded = true;
        return this;
    }

    /// The own columns shown out of the box, then the context the rows can carry.
    private IReadOnlyList<string> DefaultShipped(DataViewLayout probe)
    {
        var keys = Columns.Where(c => c.Shown).Select(c => c.Key).ToList();
        if (Findings != RowFindingKey.None)
            keys.AddRange((Findings == RowFindingKey.FindingId ? DataViewDefaults.FindingContext : DataViewDefaults.IssueContext)
                .Where(k => k != DataColumnKeys.Component || !Columns.Any(c => c.Key.Equals("Component", StringComparison.OrdinalIgnoreCase))));
        if (Ci != RowCiKey.None) { keys.AddRange(DataViewDefaults.CiIdentity); keys.AddRange(DataViewDefaults.CiContext); }
        return keys.Where(k => probe.Known(k) is not null).ToList();
    }

    /// A cell's value (own or extra).
    public object? Value(object row, string key)
    {
        if (DataColumnKeys.IsExtra(key)) return RefOf is null ? null : DataViewLayout.Cell(Cells, key, RefOf(row));
        return Column(key) is { } c ? c.Value(row) : null;
    }

    /// A cell as text: the column's own words on screen, invariant in a CSV.
    public string Text(object row, string key, bool csv = false)
    {
        if (DataColumnKeys.IsExtra(key)) return DataViewLayout.Text(Value(row, key));
        var c = Column(key);
        if (c is null) return "";
        if (!csv && c.Text is not null) return c.Text(row) ?? "";
        return Format(c.Value(row), csv);
    }

    public static string Format(object? v, bool csv) => v switch
    {
        null => "",
        DateTime d => csv ? DateTime.SpecifyKind(d, DateTimeKind.Utc).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) : Fmt.When(d),
        DateTimeOffset o => csv ? o.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) : Fmt.When(o),
        double or float or decimal => csv ? Convert.ToDouble(v, CultureInfo.InvariantCulture).ToString("R", CultureInfo.InvariantCulture) : ScoreFormat.Number(Convert.ToDouble(v, CultureInfo.InvariantCulture)),
        int or long => csv ? Convert.ToString(v, CultureInfo.InvariantCulture)! : Fmt.Int(Convert.ToInt64(v, CultureInfo.InvariantCulture)),
        bool b => b ? "yes" : "no",
        _ => Convert.ToString(v, CultureInfo.InvariantCulture) ?? "",
    };

    /// A cell as Excel holds it.
    public object? Excel(object row, string key)
    {
        var v = Value(row, key);
        return v switch
        {
            null => null,
            DateTimeOffset o => o.UtcDateTime,
            DateTime d => DateTime.SpecifyKind(d, DateTimeKind.Utc),
            int or long or float or decimal => Convert.ToDouble(v, CultureInfo.InvariantCulture),
            double or bool => v,
            string s => s.Length == 0 ? null : s.Length > 32_000 ? s[..32_000] : s,
            _ => DataViewLayout.Text(v),
        };
    }

    public string Label(string key) => Column(key)?.Label ?? DataColumnKeys.Label(key);

    /// <summary>
    /// One column per name of a property bag the rows carry (a CMDB file's other columns, a record's fields): its key is a
    /// plain column key made of <paramref name="prefix"/> and the name's letters and digits (unique), its label the name.
    /// <paramref name="taken"/>: the headings of the table's other columns -- a name one of them already carries gets
    /// <paramref name="what"/> after it ("Mode (rule field)"), so no two columns of the table read the same.
    /// </summary>
    public static IReadOnlyList<DataColumn> Bag(IEnumerable<object> rows, Func<object, IReadOnlyList<KeyValuePair<string, string>>> bag, string prefix, bool shown = true,
        IEnumerable<string>? taken = null, string? what = null)
    {
        var headings = new HashSet<string>((taken ?? Array.Empty<string>()).Select(h => h.Trim()), StringComparer.OrdinalIgnoreCase);
        var names = rows.SelectMany(r => bag(r).Select(kv => kv.Key)).Where(n => !string.IsNullOrWhiteSpace(n)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var cols = new List<DataColumn>();
        foreach (var n in names)
        {
            var core = new string(n.Where(char.IsAsciiLetterOrDigit).ToArray());
            var key = prefix + (core.Length == 0 ? "Field" : core);
            if (key.Length > 38) key = key[..38];
            var k = key;
            for (var i = 2; !keys.Add(k); i++) k = key + i.ToString(CultureInfo.InvariantCulture);
            var name = n;
            // a heading of its own: the name, said to be the bag's when another column already reads so
            // #1382: in words (a raw name reads as the column's title will), so a clash is seen before the title is made
            var label = SI.Management.Core.ProData.DataColumnKeys.Title(n.Trim());
            if (!headings.Add(label))
            {
                var said = label + " (" + (string.IsNullOrWhiteSpace(what) ? "other" : what.Trim()) + ")";
                label = said;
                for (var i = 2; !headings.Add(label); i++) label = said + " " + i.ToString(CultureInfo.InvariantCulture);
            }
            cols.Add(new DataColumn(k, label, r => bag(r).FirstOrDefault(kv => kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value, Shown: shown));
        }
        return cols;
    }

    /// The export's columns: the chosen ones, or (<paramref name="all"/>) every own column and every extra on offer (and
    /// any extra column the view shows that the offer does not list: what is shown is never left out).
    public IReadOnlyList<string> ExportKeys(bool all) => all ? Columns.Select(c => c.Key).Concat(Layout.AllExtras).ToList() : Shown;

    /// <summary>
    /// #1400 every row an export writes: <see cref="Rows"/>, or (<see cref="Chunks"/>) every chunk in turn -- the extra
    /// columns of a chunk are read for its rows just before they are written (<see cref="Cells"/> then holds that chunk's).
    /// </summary>
    public async IAsyncEnumerable<object> ExportRowsAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        // the rows already read (their extra columns read with the layout), then -- with Chunks -- every chunk after them
        long written = 0;
        // #1400 review: with Chunks, a row whose key came already (it moved across the chunks) aborts the export
        var seen = Chunks is not null && KeyOf is not null ? new SI.Management.Web.Export.KeySet() : null;
        void Check(object row)
        {
            if (seen is not null && KeyOf!(row) is { Length: > 0 } k && !seen.Add(k))
                throw new SI.Management.Web.Data.ExportIncompleteException(SI.Management.Web.Export.GridChunks.Twice(k));
        }
        foreach (var row in Rows) { Check(row); written++; yield return row; }
        if (Chunks is null) yield break;
        await foreach (var chunk in SI.Management.Web.Export.CsvExport.ChunksAsync(Chunks, ct))
        {
            foreach (var row in chunk) Check(row);
            if (RefOf is not null && _wanted.Count > 0 && Layout is not null)
                Cells = await Layout.CellsAsync(_http, _log ?? Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, _wanted, chunk.Select(RefOf), CollectionId, ct);
            foreach (var row in chunk) { written++; yield return row; }
        }
        // #1400 completeness: the rows written against the count the export began with -- a difference ABORTS the export
        // (nothing is downloaded; the audit row and the log say why), never a clean-looking short file
        if (ExpectedRows is { } expected && SI.Management.Web.Export.GridChunks.Note(expected, written) is { } note)
            throw new SI.Management.Web.Data.ExportIncompleteException(note);
    }

    /// The CSV of every export row with these columns, written straight to the file (<see cref="SI.Management.Web.Export.CsvExport"/>).
    public async Task CsvAsync(SI.Management.Web.Export.CsvSink sink, IReadOnlyList<string> keys, CancellationToken ct)
    {
        await foreach (var row in ExportRowsAsync(ct)) await sink.RowAsync(keys.Select(k => Text(row, k, csv: true)));
    }

    /// The headers of an export in words (#1382) -- the same for the CSV and the workbook.
    public IReadOnlyList<string> Headers(IReadOnlyList<string> keys) => SI.Management.Core.ProData.DataColumnKeys.UniqueTitles(keys.Select(k => (k, Label(k)))).ToList();

    /// The sheet of every export row with these columns (continued on a next sheet at Excel's row limit).
    public Task SheetAsync(SI.Management.Web.Export.XlsxWriter x, SI.Management.Web.Export.ExportInfo info, string name, IReadOnlyList<string> keys, CancellationToken ct) =>
        SI.Management.Web.Export.ExcelExport.SheetAsync(x, info, name, Headers(keys), Excels(keys, ct), ct);

    private async IAsyncEnumerable<IReadOnlyList<object?>> Excels(IReadOnlyList<string> keys, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        await foreach (var row in ExportRowsAsync(ct)) yield return keys.Select(k => Excel(row, k)).ToList();
    }

    /// The export file's name stem (letters, digits, '-').
    public string Stem => new string(Title.ToLowerInvariant().Select(ch => char.IsAsciiLetterOrDigit(ch) ? ch : '-').ToArray()).Trim('-');
}
