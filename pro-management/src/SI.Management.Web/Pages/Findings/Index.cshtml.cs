using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Exemptions;
using SI.Management.Web.Export;

namespace SI.Management.Web.Pages.Findings;

/// <summary>
/// The findings browser -- the GUI's replacement for the Excel file. One collection at a time (the newest by default,
/// older ones by CollectionTime), filtered and paged SERVER-side, sorted most important first (asset tier, then risk
/// score), with the tier x severity / domain pivot of the same filtered view. Admins stage exemptions for 1..N rows;
/// nothing is written before Review &amp; commit. The current view exports as CSV or as an Excel workbook.
/// </summary>
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Views)]
public sealed class IndexModel : SI.Management.Web.Columns.DataViewPageModel
{
    public static readonly int[] Sizes = GridSql.PageChoices;
    private readonly IProDataQueries _q;
    private readonly ExemptionRepository _exemptions;
    private readonly ChangeService _changes;
    private readonly ILogger<IndexModel> _log;

    public IndexModel(IProDataQueries q, ExemptionRepository exemptions, ChangeService changes, ILogger<IndexModel> log)
    { _q = q; _exemptions = exemptions; _changes = changes; _log = log; }

    [BindProperty(SupportsGet = true)] public string? C { get; set; }
    [BindProperty(SupportsGet = true)] public string? Tier { get; set; }
    [BindProperty(SupportsGet = true)] public string? Sev { get; set; }
    [BindProperty(SupportsGet = true)] public string? Dom { get; set; }
    [BindProperty(SupportsGet = true)] public string? Rep { get; set; }
    [BindProperty(SupportsGet = true)] public string? Kind { get; set; }
    [BindProperty(SupportsGet = true)] public string? Q { get; set; }
    [BindProperty(SupportsGet = true)] public string? Sort { get; set; }
    [BindProperty(SupportsGet = true)] public int P { get; set; } = 1;
    [BindProperty(SupportsGet = true)] public int Size { get; set; } = 50;
    /// Pivot columns: severity | domain.
    [BindProperty(SupportsGet = true)] public string? Cols { get; set; }

    public IReadOnlyList<CollectionInfo> Collections { get; private set; } = Array.Empty<CollectionInfo>();
    public FindingPage? Results { get; private set; }
    public IReadOnlyList<PivotCell> Pivot { get; private set; } = Array.Empty<PivotCell>();
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Facets { get; private set; } = new Dictionary<string, IReadOnlyList<string>>();
    public IReadOnlyList<ExemptionRow> Exemptions { get; private set; } = Array.Empty<ExemptionRow>();
    public List<QueryInfo> Queries { get; } = new();
    public string? Error { get; private set; }
    public string? Notice { get; private set; }

    public string PivotCols => Cols == "domain" ? "domain" : "severity";

    /// Clicking the Severity header: most severe first, then (clicked again) least severe first -- by RANK both ways.
    public string NextSeveritySort => Sort == FindingSorts.Severity ? FindingSorts.SeverityAscending : FindingSorts.Severity;
    public string SeverityAriaSort => Sort == FindingSorts.Severity ? "descending" : Sort == FindingSorts.SeverityAscending ? "ascending" : "none";
    public string SeverityArrow => Sort == FindingSorts.Severity ? " ▼" : Sort == FindingSorts.SeverityAscending ? " ▲" : "";
    public int Pages => Results is null || Results.Total == 0 ? 1 : (int)Math.Ceiling(Results.Total / (double)Size);

    /// #855 (owner 2026-10-21: "default filter is active, so it should be active only"): the CI lifecycle this view counts --
    /// the address's lifecycle parameter, else the default: the findings of ACTIVE CIs only (said on the page).
    public LifecycleFilter Lifecycle => SI.Management.Web.Pages.LifecycleChoice.Read(HttpContext?.Request);

    public FindingFilter Filter() => new()
    {
        CollectionId = C, Tier = Tier, Severity = Sev, Domain = Dom, Report = Rep, AssetKind = Kind, Text = Q, Lifecycle = Lifecycle,
        Sort = Sort ?? FindingSorts.Importance, Take = Size, Skip = (Math.Max(P, 1) - 1) * Size,
        // what this user may see (#253): null for every role today; a department scope (#254) restricts it
        Visibility = HttpContext?.RequestServices.GetService<IAccessScope>()?.Visibility(User),
    };

    /// The filter dropdowns that show their counts (#287), and what each counts on. #431: a finding counts under EVERY kind
    /// its asset is made of (an Azure VM correlated into its MDE endpoint counts under endpoint and azure), exactly as the
    /// kind filter matches -- so the kinds can add up to more than "All", which counts each finding once.
    public static readonly IReadOnlyDictionary<string, Func<FindingRow, IEnumerable<string?>>> Counted = new Dictionary<string, Func<FindingRow, IEnumerable<string?>>>(StringComparer.Ordinal)
    {
        ["tier"] = r => [r.Tier], ["sev"] = r => [r.Severity], ["dom"] = r => [r.SecurityDomain], ["rep"] = r => [r.ReportName], ["kind"] = r => r.KindsForFilter(),
    };

    /// #287 + #431: the per-value counts of one dropdown over the rows it was read for (a row counts once per value it has).
    public static IReadOnlyList<(string Value, long N)> CountValues(IEnumerable<FindingRow> rows, Func<FindingRow, IEnumerable<string?>> of) =>
        rows.SelectMany(r => of(r).Select(v => v ?? "").Where(v => v.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase))
            .GroupBy(v => v, StringComparer.OrdinalIgnoreCase).Select(g => (g.Key, (long)g.Count())).OrderByDescending(x => x.Item2).ToList();

    /// <summary>
    /// #287: how many findings each choice of ONE filter dropdown gives under the OTHER filters -- the browser's own read
    /// (the same filter, visibility and exempted rule as the list), counted per value. Asked when the dropdown is first
    /// focused; a view too large to count answers without counts.
    /// </summary>
    public async Task<IActionResult> OnGetValueCountsAsync(string? col, CancellationToken ct)
    {
        if (col is null || !Counted.TryGetValue(col, out var of)) return new JsonResult(new { ok = false });
        Normalize();
        try
        {
            var f = ProDataFilters.Normalize(Filter()) with { Skip = 0 };
            f = col switch
            {
                "tier" => f with { Tier = null }, "sev" => f with { Severity = null }, "dom" => f with { Domain = null },
                "rep" => f with { Report = null }, _ => f with { AssetKind = null },
            };
            // #812: a dropdown the stored cells answer (tier / severity / domain / report under those filters) never reads rows
            if (await _q.CellCountsAsync(f, col, ct) is { } stored)
                return new JsonResult(new { ok = true, column = col, total = stored.Sum(x => x.N), values = stored.Select(x => new { value = x.Value, n = x.N, text = Fmt.Int(x.N) }).ToList() });
            var rows = (await _q.ExportAsync(f, ProDataFilters.MaxExport, ct)).Data;
            if (rows.Count >= ProDataFilters.MaxExport) return new JsonResult(new { ok = false, message = "too many findings to count" });
            var counts = CountValues(rows, of).Select(x => new { value = x.Value, n = x.N, text = Fmt.Int(x.N) }).ToList();
            return new JsonResult(new { ok = true, column = col, total = rows.Count, values = counts });
        }
        catch (ArgumentException ex) { return new JsonResult(new { ok = false, message = ex.Message }); }
    }

    /// The counts of one dropdown for the current view (the page's own state in the URL).
    public string CountsLink(string col) { var l = Link(); return l + (l.Contains('?') ? "&" : "?") + "handler=ValueCounts&col=" + col; }

    /// The filters that take several values (owner 2026-10-19: "all filters support multi select"): the multi-select sends
    /// one parameter per value, a link may join them with '|'; the model binds the first value only, so they are read here.
    public static readonly IReadOnlyList<string> ManyValued = ["tier", "sev", "dom", "rep", "kind"];

    private string? Joined(string key, string? bound)
    {
        var values = HttpContext?.Request.Query[key];
        if (values is not { Count: > 1 } v) return bound;
        var joined = string.Join(ProDataFilters.ValueSeparator, v.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!.Trim()));
        return joined.Length == 0 ? null : joined;
    }

    /// The chosen values of one filter (its multi-select's ticks).
    public IReadOnlyList<string> Chosen(string key) => ProDataFilters.Values(key switch
    {
        "tier" => Tier, "sev" => Sev, "dom" => Dom, "rep" => Rep, "kind" => Kind, _ => null,
    }).Select(v => v.Trim()).Where(v => v.Length > 0).ToList();

    private void Normalize()
    {
        (Tier, Sev, Dom, Rep, Kind) = (Joined("tier", Tier), Joined("sev", Sev), Joined("dom", Dom), Joined("rep", Rep), Joined("kind", Kind));
        Size = GridSql.PageSize(Size);
        P = Math.Clamp(P, 1, int.MaxValue / Math.Max(1, Size));   // #881 no page ceiling of our own (it repeated page 100,000 silently)
        Sort = ProDataFilters.Pick(Sort, FindingSorts.All, FindingSorts.Importance);
    }

    public async Task OnGetAsync(CancellationToken ct)
    {
        Normalize();
        FindingFilter f;
        try { f = ProDataFilters.Normalize(Filter()); }
        catch (ArgumentException ex) { Error = "The filter is not valid: " + ex.Message; return; }
        try
        {
            var cols = await _q.CollectionsAsync(60, ct);
            Collections = cols.Data;
            if (Collections.Count == 0)
            {
                Notice = "No collection has been loaded into the Pro database yet. The data sync copies each complete Risk Analysis run into SQL; the browser fills after the first one.";
                Queries.Add(QueryInfo.Sql(cols.Query, "Collections"));
                return;
            }
            var page = await _q.FindingsAsync(f, ct);
            Results = page.Data;
            Queries.Add(QueryInfo.Sql(page.Query, "Findings list"));
            // #812: the default view reads the order and totals the data sync stored once per collection -- never a count and
            // a sort of every finding per open; until they are written it says so
            if (!Results.Prepared) Notice = PreparingText(Results.Schema);
            var pivot = await _q.PivotAsync(f with { Skip = 0 }, ct);
            Pivot = pivot.Data;
            Queries.Add(QueryInfo.Sql(pivot.Query, "Dimensions: asset tier"));
            try { Facets = (await _q.FacetsAsync(ct)).Data; } catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "facets"); }
            try { Exemptions = (await _exemptions.ActiveAsync(null, 2000, ct)).Rows; } catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "exemptions"); }
            await ExemptedAsync(f, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading findings failed");
            Error = "The findings could not be read from the Pro database: " + ex.Message;
        }
    }

    /// What the browser says while the collection's stored order and totals are not written (schema = the database has the tables).
    public static string PreparingText(bool schema) => schema
        ? "This collection's findings list is being prepared: the data sync works out its order and counts once per collection, right after the collection is loaded. It appears when the data sync that is running now, or the next one, has finished -- open this page again in a few minutes. Meanwhile a search, a CI or an asset kind filter lists the findings."
        : "The findings list needs the database update that adds its tables: the updater adds them (setup\\Initialize-SIDataSql.ps1 -- it only adds), and the next data sync fills them. Meanwhile a search, a CI or an asset kind filter lists the findings.";

    /// An exemption approved AFTER this collection was taken covers the row: it applies from the next run (the row carries
    /// no mark in this collection).
    public bool IsExempt(FindingRow r) => !r.IsExempted && Exemptions.Any(e => ExemptionRepository.Covers(e, r.AssetKey, r.ReportName, r.ConfigurationId, r.Cve));

    // ---- #264: exempted findings in this view, and the bulk guard ----

    /// What the layout shows about exempted findings (the tick, the note); null on a page without the scope.
    public ExemptedView? ExemptedState => ExemptedView.Of(HttpContext);
    /// Whether this view includes exempted findings (shown, marked) -- false where the database has no mark.
    public bool ShowsExempted => ExemptedState is { Ready: true, Include: true };
    public int BulkMax { get; private set; } = 500;
    /// Whether "request exemption for all N matching" is offered, and why not.
    public ExemptionBulkGuard.Verdict Bulk { get; private set; } = new(false, null);
    public bool Narrowed => ExemptionBulkGuard.Narrows(Tier, Sev, Dom, Rep, Kind, Q);

    private async Task ExemptedAsync(FindingFilter f, CancellationToken ct)
    {
        var settings = HttpContext?.RequestServices.GetService<ExemptionSettings>();
        if (settings is not null) { try { BulkMax = (await settings.ReadAsync(ct)).BulkMax; } catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "exemption settings"); } }
        Bulk = ExemptionBulkGuard.Check(Narrowed, Results?.Total ?? 0, BulkMax);
        // the note counts exactly the exempted findings THIS filter leaves out
        if (ExemptedState is { Ready: true, Include: false } v && HttpContext is not null)
        {
            try { if (await _q.ExemptedCountAsync(f with { Skip = 0 }, ct) is { } n) HttpContext.Items[ExemptedView.ItemKey] = v with { NotCounted = n }; }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "exempted count"); }
        }
    }

    /// #272: the shared action bar under the list (null = nothing listed). The page's selection form carries the filter
    /// (c, tier, sev, dom, rep, kind, q) and the ticked rows (Sel); the bar adds the source and the #264 tick.
    public SI.Management.Web.Actions.FindingActionBar? ActionBar => Results is not { Total: > 0 } r ? null : new()
    {
        Source = SI.Management.Web.Actions.SelectionSources.Findings, CollectionId = C ?? r.Rows.FirstOrDefault()?.CollectionId, StripId = "quick",
        Total = r.Total, Narrowed = Narrowed, BulkMax = BulkMax,
        Hidden = ExemptedState?.Carry is { } carry ? new[] { (Exempted.QueryKey, carry) } : Array.Empty<(string, string)>(),
    };

    /// The mark of a row the view shows: "Exempted until yyyy-MM-dd".
    public static string MarkOf(FindingRow r) => Exempted.Label(r.ExemptedUntil);

    // ---- #589 the findings as THE data table: the finding's context (software, description, fix, remediation...), its
    // CI with identifiers and context, every finding field -- the chooser; every export takes exactly the chosen columns ----

    /// The view key of the list (its layouts, and the person's remembered sort / filters).
    public const string ViewKey = "findings";

    /// The filters are this page's own address parameters (tier, sev, dom, rep, kind, q, sort, size): what the person last
    /// chose comes back before they are bound; an address that names one wins. The collection, the page and the pivot's
    /// direction are never remembered.
    protected override string? AddressStateView => ViewKey;

    /// Every finding matching the filters (an export's rows; the page shows one page of them).
    private IReadOnlyList<FindingRow>? ExportRows { get; set; }

    protected override async Task LoadForExportAsync(CancellationToken ct)
    {
        Normalize();
        // "Export this page": the rows the page shows (its filters, sort, page and size); else every matching finding
        var rows = SI.Management.Web.Columns.ExportChoices.PageOnly(Request)
            ? (await _q.FindingsAsync(ProDataFilters.Normalize(Filter()), ct)).Data.Rows
            : (await _q.ExportAsync(ProDataFilters.Normalize(Filter()), ProDataFilters.MaxExport, ct)).Data;
        // "Export selected rows": only the ticked findings (Sel travels in the query from the selection strip)
        var sel = Request.Query["Sel"].Concat(Request.Query["sel"]).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v!).ToHashSet(StringComparer.Ordinal);
        ExportRows = sel.Count == 0 ? rows : rows.Where(r => sel.Contains(r.FindingId)).ToList();
    }

    protected override IReadOnlyList<SI.Management.Web.Columns.DataTable> BuildTables()
    {
        var rows = ExportRows ?? Results?.Rows;
        if (rows is null) return Array.Empty<SI.Management.Web.Columns.DataTable>();
        static FindingRow F(object o) => (FindingRow)o;
        var marked = ShowsExempted;
        // the columns of the findings export, in its order and with its names (CollectionTime ... FindingId, Exempted)
        var cols = new List<SI.Management.Web.Columns.DataColumn>
        {
            new("CollectionTime", "CollectionTime", o => F(o).CollectionTime),
            new("Tier", "Tier", o => ExcelExport.Tier(F(o).Tier), Text: o => SI.Management.Web.Pages.Tiers.TierLinks.IsUnclassified(F(o).Tier) ? "Unclassified" : "Tier " + F(o).Tier),
            new("AssetName", "AssetName", o => F(o).AssetName),
            new("AssetKind", "AssetKind", o => F(o).AssetKind),
            new("Severity", "Severity", o => F(o).Severity),
            new("RiskScore", "Risk Score", o => F(o).RiskScore, Number: true, Text: o => Fmt.Score(F(o).RiskScore)),
            new("SecurityDomain", "SecurityDomain", o => F(o).SecurityDomain),
            new("ReportName", "ReportName", o => F(o).ReportName),
            new("Cve", "Cve", o => ExcelExport.Blank(F(o).Cve)),
            new("ConfigurationId", "ConfigurationId", o => ExcelExport.Blank(F(o).ConfigurationId)),
            new("Title", "Title", o => string.IsNullOrEmpty(F(o).Title) ? "(untitled)" : F(o).Title,
                Link: o => "/Findings/Detail?c=" + Uri.EscapeDataString(F(o).CollectionId) + "&id=" + Uri.EscapeDataString(F(o).FindingId)),
            new("AssetKey", "AssetKey", o => F(o).AssetKey),
            new("FindingId", "FindingId", o => F(o).FindingId),
        };
        if (marked) cols.Add(new(ExemptedColumn, ExemptedColumn, o => F(o).IsExempted ? MarkOf(F(o)) : null));
        var collection = C ?? rows.FirstOrDefault()?.CollectionId;
        var t = new SI.Management.Web.Columns.DataTable
        {
            Id = "findings", View = ViewKey, Title = "Findings", Rows = rows.Cast<object>().ToList(), Columns = cols, Marker = "data-grid=\"findings\"",
            Ci = RowCiKey.AssetKey, Findings = RowFindingKey.FindingId, CollectionId = collection ?? "",
            RefOf = o => new SI.Management.Web.Columns.RowRef(F(o).AssetKey, SI.Management.Web.Columns.DataViewLayout.FindingId(F(o).FindingId)),
            SelectName = User.IsReader() ? "Sel" : null, SelectValue = o => F(o).FindingId,
            RowAttributes = o => new Dictionary<string, string?>
            {
                ["class"] = F(o).IsExempted ? "exempted-row" : IsExempt(F(o)) ? "exempt" : null, ["data-exempted"] = F(o).IsExempted ? "1" : null,
            },
            ServerSort = k => k switch
            {
                "Severity" => new SI.Management.Web.Columns.ServerSortLink(Link(("sort", NextSeveritySort)), SeverityAriaSort, SeverityArrow, "severity"),
                "RiskScore" => new SI.Management.Web.Columns.ServerSortLink(Link(("sort", FindingSorts.Risk)), Sort == FindingSorts.Risk ? "descending" : "none", Sort == FindingSorts.Risk ? " ▼" : "", "risk"),
                _ => null,
            },
            // the columns the findings export always had first (in their order), then the finding's context and its CI
            Shipped = cols.Select(c => c.Key).Concat(SI.Management.Web.Columns.DataViewDefaults.FindingContext)
                .Concat(new[] { SI.Management.Core.ProData.DataColumnKeys.CiId, SI.Management.Core.ProData.DataColumnKeys.Id("MdeDeviceId") })
                .Concat(SI.Management.Web.Columns.DataViewDefaults.CiContext).ToList(),
        };
        t.Html["Title"] = o =>
        {
            var f = F(o);
            var html = "<a href=\"/Findings/Detail?c=" + System.Net.WebUtility.HtmlEncode(Uri.EscapeDataString(f.CollectionId)) + "&amp;id=" + System.Net.WebUtility.HtmlEncode(Uri.EscapeDataString(f.FindingId)) + "\">"
                + System.Net.WebUtility.HtmlEncode(string.IsNullOrEmpty(f.Title) ? "(untitled)" : f.Title) + "</a>";
            if (f.IsExempted) html += " <span class=\"badge exempted\" data-exempted-mark>" + System.Net.WebUtility.HtmlEncode(MarkOf(f)) + "</span>";
            else if (IsExempt(f)) html += " <span class=\"badge good\" title=\"Approved after this collection was taken: it applies from the next run\">exemption approved</span>";
            return new Microsoft.AspNetCore.Html.HtmlString(html);
        };
        t.Html["Tier"] = o => new Microsoft.AspNetCore.Html.HtmlContentBuilder()
            .AppendHtml("<span class=\"tierdot t" + System.Net.WebUtility.HtmlEncode(F(o).Tier) + "\"></span>")
            .AppendHtml(SI.Management.Web.Pages.Tiers.TierLinks.AssetLabel(F(o).Tier, F(o).AssetKey));
        return new[] { t };
    }

    /// CSV of the current filtered view: every matching finding (all pages, bounded; or the ticked ones), exactly the
    /// chosen columns. Cells that a spreadsheet would run as a formula are prefixed with a quote.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetCsvAsync(CancellationToken ct)
    {
        SI.Management.Web.Columns.DataTable? t;
        try { t = await ExportTableAsync("findings", false, ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (t is null) return NotFound(Error ?? Notice ?? "nothing to export");
        var name = "securityinsight-findings-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + ".csv";
        return File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(t.Csv(t.ExportKeys(false)))).ToArray(), "text/csv; charset=utf-8", name);
    }

    /// Excel workbook of the current filtered view: EVERY matching row of the collection (not just this page; or the ticked
    /// ones), exactly the chosen columns, read by the fixed parameterised export statement -- at most
    /// <see cref="ProDataFilters.MaxExport"/> rows, under the Pro database's query timeout (Estate:QueryTimeoutSeconds).
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public Task<IActionResult> OnGetXlsxAsync(CancellationToken ct) => WorkbookAsync(false, ct);

    /// "Export all columns": every matching finding with every column the view offers.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public Task<IActionResult> OnGetXlsxAllAsync(CancellationToken ct) => WorkbookAsync(true, ct);

    private async Task<IActionResult> WorkbookAsync(bool all, CancellationToken ct)
    {
        FindingFilter f;
        SI.Management.Web.Columns.DataTable? t;
        try
        {
            Normalize();
            f = ProDataFilters.Normalize(Filter());
            t = await ExportTableAsync("findings", all, ct);
        }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (t is null) return NotFound(Error ?? Notice ?? "nothing to export");
        var keys = t.ExportKeys(all);
        return await ExcelExport.FileAsync(all ? "findings-all-columns" : "findings", C ?? ExportRows?.FirstOrDefault()?.CollectionId, (x, info) =>
        {
            info.Collection = C ?? ExportRows?.FirstOrDefault()?.CollectionId;
            info.Filter("Asset tier", Or(f.Tier)).Filter("Severity", Or(f.Severity)).Filter("Security domain", Or(f.Domain)).Filter("Report", Or(f.Report))
                .Filter("Asset kind", Or(f.AssetKind)).Filter("Search", f.Text).Add("Sort", f.Sort)
                .Add("CI lifecycle", ProDataSql.Life(f.Lifecycle).IsAll ? "every lifecycle" : string.Join(" or ", ProDataSql.Life(f.Lifecycle).States!.Select(CiLifecycleDefinitions.Label)) + (ProDataSql.Life(f.Lifecycle).IsDefault ? " (the default)" : ""));
            if (SI.Management.Web.Columns.ExportChoices.PageOnly(Request)) info.Add("Rows", "the page shown (page " + Fmt.Int(P) + ", " + Fmt.Int(Size) + " per page)");
            info.Add("Columns", all ? "every column this view offers" : t.Layout.Source == ColumnLayout.FromUser ? "your own columns" : t.Layout.Source == ColumnLayout.FromTenant ? "the tenant default columns" : "the standard columns");
            info.Add("Exempted findings", ExemptedState is not { Ready: true } ? "counted as before (no mark in this database)" : ShowsExempted ? "included (column Exempted)" : "left out");
            x.Sheet(info, "Findings", keys.Select(t.Label).ToList(), t.Rows.Select(row => (IReadOnlyList<object?>)keys.Select(k => t.Excel(row, k)).ToList()));
            if (t.Rows.Count >= ProDataFilters.MaxExport)
                info.Notes.Add($"The export stops at {ProDataFilters.MaxExport:N0} rows; narrow the filter to get the rest.");
            return Task.CompletedTask;
        }, ct);
    }


    /// The CSV and Excel column headers (the same list). The score column reads "Risk Score"; the field behind it is
    /// still the finding's RiskScore.
    public static readonly string[] ExportColumns =
        ["CollectionTime", "Tier", "AssetName", "AssetKind", "Severity", "Risk Score", "SecurityDomain", "ReportName", "Cve", "ConfigurationId", "Title", "AssetKey", "FindingId"];

    /// #264: the column an export carries when the view includes exempted findings.
    public const string ExemptedColumn = "Exempted";


    public static string Csv(string? v)
    {
        var s = v ?? "";
        if (s.Length > 0 && "=+-@\t\r".Contains(s[0])) s = "'" + s;
        return s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    // ---- staging exemptions for the selected rows (Admin) ----
    [BindProperty] public List<string> Sel { get; set; } = new();
    [BindProperty] public string ExemptScope { get; set; } = ExemptionRepository.ScopeFinding;
    [BindProperty] public string? ExemptReason { get; set; }
    [BindProperty] public DateTime? ExemptUntil { get; set; }

    [SI.Management.Web.Audit.Audited("exemption.finding.stage")]
    public async Task<IActionResult> OnPostExemptAsync(CancellationToken ct)
    {
        if (!User.MayChange()) return Forbid();
        Normalize();
        // role + scope (#253), server-side: a Delegated user's selection must be inside their scopes, EVERY row -- one out
        // of scope refuses the whole action (403, nothing staged)
        if (!User.IsAdmin())
        {
            var targets = new List<ScopeTarget>();
            foreach (var id in Sel.Distinct().Take(200))
            {
                try { if ((await _q.FindingAsync(C, id, ct)).Data is { } fd) targets.Add(ChangeAccess.ForFinding(fd.Finding, ExemptScope)); }
                catch (ArgumentException) { }
            }
            var gate = HttpContext.RequestServices.GetRequiredService<IAccessScope>().CanAll(User, AccessAction.Exempt, targets);
            if (targets.Count > 0 && !gate.Allowed) return AccessResults.Refused(Request, gate);
        }
        var staged = 0; var refused = new List<string>();
        foreach (var id in Sel.Distinct().Take(200))
        {
            try
            {
                var d = (await _q.FindingAsync(C, id, ct)).Data;
                if (d is null) { refused.Add($"{id}: not in this collection"); continue; }
                var f = d.Finding;
                var req = new ExemptionRequest(ExemptScope, N(f.ReportName), N(f.Cve) is null ? N(f.ConfigurationId) : null, N(f.Cve),
                    ExemptScope == ExemptionRepository.ScopeIssue ? null : f.AssetKey, f.AssetName, ExemptReason ?? "",
                    ExemptUntil is { } u ? DateTime.SpecifyKind(u.Date.AddDays(1).AddSeconds(-1), DateTimeKind.Utc) : null, N(f.SecurityDomain));
                var (change, why) = _changes.NewExemption(req);
                if (change is null) { refused.Add($"{f.AssetName}: {string.Join("; ", why)}"); continue; }
                await _changes.StageAsync(User, ChangeAccess.Stamp(change, ChangeAccess.ForFinding(f, ExemptScope)), ct);
                staged++;
            }
            catch (ArgumentException ex) { refused.Add($"{id}: {ex.Message}"); }
        }
        TempData["toast"] = staged > 0
            ? $"{Fmt.Int(staged)} exemption(s) staged -- nothing is written until you review and commit." + (refused.Count > 0 ? $" {Fmt.Int(refused.Count)} refused: {refused[0]}" : "")
            : "Nothing staged: " + (refused.FirstOrDefault() ?? "select at least one finding");
        TempData["toastKind"] = staged > 0 ? (refused.Count > 0 ? "warn" : "ok") : "error";
        return Redirect(Link(("p", P > 1 ? P.ToString(CultureInfo.InvariantCulture) : null)));
    }

    private static string? N(string? s) => string.IsNullOrWhiteSpace(s) ? null : s;

    /// A filter of several values in words ("Endpoint or Azure").
    public static string? Or(string? joined) => joined is null ? null : string.Join(" or ", ProDataFilters.Values(joined));

    /// #252: "request exemption for every finding matching the current filter" -- the request page re-reads them.
    public string RequestAllLink()
    {
        var d = new (string, string?)[] { ("src", "findings"), ("all", "1"), ("c", C), ("tier", Tier), ("sev", Sev), ("dom", Dom), ("rep", Rep), ("kind", Kind), ("q", Q), (LifecycleFilter.Parameter, Lifecycle.QueryValue),
            (Exempted.QueryKey, ExemptedState?.Carry) };
        return "/Exemptions/Request?" + string.Join("&", d.Where(x => !string.IsNullOrEmpty(x.Item2)).Select(x => x.Item1 + "=" + Uri.EscapeDataString(x.Item2!)));
    }

    /// This page's URL with the current filters, some overridden (null removes one).
    public string Link(params (string Key, string? Value)[] overrides)
    {
        var d = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["c"] = C, ["tier"] = Tier, ["sev"] = Sev, ["dom"] = Dom, ["rep"] = Rep, ["kind"] = Kind, ["q"] = Q,
            ["sort"] = Sort == FindingSorts.Importance ? null : Sort, ["size"] = Size == GridSql.DefaultPageSize ? null : Size.ToString(CultureInfo.InvariantCulture),
            ["cols"] = Cols, ["p"] = P > 1 ? P.ToString(CultureInfo.InvariantCulture) : null,
            // #855: the lifecycle choice travels with every link (the default has no parameter)
            [LifecycleFilter.Parameter] = Lifecycle.QueryValue,
        };
        foreach (var (k, v) in overrides) d[k] = v;
        if (overrides.All(o => o.Key != "p")) d["p"] = null;      // a new filter starts at page 1
        // #264: the view's tick travels with every link of the page (paging, filters, pivot cells, exports)
        if (!d.ContainsKey(Exempted.QueryKey) && ExemptedState?.Carry is { } carry) d[Exempted.QueryKey] = carry;
        var qs = string.Join("&", d.Where(kv => !string.IsNullOrEmpty(kv.Value)).Select(kv => kv.Key + "=" + Uri.EscapeDataString(kv.Value!)));
        return "/Findings" + (qs.Length > 0 ? "?" + qs : "");
    }
}
