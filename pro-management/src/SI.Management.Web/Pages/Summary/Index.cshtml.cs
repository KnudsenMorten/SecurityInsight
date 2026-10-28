using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Export;
using SI.Management.Web.Summary;

namespace SI.Management.Web.Pages.Summary;

/// <summary>
/// Risks > Summary (REQUIREMENTS #583): the RiskAnalysis_Summary workbook's rows -- one row per recommendation x tier x
/// severity x risk factors x CMDB group, with the assets it impacts -- MANAGEMENT-FRIENDLY by default: one section per tier
/// (Tier 0 first), a headline of its Critical / High recommendations and assets, and inside it the most critical risk first
/// (rating Critical > High > Moderate > Low, then the highest risk score). Each row lists its first impacted assets, each a
/// link to its CI; "+ N more" opens the row with every asset (?row=). Filters on each column, search, and Export to Excel =
/// the workbook's sheet. The newest complete Risk Analysis Summary collection (the data sync loads it). Every reader; an
/// account limited to departments sees none of it (the rows span every department).
/// </summary>
/// #636 (owner 2026-10-19: "summary could be build as views with the detailed data instead"): while the Risk Analysis Summary
/// step is off (Jobs/SummaryStep.cs) -- or with ?view=groups -- the page is THE GROUPED VIEW of the Detailed findings: the stored
/// groupings of the newest complete Detailed collection (sidata.SummaryGroup, Summary/SummaryGroups.cs), per recommendation with
/// its affected assets, per asset, tier, Domain > Category > Subcategory, risk rating, department, severity and report.
public sealed class IndexModel(ISummaryReportStore store, ILogger<IndexModel> log, ISummaryGroupsStore? groups = null,
    SI.Management.Web.Jobs.ISummaryStep? summaryStep = null) : SI.Management.Web.Columns.DataViewPageModel
{
    // ---- #636 the grouped view ----
    public const string GroupsNoTablesText = "The Pro database does not have the grouped Summary tables yet -- the next update adds them (or run setup\\Initialize-SIDataSql.ps1), then the next data sync fills them.";
    public const string GroupsNoCollectionText = "No complete Risk Analysis Detailed collection is in the Pro database yet -- it arrives with the next data sync after a Risk Analysis Detailed run.";
    public const string GroupsPreparingText = "The grouped rows of the newest collection are being prepared by the data sync -- they appear after its next run.";
    /// True: the page shows the grouped view (the Summary step is off, or ?view=groups).
    public bool Grouped { get; private set; }
    /// False: the Risk Analysis Summary step is off -- the Summary report's own rows are not offered.
    public bool SummaryOn { get; private set; } = true;
    public SummaryGroupState? GroupState { get; private set; }
    public SummaryGrouping Grouping { get; private set; } = SummaryGroups.All[0];
    public IReadOnlyList<SummaryGroupRow> GroupRows { get; private set; } = [];
    public long GroupTotal { get; private set; }
    /// True: the exempted findings are left out (sidata.SummaryGroupCounted).
    public bool Counted { get; private set; }
    public IReadOnlyDictionary<string, string> Departments { get; private set; } = new Dictionary<string, string>();
    public string? GroupSearch { get; private set; }

    private async Task LoadGroupsAsync(CancellationToken ct)
    {
        var resolver = HttpContext?.RequestServices.GetService<SI.Management.Web.Departments.IDepartmentScopeResolver>();
        if (resolver is not null && (await resolver.ResolveAsync(User, ct)).Rows is not null)
        {
            Error = "This view is not available to an account limited to departments: it shows findings across every department.";
            return;
        }
        var q = Request.Query;
        Grouping = SummaryGroups.Of(q["by"]);
        Counted = string.Equals(q["exempted"], "hide", StringComparison.OrdinalIgnoreCase);
        Size = int.TryParse(q["size"], NumberStyles.None, CultureInfo.InvariantCulture, out var s) && SummaryGroups.Sizes.Contains(s) ? s : SummaryGroups.DefaultSize;
        PageNo = int.TryParse(q["p"], NumberStyles.None, CultureInfo.InvariantCulture, out var p) && p >= 1 ? p : 1;
        var search = ((string?)q["q"])?.Trim();
        if (search is { Length: > 0 } && (search.Length > MaxText || search.Any(char.IsControl))) throw new ArgumentException("the search is not valid");
        GroupSearch = string.IsNullOrEmpty(search) ? null : search;
        GroupState = await groups!.StateAsync(ct);
        if (GroupState is not { HasTables: true, CollectionId: { } cid, Prepared: true }) return;
        (GroupRows, GroupTotal) = await groups.RowsAsync(cid, Grouping.Id, Counted, (PageNo - 1) * Size, Size, GroupSearch, ct);
        if (Grouping.Id == "department") Departments = await groups.DepartmentNamesAsync(ct);
    }

    /// A link to the grouped view with its choices, some replaced (null / "" = removed). Paging resets unless given.
    public string GroupLink(params (string Key, string? Value)[] overrides)
    {
        var cur = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["by"] = Grouping.Id == SummaryGroups.Default ? null : Grouping.Id, ["exempted"] = Counted ? "hide" : null, ["q"] = GroupSearch,
            ["size"] = Size == SummaryGroups.DefaultSize ? null : Size.ToString(CultureInfo.InvariantCulture), ["p"] = PageNo > 1 ? PageNo.ToString(CultureInfo.InvariantCulture) : null,
            ["view"] = SummaryOn ? "groups" : null,
        };
        if (overrides.Length > 0 && !overrides.Any(o => o.Key == "p")) cur["p"] = null;
        foreach (var (k, v) in overrides) cur[k] = v;
        var qs = string.Join("&", cur.Where(kv => !string.IsNullOrEmpty(kv.Value)).Select(kv => Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(kv.Value!)));
        return Route + (qs.Length > 0 ? "?" + qs : "");
    }

    public const string Route = "/Summary";
    public const string NotLoadedText = "No Risk Analysis Summary collection is in the Pro database yet -- it arrives with the next data sync after a Risk Analysis Summary run.";
    public const string NoTablesText = "The Pro database does not have the Summary report tables yet -- the next update adds them (or run setup\\Initialize-SIDataSql.ps1), then the next data sync fills them.";
    public const int MaxText = 400;

    public SummaryState State { get; private set; } = SummaryState.Missing;
    public SummaryFilter Filter { get; private set; } = new();
    public int Size { get; private set; } = SummaryReport.DefaultSize;
    public int PageNo { get; private set; } = 1;
    public IReadOnlyList<SummaryTierHead> Heads { get; private set; } = [];
    public IReadOnlyList<SummaryRowView> Rows { get; private set; } = [];
    public ILookup<int, SummaryAssetRef> Assets { get; private set; } = Array.Empty<SummaryAssetRef>().ToLookup(a => a.RowNo);
    public IReadOnlyList<SummaryFacet> Facets { get; private set; } = [];
    /// The one row opened with every impacted asset (?row=), or null.
    public SummaryRowView? One { get; private set; }
    public IReadOnlyList<SummaryAssetRef> OneAssets { get; private set; } = [];
    public string? Error { get; private set; }

    /// The rows of one tier group, in the default order.
    public IEnumerable<SummaryRowView> RowsOf(int tierGroup) => Rows.Where(r => r.TierGroup == tierGroup);
    public IEnumerable<string> FacetValues(string facet) => Facets.Where(f => f.Facet == facet).OrderByDescending(f => f.N).ThenBy(f => f.Value, StringComparer.OrdinalIgnoreCase).Select(f => f.Value);

    /// The filters from the URL, refused when a value does not fit (never passed on as anything but a parameter). Every
    /// filter may hold several values (owner 2026-10-19): one parameter per value (the multi-select), or '|'-joined (a link).
    public static SummaryFilter ReadFilter(IQueryCollection q)
    {
        static IReadOnlyList<string> Many(IQueryCollection q, string k)
        {
            var values = SI.Management.Web.Pages.MultiFilter.ValuesOf(q, k);
            foreach (var v in values) if (v.Length > MaxText || v.Any(char.IsControl)) throw new ArgumentException("the filter '" + k + "' is not valid");
            if (values.Count > SI.Management.Core.ProData.GridSql.MaxValues) throw new ArgumentException("at most " + SI.Management.Core.ProData.GridSql.MaxValues + " values per filter");
            return values;
        }
        static string? S(IQueryCollection q, string k) => Many(q, k) is { Count: > 0 } v ? string.Join(SI.Management.Core.ProData.ProDataFilters.ValueSeparator, v) : null;
        var tiers = Many(q, "tier").Select(t =>
            t.Equals("none", StringComparison.OrdinalIgnoreCase) ? SummaryReport.NoTier
            : int.TryParse(t, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n is >= 0 and <= 9 ? n
            : throw new ArgumentException("the tier filter is not valid")).Distinct().ToList();
        return new SummaryFilter(tiers.Count == 1 ? tiers[0] : null, S(q, "rating"), S(q, "severity"), S(q, "domain"), S(q, "category"), S(q, "subcategory"), S(q, "cmdb"), S(q, "report"),
            ((string?)q["q"])?.Trim() is { Length: > 0 } text ? (text.Length > MaxText || text.Any(char.IsControl) ? throw new ArgumentException("the filter 'q' is not valid") : text) : null)
        {
            Tiers = tiers.Count > 1 ? tiers : null,
        };
    }

    /// A link to this page with the current filters, some replaced (null / "" = removed). Paging resets unless given.
    public string Link(params (string Key, string? Value)[] overrides)
    {
        var over = overrides.Select(o => o.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var parts = new List<(string, string)>();
        foreach (var kv in Request.Query)
        {
            if (kv.Key.Equals("handler", StringComparison.OrdinalIgnoreCase) || kv.Key.Equals("row", StringComparison.OrdinalIgnoreCase) || over.Contains(kv.Key)) continue;
            if (kv.Key.Equals("p", StringComparison.OrdinalIgnoreCase) && overrides.Length > 0) continue;
            foreach (var v in kv.Value) if (!string.IsNullOrEmpty(v)) parts.Add((kv.Key, v));
        }
        foreach (var (k, v) in overrides) if (!string.IsNullOrEmpty(v)) parts.Add((k, v));
        var qs = string.Join("&", parts.Select(x => Uri.EscapeDataString(x.Item1) + "=" + Uri.EscapeDataString(x.Item2)));
        return Route + (qs.Length > 0 ? "?" + qs : "");
    }

    public string HandlerLink(string handler) { var l = Link(); return l + (l.Contains('?') ? "&" : "?") + "handler=" + handler; }
    public string RowLink(int rowNo) { var l = Link(); return l + (l.Contains('?') ? "&" : "?") + "row=" + rowNo.ToString(CultureInfo.InvariantCulture); }
    public static string TierParam(int tierGroup) => tierGroup == SummaryReport.NoTier ? "none" : tierGroup.ToString(CultureInfo.InvariantCulture);

    private async Task<bool> PrepareAsync(CancellationToken ct)
    {
        var resolver = HttpContext?.RequestServices.GetService<SI.Management.Web.Departments.IDepartmentScopeResolver>();
        if (resolver is not null && (await resolver.ResolveAsync(User, ct)).Rows is not null)
        {
            Error = "This view is not available to an account limited to departments: it shows findings across every department.";
            return false;
        }
        Filter = ReadFilter(Request.Query);
        State = await store.StateAsync(ct);
        return State.HasTables && State.Latest is not null;
    }

    public async Task OnGetAsync(CancellationToken ct)
    {
        // #636: the Summary step off (or ?view=groups) -> the grouped view of the Detailed findings
        SummaryOn = summaryStep is null || await summaryStep.IsOnAsync(ct);
        Grouped = groups is not null && (!SummaryOn || string.Equals(Request.Query["view"], "groups", StringComparison.OrdinalIgnoreCase));
        if (Grouped)
        {
            try { await LoadGroupsAsync(ct); }
            catch (ArgumentException ex) { Error = "The filter is not valid: " + ex.Message; }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                log.LogError(ex, "the grouped Summary view could not be read");
                Error = "The grouped Summary view could not be read from the Pro database: " + ex.Message;
            }
            return;
        }
        try
        {
            var q = Request.Query;
            Size = int.TryParse(q["size"], NumberStyles.None, CultureInfo.InvariantCulture, out var s) && SummaryReport.Sizes.Contains(s) ? s : SummaryReport.DefaultSize;
            PageNo = int.TryParse(q["p"], NumberStyles.None, CultureInfo.InvariantCulture, out var p) && p >= 1 ? p : 1;
            if (!await PrepareAsync(ct)) return;
            var at = State.Latest!.CollectionTime;
            if (int.TryParse(q["row"], NumberStyles.None, CultureInfo.InvariantCulture, out var rowNo))
            {
                One = await store.RowAsync(at, rowNo, ct);
                if (One is null) { Response.StatusCode = StatusCodes.Status404NotFound; Error = "That row is not in the newest Summary collection (a newer collection may have replaced it)."; return; }
                OneAssets = await store.AssetsAsync(at, [rowNo], int.MaxValue, State.HasCi, ct);
                return;
            }
            Facets = await store.FacetsAsync(at, ct);
            Heads = await store.HeadsAsync(at, Filter, ct);
            // one tier chosen: its rows, paged; else each tier's first rows, with a link to the rest of the tier
            var skip = Filter.Tier is not null ? (PageNo - 1) * Size : 0;
            Rows = await store.RowsAsync(at, Filter, skip, Size, false, ct);
            Assets = (await store.AssetsAsync(at, Rows.Select(r => r.RowNo).ToList(), SummaryReport.InlineAssets, State.HasCi, ct)).ToLookup(a => a.RowNo);
        }
        catch (ArgumentException ex) { Error = "The filter is not valid: " + ex.Message; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogError(ex, "the Summary report could not be read");
            Error = "The Summary report could not be read from the Pro database: " + ex.Message;
        }
    }

    // ---- #589 the rows as THE data table: one layout for every tier, the recommendation's context (description, fix,
    // remediation, affected software...), every column of the workbook -- the chooser; every export the chosen columns ----

    public const string View = "summary";

    /// The filters are this page's own address parameters (tier, rating, severity, domain, category, subcategory, cmdb,
    /// report, q, size): what the person last chose comes back before they are read; an address that names one wins. The
    /// page number and the one row opened are never remembered. Each tier's table keeps its own sort in the browser.
    protected override string? AddressStateView => View;

    /// Every row the filters keep, in the page's order (an export's rows).
    private IReadOnlyList<SummaryRowView>? ExportRows { get; set; }

    protected override async Task LoadForExportAsync(CancellationToken ct)
    {
        if (!await PrepareAsync(ct)) return;
        ExportRows = await store.RowsAsync(State.Latest!.CollectionTime, Filter, 0, SI.Management.Core.ProData.ProDataFilters.MaxExport, true, ct);
    }

    /// The workbook's column name as a column key (letters and digits).
    public static string KeyOf(string column) => new(column.Where(char.IsAsciiLetterOrDigit).ToArray());

    /// The columns: the row number on the page, then every column of the RiskAnalysis_Summary workbook, in its order.
    private IReadOnlyList<SI.Management.Web.Columns.DataColumn> Columns(IReadOnlyDictionary<int, int> numbers)
    {
        static SummaryRowView R(object o) => (SummaryRowView)o;
        var shown = new HashSet<string>(StringComparer.Ordinal)
        {
            "ConfigurationName", "ConfigurationId", "SecuritySeverity", "RiskRating", "RiskScoreTotal", "RiskScoreTotal_Weighted", "RiskFactorIds", "cmdbId", "cmdbName",
            "ImpactedAssetCount", "ImpactedAssetsList", "MoreDetails", "Category", "Subcategory",
        };
        var cols = new List<SI.Management.Web.Columns.DataColumn>
        {
            new("No", "#", o => numbers.TryGetValue(R(o).RowNo, out var n) ? (object?)n : null, Number: true),
            new("Factors", "Risk factors", o => SummaryReport.FactorsText(R(o))),
        };
        for (var i = 0; i < SummaryReport.ExportColumns.Count; i++)
        {
            var at = i;
            var name = SummaryReport.ExportColumns[i];
            var number = name is "CriticalityTier" or "RiskFactor_Consequence" or "RiskFactor_Probability" or "RiskConsequenceScore" or "RiskProbabilityScore" or "RiskScoreTotal"
                or "RiskScore_Weight_Factor" or "RiskScoreTotal_Weighted" or "ImpactedAssetCount";
            Func<object, string?>? text = null;
            if (name is "RiskScoreTotal" or "RiskScoreTotal_Weighted") text = o => Fmt.Score(SummaryReport.ExportCells(R(o))[at] as double?);
            cols.Add(new(KeyOf(name), name, o => SummaryReport.ExportCells(R(o))[at], Number: number, Shown: shown.Contains(name), Text: text));
        }
        return cols;
    }

    private SI.Management.Web.Columns.DataTable Table(string id, string title, IReadOnlyList<SummaryRowView> rows, IReadOnlyDictionary<int, int> numbers)
    {
        static SummaryRowView R(object o) => (SummaryRowView)o;
        var t = new SI.Management.Web.Columns.DataTable
        {
            Id = id, View = View, Title = title, Rows = rows.Cast<object>().ToList(), Columns = Columns(numbers),
            Findings = SI.Management.Core.ProData.RowFindingKey.Issue, CollectionId = "",
            RefOf = o => new SI.Management.Web.Columns.RowRef(null, null, R(o).ConfigurationId),
            Marker = "class=\"findings summary-table\" data-summary-table=\"" + (id.StartsWith("tier-", StringComparison.Ordinal) ? id[5..] : id) + "\"",
            RowAttributes = o => new Dictionary<string, string?> { ["data-row"] = R(o).RowNo.ToString(CultureInfo.InvariantCulture), ["data-rating"] = R(o).RiskRating },
            Shipped = new[] { "No", "ConfigurationName", "ConfigurationId", "Category", "Subcategory" }
                .Concat(SI.Management.Web.Columns.DataViewDefaults.IssueContext.Where(k => k != SI.Management.Core.ProData.DataColumnKeys.Assets))
                .Concat(new[] { "SecuritySeverity", "RiskRating", "RiskScoreTotal", "RiskScoreTotalWeighted", "Factors", "cmdbId", "cmdbName", "ImpactedAssetCount", "ImpactedAssetsList", "MoreDetails" })
                .ToList(),
        };
        // on the page the recommendation reads as before (its path under it) and the impacted assets are links (+ N more)
        t.Html["ConfigurationName"] = o => new Microsoft.AspNetCore.Html.HtmlString("<strong>" + System.Net.WebUtility.HtmlEncode(R(o).ConfigurationName ?? "") + "</strong><br /><span class=\"hint small\">"
            + System.Net.WebUtility.HtmlEncode(SummaryReport.Path(R(o))) + "</span>");
        t.Html["RiskRating"] = o => SI.Management.Web.Columns.DataCellHtml.Badges((SummaryReport.RatingClass(R(o).RiskRating), R(o).RiskRating ?? "--"));
        t.Html["ImpactedAssetsList"] = o =>
        {
            var r = R(o);
            var shown = Assets[r.RowNo].ToList();
            if (shown.Count == 0) return SI.Management.Web.Columns.DataCellHtml.Render(r.ImpactedAssetsList);
            var more = Math.Max(r.ImpactedAssetCount, shown.Count) - shown.Count;
            var html = string.Join(", ", shown.Select(a => "<a href=\"" + System.Net.WebUtility.HtmlEncode(a.Href) + "\" data-asset-link>" + System.Net.WebUtility.HtmlEncode(a.Label) + "</a>"));
            if (more > 0) html += " <a href=\"" + System.Net.WebUtility.HtmlEncode(RowLink(r.RowNo)) + "\" class=\"summary-more\" data-more=\"" + more + "\">+ " + Fmt.Int(more) + " more</a>";
            return new Microsoft.AspNetCore.Html.HtmlString("<span data-assets>" + html + "</span>");
        };
        return t;
    }

    protected override IReadOnlyList<SI.Management.Web.Columns.DataTable> BuildTables()
    {
        if (ExportRows is { } all)
            return new[] { Table("summary", "Summary", all, all.Select((r, i) => (r.RowNo, i + 1)).GroupBy(x => x.RowNo).ToDictionary(g => g.Key, g => g.First().Item2)) };
        var first = Filter.Tier is not null ? (PageNo - 1) * Size : 0;
        return Heads.Select(h =>
        {
            var rows = RowsOf(h.TierGroup).ToList();
            var numbers = rows.Select((r, i) => (r.RowNo, first + i + 1)).GroupBy(x => x.RowNo).ToDictionary(g => g.Key, g => g.First().Item2);
            return Table("tier-" + TierParam(h.TierGroup), SummaryReport.TierLabel(h.TierGroup), rows, numbers);
        }).ToList();
    }

    /// The all-rows exports: every row the filters keep (every tier, every page), exactly the chosen columns.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public Task<IActionResult> OnGetXlsxAsync(CancellationToken ct) => OnGetTableExportAsync("summary", "xlsx", ct);

    [SI.Management.Web.Audit.Audited("data.export.download")]
    public Task<IActionResult> OnGetCsvAsync(CancellationToken ct) => OnGetTableExportAsync("summary", "csv", ct);

    /// "Export all columns": every row the filters keep with every column of the workbook and every context column.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public Task<IActionResult> OnGetXlsxAllAsync(CancellationToken ct) => OnGetTableExportAsync("summary", "all", ct);

    /// The chooser of the page (one layout for every tier's table).
    public SI.Management.Web.Cis.ColumnChooser? Chooser => Tables.FirstOrDefault()?.Layout.Chooser(Link(), SI.Management.Web.Auth.UserExtensions.IsAdmin(User));
}
