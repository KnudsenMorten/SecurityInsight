using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.DependencyInjection;
using SI.Management.Core.ProData;
using SI.Management.Web.Columns;
using SI.Management.Web.Export;

namespace SI.Management.Web.Pages.Collection;

/// What a view's grid is: the spec, the values its source needs, the cache scope, the column options (multi-select
/// values), and the sort a view opens with when the URL names none.
public sealed record GridPlan(GridSpec Spec, IReadOnlyDictionary<string, object?> Parameters, string Scope,
    IReadOnlyDictionary<string, IReadOnlyList<string>>? Options = null, string? DefaultSort = null, bool? DefaultDesc = null,
    IReadOnlyDictionary<string, string>? DefaultFilters = null);

/// One group of the counts raw rows opens with (<see cref="CollectionPageModel.OpeningCounts"/>): "Domain" and its values.
public sealed record OpeningCount(string Label, IReadOnlyList<OpeningValue> Values);
/// One value of an opening count: its words, how many findings it holds, the grid narrowed to it.
public sealed record OpeningValue(string Value, string Label, long Findings, string Href);

/// <summary>
/// The base of the fourteen collection views (REQUIREMENTS #241): ONE collection at a time (the collection picker; the
/// newest complete one by default), ONE grid component (server-side paging, sort on any column, per-column filters,
/// multi-select, free-text search, export to Excel / CSV through the app's export), and the grid's whole state in the
/// URL -- so a link shares the view exactly. Reads go through <see cref="ICollectionViews"/> (cached per collection);
/// nothing here calls Log Analytics.
/// </summary>
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Views)]
public abstract class CollectionPageModel : PageModel
{
    protected readonly ICollectionViews Views;
    protected readonly ILogger Log;

    protected CollectionPageModel(ICollectionViews views, ILogger log) { Views = views; Log = log; }

    /// The page's own path, e.g. "/Collection/Rows".
    public abstract string PagePath { get; }
    public abstract string Heading { get; }
    public abstract string Lede { get; }
    /// The export file's page name.
    public virtual string ExportName => PagePath.Split('/').Last().ToLowerInvariant();

    [BindProperty(SupportsGet = true)] public string? C { get; set; }

    public IReadOnlyList<ViewCollection> Collections { get; private set; } = Array.Empty<ViewCollection>();
    public ViewCollection? Current { get; private set; }
    public IReadOnlyList<FacetRow> FacetRows { get; protected set; } = Array.Empty<FacetRow>();
    public GridPlan? Plan { get; private set; }
    public GridPage? Grid { get; private set; }
    public List<QueryInfo> Queries { get; } = new();
    public string? Error { get; protected set; }
    public string? Notice { get; protected set; }
    /// The collection before the current one (the comparison base of "what changed" and "lifecycle").
    public ViewCollection? Previous => Current is null ? null : Collections.Where(c => c.CollectionTime < Current.CollectionTime).OrderByDescending(c => c.CollectionTime).FirstOrDefault();

    /// The window "what happened with this collection": from its time to the next collection's (or now).
    public (DateTime From, DateTime To) Window => Current is null ? default
        : (DateTime.SpecifyKind(Current.CollectionTime, DateTimeKind.Utc), DateTime.SpecifyKind(Current.NextTime ?? DateTime.UtcNow.AddMinutes(1), DateTimeKind.Utc));

    /// Loads what the page shows above its grid and says which grid it has (null = none, e.g. a missing CI key).
    protected abstract Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct);

    // ---- the URL state --------------------------------------------------------------------------------------------

    /// The grid request as the URL carries it: sort, dir, p, size, q, f.&lt;column&gt; (several values = several
    /// parameters, or one joined with '|'), sel (the selected rows).
    public GridRequest ReadGrid(GridPlan plan)
    {
        var q = Request.Query;
        var filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in q)
        {
            if (!kv.Key.StartsWith("f.", StringComparison.OrdinalIgnoreCase)) continue;
            var joined = string.Join("|", kv.Value.Where(v => !string.IsNullOrWhiteSpace(v)));
            if (joined.Length > 0) filters[kv.Key[2..]] = joined;
        }
        if (plan.DefaultFilters is not null && !q.ContainsKey("f"))
            foreach (var (k, v) in plan.DefaultFilters) if (!q.Keys.Any(x => x.Equals("f." + k, StringComparison.OrdinalIgnoreCase))) filters[k] = v;
        var dir = (string?)q["dir"];
        var sort = (string?)q["sort"];
        return new GridRequest
        {
            Sort = sort ?? plan.DefaultSort,
            Desc = dir is "desc" ? true : dir is "asc" ? false : sort is null ? plan.DefaultDesc : null,
            Page = int.TryParse(q["p"], NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : 1,
            Size = GridSql.PageSize((string?)q["size"]),
            Search = q["q"],
            Filters = filters,
            Selected = q["sel"].Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v!).ToList(),
        };
    }

    /// This page's URL with the current query, some parameters overridden (null removes one). A change of anything but
    /// the page number starts at page 1. Values of a multi-valued parameter (sel, f.*) are kept.
    public string Link(params (string Key, string? Value)[] overrides)
    {
        var parts = new List<(string, string)>();
        var over = overrides.Select(o => o.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in Request.Query)
        {
            if (kv.Key.Equals("handler", StringComparison.OrdinalIgnoreCase) || over.Contains(kv.Key)) continue;
            if (kv.Key.Equals("p", StringComparison.OrdinalIgnoreCase) && overrides.Length > 0) continue;
            foreach (var v in kv.Value) if (!string.IsNullOrEmpty(v)) parts.Add((kv.Key, v));
        }
        foreach (var (k, v) in overrides) if (!string.IsNullOrEmpty(v)) parts.Add((k, v));
        if (!Request.Query.ContainsKey("c") && !over.Contains("c") && C is not null) parts.Insert(0, ("c", C));
        var qs = string.Join("&", parts.Select(x => Uri.EscapeDataString(x.Item1) + "=" + Uri.EscapeDataString(x.Item2)));
        return PagePath + (qs.Length > 0 ? "?" + qs : "");
    }

    public string HandlerLink(string handler) { var l = Link(); return l + (l.Contains('?') ? "&" : "?") + "handler=" + handler; }

    /// A link to another view of THIS collection.
    public string ViewLink(string path, params (string Key, string? Value)[] extra)
    {
        var parts = new List<string>();
        if (Current is not null) parts.Add("c=" + Uri.EscapeDataString(Current.CollectionId));
        foreach (var (k, v) in extra) if (!string.IsNullOrEmpty(v)) parts.Add(Uri.EscapeDataString(k) + "=" + Uri.EscapeDataString(v));
        // #264: a drill-down into another view shows the same population (the view's tick travels)
        return SI.Management.Web.Exemptions.ExemptedTick.Carry(HttpContext, path + (parts.Count > 0 ? "?" + string.Join("&", parts) : ""));
    }

    /// Page-specific state the grid's forms must carry (e.g. the CI key, the second collection).
    public virtual IEnumerable<(string Key, string Value)> ExtraState() => Array.Empty<(string, string)>();

    /// #636: the named views at the top of the page (null = the page has none) -- Security recommendations > Summary / Detailed.
    public virtual SI.Management.Web.Navigation.ViewPicker? Picker => null;

    /// #636 the tight frame: the page's explanation sits behind "About this page", so the table starts in the top third.
    public virtual bool CompactFrame => false;

    // ---- #589 every column on every view: the layout, the extra columns, the exports ------------------------------------

    /// The view's columns (its own + the extra columns its rows can carry), the person's layout -- null until the grid is planned.
    public DataViewLayout? ViewLayout { get; private set; }
    /// The columns the grid shows (and the exports of the chosen columns write), in the chosen order.
    public IReadOnlyList<GridColumn> DisplayColumns { get; private set; } = Array.Empty<GridColumn>();

    /// The key the view's layouts are stored under (cfg.ColumnLayout): "/Collection/Rows" -> "collection-rows".
    public virtual string ViewKey => PagePath.Trim('/').Replace('/', '-').ToLowerInvariant();

    /// The key one grid of the view is stored under: the view key and the grid (a view with two grids -- What changed for
    /// findings or CIs, Services and one service -- keeps one layout per grid). A department restriction is the same grid.
    protected virtual string LayoutKey(GridSpec s) => ViewKey + "." + s.Name.Split('@')[0];

    /// How the grid's rows reach their CI: the asset key column, else a CI id column, else not at all.
    protected virtual RowCiKey RowCi(GridSpec s) =>
        s.Column("AssetKey") is not null ? RowCiKey.AssetKey : s.Column("CiId") is not null ? RowCiKey.CiId : RowCiKey.None;

    /// How the grid's rows reach their finding(s), and the column that holds the key.
    protected virtual (RowFindingKey Kind, string? Column) RowFindings(GridSpec s) =>
        s.KeyColumn == "FindingId" ? (RowFindingKey.FindingId, "FindingId")
        : s.KeyColumn == "Cve" ? (RowFindingKey.Cve, "Cve")
        : s.Column("Issue") is not null ? (RowFindingKey.Issue, "Issue")
        : s.Column("IssueKey") is not null ? (RowFindingKey.Issue, "IssueKey")
        : s.Column("Cve") is not null ? (RowFindingKey.Cve, "Cve")
        : (RowFindingKey.None, null);

    /// Extra columns a view reads for its rows even when they are not shown (e.g. the software a CVE row's title is made of).
    protected virtual IReadOnlyList<string> AlwaysFilled => Array.Empty<string>();

    /// #589 (tier board redesign): the URL of the HTML fragment a click on the row opens in a side drawer (null = none).
    public virtual string? RowDrawer(IReadOnlyDictionary<string, object?> row) => null;

    /// The grid's column chooser: every own column, then every extra column the rows can carry, per group.
    public virtual SI.Management.Web.Cis.ColumnChooser? Chooser =>
        ViewLayout is null || Grid is null ? null : ViewLayout.Chooser(Link(), SI.Management.Web.Auth.UserExtensions.IsAdmin(User));

    /// Whether the grid offers "Export all columns" (every own column + every extra column on offer).
    public virtual bool ExportsAllColumns => ViewLayout is not null;

    /// The export buttons (words in <see cref="ExportLabels"/>).
    public ViewExports Exports => ViewExports.Of(HandlerLink, ExportsAllColumns);

    /// <summary>
    /// The "What you're looking at" line of this view (owner 2026-10-19; Pages/Shared/_ViewScope.cshtml), from what the page
    /// read: the run, what it does with the CIs' lifecycle (a run's view shows what the run reported, whatever the CI's
    /// lifecycle -- said so, with the lifecycle's numbers from the settings), the exempted findings, a department scope, a
    /// default filter in force, the person's filters and search as chips, and "Show everything".
    /// </summary>
    public async Task<ViewScope> ScopeAsync(CancellationToken ct)
    {
        var rules = HttpContext?.RequestServices.GetService<SI.Management.Core.ProData.ICiLifecycleRulesReader>() is { } ls ? await ls.ReadAsync(ct) : null;
        var st = Grid?.State;
        var defaults = new List<string>();
        var exempted = SI.Management.Web.Exemptions.ExemptedView.Of(HttpContext);
        if (exempted is { Ready: true }) defaults.Add(exempted.Include ? "exempted findings shown, marked" : "exempted findings hidden");
        if (Visibility is not null) defaults.Add("only your departments' rows");
        var defaultFilters = Plan?.DefaultFilters is { Count: > 0 } df && !Request.Query.ContainsKey("f")
            ? df.Where(kv => !Request.Query.Keys.Any(k => k.Equals("f." + kv.Key, StringComparison.OrdinalIgnoreCase))).ToList()
            : new List<KeyValuePair<string, string>>();
        if (defaultFilters.Count > 0) defaults.Add("this view's default filter is on (" + string.Join(", ", defaultFilters.Select(d => Plan!.Spec.Column(d.Key)?.Label ?? d.Key)) + ")");
        var chips = new List<ScopeChip>();
        if (st is not null)
        {
            if (st.Search is not null) chips.Add(new("Search: " + st.Search, Link(("q", null))));
            foreach (var f in st.Filters)
                if (Plan!.Spec.Column(f.Key) is { } c) chips.Add(new(c.Label + ": " + ChipText(c, f), Link(("f." + c.Key, null))));
            if (st.Selected.Count > 0) chips.Add(new("Only the " + Fmt.Int(st.Selected.Count) + " selected row(s)", Link(("sel", null))));
        }
        // #855: a lifecycle grid narrowed to some lifecycle states (the default: active) is narrowed too
        var narrowed = chips.Count > 0 || defaultFilters.Count > 0 || exempted is { Ready: true, Include: false } || (LifecycleOffered && !this.Lifecycle.IsAll);
        // "Show everything": this collection, the page's own state (one CI ...), no default filter (f=all) and the exempted
        // findings shown -- every filter and the search gone
        var parts = new List<string>();
        if (Current is not null) parts.Add("c=" + Uri.EscapeDataString(Current.CollectionId));
        parts.AddRange(ExtraState().Select(e => Uri.EscapeDataString(e.Key) + "=" + Uri.EscapeDataString(e.Value)));
        parts.Add("f=all");
        if (LifecycleOffered) parts.Add(SI.Management.Core.ProData.LifecycleFilter.Parameter + "=" + SI.Management.Core.ProData.CiLifecycleDefinitions.ClearedFilter);
        var everything = SI.Management.Web.Exemptions.ExemptedTick.Carry(PagePath + "?" + string.Join("&", parts), exempted is { Ready: true } ? "1" : null);
        var defs = new List<(string, string)>();
        if (rules is not null) defs.AddRange(rules.Definitions);
        if (exempted is { Ready: true }) defs.Add(("Exempted findings", "a finding an approved exemption covers; it is " + (exempted.Include ? "shown, marked" : "left out") + " here (the box in the header switches it)."));
        return new ViewScope
        {
            RunTime = Current?.CollectionTime, RunKind = Current?.Kind,
            Lifecycle = Plan is null && !LifecycleOffered ? null : LifecycleWords(rules), LifecycleDefaulted = LifecycleOffered && this.Lifecycle.IsDefault,
            Defaults = defaults, Chips = chips, ShowEverythingHref = narrowed ? everything : null, Definitions = defs,
        };
    }

    /// <summary>
    /// #855 what this view does with the CIs' lifecycle (owner 2026-10-21: "default filter is active, so it should be active
    /// only"): a grid over the finding rows or the per-CI rows counts the lifecycle chosen (active by default, the choice above
    /// the grid); a grid whose stored rows are of active CIs only (the per-CVE rows, the Summary groupings) says so; any other
    /// view (services, changes, events, connectors ...) shows what the run reported, whatever the CI's lifecycle.
    /// </summary>
    protected virtual string LifecycleWords(SI.Management.Core.ProData.CiLifecycleRules? rules)
    {
        var r = rules ?? SI.Management.Core.ProData.CiLifecycleDefinitions.Defaults;
        if (LifecycleOffered) return Lifecycle.Words(r, Plan?.Spec.Name is "assets" or "assetrisk" ? "rows" : "findings");
        if (CollectionViewSql.BuiltOverActive(Plan?.Spec.Name)) return SI.Management.Core.ProData.LifecycleFilter.ActiveOnlyWords(r);
        return "every CI the run reported, whatever its lifecycle (active, not seen or retired" + (rules is null ? "" : "; not seen = no source saw it within " + SI.Management.Core.ProData.CiLifecycleRules.Days(rules.SeenWithinDays)) + ")";
    }

    // ---- #855 the lifecycle choice of the grid ------------------------------------------------------------------------

    private SI.Management.Core.ProData.LifecycleFilter? _lifecycle;
    /// The CI lifecycle this request counts (lifecycle=...; none = the default, active).
    public SI.Management.Core.ProData.LifecycleFilter Lifecycle => _lifecycle ??= LifecycleChoice.Read(HttpContext?.Request);
    /// False for a view of ONE CI: its findings are shown whatever the CI's lifecycle (the CI page says which it is).
    protected virtual bool CountsLifecycle => true;
    /// True when this view's grid counts the lifecycle chosen (the choice is shown).
    public bool LifecycleOffered { get; protected set; }
    /// The Active | Not seen | Retired | All choice above the grid (null = this view offers none).
    public LifecycleChoice? LifecycleChoiceModel => LifecycleOffered && HttpContext is not null ? LifecycleChoice.For(Request, Lifecycle) : null;

    /// The plan narrowed to the lifecycle chosen, where its grid is a lifecycle grid (the cache scope carries the choice).
    private GridPlan? Lifecycled(GridPlan? plan)
    {
        if (plan is null) return null;
        if (!CountsLifecycle || CollectionViewSql.WithLifecycle(plan.Spec, Lifecycle) is not { } spec) { LifecycleOffered = false; return plan; }
        LifecycleOffered = true;
        return plan with { Spec = spec, Scope = plan.Scope + "|lc=" + Lifecycle.Key };
    }

    /// What one row of this view's grid is, for the pager and the heading ("Showing 1–50 of 1.117.524 findings").
    public virtual string RowNoun => GridNouns.Of(Plan?.Spec.Name);

    /// <summary>
    /// Owner 2026-10-19 (agreed): raw rows opened WITHOUT a filter, search or selection show how many findings each domain,
    /// severity and tier holds -- each a link that narrows the grid -- and "N findings -- pick a domain, severity or asset to
    /// narrow" above it; the grid is still there, paged, and "export all" is still one click. The counts are the
    /// collection's pre-computed ones (no extra read), exact because nothing else narrows. Null = not shown.
    /// </summary>
    public IReadOnlyList<OpeningCount>? OpeningCounts
    {
        get
        {
            if (PagePath != "/Collection/Rows" || Grid is not { } g || FacetRows.Count == 0) return null;
            var st = g.State;
            if (st.Filters.Count > 0 || st.Search is not null || st.Selected.Count > 0 || ExtraState().Any()) return null;
            // #855: the stored counts are of active CIs -- exact only while the grid counts the default (active)
            if (LifecycleOffered && !this.Lifecycle.IsActiveOnly) return null;
            var spec = Plan!.Spec;
            var groups = new List<OpeningCount>();
            foreach (var (facet, column, label) in new[] { (Facets.Domain, "SecurityDomain", "Domain"), (Facets.Severity, "Severity", "Severity"), (Facets.Tier, "Tier", "Tier") })
            {
                if (spec.Column(column) is not { } col) continue;
                var rows = Facet(facet).Where(r => r.Value != "(none)" && r.Value.Length > 0);
                rows = column == "Severity" ? rows.OrderBy(r => SeverityOrder.Rank(r.Value)) : column == "Tier" ? rows.OrderBy(r => r.Value, StringComparer.Ordinal) : rows.OrderByDescending(r => r.Findings);
                var values = rows.Select(r => new OpeningValue(r.Value, ValueLabel(col, r.Value), r.Findings, Link(("f." + column, r.Value)))).ToList();
                if (values.Count > 0) groups.Add(new OpeningCount(label, values));
            }
            return groups.Count == 0 ? null : groups;
        }
    }

    private async Task ApplyLayoutAsync(CancellationToken ct)
    {
        if (Plan is null) return;
        var spec = Plan.Spec;
        var ci = RowCi(spec);
        var (fk, _) = RowFindings(spec);
        var probe = new DataViewLayout { View = LayoutKey(spec), Own = GridLayout.Own(spec), Ci = ci, Findings = fk };
        var layout = new DataViewLayout { View = probe.View, Own = probe.Own, Ci = ci, Findings = fk, Shipped = DataViewDefaults.ForGrid(spec, ci, fk, probe.Known) };
        ViewLayout = await layout.LoadAsync(HttpContext, Log, ct);
        Plan = Plan with { Spec = GridLayout.Apply(spec, layout.Layout) };
        DisplayColumns = GridLayout.Display(Plan.Spec, layout);
    }

    /// A row's keys (its CI key, finding id, CVE / issue).
    public RowRef RefOf(IReadOnlyDictionary<string, object?> row)
    {
        var spec = Plan?.Spec;
        if (spec is null || ViewLayout is null) return default;
        var ciCol = ViewLayout.Ci == RowCiKey.AssetKey ? "AssetKey" : ViewLayout.Ci == RowCiKey.CiId ? "CiId" : null;
        var (fk, col) = RowFindings(spec);
        return GridLayout.RefOf(row, ciCol, fk == RowFindingKey.FindingId ? col : null, fk is RowFindingKey.Cve or RowFindingKey.Issue ? col : null);
    }

    /// The rows with the extra columns of <paramref name="columns"/> (and <see cref="AlwaysFilled"/>) filled in.
    protected async Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> FillAsync(IReadOnlyList<GridColumn> columns, IReadOnlyList<IReadOnlyDictionary<string, object?>> rows, CancellationToken ct)
    {
        if (ViewLayout is null) return rows;
        var all = columns.Concat(AlwaysFilled.Where(k => ViewLayout.Known(k) is not null && !columns.Any(c => c.Key == k)).Select(k => GridLayout.Extra(k, ViewLayout.Label(k)))).ToList();
        return await GridLayout.FillAsync(HttpContext, Log, ViewLayout, all, rows, RefOf, Current?.CollectionId, ct);
    }

    /// Where a cell links to (null = plain text).
    public virtual string? CellLink(string column, IReadOnlyDictionary<string, object?> row) => null;

    /// A cell as this view shows it (on screen; with <paramref name="csv"/> in the CSV export). Default: <see cref="Text"/>.
    public virtual string CellText(GridColumn c, IReadOnlyDictionary<string, object?> row, bool csv = false) =>
        GridLayout.IsExtra(c) ? GridLayout.Text(row, c.Key) : Text(c, row, csv);

    /// A cell as this view's Excel export holds it. Default: <see cref="ExcelValue"/>.
    public virtual object? CellExcel(GridColumn c, IReadOnlyDictionary<string, object?> row) =>
        GridLayout.IsExtra(c) ? GridLayout.Excel(row, c.Key) : ExcelValue(c, row);

    /// The hover text of a cell (null = none).
    public virtual string? CellTitle(GridColumn c, IReadOnlyDictionary<string, object?> row) => null;

    /// The words of a filter value in this view (the multi-select, its counts, the chip). Default: <see cref="OptionLabel"/>.
    public virtual string ValueLabel(GridColumn c, string v) => OptionLabel(c, v);

    /// The text of an active filter's chip (after "Label: ").
    public virtual string ChipText(GridColumn c, GridFilterValue f) =>
        f.Kind is GridFilter.Values or GridFilter.Tokens ? string.Join(" or ", f.Values.Select(v => ValueLabel(c, v)))
        : f.Kind is GridFilter.Range ? Fmt.RangeWords(f.Low, f.High)   // #321: in words, never "..1"
        : f.Kind is GridFilter.Dates ? DateWords(f)
        : FilterText(f);

    /// A date filter in words: "the last 30 days", "from 2026-10-01 to 2026-10-19", "from 2026-10-01", "until 2026-10-19".
    public static string DateWords(GridFilterValue f)
    {
        var t = f.Text ?? "";
        if (System.Text.RegularExpressions.Regex.Match(t, "^([0-9]{1,4})d$") is { Success: true } m) return "the last " + m.Groups[1].Value + " days";
        static string Day(DateTime d) => d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        return (f.From, f.Before) switch
        {
            ({ } a, { } b) when b.AddDays(-1) == a => "on " + Day(a),
            ({ } a, { } b) => "from " + Day(a) + " to " + Day(b.AddDays(-1)),
            ({ } a, null) => "from " + Day(a),
            (null, { } b) => "until " + Day(b.AddDays(-1)),
            _ => t,
        };
    }

    /// An active filter as the Excel export's "Export" sheet states it. Default: <see cref="FilterText"/>.
    public virtual string ExportFilterText(GridColumn c, GridFilterValue f) => FilterText(f);

    /// A cell shown as a coloured chip: its badge class (good / fair / warn / bad / info), or null = plain text.
    public virtual string? CellTone(string column, IReadOnlyDictionary<string, object?> row) => null;

    /// #360: where a row's inline expansion is read from (an HTML fragment), or null = the row does not expand.
    public virtual string? RowExpand(IReadOnlyDictionary<string, object?> row) => null;

    protected string? Cell(IReadOnlyDictionary<string, object?> row, string column) =>
        row.TryGetValue(column, out var v) && v is not null ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;

    /// The values of a facet of this collection (for a multi-select filter), most frequent first.
    public IReadOnlyList<string> Options(string facet) =>
        FacetRows.Where(f => f.Facet == facet && f.Value != "(none)").OrderByDescending(f => f.Findings).Select(f => f.Value).ToList();

    public IReadOnlyList<FacetRow> Facet(string facet) => FacetRows.Where(f => f.Facet == facet).ToList();

    // ---- loading -------------------------------------------------------------------------------------------------

    protected async Task<bool> LoadCollectionAsync(CancellationToken ct)
    {
        var cols = await Views.CollectionsAsync(ct);
        Collections = cols.Data;
        if (Collections.Count == 0)
        {
            Notice = "No complete collection has been loaded into the Pro database yet. The data sync copies each complete Risk Analysis run into SQL; the views fill after the first one.";
            Queries.Add(QueryInfo.From(cols, "The loaded collections"));
            return false;
        }
        if (C is null) Current = Collections[0];
        else
        {
            ProDataFilters.Id(C, "collection");
            Current = Collections.FirstOrDefault(c => c.CollectionId == C);
            if (Current is null) { Error = "That collection is not in the Pro database (it may have passed retention). Pick another one."; return false; }
        }
        return true;
    }

    /// The collection's pre-computed aggregates (one read, cached long). Says when they are not computed yet.
    protected async Task LoadFacetsAsync(CancellationToken ct)
    {
        if (Current is null) return;
        if (Visibility is not null)
        {
            // the precomputed counts span every department: never shown to an account limited to departments
            Notice ??= "The counts per value cover every department, so they are not shown to an account limited to departments. The rows below are your departments' only.";
            return;
        }
        var f = await Views.FacetsAsync(Current, ct);
        FacetRows = f.Data;
        Queries.Add(QueryInfo.From(f, "Counts per value (breakdowns)"));
        if (Current.DerivedAt is null)
            Notice ??= "This collection's view data (risk rating, weighted score, CVSS, MITRE tactics, compliance tags and the counts per value) is computed by the data sync after each load, and has not been computed for this collection yet. The rows are shown; those columns and counts fill in after the next data sync.";
    }

    public static readonly IReadOnlyList<string> Kinds = ProDataFilters.AssetKinds;
    public static readonly IReadOnlyList<string> TierValues = ProDataFilters.Tiers;
    public static readonly IReadOnlyList<string> Flags = ["1", "0"];

    public virtual async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            if (!await LoadCollectionAsync(ct)) return;
            if (!await LoadVisibilityAsync(ct)) return;
            Plan = Scoped(Lifecycled(await WithFindingFiltersAsync(await PrepareAsync(false, ct), ct)));
            if (Plan is null) return;
            await ApplyLayoutAsync(ct);
            GridRequest req;
            try { req = ReadGrid(Plan); GridSql.Normalize(Plan.Spec, req); }
            catch (ArgumentException ex) { Error = "The filter is not valid: " + ex.Message; return; }
            var g = await Views.GridAsync(new GridQuery(Plan.Spec, Plan.Parameters, Plan.Scope, req), ct);
            // #589: the extra columns of the shown rows, read for the page's rows only
            Grid = g.Data with { Rows = await FillAsync(DisplayColumns, g.Data.Rows, ct) };
            Queries.Insert(0, QueryInfo.From(g, Heading + ": the rows"));
            await BulkAsync(req, ct);
        }
        catch (ArgumentException ex) { Error = "The request is not valid: " + ex.Message; }
        catch (ViewTimeoutException ex)
        {
            // #284: shown in the page (never the generic error page), with the reference that finds this line in the log
            ErrorRef = Reference();
            TimedOut = true;
            Log.LogWarning(ex, "collection view {Page} grid {Grid} timed out after {Seconds}s (reference {Reference})", PagePath, Plan?.Spec.Name, ex.Limit.TotalSeconds, ErrorRef);
            Error = TimeoutText(ex.Limit, ErrorRef);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ErrorRef = Reference();
            Log.LogError(ex, "reading the collection view {Page} grid {Grid} failed: {Type} {SqlNumber} (reference {Reference})", PagePath, Plan?.Spec.Name, ex.GetType().Name, SqlNumber(ex), ErrorRef);
            Error = "This view could not be read from the Pro database: " + ex.Message + SchemaHint(ex.Message) + " Reference: " + ErrorRef + ".";
        }
    }

    /// #284: the view ran out of time (the page says so and offers what to do).
    public bool TimedOut { get; private set; }
    /// #284: the id of this request in the application log (shown with an error).
    public string? ErrorRef { get; private set; }

    private string Reference() => HttpContext is { } ctx ? SI.Management.Web.Pages.ErrorModel.ReferenceOf(ctx) : Guid.NewGuid().ToString("N");

    /// What a timed-out view tells the reader: what happened, why, what to do, and the reference.
    public static string TimeoutText(TimeSpan limit, string? reference) =>
        $"This view took too long and was stopped: the Pro database did not answer within {limit.TotalSeconds:0} seconds. " +
        "Narrow the view (a column filter, a search, or fewer rows per page) and apply it again, or pick another collection. " +
        "If even a narrow view times out, give your administrator this reference" + (reference is null ? "." : ": " + reference + ".");

    /// The SQL error number of a database error (null for anything else).
    public static int? SqlNumber(Exception ex)
    {
        for (var e = ex; e is not null; e = e.InnerException) if (e is Microsoft.Data.SqlClient.SqlException s) return s.Number;
        return null;
    }

    // ---- the department scope (#253 x #254): a department-scoped user sees only their departments' rows ---------------

    /// The views whose every read is the grid over one collection's findings (aggregates are hidden for a scoped user):
    /// the only collection views a department-scoped user may open. Every other view is refused, never shown unfiltered.
    public static readonly IReadOnlySet<string> DepartmentScopedViews = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "/Collection/Rows", "/Collection/Assets", "/Collection/RiskScore", "/Collection/WeightedRisk", "/Collection/RiskRating",
        "/Collection/Mitre", "/Collection/Compliance", "/Collection/Cvss",
    };

    /// Whether this view may be opened by a department-scoped user (it then shows only their departments' rows).
    protected virtual bool DepartmentScopeSafe => DepartmentScopedViews.Contains(PagePath);

    /// The department predicate of the signed-in user; null = sees everything.
    public RowVisibility? Visibility { get; private set; }

    protected async Task<bool> LoadVisibilityAsync(CancellationToken ct)
    {
        var resolver = HttpContext?.RequestServices.GetService<SI.Management.Web.Departments.IDepartmentScopeResolver>();
        Visibility = resolver is null ? null : (await resolver.ResolveAsync(User, ct)).Rows;
        if (Visibility is null || DepartmentScopeSafe) return true;
        Error = "This view is not available to an account limited to departments: it shows data across every department.";
        return false;
    }

    // ---- #264: exempted findings in the grid, and the bulk guard ------------------------------------------------------

    /// Whether this view includes exempted findings (shown, each marked) -- false where the database has no mark.
    public bool ShowsExempted => SI.Management.Web.Exemptions.ExemptedView.Of(HttpContext) is { Ready: true, Include: true };
    /// Whether "request exemption for all N matching" is offered, and why not.
    public SI.Management.Web.Exemptions.ExemptionBulkGuard.Verdict Bulk { get; private set; } = new(false, null);
    public int BulkMax { get; private set; } = 500;

    /// The grid's filter narrows the collection: a column filter, a search, or the page's own narrowing (one CI). The same
    /// rule the request page applies again on the server.
    public bool Narrowed(GridRequest req) =>
        req.Filters.Count > 0 || !string.IsNullOrWhiteSpace(req.Search) || ExtraState().Any(e => e.Key == "key" && !string.IsNullOrWhiteSpace(e.Value));

    private async Task BulkAsync(GridRequest req, CancellationToken ct)
    {
        var settings = HttpContext?.RequestServices.GetService<SI.Management.Web.Exemptions.ExemptionSettings>();
        if (settings is not null) { try { BulkMax = (await settings.ReadAsync(ct)).BulkMax; } catch (Exception ex) when (ex is not OperationCanceledException) { Log.LogWarning(ex, "exemption settings"); } }
        _narrowed = Narrowed(req) || ActionSource == SI.Management.Web.Actions.SelectionSources.Department;
        Bulk = SI.Management.Web.Exemptions.ExemptionBulkGuard.Check(_narrowed, Grid?.Total ?? 0, BulkMax);
    }

    private bool _narrowed;

    // ---- #272: the shared action bar on a grid that lists findings ---------------------------------------------------

    /// Where this grid's selected findings come from (<see cref="SI.Management.Web.Actions.SelectionSources"/>); null = the
    /// grid does not list findings of one collection (CIs, CVEs, changes, events...), so it gets no action bar.
    /// #286: every grid whose rows stand for findings (its <see cref="SI.Management.Web.Actions.FindingRowMap"/>) carries the
    /// SAME bar -- an aggregated row (a CVE, a CI, a service...) acts on the findings it stands for.
    public virtual string? ActionSource => SI.Management.Web.Actions.FindingRowMaps.Of(Plan?.Spec.Name) is { Acts: true } ? SI.Management.Web.Actions.SelectionSources.Rows : null;
    /// The department of a department page (its people are offered as task assignees).
    protected virtual int? ActionDepartment => null;
    /// Fields the grid's selection form does not carry but the action endpoint needs (e.g. the Unassigned marker).
    protected virtual IEnumerable<(string Key, string Value)> ActionHidden() => Array.Empty<(string, string)>();

    /// The bar under this grid (null = none).
    public SI.Management.Web.Actions.FindingActionBar? ActionBar(string stripId)
    {
        if (ActionSource is null || Grid is null) return null;
        var hidden = ActionHidden().ToList();
        if (SI.Management.Web.Exemptions.ExemptedView.Of(HttpContext)?.Carry is { } carry) hidden.Add((Exempted.QueryKey, carry));
        var map = ActionSource == SI.Management.Web.Actions.SelectionSources.Rows ? SI.Management.Web.Actions.FindingRowMaps.Of(Plan?.Spec.Name) : null;
        return new SI.Management.Web.Actions.FindingActionBar
        {
            Source = ActionSource, CollectionId = Current?.CollectionId, StripId = stripId, Total = Grid.Total, Narrowed = _narrowed, BulkMax = BulkMax,
            InGetForm = true, ShowOnlySelected = true, DepartmentId = ActionDepartment, Hidden = hidden,
            Grid = Plan?.Spec.Name, Map = map is { Aggregated: true } ? map : null,
        };
    }

    /// <summary>
    /// A grid over finding rows with the finding's category, subcategory and component as hidden filter columns (owner
    /// 2026-10-19, <see cref="FindingFilterColumns"/>) -- once the database has the prepared finding context columns.
    /// </summary>
    private async Task<GridPlan?> WithFindingFiltersAsync(GridPlan? plan, CancellationToken ct)
    {
        if (plan is null || plan.Spec.KeyColumn != "FindingId" || HttpContext?.RequestServices.GetService<IDataColumnViews>() is not { } columns) return plan;
        try { return (await columns.SchemaAsync(ct)).FindingContext ? plan with { Spec = FindingFilterColumns.With(plan.Spec) } : plan; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.LogWarning(ex, "the data schema could not be read; the finding filters stay as they are");
            return plan;
        }
    }

    /// The plan limited to the visible departments (and the estate-wide aggregates hidden), or as it was. A grid of
    /// finding rows in a view that shows exempted findings carries the mark as a column (#264).
    private GridPlan? Scoped(GridPlan? plan)
    {
        if (plan is not null && ShowsExempted && plan.Spec.KeyColumn == "FindingId") plan = plan with { Spec = Exempted.WithMark(plan.Spec) };
        if (plan is null || Visibility is null) return plan;
        if (!DepartmentScope.CanRestrict(plan.Spec)) { Error = "This view cannot be limited to your departments, so it is not shown."; return null; }
        FacetRows = Array.Empty<FacetRow>();
        var p = new Dictionary<string, object?>(plan.Parameters);
        foreach (var kv in Visibility.Parameters) p[kv.Key] = kv.Value;
        return plan with { Spec = DepartmentScope.Restrict(plan.Spec, Visibility), Parameters = p, Scope = plan.Scope + "|" + Visibility.Key };
    }

    /// What to do about a missing table or column: which setup step adds it.
    public static string SchemaHint(string message)
    {
        var missing = message.Contains("Invalid column name", StringComparison.OrdinalIgnoreCase) || message.Contains("Invalid object name", StringComparison.OrdinalIgnoreCase);
        if (!missing) return "";
        if (message.Contains("vuln.", StringComparison.OrdinalIgnoreCase)) return " -- the vulnerability close-loop's tables are not in this database (setup\\Initialize-SIVulnTargetSql.ps1 adds them).";
        if (message.Contains("cfg.", StringComparison.OrdinalIgnoreCase)) return " -- the Pro settings tables are not in this database yet.";
        return " -- the database does not have the collection views' columns yet: run setup\\Initialize-SIDataSql.ps1 again (it only adds).";
    }

    protected async Task<(GridPlan Plan, GridPage Page)?> ExportRowsAsync(CancellationToken ct)
    {
        if (!await LoadCollectionAsync(ct)) return null;
        if (!await LoadVisibilityAsync(ct)) return null;
        Plan = Scoped(Lifecycled(await WithFindingFiltersAsync(await PrepareAsync(true, ct), ct)));
        if (Plan is null) return null;
        await ApplyLayoutAsync(ct);
        var plan = Plan;
        var query = new GridQuery(plan.Spec, plan.Parameters, plan.Scope, ReadGrid(plan));
        // "Export this page": the page shown (its filters, sort, page and size); else every row matching the filters (and
        // the selection), never only the page shown
        var g = ExportChoices.PageOnly(Request) ? await Views.GridAsync(query, ct) : await Views.ExportAsync(query, ct);
        return (plan, g.Data);
    }

    /// <summary>
    /// #287: how many rows each choice of ONE column filter has, under the view's OTHER filters, its search and its
    /// selection -- so a count is exactly what ticking that choice gives. The filter dropdown asks for it when it is
    /// opened (js/app/value-counts.js); the counts are in the viewer's number format, a choice with none is dimmed.
    /// Reads only, under the same department visibility as the grid.
    /// </summary>
    public async Task<IActionResult> OnGetValueCountsAsync(string? col, CancellationToken ct)
    {
        try
        {
            if (!await LoadCollectionAsync(ct) || !await LoadVisibilityAsync(ct)) return new JsonResult(new { ok = false, message = Error ?? Notice ?? "no collection" });
            var plan = Scoped(Lifecycled(await WithFindingFiltersAsync(await PrepareAsync(true, ct), ct)));
            if (plan is null || plan.Spec.Column(col) is not { Filter: GridFilter.Values or GridFilter.Tokens } c)
                return new JsonResult(new { ok = false, message = "This column has no value filter." });
            var counts = (await Views.ValueCountsAsync(new GridQuery(plan.Spec, plan.Parameters, plan.Scope, ReadGrid(plan)), c.Key, ct)).Data;
            return new JsonResult(new
            {
                ok = true, column = c.Key,
                values = counts.Select(x => new { value = x.Key, label = ValueLabel(c, x.Key), n = x.N, text = Fmt.Int(x.N) }),
            });
        }
        catch (ArgumentException ex) { return new JsonResult(new { ok = false, message = ex.Message }); }
        catch (ViewTimeoutException) { return new JsonResult(new { ok = false, message = "Counting took too long -- the choices are shown without counts." }); }
    }

    /// The visible columns, in order (what the grid shows and what an export writes).
    public static IReadOnlyList<GridColumn> Visible(GridSpec s) => s.Columns.Where(c => !c.Hidden).ToList();

    /// Excel: every row of the current view (or only the selected rows), the visible columns, typed cells.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        (GridPlan Plan, GridPage Page)? r;
        try { r = await ExportRowsAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        catch (ViewTimeoutException ex) { return ExportTimedOut(ex); }
        if (r is null) return NotFound(Error ?? Notice ?? "nothing to export");
        var (plan, page) = r.Value;
        // #589: exactly the chosen columns (own + extra), for every row matching the filters
        var cols = DisplayColumns.Count > 0 ? DisplayColumns : Visible(plan.Spec);
        var rows = await FillAsync(cols, page.Rows, ct);
        return await ExcelExport.FileAsync(ExportName, Current?.CollectionId, (x, info) =>
        {
            info.Collection = Current?.CollectionId;
            info.Add("Collection time (UTC)", Current?.CollectionTime);
            info.Add("Sort", page.State.Sort + (page.State.Desc ? " (descending)" : ""));
            info.Filter("Search", page.State.Search);
            foreach (var f in page.State.Filters) info.Add("Filter: " + (plan.Spec.Column(f.Key)?.Label ?? f.Key), plan.Spec.Column(f.Key) is { } fc ? ExportFilterText(fc, f) : FilterText(f));
            if (page.State.Selected.Count > 0) info.Add("Selected rows", page.State.Selected.Count);
            if (ExportChoices.PageOnly(Request)) info.Add("Rows", "the page shown (page " + Fmt.Int(page.State.Page) + ", " + Fmt.Int(page.State.Size) + " per page)");
            foreach (var e in ExtraState()) info.Add(e.Key, e.Value);
            x.Sheet(info, Heading, cols.Select(c => c.Label).ToList(), rows.Select(row => (IReadOnlyList<object?>)cols.Select(c => CellExcel(c, row)).ToList()));
            if (page.Rows.Count >= ProDataFilters.MaxExport) info.Notes.Add($"The export stops at {ProDataFilters.MaxExport:N0} rows; narrow the filter to get the rest.");
            return Task.CompletedTask;
        }, ct);
    }

    /// CSV: the same rows and columns; UTF-8 with a BOM, formula-looking cells defused.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetCsvAsync(CancellationToken ct)
    {
        (GridPlan Plan, GridPage Page)? r;
        try { r = await ExportRowsAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        catch (ViewTimeoutException ex) { return ExportTimedOut(ex); }
        if (r is null) return NotFound(Error ?? Notice ?? "nothing to export");
        var (plan, page) = r.Value;
        var cols = DisplayColumns.Count > 0 ? DisplayColumns : Visible(plan.Spec);
        var rows = await FillAsync(cols, page.Rows, ct);
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", cols.Select(c => Findings.IndexModel.Csv(c.Label))));
        // machine-readable: numbers invariant, no grouping, "." decimal -- whatever the viewer's regional format
        foreach (var row in rows) sb.AppendLine(string.Join(",", cols.Select(c => Findings.IndexModel.Csv(CellText(c, row, csv: true)))));
        var name = ExportName + (Current is null ? "" : "-" + Current.CollectionId) + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + "Z.csv";
        return File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray(), "text/csv; charset=utf-8", name);
    }

    /// <summary>
    /// #589 "Export all columns": every row matching the filters (as the all-rows export) with EVERY column of the view --
    /// every own column, shown or not, the CI id, every identifier value, the linked objects, the finding context and
    /// fields -- and, for a view whose rows are tied to a CI, every field of the CI document and the Full details sheet
    /// (every property each source reported, <see cref="SI.Management.Web.Cis.CiFullExport"/>).
    /// </summary>
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAllAsync(CancellationToken ct)
    {
        (GridPlan Plan, GridPage Page)? r;
        try { r = await ExportRowsAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        catch (ViewTimeoutException ex) { return ExportTimedOut(ex); }
        if (r is null || ViewLayout is null) return NotFound(Error ?? Notice ?? "nothing to export");
        var (plan, page) = r.Value;
        var layout = ViewLayout;
        var full = layout.Ci != RowCiKey.None ? HttpContext.RequestServices.GetService<ICiFullExportViews>() : null;
        // the CI document fields and the source properties come in the CI sheet / the Full details sheet when the full export
        // is there; every other extra column is a column of the page's own part
        var extras = layout.AllExtras.Where(k => full is null || (DataColumnKeys.FieldOf(k) is null && DataColumnKeys.SourceOf(k) is null))
            .Select(k => GridLayout.Extra(k, layout.Label(k)));
        var cols = plan.Spec.Columns.Concat(extras).ToList();
        var rows = await FillAsync(cols, page.Rows, ct);
        var metadata = HttpContext.RequestServices.GetService<IAssetMetadataViews>();
        return await ExcelExport.FileAsync(ExportName + "-all-columns", Current?.CollectionId, async (x, info) =>
        {
            info.Collection = Current?.CollectionId;
            info.Add("Collection time (UTC)", Current?.CollectionTime);
            info.Add("Columns", full is null ? "every column of the view" : "every column of the view, then every CI field (all fields of the CI document), whatever columns the page shows");
            info.Add("Sort", page.State.Sort + (page.State.Desc ? " (descending)" : ""));
            info.Filter("Search", page.State.Search);
            foreach (var f in page.State.Filters) info.Add("Filter: " + (plan.Spec.Column(f.Key)?.Label ?? f.Key), plan.Spec.Column(f.Key) is { } fc ? ExportFilterText(fc, f) : FilterText(f));
            if (page.State.Selected.Count > 0) info.Add("Selected rows", page.State.Selected.Count);
            foreach (var e in ExtraState()) info.Add(e.Key, e.Value);
            var headers = cols.Select(c => c.Label).ToList();
            if (full is not null)
            {
                var keyed = rows.Select(row => new SI.Management.Web.Cis.CiExportRow(RefOf(row).Ci ?? "", Cell(row, "AssetName") ?? Cell(row, "Name"),
                    cols.Select(c => CellExcel(c, row)).ToList())).ToList();
                await SI.Management.Web.Cis.CiFullExport.WriteAsync(x, info, full, metadata, layout.Ci == RowCiKey.CiId ? CiExportKeys.CiId : CiExportKeys.AssetKey,
                    layout.Ci == RowCiKey.CiId ? "CI id" : "Asset (CI) key", headers, keyed, ct,
                    // every CI field under the heading the grid shows that column under
                    fieldHeading: f => layout.Label(DataColumnKeys.Field(f)));
            }
            else x.Sheet(info, Heading, headers, rows.Select(row => (IReadOnlyList<object?>)cols.Select(c => CellExcel(c, row)).ToList()));
            if (page.Rows.Count >= ProDataFilters.MaxExport) info.Notes.Add($"The export stops at {ProDataFilters.MaxExport:N0} rows; narrow the filter to get the rest.");
        }, ct);
    }

    /// #284: an export that ran out of time answers 504 with the same text the page shows (never the generic error page).
    private IActionResult ExportTimedOut(ViewTimeoutException ex)
    {
        var reference = Reference();
        Log.LogWarning(ex, "export of collection view {Page} timed out after {Seconds}s (reference {Reference})", PagePath, ex.Limit.TotalSeconds, reference);
        return new ContentResult { StatusCode = StatusCodes.Status504GatewayTimeout, ContentType = "text/plain; charset=utf-8", Content = TimeoutText(ex.Limit, reference) };
    }

    public static string FilterText(GridFilterValue f) => f.Kind switch
    {
        GridFilter.Range => (f.Low is { } lo ? lo.ToString(CultureInfo.InvariantCulture) : "") + ".." + (f.High is { } hi ? hi.ToString(CultureInfo.InvariantCulture) : ""),
        GridFilter.Contains => f.Text ?? "",
        GridFilter.Dates => f.Text ?? "",
        _ => string.Join(" | ", f.Values),
    };

    /// A cell as Excel should hold it: numbers as numbers, times as dates, a tier as its number, flags as booleans.
    public static object? ExcelValue(GridColumn c, IReadOnlyDictionary<string, object?> row)
    {
        if (!row.TryGetValue(c.Key, out var v) || v is null) return null;
        return c.Type switch
        {
            GridType.Number => v is string s ? (double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : s) : Convert.ToDouble(v, CultureInfo.InvariantCulture),
            GridType.Date => v is DateTimeOffset o ? o.UtcDateTime : v,
            GridType.Tier => ExcelExport.Tier(Convert.ToString(v, CultureInfo.InvariantCulture)),
            GridType.Flag => v is bool b ? b : Convert.ToString(v, CultureInfo.InvariantCulture) is "1" or "True" or "true",
            _ => ExcelExport.Blank(Convert.ToString(v, CultureInfo.InvariantCulture)),
        };
    }

    /// A risk score column (a finding's score, a weighted, highest, average, total or before / after / change of risk):
    /// shown as a WHOLE number, like every risk score in the web app (#245).
    public static bool IsScoreColumn(GridColumn c) =>
        c.Type == GridType.Number && (c.Key.Contains("Risk", StringComparison.OrdinalIgnoreCase) || c.Key.Contains("Score", StringComparison.OrdinalIgnoreCase));

    /// A cell as text: on screen in the viewer's regional format (risk scores whole); with <paramref name="csv"/> the
    /// invariant, ungrouped form a machine reads.
    public static string Text(GridColumn c, IReadOnlyDictionary<string, object?> row, bool csv = false)
    {
        if (!row.TryGetValue(c.Key, out var v) || v is null) return "";
        return c.Type switch
        {
            GridType.Number => v is string s ? s
                : csv ? ScoreFormat.Invariant(Convert.ToDouble(v, CultureInfo.InvariantCulture))
                : IsScoreColumn(c) ? ScoreFormat.Whole(Convert.ToDouble(v, CultureInfo.InvariantCulture))
                : Num(Convert.ToDouble(v, CultureInfo.InvariantCulture)),
            GridType.Date => v switch { DateTime d => Fmt.When(d), DateTimeOffset o => Fmt.When(o), _ => Convert.ToString(v, CultureInfo.InvariantCulture) ?? "" },
            GridType.Tier => Convert.ToString(v, CultureInfo.InvariantCulture) is { } t && t != ProDataFilters.Unclassified ? "Tier " + t : "Unclassified",
            GridType.Flag => v is bool b ? (b ? "yes" : "no") : Convert.ToString(v, CultureInfo.InvariantCulture) is "1" or "True" or "true" ? "yes" : "no",
            _ => Convert.ToString(v, CultureInfo.InvariantCulture) ?? "",
        };
    }

    /// The moment in a date cell (UTC), or null when the cell holds none -- the grid renders it as a &lt;time&gt; the
    /// browser shows in the viewer's zone (#313).
    public static DateTime? Moment(GridColumn c, IReadOnlyDictionary<string, object?> row) =>
        c.Type != GridType.Date || !row.TryGetValue(c.Key, out var v) ? null
        : v switch { DateTime d => LocalTime.Utc(d), DateTimeOffset o => o.UtcDateTime, _ => null };

    /// The tier of a tier cell as the dot's class suffix ("0".."3", else "Unclassified").
    public static string Cell0(IReadOnlyDictionary<string, object?> row, string key) =>
        row.TryGetValue(key, out var v) && Convert.ToString(v, CultureInfo.InvariantCulture) is { } t && ProDataFilters.Tiers.Contains(t) ? t : ProDataFilters.Unclassified;

    /// A number on screen, in the viewer's regional format (the shared formatter).
    public static string Num(double d) => ScoreFormat.Number(d);

    /// The label a filter value has in the multi-select (flags read yes / no, tiers "Tier n").
    public static string OptionLabel(GridColumn c, string v) => c.Type switch
    {
        GridType.Flag => v == "1" ? "yes" : "no",
        GridType.Tier => v == ProDataFilters.Unclassified ? v : "Tier " + v,
        _ => v,
    };
}
