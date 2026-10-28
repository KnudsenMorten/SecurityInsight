using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Cis;
using SI.Management.Web.Export;
using SI.Management.Web.Pages.Collection;

namespace SI.Management.Web.Pages.Cis;

/// <summary>
/// The CIs (V3-DATA-MODEL 2.13): one row per CI from sidata.Ci -- tier, risk score, weighted score, risk factors, the CMDB
/// values -- with filters (class, tier, lifecycle, search), sort, paging and Excel / CSV export. The columns are the
/// person's own layout, else the tenant default an Admin set, else the shipped default (the CI output map); the column
/// chooser saves either (cfg.ColumnLayout). Until the data sync has loaded the CI tables the page says so and shows nothing.
/// <para>THE CI grid is this model and Pages/Cis/_CiGrid.cshtml. The tier board (Pages/Tiers) is the same grid at its own
/// address, under its own view key and shipped layout, with tiles that set the tier / decided-by / class filters and a
/// row drawer -- it derives from this model and overrides only what differs (<see cref="Route"/>, <see cref="ViewName"/>,
/// <see cref="ShippedLayout"/>, <see cref="TileFilters"/>, <see cref="RowDrawer"/>).</para>
/// </summary>
public class IndexModel : PageModel
{
    public const string View = "cis";
    private readonly ICiViews _cis;
    private readonly IColumnLayoutStore _layouts;
    private readonly ILogger _log;

    public IndexModel(ICiViews cis, IColumnLayoutStore layouts, ILogger<IndexModel> log) : this(cis, layouts, (ILogger)log) { }

    /// For a page that is this grid at another address (the tier board).
    protected IndexModel(ICiViews cis, IColumnLayoutStore layouts, ILogger log) { _cis = cis; _layouts = layouts; _log = log; }

    /// The CI views (for a derived page's own reads).
    protected ICiViews CiData => _cis;

    /// The page's address.
    public virtual string Route => "/Cis";
    /// The view key the person's columns, sort and filters are kept under (cfg.ColumnLayout / cfg.ViewState).
    public virtual string ViewName => View;
    /// The grid's element ids and its table's marker (data-grid).
    public virtual string GridId => "cis";
    /// The export files' name stem.
    protected virtual string ExportName => "cis";
    /// The filters (address parameters: class, tier, tiersetby) the page sets with its own controls above the grid: the
    /// filter form carries them along instead of offering a second control for the same filter.
    public virtual IReadOnlySet<string> TileFilters => NoTileFilters;
    private static readonly IReadOnlySet<string> NoTileFilters = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    /// The row-click hook (data-row-drawer): the address of the fragment a row opens beside the grid; null = none.
    public virtual string? RowDrawer(IReadOnlyDictionary<string, object?> row) => null;
    /// The same content as a plain page (the link a row carries when it has a drawer: works without script); null = none.
    public virtual string? RowPanelLink(IReadOnlyDictionary<string, object?> row) => null;
    /// A mark on a row (a change staged for it, not committed yet); null = none.
    public virtual string? RowMark(IReadOnlyDictionary<string, object?> row) => null;

    public const string NotLoadedText = "The v3 data model has not been loaded yet -- it arrives with the next data sync.";

    /// #406 the lifecycle filter a page opens with when its address names none (null = none): the CI list shows the active CIs
    /// and says so; a person clears it (lifecycle=all) to see not seen and retired CIs too.
    public virtual string? DefaultLifecycle => CiLifecycleDefinitions.DefaultFilter;
    /// True when this request's lifecycle filter is the page's default (the page says it out loud).
    public bool LifecycleDefaulted { get; private set; }
    /// #406 the lifecycle in plain words, from the settings in force (seen window, grace period per category).
    public CiLifecycleRules LifecycleRules { get; private set; } = CiLifecycleDefinitions.Defaults;
    /// The lifecycle states this request lists (the named default, or the person's choice; null = every state) -- the tier
    /// board's tiles and the tab counts count the same set.
    public IReadOnlyList<string>? LifecycleInForce => ReadGrid().Filters.TryGetValue("Lifecycle", out var lv) && lv.Length > 0
        ? lv.Split(ProDataFilters.ValueSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) : null;
    /// #855 M25: the lifecycle in force as the shared filter (every state = All; a stored value the filter does not know -- none
    /// is shipped -- counts every state rather than none).
    public LifecycleFilter LifecycleFilterInForce =>
        LifecycleInForce is { Count: > 0 } states && states.Any(s => LifecycleFilter.Known.Contains(s.Trim().ToLowerInvariant()))
            ? LifecycleFilter.Of(states.ToArray()) : LifecycleFilter.All;
    /// The address that clears the lifecycle filter -- also the default one -- to every lifecycle state.
    public string LifecycleClearLink => Link(("lifecycle", CiLifecycleDefinitions.ClearedFilter));
    /// The lifecycle filter's choices with their counts (the filter values of the data, the stored order: active, not seen, retired).
    public IReadOnlyList<(string Value, string Label, long Count)> LifecycleChoices()
    {
        var order = new[] { "active", "not_seen", "retired" };
        var have = Facets.Where(f => f.Facet == "Lifecycle").ToList();
        return order.Select(v => (v, CiLifecycleDefinitions.Label(v), have.FirstOrDefault(f => string.Equals(f.Value, v, StringComparison.OrdinalIgnoreCase))?.N ?? 0L))
            .Concat(have.Where(f => !order.Contains(f.Value, StringComparer.OrdinalIgnoreCase)).Select(f => (f.Value, CiLifecycleDefinitions.Label(f.Value), f.N))).ToList();
    }

    public CiColumnCatalog Catalog { get; } = CiColumns.Default;
    public CiSchema Schema { get; private set; } = CiSchema.None;
    public bool NotLoaded { get; private set; }
    public GridSpec? Spec { get; private set; }
    public GridPage? Grid { get; private set; }
    public IReadOnlyList<string> Layout { get; private set; } = Array.Empty<string>();
    public string LayoutSource { get; private set; } = ColumnLayout.FromDefault;
    /// False while cfg.ColumnLayout does not exist (the chooser then says a layout cannot be saved yet).
    public bool LayoutStoreReady { get; private set; }
    public IReadOnlyList<CiFacet> Facets { get; private set; } = Array.Empty<CiFacet>();
    public List<QueryInfo> Queries { get; } = new();
    public string? Error { get; protected set; }

    public IReadOnlyList<string> FacetValues(string facet) => Facets.Where(f => f.Facet == facet).Select(f => f.Value).ToList();

    /// The grid request from the URL: q, class, type, subtype, tier, tiersetby (who decided the tier), lifecycle (each may
    /// repeat), sort, dir, p, size, sel.
    public GridRequest ReadGrid()
    {
        var q = Request.Query;
        var filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (param, col) in new[] { ("class", "Class"), ("type", "AssetType"), ("subtype", SI.Management.Core.ProData.CiColumns.AssetSubtypeKey), ("tier", "Tier"),
            ("tiersetby", CiColumns.TierSetByKey), ("lifecycle", "Lifecycle") })
        {
            // (#406 "all" is the lifecycle filter cleared: every lifecycle state, the named default off)
            var joined = string.Join("|", q[param].Where(v => !string.IsNullOrWhiteSpace(v) && !(param == "lifecycle" && string.Equals(v, CiLifecycleDefinitions.ClearedFilter, StringComparison.OrdinalIgnoreCase))));
            if (joined.Length > 0) filters[col] = joined;
        }
        // #406 THE NAMED DEFAULT: an address without a lifecycle filter shows the active CIs -- said on the page
        // (LifecycleRules.DefaultFilterText) and cleared with lifecycle=all; never an implicit WHERE
        LifecycleDefaulted = false;
        if (DefaultLifecycle is { Length: > 0 } dl && !q.ContainsKey("lifecycle")) { filters["Lifecycle"] = dl; LifecycleDefaulted = true; }
        // the context filters (f.<column>): environment, MFA strength, risk level, device value, Defender plan tier ...
        foreach (var c in Catalog.ValueFilters)
        {
            var joined = string.Join("|", q[ContextFilterParam(c)].Where(v => !string.IsNullOrWhiteSpace(v)));
            if (joined.Length > 0) filters[c.Key] = joined;
        }
        // "+ Add filter" (f.<column>): every other typed column that filters in SQL -- a list of values, a number range, a
        // date range, a text
        foreach (var c in AddableFilters)
        {
            var given = q[ContextFilterParam(c)].Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v!).ToList();
            if (given.Count == 0) continue;
            filters[c.Key] = c.Filter is GridFilter.Values or GridFilter.Tokens ? string.Join("|", given) : given[0];
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

    /// The URL parameter a column's filter travels in (what an active filter's chip removes): the filters above the grid
    /// have their own names (the asset type is "type", the subtype "subtype"), a context filter is "f." + its column.
    public string FilterParam(string key) =>
        key == "AssetType" ? "type"
        : key == CiColumns.AssetSubtypeKey ? "subtype"
        : Catalog.ValueFilters.FirstOrDefault(x => x.Key == key) is { } context ? ContextFilterParam(context)
        : AddableFilters.FirstOrDefault(x => x.Key == key) is { } added ? ContextFilterParam(added)
        : key.ToLowerInvariant();

    /// The URL parameter of a context filter ("f.Environment"); #855 item 3: the onboarding status travels as "onboarding" (the
    /// executive coverage figure links /Cis/Index?class=device&amp;onboarding=can_be_onboarded).
    public static string ContextFilterParam(CiColumn c) => c.Field == CiColumns.OnboardingField ? CiColumns.OnboardingParam : "f." + c.Key;

    /// The context filters this request sets (their columns are carried by the statement whatever the layout shows).
    private IReadOnlyList<string> FilteredContext() =>
        Catalog.ValueFilters.Concat(AddableFilters).Where(c => Request.Query[ContextFilterParam(c)].Any(v => !string.IsNullOrWhiteSpace(v))).Select(c => c.Key).ToList();

    /// The filters above the grid that have their own address parameter (class, type, subtype, tier, tiersetby, lifecycle).
    public static readonly IReadOnlySet<string> AboveGridKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "Class", "AssetType", CiColumns.AssetSubtypeKey, "Tier", CiColumns.TierSetByKey, "Lifecycle" };

    /// <summary>
    /// "+ Add filter" of the CI views (owner 2026-10-19, "CI-document fields through the promoted typed columns"): every
    /// field the CI holds as a TYPED COLUMN -- a column of sidata.Ci of its own, the CI grid's promoted fields, the
    /// prepared list (view-stored-columns.json) -- that filters in SQL, beyond the filters above the grid. A field read
    /// from the CI document only is not offered (<see cref="NotFilterable"/>).
    /// </summary>
    public IReadOnlyList<CiColumn> AddableFilters => _addable ??= Catalog.Columns
        .Where(c => (c.Stored || c.Promoted is not null) && c.Filter != GridFilter.None && !c.Dynamic && !AboveGridKeys.Contains(c.Key) && !Catalog.ValueFilters.Any(v => v.Key == c.Key))
        .ToList();
    private IReadOnlyList<CiColumn>? _addable;

    /// The CI fields "+ Add filter" does not offer, and why (shown under it): a list or an object (the JSON of the field),
    /// or a field read from the CI document alone -- filtering on it would read every CI's document; it becomes filterable
    /// once it is a prepared column (one entry in view-stored-columns.json).
    public IReadOnlyList<(string Label, string Why)> NotFilterable => Catalog.Columns
        .Where(c => !AddableFilters.Contains(c) && !Catalog.ValueFilters.Contains(c) && !AboveGridKeys.Contains(c.Key))
        .Select(c => (c.Label, c.Dynamic ? NotFilterableList : c.Stored || c.Promoted is not null ? NotFilterableShown : NotFilterableDocument))
        .ToList();

    public const string NotFilterableList = "a list or an object: shown and exported, not filtered";
    public const string NotFilterableDocument = "read from the CI document only: it becomes a filter once it is a prepared column";
    public const string NotFilterableShown = "a long text: shown and exported, not filtered";

    /// The context filters offered above the grid: the ones the data has values for (read from each column's index, cached
    /// per data version), and any the URL already sets.
    public IReadOnlyList<CiColumn> ContextFilters =>
        Catalog.ValueFilters.Where(c => Facets.Any(f => f.Facet == c.Key) || Request.Query.ContainsKey(ContextFilterParam(c))).ToList();

    /// The classes the request is filtered to (the class filter above the grid).
    private IReadOnlyList<string> FilteredClasses() =>
        Request.Query["class"].Where(v => !string.IsNullOrWhiteSpace(v)).SelectMany(v => v!.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// The asset types the request is filtered to (the asset type filter above the grid; a value may repeat or be '|'-joined).
    private IReadOnlyList<string> FilteredAssetTypes() =>
        Request.Query["type"].Where(v => !string.IsNullOrWhiteSpace(v)).SelectMany(v => v!.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// This page's URL with the current query, some parameters overridden (null removes one; any change but the page
    /// number starts at page 1).
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

    /// The user key a person's own layout is stored under.
    private string UserKey => User.ChangeName();

    /// A department-limited account sees no CI list: the CIs span every department.
    protected async Task<bool> DepartmentLimitedAsync(CancellationToken ct)
    {
        var resolver = HttpContext?.RequestServices.GetService<SI.Management.Web.Departments.IDepartmentScopeResolver>();
        if (resolver is null || (await resolver.ResolveAsync(User, ct)).Rows is null) return false;
        Error = "This view is not available to an account limited to departments: it shows CIs across every department.";
        return true;
    }

    private async Task LoadLayoutAsync(CancellationToken ct)
    {
        // #589: the CI fields of the catalog are this view's own columns; the extra columns are the identifier values, the
        // linked objects, the source properties and the CI document fields the catalog does not list
        var own = Catalog.Columns.Select(c => new SI.Management.Web.Columns.ViewColumn(c.Key, c.Label, Catalog.DefaultLayout.Contains(c.Key, StringComparer.OrdinalIgnoreCase), c.Description, c.Group)).ToList();
        var ownFields = new HashSet<string>(Catalog.Columns.Select(c => c.Field), StringComparer.Ordinal);
        var probe = new SI.Management.Web.Columns.DataViewLayout { View = ViewName, Own = own, Ci = RowCiKey.CiId, OwnCiFields = ownFields };
        var shipped = ShippedLayout();
        ViewLayout = await new SI.Management.Web.Columns.DataViewLayout
        {
            View = ViewName, Own = own, Ci = RowCiKey.CiId, OwnCiFields = ownFields, Shipped = SI.Management.Web.Columns.DataViewDefaults.Complete(shipped, probe.Known),
        }.LoadAsync(HttpContext, _log, ct);
        (Layout, LayoutSource, LayoutStoreReady) = (ViewLayout.Layout, ViewLayout.Source, ViewLayout.StoreReady);
        // the promoted fields from their columns once the data sync filled them; the CI document only where it has not
        Spec = Catalog.Spec(Layout, State.Mode, State.CtxMode, FilteredContext());
        DisplayColumns = SI.Management.Web.Columns.GridLayout.Display(Spec, ViewLayout);
    }

    /// The shipped layout: the CI output map, the cross-class context, then -- when the list is filtered to ONE class --
    /// what that class carries (devices: primary user, encryption, open alerts ...), and for identities what the ONE kind
    /// chosen with the asset type filter carries (users: MFA strength, risk level, manager ...; service principals:
    /// owners, credential expiry, attached resource ...) -- identities of both kinds open with the cross-class context
    /// only. Then the CI's identity. Every one of them is a prepared column. Only the SHIPPED layout follows the filter:
    /// a person's own layout, or the tenant default, still wins.
    protected virtual IEnumerable<string> ShippedLayout()
    {
        var classes = FilteredClasses();
        var forClass = ShippedForClass(Catalog, classes, FilteredAssetTypes());
        // a list of identities: what only ONE kind carries (a user's MFA strength, a service principal's credential
        // expiry) shows for that kind alone -- also when the catalog shows the field by default: never a user's columns
        // on a list of service principals, or half-empty columns while both kinds are listed
        var identities = classes.Count == 1 && classes.First().Trim().Equals(SI.Management.Web.Columns.DataViewDefaults.IdentityClass, StringComparison.OrdinalIgnoreCase);
        var otherKind = (identities ? SI.Management.Web.Columns.DataViewDefaults.IdentityKindContext.Values.SelectMany(f => f) : Enumerable.Empty<string>())
            .Select(f => Catalog.OfField(f)?.Key).Where(k => k is not null).Select(k => k!)
            .Except(forClass, StringComparer.OrdinalIgnoreCase).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return Catalog.DefaultLayout.Where(k => !otherKind.Contains(k)).Concat(ShippedExtra).Concat(forClass).Concat(SI.Management.Web.Columns.DataViewDefaults.CiIdentity);
    }

    /// #589: the CI context All CIs opens with beyond the CI output map (owner 2026-10-11: "enable all relevant columns per
    /// view"): who answers for the CI, what it runs, where it lives -- every reference as id and name.
    public static readonly IReadOnlyList<string> ShippedExtra =
        ["CiId", "Owner", "Department", "Environment", "OsName", "OsVersion", "IpAddress", "Hostname", "AzureSubscriptionId", "AzureSubscriptionName", "AzureResourceGroup",
         "ManagementGroupPath", "ServiceSupportGroup", "ServiceSupportGroupId", "CmdbId", "CmdbName", "LastSeen"];

    /// The columns (grid keys) of what ONE class carries (<see cref="SI.Management.Web.Columns.DataViewDefaults.ClassContext"/>):
    /// added to the shipped layout when the list is filtered to that class alone.
    public static IReadOnlyList<string> ShippedForClass(CiColumnCatalog catalog, IReadOnlyCollection<string> classes) =>
        ShippedForClass(catalog, classes, Array.Empty<string>());

    /// The same with the asset types the list is filtered to: identities open with the columns of the ONE kind they name
    /// (<see cref="SI.Management.Web.Columns.DataViewDefaults.IdentityKindContext"/>), and with none while both kinds --
    /// or no asset type -- are chosen.
    public static IReadOnlyList<string> ShippedForClass(CiColumnCatalog catalog, IReadOnlyCollection<string> classes, IReadOnlyCollection<string> assetTypes) =>
        SI.Management.Web.Columns.DataViewDefaults.ForClass(classes, assetTypes).Select(f => catalog.OfField(f)?.Key).Where(k => k is not null).Select(k => k!).ToList();

    /// The view's columns and the person's layout (#589).
    public SI.Management.Web.Columns.DataViewLayout? ViewLayout { get; private set; }
    /// The columns shown (and exported by the all-rows / selected exports), in the chosen order.
    public IReadOnlyList<GridColumn> DisplayColumns { get; private set; } = Array.Empty<GridColumn>();

    private Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> FillAsync(IReadOnlyList<GridColumn> cols, IReadOnlyList<IReadOnlyDictionary<string, object?>> rows, CancellationToken ct) =>
        ViewLayout is null ? Task.FromResult(rows)
            : SI.Management.Web.Columns.GridLayout.FillAsync(HttpContext, _log, ViewLayout, cols, rows, r => new SI.Management.Web.Columns.RowRef(Key(r)), null, ct);

    /// How sidata.Ci is read now and the version the cached filter values belong to (owner 2026-10-11: the page took ~10 s).
    public CiDataState State { get; private set; } = CiDataState.Unknown;

    private async Task<bool> PrepareAsync(CancellationToken ct)
    {
        var schema = await _cis.SchemaAsync(ct);
        Schema = schema.Data;
        if (!Schema.Ci) { NotLoaded = true; return false; }
        if (await DepartmentLimitedAsync(ct)) return false;
        try { State = (await _cis.DataStateAsync(Schema, ct)).Data; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // unknown = the document, as before the columns existed: slower, never wrong
            _log.LogWarning(ex, "the CI data state could not be read; the CI list reads the CI documents");
            State = CiDataState.Unknown;
        }
        await LoadLayoutAsync(ct);
        return true;
    }

    public virtual async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        await LoadGridAsync(ct);
        return Page();
    }

    /// The values of one "+ Add filter" list column with their counts, under the other filters (js/app/value-counts.js).
    public async Task<IActionResult> OnGetValueCountsAsync(string? col, CancellationToken ct)
    {
        try
        {
            if (!await PrepareAsync(ct)) return new JsonResult(new { ok = false, message = Error ?? NotLoadedText });
            if (AddableFilters.Concat(Catalog.ValueFilters).FirstOrDefault(c => string.Equals(c.Key, col, StringComparison.OrdinalIgnoreCase)) is not { Filter: GridFilter.Values or GridFilter.Tokens } c)
                return new JsonResult(new { ok = false, message = "This column has no value filter." });
            var spec = Catalog.Spec(Layout, State.Mode, State.CtxMode, FilteredContext().Append(c.Key).Distinct(StringComparer.OrdinalIgnoreCase).ToList());
            var counts = (await _cis.ValueCountsAsync(spec, ReadGrid(), c.Key, ct)).Data;
            return new JsonResult(new { ok = true, column = c.Key, values = counts.Select(x => new { value = x.Value, label = x.Value, n = x.N, text = Fmt.Int(x.N) }) });
        }
        catch (ArgumentException ex) { return new JsonResult(new { ok = false, message = ex.Message }); }
        catch (ViewTimeoutException) { return new JsonResult(new { ok = false, message = "Counting took too long -- the filter is shown without its values." }); }
    }

    /// Reads the page of the grid the address asks for (the layout, the rows, the filter choices). A read that fails
    /// does not throw: the page says what went wrong.
    protected async Task LoadGridAsync(CancellationToken ct)
    {
        try
        {
            if (!await PrepareAsync(ct)) return;
            // #406 the lifecycle definitions from the settings in force (a page without the reader keeps the defaults)
            // (the reader -- and the settings store behind it -- is resolved inside the guard: a host without a settings
            // database must still show the CIs)
            try { if (HttpContext?.RequestServices.GetService<ICiLifecycleRulesReader>() is { } lr) LifecycleRules = await lr.ReadAsync(ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the lifecycle settings could not be read; the defaults are shown"); }
            var req = ReadGrid();
            try { GridSql.Normalize(Spec!, req); }
            catch (ArgumentException ex) { Error = "The filter is not valid: " + ex.Message; return; }
            // the filter choices are read WHILE the grid is: neither needs the other (each read has its own connection)
            var facets = FacetsOrNoneAsync(ct);
            var g = await _cis.GridAsync(Spec!, req, false, ct);
            Grid = g.Data with { Rows = await FillAsync(DisplayColumns, g.Data.Rows, ct) };
            Queries.Add(QueryInfo.From(g, "The CIs"));
            if (await facets is { } f)
            {
                Facets = f.Data;
                Queries.Add(QueryInfo.From(f, "The filter choices"));
            }
        }
        catch (ArgumentException ex) { Error = "The request is not valid: " + ex.Message; }
        catch (ViewTimeoutException ex) { Error = CollectionPageModel.TimeoutText(ex.Limit, null); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the CI list could not be read");
            Error = "The CIs could not be read from the Pro database: " + ex.Message;
        }
    }

    /// The filter choices, or null when they could not be read (logged; the grid is shown without them). Never throws -- also
    /// not for the request's own cancellation -- so the read started beside the grid is never left faulted.
    private async Task<SI.Management.Core.QueryResult<IReadOnlyList<CiFacet>>?> FacetsOrNoneAsync(CancellationToken ct)
    {
        // #855 M25: the choices are counted over the CIs of the lifecycle in force (the lifecycle's own choice counts every state)
        try { return await _cis.CiFacetsAsync(State, LifecycleFilterInForce, ct); }
        catch (OperationCanceledException) { return null; }
        catch (Exception ex) { _log.LogWarning(ex, "the CI filter choices could not be read"); return null; }
    }

    // ---- cells ----------------------------------------------------------------------------------------------------

    /// A cell on screen (viewer's number format) or, with <paramref name="csv"/>, the invariant form a machine reads.
    public string CellText(GridColumn c, IReadOnlyDictionary<string, object?> row, bool csv = false)
    {
        if (SI.Management.Web.Columns.GridLayout.IsExtra(c)) return SI.Management.Web.Columns.GridLayout.Text(row, c.Key);
        var col = Catalog.Find(c.Key);
        if (col is { Dynamic: true }) return CiDoc.Text(row.TryGetValue(c.Key, out var v) ? Convert.ToString(v, CultureInfo.InvariantCulture) : null);
        if (c.Key == "RiskFactors") return string.Join("; ", CollectionPageModel.Text(c, row, csv).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        return CollectionPageModel.Text(c, row, csv);
    }

    /// A cell as the grid shows it: long text is cut at 160 characters -- except the tier explanation, which is one sentence
    /// meant to be read whole (#579).
    public static string CellShown(GridColumn c, string text) =>
        text.Length > 160 && c.Key != CiColumns.TierExplanationKey ? text[..160] + "…" : text;

    /// The "decided by" filter's choices: the shipped values, then any other value the data holds.
    public IReadOnlyList<string> TierSetByChoices() => CiColumns.TierSetByValues.Union(FacetValues(CiColumns.TierSetByKey), StringComparer.OrdinalIgnoreCase).ToList();

    public object? CellExcel(GridColumn c, IReadOnlyDictionary<string, object?> row) =>
        SI.Management.Web.Columns.GridLayout.IsExtra(c) ? SI.Management.Web.Columns.GridLayout.Excel(row, c.Key)
        : Catalog.Find(c.Key) is { Dynamic: true } ? ExcelExport.Blank(CellText(c, row, csv: true)) : CollectionPageModel.ExcelValue(c, row);

    /// #856 a nameless CI's fallback (its IP / MAC address or source id), from the hidden column every CI statement carries;
    /// null when the CI has a name. Shown marked in the grid -- never as the name in an export.
    public static CiNameFallback? NameFallback(IReadOnlyDictionary<string, object?> row) =>
        CiDisplayName.Of(row.TryGetValue("Name", out var n) ? Convert.ToString(n, CultureInfo.InvariantCulture) : null,
            row.TryGetValue(CiDisplayName.FallbackKey, out var f) ? Convert.ToString(f, CultureInfo.InvariantCulture) : null);

    /// Where a cell links: the name and the CI id open the CI.
    public string? CellLink(GridColumn c, IReadOnlyDictionary<string, object?> row) =>
        c.Key is "Name" or "CiId" && row.TryGetValue(CiColumns.KeyColumn, out var id) && Convert.ToString(id, CultureInfo.InvariantCulture) is { Length: > 0 } s
            ? "/Cis/Detail?id=" + Uri.EscapeDataString(s) : null;

    public string? Key(IReadOnlyDictionary<string, object?> row) =>
        row.TryGetValue(CiColumns.KeyColumn, out var v) ? Convert.ToString(v, CultureInfo.InvariantCulture) : null;

    // ---- export ---------------------------------------------------------------------------------------------------

    private async Task<GridPage?> ExportRowsAsync(CancellationToken ct)
    {
        if (!await PrepareAsync(ct)) return null;
        // "Export this page" reads the page shown; every other export every matching CI
        return (await _cis.GridAsync(Spec!, ReadGrid(), !SI.Management.Web.Columns.ExportChoices.PageOnly(Request), ct)).Data;
    }

    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        GridPage? page;
        try { page = await ExportRowsAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (page is null) return NotFound(Error ?? NotLoadedText);
        var cols = DisplayColumns.Count > 0 ? DisplayColumns : CollectionPageModel.Visible(Spec!);
        var rows = await FillAsync(cols, page.Rows, ct);
        return await ExcelExport.FileAsync(ExportName, null, (x, info) =>
        {
            info.Add("Columns", LayoutSource == ColumnLayout.FromUser ? "your own layout" : LayoutSource == ColumnLayout.FromTenant ? "the tenant default" : "the shipped default");
            info.Add("Sort", page.State.Sort + (page.State.Desc ? " (descending)" : ""));
            info.Filter("Search", page.State.Search);
            foreach (var f in page.State.Filters) info.Add("Filter: " + (Spec!.Column(f.Key)?.Label ?? f.Key), CollectionPageModel.FilterText(f));
            if (page.State.Selected.Count > 0) info.Add("Selected rows", page.State.Selected.Count);
            if (SI.Management.Web.Columns.ExportChoices.PageOnly(Request)) info.Add("Rows", "the page shown (page " + Fmt.Int(page.State.Page) + ", " + Fmt.Int(page.State.Size) + " per page)");
            x.Sheet(info, "CIs", cols.Select(c => c.Label).ToList(), rows.Select(row => (IReadOnlyList<object?>)cols.Select(c => CellExcel(c, row)).ToList()));
            if (page.Rows.Count >= ProDataFilters.MaxExport) info.Notes.Add($"The export stops at {ProDataFilters.MaxExport:N0} rows; narrow the filter to get the rest.");
            return Task.CompletedTask;
        }, ct);
    }

    /// The heading the CI grid shows a CI document field under when the field is one of its own columns (the catalog's:
    /// "si_os_name" -> "OS"); null for a field the catalog does not list (it has the heading of an extra column).
    public static string? OwnFieldHeading(CiColumnCatalog catalog, string field) => catalog.OfField(field)?.Label;

    /// <summary>
    /// "Export all columns": the CIs matching the filter (the same rows as Export to Excel) with EVERY field of each CI's
    /// document -- not only the columns shown -- and a Full details sheet: every property each source reported about each
    /// CI (<see cref="CiFullExport"/>). Every field is written under the heading the grid shows it under, never under its
    /// internal field name.
    /// </summary>
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAllAsync(CancellationToken ct)
    {
        GridPage? page;
        try { page = await ExportRowsAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (page is null) return NotFound(Error ?? NotLoadedText);
        var views = HttpContext.RequestServices.GetService<ICiFullExportViews>();
        if (views is null) return NotFound("The full export is not available in this installation.");
        var metadata = HttpContext.RequestServices.GetService<IAssetMetadataViews>();
        // #589: after the CI document's fields, every identifier type with its values and the linked objects
        var tail = (ViewLayout?.OfferedExtras ?? Array.Empty<string>())
            .Where(k => k == SI.Management.Core.ProData.DataColumnKeys.Links || SI.Management.Core.ProData.DataColumnKeys.IdTypeOf(k) is not null)
            .Select(k => SI.Management.Web.Columns.GridLayout.Extra(k, SI.Management.Core.ProData.DataColumnKeys.Label(k))).ToList();
        var filled = await FillAsync(tail, page.Rows, ct);
        var rows = filled.Select(r => new CiExportRow(Key(r) ?? "", r.TryGetValue("Name", out var n) ? Convert.ToString(n, CultureInfo.InvariantCulture) : null, Array.Empty<object?>(),
                tail.Select(c => SI.Management.Web.Columns.GridLayout.Excel(r, c.Key)).ToList()))
            .Where(r => r.Key.Length > 0).ToList();
        return await ExcelExport.FileAsync(ExportName + "-all-columns", null, async (x, info) =>
        {
            info.Add("Columns", "every CI field (all fields of the CI document), whatever columns the page shows; the Linked objects sheet has one row per CI and linked object");
            info.Add("Sort", page.State.Sort + (page.State.Desc ? " (descending)" : ""));
            info.Filter("Search", page.State.Search);
            foreach (var f in page.State.Filters) info.Add("Filter: " + (Spec!.Column(f.Key)?.Label ?? f.Key), CollectionPageModel.FilterText(f));
            if (page.State.Selected.Count > 0) info.Add("Selected rows", page.State.Selected.Count);
            // every field under the heading the grid shows it under: this view's own column's, else the extra column's
            await CiFullExport.WriteAsync(x, info, views, metadata, CiExportKeys.CiId, "CI id", Array.Empty<string>(), rows, ct, tail.Select(c => c.Label).ToList(),
                f => OwnFieldHeading(Catalog, f));
            if (page.Rows.Count >= ProDataFilters.MaxExport) info.Notes.Add($"The export stops at {ProDataFilters.MaxExport:N0} CIs; narrow the filter to get the rest.");
        }, ct);
    }

    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetCsvAsync(CancellationToken ct)
    {
        GridPage? page;
        try { page = await ExportRowsAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (page is null) return NotFound(Error ?? NotLoadedText);
        var cols = DisplayColumns.Count > 0 ? DisplayColumns : CollectionPageModel.Visible(Spec!);
        var rows = await FillAsync(cols, page.Rows, ct);
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", cols.Select(c => Findings.IndexModel.Csv(c.Label))));
        foreach (var row in rows) sb.AppendLine(string.Join(",", cols.Select(c => Findings.IndexModel.Csv(CellText(c, row, csv: true)))));
        var name = ExportName + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + "Z.csv";
        return File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray(), "text/csv; charset=utf-8", name);
    }

    // ---- the column chooser -----------------------------------------------------------------------------------------

    /// The chooser (Pages/Shared/_ColumnChooser.cshtml): the catalog per catalog group, then (#589) the identifier values,
    /// the linked objects, every source property and the CI document fields the catalog does not list.
    public ColumnChooser? Chooser(bool isAdmin) => ViewLayout?.Chooser(Link(), isAdmin);

    /// A key a layout of this view may hold: a catalog column, or an extra column of a CI.
    private string? KnownKey(string k) => Catalog.Find(k)?.Key ?? (DataColumnKeys.IsValid(k) && DataColumnKeys.IsCi(k) ? k : null);

    [BindProperty] public List<string> Columns { get; set; } = new();
    [BindProperty] public string? Scope { get; set; }
    [BindProperty] public string? Return { get; set; }

    /// Where a post returns: this page with the grid's state (never another site).
    private IActionResult Back(string message, bool ok)
    {
        TempData["toast"] = message;
        TempData["toastKind"] = ok ? "ok" : "error";
        var back = Return is { Length: > 0 } r && r.StartsWith(Route, StringComparison.OrdinalIgnoreCase) && !r.StartsWith("//", StringComparison.Ordinal) ? r : Route;
        return LocalRedirect(back);
    }

    /// Saves the ticked columns, in the order they were listed: as the person's own layout, or (an Admin) as the tenant default.
    [SI.Management.Web.Audit.Audited("view.columns.save")]
    public async Task<IActionResult> OnPostColumnsAsync(CancellationToken ct)
    {
        var tenant = Scope == SqlColumnLayoutStore.ScopeTenant;
        if (tenant && !User.IsAdmin()) return Forbid();
        var keys = ColumnLayout.Clean(Columns, KnownKey);
        if (keys.Count == 0) return Back("Not saved: tick at least one column.", false);
        var saved = await _layouts.SaveAsync(tenant ? SqlColumnLayoutStore.ScopeTenant : SqlColumnLayoutStore.ScopeUser, UserKey, ViewName, ColumnLayout.ToJson(keys), User.ChangeName(), ct);
        if (!saved) return Back("Not saved: the column layouts are not in the Pro database yet (the next settings update adds them).", false);
        return Back(tenant ? "Saved as the tenant default: everyone without a layout of their own sees these columns." : "Saved: these are your columns on this page.", true);
    }

    /// Removes the person's own layout (they see the tenant default), or -- an Admin, Scope tenant -- the tenant default
    /// (everyone without a layout of their own sees the shipped default).
    [SI.Management.Web.Audit.Audited("view.columns.reset")]
    public async Task<IActionResult> OnPostResetAsync(CancellationToken ct)
    {
        var tenant = Scope == SqlColumnLayoutStore.ScopeTenant;
        if (tenant && !User.IsAdmin()) return Forbid();
        var done = await _layouts.ResetAsync(tenant ? SqlColumnLayoutStore.ScopeTenant : SqlColumnLayoutStore.ScopeUser, UserKey, ViewName, ct);
        if (!done) return Back("Nothing to reset: the column layouts are not in the Pro database yet.", false);
        return Back(tenant ? "The tenant default is the shipped default again." : "Reset: you see the tenant default columns again.", true);
    }
}
