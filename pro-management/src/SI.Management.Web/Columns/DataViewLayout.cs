using System.Globalization;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Cis;

namespace SI.Management.Web.Columns;

/// One column a view has of its own: its key (also the layout entry), its label, and whether the view shows it out of the box.
public sealed record ViewColumn(string Key, string Label, bool Shown = true, string? Description = null, string? Group = null);

/// What one row is tied to: its CI key (a CI id or an asset key, by <see cref="DataViewLayout.Ci"/>), its finding id, its CVE.
public readonly record struct RowRef(string? Ci, long? Finding = null, string? Cve = null);

/// <summary>
/// THE column mechanism of every data view (owner 2026-10-11, "al views must support to add all available columns. i
/// decided what to view, not you"): the view's own columns + -- for a view whose rows are CIs or tied to one -- the CI id,
/// every CI field, one column per identifier type with its values, the linked objects and every source property; for a
/// view of findings the finding context (software, description, fix, remediation...) and every finding field
/// (<see cref="DataColumnKeys"/>). One stored layout per view (cfg.ColumnLayout): the person's own, else the tenant
/// default an Admin saved, else the view's SHIPPED layout -- which already shows the context that makes a row readable
/// (owner 2026-10-11: "enable all relevant columns per view (beter more than too little)"; <see cref="DataViewDefaults"/>).
/// The extra columns' VALUES are read late, for the rows shown (or exported) only, by their keys (<see cref="IDataColumnViews"/>).
/// </summary>
public sealed class DataViewLayout
{
    public required string View { get; init; }
    public required IReadOnlyList<ViewColumn> Own { get; init; }
    public RowCiKey Ci { get; init; }
    public RowFindingKey Findings { get; init; }
    /// The CI fields the view's own columns already are (All CIs): ci.f.<field> of those is not offered or kept twice.
    public IReadOnlySet<string>? OwnCiFields { get; init; }
    /// The shipped layout (own + extra keys, in order); null = the own columns the view shows out of the box.
    public IReadOnlyList<string>? Shipped { get; init; }
    public IReadOnlyList<string> Layout { get; private set; } = Array.Empty<string>();
    public string Source { get; private set; } = ColumnLayout.FromDefault;
    public bool StoreReady { get; private set; }
    public DataColumnCatalog Catalog { get; private set; } = DataColumnCatalog.Empty;

    /// Whether the view offers anything beyond its own columns.
    public bool HasExtras => Ci != RowCiKey.None || Findings != RowFindingKey.None;

    /// The view's shipped layout: <see cref="Shipped"/> (its keys the view knows), else the own columns shown out of the box.
    public IReadOnlyList<string> DefaultLayout =>
        (Shipped ?? Own.Where(c => c.Shown).Select(c => c.Key).ToList()).Select(Known).Where(k => k is not null).Select(k => k!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    /// A key the layout may hold: one of the view's own columns (its spelling), or a well-formed extra column of a kind the
    /// view offers (a stored source property is kept even when this database's sample does not list it).
    public string? Known(string key)
    {
        if (Own.FirstOrDefault(c => c.Key.Equals(key, StringComparison.OrdinalIgnoreCase)) is { } own) return own.Key;
        // a name that was retired (never in the field catalog) is dropped from a stored layout, like any key the view does not know
        if (!DataColumnKeys.IsValid(key) || DataColumnKeys.IsRetired(key)) return null;
        if (DataColumnKeys.IsCi(key)) return Ci == RowCiKey.None || (OwnCiFields is not null && DataColumnKeys.FieldOf(key) is { } of && OwnCiFields.Contains(of)) ? null : key;
        if (DataColumnKeys.ContextOf(key) is { } c) return Findings == RowFindingKey.None || (c.AggregateOnly && Findings == RowFindingKey.FindingId) ? null : key;
        if (DataColumnKeys.IsFinding(key)) return Findings == RowFindingKey.FindingId ? key : null;
        return null;
    }

    /// The chosen own columns, in the chosen order.
    public IReadOnlyList<string> ChosenOwn => Layout.Where(k => !DataColumnKeys.IsExtra(k)).ToList();
    /// The chosen extra columns, in the chosen order.
    public IReadOnlyList<string> ChosenExtras => Layout.Where(DataColumnKeys.IsExtra).ToList();

    public string Label(string key) => Own.FirstOrDefault(c => c.Key.Equals(key, StringComparison.OrdinalIgnoreCase))?.Label ?? DataColumnKeys.Label(key);

    /// Every extra column the view offers (the chooser's list and "Export all columns").
    public IReadOnlyList<string> OfferedExtras => Catalog.Offered(Ci, Findings, OwnCiFields);

    /// <summary>
    /// Every extra column "Export all columns" writes: everything on offer, then any extra column the view SHOWS that the
    /// offer does not list (a shipped or saved column whose CI field no sampled CI of this database carries -- the chooser
    /// lists it the same way). So the export with every column never lacks a column the person sees on the page.
    /// </summary>
    public IReadOnlyList<string> AllExtras
    {
        get
        {
            var offered = OfferedExtras;
            var known = new HashSet<string>(offered, StringComparer.Ordinal);
            return offered.Concat(Layout.Where(k => DataColumnKeys.IsExtra(k) && known.Add(k))).ToList();
        }
    }

    private const string StoredItemPrefix = "si.view.stored:";

    /// <summary>
    /// What is stored for a view and the signed-in person -- read ONCE per view and request (a page that restores its
    /// filters before it binds them, and a page with several tables under one view key, share the one keyed read). Never
    /// fails the page: a store that cannot be read answers "nothing stored".
    /// </summary>
    public static async Task<StoredLayouts> StoredAsync(HttpContext? http, string view, ILogger log, CancellationToken ct)
    {
        var none = new StoredLayouts(false, null, null);
        if (http is null) return none;
        var item = StoredItemPrefix + view;
        if (http.Items.TryGetValue(item, out var have) && have is StoredLayouts read) return read;
        var stored = none;
        if (http.RequestServices?.GetService<IColumnLayoutStore>() is { } store)
        {
            try { stored = await store.ReadAsync(view, http.User.ChangeName(), ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the column layouts of {View} could not be read; the standard columns are shown", view); }
        }
        http.Items[item] = stored;
        return stored;
    }

    /// <summary>
    /// For a page whose filters are its OWN address parameters (the Findings browser, the task lists, the Summary --
    /// <see cref="ViewState.Pages"/>): puts the person's remembered sort / filters into the request BEFORE the page binds
    /// them, exactly as a grid gets them -- only on a plain page view whose address names none (the address always wins).
    /// The read is the layout read of this request (<see cref="StoredAsync"/>): the tables use it again, no second one.
    /// True = the page now shows the remembered state.
    /// </summary>
    public static async Task<bool> RestoreAsync(HttpContext? http, string view, ILogger log, CancellationToken ct)
    {
        if (http is null) return false;
        ViewState.FromMenu(http);
        http.Items[ViewState.AddressViewItem] = view;
        // a post, an export, a fragment or an address that names a sort / filter: nothing would be put in -- the tables read the layout when they load
        if (!ViewState.CanApply(http, view)) return false;
        var stored = await StoredAsync(http, view, log, ct);
        if (!ViewState.Apply(http, stored.State, view)) return false;
        http.Items[ViewState.AppliedItem] = view;
        return true;
    }

    /// Reads the stored layouts of this view and the extra columns on offer. Never fails the page: a store or catalog that
    /// cannot be read leaves the shipped columns.
    public async Task<DataViewLayout> LoadAsync(HttpContext? http, ILogger log, CancellationToken ct)
    {
        // the menu's mark is read (and taken out of the request) before anything of the page reads its address
        OpenedFromMenu = http is not null && ViewState.FromMenu(http);
        // the extra columns on offer are read WHILE the stored layouts are: neither needs the other (the catalog touches
        // nothing of the request). It never fails the page.
        var catalog = HasExtras && http?.RequestServices.GetService<IDataColumnViews>() is { } views ? CatalogOrNoneAsync(views, log, ct) : null;
        var stored = await StoredAsync(http, View, log, ct);
        StoreReady = stored.Ready;
        (Layout, Source) = ColumnLayout.Resolve(DefaultLayout, stored.Tenant, stored.User, Known);
        // each person's own fine-tuning of the view, from the same read: the last sort / filters (put into the request when
        // the address names none -- the address always wins), the widths, the named layouts (ViewState)
        Stored = stored;
        ClientState = http?.Items.ContainsKey(ViewState.PageTablesItem) == true;
        // a page whose filters are its own address parameters had them restored before it bound them (RestoreAsync); a
        // grid reads its state from the request now
        var ownAddress = http is not null && http.Items.TryGetValue(ViewState.AddressViewItem, out var av) && av is string addressView
            && addressView.Equals(View, StringComparison.OrdinalIgnoreCase);
        AddressState = !ClientState || ownAddress;
        StateShown = ClientState
            ? ownAddress && http!.Items.TryGetValue(ViewState.AppliedItem, out var applied) && applied is string appliedView && appliedView.Equals(View, StringComparison.OrdinalIgnoreCase)
            : ViewState.Apply(http, stored.State, View);
        // the page now shows the remembered state: a save returns to an address that NAMES it (the menu's mark never
        // travels on, and without it a bare address would show the standard)
        if (StateShown && http is not null)
            ShownReturn = http.Request.Path + QueryString.Create(http.Request.Query.Where(kv => !kv.Key.Equals("handler", StringComparison.OrdinalIgnoreCase))).ToString();
        // the columns an Admin promoted on "New context available" join the default (shipped or tenant) layout; a person's
        // own layout stays as they saved it (IColumnPromotions: a tiny list, read at most once a minute)
        if (HasExtras && stored.Ready && Source != ColumnLayout.FromUser && http?.RequestServices.GetService<IColumnPromotions>() is { } promoted)
        {
            try
            {
                var add = (await promoted.ForAsync(View, ct)).Select(Known).Where(k => k is not null).Select(k => k!)
                    .Where(k => !Layout.Contains(k, StringComparer.OrdinalIgnoreCase)).ToList();
                if (add.Count > 0) Layout = Layout.Concat(add).Distinct(StringComparer.OrdinalIgnoreCase).Take(ColumnLayout.MaxColumns).ToList();
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the promoted columns of {View} could not be read; the layout is shown without them", View); }
        }
        if (catalog is not null && await catalog is { } read) Catalog = read;
        return this;
    }

    /// The catalog, or null when it could not be read (logged; the shipped columns stay). Never throws, also not for the
    /// request's own cancellation (the page's next read ends the request) -- so a task started early is never left faulted.
    private async Task<DataColumnCatalog?> CatalogOrNoneAsync(IDataColumnViews views, ILogger log, CancellationToken ct)
    {
        try { return await views.CatalogAsync(ct); }
        catch (OperationCanceledException) { return null; }
        catch (Exception ex) { log.LogWarning(ex, "the extra columns of {View} could not be listed", View); return null; }
    }

    /// The chooser (Pages/Shared/_ColumnChooser.cshtml): the view's own columns, then the extras per group.
    public ColumnChooser Chooser(string returnUrl, bool isAdmin)
    {
        var offered = OfferedExtras;
        var known = new HashSet<string>(offered, StringComparer.Ordinal);
        return new ColumnChooser
        {
            View = View,
            Choices = Own.Select(c => new ColumnChoice(c.Key, c.Label, c.Group ?? DataColumnKeys.GroupView, c.Description))
                .Concat(offered.Select(k => new ColumnChoice(k, DataColumnKeys.Label(k), DataColumnKeys.Group(k))))
                .Concat(Layout.Where(k => DataColumnKeys.IsExtra(k) && !known.Contains(k)).Select(k => new ColumnChoice(k, DataColumnKeys.Label(k), DataColumnKeys.Group(k))))
                .ToList(),
            Layout = Layout, Source = Source, StoreReady = StoreReady, Return = ReturnTo(returnUrl), IsAdmin = isAdmin,
            ExtrasPending = HasExtras && Catalog.Pending,
            MoreReady = Stored.More, State = Stored.State, ClientState = ClientState, AddressState = AddressState, Widths = Stored.Widths, Named = Stored.Named, ActiveId = Stored.ActiveId, ActiveChanged = Stored.ActiveChanged,
        };
    }

    /// What is stored for this view and this person (the one read of <see cref="LoadAsync"/>): their sort / filters, widths, named layouts.
    public StoredLayouts Stored { get; private set; } = new(false, null, null);
    /// The page shows the person's remembered sort / filters (the address named none).
    public bool StateShown { get; private set; }
    /// The page's address with the remembered state named in it (set while <see cref="StateShown"/>): where a save returns.
    public string? ShownReturn { get; private set; }

    /// Where a save returns: the page's own address without the menu's mark -- and, while the page shows the remembered
    /// state and that address does not name it, the address that does (so the person sees after the save what they saw before).
    public string ReturnTo(string returnUrl)
    {
        var back = ViewState.WithoutMarker(returnUrl);
        if (ShownReturn is not null && !ViewState.NamesState(back, View)) back = ShownReturn;
        // a table sorted in the browser gets its remembered sort back from the page's script, which looks for the mark
        return ClientState && OpenedFromMenu ? ViewState.WithMarker(back) : back;
    }

    /// The view was opened from the menu (its link carried the mark).
    public bool OpenedFromMenu { get; private set; }
    /// The view's table is sorted and filtered in the browser (a page table): its state is restored there.
    public bool ClientState { get; private set; }
    /// The view's sort / filters are in the address: a grid, or a page table whose page restores its own filters
    /// (<see cref="RestoreAsync"/>) -- then both hold: the filters in the address, each table's own sort in the browser.
    public bool AddressState { get; private set; } = true;
    /// What the columns shown are, in words (the exports say it): the named layout in use, else own / tenant default / standard.
    public string SourceWords => ColumnChooser.SourceWords(Source, Stored.ActiveId is { } id ? Stored.Named.FirstOrDefault(n => n.Id == id) : null, Stored.ActiveChanged);

    /// <summary>
    /// The values of the <paramref name="columns"/> (extra keys) for some rows (their CI key, finding id, CVE). Empty when
    /// nothing extra is asked for. A read failure is logged and leaves the cells empty -- the page is shown.
    /// </summary>
    public async Task<DataColumnCells> CellsAsync(HttpContext? http, ILogger log, IReadOnlyCollection<string> columns, IEnumerable<RowRef> rows,
        string? collectionId, CancellationToken ct)
    {
        var cells = new DataColumnCells();
        var wanted = columns.Where(DataColumnKeys.IsExtra).ToList();
        if (wanted.Count == 0 || http?.RequestServices.GetService<IDataColumnViews>() is not { } views) return cells;
        var refs = rows.ToList();
        try
        {
            if (Ci != RowCiKey.None && wanted.Any(DataColumnKeys.IsCi))
            {
                var keys = refs.Select(r => r.Ci).Where(k => !string.IsNullOrEmpty(k)).Select(k => k!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                if (keys.Count > 0) foreach (var (k, v) in await views.CiCellsAsync(Ci, keys, wanted, ct)) cells.ByCi[k] = v;
            }
            if (collectionId is not null && wanted.Any(DataColumnKeys.IsFinding))
            {
                if (Findings == RowFindingKey.FindingId)
                {
                    var ids = refs.Where(r => r.Finding is not null).Select(r => r.Finding!.Value).Distinct().ToList();
                    if (ids.Count > 0) foreach (var (k, v) in await views.FindingCellsAsync(collectionId, ids, wanted, ct)) cells.ByFinding[k] = v;
                }
                else if (Findings is RowFindingKey.Cve or RowFindingKey.Issue)
                {
                    var cves = refs.Select(r => r.Cve).Where(c => !string.IsNullOrEmpty(c)).Select(c => c!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                    if (cves.Count > 0) foreach (var (k, v) in await views.CveCellsAsync(collectionId, cves, wanted, ct, Findings == RowFindingKey.Issue)) cells.ByCve[k] = v;
                }
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the extra columns of {View} could not be read; they are shown empty", View);
        }
        return cells;
    }

    /// A row's cell of an extra column.
    public static object? Cell(DataColumnCells cells, string column, RowRef row) =>
        cells.Get(column, row.Ci, row.Finding, row.Cve);

    /// A row's finding id as a number (null when it has none).
    public static long? FindingId(object? v) => v switch
    {
        null => null,
        long l => l,
        int i => i,
        string s => long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null,
        IConvertible c => Convert.ToInt64(c, CultureInfo.InvariantCulture),
        _ => null,
    };

    /// An extra cell as Excel holds it (numbers stay numbers, true / false booleans, text cut at Excel's cell limit).
    public static object? Excel(object? v) => v switch
    {
        null => null,
        double or bool => v,
        string s => s.Length == 0 ? null : s.Length > 32_000 ? s[..32_000] : s,
        _ => DataColumnKeys.Text(v),
    };

    /// An extra cell as text (screen and CSV).
    public static string Text(object? v) => v switch
    {
        null => "",
        bool b => b ? "yes" : "no",
        _ => DataColumnKeys.Text(v),
    };
}
