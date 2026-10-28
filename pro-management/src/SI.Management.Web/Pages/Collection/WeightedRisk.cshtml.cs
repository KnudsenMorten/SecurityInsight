using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Collection;
using SI.Management.Web.Export;

namespace SI.Management.Web.Pages.Collection;

/// <summary>
/// RISKS > WEIGHTED RISK SCORE (#360). Three tabs over one collection:
/// <list type="bullet">
/// <item><b>By service</b> (default): the CMDB business services, the most critical (as the CMDB defines it) first, then
/// the highest weighted total -- or sorted by weighted risk alone; or the dimension turned around (asset -> its services).
/// A row expands in place to its assets (or services) and opens them; the assets no CMDB service claims are a group of
/// their own, linked to the correlation page's "not in the CMDB".</item>
/// <item><b>Pivot</b>: a builder -- fields to rows / columns / filters, measures to values, by drag and drop or the
/// buttons -- answered in SQL from a fixed list of fields (<see cref="PivotSql"/>); sorted on any column, exported,
/// saved as a named view (personal; an Admin may share one).</item>
/// <item><b>Score distribution</b>: the spread of weighted scores and every CI's weighted total (the page as it was).</item>
/// </list>
/// </summary>
public sealed class WeightedRiskModel(ICollectionViews views, ILogger<WeightedRiskModel> log) : RiskPageModel(views, log, weighted: true)
{
    public const string TabService = "service";
    public const string TabPivot = "pivot";
    public const string TabDistribution = "distribution";
    public const string ByAssetValue = "asset";

    [BindProperty(SupportsGet = true)] public string? Tab { get; set; }
    /// "asset" = the dimension turned around (asset -> its services); anything else = service -> its assets.
    [BindProperty(SupportsGet = true)] public string? By { get; set; }
    /// The service drilled into (its assets).
    [BindProperty(SupportsGet = true)] public string? Svc { get; set; }
    /// The asset drilled into (its services).
    [BindProperty(SupportsGet = true)] public string? Ci { get; set; }
    /// A saved pivot view to open.
    [BindProperty(SupportsGet = true)] public long? View { get; set; }

    public override string PagePath => "/Collection/WeightedRisk";
    public override string Heading => Svc is not null ? (Service?.ServiceName ?? Svc) : Ci is not null ? "Services of " + Ci : "Weighted risk score";
    public override string Lede => CurrentTab switch
    {
        TabPivot => "Build your own view of the weighted risk: drag fields to Rows, Columns or Filters and measures to Values (or use the buttons), sort on any column, export it, save it as a named view.",
        TabDistribution => "The spread of weighted scores over the findings, and every CI's weighted total, highest and average -- the order to work in.",
        _ when Svc is not null => "The assets of this service in the collection, the highest weighted total first. Open an asset for its findings.",
        _ when Ci is not null => "The CMDB services this asset is in, the most critical first. Open a service for its assets.",
        _ => "The weighted risk score per CMDB business service: the services the CMDB rates most critical first, then the most weighted risk. The weighted score is the risk score times the risk model's weights. A service opens its assets, an asset its findings. An asset in more than one service counts under each of them.",
    };
    public override string ExportName => CurrentTab == TabService ? (Svc is not null ? "service-assets" : Ci is not null ? "asset-services" : AssetFirst ? "weighted-by-asset" : "weighted-by-service") : "weighted-risk";

    public string CurrentTab => Tab is TabPivot or TabDistribution ? Tab : TabService;
    public bool AssetFirst => string.Equals(By, ByAssetValue, StringComparison.OrdinalIgnoreCase);
    public CmdbState Cmdb { get; private set; } = CmdbState.None;
    public ServicesState? State { get; private set; }
    public ServiceRow? Service { get; private set; }
    /// The assets no CMDB service claims (the no-service group), when the collection has any.
    public ServiceRow? NoService { get; private set; }
    /// The service tab is shown per asset instead: a department-scoped user (the service totals span every department).
    public bool ScopedFallback { get; private set; }

    public override IEnumerable<(string Key, string Value)> ExtraState()
    {
        if (CurrentTab != TabService) yield return ("tab", CurrentTab);
        if (AssetFirst) yield return ("by", ByAssetValue);
        if (Svc is not null) yield return ("svc", Svc);
        if (Ci is not null) yield return ("ci", Ci);
    }

    /// A link to a tab of this page for the current collection.
    public string TabLink(string tab) => ViewLink(PagePath, ("tab", tab == TabService ? null : tab));

    /// The sort toggle: "Service criticality" (criticality, then weighted risk) or "Weighted risk".
    public bool SortedByCriticality => Grid?.State.Sort == "ServiceOrder";
    public string SortLink(bool byCriticality) => Link(("sort", byCriticality ? "ServiceOrder" : "WeightedRisk"), ("dir", byCriticality ? "asc" : "desc"));
    /// The group toggle: service -> asset, or asset -> service (drill-downs left).
    public string GroupLink(bool assetFirst) => ViewLink(PagePath, ("by", assetFirst ? ByAssetValue : null));

    /// The correlation page's "not in the CMDB" figure for this collection.
    public string NotInCmdbLink => ViewLink("/Collection/Correlation", ("f.CmdbState", "si-only")) + "#" + CorrelationModel.DrillAnchor;

    protected override bool DepartmentScopeSafe => true;

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (Svc is not null) Svc = CollectionViewSql.ServiceKey(Svc);
        if (Ci is not null) Ci = ProDataFilters.AssetKey(Ci) ?? throw new ArgumentException("an asset key is required");
        await LoadCmdbAsync(ct);
        if (CurrentTab == TabDistribution) return await base.PrepareAsync(forExport, ct);
        // #855: the pivot counts the CI lifecycle chosen (the stored cube carries it as a key) -- active by default
        if (CurrentTab == TabPivot) { LifecycleOffered = true; if (!forExport) await LoadPivotAsync(ct); return null; }

        // the service totals are pre-computed over every department: a department-scoped user gets their CIs instead
        if (Visibility is not null)
        {
            ScopedFallback = true;
            Notice ??= "The totals per service cover every department, so they are not shown to an account limited to departments. Below: your departments' CIs by weighted risk. The Pivot tab groups your departments' findings by service.";
            // the department's own findings grouped live (the pre-computed per-CI rows span every department)
            return new GridPlan(CollectionViewSql.AssetRiskLive, new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId }, Current.Version,
                new Dictionary<string, IReadOnlyList<string>> { ["AssetKind"] = Kinds, ["Tier"] = TierValues }, "TotalWeighted", true);
        }

        var s = await Views.ServicesStateAsync(Current!, ct); State = s.Data; Queries.Add(QueryInfo.From(s, "Services in this collection"));
        if (State.DerivedAt is null)
            Notice ??= "This collection's services are computed by the data sync after each load, and have not been computed for this collection yet. They fill in after the next data sync.";
        var scope = Current!.Version + "|svc@" + State.Version + "|" + Cmdb.Version;
        var crit = new Dictionary<string, IReadOnlyList<string>> { ["Criticality"] = Criticalities, ["Tier"] = TierValues, ["AssetKind"] = Kinds };
        if (Svc is not null)
        {
            if (!forExport) { var one = await Views.ServiceAsync(Current, Svc, ct); Service = one.Data; Queries.Add(QueryInfo.From(one, "This service")); }
            return new GridPlan(WeightedServiceSql.ServiceAssets, new Dictionary<string, object?> { ["CollectionId"] = Current.CollectionId, ["Service"] = Svc }, scope, crit);
        }
        if (Ci is not null)
            return new GridPlan(WeightedServiceSql.AssetServices(Cmdb.HasCmdb), new Dictionary<string, object?> { ["CollectionId"] = Current.CollectionId, ["AssetKey"] = Ci }, scope, crit);
        if (!forExport && !AssetFirst)
        {
            var none = await Views.ServiceAsync(Current, CollectionViewSql.NoServiceKey, ct); NoService = none.Data; Queries.Add(QueryInfo.From(none, "Assets in no CMDB service"));
        }
        return new GridPlan(AssetFirst ? WeightedServiceSql.ByAsset(Cmdb.HasCmdb) : WeightedServiceSql.ByService(Cmdb.HasCmdb),
            new Dictionary<string, object?> { ["CollectionId"] = Current.CollectionId }, scope, crit);
    }

    /// The criticality words the filter offers (the CMDB's own values are counted when the filter opens).
    public static readonly IReadOnlyList<string> Criticalities = ["Critical", "High", "Medium", "Low"];

    private async Task LoadCmdbAsync(CancellationToken ct)
    {
        try { var c = await Views.CmdbStateAsync(ct); Cmdb = c.Data; if (c.Query.Length > 0) Queries.Add(QueryInfo.From(c, "The CMDB")); }
        catch (Exception ex) when (ex is not OperationCanceledException and not ArgumentException) { Log.LogWarning(ex, "CMDB state"); Cmdb = CmdbState.None; }
    }

    /// Why the services carry no criticality yet, in words (null = they do).
    public string? CmdbHint => Cmdb.HasCriticality ? null
        : !Cmdb.HasCmdb || Cmdb.Services == 0 ? "Import your CMDB to see services ordered by how critical they are: until then every service reads \"not set\" and the order is the weighted risk alone."
        : "Your CMDB has services but none with a criticality: set Critical, High, Medium or Low on them (on the CMDB page, or in the CMDB you import) to order the services by it.";

    // ---- the grid's cells ------------------------------------------------------------------------------------------

    public override string CellText(GridColumn c, IReadOnlyDictionary<string, object?> row, bool csv = false) =>
        c.Key == "Criticality" && !ScopedFallback && Cell(row, "Criticality") is null ? (csv ? "" : WeightedServiceSql.NotSet) : base.CellText(c, row, csv);

    public override string? CellTone(string column, IReadOnlyDictionary<string, object?> row) =>
        column == "Criticality" ? WeightedServiceSql.Tone(Cell(row, "Criticality")) : null;

    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row)
    {
        string? Svc(string key) => Cell(row, key) is { } k ? ViewLink(PagePath, ("svc", k)) : null;
        string? Asset(string key) => Cell(row, key) is { } k ? ViewLink("/Collection/Asset", ("key", k)) : null;
        return (ExpandPlan ?? Plan)?.Spec.Name switch
        {
            "svccrit" => column switch { "ServiceName" or "Assets" => Svc("ServiceKey"), "TopAssetName" => Asset("TopAssetKey"), _ => null },
            "assetsvc" => column switch { "AssetName" or "Findings" => Asset("AssetKey"), "Assets" => Cell(row, "AssetKey") is { } k ? ViewLink(PagePath, ("by", ByAssetValue), ("ci", k)) : null, _ => null },
            "svcassetw" => column is "AssetName" or "Findings" ? Asset("AssetKey") : null,
            "assetsvcs" => column is "ServiceName" or "Assets" ? Svc("ServiceKey") : null,
            "assetrisk" => column == "AssetName" ? Asset("AssetKey") : null,
            _ => null,
        };
    }

    public override string? RowExpand(IReadOnlyDictionary<string, object?> row) => Plan?.Spec.Name switch
    {
        "svccrit" => Cell(row, "ServiceKey") is { } k ? ExpandLink(("svc", k)) : null,
        "assetsvc" => Cell(row, "AssetKey") is { } a ? ExpandLink(("ci", a)) : null,
        _ => null,
    };

    private string ExpandLink((string Key, string Value) what) =>
        PagePath + "?handler=Expand&c=" + Uri.EscapeDataString(Current?.CollectionId ?? "") + "&" + what.Key + "=" + Uri.EscapeDataString(what.Value);

    // ---- the inline expansion: a service's assets / an asset's services -------------------------------------------

    public GridPlan? ExpandPlan { get; private set; }
    public GridPage? ExpandPage { get; private set; }
    public const int ExpandRows = 25;

    /// The first <see cref="ExpandRows"/> assets of a service (or services of an asset) as an HTML fragment, with a link to
    /// all of them. Read-only, under the same rules as the page.
    public async Task<IActionResult> OnGetExpandAsync(CancellationToken ct)
    {
        try
        {
            if (!await LoadCollectionAsync(ct) || !await LoadVisibilityAsync(ct)) return NotFound(Error ?? Notice ?? "no collection");
            if (Visibility is not null) return StatusCode(StatusCodes.Status403Forbidden, "not shown to an account limited to departments");
            if (Svc is null && Ci is null) return BadRequest("a service or an asset is required");
            Tab = null;
            var plan = await PrepareAsync(true, ct);
            if (plan is null) return NotFound();
            ExpandPlan = plan;
            ExpandPage = (await Views.GridAsync(new GridQuery(plan.Spec, plan.Parameters, plan.Scope, new GridRequest { Size = ExpandRows }), ct)).Data;
            return Partial("_WeightedExpand", this);
        }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        catch (ViewTimeoutException) { return StatusCode(StatusCodes.Status504GatewayTimeout, "This took too long: open the service instead."); }
    }

    /// The link that opens the whole drill-down the expansion previews.
    public string ExpandAllLink => Svc is not null ? ViewLink(PagePath, ("svc", Svc)) : ViewLink(PagePath, ("by", ByAssetValue), ("ci", Ci));

    // ---- the pivot -----------------------------------------------------------------------------------------------

    public PivotRequest? Pivot { get; private set; }
    public PivotTable? PivotResult { get; private set; }
    public string? PivotNote { get; private set; }
    public IReadOnlyList<PivotSql.Field> PivotFields { get; private set; } = PivotSql.Fields;
    /// The values each filter field takes (label, findings), the most findings first.
    public Dictionary<string, IReadOnlyList<(string Value, double Findings)>> PivotChoices { get; } = new(StringComparer.Ordinal);
    public IReadOnlyList<PivotView> SavedViews { get; private set; } = [];
    public bool SavedReady { get; private set; }
    public PivotView? OpenView { get; private set; }
    public bool CanShare => User.IsAdmin();
    public string Me => AuditScope.ActorOf(User);

    private static readonly string[] PivotKeys = ["pr", "pc", "pv", "pf", "psort", "pdir"];

    /// The pivot the URL asks for (null = none: the default, or the saved view named by "view").
    private PivotRequest? FromQuery()
    {
        var q = Request.Query;
        if (!PivotKeys.Any(q.ContainsKey) && !q.Keys.Any(k => k.StartsWith("pfv.", StringComparison.Ordinal))) return null;
        var allowed = PivotFields.Select(f => f.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var dropped = new List<string>();
        IEnumerable<string?> Fields(string k) => q[k].Where(v =>
        {
            if (string.IsNullOrWhiteSpace(v) || PivotSql.FieldOf(v) is null || allowed.Contains(v!)) return true;   // unknown keys are REFUSED by Normalize
            dropped.Add(PivotSql.FieldOf(v)!.Label); return false;
        });
        // an unknown key is passed on (and REFUSED by Normalize); a known one this database cannot answer is left out
        var fv = q.Keys.Where(k => k.StartsWith("pfv.", StringComparison.Ordinal) && (PivotSql.FieldOf(k[4..]) is null || allowed.Contains(k[4..])))
            .ToDictionary(k => k[4..], k => (IReadOnlyList<string>)q[k].Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v!).ToList());
        var dir = (string?)q["pdir"];
        var r = PivotSql.Normalize(Fields("pr"), Fields("pc"), q["pv"], Fields("pf"), fv, q["psort"], dir is "desc" ? true : dir is "asc" ? false : null);
        if (dropped.Count > 0) PivotNote = "Not available in this database, so left out: " + string.Join(", ", dropped.Distinct()) + ".";
        return r;
    }

    private async Task LoadPivotAsync(CancellationToken ct)
    {
        PivotFields = PivotSql.Available(Cmdb);
        await LoadSavedAsync(ct);
        try { Pivot = FromQuery(); }
        catch (ArgumentException ex) { Error = "The pivot is not valid: " + ex.Message; return; }
        if (Pivot is null && View is { } id)
        {
            OpenView = SavedViews.FirstOrDefault(v => v.Id == id);
            if (OpenView is null) Notice ??= "That saved view is not there any more (or it is someone else's). The default pivot is shown.";
            else
            {
                try { Pivot = PivotRequest.Parse(OpenView.State); }
                catch (ArgumentException ex) { Notice ??= "That saved view can no longer be read (" + ex.Message + "). The default pivot is shown."; }
            }
        }
        Pivot ??= PivotSql.Default(PivotFields.Any(f => f.Key == "service"));
        if (Pivot.FieldsUsed.Any(k => PivotFields.All(f => f.Key != k))) { Pivot = PivotSql.Default(false); PivotNote ??= "That view uses a field this database cannot answer yet; the default pivot is shown."; }
        try
        {
            var res = await Views.PivotAsync(Current!, Pivot, Cmdb.HasCmdb, Visibility, PivotSql.MaxGroups, ct, Lifecycle);
            Queries.Insert(0, QueryInfo.From(res, "Pivot"));
            PivotResult = PivotSql.Shape(Pivot, res.Data);
            foreach (var f in Pivot.Filters.Concat(Pivot.FilterValues.Keys).Distinct())
            {
                var ch = await Views.PivotAsync(Current!, PivotSql.ChoicesRequest(f), Cmdb.HasCmdb, Visibility, PivotSql.MaxChoices, ct, Lifecycle);
                var shaped = PivotSql.Shape(PivotSql.ChoicesRequest(f), ch.Data, PivotSql.MaxChoices);
                PivotChoices[f] = shaped.Lines.Select(l => (l.Labels[0], l.Total.Length > 0 ? l.Total[0] ?? 0 : 0)).ToList();
            }
        }
        // #812: the pivot reads the collection's stored cube; a field it does not carry, or a cube not written yet, is said
        catch (PivotNotStoredException ex) { PivotResult = null; PivotChoices.Clear(); PivotNote = ex.Message; }
        catch (NotSupportedException) { PivotNote = "The pivot is not available in this installation."; }
        catch (ViewTimeoutException ex)
        {
            Log.LogWarning(ex, "pivot timed out");
            Error = TimeoutText(ex.Limit, null).Replace("a column filter, a search, or fewer rows per page", "a filter, or fewer fields", StringComparison.Ordinal);
        }
    }

    private async Task LoadSavedAsync(CancellationToken ct)
    {
        var store = HttpContext?.RequestServices.GetService(typeof(IPivotViewStore)) as IPivotViewStore;
        if (store is null) return;
        try { SavedReady = await store.ReadyAsync(ct); if (SavedReady) SavedViews = await store.ListAsync(Me, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { Log.LogWarning(ex, "saved pivot views"); SavedReady = false; }
    }

    /// The page with a pivot (null = the current one), for the builder's buttons and every sort link.
    public string PivotLink(PivotRequest? q = null) =>
        PagePath + "?" + (Current is null ? "" : "c=" + Uri.EscapeDataString(Current.CollectionId) + "&") + "tab=pivot&" + (q ?? Pivot)!.QueryString()
        // #855: the lifecycle chosen travels with every pivot link (the default has no parameter)
        + (Lifecycle.QueryValue is { } lv ? "&" + SI.Management.Core.ProData.LifecycleFilter.Parameter + "=" + Uri.EscapeDataString(lv) : "");

    public string? MoveLink(string key, string zone) => Pivot is { } q && PivotEdit.CanMove(q, key, zone) ? PivotLink(PivotEdit.Move(q, key, zone)) : null;
    public string? ShiftLink(string key, int by) => Pivot is { } q && PivotEdit.Shift(q, key, by) is { } s ? PivotLink(s) : null;
    public string PivotSortLink(string sort) => PivotLink(PivotEdit.SortBy(Pivot!, sort));

    public static string ZoneLabel(string zone) => zone switch
    {
        PivotEdit.Rows => "Rows", PivotEdit.Columns => "Columns", PivotEdit.Filters => "Filters", PivotEdit.Values => "Values", _ => "Fields",
    };

    public static string KeyLabel(string key) => PivotSql.FieldOf(key)?.Label ?? PivotSql.MeasureOf(key)?.Label ?? key;

    /// A measure's value on screen: scores whole, counts as counts, in the viewer's format.
    public static string Measure(string measure, double? v) =>
        v is null ? "" : PivotSql.MeasureOf(measure) is { Score: false } ? ScoreFormat.Count((long)Math.Round(v.Value)) : ScoreFormat.Whole(v);

    // the pivot as one flat sheet: the row fields, then per column value each measure, then each measure's total
    private (List<string> Headers, List<List<object?>> Rows) Flat()
    {
        var t = PivotResult!; var q = t.Request;
        var headers = q.Rows.Select(KeyLabel).ToList();
        foreach (var c in t.ColumnKeys) foreach (var m in q.Values) headers.Add(KeyLabel(m) + " · " + c);
        foreach (var m in q.Values) headers.Add(q.Columns.Count > 0 ? KeyLabel(m) + " (total)" : KeyLabel(m));
        var rows = new List<List<object?>>();
        foreach (var l in t.Lines)
        {
            var r = l.Labels.Cast<object?>().ToList();
            foreach (var c in t.ColumnKeys) for (var i = 0; i < q.Values.Count; i++) r.Add(l.Cells.TryGetValue(c, out var v) ? v[i] : null);
            for (var i = 0; i < q.Values.Count; i++) r.Add(l.Total.Length > i ? l.Total[i] : null);
            rows.Add(r);
        }
        var total = q.Rows.Select((_, i) => (object?)(i == 0 ? "Total" : "")).ToList();
        foreach (var c in t.ColumnKeys) for (var i = 0; i < q.Values.Count; i++) total.Add(t.ColumnTotals.TryGetValue(c, out var v) ? v[i] : null);
        for (var i = 0; i < q.Values.Count; i++) total.Add(t.Grand.Length > i ? t.Grand[i] : null);
        rows.Add(total);
        return (headers, rows);
    }

    private async Task<IActionResult?> PivotForExportAsync(CancellationToken ct)
    {
        if (!await LoadCollectionAsync(ct) || !await LoadVisibilityAsync(ct)) return NotFound(Error ?? Notice ?? "nothing to export");
        Tab = TabPivot;
        await LoadCmdbAsync(ct);
        await LoadPivotAsync(ct);
        if (Error is not null) return BadRequest(Error);
        return PivotResult is null ? NotFound(PivotNote ?? "nothing to export") : null;
    }

    /// The pivot as an Excel workbook (the cells as numbers).
    [Audited("data.export.download")]
    public async Task<IActionResult> OnGetPivotXlsxAsync(CancellationToken ct)
    {
        IActionResult? refused;
        try { refused = await PivotForExportAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (refused is not null) return refused;
        var (headers, rows) = Flat();
        var q = PivotResult!.Request;
        return await ExcelExport.FileAsync("weighted-pivot", Current?.CollectionId, (x, info) =>
        {
            info.Collection = Current?.CollectionId;
            info.Add("Collection time (UTC)", Current?.CollectionTime);
            info.Add("Rows", string.Join(", ", q.Rows.Select(KeyLabel)));
            info.Add("Columns", string.Join(", ", q.Columns.Select(KeyLabel)));
            info.Add("Values", string.Join(", ", q.Values.Select(KeyLabel)));
            foreach (var (k, v) in q.FilterValues) info.Add("Filter: " + KeyLabel(k), string.Join(" | ", v));
            if (OpenView is not null) info.Add("Saved view", OpenView.Name);
            if (PivotResult.ColumnsCut) info.Notes.Add($"Only the {PivotSql.MaxColumnValues} largest column values are columns; the totals count every value.");
            if (PivotResult.Truncated) info.Notes.Add("The pivot was cut at " + ScoreFormat.Count(PivotSql.MaxGroups) + " groups: add a filter for the rest.");
            x.Sheet(info, "Pivot", headers, rows.Select(r => (IReadOnlyList<object?>)r));
            return Task.CompletedTask;
        }, ct);
    }

    /// The pivot as CSV: UTF-8 with a BOM, numbers invariant, formula-looking cells defused.
    [Audited("data.export.download")]
    public async Task<IActionResult> OnGetPivotCsvAsync(CancellationToken ct)
    {
        IActionResult? refused;
        try { refused = await PivotForExportAsync(ct); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        if (refused is not null) return refused;
        var (headers, rows) = Flat();
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", headers.Select(Findings.IndexModel.Csv)));
        foreach (var r in rows)
            sb.AppendLine(string.Join(",", r.Select(v => Findings.IndexModel.Csv(v switch { null => "", double d => ScoreFormat.Invariant(d), _ => Convert.ToString(v, CultureInfo.InvariantCulture) ?? "" }))));
        var name = "weighted-pivot" + (Current is null ? "" : "-" + Current.CollectionId) + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + "Z.csv";
        return File(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray(), "text/csv; charset=utf-8", name);
    }

    // ---- saved views -------------------------------------------------------------------------------------------------

    /// Saves the pivot (the form's State, read back through the whitelist) under a name; an Admin may share it.
    [Audited("view.pivot.save")]
    public async Task<IActionResult> OnPostSaveViewAsync([FromForm] string? name, [FromForm] string? state, [FromForm] bool shared, CancellationToken ct)
    {
        if (HttpContext.RequestServices.GetService(typeof(IPivotViewStore)) is not IPivotViewStore store) return NotFound();
        if (PivotView.NameProblem(name) is { } problem) return Back(problem);
        PivotRequest q;
        try { q = PivotRequest.Parse(state ?? ""); }
        catch (ArgumentException ex) { return BadRequest("The pivot is not valid: " + ex.Message); }
        var text = q.QueryString();
        if (text.Length > PivotView.MaxState) return Back("This pivot is too large to save: remove some filter values.");
        if (!await store.ReadyAsync(ct)) return Back("Saved views need the latest database setup (setup\\Import-SIProSettings.ps1 -CreateSchema): run it once, then save again.");
        var id = await store.SaveAsync(name!.Trim(), Me, shared && User.IsAdmin(), text, ct);
        TempData["toast"] = "Saved: " + name.Trim() + (shared && User.IsAdmin() ? " (shared with every reader)" : "");
        return Redirect(PagePath + "?" + (C is null ? "" : "c=" + Uri.EscapeDataString(C) + "&") + "tab=pivot&view=" + id.ToString(CultureInfo.InvariantCulture));

        IActionResult Back(string why)
        {
            TempData["toast"] = why;
            return Redirect(PagePath + "?" + (C is null ? "" : "c=" + Uri.EscapeDataString(C) + "&") + "tab=pivot&" + (TryParse(state)?.QueryString() ?? ""));
        }
    }

    private static PivotRequest? TryParse(string? state) { try { return PivotRequest.Parse(state ?? ""); } catch (ArgumentException) { return null; } }

    /// Removes a saved view: your own, or (an Admin) a shared one.
    [Audited("view.pivot.remove")]
    public async Task<IActionResult> OnPostRemoveViewAsync([FromForm] long id, CancellationToken ct)
    {
        if (HttpContext.RequestServices.GetService(typeof(IPivotViewStore)) is not IPivotViewStore store) return NotFound();
        var ok = await store.RemoveAsync(id, Me, User.IsAdmin(), ct);
        TempData["toast"] = ok ? "Removed the saved view." : "That view was already removed, or it is not yours to remove.";
        return Redirect(PagePath + "?" + (C is null ? "" : "c=" + Uri.EscapeDataString(C) + "&") + "tab=pivot");
    }
}
