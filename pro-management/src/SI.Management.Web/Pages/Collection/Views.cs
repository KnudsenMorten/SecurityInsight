using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Navigation;

namespace SI.Management.Web.Pages.Collection;

/// One aggregate table on a view: rows with the grid link each value opens.
/// NumericValue: the value column is itself a number stored invariant (a score bucket, "2254" / "12.5") -- shown in the
/// viewer's format, never as the raw invariant text.
public sealed record FacetTable(string Id, string Title, string ValueHeader, IReadOnlyList<(FacetRow Row, string? Href)> Rows,
    bool Weighted = false, bool ByScore = false, string? Hint = null, string? Empty = null, bool NumericValue = false);

/// The views whose grid is the collection's finding rows (raw rows, the facet views, the findings of one CI).
public abstract class FindingRowsPageModel : CollectionPageModel
{
    protected FindingRowsPageModel(ICollectionViews views, ILogger log) : base(views, log) { }

    /// #272: the grid lists the collection's finding rows -- the shared action bar sits under it (a named view's grouped rows
    /// are not findings: a group opens its rows on Raw rows, where they are acted on).
    public override string? ActionSource => NamedView is null ? SI.Management.Web.Actions.SelectionSources.Rows : null;

    /// #812: the #636 grouping this page's grid shows (null = the finding rows).
    public SummaryGroupViewSql.View? NamedView { get; private set; }

    /// <summary>
    /// #812 (owner rule "SI views: SQL-cached + indexed columns"): Risk rating, MITRE ATT&amp;CK, Compliance and CVSS are NAMED
    /// VIEWS over the #636 groupings the data sync writes once per collection (sidata.SummaryGroup) -- they never count and
    /// sort every finding row of the collection per request. A collection whose grouped rows do not hold the grouping yet is
    /// never read: the page says it is being prepared (no grid, no counts, no export). An account limited to departments gets
    /// its departments' finding rows (the groupings span every department; the restricted read is narrow).
    /// </summary>
    protected async Task<GridPlan?> GroupingPlanAsync(SummaryGroupViewSql.View view, CancellationToken ct)
    {
        if (Visibility is not null)
        {
            Notice ??= "The groupings of this view cover every department, so an account limited to departments sees its departments' finding rows instead.";
            return RowsPlan(defaultSort: view == SummaryGroupViewSql.Cvss ? "Cvss" : null);
        }
        var s = await Views.GroupingStateAsync(Current!, view.GroupingId, ct);
        if (s.Query.Length > 0) Queries.Add(QueryInfo.From(s, "The collection's grouped rows"));
        if (!s.Data.Built) { Notice = GroupingPreparingText(s.Data.Schema); return null; }
        NamedView = view;
        return new GridPlan(SummaryGroupViewSql.Spec(view), new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId, ["GroupingId"] = view.GroupingId },
            Current.Version + "|grp@" + s.Data.Version, new Dictionary<string, IReadOnlyList<string>> { ["Tier"] = TierValues });
    }

    /// What a named view says while the collection's grouped rows are not written (Schema = the database has the tables).
    public static string GroupingPreparingText(bool schema) => schema
        ? "This collection's groups are being prepared: the data sync works them out once per collection (from every finding) right after the collection is loaded. They appear when the data sync that is running now, or the next one, has finished -- open this page again in a few minutes. Meanwhile every finding of the collection is on Raw rows."
        : "The groups of this view need the database update that adds their tables: the updater adds them (setup\\Initialize-SIDataSql.ps1 -- it only adds), and the next data sync fills them. Meanwhile every finding of the collection is on Raw rows.";

    protected GridPlan RowsPlan(string? assetKey = null, string? defaultSort = null) => new(
        CollectionViewSql.Rows,
        new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId, ["AssetKey"] = assetKey is null ? null : ProDataFilters.AssetKey(assetKey) },
        Current.Version,
        new Dictionary<string, IReadOnlyList<string>>
        {
            ["Tier"] = TierValues, ["AssetKind"] = Kinds, ["Severity"] = Options(Facets.Severity), ["RiskRating"] = Options(Facets.Rating),
            ["SecurityDomain"] = Options(Facets.Domain), ["ReportName"] = Options(Facets.Report), ["MitreTactics"] = Options(Facets.Tactic),
            ["ComplianceTags"] = Options(Facets.Tag), ["HasExploit"] = Flags,
        },
        defaultSort);

    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) => column switch
    {
        // a group opens its findings on Raw rows, filtered on its value
        "Key" when NamedView is { RowsColumn: { } rc } nv && Cell(row, "Key") is { Length: > 0 } key && (nv.RowsValue is null ? key : nv.RowsValue(key)) is { } fv =>
            ViewLink("/Collection/Rows", ("f." + rc, fv)),
        "Title" => Cell(row, "FindingId") is { } id ? "/Findings/Detail?c=" + Uri.EscapeDataString(Current!.CollectionId) + "&id=" + Uri.EscapeDataString(id) : null,
        "AssetName" => Cell(row, "AssetKey") is { } k ? ViewLink("/Collection/Asset", ("key", k)) : null,
        _ => null,
    };

    /// #589: the affected software is read for every row: a generic title ("Update vulnerable software") then names it.
    protected override IReadOnlyList<string> AlwaysFilled => NamedView is null ? [DataColumnKeys.Software] : Array.Empty<string>();

    public override string CellText(GridColumn c, IReadOnlyDictionary<string, object?> row, bool csv = false) =>
        NamedView is not null && c.Key == "Key" ? SI.Management.Web.Summary.SummaryGroups.KeyText(NamedView.GroupingId, 0, Cell(row, "Key") ?? "")
        : c.Key == "Title" && SoftwareTitle(Cell(row, "Title"), row) is { } t ? t : base.CellText(c, row, csv);

    public override object? CellExcel(GridColumn c, IReadOnlyDictionary<string, object?> row) =>
        c.Key == "Title" && SoftwareTitle(Cell(row, "Title"), row) is { } t ? t : base.CellExcel(c, row);

    /// The generic Risk Analysis titles that say nothing about WHAT (owner 2026-10-11: "i cannot see what app it is related").
    public static readonly IReadOnlySet<string> GenericTitles = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Update vulnerable software" };

    /// "Update chrome 128.0 (google)" for a generic title whose row knows its software; null = the title as it is.
    public static string? SoftwareTitle(string? title, IReadOnlyDictionary<string, object?> row) =>
        title is not null && GenericTitles.Contains(title) && row.TryGetValue(DataColumnKeys.Software, out var sw) && SI.Management.Web.Columns.DataViewLayout.Text(sw) is { Length: > 0 } s
            ? "Update " + s : null;

    /// A facet as a table whose values filter the grid on <paramref name="column"/>.
    /// <paramref name="rowsPage"/>: a value opens Raw rows filtered on it (#812: the named views' grid is the grouping, not the rows).
    protected FacetTable Table(string id, string facet, string title, string header, string? column, Func<FacetRow, string?>? filterValue = null,
        IEnumerable<FacetRow>? order = null, bool weighted = false, string? hint = null, string? empty = null, bool rowsPage = false) =>
        new(id, title, header, (order ?? Facet(facet).OrderByDescending(r => r.Findings)).Select(r =>
        {
            var v = filterValue is null ? (r.Value == "(none)" ? null : r.Value) : filterValue(r);
            return (r, column is null || v is null ? null : (string?)(rowsPage ? ViewLink("/Collection/Rows", ("f." + column, v)) : Link(("f." + column, v))));
        }).ToList(), weighted, false, hint, empty ?? (Current?.DerivedAt is null ? "Computed by the next data sync." : "This collection has none."));
}

// ---- (1) Security recommendations > Detailed: one recommendation on one asset (#636; was "Raw rows" and "Findings") -------

public sealed class RowsModel(ICollectionViews views, ILogger<RowsModel> log) : FindingRowsPageModel(views, log)
{
    /// The named view in use (?view=...), the remediation whose findings are shown (?fix=..., from Remediations).
    [BindProperty(SupportsGet = true)] public string? View { get; set; }
    [BindProperty(SupportsGet = true)] public string? Fix { get; set; }

    public override string PagePath => "/Collection/Rows";
    public override string Heading => "Detailed";
    public override string Lede => "One security recommendation on one asset per row -- every finding of the collection, as the Risk Analysis Detailed workbook has them: sort on any column, filter each column (Domain > Category > Subcategory, risk rating, severity, tier, department ...), search, select rows and act on them, and export. The views at the top open the most used selections.";
    public override bool CompactFrame => true;

    public NamedView? CurrentView => NamedViews.Find(PagePath, View);

    public override IEnumerable<(string Key, string Value)> ExtraState()
    {
        if (CurrentView is { } v) yield return ("view", v.Id);
        if (!string.IsNullOrWhiteSpace(Fix)) yield return ("fix", Fix!);
    }

    public override ViewPicker? Picker => new(PagePath, Current?.CollectionId, NamedViews.Visible(PagePath, Hidden), CurrentView, FacetLinks());

    /// The views an Admin hid for everyone (SI_Pro_HiddenViews), read with the page.
    private IReadOnlyList<string> Hidden { get; set; } = [];

    /// The counts per value of the view's facet, each narrowing the table to that value.
    private IReadOnlyList<(string Label, long Findings, string Href)>? FacetLinks()
    {
        if (CurrentView is not { Facet: { } facet, FacetColumn: { } col } || FacetRows.Count == 0) return null;
        // #855: the stored counts are of active CIs -- shown only while the grid counts the default (active)
        if (LifecycleOffered && !Lifecycle.IsActiveOnly) return null;
        var rows = Facet(facet).Where(r => r.Value != "(none)");
        rows = facet == Facets.Rating ? rows.OrderBy(r => Array.IndexOf(RatingOrder, r.Value) is var i and >= 0 ? i : 9)
            : facet == Facets.Cvss ? rows.OrderBy(r => Array.IndexOf(CvssOrder, r.Value) is var j and >= 0 ? j : 9)
            : rows.OrderByDescending(r => r.Findings);
        return rows.Take(30).Select(r => (r.Value, (long)r.Findings, Link(("f." + col, facet == Facets.Cvss ? CvssRange(r.Value) ?? r.Value : r.Value)))).ToList();
    }

    public static readonly string[] RatingOrder = ["Critical", "High", "Moderate", "Low"];
    public static readonly string[] CvssOrder = ["Critical (9.0-10)", "High (7.0-8.9)", "Medium (4.0-6.9)", "Low (0.1-3.9)", "None (0)"];

    /// A CVSS band as the range the grid filters on.
    public static string? CvssRange(string band) => band switch
    {
        "Critical (9.0-10)" => "9..10", "High (7.0-8.9)" => "7..8.99", "Medium (4.0-6.9)" => "4..6.99", "Low (0.1-3.9)" => "0.1..3.99", "None (0)" => "0..0", _ => null,
    };

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (!forExport)
        {
            await LoadFacetsAsync(ct);
            Hidden = await HiddenViewsAsync(HttpContext, ct);
        }
        var plan = RowsPlan(defaultSort: CurrentView?.Sort);
        if (!string.IsNullOrWhiteSpace(Fix))
        {
            var p = new Dictionary<string, object?>(plan.Parameters) { ["Fix"] = ProDataFilters.Text(Fix) };
            p.Remove("AssetKey");
            // #864: the fix's own rows, never the collection's opening page off the index (CollectionViewSql.RowsOfFix)
            if (CollectionViewSql.RowsOfFix.Keyset is not null || !CollectionViewSql.RowsOfFix.Source.Contains("f.RemediationKey = @Fix", StringComparison.Ordinal))
                throw new InvalidOperationException("the rows of one fix are not narrowed to that fix (CollectionViewSql.RowsOfFix)");
            plan = plan with { Spec = CollectionViewSql.RowsOfFix, Parameters = p, Scope = plan.Scope + "|fix" };
        }
        return plan;
    }

    /// <summary>
    /// #864: what a remediation's link shows, said on the page: exactly the findings the fix closes -- the person's remembered
    /// filters are not put on it (ViewState.SetKeys); a filter or search chosen on the page is named, with the way back to
    /// all of the fix's findings. Null without a fix.
    /// </summary>
    public string? FixNote
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Fix)) return null;
            var count = Grid is { } g ? $"the {Fmt.Int(g.Total)} finding{(g.Total == 1 ? "" : "s")}" : "the findings";
            var text = $"Showing {count} of this collection that the fix \"{Fix}\" closes. Your remembered filters for this view are not applied to a fix's link.";
            var added = new List<string>();
            if (Grid?.State is { } st)
            {
                foreach (var f in st.Filters)
                {
                    var label = CollectionViewSql.Rows.Column(f.Key)?.Label ?? f.Key;
                    var what = f.Values.Count > 0 ? string.Join(" or ", f.Values) : f.Text ?? (f.Low is not null || f.High is not null ? $"{f.Low}..{f.High}" : "set");
                    added.Add($"{label} = {what}");
                }
                if (!string.IsNullOrWhiteSpace(st.Search)) added.Add($"search \"{st.Search}\"");
            }
            if (added.Count > 0) text += " Filters added on this page narrow it: " + string.Join("; ", added) + ".";
            return text;
        }
    }

    /// The fix's link without any filter, search or page: all of the fix's findings again.
    public string FixAllHref => "/Collection/Rows?c=" + Uri.EscapeDataString(Current?.CollectionId ?? "") + "&fix=" + Uri.EscapeDataString(Fix ?? "");

    /// The shipped views an Admin hid (the setting SI_Pro_HiddenViews); none when it cannot be read.
    public static async Task<IReadOnlyList<string>> HiddenViewsAsync(HttpContext? ctx, CancellationToken ct)
    {
        if (ctx?.RequestServices.GetService(typeof(SI.Management.Web.Settings.ISettingsStoreReader)) is not SI.Management.Web.Settings.ISettingsStoreReader reader) return [];
        try
        {
            var (rows, _) = await reader.ReadSettingsAsync(ct);
            return NamedViews.ParseHidden(rows.FirstOrDefault(r => string.Equals(r.Name, NamedViews.HiddenSetting, StringComparison.OrdinalIgnoreCase))?.ValueJson);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return []; }
    }
}
// ---- (2) correlated view: one row per CI ---------------------------------------------------------------------------

/// <summary>
/// 2026-10-19 (a large customer, 1,117,524 finding rows / ~3,000 CIs): the per-CI grids -- Assets (CIs) at risk, Risk score and
/// the weighted score's distribution -- read the PRE-COMPUTED per-CI rows (sidata.AssetRiskSummary, written by the data sync
/// once per collection), never a GROUP BY over every finding per request. A collection without its rows is not grouped here:
/// the page says they are being prepared. An account limited to departments reads its own findings grouped live (the
/// pre-computed rows span every department) -- the restriction narrows the finding rows themselves.
/// </summary>
public static class AssetSummaryPlan
{
    /// The grid the page reads and its cache scope, or (null, notice) while the collection's rows are not written.
    public static async Task<(GridSpec? Spec, string Scope, string? Notice)> ChooseAsync(ICollectionViews views, ViewCollection current, bool departmentScoped,
        GridSpec summary, GridSpec live, List<QueryInfo> queries, CancellationToken ct)
    {
        if (departmentScoped) return (live, current.Version + "|live", null);
        var s = await views.AssetSummaryStateAsync(current, ct);
        if (s.Query.Length > 0) queries.Add(QueryInfo.From(s, "The collection's per-CI rows"));
        if (!s.Data.Built) return (null, current.Version, PreparingText(s.Data.Schema));
        return (summary, current.Version + "|cis@" + s.Data.Version, s.Data.StaleFor(current) ? StaleText : null);
    }

    /// What the page says while the collection's per-CI rows are not written (Schema = the database has the tables).
    public static string PreparingText(bool schema) => schema
        ? "This collection's list of CIs is being prepared: the data sync works it out once per collection (one row per CI, from every finding) right after the collection is loaded. It appears when the data sync that is running now, or the next one, has finished -- open this page again in a few minutes. Meanwhile every finding of the collection is on Raw rows."
        : "The list of CIs needs the database update that adds its tables: the updater adds them (setup\\Initialize-SIDataSql.ps1 -- it only adds), and the next data sync fills them. Meanwhile every finding of the collection is on Raw rows.";

    public const string StaleText = "This collection's view data was worked out again after its per-CI rows were written; the data sync brings the rows up to date on its next run. Until then the numbers are those of the earlier rows.";
}

/// The column chooser and "Export all columns" of this view: AssetsColumns.cs.
public sealed partial class AssetsModel(ICollectionViews views, ILogger<AssetsModel> log) : CollectionPageModel(views, log)
{
    public override string PagePath => "/Collection/Assets";
    public override string Heading => "Assets (CIs) at risk";
    public override string Lede => "One row per CI (configuration item): the asset as one thing, however many systems see it. \"Linked objects\" counts the objects the correlation joined into it -- one server seen in Defender XDR, as an Azure VM and in Active Directory is one CI with three linked objects. Open a CI for everything known about it.";
    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        var (spec, scope, notice) = await AssetSummaryPlan.ChooseAsync(Views, Current!, Visibility is not null, CollectionViewSql.Assets, CollectionViewSql.AssetsLive, Queries, ct);
        if (spec is null) { Notice = notice; return null; }
        Notice ??= notice;
        return new GridPlan(spec, new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId }, scope,
            new Dictionary<string, IReadOnlyList<string>> { ["AssetKind"] = Kinds, ["Tier"] = TierValues, ["KeySource"] = new[] { "ledger", "asset" } });
    }
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) =>
        column == "AssetName" && Cell(row, "AssetKey") is { } k ? ViewLink("/Collection/Asset", ("key", k)) : null;
}

// ---- (3) one CI -----------------------------------------------------------------------------------------------------

public sealed class AssetModel(ICollectionViews views, ILogger<AssetModel> log) : FindingRowsPageModel(views, log)
{
    [BindProperty(SupportsGet = true)] public string? Key { get; set; }
    public AssetInfo? Asset { get; private set; }
    public IReadOnlyList<IdentifierRow> Identifiers { get; private set; } = Array.Empty<IdentifierRow>();
    public IReadOnlyList<RecommendationRow> Recommendations { get; private set; } = Array.Empty<RecommendationRow>();
    public IReadOnlyList<AssetHistoryRow> History { get; private set; } = Array.Empty<AssetHistoryRow>();
    public IReadOnlyList<AssetVulnRow> VulnItems { get; private set; } = Array.Empty<AssetVulnRow>();
    public string? VulnNote { get; private set; }
    /// The CI's property bag per source system ({ "MDE": {...}, "Azure": {...} }), flattened one level for display.
    public IReadOnlyList<(string Source, IReadOnlyList<(string Name, string Value)> Props)> Properties { get; private set; } = Array.Empty<(string, IReadOnlyList<(string, string)>)>();

    public override string PagePath => "/Collection/Asset";
    public override string Heading => Asset is null ? "Asset (CI)" : (Asset.AssetName.Length > 0 ? Asset.AssetName : Asset.AssetKey);
    public override string Lede => "Everything known about one CI: what it is, every object and identifier linked to it, the properties each source system reported, its findings in this collection, its history and its vulnerabilities in the close-loop.";
    public override string ExportName => "ci";
    /// #855: one CI's findings are shown whatever its lifecycle (no lifecycle choice on this page).
    protected override bool CountsLifecycle => false;
    public override IEnumerable<(string Key, string Value)> ExtraState() => Key is null ? Array.Empty<(string, string)>() : new[] { ("key", Key) };

    /// A DETAIL page, reached by clicking a CI anywhere (grids, the correlation drilldowns, the header search), never from
    /// the menu. Opened without a CI it has nothing to show, so it goes to the list of CIs (Correlated assets) instead.
    public override async Task OnPageHandlerExecutionAsync(Microsoft.AspNetCore.Mvc.Filters.PageHandlerExecutingContext context, Microsoft.AspNetCore.Mvc.Filters.PageHandlerExecutionDelegate next)
    {
        if (string.IsNullOrEmpty(context.HandlerMethod?.Name) && HttpMethods.IsGet(Request.Method) && string.IsNullOrWhiteSpace(Key))
        {
            context.Result = RedirectToPage("/Collection/Assets");
            return;
        }
        await next();
    }

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(Key)) { Notice = "Pick a CI: open one from the correlated view or from any asset name in a grid."; return null; }
        var key = ProDataFilters.AssetKey(Key)!;
        if (!forExport)
        {
            var a = await Views.AssetAsync(key, ct); Asset = a.Data; Queries.Add(QueryInfo.From(a, "The CI"));
            if (Asset is null) Notice = "This CI is not in the Pro database's current CI list (it may have passed retention). Its findings in this collection are shown below.";
            var ids = await Views.IdentifiersAsync(key, ct); Identifiers = ids.Data; Queries.Add(QueryInfo.From(ids, "Linked objects and identifiers"));
            var rec = await Views.RecommendationsAsync(Current!, key, ct); Recommendations = rec.Data; Queries.Add(QueryInfo.From(rec, "Defender for Cloud recommendations"));
            var h = await Views.AssetHistoryAsync(key, ct); History = h.Data; Queries.Add(QueryInfo.From(h, "History"));
            try { var v = await Views.AssetVulnItemsAsync(key, ct); VulnItems = v.Data; Queries.Add(QueryInfo.From(v, "In the vulnerability close-loop")); }
            catch (Exception ex) when (ex is not OperationCanceledException and not ArgumentException)
            {
                Log.LogWarning(ex, "close-loop items of a CI");
                VulnNote = "The vulnerability close-loop could not be read" + SchemaHint(ex.Message);
            }
            Properties = ParseProperties(Asset?.PropertiesJson);
            await LoadEvidenceAsync(key, ct);
            await LoadMetadataAsync(key, ct);
            await LoadFacetsAsync(ct);
        }
        return RowsPlan(key);
    }

    public static IReadOnlyList<(string Source, IReadOnlyList<(string Name, string Value)> Props)> ParseProperties(string? json)
    {
        var list = new List<(string, IReadOnlyList<(string, string)>)>();
        if (string.IsNullOrWhiteSpace(json)) return list;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object) return list;
            var loose = new List<(string, string)>();
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (p.Value.ValueKind == System.Text.Json.JsonValueKind.Object)
                    list.Add((p.Name, p.Value.EnumerateObject().Take(200).Select(x => (x.Name, Scalar(x.Value))).ToList()));
                else loose.Add((p.Name, Scalar(p.Value)));
            }
            if (loose.Count > 0) list.Insert(0, ("SecurityInsight", loose));
        }
        catch (System.Text.Json.JsonException) { list.Add(("(unreadable)", new[] { ("PropertiesJson", json.Length > 400 ? json[..400] + "…" : json) })); }
        return list;
    }

    private static string Scalar(System.Text.Json.JsonElement e) => e.ValueKind switch
    {
        System.Text.Json.JsonValueKind.String => e.GetString() ?? "",
        System.Text.Json.JsonValueKind.Null => "",
        _ => e.GetRawText() is { Length: > 400 } t ? t[..400] + "…" : e.GetRawText(),
    };

    /// The linked objects: one per member asset (SI_AssetId), and the other identifiers grouped by type.
    public IReadOnlyList<IdentifierRow> Members => Identifiers.Where(i => i.Type == "SI_AssetId").ToList();
    public IReadOnlyList<IGrouping<string, IdentifierRow>> IdentifierGroups => Identifiers.Where(i => i.Type != "SI_AssetId").GroupBy(i => i.Type).ToList();

    // ---- the correlation evidence: why these source records are this one CI ------------------------------------------

    public IReadOnlyList<EvidenceRow> Evidence { get; private set; } = Array.Empty<EvidenceRow>();
    public IReadOnlyList<IdHistoryRow> IdHistory { get; private set; } = Array.Empty<IdHistoryRow>();
    public IReadOnlyList<ConflictRow> Conflicts { get; private set; } = Array.Empty<ConflictRow>();
    public CorrelationCi? Correlation { get; private set; }
    /// Why the Evidence section is empty (not computed yet / not readable); null = it has rows.
    public string? EvidenceNote { get; private set; }

    /// The newest load that carried evidence for this CI: its rows are the CURRENT evidence.
    public long CurrentLoad => Evidence.Count == 0 ? 0 : Evidence.Max(e => e.LastLoadId);
    public IReadOnlyList<IGrouping<string, EvidenceRow>> CurrentEvidence =>
        Evidence.Where(e => e.LastLoadId == CurrentLoad).GroupBy(e => e.Source).OrderBy(g => g.Key, StringComparer.Ordinal).ToList();
    public IReadOnlyList<EvidenceRow> EarlierEvidence => Evidence.Where(e => e.LastLoadId != CurrentLoad).ToList();
    public long ConflictLoad => Conflicts.Count == 0 ? 0 : Math.Max(CurrentLoad, Conflicts.Max(c => c.LastLoadId));
    public IReadOnlyList<ConflictRow> CurrentConflicts => Conflicts.Where(c => c.LastLoadId == ConflictLoad && c.Field != "Possible duplicate").ToList();
    public IReadOnlyList<ConflictRow> PossibleDuplicates => Conflicts.Where(c => c.LastLoadId == ConflictLoad && c.Field == "Possible duplicate").ToList();
    public IReadOnlyList<ConflictRow> ResolvedConflicts => Conflicts.Where(c => c.LastLoadId != ConflictLoad).ToList();
    /// The id-history rows that say THIS key now lives in another CI.
    public IReadOnlyList<IdHistoryRow> MovedTo => IdHistory.Where(h => h.PreviousId == Key && h.AssetKey != Key).ToList();

    private async Task LoadEvidenceAsync(string key, CancellationToken ct)
    {
        var cv = HttpContext?.RequestServices.GetService(typeof(ICorrelationViews)) as ICorrelationViews;
        if (cv is null) { EvidenceNote = "The correlation evidence is not available in this installation."; return; }
        try
        {
            var e = await cv.EvidenceAsync(key, ct); Evidence = e.Data; Queries.Add(QueryInfo.From(e, "Evidence"));
            var h = await cv.IdHistoryAsync(key, ct); IdHistory = h.Data; Queries.Add(QueryInfo.From(h, "Id history"));
            var c = await cv.ConflictsAsync(key, ct); Conflicts = c.Data; Queries.Add(QueryInfo.From(c, "Conflicts"));
            var l = await cv.LatestAsync(key, ct); Correlation = l.Data; Queries.Add(QueryInfo.From(l, "Correlation"));
            if (Evidence.Count == 0) EvidenceNote = "No correlation evidence is recorded for this CI yet. The data sync computes it with each load, from the next load on.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not ArgumentException)
        {
            Log.LogWarning(ex, "correlation evidence of a CI");
            EvidenceNote = "No correlation evidence is recorded for this CI yet. The data sync computes it with each load, from the next load on."
                + (ex.Message.Contains("Invalid", StringComparison.OrdinalIgnoreCase) ? " The database does not have the evidence tables yet: run setup\\Initialize-SIDataSql.ps1 again (it only adds)." : "");
        }
    }

    // ---- the full asset metadata (#301 / #408): every property each source reports, when the install runs 'full' ------

    /// The level and what the data sync last stored (null = not readable).
    public AssetMetadataState? MetadataState { get; private set; }
    /// This CI's objects, newest per (source, record, item), Entra first.
    public IReadOnlyList<AssetMetadataObject> Metadata { get; private set; } = Array.Empty<AssetMetadataObject>();
    /// #412: every kept snapshot of each (source, record, item), newest first, with what changed between them.
    public IReadOnlyList<AssetMetadataHistory> MetadataHistory { get; private set; } = Array.Empty<AssetMetadataHistory>();
    /// The history of one current object (its snapshots, newest first); null when there is none.
    public AssetMetadataHistory? HistoryOf(AssetMetadataObject o) =>
        MetadataHistory.FirstOrDefault(h => h.SourceSystem == o.SourceSystem && h.MemberAssetId == o.MemberAssetId && h.ItemName == o.ItemName);
    /// Is the full level on (see <see cref="AssetMetadataText.IsFull"/>)?
    public bool MetadataFull { get; private set; }
    /// Why the section shows no metadata: off, not stored yet, not readable; null = it has objects to show.
    public string? MetadataNote { get; private set; }
    public const string MetadataOffNote = "Full asset metadata is off -- Settings > Asset properties. SecurityInsight keeps the security profile only (what it needs for risk).";

    /// The objects grouped per source system, in the page's order.
    public IReadOnlyList<IGrouping<string, AssetMetadataObject>> MetadataBySource =>
        Metadata.GroupBy(o => o.SourceSystem).OrderBy(g => AssetMetadataText.Rank(g.Key)).ThenBy(g => g.Key, StringComparer.Ordinal).ToList();

    private async Task LoadMetadataAsync(string key, CancellationToken ct)
    {
        var mv = HttpContext?.RequestServices.GetService(typeof(IAssetMetadataViews)) as IAssetMetadataViews;
        if (mv is null) { MetadataNote = "Full asset metadata is not available in this installation."; return; }
        try
        {
            var s = await mv.StateAsync(ct); MetadataState = s.Data; Queries.Add(QueryInfo.From(s, "Full metadata: the level and the last load"));
            var o = await mv.ForAssetAsync(key, ct); Queries.Add(QueryInfo.From(o, "Full metadata of this CI"));
            MetadataFull = AssetMetadataText.IsFull(s.Data, o.Data.Count > 0);
            if (!MetadataFull) { MetadataNote = MetadataOffNote; return; }
            Metadata = AssetMetadataText.Newest(o.Data);
            MetadataHistory = AssetMetadataText.History(o.Data);
            if (Metadata.Count == 0)
                MetadataNote = s.Data.LastSnapshot is { } at
                    ? "No full metadata is stored for this CI. The last collection (" + Fmt.When(at) + ") had none for it -- a source that does not report this asset, or an asset seen only in findings."
                    : "Full asset metadata is on, but nothing is stored yet. It appears after the next profiler run (endpoint, identity, azure) and the data sync after it.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not ArgumentException)
        {
            Log.LogWarning(ex, "full asset metadata of a CI");
            MetadataNote = ex.Message.Contains("Invalid object name", StringComparison.OrdinalIgnoreCase)
                ? "The database does not have the full asset metadata table yet: run setup\\Initialize-SIDataSql.ps1 again (it only adds)."
                : "The full asset metadata could not be read" + SchemaHint(ex.Message) + ".";
        }
    }

    /// A number from a source object in the viewer's format (1,024 / 1.024); the raw text when it is not one.
    public static string NumberText(string? raw)
    {
        if (raw is null) return "";
        if (long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var l)) return Fmt.Int(l);
        if (double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) && double.IsFinite(d)) return d.ToString("#,##0.###", SI.Management.Core.ProData.ScoreFormat.Culture);
        return raw;
    }

    /// The badge of a confidence: the same tone as the Correlation quality page (exact green, strong teal, weak amber).
    public static string ConfidenceClass(string c) => CorrelationGroups.ConfidenceTone(c).Css();
}

// ---- (4) vulnerabilities ----------------------------------------------------------------------------------------------

public sealed class VulnerabilitiesModel(ICollectionViews views, ILogger<VulnerabilitiesModel> log) : CollectionPageModel(views, log)
{
    public override string PagePath => "/Collection/Vulnerabilities";
    public override string Heading => "Vulnerabilities";
    public override string Lede => "One row per CVE in the collection, most critical first: severity, CVSS, a known exploit, how many assets have it and how critical they are, and how many items the vulnerability close-loop has open for it.";
    /// Whether this collection's one-row-per-CVE rows are written (null until read).
    public CveSummaryState? Summary { get; private set; }

    /// The page grids the PRE-COMPUTED per-CVE rows (sidata.CveSummary, written by the data sync once per collection) -- a
    /// large customer's 1.1 million finding rows grouped per request ran past the 90 s limit. A collection without its rows
    /// is never grouped here: the page says they are being prepared, and where every finding is meanwhile.
    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        var s = await Views.CveSummaryStateAsync(Current!, ct);
        Summary = s.Data;
        if (s.Query.Length > 0) Queries.Add(QueryInfo.From(s, "The collection's per-CVE rows"));
        if (!Summary.Built)
        {
            Notice = PreparingText(Summary.Schema);
            return null;
        }
        if (Summary.StaleFor(Current!))
            Notice ??= "This collection's view data was worked out again after its per-CVE rows were written; the data sync brings the rows up to date on its next run. Until then the counts are those of the earlier rows.";
        if (!forExport) await LoadFacetsAsync(ct);
        return new GridPlan(CollectionViewSql.Vulnerabilities, new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId }, Current.Version + "|live|cves@" + Summary.Version,
            new Dictionary<string, IReadOnlyList<string>> { ["Severity"] = Options(Facets.Severity), ["Tier"] = TierValues, ["HasExploit"] = Flags });
    }

    /// What the page says while the collection's per-CVE rows are not written (Schema = the database has the tables).
    public static string PreparingText(bool schema) => schema
        ? "This collection's list of vulnerabilities is being prepared: the data sync works it out once per collection (one row per CVE, from every finding) right after the collection is loaded. It appears when the data sync that is running now, or the next one, has finished -- open this page again in a few minutes. Meanwhile every finding of the collection is on Raw rows (filter the CVE column)."
        : "The list of vulnerabilities needs the database update that adds its tables: the updater adds them (setup\\Initialize-SIDataSql.ps1 -- it only adds), and the next data sync fills them. Meanwhile every finding of the collection is on Raw rows (filter the CVE column).";
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) =>
        column == "Cve" && Cell(row, "Cve") is { } cve ? ViewLink("/Collection/Rows", ("f.Cve", cve)) : null;

    /// #589: every CVE row reads its software (a distinct list over its findings), so its title names it -- never the
    /// generic "Update vulnerable software" alone.
    protected override IReadOnlyList<string> AlwaysFilled => [DataColumnKeys.Software];

    public override string CellText(GridColumn c, IReadOnlyDictionary<string, object?> row, bool csv = false) =>
        c.Key == "Title" && FindingRowsPageModel.SoftwareTitle(Cell(row, "Title"), row) is { } t ? t : base.CellText(c, row, csv);

    public override object? CellExcel(GridColumn c, IReadOnlyDictionary<string, object?> row) =>
        c.Key == "Title" && FindingRowsPageModel.SoftwareTitle(Cell(row, "Title"), row) is { } t ? t : base.CellExcel(c, row);
}

// ---- (5) + (6) risk score per CI ----------------------------------------------------------------------------------------

public abstract class RiskPageModel(ICollectionViews views, ILogger log, bool weighted) : CollectionPageModel(views, log)
{
    public bool Weighted { get; } = weighted;
    public FacetTable? Distribution { get; private set; }
    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (!forExport)
        {
            await LoadFacetsAsync(ct);
            var facet = Weighted ? Facets.Weighted : Facets.Score;
            var rows = Facet(facet).OrderByDescending(r => double.TryParse(r.Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : double.MinValue).ToList();
            var col = Weighted ? "RiskScoreWeighted" : "RiskScore";
            Distribution = new FacetTable("dist", Weighted ? "Weighted risk score: how the findings spread" : "Risk score: how the findings spread",
                Weighted ? "Weighted score" : "Risk score",
                rows.Select(r => (r, BucketRange(r.Value) is { } range ? (string?)ViewLink("/Collection/Rows", ("f." + col, range), ("sort", col), ("dir", "desc")) : null)).ToList(),
                Weighted: true, Hint: Weighted
                    ? "The weighted score is the risk score times the report's weight (the risk model): it is what ranks the work. A value opens its findings."
                    : "Risk score = consequence x probability, per finding. A value opens its findings.",
                Empty: Current?.DerivedAt is null ? "Computed by the next data sync." : "No scored finding in this collection.",
                NumericValue: true);
        }
        // the pre-computed per-CI rows (an account limited to departments: its own findings, grouped live) -- AssetSummaryPlan
        var (spec, scope, notice) = await AssetSummaryPlan.ChooseAsync(Views, Current!, Visibility is not null, CollectionViewSql.AssetRisk, CollectionViewSql.AssetRiskLive, Queries, ct);
        if (spec is null) { Notice = notice; return null; }
        Notice ??= notice;
        return new GridPlan(spec, new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId }, scope,
            new Dictionary<string, IReadOnlyList<string>> { ["AssetKind"] = Kinds, ["Tier"] = TierValues },
            Weighted ? "TotalWeighted" : "TotalRisk", true);
    }
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) =>
        column == "AssetName" && Cell(row, "AssetKey") is { } k ? ViewLink("/Collection/Asset", ("key", k)) : null;

    /// The score range a distribution value stands for: a risk score is rounded to one decimal (v +- 0.05), a weighted
    /// score is floored to a whole number (v .. v + 0.999).
    public string? BucketRange(string value)
    {
        if (!double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var v)) return null;
        string F(double d) => d.ToString("0.###", CultureInfo.InvariantCulture);
        return Weighted ? F(v) + ".." + F(v + 0.999) : F(v - 0.05) + ".." + F(v + 0.0499);
    }
}

public sealed class RiskScoreModel(ICollectionViews views, ILogger<RiskScoreModel> log) : RiskPageModel(views, log, weighted: false)
{
    public override string PagePath => "/Collection/RiskScore";
    public override string Heading => Explain ? "Risk score, explained" : "Asset risk score";
    public override string Lede => Explain ? ExplainLede
        : "Where the risk is: the spread of risk scores over the findings, and every CI's total, highest and average risk score -- the CIs carrying the most risk first.";
    public override string ExportName => Explain ? "riskscore-explained" : base.ExportName;

    // ---- #910 the explained view (?view=explain): one row per finding with how its score was made ----------------------

    /// The view of the page: none = per asset (the default), "explain" = per finding, explained.
    [BindProperty(SupportsGet = true)] public string? View { get; set; }
    public bool Explain => string.Equals(View, ExplainView, StringComparison.OrdinalIgnoreCase);
    public const string ExplainView = "explain";
    public string ViewHref(bool explain) => ViewLink(PagePath, ("view", explain ? ExplainView : null));
    public override IEnumerable<(string Key, string Value)> ExtraState() { if (Explain) yield return ("view", ExplainView); }

    public const string ExplainLede = "How each finding's risk score is made, highest first. The asset side (consequence) is the asset's base -- from its tier and class -- plus the points of every asset factor that applies (exposed to the internet, high machine risk, confidential data ...). The vulnerability side (probability) is the finding's base -- from its type and severity -- plus the points of every vulnerability factor that applies (exploit available, remote code execution, known exploited ...). Risk score = asset side x vulnerability side; the weighted score is the risk score times the weight your CMDB criticality and data sensitivity set.";

    /// The sentence above the grid when a row of the page comes from a collection made before each part was recorded.
    public const string DerivedText = "Some rows come from a collection made before each factor's points were recorded: their base is worked out as the side's score minus its factors' points and marked \"(derived)\", and their factors are listed without points. The next collection records every part.";

    /// A row of the page shown is worked out from an older collection (<see cref="DerivedText"/> is shown).
    public bool ExplainHasDerived => Explain && Grid is { } g && g.Rows.Any(r => RiskExplanation.Of(r).Derived);

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (!Explain) return await base.PrepareAsync(forExport, ct);
        // the filters' choices from the collection's pre-computed counts (as the finding rows have them); the page has no
        // distribution table of its own -- the per-asset view shows it
        if (!forExport) await LoadFacetsAsync(ct);
        return new GridPlan(RiskExplainSql.Grid, new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId }, Current.Version,
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["Tier"] = TierValues, ["Severity"] = Options(Facets.Severity), ["RiskRating"] = Options(Facets.Rating),
                ["SecurityDomain"] = Options(Facets.Domain), ["ReportName"] = Options(Facets.Report),
            },
            "RiskScore", true);
    }

    /// The explained rows show their own parts only: no CI or finding context columns are added to them.
    protected override RowCiKey RowCi(GridSpec s) => Explain ? RowCiKey.None : base.RowCi(s);
    protected override (RowFindingKey Kind, string? Column) RowFindings(GridSpec s) => Explain ? (RowFindingKey.None, null) : base.RowFindings(s);

    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) =>
        Explain && column == "Title" && Cell(row, "FindingId") is { } id ? "/Findings/Detail?c=" + Uri.EscapeDataString(Current!.CollectionId) + "&id=" + Uri.EscapeDataString(id)
        : base.CellLink(column, row);

    public override string CellText(GridColumn c, IReadOnlyDictionary<string, object?> row, bool csv = false) =>
        Explain && ExplainText(c.Key, row, csv) is { } t ? t : base.CellText(c, row, csv);

    public override object? CellExcel(GridColumn c, IReadOnlyDictionary<string, object?> row) =>
        Explain && ExplainText(c.Key, row, csv: true) is { } t ? t : base.CellExcel(c, row);

    /// The explained parts as text (null = a column shown as it is): on screen in the viewer's number format, in a CSV invariant.
    public static string? ExplainText(string column, IReadOnlyDictionary<string, object?> row, bool csv)
    {
        Func<double, string> num = csv ? ScoreFormat.Invariant : ScoreFormat.Number;
        return column switch
        {
            "AssetBase" => RiskExplanation.BaseText(RiskExplanation.Of(row).Asset, num),
            "AssetFactors" => RiskExplanation.FactorsText(RiskExplanation.Of(row).Asset, num),
            "AssetSide" => RiskExplanation.Of(row).Asset.Score is { } a ? num(a) : "",
            "VulnBase" => RiskExplanation.BaseText(RiskExplanation.Of(row).Vulnerability, num),
            "VulnFactors" => RiskExplanation.FactorsText(RiskExplanation.Of(row).Vulnerability, num),
            "VulnSide" => RiskExplanation.Of(row).Vulnerability.Score is { } v ? num(v) : "",
            "Weight" => RiskExplanation.Of(row).WeightText(num),
            "Formula" => RiskExplanation.Of(row).Formula(num),
            _ => null,
        };
    }
}

// (6) the weighted risk score: by CMDB service, the pivot builder and the score distribution -- WeightedRisk.cshtml.cs (#360)

// ---- (7) risk rating ----------------------------------------------------------------------------------------------------

public sealed class RiskRatingModel(ICollectionViews views, ILogger<RiskRatingModel> log) : FindingRowsPageModel(views, log)
{
    public static readonly string[] Order = ["Critical", "High", "Moderate", "Low", "(none)"];
    public FacetTable? Ratings { get; private set; }
    public override string PagePath => "/Collection/RiskRating";
    public override string Heading => "Risk rating";
    public override string Lede => "The findings grouped by risk rating -- Critical, High, Moderate, Low, banded on the risk score by your thresholds (shipped 50 / 30 / 15: Critical 50 and up, High 30+, Moderate 15+, Low below; an Admin sets them under Settings, Risk rating) -- with the rows of the rating you pick.";
    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (!forExport)
        {
            await LoadFacetsAsync(ct);
            Ratings = Table("ratings", Facets.Rating, "Findings per risk rating", "Rating", "RiskRating",
                order: Facet(Facets.Rating).OrderBy(r => Array.IndexOf(Order, r.Value) is var i and >= 0 ? i : 9), hint: "A rating opens its findings on Raw rows.", rowsPage: true);
        }
        // #812: the named view of the risk-rating grouping (sidata.SummaryGroup), never every finding row per request
        return await GroupingPlanAsync(SummaryGroupViewSql.RiskRating, ct);
    }
}

// ---- (8) MITRE -------------------------------------------------------------------------------------------------------------

public sealed class MitreModel(ICollectionViews views, ILogger<MitreModel> log) : FindingRowsPageModel(views, log)
{
    public FacetTable? Tactics { get; private set; }
    public FacetTable? Techniques { get; private set; }
    public override string PagePath => "/Collection/Mitre";
    public override string Heading => "MITRE ATT&CK";
    public override string Lede => "The findings by the MITRE ATT&CK tactics and techniques they enable: which stages of an attack this collection leaves open, and on how many CIs.";

    /// #812: the grid groups per tactic (default) or, with ?by=technique, per technique.
    [BindProperty(SupportsGet = true)] public string? By { get; set; }
    public bool ByTechnique => string.Equals(By, "technique", StringComparison.OrdinalIgnoreCase);
    public string ByLink(bool technique) => ViewLink(PagePath, ("by", technique ? "technique" : null));
    public override IEnumerable<(string Key, string Value)> ExtraState() { if (ByTechnique) yield return ("by", "technique"); }

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (!forExport)
        {
            await LoadFacetsAsync(ct);
            Tactics = Table("tactics", Facets.Tactic, "Tactics", "Tactic", "MitreTactics", hint: "A finding with several tactics counts under each. A tactic opens its findings on Raw rows.", rowsPage: true);
            Techniques = Table("techniques", Facets.Technique, "Techniques (top 30)", "Technique", "MitreTechniques",
                order: Facet(Facets.Technique).OrderByDescending(r => r.Findings).Take(30), rowsPage: true);
        }
        return await GroupingPlanAsync(ByTechnique ? SummaryGroupViewSql.MitreTechnique : SummaryGroupViewSql.MitreTactic, ct);
    }
}

// ---- (9) compliance ---------------------------------------------------------------------------------------------------------

public sealed class ComplianceModel(ICollectionViews views, ILogger<ComplianceModel> log) : FindingRowsPageModel(views, log)
{
    public FacetTable? Tags { get; private set; }
    public override string PagePath => "/Collection/Compliance";
    public override string Heading => "Compliance";
    public override string Lede => "The findings by the compliance tags and benchmarks they map to: which controls this collection fails, and on how many CIs.";
    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (!forExport)
        {
            await LoadFacetsAsync(ct);
            Tags = Table("tags", Facets.Tag, "Compliance tags", "Tag", "ComplianceTags", hint: "A finding with several tags counts under each. A tag opens its findings on Raw rows.", rowsPage: true);
        }
        return await GroupingPlanAsync(SummaryGroupViewSql.Compliance, ct);
    }
}

// ---- (10) CVSS ------------------------------------------------------------------------------------------------------------------

public sealed class CvssModel(ICollectionViews views, ILogger<CvssModel> log) : FindingRowsPageModel(views, log)
{
    public static readonly string[] Order = ["Critical (9.0-10)", "High (7.0-8.9)", "Medium (4.0-6.9)", "Low (0.1-3.9)", "None (0)", "(none)"];
    public FacetTable? Bands { get; private set; }
    public override string PagePath => "/Collection/Cvss";
    public override string Heading => "CVSS";
    public override string Lede => "The findings by CVSS score band (the CVSS qualitative ratings), and the rows with the highest CVSS first.";

    /// A band as the CVSS range the grid filters on.
    public static string? Range(string band) => SummaryGroupViewSql.CvssRange(band);

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (!forExport)
        {
            await LoadFacetsAsync(ct);
            Bands = Table("bands", Facets.Cvss, "Findings per CVSS band", "CVSS band", "Cvss", r => Range(r.Value),
                order: Facet(Facets.Cvss).OrderBy(r => Array.IndexOf(Order, r.Value) is var i and >= 0 ? i : 9),
                hint: "(none) = a finding without a CVSS score (most configuration findings). A band opens its findings on Raw rows, highest CVSS first.", rowsPage: true);
        }
        return await GroupingPlanAsync(SummaryGroupViewSql.Cvss, ct);
    }
}

// ---- (11) exclusions and exemptions ---------------------------------------------------------------------------------------

[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Views, Off = true)]
public sealed class ExclusionsModel(ICollectionViews views, ILogger<ExclusionsModel> log) : CollectionPageModel(views, log)
{
    public static readonly string[] States = ["in force", "expired before", "revoked before", "created later"];
    public IReadOnlyList<CountRow> StateCounts { get; private set; } = Array.Empty<CountRow>();
    public IReadOnlyList<ExclusionDocRow> Documents { get; private set; } = Array.Empty<ExclusionDocRow>();
    public string? DocNote { get; private set; }
    public override string PagePath => "/Collection/Exclusions";
    public override string Heading => "Excluded and exempted";
    public override string Lede => "What this collection left out on purpose: the exemptions in force when it was taken (and those that were not), and the Risk Analysis exclusion rules.";
    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        var at = DateTime.SpecifyKind(Current!.CollectionTime, DateTimeKind.Utc);
        if (!forExport)
        {
            var s = await Views.ExemptionStatesAsync(at, ct); StateCounts = s.Data; Queries.Add(QueryInfo.From(s, "Exemptions at the collection"));
            try { var d = await Views.ExclusionDocumentsAsync(ct); Documents = d.Data; Queries.Add(QueryInfo.From(d, "Risk Analysis exclusion rules")); }
            catch (Exception ex) when (ex is not OperationCanceledException and not ArgumentException) { Log.LogWarning(ex, "exclusion documents"); DocNote = "The exclusion rules could not be read" + SchemaHint(ex.Message); }
            await LoadFacetsAsync(ct);
        }
        return new GridPlan(CollectionViewSql.Exemptions, new Dictionary<string, object?> { ["At"] = at }, Current.Version + "|live",
            new Dictionary<string, IReadOnlyList<string>> { ["StateAtCollection"] = States, ["Scope"] = new[] { "finding", "issue", "asset" }, ["ReportName"] = Options(Facets.Report) },
            DefaultFilters: new Dictionary<string, string> { ["StateAtCollection"] = "in force" });
    }
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) =>
        column == "AssetName" && Cell(row, "AssetKey") is { } k ? ViewLink("/Collection/Asset", ("key", k)) : null;
}

// ---- (12) lifecycle ------------------------------------------------------------------------------------------------------------

[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Views, Off = true)]
public sealed class LifecycleModel(ICollectionViews views, ILogger<LifecycleModel> log) : CollectionPageModel(views, log)
{
    public IReadOnlyList<CountRow> EventCounts { get; private set; } = Array.Empty<CountRow>();
    public IReadOnlyList<LifecycleDay> Days { get; private set; } = Array.Empty<LifecycleDay>();
    public string? CloseLoopNote { get; private set; }
    /// #865: why the close-loop's numbers may be empty (SI's own SQL target off / in test mode / not run / failed), or null.
    public string? CloseLoopStatus { get; private set; }
    public override string PagePath => "/Collection/Lifecycle";
    // a tab of Changes & trends > Vulnerabilities over time; the findings added / no longer reported are on What changed
    // (the same counts, row by row) -- not repeated here (operator 2026-10-05: the menu overlapped)
    public override string Heading => "Vulnerabilities per collection";
    public override string Lede => "What the vulnerability close-loop opened, closed and reopened between the collection you pick and the next one, vulnerability by vulnerability.";
    public long Count(IReadOnlyList<CountRow> rows, string group, string key) => rows.Where(r => r.Group == group && r.Key == key).Sum(r => r.N);

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        var (from, to) = Window;
        if (!forExport)
        {
            try
            {
                var e = await Views.EventCountsAsync(from, to, ct); EventCounts = e.Data; Queries.Add(QueryInfo.From(e, "The close-loop: events"));
                var day = DateOnly.FromDateTime(Current!.CollectionTime);
                var d = await Views.LifecycleDaysAsync(day.AddDays(-13), DateOnly.FromDateTime(to), ct); Days = d.Data; Queries.Add(QueryInfo.From(d, "The close-loop: per day"));
                CloseLoopStatus = await SI.Management.Web.Changes.OwnSqlTargetStatus.ReadAsync(HttpContext?.RequestServices, Log, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException and not ArgumentException)
            {
                Log.LogWarning(ex, "close-loop lifecycle");
                CloseLoopNote = "The vulnerability close-loop could not be read" + SchemaHint(ex.Message);
                return null;
            }
        }
        return new GridPlan(CollectionViewSql.Events, new Dictionary<string, object?> { ["From"] = from, ["To"] = to }, Current!.Version + "|live",
            new Dictionary<string, IReadOnlyList<string>> { ["Action"] = new[] { "Open", "Close", "EngineerClose", "Reopen" } });
    }
}

// ---- (13) what changed between two collections ----------------------------------------------------------------------------------

public sealed class ChangesModel(ICollectionViews views, ILogger<ChangesModel> log) : CollectionPageModel(views, log)
{
    public static readonly string[] Kinds4 = ["new", "gone", "changed", "unchanged"];
    [BindProperty(SupportsGet = true)] public string? A { get; set; }
    [BindProperty(SupportsGet = true)] public string? Show { get; set; }
    public ViewCollection? Base { get; private set; }
    public IReadOnlyList<CountRow> Summary { get; private set; } = Array.Empty<CountRow>();
    public bool AssetsMode => Show == "assets";
    public override string PagePath => "/Collection/Changes";
    public override string Heading => "What changed";
    public override string Lede => "Two collections side by side: the findings and CIs that are new, no longer reported or changed (severity, risk score, tier or rating) between them.";
    public override IEnumerable<(string Key, string Value)> ExtraState()
    {
        if (Base is not null) yield return ("a", Base.CollectionId);
        else if (A is not null) yield return ("a", A);
        if (AssetsMode) yield return ("show", "assets");
    }
    public long Count(string what, string change) => Summary.Where(r => r.Group == what && r.Key == change).Sum(r => r.N);

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (A is not null) ProDataFilters.Id(A, "collection");
        Base = A is null ? Previous : Collections.FirstOrDefault(c => c.CollectionId == A);
        if (Base is null)
        {
            Notice = A is null ? "There is no earlier collection to compare this one with yet." : "That collection is not in the Pro database. Pick another one.";
            return null;
        }
        if (Base.CollectionId == Current!.CollectionId) { Notice = "Pick two different collections."; return null; }
        // #812: the comparison the data sync wrote (this collection against the one before it) -- never compared here from
        // every finding of both collections. Another pair, or a pair not written yet, is said.
        var st = await Views.ChangeStateAsync(Current, ct);
        State = st.Data;
        if (st.Query.Length > 0) Queries.Add(QueryInfo.From(st, "The stored comparison of this collection"));
        if (!State.IsFor(Base))
        {
            Notice = NotPreparedText(State, A is null || Base.CollectionId == Previous?.CollectionId, Previous);
            return null;
        }
        if (!forExport) { var s = await Views.ChangeSummaryAsync(Base, Current, ct); Summary = s.Data; Queries.Add(QueryInfo.From(s, "What changed: the counts")); await LoadFacetsAsync(ct); }
        var p = new Dictionary<string, object?> { ["A"] = Base.CollectionId, ["B"] = Current.CollectionId };
        var scope = Base.Version + "~" + Current.Version + "|changes@" + State.Version;
        var defaults = new Dictionary<string, string> { ["Change"] = "new|gone|changed" };
        if (!AssetsMode && HttpContext?.Request.Query.TryGetValue("f.Change", out var chosen) == true
            && chosen.Any(v => v?.Split('|').Contains("unchanged", StringComparer.OrdinalIgnoreCase) == true))
            Notice ??= "Unchanged findings are counted above but not listed: they are the findings both runs report alike -- every one of them is on Raw rows.";
        return AssetsMode
            ? new GridPlan(CollectionViewSql.AssetChangesStored, p, scope, new Dictionary<string, IReadOnlyList<string>> { ["Change"] = Kinds4, ["TierAfter"] = TierValues }, DefaultFilters: defaults)
            // the counted twin (exempted findings left out) says which missing findings are exempted, not "no longer reported"
            : new GridPlan(CollectionViewSql.FindingChangesStored, p, scope, new Dictionary<string, IReadOnlyList<string>>
            {
                ["Change"] = Listed, ["ReportName"] = Options(Facets.Report), ["SeverityAfter"] = Options(Facets.Severity), ["TierAfter"] = TierValues,
            }, DefaultFilters: defaults);
    }

    /// The finding changes the stored comparison lists (an unchanged finding is counted, not listed).
    public static readonly string[] Listed = ["new", "gone", "changed"];
    /// The stored comparison of the current collection (null until read).
    public ChangeState? State { get; private set; }

    /// What the page says when the comparison asked for is not the stored one. <paramref name="defaultPair"/>: the page compares
    /// with the collection before this one (the stored pair once written).
    public static string NotPreparedText(ChangeState s, bool defaultPair, ViewCollection? previous) =>
        !s.Schema ? "The comparison of two collections needs the database update that adds its tables: the updater adds them (setup\\Initialize-SIDataSql.ps1 -- it only adds), and the next data sync fills them. Meanwhile every finding of each collection is on Raw rows."
        : defaultPair ? "This collection's comparison with the one before it is being prepared: the data sync works it out once per collection, right after the collection is loaded. It appears when the data sync that is running now, or the next one, has finished -- open this page again in a few minutes."
        : "This comparison is not prepared: the data sync prepares each collection against the collection before it" + (previous is null ? "." : " (" + previous.CollectionTime.ToString("yyyy-MM-dd HH:mm", System.Globalization.CultureInfo.InvariantCulture) + " UTC) -- pick that one to see what changed.") + " Comparing two other collections would read every finding of both, which this page does not do.";
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) =>
        column == "AssetName" && Cell(row, "AssetKey") is { Length: > 0 } k ? ViewLink("/Collection/Asset", ("key", k)) : null;

    // ---- the words a person reads: the codes (new / gone / changed) stay in the data, the URL and the filter ----------

    private static string? Code(IReadOnlyDictionary<string, object?> row) => row.TryGetValue("Change", out var v) ? v as string : null;
    private static string? Reason(IReadOnlyDictionary<string, object?> row) => row.TryGetValue("ChangeReason", out var v) ? v as string : null;

    public override string CellText(GridColumn c, IReadOnlyDictionary<string, object?> row, bool csv = false)
    {
        if (c.Key == "Change") return ChangeWording.Label(Code(row), Reason(row));
        // the side the row does not have: "—" on screen, empty in the CSV -- never "Unclassified"
        if (ChangeWording.MissingSide(c.Key, Code(row))) return csv ? "" : ChangeWording.NoValue;
        return base.CellText(c, row, csv);
    }

    public override object? CellExcel(GridColumn c, IReadOnlyDictionary<string, object?> row)
    {
        if (c.Key == "Change") return ChangeWording.Label(Code(row), Reason(row));
        if (ChangeWording.MissingSide(c.Key, Code(row))) return null;
        return base.CellExcel(c, row);
    }

    public override string? CellTitle(GridColumn c, IReadOnlyDictionary<string, object?> row) => c.Key switch
    {
        "Change" => ChangeWording.Tooltip(Code(row), Reason(row), AssetsMode),
        "RiskDelta" => ChangeWording.RiskChangeTooltip(Code(row), AssetsMode),
        _ when ChangeWording.MissingSide(c.Key, Code(row)) => Code(row) == ChangeWording.New ? "Not in the earlier run." : "Not in the newest run.",
        _ => null,
    };

    public override string ValueLabel(GridColumn c, string v) => c.Key == "Change" ? ChangeWording.Label(v) : base.ValueLabel(c, v);

    public override string ChipText(GridColumn c, GridFilterValue f) =>
        c.Key == "Change" && f.Kind is GridFilter.Values ? ChangeWording.Chip(f.Values) : base.ChipText(c, f);

    public override string ExportFilterText(GridColumn c, GridFilterValue f) => c.Key == "Change" ? ChipText(c, f) : base.ExportFilterText(c, f);

    /// The words of a summary tile ("findings no longer reported").
    public static string SummaryWord(string code) => code == ChangeWording.Gone ? "no longer reported" : code;
}

// ---- (15) services: the CMDB business services ranked by weighted risk (#255) ----------------------------------------------

[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Management)]
public sealed class ServicesModel(ICollectionViews views, ILogger<ServicesModel> log) : CollectionPageModel(views, log)
{
    /// The service drilled into (null = the list of services). <see cref="CollectionViewSql.NoServiceKey"/> = the CIs in no service.
    [BindProperty(SupportsGet = true)] public string? Svc { get; set; }
    public ServicesState? State { get; private set; }
    public ServiceRow? Service { get; private set; }
    public bool DrillDown => Svc is not null;

    public override string PagePath => "/Collection/Services";
    public override string Heading => !DrillDown ? "Services" : Service?.ServiceName ?? Svc!;
    public override string Lede => !DrillDown
        ? "The CMDB business services, the most weighted risk first: per service its weighted risk, assets, findings by severity and tier and its highest-risk asset (an asset in more than one service is counted under each of them; \"(no service)\" holds the rest)."
        : "The assets of this service in the collection, the highest weighted risk first. Open an asset for its findings. \"Services it is in\" above 1 means the asset also counts under another service.";
    public override string ExportName => DrillDown ? "service-assets" : "services";
    public override IEnumerable<(string Key, string Value)> ExtraState() => Svc is null ? Array.Empty<(string, string)>() : new[] { ("svc", Svc) };

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (Svc is not null) Svc = CollectionViewSql.ServiceKey(Svc);
        var s = await Views.ServicesStateAsync(Current!, ct); State = s.Data; Queries.Add(QueryInfo.From(s, "Services in this collection"));
        if (State.DerivedAt is null)
            Notice ??= "This collection's services are computed by the data sync after each load, and have not been computed for this collection yet. They fill in after the next data sync.";
        var scope = Current.Version + "|svc@" + State.Version;
        if (Svc is null)
            return new GridPlan(CollectionViewSql.Services, new Dictionary<string, object?> { ["CollectionId"] = Current.CollectionId }, scope);
        if (!forExport)
        {
            var one = await Views.ServiceAsync(Current, Svc, ct); Service = one.Data; Queries.Add(QueryInfo.From(one, "This service"));
            if (Service is null && State.DerivedAt is not null) Notice ??= "That service has no asset with a finding in this collection. Pick another one from the list.";
        }
        return new GridPlan(CollectionViewSql.ServiceAssets, new Dictionary<string, object?> { ["CollectionId"] = Current.CollectionId, ["Service"] = Svc }, scope,
            new Dictionary<string, IReadOnlyList<string>> { ["Tier"] = TierValues, ["AssetKind"] = Kinds });
    }

    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row)
    {
        if (!DrillDown)
            return column switch
            {
                "ServiceName" or "Assets" => Cell(row, "ServiceKey") is { } k ? ViewLink(PagePath, ("svc", k)) : null,
                "TopAssetName" => Cell(row, "TopAssetKey") is { } a ? ViewLink("/Collection/Asset", ("key", a)) : null,
                _ => null,
            };
        return column is "AssetName" or "Findings" && Cell(row, "AssetKey") is { } key ? ViewLink("/Collection/Asset", ("key", key)) : null;
    }
}

// ---- (14) connector changes ------------------------------------------------------------------------------------------------------

[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Views, Off = true)]
public sealed class ConnectorsModel(ICollectionViews views, ILogger<ConnectorsModel> log) : CollectionPageModel(views, log)
{
    [BindProperty(SupportsGet = true)] public string? Show { get; set; }
    public IReadOnlyList<ConnectorTotal> Totals { get; private set; } = Array.Empty<ConnectorTotal>();
    public bool ItemsMode => Show == "items";
    public override string PagePath => "/Collection/Connectors";
    public override string Heading => "Connector changes";
    public override string Lede => "What every connector did between the collection you pick and the next one: each run, and each item it changed in the other system -- when, which object, which target record, which field, the value before and now.";
    public override IEnumerable<(string Key, string Value)> ExtraState() => ItemsMode ? new[] { ("show", "items") } : Array.Empty<(string, string)>();
    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        var (from, to) = Window;
        if (!forExport) { var t = await Views.ConnectorTotalsAsync(from, to, ct); Totals = t.Data; Queries.Add(QueryInfo.From(t, "Connector runs in the window")); }
        var p = new Dictionary<string, object?> { ["From"] = from, ["To"] = to };
        var names = Totals.Select(x => x.Connector).ToList();
        return ItemsMode
            ? new GridPlan(CollectionViewSql.ConnectorItems, p, Current!.Version + "|live", new Dictionary<string, IReadOnlyList<string>>
            {
                ["Action"] = CollectionViewSql.ConnectorActions, ["ConnectorName"] = names,
            })
            : new GridPlan(CollectionViewSql.ConnectorRuns, p, Current!.Version + "|live", new Dictionary<string, IReadOnlyList<string>>
            {
                ["Outcome"] = new[] { "success", "partial", "held", "halted", "whatif", "failed", "refused" }, ["Mode"] = new[] { "whatif", "apply" }, ["ConnectorName"] = names,
            });
    }
}
