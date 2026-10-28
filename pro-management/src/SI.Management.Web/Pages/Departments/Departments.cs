using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Departments;
using SI.Management.Web.Exemptions;
using SI.Management.Web.Pages.Collection;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Departments;

/// <summary>
/// The department pages (#254, phase 1): ONE collection at a time (the shared collection picker), the numbers from the
/// data sync's precomputed per-department aggregate, the findings through the shared grid. A user limited to departments
/// sees only theirs (the department scope of the role framework, <see cref="IDepartmentScopeResolver"/>).
/// </summary>
[ExemptedSurface(ExemptedSurface.Departments)]
public abstract class DepartmentPageModel : CollectionPageModel
{
    protected readonly IDepartmentViews Departments;
    protected DepartmentPageModel(ICollectionViews views, IDepartmentViews departments, ILogger log) : base(views, log) => Departments = departments;

    /// Every department page applies the department scope itself (and the grid is restricted on top).
    protected override bool DepartmentScopeSafe => true;

    /// #855: the departments count the findings of active CIs only (sidata.DepartmentFacet is built over them; the findings
    /// grid follows) -- said on the page, no lifecycle choice.
    protected override string LifecycleWords(SI.Management.Core.ProData.CiLifecycleRules? rules) =>
        SI.Management.Core.ProData.LifecycleFilter.ActiveOnlyWords(rules ?? SI.Management.Core.ProData.CiLifecycleDefinitions.Defaults);

    public IReadOnlyList<DepartmentSummary> Summaries { get; private set; } = Array.Empty<DepartmentSummary>();
    public IReadOnlyDictionary<int, long> OwnedAssets { get; private set; } = new Dictionary<int, long>();
    public IReadOnlyList<DepartmentName> Names { get; private set; } = Array.Empty<DepartmentName>();

    /// Null = sees every department.
    public IReadOnlyList<int>? Mine => Visibility?.Departments;
    public bool Sees(int id) => Mine is null || Mine.Contains(id);

    public DepartmentSummary? Unassigned => Summaries.FirstOrDefault(s => s.DepartmentId == DepartmentSql.Unassigned);

    protected async Task LoadSummariesAsync(CancellationToken ct)
    {
        var n = await Departments.NamesAsync(ct); Names = n.Data; Queries.Add(QueryInfo.From(n, "Department names"));
        var f = await Departments.FacetsAsync(Current!, ct); Queries.Add(QueryInfo.From(f, "Departments: counts and weighted risk"));
        Summaries = DepartmentSummary.From(f.Data).Where(s => Sees(s.DepartmentId) && (Mine is null || s.DepartmentId != DepartmentSql.Unassigned)).ToList();
        var a = await Departments.AssetCountsAsync(ct); OwnedAssets = a.Data; Queries.Add(QueryInfo.From(a, "Assets owned"));
        if (f.Data.Count == 0)
            Notice ??= "This collection has not been resolved to departments yet. The data sync stamps every finding with its department after each load (and again after a department, rule or override changes); the numbers appear after its next run.";
    }

    public string Weighted(DepartmentSummary s) => s.WeightedTotal is { } w ? Num(w) : Num(s.ScoreTotal);
}

// ---- the overview: every department side by side -------------------------------------------------------------------

public sealed class IndexModel(ICollectionViews views, IDepartmentViews departments, ILogger<IndexModel> log) : DepartmentPageModel(views, departments, log)
{
    public override string PagePath => "/Departments/Index";
    public override string Heading => "Departments";
    public override string Lede => "Who is responsible for what: every department's weighted risk, open findings and assets in the chosen collection, and what nobody owns yet.";

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        await LoadSummariesAsync(ct);
        // departments without a finding in this collection are listed too (with zeros)
        var known = Summaries.Select(s => s.DepartmentId).ToHashSet();
        Extra = Names.Where(d => !d.Retired && !known.Contains(d.DepartmentId) && Sees(d.DepartmentId)).ToList();
        return null;
    }

    public IReadOnlyList<DepartmentName> Extra { get; private set; } = Array.Empty<DepartmentName>();
}

// ---- one department ---------------------------------------------------------------------------------------------------

public sealed class DetailModel(ICollectionViews views, IDepartmentViews departments, ILogger<DetailModel> log) : DepartmentPageModel(views, departments, log)
{
    [BindProperty(SupportsGet = true)] public int? Id { get; set; }

    public DepartmentName? Department { get; private set; }
    public DepartmentSummary? Summary { get; private set; }
    public IReadOnlyList<DepartmentTrendPoint> Trend { get; private set; } = Array.Empty<DepartmentTrendPoint>();
    public IReadOnlyList<DepartmentServiceRow> Services { get; private set; } = Array.Empty<DepartmentServiceRow>();
    public ChartSpec? Chart { get; private set; }
    /// The governance log of the department (#254 phase 2): status counts, what is planned, the newest entries.
    public DepartmentGovernance? Governance { get; private set; }

    public override string PagePath => "/Departments/Detail";
    public override string Heading => Department?.Name ?? "Department";
    public override string Lede => "The department's weighted risk and its trend, its open findings by severity and tier, its assets and services -- and the findings themselves, with why each one is the department's.";
    public override string ExportName => "department";
    public override IEnumerable<(string Key, string Value)> ExtraState() => Id is null ? Array.Empty<(string, string)>() : new[] { ("id", Id.Value.ToString(CultureInfo.InvariantCulture)) };

    /// #272: the department's findings carry the shared action bar (its people are the task form's assignees).
    public override string? ActionSource => SI.Management.Web.Actions.SelectionSources.Department;
    protected override int? ActionDepartment => Id;

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (Id is not { } id || id <= 0) { Notice = "Pick a department on the Departments page."; return null; }
        if (!Sees(id)) { Error = "This department is not one of yours."; return null; }
        if (!forExport)
        {
            await LoadSummariesAsync(ct);
            Department = Names.FirstOrDefault(n => n.DepartmentId == id);
            if (Department is null) { Error = "There is no such department."; return null; }
            Summary = Summaries.FirstOrDefault(s => s.DepartmentId == id);
            var t = await Departments.TrendAsync(id, 120, ct); Trend = t.Data; Queries.Add(QueryInfo.From(t, "Trend"));
            var s = await Departments.ServicesAsync(Current!, id, ct); Services = s.Data; Queries.Add(QueryInfo.From(s, "Services"));
            if (Trend.Count > 0)
                Chart = new ChartSpec("dept-trend", "line", Trend.Select(p => p.CollectionTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)).ToList(),
                    new[] { new ChartSeries("Weighted risk", Trend.Select(p => (double?)(p.WeightedTotal ?? p.ScoreTotal)).ToList(), 1) }, "Weighted risk",
                    "Weighted risk of the department per collection");
            Governance = await DepartmentGovernance.LoadAsync(HttpContext?.RequestServices, id, ct);
        }
        return new GridPlan(DepartmentSql.Findings,
            new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId, ["DepartmentId"] = id.ToString(CultureInfo.InvariantCulture), ["Unassigned"] = 0 },
            Current.Version + "|dept" + id,
            new Dictionary<string, IReadOnlyList<string>> { ["Tier"] = TierValues, ["AssetKind"] = Kinds, ["ResponsibilitySource"] = DepartmentSql.Sources });
    }

    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) => column switch
    {
        "Title" when Mine is null => Cell(row, "FindingId") is { } f ? "/Findings/Detail?c=" + Uri.EscapeDataString(Current!.CollectionId) + "&id=" + Uri.EscapeDataString(f) : null,
        // a person limited to departments opens the finding's governance page (its log, status and remediation)
        "Title" => Cell(row, "FindingId") is { } g ? "/Departments/Finding?c=" + Uri.EscapeDataString(Current!.CollectionId) + "&id=" + Uri.EscapeDataString(g) : null,
        "AssetName" when Mine is null => Cell(row, "AssetKey") is { } k ? ViewLink("/Collection/Asset", ("key", k)) : null,
        // #258: the finding's thread -- comments, recommendations, approvals -- for everyone who sees the department
        "RecommendationKey" => Id is { } d && Cell(row, "AssetKey") is { } ak && Cell(row, "RecommendationKey") is { } rk
            ? $"/Departments/Thread?id={d.ToString(CultureInfo.InvariantCulture)}&asset={Uri.EscapeDataString(ak)}&rec={Uri.EscapeDataString(rk)}" : null,
        _ => null,
    };

    /// Critical first.
    public static int SeverityRank(string severity) => severity.ToLowerInvariant() switch
    {
        "critical" or "very high" => 0, "high" => 1, "medium" or "moderate" => 2, "low" => 3, _ => 4,
    };

    /// The change of the weighted risk from the earliest collection in the trend to this one.
    public double? Change => Trend.Count >= 2 && Trend[^1].WeightedTotal is { } a && Trend[0].WeightedTotal is { } b ? a - b : null;
}

// ---- the Unassigned triage view ---------------------------------------------------------------------------------------

public sealed class UnassignedModel(ICollectionViews views, IDepartmentViews departments, DepartmentRepository repo, ILogger<UnassignedModel> log)
    : DepartmentPageModel(views, departments, log)
{
    public override string PagePath => "/Departments/Unassigned";
    public override string Heading => "Unassigned";
    public override string Lede => "Findings no department is responsible for yet. Filter or select them, then assign them in one go -- by the asset (every finding on it) or by the recommendation (that issue on every asset). The findings move on the next data sync.";
    public override string ExportName => "unassigned";
    public IReadOnlyList<DepartmentName> Targets => Names.Where(n => !n.Retired).ToList();

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        if (Mine is not null) { Error = "The Unassigned queue spans every department, so it is not shown to an account limited to departments."; return null; }
        if (!forExport) await LoadSummariesAsync(ct);
        return new GridPlan(DepartmentSql.Findings,
            new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId, ["DepartmentId"] = null, ["Unassigned"] = 1 },
            Current.Version + "|unassigned",
            new Dictionary<string, IReadOnlyList<string>> { ["Tier"] = TierValues, ["AssetKind"] = Kinds });
    }

    /// #272: the triage's bulk assign is the shared action bar's "Assign to department" (the responsibility override,
    /// Admin) -- over the selection, or every row the filter matches -- like every other action on findings.
    public override string? ActionSource => SI.Management.Web.Actions.SelectionSources.Department;
    protected override IEnumerable<(string Key, string Value)> ActionHidden() => new[] { ("unassigned", "1") };
}
