using SI.Management.Core.ProData;
using SI.Management.Web.Pages.Collection;

namespace SI.Management.Web.Pages.Remediations;

/// <summary>
/// #1277 THE REMEDIATION TASKS PER CI (owner 2026-11-16: "one vulnerability per CI per task to perform" -- the findings the task
/// resolves are information on it): Remediations > Tasks per asset (one row per CI and task, its state run to run) and the
/// findings of a task (and, for a library bundled in another product, the paths of that copy). Built per collection by the data
/// sync (sidata.RemediationTask / RemediationTaskFinding, SI-DataRemediationTask.ps1; the rule is in docs/DESIGN.md). The
/// existing Remediations pages are unchanged. Department-scoped people see only the tasks with findings they may see, counted
/// over those findings, and only those findings (finding level: <see cref="RemediationTaskSql.TasksFor"/>). Every view exports
/// (CSV / Excel, the shared grid's exports).
/// </summary>
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Views, Off = true)]
public abstract class RemediationTaskPageModel(ICollectionViews views, ILogger log) : CollectionPageModel(views, log)
{
    public const string TasksPage = "/Remediations/Tasks";
    public const string TaskFindingsPage = "/Remediations/TaskFindings";
    /// owner 2026-11-25 ("i expected a landing page for each remeidation task with all relevant info"): ONE task's page.
    public const string TaskPage = "/Remediations/Task";

    public override bool CompactFrame => true;
    /// every read is the task rows of one collection, limited at FINDING level for a limited person (below)
    protected override bool DepartmentScopeSafe => true;
    /// A task row stands for several findings, and a finding can have a department other than its CI's (a recommendation
    /// override): a limited person gets the tasks with at least one finding they may see, counted over those findings only,
    /// and only those findings (RemediationTaskSql.TasksFor / TaskFindingsFor) -- never the task row's own department.
    /// A grid that is not one of the task grids is not shown to them.
    protected override GridSpec? RestrictToVisibility(GridSpec spec, RowVisibility visibility) =>
        // #1283 a grid built with the person's visibility already (the dimensions chosen, the task reports) is limited as built
        spec.Name.EndsWith("@dept", StringComparison.Ordinal) ? spec : RemediationTaskSql.For(spec, visibility);

    /// #1283 the task dimensions chosen in the address ("d.Os=windows|linux"): the IT service, the OS, the risk rating, the
    /// category ... -- carried by every form and link of the page (RemediationTaskReports.Dimensions).
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Dims
    {
        get
        {
            if (_dims is not null) return _dims;
            try { _dims = HttpContext is null ? new Dictionary<string, IReadOnlyList<string>>() : RemediationTaskReports.ReadFilters(Request.Query.Select(q => new KeyValuePair<string, IEnumerable<string?>>(q.Key, q.Value))); }
            catch (ArgumentException) { _dims = new Dictionary<string, IReadOnlyList<string>>(); _dimsError = $"at most {GridSql.MaxValues} values per filter"; }
            return _dims;
        }
    }
    private IReadOnlyDictionary<string, IReadOnlyList<string>>? _dims;
    private string? _dimsError;

    /// A dimension value that does not fit is refused (the page says the request is not valid; the page itself still renders).
    protected void CheckDims() { _ = Dims; if (_dimsError is not null) throw new ArgumentException(_dimsError); }

    public override IEnumerable<(string Key, string Value)> ExtraState() => Dims.Select(kv => ("d." + kv.Key, string.Join("|", kv.Value)));

    /// The slice of the task rows the page reads: the chosen dimensions and the person's visibility.
    protected TaskSlice Slice => new(Dims, Visibility);
    /// A bundled copy's paths are shown, filtered, searched, sorted and exported IN FULL, a person's folder name included
    /// (owner 2026-11-17: the whole path is the evidence an Admin needs); who sees a task follows the department scoping.
    protected GridPlan TaskPlan(GridSpec spec, string scope, IReadOnlyDictionary<string, IReadOnlyList<string>> options) =>
        new(spec, new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId }, Current.Version + scope, options);
    /// the tasks carry their own lifecycle (open / closed and why; kept as they were while their findings are not known) --
    /// there is no CI lifecycle choice on these pages
    protected override bool CountsLifecycle => false;
    public const string LifecycleText = "Tasks are worked out from the findings of active CIs. A retired CI's tasks close as asset retired; the tasks of a CI that is not seen, or whose findings are not known this run, are kept as they were.";
    protected override string LifecycleWords(CiLifecycleRules? rules) => LifecycleText;

    /// <summary>
    /// Owner 2026-11-18 ("where i can click the asset so it also shows the linked assets"): an asset opens the ASSET PAGE --
    /// its linked objects and identifiers, its tasks and its findings -- as on every other collection grid. A task's findings
    /// count opens its findings. Owner 2026-11-25 ("when i click this ... it just returns back t same row. i expected a landing
    /// page for each remeidation task with all relevant info"): the task's NAME opens the TASK'S PAGE (Remediations > Task),
    /// with the way back to this list as it is filtered. A person limited to some rows is not offered the asset page (it is
    /// not limited to their departments): their asset opens its own tasks; the task's page is limited at finding level.
    /// </summary>
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) => column switch
    {
        // #1283 the chosen dimensions travel: a task opened from a filtered view lists the findings it was counted over
        "Findings" => TaskFindingsOf(row),
        "TaskName" => TaskOf(row),
        "AssetName" => Visibility is null && Cell(row, "AssetKey") is { Length: > 0 } a ? ViewLink("/Collection/Asset", ("key", a)) : TasksOfAsset(row),
        _ => null,
    };

    /// The task's page, with this list (its filters, sort and page) as the way back.
    private string? TaskOf(IReadOnlyDictionary<string, object?> row) =>
        Cell(row, "TaskId") is { Length: > 0 } t ? ViewLink(TaskPage, ("id", t), ("ReturnUrl", HttpContext is null ? null : Link())) : null;

    private IEnumerable<(string Key, string? Value)> DimLinks() => Dims.Select(kv => ("d." + kv.Key, (string?)string.Join("|", kv.Value)));

    private string? TaskFindingsOf(IReadOnlyDictionary<string, object?> row) =>
        Cell(row, "TaskId") is { } t ? ViewLink(TaskFindingsPage, DimLinks().Append(("f.TaskId", (string?)t)).ToArray()) : null;

    /// Every task of the row's asset: by its asset key (as the asset page links it), else by the CI the task belongs to -- with
    /// the chosen dimensions.
    private string? TasksOfAsset(IReadOnlyDictionary<string, object?> row) =>
        Cell(row, "AssetKey") is { Length: > 0 } a ? ViewLink(TasksPage, DimLinks().Append(("f.AssetKey", (string?)a)).ToArray())
        : Cell(row, "OwnerKey") is { Length: > 0 } o ? ViewLink(TasksPage, DimLinks().Append(("f.OwnerKey", (string?)o)).ToArray()) : null;
}

public sealed class TasksModel(ICollectionViews views, ILogger<TasksModel> log) : RemediationTaskPageModel(views, log)
{
    public override string PagePath => TasksPage;
    public override string Heading => "Tasks per asset";
    public override string Lede => "One row per asset and task to perform: the update, the software upgrade (one per version; a library bundled in another product: one per application that bundles it), the configuration change -- with the findings and CVEs it resolves, its highest severity and risk, the asset's owner, and its state from run to run. A task closes as fixed only when its findings are gone on a complete run. Open an asset for everything known about it (its linked objects, its tasks and its findings), a task's name for everything known about the task (what to do, where, its dates and the findings it resolves), its findings count for the findings it resolves. Built for the newest collections; shown from the newest collection whose tasks are fully built, at or before the one picked.";
    public override string ExportName => "remediation-tasks";
    protected override Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        var options = new Dictionary<string, IReadOnlyList<string>>
        {
            ["Kind"] = RemediationTaskSql.Kinds, ["State"] = RemediationTaskSql.States, ["ClosedWhy"] = RemediationTaskSql.ClosedWhy,
            ["HighestSeverity"] = RemediationTaskSql.Severities, ["Tier"] = TierValues, ["Seen"] = RemediationTaskSql.Seen,
            ["Channel"] = RemediationTaskReports.Channels.Select(c => c.Name).ToList(), ["HighestRiskRating"] = RemediationTaskReports.Ratings,
        };
        // #1283 with task dimensions chosen (a report row opens its tasks with them): the same columns over the tasks they reach,
        // counted over the matching findings when a finding-level value is chosen
        CheckDims();
        if (Dims.Count == 0) return Task.FromResult<GridPlan?>(TaskPlan(RemediationTaskSql.Tasks, "|remtasks", options));
        var s = Slice;
        var p = s.Parameters();
        p["CollectionId"] = Current!.CollectionId;
        return Task.FromResult<GridPlan?>(new GridPlan(RemediationTaskReports.Tasks(s), p, Current.Version + "|remtasks|" + s.Key, options));
    }

    public override string? CellTitle(GridColumn c, IReadOnlyDictionary<string, object?> row) =>
        c.Key == "Channel" ? RemediationTaskReports.ChannelTip(Cell(row, "Channel")) : null;
}

public sealed class TaskFindingsModel(ICollectionViews views, ILogger<TaskFindingsModel> log) : RemediationTaskPageModel(views, log)
{
    public override string PagePath => TaskFindingsPage;
    public override string Heading => "Task findings";
    public override string Lede => "The findings each task resolves (one finding can belong to several tasks: one CVE on two versions, or in three applications). For a library bundled in another product, the paths of that copy -- its fix comes from that product's vendor. Open a task's name for the task's page: what to do, where, and only its findings.";
    public override string ExportName => "remediation-task-findings";
    protected override Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        var options = new Dictionary<string, IReadOnlyList<string>>
        {
            ["Kind"] = RemediationTaskSql.Kinds, ["TaskState"] = RemediationTaskSql.States, ["Severity"] = RemediationTaskSql.Severities, ["Seen"] = RemediationTaskSql.Seen,
        };
        CheckDims();
        if (Dims.Count == 0) return Task.FromResult<GridPlan?>(TaskPlan(RemediationTaskSql.TaskFindings, "|remtaskfindings", options));
        // #1283 the findings that match the chosen values only (a task opened from a filtered report lists the findings counted)
        var s = Slice;
        var p = s.Parameters();
        p["CollectionId"] = Current!.CollectionId;
        return Task.FromResult<GridPlan?>(new GridPlan(RemediationTaskReports.TaskFindings(s), p, Current.Version + "|remtaskfindings|" + s.Key, options));
    }
}
