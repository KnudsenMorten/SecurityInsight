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

    public override bool CompactFrame => true;
    /// every read is the task rows of one collection, limited at FINDING level for a limited person (below)
    protected override bool DepartmentScopeSafe => true;
    /// A task row stands for several findings, and a finding can have a department other than its CI's (a recommendation
    /// override): a limited person gets the tasks with at least one finding they may see, counted over those findings only,
    /// and only those findings (RemediationTaskSql.TasksFor / TaskFindingsFor) -- never the task row's own department.
    /// A grid that is not one of the task grids is not shown to them.
    protected override GridSpec? RestrictToVisibility(GridSpec spec, RowVisibility visibility) => RemediationTaskSql.For(spec, visibility);
    /// A bundled copy's paths are shown, filtered, searched, sorted and exported IN FULL, a person's folder name included
    /// (owner 2026-11-17: the whole path is the evidence an Admin needs); who sees a task follows the department scoping.
    protected GridPlan TaskPlan(GridSpec spec, string scope, IReadOnlyDictionary<string, IReadOnlyList<string>> options) =>
        new(spec, new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId }, Current.Version + scope, options);
    /// the tasks carry their own lifecycle (open / closed and why; kept as they were while their findings are not known) --
    /// there is no CI lifecycle choice on these pages
    protected override bool CountsLifecycle => false;
    public const string LifecycleText = "Tasks are worked out from the findings of active CIs. A retired CI's tasks close as asset retired; the tasks of a CI that is not seen, or whose findings are not known this run, are kept as they were.";
    protected override string LifecycleWords(CiLifecycleRules? rules) => LifecycleText;

    /// A task opens its findings; an asset opens its own tasks.
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) => column switch
    {
        "TaskName" or "Findings" => Cell(row, "TaskId") is { } t ? ViewLink(TaskFindingsPage, ("f.TaskId", t)) : null,
        "AssetName" => Cell(row, "AssetKey") is { } a ? ViewLink(TasksPage, ("f.AssetKey", a)) : null,
        _ => null,
    };
}

public sealed class TasksModel(ICollectionViews views, ILogger<TasksModel> log) : RemediationTaskPageModel(views, log)
{
    public override string PagePath => TasksPage;
    public override string Heading => "Tasks per asset";
    public override string Lede => "One row per asset and task to perform: the update, the software upgrade (one per version; a library bundled in another product: one per application that bundles it), the configuration change -- with the findings and CVEs it resolves, its highest severity and risk, the asset's owner, and its state from run to run. A task closes as fixed only when its findings are gone on a complete run. Open an asset for its own tasks, a task for its findings. Built for the newest collections; shown from the newest collection whose tasks are fully built, at or before the one picked.";
    public override string ExportName => "remediation-tasks";
    protected override Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct) =>
        Task.FromResult<GridPlan?>(TaskPlan(RemediationTaskSql.Tasks, "|remtasks",
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["Kind"] = RemediationTaskSql.Kinds, ["State"] = RemediationTaskSql.States, ["ClosedWhy"] = RemediationTaskSql.ClosedWhy,
                ["HighestSeverity"] = RemediationTaskSql.Severities, ["Tier"] = TierValues, ["Seen"] = RemediationTaskSql.Seen,
            }));
}

public sealed class TaskFindingsModel(ICollectionViews views, ILogger<TaskFindingsModel> log) : RemediationTaskPageModel(views, log)
{
    public override string PagePath => TaskFindingsPage;
    public override string Heading => "Task findings";
    public override string Lede => "The findings each task resolves (one finding can belong to several tasks: one CVE on two versions, or in three applications). For a library bundled in another product, the paths of that copy -- its fix comes from that product's vendor. Open a task from Tasks per asset to see only its findings.";
    public override string ExportName => "remediation-task-findings";
    protected override Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct) =>
        Task.FromResult<GridPlan?>(TaskPlan(RemediationTaskSql.TaskFindings, "|remtaskfindings",
            new Dictionary<string, IReadOnlyList<string>>
            {
                ["Kind"] = RemediationTaskSql.Kinds, ["TaskState"] = RemediationTaskSql.States, ["Severity"] = RemediationTaskSql.Severities, ["Seen"] = RemediationTaskSql.Seen,
            }));
}
