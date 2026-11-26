using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Pages.Collection;

namespace SI.Management.Web.Pages.Remediations;

/// <summary>
/// Remediations > Task: ONE remediation task's page (owner 2026-11-25, on Tasks per asset: "when i click this (it shows as it
/// has more info) it just returns back t same row. i expected a landing page for each remeidation task with all relevant
/// info"). Everything SecurityInsight stores for the task -- what it is and its state, what to do (the recommended update,
/// the application and its version, every detected path in full, the bundled library and its version), the asset it covers,
/// its dates -- and the findings it resolves in the shared grid (filters, sort, exports), each opening its finding page.
/// Reached from every link to one task: the task's name on Tasks per asset, Task findings and the task reports, and the task
/// sections of the asset page, the CI page and the finding page. Read by the task's key (one seek on the clustered keys,
/// <see cref="RemediationTaskSql.OneTask"/> / <see cref="RemediationTaskSql.FindingsOfTask"/>); the same collection rule as
/// every task grid (the newest collection whose tasks are fully built, at or before the one picked). A person limited to
/// some rows gets the task counted over the findings they may see and only those findings -- a task none of whose findings
/// they may see is not found -- and is not offered the asset page or the CI page (they are not limited to departments).
/// </summary>
public sealed class TaskModel(ICollectionViews views, ILogger<TaskModel> log) : RemediationTaskPageModel(views, log)
{
    /// The task's id (the hex the task grids show as "Task id").
    [BindProperty(SupportsGet = true)] public string? Id { get; set; }
    /// The list the task was opened from, with its filters (the way back); only a task list of this app is followed.
    [BindProperty(SupportsGet = true)] public string? ReturnUrl { get; set; }

    /// The task's row (null = not read, or not found).
    public IReadOnlyDictionary<string, object?>? Row { get; private set; }

    public override string PagePath => TaskPage;
    public override string Heading => Row is { } r && AssetTasksView.Text(r, "TaskName") is { Length: > 0 } n ? n : "Remediation task";
    public override string Lede => "Everything SecurityInsight stores for one remediation task: what it is and its state, what to do and where (every detected path), the asset it covers, its dates, and the findings it resolves -- open a finding for its own page. Shown from the newest collection whose tasks are fully built, at or before the one picked.";
    public override string ExportName => "remediation-task";
    public override bool CompactFrame => false;

    public const string NotFoundText = "This task is not among the tasks of this collection: it may have been worked out in another collection, or the tasks of this collection are not built yet. Pick another collection, or open the task list.";

    public override IEnumerable<(string Key, string Value)> ExtraState()
    {
        if (!string.IsNullOrEmpty(Id)) yield return ("id", Id);
        if (Back(ReturnUrl) is { } r) yield return ("ReturnUrl", r);
    }

    /// Opened without a task it has nothing to show: it goes to the task list (a GET of the page; the exports return nothing).
    public override async Task OnPageHandlerExecutionAsync(Microsoft.AspNetCore.Mvc.Filters.PageHandlerExecutingContext context, Microsoft.AspNetCore.Mvc.Filters.PageHandlerExecutionDelegate next)
    {
        if (string.IsNullOrEmpty(context.HandlerMethod?.Name) && HttpMethods.IsGet(Request.Method) && string.IsNullOrWhiteSpace(Id))
        {
            context.Result = Redirect(TasksPage);
            return;
        }
        await next();
    }

    /// The findings grid of this page only (its own limited grid is built with the person's visibility).
    protected override GridSpec? RestrictToVisibility(GridSpec spec, RowVisibility visibility) =>
        spec.Name.StartsWith(RemediationTaskSql.TaskFindings.Name + "@dept@task", StringComparison.Ordinal) ? spec : null;

    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        var id = RemediationTaskSql.TaskIdOf(Id);
        if (id is null) { Error = "That is not a task id: open a task from Tasks per asset."; return null; }
        var p = new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId, [RemediationTaskSql.TaskIdParameter] = id };
        if (!forExport)
        {
            var hp = new Dictionary<string, object?>(p);
            if (Visibility is not null) foreach (var kv in Visibility.Parameters) hp[kv.Key] = kv.Value;
            var scope = Current.Version + "|remtask|" + id + (Visibility is null ? "" : "|" + Visibility.Key);
            var t = await Views.GridAsync(new GridQuery(RemediationTaskSql.OneTask(Visibility), hp, scope, new GridRequest { Page = 1, Size = 25 }), ct);
            Queries.Add(QueryInfo.From(t, "The task"));
            Row = t.Data.Rows.FirstOrDefault();
            if (Row is null) { Notice = NotFoundText; return null; }
        }
        var options = new Dictionary<string, IReadOnlyList<string>>
        {
            ["Severity"] = RemediationTaskSql.Severities, ["RiskRating"] = RemediationTaskReports.Ratings, ["Seen"] = RemediationTaskSql.Seen,
            ["WithinAcceptedLifecycle"] = ["yes", "no"],
        };
        return new GridPlan(RemediationTaskSql.FindingsOfTask(Visibility), p, Current.Version + "|remtaskfindings|" + id, options);
    }

    /// A finding opens its own page (in the collection its row is in).
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) => column switch
    {
        "FindingKey" or "CveId" or "Title" => FindingHref(row),
        _ => null,
    };

    private string? FindingHref(IReadOnlyDictionary<string, object?> row) =>
        Cell(row, "FindingId") is { Length: > 0 } f && Cell(row, "FindingCollectionId") is { Length: > 0 } c
            ? "/Findings/Detail?c=" + Uri.EscapeDataString(c) + "&id=" + Uri.EscapeDataString(f) : null;

    // ---- what the page shows above the grid ------------------------------------------------------------------------------

    public string S(string key) => Row is null ? "" : AssetTasksView.Text(Row, key);

    public DateTime? When(string key)
    {
        if (Row is null || !Row.TryGetValue(key, out var v)) return null;
        if (v is DateTime d) return d;
        if (v is DateTimeOffset o) return o.UtcDateTime;
        if (v is string s && DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var p)) return p;
        return null;
    }

    public double? Number(string key) =>
        double.TryParse(S(key), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;

    /// Every detected path, one per item, in full (never cut).
    public IReadOnlyList<string> Paths => SI.Management.Web.Columns.CellLines.Split(S("DetectedPaths"));

    public IReadOnlyList<string> RecommendedUpdates => RemediationTaskSql.Fixes(S("RecommendedUpdates"));
    public IReadOnlyList<string> RemediationTexts => RemediationTaskSql.Fixes(S("Remediations"));

    public bool Bundled => S("Kind") == "bundled-upgrade";

    /// The collection the task rows were read from (the newest whose tasks are built, at or before the one picked).
    public ViewCollection? TaskCollection => Collections.FirstOrDefault(c => c.CollectionId == S("TaskCollectionId"));

    /// The asset page of the task's asset; null for a person limited to some rows (it is not limited to their departments).
    public string? AssetHref => Visibility is null && S("AssetKey") is { Length: > 0 } a ? ViewLink("/Collection/Asset", ("key", a)) : null;
    /// The CI page of the task's CI; null for a limited person, or a task of no CI.
    public string? CiHref => Visibility is null && S("CiId") is { Length: > 0 } ci ? "/Cis/Detail?id=" + Uri.EscapeDataString(ci) : null;
    /// Every task of the task's asset on Tasks per asset.
    public string? AllTasksHref => S("AssetKey") is { Length: > 0 } a ? ViewLink(TasksPage, ("f.AssetKey", a))
        : S("OwnerKey") is { Length: > 0 } o ? ViewLink(TasksPage, ("f.OwnerKey", o)) : null;

    /// The way back: the list the task was opened from (with its filters), else the task list of its asset.
    public string BackHref => Back(ReturnUrl) ?? AllTasksHref ?? ViewLink(TasksPage);
    public string BackText => Back(ReturnUrl) is { } r && r.StartsWith(TaskFindingsPage, StringComparison.OrdinalIgnoreCase) ? "Task findings"
        : Back(ReturnUrl) is { } s && s.StartsWith(TaskReportPageModel.SinglesPage, StringComparison.OrdinalIgnoreCase) ? "Tasks no mass action fits"
        : "Tasks per asset";

    /// A way back this page follows: one of the task lists of this app, as a local path (nothing else is ever linked).
    public static string? Back(string? url)
    {
        var r = url?.Trim();
        if (string.IsNullOrEmpty(r) || r.Length > 4000 || r.Contains("//", StringComparison.Ordinal) || r.Contains('\\')) return null;
        foreach (var page in new[] { TasksPage, TaskFindingsPage, TaskReportPageModel.SinglesPage })
            if (r.Equals(page, StringComparison.OrdinalIgnoreCase) || r.StartsWith(page + "?", StringComparison.OrdinalIgnoreCase)) return r;
        return null;
    }
}
