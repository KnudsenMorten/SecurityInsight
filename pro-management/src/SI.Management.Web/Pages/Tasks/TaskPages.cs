using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Tasks;

namespace SI.Management.Web.Pages.Tasks;

/// <summary>
/// The task lists (#265) -- My tasks, Delegated tasks and Admin > All tasks: one SERVER-side grid (BRAND-2.7): the choice
/// of open / overdue / due soon / done recently / all, a department, a search text, a sortable column and the page travel
/// in the URL and are applied in SQL. What the user may see (their own keys, the departments they see) is added by
/// <see cref="FindingTaskService.ListAsync"/>, never taken from the request.
/// </summary>
public abstract class TaskListPage : SI.Management.Web.Columns.DataViewPageModel
{
    protected readonly FindingTaskService Tasks;
    private readonly IDepartmentViews? _departments;
    private readonly ILogger _log;

    protected TaskListPage(FindingTaskService tasks, ILogger log, IDepartmentViews? departments = null) { Tasks = tasks; _log = log; _departments = departments; }

    public abstract string View { get; }
    public abstract string PagePath { get; }
    public abstract string Heading { get; }
    public abstract string Lede { get; }

    [BindProperty(SupportsGet = true)] public string? Show { get; set; }
    [BindProperty(SupportsGet = true)] public int? Dept { get; set; }
    [BindProperty(SupportsGet = true)] public string? Q { get; set; }
    [BindProperty(SupportsGet = true)] public string? Sort { get; set; }
    [BindProperty(SupportsGet = true)] public string? Dir { get; set; }
    [BindProperty(SupportsGet = true)] public int P { get; set; } = 1;
    [BindProperty(SupportsGet = true)] public int Size { get; set; } = 50;

    public TaskPage? Results { get; private set; }
    public TaskQuery Query { get; private set; } = new();
    public TaskCounts? Counts { get; private set; }
    public IReadOnlyList<DepartmentName> Departments { get; private set; } = Array.Empty<DepartmentName>();
    public string? Error { get; private set; }
    public string? Notice { get; private set; }
    public DateOnly Today => Tasks.Today;

    public static readonly IReadOnlyList<(string Show, string Label)> ShowChoices =
        [("open", "Open"), ("overdue", "Overdue"), ("soon", "Due soon"), ("recent", "Done recently"), ("cancelled", "Cancelled"), ("any", "All")];

    public async Task OnGetAsync(CancellationToken ct)
    {
        // the department filter takes several departments (one parameter per value, or '|'-joined; 0 = Unassigned)
        var depts = (HttpContext?.Request is { } req ? MultiFilter.ValuesOf(req.Query, "dept") : Array.Empty<string>())
            .Select(v => int.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var n) ? n : -1).Where(n => n >= 0).Distinct().ToList();
        Query = new TaskQuery
        {
            View = View, Show = Show ?? "open", DepartmentId = depts.Count == 1 ? depts[0] : depts.Count == 0 ? Dept : null, DepartmentIds = depts.Count > 1 ? depts : null,
            Text = Q, Sort = Sort ?? "due", Descending = string.Equals(Dir, "desc", StringComparison.OrdinalIgnoreCase), Page = P, Size = Size,
        }.Normalized();
        try
        {
            if (!await Tasks.Store.ReadyAsync(ct)) { Notice = "The Pro database does not have the task tables yet: apply sql\\si-pro-settings.sql again (it only adds)."; return; }
            Results = await Tasks.ListAsync(User, Query, ct);
            if (Exporting)
            {
                // #589: an export takes EVERY task matching the choices, page by page
                var all = Results.Rows.ToList();
                for (var p = 2; p <= Results.Pages && all.Count < ProDataFilters.MaxExport; p++)
                    all.AddRange((await Tasks.ListAsync(User, Query with { Page = p }, ct)).Rows);
                ExportRows = all;
                return;
            }
            if (View == TaskQuery.ViewMine) Counts = await Tasks.CountsAsync(User, ct);
            if (_departments is not null)
            {
                var see = await Tasks.VisibleDepartmentsAsync(User, ct);
                try { Departments = (await _departments.NamesAsync(ct)).Data.Where(d => !d.Retired && FindingTaskService.Sees(see, d.DepartmentId)).ToList(); }
                catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "department names"); }
            }
            await LoadTablesAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading tasks failed");
            Error = "The tasks could not be read from the Pro database: " + ex.Message;
        }
    }

    // ---- #589 the list as the shared data table: the CI and finding context, every field, the all-rows exports --------

    /// The view key of this list (its layouts, and the person's remembered choices): tasks-mine, tasks-delegated, tasks-all.
    public string ViewKey => "tasks-" + View;

    /// The choices are this page's own address parameters (show, dept, q, sort, dir, size): what the person last chose comes
    /// back before they are bound; an address that names one wins. The page number is never remembered.
    protected override string? AddressStateView => ViewKey;

    /// Every task matching the choices (an export's rows).
    private IReadOnlyList<FindingTaskRow>? ExportRows { get; set; }

    protected override Task LoadForExportAsync(CancellationToken ct) => OnGetAsync(ct);

    protected override IReadOnlyList<SI.Management.Web.Columns.DataTable> BuildTables()
    {
        if (Results is null) return [];
        static FindingTaskRow T(object o) => (FindingTaskRow)o;
        var today = Today;
        string Bucket(FindingTaskRow t) => TaskDue.Bucket(t.Status, DateOnly.FromDateTime(t.DueDate), t.CompletedAt, today);
        SI.Management.Web.Columns.ServerSortLink? Sorted(string key, string column) => new(SortLink(column), AriaSort(column), Arrow(column), column);
        var sortOf = new Dictionary<string, string> { ["Title"] = "title", ["Finding"] = "asset", ["Assignee"] = "assignee", ["CreatedBy"] = "creator", ["Department"] = "department", ["DueDate"] = "due", ["Status"] = "status" };
        var t = new SI.Management.Web.Columns.DataTable
        {
            Id = "tasks", View = ViewKey, Title = Heading, Rows = (ExportRows ?? Results.Rows).Cast<object>().ToList(), Marker = "data-grid=\"tasks\" data-view=\"" + View + "\"",
            Ci = RowCiKey.AssetKey, Findings = RowFindingKey.Issue, CollectionId = "",
            RefOf = o => new SI.Management.Web.Columns.RowRef(T(o).AssetKey, null, T(o).RecommendationKey),
            RowAttributes = o => new Dictionary<string, string?> { ["data-task"] = T(o).TaskId.ToString(CultureInfo.InvariantCulture), ["data-status"] = T(o).Status, ["data-bucket"] = Bucket(T(o)) },
            ServerSort = k => sortOf.TryGetValue(k, out var col) ? Sorted(k, col) : null,
            Columns =
            [
                new("Title", "Task", o => T(o).Title, Link: o => "/Tasks/Task?id=" + T(o).TaskId),
                new("Finding", "Finding", o => T(o).FindingTitle ?? T(o).RecommendationKey,
                    Link: o => "/Departments/Finding?asset=" + Uri.EscapeDataString(T(o).AssetKey) + "&rec=" + Uri.EscapeDataString(T(o).RecommendationKey)),
                new("RecommendationKey", "CVE / configuration", o => T(o).RecommendationKey),
                new("AssetName", "Asset", o => T(o).AssetName),
                new("AssetKey", "Asset (CI) key", o => T(o).AssetKey),
                new("Assignee", "For", o => T(o).AssigneeName + " (" + AssigneeKinds.Label(T(o).AssigneeKind) + ")"),
                new("AssigneeId", "For (id)", o => T(o).AssigneeId),
                new("AssigneeMail", "For (mail)", o => T(o).AssigneeMail),
                new("CreatedBy", "Created by", o => T(o).CreatedBy),
                new("DepartmentId", "Department id", o => T(o).DepartmentId),
                new("Department", "Department", o => T(o).DepartmentName ?? "Unassigned"),
                new("DueDate", "Due", o => T(o).DueDate, Text: o => T(o).DueDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)),
                new("Status", "Status", o => TaskDue.Label(Bucket(T(o)))),
                new("Note", "Note", o => T(o).Note),
                new("RemindAt", "Reminder", o => T(o).RemindAt),
                new("CreatedAt", "Created", o => T(o).CreatedAt),
                new("CompletedAt", "Completed", o => T(o).CompletedAt),
                new("CompletedBy", "Completed by", o => T(o).CompletedBy),
                new("CompletionNote", "Completion note", o => T(o).CompletionNote),
                new("ResolvedAt", "Finding resolved", o => T(o).ResolvedAt),
                new("ResolvedReason", "Resolved because", o => T(o).ResolvedReason),
            ],
        };
        t.Html["Title"] = o => new Microsoft.AspNetCore.Html.HtmlString("<a href=\"/Tasks/Task?id=" + T(o).TaskId + "\">" + System.Net.WebUtility.HtmlEncode(T(o).Title) + "</a>"
            + (T(o).IsOpen && T(o).FindingResolved ? " <span class=\"badge good\" data-resolved>Finding resolved -- close the task?</span>" : ""));
        t.Html["Status"] = o =>
        {
            var b = Bucket(T(o));
            return SI.Management.Web.Columns.DataCellHtml.Badges((b == "overdue" ? "bad" : b == "soon" ? "warn" : b is "recent" or "done" ? "good" : "", TaskDue.Label(b)));
        };
        return [t];
    }

    /// This list's URL with the current choices, some overridden (null removes one); a new choice starts at page 1.
    public string Link(params (string Key, string? Value)[] overrides)
    {
        var d = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
        {
            ["show"] = Query.Show == "open" ? null : Query.Show,
            ["dept"] = Query.AllDepartmentIds.Count == 0 ? null : string.Join(SI.Management.Core.ProData.ProDataFilters.ValueSeparator, Query.AllDepartmentIds.Select(d => d.ToString(CultureInfo.InvariantCulture))), ["q"] = Query.Text,
            ["sort"] = Query.Sort == "due" ? null : Query.Sort, ["dir"] = Query.Descending ? "desc" : null,
            ["size"] = Query.Size == SI.Management.Core.ProData.GridSql.DefaultPageSize ? null : Query.Size.ToString(CultureInfo.InvariantCulture), ["p"] = Query.Page > 1 ? Query.Page.ToString(CultureInfo.InvariantCulture) : null,
        };
        foreach (var (k, v) in overrides) d[k] = v;
        if (overrides.All(o => o.Key != "p")) d["p"] = null;
        var qs = string.Join("&", d.Where(kv => !string.IsNullOrEmpty(kv.Value)).Select(kv => kv.Key + "=" + Uri.EscapeDataString(kv.Value!)));
        return PagePath + (qs.Length > 0 ? "?" + qs : "");
    }

    /// A column header's link: sorts by it, ascending first; clicked again, the other way.
    public string SortLink(string column) => Link(("sort", column == "due" ? null : column), ("dir", Query.Sort == column && !Query.Descending ? "desc" : null));
    public string AriaSort(string column) => Query.Sort != column ? "none" : Query.Descending ? "descending" : "ascending";
    public string Arrow(string column) => Query.Sort != column ? "" : Query.Descending ? " ▼" : " ▲";
}

public sealed class IndexModel(FindingTaskService tasks, IDepartmentViews departments, ILogger<IndexModel> log) : TaskListPage(tasks, log, departments)
{
    public override string View => TaskQuery.ViewMine;
    public override string PagePath => "/Tasks";
    public override string Heading => "My tasks";
    public override string Lede => "The follow-up tasks given to you -- or to a group you are in, or to the department person you are -- on the findings you see. Most urgent first.";
}

public sealed class DelegatedModel(FindingTaskService tasks, IDepartmentViews departments, ILogger<DelegatedModel> log) : TaskListPage(tasks, log, departments)
{
    public override string View => TaskQuery.ViewDelegated;
    public override string PagePath => "/Tasks/Delegated";
    public override string Heading => "Delegated tasks";
    public override string Lede => "The follow-up tasks you created for someone else, and where they stand.";
}
