using SI.Management.Core.ProData;
using SI.Management.Web.Pages.Collection;

namespace SI.Management.Web.Pages.Remediations;

/// <summary>
/// #1283 THE TASK REPORTS FOR IT OPERATIONS (owner 2026-11-18) under Remediations: the same task rows as Tasks per asset,
/// grouped for the people who push the fixes -- one deployment (a patch tool, a policy, a software deployment) that clears the
/// most risk on the most assets first. Every report filters by the task dimensions (the tool, the IT service from the CMDB
/// link, the OS and its version, the security domain, category, subcategory, severity, risk rating, tier, owner, department and
/// more: "d.&lt;dimension&gt;" in the address), exports like every grid, and opens the task rows behind a row. A department-limited
/// person's reports are worked out over the findings they may see (<see cref="TaskSlice"/>, the rule of
/// <see cref="RemediationTaskSql.TasksFor"/>). A collection whose report rows are not built yet (synced before this release)
/// says so -- "built from the next run" -- and never shows an empty report as zero.
/// </summary>
public abstract class TaskReportPageModel(ICollectionViews views, ILogger log) : RemediationTaskPageModel(views, log)
{
    public const string ActionsPage = "/Remediations/TaskActions";
    public const string ProductsPage = "/Remediations/TaskProducts";
    public const string GroupsPage = "/Remediations/TaskGroups";
    public const string SinglesPage = "/Remediations/TaskSingles";
    public const string TrendPage = "/Remediations/TaskTrend";

    public const string NotBuiltText = "The task reports are built from the next run: this collection's tasks were worked out before the reports existed. Its tasks are in Tasks per asset; the reports appear after the next data sync.";

    /// The dimensions chosen in the address (d.&lt;key&gt;).
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Chosen => Dims;
    /// The values each dimension has (the page's choices), by dimension key.
    public IReadOnlyDictionary<string, IReadOnlyList<string>> DimValues { get; private set; } = new Dictionary<string, IReadOnlyList<string>>();
    /// The collection whose tasks are shown, and its minimum for a fleet-wide candidate.
    public string? MarkedId { get; private set; }
    public DateTime? MarkedTime { get; private set; }
    public int MinAssets { get; private set; } = 5;

    /// Whether the page offers a "group by" choice (the groups report).
    public virtual bool OffersGrouping => false;
    /// Whether the page offers the dimension filters (every report but the weekly trend).
    public virtual bool OffersDimensions => true;
    /// The page's own views (per product / per version; the tools of the trend): label, link, whether it is the one shown.
    public virtual IReadOnlyList<(string Label, string Href, bool On)> Choices => [];
    /// The task reports, for the links between them.
    public IReadOnlyList<(string Label, string Href, bool On)> Reports =>
    [
        ("Deploy once, fix many", ViewLink(ActionsPage, Carried()), PagePath == ActionsPage),
        ("By product", ViewLink(ProductsPage, Carried()), PagePath == ProductsPage),
        ("By tool, owner, IT service ...", ViewLink(GroupsPage, Carried()), PagePath == GroupsPage),
        ("No mass action fits", ViewLink(SinglesPage, Carried()), PagePath == SinglesPage),
        ("Opened and fixed per week", ViewLink(TrendPage), PagePath == TrendPage),
        ("Tasks per asset", ViewLink(TasksPage, Carried()), false),
    ];
    private (string, string?)[] Carried() => Chosen.Select(kv => ("d." + kv.Key, (string?)string.Join("|", kv.Value))).ToArray();
    public virtual string? GroupBy => null;

    public override IEnumerable<(string Key, string Value)> ExtraState() =>
        GroupBy is { } by ? base.ExtraState().Append(("by", by)) : base.ExtraState();

    /// Reads the chosen dimensions, whether the collection's report rows are built, and (on screen) each dimension's values.
    /// False = nothing to show (said in <see cref="CollectionPageModel.Notice"/>).
    protected async Task<bool> ReadStateAsync(bool forExport, CancellationToken ct)
    {
        CheckDims();   // a value that does not fit is refused here (the page says the request is not valid)
        var p = new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId };
        var st = (await Views.GridAsync(new GridQuery(RemediationTaskReports.State, p, Current.Version + "|remtaskstate", new GridRequest { Size = 25 }), ct)).Data.Rows.FirstOrDefault();
        if (st is null) { Notice = "No collection at or before this one has its remediation tasks built yet."; return false; }
        MarkedId = Convert.ToString(st["MarkedId"], System.Globalization.CultureInfo.InvariantCulture);
        MarkedTime = st["MarkedTime"] as DateTime?;
        MinAssets = Convert.ToInt32(st["MinAssets"], System.Globalization.CultureInfo.InvariantCulture);
        if (Convert.ToInt32(st["Built"], System.Globalization.CultureInfo.InvariantCulture) != 1) { Notice = NotBuiltText; return false; }
        // the values offered for each dimension: read for a person who sees everything (a limited person's are worked out over
        // the findings they may see -- about 16 s at 600,000 links, measured 2026-11-18 -- so they type the values instead)
        if (!forExport && Visibility is null)
        {
            try
            {
                var spec = RemediationTaskReports.Values(Visibility);
                var vp = new Dictionary<string, object?>(p);
                if (Visibility is not null) foreach (var kv in Visibility.Parameters) vp[kv.Key] = kv.Value;
                // #1372: cached long per collection (+ visibility); only the department names are read live (cached briefly)
                var rows = (await Views.ChoicesAsync(new GridQuery(spec, vp, Current.Version + "|remtaskvalues|" + (Visibility?.Key ?? "all"), new GridRequest { Size = 500 }), ct)).Data.Rows;
                IReadOnlyList<IReadOnlyDictionary<string, object?>> names = [];
                if (rows.Any(r => string.Equals(Convert.ToString(r["Dim"], System.Globalization.CultureInfo.InvariantCulture), "Department", StringComparison.OrdinalIgnoreCase)))
                    names = (await Views.ChoicesAsync(new GridQuery(RemediationTaskReports.DepartmentNames, new Dictionary<string, object?>(), "-|remtaskdeptnames", new GridRequest { Size = 500 }), ct)).Data.Rows;
                DimValues = RemediationTaskReports.ValuesByDimension(rows, names);
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log.LogWarning(ex, "the task report dimension values could not be read; the choices are typed"); }
        }
        return true;
    }

    protected GridPlan ReportPlan(GridSpec spec, string scope, IReadOnlyDictionary<string, IReadOnlyList<string>>? options = null)
    {
        var p = Slice.Parameters();
        p["CollectionId"] = Current!.CollectionId;
        var opts = new Dictionary<string, IReadOnlyList<string>>(options ?? new Dictionary<string, IReadOnlyList<string>>())
        {
            ["HighestSeverity"] = RemediationTaskSql.Severities, ["HighestRiskRating"] = RemediationTaskReports.Ratings,
            ["Channel"] = RemediationTaskReports.Channels.Select(c => c.Name).ToList(), ["Kind"] = RemediationTaskSql.Kinds,
        };
        return new GridPlan(spec, p, Current.Version + scope + "|" + Slice.Key, opts);
    }

    /// The task rows behind a report row: Tasks per asset, open tasks, this page's dimensions and the row's own values.
    protected string TasksOf(params (string Key, string? Value)[] extra) =>
        ViewLink(TasksPage, ExtraState().Where(e => e.Key.StartsWith("d.", StringComparison.Ordinal)).Select(e => (e.Key, (string?)e.Value))
            .Append(("f.State", (string?)"open")).Concat(extra).ToArray());

    public override string? CellTitle(GridColumn c, IReadOnlyDictionary<string, object?> row) =>
        c.Key == "Channel" ? RemediationTaskReports.ChannelTip(Cell(row, "Channel")) : null;
}

public sealed class TaskActionsModel(ICollectionViews views, ILogger<TaskActionsModel> log) : TaskReportPageModel(views, log)
{
    public override string PagePath => ActionsPage;
    public override string Heading => "Deploy once, fix many";
    public override string Lede => "One row per task across your assets: the same update, upgrade or configuration change, with how many assets it is open on, how many of them are Tier 0 or Tier 1, the CVEs it removes, the findings it closes and the tool that fits. The candidates for one fleet-wide deployment come first: a task open on at least the minimum number of assets (an Admin setting) is marked as a candidate. The minimum only marks rows: every task is listed. Then the order is the weighted risk the task removes over all its assets. Open a row for the assets and tasks behind it.";
    public override string ExportName => "deploy-once-fix-many";
    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct) =>
        await ReadStateAsync(forExport, ct) ? ReportPlan(RemediationTaskReports.Actions(Slice), "|remtaskactions", new Dictionary<string, IReadOnlyList<string>> { ["Candidate"] = ["yes", "no"] }) : null;
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) => column switch
    {
        "Action" or "Assets" => Cell(row, "TaskGroup") is { } g ? TasksOf(("f.TaskGroup", g)) : null,
        _ => null,
    };
}

public sealed class TaskProductsModel(ICollectionViews views, ILogger<TaskProductsModel> log) : TaskReportPageModel(views, log)
{
    public override string PagePath => ProductsPage;
    public override string Heading => "Tasks by product";
    public override string Lede => "One row per product with open tasks: how many assets run it, how many versions are in use, the tasks and CVEs it carries. Where one upgrade policy fixes many assets, the product leads. Split by version to see the spread; open a row for the assets and tasks behind it.";
    public override string ExportName => PerVersion ? "tasks-by-product-version" : "tasks-by-product";
    public bool PerVersion => (string?)Request.Query["v"] == "1";
    public override IEnumerable<(string Key, string Value)> ExtraState() => PerVersion ? base.ExtraState().Append(("v", "1")) : base.ExtraState();
    public override IReadOnlyList<(string Label, string Href, bool On)> Choices =>
    [
        ("Per product", ViewLink(PagePath, base.ExtraState().Select(e => (e.Key, (string?)e.Value)).ToArray()), !PerVersion),
        ("Per product and version", ViewLink(PagePath, base.ExtraState().Select(e => (e.Key, (string?)e.Value)).Append(("v", "1")).ToArray()), PerVersion),
    ];
    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct) =>
        await ReadStateAsync(forExport, ct) ? ReportPlan(RemediationTaskReports.Products(Slice, PerVersion), PerVersion ? "|remtaskprodv" : "|remtaskprod") : null;
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) => column switch
    {
        "Product" or "Assets" => Cell(row, "Product") is { } p ? TasksOf(("d.Product", p)) : null,
        "Versions" => Cell(row, "Product") is { } p ? ViewLink(PagePath, base.ExtraState().Select(e => (e.Key, (string?)e.Value)).Append(("v", "1")).Append(("f.Product", p)).ToArray()) : null,
        _ => null,
    };
}

public sealed class TaskGroupsModel(ICollectionViews views, ILogger<TaskGroupsModel> log) : TaskReportPageModel(views, log)
{
    public override string PagePath => GroupsPage;
    // "Tasks by tool", "Tasks by IT service", "Tasks by OS version" (a label starting with an acronym keeps its capitals)
    public override string Heading => "Tasks by " + (By.Label.Length > 1 && char.IsUpper(By.Label[1]) ? By.Label : char.ToLowerInvariant(By.Label[0]) + By.Label[1..]);
    public override string Lede => "The open tasks grouped by one dimension: the tool that fits (how much is patch tool, policy, software deployment or manual work), the owner or department that must act, the IT service, the OS and its version, the risk rating, how long the tasks have been open, and more. A task counts under every value it has (an asset in two IT services; a task with findings of two categories, counted over each category's findings), so the rows can overlap. Open a row for the tasks behind it.";
    public override string ExportName => "tasks-by-" + By.Key.ToLowerInvariant();
    public override bool OffersGrouping => true;
    public TaskDimension By => RemediationTaskReports.Groupings.FirstOrDefault(d => string.Equals(d.Key, (string?)Request.Query["by"], StringComparison.OrdinalIgnoreCase)) ?? RemediationTaskReports.Dimensions[0];
    public override string? GroupBy => By.Key;
    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct) =>
        await ReadStateAsync(forExport, ct) ? ReportPlan(RemediationTaskReports.Groups(Slice, By), "|remtaskgroups") : null;
    public override string? CellLink(string column, IReadOnlyDictionary<string, object?> row) => column switch
    {
        // a value the group shows as "(none)" has no value to filter on: no link
        "Group" or "Assets" or "OpenTasks" => Cell(row, "Group") is { } v && v != RemediationTaskReports.None && v != RemediationTaskReports.NoService
            ? TasksOf((By.Query, v)) : null,
        _ => null,
    };
    public override string? CellTitle(GridColumn c, IReadOnlyDictionary<string, object?> row) =>
        c.Key == "Group" && By.Key == "Channel" ? RemediationTaskReports.ChannelTip(Cell(row, "Group")) : base.CellTitle(c, row);
}

public sealed class TaskSinglesModel(ICollectionViews views, ILogger<TaskSinglesModel> log) : TaskReportPageModel(views, log)
{
    public override string PagePath => SinglesPage;
    public override string Heading => "Tasks no mass action fits";
    public override string Lede => "The open tasks whose action is open on fewer assets than the minimum for a fleet-wide deployment: the leftovers a patch tool, a policy or a software deployment will not clear in one go, so they need someone to act on each asset.";
    public override string ExportName => "tasks-no-mass-action";
    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct) =>
        await ReadStateAsync(forExport, ct) ? ReportPlan(RemediationTaskReports.Singles(Slice), "|remtasksingles", new Dictionary<string, IReadOnlyList<string>>
        {
            ["State"] = RemediationTaskSql.States, ["ClosedWhy"] = RemediationTaskSql.ClosedWhy, ["Tier"] = TierValues, ["Seen"] = RemediationTaskSql.Seen,
        }) : null;
}

public sealed class TaskTrendModel(ICollectionViews views, ILogger<TaskTrendModel> log) : TaskReportPageModel(views, log)
{
    public override string PagePath => TrendPage;
    public override string Heading => "Tasks opened and fixed per week";
    public override string Lede => "Per week: the tasks opened (new, or open again), closed as fixed, and closed for another reason (exempted, asset retired, the report or the task changed), and how many were open at the week's end. Pick a tool to see its own trend.";
    public override string ExportName => "tasks-per-week";
    public string? Channel => RemediationTaskReports.Channels.Select(c => c.Name).FirstOrDefault(n => n == (string?)Request.Query["tool"]);
    public override IEnumerable<(string Key, string Value)> ExtraState() => Channel is { } c ? [("tool", c)] : [];
    public override bool OffersDimensions => false;
    public override IReadOnlyList<(string Label, string Href, bool On)> Choices =>
        new[] { ("Every tool", ViewLink(PagePath), Channel is null) }
            .Concat(RemediationTaskReports.Channels.Select(c => (c.Name, ViewLink(PagePath, ("tool", c.Name)), Channel == c.Name))).ToList();
    protected override async Task<GridPlan?> PrepareAsync(bool forExport, CancellationToken ct)
    {
        // the stored weekly counts are over every department: a limited person is told so, and shown none
        if (Visibility is not null) { Notice = "The weekly trend counts the tasks of every department, so it is shown to people who see every department. Your own tasks are in Tasks per asset."; return null; }
        if (!await ReadStateAsync(true, ct)) return null;
        var p = new Dictionary<string, object?> { ["CollectionId"] = Current!.CollectionId, ["Channel"] = Channel };
        return new GridPlan(RemediationTaskReports.Trend, p, Current.Version + "|remtasktrend|" + Channel);
    }
}
