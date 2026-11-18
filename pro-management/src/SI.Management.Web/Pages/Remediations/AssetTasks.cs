using System.Globalization;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Pages.Remediations;

/// <summary>
/// The "Remediation tasks" section of ONE asset (owner 2026-11-18: "why are tasks not shown on the asset ci view") and of ONE
/// finding (the task(s) it belongs to): the task rows of Tasks per asset, narrowed in the statement to that asset or finding
/// (<see cref="RemediationTaskSql.OfOne"/> / <see cref="RemediationTaskSql.OfFinding"/>), open first, paged in SQL -- the
/// total is always said and every page is reachable, so nothing is cut. A person limited to some rows gets the finding-level
/// scoping of Tasks per asset / Task findings, unchanged.
/// </summary>
public sealed record AssetTasksView
{
    public IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows { get; init; } = Array.Empty<IReadOnlyDictionary<string, object?>>();
    public long Total { get; init; }
    public int Page { get; init; } = 1;
    public int Size { get; init; } = AssetTasks.PageSize;
    /// The page of this section at <c>n</c> (the page's own address with the section's page parameter).
    public Func<int, string> PageLink { get; init; } = _ => "";
    /// Every task of this asset on Tasks per asset (null = none to offer: the finding section).
    public string? AllHref { get; init; }
    /// The asset page of a task's asset (by its asset key); null = the asset is not linked (a person limited to some rows:
    /// the asset page is not limited to their departments, so it is not offered to them).
    public Func<string, string>? AssetHref { get; init; }
    /// What the section says instead of rows (the tasks are not built yet, or could not be read); null = rows / none.
    public string? Note { get; init; }
    /// "asset" or "finding" (the words and the test hook).
    public string For { get; init; } = "asset";
    /// The collection the links open.
    public string? CollectionId { get; init; }
    public bool Finding => For == "finding";

    public int Pages => Total == 0 ? 1 : (int)Math.Ceiling(Total / (double)Size);
    public long First => Total == 0 ? 0 : (long)(Page - 1) * Size + 1;
    public long Last => (long)(Page - 1) * Size + Rows.Count;

    /// A task's own findings (Task findings, filtered to the task).
    public string TaskHref(string taskId) => Link(RemediationTaskPageModel.TaskFindingsPage, ("f.TaskId", taskId));

    public string Link(string path, params (string Key, string? Value)[] extra)
    {
        var parts = new List<string>();
        if (CollectionId is not null) parts.Add("c=" + Uri.EscapeDataString(CollectionId));
        foreach (var (k, v) in extra) if (!string.IsNullOrEmpty(v)) parts.Add(Uri.EscapeDataString(k) + "=" + Uri.EscapeDataString(v));
        return path + (parts.Count > 0 ? "?" + string.Join("&", parts) : "");
    }

    public static string Text(IReadOnlyDictionary<string, object?> row, string key) =>
        row.TryGetValue(key, out var v) && v is not null ? Convert.ToString(v, CultureInfo.InvariantCulture) ?? "" : "";
}

public static class AssetTasks
{
    /// The tasks one page of the section shows (every page reachable; the total is always said).
    public const int PageSize = 25;
    /// The address parameter of the section's page.
    public const string PageParameter = "tp";

    /// The section's page from the address (1 when absent or not a number).
    public static int PageOf(string? raw) =>
        int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var p) && p >= 1 ? Math.Min(p, int.MaxValue / PageSize) : 1;

    public const string NotBuiltText = "The remediation tasks are not in this database yet: the updater adds their tables and the next data sync builds them.";

    /// One page of the tasks of one asset (by its asset key or its CI id) in the collection <paramref name="collectionId"/>.
    public static Task<AssetTasksView> OfAssetAsync(ICollectionViews views, string collectionId, RemediationTaskSql.OneAsset by, string key, RowVisibility? visibility,
        int page, Func<int, string> pageLink, ILogger log, CancellationToken ct)
    {
        var spec = RemediationTaskSql.OfOne(by, visibility);
        var p = new Dictionary<string, object?> { ["CollectionId"] = collectionId, [RemediationTaskSql.KeyParameter(by)] = key };
        var all = new AssetTasksView { CollectionId = collectionId }.Link(RemediationTaskPageModel.TasksPage, ("f." + RemediationTaskSql.KeyParameter(by), key));
        return ReadAsync(views, spec, p, visibility, page, "asset", all, pageLink, log, ct);
    }

    /// The task(s) one finding belongs to.
    public static Task<AssetTasksView> OfFindingAsync(ICollectionViews views, string collectionId, string findingId, RowVisibility? visibility,
        int page, Func<int, string> pageLink, ILogger log, CancellationToken ct)
    {
        var spec = RemediationTaskSql.OfFinding(visibility);
        var p = new Dictionary<string, object?> { ["CollectionId"] = collectionId, ["FindingId"] = findingId };
        return ReadAsync(views, spec, p, visibility, page, "finding", null, pageLink, log, ct);
    }

    private static async Task<AssetTasksView> ReadAsync(ICollectionViews views, GridSpec spec, Dictionary<string, object?> parameters, RowVisibility? visibility,
        int page, string forWhat, string? all, Func<int, string> pageLink, ILogger log, CancellationToken ct)
    {
        var collectionId = (string)parameters["CollectionId"]!;
        if (visibility is not null) foreach (var kv in visibility.Parameters) parameters[kv.Key] = kv.Value;
        var empty = new AssetTasksView { For = forWhat, AllHref = all, PageLink = pageLink, CollectionId = collectionId };
        try
        {
            var scope = "tasks|" + spec.Name + "|" + collectionId + (visibility is null ? "" : "|" + visibility.Key);
            var req = new GridRequest { Sort = "State", Desc = false, Page = page, Size = PageSize };
            var g = (await views.GridAsync(new GridQuery(spec, parameters, scope, req), ct)).Data;
            return empty with { Rows = g.Rows, Total = g.Total, Page = g.State.Page, Size = g.State.Size };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            log.LogWarning(ex, "the remediation tasks of one {What} could not be read", forWhat);
            var missing = ex.Message.Contains("Invalid object name", StringComparison.OrdinalIgnoreCase) || ex.Message.Contains("Invalid column name", StringComparison.OrdinalIgnoreCase);
            return empty with { Note = missing ? NotBuiltText : "The remediation tasks could not be read just now: " + ViewerError.Text(ex) };
        }
    }
}
