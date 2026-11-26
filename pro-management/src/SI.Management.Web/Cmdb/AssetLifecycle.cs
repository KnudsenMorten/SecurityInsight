using SI.Management.Web.Data;

namespace SI.Management.Web.Cmdb;

/// One asset SecurityInsight no longer sees (#406): its category, when it was last seen, when it retires (or why it retired)
/// and its open findings. Times are UTC (the page shows them in the viewer's zone).
public sealed record NotSeenAsset(
    string CiKey,
    string? Name,
    string Category,
    string? Kind,
    DateTime LastSeen,
    int GraceDays,
    DateTime? RetireAt,
    string State,
    DateTime? StateChangedAt,
    DateTime? RetiredAt,
    string? RetiredBy,
    string? RetireReason,
    long OpenFindings,
    string? TopFindings);

/// The "Not seen anymore" page's data: the assets in their grace period, the ones retired recently, how many are active.
public sealed record NotSeenView(bool HasTable, IReadOnlyList<NotSeenAsset> NotSeen, IReadOnlyList<NotSeenAsset> Retired, long Active)
{
    public static readonly NotSeenView Missing = new(false, Array.Empty<NotSeenAsset>(), Array.Empty<NotSeenAsset>(), 0);

    /// #1400 each list's total (the lists hold one page); null = the list holds every row.
    public long? NotSeenTotalRead { get; init; }
    public long? RetiredTotalRead { get; init; }
    /// Where each list's page starts (rows before it).
    public int NotSeenSkip { get; init; }
    public int RetiredSkip { get; init; }
    public long NotSeenTotal => NotSeenTotalRead ?? NotSeenSkip + NotSeen.Count;
    public long RetiredTotal => RetiredTotalRead ?? RetiredSkip + Retired.Count;

    /// One page of each list of a whole view, with the whole lists' totals (a store that holds the lists in memory).
    public static NotSeenView Page(NotSeenView all, NotSeenPaging paging)
    {
        if (!all.HasTable) return all;
        var take = Math.Max(1, paging.Take);
        return all with
        {
            NotSeen = paging.Only is null or NotSeenPaging.NotSeen ? all.NotSeen.Skip(paging.NotSeenSkip).Take(take).ToList() : Array.Empty<NotSeenAsset>(),
            Retired = paging.Only is null or NotSeenPaging.RetiredList ? all.Retired.Skip(paging.RetiredSkip).Take(take).ToList() : Array.Empty<NotSeenAsset>(),
            NotSeenTotalRead = all.NotSeen.Count, RetiredTotalRead = all.Retired.Count, NotSeenSkip = paging.NotSeenSkip, RetiredSkip = paging.RetiredSkip,
        };
    }
}

/// <summary>
/// #1400 which page of each "Not seen anymore" list to read (rows skipped, rows per page); <paramref name="Only"/> reads one
/// list alone (<see cref="NotSeen"/> or <see cref="RetiredList"/>; null = both, and the active count).
/// </summary>
public sealed record NotSeenPaging(int NotSeenSkip, int RetiredSkip, int Take, string? Only = null)
{
    public const string NotSeen = "notseen";
    public const string RetiredList = "retired";
}

/// The outcome of an early retirement: retired, or why not.
public sealed record RetireEarlyResult(bool Retired, string Message);

/// <summary>
/// AN ASSET SECURITYINSIGHT NO LONGER SEES (#406, operator decisions 2026-10-06). The SQL CMDB job keeps
/// cmdbsync.AssetLifecycle (engine\asset-cmdb\_shared\SI-AssetLifecycle.ps1): an asset not seen for longer than the seen
/// window is "not seen", and after the grace period of its category (Pro settings SI_Pro_AssetRetire_GraceDays*, default 30
/// days) it is retired -- its open vulnerabilities then close as AssetRetired, never as fixed. The web app READS the table and
/// lets an Admin retire an asset that is in its grace period EARLY: one row changes state (not-seen -> retired) and one event
/// row records who and why; the engine does the rest on its next runs (the findings close, ServiceNow gets the state).
/// An asset seen again is reactivated by the engine, whoever retired it. Nothing is ever deleted.
/// </summary>
public interface IAssetLifecycleStore
{
    Task<NotSeenView> ReadAsync(int retiredDays, CancellationToken ct);
    /// #1400 one page of each list, with each list's total. Every store implements it itself (no fallback over a whole read).
    Task<NotSeenView> ReadPageAsync(int retiredDays, NotSeenPaging paging, CancellationToken ct);
    Task<RetireEarlyResult> RetireEarlyAsync(string ciKey, string by, string? reason, CancellationToken ct);
}

public sealed class SqlAssetLifecycleStore : IAssetLifecycleStore
{
    private readonly ISqlExecutor _sql;
    private readonly SI.Management.Core.ProData.ICiLifecycleRulesReader? _rules;
    public SqlAssetLifecycleStore(ISqlExecutor sql, SI.Management.Core.ProData.ICiLifecycleRulesReader? rules = null) { _sql = sql; _rules = rules; }

    // #855 W12 (owner 2026-10-21: "we need to be able to trust all data"): the page reads THE lifecycle -- the CI's own
    // (sidata.Ci.Lifecycle, the CI build's, from the settings in force: the same one every other view counts) -- never a
    // second one (cmdbsync.AssetLifecycle 'not-seen', the SQL CMDB job's table, could disagree with the CI list). The CI's
    // retire category (the CI build's Get-SICiRetireCategory, from its class, OS and Azure / identity type) gives its grace
    // period from the rules in force; "since" and "why" are the CI's own lifecycle evidence (si_lifecycle_since / _reason).
    // Retiring EARLY stays the existing action on cmdbsync.AssetLifecycle (keyed by the same CI key), unchanged.
    private const string ListBody = """
SELECT 1 AS HasTable, COUNT_BIG(*) OVER () AS Total, c.CiId AS CiKey, c.Name, x.Category, c.Class AS Kind, c.LastSeen,
       CASE WHEN c.Lifecycle = N'not_seen' THEN N'not-seen' ELSE N'retired' END AS State, x.Since AS StateChangedAt, x.Reason AS RetireReason,
       CONVERT(bigint, ISNULL(c.OpenFindings, 0)) AS OpenFindings,
       (SELECT STRING_AGG(CAST(t.FindingKey AS nvarchar(max)), N', ') FROM (SELECT TOP (5) s.FindingKey FROM sidata.CiFindingState AS s
         WHERE s.OwnerKey = c.CiId AND s.State <> N'closed' ORDER BY s.Severity, s.FindingKey) AS t) AS TopFindings
FROM sidata.Ci AS c
CROSS APPLY (SELECT CASE WHEN ISJSON(c.DocJson) = 1 THEN TRY_CONVERT(datetime2(0), JSON_VALUE(c.DocJson, '$.si_lifecycle_since'), 127) END AS Since,
                    CASE WHEN ISJSON(c.DocJson) = 1 THEN LEFT(JSON_VALUE(c.DocJson, '$.si_lifecycle_reason'), 400) END AS Reason,
                    CASE WHEN c.Class = N'device' AND ISJSON(c.DocJson) = 1 AND LOWER(CONCAT(JSON_VALUE(c.DocJson, '$.si_azure_resource_type'), N'')) LIKE N'microsoft.compute/virtualmachines%' THEN N'azure-vm'
                         WHEN c.Class = N'device' AND ISJSON(c.DocJson) = 1 AND (LOWER(CONCAT(JSON_VALUE(c.DocJson, '$.si_os_name'), N' ', JSON_VALUE(c.DocJson, '$.si_os_platform'), N' ', JSON_VALUE(c.DocJson, '$.si_device_category'))) LIKE N'%server%'
                                                                               OR NULLIF(JSON_VALUE(c.DocJson, '$.si_arc_status'), N'') IS NOT NULL) THEN N'server'
                         WHEN c.Class = N'device' THEN N'client-pc'
                         WHEN c.Class = N'identity' AND ISJSON(c.DocJson) = 1 AND LOWER(CONCAT(JSON_VALUE(c.DocJson, '$.si_identity_type'), N'')) LIKE N'%service%' THEN N'service-principal'
                         WHEN c.Class = N'identity' THEN N'user'
                         WHEN c.Class = N'cloud_resource' THEN N'azure-resource'
                         ELSE N'other' END AS Category) AS x
WHERE (@State = N'not_seen' AND c.Lifecycle = N'not_seen') OR (@State = N'retired' AND c.Lifecycle = N'retired' AND x.Since >= DATEADD(day, -@Days, SYSUTCDATETIME()))
ORDER BY c.LastSeen, x.Since DESC, c.Name, c.CiId
OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY
OPTION (RECOMPILE)
""";

    /// #1400 (owner 2026-11-26: "memory issues must not be a problem in any step"): the rows of one list a page shows -- each
    /// list (not seen, retired recently) is read a page at a time, its total counted in SQL; an export reads every page.
    public const int PageSize = 200;

    private static string Quote(string sql) => sql.Replace("'", "''");

    /// The CIs in their grace period (lifecycle not seen) and the ones retired in the last @Days days, with their open findings,
    /// from sidata.Ci (#855 W12). No CI table = HasTable 0. Read only.
    public static readonly string ListSql =
        "SET NOCOUNT ON;\n" +
        "IF OBJECT_ID(N'sidata.Ci') IS NULL OR OBJECT_ID(N'sidata.CiFindingState') IS NULL\n    SELECT 0 AS HasTable;\n" +
        "ELSE\n    EXEC sp_executesql N'" + Quote(ListBody) + "', N'@Days int, @State nvarchar(16), @Skip int, @Take int', @Days = @Days, @State = @State, @Skip = @Skip, @Take = @Take;\n";

    /// How many CIs are active (the CI's own lifecycle; none = active) -- the count the CI list's default shows.
    public const string ActiveSql = """
IF OBJECT_ID(N'sidata.Ci') IS NULL SELECT CAST(0 AS bigint) AS Active;
ELSE EXEC (N'SELECT COUNT_BIG(*) AS Active FROM sidata.Ci WHERE ISNULL(Lifecycle, N''active'') = N''active''');
""";

    /// Retire ONE asset in its grace period early: only from not-seen (an active asset is seen; a retired one is retired
    /// already), one transaction, one event row with who and why. Returns Outcome retired | unknown | state:<state> | missing.
    public const string RetireEarlySql = """
SET NOCOUNT ON;
SET XACT_ABORT ON;
IF OBJECT_ID(N'cmdbsync.AssetLifecycle') IS NULL OR OBJECT_ID(N'cmdbsync.AssetLifecycleEvent') IS NULL
BEGIN
    SELECT N'missing' AS Outcome;
    RETURN;
END
BEGIN TRAN;
DECLARE @from nvarchar(16) = (SELECT State FROM cmdbsync.AssetLifecycle WITH (UPDLOCK, ROWLOCK) WHERE CiKey = @CiKey);
IF @from IS NULL BEGIN ROLLBACK; SELECT N'unknown' AS Outcome; RETURN; END
IF @from <> N'not-seen' BEGIN ROLLBACK; SELECT N'state:' + @from AS Outcome; RETURN; END
UPDATE cmdbsync.AssetLifecycle
SET State = N'retired', StateChangedAt = SYSUTCDATETIME(), RetiredAt = SYSUTCDATETIME(), RetiredBy = @By, RetireReason = @Reason, UpdatedAt = SYSUTCDATETIME()
WHERE CiKey = @CiKey AND State = N'not-seen';
INSERT cmdbsync.AssetLifecycleEvent (CiKey, Change, FromState, ToState, Reason, Actor)
VALUES (@CiKey, N'retired-early', @from, N'retired', @Reason, @By);
COMMIT;
SELECT N'retired' AS Outcome;
""";

    /// The first page of each list (<see cref="ReadPageAsync"/>).
    public Task<NotSeenView> ReadAsync(int retiredDays, CancellationToken ct) => ReadPageAsync(retiredDays, new NotSeenPaging(0, 0, PageSize), ct);

    /// <summary>
    /// #1400 one page of each list -- the CIs not seen (their grace period) and the ones retired in the last
    /// <paramref name="retiredDays"/> days -- with each list's total; <see cref="NotSeenPaging.Only"/> reads one list alone (an
    /// export's next chunk). Never every not-seen CI in one read.
    /// </summary>
    public async Task<NotSeenView> ReadPageAsync(int retiredDays, NotSeenPaging paging, CancellationToken ct)
    {
        var days = Math.Clamp(retiredDays, 1, 365);
        var take = Math.Clamp(paging.Take, 1, SI.Management.Core.ProData.ProDataFilters.ExportChunk);
        // the grace period of each CI's category from the lifecycle rules in force (#859: never a day count of the page's own)
        var rules = SI.Management.Core.ProData.CiLifecycleDefinitions.Defaults;
        var rulesRead = false;
        async Task<(bool Has, IReadOnlyList<NotSeenAsset> Rows, long Total)> List(string state, string mark, int skip)
        {
            var rows = await _sql.QueryAsync(ListSql, new Dictionary<string, object?> { ["Days"] = days, ["State"] = state, ["Skip"] = Math.Max(0, skip), ["Take"] = take }, ct);
            if (rows.Count == 0 && skip > 0)
            {
                // a page past the last one: the list's total is still said (read from its first row), never 0
                var head = await _sql.QueryAsync(ListSql, new Dictionary<string, object?> { ["Days"] = days, ["State"] = state, ["Skip"] = 0, ["Take"] = 1 }, ct);
                if (head.Count > 0 && (head[0].Long("HasTable") ?? 0) != 1) return (false, Array.Empty<NotSeenAsset>(), 0);
                return (true, Array.Empty<NotSeenAsset>(), head.Count == 0 ? 0 : head[0].Long("Total") ?? 1);
            }
            if (rows.Count == 0) return (true, Array.Empty<NotSeenAsset>(), 0);
            if ((rows[0].Long("HasTable") ?? 0) != 1) return (false, Array.Empty<NotSeenAsset>(), 0);
            if (!rulesRead && _rules is not null)
            {
                rulesRead = true;
                try { rules = await _rules.ReadAsync(ct); }
                catch (Exception ex) when (ex is not OperationCanceledException) { _ = ex; }
            }
            var list = rows.Select(r =>
            {
                var cat = r.Str("Category") ?? "other";
                var grace = rules.Grace(cat);
                var seen = r.Date("LastSeen");
                var st = r.Str("State") ?? "";
                var since = r.Date("StateChangedAt");
                return new NotSeenAsset(r.Str("CiKey") ?? "", r.Str("Name"), cat, r.Str("Kind"), seen ?? DateTime.MinValue, grace,
                    seen is { } s ? s.AddDays(grace) : null, st, since, st == "retired" ? since : null,
                    null, r.Str("RetireReason"), r.Long("OpenFindings") ?? 0, r.Str("TopFindings"));
            }).Where(a => a.State == mark).ToList();
            return (true, list, Math.Max(list.Count + Math.Max(0, skip), rows[0].Long("Total") ?? list.Count));
        }
        (bool Has, IReadOnlyList<NotSeenAsset> Rows, long Total) notSeen = paging.Only is null or NotSeenPaging.NotSeen ? await List("not_seen", "not-seen", paging.NotSeenSkip) : (true, Array.Empty<NotSeenAsset>(), 0L);
        if (!notSeen.Has) return NotSeenView.Missing;
        (bool Has, IReadOnlyList<NotSeenAsset> Rows, long Total) retired = paging.Only is null or NotSeenPaging.RetiredList ? await List("retired", "retired", paging.RetiredSkip) : (true, Array.Empty<NotSeenAsset>(), 0L);
        if (!retired.Has) return NotSeenView.Missing;
        return new NotSeenView(true, notSeen.Rows, retired.Rows, paging.Only is null ? await ActiveAsync(ct) : 0)
        {
            NotSeenTotalRead = notSeen.Total, RetiredTotalRead = retired.Total, NotSeenSkip = paging.NotSeenSkip, RetiredSkip = paging.RetiredSkip,
        };
    }

    private async Task<long> ActiveAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ActiveSql, new Dictionary<string, object?>(), ct);
        return rows.FirstOrDefault()?.Long("Active") ?? 0;
    }

    public async Task<RetireEarlyResult> RetireEarlyAsync(string ciKey, string by, string? reason, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(ciKey)) return new RetireEarlyResult(false, "No asset was chosen.");
        var why = string.IsNullOrWhiteSpace(reason) ? "retired early by an Admin" : reason.Trim();
        if (why.Length > 400) why = why[..400];
        var rows = await _sql.QueryAsync(RetireEarlySql, new Dictionary<string, object?> { ["CiKey"] = ciKey, ["By"] = by, ["Reason"] = why }, ct);
        var outcome = rows.FirstOrDefault()?.Str("Outcome") ?? "";
        return outcome switch
        {
            "retired" => new RetireEarlyResult(true, "Retired. Its open findings close as \"Asset retired\" (not as fixed) in the vulnerability connector's next run, and ServiceNow gets the state with the next hand-off. If the asset is seen again it becomes active again."),
            "unknown" => new RetireEarlyResult(false, "This asset is not tracked (any more)."),
            "missing" => new RetireEarlyResult(false, "This database has no asset lifecycle table yet. Run the Pro schema (setup) once."),
            _ when outcome.StartsWith("state:", StringComparison.Ordinal) => new RetireEarlyResult(false, $"Not retired: the asset is {outcome[6..]} now -- only an asset in its grace period (not seen) can be retired early."),
            _ => new RetireEarlyResult(false, "Not retired: the database gave no answer."),
        };
    }
}
