using System.Globalization;
using SI.Management.Web.Data;

namespace SI.Management.Web.Performance;

/// One pipeline run (cfg.FlowRun).
public sealed record PerfRun(string Id, string Trigger, string State, DateTime StartedUtc, DateTime? EndedUtc, DateTime? HeartbeatUtc)
{
    /// How long it ran: to its end, or (still running) to now.
    public TimeSpan? Duration(DateTime nowUtc) => EndedUtc is { } e ? e - StartedUtc : State == "Running" ? nowUtc - StartedUtc : null;
}

/// One step of one run (cfg.FlowStepRun).
public sealed record PerfStep(string RunId, int Order, int Group, string Job, string State, DateTime? StartedUtc, DateTime? EndedUtc)
{
    public string Key => PerfRules.StepKey(Job);
    public double? Minutes => StartedUtc is { } s && EndedUtc is { } e && e >= s ? (e - s).TotalMinutes : null;
}

/// One step's time over the runs shown: minutes per run (oldest first, null = it did not run well in that run) and its typical time.
public sealed record PerfStepTrend(string Key, string Label, IReadOnlyList<double?> Minutes, double? TypicalMinutes, double? LastMinutes);

/// The run in progress: steps done / total, the step(s) running and since when, the estimated end.
/// Confidence: known (every step left has an earlier time), partial (a step has none -- the end is at least that), overdue
/// (a step runs past its earlier time -- the end is at least that).
public sealed record PerfProgress(PerfRun Run, int Done, int Total, IReadOnlyList<(string Label, DateTime? SinceUtc)> Running, DateTime? EstimatedEndUtc, string Confidence, bool Stalled);

/// One source's or report's collection state -- the heartbeat's Collections facts (engine\_shared\SI-HeartbeatJob.ps1).
/// State: complete | partial | failed | never | running.
public sealed record PerfSource(string Kind, string Label, string State, DateTime? LastGoodUtc, DateTime? LastAttemptUtc, long? Collected, long? Expected, string? Note, bool Stale);

/// One hour of one metric (cfg.PerfSample).
public sealed record PerfPoint(DateTime HourUtc, double? Avg, double? Max);

/// A size the install runs, as the heartbeat read it last.
public sealed record PerfSize(string Kind, string Name, string? Sku, double? Capacity, double? MaxBytes, double? Cpu, double? MemoryGi, DateTime ReadUtc);

/// A size change an Admin asked for on this page (the customer's setting) -- requested -> applied by the updater.
public sealed record PerfSizeRequest(string Setting, string Value, DateTime? AtUtc, string? By, long Version);

/// The Pro database as it answers about itself (DATABASEPROPERTYEX / FILEPROPERTY -- no extra right).
public sealed record PerfDbSelf(string? ServiceObjective, string? Edition, long? UsedMb, long? MaxMb);

/// Everything the Performance page reads from SQL.
public sealed record PerformanceData(
    IReadOnlyList<PerfRun> Runs, IReadOnlyList<PerfStep> Steps, IReadOnlyList<SqlRow> CollectionRows, bool HasSamples,
    IReadOnlyDictionary<(string Kind, string Name, string Metric), IReadOnlyList<PerfPoint>> Series, IReadOnlyList<PerfSize> Sizes,
    PerfDbSelf Db, IReadOnlyDictionary<string, PerfSizeRequest> Requests, double PacingHighPercent)
{
    public static readonly PerformanceData Empty = new([], [], [], false, new Dictionary<(string, string, string), IReadOnlyList<PerfPoint>>(), [],
        new PerfDbSelf(null, null, null, null), new Dictionary<string, PerfSizeRequest>(), PerfRules.PacingHighDefault);
}

public interface IPerformanceStore
{
    Task<PerformanceData> ReadAsync(CancellationToken ct);
}

/// <summary>
/// Operations &gt; Performance (#757): reads SQL only -- the run records (cfg.FlowRun / cfg.FlowStepRun), the collection
/// state the heartbeat's Collections field reads (sidata.SourceState / RecordCollection / Collection / CollectionPartial /
/// RaReportStatus / CiBuildState -- the SAME statement), the hourly load samples the heartbeat job stores (cfg.PerfSample),
/// the Pro database's own size answer and the size settings an Admin asked for. db_datareader only: the web app gets no
/// Azure right and no VIEW DATABASE STATE (CR8).
/// </summary>
public sealed class SqlPerformanceStore : IPerformanceStore
{
    private readonly ISqlExecutor _sql;
    public SqlPerformanceStore(ISqlExecutor sql) => _sql = sql;

    public const int RunsShown = 20;

    public const string RunsSql = """
IF OBJECT_ID(N'cfg.FlowRun') IS NOT NULL
SELECT TOP (20) FlowRunId, Trg, State, StartedUtc, EndedUtc, HeartbeatUtc FROM cfg.FlowRun WHERE FlowId = N'daily' ORDER BY StartedUtc DESC;
""";

    public const string StepsSql = """
IF OBJECT_ID(N'cfg.FlowStepRun') IS NOT NULL
SELECT s.FlowRunId, s.StepOrder, s.GroupNo, s.Job, s.State, s.StartedUtc, s.EndedUtc
FROM cfg.FlowStepRun AS s
JOIN (SELECT TOP (20) FlowRunId FROM cfg.FlowRun WHERE FlowId = N'daily' ORDER BY StartedUtc DESC) AS r ON r.FlowRunId = s.FlowRunId;
""";

    /// THE SAME read as the heartbeat's Collections field (engine\_shared\SI-HeartbeatJob.ps1, Get-SIHeartbeatCollectionsSql) --
    /// a test keeps the two equal, so the page and Invardia never disagree about a source.
    public const string CollectionsSql = """
SET NOCOUNT ON;
DECLARE @r TABLE (K NVARCHAR(16) NOT NULL, Name NVARCHAR(64) NULL, T1 DATETIME2(3) NULL, T2 DATETIME2(3) NULL, F1 INT NULL, F2 INT NULL, N1 BIGINT NULL, N2 BIGINT NULL, N3 BIGINT NULL, Txt NVARCHAR(400) NULL, N4 BIGINT NULL);
IF OBJECT_ID('sidata.SourceState') IS NOT NULL
    INSERT @r (K, Name, T1, T2, F1) SELECT N'source', Source, LastGoodAt, LastAttemptAt, CAST(LastAttemptOk AS INT) FROM sidata.SourceState;
IF OBJECT_ID('sidata.RecordCollection') IS NOT NULL
    INSERT @r (K, Name, T1, F1, N1, N2)
    SELECT N'records', e.Engine, e.T, h.Held, h.Recs, h.Users
    FROM (SELECT Engine, MAX(CollectionTime) AS T FROM sidata.RecordCollection WHERE Engine <> N'' GROUP BY Engine) e
    CROSS APPLY (SELECT SUM(CAST(c.Records AS BIGINT)) AS Recs, MAX(CASE WHEN c.State <> N'good' THEN 1 ELSE 0 END) AS Held,
                        SUM(CASE WHEN c.RecordType = N'user' THEN CAST(c.Records AS BIGINT) END) AS Users
                 FROM sidata.RecordCollection c WHERE c.Engine = e.Engine AND c.CollectionTime = e.T) h;
IF OBJECT_ID('sidata.Collection') IS NOT NULL
BEGIN
    DECLARE @k NVARCHAR(16), @i INT = 0;
    WHILE @i < 2
    BEGIN
        SET @k = CASE WHEN @i = 0 THEN N'Detailed' ELSE N'Summary' END; SET @i += 1;
        DECLARE @cid INT = NULL, @ct DATETIME2(3) = NULL, @cl DATETIME2(3) = NULL, @lt DATETIME2(3) = NULL, @ls NVARCHAR(16) = NULL;
        SELECT TOP (1) @cid = CollectionId, @ct = CollectionTime, @cl = LoadedAt FROM sidata.Collection WHERE Kind = @k AND Status = N'Complete' ORDER BY CollectionTime DESC;
        SELECT TOP (1) @lt = CollectionTime, @ls = Status FROM sidata.Collection WHERE Kind = @k ORDER BY CollectionTime DESC;
        IF @lt IS NULL CONTINUE;
        DECLARE @part INT = 0, @why NVARCHAR(400) = NULL, @exp BIGINT = NULL, @sto BIGINT = NULL, @unk BIGINT = NULL, @nc BIGINT = NULL, @nh BIGINT = NULL;
        IF @cid IS NOT NULL AND OBJECT_ID('sidata.CollectionPartial') IS NOT NULL
            SELECT @part = 1, @why = LEFT(Reason, 400) FROM sidata.CollectionPartial WHERE CollectionId = @cid;
        IF OBJECT_ID('sidata.RaReportStatus') IS NOT NULL
            SELECT @exp = SUM(ExpectedRows), @sto = SUM(StoredRows), @unk = SUM(CASE WHEN ExpectedRows IS NULL THEN 1 ELSE 0 END),
                   @nc = SUM(CASE WHEN State = N'NotComplete' THEN 1 ELSE 0 END)
            FROM sidata.RaReportStatus WHERE CollectionTime = @lt AND Grain = @k;
        -- #902: of them, the reports held ON PURPOSE at their last complete result (a HoldKind, no hold-back)
        IF @nc > 0 AND COL_LENGTH('sidata.RaReportStatus', 'HoldKind') IS NOT NULL AND COL_LENGTH('sidata.RaReportStatus', 'HeldRaReport') IS NOT NULL
            EXEC sp_executesql N'SELECT @h = COUNT_BIG(*) FROM sidata.RaReportStatus WHERE CollectionTime = @t AND Grain = @g AND State = N''NotComplete'' AND NULLIF(HoldKind, N'''') IS NOT NULL AND HeldRaReport IS NULL',
                 N'@t datetime2(3), @g nvarchar(16), @h bigint OUTPUT', @t = @lt, @g = @k, @h = @nh OUTPUT;
        INSERT @r (K, Name, T1, T2, F1, F2, N1, N2, N3, Txt, N4)
        VALUES (N'ra', @k, ISNULL(@cl, @ct), @lt, CASE WHEN @ls = N'Complete' THEN 1 ELSE 0 END, @part,
                CASE WHEN @unk = 0 THEN @exp END, @sto, @nc, @why, @nh);
    END
END
IF OBJECT_ID('sidata.CiBuildState') IS NOT NULL
    INSERT @r (K, Name, T1, Txt) SELECT N'ci', Name, UpdatedAt, LEFT(Value, 400) FROM sidata.CiBuildState WHERE Name IN (N'LastBuildStatus', N'LastBuildStart');
SELECT K, Name, T1, T2, F1, F2, N1, N2, N3, Txt, N4 FROM @r;
""";

    /// The load of the last 7 days and the newest sizes; one row 'probe' says whether the table is there at all.
    public const string SamplesSql = """
IF OBJECT_ID(N'cfg.PerfSample') IS NULL
    SELECT N'probe' AS Kind, CAST(NULL AS nvarchar(128)) AS Name, CAST(NULL AS nvarchar(64)) AS Metric, CAST(NULL AS datetime2(0)) AS TimeUtc, CAST(NULL AS float) AS [Avg], CAST(NULL AS float) AS [Max], CAST(NULL AS nvarchar(64)) AS [Text], 0 AS HasTable;
ELSE
    SELECT N'probe' AS Kind, NULL AS Name, NULL AS Metric, NULL AS TimeUtc, NULL AS [Avg], NULL AS [Max], NULL AS [Text], 1 AS HasTable
    UNION ALL
    SELECT Kind, Name, Metric, TimeUtc, [Avg], [Max], [Text], 1 FROM cfg.PerfSample
    WHERE (Metric NOT LIKE N'size.%' AND TimeUtc >= DATEADD(day, -7, SYSUTCDATETIME())) OR (Metric LIKE N'size.%' AND TimeUtc >= DATEADD(day, -2, SYSUTCDATETIME()));
""";

    /// The Pro database about itself -- any user may ask these (no VIEW DATABASE STATE) -- the same used / max the heartbeat's
    /// Counts carry (SI-TelemetryCounts.ps1); and the size settings asked for here, with the write pacing's high mark.
    public const string DbSql = """
SELECT CAST(DATABASEPROPERTYEX(DB_NAME(), 'ServiceObjective') AS nvarchar(64)) AS ServiceObjective,
       CAST(DATABASEPROPERTYEX(DB_NAME(), 'Edition') AS nvarchar(64)) AS Edition,
       (SELECT SUM(CAST(FILEPROPERTY(name, 'SpaceUsed') AS bigint)) * 8 / 1024 FROM sys.database_files WHERE type_desc = 'ROWS') AS UsedMb,
       CAST(DATABASEPROPERTYEX(DB_NAME(), 'MaxSizeInBytes') AS bigint) / 1048576 AS MaxMb;
""";

    public const string RequestsSql = """
IF OBJECT_ID(N'cfg.Setting') IS NOT NULL
SELECT Name, ValueJson, UpdatedAt, UpdatedBy, CONVERT(bigint, RowVersion) AS Version FROM cfg.Setting
WHERE Scope = N'solution' AND Name IN (@SqlKey, @WebCpuKey, @WebMemoryKey, N'SI_SqlPacing_HighPercent');
""";

    private static Dictionary<string, object?> None => new();
    private static DateTime? Utc(SqlRow r, string c) => r.Date(c) is { } d ? DateTime.SpecifyKind(d, DateTimeKind.Utc) : null;
    private static double? Dbl(SqlRow r, string c) => r.TryGetValue(c, out var v) && v is not null ? Convert.ToDouble(v, CultureInfo.InvariantCulture) : null;

    public async Task<PerformanceData> ReadAsync(CancellationToken ct)
    {
        var runs = (await _sql.QueryAsync(RunsSql, None, ct)).Where(r => r.Str("FlowRunId") is { Length: > 0 })
            .Select(r => new PerfRun(r.Str("FlowRunId")!, r.Str("Trg") ?? "", r.Str("State") ?? "", Utc(r, "StartedUtc") ?? DateTime.MinValue, Utc(r, "EndedUtc"), Utc(r, "HeartbeatUtc"))).ToList();
        var steps = runs.Count == 0 ? new List<PerfStep>() : (await _sql.QueryAsync(StepsSql, None, ct))
            .Select(r => new PerfStep(r.Str("FlowRunId") ?? "", (int)(r.Long("StepOrder") ?? 0), (int)(r.Long("GroupNo") ?? 0), r.Str("Job") ?? "", r.Str("State") ?? "", Utc(r, "StartedUtc"), Utc(r, "EndedUtc"))).ToList();

        IReadOnlyList<SqlRow> collections = [];
        try { collections = await _sql.QueryAsync(CollectionsSql, None, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { /* an older data schema: no collection state -- the page says so */ }

        var hasSamples = false;
        var series = new Dictionary<(string, string, string), List<PerfPoint>>();
        var sizeRows = new Dictionary<(string Kind, string Name), Dictionary<string, (double? V, string? T, DateTime At)>>();
        foreach (var r in await _sql.QueryAsync(SamplesSql, None, ct))
        {
            if (r.Str("Kind") == "probe") { hasSamples = (r.Long("HasTable") ?? 0) == 1; continue; }
            var kind = r.Str("Kind") ?? ""; var name = r.Str("Name") ?? ""; var metric = r.Str("Metric") ?? "";
            var t = Utc(r, "TimeUtc") ?? DateTime.MinValue;
            if (metric.StartsWith("size.", StringComparison.Ordinal))
            {
                if (!sizeRows.TryGetValue((kind, name), out var m)) sizeRows[(kind, name)] = m = new(StringComparer.Ordinal);
                if (!m.TryGetValue(metric, out var have) || have.At < t) m[metric] = (Dbl(r, "Avg"), r.Str("Text"), t);
                continue;
            }
            if (!series.TryGetValue((kind, name, metric), out var list)) series[(kind, name, metric)] = list = new();
            list.Add(new PerfPoint(t, Dbl(r, "Avg"), Dbl(r, "Max")));
        }
        var sizes = sizeRows.Select(kv =>
        {
            var m = kv.Value;
            (double? V, string? T, DateTime At) G(string k) => m.TryGetValue(k, out var x) ? x : (null, null, DateTime.MinValue);
            return new PerfSize(kv.Key.Kind, kv.Key.Name, G("size.sku").T, G("size.sku").V, G("size.maxBytes").V, G("size.cpu").V, G("size.memoryGi").V, m.Values.Max(x => x.At));
        }).OrderBy(s => s.Kind).ThenBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();

        var self = new PerfDbSelf(null, null, null, null);
        try
        {
            var d = (await _sql.QueryAsync(DbSql, None, ct)).FirstOrDefault();
            if (d is not null) self = new PerfDbSelf(d.Str("ServiceObjective"), d.Str("Edition"), d.Long("UsedMb"), d.Long("MaxMb"));
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { /* the database did not answer about itself: "not available" */ }

        var requests = new Dictionary<string, PerfSizeRequest>(StringComparer.OrdinalIgnoreCase);
        var pacing = PerfRules.PacingHighDefault;
        foreach (var r in await _sql.QueryAsync(RequestsSql, new Dictionary<string, object?>
                 {
                     ["SqlKey"] = PerfSizing.SqlKey, ["WebCpuKey"] = PerfSizing.WebCpuKey, ["WebMemoryKey"] = PerfSizing.WebMemoryKey,
                 }, ct))
        {
            var name = r.Str("Name") ?? "";
            var v = PerfSizing.Unquote(r.Str("ValueJson"));
            if (name.Equals("SI_SqlPacing_HighPercent", StringComparison.OrdinalIgnoreCase))
            {
                if (double.TryParse(v, NumberStyles.Float, CultureInfo.InvariantCulture, out var hp) && hp is >= 1 and <= 100) pacing = hp;
                continue;
            }
            if (v.Length > 0) requests[name] = new PerfSizeRequest(name, v, Utc(r, "UpdatedAt"), r.Str("UpdatedBy"), r.Long("Version") ?? 0);
        }

        return new PerformanceData(runs, steps, collections, hasSamples,
            series.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<PerfPoint>)kv.Value.OrderBy(p => p.HourUtc).ToList()), sizes, self, requests, pacing);
    }
}
