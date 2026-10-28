using System.Globalization;
using SI.Management.Web.Data;

namespace SI.Management.Web.QuerySplitting;

/// One run of one report, as the Risk Analysis run recorded it (cfg.RaBucketHistory).
public sealed record BucketRun(DateTime RunUtc, int StartCount, int Count, string Decided, long? ResultRows, long? MaxBucketRows, int? UsualCount, bool Jump);

/// A one-time reset an Admin staged and committed that the next run has not consumed yet (cfg.RaBucketReset).
public sealed record BucketResetPending(string Template, string? Report, DateTime RequestedUtc, string RequestedBy);

/// One report of one template as the page shows it.
public sealed record BucketRow(string Template, string Report, int? Count, DateTime? ConfirmedUtc, IReadOnlyList<BucketRun> Runs, BucketResetPending? Reset)
{
    public BucketRun? Last => Runs.Count > 0 ? Runs[0] : null;
    /// The count the report had in the run before the last one (what "before" means on the page).
    public int? Before => Runs.Count > 1 ? Runs[1].Count : null;
    /// The report's usual count: the median of its runs before the last one (3 runs at least), as the run works it out.
    public int? Usual => BucketText.Median(Runs.Skip(1).Select(r => r.Count).ToList());
    /// When the count last changed: the newest run whose count differs from the run before it.
    public DateTime? LastChangeUtc
    {
        get
        {
            for (var i = 0; i + 1 < Runs.Count; i++) if (Runs[i].Count != Runs[i + 1].Count) return Runs[i].RunUtc;
            return null;
        }
    }
    public bool Jump => Last?.Jump ?? false;
    public int? Now => Count ?? Last?.Count;
}

public sealed record BucketView(bool HasTables, IReadOnlyList<BucketRow> Rows)
{
    public static readonly BucketView Missing = new(false, Array.Empty<BucketRow>());
    public IReadOnlyList<string> Templates => Rows.Select(r => r.Template).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(t => t, StringComparer.OrdinalIgnoreCase).ToList();
}

public interface IQuerySplittingStore
{
    Task<BucketView> ReadAsync(CancellationToken ct);
    /// One one-time reset (report null = every report of the template), with its cfg.ChangeLog row, in one transaction.
    Task<string> RequestResetAsync(string template, string? report, string reason, string old, string by, CancellationToken ct);
}

/// <summary>
/// Operations &gt; Risk Analysis query splitting (#640): the bucket counts the Risk Analysis runs keep in the Pro database.
/// Reads cfg.RaBucketState / cfg.RaBucketHistory / cfg.RaBucketReset (db_datareader); writes ONLY a reset request
/// (cfg.RaBucketReset INSERT, granted in SI-ManagementGrants.ps1) with its cfg.ChangeLog row.
/// </summary>
public sealed class SqlQuerySplittingStore : IQuerySplittingStore
{
    private readonly ISqlExecutor _sql;
    public SqlQuerySplittingStore(ISqlExecutor sql) => _sql = sql;

    public const int RunsKept = 30;

    public const string ProbeSql = """
SELECT CASE WHEN OBJECT_ID(N'cfg.RaBucketState') IS NOT NULL AND OBJECT_ID(N'cfg.RaBucketHistory') IS NOT NULL AND OBJECT_ID(N'cfg.RaBucketReset') IS NOT NULL THEN 1 ELSE 0 END AS HasTables
""";

    /// The newest remembered count of each report (a report holds one per query fingerprint; the newest is the live one).
    public const string StateSql = """
SELECT s.Template, s.ReportName, s.BucketCount, s.ConfirmedUtc
FROM (SELECT Template, ReportName, BucketCount, ConfirmedUtc, ROW_NUMBER() OVER (PARTITION BY Template, ReportName ORDER BY UpdatedUtc DESC) AS n FROM cfg.RaBucketState) AS s
WHERE s.n = 1
""";

    public const string HistorySql = """
SELECT h.Template, h.ReportName, h.RunUtc, h.StartCount, h.BucketCount, h.Decided, h.ResultRows, h.MaxBucketRows, h.UsualCount, CAST(h.Jump AS int) AS Jump
FROM (SELECT Template, ReportName, RunUtc, StartCount, BucketCount, Decided, ResultRows, MaxBucketRows, UsualCount, Jump, ROW_NUMBER() OVER (PARTITION BY Template, ReportName ORDER BY Id DESC) AS n FROM cfg.RaBucketHistory) AS h
WHERE h.n <= @Keep
ORDER BY h.Template, h.ReportName, h.RunUtc DESC
""";

    public const string PendingSql = """
SELECT Template, ReportName, RequestedUtc, RequestedBy FROM cfg.RaBucketReset WHERE AppliedUtc IS NULL ORDER BY ResetId
""";

    public const string ResetSql = """
SET XACT_ABORT ON;
IF OBJECT_ID(N'cfg.RaBucketReset') IS NULL BEGIN SELECT N'Missing' AS Outcome; RETURN; END;
BEGIN TRAN;
INSERT cfg.RaBucketReset (Template, ReportName, RequestedBy, Reason) VALUES (@Template, @ReportName, @By, LEFT(@Reason, 400));
INSERT cfg.ChangeLog (Name, Scope, Kind, Action, OldValue, NewValue, ChangedBy, Reason)
VALUES (LEFT(N'bucket-reset/' + @Template + N'/' + COALESCE(@ReportName, N'*'), 128), N'riskanalysis', N'bucketreset', N'Reset', @Old,
        N'sized again on the next run of ' + @Template, @By, LEFT(@Reason, 400));
COMMIT;
SELECT N'Saved' AS Outcome;
""";

    private static readonly Dictionary<string, object?> None = new();

    public async Task<BucketView> ReadAsync(CancellationToken ct)
    {
        var probe = await _sql.QueryAsync(ProbeSql, None, ct);
        if ((probe.FirstOrDefault()?.Long("HasTables") ?? 0) != 1) return BucketView.Missing;
        var state = await _sql.QueryAsync(StateSql, None, ct);
        var history = await _sql.QueryAsync(HistorySql, new Dictionary<string, object?> { ["Keep"] = RunsKept }, ct);
        var pending = await _sql.QueryAsync(PendingSql, None, ct);
        return BucketText.Build(
            state.Select(r => (r.Str("Template") ?? "", r.Str("ReportName") ?? "", (int?)(int)(r.Long("BucketCount") ?? 0), r.Date("ConfirmedUtc"))).ToList(),
            history.Select(r => (r.Str("Template") ?? "", r.Str("ReportName") ?? "", new BucketRun(r.Date("RunUtc") ?? DateTime.MinValue, (int)(r.Long("StartCount") ?? 0),
                (int)(r.Long("BucketCount") ?? 0), r.Str("Decided") ?? "", r.Long("ResultRows"), r.Long("MaxBucketRows"), (int?)r.Long("UsualCount"), (r.Long("Jump") ?? 0) == 1))).ToList(),
            pending.Select(r => new BucketResetPending(r.Str("Template") ?? "", r.Str("ReportName"), r.Date("RequestedUtc") ?? DateTime.MinValue, r.Str("RequestedBy") ?? "")).ToList());
    }

    public async Task<string> RequestResetAsync(string template, string? report, string reason, string old, string by, CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(ResetSql, new Dictionary<string, object?>
        {
            ["Template"] = template, ["ReportName"] = report, ["Reason"] = reason, ["Old"] = old, ["By"] = by,
        }, ct);
        return rows.FirstOrDefault()?.Str("Outcome") ?? "";
    }
}

/// PURE helpers of the page.
public static class BucketText
{
    /// The median of the counts; null with fewer than 3 (the run's rule for "usual").
    public static int? Median(IReadOnlyList<int> counts)
    {
        var c = counts.Where(x => x >= 1).OrderBy(x => x).ToList();
        if (c.Count < 3) return null;
        var mid = c.Count / 2;
        return c.Count % 2 == 1 ? c[mid] : (c[mid - 1] + c[mid]) / 2;
    }

    public static BucketView Build(IReadOnlyList<(string Template, string Report, int? Count, DateTime? Confirmed)> state,
        IReadOnlyList<(string Template, string Report, BucketRun Run)> history, IReadOnlyList<BucketResetPending> pending)
    {
        var keys = state.Select(s => (s.Template, s.Report)).Concat(history.Select(h => (h.Template, h.Report)))
            .Distinct().OrderBy(k => k.Report, StringComparer.OrdinalIgnoreCase).ThenBy(k => k.Template, StringComparer.OrdinalIgnoreCase).ToList();
        var rows = new List<BucketRow>();
        foreach (var (t, r) in keys)
        {
            var s = state.FirstOrDefault(x => x.Template == t && x.Report == r);
            var runs = history.Where(h => h.Template == t && h.Report == r).Select(h => h.Run).OrderByDescending(x => x.RunUtc).ToList();
            var reset = pending.LastOrDefault(p => string.Equals(p.Template, t, StringComparison.OrdinalIgnoreCase) && (p.Report is null || p.Report == r));
            rows.Add(new BucketRow(t, r, s.Report is null ? null : s.Count, s.Report is null ? null : s.Confirmed, runs, reset));
        }
        return new BucketView(true, rows);
    }

    public static string DecidedLabel(string? decided) => decided switch
    {
        "cache" => "kept the remembered count",
        "probe" => "sized again by probing (1, 2, 4, 8 ...)",
        "measured" => "sized from its last measured result",
        "down" => "sized down: the last runs were far below every limit",
        "raised" => "raised: a bucket was too large and had to be split",
        "configured" => "the configured count",
        "incomplete" => "kept: the report was NOT COMPLETE, so its answers sized nothing",
        _ => decided ?? "",
    };

    /// What the row means, in plain words.
    public static string Note(BucketRow r)
    {
        var parts = new List<string>();
        if (r.Reset is { } p)
            parts.Add($"Reset asked by {p.RequestedBy} on {p.RequestedUtc.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)} UTC: the next run sizes this report again.");
        if (r.Jump)
            parts.Add("Far more buckets than usual (4 times its usual count, or above 256): the report's query or its data may be wrong. Check the report; reset it if the count is wrong.");
        if (r.Last is { } last) parts.Add("Last run: " + DecidedLabel(last.Decided) + ".");
        if (parts.Count == 0) parts.Add("Not run since bucket sizing moved to the database.");
        return string.Join(" ", parts);
    }
}
