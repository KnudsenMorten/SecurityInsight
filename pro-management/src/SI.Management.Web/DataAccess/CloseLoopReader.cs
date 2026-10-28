namespace SI.Management.Web.Data;

public sealed record CloseLoopBucket(string Status, string Reason, string Severity, long Items);
public sealed record CloseLoopEvent(DateTime At, string Action, string? FromState, string? ToState, string? Reason, string? RunId, string Actor, string? AssetName, string Cve);
public sealed record CloseLoopState(IReadOnlyList<CloseLoopBucket> Buckets, IReadOnlyList<CloseLoopEvent> Recent, string BucketQuery, string EventQuery);

/// The vulnerability close-loop's state (sql\si-vulnerability-target.sql), READ-ONLY: open / closed / reopened, by reason.
public interface ICloseLoopReader
{
    Task<CloseLoopState> ReadAsync(int recentEvents, CancellationToken ct);
}

public sealed class SqlCloseLoopReader : ICloseLoopReader
{
    /// Status: Closed rows by CloseReason; an Open row is "Reopened" when it carries a Reopen event (reason = the latest
    /// Reopen's), otherwise "Open".
    public const string BucketSql = """
SELECT s.Status, s.Reason, s.Severity, COUNT_BIG(*) AS Items
FROM (
    SELECT CASE WHEN i.State = N'Closed' THEN N'Closed' WHEN r.SysId IS NOT NULL THEN N'Reopened' ELSE N'Open' END AS Status,
           CASE WHEN i.State = N'Closed' THEN COALESCE(i.CloseReason, N'(no reason)')
                WHEN r.SysId IS NOT NULL THEN COALESCE(r.Reason, N'(no reason)') ELSE N'' END AS Reason,
           COALESCE(i.Severity, N'(none)') AS Severity
    FROM vuln.VulnerabilityItem AS i
    OUTER APPLY (SELECT TOP (1) e.SysId, e.Reason FROM vuln.VulnerabilityEvent AS e
                 WHERE e.SysId = i.SysId AND e.Action = N'Reopen' ORDER BY e.At DESC) AS r
) AS s
GROUP BY s.Status, s.Reason, s.Severity
ORDER BY s.Status, COUNT_BIG(*) DESC;
""";

    public const string EventSql = """
SELECT TOP (@Top) e.At, e.Action, e.FromState, e.ToState, e.Reason, e.RunId, e.Actor, i.AssetName, i.Cve
FROM vuln.VulnerabilityEvent AS e
JOIN vuln.VulnerabilityItem AS i ON i.SysId = e.SysId
WHERE e.Action <> N'Seen'
ORDER BY e.At DESC, e.EventId DESC;
""";

    private readonly ISqlExecutor _sql;
    public SqlCloseLoopReader(ISqlExecutor sql) => _sql = sql;

    public async Task<CloseLoopState> ReadAsync(int recentEvents, CancellationToken ct)
    {
        var b = await _sql.QueryAsync(BucketSql, new Dictionary<string, object?>(), ct);
        var e = await _sql.QueryAsync(EventSql, new Dictionary<string, object?> { ["Top"] = Math.Clamp(recentEvents, 1, 500) }, ct);
        return new CloseLoopState(
            b.Select(r => new CloseLoopBucket(r.Str("Status")!, r.Str("Reason") ?? "", r.Str("Severity") ?? "", r.Long("Items") ?? 0)).ToList(),
            e.Select(r => new CloseLoopEvent(r.Date("At") ?? default, r.Str("Action")!, r.Str("FromState"), r.Str("ToState"), r.Str("Reason"),
                r.Str("RunId"), r.Str("Actor") ?? "", r.Str("AssetName"), r.Str("Cve") ?? "")).ToList(),
            BucketSql, EventSql);
    }
}
