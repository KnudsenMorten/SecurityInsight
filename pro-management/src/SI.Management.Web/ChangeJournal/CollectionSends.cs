using System.Globalization;
using SI.Management.Web.Data;

namespace SI.Management.Web.ChangeJournal;

/// A connector that receives collections (the vulnerability connectors), what its newest applied run did, and whether
/// SecurityInsight can undo that run.
public sealed record SendConnector(string Name, string Kind, bool Enabled, string Mode, string? LastRunId, DateTime? LastRunUtc, string? LastOutcome,
    int Opened, int Reopened, int Closed, int Updated)
{
    /// The job that runs it: the ServiceNow connectors have their own job (#269).
    public string Job => string.Equals(Kind, "servicenow", StringComparison.OrdinalIgnoreCase) ? "caj-si-asset-vulns-servicenow" : "caj-si-asset-vulnerabilities";

    /// Why a run of this connector cannot be undone -- null when it can. Said plainly in the UI instead of pretending.
    public string? CannotUndo => Kind.ToLowerInvariant() switch
    {
        "sql" => LastRunId is null ? "it has no applied run to undo yet" : null,
        "servicenow" => "ServiceNow keeps no record SecurityInsight could use to put the items back as they were before a run -- correct them in ServiceNow, or send an earlier collection again",
        "rest" => "the other system keeps no before-state SecurityInsight can put back (SecurityInsight records only the items it created) -- send an earlier collection again instead",
        _ => "this kind of connector cannot be undone",
    };
}

/// A complete collection that can be sent again.
public sealed record SendCollection(int CollectionId, DateTime CollectionTime, long Rows, bool Partial);

/// One request to resend a collection or undo a connector run, and what came of it.
public sealed record CollectionSend(long Id, string Kind, string Connector, string? ConnectorKind, int? CollectionId, DateTime? CollectionTime, string? TargetRunId,
    string Reason, string RequestedBy, DateTime RequestedUtc, string State, string? RunId, DateTime? DoneUtc, string? OutcomeText);

public interface ICollectionSendStore
{
    Task<bool> ExistsAsync(CancellationToken ct);
    Task<IReadOnlyList<SendConnector>> ConnectorsAsync(CancellationToken ct);
    Task<IReadOnlyList<SendCollection>> CollectionsAsync(int days, CancellationToken ct);
    Task<IReadOnlyList<CollectionSend>> RecentAsync(CancellationToken ct);
    Task<long> RequestAsync(string kind, SendConnector c, SendCollection? collection, string? targetRunId, string reason, string by, string? correlationId, CancellationToken ct);
    Task SetStateAsync(long id, string state, string? text, CancellationToken ct);
}

/// <summary>
/// #404 part 2 -- send an earlier collection into a connector again, or undo the connector's last run. The collections are
/// the complete Risk Analysis collections the Pro database ALREADY keeps (sidata.Collection, its own retention -- nothing
/// is copied a second time); SIWeb_CollectionResendDays (default 3) says how far back they are offered. The request is
/// stored in cfg.CollectionSend and the connector's own job carries it out through its normal path and guards (a resend
/// is planned against the chosen collection exactly like a nightly run; a close ceiling still holds it); the job records
/// the outcome on the request and on the audit trail.
/// </summary>
public sealed class SqlCollectionSendStore : ICollectionSendStore
{
    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.CollectionSend') IS NOT NULL THEN 1 ELSE 0 END AS HasTable;";
    public const string ConnectorsSql =
        "IF OBJECT_ID(N'cfg.Connector') IS NULL SELECT TOP (0) N'' AS Name, N'' AS Kind, CAST(0 AS BIT) AS Enabled, N'' AS Mode, N'' AS RunId, SYSUTCDATETIME() AS StartedAt, N'' AS Outcome, 0 AS Opened, 0 AS Reopened, 0 AS Closed, 0 AS Updated;\n" +
        "ELSE SELECT c.Name, c.Kind, c.Enabled, c.Mode, r.RunId, r.StartedAt, r.Outcome, ISNULL(r.Opened, 0) AS Opened, ISNULL(r.Reopened, 0) AS Reopened, ISNULL(r.Closed, 0) AS Closed, ISNULL(r.Updated, 0) AS Updated\n" +
        "FROM cfg.Connector AS c\n" +
        "OUTER APPLY (SELECT TOP (1) x.RunId, x.StartedAt, x.Outcome, x.Opened, x.Reopened, x.Closed, x.Updated FROM cfg.ConnectorRun AS x\n" +
        "             WHERE x.ConnectorName = c.Name AND x.Mode = N'apply' AND x.Outcome IN (N'success', N'partial') ORDER BY x.ConnectorRunId DESC) AS r\n" +
        "WHERE c.Direction = N'vulnerability' ORDER BY c.Name;";
    public const string CollectionsSql =
        "IF OBJECT_ID(N'sidata.Collection') IS NULL SELECT TOP (0) 0 AS CollectionId, SYSUTCDATETIME() AS CollectionTime, CAST(0 AS BIGINT) AS [Rows], 0 AS Partial;\n" +
        "ELSE SELECT c.CollectionId, c.CollectionTime, CAST(c.[Rows] AS BIGINT) AS [Rows],\n" +
        "       CASE WHEN OBJECT_ID(N'sidata.CollectionPartial') IS NOT NULL AND EXISTS (SELECT 1 FROM sidata.CollectionPartial AS p WHERE p.CollectionId = c.CollectionId) THEN 1 ELSE 0 END AS Partial\n" +
        "FROM sidata.Collection AS c WHERE c.Kind = N'Detailed' AND c.Status = N'Complete' AND c.CollectionTime >= DATEADD(DAY, -@Days, SYSUTCDATETIME())\n" +
        // ONE TRUSTED RUN: a collection newer than the published run is not trusted yet -- it is not offered
        "  AND c.CollectionTime <= ISNULL(" + SI.Management.Core.ProData.PublishedRun.DetailedTime + ", c.CollectionTime)\n" +
        "ORDER BY c.CollectionTime DESC;";
    private const string Cols = "SendId, Kind, Connector, ConnectorKind, CollectionId, CollectionTime, TargetRunId, Reason, RequestedBy, RequestedUtc, State, RunId, DoneUtc, OutcomeText";
    public const string RecentSql = "SELECT TOP (50) " + Cols + " FROM cfg.CollectionSend ORDER BY SendId DESC;";
    public const string InsertSql =
        "INSERT cfg.CollectionSend (Kind, Connector, ConnectorKind, CollectionId, CollectionTime, TargetRunId, Reason, RequestedBy, CorrelationId)\n" +
        "VALUES (@Kind, @Connector, @ConnectorKind, @CollectionId, @CollectionTime, @TargetRunId, @Reason, @By, @Cid);\nSELECT CAST(SCOPE_IDENTITY() AS BIGINT) AS Id;";
    public const string StateSql = "UPDATE cfg.CollectionSend SET State = @State, OutcomeText = LEFT(@Text, 2000), DoneUtc = CASE WHEN @State IN (N'done', N'refused', N'failed') THEN SYSUTCDATETIME() END WHERE SendId = @Id AND State = N'requested';";

    private readonly ISqlExecutor _sql;
    public SqlCollectionSendStore(ISqlExecutor sql) => _sql = sql;
    private static Dictionary<string, object?> P(params (string K, object? V)[] kv) => kv.ToDictionary(x => x.K, x => x.V);
    private static DateTime? Utc(DateTime? d) => d is { } x ? DateTime.SpecifyKind(x, DateTimeKind.Utc) : null;

    public async Task<bool> ExistsAsync(CancellationToken ct) => (await _sql.QueryAsync(ExistsSql, P(), ct)).FirstOrDefault()?.Long("HasTable") == 1;

    public async Task<IReadOnlyList<SendConnector>> ConnectorsAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(ConnectorsSql, P(), ct)).Select(r => new SendConnector(r.Str("Name") ?? "", r.Str("Kind") ?? "",
            r.TryGetValue("Enabled", out var en) && en is bool b && b, r.Str("Mode") ?? "", r.Str("RunId"), Utc(r.Date("StartedAt")), r.Str("Outcome"),
            (int)(r.Long("Opened") ?? 0), (int)(r.Long("Reopened") ?? 0), (int)(r.Long("Closed") ?? 0), (int)(r.Long("Updated") ?? 0))).ToList();

    public async Task<IReadOnlyList<SendCollection>> CollectionsAsync(int days, CancellationToken ct) =>
        (await _sql.QueryAsync(CollectionsSql, P(("Days", Math.Clamp(days, 1, 90))), ct)).Select(r => new SendCollection((int)(r.Long("CollectionId") ?? 0),
            Utc(r.Date("CollectionTime")) ?? DateTime.MinValue, r.Long("Rows") ?? 0, (r.Long("Partial") ?? 0) == 1)).ToList();

    public async Task<IReadOnlyList<CollectionSend>> RecentAsync(CancellationToken ct) =>
        !await ExistsAsync(ct) ? Array.Empty<CollectionSend>() :
        (await _sql.QueryAsync(RecentSql, P(), ct)).Select(r => new CollectionSend(r.Long("SendId") ?? 0, r.Str("Kind") ?? "", r.Str("Connector") ?? "", r.Str("ConnectorKind"),
            r.Long("CollectionId") is { } ci ? (int)ci : null, Utc(r.Date("CollectionTime")), r.Str("TargetRunId"), r.Str("Reason") ?? "", r.Str("RequestedBy") ?? "",
            Utc(r.Date("RequestedUtc")) ?? DateTime.MinValue, r.Str("State") ?? "", r.Str("RunId"), Utc(r.Date("DoneUtc")), r.Str("OutcomeText"))).ToList();

    public async Task<long> RequestAsync(string kind, SendConnector c, SendCollection? collection, string? targetRunId, string reason, string by, string? correlationId, CancellationToken ct) =>
        (await _sql.QueryAsync(InsertSql, P(("Kind", kind), ("Connector", c.Name), ("ConnectorKind", c.Kind), ("CollectionId", collection?.CollectionId), ("CollectionTime", collection?.CollectionTime),
            ("TargetRunId", targetRunId), ("Reason", reason.Length > 1000 ? reason[..1000] : reason), ("By", by), ("Cid", correlationId)), ct)).FirstOrDefault()?.Long("Id") ?? 0;

    public Task SetStateAsync(long id, string state, string? text, CancellationToken ct) => _sql.QueryAsync(StateSql, P(("Id", id), ("State", state), ("Text", text)), ct);

    /// The collection time as the job reads it (SI_VulnSync_CollectionTime): ISO 8601 UTC to the millisecond.
    public static string Iso(DateTime t) => DateTime.SpecifyKind(t, DateTimeKind.Utc).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);
}
