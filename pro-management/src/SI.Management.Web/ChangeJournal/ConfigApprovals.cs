using SI.Management.Web.Data;

namespace SI.Management.Web.ChangeJournal;

/// A request waiting for a second SuperAdmin (CONFIG-1.5): a restore or a guard release.
public sealed record ConfigApproval(long Id, string Kind, string Title, string PayloadJson, string? Reason, string RequestedBy, DateTime RequestedUtc,
    DateTime ExpiresUtc, string? CorrelationId, string State, string? DecidedBy, DateTime? DecidedUtc, string? DecisionNote, string? OutcomeText)
{
    public const string Restore = "restore";
    public const string GuardRelease = "guard-release";
    public bool IsOpen(DateTime nowUtc) => State == "pending" && ExpiresUtc > nowUtc;
    /// The person who asked can never approve their own request.
    public bool MayDecide(string who, DateTime nowUtc) => IsOpen(nowUtc) && !string.Equals(who, RequestedBy, StringComparison.OrdinalIgnoreCase);
}

public interface IConfigApprovalStore
{
    Task<bool> ExistsAsync(CancellationToken ct);
    Task<long> RequestAsync(string kind, string title, string payloadJson, string reason, string by, string? correlationId, CancellationToken ct);
    Task<IReadOnlyList<ConfigApproval>> RecentAsync(string kind, CancellationToken ct);
    Task<ConfigApproval?> FindAsync(long id, CancellationToken ct);
    /// pending -> approved | rejected, ONCE, by someone other than the requester; false when it is no longer pending.
    Task<bool> DecideAsync(long id, bool approve, string by, string? note, CancellationToken ct);
    Task SetOutcomeAsync(long id, string state, string text, CancellationToken ct);
}

/// <summary>
/// #404 (framework CONFIG-1.5) -- the second person. When SIWeb_ConfigSecondPerson is on, a guard release or a restore is
/// stored here as a request; ANOTHER SuperAdmin approves (the release / the restore then happens, recorded with both
/// names) or rejects it. A request expires after 7 days. The web app's role: INSERT + UPDATE (SI-ManagementGrants).
/// </summary>
public sealed class SqlConfigApprovalStore : IConfigApprovalStore
{
    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.ConfigApproval') IS NOT NULL THEN 1 ELSE 0 END AS HasTable;";
    private const string Cols = "ApprovalId, Kind, Title, PayloadJson, Reason, RequestedBy, RequestedUtc, ExpiresUtc, CorrelationId, State, DecidedBy, DecidedUtc, DecisionNote, OutcomeText";
    public const string InsertSql =
        "INSERT cfg.ConfigApproval (Kind, Title, PayloadJson, Reason, RequestedBy, ExpiresUtc, CorrelationId) VALUES (@Kind, @Title, @Payload, @Reason, @By, DATEADD(DAY, 7, SYSUTCDATETIME()), @Cid);\n" +
        "SELECT CAST(SCOPE_IDENTITY() AS BIGINT) AS Id;";
    public const string RecentSql = "SELECT TOP (50) " + Cols + " FROM cfg.ConfigApproval WHERE Kind = @Kind AND RequestedUtc >= DATEADD(DAY, -30, SYSUTCDATETIME()) ORDER BY ApprovalId DESC;";
    public const string FindSql = "SELECT " + Cols + " FROM cfg.ConfigApproval WHERE ApprovalId = @Id;";
    public const string DecideSql =
        "UPDATE cfg.ConfigApproval SET State = @State, DecidedBy = @By, DecidedUtc = SYSUTCDATETIME(), DecisionNote = @Note\n" +
        "WHERE ApprovalId = @Id AND State = N'pending' AND ExpiresUtc > SYSUTCDATETIME() AND RequestedBy <> @By;\nSELECT @@ROWCOUNT AS Changed;";
    public const string OutcomeSql = "UPDATE cfg.ConfigApproval SET State = @State, OutcomeText = LEFT(@Text, 2000) WHERE ApprovalId = @Id;";

    private readonly ISqlExecutor _sql;
    public SqlConfigApprovalStore(ISqlExecutor sql) => _sql = sql;
    private static Dictionary<string, object?> P(params (string K, object? V)[] kv) => kv.ToDictionary(x => x.K, x => x.V);
    private static DateTime? Utc(DateTime? d) => d is { } x ? DateTime.SpecifyKind(x, DateTimeKind.Utc) : null;

    private static ConfigApproval From(SqlRow r) => new(r.Long("ApprovalId") ?? 0, r.Str("Kind") ?? "", r.Str("Title") ?? "", r.Str("PayloadJson") ?? "{}", r.Str("Reason"),
        r.Str("RequestedBy") ?? "", Utc(r.Date("RequestedUtc")) ?? DateTime.MinValue, Utc(r.Date("ExpiresUtc")) ?? DateTime.MinValue, r.Str("CorrelationId"),
        r.Str("State") ?? "", r.Str("DecidedBy"), Utc(r.Date("DecidedUtc")), r.Str("DecisionNote"), r.Str("OutcomeText"));

    public async Task<bool> ExistsAsync(CancellationToken ct) => (await _sql.QueryAsync(ExistsSql, P(), ct)).FirstOrDefault()?.Long("HasTable") == 1;

    public async Task<long> RequestAsync(string kind, string title, string payloadJson, string reason, string by, string? correlationId, CancellationToken ct) =>
        (await _sql.QueryAsync(InsertSql, P(("Kind", kind), ("Title", title.Length > 400 ? title[..400] : title), ("Payload", payloadJson),
            ("Reason", reason.Length > 1000 ? reason[..1000] : reason), ("By", by), ("Cid", correlationId)), ct)).FirstOrDefault()?.Long("Id") ?? 0;

    public async Task<IReadOnlyList<ConfigApproval>> RecentAsync(string kind, CancellationToken ct) =>
        await ExistsAsync(ct) ? (await _sql.QueryAsync(RecentSql, P(("Kind", kind)), ct)).Select(From).ToList() : Array.Empty<ConfigApproval>();

    public async Task<ConfigApproval?> FindAsync(long id, CancellationToken ct) => (await _sql.QueryAsync(FindSql, P(("Id", id)), ct)).Select(From).FirstOrDefault();

    public async Task<bool> DecideAsync(long id, bool approve, string by, string? note, CancellationToken ct) =>
        (await _sql.QueryAsync(DecideSql, P(("Id", id), ("State", approve ? "approved" : "rejected"), ("By", by), ("Note", note)), ct)).FirstOrDefault()?.Long("Changed") == 1;

    public Task SetOutcomeAsync(long id, string state, string text, CancellationToken ct) =>
        _sql.QueryAsync(OutcomeSql, P(("Id", id), ("State", state), ("Text", text)), ct);
}
