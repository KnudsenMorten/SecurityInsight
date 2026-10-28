using System.Globalization;
using System.Text.Json.Nodes;
using SI.Management.Web.Data;

namespace SI.Management.Web.ChangeJournal;

/// One commit of the change journal (cfg.ConfigJournal grouped by its commit id = the audit trail's correlation id).
public sealed record ConfigCommit(string CommitId, DateTime CommittedUtc, string InitiatedBy, string? ApprovedBy, string Source, string? UndoOf, int Records, string Entities, string? Reason);

/// One changed record of a commit: the full record before and after.
public sealed record ConfigJournalRow(long JournalId, string CommitId, DateTime CommittedUtc, string Entity, string EntityKey, string Op,
    string? BeforeJson, string? AfterJson, string InitiatedBy, string? ApprovedBy, string Source, string? UndoOf, string? Reason)
{
    public JsonObject? Before => ConfigEntities.Parse(BeforeJson);
    public JsonObject? After => ConfigEntities.Parse(AfterJson);
}

/// A later commit that changed the same record ("changed since by &lt;who&gt;").
public sealed record ConfigLaterChange(long JournalId, string CommitId, string InitiatedBy, DateTime CommittedUtc);

/// What happened under a commit's id on the audit trail: the request and every job step that put it in force.
public sealed record ConfigCommitEvent(DateTime TsUtc, string Action, string Actor, string Outcome, string? OutcomeText);

public interface IConfigJournalStore
{
    Task<bool> ExistsAsync(CancellationToken ct);
    /// Newest first. -by: only the commits this person initiated (an Admin sees their own).
    Task<(IReadOnlyList<ConfigCommit> Rows, long Total)> CommitsAsync(string? by, string? entity, string? search, int skip, int take, CancellationToken ct);
    Task<IReadOnlyList<ConfigJournalRow>> CommitAsync(string commitId, CancellationToken ct);
    /// Per journal row of the commit: the newest LATER commit that changed the same record, if any.
    Task<IReadOnlyDictionary<long, ConfigLaterChange>> LaterAsync(string commitId, CancellationToken ct);
    Task<IReadOnlyList<ConfigCommitEvent>> EventsAsync(string commitId, CancellationToken ct);
}

/// <summary>
/// #404 (framework CONFIG-1.2) -- reads the change journal for the commit history: who, when, approved by, what changed,
/// and what the commit did (its audit events: the save and every job step that put it in force). Read-only: the journal
/// is written only by the tables' triggers.
/// </summary>
public sealed class SqlConfigJournalStore : IConfigJournalStore
{
    public const string ExistsSql = "SELECT CASE WHEN OBJECT_ID(N'cfg.ConfigJournal') IS NOT NULL THEN 1 ELSE 0 END AS HasTable;";

    // @Entity: one or more kinds of configuration, a JSON array (owner 2026-10-19: every filter multi-select)
    private const string Filter = "WHERE (@By IS NULL OR j.InitiatedBy = @By) AND (@Entity IS NULL OR j.Entity IN (SELECT ev.[value] FROM OPENJSON(@Entity) AS ev))\n" +
        "  AND (@Q IS NULL OR j.EntityKey LIKE @Q OR j.InitiatedBy LIKE @Q OR j.CommitId LIKE @Q OR j.Entity LIKE @Q)";

    public const string CommitsSql =
        "SELECT g.CommitId, g.CommittedUtc, g.InitiatedBy, g.ApprovedBy, g.Source, g.UndoOf, g.Records, g.Reason,\n" +
        "       (SELECT STRING_AGG(x.Entity, N', ') FROM (SELECT DISTINCT e.Entity FROM cfg.ConfigJournal AS e WHERE e.CommitId = g.CommitId) AS x) AS Entities\n" +
        "FROM (SELECT j.CommitId, MIN(j.CommittedUtc) AS CommittedUtc, MIN(j.InitiatedBy) AS InitiatedBy, MAX(j.ApprovedBy) AS ApprovedBy, MIN(j.Source) AS Source,\n" +
        "             MAX(j.UndoOf) AS UndoOf, COUNT(*) AS Records, MAX(j.Reason) AS Reason, MIN(j.JournalId) AS FirstId\n" +
        "      FROM cfg.ConfigJournal AS j\n" + Filter + "\n      GROUP BY j.CommitId) AS g\n" +
        "ORDER BY g.FirstId DESC OFFSET @Skip ROWS FETCH NEXT @Take ROWS ONLY;";

    public const string CountSql = "SELECT COUNT(DISTINCT j.CommitId) AS N FROM cfg.ConfigJournal AS j\n" + Filter + ";";

    public const string CommitSql =
        "SELECT JournalId, CommitId, CommittedUtc, Entity, EntityKey, Op, BeforeJson, AfterJson, InitiatedBy, ApprovedBy, Source, UndoOf, Reason\n" +
        "FROM cfg.ConfigJournal WHERE CommitId = @Id ORDER BY JournalId;";

    public const string LaterSql =
        "SELECT r.JournalId, l.JournalId AS LaterId, l.CommitId, l.InitiatedBy, l.CommittedUtc\n" +
        "FROM cfg.ConfigJournal AS r\n" +
        "CROSS APPLY (SELECT TOP (1) x.JournalId, x.CommitId, x.InitiatedBy, x.CommittedUtc FROM cfg.ConfigJournal AS x\n" +
        "             WHERE x.Entity = r.Entity AND x.EntityKey = r.EntityKey AND x.JournalId > r.JournalId AND x.CommitId <> r.CommitId ORDER BY x.JournalId DESC) AS l\n" +
        "WHERE r.CommitId = @Id;";

    public const string EventsSql =
        "IF OBJECT_ID(N'cfg.AuditEvent') IS NULL SELECT TOP (0) SYSUTCDATETIME() AS TsUtc, N'' AS Action, N'' AS Actor, N'' AS Outcome, N'' AS OutcomeText;\n" +
        "ELSE SELECT TOP (50) TsUtc, Action, Actor, Outcome, OutcomeText FROM cfg.AuditEvent WHERE CorrelationId = @Id AND RecordType = N'event' ORDER BY Id;";

    private readonly ISqlExecutor _sql;
    public SqlConfigJournalStore(ISqlExecutor sql) => _sql = sql;

    public async Task<bool> ExistsAsync(CancellationToken ct) =>
        (await _sql.QueryAsync(ExistsSql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Long("HasTable") == 1;

    private static DateTime Utc(DateTime? d) => DateTime.SpecifyKind(d ?? DateTime.MinValue, DateTimeKind.Utc);

    public async Task<(IReadOnlyList<ConfigCommit> Rows, long Total)> CommitsAsync(string? by, string? entity, string? search, int skip, int take, CancellationToken ct)
    {
        var p = new Dictionary<string, object?>
        {
            // the entities: '|'-joined names (the caller passes known names only)
            ["By"] = string.IsNullOrWhiteSpace(by) ? null : by, ["Entity"] = SI.Management.Core.ProData.ProDataFilters.Json(string.IsNullOrWhiteSpace(entity) ? null : entity),
            ["Q"] = string.IsNullOrWhiteSpace(search) ? null : "%" + search.Trim().Replace("[", "[[]").Replace("%", "[%]").Replace("_", "[_]") + "%",
            ["Skip"] = Math.Max(0, skip), ["Take"] = Math.Clamp(take, 1, 500),
        };
        var rows = (await _sql.QueryAsync(CommitsSql, p, ct)).Select(r => new ConfigCommit(r.Str("CommitId") ?? "", Utc(r.Date("CommittedUtc")), r.Str("InitiatedBy") ?? "",
            r.Str("ApprovedBy"), r.Str("Source") ?? "", r.Str("UndoOf"), (int)(r.Long("Records") ?? 0), r.Str("Entities") ?? "", r.Str("Reason"))).ToList();
        var total = (await _sql.QueryAsync(CountSql, p, ct)).FirstOrDefault()?.Long("N") ?? 0;
        return (rows, total);
    }

    public async Task<IReadOnlyList<ConfigJournalRow>> CommitAsync(string commitId, CancellationToken ct) =>
        (await _sql.QueryAsync(CommitSql, new Dictionary<string, object?> { ["Id"] = commitId }, ct)).Select(r => new ConfigJournalRow(
            r.Long("JournalId") ?? 0, r.Str("CommitId") ?? "", Utc(r.Date("CommittedUtc")), r.Str("Entity") ?? "", r.Str("EntityKey") ?? "", r.Str("Op") ?? "",
            r.Str("BeforeJson"), r.Str("AfterJson"), r.Str("InitiatedBy") ?? "", r.Str("ApprovedBy"), r.Str("Source") ?? "", r.Str("UndoOf"), r.Str("Reason"))).ToList();

    public async Task<IReadOnlyDictionary<long, ConfigLaterChange>> LaterAsync(string commitId, CancellationToken ct) =>
        (await _sql.QueryAsync(LaterSql, new Dictionary<string, object?> { ["Id"] = commitId }, ct))
            .ToDictionary(r => r.Long("JournalId") ?? 0, r => new ConfigLaterChange(r.Long("LaterId") ?? 0, r.Str("CommitId") ?? "", r.Str("InitiatedBy") ?? "", Utc(r.Date("CommittedUtc"))));

    public async Task<IReadOnlyList<ConfigCommitEvent>> EventsAsync(string commitId, CancellationToken ct) =>
        (await _sql.QueryAsync(EventsSql, new Dictionary<string, object?> { ["Id"] = commitId }, ct)).Select(r => new ConfigCommitEvent(
            Utc(r.Date("TsUtc")), r.Str("Action") ?? "", r.Str("Actor") ?? "", r.Str("Outcome") ?? "", r.Str("OutcomeText"))).ToList();
}

/// <summary>
/// PURE. CONFIG-1.2 -- the inverse of a commit, record by record: Add -> Remove (the record added), Remove -> Add (the
/// record as it was before), Modify -> the before values. A record a LATER commit changed again is marked "changed since
/// by &lt;who&gt;" and is not ticked by default; reverting it is a deliberate tick.
/// </summary>
public static class ConfigUndo
{
    public sealed record Item(ConfigJournalRow Row, ConfigEntities.Entity? Entity, string Op, JsonObject? Record, ConfigLaterChange? ChangedSince, string? Blocked)
    {
        public bool DefaultTicked => Blocked is null && ChangedSince is null;
        public string Title => (Entity?.Label ?? Row.Entity) + ": " + Row.EntityKey;
    }

    public static string InverseOp(string op) => op switch { "Add" => "Remove", "Remove" => "Add", _ => "Modify" };

    public static IReadOnlyList<Item> Plan(IReadOnlyList<ConfigJournalRow> rows, IReadOnlyDictionary<long, ConfigLaterChange> later, ConfigEntities entities)
    {
        var list = new List<Item>();
        // the LAST row of a record in the commit decides what to undo (a record changed twice in one commit goes back to
        // its state before the first change)
        foreach (var g in rows.GroupBy(r => (r.Entity, r.EntityKey)))
        {
            var first = g.First(); var last = g.Last();
            var e = entities.Find(first.Entity);
            var net = Net(first.Op, last.Op);
            var row = first with { AfterJson = last.AfterJson, Op = net ?? "Modify", JournalId = last.JournalId };
            string? blocked = e is null ? "this kind of record is not part of the configuration set any more"
                : !e.Undo ? e.NoUndoWhy
                : net is null ? "it was added and removed again in the same commit -- there is nothing to undo" : null;
            var op = InverseOp(row.Op);
            var record = op == "Remove" ? row.After : row.Before;
            if (record is null && blocked is null) blocked = "the journal has no full record to put back";
            later.TryGetValue(last.JournalId, out var since);
            list.Add(new Item(row, e, op, record, since, blocked));
        }
        return list;
    }

    /// Several changes of one record in one commit, as one: added then removed = nothing to undo (null); added = Add;
    /// ends removed = Remove; removed then put back, or changed = Modify (back to the state before the commit).
    public static string? Net(string firstOp, string lastOp) => (firstOp, lastOp) switch
    {
        ("Add", "Remove") => null,
        ("Add", _) => "Add",
        (_, "Remove") => "Remove",
        _ => "Modify",
    };
}
