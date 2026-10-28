using SI.Management.Web.Data;

namespace SI.Management.Web.Cmdb;

/// The SQL CMDB connector's state for the CMDB page (#271): whether its CI table exists, the last run and the CI counts.
public sealed record CmdbSqlSyncState(
    bool HasTable,
    DateTime? LastRunAt,
    string? LastOutcome,
    string? LastReason,
    int Created,
    int Updated,
    int Unchanged,
    int Absent,
    int Retired,
    int Reactivated,
    int Held,
    DateTime? LastAppliedAt,
    long ActiveCis,
    long RetiredCis)
{
    public static readonly CmdbSqlSyncState Missing = new(false, null, null, null, 0, 0, 0, 0, 0, 0, 0, null, 0, 0);
}

/// <summary>
/// READ ONLY: the CI table the job caj-si-asset-cmdb-sql writes (sql\si-cmdbsync-schema.sql). The web app never writes
/// it -- its identity only reads (db_datareader); the job owns the table.
/// </summary>
public interface ICmdbSqlSyncReader
{
    Task<CmdbSqlSyncState> ReadAsync(CancellationToken ct);
}

public sealed class SqlCmdbSqlSyncReader : ICmdbSqlSyncReader
{
    private readonly ISqlExecutor _sql;
    public SqlCmdbSqlSyncReader(ISqlExecutor sql) => _sql = sql;

    /// The query behind the card: the last run, the last applied run and the CI counts. No table = HasTable 0.
    public const string StateSql = """
IF OBJECT_ID(N'cmdbsync.SyncRun') IS NULL OR OBJECT_ID(N'cmdbsync.ConfigurationItem') IS NULL
    SELECT 0 AS HasTable;
ELSE
    EXEC (N'SELECT 1 AS HasTable, r.StartedAt AS LastRunAt, r.Outcome AS LastOutcome, r.Reason AS LastReason,
       a.Created, a.Updated, a.Unchanged, a.Absent, a.Retired, a.Reactivated, a.Held, a.EndedAt AS LastAppliedAt,
       (SELECT COUNT_BIG(*) FROM cmdbsync.ConfigurationItem WHERE State = N''active'') AS ActiveCis,
       (SELECT COUNT_BIG(*) FROM cmdbsync.ConfigurationItem WHERE State = N''retired'') AS RetiredCis
FROM (SELECT 1 AS One) AS x
OUTER APPLY (SELECT TOP (1) StartedAt, Outcome, Reason FROM cmdbsync.SyncRun ORDER BY SyncRunId DESC) AS r
OUTER APPLY (SELECT TOP (1) Created, Updated, Unchanged, Absent, Retired, Reactivated, Held, EndedAt FROM cmdbsync.SyncRun WHERE Outcome = N''applied'' ORDER BY SyncRunId DESC) AS a');
""";

    /// The reporting view (Power BI reads the same): one row per CI.
    public const string ViewSql = "SELECT * FROM cmdbsync.vConfigurationItem ORDER BY State, Kind, Name;";

    public async Task<CmdbSqlSyncState> ReadAsync(CancellationToken ct)
    {
        var rows = await _sql.QueryAsync(StateSql, new Dictionary<string, object?>(), ct);
        var r = rows.FirstOrDefault();
        if (r is null || (r.Long("HasTable") ?? 0) != 1) return CmdbSqlSyncState.Missing;
        int I(string c) => (int)(r.Long(c) ?? 0);
        return new CmdbSqlSyncState(true, r.Date("LastRunAt"), r.Str("LastOutcome"), r.Str("LastReason"),
            I("Created"), I("Updated"), I("Unchanged"), I("Absent"), I("Retired"), I("Reactivated"), I("Held"),
            r.Date("LastAppliedAt"), r.Long("ActiveCis") ?? 0, r.Long("RetiredCis") ?? 0);
    }
}
