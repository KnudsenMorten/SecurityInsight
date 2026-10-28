using Azure.Core;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using SI.Management.Core;

namespace SI.Management.Web.Data;

/// One row: column name -> value (DBNull mapped to null).
public sealed class SqlRow : Dictionary<string, object?>
{
    public SqlRow() : base(StringComparer.OrdinalIgnoreCase) { }
    public string? Str(string col) => TryGetValue(col, out var v) && v is not null ? Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture) : null;
    public long? Long(string col) => TryGetValue(col, out var v) && v is not null ? Convert.ToInt64(v, System.Globalization.CultureInfo.InvariantCulture) : null;
    public DateTime? Date(string col) => TryGetValue(col, out var v) && v is DateTime d ? d : null;
}

/// <summary>
/// THE seam to the Pro database. Every read and every write goes through one call: a T-SQL batch plus its parameters,
/// returning the rows of the batch's LAST result set. Tests replace it with a fake that records the SQL, so what the
/// writer sends (one transaction, the ChangeLog row, the RowVersion check) is asserted on the text itself.
/// </summary>
public interface ISqlExecutor
{
    Task<IReadOnlyList<SqlRow>> QueryAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct);
}

/// <summary>Azure SQL with an Entra access token from the injected TokenCredential. A connection per call.</summary>
public sealed class AzureSqlExecutor : ISqlExecutor
{
    private static readonly string[] Scopes = { "https://database.windows.net/.default" };
    private readonly EstateOptions _o;
    private readonly TokenCredential _cred;
    private AccessToken _token;
    private readonly SemaphoreSlim _lock = new(1, 1);

    /// The ONE Pro database (Estate:SqlServer / Estate:SqlDatabase) and the process's ONE credential, both shared with
    /// the estate query layer (SI.Management.Core: Identity section -> managed identity hosted, certificate locally).
    public AzureSqlExecutor(IOptions<EstateOptions> o, TokenCredential cred) { _o = o.Value; _cred = cred; }

    public static bool IsConfigured(EstateOptions o) => !string.IsNullOrWhiteSpace(o.SqlServer) && !string.IsNullOrWhiteSpace(o.SqlDatabase);

    public string ConnectionString => new SqlConnectionStringBuilder
    {
        DataSource = $"tcp:{_o.SqlServer},1433", InitialCatalog = _o.SqlDatabase, Encrypt = SqlConnectionEncryptOption.Mandatory,
        TrustServerCertificate = false, ConnectTimeout = 30,
    }.ConnectionString;

    public async Task<string> TokenAsync(CancellationToken ct)
    {
        await _lock.WaitAsync(ct);
        try
        {
            if (_token.Token is null || _token.ExpiresOn <= DateTimeOffset.UtcNow.AddMinutes(5))
                _token = await _cred.GetTokenAsync(new TokenRequestContext(Scopes), ct);
            return _token.Token;
        }
        finally { _lock.Release(); }
    }

    public async Task<IReadOnlyList<SqlRow>> QueryAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
    {
        if (!IsConfigured(_o)) throw new InvalidOperationException("The Pro database is not configured (Estate:SqlServer / Estate:SqlDatabase).");
        // the page timing log counts this call for the request it belongs to: the time includes opening the connection
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        try
        {
            await using var cn = new SqlConnection(ConnectionString) { AccessToken = await TokenAsync(ct) };
            await cn.OpenAsync(ct);
            return await RunCoreAsync(cn, null, sql, parameters, ct, _o.QueryTimeoutSeconds);
        }
        finally { SI.Management.Web.Timing.PageTimer.Record(sql, System.Diagnostics.Stopwatch.GetElapsedTime(started)); }
    }

    /// The audit trail's request context (#260) on this connection: the cfg.ChangeLog trigger copies it onto every change
    /// row the batch writes, so the change joins the request's audit event. Session-scoped; a pooled connection is reset
    /// before its next use.
    /// #404: the change journal's keys too (who, the journal source, the approver, the commit an undo reverses, why).
    public static readonly IReadOnlyList<(string Key, string Param)> SessionContextKeys =
    [
        ("si.audit.cid", "@AuditCid"), ("si.audit.source", "@AuditSource"), ("si.audit.domain", "@AuditDomain"), ("si.audit.department", "@AuditDepartment"),
        ("si.audit.actor", "@AuditActor"), ("si.cfg.source", "@CfgSource"), ("si.cfg.initiatedBy", "@CfgInitiatedBy"), ("si.cfg.approvedBy", "@CfgApprovedBy"),
        ("si.cfg.undoOf", "@CfgUndoOf"), ("si.cfg.reason", "@CfgReason"),
    ];

    public static readonly string SessionContextSql = string.Join("\n", SessionContextKeys.Select(k => $"EXEC sys.sp_set_session_context @key = N'{k.Key}', @value = {k.Param};"));

    /// Runs a batch on an open connection (optionally inside a caller's transaction) and returns its last result set.
    public static async Task<IReadOnlyList<SqlRow>> RunAsync(SqlConnection cn, SqlTransaction? tx, string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct, int timeoutSeconds = 60)
    {
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        try { return await RunCoreAsync(cn, tx, sql, parameters, ct, timeoutSeconds); }
        finally { SI.Management.Web.Timing.PageTimer.Record(sql, System.Diagnostics.Stopwatch.GetElapsedTime(started)); }
    }

    private static async Task<IReadOnlyList<SqlRow>> RunCoreAsync(SqlConnection cn, SqlTransaction? tx, string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct, int timeoutSeconds)
    {
        if (SI.Management.Web.Audit.AuditScope.Current is { } audit)
        {
            await using var ctx = cn.CreateCommand();
            ctx.CommandText = SessionContextSql;
            ctx.Transaction = tx;
            var c = audit.SessionContext();
            foreach (var (key, param) in SessionContextKeys)
                ctx.Parameters.AddWithValue(param, c.TryGetValue(key, out var v) && v is not null ? v : DBNull.Value);
            await ctx.ExecuteNonQueryAsync(ct);
        }
        await using var cmd = cn.CreateCommand();
        cmd.CommandText = sql;
        // #881 no ceiling of our own: the caller's time (Estate:QueryTimeoutSeconds for the pages; 0 = none, for work that is
        // not an HTTP request) -- only a value below 0 is read as 0. A page is still ended by the ingress, never by this clamp.
        cmd.CommandTimeout = Math.Max(0, timeoutSeconds);
        cmd.Transaction = tx;
        foreach (var (k, v) in parameters) cmd.Parameters.AddWithValue("@" + k, v ?? DBNull.Value);
        await using var rd = await cmd.ExecuteReaderAsync(ct);
        var rows = new List<SqlRow>();
        do
        {
            if (rd.FieldCount == 0) continue;
            rows = new List<SqlRow>();
            while (await rd.ReadAsync(ct))
            {
                var r = new SqlRow();
                for (var i = 0; i < rd.FieldCount; i++) r[rd.GetName(i)] = await rd.IsDBNullAsync(i, ct) ? null : rd.GetValue(i);
                rows.Add(r);
            }
        } while (await rd.NextResultAsync(ct));
        return rows;
    }
}

/// The web app's SQL executor as the Core Pro-data seam, so the findings / trend / dashboard reads (SI.Management.Core,
/// shared with the MCP server) run on the same connection, identity and test fake as every other page.
public sealed class ExecutorProSql : SI.Management.Core.ProData.IProSql
{
    private readonly ISqlExecutor _sql;
    public ExecutorProSql(ISqlExecutor sql) => _sql = sql;
    public string SourceName => "Pro database (SQL)";
    public async Task<IReadOnlyList<IReadOnlyDictionary<string, object?>>> QueryAsync(SI.Management.Core.ProData.SqlQuery query, CancellationToken ct)
        => (await _sql.QueryAsync(query.Text, query.Parameters, ct)).Cast<IReadOnlyDictionary<string, object?>>().ToList();
}

/// Registered when Sql:Server / Sql:Database are not set: every call says so instead of guessing a database.
public sealed class NotConfiguredSqlExecutor : ISqlExecutor
{
    public Task<IReadOnlyList<SqlRow>> QueryAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
        => throw new InvalidOperationException("The Pro database is not configured (Estate:SqlServer / Estate:SqlDatabase).");
}
