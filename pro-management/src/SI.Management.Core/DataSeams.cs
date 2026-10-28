using System.Globalization;
using System.Text.Json;
using Azure.Core;
using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;

namespace SI.Management.Core;

/// One row of a result: column name -> value (case-insensitive).
public sealed class DataRow : Dictionary<string, object?>
{
    public DataRow() : base(StringComparer.OrdinalIgnoreCase) { }
}

/// THE seam to Log Analytics. Tests replace it with a fake; the real one is <see cref="LogAnalyticsReader"/>.
public interface ILogAnalyticsReader
{
    /// Display name of the source, e.g. "Log Analytics".
    string SourceName { get; }
    Task<IReadOnlyList<DataRow>> QueryAsync(string kql, CancellationToken ct);
}

/// THE seam to the Pro SQL database. Read-only: implementations run SELECT statements only.
public interface ISqlReader
{
    string SourceName { get; }
    Task<IReadOnlyList<DataRow>> QueryAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct);
}

/// Log Analytics over Azure.Monitor.Query with the injected TokenCredential.
public sealed class LogAnalyticsReader : ILogAnalyticsReader
{
    private readonly LogsQueryClient _client;
    private readonly EstateOptions _o;

    public LogAnalyticsReader(TokenCredential credential, IOptions<EstateOptions> options)
    {
        _o = options.Value;
        if (string.IsNullOrWhiteSpace(_o.WorkspaceId)) throw new InvalidOperationException("Estate:WorkspaceId is not configured.");
        _client = new LogsQueryClient(credential);
    }

    public string SourceName => "Log Analytics";

    public async Task<IReadOnlyList<DataRow>> QueryAsync(string kql, CancellationToken ct)
    {
        // The templates bound their own time window with ago(); the API range is left open so it never narrows them.
        var opts = new LogsQueryOptions { ServerTimeout = TimeSpan.FromSeconds(Math.Clamp(_o.QueryTimeoutSeconds, 10, 600)) };
        var resp = await _client.QueryWorkspaceAsync(_o.WorkspaceId, kql, QueryTimeRange.All, opts, ct).ConfigureAwait(false);
        var table = resp.Value.Table;
        var rows = new List<DataRow>(table.Rows.Count);
        foreach (var r in table.Rows)
        {
            var d = new DataRow();
            for (var i = 0; i < table.Columns.Count; i++) d[table.Columns[i].Name] = r[i];
            rows.Add(d);
        }
        return rows;
    }
}

/// Azure SQL over Microsoft.Data.SqlClient with an Entra token from the injected TokenCredential.
/// ApplicationIntent=ReadOnly, and the statement must be a SELECT (or a CTE ending in one).
public sealed class SqlReader : ISqlReader
{
    private static readonly string[] Scopes = ["https://database.windows.net/.default"];
    private readonly TokenCredential _credential;
    private readonly string _connectionString;

    public SqlReader(TokenCredential credential, IOptions<EstateOptions> options)
    {
        var o = options.Value;
        if (string.IsNullOrWhiteSpace(o.SqlServer) || string.IsNullOrWhiteSpace(o.SqlDatabase))
            throw new InvalidOperationException("Estate:SqlServer and Estate:SqlDatabase are not configured.");
        _credential = credential;
        _connectionString = new SqlConnectionStringBuilder
        {
            DataSource = $"tcp:{o.SqlServer},1433",
            InitialCatalog = o.SqlDatabase,
            Encrypt = SqlConnectionEncryptOption.Mandatory,
            TrustServerCertificate = false,
            ApplicationIntent = ApplicationIntent.ReadOnly,
            ConnectTimeout = 30,
            CommandTimeout = Math.Max(0, o.QueryTimeoutSeconds),   // #881 no ceiling of our own (0 = none)
        }.ConnectionString;
    }

    public string SourceName => "Azure SQL";

    public async Task<IReadOnlyList<DataRow>> QueryAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
    {
        SqlGuard.AssertReadOnly(sql);
        await using var cn = new SqlConnection(_connectionString)
        {
            AccessTokenCallback = async (_, token) =>
            {
                var t = await _credential.GetTokenAsync(new TokenRequestContext(Scopes), token).ConfigureAwait(false);
                return new SqlAuthenticationToken(t.Token, t.ExpiresOn);
            },
        };
        await cn.OpenAsync(ct).ConfigureAwait(false);
        await using var cmd = cn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (k, v) in parameters) cmd.Parameters.AddWithValue("@" + k, v ?? DBNull.Value);
        await using var rd = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var rows = new List<DataRow>();
        while (await rd.ReadAsync(ct).ConfigureAwait(false))
        {
            var d = new DataRow();
            for (var i = 0; i < rd.FieldCount; i++) d[rd.GetName(i)] = rd.IsDBNull(i) ? null : rd.GetValue(i);
            rows.Add(d);
        }
        return rows;
    }
}

/// Refuses any statement that is not a plain read. The templates are fixed, so this is a second line, not the first.
public static class SqlGuard
{
    private static readonly string[] WriteVerbs =
        ["INSERT", "UPDATE", "DELETE", "MERGE", "DROP", "ALTER", "CREATE", "TRUNCATE", "EXEC", "EXECUTE", "GRANT", "REVOKE", "DENY", "INTO"];

    public static void AssertReadOnly(string sql)
    {
        var t = sql.TrimStart();
        if (!(t.StartsWith("SELECT", StringComparison.OrdinalIgnoreCase) || t.StartsWith("WITH", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Only SELECT statements may run.");
        foreach (var token in System.Text.RegularExpressions.Regex.Split(sql.ToUpperInvariant(), "[^A-Z_]+"))
            if (Array.IndexOf(WriteVerbs, token) >= 0)
                throw new InvalidOperationException($"Refused: '{token}' is not allowed in a read-only query.");
    }
}

/// Lenient readers for cell values: Log Analytics hands back strings, longs, doubles, DateTimeOffsets and
/// dynamic values (as BinaryData / JSON text); SQL hands back CLR types.
public static class Cell
{
    public static string Str(DataRow r, string col)
    {
        if (!r.TryGetValue(col, out var v) || v is null) return "";
        return v switch
        {
            string s => s,
            BinaryData b => b.ToString(),
            JsonElement j => j.ValueKind == JsonValueKind.String ? j.GetString() ?? "" : j.GetRawText(),
            IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
            _ => v.ToString() ?? "",
        };
    }

    public static double? DblOrNull(DataRow r, string col)
    {
        if (!r.TryGetValue(col, out var v) || v is null) return null;
        return v switch
        {
            double d => d,
            float f => f,
            int i => i,
            long l => l,
            decimal m => (double)m,
            _ => double.TryParse(Str(r, col), NumberStyles.Float, CultureInfo.InvariantCulture, out var p) ? p : null,
        };
    }

    public static double Dbl(DataRow r, string col) => DblOrNull(r, col) ?? 0d;

    public static int Int(DataRow r, string col) => (int)Math.Round(Dbl(r, col));

    public static DateTimeOffset? Time(DataRow r, string col)
    {
        if (!r.TryGetValue(col, out var v) || v is null) return null;
        return v switch
        {
            DateTimeOffset o => o,
            DateTime d => new DateTimeOffset(DateTime.SpecifyKind(d, d.Kind == DateTimeKind.Unspecified ? DateTimeKind.Utc : d.Kind)),
            _ => DateTimeOffset.TryParse(Str(r, col), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var p) ? p : null,
        };
    }

    public static DateOnly Day(DataRow r, string col)
    {
        var t = Time(r, col);
        if (t is not null) return DateOnly.FromDateTime(t.Value.UtcDateTime);
        return DateOnly.TryParse(Str(r, col), CultureInfo.InvariantCulture, out var d) ? d : default;
    }

    /// A dynamic array (make_set etc.) as strings; a plain string becomes a one-item list.
    public static IReadOnlyList<string> List(DataRow r, string col)
    {
        if (!r.TryGetValue(col, out var v) || v is null) return [];
        if (v is IEnumerable<string> e) return e.ToList();
        var text = Str(r, col).Trim();
        if (text.Length == 0) return [];
        if (!text.StartsWith('[')) return [text];
        try
        {
            using var doc = JsonDocument.Parse(text);
            return doc.RootElement.EnumerateArray()
                .Select(x => x.ValueKind == JsonValueKind.String ? x.GetString() ?? "" : x.GetRawText())
                .Where(x => x.Length > 0)
                .ToList();
        }
        catch (JsonException) { return [text]; }
    }
}
