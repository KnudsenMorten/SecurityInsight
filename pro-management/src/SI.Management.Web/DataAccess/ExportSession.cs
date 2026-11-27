using System.Data;
using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Data.SqlClient;
using SI.Management.Web.Audit;

namespace SI.Management.Web.Data;

/// <summary>
/// #1400 (owner 2026-11-26: "SI never fewer rows than the source"; the two-agent check of 70e9294fc): ONE EXPORT, ONE VIEW OF
/// THE DATA. An export reads its rows in chunks; between two chunks the data sync may publish, an exemption may be approved, a
/// CI may be rebuilt -- offset chunks over live tables would then lose or repeat rows. While an export handler runs, every
/// statement the Pro database executor sends goes over ONE connection inside ONE SNAPSHOT-isolation transaction (Azure SQL
/// Database has ALLOW_SNAPSHOT_ISOLATION on by default): every chunk, the CI documents read twice by "Export all columns",
/// the extra columns -- all see the database as it was at the first read. A database with snapshot isolation off is read as
/// before (read committed, one connection), said once in the log; the completeness check (<see cref="Note"/>: rows written
/// against the count the first chunk saw) then tells a person when the data moved.
/// The session also carries the export's notes: the workbook writes them on its Export sheet, the audit trail records them,
/// the log says them -- never silent.
/// </summary>
public sealed partial class ExportSession : IAsyncDisposable
{
    private static readonly AsyncLocal<ExportSession?> Ambient = new();
    /// The open session of this flow (an ended one is never current: an async DisposeAsync cannot clear its caller's AsyncLocal).
    public static ExportSession? Current => Ambient.Value is { _ended: false } s ? s : null;
    private volatile bool _ended;

    private readonly ILogger _log;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private SqlConnection? _cn;
    private SqlTransaction? _tx;
    private bool _started;
    private readonly List<string> _notes = new();

    private readonly ISqlExecutor? _sql;

    private ExportSession(ILogger log, ISqlExecutor? sql) { _log = log; _sql = sql; }

    /// Starts the session of one export (ambient for the handler that runs it). <paramref name="sql"/>: the Pro database's
    /// executor (<see cref="SettleAsync"/> reads through it).
    public static ExportSession Begin(ILogger log, ISqlExecutor? sql = null)
    {
        var s = new ExportSession(log, sql);
        Ambient.Value = s;
        return s;
    }

    /// <summary>
    /// #1418 (a)(b) (review of a5a9cb402): tells whether this export reads one snapshot BEFORE anything costly is read -- when
    /// no statement went to the database yet, the cheap <see cref="SnapshotStateSql"/> goes through the executor (its first
    /// statement opens the session's connection and settles <see cref="Snapshot"/>). Nothing when it is known already, or
    /// when there is no executor.
    /// </summary>
    public async Task SettleAsync(CancellationToken ct)
    {
        if (Snapshot is not null || _sql is null) return;
        try { await _sql.QueryAsync(SnapshotStateSql, new Dictionary<string, object?>(), ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "export: whether it reads one snapshot could not be read first"); }
    }

    /// Whether the export reads one snapshot (null = no statement went to the database yet).
    public bool? Snapshot { get; private set; }
    /// Why it does not (snapshot isolation off in this database, or the check failed).
    public string? NotSnapshot { get; private set; }
    /// The statements this session ran.
    public int Statements { get; private set; }

    /// What the export has to say about itself (e.g. its rows differ from the count it began with).
    public IReadOnlyList<string> Notes { get { lock (_notes) return _notes.ToList(); } }

    public void Note(string text) { lock (_notes) if (!_notes.Contains(text)) _notes.Add(text); }

    /// A statement that must read the database AS IT IS NOW, never the export's snapshot (the published run's stamp).
    public const string LiveTag = "/* si-export-live */";

    // a write to a TABLE: the verb, not followed by a table variable or a #temp table (INSERT @x / INSERT INTO #x / DELETE
    // FROM @x / UPDATE @x / CREATE TABLE #x / DROP TABLE #x are the statement's own scratch: allowed inside a snapshot)
    [System.Text.RegularExpressions.GeneratedRegex(@"\b(INSERT|UPDATE|DELETE|MERGE|TRUNCATE|CREATE|ALTER|DROP|GRANT)\b(?!\s+(?:(?:INTO|FROM|TABLE)\s+)?(?:IF\s+EXISTS\s+)?[@#])", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex Writes();

    // string literals and comments: a word inside them ('merge', -- delete ...) is no statement
    [System.Text.RegularExpressions.GeneratedRegex(@"N?'(?:[^']|'')*'|--[^\r\n]*|/\*[\s\S]*?\*/", System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex LiteralsAndComments();

    /// <summary>
    /// Whether a statement runs inside the export's session: READS only. A statement that writes a table (a cache row, a
    /// remembered layout, the audit trail -- review of a2749b67d: a write inside a snapshot transaction can end it with 3960)
    /// and one tagged <see cref="LiveTag"/> go on their own connection, outside the snapshot, as they would without an
    /// export. Review of e2bd16d72: a write to the statement's own table variable / #temp table is a read's scratch and stays
    /// inside; words in string literals and comments are not read as verbs.
    /// </summary>
    public static bool Takes(string sql) => Takes(sql, 0);

    // #1418 (c): an EXEC in the statement's code -- of a procedure (its name) or of a dynamic text (EXEC ( ... ) / sp_executesql)
    [System.Text.RegularExpressions.GeneratedRegex(@"(?<![.@#\w\[])EXEC(?:UTE)?\b(?!\])\s*(?<t>\(|[\w.\[\]@]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex ExecCalls();

    // the literal a dynamic EXEC runs: right after "EXEC (" / "sp_executesql", N'...' with '' escapes
    [System.Text.RegularExpressions.GeneratedRegex(@"\G\s*N?'(?<s>(?:[^']|'')*)'", System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex NextLiteral();

    // right after an EXEC ( literal: only white space and the closing parenthesis
    [System.Text.RegularExpressions.GeneratedRegex(@"\G\s*\)", System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex CloseAfter();

    /// <summary>
    /// #1418 (c) (review of 6c9f60132): a write made by DYNAMIC SQL or an EXEC'd PROCEDURE is a write too -- the verbs inside
    /// the text an EXEC ( N'...' ) / sp_executesql N'...' runs are read (that text judged the same way, nested texts too); a
    /// procedure (any EXEC of a name other than sp_executesql and sys.sp_set_session_context, which only sets this
    /// connection's context) or a dynamic text whose content is not in the statement (EXEC (@x), sp_executesql @x) may
    /// write, so the statement goes outside the snapshot, as it would without an export. The export's own reads carry no
    /// such call (ExportStreamTests: every export chunk statement stays inside).
    /// </summary>
    private static bool Takes(string sql, int depth)
    {
        if (sql.Contains(LiveTag, StringComparison.Ordinal)) return false;
        var code = LiteralsAndComments().Replace(sql, m => new string(' ', m.Length));   // same offsets as sql
        if (Writes().IsMatch(code)) return false;
        foreach (System.Text.RegularExpressions.Match m in ExecCalls().Matches(code))
        {
            var t = m.Groups["t"].Value.Replace("[", "", StringComparison.Ordinal).Replace("]", "", StringComparison.Ordinal);
            var dynamic = t == "(" || t.Equals("sp_executesql", StringComparison.OrdinalIgnoreCase) || t.Equals("sys.sp_executesql", StringComparison.OrdinalIgnoreCase);
            if (!dynamic)
            {
                if (t.Equals("sys.sp_set_session_context", StringComparison.OrdinalIgnoreCase) || t.Equals("sp_set_session_context", StringComparison.OrdinalIgnoreCase)) continue;
                return false;                                                // a procedure: it may write
            }
            var lit = NextLiteral().Match(sql, m.Index + m.Length);
            if (!lit.Success) return false;                                  // EXEC (@x) / sp_executesql @x: its text is not here
            // review of 45c752500: EXEC (N'...' + @tail) runs more than its first literal -- the EXEC ( form is judged only when
            // the literal is ALL it runs (only white space, then the closing parenthesis); anything else goes outside
            if (t == "(" && !CloseAfter().IsMatch(sql, lit.Index + lit.Length)) return false;
            if (depth > 4 || !Takes(lit.Groups["s"].Value.Replace("''", "'", StringComparison.Ordinal), depth + 1)) return false;
        }
        return true;
    }

    /// Whether the database allows snapshot transactions (1 = ON).
    public const string SnapshotStateSql = "SELECT CONVERT(int, snapshot_isolation_state) AS State FROM sys.databases WHERE database_id = DB_ID();";

    /// <summary>
    /// Runs one statement on the session's connection (opened by <paramref name="open"/> on the first one, which also starts
    /// the snapshot transaction when the database allows it). One statement at a time -- a connection runs one.
    /// </summary>
    public async Task<IReadOnlyList<SqlRow>> RunAsync(Func<CancellationToken, Task<SqlConnection>> open, string sql, IReadOnlyDictionary<string, object?> parameters,
        int timeoutSeconds, CancellationToken ct)
    {
        await _gate.WaitAsync(ct);
        try
        {
            if (!_started)
            {
                _started = true;
                _cn = await open(ct);
                var state = await AzureSqlExecutor.RunAsync(_cn, null, SnapshotStateSql, new Dictionary<string, object?>(), ct, timeoutSeconds);
                if (state.FirstOrDefault()?.Long("State") == 1)
                {
                    _tx = (SqlTransaction)await _cn.BeginTransactionAsync(IsolationLevel.Snapshot, ct);
                    Snapshot = true;
                }
                else
                {
                    Snapshot = false;
                    NotSnapshot = "snapshot isolation is off in this database (ALLOW_SNAPSHOT_ISOLATION) -- the export's chunks read the live tables";
                    _log.LogWarning("export without one snapshot: {Why}; rows that change while it runs may be missing or twice (the export says so when its count differs)", NotSnapshot);
                }
            }
            Statements++;
            return await AzureSqlExecutor.RunAsync(_cn!, _tx, sql, parameters, ct, timeoutSeconds);
        }
        finally { _gate.Release(); }
    }

    public async ValueTask DisposeAsync()
    {
        _ended = true;
        if (ReferenceEquals(Ambient.Value, this)) Ambient.Value = null;
        await _gate.WaitAsync(CancellationToken.None);   // a statement still running finishes first
        try { if (_tx is not null) await _tx.CommitAsync(CancellationToken.None); }
        catch (Exception ex) when (ex is InvalidOperationException or SqlException) { /* a read-only transaction: nothing to keep */ }
        if (_tx is not null) await _tx.DisposeAsync();
        if (_cn is not null) await _cn.DisposeAsync();
        _gate.Dispose();
    }
}

/// <summary>
/// #1400 review: an export whose rows cannot be trusted -- its rows differ from the count it began with, a row came twice,
/// the data was republished while it ran. Thrown by the chunk readers; <see cref="ExportSessionPageFilter"/> answers it:
/// nothing is downloaded (never a clean-looking short file), the audit row and the log say why.
/// </summary>
public sealed class ExportIncompleteException(string message) : Exception(message);

/// <summary>
/// #1400 the page filter that gives every export handler (<see cref="AuditedAttribute"/> data.export.download / *.export) its
/// <see cref="ExportSession"/>: started before the handler, ended after it (the file is written by then). Registered after
/// the audit filter, so it runs inside the audit scope. The review of a2749b67d: (1b) the DATA-VERSION STAMP (the published
/// run: its collection, CI build, flow run, end and copy time) is read LIVE before the handler and after it -- a republish
/// during the export (also the in-place refill of the published copies, which a snapshot does not hide) and an
/// <see cref="ExportIncompleteException"/> both REFUSE the file: HTTP 409 with the words, the audit row (refused, why) and
/// a warning in the log.
/// </summary>
public sealed class ExportSessionPageFilter(ILogger<ExportSessionPageFilter> log) : IAsyncPageFilter
{
    public static bool IsExport(MethodInfo? m) =>
        m?.GetCustomAttribute<AuditedAttribute>()?.Action is { } a && (a == "data.export.download" || a.EndsWith(".export", StringComparison.Ordinal));

    /// The words a refused export answers with.
    public static string Refusal(string why) => "The data changed while it was exported -- nothing was downloaded. Export again. (" + why + ")";

    public const string Republished = "the data was republished during the export";

    public Task OnPageHandlerSelectionAsync(PageHandlerSelectedContext context) => Task.CompletedTask;

    public async Task OnPageHandlerExecutionAsync(PageHandlerExecutingContext context, PageHandlerExecutionDelegate next)
    {
        // a download is a GET (a POST that exports -- the risk index's own file -- is a small in-memory answer, never chunked)
        if (!HttpMethods.IsGet(context.HttpContext.Request.Method) || !IsExport(context.HandlerMethod?.MethodInfo)) { await next(); return; }
        var sql = context.HttpContext.RequestServices.GetService<ISqlExecutor>();
        var before = await ExportStamp.ReadAsync(sql, log, context.HttpContext.RequestAborted);
        PageHandlerExecutedContext done;
        await using (var session = ExportSession.Begin(log, sql))
        {
            done = await next();
            foreach (var n in session.Notes) log.LogWarning("export {Page}: {Note}", context.ActionDescriptor.ViewEnginePath, n);
            if (session.Notes.Count > 0 && AuditScope.Current is { } a) a.Note = string.Join(" ", session.Notes);
        }
        string? why = null;
        if (done.Exception is ExportIncompleteException incomplete) { why = incomplete.Message; done.ExceptionHandled = true; }
        else if (done.Exception is null && before is not null && await ExportStamp.ReadAsync(sql, log, CancellationToken.None) is { } after && after != before) why = Republished;
        if (why is null) return;
        if (done.Result is FileStreamResult f) await f.FileStream.DisposeAsync();
        log.LogWarning("export {Page} refused: {Why}", context.ActionDescriptor.ViewEnginePath, why);
        // a refused export sent nothing: its audit row says 0 rows (review of e2bd16d72), never the rows the file had before it was dropped
        if (AuditScope.Current is { } audit) { audit.Note = why; audit.Rows = 0; }
        done.Result = new ContentResult { StatusCode = StatusCodes.Status409Conflict, ContentType = "text/plain; charset=utf-8", Content = Refusal(why) };
    }
}

/// <summary>
/// #1400 the published run's stamp, read LIVE (outside any export snapshot: the statement carries <see cref="ExportSession.LiveTag"/>).
/// Null = no stamp to compare (no table, no executor, the read failed -- the export is not refused for that).
/// </summary>
public static class ExportStamp
{
    public static readonly string Sql = ExportSession.LiveTag + """

SET NOCOUNT ON;
IF OBJECT_ID(N'sidata.PublishedRun') IS NULL
    SELECT CAST(N'' AS nvarchar(400)) AS Stamp;
ELSE
BEGIN
    DECLARE @s nvarchar(max) = N'SELECT (SELECT CONCAT(p.DetailedCollectionId, N''|'', CONVERT(nvarchar(30), p.DetailedCollectionTime, 126), N''|'', p.CiBuildStart, N''|'', p.FlowRunId, N''|'', CONVERT(nvarchar(30), p.RunEndedUtc, 126)'
        + CASE WHEN COL_LENGTH(N'sidata.PublishedRun', N'CopiedAt') IS NULL THEN N'' ELSE N', N''|'', CONVERT(nvarchar(30), p.CopiedAt, 126)' END
        + N') FROM sidata.PublishedRun AS p WHERE p.Name = N''current'') AS Stamp;';
    EXEC (@s);
END
""";

    public static async Task<string?> ReadAsync(ISqlExecutor? sql, ILogger log, CancellationToken ct)
    {
        if (sql is null) return null;
        try { return (await sql.QueryAsync(Sql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Str("Stamp") ?? ""; }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the published run's stamp could not be read; the export is not compared with it"); return null; }
    }
}
