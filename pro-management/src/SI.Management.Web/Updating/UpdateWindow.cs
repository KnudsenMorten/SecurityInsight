using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using SI.Management.Web.Data;

namespace SI.Management.Web.Updating;

/// <summary>
/// #1112 (live 2026-11-05): while an update changed the database, the serving web app waited behind the schema step's locks
/// -- a sign-in took 45 s and the health probes timed out. THE UPDATE WINDOW: while the updater runs the schema files'
/// transactions it marks the install's lock (cfg.PipelineLock 'install': Holder caj-si-updater:..., What starting with
/// <see cref="SqlUpdateWindowProbe.WindowWhat"/>, container\updater\_shared\SI-UpdaterRunGate.ps1). The web app reads that ONE
/// row (NOLOCK, a short timeout, cached for a few seconds) and meanwhile answers every page at once with a short "being
/// updated" notice (<see cref="UpdateWindowMiddleware"/>) -- never a hung request. A read that itself times out (the row's
/// table locked) counts as "being updated"; any other failure as "not" (the page then says what failed, as before).
/// Section "UpdateWindow" (the Container App's environment: UpdateWindow__Enabled ...).
/// </summary>
public sealed class UpdateWindowOptions
{
    public const string Section = "UpdateWindow";
    /// Off: no read, no notice, every query as before.
    public bool Enabled { get; set; } = true;
    /// How long one reading of the lock row is used (seconds).
    public int CacheSeconds { get; set; } = 5;
    /// The lock row's read: past this it counts as "being updated" (milliseconds).
    public int ProbeTimeoutMs { get; set; } = 2500;
    /// A page's query that runs longer than this is checked against the window; in the window it is ended and the page
    /// answers the notice (milliseconds).
    public int QueryBudgetMs { get; set; } = 5000;
    /// How often a query past its budget is checked again (milliseconds).
    public int PollMs { get; set; } = 1000;
    /// A lock whose heartbeat is older is an updater that stopped -- no window (the runner's own rule: 15 minutes).
    public int StaleMinutes { get; set; } = 15;
    /// The Retry-After of the notice (seconds) and the page's own refresh.
    public int RetryAfterSeconds { get; set; } = 20;
}

/// What one read of the lock row said.
public enum UpdateWindowReading
{
    /// No update is changing the database (or the row could not be read for another reason than time).
    NotUpdating,
    /// The updater's lock says "database schema".
    Updating,
    /// The read did not answer within its time -- the row's table is locked: counted as "being updated".
    TimedOut,
}

/// The ONE read of the update window (tests replace it).
public interface IUpdateWindowProbe
{
    Task<UpdateWindowReading> ReadAsync(CancellationToken ct);
}

/// No Pro database: never an update window.
public sealed class NoUpdateWindowProbe : IUpdateWindowProbe
{
    public Task<UpdateWindowReading> ReadAsync(CancellationToken ct) => Task.FromResult(UpdateWindowReading.NotUpdating);
}

/// <summary>
/// The lock row, read on its own connection: READ UNCOMMITTED (NOLOCK) so a writer of the row never blocks it, a LOCK_TIMEOUT
/// and a command time of <see cref="UpdateWindowOptions.ProbeTimeoutMs"/> so a schema lock on the table cannot hold it. The
/// connection is opened BEFORE the timed part (a cold connection is not an update).
/// </summary>
public sealed class SqlUpdateWindowProbe : IUpdateWindowProbe
{
    /// The lock's What while the schema files run -- the SAME text as SI-UpdaterRunGate.ps1 WindowWhat (a Pester test checks both).
    public const string WindowWhat = "an update of SecurityInsight: database schema";

    public const string Sql = """
        SET NOCOUNT ON; SET LOCK_TIMEOUT @LockMs;
        IF OBJECT_ID(N'cfg.PipelineLock') IS NULL SELECT CAST(0 AS int) AS Updating
        ELSE SELECT CASE WHEN EXISTS (SELECT 1 FROM cfg.PipelineLock WITH (NOLOCK)
                                      WHERE LockId = N'install' AND Holder LIKE N'caj-si-updater:%' AND What LIKE @What
                                        AND HeartbeatUtc >= DATEADD(minute, -@StaleMinutes, SYSUTCDATETIME()))
                         THEN 1 ELSE 0 END AS Updating;
        """;

    private readonly AzureSqlExecutor _sql;
    private readonly UpdateWindowOptions _o;

    public SqlUpdateWindowProbe(AzureSqlExecutor sql, IOptions<UpdateWindowOptions> o) { _sql = sql; _o = o.Value; }

    public async Task<UpdateWindowReading> ReadAsync(CancellationToken ct)
    {
        SqlConnection? cn = null;
        try
        {
            // the connection first, with its own (normal) time: a slow sign-in to the database is not an update
            cn = new SqlConnection(_sql.ConnectionString) { AccessToken = await _sql.TokenAsync(ct) };
            await cn.OpenAsync(ct);
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            if (cn is not null) await cn.DisposeAsync();
            return UpdateWindowReading.NotUpdating;
        }
        await using (cn)
        {
            var ms = Math.Max(250, _o.ProbeTimeoutMs);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(ms);
            try
            {
                await using var cmd = cn.CreateCommand();
                cmd.CommandText = Sql.Replace("@LockMs", Math.Max(100, ms - 200).ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal);
                cmd.CommandTimeout = (int)Math.Ceiling(ms / 1000.0);
                cmd.Parameters.AddWithValue("@What", WindowWhat + "%");
                cmd.Parameters.AddWithValue("@StaleMinutes", Math.Max(1, _o.StaleMinutes));
                var v = await cmd.ExecuteScalarAsync(cts.Token);
                return v is not null && v is not DBNull && Convert.ToInt32(v, System.Globalization.CultureInfo.InvariantCulture) == 1
                    ? UpdateWindowReading.Updating : UpdateWindowReading.NotUpdating;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return UpdateWindowReading.TimedOut; }
            // -2 = the command's time ran out; 1222 = the lock time ran out
            catch (SqlException ex) when (ex.Number is -2 or 1222) { return UpdateWindowReading.TimedOut; }
            catch (Exception) when (!ct.IsCancellationRequested) { return UpdateWindowReading.NotUpdating; }
        }
    }
}

/// <summary>
/// The update window as the requests see it: ONE reading used for <see cref="UpdateWindowOptions.CacheSeconds"/>, one read
/// at a time (the others wait for that read -- itself bounded by its timeout). Never throws.
/// </summary>
public sealed class UpdateWindowState
{
    private readonly IUpdateWindowProbe _probe;
    private readonly UpdateWindowOptions _o;
    private readonly ILogger<UpdateWindowState>? _log;
    private readonly Func<DateTime> _now;
    private readonly object _gate = new();
    private Task<bool>? _inflight;
    private bool _last;
    private DateTime _at = DateTime.MinValue;

    public UpdateWindowState(IUpdateWindowProbe probe, IOptions<UpdateWindowOptions> o, ILogger<UpdateWindowState>? log = null, Func<DateTime>? now = null)
    { _probe = probe; _o = o.Value; _log = log; _now = now ?? (() => DateTime.UtcNow); }

    public UpdateWindowOptions Options => _o;

    /// The last reading's raw answer (for the log and the tests).
    public UpdateWindowReading LastReading { get; private set; } = UpdateWindowReading.NotUpdating;

    /// Is an update changing the database now? Off (<see cref="UpdateWindowOptions.Enabled"/>): never.
    public Task<bool> IsUpdatingAsync()
    {
        if (!_o.Enabled) return Task.FromResult(false);
        lock (_gate)
        {
            if (_now() - _at < TimeSpan.FromSeconds(Math.Max(0, _o.CacheSeconds))) return Task.FromResult(_last);
            if (_inflight is not null) return _inflight;
            var t = RefreshAsync();
            if (!t.IsCompleted) _inflight = t;
            return t;
        }
    }

    private async Task<bool> RefreshAsync()
    {
        UpdateWindowReading r;
        try
        {
            // bounded here too: a read that does not end within its own time (plus a second) is a locked table -- never a wait
            using var stop = new CancellationTokenSource();
            var read = _probe.ReadAsync(stop.Token);
            var bound = Task.Delay(Math.Max(250, _o.ProbeTimeoutMs) + 1000, stop.Token);
            if (await Task.WhenAny(read, bound) == read) r = await read;
            else
            {
                r = UpdateWindowReading.TimedOut;
                _ = read.ContinueWith(t => _ = t.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
            }
            stop.Cancel();
        }
        catch (Exception) { r = UpdateWindowReading.NotUpdating; }
        var v = r != UpdateWindowReading.NotUpdating;
        lock (_gate)
        {
            if (v != _last) _log?.LogInformation("update window: {State} ({Reading})", v ? "SecurityInsight is being updated -- pages answer the notice" : "ended", r);
            _last = v; _at = _now(); _inflight = null; LastReading = r;
        }
        return v;
    }
}

/// <summary>
/// Thrown by <see cref="UpdateWindowSqlExecutor"/> instead of a query that would wait behind the update. An
/// OperationCanceledException ON PURPOSE: the app's many "catch (Exception ex) when (ex is not OperationCanceledException)"
/// let it through to <see cref="UpdateWindowMiddleware"/>, which answers the notice; a page that catches everything shows
/// <see cref="UpdateWindowNotice.Text"/> (ViewerError).
/// </summary>
public sealed class UpdateInProgressException : OperationCanceledException
{
    public UpdateInProgressException() : base(UpdateWindowNotice.Text) { }
}

/// The request being answered is guarded by the update window (set by the middleware; flows with the request's calls).
public static class UpdateWindowScope
{
    private static readonly AsyncLocal<bool> Guarded = new();
    public static bool IsGuarded => Guarded.Value;
    public static void Enter() => Guarded.Value = true;
    public static void Exit() => Guarded.Value = false;
}

/// <summary>
/// THE SQL SEAM, guarded (a decorator of the one <see cref="ISqlExecutor"/>), for a request the middleware guards:
///   * in the window: no query is sent -- <see cref="UpdateInProgressException"/> at once;
///   * a query that runs past <see cref="UpdateWindowOptions.QueryBudgetMs"/>: the window is checked (and again every
///     <see cref="UpdateWindowOptions.PollMs"/>); once it is open the query is cancelled and the request answers the notice.
/// Outside a guarded request (background work, the key ring) every call goes through exactly as before.
/// </summary>
public sealed class UpdateWindowSqlExecutor : ISqlExecutor
{
    private readonly ISqlExecutor _inner;
    private readonly UpdateWindowState _window;

    public UpdateWindowSqlExecutor(ISqlExecutor inner, UpdateWindowState window) { _inner = inner; _window = window; }

    public ISqlExecutor Inner => _inner;

    public async Task<IReadOnlyList<SqlRow>> QueryAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
    {
        var o = _window.Options;
        if (!o.Enabled || !UpdateWindowScope.IsGuarded) return await _inner.QueryAsync(sql, parameters, ct);
        if (await _window.IsUpdatingAsync()) throw new UpdateInProgressException();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var work = _inner.QueryAsync(sql, parameters, cts.Token);
        var wait = TimeSpan.FromMilliseconds(Math.Max(1, o.QueryBudgetMs));
        while (true)
        {
            var done = await Task.WhenAny(work, Task.Delay(wait, ct));
            if (done == work) return await work;
            ct.ThrowIfCancellationRequested();
            if (await _window.IsUpdatingAsync())
            {
                cts.Cancel();
                // the cancelled query's own end is observed, never awaited: the request answers now
                _ = work.ContinueWith(t => _ = t.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
                throw new UpdateInProgressException();
            }
            wait = TimeSpan.FromMilliseconds(Math.Max(1, o.PollMs));
        }
    }
}

/// The notice's words and its two shapes (a page, and an answer for a script / API call).
public static class UpdateWindowNotice
{
    public const string Title = "SecurityInsight is being updated";
    public const string Text = "SecurityInsight is being updated -- this page refreshes by itself.";
    public const string ApiText = "SecurityInsight is being updated -- try again in a moment.";

    public static bool Is(Exception? ex)
    {
        for (var e = ex; e is not null; e = e.InnerException) if (e is UpdateInProgressException) return true;
        return ex is AggregateException a && a.Flatten().InnerExceptions.Any(i => i is UpdateInProgressException);
    }

    /// A browser opening a page (GET/HEAD asking for HTML, not a script's fetch) gets the page; everything else the API shape.
    public static bool WantsPage(HttpRequest r)
    {
        if (!HttpMethods.IsGet(r.Method) && !HttpMethods.IsHead(r.Method)) return false;
        if (string.Equals(r.Headers["X-Requested-With"], "XMLHttpRequest", StringComparison.OrdinalIgnoreCase)) return false;
        var mode = r.Headers["Sec-Fetch-Mode"].ToString();
        if (mode.Length > 0) return string.Equals(mode, "navigate", StringComparison.OrdinalIgnoreCase);
        return r.Headers.Accept.ToString().Contains("text/html", StringComparison.OrdinalIgnoreCase);
    }

    public static string Page(int refreshSeconds) =>
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        + $"<meta http-equiv=\"refresh\" content=\"{refreshSeconds}\"><meta name=\"robots\" content=\"noindex\"><title>{Title}</title></head>"
        + $"<body><main><h1>{Title}</h1><p>{Text}</p><p>It usually takes a few minutes. Nothing you saved is lost.</p></main></body></html>\n";

    public static async Task WriteAsync(HttpContext ctx, UpdateWindowOptions o)
    {
        var res = ctx.Response;
        res.Clear();
        res.StatusCode = StatusCodes.Status503ServiceUnavailable;
        var retry = Math.Max(5, o.RetryAfterSeconds);
        res.Headers.RetryAfter = retry.ToString(System.Globalization.CultureInfo.InvariantCulture);
        res.Headers.CacheControl = "no-store";
        if (WantsPage(ctx.Request))
        {
            res.ContentType = "text/html; charset=utf-8";
            if (!HttpMethods.IsHead(ctx.Request.Method)) await res.WriteAsync(Page(retry));
        }
        else
        {
            res.ContentType = "application/json; charset=utf-8";
            await res.WriteAsync(System.Text.Json.JsonSerializer.Serialize(new { status = "updating", message = ApiText, retryAfterSeconds = retry }));
        }
    }
}

/// <summary>
/// The notice, before anything else of a request touches the database: in the window every page and call answers at once
/// (503 + Retry-After; a page refreshes by itself). Left alone: the health probe, /about, the sign-in's own paths and the
/// static files. A guarded request whose query meets the window on the way (<see cref="UpdateWindowSqlExecutor"/>) answers
/// the notice too, when nothing of its answer was sent yet.
/// </summary>
public sealed class UpdateWindowMiddleware
{
    private static readonly string[] OpenPaths = { "/healthz", "/about", "/signin-oidc", "/signout-callback-oidc", "/signout" };
    private static readonly HashSet<string> StaticExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".txt", ".webmanifest",
    };

    private readonly RequestDelegate _next;
    private readonly UpdateWindowState _window;

    public UpdateWindowMiddleware(RequestDelegate next, UpdateWindowState window) { _next = next; _window = window; }

    /// Never answered with the notice (a path equal to one of them or under it; a static file by its extension).
    public static bool IsExcluded(PathString path)
    {
        var p = path.Value ?? "";
        foreach (var o in OpenPaths)
            if (p.Equals(o, StringComparison.OrdinalIgnoreCase) || p.StartsWith(o + "/", StringComparison.OrdinalIgnoreCase)) return true;
        var last = p[(p.LastIndexOf('/') + 1)..];
        var dot = last.LastIndexOf('.');
        return dot > 0 && StaticExtensions.Contains(last[dot..]);
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        if (!_window.Options.Enabled || IsExcluded(ctx.Request.Path)) { await _next(ctx); return; }
        if (await _window.IsUpdatingAsync()) { await UpdateWindowNotice.WriteAsync(ctx, _window.Options); return; }
        UpdateWindowScope.Enter();
        try { await _next(ctx); }
        catch (Exception ex) when (UpdateWindowNotice.Is(ex) && !ctx.Response.HasStarted)
        {
            await UpdateWindowNotice.WriteAsync(ctx, _window.Options);
        }
        finally { UpdateWindowScope.Exit(); }
    }
}
