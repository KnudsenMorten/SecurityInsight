using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;

namespace SI.Management.Web.Timing;

/// Section "PageTiming" (the Container App's environment: PageTiming__SlowMs).
public sealed class PageTimingOptions
{
    public const string Section = "PageTiming";
    /// A request that takes longer than this many milliseconds writes ONE line to the log. Below zero: never.
    public int SlowMs { get; set; } = 1000;
}

/// <summary>
/// What ONE request spent in the Pro database: the number of calls, their total time and the slowest statement. The
/// request's timer is ambient (it flows with the request's async calls), so the one SQL seam adds to it without knowing
/// about a request; outside a request (a background pass) there is none and nothing is counted.
/// </summary>
public sealed class PageTimer
{
    private static readonly AsyncLocal<PageTimer?> Ambient = new();
    public static PageTimer? Current { get => Ambient.Value; set => Ambient.Value = value; }

    private readonly object _gate = new();
    private int _calls;
    private TimeSpan _total;
    private TimeSpan _slowest;
    private string? _slowestSql;

    public int Calls { get { lock (_gate) return _calls; } }
    public TimeSpan Total { get { lock (_gate) return _total; } }
    public TimeSpan Slowest { get { lock (_gate) return _slowest; } }
    /// The slowest statement's text as it was sent (the log line shows <see cref="Shape"/> of it).
    public string? SlowestSql { get { lock (_gate) return _slowestSql; } }

    /// One call to the database (a page may run several at once: guarded).
    public void Sql(string sql, TimeSpan elapsed)
    {
        lock (_gate)
        {
            _calls++;
            _total += elapsed;
            if (_slowestSql is null || elapsed > _slowest) { _slowest = elapsed; _slowestSql = sql; }
        }
    }

    /// Adds a call to the current request's timer, when there is one.
    public static void Record(string sql, TimeSpan elapsed) => Current?.Sql(sql, elapsed);

    private static readonly Regex Comment = new(@"--[^\r\n]*|/\*.*?\*/", RegexOptions.Compiled | RegexOptions.Singleline);
    private static readonly Regex Text = new(@"N?'(?:[^']|'')*'", RegexOptions.Compiled);
    private static readonly Regex Number = new(@"(?<![\w@#\[])(?:0x[0-9A-Fa-f]+|\d[\d.]*)", RegexOptions.Compiled);
    private static readonly Regex Space = new(@"\s+", RegexOptions.Compiled);

    /// The start of a statement WITHOUT its values: comments, quoted texts and numbers are removed before it is cut, so
    /// the line names the statement and never carries a value a person typed (values travel as parameters anyway).
    public static string Shape(string? sql, int length = 80)
    {
        if (string.IsNullOrWhiteSpace(sql)) return "";
        // a statement far longer than what is shown is cut first: the patterns then run over a few hundred characters
        var s = sql.Length > 600 ? sql[..600] : sql;
        s = Comment.Replace(s, " ");
        s = Text.Replace(s, "?");
        // an unfinished quoted text (the cut above went through it): nothing after its opening quote is kept
        var open = s.IndexOf('\'');
        if (open >= 0) s = s[..open] + "?";
        s = Number.Replace(s, "?");
        s = Space.Replace(s, " ").Trim();
        return s.Length > length ? s[..length] : s;
    }
}

/// <summary>
/// The page timing log: a request that took longer than PageTiming:SlowMs (default one second) writes ONE Information
/// line through the category <see cref="Category"/> (its own, so the Microsoft.AspNetCore Warning level does not hide
/// it): method, the page's ROUTE (never the address: no query string, no id), status, total time, the number of database
/// calls and their time, and the slowest statement's time and shape. No user name. Static files and the health probe are
/// not timed. It never changes a response and never fails a request.
/// </summary>
public sealed class PageTimingMiddleware
{
    public const string Category = "SecurityInsight.PageTiming";

    private readonly RequestDelegate _next;
    private readonly ILogger _log;
    private readonly int _slowMs;
    private readonly TimeProvider _time;

    public PageTimingMiddleware(RequestDelegate next, ILoggerFactory loggers, IOptions<PageTimingOptions> options, TimeProvider? time = null)
    {
        _next = next;
        _log = loggers.CreateLogger(Category);
        _slowMs = options.Value.SlowMs;
        _time = time ?? TimeProvider.System;
    }

    /// The route of the request's endpoint ("/Cis/Index", "/Cis/Ci/{key}"); null for what is not timed: no endpoint (a
    /// static file, an address nothing answers) and the health probe.
    public static string? RouteOf(HttpContext ctx)
    {
        if (ctx.GetEndpoint() is not RouteEndpoint endpoint) return null;
        var route = "/" + (endpoint.RoutePattern.RawText ?? "").TrimStart('/');
        return string.Equals(route, "/healthz", StringComparison.OrdinalIgnoreCase) ? null : route;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        var route = _slowMs < 0 ? null : RouteOf(ctx);
        if (route is null) { await _next(ctx); return; }

        var before = PageTimer.Current;
        var timer = new PageTimer();
        PageTimer.Current = timer;
        var started = _time.GetTimestamp();
        var failed = false;
        try { await _next(ctx); }
        catch { failed = true; throw; }
        finally
        {
            PageTimer.Current = before;
            try
            {
                var ms = (long)_time.GetElapsedTime(started).TotalMilliseconds;
                if (ms > _slowMs)
                {
                    // an exception that left here is answered by the error page further out: the status is not set yet
                    var status = failed && ctx.Response.StatusCode < 400 ? 500 : ctx.Response.StatusCode;
                    _log.LogInformation("slow page: {Method} {Route} -> {Status} in {TotalMs} ms; database: {SqlCalls} calls, {SqlMs} ms; slowest {SlowestMs} ms: {Slowest}",
                        ctx.Request.Method, route, status, ms, timer.Calls, (long)timer.Total.TotalMilliseconds, (long)timer.Slowest.TotalMilliseconds,
                        timer.Calls == 0 ? "(none)" : PageTimer.Shape(timer.SlowestSql));
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { /* timing never fails a request */ }
        }
    }
}

public static class PageTimingExtensions
{
    /// After UseRouting (the route is known), before authentication: the time is what the person waited.
    public static IApplicationBuilder UsePageTiming(this IApplicationBuilder app) => app.UseMiddleware<PageTimingMiddleware>();
}
