using System.Text.Json;
using System.Text.RegularExpressions;
using SI.Management.Web.Auth;
using SI.Management.Web.Data;

namespace SI.Management.Web.Updating;

/// <summary>
/// THE FIRST SIGN-IN ON THIS WEB APP, recorded for the updater. When the updater moves the web app to its standard name
/// (ca-si-web) it removes the old web app only after a person really signed in on the new one -- the updater cannot sign a
/// person in itself. So each web app records it: on the first request of this process that PASSED sign-in (an Entra
/// sign-in; never /healthz, an anonymous request or a link session) it writes its OWN row cfg.InstallState
/// 'WebAppSignedIn:&lt;its container app name&gt;' = {"app":"&lt;name&gt;","at":"&lt;utc&gt;"} through cfg.WebAppSignedInRecord (the web
/// identity holds no write right on the table). One row per app name: the procedure writes it only when that app has none,
/// never overwrites, and nothing deletes it -- the old web app's row never stands in the new one's way.
/// Cheap by design: one attempt per process lifetime, started in the background -- never awaited by the request, every
/// failure caught and logged once. The name is the one Azure Container Apps sets in every container (CONTAINER_APP_NAME);
/// without it (a local run, a test) nothing is ever written.
/// </summary>
public sealed class WebAppSignedInRecorder
{
    public const string RecordSql = "EXEC cfg.WebAppSignedInRecord @App = @App;";
    private static readonly Regex AppNameRx = new("^[a-z0-9][a-z0-9-]{0,31}$", RegexOptions.CultureInvariant);

    private readonly ISqlExecutor _sql;
    private readonly ILogger<WebAppSignedInRecorder> _log;
    private int _taken;

    public WebAppSignedInRecorder(ISqlExecutor sql, ILogger<WebAppSignedInRecorder> log, string? appName = null)
    {
        _sql = sql; _log = log;
        AppName = CleanName(appName ?? Environment.GetEnvironmentVariable("CONTAINER_APP_NAME"));
    }

    /// The container app this process runs in; null = not known (nothing is ever written).
    public string? AppName { get; }

    /// The one write of this process once it was started (tests await it); null = not started.
    public Task? Pending { get; private set; }

    /// A container app name as Azure gives it (lower-case letters, digits, '-'; at most 32); anything else = null.
    public static string? CleanName(string? name)
    {
        var n = (name ?? "").Trim();
        return AppNameRx.IsMatch(n) ? n : null;
    }

    /// A request that passed an Entra sign-in: an authenticated person, not a link session, not the health probe.
    public static bool PassedSignIn(HttpContext ctx)
    {
        var user = ctx.User;
        if (user?.Identity?.IsAuthenticated != true) return false;
        if (ctx.Request.Path.StartsWithSegments("/healthz", StringComparison.OrdinalIgnoreCase)) return false;
        if (LinkArea.IsLinkPrincipal(user) || LinkArea.IsLinkArea(ctx)) return false;
        return true;
    }

    /// Called after every request; does something at most once per process. Never throws, never waits.
    public void Observe(HttpContext ctx)
    {
        try
        {
            if (Volatile.Read(ref _taken) != 0 || AppName is null) return;
            if (!PassedSignIn(ctx)) return;
            if (Interlocked.Exchange(ref _taken, 1) != 0) return;
            var app = AppName;
            Pending = Task.Run(async () =>
            {
                try { await _sql.QueryAsync(RecordSql, new Dictionary<string, object?> { ["App"] = app }, CancellationToken.None); }
                catch (Exception ex) { try { _log.LogInformation("the first sign-in on {App} could not be recorded: {Error}", app, ex.Message); } catch { } }
            });
        }
        catch { }
    }
}

/// <summary>
/// THE OLD WEB APP SENDS PEOPLE TO THE NEW ONE. After the updater switched the install to the web app's standard name (the
/// install record cfg.InstallState 'InstallNames' names another web app than this one), this web app answers every page
/// request with a redirect to the same path and query on the new web app -- so people reach it through their old bookmark,
/// the first real sign-in there is recorded, and the updater removes this app. The health probe and the sign-in callbacks
/// are never redirected. The new web app (the record names it) never redirects. The record is read at most once a minute
/// (a failed read = no redirect for that minute). The new address is this request's host with this app's name replaced by
/// the new one (Container Apps: &lt;app&gt;.&lt;environment domain&gt;); a request on any other host (a custom domain) is left alone.
/// Without CONTAINER_APP_NAME (a local run, a test) nothing is ever redirected.
/// </summary>
public sealed class OldWebAppRedirect
{
    public const string RecordSql = "IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'InstallNames';";
    private static readonly string[] NeverRedirected = ["/healthz", "/signin-oidc", "/signout-callback-oidc"];
    private static readonly TimeSpan CacheFor = TimeSpan.FromMinutes(1);

    private readonly ISqlExecutor _sql;
    private readonly ILogger<OldWebAppRedirect> _log;
    private readonly Func<DateTime> _now;
    private readonly object _gate = new();
    private DateTime _readAt = DateTime.MinValue;
    private string? _recorded;

    public OldWebAppRedirect(ISqlExecutor sql, ILogger<OldWebAppRedirect> log, string? appName = null, Func<DateTime>? now = null)
    {
        _sql = sql; _log = log; _now = now ?? (() => DateTime.UtcNow);
        AppName = WebAppSignedInRecorder.CleanName(appName ?? Environment.GetEnvironmentVariable("CONTAINER_APP_NAME"));
    }

    public string? AppName { get; }

    /// The web app the install record names ('web'), or null.
    public static string? WebNameOf(string? recordJson)
    {
        if (string.IsNullOrWhiteSpace(recordJson)) return null;
        try
        {
            using var d = JsonDocument.Parse(recordJson);
            return d.RootElement.ValueKind == JsonValueKind.Object && d.RootElement.TryGetProperty("web", out var w) && w.ValueKind == JsonValueKind.String
                ? WebAppSignedInRecorder.CleanName(w.GetString()) : null;
        }
        catch (JsonException) { return null; }
    }

    /// The health probe and the sign-in callbacks stay on this app.
    public static bool NeverRedirect(PathString path) => NeverRedirected.Any(p => path.StartsWithSegments(p, StringComparison.OrdinalIgnoreCase));

    /// https://&lt;new app&gt;.&lt;same domain&gt;&lt;path&gt;&lt;query&gt;, or null when the request is not on this app's own address.
    public static string? Target(string ownName, string newName, HttpRequest request)
    {
        var host = request.Host.Host ?? "";
        if (!host.StartsWith(ownName + ".", StringComparison.OrdinalIgnoreCase) || ownName.Equals(newName, StringComparison.OrdinalIgnoreCase)) return null;
        return "https://" + newName + host[ownName.Length..] + request.PathBase.ToUriComponent() + request.Path.ToUriComponent() + request.QueryString.ToUriComponent();
    }

    /// The web app the install record names now -- read at most once a minute.
    public async Task<string?> RecordedWebAppAsync(CancellationToken ct)
    {
        lock (_gate) { if (_now() - _readAt < CacheFor) return _recorded; }
        string? web = null;
        try
        {
            var rows = await _sql.QueryAsync(RecordSql, new Dictionary<string, object?>(), ct);
            web = WebNameOf(rows.FirstOrDefault()?.Str("Value"));
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { try { _log.LogDebug("the install record could not be read: {Error}", ex.Message); } catch { } }
        lock (_gate) { _recorded = web; _readAt = _now(); }
        return web;
    }

    /// Redirects this request to the new web app when the install was switched to it. Never throws for a read.
    public async Task<bool> TryRedirectAsync(HttpContext ctx)
    {
        if (AppName is null || NeverRedirect(ctx.Request.Path)) return false;
        var web = await RecordedWebAppAsync(ctx.RequestAborted);
        if (web is null || web.Equals(AppName, StringComparison.OrdinalIgnoreCase)) return false;
        var target = Target(AppName, web, ctx.Request);
        if (target is null) return false;
        var safeMethod = HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsHead(ctx.Request.Method);
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Redirect(target, permanent: false, preserveMethod: !safeMethod);
        return true;
    }
}
