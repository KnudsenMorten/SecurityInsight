using Microsoft.Extensions.Caching.Memory;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;

namespace SI.Management.Web.Collection;

/// <summary>
/// ONE TRUSTED RUN (owner 2026-10-19: "we need the views to use last know good run" / "and not show some parts from recent
/// run and some from last known good run"): the line in the header of every page that says which run the pages show, in
/// plain words -- "Data from the run of 19-10-2026 08:00 · a newer run is in progress", or "· the newest run did not
/// complete -- showing the last complete one" (an admin also gets the link to the pipeline). No internal names.
/// </summary>
public static class PublishedRunNoticeText
{
    public const string Lead = "Data from the run of ";
    public const string Running = " · a newer run is in progress";
    public const string NotComplete = " · the newest run did not complete — showing the last complete one";
    public const string Partial = " · a part of this run is from an earlier result";
    /// review S2: the findings per CI are not the shown run's (their part of the data sync failed) -- followed by their time,
    /// so the CI pages never present that copy as current.
    public const string CiFindingsAsOf = " · findings per CI as of ";

    /// PURE. What follows the time ("" = nothing): a run going now wins over a run that did not complete.
    public static string Tail(PublishedRunState s) =>
        (s.Running ? Running : s.RefusedAt is not null ? NotComplete : "") + (s.Partial ? Partial : "");

    /// PURE. Whether the line links to the pipeline (an admin, and the newest run did not complete).
    public static bool LinkToPipeline(PublishedRunState s, bool isAdmin) => isAdmin && !s.Running && s.RefusedAt is not null;
}

/// <summary>Which run the pages show, for the header line. Read-only, one small read, kept for <see cref="SqlPublishedRunNotices.Ttl"/>. NEVER throws.</summary>
public interface IPublishedRunNotices
{
    /// <see cref="PublishedRunState.None"/> when there is nothing to say (no data yet, or a database the update has not reached).
    Task<PublishedRunState> CurrentAsync(CancellationToken ct);
}

public sealed class SqlPublishedRunNotices : IPublishedRunNotices
{
    public static readonly TimeSpan Ttl = TimeSpan.FromSeconds(30);
    private const string CacheKey = "published-run-notice";

    private readonly ISqlExecutor _sql;
    private readonly IMemoryCache? _cache;
    private readonly ILogger<SqlPublishedRunNotices>? _log;
    public SqlPublishedRunNotices(ISqlExecutor sql, IMemoryCache? cache = null, ILogger<SqlPublishedRunNotices>? log = null) { _sql = sql; _cache = cache; _log = log; }

    public async Task<PublishedRunState> CurrentAsync(CancellationToken ct)
    {
        if (_cache is not null && _cache.TryGetValue(CacheKey, out PublishedRunState? hit) && hit is not null) return hit;
        var state = PublishedRunState.None;
        try
        {
            var rows = await _sql.QueryAsync(PublishedRun.State, new Dictionary<string, object?>(), ct);
            state = PublishedRunState.From(rows.Select(r => (IReadOnlyDictionary<string, object?>)r).ToList());
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "which run the pages show could not be read -- no line is shown");
            state = PublishedRunState.None;
        }
        _cache?.Set(CacheKey, state, Ttl);
        return state;
    }
}
