using System.Globalization;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;

namespace SI.Management.Web.Collection;

/// A data sync is running: since when (UTC, by the database's clock). The pages show the data from before it until it
/// has finished -- what the web app has read stays as it is while the run stores its data
/// (<see cref="DataSyncSignal"/>, the same signal the views' result cache holds on).
public sealed record SyncNotice(DateTime StartedUtc)
{
    /// The sentence around the start time (the layout puts the time between the two halves, in the viewer's own zone).
    public const string Before = "Data is being refreshed (started ";
    public const string After = ") — the pages show the previous data until it is done.";
}

/// <summary>
/// Whether a data sync is running now, for the notice in the header of every page. Read-only, one small read, kept for
/// <see cref="SqlSyncNotices.Ttl"/>; a database without the table, no row, or a row older than the limit (a run that
/// died) is "none". NEVER throws: a failed read shows no notice and is logged.
/// </summary>
public interface ISyncNotices
{
    Task<SyncNotice?> CurrentAsync(CancellationToken ct);
}

public sealed class SqlSyncNotices : ISyncNotices
{
    public static readonly TimeSpan Ttl = TimeSpan.FromSeconds(30);

    /// The row the data sync writes when it starts and takes away when it ends (sidata.ViewState 'sync'): when it was
    /// written and how old it is, both by the database's clock.
    public const string CurrentSql = """
IF OBJECT_ID(N'sidata.ViewState') IS NULL
    SELECT TOP (0) CAST(NULL AS datetime2(0)) AS StartedAt, CAST(NULL AS int) AS AgeSeconds;
ELSE
    SELECT v.UpdatedAt AS StartedAt, DATEDIFF(SECOND, v.UpdatedAt, SYSUTCDATETIME()) AS AgeSeconds FROM sidata.ViewState AS v WHERE v.Name = N'sync';
""";

    private const string CacheKey = "sync-notice-current";
    // what is kept is never null (a kept "none" must be told from "not kept")
    private sealed record Kept(SyncNotice? Notice);

    private readonly ISqlExecutor _sql;
    private readonly IMemoryCache? _cache;
    private readonly ILogger<SqlSyncNotices>? _log;
    public SqlSyncNotices(ISqlExecutor sql, IMemoryCache? cache = null, ILogger<SqlSyncNotices>? log = null) { _sql = sql; _cache = cache; _log = log; }

    /// The notice of one answered row; null when the row does not say "running" (no start, or older than the limit).
    public static SyncNotice? From(SqlRow r)
    {
        if (!r.TryGetValue("StartedAt", out var s) || s is not DateTime started) return null;
        long? age = null;
        try { age = r.Long("AgeSeconds"); } catch (Exception ex) when (ex is FormatException or InvalidCastException or OverflowException) { age = null; }
        // the same rule as the result cache: a start, and not older than the limit
        return DataSyncSignal.Running(started.ToString("o", CultureInfo.InvariantCulture), age) ? new SyncNotice(DateTime.SpecifyKind(started, DateTimeKind.Utc)) : null;
    }

    public async Task<SyncNotice?> CurrentAsync(CancellationToken ct)
    {
        if (_cache is not null && _cache.TryGetValue(CacheKey, out Kept? hit) && hit is not null) return hit.Notice;
        SyncNotice? notice = null;
        try
        {
            var rows = await _sql.QueryAsync(CurrentSql, new Dictionary<string, object?>(), ct);
            notice = rows.Select(From).FirstOrDefault(n => n is not null);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "whether a data sync is running could not be read -- no notice is shown");
            notice = null;
        }
        _cache?.Set(CacheKey, new Kept(notice), Ttl);
        return notice;
    }
}
