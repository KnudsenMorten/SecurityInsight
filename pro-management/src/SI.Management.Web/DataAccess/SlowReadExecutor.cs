using System.Diagnostics;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Data;

/// <summary>
/// EVERY SLOW READ IS SAID (owner 2026-11-05: "every views must be fast"). The outermost executor of the web app: every read
/// that takes <see cref="Slow"/> or longer is one warning in the app's log -- which statement (its name in the code, from
/// <see cref="ViewStatements"/>; a statement composed at run time by its first words), how long, how many rows, and whether
/// it failed -- and is counted (<see cref="Count"/>). It never changes a read, its answer or its error.
/// </summary>
public sealed class SlowReadExecutor : ISqlExecutor
{
    /// A read at least this long is a slow read (a page should show within it).
    public static readonly TimeSpan Slow = TimeSpan.FromSeconds(2);

    private static long _count;
    /// How many slow reads this process has seen.
    public static long Count => Interlocked.Read(ref _count);

    // the statements by their text (also as the exempted-findings scope reads them), built once
    private static readonly Lazy<IReadOnlyDictionary<string, string>> Names = new(() =>
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var s in ViewStatements.From(typeof(ViewStatements).Assembly, typeof(SlowReadExecutor).Assembly))
        {
            d.TryAdd(ViewStatements.Key(s.Text), s.Name);
            d.TryAdd(ViewStatements.Key(Exempted.Exclude(s.Text)), s.Name);
        }
        return d;
    });

    private readonly ISqlExecutor _inner;
    /// The executor every read goes through (for the wiring tests).
    public ISqlExecutor Inner => _inner;
    private readonly ILogger<SlowReadExecutor> _log;
    private readonly TimeProvider _clock;

    public SlowReadExecutor(ISqlExecutor inner, ILogger<SlowReadExecutor> log, TimeProvider? clock = null)
    {
        _inner = inner; _log = log; _clock = clock ?? TimeProvider.System;
    }

    /// PURE (given the catalog). The statement's name in the code, else its first words.
    public static string NameOf(string sql)
    {
        if (Names.Value.TryGetValue(ViewStatements.Key(sql), out var n)) return n;
        var k = ViewStatements.Key(sql);
        return "a composed read: " + (k.Length > 120 ? k[..120] + " ..." : k);
    }

    public async Task<IReadOnlyList<SqlRow>> QueryAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
    {
        var start = _clock.GetTimestamp();
        IReadOnlyList<SqlRow> rows;
        try { rows = await _inner.QueryAsync(sql, parameters, ct).ConfigureAwait(false); }
        catch (Exception ex)
        {
            var took = _clock.GetElapsedTime(start);
            if (took >= Slow) Record(sql, took, null, ex is OperationCanceledException ? "stopped" : "failed");
            throw;
        }
        var t = _clock.GetElapsedTime(start);
        if (t >= Slow) Record(sql, t, rows.Count, null);
        return rows;
    }

    private void Record(string sql, TimeSpan took, int? rows, string? ended)
    {
        Interlocked.Increment(ref _count);
        try
        {
            if (ended is null)
                _log.LogWarning("A slow page read: {Seconds:0.0} s, {Rows} rows -- {Statement}", took.TotalSeconds, rows, NameOf(sql));
            else
                _log.LogWarning("A slow page read: {Seconds:0.0} s, then {Ended} -- {Statement}", took.TotalSeconds, ended, NameOf(sql));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException) { Debug.WriteLine(ex); }   // saying it never fails the read
    }
}
