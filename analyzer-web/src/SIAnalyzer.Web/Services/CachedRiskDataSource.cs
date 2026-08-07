namespace SIAnalyzer.Web.Services;

/// <summary>
/// A short-TTL cache in front of the rollup read (audit #10).
///
/// <see cref="AnalyzerService"/> calls <see cref="IRiskDataSource.GetAllRowsAsync"/> from EIGHT
/// separate entry points - exec, worklist, management, board, drill-down, glossary, coaching,
/// maturity - and every one of them re-ran a query asking for up to 500,000 rows across 180 days.
/// One exec page load, one MCP conversation and one scheduled email each paid that cost again.
/// The underlying data only changes when an engine run ingests a new snapshot, which is hours
/// apart, so a few minutes of reuse is free correctness-wise and removes almost all of the load.
///
/// A DECORATOR rather than a field inside the Log Analytics class, so the caching behaviour is
/// exercised offline against a counting fake instead of needing a workspace.
///
/// Two rules that matter more than the caching itself:
///   * A PARTIAL result is NEVER cached. Caching a truncated read would keep serving understated
///     figures for the whole TTL; not caching it means the next request retries and can recover.
///   * Ad-hoc/prestaged queries (<see cref="RunGuardedQueryAsync"/>) pass straight through. An
///     analyst who runs a query twice expects to see the workspace, not a cached answer.
/// </summary>
public sealed class CachedRiskDataSource : IRiskDataSource
{
    private readonly IRiskDataSource _inner;
    private readonly TimeSpan _ttl;
    private readonly Func<DateTimeOffset> _now;
    private readonly SemaphoreSlim _gate = new(1, 1);

    private RiskSnapshot? _cached;
    private DateTimeOffset _cachedAt;

    public CachedRiskDataSource(IRiskDataSource inner, TimeSpan ttl, Func<DateTimeOffset>? now = null)
    {
        _inner = inner;
        _ttl = ttl < TimeSpan.Zero ? TimeSpan.Zero : ttl;
        _now = now ?? (() => DateTimeOffset.UtcNow);
    }

    public bool IsLive => _inner.IsLive;
    public string SourceDescription => _inner.SourceDescription;

    public async Task<RiskSnapshot> GetAllRowsAsync(CancellationToken ct = default)
    {
        if (TryGetFresh(out var hit)) return hit!;

        // Single-flight: without this, N concurrent first requests all miss and all launch the
        // same 500k-row query - the cache would make the worst case worse, not better.
        await _gate.WaitAsync(ct);
        try
        {
            if (TryGetFresh(out var second)) return second!;

            var snapshot = await _inner.GetAllRowsAsync(ct);
            if (!snapshot.Quality.IsPartial)
            {
                _cached = snapshot;
                _cachedAt = _now();
            }
            else
            {
                // Drop any previous entry too: serving an older complete snapshot while the
                // workspace is returning partial results would hide the problem behind stale data.
                _cached = null;
            }
            return snapshot;
        }
        finally
        {
            _gate.Release();
        }
    }

    public Task<QueryResult> RunGuardedQueryAsync(string kql, CancellationToken ct = default) =>
        _inner.RunGuardedQueryAsync(kql, ct);

    private bool TryGetFresh(out RiskSnapshot? snapshot)
    {
        var cached = _cached;
        if (cached is not null && _ttl > TimeSpan.Zero && _now() - _cachedAt < _ttl)
        {
            snapshot = cached;
            return true;
        }
        snapshot = null;
        return false;
    }
}
