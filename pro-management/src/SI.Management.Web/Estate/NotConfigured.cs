using SI.Management.Core;

namespace SI.Management.Web.Estate;

/// <summary>
/// Registered only when nothing else provides IEstateQueries (the shared query layer, SI.Management.Core, is built
/// separately). Every answer is empty and says why, so a page renders a clear "not configured" notice instead of a
/// chart of invented numbers.
/// </summary>
public sealed class NotConfiguredEstateQueries : IEstateQueries
{
    public const string Source = "not-configured";
    private const string Why = "(no estate query layer is registered -- IEstateQueries is not configured)";

    private static QueryResult<T> Empty<T>(T data) => new(data, Why, Source, DateTimeOffset.UtcNow);

    public Task<QueryResult<IReadOnlyList<TopRisk>>> TopRisksAsync(int top, CancellationToken ct) => Task.FromResult(Empty<IReadOnlyList<TopRisk>>(Array.Empty<TopRisk>()));
    public Task<QueryResult<IReadOnlyList<TopRisk>>> RankedAssetsAsync(int max, CancellationToken ct) => Task.FromResult(Empty<IReadOnlyList<TopRisk>>(Array.Empty<TopRisk>()));
    public Task<QueryResult<AssetDetail?>> AssetLookupAsync(string nameOrId, CancellationToken ct) => Task.FromResult(Empty<AssetDetail?>(null));
    public Task<QueryResult<IReadOnlyList<TrendPoint>>> RiskTrendAsync(int days, CancellationToken ct) => Task.FromResult(Empty<IReadOnlyList<TrendPoint>>(Array.Empty<TrendPoint>()));
    public Task<QueryResult<IReadOnlyList<DomainTrendPoint>>> DomainTrendAsync(int days, CancellationToken ct) => Task.FromResult(Empty<IReadOnlyList<DomainTrendPoint>>(Array.Empty<DomainTrendPoint>()));
    public Task<QueryResult<VulnerabilityState>> VulnerabilityStateAsync(int weeks, CancellationToken ct) => Task.FromResult(Empty(new VulnerabilityState(Array.Empty<VulnerabilityWeek>(), null)));
    public Task<QueryResult<IReadOnlyList<RunHealthRow>>> RunHealthAsync(int days, CancellationToken ct) => Task.FromResult(Empty<IReadOnlyList<RunHealthRow>>(Array.Empty<RunHealthRow>()));
}

/// <summary>
/// Wraps the real query layer so one failing query (workspace unreachable, a permission missing) renders as a notice on
/// its page instead of an error page. The failure is logged; the page shows that the data could not be read.
/// </summary>
public sealed class ResilientEstateQueries : IEstateQueries
{
    public const string Source = "unavailable";
    private readonly IEstateQueries _inner;
    private readonly ILogger<ResilientEstateQueries> _log;

    public ResilientEstateQueries(IEstateQueries inner, ILogger<ResilientEstateQueries> log) { _inner = inner; _log = log; }

    private async Task<QueryResult<T>> Guard<T>(string what, Func<Task<QueryResult<T>>> call, T empty)
    {
        try { return await call(); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "estate query {What} failed", what);
            return new QueryResult<T>(empty, $"(the {what} query failed: {ex.GetType().Name} -- see the application log)", Source, DateTimeOffset.UtcNow);
        }
    }

    public Task<QueryResult<IReadOnlyList<TopRisk>>> TopRisksAsync(int top, CancellationToken ct) => Guard("top risks", () => _inner.TopRisksAsync(top, ct), (IReadOnlyList<TopRisk>)Array.Empty<TopRisk>());
    public Task<QueryResult<IReadOnlyList<TopRisk>>> RankedAssetsAsync(int max, CancellationToken ct) => Guard("ranked assets", () => _inner.RankedAssetsAsync(max, ct), (IReadOnlyList<TopRisk>)Array.Empty<TopRisk>());
    public Task<QueryResult<AssetDetail?>> AssetLookupAsync(string nameOrId, CancellationToken ct) => Guard("asset lookup", () => _inner.AssetLookupAsync(nameOrId, ct), (AssetDetail?)null);
    public Task<QueryResult<IReadOnlyList<TrendPoint>>> RiskTrendAsync(int days, CancellationToken ct) => Guard("risk trend", () => _inner.RiskTrendAsync(days, ct), (IReadOnlyList<TrendPoint>)Array.Empty<TrendPoint>());
    public Task<QueryResult<IReadOnlyList<DomainTrendPoint>>> DomainTrendAsync(int days, CancellationToken ct) => Guard("domain trend", () => _inner.DomainTrendAsync(days, ct), (IReadOnlyList<DomainTrendPoint>)Array.Empty<DomainTrendPoint>());
    public Task<QueryResult<VulnerabilityState>> VulnerabilityStateAsync(int weeks, CancellationToken ct) => Guard("vulnerability state", () => _inner.VulnerabilityStateAsync(weeks, ct), new VulnerabilityState(Array.Empty<VulnerabilityWeek>(), null));
    public Task<QueryResult<IReadOnlyList<RunHealthRow>>> RunHealthAsync(int days, CancellationToken ct) => Guard("run health", () => _inner.RunHealthAsync(days, ct), (IReadOnlyList<RunHealthRow>)Array.Empty<RunHealthRow>());
}

public sealed class NotConfiguredChatService : IChatService
{
    public const string Message = "The chat service is not configured for this installation, so no question can be answered yet.";
    public Task<ChatAnswer> AskAsync(IReadOnlyList<ChatTurn> history, string question, bool isAdmin, CancellationToken ct)
        => Task.FromResult(new ChatAnswer(Message, Array.Empty<ToolCallTrace>()));
}
