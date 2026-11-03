using System.Threading.RateLimiting;

namespace SI.Management.Core;

/// <summary>
/// PER-CALLER LIMITS for the AI surfaces (the MCP server's /mcp and the in-app chat's questions): each caller -- a person's
/// object id, or the calling application -- may have at most <c>concurrent</c> calls running at once and <c>perMinute</c>
/// calls a minute (a token bucket refilled every 6 seconds, so a burst never empties a whole minute at once). Past either
/// limit the request is refused at once (no queue), so one caller can never hold the shared Pro database, Log Analytics or
/// the customer's Azure OpenAI deployment. A request the key function gives no key (another path, a GET) is not limited.
/// </summary>
public static class CallerLimits
{
    public const int DefaultChatPerMinute = 20;
    public const int DefaultChatConcurrent = 2;
    public const int DefaultMcpPerMinute = 120;
    public const int DefaultMcpConcurrent = 4;

    public static PartitionedRateLimiter<T> Create<T>(Func<T, string?> key, int perMinute, int concurrent)
    {
        var per = Math.Max(1, perMinute);
        var con = Math.Max(1, concurrent);
        var rate = PartitionedRateLimiter.Create<T, string>(r => key(r) is { } k
            ? RateLimitPartition.GetTokenBucketLimiter("r|" + k, _ => new TokenBucketRateLimiterOptions
            {
                TokenLimit = per, TokensPerPeriod = Math.Max(1, per / 10), ReplenishmentPeriod = TimeSpan.FromSeconds(6),
                QueueLimit = 0, AutoReplenishment = true,
            })
            : RateLimitPartition.GetNoLimiter("none"));
        var running = PartitionedRateLimiter.Create<T, string>(r => key(r) is { } k
            ? RateLimitPartition.GetConcurrencyLimiter("c|" + k, _ => new ConcurrencyLimiterOptions { PermitLimit = con, QueueLimit = 0 })
            : RateLimitPartition.GetNoLimiter("none"));
        return PartitionedRateLimiter.CreateChained(running, rate);
    }
}
