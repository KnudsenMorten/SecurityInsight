namespace SIAnalyzer.Core.Scheduling;

/// <summary>
/// A durable, cross-replica record of "this scheduled window has already been handled"
/// (audit #9).
///
/// The exec-summary scheduler used to keep that fact in a private field, which broke twice over:
///   * TWO REPLICAS each held their own copy, so both fired - two emails to the CIO per window;
///   * A RESTART re-anchored the baseline to the most recent boundary, so a redeploy inside a
///     window made the scheduler believe that window was already done and it SILENTLY SKIPPED it.
///     On the monthly board cadence that is a whole month with no email and nothing in the log.
///
/// Both come from the same cause - the baseline lived in RAM - so both are fixed by moving it
/// here. <see cref="TryClaim"/> is the interlock: it must be ATOMIC across replicas, returning
/// true to exactly ONE caller per window.
///
/// Implementations must be thread-safe. The Azure Table implementation lives in SIAnalyzer.Web
/// because Core deliberately carries no Azure SDK.
/// </summary>
public interface ISendMarkerStore
{
    /// <summary>Human-readable description of where markers are kept, for the startup log.</summary>
    string Description { get; }

    /// <summary>Whether markers survive a restart and are shared between replicas. False for the
    /// in-memory implementation - which means #9's two failure modes are both still live, so the
    /// scheduler says so at startup rather than pretending to be safe.</summary>
    bool IsDurable { get; }

    /// <summary>The most recent window recorded as handled for this job, or null if none ever
    /// was. A first-ever start (null) keeps the anti-spam anchor: the elapsed window is NOT
    /// retroactively fired.</summary>
    DateTimeOffset? GetLastHandled(string jobName);

    /// <summary>
    /// Atomically claim <paramref name="window"/> for <paramref name="jobName"/>. Returns true
    /// only to the caller that won the race; every other replica gets false and must not send.
    /// Claiming a window that is already recorded as handled (or superseded by a later one)
    /// returns false.
    /// </summary>
    bool TryClaim(string jobName, DateTimeOffset window);
}

/// <summary>
/// The non-durable implementation: one dictionary, process-local. Correct for a single instance
/// and for the offline tests, and it is what a deployment falls back to when no table is
/// configured - with <see cref="IsDurable"/> false so the scheduler can log that #9's failure
/// modes are not actually mitigated.
/// </summary>
public sealed class InMemorySendMarkerStore : ISendMarkerStore
{
    private readonly object _lock = new();
    private readonly Dictionary<string, DateTimeOffset> _handled = new(StringComparer.OrdinalIgnoreCase);

    public string Description => "in-memory (this instance only)";
    public bool IsDurable => false;

    public DateTimeOffset? GetLastHandled(string jobName)
    {
        lock (_lock) return _handled.TryGetValue(jobName, out var v) ? v : null;
    }

    public bool TryClaim(string jobName, DateTimeOffset window)
    {
        lock (_lock)
        {
            if (_handled.TryGetValue(jobName, out var existing) && existing >= window) return false;
            _handled[jobName] = window;
            return true;
        }
    }
}
