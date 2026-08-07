using SIAnalyzer.Core.Governance;

namespace SIAnalyzer.Web.Services;

/// <summary>
/// Runs the governance expiry sweep (audit #8: <c>SweepExpired</c> had no production caller, so
/// expiry never fired at runtime). Once at startup, then hourly.
///
/// Deliberately NOT leased across replicas, unlike the scheduled exec email (#9). The sweep only
/// flips a past-expiry record to Expired and appends an audit line; two replicas racing means the
/// loser finds nothing left to flip. An email sent twice is a defect - an idempotent state flip
/// run twice is not.
///
/// Suppression does NOT depend on this service: <see cref="GovernanceStore.IsRiskAccepted"/> and
/// <see cref="GovernanceStore.IsExempt"/> compare the expiry themselves, so an expired record
/// stops suppressing on time even if the sweep never runs. This service exists so the register
/// DISPLAYS the right lifecycle state.
/// </summary>
public sealed class GovernanceExpirySweepService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    private readonly GovernanceStore _store;
    private readonly ILogger<GovernanceExpirySweepService> _log;

    public GovernanceExpirySweepService(GovernanceStore store, ILogger<GovernanceExpirySweepService> log)
    {
        _store = store;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var n = _store.SweepExpired();
                if (n > 0) _log.LogInformation("Governance expiry sweep: {Count} record(s) flipped to Expired.", n);
            }
            catch (Exception ex)
            {
                // Fail-soft: a sweep failure must never take the app down. Suppression stays
                // correct without it (the expiry comparison is in the read path).
                _log.LogWarning(ex, "Governance expiry sweep failed; will retry at the next interval.");
            }

            try
            {
                await Task.Delay(Interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }
}
