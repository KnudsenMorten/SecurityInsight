using SIAnalyzer.Core.Exec;
using SIAnalyzer.Core.Scheduling;

namespace SIAnalyzer.Web.Services;

/// <summary>
/// The in-host scheduler for the exec-summary email. A lightweight <see cref="BackgroundService"/>
/// that wakes periodically and, when the configured cadence is DUE (computed by the pure
/// <see cref="EmailCadenceScheduler"/>), renders + sends the grounded exec summary.
///
/// FAIL-SOFT throughout: it is a no-op when the schedule is disabled or no recipients/SMTP
/// are configured; a send error is logged, never thrown - the loop keeps running. The data
/// plane is read-only (it only reads the exec view to render).
///
/// AUDIT #9 (2026-08-05) - "have I already sent this window?" is no longer a private field.
/// It lives in <see cref="ISendMarkerStore"/>, claimed atomically per window, which fixes two
/// failures that shared that one cause:
///   * TWO REPLICAS both sent - each had its own <c>_lastSent</c>, so the CIO got the mail twice
///     per window. Now exactly one replica wins <see cref="ISendMarkerStore.TryClaim"/>; the
///     others log that they were beaten and send nothing.
///   * A RESTART SILENTLY SKIPPED A WINDOW - the baseline was re-anchored to
///     <c>MostRecentFireTime(now)</c> at startup, so a redeploy at 09:00 on the 1st made the
///     07:00 monthly send look already-done and the board email did not go out until the NEXT
///     month, with no error anywhere. The baseline now comes from the marker, so a restart
///     inside an unsent window still sends.
/// A first-ever start (no marker at all) keeps the original anti-spam behaviour: the elapsed
/// window is claimed, not fired, so deploying the app does not immediately mail the CIO.
/// </summary>
public sealed class ScheduledExecEmailHostedService : BackgroundService
{
    /// <summary>Marker key for this job. Stable - changing it re-arms every window once.</summary>
    internal const string JobName = "exec-summary-email";

    private readonly IServiceScopeFactory _scopes;
    private readonly EmailScheduleOptions _opts;
    private readonly ISendMarkerStore _markers;
    private readonly ILogger<ScheduledExecEmailHostedService> _log;
    private readonly TimeSpan _pollInterval;

    public ScheduledExecEmailHostedService(
        IServiceScopeFactory scopes,
        EmailScheduleOptions opts,
        ISendMarkerStore markers,
        ILogger<ScheduledExecEmailHostedService> log,
        TimeSpan? pollInterval = null)
    {
        _scopes = scopes;
        _opts = opts;
        _markers = markers;
        _log = log;
        // Poll every 15 min by default; the cadence maths gates the actual send, so a coarse
        // poll is plenty and cheap. (Overridable for tests.)
        _pollInterval = pollInterval ?? TimeSpan.FromMinutes(15);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.Enabled)
        {
            _log.LogInformation("Scheduled exec-summary email is disabled (SIAnalyzer:Email:Enabled=false) - scheduler idle.");
            return;
        }

        var cadence = EmailCadenceScheduler.Parse(_opts.Cadence);
        EnsureAnchored(cadence, DateTimeOffset.Now);

        if (!_markers.IsDurable)
        {
            // Do not let this look mitigated when it is not: with a process-local marker the
            // double-send and the restart-skip are both still possible.
            _log.LogWarning(
                "Scheduled exec-summary email is using a NON-DURABLE send marker ({Store}). With more than one replica the email can be sent twice per window, and a restart can skip a window. Set SIAnalyzer:Schedule:TableEndpoint to make it durable.",
                _markers.Description);
        }

        _log.LogInformation("Scheduled exec-summary email enabled: cadence={Cadence}, hour={Hour}, recipients={Count}, marker={Store}, next fire ~{Next:u}.",
            cadence, _opts.SendAtHour, _opts.Recipients.Count(r => !string.IsNullOrWhiteSpace(r)),
            _markers.Description, EmailCadenceScheduler.NextFireTime(cadence, _opts.SendAtHour, DateTimeOffset.Now));

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await TickAsync(cadence, DateTimeOffset.Now, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break; // shutting down
            }
            catch (Exception ex)
            {
                // Fail-soft: never let the scheduler loop die.
                _log.LogWarning(ex, "Scheduled exec-summary email tick failed (fail-soft); will retry next poll.");
            }

            try { await Task.Delay(_pollInterval, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>
    /// One scheduler tick at <paramref name="now"/>. Returns true if THIS instance sent (or
    /// attempted) the window's email. Internal so the tests can drive the real decision path -
    /// including two instances ticking the same window against one marker store - without
    /// running a timer loop.
    /// </summary>
    internal async Task<bool> TickAsync(SendCadence cadence, DateTimeOffset now, CancellationToken ct)
    {
        var lastHandled = _markers.GetLastHandled(JobName);
        if (!EmailCadenceScheduler.IsDue(cadence, _opts.SendAtHour, lastHandled, now)) return false;

        // The WINDOW, not "now", is the unit every replica agrees on.
        var window = EmailCadenceScheduler.MostRecentFireTime(cadence, _opts.SendAtHour, now);
        if (!_markers.TryClaim(JobName, window))
        {
            _log.LogInformation("Scheduled exec-summary email for the {Window:u} window was already claimed by another instance - not sending.", window);
            return false;
        }

        await SendOnceAsync(ct);
        return true;
    }

    /// <summary>
    /// Seed the marker on a FIRST-EVER start so an elapsed window is not retroactively fired
    /// (no mail blast on first deploy). Only when there is no marker at all: once one exists it
    /// is the truth, which is what makes a restart inside an unsent window still send.
    /// </summary>
    internal void EnsureAnchored(SendCadence cadence, DateTimeOffset now)
    {
        if (_markers.GetLastHandled(JobName) is not null) return;
        var anchor = EmailCadenceScheduler.MostRecentFireTime(cadence, _opts.SendAtHour, now);
        _markers.TryClaim(JobName, anchor);
        _log.LogInformation("No previous exec-summary send on record - anchoring at {Anchor:u} so the elapsed window is not fired retroactively.", anchor);
    }

    private async Task SendOnceAsync(CancellationToken ct)
    {
        using var scope = _scopes.CreateScope();
        var svc = scope.ServiceProvider.GetRequiredService<ExecEmailService>();
        var result = await svc.SendNowAsync(ct);
        // The window stays claimed even on a fail-soft non-send, so a misconfigured transport
        // does not retry every poll; a real transient failure is retried at the next cadence
        // window. (Operators see the reason in the log.)
        if (result.Sent)
            _log.LogInformation("Scheduled exec-summary email: {Detail}", result.Detail);
        else
            _log.LogWarning("Scheduled exec-summary email not delivered: {Detail}", result.Detail);
    }
}
