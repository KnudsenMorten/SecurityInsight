using Sia.Core.Exec;

namespace Sia.Web.Services;

/// <summary>
/// The in-host scheduler for the exec-summary email. A lightweight <see cref="BackgroundService"/>
/// that wakes periodically and, when the configured cadence is DUE (computed by the pure
/// <see cref="EmailCadenceScheduler"/>), renders + sends the grounded exec summary.
///
/// FAIL-SOFT throughout: it is a no-op when the schedule is disabled or no recipients/SMTP
/// are configured; a send error is logged, never thrown - the loop keeps running. The data
/// plane is read-only (it only reads the exec view to render). The hosting model mirrors the
/// PIM scheduler (in-container runner), kept simple: one poll loop, cadence maths is pure.
/// </summary>
public sealed class ScheduledExecEmailHostedService : BackgroundService
{
    private readonly IServiceScopeFactory _scopes;
    private readonly EmailScheduleOptions _opts;
    private readonly ILogger<ScheduledExecEmailHostedService> _log;
    private readonly TimeSpan _pollInterval;

    private DateTimeOffset? _lastSent;

    public ScheduledExecEmailHostedService(
        IServiceScopeFactory scopes,
        EmailScheduleOptions opts,
        ILogger<ScheduledExecEmailHostedService> log,
        TimeSpan? pollInterval = null)
    {
        _scopes = scopes;
        _opts = opts;
        _log = log;
        // Poll every 15 min by default; the cadence maths gates the actual send, so a coarse
        // poll is plenty and cheap. (Overridable for tests.)
        _pollInterval = pollInterval ?? TimeSpan.FromMinutes(15);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.Enabled)
        {
            _log.LogInformation("Scheduled exec-summary email is disabled (Sia:Email:Enabled=false) - scheduler idle.");
            return;
        }

        var cadence = EmailCadenceScheduler.Parse(_opts.Cadence);

        // Anchor the baseline at startup so we don't retroactively fire a window that
        // elapsed before the app started (no spam-on-every-deploy); the first send fires
        // at the NEXT genuine boundary.
        _lastSent = EmailCadenceScheduler.MostRecentFireTime(cadence, _opts.SendAtHour, DateTimeOffset.Now);

        _log.LogInformation("Scheduled exec-summary email enabled: cadence={Cadence}, hour={Hour}, recipients={Count}, next fire ~{Next:u}.",
            cadence, _opts.SendAtHour, _opts.Recipients.Count(r => !string.IsNullOrWhiteSpace(r)),
            EmailCadenceScheduler.NextFireTime(cadence, _opts.SendAtHour, DateTimeOffset.Now));

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var now = DateTimeOffset.Now;
                if (EmailCadenceScheduler.IsDue(cadence, _opts.SendAtHour, _lastSent, now))
                {
                    await SendOnceAsync(now, stoppingToken);
                }
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

    private async Task SendOnceAsync(DateTimeOffset now, CancellationToken ct)
    {
        using var scope = _scopes.CreateScope();
        var svc = scope.ServiceProvider.GetRequiredService<ExecEmailService>();
        var result = await svc.SendNowAsync(ct);
        // Mark sent for THIS cadence window even on a fail-soft non-send, so a misconfigured
        // transport does not retry every poll; a real transient failure is still retried next
        // cadence window. (Operators see the reason in the log.)
        _lastSent = now;
        if (result.Sent)
            _log.LogInformation("Scheduled exec-summary email: {Detail}", result.Detail);
        else
            _log.LogWarning("Scheduled exec-summary email not delivered: {Detail}", result.Detail);
    }
}
