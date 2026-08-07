using Azure.Data.Tables;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SIAnalyzer.Core.Ai;
using SIAnalyzer.Core.DataAccess;
using SIAnalyzer.Core.Exec;
using SIAnalyzer.Core.Scheduling;
using SIAnalyzer.Web.Services;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// AUDIT #9 — the scheduled exec email fires ONCE per window, across replicas and across a
/// restart (TESTS.md §9.3).
///
/// The baseline used to be a private field, which broke twice over: two replicas each kept their
/// own and both sent, and a restart re-anchored the baseline to the most recent boundary so a
/// redeploy INSIDE a window made that window look already-sent — silently skipping the board
/// email until the next cadence. Both are covered below by driving the real decision path
/// (<c>TickAsync</c>) rather than a timer.
/// </summary>
public sealed class SendMarkerStoreTests
{
    private static readonly DateTimeOffset Window = new(2026, 8, 1, 7, 0, 0, TimeSpan.Zero);

    [Fact]
    public void The_first_claim_of_a_window_wins_and_the_second_loses()
    {
        var store = new InMemorySendMarkerStore();
        Assert.True(store.TryClaim("job", Window));
        Assert.False(store.TryClaim("job", Window));
    }

    [Fact]
    public void A_later_window_can_be_claimed_after_an_earlier_one()
    {
        var store = new InMemorySendMarkerStore();
        Assert.True(store.TryClaim("job", Window));
        Assert.True(store.TryClaim("job", Window.AddMonths(1)));
        Assert.Equal(Window.AddMonths(1), store.GetLastHandled("job"));
    }

    [Fact]
    public void An_earlier_window_cannot_be_re_claimed()
    {
        // A replica whose clock or poll lags must not re-send a window that is already done.
        var store = new InMemorySendMarkerStore();
        Assert.True(store.TryClaim("job", Window));
        Assert.False(store.TryClaim("job", Window.AddDays(-1)));
        Assert.Equal(Window, store.GetLastHandled("job"));
    }

    [Fact]
    public void Jobs_do_not_share_a_marker()
    {
        var store = new InMemorySendMarkerStore();
        Assert.True(store.TryClaim("job-a", Window));
        Assert.True(store.TryClaim("job-b", Window));
        Assert.Null(store.GetLastHandled("job-c"));
    }

    [Fact]
    public void Concurrent_claims_of_one_window_produce_exactly_one_winner()
    {
        var store = new InMemorySendMarkerStore();
        var winners = 0;
        Parallel.For(0, 64, _ =>
        {
            if (store.TryClaim("job", Window)) Interlocked.Increment(ref winners);
        });
        Assert.Equal(1, winners);
    }

    [Fact]
    public void The_in_memory_store_reports_itself_as_not_durable()
    {
        // This is what makes the scheduler warn instead of implying #9 is mitigated.
        Assert.False(new InMemorySendMarkerStore().IsDurable);
    }
}

/// <summary>The Azure Table marker mapping. The ETag interlock itself needs a real table (hosted
/// gate); the row shape is checked here so a marker cannot silently land in the wrong place.</summary>
public sealed class TableSendMarkerMappingTests
{
    [Fact]
    public void A_marker_row_is_keyed_by_job_and_round_trips_its_window()
    {
        var window = new DateTimeOffset(2026, 8, 1, 7, 0, 0, TimeSpan.Zero);
        var entity = TableSendMarkerStore.NewEntity("exec-summary-email", window, "replica-1");

        Assert.Equal(TableSendMarkerStore.MarkerPartition, entity.PartitionKey);
        Assert.Equal("exec-summary-email", entity.RowKey);          // one row per job
        Assert.Equal(window, TableSendMarkerStore.ReadWindow(entity));
        Assert.Equal("replica-1", entity.GetString(TableSendMarkerStore.ClaimedByColumn));
    }

    [Fact]
    public void A_local_time_window_is_stored_in_utc()
    {
        // The cadence maths works in host-local time; replicas must still agree on the window.
        var local = new DateTimeOffset(2026, 8, 1, 7, 0, 0, TimeSpan.FromHours(2));
        var entity = TableSendMarkerStore.NewEntity("job", local, "r");
        var round = TableSendMarkerStore.ReadWindow(entity);
        Assert.Equal(TimeSpan.Zero, round!.Value.Offset);
        Assert.Equal(local.UtcDateTime, round.Value.UtcDateTime);
    }
}

/// <summary>
/// The scheduler's decision path, driven directly. Each test builds real service instances (demo
/// data, AI off, a counting sender) so a "send" is a genuine render-and-send through
/// <c>ExecEmailService</c> — only the SMTP transport is faked.
/// </summary>
public sealed class ScheduledExecEmailWindowTests
{
    // Monthly at 07:00; "now" is mid-morning on the 1st, i.e. inside a due window.
    private static readonly DateTimeOffset DueNow = new(2026, 8, 1, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Window = new(2026, 8, 1, 7, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task Two_replicas_ticking_the_same_window_send_exactly_one_email()
    {
        // THE #9 regression: with the baseline in a private field, both instances sent.
        var markers = new InMemorySendMarkerStore();          // stands in for the shared table
        markers.TryClaim(ScheduledExecEmailHostedService.JobName, Window.AddMonths(-1)); // last month's send
        var sender = new CountingSender();

        var replicaA = Build(markers, sender);
        var replicaB = Build(markers, sender);

        var aSent = await replicaA.TickAsync(SendCadence.Monthly, DueNow, default);
        var bSent = await replicaB.TickAsync(SendCadence.Monthly, DueNow, default);

        Assert.Equal(1, sender.Count);
        Assert.True(aSent ^ bSent, "exactly one replica should have sent");
    }

    [Fact]
    public async Task Control_two_replicas_with_SEPARATE_markers_send_twice()
    {
        // The control for the test above: give each replica its OWN marker store - which is
        // exactly what a private _lastSent field was - and the CIO gets the email twice. Without
        // this, a harness that could never produce a second send would pass either way.
        var sender = new CountingSender();
        var replicaA = Build(MarkerAfterLastMonth(), sender);
        var replicaB = Build(MarkerAfterLastMonth(), sender);

        Assert.True(await replicaA.TickAsync(SendCadence.Monthly, DueNow, default));
        Assert.True(await replicaB.TickAsync(SendCadence.Monthly, DueNow, default));
        Assert.Equal(2, sender.Count);
    }

    private static InMemorySendMarkerStore MarkerAfterLastMonth()
    {
        var m = new InMemorySendMarkerStore();
        m.TryClaim(ScheduledExecEmailHostedService.JobName, Window.AddMonths(-1));
        return m;
    }

    [Fact]
    public async Task A_restart_inside_an_unsent_window_still_sends()
    {
        // THE SECOND #9 failure: the old startup anchor set the baseline to the most recent
        // boundary, so a redeploy at 09:00 on the 1st skipped the 07:00 monthly send entirely
        // and the board email did not go out until the NEXT month.
        var markers = new InMemorySendMarkerStore();
        markers.TryClaim(ScheduledExecEmailHostedService.JobName, Window.AddMonths(-1));
        var sender = new CountingSender();

        var afterRestart = Build(markers, sender);
        afterRestart.EnsureAnchored(SendCadence.Monthly, DueNow);   // what startup does

        Assert.True(await afterRestart.TickAsync(SendCadence.Monthly, DueNow, default));
        Assert.Equal(1, sender.Count);
    }

    [Fact]
    public async Task A_first_ever_start_does_not_retroactively_fire_the_elapsed_window()
    {
        // The anti-spam behaviour that must survive the fix: deploying the app for the first
        // time mid-window must not immediately mail the CIO.
        var markers = new InMemorySendMarkerStore();               // no marker at all
        var sender = new CountingSender();

        var fresh = Build(markers, sender);
        fresh.EnsureAnchored(SendCadence.Monthly, DueNow);

        Assert.False(await fresh.TickAsync(SendCadence.Monthly, DueNow, default));
        Assert.Equal(0, sender.Count);
        Assert.Equal(Window, markers.GetLastHandled(ScheduledExecEmailHostedService.JobName));
    }

    [Fact]
    public async Task The_next_window_fires_after_one_was_sent()
    {
        var markers = new InMemorySendMarkerStore();
        markers.TryClaim(ScheduledExecEmailHostedService.JobName, Window.AddMonths(-1));
        var sender = new CountingSender();
        var svc = Build(markers, sender);

        Assert.True(await svc.TickAsync(SendCadence.Monthly, DueNow, default));
        Assert.False(await svc.TickAsync(SendCadence.Monthly, DueNow.AddDays(10), default));   // same window
        Assert.True(await svc.TickAsync(SendCadence.Monthly, DueNow.AddMonths(1), default));   // next window
        Assert.Equal(2, sender.Count);
    }

    [Fact]
    public async Task A_failed_send_does_not_retry_every_poll()
    {
        // Existing intent, preserved: the window stays claimed even when the transport fails,
        // so a misconfigured relay does not retry every 15 minutes.
        var markers = new InMemorySendMarkerStore();
        markers.TryClaim(ScheduledExecEmailHostedService.JobName, Window.AddMonths(-1));
        var sender = new FailingSender();
        var svc = Build(markers, sender, canSend: true);

        Assert.True(await svc.TickAsync(SendCadence.Monthly, DueNow, default));
        Assert.False(await svc.TickAsync(SendCadence.Monthly, DueNow.AddHours(1), default));
        Assert.Equal(1, sender.Attempts);
    }

    // ---------------- helpers -----------------------------------------------------

    private static ScheduledExecEmailHostedService Build(ISendMarkerStore markers, IExecEmailSender sender, bool canSend = true)
    {
        var opts = new EmailScheduleOptions
        {
            Enabled = true,
            Cadence = "monthly",
            SendAtHour = 7,
            Recipients = { "ciso@example.invalid" },
            SmtpHost = canSend ? "smtp.example.invalid" : null,
            FromAddress = canSend ? "noreply@example.invalid" : null,
        };

        var services = new ServiceCollection();
        services.AddSingleton(opts);
        services.AddSingleton<IRiskDataSource>(new DemoRiskDataSource(DemoData.Load(TestData.SeedPath())));
        services.AddSingleton<IAiNarrativeService, OfflineAi>();
        services.AddSingleton(sender);
        services.AddSingleton<AnalyzerService>();
        services.AddScoped<ExecEmailService>();
        var provider = services.BuildServiceProvider();

        return new ScheduledExecEmailHostedService(
            provider.GetRequiredService<IServiceScopeFactory>(), opts, markers,
            new NullLogger<ScheduledExecEmailHostedService>());
    }

    private sealed class CountingSender : IExecEmailSender
    {
        private int _count;
        public int Count => _count;
        public bool IsConfigured => true;
        public Task<EmailSendResult> SendAsync(ExecEmailMessage message, IReadOnlyList<string> recipients, CancellationToken ct = default)
        {
            Interlocked.Increment(ref _count);
            return Task.FromResult(EmailSendResult.Delivered(recipients.Count));
        }
    }

    private sealed class FailingSender : IExecEmailSender
    {
        public int Attempts { get; private set; }
        public bool IsConfigured => true;
        public Task<EmailSendResult> SendAsync(ExecEmailMessage message, IReadOnlyList<string> recipients, CancellationToken ct = default)
        {
            Attempts++;
            return Task.FromResult(EmailSendResult.Failed("relay refused the message"));
        }
    }

    private sealed class OfflineAi : IAiNarrativeService
    {
        public bool IsAvailable => false;
        public Task<NarrativeResult> SummarizeAsync(string instruction, IReadOnlyList<SIAnalyzer.Core.Model.RiskRow> rows, Audience audience, DiffSummary? diff = null, CancellationToken ct = default)
            => Task.FromResult(new NarrativeResult(GroundedPrompt.TemplatedSummary(rows, audience, diff), false));
        public Task<string?> ComposeKqlAsync(string question, IReadOnlyList<string> allowedTables, CancellationToken ct = default)
            => Task.FromResult<string?>(null);
    }

    private sealed class NullLogger<T> : ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => false;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
    }
}
