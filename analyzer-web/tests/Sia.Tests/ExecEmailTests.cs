using Sia.Core.Ai;
using Sia.Core.DataAccess;
using Sia.Core.Exec;
using Sia.Web.Services;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// Tests for the scheduled exec-summary email (TESTS.md §9.x): the grounded email
/// rendering, the pure cadence scheduling maths, and the fail-soft send orchestration.
/// The email reuses the SAME grounded exec view as the dashboard + board deck; it must
/// carry the grounded numbers (never recompute/invent), stay free of KQL/jargon, link to
/// the board deck only when configured, and NEVER crash when no recipients/SMTP are set.
/// </summary>
public sealed class ExecEmailTests
{
    private static ExecViewModel Vm()
    {
        var data = new DemoRiskDataSource(DemoData.Load(TestData.SeedPath()));
        var svc = new AnalyzerService(data, new OfflineAi());
        return svc.GetExecAsync().GetAwaiter().GetResult();
    }

    // ---------------- rendering (grounded) ----------------------------------------

    [Fact]
    public void Email_renders_grounded_headline_score_band_and_verdict()
    {
        var vm = Vm();
        var msg = ExecEmailRenderer.Render(vm.Dashboard.Headline, vm.Dashboard, vm.ExecSummary, vm.SummaryFromAi, vm.IsLive);

        // The exact grounded verdict + score + band appear (not recomputed).
        Assert.Contains(vm.Dashboard.Headline.Sentence, msg.HtmlBody);
        Assert.Contains(vm.Dashboard.Headline.Score.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture), msg.HtmlBody);
        Assert.Contains(vm.Dashboard.ScoreBand, msg.HtmlBody);
        // Subject carries the band + direction so it reads in the inbox preview.
        Assert.Contains(vm.Dashboard.ScoreBand, msg.Subject);
        Assert.Contains("Security posture", msg.Subject);
    }

    [Fact]
    public void Email_shows_the_board_facts_and_a_text_alternative()
    {
        var vm = Vm();
        var msg = ExecEmailRenderer.Render(vm.Dashboard.Headline, vm.Dashboard, vm.ExecSummary, vm.SummaryFromAi, vm.IsLive);

        Assert.Contains("What this means", msg.HtmlBody);
        Assert.Contains("Top risks right now", msg.HtmlBody);
        Assert.Contains("Recommended next actions", msg.HtmlBody);
        // Plain-text twin is always produced + carries the same verdict.
        Assert.False(string.IsNullOrWhiteSpace(msg.TextBody));
        Assert.Contains(vm.Dashboard.Headline.Sentence, msg.TextBody);
        Assert.Contains("WHAT THIS MEANS", msg.TextBody);
    }

    [Fact]
    public void Email_has_no_kql_or_jargon()
    {
        var vm = Vm();
        var msg = ExecEmailRenderer.Render(vm.Dashboard.Headline, vm.Dashboard, vm.ExecSummary, vm.SummaryFromAi, vm.IsLive);
        foreach (var body in new[] { msg.HtmlBody, msg.TextBody })
        {
            Assert.DoesNotContain("CollectionTime", body);
            Assert.DoesNotContain("RiskScoreTotal", body);
            Assert.DoesNotContain("summarize", body);
            Assert.DoesNotContain("_CL", body);
        }
        // Honesty line about no invented figures.
        Assert.Contains("no cost or likelihood is implied", msg.HtmlBody);
    }

    [Fact]
    public void Email_links_to_the_board_deck_only_when_configured()
    {
        var vm = Vm();
        var without = ExecEmailRenderer.Render(vm.Dashboard.Headline, vm.Dashboard, vm.ExecSummary, vm.SummaryFromAi, vm.IsLive, boardDeckUrl: null);
        Assert.DoesNotContain("View the full board deck", without.HtmlBody);

        var with = ExecEmailRenderer.Render(vm.Dashboard.Headline, vm.Dashboard, vm.ExecSummary, vm.SummaryFromAi, vm.IsLive,
            boardDeckUrl: "https://example.invalid/board");
        Assert.Contains("View the full board deck", with.HtmlBody);
        Assert.Contains("https://example.invalid/board", with.HtmlBody);
        Assert.Contains("https://example.invalid/board", with.TextBody);
    }

    [Fact]
    public void Email_subject_uses_org_label_when_set_but_never_requires_it()
    {
        var vm = Vm();
        var generic = ExecEmailRenderer.Render(vm.Dashboard.Headline, vm.Dashboard, vm.ExecSummary, vm.SummaryFromAi, vm.IsLive);
        Assert.DoesNotContain(" for ", generic.Subject);

        var labelled = ExecEmailRenderer.Render(vm.Dashboard.Headline, vm.Dashboard, vm.ExecSummary, vm.SummaryFromAi, vm.IsLive, orgLabel: "Acme");
        Assert.Contains("for Acme", labelled.Subject);
    }

    // ---------------- cadence scheduling (pure) -----------------------------------

    [Fact]
    public void Cadence_parses_known_values_and_defaults_to_monthly()
    {
        Assert.Equal(SendCadence.Daily, EmailCadenceScheduler.Parse("daily"));
        Assert.Equal(SendCadence.Weekly, EmailCadenceScheduler.Parse("WEEKLY"));
        Assert.Equal(SendCadence.Monthly, EmailCadenceScheduler.Parse("monthly"));
        Assert.Equal(SendCadence.Monthly, EmailCadenceScheduler.Parse(null));
        Assert.Equal(SendCadence.Monthly, EmailCadenceScheduler.Parse("nonsense"));
    }

    [Fact]
    public void Daily_send_is_due_after_the_hour_and_not_twice_in_one_window()
    {
        var off = TimeSpan.Zero;
        var afterHour = new DateTimeOffset(2026, 6, 18, 7, 30, 0, off);

        // Anchored (null = no baseline): never retroactively fires the current/past window.
        Assert.False(EmailCadenceScheduler.IsDue(SendCadence.Daily, 7, null, afterHour));

        // Baseline anchored to yesterday's fire => due once today's hour has passed.
        var anchoredYesterday = new DateTimeOffset(2026, 6, 17, 7, 0, 0, off);
        Assert.True(EmailCadenceScheduler.IsDue(SendCadence.Daily, 7, anchoredYesterday, afterHour));

        // Already sent in this window => not due again the same day.
        var sentToday = new DateTimeOffset(2026, 6, 18, 7, 5, 0, off);
        Assert.False(EmailCadenceScheduler.IsDue(SendCadence.Daily, 7, sentToday, afterHour));

        // Next day after the hour => due again.
        var nextDay = new DateTimeOffset(2026, 6, 19, 7, 5, 0, off);
        Assert.True(EmailCadenceScheduler.IsDue(SendCadence.Daily, 7, sentToday, nextDay));
    }

    [Fact]
    public void Monthly_send_fires_on_the_first_and_only_once_per_month()
    {
        var off = TimeSpan.Zero;

        // Baseline anchored to last month's fire => due once this month's 1st-at-hour has passed.
        var anchoredLastMonth = new DateTimeOffset(2026, 5, 1, 7, 0, 0, off);
        var firstAfterHour = new DateTimeOffset(2026, 6, 1, 8, 0, 0, off);
        Assert.True(EmailCadenceScheduler.IsDue(SendCadence.Monthly, 7, anchoredLastMonth, firstAfterHour));

        // Anchored (null) never retroactively fires.
        Assert.False(EmailCadenceScheduler.IsDue(SendCadence.Monthly, 7, null, firstAfterHour));

        var sentThisMonth = new DateTimeOffset(2026, 6, 1, 7, 1, 0, off);
        var midMonth = new DateTimeOffset(2026, 6, 18, 12, 0, 0, off);
        Assert.False(EmailCadenceScheduler.IsDue(SendCadence.Monthly, 7, sentThisMonth, midMonth));

        var nextMonth = new DateTimeOffset(2026, 7, 1, 7, 1, 0, off);
        Assert.True(EmailCadenceScheduler.IsDue(SendCadence.Monthly, 7, sentThisMonth, nextMonth));
    }

    [Fact]
    public void Weekly_fire_lands_on_monday_and_next_fire_advances_a_week()
    {
        var off = TimeSpan.Zero;
        // 2026-06-18 is a Thursday; the most recent Monday-at-7 is 2026-06-15 07:00.
        var thursday = new DateTimeOffset(2026, 6, 18, 9, 0, 0, off);
        var recent = EmailCadenceScheduler.MostRecentFireTime(SendCadence.Weekly, 7, thursday);
        Assert.Equal(DayOfWeek.Monday, recent.DayOfWeek);
        Assert.Equal(new DateTimeOffset(2026, 6, 15, 7, 0, 0, off), recent);

        var next = EmailCadenceScheduler.NextFireTime(SendCadence.Weekly, 7, thursday);
        Assert.Equal(new DateTimeOffset(2026, 6, 22, 7, 0, 0, off), next);
        Assert.True(next > thursday);
    }

    // ---------------- send orchestration (fail-soft) ------------------------------

    [Fact]
    public async Task SendNow_is_fail_soft_with_no_recipients()
    {
        var svc = MakeService(new EmailScheduleOptions()); // no recipients
        var result = await svc.SendNowAsync();
        Assert.False(result.Sent);
        Assert.Equal(0, result.RecipientCount);
        Assert.Contains("recipient", result.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SendNow_renders_and_routes_through_the_sender_when_recipients_set()
    {
        var opts = new EmailScheduleOptions { Recipients = { "ciso@example.invalid" } };
        var capture = new CapturingSender();
        var svc = MakeService(opts, capture);

        var result = await svc.SendNowAsync();
        Assert.True(result.Sent);
        Assert.Equal(1, result.RecipientCount);
        Assert.NotNull(capture.LastMessage);
        // The routed message is the grounded email (carries the verdict).
        var vm = Vm();
        Assert.Contains(vm.Dashboard.Headline.Sentence, capture.LastMessage!.HtmlBody);
    }

    [Fact]
    public async Task SmtpSender_is_not_configured_and_fail_soft_without_host_or_from()
    {
        var opts = new EmailScheduleOptions { Recipients = { "ciso@example.invalid" } }; // no SmtpHost/From
        var sender = new SmtpExecEmailSender(opts, new NullLogger<SmtpExecEmailSender>());
        Assert.False(sender.IsConfigured);

        var vm = Vm();
        var msg = ExecEmailRenderer.Render(vm.Dashboard.Headline, vm.Dashboard, vm.ExecSummary, vm.SummaryFromAi, vm.IsLive);
        var result = await sender.SendAsync(msg, opts.Recipients);
        Assert.False(result.Sent); // reported, not thrown
        Assert.Contains("configured", result.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Options_CanSend_requires_recipient_host_and_from()
    {
        Assert.False(new EmailScheduleOptions().CanSend);
        Assert.False(new EmailScheduleOptions { Recipients = { "a@b.invalid" } }.CanSend);
        var full = new EmailScheduleOptions
        {
            Recipients = { "a@b.invalid" },
            SmtpHost = "smtp.example.invalid",
            FromAddress = "noreply@example.invalid",
        };
        Assert.True(full.CanSend);
        Assert.Equal("https://app.example.invalid/board",
            new EmailScheduleOptions { BaseUrl = "https://app.example.invalid/" }.BoardDeckUrl);
    }

    // ---------------- helpers -----------------------------------------------------

    private static ExecEmailService MakeService(EmailScheduleOptions opts, IExecEmailSender? sender = null)
    {
        var data = new DemoRiskDataSource(DemoData.Load(TestData.SeedPath()));
        var analyzer = new AnalyzerService(data, new OfflineAi());
        return new ExecEmailService(analyzer, sender ?? new CapturingSender(), opts);
    }

    private sealed class CapturingSender : IExecEmailSender
    {
        public ExecEmailMessage? LastMessage { get; private set; }
        public bool IsConfigured => true;
        public Task<EmailSendResult> SendAsync(ExecEmailMessage message, IReadOnlyList<string> recipients, CancellationToken ct = default)
        {
            LastMessage = message;
            return Task.FromResult(EmailSendResult.Delivered(recipients.Count));
        }
    }

    private sealed class OfflineAi : IAiNarrativeService
    {
        public bool IsAvailable => false;
        public Task<NarrativeResult> SummarizeAsync(string instruction, IReadOnlyList<Sia.Core.Model.RiskRow> rows, Audience audience, DiffSummary? diff = null, CancellationToken ct = default)
            => Task.FromResult(new NarrativeResult(GroundedPrompt.TemplatedSummary(rows, audience, diff), false));
        public Task<string?> ComposeKqlAsync(string question, IReadOnlyList<string> allowedTables, CancellationToken ct = default)
            => Task.FromResult<string?>(null);
    }

    private sealed class NullLogger<T> : Microsoft.Extensions.Logging.ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => false;
        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
    }
}
