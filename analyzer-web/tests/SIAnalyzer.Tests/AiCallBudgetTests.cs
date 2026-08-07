using Microsoft.Extensions.Logging.Abstractions;
using OpenAI.Chat;
using SIAnalyzer.Core.Ai;
using SIAnalyzer.Core.Model;
using SIAnalyzer.Web.Services;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// Audit #15 - the AI call had no output cap and no deadline of its own.
///
/// Re-verification made this WORSE than the finding said. It was written as "a slow call holds the
/// REQUEST open", but the scheduled exec email has no request in it: the hosted service passes its
/// <c>stoppingToken</c>, cancelled only at shutdown, and it calls the AI *after* claiming the send
/// window (audit #9, ScheduledExecEmailHostedService.TickAsync). A hung call there consumes the
/// window and delivers nothing - silently, until the app restarts.
///
/// ⚠️ SCOPE OF THESE TESTS. The deadline, the cap and the truncation rule are asserted directly.
/// What is NOT asserted offline is that the SDK call actually honours them, because the call goes
/// through a sealed Azure OpenAI ChatClient with no seam to fake - see REQUIREMENTS.md's hosted-gate
/// list. The wiring is verified by reading; the decisions are verified here.
/// </summary>
public class AiCallBudgetTests
{
    private static AiNarrativeService Svc(int timeoutSeconds = 45, int maxTokens = 900) =>
        new(new SIAnalyzerOptions { AiTimeoutSeconds = timeoutSeconds, AiMaxOutputTokens = maxTokens },
            NullLogger<AiNarrativeService>.Instance);

    // --- A. the defaults are bounded ------------------------------------------

    [Fact]
    public void The_shipped_defaults_bound_every_ai_call()
    {
        // The finding is that these did not exist. A default of 0/absent would reintroduce it.
        var o = new SIAnalyzerOptions();
        Assert.True(o.AiTimeoutSeconds > 0, "an AI call must have a deadline by default");
        Assert.True(o.AiMaxOutputTokens > 0, "an AI call must have an output cap by default");
        Assert.Equal(45, o.AiTimeoutSeconds);
        Assert.Equal(900, o.AiMaxOutputTokens);
    }

    [Fact]
    public void The_cap_is_sent_on_the_request()
    {
        Assert.Equal(900, Svc().ChatOptions().MaxOutputTokenCount);
        Assert.Equal(250, Svc(maxTokens: 250).ChatOptions().MaxOutputTokenCount);
    }

    [Fact]
    public void A_zero_cap_sends_none()
    {
        // The documented escape hatch, and it must be a real one: no cap sent, not a cap of 0,
        // which would make the model return nothing at all.
        Assert.Null(Svc(maxTokens: 0).ChatOptions().MaxOutputTokenCount);
    }

    // --- B. the deadline ------------------------------------------------------

    [Fact]
    public async Task The_call_gets_its_own_deadline_independent_of_the_caller()
    {
        // The scheduler's case: the caller's token will not be cancelled for hours or days, so the
        // deadline has to come from us.
        var callerNeverCancels = CancellationToken.None;
        using var cts = Svc(timeoutSeconds: 1).LinkTimeout(callerNeverCancels);

        Assert.False(cts.Token.IsCancellationRequested);
        await Task.Delay(TimeSpan.FromSeconds(2));
        Assert.True(cts.Token.IsCancellationRequested, "our own deadline must fire without the caller");
    }

    [Fact]
    public void Caller_cancellation_still_propagates_immediately()
    {
        using var caller = new CancellationTokenSource();
        using var cts = Svc().LinkTimeout(caller.Token);

        caller.Cancel();

        Assert.True(cts.Token.IsCancellationRequested);
    }

    [Fact]
    public async Task A_zero_timeout_restores_the_unbounded_behaviour()
    {
        // Documented as "not recommended"; it must nonetheless do exactly what it says, or the
        // option is a lie.
        using var cts = Svc(timeoutSeconds: 0).LinkTimeout(CancellationToken.None);
        await Task.Delay(TimeSpan.FromMilliseconds(300));
        Assert.False(cts.Token.IsCancellationRequested);
    }

    // --- C. a cap without a truncation check would be a NEW defect -------------

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Only_a_length_stop_counts_as_truncated(bool truncated)
    {
        var reason = truncated ? ChatFinishReason.Length : ChatFinishReason.Stop;
        Assert.Equal(truncated, AiNarrativeService.IsTruncated(reason));
    }

    [Fact]
    public void A_normal_stop_is_not_treated_as_truncated()
    {
        // Guards the inverse mistake: discarding good narratives would silently downgrade every
        // exec summary to the templated fallback and look like "AI is broken".
        Assert.False(AiNarrativeService.IsTruncated(ChatFinishReason.Stop));
        Assert.False(AiNarrativeService.IsTruncated(ChatFinishReason.ToolCalls));
    }

    // --- D. the fallback the timeout path depends on is real ------------------

    [Fact]
    public async Task With_ai_off_the_grounded_templated_summary_is_returned()
    {
        // Every #15 degrade path returns THIS. If the templated summary were empty or threw, the
        // timeout handling would turn a slow page into a broken one.
        var rows = SIAnalyzer.Core.DataAccess.DemoData.Load(TestData.SeedPath());
        var svc = Svc();   // no endpoint configured => AI off

        Assert.False(svc.IsAvailable);
        var r = await svc.SummarizeAsync("Summarise.", rows, Audience.Management);

        Assert.False(r.FromAi);
        Assert.False(string.IsNullOrWhiteSpace(r.Text));
    }

    [Fact]
    public async Task With_ai_off_kql_composition_returns_null_not_an_exception()
    {
        var svc = Svc();
        Assert.Null(await svc.ComposeKqlAsync("anything", new[] { "SI_Endpoint_Profile_CL" }));
    }
}
