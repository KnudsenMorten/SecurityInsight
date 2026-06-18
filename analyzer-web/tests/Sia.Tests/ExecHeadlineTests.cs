using Sia.Core.Analysis;
using Sia.Core.DataAccess;
using Sia.Core.Exec;
using Sia.Core.Model;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// Tests for the one-sentence exec headline (TESTS.md §9.8): the "if you read one thing"
/// verdict at the top of the exec view. It must be GROUNDED - the band/direction come
/// from the real score+delta, and "N actions to next band" is a real, achievable count
/// derived from the actual top findings (remove those N -> score crosses the boundary).
/// It must never invent a cost, a probability or a date.
/// </summary>
public sealed class ExecHeadlineTests
{
    private static IReadOnlyList<RiskRow> Demo() => DemoData.Load(TestData.SeedPath());

    private static RiskRow Row(double score, string name) => new()
    {
        ConfigurationName = name,
        ConfigurationId = name,
        RiskScoreTotal = score,
        SecuritySeverity = "High",
        SecurityDomain = "endpoint",
        CollectionTime = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
    };

    [Fact]
    public void Headline_band_and_score_match_the_dashboard_rollup()
    {
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var expectedScore = Math.Round(latest.Sum(r => r.RiskScoreTotal), 1);

        var hl = ExecHeadlineBuilder.Build(rows);

        Assert.Equal(expectedScore, hl.Score);
        // Band uses the exact same thresholds as the dial/band display.
        Assert.Equal(ExecDashboardBuilder.ScoreBand(expectedScore), hl.Band);
    }

    [Fact]
    public void Headline_is_carried_on_the_dashboard()
    {
        var dash = ExecDashboardBuilder.Build(Demo());
        Assert.NotNull(dash.Headline);
        Assert.Equal(dash.HeadlineScore, dash.Headline.Score);
        Assert.Equal(dash.ScoreBand, dash.Headline.Band);
        Assert.False(string.IsNullOrWhiteSpace(dash.Headline.Sentence));
    }

    [Fact]
    public void Headline_sentence_is_plain_language_no_kql_or_jargon()
    {
        var hl = ExecHeadlineBuilder.Build(Demo());
        Assert.DoesNotContain("RiskScoreTotal", hl.Sentence);
        Assert.DoesNotContain("CollectionTime", hl.Sentence);
        Assert.DoesNotContain("_CL", hl.Sentence);
        Assert.DoesNotContain("summarize", hl.Sentence);
        // It is one sentence about the posture.
        Assert.Contains("posture", hl.Sentence, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Headline_never_invents_a_cost_or_probability_figure()
    {
        var hl = ExecHeadlineBuilder.Build(Demo());
        // No currency symbols / money words and no fabricated probability.
        Assert.DoesNotContain("$", hl.Sentence);
        Assert.DoesNotContain("€", hl.Sentence);
        Assert.DoesNotContain("likelihood", hl.Sentence, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("probability", hl.Sentence, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Actions_to_next_band_is_a_real_achievable_count()
    {
        // Two findings of 150 each -> total 300 = "Elevated" (>=200). Removing the single
        // 150 finding drops it to 150 = "Moderate" (>=75), so the answer must be: 1 action
        // moves you to Moderate. This proves the count is grounded in the actual rows.
        var rows = new[] { Row(150, "a"), Row(150, "b") };
        var hl = ExecHeadlineBuilder.Build(rows, scoreDelta: 0, previousTotal: 0);

        Assert.Equal("Elevated", hl.Band);
        Assert.Equal("Moderate", hl.NextBand);
        Assert.Equal(1, hl.ActionsToNextBand);
        Assert.Contains("1 action would move you to Moderate", hl.Sentence);
    }

    [Fact]
    public void Removing_the_counted_actions_really_crosses_the_band_boundary()
    {
        // General invariant on the demo data: removing the top-N highest-scoring findings
        // (N = ActionsToNextBand) drops the score into the next-better band.
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var hl = ExecHeadlineBuilder.Build(rows);

        if (hl.NextBand is null) return; // already at the best band - nothing to assert.

        var remaining = latest
            .OrderByDescending(r => r.RiskScoreTotal)
            .Skip(hl.ActionsToNextBand)
            .Sum(r => r.RiskScoreTotal);
        Assert.Equal(hl.NextBand, ExecDashboardBuilder.ScoreBand(Math.Round(remaining, 1)));
    }

    [Fact]
    public void Low_band_has_no_next_band_and_a_hold_message()
    {
        // A single tiny finding -> "Low" (the best band): no actions, encouraging message.
        var rows = new[] { Row(10, "x") };
        var hl = ExecHeadlineBuilder.Build(rows, scoreDelta: 0, previousTotal: 0);

        Assert.Equal("Low", hl.Band);
        Assert.Null(hl.NextBand);
        Assert.Equal(0, hl.ActionsToNextBand);
        Assert.Contains("keep monitoring", hl.Sentence, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Direction_reflects_the_prior_snapshot_delta()
    {
        var rows = new[] { Row(150, "a"), Row(150, "b") };
        Assert.Equal("improving", ExecHeadlineBuilder.Build(rows, scoreDelta: -20, previousTotal: 320).Direction);
        Assert.Equal("worsening", ExecHeadlineBuilder.Build(rows, scoreDelta: 20, previousTotal: 280).Direction);
        Assert.Equal("steady", ExecHeadlineBuilder.Build(rows, scoreDelta: 0, previousTotal: 300).Direction);
    }

    [Fact]
    public void Empty_snapshot_yields_a_clear_posture_message()
    {
        var hl = ExecHeadlineBuilder.Build(Array.Empty<RiskRow>());
        Assert.Equal(0, hl.Score);
        Assert.Equal("Low", hl.Band);
        Assert.Equal(0, hl.ActionsToNextBand);
        Assert.Contains("No open security findings", hl.Sentence);
    }
}
