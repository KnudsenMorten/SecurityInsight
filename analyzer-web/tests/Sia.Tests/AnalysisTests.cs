using Sia.Core.Analysis;
using Sia.Core.DataAccess;
using Sia.Core.Exec;
using Sia.Core.Model;
using Xunit;

namespace Sia.Tests;

/// <summary>Diff + timeline + exec-rollup math, ported from the PS POC's
/// Get-SiSnapshotDiff / Get-SiScoreTimeline tests (TESTS.md §9.1).</summary>
public sealed class AnalysisTests
{
    private static IReadOnlyList<RiskRow> Demo() => DemoData.Load(TestData.SeedPath());

    [Fact]
    public void Diff_detects_new_closed_open_and_score_delta_between_demo_snapshots()
    {
        var diff = SnapshotDiff.Diff(Demo());
        // The demo seed adds admin-orphan-01 + DEMO-APP-12 in the latest snapshot.
        Assert.True(diff.NewCount >= 2);
        // demo-storage-prod is present in both but its score drops 63 -> 28 (improved).
        Assert.True(diff.ImprovedCount >= 1);
        // Score delta equals current total minus previous total.
        Assert.Equal(Math.Round(diff.CurrentTotal - diff.PreviousTotal, 2), diff.ScoreDelta);
        Assert.NotNull(diff.CurrentTime);
        Assert.NotNull(diff.PreviousTime);
    }

    [Fact]
    public void Diff_survives_a_single_snapshot()
    {
        var one = SnapshotDiff.LatestSnapshot(Demo());
        var diff = SnapshotDiff.Diff(one);
        Assert.Equal(0, diff.PreviousTotal);
        Assert.Equal(one.Count, diff.NewCount);
    }

    [Fact]
    public void Timeline_has_one_point_per_collection_time_with_percent_delta()
    {
        var t = SnapshotDiff.Timeline(Demo());
        Assert.Equal(2, t.Count);              // two demo snapshots
        Assert.Null(t[0].PercentFromPrev);     // first point has no prior
        Assert.NotNull(t[1].PercentFromPrev);  // second point carries a delta
        Assert.True(t[1].PerTier.Count > 0);
    }

    [Fact]
    public void Exec_dashboard_rolls_up_full_latest_snapshot_no_invented_numbers()
    {
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var dash = ExecDashboardBuilder.Build(rows);

        // Headline score is exactly the sum of the latest snapshot (grounded, not invented).
        Assert.Equal(Math.Round(latest.Sum(r => r.RiskScoreTotal), 1), dash.HeadlineScore);
        Assert.Equal(latest.Count, dash.TotalFindings);
        Assert.NotEmpty(dash.BySeverity);
        Assert.NotEmpty(dash.ByDomain);
        Assert.NotEmpty(dash.QuickWins);
    }

    [Fact]
    public void Trend_forecast_point_is_clearly_labelled()
    {
        var dash = ExecDashboardBuilder.Build(Demo());
        Assert.Contains(dash.Trend, p => p.IsForecast);          // a projection exists
        Assert.Single(dash.Trend, p => p.IsForecast);            // exactly one projected point
        Assert.False(dash.Trend[0].IsForecast);                  // measured points are not flagged
    }

    [Fact]
    public void Score_band_maps_monotonically()
    {
        Assert.Equal("Low", ExecDashboardBuilder.ScoreBand(10));
        Assert.Equal("Moderate", ExecDashboardBuilder.ScoreBand(100));
        Assert.Equal("Elevated", ExecDashboardBuilder.ScoreBand(250));
        Assert.Equal("Severe", ExecDashboardBuilder.ScoreBand(500));
    }
}
