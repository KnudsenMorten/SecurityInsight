using Sia.Core.Analysis;
using Sia.Core.DataAccess;
using Sia.Core.Exec;
using Sia.Core.Model;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// Tests for the two newest exec-grade enhancements (TESTS.md §9.7):
///   1. Period-over-period "since last board meeting" (configurable look-back baseline)
///   2. Risk by domain / business unit concentration breakdown
/// Both are pure, grounded aggregations over the RA rows + snapshot history - no AI, no
/// invented numbers. The period baseline is always a REAL snapshot time; the area shares
/// partition the headline score.
/// </summary>
public sealed class PeriodAndConcentrationTests
{
    private static IReadOnlyList<RiskRow> Demo() => DemoData.Load(TestData.SeedPath());

    // --- helpers to build synthetic multi-snapshot histories ---

    private static RiskRow Row(string id, string domain, double score, DateTimeOffset t) => new()
    {
        SecurityDomain = domain,
        ConfigurationName = id,
        ConfigurationId = id,
        RiskScoreTotal = score,
        SecuritySeverity = "High",
        CriticalityTier = 1,
        CriticalityTierLevel = "High - tier 1",
        CollectionTime = t,
    };

    // --- Period-over-period ---

    [Fact]
    public void Period_presets_include_the_board_cadences()
    {
        var keys = ReportingPeriod.Presets.Select(p => p.Key).ToList();
        Assert.Contains("previous", keys);
        Assert.Contains("month", keys);
        Assert.Contains("quarter", keys);
        Assert.Contains("half", keys);
        Assert.Contains("year", keys);
    }

    [Fact]
    public void Period_resolve_defaults_to_quarter_for_null_or_unknown()
    {
        Assert.Equal("quarter", ReportingPeriod.Resolve(null).Key);
        Assert.Equal("quarter", ReportingPeriod.Resolve("nonsense").Key);
        Assert.Equal("month", ReportingPeriod.Resolve("month").Key);
        Assert.Equal("month", ReportingPeriod.Resolve("MONTH").Key);  // case-insensitive
    }

    [Fact]
    public void Period_baseline_is_a_real_snapshot_time_not_invented()
    {
        var rows = Demo();
        var times = SnapshotDiff.CollectionTimes(rows);
        foreach (var preset in ReportingPeriod.Presets)
        {
            var pc = PeriodComparisonBuilder.Build(rows, preset);
            if (pc.HasBaseline)
            {
                Assert.Contains(pc.BaselineTime!.Value, times);
                Assert.NotEqual(pc.BaselineTime, pc.CurrentTime);  // never self-compares
            }
        }
    }

    [Fact]
    public void Period_previous_matches_the_headline_snapshot_diff()
    {
        var rows = Demo();
        var headline = SnapshotDiff.Diff(rows);
        var pc = PeriodComparisonBuilder.Build(rows, ReportingPeriod.Resolve("previous"));
        // "previous" period = the immediately-prior snapshot, so the deltas match the headline.
        Assert.Equal(headline.ScoreDelta, pc.Diff.ScoreDelta);
        Assert.Equal(headline.NewCount, pc.Diff.NewCount);
        Assert.Equal(headline.ClosedCount, pc.Diff.ClosedCount);
        Assert.True(pc.BaselineExact);
    }

    [Fact]
    public void Period_picks_the_latest_snapshot_at_or_before_the_lookback_target()
    {
        // Four monthly snapshots; a 90-day look-back from the latest should land on the
        // snapshot ~3 months back (the latest one at or before now-90d).
        var now = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        var rows = new List<RiskRow>();
        var snaps = new[] { now.AddDays(-120), now.AddDays(-90), now.AddDays(-30), now };
        foreach (var t in snaps) rows.Add(Row("a", "endpoint", 50, t));

        var pc = PeriodComparisonBuilder.Build(rows, ReportingPeriod.Resolve("quarter"));
        Assert.True(pc.HasBaseline);
        Assert.True(pc.BaselineExact);
        // now-90d exists exactly, so it is the baseline.
        Assert.Equal(now.AddDays(-90), pc.BaselineTime);
        Assert.Equal(90, pc.DaysSpanned);
    }

    [Fact]
    public void Period_falls_back_to_earliest_when_history_is_too_short_and_flags_inexact()
    {
        // Only two snapshots a week apart; a 365-day look-back can't be satisfied.
        var now = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
        var rows = new List<RiskRow> { Row("a", "endpoint", 50, now.AddDays(-7)), Row("a", "endpoint", 40, now) };
        var pc = PeriodComparisonBuilder.Build(rows, ReportingPeriod.Resolve("year"));
        Assert.True(pc.HasBaseline);
        Assert.False(pc.BaselineExact);                       // honest "closest we have"
        Assert.Equal(now.AddDays(-7), pc.BaselineTime);       // earliest available
    }

    [Fact]
    public void Period_with_a_single_snapshot_has_no_baseline()
    {
        var one = SnapshotDiff.LatestSnapshot(Demo());
        var pc = PeriodComparisonBuilder.Build(one, ReportingPeriod.Resolve("quarter"));
        Assert.False(pc.HasBaseline);
        Assert.Null(pc.BaselineTime);
    }

    [Fact]
    public void Period_survives_no_rows()
    {
        var pc = PeriodComparisonBuilder.Build(Array.Empty<RiskRow>(), ReportingPeriod.Resolve("quarter"));
        Assert.False(pc.HasBaseline);
        Assert.Equal(0, pc.Diff.NewCount);
    }

    // --- Risk concentration ---

    [Fact]
    public void Concentration_shares_partition_the_headline_total()
    {
        var latest = SnapshotDiff.LatestSnapshot(Demo());
        var view = RiskConcentration.Build(latest);
        var headline = Math.Round(latest.Sum(r => r.RiskScoreTotal), 1);

        // Area scores sum back to the headline (every finding counted exactly once).
        Assert.Equal(headline, Math.Round(view.Areas.Sum(a => a.Score), 1), 1);
        // Finding counts sum back to the total finding count.
        Assert.Equal(latest.Count, view.Areas.Sum(a => a.Findings));
        // Shares add up to ~100.
        Assert.Equal(100, Math.Round(view.Areas.Sum(a => a.SharePercent), 0), 0);
        Assert.Equal(view.TotalScore, headline);
    }

    [Fact]
    public void Concentration_is_sorted_highest_first_with_plain_language()
    {
        var latest = SnapshotDiff.LatestSnapshot(Demo());
        var view = RiskConcentration.Build(latest);
        var scores = view.Areas.Select(a => a.Score).ToList();
        Assert.Equal(scores.OrderByDescending(s => s).ToList(), scores);
        Assert.Equal(view.Areas[0].Area, view.MostConcentratedArea);
        Assert.All(view.Areas, a =>
        {
            Assert.False(string.IsNullOrWhiteSpace(a.Plain));
            Assert.False(string.IsNullOrWhiteSpace(a.TopContributor));
            Assert.DoesNotContain("_CL", a.Plain);
            Assert.DoesNotContain("RiskScoreTotal", a.Plain);
        });
    }

    [Fact]
    public void Concentration_top_contributor_is_the_highest_scoring_asset_in_the_area()
    {
        var latest = SnapshotDiff.LatestSnapshot(Demo());
        var view = RiskConcentration.Build(latest);
        foreach (var a in view.Areas)
        {
            var expected = latest
                .Where(r => string.Equals(
                    string.IsNullOrWhiteSpace(r.SecurityDomain) ? "other" : r.SecurityDomain.Trim().ToLowerInvariant(),
                    a.Area, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(r => r.RiskScoreTotal)
                .First().ConfigurationName;
            Assert.Equal(expected, a.TopContributor);
        }
    }

    [Fact]
    public void Concentration_direction_is_grounded_in_the_baseline_snapshot()
    {
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var times = SnapshotDiff.CollectionTimes(rows);
        var baseline = rows.Where(r => r.CollectionTime == times[0]).ToList();

        var view = RiskConcentration.Build(latest, baseline);
        // The azure area dropped (demo-storage-prod 63 -> 28) so it must read "improving".
        var cloud = view.Areas.FirstOrDefault(a => a.Area == "azure");
        Assert.NotNull(cloud);
        Assert.Equal("improving", cloud!.Direction);
    }

    [Fact]
    public void Concentration_without_a_baseline_reports_steady()
    {
        var latest = SnapshotDiff.LatestSnapshot(Demo());
        var view = RiskConcentration.Build(latest, baseline: null);
        Assert.All(view.Areas, a => Assert.Equal("steady", a.Direction));
        Assert.All(view.Areas, a => Assert.Null(a.ChangePercent));
    }

    [Fact]
    public void Concentration_survives_no_rows()
    {
        var view = RiskConcentration.Build(Array.Empty<RiskRow>());
        Assert.Empty(view.Areas);
        Assert.Null(view.MostConcentratedArea);
        Assert.Equal(0, view.TotalScore);
    }

    // --- Dashboard wiring ---

    [Fact]
    public void Exec_dashboard_carries_period_and_concentration()
    {
        var dash = ExecDashboardBuilder.Build(Demo());
        Assert.NotNull(dash.Period);
        Assert.True(dash.Period.HasBaseline);
        Assert.NotEmpty(dash.Concentration.Areas);
        // Defaulted to the quarter when no key is passed.
        Assert.Equal("quarter", dash.Period.Period.Key);
    }

    [Fact]
    public void Exec_dashboard_honours_the_requested_period_key()
    {
        var dash = ExecDashboardBuilder.Build(Demo(), "previous");
        Assert.Equal("previous", dash.Period.Period.Key);
    }
}
