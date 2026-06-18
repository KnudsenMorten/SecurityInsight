using Sia.Core.Analysis;
using Sia.Core.DataAccess;
using Sia.Core.Exec;
using Sia.Core.Model;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// Tests for the two exec-grade enhancements (TESTS.md §9.7):
///   1. Framework lens (NIST CSF / CIS / ISO 27001 control-area rollup)
///   2. Aging / time-open of the top risks
/// Both are pure, grounded aggregations over the RA rows + snapshot history - no
/// invented numbers, no AI. The framework area scores partition the headline score;
/// the aging dates come straight from the snapshot history.
/// </summary>
public sealed class ExecEnhancementsTests
{
    private static IReadOnlyList<RiskRow> Demo() => DemoData.Load(TestData.SeedPath());

    // --- Framework lens ---

    [Fact]
    public void Framework_lens_builds_the_three_board_frameworks()
    {
        var latest = SnapshotDiff.LatestSnapshot(Demo());
        var fws = FrameworkLens.Build(latest);
        Assert.Equal(3, fws.Count);
        Assert.Contains(fws, f => f.Framework == "NIST CSF");
        Assert.Contains(fws, f => f.Framework == "CIS Controls");
        Assert.Contains(fws, f => f.Framework == "ISO 27001");
        Assert.All(fws, f => Assert.NotEmpty(f.Areas));
    }

    [Fact]
    public void Framework_area_scores_partition_the_headline_score_no_invented_numbers()
    {
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var headline = Math.Round(latest.Sum(r => r.RiskScoreTotal), 1);

        foreach (var fw in FrameworkLens.Build(latest))
        {
            // Every finding maps to exactly one area, so the areas sum back to the headline
            // (each finding counted once) - the lens never invents or double-counts risk.
            var areaTotal = Math.Round(fw.Areas.Sum(a => a.Score), 1);
            Assert.Equal(headline, areaTotal, 1);
            var findingTotal = fw.Areas.Sum(a => a.Findings);
            Assert.Equal(latest.Count, findingTotal);
        }
    }

    [Fact]
    public void Framework_areas_are_sorted_highest_risk_first_with_plain_language()
    {
        var latest = SnapshotDiff.LatestSnapshot(Demo());
        foreach (var fw in FrameworkLens.Build(latest))
        {
            var scores = fw.Areas.Select(a => a.Score).ToList();
            var sorted = scores.OrderByDescending(s => s).ToList();
            Assert.Equal(sorted, scores);
            // Plain-language captions, no KQL/table names.
            Assert.All(fw.Areas, a =>
            {
                Assert.False(string.IsNullOrWhiteSpace(a.Plain));
                Assert.DoesNotContain("RiskScoreTotal", a.Plain);
                Assert.DoesNotContain("_CL", a.Plain);
            });
        }
    }

    [Fact]
    public void Framework_lens_survives_an_empty_snapshot()
    {
        var fws = FrameworkLens.Build(Array.Empty<RiskRow>());
        Assert.Equal(3, fws.Count);
        Assert.All(fws, f => Assert.Empty(f.Areas));
    }

    // --- Aging / time-open ---

    [Fact]
    public void Aging_reports_carried_over_and_new_risks_from_snapshot_history()
    {
        var ag = AgingAnalysis.Build(Demo());
        Assert.NotEmpty(ag.Items);
        // admin-orphan-01 is new in the latest snapshot; DEMO-DC-01 carries over from the prior one.
        Assert.True(ag.NewThisSnapshotCount >= 1);
        Assert.True(ag.CarriedOverCount >= 1);
        Assert.Equal(ag.Items.Count, ag.CarriedOverCount + ag.NewThisSnapshotCount);
    }

    [Fact]
    public void Aging_open_since_comes_from_the_snapshot_history_not_invented()
    {
        var rows = Demo();
        var times = SnapshotDiff.CollectionTimes(rows);
        var earliest = times[0];
        var latest = times[^1];

        var ag = AgingAnalysis.Build(rows);
        foreach (var i in ag.Items)
        {
            // Every OpenSince is an ACTUAL snapshot time in the data (never fabricated).
            Assert.Contains(i.OpenSince, times);
            Assert.True(i.OpenSince <= latest);
            Assert.True(i.OpenSince >= earliest);
            // Days-open is consistent with the OpenSince..latest span.
            Assert.Equal((int)Math.Round((latest - i.OpenSince).TotalDays), i.DaysOpen);
            // New items have exactly one snapshot of history; carried-over have more.
            if (i.IsNew) Assert.Equal(1, i.SnapshotsOpen); else Assert.True(i.SnapshotsOpen >= 2);
        }
    }

    [Fact]
    public void Aging_carried_over_risk_is_open_since_the_earliest_continuous_snapshot()
    {
        var rows = Demo();
        var times = SnapshotDiff.CollectionTimes(rows);
        var ag = AgingAnalysis.Build(rows);

        // DEMO-DC-01 (ep-0001) is present in BOTH demo snapshots, so it is open since the first.
        var dc = ag.Items.FirstOrDefault(i => i.ConfigurationName == "DEMO-DC-01");
        Assert.NotNull(dc);
        Assert.False(dc!.IsNew);
        Assert.Equal(times[0], dc.OpenSince);
        Assert.True(dc.DaysOpen > 0);
    }

    [Fact]
    public void Aging_survives_a_single_snapshot()
    {
        var one = SnapshotDiff.LatestSnapshot(Demo());
        var ag = AgingAnalysis.Build(one);
        Assert.NotEmpty(ag.Items);
        // With only one snapshot everything is "new" and open zero days.
        Assert.All(ag.Items, i => Assert.True(i.IsNew));
        Assert.Equal(0, ag.LongestDaysOpen);
        Assert.Equal(0, ag.CarriedOverCount);
    }

    [Fact]
    public void Aging_survives_no_rows()
    {
        var ag = AgingAnalysis.Build(Array.Empty<RiskRow>());
        Assert.Empty(ag.Items);
        Assert.Equal(0, ag.AverageDaysOpen);
        Assert.Equal(0, ag.LongestDaysOpen);
    }

    // --- Dashboard wiring ---

    [Fact]
    public void Exec_dashboard_carries_frameworks_and_aging()
    {
        var dash = ExecDashboardBuilder.Build(Demo());
        Assert.Equal(3, dash.Frameworks.Count);
        Assert.NotEmpty(dash.Aging.Items);
    }
}
