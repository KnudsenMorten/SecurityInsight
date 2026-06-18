using Sia.Core.Analysis;
using Sia.Core.DataAccess;
using Sia.Core.Exec;
using Sia.Core.Model;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// Tests for the prioritised remediation plan ("next N actions ranked by risk-reduction"),
/// TESTS.md §9.8. The plan is a pure, grounded aggregation over the latest RA snapshot:
/// per-asset actions ordered by risk-removed-per-effort, with a cumulative projected score +
/// real band-crossing maths. The hard guarantees verified here:
///   - GROUNDING: every action's projected drop is the sum of that asset's finding scores;
///     the cumulative "score after" really equals start - the drops above it; the band
///     crossing is the actual band of the running total.
///   - HONESTY: effort/ROI are estimates (no costs/dates); no-data and no-driver cases never
///     crash or invent (default Medium; empty plan; single snapshot still produces a plan).
///   - PRIORITISATION: actions are ordered best-ROI-first; a low-effort big-drop beats a
///     high-effort same-drop.
/// </summary>
public sealed class RemediationPlanTests
{
    private static IReadOnlyList<RiskRow> Demo() => DemoData.Load(TestData.SeedPath());

    private static RiskRow Row(string id, string domain, double score, string sev, int tier,
        string prob = "", string cons = "", DateTimeOffset? t = null) => new()
    {
        SecurityDomain = domain,
        ConfigurationName = id,
        ConfigurationId = id,
        RiskScoreTotal = score,
        SecuritySeverity = sev,
        CriticalityTier = tier,
        CriticalityTierLevel = $"{sev} - tier {tier}",
        RiskFactorProbability = prob,
        RiskFactorConsequence = cons,
        CollectionTime = t ?? new DateTimeOffset(2026, 6, 17, 6, 0, 0, TimeSpan.Zero),
    };

    // --- Grounding ----------------------------------------------------------

    [Fact]
    public void Each_action_drop_is_the_sum_of_that_assets_finding_scores()
    {
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var plan = RemediationPlan.Build(rows, top: 100);

        foreach (var a in plan.Actions)
        {
            var expected = Math.Round(
                latest.Where(r => (string.IsNullOrWhiteSpace(r.ConfigurationId) ? r.ConfigurationName : r.ConfigurationId) == a.ConfigurationId)
                      .Sum(r => r.RiskScoreTotal), 1);
            Assert.Equal(expected, a.ProjectedScoreDrop);
        }
    }

    [Fact]
    public void Start_score_equals_the_latest_snapshot_headline()
    {
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var plan = RemediationPlan.Build(rows);
        Assert.Equal(Math.Round(latest.Sum(r => r.RiskScoreTotal), 1), plan.StartScore);
        Assert.Equal(ExecDashboardBuilder.ScoreBand(plan.StartScore), plan.StartBand);
    }

    [Fact]
    public void Cumulative_score_after_each_action_is_start_minus_drops_above_it()
    {
        var rows = Demo();
        var plan = RemediationPlan.Build(rows, top: 100);
        var running = plan.StartScore;
        foreach (var a in plan.Actions)
        {
            running = Math.Round(Math.Max(0, running - a.ProjectedScoreDrop), 1);
            Assert.Equal(running, a.CumulativeScoreAfter);
            Assert.Equal(ExecDashboardBuilder.ScoreBand(running), a.BandAfter);
        }
    }

    [Fact]
    public void Crosses_band_here_is_set_exactly_when_the_running_band_changes_at_that_step()
    {
        var rows = Demo();
        var plan = RemediationPlan.Build(rows, top: 100);
        var prevBand = plan.StartBand;
        foreach (var a in plan.Actions)
        {
            var changed = !string.Equals(prevBand, a.BandAfter, StringComparison.Ordinal);
            Assert.Equal(changed, a.CrossesBandHere);
            prevBand = a.BandAfter;
        }
    }

    [Fact]
    public void Shares_are_each_drop_over_the_start_score()
    {
        var rows = Demo();
        var plan = RemediationPlan.Build(rows, top: 100);
        foreach (var a in plan.Actions)
        {
            Assert.Equal(Math.Round(a.ProjectedScoreDrop / plan.StartScore * 100, 1), a.SharePercent);
        }
    }

    [Fact]
    public void Plain_text_carries_no_kql_or_table_names()
    {
        var plan = RemediationPlan.Build(Demo(), top: 100);
        Assert.All(plan.Actions, a =>
        {
            Assert.False(string.IsNullOrWhiteSpace(a.Recommendation));
            Assert.False(string.IsNullOrWhiteSpace(a.AreaPlain));
            foreach (var s in new[] { a.Recommendation, a.AreaPlain, a.Why })
            {
                Assert.DoesNotContain("_CL", s);
                Assert.DoesNotContain("RiskScoreTotal", s);
                Assert.DoesNotContain("| where", s);
            }
        });
    }

    // --- Prioritisation (ROI) ----------------------------------------------

    [Fact]
    public void Actions_are_ordered_best_roi_first()
    {
        var plan = RemediationPlan.Build(Demo(), top: 100);
        var roi = plan.Actions.Select(a => a.RoiScore).ToList();
        Assert.Equal(roi.OrderByDescending(x => x).ToList(), roi);
        // Ranks are 1..N in order.
        for (var i = 0; i < plan.Actions.Count; i++) Assert.Equal(i + 1, plan.Actions[i].Rank);
    }

    [Fact]
    public void Lower_effort_wins_when_the_drop_is_equal()
    {
        // Two assets with the SAME projected drop (50). One is a quick config fix (Low effort),
        // the other a tier-0 multi-step remediation (High effort). ROI must rank the Low one first.
        var rows = new List<RiskRow>
        {
            Row("cfg-fix", "azure", 50, "High", 1, prob: "Public network access enabled; no private endpoint"),
            Row("hard-fix", "endpoint", 50, "Critical", 0, prob: "Internet-exposed RDP and an exploitable critical CVE",
                cons: "Domain controller; compromise = full tier-0 takeover"),
        };
        var plan = RemediationPlan.Build(rows, top: 10);
        Assert.Equal("cfg-fix", plan.Actions[0].ConfigurationName);
        Assert.Equal("Low", plan.Actions[0].Effort);
        Assert.Equal("High", plan.Actions[1].Effort);
        Assert.True(plan.Actions[0].RoiScore > plan.Actions[1].RoiScore);
    }

    [Fact]
    public void Findings_on_one_asset_collapse_into_a_single_action()
    {
        // Two findings on the same asset id -> one action, drop = the sum.
        var rows = new List<RiskRow>
        {
            Row("multi", "endpoint", 30, "High", 1, prob: "Unpatched high-CVSS vulnerability"),
            Row("multi", "endpoint", 20, "Medium", 1, prob: "Unsupported OS (EOL) carrying known CVEs"),
            Row("solo", "identity", 10, "Low", 2, prob: "no owner"),
        };
        var plan = RemediationPlan.Build(rows, top: 10);
        Assert.Equal(2, plan.TotalAssets);
        var multi = plan.Actions.Single(a => a.ConfigurationName == "multi");
        Assert.Equal(2, multi.FindingCount);
        Assert.Equal(50, multi.ProjectedScoreDrop);
    }

    // --- Band crossing ------------------------------------------------------

    [Fact]
    public void Band_crossing_count_is_the_real_number_of_actions_to_reach_the_next_band()
    {
        // Six equal-effort (Low) config fixes, distinct drops, total 258 (Elevated, >=200).
        // All Low effort => ROI order == drop order. Boundary to Moderate is <200 (gap 58).
        // The single biggest (48) lands at 210 = still Elevated; the top two (48+46=94) land
        // at 164 = Moderate, so the cross must take exactly 2 actions.
        var rows = new List<RiskRow>
        {
            Row("a", "azure", 48, "High", 1, prob: "Public network access enabled"),
            Row("b", "azure", 46, "High", 1, prob: "Public network access enabled"),
            Row("c", "azure", 44, "High", 1, prob: "Public network access enabled"),
            Row("d", "azure", 42, "High", 1, prob: "Public network access enabled"),
            Row("e", "azure", 40, "High", 1, prob: "Public network access enabled"),
            Row("f", "azure", 38, "High", 1, prob: "Public network access enabled"),
        };
        var plan = RemediationPlan.Build(rows, top: 10);
        Assert.Equal(258, plan.StartScore);
        Assert.Equal("Elevated", plan.StartBand);
        Assert.All(plan.Actions, a => Assert.Equal("Low", a.Effort)); // config fixes
        Assert.Equal("Moderate", plan.NextBetterBand);
        Assert.Equal(2, plan.BandCrossActionCount);
        // The band-crossing must be reflected on the action where it happens (the 2nd).
        Assert.False(plan.Actions[0].CrossesBandHere);
        Assert.True(plan.Actions[1].CrossesBandHere);
        Assert.Equal("Moderate", plan.Actions[1].BandAfter);
    }

    [Fact]
    public void Already_low_band_has_no_next_better_band()
    {
        var rows = new List<RiskRow> { Row("a", "identity", 20, "Low", 2, prob: "no owner") };
        var plan = RemediationPlan.Build(rows, top: 10);
        Assert.Equal("Low", plan.StartBand);
        Assert.Null(plan.NextBetterBand);
        Assert.Null(plan.BandCrossActionCount);
    }

    [Fact]
    public void Band_crossing_considers_every_asset_not_just_the_shown_top_n()
    {
        // Same six-asset 258 -> Moderate-at-2 case, but we only SHOW top=1. The crossing
        // count must still report 2 (the maths considers every asset, not just the shown one).
        var rows = new List<RiskRow>
        {
            Row("a", "azure", 48, "High", 1, prob: "Public network access enabled"),
            Row("b", "azure", 46, "High", 1, prob: "Public network access enabled"),
            Row("c", "azure", 44, "High", 1, prob: "Public network access enabled"),
            Row("d", "azure", 42, "High", 1, prob: "Public network access enabled"),
            Row("e", "azure", 40, "High", 1, prob: "Public network access enabled"),
            Row("f", "azure", 38, "High", 1, prob: "Public network access enabled"),
        };
        var plan = RemediationPlan.Build(rows, top: 1);
        Assert.Single(plan.Actions);
        Assert.Equal(2, plan.BandCrossActionCount);
        Assert.Equal(6, plan.TotalAssets);
    }

    // --- Honesty on missing / sparse data -----------------------------------

    [Fact]
    public void No_rows_yields_an_empty_plan_without_crashing()
    {
        var plan = RemediationPlan.Build(Array.Empty<RiskRow>());
        Assert.Empty(plan.Actions);
        Assert.Equal(0, plan.StartScore);
        Assert.Equal("Low", plan.StartBand);
        Assert.Equal(0, plan.TotalAssets);
        Assert.Null(plan.NextBetterBand);
        Assert.Equal(plan.StartScore, plan.ProjectedScoreAfterPlan);
    }

    [Fact]
    public void Assets_with_no_driver_text_default_to_a_medium_effort_estimate()
    {
        // No probability/consequence drivers and a non-critical tier -> we don't pretend to
        // know the effort; default is Medium (honest).
        var rows = new List<RiskRow> { Row("blank", "endpoint", 30, "Medium", 2) };
        var plan = RemediationPlan.Build(rows, top: 10);
        Assert.Equal("Medium", plan.Actions[0].Effort);
        Assert.Equal("Remediate the finding(s) on this asset to remove its risk contribution.", plan.Actions[0].Recommendation);
    }

    [Fact]
    public void Single_snapshot_still_produces_a_plan()
    {
        // Only the latest snapshot exists (no history) - the plan needs only the latest snapshot.
        var one = SnapshotDiff.LatestSnapshot(Demo());
        var plan = RemediationPlan.Build(one, top: 5);
        Assert.NotEmpty(plan.Actions);
    }

    [Fact]
    public void Zero_score_assets_are_not_offered_as_actions()
    {
        var rows = new List<RiskRow>
        {
            Row("real", "endpoint", 30, "Medium", 2, prob: "Unsupported OS EOL"),
            Row("clean", "endpoint", 0, "Low", 3),
        };
        var plan = RemediationPlan.Build(rows, top: 10);
        Assert.Single(plan.Actions);
        Assert.Equal("real", plan.Actions[0].ConfigurationName);
    }

    // --- Dashboard wiring ---------------------------------------------------

    [Fact]
    public void Exec_dashboard_carries_the_remediation_plan()
    {
        var dash = ExecDashboardBuilder.Build(Demo());
        Assert.NotNull(dash.Remediation);
        Assert.NotEmpty(dash.Remediation.Actions);
        Assert.True(dash.Remediation.Actions.Count <= 5); // top-5 view by default
        Assert.Equal(dash.HeadlineScore, dash.Remediation.StartScore);
    }
}
