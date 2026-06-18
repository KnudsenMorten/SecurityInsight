using Sia.Core.Analysis;
using Sia.Core.DataAccess;
using Sia.Core.Exec;
using Sia.Core.Model;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// Tests for the two exec-grade enhancements added in this iteration (TESTS.md §9.7):
///   1. "So what" business-impact framing (BusinessImpact) - each top risk re-stated as a
///      plain-language business consequence (data exposure / downtime / compliance /
///      reputation), grounded in the row's own domain/tier/severity/driver text.
///   2. Clean-by-default, drill-down on demand (Drilldown) - the grounded evidence rows that
///      SUM to a headline number (overall / domain / severity / tier).
/// Both are pure, grounded aggregations - no network, no AI, no invented numbers.
/// </summary>
public sealed class BusinessImpactAndDrilldownTests
{
    private static IReadOnlyList<RiskRow> Demo() => DemoData.Load(TestData.SeedPath());

    // --- Business impact ("so what") ---

    [Fact]
    public void Business_impact_frames_the_top_risks_in_business_terms()
    {
        var latest = SnapshotDiff.LatestSnapshot(Demo());
        var bi = BusinessImpact.Build(latest);
        Assert.NotEmpty(bi.Items);
        Assert.True(bi.Items.Count <= 5);
        Assert.All(bi.Items, i =>
        {
            // A recognised board-level consequence category.
            Assert.Contains(i.Category, new[] { "Data exposure", "Downtime", "Compliance", "Reputation" });
            // A plain-language consequence sentence + the grounded driver it came from.
            Assert.False(string.IsNullOrWhiteSpace(i.Consequence));
            Assert.False(string.IsNullOrWhiteSpace(i.Why));
            // No KQL/table/column jargon on the exec consequence text.
            Assert.DoesNotContain("RiskScoreTotal", i.Consequence);
            Assert.DoesNotContain("_CL", i.Consequence);
        });
    }

    [Fact]
    public void Business_impact_items_track_the_highest_scoring_rows()
    {
        var latest = SnapshotDiff.LatestSnapshot(Demo());
        var bi = BusinessImpact.Build(latest);
        var expected = latest.OrderByDescending(r => r.RiskScoreTotal).Take(bi.Items.Count)
            .Select(r => r.ConfigurationName).ToList();
        Assert.Equal(expected, bi.Items.Select(i => i.ConfigurationName).ToList());
    }

    [Fact]
    public void Business_impact_category_counts_cover_every_latest_finding()
    {
        var latest = SnapshotDiff.LatestSnapshot(Demo());
        var bi = BusinessImpact.Build(latest);
        // The category rollup is the FULL latest set (no silent cap), so the counts sum
        // back to the number of findings - every row is categorised exactly once.
        Assert.Equal(latest.Count, bi.ByCategory.Sum(s => (int)s.Value));
        // Sorted highest-count first.
        var sorted = bi.ByCategory.Select(s => s.Value).OrderByDescending(v => v).ToList();
        Assert.Equal(sorted, bi.ByCategory.Select(s => s.Value).ToList());
    }

    [Fact]
    public void Business_impact_categorize_is_grounded_in_the_signals()
    {
        // Identity / privileged -> data exposure.
        var idRow = new RiskRow { SecurityDomain = "identity", CriticalityTier = 0, SecuritySeverity = "Critical", RiskFactorConsequence = "privileged account exposure" };
        Assert.Equal("Data exposure", BusinessImpact.Categorize(idRow).Category);

        // Unsupported / EOL -> compliance.
        var eolRow = new RiskRow { SecurityDomain = "endpoint", CriticalityTier = 1, SecuritySeverity = "High", RiskFactorProbability = "unsupported operating system, end of life" };
        Assert.Equal("Compliance", BusinessImpact.Categorize(eolRow).Category);

        // Endpoint availability -> downtime.
        var epRow = new RiskRow { SecurityDomain = "endpoint", CriticalityTier = 2, SecuritySeverity = "Medium", RiskFactorConsequence = "service availability at risk" };
        Assert.Equal("Downtime", BusinessImpact.Categorize(epRow).Category);
    }

    [Fact]
    public void Business_impact_survives_an_empty_snapshot()
    {
        var bi = BusinessImpact.Build(Array.Empty<RiskRow>());
        Assert.Empty(bi.Items);
        Assert.Empty(bi.ByCategory);
    }

    // --- Drill-down on demand ---

    [Fact]
    public void Drilldown_overall_evidence_sums_to_the_headline_score()
    {
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var headline = Math.Round(latest.Sum(r => r.RiskScoreTotal), 1);

        var dd = Drilldown.Build(rows, Drilldown.DimOverall, null);
        Assert.Equal(headline, dd.Total, 1);
        Assert.Equal(latest.Count, dd.ContributorCount);
        Assert.NotEmpty(dd.Items);
        // The shown rows are a real subset and the shown score never exceeds the total.
        Assert.True(dd.ShownScore <= dd.Total + 0.05);
    }

    [Fact]
    public void Drilldown_items_are_real_rows_sorted_highest_first_with_shares()
    {
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var names = latest.Select(r => r.ConfigurationName).ToHashSet();

        var dd = Drilldown.Build(rows, Drilldown.DimOverall, null);
        var scores = dd.Items.Select(i => i.RiskScoreTotal).ToList();
        Assert.Equal(scores.OrderByDescending(s => s).ToList(), scores);
        Assert.All(dd.Items, i =>
        {
            Assert.Contains(i.ConfigurationName, names); // grounded - an actual row
            Assert.InRange(i.SharePercent, 0, 100);
        });
    }

    [Fact]
    public void Drilldown_by_domain_restricts_to_that_area()
    {
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var domain = latest.Select(r => r.SecurityDomain).First(d => !string.IsNullOrEmpty(d));
        var expected = Math.Round(latest.Where(r => string.Equals(r.SecurityDomain, domain, StringComparison.OrdinalIgnoreCase)).Sum(r => r.RiskScoreTotal), 1);

        var dd = Drilldown.Build(rows, Drilldown.DimDomain, domain);
        Assert.Equal(Drilldown.DimDomain, dd.Dimension);
        Assert.Equal(expected, dd.Total, 1);
        Assert.All(dd.Items, i => Assert.Equal(domain, i.SecurityDomain, ignoreCase: true));
    }

    [Fact]
    public void Drilldown_by_severity_restricts_to_that_band()
    {
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var sev = latest.Select(r => r.SecuritySeverity).First(s => !string.IsNullOrEmpty(s));

        var dd = Drilldown.Build(rows, Drilldown.DimSeverity, sev);
        Assert.Equal(Drilldown.DimSeverity, dd.Dimension);
        Assert.All(dd.Items, i => Assert.Equal(sev, i.SecuritySeverity, ignoreCase: true));
    }

    [Fact]
    public void Drilldown_unknown_dimension_falls_back_to_overall()
    {
        var rows = Demo();
        var dd = Drilldown.Build(rows, "bogus", "x");
        Assert.Equal(Drilldown.DimOverall, dd.Dimension);
    }

    [Fact]
    public void Drilldown_survives_no_rows()
    {
        var dd = Drilldown.Build(Array.Empty<RiskRow>(), Drilldown.DimOverall, null);
        Assert.Empty(dd.Items);
        Assert.Equal(0, dd.Total);
        Assert.Equal(0, dd.ContributorCount);
    }

    // --- Dashboard wiring ---

    [Fact]
    public void Exec_dashboard_carries_business_impact_and_overall_evidence()
    {
        var dash = ExecDashboardBuilder.Build(Demo());
        Assert.NotEmpty(dash.BusinessImpact.Items);
        Assert.NotEmpty(dash.OverallEvidence.Items);
        // The drilled overall total equals the headline score (no black box).
        Assert.Equal(dash.HeadlineScore, dash.OverallEvidence.Total, 1);
    }
}
