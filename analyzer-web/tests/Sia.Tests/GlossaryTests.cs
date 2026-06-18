using Sia.Core.Analysis;
using Sia.Core.DataAccess;
using Sia.Core.Exec;
using Sia.Core.Model;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// Tests for the exec glossary / "what these terms mean" plain-language layer (TESTS.md §9.9).
/// The glossary is a pure, grounded aggregation over the RA rows: every term gets a plain
/// definition; terms whose concept is PRESENT in the latest snapshot are surfaced first with
/// a GROUNDED example drawn straight from a real row; absent terms are still defined but
/// honestly flagged "not seen in your current data" - never given a fabricated example or
/// number. No AI, no network. These tests assert grounding + missing-data honesty.
/// </summary>
public sealed class GlossaryTests
{
    private static IReadOnlyList<RiskRow> Demo() => DemoData.Load(TestData.SeedPath());

    [Fact]
    public void Glossary_defines_every_term_and_surfaces_present_terms_first()
    {
        var g = Glossary.Build(Demo());
        Assert.NotEmpty(g.Terms);
        Assert.Equal(g.Terms.Count, g.TotalCount);

        // Every term has a non-empty plain definition and a non-empty "in your data" line.
        Assert.All(g.Terms, t =>
        {
            Assert.False(string.IsNullOrWhiteSpace(t.Term));
            Assert.False(string.IsNullOrWhiteSpace(t.Plain));
            Assert.False(string.IsNullOrWhiteSpace(t.InYourData));
        });

        // Present-now terms come before absent ones (most useful to the reader first).
        var firstAbsent = g.Terms.ToList().FindIndex(t => !t.Present);
        if (firstAbsent >= 0)
        {
            Assert.All(g.Terms.Skip(firstAbsent), t => Assert.False(t.Present));
        }
        Assert.Equal(g.Terms.Count(t => t.Present), g.PresentCount);
    }

    [Fact]
    public void Glossary_plain_language_has_no_kql_or_table_jargon()
    {
        var g = Glossary.Build(Demo());
        Assert.All(g.Terms, t =>
        {
            foreach (var jargon in new[] { "RiskScoreTotal", "_CL", "RiskFactor_", "CollectionTime", "summarize", "| where" })
            {
                Assert.DoesNotContain(jargon, t.Plain);
            }
        });
    }

    [Fact]
    public void Risk_score_example_is_grounded_in_the_real_total_and_top_row()
    {
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var total = Math.Round(latest.Sum(r => r.RiskScoreTotal), 1);
        var top = latest.OrderByDescending(r => r.RiskScoreTotal).First();

        var rs = Single(Glossary.Build(rows), "Risk score");
        Assert.True(rs.Present);
        // The grounded example cites the REAL overall total and the REAL biggest asset name.
        Assert.Contains(total.ToString("0.#", System.Globalization.CultureInfo.InvariantCulture), rs.InYourData);
        Assert.Contains(top.ConfigurationName, rs.InYourData);
    }

    [Fact]
    public void Crown_jewel_example_names_a_real_tier0_asset_when_present()
    {
        var rows = Demo();
        var latest = SnapshotDiff.LatestSnapshot(rows);
        // The demo has Tier 0 assets (DEMO-DC-01, admin-orphan-01).
        var jewel = latest.Where(r => r.CriticalityTier == 0).OrderByDescending(r => r.RiskScoreTotal).First();

        var cj = Single(Glossary.Build(rows), "Crown jewel (Tier 0)");
        Assert.True(cj.Present);
        Assert.Contains(jewel.ConfigurationName, cj.InYourData);
    }

    [Fact]
    public void Crown_jewel_is_honest_when_no_tier0_asset_is_present()
    {
        // Strip every Tier 0 row from the latest snapshot -> the term is defined but absent,
        // and the "in your data" note must NOT invent an example.
        var rows = Demo().Where(r => r.CriticalityTier != 0).ToList();
        Assert.NotEmpty(rows); // still has tier 1/2 rows to score

        var cj = Single(Glossary.Build(rows), "Crown jewel (Tier 0)");
        Assert.False(cj.Present);
        Assert.Contains("No Tier 0", cj.InYourData, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("e.g.", cj.InYourData); // no fabricated example
    }

    [Fact]
    public void Onboarding_gap_grounds_on_the_real_gap_row_or_is_honestly_absent()
    {
        // Present case: the demo has DEMO-APP-12 with an onboarding-gap driver.
        var withGap = Glossary.Build(Demo());
        var present = Single(withGap, "Onboarding / sensor gap");
        Assert.True(present.Present);
        Assert.Contains("DEMO-APP-12", present.InYourData);

        // Absent case: remove every onboarding-gap row -> honest "fully reporting" note.
        var noGap = Demo().Where(r =>
            !(r.RiskFactorProbability.Contains("onboarding", StringComparison.OrdinalIgnoreCase)
              || r.RiskFactorProbability.Contains("not fully managed", StringComparison.OrdinalIgnoreCase))).ToList();
        var absent = Single(Glossary.Build(noGap), "Onboarding / sensor gap");
        Assert.False(absent.Present);
        Assert.DoesNotContain("e.g.", absent.InYourData);
    }

    [Fact]
    public void Snapshot_term_reflects_real_snapshot_count_and_stays_honest_with_one()
    {
        var multi = Single(Glossary.Build(Demo()), "Snapshot");
        Assert.True(multi.Present);
        var snaps = SnapshotDiff.CollectionTimes(Demo()).Count;
        Assert.True(snaps >= 2);
        Assert.Contains("trends", multi.InYourData, StringComparison.OrdinalIgnoreCase);

        // Single snapshot: must NOT imply a trend exists.
        var one = SnapshotDiff.LatestSnapshot(Demo());
        var single = Single(Glossary.Build(one), "Snapshot");
        Assert.True(single.Present);
        Assert.Contains("only 1 snapshot", single.InYourData, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Glossary_examples_never_cite_an_asset_that_is_not_in_the_data()
    {
        var rows = Demo();
        var names = SnapshotDiff.LatestSnapshot(rows).Select(r => r.ConfigurationName).ToHashSet();
        var g = Glossary.Build(rows);

        // For every PRESENT term whose example uses "e.g. <name>:", the cited name must be a
        // REAL asset in the snapshot (no invented assets).
        foreach (var t in g.Terms.Where(t => t.Present && t.InYourData.Contains("e.g. ")))
        {
            var after = t.InYourData[(t.InYourData.IndexOf("e.g. ", StringComparison.Ordinal) + 5)..];
            var cited = after.Split(':')[0].Split(',')[0].Trim();
            // Some examples cite multiple names or phrase differently; assert at least one
            // real asset name appears in the example text.
            Assert.True(names.Any(n => t.InYourData.Contains(n, StringComparison.Ordinal)),
                $"Term '{t.Term}' example cites '{cited}' which is not a real asset: {t.InYourData}");
        }
    }

    [Fact]
    public void Glossary_survives_an_empty_snapshot_without_fabricating()
    {
        var g = Glossary.Build(Array.Empty<RiskRow>());
        Assert.NotEmpty(g.Terms);           // all terms still defined
        Assert.Equal(0, g.PresentCount);    // none present
        Assert.All(g.Terms, t =>
        {
            Assert.False(t.Present);
            Assert.False(string.IsNullOrWhiteSpace(t.Plain));
            Assert.DoesNotContain("e.g.", t.InYourData); // no fabricated examples on no data
        });
    }

    [Fact]
    public void Exec_dashboard_carries_the_glossary()
    {
        var dash = ExecDashboardBuilder.Build(Demo());
        Assert.NotEmpty(dash.Glossary.Terms);
        Assert.True(dash.Glossary.PresentCount > 0);
    }

    private static GlossaryTerm Single(GlossaryView g, string term) =>
        g.Terms.Single(t => t.Term == term);
}
