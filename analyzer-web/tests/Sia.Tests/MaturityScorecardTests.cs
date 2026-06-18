using Sia.Core.Analysis;
using Sia.Core.DataAccess;
using Sia.Core.Exec;
using Sia.Core.Model;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// Tests for the maturity scorecard + roadmap exec layer (TESTS.md §9.9): a leader-facing
/// capability rating across six dimensions (Tiering, Privileged Access, Identity Hygiene,
/// Exposure Management, Visibility &amp; Coverage, Operating Discipline) plus a prioritised
/// "mature here next" roadmap. It is a pure, rule-based, grounded aggregation over the latest-
/// snapshot RA rows - no AI, no network, no invented numbers - and it is HONEST about missing
/// data: each dimension's score is the share of in-scope assets WITHOUT a weakness, a dimension
/// with no in-scope asset reports "not enough data" (never a fabricated score), and the roadmap
/// is empty when no dimension stands out as a systemic gap.
/// </summary>
public sealed class MaturityScorecardTests
{
    private static IReadOnlyList<RiskRow> Demo() => DemoData.Load(TestData.SeedPath());

    private static RiskRow Row(
        string name, string domain, int tier, string prob, string cons = "",
        double score = 50, string id = "", string when = "2026-06-17T06:00:00Z") => new()
    {
        ConfigurationName = name,
        ConfigurationId = string.IsNullOrEmpty(id) ? name : id,
        SecurityDomain = domain,
        CriticalityTier = tier,
        CriticalityTierLevel = tier < 0 ? "" : (tier == 0 ? "Critical - tier 0" : $"Tier {tier}"),
        SecuritySeverity = "High",
        RiskScoreTotal = score,
        RiskFactorProbability = prob,
        RiskFactorConsequence = cons,
        CollectionTime = DateTimeOffset.Parse(when),
    };

    // --- Shape & fixed dimension set ---

    [Fact]
    public void Scorecard_has_the_six_named_dimensions_in_a_fixed_order()
    {
        var m = MaturityScorecard.Build(Demo());
        var dims = m.Dimensions.Select(d => d.Dimension).ToList();
        Assert.Equal(new[]
        {
            "Tiering", "Privileged Access", "Identity Hygiene",
            "Exposure Management", "Visibility & Coverage", "Operating Discipline",
        }, dims);
    }

    // --- Grounding: every score is a real partition, no invented numbers ---

    [Fact]
    public void Every_dimension_score_is_the_grounded_share_of_clean_in_scope_assets()
    {
        var m = MaturityScorecard.Build(Demo());
        foreach (var d in m.Dimensions)
        {
            // Score is always a legal 0-100 maturity percentage.
            Assert.InRange(d.Score, 0, 100);
            if (d.HasData)
            {
                // The numerator never exceeds the denominator (honest counts)...
                Assert.True(d.WeakAssets >= 0);
                Assert.True(d.WeakAssets <= d.Considered);
                Assert.True(d.Considered > 0);
                // ...and the score IS exactly the share of in-scope assets without a weakness.
                var expected = Math.Round(100.0 * (d.Considered - d.WeakAssets) / d.Considered, 1);
                Assert.Equal(expected, d.Score);
                // The rating band matches the score (no mismatched label).
                Assert.Equal(MaturityScorecard.RatingFor(d.Score), d.Rating);
            }
            else
            {
                Assert.Equal(0, d.Considered);
                Assert.Equal("Not enough data", d.Rating);
            }
        }
    }

    [Fact]
    public void Example_assets_are_real_latest_snapshot_names_never_fabricated()
    {
        var latest = SnapshotDiff.LatestSnapshot(Demo());
        var m = MaturityScorecard.Build(Demo());
        foreach (var d in m.Dimensions)
        {
            Assert.True(d.Examples.Count <= 3);
            Assert.All(d.Examples, e => Assert.Contains(latest, r => r.ConfigurationName == e));
            // A dimension only names examples when it actually has weak assets.
            if (d.Examples.Count > 0) Assert.True(d.WeakAssets > 0);
        }
    }

    [Fact]
    public void Overall_score_is_the_average_of_the_dimensions_that_have_data()
    {
        var m = MaturityScorecard.Build(Demo());
        var scored = m.Dimensions.Where(d => d.HasData).Select(d => d.Score).ToList();
        Assert.NotEmpty(scored);
        Assert.Equal(Math.Round(scored.Average(), 1), m.OverallScore);
        Assert.Equal(MaturityScorecard.RatingFor(m.OverallScore!.Value), m.OverallRating);
    }

    // --- Roadmap: prioritised, grounded, board-sized ---

    [Fact]
    public void Roadmap_lists_only_below_bar_dimensions_with_real_evidence_lowest_first()
    {
        // Two clear systemic gaps (exposure + privileged access) over enough assets that each
        // dimension scores below the 80 maturity bar, so both must appear on the roadmap.
        var rows = new[]
        {
            Row("EDGE-1", "publicip", 1, "Open management port exposed to the internet", score: 60, id: "pip-1"),
            Row("EDGE-2", "publicip", 1, "Internet-facing with public access enabled", score: 55, id: "pip-2"),
            Row("EDGE-3", "publicip", 1, "Open risky port on the public network", score: 50, id: "pip-3"),
            Row("svc-1", "identity", 1, "Stale - password never rotated, no MFA", score: 70, id: "id-1"),
            Row("svc-2", "identity", 1, "No owner, standing privileged access", score: 65, id: "id-2"),
        };
        var m = MaturityScorecard.Build(rows);

        Assert.True(m.HasRoadmap);
        Assert.NotEmpty(m.Roadmap);
        Assert.True(m.Roadmap.Count <= 5);
        // Every roadmap item is below the bar and has real weak-asset evidence.
        Assert.All(m.Roadmap, d =>
        {
            Assert.True(d.WeakAssets > 0);
            Assert.True(d.Score < 80);
            Assert.False(string.IsNullOrWhiteSpace(d.NextMove));
        });
        // Ordered lowest-maturity (biggest gap) first.
        var scores = m.Roadmap.Select(d => d.Score).ToList();
        Assert.Equal(scores.OrderBy(s => s).ToList(), scores);
    }

    [Fact]
    public void Recommendations_are_leadership_moves_with_no_jargon()
    {
        var m = MaturityScorecard.Build(Demo());
        Assert.All(m.Dimensions, d =>
        {
            Assert.False(string.IsNullOrWhiteSpace(d.NextMove));
            Assert.DoesNotContain("RiskScoreTotal", d.NextMove);
            Assert.DoesNotContain("_CL", d.NextMove);
            Assert.DoesNotContain("KQL", d.NextMove, StringComparison.OrdinalIgnoreCase);
        });
    }

    // --- Honesty about missing data ---

    [Fact]
    public void A_dimension_with_no_in_scope_asset_is_not_enough_data_not_a_fabricated_score()
    {
        // An estate with NO identity assets at all => Privileged Access + Identity Hygiene have
        // no in-scope assets and must honestly report "not enough data", never a made-up score.
        var rows = new[]
        {
            Row("APP-1", "endpoint", 2, "Configuration drift on a setting", score: 12),
            Row("APP-2", "endpoint", 3, "Minor hardening recommendation", score: 8),
        };
        var m = MaturityScorecard.Build(rows);

        var idHygiene = m.Dimensions.Single(d => d.Dimension == "Identity Hygiene");
        var privAccess = m.Dimensions.Single(d => d.Dimension == "Privileged Access");
        Assert.False(idHygiene.HasData);
        Assert.False(privAccess.HasData);
        Assert.Equal("Not enough data", idHygiene.Rating);
        Assert.Equal("Not enough data", privAccess.Rating);
        Assert.Empty(idHygiene.Examples);
        // A no-data dimension never lands on the roadmap (no fabricated gap).
        Assert.DoesNotContain(m.Roadmap, d => d.Dimension is "Identity Hygiene" or "Privileged Access");
    }

    [Fact]
    public void A_fully_mature_posture_scores_100_and_yields_no_roadmap()
    {
        // Clean, classified, owned, non-exposed, fully-reporting assets with no weakness signals
        // => every measurable dimension is at 100 (Managed) and nothing makes the roadmap.
        var clean = new[]
        {
            Row("APP-1", "endpoint", 2, "Telemetry healthy; baseline aligned", score: 5),
            Row("APP-2", "endpoint", 3, "Compliant configuration", score: 4),
        };
        var m = MaturityScorecard.Build(clean);

        var measurable = m.Dimensions.Where(d => d.HasData).ToList();
        Assert.NotEmpty(measurable);
        Assert.All(measurable, d =>
        {
            Assert.Equal(100, d.Score);
            Assert.Equal("Managed", d.Rating);
            Assert.Equal(0, d.WeakAssets);
        });
        Assert.False(m.HasRoadmap);
        Assert.Empty(m.Roadmap);
    }

    [Fact]
    public void Tier0_crown_jewel_with_an_open_finding_dents_tiering_maturity()
    {
        // A Tier 0 crown jewel still carrying an open finding is a tiering-maturity weakness.
        var rows = new[]
        {
            Row("DC-01", "identity", 0, "Privileged role with an open finding", score: 90, id: "t0-1"),
            Row("APP-2", "endpoint", 2, "Compliant configuration", score: 5, id: "ep-2"),
        };
        var m = MaturityScorecard.Build(rows);
        var tiering = m.Dimensions.Single(d => d.Dimension == "Tiering");
        Assert.True(tiering.WeakAssets >= 1);
        Assert.True(tiering.Score < 100);
        Assert.Contains("DC-01", tiering.Examples);
    }

    [Fact]
    public void Unclassified_tier_dents_tiering_maturity()
    {
        var rows = new[]
        {
            Row("UNK-1", "endpoint", -1, "Some finding", score: 20, id: "u-1"), // blank tier level
            Row("APP-2", "endpoint", 2, "Compliant configuration", score: 5, id: "ep-2"),
        };
        var m = MaturityScorecard.Build(rows);
        var tiering = m.Dimensions.Single(d => d.Dimension == "Tiering");
        Assert.True(tiering.WeakAssets >= 1);
        Assert.Contains("UNK-1", tiering.Examples);
    }

    [Fact]
    public void Measured_over_the_latest_snapshot_only()
    {
        // An older snapshot full of exposure signals + a clean latest snapshot must NOT drag
        // Exposure Management down - the scorecard reflects the CURRENT posture only.
        var rows = new[]
        {
            Row("EDGE-1", "publicip", 1, "Open port exposed to the internet", score: 60, id: "pip-1", when: "2026-06-10T06:00:00Z"),
            Row("EDGE-2", "publicip", 1, "Internet-facing public access enabled", score: 55, id: "pip-2", when: "2026-06-10T06:00:00Z"),
            Row("APP-NOW", "endpoint", 2, "Compliant configuration", score: 5, id: "ep-9", when: "2026-06-17T06:00:00Z"),
        };
        var m = MaturityScorecard.Build(rows);
        Assert.Equal(1, m.AssetsConsidered); // only the latest snapshot
        var exposure = m.Dimensions.Single(d => d.Dimension == "Exposure Management");
        Assert.Equal(0, exposure.WeakAssets);
        Assert.Equal(100, exposure.Score);
    }

    [Fact]
    public void The_same_asset_with_two_weakness_findings_counts_once()
    {
        // One asset, two exposure findings -> 1 in-scope asset, 1 weak asset (honest de-dup).
        var dup = new[]
        {
            Row("EDGE-1", "publicip", 1, "Open management port exposed to the internet", score: 60, id: "pip-1"),
            Row("EDGE-1", "publicip", 1, "Internet-facing with public access enabled", score: 55, id: "pip-1"),
        };
        var m = MaturityScorecard.Build(dup);
        var exposure = m.Dimensions.Single(d => d.Dimension == "Exposure Management");
        Assert.Equal(1, exposure.Considered);
        Assert.Equal(1, exposure.WeakAssets);
    }

    [Fact]
    public void Scorecard_survives_no_rows()
    {
        var m = MaturityScorecard.Build(Array.Empty<RiskRow>());
        Assert.Equal(0, m.AssetsConsidered);
        Assert.Null(m.OverallScore);
        Assert.Equal("Not enough data", m.OverallRating);
        Assert.False(m.HasRoadmap);
        Assert.Empty(m.Roadmap);
        // Every dimension still appears (fixed set) but reports no data.
        Assert.Equal(6, m.Dimensions.Count);
        Assert.All(m.Dimensions, d => Assert.False(d.HasData));
    }

    // --- Rating bands ---

    [Theory]
    [InlineData(95, "Managed")]
    [InlineData(90, "Managed")]
    [InlineData(80, "Defined")]
    [InlineData(75, "Defined")]
    [InlineData(60, "Developing")]
    [InlineData(50, "Developing")]
    [InlineData(40, "Initial")]
    [InlineData(0, "Initial")]
    public void Rating_bands_map_as_documented(double score, string expected) =>
        Assert.Equal(expected, MaturityScorecard.RatingFor(score));

    // --- Dashboard wiring ---

    [Fact]
    public void Exec_dashboard_carries_the_maturity_scorecard()
    {
        var dash = ExecDashboardBuilder.Build(Demo());
        Assert.NotNull(dash.Maturity);
        Assert.Equal(6, dash.Maturity.Dimensions.Count);
        Assert.Equal(SnapshotDiff.LatestSnapshot(Demo()).Count, dash.Maturity.AssetsConsidered);
    }
}
