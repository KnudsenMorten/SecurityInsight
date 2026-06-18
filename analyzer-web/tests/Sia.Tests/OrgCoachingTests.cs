using Sia.Core.Analysis;
using Sia.Core.DataAccess;
using Sia.Core.Exec;
using Sia.Core.Model;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// Tests for the "missing processes / org coaching" exec layer (TESTS.md §9.7): the
/// leadership-level maturity / process gaps the finding PATTERNS imply (privileged-access
/// reviews, internet-exposure reviews, patch &amp; lifecycle cadence, onboarding, ownership,
/// crown-jewel protection). It is a pure, grounded aggregation over the RA rows - no AI, no
/// network, no invented numbers - and it is HONEST about missing data: a gap is only surfaced
/// when real rows cross an evidence threshold, and the view is empty (HasGaps=false) when no
/// systemic pattern stands out.
/// </summary>
public sealed class OrgCoachingTests
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
        CriticalityTierLevel = tier == 0 ? "Critical - tier 0" : $"Tier {tier}",
        SecuritySeverity = "High",
        RiskScoreTotal = score,
        RiskFactorProbability = prob,
        RiskFactorConsequence = cons,
        CollectionTime = DateTimeOffset.Parse(when),
    };

    // --- Grounding: the demo data drives every surfaced gap ---

    [Fact]
    public void Coaching_surfaces_the_process_gaps_the_demo_patterns_imply()
    {
        var cv = OrgCoaching.Build(Demo());
        Assert.True(cv.HasGaps);
        Assert.NotEmpty(cv.Gaps);

        var themes = cv.Gaps.Select(g => g.Theme).ToList();
        // The demo latest snapshot has: 2 stale/unowned/no-MFA privileged accounts, 3
        // internet-exposed assets, 3 EOL/unpatched assets, 1 onboarding gap, an orphan owner,
        // and 2 Tier 0 assets with open findings - so these themes must appear.
        Assert.Contains("Privileged-access reviews", themes);
        Assert.Contains("Internet-exposure reviews", themes);
        Assert.Contains("Patch & lifecycle management", themes);
        Assert.Contains("Crown-jewel protection", themes);
    }

    [Fact]
    public void Every_gap_count_matches_the_distinct_assets_behind_it_no_invented_numbers()
    {
        var latest = SnapshotDiff.LatestSnapshot(Demo());
        var cv = OrgCoaching.Build(Demo());

        foreach (var g in cv.Gaps)
        {
            // The advertised count is a real, positive number of assets...
            Assert.True(g.AffectedAssets > 0);
            // ...and it is reflected verbatim in the plain finding text (no rounding/guess).
            Assert.Contains(g.AffectedAssets.ToString(), g.Finding);
            // The example assets are REAL latest-snapshot asset names (never fabricated).
            Assert.NotEmpty(g.Examples);
            Assert.True(g.Examples.Count <= 3);
            Assert.All(g.Examples, e => Assert.Contains(latest, r => r.ConfigurationName == e));
            // The count is never larger than the snapshot it was measured over.
            Assert.True(g.AffectedAssets <= latest.Count);
        }
    }

    [Fact]
    public void Recommendations_are_processes_not_per_asset_tickets_and_carry_no_jargon()
    {
        var cv = OrgCoaching.Build(Demo());
        Assert.All(cv.Gaps, g =>
        {
            Assert.False(string.IsNullOrWhiteSpace(g.Recommendation));
            Assert.False(string.IsNullOrWhiteSpace(g.Finding));
            // No KQL / table / column jargon on the exec surface.
            Assert.DoesNotContain("RiskScoreTotal", g.Recommendation);
            Assert.DoesNotContain("_CL", g.Recommendation);
            Assert.DoesNotContain("KQL", g.Recommendation, StringComparison.OrdinalIgnoreCase);
        });
    }

    [Fact]
    public void Gaps_are_ordered_most_affected_first()
    {
        var cv = OrgCoaching.Build(Demo());
        var counts = cv.Gaps.Select(g => g.AffectedAssets).ToList();
        var sorted = counts.OrderByDescending(c => c).ToList();
        Assert.Equal(sorted, counts);
    }

    // --- Honesty about missing data ---

    [Fact]
    public void Clean_posture_yields_no_invented_gap()
    {
        // A snapshot whose findings are unrelated one-offs with none of the gap signals and
        // no Tier 0 assets => no systemic process gap should be claimed.
        var clean = new[]
        {
            Row("APP-1", "endpoint", 2, "Configuration drift on a setting", score: 12),
            Row("APP-2", "endpoint", 3, "Minor hardening recommendation", score: 8),
        };
        var cv = OrgCoaching.Build(clean);
        Assert.False(cv.HasGaps);
        Assert.Empty(cv.Gaps);
        Assert.Equal(2, cv.AssetsConsidered);
    }

    [Fact]
    public void A_single_one_off_does_not_become_a_systemic_gap()
    {
        // ONE stale privileged account is a per-asset ticket, not a missing process: the
        // privileged-review pattern needs >= 2 distinct assets before it is surfaced.
        var oneOff = new[]
        {
            Row("svc-old", "identity", 1, "Stale - password never rotated", score: 40),
            Row("APP-2", "endpoint", 3, "Minor hardening recommendation", score: 8),
        };
        var cv = OrgCoaching.Build(oneOff);
        Assert.DoesNotContain(cv.Gaps, g => g.Theme == "Privileged-access reviews");
    }

    [Fact]
    public void The_same_asset_with_two_findings_counts_once()
    {
        // Same identity, two internet-exposure findings -> still ONE asset, so the 2-asset
        // exposure threshold is NOT met by a single duplicated asset (honest de-duplication).
        var dup = new[]
        {
            Row("EDGE-1", "publicip", 1, "Open management port exposed to the internet", score: 60, id: "pip-1", when: "2026-06-17T06:00:00Z"),
            Row("EDGE-1", "publicip", 1, "Internet-facing with a public access enabled", score: 55, id: "pip-1", when: "2026-06-17T06:00:00Z"),
        };
        var cv = OrgCoaching.Build(dup);
        Assert.DoesNotContain(cv.Gaps, g => g.Theme == "Internet-exposure reviews");
    }

    [Fact]
    public void Patterns_are_measured_over_the_latest_snapshot_only()
    {
        // An older snapshot full of exposure signals + a latest snapshot that is clean must
        // NOT surface an exposure gap (the gap reflects the CURRENT posture, not history).
        var rows = new[]
        {
            Row("EDGE-1", "publicip", 1, "Open port exposed to the internet", score: 60, id: "pip-1", when: "2026-06-10T06:00:00Z"),
            Row("EDGE-2", "publicip", 1, "Internet-facing public access enabled", score: 55, id: "pip-2", when: "2026-06-10T06:00:00Z"),
            Row("APP-NOW", "endpoint", 2, "Configuration drift", score: 10, id: "ep-9", when: "2026-06-17T06:00:00Z"),
        };
        var cv = OrgCoaching.Build(rows);
        Assert.Equal(1, cv.AssetsConsidered); // only the latest snapshot
        Assert.DoesNotContain(cv.Gaps, g => g.Theme == "Internet-exposure reviews");
    }

    [Fact]
    public void Coaching_survives_no_rows()
    {
        var cv = OrgCoaching.Build(Array.Empty<RiskRow>());
        Assert.False(cv.HasGaps);
        Assert.Empty(cv.Gaps);
        Assert.Equal(0, cv.AssetsConsidered);
    }

    // --- Dashboard wiring ---

    [Fact]
    public void Exec_dashboard_carries_the_coaching_view()
    {
        var dash = ExecDashboardBuilder.Build(Demo());
        Assert.NotNull(dash.Coaching);
        Assert.True(dash.Coaching.HasGaps);
        Assert.NotEmpty(dash.Coaching.Gaps);
    }
}
