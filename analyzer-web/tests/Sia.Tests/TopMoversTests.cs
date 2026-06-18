using System.Text.Json.Nodes;
using Sia.Core.Analysis;
using Sia.Core.DataAccess;
using Sia.Core.Exec;
using Sia.Core.Model;
using Sia.Web.Mcp;
using Sia.Web.Services;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// Tests for "Trends &amp; top movers" (TESTS.md §9.8): which areas / severity bands /
/// tiers improved or worsened most between snapshots. Pure grounded aggregation - the
/// per-slice deltas are real score sums, the only derived value is the percent (null on a
/// zero baseline), and a single-snapshot history reports HasComparison=false honestly.
/// </summary>
public sealed class TopMoversTests
{
    private static IReadOnlyList<RiskRow> Demo() => DemoData.Load(TestData.SeedPath());

    private static RiskRow Row(string id, string domain, string sev, int tier, string tierLevel, double score, DateTimeOffset t) => new()
    {
        SecurityDomain = domain,
        ConfigurationName = id,
        ConfigurationId = id,
        RiskScoreTotal = score,
        SecuritySeverity = sev,
        CriticalityTier = tier,
        CriticalityTierLevel = tierLevel,
        CollectionTime = t,
    };

    private static readonly DateTimeOffset T0 = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset T1 = new(2026, 6, 8, 0, 0, 0, TimeSpan.Zero);

    // --- single-snapshot honesty ---

    [Fact]
    public void Single_snapshot_reports_no_comparison()
    {
        var one = SnapshotDiff.LatestSnapshot(Demo());
        var view = TopMovers.Build(one);
        Assert.False(view.HasComparison);
        Assert.Null(view.BaselineTime);
        Assert.Empty(view.BiggestImprovements);
        Assert.Empty(view.BiggestRegressions);
        Assert.Empty(view.Groups);
    }

    [Fact]
    public void No_rows_reports_no_comparison_and_does_not_throw()
    {
        var view = TopMovers.Build(Array.Empty<RiskRow>());
        Assert.False(view.HasComparison);
        Assert.Equal(0, view.TotalDelta);
    }

    [Fact]
    public void Explicit_baseline_equal_to_latest_reports_no_comparison()
    {
        // Guard: a degenerate baseline that IS the latest snapshot must not self-compare.
        var rows = new List<RiskRow> { Row("a", "identity", "High", 1, "High - tier 1", 50, T1) };
        var view = TopMovers.Build(rows, baseline: rows);
        Assert.False(view.HasComparison);
    }

    // --- grounding: deltas are real score sums ---

    [Fact]
    public void Area_deltas_equal_the_summed_score_change_per_area()
    {
        // identity: 30 -> 50 (worse +20); endpoint: 80 -> 60 (better -20).
        var rows = new List<RiskRow>
        {
            Row("id1", "identity", "High", 1, "High - tier 1", 30, T0),
            Row("ep1", "endpoint", "High", 1, "High - tier 1", 80, T0),
            Row("id1", "identity", "High", 1, "High - tier 1", 50, T1),
            Row("ep1", "endpoint", "High", 1, "High - tier 1", 60, T1),
        };
        var view = TopMovers.Build(rows);
        Assert.True(view.HasComparison);

        var area = view.Groups.First(g => g.Dimension == TopMovers.DimArea);
        var identity = area.Moves.First(m => m.Slice == "identity");
        var endpoint = area.Moves.First(m => m.Slice == "endpoint");

        Assert.Equal(30, identity.PreviousScore);
        Assert.Equal(50, identity.CurrentScore);
        Assert.Equal(20, identity.Delta);
        Assert.Equal("worsening", identity.Direction);

        Assert.Equal(-20, endpoint.Delta);
        Assert.Equal("improving", endpoint.Direction);

        // Overall delta = sum of slice deltas (0 here).
        Assert.Equal(0, view.TotalDelta);
    }

    [Fact]
    public void Biggest_improvements_and_increases_are_sorted_and_signed_correctly()
    {
        var rows = new List<RiskRow>
        {
            Row("a", "identity", "High", 1, "High - tier 1", 10, T0),
            Row("b", "endpoint", "High", 1, "High - tier 1", 100, T0),
            Row("c", "azure", "High", 1, "High - tier 1", 50, T0),
            Row("a", "identity", "High", 1, "High - tier 1", 60, T1),   // +50 worse
            Row("b", "endpoint", "High", 1, "High - tier 1", 30, T1),   // -70 better
            Row("c", "azure", "High", 1, "High - tier 1", 45, T1),      // -5 better
        };
        var view = TopMovers.Build(rows);

        // Biggest improvement = endpoint (-70), then azure (-5). All negative, most-negative first.
        Assert.Equal("endpoint", view.BiggestImprovements[0].Slice);
        Assert.All(view.BiggestImprovements, m => Assert.True(m.Delta < 0));
        Assert.True(view.BiggestImprovements[0].Delta <= view.BiggestImprovements[^1].Delta);

        // Biggest increase = identity (+50). All positive.
        Assert.Equal("identity", view.BiggestRegressions[0].Slice);
        Assert.All(view.BiggestRegressions, m => Assert.True(m.Delta > 0));
    }

    [Fact]
    public void Percent_is_null_when_the_baseline_score_was_zero()
    {
        // A brand-new area appears (regression from 0) -> no percent (can't divide by 0).
        var rows = new List<RiskRow>
        {
            Row("a", "identity", "High", 1, "High - tier 1", 40, T0),
            Row("a", "identity", "High", 1, "High - tier 1", 40, T1),
            Row("new", "publicip", "High", 1, "High - tier 1", 25, T1),  // new area
        };
        var view = TopMovers.Build(rows);
        var area = view.Groups.First(g => g.Dimension == TopMovers.DimArea);
        var pub = area.Moves.First(m => m.Slice == "publicip");
        Assert.Equal(25, pub.Delta);
        Assert.Null(pub.ChangePercent);
        Assert.Equal("worsening", pub.Direction);
    }

    [Fact]
    public void A_disappeared_slice_counts_as_an_improvement_to_zero()
    {
        var rows = new List<RiskRow>
        {
            Row("a", "identity", "High", 1, "High - tier 1", 40, T0),
            Row("gone", "azure", "High", 1, "High - tier 1", 33, T0),  // present only in baseline
            Row("a", "identity", "High", 1, "High - tier 1", 40, T1),
        };
        var view = TopMovers.Build(rows);
        var area = view.Groups.First(g => g.Dimension == TopMovers.DimArea);
        var azure = area.Moves.First(m => m.Slice == "azure");
        Assert.Equal(33, azure.PreviousScore);
        Assert.Equal(0, azure.CurrentScore);
        Assert.Equal(-33, azure.Delta);
        Assert.Equal("improving", azure.Direction);
    }

    // --- all three lenses present + plain language ---

    [Fact]
    public void All_three_lenses_are_built_with_plain_labels()
    {
        var rows = new List<RiskRow>
        {
            Row("a", "identity", "Critical", 0, "Critical - tier 0", 90, T0),
            Row("a", "identity", "Critical", 0, "Critical - tier 0", 40, T1),
        };
        var view = TopMovers.Build(rows);
        var dims = view.Groups.Select(g => g.Dimension).ToList();
        Assert.Contains(TopMovers.DimArea, dims);
        Assert.Contains(TopMovers.DimSeverity, dims);
        Assert.Contains(TopMovers.DimTier, dims);
        Assert.All(view.Groups, g => Assert.All(g.Moves, m =>
        {
            Assert.False(string.IsNullOrWhiteSpace(m.Plain));
            Assert.DoesNotContain("_CL", m.Plain);
            Assert.DoesNotContain("RiskScoreTotal", m.Plain);
        }));
    }

    [Fact]
    public void Demo_seed_has_two_snapshots_so_movers_are_comparable()
    {
        // The shipped demo seed carries prior+latest snapshots; movers must compare.
        var view = TopMovers.Build(Demo());
        Assert.True(view.HasComparison);
        Assert.NotNull(view.BaselineTime);
        Assert.NotEqual(view.BaselineTime, view.CurrentTime);
        // Some movement exists in the demo data (it is designed to show a diff).
        Assert.NotEmpty(view.Groups);
    }

    // --- dashboard + MCP wiring ---

    [Fact]
    public void Exec_dashboard_carries_the_movers_view()
    {
        var dash = ExecDashboardBuilder.Build(Demo());
        Assert.NotNull(dash.Movers);
        Assert.True(dash.Movers.HasComparison);
    }

    [Fact]
    public async Task Top_movers_mcp_tool_returns_grounded_movement()
    {
        var data = new DemoRiskDataSource(DemoData.Load(TestData.SeedPath()));
        var svc = new AnalyzerService(data, new NoOpTestAi());
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 42,
            ["method"] = "tools/call",
            ["params"] = new JsonObject { ["name"] = "top_movers", ["arguments"] = new JsonObject() },
        };
        var resp = await McpServer.HandleAsync(req, svc, default);
        Assert.Null(resp!["error"]);
        var text = resp!["result"]!["content"]![0]!["text"]!.GetValue<string>();
        Assert.Contains("hasComparison", text);
        Assert.Contains("biggestImprovements", text);
        Assert.Contains("biggestIncreases", text);
        Assert.Contains("breakdown", text);
    }

    [Fact]
    public void Top_movers_tool_is_registered_and_read_only()
    {
        var tool = McpServer.Tools.FirstOrDefault(t => t.Name == "top_movers");
        Assert.NotNull(tool);
        // Read-only catalogue: the description must not advertise any write.
        Assert.Contains("read-only", tool!.Description, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>AI-off narrative service so the MCP tool path needs no OpenAI.</summary>
    private sealed class NoOpTestAi : IAiNarrativeService
    {
        public bool IsAvailable => false;
        public Task<NarrativeResult> SummarizeAsync(string instruction, IReadOnlyList<RiskRow> rows, Sia.Core.Ai.Audience audience, Sia.Core.Ai.DiffSummary? diff = null, CancellationToken ct = default)
            => Task.FromResult(new NarrativeResult(Sia.Core.Ai.GroundedPrompt.TemplatedSummary(rows, audience, diff), false));
        public Task<string?> ComposeKqlAsync(string question, IReadOnlyList<string> allowedTables, CancellationToken ct = default)
            => Task.FromResult<string?>(null);
    }
}
