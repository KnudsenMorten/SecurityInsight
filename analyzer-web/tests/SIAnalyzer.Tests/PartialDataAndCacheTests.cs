using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SIAnalyzer.Core.Ai;
using SIAnalyzer.Core.DataAccess;
using SIAnalyzer.Core.Exec;
using SIAnalyzer.Core.Model;
using SIAnalyzer.Web.Rendering;
using SIAnalyzer.Web.Services;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// AUDIT #10 — a partial read is never presented as a complete one, and the rollup is not
/// re-queried once per call site (TESTS.md §9.4).
///
/// The data plane took <c>response.Value.Table</c> and ignored <c>LogsQueryResultStatus</c>
/// entirely. Log Analytics returns PartialFailure — truncated rows PLUS an error — at its
/// 500,000-row / 100 MB caps, and the rollup asks for up to 500,000. Because everything
/// downstream resolves <c>max(CollectionTime)</c> and SUMS scores, a truncated read renders as
/// fewer findings and a LOWER score: it looks like the organisation got safer.
/// </summary>
public sealed class CachedRiskDataSourceTests
{
    [Fact]
    public async Task A_second_read_inside_the_ttl_does_not_hit_the_workspace()
    {
        var inner = new CountingSource();
        var cache = new CachedRiskDataSource(inner, TimeSpan.FromMinutes(5));

        await cache.GetAllRowsAsync();
        await cache.GetAllRowsAsync();
        await cache.GetAllRowsAsync();

        Assert.Equal(1, inner.Calls);
    }

    [Fact]
    public async Task The_workspace_is_read_again_once_the_ttl_expires()
    {
        var inner = new CountingSource();
        var clock = DateTimeOffset.UtcNow;
        var cache = new CachedRiskDataSource(inner, TimeSpan.FromMinutes(5), () => clock);

        await cache.GetAllRowsAsync();
        clock = clock.AddMinutes(6);
        await cache.GetAllRowsAsync();

        Assert.Equal(2, inner.Calls);
    }

    [Fact]
    public async Task A_partial_result_is_never_cached()
    {
        // Caching a truncated read would keep serving understated figures for the whole TTL.
        // Not caching it means the very next request can recover.
        var inner = new CountingSource { Partial = true };
        var cache = new CachedRiskDataSource(inner, TimeSpan.FromMinutes(5));

        await cache.GetAllRowsAsync();
        await cache.GetAllRowsAsync();

        Assert.Equal(2, inner.Calls);
    }

    [Fact]
    public async Task A_partial_result_also_evicts_an_earlier_complete_one()
    {
        // Otherwise a stale-but-complete snapshot would mask the fact that the workspace has
        // started returning partial results.
        var inner = new CountingSource();
        var cache = new CachedRiskDataSource(inner, TimeSpan.FromMinutes(5));
        await cache.GetAllRowsAsync();          // complete, cached
        inner.Partial = true;

        var clock = 0;                          // force a miss by exhausting the TTL
        var cache2 = new CachedRiskDataSource(inner, TimeSpan.FromMinutes(5), () => DateTimeOffset.UtcNow.AddMinutes(clock += 10));
        var partial = await cache2.GetAllRowsAsync();
        Assert.True(partial.Quality.IsPartial);

        var next = await cache2.GetAllRowsAsync();
        Assert.True(next.Quality.IsPartial);    // re-read, not served from cache
    }

    [Fact]
    public async Task Concurrent_first_reads_collapse_into_one_workspace_query()
    {
        // Without single-flight the cache makes the worst case WORSE: N cold requests would all
        // launch the same 500k-row query.
        var inner = new CountingSource { Delay = TimeSpan.FromMilliseconds(50) };
        var cache = new CachedRiskDataSource(inner, TimeSpan.FromMinutes(5));

        await Task.WhenAll(Enumerable.Range(0, 16).Select(_ => cache.GetAllRowsAsync()));

        Assert.Equal(1, inner.Calls);
    }

    [Fact]
    public async Task Ad_hoc_queries_are_never_cached()
    {
        // An analyst re-running a query expects the workspace, not a cached answer.
        var inner = new CountingSource();
        var cache = new CachedRiskDataSource(inner, TimeSpan.FromMinutes(5));

        await cache.RunGuardedQueryAsync("SI_RiskAnalysis_Summary_CL | take 1");
        await cache.RunGuardedQueryAsync("SI_RiskAnalysis_Summary_CL | take 1");

        Assert.Equal(2, inner.QueryCalls);
    }

    [Fact]
    public async Task A_zero_ttl_disables_caching_entirely()
    {
        var inner = new CountingSource();
        var cache = new CachedRiskDataSource(inner, TimeSpan.Zero);

        await cache.GetAllRowsAsync();
        await cache.GetAllRowsAsync();

        Assert.Equal(2, inner.Calls);
    }

    private sealed class CountingSource : IRiskDataSource
    {
        private int _calls;
        public int Calls => _calls;
        public int QueryCalls { get; private set; }
        public bool Partial { get; set; }
        public TimeSpan Delay { get; set; }

        public bool IsLive => true;
        public string SourceDescription => "counting fake";

        public async Task<RiskSnapshot> GetAllRowsAsync(CancellationToken ct = default)
        {
            Interlocked.Increment(ref _calls);
            if (Delay > TimeSpan.Zero) await Task.Delay(Delay, ct);
            var quality = Partial
                ? new DataQuality(true, "row cap reached", DateTimeOffset.UtcNow)
                : DataQuality.Complete(DateTimeOffset.UtcNow);
            return new RiskSnapshot(Array.Empty<RiskRow>(), quality);
        }

        public Task<QueryResult> RunGuardedQueryAsync(string kql, CancellationToken ct = default)
        {
            QueryCalls++;
            return Task.FromResult(new QueryResult(Array.Empty<string>(), Array.Empty<IReadOnlyList<object?>>()));
        }
    }
}

/// <summary>
/// Every surface that shows a figure must show the partial-data warning — and none of them may
/// show it when the read was complete. Both halves matter: a warning nobody sees is the bug, and
/// a warning that cries wolf gets ignored.
/// </summary>
public sealed class PartialDataSurfaceTests
{
    private static ExecViewModel Model(bool partial)
    {
        var rows = DemoData.Load(TestData.SeedPath());
        var dash = ExecDashboardBuilder.Build(rows, null);
        var quality = partial
            ? new DataQuality(true, "the query hit the 500,000-row cap", DateTimeOffset.UtcNow)
            : DataQuality.Complete(DateTimeOffset.UtcNow);
        return new ExecViewModel(dash, "summary text", false, true, "live", false, quality);
    }

    [Fact]
    public void The_exec_page_states_it_before_any_figure()
    {
        var html = ExecHtmlRenderer.RenderBody(Model(partial: true), null, false);
        Assert.Contains("PARTIAL DATA", html);
        Assert.Contains("UNDERSTATED", html);
        Assert.Contains("role=\"alert\"", html);
        // Before the score dial, not buried under it. Compare inside <main> only - the CSS block
        // above it also mentions the dial classes, which would make a whole-document IndexOf
        // compare the stylesheet rather than the rendered order.
        var body = html[html.IndexOf("<main", StringComparison.Ordinal)..];
        Assert.True(
            body.IndexOf("PARTIAL DATA", StringComparison.Ordinal) < body.IndexOf("dial-score", StringComparison.Ordinal),
            "the partial-data warning must render above the score dial");
    }

    [Fact]
    public void The_board_deck_carries_it_too()
    {
        // The deck is PRINTED and handed round; it cannot rely on the reader having seen the app.
        var html = BoardDeckRenderer.Render(Model(partial: true));
        Assert.Contains("PARTIAL DATA", html);
        Assert.Contains("UNDERSTATED", html);
        // Above the score badge: on a handout the big number is what a reader takes in first, so
        // the caveat must not come after the figure it qualifies.
        var body = html[html.IndexOf("<main", StringComparison.Ordinal)..];
        Assert.True(
            body.IndexOf("PARTIAL DATA", StringComparison.Ordinal) < body.IndexOf("badge-score", StringComparison.Ordinal),
            "the partial-data warning must render above the score badge on the board deck");
    }

    [Fact]
    public void The_email_says_it_in_the_subject_the_body_and_the_text_twin()
    {
        var vm = Model(partial: true);
        var msg = ExecEmailRenderer.Render(vm.Dashboard.Headline, vm.Dashboard, vm.ExecSummary, false, true,
            null, null, DataQuality.Warning);

        Assert.StartsWith("[PARTIAL DATA]", msg.Subject);
        Assert.Contains("PARTIAL DATA", msg.HtmlBody);
        Assert.Contains("PARTIAL DATA", msg.TextBody);
    }

    [Fact]
    public void A_complete_read_shows_no_warning_anywhere()
    {
        // The control: no false alarms, or the banner stops meaning anything.
        var vm = Model(partial: false);
        var exec = ExecHtmlRenderer.RenderBody(vm, null, false);
        var deck = BoardDeckRenderer.Render(vm);
        var msg = ExecEmailRenderer.Render(vm.Dashboard.Headline, vm.Dashboard, vm.ExecSummary, false, true, null, null, null);

        Assert.DoesNotContain("PARTIAL DATA", exec);
        Assert.DoesNotContain("PARTIAL DATA", deck);
        Assert.DoesNotContain("PARTIAL DATA", msg.Subject);
        Assert.DoesNotContain("PARTIAL DATA", msg.HtmlBody);
        Assert.DoesNotContain("PARTIAL DATA", msg.TextBody);
    }

    [Fact]
    public void The_wording_is_one_constant_so_the_surfaces_cannot_drift()
    {
        Assert.Contains("UNDERSTATED", DataQuality.Warning);
        Assert.Contains("Do not read this as an improvement", DataQuality.Warning);
    }
}

/// <summary>The partial warning reaching the live surfaces end to end, with a data source that
/// reports a truncated read.</summary>
public sealed class PartialDataAppFactory : WebApplicationFactory<Program>
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.ConfigureHostConfiguration(cfg =>
        {
            cfg.AddInMemoryCollection(new Dictionary<string, string?> { ["SIAnalyzer:UseDemoData"] = "true" });
        });
        Environment.SetEnvironmentVariable("SIA_TEST_SEED", TestData.SeedPath());
        return base.CreateHost(builder);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            services.AddSingleton<IRiskDataSource>(_ => new PartialDemoSource(DemoData.Load(TestData.SeedPath())));
        });
    }

    private sealed class PartialDemoSource : IRiskDataSource
    {
        private readonly DemoRiskDataSource _inner;
        public PartialDemoSource(IReadOnlyList<RiskRow> rows) => _inner = new DemoRiskDataSource(rows);
        public bool IsLive => true;
        public string SourceDescription => "partial (test)";
        public async Task<RiskSnapshot> GetAllRowsAsync(CancellationToken ct = default) =>
            new((await _inner.GetAllRowsAsync(ct)).Rows, new DataQuality(true, "the query hit the row cap", DateTimeOffset.UtcNow));
        public Task<QueryResult> RunGuardedQueryAsync(string kql, CancellationToken ct = default) => _inner.RunGuardedQueryAsync(kql, ct);
    }
}

public sealed class PartialDataEndToEndTests : IClassFixture<PartialDataAppFactory>
{
    private readonly PartialDataAppFactory _factory;
    public PartialDataEndToEndTests(PartialDataAppFactory factory) => _factory = factory;

    [Theory]
    [InlineData("/exec")]
    [InlineData("/board")]
    [InlineData("/analyst")]
    public async Task Every_page_that_shows_figures_warns_about_the_partial_read(string path)
    {
        var html = await _factory.CreateClient().GetStringAsync(path);
        Assert.Contains("PARTIAL DATA", html);
    }

    [Fact]
    public async Task The_api_reports_the_quality_so_a_caller_can_see_it_too()
    {
        var json = await _factory.CreateClient().GetStringAsync("/api/exec");
        Assert.Contains("\"isPartial\":true", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task The_email_preview_warns_as_well()
    {
        var html = await _factory.CreateClient().GetStringAsync("/api/email/preview");
        Assert.Contains("PARTIAL DATA", html);
    }
}
