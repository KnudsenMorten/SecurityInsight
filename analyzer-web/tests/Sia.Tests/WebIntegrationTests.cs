using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// In-process integration tests over the real ASP.NET pipeline (demo data, AI-off).
/// Proves: the EXEC view is the DEFAULT landing surface; the exec dashboard renders
/// (headless build/render check) with its key board panels; the analyst surface is
/// secondary; the MCP endpoint answers; the guarded API rejects a write. No live
/// workspace / AI / secrets - the hosted run is the release gate.
/// </summary>
public sealed class WebIntegrationTests : IClassFixture<SiaAppFactory>
{
    private readonly SiaAppFactory _factory;
    public WebIntegrationTests(SiaAppFactory factory) => _factory = factory;

    [Fact]
    public async Task Root_redirects_to_the_exec_view()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var resp = await client.GetAsync("/");
        Assert.Equal(HttpStatusCode.Redirect, resp.StatusCode);
        Assert.Equal("/exec", resp.Headers.Location?.ToString());
    }

    [Fact]
    public async Task Exec_view_renders_the_board_ready_panels_with_no_kql_or_jargon()
    {
        var client = _factory.CreateClient();
        var html = await client.GetStringAsync("/exec");

        // Board-ready exec panels present.
        Assert.Contains("Overall risk score", html);
        Assert.Contains("Are we getting safer?", html);          // trend
        Assert.Contains("Quickest wins", html);                  // quick wins / ROI
        Assert.Contains("How complete is this picture?", html);  // coverage & confidence
        Assert.Contains("How does this map to the frameworks you report on?", html); // framework lens
        Assert.Contains("NIST CSF", html);                       // a board framework name
        Assert.Contains("How long have the top risks been open?", html); // aging / time-open
        Assert.Contains("Average time open", html);              // aging KPI
        Assert.Contains("id=\"dial\"", html);                    // score dial canvas
        Assert.Contains("id=\"trend\"", html);                   // trend canvas
        Assert.Contains("dashed point is a projection", html);   // labelled forecast
        Assert.Contains("Where does the risk concentrate?", html); // risk-by-area panel
        Assert.Contains("% of risk", html);                      // area share
        Assert.Contains("What moved the most?", html);           // trends & top movers panel
        Assert.Contains("Biggest improvements", html);           // movers improvement column
        Assert.Contains("Since last board meeting", html);       // period-over-period (default quarter label)
        Assert.Contains("/exec?period=", html);                  // period selector links
        Assert.Contains("So what? What this means for the business", html); // business-impact framing
        Assert.Contains("Show me the detail behind the score", html);       // drill-down on demand reveal
        Assert.Contains("What do these terms mean?", html);                  // exec glossary reveal
        Assert.Contains("in your data now", html);                           // a present-now glossary term badge
        Assert.Contains("Processes worth strengthening", html);              // missing-processes / org coaching panel
        Assert.Contains("Recommended:", html);                               // a coaching recommendation

        // Exec surface must NOT leak KQL/jargon.
        Assert.DoesNotContain("CollectionTime", html);
        Assert.DoesNotContain("summarize", html);
        Assert.DoesNotContain("RiskScoreTotal", html);
    }

    [Fact]
    public async Task Exec_view_honours_the_period_query_param()
    {
        var client = _factory.CreateClient();
        var html = await client.GetStringAsync("/exec?period=month");
        // The "Since last month" period label appears and its chip is active.
        Assert.Contains("Since last month", html);
        Assert.Contains("chip active", html);
    }

    [Fact]
    public async Task Exec_view_shows_the_grounded_one_sentence_headline()
    {
        var client = _factory.CreateClient();
        var html = await client.GetStringAsync("/exec");
        // The headline is the grounded verdict, not the old hardcoded phrase.
        Assert.Contains("Your security posture is", html);
        Assert.Contains("class=\"headline", html);
        // Links to the board-deck export are present.
        Assert.Contains("/board", html);
        Assert.Contains("Open board deck", html);
    }

    [Fact]
    public async Task Board_deck_page_renders_a_clean_one_page_handout()
    {
        var client = _factory.CreateClient();
        var html = await client.GetStringAsync("/board");
        Assert.Contains("Security posture - board summary", html);
        Assert.Contains("What this means", html);
        Assert.Contains("Recommended next actions", html);
        Assert.Contains("Processes worth strengthening", html); // org-coaching block on the handout
        Assert.Contains("Print / Save as PDF", html);
        // Print-ready, no charts/jargon on the handout.
        Assert.Contains("@media print", html);
        Assert.DoesNotContain("<canvas", html);
        Assert.DoesNotContain("RiskScoreTotal", html);
        Assert.DoesNotContain("CollectionTime", html);
    }

    [Fact]
    public async Task Board_api_returns_the_handout_as_html()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/board");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("text/html", resp.Content.Headers.ContentType?.MediaType);
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Contains("board summary", html);
    }

    [Fact]
    public async Task Email_preview_api_renders_the_grounded_exec_summary_email()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/api/email/preview");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal("text/html", resp.Content.Headers.ContentType?.MediaType);
        var html = await resp.Content.ReadAsStringAsync();
        Assert.Contains("Security posture - executive summary", html);
        Assert.Contains("What this means", html);
        Assert.Contains("Recommended next actions", html);
        // Grounded email carries no KQL/jargon.
        Assert.DoesNotContain("RiskScoreTotal", html);
        Assert.DoesNotContain("CollectionTime", html);
    }

    [Fact]
    public async Task Email_send_api_is_fail_soft_when_no_recipients_configured()
    {
        var client = _factory.CreateClient();
        // Default test config has no recipients => the trigger returns a clean not-sent result, not a 500.
        var resp = await client.PostAsJsonSafeAsync("/api/email/send", new { });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("\"sent\"", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("recipient", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Mcp_endpoint_lists_the_send_exec_summary_email_tool()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonSafeAsync("/mcp", new { jsonrpc = "2.0", id = 1, method = "tools/list" });
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("send_exec_summary_email", body);
    }

    [Fact]
    public async Task Analyst_view_is_available_as_a_secondary_surface()
    {
        var client = _factory.CreateClient();
        var html = await client.GetStringAsync("/analyst");
        Assert.Contains("Ask a question", html);
        Assert.Contains("Run read-only KQL", html);
    }

    [Fact]
    public async Task Exec_api_returns_a_grounded_headline_score()
    {
        var client = _factory.CreateClient();
        var json = await client.GetStringAsync("/api/exec");
        Assert.Contains("headlineScore", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Drilldown_api_returns_grounded_evidence_behind_the_score()
    {
        var client = _factory.CreateClient();
        var json = await client.GetStringAsync("/api/drilldown?dimension=overall");
        Assert.Contains("contributorCount", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("sharePercent", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Remediation_api_returns_a_prioritised_plan()
    {
        var client = _factory.CreateClient();
        var json = await client.GetStringAsync("/api/remediation?top=3");
        Assert.Contains("projectedScoreDrop", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("cumulativeScoreAfter", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("startBand", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Glossary_api_returns_grounded_plain_language_terms()
    {
        var client = _factory.CreateClient();
        var json = await client.GetStringAsync("/api/glossary");
        Assert.Contains("presentCount", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("inYourData", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Risk score", json);
        Assert.Contains("Crown jewel", json);
        // Plain-language layer must not leak the raw schema names.
        Assert.DoesNotContain("RiskScoreTotal", json);
        Assert.DoesNotContain("_CL", json);
    }

    [Fact]
    public async Task Mcp_endpoint_answers_the_glossary_tool_with_grounded_terms()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonSafeAsync("/mcp", new
        {
            jsonrpc = "2.0",
            id = 1,
            method = "tools/call",
            @params = new { name = "glossary", arguments = new { } },
        });
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("Crown jewel", body);
        Assert.Contains("inYourData", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("present", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Coaching_api_returns_grounded_process_gaps()
    {
        var client = _factory.CreateClient();
        var json = await client.GetStringAsync("/api/coaching");
        Assert.Contains("hasGaps", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("assetsConsidered", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("recommendation", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Privileged-access reviews", json);
        // Plain-language layer must not leak the raw schema names.
        Assert.DoesNotContain("RiskScoreTotal", json);
        Assert.DoesNotContain("_CL", json);
    }

    [Fact]
    public async Task Maturity_api_returns_a_grounded_scorecard_and_roadmap()
    {
        var client = _factory.CreateClient();
        var json = await client.GetStringAsync("/api/maturity");
        Assert.Contains("dimensions", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("roadmap", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("overallScore", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("nextMove", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Tiering", json);
        Assert.Contains("Privileged Access", json);
        // Plain-language layer must not leak the raw schema names.
        Assert.DoesNotContain("RiskScoreTotal", json);
        Assert.DoesNotContain("_CL", json);
    }

    [Fact]
    public async Task Mcp_endpoint_answers_the_org_coaching_tool_with_grounded_gaps()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonSafeAsync("/mcp", new
        {
            jsonrpc = "2.0",
            id = 1,
            method = "tools/call",
            @params = new { name = "org_coaching", arguments = new { } },
        });
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("hasGaps", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("recommendation", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("examples", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Query_api_rejects_a_write_with_the_guardrail()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonSafeAsync("/api/query", new { kql = ".drop table SI_Endpoint_Profile_CL", audience = "analyst" });
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("guardrail", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Mcp_endpoint_lists_read_only_tools()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonSafeAsync("/mcp", new { jsonrpc = "2.0", id = 1, method = "tools/list" });
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("guarded_query", body);
        Assert.Contains("read-only", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Health_endpoint_is_live()
    {
        var client = _factory.CreateClient();
        var resp = await client.GetAsync("/health");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }
}

/// <summary>Boots the real app with demo data + AI-off (no live deps).</summary>
public sealed class SiaAppFactory : WebApplicationFactory<Program>
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.ConfigureHostConfiguration(cfg =>
        {
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sia:UseDemoData"] = "true",
            });
        });
        // Make the demo seed discoverable from the test content root.
        Environment.SetEnvironmentVariable("SIA_TEST_SEED", TestData.SeedPath());
        return base.CreateHost(builder);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Point the content root at the web project so App_Data/demo-snapshot.json resolves,
        // and seed an explicit demo source so the test does not depend on the publish copy.
        builder.ConfigureServices(services =>
        {
            services.AddSingleton<Sia.Web.Services.IRiskDataSource>(_ =>
                new Sia.Web.Services.DemoRiskDataSource(
                    Sia.Core.DataAccess.DemoData.Load(TestData.SeedPath())));
        });
    }
}
