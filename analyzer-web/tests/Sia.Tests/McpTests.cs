using System.Text.Json.Nodes;
using Sia.Core.DataAccess;
using Sia.Web.Mcp;
using Sia.Web.Services;
using Xunit;

namespace Sia.Tests;

/// <summary>The MCP server tool surface is read-only + guardrailed.</summary>
public sealed class McpTests
{
    private static AnalyzerService Svc()
    {
        var data = new DemoRiskDataSource(DemoData.Load(TestData.SeedPath()));
        return new AnalyzerService(data, new OfflineAi());
    }

    [Fact]
    public void No_mcp_tool_can_write()
    {
        foreach (var t in McpServer.Tools)
        {
            var n = t.Name.ToLowerInvariant();
            Assert.DoesNotContain("write", n);
            Assert.DoesNotContain("create", n);
            Assert.DoesNotContain("update", n);
            Assert.DoesNotContain("delete", n);
            Assert.DoesNotContain("set", n);
            // every description advertises read-only
            Assert.Contains("read-only", t.Description, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task ToolsList_returns_the_catalogue()
    {
        var req = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = 1, ["method"] = "tools/list" };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        var tools = resp!["result"]!["tools"]!.AsArray();
        Assert.True(tools.Count >= 5);
    }

    [Fact]
    public async Task Guarded_query_tool_rejects_a_write()
    {
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 2,
            ["method"] = "tools/call",
            ["params"] = new JsonObject
            {
                ["name"] = "guarded_query",
                ["arguments"] = new JsonObject { ["kql"] = ".drop table SI_Endpoint_Profile_CL" },
            },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.NotNull(resp!["error"]);
        Assert.Contains("guardrail", resp!["error"]!["message"]!.GetValue<string>());
    }

    [Fact]
    public async Task Guarded_query_tool_runs_a_clean_read_only_query()
    {
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 3,
            ["method"] = "tools/call",
            ["params"] = new JsonObject
            {
                ["name"] = "guarded_query",
                ["arguments"] = new JsonObject { ["kql"] = "SI_Endpoint_Profile_CL | where CriticalityTier <= 1 | take 5" },
            },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.Null(resp!["error"]);
        Assert.False(resp!["result"]!["isError"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Exec_summary_tool_returns_a_grounded_headline()
    {
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 4,
            ["method"] = "tools/call",
            ["params"] = new JsonObject { ["name"] = "exec_summary", ["arguments"] = new JsonObject() },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        var text = resp!["result"]!["content"]![0]!["text"]!.GetValue<string>();
        Assert.Contains("headlineScore", text);
    }

    [Fact]
    public async Task Exec_headline_tool_returns_the_grounded_one_sentence_verdict()
    {
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 10,
            ["method"] = "tools/call",
            ["params"] = new JsonObject { ["name"] = "exec_headline", ["arguments"] = new JsonObject() },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.Null(resp!["error"]);
        var text = resp!["result"]!["content"]![0]!["text"]!.GetValue<string>();
        Assert.Contains("sentence", text);
        Assert.Contains("band", text);
        Assert.Contains("actionsToNextBand", text);
        // Grounded: no invented cost/probability in the verdict.
        Assert.DoesNotContain("$", text);
    }

    [Fact]
    public async Task Period_comparison_tool_returns_grounded_counts()
    {
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 5,
            ["method"] = "tools/call",
            ["params"] = new JsonObject
            {
                ["name"] = "period_comparison",
                ["arguments"] = new JsonObject { ["period"] = "previous" },
            },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.Null(resp!["error"]);
        var text = resp!["result"]!["content"]![0]!["text"]!.GetValue<string>();
        Assert.Contains("newCount", text);
        Assert.Contains("scoreDelta", text);
        Assert.Contains("hasBaseline", text);
    }

    [Fact]
    public async Task Risk_by_area_tool_returns_the_concentration_breakdown()
    {
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 6,
            ["method"] = "tools/call",
            ["params"] = new JsonObject { ["name"] = "risk_by_area", ["arguments"] = new JsonObject() },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.Null(resp!["error"]);
        var text = resp!["result"]!["content"]![0]!["text"]!.GetValue<string>();
        Assert.Contains("sharePercent", text);
        Assert.Contains("topContributor", text);
    }

    [Fact]
    public async Task Business_impact_tool_returns_grounded_consequences()
    {
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 7,
            ["method"] = "tools/call",
            ["params"] = new JsonObject { ["name"] = "business_impact", ["arguments"] = new JsonObject() },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.Null(resp!["error"]);
        var text = resp!["result"]!["content"]![0]!["text"]!.GetValue<string>();
        Assert.Contains("category", text);
        Assert.Contains("consequence", text);
        Assert.Contains("byCategory", text);
    }

    [Fact]
    public async Task Drilldown_tool_returns_evidence_behind_the_score()
    {
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 8,
            ["method"] = "tools/call",
            ["params"] = new JsonObject
            {
                ["name"] = "drilldown",
                ["arguments"] = new JsonObject { ["dimension"] = "overall" },
            },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.Null(resp!["error"]);
        var text = resp!["result"]!["content"]![0]!["text"]!.GetValue<string>();
        Assert.Contains("contributorCount", text);
        Assert.Contains("sharePercent", text);
    }

    [Fact]
    public async Task Drilldown_tool_defaults_to_overall_with_no_args()
    {
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 9,
            ["method"] = "tools/call",
            ["params"] = new JsonObject { ["name"] = "drilldown", ["arguments"] = new JsonObject() },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.Null(resp!["error"]);
        var text = resp!["result"]!["content"]![0]!["text"]!.GetValue<string>();
        Assert.Contains("overall", text);
    }

    [Fact]
    public async Task Maturity_scorecard_tool_returns_a_grounded_rating_per_dimension()
    {
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 14,
            ["method"] = "tools/call",
            ["params"] = new JsonObject { ["name"] = "maturity_scorecard", ["arguments"] = new JsonObject() },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.Null(resp!["error"]);
        var text = resp!["result"]!["content"]![0]!["text"]!.GetValue<string>();
        Assert.Contains("dimensions", text);
        Assert.Contains("roadmap", text);
        Assert.Contains("overallScore", text);
        Assert.Contains("weakAssets", text);
        Assert.Contains("nextMove", text);
        // Grounded: no invented cost figure on the maturity surface.
        Assert.DoesNotContain("$", text);
    }

    [Fact]
    public async Task Remediation_plan_tool_returns_a_grounded_prioritised_plan()
    {
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 13,
            ["method"] = "tools/call",
            ["params"] = new JsonObject
            {
                ["name"] = "remediation_plan",
                ["arguments"] = new JsonObject { ["top"] = 3 },
            },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.Null(resp!["error"]);
        var text = resp!["result"]!["content"]![0]!["text"]!.GetValue<string>();
        Assert.Contains("projectedScoreDrop", text);
        Assert.Contains("effort", text);
        Assert.Contains("cumulativeScoreAfter", text);
        Assert.Contains("projectedBandAfterPlan", text);
        // Grounded: no invented cost/date figure in the plan.
        Assert.DoesNotContain("$", text);
    }

    [Fact]
    public async Task Send_exec_summary_email_tool_is_fail_soft_with_no_recipients()
    {
        var svc = Svc();
        var emailOpts = new EmailScheduleOptions(); // no recipients / no SMTP
        var email = new ExecEmailService(svc, new SmtpExecEmailSender(emailOpts, new NullLogger<SmtpExecEmailSender>()), emailOpts);

        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 11,
            ["method"] = "tools/call",
            ["params"] = new JsonObject { ["name"] = "send_exec_summary_email", ["arguments"] = new JsonObject() },
        };
        var resp = await McpServer.HandleAsync(req, svc, default, email);
        Assert.Null(resp!["error"]);
        var text = resp!["result"]!["content"]![0]!["text"]!.GetValue<string>();
        Assert.Contains("sent", text, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("recipient", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Send_exec_summary_email_tool_errors_cleanly_when_unavailable()
    {
        // No email service passed => the tool reports unavailable, never throws.
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 12,
            ["method"] = "tools/call",
            ["params"] = new JsonObject { ["name"] = "send_exec_summary_email", ["arguments"] = new JsonObject() },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.NotNull(resp!["error"]);
        Assert.Contains("not available", resp!["error"]!["message"]!.GetValue<string>());
    }

    private sealed class NullLogger<T> : Microsoft.Extensions.Logging.ILogger<T>
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => false;
        public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
    }

    // AI-off narrative for offline MCP tests (grounded templated fallback).
    private sealed class OfflineAi : IAiNarrativeService
    {
        public bool IsAvailable => false;
        public Task<NarrativeResult> SummarizeAsync(string instruction, IReadOnlyList<Sia.Core.Model.RiskRow> rows, Sia.Core.Ai.Audience audience, Sia.Core.Ai.DiffSummary? diff = null, CancellationToken ct = default)
            => Task.FromResult(new NarrativeResult(Sia.Core.Ai.GroundedPrompt.TemplatedSummary(rows, audience, diff), false));
        public Task<string?> ComposeKqlAsync(string question, IReadOnlyList<string> allowedTables, CancellationToken ct = default)
            => Task.FromResult<string?>(null);
    }
}
