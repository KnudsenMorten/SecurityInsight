using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SIAnalyzer.Core.DataAccess;
using SIAnalyzer.Web.Mcp;
using SIAnalyzer.Web.Services;
using SIAnalyzer.Core.Ai;
using SIAnalyzer.Core.Exec;
using SIAnalyzer.Core.Model;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// AUDIT #11 — the MCP server's contract matches what it actually does (TESTS.md §9.5).
///
/// The file claimed "it never exposes a write tool" and "(no write tools exist)" while shipping
/// <c>send_exec_summary_email</c>, which transmits mail to the configured executive recipients.
/// The contract is now "read-only EXCEPT one declared side-effecting tool", that tool is annotated
/// and ships OFF, notifications get the silence the protocol requires, and an unexpected exception
/// no longer hands its internal message to the caller.
/// </summary>
public sealed class McpSideEffectTests
{
    private static AnalyzerService Svc()
        => new(new DemoRiskDataSource(DemoData.Load(TestData.SeedPath())), new OfflineAi());

    private static JsonObject Call(string tool, int id = 1) => new()
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id,
        ["method"] = "tools/call",
        ["params"] = new JsonObject { ["name"] = tool, ["arguments"] = new JsonObject() },
    };

    // --- The side-effecting tool is declared, and off by default ------------

    [Fact]
    public async Task The_default_catalogue_is_genuinely_read_only()
    {
        var req = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = 1, ["method"] = "tools/list" };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        var tools = resp!["result"]!["tools"]!.AsArray();

        Assert.DoesNotContain(tools, t => t!["name"]!.GetValue<string>() == "send_exec_summary_email");
        // ...and every listed tool says so in its annotation, rather than leaving a caller to infer
        // read-only from the absence of a flag.
        Assert.All(tools, t => Assert.True(t!["annotations"]!["readOnlyHint"]!.GetValue<bool>()));
    }

    [Fact]
    public async Task Enabling_it_lists_it_and_marks_it_NOT_read_only()
    {
        var req = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = 1, ["method"] = "tools/list" };
        var resp = await McpServer.HandleAsync(req, Svc(), default, email: null, allowEmailSend: true);
        var tools = resp!["result"]!["tools"]!.AsArray();

        var email = Assert.Single(tools.Where(t => t!["name"]!.GetValue<string>() == "send_exec_summary_email"));
        Assert.False(email!["annotations"]!["readOnlyHint"]!.GetValue<bool>());
        Assert.Contains("SIDE EFFECT", email!["description"]!.GetValue<string>(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Calling_the_disabled_tool_by_name_is_REFUSED_not_merely_hidden()
    {
        // A client that already knows the name must not get through just because tools/list
        // stopped advertising it.
        var resp = await McpServer.HandleAsync(Call("send_exec_summary_email"), Svc(), default);
        Assert.NotNull(resp!["error"]);
        Assert.Contains("side effect", resp!["error"]!["message"]!.GetValue<string>(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Read_only_tools_are_unaffected_by_the_flag()
    {
        // The control: gating the one write tool must not narrow the read surface.
        var resp = await McpServer.HandleAsync(Call("exec_headline"), Svc(), default);
        Assert.Null(resp!["error"]);
    }

    // --- JSON-RPC notifications ---------------------------------------------

    [Fact]
    public async Task A_notification_gets_no_response_at_all()
    {
        // Every spec-compliant MCP client sends this immediately after initialize. The server used
        // to answer it with "Method not found" - a protocol violation, and the first thing such a
        // client sees.
        var note = new JsonObject { ["jsonrpc"] = "2.0", ["method"] = "notifications/initialized" };
        Assert.Null(await McpServer.HandleAsync(note, Svc(), default));
    }

    [Fact]
    public async Task A_notification_with_an_explicit_null_id_is_still_silent()
    {
        var note = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = null, ["method"] = "notifications/cancelled" };
        Assert.Null(await McpServer.HandleAsync(note, Svc(), default));
    }

    [Fact]
    public async Task A_request_with_an_id_still_gets_a_response()
    {
        // The control: silence must apply to notifications ONLY.
        var req = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = 7, ["method"] = "tools/list" };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.NotNull(resp);
        Assert.Equal(7, resp!["id"]!.GetValue<int>());
    }

    [Fact]
    public async Task An_unknown_METHOD_with_an_id_is_still_an_error()
    {
        var req = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = 8, ["method"] = "nonsense/method" };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.Equal(-32601, resp!["error"]!["code"]!.GetValue<int>());
    }

    // --- Internal exception text ---------------------------------------------

    [Fact]
    public async Task An_unexpected_exception_does_not_leak_its_message_to_the_caller()
    {
        // The data source throws with a message an internal stack would carry. The caller must get
        // a generic failure; the detail belongs in the server log.
        var svc = new AnalyzerService(new ThrowingSource("workspace=deadbeef;key=SECRET-VALUE"), new OfflineAi());
        var resp = await McpServer.HandleAsync(Call("exec_headline"), svc, default);

        var message = resp!["error"]!["message"]!.GetValue<string>();
        Assert.Equal(-32603, resp!["error"]!["code"]!.GetValue<int>());
        Assert.DoesNotContain("SECRET-VALUE", message);
        Assert.DoesNotContain("deadbeef", message);
        Assert.Contains("Internal error", message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_deliberate_caller_facing_error_is_still_returned_verbatim()
    {
        // The control: McpError messages are written FOR the caller (a rejected query, a bad
        // argument) and must not be flattened into "internal error".
        var req = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = 9,
            ["method"] = "tools/call",
            ["params"] = new JsonObject
            {
                ["name"] = "guarded_query",
                ["arguments"] = new JsonObject { ["kql"] = "SigninLogs | take 5" },
            },
        };
        var resp = await McpServer.HandleAsync(req, Svc(), default);
        Assert.Contains("guardrail", resp!["error"]!["message"]!.GetValue<string>(), StringComparison.OrdinalIgnoreCase);
    }

    private sealed class ThrowingSource : IRiskDataSource
    {
        private readonly string _secret;
        public ThrowingSource(string secret) => _secret = secret;
        public bool IsLive => true;
        public string SourceDescription => "throwing fake";
        public Task<RiskSnapshot> GetAllRowsAsync(CancellationToken ct = default) =>
            throw new InvalidOperationException("Connection failed: " + _secret);
        public Task<QueryResult> RunGuardedQueryAsync(string kql, CancellationToken ct = default) =>
            throw new InvalidOperationException("Connection failed: " + _secret);
    }
}

/// <summary>The same guarantees over the real HTTP endpoint, including the 204 a notification
/// must produce (serialising "null" with a 200 is not silence).</summary>
public sealed class McpEndpointTests : IClassFixture<SIAnalyzerAppFactory>
{
    private readonly SIAnalyzerAppFactory _factory;
    public McpEndpointTests(SIAnalyzerAppFactory factory) => _factory = factory;

    [Fact]
    public async Task A_notification_over_http_returns_no_content()
    {
        var resp = await _factory.CreateClient().PostAsJsonSafeAsync("/mcp",
            new { jsonrpc = "2.0", method = "notifications/initialized" });

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        Assert.Equal(0, (await resp.Content.ReadAsStringAsync()).Length);
    }

    [Fact]
    public async Task Calling_the_email_tool_over_http_is_refused_by_default()
    {
        var resp = await _factory.CreateClient().PostAsJsonSafeAsync("/mcp", new
        {
            jsonrpc = "2.0",
            id = 1,
            method = "tools/call",
            @params = new { name = "send_exec_summary_email", arguments = new { } },
        });
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("side effect", body, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>With the operator opt-in on, the tool is exposed again - the capability is gated, not
/// removed.</summary>
public sealed class McpEmailEnabledAppFactory : WebApplicationFactory<Program>
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.ConfigureHostConfiguration(cfg =>
        {
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SIAnalyzer:UseDemoData"] = "true",
                ["SIAnalyzer:Mcp:AllowEmailSend"] = "true",
            });
        });
        Environment.SetEnvironmentVariable("SIA_TEST_SEED", TestData.SeedPath());
        return base.CreateHost(builder);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            services.AddSingleton<IRiskDataSource>(_ => new DemoRiskDataSource(DemoData.Load(TestData.SeedPath())));
        });
    }
}

public sealed class McpEmailEnabledTests : IClassFixture<McpEmailEnabledAppFactory>
{
    private readonly McpEmailEnabledAppFactory _factory;
    public McpEmailEnabledTests(McpEmailEnabledAppFactory factory) => _factory = factory;

    [Fact]
    public async Task The_opt_in_exposes_the_tool_again()
    {
        var resp = await _factory.CreateClient().PostAsJsonSafeAsync("/mcp",
            new { jsonrpc = "2.0", id = 1, method = "tools/list" });
        var body = await resp.Content.ReadAsStringAsync();

        Assert.Contains("send_exec_summary_email", body);
        Assert.Contains("SIDE EFFECT", body);
    }
}

/// <summary>AI off, so nothing in these tests depends on a model being reachable.</summary>
internal sealed class OfflineAi : IAiNarrativeService
{
    public bool IsAvailable => false;
    public Task<NarrativeResult> SummarizeAsync(string instruction, IReadOnlyList<RiskRow> rows, Audience audience, DiffSummary? diff = null, CancellationToken ct = default)
        => Task.FromResult(new NarrativeResult(GroundedPrompt.TemplatedSummary(rows, audience, diff), false));
    public Task<string?> ComposeKqlAsync(string question, IReadOnlyList<string> allowedTables, CancellationToken ct = default)
        => Task.FromResult<string?>(null);
}
