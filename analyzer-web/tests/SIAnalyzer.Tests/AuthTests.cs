using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SIAnalyzer.Web.Auth;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// Phase 3 - auth hardening. Two layers:
///  (1) the <see cref="ClientPrincipal"/> parser validates the Easy Auth
///      <c>X-MS-CLIENT-PRINCIPAL</c> header end-to-end (real principal vs garbage/empty);
///  (2) the in-app gate keeps <c>/mcp</c> behind the SAME authenticated principal as the UI
///      when <c>SIAnalyzer:Auth:RequireClientPrincipal</c> is on - allow (authenticated) + deny
///      (anonymous) paths, plus that the gate stays OFF by default (existing behaviour).
/// </summary>
public sealed class AuthTests
{
    // --- A. The X-MS-CLIENT-PRINCIPAL header parser (end-to-end validation) ---

    /// <summary>Build the base64 JSON value Easy Auth puts in X-MS-CLIENT-PRINCIPAL.</summary>
    internal static string EncodePrincipal(string name = "Exec User", string upn = "exec@example.com")
    {
        var payload = new
        {
            auth_typ = "aad",
            name_typ = "name",
            role_typ = "roles",
            claims = new[]
            {
                new { typ = "name", val = name },
                new { typ = "preferred_username", val = upn },
            },
        };
        var json = JsonSerializer.Serialize(payload);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    }

    [Fact]
    public void Parses_a_real_easy_auth_principal_header()
    {
        var p = ClientPrincipal.FromHeaderValue(EncodePrincipal("Jane Exec", "jane@example.com"));
        Assert.NotNull(p);
        Assert.True(p!.IsAuthenticated);
        Assert.Equal("aad", p.AuthenticationType);
        Assert.Equal("Jane Exec", p.Name);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-base64-$$$")]
    public void Treats_missing_or_garbage_header_as_anonymous(string? headerValue)
    {
        Assert.Null(ClientPrincipal.FromHeaderValue(headerValue));
    }

    [Fact]
    public void Treats_an_empty_principal_payload_as_anonymous()
    {
        // Valid base64 + JSON but no auth type / no claims => not an authenticated principal.
        var empty = Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"claims\":[]}"));
        Assert.Null(ClientPrincipal.FromHeaderValue(empty));
    }

    // --- B. The /mcp gate: allow (authenticated) + deny (anonymous) -----------

    [Fact]
    public async Task Mcp_is_open_when_the_gate_is_off_by_default()
    {
        // The default factory does NOT enable the gate => existing behaviour (open /mcp).
        using var factory = new SIAnalyzerAppFactory();
        var client = factory.CreateClient();
        var resp = await client.PostAsJsonSafeAsync("/mcp", new { jsonrpc = "2.0", id = 1, method = "tools/list" });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Mcp_denies_an_anonymous_call_when_the_gate_is_on()
    {
        using var factory = new GatedSIAnalyzerAppFactory();
        var client = factory.CreateClient();
        // No X-MS-CLIENT-PRINCIPAL => anonymous => 401, the MCP tool surface is never anonymous.
        var resp = await client.PostAsJsonSafeAsync("/mcp", new { jsonrpc = "2.0", id = 1, method = "tools/list" });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Mcp_allows_an_authenticated_call_when_the_gate_is_on()
    {
        using var factory = new GatedSIAnalyzerAppFactory();
        var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Post, "/mcp")
        {
            Content = new StringContent(
                JsonSerializer.Serialize(new { jsonrpc = "2.0", id = 1, method = "tools/list" }),
                Encoding.UTF8, "application/json"),
        };
        req.Headers.Add(ClientPrincipal.HeaderName, EncodePrincipal());
        var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("guarded_query", body); // the read-only catalogue came back
    }

    [Fact]
    public async Task Me_endpoint_reflects_the_authenticated_principal_when_the_gate_is_on()
    {
        using var factory = new GatedSIAnalyzerAppFactory();
        var client = factory.CreateClient();
        var req = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        req.Headers.Add(ClientPrincipal.HeaderName, EncodePrincipal("Cio Person", "cio@example.com"));
        var resp = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.Contains("Cio Person", body);
        Assert.Contains("\"authenticated\":true", body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Me_endpoint_denies_anonymous_when_the_gate_is_on()
    {
        using var factory = new GatedSIAnalyzerAppFactory();
        var client = factory.CreateClient();
        var resp = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }
}

/// <summary>Boots the app with demo data + AI-off AND the in-app Easy Auth gate ON
/// (SIAnalyzer:Auth:RequireClientPrincipal=true), so the deny/allow paths can be exercised.</summary>
public sealed class GatedSIAnalyzerAppFactory : WebApplicationFactory<Program>
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.ConfigureHostConfiguration(cfg =>
        {
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SIAnalyzer:UseDemoData"] = "true",
                ["SIAnalyzer:Auth:RequireClientPrincipal"] = "true",
            });
        });
        Environment.SetEnvironmentVariable("SIA_TEST_SEED", TestData.SeedPath());
        return base.CreateHost(builder);
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            services.AddSingleton<SIAnalyzer.Web.Services.IRiskDataSource>(_ =>
                new SIAnalyzer.Web.Services.DemoRiskDataSource(
                    SIAnalyzer.Core.DataAccess.DemoData.Load(TestData.SeedPath())));
        });
    }
}
