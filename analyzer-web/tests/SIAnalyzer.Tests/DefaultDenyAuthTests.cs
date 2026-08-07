using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SIAnalyzer.Web.Auth;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// Audit #3 / #3a -- the DEFAULT-DENY authentication gate.
///
/// The defect these guard against: EasyAuth.RequireAuthenticated was called on exactly FOUR
/// endpoints, so every other API route and Razor page was anonymous - including
/// POST /api/query (arbitrary guardrailed KQL against the live workspace), GET /api/governance
/// (the exemption register with owner names) and POST /api/email/send. That state arose by
/// OMISSION, so the fix is a blanket gate: a new endpoint must be GATED unless explicitly
/// exempted, never the reverse.
///
/// Operator directive 2026-08-05: "authenticated by default, except if we provide dashboards to
/// internal audience", and "start with empty exemption list, i will add screens later".
/// </summary>
public class DefaultDenyAuthTests
{
    // --- the routes that were anonymous before the gate ------------------------
    public static TheoryData<string> PreviouslyAnonymousGets() => new()
    {
        "/api/exec", "/api/worklist", "/api/governance", "/api/board",
        "/api/remediation", "/api/maturity", "/api/glossary", "/api/coaching",
        "/exec", "/board", "/analyst", "/governance",
    };

    [Theory]
    [MemberData(nameof(PreviouslyAnonymousGets))]
    public async Task Anonymous_request_is_denied_on_every_previously_open_route(string path)
    {
        using var factory = new GatedSIAnalyzerAppFactory();
        var client = factory.CreateClient();

        var resp = await client.GetAsync(path);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Anonymous_POST_to_the_KQL_surface_is_denied()
    {
        // The sharpest one: arbitrary guardrailed KQL against the live workspace.
        using var factory = new GatedSIAnalyzerAppFactory();
        var client = factory.CreateClient();

        var resp = await client.PostAsJsonAsync("/api/query", new { kql = "SI_RiskAnalysis_Summary_CL | take 1" });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Anonymous_POST_to_email_send_is_denied()
    {
        // Takes no body, so a cross-site form POST reached it (audit #14).
        //
        // The status CHANGED when #14 landed, and deliberately: a body-less POST with no Origin and
        // no Sec-Fetch-Site is precisely the forgery shape, so the CSRF guard - which runs BEFORE
        // the auth gate, because a forged request from a signed-in victim WOULD be authenticated -
        // refuses it first. Still denied, and now for the stronger reason.
        using var factory = new GatedSIAnalyzerAppFactory();
        var client = factory.CreateClient();

        var resp = await client.PostAsync("/api/email/send", content: null);

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task The_auth_gate_still_covers_email_send_once_csrf_is_satisfied()
    {
        // The companion to the above, and the assertion the original test was really making.
        // A request that CLEARS the CSRF guard (a non-browser JSON caller) must still be refused by
        // the auth gate when it presents no principal - otherwise #14 would have quietly REPLACED
        // #3's coverage of this route instead of adding to it.
        using var factory = new GatedSIAnalyzerAppFactory();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/email/send")
        {
            Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json"),
        };

        var resp = await factory.CreateClient().SendAsync(req);

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Health_stays_open_so_probes_and_the_deploy_gate_still_work()
    {
        // ACA liveness probes and Deploy-SIAnalyzer.ps1's post-deploy health gate cannot
        // present a principal. Gating /health would break every deploy.
        using var factory = new GatedSIAnalyzerAppFactory();
        var client = factory.CreateClient();

        var resp = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task An_authenticated_principal_is_allowed_through()
    {
        // Control: the gate must DENY anonymous without also denying everyone -- otherwise
        // these tests would pass against an app that simply 401s unconditionally.
        using var factory = new GatedSIAnalyzerAppFactory();
        var client = factory.CreateClient();

        var req = new HttpRequestMessage(HttpMethod.Get, "/api/exec");
        req.Headers.Add(ClientPrincipal.HeaderName, AuthTests.EncodePrincipal());
        var resp = await client.SendAsync(req);

        Assert.NotEqual(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task The_exemption_list_is_EMPTY_by_default()
    {
        // Operator: "start with empty exemption list". A future edit that quietly seeds a
        // default dashboard route should fail here.
        var opts = new EasyAuthOptions();

        Assert.True(opts.RequireClientPrincipal, "the gate must default to ON (fail-closed)");
        Assert.Empty(opts.AnonymousPaths);
    }

    [Fact]
    public async Task A_configured_dashboard_route_is_served_anonymously()
    {
        // The info-screen exception: wall displays cannot sign in. Only routes named in
        // AnonymousPaths are anonymous, and only then.
        using var factory = new DashboardExemptAppFactory();
        var client = factory.CreateClient();

        var exempt = await client.GetAsync("/board");
        var stillGated = await client.GetAsync("/api/query");

        Assert.NotEqual(HttpStatusCode.Unauthorized, exempt.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, stillGated.StatusCode);
    }
}

/// <summary>Gate ON, plus "/board" exempted -- models an info screen the operator has opted in.</summary>
public sealed class DashboardExemptAppFactory : WebApplicationFactory<Program>
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.ConfigureHostConfiguration(cfg =>
        {
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SIAnalyzer:UseDemoData"] = "true",
                ["SIAnalyzer:Auth:RequireClientPrincipal"] = "true",
                ["SIAnalyzer:Auth:AnonymousPaths:0"] = "/board",
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
