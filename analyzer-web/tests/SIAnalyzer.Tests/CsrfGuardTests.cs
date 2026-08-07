using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using SIAnalyzer.Web.Security;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// Audit #14 - CSRF on the state-changing endpoints, above all <c>POST /api/email/send</c>, which
/// takes no body and so is reachable by a plain cross-site HTML form.
///
/// Re-verification settled the question the audit left open ("how much does #3's default-deny
/// absorb?"): NOTHING. Easy Auth sits in front of the container, so a signed-in victim's browser
/// carries the platform session cookie, the platform authenticates the forged POST and injects
/// X-MS-CLIENT-PRINCIPAL, and the gate passes it. #13's form-action 'self' does not help either -
/// that constrains our pages, not the attacker's.
/// </summary>
public class CsrfGuardTests
{
    private static HttpRequest Req(string method, string? origin = null, string? secFetchSite = null,
                                   string? contentType = null, string scheme = "https",
                                   string host = "sia.example.net", bool explicitHeader = false)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Scheme = scheme;
        ctx.Request.Host = new HostString(host);
        if (origin is not null) ctx.Request.Headers.Origin = origin;
        if (secFetchSite is not null) ctx.Request.Headers["Sec-Fetch-Site"] = secFetchSite;
        if (contentType is not null) ctx.Request.ContentType = contentType;
        if (explicitHeader) ctx.Request.Headers[CsrfGuard.RequestHeader] = "1";
        return ctx.Request;
    }

    // --- A. the decision table -------------------------------------------------

    [Theory]
    [InlineData("GET")]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    public void Safe_methods_are_never_blocked(string method)
    {
        Assert.True(CsrfGuard.IsAllowed(Req(method), out _));
    }

    [Fact]
    public void A_cross_site_form_post_is_rejected()
    {
        // THE finding: <form method="post" action="https://sia.../api/email/send"> on evil.com.
        var req = Req("POST", origin: "https://evil.example",
                      contentType: "application/x-www-form-urlencoded");
        Assert.False(CsrfGuard.IsAllowed(req, out var why));
        Assert.Contains("evil.example", why);
    }

    [Fact]
    public void A_body_less_cross_site_post_is_rejected()
    {
        // /api/email/send binds no body, so a form needs to send nothing at all.
        Assert.False(CsrfGuard.IsAllowed(Req("POST", origin: "https://evil.example"), out _));
    }

    [Fact]
    public void Our_own_pages_are_allowed()
    {
        var req = Req("POST", origin: "https://sia.example.net", contentType: "application/json");
        Assert.True(CsrfGuard.IsAllowed(req, out var why));
        Assert.Equal("same origin", why);
    }

    [Theory]
    [InlineData("cross-site", false)]
    [InlineData("same-site", false)]   // a sibling subdomain is not us
    [InlineData("same-origin", true)]
    [InlineData("none", true)]         // typed in the address bar
    public void Sec_fetch_site_decides_when_there_is_no_origin(string site, bool allowed)
    {
        Assert.Equal(allowed, CsrfGuard.IsAllowed(Req("POST", secFetchSite: site), out _));
    }

    [Fact]
    public void A_non_browser_client_sending_json_is_allowed()
    {
        // An MCP agent or curl: no Origin, no Sec-Fetch-Site. An HTML form can never send this
        // content type, so it is not a forgery vector.
        Assert.True(CsrfGuard.IsAllowed(Req("POST", contentType: "application/json"), out _));
        Assert.True(CsrfGuard.IsAllowed(Req("POST", contentType: "application/json; charset=utf-8"), out _));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("application/x-www-form-urlencoded")]
    [InlineData("multipart/form-data; boundary=x")]
    [InlineData("text/plain")]
    public void A_signal_less_form_submittable_post_is_rejected(string? contentType)
    {
        // These four are exactly what an HTML form can produce. Everything else needs script,
        // which cannot reach us cross-origin without a CORS preflight we never answer.
        Assert.False(CsrfGuard.IsAllowed(Req("POST", contentType: contentType), out _));
    }

    [Fact]
    public void A_non_browser_client_can_opt_in_with_the_explicit_header()
    {
        Assert.True(CsrfGuard.IsAllowed(Req("POST", explicitHeader: true), out _));
    }

    // --- B. the interlock with audit #13 --------------------------------------

    [Fact]
    public void Origin_matching_depends_on_the_forwarded_scheme()
    {
        // Behind TLS-terminating ingress the browser sends Origin: https://host. If the app still
        // believed it was serving http (i.e. UseForwardedHeaders from #13 removed), this comparison
        // would fail and EVERY same-origin POST would be rejected - the app would look broken.
        var withoutForwarding = Req("POST", origin: "https://sia.example.net", scheme: "http");
        Assert.False(CsrfGuard.IsAllowed(withoutForwarding, out var why));
        Assert.Contains("http://sia.example.net", why);

        var withForwarding = Req("POST", origin: "https://sia.example.net", scheme: "https");
        Assert.True(CsrfGuard.IsAllowed(withForwarding, out _));
    }

    // --- C. end to end --------------------------------------------------------

    [Fact]
    public async Task Cross_site_post_to_email_send_is_refused_over_http()
    {
        using var factory = new SIAnalyzerAppFactory();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/email/send");
        req.Headers.Add("Origin", "https://evil.example");

        var r = await factory.CreateClient().SendAsync(req);

        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        Assert.Contains("Cross-site request rejected", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task The_guard_runs_before_the_auth_gate()
    {
        // A forged request must never reach the code that sends mail, and the response should say
        // what was actually wrong. If auth ran first this would be a 401.
        using var gated = new GatedSIAnalyzerAppFactory();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/email/send");
        req.Headers.Add("Origin", "https://evil.example");

        var r = await gated.CreateClient().SendAsync(req);

        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
    }

    [Fact]
    public async Task The_mcp_endpoint_still_works_for_an_agent()
    {
        // MCP clients are not browsers and send JSON. Breaking them would trade one finding for
        // another (#11 declared this surface supported).
        using var factory = new SIAnalyzerAppFactory();
        var body = new StringContent("""{"jsonrpc":"2.0","id":1,"method":"tools/list"}""",
                                     Encoding.UTF8, "application/json");

        var r = await factory.CreateClient().PostAsync("/mcp", body);

        Assert.NotEqual(HttpStatusCode.Forbidden, r.StatusCode);
    }

    [Fact]
    public async Task The_ui_json_posts_still_work()
    {
        using var factory = new SIAnalyzerAppFactory();
        var req = new HttpRequestMessage(HttpMethod.Post, "/api/query")
        {
            Content = new StringContent("""{"kql":"SI_Endpoint_Profile_CL | take 1","audience":"analyst"}""",
                                        Encoding.UTF8, "application/json"),
        };
        req.Headers.Add("Origin", "http://localhost");

        var r = await factory.CreateClient().SendAsync(req);

        Assert.NotEqual(HttpStatusCode.Forbidden, r.StatusCode);
    }
}
