using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// Audit #13 - security headers, the nonce-based CSP, and the forwarded-proto plumbing HSTS
/// depends on. Also pins audit #19's fix (no id interpolated into generated JS).
///
/// Re-verification found that two of #13's three asks were traps, and these tests encode why:
///   * UseHsts() emits NOTHING unless the request is seen as HTTPS. Behind Container Apps, which
///     terminates TLS, that is only true once ForwardedHeaders is wired - so "add UseHsts" alone
///     would have been another switch that exists and never fires.
///   * UseHttpsRedirection() would have looped forever for the same reason. It is deliberately
///     NOT in the app; the ingress refuses plain HTTP and Deploy-SIAnalyzer.ps1 asserts that.
/// </summary>
public sealed class SecurityHeadersTests : IClassFixture<SIAnalyzerAppFactory>
{
    private readonly SIAnalyzerAppFactory _factory;
    public SecurityHeadersTests(SIAnalyzerAppFactory factory) => _factory = factory;

    /// <summary>Every surface that renders HTML we serve.</summary>
    public static TheoryData<string> HtmlSurfaces() => new()
    {
        "/exec", "/analyst", "/governance", "/board", "/api/board",
    };

    private static string CspOf(HttpResponseMessage r) =>
        Assert.Single(r.Headers.GetValues("Content-Security-Policy"));

    private static string NonceFromCsp(string csp)
    {
        var m = Regex.Match(csp, @"'nonce-(?<n>[^']+)'");
        Assert.True(m.Success, $"CSP carries no nonce: {csp}");
        return m.Groups["n"].Value;
    }

    // --- A. the headers are actually emitted -----------------------------------

    [Theory]
    [MemberData(nameof(HtmlSurfaces))]
    public async Task Every_html_surface_carries_the_security_headers(string path)
    {
        var r = await _factory.CreateClient().GetAsync(path);
        r.EnsureSuccessStatusCode();

        Assert.Equal("nosniff", Assert.Single(r.Headers.GetValues("X-Content-Type-Options")));
        Assert.Equal("no-referrer", Assert.Single(r.Headers.GetValues("Referrer-Policy")));
        Assert.Equal("DENY", Assert.Single(r.Headers.GetValues("X-Frame-Options")));
        Assert.Equal("same-origin", Assert.Single(r.Headers.GetValues("Cross-Origin-Opener-Policy")));
        Assert.Contains("geolocation=()", Assert.Single(r.Headers.GetValues("Permissions-Policy")));
    }

    [Fact]
    public async Task Headers_are_present_on_a_denied_response_too()
    {
        // The gate returns 401 before any page renders. A response that carries no CSP is still a
        // response an attacker can frame or sniff, so the headers are emitted BEFORE the gate.
        using var gated = new GatedSIAnalyzerAppFactory();
        var r = await gated.CreateClient().GetAsync("/exec");

        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.Equal("nosniff", Assert.Single(r.Headers.GetValues("X-Content-Type-Options")));
        Assert.Contains("frame-ancestors 'none'", CspOf(r));
    }

    // --- B. the policy is strict, not decorative -------------------------------

    [Fact]
    public async Task Script_src_uses_a_nonce_and_never_unsafe_inline()
    {
        var csp = CspOf(await _factory.CreateClient().GetAsync("/exec"));

        var scriptSrc = Regex.Match(csp, @"script-src[^;]*").Value;
        Assert.Contains("'self'", scriptSrc);
        Assert.Contains("'nonce-", scriptSrc);
        // The whole point of the finding: 'unsafe-inline' would have been the one-line answer and
        // would still let injected script run.
        Assert.DoesNotContain("unsafe-inline", scriptSrc);
        Assert.DoesNotContain("unsafe-eval", scriptSrc);

        Assert.Contains("object-src 'none'", csp);
        Assert.Contains("base-uri 'self'", csp);
        Assert.Contains("form-action 'self'", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.Contains("default-src 'self'", csp);
    }

    [Fact]
    public async Task The_nonce_is_fresh_on_every_response()
    {
        // A reused nonce is worth no more than 'unsafe-inline' - an attacker who reads it once
        // can reuse it forever.
        var client = _factory.CreateClient();
        var first = NonceFromCsp(CspOf(await client.GetAsync("/exec")));
        var second = NonceFromCsp(CspOf(await client.GetAsync("/exec")));

        Assert.NotEqual(first, second);
        // 128 bits as hex -> 32 chars. Guards against a short or truncated nonce.
        Assert.Equal(32, first.Length);
        // Hex only. Base64 would emit '+' and '/', which HTML-encode to character references in the
        // attribute -- making the markup and the header differ textually and this suite flaky.
        Assert.Matches("^[0-9A-F]+$", first);
    }

    // --- C. header and markup agree (a mismatch = a blank page) ----------------

    [Theory]
    [MemberData(nameof(HtmlSurfaces))]
    public async Task Every_inline_script_carries_the_nonce_from_this_response(string path)
    {
        var r = await _factory.CreateClient().GetAsync(path);
        r.EnsureSuccessStatusCode();
        var html = await r.Content.ReadAsStringAsync();
        var nonce = NonceFromCsp(CspOf(r));

        var scriptTags = Regex.Matches(html, @"<script\b[^>]*>");
        Assert.NotEmpty(scriptTags);
        foreach (Match tag in scriptTags)
        {
            // If this ever fails, the browser silently drops the script and the page renders
            // dead - no error, no failing assertion anywhere else. That is why it is per-surface.
            Assert.Contains($"nonce=\"{nonce}\"", tag.Value);
        }
    }

    // --- D. the strict policy stays honest -------------------------------------

    /// <summary>Markup with every &lt;script&gt; BODY removed, so a handler assigned in JS
    /// (c.onclick = ...) is not confused with an inline on* ATTRIBUTE, which is the only form CSP
    /// blocks.</summary>
    private static string StripScriptBodies(string html) =>
        Regex.Replace(html, @"<script\b[^>]*>.*?</script>", "<script></script>",
                      RegexOptions.Singleline | RegexOptions.IgnoreCase);

    [Theory]
    [MemberData(nameof(HtmlSurfaces))]
    public async Task No_surface_ships_an_inline_event_handler(string path)
    {
        // THE pin for this finding. A nonce does not whitelist inline handlers - so the moment one
        // comes back, either the button is dead or someone "fixes" it with 'unsafe-inline' and the
        // CSP becomes decorative. Twelve of these were removed; none may return.
        var html = await _factory.CreateClient().GetStringAsync(path);
        var markup = StripScriptBodies(html);

        var handler = Regex.Match(markup, @"\son(click|change|submit|load|error|input|focus|blur|mouse\w+)\s*=",
                                  RegexOptions.IgnoreCase);
        Assert.False(handler.Success,
            $"{path} still has an inline handler attribute: '{handler.Value.Trim()}'");
    }

    [Fact]
    public async Task Prestaged_ids_travel_as_data_attributes_not_generated_code()
    {
        // Audit #19: this was onclick="runPrestaged('@a.Id')" - the id HTML-encoded but dropped
        // into a JS string literal. Now it is a data attribute, never parsed as code.
        var html = await _factory.CreateClient().GetStringAsync("/analyst");

        Assert.Contains("data-prestaged-id=", html);
        Assert.DoesNotContain("runPrestaged('", StripScriptBodies(html));
    }

    [Fact]
    public async Task The_governance_renew_button_carries_its_id_as_data()
    {
        var html = await _factory.CreateClient().GetStringAsync("/governance");
        // Same class of defect as #19, found during #13's sweep: onclick="renew('<id>')".
        Assert.DoesNotContain("onclick=\"renew(", html);
    }

    // --- E. HSTS only works because forwarded headers are wired ----------------

    [Fact]
    public async Task Hsts_is_absent_when_the_request_is_plain_http()
    {
        var r = await _factory.CreateClient().GetAsync("/exec");
        Assert.False(r.Headers.Contains("Strict-Transport-Security"),
            "HSTS must not be claimed on a connection that is not HTTPS.");
    }

    [Fact]
    public async Task Hsts_appears_once_the_proxy_says_the_request_was_https()
    {
        // This is the test that proves ForwardedHeaders is actually wired. Without it the app
        // sees plain HTTP forever and this header would never appear in production either.
        // Host is set away from localhost on purpose: HstsOptions.ExcludedHosts skips localhost
        // by default, which would mask the very thing under test.
        var req = new HttpRequestMessage(HttpMethod.Get, "/exec");
        req.Headers.Add("X-Forwarded-Proto", "https");
        req.Headers.Host = "sia.example.net";

        var r = await _factory.CreateClient().SendAsync(req);
        r.EnsureSuccessStatusCode();

        var hsts = Assert.Single(r.Headers.GetValues("Strict-Transport-Security"));
        Assert.Contains("max-age=", hsts);
    }

    [Fact]
    public async Task The_app_does_not_redirect_to_https_itself()
    {
        // Deliberate: behind TLS-terminating ingress, in-app redirection is an infinite loop.
        // Enforcement lives at the ingress (allowInsecure=false), asserted by the deploy script.
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var r = await client.GetAsync("/exec");

        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    // --- F. the standalone artifact is a different contract --------------------

    [Fact]
    public void A_standalone_artifact_carries_no_nonce()
    {
        // Correct, not an oversight: a downloaded/emailed HTML file is not served by us and no CSP
        // governs it. Stamping a nonce there would imply a policy that does not exist.
        var data = new SIAnalyzer.Web.Services.DemoRiskDataSource(
            SIAnalyzer.Core.DataAccess.DemoData.Load(TestData.SeedPath()));
        var vm = new SIAnalyzer.Web.Services.AnalyzerService(data, new OfflineAi())
            .GetExecAsync().GetAwaiter().GetResult();
        var html = SIAnalyzer.Web.Rendering.ExecHtmlRenderer.RenderStandalone(vm, "/*chartjs*/");

        Assert.DoesNotContain("nonce=", html);
        Assert.Contains("<script>", html);
    }
}
