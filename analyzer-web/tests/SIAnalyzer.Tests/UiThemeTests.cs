using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// Phase 5 (mobile / a11y) + Phase 6 (PIM-blue restyle). Verifies the exec, board and
/// analyst surfaces share the PIM-Manager-matched chrome (blue #0969da scheme, brand bar +
/// tab menu), are mobile-ready (viewport meta, no fixed page widths that overflow, scrollable
/// tables) and pass accessibility basics (semantic landmarks, aria-current, a visible focus
/// ring). These are offline render checks; the hosted run is still the release gate.
/// </summary>
public sealed class UiThemeTests : IClassFixture<SIAnalyzerAppFactory>
{
    private readonly SIAnalyzerAppFactory _factory;
    public UiThemeTests(SIAnalyzerAppFactory factory) => _factory = factory;

    [Fact]
    public async Task Exec_uses_the_pim_blue_scheme_and_brandbar_nav()
    {
        var html = await _factory.CreateClient().GetStringAsync("/exec");
        // PIM Manager primary blue.
        Assert.Contains("#0969da", html);
        // PIM-style chrome: blue brand bar + a tab strip menu (sibling of the Manager).
        Assert.Contains("class=\"brandbar\"", html);
        Assert.Contains("class=\"tabs\"", html);
        Assert.Contains(">Executive<", html);
        Assert.Contains(">Board deck<", html);
        Assert.Contains(">Analyst<", html);
        // The dark POC theme is gone.
        Assert.DoesNotContain("#0f1623", html);
    }

    [Fact]
    public async Task Exec_is_mobile_ready_and_accessible()
    {
        var html = await _factory.CreateClient().GetStringAsync("/exec");
        // Mobile: responsive viewport + a small-screen breakpoint (~360-420px) + no fixed
        // max-width that overflows a phone (the wrap is centered/auto, not a fixed px width).
        Assert.Contains("width=device-width", html);
        Assert.Contains("max-width:420px", html);
        Assert.Contains("max-width:100%", html);      // canvases/dial never overflow the viewport
        // a11y: landmarks, the active tab is marked, and there is a visible focus ring.
        Assert.Contains("role=\"banner\"", html);
        Assert.Contains("role=\"main\"", html);
        Assert.Contains("aria-current=\"page\"", html);
        Assert.Contains(":focus-visible", html);
    }

    [Fact]
    public async Task Analyst_shares_the_pim_blue_chrome()
    {
        var html = await _factory.CreateClient().GetStringAsync("/analyst");
        Assert.Contains("#0969da", html);
        Assert.Contains("class=\"brandbar\"", html);
        Assert.Contains("class=\"tabs\"", html);
        Assert.Contains("aria-current=\"page\"", html); // Analyst tab marked active
        Assert.DoesNotContain("#0f1623", html);          // old dark theme gone
    }
}
