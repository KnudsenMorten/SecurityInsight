using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SIAnalyzer.Core.Governance;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// Phase 6 governance (the ONLY sanctioned write path) + the CRITICAL no-auto-revoke rule:
/// every governance write/sync surface ships OFF by default; the PLATFORM-writing sync is
/// HARD-LOCKED off (a build can never ship an enable-able platform write) and is rendered in
/// the GUI VISIBLE but dimmed/disabled with a "disabled until tested" note. Local
/// risk-accept/exemption recording (SIA's own store, no platform written) is the allowed part
/// when opted in; reads (register/audit/accepted-state display) are always available.
/// </summary>
public sealed class GovernanceTests
{
    private static GovernanceStore Store(bool localOn, bool requestSync)
        => new(new GovernanceCapabilities { LocalRegisterEnabled = localOn, EnablePlatformSync = requestSync });

    // --- The hard lock (no-auto-revoke) -------------------------------------

    [Fact]
    public void Platform_sync_is_compile_time_locked_off()
    {
        // The constant guarantee: this build cannot ship an enable-able platform write.
        Assert.True(GovernanceCapabilities.PlatformSyncLocked);
    }

    [Fact]
    public void Config_cannot_enable_platform_sync_while_locked()
    {
        // Even with the operator REQUESTING sync on, the effective state stays off.
        var caps = new GovernanceCapabilities { LocalRegisterEnabled = true, EnablePlatformSync = true };
        Assert.False(caps.PlatformSyncEnabled);
        Assert.Contains("Disabled until tested", caps.PlatformSyncDisabledReason);
    }

    [Fact]
    public void Default_capabilities_are_all_off()
    {
        var caps = new GovernanceCapabilities();
        Assert.False(caps.LocalRegisterEnabled);
        Assert.False(caps.EnablePlatformSync);
        Assert.False(caps.PlatformSyncEnabled);
    }

    // --- Writes refused when off; local writes allowed when opted in --------

    [Fact]
    public void Register_is_read_only_until_opted_in()
    {
        var s = Store(localOn: false, requestSync: false);
        var r = s.AddRiskAcceptComment("f1", "host-a", "owner", "accepted for Q3");
        Assert.False(r.Accepted);
        Assert.Empty(s.Comments);
    }

    [Fact]
    public void Local_risk_accept_is_recorded_without_touching_a_platform()
    {
        var s = Store(localOn: true, requestSync: false);
        var r = s.AddRiskAcceptComment("f1", "host-a", "owner", "compensating control in place");
        Assert.True(r.Accepted);
        Assert.False(r.PlatformSynced);
        Assert.True(s.IsRiskAccepted("f1"));
    }

    [Fact]
    public void Risk_accept_requires_a_justification()
    {
        var s = Store(localOn: true, requestSync: false);
        Assert.False(s.AddRiskAcceptComment("f1", "host-a", "owner", "   ").Accepted);
    }

    [Fact]
    public void Exemption_records_locally_but_never_syncs_while_locked()
    {
        var s = Store(localOn: true, requestSync: true); // operator REQUESTED sync...
        var future = DateTimeOffset.UtcNow.AddMonths(3);
        var r = s.RecordExemption("f2", "host-b", "subscription-x", "owner", "vendor patch ETA Q4", future,
            new[] { GovernancePlatform.DefenderForCloud, GovernancePlatform.AzurePolicy, GovernancePlatform.DefenderXdr });
        Assert.True(r.Accepted);            // recorded locally
        Assert.False(r.PlatformSynced);     // ...but NOTHING suppressed on any platform (lock holds)
        Assert.Single(s.Exemptions);
        Assert.False(s.Exemptions[0].Synced);
        Assert.Contains("not", r.Detail, StringComparison.OrdinalIgnoreCase);
        // The audit trail records the skip honestly.
        Assert.Contains(s.Audit, a => a.Action == "exemption-sync-skipped");
        Assert.DoesNotContain(s.Audit, a => a.Action == "exemption-sync");
    }

    [Fact]
    public void Exemption_requires_a_future_expiry()
    {
        var s = Store(localOn: true, requestSync: false);
        var past = DateTimeOffset.UtcNow.AddDays(-1);
        Assert.False(s.RecordExemption("f3", "host-c", "scope", "owner", "reason", past, Array.Empty<GovernancePlatform>()).Accepted);
    }

    [Fact]
    public void Expiry_sweep_flips_past_due_records_and_renewal_extends()
    {
        var now = DateTimeOffset.UtcNow;
        var clock = now;
        var s = new GovernanceStore(new GovernanceCapabilities { LocalRegisterEnabled = true },
            new InMemoryGovernancePersistence(), () => clock);
        var rec = s.RecordExemption("f4", "host-d", "scope", "owner", "reason", now.AddDays(5), Array.Empty<GovernancePlatform>());
        Assert.True(rec.Accepted);

        clock = now.AddDays(10);                 // time passes beyond expiry
        Assert.Equal(1, s.SweepExpired());
        Assert.Equal(GovernanceState.Expired, s.Exemptions[0].State);

        var renew = s.RenewExemption(rec.RecordId!, clock.AddDays(30), "owner");
        Assert.True(renew.Accepted);
        Assert.Equal(GovernanceState.Renewed, s.Exemptions[0].State);
    }

    [Fact]
    public void Audit_trail_captures_who_what_when()
    {
        var s = Store(localOn: true, requestSync: false);
        s.AddRiskAcceptComment("f5", "host-e", "jane", "accepted");
        Assert.Contains(s.Audit, a => a.Actor == "jane" && a.Action == "risk-accept");
        Assert.All(s.Audit, a => Assert.True(a.TimestampUtc != default));
    }
}

/// <summary>The governance web surface: the page renders the register + audit + the
/// platform-sync control VISIBLE but DIMMED/disabled with the "disabled until tested" note,
/// and the write API refuses to sync to a platform while the lock holds.</summary>
public sealed class GovernanceWebTests : IClassFixture<SIAnalyzerAppFactory>
{
    private readonly SIAnalyzerAppFactory _factory;
    public GovernanceWebTests(SIAnalyzerAppFactory factory) => _factory = factory;

    [Fact]
    public async Task Governance_page_shows_the_sync_control_visible_but_disabled_until_tested()
    {
        var html = await _factory.CreateClient().GetStringAsync("/governance");
        // The control is VISIBLE (the heading + toggle render)...
        Assert.Contains("Sync exemptions to the security platforms", html);
        Assert.Contains("gov-toggle", html);
        // ...but DIMMED + DISABLED + carrying the "disabled until tested" note.
        Assert.Contains("gov-disabled", html);
        Assert.Contains("Disabled until tested", html);
        Assert.Contains("disabled", html);           // the toggle input is disabled
        // The three platform targets are named (Defender for Cloud / Azure Policy / Defender XDR).
        Assert.Contains("Defender for Cloud", html);
        Assert.Contains("Azure Policy", html);
        Assert.Contains("Defender XDR", html);
        // PIM-blue sibling chrome.
        Assert.Contains("#0969da", html);
        Assert.Contains("class=\"tabs\"", html);
    }

    [Fact]
    public async Task Governance_api_reports_platform_sync_locked_off()
    {
        var json = await _factory.CreateClient().GetStringAsync("/api/governance");
        Assert.Contains("\"platformSyncLocked\":true", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"platformSyncEnabled\":false", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Exemption_api_never_syncs_to_a_platform()
    {
        // Even requesting all three targets, the response must report platformSynced=false.
        var body = new
        {
            findingId = "f9",
            configurationName = "host-z",
            scope = "sub-1",
            reason = "vendor fix pending",
            expiry = DateTimeOffset.UtcNow.AddMonths(2),
            syncTargets = new[] { "DefenderForCloud", "AzurePolicy", "DefenderXdr" },
        };
        var resp = await _factory.CreateClient().PostAsJsonSafeAsync("/api/governance/exemption", body);
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var text = await resp.Content.ReadAsStringAsync();
        Assert.Contains("\"platformSynced\":false", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Governance_tab_is_in_the_exec_nav()
    {
        var html = await _factory.CreateClient().GetStringAsync("/exec");
        Assert.Contains(">Governance<", html);
        Assert.Contains("/governance", html);
    }
}

/// <summary>Boots the app with the governance LOCAL register enabled AND platform sync
/// REQUESTED on - to prove the hard lock still refuses every platform write end-to-end.</summary>
public sealed class GovernanceEnabledAppFactory : WebApplicationFactory<Program>
{
    protected override IHost CreateHost(IHostBuilder builder)
    {
        builder.ConfigureHostConfiguration(cfg =>
        {
            cfg.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SIAnalyzer:UseDemoData"] = "true",
                ["SIAnalyzer:Governance:LocalRegisterEnabled"] = "true",
                ["SIAnalyzer:Governance:EnablePlatformSync"] = "true", // requested - the lock must still win
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

/// <summary>The end-to-end proof that even with the operator REQUESTING platform sync, the
/// lock refuses every platform write (the no-auto-revoke guarantee in the live pipeline).</summary>
public sealed class GovernanceLockedEndToEndTests : IClassFixture<GovernanceEnabledAppFactory>
{
    private readonly GovernanceEnabledAppFactory _factory;
    public GovernanceLockedEndToEndTests(GovernanceEnabledAppFactory factory) => _factory = factory;

    [Fact]
    public async Task Sync_requested_in_config_still_does_not_write_a_platform()
    {
        var json = await _factory.CreateClient().GetStringAsync("/api/governance");
        Assert.Contains("\"platformSyncEnabled\":false", json, StringComparison.OrdinalIgnoreCase);

        var body = new
        {
            findingId = "fe",
            configurationName = "host-e2e",
            scope = "sub-2",
            reason = "still pending",
            expiry = DateTimeOffset.UtcNow.AddMonths(1),
            syncTargets = new[] { "DefenderForCloud" },
        };
        var resp = await _factory.CreateClient().PostAsJsonSafeAsync("/api/governance/exemption", body);
        var text = await resp.Content.ReadAsStringAsync();
        Assert.Contains("\"accepted\":true", text, StringComparison.OrdinalIgnoreCase);     // local record made
        Assert.Contains("\"platformSynced\":false", text, StringComparison.OrdinalIgnoreCase); // nothing suppressed
    }

    [Fact]
    public async Task Page_still_renders_the_sync_control_disabled_even_when_requested()
    {
        var html = await _factory.CreateClient().GetStringAsync("/governance");
        Assert.Contains("Disabled until tested", html);
        Assert.Contains("gov-disabled", html);
    }
}
