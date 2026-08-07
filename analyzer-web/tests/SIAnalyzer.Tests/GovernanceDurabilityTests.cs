using System.Net;
using Azure.Data.Tables;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SIAnalyzer.Core.Governance;
using SIAnalyzer.Web.Services;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// AUDIT #7 + #8 — the governance register is durable, active and actually consulted
/// (TESTS.md §9.2).
///
/// #7: the store held three <c>List&lt;&gt;</c>s in a singleton, so every risk-acceptance,
/// exemption and audit line died on restart and diverged per replica while the page presented
/// the result as a register of record. #8: <c>IsRiskAccepted</c> and <c>SweepExpired</c> had no
/// production callers, so recording a decision changed nothing anywhere and expiry never fired.
///
/// What is NOT provable here: that Azure Table Storage can be reached. These tests cover the
/// rules, the seam and the entity mapping offline; the live round-trip is the hosted gate.
/// </summary>
public sealed class GovernanceDurabilityTests
{
    private static GovernanceStore Store(IGovernancePersistence p, Func<DateTimeOffset>? now = null)
        => new(new GovernanceCapabilities { LocalRegisterEnabled = true }, p, now);

    // --- #7: the records outlive the store instance -------------------------

    [Fact]
    public void A_new_store_over_the_same_persistence_sees_the_existing_register()
    {
        // "Restart" = a brand-new GovernanceStore over the same backing store. Before #7 the
        // records lived IN the store instance, so this lost everything.
        var backing = new InMemoryGovernancePersistence();
        var before = Store(backing);
        before.AddRiskAcceptComment("f1", "host-a", "jane", "compensating control");
        before.RecordExemption("f2", "host-b", "sub-1", "jane", "vendor fix Q4",
            DateTimeOffset.UtcNow.AddMonths(3), Array.Empty<GovernancePlatform>());

        var after = Store(backing);
        Assert.Single(after.Comments);
        Assert.Single(after.Exemptions);
        Assert.True(after.IsRiskAccepted("f1"));
        Assert.True(after.IsExempt("f2"));
        Assert.Contains(after.Audit, a => a.Action == "risk-accept");
    }

    [Fact]
    public void Two_stores_on_one_persistence_see_the_same_register()
    {
        // The second half of #7: two replicas must not diverge. Each store reads through to
        // persistence rather than caching a working set of its own.
        var backing = new InMemoryGovernancePersistence();
        var replicaA = Store(backing);
        var replicaB = Store(backing);

        replicaA.AddRiskAcceptComment("f3", "host-c", "sam", "accepted for Q3");

        Assert.True(replicaB.IsRiskAccepted("f3"));
        Assert.Single(replicaB.Comments);
    }

    [Fact]
    public void Storage_mode_is_reported_honestly()
    {
        var volatileStore = Store(new InMemoryGovernancePersistence());
        Assert.False(volatileStore.StorageIsDurable);
        Assert.Contains("in-memory", volatileStore.StorageDescription, StringComparison.OrdinalIgnoreCase);
    }

    // --- #8: expiry decides suppression, not the sweep ----------------------

    [Fact]
    public void An_expired_risk_acceptance_stops_suppressing_even_if_the_sweep_never_runs()
    {
        // THE #8 bug: IsRiskAccepted only checked State != Expired, and nothing ever called
        // SweepExpired - so an expired acceptance suppressed a finding forever.
        var now = DateTimeOffset.UtcNow;
        var clock = now;
        var s = Store(new InMemoryGovernancePersistence(), () => clock);
        s.AddRiskAcceptComment("f4", "host-d", "jane", "temporary", now.AddDays(5));
        Assert.True(s.IsRiskAccepted("f4"));

        clock = now.AddDays(10);                 // past expiry; no sweep has run
        Assert.Equal(GovernanceState.Recorded, s.Comments[0].State);   // state NOT yet flipped
        Assert.False(s.IsRiskAccepted("f4"));                          // ...but it no longer suppresses
    }

    [Fact]
    public void An_expired_exemption_stops_suppressing_even_if_the_sweep_never_runs()
    {
        var now = DateTimeOffset.UtcNow;
        var clock = now;
        var s = Store(new InMemoryGovernancePersistence(), () => clock);
        s.RecordExemption("f5", "host-e", "sub", "jane", "vendor fix", now.AddDays(5), Array.Empty<GovernancePlatform>());
        Assert.True(s.IsExempt("f5"));

        clock = now.AddDays(10);
        Assert.False(s.IsExempt("f5"));
    }

    [Fact]
    public void A_risk_acceptance_with_no_expiry_does_not_lapse()
    {
        var now = DateTimeOffset.UtcNow;
        var clock = now;
        var s = Store(new InMemoryGovernancePersistence(), () => clock);
        s.AddRiskAcceptComment("f6", "host-f", "jane", "permanent by design");
        clock = now.AddYears(5);
        Assert.True(s.IsRiskAccepted("f6"));
    }

    [Fact]
    public void A_renewed_exemption_suppresses_again()
    {
        var now = DateTimeOffset.UtcNow;
        var clock = now;
        var s = Store(new InMemoryGovernancePersistence(), () => clock);
        var rec = s.RecordExemption("f7", "host-g", "sub", "jane", "reason", now.AddDays(5), Array.Empty<GovernancePlatform>());

        clock = now.AddDays(10);
        s.SweepExpired();
        Assert.False(s.IsExempt("f7"));

        Assert.True(s.RenewExemption(rec.RecordId!, clock.AddDays(30), "jane").Accepted);
        Assert.True(s.IsExempt("f7"));
    }

    [Fact]
    public void The_sweep_is_idempotent_so_two_replicas_racing_is_harmless()
    {
        var now = DateTimeOffset.UtcNow;
        var clock = now;
        var backing = new InMemoryGovernancePersistence();
        var a = Store(backing, () => clock);
        var b = Store(backing, () => clock);
        a.RecordExemption("f8", "host-h", "sub", "jane", "reason", now.AddDays(1), Array.Empty<GovernancePlatform>());

        clock = now.AddDays(2);
        Assert.Equal(1, a.SweepExpired());
        Assert.Equal(0, b.SweepExpired());     // nothing left to flip - not a double-write
    }

    [Fact]
    public void An_exemption_wins_over_a_risk_acceptance_in_the_finding_state()
    {
        var s = Store(new InMemoryGovernancePersistence());
        s.AddRiskAcceptComment("f9", "host-i", "jane", "accepted");
        s.RecordExemption("f9", "host-i", "sub", "sam", "exempted", DateTimeOffset.UtcNow.AddMonths(1), Array.Empty<GovernancePlatform>());

        var state = s.GetFindingState("f9");
        Assert.True(state.Exempt);
        Assert.False(state.RiskAccepted);
        Assert.Equal("Exempt", state.Label);
        Assert.Equal("sam", state.Owner);
    }

    [Fact]
    public void A_finding_with_no_record_reports_none()
    {
        var s = Store(new InMemoryGovernancePersistence());
        var state = s.GetFindingState("nothing-here");
        Assert.False(state.HasRecord);
        Assert.Equal("", state.Label);
    }

    [Fact]
    public void Batch_lookup_matches_the_single_lookup()
    {
        var s = Store(new InMemoryGovernancePersistence());
        s.AddRiskAcceptComment("a", "host-a", "jane", "why");
        s.RecordExemption("b", "host-b", "sub", "jane", "why", DateTimeOffset.UtcNow.AddMonths(1), Array.Empty<GovernancePlatform>());

        var batch = s.GetFindingStates(new[] { "a", "b", "c" });
        Assert.True(batch["a"].RiskAccepted);
        Assert.True(batch["b"].Exempt);
        Assert.False(batch.ContainsKey("c"));
        Assert.Equal(s.GetFindingState("a"), batch["a"]);
    }

    [Fact]
    public void A_risk_acceptance_cannot_be_recorded_already_expired()
    {
        var s = Store(new InMemoryGovernancePersistence());
        var r = s.AddRiskAcceptComment("f10", "host-j", "jane", "why", DateTimeOffset.UtcNow.AddDays(-1));
        Assert.False(r.Accepted);
        Assert.Empty(s.Comments);
    }
}

/// <summary>
/// The Azure Table mapping (audit #7). The Azure ROUND-TRIP cannot be tested offline, so the
/// part that can be — record → entity → record — is, because a silent mapping bug would lose
/// exactly the fields a register of record exists to keep (owner, reason, expiry, state).
/// </summary>
public sealed class GovernanceTableMappingTests
{
    [Fact]
    public void Risk_accept_comment_round_trips_through_a_table_entity()
    {
        var original = new RiskAcceptComment
        {
            Id = "rac-abc123",
            FindingId = "cfg-1",
            ConfigurationName = "host-a",
            Owner = "jane@example.com",
            Justification = "compensating control in place",
            CreatedUtc = new DateTimeOffset(2026, 8, 5, 10, 30, 0, TimeSpan.Zero),
            ExpiryUtc = new DateTimeOffset(2026, 11, 5, 0, 0, 0, TimeSpan.Zero),
            State = GovernanceState.Renewed,
        };

        var round = TableGovernancePersistence.ToComment(TableGovernancePersistence.ToEntity(original));
        Assert.Equal(original, round);
    }

    [Fact]
    public void A_risk_accept_comment_with_no_expiry_round_trips()
    {
        var original = new RiskAcceptComment
        {
            Id = "rac-noexp",
            FindingId = "cfg-2",
            ConfigurationName = "host-b",
            Owner = "sam",
            Justification = "permanent",
            CreatedUtc = new DateTimeOffset(2026, 8, 5, 0, 0, 0, TimeSpan.Zero),
            ExpiryUtc = null,
            State = GovernanceState.Recorded,
        };

        var round = TableGovernancePersistence.ToComment(TableGovernancePersistence.ToEntity(original));
        Assert.Null(round.ExpiryUtc);
        Assert.Equal(original, round);
    }

    [Fact]
    public void Exemption_round_trips_including_its_sync_targets()
    {
        var original = new ExemptionRecord
        {
            Id = "exm-xyz789",
            FindingId = "cfg-3",
            ConfigurationName = "host-c",
            Scope = "subscription-x",
            Owner = "jane",
            Reason = "vendor patch ETA Q4",
            CreatedUtc = new DateTimeOffset(2026, 8, 5, 9, 0, 0, TimeSpan.Zero),
            ExpiryUtc = new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero),
            State = GovernanceState.Recorded,
            SyncTargets = new[] { GovernancePlatform.DefenderForCloud, GovernancePlatform.DefenderXdr },
            Synced = false,
        };

        var round = TableGovernancePersistence.ToExemption(TableGovernancePersistence.ToEntity(original));
        Assert.Equal(original.SyncTargets, round.SyncTargets);
        // Compare the rest with the list member normalised: ExemptionRecord's generated equality
        // compares SyncTargets by REFERENCE (it is an IReadOnlyList), so an array and a List with
        // identical contents are "different" records. That is a property of the model, not a
        // mapping bug - the sequence itself is asserted above.
        var empty = Array.Empty<GovernancePlatform>();
        Assert.Equal(original with { SyncTargets = empty }, round with { SyncTargets = empty });
    }

    [Fact]
    public void Audit_entries_round_trip_and_sort_newest_first_by_row_key()
    {
        var older = new AuditEntry { TimestampUtc = new DateTimeOffset(2026, 8, 1, 0, 0, 0, TimeSpan.Zero), Actor = "jane", Action = "risk-accept", Detail = "d1" };
        var newer = older with { TimestampUtc = new DateTimeOffset(2026, 8, 5, 0, 0, 0, TimeSpan.Zero) };

        Assert.Equal(older, TableGovernancePersistence.ToAudit(TableGovernancePersistence.ToEntity(older)));

        // Reverse-ticks RowKey: ascending key order == newest first, which is how GetAudit
        // returns the trail without a sort.
        var keyOlder = TableGovernancePersistence.ToEntity(older).RowKey;
        var keyNewer = TableGovernancePersistence.ToEntity(newer).RowKey;
        Assert.True(string.CompareOrdinal(keyNewer, keyOlder) < 0);
    }

    [Fact]
    public void Two_audit_entries_in_the_same_tick_get_distinct_row_keys()
    {
        // An append-only trail that silently overwrote a colliding key would lose entries.
        var ts = new DateTimeOffset(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);
        var keys = Enumerable.Range(0, 50).Select(_ => TableGovernancePersistence.AuditRowKey(ts)).ToList();
        Assert.Equal(keys.Count, keys.Distinct().Count());
    }

    [Fact]
    public void Records_land_in_their_own_partitions()
    {
        var c = TableGovernancePersistence.ToEntity(new RiskAcceptComment
        {
            Id = "rac-1", FindingId = "f", ConfigurationName = "n", Owner = "o", Justification = "j",
        });
        var x = TableGovernancePersistence.ToEntity(new ExemptionRecord
        {
            Id = "exm-1", FindingId = "f", ConfigurationName = "n", Scope = "s", Owner = "o", Reason = "r",
            ExpiryUtc = DateTimeOffset.UtcNow.AddDays(1),
        });
        var a = TableGovernancePersistence.ToEntity(new AuditEntry
        {
            TimestampUtc = DateTimeOffset.UtcNow, Actor = "o", Action = "x", Detail = "d",
        });

        Assert.Equal(TableGovernancePersistence.RiskAcceptPartition, c.PartitionKey);
        Assert.Equal(TableGovernancePersistence.ExemptionPartition, x.PartitionKey);
        Assert.Equal(TableGovernancePersistence.AuditPartition, a.PartitionKey);
        Assert.Equal("rac-1", c.RowKey);          // the record id IS the row key
        Assert.Equal("exm-1", x.RowKey);
    }
}

/// <summary>
/// The write surface end to end: the register is ACTIVE by default (operator decision
/// 2026-08-05 — SIA is deployed nowhere, so there is no read-only deployment to protect), the
/// page offers the forms that used to be missing entirely, and the worklist REFLECTS a
/// risk-accepted finding instead of ignoring the register.
/// </summary>
public sealed class GovernanceActiveSurfaceTests : IClassFixture<SIAnalyzerAppFactory>
{
    private readonly SIAnalyzerAppFactory _factory;
    public GovernanceActiveSurfaceTests(SIAnalyzerAppFactory factory) => _factory = factory;

    [Fact]
    public void The_register_is_enabled_by_default_but_platform_sync_is_still_locked()
    {
        var opts = new GovernanceOptions();
        Assert.True(opts.LocalRegisterEnabled);                    // SIA's own store: ON
        Assert.False(opts.EnablePlatformSync);                     // the platform write: OFF
        Assert.False(opts.ToCapabilities().PlatformSyncEnabled);   // ...and locked, whatever config says
    }

    [Fact]
    public async Task The_page_offers_the_write_forms()
    {
        // Both write endpoints existed from the start and NOTHING in the app ever called them,
        // so the register could only ever be empty.
        var html = await _factory.CreateClient().GetStringAsync("/governance");
        Assert.Contains("Record a decision", html);
        Assert.Contains("recordAccept", html);
        Assert.Contains("recordExemption", html);
        Assert.Contains("Renew", html);
    }

    [Fact]
    public async Task The_page_states_where_the_register_lives()
    {
        // The test host has no table endpoint, so it must say plainly that this is not durable
        // rather than presenting a volatile list as a register of record.
        var html = await _factory.CreateClient().GetStringAsync("/governance");
        Assert.Contains("NOT a register of record", html);
        Assert.Contains("in-memory", html);
    }

    [Fact]
    public async Task The_api_reports_the_storage_mode()
    {
        var json = await _factory.CreateClient().GetStringAsync("/api/governance");
        Assert.Contains("\"durable\":false", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task The_worklist_carries_the_governance_state_of_each_finding()
    {
        var json = await _factory.CreateClient().GetStringAsync("/api/worklist?top=5");
        Assert.Contains("\"finding\"", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("\"governance\"", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Recording_a_risk_acceptance_changes_what_the_worklist_says()
    {
        // THE #8 regression test: before this, recording a decision changed no view anywhere.
        var client = _factory.CreateClient();
        var first = await client.GetFromJsonSafeAsync<List<GovernedRowDto>>("/api/worklist?top=1");
        var target = Assert.Single(first!);
        Assert.False(target.Governance.RiskAccepted);

        var resp = await client.PostAsJsonSafeAsync("/api/governance/risk-accept", new
        {
            findingId = target.Finding.ConfigurationId,
            configurationName = target.Finding.ConfigurationName,
            justification = "accepted by the test",
        });
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);

        var after = await client.GetFromJsonSafeAsync<List<GovernedRowDto>>("/api/worklist?top=1");
        Assert.True(after!.Single().Governance.RiskAccepted);
        Assert.Equal("accepted by the test", after.Single().Governance.Reason);
    }

    public sealed record GovernedRowDto(FindingDto Finding, GovernanceDto Governance);
    public sealed record FindingDto(string ConfigurationId, string ConfigurationName);
    public sealed record GovernanceDto(bool RiskAccepted, bool Exempt, string? Owner, string? Reason);
}
