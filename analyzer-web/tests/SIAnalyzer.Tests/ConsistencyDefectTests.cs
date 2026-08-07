using SIAnalyzer.Core.Governance;
using SIAnalyzer.Core.Kql;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// Audit #18 - two "small consistency defects". Re-verification split them apart: one is worse than
/// Low, the other was never reachable.
///
///  * <b>The id truncation is NOT cosmetic.</b> The id becomes the Azure Table RowKey and records
///    are written with UpsertEntity(..., TableUpdateMode.Replace), so a collision does not error -
///    it SILENTLY REPLACES an existing risk-acceptance or exemption. That only became true when
///    audit #7 made the register durable, which is why the original Low rating has aged badly.
///  * <b>The case-sensitivity failed CLOSED and was unreachable.</b> A differently-cased table name
///    was rejected, never let through, and KqlBuilders.SnapshotFilter has no production caller -
///    only tests. Real defect, never live. Fixed because the next caller would have met it.
/// </summary>
public class ConsistencyDefectTests
{
    // --- A. governance ids are wide enough to be a key -------------------------

    private static GovernanceStore NewStore() =>
        new(new GovernanceCapabilities { LocalRegisterEnabled = true }, new InMemoryGovernancePersistence());

    [Fact]
    public void A_risk_acceptance_id_keeps_the_whole_guid()
    {
        var store = NewStore();
        store.AddRiskAcceptComment("cfg-1", "ASSET-1", "tester", "because");

        var id = Assert.Single(store.Comments).Id;

        // "rac-" + 32 hex. The defect was Substring(0,16): 4-char prefix + only 12 hex chars.
        Assert.StartsWith("rac-", id);
        Assert.Equal(36, id.Length);
        Assert.Matches("^rac-[0-9a-f]{32}$", id);
    }

    [Fact]
    public void An_exemption_id_keeps_the_whole_guid()
    {
        var store = NewStore();
        store.RecordExemption("cfg-2", "ASSET-2", "subscription", "tester", "why",
                              DateTimeOffset.UtcNow.AddDays(30), new List<GovernancePlatform>());

        var id = Assert.Single(store.Exemptions).Id;

        Assert.Matches("^exm-[0-9a-f]{32}$", id);
    }

    [Fact]
    public void Ids_are_unique_across_many_records()
    {
        // 48 bits made a collision remote but not impossible, and the consequence was a SILENT
        // overwrite of a governance decision. This is the property that matters, stated directly.
        var store = NewStore();
        for (var i = 0; i < 500; i++)
            store.AddRiskAcceptComment($"cfg-{i}", $"ASSET-{i}", "tester", "because");

        var ids = store.Comments.Select(c => c.Id).ToList();
        Assert.Equal(500, ids.Count);
        Assert.Equal(ids.Count, ids.Distinct().Count());
    }

    [Fact]
    public void Existing_short_ids_still_resolve()
    {
        // Widening must not orphan records already in the durable table. Ids are only ever compared
        // for equality, so a legacy 16-char id must still be found by renew.
        var persistence = new InMemoryGovernancePersistence();
        var legacy = new ExemptionRecord
        {
            Id = "exm-0123456789ab",           // the OLD 16-char shape
            FindingId = "cfg-legacy",
            ConfigurationName = "LEGACY",
            Scope = "subscription",
            Owner = "tester",
            Reason = "pre-existing",
            ExpiryUtc = DateTimeOffset.UtcNow.AddDays(10),
            State = GovernanceState.Recorded,
        };
        persistence.UpsertExemption(legacy);
        var store = new GovernanceStore(new GovernanceCapabilities { LocalRegisterEnabled = true }, persistence);

        var result = store.RenewExemption("exm-0123456789ab", DateTimeOffset.UtcNow.AddDays(90), "tester");

        Assert.True(result.Accepted);
    }

    // --- B. the guardrail's allow-list check is consistent ---------------------

    [Fact]
    public void The_snapshot_filter_accepts_the_canonical_name()
    {
        var kql = KqlBuilders.SnapshotFilter("SI_Endpoint_Profile_CL");
        Assert.Contains("SI_Endpoint_Profile_CL", kql);
        Assert.Contains("max(CollectionTime)", kql);
    }

    [Theory]
    [InlineData("si_endpoint_profile_cl")]
    [InlineData("SI_ENDPOINT_PROFILE_CL")]
    [InlineData("Si_Endpoint_Profile_Cl")]
    public void Table_matching_is_case_insensitive_like_the_rest_of_the_guardrail(string spelling)
    {
        var kql = KqlBuilders.SnapshotFilter(spelling);

        // AND it emits the CANONICAL spelling, not the caller's. Log Analytics table names are
        // case-sensitive, so echoing the input back would build a query that clears the guardrail
        // and then fails at the workspace.
        Assert.Contains("SI_Endpoint_Profile_CL", kql);
        Assert.DoesNotContain(spelling, kql, StringComparison.Ordinal);
    }

    [Fact]
    public void An_off_list_table_is_still_refused_whatever_its_case()
    {
        // The control: relaxing the comparer must not relax the allow-list itself.
        Assert.Throws<ArgumentException>(() => KqlBuilders.SnapshotFilter("SigninLogs"));
        Assert.Throws<ArgumentException>(() => KqlBuilders.SnapshotFilter("signinlogs"));
        Assert.Throws<ArgumentException>(() => KqlBuilders.SnapshotFilter("SI_Endpoint_Profile_CL_Evil"));
    }
}
