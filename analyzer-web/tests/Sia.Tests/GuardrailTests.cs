using Sia.Core.Kql;
using Xunit;

namespace Sia.Tests;

/// <summary>The read-only KQL guardrail - ported behaviour from the PS POC's
/// Test-SiKqlReadOnly tests (TESTS.md §9.1). Proves it ALLOWS a clean snapshot
/// query and REJECTS every write / control / external / off-list / ungrounded form.</summary>
public sealed class GuardrailTests
{
    [Fact]
    public void Allows_a_clean_snapshot_correct_query()
    {
        var kql = KqlBuilders.SnapshotFilter("SI_Endpoint_Profile_CL") + "\n| take 10";
        var r = KqlGuardrail.Check(kql);
        Assert.True(r.Allowed, string.Join("; ", r.Reasons));
        Assert.Contains("SI_Endpoint_Profile_CL", r.Tables);
    }

    [Theory]
    [InlineData(".drop table SI_Endpoint_Profile_CL")]
    [InlineData(".set-or-append SI_Endpoint_Profile_CL <| SI_Endpoint_Profile_CL")]
    [InlineData(".create table Foo (a:string)")]
    [InlineData(".append SI_Endpoint_Profile_CL <| SI_Endpoint_Profile_CL")]
    [InlineData(".ingest inline into table SI_Endpoint_Profile_CL [1]")]
    [InlineData(".purge table SI_Endpoint_Profile_CL")]
    public void Rejects_control_and_write_commands(string kql)
    {
        var r = KqlGuardrail.Check(kql);
        Assert.False(r.Allowed);
    }

    [Theory]
    [InlineData("externaldata (x:string) [\"https://evil/x\"]")]
    [InlineData("SI_Endpoint_Profile_CL | where x == 1 into table Foo")]
    [InlineData("cluster('other').database('d').SI_Endpoint_Profile_CL")]
    [InlineData("database('other').SI_Endpoint_Profile_CL")]
    public void Rejects_external_and_cross_cluster_reach(string kql)
    {
        var r = KqlGuardrail.Check(kql);
        Assert.False(r.Allowed);
    }

    [Fact]
    public void Rejects_an_unrecognised_table_as_ungrounded()
    {
        // A non-_CL token that isn't a known table is not allow-list-matched; it is
        // rejected as ungrounded (matches the PS POC guardrail behaviour exactly).
        var r = KqlGuardrail.Check("SigninLogs | take 5");
        Assert.False(r.Allowed);
    }

    [Fact]
    public void Rejects_a_custom_CL_table_not_on_the_list_with_an_allow_list_reason()
    {
        var r = KqlGuardrail.Check("SomeOther_CL | take 5");
        Assert.False(r.Allowed);
        Assert.Contains(r.Reasons, x => x.Contains("allow-list"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Rejects_empty_query(string kql)
    {
        var r = KqlGuardrail.Check(kql);
        Assert.False(r.Allowed);
    }

    [Fact]
    public void Rejects_ungrounded_query_with_no_known_table()
    {
        var r = KqlGuardrail.Check("print x = 1");
        Assert.False(r.Allowed);
        Assert.Contains(r.Reasons, x => x.Contains("ungrounded"));
    }

    [Fact]
    public void Every_prestaged_analysis_passes_the_guardrail()
    {
        var failures = PrestagedLibrary.ValidateAll();
        Assert.True(failures.Count == 0, "Prestaged failures: " + string.Join(" | ", failures.Select(f => f.Id + ": " + string.Join(",", f.Reasons))));
    }

    [Fact]
    public void Ships_at_least_three_prestaged_analyses()
    {
        Assert.True(PrestagedLibrary.All.Count >= 3);
    }

    [Fact]
    public void Builders_are_snapshot_correct()
    {
        Assert.Contains("max(CollectionTime)", KqlBuilders.TopWorklist());
        Assert.Contains("max(CollectionTime)", KqlBuilders.SnapshotFilter("SI_Identity_Profile_CL"));
    }
}
