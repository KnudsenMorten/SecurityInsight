using Sia.Core.Ai;
using Sia.Core.Configuration;
using Sia.Core.DataAccess;
using Sia.Core.Kql;
using Xunit;

namespace Sia.Tests;

/// <summary>Grounding contract + AI-optional fallback + default-workspace resolution.</summary>
public sealed class GroundingAndConfigTests
{
    [Fact]
    public void Grounded_prompt_carries_the_no_invention_contract_and_the_actual_rows()
    {
        var rows = SnapshotRows();
        var prompt = GroundedPrompt.BuildGrounded("Summarize.", rows, Audience.Management);
        Assert.Contains("Use ONLY the data rows below", prompt);
        Assert.Contains("Do not invent", prompt);
        Assert.Contains("Every claim must trace to a row", prompt);
        // The prompt must embed the real data (a known demo asset name) so the model is grounded.
        Assert.Contains("DEMO-DC-01", prompt);
    }

    [Fact]
    public void Management_tone_strips_jargon_analyst_tone_keeps_it()
    {
        var rows = SnapshotRows();
        Assert.Contains("non-technical leader", GroundedPrompt.BuildGrounded("x", rows, Audience.Management));
        Assert.Contains("security analyst", GroundedPrompt.BuildGrounded("x", rows, Audience.Analyst));
    }

    [Fact]
    public void NlToKql_prompt_states_the_read_only_contract_and_allow_list()
    {
        var prompt = GroundedPrompt.BuildNlToKql("show crown jewels", KqlGuardrail.AllowedTables);
        Assert.Contains("READ-ONLY ONLY", prompt);
        Assert.Contains("SI_Endpoint_Profile_CL", prompt);
        Assert.Contains("max(CollectionTime)", prompt);
    }

    [Fact]
    public void Templated_fallback_only_cites_supplied_rows_no_ungrounded_claims()
    {
        var rows = SnapshotRows();
        var text = GroundedPrompt.TemplatedSummary(rows, Audience.Management);
        // Every asset named in the summary must exist in the supplied rows (no invention).
        var known = rows.Select(r => r.ConfigurationName).ToHashSet();
        foreach (var line in text.Split('\n').Where(l => l.Contains("* ")))
        {
            Assert.Contains(known, k => line.Contains(k));
        }
        Assert.Contains("AI summary unavailable", text); // labelled as generated
    }

    [Fact]
    public void Empty_rows_fallback_is_safe()
    {
        var text = GroundedPrompt.TemplatedSummary(Array.Empty<Sia.Core.Model.RiskRow>(), Audience.Management);
        Assert.Contains("No findings", text);
    }

    // --- default-workspace = internal resolution ---------------------------

    [Fact]
    public void Configured_workspace_is_used_as_the_live_base()
    {
        var r = WorkspaceResolver.Resolve("00000000-0000-0000-0000-000000000000", forceDemo: false);
        Assert.True(r.IsLive);
        Assert.False(r.UseDemoData);
        Assert.Contains("base", r.Source);
    }

    [Fact]
    public void Explicit_demo_overrides_a_configured_workspace()
    {
        var r = WorkspaceResolver.Resolve("00000000-0000-0000-0000-000000000000", forceDemo: true);
        Assert.True(r.UseDemoData);
        Assert.False(r.IsLive);
    }

    [Fact]
    public void No_workspace_falls_back_to_demo_but_flags_the_gap()
    {
        var r = WorkspaceResolver.Resolve(null, forceDemo: false);
        Assert.True(r.UseDemoData);
        Assert.Contains("Set Sia:WorkspaceId", r.Source);
    }

    private static IReadOnlyList<Sia.Core.Model.RiskRow> SnapshotRows() =>
        SnapshotDiffLatest(DemoData.Load(TestData.SeedPath()));

    private static IReadOnlyList<Sia.Core.Model.RiskRow> SnapshotDiffLatest(IReadOnlyList<Sia.Core.Model.RiskRow> rows) =>
        Sia.Core.Analysis.SnapshotDiff.LatestSnapshot(rows);
}
