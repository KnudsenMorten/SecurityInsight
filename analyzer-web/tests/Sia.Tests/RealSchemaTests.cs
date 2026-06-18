using Sia.Core.Kql;
using Sia.Core.Model;
using Xunit;

namespace Sia.Tests;

/// <summary>
/// Proves the Analyzer targets the REAL SI engine schema, not a guessed one:
///   * the SCORED rollup/worklist/timeline read SI_RiskAnalysis_Summary_CL (the RA output
///     that actually carries RiskScoreTotal / SecuritySeverity / CriticalityTierLevel /
///     RiskFactor_*), NOT the Profile_CL tables (which carry asset attributes only);
///   * every builder + prestaged query is latest-snapshot-correct and guardrail-clean;
///   * the RiskRowMapper prefers the plain-language RiskFactor_*_Detailed text over the
///     bare numeric RiskFactor_* factor (engine reality).
/// </summary>
public sealed class RealSchemaTests
{
    [Fact]
    public void RiskAnalysis_summary_table_is_on_the_allow_list()
    {
        Assert.Contains(SiTables.RiskAnalysisSummary, KqlGuardrail.AllowedTables);
        Assert.Contains(SiTables.RiskAnalysisDetailed, KqlGuardrail.AllowedTables);
        Assert.Equal("SI_RiskAnalysis_Summary_CL", SiTables.RiskAnalysisSummary);
    }

    [Fact]
    public void TopWorklist_reads_the_RA_summary_table_latest_snapshot()
    {
        var kql = KqlBuilders.TopWorklist(50);
        Assert.Contains(SiTables.RiskAnalysisSummary, kql);
        Assert.Contains("max(CollectionTime)", kql);
        Assert.Contains("RiskScoreTotal desc", kql);
        // It must NOT be sourcing scores from the attribute-only Profile tables.
        Assert.DoesNotContain("SI_Endpoint_Profile_CL", kql);
        Assert.True(KqlGuardrail.Check(kql).Allowed, string.Join("; ", KqlGuardrail.Check(kql).Reasons));
    }

    [Fact]
    public void TopWorklist_can_narrow_to_one_domain_inside_the_summary_table()
    {
        var kql = KqlBuilders.TopWorklist(50, "identity");
        Assert.Contains(SiTables.RiskAnalysisSummary, kql);
        Assert.Contains("SecurityDomain =~ \"identity\"", kql);
        Assert.True(KqlGuardrail.Check(kql).Allowed);
    }

    [Fact]
    public void ScoreTimeline_and_RollupAllSnapshots_read_the_RA_summary_table()
    {
        var timeline = KqlBuilders.ScoreTimeline(90);
        Assert.Contains(SiTables.RiskAnalysisSummary, timeline);
        Assert.Contains("sum(RiskScoreTotal)", timeline);
        Assert.Contains("by CollectionTime, CriticalityTierLevel", timeline);
        Assert.True(KqlGuardrail.Check(timeline).Allowed, string.Join("; ", KqlGuardrail.Check(timeline).Reasons));

        var rollup = KqlBuilders.RollupAllSnapshots(180);
        Assert.Contains(SiTables.RiskAnalysisSummary, rollup);
        Assert.Contains("ago(180d)", rollup);
        // Projects the plain-language driver columns so the live mapper can surface them.
        Assert.Contains("RiskFactor_Consequence_Detailed", rollup);
        Assert.Contains("RiskFactor_Probability_Detailed", rollup);
        Assert.True(KqlGuardrail.Check(rollup).Allowed, string.Join("; ", KqlGuardrail.Check(rollup).Reasons));
    }

    [Fact]
    public void Every_prestaged_query_targets_an_allow_listed_table_and_is_snapshot_correct()
    {
        foreach (var a in PrestagedLibrary.All)
        {
            var g = KqlGuardrail.Check(a.Kql);
            Assert.True(g.Allowed, $"{a.Id}: {string.Join("; ", g.Reasons)}");
            // Every referenced table is on the allow-list (guardrail already enforces this,
            // but assert at least one real SI table is present so none is empty/ungrounded).
            Assert.NotEmpty(g.Tables);
            Assert.All(g.Tables, t => Assert.Contains(t, KqlGuardrail.AllowedTables));
            Assert.Contains("max(CollectionTime)", a.Kql);
        }
    }

    [Fact]
    public void Scored_prestaged_analyses_source_from_the_RA_summary_table_not_profile_tables()
    {
        // The risk-scored prestaged analyses must read the RA Summary table (where the
        // scores live), never the attribute-only Profile_CL tables.
        foreach (var a in PrestagedLibrary.All)
        {
            Assert.Contains(SiTables.RiskAnalysisSummary, a.Kql);
            Assert.DoesNotContain("SI_Endpoint_Profile_CL", a.Kql);
            Assert.DoesNotContain("SI_Identity_Profile_CL", a.Kql);
        }
    }

    [Fact]
    public void Prestaged_text_filters_use_the_plain_language_Detailed_columns_only()
    {
        // The bare RiskFactor_Consequence / RiskFactor_Probability columns are NUMERIC in
        // the real schema; keyword matching must target the *_Detailed text columns. Assert
        // no prestaged query does a text `has`/`has_cs` against a bare (non-_Detailed) factor.
        foreach (var a in PrestagedLibrary.All)
        {
            Assert.DoesNotContain("RiskFactor_Probability has", a.Kql);
            Assert.DoesNotContain("RiskFactor_Consequence has", a.Kql);
        }
    }

    [Fact]
    public void Mapper_prefers_plain_language_Detailed_text_over_the_numeric_factor()
    {
        var cols = new[]
        {
            SiTables.Cols.ConfigurationName, SiTables.Cols.RiskScoreTotal,
            SiTables.Cols.RiskFactorConsequence, SiTables.Cols.RiskFactorConsequenceDetailed,
            SiTables.Cols.RiskFactorProbability, SiTables.Cols.RiskFactorProbabilityDetailed,
        };
        var cells = new object?[] { "DEMO-DC-01", 96.0, 2, "Domain controller; tier-0 takeover", 3, "Internet-exposed RDP + critical CVE" };
        var row = RiskRowMapper.FromCells(cols, cells);

        Assert.Equal("DEMO-DC-01", row.ConfigurationName);
        Assert.Equal(96.0, row.RiskScoreTotal);
        // Detailed text wins over the numeric factor (2 / 3).
        Assert.Equal("Domain controller; tier-0 takeover", row.RiskFactorConsequence);
        Assert.Equal("Internet-exposed RDP + critical CVE", row.RiskFactorProbability);
    }

    [Fact]
    public void Mapper_falls_back_to_a_nonzero_numeric_factor_when_no_detailed_text()
    {
        var cols = new[]
        {
            SiTables.Cols.ConfigurationName,
            SiTables.Cols.RiskFactorConsequence, SiTables.Cols.RiskFactorProbability,
        };
        // Consequence factor 4 (signal), probability 0 (noise -> blank, not "0").
        var cells = new object?[] { "svc-x", 4, 0 };
        var row = RiskRowMapper.FromCells(cols, cells);
        Assert.Equal("4", row.RiskFactorConsequence);
        Assert.Equal("", row.RiskFactorProbability);
    }

    [Fact]
    public void Mapper_parses_score_with_invariant_culture()
    {
        var cols = new[] { SiTables.Cols.ConfigurationName, SiTables.Cols.RiskScoreTotal, SiTables.Cols.CriticalityTier };
        var cells = new object?[] { "a", "78.5", "1" };
        var row = RiskRowMapper.FromCells(cols, cells);
        Assert.Equal(78.5, row.RiskScoreTotal);   // "." is the decimal point regardless of host locale
        Assert.Equal(1, row.CriticalityTier);
    }
}
