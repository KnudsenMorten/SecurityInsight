using SIAnalyzer.Core.Kql;
using Xunit;

namespace SIAnalyzer.Tests;

/// <summary>
/// AUDIT #6 - the KQL guardrail is a SOURCE WHITELIST, not a mention scan (TESTS.md §9.1).
///
/// Every string in <see cref="Bypasses"/> was verified ALLOWED against the pre-fix guardrail,
/// so each one is a regression test for a real bypass, not a hypothetical. The controls below
/// matter just as much: a gate that rejects everything would satisfy the first half alone.
/// </summary>
public sealed class KqlSourceWhitelistTests
{
    private const string Allowed = "SI_RiskAnalysis_Summary_CL";

    public static TheoryData<string> Bypasses() => new()
    {
        // The finding as reported: one allowed mention grounds the query, then union * reads
        // every table in the workspace.
        $"{Allowed} | union *",
        $"{Allowed} | union {Allowed}, *",
        $"{Allowed} | UNION *",
        $"{Allowed}\n| where CollectionTime > ago(1d)\n| union *",
        "union withsource=T *",
        "union SI_*",
        // A mention inside a comment or a string literal used to ground ANY query.
        $"// {Allowed}\nSigninLogs | take 5",
        $"let x = '{Allowed}'; SigninLogs | take 5",
        $"search \"admin\" // {Allowed}",
        $"find where * contains \"secret\" // {Allowed}",
        // Tables that are neither *_CL nor a known Defender name were invisible to the old
        // regex scan - neither allow-listed nor rejected.
        "SigninLogs | take 5",
        "SecurityEvent | summarize count()",
        $"{Allowed} | take 1; SecurityEvent | take 5",
        $"{Allowed} | join SigninLogs on ConfigurationId",
        $"{Allowed} | join kind=inner (SigninLogs | project x) on x",
        $"{Allowed} | union withsource=Src SI_Endpoint_Profile_CL, SigninLogs",
        $"{Allowed} | extend x = toscalar(SigninLogs | count)",
        "materialize(SigninLogs | take 5)",
        "union (SI_Endpoint_Profile_CL | take 1), (SigninLogs | take 1)",
        // Reach into a DIFFERENT workspace / application, or a table named at runtime. Only
        // cluster() and database() were banned before.
        $"workspace('other-ws').SigninLogs // {Allowed}",
        $"app('otherapp').requests // {Allowed}",
        $"table('SigninLogs') // {Allowed}",
        // A tabular let-function would smuggle a source past a source-position walk.
        "let f = (T:(*)) { T | count }; f(SigninLogs)",
        // Unscoped whole-workspace scans.
        $"search in (SigninLogs) \"x\" // {Allowed}",
    };

    [Theory]
    [MemberData(nameof(Bypasses))]
    public void Rejects_every_known_guardrail_bypass(string kql)
    {
        var r = KqlGuardrail.Check(kql);
        Assert.False(r.Allowed, "Guardrail ALLOWED a known bypass: " + kql);
    }

    /// <summary>The control half: the shapes a legitimate analyst or AI-composed query uses
    /// must still pass, or the gate above is just "reject everything".</summary>
    public static TheoryData<string> LegitimateShapes() => new()
    {
        "let _snap = toscalar(SI_RiskAnalysis_Summary_CL | summarize max(CollectionTime));\n"
            + "SI_RiskAnalysis_Summary_CL\n| where CollectionTime == _snap\n| take 10",
        "SI_Endpoint_Profile_CL | union SI_Identity_Profile_CL, SI_Azure_Profile_CL | take 10",
        "SI_RiskAnalysis_Summary_CL | join kind=leftanti (SI_Endpoint_Profile_CL | project ConfigurationId) on ConfigurationId",
        "ExposureGraphNodes | join ExposureGraphEdges on $left.NodeId == $right.SourceNodeId | take 5",
        "SI_RiskAnalysis_Summary_CL | summarize Total = sum(RiskScoreTotal), n = count() by bin(CollectionTime, 1d), CriticalityTierLevel",
        "SI_RiskAnalysis_Summary_CL | where SecuritySeverity in (\"Critical\",\"High\") | project-away RiskFactor_* | take 5",
        "SI_RiskAnalysis_Summary_CL | mv-expand parse_json(RiskFactor_Consequence_Detailed) | take 5",
        // 'search' bound to an allow-listed source searches only that table - still fine.
        "SI_RiskAnalysis_Summary_CL | search \"admin\"",
        // A banned word inside a string literal is data, not an operator.
        "SI_RiskAnalysis_Summary_CL | where ConfigurationName has \"union *\" | take 5",
        "SI_RiskAnalysis_Summary_CL | where ConfigurationName has \".drop\" | take 5",
    };

    [Theory]
    [MemberData(nameof(LegitimateShapes))]
    public void Allows_legitimate_query_shapes(string kql)
    {
        var r = KqlGuardrail.Check(kql);
        Assert.True(r.Allowed, "Guardrail BLOCKED a legitimate query: " + kql + " -- " + string.Join("; ", r.Reasons));
    }

    [Fact]
    public void Reports_only_source_tables_not_every_mention()
    {
        // CollectionTime, RiskScoreTotal and the commented table name are not sources.
        var r = KqlGuardrail.Check(
            "// SI_Endpoint_Profile_CL\n"
            + "let _snap = toscalar(SI_RiskAnalysis_Summary_CL | summarize max(CollectionTime));\n"
            + "SI_RiskAnalysis_Summary_CL | where CollectionTime == _snap | sort by RiskScoreTotal desc");
        Assert.True(r.Allowed, string.Join("; ", r.Reasons));
        Assert.Equal(new[] { "SI_RiskAnalysis_Summary_CL" }, r.Tables);
    }

    [Fact]
    public void Names_the_off_list_table_in_the_reason()
    {
        var r = KqlGuardrail.Check("SigninLogs | take 5");
        Assert.False(r.Allowed);
        Assert.Contains(r.Reasons, x => x.Contains("allow-list") && x.Contains("SigninLogs"));
    }

    [Fact]
    public void Every_allowed_table_is_usable_as_a_source()
    {
        // A table on the allow-list that the walker cannot recognise as a source would be a
        // silent outage of that surface, not a security hole - so assert both directions.
        foreach (var table in KqlGuardrail.AllowedTables)
        {
            var r = KqlGuardrail.Check($"{table} | take 5");
            Assert.True(r.Allowed, $"Allow-listed table {table} was rejected: {string.Join("; ", r.Reasons)}");
            Assert.Contains(table, r.Tables);
        }
    }
}
