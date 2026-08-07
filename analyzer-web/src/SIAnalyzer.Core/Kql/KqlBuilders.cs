namespace SIAnalyzer.Core.Kql;

/// <summary>
/// Snapshot-correct KQL builders against the REAL SI engine schema. Every builder anchors
/// on the latest CollectionTime (the SI convention: compute max(CollectionTime) then
/// filter) so the analyst/exec always reads ONE coherent snapshot. Output is plain KQL
/// text; it is ALWAYS re-checked through <see cref="KqlGuardrail"/> before execution.
///
/// The SCORED rollup (worklist, timeline, exec) reads <c>SI_RiskAnalysis_Summary_CL</c> -
/// the RA engine output that actually carries RiskScoreTotal / SecuritySeverity /
/// CriticalityTierLevel / RiskFactor_*. The Profile_CL tables hold asset ATTRIBUTES only
/// (Tier, DisplayName, ...) and are used for attribute drill-downs via <see cref="SnapshotFilter"/>.
/// </summary>
public static class KqlBuilders
{
    private static readonly IReadOnlyDictionary<string, string> DomainTable = SiTables.DomainProfileTable;

    /// <summary>
    /// Two-phase latest-snapshot filter for one allowed table.
    ///
    /// AUDIT #18: the allow-list check was <c>AllowedTables.Contains(table)</c> over an
    /// <c>IReadOnlyList&lt;string&gt;</c> - ordinal and case-SENSITIVE - while the rest of the
    /// guardrail canonicalises with <c>OrdinalIgnoreCase</c> (see KqlGuardrail's source scan).
    /// Two things re-verification established, both worth recording:
    ///  * The inconsistency failed <b>CLOSED</b>. A differently-cased name was REJECTED, never let
    ///    through, so it could not be used to reach an off-list table.
    ///  * It was also unreachable: this method has <b>no production caller</b>, only tests.
    /// Real, but never live. Fixed anyway, because the next caller would have met it.
    ///
    /// The fix does more than swap the comparer: it emits the <b>canonical</b> spelling from the
    /// allow-list instead of whatever the caller passed. Log Analytics table names are
    /// case-sensitive, so accepting "si_endpoint_profile_cl" and then embedding it verbatim would
    /// build a query that clears the guardrail and then fails at the workspace - trading a clear
    /// rejection for a confusing runtime error.
    /// </summary>
    public static string SnapshotFilter(string table)
    {
        var canonical = KqlGuardrail.AllowedTables.FirstOrDefault(
            a => string.Equals(a, table, StringComparison.OrdinalIgnoreCase));
        if (canonical is null)
        {
            throw new ArgumentException($"SnapshotFilter: '{table}' is not an allowed table.", nameof(table));
        }
        return $"let _snap = toscalar({canonical} | summarize max(CollectionTime));\n{canonical}\n| where CollectionTime == _snap";
    }

    /// <summary>The canonical projection of the RA Summary columns the Analyzer maps.
    /// Surfaces the PLAIN-LANGUAGE RiskFactor_*_Detailed text (what humans read) plus the
    /// numeric score columns. Used by the worklist + the live data source rollup.</summary>
    public const string RaProjection =
        "| project SecurityDomain, ConfigurationName, ConfigurationId, CriticalityTier, " +
        "CriticalityTierLevel, SecuritySeverity, RiskScoreTotal, RiskScoreTotal_Weighted, " +
        "RiskFactor_Consequence_Detailed, RiskFactor_Probability_Detailed, " +
        "RiskFactor_Consequence, RiskFactor_Probability, CollectionTime";

    /// <summary>
    /// Top-N worklist (highest RiskScoreTotal, latest snapshot) over the RA Summary table.
    /// Optionally narrowed to one SecurityDomain (endpoint/identity/azure/publicip/crossengine).
    /// This is the SCORED finding list - the exec rollup + analyst worklist both read it.
    /// </summary>
    public static string TopWorklist(int top = 100, string domain = "all")
    {
        if (top < 1) top = 1;
        var t = SiTables.RiskAnalysisSummary;
        var domainFilter = string.Equals(domain, "all", StringComparison.OrdinalIgnoreCase)
            ? ""
            : $"| where SecurityDomain =~ \"{Escape(domain)}\"\n";

        return
            $"let _snap = toscalar({t} | summarize max(CollectionTime));\n" +
            $"{t}\n" +
            "| where CollectionTime == _snap\n" +
            domainFilter +
            RaProjection + "\n" +
            "| sort by RiskScoreTotal desc\n" +
            $"| take {top}";
    }

    /// <summary>
    /// Score timeline across snapshots: total RiskScoreTotal + finding-count per
    /// (CollectionTime, CriticalityTierLevel), from the RA Summary table. The management
    /// trend line. Anchored on CollectionTime (not TimeGenerated) so each point is exactly
    /// one engine run, matching the snapshot model.
    /// </summary>
    public static string ScoreTimeline(int lookbackDays = 180)
    {
        if (lookbackDays < 1) lookbackDays = 1;
        var t = SiTables.RiskAnalysisSummary;
        return
            $"{t}\n" +
            $"| where CollectionTime > ago({lookbackDays}d)\n" +
            "| summarize TotalScore = sum(RiskScoreTotal), FindingCount = count() by CollectionTime, CriticalityTierLevel\n" +
            "| sort by CollectionTime asc";
    }

    /// <summary>The full lookback rollup the live data source pulls: every RA Summary row
    /// across the lookback window (all snapshots) so the diff/timeline have history. NOT
    /// latest-only - the C# layer slices the latest snapshot for the headline.</summary>
    public static string RollupAllSnapshots(int lookbackDays, int take = 500000)
    {
        if (lookbackDays < 1) lookbackDays = 1;
        if (take < 1) take = 1;
        var t = SiTables.RiskAnalysisSummary;
        return
            $"{t}\n" +
            $"| where CollectionTime > ago({lookbackDays}d)\n" +
            RaProjection + "\n" +
            "| sort by CollectionTime desc, RiskScoreTotal desc\n" +
            $"| take {take}";
    }

    private static string Escape(string s) => (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
}
