namespace Sia.Core.Model;

/// <summary>
/// One Risk-Analysis finding row, as produced by the SI RA engine and stored in
/// the SI_*_Profile_CL Log Analytics tables. This mirrors the shape the PowerShell
/// POC consumed (analyzer/seed/demo-snapshot.json + SiAnalyzer-Diff.ps1): identity
/// is <see cref="ConfigurationId"/>; the score is <see cref="RiskScoreTotal"/>;
/// snapshots are keyed by <see cref="CollectionTime"/>.
///
/// Read-only contract: these rows are READ from the workspace and never written
/// back (SI v2.2 invariant). The Analyzer only ever projects/aggregates them.
/// </summary>
public sealed record RiskRow
{
    /// <summary>Security domain: endpoint | identity | azure | publicip.</summary>
    public string SecurityDomain { get; init; } = "";

    /// <summary>Human-friendly asset/identity name (shown on the exec surface).</summary>
    public string ConfigurationName { get; init; } = "";

    /// <summary>Stable identity used for snapshot diffing (new/closed/open).</summary>
    public string ConfigurationId { get; init; } = "";

    /// <summary>Numeric tier 0..3 (0 = crown jewel). Always from SI_*_Profile_CL.Tier.</summary>
    public int CriticalityTier { get; init; }

    /// <summary>Plain-language tier label, e.g. "Critical - tier 0".</summary>
    public string CriticalityTierLevel { get; init; } = "";

    /// <summary>Critical | High | Medium | Low (CVSS-derived severity band).</summary>
    public string SecuritySeverity { get; init; } = "";

    /// <summary>The headline risk score; the rollup/timeline sum this.</summary>
    public double RiskScoreTotal { get; init; }

    /// <summary>CMDB-weighted variant (weighted layer only; never invents math).</summary>
    public double RiskScoreTotalWeighted { get; init; }

    /// <summary>
    /// Plain-language consequence driver ("why it matters"). In the real RA schema the
    /// human-readable text lives in the <c>RiskFactor_Consequence_Detailed</c> column
    /// (a semicolon-joined token list); the bare <c>RiskFactor_Consequence</c> column is
    /// a NUMERIC factor. The live mapper prefers the _Detailed text and only falls back
    /// to the numeric column when no text is present.
    /// </summary>
    public string RiskFactorConsequence { get; init; } = "";

    /// <summary>
    /// Plain-language probability driver ("how it gets exploited"). Sourced from
    /// <c>RiskFactor_Probability_Detailed</c> (text) with the numeric
    /// <c>RiskFactor_Probability</c> as fallback - see <see cref="RiskFactorConsequence"/>.
    /// </summary>
    public string RiskFactorProbability { get; init; } = "";

    /// <summary>Snapshot key. All rows of one engine run share an identical value.</summary>
    public DateTimeOffset CollectionTime { get; init; }
}
