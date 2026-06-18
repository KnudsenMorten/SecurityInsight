namespace Sia.Core.Kql;

/// <summary>
/// Single source of truth for the REAL SecurityInsight Log Analytics table + column
/// names the Analyzer reads. Grounded in the live SI engine output schema, NOT guessed:
///
///   * Risk-Analysis output (the SCORED findings) -> SI_RiskAnalysis_Summary_CL
///     (and the per-asset SI_RiskAnalysis_Detailed_CL). These carry the columns the
///     exec rollup needs: RiskScoreTotal, RiskScoreTotal_Weighted, SecuritySeverity,
///     CriticalityTier (int), CriticalityTierLevel (text), SecurityDomain, Category,
///     Subcategory, ConfigurationName, ConfigurationId, the RiskFactor_* columns,
///     and the engine-stamped CollectionTime / SolutionVersion / TraceID.
///     Source: engine/risk-analysis/Invoke-RiskAnalysis.ps1 (table-name + DCR config
///     around line 8057, column shaping ~7781) and the RA report YAML projections.
///
///   * Asset profiling output (asset ATTRIBUTES) -> SI_{Endpoint|Identity|Azure|PublicIP}_Profile_CL.
///     One flat row per asset per snapshot. These carry Tier (NOT "CriticalityTier"),
///     DisplayName, Hostname/Upn, AssetName, and the per-asset signal columns - but they
///     do NOT contain RiskScoreTotal (that is computed downstream by the RA engine).
///     Source: docs/DESIGN.md "table column names are UNPREFIXED" + the profile schema.
///
/// IMPORTANT - the RiskFactor_* duality (engine reality, see DESIGN.md scoring contract):
///   * RiskFactor_Consequence  / RiskFactor_Probability  are NUMERIC factors
///     (consAdj = consBase + RiskFactor_Consequence; RiskScoreTotal = consAdj * probAdj).
///   * RiskFactor_Consequence_Detailed / RiskFactor_Probability_Detailed are the
///     PLAIN-LANGUAGE semicolon-joined driver lists ("why it matters" / "how it gets
///     exploited"). The Analyzer surfaces the _Detailed text to humans, never the bare
///     numeric factor.
/// </summary>
public static class SiTables
{
    // --- Risk-Analysis output tables (scored findings) ---------------------
    public const string RiskAnalysisSummary  = "SI_RiskAnalysis_Summary_CL";
    public const string RiskAnalysisDetailed = "SI_RiskAnalysis_Detailed_CL";

    // --- Asset-profile attribute tables ------------------------------------
    public const string EndpointProfile = "SI_Endpoint_Profile_CL";
    public const string IdentityProfile = "SI_Identity_Profile_CL";
    public const string AzureProfile    = "SI_Azure_Profile_CL";
    public const string PublicIpProfile = "SI_PublicIP_Profile_CL";

    /// <summary>The RA Summary columns the Analyzer projects/maps. These exist on every
    /// RA report row (engine common header + per-report projection + engine stamps).</summary>
    public static class Cols
    {
        public const string SecurityDomain          = "SecurityDomain";
        public const string Category                = "Category";
        public const string Subcategory             = "Subcategory";
        public const string ConfigurationName       = "ConfigurationName";
        public const string ConfigurationId         = "ConfigurationId";
        public const string CriticalityTier         = "CriticalityTier";       // int 0..3
        public const string CriticalityTierLevel    = "CriticalityTierLevel";  // text e.g. "Critical - tier 0"
        public const string SecuritySeverity        = "SecuritySeverity";      // Critical|High|Medium|Low
        public const string RiskScoreTotal          = "RiskScoreTotal";        // numeric headline
        public const string RiskScoreTotalWeighted  = "RiskScoreTotal_Weighted";
        public const string RiskFactorConsequence         = "RiskFactor_Consequence";          // NUMERIC factor
        public const string RiskFactorProbability         = "RiskFactor_Probability";          // NUMERIC factor
        public const string RiskFactorConsequenceDetailed = "RiskFactor_Consequence_Detailed"; // PLAIN-LANGUAGE
        public const string RiskFactorProbabilityDetailed = "RiskFactor_Probability_Detailed"; // PLAIN-LANGUAGE
        public const string CollectionTime          = "CollectionTime";        // snapshot key
    }

    /// <summary>The four asset-profile tables, in domain order.</summary>
    public static readonly IReadOnlyDictionary<string, string> DomainProfileTable =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["endpoint"] = EndpointProfile,
            ["identity"] = IdentityProfile,
            ["azure"]    = AzureProfile,
            ["publicip"] = PublicIpProfile,
        };
}
