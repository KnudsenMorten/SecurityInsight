namespace Sia.Core.Kql;

/// <summary>One prestaged, one-click analysis: a plain name, plain meaning, a vetted
/// read-only KQL, and an AI-explanation template.</summary>
public sealed record PrestagedAnalysis(string Id, string Title, string Plain, string Domain, string Kql, string AiTemplate);

/// <summary>
/// The prestaged-analysis library. Each entry is a plain-named, clickable analysis whose
/// KQL is snapshot-correct and passes <see cref="KqlGuardrail"/>. The exec surface uses
/// these for the "so what" drill-downs; the analyst surface lists them directly.
///
/// These query the REAL SI schema: the SCORED findings live in
/// <c>SI_RiskAnalysis_Summary_CL</c> (RiskScoreTotal, SecuritySeverity, CriticalityTier*,
/// and the plain-language RiskFactor_*_Detailed driver text). Text/keyword matching is done
/// against the *_Detailed columns (the bare RiskFactor_* columns are numeric factors, not
/// text). The SecurityDomain column narrows by domain inside the one summary table.
/// </summary>
public static class PrestagedLibrary
{
    public static IReadOnlyList<PrestagedAnalysis> All { get; } = new[]
    {
        new PrestagedAnalysis(
            "crown-jewel-exposure",
            "Crown-jewel exposure paths",
            "Your most critical (Tier 0/1) assets that are exposed to attack right now.",
            "endpoint",
            """
            let _snap = toscalar(SI_RiskAnalysis_Summary_CL | summarize max(CollectionTime));
            SI_RiskAnalysis_Summary_CL
            | where CollectionTime == _snap
            | where SecurityDomain =~ "Endpoint"
            | where CriticalityTier <= 1
            | sort by RiskScoreTotal desc
            | project ConfigurationName, CriticalityTierLevel, SecuritySeverity, RiskScoreTotal, RiskFactor_Consequence_Detailed, RiskFactor_Probability_Detailed
            | take 50
            """,
            "These are the highest-value systems most exposed to compromise. For each, say in plain language what it is, why its exposure matters to the business, the single most effective action to reduce risk, and how urgent it is."),

        new PrestagedAnalysis(
            "stale-but-privileged",
            "Stale but privileged",
            "Powerful accounts/assets that have not been used recently -- prime targets and easy wins to remove.",
            "identity",
            """
            let _snap = toscalar(SI_RiskAnalysis_Summary_CL | summarize max(CollectionTime));
            SI_RiskAnalysis_Summary_CL
            | where CollectionTime == _snap
            | where SecurityDomain =~ "Identity"
            | where CriticalityTier <= 1
            | where RiskFactor_Probability_Detailed has_cs "stale" or RiskFactor_Probability_Detailed has_cs "inactive" or RiskFactor_Consequence_Detailed has_cs "stale"
            | sort by RiskScoreTotal desc
            | project ConfigurationName, CriticalityTierLevel, RiskScoreTotal, RiskFactor_Probability_Detailed, RiskFactor_Consequence_Detailed
            | take 50
            """,
            "These are highly privileged identities/assets that appear dormant. Explain the danger of unused privileged access in plain terms and recommend whether to disable, reduce privilege, or review each."),

        new PrestagedAnalysis(
            "internet-facing-critical-cve",
            "Internet-facing with a critical vulnerability",
            "Assets reachable from the internet that also carry a serious, fixable vulnerability.",
            "endpoint",
            """
            let _snap = toscalar(SI_RiskAnalysis_Summary_CL | summarize max(CollectionTime));
            SI_RiskAnalysis_Summary_CL
            | where CollectionTime == _snap
            | where SecuritySeverity in ("Critical","High")
            | where RiskFactor_Probability_Detailed has_cs "internet" or RiskFactor_Probability_Detailed has_cs "exposed" or RiskFactor_Probability_Detailed has_cs "cve" or RiskFactor_Consequence_Detailed has_cs "cve"
            | sort by RiskScoreTotal desc
            | project ConfigurationName, SecurityDomain, CriticalityTierLevel, SecuritySeverity, RiskScoreTotal, RiskFactor_Consequence_Detailed, RiskFactor_Probability_Detailed
            | take 50
            """,
            "These systems are reachable from the internet and have a serious vulnerability -- a classic break-in route. Explain the combined risk and the fastest path to close it (patch, restrict exposure, or both)."),

        new PrestagedAnalysis(
            "identity-to-t0-lateral",
            "Identity to Tier-0 lateral movement",
            "Everyday accounts that can reach your most critical systems -- the paths attackers love.",
            "identity",
            """
            let _snap = toscalar(SI_RiskAnalysis_Summary_CL | summarize max(CollectionTime));
            SI_RiskAnalysis_Summary_CL
            | where CollectionTime == _snap
            | where SecurityDomain in~ ("Identity","CrossEngine")
            | where RiskFactor_Consequence_Detailed has_cs "tier 0" or RiskFactor_Consequence_Detailed has_cs "lateral" or RiskFactor_Probability_Detailed has_cs "path" or Subcategory has_cs "lateral"
            | sort by RiskScoreTotal desc
            | project ConfigurationName, SecurityDomain, Subcategory, CriticalityTierLevel, RiskScoreTotal, RiskFactor_Consequence_Detailed, RiskFactor_Probability_Detailed
            | take 50
            """,
            "These identities can reach Tier-0 (crown-jewel) systems. Explain the lateral-movement risk plainly and recommend how to break the path (tiering, JIT, credential hygiene)."),

        new PrestagedAnalysis(
            "new-high-risk",
            "New high-risk this run",
            "High-risk findings that appeared since the previous snapshot -- what just got worse.",
            "all",
            """
            let _snap = toscalar(SI_RiskAnalysis_Summary_CL | summarize max(CollectionTime));
            let _prev = toscalar(SI_RiskAnalysis_Summary_CL | where CollectionTime < _snap | summarize max(CollectionTime));
            let _now = SI_RiskAnalysis_Summary_CL | where CollectionTime == _snap | project ConfigurationId, ConfigurationName, SecurityDomain, RiskScoreTotal, CriticalityTierLevel, SecuritySeverity;
            let _before = SI_RiskAnalysis_Summary_CL | where CollectionTime == _prev | project ConfigurationId;
            _now
            | join kind=leftanti _before on ConfigurationId
            | where RiskScoreTotal > 0
            | sort by RiskScoreTotal desc
            | take 50
            """,
            "These high-risk items are brand new since the last snapshot. Explain what changed and which deserve immediate attention."),

        new PrestagedAnalysis(
            "why-did-our-score-change",
            "Why did our score change?",
            "Plain-language reasons our overall risk number moved since last time -- real change vs noise.",
            "all",
            """
            let _snap = toscalar(SI_RiskAnalysis_Summary_CL | summarize max(CollectionTime));
            let _prev = toscalar(SI_RiskAnalysis_Summary_CL | where CollectionTime < _snap | summarize max(CollectionTime));
            let _now = SI_RiskAnalysis_Summary_CL | where CollectionTime == _snap | project ConfigurationId, ConfigurationName, NowScore=RiskScoreTotal, NowTier=CriticalityTierLevel;
            let _was = SI_RiskAnalysis_Summary_CL | where CollectionTime == _prev | project ConfigurationId, WasScore=RiskScoreTotal, WasTier=CriticalityTierLevel;
            _now
            | join kind=fullouter _was on ConfigurationId
            | extend Delta = coalesce(NowScore, 0.0) - coalesce(WasScore, 0.0)
            | where abs(Delta) > 0
            | sort by abs(Delta) desc
            | project ConfigurationName, NowTier, WasTier, WasScore, NowScore, Delta
            | take 50
            """,
            "Explain in plain language WHY the overall risk number moved: separate real posture change (new CVE, newly exposed, remediated) from noise (newly discovered assets, exclusions). For each big mover say what to do and the projected score impact."),
    };

    /// <summary>Validate that every prestaged query passes the guardrail. Empty == clean.</summary>
    public static IReadOnlyList<(string Id, IReadOnlyList<string> Reasons)> ValidateAll()
    {
        var failures = new List<(string, IReadOnlyList<string>)>();
        foreach (var a in All)
        {
            var r = KqlGuardrail.Check(a.Kql);
            if (!r.Allowed) failures.Add((a.Id, r.Reasons));
        }
        return failures;
    }
}
