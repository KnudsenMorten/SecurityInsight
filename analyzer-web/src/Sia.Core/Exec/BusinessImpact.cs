using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>
/// One top risk re-framed in BUSINESS terms - the "so what" for a non-technical exec.
/// <see cref="Category"/> is the kind of business consequence (data exposure, downtime,
/// compliance, reputation); <see cref="Consequence"/> is the plain-language "if this is
/// exploited, here is what it costs the business" sentence; <see cref="Why"/> is the
/// grounded technical driver it was derived from (so the claim is never a black box).
/// Every field is derived from the row's own domain + tier + severity + driver text -
/// nothing is invented and no figure (cost/probability) is fabricated.
/// </summary>
public sealed record BusinessImpactItem(
    string ConfigurationName,
    string SecuritySeverity,
    int CriticalityTier,
    double RiskScoreTotal,
    string Category,
    string Consequence,
    string Why);

/// <summary>The "so what" business-impact view for the top risks of the latest snapshot,
/// plus the count of findings per business-impact category so leadership sees where the
/// consequence concentrates (data exposure vs downtime vs compliance vs reputation).</summary>
public sealed record BusinessImpactView(
    IReadOnlyList<BusinessImpactItem> Items,
    IReadOnlyList<ChartSlice> ByCategory);

/// <summary>
/// "So what" business-impact framing (REQUIREMENTS.md "SI Analyzer" - "translate each
/// headline item into business impact (data exposure / downtime / compliance /
/// reputation), not technical cause. The CIO cares about consequence."). Pure, grounded
/// translation of each top risk into a plain-language business consequence - no network,
/// no AI, no invented numbers. The AI narrative still narrates ON TOP; this gives the
/// exec the structured "so what" even when AI is unavailable (fail-soft).
/// </summary>
public static class BusinessImpact
{
    /// <summary>Build the business-impact view for the top-<paramref name="top"/> risks of
    /// the latest snapshot. <paramref name="latest"/> is the latest-snapshot rows.</summary>
    public static BusinessImpactView Build(IReadOnlyList<RiskRow> latest, int top = 5)
    {
        var items = latest
            .OrderByDescending(r => r.RiskScoreTotal)
            .Take(top)
            .Select(ToItem)
            .ToList();

        // Category concentration across ALL latest rows (the rollup is the full set; the
        // item list is a top-N VIEW per the no-silent-caps rule).
        var byCategory = latest
            .GroupBy(r => Categorize(r).Category)
            .Select(g => new ChartSlice(g.Key, g.Count()))
            .OrderByDescending(s => s.Value)
            .ToList();

        return new BusinessImpactView(items, byCategory);
    }

    private static BusinessImpactItem ToItem(RiskRow r)
    {
        var (category, consequence) = Categorize(r);
        var why = string.IsNullOrWhiteSpace(r.RiskFactorConsequence)
            ? (string.IsNullOrWhiteSpace(r.RiskFactorProbability) ? "Flagged by the risk engine." : r.RiskFactorProbability)
            : r.RiskFactorConsequence;
        return new BusinessImpactItem(
            r.ConfigurationName,
            r.SecuritySeverity ?? "",
            r.CriticalityTier,
            Math.Round(r.RiskScoreTotal, 1),
            category,
            consequence,
            why);
    }

    /// <summary>
    /// Classify a finding into a business-impact category + a plain consequence sentence.
    /// The classification is GROUNDED: it reads the row's domain, tier and the human driver
    /// text already present on the row, and maps to the four board-level consequence kinds.
    /// Order matters - the strongest consequence the signals support wins. No cost or
    /// likelihood number is ever invented; the sentence states the KIND of consequence only.
    /// </summary>
    public static (string Category, string Consequence) Categorize(RiskRow r)
    {
        var text = ((r.RiskFactorConsequence ?? "") + " " + (r.RiskFactorProbability ?? "")).ToLowerInvariant();
        var domain = (r.SecurityDomain ?? "").Trim().ToLowerInvariant();
        var crownJewel = r.CriticalityTier <= 1; // tier 0/1 = crown jewel

        // Compliance / audit exposure - regulated data or audit-relevant gaps.
        if (Has(text, "compliance", "regulat", "audit", "gdpr", "iso", "pci", "unsupported", "end of life", "eol", "out of support", "patch"))
        {
            return ("Compliance", crownJewel
                ? "A failure or breach here is likely to be reportable and could trigger regulatory penalties and failed audits on a business-critical system."
                : "This weakens audit and regulatory standing and could surface as a finding in a compliance review.");
        }

        // Data exposure - identity, privileged access, internet-facing, or sensitive data.
        if (domain == "identity" || domain == "publicip"
            || Has(text, "privileg", "admin", "credential", "expos", "internet", "public", "data", "exfil", "lateral", "crown", "tier 0", "tier0"))
        {
            return ("Data exposure", crownJewel
                ? "If exploited, an attacker could reach sensitive data or take over privileged access - a serious confidentiality breach for the organisation."
                : "If exploited, this could expose data or hand an attacker a foothold to move toward more sensitive systems.");
        }

        // Downtime / operational disruption - endpoints, cloud services, availability.
        if (domain == "endpoint" || domain == "azure"
            || Has(text, "availab", "ransom", "downtime", "service", "outage", "encrypt", "destruct"))
        {
            return ("Downtime", crownJewel
                ? "Compromise of this critical system could interrupt operations the business depends on, causing measurable downtime."
                : "Compromise here could disrupt the services this asset supports.");
        }

        // Reputation - the residual bucket; any unremediated critical/high finding carries it.
        return ("Reputation", crownJewel
            ? "An incident on a system this important would be visible to customers and partners and could damage trust in the organisation."
            : "Left unaddressed, this contributes to the kind of incident that erodes customer and partner trust.");
    }

    private static bool Has(string haystack, params string[] needles)
    {
        foreach (var n in needles)
        {
            if (haystack.Contains(n, StringComparison.Ordinal)) return true;
        }
        return false;
    }
}
