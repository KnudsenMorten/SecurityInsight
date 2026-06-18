using Sia.Core.Analysis;
using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>
/// One ranked remediation action: a grounded grouping of the latest-snapshot findings on
/// ONE asset (<see cref="ConfigurationId"/>), restated as a single thing leadership can
/// direct. Every figure traces to the rows:
/// <list type="bullet">
///   <item><see cref="ProjectedScoreDrop"/> is the SUM of the asset's finding scores - the
///   exact amount the headline falls if the asset is fully remediated (removing those rows).</item>
///   <item><see cref="Effort"/> is an HONESTLY-LABELLED estimate ("Low/Medium/High") derived
///   from the asset's own grounded driver text + tier (never an invented hour/cost figure).</item>
///   <item><see cref="RoiScore"/> = projected drop / effort weight - the "biggest risk removed
///   per unit of work" ordering. It is a relative ranking key, not a unit.</item>
///   <item><see cref="CumulativeScoreAfter"/> / <see cref="BandAfter"/> walk the plan in ROI
///   order: the running headline + band once this action and all higher-ranked ones are done.</item>
/// </list>
/// </summary>
public sealed record RemediationAction(
    int Rank,
    string ConfigurationId,
    string ConfigurationName,
    string SecurityDomain,
    string AreaPlain,
    int CriticalityTier,
    string TopSeverity,
    int FindingCount,
    double ProjectedScoreDrop,
    double SharePercent,
    string Effort,
    double RoiScore,
    string Why,
    string Recommendation,
    double CumulativeScoreAfter,
    string BandAfter,
    bool CrossesBandHere);

/// <summary>
/// The prioritised remediation plan: the "next N actions, ranked by risk-reduction" view a
/// CIO/CISO uses to decide where to spend the next sprint. <see cref="StartScore"/> /
/// <see cref="StartBand"/> are today; <see cref="Actions"/> are ordered best-ROI-first;
/// <see cref="ProjectedScoreAfterPlan"/> / <see cref="ProjectedBandAfterPlan"/> are where the
/// posture lands if the whole shown plan is delivered; <see cref="BandCrossActionCount"/> is
/// how many of the shown actions it takes to reach the next-better band (null if the plan
/// can't cross one). All grounded; effort/ROI are clearly-labelled estimates, no costs/dates.
/// </summary>
public sealed record RemediationPlanView(
    double StartScore,
    string StartBand,
    IReadOnlyList<RemediationAction> Actions,
    int TotalAssets,
    double ProjectedScoreAfterPlan,
    string ProjectedBandAfterPlan,
    string? NextBetterBand,
    int? BandCrossActionCount);

/// <summary>
/// Prioritised remediation plan / "next N actions ranked by risk-reduction"
/// (REQUIREMENTS.md "SI Analyzer" - "Quick wins / ROI: 'fix these 3 -&gt; biggest score
/// drop', ranked by impact vs effort ... show the projected score delta"). Unlike the flat
/// quick-wins list (one row = one fix) this GROUPS every finding on an asset into one action,
/// estimates the EFFORT to remediate it from the asset's own grounded drivers, ranks by
/// risk-removed-per-effort (ROI), and walks the plan to show the CUMULATIVE projected score +
/// when the posture crosses into a better band. Pure aggregation over the latest snapshot -
/// no network, no AI, no invented numbers; effort/ROI are explicitly estimates.
/// </summary>
public static class RemediationPlan
{
    /// <summary>Relative effort weights (bigger = more work). Used only to ORDER actions by
    /// risk-removed-per-effort; they are not hours or costs and are labelled as estimates.</summary>
    private static readonly Dictionary<string, double> EffortWeight = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Low"] = 1.0,
        ["Medium"] = 2.0,
        ["High"] = 3.0,
    };

    /// <summary>
    /// Build the plan from the full row set (the latest snapshot is selected internally so the
    /// plan is snapshot-correct). <paramref name="top"/> caps how many actions are SHOWN (a
    /// view, not a data cap - the ROI ranking + band maths consider every asset). Actions are
    /// returned best-ROI-first with a running cumulative score/band.
    /// </summary>
    public static RemediationPlanView Build(IReadOnlyCollection<RiskRow> allRows, int top = 5)
    {
        var latest = SnapshotDiff.LatestSnapshot(allRows);
        var startScore = Math.Round(latest.Sum(r => r.RiskScoreTotal), 1);
        var startBand = ExecDashboardBuilder.ScoreBand(startScore);

        // One candidate action per asset (ConfigurationId): the sum of that asset's findings is
        // exactly how much the headline drops if the asset is fully remediated - a real number.
        var candidates = latest
            .GroupBy(r => string.IsNullOrWhiteSpace(r.ConfigurationId) ? r.ConfigurationName : r.ConfigurationId)
            .Select(g =>
            {
                var rows = g.ToList();
                var drop = Math.Round(rows.Sum(r => r.RiskScoreTotal), 1);
                var lead = rows.OrderByDescending(r => r.RiskScoreTotal).First();
                var effort = EstimateEffort(rows, lead);
                var weight = EffortWeight.TryGetValue(effort, out var w) ? w : 2.0;
                var topSev = TopSeverity(rows);
                return new
                {
                    Id = g.Key,
                    Name = lead.ConfigurationName,
                    Domain = lead.SecurityDomain ?? "",
                    Tier = rows.Min(r => r.CriticalityTier), // best (lowest) tier number = most critical
                    TopSev = topSev,
                    Count = rows.Count,
                    Drop = drop,
                    Effort = effort,
                    // ROI: risk removed per unit of effort. Highest first. Ties broken by raw
                    // drop then by criticality (lower tier number = more critical = first).
                    Roi = weight <= 0 ? drop : Math.Round(drop / weight, 2),
                    Why = BuildWhy(lead),
                    Reco = BuildRecommendation(rows, lead),
                };
            })
            .Where(c => c.Drop > 0)
            .OrderByDescending(c => c.Roi)
            .ThenByDescending(c => c.Drop)
            .ThenBy(c => c.Tier)
            .ToList();

        // Walk EVERY candidate in ROI order to find when the band first improves (grounded,
        // even if it happens beyond the shown top-N). The running total can never go negative.
        var (nextBand, bandCrossCount) = BandCrossing(startScore, startBand, candidates.Select(c => c.Drop).ToList());

        // Build the SHOWN actions with their running cumulative score/band.
        var actions = new List<RemediationAction>();
        var running = startScore;
        var rank = 0;
        foreach (var c in candidates.Take(Math.Max(0, top)))
        {
            rank++;
            var before = running;
            running = Math.Round(Math.Max(0, running - c.Drop), 1);
            var bandBefore = ExecDashboardBuilder.ScoreBand(before);
            var bandAfter = ExecDashboardBuilder.ScoreBand(running);
            actions.Add(new RemediationAction(
                Rank: rank,
                ConfigurationId: c.Id,
                ConfigurationName: c.Name,
                SecurityDomain: c.Domain,
                AreaPlain: AreaPlain(c.Domain),
                CriticalityTier: c.Tier,
                TopSeverity: c.TopSev,
                FindingCount: c.Count,
                ProjectedScoreDrop: c.Drop,
                SharePercent: startScore <= 0 ? 0 : Math.Round(c.Drop / startScore * 100, 1),
                Effort: c.Effort,
                RoiScore: c.Roi,
                Why: c.Why,
                Recommendation: c.Reco,
                CumulativeScoreAfter: running,
                BandAfter: bandAfter,
                CrossesBandHere: !string.Equals(bandBefore, bandAfter, StringComparison.Ordinal)));
        }

        var afterPlan = actions.Count > 0 ? actions[^1].CumulativeScoreAfter : startScore;
        var afterBand = ExecDashboardBuilder.ScoreBand(afterPlan);

        return new RemediationPlanView(
            startScore, startBand, actions, candidates.Count,
            afterPlan, afterBand, nextBand, bandCrossCount);
    }

    /// <summary>
    /// How many of the ROI-ordered actions it takes for the running headline to fall into the
    /// next-better band, and which band that is. Returns (null, null) when already at the best
    /// band or when remediating every asset still cannot cross a boundary. Grounded: it walks
    /// the same per-asset drops the plan uses.
    /// </summary>
    private static (string? NextBand, int? Count) BandCrossing(double startScore, string startBand, IReadOnlyList<double> dropsRoiOrdered)
    {
        var nextBand = ExecDashboardBuilder.ScoreBand(0) == startBand ? null : NextBetterBand(startBand);
        if (nextBand is null) return (null, null);

        var running = startScore;
        var count = 0;
        foreach (var drop in dropsRoiOrdered)
        {
            running = Math.Round(Math.Max(0, running - drop), 1);
            count++;
            if (!string.Equals(ExecDashboardBuilder.ScoreBand(running), startBand, StringComparison.Ordinal))
            {
                return (ExecDashboardBuilder.ScoreBand(running), count);
            }
        }
        return (null, null); // can't cross even by doing everything (shouldn't happen above Low)
    }

    /// <summary>The band one step better than the given band (its name), or null at the best band.</summary>
    private static string? NextBetterBand(string band) => band switch
    {
        "Severe" => "Elevated",
        "Elevated" => "Moderate",
        "Moderate" => "Low",
        _ => null, // Low is best
    };

    /// <summary>
    /// Estimate the remediation effort from the asset's OWN grounded driver text + tier. This
    /// is an explicitly-labelled heuristic estimate (never hours/cost): configuration toggles
    /// and account hygiene are typically "Low"; patching/CVE/onboarding work is "Medium";
    /// tier-0 coordination or multi-finding assets lean "High". Honest by design - when the
    /// drivers give no signal it defaults to "Medium" (we don't pretend to know).
    /// </summary>
    private static string EstimateEffort(IReadOnlyList<RiskRow> rows, RiskRow lead)
    {
        var text = string.Join(" ; ",
            rows.Select(r => (r.RiskFactorProbability + " " + r.RiskFactorConsequence)))
            .ToLowerInvariant();

        bool Has(params string[] needles) => needles.Any(n => text.Contains(n, StringComparison.Ordinal));

        // Low: config switch / account hygiene - quick, well-understood changes.
        var low = Has("public network access", "public access", "private endpoint", "no mfa", "mfa gap",
            "mfa gaps", "password never rotated", "no owner", "open risky", "open port", "exposed to the internet",
            "rdp");
        // High signals: tier-0 coordination, lateral-movement remediation, or many findings.
        var high = lead.CriticalityTier == 0 || rows.Count >= 3
            || Has("lateral movement", "tier 0 takeover", "tier-0 takeover", "full tier-0");
        // Medium signals: patching / onboarding / EOL migration - real but bounded project work.
        var medium = Has("cve", "unpatched", "high-cvss", "patch", "onboarding", "not fully managed",
            "not managed", "unsupported os", "eol", "end of life");

        if (high) return "High";
        if (low && !medium) return "Low";
        if (medium) return "Medium";
        if (low) return "Low";
        return "Medium";
    }

    /// <summary>Plain "why this matters" line from the asset's grounded drivers (consequence
    /// preferred, probability as fallback) - no KQL, no invented claim.</summary>
    private static string BuildWhy(RiskRow lead) =>
        !string.IsNullOrWhiteSpace(lead.RiskFactorConsequence) ? lead.RiskFactorConsequence
        : !string.IsNullOrWhiteSpace(lead.RiskFactorProbability) ? lead.RiskFactorProbability
        : "Contributes to the overall risk score.";

    /// <summary>A plain, action-shaped recommendation derived from the grounded drivers. It
    /// suggests the KIND of fix the drivers imply (patch / restrict access / rotate or remove
    /// the account / onboard) - never a specific product step or invented detail.</summary>
    private static string BuildRecommendation(IReadOnlyList<RiskRow> rows, RiskRow lead)
    {
        var text = string.Join(" ; ", rows.Select(r => r.RiskFactorProbability + " " + r.RiskFactorConsequence)).ToLowerInvariant();
        bool Has(params string[] n) => n.Any(x => text.Contains(x, StringComparison.Ordinal));

        if (Has("public network access", "public access", "private endpoint"))
            return "Restrict public network access (add a private endpoint / firewall the service).";
        if (Has("open risky", "open port", "exposed to the internet", "rdp"))
            return "Close or restrict the internet-exposed management port to trusted networks only.";
        if (Has("no mfa", "mfa gap", "mfa gaps"))
            return "Enforce MFA and review the account's privileged access.";
        if (Has("password never rotated", "no interactive logon", "stale"))
            return "Rotate the credential and disable or right-size this stale privileged account.";
        if (Has("no owner"))
            return "Assign an owner, then review and right-size the account's privileges (or remove it).";
        if (Has("cve", "unpatched", "high-cvss", "patch"))
            return "Patch the known vulnerability (or isolate the asset until it can be patched).";
        if (Has("onboarding", "not fully managed", "not managed"))
            return "Complete onboarding so the asset is fully managed and monitored.";
        if (Has("unsupported os", "eol", "end of life"))
            return "Plan migration off the unsupported OS (or isolate it as a compensating control).";
        if (Has("lateral movement", "reachable path", "crown-jewel"))
            return "Break the lateral-movement path to the crown-jewel asset (tier the access).";

        return "Remediate the finding(s) on this asset to remove its risk contribution.";
    }

    /// <summary>Highest severity among the asset's findings (Critical &gt; High &gt; Medium &gt; Low).</summary>
    private static string TopSeverity(IReadOnlyList<RiskRow> rows)
    {
        int Rank(string s) => s switch { "Critical" => 4, "High" => 3, "Medium" => 2, "Low" => 1, _ => 0 };
        return rows.OrderByDescending(r => Rank(r.SecuritySeverity ?? "")).First().SecuritySeverity ?? "";
    }

    /// <summary>Plain board names for the SI domains (kept consistent with the concentration view).</summary>
    private static string AreaPlain(string area) => (area ?? "").Trim().ToLowerInvariant() switch
    {
        "endpoint" => "Endpoints (servers & workstations)",
        "identity" => "Identity & access",
        "azure" => "Cloud platform",
        "publicip" => "Internet-facing exposure",
        "" => "Other assets",
        _ => char.ToUpperInvariant(area!.Trim()[0]) + area.Trim()[1..],
    };
}
