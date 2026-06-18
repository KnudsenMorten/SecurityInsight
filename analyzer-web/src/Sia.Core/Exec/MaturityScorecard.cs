using Sia.Core.Analysis;
using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>
/// One maturity dimension's grounded rating. <see cref="Dimension"/> is the leadership-level
/// capability area (Tiering, Privileged Access, Identity Hygiene, Exposure Management,
/// Visibility &amp; Coverage, Operating Discipline). <see cref="Score"/> is a rule-based 0-100
/// maturity score (HIGHER is better): it is <c>100 * (1 - weakAssets/considered)</c> - the share
/// of in-scope assets that do NOT exhibit a weakness signal for this dimension - so it is a pure,
/// grounded partition of the real rows, never an invented figure. <see cref="Rating"/> is the
/// plain band (Initial/Developing/Defined/Managed). <see cref="WeakAssets"/> is the distinct
/// latest-snapshot assets showing a gap; <see cref="Considered"/> is the in-scope denominator;
/// <see cref="Examples"/> names a few of the real weak assets. When <see cref="HasData"/> is
/// false no in-scope asset was observed, so the score is omitted and the surface says so honestly
/// rather than implying a measured rating.
/// </summary>
public sealed record MaturityDimension(
    string Dimension,
    string Plain,
    double Score,
    string Rating,
    int WeakAssets,
    int Considered,
    bool HasData,
    IReadOnlyList<string> Examples,
    string NextMove);

/// <summary>
/// The maturity scorecard + roadmap. <see cref="Dimensions"/> is every capability area in a fixed
/// order (so the board reads the same card every period). <see cref="Roadmap"/> is the prioritised
/// "mature here next" moves - the lowest-maturity dimensions with real evidence behind them, most
/// impactful first; it is empty (and <see cref="HasRoadmap"/> false) when no dimension stands out
/// as a systemic gap, so the surface never invents a roadmap item. <see cref="OverallScore"/> is
/// the simple average of the dimensions that actually have data (null when none do), and
/// <see cref="AssetsConsidered"/> is the latest-snapshot size the scorecard was measured over.
/// </summary>
public sealed record MaturityScorecardView(
    IReadOnlyList<MaturityDimension> Dimensions,
    IReadOnlyList<MaturityDimension> Roadmap,
    bool HasRoadmap,
    double? OverallScore,
    string OverallRating,
    int AssetsConsidered);

/// <summary>
/// Maturity assessment (REQUIREMENTS.md "SI Analyzer" -&gt; "Maturity scorecard + roadmap"): roll
/// the recurring drift drivers up into a leader-facing maturity view across a few clear dimensions
/// - "not fix these 100 findings, but here is where your environment and operating behaviour need
/// to mature so these findings stop coming back."
///
/// Each dimension is scored purely from the latest-snapshot rows: an in-scope asset is one the
/// dimension can be measured on (e.g. Tiering is measured over every asset; Privileged Access only
/// over privileged/identity assets), and a WEAK asset is one carrying a weakness signal in its own
/// plain-language driver text / domain / tier. The maturity score is the share of in-scope assets
/// WITHOUT a weakness - a grounded partition, no AI, no invented numbers. A dimension with no
/// in-scope asset is honestly reported as "not enough data", never given a fabricated score. The
/// roadmap surfaces only the dimensions that fall below a maturity bar AND have real weak-asset
/// evidence, ordered by how much room they have to improve, so leadership gets 3-5 concrete moves
/// rather than a placeholder. The AI narrative may coach on top; this layer is the grounded
/// backbone even when AI is off.
/// </summary>
public static class MaturityScorecard
{
    // A dimension below this maturity score (and with real weak-asset evidence) earns a place on
    // the "mature here next" roadmap; at-or-above it is treated as good enough not to crowd the
    // board with non-issues.
    private const double RoadmapBar = 80.0;
    // Keep the roadmap board-sized: 3-5 moves, most-impactful first.
    private const int MaxRoadmap = 5;

    /// <summary>
    /// One capability area: its plain label, an "is this asset in scope to be measured here"
    /// predicate, an "is this in-scope asset weak here" predicate, and the leadership move to make
    /// when the area is immature. The score is derived from the predicates over the real rows; the
    /// strings are fixed so nothing is ever fabricated.
    /// </summary>
    private sealed record Lens(
        string Dimension,
        string Plain,
        Func<RiskRow, bool> InScope,
        Func<RiskRow, bool> IsWeak,
        string NextMove);

    // Fixed dimension order - the board reads the same scorecard every period.
    private static readonly IReadOnlyList<Lens> Lenses = new[]
    {
        new Lens(
            "Tiering",
            "Whether business-criticality is modelled and the crown jewels are protected first.",
            // Every asset is in scope: tiering is a whole-estate discipline.
            _ => true,
            // Weak = unclassified tier, OR a Tier 0 crown jewel still carrying an open finding.
            r => string.IsNullOrWhiteSpace(r.CriticalityTierLevel) || r.CriticalityTier == 0,
            "Finish the tiering model and treat Tier 0 / crown-jewel assets as a fast-tracked programme: classify every asset, then remediate the crown jewels first with the strongest controls."),

        new Lens(
            "Privileged Access",
            "Whether privileged accounts are reviewed, owned and protected on a cadence.",
            // In scope = privileged / identity assets.
            r => IsIdentity(r) || Has(r, "privileg", "admin", "service account", "global-admin"),
            // Weak = stale, unowned, unrotated or missing-MFA privileged access.
            r => Has(r, "stale", "no owner", "never rotated", "password never", "no interactive logon",
                        "no mfa", "mfa gap", "mfa gaps", "standing", "always-on", "permanent"),
            "Introduce a recurring privileged-access review (e.g. quarterly): confirm each privileged account still has an owner, is still needed, has MFA, and move standing rights to just-in-time."),

        new Lens(
            "Identity Hygiene",
            "Whether identities are kept clean - no orphans, no legacy auth, no dormant accounts.",
            // In scope = identity assets.
            IsIdentity,
            // Weak = orphan / stale / legacy-auth / MFA-gap identity hygiene signals.
            r => Has(r, "orphan", "unowned", "no owner", "stale", "dormant", "legacy", "basic auth",
                        "no mfa", "mfa gap", "guest", "external"),
            "Run an identity-hygiene cycle: remove orphaned and dormant accounts, retire legacy/basic authentication, and require strong (passwordless/MFA) sign-in everywhere."),

        new Lens(
            "Exposure Management",
            "Whether internet exposure and vulnerabilities are routinely reviewed and reduced.",
            // In scope = every asset (exposure is an estate-wide discipline).
            _ => true,
            // Weak = internet-facing / open-port / exploitable-CVE / EOL exposure.
            r => Has(r, "internet", "internet-facing", "internet-exposed", "public network",
                        "public access", "open risky", "open port", "open management port",
                        "exposed to the internet", "cve", "vulnerab", "unpatched", "eol",
                        "end of life", "end-of-life", "unsupported os", "unsupported", "out of support"),
            "Establish an exposure-management cadence: routinely inventory and justify what is internet-facing, shield or close what does not need to be public, and run a measured patch/lifecycle cycle."),

        new Lens(
            "Visibility & Coverage",
            "Whether the security sensors actually see the whole estate - no blind spots.",
            // In scope = every asset (coverage is measured against the whole estate).
            _ => true,
            // Weak = onboarding / sensor / reporting gaps (we cannot fully see the asset).
            r => Has(r, "onboarding", "not fully managed", "not managed", "sensor", "not reporting",
                        "blind spot", "no coverage", "not onboarded"),
            "Close the onboarding loop: make full sensor enrolment part of the standard build, and reconcile in-scope assets against what is actually reporting on a regular basis."),

        new Lens(
            "Operating Discipline",
            "Whether ownership and accountability are in place so findings get acted on.",
            // In scope = every asset (ownership/accountability applies estate-wide).
            _ => true,
            // Weak = no owner / no accountable party.
            r => Has(r, "no owner", "orphan", "unowned", "ownerless", "no accountable"),
            "Make ownership a standing requirement: assign and maintain an accountable owner for every asset and privileged account, and treat 'no owner' as a finding in its own right."),
    };

    /// <summary>
    /// Build the maturity scorecard from the FULL row set (measured over the latest snapshot - the
    /// CURRENT posture). Dimensions are returned in their fixed order; the roadmap is the
    /// below-bar dimensions with real evidence, ordered by improvement headroom (lowest score,
    /// then most weak assets) first, capped to a board-sized list. Everything is grounded in the
    /// rows - no AI, no invented numbers - and honest when a dimension has no data.
    /// </summary>
    public static MaturityScorecardView Build(IReadOnlyCollection<RiskRow> allRows)
    {
        var latest = SnapshotDiff.LatestSnapshot(allRows);

        var dims = new List<MaturityDimension>();
        foreach (var lens in Lenses)
        {
            // Distinct in-scope assets (by identity) - the honest denominator.
            var inScope = latest
                .Where(lens.InScope)
                .GroupBy(Key)
                .Select(g => g.OrderByDescending(r => r.RiskScoreTotal).First())
                .ToList();

            // Distinct weak assets (by identity) - the grounded numerator.
            var weak = inScope
                .Where(lens.IsWeak)
                .OrderByDescending(r => r.RiskScoreTotal)
                .ToList();

            var considered = inScope.Count;
            var hasData = considered > 0;
            // Score = share of in-scope assets WITHOUT a weakness (higher = more mature).
            var score = hasData
                ? Math.Round(100.0 * (considered - weak.Count) / considered, 1)
                : 0.0;

            var examples = weak
                .Take(3)
                .Select(r => r.ConfigurationName)
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .ToList();

            dims.Add(new MaturityDimension(
                lens.Dimension,
                lens.Plain,
                score,
                hasData ? RatingFor(score) : "Not enough data",
                weak.Count,
                considered,
                hasData,
                examples,
                lens.NextMove));
        }

        // Roadmap: below-bar dimensions WITH real weak-asset evidence, lowest maturity first
        // (then most weak assets), capped to a board-sized list. Empty = honest "no systemic gap".
        var roadmap = dims
            .Where(d => d.HasData && d.WeakAssets > 0 && d.Score < RoadmapBar)
            .OrderBy(d => d.Score)
            .ThenByDescending(d => d.WeakAssets)
            .Take(MaxRoadmap)
            .ToList();

        var scored = dims.Where(d => d.HasData).ToList();
        double? overall = scored.Count > 0
            ? Math.Round(scored.Average(d => d.Score), 1)
            : (double?)null;

        return new MaturityScorecardView(
            dims,
            roadmap,
            roadmap.Count > 0,
            overall,
            overall is { } o ? RatingFor(o) : "Not enough data",
            latest.Count);
    }

    /// <summary>Plain board band for a 0-100 maturity score (higher = more mature).</summary>
    public static string RatingFor(double score) => score switch
    {
        >= 90 => "Managed",
        >= 75 => "Defined",
        >= 50 => "Developing",
        _ => "Initial",
    };

    // --- grounding helpers (read-only over the real rows) ---

    private static string Key(RiskRow r) =>
        string.IsNullOrWhiteSpace(r.ConfigurationId) ? r.ConfigurationName : r.ConfigurationId;

    private static bool IsIdentity(RiskRow r) =>
        (r.SecurityDomain ?? "").Contains("identity", StringComparison.OrdinalIgnoreCase);

    private static bool Has(RiskRow r, params string[] needles)
    {
        var hay = (r.RiskFactorProbability ?? "") + " " + (r.RiskFactorConsequence ?? "");
        foreach (var n in needles)
        {
            if (hay.Contains(n, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }
}
