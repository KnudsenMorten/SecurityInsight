using Sia.Core.Analysis;
using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>
/// One organisational / process maturity gap inferred from a PATTERN across many findings -
/// not a single per-asset ticket. <see cref="Theme"/> is the leadership-level theme
/// (e.g. "Privileged-access reviews"); <see cref="Finding"/> is the plain-language
/// observation ("X assets show ... so the process behind it is not running on a cadence");
/// <see cref="Recommendation"/> is the coaching-style action framed as a PROCESS / BEHAVIOUR
/// for leadership ("introduce a quarterly privileged-access review"), never a technical
/// ticket; <see cref="AffectedAssets"/> is how many latest-snapshot assets exhibit the
/// pattern (the grounded evidence count); <see cref="Examples"/> names a couple of the real
/// assets so the claim is never a black box. Every value is derived from the rows - no AI,
/// no invented numbers, no fabricated example.
/// </summary>
public sealed record CoachingGap(
    string Theme,
    string Finding,
    string Recommendation,
    int AffectedAssets,
    IReadOnlyList<string> Examples);

/// <summary>
/// The organisational-coaching view: the maturity / process gaps the finding patterns imply,
/// ordered by how widespread each pattern is (most-affected first). <see cref="HasGaps"/> is
/// false - and <see cref="Gaps"/> empty - when no pattern crosses its evidence threshold, so
/// the exec surface can honestly say "no systemic process gaps stand out" rather than invent
/// one. <see cref="AssetsConsidered"/> is the size of the latest snapshot the patterns were
/// measured over (the honest denominator).
/// </summary>
public sealed record OrgCoachingView(
    IReadOnlyList<CoachingGap> Gaps,
    bool HasGaps,
    int AssetsConsidered);

/// <summary>
/// Missing processes / org coaching (REQUIREMENTS.md "SI Analyzer" - "beyond per-asset
/// findings, surface organizational + process gaps and coaching-style recommendations the
/// patterns imply ... maturity guidance for leadership, not technical tickets ... grounded in
/// the observed signals, framed as recommended processes/behaviours, never invented facts").
///
/// Where the per-asset risk lists answer "what is broken", this answers "what process would
/// stop it recurring". It looks for PATTERNS across the latest snapshot - e.g. several stale
/// or unowned privileged accounts imply no privileged-access review cadence; many internet-
/// exposed assets imply no external-exposure review; widespread EOL/unpatched software implies
/// no patch/lifecycle cadence. Each pattern is only surfaced when REAL rows cross a small
/// evidence threshold; the count and the example assets are pulled straight from those rows.
/// Pure aggregation - no AI, no network beyond the read-only row fetch, nothing invented. The
/// AI narrative may coach on top; this layer gives the grounded backbone even when AI is off.
/// </summary>
public static class OrgCoaching
{
    /// <summary>
    /// A pattern detector: the leadership theme + the plain finding/recommendation language +
    /// a predicate over the human-readable driver text / domain / tier of a row, plus the
    /// minimum number of distinct assets that must match before the gap is surfaced (so a
    /// single one-off finding never gets dressed up as a systemic process gap).
    /// </summary>
    private sealed record Pattern(
        string Theme,
        Func<int, IReadOnlyList<string>, string> Finding,
        string Recommendation,
        Func<RiskRow, bool> Matches,
        int MinAssets);

    // The grounded backbone. Each pattern's plain language is fixed; ONLY the count + the
    // example asset names are filled from the real rows, so nothing is ever fabricated.
    private static readonly IReadOnlyList<Pattern> Patterns = new[]
    {
        new Pattern(
            "Privileged-access reviews",
            (n, eg) => $"{n} privileged account{Plural(n)} are stale, unowned or missing MFA (e.g. {Join(eg)}) - a sign that privileged access is not being reviewed on a cadence.",
            "Introduce a recurring privileged-access review (e.g. quarterly): confirm each privileged account still has an owner, is still needed, has MFA, and has its credentials rotated. Retire what is not.",
            r => HasText(r, "stale", "no owner", "never rotated", "password never", "no interactive logon", "no mfa", "mfa gap", "mfa gaps")
                 && (IsIdentity(r) || HasText(r, "privileg", "admin", "service account", "global-admin")),
            2),

        new Pattern(
            "Internet-exposure reviews",
            (n, eg) => $"{n} asset{Plural(n)} are reachable from the internet (e.g. {Join(eg)}) - exposure is accumulating without a routine review of what should face the public network.",
            "Establish a routine external-exposure review: periodically inventory what is internet-facing, justify each exposure, and close or shield (private endpoint / VPN / firewall) anything that does not need to be public.",
            r => HasText(r, "internet", "internet-facing", "internet-exposed", "public network", "public access", "open risky", "open port", "open management port", "exposed to the internet"),
            2),

        new Pattern(
            "Patch & lifecycle management",
            (n, eg) => $"{n} asset{Plural(n)} carry unpatched, end-of-life or unsupported software (e.g. {Join(eg)}) - the patch and lifecycle process is not keeping pace.",
            "Run a patch & lifecycle cadence: a regular patch window with measured coverage, plus a hardware/software lifecycle plan to replace end-of-life systems before they go unsupported.",
            r => HasText(r, "unpatched", "cve", "vulnerab", "eol", "end of life", "end-of-life", "unsupported os", "unsupported", "out of support", "legacy"),
            2),

        new Pattern(
            "Asset onboarding & visibility",
            (n, eg) => $"{n} in-scope asset{Plural(n)} are not fully reporting to the security sensors (e.g. {Join(eg)}) - onboarding is incomplete, so the security picture has blind spots.",
            "Close the onboarding loop: make full sensor enrolment part of the standard build/provisioning process, and reconcile in-scope assets against what is actually reporting on a regular basis.",
            r => HasText(r, "onboarding", "not fully managed", "not managed", "sensor", "not reporting", "blind spot"),
            1),

        new Pattern(
            "Asset ownership",
            (n, eg) => $"{n} asset{Plural(n)} have no identified owner (e.g. {Join(eg)}) - without clear ownership, findings have no one accountable to act on them.",
            "Make ownership a standing requirement: assign and maintain an accountable owner for every asset and privileged account, and treat 'no owner' as a finding in its own right.",
            r => HasText(r, "no owner", "orphan", "unowned", "ownerless"),
            1),

        new Pattern(
            "Crown-jewel protection",
            (n, eg) => $"{n} of your most business-critical (Tier 0) asset{Plural(n)} still carry an open finding (e.g. {Join(eg)}) - the crown jewels are not yet being protected first.",
            "Treat Tier 0 / crown-jewel assets as a separate, fast-tracked programme: tighter review cadence, priority remediation SLAs, and the strongest controls (MFA, isolation, monitoring) applied there first.",
            r => r.CriticalityTier == 0,
            2),
    };

    /// <summary>
    /// Build the org-coaching view from the FULL row set (patterns are measured over the
    /// latest snapshot - the current posture - so a fixed-then-recurred asset never inflates
    /// a gap). Gaps are ordered most-affected first; an empty list is an HONEST "no systemic
    /// process gap stands out", never a placeholder gap.
    /// </summary>
    public static OrgCoachingView Build(IReadOnlyCollection<RiskRow> allRows)
    {
        var latest = SnapshotDiff.LatestSnapshot(allRows);

        var gaps = new List<CoachingGap>();
        foreach (var p in Patterns)
        {
            // Distinct assets (by identity) that exhibit the pattern - so the same asset with
            // two matching findings counts once, and the evidence count is honest.
            var matched = latest
                .Where(p.Matches)
                .GroupBy(r => string.IsNullOrWhiteSpace(r.ConfigurationId) ? r.ConfigurationName : r.ConfigurationId)
                .Select(g => g.OrderByDescending(r => r.RiskScoreTotal).First())
                .OrderByDescending(r => r.RiskScoreTotal)
                .ToList();

            if (matched.Count < p.MinAssets) continue;

            var examples = matched
                .Take(3)
                .Select(r => r.ConfigurationName)
                .Where(n => !string.IsNullOrWhiteSpace(n))
                .ToList();

            gaps.Add(new CoachingGap(
                p.Theme,
                p.Finding(matched.Count, examples),
                p.Recommendation,
                matched.Count,
                examples));
        }

        // Most-widespread gap first (the biggest organisational lever). Ties keep the
        // declared pattern order, which runs hygiene -> exposure -> lifecycle -> the rest.
        var ordered = gaps
            .OrderByDescending(g => g.AffectedAssets)
            .ToList();

        return new OrgCoachingView(ordered, ordered.Count > 0, latest.Count);
    }

    // --- grounding helpers (read-only over the real rows) ---

    private static bool IsIdentity(RiskRow r) =>
        (r.SecurityDomain ?? "").Contains("identity", StringComparison.OrdinalIgnoreCase);

    private static bool HasText(RiskRow r, params string[] needles)
    {
        var hay = (r.RiskFactorProbability ?? "") + " " + (r.RiskFactorConsequence ?? "");
        foreach (var n in needles)
        {
            if (hay.Contains(n, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static string Join(IReadOnlyList<string> names) =>
        names.Count == 0 ? "the affected assets" : string.Join(", ", names);

    private static string Plural(int n) => n == 1 ? "" : "s";
}
