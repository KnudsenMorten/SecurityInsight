using System.Globalization;
using Sia.Core.Analysis;
using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>
/// One plain-language glossary entry for the exec surface. <see cref="Term"/> is the
/// jargon word as it appears on the dashboard (e.g. "Risk score", "Tier 0 / crown jewel",
/// "Severity"); <see cref="Plain"/> is a one-sentence, non-technical explanation a CIO
/// understands. <see cref="Present"/> is true ONLY when the concept actually occurs in the
/// current snapshot; <see cref="InYourData"/> is a grounded, real example drawn straight
/// from the rows (never invented) - or an honest "not seen in your current data" note when
/// the term is absent. The exec page can therefore lead with the terms that are live now
/// and still define the rest without ever fabricating an example or a number.
/// </summary>
public sealed record GlossaryTerm(string Term, string Plain, bool Present, string InYourData);

/// <summary>The grounded exec glossary view: every defined term, with the present-now ones
/// surfaced first. <see cref="PresentCount"/> is how many terms are actually live in the
/// current snapshot (the rest are still defined, just flagged absent).</summary>
public sealed record GlossaryView(IReadOnlyList<GlossaryTerm> Terms, int PresentCount, int TotalCount);

/// <summary>
/// Exec glossary / "what these terms mean" plain-language layer (REQUIREMENTS.md
/// "SI Analyzer" - exec glossary candidate). The exec dashboard necessarily uses a handful
/// of security terms (risk score, tier, severity, crown jewel, exposure, onboarding gap,
/// remediation, snapshot, ...). For the non-technical CIO/CISO audience this service turns
/// each into a one-sentence plain definition AND, where the concept is actually present,
/// a GROUNDED example pulled straight from the latest snapshot ("e.g. DEMO-DC-01, a Tier 0
/// asset"). It is pure aggregation over the rows: no AI, no network, no invented numbers,
/// and it is HONEST about missing data - a term with no occurrence in the current data is
/// still defined but clearly flagged "not seen in your current data" rather than given a
/// fabricated example. The AI narrative may narrate on top; this layer never invents.
/// </summary>
public static class Glossary
{
    private const string Absent = "Not seen in your current data.";

    /// <summary>Build the glossary against the FULL row set (the snapshot count term needs
    /// the whole history; the rest key off the latest snapshot). Terms whose concept is
    /// present in the latest snapshot are surfaced first; all terms are always defined.</summary>
    public static GlossaryView Build(IReadOnlyCollection<RiskRow> allRows)
    {
        var latest = SnapshotDiff.LatestSnapshot(allRows);
        var snapshotCount = SnapshotDiff.CollectionTimes(allRows).Count;

        var terms = new List<GlossaryTerm>
        {
            RiskScore(latest),
            Severity(latest),
            CriticalityTier(latest),
            CrownJewel(latest),
            Exposure(latest),
            Vulnerability(latest),
            StalePrivileged(latest),
            OnboardingGap(latest),
            Remediation(latest),
            Snapshot(latest, snapshotCount),
        };

        // Present-now terms first (most useful to the reader), each block keeping its
        // defined order; absent terms still listed so nothing on the page is unexplained.
        var ordered = terms
            .OrderByDescending(t => t.Present)
            .ToList();

        return new GlossaryView(ordered, terms.Count(t => t.Present), terms.Count);
    }

    // --- Individual terms. Each "InYourData" is grounded in a REAL row, or honestly absent. ---

    private static GlossaryTerm RiskScore(IReadOnlyList<RiskRow> latest)
    {
        const string plain = "A single number that adds up how much security risk we carry right now - higher means more risk. It is the sum of every finding's score, so fixing the biggest findings moves it the most.";
        if (latest.Count == 0) return new("Risk score", plain, false, Absent);
        var total = Math.Round(latest.Sum(r => r.RiskScoreTotal), 1);
        var top = latest.OrderByDescending(r => r.RiskScoreTotal).First();
        return new("Risk score", plain, true,
            $"Your overall score is {Num(total)}, made up of {latest.Count} finding{Plural(latest.Count)}; the single biggest is {top.ConfigurationName} at {Num(top.RiskScoreTotal)}.");
    }

    private static GlossaryTerm Severity(IReadOnlyList<RiskRow> latest)
    {
        const string plain = "How dangerous a single finding is if it were exploited - Critical, High, Medium or Low. It is about the weakness itself, separate from how important the affected asset is.";
        var bands = latest
            .Where(r => !string.IsNullOrWhiteSpace(r.SecuritySeverity))
            .GroupBy(r => r.SecuritySeverity)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);
        if (bands.Count == 0) return new("Severity", plain, false, Absent);
        var parts = OrderBands(bands).Select(kv => $"{kv.Value} {kv.Key}");
        return new("Severity", plain, true, "Right now: " + string.Join(", ", parts) + ".");
    }

    private static GlossaryTerm CriticalityTier(IReadOnlyList<RiskRow> latest)
    {
        const string plain = "How important an asset is to the business, from Tier 0 (most critical - the crown jewels) to Tier 3. A weakness on a Tier 0 asset matters far more than the same weakness on a low-tier one.";
        var tiered = latest.Where(r => !string.IsNullOrWhiteSpace(r.CriticalityTierLevel)).ToList();
        if (tiered.Count == 0) return new("Criticality tier", plain, false, Absent);
        var byTier = tiered
            .GroupBy(r => r.CriticalityTier)
            .OrderBy(g => g.Key)
            .Select(g => $"{g.Count()} at Tier {g.Key.ToString(CultureInfo.InvariantCulture)}");
        return new("Criticality tier", plain, true, "Your findings span: " + string.Join(", ", byTier) + ".");
    }

    private static GlossaryTerm CrownJewel(IReadOnlyList<RiskRow> latest)
    {
        const string plain = "Your most business-critical assets (Tier 0) - the ones whose compromise would do the most damage, such as domain controllers or global-admin accounts. These are protected first.";
        var jewels = latest.Where(r => r.CriticalityTier == 0).OrderByDescending(r => r.RiskScoreTotal).ToList();
        if (jewels.Count == 0)
            return new("Crown jewel (Tier 0)", plain, false, "No Tier 0 / crown-jewel asset carries a finding in your current data.");
        var names = string.Join(", ", jewels.Take(2).Select(r => r.ConfigurationName));
        return new("Crown jewel (Tier 0)", plain, true,
            $"{jewels.Count} crown-jewel asset{Plural(jewels.Count)} currently carry a finding, e.g. {names}.");
    }

    private static GlossaryTerm Exposure(IReadOnlyList<RiskRow> latest)
    {
        const string plain = "How reachable a weakness is to an attacker - for example an asset facing the public internet or an open management port. The more exposed, the easier it is to exploit.";
        var ex = FirstWith(latest, "internet", "exposed", "public", "open port", "open risky", "internet-facing", "internet-exposed");
        if (ex is null) return new("Exposure", plain, false, Absent);
        return new("Exposure", plain, true, $"e.g. {ex.ConfigurationName}: {Trim(Driver(ex))}");
    }

    private static GlossaryTerm Vulnerability(IReadOnlyList<RiskRow> latest)
    {
        const string plain = "A known software weakness (often tracked as a CVE) that an attacker can use - typically fixed by patching or upgrading. \"High-CVSS\" means it scores high on the industry severity scale.";
        var v = FirstWith(latest, "cve", "vuln", "unpatched", "eol", "unsupported", "cvss");
        if (v is null) return new("Vulnerability / CVE", plain, false, Absent);
        return new("Vulnerability / CVE", plain, true, $"e.g. {v.ConfigurationName}: {Trim(Driver(v))}");
    }

    private static GlossaryTerm StalePrivileged(IReadOnlyList<RiskRow> latest)
    {
        const string plain = "An account with strong access that is no longer properly used or maintained - for example never logged in for months, a password never rotated, or no owner. These are prime targets.";
        var s = FirstWith(latest, "stale", "no owner", "never rotated", "password never", "no interactive logon", "no mfa", "mfa gap", "privileged");
        if (s is null) return new("Stale / unmanaged privileged account", plain, false, Absent);
        return new("Stale / unmanaged privileged account", plain, true, $"e.g. {s.ConfigurationName}: {Trim(Driver(s))}");
    }

    private static GlossaryTerm OnboardingGap(IReadOnlyList<RiskRow> latest)
    {
        const string plain = "An asset we cannot fully see or monitor yet - it is in scope but not completely reporting to our security sensors, so our picture of it is incomplete.";
        var g = FirstWith(latest, "onboarding", "not fully managed", "not managed", "sensor");
        if (g is null) return new("Onboarding / sensor gap", plain, false, "Every asset in your current data is fully reporting - no onboarding gap detected.");
        return new("Onboarding / sensor gap", plain, true, $"e.g. {g.ConfigurationName}: {Trim(Driver(g))}");
    }

    private static GlossaryTerm Remediation(IReadOnlyList<RiskRow> latest)
    {
        const string plain = "The act of fixing a finding - patching, reconfiguring, removing access, or retiring an asset. When a finding is remediated it drops out of the next snapshot and your risk score falls.";
        if (latest.Count == 0) return new("Remediation", plain, false, Absent);
        var top = latest.OrderByDescending(r => r.RiskScoreTotal).First();
        return new("Remediation", plain, true,
            $"e.g. fully fixing {top.ConfigurationName} would remove {Num(top.RiskScoreTotal)} from your overall score.");
    }

    private static GlossaryTerm Snapshot(IReadOnlyList<RiskRow> latest, int snapshotCount)
    {
        const string plain = "One complete reading of your security posture at a point in time. We compare snapshots over time to show whether you are getting safer (the trend) and what changed.";
        if (snapshotCount == 0) return new("Snapshot", plain, false, Absent);
        var asOf = latest.Count > 0
            ? latest[0].CollectionTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)
            : "the latest run";
        var trend = snapshotCount >= 2
            ? $"You have {snapshotCount} snapshots, so trends and \"what changed\" are available (latest: {asOf})."
            : $"You have only 1 snapshot so far (as of {asOf}); a second run unlocks the trend and \"what changed\".";
        return new("Snapshot", plain, true, trend);
    }

    // --- grounding helpers (all read-only over the real rows) ---

    private static RiskRow? FirstWith(IReadOnlyList<RiskRow> latest, params string[] needles)
    {
        // Highest-scoring matching row, so the example is the most relevant one the exec
        // already sees at the top of the page (grounded, never invented).
        return latest
            .Where(r => Matches(r, needles))
            .OrderByDescending(r => r.RiskScoreTotal)
            .FirstOrDefault();
    }

    private static bool Matches(RiskRow r, string[] needles)
    {
        var hay = r.RiskFactorProbability + " " + r.RiskFactorConsequence;
        foreach (var n in needles)
        {
            if (hay.Contains(n, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private static string Driver(RiskRow r) =>
        !string.IsNullOrWhiteSpace(r.RiskFactorProbability) ? r.RiskFactorProbability : r.RiskFactorConsequence;

    private static string Trim(string s)
    {
        s = (s ?? "").Trim();
        return s.Length <= 90 ? s : s[..87].TrimEnd() + "...";
    }

    private static IEnumerable<KeyValuePair<string, int>> OrderBands(Dictionary<string, int> bands)
    {
        int Rank(string b) => b.ToLowerInvariant() switch
        {
            "critical" => 0, "high" => 1, "medium" => 2, "low" => 3, _ => 4,
        };
        return bands.OrderBy(kv => Rank(kv.Key));
    }

    private static string Num(double v) => v.ToString("0.#", CultureInfo.InvariantCulture);
    private static string Plural(int n) => n == 1 ? "" : "s";
}
