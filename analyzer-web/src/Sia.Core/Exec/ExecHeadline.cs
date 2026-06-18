using Sia.Core.Analysis;
using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>
/// The "if you read one thing" headline verdict for the very top of the exec view -
/// the single most important sentence a CIO reads (REQUIREMENTS.md "SI Analyzer":
/// "One-sentence headline - the 'if you read one thing' verdict at the very top
/// (e.g. 'Posture is High but improving; 3 actions would move you to Medium')").
///
/// Every field is GROUNDED in the latest-snapshot RA rows + the snapshot diff:
/// <list type="bullet">
///   <item><see cref="Band"/> / <see cref="Direction"/> come from the headline score
///   and the prior-snapshot delta.</item>
///   <item><see cref="ActionsToNextBand"/> is computed by counting how many of the
///   highest-scoring findings would have to be fully remediated for the headline score
///   to drop below the next-better band threshold - a real, achievable count, never a
///   guess. <see cref="NextBand"/> is that better band.</item>
/// </list>
/// It states a verdict + a count of concrete actions only; it NEVER invents a cost,
/// a probability, or a date. The AI narrative narrates on top; this gives the exec the
/// one-line verdict even when AI is unavailable (fail-soft).
/// </summary>
public sealed record ExecHeadline(
    double Score,
    string Band,
    string Direction,
    double ScoreDelta,
    double? PercentChange,
    string? NextBand,
    int ActionsToNextBand,
    string Sentence);

/// <summary>
/// Builds the one-sentence exec headline from the latest RA snapshot + the snapshot
/// diff. Pure aggregation - no network, no AI, no invented numbers. The action count
/// is derived from the actual top findings, so "N actions would move you to X" is a
/// claim the data supports (remediating those N findings really does drop the score
/// past the band boundary).
/// </summary>
public static class ExecHeadlineBuilder
{
    /// <summary>The ordered band thresholds (lower bound, name), worst-first, matching
    /// <see cref="ExecDashboardBuilder.ScoreBand"/>. Kept here so the "actions to next
    /// band" maths uses the exact same boundaries the dial/band display uses.</summary>
    private static readonly (double Floor, string Name)[] Bands =
    {
        (400, "Severe"),
        (200, "Elevated"),
        (75, "Moderate"),
        (0, "Low"),
    };

    /// <summary>
    /// Build the headline from ALL rows. The headline score + direction use the latest
    /// snapshot and the immediately-prior snapshot (same basis as the dial), and the
    /// "actions to next band" count is derived from the latest snapshot's findings.
    /// </summary>
    public static ExecHeadline Build(IReadOnlyCollection<RiskRow> allRows)
    {
        var latest = SnapshotDiff.LatestSnapshot(allRows);
        var diff = SnapshotDiff.Diff(allRows);
        return Build(latest, diff.ScoreDelta, diff.PreviousTotal);
    }

    /// <summary>Core overload (testable without the diff plumbing): build from the
    /// latest-snapshot rows, the prior-snapshot score delta and the prior total.</summary>
    public static ExecHeadline Build(IReadOnlyList<RiskRow> latest, double scoreDelta, double previousTotal)
    {
        var score = Math.Round(latest.Sum(r => r.RiskScoreTotal), 1);
        var band = ExecDashboardBuilder.ScoreBand(score);
        var direction = scoreDelta < 0 ? "improving" : scoreDelta > 0 ? "worsening" : "steady";
        double? pct = previousTotal != 0
            ? Math.Round((latest.Sum(r => r.RiskScoreTotal) - previousTotal) / previousTotal * 100, 1)
            : null;

        var (nextBand, actions) = ActionsToNextBetterBand(latest, score, band);
        var sentence = Compose(score, band, direction, pct, nextBand, actions, latest.Count);

        return new ExecHeadline(score, band, direction, scoreDelta, pct, nextBand, actions, sentence);
    }

    /// <summary>
    /// How many of the highest-scoring findings must be fully remediated for the headline
    /// score to fall into the next-better band, and what that band is. Returns (null, 0)
    /// when already at the best band or when no single set of findings can cross the
    /// boundary. Grounded: it walks the actual rows highest-score-first and counts how many
    /// it takes to drop the running total below the next-better band's ceiling.
    /// </summary>
    private static (string? NextBand, int Actions) ActionsToNextBetterBand(
        IReadOnlyList<RiskRow> latest, double score, string band)
    {
        // The "next better band" is the band one step below the current one. Its UPPER
        // bound is the current band's floor (e.g. to leave "Elevated" (>=200) you must get
        // strictly below 200, which lands you in "Moderate").
        var idx = Array.FindIndex(Bands, b => b.Name == band);
        if (idx < 0 || idx == Bands.Length - 1)
        {
            return (null, 0); // already Low (best band) - nothing to improve toward.
        }

        var currentFloor = Bands[idx].Floor;       // strictly-below-this leaves the current band
        var nextBandName = Bands[idx + 1].Name;
        var target = currentFloor - 0.1;           // just below the boundary (scores are rounded to .1)

        // Remove the biggest findings first; count how many it takes to get the running
        // total at-or-below the target. This is the minimum-actions answer because removing
        // higher-scoring items first drops the total fastest.
        var ordered = latest.OrderByDescending(r => r.RiskScoreTotal).ToList();
        var running = score;
        var actions = 0;
        foreach (var r in ordered)
        {
            if (running <= target) break;
            running = Math.Round(running - r.RiskScoreTotal, 1);
            actions++;
        }

        // If even removing every finding cannot cross the boundary (shouldn't happen, since
        // removing all leaves 0 = Low), fall back to "no clean step".
        if (running > target) return (null, 0);
        return (nextBandName, actions);
    }

    /// <summary>Compose the plain-language one-sentence verdict. No jargon, no KQL, no
    /// invented figures - just the band, the direction, and the concrete action count.</summary>
    private static string Compose(double score, string band, string direction, double? pct,
        string? nextBand, int actions, int findingCount)
    {
        if (findingCount == 0)
        {
            return "No open security findings in the latest snapshot - your posture is clear.";
        }

        var dirPhrase = direction switch
        {
            "improving" => "and improving",
            "worsening" => "and rising",
            _ => "and holding steady",
        };

        // Lead with the verdict (band + direction), then the single concrete next step.
        var lead = $"Your security posture is {band} {dirPhrase}";

        if (nextBand is not null && actions > 0)
        {
            var actionWord = actions == 1 ? "action" : "actions";
            return $"{lead}; {actions} {actionWord} would move you to {nextBand}.";
        }

        // Already at the best band, or no clean band-crossing step.
        return band == "Low"
            ? $"{lead}; keep monitoring to hold this level."
            : $"{lead}; focus on the highest-scoring findings to bring it down.";
    }
}
