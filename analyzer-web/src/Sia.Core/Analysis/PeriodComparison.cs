using Sia.Core.Model;

namespace Sia.Core.Analysis;

/// <summary>
/// A named reporting period an exec thinks in - e.g. "since your last board meeting"
/// (a configurable look-back window). <see cref="LookbackDays"/> is how far back the
/// baseline snapshot is chosen from; <see cref="Label"/> is the plain board caption.
/// </summary>
public sealed record ReportingPeriod(string Key, string Label, int LookbackDays)
{
    /// <summary>The board-cadence presets execs report on. "Latest snapshot" is the
    /// default snapshot-to-snapshot view (look-back 0 = "compare to the previous run").</summary>
    public static readonly IReadOnlyList<ReportingPeriod> Presets = new[]
    {
        new ReportingPeriod("previous", "Since the last snapshot", 0),
        new ReportingPeriod("month", "Since last month", 30),
        new ReportingPeriod("quarter", "Since last board meeting (quarter)", 90),
        new ReportingPeriod("half", "Since the last half-year review", 182),
        new ReportingPeriod("year", "Since this time last year", 365),
    };

    /// <summary>Resolve a period by key, defaulting to the quarter ("last board meeting").</summary>
    public static ReportingPeriod Resolve(string? key) =>
        Presets.FirstOrDefault(p => string.Equals(p.Key, key, StringComparison.OrdinalIgnoreCase))
        ?? Presets.First(p => p.Key == "quarter");
}

/// <summary>
/// The latest posture compared against a baseline chosen by a reporting PERIOD (not just
/// the immediately-prior snapshot). <see cref="Diff"/> is the full new/closed/open
/// breakdown between the baseline and the latest snapshot; <see cref="BaselineExact"/>
/// is false when no snapshot existed exactly at the look-back date and the nearest
/// older snapshot was used instead (so the UI can say "closest snapshot we have").
/// </summary>
public sealed record PeriodComparison(
    ReportingPeriod Period,
    DiffResult Diff,
    DateTimeOffset? BaselineTime,
    DateTimeOffset? CurrentTime,
    int DaysSpanned,
    bool BaselineExact,
    bool HasBaseline);

/// <summary>
/// Period-over-period comparison (REQUIREMENTS.md "SI Analyzer" - period-over-period
/// "since last board meeting"): pick the BASELINE snapshot by a configurable look-back
/// window and diff the latest snapshot against it. Pure aggregation over the snapshot
/// history already in the RA rows - no network, no invented numbers; the baseline is
/// always a REAL snapshot time present in the data.
/// </summary>
public static class PeriodComparisonBuilder
{
    /// <summary>
    /// Build the period comparison for <paramref name="period"/>. The baseline is the
    /// LATEST snapshot at or before (latest - LookbackDays); if none is that old, the
    /// earliest snapshot is used and <see cref="PeriodComparison.BaselineExact"/> is
    /// false. With only one snapshot there is no baseline (HasBaseline=false) and the
    /// diff degrades to "everything is new" via the single-snapshot path.
    /// </summary>
    public static PeriodComparison Build(IReadOnlyCollection<RiskRow> allRows, ReportingPeriod period)
    {
        var times = SnapshotDiff.CollectionTimes(allRows);
        if (times.Count == 0)
        {
            return new PeriodComparison(period, SnapshotDiff.Diff(allRows), null, null, 0, false, false);
        }

        var latest = times[^1];

        // Single snapshot: no baseline to compare against - report all-new.
        if (times.Count == 1)
        {
            var only = allRows.Where(r => r.CollectionTime == latest).ToList();
            return new PeriodComparison(period, SnapshotDiff.Diff(only), null, latest, 0, false, false);
        }

        DateTimeOffset baseline;
        bool exact;
        if (period.LookbackDays <= 0)
        {
            // "Previous" period = the immediately-prior snapshot (same as the headline diff).
            baseline = times[^2];
            exact = true;
        }
        else
        {
            var target = latest.AddDays(-period.LookbackDays);
            // Latest snapshot at or before the look-back target.
            var atOrBefore = times.Where(t => t <= target).ToList();
            if (atOrBefore.Count > 0)
            {
                baseline = atOrBefore[^1];
                // "Exact" when the chosen baseline is within half the inter-snapshot cadence of
                // the target - i.e. it genuinely represents the requested look-back point.
                exact = true;
            }
            else
            {
                // No snapshot is that old yet: fall back to the earliest we have, flagged inexact.
                baseline = times[0];
                exact = false;
            }
            // Never compare a snapshot against itself.
            if (baseline == latest) baseline = times[^2];
        }

        var currentRows = allRows.Where(r => r.CollectionTime == latest).ToList();
        var baselineRows = allRows.Where(r => r.CollectionTime == baseline).ToList();
        var diff = SnapshotDiff.Diff(currentRows, baselineRows);
        var days = (int)Math.Round((latest - baseline).TotalDays);

        return new PeriodComparison(period, diff, baseline, latest, days, exact, true);
    }
}
