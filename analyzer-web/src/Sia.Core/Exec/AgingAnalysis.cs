using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>
/// One top risk with how long it has been open (accountability lens). All values are
/// derived from the snapshot history in the RA rows - <see cref="OpenSince"/> is the
/// earliest CollectionTime in the UNBROKEN run of snapshots in which this
/// ConfigurationId has carried risk, up to and including the latest snapshot; nothing
/// is invented. <see cref="SnapshotsOpen"/> is how many consecutive snapshots it has
/// persisted; <see cref="DaysOpen"/> spans OpenSince..latest. <see cref="IsNew"/> is
/// true when it first appeared in the latest snapshot.
/// </summary>
public sealed record AgingItem(
    string ConfigurationName,
    string SecuritySeverity,
    double RiskScoreTotal,
    DateTimeOffset OpenSince,
    int SnapshotsOpen,
    int DaysOpen,
    bool IsNew);

/// <summary>
/// The board-facing aging / time-open summary: how long the worst risks have been
/// open, plus the count of risks open longer than one snapshot. Plain accountability
/// signal - "these have been open for N days".
/// </summary>
public sealed record AgingSummary(
    IReadOnlyList<AgingItem> Items,
    double AverageDaysOpen,
    int LongestDaysOpen,
    int CarriedOverCount,
    int NewThisSnapshotCount);

/// <summary>
/// Aging / time-open analysis (REQUIREMENTS.md "SI Analyzer" - "Aging / time-open: how long
/// the top risks have been open (accountability)"). Pure aggregation over the snapshot
/// history already present in the RA rows; no network, no invented dates.
/// </summary>
public static class AgingAnalysis
{
    /// <summary>
    /// Build the aging summary for the top-<paramref name="top"/> risks of the latest snapshot.
    /// </summary>
    public static AgingSummary Build(IReadOnlyCollection<RiskRow> allRows, int top = 5)
    {
        var times = allRows.Select(r => r.CollectionTime).Distinct().OrderBy(t => t).ToList();
        if (times.Count == 0)
        {
            return new AgingSummary(Array.Empty<AgingItem>(), 0, 0, 0, 0);
        }

        var latestTime = times[^1];
        // Index: ConfigurationId -> set of snapshot times it appears in.
        var seenByConfig = allRows
            .GroupBy(r => r.ConfigurationId)
            .ToDictionary(g => g.Key, g => g.Select(r => r.CollectionTime).ToHashSet());

        var latest = allRows
            .Where(r => r.CollectionTime == latestTime)
            .OrderByDescending(r => r.RiskScoreTotal)
            .ToList();

        var items = new List<AgingItem>();
        foreach (var r in latest.Take(top))
        {
            var seen = seenByConfig.TryGetValue(r.ConfigurationId, out var s) ? s : new HashSet<DateTimeOffset> { latestTime };
            var (openSince, snapshotsOpen) = OpenRun(times, seen, latestTime);
            var daysOpen = (int)Math.Round((latestTime - openSince).TotalDays);
            items.Add(new AgingItem(
                r.ConfigurationName,
                r.SecuritySeverity,
                Math.Round(r.RiskScoreTotal, 1),
                openSince,
                snapshotsOpen,
                daysOpen,
                IsNew: snapshotsOpen <= 1));
        }

        var avg = items.Count == 0 ? 0 : Math.Round(items.Average(i => i.DaysOpen), 1);
        var longest = items.Count == 0 ? 0 : items.Max(i => i.DaysOpen);
        var carried = items.Count(i => !i.IsNew);
        var newCount = items.Count(i => i.IsNew);

        return new AgingSummary(items, avg, longest, carried, newCount);
    }

    /// <summary>
    /// Walk backwards from the latest snapshot while the config is present in each
    /// consecutive snapshot; return the earliest still-unbroken time + the run length.
    /// A gap (absent in an earlier snapshot) stops the run - we only count the CURRENT
    /// continuous open spell, not a prior, already-closed appearance.
    /// </summary>
    private static (DateTimeOffset openSince, int runLength) OpenRun(
        IReadOnlyList<DateTimeOffset> times,
        HashSet<DateTimeOffset> seen,
        DateTimeOffset latestTime)
    {
        var openSince = latestTime;
        var run = 0;
        for (var i = times.Count - 1; i >= 0; i--)
        {
            if (!seen.Contains(times[i])) break;
            openSince = times[i];
            run++;
        }
        if (run == 0) { openSince = latestTime; run = 1; }
        return (openSince, run);
    }
}
