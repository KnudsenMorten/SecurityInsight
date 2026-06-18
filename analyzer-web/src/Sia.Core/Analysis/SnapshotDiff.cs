using Sia.Core.Model;

namespace Sia.Core.Analysis;

/// <summary>A finding whose score moved between two snapshots.</summary>
public sealed record ScoreMove(RiskRow Row, double PreviousScore, double CurrentScore, double Delta);

/// <summary>The new/closed/open/regressed/improved breakdown + score totals between two snapshots.</summary>
public sealed record DiffResult(
    IReadOnlyList<RiskRow> New,
    IReadOnlyList<RiskRow> Closed,
    IReadOnlyList<RiskRow> Open,
    IReadOnlyList<ScoreMove> Regressed,
    IReadOnlyList<ScoreMove> Improved,
    double CurrentTotal,
    double PreviousTotal,
    double ScoreDelta,
    DateTimeOffset? CurrentTime,
    DateTimeOffset? PreviousTime)
{
    public int NewCount => New.Count;
    public int ClosedCount => Closed.Count;
    public int OpenCount => Open.Count;
    public int RegressedCount => Regressed.Count;
    public int ImprovedCount => Improved.Count;
}

/// <summary>One point on the risk-score timeline (per CollectionTime snapshot).</summary>
public sealed record TimelinePoint(
    DateTimeOffset CollectionTime,
    double TotalScore,
    int FindingCount,
    IReadOnlyDictionary<string, double> PerTier,
    double? DeltaFromPrev,
    double? PercentFromPrev);

/// <summary>
/// Pure snapshot-diff + score-timeline math - the C# port of
/// analyzer/lib/SiAnalyzer-Diff.ps1. Operates on already-fetched RA rows; no network.
/// Identity is <see cref="RiskRow.ConfigurationId"/>; snapshots are keyed by
/// <see cref="RiskRow.CollectionTime"/>.
///
/// Definitions (kept identical to the PS POC):
///   new       - present now, absent before
///   closed    - present before, absent now (or score fell to/below ClosedThreshold)
///   open      - present in both
///   regressed - open AND score went up by >= MoveThreshold
///   improved  - open AND score went down by >= MoveThreshold
/// </summary>
public static class SnapshotDiff
{
    /// <summary>Distinct CollectionTimes present in the rows, ascending.</summary>
    public static IReadOnlyList<DateTimeOffset> CollectionTimes(IEnumerable<RiskRow> rows) =>
        rows.Select(r => r.CollectionTime).Distinct().OrderBy(t => t).ToList();

    /// <summary>Rows for the latest snapshot only (max CollectionTime).</summary>
    public static IReadOnlyList<RiskRow> LatestSnapshot(IReadOnlyCollection<RiskRow> rows)
    {
        if (rows.Count == 0) return Array.Empty<RiskRow>();
        var max = rows.Max(r => r.CollectionTime);
        return rows.Where(r => r.CollectionTime == max).ToList();
    }

    /// <summary>Auto mode: diff the two most-recent snapshots in <paramref name="rows"/>.</summary>
    public static DiffResult Diff(IReadOnlyCollection<RiskRow> rows, double closedThreshold = 0, double moveThreshold = 0.01)
    {
        var times = CollectionTimes(rows);
        if (times.Count == 0)
        {
            return new DiffResult(
                Array.Empty<RiskRow>(), Array.Empty<RiskRow>(), Array.Empty<RiskRow>(),
                Array.Empty<ScoreMove>(), Array.Empty<ScoreMove>(),
                0, 0, 0, null, null);
        }
        var cur = times[^1];
        DateTimeOffset? prev = times.Count >= 2 ? times[^2] : null;
        var currentRows = rows.Where(r => r.CollectionTime == cur).ToList();
        var previousRows = prev.HasValue ? rows.Where(r => r.CollectionTime == prev.Value).ToList() : new List<RiskRow>();
        return Diff(currentRows, previousRows, closedThreshold, moveThreshold);
    }

    /// <summary>Explicit mode: diff two given snapshots.</summary>
    public static DiffResult Diff(
        IReadOnlyCollection<RiskRow> currentRows,
        IReadOnlyCollection<RiskRow> previousRows,
        double closedThreshold = 0,
        double moveThreshold = 0.01)
    {
        // Index by ConfigurationId (last write wins per snapshot).
        var curIdx = new Dictionary<string, RiskRow>();
        foreach (var r in currentRows) curIdx[r.ConfigurationId] = r;
        var prevIdx = new Dictionary<string, RiskRow>();
        foreach (var r in previousRows) prevIdx[r.ConfigurationId] = r;

        var @new = new List<RiskRow>();
        var closed = new List<RiskRow>();
        var open = new List<RiskRow>();
        var regressed = new List<ScoreMove>();
        var improved = new List<ScoreMove>();

        foreach (var (id, row) in curIdx)
        {
            var curScore = row.RiskScoreTotal;
            if (!prevIdx.TryGetValue(id, out var prevRow))
            {
                @new.Add(row);
            }
            else
            {
                open.Add(row);
                var delta = curScore - prevRow.RiskScoreTotal;
                if (delta >= moveThreshold)
                {
                    regressed.Add(new ScoreMove(row, prevRow.RiskScoreTotal, curScore, delta));
                }
                else if (delta <= -moveThreshold)
                {
                    improved.Add(new ScoreMove(row, prevRow.RiskScoreTotal, curScore, delta));
                }
            }
        }

        // Closed = in previous, not in current, OR present-but-fell to/below threshold.
        foreach (var (id, prevRow) in prevIdx)
        {
            if (!curIdx.TryGetValue(id, out var curRow))
            {
                closed.Add(prevRow);
            }
            else if (prevRow.RiskScoreTotal > closedThreshold && curRow.RiskScoreTotal <= closedThreshold)
            {
                closed.Add(curRow);
            }
        }

        var curTotal = currentRows.Sum(r => r.RiskScoreTotal);
        var prevTotal = previousRows.Sum(r => r.RiskScoreTotal);
        DateTimeOffset? curTime = currentRows.Count > 0 ? currentRows.First().CollectionTime : null;
        DateTimeOffset? prevTime = previousRows.Count > 0 ? previousRows.First().CollectionTime : null;

        return new DiffResult(
            @new, closed, open, regressed, improved,
            Math.Round(curTotal, 2),
            Math.Round(prevTotal, 2),
            Math.Round(curTotal - prevTotal, 2),
            curTime, prevTime);
    }

    /// <summary>
    /// Score timeline: one point per CollectionTime with total, count, per-tier
    /// breakdown, and the percent delta vs the prior point (for "down 12%" captions).
    /// Mirrors Get-SiScoreTimeline.
    /// </summary>
    public static IReadOnlyList<TimelinePoint> Timeline(IEnumerable<RiskRow> rows)
    {
        var byTime = rows
            .GroupBy(r => r.CollectionTime)
            .OrderBy(g => g.Key)
            .ToList();

        var result = new List<TimelinePoint>();
        TimelinePoint? prev = null;
        foreach (var g in byTime)
        {
            var total = g.Sum(r => r.RiskScoreTotal);
            var perTier = g
                .GroupBy(r => string.IsNullOrEmpty(r.CriticalityTierLevel) ? "Unclassified" : r.CriticalityTierLevel)
                .ToDictionary(x => x.Key, x => Math.Round(x.Sum(r => r.RiskScoreTotal), 2));

            double? delta = null, pct = null;
            if (prev is not null && prev.TotalScore != 0)
            {
                delta = Math.Round(total - prev.TotalScore, 2);
                pct = Math.Round((total - prev.TotalScore) / prev.TotalScore * 100, 1);
            }

            var pt = new TimelinePoint(g.Key, Math.Round(total, 2), g.Count(), perTier, delta, pct);
            result.Add(pt);
            prev = pt;
        }
        return result;
    }
}
