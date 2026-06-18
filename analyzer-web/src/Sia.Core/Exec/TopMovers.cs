using Sia.Core.Analysis;
using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>
/// One dimension slice (e.g. a security area, a severity band or a tier) whose summed
/// risk score MOVED between the baseline and the latest snapshot. <see cref="Delta"/> is
/// the signed change in summed <see cref="RiskRow.RiskScoreTotal"/> for the slice
/// (negative = improved, positive = worsened); <see cref="Direction"/> is the plain word.
/// All values are grounded in the rows - nothing invented.
/// </summary>
public sealed record DimensionMove(
    string Slice,
    string Plain,
    double PreviousScore,
    double CurrentScore,
    double Delta,
    double? ChangePercent,
    string Direction);

/// <summary>
/// The "trends and top movers" rollup: which AREAS / SEVERITY BANDS / TIERS improved the
/// most and which worsened the most between two snapshots. Unlike the raw per-finding
/// improved/regressed lists (which a CIO cannot parse), this answers the board question
/// "what moved?" at the level leadership reasons about. <see cref="HasComparison"/> is
/// false when there is only one snapshot - the UI must then state that honestly rather
/// than imply a trend.
/// </summary>
public sealed record TopMoversView(
    bool HasComparison,
    DateTimeOffset? BaselineTime,
    DateTimeOffset? CurrentTime,
    double TotalDelta,
    IReadOnlyList<DimensionMove> BiggestImprovements,
    IReadOnlyList<DimensionMove> BiggestRegressions,
    IReadOnlyList<DimensionMoveGroup> Groups);

/// <summary>A whole dimension's set of slice moves (e.g. all the "by area" moves), so the
/// UI can show the full picture per lens, not only the single biggest mover.</summary>
public sealed record DimensionMoveGroup(
    string Dimension,
    string Plain,
    IReadOnlyList<DimensionMove> Moves);

/// <summary>
/// Trends and top movers (REQUIREMENTS.md "SI Analyzer" - Surface B "Trends &amp; top
/// movers: by tier, severity, domain; biggest improvements and biggest regressions;
/// counts + direction arrows, all in plain language").
///
/// Pure, grounded aggregation: it diffs the SUMMED risk score per slice between the
/// latest snapshot and a baseline snapshot (the immediately-prior one by default, or a
/// supplied period baseline). Every slice's previous/current/delta is a real sum of real
/// rows; the only derived value is the percentage, and that is null when the baseline was
/// zero. No AI, no network, no invented numbers. When only one snapshot exists,
/// <see cref="TopMoversView.HasComparison"/> is false so the surface tells the truth.
/// </summary>
public static class TopMovers
{
    public const string DimArea = "area";
    public const string DimSeverity = "severity";
    public const string DimTier = "tier";

    /// <summary>How many movers to surface per direction (the "biggest" lists).</summary>
    private const int TopN = 3;

    /// <summary>Movement smaller than this (in score points) counts as "steady" - it stops
    /// floating-point dust being reported as a real change.</summary>
    private const double Epsilon = 0.01;

    /// <summary>
    /// Build the top-movers view. <paramref name="baseline"/> is optional; when null the
    /// immediately-prior snapshot is used (auto mode). When the data has only one snapshot
    /// (no baseline resolvable), the result reports <see cref="TopMoversView.HasComparison"/>
    /// = false and empty mover lists - the caller must render that honestly.
    /// </summary>
    public static TopMoversView Build(
        IReadOnlyCollection<RiskRow> allRows,
        IReadOnlyList<RiskRow>? baseline = null)
    {
        var latest = SnapshotDiff.LatestSnapshot(allRows);
        var currentTime = latest.Count > 0 ? latest[0].CollectionTime : (DateTimeOffset?)null;

        // Resolve the baseline snapshot: explicit if supplied, else the immediately-prior one.
        IReadOnlyList<RiskRow> baseRows;
        DateTimeOffset? baselineTime;
        if (baseline is not null)
        {
            baseRows = baseline;
            baselineTime = baseline.Count > 0 ? baseline[0].CollectionTime : null;
        }
        else
        {
            var times = SnapshotDiff.CollectionTimes(allRows);
            if (times.Count >= 2)
            {
                baselineTime = times[^2];
                var bt = baselineTime.Value;
                baseRows = allRows.Where(r => r.CollectionTime == bt).ToList();
            }
            else
            {
                baseRows = Array.Empty<RiskRow>();
                baselineTime = null;
            }
        }

        // No comparison possible (single snapshot or no baseline). Be honest.
        if (baselineTime is null || baselineTime == currentTime || latest.Count == 0)
        {
            return new TopMoversView(
                HasComparison: false,
                BaselineTime: null,
                CurrentTime: currentTime,
                TotalDelta: 0,
                BiggestImprovements: Array.Empty<DimensionMove>(),
                BiggestRegressions: Array.Empty<DimensionMove>(),
                Groups: Array.Empty<DimensionMoveGroup>());
        }

        var groups = new[]
        {
            BuildGroup(DimArea, "By area", latest, baseRows, AreaKey, AreaPlain),
            BuildGroup(DimSeverity, "By severity", latest, baseRows, SeverityKey, SeverityPlain),
            BuildGroup(DimTier, "By tier", latest, baseRows, TierKey, TierPlain),
        };

        // The "biggest movers" lists pull from the BY-AREA lens - the one a CIO reasons
        // about ("identity got worse, endpoints improved"). Improvements are the most-
        // negative deltas; regressions the most-positive.
        var areaMoves = groups[0].Moves;
        var improvements = areaMoves
            .Where(m => m.Delta < -Epsilon)
            .OrderBy(m => m.Delta)
            .Take(TopN)
            .ToList();
        var regressions = areaMoves
            .Where(m => m.Delta > Epsilon)
            .OrderByDescending(m => m.Delta)
            .Take(TopN)
            .ToList();

        var totalDelta = Math.Round(latest.Sum(r => r.RiskScoreTotal) - baseRows.Sum(r => r.RiskScoreTotal), 1);

        return new TopMoversView(
            HasComparison: true,
            BaselineTime: baselineTime,
            CurrentTime: currentTime,
            TotalDelta: totalDelta,
            BiggestImprovements: improvements,
            BiggestRegressions: regressions,
            Groups: groups);
    }

    /// <summary>Diff one dimension: sum each slice's score in both snapshots and emit the
    /// move. Slices present in EITHER snapshot are included (a slice that disappeared counts
    /// as an improvement to 0; a brand-new slice counts as a regression from 0) so no real
    /// movement is dropped. Sorted biggest-absolute-move first.</summary>
    private static DimensionMoveGroup BuildGroup(
        string dimension,
        string plain,
        IReadOnlyList<RiskRow> latest,
        IReadOnlyList<RiskRow> baseRows,
        Func<RiskRow, string> key,
        Func<string, string> sliceName)
    {
        var cur = latest.GroupBy(key).ToDictionary(g => g.Key, g => g.Sum(r => r.RiskScoreTotal), StringComparer.OrdinalIgnoreCase);
        var prev = baseRows.GroupBy(key).ToDictionary(g => g.Key, g => g.Sum(r => r.RiskScoreTotal), StringComparer.OrdinalIgnoreCase);

        var slices = cur.Keys.Union(prev.Keys, StringComparer.OrdinalIgnoreCase);
        var moves = new List<DimensionMove>();
        foreach (var s in slices)
        {
            var c = cur.TryGetValue(s, out var cv) ? cv : 0;
            var p = prev.TryGetValue(s, out var pv) ? pv : 0;
            var delta = Math.Round(c - p, 1);
            double? pct = p != 0 ? Math.Round((c - p) / p * 100, 1) : null;
            var dir = delta < -Epsilon ? "improving" : delta > Epsilon ? "worsening" : "steady";
            moves.Add(new DimensionMove(s, sliceName(s), Math.Round(p, 1), Math.Round(c, 1), delta, pct, dir));
        }

        moves = moves.OrderByDescending(m => Math.Abs(m.Delta)).ToList();
        return new DimensionMoveGroup(dimension, plain, moves);
    }

    // --- slice keys + plain names (shared vocabulary with RiskConcentration) ---

    private static string AreaKey(RiskRow r) =>
        string.IsNullOrWhiteSpace(r.SecurityDomain) ? "other" : r.SecurityDomain.Trim().ToLowerInvariant();

    private static string AreaPlain(string area) => area switch
    {
        "endpoint" => "Endpoints (servers & workstations)",
        "identity" => "Identity & access",
        "azure" => "Cloud platform",
        "publicip" => "Internet-facing exposure",
        "other" => "Other assets",
        _ => char.ToUpperInvariant(area[0]) + area[1..],
    };

    private static string SeverityKey(RiskRow r) =>
        string.IsNullOrWhiteSpace(r.SecuritySeverity) ? "Unknown" : r.SecuritySeverity.Trim();

    private static string SeverityPlain(string sev) => sev;

    private static string TierKey(RiskRow r) =>
        string.IsNullOrWhiteSpace(r.CriticalityTierLevel) ? "Unclassified" : r.CriticalityTierLevel.Trim();

    private static string TierPlain(string tier) => tier;
}
