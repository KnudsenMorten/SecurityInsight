using Sia.Core.Analysis;
using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>One evidence row behind a headline number: the contributing finding, its own
/// score, and that score's SHARE of the drill-down total. Grounded - it is an actual RA
/// row from the latest snapshot, never a synthesised example.</summary>
public sealed record EvidenceRow(
    string ConfigurationName,
    string SecurityDomain,
    string SecuritySeverity,
    double RiskScoreTotal,
    double SharePercent,
    string Why);

/// <summary>
/// The grounded evidence behind ONE headline number (the overall score, an area, or a
/// severity band). <see cref="Total"/> is the number the exec saw; <see cref="Items"/> are
/// the top contributing findings; <see cref="ContributorCount"/> is how MANY findings make
/// up the number (so "top 10 of 142" is honest); <see cref="ShownScore"/> is how much of
/// the total the shown rows account for. This is the "clean-by-default, drill-down on
/// demand" reveal - no black-box claims; every number traces to rows.
/// </summary>
public sealed record DrilldownView(
    string Dimension,
    string Key,
    string Plain,
    double Total,
    int ContributorCount,
    double ShownScore,
    IReadOnlyList<EvidenceRow> Items);

/// <summary>
/// Clean-by-default, drill-down on demand (REQUIREMENTS.md "SI Analyzer" - "a 'show me the
/// detail' reveals the grounded analyst evidence behind any number (no black-box claims)").
/// Given a dimension + key, returns the latest-snapshot rows that SUM to that headline
/// number, so an exec can expand any figure and see exactly which findings produced it.
/// Pure aggregation over the already-fetched rows - no network, no AI, no invented numbers.
/// </summary>
public static class Drilldown
{
    /// <summary>Dimensions a number on the exec surface can be drilled into.</summary>
    public const string DimOverall = "overall";
    public const string DimDomain = "domain";
    public const string DimSeverity = "severity";
    public const string DimTier = "tier";

    /// <summary>
    /// Build the evidence behind a headline number. <paramref name="allRows"/> is the full
    /// row set (the latest snapshot is selected internally so the reveal is snapshot-correct).
    /// <paramref name="dimension"/> is one of the Dim* constants; <paramref name="key"/>
    /// selects the slice (e.g. domain "identity", severity "Critical"); null/empty key with
    /// the "overall" dimension drills the whole headline score.
    /// </summary>
    public static DrilldownView Build(IReadOnlyCollection<RiskRow> allRows, string dimension, string? key, int top = 10)
    {
        var latest = SnapshotDiff.LatestSnapshot(allRows);
        var dim = (dimension ?? "").Trim().ToLowerInvariant();
        var k = (key ?? "").Trim();

        IEnumerable<RiskRow> slice = dim switch
        {
            DimDomain => latest.Where(r => Eq(r.SecurityDomain, k)),
            DimSeverity => latest.Where(r => Eq(r.SecuritySeverity, k)),
            DimTier => latest.Where(r => Eq(r.CriticalityTierLevel, k)),
            _ => latest, // overall (also the fallback for an unknown dimension)
        };

        var sliceRows = slice.ToList();
        var total = Math.Round(sliceRows.Sum(r => r.RiskScoreTotal), 1);

        var items = sliceRows
            .OrderByDescending(r => r.RiskScoreTotal)
            .Take(top)
            .Select(r => new EvidenceRow(
                r.ConfigurationName,
                r.SecurityDomain ?? "",
                r.SecuritySeverity ?? "",
                Math.Round(r.RiskScoreTotal, 1),
                total <= 0 ? 0 : Math.Round(r.RiskScoreTotal / total * 100, 1),
                string.IsNullOrWhiteSpace(r.RiskFactorConsequence) ? (r.RiskFactorProbability ?? "") : r.RiskFactorConsequence))
            .ToList();

        var shown = Math.Round(items.Sum(i => i.RiskScoreTotal), 1);
        var plain = Plain(dim, k);

        return new DrilldownView(
            dim is DimOverall or DimDomain or DimSeverity or DimTier ? dim : DimOverall,
            k, plain, total, sliceRows.Count, shown, items);
    }

    private static bool Eq(string? value, string key) =>
        string.Equals((value ?? "").Trim(), key, StringComparison.OrdinalIgnoreCase);

    private static string Plain(string dim, string key) => dim switch
    {
        DimDomain => $"Findings in the '{KeyOrAll(key)}' area",
        DimSeverity => $"{KeyOrAll(key)}-severity findings",
        DimTier => $"Findings at '{KeyOrAll(key)}'",
        _ => "All findings behind the overall score",
    };

    private static string KeyOrAll(string key) => string.IsNullOrWhiteSpace(key) ? "all" : key;
}
