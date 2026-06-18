using Sia.Core.Analysis;
using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>
/// Where risk concentrates for ONE area (security domain / business area), in board
/// language. <see cref="Score"/> is the summed RA risk for the area in the latest
/// snapshot; <see cref="SharePercent"/> is its share of the total (the shares sum to
/// 100); <see cref="Direction"/> + <see cref="ChangePercent"/> are period-over-period vs
/// the chosen baseline snapshot; <see cref="TopContributor"/> names the single
/// highest-scoring asset in the area so leadership knows what is driving it. All values
/// are grounded in the rows - nothing invented.
/// </summary>
public sealed record DomainConcentration(
    string Area,
    string Plain,
    double Score,
    double SharePercent,
    int Findings,
    string Direction,
    double? ChangePercent,
    string TopContributor);

/// <summary>The risk-concentration breakdown: where the risk sits by area, highest first,
/// plus the single most-concentrated area as a one-line "invest here" steer.</summary>
public sealed record RiskConcentrationView(
    IReadOnlyList<DomainConcentration> Areas,
    string? MostConcentratedArea,
    double TotalScore);

/// <summary>
/// Risk by domain / business unit (REQUIREMENTS.md "SI Analyzer" - "Risk by domain /
/// business unit: where risk concentrates (identity vs endpoint vs cloud) so leadership
/// knows where to invest"). Unlike the raw by-domain donut, this adds each area's SHARE
/// of the total, its period-over-period DIRECTION, and its TOP CONTRIBUTOR - the
/// "where do we invest" lens. Pure grounded aggregation over the latest snapshot +
/// a baseline snapshot; no network, no AI, no invented numbers.
/// </summary>
public static class RiskConcentration
{
    /// <summary>
    /// Build the concentration view. <paramref name="baseline"/> (the period baseline
    /// snapshot rows) is optional; when supplied, each area carries a period-over-period
    /// direction vs the baseline. Areas are grouped by <see cref="RiskRow.SecurityDomain"/>
    /// (the SI domain = the closest thing to a business area in the RA schema).
    /// </summary>
    public static RiskConcentrationView Build(
        IReadOnlyList<RiskRow> latest,
        IReadOnlyList<RiskRow>? baseline = null)
    {
        var total = Math.Round(latest.Sum(r => r.RiskScoreTotal), 1);

        // Baseline per-area score for the period-over-period direction (grounded).
        var basePerArea = (baseline ?? Array.Empty<RiskRow>())
            .GroupBy(AreaKey)
            .ToDictionary(g => g.Key, g => g.Sum(r => r.RiskScoreTotal), StringComparer.OrdinalIgnoreCase);

        var areas = latest
            .GroupBy(AreaKey)
            .Select(g =>
            {
                var score = Math.Round(g.Sum(r => r.RiskScoreTotal), 1);
                var share = total <= 0 ? 0 : Math.Round(score / total * 100, 1);
                var top = g.OrderByDescending(r => r.RiskScoreTotal).First().ConfigurationName;

                string direction = "steady";
                double? changePct = null;
                if (baseline is not null && baseline.Count > 0)
                {
                    var prev = basePerArea.TryGetValue(g.Key, out var p) ? p : 0;
                    var delta = g.Sum(r => r.RiskScoreTotal) - prev;
                    direction = delta < -0.01 ? "improving" : delta > 0.01 ? "worsening" : "steady";
                    changePct = prev != 0 ? Math.Round((g.Sum(r => r.RiskScoreTotal) - prev) / prev * 100, 1) : null;
                }

                return new DomainConcentration(
                    g.Key, AreaPlain(g.Key), score, share, g.Count(), direction, changePct, top);
            })
            .OrderByDescending(a => a.Score)
            .ToList();

        var most = areas.Count > 0 ? areas[0].Area : null;
        return new RiskConcentrationView(areas, most, total);
    }

    /// <summary>Map a row to its area label. Empty domain becomes a clear "Other" bucket
    /// (never silently dropped) so the shares still add up to the headline total.</summary>
    private static string AreaKey(RiskRow r) =>
        string.IsNullOrWhiteSpace(r.SecurityDomain) ? "other" : r.SecurityDomain.Trim().ToLowerInvariant();

    /// <summary>Plain board names for the SI domains - "identity vs endpoint vs cloud".</summary>
    private static string AreaPlain(string area) => area switch
    {
        "endpoint" => "Endpoints (servers & workstations)",
        "identity" => "Identity & access",
        "azure" => "Cloud platform",
        "publicip" => "Internet-facing exposure",
        "other" => "Other assets",
        _ => char.ToUpperInvariant(area[0]) + area[1..],
    };
}
