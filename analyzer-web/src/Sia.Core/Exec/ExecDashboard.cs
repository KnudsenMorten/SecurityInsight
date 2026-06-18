using Sia.Core.Analysis;
using Sia.Core.Model;

namespace Sia.Core.Exec;

/// <summary>A labelled slice for a donut/bar chart.</summary>
public sealed record ChartSlice(string Label, double Value);

/// <summary>A board-ready quick win: a fix with an estimated score reduction.</summary>
public sealed record QuickWin(string Title, string Plain, double ProjectedScoreDrop, int AffectedAssets, string Urgency);

/// <summary>One timeline point flattened for charting + a forecast flag.</summary>
public sealed record TrendPoint(string Date, double Score, int FindingCount, bool IsForecast);

/// <summary>A coverage/confidence banner fact.</summary>
public sealed record CoverageFact(string Dimension, string Plain, double Percent);

/// <summary>
/// The board-ready executive dashboard view-model. Pure aggregation over RA rows +
/// the snapshot diff/timeline cores - NO AI numbers, NO invented data. The AI
/// narrative is layered on TOP (the exec summary text) by the Web layer; every number
/// on this object is computed from the rows so the AI can never fabricate a figure.
///
/// Implements the exec-surface content from REQUIREMENTS.md "SI Analyzer":
/// headline RISK SCORE + direction, severity/domain donuts, trend with a LABELLED
/// forecast, risks+wins, quick-wins/ROI, coverage&confidence, period-over-period.
/// Projections/forecasts are explicitly labelled (IsForecast / "projected").
/// </summary>
public sealed record ExecDashboard(
    ExecHeadline Headline,
    double HeadlineScore,
    string ScoreBand,
    string Direction,
    double ScoreDelta,
    double? PercentChange,
    int TotalFindings,
    int NewCount,
    int ClosedCount,
    int RegressedCount,
    int ImprovedCount,
    DateTimeOffset? CurrentTime,
    DateTimeOffset? PreviousTime,
    IReadOnlyList<ChartSlice> BySeverity,
    IReadOnlyList<ChartSlice> ByDomain,
    IReadOnlyList<ChartSlice> ByTier,
    IReadOnlyList<TrendPoint> Trend,
    IReadOnlyList<RiskRow> TopRisks,
    IReadOnlyList<RiskRow> TopWins,
    IReadOnlyList<QuickWin> QuickWins,
    IReadOnlyList<CoverageFact> Coverage,
    IReadOnlyList<FrameworkView> Frameworks,
    AgingSummary Aging,
    PeriodComparison Period,
    RiskConcentrationView Concentration,
    TopMoversView Movers,
    BusinessImpactView BusinessImpact,
    DrilldownView OverallEvidence,
    RemediationPlanView Remediation,
    GlossaryView Glossary,
    OrgCoachingView Coaching,
    MaturityScorecardView Maturity);

/// <summary>Builds the <see cref="ExecDashboard"/> from the full RA row set.</summary>
public static class ExecDashboardBuilder
{
    /// <summary>
    /// Build the exec view from ALL rows (no cap - the rollup uses the full set;
    /// "top N" lists are VIEWS, not a data cap, per the no-silent-caps rule).
    /// </summary>
    /// <param name="forecastFactor">
    /// Linear projection multiplier for the labelled forecast point. Derived from the
    /// last observed period-over-period change; always rendered as a clearly-labelled
    /// projection, never as measured data.
    /// </param>
    /// <param name="periodKey">
    /// The reporting period the exec wants the period-over-period comparison to snap to
    /// (see <see cref="ReportingPeriod.Presets"/>; e.g. "quarter" = "since last board
    /// meeting"). Null/unknown defaults to the quarter. The HEADLINE diff is always the
    /// immediately-prior snapshot; the period comparison is the configurable view.
    /// </param>
    public static ExecDashboard Build(IReadOnlyCollection<RiskRow> allRows, string? periodKey = null)
    {
        var latest = SnapshotDiff.LatestSnapshot(allRows);
        var diff = SnapshotDiff.Diff(allRows);
        var timeline = SnapshotDiff.Timeline(allRows);

        var period = PeriodComparisonBuilder.Build(allRows, ReportingPeriod.Resolve(periodKey));
        var baselineRows = period.BaselineTime is { } bt
            ? allRows.Where(r => r.CollectionTime == bt).ToList()
            : null;
        var concentration = RiskConcentration.Build(latest, baselineRows);
        // Top movers diff against the SAME period baseline as the concentration view, so
        // "what moved" and "where it concentrates" tell one consistent story. Falls back
        // to the immediately-prior snapshot (auto mode) when no period baseline exists.
        var movers = TopMovers.Build(allRows, baselineRows);

        var headline = Math.Round(latest.Sum(r => r.RiskScoreTotal), 1);
        var headlineVerdict = ExecHeadlineBuilder.Build(latest, diff.ScoreDelta, diff.PreviousTotal);
        var direction = diff.ScoreDelta < 0 ? "improving" : diff.ScoreDelta > 0 ? "worsening" : "steady";
        double? pct = diff.PreviousTotal != 0
            ? Math.Round((diff.CurrentTotal - diff.PreviousTotal) / diff.PreviousTotal * 100, 1)
            : null;

        var bySeverity = latest
            .GroupBy(r => string.IsNullOrEmpty(r.SecuritySeverity) ? "Unknown" : r.SecuritySeverity)
            .Select(g => new ChartSlice(g.Key, Math.Round(g.Sum(r => r.RiskScoreTotal), 1)))
            .OrderByDescending(s => s.Value)
            .ToList();

        var byDomain = latest
            .GroupBy(r => string.IsNullOrEmpty(r.SecurityDomain) ? "Unknown" : r.SecurityDomain)
            .Select(g => new ChartSlice(g.Key, Math.Round(g.Sum(r => r.RiskScoreTotal), 1)))
            .OrderByDescending(s => s.Value)
            .ToList();

        var byTier = latest
            .GroupBy(r => string.IsNullOrEmpty(r.CriticalityTierLevel) ? "Unclassified" : r.CriticalityTierLevel)
            .Select(g => new ChartSlice(g.Key, Math.Round(g.Sum(r => r.RiskScoreTotal), 1)))
            .OrderByDescending(s => s.Value)
            .ToList();

        var trend = BuildTrend(timeline);

        var topRisks = latest.OrderByDescending(r => r.RiskScoreTotal).Take(5).ToList();
        var topWins = diff.Improved.OrderBy(m => m.Delta).Take(5).Select(m => m.Row).ToList();
        var quickWins = BuildQuickWins(latest);
        var coverage = BuildCoverage(latest);
        var frameworks = FrameworkLens.Build(latest);
        var aging = AgingAnalysis.Build(allRows);
        var businessImpact = BusinessImpact.Build(latest);
        // The "drill-down on demand" reveal for the headline number itself; per-slice
        // drill-downs are served on demand by the service/MCP, not baked into the model.
        var overallEvidence = Drilldown.Build(allRows, Drilldown.DimOverall, null);
        // Prioritised "next 5 actions" remediation plan, ranked by risk-removed-per-effort.
        var remediation = RemediationPlan.Build(allRows, top: 5);
        // Plain-language glossary: every jargon term on this page defined, present-now
        // terms surfaced first, each with a GROUNDED example from the real rows.
        var glossary = Glossary.Build(allRows);
        // Missing processes / org coaching: the leadership-level maturity gaps the finding
        // PATTERNS imply (privileged-access reviews, exposure reviews, patch cadence, ...),
        // grounded in real rows, honest when no systemic gap stands out.
        var coaching = OrgCoaching.Build(allRows);
        // Maturity scorecard + roadmap: roll the recurring drift drivers up into a leader-facing
        // capability view (Tiering, Privileged Access, Identity Hygiene, Exposure Management,
        // Visibility & Coverage, Operating Discipline) - "where the environment and behaviour need
        // to mature so these findings stop coming back." Rule-based, grounded, honest on no data.
        var maturity = MaturityScorecard.Build(allRows);

        return new ExecDashboard(
            headlineVerdict,
            headline, ScoreBand(headline), direction,
            diff.ScoreDelta, pct,
            latest.Count, diff.NewCount, diff.ClosedCount, diff.RegressedCount, diff.ImprovedCount,
            diff.CurrentTime, diff.PreviousTime,
            bySeverity, byDomain, byTier,
            trend, topRisks, topWins, quickWins, coverage,
            frameworks, aging, period, concentration, movers,
            businessImpact, overallEvidence, remediation, glossary, coaching, maturity);
    }

    /// <summary>Map the headline score to a plain board band.</summary>
    public static string ScoreBand(double score) => score switch
    {
        >= 400 => "Severe",
        >= 200 => "Elevated",
        >= 75 => "Moderate",
        _ => "Low",
    };

    private static IReadOnlyList<TrendPoint> BuildTrend(IReadOnlyList<TimelinePoint> timeline)
    {
        var pts = timeline
            .Select(p => new TrendPoint(p.CollectionTime.ToString("yyyy-MM-dd"), p.TotalScore, p.FindingCount, false))
            .ToList();

        // Labelled linear forecast: extend one step using the last observed delta.
        // Always flagged IsForecast=true so the UI renders it dashed/"projected".
        if (timeline.Count >= 2)
        {
            var last = timeline[^1];
            var prev = timeline[^2];
            var delta = last.TotalScore - prev.TotalScore;
            var projected = Math.Max(0, Math.Round(last.TotalScore + delta, 1));
            var step = last.CollectionTime - prev.CollectionTime;
            var forecastDate = last.CollectionTime + step;
            pts.Add(new TrendPoint(forecastDate.ToString("yyyy-MM-dd"), projected, last.FindingCount, true));
        }
        return pts;
    }

    private static IReadOnlyList<QuickWin> BuildQuickWins(IReadOnlyList<RiskRow> latest)
    {
        // ROI-ordered: the highest-scoring critical-tier items are the biggest
        // single-fix score drops. We report the row's own score as the projected
        // drop if remediated (grounded in the data; labelled "projected").
        return latest
            .Where(r => r.CriticalityTier <= 1)
            .OrderByDescending(r => r.RiskScoreTotal)
            .Take(5)
            .Select(r => new QuickWin(
                Title: $"Remediate {r.ConfigurationName}",
                Plain: string.IsNullOrEmpty(r.RiskFactorProbability) ? r.RiskFactorConsequence : r.RiskFactorProbability,
                ProjectedScoreDrop: Math.Round(r.RiskScoreTotal, 1),
                AffectedAssets: 1,
                Urgency: r.SecuritySeverity switch
                {
                    "Critical" => "Now",
                    "High" => "This week",
                    _ => "This month",
                }))
            .ToList();
    }

    private static IReadOnlyList<CoverageFact> BuildCoverage(IReadOnlyList<RiskRow> latest)
    {
        // Coverage & confidence banner. "Classified" = rows that carry a tier label;
        // "Onboarded" = rows NOT flagged as an onboarding/sensor gap in their factors.
        // Pure, grounded; no invented confidence numbers.
        var total = latest.Count;
        double pct(Func<RiskRow, bool> ok) => total == 0 ? 100 : Math.Round(latest.Count(ok) * 100.0 / total, 0);

        return new[]
        {
            new CoverageFact("Classified assets", "Assets with a confirmed criticality tier.",
                pct(r => !string.IsNullOrEmpty(r.CriticalityTierLevel) && !r.CriticalityTierLevel.Contains("Unclass", StringComparison.OrdinalIgnoreCase))),
            new CoverageFact("Sensor coverage", "Assets fully reporting (no onboarding/sensor gap).",
                pct(r => !(r.RiskFactorProbability.Contains("onboarding", StringComparison.OrdinalIgnoreCase)
                          || r.RiskFactorProbability.Contains("not fully managed", StringComparison.OrdinalIgnoreCase)
                          || r.RiskFactorProbability.Contains("not managed", StringComparison.OrdinalIgnoreCase)))),
            new CoverageFact("Owned assets", "Assets with an identified owner.",
                pct(r => !r.RiskFactorProbability.Contains("no owner", StringComparison.OrdinalIgnoreCase))),
        };
    }
}
