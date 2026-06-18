using Sia.Core.Ai;
using Sia.Core.Analysis;
using Sia.Core.Exec;
using Sia.Core.Kql;
using Sia.Core.Model;

namespace Sia.Web.Services;

/// <summary>
/// The application service that composes the data plane + Core logic into the view
/// models the exec page, analyst page and MCP tools consume. It keeps the read-only
/// guardrail and grounding contracts central so every surface (page, API, MCP) shares
/// the exact same safety + grounding behaviour.
/// </summary>
public sealed class AnalyzerService
{
    private readonly IRiskDataSource _data;
    private readonly IAiNarrativeService _ai;

    public AnalyzerService(IRiskDataSource data, IAiNarrativeService ai)
    {
        _data = data;
        _ai = ai;
    }

    public bool IsLive => _data.IsLive;
    public string SourceDescription => _data.SourceDescription;
    public bool AiAvailable => _ai.IsAvailable;

    /// <summary>Build the board-ready exec dashboard + a grounded AI exec summary.</summary>
    /// <param name="periodKey">The reporting period the period-over-period view snaps to
    /// (e.g. "quarter" = "since last board meeting"); null/unknown defaults to the quarter.</param>
    public async Task<ExecViewModel> GetExecAsync(string? periodKey = null, CancellationToken ct = default)
    {
        var rows = await _data.GetAllRowsAsync(ct);
        var dash = ExecDashboardBuilder.Build(rows, periodKey);
        var latest = SnapshotDiff.LatestSnapshot(rows);
        var diff = SnapshotDiff.Diff(rows);

        var narrative = await _ai.SummarizeAsync(
            "Write a one-paragraph, board-ready executive summary of the organisation's security posture and its direction, then list the top 3 recommended actions with the projected score impact. Plain business language.",
            latest, Audience.Management,
            new DiffSummary(diff.ScoreDelta, diff.NewCount, diff.ClosedCount), ct);

        return new ExecViewModel(dash, narrative.Text, narrative.FromAi, _data.IsLive, _data.SourceDescription, _ai.IsAvailable);
    }

    /// <summary>The analyst top-N worklist (latest snapshot, highest score).</summary>
    public async Task<IReadOnlyList<RiskRow>> GetWorklistAsync(int top = 100, CancellationToken ct = default)
    {
        var rows = await _data.GetAllRowsAsync(ct);
        return SnapshotDiff.LatestSnapshot(rows)
            .OrderByDescending(r => r.RiskScoreTotal)
            .Take(top)
            .ToList();
    }

    /// <summary>List the prestaged analyses (id/title/plain/domain - never the raw KQL on the exec surface).</summary>
    public IReadOnlyList<PrestagedAnalysis> GetPrestaged() => PrestagedLibrary.All;

    /// <summary>Run a prestaged analysis (guardrail-checked) + a grounded AI explanation.</summary>
    public async Task<AnalysisRunResult> RunPrestagedAsync(string id, Audience audience, CancellationToken ct = default)
    {
        var analysis = PrestagedLibrary.All.FirstOrDefault(a => a.Id == id)
            ?? throw new ArgumentException($"Unknown prestaged analysis '{id}'.", nameof(id));
        var result = await _data.RunGuardedQueryAsync(analysis.Kql, ct);
        var rows = ToRiskRows(result);
        var narrative = await _ai.SummarizeAsync(analysis.AiTemplate, rows, audience, null, ct);
        return new AnalysisRunResult(analysis.Title, analysis.Kql, result, narrative.Text, narrative.FromAi);
    }

    /// <summary>Ad-hoc prompt: AI composes KQL -> guardrail -> run -> grounded explanation.
    /// The guardrail is the hard gate; AI is only the composer.</summary>
    public async Task<AdHocResult> RunAdHocAsync(string question, Audience audience, CancellationToken ct = default)
    {
        var kql = await _ai.ComposeKqlAsync(question, KqlGuardrail.AllowedTables, ct);
        if (string.IsNullOrWhiteSpace(kql))
        {
            return new AdHocResult(question, null, null, "AI is unavailable to compose a query. Use the analyst KQL box directly, or pick a prestaged analysis.", false, false);
        }
        var g = KqlGuardrail.Check(kql);
        if (!g.Allowed)
        {
            return new AdHocResult(question, kql, null, "The composed query was rejected by the read-only guardrail: " + string.Join("; ", g.Reasons), false, false);
        }
        var result = await _data.RunGuardedQueryAsync(kql, ct);
        var rows = ToRiskRows(result);
        var narrative = await _ai.SummarizeAsync("Explain this result in plain language and recommend the next action.", rows, audience, null, ct);
        return new AdHocResult(question, kql, result, narrative.Text, true, narrative.FromAi);
    }

    /// <summary>Run an analyst-supplied raw KQL - guardrail is enforced (read-only only).</summary>
    public async Task<AdHocResult> RunRawKqlAsync(string kql, Audience audience, CancellationToken ct = default)
    {
        var g = KqlGuardrail.Check(kql);
        if (!g.Allowed)
        {
            return new AdHocResult(kql, kql, null, "Query rejected by the read-only guardrail: " + string.Join("; ", g.Reasons), false, false);
        }
        var result = await _data.RunGuardedQueryAsync(kql, ct);
        var rows = ToRiskRows(result);
        var narrative = await _ai.SummarizeAsync("Explain this result in plain language and recommend the next action.", rows, audience, null, ct);
        return new AdHocResult(kql, kql, result, narrative.Text, true, narrative.FromAi);
    }

    /// <summary>On-demand drill-down: the grounded evidence rows behind a headline number
    /// (overall / a domain / a severity band / a tier). Powers the "clean-by-default,
    /// drill-down on demand" reveal so no exec figure is a black box.</summary>
    public async Task<DrilldownView> GetDrilldownAsync(string dimension, string? key, int top = 10, CancellationToken ct = default)
    {
        var rows = await _data.GetAllRowsAsync(ct);
        return Drilldown.Build(rows, dimension, key, top);
    }

    /// <summary>The prioritised remediation plan ("next N actions ranked by risk-reduction"):
    /// per-asset actions ordered by risk-removed-per-effort, with the cumulative projected
    /// score + band crossing. Grounded in the latest snapshot; effort/ROI are estimates.</summary>
    public async Task<RemediationPlanView> GetRemediationPlanAsync(int top = 5, CancellationToken ct = default)
    {
        var rows = await _data.GetAllRowsAsync(ct);
        return RemediationPlan.Build(rows, top);
    }

    /// <summary>The plain-language exec glossary ("what these terms mean"): every term on
    /// the exec surface defined for a non-technical reader, present-now terms first, each
    /// with a grounded example from the real rows. Honest about absent terms. No AI, no
    /// network beyond the read-only row fetch; nothing invented.</summary>
    public async Task<GlossaryView> GetGlossaryAsync(CancellationToken ct = default)
    {
        var rows = await _data.GetAllRowsAsync(ct);
        return Glossary.Build(rows);
    }

    /// <summary>The organisational-coaching view ("missing processes"): the leadership-level
    /// maturity / process gaps the finding PATTERNS imply (privileged-access reviews, exposure
    /// reviews, patch cadence, onboarding, ownership, crown-jewel protection). Grounded in the
    /// real latest-snapshot rows, framed as recommended processes/behaviours, honest when no
    /// systemic gap stands out. No AI, no network beyond the read-only row fetch.</summary>
    public async Task<OrgCoachingView> GetOrgCoachingAsync(CancellationToken ct = default)
    {
        var rows = await _data.GetAllRowsAsync(ct);
        return OrgCoaching.Build(rows);
    }

    /// <summary>The maturity scorecard + roadmap ("where the environment and behaviour need to
    /// mature"): a rule-based 0-100 maturity rating per leadership dimension (Tiering, Privileged
    /// Access, Identity Hygiene, Exposure Management, Visibility &amp; Coverage, Operating
    /// Discipline), each grounded in the latest-snapshot rows, plus a prioritised "mature here
    /// next" roadmap. Honest when a dimension has no data; no AI, no invented numbers.</summary>
    public async Task<MaturityScorecardView> GetMaturityAsync(CancellationToken ct = default)
    {
        var rows = await _data.GetAllRowsAsync(ct);
        return MaturityScorecard.Build(rows);
    }

    /// <summary>Management diff + timeline (for the MCP tool + analyst trend).</summary>
    public async Task<ManagementViewModel> GetManagementAsync(CancellationToken ct = default)
    {
        var rows = await _data.GetAllRowsAsync(ct);
        return new ManagementViewModel(SnapshotDiff.Diff(rows), SnapshotDiff.Timeline(rows));
    }

    /// <summary>Map a tabular query result back to RiskRow for grounding the AI. Uses the
    /// shared <see cref="RiskRowMapper"/> so the RA-Summary schema + the
    /// RiskFactor_*_Detailed-over-numeric preference are resolved identically to the live
    /// data-source rollup (any allow-listed prestaged/ad-hoc result maps the same way).</summary>
    private static IReadOnlyList<RiskRow> ToRiskRows(QueryResult result) =>
        result.Rows.Select(r => RiskRowMapper.FromCells(result.Columns, r)).ToList();
}

public sealed record ExecViewModel(ExecDashboard Dashboard, string ExecSummary, bool SummaryFromAi, bool IsLive, string SourceDescription, bool AiAvailable);
public sealed record AnalysisRunResult(string Title, string Kql, QueryResult Result, string Narrative, bool NarrativeFromAi);
public sealed record AdHocResult(string Question, string? Kql, QueryResult? Result, string Narrative, bool Ran, bool NarrativeFromAi);
public sealed record ManagementViewModel(DiffResult Diff, IReadOnlyList<TimelinePoint> Timeline);
