using SIAnalyzer.Core.Exec;

namespace SIAnalyzer.Web.Services;

/// <summary>
/// Orchestrates the scheduled exec-summary email (REQUIREMENTS.md "SI Analyzer":
/// "scheduled monthly email ... so the CIO gets it without opening the tool"). It:
/// <list type="number">
///   <item>builds the SAME grounded exec view the GUI + board deck use (via
///   <see cref="AnalyzerService.GetExecAsync"/> - AI-narrated when AI is on, templated
///   when off);</item>
///   <item>renders the email (<see cref="ExecEmailRenderer"/>) with the board-deck link;</item>
///   <item>routes it through the configured <see cref="IExecEmailSender"/> (fail-soft).</item>
/// </list>
/// Every figure is the grounded RA number - nothing is recomputed or invented here. The
/// data plane is read-only (it only reads the exec view). Used by the manual "send now"
/// API trigger, the MCP tool, and the scheduled <see cref="ScheduledExecEmailHostedService"/>.
/// </summary>
public sealed class ExecEmailService
{
    private readonly AnalyzerService _analyzer;
    private readonly IExecEmailSender _sender;
    private readonly EmailScheduleOptions _opts;

    public ExecEmailService(AnalyzerService analyzer, IExecEmailSender sender, EmailScheduleOptions opts)
    {
        _analyzer = analyzer;
        _sender = sender;
        _opts = opts;
    }

    /// <summary>Build the grounded exec-summary email message (no send) - used by the
    /// "preview" path + tests so the rendered output can be inspected without a mail server.</summary>
    public async Task<ExecEmailMessage> RenderAsync(CancellationToken ct = default)
    {
        var vm = await _analyzer.GetExecAsync(_opts.Period, ct);
        return ExecEmailRenderer.Render(
            vm.Dashboard.Headline, vm.Dashboard, vm.ExecSummary, vm.SummaryFromAi, vm.IsLive,
            _opts.BoardDeckUrl, _opts.OrgLabel,
            // AUDIT #10: a scheduled email built on a truncated read would report an improvement
            // that never happened, to the one audience least able to check it.
            vm.Quality?.IsPartial == true ? DataQuality.Warning : null);
    }

    /// <summary>Render + send the exec-summary email now (the manual trigger + the MCP tool +
    /// the scheduler all funnel through here). Fail-soft: no recipients / no transport =>
    /// a "not configured" result, never an exception.</summary>
    public async Task<EmailSendResult> SendNowAsync(CancellationToken ct = default)
    {
        var recipients = _opts.Recipients.Where(r => !string.IsNullOrWhiteSpace(r)).ToList();
        if (recipients.Count == 0)
            return EmailSendResult.NotConfigured("No recipients configured (SIAnalyzer:Email:Recipients).");

        var message = await RenderAsync(ct);
        return await _sender.SendAsync(message, recipients, ct);
    }
}
