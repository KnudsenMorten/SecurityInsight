namespace SI.Management.Web.Jobs;

/// <summary>
/// IS THE RISK ANALYSIS SUMMARY STEP ON? (#636, owner 2026-10-19: "i prefer to switch so detailed becomes the engine default and
/// summary is optional"). The Summary step (job 'risk-analysis') is off by default; a customer switches it on with the step's
/// own switch on Operations > Jobs. While it is off the web app shows no Summary selection: the executive view, the wall board,
/// the management summary and the Risk Analysis page show the Detailed report (a kept Summary view, a Summary leader or a
/// remembered Summary choice are ignored), and Risks > Summary opens the grouped view of the Detailed findings.
/// The same rule as the engine's (engine\_shared\SI-SummaryStep.ps1 Get-SISummaryStepStateFromJson):
///   off      the stored pipeline (mode flow) has the step switched off or does not have it
///   on       the stored pipeline runs it
///   unknown  the jobs run on their own timers (mode schedules), or no pipeline is stored -- shown as before (on)
/// A read that fails is shown as before (on): never hide what may be there.
/// </summary>
public interface ISummaryStep
{
    /// True when the Summary step may run (on, or unknown); false when it is off.
    Task<bool> IsOnAsync(CancellationToken ct);
}

public sealed class SummaryStep(IFlowStore flows, ILogger<SummaryStep> log) : ISummaryStep
{
    public const string Job = "risk-analysis";
    private static readonly TimeSpan Keep = TimeSpan.FromSeconds(60);
    private readonly object _gate = new();
    private (bool On, DateTime At)? _last;

    /// PURE. 'on' | 'off' | 'unknown' of a stored pipeline (StoredFlow as IFlowStore reads it).
    public static string StateOf(StoredFlow s)
    {
        // nothing stored: never hide a step on a guess (the jobs may run on their own timers)
        if (!s.HasTable || s.Definition is null) return "unknown";
        var mode = (string.IsNullOrWhiteSpace(s.Mode) ? s.Definition.Mode : s.Mode).ToLowerInvariant();
        if (mode != "flow") return "unknown";
        var step = s.Definition.Steps.FirstOrDefault(x => JobSchedule.Key(x.Job) == Job);
        return step is null ? "off" : step.Enabled ? "on" : "off";
    }

    public async Task<bool> IsOnAsync(CancellationToken ct)
    {
        lock (_gate) { if (_last is { } l && DateTime.UtcNow - l.At < Keep) return l.On; }
        bool on;
        try { on = StateOf(await flows.ReadAsync(ct)) != "off"; }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "summary step: the pipeline could not be read"); return true; }
        lock (_gate) { _last = (on, DateTime.UtcNow); }
        return on;
    }
}
