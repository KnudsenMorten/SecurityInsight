using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core;

namespace SI.Management.Web.Pages.Admin;

/// The latest run of one engine on the Run health page: the record that says how it ended (its End, else its Start),
/// the moment of its last record, and whether the engine's own records or the job flow's step records
/// (Engine 'flow:&lt;engine&gt;') said it.
public sealed record LatestRun(string Engine, RunHealthRow Row, bool ViaFlow, DateTimeOffset LastRecord)
{
    public bool HasEnd => !RunHealthModel.IsStart(Row.Phase);
}

/// Every engine run: when, phase, duration, verdict. Through the shared query layer (SI_RunHealth_CL).
public sealed class RunHealthModel : PageModel
{
    private readonly IEstateQueries _q;
    public RunHealthModel(IEstateQueries q) => _q = q;

    [BindProperty(SupportsGet = true)] public int Days { get; set; } = 7;
    public QueryResult<IReadOnlyList<RunHealthRow>>? Health { get; private set; }
    public IReadOnlyList<LatestRun> LatestPerEngine { get; private set; } = Array.Empty<LatestRun>();
    /// Every record of the window, newest record first.
    public IReadOnlyList<RunHealthRow> AllRuns { get; private set; } = Array.Empty<RunHealthRow>();

    /// An exit reason that is not one of the success words counts as a failure on the summary.
    public static bool IsOk(string? exitReason) =>
        string.IsNullOrWhiteSpace(exitReason) || exitReason.Equals("Success", StringComparison.OrdinalIgnoreCase)
        || exitReason.Equals("OK", StringComparison.OrdinalIgnoreCase) || exitReason.Equals("Completed", StringComparison.OrdinalIgnoreCase);

    /// A dry run (asked for with -WhatIfMode) published nothing: shown as such, neither OK nor Failed.
    public static bool IsDryRun(string? exitReason) =>
        exitReason is not null && exitReason.Equals("dry-run", StringComparison.OrdinalIgnoreCase);

    /// A run that finished but did not publish everything (an output failed or holds less than it should): neither OK nor Failed.
    public static bool IsPartial(string? exitReason) =>
        exitReason is not null && exitReason.Equals("success-partial", StringComparison.OrdinalIgnoreCase);

    /// #532 THROTTLE-IS-NORMAL (framework §12.18): a run Microsoft only throttled published nothing and runs again at its
    /// next scheduled time -- amber, neither OK nor Failed, and never counted as a failure.
    public static bool IsThrottled(string? exitReason) =>
        exitReason is not null && exitReason.Equals("throttled", StringComparison.OrdinalIgnoreCase);

    /// A guard row (#277, Phase Guard) is an event inside a run, never the run's verdict.
    public static bool IsGuardEvent(string? phase) =>
        phase is not null && phase.Equals("Guard", StringComparison.OrdinalIgnoreCase);

    public static bool IsStart(string? phase) =>
        phase is not null && phase.Equals("Start", StringComparison.OrdinalIgnoreCase);

    /// The engine a record is about: the job flow records each of its steps as 'flow:&lt;engine&gt;' -- the same engine.
    public static string EngineOf(string? engine, out bool viaFlow)
    {
        var e = (engine ?? "").Trim();
        viaFlow = e.Length > 5 && e.StartsWith("flow:", StringComparison.OrdinalIgnoreCase);
        return viaFlow ? e[5..].Trim() : e;
    }

    /// <summary>
    /// The latest run per engine (#317), newest first.
    /// A run's Start and End records carry the SAME CollectionTime (the run's start), so the records are grouped per run
    /// (engine + RunId) and a run is said by its End when it has one -- never by whichever of the two tied records came
    /// first (that showed "Started -- no end row yet" for runs that had ended).
    /// The engine's own records and the flow's step records ('flow:&lt;engine&gt;') are one engine: the run whose LAST
    /// record is newest wins, so a step the flow saw end after an older failure of the engine is the latest. On a tie the
    /// engine's own record is preferred, then a run with an End. Guard events are never a verdict. The flow's own summary
    /// record (Engine 'flow') stays a line of its own.
    /// </summary>
    public static IReadOnlyList<LatestRun> LatestRuns(IEnumerable<RunHealthRow> rows)
    {
        var runs = rows.Where(r => !IsGuardEvent(r.Phase))
            .Select(r => (Row: r, Engine: EngineOf(r.Engine, out var viaFlow), ViaFlow: viaFlow))
            .Where(x => x.Engine.Length > 0)
            .GroupBy(x => (Engine: x.Engine.ToLowerInvariant(), x.ViaFlow,
                           Run: string.IsNullOrWhiteSpace(x.Row.RunId) ? "@" + x.Row.CollectionTime.UtcTicks : x.Row.RunId.Trim().ToLowerInvariant()))
            .Select(g =>
            {
                var verdict = g.Where(x => !IsStart(x.Row.Phase)).OrderByDescending(x => x.Row.When).Select(x => x.Row).FirstOrDefault()
                              ?? g.OrderByDescending(x => x.Row.When).First().Row;
                return new LatestRun(g.First().Engine, verdict, g.Key.ViaFlow, g.Max(x => x.Row.When));
            });
        return runs.GroupBy(r => r.Engine, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(r => r.LastRecord).ThenBy(r => r.ViaFlow).ThenByDescending(r => r.HasEnd).First())
            .OrderByDescending(r => r.LastRecord).ThenBy(r => r.Engine, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public async Task OnGetAsync(CancellationToken ct)
    {
        Days = Fmt.Pick(Days, 7, 1, 7, 30);
        Health = await _q.RunHealthAsync(Days, ct);
        LatestPerEngine = LatestRuns(Health.Data);
        // newest record first; of one run's tied records (no record time known) the End above the Start
        AllRuns = Health.Data.OrderByDescending(r => r.When).ThenBy(r => IsStart(r.Phase)).ToList();
    }
}
