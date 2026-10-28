using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core;
using SI.Management.Core.ProData;
using SI.Management.Web.Data;
using SI.Management.Web.Export;
using SI.Management.Web.Jobs;

namespace SI.Management.Web.Pages.Admin;

public sealed record TargetState(string Source, long Open, long Closed, DateTime? LastChange);
public sealed record AppliedRun(string RunId, DateTime? FirstAt, DateTime? LastAt, long Opened, long Closed, long Reopened, long Seen);
public sealed record ConnectorRun(string RunId, string Engine, DateTime? StartedAt, DateTime? EndedAt, string Verdict);

/// <summary>
/// Connector status: the close-loop target(s) (open / closed per source, what each recent run wrote), the connector
/// engines' runs (sidata.Run when the data sync records them, and SI_RunHealth_CL), and their summary lines --
/// the close-loop's plan numbers, why a run HALTED, the CMDB push's counts -- from the jobs' console logs.
/// Every source is read independently: one missing source never hides the others.
/// </summary>
public sealed class ConnectorsModel : PageModel
{
    private readonly ISqlExecutor _sql;
    private readonly IEstateQueries _estate;
    private readonly IConsoleLogReader _logs;
    private readonly ILogger<ConnectorsModel> _log;
    private readonly SI.Management.Web.Changes.ConnectorRepository _connectors;

    public ConnectorsModel(ISqlExecutor sql, IEstateQueries estate, IConsoleLogReader logs, SI.Management.Web.Changes.ConnectorRepository connectors, ILogger<ConnectorsModel> log)
    { _sql = sql; _estate = estate; _logs = logs; _connectors = connectors; _log = log; }

    /// Phase E: one row per connector per close-loop run (cfg.ConnectorRun) -- what it planned, what landed, how it ended.
    public IReadOnlyList<SI.Management.Web.Changes.ConnectorRunRow> ConnectorRunRows { get; private set; } = Array.Empty<SI.Management.Web.Changes.ConnectorRunRow>();

    public IReadOnlyList<TargetState> Targets { get; private set; } = Array.Empty<TargetState>();
    public IReadOnlyList<AppliedRun> Applied { get; private set; } = Array.Empty<AppliedRun>();
    public IReadOnlyList<ConnectorRun> Runs { get; private set; } = Array.Empty<ConnectorRun>();
    public IReadOnlyList<RunHealthRow> Health { get; private set; } = Array.Empty<RunHealthRow>();
    public IReadOnlyList<ConsoleLine> Lines { get; private set; } = Array.Empty<ConsoleLine>();
    public List<QueryInfo> Queries { get; } = new();
    public List<string> Errors { get; } = new();

    public static bool IsConnectorEngine(string engine) =>
        engine.Contains("cmdb", StringComparison.OrdinalIgnoreCase) || engine.Contains("vuln", StringComparison.OrdinalIgnoreCase)
        || engine.Contains("close", StringComparison.OrdinalIgnoreCase) || engine.Contains("connector", StringComparison.OrdinalIgnoreCase);

    public async Task OnGetAsync(CancellationToken ct)
    {
        await Guard("connector runs (cfg.ConnectorRun)", async () =>
        {
            ConnectorRunRows = await _connectors.RunsAsync(null, 50, ct);
            Queries.Add(QueryInfo.Sql(SI.Management.Web.Changes.ConnectorRepository.RunsSql, "Runs per connector"));
        });
        await Guard("close-loop targets", async () =>
        {
            var rows = await _sql.QueryAsync(ProDataSql.CloseLoopTargets, new Dictionary<string, object?>(), ct);
            Targets = rows.Select(r => new TargetState(r.Str("Source") ?? "", r.Long("OpenItems") ?? 0, r.Long("ClosedItems") ?? 0, r.Date("LastChange"))).ToList();
            Queries.Add(QueryInfo.Sql(ProDataSql.CloseLoopTargets, "Close-loop targets"));
        });
        await Guard("close-loop runs", async () =>
        {
            var rows = await _sql.QueryAsync(ProDataSql.CloseLoopRuns, new Dictionary<string, object?> { ["Top"] = 20 }, ct);
            Applied = rows.Select(r => new AppliedRun(r.Str("RunId") ?? "", r.Date("FirstAt"), r.Date("LastAt"), r.Long("Opened") ?? 0, r.Long("Closed") ?? 0,
                r.Long("Reopened") ?? 0, r.Long("Seen") ?? 0)).ToList();
            Queries.Add(QueryInfo.Sql(ProDataSql.CloseLoopRuns, "Written per close-loop run"));
        });
        await Guard("connector runs (sidata.Run)", async () =>
        {
            var q = ProDataSql.ConnectorRunsTop(30);
            var rows = await _sql.QueryAsync(q.Text, q.Parameters, ct);
            Runs = rows.Select(r => new ConnectorRun(r.Str("RunId") ?? "", r.Str("Engine") ?? "", r.Date("StartedAt"), r.Date("EndedAt"), r.Str("Verdict") ?? "")).ToList();
            Queries.Add(QueryInfo.Sql(q.Text, "Connector engine runs: recorded by the data sync"));
        });
        await Guard("run health", async () =>
        {
            var r = await _estate.RunHealthAsync(7, ct);
            Health = r.Data.Where(h => IsConnectorEngine(h.Engine)).ToList();
            Queries.Add(QueryInfo.From(r, "Connector engine runs"));
        });
        await Guard("connector log lines", async () =>
        {
            var r = await _logs.ConnectorLinesAsync(24 * 7, 200, ct);
            Lines = r.Data;
            Queries.Add(QueryInfo.From(r, "Plan, halts and push summaries"));
        });
    }

    /// Excel workbook of every table on this page, one sheet each.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        await OnGetAsync(ct);
        return await ExcelExport.FileAsync("connector-status", null, (x, info) =>
        {
            info.Notes.AddRange(Errors);
            x.Sheet(info, "Runs per connector", new[]
                {
                    "Connector", "Kind", "Run", "Started", "Ended", "Mode", "Outcome", "Plan open", "Plan reopen", "Plan update", "Plan close", "Held",
                    "Opened", "Reopened", "Updated", "Closed", "Errors", "Not sent", "Halt reason", "Error",
                },
                ConnectorRunRows.Select(r => new object?[]
                {
                    r.ConnectorName, r.Kind, r.RunId, r.StartedAt, r.EndedAt, r.Mode, r.Outcome, r.PlanOpen, r.PlanReopen, r.PlanUpdate, r.PlanClose, r.Held,
                    r.Opened, r.Reopened, r.Updated, r.Closed, r.Errors, r.NotSent, r.HaltReason, r.Error,
                }));
            x.Sheet(info, "Close-loop targets", new[] { "Source", "Open", "Closed", "Last change" },
                Targets.Select(t => new object?[] { t.Source, t.Open, t.Closed, t.LastChange }));
            x.Sheet(info, "Written per close-loop run", new[] { "Run", "First write", "Last write", "Opened", "Closed", "Reopened", "Seen" },
                Applied.Select(a => new object?[] { a.RunId, a.FirstAt, a.LastAt, a.Opened, a.Closed, a.Reopened, a.Seen }));
            x.Sheet(info, "Connector engine runs", new[] { "Engine", "When", "Phase", "Outcome", "Duration (s)", "Run" },
                Health.Select(h => new object?[] { h.Engine, h.CollectionTime, h.Phase, h.ExitReason.Length == 0 ? "ok" : h.ExitReason, h.DurationSec, h.RunId }));
            x.Sheet(info, "Recorded by the data sync", new[] { "Run", "Engine", "Started", "Ended", "Verdict" },
                Runs.Select(r => new object?[] { r.RunId, r.Engine, r.StartedAt, r.EndedAt, r.Verdict }));
            x.Sheet(info, "Plan, halts and push summaries", new[] { "When", "Execution", "Halted", "Line" },
                Lines.Select(l => new object?[] { l.At, l.Execution, l.Text.Contains("HALTED", StringComparison.Ordinal), l.Text }));
            return Task.CompletedTask;
        }, ct);
    }

    private async Task Guard(string what, Func<Task> f)
    {
        try { await f(); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "{What} could not be read", what);
            Errors.Add($"{what}: not available ({ex.Message})");
        }
    }
}
