using Azure.Identity;
using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using SIAnalyzer.Core.Kql;
using SIAnalyzer.Core.Model;

namespace SIAnalyzer.Web.Services;

/// <summary>
/// The LIVE, read-only data plane: Azure Monitor Query SDK against the SI workspace,
/// authenticated with the app's Managed Identity (granted Log Analytics Reader on the
/// workspace). It NEVER writes - the SDK only supports queries, and every KQL it runs
/// is first vetted by <see cref="KqlGuardrail"/>, so the SI v2.2 read-only invariant
/// holds end-to-end.
///
/// This is the C# equivalent of the POC's Invoke-AzOperationalInsightsQuery path, but
/// switched to Managed Identity (no interactive Connect-AzAccount) per the hosting spec.
/// </summary>
public sealed class LogAnalyticsRiskDataSource : IRiskDataSource
{
    /// <summary>Explicit server-side query timeout (audit #10). The service allows up to 10
    /// minutes; nothing behind a page load should wait that long.</summary>
    private static readonly TimeSpan ServerTimeout = TimeSpan.FromMinutes(3);

    private readonly LogsQueryClient _client;
    private readonly string _workspaceId;
    private readonly int _lookbackDays;
    private readonly ILogger<LogAnalyticsRiskDataSource> _log;

    public LogAnalyticsRiskDataSource(string workspaceId, int lookbackDays, ILogger<LogAnalyticsRiskDataSource> log)
    {
        _workspaceId = workspaceId;
        _lookbackDays = lookbackDays < 1 ? 180 : lookbackDays;
        _log = log;
        // DefaultAzureCredential resolves the system-assigned Managed Identity in Azure
        // (and a developer credential locally), so no secrets live in the app.
        _client = new LogsQueryClient(new DefaultAzureCredential());
    }

    public bool IsLive => true;
    public string SourceDescription => "Live Log Analytics workspace (read-only via Managed Identity / Log Analytics Reader).";

    public async Task<RiskSnapshot> GetAllRowsAsync(CancellationToken ct = default)
    {
        // Pull ALL snapshots in the lookback window from the RA SUMMARY table - the SI
        // engine output that carries the scored findings (RiskScoreTotal, SecuritySeverity,
        // CriticalityTierLevel, RiskFactor_*). The C# layer slices the latest snapshot for
        // the headline and diffs across snapshots for the trend.
        var kql = KqlBuilders.RollupAllSnapshots(_lookbackDays);

        var g = KqlGuardrail.Check(kql);
        if (!g.Allowed)
        {
            throw new InvalidOperationException("Internal rollup query failed the read-only guardrail: " + string.Join("; ", g.Reasons));
        }

        var (table, quality) = await RunRawAsync(kql, ct);
        return new RiskSnapshot(MapRiskRows(table), quality);
    }

    public async Task<QueryResult> RunGuardedQueryAsync(string kql, CancellationToken ct = default)
    {
        var g = KqlGuardrail.Check(kql);
        if (!g.Allowed)
        {
            throw new InvalidOperationException("Query rejected by read-only guardrail: " + string.Join("; ", g.Reasons));
        }
        var (table, _) = await RunRawAsync(kql, ct);
        var cols = table.Columns.Select(c => c.Name).ToList();
        var rows = table.Rows
            .Select(r => (IReadOnlyList<object?>)Enumerable.Range(0, cols.Count).Select(i => r[i]).ToList())
            .ToList();
        return new QueryResult(cols, rows);
    }

    private async Task<(LogsTable Table, DataQuality Quality)> RunRawAsync(string kql, CancellationToken ct)
    {
        var range = new QueryTimeRange(TimeSpan.FromDays(_lookbackDays + 1));
        // AUDIT #10: an explicit server timeout. Without one the query inherits the service
        // default and a pathological rollup can hold a request open far longer than a page load
        // should ever wait.
        var options = new LogsQueryOptions { ServerTimeout = ServerTimeout };
        var resp = await _client.QueryWorkspaceAsync(_workspaceId, kql, range, options, ct);
        var result = resp.Value;

        // AUDIT #10: the status was never read. PartialFailure means Log Analytics returned SOME
        // rows AND an error - the caps are 500,000 rows / 100 MB, and the rollup asks for up to
        // 500,000. Reporting it is not optional: fewer rows means a lower total score, which
        // renders as an IMPROVEMENT unless the surface says otherwise.
        if (result.Status == LogsQueryResultStatus.PartialFailure)
        {
            var detail = result.Error?.Message ?? "the workspace returned a partial result (row/size cap or a failed shard).";
            _log.LogError("Log Analytics returned a PARTIAL result for the rollup query: {Detail}. Figures derived from it are understated and are flagged as partial on every surface.", detail);
            return (result.Table, new DataQuality(true, detail, DateTimeOffset.UtcNow));
        }

        return (result.Table, DataQuality.Complete(DateTimeOffset.UtcNow));
    }

    private static IReadOnlyList<RiskRow> MapRiskRows(LogsTable table)
    {
        var colNames = table.Columns.Select(c => c.Name).ToList();
        var rows = new List<RiskRow>(table.Rows.Count);
        foreach (var r in table.Rows)
        {
            var cells = colNames.Select((_, i) => (object?)r[i]).ToList();
            rows.Add(RiskRowMapper.FromCells(colNames, cells));
        }
        return rows;
    }
}
