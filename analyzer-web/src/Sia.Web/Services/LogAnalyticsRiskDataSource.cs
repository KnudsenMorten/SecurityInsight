using Azure.Identity;
using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using Sia.Core.Kql;
using Sia.Core.Model;

namespace Sia.Web.Services;

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

    public async Task<IReadOnlyList<RiskRow>> GetAllRowsAsync(CancellationToken ct = default)
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

        var result = await RunRawAsync(kql, ct);
        return MapRiskRows(result);
    }

    public async Task<QueryResult> RunGuardedQueryAsync(string kql, CancellationToken ct = default)
    {
        var g = KqlGuardrail.Check(kql);
        if (!g.Allowed)
        {
            throw new InvalidOperationException("Query rejected by read-only guardrail: " + string.Join("; ", g.Reasons));
        }
        var table = await RunRawAsync(kql, ct);
        var cols = table.Columns.Select(c => c.Name).ToList();
        var rows = table.Rows
            .Select(r => (IReadOnlyList<object?>)Enumerable.Range(0, cols.Count).Select(i => r[i]).ToList())
            .ToList();
        return new QueryResult(cols, rows);
    }

    private async Task<LogsTable> RunRawAsync(string kql, CancellationToken ct)
    {
        var range = new QueryTimeRange(TimeSpan.FromDays(_lookbackDays + 1));
        var resp = await _client.QueryWorkspaceAsync(_workspaceId, kql, range, cancellationToken: ct);
        return resp.Value.Table;
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
