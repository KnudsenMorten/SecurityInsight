using Sia.Core.DataAccess;
using Sia.Core.Kql;
using Sia.Core.Model;

namespace Sia.Web.Services;

/// <summary>
/// The offline / preview data source. Loads the synthetic demo snapshot (the same
/// seed the PowerShell POC ships) and answers guarded queries with a tiny in-memory
/// evaluator sufficient for the prestaged analyses + the preview. Still routes every
/// query through the read-only guardrail (defence in depth) so the demo path exercises
/// the exact same safety gate as live.
/// </summary>
public sealed class DemoRiskDataSource : IRiskDataSource
{
    private readonly IReadOnlyList<RiskRow> _rows;

    public DemoRiskDataSource(string seedPath)
    {
        _rows = DemoData.Load(seedPath);
    }

    public DemoRiskDataSource(IReadOnlyList<RiskRow> rows)
    {
        _rows = rows;
    }

    public bool IsLive => false;
    public string SourceDescription => "Demo data (synthetic seed snapshot - no live workspace).";

    public Task<IReadOnlyList<RiskRow>> GetAllRowsAsync(CancellationToken ct = default) =>
        Task.FromResult(_rows);

    public Task<QueryResult> RunGuardedQueryAsync(string kql, CancellationToken ct = default)
    {
        var g = KqlGuardrail.Check(kql);
        if (!g.Allowed)
        {
            throw new InvalidOperationException("Query rejected by read-only guardrail: " + string.Join("; ", g.Reasons));
        }

        // The demo evaluator returns the latest snapshot of whatever domain the query
        // names, projected to the common risk columns. It does not interpret arbitrary
        // KQL - it is a preview stand-in, not a Kusto engine.
        var latest = Sia.Core.Analysis.SnapshotDiff.LatestSnapshot(_rows);
        var domain = kql.Contains("Identity_Profile", StringComparison.OrdinalIgnoreCase) ? "identity"
            : kql.Contains("Azure_Profile", StringComparison.OrdinalIgnoreCase) ? "azure"
            : kql.Contains("PublicIP_Profile", StringComparison.OrdinalIgnoreCase) ? "publicip"
            : kql.Contains("Endpoint_Profile", StringComparison.OrdinalIgnoreCase) ? "endpoint"
            : "all";

        var rows = (domain == "all" ? latest : latest.Where(r => r.SecurityDomain == domain))
            .OrderByDescending(r => r.RiskScoreTotal)
            .ToList();

        var cols = new[] { "ConfigurationName", "CriticalityTierLevel", "SecuritySeverity", "RiskScoreTotal", "RiskFactor_Consequence", "RiskFactor_Probability" };
        var data = rows.Select(r => (IReadOnlyList<object?>)new object?[]
        {
            r.ConfigurationName, r.CriticalityTierLevel, r.SecuritySeverity, r.RiskScoreTotal, r.RiskFactorConsequence, r.RiskFactorProbability
        }).ToList();

        return Task.FromResult(new QueryResult(cols, data));
    }
}
