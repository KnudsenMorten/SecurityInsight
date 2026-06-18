using Sia.Core.Model;

namespace Sia.Web.Services;

/// <summary>The read-only RA data plane. Implementations: Log Analytics (MI) or demo.</summary>
public interface IRiskDataSource
{
    /// <summary>True when reading a live workspace (false = demo data).</summary>
    bool IsLive { get; }

    /// <summary>Human-readable description of where the data comes from.</summary>
    string SourceDescription { get; }

    /// <summary>
    /// Fetch the RA rows across the timeline window (all snapshots) for the exec rollup,
    /// diff and timeline. NO cap on the data scanned (top-N is a view, not a data cap).
    /// </summary>
    Task<IReadOnlyList<RiskRow>> GetAllRowsAsync(CancellationToken ct = default);

    /// <summary>
    /// Run a guardrail-CHECKED read-only KQL query and return raw column/row tabular data.
    /// The caller MUST have passed the query through the guardrail first; implementations
    /// re-assert read-only (defence in depth) and never execute control commands.
    /// </summary>
    Task<QueryResult> RunGuardedQueryAsync(string kql, CancellationToken ct = default);
}

/// <summary>Tabular result of a guarded ad-hoc/prestaged query.</summary>
public sealed record QueryResult(IReadOnlyList<string> Columns, IReadOnlyList<IReadOnlyList<object?>> Rows);
