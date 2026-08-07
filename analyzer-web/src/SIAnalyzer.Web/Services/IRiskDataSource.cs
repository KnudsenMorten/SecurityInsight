using SIAnalyzer.Core.Model;

namespace SIAnalyzer.Web.Services;

/// <summary>
/// How complete a read of the workspace actually was (audit #10).
///
/// Log Analytics returns <c>PartialFailure</c> - truncated rows PLUS an error - when a query hits
/// the service caps (500,000 rows / 100 MB) or a shard fails. The data plane used to take
/// <c>response.Value.Table</c> and ignore the status entirely, so a truncated read was
/// indistinguishable from a complete one.
///
/// 🔴 That is not merely a missing warning. Everything downstream resolves
/// <c>where CollectionTime == max(CollectionTime)</c> and SUMS the scores, so a truncated read
/// renders as FEWER findings and a LOWER score - it looks like the organisation got safer. Same
/// shape as audit #5: silent, self-consistent, and pointing the wrong way.
/// </summary>
/// <param name="IsPartial">True when the workspace returned an incomplete result.</param>
/// <param name="Detail">Plain-language reason, for the banner and the log. Null when complete.</param>
/// <param name="RetrievedUtc">When these rows were read (or last refreshed from cache).</param>
public sealed record DataQuality(bool IsPartial, string? Detail, DateTimeOffset RetrievedUtc)
{
    public static DataQuality Complete(DateTimeOffset at) => new(false, null, at);

    /// <summary>The one-line warning every surface shows verbatim, so the exec page, the board
    /// deck, the analyst view and the CIO email cannot drift into wording it differently.</summary>
    public const string Warning =
        "PARTIAL DATA - the workspace returned an incomplete result, so the findings and scores shown are UNDERSTATED. Do not read this as an improvement.";
}

/// <summary>Rows plus how complete the read that produced them was.</summary>
public sealed record RiskSnapshot(IReadOnlyList<RiskRow> Rows, DataQuality Quality);

/// <summary>The read-only RA data plane. Implementations: Log Analytics (MI) or demo.</summary>
public interface IRiskDataSource
{
    /// <summary>True when reading a live workspace (false = demo data).</summary>
    bool IsLive { get; }

    /// <summary>Human-readable description of where the data comes from.</summary>
    string SourceDescription { get; }

    /// <summary>
    /// Fetch the RA rows across the timeline window (all snapshots) for the exec rollup,
    /// diff and timeline, WITH the completeness of that read. NO cap on the data scanned
    /// (top-N is a view, not a data cap).
    /// </summary>
    Task<RiskSnapshot> GetAllRowsAsync(CancellationToken ct = default);

    /// <summary>
    /// Run a guardrail-CHECKED read-only KQL query and return raw column/row tabular data.
    /// The caller MUST have passed the query through the guardrail first; implementations
    /// re-assert read-only (defence in depth) and never execute control commands.
    /// </summary>
    Task<QueryResult> RunGuardedQueryAsync(string kql, CancellationToken ct = default);
}

/// <summary>Tabular result of a guarded ad-hoc/prestaged query.</summary>
public sealed record QueryResult(IReadOnlyList<string> Columns, IReadOnlyList<IReadOnlyList<object?>> Rows);
