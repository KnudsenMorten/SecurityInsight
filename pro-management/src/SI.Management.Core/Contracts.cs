using System.Text.Json;
namespace SI.Management.Core;

/// Every answer carries the query that produced it (curated, traceable, read-only).
public sealed record QueryResult<T>(T Data, string Query, string Source, DateTimeOffset AsOf);

public sealed record TopRisk(int Rank, string AssetName, string AssetId, string Tier, double WeightedRiskScore, int Findings, IReadOnlyList<string> Domains);
public sealed record FindingSummary(string Report, string Title, string Severity, double RiskScore);
public sealed record AssetDetail(string AssetId, string AssetName, string Tier, string AssetType, IReadOnlyList<string> RelatedIds, IReadOnlyList<FindingSummary> TopFindings);
/// One day of the estate: the AVERAGE risk score per finding (a sum of every finding's score only grows with the number
/// of findings and is never reported), the findings, how many are at the top severities (Very High / Critical, High),
/// and the tier-0 assets with findings.
public sealed record TrendPoint(DateOnly Day, double? AverageRiskScore, int Findings, int TopSeverityFindings, int Tier0Exposed);
/// One day of one security domain: its average risk score per finding and its findings.
public sealed record DomainTrendPoint(DateOnly Day, string Domain, double? AverageRiskScore, int Findings);
public sealed record VulnerabilityWeek(DateOnly WeekStart, int New, int Fixed, int Reopened, int Open);
public sealed record VulnerabilityState(IReadOnlyList<VulnerabilityWeek> Weeks, double? MedianDaysToFix);
/// One run-health record. CollectionTime is the RUN's start -- the same on its Start and its End record; RecordedAt is when
/// this record itself was written (Log Analytics' TimeGenerated: the Start moment, the End moment), null when not known.
/// PermissionGaps: the engine's own permission self-check on its END record (JSON: the gaps and what could not be checked;
/// empty = the record carries no check) -- engine/_shared/SI-PermissionCheck.ps1, read by Get Started > Permissions.
public sealed record RunHealthRow(DateTimeOffset CollectionTime, string Engine, string Phase, double? DurationSec, string ExitReason, string RunId,
    DateTimeOffset? RecordedAt = null, string? PermissionGaps = null)
{
    /// The moment of this record: when it was written, else the run's start.
    public DateTimeOffset When => RecordedAt ?? CollectionTime;
}

public interface IEstateQueries
{
    Task<QueryResult<IReadOnlyList<TopRisk>>> TopRisksAsync(int top, CancellationToken ct);
    /// The SAME ranking as TopRisksAsync (one asset, one row; estate-wide rank), but up to QueryParameters.MaxRanked
    /// assets -- so a page can list every asset of a tier with its estate rank, not only those in the top 100.
    Task<QueryResult<IReadOnlyList<TopRisk>>> RankedAssetsAsync(int max, CancellationToken ct);
    Task<QueryResult<AssetDetail?>> AssetLookupAsync(string nameOrId, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<TrendPoint>>> RiskTrendAsync(int days, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<DomainTrendPoint>>> DomainTrendAsync(int days, CancellationToken ct);
    Task<QueryResult<VulnerabilityState>> VulnerabilityStateAsync(int weeks, CancellationToken ct);
    Task<QueryResult<IReadOnlyList<RunHealthRow>>> RunHealthAsync(int days, CancellationToken ct);
}

public sealed record ChatTurn(string Role, string Content);
public sealed record ToolCallTrace(string Tool, string ArgumentsJson, string Query, string Source);
/// An asset a tool result named: its name, and its asset key when the result carried one (the key opens its asset page).
public sealed record ChatAsset(string Name, string? Key);
/// The model's answer (Text: the answer only -- the "Based on" line is ChatService.Basis, shown with the tool calls),
/// the calls behind it, and the assets their results named (for the answer's highlighting and asset links).
public sealed record ChatAnswer(string Text, IReadOnlyList<ToolCallTrace> ToolCalls)
{
    public IReadOnlyList<ChatAsset> Assets { get; init; } = Array.Empty<ChatAsset>();
}

public interface IChatService
{
    /// Answers using ONLY the curated read-only tools; every answer lists the tool calls (and their queries) behind it.
    /// isAdmin = false withholds settings history (Viewer role).
    Task<ChatAnswer> AskAsync(IReadOnlyList<ChatTurn> history, string question, bool isAdmin, CancellationToken ct);

    /// The same, asked from a page: the page's context (view, collection, filters, selection) reaches the model as
    /// structured data, so "this", "here" and "top 3 here" mean what is on screen. A service without context support
    /// answers without it.
    Task<ChatAnswer> AskAsync(IReadOnlyList<ChatTurn> history, string question, bool isAdmin, ChatPageContext? context, CancellationToken ct)
        => AskAsync(history, question, isAdmin, ct);
}
