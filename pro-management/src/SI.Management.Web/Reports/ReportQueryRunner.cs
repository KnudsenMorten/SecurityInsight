using SI.Management.Core;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Reports;

/// What a test run of a report query found: the columns, at most Cap rows, whether there were more, the contract
/// problems, or why it could not run.
public sealed record ReportTestResult(bool Ran, IReadOnlyList<string> Columns, IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows, bool More,
    IReadOnlyList<ContractIssue> Issues, string? Error, double Seconds);

/// The Test button's seam (#274): runs a report query READ-ONLY against the workspace through the web app's Log Analytics
/// read path (the same identity the estate and chat queries use), with a row cap and a timeout.
public interface IReportQueryRunner
{
    bool Configured { get; }
    Task<ReportTestResult> RunAsync(string query, CancellationToken ct);
}

public sealed class LogAnalyticsReportQueryRunner : IReportQueryRunner
{
    public const int Cap = 50;
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);
    private readonly ILogAnalyticsReader _la;
    public LogAnalyticsReportQueryRunner(ILogAnalyticsReader la) => _la = la;
    public bool Configured => true;

    public async Task<ReportTestResult> RunAsync(string query, CancellationToken ct) => await Run(_la.QueryAsync, query, ct);

    /// The run itself, over any query function (tests pass a fake): refused unless read-only; capped; timed out.
    public static async Task<ReportTestResult> Run(Func<string, CancellationToken, Task<IReadOnlyList<DataRow>>> query, string q, CancellationToken ct)
    {
        var why = KqlReadOnly.Problems(q);
        if (why.Count > 0) return new ReportTestResult(false, [], [], false, [], "Not run: " + string.Join("; ", why), 0);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var rows = await query(KqlReadOnly.Capped(q, Cap + 1), cts.Token);
            IReadOnlyList<string> cols = rows.Count > 0 ? rows[0].Keys.ToList() : Array.Empty<string>();
            if (rows.Count == 0)
            {
                var schema = await query(KqlReadOnly.Schema(q), cts.Token);
                cols = schema.Select(r => r.TryGetValue("ColumnName", out var n) ? Convert.ToString(n, System.Globalization.CultureInfo.InvariantCulture) ?? "" : "").Where(n => n.Length > 0).ToList();
            }
            var shown = rows.Take(Cap).Select(r => (IReadOnlyDictionary<string, object?>)r).ToList();
            return new ReportTestResult(true, cols, shown, rows.Count > Cap, ContractCheck.Check(cols, shown), null, sw.Elapsed.TotalSeconds);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new ReportTestResult(false, [], [], false, [], $"the query did not finish within {Timeout.TotalSeconds:0} seconds -- narrow it (a time window, fewer joins)", sw.Elapsed.TotalSeconds);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new ReportTestResult(false, [], [], false, [], "the workspace refused the query: " + ex.Message, sw.Elapsed.TotalSeconds);
        }
    }
}

/// No workspace configured: the Test button says so instead of running anything.
public sealed class NotConfiguredReportQueryRunner : IReportQueryRunner
{
    public const string Why = "no Log Analytics workspace is configured for the web app (Estate:WorkspaceId), so a query cannot be tested here";
    public bool Configured => false;
    public Task<ReportTestResult> RunAsync(string query, CancellationToken ct)
    {
        var why = KqlReadOnly.Problems(query);
        return Task.FromResult(new ReportTestResult(false, [], [], false, [], why.Count > 0 ? "Not run: " + string.Join("; ", why) : Why, 0));
    }
}
