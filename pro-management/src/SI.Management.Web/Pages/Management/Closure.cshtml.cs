using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Export;

namespace SI.Management.Web.Pages.Management;

/// <summary>
/// Vulnerabilities over time (was "Vulnerability closure"): new / closed / reopened per day, week or month (the pre-computed sidata.VulnLifecycleDaily),
/// and what is open now by severity and asset tier (vuln current state). No time to fix (owner 2026-10-15: "remove the time
/// to fix in emails and gui. it makes no value") -- the close-loop's record keeps every date; the page no longer reads it.
/// </summary>
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Management)]
public sealed class ClosureModel : PageModel
{
    private readonly IProDataQueries _q;
    private readonly ILogger<ClosureModel> _log;
    public ClosureModel(IProDataQueries q, ILogger<ClosureModel> log) { _q = q; _log = log; }

    [BindProperty(SupportsGet = true)] public string? Grain { get; set; }
    [BindProperty(SupportsGet = true)] public int Days { get; set; } = 90;

    public IReadOnlyList<LifecycleBucket> Buckets { get; private set; } = Array.Empty<LifecycleBucket>();
    public IReadOnlyList<OpenVulnCell> Open { get; private set; } = Array.Empty<OpenVulnCell>();
    public ChartSpec? Flow { get; private set; }
    public ChartSpec? Backlog { get; private set; }
    public List<QueryInfo> Queries { get; } = new();
    public List<string> Errors { get; } = new();
    public long Opened => Buckets.Sum(b => b.Opened);
    public long Closed => Buckets.Sum(b => b.Closed);
    public long Reopened => Buckets.Sum(b => b.Reopened);
    /// #855 W9 (owner 2026-10-21: "we need to be able to trust all data"): the closes by reason -- FIXED (Remediated) is the only
    /// fixed work; an asset that retired is not fixed, nor is any other reason. Null when a day of the period predates the split.
    public bool ReasonsKnown => Buckets.Count > 0 && Buckets.All(b => b.ClosedFixed is not null);
    public long? ClosedFixed => ReasonsKnown ? Buckets.Sum(b => b.ClosedFixed ?? 0) : null;
    public long? ClosedRetired => ReasonsKnown ? Buckets.Sum(b => b.ClosedRetired ?? 0) : null;
    public long? ClosedOther => ReasonsKnown ? Buckets.Sum(b => b.ClosedOther ?? 0) : null;
    public long? OpenNow => Buckets.LastOrDefault(b => b.OpenAtEnd is not null)?.OpenAtEnd;

    /// False when the open vulnerabilities by severity and tier could not be counted in time (the page says so, no numbers).
    public bool OpenKnown { get; private set; } = true;
    /// When the data sync counted them (null = counted for this page).
    public DateTime? OpenCountedAt { get; private set; }
    /// #865: why the close-loop's numbers may be empty (SI's own SQL target off / in test mode / not run / failed), or null.
    public string? CloseLoopStatus { get; private set; }
    public const string OpenPendingText = "The open vulnerabilities by severity and asset tier are not counted yet -- they appear after the next data sync.";

    public async Task OnGetAsync(CancellationToken ct)
    {
        Grain = ProDataFilters.Pick(Grain, Grains.All, Grains.Week);
        Days = Fmt.Pick(Days, 90, 30, 90, 180, 365);
        // the two reads need nothing of each other: both start at once (each read has its own connection), their results are
        // taken in the page's order
        var lifecycle = Capture(() => _q.LifecycleAsync(Days, ct));
        var open = Capture(() => _q.OpenVulnerabilityCountsAsync(ct));
        var status = SI.Management.Web.Changes.OwnSqlTargetStatus.ReadAsync(HttpContext?.RequestServices, _log, ct);
        await Task.WhenAll(lifecycle, open, status);
        CloseLoopStatus = await status;
        await Guard("vulnerability lifecycle", async () =>
        {
            var r = await await lifecycle;
            Queries.Add(QueryInfo.Sql(r.Query, "New vs closed, open backlog, per period"));
            Buckets = ProDataQueries.Bucket(r.Data, Grain);
            var labels = Buckets.Select(b => b.Label).ToList();
            // #855 W9: "closed" was every close -- an asset that retired counted as fixed work. Fixed, asset retired and other
            // closes are their own series; a period from before the split shows its closes as one series, said as such
            Flow = new ChartSpec("closure-flow", "bar", labels, ReasonsKnown
                ? new[]
                {
                    new ChartSeries("New", Buckets.Select(b => (double?)b.Opened).ToList(), 2),
                    new ChartSeries("Closed: fixed", Buckets.Select(b => (double?)b.ClosedFixed).ToList(), 3),
                    new ChartSeries("Closed: asset retired", Buckets.Select(b => (double?)b.ClosedRetired).ToList(), 5),
                    new ChartSeries("Closed: other reason", Buckets.Select(b => (double?)b.ClosedOther).ToList(), 6),
                    new ChartSeries("Reopened", Buckets.Select(b => (double?)b.Reopened).ToList(), 4),
                }
                : new[]
                {
                    new ChartSeries("New", Buckets.Select(b => (double?)b.Opened).ToList(), 2),
                    new ChartSeries("Closed (any reason)", Buckets.Select(b => (double?)b.Closed).ToList(), 3),
                    new ChartSeries("Reopened", Buckets.Select(b => (double?)b.Reopened).ToList(), 4),
                }, "Vulnerabilities", $"New, closed and reopened vulnerabilities per {Grain}, last {Days} days");
            Backlog = new ChartSpec("closure-open", "line", labels,
                new[] { new ChartSeries("Open at the end", Buckets.Select(b => b.OpenAtEnd is { } o ? (double?)o : null).ToList(), 1) },
                "Open", $"Open vulnerabilities at the end of each {Grain}");
        });
        await Guard("open vulnerabilities", async () =>
        {
            var r = await await open;
            Open = r.Data.Cells;
            OpenKnown = r.Data.Known;
            OpenCountedAt = r.Data.CountedAt;
            Queries.Add(QueryInfo.Sql(r.Query, "Open now by severity and asset tier"));
        });
    }

    /// Starts a read and hands back the finished task (its result or its failure) -- awaiting the outer task never throws,
    /// so both reads always finish before either result is taken (the request's own cancellation still ends the request).
    private static async Task<Task<T>> Capture<T>(Func<Task<T>> read)
    {
        Task<T> t;
        try { t = read(); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return Task.FromException<T>(ex); }
        try { await t; } catch (Exception ex) when (ex is not OperationCanceledException) { }
        return t;
    }

    /// Excel workbook of this page's tables (one sheet each) for the chosen period and grouping.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        await OnGetAsync(ct);
        return await ExcelExport.FileAsync("closure", null, (x, info) =>
        {
            info.Add("Period (days)", Days).Add("Grouping", "per " + Grain);
            info.Notes.AddRange(Errors);
            x.Sheet(info, "Per " + Grain, new[] { "Period", "Period start", "New", "Closed (any reason)", "Closed: fixed", "Closed: asset retired", "Closed: other reason", "Reopened", "Open at end" },
                Buckets.Select(b => new object?[] { b.Label, b.Start, b.Opened, b.Closed, b.ClosedFixed, b.ClosedRetired, b.ClosedOther, b.Reopened, b.OpenAtEnd }));
            x.Sheet(info, "Open by severity and tier", new[] { "Asset tier", "Severity", "Open" },
                Open.OrderBy(o => o.Tier, StringComparer.Ordinal).ThenBy(o => o.Severity, SeverityOrder.Comparer)
                    .Select(o => new object?[] { ExcelExport.Tier(o.Tier), o.Severity, o.Items }));
            return Task.CompletedTask;
        }, ct);
    }

    private async Task Guard(string what, Func<Task> f)
    {
        try { await f(); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "{What} failed", what);
            Errors.Add($"The {what} could not be read: {ex.Message}");
        }
    }

    public string RangeLink(int days) => $"?days={days}&grain={Grain}";
    public string GrainLink(string grain) => $"?days={Days}&grain={grain}";
}
