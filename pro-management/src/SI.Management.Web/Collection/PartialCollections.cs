using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Data;

namespace SI.Management.Web.Collection;

/// One report of a collection that its run could not finish (sidata.CollectionReportCarry, written by the data sync): it
/// shows its last complete result from <see cref="FromUtc"/> (null = no complete earlier result exists -- it shows only
/// what this run found). Reason is the technical cause (support / Admin only, never in the customer line).
public sealed record CarriedReport(string ReportName, DateTime? FromUtc, long CarriedRows, long ThisRunRows, string? Reason)
{
    /// The report as a person reads it ("Admin sign-ins to lower-tier devices"), never its template id.
    public string DisplayName => ReportNames.Display(ReportName);
}

/// A collection an Admin released although its Risk Analysis run was not shown complete: loaded once and MARKED PARTIAL
/// (sidata.CollectionPartial, written by the data sync). Reason = why it was held (which part of the run was incomplete).
public sealed record PartialMark(string CollectionId, string? Reason, string? ReleasedBy, DateTime? ReleasedUtc)
{
    /// The data sync's mark of a collection whose run could not complete only some named reports (per-report loading): the
    /// collection is current, those reports show their last complete result.
    public const string PerReportBy = "per report";

    /// The reports of a per-report mark (sidata.CollectionReportCarry). Empty for a whole-collection mark, and for a
    /// database the updater has not given the table yet (then nothing is known per report: the mark shows everywhere).
    public IReadOnlyList<CarriedReport> Reports { get; init; } = Array.Empty<CarriedReport>();

    /// True when only named reports of the run could not be completed (the rest of the collection is current).
    public bool PerReport => string.Equals(ReleasedBy, PerReportBy, StringComparison.OrdinalIgnoreCase);

    /// The badge word: "partial", or per report "older data" (owner 2026-10-19: plain words, no internals).
    public string Badge => PerReport ? "older data" : "partial";

    /// The reports of this mark whose data a page shows (<see cref="ReportPages.Feeds"/>); -report narrows to one report
    /// (a page filtered to one report). Every report when the page is not known.
    public IReadOnlyList<CarriedReport> ReportsOn(string? page, string? report = null) =>
        Reports.Where(r => ReportPages.Feeds(r.ReportName, page) && (string.IsNullOrWhiteSpace(report) || string.Equals(r.ReportName, report, StringComparison.OrdinalIgnoreCase))).ToList();

    /// Whether the mark is shown on a page: a whole-collection mark always; a per-report mark only where one of its reports
    /// feeds the page -- or everywhere when its reports are not known (never hidden on a guess: no silent data loss).
    public bool ShowsOn(string? page, string? report = null) => !PerReport || Reports.Count == 0 || ReportsOn(page, report).Count > 0;

    /// The words of the mark without its reports: the whole-collection partial text, or -- per report, when the reports are
    /// not known -- one plain line. The per-report line with its reports and dates is the shared notice
    /// (Pages/Shared/_PartialNotice.cshtml, <see cref="PartialNotice"/>).
    public string Text => PerReport
        ? "Some reports show data from an earlier run: this run could not finish them."
        : "Partial collection: loaded on request of " + (string.IsNullOrWhiteSpace(ReleasedBy) ? "an Admin" : ReleasedBy) +
        " although the Risk Analysis run that produced it did not finish completely" + (string.IsNullOrWhiteSpace(Reason) ? "." : " -- " + Reason.TrimEnd('.') + ".") +
        " Findings missing from it are unknown, not resolved.";
}

/// What one page shows of a mark: the mark, the reports that feed the page, and whether the reader may see the details
/// (the technical cause -- Admins and support). The model of Pages/Shared/_PartialNotice.cshtml.
public sealed record PartialNotice(PartialMark Mark, IReadOnlyList<CarriedReport> Reports, bool Details)
{
    /// The notice for a page, or null when the mark is not shown there.
    public static PartialNotice? For(PartialMark? mark, string? page, bool details, string? report = null) =>
        mark is null || !mark.ShowsOn(page, report) ? null : new PartialNotice(mark, mark.ReportsOn(page, report), details);

    /// <summary>
    /// The one customer line (owner 2026-10-19), in words around the date -- the view renders the date in the viewer's own
    /// format. Every report from the same day: "1 report shows data from [date] (this run could not finish it): Admin
    /// sign-ins to lower-tier devices." None with an earlier result: "1 report could not be finished in this run and shows
    /// only what it found: ...". Mixed: Lead "2 reports could not be finished in this run:" and <see cref="Items"/> = true
    /// (each report then says its own date, or "only what this run found").
    /// </summary>
    public (string Lead, DateTime? Date, string Tail, bool Items) Line()
    {
        var n = Reports.Count;
        var count = n == 1 ? "1 report" : n.ToString(CultureInfo.InvariantCulture) + " reports";
        var names = string.Join(", ", Reports.Select(r => r.DisplayName)) + ".";
        var days = Reports.Select(r => r.FromUtc?.Date).Distinct().ToList();
        if (days.Count == 1 && Reports[0].FromUtc is { } from)
            return (count + (n == 1 ? " shows" : " show") + " data from", from, "(this run could not finish " + (n == 1 ? "it" : "them") + "): " + names, false);
        if (days.Count == 1)
            return (count + " could not be finished in this run and " + (n == 1 ? "shows" : "show") + " only what it found: " + names, null, "", false);
        return (count + " could not be finished in this run:", null, "", true);
    }
}

/// <summary>
/// Which reports feed which page (owner 2026-10-19: "shown only where it is relevant"). A page of CVE rows (Vulnerabilities,
/// CVSS, Vulnerabilities per collection) shows the findings of the reports about vulnerabilities only -- the report scope's
/// subject "vulnerability" (data-model/report-scope.locked.json, embedded in SI.Management.Core); a page about the CIs'
/// correlation shows no report's findings. Every other page shows every report. A report the scope does not know (a
/// customer's own) feeds every page: it is never hidden on a guess.
/// </summary>
public static class ReportPages
{
    /// The pages whose rows are CVEs.
    public static readonly IReadOnlySet<string> CvePages = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    { "/Collection/Vulnerabilities", "/Collection/Cvss", "/Collection/Lifecycle" };

    /// The pages that show no report's findings (the correlation of the CIs).
    public static readonly IReadOnlySet<string> NoReportPages = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    { "/Collection/Correlation" };

    public static bool Feeds(string reportName, string? page)
    {
        if (string.IsNullOrWhiteSpace(page)) return true;
        if (NoReportPages.Contains(page)) return false;
        if (CvePages.Contains(page)) return ReportScopeSubjects.Of(reportName) is not { } s || s.Contains("vulnerability");
        return true;
    }
}

/// The subjects of each shipped report (data-model/report-scope.locked.json: "identity-user", "device", "vulnerability"...),
/// read once from the copy embedded in SI.Management.Core (held to the original by a test). Null = not a shipped report.
public static class ReportScopeSubjects
{
    private static readonly Lazy<IReadOnlyDictionary<string, IReadOnlySet<string>>> All = new(Load);

    public static IReadOnlySet<string>? Of(string? reportName) =>
        reportName is not null && All.Value.TryGetValue(reportName.Trim(), out var s) ? s : null;

    private static IReadOnlyDictionary<string, IReadOnlySet<string>> Load()
    {
        var map = new Dictionary<string, IReadOnlySet<string>>(StringComparer.OrdinalIgnoreCase);
        using var stream = typeof(SI.Management.Core.ProData.CiColumns).Assembly.GetManifestResourceStream("DataModel/report-scope.locked.json");
        if (stream is null) return map;
        using var doc = JsonDocument.Parse(stream);
        if (!doc.RootElement.TryGetProperty("reports", out var reports) || reports.ValueKind != JsonValueKind.Array) return map;
        foreach (var r in reports.EnumerateArray())
        {
            if (!r.TryGetProperty("id", out var id) || id.GetString() is not { Length: > 0 } name) continue;
            var subjects = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (r.TryGetProperty("subjects", out var s) && s.ValueKind == JsonValueKind.Array)
                foreach (var x in s.EnumerateArray()) if (x.GetString() is { Length: > 0 } v) subjects.Add(v);
            map[name] = subjects;
        }
        return map;
    }
}

/// <summary>
/// A report as a person reads it, from its template id: the grain (Summary / Detailed) and a leading Identity / Endpoint
/// domain dropped, the words split and in lower case, acronyms kept, and the few compound words SI's report ids use
/// written out ("Identity_Admin_LogonTo_LowTierDevice_Detailed" -> "Admin sign-ins to lower-tier devices"). PURE.
/// </summary>
public static class ReportNames
{
    private static readonly Dictionary<string, string> Phrases = new(StringComparer.Ordinal)
    {
        ["LogonTo"] = "sign-ins to",
        ["LowTierDevice"] = "lower-tier devices",
        ["InternetExposedDevice"] = "internet-exposed devices",
        ["VulnerableDevice"] = "vulnerable devices",
        ["ExploitableDevice"] = "exploitable devices",
        ["NoMFA"] = "no MFA",
        ["CVEs"] = "CVEs",
        ["PublicIP"] = "public IP",
    };

    private static readonly HashSet<string> Domains = new(StringComparer.Ordinal) { "Identity", "Endpoint" };
    private static readonly HashSet<string> Grains = new(StringComparer.Ordinal) { "Detailed", "Summary" };

    public static string Display(string? reportName)
    {
        if (string.IsNullOrWhiteSpace(reportName)) return "";
        var tokens = reportName.Trim().Split('_', StringSplitOptions.RemoveEmptyEntries).Where(t => !Grains.Contains(t)).ToList();
        if (tokens.Count > 1 && Domains.Contains(tokens[0])) tokens.RemoveAt(0);
        var words = new List<string>();
        foreach (var t in tokens)
        {
            if (Phrases.TryGetValue(t, out var p)) { words.Add(p); continue; }
            if (Regex.IsMatch(t, "^[A-Z0-9]{2,}s?$")) { words.Add(t); continue; }
            foreach (var w in Regex.Split(t, "(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])"))
                if (w.Length > 0) words.Add(Regex.IsMatch(w, "^[A-Z0-9]{2,}s?$") ? w : w.ToLowerInvariant());
        }
        if (words.Count == 0) return reportName.Trim();
        var s = string.Join(" ", words);
        return char.ToUpperInvariant(s[0]) + s[1..];
    }
}

/// <summary>
/// The partial marks, for the "partial" badge wherever a collection is shown (the collection views' picker and header,
/// the departments, the findings browser, the Guards page). Read-only; a database without sidata.CollectionPartial (the
/// data sync adds it with the first released load) has no marks. NEVER throws: a failed read shows no badge and is logged.
/// </summary>
public interface IPartialCollections
{
    Task<IReadOnlyDictionary<string, PartialMark>> MarksAsync(CancellationToken ct);
}

public sealed class SqlPartialCollections : IPartialCollections
{
    public const string MarksSql = """
IF OBJECT_ID(N'sidata.CollectionPartial') IS NULL
    SELECT TOP (0) CAST(NULL AS nvarchar(64)) AS CollectionId, CAST(NULL AS nvarchar(2000)) AS Reason, CAST(NULL AS nvarchar(256)) AS ReleasedBy, CAST(NULL AS datetime2(0)) AS ReleasedUtc;
ELSE
    SELECT CONVERT(nvarchar(64), p.CollectionId) AS CollectionId, p.Reason, p.ReleasedBy, p.ReleasedUtc FROM sidata.CollectionPartial AS p;
""";

    /// The reports of the marked collections that their run could not finish (one row per collection and report; a small
    /// table -- the data sync clears the rows of collections that are gone). A database without the table answers none.
    public const string ReportsSql = """
IF OBJECT_ID(N'sidata.CollectionReportCarry') IS NULL OR OBJECT_ID(N'sidata.CollectionPartial') IS NULL
    SELECT TOP (0) CAST(NULL AS nvarchar(64)) AS CollectionId, CAST(NULL AS nvarchar(256)) AS ReportName, CAST(NULL AS datetime2(3)) AS FromTime, CAST(NULL AS int) AS CarriedRows, CAST(NULL AS int) AS ThisRunRows, CAST(NULL AS nvarchar(2000)) AS Reason;
ELSE
    SELECT CONVERT(nvarchar(64), r.CollectionId) AS CollectionId, r.ReportName, r.FromTime, r.CarriedRows, r.ThisRunRows, r.Reason
    FROM sidata.CollectionReportCarry AS r
    WHERE EXISTS (SELECT 1 FROM sidata.CollectionPartial AS p WHERE p.CollectionId = r.CollectionId)
    ORDER BY r.CollectionId, r.ReportName;
""";

    private readonly ISqlExecutor _sql;
    private readonly IMemoryCache? _cache;
    private readonly ILogger<SqlPartialCollections>? _log;
    public SqlPartialCollections(ISqlExecutor sql, IMemoryCache? cache = null, ILogger<SqlPartialCollections>? log = null) { _sql = sql; _cache = cache; _log = log; }

    public async Task<IReadOnlyDictionary<string, PartialMark>> MarksAsync(CancellationToken ct)
    {
        if (_cache is not null && _cache.TryGetValue("partial-collections", out IReadOnlyDictionary<string, PartialMark>? hit) && hit is not null) return hit;
        IReadOnlyDictionary<string, PartialMark> marks;
        try
        {
            var rows = await _sql.QueryAsync(MarksSql, new Dictionary<string, object?>(), ct);
            var reports = rows.Count == 0 ? new Dictionary<string, List<CarriedReport>>() : await ReportsAsync(ct);
            marks = rows.Select(r => new PartialMark(r.Str("CollectionId") ?? "", r.Str("Reason"), r.Str("ReleasedBy"),
                    r.TryGetValue("ReleasedUtc", out var v) && v is DateTime d ? DateTime.SpecifyKind(d, DateTimeKind.Utc) : null))
                .Where(m => m.CollectionId.Length > 0).GroupBy(m => m.CollectionId)
                .ToDictionary(g => g.Key, g => g.First() with { Reports = reports.TryGetValue(g.Key, out var l) ? l : (IReadOnlyList<CarriedReport>)Array.Empty<CarriedReport>() }, StringComparer.Ordinal);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "the partial collection marks could not be read -- no partial badge is shown");
            marks = new Dictionary<string, PartialMark>();
        }
        _cache?.Set("partial-collections", marks, TimeSpan.FromSeconds(60));
        return marks;
    }

    /// The reports per collection; a failed read is logged and answers none (the mark then shows without them, everywhere).
    private async Task<Dictionary<string, List<CarriedReport>>> ReportsAsync(CancellationToken ct)
    {
        var map = new Dictionary<string, List<CarriedReport>>(StringComparer.Ordinal);
        try
        {
            foreach (var r in await _sql.QueryAsync(ReportsSql, new Dictionary<string, object?>(), ct))
            {
                var id = r.Str("CollectionId"); var name = r.Str("ReportName");
                if (string.IsNullOrEmpty(id) || string.IsNullOrWhiteSpace(name)) continue;
                if (!map.TryGetValue(id, out var list)) map[id] = list = new List<CarriedReport>();
                list.Add(new CarriedReport(name.Trim(), r.Date("FromTime") is { } f ? DateTime.SpecifyKind(f, DateTimeKind.Utc) : null,
                    r.Long("CarriedRows") ?? 0, r.Long("ThisRunRows") ?? 0, r.Str("Reason")));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "the reports of the partial collections could not be read -- their marks show without them");
        }
        return map;
    }

    public static string Id(long id) => id.ToString(CultureInfo.InvariantCulture);
}
