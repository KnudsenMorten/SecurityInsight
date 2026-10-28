using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Export;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Admin &gt; Audit trail (#260, framework AUDIT-1.4) -- what was Change history. Every event of the install, newest
/// first: who (actor, source), what (action, target), why (reason), how it ended (outcome) and the change summary
/// (before -> after; the cfg.ChangeLog rows the event wrote are shown under it). Server-side search, time window and
/// from / to, filters per column, sort, paging; CSV and Excel of the WHOLE filtered result and a print view -- each of
/// those is itself on the trail. Admin and up see everything; a Delegated user sees the rows in their scope (and what
/// they did themselves); every other role is refused (the page's policy). Read-only: nothing here writes the trail
/// except the audit filter recording the export / print.
/// A database whose schema is older than the trail shows the change log as before, with a notice.
/// </summary>
public sealed class HistoryModel : PageModel
{
    private readonly ISettingsStoreReader _reader;
    private readonly AuditTrailReader _trail;
    private readonly AuditActions _actions;
    private readonly AuditHealth _health;
    private readonly ILogger<HistoryModel> _log;
    public HistoryModel(ISettingsStoreReader reader, AuditTrailReader trail, AuditActions actions, AuditHealth health, ILogger<HistoryModel> log)
    { _reader = reader; _trail = trail; _actions = actions; _health = health; _log = log; }

    public static readonly (string Value, string Label)[] Windows =
        [("1", "Last month"), ("3", "Last 3 months"), ("6", "Last 6 months"), ("13", "Last 13 months"), ("24", "Last 24 months"), ("all", "All time")];
    public const int PrintMax = 2000;

    // ---- the legacy filter (deep links from Deviations, Settings, the CMDB): a name -> Target contains
    [BindProperty(SupportsGet = true)] public string? Name { get; set; }
    [BindProperty(SupportsGet = true)] public int Top { get; set; } = 200;
    [BindProperty(SupportsGet = true)] public string? Win { get; set; }
    [BindProperty(SupportsGet = true)] public string? From { get; set; }
    [BindProperty(SupportsGet = true)] public string? To { get; set; }
    /// The browser's time zone (IANA), sent with the filter form: from / to are the person's own days (#313).
    [BindProperty(SupportsGet = true)] public string? Tz { get; set; }

    public bool HasTrail { get; private set; }
    public IReadOnlyList<ChangeLogRow> Rows { get; private set; } = Array.Empty<ChangeLogRow>();
    public IReadOnlyList<AuditRow> Events { get; private set; } = Array.Empty<AuditRow>();
    public IReadOnlyDictionary<string, IReadOnlyList<AuditRow>> Changes { get; private set; } = new Dictionary<string, IReadOnlyList<AuditRow>>();
    public long Total { get; private set; }
    public GridState? State { get; private set; }
    public AuditVisibility? Visibility { get; private set; }
    public string Query { get; private set; } = SqlSettingsReader.ChangeLogSql;
    public string? Error { get; private set; }
    public bool PrintView { get; private set; }
    public DateTime? FromUtc { get; private set; }
    public DateTime? ToUtc { get; private set; }
    public string WindowValue => Win is { Length: > 0 } w && Windows.Any(x => x.Value == w) ? w : (From is not null || To is not null ? "all" : "3");
    public AuditHealth Health => _health;
    public IReadOnlyList<string> Categories => _actions.Categories;
    public static readonly IReadOnlyList<string> Outcomes = [AuditOutcomes.Ok, AuditOutcomes.Refused, AuditOutcomes.Error, AuditOutcomes.Held];
    public IReadOnlyList<string> Sources => _actions.ActorSources;
    public static IReadOnlyList<string> Domains => SecurityDomains.Known;

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (AuditVisibility.Of(User) is not { } vis) return Forbid();
        Visibility = vis;
        try
        {
            HasTrail = await _trail.ExistsAsync(ct);
            if (!HasTrail)
            {
                // the schema predates the trail: the change log, as before (Admin only -- it is not scoped)
                if (!vis.All) { Error = "The audit trail is not set up in this database yet -- ask an Admin to apply the Pro settings schema."; return Page(); }
                Top = Fmt.Pick(Top, 200, 50, 200, 1000);
                (Rows, Query) = await _reader.ReadChangeLogAsync(Name, Top, ct);
                return Page();
            }
            await LoadPageAsync(vis, ct);
        }
        catch (ArgumentException ex) { Error = ex.Message; }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the audit trail failed");
            Error = "The audit trail could not be read: " + ex.Message;
        }
        return Page();
    }

    private async Task LoadPageAsync(AuditVisibility vis, CancellationToken ct, int? size = null)
    {
        var st = State = GridState(size);
        (FromUtc, ToUtc) = Range();
        (Events, Total, Query) = await _trail.PageAsync(st, vis, FromUtc, ToUtc, ct);
        Changes = await _trail.ChangesAsync(Events.Where(e => e.RecordType == "event" && e.Changes > 0).Select(e => e.CorrelationId!), ct);
    }

    /// The print view (AUDIT-1.4 "print as evidence"): the filter, the time range, who printed it and when, and up to
    /// <see cref="PrintMax"/> rows of the filtered trail -- the export carries the whole of it.
    [Audited("audit.trail.print")]
    public async Task<IActionResult> OnGetPrintAsync(CancellationToken ct)
    {
        if (AuditVisibility.Of(User) is not { } vis) return Forbid();
        Visibility = vis;
        PrintView = true;
        if (!(HasTrail = await _trail.ExistsAsync(ct))) return NotFound("The audit trail is not set up in this database yet.");
        await LoadPageAsync(vis, ct, PrintMax);
        if (AuditScope.Current is { } a) { a.Rows = Events.Count; a.Filter = FilterText(); }
        return Page();
    }

    /// CSV of the WHOLE filtered trail (UTF-8 with a BOM; formula-looking cells defused; times ISO UTC). Audited.
    [Audited("audit.trail.export")]
    public async Task<IActionResult> OnGetCsvAsync(CancellationToken ct)
    {
        if (AuditVisibility.Of(User) is not { } vis) return Forbid();
        if (!await _trail.ExistsAsync(ct)) return NotFound("The audit trail is not set up in this database yet.");
        GridState st; (DateTime?, DateTime?) range;
        try { st = GridState(null); range = Range(); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        var path = Path.Combine(Path.GetTempPath(), "si-audit-" + Guid.NewGuid().ToString("N") + ".csv");
        var file = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 64 * 1024, FileOptions.DeleteOnClose);
        long n = 0;
        try
        {
            await using (var w = new StreamWriter(file, new UTF8Encoding(true), 64 * 1024, leaveOpen: true))
            {
                await w.WriteLineAsync(string.Join(",", ExportColumns));
                await foreach (var r in _trail.AllAsync(st, vis, range.Item1, range.Item2, ct))
                {
                    await w.WriteLineAsync(string.Join(",", Cells(r).Select(c => Findings.IndexModel.Csv(c is DateTime d ? d.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture) : Convert.ToString(c, CultureInfo.InvariantCulture)))));
                    n++;
                }
            }
            file.Position = 0;
        }
        catch { await file.DisposeAsync(); throw; }
        if (AuditScope.Current is { } a) { a.Rows = n; a.Filter = FilterText(); }
        return new FileStreamResult(file, "text/csv; charset=utf-8") { FileDownloadName = "audit-trail-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + "Z.csv" };
    }

    /// Excel of the WHOLE filtered trail (up to Excel's row limit, which the Export sheet then says). Audited.
    [Audited("audit.trail.export")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        if (AuditVisibility.Of(User) is not { } vis) return Forbid();
        if (!await _trail.ExistsAsync(ct)) return NotFound("The audit trail is not set up in this database yet.");
        GridState st; (DateTime?, DateTime?) range;
        try { st = GridState(null); range = Range(); }
        catch (ArgumentException ex) { return BadRequest(ex.Message); }
        var filter = FilterText();
        var result = await ExcelExport.FileAsync("audit-trail", null, async (x, info) =>
        {
            info.Add("Visible to you", vis.Describe());
            info.Filter("Time window", WindowText(range.Item1, range.Item2));
            info.Filter("Filter", filter);
            using var s = x.AddSheet("Audit trail", ExportColumns);
            await foreach (var r in _trail.AllAsync(st, vis, range.Item1, range.Item2, ct))
            {
                if (s.RowCount + 2 >= XlsxWriter.MaxRows) { info.Notes.Add("Excel's row limit was reached -- the CSV export carries every row."); break; }
                s.WriteRow(Cells(r));
            }
            info.Rows.Add((s.Name, s.RowCount));
        }, ct);
        if (AuditScope.Current is { } a) a.Filter = filter;
        return result;
    }

    public static readonly string[] ExportColumns =
        ["Id", "Time (UTC)", "Record", "Action", "Category", "Actor", "Source", "Target", "Reason", "Outcome", "Detail", "Plan (WhatIf)", "Domain", "Department", "Correlation", "Before", "After"];

    private static object?[] Cells(AuditRow r) =>
    [
        r.Id, r.TsUtc, r.RecordType, r.Action, r.Category, r.Actor, r.ActorSource, r.Target, r.Reason, r.Outcome, r.OutcomeText, r.WhatIf ? 1 : 0,
        r.ScopeDomain, r.ScopeDepartmentId, r.CorrelationId, r.BeforeJson, r.AfterJson,
    ];

    // ---- the URL state ---------------------------------------------------------------------------------------------
    /// #287: the events per choice of one column filter, under the OTHER filters, the time range and the reader's
    /// visibility (read when the filter is opened).
    public async Task<IActionResult> OnGetValueCountsAsync(string? col, CancellationToken ct)
    {
        if (AuditVisibility.Of(User) is not { } vis) return Forbid();
        try
        {
            if (!await _trail.ExistsAsync(ct) || AuditTrailReader.Spec.Column(col) is not { Filter: GridFilter.Values or GridFilter.Tokens } c)
                return new JsonResult(new { ok = false });
            var (from, to) = Range();
            var counts = await _trail.ValueCountsAsync(GridState(null), vis, from, to, c.Key, ct);
            return new JsonResult(new { ok = true, column = c.Key, values = counts.Select(x => new { value = x.Value, n = x.N, text = Fmt.Int(x.N) }) });
        }
        catch (ArgumentException ex) { return new JsonResult(new { ok = false, message = ex.Message }); }
    }

    public GridState GridState(int? size)
    {
        var q = Request.Query;
        var filters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var kv in q)
        {
            if (!kv.Key.StartsWith("f.", StringComparison.OrdinalIgnoreCase)) continue;
            var joined = string.Join("|", kv.Value.Where(v => !string.IsNullOrWhiteSpace(v)));
            if (joined.Length > 0) filters[kv.Key[2..]] = joined;
        }
        // a deep link by name (Deviations, Settings, the CMDB): the target names it
        if (!string.IsNullOrWhiteSpace(Name) && !filters.ContainsKey("Target")) filters["Target"] = Name.Trim();
        var dir = (string?)q["dir"];
        var req = new GridRequest
        {
            Sort = q["sort"], Desc = dir is "desc" ? true : dir is "asc" ? false : null,
            Page = int.TryParse(q["p"], NumberStyles.None, CultureInfo.InvariantCulture, out var p) ? p : 1,
            Size = GridSql.PageSize((string?)q["size"]),
            Search = q["q"], Filters = filters,
        };
        var st = GridSql.Normalize(AuditTrailReader.Spec, req);
        return size is { } n ? st with { Page = 1, Size = n } : st;
    }

    /// The time window: last N months (from now), or all; an explicit from / to (to inclusive) narrows it. The days are
    /// the person's own: read in the browser's zone (<see cref="Tz"/>, BRAND-2.10), UTC days when no zone was sent.
    public (DateTime? From, DateTime? To) Range()
    {
        string? tz = Tz;
        DateTime? Day(string? s, string what, int addDays = 0) => string.IsNullOrWhiteSpace(s) ? null
            : DateTime.TryParseExact(s.Trim(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var d)
                ? LocalTime.DayStartUtc(d.AddDays(addDays).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), tz)
                : throw new ArgumentException($"'{s}' is not a date ({what}: yyyy-MM-dd)");
        DateTime? from = WindowValue == "all" ? null : DateTime.UtcNow.AddMonths(-int.Parse(WindowValue, CultureInfo.InvariantCulture));
        var f = Day(From, "from");
        if (f is { } ff && (from is null || ff > from)) from = ff;
        DateTime? to = Day(To, "to", 1);
        if (from is { } a && to is { } b && b <= a) throw new ArgumentException("'to' is before 'from'");
        return (from, to);
    }

    public string WindowText(DateTime? from, DateTime? to) =>
        (from is null ? "from the beginning" : "from " + Fmt.When(from)) + (to is null ? " to now" : " to " + Fmt.When(to));

    /// The filter as a sentence (the print view, the export's Export sheet, the audit row of the export).
    public string FilterText()
    {
        var st = State ?? GridState(null);
        var parts = new List<string> { "window " + Windows.First(w => w.Value == WindowValue).Label.ToLowerInvariant() };
        if (!string.IsNullOrWhiteSpace(From)) parts.Add("from " + From);
        if (!string.IsNullOrWhiteSpace(To)) parts.Add("to " + To);
        if (st.Search is { } s) parts.Add("search \"" + s + "\"");
        foreach (var f in st.Filters)
            parts.Add((AuditTrailReader.Spec.Column(f.Key)?.Label ?? f.Key) + ": " + (f.Values.Count > 0 ? string.Join(" or ", f.Values) : f.Text ?? (f.Low + ".." + f.High)));
        parts.Add("sort " + st.Sort + (st.Desc ? " (descending)" : ""));
        return string.Join("; ", parts);
    }

    /// This page's URL with the current query, some parameters overridden (null removes one; anything but p starts at 1).
    public string Link(params (string Key, string? Value)[] overrides)
    {
        var over = overrides.Select(o => o.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var parts = new List<(string, string)>();
        foreach (var kv in Request.Query)
        {
            if (kv.Key.Equals("handler", StringComparison.OrdinalIgnoreCase) || over.Contains(kv.Key)) continue;
            if (kv.Key.Equals("p", StringComparison.OrdinalIgnoreCase) && overrides.Length > 0) continue;
            foreach (var v in kv.Value) if (!string.IsNullOrEmpty(v)) parts.Add((kv.Key, v));
        }
        foreach (var (k, v) in overrides) if (!string.IsNullOrEmpty(v)) parts.Add((k, v));
        var qs = string.Join("&", parts.Select(x => Uri.EscapeDataString(x.Item1) + "=" + Uri.EscapeDataString(x.Item2)));
        return "/Admin/History" + (qs.Length > 0 ? "?" + qs : "");
    }

    public string HandlerLink(string handler) { var l = Link(); return l + (l.Contains('?') ? "&" : "?") + "handler=" + handler; }
}
