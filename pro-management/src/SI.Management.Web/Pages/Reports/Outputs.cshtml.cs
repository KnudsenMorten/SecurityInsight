using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Outputs;
using SI.Management.Web.Reports;
using ItemWrite = SI.Management.Core.ProData.ItemWrite; // the report designer's write (not the editors' Changes.ItemWrite)

namespace SI.Management.Web.Pages.Reports;

/// <summary>
/// The output scope per destination (#274 part 4): Excel + mail, the SQL and ServiceNow vulnerability connectors, the SQL
/// and ServiceNow CMDB connectors -- which templates / reports feed each and which severities, tiers and domains (CMDB: tiers
/// and asset kinds) pass, with a preview count from the newest collection by the engines' own rule. Stored as the
/// cfg.ItemOverride kind 'outputscope'; the engines read it from config\output-scope.json (SI-OutputScope.ps1).
/// </summary>
/// Owner 2026-10-19 ("one for reports and one for connectors"): the same store, split in the VIEW -- the workbooks' scope
/// (Excel + mail) on Configuration > Reports > Workbook scope, every connector's on Configuration > Connectors > Scope
/// (<see cref="SI.Management.Web.Pages.Connectors.ScopeModel"/>).
public class OutputsModel : ReportsPage
{
    public OutputsModel(IReportStore store, ChangeService changes, ILogger<OutputsModel> log) : base(store, changes, log) { }
    protected OutputsModel(IReportStore store, ChangeService changes, ILogger log) : base(store, changes, log) { }

    /// "workbook" (Excel + mail) or "connector" (every other destination).
    public virtual string Area => OutputFieldsModel.WorkbookArea;

    /// The destinations of this area.
    public IReadOnlyList<OutputDestination> Destinations => OutputScope.Destinations.Where(d => AreaOf(d) == Area).ToList();

    /// The area a destination belongs to: Excel + mail is the workbooks'; every other destination a connector's.
    public static string AreaOf(OutputDestination d) => d.Key == "excel" ? OutputFieldsModel.WorkbookArea : OutputFieldsModel.ConnectorArea;

    [BindProperty] public string? Destination { get; set; }
    [BindProperty] public List<string> Templates { get; set; } = new();
    [BindProperty] public List<string> Reports { get; set; } = new();
    [BindProperty] public List<string> Severities { get; set; } = new();
    [BindProperty] public List<int> Tiers { get; set; } = new();
    [BindProperty] public List<string> Domains { get; set; } = new();
    [BindProperty] public List<string> AssetKinds { get; set; } = new();

    public ReportPreviewData? Preview { get; private set; }
    public IReadOnlyDictionary<string, IReadOnlyList<string>> Membership { get; private set; } = new Dictionary<string, IReadOnlyList<string>>();

    public async Task OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return;
        await PrepareAsync(ct);
    }

    /// Owner 2026-10-19: per finding destination, how many findings on how many assets its scope (as in force, or as the
    /// form posted it) lets through of the newest collection.
    public Dictionary<string, ScopeCount?> Counts { get; } = new(StringComparer.Ordinal);
    /// A scope as the form posted it (shown and counted instead of the one in force, e.g. after a quick choice).
    public Dictionary<string, OutputScope> Posted { get; } = new(StringComparer.Ordinal);
    /// Per vulnerability destination: its connectors are not sending yet (none, switched off, or whatif) -- the export of
    /// what would be sent is offered.
    public Dictionary<string, (bool TestMode, string Words)> Modes { get; } = new(StringComparer.Ordinal);

    /// The scope a destination's form shows: as posted, else in force.
    public OutputScope ScopeShown(string dest) => Posted.TryGetValue(dest, out var p) ? p : State!.ScopeOf(dest);

    private async Task PrepareAsync(CancellationToken ct)
    {
        Membership = State!.Membership();
        try { Preview = await Store.PreviewAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.LogWarning(ex, "the preview counts could not be read");
            Preview = new ReportPreviewData([], [], null, "the preview counts could not be read: " + ex.Message);
        }
        foreach (var d in Destinations.Where(d => !d.Asset))
        {
            var s = ScopeShown(d.Key);
            try { Counts[d.Key] = await Store.ScopeCountAsync(s, s.Resolved(Membership), ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log.LogWarning(ex, "the scope count of {Destination} could not be read", d.Key); Counts[d.Key] = null; }
        }
        await ReadModesAsync(ct);
    }

    private async Task ReadModesAsync(CancellationToken ct)
    {
        IReadOnlyList<ConnectorRow> rows = Array.Empty<ConnectorRow>();
        if (HttpContext?.RequestServices.GetService<ConnectorRepository>() is { } repo)
        {
            try { if (await repo.TableExistsAsync(ct)) rows = await repo.ListAsync(ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { Log.LogWarning(ex, "the connectors could not be read"); }
        }
        foreach (var d in Destinations.Where(d => d.Key.StartsWith("vuln-", StringComparison.Ordinal)))
            Modes[d.Key] = ScopeExport.Mode(d.Key, rows);
    }

    /// "N findings on M assets would be sent (of T)" -- by the filters, from the newest collection.
    public string? Sent(OutputScope s) =>
        Counts.TryGetValue(s.Destination, out var c) && c is not null
            ? $"{Fmt.Int(c.Findings)} {"finding(s)"} on {Fmt.Int(c.Assets)} asset(s) would be sent (of {Fmt.Int(c.TotalFindings)})"
              + (c.NotCounted.Count > 0 ? " -- not counted: " + string.Join(", ", c.NotCounted) + " (no column of the findings yet)" : "")
            : null;

    public string? Count(OutputScope s)
    {
        if (!s.IsAsset && Sent(s) is { } sent) return sent;
        if (Preview is null || Preview.Note is not null) return null;
        var total = s.IsAsset ? Preview.Assets.Where(a => ReportVocabulary.CmdbSentKinds.Contains((a.Kind ?? "").ToLowerInvariant())).Sum(a => a.Count)
                              : Preview.Findings.Where(g => !s.Destination.StartsWith("vuln-", StringComparison.Ordinal) || g.IsCve).Sum(g => g.Count);
        var n = s.IsAsset ? OutputPreview.Assets(s, Preview.Assets) : OutputPreview.Findings(s, Preview.Findings, Membership);
        if (s.IsAsset) return AssetCountWords(s, n, total);
        return $"{Fmt.Int(n)} of {Fmt.Int(total)} {(s.IsAsset ? "asset(s)" : s.Destination.StartsWith("vuln-", StringComparison.Ordinal) ? "CVE finding(s)" : "finding(s)")}";
    }

    /// The write a destination's form makes (an empty scope = back to everything: the item is removed).
    public static (ItemWrite? Write, IReadOnlyList<string> Problems) WriteFor(ReportState s, OutputScope scope)
    {
        var why = scope.Validate(s.Templates.Select(t => t.Name).ToList(), s.Reports.Select(r => r.Name).ToList());
        if (why.Count > 0) return (null, why);
        s.Scopes.TryGetValue(scope.Destination, out var cur);
        var curState = cur.State; var curBody = cur.Body;
        var w = ItemWrites.For("outputscope", scope.Destination, null, curState, curBody, scope.Everything ? null : scope.ToBody(), true, scope.Describe());
        return (w, Array.Empty<string>());
    }

    /// The filters the form posted: F.<si field> (each ticked value, or a box of '|'-separated values).
    public IReadOnlyList<ScopeFilter> PostedFilters()
    {
        var list = new List<ScopeFilter>();
        foreach (var kv in Request.Form.Where(k => k.Key.StartsWith("F.", StringComparison.Ordinal)).OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            var vals = kv.Value.Where(v => !string.IsNullOrWhiteSpace(v)).SelectMany(v => v!.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (vals.Count > 0) list.Add(new ScopeFilter(kv.Key[2..], vals));
        }
        // "+ Add filter": another SI field of the finding, by name
        if (((string?)Request.Form["OtherField"])?.Trim() is { Length: > 0 } other && !list.Any(f => f.Field == other))
        {
            var vals = ((string?)Request.Form["OtherValues"] ?? "").Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            list.Add(new ScopeFilter(other, vals));
        }
        return list;
    }

    /// "Count with these filters": the scope as the form has it, counted on the newest collection -- nothing is staged.
    [NotAudited("a read: counts what a scope as posted would let through; stages and writes nothing")]
    public async Task<IActionResult> OnPostCountAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        if (OutputScope.Find(Destination ?? "") is { } d)
            Posted[d.Key] = new OutputScope(d.Key, Templates, Reports, Severities, Tiers, Domains, AssetKinds) { Filters = PostedFilters() };
        await PrepareAsync(ct);
        return Page();
    }

    /// The address parameter of a filter field.
    public static string FilterParam(string field) => "F." + field;

    /// The words of an asset kind in the CMDB connectors' scope (#817).
    public static string AssetKindWords(string kind) => kind switch
    {
        "endpoint" => "Endpoint (devices)", "identity" => "Identity", "azure" => "Azure", "publicip" => "Public IP", _ => kind,
    };

    /// #817 (main 2026-10-20): every kind is offered, but a kind no CMDB connector sends yet never fails silently -- its
    /// checkbox says so, ticking it shows <see cref="UnsentHint"/> on the card, and the count line names it.
    public static string AssetKindChoiceWords(string kind) =>
        AssetKindWords(kind) + (ReportVocabulary.CmdbSentKinds.Contains(kind) ? "" : " (not sent by this connector yet)");
    public const string UnsentHint = "This connector sends endpoint and azure assets today; identity and public IP are planned.";
    public static IReadOnlyList<string> UnsentKinds => ReportVocabulary.AssetKinds.Where(k => !ReportVocabulary.CmdbSentKinds.Contains(k)).ToList();
    public static IReadOnlyList<string> UnsentTicked(OutputScope s) =>
        UnsentKinds.Where(k => s.AssetKinds.Contains(k, StringComparer.OrdinalIgnoreCase)).ToList();
    private static string UnsentWord(string kind) => kind == "publicip" ? "public IP" : kind;
    /// A CMDB connector's count line: "N of M asset(s)", or with a ticked kind it cannot send yet, what IS sent and what is not.
    public static string AssetCountWords(OutputScope s, long n, long total) => UnsentTicked(s) is { Count: > 0 } unsent
        ? $"{Fmt.Int(n)} asset(s) would be sent; {string.Join(" / ", unsent.Select(UnsentWord))} ticked but not sent yet"
        : $"{Fmt.Int(n)} of {Fmt.Int(total)} asset(s)";

    /// The values of one scope filter in the newest collection, with their counts (js/app/value-counts.js).
    [NotAudited("a read: how many findings of the newest collection hold each value of one column")]
    public async Task<IActionResult> OnGetValueCountsAsync(string? col, CancellationToken ct)
    {
        var column = col switch
        {
            "Severities" => "Severity", "Domains" => "SecurityDomain", "Tiers" => "Tier", "Reports" => "ReportName",
            _ when col is not null && col.StartsWith("F.", StringComparison.Ordinal) => ScopeFilters.Find(col[2..])?.FindingColumn,
            _ => null,
        };
        if (column is null) return new JsonResult(new { ok = false, message = "This filter has no counts in the findings table." });
        try
        {
            var counts = await Store.ValueCountsAsync(column, ct);
            return new JsonResult(new { ok = true, column = col, values = counts.Select(x => new { value = x.Value, label = col == "Tiers" && int.TryParse(x.Value, out var t) && t is >= 0 and <= 3 ? ReportVocabulary.Tiers[t] : x.Value, n = x.N, text = Fmt.Int(x.N) }) });
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return new JsonResult(new { ok = false, message = ex.Message }); }
    }

    /// The scope an export of <paramref name="dest"/> applies and the words for it: the one the page counted (posted, carried
    /// in the link as its stored body -- checked like a staged one), else the scope in force. (null, why) when unusable.
    public (OutputScope? Scope, string Words) ScopeForExport(string dest, string? body)
    {
        if (string.IsNullOrWhiteSpace(body)) { var f = State!.ScopeOf(dest); return (f, "the scope in force: " + f.Describe()); }
        var s = OutputScope.FromBody(dest, body);
        if (s is null) return (null, "the scope in the link could not be read");
        var why = s.Validate(State!.Templates.Select(t => t.Name).ToList(), State.Reports.Select(r => r.Name).ToList());
        return why.Count > 0 ? (null, "the scope in the link is not valid: " + string.Join("; ", why)) : (s, "the scope being edited (not staged): " + s.Describe());
    }

    /// The export link of a destination's card: the scope the page shows travels with it when it was counted, not staged.
    public string ExportLink(string dest, bool csv) =>
        Request.Path + "?handler=Export&destination=" + Uri.EscapeDataString(dest) + (csv ? "&format=csv" : "")
        + (Posted.TryGetValue(dest, out var p) ? "&scope=" + Uri.EscapeDataString(p.ToBody()) : "");

    /// TEST MODE EXPORT (owner 2026-10-19: "a way to export the connector into a excel file when in test mode, before we hit
    /// the prod status"): EVERY row the vulnerability connector would send -- the scope applied, the Fields-sent columns
    /// in their order -- as Excel (with a sheet saying the scope, the run, the counts and the mode) or CSV, generated here
    /// and streamed. Offered while the destination's connectors do not send yet -- the ServiceNow vulnerable items always.
    [Audited("data.export.download")]
    public async Task<IActionResult> OnGetExportAsync(string? destination, string? format, string? scope, CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return NotFound(string.Join(" ", Messages));
        var d = OutputScope.Find(destination ?? "");
        if (d is null || !d.Key.StartsWith("vuln-", StringComparison.Ordinal) || AreaOf(d) != Area) return NotFound("not a vulnerability destination of this page");
        Membership = State!.Membership();
        await ReadModesAsync(ct);
        var exporter = HttpContext.RequestServices.GetRequiredService<ScopeExport>();
        // owner 2026-10-20 ("count of rows that will be send with current filter and rows in excel format and csv format"):
        // the ServiceNow vulnerable items -- always offered, test mode or live, every row with its values as sent; the scope
        // being edited when the page counted one (it travels in the link), else the scope in force
        if (d.Key == "vuln-servicenow" && OutputMapRules.Catalog.FirstOrDefault(x => x.Output == "servicenow-vulnerable-item") is { } snow)
        {
            var (sc, words) = ScopeForExport(d.Key, scope);
            if (sc is null) return BadRequest(words);
            var sf = await exporter.WriteServiceNowAsync(snow, sc, sc.Resolved(Membership), words, Modes.GetValueOrDefault(d.Key).Words ?? "", format == "csv", ct);
            if (AuditScope.Current is { } a) a.Reason = words + "; " + sf.Rows.ToString(System.Globalization.CultureInfo.InvariantCulture) + " row(s)";
            return File(sf.Stream, sf.ContentType, sf.Name);
        }
        var file = await exporter.WriteAsync(d, State.ScopeOf(d.Key), State.ScopeOf(d.Key).Resolved(Membership), Modes.GetValueOrDefault(d.Key).Words ?? "", format == "csv", ct);
        return File(file.Stream, file.ContentType, file.Name);
    }

    [Audited("output.scope.change")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!await LoadAsync(ct)) return Page();
        var d = OutputScope.Find(Destination ?? "");
        if (d is null) { Messages.Add("Not staged: choose a destination"); await PrepareAsync(ct); return Page(); }
        var scope = new OutputScope(d.Key, Templates, Reports, Severities, Tiers, Domains, AssetKinds) { Filters = PostedFilters() };
        var (w, why) = WriteFor(State!, scope);
        if (why.Count > 0) { Messages.AddRange(why.Select(x => "Not staged: " + x)); await PrepareAsync(ct); return Page(); }
        var staged = await StageAsync(ReportChanges.Output, $"Output scope {d.Label}: {scope.Describe()}", w is null ? Array.Empty<ItemWrite>() : new[] { w }, ct);
        if (staged is not null) return staged;
        await PrepareAsync(ct);
        return Page();
    }
}
