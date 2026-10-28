using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using SI.Management.Core.ProData;
using SI.Management.Web.Changes;
using SI.Management.Web.Export;

namespace SI.Management.Web.Outputs;

/// One generated export: a stream (deleted when closed), its content type and file name.
public sealed record ScopeExportFile(Stream Stream, string ContentType, string Name, long Rows);

/// <summary>
/// THE TEST MODE EXPORT of a vulnerability connector (owner 2026-10-19: "i also need a way to export the connector into a
/// excel file when in test mode, before we hit the prod status"): EVERY finding the connector would send -- the
/// destination's output scope applied (<see cref="OutputScope.Passes"/>, the same rule the engine applies), with the
/// columns of its Fields-sent map in their order (<see cref="OutputMapper"/>) -- read a page at a time and written straight
/// to a temporary file (deleted when the download closes): no row cap. Excel holds 1,048,575 rows a sheet, so a larger set
/// goes on to "Would send 2", ... A last sheet says the destination, the scope, the run, the counts and the mode. CSV:
/// one file, every row.
/// </summary>
public sealed class ScopeExport(OutputRowPreview items, OutputMapStore maps, ILogger<ScopeExport> log)
{
    /// The output map of what each vulnerability destination sends.
    public static string OutputOf(string destination) => destination == "vuln-sql" ? "sql-vulnerability-target" : "servicenow-vulnerable-item";

    /// The columns when no output map is in the settings database yet: the finding as it is identified and scoped.
    public static readonly IReadOnlyList<OutputColumn> Fallback =
    [
        new("si_ci_id", "si_ci_id", null, null), new("si_asset_name", "si_asset_name", null, null), new("si_finding_key", "si_finding_key", null, null),
        new("si_severity", "si_severity", null, null), new("si_risk_rating", "si_risk_rating", null, null), new("si_tier", "si_tier", null, null),
        new("si_security_domain", "si_security_domain", null, null), new("si_component", "si_component", null, null), new("si_finding_state", "si_finding_state", null, null),
    ];

    /// The Scope sheet's "Source" line.
    public const string CiSource = "the findings per CI (the newest CI build)";
    public const string RunSource = "the published run's findings -- the findings per CI are not built yet (the data sync builds them)";

    /// Whether the destination's connectors send yet: none, switched off or whatif = test mode (the export is offered).
    public static (bool TestMode, string Words) Mode(string destination, IReadOnlyList<ConnectorRow> connectors)
    {
        var kind = destination == "vuln-sql" ? "sql" : "servicenow";
        var mine = connectors.Where(c => string.Equals(c.Kind, kind, StringComparison.OrdinalIgnoreCase) && string.Equals(c.Direction, "vulnerability", StringComparison.OrdinalIgnoreCase)).ToList();
        if (mine.Count == 0) return (true, "no connector set up yet");
        var words = string.Join("; ", mine.Select(c => c.Name + ": " + (!c.Enabled ? "switched off" : c.Mode == "apply" ? "sends (apply)" : "whatif -- plans and logs, sends nothing")));
        return (!mine.Any(c => c.Enabled && c.Mode == "apply"), words);
    }

    /// The finding's values for the scope's old dimensions (severity, tier, domain, report).
    private static (string? Sev, int? Tier, string? Dom, string? Rep) Dims(JsonObject it)
    {
        string? T(string n) => OutputMapper.Get(it, n) is { } v && OutputMapper.Text(v) is { Length: > 0 } s ? s : null;
        int? tier = int.TryParse(T("si_tier"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var t) ? t : null;
        return (T("si_severity") ?? T("SecuritySeverity"), tier, T("si_security_domain") ?? T("SecurityDomain"), T("si_report_name") ?? T("ReportName"));
    }

    /// Does one finding item pass the destination's scope (and the output map's own filter)?
    public static bool Passes(OutputScope scope, IReadOnlySet<string>? resolved, JsonObject? mapFilter, JsonObject it)
    {
        if (!OutputMapper.Passes(it, mapFilter)) return false;
        var (sev, tier, dom, rep) = Dims(it);
        return scope.Passes(sev, tier, dom, rep, resolved, ScopeFilters.ValuesOf(it, scope.Filters));
    }

    public async Task<ScopeExportFile> WriteAsync(OutputDestination d, OutputScope scope, IReadOnlySet<string>? resolved, string mode, bool csv, CancellationToken ct)
    {
        var output = OutputOf(d.Key);
        OutputMapView? map = null;
        try { map = await maps.LoadAsync(output, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the output map {Output} could not be read; the export carries the finding's own fields", output); }
        var columns = map is null ? Fallback : map.Columns.Where(c => !c.Removed).Select(c => c.InForce).ToList();
        JsonObject? mapFilter = null;
        try { if (map?.FilterJson is { } fj) mapFilter = JsonNode.Parse(fj) as JsonObject; } catch (System.Text.Json.JsonException) { mapFilter = null; }
        var header = columns.Select(c => c.Name).ToList();
        var path = Path.Combine(Path.GetTempPath(), "si-scope-export-" + Guid.NewGuid().ToString("N") + (csv ? ".csv" : ".xlsx"));
        var fs = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 1 << 16, FileOptions.DeleteOnClose);
        long total = 0, sent = 0;
        var assets = new HashSet<string>(StringComparer.Ordinal);
        var maps0 = OutputMapper.ShippedValueMaps;
        var now = DateTime.UtcNow;
        // owner 2026-10-20 ("the export must contain data from the source (si)"): the findings per CI when the data sync has
        // built them, else the published run's own findings -- what the vulnerability connectors' snapshot reads anyway
        var fromRun = !await items.HasCiFindingsAsync(ct);
        var source = fromRun ? RunSource : CiSource;
        IAsyncEnumerable<JsonObject> Items() => fromRun ? items.RunFindingItemsAsync(ct) : items.FindingItemsAsync(ct);
        if (csv)
        {
            await using (var w = new StreamWriter(fs, new UTF8Encoding(true), 1 << 16, leaveOpen: true))
            {
                await w.WriteLineAsync(string.Join(",", header.Select(Csv)));
                await foreach (var it in Items())
                {
                    total++;
                    if (!Passes(scope, resolved, mapFilter, it)) continue;
                    sent++; assets.Add(AssetOf(it));
                    await w.WriteLineAsync(string.Join(",", OutputMapper.Row(columns, it, maps0).Select(Csv)));
                }
            }
        }
        else
        {
            using (var x = new XlsxWriter(fs, "SecurityInsight " + d.Label + " -- would send", now))
            {
            var sheetNo = 1;
            var sheet = x.AddSheet("Would send", header);
            try
            {
                await foreach (var it in Items())
                {
                    total++;
                    if (!Passes(scope, resolved, mapFilter, it)) continue;
                    sent++; assets.Add(AssetOf(it));
                    if (sheet.RowCount >= XlsxWriter.MaxRows - 1) { sheet.Dispose(); sheet = x.AddSheet("Would send " + (++sheetNo).ToString(CultureInfo.InvariantCulture), header); }
                    sheet.WriteRow(OutputMapper.Row(columns, it, maps0).Cast<object?>().ToList());
                }
            }
            finally { sheet.Dispose(); }
            x.WriteSheet("Scope", ["What", "Value"], new List<IReadOnlyList<object?>>
            {
                new object?[] { "Destination", d.Label }, new object?[] { "Output (Fields sent)", map is null ? output + " -- not in the settings database yet: the finding's own fields" : map.Entry.Label },
                new object?[] { "Scope", scope.Describe() }, new object?[] { "Mode", mode }, new object?[] { "Source", source },
                new object?[] { "Findings read", total }, new object?[] { "Findings it would send", sent }, new object?[] { "Assets it would send", (long)assets.Count },
                new object?[] { "Exported (UTC)", now }, new object?[] { "Columns", string.Join(", ", header) },
                new object?[] { "Note", "The findings the data model holds now (the newest CI build), the scope applied with the rule the connector applies; the run's own values say " + OutputMapper.ComputedAtSend + "." },
            });
            x.Complete();
            }
        }
        log.LogInformation("test mode export of {Destination}: {Sent} of {Total} findings on {Assets} assets ({Format}; {Source})", d.Key, sent, total, assets.Count, csv ? "csv" : "xlsx", fromRun ? "the run's findings" : "the findings per CI");
        fs.Position = 0;
        var name = "SecurityInsight_" + d.Key + "_would-send_" + now.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + (csv ? ".csv" : ".xlsx");
        return new ScopeExportFile(fs, csv ? "text/csv; charset=utf-8" : XlsxWriter.ContentType, name, sent);
    }

    /// <summary>
    /// EVERY ROW A SERVICENOW OUTPUT WOULD SEND (owner 2026-10-20: "in the servicenow show also count of rows that will be send
    /// with current filter and rows in excel format and csv fomat" -- "so servicenow can test"), in test mode or live: the
    /// columns IN FORCE in their order, each value EXACTLY as the connector sends it (<see cref="OutputMapper.SentRow"/>:
    /// true / false, a list as JSON, ISO dates; a run value says "(set when sent)"). The vulnerable items with the ServiceNow
    /// vulnerability connector's scope (<paramref name="scope"/>: as posted or in force -- <paramref name="scopeWords"/> says
    /// which) and the output's own filter; the CI hand-off with the output's own filter (its rows are the CIs). Read a page at
    /// a time and written straight to a temporary file (deleted when the download closes): no row cap. Excel holds 1,048,575
    /// rows a sheet, so a larger set goes on to "Would send 2", ... with a last sheet saying the output, the filter, the mode
    /// and the counts. CSV: UTF-8, comma-separated, quoted as RFC 4180 (CRLF line ends), the header = the column names.
    /// </summary>
    public async Task<ScopeExportFile> WriteServiceNowAsync(DataOutEntry e, OutputScope? scope, IReadOnlySet<string>? resolved, string scopeWords, string mode, bool csv, CancellationToken ct)
    {
        if (ServiceNowOutputs.Of(e.Output) is null) throw new ArgumentException($"'{e.Output}' is not a ServiceNow output");
        OutputMapView? map = null;
        try { map = await maps.LoadAsync(e.Output, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the output map {Output} could not be read; the export carries the item's own fields", e.Output); }
        var columns = map is null ? Fallback : map.Columns.Where(c => !c.Removed).Select(c => c.InForce).ToList();
        JsonObject? mapFilter = null;
        try { if (map?.FilterJson is { } fj) mapFilter = JsonNode.Parse(fj) as JsonObject; } catch (System.Text.Json.JsonException) { mapFilter = null; }
        var header = columns.Select(c => c.Name).ToList();
        var isCi = e.Output == "servicenow-ci";
        string source;
        IAsyncEnumerable<JsonObject> stream;
        if (isCi) { source = "the CIs (the newest CI build)"; stream = items.CiPagesAsync(ct); }
        else
        {
            var fromRun = !await items.HasCiFindingsAsync(ct);
            source = fromRun ? RunSource : CiSource;
            stream = fromRun ? items.RunFindingItemsAsync(ct) : items.FindingItemsAsync(ct);
        }
        bool Keep(JsonObject it) => !isCi && scope is not null ? Passes(scope, resolved, mapFilter, it) : OutputMapper.Passes(it, mapFilter);
        var path = Path.Combine(Path.GetTempPath(), "si-snow-export-" + Guid.NewGuid().ToString("N") + (csv ? ".csv" : ".xlsx"));
        var fs = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 1 << 16, FileOptions.DeleteOnClose);
        long total = 0, sent = 0;
        var vmaps = OutputMapper.ShippedValueMaps;
        var now = DateTime.UtcNow;
        if (csv)
        {
            await using var w = new StreamWriter(fs, new UTF8Encoding(true), 1 << 16, leaveOpen: true) { NewLine = "\r\n" };
            await w.WriteLineAsync(string.Join(",", header.Select(SentCsv)));
            await foreach (var it in stream)
            {
                total++;
                if (!Keep(it)) continue;
                sent++;
                await w.WriteLineAsync(string.Join(",", OutputMapper.SentRow(columns, it, vmaps).Select(SentCsv)));
            }
        }
        else
        {
            using var x = new XlsxWriter(fs, "SecurityInsight " + e.Label + " -- would send", now);
            var sheetNo = 1;
            var sheet = x.AddSheet("Would send", header);
            try
            {
                await foreach (var it in stream)
                {
                    total++;
                    if (!Keep(it)) continue;
                    sent++;
                    if (sheet.RowCount >= XlsxWriter.MaxRows - 1) { sheet.Dispose(); sheet = x.AddSheet("Would send " + (++sheetNo).ToString(CultureInfo.InvariantCulture), header); }
                    sheet.WriteRow(OutputMapper.SentRow(columns, it, vmaps).Cast<object?>().ToList());
                }
            }
            finally { sheet.Dispose(); }
            x.WriteSheet("Scope", ["What", "Value"], new List<IReadOnlyList<object?>>
            {
                new object?[] { "Output", e.Label + " (" + e.Output + ")" },
                new object?[] { "Columns (Fields sent)", (map is null ? "the output map is not in the settings database yet -- the item's own fields: " : "") + string.Join(", ", header) },
                new object?[] { "Filter", scopeWords }, new object?[] { "Mode", mode }, new object?[] { "Source", source },
                new object?[] { isCi ? "CIs read" : "Findings read", total }, new object?[] { "Rows it would send", sent },
                new object?[] { "Exported (UTC)", now },
                new object?[] { "Values", "exactly as the connector sends them: true / false, a list as JSON text, dates in ISO 8601 UTC; " + OutputMapper.ComputedAtSend + " = a value the run sets when it sends" },
                new object?[] { "Note", "Every sync sends every row in scope, each with its u_action and u_row_hash (an unchanged record has the same hash); this file holds every row the filter lets through, so the ServiceNow team can test with all of them." },
            });
            x.Complete();
        }
        log.LogInformation("ServiceNow export of {Output}: {Sent} of {Total} rows ({Format}; {Source})", e.Output, sent, total, csv ? "csv" : "xlsx", source);
        fs.Position = 0;
        var name = "SecurityInsight_" + e.Output + "_would-send_" + now.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + (csv ? ".csv" : ".xlsx");
        return new ScopeExportFile(fs, csv ? "text/csv; charset=utf-8" : XlsxWriter.ContentType, name, sent);
    }

    /// A CSV field as RFC 4180 quotes it: in double quotes when it holds a comma, a quote, a line break or a leading /
    /// trailing space (a quote doubled), else as is -- the value exactly as sent. Only a text a spreadsheet would RUN
    /// (starting with =, +, @, a tab, or a - that does not start a number) gets a leading apostrophe; the Excel file carries
    /// every value as is.
    public static string SentCsv(string? v)
    {
        var s = v ?? "";
        if (s.Length > 0 && (s[0] is '=' or '+' or '@' or '\t' or '\r' || (s[0] == '-' && !double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out _)))) s = "'" + s;
        return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 || (s.Length > 0 && (s[0] == ' ' || s[^1] == ' ')) ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    private static string AssetOf(JsonObject it) =>
        OutputMapper.Text(OutputMapper.Get(it, "si_ci_id")) is { Length: > 0 } ci ? ci : "asset:" + OutputMapper.Text(OutputMapper.Get(it, "si_asset_id"));

    /// A CSV cell: quoted when it holds a comma, a quote or a line break; a formula-looking text gets a quote prefix.
    public static string Csv(string? v)
    {
        var s = v ?? "";
        if (s.Length > 0 && "=+-@".Contains(s[0])) s = "'" + s;
        return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }
}
