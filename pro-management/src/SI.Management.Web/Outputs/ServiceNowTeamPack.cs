using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using SI.Management.Core.ProData;
using SI.Management.Web.Export;

namespace SI.Management.Web.Outputs;

/// <summary>
/// THE SERVICENOW TEAM PACK (owner 2026-10-20: "rgr vulnerability to servicenow i must be able to extract the columns with
/// real data so i can send to servicenow team"): one Excel file per ServiceNow output -- the vulnerable items, the CI
/// hand-off -- that the ServiceNow team can build its Import Set table and transform map from:
///   Target       the Import Set table (its setting's value, or "not set yet"), the intended target table, the coalesce
///                key(s), how SecurityInsight sends;
///   Schema       every column sent, the SI field it reads, its type, the longest value in the sample, whether it is a key,
///                its meaning in plain words and an example value;
///   Sample rows  up to <see cref="SampleRows"/> REAL rows with the columns as sent -- the vulnerable items scoped by the
///                ServiceNow vulnerability connector's scope, read as the test mode export reads them (the findings per CI,
///                else the published run's findings).
/// No secret is ever in it: no instance, user, password or secret name -- only the table's name and the data.
/// </summary>
public sealed class ServiceNowTeamPack(OutputRowPreview items, OutputMapStore maps, ILogger<ServiceNowTeamPack> log)
{
    public const int SampleRows = 200;

    /// What the product documents for each ServiceNow output (docs/SERVICENOW-CMDB-SCHEMA.md, SERVICENOW-TEST-PACK.md).
    public sealed record Target(string Output, string Intended, IReadOnlyList<string> Keys, string KeyWords, string Sends);

    public static readonly IReadOnlyList<Target> Targets =
    [
        new("servicenow-vulnerable-item", "sn_vul_vulnerable_item (Vulnerability Response)", ["u_si_correlation_id", "u_vulnerability"],
            "coalesce on u_si_correlation_id + u_vulnerability (the CI key and the finding: one record per finding on a CI; u_source_record_id carries the same two joined by |, stable too)",
            "Every sync sends every vulnerable item in scope, one row each, CIs first: u_action says new, update, close, reopen, held (change nothing) or out_of_scope (close as Out of scope, never as fixed). A finding closes only after it is absent from the configured number of complete runs (default 2); while that is counted its row says held."),
        new("servicenow-ci", "cmdb_ci (and its classes, through the CMDB Identification and Reconciliation engine)", ["u_si_correlation_id"],
            "coalesce on u_si_correlation_id (the CI's key in SecurityInsight; it never changes for one CI)",
            "Every sync sends every CI in scope (devices, Azure resources and Entra identities), one row each: u_action says new, update, close (retired), reopen, held or out_of_scope; a CI is never deleted."),
    ];

    public static Target? TargetOf(string output) => Targets.FirstOrDefault(t => t.Output == output);

    public const string NotSet = "not set yet -- agree the name with the ServiceNow team, then set it on Connectors > Setup";
    public const string HowSent = "the ServiceNow Import Set REST API (POST /api/now/import/<table>), in batches; a transform map on the ServiceNow side moves the rows into the target table. SecurityInsight never writes the target table itself.";

    private static readonly Lazy<IReadOnlyDictionary<string, (string Type, string Meaning)>> Fields = new(() =>
    {
        var d = new Dictionary<string, (string, string)>(StringComparer.Ordinal);
        using var s = typeof(CiColumns).Assembly.GetManifestResourceStream("DataModel/field-catalog.locked.json");
        if (s is null) return d;
        using var doc = JsonDocument.Parse(s);
        if (doc.RootElement.TryGetProperty("fields", out var fields) && fields.ValueKind == JsonValueKind.Array)
            foreach (var e in fields.EnumerateArray())
            {
                if (!e.TryGetProperty("name", out var n) || n.GetString() is not { Length: > 0 } name) continue;
                var type = e.TryGetProperty("type", out var t) && t.ValueKind == JsonValueKind.String ? t.GetString() ?? "" : "";
                var meaning = e.TryGetProperty("description", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() ?? "" : "";
                d[name] = (type, meaning);
            }
        return d;
    });

    /// The SI field's type and meaning (the field catalog); a value computed when the row is sent says so.
    public static (string Type, string Meaning) FieldInfo(string from)
    {
        if (Fields.Value.TryGetValue(from, out var f)) return (f.Type.Length > 0 ? f.Type : "string", f.Meaning);
        if (from.StartsWith('$')) return ("string", "set when the row is sent (" + from + ")");
        return ("string", "");
    }

    /// The columns in force and up to <see cref="SampleRows"/> real rows of them -- what the pack and the schema are made from.
    public sealed record Sample(Target Target, IReadOnlyList<OutputColumn> Columns, IReadOnlyList<IReadOnlyList<string>> Rows, string Source);

    /// The ServiceNow schema (JSON) of an output: built on every call from the columns in force (REQUIREMENTS #840).
    public async Task<JsonObject> SchemaAsync(DataOutEntry e, string? table, OutputScope? scope, IReadOnlySet<string>? resolved, string version, CancellationToken ct)
    {
        var s = await SampleAsync(e, scope, resolved, ct);
        var json = ServiceNowSchema.Build(e, s.Target, table, s.Columns, s.Rows, s.Source + (scope is null ? "" : "; the scope of the ServiceNow vulnerability connector: " + scope.Describe()),
            version, DateTime.UtcNow, OutputMapper.ShippedValueMaps);
        log.LogInformation("ServiceNow schema of {Output}: {Columns} columns, lengths from {Rows} sample rows ({Source})", e.Output, s.Columns.Count, s.Rows.Count, s.Source);
        return json;
    }

    /// The pack. <paramref name="table"/> = the Import Set table's setting value (null = not set); <paramref name="scope"/> +
    /// <paramref name="resolved"/> = the vulnerability connector's scope (null for the CI hand-off).
    public async Task<ScopeExportFile> WriteAsync(DataOutEntry e, string? table, OutputScope? scope, IReadOnlySet<string>? resolved, CancellationToken ct)
    {
        var (target, columns, rows, source) = await SampleAsync(e, scope, resolved, ct);
        var header = columns.Select(c => c.Name).ToList();
        var now = DateTime.UtcNow;
        var path = Path.Combine(Path.GetTempPath(), "si-snow-pack-" + Guid.NewGuid().ToString("N") + ".xlsx");
        var fs = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 1 << 16, FileOptions.DeleteOnClose);
        using (var x = new XlsxWriter(fs, "SecurityInsight " + e.Label + " -- for the ServiceNow team", now))
        {
            x.WriteSheet("Target", ["What", "Value"], new List<IReadOnlyList<object?>>
            {
                new object?[] { "Output", e.Label + " (" + e.Output + ")" },
                new object?[] { "Import Set table (staging)", string.IsNullOrWhiteSpace(table) ? NotSet : table.Trim() },
                new object?[] { "Its setting", e.TableSetting },
                new object?[] { "Intended target table", target.Intended },
                new object?[] { "Coalesce / correlation key", target.KeyWords },
                new object?[] { "What one row is", target.Sends },
                new object?[] { "How SecurityInsight sends", HowSent },
                new object?[] { "Columns sent", (long)header.Count },
                new object?[] { "Sample rows (sheet 'Sample rows')", (long)rows.Count },
                new object?[] { "Sample from", source + (scope is null ? "" : "; the scope of the ServiceNow vulnerability connector: " + scope.Describe()) },
                new object?[] { "Made (UTC)", now },
                new object?[] { "Secrets", "none -- this file holds no instance, user, password or secret name" },
            });
            var schema = columns.Select((c, i) =>
            {
                var (_, meaning) = FieldInfo(c.From);
                var type = ServiceNowSchema.TypeOf(c);
                var longest = ServiceNowSchema.Longest(rows, i);
                var example = rows.Select(r => i < r.Count ? r[i] : "").FirstOrDefault(v => !string.IsNullOrWhiteSpace(v) && v != OutputMapper.ComputedAtSend) ?? "";
                var key = target.Keys.Contains(c.Name, StringComparer.OrdinalIgnoreCase);
                return (IReadOnlyList<object?>)new object?[]
                {
                    c.Name, c.From, string.IsNullOrWhiteSpace(c.Op) ? "" : c.Op, type.Type, type.ServiceNowType, (long)ServiceNowSchema.LengthOf(c, type, longest), (long)longest,
                    key ? "yes -- coalesce key" : "no", meaning, example.Length > 300 ? example[..300] + "..." : example,
                };
            }).ToList();
            x.WriteSheet("Schema", SchemaHeader, schema);
            using (var sheet = x.AddSheet("Sample rows", header))
                foreach (var r in rows) sheet.WriteRow(r.Cast<object?>().ToList());
            x.Complete();
        }
        log.LogInformation("ServiceNow team pack of {Output}: {Columns} columns, {Rows} sample rows ({Source})", e.Output, header.Count, rows.Count, source);
        fs.Position = 0;
        return new ScopeExportFile(fs, XlsxWriter.ContentType, "SecurityInsight_" + e.Output + "_servicenow-team-pack_" + now.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + ".xlsx", rows.Count);
    }

    /// The team pack's Schema sheet header (the type and length are the JSON schema's, <see cref="ServiceNowSchema"/>).
    public static readonly IReadOnlyList<string> SchemaHeader =
        ["Column", "SI field it reads", "Operation", "Type", "ServiceNow field type", "Length to create", "Longest value in the sample", "Key", "Meaning", "Example"];

    /// The columns in force of a ServiceNow output and real rows of them (the scope applied for the vulnerable items).
    public async Task<Sample> SampleAsync(DataOutEntry e, OutputScope? scope, IReadOnlySet<string>? resolved, CancellationToken ct)
    {
        var target = TargetOf(e.Output) ?? throw new ArgumentException($"'{e.Output}' is not a ServiceNow output");
        OutputMapView? map = null;
        try { map = await maps.LoadAsync(e.Output, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the output map {Output} could not be read", e.Output); }
        var columns = map is null ? ScopeExport.Fallback : map.Columns.Where(c => !c.Removed).Select(c => c.InForce).ToList();
        JsonObject? mapFilter = null;
        try { if (map?.FilterJson is { } fj) mapFilter = JsonNode.Parse(fj) as JsonObject; } catch (JsonException) { mapFilter = null; }

        // the sample rows: real data, the scope applied for the vulnerable items
        var rows = new List<IReadOnlyList<string>>();
        var source = "";
        if (e.Output == "servicenow-ci")
        {
            source = "the CIs (the newest CI build)";
            await foreach (var it in items.CiItemsAsync(SampleRows * 5, ct))
            {
                if (!OutputMapper.Passes(it, mapFilter)) continue;
                rows.Add(OutputMapper.SentRow(columns, it, OutputMapper.ShippedValueMaps));
                if (rows.Count >= SampleRows) break;
            }
        }
        else
        {
            var fromRun = !await items.HasCiFindingsAsync(ct);
            source = fromRun ? ScopeExport.RunSource : ScopeExport.CiSource;
            var stream = fromRun ? items.RunFindingItemsAsync(ct, 1000) : items.FindingItemsAsync(ct, 1000);
            await foreach (var it in stream)
            {
                if (scope is not null ? !ScopeExport.Passes(scope, resolved, mapFilter, it) : !OutputMapper.Passes(it, mapFilter)) continue;
                rows.Add(OutputMapper.SentRow(columns, it, OutputMapper.ShippedValueMaps));
                if (rows.Count >= SampleRows) break;
            }
        }
        return new Sample(target, columns, rows, source);
    }
}
