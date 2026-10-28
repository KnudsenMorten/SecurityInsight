using System.Globalization;
using System.Text.Json.Nodes;
using SI.Management.Core.ProData;

namespace SI.Management.Web.Outputs;

/// <summary>
/// THE SERVICENOW SCHEMA (owner 2026-10-20: "servicenow team has requested a schema definition in json format, with each
/// field to create, their format (string, datetime, number etc) so they can create the table. both for cmdb + vulnerability
/// ... it must be dynamic so if the fields below are changed then it must update or build when i click ... limits also in
/// the schema"; REQUIREMENTS #840). PURE: from the columns IN FORCE of a ServiceNow output (the customer's renames, removals
/// and own columns) and the cells of real sample rows -- per column the name to create, its type, the ServiceNow field type,
/// the length to create and the allowed values of a value translation; plus the table, the target and how rows arrive.
/// The type follows what the engine sends (engine\data-model\SI-OutputMapper.ps1 Get-SIOutputValue, the field catalog's
/// type, then the column's operation). The JSON holds no sample value and no secret. The team pack's Schema sheet uses the
/// same <see cref="TypeOf"/> and <see cref="LengthOf"/>, so the two never disagree.
/// </summary>
public static class ServiceNowSchema
{
    public const string Kind = "securityinsight-servicenow-importset-schema";
    public const int SchemaVersion = 1;

    /// One column's type: the type SecurityInsight sends (string, integer, decimal, boolean, datetime), the ServiceNow field
    /// type for the target field, and how the value is written when that is not plain.
    public sealed record ColumnType(string Type, string ServiceNowType, string? Format);

    /// How a datetime arrives (ConvertTo-Json of a UTC time in the engine; a value read from a CI document is already that text).
    public const string DateTimeFormat = "ISO 8601 in UTC, e.g. 2026-10-20T19:05:00Z (the seconds may carry a fraction)";

    /// ServiceNow's default length of a new string field -- a column is never created shorter.
    public const int ServiceNowDefaultLength = 40;

    /// The lengths a string field is created with: the first at least twice the longest value seen (room for the rows the
    /// sample did not read). Above 4,000 ServiceNow stores a large string.
    public static readonly int[] LengthSteps = [40, 100, 255, 1000, 4000, 65000];

    /// The documented minimum lengths by what a column reads (SERVICENOW-CMDB-SCHEMA.md, the test pack's HOW-TO): real CI
    /// keys are longer than 150 characters, a finding key holds a CVE or a configuration id, a row hash is a SHA-256 in hex.
    public static readonly IReadOnlyDictionary<string, int> MinimumLength = new Dictionary<string, int>(StringComparer.Ordinal)
    {
        ["si_ci_id"] = 400, ["si_asset_id"] = 400, ["si_finding_key"] = 100, ["$row_hash"] = 64, ["$run_id"] = 100,
        // #914 the contract envelope: the action, the batch id (<run id>:<output>), the clear marker (column names), the reason, the replaced key
        ["finding.item_key"] = 400, ["$action"] = 40, ["$batch_id"] = 100, ["$cleared"] = 1000, ["$reason"] = 1000, ["$replaces"] = 400,
    };

    /// The type of a property the item carries outside the field catalog (finding.x / summary.x / record.x), by its name.
    public static readonly IReadOnlyDictionary<string, string> PathTypes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["closed_at"] = "datetime", ["absent_runs"] = "integer", ["record_id"] = "string", ["item_key"] = "string",
    };

    private static ColumnType Of(string type, string? format = null) => new(type, type switch
    {
        "integer" => "integer",
        "decimal" => "decimal",
        "boolean" => "boolean",
        "datetime" => "glide_date_time",
        _ => "string",
    }, format ?? (type == "datetime" ? DateTimeFormat : type == "boolean" ? "true or false" : type is "integer" or "decimal" ? "digits, '.' as the decimal separator, no thousands separator" : null));

    /// The type the field catalog gives a field, in the schema's words (dynamic: a list or an object, sent as text).
    private static string CatalogType(string catalogType) => catalogType switch
    {
        "int" or "long" => "integer",
        "real" or "decimal" or "double" => "decimal",
        "bool" => "boolean",
        "datetime" => "datetime",
        "dynamic" => "list",
        _ => "string",
    };

    /// The type of the value a column reads, before its operation.
    private static string ReadType(string from)
    {
        if (from is "$run_time" or "$changed_at") return "datetime";
        if (from.StartsWith('$')) return "string";
        foreach (var prefix in new[] { "finding.", "summary.", "record." })
            if (from.StartsWith(prefix, StringComparison.Ordinal))
                return PathTypes.TryGetValue(from[prefix.Length..], out var t) ? t : "string";
        return CatalogType(ServiceNowTeamPack.FieldInfo(from).Type);
    }

    /// PURE. The type of a column as it is sent: what it reads, then its operation (the closed set of OutputMapRules.Ops).
    public static ColumnType TypeOf(OutputColumn c)
    {
        var read = ReadType(c.From.Trim());
        var op = (c.Op ?? "").Trim();
        var name = op.Split(':')[0];
        var arg = op.Length > name.Length ? op[(name.Length + 1)..] : "";
        var type = name switch
        {
            "" or "if_class" => read,
            "first" => read == "list" ? "string" : read,
            "format_date" => "datetime",
            "round" => int.TryParse(arg, NumberStyles.Integer, CultureInfo.InvariantCulture, out var d) && d > 0 ? "decimal" : "integer",
            _ => "string",   // enum, join, join_ids, render, mask, domain_part, lower, upper: text
        };
        if (name == "format_date") return Of("datetime", "yyyy-MM-dd HH:mm in UTC");
        if (type == "list") return Of("string", "a list, sent as JSON text");
        return Of(type);
    }

    /// PURE. The length to create a column with: at least ServiceNow's 40 and the documented minimum of what it reads; for a
    /// string the first step at least twice the longest value seen.
    public static int LengthOf(OutputColumn c, ColumnType t, int longest)
    {
        var min = Math.Max(ServiceNowDefaultLength, MinimumLength.TryGetValue(c.From.Trim(), out var m) ? m : 0);
        if (t.Type != "string") return Math.Max(min, longest);
        var want = Math.Max(min, longest * 2);
        foreach (var step in LengthSteps) if (step >= want) return step;
        return want;
    }

    /// PURE. The values a value translation (enum:&lt;map&gt;) can send, from the shipped value maps; null for other columns.
    public static IReadOnlyList<string>? AllowedValues(OutputColumn c, JsonObject? valueMaps)
    {
        var op = (c.Op ?? "").Trim();
        if (!op.StartsWith("enum:", StringComparison.Ordinal) || valueMaps?[op[5..]] is not JsonObject map) return null;
        return map.Select(kv => kv.Value is JsonValue v && v.TryGetValue<string>(out var s) ? s : null)
            .Where(s => !string.IsNullOrEmpty(s)).Select(s => s!).Distinct(StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToList();
    }

    /// PURE. The longest value of each column in the sample rows (a value the run sets itself is not counted).
    public static int Longest(IReadOnlyList<IReadOnlyList<string>> rows, int index) =>
        rows.Count == 0 ? 0 : rows.Max(r => index < r.Count && r[index] is { } v && v != OutputMapper.ComputedAtSend ? v.Length : 0);

    /// PURE. The schema of one ServiceNow output. <paramref name="table"/>: the Import Set table's setting value (null = not
    /// set yet); <paramref name="rows"/>: the sample rows' cells, in <paramref name="columns"/>' order.
    public static JsonObject Build(DataOutEntry e, ServiceNowTeamPack.Target target, string? table, IReadOnlyList<OutputColumn> columns,
        IReadOnlyList<IReadOnlyList<string>> rows, string sampleFrom, string version, DateTime nowUtc, JsonObject? valueMaps)
    {
        var fields = new JsonArray();
        for (var i = 0; i < columns.Count; i++)
        {
            var c = columns[i];
            var t = TypeOf(c);
            var longest = Longest(rows, i);
            var (_, meaning) = ServiceNowTeamPack.FieldInfo(c.From);
            var f = new JsonObject
            {
                ["name"] = c.Name,
                ["label"] = c.Name,
                ["type"] = t.Type,
                ["servicenowType"] = t.ServiceNowType,
                ["maxLength"] = LengthOf(c, t, longest),
            };
            if (t.Format is { } fmt) f["format"] = fmt;
            f["key"] = target.Keys.Contains(c.Name, StringComparer.OrdinalIgnoreCase);
            if (AllowedValues(c, valueMaps) is { Count: > 0 } allowed) f["allowedValues"] = new JsonArray(allowed.Select(a => (JsonNode)JsonValue.Create(a)!).ToArray());
            f["reads"] = c.From;
            if (!string.IsNullOrWhiteSpace(c.Op)) f["operation"] = c.Op.Trim();
            f["description"] = meaning;
            f["longestSeen"] = longest;
            fields.Add(f);
        }
        // #912: every data row carries its batch (the staging status table says when the batch is complete) -- set when the row is sent
        if (!columns.Any(c => string.Equals(c.Name, ServiceNowStagingStatus.BatchIdColumn, StringComparison.OrdinalIgnoreCase)))
            fields.Add(new JsonObject
            {
                ["name"] = ServiceNowStagingStatus.BatchIdColumn, ["label"] = ServiceNowStagingStatus.BatchId.Label, ["type"] = "string", ["servicenowType"] = "string",
                ["maxLength"] = ServiceNowStagingStatus.BatchIdLength, ["key"] = false, ["reads"] = "$batch_id",
                ["description"] = ServiceNowStagingStatus.BatchId.Meaning, ["longestSeen"] = 0,
            });
        return new JsonObject
        {
            ["kind"] = Kind,
            ["schemaVersion"] = SchemaVersion,
            ["product"] = "SecurityInsight",
            ["productVersion"] = version,
            ["generatedUtc"] = nowUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
            ["output"] = e.Output,
            ["label"] = e.Label,
            ["table"] = new JsonObject
            {
                ["name"] = string.IsNullOrWhiteSpace(table) ? null : table.Trim(),
                ["nameNote"] = string.IsNullOrWhiteSpace(table) ? ServiceNowTeamPack.NotSet : null,
                ["setting"] = e.TableSetting,
                ["extends"] = "sys_import_set_row",
                ["columnNames"] = "create every field with exactly the name below (the label too): SecurityInsight addresses a column by its name",
            },
            ["target"] = new JsonObject
            {
                ["table"] = target.Intended,
                ["coalesce"] = new JsonArray(target.Keys.Select(k => (JsonNode)JsonValue.Create(k)!).ToArray()),
                ["coalesceRule"] = target.KeyWords,
                ["row"] = target.Sends,
            },
            ["transport"] = new JsonObject
            {
                ["api"] = "POST /api/now/import/<table>/insertMultiple",
                ["batchRows"] = 200,
                ["columnMappings"] = "set REST Insert Multiple (sys_rest_insert_multiple) for the table to Column mappings = Column name -- by default ServiceNow maps by label, and every column lands empty",
                ["emptyValues"] = "a column without a value is left out of the row",
                ["datetime"] = DateTimeFormat,
                ["numbers"] = "digits, '.' as the decimal separator, no thousands separator",
                ["booleans"] = "true or false",
                ["sends"] = ServiceNowTeamPack.HowSent,
            },
            ["lengths"] = new JsonObject
            {
                ["rule"] = $"maxLength is the length to create the field with: never below ServiceNow's {ServiceNowDefaultLength} or the documented minimum of what the field reads; for text the first of {string.Join(", ", LengthSteps)} that holds twice the longest value seen",
                ["sampleRows"] = rows.Count,
                ["sampleFrom"] = sampleFrom,
            },
            ["fields"] = fields,
        };
    }
}
