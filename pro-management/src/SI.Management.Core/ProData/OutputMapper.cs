using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SI.Management.Core.ProData;

/// <summary>
/// THE PREVIEW of an output (owner 2026-10-19: "Fields sent: the column builder ... and the 10-row preview"): the C# twin
/// of the engine's output mapper (engine\data-model\SI-OutputMapper.ps1, Invoke-SIOutputMap) over items the web app reads
/// the way the data sync does -- so the preview shows, column by column, what the next run sends for the first rows. The
/// same reads (<see cref="Value"/>), the same closed operations (<see cref="Op"/>), the same filter, the same order
/// (<see cref="OutputMapRules.Arrange{T}"/>). The run's own values ($run_id, $run_time, $changed_at, $row_hash) are named,
/// not invented. A value translation (enum:) uses the SHIPPED value maps (an embedded copy of
/// data-model/value-maps.locked.json, held to the original by a test).
/// </summary>
public static class OutputMapper
{
    /// What a preview cell of a value the run computes when it sends says.
    public const string ComputedAtSend = "(set when sent)";

    private static readonly Lazy<JsonObject?> ValueMapsLazy = new(() =>
    {
        using var s = typeof(OutputMapper).Assembly.GetManifestResourceStream("DataModel/value-maps.locked.json")
            ?? throw new InvalidOperationException("the embedded data model file value-maps.locked.json is missing from the build");
        return JsonNode.Parse(s)?["maps"] as JsonObject;
    });

    /// The shipped value maps (map id -> map).
    public static JsonObject? ShippedValueMaps => ValueMapsLazy.Value;

    /// One property of an item, its name compared case-insensitively (as the engine's Get-SIItemValue).
    public static JsonNode? Get(JsonObject? item, string name)
    {
        if (item is null || string.IsNullOrEmpty(name)) return null;
        if (item.TryGetPropertyValue(name, out var v)) return v;
        foreach (var kv in item) if (string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)) return kv.Value;
        return null;
    }

    /// Whether an item passes the map's filter ({ "field": [ values ] }: the field's text is one of the values).
    public static bool Passes(JsonObject item, JsonObject? filter)
    {
        if (filter is null) return true;
        foreach (var (field, want) in filter)
        {
            var values = want is JsonArray a ? a.Select(x => Text(x)).ToList() : new List<string> { Text(want) };
            if (!values.Contains(Text(Get(item, field)), StringComparer.Ordinal)) return false;
        }
        return true;
    }

    /// One column's raw value from an item, before its operation (null = a value only the run knows).
    public static JsonNode? Value(JsonObject item, string from, out bool atSend)
    {
        atSend = false;
        if (from.StartsWith("$const:", StringComparison.Ordinal)) return JsonValue.Create(from[7..]);
        if (from is "$run_id" or "$run_time" or "$changed_at" or "$row_hash" or "$action" or "$batch_id" or "$cleared" or "$reason" or "$replaces") { atSend = true; return null; }
        foreach (var prefix in new[] { "finding.", "summary.", "record." })
            if (from.StartsWith(prefix, StringComparison.Ordinal)) return Get(item, from[prefix.Length..]);
        return Get(item, from);
    }

    /// A value as a flat list: null -> none; a list -> its items; anything else -> itself.
    private static List<JsonNode?> List(JsonNode? v) => v switch
    {
        null => new List<JsonNode?>(),
        JsonArray a => a.Where(x => x is not null).ToList(),
        _ => new List<JsonNode?> { v },
    };

    /// A value as the engine's [string] of it: a text, a number in invariant form, true / false; a list or object as JSON.
    public static string Text(JsonNode? v) => v switch
    {
        null => "",
        JsonValue jv when jv.TryGetValue<string>(out var s) => s,
        JsonValue jv when jv.TryGetValue<bool>(out var b) => b ? "True" : "False",
        JsonValue jv when jv.TryGetValue<double>(out var d) => d.ToString(CultureInfo.InvariantCulture),
        _ => v.ToJsonString(),
    };

    /// One closed output operation over a value (the engine's Invoke-SIOutputOp).
    public static JsonNode? Op(JsonNode? value, string? op, JsonObject item, JsonObject? valueMaps)
    {
        if (string.IsNullOrWhiteSpace(op)) return value;
        var i = op.IndexOf(':');
        var name = i < 0 ? op : op[..i];
        var arg = i < 0 ? "" : op[(i + 1)..];
        switch (name)
        {
            case "enum":
                if (value is null) return null;
                return Get(valueMaps, arg) is JsonObject map ? MapValue(map, Text(value)) : null;
            case "first": return List(value).FirstOrDefault()?.DeepClone();
            case "join": return JsonValue.Create(string.Join(arg.Length == 0 ? ";" : arg, List(value).Select(Text)));
            case "join_ids":
                return JsonValue.Create(string.Join(arg.Length == 0 ? ";" : arg, List(value).Select(x => x is JsonObject o && Get(o, "id") is { } id ? Text(id) : Text(x))));
            case "render":
                var parts = arg.Split(':');
                return JsonValue.Create(string.Join("; ", List(value).Select(x => string.Join(":", parts.Select(p => Text(Get(x as JsonObject, p)))))));
            case "format_date":
                var t = Text(value);
                return DateTimeOffset.TryParse(t, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dto)
                    ? JsonValue.Create(dto.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)) : null;
            case "round":
                if (!double.TryParse(Text(value), NumberStyles.Float, CultureInfo.InvariantCulture, out var n)) return null;
                return JsonValue.Create(Math.Round(n, int.TryParse(arg, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dg) ? dg : 0));
            case "mask": return value is null || Text(value).Trim().Length == 0 ? value : JsonValue.Create("***");
            case "domain_part": var s = Text(value); var j = s.IndexOf('.'); return JsonValue.Create(j < 0 ? "" : s[(j + 1)..]);
            case "if_class": return Text(Get(item, "si_class")) == arg ? value : null;
            case "lower": return value is null ? null : JsonValue.Create(Text(value).ToLowerInvariant());
            case "upper": return value is null ? null : JsonValue.Create(Text(value).ToUpperInvariant());
            default: throw new ArgumentException($"unknown output operation '{name}'");
        }
    }

    /// A value looked up in a value map (the engine's Get-SIValueMapResult): longest key first; $match exact / prefix /
    /// contains, case-insensitive; else $default ($self_lower = the value itself, lower-case); else nothing.
    public static JsonNode? MapValue(JsonObject map, string value)
    {
        var mode = Text(Get(map, "$match")) is { Length: > 0 } m ? m : "exact";
        var s = value.Trim();
        foreach (var (k, v) in map.Where(kv => !kv.Key.StartsWith('$')).OrderByDescending(kv => kv.Key.Length))
        {
            var hit = mode switch
            {
                "prefix" => s.StartsWith(k, StringComparison.OrdinalIgnoreCase),
                "contains" => s.Contains(k, StringComparison.OrdinalIgnoreCase),
                _ => string.Equals(s, k, StringComparison.OrdinalIgnoreCase),
            };
            if (hit) return v?.DeepClone();
        }
        if (map.TryGetPropertyValue("$default", out var d)) return Text(d) == "$self_lower" ? JsonValue.Create(s.ToLowerInvariant()) : d?.DeepClone();
        return null;
    }

    /// <summary>
    /// The first <paramref name="take"/> rows an output sends for <paramref name="items"/>: per row the cells in the order
    /// of <paramref name="columns"/> (already in the order sent), each as display text. A value only the run knows reads
    /// <see cref="ComputedAtSend"/>; a cell an operation could not compute says why.
    /// </summary>
    public static IReadOnlyList<IReadOnlyList<string>> Preview(IReadOnlyList<OutputColumn> columns, IEnumerable<JsonObject> items, JsonObject? filter, JsonObject? valueMaps, int take = 10)
    {
        var rows = new List<IReadOnlyList<string>>();
        foreach (var it in items)
        {
            if (rows.Count >= take) break;
            if (!Passes(it, filter)) continue;
            rows.Add(Row(columns, it, valueMaps));
        }
        return rows;
    }

    /// One item's cells, in the order of <paramref name="columns"/>.
    public static IReadOnlyList<string> Row(IReadOnlyList<OutputColumn> columns, JsonObject it, JsonObject? valueMaps)
    {
        var cells = new List<string>(columns.Count);
        foreach (var c in columns)
        {
            var raw = Value(it, c.From, out var atSend);
            if (atSend) { cells.Add(ComputedAtSend); continue; }
            try { cells.Add(Cell(Op(raw, c.Op, it, valueMaps))); }
            catch (ArgumentException ex) { cells.Add("(" + ex.Message + ")"); }
        }
        return cells;
    }

    /// One row as a ServiceNow output SENDS it (the engine's insertMultiple body, ConvertTo-Json): a boolean true / false, a
    /// list or an object as its JSON text -- what the ServiceNow team pack's sample rows show, so the formatting can be
    /// checked before the connector runs. A value the run sets itself says <see cref="ComputedAtSend"/>.
    public static IReadOnlyList<string> SentRow(IReadOnlyList<OutputColumn> columns, JsonObject it, JsonObject? valueMaps)
    {
        var cells = new List<string>(columns.Count);
        foreach (var c in columns)
        {
            var raw = Value(it, c.From, out var atSend);
            if (atSend) { cells.Add(ComputedAtSend); continue; }
            try { cells.Add(Sent(Op(raw, c.Op, it, valueMaps))); }
            catch (ArgumentException ex) { cells.Add("(" + ex.Message + ")"); }
        }
        return cells;
    }

    /// A value as the ServiceNow body carries it (see <see cref="SentRow"/>).
    public static string Sent(JsonNode? v) => v switch
    {
        null => "",
        JsonValue jv when jv.TryGetValue<bool>(out var b) => b ? "true" : "false",
        JsonArray or JsonObject => v.ToJsonString(),
        _ => Text(v),
    };

    /// A cell as the preview shows it: a list or an object flattened like the workbook does ("a; b").
    public static string Cell(JsonNode? v) => v switch
    {
        null => "",
        JsonArray a => string.Join("; ", a.Select(x => x is JsonValue ? Text(x) : x?.ToJsonString() ?? "")),
        JsonObject o => o.ToJsonString(),
        _ => Text(v),
    };
}
