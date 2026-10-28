using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.SchemaOverlay;

/// One profile column of the overlay. Raw = the column's JSON as it was (every key the form does not show is kept).
public sealed class OverlayField
{
    public string Name { get; set; } = "";
    public string Type { get; set; } = "string";
    public string? Purpose { get; set; }
    public string? WrittenBy { get; set; }
    /// The default value as text ("" = none); written as the column's type (true / false, a number, or text).
    public string? Default { get; set; }
    public string? Description { get; set; }
    public string? Raw { get; set; }
}

/// One aggregator contributor: its id and its settings (name = JSON value, so a number, a list or an object stays one).
public sealed class OverlayContributor
{
    public string Id { get; set; } = "";
    public List<OverlaySetting> Settings { get; set; } = new();
}

public sealed class OverlaySetting { public string Name { get; set; } = ""; public string Value { get; set; } = ""; }

/// One raw-payload source bucket and the include paths it adds (one per line). Raw = its JSON as it was.
public sealed class OverlaySource
{
    public string Name { get; set; } = "";
    public string IncludePaths { get; set; } = "";
    public string? Raw { get; set; }
}

/// <summary>
/// A schema overlay as a form, by the merge rules of Get-SISchemaWithCustomMerge: COLUMNS (a column with the name of a
/// shipped one replaces it; a new name adds a column), aggregator CONTRIBUTORS (same id replaces, new id adds) and
/// RAW-PAYLOAD include paths (added to the shipped ones; a new source name adds a bucket). Every key the form does not
/// show -- notes, a column's usedBy / derivation, the overlay's own extras -- is kept as it was.
/// </summary>
public sealed partial class OverlayFormModel
{
    public List<OverlayField> Fields { get; set; } = new();
    public List<OverlayContributor> Contributors { get; set; } = new();
    public List<OverlaySource> Sources { get; set; } = new();
    public string? Original { get; set; }

    public static readonly string[] Types = ["string", "bool", "int", "real", "datetime", "dynamic"];
    public static readonly string[] Purposes = ["risk", "context", "metadata", "attribution", "audit", "compliance", "correlation", "enrichment", "forensic", "freshness", "identifier", "identity", "kpi", "lifecycle", "pivot", "policy", "posture", "provenance"];
    public static readonly string[] Stages = ["collect", "enrich", "classify", "profile", "reconcile", "posture_analyze", "bootstrap"];

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_]{0,99}$")] private static partial Regex ColumnName();
    private static readonly HashSet<string> FieldKeys = new(StringComparer.Ordinal) { "name", "type", "purpose", "stage", "default", "description" };

    public static OverlayFormModel From(string? body)
    {
        var o = TaggingStore.Parse(body) ?? new JsonObject();
        var f = new OverlayFormModel { Original = body };
        if (o["fields"] is JsonArray fa)
            foreach (var x in fa.OfType<JsonObject>())
                f.Fields.Add(new OverlayField
                {
                    Name = Str(x["name"]) ?? "", Type = Str(x["type"]) ?? "string", Purpose = Str(x["purpose"]), WrittenBy = Str((x["stage"] as JsonObject)?["writtenBy"]),
                    Default = x.ContainsKey("default") ? (x["default"] is JsonValue dv && dv.TryGetValue<string>(out var ds) ? ds : x["default"]?.ToJsonString() ?? "null") : null,
                    Description = Str(x["description"]), Raw = x.ToJsonString(),
                });
        if ((o["aggregator"] as JsonObject)?["contributors"] is JsonArray ca)
            foreach (var x in ca.OfType<JsonObject>())
                f.Contributors.Add(new OverlayContributor
                {
                    Id = Str(x["id"]) ?? "",
                    Settings = x.Where(kv => kv.Key != "id").Select(kv => new OverlaySetting { Name = kv.Key, Value = kv.Value?.ToJsonString(TaggingStore.Write).Replace("\r\n", "\n") ?? "null" }).ToList(),
                });
        if ((o["rawPayload"] as JsonObject)?["sources"] is JsonObject so)
            foreach (var (k, v) in so)
                if (v is JsonObject sv)
                    f.Sources.Add(new OverlaySource
                    {
                        Name = k, Raw = sv.ToJsonString(),
                        IncludePaths = sv["includePaths"] is JsonArray ip ? string.Join("\n", ip.Select(Str)) : "",
                    });
        return f;
    }

    private static string? Str(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : n?.ToJsonString();

    /// True when the body holds what the form cannot show without losing it (e.g. a raw-payload source that is not an
    /// object, or a column without a name) -- then the overlay is shown as text only.
    public static string? CannotShow(string? body)
    {
        var o = TaggingStore.Parse(body);
        if (body is not null && o is null) return "the overlay is not a JSON object";
        if (o?["fields"] is JsonNode fn && (fn is not JsonArray fa || fa.Any(x => x is not JsonObject xo || Str(xo["name"]) is null || (xo["stage"] is JsonNode st && st is not JsonObject))))
            return "a column is not an object with a name";
        if (o?["aggregator"] is JsonNode an && (an is not JsonObject ao || (ao["contributors"] is JsonNode cn && (cn is not JsonArray ca || ca.Any(x => x is not JsonObject)))))
            return "the aggregator holds something other than a list of contributors";
        if (o?["rawPayload"] is JsonNode rn && (rn is not JsonObject ro || (ro["sources"] is JsonNode sn && sn is not JsonObject)))
            return "the raw payload holds something other than sources";
        return null;
    }

    public IReadOnlyList<string> Problems()
    {
        var why = new List<string>();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in Fields)
        {
            if (!ColumnName().IsMatch(f.Name ?? "")) { why.Add($"'{f.Name}' is not a column name (letters, digits and _, starting with a letter or _)"); continue; }
            if (!names.Add(f.Name!)) why.Add($"the column {f.Name} is there twice");
            if (!Types.Contains(f.Type)) why.Add($"{f.Name}: '{f.Type}' is not a column type ({string.Join(", ", Types)})");
            if (!string.IsNullOrEmpty(f.Default) && DefaultNode(f) is null) why.Add($"{f.Name}: the default '{f.Default}' is not a {f.Type}");
        }
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var c in Contributors)
        {
            if (string.IsNullOrWhiteSpace(c.Id)) { why.Add("a contributor needs an id"); continue; }
            if (!ids.Add(c.Id.Trim())) why.Add($"the contributor {c.Id} is there twice");
            foreach (var s in c.Settings)
            {
                if (string.IsNullOrWhiteSpace(s.Name) || s.Name == "id") why.Add($"contributor {c.Id}: a setting needs a name (other than id)");
                else if (Value(s.Value) is null && s.Value.Trim() != "null") why.Add($"contributor {c.Id}: {s.Name} is not a value (text in quotes, a number, true / false, a list [ ] or an object {{ }})");
            }
        }
        var srcs = new HashSet<string>(StringComparer.Ordinal);
        foreach (var s in Sources)
        {
            if (string.IsNullOrWhiteSpace(s.Name) || s.Name.StartsWith('_')) why.Add("a raw-payload source needs a name");
            else if (!srcs.Add(s.Name.Trim())) why.Add($"the source {s.Name} is there twice");
        }
        return why;
    }

    private static JsonNode? Value(string text)
    {
        try { return JsonNode.Parse(text); } catch (JsonException) { return null; }
    }

    /// The default as the column's type: bool -> true / false, int / real -> a number, the rest -> text.
    private static JsonNode? DefaultNode(OverlayField f)
    {
        var d = (f.Default ?? "").Trim();
        return f.Type switch
        {
            "bool" => bool.TryParse(d, out var b) ? JsonValue.Create(b) : null,
            "int" => long.TryParse(d, NumberStyles.Integer, CultureInfo.InvariantCulture, out var l) ? JsonValue.Create(l) : null,
            "real" => double.TryParse(d, NumberStyles.Float, CultureInfo.InvariantCulture, out var r) ? JsonValue.Create(r) : null,
            "dynamic" => Value(d),
            _ => JsonValue.Create(f.Default ?? ""),
        };
    }

    public string ToJson()
    {
        var o = TaggingStore.Parse(Original) ?? new JsonObject();
        if (Fields.Count > 0 || o.ContainsKey("fields"))
        {
            var arr = new JsonArray();
            foreach (var f in Fields)
            {
                var x = TaggingStore.Parse(f.Raw) ?? new JsonObject();
                x["name"] = f.Name.Trim();
                x["type"] = f.Type;
                if (string.IsNullOrWhiteSpace(f.Purpose)) x.Remove("purpose"); else x["purpose"] = f.Purpose.Trim();
                if (string.IsNullOrWhiteSpace(f.WrittenBy)) { if (x["stage"] is JsonObject st) st.Remove("writtenBy"); }
                else { if (x["stage"] is not JsonObject st) { st = new JsonObject(); x["stage"] = st; } st["writtenBy"] = f.WrittenBy.Trim(); }
                if (f.Default is null || (f.Default.Length == 0 && f.Type != "string")) x.Remove("default"); else x["default"] = DefaultNode(f);
                if (string.IsNullOrWhiteSpace(f.Description)) x.Remove("description"); else x["description"] = f.Description.Trim();
                arr.Add(x);
            }
            o["fields"] = arr;
        }
        if (Contributors.Count > 0 || (o["aggregator"] as JsonObject)?.ContainsKey("contributors") == true)
        {
            if (o["aggregator"] is not JsonObject ag) { ag = new JsonObject(); o["aggregator"] = ag; }
            ag["contributors"] = new JsonArray(Contributors.Select(c =>
            {
                var x = new JsonObject { ["id"] = c.Id.Trim() };
                foreach (var s in c.Settings.Where(s => !string.IsNullOrWhiteSpace(s.Name))) x[s.Name.Trim()] = Value(s.Value);
                return (JsonNode?)x;
            }).ToArray());
        }
        if (Sources.Count > 0 || (o["rawPayload"] as JsonObject)?.ContainsKey("sources") == true)
        {
            if (o["rawPayload"] is not JsonObject rp) { rp = new JsonObject(); o["rawPayload"] = rp; }
            var old = rp["sources"] as JsonObject;
            var so = new JsonObject();
            // notes among the sources (a '_comment' string) stay where they were
            if (old is not null) foreach (var (k, v) in old) if (v is not JsonObject) so[k] = v?.DeepClone();
            foreach (var s in Sources)
            {
                var x = TaggingStore.Parse(s.Raw) ?? new JsonObject();
                x["includePaths"] = new JsonArray((s.IncludePaths ?? "").Replace("\r\n", "\n").Split('\n').Select(p => p.Trim()).Where(p => p.Length > 0).Select(p => (JsonNode?)JsonValue.Create(p)).ToArray());
                so[s.Name.Trim()] = x;
            }
            rp["sources"] = so;
        }
        return TaggingStore.Json(o);
    }
}
