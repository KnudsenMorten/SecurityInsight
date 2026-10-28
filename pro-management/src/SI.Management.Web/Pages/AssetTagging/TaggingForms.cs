using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.AssetTagging;

/// <summary>
/// One asset tag rule as a form: the tag name ('&lt;stem&gt;--tier&lt;N&gt;--SI' or '&lt;stem&gt;--excluded--SI'), mode, query
/// engine, the gate that switches it on, whether it is scoped by the device-name patterns, the description and its
/// queries. Every other key of the rule is kept as it was (the body is edited in place, never rebuilt), so nothing the
/// form does not show is lost.
/// </summary>
public sealed partial class TagFormModel
{
    public string Stem { get; set; } = "";
    /// tier0 .. tier3 | excluded
    public string Marker { get; set; } = "tier2";
    public string Mode { get; set; } = "Prod";
    public string QueryEngine { get; set; } = "DefenderGraph";
    public string? Gate { get; set; }
    public bool NamePatterns { get; set; }
    public string? Description { get; set; }
    public List<string> Queries { get; set; } = new();
    /// The body the form edits (hidden in the page): its other keys are kept.
    public string? Original { get; set; }

    public static readonly string[] Engines = ["DefenderGraph", "AzureResourceGraph", "KustoCL"];
    public static readonly string[] Modes = ["Prod", "Test"];

    [GeneratedRegex(@"^(?<stem>.+?)--(?<m>tier[0-3]|excluded)--SI$", RegexOptions.IgnoreCase)] private static partial Regex NameRx();
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9 _\.\-]{0,99}$")] private static partial Regex StemRx();

    public string Name => $"{Stem.Trim()}--{(Marker == "excluded" ? "Excluded" : Marker)}--SI";
    public string Key => "tag/" + (ItemValidator.StemKey(Name) ?? "");

    public static TagFormModel From(string? body)
    {
        var o = TaggingStore.Parse(body) ?? new JsonObject();
        var f = new TagFormModel { Original = body };
        var name = TaggingStore.Str(o, "AssetTagName") ?? "";
        var m = NameRx().Match(name.Trim());
        if (m.Success) { f.Stem = m.Groups["stem"].Value; f.Marker = m.Groups["m"].Value.ToLowerInvariant(); }
        else f.Stem = name;
        f.Mode = TaggingStore.Str(o, "Mode") ?? "Prod";
        f.QueryEngine = TaggingStore.Str(o, "QueryEngine") ?? "DefenderGraph";
        f.Gate = TaggingStore.Str(o, "EnabledByConfigFlag");
        f.NamePatterns = Get(o, "ApplyDeviceNamePatterns") is JsonValue v && v.TryGetValue<bool>(out var b) && b;
        f.Description = TaggingStore.Str(o, "Description");
        f.Queries = Get(o, "Query") switch
        {
            JsonArray a => a.Select(x => x is JsonValue jv && jv.TryGetValue<string>(out var s) ? s : x?.ToJsonString() ?? "").ToList(),
            JsonValue jv when jv.TryGetValue<string>(out var s) => new List<string> { s },
            _ => new List<string>(),
        };
        return f;
    }

    private static JsonNode? Get(JsonObject o, string name) => o.FirstOrDefault(kv => string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)).Value;

    private static void Set(JsonObject o, string name, JsonNode? value)
    {
        var existing = o.FirstOrDefault(kv => string.Equals(kv.Key, name, StringComparison.OrdinalIgnoreCase)).Key;
        if (value is null) { if (existing is not null) o.Remove(existing); return; }
        o[existing ?? name] = value;
    }

    public IReadOnlyList<string> Problems()
    {
        var why = new List<string>();
        if (!StemRx().IsMatch(Stem.Trim())) why.Add("the tag's name must be letters, digits, spaces, _ . and - (the part before --tier<N>--SI)");
        if (Marker is not ("tier0" or "tier1" or "tier2" or "tier3" or "excluded")) why.Add("choose Tier 0 to 3, or excluded");
        if (Queries.All(string.IsNullOrWhiteSpace)) why.Add("a tag needs a query");
        if (!string.IsNullOrWhiteSpace(Gate) && !Regex.IsMatch(Gate.Trim(), @"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")) why.Add("the gate is a dotted path in the gates, e.g. AutoExcludeRules.ExcludeCanBeOnboarded");
        return why;
    }

    /// The body to store: the original object with the form's keys set (order kept, new keys appended).
    public string ToJson()
    {
        var o = TaggingStore.Parse(Original) ?? new JsonObject();
        var wasText = Get(o, "Query") is JsonValue;
        Set(o, "AssetTagName", Name);
        Set(o, "Mode", Mode.Trim());
        Set(o, "QueryEngine", QueryEngine.Trim());
        Set(o, "EnabledByConfigFlag", string.IsNullOrWhiteSpace(Gate) ? null : JsonValue.Create(Gate.Trim()));
        Set(o, "ApplyDeviceNamePatterns", NamePatterns ? JsonValue.Create(true) : (Get(o, "ApplyDeviceNamePatterns") is null ? null : JsonValue.Create(false)));
        Set(o, "Description", string.IsNullOrEmpty(Description) ? null : JsonValue.Create(Description.Replace("\r\n", "\n")));
        var qs = Queries.Where(q => !string.IsNullOrWhiteSpace(q)).Select(q => q.Replace("\r\n", "\n")).ToList();
        Set(o, "Query", wasText && qs.Count == 1 ? JsonValue.Create(qs[0]) : new JsonArray(qs.Select(q => (JsonNode?)JsonValue.Create(q)).ToArray()));
        return TaggingStore.Json(o);
    }
}

/// <summary>
/// The gates (v2.2's config\asset-tagging.config.json): the AutoExclude switches each gated tag names, and the device-name
/// patterns the name-pattern tag uses. Every other key -- notes, switches of your own -- is kept.
/// </summary>
public sealed class GatesFormModel
{
    public sealed class Switch { public string Path { get; set; } = ""; public bool On { get; set; } }
    public List<Switch> Switches { get; set; } = new();
    public string StartsWith { get; set; } = "";
    public string Contains { get; set; } = "";
    public string MatchesRegex { get; set; } = "";
    public string? Original { get; set; }

    public static readonly string[] Known = ["AutoExcludeRules.ExcludeCanBeOnboarded", "AutoExcludeRules.ExcludeInsufficientInfo", "AutoExcludeRules.ExcludeUnsupported", "AutoExcludeRules.ExcludeByDeviceNamePattern"];

    /// The form of a gates body (null = none stored: every switch off); the switches are the known ones, every switch the
    /// body holds, and every gate a tag in force names.
    public static GatesFormModel From(string? body, IEnumerable<string?> tagGates)
    {
        var o = TaggingStore.Parse(body) ?? new JsonObject();
        var f = new GatesFormModel { Original = body };
        var paths = new List<string>(Known);
        void Walk(JsonObject n, string prefix)
        {
            foreach (var (k, v) in n)
            {
                if (k.StartsWith('_') || k == "DeviceNamePatterns" && prefix.Length == 0) continue;
                var p = prefix.Length == 0 ? k : prefix + "." + k;
                if (v is JsonObject c) Walk(c, p);
                else if (v is JsonValue jv && (jv.TryGetValue<bool>(out _) || (jv.TryGetValue<string>(out var s) && s.ToLowerInvariant() is "true" or "false" or "1" or "0"))) paths.Add(p);
            }
        }
        Walk(o, "");
        paths.AddRange(tagGates.Where(g => !string.IsNullOrWhiteSpace(g)).Select(g => g!.Trim()));
        foreach (var p in paths.Distinct(StringComparer.Ordinal)) f.Switches.Add(new Switch { Path = p, On = Flag(o, p) });
        var dn = o["DeviceNamePatterns"] as JsonObject;
        string Lines(string k) => dn?[k] is JsonArray a ? string.Join("\n", a.Select(x => x?.GetValue<string>() ?? "")) : "";
        f.StartsWith = Lines("StartsWith"); f.Contains = Lines("Contains"); f.MatchesRegex = Lines("MatchesRegex");
        return f;
    }

    /// Test-TaggingConfigFlag (AssetTagging.ps1): a dotted path to a boolean true -- anything else is off.
    public static bool Flag(JsonObject? o, string path)
    {
        JsonNode? n = o;
        foreach (var seg in path.Split('.'))
        {
            if (n is not JsonObject jo) return false;
            n = jo.FirstOrDefault(kv => string.Equals(kv.Key, seg, StringComparison.OrdinalIgnoreCase)).Value;
        }
        if (n is not JsonValue v) return false;
        if (v.TryGetValue<bool>(out var b)) return b;
        // the engine also reads the text 'true' (any case) or '1' as on
        return v.TryGetValue<string>(out var s) && (string.Equals(s, "true", StringComparison.OrdinalIgnoreCase) || s == "1");
    }

    public IReadOnlyList<string> Problems()
    {
        var why = new List<string>();
        foreach (var s in Switches)
            if (!Regex.IsMatch(s.Path ?? "", @"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")) why.Add($"'{s.Path}' is not a switch path");
        foreach (var r in Split(MatchesRegex))
        {
            try { _ = new Regex(r); } catch (ArgumentException ex) { why.Add($"'{r}' is not a valid pattern: {ex.Message}"); }
        }
        return why;
    }

    private static List<string> Split(string s) => (s ?? "").Replace("\r\n", "\n").Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();

    public string ToJson()
    {
        var o = TaggingStore.Parse(Original) ?? new JsonObject();
        foreach (var s in Switches)
        {
            var segs = s.Path.Split('.');
            var node = o;
            for (var i = 0; i < segs.Length - 1; i++)
            {
                if (node[segs[i]] is not JsonObject next) { next = new JsonObject(); node[segs[i]] = next; }
                node = next;
            }
            node[segs[^1]] = s.On;
        }
        if (o["DeviceNamePatterns"] is not JsonObject dn) { dn = new JsonObject(); o["DeviceNamePatterns"] = dn; }
        dn["StartsWith"] = new JsonArray(Split(StartsWith).Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
        dn["Contains"] = new JsonArray(Split(Contains).Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
        dn["MatchesRegex"] = new JsonArray(Split(MatchesRegex).Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
        return TaggingStore.Json(o);
    }
}
