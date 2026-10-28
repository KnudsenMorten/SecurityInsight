using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Changes;

/// <summary>
/// A factor's criteria block -- what the Risk factors wizard edits (#541 (7)); the C# twin of Test-SIRiskFactorCriteria
/// (engine\data-model\SI-RiskFactorCatalog.ps1).
///   criteria: { kind: list | threshold | range, field: si_*, source: collected | enum | lifecycle,
///               list + detailField (list) | op + min + max + unit (threshold) | min + max (range) }
/// The wizard never takes free text: a list entry is built ONLY from values SI collected (re-read on save and checked), a
/// threshold is a whole number inside [min, max]. The result is a normal data-model item (the factor or its list) staged
/// on Review &amp; commit as a cfg.ItemOverride row and validated again there and by the engine.
/// </summary>
public sealed record FactorCriteria(string Kind, string Field, string Source, string? List, string? DetailField, string? Op, double? Min, double? Max, string? Unit)
{
    public static readonly string[] Kinds = { "list", "threshold", "range" };
    public static readonly string[] Sources = { "collected", "enum", "lifecycle" };
    public const int MaxValueLength = 256;
    public const int MaxEntries = 500;

    /// The criteria of a factor body, or null (no criteria / unreadable).
    public static FactorCriteria? Of(string? factorJson)
    {
        if (string.IsNullOrWhiteSpace(factorJson)) return null;
        try { using var d = JsonDocument.Parse(factorJson); return Of(d.RootElement); }
        catch (JsonException) { return null; }
    }

    public static FactorCriteria? Of(JsonElement factor)
    {
        if (factor.ValueKind != JsonValueKind.Object || !factor.TryGetProperty("criteria", out var c) || c.ValueKind != JsonValueKind.Object) return null;
        return new FactorCriteria(S(c, "kind") ?? "", S(c, "field") ?? "", S(c, "source") ?? "", S(c, "list"), S(c, "detailField"), S(c, "op"), N(c, "min"), N(c, "max"), S(c, "unit"));
    }

    private static string? S(JsonElement o, string p) => o.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static double? N(JsonElement o, string p) => o.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d) ? d : null;

    private static readonly Regex SiFieldRx = new(@"^si_[a-z0-9_]+$", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// The reasons a factor's criteria are refused (empty = accepted / none). Mirrors Test-SIRiskFactorCriteria.
    public static IReadOnlyList<string> Problems(JsonElement factor)
    {
        var c = Of(factor);
        if (c is null) return Array.Empty<string>();
        var why = new List<string>();
        if (!Kinds.Contains(c.Kind, StringComparer.Ordinal)) why.Add($"criteria kind '{c.Kind}' (list, threshold or range)");
        if (!SiFieldRx.IsMatch(c.Field) || c.Field == "si_tier") why.Add($"criteria field '{c.Field}' must be an SI field (si_*), never si_tier");
        if (!Sources.Contains(c.Source, StringComparer.Ordinal)) why.Add($"criteria source '{c.Source}' (collected, enum or lifecycle)");
        var leaves = Leaves(factor.TryGetProperty("when", out var w) ? w : default).ToList();
        if (c.Kind == "list")
        {
            if (string.IsNullOrEmpty(c.List)) why.Add("criteria list is missing");
            else if (!leaves.Any(l => l.Value.ValueKind == JsonValueKind.String && l.Value.GetString() == c.List && l.Op is "in_list" or "in_ranges" or "contains_any"))
                why.Add($"its condition does not read the criteria list '{c.List}'");
            if (c.DetailField is { Length: > 0 } df && (!SiFieldRx.IsMatch(df) || df == "si_tier")) why.Add($"criteria detailField '{df}' must be an SI field");
        }
        else if (c.Kind is "threshold" or "range")
        {
            if (c.Min is null || c.Max is null || c.Min > c.Max) why.Add("criteria min / max must be numbers, min <= max");
            else if (c.Kind == "threshold")
            {
                var hit = leaves.Where(l => l.Field == c.Field && l.Op == c.Op).ToList();
                if (hit.Count == 0) why.Add($"its condition has no '{c.Field} {c.Op}' leaf for the criteria");
                foreach (var l in hit)
                    if (l.Value.ValueKind != JsonValueKind.Number || !l.Value.TryGetDouble(out var v) || v < c.Min || v > c.Max)
                        why.Add($"'{c.Field} {c.Op} {l.Value}' is outside the criteria range {c.Min}..{c.Max}");
            }
        }
        return why;
    }

    public sealed record Leaf(string Field, string Op, JsonElement Value);

    public static IEnumerable<Leaf> Leaves(JsonElement c)
    {
        if (c.ValueKind != JsonValueKind.Object) yield break;
        foreach (var g in new[] { "all", "any" })
            if (c.TryGetProperty(g, out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var x in arr.EnumerateArray()) foreach (var l in Leaves(x)) yield return l;
                yield break;
            }
        var f = c.TryGetProperty("field", out var fe) && fe.ValueKind == JsonValueKind.String ? fe.GetString() ?? "" : "";
        var o = c.TryGetProperty("op", out var oe) && oe.ValueKind == JsonValueKind.String ? oe.GetString() ?? "" : "";
        yield return new Leaf(f, o, c.TryGetProperty("value", out var v) ? v.Clone() : default);
    }

    private static string? Str(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    /// The threshold in force (the first matching leaf's number), or null.
    public int? CurrentThreshold(string factorJson)
    {
        try
        {
            using var d = JsonDocument.Parse(factorJson);
            var l = Leaves(d.RootElement.TryGetProperty("when", out var w) ? w : default).FirstOrDefault(x => x.Field == Field && x.Op == Op && x.Value.ValueKind == JsonValueKind.Number);
            return l is not null && l.Value.TryGetDouble(out var v) ? (int)Math.Round(v) : null;
        }
        catch (JsonException) { return null; }
    }

    /// THRESHOLD WIZARD: the factor body with every '{Field} {Op}' leaf set to the new whole number. Refused outside [Min, Max].
    public (string? Body, IReadOnlyList<string> Problems) WithThreshold(string factorJson, string? posted)
    {
        if (Kind != "threshold") return (null, new[] { "this factor's criteria are not a threshold" });
        if (!int.TryParse(posted, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)) return (null, new[] { $"'{posted}' is not a whole number" });
        if (Min is null || Max is null || n < Min || n > Max) return (null, new[] { $"{n} is outside {Min}..{Max}{(Unit is null ? "" : " " + Unit)}" });
        var node = JsonNode.Parse(factorJson) as JsonObject;
        if (node is null) return (null, new[] { "the factor is not a JSON object" });
        var changed = 0;
        void Walk(JsonNode? x)
        {
            if (x is not JsonObject o) return;
            foreach (var g in new[] { "all", "any" }) if (o[g] is JsonArray a) { foreach (var i in a) Walk(i); return; }
            if (Str(o["field"]) == Field && Str(o["op"]) == Op) { o["value"] = n; changed++; }
        }
        Walk(node["when"]);
        if (changed == 0) return (null, new[] { $"the factor has no '{Field} {Op}' condition to set" });
        return (node.ToJsonString(), Array.Empty<string>());
    }

    /// One collected value pair a list wizard offers (e.g. OS name + version) and how many CIs carry it.
    public sealed record Collected(string Value, string? Detail, long Count)
    {
        /// The opaque token a form posts for it (the server maps it back to the collected values -- never free text).
        public string Token => Detail is null ? "v:" + Value : "d:" + Value + "\u001f" + Detail;
        public string Label => Detail is null ? $"{Value} (any version)" : $"{Value} {Detail}";
    }

    /// One entry of the list in force, for the wizard's "keep" check boxes.
    public sealed record ListEntry(int Index, string Name, string Json);

    public static IReadOnlyList<ListEntry> Entries(string? listJson)
    {
        var list = new List<ListEntry>();
        if (string.IsNullOrWhiteSpace(listJson)) return list;
        try
        {
            using var d = JsonDocument.Parse(listJson);
            if (d.RootElement.TryGetProperty("entries", out var e) && e.ValueKind == JsonValueKind.Array)
            {
                var i = 0;
                foreach (var x in e.EnumerateArray()) { list.Add(new ListEntry(i++, x.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() ?? "" : $"entry {i}", x.GetRawText())); }
            }
        }
        catch (JsonException) { }
        return list;
    }

    /// LIST WIZARD: the list body = the kept entries of the list in force (by index, verbatim) + one entry per picked token,
    /// each built from a COLLECTED value only ({Field} eq value [and {DetailField} eq detail]). A token that is not one of the
    /// collected values is refused -- nothing typed reaches the list.
    public (string? Body, IReadOnlyList<string> Problems) WithList(string listJson, IEnumerable<int> keep, IEnumerable<string> picked, IReadOnlyCollection<Collected> collected)
    {
        if (Kind != "list") return (null, new[] { "this factor's criteria are not a list" });
        var node = JsonNode.Parse(listJson) as JsonObject;
        if (node is null) return (null, new[] { "the list is not a JSON object" });
        if (Str(node["type"]) != "conditions") return (null, new[] { "the wizard edits a conditions list" });
        var old = node["entries"] as JsonArray ?? new JsonArray();
        var keepSet = keep.ToHashSet();
        var entries = new JsonArray();
        for (var i = 0; i < old.Count; i++) if (keepSet.Contains(i)) entries.Add(old[i]?.DeepClone());
        var byToken = collected.GroupBy(c => c.Token, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        var why = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var t in picked.Where(t => !string.IsNullOrEmpty(t)))
        {
            if (!byToken.TryGetValue(t, out var c)) { why.Add("a picked value is not one SecurityInsight collected -- reload the page and pick again"); continue; }
            if (!seen.Add(t)) continue;
            if (c.Value.Length > MaxValueLength || (c.Detail?.Length ?? 0) > MaxValueLength || c.Value.Any(char.IsControl) || (c.Detail?.Any(char.IsControl) ?? false)) { why.Add($"'{c.Label}' is too long or not plain text"); continue; }
            var all = new JsonArray { new JsonObject { ["field"] = Field, ["op"] = "eq", ["value"] = c.Value } };
            if (c.Detail is not null && DetailField is { Length: > 0 }) all.Add(new JsonObject { ["field"] = DetailField, ["op"] = "eq", ["value"] = c.Detail });
            entries.Add(new JsonObject { ["name"] = c.Label, ["when"] = new JsonObject { ["all"] = all } });
        }
        if (entries.Count > MaxEntries) why.Add($"at most {MaxEntries} entries");
        if (why.Count > 0) return (null, why);
        node["entries"] = entries;
        return (node.ToJsonString(), Array.Empty<string>());
    }
}

