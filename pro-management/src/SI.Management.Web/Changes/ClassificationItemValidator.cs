using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Changes;

/// <summary>
/// #561 / #562: the C# twin of Test-SIDimensionItem and Test-SIClassificationRule (engine\data-model\SI-Classification.ps1)
/// for the 'datamodel' cfg.ItemOverride rows of the ONE generic classification mechanism:
///   'dimensions:&lt;id&gt;'      a dimension (asset_type, asset_subtype, component, ...): ONLY its list of values
///   'classification:&lt;id&gt;'  a row: source + field (an SI field or a source path) + match (equals | in -> values;
///                               prefix | pattern -> pattern, a glob) -> target (the SI field it sets) = set, priority
///                               0..10000 (higher wins), state enabled | disabled; optional 'when' (SI fields only)
/// The closed sets are the engine's (Get-SIClassificationShape); the run validates the whole model again (Test-SIDataModel),
/// including that a row's target is a classification target and its 'set' one of that dimension's values.
/// </summary>
public static partial class ClassificationItemValidator
{
    public const string DimensionsTemplate = "dimensions";
    public const string ClassificationTemplate = "classification";
    public static readonly string[] MatchOps = { "equals", "in", "prefix", "pattern" };
    public static readonly string[] States = { "enabled", "disabled" };
    public const int PriorityMax = 10000;

    [GeneratedRegex(@"^[a-z][a-z0-9_]{0,47}$", RegexOptions.CultureInvariant)]
    private static partial Regex DimensionId();

    [GeneratedRegex(@"^[a-z0-9][a-z0-9_\-\.]{0,99}$", RegexOptions.CultureInvariant)]
    private static partial Regex RowId();

    [GeneratedRegex(@"^si_[a-z0-9_]+$", RegexOptions.CultureInvariant)]
    private static partial Regex SiField();

    // an SI field, or a source path (a.b[*].c)
    [GeneratedRegex(@"^(si_[a-z0-9_]+|[A-Za-z_][A-Za-z0-9_]*(\[\*\])?(\.[A-Za-z0-9_$@-]+(\[\*\])?)*)$", RegexOptions.CultureInvariant)]
    private static partial Regex FieldOrPath();

    [GeneratedRegex(@"^[a-z][a-z0-9_]{0,31}$", RegexOptions.CultureInvariant)]
    private static partial Regex Source();

    private static string Str(JsonElement o, string p) => o.ValueKind == JsonValueKind.Object && o.TryGetProperty(p, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static List<JsonElement> Items(JsonElement o, string p)
    {
        if (o.ValueKind != JsonValueKind.Object || !o.TryGetProperty(p, out var v)) return new List<JsonElement>();
        if (v.ValueKind == JsonValueKind.Array) return v.EnumerateArray().Where(x => x.ValueKind is not JsonValueKind.Null && !(x.ValueKind == JsonValueKind.String && (x.GetString() ?? "").Length == 0)).ToList();
        if (v.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined) return new List<JsonElement>();
        if (v.ValueKind == JsonValueKind.String && string.IsNullOrWhiteSpace(v.GetString())) return new List<JsonElement>();
        return new List<JsonElement> { v };
    }

    /// One dimension: its id is the key, one or more distinct values of one line, at most 64 characters, no ';'.
    public static IReadOnlyList<string> Dimension(string item, JsonElement d)
    {
        var why = new List<string>();
        var id = Str(d, "id");
        if (id != item) why.Add($"id must be '{item}' -- the key names the dimension");
        if (!DimensionId().IsMatch(id)) why.Add($"dimension id '{id}': a lower snake_case word of at most 48 characters");
        var values = Items(d, "values").Where(x => x.ValueKind == JsonValueKind.String).Select(x => (x.GetString() ?? "").Trim()).Where(x => x.Length > 0).ToList();
        if (values.Count == 0) why.Add($"dimension '{id}': values names at least one value");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var v in values)
        {
            if (v.Length > 64 || v.IndexOfAny(new[] { '\r', '\n', '\t', ';' }) >= 0) why.Add($"dimension '{id}': value '{v}' must be one line of at most 64 characters without ';'");
            if (!seen.Add(v)) why.Add($"dimension '{id}': value '{v}' is listed twice");
        }
        // #772 an optional default: the fallback of the dimension's finding / single-value targets -- one of its own values
        if (Str(d, "default").Trim() is { Length: > 0 } def && !seen.Contains(def)) why.Add($"dimension '{id}': default '{def}' is not one of its values");
        return why;
    }

    /// One classification row (the contract the classification wizard writes).
    public static IReadOnlyList<string> Rule(string item, JsonElement r)
    {
        var why = new List<string>();
        var id = Str(r, "id");
        if (id != item) why.Add($"id must be '{item}' -- the key names the row");
        if (!RowId().IsMatch(id)) why.Add($"row id '{id}': lower-case letters, digits, - _ . (at most 100)");
        var field = Str(r, "field");
        if (!FieldOrPath().IsMatch(field)) why.Add($"row '{id}': field '{field}' must be an SI field (si_*) or a source path (a.b[*].c)");
        var op = Str(r, "match");
        if (!MatchOps.Contains(op)) why.Add($"row '{id}': match '{op}' (equals | in | prefix | pattern)");
        var values = Items(r, "values");
        var pattern = Items(r, "pattern");
        if (op is "equals" or "in")
        {
            if (values.Count == 0) why.Add($"row '{id}': match '{op}' needs values (a list)");
            if (op == "equals" && values.Count > 1) why.Add($"row '{id}': equals takes one value -- use in for several");
            if (pattern.Count > 0) why.Add($"row '{id}': match '{op}' reads values, not pattern");
        }
        if (op is "prefix" or "pattern")
        {
            if (pattern.Count == 0) why.Add($"row '{id}': match '{op}' needs a pattern (a glob)");
            if (values.Count > 0) why.Add($"row '{id}': match '{op}' reads pattern, not values");
            if (pattern.Any(x => x.ValueKind != JsonValueKind.String)) why.Add($"row '{id}': a pattern is text (a glob)");
        }
        var target = Str(r, "target");
        if (!SiField().IsMatch(target)) why.Add($"row '{id}': target '{target}' must be an SI field (si_*)");
        if (Str(r, "set").Trim().Length == 0) why.Add($"row '{id}': set (the value) is required");
        if (!(r.TryGetProperty("priority", out var p) && p.ValueKind == JsonValueKind.Number && p.TryGetInt32(out var pv) && pv >= 0 && pv <= PriorityMax))
            why.Add($"row '{id}': priority must be an integer 0..{PriorityMax} (higher wins)");
        if (Str(r, "state") is { Length: > 0 } st && !States.Contains(st)) why.Add($"row '{id}': state is enabled or disabled");
        if (Str(r, "source") is { Length: > 0 } src && !Source().IsMatch(src)) why.Add($"row '{id}': source '{src}' is not a provider name");
        if (r.TryGetProperty("when", out var when) && when.ValueKind != JsonValueKind.Null) Walk(id, when, why);
        return why;
    }

    private static bool ValidRegex(string p)
    {
        try { _ = new Regex(p, RegexOptions.None, TimeSpan.FromMilliseconds(200)); return true; }
        catch (ArgumentException) { return false; }
    }

    // the condition language's closed operation set (SI-Conditions.ps1 Get-SIConditionOps), in_list excluded for a row
    private static readonly string[] ConditionOps = { "eq", "ne", "in", "not_in", "is_true", "is_false", "is_empty", "not_empty", "gt", "gte", "lt", "lte", "like",
        "contains", "contains_any", "matches", "older_than_days", "newer_than_days", "in_ranges" };

    private static void Walk(string id, JsonElement c, List<string> why)
    {
        if (c.ValueKind != JsonValueKind.Object) { why.Add($"row '{id}': when is a condition object"); return; }
        foreach (var g in new[] { "all", "any" })
        {
            if (c.TryGetProperty(g, out var arr) && arr.ValueKind == JsonValueKind.Array)
            {
                foreach (var x in arr.EnumerateArray()) Walk(id, x, why);
                return;
            }
        }
        var f = Str(c, "field");
        if (!SiField().IsMatch(f)) why.Add($"row '{id}': when reads '{f}' -- an extra condition reads SI fields (si_*) only");
        var op = Str(c, "op");
        if (op == "in_list") why.Add($"row '{id}': in_list is not available to a classification row -- list the values (in)");
        else if (!ConditionOps.Contains(op)) why.Add($"row '{id}': unknown condition operation '{op}'");
        if (op == "matches")
            foreach (var pat in Items(c, "value").Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? ""))
                if (!ValidRegex(pat)) why.Add($"row '{id}': invalid pattern '{pat}'");
    }
}
