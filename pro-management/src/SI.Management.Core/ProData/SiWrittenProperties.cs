using System.Text;
using System.Text.Json;

namespace SI.Management.Core.ProData;

/// One property SecurityInsight writes itself: the source, the record types ('*' = every one), the record part, the
/// property as discovery names it (a trailing '*' = every property that starts with the text before it), mapped or
/// internal, the si_ fields that read it and why.
public sealed record SiWrittenProperty(string Source, IReadOnlyList<string> RecordTypes, string Part, string Property, string Use, IReadOnlyList<string> Fields, string Why)
{
    public bool IsPrefix => Property.EndsWith('*');
    public string Stem => IsPrefix ? Property[..^1] : Property;
}

/// <summary>
/// THE PROPERTIES SECURITYINSIGHT WRITES ITSELF (owner 2026-11-25: "if we control it, why dont you fill out these fields and
/// activate them ?") -- an embedded copy of data-model/si-written-properties.locked.json (ProData/DataModel, held to the
/// original by a test). Continuous discovery sees them on the records like any source property; Configuration > New
/// context available leaves them out of what is NEW (they are SecurityInsight's own, shipped mapped or internal, never a
/// decision for an Admin) and lists them under Everything known only.
/// </summary>
public static class SiWrittenProperties
{
    private static Stream Resource(string name) =>
        typeof(SiWrittenProperties).Assembly.GetManifestResourceStream("DataModel/" + name)
        ?? throw new InvalidOperationException($"the embedded data model file {name} is missing from the build");

    /// PURE. The list from the file's text (an entry without a source, a part or a property is left out).
    public static IReadOnlyList<SiWrittenProperty> Load(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var list = new List<SiWrittenProperty>();
        if (!doc.RootElement.TryGetProperty("properties", out var items) || items.ValueKind != JsonValueKind.Array) return list;
        foreach (var e in items.EnumerateArray())
        {
            if (e.ValueKind != JsonValueKind.Object) continue;
            var source = Str(e, "source"); var part = Str(e, "part"); var property = Str(e, "property");
            if (source is null || part is null || property is null || property == "*") continue;
            list.Add(new SiWrittenProperty(source, Strings(e, "recordTypes"), part, property, Str(e, "use") ?? "", Strings(e, "fields"), Str(e, "why") ?? ""));
        }
        return list;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(v.GetString()) ? v.GetString()!.Trim() : null;

    private static IReadOnlyList<string> Strings(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(x.GetString())).Select(x => x.GetString()!.Trim()).ToList()
            : Array.Empty<string>();

    private static readonly Lazy<IReadOnlyList<SiWrittenProperty>> Lazy = new(() =>
    {
        try
        {
            using var r = new StreamReader(Resource("si-written-properties.locked.json"));
            return Load(r.ReadToEnd());
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            // nothing readable: nothing is left out -- the page shows every property, as before
            return Array.Empty<SiWrittenProperty>();
        }
    });

    /// The shipped list.
    public static IReadOnlyList<SiWrittenProperty> Default => Lazy.Value;

    /// PURE. Whether SecurityInsight writes the property itself (source, record type and part as discovery keeps them).
    public static bool IsSiWritten(IEnumerable<SiWrittenProperty> list, string source, string recordType, string part, string property) =>
        list.Any(p => p.Source.Equals(source, StringComparison.OrdinalIgnoreCase) && p.Part.Equals(part, StringComparison.OrdinalIgnoreCase)
            && (p.RecordTypes.Count == 0 || p.RecordTypes.Contains("*") || p.RecordTypes.Contains(recordType, StringComparer.OrdinalIgnoreCase))
            && (p.IsPrefix ? property.StartsWith(p.Stem, StringComparison.OrdinalIgnoreCase) : property.Equals(p.Property, StringComparison.OrdinalIgnoreCase)));

    private static string Lit(string s) => "N'" + s.Replace("'", "''") + "'";

    // a LIKE pattern for the text before the '*': the LIKE wildcards in it are taken literally
    private static string LikeStem(string s) => "N'" + s.Replace("'", "''").Replace("[", "[[]").Replace("%", "[%]").Replace("_", "[_]") + "%'";

    /// <summary>
    /// PURE. The SQL condition (on sidata.SourceProperty under the alias <paramref name="alias"/>) that is TRUE for a
    /// property SecurityInsight writes itself; "1 = 0" when the list is empty. Built from the shipped list only (never a
    /// customer value), every text a quoted literal.
    /// </summary>
    public static string SqlCondition(IEnumerable<SiWrittenProperty> list, string alias = "p")
    {
        var parts = new List<string>();
        foreach (var p in list)
        {
            var sb = new StringBuilder("(");
            sb.Append(alias).Append(".Source = ").Append(Lit(p.Source)).Append(" AND ").Append(alias).Append(".Part = ").Append(Lit(p.Part));
            var types = p.RecordTypes.Where(t => t != "*").ToList();
            if (types.Count > 0 && !p.RecordTypes.Contains("*"))
                sb.Append(" AND ").Append(alias).Append(".RecordType IN (").Append(string.Join(", ", types.Select(Lit))).Append(')');
            sb.Append(" AND ").Append(alias).Append(".Property ").Append(p.IsPrefix ? "LIKE " + LikeStem(p.Stem) : "= " + Lit(p.Property));
            sb.Append(')');
            parts.Add(sb.ToString());
        }
        return parts.Count == 0 ? "1 = 0" : "(" + string.Join(" OR ", parts) + ")";
    }
}
