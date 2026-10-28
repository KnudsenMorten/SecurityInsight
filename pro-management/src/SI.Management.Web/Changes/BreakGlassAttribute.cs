using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Changes;

/// <summary>
/// The break glass (emergency-access) EXTENSION ATTRIBUTE rule -- pure, no I/O. An account that carries the attribute and
/// value the customer defines here is a break glass account (owner 2026-10-11: "extension attr tag value i define").
/// Nothing is shipped: the data-model list 'lists:break_glass_attribute' is empty until the customer adds an entry. Each
/// entry of the list is the text <c>attribute=value</c>; a change is that list's cfg.ItemOverride body, staged on Review
/// &amp; commit and validated again there (<see cref="DataModelItemValidator.List"/>) -- exactly as the naming patterns
/// (<see cref="BreakGlassPatterns"/>).
///
/// <see cref="Parse"/> is the C# twin of the engine's ConvertTo-SIBreakGlassAttributeRule
/// (engine/data-model/SI-BreakGlass.ps1), which is THE rule: the collector asks Microsoft Graph for the attribute an entry
/// names and the CI build classifies from the match. An entry the engine would skip must never be stored from here, so the
/// two are held to one table of examples (tests/fixtures/break-glass-attribute-entries.json: BreakGlassAttributeTests and
/// the Pester suite SIv3-BreakGlassAttributeParity).
///   attribute   extensionAttribute1 .. extensionAttribute15 (any case; stored in that spelling), or the name of a
///               directory extension: extension_&lt;32 hex characters&gt;_&lt;name of letters, digits and _, 1-128&gt;
///   value       the text the attribute must hold: 1 to 256 characters after trimming -- never empty (an empty value
///               would make every account break glass)
/// </summary>
public static partial class BreakGlassAttribute
{
    public const string ListId = "break_glass_attribute";
    public const string ItemKey = "lists:" + ListId;
    public const int MaxValueLength = 256;
    public const int MaxEntries = 50;
    public const string KindExtensionAttribute = "extensionAttribute";
    public const string KindDirectoryExtension = "directoryExtension";
    public const string Description = "The extension attribute and value that mark a break glass (emergency-access) account: entries attribute=value, the attribute extensionAttribute1 to extensionAttribute15 or a directory extension name.";

    /// What the page says an entry is, in one sentence (also the refusal text).
    public const string Rule = "the attribute is extensionAttribute1 to extensionAttribute15 or a directory extension name (extension_<application id without dashes>_<name>), and the value is 1 to 256 characters";

    /// One valid entry. <see cref="Text"/> is what the list stores and what the collector writes on a matching account.
    public sealed record Entry(string Attribute, string Value, string Kind)
    {
        public string Text => Attribute + "=" + Value;
    }

    [GeneratedRegex(@"^extensionAttribute(?<n>1[0-5]|[1-9])$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex OnPremAttribute();

    [GeneratedRegex(@"^extension_[0-9a-fA-F]{32}_[A-Za-z0-9_]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex DirectoryExtension();

    /// The attribute names the form offers (the fifteen on-premises extension attributes; a directory extension is typed).
    public static readonly IReadOnlyList<string> OnPremAttributes = Enumerable.Range(1, 15).Select(n => "extensionAttribute" + n).ToList();

    /// One entry "attribute=value" as the engine reads it, or null when the engine would skip it. The first '=' separates
    /// the two (a value may hold more); both parts are trimmed; the attribute is put in its one spelling.
    public static Entry? Parse(string? entry)
    {
        var s = entry ?? "";
        var i = s.IndexOf('=');
        if (i < 1) return null;
        var a = s[..i].Trim();
        var v = s[(i + 1)..].Trim();
        if (v.Length == 0 || v.Length > MaxValueLength) return null;
        var m = OnPremAttribute().Match(a);
        // '$' also matches before a final line break; the attribute is trimmed, so a whole match is the whole text
        if (m.Success && m.Length == a.Length) return new Entry("extensionAttribute" + m.Groups["n"].Value, v, KindExtensionAttribute);
        var d = DirectoryExtension().Match(a);
        if (d.Success && d.Length == a.Length) return new Entry(a, v, KindDirectoryExtension);
        return null;
    }

    /// The entry of an attribute and a value typed in two fields, or null (the same rule: the two joined by '=').
    public static Entry? Parse(string? attribute, string? value)
    {
        var a = (attribute ?? "").Trim();
        // an '=' in the attribute field would move the split: an attribute name never holds one
        if (a.Length == 0 || a.Contains('=')) return null;
        return Parse(a + "=" + (value ?? ""));
    }

    /// Why an entry is refused, or null when it is valid. On top of the engine's rule a stored entry is plain text (no
    /// control character), as every value of a data-model list is.
    public static string? Problem(string? entry)
    {
        var e = entry ?? "";
        if (e.Any(char.IsControl)) return $"'{Short(e)}' is not plain text";
        return Parse(e) is null ? $"'{Short(e)}' is not attribute=value -- {Rule}" : null;
    }

    private static string Short(string s) => s.Length > 60 ? s[..60] + "..." : s;

    /// The entries of the list body in force (its 'values'), in order: the stored text and what it parses to (null = an
    /// entry the engine skips -- shown so it can be removed).
    public static IReadOnlyList<(string Text, Entry? Parsed)> Entries(string? listJson)
    {
        if (string.IsNullOrWhiteSpace(listJson)) return Array.Empty<(string, Entry?)>();
        try
        {
            using var d = JsonDocument.Parse(listJson);
            if (d.RootElement.ValueKind == JsonValueKind.Object && d.RootElement.TryGetProperty("values", out var v) && v.ValueKind == JsonValueKind.Array)
                return v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").Where(x => x.Length > 0)
                    .Select(x => (x, Parse(x))).ToList();
        }
        catch (JsonException) { }
        return Array.Empty<(string, Entry?)>();
    }

    /// The list body with these entries (rows with both fields blank dropped; the same attribute and value twice kept once,
    /// upper and lower case alike -- the engine compares the value without regard to case; order kept). The list's other
    /// fields are kept; a list SecurityInsight does not ship yet is created as a values list. Refused when a row is not a
    /// valid entry, or over the maximum.
    public static (string? Body, IReadOnlyList<string> Problems) WithEntries(string? listJson, IEnumerable<(string? Attribute, string? Value)> posted)
    {
        var why = new List<string>();
        var kept = new List<Entry>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (rawA, rawV) in posted)
        {
            var a = (rawA ?? "").Trim();
            var v = (rawV ?? "").Trim();
            if (a.Length == 0 && v.Length == 0) continue;
            if (a.Length == 0) { why.Add($"the value '{Short(v)}' has no attribute"); continue; }
            if (v.Length == 0) { why.Add($"'{Short(a)}' has no value -- an empty value would make every account break glass"); continue; }
            if ((a + v).Any(char.IsControl)) { why.Add($"'{Short(a)}' is not plain text"); continue; }
            if (Parse(a, v) is not { } e) { why.Add($"'{Short(a + "=" + v)}' is not accepted -- {Rule}"); continue; }
            if (seen.Add(e.Text)) kept.Add(e);
        }
        if (kept.Count > MaxEntries) why.Add($"at most {MaxEntries} entries");
        if (why.Count > 0) return (null, why);
        JsonObject o;
        try { o = (string.IsNullOrWhiteSpace(listJson) ? null : JsonNode.Parse(listJson) as JsonObject) ?? new JsonObject(); }
        catch (JsonException) { o = new JsonObject(); }
        o["id"] = ListId;
        o["type"] = "values";
        if (o["description"] is null) o["description"] = Description;
        o.Remove("entries");
        var arr = new JsonArray();
        foreach (var e in kept) arr.Add(e.Text);
        o["values"] = arr;
        return (o.ToJsonString(), Array.Empty<string>());
    }

    /// Does the entry an account carries (the collector's "attribute=value") belong to this rule? Compared whole, upper
    /// and lower case alike -- as the CI build does.
    public static bool Carries(Entry rule, string? carried) =>
        !string.IsNullOrWhiteSpace(carried) && string.Equals(rule.Text, carried.Trim(), StringComparison.OrdinalIgnoreCase);
}
