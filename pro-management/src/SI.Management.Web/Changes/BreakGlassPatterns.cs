using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Changes;

/// <summary>
/// Break glass (emergency-access) naming patterns -- pure, no I/O. Break glass is not a risk factor: it is an SI
/// classification detected from the platform (Conditional Access exclusions, the emergency-access group) plus naming
/// patterns SecurityInsight ships and the customer sets here. The patterns are the data-model list
/// 'lists:break_glass_patterns' (a values list); a change is that list's cfg.ItemOverride body, staged on Review &amp;
/// commit and validated again there (<see cref="DataModelItemValidator.List"/>).
///
/// A pattern is a GLOB over the account name: letters, digits, space and . _ @ - plus the wildcards * (any run) and ?
/// (one character). Nothing else is accepted -- no quote, backslash, bracket or bar -- so a pattern can never carry text
/// that changes a query, however the engine turns it into a match. A pattern of wildcards only ("*") is refused: it
/// would make every account break glass.
/// </summary>
public static partial class BreakGlassPatterns
{
    public const string ListId = "break_glass_patterns";
    public const string ItemKey = "lists:" + ListId;
    public const int MaxLength = 128;
    public const int MaxPatterns = 200;
    public const string Description = "Naming patterns of break glass (emergency-access) accounts: globs over the account name, * = any run of characters, ? = one character.";

    [GeneratedRegex(@"^[A-Za-z0-9 ._@\-*?]+$", RegexOptions.CultureInvariant)]
    private static partial Regex GlobChars();

    /// Why a pattern is refused, or null when it is a valid glob.
    public static string? Problem(string? pattern)
    {
        var p = pattern ?? "";
        if (p.Length == 0) return "a pattern is empty";
        if (p.Length > MaxLength) return $"'{Short(p)}' is longer than {MaxLength} characters";
        if (p != p.Trim()) return $"'{p}' starts or ends with a space";
        if (!GlobChars().IsMatch(p)) return $"'{Short(p)}' is not a glob pattern -- use letters, digits, space, . _ @ - and the wildcards * and ?";
        if (p.All(c => c is '*' or '?' or ' ')) return $"'{p}' matches every account -- a pattern needs at least one letter or digit";
        return null;
    }

    private static string Short(string s) => s.Length > 40 ? s[..40] + "..." : s;

    /// The patterns of the list body in force (its 'values'), in order.
    public static IReadOnlyList<string> Patterns(string? listJson)
    {
        if (string.IsNullOrWhiteSpace(listJson)) return Array.Empty<string>();
        try
        {
            using var d = JsonDocument.Parse(listJson);
            if (d.RootElement.ValueKind == JsonValueKind.Object && d.RootElement.TryGetProperty("values", out var v) && v.ValueKind == JsonValueKind.Array)
                return v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString() ?? "").Where(x => x.Length > 0).ToList();
        }
        catch (JsonException) { }
        return Array.Empty<string>();
    }

    /// The list body with these patterns (blank rows dropped, duplicates dropped case-insensitively, order kept). The
    /// list's other fields are kept; a list SecurityInsight does not ship yet is created as a values list. Refused when
    /// any pattern is not a valid glob, or over the maximum.
    public static (string? Body, IReadOnlyList<string> Problems) WithPatterns(string? listJson, IEnumerable<string?> posted)
    {
        var why = new List<string>();
        var kept = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in posted)
        {
            var p = (raw ?? "").Trim();
            if (p.Length == 0) continue;
            if (Problem(p) is { } bad) { why.Add(bad); continue; }
            if (seen.Add(p)) kept.Add(p);
        }
        if (kept.Count > MaxPatterns) why.Add($"at most {MaxPatterns} patterns");
        if (why.Count > 0) return (null, why);
        JsonObject o;
        try { o = (string.IsNullOrWhiteSpace(listJson) ? null : JsonNode.Parse(listJson) as JsonObject) ?? new JsonObject(); }
        catch (JsonException) { o = new JsonObject(); }
        o["id"] = ListId;
        o["type"] = "values";
        if (o["description"] is null) o["description"] = Description;
        o.Remove("entries");
        var arr = new JsonArray();
        foreach (var p in kept) arr.Add(p);
        o["values"] = arr;
        return (o.ToJsonString(), Array.Empty<string>());
    }

    /// Does an account name match a pattern (case-insensitive glob)? For the page's "try a name" check only.
    public static bool Matches(string pattern, string name)
    {
        if (Problem(pattern) is not null || string.IsNullOrEmpty(name)) return false;
        var rx = "^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
        return Regex.IsMatch(name, rx, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
    }
}
