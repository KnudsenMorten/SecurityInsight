using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Changes;

/// <summary>
/// #405 (operator decision 2026-10-06) -- every shipped template is one of three classes, which decides how a change to it
/// travels: <c>fix</c> (with the code, never held), <c>default</c> (customer business logic: a customer's edit is never
/// changed) and <c>microsoft</c> (a Microsoft content pack between releases, installed automatically unless held). The
/// classification is data, <c>config\template-classification.locked.json</c> (linked next to the app as
/// <c>catalog\template-classification.locked.json</c>). <see cref="Of"/> is Get-SIProTemplateClass
/// (engine\pro-settings\SI-TemplatePacks.ps1), rule for rule: Items (exact '&lt;kind&gt;/&lt;key&gt;'), then Rules in order
/// (Kind equal, an ordinal culture-invariant regex on the ItemKey), then ByKind, else <c>fix</c>. A test runs both on every
/// shipped item.
/// </summary>
public sealed class TemplateClasses
{
    public const string Fix = "fix", Default = "default", Microsoft = "microsoft";
    public static readonly string[] All = { Fix, Default, Microsoft };
    public const string FileName = "template-classification.locked.json";

    private sealed record Rule(string Kind, Regex Pattern, string Class, string Reason);

    private readonly Dictionary<string, (string Class, string Reason)> _items = new(StringComparer.Ordinal);
    private readonly List<Rule> _rules = new();
    private readonly Dictionary<string, string> _byKind = new(StringComparer.Ordinal);

    /// Was a classification document read (a missing one = every item is <c>fix</c>)?
    public bool Present { get; }

    private TemplateClasses(JsonObject? doc)
    {
        Present = doc is not null;
        if (doc is null) return;
        if (doc["Items"] is JsonObject items)
            foreach (var (name, v) in items)
                if (v is JsonObject o && IsClass((string?)o["Class"])) _items[name] = ((string)o["Class"]!, (string?)o["Reason"] ?? "");
        if (doc["Rules"] is JsonArray rules)
            foreach (var r in rules.OfType<JsonObject>())
            {
                var cls = (string?)r["Class"]; var pattern = (string?)r["Pattern"];
                if (!IsClass(cls) || string.IsNullOrEmpty(pattern)) continue;
                _rules.Add(new Rule((string?)r["Kind"] ?? "", new Regex(pattern, RegexOptions.CultureInvariant), cls!, (string?)r["Reason"] ?? ""));
            }
        if (doc["ByKind"] is JsonObject byKind)
            foreach (var (kind, v) in byKind)
                if (v is JsonValue jv && jv.TryGetValue<string>(out var s) && IsClass(s)) _byKind[kind] = s;
    }

    public static bool IsClass(string? c) => c is not null && All.Contains(c, StringComparer.Ordinal);

    /// The document as text (tests); unreadable text = not present.
    public static TemplateClasses FromJson(string? text)
    {
        try { return new TemplateClasses(string.IsNullOrWhiteSpace(text) ? null : JsonNode.Parse(text) as JsonObject); }
        catch (JsonException) { return new TemplateClasses(null); }
    }

    /// The document next to the app (catalog\template-classification.locked.json), read once.
    public static TemplateClasses Shipped => _shipped.Value;
    private static readonly Lazy<TemplateClasses> _shipped = new(() =>
    {
        var p = Path.Combine(AppContext.BaseDirectory, "catalog", FileName);
        return FromJson(File.Exists(p) ? File.ReadAllText(p) : null);
    });

    /// The class of one item (Get-SIProTemplateClass).
    public string Of(string kind, string itemKey) => Explain(kind, itemKey).Class;

    public (string Class, string Source, string Reason) Explain(string kind, string itemKey)
    {
        if (_items.TryGetValue(kind + "/" + itemKey, out var it)) return (it.Class, "item", it.Reason);
        foreach (var r in _rules)
            if (string.Equals(r.Kind, kind, StringComparison.Ordinal) && r.Pattern.IsMatch(itemKey ?? "")) return (r.Class, "rule", r.Reason);
        if (_byKind.TryGetValue(kind, out var k)) return (k, "kind", $"every {kind} item is {k} unless named otherwise");
        return (Fix, "fallback", "not classified -- fix is the safe side (ships with the code, never held)");
    }

    /// How the page names a class.
    public static string Label(string? cls) => cls switch
    {
        Fix => "Fix",
        Default => "Your business logic",
        Microsoft => "Microsoft content",
        _ => cls ?? "",
    };
}
