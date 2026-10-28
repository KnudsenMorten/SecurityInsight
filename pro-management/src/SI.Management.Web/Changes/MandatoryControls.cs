using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SI.Management.Web.Changes;

/// One mandatory control: the part of a shipped template item SecurityInsight's own code requires.
public sealed record MandatoryControl(string Id, string Kind, string ItemKey, string Rule, string Path, JsonNode? Value, JsonNode? Default, string Reason);

/// <summary>
/// MANDATORY CONTROLS ON TOP OF TEMPLATES (adopted from PIM4EntraPS: engine-enforced defaults applied on top of every
/// template). The C# twin of Test-SIProMandatoryOverride (engine\pro-settings\SI-TemplateMandatory.ps1): a customer
/// override may never switch off or weaken a part the product requires. The set is data,
/// <c>config\template-mandatory.locked.json</c> (linked next to the app as <c>catalog\template-mandatory.locked.json</c>) --
/// the same file the run reads to apply the required values on top. Rules: present (the item cannot be switched off),
/// equals, atLeast, above, contains. An item with ANY control cannot be switched off (that switches every part off).
/// </summary>
public sealed class MandatoryControls
{
    public const string FileName = "template-mandatory.locked.json";
    public static readonly string[] Rules = { "present", "equals", "atLeast", "above", "contains" };

    public IReadOnlyList<MandatoryControl> Controls { get; }

    private MandatoryControls(IReadOnlyList<MandatoryControl> controls) => Controls = controls;

    /// The catalog as text (tests); unreadable or empty text = no controls.
    public static MandatoryControls FromJson(string? text)
    {
        var list = new List<MandatoryControl>();
        if (!string.IsNullOrWhiteSpace(text))
        {
            try
            {
                if (JsonNode.Parse(text) is JsonObject doc && doc["Controls"] is JsonArray arr)
                    foreach (var c in arr.OfType<JsonObject>())
                    {
                        var rule = (string?)c["Rule"] ?? "";
                        var kind = (string?)c["Kind"] ?? ""; var key = (string?)c["ItemKey"] ?? "";
                        if (!Rules.Contains(rule, StringComparer.Ordinal) || kind.Length == 0 || key.Length == 0) continue;
                        list.Add(new MandatoryControl((string?)c["Id"] ?? "", kind, key, rule, (string?)c["Path"] ?? "",
                            c["Value"]?.DeepClone(), c["Default"]?.DeepClone(), (string?)c["Reason"] ?? ""));
                    }
            }
            catch (JsonException) { list.Clear(); }
        }
        return new MandatoryControls(list);
    }

    /// The catalog next to the app (catalog\template-mandatory.locked.json), read once.
    public static MandatoryControls Shipped => _shipped.Value;
    private static readonly Lazy<MandatoryControls> _shipped = new(() =>
    {
        var p = Path.Combine(AppContext.BaseDirectory, "catalog", FileName);
        return FromJson(File.Exists(p) ? File.ReadAllText(p) : null);
    });

    public IReadOnlyList<MandatoryControl> For(string kind, string key) =>
        Controls.Where(c => string.Equals(c.Kind, kind, StringComparison.Ordinal) && string.Equals(c.ItemKey, key, StringComparison.Ordinal)).ToList();

    /// Does the item carry any control (the page marks it "required")?
    public bool IsMandatory(string kind, string key) => For(kind, key).Count > 0;

    private static string Canon(JsonNode? n) => TemplateConformance.Normalise(n?.ToJsonString() ?? "null")?.ToJsonString() ?? (n?.ToJsonString() ?? "null");

    private static double? Number(JsonNode? n)
    {
        if (n is not JsonValue v || !v.TryGetValue<JsonElement>(out var e)) return n is JsonValue v2 && v2.TryGetValue<double>(out var d2) ? d2 : null;
        return e.ValueKind == JsonValueKind.Number && e.TryGetDouble(out var d) ? d : null;
    }

    private static (bool Found, JsonNode? Value) At(JsonNode? body, string path)
    {
        var cur = body;
        foreach (var seg in path.Split('.'))
        {
            if (cur is not JsonObject o || !o.ContainsKey(seg)) return (false, null);
            cur = o[seg];
        }
        return (true, cur);
    }

    /// Get-SIProMandatoryText -WhatOnly.
    public static string What(MandatoryControl c)
    {
        var v = c.Value?.ToJsonString() ?? "null";
        return c.Rule switch
        {
            "present" => "it cannot be switched off",
            "equals" => $"'{c.Path}' must stay {v}",
            "atLeast" => $"'{c.Path}' must be at least {v}",
            "above" => $"'{c.Path}' must be more than {v}",
            "contains" => $"'{c.Path}' must keep {v}",
            _ => "",
        };
    }

    /// Test-SIProMandatoryValue.
    public static bool Satisfied(MandatoryControl c, bool found, JsonNode? value)
    {
        switch (c.Rule)
        {
            case "present": return true;
            case "equals": return found && Canon(value) == Canon(c.Value);
            case "atLeast": { var d = Number(value); var b = Number(c.Value); return found && d is not null && b is not null && d >= b; }
            case "above": { var d = Number(value); var b = Number(c.Value); return found && d is not null && b is not null && d > b; }
            case "contains":
                if (!found || value is not JsonArray have) return false;
                var set = have.Select(Canon).ToHashSet(StringComparer.Ordinal);
                return (c.Value as JsonArray ?? new JsonArray()).All(n => set.Contains(Canon(n)));
            default: return false;
        }
    }

    /// The reasons a customer's state of an item is refused because it switches a required part off or weakens it
    /// (empty = accepted). Sends nothing. 'inherit' is always accepted (the shipped item meets every control); an
    /// unreadable body is the item validator's to refuse.
    public IReadOnlyList<string> Check(string kind, string key, string state, string? body)
    {
        var mine = For(kind, key);
        if (mine.Count == 0 || state == ItemOverrideRepository.StateInherit) return Array.Empty<string>();
        if (state == ItemOverrideRepository.StateDisable)
            return mine.Select(c => $"{kind}/{key} is required by SecurityInsight and cannot be switched off" + (c.Reason.Length > 0 ? " -- " + c.Reason : "")).Distinct(StringComparer.Ordinal).ToList();
        JsonNode? o;
        try { o = JsonNode.Parse((body ?? "").TrimStart((char)0xFEFF)); }
        catch (JsonException) { return Array.Empty<string>(); }
        var why = new List<string>();
        foreach (var c in mine)
        {
            if (c.Rule == "present") continue;
            var (found, value) = At(o, c.Path);
            if (!Satisfied(c, found, value)) why.Add($"{kind}/{key} is required by SecurityInsight: {What(c)}" + (c.Reason.Length > 0 ? " -- " + c.Reason : ""));
        }
        return why;
    }

    /// For logs and tests: the number as SecurityInsight writes it.
    public static string Num(double d) => d.ToString(CultureInfo.InvariantCulture);
}
