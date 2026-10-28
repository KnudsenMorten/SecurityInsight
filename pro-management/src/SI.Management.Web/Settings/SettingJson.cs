using System.Globalization;
using System.Text;
using System.Text.Json;

namespace SI.Management.Web.Settings;

/// The value side of a setting: form text -> a JSON value, and a JSON value -> the ValueJson text stored in cfg.Setting.
public static class SettingJson
{
    /// <summary>
    /// What an edit form posts, as the JSON value the writer validates and stores. Mirrors Invoke-SISettingsPlan's
    /// normalisation: an int or a number typed as text becomes a JSON number when it parses (a number: invariant culture
    /// only; otherwise it stays text, so the validator gives its reason); a list is one item per line; every other type is text.
    /// </summary>
    public static JsonElement FromForm(CatalogSetting setting, string? text)
    {
        text ??= "";
        switch (setting.Type)
        {
            case "bool":
                var t = text.Trim();
                if (t.Equals("true", StringComparison.OrdinalIgnoreCase)) return Parse("true");
                if (t.Equals("false", StringComparison.OrdinalIgnoreCase)) return Parse("false");
                return Json(text);
            case "int":
                return long.TryParse(text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)
                    ? Parse(n.ToString(CultureInfo.InvariantCulture)) : Json(text);
            case "number":
                // a number typed with the invariant point becomes a JSON number, written round-trip and invariant; any
                // other text ("0,01", "cheap") stays text, so the validator gives its reason
                return SettingValidator.ToNumber(Json(text)) is { } d
                    ? Parse(d.ToString("R", CultureInfo.InvariantCulture)) : Json(text);
            case "list":
                var items = text.Split('\n').Select(l => l.Trim('\r', ' ', '\t')).Where(l => l.Length > 0).ToArray();
                return JsonSerializer.SerializeToElement(items);
            default:
                return Json(text);
        }
    }

    /// <summary>A stored ValueJson back to the text an edit form shows (a list: one item per line).</summary>
    public static string ToFormText(string? valueJson)
    {
        if (string.IsNullOrEmpty(valueJson)) return "";
        try
        {
            using var doc = JsonDocument.Parse(valueJson);
            var e = doc.RootElement;
            return e.ValueKind switch
            {
                JsonValueKind.String => e.GetString() ?? "",
                JsonValueKind.Array => string.Join("\n", e.EnumerateArray().Select(x => SettingValidator.PsString(x))),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Null => "",
                _ => e.GetRawText(),
            };
        }
        catch (JsonException) { return valueJson; }
    }

    /// <summary>
    /// A port of ConvertTo-SIJsonText: stable, readable JSON (2-space indent, a list ALWAYS an array, strings escaped the
    /// same way), so a row written by this page reads exactly like one written by Set-SIProSetting.
    /// </summary>
    public static string ToStoredText(JsonElement value, int level = 0)
    {
        var pad = new string(' ', 2 * level);
        var pad1 = new string(' ', 2 * (level + 1));
        switch (value.ValueKind)
        {
            case JsonValueKind.Null:
            case JsonValueKind.Undefined: return "null";
            case JsonValueKind.True: return "true";
            case JsonValueKind.False: return "false";
            case JsonValueKind.Number: return value.GetRawText();
            case JsonValueKind.String: return Escape(value.GetString() ?? "");
            case JsonValueKind.Object:
                var props = value.EnumerateObject().ToList();
                if (props.Count == 0) return "{}";
                return "{\n" + string.Join(",\n", props.Select(p => pad1 + Escape(p.Name) + ": " + ToStoredText(p.Value, level + 1))) + "\n" + pad + "}";
            case JsonValueKind.Array:
                var items = value.EnumerateArray().ToList();
                if (items.Count == 0) return "[]";
                return "[\n" + string.Join(",\n", items.Select(i => pad1 + ToStoredText(i, level + 1))) + "\n" + pad + "]";
            default: return value.GetRawText();
        }
    }

    private static string Escape(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (var ch in s)
        {
            switch (ch)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (ch < 32) sb.Append("\\u").Append(((int)ch).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(ch);
                    break;
            }
        }
        return sb.Append('"').ToString();
    }

    private static JsonElement Json(string s) => JsonSerializer.SerializeToElement(s);
    private static JsonElement Parse(string json) { using var d = JsonDocument.Parse(json); return d.RootElement.Clone(); }
}
