using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Settings;

/// <summary>
/// A C# port of Test-SISettingValue (engine\pro-settings\SI-Settings.ps1). Returns null when the value fits the
/// setting, else the reason -- the SAME reason text, so the Pro page, the Community page and the PowerShell run-start
/// reader refuse the same values for the same words.
///
/// The value is what ConvertFrom-Json would hand the PowerShell function: a JSON element (null when absent). The
/// PowerShell type rules are reproduced literally, including their sharp edges:
///   - 'int' takes [long]::TryParse([string]$Value): the string "25" is valid, true ("True") and 25.5 are not;
///   - 'number' takes a JSON number, or a string that parses as a number with the INVARIANT culture ("0.01", never
///     "0,01"); NaN and infinity are refused, and so is anything else (a bool, a list, null). min / max are compared as
///     doubles and the reason is written invariant -- ConvertTo-SISettingNumber is the PowerShell side;
///   - every type the switch does not name falls into the DEFAULT branch, which demands TEXT;
///   - PowerShell's -notcontains and -notmatch are case-insensitive, so enum and pattern checks are too.
/// pro-management\tests\fixtures\settings-validation-cases.json holds the cases; Test-ValidationFixtureParity.ps1 runs the
/// same file through the real PowerShell function, so the two cannot drift silently.
/// </summary>
public static class SettingValidator
{
    public static string? Validate(CatalogSetting setting, JsonElement? value)
    {
        JsonElement? v = value is { ValueKind: JsonValueKind.Null or JsonValueKind.Undefined } ? null : value;
        switch (setting.Type)
        {
            case "bool":
                if (v is not { ValueKind: JsonValueKind.True or JsonValueKind.False }) return "must be true or false";
                break;
            case "int":
                if (!long.TryParse(PsString(v), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n)) return "must be a whole number";
                // PowerShell compares against [long]$Setting.min -- a banker's-rounded cast, as Math.Round rounds
                if (setting.Min is { } min && n < (long)Math.Round(min)) return "must be at least " + Fmt(min);
                if (setting.Max is { } max && n > (long)Math.Round(max)) return "must be at most " + Fmt(max);
                break;
            case "number":
                if (ToNumber(v) is not { } d) return "must be a number";
                if (setting.Min is { } nmin && d < nmin) return "must be at least " + Fmt(nmin);
                if (setting.Max is { } nmax && d > nmax) return "must be at most " + Fmt(nmax);
                break;
            case "list":
                if (PsNotNull(v) && v!.Value.ValueKind != JsonValueKind.Array) return "must be a list";
                break;
            case "enum":
                var allowed = setting.Values ?? Array.Empty<string>();
                if (!allowed.Contains(PsString(v), StringComparer.OrdinalIgnoreCase)) return "must be one of: " + string.Join(", ", allowed);
                break;
            default:
                if (PsNotNull(v) && v!.Value.ValueKind != JsonValueKind.String) return "must be text";
                break;
        }
        if (!string.IsNullOrEmpty(setting.Pattern) && PsNotNull(v))
        {
            var s = PsString(v);
            if (s != "" && !Regex.IsMatch(s, setting.Pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)))
                return $"does not match the expected format ({setting.PatternHint})";
        }
        return null;
    }

    /// <summary>A port of ConvertTo-SISettingNumber: a JSON number, or a string parsed with the invariant culture, as a
    /// finite double -- else null (NaN, infinity, a bool, a list, an object, null).</summary>
    public static double? ToNumber(JsonElement? value)
    {
        if (value is not { } v) return null;
        double d;
        switch (v.ValueKind)
        {
            case JsonValueKind.Number:
                if (!v.TryGetDouble(out d)) return null;
                break;
            case JsonValueKind.String:
                if (!double.TryParse(v.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out d)) return null;
                break;
            default:
                return null;
        }
        return double.IsFinite(d) ? d : null;
    }

    /// <summary>A min / max as the reason text shows it: invariant, as PowerShell's [string]::Format(InvariantCulture, ...).</summary>
    internal static string Fmt(double x) => x.ToString(CultureInfo.InvariantCulture);

    /// <summary>PowerShell's <c>$null -ne $Value</c> with $null on the LEFT: a plain null test, so even an empty array is
    /// "not null" (and an empty list given to a text setting is refused, as PowerShell refuses it).</summary>
    internal static bool PsNotNull(JsonElement? value) =>
        value is { } v && v.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined);

    /// <summary>What PowerShell's [string] cast makes of a ConvertFrom-Json value: null -> "", an array -> its items
    /// joined by a space, true -> "True", a number -> its text, an object -> never a valid scalar.</summary>
    internal static string PsString(JsonElement? value)
    {
        if (value is not { } v) return "";
        return v.ValueKind switch
        {
            JsonValueKind.Null or JsonValueKind.Undefined => "",
            JsonValueKind.String => v.GetString() ?? "",
            JsonValueKind.True => "True",
            JsonValueKind.False => "False",
            JsonValueKind.Number => v.GetRawText(),
            JsonValueKind.Array => string.Join(" ", v.EnumerateArray().Select(e => PsString(e))),
            _ => "@{}",
        };
    }
}
