using System.Text;
using System.Text.RegularExpressions;

namespace SI.Management.Core;

/// The ONLY way a caller's value reaches query text. Integers are range-checked; the one free-text input
/// (an asset name or id) must match a safe pattern and is then written as an escaped KQL string literal.
/// Anything else is refused with ArgumentException, never silently trimmed into something different.
public static partial class QueryParameters
{
    public const int MaxTop = 100;
    /// The longest ranking a page may ask for (every exposed asset of one tier, with its estate rank).
    public const int MaxRanked = 5000;
    public const int MaxDays = 365;
    public const int MaxWeeks = 104;
    public const int MaxNameOrIdLength = 400;
    public const int MaxHistoryRows = 200;

    // Letters (any script), digits, and the punctuation real asset names and ids carry: FQDNs (.), ARM paths (/ :),
    // UPNs (@), ExposureGraph child labels "db (server/db)" ((, ), space), GUIDs (-), and _ + #.
    // NOT allowed: quotes, backslash, pipe, semicolon, newline, braces, brackets, angle brackets, $, =, `, %, *.
    [GeneratedRegex(@"^[\p{L}\p{N}][\p{L}\p{N} ._:/@()+#\-]*$", RegexOptions.CultureInvariant)]
    private static partial Regex NameOrIdPattern();

    [GeneratedRegex(@"^[A-Za-z0-9_]{1,128}$", RegexOptions.CultureInvariant)]
    private static partial Regex SettingNamePattern();

    [GeneratedRegex(@"^[A-Za-z0-9.+_\-]{0,32}$", RegexOptions.CultureInvariant)]
    private static partial Regex EditionPattern();

    public static int Top(int top) => Bounded(top, 1, MaxTop, nameof(top));
    public static int Ranked(int max) => Bounded(max, 1, MaxRanked, nameof(max));
    public static int Days(int days) => Bounded(days, 1, MaxDays, nameof(days));
    public static int Weeks(int weeks) => Bounded(weeks, 1, MaxWeeks, nameof(weeks));
    public static int HistoryRows(int rows) => Bounded(rows, 1, MaxHistoryRows, nameof(rows));
    public static int LookbackDays(int days, string name) => Bounded(days, 1, 30, name);

    private static int Bounded(int v, int min, int max, string name)
    {
        if (v < min || v > max)
            throw new ArgumentOutOfRangeException(name, v, $"{name} must be between {min} and {max}.");
        return v;
    }

    /// Validates an asset name or id and returns it trimmed. Throws ArgumentException when it is not safe.
    public static string NameOrId(string? value)
    {
        var v = (value ?? "").Trim();
        if (v.Length == 0) throw new ArgumentException("nameOrId is required.", nameof(value));
        if (v.Length > MaxNameOrIdLength) throw new ArgumentException($"nameOrId is longer than {MaxNameOrIdLength} characters.", nameof(value));
        if (!NameOrIdPattern().IsMatch(v))
            throw new ArgumentException("nameOrId may contain only letters, digits, spaces and . _ : / @ ( ) + # -", nameof(value));
        return v;
    }

    /// A setting name filter (optional). Null/empty = all settings.
    public static string? SettingName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var v = value.Trim();
        if (!SettingNamePattern().IsMatch(v)) throw new ArgumentException("name may contain only letters, digits and _ (max 128).", nameof(value));
        return v;
    }

    /// The configured edition marker (configuration, not user input -- still checked before it reaches a query).
    public static string Edition(string? value)
    {
        var v = value ?? "";
        if (!EditionPattern().IsMatch(v)) throw new InvalidOperationException("Estate:RaEditionSuffix may contain only letters, digits and . + _ -");
        return v;
    }

    /// A KQL double-quoted string literal. Backslash and double quote are escaped and control characters are
    /// refused, so the value can never close the literal -- even if a caller skipped validation.
    public static string KqlString(string value)
    {
        var sb = new StringBuilder(value.Length + 2);
        sb.Append('"');
        foreach (var ch in value)
        {
            switch (ch)
            {
                case '\\': sb.Append(@"\\"); break;
                case '"': sb.Append("\\\""); break;
                default:
                    if (char.IsControl(ch)) throw new ArgumentException("A control character cannot be part of a query literal.", nameof(value));
                    sb.Append(ch);
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }
}
