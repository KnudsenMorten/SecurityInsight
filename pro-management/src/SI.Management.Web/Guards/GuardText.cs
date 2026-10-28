using System.Globalization;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Guards;

/// The three parts a person reads about one guard event, plus what to do (operator 2026-10-05: "i need more context for
/// these things - cause, what to do, consequence?").
/// Operator 2026-10-09 ("nobody understand the context you provide for the guards"): the page reads them as What happened ·
/// Why it held (what it protects you from) · If you release · If you leave it (= Consequence) · What to do.
public sealed record GuardParts(string Kind, string What, string Why, string Consequence, IReadOnlyList<string> Steps, string IfRelease = "");

/// <summary>
/// The catalog's templates (config\guard-catalog.locked.json: what / why / consequence / steps) filled from one event --
/// the SAME rules as the PowerShell side (engine\_shared\SI-Guard.ps1, Format-SIGuardText), so the Guards page, the mail
/// and the report to Invardia say the same words:
///   {held} what was held · {detail} the event's detail · {subject} where · {when} the event's time ·
///   {latest} the newest collection the web app shows (web only) · {v:name} a measured value;
///   {x|text} uses text when x is empty; a [ ... ] part is left out when a placeholder in it is empty.
/// PURE.
/// </summary>
public static partial class GuardText
{
    [GeneratedRegex(@"\{(held|detail|subject|when|latest|v:[A-Za-z0-9]+)(?:\|([^{}]*))?\}", RegexOptions.CultureInvariant)]
    private static partial Regex Placeholder();

    [GeneratedRegex(@"\s?\[([^\[\]]*)\]", RegexOptions.CultureInvariant)]
    private static partial Regex Optional();

    [GeneratedRegex(@"\s{2,}", RegexOptions.CultureInvariant)]
    private static partial Regex Spaces();

    /// The placeholder names a template may use.
    public static IReadOnlyList<string> Names(string template) => Placeholder().Matches(template ?? "").Select(m => m.Groups[1].Value).ToList();

    /// One template filled from <paramref name="fields"/> (a missing or blank value reads empty).
    public static string Fill(string? template, IReadOnlyDictionary<string, string?> fields)
    {
        if (string.IsNullOrEmpty(template)) return "";
        string Sub(string s, ref bool missing)
        {
            var miss = false;
            var r = Placeholder().Replace(s, m =>
            {
                var v = fields.TryGetValue(m.Groups[1].Value, out var x) ? x?.Trim() : null;
                if (!string.IsNullOrEmpty(v)) return v;
                if (m.Groups[2].Success) return m.Groups[2].Value;
                miss = true;
                return "";
            });
            missing |= miss;
            return r;
        }
        var outer = Optional().Replace(template, m =>
        {
            var miss = false;
            var inner = Sub(m.Groups[1].Value, ref miss);
            return miss ? "" : (m.Value.StartsWith(' ') ? " " : "") + inner;
        });
        var none = false;
        return Plurals(Spaces().Replace(Sub(outer, ref none), " ").Trim());
    }

    [GeneratedRegex(@"(?<n>\d[\d,. ']*)\s+(?<w>[A-Za-z-]+)\(s\)", RegexOptions.CultureInvariant)]
    private static partial Regex CountedPlural();
    [GeneratedRegex(@"(?<w>[A-Za-z-]+)\(s\)", RegexOptions.CultureInvariant)]
    private static partial Regex BarePlural();

    /// Operator 2026-10-09 ("no (s) anywhere"): "1 job(s)" -> "1 job", "2 job(s)" -> "2 jobs", "report(s)" -> "reports".
    public static string Plurals(string text)
    {
        if (string.IsNullOrEmpty(text) || !text.Contains("(s)", StringComparison.Ordinal)) return text;
        static string Many(string w) =>
            w.EndsWith('y') && w.Length > 1 && "aeiou".IndexOf(char.ToLowerInvariant(w[^2])) < 0 ? w[..^1] + "ies"
            : w.EndsWith('s') || w.EndsWith('x') || w.EndsWith("ch", StringComparison.Ordinal) || w.EndsWith("sh", StringComparison.Ordinal) ? w + "es" : w + "s";
        var t = CountedPlural().Replace(text, m =>
        {
            var digits = new string(m.Groups["n"].Value.Where(char.IsDigit).ToArray());
            var one = digits.TrimStart('0') == "1" && !m.Groups["n"].Value.Contains('.') ;
            return m.Groups["n"].Value + " " + (one ? m.Groups["w"].Value : Many(m.Groups["w"].Value));
        });
        return BarePlural().Replace(t, m => Many(m.Groups["w"].Value));
    }

    /// The placeholder values of one event. <paramref name="latest"/>: the newest collection the web app shows (text).
    public static Dictionary<string, string?> Fields(GuardRow row, string? latest = null, CultureInfo? culture = null)
    {
        var c = culture ?? SI.Management.Core.ProData.ScoreFormat.Culture;
        static string N(double v, CultureInfo c) => Math.Abs(v % 1) < 1e-9 ? v.ToString("N0", c) : v.ToString("#,0.##", c);
        var f = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["held"] = row.Held > 0 ? row.Held.ToString("N0", c) : null,
            ["detail"] = row.Detail,
            ["subject"] = row.Subject,
            ["when"] = row.TsUtc is { } t ? t.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC" : null,
            ["latest"] = latest,
        };
        foreach (var v in row.Values()) if (v.Measured is { } m) f["v:" + v.Name] = N(m, c);
        return f;
    }

    /// The three parts + steps of one event. An older catalog entry without them falls back to its action as one step.
    public static GuardParts Parts(GuardCatalog.Entry? entry, GuardRow row, string? latest = null, CultureInfo? culture = null)
    {
        var fields = Fields(row, latest, culture);
        // owner 2026-10-17 (guards heal themselves): a clear is not a trip -- it says what closed the guard, nothing to do
        if (row.IsTaken)
            return new GuardParts(GuardKinds.Review, (string.IsNullOrWhiteSpace(entry?.Title) ? row.GuardId : entry!.Title) + " -- " + (row.Detail ?? "taken as the new level"), "",
                "This is NOT back to normal: the lower level is now taken as the truth, so what the source no longer lists is treated as gone.",
                ["Check the source if this drop is not expected (for example a lost permission, a changed scope or a failed sign-in).", "Acknowledge this when you have checked it."], "");
        if (row.IsClear)
            return new GuardParts(GuardKinds.Info, (string.IsNullOrWhiteSpace(entry?.Title) ? row.GuardId : entry!.Title) + " -- " + (row.Detail ?? "back to normal"), "",
                "Nothing is held any more because of this check.", ["Nothing to do."], "");
        if (entry is null)
            return new GuardParts(GuardKinds.Info, row.Detail ?? "", "", "", string.IsNullOrWhiteSpace(row.ActionText) ? [] : [row.ActionText!]);
        var steps = entry.StepList.Select(s => Fill(s, fields)).Where(s => s.Length > 0).ToList();
        if (steps.Count == 0 && !string.IsNullOrWhiteSpace(entry.Action)) steps.Add(entry.Action);
        var what = Fill(entry.What, fields);
        return new GuardParts(entry.Kind, what.Length > 0 ? what : row.Detail ?? "", Fill(entry.Why, fields), Fill(entry.Consequence, fields), steps, Fill(entry.IfRelease, fields));
    }

    [GeneratedRegex(@"\{detail(?:\|[^{}]*)?\}", RegexOptions.CultureInvariant)]
    private static partial Regex DetailPart();

    /// What a guard protects you from: its 'why' without the event's own words (the Control panel, where no event is).
    public static string Protection(GuardCatalog.Entry g) => Fill(DetailPart().Replace(g.Why ?? "", ""), new Dictionary<string, string?>());

    /// The severity chip: "Critical" | "Warning" | "Info" (a warning of a guard with nothing to do reads Info).
    public static string SeverityWord(string severity, string kind) =>
        string.Equals(severity, "critical", StringComparison.OrdinalIgnoreCase) ? "Critical" : kind == GuardKinds.Info ? "Info" : "Warning";
}
