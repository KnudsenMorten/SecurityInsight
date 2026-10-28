using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using SI.Management.Core;

namespace SI.Management.Web.ChatView;

/// <summary>
/// Turns a chat answer (model text) into SAFE HTML for the answer bubble (operator, 2026-10-04: "answer must be much
/// easier to see ... highlight important things like asset name, numbers").
/// 🔒 SAFE BY CONSTRUCTION: the text is never passed through as HTML. Every character of the answer is escaped; the only
/// markup that comes out is what this class writes itself, from a whitelist: paragraphs, line breaks, bullet lists,
/// **bold**, `inline code`, and the highlight spans/links below. A model (or a tool result it repeats) that writes
/// &lt;script&gt;, an &lt;img onerror&gt;, a markdown link or image gets that text shown, escaped -- never rendered.
/// The post-pass highlights, even where the model did not mark anything:
///   - the asset names the tool results carried (a link to the asset page when the result had the asset key);
///   - numbers -- re-written in the viewer's number format (BRAND-2.6: "2293" -> "2.293" for da-DK); never numbers inside
///     a CVE id, a date, a time, a version, an IP address or an identifier (MGMT1, KB5012345);
///   - severities (the badge colours) and "Tier N" (the tier colour).
/// Years (1900-2099 written without separators) are highlighted but not regrouped: "2026" must not read "2.026".
/// </summary>
public static class ChatAnswerRenderer
{
    public const int MaxChars = 20_000;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(1);

    private static readonly Regex Bullet = new(@"^\s*[-*•]\s+(?<t>.*)$", RegexOptions.CultureInvariant, Timeout);
    private static readonly Regex Heading = new(@"^\s*#{1,6}\s+(?<t>.*)$", RegexOptions.CultureInvariant, Timeout);
    private static readonly Regex Markup = new(@"\*\*(?<b>(?:(?!\*\*).)+?)\*\*|`(?<c>[^`\n]+)`", RegexOptions.CultureInvariant, Timeout);

    private const string Entities =
        @"(?<cve>\b(?:CVE|cve)-\d{4}-\d{4,7}\b)" +
        @"|(?<date>\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?Z?)?)" +
        @"|(?<ver>(?<![\w.])v?\d+(?:\.\d+){2,}(?![\w.]*\d)|\bv\d+(?:\.\d+)?\b)" +
        @"|(?<tier>\b[Tt]ier[ -]?(?<tn>[0-9])\b)" +
        @"|(?<sev>\b(?:Very High|Medium-High|High|Medium|Low|Critical|Informational)\b)" +
        @"|(?<num>(?<![\w.,\-/:#])(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?(?![\w\-/:]|[.,]\d))";
    private static readonly Regex NoAssets = new(Entities, RegexOptions.CultureInvariant, Timeout);

    /// The answer as HTML. Assets: the names (and keys) the tool results carried. Culture: the viewer's number format.
    public static string Render(string? text, IReadOnlyList<ChatAsset>? assets, CultureInfo culture)
    {
        var src = (text ?? "").Replace("\r\n", "\n").Replace('\r', '\n');
        if (src.Length > MaxChars) src = src[..MaxChars] + "...";
        var ctx = new Ctx(assets, culture);
        var sb = new StringBuilder();
        var para = new List<string>();
        var list = new List<string>();

        void FlushPara()
        {
            if (para.Count == 0) return;
            sb.Append("<p>").Append(string.Join("<br>", para)).Append("</p>");
            para.Clear();
        }
        void FlushList()
        {
            if (list.Count == 0) return;
            sb.Append("<ul>");
            foreach (var li in list) sb.Append("<li>").Append(li).Append("</li>");
            sb.Append("</ul>");
            list.Clear();
        }

        foreach (var raw in src.Split('\n'))
        {
            if (string.IsNullOrWhiteSpace(raw)) { FlushPara(); FlushList(); continue; }
            if (Bullet.Match(raw) is { Success: true } b) { FlushPara(); list.Add(Inline(b.Groups["t"].Value, ctx)); continue; }
            FlushList();
            if (Heading.Match(raw) is { Success: true } h) { FlushPara(); para.Add("<strong>" + Inline(h.Groups["t"].Value, ctx) + "</strong>"); FlushPara(); continue; }
            para.Add(Inline(raw.Trim(), ctx));
        }
        FlushPara(); FlushList();
        return sb.ToString();
    }

    private sealed class Ctx
    {
        public readonly CultureInfo Culture;
        public readonly Dictionary<string, ChatAsset> Assets;
        public readonly Regex Entities;

        public Ctx(IReadOnlyList<ChatAsset>? assets, CultureInfo culture)
        {
            Culture = culture;
            Assets = new(StringComparer.OrdinalIgnoreCase);
            foreach (var a in assets ?? Array.Empty<ChatAsset>())
                if (a is not null && !string.IsNullOrWhiteSpace(a.Name) && a.Name.Trim().Length >= 2 && Assets.Count < ChatService.MaxAssets)
                    Assets.TryAdd(a.Name.Trim(), a);
            Entities = Assets.Count == 0 ? NoAssets : new Regex(
                @"(?<asset>(?<![\w-])(?i:" + string.Join("|", Assets.Keys.OrderByDescending(k => k.Length).Select(Regex.Escape)) + @")(?![\w-]))|" + ChatAnswerRenderer.Entities,
                RegexOptions.CultureInvariant, Timeout);
        }
    }

    /// One line: **bold** and `code` (the only inline markup), everything else escaped and highlighted.
    private static string Inline(string line, Ctx ctx)
    {
        var sb = new StringBuilder();
        var at = 0;
        foreach (Match m in Markup.Matches(line))
        {
            sb.Append(Highlight(line[at..m.Index], ctx));
            if (m.Groups["c"].Success) sb.Append("<code class=\"chat-code\">").Append(Enc(m.Groups["c"].Value)).Append("</code>");
            else sb.Append(Bold(m.Groups["b"].Value, ctx));
            at = m.Index + m.Length;
        }
        sb.Append(Highlight(line[at..], ctx));
        return sb.ToString();
    }

    /// Bold text: an asset name on its own becomes the asset (a link when it has a key); anything else is emphasised,
    /// with `code` and the highlights allowed inside (never another bold).
    private static string Bold(string inner, Ctx ctx)
    {
        var t = inner.Trim();
        if (ctx.Assets.TryGetValue(t, out var asset)) return Asset(inner, asset);
        var sb = new StringBuilder("<strong class=\"chat-em\">");
        var at = 0;
        foreach (Match m in Markup.Matches(inner))
        {
            if (!m.Groups["c"].Success) continue;
            sb.Append(Highlight(inner[at..m.Index], ctx)).Append("<code class=\"chat-code\">").Append(Enc(m.Groups["c"].Value)).Append("</code>");
            at = m.Index + m.Length;
        }
        sb.Append(Highlight(inner[at..], ctx)).Append("</strong>");
        return sb.ToString();
    }

    private static string Asset(string shown, ChatAsset a) =>
        a.Key is { Length: > 0 } key
            ? "<a class=\"chat-asset\" href=\"" + Enc("/Collection/Asset?key=" + Uri.EscapeDataString(key)) + "\">" + Enc(shown) + "</a>"
            : "<strong class=\"chat-asset\">" + Enc(shown) + "</strong>";

    /// Plain text: escaped, with the entities marked.
    private static string Highlight(string s, Ctx ctx)
    {
        if (s.Length == 0) return "";
        var sb = new StringBuilder();
        var at = 0;
        foreach (Match m in ctx.Entities.Matches(s))
        {
            sb.Append(Enc(s[at..m.Index]));
            var v = m.Value;
            if (m.Groups["asset"].Success && ctx.Assets.TryGetValue(v, out var a)) sb.Append(Asset(v, a));
            else if (m.Groups["cve"].Success) sb.Append("<code class=\"chat-code\">").Append(Enc(v)).Append("</code>");
            else if (m.Groups["date"].Success || m.Groups["ver"].Success) sb.Append(Enc(v));
            else if (m.Groups["tier"].Success) sb.Append("<span class=\"chat-tier t").Append(m.Groups["tn"].Value).Append("\">").Append(Enc(v)).Append("</span>");
            else if (m.Groups["sev"].Success) sb.Append("<span class=\"sev ").Append(SevClass(v)).Append("\">").Append(Enc(v)).Append("</span>");
            else if (m.Groups["num"].Success) sb.Append("<span class=\"chat-num\">").Append(Enc(Number(v, ctx.Culture))).Append("</span>");
            else sb.Append(Enc(v));
            at = m.Index + m.Length;
        }
        sb.Append(Enc(s[at..]));
        return sb.ToString();
    }

    internal static string SevClass(string severity) => severity switch
    {
        "Very High" or "Critical" => "sev-vh",
        "High" => "sev-h",
        "Medium-High" => "sev-mh",
        "Medium" => "sev-m",
        _ => "sev-l",
    };

    /// A number as the model wrote it (invariant: "2293", "2,293", "12.5") in the viewer's format. A year is left as is.
    internal static string Number(string invariant, CultureInfo culture)
    {
        var plain = invariant.Replace(",", "", StringComparison.Ordinal);
        if (!decimal.TryParse(plain, NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var d)) return invariant;
        var dot = plain.IndexOf('.', StringComparison.Ordinal);
        if (dot < 0 && !invariant.Contains(',') && plain.Length == 4 && d is >= 1900 and <= 2099) return invariant;
        var decimals = dot < 0 ? 0 : Math.Min(plain.Length - dot - 1, 6);
        return d.ToString("N" + decimals.ToString(CultureInfo.InvariantCulture), culture);
    }

    /// HTML escaping for text AND double/single-quoted attribute values.
    internal static string Enc(string s)
    {
        if (s.Length == 0) return s;
        var sb = new StringBuilder(s.Length + 16);
        foreach (var ch in s)
        {
            sb.Append(ch switch
            {
                '&' => "&amp;",
                '<' => "&lt;",
                '>' => "&gt;",
                '"' => "&quot;",
                '\'' => "&#39;",
                _ => ch.ToString(),
            });
        }
        return sb.ToString();
    }
}
