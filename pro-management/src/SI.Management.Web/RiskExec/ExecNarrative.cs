using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace SI.Management.Web.RiskExec;

/// <summary>
/// The AI-written analysis of the Risk Analysis mail, rendered for the executive view (#288) the way the mail renders it
/// (the engine's _MdToHtml): ## and ### headings, bullets and nested bullets, **bold**, _italic_, [label](https://...)
/// links and bare https links. 🔒 SAFE BY CONSTRUCTION: every character of the text is HTML-escaped first; the only
/// markup that comes out is what this class writes, and a link is only ever an http(s) URL opened in a new tab.
///
/// The mail's "## Top N risky assets" section is the AI copying the engine's Top-50 list into prose. The page shows that
/// list as a table from the SAME numbers (so each asset can link to its page); <see cref="Sections"/> lets the page put
/// the table where the section was.
/// </summary>
public static class ExecNarrative
{
    private static readonly TimeSpan T = TimeSpan.FromSeconds(1);
    private static readonly Regex TopAssets = new(@"^Top\s+\d+\s+risky\s+assets\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, T);
    private static readonly Regex Link = new(@"\[([^\]\n]+)\]\((https?://[^\s)]+)\)", RegexOptions.CultureInvariant, T);
    private static readonly Regex Bare = new(@"(?<![""'>=])(https?://[^\s<>""`)\]]+)", RegexOptions.CultureInvariant, T);
    private static readonly Regex Bold = new(@"\*\*([^\*\n]+?)\*\*", RegexOptions.CultureInvariant, T);
    private static readonly Regex Italic = new(@"(^|\s)_([^_\n]+?)_(?=\s|[\.,;:\)\]]|$)", RegexOptions.CultureInvariant, T);

    public sealed record Section(string? Heading, string Body)
    {
        /// The section the page replaces with the linked Top-50 table.
        public bool IsTopAssets => Heading is not null && TopAssets.IsMatch(Heading);
    }

    /// The text split at its "## " headings (text before the first heading is a section without one).
    public static IReadOnlyList<Section> Sections(string? markdown)
    {
        var list = new List<Section>();
        string? heading = null; var body = new StringBuilder();
        foreach (var raw in (markdown ?? "").Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            var line = raw.TrimEnd();
            if (line.StartsWith("## ", StringComparison.Ordinal) && !line.StartsWith("### ", StringComparison.Ordinal))
            {
                if (heading is not null || body.ToString().Trim().Length > 0) list.Add(new Section(heading, body.ToString().Trim('\n')));
                heading = line[3..].Trim(); body.Clear();
                continue;
            }
            body.Append(raw).Append('\n');
        }
        if (heading is not null || body.ToString().Trim().Length > 0) list.Add(new Section(heading, body.ToString().Trim('\n')));
        return list;
    }

    /// One block of the text as safe HTML.
    public static string ToHtml(string? markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown)) return "";
        var sb = new StringBuilder();
        var inList = false; var inSub = false;
        void Close() { if (inSub) { sb.Append("</ul></li>"); inSub = false; } if (inList) { sb.Append("</ul>"); inList = false; } }
        foreach (var raw in markdown.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
        {
            var line = raw.TrimEnd();
            Match m;
            if ((m = Regex.Match(line, @"^(\s{2,})-\s+(.+)$", RegexOptions.None, T)).Success)
            {
                if (!inList) { sb.Append("<ul>"); inList = true; }
                if (!inSub) { sb.Append("<li class=\"sub\"><ul>"); inSub = true; }
                sb.Append("<li>").Append(Inline(m.Groups[2].Value)).Append("</li>");
                continue;
            }
            if ((m = Regex.Match(line, @"^-\s+(.+)$", RegexOptions.None, T)).Success)
            {
                if (inSub) { sb.Append("</ul></li>"); inSub = false; }
                if (!inList) { sb.Append("<ul>"); inList = true; }
                sb.Append("<li>").Append(Inline(m.Groups[1].Value)).Append("</li>");
                continue;
            }
            Close();
            if ((m = Regex.Match(line, @"^###\s+(.+)$", RegexOptions.None, T)).Success) { sb.Append("<h4>").Append(Inline(m.Groups[1].Value)).Append("</h4>"); continue; }
            if ((m = Regex.Match(line, @"^##\s+(.+)$", RegexOptions.None, T)).Success) { sb.Append("<h3>").Append(Inline(m.Groups[1].Value)).Append("</h3>"); continue; }
            if (string.IsNullOrWhiteSpace(line)) continue;
            sb.Append("<p>").Append(Inline(line)).Append("</p>");
        }
        Close();
        return sb.ToString();
    }

    private static string Inline(string text)
    {
        var s = WebUtility.HtmlEncode(text);
        // links first (on the escaped text: an ampersand in a URL is &amp;, which is what an href wants)
        s = Link.Replace(s, m => $"<a href=\"{m.Groups[2].Value.Replace("\"", "&quot;")}\" target=\"_blank\" rel=\"noopener noreferrer\">{m.Groups[1].Value}</a>");
        s = Bare.Replace(s, m => $"<a href=\"{m.Groups[1].Value}\" target=\"_blank\" rel=\"noopener noreferrer\">{m.Groups[1].Value}</a>");
        s = Bold.Replace(s, "<strong>$1</strong>");
        s = Italic.Replace(s, "$1<em>$2</em>");
        return s;
    }
}
