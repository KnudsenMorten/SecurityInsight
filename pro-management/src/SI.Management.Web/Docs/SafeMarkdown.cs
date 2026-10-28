using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Docs;

/// One heading of a rendered page: its level (1-4), its text and the anchor (id) the page gives it.
public sealed record DocHeading(int Level, string Text, string Anchor);

/// <summary>
/// #679: the shipped documentation pages, Markdown -> HTML, SAFE BY CONSTRUCTION. Every character of the source is
/// HTML-encoded; the only markup in the result is the small set of tags this class writes itself (headings, paragraphs,
/// lists, tables, code, quotes, emphasis, links, images). So:
///   * raw HTML in a page (&lt;script&gt;, &lt;img onerror&gt;, &lt;iframe&gt;) is shown as text, never run;
///   * a link is kept only when it is http(s) / mailto (opens outside, rel="noopener noreferrer") or a page of the shipped
///     documentation that exists (with its anchor) -- javascript:, data: and a page that is not shipped become plain text,
///     so there is never a dead link;
///   * an image is shown only when it is one of the shipped images (served by the web app itself); an external image is
///     never loaded -- the page makes no outbound call.
/// Not a full CommonMark implementation: the subset the documentation pages use.
/// </summary>
public sealed class SafeMarkdown
{
    /// Resolves a link target inside the documentation ("guards", "guards#acknowledge", "#acknowledge") to the web app's
    /// URL, or null when that page / anchor is not shipped. The second argument is the page being rendered.
    private readonly Func<string, string?> _resolveLink;
    /// Resolves an image source ("images/settings-cards.png") to the web app's URL, or null when it is not shipped.
    private readonly Func<string, string?> _resolveImage;
    private readonly List<DocHeading> _headings = new();
    private readonly Dictionary<string, int> _anchors = new(StringComparer.Ordinal);

    private SafeMarkdown(Func<string, string?> resolveLink, Func<string, string?> resolveImage)
    { _resolveLink = resolveLink; _resolveImage = resolveImage; }

    /// Renders <paramref name="markdown"/>; returns the HTML and the page's headings with their anchors.
    public static (string Html, IReadOnlyList<DocHeading> Headings) Render(string markdown, Func<string, string?>? resolveLink = null, Func<string, string?>? resolveImage = null)
    {
        var md = new SafeMarkdown(resolveLink ?? (_ => null), resolveImage ?? (_ => null));
        var lines = (markdown ?? "").Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');
        var sb = new StringBuilder();
        md.Blocks(lines, sb);
        return (sb.ToString(), md._headings);
    }

    /// The headings and their anchors only (the same anchors <see cref="Render"/> gives them).
    public static IReadOnlyList<DocHeading> Headings(string markdown) => Render(markdown).Headings;

    /// GitHub's anchor of a heading: lower case, punctuation dropped (except '-' and '_'), each space a '-'.
    /// "Licence &amp; updates" -> "licence--updates"; "1. The SQL hand-off (default)" -> "1-the-sql-hand-off-default".
    public static string Slug(string text)
    {
        var sb = new StringBuilder();
        foreach (var ch in (text ?? "").Trim().ToLowerInvariant())
        {
            if (char.IsLetterOrDigit(ch) || ch == '-' || ch == '_') sb.Append(ch);
            else if (ch == ' ') sb.Append('-');
        }
        return sb.ToString();
    }

    /// Markdown inline text -> plain words (for anchors and search): emphasis, code ticks and link targets dropped.
    public static string Plain(string inline)
    {
        var s = Regex.Replace(inline ?? "", @"!\[([^\]]*)\]\([^)]*\)", "$1");
        s = Regex.Replace(s, @"\[([^\]]*)\]\([^)]*\)", "$1");
        s = Regex.Replace(s, @"(\*\*|__|\*|`)", "");
        s = Regex.Replace(s, @"(?<![A-Za-z0-9])_(?=\S)|(?<=\S)_(?![A-Za-z0-9])", "");
        s = Regex.Replace(s, @"\\([\\`*_{}\[\]()#+\-.!|>~])", "$1");
        return s.Trim();
    }

    private static string E(string s) => WebUtility.HtmlEncode(s);

    // ------------------------------------------------------------------------------------------------- blocks
    private static readonly Regex Fence = new(@"^\s{0,3}(```|~~~)", RegexOptions.Compiled);
    private static readonly Regex HeadingRx = new(@"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$", RegexOptions.Compiled);
    private static readonly Regex Bullet = new(@"^(\s{0,3})([-*+])\s+(.*)$", RegexOptions.Compiled);
    private static readonly Regex Ordered = new(@"^(\s{0,3})(\d{1,9})[.)]\s+(.*)$", RegexOptions.Compiled);
    private static readonly Regex Rule = new(@"^\s{0,3}([-*_])(\s*\1){2,}\s*$", RegexOptions.Compiled);
    private static readonly Regex TableSep = new(@"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$", RegexOptions.Compiled);

    private void Blocks(IReadOnlyList<string> lines, StringBuilder sb)
    {
        var i = 0;
        while (i < lines.Count)
        {
            var line = lines[i];
            if (string.IsNullOrWhiteSpace(line)) { i++; continue; }

            // fenced code: kept exactly, encoded
            var f = Fence.Match(line);
            if (f.Success)
            {
                var marker = f.Groups[1].Value;
                var indent = line.Length - line.TrimStart().Length;
                var code = new List<string>();
                i++;
                while (i < lines.Count && !lines[i].TrimStart().StartsWith(marker, StringComparison.Ordinal)) { code.Add(Dedent(lines[i], indent)); i++; }
                i++;   // the closing fence (or the end)
                sb.Append("<pre><code>").Append(E(string.Join("\n", code))).Append("</code></pre>\n");
                continue;
            }

            var h = HeadingRx.Match(line);
            if (h.Success)
            {
                var level = Math.Min(h.Groups[1].Value.Length, 4);
                var text = h.Groups[2].Value;
                var anchor = UniqueAnchor(Slug(Plain(text)));
                _headings.Add(new DocHeading(level, Plain(text), anchor));
                sb.Append("<h").Append(level).Append(" id=\"").Append(E(anchor)).Append("\">").Append(Inline(text)).Append("</h").Append(level).Append(">\n");
                i++; continue;
            }

            if (Rule.IsMatch(line)) { sb.Append("<hr />\n"); i++; continue; }

            // a table: a row of cells, then the separator row
            if (line.Contains('|') && i + 1 < lines.Count && TableSep.IsMatch(lines[i + 1]))
            {
                var head = Cells(line);
                sb.Append("<div class=\"doc-table\"><table><thead><tr>");
                foreach (var c in head) sb.Append("<th>").Append(Inline(c)).Append("</th>");
                sb.Append("</tr></thead><tbody>\n");
                i += 2;
                while (i < lines.Count && !string.IsNullOrWhiteSpace(lines[i]) && lines[i].Contains('|'))
                {
                    var cells = Cells(lines[i]);
                    sb.Append("<tr>");
                    for (var c = 0; c < head.Count; c++) sb.Append("<td>").Append(c < cells.Count ? Inline(cells[c]) : "").Append("</td>");
                    sb.Append("</tr>\n");
                    i++;
                }
                sb.Append("</tbody></table></div>\n");
                continue;
            }

            // a quote: its lines without the '>' are blocks of their own
            if (line.TrimStart().StartsWith('>'))
            {
                var inner = new List<string>();
                while (i < lines.Count && lines[i].TrimStart().StartsWith('>'))
                {
                    var t = lines[i].TrimStart()[1..];
                    inner.Add(t.StartsWith(' ') ? t[1..] : t);
                    i++;
                }
                sb.Append("<blockquote>\n");
                Blocks(inner, sb);
                sb.Append("</blockquote>\n");
                continue;
            }

            var b = Bullet.Match(line);
            var o = Ordered.Match(line);
            if (b.Success || o.Success)
            {
                i = List(lines, i, o.Success && !b.Success, sb);
                continue;
            }

            // a paragraph: until a blank line or the start of another block
            var para = new List<string> { line.Trim() };
            i++;
            while (i < lines.Count && !string.IsNullOrWhiteSpace(lines[i]) && !StartsBlock(lines, i)) { para.Add(lines[i].Trim()); i++; }
            sb.Append("<p>").Append(Inline(string.Join(" ", para))).Append("</p>\n");
        }
    }

    private static bool StartsBlock(IReadOnlyList<string> lines, int i)
    {
        var l = lines[i];
        return Fence.IsMatch(l) || HeadingRx.IsMatch(l) || Rule.IsMatch(l) || l.TrimStart().StartsWith('>') || Bullet.IsMatch(l) || Ordered.IsMatch(l)
            || (l.Contains('|') && i + 1 < lines.Count && TableSep.IsMatch(lines[i + 1]));
    }

    /// One list (ordered or not) from line <paramref name="i"/>; each item's own lines (its first line, the lines indented
    /// under it, a blank line between items) are rendered as blocks of their own -- so code, a table or a list inside an
    /// item works. Returns the line after the list.
    private int List(IReadOnlyList<string> lines, int i, bool ordered, StringBuilder sb)
    {
        var first = ordered ? Ordered.Match(lines[i]) : Bullet.Match(lines[i]);
        var baseIndent = first.Groups[1].Value.Length;
        var start = ordered && int.TryParse(first.Groups[2].Value, out var n) ? n : 1;
        sb.Append(ordered ? (start != 1 ? $"<ol start=\"{start}\">" : "<ol>") : "<ul>").Append('\n');
        while (i < lines.Count)
        {
            var m = ordered ? Ordered.Match(lines[i]) : Bullet.Match(lines[i]);
            if (!m.Success || m.Groups[1].Value.Length != baseIndent) break;
            var contentIndent = lines[i].Length - m.Groups[3].Value.Length;
            var item = new List<string> { m.Groups[3].Value };
            i++;
            while (i < lines.Count)
            {
                var l = lines[i];
                if (string.IsNullOrWhiteSpace(l))
                {
                    // a blank line belongs to the item when the next text line is indented under it
                    var k = i + 1;
                    while (k < lines.Count && string.IsNullOrWhiteSpace(lines[k])) k++;
                    if (k < lines.Count && Indent(lines[k]) >= Math.Min(contentIndent, baseIndent + 2)) { item.Add(""); i++; continue; }
                    break;
                }
                var ind = Indent(l);
                if (ind <= baseIndent && (Bullet.IsMatch(l) || Ordered.IsMatch(l))) break;   // the next item (or another list)
                if (ind < Math.Min(contentIndent, baseIndent + 2) && StartsBlock(lines, i)) break;
                item.Add(Dedent(l, Math.Min(ind, contentIndent)));
                i++;
            }
            var inner = new StringBuilder();
            Blocks(item, inner);
            var html = inner.ToString();
            // a one-paragraph item shows without its <p>
            if (html.StartsWith("<p>", StringComparison.Ordinal) && html.IndexOf("<p>", 3, StringComparison.Ordinal) < 0 && html.EndsWith("</p>\n", StringComparison.Ordinal))
                html = html[3..^5];
            sb.Append("<li>").Append(html.TrimEnd('\n')).Append("</li>\n");
            // a blank line between two items of the same list
            var j = i;
            while (j < lines.Count && string.IsNullOrWhiteSpace(lines[j])) j++;
            if (j > i && j < lines.Count && (ordered ? Ordered.Match(lines[j]) : Bullet.Match(lines[j])) is { Success: true } nx && nx.Groups[1].Value.Length == baseIndent) i = j;
        }
        sb.Append(ordered ? "</ol>" : "</ul>").Append('\n');
        return i;
    }

    private static int Indent(string l) => l.Length - l.TrimStart().Length;

    private static string Dedent(string l, int n)
    {
        var k = 0;
        while (k < n && k < l.Length && l[k] == ' ') k++;
        return l[k..];
    }

    private static List<string> Cells(string row)
    {
        var t = row.Trim();
        if (t.StartsWith('|')) t = t[1..];
        if (t.EndsWith('|') && !t.EndsWith("\\|", StringComparison.Ordinal)) t = t[..^1];
        var cells = new List<string>();
        var cur = new StringBuilder();
        var inCode = false;
        for (var k = 0; k < t.Length; k++)
        {
            var ch = t[k];
            if (ch == '\\' && k + 1 < t.Length && t[k + 1] == '|') { cur.Append('|'); k++; continue; }
            if (ch == '`') inCode = !inCode;
            if (ch == '|' && !inCode) { cells.Add(cur.ToString().Trim()); cur.Clear(); continue; }
            cur.Append(ch);
        }
        cells.Add(cur.ToString().Trim());
        return cells;
    }

    private string UniqueAnchor(string slug)
    {
        if (slug.Length == 0) slug = "section";
        if (!_anchors.TryGetValue(slug, out var n)) { _anchors[slug] = 1; return slug; }
        _anchors[slug] = n + 1;
        return slug + "-" + n;
    }

    // ------------------------------------------------------------------------------------------------- inline
    private static bool IsPunct(char c) => "\\`*_{}[]()#+-.!|>~<\"'".IndexOf(c) >= 0;

    /// One line of inline Markdown -> encoded HTML with the inline tags this class writes.
    public string Inline(string s)
    {
        var sb = new StringBuilder();
        var i = 0;
        while (i < s.Length)
        {
            var c = s[i];
            if (c == '\\' && i + 1 < s.Length && IsPunct(s[i + 1])) { sb.Append(E(s[i + 1].ToString())); i += 2; continue; }
            if (c == '`')
            {
                var run = 0; while (i + run < s.Length && s[i + run] == '`') run++;
                var close = s.IndexOf(new string('`', run), i + run, StringComparison.Ordinal);
                if (close > 0)
                {
                    sb.Append("<code>").Append(E(s.Substring(i + run, close - i - run).Trim())).Append("</code>");
                    i = close + run; continue;
                }
                sb.Append(E(new string('`', run))); i += run; continue;
            }
            if ((c == '!' && i + 1 < s.Length && s[i + 1] == '[') || c == '[')
            {
                var image = c == '!';
                if (TryLink(s, image ? i + 1 : i, out var text, out var target, out var end))
                {
                    sb.Append(image ? Image(text, target) : Link(text, target));
                    i = end; continue;
                }
            }
            if (c == '*' || c == '_')
            {
                var run = 0; while (i + run < s.Length && s[i + run] == c) run++;
                run = Math.Min(run, 3);
                var opens = i + run < s.Length && !char.IsWhiteSpace(s[i + run])
                    && (c == '*' || i == 0 || !char.IsLetterOrDigit(s[i - 1]));
                if (opens)
                {
                    var close = FindClose(s, i + run, c, run);
                    if (close > 0)
                    {
                        var inner = Inline(s.Substring(i + run, close - i - run));
                        sb.Append(run switch { 1 => "<em>" + inner + "</em>", 2 => "<strong>" + inner + "</strong>", _ => "<strong><em>" + inner + "</em></strong>" });
                        i = close + run; continue;
                    }
                }
                sb.Append(E(new string(c, run))); i += run; continue;
            }
            sb.Append(E(c.ToString()));
            i++;
        }
        return sb.ToString();
    }

    private static int FindClose(string s, int from, char c, int run)
    {
        var marker = new string(c, run);
        var k = from;
        while (k < s.Length)
        {
            if (s[k] == '`') { var e = s.IndexOf('`', k + 1); if (e < 0) return -1; k = e + 1; continue; }
            if (s[k] == '\\') { k += 2; continue; }
            if (string.CompareOrdinal(s, k, marker, 0, run) == 0 && !char.IsWhiteSpace(s[k - 1])
                && (k + run >= s.Length || s[k + run] != c)
                && (c == '*' || k + run >= s.Length || !char.IsLetterOrDigit(s[k + run])))
                return k;
            k++;
        }
        return -1;
    }

    /// [text](target) at <paramref name="i"/> (the '['); nested brackets in the text and parentheses in the target count.
    private static bool TryLink(string s, int i, out string text, out string target, out int end)
    {
        text = target = ""; end = i;
        var depth = 0; var k = i;
        for (; k < s.Length; k++)
        {
            if (s[k] == '\\') { k++; continue; }
            if (s[k] == '[') depth++;
            else if (s[k] == ']' && --depth == 0) break;
        }
        if (k >= s.Length || k + 1 >= s.Length || s[k + 1] != '(') return false;
        var close = k + 2; var paren = 1;
        for (; close < s.Length; close++)
        {
            if (s[close] == '(') paren++;
            else if (s[close] == ')' && --paren == 0) break;
        }
        if (close >= s.Length) return false;
        text = s.Substring(i + 1, k - i - 1);
        target = s.Substring(k + 2, close - k - 2).Trim();
        var sp = target.IndexOf(' ');   // [x](url "title") -- the title is dropped
        if (sp > 0) target = target[..sp];
        end = close + 1;
        return true;
    }

    private string Link(string text, string target)
    {
        var inner = Inline(text);
        if (Regex.IsMatch(target, @"^https?://[^\s<>""']+$", RegexOptions.IgnoreCase) || Regex.IsMatch(target, @"^mailto:[^\s<>""']+$", RegexOptions.IgnoreCase))
            return "<a href=\"" + E(target) + "\" rel=\"noopener noreferrer\" target=\"_blank\" class=\"doc-ext\">" + inner + "</a>";
        // a page of the shipped documentation (and its anchor), resolved by the library; anything else is text
        if (Regex.IsMatch(target, @"^(#|[A-Za-z0-9][A-Za-z0-9_-]*(\.md)?(#|$))") && _resolveLink(target) is { } url)
            return "<a href=\"" + E(url) + "\">" + inner + "</a>";
        return "<span class=\"doc-nolink\">" + inner + "</span>";
    }

    private string Image(string alt, string src)
    {
        var plainAlt = Plain(alt);
        if (!Regex.IsMatch(src, @"^[a-z][a-z0-9+.-]*:", RegexOptions.IgnoreCase) && !src.StartsWith("//", StringComparison.Ordinal) && _resolveImage(src) is { } url)
            return "<img src=\"" + E(url) + "\" alt=\"" + E(plainAlt) + "\" loading=\"lazy\" />";
        // an external image is never loaded (no outbound call); its words stay
        return "<span class=\"doc-noimage\">[" + E(plainAlt.Length > 0 ? plainAlt : "image") + "]</span>";
    }
}
