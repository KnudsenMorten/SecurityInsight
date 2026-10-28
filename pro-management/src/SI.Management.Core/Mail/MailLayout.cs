using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace SI.Management.Core.Mail;

/// <summary>
/// PURE. The ONE mail layout of the web app (framework MAIL-2, REQUIREMENTS #573: every SI mail readable, with real paragraphs
/// and blank lines) -- the C# twin of engine\_shared\SI-MailLayout.ps1. Every mail the web app composes is queued in an
/// outbox (cfg.SignInMail, cfg.ExemptionMail, cfg.GovernanceMail, cfg.ReportMail) through <see cref="Normalize"/>, and the
/// mail job's Send-SIMail formats it again with the PowerShell twin before it is sent.
///
/// The rules: a &lt;p&gt; per paragraph with an explicit bottom margin (Outlook drops the default paragraph spacing),
/// &lt;br&gt; only inside a paragraph, every value HTML-encoded, multi-line free text keeps its line breaks. One HTML body:
/// Microsoft Graph sendMail takes one body; <see cref="ToText"/> is the CRLF plain-text rendering (a blank line between
/// paragraphs) of the same mail.
/// </summary>
public static partial class MailLayout
{
    public const string Marker = "data-si-mail-layout";
    /// The paragraph style every mail paragraph carries.
    public const string ParagraphStyle = "margin:0 0 14px 0;line-height:1.55;";
    private const string Font = "font-family:Segoe UI,Arial,sans-serif;";
    private const string Blue = "#1B4FE4";

    public static string Encode(string? s) => WebUtility.HtmlEncode(s ?? "");

    /// <summary>One free-text VALUE (a reason, a comment, a request) for inside a paragraph or a cell: encoded, links
    /// clickable, every line break kept as &lt;br&gt;.</summary>
    public static string Inline(string? text)
    {
        var t = (text ?? "").Replace("\r\n", "\n").Replace('\r', '\n').Trim();
        if (t.Length == 0) return "";
        return string.Join("<br>", t.Split('\n').Select(l => Linkify(l.TrimEnd())));
    }

    /// <summary>Plain text -> paragraphs: a blank line separates paragraphs (&lt;p&gt; with the explicit margin), a single
    /// line break stays a &lt;br&gt;, a run of lines starting with "- " is a list. Everything encoded.</summary>
    public static string Paragraphs(string? text, string? style = null)
    {
        var t = (text ?? "").Replace("\r\n", "\n").Replace('\r', '\n').Trim();
        if (t.Length == 0) return "";
        var st = style ?? ParagraphStyle;
        var sb = new StringBuilder();
        foreach (var para in BlankLine().Split(t))
        {
            var lines = para.Split('\n').Select(l => l.TrimEnd()).Where(l => l.Trim().Length > 0).ToList();
            var buf = new List<string>();
            var ul = new List<string>();
            void FlushP() { if (buf.Count > 0) { sb.Append($"<p style=\"{Font}{st}\">{string.Join("<br>", buf)}</p>"); buf.Clear(); } }
            void FlushU() { if (ul.Count > 0) { sb.Append($"<ul style=\"{Font}margin:0 0 14px 0;padding:0 0 0 22px;\">{string.Concat(ul.Select(x => $"<li style=\"margin:0 0 4px 0;\">{x}</li>"))}</ul>"); ul.Clear(); } }
            foreach (var l in lines)
            {
                var m = Bullet().Match(l);
                if (m.Success) { FlushP(); ul.Add(Linkify(m.Groups[1].Value.Trim())); continue; }
                FlushU();
                buf.Add(Linkify(l.Trim()));
            }
            FlushP(); FlushU();
        }
        return sb.ToString();
    }

    // ---- #728: NO tables in a mail (owner: "Drop the tables in emails as it becomes hard to read on mobiles / Make line with
    // topic: / Then text. / Use bold where it can add important context / Use line spacing where needed"). The C# twins of
    // engine\_shared\SI-MailLayout.ps1: a summary block first, sections with a heading, "Topic: text" lines with the topic
    // in bold, one line per record, a max-width div frame (no fixed width).
    private const string Ink = "#0B1633";
    private const string Muted = "#52607D";
    private const string Tint = "#EEF3FE";

    /// <summary>A section heading. Encoded.</summary>
    public static string Heading(string? text) =>
        string.IsNullOrWhiteSpace(text) ? "" : $"<h2 style=\"{Font}font-size:16px;line-height:1.35;font-weight:700;color:{Ink};margin:24px 0 10px 0;\">{Encode(text)}</h2>";

    /// <summary>ONE "Topic: text" line: the topic in bold, then the text (plain, encoded, line breaks kept), a paragraph of
    /// its own. <paramref name="html"/> instead of <paramref name="text"/>: a trusted fragment already built with encoded values.</summary>
    public static string Line(string? topic, string? text = null, string? html = null, string? color = null)
    {
        var body = html ?? Inline(text);
        var t = (topic ?? "").Trim().TrimEnd(':');
        if (t.Length == 0 && body.Trim().Length == 0) return "";
        var lead = t.Length > 0 ? $"<strong>{Encode(t)}:</strong> " : "";
        return $"<p style=\"{Font}font-size:14px;line-height:1.5;color:{color ?? Ink};margin:0 0 10px 0;\">{lead}{body}</p>";
    }

    /// <summary>The SUMMARY block every mail starts with: a few short lines (trusted HTML fragments, already encoded), one per
    /// line, in a tinted block with a blue edge -- a &lt;div data-mail-summary&gt; with NO div inside it (the mail job puts the
    /// portal link line directly under it).</summary>
    public static string Summary(IEnumerable<string> htmlLines)
    {
        var parts = htmlLines.Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
        if (parts.Count == 0) return "";
        return $"<div data-mail-summary style=\"{Font}background:{Tint};border-left:4px solid {Blue};border-radius:4px;padding:12px 16px;margin:0 0 18px 0;font-size:15px;line-height:1.55;color:{Ink};\"><p style=\"margin:0;\">{string.Join("<br>", parts)}</p></div>";
    }

    /// <summary>The one blue button: a styled link in a paragraph of its own (no table). Not https:// = no button
    /// (<paramref name="anyWebLink"/>: any link the web app built itself -- http:// or relative too, as before).</summary>
    public static string Button(string? url, string? text, bool anyWebLink = false)
    {
        if (url is null) return "";
        var ok = url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
            || (anyWebLink && url.Trim().Length > 0 && !url.TrimStart().StartsWith("javascript:", StringComparison.OrdinalIgnoreCase));
        if (!ok) return "";
        return $"<p data-mail-button style=\"{Font}margin:8px 0 18px 0;line-height:1.2;\"><a href=\"{Encode(url)}\" style=\"{Font}display:inline-block;background:{Blue};border:2px solid {Blue};border-radius:8px;padding:12px 24px;font-size:15px;font-weight:700;color:#ffffff;text-decoration:none;\" target=\"_blank\">{Encode(text)}</a></p>";
    }

    /// <summary>The frame every mail sits in: no table, no fixed width (a div with a max-width). <paramref name="brandHtml"/>,
    /// <paramref name="contentHtml"/> and <paramref name="footerHtml"/> are trusted fragments. Extra attributes
    /// (data-mail-brand, data-mail-body) close the brand bar's and the content div's opening tag ("data-mail-body&gt;").</summary>
    public static string Frame(string brandHtml, string? title, string? subtitle, string contentHtml, string? footerHtml,
                               string brandAttr = "data-mail-brand", string bodyAttr = "data-mail-body")
    {
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta name=\"color-scheme\" content=\"light only\"></head>");
        sb.Append("<body style=\"margin:0;padding:0;background:#f3f5f8;\"><div style=\"background:#f3f5f8;padding:16px 8px;\">");
        sb.Append("<div style=\"max-width:680px;margin:0 auto;background:#ffffff;border:1px solid #e0e6ed;border-radius:8px;\">");
        sb.Append($"<div style=\"background:{Ink};padding:14px 20px;border-radius:8px 8px 0 0;{Font}font-size:18px;font-weight:700;color:#ffffff;\" {brandAttr}>{brandHtml}</div>");
        if (!string.IsNullOrWhiteSpace(title) || !string.IsNullOrWhiteSpace(subtitle))
        {
            sb.Append("<div style=\"padding:18px 20px 0 20px;\">");
            if (!string.IsNullOrWhiteSpace(title)) sb.Append($"<h1 style=\"{Font}font-size:21px;line-height:1.3;color:{Ink};margin:0 0 6px 0;\">{Encode(title)}</h1>");
            if (!string.IsNullOrWhiteSpace(subtitle)) sb.Append($"<p style=\"{Font}font-size:13px;color:{Muted};margin:0 0 10px 0;\">{Encode(subtitle)}</p>");
            sb.Append("</div>");
        }
        sb.Append($"<div style=\"padding:8px 20px 12px 20px;{Font}font-size:14px;color:{Ink};\" {bodyAttr}>{contentHtml}</div>");
        if (!string.IsNullOrWhiteSpace(footerHtml))
            sb.Append($"<div style=\"padding:12px 20px 16px 20px;border-top:1px solid #e0e6ed;{Font}font-size:11px;line-height:1.5;color:{Muted};\">{footerHtml}</div>");
        sb.Append("</div></div></body></html>");
        return sb.ToString();
    }

    /// <summary>Encoded text with every https:// link clickable.</summary>
    public static string Linkify(string? text)
    {
        var t = text ?? "";
        var sb = new StringBuilder();
        var i = 0;
        foreach (Match m in Url().Matches(t))
        {
            var url = m.Value;
            while (url.Length > 8 && ".,;:)]".Contains(url[^1])) url = url[..^1];
            sb.Append(Encode(t[i..m.Index]));
            sb.Append($"<a href=\"{Encode(url)}\" style=\"color:{Blue};text-decoration:underline;\">{Encode(url)}</a>");
            i = m.Index + url.Length;
        }
        if (i < t.Length) sb.Append(Encode(t[i..]));
        return sb.ToString();
    }

    /// <summary>
    /// THE outbox chokepoint: plain text -> paragraphs in a minimal frame; HTML -> structure kept, every &lt;p&gt; without
    /// a margin of its own gets the explicit paragraph margin, a raw line break inside a paragraph's text becomes &lt;br&gt;.
    /// Idempotent (the marker).
    /// </summary>
    public static string Normalize(string? body)
    {
        var html = body ?? "";
        if (html.Contains(Marker, StringComparison.Ordinal)) return html;
        if (!AnyTag().IsMatch(html))
            return $"<!DOCTYPE html><html><head><meta charset=\"UTF-8\"></head><body {Marker}=\"1\" style=\"margin:0;padding:16px 24px;{Font}font-size:14px;color:#0B1633;\">{Paragraphs(html)}</body></html>";
        html = ParagraphElement().Replace(html, m =>
        {
            var inner = TwoBreaks().Replace(m.Groups[2].Value, "<br><br>");
            inner = OneBreak().Replace(inner, "<br>");
            return m.Groups[1].Value + inner + m.Groups[3].Value;
        });
        html = ParagraphOpen().Replace(html, m =>
        {
            var attrs = m.Groups[1].Value;
            var s = StyleAttr().Match(attrs);
            if (!s.Success) return $"<p{attrs} style=\"{ParagraphStyle}\">";
            var st = s.Groups[1].Value;
            if (HasMargin().IsMatch(st)) return m.Value;
            var merged = st.TrimEnd(';', ' ') + (st.Trim().Length > 0 ? ";" : "") + ParagraphStyle;
            return "<p" + attrs.Replace(s.Value, $"style=\"{merged}\"") + ">";
        });
        var body1 = BodyOpen().Match(html);
        return body1.Success ? html.Insert(body1.Index + body1.Length, $" {Marker}=\"1\"") : $"<div {Marker}=\"1\">{html}</div>";
    }

    /// <summary>The plain-text rendering: CRLF line ends, one blank line between paragraphs / headings / tables / lists.</summary>
    public static string ToText(string? html)
    {
        if (string.IsNullOrEmpty(html)) return "";
        var h = HeadStyle().Replace(html, "");
        h = Regex.Replace(h, "(?s)<!--.*?-->", "");
        h = Regex.Replace(h, "[\r\n\t]+", " ");
        h = Regex.Replace(h, "(?is)<a\\b[^>]*href=\"(https?://[^\"]+)\"[^>]*>(.*?)</a>", m =>
        {
            var label = Regex.Replace(m.Groups[2].Value, "<[^>]+>", "").Trim();
            var url = WebUtility.HtmlDecode(m.Groups[1].Value);
            return label.Length == 0 || WebUtility.HtmlDecode(label) == url ? url : $"{label} ({url})";
        });
        h = Regex.Replace(h, "(?i)<br\\s*/?>", "\n");
        h = Regex.Replace(h, "(?i)<li\\b[^>]*>", "\n- ");
        h = Regex.Replace(h, "(?i)</t[dh]>", " | ");
        h = Regex.Replace(h, "(?i)</tr>", "\n");
        h = Regex.Replace(h, "(?i)</?(p|h[1-6]|ul|ol|table|div|pre|blockquote)\\b[^>]*>", "\n\n");
        h = Regex.Replace(h, "<[^>]+>", "");
        h = WebUtility.HtmlDecode(h);
        var outLines = new List<string>();
        foreach (var raw in h.Split('\n'))
        {
            var x = Regex.Replace(raw, "[ \u00A0]+", " ").Trim();
            x = Regex.Replace(x, "(\\s*\\|\\s*)+$", "");
            x = Regex.Replace(x, "^(\\|\\s*)+", "");
            if (x.Length == 0) { if (outLines.Count > 0 && outLines[^1].Length > 0) outLines.Add(""); continue; }
            outLines.Add(x);
        }
        while (outLines.Count > 0 && outLines[^1].Length == 0) outLines.RemoveAt(outLines.Count - 1);
        return string.Join("\r\n", outLines);
    }

    [GeneratedRegex("\\n[ \\t]*\\n")] private static partial Regex BlankLine();
    [GeneratedRegex("^\\s*[-*\\u2022]\\s+(.+)$")] private static partial Regex Bullet();
    [GeneratedRegex("https://[^\\s<>\"']+")] private static partial Regex Url();
    // HTML = it carries a mail markup element; anything else tag-like in a text ("<script>" in a reason) is text, encoded
    [GeneratedRegex("(?i)<!DOCTYPE\\b|</?(html|body|head|p|div|span|table|thead|tbody|tr|td|th|br|hr|h[1-6]|ul|ol|li|strong|b|em|i|u|a|img|code|pre|blockquote|font|center|small|meta|style)(\\s[^>]*)?/?>")] private static partial Regex AnyTag();
    [GeneratedRegex("(?is)(<p\\b[^>]*>)(.*?)(</p>)")] private static partial Regex ParagraphElement();
    [GeneratedRegex("(?<=[^\\s>])[ \\t]*\\r?\\n[ \\t]*\\r?\\n[ \\t]*(?=[^\\s<])")] private static partial Regex TwoBreaks();
    [GeneratedRegex("(?<=[^\\s>])[ \\t]*\\r?\\n[ \\t]*(?=[^\\s<])")] private static partial Regex OneBreak();
    [GeneratedRegex("(?i)<p(\\s[^>]*)?>")] private static partial Regex ParagraphOpen();
    [GeneratedRegex("(?i)\\bstyle\\s*=\\s*\"([^\"]*)\"")] private static partial Regex StyleAttr();
    [GeneratedRegex("(?i)(^|;)\\s*margin(-[a-z]+)?\\s*:")] private static partial Regex HasMargin();
    [GeneratedRegex("(?i)<body\\b")] private static partial Regex BodyOpen();
    [GeneratedRegex("(?is)<(head|style|script)\\b.*?</\\1>")] private static partial Regex HeadStyle();
}
