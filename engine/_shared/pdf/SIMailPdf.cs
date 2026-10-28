// SECURITYINSIGHT -- THE ONE PDF BUILDER (REQUIREMENTS #574; owner: "include pdf file with summary and relavant infp in
// mails"). ONE source for both runtimes: the web app compiles it (engine/_shared/pdf/SI.Pdf.csproj, referenced by
// SI.Management.Web), the PowerShell engines compile it at run time with Add-Type against the same PDFsharp / MigraDoc
// DLLs (engine/_shared/SI-MailPdf.ps1). The same builder serves the as-built PDF (#568) through Render().
//
// The mail PDF is built FROM THE MAIL'S OWN HTML (after the #573 layout): the same headings, paragraphs, lists and tables
// in the same order -- so the body and the PDF never disagree, and the PDF carries nothing the mail does not show (no
// secrets). Layout tables are flattened; data tables (a <th> row or the layout's facts table) stay tables.
// A4, readable printed: a title, the generation time, the content, a footer with the page number.
//
// PDFsharp + MigraDoc 6.2.4, MIT (engine/_shared/pdf/THIRD-PARTY-NOTICES.md). Fonts: the system's (DejaVu Sans in the
// container images, Arial / Segoe UI on Windows) through SIPdfFontResolver -- no font is bundled.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;
using PdfSharp.Fonts;
using PdfSharp.Pdf;

namespace SecurityInsight.Pdf
{
    public enum SIPdfBlockKind { Heading, Paragraph, Bullet, Table, Note }

    /// <summary>One block of the PDF: a heading (Level 1-4), a paragraph (Text, "\n" = a line break), a bullet, a table
    /// (Header may be empty, Rows), or a note (small grey print).</summary>
    public sealed class SIPdfBlock
    {
        public SIPdfBlockKind Kind { get; set; }
        public int Level { get; set; }
        public string Text { get; set; } = "";
        public List<string> Header { get; set; } = new List<string>();
        public List<List<string>> Rows { get; set; } = new List<List<string>>();
    }

    /// <summary>A whole PDF: the title, an optional subtitle, the blocks, the footer text.</summary>
    public sealed class SIPdfDocument
    {
        public string Title { get; set; } = "SecurityInsight";
        public string Subtitle { get; set; } = "";
        public List<SIPdfBlock> Blocks { get; set; } = new List<SIPdfBlock>();
        public string Footer { get; set; } = "SecurityInsight";
        public DateTime GeneratedUtc { get; set; } = DateTime.UtcNow;
    }

    public static class SIMailPdf
    {
        public const string FontFamily = "SI Sans";
        private static readonly object Gate = new object();
        private static readonly HashSet<string> Void = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "br", "hr", "img", "meta", "link", "input", "col", "wbr", "area", "base", "source" };
        private static readonly HashSet<string> BlockTags = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li", "table", "thead", "tbody", "tfoot", "tr", "td", "th", "pre", "blockquote", "center", "body", "html", "section", "header", "footer", "article", "hr" };

        /// <summary>The mail PDF: the mail's HTML (as sent) -> blocks -> A4 PDF bytes. Throws when it cannot render
        /// (the caller sends the mail without it).</summary>
        public static byte[] FromHtml(string title, string html, string footer)
        {
            var d = new SIPdfDocument { Title = string.IsNullOrWhiteSpace(title) ? "SecurityInsight" : title.Trim(), Blocks = HtmlToBlocks(html ?? ""), Footer = string.IsNullOrWhiteSpace(footer) ? "SecurityInsight" : footer.Trim() };
            return Render(d);
        }

        // ---------------------------------------------------------------------------------------------------------
        //  HTML -> blocks
        // ---------------------------------------------------------------------------------------------------------
        private sealed class Node
        {
            public string Tag = "";          // "" = a text node
            public string Attrs = "";
            public string Text = "";
            public Node Parent;
            public List<Node> Children = new List<Node>();
        }

        private static Node Parse(string html)
        {
            var h = Regex.Replace(html, "(?is)<(head|style|script|title)\\b.*?</\\1\\s*>", "");
            h = Regex.Replace(h, "(?s)<!--.*?-->", "");
            var root = new Node { Tag = "#root" };
            var cur = root;
            foreach (Match m in Regex.Matches(h, "<(/?)([a-zA-Z][a-zA-Z0-9]*)\\b([^>]*)>|<![^>]*>|[^<]+|<"))
            {
                if (m.Groups[2].Success)
                {
                    var tag = m.Groups[2].Value.ToLowerInvariant();
                    if (m.Groups[1].Value == "/")
                    {
                        for (var n = cur; n != null && n != root; n = n.Parent)
                            if (n.Tag == tag) { cur = n.Parent; break; }
                        continue;
                    }
                    var attrs = m.Groups[3].Value;
                    // an unclosed <p> / <li> ends where the next one starts
                    if ((tag == "p" || tag == "li") && cur.Tag == tag) cur = cur.Parent;
                    var node = new Node { Tag = tag, Attrs = attrs, Parent = cur };
                    cur.Children.Add(node);
                    if (!Void.Contains(tag) && !attrs.TrimEnd().EndsWith("/", StringComparison.Ordinal)) cur = node;
                }
                else if (m.Value.StartsWith("<!", StringComparison.Ordinal)) { }
                else cur.Children.Add(new Node { Text = WebUtility.HtmlDecode(m.Value), Parent = cur });
            }
            return root;
        }

        /// <summary>The mail HTML as PDF blocks, in order.</summary>
        public static List<SIPdfBlock> HtmlToBlocks(string html)
        {
            var blocks = new List<SIPdfBlock>();
            Walk(Parse(html ?? ""), blocks);
            // drop empty and immediately repeated paragraphs
            var outList = new List<SIPdfBlock>();
            foreach (var b in blocks)
            {
                if (b.Kind != SIPdfBlockKind.Table && string.IsNullOrWhiteSpace(b.Text)) continue;
                if (outList.Count > 0 && b.Kind != SIPdfBlockKind.Table && outList[outList.Count - 1].Kind == b.Kind && outList[outList.Count - 1].Text == b.Text) continue;
                outList.Add(b);
            }
            return outList;
        }

        private static bool IsBlock(Node n) => n.Tag.Length > 0 && BlockTags.Contains(n.Tag);
        private static bool HasAttr(Node n, string name) => Regex.IsMatch(n.Attrs, "(^|\\s)" + Regex.Escape(name) + "(\\s|=|$)", RegexOptions.IgnoreCase);

        private static void Walk(Node container, List<SIPdfBlock> blocks)
        {
            var inline = new List<Node>();
            void Flush()
            {
                if (inline.Count == 0) return;
                var t = Clean(string.Concat(inline.Select(InlineText)));
                inline.Clear();
                if (t.Length > 0) blocks.Add(new SIPdfBlock { Kind = SIPdfBlockKind.Paragraph, Text = t });
            }
            foreach (var c in container.Children)
            {
                if (!IsBlock(c)) { inline.Add(c); continue; }
                Flush();
                Block(c, blocks);
            }
            Flush();
        }

        private static void Block(Node n, List<SIPdfBlock> blocks)
        {
            switch (n.Tag)
            {
                case "h1": case "h2": case "h3": case "h4": case "h5": case "h6":
                    blocks.Add(new SIPdfBlock { Kind = SIPdfBlockKind.Heading, Level = Math.Min(4, n.Tag[1] - '0'), Text = Clean(InlineText(n)) });
                    return;
                case "p": case "pre": case "blockquote":
                    if (n.Children.Any(IsBlock)) { Walk(n, blocks); return; }
                    blocks.Add(new SIPdfBlock { Kind = SIPdfBlockKind.Paragraph, Text = Clean(InlineText(n)) });
                    return;
                case "li":
                    blocks.Add(new SIPdfBlock { Kind = SIPdfBlockKind.Bullet, Text = Clean(DeepText(n)) });
                    return;
                case "hr":
                    return;
                case "table":
                    if (IsDataTable(n)) { blocks.Add(DataTable(n)); return; }
                    foreach (var row in Rows(n)) foreach (var cell in row.Children.Where(x => x.Tag == "td" || x.Tag == "th")) Walk(cell, blocks);
                    return;
                case "div":
                    if (HasAttr(n, "data-si-mail-footer")) { blocks.Add(new SIPdfBlock { Kind = SIPdfBlockKind.Note, Text = Clean(DeepText(n)) }); return; }
                    Walk(n, blocks);
                    return;
                default:
                    Walk(n, blocks);
                    return;
            }
        }

        private static IEnumerable<Node> Rows(Node table)
        {
            foreach (var c in table.Children)
            {
                if (c.Tag == "tr") yield return c;
                else if (c.Tag == "thead" || c.Tag == "tbody" || c.Tag == "tfoot") foreach (var r in c.Children.Where(x => x.Tag == "tr")) yield return r;
            }
        }

        private static bool ContainsBlockContent(Node n) => n.Children.Any(c => c.Tag == "table" || c.Tag == "p" || c.Tag == "div" || c.Tag == "ul" || c.Tag == "ol" || (c.Tag.Length == 2 && c.Tag[0] == 'h' && char.IsDigit(c.Tag[1])) || ContainsBlockContent(c));

        private static bool IsDataTable(Node table)
        {
            if (HasAttr(table, "data-mail-facts")) return true;
            var rows = Rows(table).ToList();
            if (rows.Count == 0) return false;
            if (rows.Any(r => r.Children.Any(c => c.Tag == "th"))) return true;
            if (rows.Count < 2) return false;
            var cells = rows.SelectMany(r => r.Children.Where(c => c.Tag == "td")).ToList();
            if (cells.Any(ContainsBlockContent)) return false;
            return rows.Max(r => r.Children.Count(c => c.Tag == "td")) >= 2;
        }

        private static SIPdfBlock DataTable(Node table)
        {
            var b = new SIPdfBlock { Kind = SIPdfBlockKind.Table };
            var first = true;
            foreach (var r in Rows(table))
            {
                var cells = r.Children.Where(c => c.Tag == "td" || c.Tag == "th").ToList();
                if (cells.Count == 0) continue;
                var texts = cells.Select(c => Clean(DeepText(c))).ToList();
                if (first && cells.All(c => c.Tag == "th")) b.Header = texts;
                else b.Rows.Add(texts);
                first = false;
            }
            return b;
        }

        private static string InlineText(Node n)
        {
            if (n.Tag.Length == 0) return n.Text;
            if (n.Tag == "br") return "\n";
            var inner = string.Concat(n.Children.Select(InlineText));
            if (n.Tag == "a")
            {
                var href = Regex.Match(n.Attrs, "href\\s*=\\s*\"(https?://[^\"]+)\"", RegexOptions.IgnoreCase);
                if (href.Success)
                {
                    var url = WebUtility.HtmlDecode(href.Groups[1].Value);
                    var label = Clean(inner);
                    if (label.Length == 0 || label == url) return url;
                    return inner + " (" + url + ")";
                }
            }
            if (IsBlock(n)) return " " + inner + " ";
            return inner;
        }

        private static string DeepText(Node n)
        {
            if (n.Tag.Length == 0) return n.Text;
            if (n.Tag == "br") return "\n";
            if (n.Tag == "a") return InlineText(n);
            var inner = string.Concat(n.Children.Select(DeepText));
            return (n.Tag == "p" || n.Tag == "div" || n.Tag == "li" || n.Tag == "tr") ? inner + "\n" : (n.Tag == "td" || n.Tag == "th") ? inner + " " : inner;
        }

        /// <summary>Whitespace collapsed per line, line breaks kept (at most one blank line), trimmed.</summary>
        private static string Clean(string s)
        {
            var lines = (s ?? "").Replace("\r\n", "\n").Replace('\r', '\n').Replace('\u00A0', ' ').Split('\n')
                .Select(l => Regex.Replace(l, "[ \\t]+", " ").Trim()).ToList();
            var outLines = new List<string>();
            foreach (var l in lines)
            {
                if (l.Length == 0) { if (outLines.Count > 0 && outLines[outLines.Count - 1].Length > 0) outLines.Add(""); continue; }
                outLines.Add(l);
            }
            while (outLines.Count > 0 && outLines[outLines.Count - 1].Length == 0) outLines.RemoveAt(outLines.Count - 1);
            return string.Join("\n", outLines);
        }

        // ---------------------------------------------------------------------------------------------------------
        //  blocks -> PDF
        // ---------------------------------------------------------------------------------------------------------
        private static readonly Color Ink = Color.FromRgb(0x0B, 0x16, 0x33);
        private static readonly Color Muted = Color.FromRgb(0x52, 0x60, 0x7D);
        private static readonly Color LineColor = Color.FromRgb(0xDC, 0xE3, 0xF2);
        private static readonly Color Panel = Color.FromRgb(0xF6, 0xF8, 0xFD);

        /// <summary>Text that WinAnsi (the PDF's text encoding: the text stays searchable and copyable) can carry; the
        /// rest becomes '?'.</summary>
        public static string Printable(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            var sb = new StringBuilder(s.Length);
            foreach (var ch in s)
            {
                if (ch == '\n' || (ch >= 0x20 && ch < 0x7F) || (ch >= 0xA0 && ch <= 0xFF) || "\u20AC\u201A\u0192\u201E\u2026\u2020\u2021\u02C6\u2030\u0160\u2039\u0152\u017D\u2018\u2019\u201C\u201D\u2022\u2013\u2014\u02DC\u2122\u0161\u203A\u0153\u017E\u0178".IndexOf(ch) >= 0) sb.Append(ch);
                else if (ch == '\t') sb.Append(' ');
                else if (char.IsHighSurrogate(ch)) sb.Append('?');
                else if (!char.IsLowSurrogate(ch)) sb.Append('?');
            }
            return sb.ToString();
        }

        private static void EnsureFonts()
        {
            lock (Gate)
            {
                if (GlobalFontSettings.FontResolver == null) GlobalFontSettings.FontResolver = new SIPdfFontResolver();
                try { if (GlobalFontSettings.DefaultFontEncoding != PdfFontEncoding.WinAnsi) GlobalFontSettings.DefaultFontEncoding = PdfFontEncoding.WinAnsi; } catch (InvalidOperationException) { }
            }
        }

        /// <summary>Any SIPdfDocument -> A4 PDF bytes (the mail PDF and the as-built PDF, #568).</summary>
        public static byte[] Render(SIPdfDocument d)
        {
            if (d == null) throw new ArgumentNullException("d");
            EnsureFonts();
            var doc = new Document();
            doc.Info.Title = Printable(d.Title);
            doc.Info.Author = "SecurityInsight";
            var normal = doc.Styles["Normal"];
            normal.Font.Name = FontFamily;
            normal.Font.Size = 10;
            normal.Font.Color = Ink;
            normal.ParagraphFormat.SpaceAfter = Unit.FromPoint(6);
            normal.ParagraphFormat.LineSpacingRule = MigraDoc.DocumentObjectModel.LineSpacingRule.Multiple;
            normal.ParagraphFormat.LineSpacing = 1.15;
            var sizes = new[] { 15.0, 13.0, 11.5, 10.5 };
            for (var i = 1; i <= 4; i++)
            {
                var hs = doc.Styles["Heading" + i];
                hs.Font.Name = FontFamily; hs.Font.Size = sizes[i - 1]; hs.Font.Bold = true; hs.Font.Color = Ink;
                hs.ParagraphFormat.SpaceBefore = Unit.FromPoint(i == 1 ? 12 : 10); hs.ParagraphFormat.SpaceAfter = Unit.FromPoint(5);
                hs.ParagraphFormat.KeepWithNext = true;
            }
            var bullet = doc.Styles.AddStyle("SIBullet", "Normal");
            bullet.ParagraphFormat.LeftIndent = Unit.FromCentimeter(0.6);
            bullet.ParagraphFormat.FirstLineIndent = Unit.FromCentimeter(-0.4);
            bullet.ParagraphFormat.SpaceAfter = Unit.FromPoint(3);
            var note = doc.Styles.AddStyle("SINote", "Normal");
            note.Font.Size = 8; note.Font.Color = Muted;

            var sec = doc.AddSection();
            sec.PageSetup = doc.DefaultPageSetup.Clone();
            sec.PageSetup.PageFormat = PageFormat.A4;
            sec.PageSetup.TopMargin = Unit.FromCentimeter(1.8);
            sec.PageSetup.BottomMargin = Unit.FromCentimeter(1.8);
            sec.PageSetup.LeftMargin = Unit.FromCentimeter(1.8);
            sec.PageSetup.RightMargin = Unit.FromCentimeter(1.8);
            var usable = Unit.FromCentimeter(21.0 - 3.6);

            var foot = sec.Footers.Primary.AddParagraph();
            foot.Style = "SINote";
            foot.AddText(Printable(d.Footer) + "  \u00B7  page ");
            foot.AddPageField();
            foot.AddText(" of ");
            foot.AddNumPagesField();

            var title = sec.AddParagraph(Printable(d.Title), "Heading1");
            title.Format.SpaceBefore = 0;
            var gen = sec.AddParagraph(Printable((string.IsNullOrWhiteSpace(d.Subtitle) ? "" : d.Subtitle.Trim() + "  \u00B7  ") + "Generated " + d.GeneratedUtc.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC"), "SINote");
            gen.Format.SpaceAfter = Unit.FromPoint(10);

            var firstHeadingSkipped = false;
            foreach (var b in d.Blocks ?? new List<SIPdfBlock>())
            {
                switch (b.Kind)
                {
                    case SIPdfBlockKind.Heading:
                        // the mail's own title repeats the PDF's title: once is enough
                        if (!firstHeadingSkipped && string.Equals(b.Text.Trim(), d.Title.Trim(), StringComparison.OrdinalIgnoreCase)) { firstHeadingSkipped = true; continue; }
                        sec.AddParagraph(Printable(b.Text), "Heading" + Math.Max(1, Math.Min(4, b.Level <= 1 ? 2 : b.Level)));
                        break;
                    case SIPdfBlockKind.Bullet:
                        AddText(sec.AddParagraph("\u2022  ", "SIBullet"), b.Text);
                        break;
                    case SIPdfBlockKind.Note:
                        AddText(sec.AddParagraph("", "SINote"), b.Text);
                        break;
                    case SIPdfBlockKind.Table:
                        AddTable(sec, b, usable);
                        break;
                    default:
                        AddText(sec.AddParagraph(), b.Text);
                        break;
                }
            }

            var renderer = new PdfDocumentRenderer { Document = doc };
            renderer.RenderDocument();
            using (var ms = new MemoryStream())
            {
                renderer.PdfDocument.Save(ms);
                return ms.ToArray();
            }
        }

        private static void AddText(Paragraph p, string text)
        {
            var lines = Printable(text ?? "").Split('\n');
            for (var i = 0; i < lines.Length; i++)
            {
                if (i > 0) p.AddLineBreak();
                if (lines[i].Length > 0) p.AddText(lines[i]);
            }
        }

        private static void AddTable(Section sec, SIPdfBlock b, Unit usable)
        {
            var n = Math.Max(b.Header.Count, b.Rows.Count == 0 ? 0 : b.Rows.Max(r => r.Count));
            if (n == 0) return;
            var t = sec.AddTable();
            t.Borders.Width = 0.5;
            t.Borders.Color = LineColor;
            t.Format.Font.Size = n > 8 ? 7 : n > 5 ? 8 : 9;
            t.Format.SpaceAfter = 0;
            var w = Unit.FromPoint(usable.Point / n);
            for (var i = 0; i < n; i++) t.AddColumn(w);
            if (b.Header.Count > 0)
            {
                var hr = t.AddRow();
                hr.HeadingFormat = true;
                hr.Shading.Color = Panel;
                for (var i = 0; i < n; i++)
                {
                    var p = hr.Cells[i].AddParagraph();
                    p.Format.Font.Bold = true; p.Format.Font.Color = Muted;
                    AddText(p, i < b.Header.Count ? b.Header[i] : "");
                }
            }
            foreach (var r in b.Rows)
            {
                var row = t.AddRow();
                row.TopPadding = Unit.FromPoint(2); row.BottomPadding = Unit.FromPoint(2);
                for (var i = 0; i < n; i++) AddText(row.Cells[i].AddParagraph(), i < r.Count ? r[i] : "");
            }
            sec.AddParagraph().Format.SpaceAfter = Unit.FromPoint(4);
        }
    }

    /// <summary>The fonts: the system's own -- DejaVu Sans / Liberation Sans on Linux (the container images install
    /// fonts-dejavu-core), Segoe UI / Arial on Windows; SI_PDF_FONT_DIR first when set. Italic is simulated; bold falls
    /// back to simulated bold when the system has no bold face. No font: an error (the mail goes without its PDF).</summary>
    public sealed class SIPdfFontResolver : IFontResolver
    {
        private static readonly string[] RegularNames = { "DejaVuSans.ttf", "LiberationSans-Regular.ttf", "segoeui.ttf", "arial.ttf", "Arial.ttf" };
        private static readonly string[] BoldNames = { "DejaVuSans-Bold.ttf", "LiberationSans-Bold.ttf", "segoeuib.ttf", "arialbd.ttf", "Arial Bold.ttf" };
        private static readonly Dictionary<string, byte[]> Cache = new Dictionary<string, byte[]>();

        private static IEnumerable<string> Dirs()
        {
            var env = Environment.GetEnvironmentVariable("SI_PDF_FONT_DIR");
            if (!string.IsNullOrWhiteSpace(env)) yield return env.Trim();
            yield return "/usr/share/fonts/truetype/dejavu";
            yield return "/usr/share/fonts/dejavu";
            yield return "/usr/share/fonts/TTF";
            yield return "/usr/share/fonts/truetype/liberation";
            yield return "/usr/share/fonts/truetype/liberation2";
            var win = Environment.GetFolderPath(Environment.SpecialFolder.Fonts);
            if (!string.IsNullOrEmpty(win)) yield return win;
            yield return "C:\\Windows\\Fonts";
            yield return "/System/Library/Fonts/Supplemental";
            yield return "/Library/Fonts";
        }

        public static string Find(bool bold)
        {
            foreach (var dir in Dirs())
                foreach (var name in bold ? BoldNames : RegularNames)
                {
                    try { var p = Path.Combine(dir, name); if (File.Exists(p)) return p; } catch (Exception) { }
                }
            return null;
        }

        public FontResolverInfo ResolveTypeface(string familyName, bool bold, bool italic)
        {
            var hasBold = bold && Find(true) != null;
            var face = hasBold ? "SI#Bold" : "SI#Regular";
            return new FontResolverInfo(face, bold && !hasBold, italic);
        }

        public byte[] GetFont(string faceName)
        {
            lock (Cache)
            {
                byte[] data;
                if (Cache.TryGetValue(faceName, out data)) return data;
                var path = Find(faceName == "SI#Bold") ?? Find(false);
                if (path == null) throw new InvalidOperationException("no font for the PDF: install fonts-dejavu-core (Linux) or set SI_PDF_FONT_DIR to a folder with DejaVuSans.ttf");
                data = File.ReadAllBytes(path);
                Cache[faceName] = data;
                return data;
            }
        }
    }
}
