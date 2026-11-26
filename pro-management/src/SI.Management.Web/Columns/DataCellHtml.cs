using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Html;

namespace SI.Management.Web.Columns;

/// <summary>
/// An extra column's cell on screen: the text, HTML-encoded, with every http(s) address in it a link (More details lists
/// "CVE-2024-1 => https://nvd..." pairs) -- the WHOLE text, never cut (#1386, owner 2026-11-25: "it is important we can see
/// all info", e.g. paths). The screen caps it at two lines (js/app/grid-cells.js); the row's "Show full text", the column's
/// "Full text", the hover and the export show all of it. Sending it whole costs less than the old cut (400) plus the whole
/// text again in the tooltip.
/// </summary>
public static partial class DataCellHtml
{

    [GeneratedRegex(@"https?://[^\s;,""'<>]+", RegexOptions.CultureInvariant)]
    private static partial Regex Url();

    /// A badge (good / fair / warn / bad / info, or none) with its text; several are joined by a space.
    public static IHtmlContent Badges(params (string? Css, string? Text)[] badges) => new HtmlString(string.Join(" ",
        badges.Where(b => !string.IsNullOrEmpty(b.Text)).Select(b => "<span class=\"badge " + HtmlEncoder.Default.Encode(b.Css ?? "") + "\">" + HtmlEncoder.Default.Encode(b.Text!) + "</span>")));

    /// Text followed by muted text ("2026-10-01 -- by anna").
    public static IHtmlContent WithMuted(string? text, string? muted) => new HtmlString(HtmlEncoder.Default.Encode(text ?? "")
        + (string.IsNullOrEmpty(muted) ? "" : "<span class=\"muted\"> -- " + HtmlEncoder.Default.Encode(muted) + "</span>"));

    public static IHtmlContent Render(string? text)
    {
        if (string.IsNullOrEmpty(text)) return HtmlString.Empty;
        var shown = text;   // #1386: whole, never cut
        var sb = new StringBuilder();
        var at = 0;
        foreach (Match m in Url().Matches(shown))
        {
            sb.Append(HtmlEncoder.Default.Encode(shown[at..m.Index]));
            var href = HtmlEncoder.Default.Encode(m.Value);
            sb.Append("<a href=\"").Append(href).Append("\" target=\"_blank\" rel=\"noopener noreferrer\">").Append(href).Append("</a>");
            at = m.Index + m.Length;
        }
        sb.Append(HtmlEncoder.Default.Encode(shown[at..]));
        return new HtmlString(sb.ToString());
    }
}
