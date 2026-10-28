using System.Globalization;
using System.Net;
using System.Text;

namespace SI.Management.Web.Notify;

/// <summary>
/// Framework MAIL-2 item 1: the AUDIENCE of a mail recipient -- it decides where the mail's blue button leads. A SOC analyst
/// lands on the findings, posture people on the risk / exposure views, a manager on the management reports. A recipient
/// with no audience set is a posture reader (the Executive overview), the page every role may open.
/// </summary>
public static class MailAudience
{
    public const string Soc = "soc";
    public const string Posture = "posture";
    public const string Manager = "manager";
    public static readonly IReadOnlyList<string> All = [Soc, Posture, Manager];

    public static string Normalize(string? a) => All.FirstOrDefault(x => x.Equals((a ?? "").Trim(), StringComparison.OrdinalIgnoreCase)) ?? Posture;

    public static string Label(string? a) => Normalize(a) switch
    {
        Soc => "SOC analyst",
        Manager => "Manager",
        _ => "Posture / risk",
    };

    /// The page the audience lands on (a stable deep link: a page, never a session URL).
    public static string Landing(string? a) => Normalize(a) switch
    {
        Soc => "/Findings",
        Manager => "/Management/Summary",
        _ => "/Management",
    };

    /// The words on the button for the audience.
    public static string ButtonText(string? a) => Normalize(a) switch
    {
        Soc => "Open the findings",
        Manager => "Open the management summary",
        _ => "Open the risk overview",
    };
}

/// <summary>
/// PURE. Framework MAIL-2 items 1, 4 and 7 -- the look every mail the web app composes shares: the brand bar (the Invardia
/// SecurityInsight Pro wordmark on the brand ink -- a mail client does not load the web app's SVG logo, which sits behind the
/// sign-in), a summary first, one clear BLUE button that deep-links to the right page, and a plain link to the web app's
/// home. Inline styles only: it is a mail. Without the web app's public address (SIWeb_PublicBaseUrl) there is no link to
/// give -- the mail says so instead of a broken button.
/// </summary>
public static class MailBrand
{
    public const string Blue = "#1B4FE4";
    public const string Ink = "#0B1633";
    public const string Wordmark = "#9FC3FF";
    private const string Font = "font-family:Segoe UI,Arial,sans-serif;";

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    /// The product name in the mail's brand bar: SecurityInsight Pro unless the installation runs the Community edition.
    public const string ProProductName = "SecurityInsight Pro";

    /// Owner 2026-10-28: a mail of the Community edition carries the Community edition's name in its brand bar (a mail client
    /// loads no logo image -- the wordmark is text). Swaps exactly the two marked spans of <see cref="Wrap"/>; any other text
    /// of the mail is untouched. -pro: the licence check's verdict (Licensing/EditionBrand.cs).
    public static string ForEdition(string html, bool pro)
    {
        if (pro || string.IsNullOrEmpty(html)) return html;
        var c = SI.Management.Web.Licensing.EditionBrand.CommunityProduct;
        return html.Replace($"data-mail-product>{ProProductName}</span>", $"data-mail-product>{c}</span>", StringComparison.Ordinal)
                   .Replace($"<span data-mail-product-home>{ProProductName}</span>", $"<span data-mail-product-home>{c}</span>", StringComparison.Ordinal);
    }

    /// An absolute link into the web app, or null when its public address is not set.
    public static string? Link(string? baseUrl, string path)
    {
        var b = (baseUrl ?? "").Trim().TrimEnd('/');
        if (b.Length == 0 || !b.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return null;
        return b + (path.StartsWith('/') ? path : "/" + path);
    }

    /// The one blue button (#728: a styled link in a paragraph of its own -- no table).
    public static string Button(string href, string text) => SI.Management.Core.Mail.MailLayout.Button(href, text);

    /// The button for a recipient's audience, or a line saying why there is none.
    public static string AudienceButton(string? baseUrl, string? audience, string? path = null, string? text = null) =>
        Link(baseUrl, path ?? MailAudience.Landing(audience)) is { } href
            ? Button(href, text ?? MailAudience.ButtonText(audience))
            : Para("<em>The web app's public address is not set (setting SIWeb_PublicBaseUrl), so this mail carries no link into SecurityInsight.</em>");

    public static string Para(string html) => $"<p style=\"{Font}font-size:14px;color:#24292f;{SI.Management.Core.Mail.MailLayout.ParagraphStyle}\">{html}</p>";
    public static string H2(string text) => SI.Management.Core.Mail.MailLayout.Heading(text);

    /// One "Topic: text" line (#728): the topic in bold. <paramref name="html"/> is a trusted fragment (already encoded).
    public static string Line(string topic, string html) => SI.Management.Core.Mail.MailLayout.Line(topic, html: html);

    /// A summary block (#728: no table): the few numbers or words that matter, first -- one "Label: value" line each, the
    /// label in bold.
    public static string Summary(IEnumerable<(string Label, string Value)> items) =>
        SI.Management.Core.Mail.MailLayout.Summary(items.Select(i => $"<strong>{E(i.Label)}:</strong> {E(i.Value)}"));

    /// The whole mail: brand bar, title, body, footer with the home link (#728: a max-width div frame, no table).
    public static string Wrap(string title, string? subtitle, string bodyHtml, string? baseUrl, DateTime nowUtc, string? tenant = null)
    {
        var home = Link(baseUrl, "/");
        var homeLine = home is null ? $"<span data-mail-product-home>{ProProductName}</span>" : $"<a href=\"{E(home)}\" style=\"color:{Blue};\" data-mail-home>Open SecurityInsight</a>";
        var when = nowUtc.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";
        var line2 = string.IsNullOrWhiteSpace(tenant) ? when : $"{tenant} · {when}";
        var brand = $"invardia <span style=\"color:{Wordmark};font-weight:600;\" data-mail-product>{ProProductName}</span><br><span style=\"font-size:12px;font-weight:400;color:#cfdce8;\">{E(line2)}</span>";
        return SI.Management.Core.Mail.MailLayout.Frame(brand, title, subtitle, bodyHtml,
            $"{homeLine} &middot; you receive this as a SecurityInsight mail recipient; an Admin changes what you get on the Notifications page.");
    }
}