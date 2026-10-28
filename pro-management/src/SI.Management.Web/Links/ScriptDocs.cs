using System.Text;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Links;

/// <summary>
/// "What does this script do?" next to EVERY script command the web app shows (framework section 12.7 SCRIPT-DOC-1):
/// wherever a page names one of SecurityInsight's scripts (setup\Set-SIMail.ps1, diagnostics/Test-SIInstall.ps1, ...),
/// the link to that script's documentation page on invardia.com follows -- its purpose, what it changes, the permissions
/// it needs, its -WhatIf. Done ONCE, on the rendered page (<see cref="ScriptDocLinkMiddleware"/>), so a page, a notice
/// or an error text that names a script carries the link without each place having to remember it.
/// The page exists for every script named: tests\pester\SIv3-ScriptDocs.Tests.ps1 fails when the web app names a script
/// without a documentation manifest (release\script-docs\&lt;Script&gt;.doc.json).
/// </summary>
public static class ScriptDocs
{
    public const string BaseUrl = "https://invardia.com/docs/si/scripts/";
    public const string LinkText = "What does this script do?";

    /// The documentation page of one script: https://invardia.com/docs/si/scripts/&lt;Script&gt;/ (no .ps1, trailing slash).
    public static string Url(string script) => BaseUrl + Uri.EscapeDataString(script) + "/";

    // setup\X.ps1 or setup/X.ps1 (diagnostics too), not part of a longer path or URL
    private static readonly Regex Mention = new(@"(?<![\w./\\-])(?:setup|diagnostics)[\\/](?<name>[A-Z][a-z]+-(?:SI[A-Za-z]+|SecurityInsight))\.ps1\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly Regex Token = new(@"<!--.*?-->|<[^>]*>|[^<]+", RegexOptions.Compiled | RegexOptions.Singleline | RegexOptions.CultureInvariant);
    private static readonly Regex TagName = new(@"^<\s*(?<close>/)?\s*(?<name>[A-Za-z][A-Za-z0-9-]*)", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // raw text: copied as is; their text is never scanned
    private static readonly HashSet<string> Raw = new(StringComparer.OrdinalIgnoreCase) { "script", "style", "textarea", "title" };
    // text that cannot hold a link: a mention there gets none
    private static readonly HashSet<string> NoLink = new(StringComparer.OrdinalIgnoreCase) { "option", "select", "head" };
    // inline: the link waits until the block around them ends (never inside a <code> or another link)
    private static readonly HashSet<string> Inline = new(StringComparer.OrdinalIgnoreCase)
        { "a", "abbr", "b", "bdi", "br", "code", "em", "i", "kbd", "mark", "q", "s", "samp", "small", "span", "strong", "sub", "sup", "time", "u", "var", "wbr" };

    /// The script names a text mentions, in order, each once. PURE.
    public static IReadOnlyList<string> Scripts(string? text)
    {
        var seen = new List<string>();
        if (string.IsNullOrEmpty(text)) return seen;
        foreach (Match m in Mention.Matches(text)) { var n = m.Groups["name"].Value; if (!seen.Contains(n)) seen.Add(n); }
        return seen;
    }

    /// The link(s) for these scripts, as HTML: one script = "What does this script do?"; several = "What does X do?" each.
    public static string LinksHtml(IReadOnlyList<string> scripts)
    {
        var sb = new StringBuilder();
        foreach (var s in scripts)
        {
            var text = scripts.Count == 1 ? LinkText : "What does " + s + " do?";
            sb.Append(" <a class=\"script-doc\" data-script-doc=\"").Append(s).Append("\" href=\"").Append(Url(s))
              .Append("\" target=\"_blank\" rel=\"noopener noreferrer\">").Append(System.Net.WebUtility.HtmlEncode(text)).Append("</a>");
        }
        return sb.ToString();
    }

    /// <summary>
    /// PURE. The page with the documentation link after every block that names a script: the link follows the end of the
    /// sentence's block (the &lt;p&gt;, &lt;li&gt;, &lt;td&gt;, ...), never inside a &lt;code&gt;, a link or an attribute, and
    /// never in &lt;script&gt; / &lt;style&gt; / &lt;textarea&gt; / &lt;title&gt; / &lt;option&gt;. A page that already carries a
    /// script's link (data-script-doc) gets no second one for it.
    /// </summary>
    public static string Annotate(string html)
    {
        if (string.IsNullOrEmpty(html) || !Mention.IsMatch(html)) return html;
        var already = new HashSet<string>(Regex.Matches(html, "data-script-doc=\"([^\"]+)\"").Select(m => m.Groups[1].Value), StringComparer.Ordinal);
        var sb = new StringBuilder(html.Length + 256);
        var pending = new List<string>();
        string? rawUntil = null;
        var noLinkDepth = 0;
        void Flush()
        {
            if (pending.Count == 0) return;
            var fresh = pending.Where(p => !already.Contains(p)).ToList();
            if (fresh.Count > 0) sb.Append(LinksHtml(fresh));
            pending.Clear();
        }
        foreach (Match t in Token.Matches(html))
        {
            var s = t.Value;
            if (rawUntil is not null)
            {
                sb.Append(s);
                if (s.StartsWith("</", StringComparison.Ordinal) && TagName.Match(s) is { Success: true } rc && string.Equals(rc.Groups["name"].Value, rawUntil, StringComparison.OrdinalIgnoreCase)) rawUntil = null;
                continue;
            }
            if (s.StartsWith("<!--", StringComparison.Ordinal)) { sb.Append(s); continue; }
            if (s[0] == '<')
            {
                var tm = TagName.Match(s);
                if (tm.Success)
                {
                    var name = tm.Groups["name"].Value;
                    var closing = tm.Groups["close"].Success;
                    // a command block (<pre>) holds only the commands: its link goes NEXT to it, after </pre> (owner 2026-10-11)
                    if (closing && string.Equals(name, "pre", StringComparison.OrdinalIgnoreCase)) { sb.Append(s); Flush(); continue; }
                    if (!Inline.Contains(name)) Flush();          // a block starts or ends: the sentence before it is complete
                    sb.Append(s);
                    if (!closing && Raw.Contains(name) && !s.EndsWith("/>", StringComparison.Ordinal)) rawUntil = name;
                    if (NoLink.Contains(name)) noLinkDepth = Math.Max(0, noLinkDepth + (closing ? -1 : 1));
                    continue;
                }
                sb.Append(s);
                continue;
            }
            sb.Append(s);
            if (noLinkDepth > 0) continue;
            foreach (var n in Scripts(s)) if (!pending.Contains(n)) pending.Add(n);
        }
        Flush();
        return sb.ToString();
    }
}

/// <summary>
/// Puts <see cref="ScriptDocs.Annotate"/> on every HTML page the app renders. Anything that is not text/html (a download,
/// JSON, an event stream, a compressed body) passes untouched, and so does a page that names no script.
/// </summary>
public sealed class ScriptDocLinkMiddleware
{
    private readonly RequestDelegate _next;
    public ScriptDocLinkMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext ctx)
    {
        var original = ctx.Response.Body;
        await using var buffer = new MemoryStream();
        ctx.Response.Body = buffer;
        try { await _next(ctx); }
        finally { ctx.Response.Body = original; }

        buffer.Position = 0;
        var type = ctx.Response.ContentType ?? "";
        var html = type.StartsWith("text/html", StringComparison.OrdinalIgnoreCase) && !ctx.Response.Headers.ContainsKey("Content-Encoding");
        if (!html || buffer.Length == 0) { await buffer.CopyToAsync(original, ctx.RequestAborted); return; }
        var text = Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
        var annotated = ScriptDocs.Annotate(text);
        if (ReferenceEquals(annotated, text)) { await buffer.CopyToAsync(original, ctx.RequestAborted); return; }
        var bytes = Encoding.UTF8.GetBytes(annotated);
        if (!ctx.Response.HasStarted) ctx.Response.ContentLength = bytes.Length;
        await original.WriteAsync(bytes, ctx.RequestAborted);
    }
}

public static class ScriptDocLinkExtensions
{
    /// The documentation link next to every script a page names (<see cref="ScriptDocs"/>).
    public static IApplicationBuilder UseScriptDocLinks(this IApplicationBuilder app) => app.UseMiddleware<ScriptDocLinkMiddleware>();
}
