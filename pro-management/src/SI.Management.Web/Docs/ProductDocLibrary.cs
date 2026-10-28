using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Docs;

/// One page of the shipped documentation, rendered once (safe HTML, see <see cref="SafeMarkdown"/>).
public sealed record DocPage(string Slug, string Title, int Order, string Html, IReadOnlyList<DocHeading> Headings, IReadOnlyList<DocSection> Sections)
{
    public string Href => ProductDocLibrary.HrefOf(Slug);
    public bool HasAnchor(string anchor) => Headings.Any(h => h.Anchor == anchor);
}

/// The words under one heading (for search): the heading, its anchor and its plain text.
public sealed record DocSection(string Heading, string Anchor, string Text);

/// A link to a place in the shipped documentation ("More info" of a setting, a search hit).
public sealed record DocLink(string Slug, string? Anchor, string PageTitle, string? HeadingText)
{
    public string Href => ProductDocLibrary.HrefOf(Slug) + (string.IsNullOrEmpty(Anchor) ? "" : "#" + Anchor);
    public string Text => HeadingText is { Length: > 0 } h && h != PageTitle ? PageTitle + ": " + h : PageTitle;
}

/// One search hit: the page, the section and a short piece of its text.
public sealed record DocHit(DocPage Page, DocSection Section, string Snippet)
{
    public string Href => Page.Href + (Section.Anchor.Length > 0 ? "#" + Section.Anchor : "");
}

/// <summary>
/// #679 THE DOCUMENTATION THAT SHIPS WITH THIS VERSION. The pages Invardia publishes for a version (the hand-over docs
/// pack: docs.json + *.md + images\) are copied into ProductDocs\ by setup\Import-SIProductDocs.ps1 and EMBEDDED in the
/// web app at build time, so every install -- also one on a private network, without contact -- reads the pages of the
/// version it runs, and the Documentation page never fetches anything from outside.
/// ProductDocs\more-info.json (SecurityInsight's own) says which settings a page explains: per Settings-page category
/// (the catalog's categories) and per setting. A link is offered only when its page and anchor exist in the shipped
/// pages -- a setting without a page shows no link, never a dead one.
/// </summary>
public sealed class ProductDocLibrary
{
    public const string ResourcePrefix = "ProductDocs/";
    /// The published pages on Invardia's site -- only ever a link the reader may follow; the web app never calls it.
    public const string PublishedUrl = "https://invardia.com/docs/securityinsight/";
    /// One page of the published documentation (the same slug): https://invardia.com/docs/securityinsight/<page>/.
    public static string PublishedUrlOf(string slug) => PublishedUrl + Uri.EscapeDataString(slug) + "/";

    private static readonly Lazy<ProductDocLibrary> _shipped = new(() => FromAssembly(typeof(ProductDocLibrary).Assembly));
    /// The pages embedded in this build of the web app.
    public static ProductDocLibrary Shipped => _shipped.Value;

    private readonly Dictionary<string, DocPage> _bySlug;
    private readonly Dictionary<string, byte[]> _images;
    private readonly Dictionary<string, string> _categoryLinks;
    private readonly Dictionary<string, string> _settingLinks;

    public string Version { get; }
    public IReadOnlyList<DocPage> Pages { get; }
    /// Problems found while loading (a page listed but missing, unreadable docs.json) -- shown to an Admin, never thrown.
    public IReadOnlyList<string> Problems { get; }

    public static string HrefOf(string slug) => "/Docs/" + Uri.EscapeDataString(slug);
    public static string ImageHref(string name) => "/Docs?handler=Image&name=" + Uri.EscapeDataString(name);

    /// The library from the embedded resources of <paramref name="asm"/> ("ProductDocs/docs.json", "ProductDocs/x.md",
    /// "ProductDocs/images/y.png", "ProductDocs/more-info.json").
    public static ProductDocLibrary FromAssembly(Assembly asm)
    {
        var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in asm.GetManifestResourceNames().Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal)))
        {
            using var s = asm.GetManifestResourceStream(name)!;
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            files[name[ResourcePrefix.Length..].Replace('\\', '/')] = ms.ToArray();
        }
        return FromFiles(files);
    }

    /// The library from files keyed by their path inside ProductDocs ("docs.json", "guards.md", "images/a.png").
    public static ProductDocLibrary FromFiles(IReadOnlyDictionary<string, byte[]> files) => new(files);

    private ProductDocLibrary(IReadOnlyDictionary<string, byte[]> files)
    {
        var problems = new List<string>();
        string Text(string path) => files.TryGetValue(path, out var b) ? Encoding.UTF8.GetString(b).TrimStart('﻿') : "";

        _images = files.Where(kv => kv.Key.StartsWith("images/", StringComparison.OrdinalIgnoreCase) && IsImageName(kv.Key["images/".Length..]))
            .ToDictionary(kv => kv.Key["images/".Length..], kv => kv.Value, StringComparer.OrdinalIgnoreCase);

        // the page list
        var entries = new List<(string Slug, string Title, int Order, string File)>();
        var version = "";
        try
        {
            using var doc = JsonDocument.Parse(Text("docs.json") is { Length: > 0 } j ? j : "{}");
            if (doc.RootElement.TryGetProperty("version", out var v)) version = v.GetString() ?? "";
            if (doc.RootElement.TryGetProperty("pages", out var ps) && ps.ValueKind == JsonValueKind.Array)
                foreach (var p in ps.EnumerateArray())
                {
                    var slug = p.TryGetProperty("slug", out var s) ? s.GetString() ?? "" : "";
                    var file = p.TryGetProperty("file", out var f) ? f.GetString() ?? "" : "";
                    var title = p.TryGetProperty("title", out var t) ? t.GetString() ?? slug : slug;
                    var order = p.TryGetProperty("order", out var o) && o.TryGetInt32(out var oi) ? oi : 999;
                    if (!Regex.IsMatch(slug, "^[a-z0-9][a-z0-9-]{0,63}$")) { problems.Add($"docs.json: the slug '{slug}' is not plain -- left out"); continue; }
                    if (entries.Any(x => x.Slug == slug)) { problems.Add($"docs.json lists the slug '{slug}' twice -- the second left out"); continue; }
                    if (!files.ContainsKey(file)) { problems.Add($"docs.json lists {file}, which is not shipped -- left out"); continue; }
                    entries.Add((slug, title, order, file));
                }
        }
        catch (JsonException e) { problems.Add("docs.json is not readable: " + e.Message); }
        Version = version;

        // headings first (links between pages resolve against every page's anchors), then the pages
        var anchors = entries.ToDictionary(e => e.Slug, e => SafeMarkdown.Headings(Text(e.File)).Select(h => h.Anchor).ToHashSet(StringComparer.Ordinal), StringComparer.Ordinal);
        var pages = new List<DocPage>();
        foreach (var e in entries)
        {
            var md = Text(e.File);
            string? ResolveLink(string target)
            {
                var t = target.Trim();
                var hash = t.IndexOf('#');
                var slug = hash < 0 ? t : t[..hash];
                var anchor = hash < 0 ? "" : t[(hash + 1)..];
                if (slug.EndsWith(".md", StringComparison.OrdinalIgnoreCase)) slug = slug[..^3];
                if (slug.Length == 0) slug = e.Slug;
                if (!anchors.TryGetValue(slug, out var set)) return null;
                if (anchor.Length > 0 && !set.Contains(anchor)) return null;
                return (slug == e.Slug && anchor.Length > 0 && hash == 0 ? "" : HrefOf(slug)) + (anchor.Length > 0 ? "#" + anchor : "");
            }
            string? ResolveImage(string src)
            {
                var name = src.Trim();
                if (name.StartsWith("./", StringComparison.Ordinal)) name = name[2..];
                if (!name.StartsWith("images/", StringComparison.OrdinalIgnoreCase)) return null;
                name = name["images/".Length..];
                return IsImageName(name) && _images.ContainsKey(name) ? ImageHref(name) : null;
            }
            var (html, headings) = SafeMarkdown.Render(md, ResolveLink, ResolveImage);
            pages.Add(new DocPage(e.Slug, e.Title, e.Order, html, headings, Sections(md, headings)));
        }
        Pages = pages.OrderBy(p => p.Order).ThenBy(p => p.Title, StringComparer.OrdinalIgnoreCase).ToList();
        _bySlug = Pages.ToDictionary(p => p.Slug, StringComparer.Ordinal);

        // which settings a page explains (SecurityInsight's own map)
        _categoryLinks = new(StringComparer.OrdinalIgnoreCase);
        _settingLinks = new(StringComparer.OrdinalIgnoreCase);
        if (Text("more-info.json") is { Length: > 0 } mi)
        {
            try
            {
                using var doc = JsonDocument.Parse(mi);
                void Read(string prop, Dictionary<string, string> into)
                {
                    if (!doc.RootElement.TryGetProperty(prop, out var o) || o.ValueKind != JsonValueKind.Object) return;
                    foreach (var kv in o.EnumerateObject()) if (kv.Value.ValueKind == JsonValueKind.String) into[kv.Name] = kv.Value.GetString()!;
                }
                Read("categories", _categoryLinks);
                Read("settings", _settingLinks);
            }
            catch (JsonException e) { problems.Add("more-info.json is not readable: " + e.Message); }
        }
        Problems = problems;
    }

    public static bool IsImageName(string name) => Regex.IsMatch(name, @"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}\.(png|jpg|jpeg|gif|webp)$", RegexOptions.IgnoreCase);

    public static string ContentTypeOf(string name) => Path.GetExtension(name).ToLowerInvariant() switch
    {
        ".png" => "image/png", ".jpg" or ".jpeg" => "image/jpeg", ".gif" => "image/gif", ".webp" => "image/webp", _ => "application/octet-stream",
    };

    public DocPage? Find(string? slug) => slug is not null && _bySlug.TryGetValue(slug, out var p) ? p : null;

    public byte[]? Image(string? name) => name is not null && IsImageName(name) && _images.TryGetValue(name, out var b) ? b : null;

    /// The place "slug" or "slug#anchor" names, or null when that page or anchor is not shipped.
    public DocLink? Resolve(string? target)
    {
        if (string.IsNullOrWhiteSpace(target)) return null;
        var hash = target.IndexOf('#');
        var slug = hash < 0 ? target : target[..hash];
        var anchor = hash < 0 ? null : target[(hash + 1)..];
        if (Find(slug) is not { } page) return null;
        if (string.IsNullOrEmpty(anchor)) return new DocLink(page.Slug, null, page.Title, null);
        var h = page.Headings.FirstOrDefault(x => x.Anchor == anchor);
        return h is null ? null : new DocLink(page.Slug, anchor, page.Title, h.Text);
    }

    /// "More info" of a setting: the page (and anchor) that explains it -- the setting's own entry, else its Settings-page
    /// category's -- or null when none is shipped. Never a link to a page or anchor that does not exist.
    public DocLink? MoreInfoFor(string settingName, string? category) =>
        (_settingLinks.TryGetValue(settingName, out var t) ? Resolve(t) : null)
        ?? (category is not null && _categoryLinks.TryGetValue(category, out var c) ? Resolve(c) : null);

    /// Every entry of more-info.json whose page or anchor is not shipped ("categories: X -> y#z") -- the tests keep it empty.
    public IReadOnlyList<string> UnresolvedMoreInfo() =>
        _categoryLinks.Where(kv => Resolve(kv.Value) is null).Select(kv => $"categories: {kv.Key} -> {kv.Value}")
            .Concat(_settingLinks.Where(kv => Resolve(kv.Value) is null).Select(kv => $"settings: {kv.Key} -> {kv.Value}")).ToList();

    public IReadOnlyDictionary<string, string> CategoryLinks => _categoryLinks;
    public IReadOnlyDictionary<string, string> SettingLinks => _settingLinks;

    /// Every word of <paramref name="query"/> in one section (heading or text), at most <paramref name="max"/> hits, in page order.
    public IReadOnlyList<DocHit> Search(string? query, int max = 50)
    {
        var words = (query ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Where(w => w.Length > 0).Take(8).ToArray();
        if (words.Length == 0) return Array.Empty<DocHit>();
        var hits = new List<DocHit>();
        foreach (var p in Pages)
            foreach (var s in p.Sections)
            {
                var all = s.Heading + " " + s.Text;
                if (!words.All(w => all.Contains(w, StringComparison.OrdinalIgnoreCase))) continue;
                hits.Add(new DocHit(p, s, Snippet(s.Text, words[0])));
                if (hits.Count >= max) return hits;
            }
        return hits;
    }

    private static string Snippet(string text, string word)
    {
        var at = text.IndexOf(word, StringComparison.OrdinalIgnoreCase);
        if (at < 0) return text.Length <= 200 ? text : text[..200] + " ...";
        var from = Math.Max(0, at - 80);
        var to = Math.Min(text.Length, at + word.Length + 120);
        return (from > 0 ? "... " : "") + text[from..to] + (to < text.Length ? " ..." : "");
    }

    /// The page's text split at its headings (the same anchors as the rendered page), as plain words.
    private static IReadOnlyList<DocSection> Sections(string md, IReadOnlyList<DocHeading> headings)
    {
        var sections = new List<DocSection>();
        var lines = md.Replace("\r\n", "\n").Split('\n');
        var hx = 0;
        string head = "", anchor = "";
        var text = new StringBuilder();
        var inFence = false;
        void Flush() { if (head.Length > 0 || text.Length > 0) sections.Add(new DocSection(head, anchor, Regex.Replace(text.ToString(), @"\s+", " ").Trim())); text.Clear(); }
        foreach (var l in lines)
        {
            if (Regex.IsMatch(l, @"^\s{0,3}(```|~~~)")) { inFence = !inFence; continue; }
            if (!inFence && Regex.IsMatch(l, @"^\s{0,3}#{1,6}\s") && hx < headings.Count)
            {
                Flush();
                head = headings[hx].Text; anchor = headings[hx].Anchor; hx++;
                continue;
            }
            var t = inFence ? l : SafeMarkdown.Plain(Regex.Replace(l, @"^\s*([-*+]|\d+[.)]|>|\|)\s*", "").Replace("|", " "));
            if (Regex.IsMatch(t, @"^[\s:|-]+$")) continue;
            text.Append(t).Append(' ');
        }
        Flush();
        return sections;
    }
}
