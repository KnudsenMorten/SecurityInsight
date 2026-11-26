using System.Security.Cryptography;
using System.Text;

namespace SI.Management.Web.Pages;

/// <summary>
/// ONE version stamp for every page module (3.1.50 live, owner 2026-11-25: a page loaded a new main.js but the modules it
/// imports -- ./tables.js, ./rule-kinds.js ... -- had no version, so a browser could mix a new file with an old cached one).
/// The layout loads main.js from <c>/js/v/&lt;stamp&gt;/app/main.js</c>; every import inside it is relative ("./x.js", static
/// and dynamic alike), so the browser asks <c>/js/v/&lt;stamp&gt;/app/x.js</c> for each -- the stamp carries through the whole
/// module graph without a list of files or an import map (an inline import map is refused by the CSP anyway).
/// The stamp is the SHA-256 of the files under wwwroot/js (paths + contents), 12 hex: it changes exactly when a script does.
/// <see cref="Middleware"/> serves <c>/js/v/&lt;any&gt;/...</c> as <c>/js/...</c> (an old page's stamp still gets the
/// files); the current stamp is cached for good (the URL changes with the content), any other stamp is not cached.
/// </summary>
public static class AppScripts
{
    public const string Prefix = "/js/v/";
    public static string Stamp { get; private set; } = "dev";

    /// The address a page loads a script module from, e.g. Url("app/main.js") = /js/v/0123456789ab/app/main.js.
    public static string Url(string underJs) => Prefix + Stamp + "/" + underJs.TrimStart('/');

    public static void Init(string? webRoot)
    {
        var js = webRoot is null ? null : Path.Combine(webRoot, "js");
        if (js is null || !Directory.Exists(js)) return;
        Stamp = Compute(js);
    }

    /// PURE over the folder: the same files give the same stamp, any changed byte or file name another.
    public static string Compute(string jsFolder)
    {
        using var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var f in Directory.EnumerateFiles(jsFolder, "*", SearchOption.AllDirectories)
                     .Select(f => (Rel: Path.GetRelativePath(jsFolder, f).Replace('\\', '/'), Full: f))
                     .OrderBy(x => x.Rel, StringComparer.Ordinal))
        {
            h.AppendData(Encoding.UTF8.GetBytes(f.Rel + "\n"));
            h.AppendData(File.ReadAllBytes(f.Full));
            h.AppendData(new byte[] { 0 });
        }
        return Convert.ToHexString(h.GetHashAndReset()).ToLowerInvariant()[..12];
    }

    /// Before the static files: /js/v/&lt;stamp&gt;/rest -> /js/rest.
    public static Task Middleware(HttpContext ctx, Func<Task> next)
    {
        var p = ctx.Request.Path.Value;
        if (p is not null && p.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        {
            var rest = p[Prefix.Length..];
            var slash = rest.IndexOf('/');
            if (slash > 0)
            {
                var stamp = rest[..slash];
                ctx.Request.Path = "/js/" + rest[(slash + 1)..];
                // behind sign-in: private; the current stamp's content never changes under its URL
                ctx.Response.Headers.CacheControl = string.Equals(stamp, Stamp, StringComparison.Ordinal)
                    ? "private, max-age=31536000, immutable" : "no-cache";
            }
        }
        return next();
    }
}
