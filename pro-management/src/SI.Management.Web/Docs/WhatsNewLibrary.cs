using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SI.Management.Web.Docs;

/// <summary>
/// WHAT'S NEW (framework WHATS-NEW-1, owner 2026-11-13: "all solutions have a whats new which is human friendly info from
/// release notes. structure in fix and new features must be in gui"). Every release's whats-new\&lt;version&gt;.json ships
/// INSIDE the web app: release\Update-SIWhatsNew.ps1 copies the solution's whats-new\ folder into WhatsNew\ (a test holds
/// the copy to the folder) and the build embeds it, so every install -- Pro and Community, also one without contact -- shows
/// the releases up to the one it runs. Help &gt; What's new serves the files as they are (<see cref="FilesJson"/>) and
/// Invardia's renderer (wwwroot/lib/whatsnew/whats-new.js, unchanged) draws them; nothing here re-implements the layout.
/// The server reads only what the menu's "New" badge needs: the newest version (<see cref="Newest"/>).
/// </summary>
public sealed class WhatsNewLibrary
{
    public const string ResourcePrefix = "WhatsNew/";
    /// The product key of the "New" badge's seen-marker in the browser (whats-new.js: invardia-whatsnew-last-seen:&lt;product&gt;).
    public const string Product = "securityinsight";
    public const string ProductName = "SecurityInsight";
    public const string FilesHref = "/WhatsNew?handler=Files";

    private static readonly Lazy<WhatsNewLibrary> _shipped = new(() => FromAssembly(typeof(WhatsNewLibrary).Assembly));
    /// The files embedded in this build of the web app.
    public static WhatsNewLibrary Shipped => _shipped.Value;

    private static readonly Regex VersionPattern = new(@"^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]{1,30})?$", RegexOptions.CultureInvariant);

    /// The versions shipped, newest first.
    public IReadOnlyList<string> Versions { get; }
    /// The newest version shipped ("" when none) -- what the menu's badge compares with the last one opened.
    public string Newest => Versions.Count > 0 ? Versions[0] : "";
    /// Every file as a JSON array (newest first), each file's own JSON unchanged -- what the page hands the renderer.
    public string FilesJson { get; }
    /// Files left out because they are not JSON objects with a version (never thrown; the renderer also skips bad files).
    public IReadOnlyList<string> Problems { get; }

    /// The files from the embedded resources of <paramref name="asm"/> ("WhatsNew/3.1.16.json").
    public static WhatsNewLibrary FromAssembly(Assembly asm)
    {
        var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in asm.GetManifestResourceNames().Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal) && n.EndsWith(".json", StringComparison.OrdinalIgnoreCase)))
        {
            using var s = asm.GetManifestResourceStream(name)!;
            using var ms = new MemoryStream();
            s.CopyTo(ms);
            files[name[ResourcePrefix.Length..]] = ms.ToArray();
        }
        return FromFiles(files);
    }

    /// The files keyed by their name ("3.1.16.json").
    public static WhatsNewLibrary FromFiles(IReadOnlyDictionary<string, byte[]> files) => new(files);

    private WhatsNewLibrary(IReadOnlyDictionary<string, byte[]> files)
    {
        var problems = new List<string>();
        var good = new List<(string Version, string Json)>();
        foreach (var (name, bytes) in files.OrderBy(f => f.Key, StringComparer.Ordinal))
        {
            var text = Encoding.UTF8.GetString(bytes).TrimStart('﻿');
            try
            {
                using var doc = JsonDocument.Parse(text);
                if (doc.RootElement.ValueKind != JsonValueKind.Object
                    || !doc.RootElement.TryGetProperty("version", out var v) || v.ValueKind != JsonValueKind.String
                    || v.GetString() is not { } version || !VersionPattern.IsMatch(version))
                { problems.Add(name + ": no release version"); continue; }
                good.Add((version, doc.RootElement.GetRawText()));
            }
            catch (JsonException) { problems.Add(name + ": not valid JSON"); }
        }
        good.Sort((a, b) => Compare(b.Version, a.Version));
        Versions = good.Select(g => g.Version).ToList();
        FilesJson = "[" + string.Join(",", good.Select(g => g.Json)) + "]";
        Problems = problems;
    }

    /// Release versions compared part by part, digits as numbers (the order of whats-new.js compareWhatsNewVersion).
    public static int Compare(string a, string b)
    {
        var pa = a.Split('.', '-'); var pb = b.Split('.', '-');
        for (var i = 0; i < Math.Max(pa.Length, pb.Length); i++)
        {
            if (i >= pa.Length) return -1;
            if (i >= pb.Length) return 1;
            int c;
            if (System.Numerics.BigInteger.TryParse(pa[i], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var x)
                && System.Numerics.BigInteger.TryParse(pb[i], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var y))
                c = x.CompareTo(y);
            else c = string.CompareOrdinal(pa[i], pb[i]);
            if (c != 0) return Math.Sign(c);
        }
        return 0;
    }
}
