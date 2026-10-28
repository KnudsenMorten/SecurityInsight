using System.Globalization;
using System.Reflection;
using System.Text.Json;

namespace SI.Management.Web.Pages;

/// <summary>
/// What the header's version pill and the footer show: the SecurityInsight version this web app was built from --
/// "3.0.0-rc.12" for a pre-release build, "3.0.0" for the tagged release (operator 2026-10-05: "just show version, love the
/// prerelease idea"). It comes from BUILD.json, stamped ONCE when the image is built (Deploy-SIManagement.ps1 stages it,
/// the csproj copies it next to the app); without it, from the VERSION file stamped into the assembly. The build details
/// (commit, build time, channel, ring) are NOT in the header or footer -- they are on /about and the Help page, so support
/// can tell builds apart. Shown to signed-in people only -- the anonymous /healthz still says nothing about the version.
/// </summary>
public static class AppInfo
{
    public const string Product = "SecurityInsight Pro";
    public const string Vendor = "Invardia";
    /// Invardia's official routes (brand.ts): Pro support in the portal (or support@ -- a ticket per mail), info@ the one contact.
    public const string SupportUrl = "https://portal.invardia.com/";
    public const string SupportEmail = "support@invardia.com";
    public const string ContactEmail = "info@invardia.com";

    public static BuildIdentity Build { get; } = BuildIdentity.Load(Path.Combine(AppContext.BaseDirectory, "BUILD.json"), AssemblyVersion());

    /// The version the header + footer show ("3.0.0-rc.12" / "3.0.0"); "" when nothing is known.
    public static string Version => Build.Display;

    internal static string AssemblyVersion()
    {
        var a = typeof(AppInfo).Assembly;
        var v = a.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? a.GetName().Version?.ToString() ?? "";
        var plus = v.IndexOf('+');   // the SDK appends "+<commit>"; the pill shows the release only
        if (plus >= 0) v = v[..plus];
        return string.IsNullOrWhiteSpace(v) || v == "1.0.0" ? "" : v;
    }
}

/// <summary>The build this app is, read from BUILD.json (engine\_shared\SI-BuildInfo.ps1 writes it).</summary>
public sealed record BuildIdentity(string Version, string Display, string Commit, string ShortCommit, string BuiltUtc, int? Rc, string? Channel, int? Ring)
{
    /// True when a BUILD.json said which commit this is.
    public bool Known => ShortCommit.Length > 0;

    /// What tells two builds apart for the "new version, reload" banner (#345): the commit when BUILD.json names one,
    /// else the version shown. Every page carries it (html data-app-build); version-check.js compares it with /about's
    /// commit (or display) the same way -- so a redeploy of the same rc from a new commit is a new build too.
    public string Id => Commit.Length > 0 ? Commit : Display;

    /// #919: when this build was made ("2026-10-05 14:10 UTC"), "" when BUILD.json does not say -- the version pill's tooltip.
    public string BuiltText => DateTime.TryParse(BuiltUtc, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t)
        ? t.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC" : "";

    /// "build 0dc9062 · 2026-10-05 14:10 UTC · ring 1", or "build unknown".
    public string Line
    {
        get
        {
            if (!Known) return "build unknown";
            var parts = new List<string> { "build " + ShortCommit };
            if (DateTime.TryParse(BuiltUtc, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t))
                parts.Add(t.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC");
            if (Ring is not null) parts.Add("ring " + Ring.Value.ToString(CultureInfo.InvariantCulture));
            if (!string.IsNullOrWhiteSpace(Channel)) parts.Add("channel " + Channel);
            return string.Join(" · ", parts);
        }
    }

    public static BuildIdentity Load(string path, string fallbackVersion)
    {
        try { return Parse(File.Exists(path) ? File.ReadAllText(path) : null, fallbackVersion); }
        catch (IOException) { return Parse(null, fallbackVersion); }
        catch (UnauthorizedAccessException) { return Parse(null, fallbackVersion); }
    }

    /// PURE. BUILD.json's text (or null) -> the identity; anything unreadable degrades to the fallback version, "build unknown".
    public static BuildIdentity Parse(string? json, string fallbackVersion)
    {
        var fallback = new BuildIdentity(fallbackVersion, fallbackVersion, "", "", "", null, null, null);
        if (string.IsNullOrWhiteSpace(json)) return fallback;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var r = doc.RootElement;
            if (r.ValueKind != JsonValueKind.Object) return fallback;
            string S(string n) => r.TryGetProperty(n, out var e) && e.ValueKind == JsonValueKind.String ? e.GetString()!.Trim() : "";
            int? I(string n) => r.TryGetProperty(n, out var e) && e.ValueKind == JsonValueKind.Number && e.TryGetInt32(out var i) ? i : null;
            var version = S("version");
            if (version.Length == 0) return fallback;
            var display = S("display");
            var commit = S("commit");
            var shortCommit = S("shortCommit");
            if (shortCommit.Length == 0 && commit.Length >= 7) shortCommit = commit[..7];
            var channel = S("channel");
            return new BuildIdentity(version, display.Length > 0 ? display : version, commit, shortCommit, S("builtUtc"), I("rc"),
                channel.Length > 0 ? channel : null, I("ring"));
        }
        catch (JsonException) { return fallback; }
    }
}
