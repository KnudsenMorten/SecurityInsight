using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Data;

namespace SI.Management.Web.Changes;

/// <summary>
/// THE RELEASE THIS INSTALL RUNS, for the header's version pill (owner 2026-10-19, an install's header read
/// "v3.0.0-rc.1318" while it ran release 3.0.0.202610190750): cfg.InstallState 'EngineFingerprint' $.version -- the version
/// the updater read back after it installed the release. The web image is content-hashed: a release that does not change
/// the web code keeps the image, and with it the build number baked into it, so the image's own version is shown only when
/// the database cannot be read or holds no release yet. Read once a minute at most; never fails a page.
/// </summary>
public sealed class InstalledRelease(ISqlExecutor sql, IMemoryCache cache, ILogger<InstalledRelease> log)
{
    public const string Sql = """
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'EngineFingerprint';
""";

    /// The installed release ("3.0.0.202610190750"), or null (not recorded, or the database could not be read).
    public async Task<string?> ReadAsync(CancellationToken ct) =>
        await cache.GetOrCreateAsync("header:installed-release", async e =>
        {
            e.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1);
            try { return VersionOf((await sql.QueryAsync(Sql, new Dictionary<string, object?>(), ct)).FirstOrDefault()?.Str("Value")); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                log.LogWarning(ex, "the installed release could not be read; the header shows the web image's own version");
                return null;
            }
        });

    /// PURE. The 'version' of the fingerprint's JSON, or null.
    public static string? VersionOf(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var d = JsonDocument.Parse(json);
            return d.RootElement.ValueKind == JsonValueKind.Object && d.RootElement.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String
                   && v.GetString() is { } s && s.Trim().Length > 0 ? s.Trim() : null;
        }
        catch (JsonException) { return null; }
    }

    /// What the pill says: the installed release, else the image's version -- SHORT (#919, owner 2026-10-28): a release
    /// numbered the old way, 3.0.0.&lt;yyyyMMddHHmm&gt;, shows as 3.0.0; the build / date is in the tooltip (Tooltip).
    public static string Shown(string? installed, string imageVersion) => Short(installed ?? imageVersion);

    /// PURE. #919: "3.0.0.202610272235" -> "3.0.0" (a fourth part of 8 digits or more is a build stamp, never shown in the
    /// pill); "3.0.1", "3.0.0-rc.1318" and anything else stay as they are.
    public static string Short(string? version)
    {
        var v = (version ?? "").Trim();
        var m = System.Text.RegularExpressions.Regex.Match(v, @"^(\d+\.\d+\.\d+)\.\d{8,}$");
        return m.Success ? m.Groups[1].Value : v;
    }

    /// The pill's tooltip: the release (in full, its build stamp with it), the web build and when it was built, the engine version.
    public static string Tooltip(string? installed, BuildIdentityText web) =>
        "SecurityInsight release " + (installed ?? web.Version + " (the web app's own version: the installed release could not be read)")
        + " · web build " + web.Build + (string.IsNullOrWhiteSpace(web.Built) ? "" : " (" + web.Built + ")") + " · engine " + (installed ?? "not recorded");
}

/// The web app's own build, as the pill's tooltip names it (#919: and when it was built -- the date is never in the pill).
public sealed record BuildIdentityText(string Version, string Build, string Built = "");
