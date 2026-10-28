using System.Globalization;
using Microsoft.AspNetCore.Html;

namespace SI.Management.Web.Pages;

/// <summary>
/// Times a person reads are shown in the BROWSER's time zone, never UTC (framework BRAND-2.10, SI #313). Stored UTC,
/// shown local: the server never converts (it does not know the viewer's zone) -- it writes the moment as UTC with a
/// machine-readable form, and ONE browser formatter (wwwroot/js/local-time.js) rewrites it in the viewer's zone,
/// daylight saving included, as <c>yyyy-MM-dd HH:mm</c> (BRAND-2.6). Two shapes, one formatter:
/// <list type="bullet">
/// <item><see cref="Tag"/> -- an element: <c>&lt;time datetime="2026-10-04T18:54:00Z" data-fmt="datetime"&gt;2026-10-04 18:54 UTC&lt;/time&gt;</c>.
/// The text inside is the fallback a browser without script shows (honest: it says UTC).</item>
/// <item><c>data-utc</c> on an element whose text or <c>title</c> holds server-written UTC times (<see cref="Text"/>:
/// "yyyy-MM-dd HH:mm UTC") -- for the places that cannot hold an element: an &lt;option&gt;'s text, a tooltip, a
/// sentence built in C#. The formatter rewrites every such time in place.</item>
/// </list>
/// A value whose Kind is Unspecified is UTC (SQL datetime2 columns are written with SYSUTCDATETIME()).
/// </summary>
public static class LocalTime
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    /// The formats the browser formatter knows: a date and time (the default), a date, a time of day, or "relative"
    /// ("5 min ago", the local date and time in its tooltip).
    public static readonly IReadOnlyList<string> Formats = new[] { "datetime", "date", "time", "relative" };

    public static DateTime Utc(DateTime d) => d.Kind switch
    {
        DateTimeKind.Utc => d,
        DateTimeKind.Local => d.ToUniversalTime(),
        _ => DateTime.SpecifyKind(d, DateTimeKind.Utc),
    };

    /// The moment as ISO 8601 UTC with the Z ("2026-10-04T18:54:00Z") -- the machine form in datetime="".
    public static string Iso(DateTime? v) => v is { } d ? Utc(d).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", Inv) : "";
    public static string Iso(DateTimeOffset? v) => v is { } o ? Iso(o.UtcDateTime) : "";

    /// The UTC fallback text ("2026-10-04 18:54 UTC"): what a browser without script shows, and the form the formatter
    /// finds inside a data-utc element. Never shown on its own to a person with script on.
    public static string Text(DateTime? v, string fmt = "datetime", bool seconds = false)
    {
        if (v is not { } d) return "";
        var u = Utc(d);
        var t = u.ToString(seconds ? "HH:mm:ss" : "HH:mm", Inv);
        return fmt switch
        {
            "date" => u.ToString("yyyy-MM-dd", Inv),
            "time" => t + " UTC",
            _ => u.ToString("yyyy-MM-dd", Inv) + " " + t + " UTC",
        };
    }
    public static string Text(DateTimeOffset? v, string fmt = "datetime", bool seconds = false) => Text(v?.UtcDateTime, fmt, seconds);

    /// <summary>
    /// The &lt;time&gt; element for a moment. <paramref name="zone"/> adds a small zone label (CEST) and the UTC value
    /// in the tooltip -- for audit and evidence views, where a screenshot may travel. A null moment renders
    /// <paramref name="empty"/> (plain text).
    /// </summary>
    public static IHtmlContent Tag(DateTime? v, string fmt = "datetime", bool zone = false, bool seconds = false, string empty = "")
    {
        if (v is null) return new HtmlString(System.Net.WebUtility.HtmlEncode(empty));
        if (!Formats.Contains(fmt)) throw new ArgumentOutOfRangeException(nameof(fmt), fmt, "datetime, date, time or relative");
        var attrs = $" datetime=\"{Iso(v)}\" data-fmt=\"{fmt}\"" + (zone ? " data-zone" : "") + (seconds ? " data-seconds" : "");
        return new HtmlString($"<time{attrs}>{Text(v, fmt == "relative" ? "datetime" : fmt, seconds)}</time>");
    }
    public static IHtmlContent Tag(DateTimeOffset? v, string fmt = "datetime", bool zone = false, bool seconds = false, string empty = "") =>
        Tag(v?.UtcDateTime, fmt, zone, seconds, empty);

    /// <summary>
    /// A day a person typed into a date filter (yyyy-MM-dd), read in THEIR zone (<paramref name="tz"/> = the browser's
    /// IANA zone, which the page sends with the form): the UTC moment that day starts. No zone, or one this server does
    /// not know, reads the day as UTC (the behaviour before BRAND-2.10). Null when the text is not a date.
    /// </summary>
    public static DateTime? DayStartUtc(string? day, string? tz)
    {
        if (string.IsNullOrWhiteSpace(day) || !DateTime.TryParseExact(day.Trim(), "yyyy-MM-dd", Inv, DateTimeStyles.None, out var d)) return null;
        var zone = Zone(tz);
        if (zone is null) return DateTime.SpecifyKind(d, DateTimeKind.Utc);
        var local = DateTime.SpecifyKind(d, DateTimeKind.Unspecified);
        while (zone.IsInvalidTime(local)) local = local.AddMinutes(30);   // a zone whose clocks jump at midnight
        return TimeZoneInfo.ConvertTimeToUtc(local, zone);
    }

    /// The browser's zone, when it names one this server knows (IANA ids work on every platform .NET 6+ runs on).
    public static TimeZoneInfo? Zone(string? tz)
    {
        if (string.IsNullOrWhiteSpace(tz) || tz.Length > 64) return null;
        try { return TimeZoneInfo.FindSystemTimeZoneById(tz.Trim()); }
        catch (TimeZoneNotFoundException) { return null; }
        catch (InvalidTimeZoneException) { return null; }
    }
}
