using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.Html;

namespace SI.Management.Web.Performance;

/// <summary>
/// The page's small charts, drawn on the server as inline SVG (no script, no library): a line over the hours of the last 7
/// days with the limit drawn as a dashed line, and bars for a step's time per run. Colours come from the theme (currentColor
/// and the CSS variables of app.css), so light and dark both work; each chart carries a plain-words label for screen readers.
/// </summary>
public static class PerfSvg
{
    private static string N(double v) => v.ToString("0.##", CultureInfo.InvariantCulture);

    /// A line of hourly values (percent, 0-100) over the given hours, with a dashed line at -limit.
    public static IHtmlContent Load(IReadOnlyList<(DateTime Hour, double Value)> points, double limit, string label, int width = 560, int height = 90)
    {
        var aria = WebUtility.HtmlEncode(label);
        if (points.Count == 0) return new HtmlString($"<p class=\"hint\" data-perf-chart=\"empty\">{aria}: not available yet.</p>");
        var first = points[0].Hour; var last = points[points.Count - 1].Hour;
        var span = Math.Max(1.0, (last - first).TotalHours);
        double X(DateTime h) => (h - first).TotalHours / span * (width - 2) + 1;
        double Y(double v) => height - 1 - Math.Clamp(v, 0, 100) / 100.0 * (height - 2);
        var line = string.Join(' ', points.Select(p => N(X(p.Hour)) + "," + N(Y(p.Value))));
        var ly = N(Y(limit));
        return new HtmlString(
            $"<svg class=\"perf-chart\" viewBox=\"0 0 {width} {height}\" preserveAspectRatio=\"none\" role=\"img\" aria-label=\"{aria}\" data-perf-chart=\"load\">" +
            $"<line class=\"perf-limit\" x1=\"0\" x2=\"{width}\" y1=\"{ly}\" y2=\"{ly}\" />" +
            $"<polyline class=\"perf-line\" points=\"{line}\" /></svg>");
    }

    /// Bars of a step's minutes per run (oldest first); a run it did not run well in is a gap.
    public static IHtmlContent Bars(IReadOnlyList<double?> minutes, string label, int width = 160, int height = 28)
    {
        var aria = WebUtility.HtmlEncode(label);
        var max = minutes.Where(m => m is not null).Select(m => m!.Value).DefaultIfEmpty(0).Max();
        if (minutes.Count == 0 || max <= 0) return new HtmlString("<span class=\"muted\">--</span>");
        var w = (double)width / minutes.Count;
        var bars = string.Concat(minutes.Select((m, i) => m is { } v
            ? $"<rect x=\"{N(i * w + 1)}\" y=\"{N(height - Math.Max(1, v / max * height))}\" width=\"{N(Math.Max(1, w - 2))}\" height=\"{N(Math.Max(1, v / max * height))}\" />"
            : ""));
        return new HtmlString($"<svg class=\"perf-bars\" viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"{aria}\" data-perf-chart=\"bars\">{bars}</svg>");
    }
}
