using System.Globalization;

namespace SI.Management.Core.ProData;

/// <summary>
/// THE ONE on-screen format of a number in the web app, in the VIEWER's regional format (the request's display
/// culture, CultureInfo.CurrentUICulture -- set from the browser's Accept-Language, en-US when unknown):
///   * a risk score (a finding's score, a weighted risk, an average, a highest) is a WHOLE number, rounded half away
///     from zero, grouped per culture: "2,293" (en-US) / "2.293" (da-DK);
///   * a count is grouped the same way: "12,205" / "12.205";
///   * any other number keeps one decimal when it has one, with the culture's decimal mark.
/// Only the DISPLAY changes: CSV is invariant (no grouping, "." decimal), Excel keeps real numbers, and tool answers
/// carry <see cref="Round"/> numbers.
/// </summary>
public static class ScoreFormat
{
    /// What an unknown score shows (no finding, or not recorded yet) -- never a misleading 0.
    public const string Unknown = "–";

    /// The viewer's display culture.
    public static CultureInfo Culture => CultureInfo.CurrentUICulture;

    public static string Whole(double? score) => Whole(score, Culture);

    public static string Whole(double? score, IFormatProvider culture) => score is { } s && double.IsFinite(s)
        ? Math.Round(s, MidpointRounding.AwayFromZero).ToString("N0", culture)
        : Unknown;

    /// A signed change of a score, whole: "+12", "-3", "0" (grouped per culture).
    public static string SignedWhole(double change) => SignedWhole(change, Culture);

    public static string SignedWhole(double change, IFormatProvider culture)
    {
        var r = Math.Round(change, MidpointRounding.AwayFromZero);
        return (r > 0 ? "+" : "") + r.ToString("N0", culture);
    }

    /// A count, grouped per culture.
    public static string Count(long n) => n.ToString("N0", Culture);

    /// Any other number: whole when it is whole, else one decimal -- in the viewer's format.
    public static string Number(double d) => Math.Abs(d % 1) < 1e-9 ? d.ToString("N0", Culture) : d.ToString("N1", Culture);

    /// The same number for a machine-readable file (CSV): invariant, no grouping, "." decimal.
    public static string Invariant(double d) => d.ToString("0.##", CultureInfo.InvariantCulture);

    /// The same rounding as a number, for answers that render a score (the chat / MCP tools).
    public static double? Round(double? score) => score is { } s && double.IsFinite(s) ? Math.Round(s, MidpointRounding.AwayFromZero) : null;
}
