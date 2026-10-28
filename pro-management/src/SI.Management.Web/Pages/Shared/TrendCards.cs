using System.Globalization;
using System.Text;

namespace SI.Management.Web.Pages;

/// <summary>
/// Trend cards (#334): one card per group (a tier, a severity, a domain) instead of one multi-line chart. Each card shows
/// the group's value on the newest day BIG, its change against the previous day and against 7 days before, and a
/// sparkline over the period on the card's OWN y-scale -- so a group at 45 reads as clearly as one at 8,205, which one
/// shared axis cannot do. Rendered by <c>Pages/Shared/_TrendCards.cshtml</c>; hover / focus on a sparkline is
/// <c>wwwroot/js/app/sparkline.js</c>. No chart library.
/// </summary>
public sealed record TrendCardSet(string Id, string AriaLabel, IReadOnlyList<DateOnly> Days, IReadOnlyList<TrendCard> Cards,
    TrendValueKind Kind = TrendValueKind.Count, bool LowerIsBetter = true)
{
    /// No day at all in the period: the partial says "No data yet" instead of empty cards.
    public bool Empty => Days.Count == 0;
}

/// <summary>One card. <c>Values</c> line up with the set's <c>Days</c> (null = no value that day). <c>Tone</c> is the
/// colour class (t0..t3 / tu = the tier tokens of the Tier board; sev-vh / sev-h / sev-m / sev-l; s1.. = a series
/// slot). <c>Href</c>: where a click on the card goes (the findings of that group).</summary>
public sealed record TrendCard(string Key, string Label, string Tone, string? Href, IReadOnlyList<double?> Values);

public enum TrendValueKind { Count, Score }

public enum TrendTone { Good, Bad, Neutral }

/// <summary>A change between two values: the difference, the percentage of the earlier value (null when that was 0)
/// and whether it is good, bad or neither for this measure.</summary>
public sealed record TrendChange(double Delta, double? Percent, TrendTone Tone, DateOnly Against)
{
    public string Arrow => Delta > 0 ? "▲" : Delta < 0 ? "▼" : "=";
    public string ToneClass => Tone switch { TrendTone.Good => "good", TrendTone.Bad => "bad", _ => "neutral" };
    /// The word a screen reader hears after the numbers ("better" / "worse" / "unchanged").
    public string Meaning => Tone switch { TrendTone.Good => "better", TrendTone.Bad => "worse", _ => "unchanged" };
}

/// <summary>A sparkline: the SVG path on the card's own scale + the raw points the script reads for hover / focus.</summary>
public sealed record Sparkline(string Path, double Min, double Max, IReadOnlyList<(double X, double Y)?> Points);

public static class TrendCardMath
{
    public const double Width = 120, Height = 36, Pad = 3;

    /// The index of the newest day that has a value (-1 = none).
    public static int LastIndex(TrendCard c)
    {
        for (var i = c.Values.Count - 1; i >= 0; i--) if (c.Values[i] is not null) return i;
        return -1;
    }

    /// The card's newest value (null = no data yet).
    public static double? Today(TrendCard c) => LastIndex(c) is var i and >= 0 ? c.Values[i] : null;

    /// The newest day the card has a value for.
    public static DateOnly? TodayDay(TrendCardSet s, TrendCard c) => LastIndex(c) is var i and >= 0 ? s.Days[i] : null;

    /// Against the day before the newest one in the series (the previous collection day). Null with a single day.
    public static TrendChange? VsPreviousDay(TrendCardSet s, TrendCard c)
    {
        var i = LastIndex(c);
        if (i < 1 || c.Values[i - 1] is not { } then) return null;
        return Change(c.Values[i]!.Value, then, s.LowerIsBetter, s.Days[i - 1]);
    }

    /// Against 7 days before the newest day: that day, or the newest day with a value on or before it. Null when the
    /// period holds no day that old (a new installation, a gap).
    public static TrendChange? VsWeekAgo(TrendCardSet s, TrendCard c)
    {
        var i = LastIndex(c);
        if (i < 1) return null;
        var target = s.Days[i].AddDays(-7);
        for (var j = i - 1; j >= 0; j--)
            if (s.Days[j] <= target && c.Values[j] is { } then) return Change(c.Values[i]!.Value, then, s.LowerIsBetter, s.Days[j]);
        return null;
    }

    /// The change from <paramref name="then"/> to <paramref name="now"/>. For findings and risk scores DOWN is good.
    public static TrendChange Change(double now, double then, bool lowerIsBetter, DateOnly against)
    {
        var d = now - then;
        if (Math.Abs(d) < 1e-9) d = 0;
        var tone = d == 0 ? TrendTone.Neutral : (d < 0) == lowerIsBetter ? TrendTone.Good : TrendTone.Bad;
        return new TrendChange(d, then != 0 ? d / Math.Abs(then) * 100 : null, tone, against);
    }

    /// The sparkline on the card's OWN scale: its lowest value at the bottom, its highest at the top; a flat line sits in
    /// the middle. A day without a value breaks the line.
    public static Sparkline Spark(TrendCard c)
    {
        var vals = c.Values.Where(v => v is not null).Select(v => v!.Value).ToList();
        var min = vals.Count > 0 ? vals.Min() : 0;
        var max = vals.Count > 0 ? vals.Max() : 0;
        var n = c.Values.Count;
        var pts = new List<(double X, double Y)?>(n);
        var sb = new StringBuilder();
        var pen = false;
        for (var i = 0; i < n; i++)
        {
            if (c.Values[i] is not { } v) { pts.Add(null); pen = false; continue; }
            var x = n == 1 ? Width / 2 : Pad + i * (Width - 2 * Pad) / (n - 1);
            var y = max > min ? Pad + (Height - 2 * Pad) * (1 - (v - min) / (max - min)) : Height / 2;
            pts.Add((Math.Round(x, 2), Math.Round(y, 2)));
            sb.Append(pen ? " L" : (sb.Length > 0 ? " M" : "M")).Append(R(x)).Append(' ').Append(R(y));
            pen = true;
        }
        return new Sparkline(sb.ToString(), min, max, pts);
    }

    /// A value as a person reads it, in the viewer's number format (BRAND-2.6).
    public static string Show(TrendCardSet s, double? v) =>
        v is not { } x ? "–" : s.Kind == TrendValueKind.Score ? Fmt.Score(x) : Fmt.Int((long)Math.Round(x));

    /// The change as text: "▲ 120 (+1.5%)", "▼ 3 (-25%)", "= 0". The arrow carries the sign; the number is the size.
    public static string ShowChange(TrendCardSet s, TrendChange ch)
    {
        if (ch.Delta == 0) return "= 0";
        var size = Show(s, Math.Abs(ch.Delta));
        if (ch.Percent is not { } p) return $"{ch.Arrow} {size}";
        var pct = Fmt.Pct(Math.Abs(p), Math.Abs(p) < 10 ? 1 : 0);
        return $"{ch.Arrow} {size} ({(p > 0 ? "+" : "-")}{pct})";
    }

    /// The raw numbers / ISO days for the script (invariant; never shown as they are).
    public static string RawValues(TrendCard c) => string.Join(",", c.Values.Select(v => Fmt.Raw(v)));
    public static string RawDays(TrendCardSet s) => string.Join(",", s.Days.Select(Fmt.Day));

    /// The tone class of a tier value ("0".."3" -> t0..t3, anything else = unclassified, tu) -- the Tier board's colours.
    public static string TierTone(string tier) => tier is "0" or "1" or "2" or "3" ? "t" + tier : "tu";

    /// The tone class of a severity, by rank (Very High / Critical, High, Medium-High + Medium, the rest).
    public static string SeverityTone(string severity) => SI.Management.Core.ProData.SeverityOrder.Rank(severity) switch
    {
        0 => "sev-vh", 1 => "sev-h", 2 or 3 => "sev-m", _ => "sev-l",
    };

    private static string R(double v) => Math.Round(v, 2).ToString("0.##", CultureInfo.InvariantCulture);
}
