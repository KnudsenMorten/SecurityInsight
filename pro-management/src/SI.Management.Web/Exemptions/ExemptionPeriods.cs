using System.Globalization;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Exemptions;

/// <summary>
/// The period of an exemption: a dropdown of 3 months / 6 months / 1 year / a custom end date (and "no end date" only
/// when the setting allows it), pre-selected from the default-period setting. An end date is the END of that day, UTC.
/// PURE: the clock is a parameter.
/// </summary>
public static class ExemptionPeriods
{
    public const string ThreeMonths = "3m";
    public const string SixMonths = "6m";
    public const string OneYear = "1y";
    public const string Custom = "custom";
    public const string NoEnd = "none";

    public static IReadOnlyList<(string Value, string Label)> Choices(bool allowOpenEnded)
    {
        var list = new List<(string, string)> { (ThreeMonths, "3 months"), (SixMonths, "6 months"), (OneYear, "1 year"), (Custom, "Custom end date") };
        if (allowOpenEnded) list.Add((NoEnd, "No end date"));
        return list;
    }

    /// The choice the dropdown opens on: the default period when it is one of the three, else a custom end date.
    public static string DefaultChoice(int defaultMonths) => defaultMonths switch { 3 => ThreeMonths, 6 => SixMonths, 12 => OneYear, _ => Custom };

    /// The custom date field's pre-filled value (yyyy-MM-dd): today + the default period.
    public static string DefaultCustomDate(int defaultMonths, DateTime nowUtc) =>
        nowUtc.Date.AddMonths(defaultMonths).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    public static DateTime EndOfDay(DateTime day) => DateTime.SpecifyKind(day.Date.AddDays(1).AddSeconds(-1), DateTimeKind.Utc);

    /// <summary>
    /// The end date a choice gives, or why it is refused. An empty choice = the default period (never "no end").
    /// Custom: a date after today, at most <see cref="ExemptionRepository.MaxExpiryDays"/> days ahead.
    /// </summary>
    public static (DateTime? ExpiresAt, string? Error) Resolve(string? choice, DateTime? customDate, ExemptionSettings.Values s, DateTime nowUtc)
    {
        var today = nowUtc.Date;
        switch ((choice ?? "").Trim().ToLowerInvariant())
        {
            case "":
                return (EndOfDay(today.AddMonths(s.DefaultMonths)), null);
            case ThreeMonths: return (EndOfDay(today.AddMonths(3)), null);
            case SixMonths: return (EndOfDay(today.AddMonths(6)), null);
            case OneYear: return (EndOfDay(today.AddYears(1)), null);
            case NoEnd:
                return s.AllowOpenEnded ? (null, null)
                    : (null, "an exemption needs an end date -- exemptions without one are not allowed here (setting " + ExemptionSettings.AllowOpenEnded + ")");
            case Custom:
                if (customDate is not { } d) return (null, "pick the custom end date");
                if (d.Date <= today) return (null, "the end date must be after today");
                if (d.Date > today.AddDays(ExemptionRepository.MaxExpiryDays)) return (null, $"the end date is more than {ExemptionRepository.MaxExpiryDays} days away");
                return (EndOfDay(d), null);
            default:
                return (null, $"'{choice}' is not a period (3m, 6m, 1y, custom)");
        }
    }

    public static string Describe(DateTime? expiresAt) =>
        expiresAt is { } e ? "until " + e.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "no end date";
}
