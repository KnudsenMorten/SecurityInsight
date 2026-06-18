namespace Sia.Core.Exec;

/// <summary>How often the scheduled exec-summary email fires.</summary>
public enum SendCadence
{
    /// <summary>Every day at the configured hour.</summary>
    Daily,
    /// <summary>Once a week (Monday) at the configured hour.</summary>
    Weekly,
    /// <summary>Once a month (1st of the month) at the configured hour - the board cadence.</summary>
    Monthly,
}

/// <summary>
/// Pure scheduling maths for the exec-summary email (no timers, no clock, no I/O - so it
/// is fully unit-testable). Given the cadence, the configured send-hour, the last send
/// time and "now", it answers "is a send due?" and "when is the next send?". The hosted
/// BackgroundService polls this; keeping the logic pure means the cadence is verified
/// without sleeping a thread.
/// </summary>
public static class EmailCadenceScheduler
{
    /// <summary>Parse a cadence string (daily | weekly | monthly). Unknown/empty =&gt; Monthly.</summary>
    public static SendCadence Parse(string? cadence) => (cadence ?? "").Trim().ToLowerInvariant() switch
    {
        "daily" => SendCadence.Daily,
        "weekly" => SendCadence.Weekly,
        _ => SendCadence.Monthly,
    };

    /// <summary>
    /// Is a scheduled send due at <paramref name="now"/>? True when we have crossed the
    /// most-recent scheduled fire time (cadence + hour) and have NOT already sent at or
    /// after that fire time.
    ///
    /// A null <paramref name="lastSent"/> is treated as "anchored - no baseline yet": the
    /// most-recent fire boundary is considered already handled, so a fresh start does NOT
    /// retroactively fire a window that elapsed before it began; the first send happens at
    /// the NEXT genuine boundary. (The hosted scheduler seeds its own baseline at startup.)
    /// </summary>
    public static bool IsDue(SendCadence cadence, int sendAtHour, DateTimeOffset? lastSent, DateTimeOffset now)
    {
        var fire = MostRecentFireTime(cadence, sendAtHour, now);
        if (now < fire) return false;             // the latest fire time is still in the future
        if (lastSent is null) return false;       // anchored: wait for the next boundary
        return lastSent.Value < fire;             // due iff we have not already sent in this window
    }

    /// <summary>The next time a send will fire at or after <paramref name="after"/>.</summary>
    public static DateTimeOffset NextFireTime(SendCadence cadence, int sendAtHour, DateTimeOffset after)
    {
        var recent = MostRecentFireTime(cadence, sendAtHour, after);
        if (recent > after) return recent;        // (only when after is before today's fire)
        return AdvanceOne(cadence, recent);
    }

    /// <summary>The most recent scheduled fire time at or before <paramref name="now"/>.</summary>
    public static DateTimeOffset MostRecentFireTime(SendCadence cadence, int sendAtHour, DateTimeOffset now)
    {
        var hour = Math.Clamp(sendAtHour, 0, 23);
        switch (cadence)
        {
            case SendCadence.Daily:
            {
                var today = new DateTimeOffset(now.Year, now.Month, now.Day, hour, 0, 0, now.Offset);
                return now >= today ? today : today.AddDays(-1);
            }
            case SendCadence.Weekly:
            {
                // Fire on Monday at the hour. Walk back to the most recent Monday-at-hour.
                var todayAtHour = new DateTimeOffset(now.Year, now.Month, now.Day, hour, 0, 0, now.Offset);
                int daysSinceMonday = ((int)now.DayOfWeek + 6) % 7; // Mon=0 .. Sun=6
                var thisMonday = todayAtHour.AddDays(-daysSinceMonday);
                return now >= thisMonday ? thisMonday : thisMonday.AddDays(-7);
            }
            default: // Monthly: 1st of the month at the hour.
            {
                var thisMonthFirst = new DateTimeOffset(now.Year, now.Month, 1, hour, 0, 0, now.Offset);
                return now >= thisMonthFirst ? thisMonthFirst : thisMonthFirst.AddMonths(-1);
            }
        }
    }

    private static DateTimeOffset AdvanceOne(SendCadence cadence, DateTimeOffset fire) => cadence switch
    {
        SendCadence.Daily => fire.AddDays(1),
        SendCadence.Weekly => fire.AddDays(7),
        _ => fire.AddMonths(1),
    };
}
