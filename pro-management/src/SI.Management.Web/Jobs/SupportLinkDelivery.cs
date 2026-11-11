using System.Globalization;
using System.Text.Json;
using SI.Management.Web.Data;
using SI.Management.Web.Pages;

namespace SI.Management.Web.Jobs;

/// <summary>
/// SUPPORT-LINK-1 (framework rule, owner 2026-11-10): the delivery state of the Invardia support link (caj-si-heartbeat) on
/// the Jobs page. The job always ends well (exit 0), so its executions are always green; the heartbeat job records each half
/// hour's delivery in cfg.InstallState 'HeartbeatDelivery' ({failedInRow, lastFailedSlot, lastFailedUtc, lastSentUtc},
/// engine\_shared\SI-HeartbeatJob.ps1 Update-SIHeartbeatDelivery) -- a half hour counts once however many ticks retry it, and a
/// delivered one sets the count to 0. 0 = green; 1-2 = green with an info line; 3 or more in a row = amber. Never a mail.
/// </summary>
public sealed record SupportLinkState(int FailedInRow, DateTime? LastSentUtc, DateTime? LastFailedUtc);

public sealed record SupportLinkView(string Kind, string Badge, string? Line);

public static class SupportLinkDelivery
{
    public const string JobKey = "heartbeat";
    /// failed delivery cycles in a row before the page shows amber
    public const int AmberAt = 3;

    public const string Sql = """
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Value FROM cfg.InstallState WHERE Name = N'HeartbeatDelivery';
""";

    /// null = nothing recorded yet (an install before this release, or no claimed half hour yet) -- the row shows as before.
    public static async Task<SupportLinkState?> ReadAsync(ISqlExecutor sql, CancellationToken ct)
    {
        var rows = await sql.QueryAsync(Sql, new Dictionary<string, object?>(), ct);
        var row = rows.FirstOrDefault(r => r.ContainsKey("Value"));
        return row is null ? null : Parse(row.Str("Value"));
    }

    public static SupportLinkState? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return null;
            var n = o.TryGetProperty("failedInRow", out var f) && f.ValueKind == JsonValueKind.Number && f.TryGetInt32(out var v) && v > 0 ? v : 0;
            static DateTime? T(JsonElement e, string name) =>
                e.TryGetProperty(name, out var x) && x.ValueKind == JsonValueKind.String &&
                DateTime.TryParse(x.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
            return new SupportLinkState(n, T(o, "lastSentUtc"), T(o, "lastFailedUtc"));
        }
        catch (JsonException) { return null; }
    }

    /// What the job's row shows: green "delivering" (0), green with the info line (1-2), amber (3 or more). Plain words; the
    /// count in the viewer's number format.
    public static SupportLinkView View(SupportLinkState? s)
    {
        var n = s?.FailedInRow ?? 0;
        if (n <= 0) return new("ok", "delivering", null);
        if (n < AmberAt)
            return new("ok", "delivering", n == 1
                ? "1 report could not be delivered; it is retried next cycle"
                : $"{Fmt.Int(n)} reports could not be delivered; they are retried next cycle");
        return new("warn", "not delivering",
            $"The last {Fmt.Int(n)} reports could not be delivered to Invardia support; they are retried every cycle. SecurityInsight itself keeps running.");
    }

    public static bool IsSupportLink(string jobName) => JobSchedule.Key(jobName) == JobKey;
}
