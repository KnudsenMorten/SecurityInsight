using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.MgmtReports;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Notify;

/// <summary>
/// One report or alert SecurityInsight mails (framework MAIL-2 item 6). <see cref="RecipientSettings"/> = the settings that
/// hold its recipient list (the first one set wins: a report's own list, then the default list); <see cref="RecipientsText"/>
/// = who gets it when it is not a list (the owners of a domain). <see cref="SentBy"/> says which part sends it: "web" mails
/// are composed by the web app and follow each recipient's notifications now; "engine" mails are composed by a job.
/// </summary>
public sealed record NotifyEntry(string Id, string Title, string Kind, string Cadence, string SentBy, IReadOnlyList<string> RecipientSettings,
    string ConfigurePath, string? RecipientsText = null, string DefaultAudience = MailAudience.Posture)
{
    public const string Report = "report";
    public const string Alert = "alert";
    public bool IsAlert => Kind == Alert;
    public bool HonoursNotifications => SentBy == "web";
}

/// One line of the central view: the entry, its recipients as they stand now, when it was last sent and goes next.
public sealed record NotifyLine(NotifyEntry Entry, IReadOnlyList<string> Recipients, DateTime? LastSentUtc, DateTime? NextUtc, bool Enabled = true);

/// <summary>
/// THE LIST of every report and alert SecurityInsight mails -- the one source of the central view (Reports and alerts), the
/// Notifications page's switches and the routing in the web app's own senders. A management summary is one entry per
/// definition (mgmt-summary-&lt;id&gt;).
/// </summary>
public static class NotifyCatalog
{
    public const string GetStartedReminder = "getstarted-reminder";
    public const string MgmtSummaryPrefix = "mgmt-summary-";
    public static string MgmtSummaryId(long id) => MgmtSummaryPrefix + id.ToString(System.Globalization.CultureInfo.InvariantCulture);

    public static readonly IReadOnlyList<NotifyEntry> Fixed =
    [
        new("ra-summary", "Risk Analysis -- Summary report", NotifyEntry.Report, "after each daily Risk Analysis run", "engine",
            ["RiskAnalysis_Summary_To", "Mail_SecurityInsight_Summary_To", "MailTo"], "/Admin/Settings?q=RiskAnalysis_Summary_To", DefaultAudience: MailAudience.Manager),
        new("ra-detailed", "Risk Analysis -- Detailed report", NotifyEntry.Report, "after each daily Risk Analysis run", "engine",
            ["RiskAnalysis_Detailed_To", "Mail_SecurityInsight_Detailed_To", "MailTo"], "/Admin/Settings?q=RiskAnalysis_Detailed_To", DefaultAudience: MailAudience.Soc),
        new("closeloop-daily", "Daily vulnerability mail", NotifyEntry.Report, "daily, with the close-loop mail job", "engine",
            ["Mail_CloseLoop_Daily_To"], "/Admin/Settings?q=Mail_CloseLoop_Daily_To", DefaultAudience: MailAudience.Soc),
        new("guard-alert", "Safety-check alert", NotifyEntry.Alert, "when a safety check holds, refuses or stops a step", "engine",
            ["SI_GuardMail_To"], "/Admin/Settings?q=SI_GuardMail_To"),
        // the id stays getstarted-reminder: the recipients' stored switches keep working (SI #556 widened it to approvals)
        new(GetStartedReminder, "Waiting for you reminder (Get Started steps and approvals)", NotifyEntry.Alert, "daily while a required Get Started step is open or a decision waits", "web",
            ["SI_GuardMail_To", "SI_LicenseRequest_ContactEmail"], "/Admin/Settings?q=SIWeb_GetStartedReminder"),
        new("exemption-mails", "Exemption requests, decisions, expiry warnings and the monthly review", NotifyEntry.Alert, "when requested or decided; the review monthly", "engine",
            [], "/Admin/DomainRoles", RecipientsText: "the owners and approvers of each security domain and category"),
    ];

    /// Every entry: the fixed ones and one per management summary definition.
    public static IReadOnlyList<NotifyEntry> All(IEnumerable<MgmtReport> summaries) =>
        Fixed.Concat(summaries.Select(r => new NotifyEntry(MgmtSummaryId(r.Id), "Management summary: " + r.Name, NotifyEntry.Report, MgmtSchedule.Describe(r), "web",
            [], "/Reports/Management", DefaultAudience: MailAudience.Manager))).ToList();

    /// PURE. The effective list value of a setting: an engine-scoped row first (it wins over the solution value), then the
    /// solution row; a JSON array or a ';' / ',' separated text. Null = no row.
    public static IReadOnlyList<string>? ListOf(IEnumerable<SettingRow> rows, string name)
    {
        var mine = rows.Where(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && r.Scope != CatalogSetting.WebScope).ToList();
        var row = mine.FirstOrDefault(r => r.Scope.StartsWith("engine:", StringComparison.Ordinal)) ?? mine.FirstOrDefault(r => r.Scope == "solution");
        if (row?.ValueJson is not { } json) return null;
        try
        {
            using var d = JsonDocument.Parse(json);
            var items = d.RootElement.ValueKind switch
            {
                JsonValueKind.Array => d.RootElement.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString() ?? ""),
                JsonValueKind.String => (d.RootElement.GetString() ?? "").Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries),
                _ => Enumerable.Empty<string>(),
            };
            return items.Select(s => s.Trim()).Where(NotificationPrefs.IsAddress).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }
        catch (JsonException) { return null; }
    }

    /// PURE. An entry's recipients: the first of its settings that has a non-empty list.
    public static IReadOnlyList<string> RecipientsOf(NotifyEntry e, IEnumerable<SettingRow> rows)
    {
        var list = rows as IReadOnlyList<SettingRow> ?? rows.ToList();
        foreach (var s in e.RecipientSettings) if (ListOf(list, s) is { Count: > 0 } l) return l;
        return Array.Empty<string>();
    }
}

/// <summary>
/// Reads and saves the notifications (the one setting <see cref="NotifySettings.Prefs"/>) and builds the central view's lines
/// from the settings rows and the management summary definitions. Reads never fail a page: what cannot be read is empty.
/// </summary>
public sealed class NotificationService(ISettingsStoreReader reader, SettingsWriter writer, IMgmtReportStore reports, IMemoryCache cache, TimeProvider clock, ILogger<NotificationService> log)
{
    private const string CacheKey = "si-notify-prefs";

    public sealed record State(NotificationPrefs Prefs, long? Version, IReadOnlyList<SettingRow> Rows, IReadOnlyList<MgmtReport> Summaries, string? Error);

    public async Task<State> ReadAsync(CancellationToken ct)
    {
        IReadOnlyList<SettingRow> rows = Array.Empty<SettingRow>();
        string? error = null;
        try { rows = (await reader.ReadSettingsAsync(ct)).Rows; }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "notifications: settings"); error = "The settings could not be read: " + ex.Message; }
        IReadOnlyList<MgmtReport> summaries = Array.Empty<MgmtReport>();
        try { if (await reports.ReadyAsync(ct)) summaries = await reports.ListAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "notifications: management summaries"); }
        var row = rows.FirstOrDefault(r => r.Name.Equals(NotifySettings.Prefs, StringComparison.OrdinalIgnoreCase) && r.Scope == CatalogSetting.WebScope);
        return new State(NotificationPrefs.Parse(row?.ValueJson), row?.Version, rows, summaries, error);
    }

    /// The preferences alone, cached for a minute (the senders read them on every send).
    public async Task<NotificationPrefs> PrefsAsync(CancellationToken ct)
    {
        if (cache.TryGetValue(CacheKey, out NotificationPrefs? hit) && hit is not null) return hit;
        var p = (await ReadAsync(ct)).Prefs;
        cache.Set(CacheKey, p, TimeSpan.FromMinutes(1));
        return p;
    }

    /// The central view's lines, in the catalog's order.
    public static IReadOnlyList<NotifyLine> Lines(State s, DateTime nowUtc) =>
        NotifyCatalog.All(s.Summaries).Select(e =>
        {
            if (e.Id.StartsWith(NotifyCatalog.MgmtSummaryPrefix, StringComparison.Ordinal))
            {
                var r = s.Summaries.First(x => NotifyCatalog.MgmtSummaryId(x.Id) == e.Id);
                return new NotifyLine(e, r.Recipients, r.LastSentAt is { } l ? DateTime.SpecifyKind(l, DateTimeKind.Utc) : null, r.Enabled ? MgmtSchedule.NextSlot(r, nowUtc) : null, r.Enabled);
            }
            return new NotifyLine(e, NotifyCatalog.RecipientsOf(e, s.Rows), null, null);
        }).ToList();

    /// Every address on any list, and every one with preferences -- the Notifications page's rows.
    public static IReadOnlyList<string> AllRecipients(State s, DateTime nowUtc) =>
        Lines(s, nowUtc).SelectMany(l => l.Recipients).Concat(s.Prefs.Recipients.Select(r => r.Address))
            .Select(a => a.Trim()).Where(NotificationPrefs.IsAddress).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList();

    /// Saves the preferences (the version read guards against a concurrent change).
    public async Task<WriteResult> SaveAsync(NotificationPrefs prefs, long? expectedVersion, string by, string reason, CancellationToken ct)
    {
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(prefs.ToJson()));
        var r = await writer.WriteAsync(new SettingWrite(NotifySettings.Prefs, CatalogSetting.WebScope, "Set", doc.RootElement.Clone(), null, expectedVersion, reason), by, ct);
        cache.Remove(CacheKey);
        return r;
    }

    public DateTime Now => clock.GetUtcNow().UtcDateTime;
}
