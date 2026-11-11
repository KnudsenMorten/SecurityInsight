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
        // the engine's own order (Get-SIGuardMailRecipients): its list, else the default list -- the SuperAdmins after both
        new("guard-alert", "Safety-check alert", NotifyEntry.Alert, "when a safety check holds, refuses or stops a step", "engine",
            ["SI_GuardMail_To", "MailTo"], "/Admin/Settings?q=SI_GuardMail_To"),
        // the id stays getstarted-reminder: the recipients' stored switches keep working (SI #556 widened it to approvals).
        // #1172: its own list first; until the list of people is confirmed, the alert recipients, else the installing admin
        new(GetStartedReminder, "Waiting for you reminder (Get Started steps and approvals)", NotifyEntry.Alert, "daily while a required Get Started step is open or a decision waits", "web",
            [NotifySettings.ReminderTo, "SI_GuardMail_To", "SI_LicenseRequest_ContactEmail"], "/Admin/Settings?q=SIWeb_GetStartedReminder"),
        new("exemption-mails", "Exemption requests, decisions, expiry warnings and the monthly review", NotifyEntry.Alert, "when requested or decided; the review monthly", "engine",
            [], "/Admin/DomainRoles", RecipientsText: "the owners and approvers of each security domain and category"),
    ];

    /// Every entry: the fixed ones and one per management summary definition.
    public static IReadOnlyList<NotifyEntry> All(IEnumerable<MgmtReport> summaries) =>
        Fixed.Concat(summaries.Select(r => new NotifyEntry(MgmtSummaryId(r.Id), "Management summary: " + r.Name, NotifyEntry.Report, MgmtSchedule.Describe(r), "web",
            [], "/Reports/Management", DefaultAudience: MailAudience.Manager))).ToList();

    /// A web-app setting (stored only at the web app's scope).
    public static bool IsWebSetting(string name) => name.StartsWith("SIWeb_", StringComparison.Ordinal);

    /// The rows a list setting is stored in: a web setting's one row, else every engine-visible row (solution and each
    /// engine scope) -- the grid writes all of them, so no scope keeps an old list.
    public static IReadOnlyList<SettingRow> RowsOf(IEnumerable<SettingRow> rows, string name) =>
        rows.Where(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && (IsWebSetting(name) ? r.Scope == CatalogSetting.WebScope : r.Scope != CatalogSetting.WebScope)).ToList();

    /// PURE. The effective list value of a setting: an engine-scoped row first (it wins over the solution value), then the
    /// solution row (a web setting: its row at the web app's scope); a JSON array or a ';' / ',' separated text. Null = no row.
    public static IReadOnlyList<string>? ListOf(IEnumerable<SettingRow> rows, string name)
    {
        var mine = RowsOf(rows, name);
        var row = IsWebSetting(name) ? mine.FirstOrDefault()
            : mine.FirstOrDefault(r => r.Scope.StartsWith("engine:", StringComparison.Ordinal)) ?? mine.FirstOrDefault(r => r.Scope == "solution");
        return ParseList(row?.ValueJson);
    }

    /// PURE. A stored list value: a JSON array or a ';' / ',' separated text, addresses only. Null = no value / unreadable.
    public static IReadOnlyList<string>? ParseList(string? valueJson)
    {
        if (valueJson is not { } json) return null;
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

    /// PURE. An entry's recipients. Before the list of people is confirmed (#1172): the first of its settings that has a
    /// non-empty list (the fallback chain the jobs use). Once it is confirmed: its OWN list exactly -- an empty one is
    /// nobody, never a fallback.
    public static IReadOnlyList<string> RecipientsOf(NotifyEntry e, IEnumerable<SettingRow> rows)
    {
        var list = rows as IReadOnlyList<SettingRow> ?? rows.ToList();
        if (Confirmation.Of(list) is not null)
            return e.RecipientSettings.Count == 0 ? Array.Empty<string>() : ListOf(list, e.RecipientSettings[0]) ?? (IReadOnlyList<string>)Array.Empty<string>();
        foreach (var s in e.RecipientSettings) if (ListOf(list, s) is { Count: > 0 } l) return l;
        return Array.Empty<string>();
    }
}

/// <summary>
/// #1172: who confirmed the list of people (the one setting SIWeb_MailRecipientsConfirmed, "&lt;time UTC&gt;|&lt;who&gt;"). Its
/// presence is also what makes every report's own list exact: the jobs read it (SI-ProSettings' web settings for engines)
/// and stop falling back to the default list.
/// </summary>
public sealed record Confirmation(DateTime AtUtc, string By)
{
    public string ToValue() => AtUtc.ToString("yyyy-MM-ddTHH:mm:ssZ", System.Globalization.CultureInfo.InvariantCulture) + "|" + By.Trim();

    public static Confirmation? Of(IEnumerable<SettingRow> rows)
    {
        var row = rows.FirstOrDefault(r => r.Name.Equals(NotifySettings.Confirmed, StringComparison.OrdinalIgnoreCase) && r.Scope == CatalogSetting.WebScope);
        if (row?.ValueJson is not { } json) return null;
        string? text;
        try { using var d = JsonDocument.Parse(json); text = d.RootElement.ValueKind == JsonValueKind.String ? d.RootElement.GetString() : null; }
        catch (JsonException) { return null; }
        if (string.IsNullOrWhiteSpace(text)) return null;
        var bar = text.IndexOf('|');
        var at = DateTime.TryParse(bar < 0 ? text : text[..bar], System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var t) ? DateTime.SpecifyKind(t, DateTimeKind.Utc) : DateTime.MinValue;
        return new Confirmation(at, bar < 0 ? "" : text[(bar + 1)..].Trim());
    }
}

/// <summary>
/// PURE. #1172 (owner 2026-11-10 at a customer: "it is a mesh" / "too complex"): ONE list of people per install -- a row per
/// mail address, a tick per report and alert (the fixed entries and each management summary). Ticked = receives it. The
/// people are everyone on any list and everyone with notification choices, so a person added on Notifications is a row
/// here. For a mail the web app composes, a tick is also "not switched off on Notifications" -- the grid never shows a tick
/// for someone who gets nothing. The exemption mails have no list (the owners and approvers of each domain): not a column.
/// </summary>
public sealed record RecipientGrid(IReadOnlyList<NotifyEntry> Columns, IReadOnlyList<string> People, IReadOnlyDictionary<string, IReadOnlyList<string>> Receivers)
{
    public bool Ticked(string entryId, string address) =>
        Receivers.TryGetValue(entryId, out var l) && l.Contains(address, StringComparer.OrdinalIgnoreCase);

    /// The entries a person receives.
    public IReadOnlyList<NotifyEntry> Of(string address) => Columns.Where(c => Ticked(c.Id, address)).ToList();

    /// A grid column: every entry with a list (fixed or a management summary).
    public static bool IsColumn(NotifyEntry e) => e.RecipientSettings.Count > 0 || e.Id.StartsWith(NotifyCatalog.MgmtSummaryPrefix, StringComparison.Ordinal);

    public static RecipientGrid Build(NotificationService.State s, DateTime nowUtc)
    {
        var lines = NotificationService.Lines(s, nowUtc).Where(l => IsColumn(l.Entry)).ToList();
        var receivers = lines.ToDictionary(l => l.Entry.Id,
            l => (IReadOnlyList<string>)l.Recipients.Where(a => !l.Entry.HonoursNotifications || s.Prefs.For(a).Wants(l.Entry.Id)).ToList());
        var people = lines.SelectMany(l => l.Recipients).Concat(s.Prefs.Recipients.Select(r => r.Address))
            .Select(a => a.Trim()).Where(NotificationPrefs.IsAddress).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(a => a, StringComparer.OrdinalIgnoreCase).ToList();
        return new RecipientGrid(lines.Select(l => l.Entry).ToList(), people, receivers);
    }

    /// The same grid with a person's ticks replaced (a person not on it yet is added).
    public RecipientGrid With(string address, IEnumerable<string> entryIds)
    {
        var a = address.Trim();
        var ids = entryIds.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var people = People.Any(p => p.Equals(a, StringComparison.OrdinalIgnoreCase)) ? People : People.Append(a).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
        var rec = Columns.ToDictionary(c => c.Id, c =>
        {
            var keep = (Receivers.TryGetValue(c.Id, out var l) ? l : Array.Empty<string>()).Where(x => !x.Equals(a, StringComparison.OrdinalIgnoreCase));
            return (IReadOnlyList<string>)(ids.Contains(c.Id) ? keep.Append(a) : keep).ToList();
        });
        return new RecipientGrid(Columns, people, rec);
    }

    /// The same grid without a person.
    public RecipientGrid Without(string address) =>
        new(Columns, People.Where(p => !p.Equals(address.Trim(), StringComparison.OrdinalIgnoreCase)).ToList(),
            Receivers.ToDictionary(k => k.Key, k => (IReadOnlyList<string>)k.Value.Where(x => !x.Equals(address.Trim(), StringComparison.OrdinalIgnoreCase)).ToList()));

    /// The grid as posted: every person's ticks ("&lt;entry id&gt;|&lt;address&gt;"); a person without a tick stays a row
    /// only through their notification choices.
    public RecipientGrid FromTicks(IEnumerable<string> people, IEnumerable<string> ticks)
    {
        var set = ticks.Select(t => t.Split('|', 2)).Where(p => p.Length == 2 && NotificationPrefs.IsAddress(p[1]))
            .Select(p => (Id: p[0].Trim(), Address: p[1].Trim())).ToList();
        var who = people.Select(p => p.Trim()).Where(NotificationPrefs.IsAddress).Concat(set.Select(t => t.Address)).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
        var rec = Columns.ToDictionary(c => c.Id, c => (IReadOnlyList<string>)set.Where(t => t.Id.Equals(c.Id, StringComparison.OrdinalIgnoreCase)).Select(t => t.Address).Distinct(StringComparer.OrdinalIgnoreCase).ToList());
        return new RecipientGrid(Columns, who, rec);
    }

    /// A short, stable fingerprint of what the grid was read from (each list row's version, the management summaries'
    /// recipients, the notifications' version): a save whose fingerprint no longer matches is refused, writing nothing.
    public static string Fingerprint(NotificationService.State s)
    {
        var names = NotifyCatalog.Fixed.SelectMany(e => e.RecipientSettings).Append(NotifySettings.Confirmed).Distinct(StringComparer.OrdinalIgnoreCase);
        var parts = s.Rows.Where(r => names.Contains(r.Name, StringComparer.OrdinalIgnoreCase))
            .Select(r => r.Name.ToLowerInvariant() + "@" + r.Scope + "=" + r.Version.ToString(System.Globalization.CultureInfo.InvariantCulture))
            .Concat(s.Summaries.Select(m => "mgmt" + m.Id.ToString(System.Globalization.CultureInfo.InvariantCulture) + "=" + string.Join(";", m.Recipients)))
            .Append("prefs=" + (s.Version?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "-"))
            .OrderBy(p => p, StringComparer.Ordinal);
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(string.Join("\n", parts))))[..16].ToLowerInvariant();
    }

    /// One planned settings write: the setting, its scope, the exact new list and the version it was read at (null = no row).
    public sealed record ListWrite(string Name, string Scope, IReadOnlyList<string> To, long? ExpectedVersion);

    /// PURE. The settings writes that make every list EXACTLY this grid: each fixed entry's OWN list (the first name in its
    /// settings) in every row it is stored in (the solution row when there is none), and the default list (MailTo) emptied
    /// -- once the list is confirmed it never decides who gets a mail again, so its old addresses cannot come back through
    /// any job's fallback. A row that already holds exactly that list is left alone (no change-log noise).
    public static IReadOnlyList<ListWrite> PlanWrites(RecipientGrid g, IReadOnlyList<SettingRow> rows)
    {
        var plan = new List<ListWrite>();
        void Exact(string name, IReadOnlyList<string> to)
        {
            var mine = NotifyCatalog.RowsOf(rows, name);
            if (mine.Count == 0) { plan.Add(new ListWrite(name, NotifyCatalog.IsWebSetting(name) ? CatalogSetting.WebScope : "solution", to, null)); return; }
            foreach (var r in mine)
            {
                var now = IsArray(r.ValueJson) ? NotifyCatalog.ParseList(r.ValueJson) : null;
                if (now is not null && now.Count == to.Count && now.Zip(to).All(p => p.First.Equals(p.Second, StringComparison.OrdinalIgnoreCase))) continue;
                plan.Add(new ListWrite(name, r.Scope, to, r.Version));
            }
        }
        foreach (var e in NotifyCatalog.Fixed.Where(e => e.RecipientSettings.Count > 0))
            Exact(e.RecipientSettings[0], g.Receivers.TryGetValue(e.Id, out var l) ? l : Array.Empty<string>());
        Exact("MailTo", Array.Empty<string>());
        return plan;
    }

    private static bool IsArray(string? json)
    {
        if (json is null) return false;
        try { using var d = JsonDocument.Parse(json); return d.RootElement.ValueKind == JsonValueKind.Array; }
        catch (JsonException) { return false; }
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
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "notifications: settings"); error = "The settings could not be read: " + ViewerError.Text(ex); }
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

    /// The result of saving the list of people: whether all of it was saved, the words for the person, how many writes.
    public sealed record GridSave(bool Ok, bool Stale, string Message, int Written);

    /// <summary>
    /// #1172: saves the list of people EXACTLY as <paramref name="g"/> says and records who confirmed it. Every write goes
    /// through the settings writer (validation, the version read, the change log) or the management summary store, one by
    /// one: a refused or stale write stops the save there and says how far it got -- the confirmation is written only
    /// after everything else, so a half-saved list is never marked confirmed. <paramref name="prefs"/> = the notification
    /// choices to keep (a person added or removed); a ticked mail the web app composes is switched back on for that person.
    /// </summary>
    public async Task<GridSave> SaveGridAsync(State s, RecipientGrid g, NotificationPrefs? prefs, string by, string reason, CancellationToken ct)
    {
        var p = prefs ?? s.Prefs;
        foreach (var c in g.Columns.Where(c => c.HonoursNotifications))
            foreach (var a in g.Receivers.TryGetValue(c.Id, out var l) ? l : Array.Empty<string>())
                if (p.For(a) is var r && !r.Wants(c.Id) && p.Recipients.Any(x => x.Address.Equals(a, StringComparison.OrdinalIgnoreCase)))
                    p = p.With(r with { Off = r.Off.Where(x => !x.Equals(c.Id, StringComparison.OrdinalIgnoreCase)).ToList() });
        var written = 0;
        GridSave Fail(WriteResult w, string what) => new(false, w.Status == WriteStatus.Stale,
            (written > 0 ? $"{written} change{(written == 1 ? " was" : "s were")} saved, then " : "") + what + " was not: " + w.Message + ". Reload the page and check the list again.", written);
        foreach (var w in RecipientGrid.PlanWrites(g, s.Rows))
        {
            using var doc = JsonDocument.Parse(JsonSerializer.Serialize(w.To));
            var r = await writer.WriteAsync(new SettingWrite(w.Name, w.Scope, "Set", doc.RootElement.Clone(), null, w.ExpectedVersion, reason), by, ct);
            if (r.Status != WriteStatus.Saved) return Fail(r, "a recipient list");
            written++;
        }
        foreach (var m in s.Summaries)
        {
            var to = g.Receivers.TryGetValue(NotifyCatalog.MgmtSummaryId(m.Id), out var l) ? l : Array.Empty<string>();
            if (to.Count == m.Recipients.Count && to.Zip(m.Recipients).All(x => x.First.Equals(x.Second, StringComparison.OrdinalIgnoreCase))) continue;
            await reports.SaveAsync(m with { Recipients = to.ToList() }, by, ct);
            written++;
        }
        if (p.ToJson() != s.Prefs.ToJson())
        {
            var w = await SaveAsync(p, s.Version, by, reason, ct);
            if (w.Status != WriteStatus.Saved) return Fail(w, "the notification choices");
            written++;
        }
        var conf = s.Rows.FirstOrDefault(r => r.Name.Equals(NotifySettings.Confirmed, StringComparison.OrdinalIgnoreCase) && r.Scope == CatalogSetting.WebScope);
        using (var cdoc = JsonDocument.Parse(JsonSerializer.Serialize(new Confirmation(Now, by).ToValue())))
        {
            var c = await writer.WriteAsync(new SettingWrite(NotifySettings.Confirmed, CatalogSetting.WebScope, "Set", cdoc.RootElement.Clone(), null, conf?.Version, reason), by, ct);
            if (c.Status != WriteStatus.Saved) return Fail(c, "the confirmation");
        }
        cache.Remove(CacheKey);
        return new GridSave(true, false, "", written);
    }
}
