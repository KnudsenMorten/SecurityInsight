using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Notify;

/// <summary>
/// One mail recipient's notifications (framework MAIL-2 item 2): their audience (where the mail's blue button leads), the
/// reports and alerts switched OFF for them (everything is on until switched off), and the lowest severity of an alert
/// they still get (null = every alert).
/// </summary>
public sealed record RecipientPrefs(string Address, string Audience, IReadOnlyList<string> Off, string? SeverityFloor = null)
{
    public bool Wants(string entryId) => !Off.Contains(entryId, StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// PURE. Every recipient's notifications -- stored as ONE web-app setting (SIWeb_MailNotifications, JSON text at scope
/// engine:management-web), so it is saved, journaled, backed up, exported and undone like every other setting, and the
/// engine's mail steps can read it from cfg.Setting at send time. A recipient not listed gets everything with the posture
/// audience.
/// </summary>
public sealed record NotificationPrefs(IReadOnlyList<RecipientPrefs> Recipients)
{
    public static readonly NotificationPrefs Empty = new(Array.Empty<RecipientPrefs>());
    public static readonly IReadOnlyList<string> SeverityFloors = ["Critical", "High", "Medium", "Low"];
    private static readonly Regex Mail = new(@"^[^@\s;,<>""]+@[^@\s;,<>""]+\.[^@\s;,<>""]+$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    public static bool IsAddress(string? s) => !string.IsNullOrWhiteSpace(s) && s.Length <= 254 && Mail.IsMatch(s.Trim());

    /// The recipient's preferences (a default one when not listed).
    public RecipientPrefs For(string address) =>
        Recipients.FirstOrDefault(r => r.Address.Equals((address ?? "").Trim(), StringComparison.OrdinalIgnoreCase))
        ?? new RecipientPrefs((address ?? "").Trim(), MailAudience.Posture, Array.Empty<string>());

    /// The recipients of one report / alert after the switches: those that did not switch it off, grouped by audience
    /// (one mail per audience, each with its own button). Duplicates and non-addresses are left out.
    public IReadOnlyList<(string Audience, IReadOnlyList<string> To)> Route(IEnumerable<string> recipients, string entryId) =>
        recipients.Select(r => (r ?? "").Trim()).Where(IsAddress).Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(For).Where(p => p.Wants(entryId))
            .GroupBy(p => MailAudience.Normalize(p.Audience))
            .OrderBy(g => MailAudience.All.ToList().IndexOf(g.Key))
            .Select(g => (g.Key, (IReadOnlyList<string>)g.Select(p => p.Address).ToList())).ToList();

    /// Is an alert of this severity for the recipient (their floor or above)? Unknown severity = yes.
    public static bool AtOrAbove(string? severity, string? floor)
    {
        if (string.IsNullOrWhiteSpace(floor)) return true;
        var order = SeverityFloors.ToList();
        var s = order.FindIndex(x => x.Equals((severity ?? "").Trim(), StringComparison.OrdinalIgnoreCase));
        var f = order.FindIndex(x => x.Equals(floor.Trim(), StringComparison.OrdinalIgnoreCase));
        return s < 0 || f < 0 || s <= f;
    }

    /// The stored JSON text: {"recipients":[{"address","audience","off":[...],"floor"}]}.
    public string ToJson()
    {
        var arr = new JsonArray();
        foreach (var r in Recipients.OrderBy(r => r.Address, StringComparer.OrdinalIgnoreCase))
        {
            var o = new JsonObject { ["address"] = r.Address.Trim().ToLowerInvariant(), ["audience"] = MailAudience.Normalize(r.Audience) };
            if (r.Off.Count > 0) o["off"] = new JsonArray(r.Off.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.Ordinal).Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
            if (!string.IsNullOrWhiteSpace(r.SeverityFloor)) o["floor"] = r.SeverityFloor;
            arr.Add(o);
        }
        return new JsonObject { ["recipients"] = arr }.ToJsonString();
    }

    /// Reads the stored text (the setting's value: a JSON string holding the JSON above). Anything unreadable = Empty.
    public static NotificationPrefs Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return Empty;
        try
        {
            var node = JsonNode.Parse(text);
            // the setting's ValueJson is a JSON string whose content is the document
            if (node is JsonValue v && v.TryGetValue<string>(out var inner)) node = string.IsNullOrWhiteSpace(inner) ? null : JsonNode.Parse(inner);
            if (node?["recipients"] is not JsonArray arr) return Empty;
            var list = new List<RecipientPrefs>();
            foreach (var o in arr.OfType<JsonObject>())
            {
                var a = (o["address"]?.GetValue<string>() ?? "").Trim();
                if (!IsAddress(a) || list.Any(x => x.Address.Equals(a, StringComparison.OrdinalIgnoreCase))) continue;
                var off = (o["off"] as JsonArray)?.Select(x => x?.GetValue<string>()).Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => x!).ToList() ?? new List<string>();
                var floor = o["floor"]?.GetValue<string>();
                list.Add(new RecipientPrefs(a, MailAudience.Normalize(o["audience"]?.GetValue<string>()), off, SeverityFloors.Contains(floor ?? "", StringComparer.OrdinalIgnoreCase) ? floor : null));
            }
            return new NotificationPrefs(list);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or FormatException) { return Empty; }
    }

    /// A copy with one recipient replaced (or added).
    public NotificationPrefs With(RecipientPrefs p) =>
        new(Recipients.Where(r => !r.Address.Equals(p.Address, StringComparison.OrdinalIgnoreCase)).Append(p).ToList());

    /// A copy without one recipient.
    public NotificationPrefs Without(string address) =>
        new(Recipients.Where(r => !r.Address.Equals((address ?? "").Trim(), StringComparison.OrdinalIgnoreCase)).ToList());
}

/// <summary>
/// The web app's settings of the notifications (framework MAIL-2 items 2 and 8): the per-recipient choices, and the daily
/// Get Started reminder (on by default, the hour it goes out). Stored at scope engine:management-web like every web setting.
/// </summary>
public static class NotifySettings
{
    public const string Prefs = "SIWeb_MailNotifications";
    public const string Reminder = "SIWeb_GetStartedReminder";
    public const string ReminderHour = "SIWeb_GetStartedReminderHourUtc";
    /// #1172: the Waiting for you reminder's own list (a column of the list of people on Reports and alerts).
    public const string ReminderTo = "SIWeb_GetStartedReminder_To";
    /// #1172: who confirmed the list of people, and when ("&lt;time UTC&gt;|&lt;who&gt;"). Set = every report's own list is exact.
    public const string Confirmed = "SIWeb_MailRecipientsConfirmed";

    private static JsonElement J(string json) { using var d = JsonDocument.Parse(json); return d.RootElement.Clone(); }

    private static CatalogSetting S(string name, string type, string label, string description, string def, string defaultText, string effect, string when,
        double? min = null, double? max = null, string? unit = null, string card = "Notifications", string? itemFormat = null) => new()
    {
        Name = name, Label = label, Group = SI.Management.Web.Links.WebSettings.SettingsArea, Type = type, Engines = new[] { "management-web" }, Edition = "community",
        Default = J(def), Description = description, DefaultText = defaultText, Effect = effect, WhenToChange = when, Min = min, Max = max, Unit = unit,
        WebOnly = true, Card = card, Advanced = name is Prefs or Confirmed or ReminderTo, ItemFormat = itemFormat,
    };

    public static readonly IReadOnlyList<CatalogSetting> Catalog =
    [
        S(Prefs, "text", "Mail notifications per recipient",
            "Each mail recipient's choices: their audience (SOC analyst, posture / risk or manager -- where the blue button in a mail leads) and the reports and alerts switched off for them. Edited on the Notifications page; stored here as JSON.",
            "\"\"", "Not set: every recipient gets every report and alert they are a recipient of, with the risk overview button",
            "A recipient who switches a report off no longer gets it from the web app's mails; their address stays on the report's recipient list.",
            "When a recipient asks for fewer mails, or for a button that leads to their own page."),
        S(Reminder, "bool", "Daily Waiting for you reminder",
            "While a REQUIRED Get Started step is open, or something waits for a decision (a request waiting for a second SuperAdmin, a configuration import, an exemption request waiting for its approver, a guard hold, a held template pack), SecurityInsight mails the alert recipients once a day: what waits, who decides it, and a button straight to the page. It stops by itself when nothing waits.",
            "true", "On: a daily reminder while a required step is open or a decision waits",
            "Off: no reminder is mailed; the open steps and waiting decisions still show on Get Started, the Overview and the counts in the menu.",
            "Only when the install is deliberately left unfinished (a test install) and the reminders are not wanted.", card: "Get Started reminder"),
        S(ReminderHour, "int", "Waiting for you reminder hour (UTC)",
            "The hour of the day (UTC, 0 to 23) the daily Waiting for you reminder goes out.",
            "7", "07:00 UTC", "The reminder goes out at the first check after this hour, once a day.",
            "When 07:00 UTC is outside your IT team's working day.", 0, 23, "hour (UTC)", card: "Get Started reminder"),
        S(ReminderTo, "list", "Waiting for you reminder recipients",
            "Who receives the daily Waiting for you reminder. Set with the list of people on Reports and alerts (one row per person, one tick per report and alert).",
            "null", "Not set: until the list of people is confirmed, the safety-check alert recipients, else the address given for the licence request",
            "These addresses get the reminder. Once the list of people is confirmed, nobody else does -- an empty list means no one.",
            "Change it on Reports and alerts, with the rest of the list of people.", card: "Get Started reminder", itemFormat: "email"),
        S(Confirmed, "text", "List of people confirmed",
            "Who confirmed the list of people on Reports and alerts, and when. Saving the list there records it; the Get Started step Who gets the reports is done once it is set.",
            "\"\"", "Not set: the list of people has not been confirmed yet, and each report still falls back to the default recipients",
            "Set: each report and alert goes exactly to the people ticked for it -- nobody ticked means nobody, never a default list.",
            "Never by hand: saving the list of people on Reports and alerts sets it."),
    ];
}
