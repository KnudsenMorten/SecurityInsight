using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Settings;
using SI.Management.Web.Navigation;

namespace SI.Management.Web.Exemptions;

/// <summary>
/// The settings of the governed exemption flow (#252). Like the web app's link settings they live ONLY at scope
/// 'engine:management-web' (no engine's run-start check reads them, so a value here can never stop a run); the
/// close-loop mail job reads the mail ones from cfg.Setting directly, as it already reads the web app's address.
/// Edited on the Settings pages with the normal editor (validated, audited). Read with a one-minute cache; when they
/// cannot be read the defaults apply (which are the safe ones: 6 months, no open-ended exemption).
/// </summary>
public sealed class ExemptionSettings
{
    /// The Settings page area these sit in.
    public const string Group = "Exemptions";
    public const string DefaultMonths = "SIWeb_ExemptionDefaultMonths";
    public const string AllowOpenEnded = "SIWeb_ExemptionAllowOpenEnded";
    public const string ReviewOverdueDays = "SIWeb_ExemptionReviewOverdueDays";
    public const string MailEnabled = "SIWeb_ExemptionMailEnabled";
    public const string ReviewDayOfMonth = "SIWeb_ExemptionReviewDayOfMonth";
    public const string ExpiryWarningDays = "SIWeb_ExemptionExpiryWarningDays";
    // #264 -- the bulk guard and how exempted findings are shown and counted
    public const string BulkMax = "SIWeb_Exemption_BulkMax";
    public const string ShowInViews = "SIWeb_Exempted_ShowInViews";
    /// Read by the engines too (Risk Analysis, the department reports), so they live in the engines' catalog
    /// (config\settings.catalog.locked.json) at solution scope; the web app reads them from any scope.
    public const string CountInManagement = "SI_Exempted_CountInManagement";
    public const string InDepartmentReports = "SI_Exempted_InDepartmentReports";

    private static JsonElement J(string json) { using var d = JsonDocument.Parse(json); return d.RootElement.Clone(); }

    private static CatalogSetting S(string name, string type, string label, string purpose, string effect, string def, string defText, double? min = null, double? max = null,
        string? when = null, string? unit = null) => new()
    {
        Name = name, Label = label, Group = Group, Type = type, Engines = new[] { "management-web" }, Edition = "pro",
        Default = J(def), DefaultText = defText, Description = purpose, Purpose = purpose, Effect = effect, WhenToChange = when, Unit = unit,
        Min = min, Max = max, WebOnly = true,
    };

    /// Every setting fully described: label, purpose, default and effect.
    public static readonly IReadOnlyList<CatalogSetting> Catalog =
    [
        S(DefaultMonths, "int", "Default exemption period (months)",
            "How long a new exemption lasts when the requester keeps the pre-selected period.",
            "The period dropdown (3 months / 6 months / 1 year / custom end date) opens on this; a value that is not 3, 6 or 12 opens on a custom end date this many months ahead. An exemption staged without an end date also gets it.",
            "6", "6 months", 1, 36, when: "When your policy sets a different standard length for accepted risk.", unit: "months"),
        S(AllowOpenEnded, "bool", "Allow exemptions without an end date",
            "Whether a requester may ask for an exemption that never expires.",
            "Off: every exemption has an end date and the period list offers no 'no end date'. On: 'no end date' is offered; such an exemption still comes up in every monthly review.",
            "false", "off", when: "Only if your policy accepts permanent exemptions."),
        S(ReviewOverdueDays, "int", "Review overdue after (days)",
            "How long an active exemption may go without an owner's review (keep or extend) before it is flagged.",
            "An exemption whose last review -- or approval, when it has none -- is older than this is flagged 'review overdue' on the Exemptions page and on " + NavModel.PathOf("/Admin/Deviations") + ". It still applies; the flag asks its domain's owners to look.",
            "45", "45 days", 7, 400, when: "When owners review on a cycle other than monthly.", unit: "days"),
        S(MailEnabled, "bool", "Exemption mails",
            "Whether the exemption flow sends mail: a request to the domain's approvers, a decision to the requester, expiry warnings and the monthly review to the domain's owners.",
            "On: the web app queues request and decision mails and the close-loop mail job sends them, the warnings and the monthly review through the Risk Analysis SMTP settings. Off: nothing is queued or sent; the flow itself works the same.",
            "true", "on", when: "Turn off only while no SMTP relay is configured, or if requests are announced another way."),
        S(ReviewDayOfMonth, "int", "Monthly review day",
            "The day of the month the monthly exemption review mail goes to each domain's owners.",
            "From this day on, the close-loop mail job's daily run sends each domain's owners the review (expiring soon, expired, all active, one link to review) once per month. Use 1 to 28.",
            "1", "the 1st", 1, 28, when: "When owners prefer the review at another point in the month."),
        S(ExpiryWarningDays, "int", "Expiry warning (days before)",
            "How many days before an exemption ends its domain's owners are warned, and what 'expiring soon' means in the review.",
            "The close-loop mail job warns each domain's owners once per exemption and end date when it enters this window. 0 = no warning mail (the monthly review still lists what is expiring).",
            "30", "30 days", 0, 180, when: "When owners need more (or less) notice before an exemption ends.", unit: "days"),
        S(BulkMax, "int", "Most findings in one bulk exemption request",
            "The largest number of findings one \"Request exemption for all N matching\" may cover. It also needs a filter that narrows the collection: a whole collection is never exempted in one go.",
            "The \"Request exemption for all N matching\" button on the findings browser and the collection views is offered only when the current filter narrows the set (a severity, domain, report, asset, search, column filter ...) AND N is at most this. Otherwise the button is replaced by a hint saying how to narrow. The server checks both again when the request is opened and submitted, and refuses a crafted one with the reason.",
            "500", "500 findings", 1, 2000, when: "Raise it only if your approvers really review larger batches; lower it to force smaller, reviewable requests.", unit: "findings"),
        S(ShowInViews, "bool", "Show exempted findings in the views",
            "Whether the findings browser, the collection views, the asset pages and the CMDB pages show findings that an approved exemption covers.",
            "Off (the default): exempted findings are hidden; every view that leaves them out says \"N exempted not counted\" with a link to show them, and each view has a \"Show exempted\" tick that shows them for that view only (carried through its links and exports). On: they are shown, marked \"Exempted until <date>\", and the tick hides them. The data always keeps them: this only decides what a view shows.",
            "false", "off (hidden)", when: "Turn on if your analysts should see exempted findings by default, e.g. to review them."),
    ];

    public sealed record Values(int DefaultMonths, bool AllowOpenEnded, int ReviewOverdueDays, bool MailEnabled, int ReviewDayOfMonth, int ExpiryWarningDays,
        int BulkMax = 500, bool ShowInViews = false, bool CountInManagement = false, bool InDepartmentReports = false)
    {
        public static Values Defaults { get; } = new(6, false, 45, true, 1, 30);
    }

    private readonly ISettingsStoreReader _reader;
    private readonly IMemoryCache _cache;
    private readonly ILogger<ExemptionSettings> _log;

    public ExemptionSettings(ISettingsStoreReader reader, IMemoryCache cache, ILogger<ExemptionSettings> log) { _reader = reader; _cache = cache; _log = log; }

    public async Task<Values> ReadAsync(CancellationToken ct)
    {
        if (_cache.TryGetValue("si-exemption-settings", out Values? hit) && hit is not null) return hit;
        IReadOnlyList<SettingRow> rows;
        // the web app's own settings from their scope; the two the engines read too (#264) from any scope
        try { rows = (await _reader.ReadSettingsAsync(ct)).Rows.Where(r => r.Scope == CatalogSetting.WebScope || r.Name.StartsWith("SI_Exempted_", StringComparison.OrdinalIgnoreCase)).ToList(); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "exemption settings could not be read -- the defaults apply");
            return Values.Defaults;
        }
        var v = From(rows);
        _cache.Set("si-exemption-settings", v, TimeSpan.FromMinutes(1));
        return v;
    }

    /// PURE: the values from the setting rows (an unparsable or out-of-range value falls back to the default).
    public static Values From(IEnumerable<SettingRow> rows)
    {
        var list = rows.ToList();
        string? Str(string n) => list.FirstOrDefault(r => string.Equals(r.Name, n, StringComparison.OrdinalIgnoreCase)) is { ValueJson: { } j } ? Parse(j) : null;
        int Int(string n, int def, int min, int max) => int.TryParse(Str(n), out var x) && x >= min && x <= max ? x : def;
        bool Bool(string n, bool def) => Str(n) switch { "true" => true, "false" => false, _ => def };
        var d = Values.Defaults;
        // a solution-scope value of an engine setting wins over an engine-scope one (the reference's own order)
        list = list.OrderBy(r => r.Scope == "solution" ? 0 : 1).ToList();
        return new Values(Int(DefaultMonths, d.DefaultMonths, 1, 36), Bool(AllowOpenEnded, d.AllowOpenEnded), Int(ReviewOverdueDays, d.ReviewOverdueDays, 7, 400),
            Bool(MailEnabled, d.MailEnabled), Int(ReviewDayOfMonth, d.ReviewDayOfMonth, 1, 28), Int(ExpiryWarningDays, d.ExpiryWarningDays, 0, 180),
            Int(BulkMax, d.BulkMax, 1, 2000), Bool(ShowInViews, d.ShowInViews), Bool(CountInManagement, d.CountInManagement), Bool(InDepartmentReports, d.InDepartmentReports));
    }

    private static string? Parse(string json)
    {
        try
        {
            using var d = JsonDocument.Parse(json);
            return d.RootElement.ValueKind switch
            {
                JsonValueKind.String => d.RootElement.GetString(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Null => null,
                _ => d.RootElement.GetRawText(),
            };
        }
        catch (JsonException) { return null; }
    }
}
