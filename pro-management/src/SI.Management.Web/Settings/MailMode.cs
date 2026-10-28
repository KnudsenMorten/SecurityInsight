using System.Globalization;
using System.Text.Json;

namespace SI.Management.Web.Settings;

/// <summary>
/// The ONE mail transport of SecurityInsight and its mode setting (SI_Mail_Mode = none | smtp | sharedMailbox), as the
/// PowerShell engines read it. sharedMailbox (recommended): Microsoft Graph app-only sendMail as one Exchange Online
/// shared mailbox with SI's own managed identity, Mail.Send granted ONLY through Exchange "RBAC for Applications"
/// scoped to that mailbox. smtp: the customer's own relay. Pure -- the page and the home banner share it.
/// </summary>
public static class MailMode
{
    public const string None = "none";
    public const string Smtp = "smtp";
    public const string SharedMailbox = "sharedMailbox";

    /// The settings of the mail transport (catalog names).
    public const string ModeSetting = "SI_Mail_Mode";
    public const string FromSetting = "SI_Mail_From";
    public const string ProbeSetting = "SI_Mail_ProbeMailbox";
    public const string SmtpServerSetting = "SmtpServer";
    public const string SmtpPortSetting = "SMTPPort";
    public const string SmtpSslSetting = "SMTP_UseSSL";
    public const string SmtpUserSetting = "SMTPUser";
    public const string SmtpFromSetting = "SMTPFrom";
    public const string SmtpPasswordSetting = "SMTPPassword";

    /// Where the mode came from: the setting, the legacy SMTP server (no mode set, a server is), or the default (off).
    public const string FromSettingSource = "setting";
    public const string LegacySmtpSource = "legacy-smtp";
    public const string DefaultSource = "default";

    /// <summary>
    /// The mode in force. <paramref name="modeValue"/> and <paramref name="smtpServer"/> are cfg.Setting ValueJson texts
    /// (JSON, e.g. "\"sharedMailbox\""; null = no row). Not set: smtp when an SMTP server is set, else none. Set: compared
    /// case-insensitively; "shared" / "sharedmailbox" / "graph" = sharedMailbox, "off" / "" = none; anything else is
    /// treated as none WITH a problem (never guessed into a transport).
    /// </summary>
    public static MailModeResolution Resolve(string? modeValue, string? smtpServer)
    {
        if (modeValue is null)
            return string.IsNullOrWhiteSpace(Plain(smtpServer))
                ? new MailModeResolution(None, DefaultSource, null)
                : new MailModeResolution(Smtp, LegacySmtpSource, null);
        var raw = Plain(modeValue) ?? "";
        return raw.Trim().ToLowerInvariant() switch
        {
            "" or "none" or "off" => new MailModeResolution(None, FromSettingSource, null),
            "smtp" => new MailModeResolution(Smtp, FromSettingSource, null),
            "sharedmailbox" or "shared" or "graph" => new MailModeResolution(SharedMailbox, FromSettingSource, null),
            _ => new MailModeResolution(None, FromSettingSource, $"SI_Mail_Mode '{raw.Trim()}' is not one of none, smtp, sharedMailbox"),
        };
    }

    /// A stored ValueJson as the plain text it holds (a JSON string unquoted; a non-JSON text as it is); null stays null.
    public static string? Plain(string? valueJson)
    {
        if (valueJson is null) return null;
        var t = SettingJson.ToFormText(valueJson);
        return valueJson.Trim() == "null" ? null : t;
    }

    /// The row of a setting that applies solution-wide: the solution row, else the only other row (web-only rows aside).
    public static SettingRow? RowOf(IEnumerable<SettingRow> rows, string name)
    {
        var mine = rows.Where(r => string.Equals(r.Name, name, StringComparison.OrdinalIgnoreCase) && r.Scope != CatalogSetting.WebScope).ToList();
        return mine.FirstOrDefault(r => r.Scope == "solution") ?? mine.FirstOrDefault();
    }

    /// The mode in force from the settings rows.
    public static MailModeResolution Resolve(IEnumerable<SettingRow> rows)
    {
        var list = rows as IReadOnlyCollection<SettingRow> ?? rows.ToList();
        return Resolve(RowOf(list, ModeSetting)?.ValueJson, RowOf(list, SmtpServerSetting)?.ValueJson);
    }

    /// The mailbox SI sends as: SI_Mail_From, else (smtp) SMTPFrom; null when neither is set.
    public static string? FromAddress(IEnumerable<SettingRow> rows)
    {
        var list = rows as IReadOnlyCollection<SettingRow> ?? rows.ToList();
        var from = Plain(RowOf(list, FromSetting)?.ValueJson);
        if (!string.IsNullOrWhiteSpace(from)) return from.Trim();
        var smtp = Plain(RowOf(list, SmtpFromSetting)?.ValueJson);
        return string.IsNullOrWhiteSpace(smtp) ? null : smtp.Trim();
    }

    /// The words a person reads for a mode.
    public static string Label(string mode) => mode switch
    {
        SharedMailbox => "Office 365 shared mailbox (Microsoft Graph)",
        Smtp => "Your own SMTP relay",
        _ => "Off -- no mail is sent",
    };

    /// The words for where the mode came from.
    public static string SourceLabel(string source) => source switch
    {
        FromSettingSource => "set in SI_Mail_Mode",
        LegacySmtpSource => "SI_Mail_Mode is not set; an SMTP server is, so mail goes through it",
        _ => "SI_Mail_Mode is not set and no SMTP server is",
    };

    /// The recipient setting of each mail type, in the order the card lists them (only names in the catalog are shown).
    public static readonly IReadOnlyList<(string Setting, string MailType)> RecipientSettings =
    [
        ("MailTo", "Default recipients (every report mail without its own list)"),
        ("RiskAnalysis_Summary_To", "Risk Analysis -- Summary report"),
        ("RiskAnalysis_Detailed_To", "Risk Analysis -- Detailed report"),
        ("Mail_SecurityInsight_Summary_To", "SecurityInsight -- Summary report"),
        ("Mail_SecurityInsight_Detailed_To", "SecurityInsight -- Detailed report"),
        ("Mail_CloseLoop_Daily_To", "Daily vulnerability (close-loop) mail"),
        ("SI_GuardMail_To", "Safety-check (guard) alerts"),
    ];
}

/// The mode in force, where it came from ("setting" | "legacy-smtp" | "default"), and a problem with the setting (or null).
public sealed record MailModeResolution(string Mode, string Source, string? Problem)
{
    public bool IsNone => Mode == MailMode.None;
    public bool IsSmtp => Mode == MailMode.Smtp;
    public bool IsSharedMailbox => Mode == MailMode.SharedMailbox;
}

/// <summary>
/// Whether Mail.Send is restricted to the shared mailbox, as the mail job last proved it: cfg.InstallState
/// 'MailRestriction', compact JSON {"state","detail","mailbox","checkedUtc"}. verified + legacy-policy allow sending
/// (legacy-policy = an Application Access Policy restricts it: works, but should move to RBAC for Applications);
/// unrestricted = Mail.Send reaches other mailboxes (RED); not-granted / unverified / error (and nothing recorded) =
/// SI refuses to send in sharedMailbox mode.
/// </summary>
public sealed record MailRestrictionStatus(string State, string? Detail, string? Mailbox, DateTime? CheckedUtc)
{
    public const string Verified = "verified";
    public const string LegacyPolicy = "legacy-policy";
    public const string Unrestricted = "unrestricted";
    public const string NotGranted = "not-granted";
    public const string Unverified = "unverified";
    public const string Error = "error";

    private static readonly string[] Known = [Verified, LegacyPolicy, Unrestricted, NotGranted, Unverified, Error];

    /// Nothing recorded yet.
    public static MailRestrictionStatus NotRecorded { get; } = new(Unverified, "The mail job has not checked the restriction yet.", null, null);

    public bool AllowsSend => State is Verified or LegacyPolicy;
    public bool IsUnrestricted => State == Unrestricted;
    public bool IsVerified => State == Verified;
    public bool IsLegacyPolicy => State == LegacyPolicy;

    /// The words for the state.
    public string Label => State switch
    {
        Verified => "verified -- Mail.Send reaches only the shared mailbox",
        LegacyPolicy => "restricted by an Application Access Policy (works; move it to RBAC for Applications)",
        Unrestricted => "NOT restricted -- Mail.Send reaches other mailboxes",
        NotGranted => "Mail.Send is not granted yet",
        Error => "the check failed",
        _ => "not verified yet",
    };

    /// The row's JSON -> the status; missing / bad JSON / an unknown state = unverified (with the reason as the detail).
    public static MailRestrictionStatus Parse(string? installStateJson)
    {
        if (string.IsNullOrWhiteSpace(installStateJson)) return NotRecorded;
        try
        {
            using var doc = JsonDocument.Parse(installStateJson);
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return new(Unverified, "The recorded restriction status is not readable.", null, null);
            var state = Str(o, "state")?.ToLowerInvariant();
            var detail = Str(o, "detail");
            var mailbox = Str(o, "mailbox");
            DateTime? at = DateTime.TryParse(Str(o, "checkedUtc"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
            if (state is null || !Known.Contains(state))
                return new(Unverified, $"The recorded restriction state '{state ?? ""}' is not known." + (detail is null ? "" : " " + detail), mailbox, at);
            return new(state, detail, mailbox, at);
        }
        catch (JsonException) { return new(Unverified, "The recorded restriction status is not readable.", null, null); }
    }

    internal static string? Str(JsonElement o, string name) =>
        o.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { } s && s.Trim().Length > 0 ? s.Trim() : null;
}

/// <summary>An Exchange administrator's proof that Mail.Send reaches only the shared mailbox: cfg.InstallState
/// 'MailRestrictionAttestation' {"mailbox","scope","by","utc"}, written by setup (or the guided setup) after
/// Test-ServicePrincipalAuthorization.</summary>
public sealed record MailAttestation(string? Mailbox, string? Scope, string? By, DateTime? Utc)
{
    public static MailAttestation? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var o = doc.RootElement;
            if (o.ValueKind != JsonValueKind.Object) return null;
            DateTime? at = DateTime.TryParse(MailRestrictionStatus.Str(o, "utc"), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
            return new MailAttestation(MailRestrictionStatus.Str(o, "mailbox"), MailRestrictionStatus.Str(o, "scope"), MailRestrictionStatus.Str(o, "by"), at);
        }
        catch (JsonException) { return null; }
    }

    /// The compact JSON the row holds.
    public static string ToJson(string mailbox, string scope, string by, DateTime utc) => JsonSerializer.Serialize(new Dictionary<string, string>
    {
        ["mailbox"] = mailbox, ["scope"] = scope, ["by"] = by, ["utc"] = utc.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture),
    });
}

/// <summary>The newest test mail (cfg.SignInMail, Kind 'mail-test'): queued, sent (or not yet), attempts, last error.</summary>
public sealed record MailTestResult(string? To, DateTime? QueuedAt, DateTime? SentAt, long Attempts, string? LastError)
{
    public const string Kind = "mail-test";

    public bool Sent => SentAt is not null;
    /// The engine tried and it failed (an error recorded, not sent).
    public bool Failed => SentAt is null && !string.IsNullOrWhiteSpace(LastError);
    public bool Waiting => SentAt is null && string.IsNullOrWhiteSpace(LastError);

    /// One line (times as UTC text: show it inside an element marked data-utc, which the browser rewrites to local time).
    public string Summary =>
        Sent ? "sent " + SI.Management.Web.Pages.Fmt.When(SentAt) + (To is null ? "" : " to " + To)
        : Failed ? $"FAILED after {Attempts} attempt(s): {LastError}"
        : "queued " + SI.Management.Web.Pages.Fmt.When(QueuedAt) + (To is null ? "" : " to " + To) + ", waiting for the mail job";
}
