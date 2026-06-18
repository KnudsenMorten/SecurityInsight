namespace Sia.Web.Services;

/// <summary>
/// Configuration for the scheduled exec-summary email (REQUIREMENTS.md "SI Analyzer":
/// "scheduled monthly email ... so the CIO gets it without opening the tool"). Bound from
/// the "Sia:Email" config section (appsettings + env, themselves Key-Vault-backed in the
/// hosted env). Holds NO secrets in source.
///
/// Everything is config-driven and FAIL-SOFT: with no recipients or no SMTP host the
/// scheduler simply does nothing (it never crashes the app). The rendering + scheduling +
/// manual trigger are real and tested; the actual SMTP send is config-completed by the
/// operator (host/port/from), matching how the platform wires mail elsewhere.
/// </summary>
public sealed class EmailScheduleOptions
{
    public const string SectionName = "Sia:Email";

    /// <summary>Master switch for the scheduled send. Even when false the manual
    /// "send now" trigger + the MCP tool still render + (if a sender is configured) send.</summary>
    public bool Enabled { get; set; }

    /// <summary>Recipients (To). No recipients => nothing is sent (fail-soft).</summary>
    public List<string> Recipients { get; set; } = new();

    /// <summary>Cadence the scheduler sends on. One of: daily | weekly | monthly.
    /// Unknown/empty defaults to monthly (the board cadence).</summary>
    public string Cadence { get; set; } = "monthly";

    /// <summary>Hour of day (0-23, host local time) the scheduled send fires at.</summary>
    public int SendAtHour { get; set; } = 7;

    /// <summary>The reporting period the email's figures snap to (see ReportingPeriod
    /// presets: previous | month | quarter | half | year). Defaults to the quarter.</summary>
    public string? Period { get; set; }

    /// <summary>Absolute base URL of the hosted analyzer (e.g. https://app-... ). When set,
    /// the email links to "{BaseUrl}/board" for the full deck. Omitted => no link (never invented).</summary>
    public string? BaseUrl { get; set; }

    /// <summary>Friendly org/tenant label for the subject line. Optional; never a tenant id.</summary>
    public string? OrgLabel { get; set; }

    // ---- SMTP transport (operator-completed; absent => no send, fail-soft) ----------
    /// <summary>SMTP host. Absent => the sender is a no-op (renders but does not transmit).</summary>
    public string? SmtpHost { get; set; }

    /// <summary>SMTP port. Defaults to 587 (STARTTLS submission).</summary>
    public int SmtpPort { get; set; } = 587;

    /// <summary>Use STARTTLS/SSL for the SMTP connection.</summary>
    public bool SmtpUseSsl { get; set; } = true;

    /// <summary>Optional SMTP auth user. Absent => anonymous/relay (e.g. an internal relay).</summary>
    public string? SmtpUser { get; set; }

    /// <summary>Optional SMTP auth password (Key-Vault-backed app setting in the hosted env).</summary>
    public string? SmtpPassword { get; set; }

    /// <summary>From address. Required to actually send; absent => no send (fail-soft).</summary>
    public string? FromAddress { get; set; }

    /// <summary>Convenience: the board-deck URL derived from <see cref="BaseUrl"/>, or null.</summary>
    public string? BoardDeckUrl =>
        string.IsNullOrWhiteSpace(BaseUrl) ? null : BaseUrl!.TrimEnd('/') + "/board";

    /// <summary>True when at least one recipient AND the transport (host + from) are set,
    /// i.e. a real send can be attempted. When false the service still RENDERS (for the
    /// manual-trigger preview + tests) but reports "not configured" instead of crashing.</summary>
    public bool CanSend =>
        Recipients.Any(r => !string.IsNullOrWhiteSpace(r))
        && !string.IsNullOrWhiteSpace(SmtpHost)
        && !string.IsNullOrWhiteSpace(FromAddress);
}
