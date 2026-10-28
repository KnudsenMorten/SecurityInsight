using SI.Management.Web.Data;
using SI.Management.Web.Exemptions;

namespace SI.Management.Web.Settings;

/// <summary>
/// What the mail job recorded about the ONE mail transport: the restriction status (cfg.InstallState 'MailRestriction'),
/// an Exchange administrator's attestation ('MailRestrictionAttestation'), and the newest test mail (cfg.SignInMail,
/// Kind 'mail-test'). The guided setup also writes the attestation. Tests replace it with an in-memory fake.
/// </summary>
public interface IMailStatusStore
{
    Task<MailStatusSnapshot> ReadAsync(CancellationToken ct);
    Task WriteAttestationAsync(string json, string by, CancellationToken ct);
}

public sealed record MailStatusSnapshot(MailRestrictionStatus Restriction, MailAttestation? Attestation, MailTestResult? LastTest);

public sealed class SqlMailStatusStore : IMailStatusStore
{
    public const string RestrictionName = "MailRestriction";
    public const string AttestationName = "MailRestrictionAttestation";

    public const string StateSql = """
IF OBJECT_ID(N'cfg.InstallState') IS NOT NULL SELECT Name, Value, UpdatedAt FROM cfg.InstallState WHERE Name IN (N'MailRestriction', N'MailRestrictionAttestation');
""";

    public const string LastTestSql = """
IF OBJECT_ID(N'cfg.SignInMail') IS NOT NULL SELECT TOP (1) ToList, QueuedAt, SentAt, Attempts, LastError FROM cfg.SignInMail WHERE Kind = N'mail-test' ORDER BY QueuedAt DESC, MailId DESC;
""";

    /// The one row the web app writes in cfg.InstallState, only through its procedure: the web identity holds no write
    /// right on the table (the licence, the ring, the update state and the proven restriction are not the web app's).
    public const string AttestSql = "EXEC cfg.MailRestrictionAttestationSet @Value = @Value, @By = @By;";

    private readonly ISqlExecutor _sql;
    public SqlMailStatusStore(ISqlExecutor sql) => _sql = sql;

    public async Task<MailStatusSnapshot> ReadAsync(CancellationToken ct)
    {
        var state = await _sql.QueryAsync(StateSql, new Dictionary<string, object?>(), ct);
        var restriction = state.FirstOrDefault(r => string.Equals(r.Str("Name"), RestrictionName, StringComparison.OrdinalIgnoreCase));
        var attestation = state.FirstOrDefault(r => string.Equals(r.Str("Name"), AttestationName, StringComparison.OrdinalIgnoreCase));
        var test = (await _sql.QueryAsync(LastTestSql, new Dictionary<string, object?>(), ct)).FirstOrDefault(r => r.ContainsKey("QueuedAt"));
        return new MailStatusSnapshot(
            MailRestrictionStatus.Parse(restriction?.Str("Value")),
            MailAttestation.Parse(attestation?.Str("Value")),
            test is null ? null : new MailTestResult(test.Str("ToList"), test.Date("QueuedAt"), test.Date("SentAt"), test.Long("Attempts") ?? 0, test.Str("LastError")));
    }

    public async Task WriteAttestationAsync(string json, string by, CancellationToken ct)
    {
        if (json.Length > 400) throw new InvalidOperationException("the attestation is longer than cfg.InstallState holds (400)");
        await _sql.QueryAsync(AttestSql, new Dictionary<string, object?> { ["Value"] = json, ["By"] = by.Length > 256 ? by[..256] : by }, ct);
    }
}

/// Everything the Mail card and the home banner show, read once.
public sealed record MailOverview(MailModeResolution Mode, string? From, string? Identity, MailRestrictionStatus Restriction,
    MailAttestation? Attestation, MailTestResult? LastTest, MailHealthResult Health, string? Error, bool SmtpKept = false);

/// The home page banner (Pages/Shared/_MailBanner.cshtml): the overview, whether the viewer may open the setup (Admin)
/// and start a re-check (Admin), and the outcome of a Verify just pressed.
public sealed record MailBannerView(MailOverview Overview, bool CanSetup, bool CanVerify, string? Message);

/// Reads the settings + the recorded status into a <see cref="MailOverview"/>. Never throws (except cancellation): a
/// failed read is the overview's Error, and the verdict is then computed from what could be read.
public sealed class MailOverviewLoader
{
    /// The engine identity's client id, in the order the jobs read it.
    public static readonly string[] IdentitySettings = ["SI_UAMI_ClientId", "SI_ManagedIdentityClientId"];

    private readonly ISettingsStoreReader _settings;
    private readonly IMailStatusStore _store;
    private readonly ILogger<MailOverviewLoader> _log;

    public MailOverviewLoader(ISettingsStoreReader settings, IMailStatusStore store, ILogger<MailOverviewLoader> log) { _settings = settings; _store = store; _log = log; }

    /// The engine identity's client id from the settings rows, or null.
    public static string? IdentityClientId(IEnumerable<SettingRow> rows)
    {
        var list = rows.ToList();
        foreach (var name in IdentitySettings)
            if (MailMode.Plain(MailMode.RowOf(list, name)?.ValueJson) is { } v && v.Trim().Length > 0) return v.Trim();
        return null;
    }

    /// SI_Mail_SmtpKept from the settings rows: the SMTP relay kept by choice (absent or anything but true = not kept).
    public static bool SmtpKept(IEnumerable<SettingRow> rows) =>
        string.Equals(MailMode.Plain(MailMode.RowOf(rows, MailHealth.KeptSetting)?.ValueJson)?.Trim(), "true", StringComparison.OrdinalIgnoreCase);

    public async Task<MailOverview> LoadAsync(CancellationToken ct)
    {
        IReadOnlyList<SettingRow> rows = Array.Empty<SettingRow>();
        string? error = null;
        try { rows = (await _settings.ReadSettingsAsync(ct)).Rows; }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "mail settings"); error = "The mail settings could not be read."; }
        var snap = new MailStatusSnapshot(MailRestrictionStatus.NotRecorded, null, null);
        try { snap = await _store.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "mail status"); error ??= "The recorded mail status could not be read."; }
        var mode = MailMode.Resolve(rows);
        var from = MailMode.FromAddress(rows);
        var clientId = IdentityClientId(rows);
        var identity = clientId is null ? null : "managed identity " + clientId;
        var kept = SmtpKept(rows);
        return new MailOverview(mode, from, identity, snap.Restriction, snap.Attestation, snap.LastTest,
            MailHealth.Evaluate(mode, snap.Restriction, snap.LastTest, from, identity, kept), error, kept);
    }
}

/// The test mail: queued in the outbox (cfg.SignInMail, Kind 'mail-test') and sent by the mail job through the ONE
/// transport -- the web app never talks to a mail server.
public static class MailTestMail
{
    public const string Subject = "Test mail";   // MAIL-3 (#653): the transport adds "[<environment>]" and "[SecurityInsight]"

    /// #728: the mail layout -- a summary first ("Test mail: ...", "Mail mode: ..."), then one paragraph; no table.
    public static QueuedMail Build(string to, MailModeResolution mode, string? from) =>
        new(MailTestResult.Kind, null, null, new[] { to.Trim() }, Subject,
            SI.Management.Core.Mail.MailLayout.Summary(new[]
            {
                "<strong>Test mail:</strong> sent by SecurityInsight, no action needed",
                $"<strong>Mail mode:</strong> {System.Net.WebUtility.HtmlEncode(mode.Mode)} ({System.Net.WebUtility.HtmlEncode(MailMode.Label(mode.Mode))})"
                    + (string.IsNullOrWhiteSpace(from) ? "" : $", sent as {System.Net.WebUtility.HtmlEncode(from)}"),
            })
            + "<p>This is a test mail from SecurityInsight.</p>"
            + "<p>If you can read this, SecurityInsight can deliver its reports, safety-check alerts and close-loop mails.</p>");
}

/// <summary>"Verify": starts the close-loop mail job once, outbox-only, with SI_MAIL_VERIFY=1, so it re-runs the
/// restriction probe and rewrites cfg.InstallState 'MailRestriction'. Returns the words the page shows.</summary>
public sealed class MailVerifier
{
    public const string VerifyEnv = "SI_MAIL_VERIFY";

    private readonly SI.Management.Web.Jobs.IJobsClient _jobs;
    private readonly Microsoft.Extensions.Options.IOptions<SI.Management.Web.Jobs.JobsOptions> _options;
    private readonly ILogger<MailVerifier> _log;

    public MailVerifier(SI.Management.Web.Jobs.IJobsClient jobs, Microsoft.Extensions.Options.IOptions<SI.Management.Web.Jobs.JobsOptions> options, ILogger<MailVerifier> log)
    { _jobs = jobs; _options = options; _log = log; }

    public async Task<(bool Started, string Message)> StartAsync(CancellationToken ct)
    {
        var job = _options.Value.CloseLoopMailJob;
        if (!_jobs.IsConfigured || string.IsNullOrWhiteSpace(job))
            return (false, "The mail job cannot be started from here on this install -- the restriction is checked again at its next run.");
        try
        {
            await _jobs.StartWithEnvAsync(job, new Dictionary<string, string> { [OutboxExemptionMailer.OnlyEnv] = "1", [VerifyEnv] = "1" }, ct);
            return (true, "The mail job was started to check the restriction again -- reload this page in a few minutes.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the mail job could not be started for a restriction check");
            return (false, "The mail job could not be started: " + ex.Message);
        }
    }
}
