using SI.Management.Web.Data;
using SI.Management.Web.Exemptions;
using SI.Management.Web.Jobs;

namespace SI.Management.Web.Advisors;

/// Where a department sign-in mail (a link, a one-time code) is handed. Tests replace it with a recorder.
public interface ISignInMailer
{
    Task SendAsync(QueuedMail mail, string by, CancellationToken ct);
}

/// <summary>
/// Queues the mail in cfg.SignInMail (#258) and -- best effort -- starts the close-loop mail job in its outbox-only mode,
/// as the exemption mails do: the job sends it through the Risk Analysis SMTP path and BLANKS ITS BODY once sent
/// (engine\asset-cmdb\_shared\SI-ExemptionMail.ps1), so the secret is in the database only until the mail goes out.
/// The web app never talks to a mail server.
/// </summary>
public sealed class OutboxSignInMailer : ISignInMailer
{
    public const string QueueSql = """
INSERT cfg.SignInMail (Kind, ToList, Subject, BodyHtml, QueuedBy) VALUES (@Kind, @ToList, @Subject, @BodyHtml, @By);
SELECT N'Saved' AS Outcome;
""";

    private readonly ISqlExecutor _sql;
    private readonly IJobsClient _jobs;
    private readonly Microsoft.Extensions.Options.IOptions<JobsOptions> _options;
    private readonly ILogger<OutboxSignInMailer> _log;

    public OutboxSignInMailer(ISqlExecutor sql, IJobsClient jobs, Microsoft.Extensions.Options.IOptions<JobsOptions> options, ILogger<OutboxSignInMailer> log)
    { _sql = sql; _jobs = jobs; _options = options; _log = log; }

    private static string Cut(string s, int n) => s.Length > n ? s[..n] : s;

    public async Task SendAsync(QueuedMail mail, string by, CancellationToken ct)
    {
        await _sql.QueryAsync(QueueSql, new Dictionary<string, object?>
        {
            ["Kind"] = mail.Kind, ["ToList"] = Cut(string.Join(";", mail.To), 2000), ["Subject"] = Cut(mail.Subject, 400), ["BodyHtml"] = SI.Management.Core.Mail.MailLayout.Normalize(mail.BodyHtml), ["By"] = Cut(by, 256),
        }, ct);
        if (!_jobs.IsConfigured || string.IsNullOrWhiteSpace(_options.Value.CloseLoopMailJob)) return;
        try { await _jobs.StartWithEnvAsync(_options.Value.CloseLoopMailJob, new Dictionary<string, string> { [OutboxExemptionMailer.OnlyEnv] = "1" }, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the mail job could not be started -- the sign-in mail goes with its next run");
        }
    }
}
