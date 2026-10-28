using System.Globalization;
using System.Net;
using System.Text;
using SI.Management.Web.Jobs;

namespace SI.Management.Web.Exemptions;

/// <summary>
/// Where the exemption flow hands a mail. The web app never talks to a mail server: <see cref="OutboxExemptionMailer"/>
/// queues the mail in cfg.ExemptionMail and the close-loop mail job sends it through the Risk Analysis SMTP transports
/// (the one mail path, with its SMTP settings). Tests replace this with a recorder.
/// </summary>
public interface IExemptionMailer
{
    Task SendAsync(QueuedMail mail, string by, CancellationToken ct);
}

/// <summary>
/// Queues the mail, then -- best effort -- starts one execution of the close-loop mail job with
/// SI_EXEMPTION_MAIL_ONLY=1, so a request reaches its approvers in minutes instead of at the job's next daily run.
/// When the jobs are not reachable (or the start fails) the mail simply waits for that daily run: it is never lost.
/// </summary>
public sealed class OutboxExemptionMailer : IExemptionMailer
{
    public const string OnlyEnv = "SI_EXEMPTION_MAIL_ONLY";
    private readonly IExemptionStore _store;
    private readonly IJobsClient _jobs;
    private readonly Microsoft.Extensions.Options.IOptions<JobsOptions> _options;
    private readonly ILogger<OutboxExemptionMailer> _log;

    public OutboxExemptionMailer(IExemptionStore store, IJobsClient jobs, Microsoft.Extensions.Options.IOptions<JobsOptions> options, ILogger<OutboxExemptionMailer> log)
    { _store = store; _jobs = jobs; _options = options; _log = log; }

    public async Task SendAsync(QueuedMail mail, string by, CancellationToken ct)
    {
        await _store.QueueMailAsync(mail, by, ct);
        if (!_jobs.IsConfigured || string.IsNullOrWhiteSpace(_options.Value.CloseLoopMailJob)) return;
        try { await _jobs.StartWithEnvAsync(_options.Value.CloseLoopMailJob, new Dictionary<string, string> { [OnlyEnv] = "1" }, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the mail job could not be started -- the exemption mail goes with its next scheduled run");
        }
    }
}

/// <summary>
/// The request and decision mails, in the SI mail layout (#728: a summary first, one line per finding, no table). PURE: what goes in, what
/// comes out. The expiry warnings and the monthly review are composed by the mail job itself
/// (engine\asset-cmdb\_shared\SI-ExemptionMail.ps1), from the same tables.
/// </summary>
public static class ExemptionMailComposer
{
    public const int MaxListed = 50;
    private const string Font = "font-family:Segoe UI,Arial,sans-serif;";

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
    private static string Day(DateTime? d) => d is { } x ? x.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "no end date";

    /// To the most specific owners of the request's scope (#283: its category's owners, else its domain's owners, else its
    /// domain's approvers) -- or the one the requester asked: what is asked, why, until when, one link to decide.
    public static QueuedMail Request(RequestRow r, IReadOnlyList<RequestItem> items, IReadOnlyList<string> to, string? link)
    {
        var scope = r.ScopeLabel;
        // MAIL-3 (#653): the engine's transport adds "[<environment>]" and "[SecurityInsight]"; a request waits for a decision
        var subject = $"Action needed: Exemption request #{r.RequestId}: {r.ItemCount} finding(s) in {scope}, from {r.RequestedBy}";
        var body = new StringBuilder();
        // #728: the summary first -- what is asked and that the reader must act
        body.Append(SI.Management.Core.Mail.MailLayout.Summary(new[]
        {
            "<strong>Action needed:</strong> approve or reject this request",
            $"<strong>Request:</strong> {E(r.RequestedBy)} asks to exempt {r.ItemCount} finding(s) in {E(scope)} until {Day(r.ExpiresAt)}",
        }));
        body.Append(Para("Reason: " + SI.Management.Core.Mail.MailLayout.Inline(r.Reason)));
        if (r.Approver is not null) body.Append(Para("Asked of: " + E(r.Approver)));
        body.Append(Items(items));
        body.Append(Para("You receive this as an owner (or approver) of " + E(scope) + ". One approval is enough; nothing is exempted until the request is approved."));
        return new QueuedMail(QueuedMail.Request, r.RequestId, r.Domain, to, subject, Wrap("Exemption request", $"#{r.RequestId} · {E(scope)}", body.ToString(), link, "Approve or reject"));
    }

    /// To the requester: approved or rejected, by whom, with the approver's comment.
    public static QueuedMail Decision(RequestRow r, string state, string decidedBy, string? comment, int created, string? link)
    {
        var approved = state == ExemptionStates.Approved;
        var subject = $"Exemption request #{r.RequestId} {(approved ? "approved" : "rejected")} by {decidedBy}";
        var body = new StringBuilder();
        // #728: the summary first -- the decision, and whether anything is exempted
        body.Append(SI.Management.Core.Mail.MailLayout.Summary(new[]
        {
            $"<strong>Decision:</strong> {(approved ? "approved" : "rejected")} by {E(decidedBy)}",
            approved ? $"<strong>Exempted:</strong> {r.ItemCount} finding(s) in {E(r.ScopeLabel)} until {Day(r.ExpiresAt)}" : "<strong>Exempted:</strong> nothing",
        }));
        body.Append(Para(approved
            ? $"Your request to exempt <strong>{r.ItemCount}</strong> finding(s) in <strong>{E(r.ScopeLabel)}</strong> was <strong>approved</strong> by {E(decidedBy)}. The exemptions apply until {Day(r.ExpiresAt)}, from the next Risk Analysis run."
            : $"Your request to exempt <strong>{r.ItemCount}</strong> finding(s) in <strong>{E(r.ScopeLabel)}</strong> was <strong>rejected</strong> by {E(decidedBy)}. Nothing was exempted."));
        if (!string.IsNullOrWhiteSpace(comment)) body.Append(Para("Comment: " + SI.Management.Core.Mail.MailLayout.Inline(comment)));
        body.Append(Para("Your reason: " + SI.Management.Core.Mail.MailLayout.Inline(r.Reason)));
        if (approved && created < r.ItemCount) body.Append(Para($"{r.ItemCount - created} of them were already exempted and keep that exemption."));
        return new QueuedMail(QueuedMail.Decision, r.RequestId, r.Domain, new[] { r.RequestedBy }, subject,
            Wrap("Exemption " + (approved ? "approved" : "rejected"), $"#{r.RequestId} · {E(r.ScopeLabel)}", body.ToString(), link, "Open your exemptions"));
    }

    private static string Para(string html) => $"<p style=\"{SI.Management.Core.Mail.MailLayout.ParagraphStyle}\">{html}</p>";

    /// #728: ONE line per finding (no table): "CVE-2024-0001: OpenSSL · asset dc1 · report Summary".
    private static string Items(IReadOnlyList<RequestItem> items)
    {
        var sb = new StringBuilder();
        sb.Append(SI.Management.Core.Mail.MailLayout.Heading("The findings"));
        foreach (var i in items.Take(MaxListed))
        {
            var what = i.Title is null ? "" : E(i.Title) + " &middot; ";
            sb.Append(SI.Management.Core.Mail.MailLayout.Line(i.Cve ?? i.ConfigurationId ?? "every finding",
                html: $"{what}asset {E(i.Scope == "issue" ? "every asset" : i.AssetName ?? i.AssetKey)} &middot; report {E(i.ReportName ?? "every report")}"));
        }
        if (items.Count > MaxListed) sb.Append(Para($"... and {items.Count - MaxListed} more -- the link shows them all."));
        return sb.ToString();
    }

    /// #728: no table -- a max-width div frame; the button (a styled link) and the plain link after the body.
    private static string Wrap(string title, string sub, string body, string? link, string linkText)
    {
        var button = link is null ? "" :
            SI.Management.Core.Mail.MailLayout.Button(link, linkText, anyWebLink: true) +
            $"<p style=\"{Font}font-size:12px;color:#8a99aa;margin:0 0 14px 0;\">{E(link)}</p>";
        return SI.Management.Core.Mail.MailLayout.Frame($"SecurityInsight &middot; {E(title)}<br><span style=\"font-size:12px;color:#cfdce8;font-weight:400;\">{sub}</span>",
            null, null, body + button, "SecurityInsight Pro &middot; Exemptions");
    }
}