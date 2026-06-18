using System.Net;
using System.Net.Mail;
using Sia.Core.Exec;

namespace Sia.Web.Services;

/// <summary>The transport that actually delivers a rendered exec-summary email.
/// Abstracted so the service + tests can render-and-route without a live mail server,
/// and so the SMTP transport can be swapped for a Graph sender later without touching
/// the orchestration. ALWAYS fail-soft: a transport that is not configured returns a
/// "not sent" result, it never throws.</summary>
public interface IExecEmailSender
{
    /// <summary>True when the transport is configured enough to attempt a real send.</summary>
    bool IsConfigured { get; }

    /// <summary>Send the rendered message to the recipients. Returns a result describing
    /// what happened; never throws on a config/transport problem (it is reported instead).</summary>
    Task<EmailSendResult> SendAsync(ExecEmailMessage message, IReadOnlyList<string> recipients, CancellationToken ct = default);
}

/// <summary>The outcome of an attempted exec-summary send (for the API + MCP + logs).</summary>
public sealed record EmailSendResult(bool Sent, int RecipientCount, string Detail)
{
    public static EmailSendResult NotConfigured(string why) => new(false, 0, why);
    public static EmailSendResult Delivered(int count) => new(true, count, $"Sent to {count} recipient(s).");
    public static EmailSendResult Failed(string why) => new(false, 0, "Send failed (fail-soft): " + why);
}

/// <summary>
/// SMTP-backed sender. Config-driven (host/port/from/auth from <see cref="EmailScheduleOptions"/>);
/// when the transport is not configured (<see cref="EmailScheduleOptions.CanSend"/> false) it is a
/// NO-OP that returns "not configured" - so a fresh deploy with no SMTP set never crashes. When
/// configured it sends a multipart HTML + plain-text alternative.
/// </summary>
public sealed class SmtpExecEmailSender : IExecEmailSender
{
    private readonly EmailScheduleOptions _opts;
    private readonly ILogger<SmtpExecEmailSender> _log;

    public SmtpExecEmailSender(EmailScheduleOptions opts, ILogger<SmtpExecEmailSender> log)
    {
        _opts = opts;
        _log = log;
    }

    public bool IsConfigured => _opts.CanSend;

    public async Task<EmailSendResult> SendAsync(ExecEmailMessage message, IReadOnlyList<string> recipients, CancellationToken ct = default)
    {
        var to = recipients.Where(r => !string.IsNullOrWhiteSpace(r)).Distinct().ToList();
        if (to.Count == 0) return EmailSendResult.NotConfigured("No recipients configured.");
        if (string.IsNullOrWhiteSpace(_opts.SmtpHost) || string.IsNullOrWhiteSpace(_opts.FromAddress))
            return EmailSendResult.NotConfigured("SMTP host / from-address not configured.");

        try
        {
            using var mail = new MailMessage { From = new MailAddress(_opts.FromAddress!), Subject = message.Subject };
            foreach (var r in to) mail.To.Add(r);
            mail.Body = message.TextBody;                          // plain-text fallback as the body
            mail.IsBodyHtml = false;
            var htmlView = AlternateView.CreateAlternateViewFromString(message.HtmlBody, null, "text/html");
            mail.AlternateViews.Add(htmlView);

            using var client = new SmtpClient(_opts.SmtpHost, _opts.SmtpPort) { EnableSsl = _opts.SmtpUseSsl };
            if (!string.IsNullOrWhiteSpace(_opts.SmtpUser))
                client.Credentials = new NetworkCredential(_opts.SmtpUser, _opts.SmtpPassword ?? "");

            await client.SendMailAsync(mail, ct);
            _log.LogInformation("Exec-summary email sent to {Count} recipient(s).", to.Count);
            return EmailSendResult.Delivered(to.Count);
        }
        catch (Exception ex)
        {
            // Fail-soft: a transport error is reported, never thrown (the scheduler must not crash).
            _log.LogWarning(ex, "Exec-summary email send failed (fail-soft).");
            return EmailSendResult.Failed(ex.Message);
        }
    }
}
