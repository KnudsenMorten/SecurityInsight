namespace SI.Management.Web.Settings;

/// <summary>
/// ONE verdict on SecurityInsight's mail, shared by the home page banner and Settings > E-mail + links (so both say the
/// same): red = mail is not set up (mode none; sharedMailbox not verified, or Mail.Send unrestricted; or the last test
/// mail failed), amber = it works but should move (smtp relay -> an Office 365 shared mailbox, unless the relay is kept by
/// choice -- SI_Mail_SmtpKept, then none; an Application Access
/// Policy -> RBAC for Applications), none = sharedMailbox verified. Pure.
/// </summary>
public static class MailHealth
{
    public const string Red = "red";
    public const string Amber = "amber";
    public const string Ok = "none";

    public const string RedTitle = "Mail is not set up -- reports, safety-check alerts and close-loop mails are not sent.";
    public const string SmtpTitle = "Mail goes through your own SMTP relay";
    public const string LegacyPolicyTitle = "Mail works, but Mail.Send is restricted by an Application Access Policy -- move it to RBAC for Applications";
    public const string MoveHint = "Move to an Office 365 shared mailbox";
    /// The SMTP relay kept by choice (SI_Mail_SmtpKept): mail is set up, the move hint is not shown.
    public const string SmtpKeptTitle = "Mail goes through your own SMTP relay (kept by choice)";
    public const string KeptSetting = "SI_Mail_SmtpKept";

    public static MailHealthResult Evaluate(MailModeResolution mode, MailRestrictionStatus? restriction, MailTestResult? lastTest, string? from = null, string? identity = null, bool smtpKept = false)
    {
        restriction ??= MailRestrictionStatus.NotRecorded;
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(identity)) parts.Add("SI identity: " + identity);
        parts.Add("Mail mode: " + mode.Mode + (mode.Problem is null ? "" : " (" + mode.Problem + ")"));
        if (!mode.IsNone) parts.Add("From: " + (string.IsNullOrWhiteSpace(from) ? "not set" : from));
        if (mode.IsSharedMailbox) parts.Add("Restriction: " + restriction.Label);
        parts.Add("Last test: " + (lastTest is null ? "none sent yet" : lastTest.Summary));
        var detail = string.Join(" · ", parts);

        if (mode.IsNone) return new(Red, RedTitle, detail, "Mail is off.");
        if (lastTest is { Failed: true }) return new(Red, RedTitle, detail, "The last test mail failed.");
        if (mode.IsSharedMailbox)
        {
            if (restriction.IsUnrestricted) return new(Red, RedTitle, detail, "Mail.Send is not restricted to the shared mailbox.");
            if (restriction.IsLegacyPolicy) return new(Amber, LegacyPolicyTitle, detail, null);
            if (!restriction.AllowsSend) return new(Red, RedTitle, detail, "Mail.Send is not restricted to the shared mailbox yet -- SecurityInsight refuses to send until the restriction is verified.");
            return new(Ok, "Mail is set up", detail, null);
        }
        // SMTP kept by choice: set up (a failed test mail is red above, whatever the choice)
        if (smtpKept) return new(Ok, SmtpKeptTitle, detail, null);
        return new(Amber, SmtpTitle, detail, MoveHint);
    }
}

/// The verdict: Level ("red" | "amber" | "none"), the title, the one detail line, and the reason / hint (or null).
public sealed record MailHealthResult(string Level, string Title, string Detail, string? Reason)
{
    public bool IsRed => Level == MailHealth.Red;
    public bool IsAmber => Level == MailHealth.Amber;
    public bool IsOk => Level == MailHealth.Ok;
    /// The SMTP amber: works through your own relay, the move to a shared mailbox is suggested (Ignore keeps the relay).
    public bool IsSmtpMove => IsAmber && Title == MailHealth.SmtpTitle;
    /// The SMTP relay kept by choice (Settings > E-mail offers Undo).
    public bool IsSmtpKept => IsOk && Title == MailHealth.SmtpKeptTitle;
}
