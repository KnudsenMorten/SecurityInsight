using System.Globalization;
using System.Net;
using System.Text;
using Microsoft.Extensions.Options;
using SI.Management.Web.Data;
using SI.Management.Web.GetStarted;
using SI.Management.Web.Jobs;
using SI.Management.Web.Links;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Notify;

/// <summary>
/// PURE. Framework MAIL-2 item 8 (SI #489, owner 2026-10-09: "not completed get started must be alerted daily by mail to
/// alert emails" / "to customer it"): while any REQUIRED Get Started step is open, ONE mail a day to the customer's IT -- the
/// alert recipients (SI_GuardMail_To), else the installing admin (SI_LicenseRequest_ContactEmail) -- never Invardia. It lists
/// the open required steps (why each matters, a blue button straight to the step), the optional ones separately as
/// "optional" (they never make the mail go out on their own), and stops by itself when every required step is done. With
/// the mail step itself open there is no working mail -- nothing is queued (Get Started shows it as the first open step).
///
/// SI #556 (owner 2026-10-10: "customer must also get a reminder to super admins if there are pending actions they have to
/// do in get started or approvals ... this comes from the solution, not invardia"): the SAME daily mail is the one "Waiting
/// for you" reminder. Next to the open required steps it lists everything that waits for a person's decision -- the menu's
/// blocking items (framework PENDING-1, <see cref="SI.Management.Web.Navigation.IBlockingItemSource"/>, the one source):
/// requests waiting for a second SuperAdmin (guard releases, restores), configuration imports waiting for a second
/// SuperAdmin, exemption requests waiting for their approver, guard holds and held template packs -- each with a button
/// straight to the page where it is decided. It goes out daily while anything waits and stops by itself when nothing does;
/// the per-recipient Notifications switch (the same entry, getstarted-reminder) and the reminder's on / off setting apply.
/// </summary>
public static class GetStartedReminderPlan
{
    public sealed record Plan(bool Send, string Why, IReadOnlyList<(string Audience, IReadOnlyList<string> To)> Groups, string Subject, string PeriodKey)
    {
        public int Recipients => Groups.Sum(g => g.To.Count);
    }

    /// The period of a day: "gs-2026-10-10" (fits cfg.ReportMail.PeriodKey, 16 characters).
    public static string PeriodKey(DateTime nowUtc) => "gs-" + nowUtc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    /// Who gets it: the alert recipients, else the installing admin's address.
    public static IReadOnlyList<string> Recipients(IReadOnlyList<SettingRow> rows)
    {
        if (NotifyCatalog.ListOf(rows, "SI_GuardMail_To") is { Count: > 0 } alert) return alert;
        var contact = rows.Where(r => r.Name.Equals("SI_LicenseRequest_ContactEmail", StringComparison.OrdinalIgnoreCase) && r.ValueJson is not null)
            .Select(r => r.ValueJson!.Trim().Trim('"').Trim()).FirstOrDefault(NotificationPrefs.IsAddress);
        return contact is null ? Array.Empty<string>() : new[] { contact };
    }

    /// The subject: the open required steps alone keep the Get Started wording; anything waiting for a decision makes it
    /// the "Waiting for you" mail. MAIL-3 (#653): the severity word "Action needed" first (a step or a decision the customer
    /// must take); the engine's transport adds "[&lt;environment&gt;]" in front and "[SecurityInsight]" at the end.
    public static string SubjectOf(int openSteps, int waiting) => waiting switch
    {
        0 => $"Action needed: Get Started is not finished -- {openSteps} required step{(openSteps == 1 ? " is" : "s are")} open",
        _ when openSteps == 0 => $"Action needed: waiting for you -- {Count(waiting, "decision")}",
        _ => $"Action needed: waiting for you -- {Count(waiting, "decision")} and {Count(openSteps, "Get Started step")}",
    };

    private static string Count(int n, string what) => n.ToString(CultureInfo.InvariantCulture) + " " + what + (n == 1 ? "" : "s");

    /// The decisions that wait (the menu's blocking items); none when not given.
    private static IReadOnlyList<SI.Management.Web.Navigation.BlockingItem> Waiting(SI.Management.Web.Navigation.BlockingSummary? w) =>
        w?.Items.Where(i => i.Count > 0).ToList() ?? (IReadOnlyList<SI.Management.Web.Navigation.BlockingItem>)Array.Empty<SI.Management.Web.Navigation.BlockingItem>();

    public static Plan Decide(GetStartedResult gs, IReadOnlyList<SettingRow> rows, NotificationPrefs prefs, bool enabled, int hourUtc, DateTime nowUtc,
        SI.Management.Web.Navigation.BlockingSummary? waiting = null)
    {
        var key = PeriodKey(nowUtc);
        // only a required step a PERSON must do: a step that waits for the first run closes by itself and reminds nobody
        var open = gs.Steps.Where(s => s.OpenRequired).ToList();
        var decisions = Waiting(waiting).Sum(i => i.Count);
        var subject = SubjectOf(open.Count, decisions);
        Plan No(string why) => new(false, why, Array.Empty<(string, IReadOnlyList<string>)>(), subject, key);
        if (!enabled) return No("the daily Waiting for you reminder is off (SIWeb_GetStartedReminder)");
        if (nowUtc.Hour < hourUtc) return No($"before {hourUtc:00}:00 UTC");
        // mail is an optional step now ("No mail" is a finished choice): without a working mail setup nothing can be sent
        if (gs.Steps.Any(s => s.Id == "mail" && !s.Done)) return No("mail is not set up yet -- Get Started shows that step");
        if (open.Count == 0 && decisions == 0) return No("nothing waits: every required Get Started step is done and no decision is pending");
        var to = Recipients(rows);
        if (to.Count == 0) return No("no alert recipient (SI_GuardMail_To) and no installing admin's address (SI_LicenseRequest_ContactEmail) is set");
        var groups = prefs.Route(to, NotifyCatalog.GetStartedReminder);
        if (groups.Count == 0) return No("every recipient switched the Waiting for you reminder off on the Notifications page");
        return new Plan(true, "", groups, subject, key);
    }

    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    /// The mail for one audience group: the summary, every decision that waits with a button to its page, every open
    /// required step with its button, then the optional ones.
    public static string Compose(GetStartedResult gs, string? baseUrl, DateTime nowUtc, string? tenant = null, SI.Management.Web.Navigation.BlockingSummary? waiting = null)
    {
        var open = gs.Steps.Where(s => s.OpenRequired).ToList();
        // the optional steps a person could still do -- never the ones that wait for the first run, never a finished choice
        var optional = gs.Steps.Where(s => s.Kind == "optional" && !s.Chosen && s.Step.Checkable).ToList();
        var decisions = Waiting(waiting);
        var nDecisions = decisions.Sum(i => i.Count);
        var sb = new StringBuilder();
        // #728: the summary block first
        var summary = new List<(string, string)>();
        if (nDecisions > 0) summary.Add(("Decisions waiting", nDecisions.ToString(CultureInfo.InvariantCulture)));
        summary.Add(("Required steps open", open.Count.ToString(CultureInfo.InvariantCulture)));
        summary.Add(("Steps done", gs.Done.ToString(CultureInfo.InvariantCulture) + " of " + gs.Total.ToString(CultureInfo.InvariantCulture)));
        summary.Add(("Optional steps open", optional.Count.ToString(CultureInfo.InvariantCulture)));
        sb.Append(MailBrand.Summary(summary));
        if (nDecisions > 0)
            sb.Append(MailBrand.Para("Some things in SecurityInsight Pro wait for a person's decision, and work stays held until they are decided. This reminder comes once a day and stops by itself when nothing waits any more."));
        if (open.Count > 0)
            sb.Append(MailBrand.Para("SecurityInsight Pro is installed, but some of the steps that make it work are still open. Until they are done, parts of SecurityInsight do not run or show nothing. This reminder comes once a day and stops by itself when every required step is done."));
        if (nDecisions > 0)
        {
            sb.Append(MailBrand.H2("Waiting for a decision"));
            foreach (var d in decisions)
            {
                sb.Append($"<div style=\"border:1px solid #e0e6ed;border-left:4px solid #bf8700;border-radius:6px;padding:10px 14px;margin:10px 0;\" data-waiting=\"{E(d.Kind)}\">");
                sb.Append($"<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:15px;font-weight:600;color:#0B1633;\">{E(Sentence(d.Text))}</div>");
                sb.Append(MailBrand.Para("<strong>Who decides:</strong> " + E(d.WhoCanAct) + "."));
                // a kind without a page of its own opens the Overview, where every waiting item is listed
                sb.Append(MailBrand.AudienceButton(baseUrl, null, d.Page ?? "/", "Open the page to decide"));
                sb.Append("</div>");
            }
        }
        if (open.Count > 0) sb.Append(MailBrand.H2("Required steps still open"));
        foreach (var s in open)
        {
            sb.Append($"<div style=\"border:1px solid #e0e6ed;border-left:4px solid #cf222e;border-radius:6px;padding:10px 14px;margin:10px 0;\" data-open-step=\"{E(s.Id)}\">");
            sb.Append($"<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:15px;font-weight:600;color:#0B1633;\">{E(s.Step.Title)}</div>");
            sb.Append($"<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#57606a;margin:2px 0 6px 0;\">Now: {E(s.Note)}</div>");
            sb.Append(MailBrand.Para("<strong>Why it matters:</strong> " + E(s.Step.What)));
            sb.Append(MailBrand.AudienceButton(baseUrl, null, "/Admin/GetStarted?step=" + Uri.EscapeDataString(s.Id), "Open this step"));
            sb.Append("</div>");
        }
        if (optional.Count > 0)
        {
            sb.Append(MailBrand.H2("Optional steps"));
            sb.Append(MailBrand.Para("These are optional: they never make this reminder go out on their own."));
            sb.Append("<ul style=\"font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#24292f;\">");
            foreach (var s in optional) sb.Append($"<li data-optional-step=\"{E(s.Id)}\"><strong>{E(s.Step.Title)}</strong> (optional) -- {E(s.Note)}</li>");
            sb.Append("</ul>");
        }
        if (nDecisions == 0)
            return MailBrand.Wrap("Get Started is not finished", $"{open.Count} required step{(open.Count == 1 ? " is" : "s are")} open", sb.ToString(), baseUrl, nowUtc, tenant);
        var sub = open.Count == 0 ? Count(nDecisions, "decision") + " waiting" : Count(nDecisions, "decision") + " waiting and " + Count(open.Count, "required step") + " open";
        return MailBrand.Wrap("Waiting for you", sub, sb.ToString(), baseUrl, nowUtc, tenant);
    }

    /// "2 guard holds wait for a release" -> "2 guard holds wait for a release."
    private static string Sentence(string text) => string.IsNullOrWhiteSpace(text) ? "" : char.ToUpperInvariant(text[0]) + text[1..] + (text.EndsWith('.') ? "" : ".");
}

/// The outbox write of the reminder: one row per day and audience group, claimed so that two replicas never send twice.
public interface IReminderOutbox
{
    /// Queues the day's reminder unless one is already queued for that period; true = queued now.
    Task<bool> QueueOnceAsync(string periodKey, IReadOnlyList<(IReadOnlyList<string> To, string Subject, string Html)> mails, CancellationToken ct);
}

/// <summary>cfg.ReportMail with ReportId 0 (the Get Started reminder -- a management summary's id starts at 1), the outbox
/// the mail job already sends. The INSERT runs only when no row of that period exists, under a range lock.</summary>
public sealed class SqlReminderOutbox(ISqlExecutor sql) : IReminderOutbox
{
    public const long ReminderReportId = 0;
    public const string QueueSql = """
IF OBJECT_ID(N'cfg.ReportMail') IS NULL BEGIN SELECT 0 AS Queued; RETURN; END
BEGIN TRAN;
IF EXISTS (SELECT 1 FROM cfg.ReportMail WITH (UPDLOCK, HOLDLOCK) WHERE ReportId = 0 AND PeriodKey = @PeriodKey AND @First = 1)
BEGIN COMMIT; SELECT 0 AS Queued; RETURN; END
INSERT cfg.ReportMail (ReportId, PeriodKey, ToList, Subject, BodyHtml, QueuedBy) VALUES (0, @PeriodKey, @ToList, @Subject, @BodyHtml, N'SecurityInsight');
COMMIT;
SELECT 1 AS Queued;
""";

    public async Task<bool> QueueOnceAsync(string periodKey, IReadOnlyList<(IReadOnlyList<string> To, string Subject, string Html)> mails, CancellationToken ct)
    {
        var first = true;
        foreach (var m in mails)
        {
            var r = await sql.QueryAsync(QueueSql, new Dictionary<string, object?>
            {
                ["PeriodKey"] = periodKey, ["First"] = first ? 1 : 0, ["ToList"] = Cut(string.Join(";", m.To), 2000), ["Subject"] = Cut(m.Subject, 400), ["BodyHtml"] = SI.Management.Core.Mail.MailLayout.Normalize(m.Html),
            }, ct);
            if (first && (r.FirstOrDefault()?.Long("Queued") ?? 0) != 1) return false;
            first = false;
        }
        return !first;
    }

    private static string Cut(string s, int n) => s.Length > n ? s[..n] : s;
}

/// <summary>
/// Runs the reminder: evaluates Get Started from the install's data, decides, composes one mail per audience group, queues
/// it once a day and wakes the mail job (best effort). Writes its audit row. Never sends a mail itself.
/// </summary>
public sealed class GetStartedReminderService(GetStartedService getStarted, NotificationService notify, WebSettings web, IReminderOutbox outbox,
    IJobsClient jobs, IOptions<JobsOptions> jobOptions, SI.Management.Web.Audit.IAuditWriter audit, SI.Management.Web.Changes.InstallTenantReader tenant,
    TimeProvider clock, ILogger<GetStartedReminderService> log, SI.Management.Web.Navigation.IBlockingItemSource? blocking = null,
    SI.Management.Web.Licensing.IProLicence? licence = null)
{
    /// SI #556: what waits for a decision, from the menu's one source (never fails the pass: unreadable = nothing waits).
    private async Task<SI.Management.Web.Navigation.BlockingSummary> WaitingAsync(CancellationToken ct)
    {
        if (blocking is null) return SI.Management.Web.Navigation.BlockingSummary.None;
        try { return await blocking.ReadAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogDebug(ex, "waiting decisions"); return SI.Management.Web.Navigation.BlockingSummary.None; }
    }

    public async Task<GetStartedReminderPlan.Plan> RunOnceAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var state = await notify.ReadAsync(ct);
        var enabled = !state.Rows.Any(r => r.Name.Equals(NotifySettings.Reminder, StringComparison.OrdinalIgnoreCase) && (r.ValueJson ?? "").Trim().Equals("false", StringComparison.OrdinalIgnoreCase));
        var hour = state.Rows.FirstOrDefault(r => r.Name.Equals(NotifySettings.ReminderHour, StringComparison.OrdinalIgnoreCase)) is { ValueJson: { } hj }
            && int.TryParse(hj.Trim().Trim('"'), NumberStyles.Integer, CultureInfo.InvariantCulture, out var h) && h is >= 0 and <= 23 ? h : 7;
        if (!enabled || now.Hour < hour) return GetStartedReminderPlan.Decide(new GetStartedResult(Array.Empty<StepState>()), state.Rows, state.Prefs, enabled, hour, now);
        var gs = await getStarted.EvaluateAsync(fresh: true, ct);
        var waiting = await WaitingAsync(ct);
        var plan = GetStartedReminderPlan.Decide(gs, state.Rows, state.Prefs, enabled, hour, now, waiting);
        if (!plan.Send) { log.LogDebug("Waiting for you reminder: not sent -- {Why}", plan.Why); return plan; }
        var baseUrl = (await web.ReadAsync(ct)).PublicBaseUrl;
        string? tenantName = null;
        try { tenantName = (await tenant.ReadAsync(ct))?.Name; } catch (Exception ex) when (ex is not OperationCanceledException) { log.LogDebug(ex, "tenant name"); }
        var html = GetStartedReminderPlan.Compose(gs, baseUrl, now, tenantName, waiting);
        // owner 2026-10-28: the Community edition's mail carries the Community edition's name (Pro only while the licence says Pro)
        html = MailBrand.ForEdition(html, (await SI.Management.Web.Licensing.EditionBrand.CurrentAsync(licence, ct)).Pro);
        var queued = await outbox.QueueOnceAsync(plan.PeriodKey, plan.Groups.Select(g => (g.To, plan.Subject, html)).ToList(), ct);
        if (!queued) return plan with { Send = false, Why = "already queued today" };
        var waitingText = waiting.Total == 0 ? "" : $"; {waiting.Total} decision(s) waiting ({string.Join(", ", waiting.Items.Select(i => i.Kind + "=" + i.Count.ToString(CultureInfo.InvariantCulture)))})";
        await audit.WriteAsync(new SI.Management.Web.Audit.AuditRecord("getstarted.reminder.send", "scheduler", "job", "ok")
        {
            Target = "/Admin/GetStarted", OutcomeText = $"queued for {plan.Recipients} recipient(s): {gs.OpenRequired} required step(s) open ({string.Join(", ", gs.Steps.Where(s => s.OpenRequired).Select(s => s.Id))}){waitingText}",
        }, CancellationToken.None);
        if (jobs.IsConfigured && !string.IsNullOrWhiteSpace(jobOptions.Value.CloseLoopMailJob))
        {
            try { await jobs.StartWithEnvAsync(jobOptions.Value.CloseLoopMailJob, new Dictionary<string, string> { [SI.Management.Web.Exemptions.OutboxExemptionMailer.OnlyEnv] = "1" }, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "the mail job could not be started -- the Get Started reminder goes with its next run"); }
        }
        return plan;
    }
}

/// The reminder's clock: one pass every 15 minutes (the first after 5 minutes); the outbox claim makes it once a day.
public sealed class GetStartedReminderScheduler(IServiceProvider services, ILogger<GetStartedReminderScheduler> log) : BackgroundService
{
    public static readonly TimeSpan First = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan Every = TimeSpan.FromMinutes(15);
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var wait = First;
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(wait, stoppingToken); } catch (OperationCanceledException) { return; }
            wait = Every;
            try { await services.GetRequiredService<GetStartedReminderService>().RunOnceAsync(stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogWarning(ex, "Get Started reminder pass"); }
        }
    }
}
