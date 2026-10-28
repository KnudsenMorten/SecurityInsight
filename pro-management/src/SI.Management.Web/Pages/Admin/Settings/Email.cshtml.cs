using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Advisors;
using SI.Management.Web.Auth;
using SI.Management.Web.Links;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.Settings;

/// <summary>
/// E-mail + links: first the Mail card -- the ONE mail transport (SI_Mail_Mode: none | smtp | sharedMailbox), the
/// mailbox SI sends as, who gets which mail, whether Mail.Send is restricted to the shared mailbox (as the mail job last
/// proved it), a test mail (queued in the outbox and sent by the mail job -- this app never talks to a mail server) and
/// the guided setup (SuperAdmin). Then the mail settings of the catalog and the web app's own link settings, each edited
/// through the normal setting editor (validated, reviewed, audited). The send schedule is the job's cron (Jobs page).
/// A link builder shows the deep link (and magic link, when enabled) an e-mail would carry.
/// </summary>
public sealed partial class EmailModel : PageModel
{
    [GeneratedRegex(@"^(Mail|SMTP|Smtp|SI_Mail_|SendMail$|RA_MailEvenIfEmpty$|SI_MaxMailAttachmentMB$|RiskAnalysis_.*SendMail$)", RegexOptions.CultureInvariant)]
    private static partial Regex MailName();

    /// The cookie that remembers, per user, that the "move to a shared mailbox" hint was dismissed.
    public const string HintCookie = "si-mail-move-hint";

    private readonly SettingsCatalog _catalog;
    private readonly ISettingsStoreReader _reader;
    private readonly DeepLinks _links;
    private readonly MailOverviewLoader _mail;
    private readonly ISignInMailer _mailer;
    private readonly MailSetupFlow _mailFlow;
    private readonly MailVerifier _verifier;
    private readonly Microsoft.Extensions.Options.IOptions<SI.Management.Web.Jobs.JobsOptions> _jobs;
    private readonly IConfiguration _config;
    private readonly ILogger<EmailModel> _log;

    public EmailModel(SettingsCatalog catalog, ISettingsStoreReader reader, DeepLinks links, MailOverviewLoader mail, ISignInMailer mailer, MailSetupFlow mailFlow,
        MailVerifier verifier, Microsoft.Extensions.Options.IOptions<SI.Management.Web.Jobs.JobsOptions> jobs, IConfiguration config, ILogger<EmailModel> log)
    { _catalog = catalog; _reader = reader; _links = links; _mail = mail; _mailer = mailer; _mailFlow = mailFlow; _verifier = verifier; _jobs = jobs; _config = config; _log = log; }

    public IReadOnlyList<CatalogSetting> Mail { get; private set; } = Array.Empty<CatalogSetting>();
    public IReadOnlyList<CatalogSetting> Web { get; private set; } = Array.Empty<CatalogSetting>();
    public ILookup<string, SettingRow> Rows { get; private set; } = Array.Empty<SettingRow>().ToLookup(r => r.Name);
    public string? Error { get; private set; }

    /// The Mail card: the mode, From, restriction, attestation, last test and the shared verdict.
    public MailOverview? Overview { get; private set; }
    /// The recipient setting of each mail type that this catalog has: (setting, mail type).
    public IReadOnlyList<(CatalogSetting Setting, string MailType)> Recipients { get; private set; } = Array.Empty<(CatalogSetting, string)>();
    /// ?hint=dismiss: the "move to a shared mailbox" hint is not shown again to this user (a cookie).
    [BindProperty(SupportsGet = true)] public string? Hint { get; set; }
    public bool MoveHintDismissed { get; private set; }

    [BindProperty] public string? TestTo { get; set; }
    public string? TestMessage { get; private set; }
    public string? TestError { get; private set; }

    [BindProperty] public string LinkPage { get; set; } = "/Management/Closure";
    [BindProperty] public string? LinkQuery { get; set; }
    public string? DeepLink { get; private set; }
    public string? MailLink { get; private set; }
    public string? LinkError { get; private set; }

    public static bool IsMail(string name) => MailName().IsMatch(name);

    /// The signed-in user's own address (the test mail's default recipient), when the sign-in carries a mail-style name.
    public static string? OwnAddress(System.Security.Claims.ClaimsPrincipal user)
    {
        foreach (var t in new[] { "email", "preferred_username", "upn", System.Security.Claims.ClaimTypes.Email, System.Security.Claims.ClaimTypes.Upn })
            if (user.FindFirst(t)?.Value is { } v && SettingsForm.IsMailAddress(v)) return v.Trim();
        return null;
    }

    /// The dismiss cookie's value for a user: a short hash of their name (one browser, several admins).
    public static string HintKey(string user) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(user.ToLowerInvariant())))[..16];

    public async Task OnGetAsync(CancellationToken ct)
    {
        var key = HintKey(User.ChangeName());
        if (string.Equals(Hint, "dismiss", StringComparison.OrdinalIgnoreCase))
        {
            Response.Cookies.Append(HintCookie, key, new CookieOptions
            {
                HttpOnly = true, Secure = Request.IsHttps, SameSite = SameSiteMode.Lax, IsEssential = true, MaxAge = TimeSpan.FromDays(3650), Path = "/Admin/Settings",
            });
            MoveHintDismissed = true;
        }
        TestTo ??= OwnAddress(User);
        await LoadAsync(ct);
    }

    private async Task LoadAsync(CancellationToken ct)
    {
        MoveHintDismissed |= string.Equals(Request.Cookies[HintCookie], HintKey(User.ChangeName()), StringComparison.Ordinal);
        Mail = _catalog.All.Where(s => IsMail(s.Name)).OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList();
        Web = _catalog.All.Where(s => s.WebOnly).ToList();
        Recipients = MailMode.RecipientSettings.Select(r => (Setting: _catalog.Find(r.Setting), r.MailType)).Where(r => r.Setting is not null)
            .Select(r => (r.Setting!, r.MailType)).ToList();
        try { Rows = (await _reader.ReadSettingsAsync(ct)).Rows.ToLookup(r => r.Name, StringComparer.OrdinalIgnoreCase); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogError(ex, "cfg.Setting"); Error = "The settings could not be read: " + ex.Message; }
        Overview = await _mail.LoadAsync(ct);
        MailboxSteps = StepsOf(Rows.SelectMany(g => g), User, _config, _jobs.Value);
    }

    /// #503: the shared mailbox in two steps (Pages/Shared/_MailboxSteps.cshtml) -- here and in Get Started's mail step.
    public SharedMailboxSteps? MailboxSteps { get; private set; }

    public static SharedMailboxSteps StepsOf(IEnumerable<SettingRow> rows, System.Security.Claims.ClaimsPrincipal user, IConfiguration config, SI.Management.Web.Jobs.JobsOptions jobs) =>
        SharedMailboxSteps.From(rows, OwnAddress(user), config["Exchange:TenantInitialDomain"], jobs.SubscriptionId, jobs.ResourceGroup);

    [BindProperty] public string? MailboxName { get; set; }
    [BindProperty] public string? MailDomainPick { get; set; }
    [BindProperty] public string? MailDomainOther { get; set; }
    [BindProperty] public string? MailDisplayName { get; set; }
    [BindProperty] public bool MailboxExists { get; set; }
    [BindProperty] public string? ReturnTo { get; set; }

    /// Where a step's form goes back to: Get Started's mail step or this card -- never anywhere else.
    private string Back(string anchor) => (ReturnTo == "/Admin/GetStarted?step=mail" ? "/Admin/GetStarted?step=mail" : "/Admin/Settings/Email") + "#" + anchor;

    /// Step 1 "Name and create": the mailbox name (the company's own naming), its domain -> the address is remembered as
    /// SI_Mail_From, through the settings writer. The command for the Exchange administrator is shown on the page.
    [SI.Management.Web.Audit.Audited("mail.sharedmailbox.configure")]
    public async Task<IActionResult> OnPostMailboxNameAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        if (!SharedMailboxSteps.IsName(MailboxName)) { await LoadAsync(ct); TestError = "Give the mailbox name: letters, digits, dot, dash or underscore (the part before the @)."; return Page(); }
        if (SharedMailboxSteps.AddressOf(MailboxName, SharedMailboxSteps.DomainOf(MailDomainPick, MailDomainOther)) is not { } address) { await LoadAsync(ct); TestError = "Choose the domain of the shared mailbox (for example contoso.com)."; return Page(); }
        var errors = await _mailFlow.SaveAsync(new[] { (MailMode.FromSetting, address) }, User.ChangeName(), ct, "shared mailbox named (step 1)");
        if (errors.Count > 0) { await LoadAsync(ct); TestError = "Not saved: " + string.Join(" ", errors); return Page(); }
        TempData["toast"] = $"Remembered {address}. When your Exchange administrator has run the command, validate it in step 2.";
        return Redirect(Back("mailbox-step2"));
    }

    /// Step 2 "Validate": the remembered address becomes the sender (mode sharedMailbox, the signed-in admin as the
    /// mailbox the restriction is proven against when none is set), the mail job checks the restriction again, and a test
    /// mail is queued to the admin -- one button.
    [SI.Management.Web.Audit.Audited("mail.sharedmailbox.configure")]
    public async Task<IActionResult> OnPostMailboxValidateAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var rows = (await _reader.ReadSettingsAsync(ct)).Rows;
        var address = StepsOf(rows, User, _config, _jobs.Value).Remembered;
        if (address is null) { await LoadAsync(ct); TestError = "Save the mailbox name in step 1 first."; return Page(); }
        var me = OwnAddress(User);
        var values = new List<(string, string)> { (MailMode.ModeSetting, MailMode.SharedMailbox), (MailMode.FromSetting, address) };
        if (me is not null && !string.Equals(me, address, StringComparison.OrdinalIgnoreCase) && MailMode.Plain(MailMode.RowOf(rows, MailMode.ProbeSetting)?.ValueJson) is not { Length: > 0 })
            values.Add((MailMode.ProbeSetting, me));
        var errors = await _mailFlow.SaveAsync(values, User.ChangeName(), ct, "shared mailbox validated (step 2)");
        if (errors.Count > 0) { await LoadAsync(ct); TestError = "Not saved: " + string.Join(" ", errors); return Page(); }
        var (_, verify) = await _verifier.StartAsync(ct);
        var test = me is null ? "Your account has no mail address for the test mail." :
            (await _mailFlow.QueueTestAsync(me, new MailModeResolution(MailMode.SharedMailbox, MailMode.FromSettingSource, null), address, User.ChangeName(), ct)) ?? $"A test mail to {me} is queued.";
        TempData["toast"] = $"{address} is the sender now. {verify} {test}";
        return Redirect(Back("mail"));
    }

    /// "Undo" on "SMTP relay kept by choice": SI_Mail_SmtpKept = false through the settings writer -- SecurityInsight
    /// recommends the shared mailbox again (Home and this card show the hint). Admin; audited as the keep it reverses.
    [SI.Management.Web.Audit.Audited("mail.smtp.keep")]
    public async Task<IActionResult> OnPostSmtpKeptUndoAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var errors = await _mailFlow.SetSmtpKeptAsync(false, User.ChangeName(), ct);
        if (errors.Count > 0) { await LoadAsync(ct); TestError = "Not saved: " + string.Join(" ", errors); return Page(); }
        TempData["toast"] = "SecurityInsight recommends the shared mailbox again -- the hint is shown on Home and here.";
        return RedirectToPage(null, null, "mail");
    }

    /// Queues a test mail in the outbox (cfg.SignInMail, Kind 'mail-test'); the mail job sends it through the ONE
    /// transport. Nothing here talks to a mail server.
    [SI.Management.Web.Audit.Audited("mail.test.send")]
    public async Task<IActionResult> OnPostTestMailAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        var to = (TestTo ?? "").Trim();
        if (!SettingsForm.IsMailAddress(to)) { TestError = $"'{to}' is not an e-mail address."; return Page(); }
        if (Overview!.Mode.IsNone) { TestError = "Mail is off (SI_Mail_Mode is none) -- set up mail first; a test mail would never be sent."; return Page(); }
        try
        {
            await _mailer.SendAsync(MailTestMail.Build(to, Overview.Mode, Overview.From), User.ChangeName(), ct);
            // the handler's own word: the page's other forms have bound fields that this post does not carry
            SI.Management.Web.Audit.AuditScope.Current?.Set(SI.Management.Web.Audit.AuditOutcomes.Ok, "queued for " + to);
            TestMessage = $"A test mail to {to} is queued -- the mail job sends it through the {Overview.Mode.Mode} transport within minutes. The result shows under 'Last test mail' (reload the page).";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "queueing the test mail failed");
            TestError = "The test mail could not be queued: " + ex.Message;
        }
        Overview = await _mail.LoadAsync(ct);
        return Page();
    }

    /// Builds the links an e-mail would carry for a page. A magic link is issued only when they are enabled (and is
    /// then a real, single-use link: do not share it).
    [SI.Management.Web.Audit.Audited("magiclink.link.issue")]
    public async Task<IActionResult> OnPostLinkAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        if (!DeepLinks.MagicPages.Contains(LinkPage, StringComparer.OrdinalIgnoreCase)) { LinkError = "Pick one of the listed pages."; return Page(); }
        var q = new Dictionary<string, string?>();
        foreach (var part in (LinkQuery ?? "").Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var i = part.IndexOf('=');
            if (i <= 0 || !Regex.IsMatch(part[..i], "^[A-Za-z]{1,16}$")) { LinkError = $"'{part}' is not name=value"; return Page(); }
            q[part[..i]] = Uri.UnescapeDataString(part[(i + 1)..]);
        }
        try
        {
            DeepLink = await _links.DeepAsync(LinkPage, q, ct);
            if (DeepLink is null) { LinkError = $"Set {WebSettings.PublicBaseUrl} first -- links are built on the app's public address."; return Page(); }
            var mail = await _links.ForMailAsync(LinkPage, q, ct);
            MailLink = mail != DeepLink ? mail : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "building a link failed");
            LinkError = "The link could not be built: " + ex.Message;
        }
        return Page();
    }
}
