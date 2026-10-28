using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Identity.Web;
using SI.Management.Web.Auth;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.Settings;

/// <summary>
/// Settings > E-mail + links > Set up mail (SuperAdmin; every run audited, every setting through the settings writer and
/// its cfg.ChangeLog row). Shared mailbox (recommended): create or pick the mailbox, then ONE button runs the Exchange
/// steps (module-free REST, with the signed-in admin's delegated Exchange token, requested only here -- incremental
/// consent through [AuthorizeForScopes]), verifies the restriction, saves the settings and queues a test mail. SMTP:
/// the relay settings (the password only as a Key Vault secret NAME) + a test mail. When the app cannot sign in to
/// Exchange on the admin's behalf, the page hands over setup\Set-SIMail.ps1 instead.
/// </summary>
[AuthorizeForScopes(Scopes = new[] { ExchangeAdminClient.DelegatedScope })]
public sealed class MailSetupModel : PageModel
{
    public const string NoAddressText = "Name the shared mailbox first: Settings > E-mail + links, step 1 -- this setup uses that address.";
    public const string NotAvailable = "One-click Exchange setup is not available on this install (the web app cannot sign in to Exchange on your behalf). Download setup\\Set-SIMail.ps1 and have your Exchange administrator run it";

    private readonly MailSetupFlow _flow;
    private readonly IExchangeTokenSource _tokens;
    private readonly ISettingsStoreReader _reader;
    private readonly IConfiguration _config;
    private readonly ILogger<MailSetupModel> _log;

    public MailSetupModel(MailSetupFlow flow, IExchangeTokenSource tokens, ISettingsStoreReader reader, IConfiguration config, ILogger<MailSetupModel> log)
    { _flow = flow; _tokens = tokens; _reader = reader; _config = config; _log = log; }

    /// "sharedMailbox" (default) or "smtp".
    [BindProperty(SupportsGet = true)] public string Choice { get; set; } = MailMode.SharedMailbox;
    /// "new" (create a shared mailbox) or "existing".
    [BindProperty] public string Mailbox { get; set; } = "new";
    /// #503: the address is the one named in step 1 (SI_Mail_From, Settings &gt; E-mail) -- this page has no field of its own.
    public string? Address { get; private set; }
    [BindProperty] public string DisplayName { get; set; } = "SecurityInsight";
    [BindProperty] public string? ClientId { get; set; }
    [BindProperty] public string? ObjectId { get; set; }

    [BindProperty] public string? SmtpServer { get; set; }
    [BindProperty] public string SmtpPort { get; set; } = "587";
    [BindProperty] public bool SmtpUseSsl { get; set; } = true;
    [BindProperty] public string? SmtpUser { get; set; }
    [BindProperty] public string? From { get; set; }
    [BindProperty] public string SmtpPasswordSecretName { get; set; } = MailSetupFlow.DefaultPasswordSecretName;

    public bool ExchangeAvailable => _tokens.IsAvailable;
    public string AdminUpn => User.ChangeName();
    public MailSetupResult? Result { get; private set; }
    public string? Error { get; private set; }
    /// The engine identity's client id came from the settings (the field is then prefilled).
    public bool ClientIdFromSettings { get; private set; }

    public async Task OnGetAsync(CancellationToken ct) => await PrefillAsync(ct);

    private async Task PrefillAsync(CancellationToken ct)
    {
        if (Choice is not (MailMode.SharedMailbox or MailMode.Smtp)) Choice = MailMode.SharedMailbox;
        try
        {
            var rows = (await _reader.ReadSettingsAsync(ct)).Rows;
            if (string.IsNullOrWhiteSpace(ClientId) && MailOverviewLoader.IdentityClientId(rows) is { } cid) { ClientId = cid; ClientIdFromSettings = true; }
            SmtpServer ??= MailMode.Plain(MailMode.RowOf(rows, MailMode.SmtpServerSetting)?.ValueJson);
            From ??= MailMode.FromAddress(rows);
            Address = MailMode.Plain(MailMode.RowOf(rows, MailMode.FromSetting)?.ValueJson)?.Trim() is { } a && SettingsForm.IsMailAddress(a) ? a : null;
            SmtpUser ??= MailMode.Plain(MailMode.RowOf(rows, MailMode.SmtpUserSetting)?.ValueJson);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "mail setup prefill"); }
    }

    /// The tenant of the signed-in admin (the token's tid), else the app's own tenant.
    private string TenantId => User.FindFirst("tid")?.Value ?? User.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid")?.Value ?? _config["AzureAd:TenantId"] ?? "";

    /// Runs the shared-mailbox setup, step by step (Exchange, verify, settings, test mail).
    [SI.Management.Web.Audit.Audited("mail.sharedmailbox.configure")]
    public async Task<IActionResult> OnPostSharedMailboxAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return AccessResults.Refused(Request, AccessDecision.No("setting up mail needs SuperAdmin."));
        Choice = MailMode.SharedMailbox;
        if (!_tokens.IsAvailable) { Error = NotAvailable + " (" + MailSetupFlow.ScriptUrl + ")."; return Page(); }
        // #503: the address named in step 1 -- never typed again here
        await PrefillAsync(ct);
        if (Address is null) { Error = NoAddressText; return Page(); }
        var setup = new SharedMailboxSetup(Mailbox != "existing", (Address ?? "").Trim(), (DisplayName ?? "").Trim(), (ClientId ?? "").Trim(), (ObjectId ?? "").Trim(), AdminUpn, TenantId);
        if (MailSetupFlow.Validate(setup) is { } why) { Error = why; return Page(); }
        // a MicrosoftIdentityWebChallengeUserException (consent for Exchange.Manage first) is NOT caught: [AuthorizeForScopes]
        // turns it into the incremental-consent sign-in, after which the admin presses the button again
        ExchangeToken token;
        try { token = await _tokens.GetAsync(User, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException && ex is not MicrosoftIdentityWebChallengeUserException && ex.InnerException is not Microsoft.Identity.Client.MsalUiRequiredException)
        {
            _log.LogWarning(ex, "Exchange token");
            Error = "No Exchange token could be acquired for your account: " + ex.Message;
            return Page();
        }
        var session = new ExchangeSession(TenantId, token.AccessToken, ExchangeAdminClient.Anchor(token.AppOnly, AdminUpn, _config["Exchange:TenantInitialDomain"]));
        Result = await _flow.RunSharedMailboxAsync(setup, session, User.ChangeName(), ct);
        // the handler's own word: the page has bound fields of the other form, which are not posted (model state is not the outcome)
        SI.Management.Web.Audit.AuditScope.Current?.Set(Result.Succeeded ? SI.Management.Web.Audit.AuditOutcomes.Ok : (Result.NeedsRole ? SI.Management.Web.Audit.AuditOutcomes.Refused : SI.Management.Web.Audit.AuditOutcomes.Error),
            string.Join("; ", Result.Steps.Select(s => s.Number + " " + s.Title + ": " + s.State)));
        return Page();
    }

    /// Saves the SMTP relay (+ SI_Mail_Mode = smtp) and queues a test mail to the signed-in admin.
    [SI.Management.Web.Audit.Audited("mail.smtp.configure")]
    public async Task<IActionResult> OnPostSmtpAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return AccessResults.Refused(Request, AccessDecision.No("setting up mail needs SuperAdmin."));
        Choice = MailMode.Smtp;
        var setup = new SmtpSetup((SmtpServer ?? "").Trim(), (SmtpPort ?? "").Trim(), SmtpUseSsl, SmtpUser, (From ?? "").Trim(), SmtpPasswordSecretName);
        if (MailSetupFlow.Validate(setup) is { } why) { Error = why; return Page(); }
        var to = EmailModel.OwnAddress(User);
        if (to is null) { Error = "Your account has no mail-style user name to send the test mail to."; return Page(); }
        Result = await _flow.RunSmtpAsync(setup, to, User.ChangeName(), ct);
        // the handler's own word: the page has bound fields of the other form, which are not posted (model state is not the outcome)
        SI.Management.Web.Audit.AuditScope.Current?.Set(Result.Succeeded ? SI.Management.Web.Audit.AuditOutcomes.Ok : (Result.NeedsRole ? SI.Management.Web.Audit.AuditOutcomes.Refused : SI.Management.Web.Audit.AuditOutcomes.Error),
            string.Join("; ", Result.Steps.Select(s => s.Number + " " + s.Title + ": " + s.State)));
        return Page();
    }
}
