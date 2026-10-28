using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Links;
using SI.Management.Web.RiskExec;

namespace SI.Management.Web.Pages;

/// <summary>
/// The big screen for the IT department: full-screen, reloads itself (default every 5 minutes), readable from across
/// the room. Headline numbers + the top 10 Tier-0 assets of the newest collection. The kiosk account has the Wallboard app
/// role, which opens this page and nothing else. Reads only the pre-computed aggregates and ONE page of findings.
/// #415 (operator 2026-10-06): the wall board is also the HOME page ("/") of every role that may see it, and it opens with
/// the Risk Score KPI panel (the kept Risk Analysis figures, <see cref="RiskScorePanel"/>). The kiosk account (and
/// ?kiosk=1, for a reader's account on a TV) gets the full-screen layout without a menu; everyone else the normal one.
/// </summary>
[SI.Management.Web.Exemptions.ExemptedSurface(SI.Management.Web.Exemptions.ExemptedSurface.Management, NoTick = true)]
public sealed class WallboardModel : PageModel
{
    private readonly IProDataQueries _q;
    private readonly WebSettings _settings;
    private readonly ILogger<WallboardModel> _log;
    private readonly ExecViewLoader _exec;
    private readonly SI.Management.Web.Settings.MailOverviewLoader _mail;
    private readonly SI.Management.Web.Settings.MailVerifier _verifier;
    private readonly SI.Management.Web.Settings.MailSetupFlow _mailFlow;
    public WallboardModel(IProDataQueries q, WebSettings settings, ExecViewLoader exec, SI.Management.Web.Settings.MailOverviewLoader mail,
        SI.Management.Web.Settings.MailVerifier verifier, SI.Management.Web.Settings.MailSetupFlow mailFlow, ILogger<WallboardModel> log)
    { _q = q; _settings = settings; _exec = exec; _mail = mail; _verifier = verifier; _mailFlow = mailFlow; _log = log; }

    /// The mail banner (red: mail is not set up; amber: it works but should move) -- for readers and up on the normal
    /// layout; the kiosk screen never shows it. Null = not shown to this viewer.
    public SI.Management.Web.Settings.MailBannerView? MailBanner { get; private set; }
    private string? _verifyMessage;

    /// "Verify" on the mail banner: starts the mail job once to check the Mail.Send restriction again (it rewrites
    /// cfg.InstallState 'MailRestriction'), then shows the page. Admin.
    [SI.Management.Web.Audit.Audited("mail.restriction.verify")]
    public async Task<Microsoft.AspNetCore.Mvc.IActionResult> OnPostVerifyAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return AccessResults.Refused(Request, AccessDecision.No("checking the mail restriction again needs Admin."));
        _verifyMessage = (await _verifier.StartAsync(ct)).Message;
        await OnGetAsync(ct);
        return Page();
    }

    /// "Ignore" on the SMTP amber of the mail banner (operator 2026-10-09: "make option to ignore"): the SMTP relay is kept
    /// by choice -- SI_Mail_SmtpKept = true through the settings writer, as every mail setting -- so the move hint is no
    /// longer shown here or on Settings > E-mail (Undo there). A failed test mail stays red whatever the choice. Admin.
    [SI.Management.Web.Audit.Audited("mail.smtp.keep")]
    public async Task<Microsoft.AspNetCore.Mvc.IActionResult> OnPostIgnoreAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return AccessResults.Refused(Request, AccessDecision.No("keeping the SMTP relay by choice needs Admin."));
        var errors = await _mailFlow.SetSmtpKeptAsync(true, User.ChangeName(), ct);
        if (errors.Count == 0)
        {
            // the banner is gone now, so the words go in the toast
            TempData["toast"] = "Your SMTP relay is kept by choice -- the hint to move to a shared mailbox is no longer shown. Undo on Settings > E-mail.";
            return RedirectToPage();
        }
        _verifyMessage = "Not saved: " + string.Join(" ", errors);
        await OnGetAsync(ct);
        return Page();
    }

    private async Task LoadMailBannerAsync(CancellationToken ct)
    {
        if (FullScreen || !User.IsReader() || User.IsMagic()) return;
        try
        {
            var o = await _mail.LoadAsync(ct);
            MailBanner = new SI.Management.Web.Settings.MailBannerView(o, User.IsAdmin(), User.IsAdmin(), _verifyMessage);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "wallboard mail banner"); }
    }

    /// ?kiosk=1: the full-screen layout without the menu (a reader's account on a TV); the Wallboard role always has it.
    [Microsoft.AspNetCore.Mvc.BindProperty(SupportsGet = true)] public string? Kiosk { get; set; }
    public bool FullScreen => Kiosk is "1" or "true" || User.IsWallboardOnly();
    /// #415: the Risk Score KPI panel -- the kept Risk Analysis figures (one risk-score source, #388).
    public RiskScorePanel RiskScore { get; private set; } = new(null, RiskExecGrain.Detailed, null);

    public WallboardKpis? Kpis { get; private set; }
    /// #855 M9 (owner 2026-10-21: "default filter is active, so it should be active only"): the CI lifecycle the board's finding
    /// counts and its top Tier-0 assets count -- ACTIVE CIs by default (a retired tier-0 CI is never in the top ten).
    public LifecycleFilter Lifecycle => LifecycleChoice.Read(HttpContext?.Request);
    /// #636 (owner 2026-10-19): the protection score tile -- both views, "within accepted lifecycle" by default (a CISO can
    /// switch to technical with ?view=technical); the same stored figures as the Executive overview and report.
    public ExecutiveFigures Protection { get; private set; } = new() { Missing = ExecutiveFigures.NotBuilt };
    [Microsoft.AspNetCore.Mvc.BindProperty(SupportsGet = true)] public string? View { get; set; }
    public string ViewKey => ExecutiveFigures.ProtectionView(View);
    public long Opened7 { get; private set; }
    public long Closed7 { get; private set; }
    public long? OpenNow { get; private set; }
    /// #292: the top Tier-0 assets by Very High, then High vulnerabilities, then risk (the Top-50 issues table was dropped).
    public IReadOnlyList<Tier0Asset> Tier0 { get; private set; } = Array.Empty<Tier0Asset>();
    public int RefreshSeconds { get; private set; } = 300;
    public DateTimeOffset At { get; } = DateTimeOffset.UtcNow;
    public List<string> Errors { get; } = new();

    public async Task OnGetAsync(CancellationToken ct)
    {
        try { RefreshSeconds = (await _settings.ReadAsync(ct)).WallboardRefreshSeconds; } catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "wallboard settings"); }
        await LoadMailBannerAsync(ct);
        try
        {
            var loaded = await _exec.LoadAsync(HttpContext, null, ct);
            RiskScore = RiskScorePanel.Of(loaded);
            if (loaded.Error is not null) Errors.Add("Risk Analysis KPI unavailable");
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogError(ex, "wallboard risk analysis kpi"); Errors.Add("Risk Analysis KPI unavailable"); }
        try { Protection = await ExecutiveFigures.LoadAsync(HttpContext.RequestServices, null, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogError(ex, "wallboard protection score"); }
        // owner 2026-10-20: the view switch drives the domain x severity table too, not only the two numbers
        RiskScore = RiskScore with { View = ViewKey, Figures = Protection };
        try { Kpis = (await _q.KpisAsync(Lifecycle, ct)).Data; }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogError(ex, "wallboard kpis"); Errors.Add("Headline numbers unavailable"); }
        try
        {
            var days = (await _q.LifecycleAsync(8, ct)).Data;
            var since = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-7));
            Opened7 = days.Where(d => d.Day > since).Sum(d => d.Opened);
            Closed7 = days.Where(d => d.Day > since).Sum(d => d.Closed);
            OpenNow = days.LastOrDefault(d => d.OpenAtEndOfDay is not null)?.OpenAtEndOfDay;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogError(ex, "wallboard lifecycle"); Errors.Add("Vulnerability flow unavailable"); }
        // #812: the rows the data sync wrote once per collection -- while they are not written the board says so (never the
        // per-refresh grouping of every finding)
        try
        {
            Tier0Prepared = await _q.Tier0PreparedAsync(ct);
            if (Tier0Prepared == true) Tier0 = (await _q.Tier0TopAsync(10, Lifecycle, ct)).Data;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogError(ex, "wallboard tier-0 assets"); Errors.Add("Top Tier-0 assets unavailable"); }
    }

    /// #812: whether the shown collection's top Tier-0 assets are written (false = being prepared; null = the update adds the tables).
    public bool? Tier0Prepared { get; private set; } = true;
}
