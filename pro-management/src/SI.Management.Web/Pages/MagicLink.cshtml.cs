using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Advisors;
using SI.Management.Web.Auth;
using SI.Management.Web.Links;

namespace SI.Management.Web.Pages;

/// <summary>
/// Redeems a magic link (anonymous route; the token is the credential). Answers 404 while magic links are OFF (the
/// default). Two kinds of token:
/// <list type="bullet">
/// <item>the signed ONE-PAGE token of a mail: a genuine, unexpired, unused token for an allowed page creates a session
/// that can open THAT page only, read-only, until the token's expiry; the nonce is recorded so the link never works
/// again;</item>
/// <item>a DEPARTMENT sign-in token (#258, "d1."): per person, redeemed once against its stored hash; the session it
/// creates is scoped to the person's department and re-checked against its row on every request.</item>
/// </list>
/// A signed-in Admin or Reader is simply sent on (the token is still spent).
/// </summary>
[IgnoreAntiforgeryToken]
public sealed class MagicLinkModel : PageModel
{
    private readonly MagicLinkService _magic;
    private readonly DepartmentSignInService? _department;
    private readonly ILogger<MagicLinkModel> _log;
    private readonly bool _front;
    public MagicLinkModel(MagicLinkService magic, ILogger<MagicLinkModel> log, IConfiguration configuration, DepartmentSignInService? department = null)
    { _magic = magic; _log = log; _department = department; _front = SigninFront.IsEnabled(configuration); }

    public string? Why { get; private set; }
    /// Behind the sign-in front (CR7 Option A) the redeemed link becomes a link session under /MagicLink/s/ with its own
    /// cookie; without the front, the app's sign-in cookie as before.
    private string Scheme => _front ? LinkArea.Scheme : CookieAuthenticationDefaults.AuthenticationScheme;
    private string Into(string target) => _front ? LinkArea.Url(target) : target;

    [SI.Management.Web.Audit.Audited("signin.link.redeem")]
    public async Task<IActionResult> OnGetAsync(string? t, string? ended, CancellationToken ct)
    {
        Response.Headers["Cache-Control"] = "no-store";
        if (t is null && ended is not null) { Why = "You are signed out of the link session. A link works once: ask for a new one."; return Page(); }
        if (SignInSecrets.IsToken(t) && _department is not null) return await DepartmentAsync(t!, ct);
        (MagicToken? token, string? why) r;
        try { r = await _magic.RedeemAsync(t, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "magic link redemption failed");
            r = (null, "error");
        }
        if (r.why == "disabled") return NotFound();
        if (r.token is null)
        {
            _log.LogWarning("magic link refused: {Why}", r.why);
            Why = Words(r.why);
            return Page();
        }
        var target = r.token.Page + (r.token.Query.Length > 0 ? "?" + r.token.Query : "");
        if (SI.Management.Web.Audit.AuditScope.Current is { } audit)
        {
            // #260: who redeemed it is the link's own session (or the signed-in reader), never "anonymous"
            if (!User.IsReader()) { audit.Actor = "magic link (" + r.token.Page + ")"; audit.ActorSource = SI.Management.Web.Audit.AuditSources.Portal; }
            audit.Target = "magic link|" + r.token.Page;
        }
        if (User.IsReader()) return LocalRedirect(target);
        var id = new ClaimsIdentity(Scheme, "name", "roles");
        id.AddClaim(new Claim("name", "magic link"));
        id.AddClaim(new Claim("roles", Roles.MagicLink));
        id.AddClaim(new Claim(Claims.MagicPage, r.token.Page));
        // bound to the target: the page AND the query the token was signed for (a link to finding X never opens finding Y)
        id.AddClaim(new Claim(Claims.MagicQuery, r.token.Query));
        await HttpContext.SignInAsync(Scheme, new ClaimsPrincipal(id), new AuthenticationProperties
        {
            IsPersistent = false, AllowRefresh = false, ExpiresUtc = r.token.Expires,
        });
        _log.LogInformation("magic link redeemed for {Page}", r.token.Page);
        return LocalRedirect(Into(target));
    }

    private static string Words(string? why) => why switch
    {
        "expired" => "This link has expired.",
        "used" => "This link has already been used -- a magic link works once.",
        "revoked" => "This link was revoked.",
        "persongone" => "This link no longer opens: you are no longer listed for that department.",
        _ => "This link is not valid.",
    };

    /// A department sign-in link (#258).
    private async Task<IActionResult> DepartmentAsync(string token, CancellationToken ct)
    {
        (SignInRow? row, string? why) r;
        try { r = await _department!.RedeemAsync(token, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "department sign-in link redemption failed");
            r = (null, "error");
        }
        if (r.why == "disabled") return NotFound();
        if (r.row is null)
        {
            _log.LogWarning("department sign-in link refused: {Why}", r.why);
            Why = Words(r.why);
            return Page();
        }
        var target = DepartmentSignInService.SafeTarget(r.row.TargetPath, r.row.DepartmentId) ?? DepartmentSignInService.DefaultTarget(r.row.DepartmentId);
        if (SI.Management.Web.Audit.AuditScope.Current is { } audit)
        {
            // #260: the person the link was issued to, on their department's trail
            if (!User.IsReader()) { audit.Actor = r.row.PersonName; audit.ActorSource = SI.Management.Web.Audit.AuditSources.Portal; }
            audit.Target = "department-signin|" + r.row.SignInId;
            audit.DepartmentId = r.row.DepartmentId;
        }
        // someone already signed in on the ladder keeps their own sign-in (the link is spent)
        if (User.IsReader()) return LocalRedirect(target);
        // a HARD end: the session row's expiry (set at redemption, minutes; re-checked against the row on every request)
        var end = r.row.SessionExpiresAt is { } e ? new DateTimeOffset(DateTime.SpecifyKind(e, DateTimeKind.Utc)) : DateTimeOffset.UtcNow.AddMinutes(MagicTokenCodec.MaxLifetimeMinutes);
        await HttpContext.SignInAsync(Scheme, DepartmentSignInService.SessionPrincipal(r.row, r.row.PersonName), new AuthenticationProperties
        {
            IsPersistent = false, AllowRefresh = false, ExpiresUtc = end,
        });
        _log.LogInformation("department sign-in link {SignIn} redeemed for department {Department}", r.row.SignInId, r.row.DepartmentId);
        return LocalRedirect(Into(target));
    }
}
