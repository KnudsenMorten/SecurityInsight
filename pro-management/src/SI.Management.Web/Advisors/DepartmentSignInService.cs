using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Caching.Memory;
using SI.Management.Web.Auth;
using SI.Management.Web.Exemptions;
using SI.Management.Web.Links;
using SI.Management.Web.Settings;
using SI.Management.Web.Navigation;

namespace SI.Management.Web.Advisors;

/// <summary>
/// DEPARTMENT SIGN-IN (#258): magic links per person, scoped to one department, and the one-time code that is the second
/// check before an approval. The rules (operator, 2026-10-04):
/// <list type="bullet">
/// <item>a link is PER PERSON (an advisor, or a person of the department with a mail address), short-lived (the magic-link
/// lifetime setting), SINGLE-USE (redeemed once, atomically -- the redeemed link becomes the session), REVOCABLE (the link,
/// or the advisor; the session re-checks its row on every request), SCOPED to the department;</item>
/// <item>issued from the department's admin page, or asked for by the person from a mail's link (the mail itself never
/// carries a secret the engines made);</item>
/// <item>a link session may view, comment and recommend; APPROVE needs the second check -- a one-time code mailed to the
/// same mailbox -- or an Entra sign-in;</item>
/// <item>only hashes are stored; every step has its cfg.ChangeLog row.</item>
/// </list>
/// Off with the magic links (SIWeb_MagicLinksEnabled, off by default); a mail also needs SIWeb_ExemptionMailEnabled (the
/// web app's mail switch). The mails go through their own outbox (cfg.SignInMail), whose sender blanks them once sent.
/// </summary>
public sealed partial class DepartmentSignInService
{
    public const int CodeMinutes = 10;
    public const int MaxCodeAttempts = 5;
    public const int MaxCodesPerHour = 3;
    /// Links a person may ASK for in an hour (the anonymous request page).
    public const int MaxRequestedPerHour = 3;
    /// Links an Admin may send one person in an hour.
    public const int MaxIssuedPerHour = 10;
    public const string OriginAdmin = "admin";
    public const string OriginRequest = "request";
    public const string MailKind = "sign-in";
    public const string CodeMailKind = "sign-in-code";

    [GeneratedRegex(@"^[^@\s;,<>""]{1,64}@[^@\s;,<>""]{1,190}\.[A-Za-z]{2,}$", RegexOptions.CultureInvariant)] private static partial Regex MailPattern();

    private readonly IDepartmentSignInStore _store;
    private readonly IAdvisorStore _people;
    private readonly WebSettings _web;
    private readonly ExemptionSettings _mail;
    private readonly ISignInMailer _mailer;
    private readonly IMemoryCache _cache;
    private readonly IAccessScope _access;
    private readonly ILogger<DepartmentSignInService> _log;
    private readonly TimeProvider _clock;

    public DepartmentSignInService(IDepartmentSignInStore store, IAdvisorStore people, WebSettings web, ExemptionSettings mail, ISignInMailer mailer, IMemoryCache cache,
        IAccessScope access, ILogger<DepartmentSignInService> log, TimeProvider? clock = null)
    { _store = store; _people = people; _web = web; _mail = mail; _mailer = mailer; _cache = cache; _access = access; _log = log; _clock = clock ?? TimeProvider.System; }

    public DateTime Now => _clock.GetUtcNow().UtcDateTime;
    public static string SessionCacheKey(long signInId) => "si-dept-session|" + signInId.ToString(CultureInfo.InvariantCulture);

    /// Whether links can be sent now, and if not, why (for the admin page).
    public async Task<(bool On, string? Why)> AvailableAsync(CancellationToken ct)
    {
        var w = await _web.ReadAsync(ct);
        if (!w.MagicLinksEnabled) return (false, "Magic links are off (" + NavModel.PathOf("/Admin/Settings/Email") + ": Magic links in e-mails).");
        if (string.IsNullOrWhiteSpace(w.PublicBaseUrl)) return (false, "The web app's public address is not set (SIWeb_PublicBaseUrl) -- a link needs it.");
        if (!(await _mail.ReadAsync(ct)).MailEnabled) return (false, "Web app mails are off (SIWeb_ExemptionMailEnabled): a sign-in link could not be delivered.");
        if (!await _people.ReadyAsync(ct)) return (false, "The Pro database does not have the advisor / sign-in tables yet: apply sql\\si-pro-settings.sql again (it only adds).");
        return (true, null);
    }

    /// A target inside the department area only (the session can open nothing else anyway).
    public static string? SafeTarget(string? target, int departmentId)
    {
        var t = (target ?? "").Trim();
        if (t.Length == 0 || t.Length > 400 || !t.StartsWith("/Departments/", StringComparison.OrdinalIgnoreCase) || t.Contains("//", StringComparison.Ordinal)
            || t.Contains("..", StringComparison.Ordinal) || t.Contains('\\') || t.Any(char.IsControl)) return null;
        return t;
    }

    public static string DefaultTarget(int departmentId) => "/Departments/Detail?id=" + departmentId.ToString(CultureInfo.InvariantCulture);

    // ------------------------------------------------------------------------------------------------- issue

    /// An Admin sends one person of the department a sign-in link (the department's admin page / department page).
    public async Task<WriteResult> IssueAsync(ClaimsPrincipal by, int departmentId, string personKind, int personId, string? target, CancellationToken ct)
    {
        var gate = _access.Can(by, AccessAction.Administer);
        if (!gate.Allowed) return new WriteResult(WriteStatus.Refused, gate.Reason);
        var (on, why) = await AvailableAsync(ct);
        if (!on) return new WriteResult(WriteStatus.Refused, why!);
        var person = (await _people.MailablePeopleAsync(departmentId, ct)).FirstOrDefault(p => p.Kind == personKind && p.PersonId == personId);
        if (person is null) return new WriteResult(WriteStatus.Refused, "that person is not an active advisor or person of this department with a mail address");
        return await IssueCoreAsync(person, OriginAdmin, SafeTarget(target, departmentId), by.ChangeName(), MaxIssuedPerHour, ct);
    }

    /// <summary>
    /// The person asks for a link (anonymous: from the link in a monthly / per-finding mail). SILENT by design: the answer
    /// never says whether the address belongs to the department, and an address that does gets at most
    /// <see cref="MaxRequestedPerHour"/> links an hour -- the link only ever goes to that address itself.
    /// </summary>
    public async Task RequestAsync(int departmentId, string? mail, string? target, CancellationToken ct)
    {
        var m = (mail ?? "").Trim().ToLowerInvariant();
        if (departmentId <= 0 || !MailPattern().IsMatch(m)) return;
        try
        {
            if (!(await AvailableAsync(ct)).On) return;
            var person = (await _people.MailablePeopleAsync(departmentId, ct))
                .Where(p => string.Equals(p.Mail?.Trim(), m, StringComparison.OrdinalIgnoreCase))
                .OrderBy(p => p.IsAdvisor ? 1 : 0).FirstOrDefault();
            if (person is null) { _log.LogInformation("a sign-in link was asked for department {Department} by an address it does not list", departmentId); return; }
            var r = await IssueCoreAsync(person, OriginRequest, SafeTarget(target, departmentId), "self-service: " + m, MaxRequestedPerHour, ct);
            if (r.Status != WriteStatus.Saved) _log.LogInformation("a requested sign-in link was not sent: {Why}", r.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogError(ex, "a requested sign-in link failed"); }
    }

    private async Task<WriteResult> IssueCoreAsync(DepartmentPerson person, string origin, string? target, string by, int maxPerHour, CancellationToken ct)
    {
        var w = await _web.ReadAsync(ct);
        var now = Now;
        var token = SignInSecrets.NewToken();
        var expires = now.AddMinutes(Math.Clamp(w.MagicLinkMinutes, 5, 1440));
        var (outcome, id) = await _store.IssueAsync(new NewSignIn(person.DepartmentId, person.Kind, person.PersonId, person.Mail!, SignInSecrets.TokenHash(token), origin,
            target ?? DefaultTarget(person.DepartmentId), now, expires, by, maxPerHour), ct);
        if (outcome == "Limited") return new WriteResult(WriteStatus.Refused, $"{person.DisplayName} was sent {maxPerHour} links in the last hour -- wait a while");
        if (outcome != "Saved" || id is null) return new WriteResult(WriteStatus.Stale, "the department is retired or gone -- no link was sent");
        var link = DeepLinks.Build(w.PublicBaseUrl, "/MagicLink", new Dictionary<string, string?> { ["t"] = token })!;
        await _mailer.SendAsync(SignInMail.Link(person, link, expires), by, ct);
        return new WriteResult(WriteStatus.Saved, $"a sign-in link was sent to {person.Mail} ({person.DisplayName}); it works once, until {expires:yyyy-MM-dd HH:mm} UTC");
    }

    // ------------------------------------------------------------------------------------------------- redeem

    /// The link, redeemed: the session row (Fresh), or why not. Disabled = (null, "disabled").
    public async Task<(SignInRow? Row, string? Why)> RedeemAsync(string? token, CancellationToken ct)
    {
        var w = await _web.ReadAsync(ct);
        if (!w.MagicLinksEnabled) return (null, "disabled");
        if (!SignInSecrets.IsToken(token)) return (null, "malformed");
        var now = Now;
        var (o, row) = await _store.RedeemAsync(SignInSecrets.TokenHash(token!), now, now.AddMinutes(Math.Clamp(w.MagicLinkMinutes, 5, 1440)), ct);
        return o == "Fresh" && row is not null ? (row, null) : (null, o.ToLowerInvariant());
    }

    /// The session cookie a redeemed link creates: its own authentication type (no Entra token can produce it) and the
    /// sign-in id. Name and mail are for display and the audit; the rights come from the row on every request.
    public static ClaimsPrincipal SessionPrincipal(SignInRow row, string? displayName)
    {
        var id = new ClaimsIdentity(DepartmentSessions.IdentityType, "name", "roles");
        id.AddClaim(new Claim("name", string.IsNullOrWhiteSpace(displayName) ? row.Mail : displayName));
        id.AddClaim(new Claim("preferred_username", row.Mail));
        id.AddClaim(new Claim("roles", Roles.MagicLink));
        id.AddClaim(new Claim(DepartmentSessions.SignInClaim, row.SignInId.ToString(CultureInfo.InvariantCulture)));
        return new ClaimsPrincipal(id);
    }

    // ------------------------------------------------------------------------------------------------- second check

    private async Task<(long Id, SessionState? State)> SessionOfAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        if (DepartmentSessions.SignInId(user) is not { } id) return (0, null);
        return (id, await _store.SessionAsync(id, ct));
    }

    /// Mails a one-time code to the session's own mailbox.
    public async Task<WriteResult> SendCodeAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        var (id, s) = await SessionOfAsync(user, ct);
        if (id == 0) return new WriteResult(WriteStatus.Refused, "you signed in with your organisation account -- that already counts as the strong sign-in; no code is needed");
        if (s is null || !s.ValidAt(Now)) return new WriteResult(WriteStatus.Refused, "this sign-in has ended -- ask for a new link");
        if (s.Row.OtpConfirmedAt is not null) return new WriteResult(WriteStatus.Stale, "this sign-in is already confirmed");
        if (!(await _mail.ReadAsync(ct)).MailEnabled) return new WriteResult(WriteStatus.Refused, "web app mails are off -- a code cannot be sent; sign in with your organisation account instead");
        var now = Now;
        var code = SignInSecrets.NewCode();
        var salt = SignInSecrets.NewSalt();
        var outcome = await _store.AddCodeAsync(id, salt, SignInSecrets.CodeHash(salt, id, code), now, now.AddMinutes(CodeMinutes), MaxCodesPerHour, s.Row.Mail, ct);
        if (outcome == "Limited") return new WriteResult(WriteStatus.Refused, $"{MaxCodesPerHour} codes were sent in the last hour -- wait a while, or sign in with your organisation account");
        if (outcome != "Saved") return new WriteResult(WriteStatus.Refused, "this sign-in has ended -- ask for a new link");
        await _mailer.SendAsync(SignInMail.Code(s.Row.Mail, s.PersonName, code, CodeMinutes), s.Row.Mail, ct);
        return new WriteResult(WriteStatus.Saved, $"a one-time code was sent to {s.Row.Mail}; it works for {CodeMinutes} minutes");
    }

    /// Checks the code; confirmed = this session may approve from now on.
    public async Task<WriteResult> ConfirmCodeAsync(ClaimsPrincipal user, string? code, CancellationToken ct)
    {
        var (id, s) = await SessionOfAsync(user, ct);
        if (id == 0) return new WriteResult(WriteStatus.Refused, "only a sign-in link session confirms with a code");
        if (s is null || !s.ValidAt(Now)) return new WriteResult(WriteStatus.Refused, "this sign-in has ended -- ask for a new link");
        var c = (code ?? "").Trim();
        if (!SignInSecrets.IsCode(c)) return new WriteResult(WriteStatus.Refused, "the code is six digits");
        var latest = await _store.LatestCodeAsync(id, Now, MaxCodeAttempts, ct);
        if (latest is null) return new WriteResult(WriteStatus.Refused, "no code is waiting (or it expired / was tried too often) -- send a new one");
        var match = SignInSecrets.CodeMatches(latest.Salt, latest.CodeHash, id, c);
        var (o, left) = await _store.UseCodeAsync(latest.CodeId, id, match, Now, MaxCodeAttempts, s.Row.Mail, ct);
        _cache.Remove(SessionCacheKey(id));
        return o switch
        {
            "Confirmed" => new WriteResult(WriteStatus.Saved, "confirmed -- you can approve for the rest of this sign-in"),
            "Wrong" => new WriteResult(WriteStatus.Refused, left > 0 ? $"that is not the code -- {left} tr{(left == 1 ? "y" : "ies")} left" : "that is not the code, and it was the last try -- send a new one"),
            _ => new WriteResult(WriteStatus.Refused, "that code can no longer be used -- send a new one"),
        };
    }

    // ------------------------------------------------------------------------------------------------- admin

    public async Task<WriteResult> RevokeAsync(ClaimsPrincipal by, int departmentId, long signInId, CancellationToken ct)
    {
        var gate = _access.Can(by, AccessAction.Administer);
        if (!gate.Allowed) return new WriteResult(WriteStatus.Refused, gate.Reason);
        var o = await _store.RevokeAsync(signInId, departmentId, Now, by.ChangeName(), ct);
        _cache.Remove(SessionCacheKey(signInId));
        return o == "Saved" ? new WriteResult(WriteStatus.Saved, "link revoked: it no longer opens, and a session it started ends on its next request")
                            : new WriteResult(WriteStatus.Stale, "that link is already revoked");
    }

    public Task<IReadOnlyList<SignInRow>> ListAsync(int departmentId, CancellationToken ct) => _store.ListAsync(departmentId, Now, ct);
}

/// <summary>
/// The role framework's view of the department people (#258) -- <see cref="IDepartmentGrants"/>: a sign-in link
/// session's grant from its row (checked on every request, cached for seconds), and an Entra user's grant from the
/// departments that list them. Advisor when every listing is as an advisor; otherwise Department.
/// </summary>
public sealed class DepartmentGrants : IDepartmentGrants
{
    public static readonly TimeSpan SessionTtl = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan PersonTtl = TimeSpan.FromSeconds(30);
    private readonly IDepartmentSignInStore _store;
    private readonly IAdvisorStore _people;
    private readonly IMemoryCache _cache;
    private readonly TimeProvider _clock;

    public DepartmentGrants(IDepartmentSignInStore store, IAdvisorStore people, IMemoryCache cache, TimeProvider? clock = null)
    { _store = store; _people = people; _cache = cache; _clock = clock ?? TimeProvider.System; }

    public async Task<DepartmentGrant?> SessionAsync(ClaimsPrincipal session, CancellationToken ct)
    {
        if (DepartmentSessions.SignInId(session) is not { } id) return null;
        var key = DepartmentSignInService.SessionCacheKey(id);
        if (!_cache.TryGetValue(key, out SessionState? s))
        {
            s = await _store.SessionAsync(id, ct);
            _cache.Set(key, s, SessionTtl);
        }
        if (s is null || !s.ValidAt(_clock.GetUtcNow().UtcDateTime)) return null;
        var role = s.Row.PersonKind == DepartmentPerson.AdvisorKind || s.PersonRole == "advisor" ? SiRole.Advisor : SiRole.DepartmentMember;
        return new DepartmentGrant(role, [s.Row.DepartmentId], $"sign-in link mailed to {s.Row.Mail}",
            s.Row.OtpConfirmedAt is null ? AuthMethods.MagicLink : AuthMethods.MagicLinkOtp);
    }

    public async Task<DepartmentGrant?> PersonAsync(ClaimsPrincipal user, IReadOnlyList<string> groups, CancellationToken ct)
    {
        var ids = new List<string>();
        if (AccessClaims.ObjectId(user) is { } oid) ids.Add(oid);
        ids.AddRange(groups);
        // the UPN Entra issued (a B2B guest's is their home address) -- never a mail claim the user can edit
        var upn = user.FindFirst("preferred_username")?.Value ?? user.FindFirst(ClaimTypes.Upn)?.Value;
        if (ids.Count == 0 && string.IsNullOrWhiteSpace(upn)) return null;
        var key = "si-dept-person|" + string.Join(",", ids.Select(i => i.ToLowerInvariant()).OrderBy(i => i, StringComparer.Ordinal)) + "|" + upn?.ToLowerInvariant();
        if (!_cache.TryGetValue(key, out IReadOnlyList<DepartmentPerson>? people) || people is null)
        {
            people = await _people.PeopleAsync(ids, upn, ct);
            _cache.Set(key, people, PersonTtl);
        }
        if (people.Count == 0) return null;
        var advisorOnly = people.All(p => p.IsAdvisor || p.Role == "advisor");
        return new DepartmentGrant(advisorOnly ? SiRole.Advisor : SiRole.DepartmentMember, people.Select(p => p.DepartmentId).Distinct().ToList(),
            advisorOnly ? "department advisor" : "person of a department");
    }
}

/// The two sign-in mails, in the Risk Analysis mail's look. PURE.
public static class SignInMail
{
    private const string Font = "font-family:Segoe UI,Arial,sans-serif;";
    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    public static QueuedMail Link(DepartmentPerson p, string link, DateTime expires)
    {
        var body = new StringBuilder();
        // #728: the summary first
        body.Append(SI.Management.Core.Mail.MailLayout.Summary(new[]
        {
            "<strong>Your sign-in link:</strong> works once, expires " + expires.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC",
            "<strong>Never forward it:</strong> it signs in as you",
        }));
        body.Append(Para($"Hello {E(p.DisplayName)},"));
        body.Append(Para("This is your personal sign-in link to SecurityInsight for the department you advise or belong to. It opens the department's page, works <strong>once</strong>, and expires at <strong>" +
                         expires.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC</strong>."));
        body.Append(Para("Signed in this way you can read the department's findings, comment and recommend. To approve, you confirm the sign-in with a one-time code we mail to this same address -- or sign in with your organisation account instead."));
        body.Append(Para("Did not expect this? Ignore it -- nothing happens unless the link is opened. Never forward it: it signs in as you."));
        return new QueuedMail(DepartmentSignInService.MailKind, null, null, [p.Mail!], "Your sign-in link", Wrap("Your sign-in link", body.ToString(), link, "Sign in"));
    }

    public static QueuedMail Code(string mail, string name, string code, int minutes)
    {
        var body = new StringBuilder();
        // #728: the summary first
        body.Append(SI.Management.Core.Mail.MailLayout.Summary(new[] { $"<strong>Your one-time code:</strong> works once, for {minutes} minutes" }));
        body.Append(Para($"Hello {E(name)},"));
        body.Append(Para("Your one-time code to confirm your SecurityInsight sign-in before an approval:"));
        body.Append($"<p style=\"margin:6px 0 14px 0;{Font}font-size:28px;font-weight:700;letter-spacing:6px;color:#1a3a5e;\">{E(code)}</p>");
        body.Append(Para($"It works once, for {minutes} minutes. If you did not ask for it, someone may have your sign-in link: tell the department's owner."));
        return new QueuedMail(DepartmentSignInService.CodeMailKind, null, null, [mail], "Your one-time code", Wrap("One-time code", body.ToString(), null, ""));
    }

    private static string Para(string html) => $"<p style=\"{SI.Management.Core.Mail.MailLayout.ParagraphStyle}\">{html}</p>";

    /// #728: no table -- the frame is a max-width div, the button a styled link after the body.
    private static string Wrap(string title, string body, string? link, string linkText) =>
        SI.Management.Core.Mail.MailLayout.Frame($"SecurityInsight &middot; {E(title)}", null, null,
            body + (link is null ? "" : SI.Management.Core.Mail.MailLayout.Button(link, linkText, anyWebLink: true)), "SecurityInsight Pro &middot; Departments");
}
