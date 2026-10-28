using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Notify;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.Settings;

/// <summary>
/// The Notifications page (framework MAIL-2 items 2 and 5, SI #485): every mail recipient on one page -- their audience
/// (where the blue button in a mail leads), every report and alert switched on or off for them, the lowest alert severity
/// they get, and whether they can open the links (a user of the web app). Adding a recipient who is not a user yet adds
/// them as Reader (said in the toast and on the audit trail); removing one only forgets their choices -- a role is never
/// taken away here. Admin; every save is the one setting SIWeb_MailNotifications (journaled, backed up, exported).
/// </summary>
public sealed class NotificationsModel(NotificationService notify, AutoReader autoReader, ILogger<NotificationsModel> log, IAccessStore? people = null) : PageModel
{
    public const int MaxChecked = 100;

    [BindProperty] public string? Address { get; set; }
    [BindProperty] public string? Audience { get; set; }
    [BindProperty] public List<string> On { get; set; } = new();
    [BindProperty] public string? Floor { get; set; }
    [BindProperty] public long? Version { get; set; }

    public NotificationService.State? State { get; private set; }
    public IReadOnlyList<NotifyLine> Lines { get; private set; } = Array.Empty<NotifyLine>();
    public IReadOnlyList<string> Recipients { get; private set; } = Array.Empty<string>();
    public Dictionary<string, RecipientAccess> Access { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// #765: a recipient who is a person on Admin > Access with "Send SecurityInsight mail to": where their mail really goes.
    public Dictionary<string, string> ForwardOf { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string? Error { get; private set; }
    public bool CanEdit => User.IsAdmin();

    private async Task LoadAsync(bool access, CancellationToken ct)
    {
        State = await notify.ReadAsync(ct);
        Error = State.Error;
        Lines = NotificationService.Lines(State, notify.Now);
        Recipients = NotificationService.AllRecipients(State, notify.Now);
        if (!access) return;
        try
        {
            if (people is not null)
            {
                var list = await people.ListAsync(ct);
                foreach (var r in Recipients) if (MailForward.TargetOf(r, list) is { } f) ForwardOf[r] = f;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { log.LogInformation(ex, "notifications: the mail forwards of the people with access"); }
        foreach (var r in Recipients.Take(MaxChecked))
        {
            try { Access[r] = await autoReader.CheckAsync(r, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { log.LogInformation(ex, "notifications: access of a recipient"); }
        }
    }

    /// The lists a recipient is on (the entry titles), for the row's "receives" line.
    public IEnumerable<NotifyLine> ListsOf(string address) => Lines.Where(l => l.Recipients.Contains(address, StringComparer.OrdinalIgnoreCase));

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(true, ct);

    private IActionResult Back(string message, bool ok, string? anchor = null)
    {
        TempData["toast"] = message; TempData["toastKind"] = ok ? "ok" : "error";
        return Redirect("/Admin/Settings/Notifications" + (anchor is null ? "" : "#" + anchor));
    }

    private IActionResult Refused(string message, string? anchor = null)
    {
        AuditScope.Current?.Refused(message);
        return Back("Not saved: " + message, false, anchor);
    }

    public static string Anchor(string address) => "r-" + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(address.Trim().ToLowerInvariant())))[..10].ToLowerInvariant();

    private async Task<IActionResult> SaveAsync(NotificationPrefs prefs, string what, string anchor, CancellationToken ct)
    {
        var w = await notify.SaveAsync(prefs, Version, User.ChangeName(), what, ct);
        return w.Status switch
        {
            WriteStatus.Saved => Back(what + ".", true, anchor),
            WriteStatus.Stale => Refused("someone changed the notifications since you opened the page -- reload it and try again", anchor),
            _ => Refused(w.Message, anchor),
        };
    }

    /// One recipient's choices: audience, the reports and alerts left ticked (the rest switched off), the alert floor.
    [Audited("notify.recipient.save")]
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var address = (Address ?? "").Trim();
        if (AuditScope.Current is { } a) a.Target = "/Admin/Settings/Notifications/" + address;
        if (!NotificationPrefs.IsAddress(address)) return Refused("that is not a mail address");
        await LoadAsync(false, ct);
        var ids = NotifyCatalog.All(State!.Summaries).Select(e => e.Id).ToList();
        var off = ids.Where(id => !On.Contains(id, StringComparer.OrdinalIgnoreCase)).ToList();
        var floor = NotificationPrefs.SeverityFloors.FirstOrDefault(f => f.Equals(Floor ?? "", StringComparison.OrdinalIgnoreCase));
        var p = new RecipientPrefs(address, MailAudience.Normalize(Audience), off, floor);
        if (AuditScope.Current is { } a2) { a2.BeforeJson = JsonSerializer.Serialize(State.Prefs.For(address)); a2.AfterJson = JsonSerializer.Serialize(p); }
        return await SaveAsync(State.Prefs.With(p), $"Notifications of {address} saved: {MailAudience.Label(p.Audience)}, {ids.Count - off.Count} of {ids.Count} reports and alerts on", Anchor(address), ct);
    }

    /// A new recipient (their choices start with everything on) -- added as Reader when they are not a user yet.
    [Audited("notify.recipient.save")]
    public async Task<IActionResult> OnPostAddAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var address = (Address ?? "").Trim();
        if (AuditScope.Current is { } a) a.Target = "/Admin/Settings/Notifications/" + address;
        if (!NotificationPrefs.IsAddress(address)) return Refused("that is not a mail address");
        await LoadAsync(false, ct);
        var p = State!.Prefs.Recipients.FirstOrDefault(r => r.Address.Equals(address, StringComparison.OrdinalIgnoreCase)) ?? new RecipientPrefs(address, MailAudience.Normalize(Audience), Array.Empty<string>());
        var acc = await autoReader.EnsureAsync(address, User.ChangeName(), ct);
        if (AuditScope.Current is { } a2) a2.AfterJson = JsonSerializer.Serialize(new { recipient = p, access = acc.State, accessText = acc.Words });
        var w = await notify.SaveAsync(State.Prefs.With(p with { Audience = MailAudience.Normalize(Audience) }), Version, User.ChangeName(), "recipient added on the Notifications page", ct);
        if (w.Status != WriteStatus.Saved) return Refused(w.Status == WriteStatus.Stale ? "someone changed the notifications since you opened the page -- reload it" : w.Message);
        var accessWords = acc.State == "added" ? " -- added as Reader, so the links in their mails open" : " -- " + acc.Words;
        return Back($"{address} added ({MailAudience.Label(Audience)}){accessWords}. Put the address on the reports it should get (Reports and alerts).", acc.State != "refused", Anchor(address));
    }

    /// Forgets a recipient's choices. Their address stays on the reports' lists and their role is NOT removed (said).
    [Audited("notify.recipient.remove")]
    public async Task<IActionResult> OnPostRemoveAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var address = (Address ?? "").Trim();
        if (AuditScope.Current is { } a) a.Target = "/Admin/Settings/Notifications/" + address;
        await LoadAsync(false, ct);
        if (!State!.Prefs.Recipients.Any(r => r.Address.Equals(address, StringComparison.OrdinalIgnoreCase))) return Refused("that recipient has no saved choices");
        return await SaveAsync(State.Prefs.Without(address), $"The choices of {address} are removed (they get every report they are a recipient of again). Their role in the web app is unchanged -- remove it on Access if they should no longer sign in", "recipients", ct);
    }

    /// Every recipient who is not a user yet, added as Reader at once.
    [Audited("notify.recipient.save")]
    public async Task<IActionResult> OnPostReadersAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        await LoadAsync(false, ct);
        var added = new List<string>();
        var notChecked = 0;
        foreach (var r in Recipients.Take(MaxChecked))
        {
            var acc = await autoReader.EnsureAsync(r, User.ChangeName(), ct);
            if (acc.State == "added") added.Add(r);
            else if (acc.State == "unknown") notChecked++;
        }
        if (AuditScope.Current is { } a) { a.Target = "/Admin/Settings/Notifications/readers"; a.AfterJson = JsonSerializer.Serialize(new { added, notChecked }); }
        if (notChecked > 0 && added.Count == 0) return Back("Nobody could be checked: the directory lookup is off or could not be read (Access:GraphLookup).", false, "recipients");
        return Back(added.Count == 0 ? "Every recipient who can sign in is a user already." : "Added as Reader: " + string.Join(", ", added) + ".", true, "recipients");
    }
}
