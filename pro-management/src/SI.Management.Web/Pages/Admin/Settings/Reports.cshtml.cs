using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Notify;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.Settings;

/// <summary>
/// Reports and alerts (framework MAIL-2 item 6, SI #485): ONE view of every report and alert SecurityInsight mails -- its
/// cadence, recipients, last sent, next run, whether a PDF is attached and whether it already follows each recipient's
/// notifications -- each with the one place its schedule is configured. Admin.
/// #1172 (owner 2026-11-10 at a customer: "it is a mesh" / "too complex"): WHO gets which mail is ONE list of people, edited
/// here -- a row per mail address, a tick per report and alert (<see cref="RecipientGrid"/>). A save writes every report's
/// OWN list exactly (through the settings writer: validation, the version read, the change log; the management summaries
/// through their store) and records who confirmed it, which closes the Get Started step "Who gets the reports". The storage
/// the jobs read does not change.
/// </summary>
public sealed class ReportsModel(NotificationService notify, AutoReader autoReader) : PageModel
{
    [BindProperty] public List<string> Person { get; set; } = new();
    [BindProperty] public List<string> Tick { get; set; } = new();
    [BindProperty] public string? Fingerprint { get; set; }
    [BindProperty] public string? Address { get; set; }
    [BindProperty] public List<string> AddTick { get; set; } = new();
    /// A person to point at (after they were added on Notifications).
    [BindProperty(SupportsGet = true, Name = "show")] public string? Show { get; set; }

    public IReadOnlyList<NotifyLine> Lines { get; private set; } = Array.Empty<NotifyLine>();
    public RecipientGrid Grid { get; private set; } = new(Array.Empty<NotifyEntry>(), Array.Empty<string>(), new Dictionary<string, IReadOnlyList<string>>());
    public string Version { get; private set; } = "";
    public Confirmation? Confirmed { get; private set; }
    public string? Error { get; private set; }
    /// The people in the list -- exactly the rows of the grid.
    public int Recipients => Grid.People.Count;
    public bool CanEdit => User.IsAdmin();

    /// The signed-in person's address, SUGGESTED (never set) while the list is empty.
    public string? Suggested => Grid.People.Count > 0 ? null
        : new[] { "email", "preferred_username", "upn", System.Security.Claims.ClaimTypes.Email, System.Security.Claims.ClaimTypes.Upn }
            .Select(t => User.FindFirst(t)?.Value?.Trim()).FirstOrDefault(NotificationPrefs.IsAddress);

    /// The words for a line nobody receives: plain, never a setting name.
    public string NobodyText(NotifyEntry e) =>
        e.Id == "guard-alert"
            ? (Confirmed is null ? "no one at your organisation receives this yet -- until someone does, the SuperAdmins get it" : "no one is ticked -- the SuperAdmins get it")
            : Confirmed is null ? "no one at your organisation receives this yet" : "no one (nobody is ticked)";

    public static string Anchor(string address) => NotificationsModel.Anchor(address);

    private async Task<NotificationService.State> LoadAsync(CancellationToken ct)
    {
        var s = await notify.ReadAsync(ct);
        Error = s.Error;
        Lines = NotificationService.Lines(s, notify.Now);
        Grid = RecipientGrid.Build(s, notify.Now);
        Version = RecipientGrid.Fingerprint(s);
        Confirmed = Confirmation.Of(s.Rows);
        return s;
    }

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    private IActionResult Back(string message, bool ok, string? anchor = null)
    {
        TempData["toast"] = message; TempData["toastKind"] = ok ? "ok" : "error";
        return Redirect("/Admin/Settings/Reports" + "#" + (anchor ?? "people"));
    }

    private IActionResult Refused(string message)
    {
        AuditScope.Current?.Refused(message);
        return Back("Not saved: " + message, false);
    }

    private async Task<IActionResult> SaveAsync(NotificationService.State s, RecipientGrid before, RecipientGrid after, NotificationPrefs? prefs, string what, string? anchor, CancellationToken ct)
    {
        if (AuditScope.Current is { } a)
        {
            a.Target = "/Admin/Settings/Reports#people";
            a.BeforeJson = JsonSerializer.Serialize(before.Columns.ToDictionary(c => c.Id, c => before.Receivers.TryGetValue(c.Id, out var l) ? l : Array.Empty<string>()));
            a.AfterJson = JsonSerializer.Serialize(after.Columns.ToDictionary(c => c.Id, c => after.Receivers.TryGetValue(c.Id, out var l) ? l : Array.Empty<string>()));
        }
        var r = await notify.SaveGridAsync(s, after, prefs, User.ChangeName(), what, ct);
        if (!r.Ok) return Refused(r.Stale ? "someone changed the list since you opened the page -- reload it and try again" : r.Message);
        return Back(what + ". Each report and alert now goes exactly to the people ticked for it.", true, anchor);
    }

    private async Task<(NotificationService.State? State, IActionResult? Refusal)> ReadForSaveAsync(CancellationToken ct)
    {
        var s = await LoadAsync(ct);
        if (s.Error is not null) return (null, Refused(s.Error));
        if (!string.Equals(Fingerprint, Version, StringComparison.Ordinal)) return (null, Refused("someone changed the list since you opened the page -- reload it and try again"));
        return (s, null);
    }

    /// The whole list as ticked.
    [Audited("notify.recipient.save")]
    public async Task<IActionResult> OnPostSaveAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var (s, no) = await ReadForSaveAsync(ct);
        if (no is not null) return no;
        return await SaveAsync(s!, Grid, Grid.FromTicks(Person, Tick), null, "The list of people is saved and confirmed", null, ct);
    }

    /// A new person with the reports and alerts ticked for them; added as Reader when they are not a user yet, so the links
    /// in their mails open (said in the toast and on the audit trail).
    [Audited("notify.recipient.save")]
    public async Task<IActionResult> OnPostAddAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var address = (Address ?? "").Trim();
        if (!NotificationPrefs.IsAddress(address)) return Refused("that is not a mail address");
        var (s, no) = await ReadForSaveAsync(ct);
        if (no is not null) return no;
        var prefs = s!.Prefs.Recipients.Any(r => r.Address.Equals(address, StringComparison.OrdinalIgnoreCase)) ? s.Prefs
            : s.Prefs.With(new RecipientPrefs(address, MailAudience.Posture, Array.Empty<string>()));
        var acc = await autoReader.EnsureAsync(address, User.ChangeName(), ct);
        var after = Grid.With(address, Grid.Of(address).Select(e => e.Id).Concat(AddTick));
        var ticked = after.Of(address).Count;
        return await SaveAsync(s!, Grid, after, prefs,
            $"{address} is added to the list of people ({ticked} of {Grid.Columns.Count} reports and alerts){(acc.State == "added" ? " and as Reader, so the links in their mails open" : "")}", Anchor(address), ct);
    }

    /// A person off every list (their notification choices forgotten). Their role in the web app is NOT removed (said).
    [Audited("notify.recipient.remove")]
    public async Task<IActionResult> OnPostRemoveAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var address = (Address ?? "").Trim();
        if (!NotificationPrefs.IsAddress(address)) return Refused("that is not a mail address");
        var (s, no) = await ReadForSaveAsync(ct);
        if (no is not null) return no;
        if (!Grid.People.Contains(address, StringComparer.OrdinalIgnoreCase)) return Refused("that person is not on the list");
        return await SaveAsync(s!, Grid, Grid.Without(address), s!.Prefs.Without(address),
            $"{address} is removed from every report and alert (their role in the web app is unchanged -- remove it on Access if they should no longer sign in)", null, ct);
    }
}
