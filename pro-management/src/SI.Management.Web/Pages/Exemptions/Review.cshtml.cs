using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Auth;
using SI.Management.Web.Exemptions;
using SI.Management.Web.Settings;
using SI.Management.Web.Navigation;

namespace SI.Management.Web.Pages.Exemptions;

/// <summary>
/// THE review page the monthly mail links to: the exemptions of the domains I own (an Admin: every domain) that are
/// not ended -- expiring soon first, then expired, then the rest -- each to EXTEND (a new period from today), KEEP (as
/// it is: reviewed) or END; one at a time or many at once. Every action is written with my name and a ChangeLog row.
/// </summary>
public sealed class ReviewModel : PageModel
{
    private readonly ExemptionWorkflow _flow;
    private readonly ILogger<ReviewModel> _log;
    public ReviewModel(ExemptionWorkflow flow, ILogger<ReviewModel> log) { _flow = flow; _log = log; }

    [BindProperty(SupportsGet = true)] public string? Domain { get; set; }
    /// #283: narrow to one category (the monthly review of a category owner links here with it).
    [BindProperty(SupportsGet = true)] public string? Category { get; set; }
    [BindProperty] public List<long> Sel { get; set; } = new();
    [BindProperty] public string? ReviewAction { get; set; }
    [BindProperty] public string? Period { get; set; }
    [BindProperty] public DateTime? CustomDate { get; set; }
    [BindProperty] public string? Reason { get; set; }

    public DateTime Now { get; private set; }
    public ExemptionSettings.Values Settings { get; private set; } = ExemptionSettings.Values.Defaults;
    public IReadOnlyList<string> MyDomains { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<ExemptionInfo> Rows { get; private set; } = Array.Empty<ExemptionInfo>();
    public string? Error { get; private set; }
    public string? Notice { get; private set; }

    private async Task LoadAsync(CancellationToken ct)
    {
        Now = _flow.Now;
        try
        {
            Settings = await _flow.SettingsAsync(ct);
            Period ??= ExemptionPeriods.DefaultChoice(Settings.DefaultMonths);
            if (!await _flow.ReadyAsync(ct)) { Error = "This database does not have the exemption review columns yet: run the Pro settings setup (it only adds)."; return; }
            var roster = await _flow.RosterAsync(ct);
            // #283: both levels -- the domains and the categories I own
            MyDomains = roster.OwnedBy(User.ChangeName()).Select(n => DomainRoles.Label(n.Domain, n.Category)).ToList();
            var all = await _flow.ExemptionsAsync(ct);
            var mine = all.Where(e => e.State(Now) != ExemptionStates.Ended && ExemptionWorkflow.CanReview(User, roster, e.DomainKey, e.CategoryKey));
            if (!string.IsNullOrWhiteSpace(Domain)) mine = mine.Where(e => string.Equals(e.DomainKey, Domain, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(Category)) mine = mine.Where(e => string.Equals(e.CategoryKey, Category.Trim(), StringComparison.OrdinalIgnoreCase));
            Rows = mine.OrderBy(e => e.State(Now) == ExemptionStates.Expired ? 1 : e.IsExpiringWithin(Now, Math.Max(Settings.ExpiryWarningDays, 1)) ? 0 : 2)
                       .ThenBy(e => e.ExpiresAt ?? DateTime.MaxValue).ToList();
            if (!User.IsAdmin() && MyDomains.Count == 0) Notice = "You are not an owner of any security domain or category, so there is nothing for you to review here. An Admin sets owners on " + NavModel.PathOf("/Admin/DomainRoles") + ".";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading the exemptions to review failed");
            Error = "The exemptions could not be read: " + ex.Message;
        }
    }

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    [SI.Management.Web.Audit.Audited("exemption.review.record")]
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var r = await _flow.ReviewAsync(User, ReviewAction ?? "", Sel, Period, CustomDate, Reason, ct);
        TempData["toast"] = r.Message;
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? (r.Message.Contains("refused") ? "warn" : "ok") : "error";
        if (r.Status == WriteStatus.Refused) { await LoadAsync(ct); Error = r.Message; return Page(); }
        var q = new List<string>();
        if (!string.IsNullOrWhiteSpace(Domain)) q.Add("domain=" + Uri.EscapeDataString(Domain));
        if (!string.IsNullOrWhiteSpace(Category)) q.Add("category=" + Uri.EscapeDataString(Category));
        return Redirect("/Exemptions/Review" + (q.Count == 0 ? "" : "?" + string.Join("&", q)));
    }
}
