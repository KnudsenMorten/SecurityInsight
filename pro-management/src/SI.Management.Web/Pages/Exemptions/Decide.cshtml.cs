using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Exemptions;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Exemptions;

/// <summary>
/// One request: what is asked, by whom, why, until when -- and, for an approver of its domain (or an Admin), approve or
/// reject with a comment. The approval IS the review: approving writes the exemptions at once (no Review &amp; commit).
/// </summary>
public sealed class DecideModel : PageModel
{
    private readonly ExemptionWorkflow _flow;
    private readonly ILogger<DecideModel> _log;
    public DecideModel(ExemptionWorkflow flow, ILogger<DecideModel> log) { _flow = flow; _log = log; }

    [BindProperty(SupportsGet = true)] public long Id { get; set; }
    [BindProperty] public string? Comment { get; set; }

    public RequestRow? Req { get; private set; }
    public IReadOnlyList<RequestItem> Items { get; private set; } = Array.Empty<RequestItem>();
    public bool MayDecide { get; private set; }
    /// #283: whether this user is among the request's deciders at all (whatever its state).
    public bool IsDecider { get; private set; }
    /// The most specific owners it is asked of, and who else may decide it.
    public IReadOnlyList<string> Asked { get; private set; } = Array.Empty<string>();
    public IReadOnlyList<string> AlsoDecide { get; private set; } = Array.Empty<string>();
    /// #391: who it is asked of, and the department whose business approvers they are (null = the security owners).
    public AskedOf? AskedOf { get; private set; }
    public string? Error { get; private set; }
    private Roster _roster = new(Array.Empty<DomainRoleRow>());

    private async Task LoadAsync(CancellationToken ct)
    {
        try
        {
            if (!await _flow.ReadyAsync(ct)) { Error = "This database does not have the exemption request tables yet."; return; }
            Req = await _flow.RequestAsync(Id, ct);
            if (Req is null) { Error = $"Request #{Id} does not exist."; return; }
            Items = await _flow.ItemsAsync(Id, ct);
            _roster = await _flow.RosterAsync(ct);
            // #391: a request made on a department's page is asked of that department's business approvers
            AskedOf = await _flow.AskedOfAsync(_roster, Req, ct);
            Asked = AskedOf.People;
            AlsoDecide = _roster.Deciders(Req.Domain, Req.Category).Except(Asked).ToList();
            IsDecider = await _flow.MayDecideAsync(User, _roster, Req, ct);
            MayDecide = Req.State == ExemptionStates.Requested && IsDecider;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "reading request {Id} failed", Id);
            Error = "The request could not be read: " + ex.Message;
        }
    }

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    [SI.Management.Web.Audit.Audited("exemption.request.approve")]
    public Task<IActionResult> OnPostApproveAsync(CancellationToken ct) => DecideAsync(true, ct);
    [SI.Management.Web.Audit.Audited("exemption.request.reject")]
    public Task<IActionResult> OnPostRejectAsync(CancellationToken ct) => DecideAsync(false, ct);

    private async Task<IActionResult> DecideAsync(bool approve, CancellationToken ct)
    {
        // #283: a decision by someone outside the request's deciders (its category's / domain's owners, its domain's
        // approvers, or an Admin) is refused with 403 -- the audit row records the refusal and who it was asked of
        await LoadAsync(ct);
        if (Req is not null && Error is null && !IsDecider)
        {
            var why = ExemptionWorkflow.NotYoursToDecide(_roster, Req, AskedOf);
            SI.Management.Web.Audit.AuditScope.Current?.Refused(why);
            Error = "Not decided: " + why + ".";
            Response.StatusCode = StatusCodes.Status403Forbidden;
            return Page();
        }
        var r = approve ? await _flow.ApproveAsync(User, Id, Comment, ct) : await _flow.RejectAsync(User, Id, Comment, ct);
        TempData["toast"] = r.Message;
        TempData["toastKind"] = r.Status == WriteStatus.Saved ? "ok" : r.Status == WriteStatus.Stale ? "warn" : "error";
        if (r.Status == WriteStatus.Refused) { await LoadAsync(ct); Error ??= r.Message; return Page(); }
        return Redirect("/Exemptions/Decide?id=" + Id);
    }
}
