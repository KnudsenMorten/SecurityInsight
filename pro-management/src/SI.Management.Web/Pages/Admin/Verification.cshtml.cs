using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Verification;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Operations > Verification (docs\V3-DATA-MODEL.md 2.11): the settings and plans SecurityInsight's data depends on that
/// are NOT on in the Microsoft estate -- found by the verification job (caj-si-verification), read-only toward Defender,
/// Entra and Azure. Readers see the checks, the gaps and the review queue; an Admin ignores or accepts a gap (with why and
/// a reviewer, due for review after 180 days), reviews a decision (a new decision replaces it) or withdraws one. Every
/// decision is audited and stays in the gap's history.
/// </summary>
public sealed class VerificationModel : PageModel
{
    private readonly IVerificationStore _store;
    private readonly ILogger<VerificationModel> _log;
    public VerificationModel(IVerificationStore store, ILogger<VerificationModel> log) { _store = store; _log = log; }

    /// How far back resolved gaps are listed.
    public const int ResolvedDays = 30;
    /// The review queue shows decisions due within this many days.
    public const int ReviewWithinDays = 30;

    public VerificationCatalog Catalog { get; } = VerificationCatalog.Default;
    public VerificationView View { get; private set; } = VerificationView.Missing;
    public IReadOnlyList<VerificationFindingRow> Rows { get; private set; } = Array.Empty<VerificationFindingRow>();
    public IReadOnlyList<VerificationFindingRow> Queue { get; private set; } = Array.Empty<VerificationFindingRow>();
    public IReadOnlyList<VerificationHistoryRow> History { get; private set; } = Array.Empty<VerificationHistoryRow>();
    public DateTime NowUtc { get; } = DateTime.UtcNow;
    public string? Error { get; private set; }

    [BindProperty(SupportsGet = true)] public string? Check { get; set; }
    [BindProperty(SupportsGet = true)] public string? Status { get; set; }
    [BindProperty(SupportsGet = true, Name = "dec")] public string? DecisionFilter { get; set; }
    [BindProperty(SupportsGet = true)] public string? Severity { get; set; }
    [BindProperty(SupportsGet = true)] public string? Key { get; set; }

    [BindProperty] public string? FindingKey { get; set; }
    [BindProperty] public string? Decision { get; set; }
    [BindProperty] public string? Reason { get; set; }
    [BindProperty] public string? Owner { get; set; }

    private string? Joined(string key) =>
        HttpContext?.Request is { } r && MultiFilter.ValuesOf(r.Query, key) is { Count: > 0 } v ? string.Join(SI.Management.Core.ProData.ProDataFilters.ValueSeparator, v) : null;

    public async Task OnGetAsync(CancellationToken ct)
    {
        try
        {
            View = await _store.ReadAsync(ResolvedDays, ct);
            // check, decision and severity take several values (one parameter per value): '|'-joined for the filter
            (Check, DecisionFilter, Severity) = (Joined("check") ?? Check, Joined("dec") ?? DecisionFilter, Joined("severity") ?? Severity);
            Rows = VerificationFilter.Apply(View.Findings, Check, Status, DecisionFilter, Severity, NowUtc);
            Queue = VerificationFilter.ReviewQueue(View.Findings, NowUtc, ReviewWithinDays);
            if (!string.IsNullOrWhiteSpace(Key)) History = await _store.HistoryAsync(Key, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the verification results could not be read");
            Error = "The verification results could not be read from the Pro database: " + ex.Message;
        }
    }

    /// Ignore or accept a gap, or review its decision (Admin): a new decision, due for review after the catalog's days.
    [Audited("verification.decision.save")]
    public async Task<IActionResult> OnPostDecideAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var audit = AuditScope.Current;
        if (audit is not null) { audit.Target = "/Admin/Verification/" + (FindingKey ?? ""); audit.Reason = Reason; audit.AfterJson = System.Text.Json.JsonSerializer.Serialize(new { decision = Decision, owner = Owner, reviewDays = Catalog.ReviewDays }); }
        if (SqlVerificationStore.Validate(Decision, Reason) is { } bad)
        {
            audit?.Refused(bad);
            return Toast(false, bad);
        }
        VerificationDecideResult r;
        try { r = await _store.DecideAsync(FindingKey ?? "", Decision!, Reason, Owner, User.ChangeName(), Catalog.ReviewDays, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "a verification decision failed");
            r = new VerificationDecideResult(false, "Not saved: " + ex.Message);
        }
        if (!r.Saved) audit?.Refused(r.Message);
        return Toast(r.Saved, r.Message);
    }

    /// Withdraw the decision on a gap (Admin): it is open again.
    [Audited("verification.decision.revoke")]
    public async Task<IActionResult> OnPostRevokeAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var audit = AuditScope.Current;
        if (audit is not null) audit.Target = "/Admin/Verification/" + (FindingKey ?? "");
        VerificationDecideResult r;
        try { r = await _store.RevokeAsync(FindingKey ?? "", User.ChangeName(), ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "withdrawing a verification decision failed");
            r = new VerificationDecideResult(false, "Not withdrawn: " + ex.Message);
        }
        if (!r.Saved) audit?.Refused(r.Message);
        return Toast(r.Saved, r.Message);
    }

    private IActionResult Toast(bool ok, string message)
    {
        TempData["toast"] = message;
        TempData["toastKind"] = ok ? "ok" : "error";
        return RedirectToPage(new { check = Check, status = Status, dec = DecisionFilter, severity = Severity });
    }

    public VerificationCheck? CheckOf(string id) => Catalog.Find(id);
    public string TitleOf(string id) => Catalog.Find(id)?.Title ?? id;

    public static string StateLabel(string state) => state switch
    {
        "ok" => "No gaps",
        "gaps" => "Gaps found",
        "not-checked" => "Not checked",
        _ => state,
    };

    public static string DecisionLabel(string? decision) => decision switch
    {
        "ignored" => "Ignored",
        "accepted" => "Accepted",
        _ => "Open",
    };
}
