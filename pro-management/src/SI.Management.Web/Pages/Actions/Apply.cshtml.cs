using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Actions;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.Departments;

namespace SI.Management.Web.Pages.Actions;

/// <summary>
/// THE ONE ENDPOINT of the shared action bar (#272): POST /Actions/Apply with the action key, the selection (keys) or
/// "all matching" plus the filter, and the action's form (a.* fields). In order: the action from the registry; the user
/// may use it at all; the findings read back on the server (<see cref="FindingSelectionResolver"/> -- the department
/// visibility and the #264 bulk guard -- a request over the guard is still refused AS A WHOLE, because that is a guard,
/// not a scope); EVERY finding checked by the action (the role framework through the owning service). Operator decision
/// 2026-10-04: a finding outside what the user may change, or outside what they see, is REFUSED BY NAME and the action
/// runs for the rest (one transaction where the store allows) -- "N done, M refused", each refused finding with its
/// reason, nothing written for a refused one. Only when EVERY finding is refused is nothing done (403). EXACTLY ONE audit
/// event per request (AUDIT-1): the action's own audit name, the done and refused counts, the refused ids and the
/// per-finding outcomes in its detail. A JSON caller (the bar's script) gets the results
/// as JSON; a form post gets this page; an export gets its file. /Actions/Prepare (no script) shows the action's form
/// for a selection -- it writes nothing.
/// </summary>
public sealed class ApplyModel : PageModel
{
    public const string DefaultAuditAction = "finding.action.apply";
    /// The most per-finding outcomes the audit row's detail lists (the counts are always complete).
    public const int AuditedResults = 500;

    private readonly FindingActionRegistry _registry;
    private readonly FindingSelectionResolver _resolver;
    private readonly IDepartmentScopeResolver _scope;
    private readonly ILogger<ApplyModel> _log;

    public ApplyModel(FindingActionRegistry registry, FindingSelectionResolver resolver, IDepartmentScopeResolver scope, ILogger<ApplyModel> log)
    { _registry = registry; _resolver = resolver; _scope = scope; _log = log; }

    public IFindingAction? Action { get; private set; }
    public FindingSelection? Selection { get; private set; }
    public ResolvedSelection? Resolved { get; private set; }
    public IReadOnlyList<FindingActionResult> Results { get; private set; } = Array.Empty<FindingActionResult>();
    public string? Message { get; private set; }
    public string? Error { get; private set; }

    public void OnGet() => Error = "Select findings on a grid (Findings, a collection view, a department page) and pick an action in the bar under it.";

    private bool WantsJson => Request.Headers.Accept.ToString().Contains("application/json", StringComparison.OrdinalIgnoreCase);

    private IFindingAction? Pick()
    {
        var all = Request.Form["all"] == "1";
        return _registry.Find(all && Request.Form["allAction"].ToString() is { Length: > 0 } a ? a : Request.Form["action"].ToString());
    }

    [Audited(DefaultAuditAction)]
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var audit = AuditScope.Current;
        var action = Pick();
        if (action is null) return Fail(null, "Choose an action -- nothing was done.", 200);
        if (audit is not null) audit.Action = action.AuditAction;
        Selection = FindingSelection.From(Request.Form);
        Action = action;
        // #391: the department page the selection was made on travels with the selection, never as a form field
        var form = ActionForm.From(Request.Form).InDepartment(Selection.DepartmentContext);

        // ONE WEB APP, BOTH VERSIONS (owner 2026-10-18): a paid action without a Pro licence is refused here, server side
        if (!await _registry.LicensedAsync(action, ct))
            return Refuse(action, form, AccessDecision.No(SI.Management.Web.Licensing.ProFeatures.RefusalText(SI.Management.Web.Licensing.ProFeatures.ForAction(action.Key)!)), Array.Empty<FindingActionResult>());
        if (!await action.OfferedAsync(User, ct))
            return Refuse(action, form, AccessDecision.No($"your role cannot use \"{action.Label}\""), Array.Empty<FindingActionResult>());

        Resolved = await _resolver.ResolveAsync(User, Selection, action, ct);
        if (Resolved.Error is not null) return Fail(action, Resolved.Error, 200, form);

        // every finding: inside what the user SEES (the department scope) and what the action allows them to change
        var access = await _scope.ResolveAsync(User, ct);
        var refused = new List<FindingActionResult>();
        foreach (var t in Resolved.Targets)
        {
            if (!access.Unrestricted && (t.DepartmentId is not { } dep || !access.Sees(dep))) { refused.Add(FindingActionResult.No(t, "this finding is not one of your departments'")); continue; }
            var d = await action.CanAsync(User, t, ct);
            if (!d.Allowed) refused.Add(FindingActionResult.No(t, d.Reason));
        }
        // every finding refused: nothing is done (403), each one named with its reason
        if (refused.Count > 0 && refused.Count == Resolved.Targets.Count)
            return Refuse(action, form, AccessDecision.No(Resolved.Targets.Count == 1 ? refused[0].Why!
                : $"none of the {Fmt.Int(Resolved.Targets.Count)} findings is one you may change, so nothing was done. First: {refused[0].Why}"),
                Resolved.Missing.Concat(refused).ToList());

        // some refused: the action runs for the allowed ones only -- nothing is written for a refused finding
        var refusedIds = refused.Select(r => r.FindingId).ToHashSet(StringComparer.Ordinal);
        var allowed = Resolved.Targets.Where(t => !refusedIds.Contains(t.Finding.FindingId)).ToList();
        ActionOutcome outcome;
        try { outcome = await action.ExecuteAsync(User, allowed, form, ct); }
        catch (ArgumentException ex) { return Fail(action, "Nothing was done: " + ex.Message, 200, form); }
        Results = Resolved.Missing.Concat(refused).Concat(outcome.Results).ToList();
        var done = Results.Count(r => r.Done);
        var no = Results.Count - done;
        Message = outcome.Message;
        Record(action, form, done > 0 ? AuditOutcomes.Ok : AuditOutcomes.Refused, no == 0 ? outcome.Message : Summary(done, no) + " " + outcome.Message);
        if (outcome.File is not null && done > 0)
        {
            if (audit is not null) audit.Rows = done;
            return outcome.File;
        }
        if (WantsJson) return Json(done > 0 || Results.Count == 0, 200);
        return Page();
    }

    /// "N done, M refused." in the viewer's number format.
    public static string Summary(int done, int refused) => $"{Fmt.Int(done)} done, {Fmt.Int(refused)} refused.";

    private IActionResult Refuse(IFindingAction action, ActionForm form, AccessDecision why, IReadOnlyList<FindingActionResult> refused)
    {
        Results = refused;
        Error = "Not allowed: " + why.Reason + " Nothing was written.";
        Record(action, form, AuditOutcomes.Refused, why.Reason);
        if (WantsJson) return Json(false, StatusCodes.Status403Forbidden);
        Response.StatusCode = StatusCodes.Status403Forbidden;
        return Page();
    }

    private IActionResult Fail(IFindingAction? action, string why, int status, ActionForm? form = null)
    {
        Error = why;
        if (action is not null) Record(action, form ?? ActionForm.Of(), AuditOutcomes.Refused, why);
        else AuditScope.Current?.Refused(why);
        if (WantsJson) return Json(false, status);
        return Page();
    }

    private JsonResult Json(bool ok, int status) => new(new
    {
        ok,
        action = Action?.Key,
        message = Error ?? Message,
        summary = Summary(Results.Count(r => r.Done), Results.Count(r => !r.Done)),
        done = Results.Count(r => r.Done),
        refused = Results.Count(r => !r.Done),
        results = Results.Select(r => new { findingId = r.FindingId, asset = r.AssetName, title = r.Title, done = r.Done, why = r.Why }),
    }) { StatusCode = status };

    /// The request's ONE audit row: the action, the selection, the form (secrets hidden) and the outcome per finding.
    private void Record(IFindingAction action, ActionForm form, string outcome, string? text)
    {
        if (AuditScope.Current is not { } audit) return;
        audit.Action = action.AuditAction;
        audit.Target = "/Actions/Apply|action=" + action.Key + ", " + (Selection?.All == true ? "all matching" : "selected=" + (Selection?.Ids.Count ?? 0));
        var fields = form.Values.Where(kv => !AuditRedaction.IsSecretField(kv.Key))
            .ToDictionary(kv => kv.Key, kv => AuditRedaction.Text(kv.Value.Length > 400 ? kv.Value[..400] + "..." : kv.Value), StringComparer.Ordinal);
        audit.AfterJson = JsonSerializer.Serialize(new SortedDictionary<string, object?>(StringComparer.Ordinal)
        {
            ["action"] = action.Key,
            ["source"] = Selection?.Source,
            ["collection"] = Selection?.CollectionId,
            ["all"] = Selection?.All ?? false,
            ["filter"] = Selection is { All: true } s ? s.Origin.ToDictionary(kv => kv.Key, kv => string.Join("|", kv.Value)) : null,
            ["matching"] = Resolved?.Matching,
            ["form"] = new SortedDictionary<string, string?>(fields, StringComparer.Ordinal),
            ["done"] = Results.Count(r => r.Done),
            ["refused"] = Results.Count(r => !r.Done),
            ["refusedIds"] = Results.Where(r => !r.Done).Select(r => r.FindingId).Take(AuditedResults).ToList(),
            ["results"] = Results.Take(AuditedResults).Select(r => new { id = r.FindingId, asset = r.AssetName, outcome = r.Done ? AuditOutcomes.Ok : AuditOutcomes.Refused, why = r.Why }).ToList(),
        });
        audit.Set(outcome, text);
    }
}
