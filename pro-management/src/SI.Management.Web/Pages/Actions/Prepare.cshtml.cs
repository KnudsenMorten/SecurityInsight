using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Actions;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;

namespace SI.Management.Web.Pages.Actions;

/// <summary>
/// The shared action bar WITHOUT script (#272): a bar button posts the grid's selection (or "all matching" and the filter)
/// here, and this page shows the findings read back on the server and the action's form, which posts to /Actions/Apply.
/// It writes nothing, so it takes no antiforgery token: the collection grids' selection form is a GET form, and a token
/// in it would end up in the URL of "show only these". The write (Apply) checks its token as every write does.
/// </summary>
[IgnoreAntiforgeryToken]
public sealed class PrepareModel : PageModel
{
    private readonly FindingActionRegistry _registry;
    private readonly FindingSelectionResolver _resolver;

    private readonly ILogger<PrepareModel>? _log;

    public PrepareModel(FindingActionRegistry registry, FindingSelectionResolver resolver, ILogger<PrepareModel>? log = null) { _registry = registry; _resolver = resolver; _log = log; }

    public IFindingAction? Action { get; private set; }
    public FindingSelection? Selection { get; private set; }
    public ResolvedSelection? Resolved { get; private set; }
    public FindingActionBar? Bar { get; private set; }
    public string? Error { get; private set; }
    /// The hidden fields that carry the selection to /Actions/Apply.
    public List<(string Key, string Value)> Carry { get; } = new();

    public void OnGet() => Error = "Select findings on a grid (Findings, a collection view, a department page) and pick an action in the bar under it.";

    [NotAudited("fills an action's form from a selection; nothing is written until it is applied")]
    public async Task<IActionResult> OnPostAsync(CancellationToken ct)
    {
        var all = Request.Form["all"] == "1";
        var action = _registry.Find(all && Request.Form["allAction"].ToString() is { Length: > 0 } a ? a : Request.Form["action"].ToString());
        if (action is null) { Error = "Choose an action."; return Page(); }
        // the licence first (a paid action without a Pro licence: refused, server side), then the role
        if (!await _registry.LicensedAsync(action, ct)) return SI.Management.Web.Licensing.ProFeaturePageFilter.Refuse(Request, SI.Management.Web.Licensing.ProFeatures.ForAction(action.Key)!);
        if (!await action.OfferedAsync(User, ct)) return AccessResults.Refused(Request, AccessDecision.No($"\"{action.Label}\" is not open to your role"));
        Action = action;
        Selection = FindingSelection.From(Request.Form);
        Carry.AddRange(Carried(Selection));
        Bar = BarOf(Selection);
        Resolved = await _resolver.ResolveAsync(User, Selection, action, ct);
        Error = Resolved.Error;
        return Page();
    }

    /// <summary>
    /// #286: what a selection stands for, BEFORE anything is done -- the bar's dialog asks this when it opens on an
    /// aggregated grid and shows "2 CVE row(s) = 5 finding(s)". Reads only (the same resolver as Apply: department
    /// visibility and the guards), writes nothing.
    /// </summary>
    [NotAudited("counts the findings a selection stands for; nothing is written")]
    public async Task<IActionResult> OnPostCountAsync(CancellationToken ct)
    {
        var action = _registry.Find(Request.Form["action"].ToString());
        if (action is null || !await _registry.MayUseAsync(action, User, ct)) return new JsonResult(new { ok = false, message = "Choose an action you may use." });
        var sel = FindingSelection.From(Request.Form);
        // "all matching" is counted by Apply itself (its guard records a refusal) -- the preview is for a selection only
        if (sel.All) return new JsonResult(new { ok = true, rows = (long?)null, findings = (long?)null, refused = 0, message = (string?)null });
        // #330: a count that fails ANSWERS (ok = false, the reason) -- the dialog shows it instead of "counting..." forever
        try
        {
            var r = await _resolver.ResolveAsync(User, sel, action, ct);
            var summary = r.Error is null ? SelectionSummary.Of(r.Targets.Select(t => t.Finding).ToList(), r.Rows, r.RowNoun) : null;
            object? preview = null;
            if (summary is not null && r.Targets.Count > 0 && action is IFindingActionPreview p) preview = await p.PreviewAsync(User, r.Targets, sel.DepartmentContext, ct);
            return new JsonResult(new
            {
                ok = r.Error is null,
                rows = r.Rows,
                findings = r.Error is null ? r.Targets.Count : (long?)null,
                refused = r.Missing.Count,
                message = r.Error ?? r.Expansion ?? Fmt.Int(r.Targets.Count) + " finding(s).",
                what = summary?.What,
                title = summary is null ? null : action.Title(summary.What),
                preview,
            });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log?.LogWarning(ex, "counting the findings of a selection failed");
            var why = ex is TimeoutException ? "the Pro database did not answer in time" : "the Pro database could not be read";
            return new JsonResult(new { ok = false, rows = (long?)null, findings = (long?)null, refused = 0,
                message = $"The findings could not be counted: {why}. The action still checks each finding when you apply it." });
        }
    }

    /// The selection as hidden fields (keys and filter only).
    public static IEnumerable<(string, string)> Carried(FindingSelection sel)
    {
        yield return ("src", sel.Source);
        if (sel.Grid is not null) yield return ("grid", sel.Grid);
        if (sel.CollectionId is not null) yield return ("c", sel.CollectionId);
        foreach (var id in sel.Ids) yield return ("sel", id);
        if (sel.All) yield return ("all", "1");
        foreach (var (k, vs) in sel.Origin) foreach (var v in vs) yield return (k, v);
    }

    public static FindingActionBar BarOf(FindingSelection sel) => new()
    {
        Source = sel.Source, CollectionId = sel.CollectionId, StripId = "apply", Grid = sel.Grid, Map = sel.Map is { Aggregated: true } m ? m : null,
        DepartmentId = sel.DepartmentContext,
    };
}
