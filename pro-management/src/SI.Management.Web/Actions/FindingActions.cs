using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using SI.Management.Web.Auth;
using SI.Management.Web.Departments;

namespace SI.Management.Web.Actions;

/// <summary>
/// ONE ACTION on selected findings (#272): request an exemption, comment, create a task, assign to a department, set the
/// governance status, escalate to the vendor, export. Every grid that lists findings offers the same set through ONE bar
/// (<c>Pages/Shared/_FindingActions.cshtml</c>) and ONE endpoint (<c>/Actions/Apply</c>). An action WRAPS the service that
/// already decides and writes it -- it never holds business logic of its own. A new action is one class implementing this
/// interface plus one registration line in <see cref="FindingActionRegistration"/>: no page changes.
/// </summary>
public interface IFindingAction
{
    /// Stable key, used in the form and the URL ("comment").
    string Key { get; }
    /// The button text ("Comment").
    string Label { get; }
    /// One short word for the icon class (optional).
    string? Icon { get; }
    /// The bar groups its buttons by this (<see cref="ActionGroups"/>).
    string Group { get; }
    /// The order inside the bar (lower first).
    int Order { get; }
    /// One line: what it does (the dialog's lede).
    string Hint { get; }
    /// The audit action the request's ONE event row carries (AUDIT-1, on the closed list).
    string AuditAction { get; }
    /// Whether "apply to all N matching the filter" is offered (also guarded by #264's bulk guard).
    bool SupportsAllMatching { get; }
    /// The most findings one request may cover; a larger selection is refused as a whole.
    int BulkLimit { get; }
    /// The partial with the fields the action asks for (named a.&lt;field&gt;); model: <see cref="ActionFormModel"/>.
    string FormPartial { get; }
    /// True when the answer is a file (the browser downloads it instead of showing results).
    bool Downloads => false;

    /// #330: the dialog's title for a selection, from <see cref="SelectionSummary.What"/> ("Exempt CVE-X on 3 assets").
    string Title(string what) => Label + ": " + what;

    /// Whether the bar offers it to this user at all (a quick role check; the per-finding check is <see cref="CanAsync"/>).
    Task<bool> OfferedAsync(ClaimsPrincipal user, CancellationToken ct);

    /// May this user apply the action to this finding -- the role framework (<see cref="IAccessScope"/>: the finding's
    /// domain, asset kind, tier and department) through the service that owns the decision. Server-side, per finding.
    Task<AccessDecision> CanAsync(ClaimsPrincipal user, GovernanceTarget finding, CancellationToken ct);

    /// Applies it to the findings (every one already allowed by <see cref="CanAsync"/>): one transaction where the store
    /// allows, a result per finding (done, or refused and why).
    Task<ActionOutcome> ExecuteAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, ActionForm form, CancellationToken ct);
}

/// <summary>
/// #330: an action whose form depends on WHAT is selected (who approves it, what else may be offered) previews it when its
/// dialog opens: the count endpoint (/Actions/Prepare?handler=Count) adds this object to its answer, and the no-script
/// page renders the same. Reads only.
/// </summary>
public interface IFindingActionPreview
{
    /// #391: <paramref name="department"/> = the department whose own page the selection was made on (null elsewhere).
    Task<object?> PreviewAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, int? department, CancellationToken ct);
}

/// The groups of the bar, in order.
public static class ActionGroups
{
    public const string Decide = "decide";
    public const string FollowUp = "follow-up";
    public const string Responsibility = "responsibility";
    public const string Data = "data";
    public static readonly IReadOnlyList<string> Order = [Decide, FollowUp, Responsibility, Data];
}

/// What one action's form posted: the fields named a.&lt;field&gt; (the prefix keeps them apart from the grid's own fields).
public sealed class ActionForm
{
    public const string Prefix = "a.";
    private readonly Dictionary<string, string> _v;

    public ActionForm(IEnumerable<KeyValuePair<string, string?>> values) =>
        _v = values.Where(kv => kv.Value is not null).GroupBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Last().Value!, StringComparer.OrdinalIgnoreCase);

    public static ActionForm From(IFormCollection form) => new(form.Where(kv => kv.Key.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase))
        .Select(kv => new KeyValuePair<string, string?>(kv.Key[Prefix.Length..], kv.Value.ToString())));

    public static ActionForm Of(params (string Key, string? Value)[] values) => new(values.Select(v => new KeyValuePair<string, string?>(v.Key, v.Value)));

    public IReadOnlyDictionary<string, string> Values => _v;

    /// <summary>
    /// #391: the department whose OWN page the selection was made on (Departments > a department's findings) -- set by
    /// the endpoint from the selection it resolved on the server (<see cref="FindingSelection.DepartmentContext"/>), never
    /// from a posted a.* field. Null everywhere else.
    /// </summary>
    public int? Department { get; private set; }

    public ActionForm InDepartment(int? departmentId) { Department = departmentId is > 0 ? departmentId : null; return this; }
    public string? Get(string name) => _v.TryGetValue(name, out var s) && !string.IsNullOrWhiteSpace(s) ? s.Trim() : null;
    public bool Flag(string name) => Get(name) is "true" or "on" or "1";
    public DateTime? Date(string name) =>
        DateTime.TryParseExact(Get(name), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : null;
}

/// The result of one finding: done, or refused and why.
public sealed record FindingActionResult(string FindingId, string? AssetName, string? Title, bool Done, string? Why)
{
    public static FindingActionResult Ok(GovernanceTarget t, string? note = null) => new(t.Finding.FindingId, t.Finding.AssetName, t.Finding.Title, true, note);
    public static FindingActionResult No(GovernanceTarget t, string why) => new(t.Finding.FindingId, t.Finding.AssetName, t.Finding.Title, false, why);
}

/// What an action did: a result per finding, one sentence for the toast, and (an export) the file to send.
public sealed record ActionOutcome(IReadOnlyList<FindingActionResult> Results, string Message, IActionResult? File = null)
{
    public int Done => Results.Count(r => r.Done);
    public int Refused => Results.Count(r => !r.Done);

    /// Every finding gets the same answer (a store that writes them in one transaction).
    public static ActionOutcome All(IReadOnlyList<GovernanceTarget> findings, bool done, string message) =>
        new(findings.Select(t => done ? FindingActionResult.Ok(t) : FindingActionResult.No(t, message)).ToList(), message);
}

/// The model of an action's form partial: the action, the bar it is opened from (department, collection), a prefix that
/// keeps the element ids unique on a page that renders several forms.
public sealed record ActionFormModel(IFindingAction Action, FindingActionBar Bar)
{
    /// #330: the findings the form is for, when the server already read them (the no-script page); null in the dialog,
    /// whose script fills the selection-dependent parts from the count endpoint.
    public IReadOnlyList<GovernanceTarget>? Targets { get; init; }

    public string Id(string field) => "fa-" + Action.Key + "-" + field;
    public static string Name(string field) => ActionForm.Prefix + field;
}

/// <summary>
/// THE registry: every <see cref="IFindingAction"/> registered in DI, in the bar's order. Pages, the bar and the endpoint
/// ask it; nothing else lists actions.
/// </summary>
public sealed class FindingActionRegistry
{
    public IReadOnlyList<IFindingAction> All { get; }
    private readonly SI.Management.Web.Licensing.IProLicence? _licence;

    /// <param name="licence">The installed licence (DI always gives it): a paid action (Licensing/ProFeatures.cs) is offered
    /// and accepted only with a Pro licence. A registry built without one (a unit test of the actions themselves) does not
    /// check the licence.</param>
    public FindingActionRegistry(IEnumerable<IFindingAction> actions, SI.Management.Web.Licensing.IProLicence? licence = null)
    {
        var list = actions.OrderBy(a => Math.Max(0, ActionGroups.Order.ToList().IndexOf(a.Group))).ThenBy(a => a.Order).ThenBy(a => a.Key, StringComparer.Ordinal).ToList();
        var dup = list.GroupBy(a => a.Key, StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() > 1);
        if (dup is not null) throw new InvalidOperationException($"two finding actions share the key '{dup.Key}'");
        All = list;
        _licence = licence;
    }

    public IFindingAction? Find(string? key) => string.IsNullOrWhiteSpace(key) ? null : All.FirstOrDefault(a => string.Equals(a.Key, key.Trim(), StringComparison.OrdinalIgnoreCase));

    /// ONE WEB APP, BOTH VERSIONS (owner 2026-10-18): may this installation use the action at all? A paid action needs a Pro
    /// licence -- checked here, server side, by the bar AND by the endpoint (/Actions/Apply, /Actions/Prepare).
    public async Task<bool> LicensedAsync(IFindingAction action, CancellationToken ct) =>
        _licence is null || SI.Management.Web.Licensing.ProFeatures.ForAction(action.Key) is null || await _licence.IsProAsync(ct);

    /// The licence first (<see cref="LicensedAsync"/>), then the action's own role check.
    public async Task<bool> MayUseAsync(IFindingAction action, ClaimsPrincipal user, CancellationToken ct) =>
        await LicensedAsync(action, ct) && await action.OfferedAsync(user, ct);

    /// The actions the bar offers this user.
    public async Task<IReadOnlyList<IFindingAction>> OfferedAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        var list = new List<IFindingAction>();
        foreach (var a in All)
        {
            try { if (await MayUseAsync(a, user, ct)) list.Add(a); }
            catch (Exception ex) when (ex is not OperationCanceledException) { /* an action that cannot tell is not offered */ }
        }
        return list;
    }
}

/// The registration lines: ONE per action. A new action = its class + one line here.
public static class FindingActionRegistration
{
    public static IServiceCollection AddFindingActions(this IServiceCollection s)
    {
        s.AddFindingAction<RequestExemptionAction>();
        s.AddFindingAction<CommentAction>();
        s.AddFindingAction<SetStatusAction>();
        s.AddFindingAction<CreateTaskAction>();
        s.AddFindingAction<EscalateVendorAction>();
        s.AddFindingAction<AssignDepartmentAction>();
        s.AddFindingAction<LinkFindingsAction>();   // #693 link two or more findings of one CI into one
        s.AddSingleton<SI.Management.Web.Changes.FindingLinks>();
        s.AddFindingAction<ExportSelectedAction>();
        s.AddSingleton<FindingActionRegistry>();
        s.AddSingleton<FindingSelectionResolver>();
        return s;
    }

    public static IServiceCollection AddFindingAction<T>(this IServiceCollection s) where T : class, IFindingAction
    {
        s.AddSingleton<IFindingAction, T>();
        return s;
    }
}
