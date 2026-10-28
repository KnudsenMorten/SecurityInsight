using System.Globalization;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Departments;
using SI.Management.Web.Exemptions;
using SI.Management.Web.Export;
using SI.Management.Web.Settings;
using SI.Management.Web.Tasks;

using Fmt = SI.Management.Web.Pages.Fmt;

namespace SI.Management.Web.Actions;

// THE SEVEN ACTIONS of the shared bar (#272). Each one only wraps the service that already owns the decision and the
// write: ExemptionWorkflow (#252), GovernanceService (#254 phase 2 + 3), FindingTaskService (#265), DepartmentRepository
// (the responsibility override, #254 phase 1) and the findings export. None of them decides a permission itself.

/// Shared: who writes to a finding's governance log (the role framework's Comment on the finding, or a person of its department).
internal static class GovernanceWriters
{
    public static async Task<bool> OfferedAsync(ClaimsPrincipal user, DepartmentRepository departments, CancellationToken ct)
    {
        if (user.Identity?.IsAuthenticated != true) return false;
        if (RoleDefinitions.Find(user.EffectiveRole())?.Allows(AccessAction.Comment) == true) return true;
        try { return (await departments.MembershipAsync(MembershipDepartmentScope.ObjectIds(user), ct)).Any(m => GovernanceService.WriterRoles.Contains(m.Role)); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return false; }
    }

    /// The finding needs a recommendation key (CVE or configuration id) for anything kept per finding across collections.
    public static AccessDecision? NoKey(GovernanceTarget t) =>
        t.RecommendationKey is null ? AccessDecision.No("the finding has no recommendation (configuration id or CVE) to keep it against") : null;
}

// ---------------------------------------------------------------------------------------------------- request exemption

/// #252: one exemption REQUEST for the selected findings (one per security domain), decided by the domain's approvers --
/// or approved at once by a requester who may decide the domain. Nothing applies before it is approved.
public sealed class RequestExemptionAction(ExemptionWorkflow flow) : IFindingAction, IFindingActionPreview
{
    public const string ActionKey = "exemption-request";
    public string Key => ActionKey;
    public string Label => "Request exemption";
    public string? Icon => "shield";
    public string Group => ActionGroups.Decide;
    public int Order => 10;
    /// #330: one sentence (the routing per domain / category is the workflow's; #391: on a department's own page its
    /// business approvers -- the dialog's approver line names them).
    public string Hint => "The approvers named here decide it; it counts from the next run.";
    public string Title(string what) => "Exempt " + what;

    /// The findings as the exemption flow reads them.
    public static List<FindingRef> Refs(IEnumerable<GovernanceTarget> findings) => findings.Select(t => new FindingRef(t.Finding.FindingId, t.Finding.AssetKey, t.Finding.AssetName,
        t.Finding.ReportName, t.Finding.Cve, t.Finding.ConfigurationId, t.Finding.SecurityDomain, t.Finding.Title, t.Finding.Category)).ToList();

    /// <summary>
    /// #391: the department a request is routed to -- the department page the selection was made on, and only when EVERY
    /// finding (read back on the server) is that department's. Anything else = no department context (the owners decide).
    /// </summary>
    public static int? DepartmentOf(int? context, IReadOnlyCollection<GovernanceTarget> findings) =>
        context is > 0 && findings.Count > 0 && findings.All(t => t.DepartmentId == context) ? context : null;

    /// #330: who approves this selection, whether "Approve now" is offered, and the one wider scope that fits.
    public async Task<ExemptionPreview> PreviewOfAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, CancellationToken ct, int? department = null)
    {
        var open = findings.Where(t => !t.Finding.IsExempted).ToList();
        return await flow.PreviewAsync(user, Refs(open), findings.Count - open.Count, ct, DepartmentOf(department, open));
    }

    async Task<object?> IFindingActionPreview.PreviewAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, int? department, CancellationToken ct)
    {
        var p = await PreviewOfAsync(user, findings, ct, department);
        return new
        {
            approvers = p.ApproversText,
            parts = p.Parts.Select(x => new { label = x.Label, approvers = x.Approvers }),
            canApproveAll = p.CanApproveAll,
            overrides = p.Overrides,
            alternatives = p.Alternatives.Select(a => new { scope = a.Scope, label = a.Label }),
            alreadyExempted = p.AlreadyExempted,
            department = p.Department,
            toDepartment = p.ToDepartment,
        };
    }
    public string AuditAction => "exemption.request.submit";
    public bool SupportsAllMatching => true;
    public int BulkLimit => ExemptionWorkflow.MaxItems;
    public string FormPartial => "~/Pages/Shared/FindingActions/_Exemption.cshtml";
    public ExemptionWorkflow Flow => flow;

    public Task<bool> OfferedAsync(ClaimsPrincipal user, CancellationToken ct) => Task.FromResult(user.IsReader());

    public Task<AccessDecision> CanAsync(ClaimsPrincipal user, GovernanceTarget finding, CancellationToken ct) =>
        Task.FromResult(user.IsReader() ? AccessDecision.Yes : AccessDecision.No("only a Reader or above can request an exemption"));

    public async Task<ActionOutcome> ExecuteAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, ActionForm form, CancellationToken ct)
    {
        var results = new List<FindingActionResult>();
        var go = new List<GovernanceTarget>();
        foreach (var t in findings)
            if (t.Finding.IsExempted) results.Add(FindingActionResult.No(t, "already exempted in this collection"));
            else go.Add(t);
        if (go.Count == 0) return new ActionOutcome(results, "Nothing requested: every selected finding is already exempted.");
        var scope = form.Get("scope") ?? ExemptionRepository.ScopeFinding;
        // #330: the default is exactly the selection; a wider scope only where the dialog offers it (one issue, or one asset)
        if (!ExemptionPreview.Allows(scope, Refs(go)))
            throw new ArgumentException(scope == ExemptionRepository.ScopeIssue
                ? "\"every asset, now and later\" needs a selection of ONE issue (CVE / configuration) -- this one has several. Leave the default to exempt exactly the selection."
                : scope == ExemptionRepository.ScopeAsset
                    ? "\"every finding on the asset, now and later\" needs a selection on ONE asset -- this one spans several. Leave the default to exempt exactly the selection."
                    : $"'{scope}' is not an exemption scope.");
        // #391: made on a department's own page (the endpoint's server-side context, all findings that department's) -> its
        // business approvers decide
        var f = new RequestForm(scope, form.Get("reason") ?? "", form.Get("period"), form.Date("customDate"),
            form.Get("approver"), form.Flag("approveNow"), DepartmentOf(form.Department, go));
        var refs = await flow.WithCategoriesAsync(Refs(go), ct);
        var categories = refs.ToDictionary(x => x.FindingId, x => x.Category, StringComparer.Ordinal);
        var r = await flow.RequestAsync(user, f, refs, "actions", ct);
        foreach (var t in go)
        {
            var domain = DomainRoles.Normalize(t.Finding.SecurityDomain);
            var cat = categories.GetValueOrDefault(t.Finding.FindingId);
            // #283: its category's own request when the category has owners, else its domain's
            var req = r.Requests.FirstOrDefault(x => string.Equals(x.Domain, domain, StringComparison.OrdinalIgnoreCase) && x.Category is not null && string.Equals(x.Category, cat, StringComparison.OrdinalIgnoreCase))
                      ?? r.Requests.FirstOrDefault(x => string.Equals(x.Domain, domain, StringComparison.OrdinalIgnoreCase) && x.Category is null);
            var own = r.Problems.FirstOrDefault(p => (t.Finding.AssetName.Length > 0 && p.StartsWith(t.Finding.AssetName + ":", StringComparison.Ordinal)) || p.StartsWith(t.Finding.FindingId + ":", StringComparison.Ordinal));
            if (req is not null && own is null)
                results.Add(FindingActionResult.Ok(t, req.State == ExemptionStates.Approved ? $"approved in request #{req.RequestId}" : $"in request #{req.RequestId} ({req.ScopeLabel}), waiting for a decision"));
            else
                results.Add(FindingActionResult.No(t, own ?? r.Problems.FirstOrDefault(p => p.Contains(" " + domain + " ", StringComparison.Ordinal)) ?? r.Problems.FirstOrDefault() ?? "not requested"));
        }
        var ids = string.Join(", ", r.Requests.Select(x => "#" + x.RequestId.ToString(CultureInfo.InvariantCulture)));
        var msg = !r.Ok ? "No exemption was requested: " + string.Join("; ", r.Problems.Take(2))
            : r.Approved > 0 ? $"{Fmt.Int(r.Approved)} exemption(s) approved by you and written ({ids}) -- they apply from the next run."
            : $"Requested: {Fmt.Int(r.Items)} finding(s) in {Fmt.Int(r.Requests.Count)} request(s) ({ids}). An approver decides; nothing applies before that.";
        // #391: who it went to (also on the request's audit row)
        if (r.Ok && r.RoutedTo is not null) msg += $" Asked of {r.RoutedTo}.";
        if (r.Notes.Count > 0) msg += " " + r.Notes[0];
        return new ActionOutcome(results, msg);
    }
}

// ---------------------------------------------------------------------------------------------------- comment

/// #254 / #265: a comment in each selected finding's governance log (its one thread), kept across collections.
public sealed class CommentAction(GovernanceService gov, DepartmentRepository departments) : IFindingAction
{
    public const string ActionKey = "comment";
    public string Key => ActionKey;
    public string Label => "Comment";
    public string? Icon => "comment";
    public string Group => ActionGroups.FollowUp;
    public int Order => 10;
    public string Hint => "The same comment in the governance log of every selected finding -- it stays with the finding on its asset across collections.";
    public string Title(string what) => "Comment on " + what;
    public string AuditAction => "finding.comment.add";
    public bool SupportsAllMatching => true;
    public int BulkLimit => 500;
    public string FormPartial => "~/Pages/Shared/FindingActions/_Comment.cshtml";

    public Task<bool> OfferedAsync(ClaimsPrincipal user, CancellationToken ct) => GovernanceWriters.OfferedAsync(user, departments, ct);

    public async Task<AccessDecision> CanAsync(ClaimsPrincipal user, GovernanceTarget finding, CancellationToken ct) =>
        GovernanceWriters.NoKey(finding) ?? await gov.CanWriteAsync(user, finding, ct);

    public async Task<ActionOutcome> ExecuteAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, ActionForm form, CancellationToken ct)
    {
        var text = form.Get("comment") ?? "";
        if (text.Length < 3) return ActionOutcome.All(findings, false, "write a comment (at least 3 characters) -- it is what the log and the audit show");
        var results = new List<FindingActionResult>();
        foreach (var t in findings)
        {
            var r = await gov.CommentAsync(user, t, null, text, ct);
            results.Add(r.Status == WriteStatus.Saved ? FindingActionResult.Ok(t) : FindingActionResult.No(t, r.Message));
        }
        var done = results.Count(x => x.Done);
        return new ActionOutcome(results, done > 0 ? $"Comment added to the log of {Fmt.Int(done)} finding(s)." : "No comment was added: " + results.FirstOrDefault()?.Why);
    }
}

// ---------------------------------------------------------------------------------------------------- set status

/// #254 phase 2: the governance status (open / in progress / planned / fixed pending verification / not applicable) with a
/// comment. Accepted and Escalated are never set here: they come from their own actions.
public sealed class SetStatusAction(GovernanceService gov, DepartmentRepository departments) : IFindingAction
{
    public const string ActionKey = "status";
    public string Key => ActionKey;
    public string Label => "Set status";
    public string? Icon => "status";
    public string Group => ActionGroups.FollowUp;
    public int Order => 20;
    public string Hint => "The governance status of every selected finding, with the comment that explains it (both in its log).";
    public string Title(string what) => "Set the status of " + what;
    public string AuditAction => "governance.status.set";
    public bool SupportsAllMatching => true;
    public int BulkLimit => 500;
    public string FormPartial => "~/Pages/Shared/FindingActions/_Status.cshtml";

    public Task<bool> OfferedAsync(ClaimsPrincipal user, CancellationToken ct) => GovernanceWriters.OfferedAsync(user, departments, ct);

    public async Task<AccessDecision> CanAsync(ClaimsPrincipal user, GovernanceTarget finding, CancellationToken ct) =>
        GovernanceWriters.NoKey(finding) ?? await gov.CanWriteAsync(user, finding, ct);

    public async Task<ActionOutcome> ExecuteAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, ActionForm form, CancellationToken ct)
    {
        var status = form.Get("status");
        if (status is null || !GovernanceStatuses.Settable.Contains(status))
            return ActionOutcome.All(findings, false, $"choose a status ({string.Join(", ", GovernanceStatuses.Settable.Select(GovernanceStatuses.Label))})");
        var text = form.Get("comment") ?? "";
        if (text.Length < 3) return ActionOutcome.All(findings, false, "write why (at least 3 characters) -- it is what the log and the audit show");
        var results = new List<FindingActionResult>();
        foreach (var t in findings)
        {
            var r = await gov.CommentAsync(user, t, status, text, ct);
            results.Add(r.Status == WriteStatus.Saved ? FindingActionResult.Ok(t, GovernanceStatuses.Label(status)) : FindingActionResult.No(t, r.Message));
        }
        var done = results.Count(x => x.Done);
        return new ActionOutcome(results, done > 0 ? $"Status set to {GovernanceStatuses.Label(status).ToLowerInvariant()} on {Fmt.Int(done)} finding(s)." : "No status was set: " + results.FirstOrDefault()?.Why);
    }
}

// ---------------------------------------------------------------------------------------------------- create task

/// #265: one follow-up task per selected finding -- the same title, person and due day -- in ONE transaction; refused as
/// a whole when the assignee does not fit every finding.
public sealed class CreateTaskAction(FindingTaskService tasks, DepartmentRepository departments) : IFindingAction
{
    public const string ActionKey = "task";
    public string Key => ActionKey;
    public string Label => "Create task";
    public string? Icon => "task";
    public string Group => ActionGroups.FollowUp;
    public int Order => 30;
    public string Hint => "A follow-up task on each selected finding -- in the assignee's My tasks and your Delegated tasks.";
    public string Title(string what) => "Create a task for " + what;
    public string AuditAction => "finding.task.create";
    public bool SupportsAllMatching => true;
    public int BulkLimit => FindingTaskService.MaxBulk;
    public string FormPartial => "~/Pages/Shared/FindingActions/_Task.cshtml";
    public FindingTaskService Tasks => tasks;

    public Task<bool> OfferedAsync(ClaimsPrincipal user, CancellationToken ct) => GovernanceWriters.OfferedAsync(user, departments, ct);

    public async Task<AccessDecision> CanAsync(ClaimsPrincipal user, GovernanceTarget finding, CancellationToken ct) =>
        GovernanceWriters.NoKey(finding) ?? await tasks.CanCreateAsync(user, finding, ct);

    public async Task<ActionOutcome> ExecuteAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, ActionForm form, CancellationToken ct)
    {
        var f = new TaskForm(form.Get("title"), form.Get("note"), form.Get("assignee"), form.Date("due"), form.Date("remind"),
            form.Get("entraKind"), form.Get("entraId"), form.Get("entraName"), form.Get("entraMail"));
        var (r, _) = await tasks.CreateAsync(user, findings, f, ct);
        return r.Status == WriteStatus.Saved
            ? ActionOutcome.All(findings, true, char.ToUpperInvariant(r.Message[0]) + r.Message[1..] + " -- one per finding.")
            : ActionOutcome.All(findings, false, r.Message);
    }
}

// ---------------------------------------------------------------------------------------------------- escalate to vendor

/// #254 phase 3: the remediation flow's "Escalate to the vendor" -- a mail with each finding's detail to the vendor contact
/// of the flow that applies to it, queued with its log entry. Offered only where a flow names a vendor.
public sealed class EscalateVendorAction(GovernanceService gov, DepartmentRepository departments) : IFindingAction
{
    public const string ActionKey = "escalate-vendor";
    public string Key => ActionKey;
    public string Label => "Escalate to vendor";
    public string? Icon => "mail";
    public string Group => ActionGroups.FollowUp;
    public int Order => 40;
    public string Hint => "Each finding goes to the vendor contact of the remediation flow that applies to it (a mail per finding, recorded as escalated). A finding no flow sends to a vendor is refused.";
    public string Title(string what) => "Escalate " + what + " to the vendor";
    public string AuditAction => "governance.vendor.escalate";
    public bool SupportsAllMatching => false;
    public int BulkLimit => 50;
    public string FormPartial => "~/Pages/Shared/FindingActions/_Vendor.cshtml";

    public async Task<bool> OfferedAsync(ClaimsPrincipal user, CancellationToken ct)
    {
        if (!await GovernanceWriters.OfferedAsync(user, departments, ct)) return false;
        try
        {
            return await gov.Repository.TablesExistAsync(ct)
                && (await gov.Repository.FlowsAsync(false, ct)).Any(f => f.Action == RemediationActions.EscalateVendor && !string.IsNullOrWhiteSpace(f.VendorMail));
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return false; }
    }

    public async Task<AccessDecision> CanAsync(ClaimsPrincipal user, GovernanceTarget finding, CancellationToken ct) =>
        GovernanceWriters.NoKey(finding) ?? await gov.CanWriteAsync(user, finding, ct);

    public async Task<ActionOutcome> ExecuteAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, ActionForm form, CancellationToken ct)
    {
        var note = form.Get("note") ?? "";
        if (note.Length < 3) return ActionOutcome.All(findings, false, "write what you ask of the vendor (at least 3 characters) -- it goes into the mail and the log");
        var results = new List<FindingActionResult>();
        foreach (var t in findings)
        {
            var r = await gov.ApplyAsync(user, t, RemediationActions.EscalateVendor, note, ct);
            results.Add(r.Status == WriteStatus.Saved ? FindingActionResult.Ok(t, r.Message) : FindingActionResult.No(t, r.Message));
        }
        var done = results.Count(x => x.Done);
        return new ActionOutcome(results, done > 0 ? $"{Fmt.Int(done)} finding(s) escalated to their vendor -- the mails go out with the next mail run." : "Nothing was escalated: " + results.FirstOrDefault()?.Why);
    }
}

// ---------------------------------------------------------------------------------------------------- assign to department

/// #254: the responsibility override -- the selected findings' ASSETS (every finding on them) or RECOMMENDATIONS (that
/// issue on every asset) belong to a department. One override per distinct key, one transaction; the findings move on the
/// next data sync. Who may: the role framework's Administer (Admin and up), as the Unassigned triage always was.
public sealed class AssignDepartmentAction(DepartmentRepository departments, IAccessScope access) : IFindingAction, IFindingActionPreview
{
    /// #330: the "Assign by" choice opens on what the selection is -- ONE issue on several assets = the recommendation
    /// (that issue, wherever it is); anything else = the assets. The other stays one click away.
    public static string DefaultScope(IReadOnlyCollection<GovernanceTarget> findings)
    {
        var s = SelectionSummary.Of(findings.Select(t => t.Finding).ToList());
        return s.Issue is not null && s.Assets > 1 && findings.All(t => t.RecommendationKey is not null) ? "recommendation" : "asset";
    }

    Task<object?> IFindingActionPreview.PreviewAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, int? department, CancellationToken ct) =>
        Task.FromResult<object?>(new { defaultScope = DefaultScope(findings) });

    public const string ActionKey = "assign-department";
    public string Key => ActionKey;
    public string Label => "Assign to department";
    public string? Icon => "department";
    public string Group => ActionGroups.Responsibility;
    public int Order => 10;
    public string Hint => "The selected findings' assets (every finding on them) or recommendations (that issue on every asset) belong to a department from now on. The findings move on the next data sync.";
    public string Title(string what) => "Assign " + what + " to a department";
    public string AuditAction => "responsibility.assignment.bulk";
    public bool SupportsAllMatching => true;
    public int BulkLimit => ExemptionWorkflow.MaxItems;
    public string FormPartial => "~/Pages/Shared/FindingActions/_Department.cshtml";
    public DepartmentRepository Departments => departments;

    public Task<bool> OfferedAsync(ClaimsPrincipal user, CancellationToken ct) => Task.FromResult(access.Can(user, AccessAction.Administer).Allowed);

    public Task<AccessDecision> CanAsync(ClaimsPrincipal user, GovernanceTarget finding, CancellationToken ct)
    {
        var d = access.Can(user, AccessAction.Administer);
        return Task.FromResult(d.Allowed ? AccessDecision.Yes : AccessDecision.No("assigning findings to a department is an Admin change: " + d.Reason));
    }

    public async Task<ActionOutcome> ExecuteAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, ActionForm form, CancellationToken ct)
    {
        var scope = form.Get("scope") == "asset" ? "asset" : "recommendation";
        if (!int.TryParse(form.Get("departmentId"), NumberStyles.None, CultureInfo.InvariantCulture, out var dept) || dept <= 0)
            return ActionOutcome.All(findings, false, "choose the department");
        var keyed = findings.Select(t => (t, key: scope == "asset" ? t.AssetKey : t.RecommendationKey)).ToList();
        var keys = keyed.Where(x => !string.IsNullOrWhiteSpace(x.key)).Select(x => x.key!).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var r = await departments.OverrideAsync(scope, keys, dept, form.Get("reason") ?? "", user.ChangeName(), ct);
        var ok = r.Status == WriteStatus.Saved;
        return new ActionOutcome(keyed.Select(x => string.IsNullOrWhiteSpace(x.key)
                ? FindingActionResult.No(x.t, scope == "asset" ? "the finding has no asset key" : "the finding has no recommendation (configuration id or CVE)")
                : ok ? FindingActionResult.Ok(x.t) : FindingActionResult.No(x.t, r.Message)).ToList(),
            ok ? char.ToUpperInvariant(r.Message[0]) + r.Message[1..] + "." : "Nothing was assigned: " + r.Message);
    }
}

// ---------------------------------------------------------------------------------------------------- export selected

/// Just the selected findings, as CSV or an Excel workbook (the findings browser's columns). Audited as data.export.download.
public sealed class ExportSelectedAction(IAccessScope access) : IFindingAction
{
    public const string ActionKey = "export";
    public string Key => ActionKey;
    public string Label => SI.Management.Web.Columns.ExportLabels.SelectedRowsFindings;
    public string? Icon => "download";
    public string Group => ActionGroups.Data;
    public int Order => 10;
    public string Hint => "Just the selected findings, as CSV or an Excel workbook. The page's own export takes every finding of the view.";
    public string Title(string what) => "Export " + what;
    public string AuditAction => "data.export.download";
    public bool SupportsAllMatching => false;
    public int BulkLimit => SI.Management.Core.ProData.GridSql.MaxSelected;
    public string FormPartial => "~/Pages/Shared/FindingActions/_Export.cshtml";
    public bool Downloads => true;

    public Task<bool> OfferedAsync(ClaimsPrincipal user, CancellationToken ct) => Task.FromResult(access.Can(user, AccessAction.View).Allowed);

    public Task<AccessDecision> CanAsync(ClaimsPrincipal user, GovernanceTarget finding, CancellationToken ct) => Task.FromResult(access.Can(user, AccessAction.View));

    public async Task<ActionOutcome> ExecuteAsync(ClaimsPrincipal user, IReadOnlyList<GovernanceTarget> findings, ActionForm form, CancellationToken ct)
    {
        var rows = findings.Select(t => t.Finding).ToList();
        var cols = Pages.Findings.IndexModel.ExportColumns.Append("Department").ToArray();
        object?[] Cells(GovernanceTarget t)
        {
            var r = t.Finding;
            return [r.CollectionTime, ExcelExport.Tier(r.Tier), r.AssetName, r.AssetKind, r.Severity, r.RiskScore, r.SecurityDomain, r.ReportName,
                ExcelExport.Blank(r.Cve), ExcelExport.Blank(r.ConfigurationId), r.Title, r.AssetKey, r.FindingId, t.DepartmentName ?? (t.DepartmentId is null ? "Unassigned" : null)];
        }
        IActionResult file;
        var collection = rows.FirstOrDefault()?.CollectionId;
        if (form.Get("format") == "xlsx")
        {
            file = await ExcelExport.FileAsync("findings-selected", collection, (x, info) =>
            {
                info.Collection = collection;
                info.Add("Selected findings", rows.Count);
                x.Sheet(info, "Findings", cols, findings.Select(t => (IReadOnlyList<object?>)Cells(t)));
                return Task.CompletedTask;
            }, ct);
        }
        else
        {
            var sb = new StringBuilder();
            sb.AppendLine(string.Join(",", cols.Select(Pages.Findings.IndexModel.Csv)));
            foreach (var t in findings)
            {
                var r = t.Finding;
                var cells = new[]
                {
                    r.CollectionTime?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "", r.Tier, r.AssetName, r.AssetKind, r.Severity,
                    r.RiskScore.ToString("0.##", CultureInfo.InvariantCulture), r.SecurityDomain, r.ReportName, r.Cve, r.ConfigurationId, r.Title, r.AssetKey, r.FindingId,
                    t.DepartmentName ?? (t.DepartmentId is null ? "Unassigned" : ""),
                };
                sb.AppendLine(string.Join(",", cells.Select(Pages.Findings.IndexModel.Csv)));
            }
            var name = "securityinsight-findings-selected-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + ".csv";
            file = new FileContentResult(Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray(), "text/csv; charset=utf-8") { FileDownloadName = name };
        }
        return new ActionOutcome(findings.Select(t => FindingActionResult.Ok(t)).ToList(), $"{Fmt.Int(rows.Count)} finding(s) exported.", file);
    }
}
