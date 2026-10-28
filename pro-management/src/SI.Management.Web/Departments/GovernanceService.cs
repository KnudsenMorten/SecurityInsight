using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Exemptions;
using SI.Management.Web.Jobs;
using SI.Management.Web.Settings;
using SI.Management.Web.Navigation;

namespace SI.Management.Web.Departments;

/// One finding as the governance log sees it: the row, the department the data sync stamped on it, its collection.
public sealed record GovernanceTarget(FindingRow Finding, int? DepartmentId, string? DepartmentName, string CollectionId)
{
    public string AssetKey => Finding.AssetKey;
    public string? RecommendationKey => GovernanceKeys.Recommendation(Finding.ConfigurationId, Finding.Cve);
}

/// <summary>
/// THE governance decisions and workflows (#254, phase 2 + 3). WHO may write to a finding's log: anyone the role framework
/// lets COMMENT on it (<see cref="IAccessScope.Can"/> with the finding's domain, kind, tier AND its department -- so a
/// Delegated user scoped to one department is refused on every other), or a person of the finding's department
/// (technical owner, business owner, technical or business approver, delegate -- cfg.DepartmentMember, by object id or a group in the token).
/// Advisors (#258) are not writers here yet. Everything is written through <see cref="GovernanceRepository"/>, one
/// transaction per write with its change-log row. SecurityInsight never pushes a change to Defender, Intune, Entra or
/// Azure: "Auto in the maintenance window" records a planned state and its window.
/// </summary>
public sealed class GovernanceService
{
    public static readonly IReadOnlyList<string> WriterRoles = [DepartmentRoles.TechnicalOwner, DepartmentRoles.BusinessOwner, DepartmentRoles.TechnicalApprover, DepartmentRoles.BusinessApprover, DepartmentRoles.Delegate];
    public const string MailKindVendor = "vendor";

    private readonly GovernanceRepository _repo;
    private readonly DepartmentRepository _departments;
    private readonly IAccessScope _access;
    private readonly ExemptionWorkflow? _exemptions;
    private readonly IJobsClient? _jobs;
    private readonly IOptions<JobsOptions>? _jobOptions;
    private readonly TimeProvider _clock;
    private readonly ILogger<GovernanceService> _log;

    public GovernanceService(GovernanceRepository repo, DepartmentRepository departments, IAccessScope access, ILogger<GovernanceService> log,
        ExemptionWorkflow? exemptions = null, IJobsClient? jobs = null, IOptions<JobsOptions>? jobOptions = null, TimeProvider? clock = null)
    {
        _repo = repo; _departments = departments; _access = access; _log = log; _exemptions = exemptions; _jobs = jobs; _jobOptions = jobOptions;
        _clock = clock ?? TimeProvider.System;
    }

    public GovernanceRepository Repository => _repo;
    public DateTime Now => _clock.GetUtcNow().UtcDateTime;

    // ------------------------------------------------------------------------------------------------- who may write

    /// The role framework's target of a finding, with its department (the #254 scope type).
    public static ScopeTarget TargetOf(GovernanceTarget t) =>
        ChangeAccess.ForFinding(t.Finding, ExemptionRepository.ScopeFinding).With(ScopeTypes.Department, t.DepartmentId?.ToString(CultureInfo.InvariantCulture));

    public async Task<AccessDecision> CanWriteAsync(ClaimsPrincipal user, GovernanceTarget t, CancellationToken ct)
    {
        if (user.Identity?.IsAuthenticated != true) return AccessDecision.No("you are not signed in");
        var d = _access.Can(user, AccessAction.Comment, TargetOf(t));
        if (d.Allowed) return d;
        if (t.DepartmentId is { } id)
        {
            try
            {
                var mine = await _departments.MembershipAsync(MembershipDepartmentScope.ObjectIds(user), ct);
                if (mine.Any(m => m.DepartmentId == id && WriterRoles.Contains(m.Role))) return AccessDecision.Yes;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // fail CLOSED: a membership that cannot be read grants nothing
                _log.LogWarning(ex, "department membership could not be read for the governance check");
            }
        }
        return t.DepartmentId is null
            ? AccessDecision.No("this finding belongs to no department yet (Unassigned) -- only an Admin can write to its log: " + d.Reason)
            : AccessDecision.No($"you are not a person of {t.DepartmentName ?? "this department"} and your role does not cover it: {d.Reason}");
    }

    // ------------------------------------------------------------------------------------------------- phase 2: the log

    /// A comment, with or without a new status (one a person sets directly; accepted / escalated come from their actions).
    public async Task<WriteResult> CommentAsync(ClaimsPrincipal user, GovernanceTarget t, string? status, string? comment, CancellationToken ct)
    {
        var gate = await CanWriteAsync(user, t, ct);
        if (!gate.Allowed) return new WriteResult(WriteStatus.Refused, "Not allowed: " + gate.Reason);
        var st = string.IsNullOrWhiteSpace(status) ? null : status.Trim();
        if (st is not null && !GovernanceStatuses.Settable.Contains(st))
            return new WriteResult(WriteStatus.Refused, $"'{st}' is not a status you set directly -- accepting a risk and escalating to the vendor are their own actions");
        if (t.RecommendationKey is null) return new WriteResult(WriteStatus.Refused, "the finding has no recommendation (configuration id or CVE) to log against");
        var (r, _) = await _repo.AddAsync(new GovernanceWrite(t.AssetKey, t.RecommendationKey, t.DepartmentId, st, comment ?? "", "web", CollectionId: t.CollectionId), user.ChangeName(), ct);
        return r;
    }

    // ------------------------------------------------------------------------------------------------- phase 3: the flows

    /// The flow that applies to a finding of its department (the most specific, then the order).
    public async Task<RemediationFlowDef?> FlowForAsync(GovernanceTarget t, CancellationToken ct) =>
        RemediationFlowResolver.Resolve((await _repo.FlowsAsync(false, ct)).Select(f => f.Def), t.DepartmentId, t.Finding.SecurityDomain, t.Finding.ReportName);

    /// <summary>
    /// Applies a remediation action to one finding, recorded in its log (one transaction with the change-log row):
    /// auto-window -> planned for the department's next maintenance window (nothing is pushed to the platform);
    /// manual -> in progress; escalate-vendor -> a mail with the finding's detail to the flow's vendor contact, queued in
    /// the same transaction; accept-risk -> an exemption request (#252) -- the risk is accepted only once approved;
    /// not-applicable -> recorded.
    /// </summary>
    public async Task<WriteResult> ApplyAsync(ClaimsPrincipal user, GovernanceTarget t, string? action, string? comment, CancellationToken ct)
    {
        var gate = await CanWriteAsync(user, t, ct);
        if (!gate.Allowed) return new WriteResult(WriteStatus.Refused, "Not allowed: " + gate.Reason);
        var a = (action ?? "").Trim();
        if (!RemediationActions.All.Contains(a)) return new WriteResult(WriteStatus.Refused, $"'{a}' is not a remediation action ({string.Join(", ", RemediationActions.All)})");
        if (t.RecommendationKey is null) return new WriteResult(WriteStatus.Refused, "the finding has no recommendation (configuration id or CVE) to log against");
        var note = (comment ?? "").Trim();
        var flow = await FlowForAsync(t, ct);
        var by = user.ChangeName();
        GovernanceWrite W(string text, DateTime? when = null, long? request = null, GovernanceMailItem? mail = null) =>
            new(t.AssetKey, t.RecommendationKey!, t.DepartmentId, RemediationActions.StatusOf(a), text, "web", flow?.FlowId, when, request, t.CollectionId, mail);

        switch (a)
        {
            case RemediationActions.AutoWindow:
            {
                if (t.DepartmentId is not { } id) return new WriteResult(WriteStatus.Refused, "the finding belongs to no department, so there is no maintenance window to plan it in");
                var dept = await _departments.GetAsync(id, ct);
                // #335: a department that names TECHNICAL APPROVERS has a fix planned into its window only by one of them
                // (or by someone the role framework lets approve here, e.g. an Admin); without any, as before
                var techs = (await _departments.MembersAsync(id, ct)).Where(m => m.Role == DepartmentRoles.TechnicalApprover).ToList();
                if (techs.Count > 0 && !techs.Any(m => DepartmentApprovers.Matches(m, user)) && !_access.Can(user, AccessAction.Approve, TargetOf(t)).Allowed)
                    return new WriteResult(WriteStatus.Refused, $"planning a fix into {dept?.Name ?? "the department"}'s maintenance window is approved by its technical approvers ({string.Join(", ", techs.Select(m => m.Mail ?? m.DisplayName).Distinct())}) -- ask one of them");
                var (windows, problems) = MaintenanceWindows.Parse(dept?.MaintenanceWindowsJson);
                if (problems.Count > 0) return new WriteResult(WriteStatus.Refused, $"{dept?.Name ?? "the department"}'s maintenance windows cannot be read: {string.Join("; ", problems)} ({NavModel.PathOf("/Admin/Departments/Index")})");
                if (MaintenanceWindows.Next(windows, Now) is not { } next) return new WriteResult(WriteStatus.Refused, $"{dept?.Name ?? "the department"} has no maintenance window ({NavModel.PathOf("/Admin/Departments/Index")} sets them)");
                var text = string.Create(CultureInfo.InvariantCulture, $"Planned for the maintenance window {next.Start:yyyy-MM-dd HH:mm}-{next.End:HH:mm} UTC. The fix is made by the platform's own tooling; SecurityInsight verifies it in the collections after the window.")
                           + (note.Length > 0 ? " " + note : "");
                return (await _repo.AddAsync(W(text, next.Start), by, ct)).Result;
            }
            case RemediationActions.EscalateVendor:
            {
                if (flow?.VendorMail is not { Length: > 0 } vendor) return new WriteResult(WriteStatus.Refused, "no remediation flow names a vendor contact for this finding (" + NavModel.PathOf("/Admin/Departments/Flows") + ")");
                if (note.Length < 3) return new WriteResult(WriteStatus.Refused, "write what you ask of the vendor (at least 3 characters) -- it goes into the mail and the log");
                var mail = GovernanceMailComposer.Vendor(t, flow, note, by);
                var text = $"Escalated to {flow.VendorName ?? vendor} ({vendor}) for review: {note}";
                var (r, _) = await _repo.AddAsync(W(text, mail: mail), by, ct);
                if (r.Status == WriteStatus.Saved) await NudgeAsync(ct);
                return r with { Message = r.Status == WriteStatus.Saved ? $"escalated to {flow.VendorName ?? vendor}: the mail is queued and goes out with the next mail run" : r.Message };
            }
            case RemediationActions.AcceptRisk:
            {
                if (_exemptions is null) return new WriteResult(WriteStatus.Refused, "the exemption flow is not available here");
                if (note.Length < 3) return new WriteResult(WriteStatus.Refused, "give the reason the risk is accepted (at least 3 characters) -- the approver and the audit see it");
                var f = t.Finding;
                var outcome = await _exemptions.RequestAsync(user, new RequestForm(ExemptionRepository.ScopeFinding, note, null, null, null, false),
                    [new FindingRef(f.FindingId, f.AssetKey, f.AssetName, f.ReportName, f.Cve, f.ConfigurationId, f.SecurityDomain, f.Title, f.Category)], "governance", ct);
                if (!outcome.Ok) return new WriteResult(WriteStatus.Refused, "No exemption was requested: " + string.Join("; ", outcome.Problems));
                var req = outcome.Requests[0];
                var text = $"Risk accepted, pending approval: exemption request #{req.RequestId} ({req.ScopeLabel}). {note}";
                var logged = (await _repo.AddAsync(W(text, request: req.RequestId), by, ct)).Result;
                if (logged.Status != WriteStatus.Saved) return logged;
                // #335: the department's business approvers may decide it too (the log entry just written names the department)
                var asked = t.DepartmentId is { } did ? await _exemptions.AskDepartmentAsync(req, did, ct) : Array.Empty<string>();
                return logged with { Message = $"exemption request #{req.RequestId} raised and logged -- the risk is accepted once an owner of {req.ScopeLabel}"
                    + (asked.Count > 0 ? $" or a business approver of {t.DepartmentName ?? "the department"}" : "") + " approves it" };
            }
            default:
            {
                if (note.Length < 3) note = a == RemediationActions.Manual ? "Manual implementation by the technical owners." : "Not applicable for the department.";
                return (await _repo.AddAsync(W(note), by, ct)).Result;
            }
        }
    }

    private async Task NudgeAsync(CancellationToken ct)
    {
        if (_jobs is null || !_jobs.IsConfigured || string.IsNullOrWhiteSpace(_jobOptions?.Value.CloseLoopMailJob)) return;
        try { await _jobs.StartWithEnvAsync(_jobOptions!.Value.CloseLoopMailJob, new Dictionary<string, string> { [OutboxExemptionMailer.OnlyEnv] = "1" }, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the mail job could not be started -- the vendor mail goes with its next scheduled run");
        }
    }
}

/// <summary>
/// The vendor escalation mail (PURE): the finding's detail for an outside reader -- no link into the web app, no tier,
/// no risk score; the person who escalated is named so the vendor can answer them.
/// </summary>
public static class GovernanceMailComposer
{
    private const string Font = "font-family:Segoe UI,Arial,sans-serif;";
    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    public static GovernanceMailItem Vendor(GovernanceTarget t, RemediationFlowDef flow, string request, string by)
    {
        var f = t.Finding;
        var id = string.IsNullOrWhiteSpace(f.Cve) ? f.ConfigurationId : f.Cve;
        var subject = $"Action needed: Security finding for review: {(string.IsNullOrWhiteSpace(id) ? f.Title : id)} on {f.AssetName}";
        if (subject.Length > 400) subject = subject[..400];
        var rows = new (string, string?)[]
        {
            ("Finding", f.Title), ("CVE / configuration", id), ("Severity", f.Severity), ("Asset", f.AssetName), ("Category", f.SecurityDomain),
            ("Report", f.ReportName), ("Seen", f.CollectionTime is { } c ? c.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture) : null),
            ("Department", t.DepartmentName),
        };
        // #728: no table -- a summary first, then the finding as "Topic: text" lines (the topic in bold), in a max-width frame
        var lines = new StringBuilder();
        foreach (var (k, v) in rows.Where(r => !string.IsNullOrWhiteSpace(r.Item2)))
            lines.Append(SI.Management.Core.Mail.MailLayout.Line(k, v));
        var what = string.IsNullOrWhiteSpace(id) ? f.Title : id;
        var summary = SI.Management.Core.Mail.MailLayout.Summary(new[]
        {
            $"<strong>Action needed:</strong> review the finding below and reply to {E(by)}",
            $"<strong>Finding:</strong> {E(what)} on {E(f.AssetName)}{(string.IsNullOrWhiteSpace(f.Severity) ? "" : " (" + E(f.Severity) + ")")}",
        });
        var body = summary +
                   $"<p style=\"margin:0 0 14px 0;line-height:1.55;\">{E(flow.VendorName is null ? "Hello," : "Hello " + flow.VendorName + ",")}</p>" +
                   $"<p style=\"margin:0 0 14px 0;line-height:1.55;\">{E(by)} asks you to review the security finding below.</p>" +
                   $"<p style=\"margin:0 0 14px 0;line-height:1.55;\"><strong>Request:</strong><br>{SI.Management.Core.Mail.MailLayout.Inline(request)}</p>" +
                   SI.Management.Core.Mail.MailLayout.Heading("The finding") + lines +
                   $"<p style=\"margin:14px 0 14px 0;line-height:1.55;\">Please reply to {E(by)}.</p>";
        var html = SI.Management.Core.Mail.MailLayout.Frame("Security finding for review", null, null, body, $"Sent with SecurityInsight Pro on behalf of {E(by)}");
        return new GovernanceMailItem(GovernanceService.MailKindVendor, [flow.VendorMail!.Trim()], subject, html);
    }
}
