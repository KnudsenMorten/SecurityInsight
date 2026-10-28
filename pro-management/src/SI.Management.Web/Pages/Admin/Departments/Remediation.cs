using Microsoft.AspNetCore.Mvc;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Departments;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.Departments;

/// <summary>
/// Admin &gt; Remediation flows (#254, phase 3): what each department does with a category (security domain) / subcategory
/// (report) of findings -- Auto in the maintenance window, Manual, Escalate to the vendor, Accept the risk (exemption
/// flow), Not applicable. The most specific flow wins (a department's own over every department's; a named category /
/// subcategory over "*"), then the order. Every change is one transaction with its cfg.ChangeLog row; a flow is retired,
/// never removed. Admin only (the /Admin folder's policy).
/// </summary>
public sealed class FlowsModel(DepartmentRepository departments, GovernanceRepository repo, ILogger<FlowsModel> log) : DepartmentAdminModel(departments, log)
{
    public IReadOnlyList<RemediationFlowRow> Flows { get; private set; } = Array.Empty<RemediationFlowRow>();
    public IReadOnlyList<DepartmentRow> Active { get; private set; } = Array.Empty<DepartmentRow>();
    public bool GovernanceReady { get; private set; }
    [BindProperty(SupportsGet = true)] public bool Retired { get; set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        ReadRefusal();
        if (!await ReadyAsync(ct)) return;
        try
        {
            GovernanceReady = await repo.TablesExistAsync(ct);
            if (!GovernanceReady) { Error = "The Pro database does not have the remediation-flow tables yet: apply the Pro settings schema again (sql\\si-pro-settings.sql; it only adds)."; return; }
            Flows = await repo.FlowsAsync(Retired, ct);
            Active = await Repo.ListAsync(false, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log.LogError(ex, "remediation flows");
            Error = "The remediation flows could not be read: " + ex.Message;
        }
    }

    public static IReadOnlyList<string> Categories => SecurityDomains.Known;

    [SI.Management.Web.Audit.Audited("remediation.flow.add")]
    public async Task<IActionResult> OnPostAddAsync(int? departmentId, string? category, string? subcategory, string? action, string? vendorName, string? vendorMail,
        string? note, int sortOrder, CancellationToken ct) =>
        Done(await Safely(() => repo.AddFlowAsync(new RemediationFlowInput(departmentId is > 0 ? departmentId : null, string.IsNullOrWhiteSpace(category) ? RemediationFlowResolver.Any : category,
            string.IsNullOrWhiteSpace(subcategory) ? RemediationFlowResolver.Any : subcategory, action ?? "", vendorName, vendorMail, note, sortOrder), User.ChangeName(), ct), "The flow"),
            "/Admin/Departments/Flows");

    [SI.Management.Web.Audit.Audited("remediation.flow.retire")]
    public async Task<IActionResult> OnPostRetireAsync(int flowId, string? reason, CancellationToken ct) =>
        Done(await Safely(() => repo.RetireFlowAsync(flowId, reason ?? "", User.ChangeName(), ct), "The retirement"), "/Admin/Departments/Flows");
}
