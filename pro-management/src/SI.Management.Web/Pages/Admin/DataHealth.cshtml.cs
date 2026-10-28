using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Audit;
using SI.Management.Web.Auth;
using SI.Management.Web.DataHealth;

namespace SI.Management.Web.Pages.Admin;

/// <summary>
/// Configuration > Connectors > Data-health hold (CR2, SI #656 -- SecurityInsight only): the daily check of SecurityInsight's own data -- when it
/// ran, per source and per Risk Analysis report how many records were checked, found, missing and different, the records
/// that did not match, and the state (Healthy / Unhealthy). While Unhealthy every data-out channel plans only; a SuperAdmin
/// lets ONE channel through with a reason, until the data is Healthy again (audited data-health.override.set / .clear).
/// Readers see everything; only a SuperAdmin changes anything.
/// </summary>
public sealed class DataHealthModel : PageModel
{
    private readonly IDataHealthStore _store;
    private readonly ILogger<DataHealthModel> _log;
    public DataHealthModel(IDataHealthStore store, ILogger<DataHealthModel> log) { _store = store; _log = log; }

    public DataHealthView View { get; private set; } = DataHealthView.Missing0;
    public string? Error { get; private set; }

    [BindProperty(SupportsGet = true)] public long? Cycle { get; set; }
    [BindProperty] public string? Channel { get; set; }
    [BindProperty] public string? Reason { get; set; }

    public async Task OnGetAsync(CancellationToken ct)
    {
        try { View = await _store.ReadAsync(Cycle, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the data health results could not be read");
            Error = "The data health results could not be read from the Pro database: " + ex.Message;
        }
        // owner 2026-10-20 ("verify table schema matches + get alerts"): a ServiceNow output whose newest check is not ok
        if (HttpContext?.RequestServices.GetService<SI.Management.Web.Outputs.IServiceNowCheckStore>() is { } snow)
        {
            // #903: only an output that is switched on (SI_DataOut_Outputs) -- a switched-off output is never a warning here, whatever
            // its newest stored check says (owner: no unnecessary alerts; the heartbeat and the daily mail apply the same rule)
            IReadOnlySet<string> on = new HashSet<string>(StringComparer.Ordinal);
            try
            {
                if (HttpContext.RequestServices.GetService<SI.Management.Web.Settings.ISettingsStoreReader>() is { } reader)
                {
                    var row = (await reader.ReadSettingsAsync(ct)).Rows.Where(r => r.Name.Equals(SI.Management.Web.Pages.Reports.OutputFieldsModel.OutputsSetting, StringComparison.OrdinalIgnoreCase)).OrderBy(r => r.Scope == "solution" ? 0 : 1).FirstOrDefault();
                    on = SI.Management.Web.Pages.Reports.OutputFieldsModel.OnOutputs(SI.Management.Core.ProData.OutputMapRules.Catalog, row is null ? null : SI.Management.Web.Settings.SettingJson.ToFormText(row.ValueJson));
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the outputs setting could not be read"); }
            try { ServiceNowWarnings = (await snow.LatestAsync(ct)).Where(c => c.Outcome != "ok" && on.Contains(c.Output)).OrderBy(c => c.Outcome == "failed" ? 0 : 1).ThenBy(c => c.Output, StringComparer.Ordinal).ToList(); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the ServiceNow checks could not be read"); }
        }
    }

    /// The ServiceNow outputs whose newest check failed (the push is held) or warned -- shown as data health warnings.
    public IReadOnlyList<SI.Management.Web.Outputs.SnowCheckRow> ServiceNowWarnings { get; private set; } = Array.Empty<SI.Management.Web.Outputs.SnowCheckRow>();

    /// Let one data-out channel through while the data is Unhealthy (SuperAdmin, with a reason) -- until Healthy again.
    [Audited("data-health.override.set")]
    public async Task<IActionResult> OnPostOverrideAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        var audit = AuditScope.Current;
        if (audit is not null) { audit.Target = "/Admin/DataHealth/" + (Channel ?? ""); audit.Reason = Reason; }
        (bool Saved, string Message) r;
        try
        {
            var view = await _store.ReadAsync(null, ct);
            if (DataHealthRules.Validate(view.State, Channel, Reason, view.Overrides) is { } bad) { audit?.Refused(bad); return Toast(false, bad); }
            r = await _store.OverrideAsync(Channel!, Reason!, User.ChangeName(), "SuperAdmin", ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "a data health override failed");
            r = (false, "Not saved: " + ex.Message);
        }
        if (!r.Saved) audit?.Refused(r.Message);
        return Toast(r.Saved, r.Message);
    }

    /// Take an override back: the channel is held again while the data is Unhealthy (SuperAdmin).
    [Audited("data-health.override.clear")]
    public async Task<IActionResult> OnPostClearAsync(CancellationToken ct)
    {
        if (!User.IsSuperAdmin()) return Forbid();
        var audit = AuditScope.Current;
        if (audit is not null) audit.Target = "/Admin/DataHealth/" + (Channel ?? "");
        if (string.IsNullOrWhiteSpace(Channel)) return Toast(false, "No channel was chosen.");
        (bool Saved, string Message) r;
        try { r = await _store.ClearOverrideAsync(Channel, User.ChangeName(), ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "taking a data health override back failed");
            r = (false, "Not taken back: " + ex.Message);
        }
        if (!r.Saved) audit?.Refused(r.Message);
        return Toast(r.Saved, r.Message);
    }

    private IActionResult Toast(bool ok, string message)
    {
        TempData["toast"] = message;
        TempData["toastKind"] = ok ? "ok" : "error";
        return RedirectToPage(new { cycle = Cycle });
    }
}
