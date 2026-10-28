using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Changes;
using SI.Management.Web.Export;
using SI.Management.Web.Settings;

namespace SI.Management.Web.Pages.Admin.ConnectorSetup;

/// <summary>
/// Connectors (cfg.Connector, phase E): every connector the vulnerability close-loop sends its results to -- sql,
/// servicenow or a rest mapping for any third-party risk / ticketing system -- with its mode, arming and last run
/// (cfg.ConnectorRun). Enable / disable is STAGED like every other change and written on Review &amp; commit.
/// </summary>
public sealed class IndexModel : PageModel
{
    private readonly ConnectorRepository _repo;
    private readonly ChangeService _changes;
    private readonly ILogger<IndexModel> _log;
    private readonly SettingsCatalog _catalog;
    private readonly ISettingsStoreReader _settings;
    public IndexModel(ConnectorRepository repo, ChangeService changes, ILogger<IndexModel> log, SettingsCatalog catalog, ISettingsStoreReader settings)
    { _repo = repo; _changes = changes; _log = log; _catalog = catalog; _settings = settings; }

    /// #914 (owner 2026-10-27) ONE ROUTE into ServiceNow: the ServiceNow data-out connector (or the hand-off database). The older
    /// push -- the CMDB job, the close-loop's ServiceNow connector and their two direct-write switches -- was removed; this card
    /// says so where the switches were.
    public const string OneRouteText = "SecurityInsight sends to ServiceNow through one route: the ServiceNow data-out connector below (direction data-out), which writes only to Import Set staging tables -- or your ServiceNow reads the hand-off database. Your import and transform rules make every change. SecurityInsight never writes a configuration item or a vulnerable item itself.";
    /// #914 (i) / (j): a full resync (every record in scope sent again, mode resync) or a test batch (at most 5 rows per output,
    /// mode test -- the importer never imports it) on the next sync. The request is the setting SI_DataOut_ServiceNowRequest,
    /// saved through Review and Save on the settings page (change-logged, audited); carried out once per token.
    public const string RequestSetting = "SI_DataOut_ServiceNowRequest";
    public const string RequestText = "Full resync: the next sync sends every record in scope again as new, in one batch (mode resync). Send a test batch: the next sync first sends at most 5 rows of each output as a batch your importer never imports (mode test). Each is reviewed and saved on the settings page, and carried out once.";
    /// PURE. The settings page with the request proposed (a fresh token, UTC time).
    public static string RequestLink(string kind) => "/Admin/Settings/Edit?name=" + RequestSetting + "&proposed=" + Uri.EscapeDataString(kind + ":" + DateTime.UtcNow.ToString("yyyyMMddHHmmss", System.Globalization.CultureInfo.InvariantCulture));

    /// #829 / #830 (owner 2026-10-20): the optional outputs Risk Analysis writes besides its own results in the database --
    /// listed here like every other writer (no hidden writer), OFF by default, changed on the Settings page like every
    /// setting: the findings per CI (SI_Finding_CL) and the report rows (SI_RiskAnalysis_Detailed_CL, with the Summary rows
    /// and the trend row). SecurityInsight itself reads neither: its pages read the database.
    public const string ReportCopySetting = "SendToLogAnalytics";
    public const string ReportCopyName = "Copy Risk Analysis report rows to Log Analytics (SI_RiskAnalysis_Detailed_CL)";
    public const string ReportCopyText = "Optional. After each Risk Analysis run, copies its report rows into your Log Analytics workspace (SI_RiskAnalysis_Detailed_CL; SI_RiskAnalysis_Summary_CL for the Summary report; the day's trend row in SI_Trend_CL), for your own workbooks, Sentinel or KQL. SecurityInsight itself does not need it: its pages read the results from its database. On a large estate the copy takes a long time and adds Log Analytics ingestion cost. Off by default.";
    public const string FindingsCopySetting = "SI_RA_Findings";
    public const string FindingsCopyName = "Copy findings per CI to Log Analytics (SI_Finding_CL)";
    public const string FindingsCopyText = "Optional. After each Risk Analysis Detailed run, copies the de-duplicated findings (one row per CI and finding) into your Log Analytics workspace, for your own workbooks, Sentinel or KQL. SecurityInsight itself does not need it: its pages read the findings from its database. On a large estate the copy can take hours and adds Log Analytics ingestion cost. Off by default.";
    public sealed record OutputView(string Name, string Title, string Text, bool On, string ValueText);
    public IReadOnlyList<OutputView> Outputs { get; private set; } = Array.Empty<OutputView>();

    public IReadOnlyList<ConnectorRow> Connectors { get; private set; } = Array.Empty<ConnectorRow>();
    public IReadOnlyDictionary<string, ConnectorRunRow> LastRun { get; private set; } = new Dictionary<string, ConnectorRunRow>();
    public bool TableMissing { get; private set; }
    /// #903: two (or more) ServiceNow data-out connectors switched on -- nothing is sent to ServiceNow until one is switched off.
    public string? DataOutProblem { get; private set; }
    public List<string> Errors { get; } = new();

    [BindProperty] public string? Name { get; set; }
    [BindProperty] public long? ReadVersion { get; set; }
    [BindProperty] public bool Enable { get; set; }
    [BindProperty] public string? Reason { get; set; }

    public async Task OnGetAsync(CancellationToken ct) => await LoadAsync(ct);

    /// A switch is ON only for an explicit true / 1 / "true" / "yes" / "on" -- the engine's rule (Test-SIFindingsCopyOn):
    /// anything else, a typo included, is OFF.
    public static bool IsOn(string? valueJson)
    {
        if (string.IsNullOrWhiteSpace(valueJson)) return false;
        var v = valueJson.Trim().Trim('"').Trim().ToLowerInvariant();
        return v is "true" or "1" or "yes" or "on";
    }

    private async Task LoadDirectWriteAsync(CancellationToken ct)
    {
        IReadOnlyList<SettingRow> rows = Array.Empty<SettingRow>();
        try { rows = (await _settings.ReadSettingsAsync(ct)).Rows; }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "settings could not be read"); }
        // the engine's rule (Test-SIFindingsCopyOn): on only for an explicit true / 1 / "on" / "yes"; not set = off
        var fc = rows.FirstOrDefault(r => r.Name == FindingsCopySetting && r.Scope == "solution") ?? rows.FirstOrDefault(r => r.Name == FindingsCopySetting);
        var fcOn = IsOn(fc?.ValueJson);
        // #830 the report rows: the value the Risk Analysis jobs read (their engine's own first, then the solution's); the
        // engine's rule (Test-SIRaReportCopyOn) -- on only for an explicit true / 1 / "on" / "yes"; not set = off
        var rc = rows.FirstOrDefault(r => r.Name == ReportCopySetting && r.Scope == "engine:risk-analysis")
                 ?? rows.FirstOrDefault(r => r.Name == ReportCopySetting && r.Scope == "solution") ?? rows.FirstOrDefault(r => r.Name == ReportCopySetting);
        var rcOn = IsOn(rc?.ValueJson);
        Outputs = new[]
        {
            new OutputView(FindingsCopySetting, FindingsCopyName, FindingsCopyText, fcOn, fcOn ? "on" : (fc is null ? "off -- the default" : "off")),
            new OutputView(ReportCopySetting, ReportCopyName, ReportCopyText, rcOn, rcOn ? "on" : (rc is null ? "off -- the default" : "off")),
        };
    }

    private async Task LoadAsync(CancellationToken ct)
    {
        await LoadDirectWriteAsync(ct);
        try
        {
            TableMissing = !await _repo.TableExistsAsync(ct);
            if (TableMissing) return;
            Connectors = await _repo.ListAsync(ct);
            var on = ServiceNowDataOut.On(Connectors);
            DataOutProblem = on.Count > 1 ? ServiceNowDataOut.TwoOnText(on) : null;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "connectors could not be read");
            Errors.Add("The connectors could not be read: " + ex.Message);
            return;
        }
        try
        {
            LastRun = (await _repo.RunsAsync(null, 200, ct)).GroupBy(r => r.ConnectorName, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "connector runs could not be read");
            Errors.Add("The last runs could not be read: " + ex.Message);
        }
    }

    /// Excel workbook of the connector list with each connector's last run. Definitions (settings, mappings, secret
    /// names) are not exported -- they are read on the connector's own page.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetXlsxAsync(CancellationToken ct)
    {
        await LoadAsync(ct);
        return await ExcelExport.FileAsync("connectors", null, (x, info) =>
        {
            info.Notes.AddRange(Errors);
            if (TableMissing) info.Notes.Add("This database has no connector table yet.");
            x.Sheet(info, "Connectors", new[] { "Name", "Kind", "Direction", "Enabled", "Mode", "Allow create", "Allow close", "Last run outcome", "Last run started", "Changed by", "Changed", "Version" },
                Connectors.Select(c =>
                {
                    LastRun.TryGetValue(c.Name, out var run);
                    return new object?[] { c.Name, c.Kind, c.Direction, c.Enabled, c.Mode, c.AllowCreate, c.AllowClose, run?.Outcome ?? "never", run?.StartedAt, c.UpdatedBy, c.UpdatedAt, c.Version };
                }));
            return Task.CompletedTask;
        }, ct);
    }

    /// Stage "enable" or "disable" for one connector -- the rest of its definition unchanged.
    [SI.Management.Web.Audit.Audited("connector.state.stage")]
    public async Task<IActionResult> OnPostToggleAsync(CancellationToken ct)
    {
        var cur = string.IsNullOrWhiteSpace(Name) ? null : await _repo.ReadAsync(Name.Trim(), ct);
        if (cur is null) { Errors.Add($"The connector '{Name}' does not exist."); await LoadAsync(ct); return Page(); }
        if (cur.Version != ReadVersion) { Errors.Add($"The connector {cur.Name} changed since the page was opened. Reload and try again."); await LoadAsync(ct); return Page(); }
        var w = ConnectorRepository.FromRow(cur, "Set", string.IsNullOrWhiteSpace(Reason) ? (Enable ? "enabled" : "disabled") + " on the Connectors page" : Reason) with { Enabled = Enable };
        // #903: the ServiceNow data-out connector -- always apply, only one on at a time; switched on, it feeds both ServiceNow outputs
        var dataOut = ServiceNowDataOut.Is(cur);
        if (dataOut) w = ConnectorRepository.AlwaysOn(w);
        if (dataOut && Enable && ServiceNowDataOut.Conflict(w, await _repo.ListAsync(ct)) is { } conflict) { Errors.Add($"{cur.Name}: {conflict}"); await LoadAsync(ct); return Page(); }
        var (c, why) = dataOut && Enable
            ? ChangeService.NewConnector(w, $"Switch on the ServiceNow data-out connector {cur.Name} and send both ServiceNow outputs", ServiceNowDataOut.Outputs)
            : ChangeService.NewConnector(w, $"{(Enable ? "Enable" : "Disable")} the connector {cur.Name}");
        if (c is null) { Errors.AddRange(why.Select(p => $"{cur.Name}: {p}")); await LoadAsync(ct); return Page(); }
        await _changes.StageAsync(User, c, ct);
        TempData["toast"] = "Staged: " + c.Title + ". Nothing is written until you review and commit.";
        return Redirect("/Changes");
    }

    public static string VersionText(long v) => v.ToString(CultureInfo.InvariantCulture);
}
