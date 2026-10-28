using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Core.ProData;
using SI.Management.Web.Auth;
using SI.Management.Web.Changes;
using SI.Management.Web.Outputs;
using WriteStatus = SI.Management.Web.Settings.WriteStatus;

namespace SI.Management.Web.Pages.Reports;

/// <summary>
/// Configuration &gt; Reports &gt; Output fields (V3-DATA-MODEL 2.12, REQUIREMENTS #467): per output -- the CI
/// and findings workbooks, the ServiceNow hand-offs -- which columns it sends, from which SI field, under which name, and
/// whether a column is shipped, changed, removed, your own, or changed by you while the shipped column changed since
/// (UpgradeAvailable: compare on Template conformance). Readers see it; an Admin stages a change (change, remove, put back,
/// add) for Review &amp; commit. Every output is a listed connector: its runs are on Configuration &gt; Connectors &gt; Runs.
/// </summary>
/// Owner 2026-10-19 ("one for reports and one for connectors"): the same store, split in the VIEW by the output's kind --
/// the workbooks (Excel) on Configuration > Reports > Workbook fields, every connector output (the ServiceNow hand-offs ...)
/// on Configuration > Connectors > Fields sent (<see cref="SI.Management.Web.Pages.Connectors.FieldsModel"/>).
public class OutputFieldsModel : PageModel
{
    /// "workbook" (the Excel outputs) or "connector" (every other output).
    public virtual string Area => WorkbookArea;
    public const string WorkbookArea = "workbook";
    public const string ConnectorArea = "connector";
    /// This page's address.
    public virtual string PagePath => "/Reports/OutputFields";

    /// The area an output belongs to.
    public static string AreaOf(DataOutEntry e) => e.Kind == "excel" ? WorkbookArea : ConnectorArea;

    private readonly OutputMapStore _store;
    private readonly OutputMapChanges _changes;
    private readonly ChangeService _staging;
    private readonly ILogger _log;
    public OutputFieldsModel(OutputMapStore store, OutputMapChanges changes, ChangeService staging, ILogger<OutputFieldsModel> log) : this(store, changes, staging, (ILogger)log) { }
    protected OutputFieldsModel(OutputMapStore store, OutputMapChanges changes, ChangeService staging, ILogger log) { _store = store; _changes = changes; _staging = staging; _log = log; }

    [BindProperty(SupportsGet = true)] public string? Output { get; set; }
    /// "1" = show the 10-row preview of the columns in force (everyone who can open the page).
    [BindProperty(SupportsGet = true)] public string? Preview { get; set; }

    public IReadOnlyList<OutputMapView> Maps { get; private set; } = Array.Empty<OutputMapView>();
    public OutputMapView? Selected { get; private set; }
    /// The outputs of this area.
    public IReadOnlyList<DataOutEntry> Catalog => OutputMapRules.Catalog.Where(e => AreaOf(e) == Area).ToList();
    public bool CanEdit => User.IsAdmin();
    public string? Error { get; private set; }

    /// The fields a column may read, sorted (the datalist of the form).
    public static IReadOnlyList<string> FieldChoices { get; } = OutputMapRules.Fields.OrderBy(f => f, StringComparer.Ordinal).ToList();

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        // an output of the other area (an old link: every output was on one page) opens where it is now
        if (OutputMapRules.Catalog.FirstOrDefault(e => e.Output == Output) is { } asked && AreaOf(asked) != Area)
            return Redirect((AreaOf(asked) == WorkbookArea ? "/Reports/OutputFields" : "/Connectors/Fields") + "?output=" + Uri.EscapeDataString(asked.Output));
        await LoadMapsAsync(ct);
        await LoadOutputStateAsync(ct);
        if (Area == ConnectorArea) await CountServiceNowAsync(ct);
        if (Preview == "1" && Selected is not null)
            await PreviewAsync(Selected.Columns.Where(c => !c.Removed).Select(c => c.InForce).ToList(), ct);
        return Page();
    }

    // ---- the ServiceNow outputs' rows (owner 2026-10-20: "count of rows that will be send with current filter and rows in
    //      excel format and csv fomat" -- "so servicenow can test") -------------------------------------------------------

    /// Per ServiceNow output: "N rows would be sent" with the filter it applies, from stored data.
    public Dictionary<string, string> SnowCounts { get; } = new(StringComparer.Ordinal);

    private async Task CountServiceNowAsync(CancellationToken ct)
    {
        foreach (var e in Catalog.Where(e => ServiceNowOutputs.Of(e.Output) is not null))
        {
            try
            {
                if (e.Output == "servicenow-ci")
                {
                    var filter = MapFilter(e.Output);
                    var (n, total) = await HttpContext.RequestServices.GetRequiredService<ServiceNowRowCount>().CiAsync(filter, ct);
                    SnowCounts[e.Output] = (n is { } x ? Fmt.Int(x) + " of " + Fmt.Int(total) + " CI row(s) would be sent" : "the export counts the rows (the output's filter names more than the CI's class)")
                        + " -- the output's filter: " + FilterWords(filter);
                }
                else
                {
                    var (scope, resolved) = await ScopeOfAsync(e, ct);
                    var store = HttpContext.RequestServices.GetService<SI.Management.Web.Reports.IReportStore>();
                    var c = scope is null || store is null ? null : await store.ScopeCountAsync(scope, resolved, ct);
                    SnowCounts[e.Output] = (c is null ? "not counted yet (no published run)" : Fmt.Int(c.Findings) + " row(s) would be sent (of " + Fmt.Int(c.TotalFindings) + " findings)")
                        + " -- the scope in force: " + (scope?.Describe() ?? "everything (no scope)");
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the rows of {Output} could not be counted", e.Output); SnowCounts[e.Output] = "the rows could not be counted: " + ex.Message; }
        }
    }

    private System.Text.Json.Nodes.JsonObject? MapFilter(string output)
    {
        try { return Maps.FirstOrDefault(m => m.Entry.Output == output)?.FilterJson is { } fj ? System.Text.Json.Nodes.JsonNode.Parse(fj) as System.Text.Json.Nodes.JsonObject : null; }
        catch (System.Text.Json.JsonException) { return null; }
    }

    /// PURE. An output's filter in words ("si_class device, cloud_resource" -- none = every row).
    public static string FilterWords(System.Text.Json.Nodes.JsonObject? filter) =>
        filter is null || filter.Count == 0 ? "none (every row)"
            : string.Join("; ", filter.Select(kv => kv.Key + " " + (kv.Value is System.Text.Json.Nodes.JsonArray a ? string.Join(", ", a.Select(x => OutputMapper.Text(x))) : OutputMapper.Text(kv.Value))));

    /// EVERY ROW a ServiceNow output would send (Excel or CSV), the values as sent -- a read, audited as an export.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetExportAsync(string? format, CancellationToken ct)
    {
        var e = OutputMapRules.Catalog.FirstOrDefault(x => x.Output == Output);
        if (e is null || ServiceNowOutputs.Of(e.Output) is null || AreaOf(e) != Area) return NotFound("not a ServiceNow output");
        await LoadMapsAsync(ct);
        var (scope, resolved) = await ScopeOfAsync(e, ct);
        var words = e.Output == "servicenow-ci" ? "the output's filter: " + FilterWords(MapFilter(e.Output)) : "the scope in force: " + (scope?.Describe() ?? "everything (no scope)");
        var file = await HttpContext.RequestServices.GetRequiredService<ScopeExport>().WriteServiceNowAsync(e, scope, resolved, words, "", format == "csv", ct);
        if (SI.Management.Web.Audit.AuditScope.Current is { } a) a.Reason = words + "; " + file.Rows.ToString(System.Globalization.CultureInfo.InvariantCulture) + " row(s)";
        return File(file.Stream, file.ContentType, file.Name);
    }

    // ---- which outputs run: a real switch per output (owner 2026-10-20: "how and where do i turn on this connector") -------

    public const string OutputsSetting = "SI_DataOut_Outputs";
    /// The outputs that run now (SI_DataOut_Outputs, else each output's default) -- null = the setting could not be read.
    public IReadOnlySet<string>? On { get; private set; }
    /// A ServiceNow output's Import Set table (its setting's value; empty = not set).
    public Dictionary<string, string?> Tables { get; } = new(StringComparer.Ordinal);
    /// Per ServiceNow output: whether exactly one ServiceNow data-out connector is switched on to send it (#903, Connectors > Setup).
    public Dictionary<string, bool> HasConnector { get; } = new(StringComparer.Ordinal);
    /// #903: two (or more) ServiceNow data-out connectors switched on -- nothing is sent until one is switched off (null = fine).
    public string? DataOutProblem { get; private set; }
    private string? _outputsText;
    private long? _outputsVersion;
    private string? _outputsScope;

    /// The direction of the ServiceNow connector an output needs (#903: both ServiceNow outputs, the one data-out connector).
    public static string? DirectionOf(DataOutEntry e) => e.Output is "servicenow-vulnerable-item" or "servicenow-ci" ? ServiceNowDataOut.Direction : null;

    /// PURE -- the engine's Get-SIDataOutEnabled (engine\data-out\SI-DataOut.ps1): the setting's list (ids, comma / semicolon
    /// separated) when it names any, else every output's default; never a 'fixed' output.
    public static IReadOnlySet<string> OnOutputs(IReadOnlyList<DataOutEntry> catalog, string? setting)
    {
        var chosen = (setting ?? "").Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(s => s.ToLowerInvariant()).ToList();
        return catalog.Where(e => e.Kind != "fixed" && (chosen.Count > 0 ? chosen.Contains(e.Output) : e.Default)).Select(e => e.Output).ToHashSet(StringComparer.Ordinal);
    }

    /// PURE -- the setting's value after one output is switched: every other output keeps what it does now; a set that
    /// is exactly the defaults = null (the setting is reset, so an output a later release adds follows its own default).
    public static string? Switched(IReadOnlyList<DataOutEntry> catalog, string? setting, string output, bool on)
    {
        var set = OnOutputs(catalog, setting).ToHashSet(StringComparer.Ordinal);
        if (on) set.Add(output); else set.Remove(output);
        if (set.SetEquals(OnOutputs(catalog, null))) return null;
        return string.Join(";", catalog.Where(e => set.Contains(e.Output)).Select(e => e.Output));
    }

    private async Task LoadOutputStateAsync(CancellationToken ct)
    {
        var reader = HttpContext?.RequestServices.GetService<SI.Management.Web.Settings.ISettingsStoreReader>();
        if (reader is not null)
        {
            try
            {
                var (rows, _) = await reader.ReadSettingsAsync(ct);
                var row = rows.Where(r => r.Name.Equals(OutputsSetting, StringComparison.OrdinalIgnoreCase)).OrderBy(r => r.Scope == "global" ? 0 : 1).FirstOrDefault();
                _outputsText = row is null ? null : SI.Management.Web.Settings.SettingJson.ToFormText(row.ValueJson);
                (_outputsVersion, _outputsScope) = (row?.Version, row?.Scope);
                On = OnOutputs(OutputMapRules.Catalog, _outputsText);
                foreach (var e in OutputMapRules.Catalog.Where(e => e.TableSetting is not null))
                {
                    var t = rows.FirstOrDefault(r => r.Name.Equals(e.TableSetting, StringComparison.OrdinalIgnoreCase));
                    Tables[e.Output] = t is null ? null : SI.Management.Web.Settings.SettingJson.ToFormText(t.ValueJson) is { Length: > 0 } v ? v : null;
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the outputs setting could not be read"); On = null; }
        }
        if (HttpContext?.RequestServices.GetService<ConnectorRepository>() is { } repo)
        {
            try
            {
                var list = await repo.TableExistsAsync(ct) ? await repo.ListAsync(ct) : Array.Empty<ConnectorRow>();
                var on = ServiceNowDataOut.On(list);
                DataOutProblem = on.Count > 1 ? ServiceNowDataOut.TwoOnText(on) : null;
                foreach (var e in OutputMapRules.Catalog.Where(e => DirectionOf(e) is not null))
                    HasConnector[e.Output] = on.Count == 1;
            }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the connectors could not be read"); }
        }
    }

    [BindProperty] public string? SwitchOutput { get; set; }
    [BindProperty] public bool SwitchOn { get; set; }

    /// One output switched on or off: SI_DataOut_Outputs written with its reason (the settings writer: version-checked,
    /// cfg.ChangeLog), every other output kept as it runs now.
    [SI.Management.Web.Audit.Audited("settings.value.save")]
    public async Task<IActionResult> OnPostSwitchAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        var e = OutputMapRules.Catalog.FirstOrDefault(x => x.Output == SwitchOutput);
        string message; var ok = false;
        if (e is null || e.Kind == "fixed") message = "Not changed: that output cannot be switched here.";
        else if (string.IsNullOrWhiteSpace(Reason) || Reason.Trim().Length < 3) message = "Not changed: give a reason (at least 3 characters).";
        else
        {
            await LoadOutputStateAsync(ct);
            var catalog = HttpContext.RequestServices.GetRequiredService<SI.Management.Web.Settings.SettingsCatalog>();
            var writer = HttpContext.RequestServices.GetRequiredService<SI.Management.Web.Settings.SettingsWriter>();
            var setting = catalog.Find(OutputsSetting);
            if (setting is null) message = "Not changed: this install's settings catalog has no " + OutputsSetting + ".";
            else
            {
                var value = Switched(OutputMapRules.Catalog, _outputsText, e.Output, SwitchOn);
                var scope = _outputsScope ?? setting.DefaultScope;
                var w = value is null
                    ? new SI.Management.Web.Settings.SettingWrite(setting.Name, scope, "Reset", null, null, _outputsVersion, Reason.Trim())
                    : new SI.Management.Web.Settings.SettingWrite(setting.Name, scope, "Set", SI.Management.Web.Settings.SettingJson.FromForm(setting, value), null, _outputsVersion, Reason.Trim());
                if (value is null && _outputsVersion is null) { ok = true; message = $"{e.Label} is {(SwitchOn ? "on" : "off")} already."; }
                else
                {
                    var r = await writer.WriteAsync(w, User.ChangeName(), ct);
                    ok = r.Status == WriteStatus.Saved;
                    message = ok ? $"{e.Label} is switched {(SwitchOn ? "on" : "off")} ({OutputsSetting} {(value is null ? "back to the defaults" : "= " + value)}). It applies from the next run."
                        : r.Status == WriteStatus.Stale ? "Not changed: someone changed the outputs since this page was opened -- open it again." : "Not changed: " + r.Message;
                }
            }
        }
        TempData["toast"] = message;
        TempData["toastKind"] = ok ? "ok" : "error";
        return RedirectToPage(new { output = Output });
    }

    /// The ServiceNow team pack of a ServiceNow output (Excel): the target, the schema and real sample rows -- no secret.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetTeamPackAsync(CancellationToken ct)
    {
        var e = OutputMapRules.Catalog.FirstOrDefault(x => x.Output == Output);
        if (e is null || ServiceNowTeamPack.TargetOf(e.Output) is null) return NotFound("not a ServiceNow output");
        await LoadOutputStateAsync(ct);
        var (scope, resolved) = await ScopeOfAsync(e, ct);
        var file = await HttpContext.RequestServices.GetRequiredService<ServiceNowTeamPack>().WriteAsync(e, Tables.GetValueOrDefault(e.Output), scope, resolved, ct);
        return File(file.Stream, file.ContentType, file.Name);
    }

    /// The ServiceNow schema of a ServiceNow output (JSON, REQUIREMENTS #840): every column in force with its type and the
    /// length to create, built on every click -- no sample value, no secret.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetSchemaAsync(CancellationToken ct)
    {
        var e = OutputMapRules.Catalog.FirstOrDefault(x => x.Output == Output);
        if (e is null || ServiceNowTeamPack.TargetOf(e.Output) is null) return NotFound("not a ServiceNow output");
        await LoadOutputStateAsync(ct);
        var (scope, resolved) = await ScopeOfAsync(e, ct);
        var json = await HttpContext.RequestServices.GetRequiredService<ServiceNowTeamPack>().SchemaAsync(e, Tables.GetValueOrDefault(e.Output), scope, resolved, AppInfo.Version, ct);
        var bytes = System.Text.Encoding.UTF8.GetBytes(json.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
        return File(bytes, "application/json", "SecurityInsight_" + e.Output + "_servicenow-schema_" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm", System.Globalization.CultureInfo.InvariantCulture) + ".json");
    }

    /// The vulnerability connector's scope for the vulnerable items' sample rows (null for the CI hand-off, or when unread).
    private async Task<(OutputScope? Scope, IReadOnlySet<string>? Resolved)> ScopeOfAsync(DataOutEntry e, CancellationToken ct)
    {
        if (e.Output != "servicenow-vulnerable-item" || HttpContext.RequestServices.GetService<SI.Management.Web.Reports.IReportStore>() is not { } store) return (null, null);
        try
        {
            if (!await store.SchemaAsync(ct)) return (null, null);
            var st = await store.LoadAsync(ct);
            var scope = st.ScopeOf("vuln-servicenow");
            return (scope, scope.Resolved(st.Membership()));
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the connector scope could not be read; the sample rows are not scoped"); return (null, null); }
    }

    private async Task LoadMapsAsync(CancellationToken ct)
    {
        try
        {
            Maps = (await _store.LoadAsync(ct)).Where(m => AreaOf(m.Entry) == Area).ToList();
            Selected = Maps.FirstOrDefault(m => m.Entry.Output == Output) ?? Maps.FirstOrDefault();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "the output maps could not be read");
            Error = "The output maps could not be read from the Pro database: " + ex.Message;
        }
    }

    // ---- the column builder and its preview (owner 2026-10-19) --------------------------------------------------------

    /// The 10-row preview shown (null = none asked).
    public OutputPreviewResult? PreviewResult { get; private set; }
    /// The builder as posted (a preview of a builder shows it as it was sent); null = the map in force.
    public IReadOnlyList<BuilderColumn>? Posted { get; private set; }
    public IReadOnlyList<BuilderAdd> PostedAdds { get; private set; } = Array.Empty<BuilderAdd>();
    /// What is wrong with the builder's post.
    public IReadOnlyList<string> BuilderProblems { get; private set; } = Array.Empty<string>();

    /// How many new columns one builder post can add.
    public const int AddRows = 3;

    [BindProperty] public List<string> BTarget { get; set; } = new();
    [BindProperty] public List<string> BSend { get; set; } = new();
    [BindProperty] public List<string?> BName { get; set; } = new();
    [BindProperty] public List<string?> BPlace { get; set; } = new();
    [BindProperty] public List<string?> ATarget { get; set; } = new();
    [BindProperty] public List<string?> AFrom { get; set; } = new();
    [BindProperty] public List<string?> AName { get; set; } = new();

    /// The builder's rows: the columns in the order sent, then the ones not sent -- from the post, else the map in force.
    public IReadOnlyList<(OutputColumnRow Row, bool Send, string? Name, int Place)> BuilderRows()
    {
        if (Selected is null) return Array.Empty<(OutputColumnRow, bool, string?, int)>();
        var byTarget = Selected.Columns.ToDictionary(c => c.InForce.Target, StringComparer.Ordinal);
        if (Posted is not null)
            return Posted.Where(p => byTarget.ContainsKey(p.Target)).Select((p, i) => (byTarget[p.Target], p.Send, p.Name, p.Place ?? i + 1)).ToList();
        return Selected.Columns.Select((c, i) => (c, !c.Removed, c.InForce.As, i + 1)).ToList();
    }

    private (IReadOnlyList<BuilderColumn> Columns, IReadOnlyList<BuilderAdd> Adds) ReadBuilder()
    {
        var send = BSend.ToHashSet(StringComparer.Ordinal);
        var cols = BTarget.Select((t, i) => new BuilderColumn(t, send.Contains(t), i < BName.Count ? BName[i] : null,
            i < BPlace.Count && int.TryParse(BPlace[i], System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var p) ? p : null)).ToList();
        var adds = Enumerable.Range(0, Math.Min(AddRows, Math.Max(ATarget.Count, AFrom.Count)))
            .Select(i => new BuilderAdd(i < ATarget.Count ? ATarget[i] ?? "" : "", i < AFrom.Count ? AFrom[i] ?? "" : "", i < AName.Count ? AName[i] : null)).ToList();
        return (cols, adds);
    }

    private async Task PreviewAsync(IReadOnlyList<OutputColumn> columns, CancellationToken ct)
    {
        if (Selected is null) return;
        var preview = HttpContext.RequestServices.GetRequiredService<OutputRowPreview>();
        System.Text.Json.Nodes.JsonObject? filter = null;
        try { if (Selected.FilterJson is { } fj) filter = System.Text.Json.Nodes.JsonNode.Parse(fj) as System.Text.Json.Nodes.JsonObject; } catch (System.Text.Json.JsonException) { filter = null; }
        try { PreviewResult = await preview.ReadAsync(Selected.Grain, columns, filter, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "the output preview could not be read");
            PreviewResult = new OutputPreviewResult(columns.Select(c => c.Name).ToList(), Array.Empty<IReadOnlyList<string>>(), "The preview could not be read from the Pro database: " + ex.Message);
        }
    }

    /// The 10-row preview of the builder as posted -- nothing is staged.
    [SI.Management.Web.Audit.NotAudited("a preview: reads ten rows of the output with the columns the builder shows, changes nothing")]
    public async Task<IActionResult> OnPostPreviewAsync(CancellationToken ct)
    {
        // a read (every reader may preview); the builder itself, and staging, are an Admin's
        await LoadMapsAsync(ct);
        await LoadOutputStateAsync(ct);
        if (Selected is null) return Page();
        var (cols, adds) = ReadBuilder();
        (Posted, PostedAdds) = (cols, adds);
        var plan = OutputColumnBuilder.Plan(Selected, cols, adds);
        BuilderProblems = plan.Problems;
        await PreviewAsync(plan.Sent, ct);
        return Page();
    }

    /// The builder's changes, one staged change per column changed, for Review &amp; commit.
    [SI.Management.Web.Audit.Audited("outputmap.column.stage")]
    public async Task<IActionResult> OnPostBuildAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        await LoadMapsAsync(ct);
        if (Selected is null) return RedirectToPage(new { output = Output });
        var (cols, adds) = ReadBuilder();
        var plan = OutputColumnBuilder.Plan(Selected, cols, adds);
        var problems = plan.Problems.ToList();
        if (string.IsNullOrWhiteSpace(Reason) || Reason.Trim().Length < 3) problems.Add("give a reason (at least 3 characters)");
        if (plan.Steps.Count == 0 && problems.Count == 0) problems.Add("nothing changed");
        if (problems.Count > 0)
        {
            (Posted, PostedAdds, BuilderProblems) = (cols, adds, problems);
            return Page();
        }
        var access = HttpContext.RequestServices.GetRequiredService<IAccessScope>();
        var staged = new List<string>();
        var refused = new List<string>();
        foreach (var s in plan.Steps)
        {
            (StagedChange? change, IReadOnlyList<string> why) r;
            try { r = await _changes.NewAsync(Selected.Entry.Output, s.Action, s.Target, s.From, null, s.Name, Reason, ct, s.Position, s.SetPosition); }
            catch (ArgumentException ex) { r = (null, new[] { ex.Message }); }
            if (r.change is null) { refused.Add(s.Target + ": " + string.Join("; ", r.why)); continue; }
            var gate = ChangeAccess.Check(access, User, r.change);
            if (!gate.Allowed) return AccessResults.Refused(Request, gate);
            await _staging.StageAsync(User, r.change, ct);
            staged.Add(r.change.Title);
        }
        TempData["toast"] = (staged.Count > 0 ? "Staged " + Fmt.Int(staged.Count) + " change(s) of the " + Selected.Entry.Label + ". Nothing is written until you review and commit them on " + SI.Management.Web.Navigation.NavModel.PathOf("/Changes/Index") + "." : "")
            + (refused.Count > 0 ? " Not staged: " + string.Join("; ", refused) + "." : "");
        TempData["toastKind"] = refused.Count > 0 ? "error" : "ok";
        return RedirectToPage(new { output = Output });
    }

    /// The plain words of a column's state.
    public static string StateText(OutputColumnRow c) => c.State switch
    {
        _ when c.Removed && c.State != TemplateConformance.UpgradeAvailable => "removed by you",
        TemplateConformance.UpToDate => "shipped",
        TemplateConformance.Overridden => "changed by you",
        TemplateConformance.Disabled => "removed by you",
        TemplateConformance.UpgradeAvailable => "changed by you -- the shipped column changed since",
        TemplateConformance.Own => "your own",
        TemplateConformance.Retired => "no longer shipped",
        _ => c.State,
    };

    public static string StateBadge(OutputColumnRow c) => c.State switch
    {
        TemplateConformance.UpgradeAvailable => "danger",
        TemplateConformance.Overridden or TemplateConformance.Disabled or TemplateConformance.Own => "warn",
        _ => "",
    };

    // ---- staging (Admin) ------------------------------------------------------------------------------------------
    [BindProperty] public string? Action { get; set; }
    [BindProperty] public string? Target { get; set; }
    [BindProperty] public string? From { get; set; }
    [BindProperty] public string? Op { get; set; }
    [BindProperty] public string? Name { get; set; }
    [BindProperty] public string? Reason { get; set; }

    [SI.Management.Web.Audit.Audited("outputmap.column.stage")]
    public async Task<IActionResult> OnPostStageAsync(CancellationToken ct)
    {
        if (!User.IsAdmin()) return Forbid();
        (StagedChange? change, IReadOnlyList<string> why) r;
        try { r = await _changes.NewAsync(Output ?? "", Action ?? "", Target ?? "", From, Op, Name, Reason, ct); }
        catch (ArgumentException ex) { r = (null, new[] { ex.Message }); }
        string message;
        if (r.change is not null)
        {
            var gate = ChangeAccess.Check(HttpContext.RequestServices.GetRequiredService<IAccessScope>(), User, r.change);
            if (!gate.Allowed) return AccessResults.Refused(Request, gate);
            await _staging.StageAsync(User, r.change, ct);
            message = "Staged: " + r.change.Title + ". Nothing is written until you review and commit it on " + SI.Management.Web.Navigation.NavModel.PathOf("/Changes/Index") + ".";
        }
        else message = "Not staged: " + string.Join("; ", r.why);
        TempData["toast"] = message;
        TempData["toastKind"] = r.change is null ? "error" : "ok";
        return RedirectToPage(new { output = Output });
    }
}
