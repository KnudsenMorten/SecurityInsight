using SI.Management.Web.Auth;
using System.Globalization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SI.Management.Web.Changes;

namespace SI.Management.Web.Pages.Admin.ConnectorSetup;

/// One connector: its definition, checked on "Check" by the close-loop's own rules (JSON, secret NAMES only, the mapping),
/// and STAGED (set or remove) for Review &amp; commit. The version read when the page opened travels with the change, so a
/// connector that moved since is refused.
public sealed class EditModel : PageModel
{
    private readonly ConnectorRepository _repo;
    private readonly ChangeService _changes;
    private readonly ILogger<EditModel> _log;
    private readonly SI.Management.Web.Cmdb.IServiceNowPreview _preview;
    public EditModel(ConnectorRepository repo, ChangeService changes, ILogger<EditModel> log, SI.Management.Web.Cmdb.IServiceNowPreview preview)
    { _repo = repo; _changes = changes; _log = log; _preview = preview; }

    /// "Preview with your data" was asked for (?preview=1): the first rows of this install's own hand-off views.
    [BindProperty(SupportsGet = true)] public bool Preview { get; set; }
    public IReadOnlyList<SI.Management.Web.Cmdb.SnowPreviewView>? PreviewViews { get; private set; }
    public string? PreviewProblem { get; private set; }
    /// How many rows the preview shows per view.
    public const int PreviewRows = 5;

    /// The sample data for the customer's ServiceNow team is shown for the connectors that hand data to ServiceNow: a
    /// servicenow connector, and a sql connector (its database is what a JDBC data source reads).
    public bool ShowServiceNowSamples => (Kind ?? "").Trim().ToLowerInvariant() is "servicenow" or "sql";
    public static SI.Management.Web.Cmdb.SnowPack Samples => SI.Management.Web.Cmdb.ServiceNowTestPack.Pack;

    [BindProperty(SupportsGet = true)] public string? Name { get; set; }
    [BindProperty(SupportsGet = true)] public string? Kind { get; set; }
    [BindProperty] public string Direction { get; set; } = "vulnerability";
    [BindProperty] public bool Enabled { get; set; }
    [BindProperty] public string Mode { get; set; } = "whatif";
    [BindProperty] public bool AllowCreate { get; set; }
    [BindProperty] public bool AllowClose { get; set; }
    [BindProperty] public string? SettingsJson { get; set; }
    [BindProperty] public string? SecretRefsJson { get; set; }
    [BindProperty] public string? MappingJson { get; set; }
    [BindProperty] public string? Reason { get; set; }
    [BindProperty] public long? ReadVersion { get; set; }

    public ConnectorRow? Current { get; private set; }
    public IReadOnlyList<ConnectorRunRow> Runs { get; private set; } = Array.Empty<ConnectorRunRow>();
    public IReadOnlyList<string> Problems { get; private set; } = Array.Empty<string>();
    public bool Checked { get; private set; }
    public string? NameProblem { get; private set; }

    public string VersionText => ReadVersion?.ToString(CultureInfo.InvariantCulture) ?? "";

    private async Task<bool> LoadAsync(CancellationToken ct)
    {
        Name = Name?.Trim();
        if (!ConnectorRepository.NamePattern().IsMatch(Name ?? "")) { NameProblem = $"'{Name}' is not a connector name: 2-63 lower-case letters, digits and dashes"; return false; }
        Current = await _repo.ReadAsync(Name!, ct);
        try { Runs = await _repo.RunsAsync(Name, 15, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "connector runs could not be read"); }
        return true;
    }

    public async Task<IActionResult> OnGetAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        if (Current is { } c)
        {
            Kind = c.Kind; Direction = c.Direction; Enabled = c.Enabled; Mode = c.Mode; AllowCreate = c.AllowCreate; AllowClose = c.AllowClose;
            SettingsJson = c.SettingsJson; SecretRefsJson = c.SecretRefsJson; MappingJson = c.MappingJson; ReadVersion = c.Version;
        }
        else
        {
            Kind = ConnectorRepository.Kinds.Contains(Kind ?? "") ? Kind : "rest";
            (SettingsJson, SecretRefsJson, MappingJson) = Template(Kind!);
            Mode = "whatif"; Enabled = false; AllowCreate = true; AllowClose = false;
        }
        if (Preview && ShowServiceNowSamples && User.IsAdmin())
        {
            try { PreviewViews = await _preview.ReadAsync(PreviewRows, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _log.LogWarning(ex, "the ServiceNow hand-off preview could not be read");
                PreviewProblem = "Your hand-off data could not be read right now. The sample data below is not affected.";
            }
        }
        await LoadServiceNowGuideAsync(ct);
        return Page();
    }

    // ---- THE SERVICENOW GUIDE (owner 2026-10-20: "i connect to servicenow + verify connection. verify table schema matches
    //      + get alerts + set api key in keyvault + url to instance and what is needed"; "count of rows that will be send with
    //      current filter and rows in excel format and csv fomat"). One place per ServiceNow connector: what is needed, the
    //      instance URL, the API key (Set value), Verify, the newest check with the schema comparison, and the rows. ----------

    /// A ServiceNow connector: the guide shows its instance and how it signs in (any direction).
    public bool IsSnow => (Kind ?? "").Trim().Equals("servicenow", StringComparison.OrdinalIgnoreCase);
    /// #903: the ServiceNow data-out connector -- it feeds BOTH ServiceNow outputs (one switched on at a time).
    public bool IsDataOut => ServiceNowDataOut.Is(Kind, Direction);
    /// The ServiceNow outputs this connector feeds: both for the data-out connector, none for any other.
    public IReadOnlyList<SI.Management.Web.Outputs.ServiceNowOutputs.Info> SnowInfos =>
        IsSnow ? SI.Management.Web.Outputs.ServiceNowOutputs.OfDirection(Direction) : Array.Empty<SI.Management.Web.Outputs.ServiceNowOutputs.Info>();

    /// One output as the page shows it: its table, whether it runs, its newest check, its checklist, its schema, its rows.
    public sealed class SnowOutputView
    {
        public required SI.Management.Web.Outputs.ServiceNowOutputs.Info Info { get; init; }
        public string? Table { get; set; }
        public bool On { get; set; }
        public SI.Management.Web.Outputs.SnowCheckRow? Latest { get; set; }
        public IReadOnlyList<SI.Management.Web.Outputs.ChecklistItem> Checklist { get; set; } = Array.Empty<SI.Management.Web.Outputs.ChecklistItem>();
        public IReadOnlyList<SI.Management.Web.Outputs.SchemaLine> Schema { get; set; } = Array.Empty<SI.Management.Web.Outputs.SchemaLine>();
        public string? SchemaProblem { get; set; }
        public string? Count { get; set; }
    }
    public List<SnowOutputView> SnowOutputs { get; } = new();
    /// The connector's own items of "What is needed" (instance, how it signs in, roles).
    public IReadOnlyList<SI.Management.Web.Outputs.ChecklistItem> SnowConnectorChecklist { get; private set; } = Array.Empty<SI.Management.Web.Outputs.ChecklistItem>();
    /// The newest check of any of its outputs (the connection is the connector's).
    public SI.Management.Web.Outputs.SnowCheckRow? SnowLatest { get; private set; }
    /// The connector's secret references a SuperAdmin may set here (reference -> Key Vault secret name).
    public IReadOnlyList<(string Ref, string Secret)> SnowSecrets { get; private set; } = Array.Empty<(string, string)>();
    /// How it signs in now: apikey | user-password | none, and a wrong combination in plain words.
    public string SnowCredentialWay { get; private set; } = SI.Management.Web.Outputs.ServiceNowCredential.None;
    public string? SnowCredentialProblem { get; private set; }
    public (string ApiKey, string User, string Password) SnowDefaultNames => SI.Management.Web.Outputs.ServiceNowCredential.DefaultNames(Name ?? "");
    /// Other ServiceNow connectors that name the same credential secret (a Test and a Prod sharing a key, almost always a mistake).
    public IReadOnlyList<string> SnowSharedWith { get; private set; } = Array.Empty<string>();
    /// #903: the data-out connectors switched on; two or more = the problem in words (nothing is sent).
    public IReadOnlyList<string> DataOutOn { get; private set; } = Array.Empty<string>();
    public string? DataOutProblem { get; private set; }
    /// "For your ServiceNow team" (data-out only): the lines and the text Copy / the download hand over -- never a secret.
    public IReadOnlyList<SI.Management.Web.Outputs.ServiceNowTeamBrief.Line> TeamBrief { get; private set; } = Array.Empty<SI.Management.Web.Outputs.ServiceNowTeamBrief.Line>();
    public string TeamBriefText { get; private set; } = "";
    /// #912: the staging status table in force ('' = none set: the rows go without a batch, with a warning) and the three tables
    /// the ServiceNow team creates, each with every column -- shown in "For your ServiceNow team", in its text and its downloads.
    public string StagingStatusTable { get; private set; } = SI.Management.Web.Outputs.ServiceNowStagingStatus.DefaultTable;
    public List<SI.Management.Web.Outputs.ServiceNowTeamBrief.TableDef> TeamTables { get; } = new();
    /// A setting with a table key in this connector's settings that nothing reads (the table is the setting).
    public IReadOnlyList<string> SnowUnreadKeys { get; private set; } = Array.Empty<string>();
    [BindProperty] public string? InstanceUrl { get; set; }
    public string? InstanceProblem { get; private set; }
    public string? CredentialProblem { get; private set; }
    public string? SwitchProblem { get; private set; }

    private T? Svc<T>() where T : class => HttpContext?.RequestServices.GetService<T>();

    private async Task LoadServiceNowGuideAsync(CancellationToken ct)
    {
        if (!IsSnow) return;
        var refsJson = Current?.SecretRefsJson ?? SecretRefsJson;
        var refs = Obj(refsJson);
        SnowSecrets = refs.Where(p => p.Value is System.Text.Json.Nodes.JsonValue v && v.TryGetValue<string>(out _)
                && SI.Management.Web.Settings.SecretAllowList.ConnectorRefs.Contains(p.Key) && p.Key != "instance" && Current is not null)
            .Select(p => (p.Key, p.Value!.GetValue<string>())).OrderBy(p => p.Key == "apikey" ? 0 : p.Key == "user" ? 1 : 2).ToList();
        SnowCredentialWay = SI.Management.Web.Outputs.ServiceNowCredential.Of(refsJson);
        SnowCredentialProblem = SI.Management.Web.Outputs.ServiceNowCredential.Problem(refsJson);
        InstanceUrl ??= Obj(Current?.SettingsJson ?? SettingsJson)["instance"] is System.Text.Json.Nodes.JsonValue iv && iv.TryGetValue<string>(out var inst) ? inst : null;
        try
        {
            var all = await _repo.ListAsync(ct);
            DataOutOn = ServiceNowDataOut.On(all);
            DataOutProblem = DataOutOn.Count > 1 ? ServiceNowDataOut.TwoOnText(DataOutOn) : null;
            SnowSharedWith = SI.Management.Web.Outputs.ServiceNowCredential.SharedWith(Name ?? "", refsJson, all);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the connectors could not be read"); }
        IReadOnlyList<SI.Management.Web.Settings.SettingRow> settings = Array.Empty<SI.Management.Web.Settings.SettingRow>();
        try { if (Svc<SI.Management.Web.Settings.ISettingsStoreReader>() is { } reader) settings = (await reader.ReadSettingsAsync(ct)).Rows; }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the settings could not be read"); }
        string? Text(string name) => settings.FirstOrDefault(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase)) is { } t
            && SI.Management.Web.Settings.SettingJson.ToFormText(t.ValueJson) is { Length: > 0 } v ? v : null;
        // #912 the staging status table in force: no settings row = the default; a row = its value ('' = none)
        var stRow = settings.FirstOrDefault(r => r.Name.Equals(SI.Management.Web.Outputs.ServiceNowStagingStatus.Setting, StringComparison.OrdinalIgnoreCase));
        StagingStatusTable = SI.Management.Web.Outputs.ServiceNowStagingStatus.TableOf(stRow is not null, stRow is null ? null : SI.Management.Web.Settings.SettingJson.ToFormText(stRow.ValueJson));
        var on = SI.Management.Web.Pages.Reports.OutputFieldsModel.OnOutputs(SI.Management.Core.ProData.OutputMapRules.Catalog, Text(SI.Management.Web.Pages.Reports.OutputFieldsModel.OutputsSetting));
        IReadOnlyList<SI.Management.Web.Outputs.SnowCheckRow> latest = Array.Empty<SI.Management.Web.Outputs.SnowCheckRow>();
        try { if (Svc<SI.Management.Web.Outputs.IServiceNowCheckStore>() is { } checks) latest = await checks.LatestAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the ServiceNow checks could not be read"); }
        var states = new Dictionary<string, SI.Management.Web.Settings.SecretStateView?>(StringComparer.Ordinal);
        if (Current is not null && Svc<SI.Management.Web.Settings.SecretHandoverService>() is { } handover)
            foreach (var (r, _) in SnowSecrets)
            {
                try { states[r] = await handover.StateOfAsync(SI.Management.Web.Settings.SecretAllowList.ConnectorTarget(Current.Name, r), null, DateTime.UtcNow, ct); }
                catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "a secret's state could not be read"); }
            }
        // a table key in the connector's settings is never read (the table is the setting) -- said
        var s = Obj(Current?.SettingsJson ?? SettingsJson);
        SnowUnreadKeys = SnowInfos.Select(i => i.TableSetting).Where(k => s.Any(p => p.Key.Equals(k, StringComparison.OrdinalIgnoreCase))).ToList();
        foreach (var info in SnowInfos)
        {
            var o = new SnowOutputView { Info = info, Table = Text(info.TableSetting), On = on.Contains(info.Output), Latest = latest.FirstOrDefault(c => c.Output == info.Output) };
            o.Checklist = SI.Management.Web.Outputs.ServiceNowChecklist.BuildOutput(info, o.Table, o.Latest);
            var entry = SI.Management.Core.ProData.OutputMapRules.Catalog.FirstOrDefault(e => e.Output == info.Output);
            var (scope, resolved) = await VulnScopeAsync(info, ct);
            // the schema the team creates the table from (#912: shown in "For your ServiceNow team" for all three tables), and the
            // comparison: the newest check's columns against the columns in force
            if (entry is not null && IsDataOut && Svc<SI.Management.Web.Outputs.ServiceNowTeamPack>() is { } pack)
            {
                try
                {
                    var schema = await pack.SchemaAsync(entry, o.Table, scope, resolved, SI.Management.Web.Pages.AppInfo.Version, ct);
                    TeamTables.Add(SI.Management.Web.Outputs.ServiceNowTeamBrief.TableFromSchema(info.Output, "Staging table for " + info.Label, o.Table, schema,
                        "/Connectors/Fields?handler=Schema&output=" + Uri.EscapeDataString(info.Output)));
                    if (o.Latest is { Facts.ColumnsRead: true } l)
                        o.Schema = SI.Management.Web.Outputs.ServiceNowSchemaCompare.Compare(SI.Management.Web.Outputs.ServiceNowSchemaCompare.FromSchema(schema), l.Facts.Columns, l.Facts.Mapping, batchIdSent: StagingStatusTable.Length > 0);
                }
                catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the ServiceNow schema could not be built for the comparison"); o.SchemaProblem = "The columns in force could not be read for the comparison: " + ex.Message; }
            }
            try { o.Count = await CountWordsAsync(info, scope, resolved, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the rows could not be counted"); o.Count = "The rows could not be counted: " + ex.Message; }
            SnowOutputs.Add(o);
        }
        SnowLatest = SnowOutputs.Select(o => o.Latest).Where(l => l is not null).OrderByDescending(l => l!.CheckedAt).FirstOrDefault();
        SnowConnectorChecklist = SI.Management.Web.Outputs.ServiceNowChecklist.BuildConnector(Current, states.GetValueOrDefault("apikey"), SnowLatest, states);
        if (IsDataOut)
        {
            TeamTables.Add(SI.Management.Web.Outputs.ServiceNowTeamBrief.StatusTableDef(StagingStatusTable, "?name=" + Uri.EscapeDataString(Name ?? "") + "&handler=StagingStatusSchema"));
            TeamBrief = SI.Management.Web.Outputs.ServiceNowTeamBrief.Build(Current, SnowOutputs.Select(o => new SI.Management.Web.Outputs.ServiceNowTeamBrief.OutputState(o.Info, o.Table, o.Latest, o.Schema, o.On)).ToList(), StagingStatusTable);
            TeamBriefText = SI.Management.Web.Outputs.ServiceNowTeamBrief.PlainText(Current, TeamBrief, DateTime.UtcNow, TeamTables);
        }
    }

    private async Task<(SI.Management.Core.ProData.OutputScope? Scope, IReadOnlySet<string>? Resolved)> VulnScopeAsync(SI.Management.Web.Outputs.ServiceNowOutputs.Info info, CancellationToken ct)
    {
        if (info.Output != "servicenow-vulnerable-item" || Svc<SI.Management.Web.Reports.IReportStore>() is not { } store) return (null, null);
        try
        {
            if (!await store.SchemaAsync(ct)) return (null, null);
            var st = await store.LoadAsync(ct);
            var s = st.ScopeOf(info.Destination);
            return (s, s.Resolved(st.Membership()));
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the connector scope could not be read"); return (null, null); }
    }

    private async Task<string?> CountWordsAsync(SI.Management.Web.Outputs.ServiceNowOutputs.Info info, SI.Management.Core.ProData.OutputScope? scope, IReadOnlySet<string>? resolved, CancellationToken ct)
    {
        if (info.Output == "servicenow-ci")
        {
            if (Svc<SI.Management.Web.Outputs.ServiceNowRowCount>() is not { } counter || Svc<SI.Management.Web.Outputs.OutputMapStore>() is not { } maps) return null;
            System.Text.Json.Nodes.JsonObject? filter = null;
            try { if ((await maps.LoadAsync(info.Output, ct))?.FilterJson is { } fj) filter = System.Text.Json.Nodes.JsonNode.Parse(fj) as System.Text.Json.Nodes.JsonObject; } catch (System.Text.Json.JsonException) { filter = null; }
            var (n, total) = await counter.CiAsync(filter, ct);
            return (n is { } x ? Fmt.Int(x) + " of " + Fmt.Int(total) + " CI row(s) would be sent" : "The export counts the rows") + " -- the output's filter: " + SI.Management.Web.Pages.Reports.OutputFieldsModel.FilterWords(filter) + ".";
        }
        if (scope is null || Svc<SI.Management.Web.Reports.IReportStore>() is not { } store) return null;
        var c = await store.ScopeCountAsync(scope, resolved, ct);
        return (c is null ? "Not counted yet (no published run)" : Fmt.Int(c.Findings) + " row(s) would be sent (of " + Fmt.Int(c.TotalFindings) + " findings)") + " -- the scope in force: " + scope.Describe() + ".";
    }

    private static System.Text.Json.Nodes.JsonObject Obj(string? json)
    {
        try { return System.Text.Json.Nodes.JsonNode.Parse(string.IsNullOrWhiteSpace(json) ? "{}" : json) as System.Text.Json.Nodes.JsonObject ?? new(); }
        catch (System.Text.Json.JsonException) { return new(); }
    }

    /// The instance URL, checked and staged as a change of the connector's settings (Review &amp; commit), every other setting kept.
    [SI.Management.Web.Audit.Audited("connector.definition.stage")]
    public async Task<IActionResult> OnPostInstanceAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        if (Current is null) { InstanceProblem = "Stage the connector first; then set its instance address here."; return await GuidePageAsync(ct); }
        var (url, why) = SI.Management.Web.Outputs.ServiceNowInstanceUrl.Validate(InstanceUrl);
        if (url is null) { InstanceProblem = "Not staged: " + why + "."; return await GuidePageAsync(ct); }
        if (Current.Version != ReadVersion) { InstanceProblem = "This connector changed since you opened it. Reload it and set the address again."; return await GuidePageAsync(ct); }
        var write = ConnectorRepository.FromRow(Current, "Set", string.IsNullOrWhiteSpace(Reason) ? "ServiceNow instance address set to " + url : Reason) with
        { SettingsJson = SI.Management.Web.Outputs.ServiceNowInstanceUrl.WithInstance(Current.SettingsJson, url) };
        var (c, problems) = ChangeService.NewConnector(write);
        if (c is null) { InstanceProblem = "Not staged: " + string.Join("; ", problems); return await GuidePageAsync(ct); }
        await _changes.StageAsync(User, c, ct);
        TempData["toast"] = "Staged: the instance address " + url + ". Nothing is written until you review and commit.";
        return Redirect("/Changes");
    }

    /// #903: why a write may not be staged because another ServiceNow data-out connector is switched on (null = fine).
    private async Task<string?> DataOutConflictAsync(ConnectorWrite w, CancellationToken ct)
    {
        if (!ServiceNowDataOut.Is(w.Kind, w.Direction) || !w.Enabled) return null;
        try { return ServiceNowDataOut.Conflict(w, await _repo.ListAsync(ct)); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the connectors could not be read for the one-on rule"); return null; }   // the commit's SQL write refuses it then
    }

    // ---- #903 HOW IT SIGNS IN: an API key OR a user and a password (a customer's ServiceNow admin stored a password under
    //      'apikey' -- it was sent as an API key and refused every day). The chosen way's references are staged; the other way's
    //      are removed; no Key Vault secret is deleted. ------------------------------------------------------------------------
    [BindProperty] public string? CredentialChoice { get; set; }
    [BindProperty] public string? ApiKeyName { get; set; }
    [BindProperty] public string? UserName { get; set; }
    [BindProperty] public string? PasswordName { get; set; }

    [SI.Management.Web.Audit.Audited("connector.definition.stage")]
    public async Task<IActionResult> OnPostCredentialAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        if (Current is null) { CredentialProblem = "Stage the connector first; then choose how it signs in."; return await GuidePageAsync(ct); }
        if (!Current.Kind.Equals("servicenow", StringComparison.OrdinalIgnoreCase)) { CredentialProblem = "Not staged: this is not a ServiceNow connector."; return await GuidePageAsync(ct); }
        if (Current.Version != ReadVersion) { CredentialProblem = "This connector changed since you opened it. Reload it and choose again."; return await GuidePageAsync(ct); }
        var choice = (CredentialChoice ?? "").Trim();
        if (choice is not (SI.Management.Web.Outputs.ServiceNowCredential.ApiKey or SI.Management.Web.Outputs.ServiceNowCredential.UserPassword))
        { CredentialProblem = "Not staged: choose an API key, or a user and a password."; return await GuidePageAsync(ct); }
        var names = choice == SI.Management.Web.Outputs.ServiceNowCredential.ApiKey ? new[] { ("apikey", ApiKeyName) } : new[] { ("user", UserName), ("password", PasswordName) };
        foreach (var (r, n) in names)
        {
            if (string.IsNullOrWhiteSpace(n)) { CredentialProblem = $"Not staged: name the Key Vault secret of the {(r == "apikey" ? "API key" : r)}."; return await GuidePageAsync(ct); }
            if (SI.Management.Web.Settings.SecretAllowList.WhyNot(SI.Management.Web.Settings.SecretAllowList.ConnectorTarget(Current.Name, r), n.Trim()) is { } why)
            { CredentialProblem = $"Not staged: the {(r == "apikey" ? "API key" : r)}'s secret name -- {why}."; return await GuidePageAsync(ct); }
        }
        if (choice == SI.Management.Web.Outputs.ServiceNowCredential.UserPassword && string.Equals(UserName?.Trim(), PasswordName?.Trim(), StringComparison.OrdinalIgnoreCase))
        { CredentialProblem = "Not staged: the user and the password are two secrets with two names."; return await GuidePageAsync(ct); }
        var refs = SI.Management.Web.Outputs.ServiceNowCredential.RefsFor(Current.SecretRefsJson, choice, ApiKeyName, UserName, PasswordName);
        var words = choice == SI.Management.Web.Outputs.ServiceNowCredential.ApiKey ? "an API key" : "a user and a password";
        var write = ConnectorRepository.AlwaysOn(ConnectorRepository.FromRow(Current, "Set", string.IsNullOrWhiteSpace(Reason) ? "ServiceNow: signs in with " + words : Reason) with { SecretRefsJson = refs });
        var (c, problems) = ChangeService.NewConnector(write, $"The connector {Current.Name} signs in with {words}");
        if (c is null) { CredentialProblem = "Not staged: " + string.Join("; ", problems); return await GuidePageAsync(ct); }
        await _changes.StageAsync(User, c, ct);
        TempData["toast"] = $"Staged: {Current.Name} signs in with {words}. After Review & commit, a SuperAdmin sets the value here. No Key Vault secret was deleted.";
        return Redirect("/Changes");
    }

    // ---- #903 SWITCH ON / OFF the data-out connector: on stages the connector on AND the outputs chosen (both by default) on in
    //      SI_DataOut_Outputs, as one change; off stages it off (the outputs' own switches are kept). ----------------------------
    [BindProperty] public bool SwitchOn { get; set; }
    [BindProperty] public List<string> SwitchOutputs { get; set; } = new();

    [SI.Management.Web.Audit.Audited("connector.state.stage")]
    public async Task<IActionResult> OnPostSwitchAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        if (Current is null || !ServiceNowDataOut.Is(Current)) { SwitchProblem = "Not staged: only the ServiceNow data-out connector is switched here."; return await GuidePageAsync(ct); }
        if (Current.Version != ReadVersion) { SwitchProblem = "This connector changed since you opened it. Reload it and switch it again."; return await GuidePageAsync(ct); }
        var outputs = SwitchOn ? SwitchOutputs.Where(o => ServiceNowDataOut.Outputs.Contains(o)).Distinct().ToList() : new List<string>();
        var write = ConnectorRepository.AlwaysOn(ConnectorRepository.FromRow(Current, "Set", string.IsNullOrWhiteSpace(Reason) ? (SwitchOn ? "switched on as the ServiceNow data-out connector" : "switched off") : Reason) with { Enabled = SwitchOn });
        if (await DataOutConflictAsync(write, ct) is { } conflict) { SwitchProblem = "Not staged: " + conflict; return await GuidePageAsync(ct); }
        var title = SwitchOn
            ? $"Switch on the ServiceNow data-out connector {Current.Name}" + (outputs.Count > 0 ? " and send " + string.Join(" and ", outputs.Select(o => SI.Management.Web.Outputs.ServiceNowOutputs.Of(o)?.Label ?? o)) : "")
            : $"Switch off the ServiceNow data-out connector {Current.Name}";
        var (c, problems) = ChangeService.NewConnector(write, title, outputs);
        if (c is null) { SwitchProblem = "Not staged: " + string.Join("; ", problems); return await GuidePageAsync(ct); }
        await _changes.StageAsync(User, c, ct);
        TempData["toast"] = "Staged: " + title + ". Nothing is written until you review and commit.";
        return Redirect("/Changes");
    }

    /// "For your ServiceNow team" as plain text, to send to the customer's ServiceNow team -- no secret, no secret name.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetTeamBriefAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct) || Current is null) return NotFound("no such connector");
        Kind = Current.Kind; Direction = Current.Direction; SettingsJson = Current.SettingsJson; SecretRefsJson = Current.SecretRefsJson;
        if (!IsDataOut) return NotFound("not the ServiceNow data-out connector");
        await LoadServiceNowGuideAsync(ct);
        if (SI.Management.Web.Audit.AuditScope.Current is { } a) a.Reason = "for your ServiceNow team, " + TeamBrief.Count(l => l.Done == false).ToString(CultureInfo.InvariantCulture) + " item(s) still to do";
        return File(System.Text.Encoding.UTF8.GetBytes(TeamBriefText), "text/plain; charset=utf-8", SI.Management.Web.Outputs.ServiceNowTeamBrief.FileName(Current.Name));
    }

    /// #912 the staging status table's definition (JSON, the format of the data staging tables' ServiceNow schema) -- no secret.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetStagingStatusSchemaAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct) || Current is null) return NotFound("no such connector");
        Kind = Current.Kind; Direction = Current.Direction; SettingsJson = Current.SettingsJson; SecretRefsJson = Current.SecretRefsJson;
        if (!IsDataOut) return NotFound("not the ServiceNow data-out connector");
        var table = SI.Management.Web.Outputs.ServiceNowStagingStatus.DefaultTable;
        try
        {
            if (Svc<SI.Management.Web.Settings.ISettingsStoreReader>() is { } reader)
            {
                var row = (await reader.ReadSettingsAsync(ct)).Rows.FirstOrDefault(r => r.Name.Equals(SI.Management.Web.Outputs.ServiceNowStagingStatus.Setting, StringComparison.OrdinalIgnoreCase));
                var v = SI.Management.Web.Outputs.ServiceNowStagingStatus.TableOf(row is not null, row is null ? null : SI.Management.Web.Settings.SettingJson.ToFormText(row.ValueJson));
                if (v.Length > 0) table = v;
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _log.LogWarning(ex, "the settings could not be read -- the default staging status table name is used"); }
        var json = SI.Management.Web.Outputs.ServiceNowStagingStatus.Schema(table, SI.Management.Web.Pages.AppInfo.Version, DateTime.UtcNow);
        if (SI.Management.Web.Audit.AuditScope.Current is { } a) a.Reason = "the ServiceNow staging status table's schema (" + table + ")";
        return File(System.Text.Encoding.UTF8.GetBytes(json.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true })), "application/json; charset=utf-8", SI.Management.Web.Outputs.ServiceNowStagingStatus.FileName(table));
    }

    private async Task<IActionResult> GuidePageAsync(CancellationToken ct)
    {
        if (Current is { } cur)
        {
            Kind = cur.Kind; Direction = cur.Direction; Enabled = cur.Enabled; Mode = cur.Mode; AllowCreate = cur.AllowCreate; AllowClose = cur.AllowClose;
            SettingsJson = cur.SettingsJson; SecretRefsJson = cur.SecretRefsJson; MappingJson = cur.MappingJson; ReadVersion = cur.Version;
        }
        await LoadServiceNowGuideAsync(ct);
        return Page();
    }

    /// "Verify connection" / "Verify table schema": the mail job runs the ServiceNow checks with the engine identity (the web
    /// app holds no Key Vault right and never signs in to ServiceNow) and records the result; this page shows it on reload.
    [SI.Management.Web.Audit.Audited("connector.servicenow.verify")]
    public async Task<IActionResult> OnPostVerifyAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        if (Current is not null) { Kind = Current.Kind; Direction = Current.Direction; }
        // #903: the data-out connector feeds both outputs -- Verify checks both against it
        if (!IsDataOut || SnowInfos.Count == 0) { TempData["toast"] = "Not started: only the ServiceNow data-out connector is checked here."; TempData["toastKind"] = "error"; return RedirectToPage(new { name = Name }); }
        var what = SI.Management.Web.Outputs.ServiceNowVerifier.AllOutputs;
        if (SI.Management.Web.Audit.AuditScope.Current is { } a) { a.Target = "/Admin/ConnectorSetup/Edit, connector=" + Name + ", output=" + what; a.Reason = "ServiceNow check asked for"; }
        var verifier = HttpContext.RequestServices.GetRequiredService<SI.Management.Web.Outputs.ServiceNowVerifier>();
        var (started, message) = await verifier.StartAsync(what, User.ChangeName(), ct);
        if (!started) SI.Management.Web.Audit.AuditScope.Current?.Failed(message);
        TempData["toast"] = message; TempData["toastKind"] = started ? "ok" : "warn";
        return RedirectToPage(new { name = Name });
    }

    /// EVERY ROW the connector's ServiceNow output would send (Excel or CSV), the values as sent -- a read, audited.
    [SI.Management.Web.Audit.Audited("data.export.download")]
    public async Task<IActionResult> OnGetExportAsync(string? format, string? output, CancellationToken ct)
    {
        if (!await LoadAsync(ct) || Current is null) return NotFound("no such connector");
        Kind = Current.Kind; Direction = Current.Direction;
        // #903: the data-out connector feeds both outputs -- ?output= picks one (the CIs when none is named)
        var info = SnowInfos.FirstOrDefault(i => i.Output == output) ?? (string.IsNullOrEmpty(output) ? SnowInfos.FirstOrDefault() : null);
        if (info is null || SI.Management.Core.ProData.OutputMapRules.Catalog.FirstOrDefault(e => e.Output == info.Output) is not { } entry) return NotFound("not a ServiceNow output of this connector");
        var (scope, resolved) = await VulnScopeAsync(info, ct);
        string words;
        if (info.Output == "servicenow-ci")
        {
            System.Text.Json.Nodes.JsonObject? filter = null;
            try { if (Svc<SI.Management.Web.Outputs.OutputMapStore>() is { } maps && (await maps.LoadAsync(info.Output, ct))?.FilterJson is { } fj) filter = System.Text.Json.Nodes.JsonNode.Parse(fj) as System.Text.Json.Nodes.JsonObject; }
            catch (System.Text.Json.JsonException) { filter = null; }
            words = "the output's filter: " + SI.Management.Web.Pages.Reports.OutputFieldsModel.FilterWords(filter);
        }
        else words = "the scope in force: " + (scope?.Describe() ?? "everything (no scope)");
        var mode = !Current.Enabled ? "switched off" : IsDataOut || Current.Mode == "apply" ? "sends (apply)" : "whatif -- plans and logs, sends nothing";
        var file = await HttpContext.RequestServices.GetRequiredService<SI.Management.Web.Outputs.ScopeExport>().WriteServiceNowAsync(entry, scope, resolved, words, Current.Name + ": " + mode, format == "csv", ct);
        if (SI.Management.Web.Audit.AuditScope.Current is { } a) a.Reason = words + "; " + file.Rows.ToString(CultureInfo.InvariantCulture) + " row(s)";
        return File(file.Stream, file.ContentType, file.Name);
    }

    /// The ServiceNow test pack as a zip: fictional sample rows (CSV per object, the Import Set bodies), the column
    /// dictionary and the how-to for the customer's ServiceNow team. Static content, no customer data.
    [SI.Management.Web.Audit.NotAudited("a download of the fixed, fictional sample pack: no customer data, nothing changes")]
    public IActionResult OnGetTestPack() =>
        File(SI.Management.Web.Cmdb.ServiceNowTestPack.Zip(), "application/zip", SI.Management.Web.Cmdb.ServiceNowTestPack.ZipName);

    // #865: the own SQL vulnerability target is always apply + create + close (ConnectorRepository.AlwaysOn)
    private ConnectorWrite Write(string action) => ConnectorRepository.AlwaysOn(new(Name ?? "", action, (Kind ?? "").Trim().ToLowerInvariant(), (Direction ?? "").Trim().ToLowerInvariant(), Enabled,
        (Mode ?? "").Trim().ToLowerInvariant(), AllowCreate, AllowClose, Blank(SettingsJson), Blank(SecretRefsJson), Blank(MappingJson), ReadVersion, Reason));

    private static string? Blank(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    [SI.Management.Web.Audit.NotAudited("a check: validates the definition and stages and writes nothing")]
    public async Task<IActionResult> OnPostCheckAsync(CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        Problems = ConnectorRepository.Validate(Write("Set"));
        Checked = true;
        return Page();
    }

    [SI.Management.Web.Audit.Audited("connector.definition.stage")]
    public Task<IActionResult> OnPostStageAsync(CancellationToken ct) => StageAsync("Set", ct);
    [SI.Management.Web.Audit.Audited("connector.removal.stage")]
    public Task<IActionResult> OnPostRemoveAsync(CancellationToken ct) => StageAsync("Reset", ct);

    private async Task<IActionResult> StageAsync(string action, CancellationToken ct)
    {
        if (!await LoadAsync(ct)) return Page();
        if ((Current?.Version) != ReadVersion)
        {
            Problems = new[] { "This connector changed since you opened it. Reload it and make the change again." };
            return Page();
        }
        var write = Write(action);
        // #903: only one ServiceNow data-out connector can be switched on -- refused when staged, in plain words
        if (await DataOutConflictAsync(write, ct) is { } conflict) { Problems = new[] { conflict }; Checked = true; return Page(); }
        var (c, why) = ChangeService.NewConnector(write);
        if (c is null) { Problems = why; Checked = true; return Page(); }
        await _changes.StageAsync(User, c, ct);
        TempData["toast"] = "Staged: " + c.Title + ". Nothing is written until you review and commit.";
        return Redirect("/Changes");
    }

    /// The one-line explanation of a sql connector with the cmdb direction (the CMDB hand-off database).
    public const string SqlCmdbExplanation = "ServiceNow imports these tables with a JDBC data source (MID server) into an import set; your transform/IRE creates and updates CIs.";

    /// The ServiceNow-side setup of a sql + cmdb connector -- documentation only; SecurityInsight never writes to ServiceNow here.
    public static readonly IReadOnlyList<string> SqlCmdbServiceNowSteps =
    [
        "Grant the SecurityInsight job identity db_datareader, db_datawriter and (for the first run, which creates the snowstage tables) db_ddladmin in the hand-off database; give the account the MID server connects with db_datareader only.",
        "Data source: System Import Sets > Data Sources, type JDBC, format SQL Server, use MID server, the hand-off database, query 'Specific SQL': SELECT * FROM snowstage.vImportCi (one data source per view: vImportCi, vImportCiKeyValue, vImportCiRelation). The views always show the newest COMPLETE batch, so an import never reads a half-written one.",
        "Import set table: let the first Test load create it (for example u_si_ci_import); every column is a u_ column of the view.",
        "Transform map (or IntegrationHub ETL): map u_si_correlation_id, u_name, u_fqdn, u_serial_number, u_mac_address, u_azure_resource_id and the other identifiers to the target class from u_proposed_class, with the discovery source SecurityInsight, so every row goes through Identification and Reconciliation (IRE).",
        "Data sensitivity (optional): u_data_sensitivity is the value SecurityInsight weighs risk with -- your asset-profile rule's override wins over the CMDB record. In the transform map, map it to the field your CMDB keeps data sensitivity in (for example a u_data_sensitivity field on the class), with SecurityInsight as a low-priority source, or leave it unmapped to keep your CMDB's own value.",
        "IRE identification rules: keep your own rules; add u_si_correlation_id as the LAST identifier entry (a tie-breaker) on the rule's own table, and a reconciliation rule for the attributes SecurityInsight is authoritative for (tier, exposure, last seen).",
        "Schedule the import after the SecurityInsight CMDB job; for a delta import filter on u_changed_at later than the last import. Proposed CIs (snowstage.vProposedCi) are a report for your CMDB team -- SecurityInsight creates no CI.",
    ];

    /// How the customer's ServiceNow team tests with the sample data (the pack's HOW-TO-TEST.md says the same at length).
    public static readonly IReadOnlyList<string> TestPackSteps =
    [
        "Register SecurityInsight as a choice on cmdb_ci.discovery_source (IRE refuses a payload from an unregistered source).",
        "Create the staging tables from the sample files, one per object (for example u_si_ci_import from sql/vImportCi.csv). Every column keeps its u_ name and is at least as long as columns.csv says (u_si_correlation_id 400).",
        "For the Import Set push: add a REST Insert Multiple record per staging table with the column mapping 'Column name' -- otherwise the rows arrive empty (insertMultiple maps by column label by default).",
        "Set the identification and reconciliation rules BEFORE the first transform: your rules first, u_si_correlation_id last; SecurityInsight authoritative only for its own attributes.",
        "Build the transform maps: an onBefore script hands each CI row to IRE with the data source SecurityInsight (class from u_proposed_class) and ignores the row; never set error = true (it aborts the import set). Tags to cmdb_key_value; relations to cmdb_rel_ci; vulnerabilities through your Vulnerability Response transform, coalescing on u_source_record_id, else u_si_correlation_id + u_vulnerability.",
        "Run the transforms on the sample rows and compare each case with the result to expect below.",
        "Tick the approval checklist, then connect the real feed: a JDBC data source on your MID Server per view (filter u_changed_at > the last import), or the Import Set push to the same staging tables.",
    ];

    /// A starting definition per kind -- one the checks accept once the placeholders are the real names.
    public static (string Settings, string? SecretRefs, string? Mapping) Template(string kind) => kind switch
    {
        "sql" => ("{\n  \"server\": \"<server>.database.windows.net\",\n  \"database\": \"sqldb-si-vulnerabilities\"\n}", null, null),
        "servicenow" => ("{\n  \"table\": \"u_si_vulnerable_item\"\n}",
                         "{\n  \"instance\": \"SI-ServiceNow-Instance\",\n  \"user\": \"SI-ServiceNow-User\",\n  \"password\": \"SI-ServiceNow-Password\"\n}", null),
        _ => ("{\n  \"owner\": \"IT Security\"\n}", "{\n  \"token\": \"si-risk-api-token\"\n}", """
{
  "baseUrl": "https://risk.example.com/api",
  "auth": { "type": "bearer", "secretRef": "token" },
  "operations": {
    "listOpen": { "method": "GET", "url": "{{baseUrl}}/v1/risks?status=open&source=SecurityInsight", "itemsPath": "value", "idPath": "id",
                  "paging": { "type": "nextLink", "nextLinkPath": "nextLink" } },
    "create": { "method": "POST", "url": "{{baseUrl}}/v1/risks", "idPath": "id", "successCodes": [201],
                "body": { "title": "{{vuln.cve}} on {{asset.name}}", "externalReference": "{{finding.id}}", "owner": "{{settings.owner}}",
                          "severity": "{{vuln.severity}}", "riskScore": "{{vuln.riskScore}}" } },
    "close": { "method": "POST", "url": "{{baseUrl}}/v1/risks/{{external.id}}/close", "body": { "resolution": "{{reason}}" } },
    "reopen": { "method": "POST", "url": "{{baseUrl}}/v1/risks/{{external.id}}/reopen", "body": { "reason": "{{reason}}" } }
  }
}
"""),
    };
}
